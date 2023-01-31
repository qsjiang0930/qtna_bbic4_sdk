/**
  Copyright (c) 2008 - 2013 Quantenna Communications Inc
  All Rights Reserved

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

 **/

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/version.h>

#include <linux/device.h>
#include <linux/time.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/pm_qos_params.h>
#include <linux/workqueue.h>
#include "qdrv_features.h"
#include "qdrv_debug.h"
#include "qdrv_mac.h"
#include "qdrv_soc.h"
#include "qdrv_hal.h"
#include "qdrv_muc.h"
#include "qdrv_dsp.h"
#include "qtn/registers.h"
#include "qtn/muc_phy_stats.h"
#include "qdrv_comm.h"
#include "qdrv_wlan.h"
#include "qdrv_radar.h"
#include <net/iw_handler.h> /* wireless_send_event(..) */
#include "qdrv_debug.h"
#include <net80211/ieee80211_var.h>
#if defined(CONFIG_QTN_BSA_SUPPORT)
#include "net80211/ieee80211_qrpe.h"
#endif
#include "qdrv_control.h"
#include <asm/board/pm.h>


/* Will move this to a configuration later.  */
#define CONFIG_QHOP 1

#define DFS_CS_TIMER_VAL	(HZ / 10)

#define QDRV_RADAR_SAMPLE_RATE	1	/* sampling rate (seconds) */
#define QDRV_RADAR_SAMPLE_DELAY	10	/* Give MuC time to update stats (jiffies) */

#define QDRV_RADAR_PROC_SIZE		(8192)
#define QDRV_RADAR_PROC_MAX_WRITE_SIZE	(256)

static bool qdrv_radar_configured = false;
static bool qdrv_radar_first_call = true;
static bool qdrv_radar_sta_dfs = false;

/*
 * Control block for qdrv_radar
 */
static struct {
	bool				enabled;
	bool				xmit_stopped;
	struct qdrv_mac			*mac;
	struct ieee80211com		*ic;
	struct ieee80211_channel	*cac_chan;
	struct timer_list		cac_timer; /* a timer for CAC */
	struct timer_list		nonoccupy_timer[IEEE80211_CHAN_MAX+1];
	unsigned long			nonoccupy_jiffies[IEEE80211_CHAN_MAX+1];
	struct ieee80211_channel	*dfs_des_chan;
	struct timer_list		dfs_cs_timer; /* a timer for a channel switch */
	struct notifier_block		pm_notifier;
	struct qtn_ocac_info		*ocac_info;
	uint32_t			region;
	uint8_t				ocac_last_chan;

	radar_stats_handler_t		stats_handler;
	void				*stats_handler_arg;

	struct proc_dir_entry		*radar_proc;
	struct proc_dir_entry		*radar_pulse_proc;
	struct proc_dir_entry		*radar_zc_proc;
	struct proc_dir_entry		*radar_ocac_proc;
} qdrv_radar_cb;

/*
 * Utility macros
 */

/*
 * True if this mode must behave like a DFS master, ie do Channel
 * Check Availability and In Service Monitoring. We need to make sure
 * that all modes cannot send data without being authorized. Such
 * enforcement is not done in monitor mode however.
 */
static inline int ieee80211_is_dfs_master(struct ieee80211com *ic)
{
	struct ieee80211vap *vap = NULL;

	KASSERT(ic->ic_opmode != IEEE80211_M_WDS,
		(DBGEFMT "Incorrect ic opmode %d\n", DBGARG, ic->ic_opmode));

	vap = ieee80211_get_active_ap_vap(ic);
	if (vap)
		return 1;

	if (ic->ic_opmode == IEEE80211_M_IBSS)
		return 1;

	if (ic->ic_opmode == IEEE80211_M_AHDEMO)
		return 1;

	return 0;
}

static inline int qdrv_is_dfs_master(void)
{
	return ieee80211_is_dfs_master(qdrv_radar_cb.ic);
}

static inline int qdrv_is_dfs_slave(void)
{
	return !ieee80211_is_dfs_master(qdrv_radar_cb.ic);
}

#define GET_CHANIDX(chan)	((chan) - ic->ic_channels)

static void stop_cac(void);
static void stop_dfs_cs(void);
static void qdrv_ocac_irqhandler(void *arg1, void *arg2);
static int qdrv_init_ocac_irqhandler(struct qdrv_wlan *qw);
static void dfs_action_after_newchan_select(struct ieee80211_channel *new_chan,
	bool radar_detected_during_cac);

#ifndef SYSTEM_BUILD
#define ic2dev(ic)	((struct ieee80211vap *)(TAILQ_FIRST(&(ic)->ic_vaps)) ? \
			((struct ieee80211vap *)(TAILQ_FIRST(&(ic)->ic_vaps)))->iv_dev : NULL)
#else
#define ic2dev(ic)	NULL
#endif

/* used to report RADAR: messages to event server */
#define radar_event_report(...)			qdrv_eventf(__VA_ARGS__)

#define DBGPRINTF_N_QEVT(qevtdev, ...)		do {\
							DBGPRINTF_N(__VA_ARGS__);\
							radar_event_report(qevtdev, __VA_ARGS__);\
						} while (0)

#ifdef CONFIG_QHOP
/*
 *   RBS reports channel change detect to MBS over the WDS link.
 */
static void
qdrv_qhop_send_rbs_report_frame(struct ieee80211vap *vap,
	u_int8_t new_chan)
{
	struct ieee80211_node *ni = ieee80211_get_wds_peer_node_ref(vap);
	struct sk_buff *skb;
	int frm_len = sizeof(struct qdrv_vendor_action_header) +
			sizeof(struct qdrv_vendor_action_qhop_dfs_data);
	u_int8_t *frm;

	if (!ni) {
		DBGPRINTF_E("WDS peer is NULL!\n");
		return;
	}

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
	                "%s: Sending action frame with RBS report IE: %u\n",
	                __func__, new_chan);

	skb = ieee80211_getmgtframe(&frm, frm_len);
	if (skb == NULL) {
	        IEEE80211_NOTE(vap, IEEE80211_MSG_ANY, ni,
			"%s: cannot get buf; size %u", __func__, frm_len);
	        vap->iv_stats.is_tx_nobuf++;
		ieee80211_free_node(ni);
	        return;
	}

	/* Fill in QHOP action header and data */
	*frm++ = IEEE80211_ACTION_CAT_VENDOR;
	frm += 3;
	*frm++ = QDRV_ACTION_TYPE_QHOP;
	*frm++ = QDRV_ACTION_QHOP_DFS_REPORT;
	*frm++ = new_chan;

	ieee80211_mgmt_output(ni, skb, IEEE80211_FC0_SUBTYPE_ACTION, ni->ni_macaddr);
}
#endif

/*
 * Status-checking inline functions
 */
inline static bool is_cac_started(void)
{
	return (qdrv_radar_cb.cac_chan != NULL);
}

inline static bool is_dfs_cs_started(void)
{
	return (qdrv_radar_cb.dfs_des_chan != NULL);
}

static bool qdrv_radar_get_status(void)
{
	volatile struct shared_params *sp = qtn_mproc_sync_shared_params_get();

	return sp->radar_lhost->enabled;
}

static void qdrv_radar_set_chan(uint8_t channel)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct qdrv_wlan *qw = container_of(ic, struct qdrv_wlan, ic);

	qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_CHAN, channel);
}

/*
 * Enable radar detection on channel
 */
inline static void sys_enable_rdetection(void)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct qdrv_wlan *qw = container_of(ic, struct qdrv_wlan, ic);

	if (DBG_LOG_FUNC_TEST(QDRV_LF_DFS_DISALLOWRADARDETECT)) {
		DBGPRINTF_N("RADAR: test mode - radar not enabled\n");
		return;
	}
	if (qdrv_is_dfs_slave() && !qdrv_radar_sta_dfs)
		return;

	qdrv_hostlink_radar_enable(qw);
}

/*
 * Disable radar detection on channel
 */
inline static void sys_disable_rdetection(void)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct qdrv_wlan *qw = container_of(ic, struct qdrv_wlan, ic);

	DBGPRINTF(DBG_LL_INFO, QDRV_LF_RADAR, "Radar detection disabled\n");
	qdrv_hostlink_radar_disable(qw);
}

static enum radar_dfs_rqmt dfs_rqmt_code(const char *region)
{
	if (strcmp(region, "us") == 0)
		return DFS_RQMT_US;
	else if (strcmp(region, "eu") == 0)
		return DFS_RQMT_EU;
	else if (strcmp(region, "jp") == 0)
		return DFS_RQMT_JP;
	else if (strcmp(region, "au") == 0)
		return DFS_RQMT_AU;
	else if (strcmp(region, "br") == 0)
		return DFS_RQMT_BR;
	else if (strcmp(region, "cl") == 0)
		return DFS_RQMT_CL;
	else
		return DFS_RQMT_UNKNOWN;
}

/*
 * Start the radar module
 */
inline static bool sys_start_radarmod(const char *region)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct qdrv_wlan *qw = container_of(ic, struct qdrv_wlan, ic);
	int res;

	res = qdrv_hostlink_radar_start(qw, dfs_rqmt_code(region), get_bootcfg_scancnt());

	if (res >= 0) {
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_BW, ic->ic_radar_bw);
		sys_disable_rdetection();
	}

	return res >= 0;
}

/*
 * Stop the radar module
 */
static inline void sys_stop_radarmod(void)
{
	sys_disable_rdetection();
}

static inline void sys_raw_enable_xmit(void)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct qdrv_wlan *qw = container_of(ic, struct qdrv_wlan, ic);

	qdrv_hostlink_xmitctl(qw, true);
	DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR, "transmission enabled\n");
}

static inline void sys_raw_disable_xmit(void)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct qdrv_wlan *qw = container_of(ic, struct qdrv_wlan, ic);

	qdrv_hostlink_xmitctl(qw, false);
	DBGPRINTF(DBG_LL_INFO, QDRV_LF_RADAR, "transmission disabled\n");
}
/*
 * Instruct MuC to enable transmission
 */
void sys_enable_xmit(const char *caller)
{
	if (qdrv_radar_cb.xmit_stopped == false)
		return;

	DBGPRINTF(DBG_LL_INFO, QDRV_LF_RADAR,
			"caller %s - enable Xmit\n", caller);
	sys_raw_enable_xmit();
	qdrv_radar_cb.xmit_stopped = false;
}

/*
 * Instruct MuC to disable transmission
 */
void sys_disable_xmit(const char *caller)
{
	if (qdrv_radar_cb.xmit_stopped == true)
		return;

	/* If training is running, stop it */
	ieee80211_stop_training(qdrv_radar_cb.ic);
	DBGPRINTF(DBG_LL_INFO, QDRV_LF_RADAR,
			"caller %s - disable Xmit\n", caller);

	sys_raw_disable_xmit();
	qdrv_radar_cb.xmit_stopped = true;
}

/*
 * Instruct MuC to enable/disable transmission for STA mode
 */
void qdrv_sta_set_xmit(int enable)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;

	if (!qdrv_radar_cb.ic)
		return;

	if (qdrv_is_dfs_master())
		return;

	if (enable) {
		if (ic->sta_dfs_info.sta_dfs_strict_mode &&
			((ieee80211_is_chan_radar_detected(ic->ic_curchan)) ||
			(ieee80211_is_chan_cac_required(ic->ic_curchan)))) {
			DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR,
				"\n%s: xmit cannot be enabled on channel %d [%s]\n",
				__func__, ic->ic_curchan ? ic->ic_curchan->ic_ieee : 0,
				ieee80211_is_chan_radar_detected(ic->ic_curchan) ?
				"CAC required" : "in Non-Occupancy list");
			return;
		}
		sys_enable_xmit(__func__);
	} else {
		sys_disable_xmit(__func__);
	}
}

static int qdrv_radar_set_detect_flag(unsigned chan_idx)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct ieee80211_channel *chan;

	KASSERT(chan_idx < ic->ic_nchans,
		(DBGEFMT "out-of-range channel idx %u\n", DBGARG, chan_idx));

	chan = &ic->ic_channels[chan_idx];

	if (ic->sta_dfs_info.sta_dfs_strict_mode) {
		/* Check IEEE80211_CHAN_RADAR flag to avoid repeated actions */
		if (chan->ic_flags & IEEE80211_CHAN_RADAR)
			return 0;
	} else if (qdrv_is_dfs_slave()) {
		/* DFS slave depends on a master for this period */
		return 0;
	}

	chan->ic_flags |= IEEE80211_CHAN_RADAR;
	chan->ic_radardetected++;

	return 1;
}

/*
 * Start or restart the non-occupy period
 */
static void start_nonoccupy(unsigned chan_idx)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct timer_list *nonoccupy_timer;
	struct ieee80211_channel *chan;
	unsigned long expires;
	unsigned long sta_dfs_timer_expires;

	KASSERT(chan_idx < ic->ic_nchans,
		(DBGEFMT "out-of-range channel idx %u\n", DBGARG, chan_idx));

	chan = &ic->ic_channels[chan_idx];

	if (ic->sta_dfs_info.sta_dfs_strict_mode) {
		/*
		 * Mark channel with NOT_AVAILABLE_RADAR_DETECTED flag after a delay
		 * to allow the transmission of the measurement report to the AP
		 * by the STA.
		 */
		ic->sta_dfs_info.sta_radar_timer.data = chan->ic_ieee;
		sta_dfs_timer_expires = jiffies +
			IEEE80211_MS_TO_JIFFIES(ic->sta_dfs_info.sta_dfs_tx_chan_close_time);
		ic->sta_dfs_info.sta_dfs_radar_detected_timer = true;
		ic->sta_dfs_info.sta_dfs_radar_detected_channel = chan->ic_ieee;
		mod_timer(&ic->sta_dfs_info.sta_radar_timer, sta_dfs_timer_expires);
		DBGPRINTF(DBG_LL_INFO, QDRV_LF_RADAR,
			"%s: Start sta_radar_timer [expiry:CSA/%lums]\n",
			__func__, ic->sta_dfs_info.sta_dfs_tx_chan_close_time);
	}

	nonoccupy_timer = &qdrv_radar_cb.nonoccupy_timer[chan_idx];

	expires = jiffies + ic->ic_non_occupancy_period;

	if (DBG_LOG_FUNC_TEST(QDRV_LF_DFS_QUICKTIMER)) {
		DBGPRINTF_N("RADAR: test mode - non-occupancy period will expire quickly\n");
		expires = jiffies + NONOCCUPY_PERIOD_QUICK;
	}

	mod_timer(nonoccupy_timer, expires);
	qdrv_radar_cb.nonoccupy_jiffies[chan_idx] = jiffies;

	DBGPRINTF_N_QEVT(ic2dev(ic), "RADAR: non-occupancy period started for channel %3d "
			"(%4d MHz)\n", chan->ic_ieee, chan->ic_freq);

	if (!ic->sta_dfs_info.sta_dfs_strict_mode) {
		ic->ic_mark_channel_availability_status(ic, chan,
			IEEE80211_CHANNEL_STATUS_NOT_AVAILABLE_RADAR_DETECTED);
	}
}

/*
 * Stop active or inactive nonoccupy period
 */
static void raw_stop_nonoccupy(unsigned chan_idx)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct timer_list *nonoccupy_timer;
	struct ieee80211_channel *chan = &ic->ic_channels[chan_idx];

	KASSERT(chan_idx < ic->ic_nchans,
		(DBGFMT "out-of-range channel idx %u\n", DBGARG, chan_idx));

	if (!(chan->ic_flags & IEEE80211_CHAN_RADAR))
		return;

	chan->ic_flags &= ~IEEE80211_CHAN_RADAR;

	nonoccupy_timer = &qdrv_radar_cb.nonoccupy_timer[chan_idx];
	del_timer(nonoccupy_timer);
        qdrv_radar_cb.nonoccupy_jiffies[chan_idx] = 0;

	DBGPRINTF_N_QEVT(ic2dev(ic), "RADAR: non-occupancy period stopped for channel %3d "
			 "(%4d MHz)\n", chan->ic_ieee, chan->ic_freq);
}

void qdrv_radar_run_dfs_action(struct ieee80211com *ic)
{
	int handle_radar = !(IEEE80211_IS_CHAN_CACDONE(ic->ic_curchan)) &&
			!(IEEE80211_IS_CHAN_CAC_IN_PROGRESS(ic->ic_curchan)) &&
			!(IEEE80211_IS_CHAN_RADAR(ic->ic_curchan));

	if (!is_ieee80211_chan_valid(ic->ic_curchan)) {
		printk("%s: invalid ic_curchan\n", __func__);
		return;
	}

	if (handle_radar)
		qdrv_radar_before_newchan();

	qdrv_radar_on_newchan();
}

static void qdrv_radar_enable_action(void)
{
	struct ieee80211com *ic;
	struct qdrv_wlan *qw;

	if (qdrv_radar_first_call == true || !qdrv_radar_configured) {
		DBGPRINTF_E("radar unconfigured\n");
		return;
	}

	if (qdrv_radar_cb.enabled) {
		DBGPRINTF_E("radar already enabled\n");
		return;
	}

	ic = qdrv_radar_cb.ic;
	qw = container_of(ic, struct qdrv_wlan, ic);

	qdrv_mac_enable_irq(qw->mac, RUBY_M2L_IRQ_LO_OCAC);

	qdrv_radar_cb.enabled = true;

	qdrv_radar_run_dfs_action(ic);

	/* For external stats */
	QDRV_SET_SM_FLAG(qw->sm_stats, QDRV_WLAN_SM_STATE_RADAR_EN);

	DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR, "Radar enabled\n");
}

/*
 * Disable DFS feature
 */
void qdrv_radar_disable(void)
{
	struct ieee80211com *ic;
	struct qdrv_wlan *qw;
	struct qdrv_mac *mac;
	unsigned chan_idx;
	struct ieee80211_channel *chan;

	if (qdrv_radar_first_call == true || !qdrv_radar_configured) {
		DBGPRINTF_E("radar unconfigured\n");
		return;
	}

	if (!qdrv_radar_cb.enabled) {
		DBGPRINTF_E("radar already disabled\n");
		return;
	}

	sys_disable_rdetection();

	mac = qdrv_radar_cb.mac;
	qdrv_mac_disable_irq(mac, RUBY_M2L_IRQ_LO_OCAC);

	/* stop CAC if any */
	stop_cac();

	/* stop CS if any */
	stop_dfs_cs();

	ic = qdrv_radar_cb.ic;
	/* delete all nonoccupy timers and clear CAC done flag */
	for (chan_idx = 0; chan_idx < ic->ic_nchans; chan_idx++) {
		chan = &ic->ic_channels[chan_idx];
		chan->ic_flags &= ~(IEEE80211_CHAN_DFS_CAC_DONE |
				IEEE80211_CHAN_DFS_CAC_IN_PROGRESS);
		raw_stop_nonoccupy(chan_idx);
		if (ic->sta_dfs_info.sta_dfs_strict_mode &&
				(chan->ic_flags & IEEE80211_CHAN_DFS)) {
			ic->ic_chan_availability_status[chan->ic_ieee]
					= IEEE80211_CHANNEL_STATUS_NON_AVAILABLE;
			ic->ic_mark_channel_dfs_cac_status(ic, chan,
				IEEE80211_CHAN_DFS_CAC_DONE, false);
			ic->ic_mark_channel_dfs_cac_status(ic, chan,
				IEEE80211_CHAN_DFS_CAC_IN_PROGRESS, false);
		}
	}

	if (ic->sta_dfs_info.sta_dfs_strict_mode) {
		del_timer(&ic->sta_dfs_info.sta_radar_timer);
		ic->sta_dfs_info.sta_dfs_radar_detected_timer = false;
		ic->sta_dfs_info.sta_dfs_radar_detected_channel = 0;
	}

#ifdef CONFIG_QHOP
	del_timer(&ic->rbs_mbs_dfs_info.rbs_dfs_radar_timer);
#endif

	/* always enable transmission */
	sys_enable_xmit(__func__);

	qdrv_radar_cb.enabled = false;
	/* For external stats */
	qw = container_of(ic, struct qdrv_wlan, ic);
	QDRV_CLEAR_SM_FLAG(qw->sm_stats, QDRV_WLAN_SM_STATE_RADAR_EN);

	/* success */
	DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR, "radar disabled\n");
}

void qdrv_set_radar(int enable)
{
	if (qdrv_radar_first_call == true || !qdrv_radar_configured) {
		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR,
				"radar already unconfigured\n");
		return;
	}

	enable = !!enable;
	if (enable == qdrv_radar_cb.enabled) {
		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR, "Radar already %s\n",
				enable ? "enabled" : "disabled");
		return;
	}

	if (enable)
		qdrv_radar_enable_action();
	else
		qdrv_radar_disable();

	DBGPRINTF(DBG_LL_INFO, QDRV_LF_RADAR, "Radar configured manually\n");
}

int qdrv_radar_is_enabled(void)
{
	return !!qdrv_radar_cb.enabled;
}

int qdrv_radar_detections_num(uint32_t chan)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	uint32_t chan_idx = 0;

	if (!qdrv_radar_cb.enabled)
		return -1;

	for (chan_idx = 0; chan_idx < ic->ic_nchans; chan_idx++) {
		if (ic->ic_channels[chan_idx].ic_ieee == chan)
			break;
	}

	if (ic->ic_channels[chan_idx].ic_flags & IEEE80211_CHAN_DFS)
		return (ic->ic_channels[chan_idx].ic_radardetected);
	else
		return -1;
}

static void qdrv_radar_ocac_handler(void)
{
	const struct qtn_ocac_info *ocac_info = qdrv_radar_cb.ocac_info;
	struct ieee80211com *ic = qdrv_radar_cb.ic;

	if (unlikely(!qdrv_radar_cb.enabled))
		return;

	if (unlikely(!ic->ic_ocac.ocac_chan))
		return;

	/* Only do off channel CAC on non-DFS channel */
	if (qdrv_radar_is_rdetection_required(ic->ic_bsschan))
		return;

	qdrv_radar_cb.ocac_last_chan = ic->ic_ocac.ocac_chan->ic_ieee;

	if (ocac_info->chan_status == QTN_OCAC_ON_DATA_CHAN) {
		ic->ic_ocac.ocac_counts.tasklet_data_chan++;
		ic->ic_ocac.ocac_accum_cac_time_ms += ocac_info->actual_dwell_time;
		ic->ic_chan_switch_reason_record(ic, IEEE80211_CSW_REASON_OCAC_RUN);
	} else {
		ic->ic_ocac.ocac_counts.tasklet_off_chan++;
	}
}

/*
 * Send CSA frame to MuC
 */
#ifndef CONFIG_QHOP
static void sys_send_csa(struct ieee80211vap *vap,
	struct ieee80211_channel* new_chan, u_int64_t tsf)
{
	struct ieee80211com *ic;

	if ((vap == NULL) || (new_chan == NULL)) {
		DBGPRINTF_E("vap 0x%p, new_chan 0x%p\n", vap, new_chan);
		return;
	}
	ic = vap->iv_ic;
	ic->ic_send_csa_frame(vap, IEEE80211_CSA_MUST_STOP_TX,
		new_chan->ic_ieee, IEEE80211_RADAR_11HCOUNT, tsf);
}
#endif

static void send_channel_related_event(struct net_device *dev, char *event_string)
{
	if (event_string == NULL || dev == NULL) {
		return;
	}

	DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR,
		"send event to userspace, dev=%s msg=%s\n", dev->name, event_string);

	radar_event_report(dev, "%s", event_string);
}


/* notify the dfs reentry demon of the channel switch info */
void dfs_reentry_chan_switch_notify(struct net_device *dev,
	struct ieee80211_channel *new_chan)
{
	char *dfs_chan_sw = "dfs_csa";
	char *nondfs_chan_sw = "non_dfs_csa";
	char *no_chan_valid = "csa_fail";
	char *notify_string;

	if (NULL == new_chan)
		notify_string = no_chan_valid;
	else if (new_chan->ic_flags & IEEE80211_CHAN_DFS)
		notify_string = dfs_chan_sw;
	else
		notify_string = nondfs_chan_sw;

	send_channel_related_event(dev, notify_string);
}
EXPORT_SYMBOL(dfs_reentry_chan_switch_notify);


/*
 * Initiate a channel switch
 * - 'new_chan' should not be NULL
 */
static void sys_change_chan(struct ieee80211_channel *new_chan)
{
#define IEEE80211_VAPS_LOCK_BH(_ic)	spin_lock_bh(&(_ic)->ic_vapslock);
#define IEEE80211_VAPS_UNLOCK_BH(_ic)	spin_unlock_bh(&(_ic)->ic_vapslock);

	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct ieee80211vap *vap = ieee80211_get_primary_vap(ic, 0);

	if (!new_chan || !vap) {
		DBGPRINTF_E("null channel or vap\n");
		return;
	}
	/* if dfs channel the notify will be send after cac */
	if (!(new_chan->ic_flags & IEEE80211_CHAN_DFS))
		dfs_reentry_chan_switch_notify(vap->iv_dev, new_chan);

	if (ieee80211_is_dev_running(vap->iv_dev)) {
		ic->ic_prevchan = ic->ic_curchan;
		ic->ic_curchan = ic->ic_des_chan = new_chan;
		ic->ic_csw_reason = IEEE80211_CSW_REASON_DFS;
		IEEE80211_VAPS_LOCK_BH(ic);
		vap->iv_newstate(vap, IEEE80211_S_SCAN, 0);
		IEEE80211_VAPS_UNLOCK_BH(ic);
		ic->ic_flags &= ~IEEE80211_F_CHANSWITCH;
	} else if (vap->iv_state == IEEE80211_S_RUN) {
		/* Normally, we don't get to here */
		TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
			if ((vap->iv_opmode == IEEE80211_M_WDS) &&
					(vap->iv_state == IEEE80211_S_RUN)) {
				IEEE80211_VAPS_LOCK_BH(ic);
				vap->iv_newstate(vap, IEEE80211_S_INIT, 0);
				IEEE80211_VAPS_UNLOCK_BH(ic);
			}
		}

		ic->ic_prevchan = ic->ic_curchan;
		ic->ic_curchan = new_chan;
		ic->ic_bsschan = new_chan;
		ic->ic_csw_reason = IEEE80211_CSW_REASON_DFS;
		ic->ic_set_channel(ic);
		ic->ic_flags &= ~IEEE80211_F_CHANSWITCH;

		TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
			if ((vap->iv_opmode == IEEE80211_M_WDS) &&
					(vap->iv_state == IEEE80211_S_INIT)) {
				IEEE80211_VAPS_LOCK_BH(ic);
				vap->iv_newstate(vap, IEEE80211_S_RUN, 0);
				IEEE80211_VAPS_UNLOCK_BH(ic);
			}

			if (vap->iv_opmode != IEEE80211_M_HOSTAP)
				continue;

			if ((vap->iv_state != IEEE80211_S_RUN) &&
					(vap->iv_state != IEEE80211_S_SCAN))
				continue;

			ic->ic_beacon_update(vap);
		}
	} else {
		ic->ic_flags &= ~IEEE80211_F_CHANSWITCH;
		DBGPRINTF_E("channel change failed\n");
	}
}

/*
 * CAC has successfully passed
 */
static void cac_completed_action(unsigned long data)
{
	struct ieee80211com *ic;
	struct qdrv_wlan *qw;
	struct ieee80211_channel *chan;
	struct ieee80211vap *vap;
	int chan_status = 0;

	ic = qdrv_radar_cb.ic;
	if (ic == NULL || !is_cac_started()) {
		DBGPRINTF_E("CAC not in progress\n");
		return;
	}

	vap = ieee80211_get_primary_vap(ic, 0);
	if (vap == NULL || vap->iv_dev == NULL)
		return;

	qw = container_of(ic, struct qdrv_wlan, ic);
	chan = qdrv_radar_cb.cac_chan;
	/* resume normal operation on channel */
	sys_enable_xmit(__func__);
	chan->ic_flags |= IEEE80211_CHAN_DFS_CAC_DONE;
	chan->ic_flags &= ~IEEE80211_CHAN_DFS_CAC_IN_PROGRESS;

	if (ic->sta_dfs_info.sta_dfs_strict_mode) {
		if (!(vap->iv_bss && IEEE80211_NODE_AID(vap->iv_bss)))
			chan_status = IEEE80211_CHANNEL_STATUS_NON_AVAILABLE;
		else
			chan_status = IEEE80211_CHANNEL_STATUS_AVAILABLE;
	} else {
		chan_status = IEEE80211_CHANNEL_STATUS_AVAILABLE;
	}

	ic->ic_mark_channel_availability_status(ic, chan, chan_status);

	if (ic->sta_dfs_info.sta_dfs_strict_mode &&
			(chan_status == IEEE80211_CHANNEL_STATUS_NON_AVAILABLE))
		ic->ic_mark_channel_dfs_cac_status(ic, chan,
				IEEE80211_CHAN_DFS_CAC_DONE, false);
	else
		ic->ic_mark_channel_dfs_cac_status(ic, chan,
				IEEE80211_CHAN_DFS_CAC_DONE, true);
	ic->ic_mark_channel_dfs_cac_status(ic, chan,
				IEEE80211_CHAN_DFS_CAC_IN_PROGRESS, false);

	DBGPRINTF_N_QEVT(vap->iv_dev, "RADAR: CAC completed for channel %3d (%4d MHz)\n",
		chan->ic_ieee, chan->ic_freq);

	DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR, "\n%s: chan_status=%d\n", __func__, chan_status);

	QDRV_CLEAR_SM_FLAG(qw->sm_stats, QDRV_WLAN_SM_STATE_CAC_ACTIVE);
	/* cac has ended, it means can switch to a dfs channel succed*/
	dfs_reentry_chan_switch_notify(vap->iv_dev, qdrv_radar_cb.cac_chan);
	qdrv_radar_cb.cac_chan = NULL;

	ic->ic_pm_reason = IEEE80211_PM_LEVEL_CAC_COMPLETED;
	ieee80211_pm_queue_work_custom(ic, BOARD_PM_WLAN_IDLE_TIMEOUT);

	if (ic->ic_ap_next_cac) {
		(void) ic->ic_ap_next_cac(ic, vap, CAC_PERIOD, &qdrv_radar_cb.cac_chan,
					IEEE80211_SCAN_PICK_NOT_AVAILABLE_DFS_ONLY);
	}
#if defined(CONFIG_QTN_BSA_SUPPORT)
	if (IEEE80211_XCAC_CAC_EVENT_EN(ic)) {
		ieee80211_qrpe_send_event_xcac_status_update(vap, IEEE80211_QRPE_XCAC_COMPLETED,
			chan->ic_ieee, IEEE80211_QRPE_CHAN_STATUS_AVAILABLE);
		if ((ic->ic_xcac_req_flags & IEEE80211_XCAC_FLAG_ACT_RETURN) &&
				is_ieee80211_chan_valid(ic->ic_xcac_return_chan))
			dfs_action_after_newchan_select(ic->ic_xcac_return_chan, false);
		ic->ic_xcac_req_flags = 0;
	}
#endif
}

void qdrv_cac_instant_completed(void)
{
	struct timer_list *cac_timer;

	if (!is_cac_started())
		return;

	KASSERT((qdrv_radar_cb.cac_chan->ic_flags & IEEE80211_CHAN_DFS) != 0,
			(DBGEFMT "CAC started on non-DFS channel: %3d (%4d MHz)\n",
			DBGARG, qdrv_radar_cb.cac_chan->ic_ieee,
			qdrv_radar_cb.cac_chan->ic_freq));
	KASSERT(!(qdrv_radar_cb.cac_chan->ic_flags & IEEE80211_CHAN_DFS_CAC_DONE),
			(DBGEFMT "CAC_DONE marked prior to CAC completed\n", DBGARG));

	cac_timer = &qdrv_radar_cb.cac_timer;
	mod_timer(cac_timer, jiffies);
	DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR, "RADAR: CAC period will expire instantly\n");
}

unsigned long qdrv_get_cac_duration_jiffies(struct ieee80211com *ic,
	struct ieee80211_channel *channel)
{
	unsigned long duration;

	if (ieee80211_is_on_weather_channel(ic, channel))
		duration = CAC_WEATHER_PERIOD_EU;
	else
		duration = CAC_PERIOD;

	if (DBG_LOG_FUNC_TEST(QDRV_LF_DFS_QUICKTIMER)) {
		DBGPRINTF_N("RADAR: test mode - CAC period will expire quickly\n");
		duration = CAC_PERIOD_QUICK;
	}
	return duration;
}

/*
 * Start or restart the CAC procedure
 * - precondition: transmission is already disabled
 */
static void start_cac(void)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct ieee80211_channel *cur_chan = ic->ic_curchan;
	struct qdrv_wlan *qw = container_of(ic, struct qdrv_wlan, ic);
	struct timer_list *cac_timer = &qdrv_radar_cb.cac_timer;
	unsigned long expires;

	/* CAC not required for DFS slave */
	if (qdrv_is_dfs_slave() && !(ic->sta_dfs_info.sta_dfs_strict_mode))
		return;

	if (qdrv_radar_cb.cac_chan == cur_chan) {
		DBGPRINTF_W("RADAR: CAC continue on channel %u\n", cur_chan->ic_ieee);
		return;
	}

	/* stop cac if any */
	stop_cac();

	KASSERT(qdrv_radar_cb.cac_chan == NULL,
		(DBGEFMT "CAC channel is not null\n", DBGARG));

	if (cur_chan == IEEE80211_CHAN_ANYC) {
		DBGPRINTF_E("operational channel not yet selected\n");
		return;
	}

	/* save the operational channel into the control block */
	qdrv_radar_cb.cac_chan = cur_chan;
	cur_chan->ic_flags |= IEEE80211_CHAN_DFS_CAC_IN_PROGRESS;

	ic->ic_mark_channel_dfs_cac_status(ic, cur_chan,
			IEEE80211_CHAN_DFS_CAC_IN_PROGRESS, true);

	expires = qdrv_get_cac_duration_jiffies(ic, cur_chan) + jiffies;

	if (ic->ic_start_icac_procedure) {
		ic->ic_start_icac_procedure(ic);
	}
	mod_timer(cac_timer, expires);

	QDRV_SET_SM_FLAG(qw->sm_stats, QDRV_WLAN_SM_STATE_CAC_ACTIVE);
	DBGPRINTF_N_QEVT(ic2dev(ic), "RADAR: CAC started for channel %3d (%4d MHz)\n",
			 cur_chan->ic_ieee, cur_chan->ic_freq);
}

/*
 * Stop cac procedure
 */
static void raw_stop_cac(void)
{
	struct ieee80211_channel *chan = qdrv_radar_cb.cac_chan;
	struct timer_list *cac_timer = &qdrv_radar_cb.cac_timer;
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct qdrv_wlan *qw = container_of(ic, struct qdrv_wlan, ic);
	struct ieee80211vap *vap = ieee80211_get_primary_vap(ic, 0);

	if (!is_cac_started()) { /* no cac to stop */
		DBGPRINTF_E("CAC is not started\n");
		return;
	}

	del_timer(cac_timer);
	chan->ic_flags &= ~(IEEE80211_CHAN_DFS_CAC_DONE |
			IEEE80211_CHAN_DFS_CAC_IN_PROGRESS);

	ic->ic_mark_channel_dfs_cac_status(ic, chan,
			IEEE80211_CHAN_DFS_CAC_DONE, false);
	ic->ic_mark_channel_dfs_cac_status(ic, chan,
			IEEE80211_CHAN_DFS_CAC_IN_PROGRESS, false);

	QDRV_CLEAR_SM_FLAG(qw->sm_stats, QDRV_WLAN_SM_STATE_CAC_ACTIVE);
	DBGPRINTF_N_QEVT(ic2dev(ic), "RADAR: CAC stopped for channel %3d (%4d MHz)\n",
			 chan->ic_ieee, chan->ic_freq);

	/* no cac now */
	qdrv_radar_cb.cac_chan = NULL;
	/* take it as an channel switch failed event
	 * to satisfy the dfs reentry demon when it's waiting for the dfs reentry result */
	if (vap && vap->iv_dev)
		dfs_reentry_chan_switch_notify(vap->iv_dev, NULL);
}

void qdrv_set_dfs_available_channel(uint32_t dfs_available_channel)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct ieee80211_channel *chan = NULL;
	bool rdetect;

	if (!dfs_available_channel)
		return ;

	chan = ieee80211_find_channel_by_ieee(ic, dfs_available_channel);
	if (!chan) {
		DBGPRINTF_E("channel %d not found\n", dfs_available_channel);
		return;
	}

	rdetect = qdrv_radar_is_rdetection_required(chan);

	if  (qdrv_radar_cb.cac_chan == chan) {
		del_timer(&qdrv_radar_cb.cac_timer);
		cac_completed_action(0);
	} else if (rdetect) {
		if (ic->ic_mark_channel_availability_status) {
			ic->ic_mark_channel_availability_status(ic, chan, IEEE80211_CHANNEL_STATUS_AVAILABLE);
		}

		if (ic->ic_mark_channel_dfs_cac_status) {
			ic->ic_mark_channel_dfs_cac_status(ic, chan, IEEE80211_CHAN_DFS_CAC_DONE, true);
			ic->ic_mark_channel_dfs_cac_status(ic, chan, IEEE80211_CHAN_DFS_CAC_IN_PROGRESS, false);
		}
	}
}



static void stop_cac(void)
{
	if (is_cac_started())
		raw_stop_cac();
}

void qdrv_radar_stop_active_cac(void)
{
	if (!qdrv_radar_cb.enabled)
		return;

	if (is_cac_started()) {
		raw_stop_cac();
		DBGPRINTF(DBG_LL_INFO, QDRV_LF_RADAR, "%s: stop CAC\n", __func__);
	}
}

static void sta_dfs_strict_cac_action(struct ieee80211_channel *chan)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;

	if (!ic->sta_dfs_info.sta_dfs_strict_mode) {
		return;
	}

	if (!qdrv_radar_cb.enabled)
		return;

	if (ieee80211_is_chan_cac_required(chan)) {
		sys_disable_xmit(__func__);
		start_cac();
	} else if (ieee80211_is_chan_not_available(chan) || ieee80211_is_chan_available(chan)) {
		sys_enable_xmit(__func__);
	}
}

/*
 * The non-occupancy period expires
 * - the channel is now available for use
 */
static void nonoccupy_expire_action(unsigned long data)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	unsigned chan_idx = data;
	struct ieee80211_channel *chan;
	struct ieee80211vap *vap = ieee80211_get_primary_vap(ic, 0);

	KASSERT(chan_idx < ic->ic_nchans,
		(DBGEFMT "out-of-range channel idx %u\n", DBGARG, chan_idx));

	chan = &ic->ic_channels[chan_idx];
	chan->ic_flags &= ~IEEE80211_CHAN_RADAR;

	if (ic->ic_flags_qtn & IEEE80211_QTN_RADAR_SCAN_START) {
		if (ic->ic_initiate_scan) {
			ic->ic_initiate_scan(vap);
		}
	}

	/* Mark the channel as not_available and ready for cac */
	ic->ic_mark_channel_availability_status(ic, chan,
			IEEE80211_CHANNEL_STATUS_NOT_AVAILABLE_CAC_REQUIRED);

	if ((ic->sta_dfs_info.sta_dfs_strict_mode)
		&& (ic->ic_curchan == chan)) {
		TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
			if ((vap->iv_state != IEEE80211_S_RUN)
				&& (vap->iv_state != IEEE80211_S_SCAN)) {
				continue;
			}
			DBGPRINTF(DBG_LL_INFO, QDRV_LF_RADAR, "%s: Trigger scan\n", __func__);
			vap->iv_newstate(vap, IEEE80211_S_SCAN, 0);
		}
	}

        qdrv_radar_cb.nonoccupy_jiffies[chan_idx] = 0;
	DBGPRINTF_N_QEVT(ic2dev(ic), "RADAR: non-occupancy period expired for channel %3d "
			 "(%4d MHz)\n", chan->ic_ieee, chan->ic_freq);
}

#ifdef CONFIG_QHOP
static void rbs_radar_detected_timer_action(unsigned long chan_ic_ieee)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct ieee80211_channel *chan = ieee80211_find_channel_by_ieee(ic, chan_ic_ieee);

	ic->ic_mark_channel_availability_status(ic, chan,
			IEEE80211_CHANNEL_STATUS_NOT_AVAILABLE_RADAR_DETECTED);

	if (ic->ic_chan_compare_equality(ic, ic->ic_curchan, chan))
		sys_disable_xmit(__func__);

	DBGPRINTF(DBG_LL_INFO, QDRV_LF_RADAR, "%s expired\n", __func__);
}
#endif

static void sta_radar_detected_timer_action(unsigned long chan_ic_ieee)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct ieee80211_channel *chan = ieee80211_find_channel_by_ieee(ic, chan_ic_ieee);
	ic->sta_dfs_info.sta_dfs_radar_detected_timer = false;

	ic->ic_mark_channel_availability_status(ic, chan,
			IEEE80211_CHANNEL_STATUS_NOT_AVAILABLE_RADAR_DETECTED);

	if (ic->ic_chan_compare_equality(ic, ic->ic_curchan, chan))
		sys_disable_xmit(__func__);

	DBGPRINTF(DBG_LL_INFO, QDRV_LF_RADAR, "%s: sta_radar_timer expired\n", __func__);
}

static void sta_silence_timer_action(unsigned long data)
{
	struct ieee80211vap *vap = (struct ieee80211vap *)data;

	DBGPRINTF(DBG_LL_INFO, QDRV_LF_RADAR, "%s: sta_silence_timer expired\n", __func__);

	if (!vap || vap->iv_opmode != IEEE80211_M_STA)
		return;

	if (vap->iv_ic->ic_flags_ext2 & IEEE80211_FEXT2_NO_80211_SM) {
		qdrv_sta_set_xmit(true);
	} else {
		/*
		 * Scan process would set ioctl IEEE80211_PARAM_BEACON_ALLOW
		 * to allow all good beacons reception
		 */
		ieee80211_new_state(vap, IEEE80211_S_SCAN, 0);
	}
}

/*
 * Time to perform channel switch
 */
static void dfs_cs_timer_expire_action(unsigned long data)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct ieee80211vap *vap = ieee80211_get_primary_vap(ic, 1);

	if (!vap)
		return;

	if (is_dfs_cs_started()) {
		struct ieee80211_channel *chan = qdrv_radar_cb.dfs_des_chan;

		if (qdrv_radar_cb.dfs_des_chan != IEEE80211_CHAN_ANYC){
			DBGPRINTF_N_QEVT(ic2dev(ic), "RADAR: DFS channel switch to %3d (%4d MHz)\n",
					 chan->ic_ieee, chan->ic_freq);
			sys_change_chan(chan);
		} else {
			/* disable the transmission before starting the AP scan */
			sys_disable_xmit(__func__);

			/* no channel selected by radar module. Call Scanner */
			DBGPRINTF_N_QEVT(ic2dev(ic), "RADAR: starting AP scan due to radar "
					 "detection\n");
			(void) ieee80211_start_scan(vap, IEEE80211_SCAN_NO_DFS,
				IEEE80211_SCAN_FOREVER, 0, NULL);
		}

		qdrv_radar_cb.dfs_des_chan = NULL;
	}
}

/*
 * Start a DFS-triggered channel switch
 */
#ifndef CONFIG_QHOP
static void start_dfs_cs(struct ieee80211_channel *new_chan)
{
	struct timer_list *dfs_cs_timer = &qdrv_radar_cb.dfs_cs_timer;

	if (is_dfs_cs_started())
		stop_dfs_cs();

	qdrv_radar_cb.dfs_des_chan = new_chan;
	mod_timer(dfs_cs_timer, jiffies + DFS_CS_TIMER_VAL);
}
#endif

/*
 * Stop the DFS-triggered channel switch
 */
static void stop_dfs_cs()
{
	struct timer_list *dfs_cs_timer = &qdrv_radar_cb.dfs_cs_timer;

	if (is_dfs_cs_started()) {
		del_timer(dfs_cs_timer);
		qdrv_radar_cb.dfs_des_chan = NULL;
	}
}

static struct ieee80211_channel *qdrv_validate_fs_chan(int fast_switch, u_int8_t new_ieee)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct ieee80211_channel *chan = NULL;
	struct ieee80211_channel *new_chan = NULL;
	unsigned chan_idx;
	int flags = fast_switch ? IEEE80211_CHANNEL_CHECK_FASTSWITCH : 0;

	if (new_ieee == 0)
		return NULL;

	chan = ic->ic_channels;
	for (chan_idx = 0; chan_idx < ic->ic_nchans; chan_idx++, chan++) {
		if (chan->ic_ieee == new_ieee) {
			new_chan = chan;
			break;
		}
	}

	if (new_chan == NULL) {
		DBGPRINTF_E("channel %d not found\n", new_ieee);
	} else if (!ic->ic_check_channel(ic, chan, flags)) {
		DBGPRINTF_E("channel %d is not usable\n", new_ieee);
		new_chan = NULL;
	}

	return new_chan;
}

/*
 * Select a new channel to use
 * - according to FCC/ETSI rules on uniform spreading, we shall select a
 * channel out of the list of usable channels so that the probability
 * of selecting a given channel shall be the same for all channels
 * (reference: ETSI 301 893 v1.5.1 $4.7.2.6)
 * - possible for this function to return NULL
 * - a random channel can be returned if the specified channel is neither
 *	 found nor usable
 */
struct ieee80211_channel *qdrv_radar_select_newchan(u_int8_t new_ieee)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct ieee80211_channel *chan;
	struct ieee80211_channel *new_chan = NULL;
	unsigned chan_idx;
	int fast_switch = (ic->ic_flags_ext & IEEE80211_FEXT_DFS_FAST_SWITCH) != 0;
	int flags = fast_switch ? IEEE80211_CHANNEL_CHECK_FASTSWITCH : 0;

	/* check if we can switch to the user configured channel */
	new_chan = qdrv_validate_fs_chan(fast_switch, new_ieee);

	if ((new_chan == NULL) && (new_ieee != ic->ic_ieee_best_alt_chan))
		new_chan = qdrv_validate_fs_chan(fast_switch, ic->ic_ieee_best_alt_chan);

	/* select a random channel */
	if (new_chan == NULL) {
		unsigned count;
		chan = ic->ic_channels;
		for (count = 0, chan_idx = 0; chan_idx < ic->ic_nchans;
				chan_idx++, chan++) {
			if (ic->ic_check_channel(ic, chan, flags))
				count++;
		}

		if (count != 0) {
			unsigned rand = jiffies % count;

			chan = ic->ic_channels;
			for (count = 0, chan_idx = 0; chan_idx < ic->ic_nchans;
					chan_idx++, chan++) {
				if (ic->ic_check_channel(ic, chan, flags)) {
					if (count++ == rand) {
						new_chan = &ic->ic_channels[chan_idx];
						break;
					}
				}
			}
		}
	}

	if (new_chan) {
		chan = new_chan;
		new_chan = ieee80211_scs_switch_pri_chan(ic->ic_scan, new_chan);
		if (!new_chan) {
			DBGPRINTF_W("All subchannels are crowded with BSS,"
					" selected anyway\n");
			new_chan = chan;
		}
	}

	if (new_chan) {
		DBGPRINTF_N_QEVT(ic2dev(ic), "RADAR: new channel selected %d (%d MHz)\n",
				 new_chan->ic_ieee, new_chan->ic_freq);
	} else {
		DBGPRINTF_E("no valid channel found\n");
	}

	return new_chan;
}
EXPORT_SYMBOL(qdrv_radar_select_newchan);

/*
 * Perform the dfs related action after new channel has been selected
 */
static void
dfs_action_after_newchan_select(struct ieee80211_channel *new_chan,
	bool radar_detected_during_cac)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct ieee80211_channel *cur_chan = ic->ic_curchan;
	struct ieee80211vap *vap;

	if (new_chan == NULL) {
		vap = ieee80211_get_ap_vap(ic);
		if (vap == NULL)
			return;

		DBGPRINTF_E("new channel not found, start scan to re-select\n");
		dfs_reentry_chan_switch_notify(vap->iv_dev, new_chan);
		/* disable the transmission before starting the AP scan */
                sys_disable_xmit(__func__);
		/* no channel selected by radar module. Call Scanner */
		(void) ieee80211_start_scan(vap, IEEE80211_SCAN_NO_DFS,
			IEEE80211_SCAN_FOREVER, 0, NULL);
		return;
	}

#ifdef ARTSMNG_SUPPORT
	/*
	 * always enter CSA state to send CSA frames to WDS peers
	 * since this function only called after radar detection we call enter_csa
	 * with REASON_DFS flag
	 */
	ieee80211_enter_csa(TAILQ_FIRST(&ic->ic_vaps)->iv_ic, new_chan, NULL,
			IEEE80211_CSW_REASON_DFS,
			IEEE80211_DEFAULT_CHANCHANGE_TBTT_COUNT,
			IEEE80211_CSA_MUST_STOP_TX,
			IEEE80211_CSA_F_ACTION | IEEE80211_CSA_F_BEACON);
#else
	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
		if (vap->iv_opmode != IEEE80211_M_HOSTAP)
			continue;

		if (vap->iv_state != IEEE80211_S_RUN)
			continue;

		if (radar_detected_during_cac &&
				ic->rbs_mbs_dfs_info.rbs_mbs_allow_tx_frms_in_cac) {
			ic->rbs_mbs_dfs_info.mbs_allow_csa = true;
			sys_enable_xmit(__func__);
		}
		ieee80211_dfs_send_csa(vap, new_chan->ic_ieee);
	}
#endif /* ARTSMNG_SUPPORT */

	ic->ic_dfs_cce.cce_previous = cur_chan->ic_ieee;
	ic->ic_dfs_cce.cce_current = new_chan->ic_ieee;
}

static void
dfs_send_report_frame(struct ieee80211com *ic, struct ieee80211vap *vap) {
	struct ieee80211_node *ni;
	struct ieee80211_channel *cur_chan;
	struct ieee80211_meas_report_ctrl mreport_ctrl;
	struct ieee80211_action_data action_data;

	/* DFS enabled STA sends Autonomous Measurement Report Action Frame to AP*/
	if (vap == NULL)
		return;

	KASSERT(vap->iv_state == IEEE80211_S_RUN, (DBGEFMT "Radar send reprot "
			"frame, vap state incorrect: %d\n", DBGARG, vap->iv_state));

	memset(&mreport_ctrl, 0, sizeof(mreport_ctrl));
	memset(&action_data, 0, sizeof(action_data));
	ni = vap->iv_bss;
	cur_chan = ic->ic_curchan;

	mreport_ctrl.meas_type = IEEE80211_CCA_MEASTYPE_BASIC;
	mreport_ctrl.report_mode = 0;
	mreport_ctrl.autonomous = 1;
	mreport_ctrl.u.basic.channel = ieee80211_chan2ieee(ic, cur_chan);
	mreport_ctrl.u.basic.basic_report |= IEEE80211_MEASURE_BASIC_REPORT_RADAR;
	action_data.cat = IEEE80211_ACTION_CAT_SPEC_MGMT;
	action_data.action = IEEE80211_ACTION_S_MEASUREMENT_REPORT;
	action_data.params = &mreport_ctrl;
	ic->ic_send_mgmt(ni, IEEE80211_FC0_SUBTYPE_ACTION, (int)&action_data);
}

static void
dfs_slave_push_state_machine(struct ieee80211com *ic)
{
	struct ieee80211vap *vap;

	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
		if ((vap->iv_state != IEEE80211_S_RUN) &&
				(vap->iv_state != IEEE80211_S_SCAN)) {
			continue;
		}

		vap->iv_newstate(vap, IEEE80211_S_SCAN, 0);
	}

	ic->ic_chan_switch_reason_record(ic, IEEE80211_CSW_REASON_DFS);
}

static void
qdrv_ap_default_dfs_action(uint8_t new_ieee, bool radar_detected_during_cac)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct ieee80211_channel *new_chan = NULL;
	struct ieee80211vap *vap = ieee80211_get_ap_vap(ic);
	int icac_enabled = -1;

	if (vap == NULL)
		return;

	if (ic->ic_ap_next_cac)
		icac_enabled = ic->ic_ap_next_cac(ic, vap,
			CAC_PERIOD, &qdrv_radar_cb.cac_chan,
			IEEE80211_SCAN_PICK_NOT_AVAILABLE_DFS_ONLY);

	/*
	 * Default behavior for AP:
	 * If radar detected during ICAC, continue ICAC on next NOT_AVAILABLE_DFS channel
	 * If DFS fast switch configured, do random channel selection or fixed channel
	 * based on customer's configuration;
	 * If DFS fast switch not configured, use channel scan to pick up a best non-DFS channel
	 */
	if (icac_enabled < 0) {
		if (ic->ic_flags_ext & IEEE80211_FEXT_DFS_FAST_SWITCH) {
			/*
			 * select one channel at random
			 */
			new_chan = qdrv_radar_select_newchan(new_ieee);
			dfs_action_after_newchan_select(new_chan, radar_detected_during_cac);
		} else {
			/*
			 * Using channel scan to pick up a best non-DFS channel to switch
			 * Channel switch and DFS action will be done after scanning is done
			 */
			ieee80211_start_scan(vap, IEEE80211_SCAN_FLUSH | IEEE80211_SCAN_NO_DFS
					| IEEE80211_SCAN_DFS_ACTION, IEEE80211_SCAN_FOREVER,
					vap->iv_des_nssid, vap->iv_des_ssid);
		}
	}

	ic->ic_chan_switch_reason_record(ic, IEEE80211_CSW_REASON_DFS);
}

#ifdef CONFIG_QHOP
static void
dfs_send_qhop_report_frame(struct ieee80211com *ic, u_int8_t new_ieee)
{
	struct ieee80211vap *vap;

	/*
	 * If this is an RBS we send the reports to the MBS on the WDS link
	 * Note: We are assuming hub and spoke topology. For general tree or mesh
	 * much more sophisticated routing algorithm should be implemented
	 */
	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
		/* Note: We are assuming hub and spoke topology. For general tree or mesh */
		/* much more sophisticated routing algorithm should be implemented */
		if (IEEE80211_VAP_WDS_IS_RBS(vap)) {
			qdrv_qhop_send_rbs_report_frame(vap, new_ieee);
			return;
		}
	}
}
#endif

static int ieee80211_get_chan_idx_from_chan(struct ieee80211com *ic, int chan_ic_ieee)
{
	int chan_idx;

	for (chan_idx = 0; chan_idx < ic->ic_nchans; chan_idx++) {
		if (ic->ic_channels[chan_idx].ic_ieee == chan_ic_ieee)
			return chan_idx;
	}

	return -1;
}

static int ieee80211_get_first_nop_timer_ref_from_chan(struct ieee80211com *ic,
	struct ieee80211_channel *chan)
{
	int i;
	int nchan_idx = -1;
	struct ieee80211_channel *chan_list[IEEE80211_MAX_CHANNELS_IN_BW(BW_HT80)] = {NULL};

	if (NULL == chan)
		return -1;

	ic->ic_get_full_bss_chan(ic, chan, chan_list, BW_HT80);

	for (i = 0; i < IEEE80211_MAX_CHANNELS_IN_BW(BW_HT80); i++) {
		if (chan_list[i] && ieee80211_is_chan_radar_detected(chan_list[i])) {
			nchan_idx = ieee80211_get_chan_idx_from_chan(ic, chan_list[i]->ic_ieee);
			if ((nchan_idx >= 0) && qdrv_radar_cb.nonoccupy_jiffies[nchan_idx])
				return nchan_idx;
		}
	}

	return -1;
}

/*
 * Sets one nop timer for @chan_list
 */
void ieee80211_reset_nop_timers(struct ieee80211com *ic, struct ieee80211_channel *chan,
		struct ieee80211_channel *chan_list[], int cur_bw)
{
	int i;
	int nchan_idx = -1;
	int nop_count = 0;
	int radar_channel_count = 0;
	int recent_nop_chan_idx = -1;
	unsigned long recent_nop = 0;
	unsigned long nop_timer_ts = 0;
	int no_of_sub_channels = IEEE80211_MAX_CHANNELS_IN_BW(cur_bw);

	for (i = 0; i < no_of_sub_channels; i++) {
		if (chan_list[i]) {
			nop_timer_ts = 0;
			nchan_idx = ieee80211_get_chan_idx_from_chan(ic, chan_list[i]->ic_ieee);
			if (nchan_idx >= 0)
				nop_timer_ts = qdrv_radar_cb.nonoccupy_jiffies[nchan_idx];

			if (nop_timer_ts) {
				if (nop_timer_ts > recent_nop) {
					recent_nop = nop_timer_ts;
					recent_nop_chan_idx = nchan_idx;
				}
				nop_count++;
			}

			if (ieee80211_is_chan_radar_detected(chan_list[i]))
				radar_channel_count++;
		}
	}

	/* This occurs when bw changed from lower-->higher */
	if (nop_count > 1) {
		/* Cancel all nop timers other than recent one */
		for (i = 0; i < no_of_sub_channels; i++) {
			nchan_idx = ieee80211_get_chan_idx_from_chan(ic, chan_list[i]->ic_ieee);
			if ((nchan_idx >= 0) && (recent_nop_chan_idx != nchan_idx)) {
				if (qdrv_radar_cb.nonoccupy_jiffies[nchan_idx]) {
					del_timer(&qdrv_radar_cb.nonoccupy_timer[nchan_idx]);
					qdrv_radar_cb.nonoccupy_jiffies[nchan_idx] = 0;
				}
			}
		}
		return;
	}

	/* This occurs when bw changed from higher-->lower */
	if ((!nop_count) && (radar_channel_count)) {
		int nop_ref_idx = ieee80211_get_first_nop_timer_ref_from_chan(ic, chan);

		if (nop_ref_idx >= 0) {
			nchan_idx = ieee80211_get_chan_idx_from_chan(ic, chan->ic_ieee);
			if ((nchan_idx >= 0) && !qdrv_radar_cb.nonoccupy_jiffies[nchan_idx]) {
				mod_timer(&qdrv_radar_cb.nonoccupy_timer[nchan_idx],
						qdrv_radar_cb.nonoccupy_jiffies[nop_ref_idx] +
						ic->ic_non_occupancy_period);
				qdrv_radar_cb.nonoccupy_jiffies[nchan_idx] = jiffies;
			}
		}
		return;
	}
}
EXPORT_SYMBOL(ieee80211_reset_nop_timers);

static void
qdrv_rbs_report_radar(uint8_t new_ieee, bool radar_detected_during_cac)
{
#ifdef CONFIG_QHOP
	struct ieee80211com *ic = qdrv_radar_cb.ic;

	if (ic->ic_extender_role != IEEE80211_EXTENDER_ROLE_RBS)
		return;

	if (radar_detected_during_cac &&
			ic->rbs_mbs_dfs_info.rbs_mbs_allow_tx_frms_in_cac) {
		ic->rbs_mbs_dfs_info.rbs_allow_qhop_report = true;
		sys_enable_xmit(__func__);
	}

	ic->rbs_mbs_dfs_info.rbs_dfs_radar_timer.data = ic->ic_curchan->ic_ieee;
	mod_timer(&ic->rbs_mbs_dfs_info.rbs_dfs_radar_timer, (jiffies +
		IEEE80211_MS_TO_JIFFIES(ic->rbs_mbs_dfs_info.rbs_dfs_tx_chan_close_time)));

	dfs_send_qhop_report_frame(ic, new_ieee);
#endif
}

static void
qdrv_dfs_report_radar(bool radar_detected_during_cac)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct ieee80211vap *vap = ieee80211_get_sta_vap(ic);
	uint32_t repeater_mode = ieee80211_is_repeater(ic);
	int enable_xmit;

	if (!qdrv_is_dfs_slave() && !repeater_mode)
		return;

	enable_xmit = ic->sta_dfs_info.sta_dfs_strict_mode &&
			ic->sta_dfs_info.sta_dfs_strict_msr_cac &&
			radar_detected_during_cac;

	/*
	 * Inform associated AP radar is detected in assoication state
	 */
	if (vap && vap->iv_state == IEEE80211_S_RUN) {
		if ((qdrv_radar_cb.xmit_stopped == true)
				&& !enable_xmit) {
			DBGPRINTF(DBG_LL_WARNING, QDRV_LF_RADAR,
					"%s report radar failed\n",
					repeater_mode ? "Repeater" : "STA");
		} else {
			DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR,
					"%s report radar to master\n",
					repeater_mode ? "Repeater" : "STA");

			if (enable_xmit) {
				DBGPRINTF_N_QEVT(vap->iv_dev,
					"STA-DFS: Sending measurement frame during CAC\n");
				sys_enable_xmit(__func__);
				ic->sta_dfs_info.allow_measurement_report = true;
			}

			dfs_send_report_frame(ic, vap);
			if (qdrv_radar_sta_dfs || repeater_mode)
				return;
		}
	}

	/*
	 * In disassociation state, STA's default DFS action is to enter SCAN state
	 */
	if (!repeater_mode)
		dfs_slave_push_state_machine(ic);
}

/*
 * Perform the dfs action including channel switch.
 */
static void dfs_action(uint8_t new_ieee, bool radar_detected_during_cac)
{
	/* RBS informs MBS radar is detected */
	qdrv_rbs_report_radar(new_ieee, radar_detected_during_cac);

	/* DFS device informs parent device radar is detected */
	qdrv_dfs_report_radar(radar_detected_during_cac);

	/* Select an alternative channel and switch channel */
	qdrv_ap_default_dfs_action(new_ieee, radar_detected_during_cac);
}

void qdrv_dfs_action_scan_done(void)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct ieee80211_channel *new_chan = NULL;

	IEEE80211_LOCK_IRQ(ic);
	new_chan = ieee80211_scan_pickchannel(ic, IEEE80211_SCAN_NO_DFS);
	IEEE80211_UNLOCK_IRQ(ic);

	dfs_action_after_newchan_select(new_chan, false);
}

/*
 * Decide whether or not to detect radar on the channel
 */
bool qdrv_radar_is_rdetection_required(const struct ieee80211_channel *chan)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	bool rdetect = false;
	bool doth = ic->ic_flags & IEEE80211_F_DOTH;

	if (DBG_LOG_FUNC_TEST(QDRV_LF_DFS_DONTCAREDOTH)) {
		DBGPRINTF_N("RADAR: test mode - detection enabled\n");
		doth = true;
	}

	if (doth) {
		if (chan == IEEE80211_CHAN_ANYC) {
			DBGPRINTF_E("channel not yet set\n");
			return false;
		}

		if (chan->ic_flags & IEEE80211_CHAN_DFS)
			rdetect = true;
	}

	return rdetect;
}

static int32_t qdrv_radar_off_chan_cac_action(struct ieee80211com *ic)
{
	uint8_t ocac_scan_chan = qdrv_radar_cb.ocac_last_chan;

	if (qdrv_is_dfs_slave())
		return -EINVAL;

	if (ieee80211_is_repeater(ic))
		return -EINVAL;

	if (qdrv_radar_cb.region == DFS_RQMT_US) {
		DBGPRINTF_N_QEVT(ic2dev(ic), "RADAR: radar found on channel %u during CAC\n",
				 ocac_scan_chan);
	} else {
		DBGPRINTF_N_QEVT(ic2dev(ic), "RADAR: radar found on off channel %u, current "
				 "chan %u\n", ocac_scan_chan, ic->ic_curchan->ic_ieee);
	}

	return ocac_scan_chan;
}

/*
 * Invoked when a radar is detected.
 * Called directly from iwpriv wifi0 doth_radar <new channel>.
 * Called when AP receives a radar detection report from an associated STA.
 */
void qdrv_radar_detected(struct ieee80211com *ic, u_int8_t new_ieee)
{
	uint8_t local_new_ieee = new_ieee;
	uint32_t chan_idx;
	struct ieee80211_channel *cur_chan;
	struct ieee80211_channel *chan = NULL;
	struct ieee80211vap *vap = ieee80211_get_primary_vap(ic, 1);
	bool rdetect;
	int rdetect_flag_set;
	int32_t radar_chan;
	bool radar_detected_during_cac = is_cac_started();

	if (!vap)
		return;

	if (!qdrv_radar_configured) {
		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR, "radar not initialized\n");
		return;
	}

	if (!qdrv_radar_cb.enabled) {
		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR, "radar not enabled\n");
		return;
	}

	if (ic != qdrv_radar_cb.ic) {
		DBGPRINTF_E("ic 0x%p not matching the configured ic 0x%p\n",
			ic, qdrv_radar_cb.ic);
		return;
	}

	/* stop cac if any */
	stop_cac();

	if (qdrv_is_dfs_slave() && !qdrv_radar_sta_dfs) {
		DBGPRINTF_E("ic mode is %d and sta dfs is %s\n", ic->ic_opmode,
				qdrv_radar_sta_dfs ? "enabled" : "disabled");
		return;
	}

	/*
	 * we need to consider the radar detection events during scan even if they occur outside of home channel
	 * because there is a case that the radar detection interrupt occurs after scan channel change,
	 * but radar belongs to home channel.
	 * use ic_des_chan instead of ic_curchan which is the corect one while scanning
	 */
	cur_chan = ((ic->ic_flags & IEEE80211_F_SCAN) && (ic->ic_des_chan != IEEE80211_CHAN_ANYC))
			? ic->ic_des_chan : ic->ic_curchan;

	rdetect = qdrv_radar_is_rdetection_required(cur_chan);

	if (!rdetect) {
		/* detect radar during off channel CAC */
		if (!ic->ic_ocac.ocac_chan) {
			DBGPRINTF_E("radar operating channel %u invalid\n", ic->ic_curchan->ic_ieee);
			return;
		}
		radar_chan = qdrv_radar_off_chan_cac_action(ic);
	} else {
		radar_chan = cur_chan->ic_ieee;
	}

	if (radar_chan < 0) {
		DBGPRINTF_E("radar operating channel invalid\n");
		return;
	}

	/* get an in-service channel */
	for (chan_idx = 0; chan_idx < ic->ic_nchans; chan_idx++) {
		if (ic->ic_channels[chan_idx].ic_ieee == radar_chan) {
			chan = &ic->ic_channels[chan_idx];
			break;
		}
	}
	if (!chan) {
		DBGPRINTF_E("no matching in-service channel for freq=%d\n",
				cur_chan->ic_freq);
		return;
	}
	KASSERT((chan->ic_flags & IEEE80211_CHAN_DFS), (DBGEFMT "Radar"
				" detected on non-DFS channel\n", DBGARG));
	DBGPRINTF_N_QEVT(ic2dev(ic), "RADAR: radar found on channel %3d (%4d MHz)\n",
			 chan->ic_ieee, chan->ic_freq);

	/*
	 * To avoid repeated dfs actions when AP and STAs detected
	 * same radar, test flag here. (only for AP side)
	 */
	if (!qdrv_radar_is_test_mode()) {
		if ((chan->ic_flags & IEEE80211_CHAN_RADAR) &&
				!(ic->sta_dfs_info.sta_dfs_strict_mode)) {
			DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR,
					"DFS already marked on channel %3d (%4d MHz)\n",
					chan->ic_ieee, chan->ic_freq);
			return;
		}
	}

	/* check if dfs marking is allowed */
	if (!(ic->ic_flags_ext & IEEE80211_FEXT_MARKDFS)) {
		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR, "DFS marking disabled\n");
		return;
	}

	/* set radar found flag */
	rdetect_flag_set = qdrv_radar_set_detect_flag(chan_idx);

	/* return immediately if we are in the dfs test mode */
	if (qdrv_radar_is_test_mode()) {
		DBGPRINTF(DBG_LL_CRIT, QDRV_LF_RADAR | QDRV_LF_DFS_TESTMODE,
				"test mode - no DFS action taken\n");
		if (qdrv_radar_test_mode_csa_en() && qdrv_is_dfs_master()) {
			DBGPRINTF(DBG_LL_CRIT, QDRV_LF_RADAR | QDRV_LF_DFS_TESTMODE,
					"send CSA action\n");
			ieee80211_dfs_send_csa(vap, ic->ic_curchan->ic_ieee);
		}
		return;
	}

	/* Start non-occupancy timer if needed */
	if (rdetect_flag_set)
		start_nonoccupy(chan_idx);

	/*
	 * should stop an ongoing scan if radar found during scan to take the dfs action.
	 * otherwise it is ignored
	 */
	ieee80211_cancel_scan_no_wait(vap);

	/* OCAC do not required for DFS actions */
	if (!rdetect) {
		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR,
				"OCAC DFS: no DFS action taken\n");
		return;
	}

	/* disable radar detection to avoid redundant detection */
	sys_disable_rdetection();

	if (local_new_ieee == 0 && ic->ic_ieee_alt_chan != 0)
		local_new_ieee = ic->ic_ieee_alt_chan;

#if defined(CONFIG_QTN_BSA_SUPPORT)
	if (IEEE80211_XCAC_CAC_EVENT_EN(ic)) {
		ieee80211_qrpe_send_event_xcac_status_update(vap, IEEE80211_QRPE_XCAC_COMPLETED,
			radar_chan, IEEE80211_QRPE_CHAN_STATUS_NOT_AVAILABLE_RADAR_DETECTED);
		if ((ic->ic_xcac_req_flags & IEEE80211_XCAC_FLAG_ACT_RETURN) &&
				is_ieee80211_chan_valid(ic->ic_xcac_return_chan))
			local_new_ieee = ic->ic_xcac_return_chan->ic_ieee;
		ic->ic_xcac_req_flags = 0;
	}
#endif
	/* take a dfs action */
	dfs_action(local_new_ieee, radar_detected_during_cac);
}

/*
 * Invoked when radar is detected
 * - a callback function registered to the radar module
 */
void qdrv_radar_mark_radar(void)
{
	qdrv_radar_detected(qdrv_radar_cb.ic, 0);
}

/*
 * Invoked when new radar samples are ready.
 * Samples are accessed via shared_params.
 */
void qdrv_radar_handle_samples(size_t size)
{
	struct shared_params *sp = qtn_mproc_sync_shared_params_get();

	if (!size)
		return;

	rmb();

	WARN_ON(size != sp->radar_lhost->samples.size);

	if (qdrv_radar_cb.stats_handler)
		qdrv_radar_cb.stats_handler(qdrv_radar_cb.stats_handler_arg,
					    sp->radar_lhost->samples.data,
					    sp->radar_lhost->samples.size);

	sp->radar_lhost->samples.size = 0;
	wmb();
}

void qdrv_radar_register_statcb(radar_stats_handler_t handler, void *arg)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct qdrv_wlan *qw = container_of(ic, struct qdrv_wlan, ic);

	if (!qdrv_radar_cb.stats_handler && handler) {
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_SAMPLES_STAT_EN, 1);
		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR, "Radar samples collection enabled\n");
	} else if (qdrv_radar_cb.stats_handler && !handler) {
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_SAMPLES_STAT_EN, 0);
		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR, "Radar samples collection disabled\n");
	}

	qdrv_radar_cb.stats_handler = handler;
	qdrv_radar_cb.stats_handler_arg = arg;
}

int qdrv_radar_test_mode_enabled(void)
{
	if (qdrv_radar_cb.enabled && qdrv_radar_is_test_mode())
		return 1;

	return 0;
}

/*
 * Check if safe to perform channel sampling
 * Returns 1 if OK, else 0.
 */
int qdrv_radar_can_sample_chan(void)
{
	if ((qdrv_radar_cb.enabled != 0) &&
		is_cac_started()) {
		return 0;
	}

	if (qdrv_radar_test_mode_enabled()) {
		return 0;
	}

	return 1;
}

int qdrv_radar_require_sta_slient(struct ieee80211com *ic)
{
	if (!qdrv_radar_cb.enabled)
		return 1;

	if (qdrv_is_dfs_slave() && qdrv_radar_sta_dfs &&
			!ic->sta_dfs_info.sta_dfs_strict_mode)
		return 1;

	return 0;
}

/*
 * Take appropriate action(s) right before channel switch
 */
void qdrv_radar_before_newchan(void)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct qdrv_wlan *qw = container_of(ic, struct qdrv_wlan, ic);
	struct ieee80211_channel *new_chan = NULL;
	struct ieee80211vap *sta_vap = NULL;
	char message[100] = {'\0'};
	int silence_period;
	int sta_slient;
	bool rdetect;

	/* now safe to set 'new_chan' */
	new_chan = ic->ic_curchan;

	/* check if the new channel requires radar detection */
	rdetect = qdrv_radar_is_rdetection_required(new_chan);
	sta_slient = qdrv_radar_require_sta_slient(ic);

	DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR,
		"Require_sta_silent %s, before new channel %3d (%4d MHz)"
		" with DFS %s (F_DOTH %d, CHAN_DFS %d) \n",
		sta_slient ? "Yes" : "No",
		new_chan->ic_ieee, new_chan->ic_freq,
		(rdetect) ? "enabled" : "disabled",
		(ic->ic_flags & IEEE80211_F_DOTH) ? 1 : 0 ,
		(new_chan->ic_flags & IEEE80211_CHAN_DFS) ? 1 : 0);

	if (sta_slient) {
		sta_vap = ieee80211_get_sta_vap(ic);
		if (!sta_vap) {
			DBGPRINTF(DBG_LL_ERR, QDRV_LF_RADAR,
				"Radar disabled in non STA mode\n");
			return;
		}

		if (rdetect && !IEEE80211_IS_CHAN_CACDONE(new_chan)) {
			snprintf(message, sizeof(message),
					"%s STA handle DFS", __func__);
			sys_disable_xmit(message);

			ieee80211_sta_allow_beacon_reception(sta_vap, 1);

			if (ieee80211_is_on_weather_channel(ic, new_chan))
				silence_period = STA_WEATHER_CHAN_SILENCE_PERIOD;
			else
				silence_period = STA_SILENCE_PERIOD;

			ic->sta_dfs_info.sta_silence_timer.data =
					(unsigned long)sta_vap;
			mod_timer(&ic->sta_dfs_info.sta_silence_timer,
					jiffies + silence_period);

			DBGPRINTF(DBG_LL_INFO, QDRV_LF_RADAR, "Make STA silent %u s"
				" before receive frames on DFS channel\n",
				silence_period / HZ);
		} else if (timer_pending(&ic->sta_dfs_info.sta_silence_timer)) {
			del_timer(&ic->sta_dfs_info.sta_silence_timer);
			ieee80211_sta_allow_beacon_reception(sta_vap, 0);
		}

		return;
	}

	if (ic->ic_flags & IEEE80211_F_SCAN) {
		if (is_cac_started()) {
			/* The ongoing CAC is invalid since channel scan is running */
			qdrv_radar_cb.cac_chan->ic_flags &=
				~IEEE80211_CHAN_DFS_CAC_IN_PROGRESS;
			ic->ic_mark_channel_dfs_cac_status(ic, qdrv_radar_cb.cac_chan,
				IEEE80211_CHAN_DFS_CAC_IN_PROGRESS, false);
		}
	} else {
		/* stop cac if any */
		stop_cac();

		/* other channel switches override the DFS-triggered one */
		if (is_dfs_cs_started() &&
				(qdrv_radar_cb.dfs_des_chan != new_chan)) {
			stop_dfs_cs();
		}
	}

	if (rdetect) {
		QDRV_SET_SM_FLAG(qw->sm_stats, QDRV_WLAN_SM_STATE_RADAR_ACT);
		if (qdrv_radar_cb.enabled || qdrv_is_dfs_master() ||
				ic->sta_dfs_info.sta_dfs_strict_mode) {
			snprintf(message, sizeof(message),
					"%s need to handle DFS", __func__);
			sys_disable_xmit(message);
		}
		sys_disable_rdetection();
	} else {
		QDRV_CLEAR_SM_FLAG(qw->sm_stats, QDRV_WLAN_SM_STATE_RADAR_ACT);
	}
}

void qdrv_radar_enable_radar_detection(void)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;

	if (!qdrv_radar_cb.enabled)
		return;

	if (ic->ic_flags & IEEE80211_F_SCAN)
		return;

	if (qdrv_radar_is_rdetection_required(ic->ic_curchan)) {
		qdrv_radar_set_chan(ic->ic_curchan->ic_ieee);
		if (!qdrv_radar_get_status()) {
			if (ic->ic_pm_state[QTN_PM_CURRENT_LEVEL] < BOARD_PM_LEVEL_DUTY)
				sys_enable_rdetection();
		}
	}
}

/*
 * Decide what to do on the new channel
 */
void qdrv_radar_on_newchan(void)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct ieee80211_channel *new_chan = NULL;
	struct ieee80211vap *sta_vap = NULL;
	char message[100] = {'\0'};
	bool rdetect;
        int handle_cac = 0;

	if (!is_ieee80211_chan_valid(ic->ic_curchan))
		return;

	new_chan = ic->ic_curchan;

	rdetect = qdrv_radar_is_rdetection_required(new_chan);

	/* log a new channel info */
	DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR,
		"now on channel %3d (%4d MHz) with DFS %s (F_DOTH %d, CHAN_DFS %d)\n",
		new_chan->ic_ieee, new_chan->ic_freq,
		(rdetect) ? "enabled" : "disabled",
		(ic->ic_flags & IEEE80211_F_DOTH) ? 1 : 0 ,
		(new_chan->ic_flags & IEEE80211_CHAN_DFS) ? 1 : 0);

	if (ic->ic_flags & IEEE80211_F_SCAN) {
		if (!rdetect || IEEE80211_IS_CHAN_CACDONE(new_chan)) {
			snprintf(message, sizeof(message),
				"%s non-DFS channel or CAC done", __func__);
			sys_enable_xmit(message);
		}

		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR,
				"Skip DFS action as scan in process\n");
		return;
	}

	if (!qdrv_radar_cb.enabled) {
		if (!rdetect) {
			snprintf(message, sizeof(message),
				"%s DFS disabled", __func__);
			sys_enable_xmit(message);
		}

		sta_vap = ieee80211_get_sta_vap(ic);
		if (!sta_vap)
			DBGPRINTF(DBG_LL_ERR, QDRV_LF_RADAR,
				"Radar disabled in non STA mode\n");

		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR,
				"Skip DFS action as Radar disabled\n");
		return;
	}

	/* report new channel to the radar module */
	qdrv_radar_set_chan(new_chan->ic_ieee);

	if (rdetect) {
		handle_cac = !(IEEE80211_IS_CHAN_CACDONE(new_chan)) &&
			!(IEEE80211_IS_CHAN_CAC_IN_PROGRESS(new_chan)) &&
			!(IEEE80211_IS_CHAN_RADAR(new_chan));

		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR,
				"Channel %u cacdone %u cac_in_progress %u\n",
				new_chan->ic_ieee, IEEE80211_IS_CHAN_CACDONE(new_chan),
				IEEE80211_IS_CHAN_CAC_IN_PROGRESS(new_chan));

		if (new_chan->ic_flags & IEEE80211_CHAN_DFS_OCAC_DONE) {
			DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR,  "Seamless CAC completed "
					"and no action needed\n");
			snprintf(message, sizeof(message), "%s OCAC DONE", __func__);
			sys_enable_xmit(message);
			new_chan->ic_flags |= IEEE80211_CHAN_DFS_CAC_DONE;

			ic->ic_mark_channel_availability_status(ic,
				new_chan, IEEE80211_CHANNEL_STATUS_AVAILABLE);

			ic->ic_mark_channel_dfs_cac_status(ic,
				new_chan, IEEE80211_CHAN_DFS_CAC_DONE, true);
		} else if (qdrv_is_dfs_master()) {
			DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR,
					"DFS Master starts DFS action\n");
			if (handle_cac) {
				start_cac();
			} else if (ieee80211_is_chan_available(new_chan)) {
				snprintf(message, sizeof(message), "%s CAC done", __func__);
				sys_enable_xmit(message);
			}
		} else if (ic->sta_dfs_info.sta_dfs_strict_mode) {
			DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR,
					"Strict STA DFS starts DFS action\n");
			sta_dfs_strict_cac_action(new_chan);
		}

		if (!qdrv_radar_get_status()) {
			if (ic->ic_pm_state[QTN_PM_CURRENT_LEVEL] < BOARD_PM_LEVEL_DUTY)
				sys_enable_rdetection();
		}
	} else {
		snprintf(message, sizeof(message), "%s non-DFS channel", __func__);
		sys_enable_xmit(message);
		sys_disable_rdetection();
	}
}

void qdrv_sta_dfs_enable(int sta_dfs_enable)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	bool rdetect;

	if (!qdrv_radar_configured)
		return;

	if (qdrv_radar_first_call)
		return;

	if (qdrv_is_dfs_master())
		return;

	if (qdrv_is_dfs_slave() && !qdrv_radar_sta_dfs)
		return;

	if (sta_dfs_enable) {
		rdetect = qdrv_radar_is_rdetection_required(ic->ic_bsschan);
		if (rdetect)
			qdrv_radar_set_chan(ic->ic_bsschan->ic_ieee);

		qdrv_radar_enable_action();

		DBGPRINTF(DBG_LL_CRIT, QDRV_LF_RADAR, "Station DFS enable\n");
	} else {
		qdrv_radar_disable();

		DBGPRINTF(DBG_LL_CRIT, QDRV_LF_RADAR, "Station DFS disable\n");
	}
}

/*
 * Enable DFS feature
 */
void qdrv_radar_enable(const char *region)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct shared_params *sp = qtn_mproc_sync_shared_params_get();

	if (!qdrv_radar_configured) {
		DBGPRINTF_E("radar unconfigured\n");
		return;
	}

	if (qdrv_radar_cb.enabled) {
		DBGPRINTF(DBG_LL_INFO, QDRV_LF_RADAR, "radar already enabled\n");
		return;
	} else if (strcmp(region, "ru") == 0) {
		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR,
			"no DFS / radar requirement for regulatory region Russia\n");
		return;
	}

	ieee80211_ocac_update_params(ic, region);

	if (qdrv_radar_first_call) {
		if (!sys_start_radarmod(region)) {
			DBGPRINTF_E("Fail to start radar\n");
			return;
		}
		qdrv_radar_first_call = false;
		qdrv_radar_cb.region = dfs_rqmt_code(region);
		qdrv_radar_sta_dfs = sp->radar_lhost->sta_dfs;
	}

	if (qdrv_radar_cb.enabled == true) {
		DBGPRINTF_E("re-enabling radar is not supported - reboot\n");
		/* for future work of re-enabling radar
		sys_stop_radarmod();
		sys_start_radarmod(region);
		 */
	} else {
		qdrv_radar_enable_action();
	}
}

struct ieee80211_channel * qdrv_radar_get_current_cac_chan(void)
{
	return  qdrv_radar_cb.cac_chan;
}
EXPORT_SYMBOL(qdrv_radar_get_current_cac_chan);

bool qdrv_dfs_is_eu_region(void)
{
	return qdrv_radar_cb.region == DFS_RQMT_EU;
}
EXPORT_SYMBOL(qdrv_dfs_is_eu_region);

int qdrv_dfs_is_us_region(void)
{
	return (qdrv_radar_cb.region == DFS_RQMT_US);
}
EXPORT_SYMBOL(qdrv_dfs_is_us_region);

int qdrv_dfs_is_jp_region(void)
{
	return qdrv_radar_cb.region == DFS_RQMT_JP;
}
EXPORT_SYMBOL(qdrv_dfs_is_jp_region);

int qdrv_dfs_is_cl_region(void)
{
	return qdrv_radar_cb.region == DFS_RQMT_CL;
}
EXPORT_SYMBOL(qdrv_dfs_is_cl_region);

int qdrv_dfs_is_br_region(void)
{
	return qdrv_radar_cb.region == DFS_RQMT_BR;
}
EXPORT_SYMBOL(qdrv_dfs_is_br_region);

int qdrv_dfs_is_region_set(void)
{
	return qdrv_radar_cb.region != DFS_RQMT_UNKNOWN;
}
EXPORT_SYMBOL(qdrv_dfs_is_region_set);

int qdrv_dfs_is_status_save_region(void)
{
	return (qdrv_dfs_is_eu_region() || qdrv_dfs_is_cl_region() || qdrv_dfs_is_br_region());
}
EXPORT_SYMBOL(qdrv_dfs_is_status_save_region);

int qdrv_dfs_is_icac_supp_region(void)
{
	return (qdrv_dfs_is_eu_region() || qdrv_dfs_is_cl_region() || qdrv_dfs_is_br_region());
}
EXPORT_SYMBOL(qdrv_dfs_is_icac_supp_region);

int radar_pm_notify(struct notifier_block *b, unsigned long level, void *v)
{
	static int pm_prev_level = BOARD_PM_LEVEL_NO;
	const int switch_level = BOARD_PM_LEVEL_DUTY;
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct ieee80211_channel *operate_chan;
	bool rdetect;

	if (!qdrv_radar_cb.enabled)
		goto out;

	operate_chan = ic->ic_bsschan;
	rdetect = qdrv_radar_is_rdetection_required(operate_chan);

	if (rdetect) {
		if ((pm_prev_level < switch_level) && (level >= switch_level)) {
			sys_disable_rdetection();
		} else if ((pm_prev_level >= switch_level) && (level < switch_level)) {
			qdrv_radar_set_chan(ic->ic_bsschan->ic_ieee);
			sys_enable_rdetection();
		}
	}

out:
	pm_prev_level = level;
        return NOTIFY_OK;
}

static void qdrv_ocac_irqhandler(void *arg1, void *arg2)
{
	struct qdrv_wlan *qw = arg1;
	struct ieee80211com *ic = &qw->ic;
	struct shared_params *sp = qtn_mproc_sync_shared_params_get();
	struct qtn_ocac_info *ocac_info = sp->ocac_lhost;

	if (ocac_info->chan_status == QTN_OCAC_ON_OFF_CHAN)
		ic->ic_ocac.ocac_counts.intr_off_chan++;
	else
		ic->ic_ocac.ocac_counts.intr_data_chan++;

	qdrv_radar_ocac_handler();
}

static int qdrv_init_ocac_irqhandler(struct qdrv_wlan *qw)
{
	struct int_handler int_handler;

	int_handler.handler = qdrv_ocac_irqhandler;
	int_handler.arg1 = qw;
	int_handler.arg2 = NULL;

	if (qdrv_mac_set_handler(qw->mac, RUBY_M2L_IRQ_LO_OCAC, &int_handler) != 0) {
		DBGPRINTF_E("Could not set ocac irq handler\n");
		return -1;
	}

	return 0;
}


/* Put data into proc file */
static int qdrv_radar_proc_read(char *buffer, char **buffer_location, off_t offset,
				int buffer_length, int *eof, void *data)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct qdrv_wlan *qw = container_of(ic, struct qdrv_wlan, ic);
	size_t len = 0;
	int res;

	res = qdrv_hostlink_radar_get_str(qw, buffer, RADAR_STRING_SUMMARY, &len,
					  QDRV_RADAR_PROC_SIZE);

	if ((res < 0) || (res & (QTN_HLINK_RC_ERR)))
		return 0;

	return len;
}

static int qdrv_radar_pulse_proc_read(char *buffer, char **buffer_location, off_t offset,
				      int buffer_length, int *eof, void *data)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct qdrv_wlan *qw = container_of(ic, struct qdrv_wlan, ic);
	size_t len = 0;
	int res;

	res = qdrv_hostlink_radar_get_str(qw, buffer, RADAR_STRING_PULSE, &len,
					  QDRV_RADAR_PROC_SIZE);

	if ((res < 0) || (res & (QTN_HLINK_RC_ERR)))
		return 0;

	return len;
}

static int qdrv_radar_zc_proc_read(char *buffer, char **buffer_location, off_t offset,
				   int buffer_length, int *eof, void *data)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct qdrv_wlan *qw = container_of(ic, struct qdrv_wlan, ic);
	size_t len = 0;
	int res;

	res = qdrv_hostlink_radar_get_str(qw, buffer, RADAR_STRING_ZC, &len,
					  QDRV_RADAR_PROC_SIZE);

	if ((res < 0) || (res & (QTN_HLINK_RC_ERR)))
		return 0;

	return len;
}

static int qdrv_radar_ocac_proc_read(char *buffer, char **buffer_location, off_t offset,
				     int buffer_length, int *eof, void *data)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct qdrv_wlan *qw = container_of(ic, struct qdrv_wlan, ic);
	size_t len = 0;
	int res;

	res = qdrv_hostlink_radar_get_str(qw, buffer, RADAR_STRING_OCAC, &len,
					  QDRV_RADAR_PROC_SIZE);

	if ((res < 0) || (res & (QTN_HLINK_RC_ERR)))
		return 0;

	return len;
}

static int qdrv_radar_ocac_proc_write(struct file *file, const char *buffer, unsigned long count,
				      void *data)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct qdrv_wlan *qw = container_of(ic, struct qdrv_wlan, ic);
	char procfs_buffer[QDRV_RADAR_PROC_MAX_WRITE_SIZE + 1];
	unsigned long procfs_buffer_size = 0;
	u32 val = 0;

	procfs_buffer_size = count;
	if (procfs_buffer_size > QDRV_RADAR_PROC_MAX_WRITE_SIZE)
		procfs_buffer_size = QDRV_RADAR_PROC_MAX_WRITE_SIZE;

	if (copy_from_user(procfs_buffer, buffer, procfs_buffer_size))
		return -EFAULT;

	procfs_buffer[procfs_buffer_size] = '\0';

	if (sscanf(procfs_buffer, "lsr_short_timer:%u", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_OCAC_LSR_SHORT_TIMER, val);
	else if (sscanf(procfs_buffer, "lsr_burstcnt_lbnd:%u", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_OCAC_LSR_BURST_CNT_LBND, val);
	else if (sscanf(procfs_buffer, "lsr_min_chirp_detect:%u", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_OCAC_LSR_MIN_CHIRP_DETECT, val);
	else
		printk("proc: %s\n", procfs_buffer);

	return procfs_buffer_size;
}

static void qdrv_radar_print_help(void)
{
	printk("Radar Commands:\n\n");
	printk("th1              set the value of rising edge threshold\n");
	printk("th2              set the value of falling edge threshold\n");
	printk("dsample          set the value of down sampling rate\n");
	printk("ndelay           set the value of number of delays\n");
	printk("pf               enable/disable packet filter\n");
	printk("lsrw             set the lsr detection threshold on w\n");
	printk("w                set the detection threshold on w\n");
	printk("i                set the detection threshold on i\n");
	printk("cw               set the cluster detection threshold on w\n");
	printk("ci               set the cluster detection threshold on i\n");
	printk("s                set the min separation threshold\n");
	printk("tag              enable/disable the tagging mode\n");
	printk("poll             set the polling number\n");
	printk("enable           enable/disable the radar module\n");
	printk("clear            clear the radar detection module\n");
	printk("lsr_pwdiff       set the min pw difference for LSRs\n");
	printk("lsr_pcdiff       set the min pcnt difference for LSRs\n");
	printk("verbose          enable/disable the detection vebose mode\n");
	printk("radar_verbose    enable/disable the radar verbose mode\n");
	printk("lsr_verbose      enable/disable the LSR verbose mode\n");
	printk("enable_zcs_check enable/disable zero crossing stats based detection\n");
	printk("rdisp		 enable/disable the radar disp mode\n");
	printk("spw_zc_check     enable(1)/disable(0:default) short pw(<8us) zc check\n");
	printk("zcs_all0_true     when zcs are all 0, set detect true (1:default)/false(0) \n");
	printk("zcs_use_2_50msblks     use 2 50ms (1) or current (0:default) zcs blks for zcs check\n");
	printk("lsr_ea           enable/disable the LSR enhanced algorithm\n");
	printk("fh_ea            local/global frequency hopping detection algorithm\n");
	printk("noreject         enable/disable the radar state machine\n");
	printk("max_rate         max radar rate\n");
	printk("max_instrate     max instantaneous radar rate\n");
	printk("radar_filter     enable/disable the radar filter\n");
	printk("detect_cnt       min detection threshold\n");
	printk("max_cnt          max radar pulse count\n");
	printk("max_cntlsr       max LSR pulse count\n");
	printk("max_cntfh        max FH pulse count\n");
	printk("fsm_invalid_max  max LSR FSM pulse count\n");
	printk("fh_percent       fh detection threshold\n");
	printk("min_fh_pw        set min fh pw\n");
	printk("max_fh_pw        set max fh pw\n");
	printk("min_fh_pri       set min fh pri\n");
	printk("max_fh_pri       set max fh pri\n");
	printk("shtimer          radar state machine timer\n");
	printk("pp               print radar pulses\n");
	printk("zch              print radar zero crossing contents\n");
	printk("pulseh           print radar pulse memory contents\n");
	printk("timers           print both radar timers\n");
	printk("chirp_f_th       chirp town freq. neighborhood radius\n");
	printk("max_ch_rej       max number of chirp rejections for a given lsr detection\n");
	printk("min_ch_det       min number of chirp detections for a given lsr detection\n");
	printk("min_ch_dmr       min number of chirp (detections - rejections) for an lsr detection\n");
	printk("rxext_before     packet filtering extension before packet detection\n");
	printk("rxext_after      packet filtering extension after packet detection\n");
	printk("pw_lbnd          min radar pw\n" );
	printk("pw_ubnd          max radar pw\n" );
	printk("iir_sh           set the order of radar iir filter\n" );
	printk("max_pow_th       set the threshold for max power filter\n" );
	printk("max_pcnt         set the max acceptable radar pulse count\n");
	printk("max_radar_rate   max rate for radar processing\n");
	printk("pt_det_th        set the pulse-town detection radius\n");
	printk("max_lost_pcnt    max allowed LSR lost pulse count\n");
	printk("lsr_tlong        LSR long timer\n");
	printk("max_lsr_bcnt     max acceptable LSR burst count\n");
	printk("lsr_off_ctr_ea   enable/disable off-center chirp detection\n");
	printk("lsr_boost_ea     enable/disable enhanced lsr detection algorithm\n");
	printk("min_lsr_bcnt     min acceptable LSR burst count\n");
	printk("help		 help information\n");
}

static void qdrv_radar_proc_clear(struct qdrv_wlan *qw)
{
	if (qdrv_radar_cb.enabled)
		qdrv_hostlink_radar_clear(qw);
	else
		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR, "Radar disabled\n");
}

static int qdrv_radar_proc_write(struct file *file, const char *buffer, unsigned long count,
				 void *data)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct qdrv_wlan *qw = container_of(ic, struct qdrv_wlan, ic);
	char procfs_buffer[QDRV_RADAR_PROC_MAX_WRITE_SIZE + 1];
	size_t procfs_buffer_size = 0;
	u32 val = 0;

	procfs_buffer_size = count;
	if (procfs_buffer_size > QDRV_RADAR_PROC_MAX_WRITE_SIZE)
		procfs_buffer_size = QDRV_RADAR_PROC_MAX_WRITE_SIZE;

	if (copy_from_user(procfs_buffer, buffer, procfs_buffer_size))
		return -EFAULT;

	procfs_buffer[procfs_buffer_size] = '\0';

	if (sscanf(procfs_buffer, "th1:%x", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_TH1, val);
	else if (sscanf(procfs_buffer, "th2:%x", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_TH2, val);
	else if (sscanf(procfs_buffer, "dsample:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DSAMPLE, val);
	else if (sscanf(procfs_buffer, "ndelay:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_NDELAY, val);
	else if (sscanf(procfs_buffer, "pf:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_PF, val);
	else if (sscanf(procfs_buffer, "target_gain:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_TARGET_GAIN, val);
	else if (sscanf(procfs_buffer, "poll:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_POLL_INTV, val);
	else if (sscanf(procfs_buffer, "enable:%x", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_ENABLE, val);
	else if (sscanf(procfs_buffer, "verbose:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_VERBOSE, val);
	else if (sscanf(procfs_buffer, "radar_verbose:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_RADAR_VERBOSE, val);
	else if (sscanf(procfs_buffer, "lsr_verbose:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_LSR_VERBOSE, val);
	else if (sscanf(procfs_buffer, "rdisp:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_RDISP, val);
	else if (sscanf(procfs_buffer, "spw_zc_check:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_SPW_ZC_CHECK, val);
        else if (sscanf(procfs_buffer, "zcs_all0_true:%d", &val))
                qdrv_hostlink_radar_set_param(qw,  RADAR_PARAM_DETECT_ZCS_ALL0_CHECK, val);
        else if (sscanf(procfs_buffer, "zcs_use_2_50msblks:%d", &val))
                qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_ZCS_2_50MSBLK, val);
        else if (sscanf(procfs_buffer, "zcs_all0_true:%d", &val))
                qdrv_hostlink_radar_set_param(qw,  RADAR_PARAM_DETECT_ZCS_ALL0_CHECK, val);
        else if (sscanf(procfs_buffer, "zcs_use_2_50msblks:%d", &val))
                qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_ZCS_2_50MSBLK, val);
	else if (sscanf(procfs_buffer, "noreject:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_NOREJECT, val);
	else if (sscanf(procfs_buffer, "w:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_W, val);
	else if (sscanf(procfs_buffer, "lsrw:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_LSRW, val);
	else if (sscanf(procfs_buffer, "i:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_I, val);
	else if (sscanf(procfs_buffer, "cw:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_CW, val);
	else if (sscanf(procfs_buffer, "ci:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_CI, val);
	else if (sscanf(procfs_buffer, "s:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_S, val);
	else if (sscanf(procfs_buffer, "tag:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_TAG, val);
	else if (sscanf(procfs_buffer, "lsr_pwdiff:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_LSR_PWDIFF, val);
	else if (sscanf(procfs_buffer, "lsr_pcdiff:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_LSR_PCDIFF, val);
	else if (sscanf(procfs_buffer, "lsr_ea:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_LSR_EA, val);
	else if (sscanf(procfs_buffer, "fh_ea:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_FH_EA, val);
	else if (sscanf(procfs_buffer, "chirp_f_th:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_CHIRP_F_TH, val);
	else if (sscanf(procfs_buffer, "max_ch_rej:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_MAX_CH_REJ, val);
	else if (sscanf(procfs_buffer, "min_ch_det:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_MIN_CH_DET, val);
	else if (sscanf(procfs_buffer, "min_ch_dmr:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_MIN_CH_DMR, val);
	else if (sscanf(procfs_buffer, "detect_cnt:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_DETECT_CNT, val);
	else if (sscanf(procfs_buffer, "max_cnt:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_MAX_CNT, val);
	else if (sscanf(procfs_buffer, "max_cntlsr:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_MAX_CNTLSR, val);
	else if (sscanf(procfs_buffer, "min_fh_pw:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_MIN_FH_PW, val);
	else if (sscanf(procfs_buffer, "max_fh_pw:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_MAX_FH_PW, val);
	else if (sscanf(procfs_buffer, "min_fh_pri:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_MIN_FH_PRI, val);
	else if (sscanf(procfs_buffer, "max_fh_pri:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_MAX_FH_PRI, val);
	else if (sscanf(procfs_buffer, "max_cntfh:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_MAX_CNTFH, val);
	else if (sscanf(procfs_buffer, "fsm_invalid_max:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_FSM_INVALID_MAX, val);
	else if (sscanf(procfs_buffer, "fh_percent:%u", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_FH_PERCENT, val);
	else if (sscanf(procfs_buffer, "shtimer:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_SHTIMER, val);
	else if (sscanf(procfs_buffer, "rxext_after:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_RXEXT_AFTER, val);
	else if (sscanf(procfs_buffer, "tx_ext:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_TX_EXT, val);
	else if (sscanf(procfs_buffer, "pt_det_th:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_PT_DET_TH, val);
	else if (sscanf(procfs_buffer, "rxext_before:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_RXEXT_BEFORE, val);
	else if (sscanf(procfs_buffer, "max_lost_pcnt:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_MAX_LOST_PCNT, val);
	else if (sscanf(procfs_buffer, "lsr_tlong:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_LSR_TLONG, val);
	else if (sscanf(procfs_buffer, "max_lsr_bcnt:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_MAX_LSR_BCNT, val);
	else if (sscanf(procfs_buffer, "lsr_off_ctr_ea:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_LSR_OFF_CTR_EA, val);
	else if (sscanf(procfs_buffer, "zc_diff_restrict:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_ZC_DIFF_RESTRICT, val);
	else if (sscanf(procfs_buffer, "zc_min_diff:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_ZC_MIN_DIFF, val);
	else if (sscanf(procfs_buffer, "lsr_boost_ea:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_LSR_BOOST_EA, val);
	else if (sscanf(procfs_buffer, "min_lsr_bcnt:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_MIN_LSR_BCNT, val);
	else if (sscanf(procfs_buffer, "max_pcnt:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_MAX_PCNT, val);
	else if (sscanf(procfs_buffer, "pw_ubnd:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_PW_UBND, val);
	else if (sscanf(procfs_buffer, "pw_lbnd:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_PW_LBND, val);
	else if (sscanf(procfs_buffer, "max_pow_th:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_MAX_POW_TH, val);
	else if (sscanf(procfs_buffer, "iir_sh:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_DETECT_IIR_SH, val);
	else if (sscanf(procfs_buffer, "enable_zcs_check:%d", &val))
		qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_ENABLE_ZCS_CHECK, val);
	else if (strncmp(procfs_buffer, "clear", 5) == 0)
		qdrv_radar_proc_clear(qw);
	else if (strncmp(procfs_buffer, "help", 4) == 0)
		qdrv_radar_print_help();
	else
		printk("proc: %s\n", procfs_buffer);

	return procfs_buffer_size;
}

/*
 * initialize qdrv_radar.
 * - Has to be invoked inside or after qdrv_wlan_init()
 */
int qdrv_radar_init(struct qdrv_mac *mac)
{
	struct ieee80211com *ic = &(((struct qdrv_wlan*)mac->data)->ic);
	struct qdrv_wlan *qw = container_of(ic, struct qdrv_wlan, ic);
	struct shared_params *sp = qtn_mproc_sync_shared_params_get();
	struct qtn_ocac_info *ocac_info = sp->ocac_lhost;
	unsigned chan_idx;
	struct timer_list *cac_timer;
	struct timer_list *dfs_cs_timer;

	if (mac->unit != 0) {
		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR,
			"init radar request for mac%d ignored\n", mac->unit);
		return 0; /* yes, it is success by design */
	}

	if (qdrv_radar_configured) {
		DBGPRINTF_E("radar already configured\n");
		return -1;
	}

	/* clear the control block */
	memset(&qdrv_radar_cb, 0, sizeof(qdrv_radar_cb));

	qdrv_radar_cb.mac = mac;
	qdrv_radar_cb.ic = ic;

	/* initialize the cac_timer */
	cac_timer = &qdrv_radar_cb.cac_timer;
	init_timer(cac_timer);
	cac_timer->function = cac_completed_action;
	cac_timer->data = (unsigned long) NULL; /* not used */

	/* initialize all nonoccupy timers */
	ic->ic_non_occupancy_period = QDRV_RADAR_DFLT_NONOCCUPY_PERIOD * HZ;
	for (chan_idx = 0; chan_idx < ic->ic_nchans; chan_idx++) {
		struct timer_list *nonoccupy_timer = &qdrv_radar_cb.nonoccupy_timer[chan_idx];

		init_timer(nonoccupy_timer);
		nonoccupy_timer->function = nonoccupy_expire_action;
		nonoccupy_timer->data = chan_idx;
	}

	/* initialize the dfs_cs_timer */
	dfs_cs_timer = &qdrv_radar_cb.dfs_cs_timer;
	dfs_cs_timer->function = dfs_cs_timer_expire_action;
	init_timer(dfs_cs_timer);

	ic->sta_dfs_info.sta_radar_timer.function = sta_radar_detected_timer_action;
	init_timer(&ic->sta_dfs_info.sta_radar_timer);

	ic->sta_dfs_info.sta_silence_timer.function = sta_silence_timer_action;
	init_timer(&ic->sta_dfs_info.sta_silence_timer);

#ifdef CONFIG_QHOP
	ic->rbs_mbs_dfs_info.rbs_dfs_radar_timer.function = rbs_radar_detected_timer_action;
	init_timer(&ic->rbs_mbs_dfs_info.rbs_dfs_radar_timer);
#endif

	qdrv_radar_cb.pm_notifier.notifier_call = radar_pm_notify;
	pm_qos_add_notifier(PM_QOS_POWER_SAVE, &qdrv_radar_cb.pm_notifier);

	/* For off-channel CAC */
	qdrv_radar_cb.ocac_info = ocac_info;
	qdrv_init_ocac_irqhandler(qw);

	/* create a proc entry for radar */
	if ((qdrv_radar_cb.radar_proc = create_proc_entry("radar", 0x644, NULL)) == NULL) {
		printk("unable to create /proc/radar\n");
		goto proc_radar_fail;
	}
	qdrv_radar_cb.radar_proc->read_proc = qdrv_radar_proc_read;
	qdrv_radar_cb.radar_proc->write_proc = qdrv_radar_proc_write;
	qdrv_radar_cb.radar_proc->mode = S_IFREG | S_IRUGO;
	qdrv_radar_cb.radar_proc->uid = 0;
	qdrv_radar_cb.radar_proc->gid = 0;
	qdrv_radar_cb.radar_proc->size = QDRV_RADAR_PROC_SIZE;

	/* create a proc entry for pulses */
	if ((qdrv_radar_cb.radar_pulse_proc = create_proc_entry("pulse", 0x644, NULL)) == NULL) {
		printk("unable to create /proc/pulse\n");
		goto proc_pulse_fail;
	}
	qdrv_radar_cb.radar_pulse_proc->read_proc = qdrv_radar_pulse_proc_read;
	qdrv_radar_cb.radar_pulse_proc->mode = S_IFREG | S_IRUGO;
	qdrv_radar_cb.radar_pulse_proc->uid = 0;
	qdrv_radar_cb.radar_pulse_proc->gid = 0;
	qdrv_radar_cb.radar_pulse_proc->size = QDRV_RADAR_PROC_SIZE;


	/* create a proc entry for zero crossings */
	if ((qdrv_radar_cb.radar_zc_proc = create_proc_entry("zc", 0x644, NULL)) == NULL) {
		printk("unable to create /proc/zc\n");
		goto proc_zc_fail;
	}
	qdrv_radar_cb.radar_zc_proc->read_proc = qdrv_radar_zc_proc_read;
	qdrv_radar_cb.radar_zc_proc->mode = S_IFREG | S_IRUGO;
	qdrv_radar_cb.radar_zc_proc->uid = 0;
	qdrv_radar_cb.radar_zc_proc->gid = 0;
	qdrv_radar_cb.radar_zc_proc->size = QDRV_RADAR_PROC_SIZE;

	/* create a proc entry for off channel CAC */
	if ((qdrv_radar_cb.radar_ocac_proc = create_proc_entry("ocac", 0x644, NULL)) == NULL) {
		printk("unable to create /proc/ocac\n");
		goto proc_ocac_fail;
	}
	qdrv_radar_cb.radar_ocac_proc->read_proc = qdrv_radar_ocac_proc_read;
	qdrv_radar_cb.radar_ocac_proc->write_proc = qdrv_radar_ocac_proc_write;
	qdrv_radar_cb.radar_ocac_proc->mode = S_IFREG | S_IRUGO;
	qdrv_radar_cb.radar_ocac_proc->uid = 0;
	qdrv_radar_cb.radar_ocac_proc->gid = 0;
	qdrv_radar_cb.radar_ocac_proc->size = QDRV_RADAR_PROC_SIZE;

	qdrv_radar_configured = true;

	/* success */
	DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR, "radar initialized\n");

	return 0;

proc_ocac_fail:
	remove_proc_entry("zc", NULL);
proc_zc_fail:
	remove_proc_entry("pulse", NULL);
proc_pulse_fail:
	remove_proc_entry("radar", NULL);
proc_radar_fail:

	del_timer_sync(&(qdrv_radar_cb.ic->sta_dfs_info.sta_silence_timer));
	pm_qos_remove_notifier(PM_QOS_POWER_SAVE, &qdrv_radar_cb.pm_notifier);

	return -1;
}

/*
 * deinitialize qdrv_radar
 */
int qdrv_radar_exit(struct qdrv_mac *mac)
{
	if (mac->unit != 0) {
		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR,
			"exit request for mac%d ignored\n", mac->unit);
		return 0; /* yes, it is success by design */
	}

	if (qdrv_radar_first_call == true || !qdrv_radar_configured) {
		DBGPRINTF_E("radar already unconfigured\n");
		return -1;
	}

	qdrv_radar_disable();

	del_timer_sync(&(qdrv_radar_cb.ic->sta_dfs_info.sta_silence_timer));

	pm_qos_remove_notifier(PM_QOS_POWER_SAVE, &qdrv_radar_cb.pm_notifier);

	remove_proc_entry("ocac", NULL);
	remove_proc_entry("radar", NULL);
	remove_proc_entry("pulse", NULL);
	remove_proc_entry("zc", NULL);

	/* disable radar detection */
	sys_stop_radarmod();

	/* clear the control block */
	memset(&qdrv_radar_cb, 0, sizeof(qdrv_radar_cb));

	qdrv_radar_configured = false;
	qdrv_radar_sta_dfs = false;

	DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR, "radar exited\n");

	return 0;
}

int qdrv_radar_unload(struct qdrv_mac *mac)
{
	if (mac->unit != 0) {
		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR,
			"exit request for mac%d ignored\n", mac->unit);
		return 0; /* yes, it is success by design */
	}

	if (qdrv_radar_first_call == true || !qdrv_radar_configured) {
		DBGPRINTF_E("radar already unconfigured\n");
		return -1;
	}

	qdrv_radar_disable();

	/* success */
	DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_RADAR, "radar unloaded\n");

	return 0;
}

int qdrv_radar_set_bw(uint32_t bw)
{
	struct ieee80211com *ic = qdrv_radar_cb.ic;
	struct qdrv_wlan *qw = container_of(ic, struct qdrv_wlan, ic);
	uint32_t get_bw;

	qdrv_hostlink_radar_get_param(qw, RADAR_PARAM_BW, &get_bw);
	if (!qdrv_radar_cb.enabled || (bw == get_bw))
		return 0;

	qdrv_hostlink_radar_set_param(qw, RADAR_PARAM_BW, bw);
	return 1;
}
