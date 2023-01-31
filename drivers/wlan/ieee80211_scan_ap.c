/*-
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: ieee80211_scan_ap.c 1721 2006-09-20 08:45:13Z mentor $
 */
#ifndef EXPORT_SYMTAB
#define	EXPORT_SYMTAB
#endif

/*
 * IEEE 802.11 ap scanning support.
 */
#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/version.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/random.h>

#include "net80211/if_media.h"

#include "net80211/ieee80211_var.h"
#include "net80211/ieee80211_mlme_statistics.h"

static int ap_flush(struct ieee80211_scan_state *);
static void action_tasklet(IEEE80211_TQUEUE_ARG);

static int
lock_ap_list(struct ap_state *as)
{
	int bh_disabled = !in_softirq() && !irqs_disabled();

	WARN_ON_ONCE(in_irq());

	spin_lock(&as->asl_lock);
	if (bh_disabled) {
		local_bh_disable();
	}
	return bh_disabled;
}

static void
unlock_ap_list(struct ap_state *as, int bh_disabled)
{
	if (bh_disabled) {
		local_bh_enable();
	}
	spin_unlock(&as->asl_lock);
}

static int
ap_lock(struct ieee80211_scan_state *ss)
{
	struct ap_state *as = ss->ss_priv;
	return lock_ap_list(as);
}

static void ap_unlock(struct ieee80211_scan_state *ss, int bh_disabled)
{
	struct ap_state *as = ss->ss_priv;
	unlock_ap_list(as, bh_disabled);
}

static void
cleanup_se(struct ap_scan_entry *se)
{
	struct ieee80211_scan_entry *ise = &se->base;
	if (ise->se_wpa_ie) {
		FREE(ise->se_wpa_ie, M_DEVBUF);
		ise->se_wpa_ie = NULL;
	}
	if (ise->se_rsn_ie) {
		FREE(ise->se_rsn_ie, M_DEVBUF);
		ise->se_rsn_ie = NULL;
	}
	if (ise->se_wme_ie) {
		FREE(ise->se_wme_ie, M_DEVBUF);
		ise->se_wme_ie = NULL;
	}
	if (ise->se_wsc_ie) {
		FREE(ise->se_wsc_ie, M_DEVBUF);
		ise->se_wsc_ie = NULL;
	}
	if (ise->se_htcap_ie) {
		FREE(ise->se_htcap_ie, M_DEVBUF);
		ise->se_htcap_ie = NULL;
	}
	if (ise->se_htinfo_ie) {
		FREE(ise->se_htinfo_ie, M_DEVBUF);
		ise->se_htinfo_ie = NULL;
	}
	if (ise->se_vhtcap_ie) {
		FREE(ise->se_vhtcap_ie, M_DEVBUF);
		ise->se_vhtcap_ie = NULL;
	}
	if (ise->se_vhtop_ie) {
		FREE(ise->se_vhtop_ie, M_DEVBUF);
		ise->se_vhtop_ie = NULL;
	}
	if (ise->se_ath_ie) {
		FREE(ise->se_ath_ie, M_DEVBUF);
		ise->se_ath_ie = NULL;
	}
	if (ise->se_qtn_ie)
	{
		FREE(ise->se_qtn_ie, M_DEVBUF);
		ise->se_qtn_ie = NULL;
	}
	if (ise->se_ext_bssid_ie) {
		FREE(ise->se_ext_bssid_ie, M_DEVBUF);
		ise->se_ext_bssid_ie = NULL;
	}
	if (ise->se_country_ie) {
		FREE(ise->se_country_ie, M_DEVBUF);
		ise->se_country_ie = NULL;
	}
	if (ise->se_pairing_ie) {
		FREE(ise->se_pairing_ie, M_DEVBUF);
		ise->se_pairing_ie = NULL;
	}
	if (ise->se_bss_load_ie) {
		FREE(ise->se_bss_load_ie, M_DEVBUF);
		ise->se_bss_load_ie = NULL;
	}
	if (ise->se_md_ie) {
		FREE(ise->se_md_ie, M_DEVBUF);
		ise->se_md_ie = NULL;
	}
	if (ise->se_repeater_ie) {
		FREE(ise->se_repeater_ie, M_DEVBUF);
		ise->se_repeater_ie = NULL;
	}
	if (ise->se_obss_scan) {
		FREE(ise->se_obss_scan, M_DEVBUF);
		ise->se_obss_scan = NULL;
	}
	if (ise->se_rp_info_ie) {
		FREE(ise->se_rp_info_ie, M_DEVBUF);
		ise->se_rp_info_ie = NULL;
	}
}

static void
free_se(struct ap_scan_entry *se)
{
	cleanup_se(se);
	FREE(se, M_80211_SCAN);
}

static void
free_se_request(struct ap_scan_entry *se)
{
	if (se->se_inuse) {
		se->se_request_to_free = 1;
	} else {
		free_se(se);
	}
}

static void
free_se_process(struct ap_scan_entry *se)
{
	if (!se->se_inuse && se->se_request_to_free) {
		free_se(se);
	}
}

static void
set_se_inuse(struct ap_scan_entry *se)
{
	se->se_inuse = 1;
}

static void
reset_se_inuse(struct ap_scan_entry *se)
{
	se->se_inuse = 0;
	free_se_process(se);
}
/*
 * Attach prior to any scanning work.
 */
static int
ap_attach(struct ieee80211_scan_state *ss)
{
	struct ap_state *as;
	int i;

	_MOD_INC_USE(THIS_MODULE, return 0);

	MALLOC(as, struct ap_state *, sizeof(struct ap_state),
		M_SCANCACHE, M_NOWAIT | M_ZERO);
	if (as == NULL) {
		if (printk_ratelimit())
			printk("failed to attach before scanning\n");
		_MOD_DEC_USE(THIS_MODULE);
		return 0;
	}
	as->as_age = AP_PURGE_SCANS;
	ss->ss_priv = as;
	IEEE80211_INIT_TQUEUE(&as->as_actiontq, action_tasklet, ss);
	spin_lock_init(&as->asl_lock);
	for (i = 0; i < IEEE80211_CHAN_MAX; i++) {
		TAILQ_INIT(&as->as_scan_list[i].asl_head);
	}
	return 1;
}


static int
ap_flush_asl_table(struct ieee80211_scan_state *ss)
{
	struct ap_state *as = ss->ss_priv;
	struct ap_scan_entry *se, *next;
	int i;

	for (i = 0; i < IEEE80211_CHAN_MAX; i++) {
		TAILQ_FOREACH_SAFE(se, &as->as_scan_list[i].asl_head, ase_list, next) {
			TAILQ_REMOVE(&as->as_scan_list[i].asl_head, se, ase_list);
			free_se_request(se);
			if (as->as_entry_num > 0)
				as->as_entry_num--;
		}
	}
	return 0;
}

/*
 * Cleanup any private state.
 */
static int
ap_detach(struct ieee80211_scan_state *ss)
{
	struct ap_state *as = ss->ss_priv;

	if (as != NULL) {
		ap_flush_asl_table(ss);
		FREE(as, M_SCANCACHE);
	}

	_MOD_DEC_USE(THIS_MODULE);
	return 1;
}

/*
 * Flush all per-scan state.
 */
static int
ap_flush(struct ieee80211_scan_state *ss)
{
	struct ap_state *as = ss->ss_priv;
	int bh_disabled;

	bh_disabled = lock_ap_list(as);
	ap_flush_asl_table(ss);
	unlock_ap_list(as, bh_disabled);

	memset(as->as_maxrssi, 0, sizeof(as->as_maxrssi));
	memset(as->as_numpkts, 0, sizeof(as->as_numpkts));
	memset(as->as_aci,     0, sizeof(as->as_aci));
	memset(as->as_cci,     0, sizeof(as->as_aci));
	memset(as->as_numbeacons, 0, sizeof(as->as_numbeacons));
	memset(as->as_chanmetric, 0, sizeof(as->as_chanmetric));
	memset(as->as_obss_chanlayout, 0, sizeof(as->as_obss_chanlayout));
	ss->ss_last = 0;		/* ensure no channel will be picked */
	return 0;
}

static int
find11gchannel(struct ieee80211com *ic, int i, int freq)
{
	const struct ieee80211_channel *c;
	int j;

	/*
	 * The normal ordering in the channel list is b channel
	 * immediately followed by g so optimize the search for
	 * this.  We'll still do a full search just in case.
	 */
	for (j = i+1; j < ic->ic_nchans; j++) {
		c = &ic->ic_channels[j];
		if (c->ic_freq == freq && IEEE80211_IS_CHAN_ANYG(c))
			return 1;
	}
	for (j = 0; j < i; j++) {
		c = &ic->ic_channels[j];
		if (c->ic_freq == freq && IEEE80211_IS_CHAN_ANYG(c))
			return 1;
	}
	return 0;
}

/*
 * Start an ap scan by populating the channel list.
 */
static int
ap_start(struct ieee80211_scan_state *ss, struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_channel *c;
	int i;

	ss->ss_last = 0;

	if (vap->iv_scan_freqs) {
		for (i = 0; i < MIN(vap->iv_scan_freqs->num, IEEE80211_SCAN_MAX); i++) {
			c = ieee80211_find_channel(ic, vap->iv_scan_freqs->freqs[i], 0);
			if (c && isset(ic->ic_chan_active_20, c->ic_ieee) &&
					!(c->ic_flags & IEEE80211_CHAN_RADAR))
				ss->ss_chans[ss->ss_last++] = c;
		}
		FREE(vap->iv_scan_freqs, M_DEVBUF);
		vap->iv_scan_freqs = NULL;
		goto scan_channel_list_ready;
	}

	if (ic->ic_des_mode == IEEE80211_MODE_AUTO) {
		for (i = 0; i < ic->ic_nchans; i++) {
			c = &ic->ic_channels[i];
			if (c == NULL || isclr(ic->ic_chan_active, c->ic_ieee))
				continue;

			if (isclr(ic->ic_scan_chan_list, c->ic_ieee))
				continue;

			if (IEEE80211_IS_CHAN_TURBO(c)) {
				/* XR is not supported on turbo channels */
				if (vap->iv_ath_cap & IEEE80211_ATHC_XR)
					continue;
				/* dynamic channels are scanned in base mode */
				if (!IEEE80211_IS_CHAN_ST(c))
					continue;
			} else {
				/*
				 * Use any 11g channel instead of 11b one.
				 */
				if (IEEE80211_IS_CHAN_B(c) &&
				    find11gchannel(ic, i, c->ic_freq))
					continue;
			}
			if (c->ic_flags & IEEE80211_CHAN_RADAR)
				continue;
			if (ss->ss_last >= IEEE80211_SCAN_MAX)
				break;
			/* avoid DFS channels if so configured */
			if ((ss->ss_flags & IEEE80211_SCAN_NO_DFS) && (c->ic_flags & IEEE80211_CHAN_DFS))
				continue;
			ss->ss_chans[ss->ss_last++] = c;
		}
	} else {
		u_int modeflags;

		modeflags = ieee80211_get_chanflags(ic->ic_des_mode);
		if (vap->iv_ath_cap & IEEE80211_ATHC_TURBOP && modeflags != IEEE80211_CHAN_ST) {
			if (ic->ic_des_mode == IEEE80211_MODE_11G)
				modeflags = IEEE80211_CHAN_108G;
			else
				modeflags = IEEE80211_CHAN_108A;
		}
		for (i = 0; i < ic->ic_nchans; i++) {
			c = &ic->ic_channels[i];
			if (c == NULL || isclr(ic->ic_chan_active, c->ic_ieee))
				continue;

			if (isclr(ic->ic_scan_chan_list, c->ic_ieee))
				continue;

			if ((c->ic_flags & modeflags) != modeflags)
				continue;
			/* XR is not supported on turbo channels */
			if (IEEE80211_IS_CHAN_TURBO(c) && vap->iv_ath_cap & IEEE80211_ATHC_XR)
				continue;
			if (ss->ss_last >= IEEE80211_SCAN_MAX)
				break;
			/*
			 * do not select static turbo channels if the mode is not
			 * static turbo .
			 */
			if (IEEE80211_IS_CHAN_STURBO(c) && ic->ic_des_mode != IEEE80211_MODE_MAX)
				continue;
			/* No dfs interference detected channels */
			if (c->ic_flags & IEEE80211_CHAN_RADAR)
				continue;
			/* avoid DFS channels if so configured */
			if ((ss->ss_flags & IEEE80211_SCAN_NO_DFS) && (c->ic_flags & IEEE80211_CHAN_DFS))
				continue;
			ss->ss_chans[ss->ss_last++] = c;
		}
	}

scan_channel_list_ready:
	ss->ss_next = 0;
	/* XXX tunables */
	ss->ss_mindwell = msecs_to_jiffies(ic->ic_mindwell_active);
	ss->ss_maxdwell = msecs_to_jiffies(ic->ic_maxdwell_active);
	ss->ss_maxdwell_passive = msecs_to_jiffies(ic->ic_maxdwell_passive);
	ss->ss_mindwell_passive = msecs_to_jiffies(ic->ic_mindwell_passive);

#ifdef IEEE80211_DEBUG
	if (ieee80211_msg_scan(vap)) {
		printf("%s: scan set ", vap->iv_dev->name);
		ieee80211_scan_dump_channels(ss);
		printf(" dwell min %ld max %ld\n",
			ss->ss_mindwell, ss->ss_maxdwell);
	}
#endif /* IEEE80211_DEBUG */

	return 0;
}

/*
 * Restart a bg scan.
 */
static int
ap_restart(struct ieee80211_scan_state *ss, struct ieee80211vap *vap)
{
	return 0;
}

/*
 * Cancel an ongoing scan.
 */
static int
ap_cancel(struct ieee80211_scan_state *ss, struct ieee80211vap *vap)
{
	struct ap_state *as = ss->ss_priv;

	IEEE80211_CANCEL_TQUEUE(&as->as_actiontq);
	return 0;
}

static int
ap_add(struct ieee80211_scan_state *ss, const struct ieee80211_scanparams *sp,
	const struct ieee80211_frame *wh, int subtype, int rssi, int rstamp)
{
	struct ap_state *as = ss->ss_priv;
	struct ieee80211vap *vap = ss->ss_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ap_scan_entry *se;
	struct ieee80211_scan_entry *ise;
	const u_int8_t *macaddr = wh->i_addr2;
	int bh_disabled;
	int chan;
	int found = 0;

	if (is_channel_valid(sp->chan)) {
		chan = sp->chan;
	} else {
		chan = ieee80211_chan2ieee(ic, ic->ic_curchan);
		if (!is_channel_valid(chan))
			return 1;
	}

	/* XXX better quantification of channel use? */
	/* XXX count bss's? */
	/* Now we Only count beacons from different bss for better quantification of channel use */

	if (subtype == IEEE80211_FC0_SUBTYPE_BEACON) {
		if (rssi > as->as_maxrssi[chan])
			as->as_maxrssi[chan] = rssi;
	}

	as->as_numpkts[chan]++;

	bh_disabled = lock_ap_list(as);
	TAILQ_FOREACH(se, &as->as_scan_list[chan].asl_head, ase_list) {
		if (IEEE80211_ADDR_EQ(se->base.se_macaddr, macaddr)) {
			found = 1;
			break;
		}
	}

	if (!found) {
		if (as->as_entry_num >= ic->ic_scan_tbl_len_max) {
			if (printk_ratelimit())
			      printk("scan found %u scan results but the list is"
					" restricted to %u entries\n", as->as_entry_num,
					ic->ic_scan_tbl_len_max);
			unlock_ap_list(as, bh_disabled);
			return 0;
		}

		MALLOC(se, struct ap_scan_entry *, sizeof(*se), M_80211_SCAN, M_NOWAIT | M_ZERO);
		if (se == NULL) {
			if (printk_ratelimit())
				printk("failed to allocate new scan entry\n");
			unlock_ap_list(as, bh_disabled);
			return 0;
		}
		as->as_entry_num++;

		IEEE80211_ADDR_COPY(se->base.se_macaddr, macaddr);
		TAILQ_INSERT_TAIL(&as->as_scan_list[chan].asl_head, se, ase_list);

		if (subtype == IEEE80211_FC0_SUBTYPE_BEACON) {
			as->as_numbeacons[chan]++;
		}
	}
	ise = &se->base;

	ieee80211_add_scan_entry(ise, sp, wh, subtype, rssi, rstamp);
	ieee80211_scan_check_secondary_channel(ss, ise);

	if (se->se_lastupdate == 0) {		/* first sample */
		se->se_avgrssi = RSSI_IN(rssi);
	} else if (ABS(ise->se_rssi - rssi) > IEEE80211_RSSI_UPDATE_LIMIT &&
			ise->se_rssi_ignored_cnt <= IEEE80211_RSSI_IGNORE_LIMIT) {
		ise->se_rssi_ignored_cnt++;
	} else {
		RSSI_LPF(se->se_avgrssi, rssi);	/* avg with previous samples */
		if (ise->se_rssi_ignored_cnt > 0)
			ise->se_rssi_ignored_cnt--;
	}
	ise->se_rssi = RSSI_GET(se->se_avgrssi);

	unlock_ap_list(as, bh_disabled);
	se->se_lastupdate = jiffies;		/* update time */
	se->se_seen = 1;
	se->se_notseen = 0;

	return 1;
}

enum chan_sel_algorithm {
	CHAN_SEL_CLEAREST = 0,		/* Select the clearest channel */
	CHAN_SEL_DFS_REENTRY = 1,	/* Select the channel based on DFS entry/re-entry requirement */
	CHAN_SEL_MAX = 2
};


typedef struct
{
	int tx_power_factor;		/*Tx power weighting factor*/
	int aci_factor;			/*ACI weighting factor*/
	int cci_factor;			/*CCI weighting factor*/
	int dfs_factor;			/*DFS weighting factor*/
	int beacon_factor;		/*Beacon number weighting factor */
} decision_metric_factor;

/*
 * Weighting factor for TX power is 2, because we have to multiply the CCI factor by 2
 * to prevent losing precision when deriving the ACI, as the ACI is 1/2 of the CCI on
 * an adjacent channel.
 */
static const decision_metric_factor g_dm_factor[CHAN_SEL_MAX] =
{
	{2, -1, -1, 0, -1},	/* CHAN_SEL_CLEAREST */
	{2, -1, -1, 8, -1}	/* CHAN_SEL_DFS_REENTRY */
};

#define QTN_CHAN_METRIC_BASE		160	/* to make sure the channel metric not to be negative */
#define QTN_METRIC_CCI_LIMIT		16
#define QTN_METRIC_BEACON_LIMIT		4
#define QTN_AS_CCA_INTF_DIVIDER		(IEEE80211_SCS_CCA_INTF_SCALE / QTN_METRIC_CCI_LIMIT)
#define	QTN_CHAN_METRIC_MAX		(QTN_CHAN_METRIC_BASE << 18)

/* Some custom knobs for out ap scan alg */

enum ieee802111_scan_skipchan_reason {
	IEEE80211_SCAN_SKIPCHAN_REASON_INVALID		= 1,
	IEEE80211_SCAN_SKIPCHAN_REASON_DFS		= 2,
	IEEE80211_SCAN_SKIPCHAN_REASON_AVAIL		= 3,
	IEEE80211_SCAN_SKIPCHAN_REASON_NONAVAIL		= 4,
	IEEE80211_SCAN_SKIPCHAN_REASON_RADAR		= 5,
	IEEE80211_SCAN_SKIPCHAN_REASON_TURBO		= 6,
	IEEE80211_SCAN_SKIPCHAN_REASON_PURE20		= 7,
	IEEE80211_SCAN_SKIPCHAN_REASON_MISMATCH_NOTDFS	= 8,
	IEEE80211_SCAN_SKIPCHAN_REASON_MISMATCH_DFS	= 9,
	IEEE80211_SCAN_SKIPCHAN_REASON_MISMATCH_BW	= 10,
	IEEE80211_SCAN_SKIPCHAN_REASON_METRIC_BETTER	= 11,
	IEEE80211_SCAN_SKIPCHAN_REASON_PRI_INACTIVE	= 12,
	IEEE80211_SCAN_SKIPCHAN_REASON_WEATHER_CHAN	= 13,
	IEEE80211_SCAN_SKIPCHAN_REASON_NON_DFS		= 14,
};

static void local_ap_pick_channel_debug(struct ieee80211com *ic,
		struct ieee80211_scan_state *ss, int chan, int skip_reason)
{
	struct ap_state *as = ss->ss_priv;

	if (skip_reason == IEEE80211_SCAN_SKIPCHAN_REASON_INVALID)
		return;

	IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
			"ap_pick_channel: chan %3u rssi %2d #bss %2d #pkts %3d weight %4d metric %3d reason %2d\n",
			chan, as->as_maxrssi[chan], as->as_numbeacons[chan], as->as_numpkts[chan],
			ic->ic_chan_ics_weights[chan], as->as_chanmetric[chan], skip_reason);
}

/*
 * Pick a quiet channel to use for ap operation.
 *
 * (i) When ap_pick_channel is being called when channel=0, max_boot_cac=0
 *     ap_pick_channel picks from set of non-DFS channels only
 *
 * (ii) When ap_pick_channel is being called when channel=non-DFS, max_boot_cac=0
 *      DUT becomes operational on channel=non-DFS
 *
 * (iii) When ap_pick_channel is being called when channel=DFS, max_boot_cac=0
 *      DUT performs CAC on channel=DFS, start operation after CAC completes
 *
 * (iv) When ap_pick_channel is being called when channel=0, max_boot_cac=140
 *      DUT performs ICAC
 *      clears two channels
 *      Triggers auto-channel and selects a channel from available cleared channel list
 *
 * (v) when ap_pick_channel is being called when channel=non-DFS, max_boot_cac=140
 *     DUT performs ICAC
 *     clears two channels
 *     Starts operation on channel=non-DFS
 *
 * (vi) When ap_pick_channel is being called when channel=DFS, max_boot_cac=140
 *      DUT performs CAC on channel=DFS
 *      DUT clears one more DFS channel
 *      Starts operation on channel=DFS
 */

static void ap_update_ics_chan_metric(struct ieee80211com *ic, struct ieee80211_scan_state *ss)
{
	int i;
	int chan;
	int chan2;
	struct ap_state *as = ss->ss_priv;
	decision_metric_factor dm_factor;

	/*
	 * Convert CCA interference to CCI factor
	 */
	for (i = 0; i < ss->ss_last; i++) {
		chan = ieee80211_chan2ieee(ic, ss->ss_chans[i]);
		if (!is_channel_valid(chan))
			continue;

		if (as->as_cca_intf[chan] <= IEEE80211_SCS_CCA_INTF_SCALE) {
			as->as_cci[chan] = 2 * as->as_cca_intf[chan] / QTN_AS_CCA_INTF_DIVIDER;
			as->as_cci[chan] = MIN(as->as_cci[chan], QTN_METRIC_CCI_LIMIT);
		} else {
			as->as_cci[chan] = 0;
		}

		/* Reset ACI here */
		as->as_aci[chan] = 0;
	}

	/*
	 * Derive ACI (Adjacent Channel Interference) from CCI.
	 */
	for (i = 0; i < ss->ss_last; i++) {
		chan = ieee80211_chan2ieee(ic, ss->ss_chans[i]);
		if (!is_channel_valid(chan))
			continue;

		/* Adjust adjacent channel metrics to bias against close selection */
		if (i != 0) {
			chan2 = ieee80211_chan2ieee(ic, ss->ss_chans[i-1]);
			if (!is_channel_valid(chan2))
				continue;
			if (chan2 >= (chan - 4)){
				as->as_aci[chan2] += (as->as_cci[chan] >> 1);
			}
		}

		if (i != ss->ss_last - 1) {
			chan2 = ieee80211_chan2ieee(ic, ss->ss_chans[i+1]);
			if (!is_channel_valid(chan2))
				continue;
			if (chan2 <= (chan + 4)){
				as->as_aci[chan2] += (as->as_cci[chan] >> 1);
			}
		}
	}

	/* DFS entry enabled by default */
	memcpy(&dm_factor, &g_dm_factor[CHAN_SEL_DFS_REENTRY], sizeof(dm_factor));
	if (ic->ic_dm_factor.flags) {
		if (ic->ic_dm_factor.flags & DM_FLAG_TXPOWER_FACTOR_PRESENT) {
			dm_factor.tx_power_factor = ic->ic_dm_factor.txpower_factor;
		}
		if (ic->ic_dm_factor.flags & DM_FLAG_ACI_FACTOR_PRESENT) {
			dm_factor.aci_factor = ic->ic_dm_factor.aci_factor;
		}
		if (ic->ic_dm_factor.flags & DM_FLAG_CCI_FACTOR_PRESENT) {
			dm_factor.cci_factor = ic->ic_dm_factor.cci_factor;
		}
		if (ic->ic_dm_factor.flags & DM_FLAG_DFS_FACTOR_PRESENT) {
			dm_factor.dfs_factor = ic->ic_dm_factor.dfs_factor;
		}
		if (ic->ic_dm_factor.flags & DM_FLAG_BEACON_FACTOR_PRESENT) {
			dm_factor.beacon_factor = ic->ic_dm_factor.beacon_factor;
		}
	}

	/*
	 * Compute Channel Metric (Decision Metric) based on Hossein D's formula.
	 */
	for (i = 0; i < ss->ss_last; i++) {
		struct ieee80211_channel *c = ss->ss_chans[i];

		chan = ieee80211_chan2ieee(ic, ss->ss_chans[i]);
		if (!is_channel_valid(chan))
			continue;

		as->as_chanmetric[chan] = QTN_CHAN_METRIC_BASE
			+ ic->ic_chan_ics_weights[chan]
			+ dm_factor.cci_factor * as->as_cci[chan]
			+ dm_factor.aci_factor * as->as_aci[chan]
			+ dm_factor.dfs_factor * ((c->ic_flags & IEEE80211_CHAN_DFS) ? 1 : 0)
			+ dm_factor.beacon_factor * MIN(as->as_numbeacons[chan], QTN_METRIC_BEACON_LIMIT);
	}
}

static int ap_pick_ics_channel_validate(struct ieee80211com *ic,
		struct ieee80211_channel *channel,
		struct ieee80211_scan_state *ss, int flags)
{
	int chan;
	int checkflags = 0;

	if (!is_ieee80211_chan_valid(channel))
		return IEEE80211_SCAN_SKIPCHAN_REASON_INVALID;

	chan = ieee80211_chan2ieee(ic, channel);
	if (!is_channel_valid(chan))
		return IEEE80211_SCAN_SKIPCHAN_REASON_INVALID;

	if ((flags & IEEE80211_SCAN_NO_DFS)
			&& (channel->ic_flags & IEEE80211_CHAN_DFS)) {
		return IEEE80211_SCAN_SKIPCHAN_REASON_DFS;
	}

	if ((flags == IEEE80211_SCAN_PICK_ANY_DFS) &&
			(!(channel->ic_flags & IEEE80211_CHAN_DFS))) {
		return IEEE80211_SCAN_SKIPCHAN_REASON_NON_DFS;
	}

	if (flags == IEEE80211_SCAN_PICK_NOT_AVAILABLE_DFS_ONLY) {
		if (ic->ic_dfs_chans_available_for_cac(ic, channel, IEEE80211_ICAC) == false)
			return IEEE80211_SCAN_SKIPCHAN_REASON_AVAIL;
	}

	/* IEEE80211_SCAN_PICK_NOT_AVAILABLE_DFS_ONLY is set only during ICAC */
	/* Don't bypass the check of current channel in ic_check_channel */
	if (flags == IEEE80211_SCAN_PICK_NOT_AVAILABLE_DFS_ONLY ||
			flags == IEEE80211_SCAN_PICK_AVAILABLE_ANY_CHANNEL) {
		checkflags = IEEE80211_CHANNEL_CHECK_ALLOW_CURRENT;
	}
	if (!ic->ic_check_channel(ic, channel, checkflags))
		return IEEE80211_SCAN_SKIPCHAN_REASON_RADAR;

	/* IEEE80211_SCAN_PICK_AVAILABLE_ANY_CHANNEL is set only after ICAC */
	/* When channel=0, max_cac_boot=140
	 * perform cac on two of not yet available DFS channels
	 * Mark the DFS channels as available after CAC complettion
	 * At the end of initial CAC, choose the best available channel
	 * from initial metric;
	 */
	if (flags == IEEE80211_SCAN_PICK_AVAILABLE_ANY_CHANNEL) {
		if(!ieee80211_is_chan_available(channel))
			return IEEE80211_SCAN_SKIPCHAN_REASON_NONAVAIL;
	}

	/*
	 * If the channel is unoccupied the max rssi
	 * should be zero; just take it.  Otherwise
	 * track the channel with the lowest rssi and
	 * use that when all channels appear occupied.
	 *
	 * Check for channel interference, and if found,
	 * skip the channel.  We assume that all channels
	 * will be checked so atleast one can be found
	 * suitable and will change.  IF this changes,
	 * then we must know when we "have to" change
	 * channels for radar and move off.
	 */
	if (flags & IEEE80211_SCAN_KEEPMODE) {
		if (ic->ic_curchan != NULL) {
			if ((channel->ic_flags & IEEE80211_CHAN_ALLTURBO) !=
					(ic->ic_curchan->ic_flags & IEEE80211_CHAN_ALLTURBO)) {
				return IEEE80211_SCAN_SKIPCHAN_REASON_TURBO;
			}
		}
	}

	if (ic->ic_rf_chipid != CHIPID_DUAL) {
		/* hzw: temporary disable these checking for RFIC5 */
		/* FIXME: Temporarily dont select any pure 20 channels */
		if (!(channel->ic_flags & IEEE80211_CHAN_HT40))
			return IEEE80211_SCAN_SKIPCHAN_REASON_PURE20;

		if (((ss->ss_pick_flags & IEEE80211_PICK_DOMIAN_MASK) == IEEE80211_PICK_DFS) &&
				!(channel->ic_flags & IEEE80211_CHAN_DFS)) {
			return IEEE80211_SCAN_SKIPCHAN_REASON_MISMATCH_NOTDFS;
		} else if (((ss->ss_pick_flags & IEEE80211_PICK_DOMIAN_MASK) == IEEE80211_PICK_NONDFS) &&
				(channel->ic_flags & IEEE80211_CHAN_DFS)) {
			return IEEE80211_SCAN_SKIPCHAN_REASON_MISMATCH_DFS;
		}
	}

	if (!ic->ic_weachan_cac_allowed &&
			ieee80211_is_on_weather_channel(ic, channel)) {
		/*
		 * Don't pick weather channel in auto channel mode since it need
		 * too long CAC time, and it also fix the backward compatibility
		 * issue with the stations which don't support weather channels
		 */
		return IEEE80211_SCAN_SKIPCHAN_REASON_WEATHER_CHAN;
	}

	return 0;
}

static int
ap_ics_is_valid_obss_secondary(struct ieee80211com *ic, uint8_t obss_chanlayout)
{
	if (IEEE80211_IS_OBSS_CHAN_SECONDARY20(obss_chanlayout))
		return 0;

	if ((ic->ic_obss_flag & IEEE80211_OBSS_CHECK_SEC40) &&
			IEEE80211_IS_OBSS_CHAN_SECONDARY40(obss_chanlayout)) {
		return 0;
	}

	return 1;
}

static int
ap_ics_is_valid_obss_primary(struct ieee80211com *ic, uint8_t obss_chanlayout)
{
	if (!(ic->ic_obss_flag & IEEE80211_OBSS_CHECK_PRIMARY))
		return 1;

	if (IEEE80211_IS_OBSS_CHAN_PRIMARY20(obss_chanlayout))
		return 0;

	/*
	 * FIXME
	 * The function should return 1 but a compiler issue will be
	 * triggered if return 1 instead.
	 * Any change please verify against the BBIC4-11842 on jira
	 */
	return 2;
}

static int
ap_ics_obss_check(struct ieee80211com *ic, struct ap_state *as,
		struct ieee80211vap *vap, struct ieee80211_channel *channel, int bw)
{
	int chan;
	int chan_sec;

	chan = channel->ic_ieee;
	if (!ap_ics_is_valid_obss_secondary(ic, as->as_obss_chanlayout[chan])) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
				"OBSS: Violation on primary channel %3u layout 0x%02x\n",
				chan, as->as_obss_chanlayout[chan]);
		return -1;
	}

	if (bw == BW_HT20)
		return 0;

	chan_sec = ieee80211_find_sec_chan(channel);
	if (chan_sec && !ap_ics_is_valid_obss_primary(ic, as->as_obss_chanlayout[chan_sec])) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
				"OBSS: Chan %3u violation on other primary channel[%3u sec20] layout 0x%02x\n",
				chan, chan_sec, as->as_obss_chanlayout[chan_sec]);
		return -1;
	}

	if (bw <= BW_HT40)
		return 0;

	chan_sec = ieee80211_find_sec40u_chan(channel);
	if (chan_sec && !ap_ics_is_valid_obss_primary(ic, as->as_obss_chanlayout[chan_sec])) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
				"OBSS: Chan %3u violation on other primary channel[%3u sec40u] layout 0x%02x\n",
				chan, chan_sec, as->as_obss_chanlayout[chan_sec]);
		return -1;
	}

	chan_sec = ieee80211_find_sec40l_chan(channel);
	if (chan_sec && !ap_ics_is_valid_obss_primary(ic, as->as_obss_chanlayout[chan_sec])) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
				"OBSS: Chan %3u violation on other primary channel[%3u sec40l] layout 0x%02x\n",
				chan, chan_sec, as->as_obss_chanlayout[chan_sec]);
		return -1;
	}

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
			"OBSS: compliance on channel %3u flag 0x%02x\n",
			chan, as->as_obss_chanlayout[chan]);

	return 0;
}

#define	IEEE80211_ICS_CHANSET_INACTIVE		(0)
#define	IEEE80211_ICS_CHANSET_NOT_BESTCHAN	(1)
#define	IEEE80211_ICS_CHANSET_OBSS_NO_CHECK	(2)
#define	IEEE80211_ICS_CHANSET_OBSS_CHECK	(3)

static struct ieee80211_channel*
ap_pick_primary_channel(struct ieee80211com *ic,
		struct ieee80211_scan_state *ss,
		int best_chanset, int bw, uint8_t chanset_type)
{
	int first;
	int last;
	int step;
	int chan;
	int bss_chan = 0;
	int bss_chan_num = 0;
	int bss_chan_value = QTN_CHAN_METRIC_MAX;
	int metric_chan = 0;
	int metric_chan_value = QTN_CHAN_METRIC_MAX;
	struct ieee80211_channel *channel;
	struct ap_state *as = ss->ss_priv;

	step = IEEE80211_CHAN_SEC_SHIFT;
	if (bw == BW_HT80) {
		first = best_chanset - (step + step / 2);
		last = best_chanset + (step + step / 2);
	} else if (bw == BW_HT40) {
		first = best_chanset - step / 2;
		last = best_chanset + step / 2;
	} else {
		first = best_chanset;
		last = best_chanset;
	}

	for (chan = first; chan <= last; chan += step) {
		if (isset(ic->ic_chan_pri_inactive, chan) || isclr(ic->ic_chan_active, chan))
			continue;

		channel = ieee80211_find_channel_by_ieee(ic, chan);
		if (chanset_type == IEEE80211_ICS_CHANSET_OBSS_CHECK &&
				ic->ic_autochan_obss_check &&
				ap_ics_obss_check(ic, as, ss->ss_vap, channel, bw)) {
			continue;
		}

		if (metric_chan_value > as->as_chanmetric[chan]) {
			metric_chan = chan;
			metric_chan_value = as->as_chanmetric[chan];
		}

		if (bss_chan_num < as->as_numbeacons[chan] ||
				(bss_chan_num == as->as_numbeacons[chan] &&
					bss_chan_value > as->as_chanmetric[chan])) {
			bss_chan = chan;
			bss_chan_num = as->as_numbeacons[chan];
			bss_chan_value = as->as_chanmetric[bss_chan];
		}
	}

	if (metric_chan_value == QTN_CHAN_METRIC_MAX) {
		IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,  "Incorrect chanset"
				" (central chan %d bw %d) selected", best_chanset, bw);
		return NULL;
	}

	IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN, "chanset %d bw %d "
			"chan %3u metric %d bss_chan %d num %d\n",
			best_chanset, bw, metric_chan, metric_chan_value,
			bss_chan, bss_chan_num);

	if (bss_chan_num)
		return ieee80211_find_channel_by_ieee(ic, bss_chan);

	return ieee80211_find_channel_by_ieee(ic, metric_chan);
}

static int
ap_chan_metric_is_close_enough(struct ieee80211com *ic, int base, int new_metric)
{
	if (new_metric > base)
		return (new_metric - base) < ic->ic_ics_check_margin;

	return (base - new_metric) < ic->ic_ics_check_margin;
}

static int
ap_update_ics_chanset_metric(struct ieee80211com *ic,
		struct ieee80211_scan_state *ss, int flags,
		int32_t *chanset_metric, uint8_t *active_chansets)
{
	int i;
	int cur_bw;
	int chan;
	int center_chan;
	struct ieee80211_channel *channel = NULL;
	struct ap_state *as = ss->ss_priv;
	int skip_reason = 0;
	int active_chanset_cnt = 0;
	int checked_chanset_cnt = 0;
	int chanset_type = IEEE80211_ICS_CHANSET_INACTIVE;
	uint8_t txpwr_chansets[IEEE80211_SCAN_MAX] = {0};
	uint32_t best_metric = 0;
	uint32_t best_tx_power = 0;
	int chan_tx_power;
	int is_candidate;
	int candidate_chanset_cnt;
	int candidate_chanset_idx;
	int last_center_chan;
	char rndbuf;
	int is_close;

	cur_bw = ieee80211_get_bw(ic);
	/*  update chanset metrics and check type */
	for (i = 0; i < ss->ss_last; i++) {
		channel = ss->ss_chans[i];
		chan = ieee80211_chan2ieee(ic, channel);

		if (!is_channel_valid(chan))
			continue;

		center_chan = ieee80211_get_center_chan(channel, cur_bw);
		if (!chanset_metric[center_chan] ||
				chanset_metric[center_chan] > as->as_chanmetric[chan]) {
			chanset_metric[center_chan] = as->as_chanmetric[chan];
		}

		skip_reason = ap_pick_ics_channel_validate(ic, channel, ss, flags);
		if (skip_reason)
			continue;

		if (isset(ic->ic_chan_pri_inactive, chan))
			continue;

		if (isclr(ic->ic_chan_active, chan))
			continue;

		if (active_chansets[center_chan] == IEEE80211_ICS_CHANSET_INACTIVE) {
			active_chansets[center_chan] = IEEE80211_ICS_CHANSET_OBSS_NO_CHECK;

			chan_tx_power = ieee80211_chan_get_maxpwr(channel, PWR_IDX_20M);
			if (chan_tx_power <= 0)
				chan_tx_power = channel->ic_maxpower;
			txpwr_chansets[center_chan] = chan_tx_power;

			active_chanset_cnt++;
		}

		if (ic->ic_autochan_obss_check &&
				ap_ics_obss_check(ic, as, ss->ss_vap, channel, cur_bw)) {
			continue;
		}

		active_chansets[center_chan] = IEEE80211_ICS_CHANSET_OBSS_CHECK;
		checked_chanset_cnt++;
	}

	if (checked_chanset_cnt == 0) {
		if (active_chanset_cnt > 0) {
			KASSERT(ic->ic_autochan_obss_check,
					("obss check enabled, active chanset is %u",
					 active_chanset_cnt));
			chanset_type = IEEE80211_ICS_CHANSET_OBSS_NO_CHECK;
			IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
					"%s: Skip OBSS check\n", __func__);
		}
	} else {
		chanset_type = IEEE80211_ICS_CHANSET_OBSS_CHECK;
	}

	last_center_chan = -1;
	candidate_chanset_idx = 0;
	/*  figure out the best metric tuple */
	for (i = 0; i < ss->ss_last; i++) {
		channel = ss->ss_chans[i];
		chan = ieee80211_chan2ieee(ic, channel);
		if (!is_channel_valid(chan))
			continue;
		center_chan = ieee80211_get_center_chan(channel, cur_bw);

		if (active_chansets[center_chan] < chanset_type ||
				chanset_type == IEEE80211_ICS_CHANSET_INACTIVE) {
			IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
					"%s: chanset[%d]-%d check type %d : %d\n",
					__func__, center_chan, chan,
					active_chansets[center_chan], chanset_type);
			active_chansets[center_chan] = IEEE80211_ICS_CHANSET_INACTIVE;
			continue;
		}

		if (last_center_chan == center_chan) {
			IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
					"%s: chanset[%d]-%d last_center_chan %d\n", __func__,
					center_chan, chan, last_center_chan);
			continue;
		}
		last_center_chan = center_chan;

		is_close = ap_chan_metric_is_close_enough(ic,
				best_metric, chanset_metric[center_chan]);
		if (chanset_metric[center_chan] > best_metric) {
			if (!is_close || txpwr_chansets[center_chan] >= best_tx_power) {
				best_metric = chanset_metric[center_chan];
				best_tx_power = txpwr_chansets[center_chan];
			}
		} else if (is_close && txpwr_chansets[center_chan] > best_tx_power) {
			best_metric = chanset_metric[center_chan];
			best_tx_power = txpwr_chansets[center_chan];
		}
	}

	if (chanset_type == IEEE80211_ICS_CHANSET_INACTIVE) {
		IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
				"%s: no active chansets\n", __func__);
		return candidate_chanset_idx;
	}

	last_center_chan = -1;
	candidate_chanset_cnt = 0;
	/*  figure out the best channel list */
	for (i = 0; i < ss->ss_last; i++) {
		channel = ss->ss_chans[i];
		chan = ieee80211_chan2ieee(ic, channel);
		if (!is_channel_valid(chan))
			continue;
		center_chan = ieee80211_get_center_chan(channel, cur_bw);

		if (active_chansets[center_chan] == IEEE80211_ICS_CHANSET_INACTIVE ||
				last_center_chan == center_chan) {
			continue;
		}
		last_center_chan = center_chan;

		is_close = ap_chan_metric_is_close_enough(ic,
				best_metric, chanset_metric[center_chan]);
		if (!is_close || best_tx_power != txpwr_chansets[center_chan]) {
			is_candidate = 0;
			active_chansets[center_chan] = IEEE80211_ICS_CHANSET_NOT_BESTCHAN;
		} else {
			is_candidate = 1;
			candidate_chanset_cnt++;
		}

		IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
				"%sChanset %3u [bw %2u] is activated, metric is %u, tx power is %d\n",
				is_candidate ? "*" : " ", center_chan, cur_bw,
				chanset_metric[center_chan], txpwr_chansets[center_chan]);
	}

	if (candidate_chanset_cnt > 1) {
		get_random_bytes(&rndbuf, 1);
		candidate_chanset_idx = rndbuf % candidate_chanset_cnt;
	}

	IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
			"%s: best metric %d best power %d candidate cnt %d random select idx %d\n",
			__func__, best_metric, best_tx_power,
			candidate_chanset_cnt, candidate_chanset_idx);

	return candidate_chanset_idx;
}

static struct ieee80211_channel*
ap_pick_channel(struct ieee80211com *ic, struct ieee80211_scan_state *ss, int flags)
{
	int i;
	int cur_bw;
	int chan;
	int center_chan;
	int last_center_chan;
	struct ieee80211_channel *channel = NULL;
	struct ieee80211_channel *candidate = NULL;
	struct ieee80211_channel *bsschannel = NULL;
	struct ieee80211_channel *alter_candidate = NULL;
	int32_t chanset_metrics[IEEE80211_SCAN_MAX] = {0};
	uint8_t active_chansets[IEEE80211_SCAN_MAX] = {0};
	struct ap_state *as = ss->ss_priv;
	int skip_reason = 0;
	int best_chanset = 0;
	int best_chanset_metric = 0;
	int alter_chanset[2] = {0};
	int alter_chanset_metric = 0;
	int cbsschan;
	int candidate_chanset_idx;

	if (IS_IEEE80211_24G_BAND(ic)) {
		candidate = ieee80211_chanset_pick_channel(ss->ss_vap);
		goto end;
	}

	ap_update_ics_chan_metric(ic, ss);
	candidate_chanset_idx = ap_update_ics_chanset_metric(ic, ss,
			flags, chanset_metrics, active_chansets);

	cur_bw = ieee80211_get_bw(ic);
	/* NB: use scan list order to preserve channel preference */
	for (i = 0, last_center_chan = -1; i < ss->ss_last;
			local_ap_pick_channel_debug(ic, ss, chan, skip_reason), i++) {
		channel = ss->ss_chans[i];
		chan = ieee80211_chan2ieee(ic, channel);

		skip_reason = ap_pick_ics_channel_validate(ic, channel, ss, flags);
		if (skip_reason)
			continue;

		center_chan = ieee80211_get_center_chan(channel, cur_bw);

		if (active_chansets[center_chan] == IEEE80211_ICS_CHANSET_INACTIVE) {
			/* can't be primary channel till this subchannel */
			skip_reason = IEEE80211_SCAN_SKIPCHAN_REASON_PRI_INACTIVE;
			continue;
		}

		if (active_chansets[center_chan] == IEEE80211_ICS_CHANSET_NOT_BESTCHAN) {
			skip_reason = IEEE80211_SCAN_SKIPCHAN_REASON_METRIC_BETTER;
			continue;
		}

		if (last_center_chan == center_chan) {
			if (chanset_metrics[center_chan] != as->as_chanmetric[chan])
				skip_reason = IEEE80211_SCAN_SKIPCHAN_REASON_METRIC_BETTER;
			continue;
		}
		last_center_chan = center_chan;

		if (candidate_chanset_idx-- == 0) {
			best_chanset = center_chan;
			best_chanset_metric = chanset_metrics[center_chan];
		}

		if ((!(channel->ic_flags & IEEE80211_CHAN_DFS) ||
					ieee80211_is_chan_available(channel)) &&
				alter_chanset_metric < chanset_metrics[center_chan]) {
			if (alter_chanset[0] != center_chan)
				alter_chanset[1] = alter_chanset[0];

			alter_chanset[0] = center_chan;
			alter_chanset_metric = chanset_metrics[center_chan];
		}
	}

	if (flags == IEEE80211_SCAN_PICK_NOT_AVAILABLE_DFS_ONLY &&
			!ic->ic_ignore_init_scan_icac && ic->ic_des_chan_after_init_cac) {
		chan = ic->ic_des_chan_after_init_cac;
		channel = ieee80211_find_channel_by_ieee(ic, chan);
		if (channel && (ic->ic_dfs_chans_available_for_cac(ic, channel, IEEE80211_ICAC))) {
			IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
					"%s: original ic_des_chan_after_init_cac channel %d\n",
					__func__, chan);

			if (isset(ic->ic_chan_pri_inactive, chan)) {
				IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
					"%s: ic_des_chan_after_init_cac channel %d in inactive primary"
					" channel list, try to switch another sub-channel\n", __func__, chan);
				channel = ieee80211_scan_switch_pri_chan(ss, channel);
				if (channel) {
					candidate = channel;
					IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
						"%s: new ic_des_chan_after_init_cac channel %d\n",
						__func__, channel->ic_ieee);
				} else {
					IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
						"%s: fail to find new ic_des_chan_after_init_cac channel\n",
						__func__);
				}
			} else {
				candidate = channel;
			}
		}
	}

	if (candidate == NULL && best_chanset) {
		candidate = ap_pick_primary_channel(ic, ss, best_chanset,
				cur_bw, active_chansets[best_chanset]);
	}

	if (candidate == NULL) {
		if (ic->ic_bsschan != IEEE80211_CHAN_ANYC)
			goto end;

		candidate = ss->ss_chans[0];
		IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
				"%s: no suitable channel, go to a default one\n", __func__);
	}
	IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
			"Selected primary channel %d bw %d\n", candidate->ic_ieee, cur_bw);

	if (ss->ss_flags & IEEE80211_SCAN_NOPICK)
		bsschannel = ic->ic_bsschan;
	else if (ic->ic_des_chan_after_init_scan && !ic->ic_ignore_init_scan_icac)
		bsschannel = ieee80211_find_channel_by_ieee(ic, ic->ic_des_chan_after_init_scan);
	else if (ic->ic_des_chan_after_init_cac && !ic->ic_ignore_init_scan_icac)
		bsschannel = ieee80211_find_channel_by_ieee(ic, ic->ic_des_chan_after_init_cac);
	else
		bsschannel = candidate;

	chan = ieee80211_chan2ieee(ic, bsschannel);
	if (!is_channel_valid(chan)) {
		printk("Invalid bsschannel: chan=%d, ss_flags=0x%04x, des_chan_after_init_scan=%d,"
				" des_chan_after_init_cac=%d\n",
				chan, ss->ss_flags, ic->ic_des_chan_after_init_scan,
				ic->ic_des_chan_after_init_cac);
	}

	cbsschan = ieee80211_get_center_chan(bsschannel, cur_bw);
	if (!is_channel_valid(alter_chanset[0]))
		alter_candidate = NULL;
	else if (alter_chanset[0] != cbsschan ||
			!(bsschannel && (bsschannel->ic_flags & IEEE80211_CHAN_DFS)))
		alter_candidate = ap_pick_primary_channel(ic, ss, alter_chanset[0],
				cur_bw, active_chansets[alter_chanset[0]]);
	else if (is_channel_valid(alter_chanset[1]))
		alter_candidate = ap_pick_primary_channel(ic, ss, alter_chanset[1],
				cur_bw, active_chansets[alter_chanset[1]]);
	else
		alter_candidate = NULL;

	if (alter_candidate)
		ic->ic_ieee_best_alt_chan = ieee80211_chan2ieee(ic, alter_candidate);
	else
		ic->ic_ieee_best_alt_chan = 0;

	IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
			"Fast-switch channel %d bw %d\n", alter_candidate ?
			alter_candidate->ic_ieee : 0, cur_bw);

end:
	IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
		"%s: algorithm %s%s, pick in %s%s%s channels\n", __func__,
		((ss->ss_pick_flags & IEEE80211_PICK_ALGORITHM_MASK) == IEEE80211_PICK_REENTRY) ? "dfs_reentry" : "",
		((ss->ss_pick_flags & IEEE80211_PICK_ALGORITHM_MASK) == IEEE80211_PICK_CLEAREST) ? "clearest" : "",
		((ss->ss_pick_flags & IEEE80211_PICK_DOMIAN_MASK) == IEEE80211_PICK_DFS) ? "dfs" : "",
		((ss->ss_pick_flags & IEEE80211_PICK_DOMIAN_MASK) == IEEE80211_PICK_NONDFS) ? "non_dfs" : "",
		((ss->ss_pick_flags & IEEE80211_PICK_DOMIAN_MASK) == IEEE80211_PICK_ALL) ? "all" : "");

	ss->ss_pick_flags = IEEE80211_PICK_DEFAULT;	/* clean the flag */

	return candidate;
}

/*
 * Pick a quiet channel to use for ap operation.
 */
static int
ap_end(struct ieee80211_scan_state *ss, struct ieee80211vap *vap,
       int (*action)(struct ieee80211vap *, const struct ieee80211_scan_entry *),
       u_int32_t flags)
{
	struct ieee80211_channel * bestchan = NULL;
	struct ap_state *as = ss->ss_priv;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_scan_entry se;
	int ret;

	KASSERT(vap->iv_opmode == IEEE80211_M_HOSTAP,
		("wrong opmode %u", vap->iv_opmode));

	/* scan end, no action and return */
	if (ss->ss_flags & IEEE80211_SCAN_QTN_SEARCH_MBS)
		return 1;

	/* scan end, do DFS action and return */
	if (ss->ss_flags & IEEE80211_SCAN_DFS_ACTION) {
		ic->ic_dfs_action_scan_done();
		return 1;
	}

#ifdef QTN_BG_SCAN
	if (ss->ss_flags & IEEE80211_SCAN_QTN_BGSCAN) {
		ss->ss_pick_flags = IEEE80211_PICK_DEFAULT;	/* clean the flag */
		return 1;
	}
#endif

	memset(&se, 0, sizeof(se));

	if (ic->ic_get_init_cac_duration(ic) > 0) {
		IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
				"%s: pick dfs channels only: for eu ICAC\n", __func__);
		flags = IEEE80211_SCAN_PICK_NOT_AVAILABLE_DFS_ONLY;
	}

	bestchan = ap_pick_channel(ic, ss, flags);
	if (bestchan == NULL) {
		IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
			"%s: no suitable channel! Go back!\n", vap->iv_dev->name);

		/*
		 * When max_boot_cac is a very large value, all channels are cleared.
		 * Return to ICAC completion procedure
		 */
		if (ic->ic_get_init_cac_duration(ic) > 0) {
			return 0;
		}

		if (ic->ic_bsschan != IEEE80211_CHAN_ANYC) {
			se.se_chan = ic->ic_bsschan;
			ret = 0;
		} else if (!ieee80211_chanset_scan_finished(ic)) {
			return 1;
		} else {
			return 0;			/* restart scan */
		}
	} else {
		struct ieee80211_channel *c;
		/* XXX notify all vap's? */
		/* if this is a dynamic turbo frequency , start with normal mode first */

		c = bestchan;
		if (IEEE80211_IS_CHAN_TURBO(c) && !IEEE80211_IS_CHAN_STURBO(c)) {
			if ((c = ieee80211_find_channel(ic, c->ic_freq,
					c->ic_flags & ~IEEE80211_CHAN_TURBO)) == NULL) {
				/* should never happen ?? */
				return 0;
			}
		}

		/*
		 * If bss channel is valid and if the
		 * scan is to not pick any channel then select the
		 * bss channel, otherwise choose the best channel.
		 */
		if ((ic->ic_bsschan != IEEE80211_CHAN_ANYC) &&
					(ss->ss_flags & IEEE80211_SCAN_NOPICK)) {
			IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
				"BSS channel was configured %d\n", ic->ic_bsschan->ic_ieee);
			se.se_chan = ic->ic_bsschan;
		} else {
			se.se_chan = c;
		}

		ret = 1;
	}

	/*
	 * ic->ic_des_chan_after_init_scan is valid only during initial bootup scan
	 * Any Scan after the initial bootup scan, shall choose the best channel
	 * referring to as_chanmetric;
	 */
	if (!ic->ic_ignore_init_scan_icac &&
			!ic->ic_des_chan_after_init_cac &&
			ic->ic_des_chan_after_init_scan) {
		struct ieee80211_channel *ch = ieee80211_find_channel_by_ieee(ic, ic->ic_des_chan_after_init_scan);

		if (ic->ic_check_channel(ic, ch, IEEE80211_CHANNEL_CHECK_ALLOW_CURRENT) &&
				isclr(ic->ic_chan_pri_inactive, ch->ic_ieee)) {
			se.se_chan = ch;
		}
		IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
			"Using configured channel %d\n", ic->ic_des_chan_after_init_scan);
		ic->ic_des_chan_after_init_scan = 0;
	}

	ic->ic_des_chan = se.se_chan;

	as->as_action = ss->ss_ops->scan_default;
	if (action)
		as->as_action = action;
	as->as_selbss = se;

	/*
	 * Must defer action to avoid possible recursive call through 80211
	 * state machine, which would result in recursive locking.
	 */
	IEEE80211_SCHEDULE_TQUEUE(&as->as_actiontq);

	return ret;
}

static int
ap_iterate(struct ieee80211_scan_state *ss,
	ieee80211_scan_iter_func *f, void *arg)
{
	struct ap_state *as = ss->ss_priv;
	struct ieee80211vap *vap = ss->ss_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ap_scan_entry *se;
	int chan;
	int res = 0;
	int i;
	int bh_disabled;

	bh_disabled = lock_ap_list(as);
	for (i = 0; i < ss->ss_last; i++) {
		chan = ieee80211_chan2ieee(ic, ss->ss_chans[i]);
		if (!is_channel_valid(chan))
			continue;

		TAILQ_FOREACH(se, &as->as_scan_list[chan].asl_head, ase_list) {
			set_se_inuse(se);
			res = (*f)(arg, &se->base);
			reset_se_inuse(se);
			if (res) {
				unlock_ap_list(as, bh_disabled);
				return res;
			}
		}
	}
	unlock_ap_list(as, bh_disabled);
	return res;
}

static void
local_ap_age(struct ieee80211_scan_state *ss, struct ap_state *as, int age_out)
{
	struct ap_scan_entry *se, *next;
	int i;
	int bh_disabled;
	int freed = 0;

	bh_disabled = lock_ap_list(as);
	for (i = 0; i < IEEE80211_CHAN_MAX; i++) {
		TAILQ_FOREACH_SAFE(se, &as->as_scan_list[i].asl_head, ase_list, next) {
			if (se->se_notseen > as->as_age) {
				TAILQ_REMOVE(&as->as_scan_list[i].asl_head, se, ase_list);
				if (age_out && as->as_numbeacons[se->base.se_chan->ic_ieee])
					as->as_numbeacons[se->base.se_chan->ic_ieee]--;
				free_se_request(se);
				freed = 1;
				if (as->as_entry_num > 0)
					as->as_entry_num--;
			} else {
				if (se->se_seen) {
					se->se_seen = 0;
				} else {
					se->se_notseen++;
				}
			}
		}
	}

	if (age_out && freed)
		memset(as->as_obss_chanlayout, 0, sizeof(as->as_obss_chanlayout));
	unlock_ap_list(as, bh_disabled);

	if (age_out && freed)
		ap_iterate(ss, (ieee80211_scan_iter_func *)ieee80211_scan_check_secondary_channel, ss);
}

static void
ap_age(struct ieee80211_scan_state *ss)
{
	struct ap_state *as;
	struct ap_state *as_bak;

	as = (struct ap_state *)ss->ss_scs_priv;
	as_bak = ss->ss_priv;
	ss->ss_priv = as;

	local_ap_age(ss, ss->ss_scs_priv, 1);

	ss->ss_priv = as_bak;

	local_ap_age(ss, ss->ss_priv, 0);
}

static void
ap_assoc_success(struct ieee80211_scan_state *ss,
	const u_int8_t macaddr[IEEE80211_ADDR_LEN])
{
	/* should not be called */
}

static void
ap_assoc_fail(struct ieee80211_scan_state *ss,
	const u_int8_t macaddr[IEEE80211_ADDR_LEN], int reason)
{
	/* should not be called */
}

/*
 * Default action to execute when a scan entry is found for ap
 * mode.  Return 1 on success, 0 on failure
 */
static int
ap_default_action(struct ieee80211vap *vap,
	const struct ieee80211_scan_entry *se)
{
	struct ieee80211com *ic = vap->iv_ic;

	if (ic->ic_bsschan != IEEE80211_CHAN_ANYC &&
			ic->ic_bsschan != se->se_chan &&
			vap->iv_state == IEEE80211_S_RUN) {
		ieee80211_enter_csa(ic,
				se->se_chan,
				NULL,
				IEEE80211_CSW_REASON_SCAN,
				IEEE80211_DEFAULT_CHANCHANGE_TBTT_COUNT,
				IEEE80211_CSA_CAN_STOP_TX,
				IEEE80211_CSA_F_BEACON | IEEE80211_CSA_F_ACTION);

	} else {
		ieee80211_create_bss(vap, se->se_chan);
	}

	if (IS_IEEE80211_24G_40(ic))
		ieee80211_check_20_40_bss_coexist(vap);

	return 1;
}

static void
action_tasklet(IEEE80211_TQUEUE_ARG data)
{
	struct ieee80211_scan_state *ss = (struct ieee80211_scan_state *)data;
	struct ap_state *as = (struct ap_state *)ss->ss_priv;
	struct ieee80211vap *vap = ss->ss_vap;

	(*ss->ss_ops->scan_default)(vap, &as->as_selbss);
}

/*
 * Module glue.
 */
MODULE_AUTHOR("Errno Consulting, Sam Leffler");
MODULE_DESCRIPTION("802.11 wireless support: default ap scanner");
#ifdef MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif

static const struct ieee80211_scanner ap_default = {
	.scan_name		= "default",
	.scan_attach		= ap_attach,
	.scan_detach		= ap_detach,
	.scan_start		= ap_start,
	.scan_restart		= ap_restart,
	.scan_cancel		= ap_cancel,
	.scan_end		= ap_end,
	.scan_flush		= ap_flush,
	.scan_pickchan		= ap_pick_channel,
	.scan_add		= ap_add,
	.scan_age		= ap_age,
	.scan_iterate		= ap_iterate,
	.scan_assoc_success	= ap_assoc_success,
	.scan_assoc_fail	= ap_assoc_fail,
	.scan_lock		= ap_lock,
	.scan_unlock		= ap_unlock,
	.scan_default		= ap_default_action,
};

static int __init
init_scanner_ap(void)
{
	mlme_stats_init();
	ieee80211_scanner_register(IEEE80211_M_HOSTAP, &ap_default);
	return 0;
}
module_init(init_scanner_ap);

static void __exit
exit_scanner_ap(void)
{
	ieee80211_scanner_unregister_all(&ap_default);
	mlme_stats_exit();
}
module_exit(exit_scanner_ap);
