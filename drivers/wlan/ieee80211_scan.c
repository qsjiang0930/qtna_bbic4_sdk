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
 * $Id: ieee80211_scan.c 1849 2006-12-08 17:20:08Z proski $
 */
#ifndef EXPORT_SYMTAB
#define	EXPORT_SYMTAB
#endif

/*
 * IEEE 802.11 scanning support.
 */
#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/version.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/random.h>
#include <linux/interrupt.h>
#include <linux/delay.h>

#include <qtn/qtn_debug.h>
#include <qtn/shared_defs.h>
#include <qtn/shared_params.h>
#include "net80211/if_media.h"
#include "net80211/ieee80211.h"
#include "net80211/ieee80211_var.h"
#include "net80211/ieee80211_node.h"
#include "net80211/ieee80211_scan.h"
#if defined(CONFIG_QTN_BSA_SUPPORT)
#include "net80211/ieee80211_bsa.h"
#include "net80211/ieee80211_qrpe.h"
#endif

struct scan_state {
	struct ieee80211_scan_state base;	/* public state */

	u_int ss_iflags;				/* flags used internally */
#define	ISCAN_MINDWELL		0x0001		/* min dwell time reached */
#define	ISCAN_DISCARD		0x0002		/* discard rx'd frames */
#define	ISCAN_CANCEL		0x0004		/* cancel current scan */
#define	ISCAN_START		0x0008		/* 1st time through next_scan */
#define	ISCAN_CANCEL_END	0x0010		/* cancel the current scan, go to scan_end directly */
#define	ISCAN_REP	(ISCAN_MINDWELL | ISCAN_START | ISCAN_DISCARD)
	unsigned long ss_chanmindwell;		/* min dwell on curchan */
	unsigned long ss_scanend;		/* time scan must stop */
	unsigned long ss_maxdwell_used;		/* max dwell to scan a channel */
	unsigned long ss_mindwell_used;		/* min dwell to scan a channel */
	u_int ss_duration;			/* duration for next scan */
	struct tasklet_struct ss_pwrsav;	/* sta ps ena tasklet */
	struct timer_list ss_scan_timer;	/* scan timer */
	struct timer_list ss_probe_timer;	/* start sending probe requests timer */
	unsigned long	ss_cc_jiffies;		/* record the last channel change jiffies */
};
#define	SCAN_PRIVATE(ss)	((struct scan_state *) ss)

/*
 * Amount of time to go off-channel during a background
 * scan.  This value should be large enough to catch most
 * ap's but short enough that we can return on-channel
 * before our listen interval expires.
 *
 * XXX tunable
 * XXX check against configured listen interval
 */
#define	IEEE80211_SCAN_OFFCHANNEL	msecs_to_jiffies(150)

/*
 * Roaming-related defaults.  RSSI thresholds are as returned by the
 * driver (dBm).  Transmit rate thresholds are IEEE rate codes (i.e
 * .5M units).
 */
#define	SCAN_VALID_DEFAULT		60	/* scan cache valid age (secs) */
#define	ROAM_RSSI_11A_DEFAULT		24	/* rssi threshold for 11a bss */
#define	ROAM_RSSI_11B_DEFAULT		24	/* rssi threshold for 11b bss */
#define	ROAM_RSSI_11BONLY_DEFAULT	24	/* rssi threshold for 11b-only bss */
#define	ROAM_RATE_11A_DEFAULT		2*24	/* tx rate threshold for 11a bss */
#define	ROAM_RATE_11B_DEFAULT		2*9	/* tx rate threshold for 11b bss */
#define	ROAM_RATE_11BONLY_DEFAULT	2*5	/* tx rate threshold for 11b-only bss */

static u_int32_t txpow_rxgain_count = 0;
static u_int32_t txpow_rxgain_state = 1;

static void scan_restart_pwrsav(unsigned long);
static void send_probes(struct ieee80211_scan_state *ss);
static void scan_next(unsigned long);
static void scan_saveie(u_int8_t **iep, const u_int8_t *ie);

#ifdef QSCS_ENABLED
int ieee80211_scs_init_ranking_stats(struct ieee80211com *ic)
{
	struct ap_state *as;
	int i;

	MALLOC(as, struct ap_state *, sizeof(struct ap_state),
		M_SCANCACHE, M_NOWAIT | M_ZERO);
	if (as == NULL) {
		printk("Failed to alloc scs ranking stats\n");
		return -1;
	}

	if (ic->ic_scan != NULL) {
		as->as_age = AP_PURGE_SCS;
		ic->ic_scan->ss_scs_priv = as;
		spin_lock_init(&as->asl_lock);
		for (i = 0; i < IEEE80211_CHAN_MAX; i++)
			TAILQ_INIT(&as->as_scan_list[i].asl_head);
	} else {
		FREE(as, M_SCANCACHE);
		return -1;
	}

	ieee80211_scs_clean_stats(ic, IEEE80211_SCS_STATE_RESET, 0);

	return 0;
}

void ieee80211_scs_deinit_ranking_stats(struct ieee80211com *ic)
{
	struct ieee80211_scan_state *ss = ic->ic_scan;
	struct ap_state *as;
	struct ap_state *as_bak;
	const struct ieee80211_scanner *scan;

	as = (struct ap_state *)ss->ss_scs_priv;
	if (as != NULL) {
		scan = ieee80211_scanner_get(IEEE80211_M_HOSTAP, 0);
		if (scan == NULL) {
			IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
				"%s: no scanner support for AP mode\n", __func__);
		} else {
			as_bak = ss->ss_priv;
			ss->ss_priv = as;
			scan->scan_detach(ss);
			ss->ss_priv = as_bak;
		}
		FREE(as, M_SCANCACHE);
	}

	ss->ss_scs_priv = NULL;
}
#endif

static void ieee80211_scan_free_phy_stats(struct ieee80211_scan_state *ss)
{
	int i;
	struct ieee80211_chan_phy_stats *p_phy_stats;

	for (i = 0; i < IEEE80211_SCAN_MAX; i++) {
		p_phy_stats = ss->phy_stats[i];
		kfree(p_phy_stats);
	}
}

static void send_probes_hdlr(unsigned long arg)
{
	struct ieee80211_scan_state *ss = (struct ieee80211_scan_state *) arg;

	send_probes(ss);
}

void
ieee80211_scan_attach(struct ieee80211com *ic)
{
	struct scan_state *ss;

	ic->ic_roaming = IEEE80211_ROAMING_AUTO;

	MALLOC(ss, struct scan_state *, sizeof(struct scan_state),
		M_80211_SCAN, M_NOWAIT | M_ZERO);
	if (ss != NULL) {
		init_timer(&ss->ss_scan_timer);
		ss->ss_scan_timer.function = scan_next;
		ss->ss_scan_timer.data = (unsigned long) ss;
		/* Init the send probe timer for active scans */
		init_timer(&ss->ss_probe_timer);
		ss->ss_probe_timer.function = send_probes_hdlr;
		ss->ss_probe_timer.data = (unsigned long) ss;
		tasklet_init(&ss->ss_pwrsav, scan_restart_pwrsav,
			(unsigned long) ss);
		ss->base.ss_pick_flags = IEEE80211_PICK_DEFAULT;
		ss->base.is_scan_valid = 0;
		ic->ic_scan = &ss->base;
		memcpy(ic->ic_scan_chan_list, ic->ic_chan_avail, sizeof(ic->ic_scan_chan_list));
	} else
		ic->ic_scan = NULL;

#ifdef QSCS_ENABLED
	ieee80211_scs_init_ranking_stats(ic);
#endif
}

void
ieee80211_scan_detach(struct ieee80211com *ic)
{
	struct ieee80211_scan_state *ss = ic->ic_scan;

	if (ss != NULL) {
#ifdef QSCS_ENABLED
		ieee80211_scs_deinit_ranking_stats(ic);
#endif
		del_timer(&SCAN_PRIVATE(ss)->ss_scan_timer);
		del_timer(&SCAN_PRIVATE(ss)->ss_probe_timer);
		tasklet_kill(&SCAN_PRIVATE(ss)->ss_pwrsav);
		if (ss->ss_ops != NULL) {
			ss->ss_ops->scan_detach(ss);
			ss->ss_ops = NULL;
		}
		ic->ic_flags &= ~IEEE80211_F_SCAN;
		ic->ic_flags_qtn &= ~IEEE80211_QTN_BGSCAN;
		ieee80211_scan_free_phy_stats(ss);
		ic->ic_scan = NULL;
		FREE(SCAN_PRIVATE(ss), M_80211_SCAN);
	}
}

void
ieee80211_scan_vattach(struct ieee80211vap *vap)
{
	vap->iv_bgscanidle = msecs_to_jiffies(IEEE80211_BGSCAN_IDLE_DEFAULT);
	vap->iv_bgscanintvl = vap->iv_ic->ic_extender_bgscanintvl;
	vap->iv_scanvalid = SCAN_VALID_DEFAULT * HZ;
	vap->iv_roam.rssi11a = ROAM_RSSI_11A_DEFAULT;
	vap->iv_roam.rssi11b = ROAM_RSSI_11B_DEFAULT;
	vap->iv_roam.rssi11bOnly = ROAM_RSSI_11BONLY_DEFAULT;
	vap->iv_roam.rate11a = ROAM_RATE_11A_DEFAULT;
	vap->iv_roam.rate11b = ROAM_RATE_11B_DEFAULT;
	vap->iv_roam.rate11bOnly = ROAM_RATE_11BONLY_DEFAULT;

	txpow_rxgain_count = 0;
	txpow_rxgain_state = 1;
}

void
ieee80211_scan_vdetach(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_scan_state *ss = ic->ic_scan;

	if (vap->iv_scan_freqs) {
		FREE(vap->iv_scan_freqs, M_DEVBUF);
		vap->iv_scan_freqs = NULL;
	}

	IEEE80211_LOCK_IRQ(ic);
	if (ss->ss_vap == vap) {
		if (ieee80211_is_scanning(ic)) {
			del_timer(&SCAN_PRIVATE(ss)->ss_scan_timer);
			del_timer(&SCAN_PRIVATE(ss)->ss_probe_timer);
			ic->ic_flags &= ~IEEE80211_F_SCAN;
			ic->ic_flags_qtn &= ~IEEE80211_QTN_BGSCAN;
			IEEE80211_ADDR_COPY(ss->scan_addr, vap->iv_myaddr);
		}
		if (ss->ss_ops != NULL) {
			ss->ss_ops->scan_detach(ss);
			ss->ss_ops = NULL;
		}
	}
	IEEE80211_UNLOCK_IRQ(ic);
}

/*
 * Simple-minded scanner module support.
 */
#define	IEEE80211_SCANNER_MAX	(IEEE80211_M_MONITOR+1)

static const char *scan_modnames[IEEE80211_SCANNER_MAX] = {
	[IEEE80211_M_IBSS]	= "wlan_scan_sta",
	[IEEE80211_M_STA]	= "wlan_scan_sta",
	[IEEE80211_M_AHDEMO]	= "wlan_scan_sta",
	[IEEE80211_M_HOSTAP]	= "wlan_scan_ap",
};
static const struct ieee80211_scanner *scanners[IEEE80211_SCANNER_MAX];

const struct ieee80211_scanner *
ieee80211_scanner_get(enum ieee80211_opmode mode, int tryload)
{
	int err;
	if (mode >= IEEE80211_SCANNER_MAX)
		return NULL;
	if (scan_modnames[mode] == NULL)
		return NULL;
	if (scanners[mode] == NULL && tryload) {
		err = ieee80211_load_module(scan_modnames[mode]);
		if (scanners[mode] == NULL || err)
			printk(KERN_WARNING "unable to load %s\n", scan_modnames[mode]);
	}
	return scanners[mode];
}
EXPORT_SYMBOL(ieee80211_scanner_get);

void
ieee80211_scanner_register(enum ieee80211_opmode mode,
	const struct ieee80211_scanner *scan)
{
	if (mode >= IEEE80211_SCANNER_MAX)
		return;
	scanners[mode] = scan;
}
EXPORT_SYMBOL(ieee80211_scanner_register);

void
ieee80211_scanner_unregister(enum ieee80211_opmode mode,
	const struct ieee80211_scanner *scan)
{
	if (mode >= IEEE80211_SCANNER_MAX)
		return;
	if (scanners[mode] == scan)
		scanners[mode] = NULL;
}
EXPORT_SYMBOL(ieee80211_scanner_unregister);

void
ieee80211_scanner_unregister_all(const struct ieee80211_scanner *scan)
{
	int m;

	for (m = 0; m < IEEE80211_SCANNER_MAX; m++)
		if (scanners[m] == scan)
			scanners[m] = NULL;
}
EXPORT_SYMBOL(ieee80211_scanner_unregister_all);

u_int8_t g_channel_fixed = 0;
static int
change_channel(struct ieee80211com *ic,
	struct ieee80211_channel *chan)
{
	if (!is_ieee80211_chan_valid(chan))
		return 1;

	/* If channel is fixed using iwconfig then don't do anything */
	if (!g_channel_fixed) {
		ic->ic_prevchan = ic->ic_curchan;
		ic->ic_curchan = chan;
		ic->ic_set_channel(ic);
	}

	return 0;
}

static char
channel_type(const struct ieee80211_channel *c)
{
	if (IEEE80211_IS_CHAN_ST(c))
		return 'S';
	if (IEEE80211_IS_CHAN_108A(c))
		return 'T';
	if (IEEE80211_IS_CHAN_108G(c))
		return 'G';
	if (IEEE80211_IS_CHAN_A(c))
		return 'a';
	if (IEEE80211_IS_CHAN_ANYG(c))
		return 'g';
	if (IEEE80211_IS_CHAN_B(c))
		return 'b';
	return 'f';
}

void
ieee80211_scan_dump_channels(const struct ieee80211_scan_state *ss)
{
	struct ieee80211com *ic = ss->ss_vap->iv_ic;
	const char *sep;
	int i;

	sep = "";
	for (i = ss->ss_next; i < ss->ss_last; i++) {
		const struct ieee80211_channel *c = ss->ss_chans[i];

		printf("%s%u%c", sep, ieee80211_chan2ieee(ic, c),
			channel_type(c));
		sep = ", ";
	}
}
EXPORT_SYMBOL(ieee80211_scan_dump_channels);

/*
 * Enable station power save mode and start/restart the scanning thread.
 */
static void
scan_restart_pwrsav(unsigned long arg)
{
	struct scan_state *ss = (struct scan_state *) arg;
	struct ieee80211vap *vap = ss->base.ss_vap;
	struct ieee80211com *ic = vap->iv_ic;
	/*
	 * Use an initial 1ms delay to ensure the null
	 * data frame has a chance to go out.
	 * XXX 1ms is a lot, better to trigger scan
	 * on tx complete.
	 */
	const int delay = MAX(msecs_to_jiffies(1), 1);

	ieee80211_sta_pwrsave(vap, 1);

	ic->ic_setparam(vap->iv_bss, IEEE80211_PARAM_BEACON_ALLOW,
			1, NULL, 0);
	ic->ic_scan_start(ic, ss->base.scan_addr);
	ss->ss_scanend = jiffies + delay + ss->ss_duration;
	ss->ss_iflags |= ISCAN_START;
	mod_timer(&ss->ss_scan_timer, jiffies + delay);
	/*
	 * FIXME: Note, we are not delaying probes at the start here so there
	 * may be issues with probe requests not being on the correct
	 * channel for the first channel scanned.
	 */
}

/*
 * Start/restart scanning.  If we're operating in station mode
 * and associated notify the ap we're going into power save mode
 * and schedule a callback to initiate the work (where there's a
 * better context for doing the work).  Otherwise, start the scan
 * directly.
 */
static int
scan_restart(struct scan_state *ss, u_int duration)
{
	struct ieee80211vap *vap = ss->base.ss_vap;
	struct ieee80211com *ic = vap->iv_ic;
	int defer = 0;

	if (ss->base.ss_next == ss->base.ss_last) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
			"%s: no channels to scan\n", __func__);
		return 0;
	}
	if (vap->iv_opmode == IEEE80211_M_STA &&
			/* qtn bgscan sends pwrsav frame in MuC, or use large NAV */
			(ss->base.ss_flags & IEEE80211_SCAN_QTN_BGSCAN) == 0 &&
			vap->iv_state == IEEE80211_S_RUN &&
			(ss->base.ss_flags & IEEE80211_SCAN_OPCHAN) == 0) {
		if ((vap->iv_bss->ni_flags & IEEE80211_NODE_PWR_MGT) == 0) {
			/*
			 * Initiate power save before going off-channel.
			 * Note that we cannot do this directly because
			 * of locking issues; instead we defer it to a
			 * tasklet.
			 */
			ss->ss_duration = duration;
			tasklet_schedule(&ss->ss_pwrsav);
			defer = 1;
		}
	}

	if (!defer) {
		if (vap->iv_opmode == IEEE80211_M_STA &&
				!(ss->base.ss_flags & IEEE80211_SCAN_QTN_BGSCAN) &&
				vap->iv_state == IEEE80211_S_RUN) {
			ic->ic_setparam(vap->iv_bss, IEEE80211_PARAM_BEACON_ALLOW,
				1, NULL, 0);
		}

		/* notify MuC firmware */
		ic->ic_scan_start(ic, ss->base.scan_addr);
		ss->ss_scanend = jiffies + duration;
		ss->ss_iflags |= ISCAN_START;
		mod_timer(&ss->ss_scan_timer, jiffies);
		/*
		 * FIXME: Note, we are not delaying probes at the start here so there
		 * may be issues with probe requests not being on the correct
		 * channel for the first channel scanned.
		 */
	}
	return 1;
}

static void
copy_ssid(struct ieee80211vap *vap, struct ieee80211_scan_state *ss,
	int nssid, const struct ieee80211_scan_ssid ssids[])
{
	uint32_t i;
	u_int8_t ssid[IEEE80211_NWID_LEN + 1];

	if (nssid > IEEE80211_SCAN_MAX_SSID) {
		/* XXX printf */
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
			"%s: too many ssid %d, ignoring all of them\n",
			__func__, nssid);
		return;
	}
	memcpy(ss->ss_ssid, ssids, nssid * sizeof(ssids[0]));
	ss->ss_nssid = nssid;

	for (i = 0; i < nssid; i++) {
		memcpy(ssid, &ssids[i].ssid, sizeof(ssids[i].ssid));
		ssid[ssids[i].len] = '\0';
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
			"specific scan SSID: %s\n", ssid);
	}
}

/*
 * Randomise the low order bytes of a MAC address.
 */
#define IEEE80211_SCAN_RANDOM_MAC_OFFSET 3
static void ieee80211_randomize_macaddr(uint8_t *macaddr)
{
	get_random_bytes(&macaddr[IEEE80211_SCAN_RANDOM_MAC_OFFSET],
			IEEE80211_ADDR_LEN - IEEE80211_SCAN_RANDOM_MAC_OFFSET);
}

/*
 * Randomize sequence num
 */
static void ieee80211_randomize_seqnum(struct ieee80211_node *ni)
{
	get_random_bytes(&ni->ni_txseqs[0], sizeof(ni->ni_txseqs[0]));
}

/*
 * Start a scan unless one is already going.
 */
int
ieee80211_start_scan(struct ieee80211vap *vap, int flags, u_int duration,
	u_int nssid, const struct ieee80211_scan_ssid ssids[])
{
	struct ieee80211com *ic = vap->iv_ic;
	const struct ieee80211_scanner *scan;
	struct ieee80211_scan_state *ss = ic->ic_scan;

	if ((ic->sta_dfs_info.sta_dfs_strict_mode) ||
			(flags & IEEE80211_SCAN_QTN_BGSCAN)) {
		if (is_ieee80211_chan_valid(ic->ic_bsschan) &&
				IEEE80211_IS_CHAN_CAC_IN_PROGRESS(ic->ic_bsschan)) {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
				"%s: Ignored - CAC in progress\n", __func__);
			return 0;
		}
	}

	scan = ieee80211_scanner_get(vap->iv_opmode, 0);
	if (scan == NULL) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
			"%s: no scanner support for mode %u\n",
			__func__, vap->iv_opmode);
		/* XXX stat */
		return 0;
	}

	if (ic->ic_flags_qtn & IEEE80211_QTN_MONITOR) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
			"%s: not scanning - monitor mode enabled\n", __func__);
		return 0;
	}

	if ((flags & IEEE80211_SCAN_ACTIVE_RANDOM) && vap->iv_state >= IEEE80211_S_AUTH) {
		ieee80211_note(vap, "Ignore randomized scan request in state=%u\n", vap->iv_state);
		flags &= ~IEEE80211_SCAN_ACTIVE_RANDOM;
	}

	IEEE80211_LOCK_IRQ(ic);
	if (!ieee80211_is_scanning(ic)) {
		/*
		 * Note, we will support background scan with scan bw flag,and for default scan bw,
		 * normal scan use default scan bw 20MHZ, background scan use default scan bw with
		 * current bw same with old version.
		 */
		if (flags & IEEE80211_SCAN_BW40)
			ss->ss_scan_bw = BW_HT40;
		else if (flags & IEEE80211_SCAN_BW80)
			ss->ss_scan_bw = BW_HT80;
		else if (flags & IEEE80211_SCAN_BW160)
			ss->ss_scan_bw = BW_HT160;
		else if (flags & IEEE80211_SCAN_BW20)
			ss->ss_scan_bw = BW_HT20;
		else if (flags & IEEE80211_SCAN_QTN_BGSCAN)
			ss->ss_scan_bw = ieee80211_get_bw(ic);
		else
			ss->ss_scan_bw = BW_HT20;

		IEEE80211_ADDR_COPY(ss->scan_addr, vap->iv_myaddr);
		if (flags & IEEE80211_SCAN_ACTIVE_RANDOM) {
			ieee80211_randomize_macaddr(ss->scan_addr);
			ieee80211_randomize_seqnum(vap->iv_bss);
		}

		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
			"%s: [%pM] %s%s scan, bw %s, duration %u, desired mode %s, %s%s%s%s%s%s\n",
			__func__,
			ss->scan_addr,
			flags & IEEE80211_SCAN_ACTIVE ? "active" : "passive",
			flags & IEEE80211_SCAN_ACTIVE_RANDOM ? " random" : "",
			ieee80211_bw2str(ss->ss_scan_bw),
			duration,
			ieee80211_phymode_name[ic->ic_des_mode],
			flags & IEEE80211_SCAN_FLUSH ? "flush" : "append",
			flags & IEEE80211_SCAN_NOPICK ? ", nopick" : "",
			flags & IEEE80211_SCAN_PICK1ST ? ", pick1st" : "",
			flags & IEEE80211_SCAN_ONCE ? ", once" : "",
			flags & IEEE80211_SCAN_OPCHAN ? ", operating channel only" : "",
			flags & IEEE80211_SCAN_QTN_BGSCAN ? ", background" : ", regular");

		ss->ss_vap = vap;
		if (ss->ss_ops != scan) {
			/* switch scanners; detach old, attach new */
			if (ss->ss_ops != NULL)
				ss->ss_ops->scan_detach(ss);
			if (!scan->scan_attach(ss)) {
				/* XXX attach failure */
				/* XXX stat+msg */
				ss->ss_ops = NULL;
			} else
				ss->ss_ops = scan;
		}

		if (ss->ss_ops != NULL) {
			if ((flags & IEEE80211_SCAN_NOSSID) == 0)
				copy_ssid(vap, ss, nssid, ssids);

			/* NB: top 4 bits for internal use */
			ss->ss_flags = flags & 0xfff;
			ss->ss_ext_flags = flags & IEEE80211_SCAN_EXT_FLAGS_MASK;
			if (ss->ss_flags & IEEE80211_SCAN_ACTIVE)
				vap->iv_stats.is_scan_active++;
			else
				vap->iv_stats.is_scan_passive++;
			if (flags & IEEE80211_SCAN_FLUSH)
				ss->ss_ops->scan_flush(ss);

			/* NB: flush frames rx'd before 1st channel change */
			SCAN_PRIVATE(ss)->ss_iflags |= ISCAN_DISCARD;
			ss->ss_ops->scan_start(ss, vap);
			if (scan_restart(SCAN_PRIVATE(ss), duration)) {
				if (flags & IEEE80211_SCAN_QTN_BGSCAN)
					ic->ic_flags_qtn |= IEEE80211_QTN_BGSCAN;
				else
					ic->ic_flags |= IEEE80211_F_SCAN;
				ieee80211_scan_scs_sample_cancel(vap);
#if defined(QBMPS_ENABLE)
				if ((ic->ic_flags_qtn & IEEE80211_QTN_BMPS) &&
						(vap->iv_opmode == IEEE80211_M_STA)) {
					/* exit power-saving */
			                ic->ic_pm_reason = IEEE80211_PM_LEVEL_SCAN_START;
					ieee80211_pm_queue_work(ic);
				}
#endif
			}

			if (ic->ic_qtn_bgscan.debug_flags >= 3) {
				printk("BG_SCAN: start %s scanning...\n",
					(ic->ic_flags_qtn & IEEE80211_QTN_BGSCAN) ?
					"background" : "regular");
			}

		}
	} else {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
			"%s: %s scan already in progress\n", __func__,
			ss->ss_flags & IEEE80211_SCAN_ACTIVE ? "active" : "passive");

		if (ieee80211_is_repeater_ap(vap))
			vap->iv_flags_ext |= IEEE80211_FEXT_SCAN_PENDING;
	}
	IEEE80211_UNLOCK_IRQ(ic);

	/* Don't transmit beacons while scanning */
	if (vap->iv_opmode == IEEE80211_M_HOSTAP &&
			!(flags & IEEE80211_SCAN_QTN_BGSCAN)) {
		ieee80211_beacon_stop_all(ic);
	}

	/* NB: racey, does it matter? */
	return (ic->ic_flags & IEEE80211_F_SCAN);
}
EXPORT_SYMBOL(ieee80211_start_scan);

/*
 * Under repeater mode, when any RUNNING AP interface is not in RUN state,
 * hold off scanning procedure on STA interface
 */
int ieee80211_should_scan(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211vap *vap_each;
	int ret = 1;

	if (vap->iv_opmode != IEEE80211_M_STA || !ieee80211_is_repeater(ic))
		return 1;

	IEEE80211_VAPS_LOCK_BH(ic);

	if (!ieee80211_get_ap_vap(ic)) {
		ret = 0;
		goto out;
	}

	if (ic->ic_flags_qtn & IEEE80211_F_CHANSWITCH) {
		ret = 0;
		goto out;
	}

	TAILQ_FOREACH(vap_each, &ic->ic_vaps, iv_next) {
		if (vap_each->iv_opmode == IEEE80211_M_HOSTAP &&
				(vap_each->iv_dev->flags & IFF_RUNNING) &&
				vap_each->iv_state != IEEE80211_S_RUN) {
			ret = 0;
			break;
		}
	}

out:
	IEEE80211_VAPS_UNLOCK_BH(ic);

	return ret;
}

/*
 * Check the scan cache for an ap/channel to use; if that
 * fails then kick off a new scan.
 */
int
ieee80211_check_scan(struct ieee80211vap *vap, int flags, u_int duration,
	u_int nssid, const struct ieee80211_scan_ssid ssids[],
	int (*action)(struct ieee80211vap *, const struct ieee80211_scan_entry *))
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_scan_state *ss = ic->ic_scan;
#ifdef SCAN_CACHE_ENABLE
	int checkscanlist = 0;
#endif

	/*
	 * Check if there's a list of scan candidates already.
	 * XXX want more than the ap we're currently associated with
	 */
	IEEE80211_LOCK_IRQ(ic);
	IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
		"%s: %s scan, duration %lu, desired mode %s, %s%s%s%s\n",
		__func__,
		flags & IEEE80211_SCAN_ACTIVE ? "active" : "passive",
		duration,
		ieee80211_phymode_name[ic->ic_des_mode],
		flags & IEEE80211_SCAN_FLUSH ? "flush" : "append",
		flags & IEEE80211_SCAN_NOPICK ? ", nopick" : "",
		flags & IEEE80211_SCAN_PICK1ST ? ", pick1st" : "",
		flags & IEEE80211_SCAN_ONCE ? ", once" : "",
		flags & IEEE80211_SCAN_USECACHE ? ", usecache" : "");

	if (ss->ss_ops != NULL) {
		/* XXX verify ss_ops matches vap->iv_opmode */
		if ((flags & IEEE80211_SCAN_NOSSID) == 0) {
			/*
			 * Update the ssid list and mark flags so if
			 * we call start_scan it doesn't duplicate work.
			 */
			copy_ssid(vap, ss, nssid, ssids);
			flags |= IEEE80211_SCAN_NOSSID;
		}
#ifdef SCAN_CACHE_ENABLE
		if (!ieee80211_is_scanning(ic) &&
				time_before(jiffies, ic->ic_lastscan + vap->iv_scanvalid)) {
			/*
			 * We're not currently scanning and the cache is
			 * deemed hot enough to consult.  Lock out others
			 * by marking IEEE80211_F_SCAN while we decide if
			 * something is already in the scan cache we can
			 * use.  Also discard any frames that might come
			 * in while temporarily marked as scanning.
			 */
			SCAN_PRIVATE(ss)->ss_iflags |= ISCAN_DISCARD;
			ic->ic_flags |= IEEE80211_F_SCAN;
			checkscanlist = 1;
		}
#endif
	}
	IEEE80211_UNLOCK_IRQ(ic);
#ifdef SCAN_CACHE_ENABLE
	if (checkscanlist) {
		/*
		 * ss must be filled out so scan may be restarted "outside"
		 * of the current callstack.
		 */
		ss->ss_flags = flags;
		ss->ss_duration = duration;
		if (ss->ss_ops->scan_end(ss, ss->ss_vap, action, flags & IEEE80211_SCAN_KEEPMODE)) {
			/* found an ap, just clear the flag */
			ic->ic_flags &= ~IEEE80211_F_SCAN;
			return 1;
		}
		/* no ap, clear the flag before starting a scan */
		ic->ic_flags &= ~IEEE80211_F_SCAN;
	}
#endif
	if ((flags & IEEE80211_SCAN_USECACHE) == 0 &&
			ieee80211_should_scan(vap)) {
		return ieee80211_start_scan(vap, flags, duration, nssid, ssids);
	} else {
		/* If we *must* use the cache and no ap was found, return failure */
		return 0;
	}
}

/*
 * Restart a previous scan.  If the previous scan completed
 * then we start again using the existing channel list.
 */
int
ieee80211_bg_scan(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_scan_state *ss = ic->ic_scan;

	IEEE80211_LOCK_IRQ(ic);
	if (!ieee80211_is_scanning(ic)) {
		u_int duration;
		/*
		 * Go off-channel for a fixed interval that is large
		 * enough to catch most ap's but short enough that
		 * we can return on-channel before our listen interval
		 * expires.
		 */
		duration = IEEE80211_SCAN_OFFCHANNEL;

		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
			"%s: %s scan, jiffies %lu duration %lu\n", __func__,
			ss->ss_flags & IEEE80211_SCAN_ACTIVE ? "active" : "passive",
			jiffies, duration);

		if (ss->ss_ops != NULL) {
			ss->ss_vap = vap;
			/*
			 * A background scan does not select a new sta; it
			 * just refreshes the scan cache.  Also, indicate
			 * the scan logic should follow the beacon schedule:
			 * we go off-channel and scan for a while, then
			 * return to the bss channel to receive a beacon,
			 * then go off-channel again.  All during this time
			 * we notify the ap we're in power save mode.  When
			 * the scan is complete we leave power save mode.
			 * If any beacon indicates there are frames pending
			 *for us then we drop out of power save mode
			 * (and background scan) automatically by way of the
			 * usual sta power save logic.
			 */
			ss->ss_flags |= IEEE80211_SCAN_NOPICK |
				IEEE80211_SCAN_BGSCAN;

			if (ic->ic_scan_opchan_enable && vap->iv_opmode == IEEE80211_M_STA) {
				ss->ss_flags |= IEEE80211_SCAN_OPCHAN | IEEE80211_SCAN_ACTIVE;
				ss->ss_ops->scan_start(ss, vap);
				IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
					"%s: force a new active bgscan", __func__);
			}

			/* if previous scan completed, restart */
			if (ss->ss_next >= ss->ss_last) {
				ss->ss_next = 0;
				if (ss->ss_flags & IEEE80211_SCAN_ACTIVE)
					vap->iv_stats.is_scan_active++;
				else
					vap->iv_stats.is_scan_passive++;
				ss->ss_ops->scan_restart(ss, vap);
			}
			/* NB: flush frames rx'd before 1st channel change */
			SCAN_PRIVATE(ss)->ss_iflags |= ISCAN_DISCARD;
			ss->ss_mindwell = duration;
			IEEE80211_ADDR_COPY(ss->scan_addr, vap->iv_myaddr);

			if (scan_restart(SCAN_PRIVATE(ss), duration)) {
				ic->ic_flags |= IEEE80211_F_SCAN;
				ic->ic_flags_ext |= IEEE80211_FEXT_BGSCAN;
			}
		} else {
			/* XXX msg+stat */
		}
	} else {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
			"%s: %s scan already in progress\n", __func__,
			ss->ss_flags & IEEE80211_SCAN_ACTIVE ? "active" : "passive");
	}
	IEEE80211_UNLOCK_IRQ(ic);

	/* NB: racey, does it matter? */
	return (ic->ic_flags & IEEE80211_F_SCAN);
}
EXPORT_SYMBOL(ieee80211_bg_scan);

static void
_ieee80211_cancel_scan(struct ieee80211vap *vap, int no_wait)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_scan_state *ss = ic->ic_scan;
	int update_beacon = 0;

	IEEE80211_LOCK_IRQ(ic);
	if (ieee80211_is_scanning(ic)) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
			"%s: cancel %s scan\n", __func__,
			ss->ss_flags & IEEE80211_SCAN_ACTIVE ? "active" : "passive");

		if (SCAN_PRIVATE(ss)->ss_iflags & ISCAN_CANCEL) {
			IEEE80211_UNLOCK_IRQ_EARLY(ic);
			return;
		}

		/* clear bg scan NOPICK and mark cancel request */
		ss->ss_flags &= ~IEEE80211_SCAN_NOPICK;
		SCAN_PRIVATE(ss)->ss_iflags |= ISCAN_CANCEL;

		if (vap->iv_state == IEEE80211_S_SCAN && is_ieee80211_chan_valid(ic->ic_des_chan))
			SCAN_PRIVATE(ss)->ss_iflags |= ISCAN_CANCEL_END;
		else
			ss->ss_ops->scan_cancel(ss, vap);

		if (no_wait) {
			/* force it to fire immediately */
			del_timer(&SCAN_PRIVATE(ss)->ss_scan_timer);
			(SCAN_PRIVATE(ss)->ss_scan_timer).function((SCAN_PRIVATE(ss)->ss_scan_timer).data);
		} else {
			/* force it to fire asap */
			mod_timer(&SCAN_PRIVATE(ss)->ss_scan_timer, jiffies);
		}

		/*
		 * Two reasons to update beacon
		 * 1. Standard scan - Beacon of all VAPs has been
		 * stopped at the scan beginning, need to start again
		 * 2. QTN BG scan - Beacon may have been updated when AP
		 * is on off channel, need to update.
		 */
		update_beacon = 1;
	}
	IEEE80211_UNLOCK_IRQ(ic);

#if defined(CONFIG_QTN_BSA_SUPPORT)
	ieee80211_qrpe_phy_info_update_event_send(ss, vap);
#endif

	if (update_beacon)
		ieee80211_beacon_update_all(ic);

	/*
	 * It's caller's responsibility to push the wlan state machine again,
	 * In case a scan was cancelled while ic_des_chan was NOT properly selected.
	 * ic_des_chan is set/valid only in AP mode; so avoid this check for non-AP interfaces
	 */
	if (vap->iv_opmode == IEEE80211_M_HOSTAP && vap->iv_state == IEEE80211_S_SCAN &&
		!is_ieee80211_chan_valid(ic->ic_des_chan))
		ieee80211_new_state(vap, IEEE80211_S_INIT, 0);
}

/*
 * Cancel any scan currently going on.
 */
void
ieee80211_cancel_scan(struct ieee80211vap *vap)
{
	_ieee80211_cancel_scan(vap, 0);
}

/*
 * Cancel any scan currently going on immediately
 */
void
ieee80211_cancel_scan_no_wait(struct ieee80211vap *vap)
{
	_ieee80211_cancel_scan(vap, 1);
}
EXPORT_SYMBOL(ieee80211_cancel_scan_no_wait);

/*
 * Process a beacon or probe response frame for SCS off channel sampling
 */
void ieee80211_add_scs_off_chan(struct ieee80211vap *vap,
	const struct ieee80211_scanparams *sp,
	const struct ieee80211_frame *wh,
	int subtype, int rssi, int rstamp)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_scan_state *ss = ic->ic_scan;
	struct ap_state *as;
	struct ap_state *as_bak;

	if (!ieee80211_are_scs_ap_only_funcs_allowed(ic))
		return;

	if (ieee80211_is_repeater(ic) && ss->ss_vap != vap) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
			"%s: unexpected ss_vap %s\n", __func__, ss->ss_vap->iv_dev->name);
		return;
	}

	as = (struct ap_state *)ss->ss_scs_priv;
	if (as && ss->ss_ops && ss->ss_ops->scan_add) {
		as_bak = ss->ss_priv;
		ss->ss_priv = as;
		ss->ss_ops->scan_add(ss, sp, wh, subtype, rssi, rstamp);
		ss->ss_priv = as_bak;
		ss->ss_ops->scan_add(ss, sp, wh, subtype, rssi, rstamp);
	}
}

void
ieee80211_scan_scs_sample_cancel(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;

	if (!ieee80211_are_scs_ap_only_funcs_allowed(ic))
		return;

	ic->ic_sample_channel_cancel(vap);
}

/*
 * Sample the state of an off-channel for Interference Mitigation
 */
void
ieee80211_scan_scs_sample(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	int scanning;
	int16_t scs_chan = ic->ic_scs.scs_last_smpl_chan;
	int16_t chan_count = 0;
	struct ieee80211_channel *chan;
	const struct ieee80211_scanner *scan;
	struct ieee80211_scan_state *ss = ic->ic_scan;
	int cur_bw;
	struct ieee80211vap *tmp_vap;
	int wds_basic_pure = 0;

	IEEE80211_LOCK_IRQ(ic);
	scanning = ieee80211_is_scanning(ic);
	IEEE80211_UNLOCK_IRQ(ic);
	if (scanning) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
			"%s: not sampling - scan in progress\n", __func__);
		IEEE80211_SCS_CNT_INC(&ic->ic_scs, IEEE80211_SCS_CNT_IN_SCAN);
		return;
	}

	if (!ic->ic_scs.scs_stats_on) {
		SCSDBG(SCSLOG_INFO, "not sampling - scs stats is disabled\n");
		return;
	}

	if (vap->iv_state != IEEE80211_S_RUN) {
		SCSDBG(SCSLOG_INFO, "not sampling - vap is not in running status\n");
		return;
	}

	if (ic->ic_ocac.ocac_running) {
		SCSDBG(SCSLOG_INFO, "not sampling - Seamless DFS is ongoing\n");
		return;
	}

	TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
		if (IEEE80211_VAP_WDS_IS_MBS(tmp_vap)) {
			wds_basic_pure = 0;
			break;
		} else if (IEEE80211_VAP_WDS_IS_RBS(tmp_vap)) {
			SCSDBG(SCSLOG_INFO, "not sampling - RBS mode\n");
			return;
		} else if (IEEE80211_VAP_WDS_BASIC(tmp_vap)) {
			wds_basic_pure = 1;
		}
	}

	if (wds_basic_pure) {
		SCSDBG(SCSLOG_INFO, "not sampling - basic WDS mode\n");
		return;
	}

	cur_bw = ieee80211_get_bw(ic);

	scan = ieee80211_scanner_get(IEEE80211_M_HOSTAP, 0);
	if (scan == NULL) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
			"%s: no scanner support for AP mode\n", __func__);
		return;
	}

	ss->ss_vap = vap;
	if (ss->ss_ops != scan) {
		if (ss->ss_ops != NULL)
			ss->ss_ops->scan_detach(ss);
		if (!scan->scan_attach(ss)) {
			ss->ss_ops = NULL;
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
				"%s: scanner attach failed\n", __func__);
			return;
		} else {
			ss->ss_ops = scan;
		}
	}

scan_next_chan:
	chan_count++;
	scs_chan += IEEE80211_SUBCHANNELS_OF_20MHZ;
	if (cur_bw >= BW_HT40)
		scs_chan += IEEE80211_SUBCHANNELS_OF_40MHZ - IEEE80211_SUBCHANNELS_OF_20MHZ;
	if (cur_bw >= BW_HT80)
		scs_chan += IEEE80211_SUBCHANNELS_OF_80MHZ - IEEE80211_SUBCHANNELS_OF_40MHZ;

	if (chan_count > ic->ic_nchans) {
		SCSDBG(SCSLOG_INFO, "no available off channel for sampling\n");
		return;
	}

	if (scs_chan >= ic->ic_nchans) {
		if (cur_bw > BW_HT20)
			ic->ic_scs.scs_smpl_chan_offset++;
		if (cur_bw == BW_HT40 && ic->ic_scs.scs_smpl_chan_offset >
					IEEE80211_SUBCHANNELS_OF_40MHZ - 1)
			ic->ic_scs.scs_smpl_chan_offset = 0;
		else if (cur_bw == BW_HT80 && ic->ic_scs.scs_smpl_chan_offset >
					IEEE80211_SUBCHANNELS_OF_80MHZ - 1)
			ic->ic_scs.scs_smpl_chan_offset = 0;
		scs_chan = 0;
		scs_chan += ic->ic_scs.scs_smpl_chan_offset;
	}

	chan = &ic->ic_channels[scs_chan];

	if (isclr(ic->ic_chan_active, chan->ic_ieee)) {
		goto scan_next_chan;
	}

	/* do not scan current working channel */
	if (chan->ic_ieee == ic->ic_curchan->ic_ieee) {
		goto scan_next_chan;
	}

	SCSDBG(SCSLOG_INFO, "choose sampling channel: %u\n", chan->ic_ieee);

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
		"%s: sampling channel %u freq=%u\n", __func__,
		chan->ic_ieee, chan->ic_freq);

	/* don't move to next until muc finish sampling */
	ic->ic_scs.scs_des_smpl_chan = scs_chan;

	ic->ic_sample_channel(vap, chan);
}
EXPORT_SYMBOL(ieee80211_scan_scs_sample);


int
ap_list_asl_table(struct ieee80211_scan_state *ss)
{
	struct ap_state *as = ss->ss_priv;
	struct ap_scan_entry *se, *next;
	int i;

	printk(KERN_ERR "CHINUSE_START\n");

	for (i = 0; i < IEEE80211_CHAN_MAX; i++) {
		TAILQ_FOREACH_SAFE(se, &as->as_scan_list[i].asl_head, ase_list, next) {
				printk(KERN_EMERG "Channel %d : %d Mhz\n",
				       se->base.se_chan->ic_ieee, se->base.se_chan->ic_freq);
				break;
		}
	}
	printk(KERN_ERR "CHINUSE_END\n");
	return 0;
}

/*
 * Getting maximum and minimum dwell time for scanning
 */
static void
ieee80211_scan_update_dwell_time(struct ieee80211_scan_state *ss,
		int is_passive, int is_obss_scan)
{
#define	NOT_PASSIVE_NOT_OBSS		0
#define	IS_PASSIVE_NOT_OBSS		1
#define	NOT_PASSIVE_BUT_OBSS		2
#define	IS_PASSIVE_AND_OBSS		3
	struct ieee80211vap *vap = ss->ss_vap;
	struct ieee80211_node *ni = vap->iv_bss;
	struct scan_state *ss_priv = SCAN_PRIVATE(ss);
	uint32_t cases = ((!!is_obss_scan) << 1) | (!!is_passive);

	if (is_passive && ss->ss_dwell_passive_override) {
		ss_priv->ss_mindwell_used = msecs_to_jiffies(ss->ss_dwell_passive_override);
		ss_priv->ss_maxdwell_used = msecs_to_jiffies(ss->ss_dwell_passive_override);
		return;
	} else if (!is_passive && ss->ss_dwell_active_override) {
		ss_priv->ss_mindwell_used = msecs_to_jiffies(ss->ss_dwell_active_override);
		ss_priv->ss_maxdwell_used = msecs_to_jiffies(ss->ss_dwell_active_override);
		return;
	}

	switch (cases) {
	case IS_PASSIVE_AND_OBSS:
		ss_priv->ss_mindwell_used = msecs_to_jiffies(ni->ni_obss_ie.obss_passive_dwell);
		ss_priv->ss_maxdwell_used = MAX(ss_priv->ss_mindwell_used, ss->ss_maxdwell_passive);
		break;
	case IS_PASSIVE_NOT_OBSS:
		ss_priv->ss_mindwell_used = ss->ss_mindwell_passive;
		ss_priv->ss_maxdwell_used = ss->ss_maxdwell_passive;
		break;
	case NOT_PASSIVE_BUT_OBSS:
		ss_priv->ss_mindwell_used = msecs_to_jiffies(ni->ni_obss_ie.obss_active_dwell);
		ss_priv->ss_maxdwell_used = MAX(ss_priv->ss_mindwell_used, ss->ss_maxdwell);
		break;
	case NOT_PASSIVE_NOT_OBSS:
		ss_priv->ss_mindwell_used = ss->ss_mindwell;
		ss_priv->ss_maxdwell_used = ss->ss_maxdwell;
		break;
	default:
		KASSERT(0, ("Invalid scan dwell time arguments\n"));
		break;
	}
}

static void send_probes(struct ieee80211_scan_state *ss)
{
	struct ieee80211vap *vap = ss->ss_vap;
	struct net_device *dev = vap->iv_dev;
	int i;

	/*
	 * Send a broadcast probe request followed by
	 * any specified directed probe requests.
	 * XXX suppress broadcast probe req?
	 * XXX remove dependence on vap/vap->iv_bss
	 * XXX move to policy code?
	 */
	if (vap->iv_bss) {
		ieee80211_send_probereq(vap->iv_bss,
			ss->scan_addr, ss->ss_bssid,
			dev->broadcast,
			(u_int8_t *)"", 0,
			vap->iv_opt_ie, vap->iv_opt_ie_len);

		for (i = 0; i < ss->ss_nssid; i++) {
			ieee80211_send_probereq(vap->iv_bss,
					ss->scan_addr, ss->ss_bssid,
				dev->broadcast,
				ss->ss_ssid[i].ssid,
				ss->ss_ssid[i].len,
				vap->iv_opt_ie, vap->iv_opt_ie_len);
		}

		if (vap->iv_opmode == IEEE80211_M_STA) {
			IEEE80211_VAPS_LOCK_BH(vap->iv_ic);
			struct ieee80211_scan_ssid_list *tmp = vap->iv_scan_ssid;
			while (tmp) {
				if (tmp->len)
					ieee80211_send_probereq(vap->iv_bss,
						ss->scan_addr, dev->broadcast,
						dev->broadcast,
						tmp->ssid,
						tmp->len,
						vap->iv_opt_ie, vap->iv_opt_ie_len);
				tmp = tmp->next;
			}
			IEEE80211_VAPS_UNLOCK_BH(vap->iv_ic);
		}
	}
}

static enum ieee80211_bgscan_mode
ieee80211_qtn_bgscan_identify_mode(struct ieee80211vap *vap,
	const struct ieee80211_channel *chan, uint16_t pick_flags,
	int is_passive)
{
	struct ieee80211com *ic = vap->iv_ic;
	enum ieee80211_bgscan_mode scan_mode;

	scan_mode = (pick_flags & IEEE80211_PICK_BG_MODE_MASK) >>
						IEEE80211_PICK_BG_MODE_SHIFT;

	if (scan_mode == IEEE80211_BGSCAN_MODE_FAKE_PS)
		return scan_mode;

	if (!is_passive)
		scan_mode = IEEE80211_BGSCAN_MODE_ACTIVE;

	if (chan->ic_ieee == ic->ic_bsschan->ic_ieee) {
		if (vap->iv_opmode != IEEE80211_M_STA) {
			scan_mode = IEEE80211_BGSCAN_MODE_ACTIVE;
		} else if ((scan_mode == IEEE80211_BGSCAN_MODE_ACTIVE)
				&& !ieee80211_is_repeater(ic)) {
			/*
			 * Allow repeater STA to use active BG scan as
			 * WMAC is always AP mode so TFS won't be messed up
			 */
			scan_mode = 0;
		}
	}

	if (!scan_mode) {
		/*
		 * Auto passive mode selection:
		 * 1) if FAT is larger than the threshold for fast mode
		 *  which is 60% by default, will pick passive fast mode
		 * 2) else if FAT is larger than the threshold for normal mode
		 * which is 30% by default, will pick passive normal mode
		 * 3) else pick passive slow mode.
		 */
		if (ic->ic_scs.scs_cca_idle_smthed >=
				ic->ic_qtn_bgscan.thrshld_fat_passive_fast)
			scan_mode = IEEE80211_BGSCAN_MODE_PASSIVE_FAST;
		else if (ic->ic_scs.scs_cca_idle_smthed >=
				ic->ic_qtn_bgscan.thrshld_fat_passive_normal)
			scan_mode = IEEE80211_BGSCAN_MODE_PASSIVE_NORMAL;
		else
			scan_mode = IEEE80211_BGSCAN_MODE_PASSIVE_SLOW;
	}

	return scan_mode;
}

/* In case traffic is detected */
#define IEEE80211_BGSCAN_TRAFFIC_DWELL_ACTIVE_MS		50
#define IEEE80211_BGSCAN_TRAFFIC_DWELL_PASSIVE_MS		100
#define IEEE80211_BGSCAN_TRAFFIC_ONCHANNEL_TIME_MS		190

/* In case no traffic is detected */
#define IEEE80211_BGSCAN_NOTRAFFIC_DWELL_ACTIVE_MS		100
#define IEEE80211_BGSCAN_NOTRAFFIC_DWELL_PASSIVE_MS		140
#define IEEE80211_BGSCAN_NOTRAFFIC_ONCHANNEL_TIME_MS		90

/* Threshold to identify if device is busy with Rx/Tx, in percentage of airtime */
#define IEEE80211_BGSCAN_THRESHLD_TRAFFIC_DETECT		15

static int ieee80211_bgscan_is_traffic_present(struct ieee80211com *ic)
{
	int cca_trfc = ic->ic_get_cca_trfc(ic);

	if (cca_trfc < 0 || cca_trfc > IEEE80211_BGSCAN_THRESHLD_TRAFFIC_DETECT)
		return 1;

	return 0;
}

static int
ieee80211_qtn_bgscan_channel(struct ieee80211_scan_state *ss,
		struct ieee80211_channel *chan,
		int is_passive, int is_obss)
{
	struct scan_state *ss_priv = SCAN_PRIVATE(ss);
	struct ieee80211vap *vap = ss->ss_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_node *ni = vap->iv_bss;
	enum ieee80211_bgscan_mode scan_mode;
	uint16_t bgscan_flags = 0;
	int bgscan_dwell = 0;
	int dwell_total = 0;
	int max_duration = 0;
	unsigned long scanend = ss_priv->ss_scanend;

	if (ss->ss_flags & IEEE80211_SCAN_QTN_BGSCAN &&
			(ss_priv->ss_iflags & ISCAN_START)) {
		ic->ic_bgscan_start(ic);
	}

	if (!is_ieee80211_chan_valid(ic->ic_bsschan)) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
				  "%s Invalid bss channel on vap state %d\n",
				  __func__, vap->iv_state);
		return 1;
	}

	scan_mode = ieee80211_qtn_bgscan_identify_mode(vap, chan, ss->ss_pick_flags, is_passive);

	switch (scan_mode) {
	case IEEE80211_BGSCAN_MODE_ACTIVE:
		max_duration = ic->ic_qtn_bgscan.duration_msecs_active;
		bgscan_flags |= QTN_OFF_CHAN_FLAG_ACTIVE;
		bgscan_dwell = ic->ic_qtn_bgscan.dwell_msecs_active;
		break;
	case IEEE80211_BGSCAN_MODE_PASSIVE_FAST:
		max_duration = ic->ic_qtn_bgscan.duration_msecs_passive_fast;
		bgscan_dwell = ic->ic_qtn_bgscan.dwell_msecs_passive;
		bgscan_flags |= QTN_OFF_CHAN_FLAG_PASSIVE_FAST;
		break;
	case IEEE80211_BGSCAN_MODE_PASSIVE_NORMAL:
		max_duration = ic->ic_qtn_bgscan.duration_msecs_passive_normal;
		bgscan_dwell = ic->ic_qtn_bgscan.dwell_msecs_passive;
		bgscan_flags |= QTN_OFF_CHAN_FLAG_PASSIVE_NORMAL;
		break;
	case IEEE80211_BGSCAN_MODE_FAKE_PS:
		if (ieee80211_bgscan_is_traffic_present(ic)) {
			if (is_passive) {
				bgscan_dwell = IEEE80211_BGSCAN_TRAFFIC_DWELL_PASSIVE_MS;
				max_duration = IEEE80211_BGSCAN_TRAFFIC_DWELL_PASSIVE_MS +
					IEEE80211_BGSCAN_TRAFFIC_ONCHANNEL_TIME_MS;
			} else {
				bgscan_dwell = IEEE80211_BGSCAN_TRAFFIC_DWELL_ACTIVE_MS;
				max_duration = IEEE80211_BGSCAN_TRAFFIC_DWELL_ACTIVE_MS +
					IEEE80211_BGSCAN_TRAFFIC_ONCHANNEL_TIME_MS;
			}
		} else {
			if (is_passive) {
				bgscan_dwell = IEEE80211_BGSCAN_NOTRAFFIC_DWELL_PASSIVE_MS;
				max_duration = IEEE80211_BGSCAN_NOTRAFFIC_DWELL_PASSIVE_MS +
					IEEE80211_BGSCAN_NOTRAFFIC_ONCHANNEL_TIME_MS;
			} else {
				bgscan_dwell = IEEE80211_BGSCAN_NOTRAFFIC_DWELL_ACTIVE_MS;
				max_duration = IEEE80211_BGSCAN_NOTRAFFIC_DWELL_ACTIVE_MS +
					IEEE80211_BGSCAN_NOTRAFFIC_ONCHANNEL_TIME_MS;
			}
		}

		if (is_passive)
			bgscan_flags |= QTN_OFF_CHAN_FLAG_PASSIVE_ONESHOT;
		else
			bgscan_flags |= QTN_OFF_CHAN_FLAG_ACTIVE;

		bgscan_flags |= QTN_OFF_CHAN_FAKE_POWERSAVE;
		break;
	case IEEE80211_BGSCAN_MODE_PASSIVE_SLOW:
	default:
		max_duration = ic->ic_qtn_bgscan.duration_msecs_passive_slow;
		bgscan_dwell = ic->ic_qtn_bgscan.dwell_msecs_passive;
		bgscan_flags |= QTN_OFF_CHAN_FLAG_PASSIVE_SLOW;
		break;
	}

	if (is_obss && ni) {
		if (is_passive) {
			bgscan_flags &= ~QTN_OFF_CHAN_FLAG_ACTIVE;
			bgscan_dwell = IEEE80211_TU_TO_MS(ni->ni_obss_ie.obss_passive_dwell);
			dwell_total = IEEE80211_TU_TO_MS(ni->ni_obss_ie.obss_passive_total);
		} else {
			bgscan_flags |= QTN_OFF_CHAN_FLAG_ACTIVE;
			bgscan_dwell = IEEE80211_TU_TO_MS(ni->ni_obss_ie.obss_active_dwell);
			dwell_total = IEEE80211_TU_TO_MS(ni->ni_obss_ie.obss_active_total);
		}

		/* switch channel only once if dwell is short */
		if (IEEE80211_MS_TO_USEC(dwell_total) <=
				(IEEE80211_MAX_NAV - QTN_SCAN_TIME_OFFCHAN_MARGIN_TOTAL_USEC))
			bgscan_dwell = dwell_total;

		if (bgscan_dwell < QTN_SCAN_TIME_OFFCHAN_MIN_DWELL_MSEC)
			bgscan_dwell = QTN_SCAN_TIME_OFFCHAN_MIN_DWELL_MSEC;

		if (!ieee80211_is_repeater(ic))
			bgscan_flags |= QTN_OFF_CHAN_FAKE_POWERSAVE;

		max_duration = ic->ic_qtn_bgscan.duration_msecs_obss;
	} else {
		if (is_passive && ss_priv->base.ss_dwell_passive_override)
			bgscan_dwell = ss_priv->base.ss_dwell_passive_override;
		else if (!is_passive && ss_priv->base.ss_dwell_active_override)
			bgscan_dwell = ss_priv->base.ss_dwell_active_override;

		if (ss_priv->base.ss_sample_duration_override)
			max_duration = ss_priv->base.ss_sample_duration_override;
	}

	ss_priv->ss_mindwell_used = msecs_to_jiffies(max_duration);
	ss_priv->ss_maxdwell_used = ss_priv->ss_mindwell_used;

	if (time_after(jiffies + ss_priv->ss_mindwell_used, scanend))
		return 1;

	/*
	 * Workaround: in STA mode, don't send probe request frame
	 * directly because the probe response frame from other AP
	 * may mess up the txalert timer
	 */
	if (chan->ic_ieee == ic->ic_bsschan->ic_ieee &&
			((vap->iv_opmode != IEEE80211_M_STA)
			 || ieee80211_is_repeater(ic))) {
		send_probes(ss);
	} else {
		if (!((ss->ss_ext_flags & IEEE80211_SCAN_BGSCAN_CHECK_TRAFFIC) &&
					ieee80211_bgscan_is_traffic_present(ic)))
			ic->ic_bgscan_channel(vap, chan, bgscan_flags,
					bgscan_dwell, dwell_total, ss->ss_scan_bw,
					max_duration, ss->ss_bssid);
		else
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
					 "%s traffic found,skip this off channel period\n",
					 __func__);
	}

	return 0;
}

static void
ieee80211_scan_adjust_txpower(struct ieee80211_scan_state *ss)
{
	struct ieee80211vap *vap = ss->ss_vap;
	struct ieee80211com *ic = vap->iv_ic;

	if ((vap->iv_opmode == IEEE80211_M_STA) && (ss->ss_next == 0)) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
				  "%s Starting a scan (Low power %s, count %d)\n",
				  __func__, txpow_rxgain_state ? "on" : "off", txpow_rxgain_count);
		/*
		 * Periodically scan using low Rx gain and Tx power in case
		 * association is failing because the AP is too close.
		 * More suitable power settings will be determined after association.
		 */
		if ((ic->ic_pwr_adjust_scancnt > 0) &&
				(ss->is_scan_valid) &&
				!(ss->ss_flags & IEEE80211_SCAN_QTN_BGSCAN) &&
				(txpow_rxgain_count) &&
				!(txpow_rxgain_count % ic->ic_pwr_adjust_scancnt)) {
			ieee80211_pwr_adjust(vap, txpow_rxgain_state);
			txpow_rxgain_state = !txpow_rxgain_state;
		}
		txpow_rxgain_count++;
	}
}

int
ieee80211_scan_phy_stats_update(struct ieee80211_scan_state *ss,
		struct ieee80211_channel *chan)
{
	struct scan_state *ss_priv = SCAN_PRIVATE(ss);
	struct ieee80211com *ic = ss->ss_vap->iv_ic;
	struct qtn_scs_scan_info scan_info;
	struct ieee80211_chan_phy_stats phy_stats = {0};
	uint8_t chan_ieee;
	int ret;

	ret = ieee80211_scs_get_scaled_scan_info(ic, chan->ic_ieee, &scan_info);

	if (!ret) {
		chan_ieee = chan->ic_ieee;
		phy_stats.bw = scan_info.bw_sel;
		phy_stats.cca_try = scan_info.cca_try;
		phy_stats.cca_pri = scan_info.cca_pri;
		phy_stats.cca_sec20 = scan_info.cca_sec20;
		phy_stats.cca_sec40 = scan_info.cca_sec40;
		phy_stats.cca_tx = scan_info.cca_tx;
		phy_stats.sample_duration = jiffies_to_msecs(jiffies - ss_priv->ss_cc_jiffies);
		phy_stats.hw_noise = scan_info.hw_noise;
		phy_stats.ispassive = (!(ss->ss_flags & IEEE80211_SCAN_ACTIVE) ||
				(ic->ic_curchan->ic_flags & IEEE80211_CHAN_PASSIVE));

		ieee80211_chan_phy_stats_update(ss, &phy_stats, chan_ieee);
	}

	return 0;
}
EXPORT_SYMBOL(ieee80211_scan_phy_stats_update);

static int
ieee80211_scan_change_channel(struct ieee80211_scan_state *ss,
		struct ieee80211_channel *chan,
		int is_passive, int is_obss)
{
	struct scan_state *ss_priv = SCAN_PRIVATE(ss);
	struct ieee80211vap *vap = ss->ss_vap;
	struct ieee80211com *ic = vap->iv_ic;
	int end = 0;
	struct ieee80211_channel *last_chan = ic->ic_curchan;

	/* Reset mindwell and maxdwell as the new channel could be passive */
	ieee80211_scan_update_dwell_time(ss, is_passive, is_obss);

	if (time_after(jiffies + ss_priv->ss_mindwell_used, ss_priv->ss_scanend))
		return 1;

	/*
	 * Watch for truncation due to the scan end time.
	 */
	if (time_after(jiffies + ss_priv->ss_maxdwell_used, ss_priv->ss_scanend))
		ss_priv->ss_maxdwell_used = ss_priv->ss_scanend - jiffies;

	/*
	 * Potentially change channel and phy mode.
	 * Channel change done with 20MHz wide channels unless in 40MHz only mode
	 */
	if (!((ss->ss_flags & IEEE80211_SCAN_BGSCAN) &&
				chan->ic_ieee == ic->ic_curchan->ic_ieee)) {
		if (ss->ss_scan_bw == BW_HT20) {
			ic->ic_flags_ext |= IEEE80211_FEXT_SCAN_20;
		} else if ((ss->ss_scan_bw == BW_HT40) || (ic->ic_11n_40_only_mode)) {
			ic->ic_flags_ext |= IEEE80211_FEXT_SCAN_40;
		} else {
			KASSERT(0, ("Invalid scan bandwidth\n"));
			return 1;
		}

		end = change_channel(ic, chan);

		if (!(ss_priv->ss_iflags & ISCAN_START))
			ieee80211_scan_phy_stats_update(ss, last_chan);
		ss_priv->ss_cc_jiffies = jiffies;

		if (ss->ss_scan_bw == BW_HT20)
			ic->ic_flags_ext &= ~IEEE80211_FEXT_SCAN_20;
		else if ((ss->ss_scan_bw == BW_HT40) || (ic->ic_11n_40_only_mode))
			ic->ic_flags_ext &= ~IEEE80211_FEXT_SCAN_40;
	}

	return end;
}

static int
ieee80211_scan_channel(struct ieee80211_scan_state *ss,
		struct ieee80211_channel *chan,
		int is_passive, int is_obss)
{
	struct scan_state *ss_priv = SCAN_PRIVATE(ss);
	struct ieee80211vap *vap = ss->ss_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_channel *prev_chan = ic->ic_curchan;
	int end;

	if (ss->ss_flags & IEEE80211_SCAN_QTN_BGSCAN)
		end = ieee80211_qtn_bgscan_channel(ss, chan, is_passive, is_obss);
	else
		end = ieee80211_scan_change_channel(ss, chan, is_passive, is_obss);

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
			"%s: chan %3u%c -> %3u%c [%s, dwell min %u max %u]\n",
			__func__,
			ieee80211_chan2ieee(ic, prev_chan),
			channel_type(prev_chan),
			ieee80211_chan2ieee(ic, chan),
			channel_type(chan),
			is_passive ? "passive" : "active",
			jiffies_to_msecs(ss_priv->ss_mindwell_used),
			jiffies_to_msecs(ss_priv->ss_maxdwell_used));

	return end;
}

static void
ieee80211_scan_probe_channel(struct ieee80211_scan_state *ss,
			int is_passive)
{
	struct scan_state *ss_priv = SCAN_PRIVATE(ss);

	/*
	 * If doing an active scan and the channel is not
	 * marked passive-only then send a probe request.
	 * Otherwise just listen for traffic on the channel.
	 */
	if (!is_passive && !(ss->ss_flags & IEEE80211_SCAN_QTN_BGSCAN)) {
		/*
		 * Delay sending the probe requests so we are on
		 * the new channel. Current delay is half of maxdwell
		 * to make sure it is well within the dwell time,
		 * this can be fine tuned later if necessary.
		 */
		mod_timer(&ss_priv->ss_probe_timer,
				jiffies + (ss_priv->ss_maxdwell_used / 2));
	}
}

static int
ieee80211_run_scan(struct ieee80211_scan_state *ss)
{
	struct scan_state *ss_priv = SCAN_PRIVATE(ss);
	struct ieee80211vap *vap = ss->ss_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_channel *chan;
	int is_passive;
	int is_obss = !!(ss->ss_flags & IEEE80211_SCAN_OBSS);
	int scandone = (ss->ss_next >= ss->ss_last) ||
				(ss_priv->ss_iflags & ISCAN_CANCEL);

	if (scandone)
		return 1;

	if (ss->ss_flags & IEEE80211_SCAN_GOTPICK)
		return 1;

	chan = ss->ss_chans[ss->ss_next++];
	ic->ic_scanchan = chan;
	is_passive = (!(ss->ss_flags & IEEE80211_SCAN_ACTIVE) ||
				(chan->ic_flags & IEEE80211_CHAN_PASSIVE));

	if (ieee80211_scan_channel(ss, chan, is_passive, is_obss))
		return 1;

	ieee80211_scan_probe_channel(ss, is_passive);

	ss_priv->ss_chanmindwell = jiffies + ss_priv->ss_mindwell_used;
	mod_timer(&ss_priv->ss_scan_timer, jiffies + ss_priv->ss_maxdwell_used);

	/* clear mindwell lock and initial channel change flush */
	ss_priv->ss_iflags &= ~ISCAN_REP;

	return 0;
}

static void
ieee80211_scan_pre_done(struct ieee80211_scan_state *ss)
{
	struct scan_state *ss_priv = SCAN_PRIVATE(ss);
	struct ieee80211vap *vap = ss->ss_vap;
	struct ieee80211com *ic = vap->iv_ic;
	int scandone = (ss->ss_next >= ss->ss_last) ||
				(ss_priv->ss_iflags & ISCAN_CANCEL);

	ic->ic_scan_end(ic);		/* notify MuC firmware */
	IEEE80211_ADDR_COPY(ss->scan_addr, vap->iv_myaddr);

	if (ss->ss_flags & IEEE80211_SCAN_QTN_BGSCAN)
		ic->ic_bgscan_end(ic);

	/*
	 * Record scan complete time.  Note that we also do
	 * this when canceled so any background scan will
	 * not be restarted for a while.
	 */
	if (scandone) {
		ic->ic_lastscan = jiffies;
#ifdef QSCS_ENABLED
		if ((ss_priv->ss_iflags & ISCAN_CANCEL) == 0)
			ieee80211_scs_update_ranking_table_by_scan(ic);
#endif
	}

	/* clear internal flags and any indication of a pick */
	ss_priv->ss_iflags &= ~ISCAN_REP;
	ss->ss_flags &= ~IEEE80211_SCAN_GOTPICK;
}

static void ieee80211_scan_abort_notify(struct ieee80211vap *vap)
{
	struct net_device *dev = vap->iv_dev;

	ieee80211_eventf(dev, IEEE80211_EVENT_SCAN_ABORT_TAG);
}

static void
ieee80211_scan_post_done(struct ieee80211_scan_state *ss)
{
	struct scan_state *ss_priv = SCAN_PRIVATE(ss);
	struct ieee80211vap *vap = ss->ss_vap;
	struct ieee80211com *ic = vap->iv_ic;
	int scandone = (ss->ss_next >= ss->ss_last) ||
				(ss_priv->ss_iflags & ISCAN_CANCEL);
	unsigned long scanend = ss_priv->ss_scanend;
	struct ieee80211vap *ap_vap;
	struct ieee80211_channel *last_chan = ic->ic_curchan;

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
			"%s: %s, [jiffies %lu, dwell min %u scanend %lu]\n",
			__func__, scandone ? "done" : "stopped",
			jiffies, jiffies_to_msecs(ss_priv->ss_mindwell_used),
			scanend);

	/* past here, scandone is ``true'' if not in bg mode */
	if ((ss->ss_flags & IEEE80211_SCAN_BGSCAN) == 0)
		scandone = 1;

	/* don't care about bgscan case */
	if (ieee80211_is_scanning(ic))
		wake_up_interruptible_all(&ic->ic_scan_comp);

	/*
	 * Clear the SCAN bit first in case frames are
	 * pending on the station power save queue.  If
	 * we defer this then the dispatch of the frames
	 * may generate a request to cancel scanning.
	 */
	ic->ic_flags &= ~IEEE80211_F_SCAN;
	ic->ic_flags_qtn &= ~IEEE80211_QTN_BGSCAN;

	/* return to the bss channel */
	if (ic->ic_bsschan != IEEE80211_CHAN_ANYC) {
		if (ss->ss_flags & IEEE80211_SCAN_QTN_BGSCAN) {
			ic->ic_run_dfs_action(ic);
		} else {
			change_channel(ic, ic->ic_bsschan);
			ieee80211_scan_phy_stats_update(ss, last_chan);
		}
		if (!(ss_priv->ss_iflags & ISCAN_CANCEL)) {
			/*
			 * Two reasons to update beacon
			 * 1. Standard scan - Beacon of all VAPs has been
			 * stopped at the scan beginning, need to start again
			 * 2. QTN BG scan - Beacon may have been updated when AP
			 * is on off channel, need to update.
			 */
			ieee80211_beacon_update_all(ic);
		}
	}

	if ((ss_priv->ss_iflags & ISCAN_CANCEL) == 0) {
		ieee80211_check_type_of_neighborhood(ic);
#ifdef QSCS_ENABLED
		ieee80211_scs_adjust_cca_threshold(ic);
#endif
	}

#if defined(QBMPS_ENABLE)
	if ((ic->ic_flags_qtn & IEEE80211_QTN_BMPS) &&
			(vap->iv_opmode == IEEE80211_M_STA)) {
		/* re-enter power-saving if possible */
                ic->ic_pm_reason = IEEE80211_PM_LEVEL_SCAN_STOP;
		ieee80211_pm_queue_work(ic);
	}
#endif
	/*
	 * Drop out of power save mode when a scan has
	 * completed.  If this scan was prematurely terminated
	 * because it is a background scan then don't notify
	 * the ap; we'll either return to scanning after we
	 * receive the beacon frame or we'll drop out of power
	 * save mode because the beacon indicates we have frames
	 * waiting for us.
	 */
	if (scandone) {
		ieee80211_sta_pwrsave(vap, 0);
		if ((vap->iv_state == IEEE80211_S_RUN) &&
				(vap->iv_opmode == IEEE80211_M_STA)) {
			ic->ic_setparam(vap->iv_bss, IEEE80211_PARAM_BEACON_ALLOW,
					0, NULL, 0);
		}

		if (ss->ss_next >= ss->ss_last) {
			ieee80211_notify_scan_done(vap);

#if defined(CONFIG_QTN_BSA_SUPPORT)
			if ((vap->iv_opmode == IEEE80211_M_STA) &&
					ieee80211_node_is_authorized(vap->iv_bss))
				ieee80211_send_analyzed_scan_result(vap);
			ieee80211_qrpe_phy_info_update_event_send(ss, vap);
#endif
			if (IS_IEEE80211_24G_40(ic) && (ic->ic_opmode == IEEE80211_M_STA))
				ieee80211_send_20_40_bss_coex(vap, 0);
		} else {
			ieee80211_scan_abort_notify(vap);
		}
		IEEE80211_ADDR_COPY(ss->ss_bssid, vap->iv_dev->broadcast);
		ic->ic_flags_ext &= ~IEEE80211_FEXT_BGSCAN;
	}

	if ((ic->ic_flags_qtn & IEEE80211_QTN_PRINT_CH_INUSE) &&
			(ic->ic_opmode == IEEE80211_M_HOSTAP)) {
		ap_list_asl_table(ss);
	}

	if (ss_priv->ss_iflags & ISCAN_CANCEL_END)
		ss->ss_ops->scan_end(ss, vap, NULL, 0);

	ss_priv->ss_iflags &= ~(ISCAN_CANCEL | ISCAN_CANCEL_END);
	ss->ss_flags &= ~(IEEE80211_SCAN_ONCE | IEEE80211_SCAN_PICK1ST);
	ss->ss_dwell_active_override = 0;
	ss->ss_dwell_passive_override = 0;
	ss->ss_sample_duration_override = 0;

	if (!ieee80211_chanset_scan_finished(ic))
		ieee80211_start_chanset_scan(vap, ic->ic_autochan_scan_flags);

	if (ieee80211_is_repeater_sta(vap)) {
		ap_vap = ieee80211_get_ap_vap(ic);
		if (ap_vap && ieee80211_is_dev_running(ap_vap->iv_dev) &&
				(ap_vap->iv_state == IEEE80211_S_SCAN) &&
				(ap_vap->iv_flags_ext & IEEE80211_FEXT_SCAN_PENDING)) {
			ap_vap->iv_flags_ext &= ~IEEE80211_FEXT_SCAN_PENDING;
			ieee80211_new_state(ap_vap, IEEE80211_S_SCAN, 0);
		}
	}
}

static int
ieee80211_scan_done(struct ieee80211_scan_state *ss)
{
	struct scan_state *ss_priv = SCAN_PRIVATE(ss);
	struct ieee80211vap *vap = ss->ss_vap;
	struct ieee80211com *ic = vap->iv_ic;
	unsigned long scanend = ss_priv->ss_scanend;

	ieee80211_scan_pre_done(ss);

	/*
	 * If not canceled and scan completed, do post-processing.
	 * If the callback function returns 0, then it wants to
	 * continue/restart scanning.  Unfortunately we needed to
	 * notify the driver to end the scan above to avoid having
	 * rx frames alter the scan candidate list.
	 */
	if ((SCAN_PRIVATE(ss)->ss_iflags & ISCAN_CANCEL) == 0 &&
			!ss->ss_ops->scan_end(ss, vap, NULL, 0) &&
			(ss->ss_flags & IEEE80211_SCAN_ONCE) == 0 &&
			time_before(jiffies + ss_priv->ss_mindwell_used, scanend)) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
				"%s: done, restart [jiffies %lu, dwell min %u scanend %lu]\n",
				__func__, jiffies,
				jiffies_to_msecs(ss_priv->ss_mindwell_used), scanend);
		ss->ss_next = 0;	/* reset to beginning */
		if (ss->ss_flags & IEEE80211_SCAN_ACTIVE)
			vap->iv_stats.is_scan_active++;
		else
			vap->iv_stats.is_scan_passive++;

		ic->ic_scan_start(ic, ss->scan_addr);

		return 0;
	}

	ieee80211_scan_post_done(ss);

	return 1;
}

/*
 * Switch to the next channel marked for scanning.
 */
static void
scan_next(unsigned long arg)
{
	struct ieee80211_scan_state *ss = (struct ieee80211_scan_state *) arg;
	struct ieee80211vap *vap = ss->ss_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_node *ni = vap->iv_bss;
	int scanning;
	int end;

	if ((ss->ss_flags & IEEE80211_SCAN_OBSS) &&
			(!ni || !IEEE80211_AID(ni->ni_associd)))
		return;

	IEEE80211_LOCK_IRQ(ic);
	scanning = ieee80211_is_scanning(ic);
	IEEE80211_UNLOCK_IRQ(ic);

	if(!scanning)			/* canceled */
		return;

	do {
		ieee80211_scan_adjust_txpower(ss);
		end = ieee80211_run_scan(ss);
	} while (end && !ieee80211_scan_done(ss));
}

#ifdef	IEEE80211_DEBUG
static void
dump_probe_beacon(u_int8_t subtype,
	const u_int8_t mac[IEEE80211_ADDR_LEN],
	const struct ieee80211_scanparams *sp)
{

	printf("[%s] %02x ", ether_sprintf(mac), subtype);
	if (sp) {
		printf("on chan %u (bss chan %u) ", sp->chan, sp->bchan);
		ieee80211_print_essid(sp->ssid + 2, sp->ssid[1]);
	}
	printf("\n");

	if (sp) {
		printf("[%s] caps 0x%x bintval %u erp 0x%x", 
			ether_sprintf(mac), sp->capinfo, sp->bintval, sp->erp);
		if (sp->country != NULL) {
#ifdef __FreeBSD__
			printf(" country info %*D",
				sp->country[1], sp->country + 2, " ");
#else
			int i;
			printf(" country info");
			for (i = 0; i < sp->country[1]; i++)
				printf(" %02x", sp->country[i + 2]);
#endif
		}
		printf("\n");
	}
}
#endif /* IEEE80211_DEBUG */

/*
 * Process a beacon or probe response frame.
 */
void
ieee80211_add_scan(struct ieee80211vap *vap,
	const struct ieee80211_scanparams *sp,
	const struct ieee80211_frame *wh,
	int subtype, int rssi, int rstamp)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_scan_state *ss = ic->ic_scan;

	/*
	 * Frames received during startup are discarded to avoid
	 * using scan state setup on the initial entry to the timer
	 * callback.  This can occur because the device may enable
	 * rx prior to our doing the initial channel change in the
	 * timer routine (we defer the channel change to the timer
	 * code to simplify locking on linux).
	 */

	if (SCAN_PRIVATE(ss)->ss_iflags & ISCAN_DISCARD)
		return;

#ifdef IEEE80211_DEBUG
	if (ieee80211_msg_scan(vap) && ieee80211_is_scanning(ic) && sp)
		dump_probe_beacon(subtype, wh->i_addr2, sp);
#endif

	if (ss->ss_ops != NULL &&
	    ss->ss_ops->scan_add(ss, sp, wh, subtype, rssi, rstamp)) {
		if (ic->ic_qtn_bgscan.debug_flags >= 4) {
			uint8_t *mac = (uint8_t *)wh->i_addr2;
			uint8_t ssid[IEEE80211_NWID_LEN + 1] = { 0 };

			if (sp->ssid[1] && sp->ssid[1] <= IEEE80211_NWID_LEN)
				memcpy(ssid, sp->ssid + 2, sp->ssid[1]);

			printk("==> Add scan entry -- chan: %u, mac: %pM, ssid: %s <==\n",
			       sp->chan, mac, (char *)ssid);
		}

		/*
		 * If we've reached the min dwell time terminate
		 * the timer so we'll switch to the next channel.
		 */
		if ((SCAN_PRIVATE(ss)->ss_iflags & ISCAN_MINDWELL) == 0 &&
				((ic->ic_flags_qtn & IEEE80211_QTN_BGSCAN) == 0) &&
				time_after_eq(jiffies, SCAN_PRIVATE(ss)->ss_chanmindwell)) {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
				"%s: chan %3d%c min dwell met (%lu > %lu)\n",
				__func__,
				ieee80211_chan2ieee(ic, ic->ic_curchan),
					channel_type(ic->ic_curchan),
				jiffies, SCAN_PRIVATE(ss)->ss_chanmindwell);
			/*
			 * XXX
			 * We want to just kick the timer and still
			 * process frames until it fires but linux
			 * will livelock unless we discard frames.
			 */
			SCAN_PRIVATE(ss)->ss_iflags |= ISCAN_DISCARD;
			/* NB: trigger at next clock tick */
			mod_timer(&SCAN_PRIVATE(ss)->ss_scan_timer, jiffies);
		}
	}

	if (ic->ic_opmode == IEEE80211_M_STA && (ic->ic_flags & IEEE80211_F_SCAN) &&
	    (ic->ic_flags_qtn & IEEE80211_QTN_BGSCAN) == 0 &&
	    subtype == IEEE80211_FC0_SUBTYPE_BEACON &&
	    (ic->ic_curchan->ic_flags & IEEE80211_CHAN_DFS) &&
	    (ic->ic_curchan->ic_flags & IEEE80211_CHAN_PASSIVE)) {
		/* Beacon received on a DFS channel, OK to send probe */
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
			"%s: sending a probe req on DFS channel %3d%c\n",
			__func__,
			ieee80211_chan2ieee(ic, ic->ic_curchan),
			channel_type(ic->ic_curchan));
		send_probes(ss);
	}
}
EXPORT_SYMBOL(ieee80211_add_scan);

/*
 * Remove a particular scan entry
 */
void
ieee80211_scan_remove(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_node *ni = vap->iv_bss;
	struct ieee80211_scan_state *ss = ic->ic_scan;

	if (ss->ss_ops != NULL && ss->ss_ops->scan_remove != NULL) {
		ss->ss_ops->scan_remove(ss, ni);
	}
}

/*
 * Timeout/age scan cache entries; called from sta timeout
 * timer (XXX should be self-contained).
 */
void
_ieee80211_scan_timeout(struct ieee80211com *ic)
{
	struct ieee80211_scan_state *ss = ic->ic_scan;

	if (ss->ss_ops != NULL)
		ss->ss_ops->scan_age(ss);
}

void ieee80211_scan_timeout(unsigned long arg)
{
	struct ieee80211com *ic = (struct ieee80211com *) arg;

	if (ic != NULL) {
		_ieee80211_scan_timeout(ic);
		ic->ic_scan_results_expire.expires = jiffies + ic->ic_scan_results_check * HZ;
		add_timer(&ic->ic_scan_results_expire);
	}
}

/*
 * Mark a scan cache entry after a successful associate.
 */
void
ieee80211_scan_assoc_success(struct ieee80211com *ic, const u_int8_t mac[])
{
	struct ieee80211_scan_state *ss = ic->ic_scan;

	if (ss->ss_ops != NULL) {
		IEEE80211_NOTE_MAC(ss->ss_vap, IEEE80211_MSG_SCAN,
			mac, "%s",  __func__);
		ss->ss_ops->scan_assoc_success(ss, mac);
	}
}

/*
 * Demerit a scan cache entry after failing to associate.
 */
void
ieee80211_scan_assoc_fail(struct ieee80211com *ic,
	const u_int8_t mac[], int reason)
{
	struct ieee80211_scan_state *ss = ic->ic_scan;

	if (ss->ss_ops != NULL) {
		IEEE80211_NOTE_MAC(ss->ss_vap, IEEE80211_MSG_SCAN, mac,
			"%s: reason %u", __func__, reason);
		ss->ss_ops->scan_assoc_fail(ss, mac, reason);
	}
}

/*
 * Iterate over the contents of the scan cache.
 */
int
ieee80211_scan_iterate(struct ieee80211com *ic,
	ieee80211_scan_iter_func *f, void *arg)
{
  int res = 0;
  struct ieee80211_scan_state *ss = ic->ic_scan;
	
  if (ss->ss_ops != NULL) {
    res = ss->ss_ops->scan_iterate(ss, f, arg);
  }
  return res;
}

static void
scan_saveie(u_int8_t **iep, const u_int8_t *ie)
{
	if (ie == NULL) {
		if (*iep) {
			FREE(*iep, M_DEVBUF);
		}
		*iep = NULL;
	} else {
		ieee80211_saveie(iep, ie);
	}
}

void
ieee80211_add_scan_entry(struct ieee80211_scan_entry *ise,
			const struct ieee80211_scanparams *sp,
			const struct ieee80211_frame *wh,
			int subtype, int rssi, int rstamp)
{
	if ((sp->ssid[1] != 0 && sp->ssid[2] != 0) &&
			(ISPROBE(subtype) || ise->se_ssid[1] == 0)) {
		memcpy(ise->se_ssid, sp->ssid, 2 + sp->ssid[1]);
	}

	memcpy(ise->se_rates, sp->rates,
			2 + IEEE80211_SANITISE_RATESIZE(sp->rates[1]));
	if (sp->xrates != NULL) {
		memcpy(ise->se_xrates, sp->xrates,
				2 + IEEE80211_SANITISE_RATESIZE(sp->xrates[1]));
	} else {
		ise->se_xrates[1] = 0;
	}
	IEEE80211_ADDR_COPY(ise->se_bssid, wh->i_addr3);

	ise->se_rstamp = rstamp;
	memcpy(ise->se_tstamp.data, sp->tstamp, sizeof(ise->se_tstamp));
	ise->se_intval = sp->bintval;
	ise->se_capinfo = sp->capinfo;
	ise->se_chan = sp->rxchan;
	ise->se_fhdwell = sp->fhdwell;
	ise->se_fhindex = sp->fhindex;
	ise->se_erp = sp->erp;
	ise->se_timoff = sp->timoff;
	if (sp->tim != NULL) {
		const struct ieee80211_tim_ie_full *tim =
		    (const struct ieee80211_tim_ie_full *) sp->tim;
		ise->se_dtimperiod = tim->tim_period;
	}
	scan_saveie(&ise->se_wme_ie, sp->wme);
	scan_saveie(&ise->se_wpa_ie, sp->wpa);
	scan_saveie(&ise->se_rsn_ie, sp->rsn);
	scan_saveie(&ise->se_wsc_ie, sp->wsc);
	scan_saveie(&ise->se_ath_ie, sp->ath);
	scan_saveie(&ise->se_qtn_ie, sp->qtn);
	scan_saveie(&ise->se_country_ie, sp->country);
	if (sp->qtn != NULL) {
		ise->se_qtn_ie_flags = ((struct ieee80211_ie_qtn *)sp->qtn)->qtn_ie_flags;
		ise->se_is_qtn_dev = 1;
	} else {
		ise->se_qtn_ie_flags = 0;
		ise->se_is_qtn_dev = 0;
	}
	scan_saveie(&ise->se_htcap_ie, sp->htcap);
	scan_saveie(&ise->se_htinfo_ie, sp->htinfo);
	scan_saveie(&ise->se_vhtcap_ie, sp->vhtcap);
	scan_saveie(&ise->se_vhtop_ie, sp->vhtop);
	scan_saveie(&ise->se_pairing_ie, sp->pairing_ie);
	scan_saveie(&ise->se_bss_load_ie, sp->bssload);

	ise->se_ext_role = sp->extender_role;
	scan_saveie(&ise->se_ext_bssid_ie, sp->ext_bssid_ie);
	ise->local_max_txpwr = sp->local_max_txpwr;
	scan_saveie(&ise->se_md_ie, sp->mdie);
	scan_saveie(&ise->se_repeater_ie, sp->repeater);
	scan_saveie(&ise->se_owe_trans_ie, sp->owe_trans_mode);
	scan_saveie(&ise->se_obss_scan, sp->obss_scan);
	scan_saveie(&ise->se_rp_info_ie, sp->rp_info);
	ise->se_jiffies = jiffies;
	ise->se_last_rssi = rssi;
}
EXPORT_SYMBOL(ieee80211_add_scan_entry);

static void
ieee80211_scan_set_channel_obssflag(struct ieee80211_scan_state *ss, uint8_t ch, int flag)
{
	struct ieee80211com *ic = ss->ss_vap->iv_ic;
	struct ap_state *as = ss->ss_priv;
	struct ieee80211_channel *chan;

	chan = ieee80211_find_channel_by_ieee(ic, ch);
	if (chan == NULL)
		return;

	as->as_obss_chanlayout[ch] |= flag;
}

void
ieee80211_scan_mark_channel_obssflag(struct ieee80211com *ic,
			struct ieee80211_channel *chan_pri,
			int bss_bw)
{
	struct ieee80211_scan_state *ss = ic->ic_scan;
	uint8_t ch_pri;
	uint8_t ch_sec;

	if (!is_ieee80211_chan_valid(chan_pri))
		return;

	ch_pri = chan_pri->ic_ieee;
	ieee80211_scan_set_channel_obssflag(ss, ch_pri, IEEE80211_OBSS_CHAN_PRI20);

	if (bss_bw != BW_HT80 && bss_bw != BW_HT40 && bss_bw != BW_HT20)
		return;

	if (bss_bw == BW_HT20)
		return;

	ch_sec = ieee80211_find_sec_chan(chan_pri);
	if (ch_sec == 0)
		return;

	ieee80211_scan_set_channel_obssflag(ss, ch_sec, IEEE80211_OBSS_CHAN_SEC20);

	if (bss_bw == BW_HT40)
		return;

	ieee80211_scan_set_channel_obssflag(ss, ch_pri, IEEE80211_OBSS_CHAN_PRI40);
	ieee80211_scan_set_channel_obssflag(ss, ch_sec, IEEE80211_OBSS_CHAN_PRI40);

	ch_sec = ieee80211_find_sec40u_chan(chan_pri);
	if (ch_sec != 0)
		ieee80211_scan_set_channel_obssflag(ss, ch_sec, IEEE80211_OBSS_CHAN_SEC40);

	ch_sec = ieee80211_find_sec40l_chan(chan_pri);
	if (ch_sec != 0)
		ieee80211_scan_set_channel_obssflag(ss, ch_sec, IEEE80211_OBSS_CHAN_SEC40);
}
EXPORT_SYMBOL(ieee80211_scan_mark_channel_obssflag);

int
ieee80211_scan_check_secondary_channel(struct ieee80211_scan_state *ss,
			struct ieee80211_scan_entry *ise)
{
	int bss_bw = ieee80211_get_max_ap_bw(ise);
	struct ieee80211vap *vap = ss->ss_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_channel *chan;
	uint8_t chan_pri;
	uint8_t chan_sec;

	ieee80211_find_ht_pri_sec_chan(vap, ise, &chan_pri, &chan_sec);
	if (chan_pri == 0)
		return 0;

	chan = ieee80211_find_channel_by_ieee(ic, chan_pri);

	ieee80211_scan_mark_channel_obssflag(ic, chan, bss_bw);

	return 0;
}
EXPORT_SYMBOL(ieee80211_scan_check_secondary_channel);

static int
ieee80211_prichan_check_newchan(struct ieee80211_scan_state *ss,
			struct ieee80211_channel *chan,
			int32_t *max_bsscnt)
{
	struct ap_state *as = ss->ss_priv;
	struct ieee80211vap *vap = ss->ss_vap;
	struct ieee80211com *ic = vap->iv_ic;
	uint32_t ch;
	int32_t cur_bss;

	if (!chan)
		return -1;

	ch = ieee80211_chan2ieee(ic, chan);
	if (!is_channel_valid(ch))
		return -1;

	if (isset(ic->ic_chan_pri_inactive, ch) || isclr(ic->ic_chan_active, ch))
		return -1;

	SCSDBG(SCSLOG_VERBOSE, "Checking OBSS violations on channel %d (%08x)\n", ch,
				as->as_obss_chanlayout[ch]);

	cur_bss = (int32_t)as->as_numbeacons[ch];
	if (!IEEE80211_IS_OBSS_CHAN_SECONDARY(as->as_obss_chanlayout[ch])) {
		if (cur_bss > *max_bsscnt) {
			*max_bsscnt = cur_bss;
			return 1;
		}
		return 0;
	}

	return -1;
}

/*
 * Channel selection methods for a VHT BSS,
 * as per IEEE Std 802.11ac 10.39.2, IEEE Std 802.11ac 10.5.3.
 * New BSS's primary channel shall not overlap other BSSs' secondary channels.
 */
struct ieee80211_channel *
ieee80211_scan_switch_pri_chan(struct ieee80211_scan_state *ss,
			struct ieee80211_channel *chan_pri)
{
	struct ieee80211vap *vap = NULL;
	struct ieee80211com *ic = NULL;
	int cur_bw = BW_INVALID;
	struct ieee80211_channel *chan_sec;
	uint32_t ch_pri = 0;
	uint32_t ch_sec;
	int32_t bsscnt = -1;

	if (!chan_pri || !ss || !ss->ss_vap || !ss->ss_vap->iv_ic) {
		return NULL;
	}

	vap = ss->ss_vap;
	ic = vap->iv_ic;
	cur_bw = ieee80211_get_bw(ic);

	if (cur_bw >= BW_HT20) {
		ch_pri = chan_pri->ic_ieee;
		if (ieee80211_prichan_check_newchan(ss, chan_pri, &bsscnt) < 0)
			ch_pri = 0;
	}

	if (cur_bw >= BW_HT40) {
		/* we look up operating class to follow different primary channel layouts, esp. 2.4G */
		ch_sec = ieee80211_find_sec_chan_by_operating_class(ic,
					chan_pri->ic_ieee,
					IEEE80211_OC_BEHAV_CHAN_UPPER);
		chan_sec = ieee80211_find_channel_by_ieee(ic, ch_sec);
		if (ieee80211_prichan_check_newchan(ss, chan_sec, &bsscnt) > 0)
			ch_pri = ch_sec;

		ch_sec = ieee80211_find_sec_chan_by_operating_class(ic,
					chan_pri->ic_ieee,
					IEEE80211_OC_BEHAV_CHAN_LOWWER);
		chan_sec = ieee80211_find_channel_by_ieee(ic, ch_sec);
		if (ieee80211_prichan_check_newchan(ss, chan_sec, &bsscnt) > 0)
			ch_pri = ch_sec;
	}

	if (cur_bw >= BW_HT80) {
		ch_sec = ieee80211_find_sec40u_chan(chan_pri);
		chan_sec = ieee80211_find_channel_by_ieee(ic, ch_sec);
		if (ieee80211_prichan_check_newchan(ss, chan_sec, &bsscnt) > 0)
			ch_pri = ch_sec;

		ch_sec = ieee80211_find_sec40l_chan(chan_pri);
		chan_sec = ieee80211_find_channel_by_ieee(ic, ch_sec);
		if (ieee80211_prichan_check_newchan(ss, chan_sec, &bsscnt) > 0)
			ch_pri = ch_sec;
	}

	SCSDBG(SCSLOG_VERBOSE, "Switch primary channel from %d to %d by OBSS validation\n",
				chan_pri->ic_ieee,
				ch_pri);
	return ieee80211_find_channel_by_ieee(ic, ch_pri);
}
EXPORT_SYMBOL(ieee80211_scan_switch_pri_chan);

struct ieee80211_channel *
ieee80211_scs_switch_pri_chan(struct ieee80211_scan_state *ss,
			struct ieee80211_channel *chan_pri)
{
	struct ieee80211_channel *chan;
	struct ap_state *as;
	struct ap_state *as_bak;

	as = (struct ap_state *)ss->ss_scs_priv;
	as_bak = ss->ss_priv;
	ss->ss_priv = as;

	chan = ieee80211_scan_switch_pri_chan(ss, chan_pri);

	ss->ss_priv = as_bak;

	return chan;
}
EXPORT_SYMBOL(ieee80211_scs_switch_pri_chan);

int
ieee80211_wps_active(uint8_t *wsc_ie)
{
#define IEEE80211_WPS_SELECTED_REGISTRAR 0x1041
	uint16_t type;
	uint16_t len;
	uint8_t *pos;
	uint8_t *end;

	if (!wsc_ie)
		return 0;

	pos = wsc_ie;
	end = wsc_ie + wsc_ie[1];

	pos += (2 + 4);
	while (pos < end) {
		if (end - pos < 4)
			break;

		type = ntohs(get_unaligned((__be16 *)pos));
		pos += 2;
		len = ntohs(get_unaligned((__be16 *)pos));
		pos += 2;

		if (len > end - pos)
			break;

		if ((type == IEEE80211_WPS_SELECTED_REGISTRAR) && (len == 1))
			return 1;

		pos += len;
	}

	return 0;
}
EXPORT_SYMBOL(ieee80211_wps_active);

void
ieee80211_dump_scan_res(struct ieee80211_scan_state *ss)
{
#define IEEE80211_BSS_CAPA_STR_LEN 30
	struct ieee80211vap *vap;
	struct sta_table *st;
	struct sta_entry *se, *next;
	struct ieee80211_scan_entry *ise;
	char ssid[IEEE80211_NWID_LEN + 1];
	char bss_capa[IEEE80211_BSS_CAPA_STR_LEN];
	char *pos;
	char *end;
	int len;

	if (!ss)
		return;

	vap = ss->ss_vap;
	st = ss->ss_priv;
	if (!vap || !st)
		return;

	if (!ieee80211_msg(vap, IEEE80211_MSG_SCAN))
		return;

	printk("%-18s  %-33s  %-7s  %-25s  %-5s\n",
		"BSSID", "SSID", "Channel", "BSS Capabilities", "RSSI");

	TAILQ_FOREACH_SAFE(se, &st->st_entry, se_list, next) {
		ise = &se->base;
		memset(ssid, 0, sizeof(ssid));
		memcpy(ssid, &ise->se_ssid[2], MIN(sizeof(ssid), ise->se_ssid[1]));

		len = 0;
		pos = bss_capa;
		end = bss_capa + IEEE80211_BSS_CAPA_STR_LEN;
		memset(bss_capa, 0, sizeof(bss_capa));

		if (ise->se_capinfo & IEEE80211_CAPINFO_IBSS) {
			len = snprintf(pos, end - pos, "IBSS");
			pos += len;
		} else if (ise->se_capinfo & IEEE80211_CAPINFO_ESS) {
			len = snprintf(pos, end - pos, "ESS");
			pos += len;
		}

		if (ise->se_wpa_ie) {
			len = snprintf(pos, end - pos, "|WPA");
			pos += len;
		}
		if (ise->se_rsn_ie) {
			len = snprintf(pos, end - pos, "|RSN");
			pos += len;
		}

		if (ieee80211_wps_active(ise->se_wsc_ie))
		      snprintf(pos, end - pos, "|WPS_ACTIVE");
		else if (ise->se_wsc_ie)
		      snprintf(pos, end - pos, "|WPS");

		printk("%-18pM  %-33s  %-7u  %-25s  %-5d\n",
			ise->se_bssid,
			ssid,
			ise->se_chan->ic_ieee,
			bss_capa,
			ise->se_rssi);
	}
}
EXPORT_SYMBOL(ieee80211_dump_scan_res);

/*
 * Flush the contents of the scan cache.
 */
void
ieee80211_scan_flush(struct ieee80211com *ic)
{
	struct ieee80211_scan_state *ss = ic->ic_scan;

	if (ss->ss_ops != NULL) {
		IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
			"%s\n",  __func__);
		ss->ss_ops->scan_flush(ss);
	}
}
EXPORT_SYMBOL(ieee80211_scan_flush);

/*
 * Refresh scan module channel list
 * In cases where ieee80211_scan_pickchannel is called
 * without initiating proper scan from ap scan module,
 * the channel list can be out of sync between QDRV and scan_ap modules
 */
void ieee80211_scan_refresh_scan_module_chan_list(struct ieee80211com *ic, struct ieee80211vap *vap)
{
	struct ieee80211_scan_state *ss = ic->ic_scan;

	IEEE80211_LOCK_ASSERT(ic);

	if (ss == NULL || ss->ss_ops == NULL || ss->ss_vap == NULL) {
		printk(KERN_WARNING "scan state structure not attached or not initialized\n");
		return;
	}
	if (ss->ss_ops->scan_start == NULL) {
		IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
		    "%s: scan module does not scan start, "
		    "opmode %s\n", __func__, ss->ss_vap->iv_opmode);
		return;
	}

	ss->ss_ops->scan_start(ss, vap);
}
EXPORT_SYMBOL(ieee80211_scan_refresh_scan_module_chan_list);

/*
 * Check the scan cache for an ap/channel to use
 */
struct ieee80211_channel *
ieee80211_scan_pickchannel(struct ieee80211com *ic, int flags)
{
	struct ieee80211_scan_state *ss = ic->ic_scan;

	IEEE80211_LOCK_ASSERT(ic);

	if (ss == NULL || ss->ss_ops == NULL || ss->ss_vap == NULL) {
		printk(KERN_WARNING "scan state structure not attached or not initialized\n");
		return NULL;
	}
	if (ss->ss_ops->scan_pickchan == NULL) {
		IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
		    "%s: scan module does not support picking a channel, "
		    "opmode %s\n", __func__, ss->ss_vap->iv_opmode);
		return NULL;
	}

	return ss->ss_ops->scan_pickchan(ic, ss, flags);
}
EXPORT_SYMBOL(ieee80211_scan_pickchannel);

/*
 * Currently STA is only allowed to receive the beacon from associated AP
 * in association state. This function is used to enable/disable STA to receive
 * the beacons from other APs in association state.
 */
void ieee80211_sta_allow_beacon_reception(struct ieee80211vap *vap,
	int allow)
{
	struct ieee80211com *ic = vap->iv_ic;

	if ((vap->iv_opmode != IEEE80211_M_STA) ||
			(vap->iv_state != IEEE80211_S_RUN) ||
			ieee80211_is_scanning(ic))
		return;

	ic->ic_setparam(vap->iv_bss, IEEE80211_PARAM_BEACON_ALLOW, !!allow, NULL, 0);
}
EXPORT_SYMBOL(ieee80211_sta_allow_beacon_reception);

int ieee80211_get_type_of_neighborhood(struct ieee80211com *ic)
{
	if (ic->ic_neighbor_count < 0)
		return IEEE80211_NEIGHBORHOOD_TYPE_UNKNOWN;
	else if (ic->ic_neighbor_count <= ic->ic_neighbor_cnt_sparse)
		return IEEE80211_NEIGHBORHOOD_TYPE_SPARSE;
	else if (ic->ic_neighbor_count <= ic->ic_neighbor_cnt_dense)
		return IEEE80211_NEIGHBORHOOD_TYPE_DENSE;
	else
		return IEEE80211_NEIGHBORHOOD_TYPE_VERY_DENSE;
}

char * ieee80211_neighborhood_type2str(int type)
{
	char *str = "Unknown";

	switch (type) {
	case IEEE80211_NEIGHBORHOOD_TYPE_SPARSE:
		str = "Sparse";
		break;
	case IEEE80211_NEIGHBORHOOD_TYPE_DENSE:
		str = "Dense";
		break;
	case IEEE80211_NEIGHBORHOOD_TYPE_VERY_DENSE:
		str = "Very dense";
		break;
	default:
		break;
	}

	return str;
}

void ieee80211_check_type_of_neighborhood(struct ieee80211com *ic)
{
	struct ieee80211_scan_state *ss = ic->ic_scan;
	struct ap_state *as = ss->ss_priv;
	struct ap_scan_entry *apse;
	struct sta_table *st = ss->ss_priv;
	struct sta_entry *se;
	int i;

	ic->ic_neighbor_count = 0;

	if (ss->ss_vap->iv_opmode == IEEE80211_M_HOSTAP) {
		for (i = 0; i < IEEE80211_CHAN_MAX; i++) {
			TAILQ_FOREACH(apse, &as->as_scan_list[i].asl_head, ase_list) {
				ic->ic_neighbor_count++;
			}
		}
	} else if (ss->ss_vap->iv_opmode == IEEE80211_M_STA) {
		TAILQ_FOREACH(se, &st->st_entry, se_list) {
			ic->ic_neighbor_count++;
		}
	}
	IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
			"%s: found %d neighborhood APs\n", __func__, ic->ic_neighbor_count);
}

