/*-
 * Copyright (c) 2018 Quantenna Communications Inc
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
 */

/*
 * IEEE 802.11 WNM handling.
 */
#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/version.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

#include "net80211/ieee80211.h"
#include "net80211/ieee80211_var.h"

/*  1 IEEEE TU = 1.024usec; 1 WNM TU = 1000 IEEE TU */

uint32_t ieee80211_wnm_convert_tu_to_msec(uint16_t wnm_tu)
{
	uint32_t local_msec;

	local_msec = wnm_tu * 1024;

	return local_msec;
}

uint16_t ieee80211_wnm_convert_msec_to_tu(uint32_t local_msec)
{
	uint16_t local_tu;

	local_tu = local_msec / 1024;

	if (local_tu == 0)
		local_tu = 1;

	return local_tu;
}

uint8_t *ieee80211_wnm_add_max_bss_idle_ie(u_int8_t *frm, uint32_t idle_time)
{
	uint16_t wnm_tu;
	struct ieee80211_max_idle_ie *ie = (struct ieee80211_max_idle_ie *)frm;

	ie->param_id = IEEE80211_ELEMID_BSS_MAX_IDLE_PERIOD;
	ie->param_len = sizeof(struct ieee80211_max_idle_ie) - 2;

	wnm_tu = ieee80211_wnm_convert_msec_to_tu(idle_time);

	ie->max_idle_period = htole16(wnm_tu);
	ie->idle_options = IEEE80211_WNM_IDLE_OPT_UNPROT;

	return (frm + sizeof(struct ieee80211_max_idle_ie));
}

void ieee80211_wnm_node_configure(struct ieee80211vap *vap, struct ieee80211_node *ni)
{
	uint32_t max_idle_period_ms;

	if (!ni)
		return;

	if (ni->ni_associd == 0) {
		IEEE80211_NOTE(ni->ni_vap, IEEE80211_MSG_INACT | IEEE80211_MSG_NODE, ni,
				"skip wnm max bss idle configuration for %pM\n", ni->ni_macaddr);
		return;
	}

	if (vap->iv_opmode == IEEE80211_M_HOSTAP)
		max_idle_period_ms = vap->max_idle_period_ms;
	else
		max_idle_period_ms = ni->ni_max_idle_period_ms;

	IEEE80211_NOTE(ni->ni_vap, IEEE80211_MSG_INACT | IEEE80211_MSG_NODE, ni,
		"wnm enabled configure timeout %u msec, peer sta %pM",
		max_idle_period_ms, ni->ni_macaddr);

	ni->ni_inact_reload = IEEE80211_INACT_WNM_MAX_BSS_IDLE;
	ni->ni_inact = ni->ni_inact_reload;
}

static void ieee80211_node_wnm_sta_check_peer_ap_active(struct ieee80211_node *ni)
{
	if (ni->ni_shared_stats->tx[STATS_SU].data_acks != ni->tx_acks) {
		ni->ni_inact = ni->ni_inact_reload;
		ni->last_active_jiffies_ts = jiffies;
	}

	ni->tx_acks = ni->ni_shared_stats->tx[STATS_SU].data_acks;

	return;
}

void ieee80211_wnm_handle_max_bss_idle_peer_ap(struct ieee80211_node *ni)
{
	unsigned long wnm_timeout_ts;

	ieee80211_node_wnm_sta_check_peer_ap_active(ni);

	wnm_timeout_ts = ni->last_active_jiffies_ts + msecs_to_jiffies(ni->ni_max_idle_period_ms)
				- msecs_to_jiffies(IEEE80211_WNM_TO_TOLERANCE * 1000);

	if (time_before(jiffies, wnm_timeout_ts)) {
		ieee80211_free_node(ni);
		return;
	}

	IEEE80211_NOTE(ni->ni_vap,IEEE80211_MSG_INACT | IEEE80211_MSG_NODE, ni,
			"%s", "vap=sta, wnm_powersave: send qos-null");

	/* Either of these frees the node reference */
	if (ni->ni_flags & IEEE80211_NODE_QOS) {
		/* non-QoS frames to 3rd party QoS node (Intel) can cause a BA teardown */
		ieee80211_send_qosnulldata(ni, WMM_AC_BK);
	} else {
		ieee80211_send_nulldata(ni);
	}
}

static void ieee80211_node_wnm_ap_check_peer_sta_active(struct ieee80211_node *ni)
{
	int su = STATS_SU;

	if ((ni->ni_shared_stats->rx[su].pkts_cum != ni->rx_pkts) ||
			(ni->ni_shared_stats->tx[su].acks != ni->tx_acks)) {
		ni->last_active_jiffies_ts = jiffies;
	}

	/* always reset the local counters in case the shared counters wrap */
	ni->rx_pkts = ni->ni_shared_stats->rx[su].pkts_cum;
	ni->tx_acks = ni->ni_shared_stats->tx[su].acks;
}

void ieee80211_wnm_handle_max_bss_idle_peer_sta(struct ieee80211_node *ni)
{
	struct ieee80211vap *vap = ni->ni_vap;
	unsigned long wnm_timeout_ts;

	ieee80211_node_wnm_ap_check_peer_sta_active(ni);

	/* Additional 5s delay while checking STA inactivity. It is seen that QoS NULL is sent by
	 * STA but before it could be processed by AP; WLAN driver generated disassoc.
	 */
	wnm_timeout_ts = ni->last_active_jiffies_ts + msecs_to_jiffies(vap->max_idle_period_ms) +
			msecs_to_jiffies(IEEE80211_WNM_TO_TOLERANCE * 1000);

	if (time_after(jiffies, wnm_timeout_ts)) {
		IEEE80211_NOTE(ni->ni_vap, IEEE80211_MSG_INACT | IEEE80211_MSG_NODE, ni,
				"%s", "tx_ack/rx_data count did not increase; node inactive");
		if (ni->ni_inact > 0)
			ni->ni_inact--;
	}
}

