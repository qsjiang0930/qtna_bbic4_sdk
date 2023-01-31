/*-
 * Copyright (c) 2017 - Quantenna Communications, Inc.
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
#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

#include "net80211/ieee80211_var.h"
#include "net80211/ieee80211_node.h"
#include "net80211/ieee80211_repeater.h"

static void ieee80211_repeater_disassoc(void *arg, struct ieee80211_node *ni)
{
	struct ieee80211vap *stavap = (struct ieee80211vap *)arg;

	if (ni->ni_associd != 0
			&& (ni->ni_qtn_flags & QTN_IS_QTN_REPEATER)
			&& ni != stavap->iv_bss) {
		IEEE80211_SEND_MGMT(ni, IEEE80211_FC0_SUBTYPE_DEAUTH, IEEE80211_REASON_ASSOC_TOOMANY);
		ieee80211_node_leave(ni);
	}
}

void ieee80211_repeater_level_update(struct ieee80211com *ic,
        uint8_t new_curr_level, uint8_t new_max_level)
{
	struct ieee80211vap *stavap;

	KASSERT(ieee80211_is_repeater(ic), ("Must be a repeater"));

	if (ic->rep_curr_level == new_curr_level &&
			ic->rep_max_level == new_max_level)
		return;

	ic->rep_curr_level = new_curr_level;
	ic->rep_max_level = new_max_level;

	ieee80211_beacon_update_all(ic);

	if (ic->rep_curr_level < ic->rep_max_level)
		return;

	stavap = ieee80211_get_sta_vap(ic);
	KASSERT(stavap != NULL, ("STA on a Repeater must be present"));

	ieee80211_iterate_nodes(&ic->ic_sta, ieee80211_repeater_disassoc, stavap, 1);
}

void ieee80211_repeater_process_cascade_ie(struct ieee80211com *ic,
	struct ieee80211_node *ni, const void *ie)
{
	struct ieee80211vap *stavap;
	const struct ieee80211_ie_qtn_repeater *rep_cascade = ie;
	struct ieee80211_node *rep_node = NULL;

	KASSERT(ni != NULL, ("null node"));

	/* store associated repeater node cascade IE */
	if (rep_cascade) {
		rep_node = ieee80211_find_node(&ic->ic_sta, rep_cascade->stamac);
		if (rep_node && (!rep_node->ni_rep_cascade_ie ||
				memcmp(&rep_node->ni_rep_cascade_ie,
					rep_cascade, sizeof(*rep_cascade)))) {
			ieee80211_saveie(&rep_node->ni_rep_cascade_ie,
					(const uint8_t *)rep_cascade);
		}
	}

	/* Repeater update own cascade level base on received cascade IE */
	if (!ieee80211_is_repeater(ic))
		goto out;

	stavap = ieee80211_get_sta_vap(ic);
	KASSERT(stavap != NULL, ("STA on a Repeater must be present"));

	if (ni == stavap->iv_bss) {
		/*
		 * Update repeater current and max level, in case
		 * 1. Upstream repeater changes its own level
		 * 2. Upstream repeater becomes an AP
		 */
		if (rep_cascade) {
			ieee80211_repeater_level_update(ic,
				rep_cascade->level + 1, rep_cascade->max_level);
		} else {
			ieee80211_repeater_level_update(ic,
				IEEE80211_REPEATER_FIRST_LEVEL, ic->rep_max_level_cfg);
		}
	} else if (rep_node && rep_node->ni_vap &&
				(rep_node->ni_vap->iv_opmode == IEEE80211_M_HOSTAP)) {
		if (ic->rep_curr_level < ic->rep_max_level)
			goto out;

		IEEE80211_SEND_MGMT(rep_node, IEEE80211_FC0_SUBTYPE_DEAUTH,
				IEEE80211_REASON_ASSOC_TOOMANY);
		ieee80211_node_leave(rep_node);
	}

out:
	if (rep_node)
		ieee80211_free_node(rep_node);
}

int ieee80211_repeater_sta_pre_join(struct ieee80211com *ic,
		struct ieee80211vap *vap, const struct ieee80211_scan_entry *se)
{
	const struct ieee80211_ie_qtn_repeater *rep_cascade =
		(struct ieee80211_ie_qtn_repeater*)se->se_repeater_ie;

	if (!ieee80211_is_repeater(ic))
		return 0;

	if (ieee80211_csa_target_sanity_check(ic, vap, se->se_chan)) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
				"Repeater BSS channel %d invalid\n", se->se_chan->ic_ieee);
		return -EPERM;
	}

	if (!rep_cascade)
		return 0;

	if (rep_cascade->level + 1 > rep_cascade->max_level)
		return -EPERM;

	return 0;
}

void ieee80211_repeater_sta_post_join(struct ieee80211com *ic, const void *ie)
{
	const struct ieee80211_ie_qtn_repeater *rep_cascade = ie;

	if (ieee80211_is_repeater(ic)) {
		if (rep_cascade) {
			ieee80211_repeater_level_update(ic,
				rep_cascade->level + 1, rep_cascade->max_level);
		} else {
			ieee80211_repeater_level_update(ic,
				IEEE80211_REPEATER_FIRST_LEVEL, ic->rep_max_level_cfg);
		}
	} else {
		ic->rep_curr_level = IEEE80211_REPEATER_FIRST_LEVEL;
		ic->rep_max_level= ic->rep_max_level_cfg;
	}
}

void ieee80211_repeater_sta_leave(struct ieee80211com *ic)
{
	if (!ieee80211_is_repeater(ic))
		return;

	ieee80211_repeater_level_update(ic, IEEE80211_REPEATER_FIRST_LEVEL, ic->rep_max_level_cfg);
}

/*
 * Level N Repeater calculates its own throughput based on
 * 1) parsed rate from upper(N-1) level Repeater RP_INFO IE
 * 2) rx PHY rate with upper(N-1) level Repeater
 */
static void ieee80211_repeater_calc_tp(struct ieee80211_node *ni,
		const struct ieee80211_ie_qtn_rp_info *rp_info)
{
	struct ieee80211com *ic = ni->ni_ic;
	struct ieee80211vap *vap = ni->ni_vap;
	uint32_t ie_phyrate;
	uint32_t my_phyrate;

	ic->ic_rxtx_phy_rate(ni, 1, NULL, NULL, NULL, NULL, NULL, &my_phyrate);
	/* no data frames received from upper level */
	if (my_phyrate == 0)
		return;

	if (ic->rep_curr_level == IEEE80211_REPEATER_FIRST_LEVEL) {
		ic->ic_rp_info.throughput = my_phyrate;
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_EXTDR, "%s: level %u throughput %u\n",
			__func__, ic->rep_curr_level, my_phyrate);
		return;
	}

	/* upper level didn't announce TP */
	if ((rp_info->flags & QTN_RP_FLAG_THROUGHPUT) == 0)
		return;
	ie_phyrate = ntohl(rp_info->throughput);

	if (ic->ic_rp_info.type == QTN_RP_TYPE_FD)
		ic->ic_rp_info.throughput = MIN(ie_phyrate, my_phyrate);
	else
		ic->ic_rp_info.throughput = (ie_phyrate * my_phyrate) / (ie_phyrate + my_phyrate);

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_EXTDR, "%s: level %u throughput %u (ie=%u my=%u)\n",
		__func__, ic->rep_curr_level, ic->ic_rp_info.throughput, ie_phyrate, my_phyrate);
}

void ieee80211_repeater_process_rp_info_ie(struct ieee80211com *ic,
	struct ieee80211_node *ni, const void *ie)
{
	const struct ieee80211_ie_qtn_rp_info *rp_info = ie;

	if (!ieee80211_is_repeater(ic))
		return;
	if (ni->ni_associd == 0)
		return;
	if (!rp_info)
		return;

	ieee80211_repeater_calc_tp(ni, rp_info);
}
