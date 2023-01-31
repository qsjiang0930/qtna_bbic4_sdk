/**
  Copyright (c) 2018 Quantenna Communications Inc
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

/*
 * Management Frame Registration
 */

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

#include "net80211/if_media.h"

#include "net80211/ieee80211_var.h"
#include "net80211/ieee80211_linux.h"

#if defined(CONFIG_QTN_BSA_SUPPORT)
#include "net80211/ieee80211_qrpe.h"
#include "net80211/ieee80211_bsa.h"
#endif
#include <qtn/shared_params.h>

/*
 * Tx action frames that can be forwarded to a registered application.
 */
uint8_t ieee80211_mfr_allow_tx_action_cat[] = {
	IEEE80211_ACTION_CAT_PUBLIC,
	IEEE80211_ACTION_CAT_RM,
	IEEE80211_ACTION_CAT_WNM,
};
const uint32_t ieee80211_mfr_allow_tx_action_cat_size = sizeof(ieee80211_mfr_allow_tx_action_cat);

/*
 * Rx action frames that can be forwarded to a registered application.
 */
uint8_t ieee80211_mfr_allow_rx_action_cat[] = {
	IEEE80211_ACTION_CAT_PUBLIC,
	IEEE80211_ACTION_CAT_RM,
	IEEE80211_ACTION_CAT_WNM,
};
const uint32_t ieee80211_mfr_allow_rx_action_cat_size = sizeof(ieee80211_mfr_allow_rx_action_cat);

/*
 * Rx management frames that can be forwarded to a registered application.
 */
uint8_t ieee80211_mfr_allow_rx_mgmt_subtype[] = {
	IEEE80211_FC0_SUBTYPE_ASSOC_REQ,
	IEEE80211_FC0_SUBTYPE_REASSOC_REQ,
	IEEE80211_FC0_SUBTYPE_DISASSOC,
	IEEE80211_FC0_SUBTYPE_AUTH,
	IEEE80211_FC0_SUBTYPE_DEAUTH,
	IEEE80211_FC0_SUBTYPE_PROBE_REQ,
	IEEE80211_FC0_SUBTYPE_BEACON,
	IEEE80211_FC0_SUBTYPE_ASSOC_RESP,
	IEEE80211_FC0_SUBTYPE_REASSOC_RESP,
	IEEE80211_FC0_SUBTYPE_PROBE_RESP,
	IEEE80211_FC0_SUBTYPE_ACTION,
};
const uint32_t ieee80211_mfr_allow_rx_mgmt_subtype_size = sizeof(ieee80211_mfr_allow_rx_mgmt_subtype);

/*
 * Tx management frames that can be forwarded to a registered application.
 */
uint8_t ieee80211_mfr_allow_tx_mgmt_subtype[] = {
	IEEE80211_FC0_SUBTYPE_ACTION,
};
const uint32_t ieee80211_mfr_allow_tx_mgmt_subtype_size = sizeof(ieee80211_mfr_allow_tx_mgmt_subtype);

static int
ieee80211_mfr_attach(struct ieee80211vap *vap)
{
	struct ieee80211_mfr_list *reg_list;

	COMPILE_TIME_ASSERT(ieee80211_mfr_allow_tx_action_cat_size <= IEEE80211_QRPE_MAX_CONFIG_ACT_NUM);
	COMPILE_TIME_ASSERT(ieee80211_mfr_allow_rx_action_cat_size <= IEEE80211_QRPE_MAX_CONFIG_ACT_NUM);
	COMPILE_TIME_ASSERT(ieee80211_mfr_allow_tx_mgmt_subtype_size <= IEEE80211_QRPE_MAX_CONFIG_FRM_NUM);
	COMPILE_TIME_ASSERT(ieee80211_mfr_allow_rx_mgmt_subtype_size <= IEEE80211_QRPE_MAX_CONFIG_FRM_NUM);

	MALLOC(reg_list, struct ieee80211_mfr_list *,
			sizeof(struct ieee80211_mfr_list),
			M_DEVBUF, M_NOWAIT | M_ZERO);
	if (reg_list == NULL) {
		IEEE80211_DPRINTF_EXT(vap, IEEE80211_MSG_MFR,
				"%s: attach frames err\n",
				__FUNCTION__);
		return -ENOMEM;
	}
	spin_lock_init(&reg_list->reg_list_lock);
	TAILQ_INIT(&reg_list->reg_list);
	vap->iv_mfr_list = reg_list;

	return 0;
}

static void
ieee80211_mfr_free(struct ieee80211_mfr_list *reg_list,
		struct ieee80211_mfr_entry *reg_entry)
{
	TAILQ_REMOVE(&reg_list->reg_list, reg_entry, reg_list);
	LIST_REMOVE(reg_entry, reg_hash);
	FREE(reg_entry, M_DEVBUF);
}

static void
ieee80211_mfr_free_all(struct ieee80211vap *vap)
{
	struct ieee80211_mfr_list *reg_list = vap->iv_mfr_list;
	struct ieee80211_mfr_entry *reg_entry;

	while ((reg_entry = TAILQ_FIRST(&reg_list->reg_list)) != NULL) {
			ieee80211_mfr_free(reg_list, reg_entry);
	}

	return;
}

/*
 * Check for features that cannot be enabled if their management frames are handled by MFR.
 */
int
ieee80211_mfr_check_conflict(struct ieee80211vap *vap, uint8_t cat)
{
	struct ieee80211_mfr_list *reg_list = vap->iv_mfr_list;
	struct ieee80211_mfr_entry *reg_entry;

	if (!reg_list)
		return 0;

	spin_lock(&reg_list->reg_list_lock);
	TAILQ_FOREACH(reg_entry, &reg_list->reg_list, reg_list) {
		if (reg_entry != NULL) {
			if ((reg_entry->subtype == IEEE80211_FC0_SUBTYPE_ACTION) &&
					(reg_entry->match[0] == cat)) {
				spin_unlock(&reg_list->reg_list_lock);
				return 1;
			}
		}
	}
	spin_unlock(&reg_list->reg_list_lock);

	return 0;
}

void
ieee80211_mfr_flags_free(struct ieee80211vap *vap, uint8_t flags)
{
	struct ieee80211_mfr_list *reg_list = vap->iv_mfr_list;
	struct ieee80211_mfr_entry *reg_entry, *next;

	if (!reg_list)
		return;

	spin_lock(&reg_list->reg_list_lock);
	TAILQ_FOREACH_SAFE(reg_entry, &reg_list->reg_list, reg_list, next) {
		if (reg_entry->flags & flags)
			ieee80211_mfr_free(reg_list, reg_entry);
	}
	spin_unlock(&reg_list->reg_list_lock);
}

void
ieee80211_mfr_detach(struct ieee80211vap *vap)
{
	struct ieee80211_mfr_list *reg_list = vap->iv_mfr_list;

	if (!reg_list)
		return;
	spin_lock(&reg_list->reg_list_lock);
	ieee80211_mfr_free_all(vap);
	vap->iv_mfr_list = NULL;
	spin_unlock(&reg_list->reg_list_lock);
	FREE(reg_list, M_DEVBUF);
}

int
ieee80211_mfr_valid_match_len(const uint8_t len, uint8_t flags)
{
	if (!len && !(flags & IEEE80211_MFR_ALLOW_ZERO_LEN))
		return 0;

	if (len <= IEEE80211_MFR_MAX_MATCH_LEN)
		return 1;

	return 0;
}

static struct ieee80211_mfr_entry *
ieee80211_mfr_find_entry(struct ieee80211_mfr_list *reg_list, const uint8_t subtype,
		const uint8_t* match, const uint8_t match_len, const uint8_t flags)
{
	struct ieee80211_mfr_entry *reg_entry;
	int hash;

	hash = IEEE80211_MFR_REG_LIST_HASH(subtype, (match_len) ? match[0]: 0,
			(match_len > 1)? match[1] : 0);

	LIST_FOREACH(reg_entry, &reg_list->reg_hash[hash], reg_hash) {
		if ((subtype == reg_entry->subtype) && (reg_entry->flags & flags)) {
			if (!reg_entry->match_len)
				return reg_entry;

			if ((reg_entry->match_len <= match_len) &&
					(!memcmp(match, reg_entry->match, reg_entry->match_len)))
				return reg_entry;
		}
	}

	return NULL;
}

static struct ieee80211_mfr_entry *
ieee80211_mfr_find_entry_on_config(struct ieee80211_mfr_list *reg_list,
		struct ieee80211_mfr_entry *reg_config)
{
	struct ieee80211_mfr_entry *reg_new = NULL;

	reg_new = ieee80211_mfr_find_entry(reg_list, reg_config->subtype,
			reg_config->match, reg_config->match_len,
			IEEE80211_MFR_FLAGS_ALL);

	return reg_new;
}

static int
ieee80211_mfr_is_supported_mgmt_frame(const struct ieee80211_mfr_entry *reg_config)
{
	uint8_t subtype = reg_config->subtype;
	uint8_t cat;
	uint8_t i;

	if ((subtype == IEEE80211_FC0_SUBTYPE_ACTION) &&
		(ieee80211_mfr_valid_match_len(reg_config->match_len, 0))) {
		cat = reg_config->match[0];
		if (reg_config->flags & IEEE80211_MFR_FLAG_XMIT) {
			for (i = 0; i < ARRAY_SIZE(ieee80211_mfr_allow_tx_action_cat); i++)
				if (cat == ieee80211_mfr_allow_tx_action_cat[i])
					return 1;
		} else if (reg_config->flags & IEEE80211_MFR_FLAG_RECV) {
			for (i = 0; i < ARRAY_SIZE(ieee80211_mfr_allow_rx_action_cat); i++)
				if (cat == ieee80211_mfr_allow_rx_action_cat[i])
					return 1;
		}

	} else if (reg_config->flags & IEEE80211_MFR_FLAG_XMIT) {
		for (i = 0; i < ARRAY_SIZE(ieee80211_mfr_allow_tx_mgmt_subtype); i++)
			if (subtype == ieee80211_mfr_allow_tx_mgmt_subtype[i])
				return 1;
	} else if (reg_config->flags & IEEE80211_MFR_FLAG_RECV) {
		for (i = 0; i < ARRAY_SIZE(ieee80211_mfr_allow_rx_mgmt_subtype); i++)
			if (subtype == ieee80211_mfr_allow_rx_mgmt_subtype[i])
				return 1;
	}
	return 0;
}

static void
ieee80211_mfr_handle_conflict(struct ieee80211vap *vap, struct ieee80211_mfr_entry *entry)
{
	struct ieee80211com *ic = vap->iv_ic;

	if (entry->match_len) {
		switch (entry->match[0]) {
		case IEEE80211_ACTION_CAT_RM:
			if (IEEE80211_COM_NEIGHREPORT_ENABLED(vap)) {
				IEEE80211_DPRINTF_EXT(vap, IEEE80211_MSG_MFR,
						"MFR: conflict with 11k neighbor report %s,"
						" disable 11k\n", __FUNCTION__);
				IEEE80211_COM_NEIGHREPORT_DISABLE(vap);
			}
			break;
		case IEEE80211_ACTION_CAT_WNM:
			if (IEEE80211_COM_BTM_ENABLED(ic)) {
				IEEE80211_DPRINTF_EXT(vap, IEEE80211_MSG_MFR,
						"MFR: conflict with 11v WNM %s, disable 11v\n",
						__FUNCTION__);
				IEEE80211_COM_BTM_DISABLE(ic);
			}
			break;

		/* TODO: more conflicts here */
		default:
			break;
		}
	}
}

int
ieee80211_mfr_add_entry(struct ieee80211vap *vap, struct ieee80211_mfr_entry *reg_config)
{
	struct ieee80211_mfr_list *reg_list;
	struct ieee80211_mfr_entry *reg_new;
	int hash;
	int retval = 0;

	if (vap->iv_mfr_list == NULL) {
		retval = ieee80211_mfr_attach(vap);
		if (retval) {
			IEEE80211_DPRINTF_EXT(vap, IEEE80211_MSG_MFR,
					"MFR: attach failed at %s\n",
					__FUNCTION__);
			return retval;
		}
	}
	reg_list = vap->iv_mfr_list;
	if (!ieee80211_mfr_is_supported_mgmt_frame(reg_config)) {
		IEEE80211_DPRINTF_EXT(vap, IEEE80211_MSG_MFR,
				"MFR: add failed - type 0x%02x len %u not supported\n",
				reg_config->subtype, reg_config->match_len,
				reg_config->flags);
		return -ENOMEM;
	}

	if ((reg_config->flags & IEEE80211_MFR_FLAG_BYPASS) &&
			(reg_config->flags & IEEE80211_MFR_FLAG_SKB_COPY)) {
		IEEE80211_DPRINTF_EXT(vap, IEEE80211_MSG_MFR,
				"MFR: add failed - type 0x%02x flags 0x%02x not supported\n",
				reg_config->subtype, reg_config->flags);
		return -ENOMEM;
	}

	spin_lock(&reg_list->reg_list_lock);
	reg_new = ieee80211_mfr_find_entry_on_config(reg_list, reg_config);
	if (reg_new) {
		IEEE80211_DPRINTF_EXT(vap, IEEE80211_MSG_MFR,
				"MFR: add failed - type 0x%02x len %u already configured\n",
				reg_config->subtype, reg_config->match_len);
		spin_unlock(&reg_list->reg_list_lock);
		return 0;
	}

	MALLOC(reg_new, struct ieee80211_mfr_entry *, sizeof(struct ieee80211_mfr_entry),
			M_DEVBUF, M_NOWAIT | M_ZERO);
	if (reg_new == NULL) {
		IEEE80211_DPRINTF_EXT(vap, IEEE80211_MSG_MFR,
				"MFR: add failed - type 0x%02x len %u malloc failed\n",
				reg_config->subtype, reg_config->match_len);
		spin_unlock(&reg_list->reg_list_lock);
		return -ENOMEM;
	}

	reg_new->subtype = reg_config->subtype;
	reg_new->flags = reg_config->flags;

	if (reg_config->match_len &&
			ieee80211_mfr_valid_match_len(reg_config->match_len, 0)) {
		reg_new->match_len = reg_config->match_len;
		memcpy(reg_new->match, reg_config->match, reg_config->match_len);
		hash = IEEE80211_MFR_REG_LIST_HASH(reg_new->subtype, reg_new->match[0],
							reg_new->match[1]);
	} else {
		hash = IEEE80211_MFR_REG_LIST_HASH(reg_new->subtype, 0, 0);
	}

	TAILQ_INSERT_TAIL(&reg_list->reg_list, reg_new, reg_list);
	LIST_INSERT_HEAD(&reg_list->reg_hash[hash], reg_new, reg_hash);
	spin_unlock(&reg_list->reg_list_lock);

	ieee80211_mfr_handle_conflict(vap, reg_new);
	IEEE80211_DPRINTF_EXT(vap, IEEE80211_MSG_MFR,
			"MFR: alloc frames success %s, %u %u\n",
			__FUNCTION__, reg_new->subtype, reg_new->match_len);
	return 0;
}

int
ieee80211_mfr_del_entry(struct ieee80211vap *vap, struct ieee80211_mfr_entry *reg_config)
{
	struct ieee80211_mfr_list *reg_list;
	struct ieee80211_mfr_entry *reg = NULL;

	if (!vap->iv_mfr_list)
		return 0;

	reg_list = vap->iv_mfr_list;

	spin_lock(&reg_list->reg_list_lock);
	reg = ieee80211_mfr_find_entry_on_config(reg_list, reg_config);
	if (!reg) {
		IEEE80211_DPRINTF_EXT(vap, IEEE80211_MSG_MFR,
				"MFR: del frames doesn't exist %d %d\n",
				reg_config->subtype, reg_config->match_len);
		spin_unlock(&reg_list->reg_list_lock);
		return 0;
	}

	ieee80211_mfr_free(reg_list, reg);
	spin_unlock(&reg_list->reg_list_lock);

	IEEE80211_DPRINTF_EXT(vap, IEEE80211_MSG_MFR,
			"MFR: delete frames success %s, %u %u\n",
			__FUNCTION__, reg_config->subtype, reg_config->match_len);
	return 0;
}

void
ieee80211_mfr_show_list(struct ieee80211vap *vap)
{
	struct ieee80211_mfr_list *reg_list;
	struct ieee80211_mfr_entry *reg_entry;
	int cnt = 0;

	if (!vap->iv_mfr_list)
		return;

	reg_list = vap->iv_mfr_list;

	spin_lock(&reg_list->reg_list_lock);
	TAILQ_FOREACH(reg_entry, &reg_list->reg_list, reg_list) {
		if (reg_entry != NULL) {
			cnt++;
			printk("%d -- subtype 0x%02x,flags 0x%02x, match_len %u, 0x%02x 0x%02x\n",
					cnt,
					reg_entry->subtype,
					reg_entry->flags,
					reg_entry->match_len,
					reg_entry->match[0],
					reg_entry->match[1]);
		}
	}
	spin_unlock(&reg_list->reg_list_lock);
}

int
ieee80211_mfr_is_forwarding_allowed(struct ieee80211vap *vap,
		int subtype, struct sk_buff *skb)
{
	struct ieee80211_frame *wh = (struct ieee80211_frame *) skb->data;
	struct ieee80211_action *ia;
	uint8_t cat = 0;
	uint8_t action = 0;

	if (subtype == IEEE80211_FC0_SUBTYPE_ACTION) {
		ia = (struct ieee80211_action *)&wh[1];
		cat = ia->ia_category;
		action = ia->ia_action;
	}

	if (ieee80211_mfr_is_in_list(vap, subtype, cat,
				action, IEEE80211_MFR_FLAG_RECV)) {
		IEEE80211_DPRINTF_EXT(vap, IEEE80211_MSG_MFR,
				"MFR: subtype 0x%02x %u %u not forwarding to hostapd\n",
				subtype, cat, action);
		return 0;
	}

	return 1;
}

struct ieee80211_mfr_entry *
ieee80211_mfr_is_in_list(struct ieee80211vap *vap, uint8_t subtype,
		uint8_t cat, uint8_t action, uint8_t flags)
{
	struct ieee80211_mfr_entry *entry;
	struct ieee80211_mfr_list *reg_list;
	uint8_t match[IEEE80211_MFR_MAX_MATCH_LEN] = {0};

	if (!vap->iv_mfr_list)
		return NULL;

	reg_list = vap->iv_mfr_list;
	match[0] = cat;
	match[1] = action;
	spin_lock(&reg_list->reg_list_lock);
	entry = ieee80211_mfr_find_entry(reg_list, subtype, match,
			IEEE80211_MFR_MAX_MATCH_LEN, flags);
	spin_unlock(&reg_list->reg_list_lock);

	return entry;
}

int
ieee80211_mfr_send_to_app(struct ieee80211vap *vap, struct ieee80211_mfr_entry *entry,
		struct sk_buff *skb, int rssi, int bsa, uint16_t *reject_code)
{
	int filtered = 0;
	struct ieee80211_qrpe_event_data *p_data;
	struct ieee80211_qrpe_event_recv_frame *pevent;
	struct ieee80211com *ic = vap->iv_ic;
	uint32_t len;
	uint8_t *event_data = NULL;
	struct ieee80211_frame *wh;

	if (!skb) {
		IEEE80211_DPRINTF_EXT(vap, IEEE80211_MSG_MFR,
				"MFR: %s failed, no param\n", __FUNCTION__);
		return filtered;
	}

	wh = (struct ieee80211_frame *)skb->data;
#if defined(CONFIG_QTN_BSA_SUPPORT)
	if (bsa && (vap->bsa_status == IEEE80211_QRPE_STATUS_ACTIVE)) {
		uint8_t matched_result[ERW_CONTENT_MATCH_MAX_BUF_LEN] = { 0 };

		ieee80211_bsa_macfilter_check(vap, wh->i_addr2, NULL, 0, entry->subtype,
					rssi, &filtered, reject_code,
					matched_result, ERW_CONTENT_MATCH_MAX_BUF_LEN);
	}
#endif

	if (!is_ieee80211_chan_valid(ic->ic_curchan)) {
		IEEE80211_DPRINTF_EXT(vap, IEEE80211_MSG_MFR,
				"MFR: %s failed, no chan\n", __FUNCTION__);
		return filtered;
	}

	len = sizeof(*p_data) + sizeof(*pevent) + skb->len;
	event_data = kmalloc(len, GFP_ATOMIC);
	if (!event_data) {
		IEEE80211_DPRINTF_EXT(vap, IEEE80211_MSG_MFR,
				"MFR: %s failed, no mem\n", __FUNCTION__);
		return filtered;
	}
	p_data = (struct ieee80211_qrpe_event_data *)event_data;
	pevent = (struct ieee80211_qrpe_event_recv_frame *)(p_data->event);
	memset(pevent, 0, sizeof(*pevent));
	rssi -= 90;
	pevent->rssi = rssi;
	if (ic->ic_flags_qtn & IEEE80211_QTN_BGSCAN) {
		struct shared_params *sp = qtn_mproc_sync_shared_params_get();
		struct qtn_scan_chan_info *scan_host = sp->chan_scan_lhost;
		struct qtn_off_chan_info *off_chan_info = &scan_host->base;
		pevent->chan = QTNCHAN_TO_IEEENUM(off_chan_info->channel);
	} else {
		pevent->chan = ic->ic_curchan->ic_ieee;
	}
	pevent->driver_process = filtered;
	pevent->data_len = skb->len;
	memcpy(pevent->data, skb->data, skb->len);
	if (net_ratelimit())
		IEEE80211_DPRINTF_EXT(vap, IEEE80211_MSG_MFR,
				"MFR: send frame sybtype 0x%02x, match %u %u, skblen %u,"
				"flags 0x%02x, rssi %d, chan %u\n",
			entry->subtype, entry->match[0], entry->match[1], skb->len,
			entry->flags, pevent->rssi, pevent->chan);

#if defined(CONFIG_QTN_BSA_SUPPORT)
	ieee80211_build_qrpe_event_head(vap, p_data,
			IEEE80211_QRPE_EVENT_RECV_MGMT_FRAME,
			len - sizeof(struct ieee80211_qrpe_event_data));
	ieee80211_send_qrpe_event(BSA_MCGRP_DRV_EVENT, (uint8_t *)p_data, len);
#endif
	kfree(event_data);

	return filtered;
}
