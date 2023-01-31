/*
 * Copyright (c) 2018 Quantenna
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
 */

/*
 * Management Frame Registration
 */
#ifndef IEEE80211_MFR_H
#define IEEE80211_MFR_H

#define IEEE80211_MFR_MAX_MATCH_LEN	7
struct ieee80211_mfr_entry {
	TAILQ_ENTRY(ieee80211_mfr_entry) reg_list;
	LIST_ENTRY(ieee80211_mfr_entry) reg_hash;
	uint8_t subtype;
	uint8_t flags;
	uint8_t match_len;
	/*
	 * match format is:
	 * byte 0 - category
	 * byte 1 - action_code
	 */
	uint8_t match[IEEE80211_MFR_MAX_MATCH_LEN];
};

#define REG_LIST_HASHSIZE	32
struct ieee80211_mfr_list {
	spinlock_t reg_list_lock;
	TAILQ_HEAD(, ieee80211_mfr_entry) reg_list;
	ATH_LIST_HEAD(, ieee80211_mfr_entry) reg_hash[REG_LIST_HASHSIZE];
};

#define IEEE80211_MFR_FLAGS_ALL		0xff
#define IEEE80211_MFR_REG_LIST_HASH(_sub, _cat, _action) \
		((((_sub) >> IEEE80211_FC0_SUBTYPE_SHIFT) + (_cat) + (_action)) % REG_LIST_HASHSIZE)

#define IEEE80211_MFR_ALLOW_ZERO_LEN	0x1

extern uint8_t ieee80211_mfr_allow_tx_mgmt_subtype[];
extern uint8_t ieee80211_mfr_allow_rx_mgmt_subtype[];
extern uint8_t ieee80211_mfr_allow_tx_action_cat[];
extern uint8_t ieee80211_mfr_allow_rx_action_cat[];

extern const uint32_t ieee80211_mfr_allow_tx_mgmt_subtype_size;
extern const uint32_t ieee80211_mfr_allow_rx_mgmt_subtype_size;
extern const uint32_t ieee80211_mfr_allow_tx_action_cat_size;
extern const uint32_t ieee80211_mfr_allow_rx_action_cat_size;

void ieee80211_mfr_flags_free(struct ieee80211vap *vap, uint8_t flags);
void ieee80211_mfr_detach(struct ieee80211vap *vap);
int ieee80211_mfr_add_entry(struct ieee80211vap *vap, struct ieee80211_mfr_entry *config);
int ieee80211_mfr_del_entry(struct ieee80211vap *vap, struct ieee80211_mfr_entry *config);
void ieee80211_mfr_show_list(struct ieee80211vap *vap);
int ieee80211_mfr_valid_match_len(const uint8_t len, uint8_t flags);
int ieee80211_mfr_is_forwarding_allowed(struct ieee80211vap *vap,
		                int subtype, struct sk_buff *skb);
int ieee80211_mfr_check_conflict(struct ieee80211vap *vap, uint8_t cat);
struct ieee80211_mfr_entry *ieee80211_mfr_is_in_list(struct ieee80211vap *vap, uint8_t subtype,
		uint8_t cat, uint8_t action, uint8_t flags);
int ieee80211_mfr_send_to_app(struct ieee80211vap *vap, struct ieee80211_mfr_entry *entry,
		struct sk_buff *skb, int rssi, int bsa, uint16_t *reject_code);

#endif /* IEEE80211_MFR_H */

