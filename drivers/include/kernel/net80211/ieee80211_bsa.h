/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications, Inc.                 **
**                            All Rights Reserved                            **
**                                                                           **
**  File        : ieee80211_bsa.h                                            **
**  Description : Quantenna Band steering defines                            **
**                                                                           **
**  This module implements portions of the IEEE Std 802.11z specification,   **
** as well as a proprietary discovery mechanism.                             **
**                                                                           **
*******************************************************************************
**                                                                           **
**  Redistribution and use in source and binary forms, with or without       **
**  modification, are permitted provided that the following conditions       **
**  are met:                                                                 **
**  1. Redistributions of source code must retain the above copyright        **
**     notice, this list of conditions and the following disclaimer.         **
**  2. Redistributions in binary form must reproduce the above copyright     **
**     notice, this list of conditions and the following disclaimer in the   **
**     documentation and/or other materials provided with the distribution.  **
**  3. The name of the author may not be used to endorse or promote products **
**     derived from this software without specific prior written permission. **
**                                                                           **
**  Alternatively, this software may be distributed under the terms of the   **
**  GNU General Public License ("GPL") version 2, or (at your option) any    **
**  later version as published by the Free Software Foundation.              **
**                                                                           **
**  In the case this software is distributed under the GPL license,          **
**  you should have received a copy of the GNU General Public License        **
**  along with this software; if not, write to the Free Software             **
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  **
**                                                                           **
**  THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR       **
**  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES**
**  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  **
**  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,         **
**  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT **
**  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,**
**  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY    **
**  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT      **
**  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF **
**  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.        **
**                                                                           **
*******************************************************************************
EH0*/

#ifndef _NET80211_IEEE80211_BSA_H_
#define _NET80211_IEEE80211_BSA_H_

#include <net/genetlink.h>

#define BSA_BTM_CAND_PREF		3
#define BSA_BTM_CAND_PREF_ID		3
#define BSA_BTM_CAND_PREF_LEN		1
#define BSA_BTM_CAND_PREF_VAL		255
#define BSA_BTM_RESP_TIMEDOUT		0xff

#define BSA_VHT_MCSMAP_NOT_SUPPORT	0xC000
#define BSA_VHT_MCSMAP_MASK		0xC000
#define DEFAULT_BANDWIDTH		40

#define IEEE80211_ERW_ENTRY_HASHSIZE	32

#define IEEE80211_BSA_ERW_MATCHED_TYPE_IE	1
#define IEEE80211_BSA_ERW_MATCHED_TYPE_SUBIE	2
#define ERW_CONTENT_MAX_BUF_LEN			512
#define ERW_CONTENT_MATCH_MAX_BUF_LEN		64
#define IEEE80211_MAX_MATCHED_IE_NUM		16
#define IEEE80211_ERW_CONTENT_MAX_IE_ITEM	5
#define IEEE80211_ERW_CONTENT_MAX_SUBIE_ITEM	8

#define	BSA_MACFILTER_HASH(addr)	\
	(((u_int8_t *)(addr))[IEEE80211_ADDR_LEN - 1] % IEEE80211_ERW_ENTRY_HASHSIZE)
MALLOC_DEFINE(M_80211_ERW, "erw", "802.11 station erw");

#define BSA_GENL_VERSION		1

enum ieee80211_bsa_action {
	BSA_ACTION_NONE = 0,
	BSA_ACTION_WITHHOLD,
	BSA_ACTION_REJECT,
};

/* multicast groups */
enum nl80211_multicast_groups {
	BSA_MCGRP_DRV_EVENT,
	BSA_MCGRP_BSA_COMMAND,
	BSA_MCGRP_BSA_PEER_EVENT,
	BSA_MCGRP_DRV_PROBE_EVENT,
};

enum qrpe_nl80211_probe_tunnel {
	QRPE_PROBE_TUNNEL_DISABLED,
	QRPE_PROBE_TUNNEL_ENABLED,
};

enum ieee80211_bsa_matched_type {
	BSA_MATCH_NONE = 0,
	BSA_MATCH_RSSI,
	BSA_MATCH_CONTENT_IE,
	BSA_MATCH_CONTENT_SUBIE,
};

struct ieee80211_erw_content_matched_item {
	uint8_t *matched_ie_start;
	uint8_t matched_ie_len;
};

struct ieee80211_bsa_erw_content_subie {
	uint8_t subie_id;
	uint8_t reject_mode;
	uint8_t subie_present;
	uint8_t match_type;
	uint16_t match_offset;
	uint16_t match_len;
	uint32_t idx_mask;
	uint8_t match[IEEE80211_BSA_MAX_CONTENT_LEN];

	TAILQ_ENTRY(ieee80211_bsa_erw_content_subie) subie_entry;
};

struct ieee80211_bsa_erw_content_ie {
	uint8_t ie_id;
	uint8_t reject_mode;
	uint8_t ie_present;
	uint8_t num_subie;
	uint32_t idx_mask;
	uint16_t match_offset;
	uint16_t match_len;
	uint16_t subel_offset;
	uint8_t match[IEEE80211_BSA_MAX_CONTENT_LEN];

	TAILQ_ENTRY(ieee80211_bsa_erw_content_ie) ie_entry;
	TAILQ_HEAD(, ieee80211_bsa_erw_content_subie) subie_missing_list;
	TAILQ_HEAD(, ieee80211_bsa_erw_content_subie) subie_present_list;
};

struct ieee80211_bsa_erw_entry {
	/* station MAC address, generic MAC address: ff:ff:ff:ff:ff:ff */
	char mac_addr[IEEE80211_ADDR_LEN];

	uint16_t frame_select;
	uint16_t reject_mode;
	uint8_t rssi_mode;
	int32_t rssi_thrd_min;
	int32_t rssi_thrd_max;
	uint32_t idx_mask;

	/* counter */
	uint32_t probe_cnt;
	uint32_t auth_cnt;
	uint32_t assoc_cnt;
	uint32_t reassoc_cnt;

	uint8_t ie_missing_num;
	uint8_t ie_present_num;

	TAILQ_HEAD(, ieee80211_bsa_erw_content_ie) ie_missing_list;
	TAILQ_HEAD(, ieee80211_bsa_erw_content_ie) ie_present_list;
};

struct ieee80211_bsa_erw_entry_list {
	TAILQ_ENTRY(ieee80211_bsa_erw_entry_list) erw_entry_list;
	LIST_ENTRY(ieee80211_bsa_erw_entry_list) erw_entry_hash;
	struct ieee80211_bsa_erw_entry erw_entry;
};

struct ieee80211_bsa_erw_table {
	int erw_entry_num;
	int erw_wildcard_status;
	struct ieee80211_bsa_erw_entry erw_wildcard_entry;
	TAILQ_HEAD(, ieee80211_bsa_erw_entry_list) erw_list; /* list of all ERW entry */
	ATH_LIST_HEAD(, ieee80211_bsa_erw_entry_list) erw_hash[IEEE80211_ERW_ENTRY_HASHSIZE];
};

struct ieee80211_bsa_erw_nr_ie {
	uint8_t	id;
	uint8_t preference;
	uint16_t nr_ie_len;

	uint8_t nr_ie[0];
};

/*
 * Match BSSID and channel.
 */
struct target_bssid_scanlookup {
	uint8_t target_bssid[IEEE80211_ADDR_LEN];
	struct ieee80211_channel *target_chans;	/* assume one channel specified */
	int chan_num;
	const struct ieee80211_scan_entry *se;
	struct ieee80211vap *vap;
};


int bsa_send_genl_multicast_event(unsigned int group, u8 *buffer, int length);
void ieee80211_bsa_macfilter_detach(struct ieee80211vap *vap);
uint32_t ieee80211_wlan_vht_mcs_streams(uint16_t mcsmap);
uint32_t ieee80211_wlan_vht_rxstreams(struct ieee80211_ie_vhtcap *vhtcap);
uint32_t ieee80211_wlan_ht_rx_maxrate(struct ieee80211_ie_htcap *htcap, uint32_t *rx_ss);
uint32_t ieee80211_wlan_vht_rx_maxrate(struct ieee80211_ie_vhtcap *vhtcap);
int ieee80211_bsa_intf_update_notify_event_send(struct ieee80211vap *vap);
/* probe/auth/assoc req and connect complete event sent to bsa peer entity*/
int ieee80211_bsa_probe_or_assoc_send(struct ieee80211vap *vap, struct sk_buff *skb, uint8_t *bssid,
					int subtype, uint8_t *sta_mac, int rssi, int filtered);
int ieee80211_bsa_auth_event_send(struct ieee80211vap *vap, struct sk_buff *skb,
					uint8_t *bssid, uint8_t *sta_mac, int rssi, int filtered);
int ieee80211_bsa_connect_complete_event_send(struct ieee80211vap *vap,struct ieee80211_node *ni);
int ieee80211_bsa_macfilter_check(struct ieee80211vap *vap, uint8_t mac[IEEE80211_ADDR_LEN],
		uint8_t *frm, uint32_t frm_len, int subtype, int rssi, int *filtered,
		uint16_t *reject_code, uint8_t *content_param, uint16_t content_len);
int ieee80211_bsa_disconnect_event_send(struct ieee80211vap *vap, struct ieee80211_node *ni,
					uint16_t reason_code, uint8_t fc_subtype, uint8_t direction);
int ieee80211_bsa_btm_resp_event(struct ieee80211vap *vap,struct ieee80211_node *ni, uint8_t status);
int ieee80211_bsa_powersave_event_send(struct ieee80211vap *vap, int pm_state,
		int pm_qos_class, const char *name);
void ieee80211_build_qrpe_event_head(struct ieee80211vap *vap, struct ieee80211_qrpe_event_data *head,
	uint16_t event_id, uint16_t len);
int ieee80211_send_qrpe_event(unsigned int group, uint8_t *event, int len);
int ieee80211_bsa_get_erw_nr_ie_len(struct ieee80211vap *vap,
			uint8_t *mac, int matched_type, void *matched_arg);
u_int8_t *ieee80211_bsa_fill_erw_nr_ie(struct ieee80211vap *vap,
			uint8_t *mac, uint8_t *frm, int matched_type, void *matched_arg);
int ieee80211_send_analyzed_scan_result(struct ieee80211vap *vap);
#endif  /* BSA_IEEE80211_H */
