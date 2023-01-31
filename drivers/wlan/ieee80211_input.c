/*-
 * Copyright (c) 2001 Atsushi Onoe
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
 * $Id: ieee80211_input.c 2610 2007-07-25 15:26:38Z mrenzmann $
 */
#ifndef EXPORT_SYMTAB
#define	EXPORT_SYMTAB
#endif

/*
 * IEEE 802.11 input handling.
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
#include <linux/if_vlan.h>
#include <net/iw_handler.h> /* wireless_send_event(..) */
#include <linux/wireless.h> /* SIOCGIWTHRSPY */
#include <linux/if_arp.h> /* ARPHRD_ETHER */
#include <linux/jiffies.h>

#include "net80211/if_llc.h"
#include "net80211/if_ethersubr.h"
#include "net80211/if_media.h"

#include "net80211/ieee80211_var.h"
#include "net80211/ieee80211_linux.h"
#include "net80211/ieee80211_dot11_msg.h"
#include "net80211/ieee80211_tpc.h"
#include "net80211/ieee80211_tdls.h"
#include "net80211/ieee80211_mlme_statistics.h"
#include "net80211/ieee80211_repeater.h"

#include "qtn/wlan_ioctl.h"

#include "qtn/qtn_global.h"
#include "qtn_logging.h"

#include <qdrv/qdrv_debug.h>
#include <qtn/shared_params.h>
#include <qtn/hardware_revision.h>
#include <qtn/qtn_nis.h>

#if defined(CONFIG_BRIDGE) || defined(CONFIG_BRIDGE_MODULE)
#include <linux/if_bridge.h>
#include <linux/net/bridge/br_public.h>
#endif

#if defined(CONFIG_QTN_BSA_SUPPORT)
#include "net80211/ieee80211_qrpe.h"
#include "net80211/ieee80211_bsa.h"
extern int g_bsa_probe_event_tunnel;
#endif

#ifdef ARTSMNG_SUPPORT
#include "artsmng.h"
#endif

#ifdef IEEE80211_DEBUG
/*
 * Decide if a received management frame should be
 * printed when debugging is enabled.  This filters some
 * of the less interesting frames that come frequently
 * (e.g. beacons).
 */
static __inline int
doprint(struct ieee80211vap *vap, int subtype)
{
	switch (subtype) {
	case IEEE80211_FC0_SUBTYPE_BEACON:
		return (vap->iv_ic->ic_flags & IEEE80211_F_SCAN);
	case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
		return (vap->iv_opmode == IEEE80211_M_IBSS);
	}
	return 1;
}

/*
 * Emit a debug message about discarding a frame or information
 * element.  One format is for extracting the mac address from
 * the frame header; the other is for when a header is not
 * available or otherwise appropriate.
 */
#define	IEEE80211_DISCARD(_vap, _m, _wh, _type, _fmt, ...) do {		\
	if ((_vap)->iv_debug & (_m))					\
		ieee80211_discard_frame(_vap, _wh, _type, _fmt, __VA_ARGS__);\
} while (0)
#define	IEEE80211_DISCARD_IE(_vap, _m, _wh, _type, _fmt, ...) do {	\
	if ((_vap)->iv_debug & (_m))					\
		ieee80211_discard_ie(_vap, _wh, _type, _fmt, __VA_ARGS__);\
} while (0)
#define	IEEE80211_DISCARD_MAC(_vap, _m, _mac, _type, _fmt, ...) do {	\
	if ((_vap)->iv_debug & (_m))					\
		ieee80211_discard_mac(_vap, _mac, _type, _fmt, __VA_ARGS__);\
} while (0)

static const u_int8_t *ieee80211_getbssid(struct ieee80211vap *,
	const struct ieee80211_frame *);
static void ieee80211_discard_frame(struct ieee80211vap *,
	const struct ieee80211_frame *, const char *, const char *, ...);
static void ieee80211_discard_ie(struct ieee80211vap *,
	const struct ieee80211_frame *, const char *, const char *, ...);
static void ieee80211_discard_mac(struct ieee80211vap *,
	const u_int8_t mac[IEEE80211_ADDR_LEN], const char *,
	const char *, ...);
#else
#define	IEEE80211_DISCARD(_vap, _m, _wh, _type, _fmt, ...)
#define	IEEE80211_DISCARD_IE(_vap, _m, _wh, _type, _fmt, ...)
#define	IEEE80211_DISCARD_MAC(_vap, _m, _mac, _type, _fmt, ...)
#endif /* IEEE80211_DEBUG */

static struct sk_buff *ieee80211_defrag(struct ieee80211_node *ni,
	struct sk_buff *skb, int hdrlen, uint8_t is_prot);
static void ieee80211_deliver_data(struct ieee80211_node *, struct sk_buff *);
static struct sk_buff *ieee80211_decap(struct ieee80211vap *,
	struct sk_buff *, int);
static void ieee80211_send_error(struct ieee80211_node *, const u_int8_t *,
	int, int);
static void ieee80211_recv_pspoll(struct ieee80211_node *, struct sk_buff *);
static int accept_data_frame(struct ieee80211vap *, struct ieee80211_node *,
	struct ieee80211_key *, struct sk_buff *, struct ether_header *);
static void forward_mgmt_to_app(struct ieee80211vap *vap, int subtype, struct sk_buff *skb,
	struct ieee80211_frame *wh, int rssi);
static void forward_mgmt_to_app_for_further_processing(struct ieee80211vap *vap,
	int subtype, struct sk_buff *skb, struct ieee80211_frame *wh, int rssi);
#ifdef USE_HEADERLEN_RESV
static __be16 ath_eth_type_trans(struct sk_buff *, struct net_device *);
#endif

static void ieee80211_recv_action_tdls(struct ieee80211_node *ni, struct sk_buff *skb,
	struct ieee80211_action *ia, int ieee80211_header, int rssi);

static void ieee80211_recv_action_vht(struct ieee80211_node *ni,
				      struct ieee80211_action *ia,
				      int subtype,
				      struct ieee80211_frame *wh,
				      u_int8_t *frm,
				      u_int8_t *efrm);
static void ieee80211_recv_action_wnm(struct ieee80211_node *ni,
				      struct ieee80211_action *ia,
				      int subtype,
				      struct ieee80211_frame *wh,
				      u_int8_t *frm,
				      u_int8_t *efrm);


/**
 * Given a node and the RSSI value of a just received frame from the node, this
 * function checks if to raise an iwspy event because we iwspy the node and RSSI
 * exceeds threshold (if active).
 *
 * @param vap: VAP
 * @param ni: sender node
 * @param rssi: RSSI value of received frame
 */
static void
iwspy_event(struct ieee80211vap *vap, struct ieee80211_node *ni, u_int rssi)
{
	if (vap->iv_spy.thr_low && vap->iv_spy.num && ni && (rssi <
		vap->iv_spy.thr_low || rssi > vap->iv_spy.thr_high)) {
		int i;
		for (i = 0; i < vap->iv_spy.num; i++) {
			if (IEEE80211_ADDR_EQ(ni->ni_macaddr,
				&(vap->iv_spy.mac[i * IEEE80211_ADDR_LEN]))) {

				union iwreq_data wrq;
				struct iw_thrspy thr;
				IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG,
					"%s: we spy %s, threshold is active "
					"and rssi exceeds it -> raise an iwspy"
					" event\n", __func__, ether_sprintf(
					 ni->ni_macaddr));
				memset(&wrq, 0, sizeof(wrq));
				wrq.data.length = 1;
				memset(&thr, 0, sizeof(struct iw_thrspy));
				memcpy(thr.addr.sa_data, ni->ni_macaddr,
					IEEE80211_ADDR_LEN);
				thr.addr.sa_family = ARPHRD_ETHER;
				set_quality(&thr.qual, rssi, vap->iv_ic->ic_channoise);
				set_quality(&thr.low, vap->iv_spy.thr_low, vap->iv_ic->ic_channoise);
				set_quality(&thr.high, vap->iv_spy.thr_high, vap->iv_ic->ic_channoise);
				wireless_send_event(vap->iv_dev,
					SIOCGIWTHRSPY, &wrq, (char*) &thr);
				break;
			}
		}
	}
}

static inline int
ieee80211_tdls_status_mismatch(struct ieee80211_node *ni)
{
	if (IEEE80211_NODE_IS_TDLS_INACTIVE(ni) ||
			IEEE80211_NODE_IS_TDLS_IDLE(ni))
		return 1;

	return 0;
}

int ieee80211_tdls_tqe_path_check(struct ieee80211_node *ni,
	struct sk_buff *skb, int rssi, uint16_t ether_type)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211_action *ia;
	uint8_t *payload_type;
	struct ether_header *eh = (struct ether_header *) skb->data;

	if (ether_type == __constant_htons(ETHERTYPE_80211MGT)) {
		payload_type = (uint8_t*)(eh + 1);
		if ( *payload_type == IEEE80211_SNAP_TYPE_TDLS) {
			if (vap->iv_opmode == IEEE80211_M_STA) {
				IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_DBG,
						"TDLS %s: got 802.11 management over data, type=%u ptr=%p (%p)\n",
						__func__, *payload_type, payload_type, eh);
				ia = (struct ieee80211_action *)(payload_type + 1);
				ieee80211_recv_action_tdls(ni, skb, ia, 0, rssi);
			}

			if (vap->iv_opmode == IEEE80211_M_HOSTAP && (vap->hs20_enable || g_l2_ext_filter)) {
				IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_DBG,
						"%s Dropping TDLS frame due to HS2.0 enabled\n", __func__);
				return 1;
			}
		} else {
			IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_WARN,
				"TDLS %s: unsupported type %u\n",
				__func__, *payload_type);
			vap->iv_stats.is_rx_mgtdiscard++;
		}
	} else if (ieee80211_tdls_status_mismatch(ni)) {
		enum ieee80211_tdls_operation operation;

		IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_WARN,
				"TDLS %s: data not allowed before tdls link is ready, peer status: %u\n",
				__func__, ni->tdls_status);
		vap->iv_stats.is_rx_tdls_stsmismatch++;
		operation = IEEE80211_TDLS_TEARDOWN;
		ieee80211_tdls_send_event(ni, IEEE80211_EVENT_TDLS, &operation);

		return 1;
	}

	return 0;
}
EXPORT_SYMBOL(ieee80211_tdls_tqe_path_check);

static int ieee80211_action_frame_check(struct ieee80211vap *vap,
	struct sk_buff *skb, struct llc *llc, int min_len)
{
	int ret = 0;
	if ((vap->iv_opmode == IEEE80211_M_STA) &&
		(skb->len >= min_len) &&
		(llc->llc_dsap == LLC_SNAP_LSAP) &&
		(llc->llc_ssap == LLC_SNAP_LSAP) &&
		(llc->llc_control == LLC_UI) &&
		(llc->llc_snap.org_code[0] == 0) &&
		(llc->llc_snap.org_code[1] == 0) &&
		(llc->llc_snap.org_code[2] == 0) &&
		(llc->llc_un.type_snap.ether_type ==
			htons(ETHERTYPE_80211MGT))) {
			ret = 1;

	}
	return ret;
}

static void ieee80211_tdls_mailbox_path_check(struct ieee80211_node *ni,
	struct sk_buff *skb, struct llc *llc, int rssi, int min_len)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211_action *ia;
	uint8_t *payload_type;

	min_len += sizeof(*payload_type) + sizeof(*ia);
	if (ieee80211_action_frame_check(vap, skb, llc, min_len)) {
		if (unlikely(ieee80211_msg(vap, IEEE80211_MSG_TDLS) &&
				ieee80211_tdls_msg(vap, IEEE80211_TDLS_MSG_DBG))) {
			ieee80211_dump_pkt(vap->iv_ic, skb->data, min_len, -1, rssi);
		}
		payload_type = (u_int8_t *)llc + LLC_SNAPFRAMELEN;
		IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_DBG,
			"TDLS %s: got 802.11 management over data, type=%u ptr=%p (%p)\n",
			__func__, *payload_type, payload_type, llc);

		if (*payload_type == IEEE80211_SNAP_TYPE_TDLS) {
			ia = (struct ieee80211_action *)(payload_type + 1);
			ieee80211_recv_action_tdls(ni, skb, ia, 1, rssi);
		} else {
			IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_WARN,
				"TDLS %s: unsupported type %u\n",
				__func__, *payload_type);
			vap->iv_stats.is_rx_mgtdiscard++;
		}
	} else if (ieee80211_tdls_status_mismatch(ni)) {
		enum ieee80211_tdls_operation operation;

		IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_WARN,
				"TDLS %s: data not allowed before tdls link is ready, peer status: %u\n",
				__func__, ni->tdls_status);
		vap->iv_stats.is_rx_tdls_stsmismatch++;
		operation = IEEE80211_TDLS_TEARDOWN;
		ieee80211_tdls_send_event(ni, IEEE80211_EVENT_TDLS, &operation);
	}
}

static int
ieee80211_is_tdls_disc_resp(struct sk_buff *skb, int hdrlen)
{
	struct ieee80211_action *ia = (struct ieee80211_action *)(skb->data + hdrlen);

	if (skb->len < (hdrlen + sizeof(struct ieee80211_action)))
		return 0;

	if ((ia->ia_category == IEEE80211_ACTION_CAT_PUBLIC) &&
			(ia->ia_action == IEEE80211_ACTION_PUB_TDLS_DISC_RESP))
		return 1;
	else
		return 0;
}


static int
ieee80211_is_tdls_action_frame(struct sk_buff *skb, int hdrlen)
{
	static const uint8_t snap_e_header_pref[] = {LLC_SNAP_LSAP, LLC_SNAP_LSAP, LLC_UI, 0x00, 0x00};
	uint8_t *data = &skb->data[hdrlen];
	uint16_t ether_type = get_unaligned((uint16_t*)&data[6]);
	int32_t snap_encap_pref = !memcmp(data, snap_e_header_pref, sizeof(snap_e_header_pref));

	return (snap_encap_pref && (ether_type == htons(ETHERTYPE_80211MGT)));
}

static __inline int
ieee80211_tdls_frame_should_accept(struct sk_buff *skb, int type, int hdrlen)
{
	return (type == IEEE80211_FC0_TYPE_DATA && ieee80211_is_tdls_action_frame(skb, hdrlen)) ||
			(type == IEEE80211_FC0_TYPE_MGT && ieee80211_is_tdls_disc_resp(skb, hdrlen));
}

/*
 * Verify length for IEs explicitly defined in the max. length array.
 * Unused/reserved IEs are allowed to have length of 255 by default for forwards compatibility
 */
static int ieee80211_verify_ie_len(struct ieee80211vap *vap,
	struct ieee80211_frame *wh, int subtype, uint8_t *ie)
{
	if (ie[1] > ieee80211_max_ie_len[*ie]) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_ELEMID,
				wh,
				ieee80211_mgt_subtype_name[subtype >> IEEE80211_FC0_SUBTYPE_SHIFT],
				"bad IE %u len %u", *ie, ie[1]);
		vap->iv_stats.is_rx_elem_toobig++;
		return 0;
	}

	return 1;
}

static int ieee80211_ie_exists(struct ieee80211vap *vap,
	struct ieee80211_frame *wh, int subtype, uint8_t *ie)
{
	if (ie)
		return 1;

	IEEE80211_DISCARD(vap, IEEE80211_MSG_ELEMID,
			wh,
			ieee80211_mgt_subtype_name[subtype >> IEEE80211_FC0_SUBTYPE_SHIFT],
			"%s","Missing IE");
	vap->iv_stats.is_rx_elem_missing++;

	return 0;
}

static int ieee80211_rx_public_action_frame(struct ieee80211_frame *wh, struct sk_buff *skb,
						uint8_t type, uint8_t subtype);

static int ieee80211_input_should_drop(struct ieee80211_node *ni, uint8_t *bssid,
					struct ieee80211_frame *wh, uint8_t type,
					uint8_t subtype, struct sk_buff *skb)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	uint8_t dir = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;

	if (dir == IEEE80211_FC1_DIR_DSTODS)
		return 0;

#ifdef QTN_BG_SCAN
	if ((ic->ic_flags_qtn & IEEE80211_QTN_BGSCAN) &&
			(type == IEEE80211_FC0_TYPE_MGT) &&
			(subtype == IEEE80211_FC0_SUBTYPE_BEACON ||
				subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP)) {
		return 0;
	}
#endif

	if (timer_pending(&ic->sta_dfs_info.sta_silence_timer) &&
		(type == IEEE80211_FC0_TYPE_MGT) &&
			(subtype == IEEE80211_FC0_SUBTYPE_BEACON ||
			subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP))
		return 0;

	if (ic->ic_flags_qtn & IEEE80211_QTN_MONITOR)
		return 0;

	if ((type != IEEE80211_FC0_TYPE_CTL) && vap->tdls_over_qhop_en
			&& ieee80211_tdls_frame_should_accept(skb,
				type, ieee80211_hdrspace(ic, wh)))
	      return 0;

	/* PS-POLL frame in State 1 */
	if (IEEE80211_ADDR_EQ(ni->ni_bssid, vap->iv_myaddr) &&
			(type == IEEE80211_FC0_TYPE_CTL) &&
			(subtype == IEEE80211_FC0_SUBTYPE_PS_POLL)) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_INPUT | IEEE80211_MSG_AUTH,
			"%s: ps-poll in unauth state - send deauth with reason %u\n",
			__func__, IEEE80211_REASON_NOT_AUTHED);

		vap->iv_stats.is_rx_ps_unauth++;
		return 1;
	}

	if (ieee80211_rx_public_action_frame(wh, skb, type, subtype))
		return 0;

	/* Packet from unknown source - send deauth. */
	if (ni == vap->iv_bss && !ieee80211_is_bcst(wh->i_addr1)) {
		if (type == IEEE80211_FC0_TYPE_MGT && subtype == IEEE80211_FC0_SUBTYPE_DEAUTH) {
			/*
			 * Corner case
			 * AP may have changed mode to STA but we are still unconscious.
			 * If Deauthentication frames from AP are dropped here, we have no chance
			 * to disconnect with AP.
			 */
			if (IEEE80211_ADDR_EQ(wh->i_addr2, ni->ni_bssid))
				return 0;
		}
	}

	IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_INPUT,
		bssid, NULL, "not from bss %pM", ni->ni_bssid);
	vap->iv_stats.is_rx_wrongbss++;

	return 1;
}

void ieee80211_update_current_mode(struct ieee80211_node *ni)
{
	struct ieee80211com *ic = ni->ni_vap->iv_ic;

	if (IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan)) {
		if (IEEE80211_NODE_IS_VHT(ni)) {
			ni->ni_wifi_mode = IEEE80211_WIFI_MODE_AC;
		} else if (IEEE80211_NODE_IS_HT(ni)) {
			ni->ni_wifi_mode = IEEE80211_WIFI_MODE_NA;
		} else {
			ni->ni_wifi_mode = IEEE80211_WIFI_MODE_A;
		}
	} else {
		if (IEEE80211_NODE_IS_HT(ni)) {
			ni->ni_wifi_mode = IEEE80211_WIFI_MODE_NG;
		} else {
			/* Check the last rate since the list was sorted */
			if ((ni->ni_rates.rs_rates[ni->ni_rates.rs_nrates - 1]
				& IEEE80211_RATE_VAL) > IEEE80211_RATE_11MBPS) {
				ni->ni_wifi_mode = IEEE80211_WIFI_MODE_G;
			} else {
				ni->ni_wifi_mode = IEEE80211_WIFI_MODE_B;
			}
		}
	}
}

static int ieee80211_input_pmf_should_drop(struct ieee80211vap *vap,
				struct ieee80211_node *ni, struct ieee80211_frame *wh,
				struct sk_buff *skb, u_int8_t subtype, int rssi)
{
	if (!ni->ni_associd || !RSN_IS_MFP(ni->ni_rsn.rsn_caps))
		return 0;

	if (wh->i_fc[1] & IEEE80211_FC1_PROT) {
		wh->i_fc[1] &= ~IEEE80211_FC1_PROT;
		return 0;
	}
	if ((vap->iv_opmode == IEEE80211_M_STA)) {
		if (!ni->ni_sa_query_timeout &&
			(subtype == IEEE80211_FC0_SUBTYPE_DEAUTH ||
				subtype == IEEE80211_FC0_SUBTYPE_DISASSOC)) {
			if (IEEE80211_IS_MULTICAST(wh->i_addr1)) {
				forward_mgmt_to_app(vap, subtype, skb, wh, rssi);
				return 1;
			} else {
				ieee80211_send_sa_query(ni, IEEE80211_ACTION_W_SA_QUERY_REQ,
							++ni->ni_sa_query_tid);
				ieee80211_start_sa_query_response_wait_timer(ni);
				return 1;
			}
		}
	}
	if ((subtype == IEEE80211_FC0_SUBTYPE_AUTH) &&
			ieee80211_node_is_authorized(ni)) {
		if (ni->ni_sa_query_timeout) {
			IEEE80211_NOTE(ni->ni_vap, IEEE80211_MSG_ASSOC, ni,
				"SA query state is already running %lu", ni->ni_sa_query_timeout);
			return 1;
		}
		ieee80211_send_sa_query(ni, IEEE80211_ACTION_W_SA_QUERY_REQ,
					++ni->ni_sa_query_tid);
		ieee80211_start_sa_query_response_wait_timer(ni);
		return 1;
	}

	/*The broadcast csa action frame may not be encrypted*/
	if (qtn_is_csa_action_frame(wh) && IEEE80211_IS_MULTICAST(wh->i_addr1))
		return 0;

	if (ieee80211_mgmt_is_robust(wh))
		return 1;

	return 0;
}

static int ieee80211_extender_peer_lost(struct ieee80211vap *vap, uint8_t type,
			uint8_t subtype, struct ieee80211_frame *wh)
{
	if (vap->iv_opmode != IEEE80211_M_WDS)
		return 0;

	if (type != IEEE80211_FC0_TYPE_MGT)
		return 0;

	switch (subtype) {
	/*
	 * Unexpected
	 * peer is now an STA
	 * Link should be destroyed
	 */
	case IEEE80211_FC0_SUBTYPE_AUTH:
		return 1;
	/*
	 * Expected
	 */
	case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
	case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
	case IEEE80211_FC0_SUBTYPE_BEACON:
	case IEEE80211_FC0_SUBTYPE_ACTION:
	case IEEE80211_FC0_SUBTYPE_ACTION_NOACK:
		break;
	/*
	 * Unexpected
	 * Ignored
	 */
	default:
		IEEE80211_EXTENDER_DPRINTF(vap, IEEE80211_EXTENDER_MSG_WARN,
			"QHop: unexpected frame 0x%x with addr %pM %pM %pM\n",
			subtype, wh->i_addr1, wh->i_addr2, wh->i_addr3);
		break;
	}

	return 0;
}

/*
 * FIXME
 * Check malformed VHT Beamforming Report frames with invalid type/subtype
 */
static int
ieee80211_check_corrupt_vht_bfrpt(const struct ieee80211_node *ni,
	const struct ieee80211_frame *wh, uint8_t type, uint8_t subtype, uint16_t len)
{
	struct ieee80211_action *act_hdr;

	if (!ieee80211_node_is_qtn(ni))
		return 0;

	if (type == IEEE80211_FC0_TYPE_MGT) {
		switch (subtype) {
		case IEEE80211_FC0_SUBTYPE_DISASSOC:
		case IEEE80211_FC0_SUBTYPE_DEAUTH:
		case IEEE80211_FC0_SUBTYPE_AUTH:
			break;
		default:
			return 0;
		}
	} else {
		return 0;
	}

	if (len <= sizeof(struct ieee80211_frame) + sizeof(struct ieee80211_action))
		return 0;

	act_hdr = (struct ieee80211_action *)(wh + 1);
	/* VHT Compressed Beamforming */
	if ((act_hdr->ia_category != IEEE80211_ACTION_CAT_VHT) ||
			(act_hdr->ia_action != IEEE80211_ACTION_VHT_CBEAMFORMING))
		return 0;

	/* may need stricter check later */
	return 1;
}

static void
ieee80211_auth_bssid_mismatch(struct ieee80211vap *vap, struct ieee80211_frame *wh,
	struct ieee80211_node *ni)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211vap *tmp_vap;
	struct ieee80211_node_table *nt;
	struct ieee80211_node *tmp_ni;

	tmp_vap = ieee80211_find_vap(ic, wh->i_addr3);
	if (!tmp_vap)
		return;

	KASSERT(vap != tmp_vap, ("incorrect vap in function %s", __func__));
	/*
	 * FIXME
	 * AP (Repeater STA interface previously associated with) may have reloaded
	 * to STA mode, and tries to associate with Repeater AP interface. Auth frame from
	 * AP (STA mode) is dropped due to BSSID (e.g. wifi0/1) mismatch, hence "AP" fails
	 * to associate with Repeater AP interface.
	 *
	 * To workaround this corner case:
	 * 1. remove scan entry of "AP" in case wpa_supplicant reassociates with it
	 * 2. change VAP state of Repeater STA interface to "INIT" to clean up "AP" node
	 */
	if (ieee80211_is_repeater_sta(vap)) {
		if (!IEEE80211_ADDR_EQ(ni->ni_macaddr, wh->i_addr2))
			return;
		ieee80211_scan_remove(vap);
		vap->iv_newstate(vap, IEEE80211_S_INIT, 0);
	}

	if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
		nt = &ic->ic_sta;
		tmp_ni = ieee80211_find_node(nt, wh->i_addr2);
		if (tmp_ni) {
			ieee80211_free_node(tmp_ni);
			if (tmp_ni->ni_associd)
				ieee80211_node_leave(tmp_ni);
		}
	}
}

/*
 * Check if the input frame should be received
 * Return value:
 *	1 - receive
 *      0 - drop
 */
static int
ieee80211_input_frame_check(struct ieee80211_node **node,
	struct sk_buff *skb, int rssi, u_int32_t rstamp)
{
#define	HAS_SEQ(type)	((type & 0x4) == 0)
	struct ieee80211_node *ni = *node;
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct net_device *dev = vap->iv_dev;
	struct ieee80211_frame *wh = (struct ieee80211_frame *)skb->data;
	uint8_t dir = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;
	uint8_t type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
	uint8_t subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
	int node_reference_held = 0;
	uint8_t *bssid;
	uint16_t rxseq;

	KASSERT(ni != NULL, ("null node"));

	/*
	 * In monitor mode, send everything directly to bpf.
	 * Also do not process frames w/o i_addr2 any further.
	 * XXX may want to include the CRC
	 */
	if (vap->iv_opmode == IEEE80211_M_MONITOR)
		goto out;

	if (skb->len < sizeof(struct ieee80211_frame_min)) {
		IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_INPUT,
			ni->ni_macaddr, NULL,
			"too short (1): len %u", skb->len);
		vap->iv_stats.is_rx_tooshort++;
		vap->iv_stats.is_rx_tooshort_cnt++;
		goto out;
	}

	/*
	 * Probe request packets and other stuff should not reset the counter
	 * for associated STAs in AP mode.
	 * This is intended to catch beacons from WDS nodes.
	 */
	if ((vap->iv_opmode == IEEE80211_M_WDS) || IEEE80211_NODE_IS_TDLS_ACTIVE(ni))
		ni->ni_inact = ni->ni_inact_reload;

	/*
	 * Bit of a cheat here, we use a pointer for a 3-address
	 * frame format but don't reference fields past outside
	 * ieee80211_frame_min w/o first validating the data is
	 * present.
	 */
	if ((wh->i_fc[0] & IEEE80211_FC0_VERSION_MASK) !=
			IEEE80211_FC0_VERSION_0) {
		IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_INPUT,
			ni->ni_macaddr, NULL, "wrong version %x", wh->i_fc[0]);
		vap->iv_stats.is_rx_badversion++;
		goto err;
	}

	if (ic->ic_flags & IEEE80211_F_SCAN)
		return 1;

	switch (vap->iv_opmode) {
	case IEEE80211_M_STA:
		if (dir == IEEE80211_FC1_DIR_NODS)
			bssid = wh->i_addr3;
		else
			bssid = wh->i_addr2;
		if (!IEEE80211_ADDR_EQ(bssid, ni->ni_bssid)) {
			if (ieee80211_input_should_drop(ni,
					bssid, wh, type, subtype, skb)) {
				goto out;
			}
		}
		iwspy_event(vap, ni, rssi);
		break;
	case IEEE80211_M_IBSS:
	case IEEE80211_M_AHDEMO:
		if (dir != IEEE80211_FC1_DIR_NODS) {
			bssid = wh->i_addr1;
		} else if (type == IEEE80211_FC0_TYPE_CTL) {
			bssid = wh->i_addr1;
		} else {
			if (skb->len < sizeof(struct ieee80211_frame)) {
				IEEE80211_DISCARD_MAC(vap,
					IEEE80211_MSG_INPUT, ni->ni_macaddr,
					NULL, "too short (2): len %u",
					skb->len);
				vap->iv_stats.is_rx_tooshort++;
				vap->iv_stats.is_rx_tooshort_cnt++;
				goto out;
			}
			bssid = wh->i_addr3;
		}

		/*
		 * Do not try to find a node reference if the packet
		 * really did come from the BSS
		 */
		if (type == IEEE80211_FC0_TYPE_DATA && ni == vap->iv_bss &&
				!IEEE80211_ADDR_EQ(vap->iv_bss->ni_macaddr, wh->i_addr2)) {
			/* Try to find sender in local node table. */
			ni = ieee80211_find_node(vap->iv_bss->ni_table, wh->i_addr2);
			if (ni == NULL) {
				/*
				 * Fake up a node for this newly discovered
				 * member of the IBSS.  This should probably
				 * done after an ACL check.
				 */
				ni = ieee80211_fakeup_adhoc_node(vap,
						wh->i_addr2);
				if (ni == NULL) {
					/* NB: stat kept for alloc failure */
					goto err;
				}
			}
			node_reference_held = 1;
		}
		iwspy_event(vap, ni, rssi);
		break;
	case IEEE80211_M_HOSTAP:
		if (dir != IEEE80211_FC1_DIR_NODS) {
			bssid = wh->i_addr1;
		} else if (type == IEEE80211_FC0_TYPE_CTL) {
			bssid = wh->i_addr1;
		} else {
			if (skb->len < sizeof(struct ieee80211_frame)) {
				IEEE80211_DISCARD_MAC(vap,
					IEEE80211_MSG_INPUT, ni->ni_macaddr,
					NULL, "too short (2): len %u",
					skb->len);
				vap->iv_stats.is_rx_tooshort++;
				vap->iv_stats.is_rx_tooshort_cnt++;
				goto out;
			}
			bssid = wh->i_addr3;
		}

		/*
		 * Validate the bssid.
		 */
		if (!IEEE80211_ADDR_EQ(bssid, vap->iv_bss->ni_bssid) &&
				!IEEE80211_ADDR_EQ(bssid, dev->broadcast)) {
			/*
			 * It can be a beacon from other network.
			 * Required for certification.
			 */
			vap->iv_stats.is_rx_wrongbss++;
			if (!((type == IEEE80211_FC0_TYPE_MGT) &&
				((subtype == IEEE80211_FC0_SUBTYPE_BEACON)
					|| ((ic->ic_flags_qtn & IEEE80211_QTN_BGSCAN)
					&& (subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP))))) {
				if (type == IEEE80211_FC0_TYPE_MGT &&
						subtype == IEEE80211_FC0_SUBTYPE_AUTH) {
					ieee80211_auth_bssid_mismatch(vap, wh, ni);
				}

				IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_INPUT,
					bssid, NULL, "%s %02X %02X", "not to bss",
					type, subtype);

				goto out;
			}
		}
		break;
	case IEEE80211_M_WDS:
		if (skb->len < sizeof(struct ieee80211_frame_addr4)) {
			IEEE80211_DISCARD_MAC(vap,
				IEEE80211_MSG_INPUT, ni->ni_macaddr,
				NULL, "too short (3): len %u",
				skb->len);
			vap->iv_stats.is_rx_tooshort++;
			vap->iv_stats.is_rx_tooshort_cnt++;
			goto out;
		}
		bssid = wh->i_addr1;
		if (!IEEE80211_ADDR_EQ(bssid, vap->iv_myaddr) &&
				!IEEE80211_ADDR_EQ(bssid, dev->broadcast)) {
#ifdef ARTSMNG_SUPPORT
			/*
			 * FIXME: add PMF check
			 * remove wds link when an auth packet received from radio
			 * to ensure incoming node can connect as a STA
			 */
			if ((type == IEEE80211_FC0_TYPE_MGT) &&
					(subtype == IEEE80211_FC0_SUBTYPE_AUTH)) {
				struct ieee80211_node *temp_ni;
				struct ieee80211_node_table *nt = &ic->ic_sta;
				temp_ni = ieee80211_find_node(nt, wh->i_addr2);
				if (temp_ni) {
					printk_ratelimited(
						"[%pM] Removing WDS link subtype=0x%02X\n",
						temp_ni->ni_macaddr, subtype);
					ieee80211_node_leave(ni);
					ieee80211_free_node(temp_ni);
				}
			}
#endif /* ARTSMNG_SUPPORT */

			/* not interested in */
			IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_INPUT,
				bssid, NULL, "%s", "not to bss");
			vap->iv_stats.is_rx_wrongbss++;
			goto out;
		}
		if (!IEEE80211_ADDR_EQ(wh->i_addr2, vap->wds_mac)) {
			/* not interested in */
			IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_INPUT,
				wh->i_addr2, NULL, "%s", "not from DS");
			vap->iv_stats.is_rx_wrongbss++;
			goto out;
		}
		break;
	default:
		/* XXX catch bad values */
		goto out;
	}

	if (ieee80211_check_corrupt_vht_bfrpt(ni, wh, type, subtype, skb->len)) {
		IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_EXTDR,
			ni->ni_macaddr, NULL, "%s: type %02X %02X", "vht_bfrpt",
			type, subtype);
		vap->iv_stats.is_rx_corrupt_vht_bfrpt++;
		goto out;
	}

	ni->ni_rstamp = rstamp;
	ni->ni_last_rx = jiffies;

	if (HAS_SEQ(type)) {
		u_int8_t tid;

		if (IEEE80211_QOS_HAS_SEQ(wh)) {
			tid = ((struct ieee80211_qosframe *)wh)->
				i_qos[0] & IEEE80211_QOS_TID;
			if (TID_TO_WME_AC(tid) >= WME_AC_VI) {
				IEEE80211_LOCK(ic);
				ic->ic_wme.wme_hipri_traffic++;
				IEEE80211_UNLOCK(ic);
			}
			tid++;
		} else {
			tid = 0;
		}

		rxseq = le16toh(*(__le16 *)wh->i_seq);
		if ((wh->i_fc[1] & IEEE80211_FC1_RETRY) &&
			IEEE80211_SEQ_EQ(rxseq, ni->ni_rxseqs[tid]) &&
			!((type == IEEE80211_FC0_TYPE_MGT) &&
				(subtype == IEEE80211_FC0_SUBTYPE_AUTH)) &&
			!((ic->ic_flags_qtn & IEEE80211_QTN_BGSCAN)
				&& (type == IEEE80211_FC0_TYPE_MGT)
				&& (subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP ||
				subtype == IEEE80211_FC0_SUBTYPE_BEACON))) {
			/* duplicate, discard */
			IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_INPUT,
				bssid, "duplicate",
				"seqno <%u,%u> fragno <%u,%u> tid %u",
				rxseq >> IEEE80211_SEQ_SEQ_SHIFT,
				ni->ni_rxseqs[tid] >>
					IEEE80211_SEQ_SEQ_SHIFT,
				rxseq & IEEE80211_SEQ_FRAG_MASK,
				ni->ni_rxseqs[tid] &
					IEEE80211_SEQ_FRAG_MASK,
				tid);
			vap->iv_stats.is_rx_dup++;
			IEEE80211_NODE_STAT(ni, rx_dup);
			goto out;
		}
		ni->ni_rxseqs[tid] = rxseq;
	}

	*node = ni;
	if (node_reference_held)
		ieee80211_free_node(ni);

	return 1;

err:
	vap->iv_devstats.rx_errors++;
out:
	if (node_reference_held)
		ieee80211_free_node(ni);

	dev_kfree_skb(skb);

	return 0;

#undef HAS_SEQ
}

static int
ieee80211_input_frame_process(struct ieee80211_node *ni,
	struct sk_buff *skb, int rssi, uint32_t rstamp)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct net_device *dev = vap->iv_dev;
	struct ieee80211_frame *wh = (struct ieee80211_frame *)skb->data;;
	uint8_t dir = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;
	uint8_t type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
	uint8_t subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
	struct qtn_wds_ext_event_data extender_event_data;
	struct ieee80211_key *key;
	struct ether_header *eh;
	struct llc *llc;
	uint8_t *bssid;
	int hdrspace;
	uint8_t is_prot = wh->i_fc[1] & IEEE80211_FC1_PROT;
	uint8_t more_frag;
	uint32_t fragno;

	switch (type) {
	case IEEE80211_FC0_TYPE_DATA:
		hdrspace = ieee80211_hdrspace(ic, wh);
		if (skb->len < hdrspace) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
				wh, "data", "too short: len %u, expecting %u",
				skb->len, hdrspace);
			vap->iv_stats.is_rx_tooshort++;
			vap->iv_stats.is_rx_tooshort_cnt++;
			goto out;
		}

		switch (vap->iv_opmode) {
		case IEEE80211_M_STA:
			if ((dir != IEEE80211_FC1_DIR_FROMDS) &&
					(dir != IEEE80211_FC1_DIR_NODS) &&
					(!((vap->iv_flags_ext & IEEE80211_FEXT_WDS) &&
					(dir == IEEE80211_FC1_DIR_DSTODS)))) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "data", "invalid dir 0x%x", dir);
				vap->iv_stats.is_rx_wrongdir++;
				goto out;
			}

			if ((dev->flags & IFF_MULTICAST) &&
					IEEE80211_IS_MULTICAST(wh->i_addr1)) {
				if (IEEE80211_ADDR_EQ(wh->i_addr3, vap->iv_myaddr)) {
					/*
					 * In IEEE802.11 network, multicast packet
					 * sent from me is broadcasted from AP.
					 * It should be silently discarded for
					 * SIMPLEX interface.
					 *
					 * NB: Linux has no IFF_ flag to indicate
					 *     if an interface is SIMPLEX or not;
					 *     so we always assume it to be true.
					 */
					IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
						wh, NULL, "%s", "multicast echo");
					vap->iv_stats.is_rx_mcastecho++;
					goto out;
				}

				/*
				 * if it is broadcast by me on behalf of
				 * a station behind me, drop it.
				 */
				if (vap->iv_flags_ext & IEEE80211_FEXT_WDS) {
					struct ieee80211_node_table *nt;
					struct ieee80211_node *ni_wds;
					nt = &ic->ic_sta;
					ni_wds = ieee80211_find_wds_node(nt, wh->i_addr3);
					if (ni_wds) {
						ieee80211_free_node(ni_wds);
						IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
							wh, NULL, "%s",	"multicast echo "
							"originated from node behind me");
						vap->iv_stats.is_rx_mcastecho++;
						goto out;
					}
				}
			}
			break;
		case IEEE80211_M_IBSS:
		case IEEE80211_M_AHDEMO:
			if (dir != IEEE80211_FC1_DIR_NODS) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "data", "invalid dir 0x%x", dir);
				vap->iv_stats.is_rx_wrongdir++;
				goto out;
			}
			break;
		case IEEE80211_M_HOSTAP:
			/*
			 * FIXME - QOS Null check added because Quantenna image
			 * currently doesn't set the to/from DS bits.
			 */
			if ((dir != IEEE80211_FC1_DIR_TODS) &&
			    (dir != IEEE80211_FC1_DIR_DSTODS) &&
			    (subtype != IEEE80211_FC0_SUBTYPE_QOS_NULL)) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "data", "invalid dir 0x%x", dir);
				vap->iv_stats.is_rx_wrongdir++;
				goto out;
			}

			/* check if source STA is associated */
			if (ni == vap->iv_bss) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "data", "%s", "unknown src");

				/* NB: caller deals with reference */
				if (vap->iv_state == IEEE80211_S_RUN) {
					if ((dir == IEEE80211_FC1_DIR_DSTODS) &&
						(IEEE80211_IS_MULTICAST(wh->i_addr1))) {
						/*
						 * Some 3rd party wds ap sends wds pkts
						 * with receiver addr as bcast/mcast which
						 * will be received by our ap and lead to
						 * a lot of deauth. But they just ignore
						 * our deauth frame. To avoid too much
						 *  deauth messages, We can safely ignore them.
						 */
						IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
							wh, "data", "%s", "mcast wds pkt");
					} else {
						ieee80211_send_error(ni, wh->i_addr2,
							IEEE80211_FC0_SUBTYPE_DEAUTH,
							IEEE80211_REASON_NOT_AUTHED);
					}
				}
				vap->iv_stats.is_rx_notassoc++;
				goto err;
			}

			if (ni->ni_associd == 0) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "data", "%s", "unassoc src");
				IEEE80211_SEND_MGMT(ni,
					IEEE80211_FC0_SUBTYPE_DISASSOC,
					IEEE80211_REASON_NOT_ASSOCED);
				vap->iv_stats.is_rx_notassoc++;
				goto err;
			}

			/*
			 * If we're a 4 address packet, make sure we have an entry in
			 * the node table for the packet source address (addr4).
			 * If not, add one.
			 */
			if (dir == IEEE80211_FC1_DIR_DSTODS) {
				struct ieee80211_node_table *nt;
				struct ieee80211_frame_addr4 *wh4;
				struct ieee80211_node *ni_wds;
				if (!(vap->iv_flags_ext & IEEE80211_FEXT_WDS)) {
					IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
						wh, "data", "%s", "4 addr not allowed");
					goto err;
				}

				wh4 = (struct ieee80211_frame_addr4 *)skb->data;
				nt = &ic->ic_sta;
				ni_wds = ieee80211_find_wds_node(nt, wh4->i_addr4);

				/* Last call increments ref count if !NULL */
				if ((ni_wds != NULL) && (ni_wds != ni)) {
					/*
					 * node with source address (addr4) moved
					 * to another WDS capable station.
					 */
					 (void) ieee80211_remove_wds_addr(nt, wh4->i_addr4);
					 ieee80211_add_wds_addr(nt, ni, wh4->i_addr4, 0);
				}

				if (ni_wds == NULL)
					ieee80211_add_wds_addr(nt, ni, wh4->i_addr4, 0);
				else
					ieee80211_free_node(ni_wds);
			}

			/*
			 * Check for power save state change.
			 */
			if (!(ni->ni_flags & IEEE80211_NODE_UAPSD)) {
				if ((wh->i_fc[1] & IEEE80211_FC1_PWR_MGT) ^
						(ni->ni_flags & IEEE80211_NODE_PWR_MGT))
					ieee80211_node_pwrsave(ni,
						wh->i_fc[1] & IEEE80211_FC1_PWR_MGT);
			} else if (ni->ni_flags & IEEE80211_NODE_PS_CHANGED) {
				int pwr_save_changed = 0;
				IEEE80211_LOCK_IRQ(ic);
				if ((*(__le16 *)(&wh->i_seq[0])) == ni->ni_pschangeseq) {
					ni->ni_flags &= ~IEEE80211_NODE_PS_CHANGED;
					pwr_save_changed = 1;
				}
				IEEE80211_UNLOCK_IRQ(ic);
				if (pwr_save_changed)
					ieee80211_node_pwrsave(ni,
						wh->i_fc[1] & IEEE80211_FC1_PWR_MGT);
			}
			break;
		case IEEE80211_M_WDS:
			if (dir != IEEE80211_FC1_DIR_DSTODS) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "data", "invalid dir 0x%x", dir);
				vap->iv_stats.is_rx_wrongdir++;
				goto out;
			}
			break;
		default:
			/* XXX here to keep compiler happy */
			goto out;
		}

		/*
		 * Handle privacy requirements.  Note that we
		 * must not be preempted from here until after
		 * we (potentially) call ieee80211_crypto_demic;
		 * otherwise we may violate assumptions in the
		 * crypto cipher modules used to do delayed update
		 * of replay sequence numbers.
		 */
		if (wh->i_fc[1] & IEEE80211_FC1_PROT) {
			if ((vap->iv_flags & IEEE80211_F_PRIVACY) == 0) {
				/*
				 * Discard encrypted frames when privacy is off.
				 */
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "WEP", "%s", "PRIVACY off");
				vap->iv_stats.is_rx_noprivacy++;
				IEEE80211_NODE_STAT(ni, rx_noprivacy);
				goto out;
			}

			key = ieee80211_crypto_decap(ni, skb, hdrspace);
			if (key == NULL) {
				/* NB: stats+msgs handled in crypto_decap */
				IEEE80211_NODE_STAT(ni, rx_wepfail);
				/*
				 * FIXME: This MUST be re-enabled - it could present
				 * a security hole.
				 * Needs more thought.
				 *
				 * RK-2009-11-24: this was commented out to allow
				 * WPA2 AES fragments to pass through the slow
				 * driver path.
				 */
				 // goto out;
			}
			wh = (struct ieee80211_frame *)skb->data;
			wh->i_fc[1] &= ~IEEE80211_FC1_PROT;
		} else {
			key = NULL;
		}

		/*
		 * Next up, any fragmentation.
		 */

		more_frag = wh->i_fc[1] & IEEE80211_FC1_MORE_FRAG;
		fragno = le16_to_cpu(get_unaligned((__le16 *)wh->i_seq)) & IEEE80211_SEQ_FRAG_MASK;
		if (IEEE80211_ADDR_EQ(wh->i_addr1, vap->iv_dev->broadcast)) {
			if (unlikely(more_frag || fragno)) {

				IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_DEBUG,
					"drop broadcast packet with fragment more=%d,fno=%x",
					more_frag, fragno);
				goto out;
			}
		}

		if (!IEEE80211_IS_MULTICAST(wh->i_addr1)) {
			skb = ieee80211_defrag(ni, skb, hdrspace, is_prot);
			if (skb == NULL) {
				/* Fragment dropped or frame not complete yet */
				goto out;
			}
		}

		/*
		 * Next strip any MSDU crypto bits.
		 */
		if (key != NULL &&
				!ieee80211_crypto_demic(vap, key, skb, hdrspace)) {
			IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_INPUT,
				ni->ni_macaddr, "data", "%s", "demic error");
			IEEE80211_NODE_STAT(ni, rx_demicfail);
			goto out;
		}

		/* TDLS data encapsulated management frame */
		llc = (struct llc *)(skb->data + hdrspace);
		ieee80211_tdls_mailbox_path_check(ni, skb, llc, rssi,
					hdrspace + LLC_SNAPFRAMELEN);

		/*
		 * Finally, strip the 802.11 header.
		 */
		wh = NULL;		/* no longer valid, catch any uses */
		skb = ieee80211_decap(vap, skb, hdrspace);
		if (skb == NULL) {
			/* don't count Null data frames as errors */
			if (subtype == IEEE80211_FC0_SUBTYPE_NODATA)
				goto out;

			IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_INPUT,
				ni->ni_macaddr, "data", "%s", "decap error");
			vap->iv_stats.is_rx_decap++;
			IEEE80211_NODE_STAT(ni, rx_decap);
			goto err;
		}
		eh = (struct ether_header *) skb->data;

		if (!accept_data_frame(vap, ni, key, skb, eh))
			goto out;

		vap->iv_devstats.rx_packets++;
		vap->iv_devstats.rx_bytes += skb->len;
		IEEE80211_NODE_STAT(ni, rx_data);
		IEEE80211_NODE_STAT_ADD(ni, rx_bytes, skb->len);
		ic->ic_lastdata = jiffies;

		/*
		 * If sub type is NULL DATA or QOS NULL DATA,
		 * don't send to linux protocol stack
		 */
		if ((subtype == IEEE80211_FC0_SUBTYPE_NODATA) ||
				(subtype == IEEE80211_FC0_SUBTYPE_QOS_NULL)) {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_INPUT,
					"%s: NULL or QOS NULL DATA: don't deliver"
					" to linux protocol stack\n", __func__);
			goto out;
		}

		ieee80211_deliver_data(ni, skb);

		return IEEE80211_FC0_TYPE_DATA;

	case IEEE80211_FC0_TYPE_MGT:
		/* Only accept action frames and peer beacons for WDS */
		if (vap->iv_opmode == IEEE80211_M_WDS &&
				subtype != IEEE80211_FC0_SUBTYPE_ACTION &&
#ifdef ARTSMNG_SUPPORT
				subtype != IEEE80211_FC0_SUBTYPE_AUTH &&
#endif /* ARTSMNG_SUPPORT */
				subtype != IEEE80211_FC0_SUBTYPE_BEACON) {
			struct ieee80211vap *pri_vap = ieee80211_get_primary_vap(ic, 0);
			if ((ic->ic_extender_role == IEEE80211_EXTENDER_ROLE_MBS) && pri_vap &&
					ieee80211_extender_peer_lost(vap, type, subtype, wh) &&
					ieee80211_extender_find_peer_wds_info(ic, wh->i_addr2)) {
				IEEE80211_EXTENDER_DPRINTF(vap, IEEE80211_EXTENDER_MSG_WARN,
						"QHop: unexpected frame 0x%x from peer %pM\n",
						subtype, wh->i_addr2);
				extender_event_data_prepare(ic, NULL,
						&extender_event_data,
						WDS_EXT_LINK_STATUS_UPDATE,
						wh->i_addr2);

				ieee80211_extender_send_event(pri_vap, &extender_event_data, NULL);
				ieee80211_extender_remove_peer_wds_info(ic, wh->i_addr2);
			}
			vap->iv_stats.is_rx_mgtdiscard++;
			goto out;
		}

		bssid = wh->i_addr3;
		if ((vap->iv_opmode == IEEE80211_M_HOSTAP) &&
				!IEEE80211_ADDR_EQ(bssid, vap->iv_myaddr) &&
				!IEEE80211_ADDR_EQ(bssid, dev->broadcast) &&
				qtn_is_csa_action_frame(wh)) {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_INPUT,
				"%s: Drop the CSA action frame from other BSS\n", __func__);
			vap->iv_stats.is_rx_mgtdiscard++;
			goto out;
		}

		if (IEEE80211_VAP_WDS_IS_MBS(vap) &&
				IEEE80211_ADDR_EQ(wh->i_addr1, dev->broadcast) &&
				qtn_is_csa_action_frame(wh)) {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_INPUT,
				"%s: MBS drops the broadcast CSA action frame from other BSS\n",
				__func__);
			vap->iv_stats.is_rx_mgtdiscard++;
			goto out;
		}

		IEEE80211_NODE_STAT(ni, rx_mgmt);

		if (dir != IEEE80211_FC1_DIR_NODS) {
			vap->iv_stats.is_rx_wrongdir++;
			goto err;
		}

		if (skb->len < sizeof(struct ieee80211_frame)) {
			IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_INPUT,
				ni->ni_macaddr, "mgt", "too short: len %u",
				skb->len);
			vap->iv_stats.is_rx_tooshort++;
			vap->iv_stats.is_rx_tooshort_cnt++;
			goto out;
		}

#ifdef IEEE80211_DEBUG
		if ((ieee80211_msg_debug(vap) && doprint(vap, subtype)) ||
		    ieee80211_msg_dumppkts(vap)) {
			ieee80211_note(vap, "received %s from %s rssi %d\n",
				ieee80211_mgt_subtype_name[subtype >>
				IEEE80211_FC0_SUBTYPE_SHIFT],
				ether_sprintf(wh->i_addr2), rssi);
		}
#endif

		if (vap->iv_pmf) {
			if (ieee80211_input_pmf_should_drop(vap, ni, wh, skb, subtype, rssi))
				goto out;
		}

		if (wh->i_fc[1] & IEEE80211_FC1_PROT) {
			if (subtype != IEEE80211_FC0_SUBTYPE_AUTH) {
				/*
				 * Only shared key auth frames with a challenge
				 * should be encrypted, discard all others.
				 */
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, ieee80211_mgt_subtype_name[subtype >>
					IEEE80211_FC0_SUBTYPE_SHIFT],
					"%s", "WEP set but not permitted");
				vap->iv_stats.is_rx_mgtdiscard++; /* XXX */
				goto out;
			}

			if ((vap->iv_flags & IEEE80211_F_PRIVACY) == 0) {
				/*
				 * Discard encrypted frames when privacy is off.
				 */
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "mgt", "%s", "WEP set but PRIVACY off");
				vap->iv_stats.is_rx_noprivacy++;
				goto out;
			}
			hdrspace = ieee80211_hdrspace(ic, wh);
			key = ieee80211_crypto_decap(ni, skb, hdrspace);
			if (key == NULL) {
				/* NB: stats+msgs handled in crypto_decap */
				goto out;
			}
			wh = (struct ieee80211_frame *)skb->data;
			wh->i_fc[1] &= ~IEEE80211_FC1_PROT;
		}

		ic->ic_recv_mgmt(ni, skb, subtype, rssi, rstamp);

		goto out;

	case IEEE80211_FC0_TYPE_CTL: {
		u_int8_t reason;
		IEEE80211_NODE_STAT(ni, rx_ctrl);
		vap->iv_stats.is_rx_ctl++;
		if (vap->iv_opmode == IEEE80211_M_HOSTAP)
			if (subtype == IEEE80211_FC0_SUBTYPE_PS_POLL)
				ieee80211_recv_pspoll(ni, skb);

		/*if a sta receive a PS-POLL, a deauth should be sent*/
		if (vap->iv_opmode == IEEE80211_M_STA &&
		    subtype == IEEE80211_FC0_SUBTYPE_PS_POLL &&
		    vap->iv_state < IEEE80211_S_RUN) {
			if (vap->iv_state <= IEEE80211_S_AUTH) {
				reason = IEEE80211_REASON_NOT_AUTHED;
			} else {
				reason = IEEE80211_REASON_NOT_ASSOCED;
			}

			IEEE80211_DPRINTF(vap, IEEE80211_MSG_INPUT | IEEE80211_MSG_AUTH |
				IEEE80211_MSG_POWER,
				"%s: ps-poll in state %d - send deauth with reason %u\n",
				__func__, (reason == IEEE80211_REASON_NOT_AUTHED) ? 1 : 2,
				reason);
			vap->iv_stats.is_ps_unassoc++;
			if (IEEE80211_ADDR_EQ(vap->iv_bss->ni_bssid, wh->i_addr1))
				ieee80211_send_error(ni, wh->i_addr2,
						IEEE80211_FC0_SUBTYPE_DEAUTH, reason);
		}

		goto out;
	}

	default:
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
			wh, NULL, "bad frame type 0x%x", type);
		vap->iv_stats.is_rx_wrong_type++;
		break;
	}

err:
	vap->iv_devstats.rx_errors++;
out:
	if (skb != NULL)
		dev_kfree_skb(skb);

	return type;
}

/*
 * Process a received frame. The node associated with the sender
 * should be supplied.  If nothing was found in the node table then
 * the caller is assumed to supply a reference to ic_bss instead.
 * The RSSI and a timestamp are also supplied.  The RSSI data is used
 * during AP scanning to select a AP to associate with; it can have
 * any units so long as values have consistent units and higher values
 * mean ``better signal''.  The receive timestamp is currently not used
 * by the 802.11 layer.
 *
 * Context: softIRQ (tasklet)
 */
int
ieee80211_input(struct ieee80211_node *ni,
	struct sk_buff *skb, int rssi, u_int32_t rstamp)
{
	uint8_t type = -1;
	int ret;

	ret = ieee80211_input_frame_check(&ni, skb, rssi, rstamp);
	if (ret > 0)
		type = ieee80211_input_frame_process(ni, skb, rssi, rstamp);

	return type;

}
EXPORT_SYMBOL(ieee80211_input);

/*
 * Determines whether a frame should be accepted, based on information
 * about the frame's origin and encryption, and policy for this vap.
 */
static int accept_data_frame(struct ieee80211vap *vap,
			struct ieee80211_node *ni, struct ieee80211_key *key,
			struct sk_buff *skb, struct ether_header *eh)
{
#define IS_EAPOL(eh) ((eh)->ether_type == __constant_htons(ETH_P_PAE))
#define PAIRWISE_SET(vap) ((vap)->iv_nw_keys[0].wk_cipher != &ieee80211_cipher_none)
	if (IS_EAPOL(eh)) {
		struct net_device *dev = vap->iv_dev;
		int local_rcv = !compare_ether_addr(eh->ether_dhost, dev->dev_addr);

		if (unlikely(!local_rcv && !ieee80211_node_is_authorized(ni) &&
				vap->iv_opmode == IEEE80211_M_HOSTAP))
			goto invalid_eapol_frame;

		/* encrypted eapol is always OK */
		if (key)
			return 1;
		/* cleartext eapol is OK if we don't have pairwise keys yet */
		if (! PAIRWISE_SET(vap))
			return 1;
		/* cleartext eapol is OK if configured to allow it */
		if (! IEEE80211_VAP_DROPUNENC_EAPOL(vap))
			return 1;
		/* cleartext eapol is OK if other unencrypted is OK */
		if (! (vap->iv_flags & IEEE80211_F_DROPUNENC))
			return 1;
invalid_eapol_frame:
		/* not OK */
		IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_INPUT,
			eh->ether_shost, "data",
			"unauthorized port: ether type 0x%x len %u",
			ntohs(eh->ether_type), skb->len);
		vap->iv_stats.is_rx_unauth++;
		vap->iv_devstats.rx_errors++;
		IEEE80211_NODE_STAT(ni, rx_unauth);
		return 0;
	}

	if (!ieee80211_node_is_authorized(ni)) {
		/*
		* Deny any non-PAE frames received prior to
		* authorization.  For open/shared-key
		* authentication the port is mark authorized
		* after authentication completes.  For 802.1x
		* the port is not marked authorized by the
		* authenticator until the handshake has completed.
		*/
		IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_INPUT,
			eh->ether_shost, "data",
			"unauthorized port: ether type 0x%x len %u",
			ntohs(eh->ether_type), skb->len);
		vap->iv_stats.is_rx_unauth++;
		vap->iv_devstats.rx_errors++;
		IEEE80211_NODE_STAT(ni, rx_unauth);
		return 0;
	}

	return 1;

#undef IS_EAPOL
#undef PAIRWISE_SET
}

/*
 * Context: softIRQ (tasklet)
 */
int
ieee80211_input_all(struct ieee80211com *ic,
	struct sk_buff *skb, int rssi, u_int32_t rstamp)
{
	struct ieee80211vap *vap;
	int type = -1;
	struct sk_buff *skb1;
	struct ieee80211_node *ni;

	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
		if (vap->iv_opmode == IEEE80211_M_WDS) {
			/* Discard input from non-peer */
			continue;
		}

		/* Performance optimization: Do not deliver packets to currently down interfaces */
		if ((vap->iv_opmode == IEEE80211_M_HOSTAP) && (vap->iv_state == IEEE80211_S_INIT))
			continue;

		if (TAILQ_NEXT(vap, iv_next) != NULL) {
			skb1 = skb_copy(skb, GFP_ATOMIC);
			if (skb1 == NULL) {
				IEEE80211_DPRINTF(vap, IEEE80211_MSG_INPUT,
					"%s: SKB copy failed\n", __func__);
				continue;
			}
		} else {
			skb1 = skb;
			skb = NULL;
		}

		ni = vap->iv_bss;
		ieee80211_ref_node(ni);
		type = ieee80211_input(ni, skb1, rssi, rstamp);
		ieee80211_free_node(ni);
	}

	/* No more vaps, reclaim skb */
	if (skb != NULL)
		dev_kfree_skb(skb);

	return type;
}
EXPORT_SYMBOL(ieee80211_input_all);

void ieee80211_clear_frag(struct ieee80211_node *ni)
{
	KASSERT(ni != NULL, ("null node"));

	if (ni->ni_rxfrag != NULL) {
		dev_kfree_skb_any(ni->ni_rxfrag);
		ni->ni_rxfrag = NULL;
		ni->ni_rxfragstamp = 0;
		IEEE80211_DISCARD_MAC(ni->ni_vap, IEEE80211_MSG_DEBUG,
			ni->ni_macaddr, NULL, "%s", "drop fragments\n");
	}
}

/*
 * This function reassemble fragments using the skb of the 1st fragment,
 * if large enough. If not, a new skb is allocated to hold incoming
 * fragments.
 *
 * Fragments are copied at the end of the previous fragment.  A different
 * strategy could have been used, where a non-linear skb is allocated and
 * fragments attached to that skb.
 */
static struct sk_buff *
ieee80211_defrag(struct ieee80211_node *ni, struct sk_buff *skb, int hdrlen, uint8_t is_prot)
{
	struct ieee80211_frame *wh = (struct ieee80211_frame *) skb->data;
	u_int16_t rxseq, last_rxseq;
	u_int8_t fragno, last_fragno;
	u_int8_t more_frag = wh->i_fc[1] & IEEE80211_FC1_MORE_FRAG;
	u_int8_t is_frag;

	rxseq = le16_to_cpu(*(__le16 *)wh->i_seq) >> IEEE80211_SEQ_SEQ_SHIFT;
	fragno = le16_to_cpu(*(__le16 *)wh->i_seq) & IEEE80211_SEQ_FRAG_MASK;

	/* Quick way out, if there's nothing to defragment */
	if (!more_frag && fragno == 0 && ni->ni_rxfrag == NULL)
		return skb;

	ni->ni_stats.ns_rx_fragment_pkts++;

	is_frag = more_frag || fragno;
	if (is_frag && !is_prot && ni->ni_vap->iv_flags & IEEE80211_F_PRIVACY) {
		ieee80211_clear_frag(ni);
		IEEE80211_NODE_STAT(ni, rx_unencrypted);
		IEEE80211_NOTE(ni->ni_vap, IEEE80211_MSG_INPUT, ni, "%s", "rx_unencrypted packet");
		/* drop unencrypted fragment */
		dev_kfree_skb(skb);
		return NULL;
	}

	if (ni->ni_rxfrag != NULL &&
			time_after(jiffies, ni->ni_rxfragstamp + HZ))
		ieee80211_clear_frag(ni);

	/*
	 * Remove frag to ensure it doesn't get reaped by timer.
	 */
	if (ni->ni_table == NULL) {
		/*
		 * Should never happen.  If the node is orphaned (not in
		 * the table) then input packets should not reach here.
		 * Otherwise, a concurrent request that yanks the table
		 * should be blocked by other interlocking and/or by first
		 * shutting the driver down.  Regardless, be defensive
		 * here and just bail
		 */
		/* XXX need msg+stat */
		dev_kfree_skb(skb);
		return NULL;
	}

	/*
	 * Use this lock to make sure ni->ni_rxfrag is
	 * not freed by the timer process while we use it.
	 * XXX bogus
	 */
	IEEE80211_NODE_LOCK_IRQ(ni->ni_table);

	/*
	 * Update the time stamp.  As a side effect, it
	 * also makes sure that the timer will not change
	 * ni->ni_rxfrag for at least 1 second, or in
	 * other words, for the remaining of this function.
	 */
	ni->ni_rxfragstamp = jiffies;

	IEEE80211_NODE_UNLOCK_IRQ(ni->ni_table);

	/*
	 * Validate that fragment is in order and
	 * related to the previous ones.
	 */
	if (ni->ni_rxfrag) {
		struct ieee80211_frame *lwh;

		lwh = (struct ieee80211_frame *) ni->ni_rxfrag->data;
		last_rxseq = le16_to_cpu(*(__le16 *)lwh->i_seq) >>
			IEEE80211_SEQ_SEQ_SHIFT;
		last_fragno = le16_to_cpu(*(__le16 *)lwh->i_seq) &
			IEEE80211_SEQ_FRAG_MASK;
		IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_DEBUG,
				"lseq=%x,seq=%x,fno=%x,lfno=%x,prot=%d,lpn=%llx,pn=%llx,len=%d\n",
				last_rxseq, rxseq, fragno, last_fragno, is_prot,
				ni->ni_rxfrag->qtn_cb.pn, skb->qtn_cb.pn, skb->len);
		if (rxseq != last_rxseq
		    || fragno != last_fragno + 1
		    || (is_prot && (skb->qtn_cb.pn != ni->ni_rxfrag->qtn_cb.pn + 1))
		    || (!IEEE80211_ADDR_EQ(wh->i_addr1, lwh->i_addr1))
		    || (!IEEE80211_ADDR_EQ(wh->i_addr2, lwh->i_addr2))
		    || (ni->ni_rxfrag->end - ni->ni_rxfrag->tail <
			skb->len)) {
			/*
			 * Unrelated fragment or no space for it,
			 * clear current fragments
			 */
			dev_kfree_skb(ni->ni_rxfrag);
			ni->ni_rxfrag = NULL;
		}
	}

	/* If this is the first fragment */
	if (ni->ni_rxfrag == NULL && fragno == 0) {
		ni->ni_rxfrag = skb;
		/* If more frags are coming */
		if (more_frag) {
			if (skb_is_nonlinear(skb)) {
				/*
				 * We need a continous buffer to
				 * assemble fragments
				 */
				ni->ni_rxfrag = skb_copy(skb, GFP_ATOMIC);
				dev_kfree_skb(skb);
			}
			/*
			 * Check that we have enough space to hold
			 * incoming fragments
			 * 1. Don't assume MTU is the RX frame size limit.
			 * 2. Don't assume original packet starts from skb->head, in case
			 * kernel reserve some bytes at headroom.
			 */
			else if ((skb_end_pointer(skb) - skb->data) <
				 (IEEE80211_MAX_LEN  + hdrlen)) {
				ni->ni_rxfrag = skb_copy_expand(skb, 0,
					(IEEE80211_MAX_LEN + hdrlen - skb->len),
					GFP_ATOMIC);
				dev_kfree_skb(skb);
			}
		}
	} else {
		if (ni->ni_rxfrag) {
			struct ieee80211_frame *lwh = (struct ieee80211_frame *)
				ni->ni_rxfrag->data;

			/*
			 * We know we have enough space to copy,
			 * we've verified that before
			 */
			/* Copy current fragment at end of previous one */
			memcpy(skb_tail_pointer(ni->ni_rxfrag),
			       skb->data + hdrlen, skb->len - hdrlen);
			/* Update tail and length */
			skb_put(ni->ni_rxfrag, skb->len - hdrlen);
			/* Keep a copy of last sequence and fragno */
			*(__le16 *) lwh->i_seq = *(__le16 *) wh->i_seq;
			ni->ni_rxfrag->qtn_cb.pn = skb->qtn_cb.pn;
		}
		/* we're done with the fragment */
		dev_kfree_skb(skb);
	}

	if (more_frag) {
		/* More to come */
		skb = NULL;
	} else {
		/* Last fragment received, we're done! */
		skb = ni->ni_rxfrag;
		ni->ni_rxfrag = NULL;
	}
	return skb;
}

static void
ieee80211_deliver_data(struct ieee80211_node *ni, struct sk_buff *skb)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct net_device *dev = vap->iv_dev;
	struct ether_header *eh = (struct ether_header *) skb->data;

	if (unlikely(g_l2_ext_filter)) {
		if (!skb->ext_l2_filter && vap->iv_opmode == IEEE80211_M_HOSTAP) {
			if (!skb->dev)
				skb->dev = dev;

#ifdef USE_HEADERLEN_RESV
			skb->protocol = ath_eth_type_trans(skb, skb->dev);
#else
			skb->protocol = eth_type_trans(skb, skb->dev);
#endif
			if (!(skb->protocol == __constant_htons(ETH_P_PAE) &&
					IEEE80211_ADDR_EQ(eh->ether_dhost, vap->iv_myaddr))) {
				vap->iv_ic->ic_send_to_l2_ext_filter(vap, skb);
				return ;
			}
		}
	}

	/*
	 * perform as a bridge within the vap
	 * - intra-vap bridging only
	 */
	if (vap->iv_opmode == IEEE80211_M_HOSTAP &&
	    (vap->iv_flags & IEEE80211_F_NOBRIDGE) == 0) {
		struct sk_buff *skb1 = NULL;

		if (ETHER_IS_MULTICAST(eh->ether_dhost)) {
			skb1 = skb_copy(skb, GFP_ATOMIC);
		} else {
			/*
			 * Check if destination is associated with the
			 * same vap and authorized to receive traffic.
			 * Beware of traffic destined for the vap itself;
			 * sending it will not work; just let it be
			 * delivered normally.
			 */
			struct ieee80211_node *ni1 = ieee80211_find_node(
				&vap->iv_ic->ic_sta, eh->ether_dhost);
			if (ni1 != NULL) {
				if (ni1->ni_vap == vap &&
				    ieee80211_node_is_authorized(ni1) &&
				    ni1 != vap->iv_bss) {
					skb1 = skb;
					skb = NULL;
				}
				/* XXX statistic? */
				ieee80211_free_node(ni1);
			}
		}
		if (skb1 != NULL) {
			skb1->dev = dev;

			skb_reset_mac_header(skb1);
			skb_set_network_header(skb1, sizeof(struct ether_header));

			skb1->protocol = __constant_htons(ETH_P_802_2);
			/* XXX insert vlan tag before queue it? */
			dev_queue_xmit(skb1);
		}
	}

	if (skb != NULL) {
		if (!skb->dev)
			skb->dev = dev;

#ifdef USE_HEADERLEN_RESV
		skb->protocol = ath_eth_type_trans(skb, skb->dev);
#else
		skb->protocol = eth_type_trans(skb, skb->dev);
#endif
		if (ni->ni_vlan != 0 && vap->iv_vlgrp != NULL) {
			/* attach vlan tag */
			vlan_hwaccel_receive_skb(skb, vap->iv_vlgrp, ni->ni_vlan);
		} else {
			netif_rx(skb);
		}
		dev->last_rx = jiffies;
	}
}

static struct sk_buff *
ieee80211_decap(struct ieee80211vap *vap, struct sk_buff *skb, int hdrlen)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_qosframe_addr4 wh;	/* Max size address frames */
	struct ether_header *eh;
	struct llc *llc;
	__be16 ether_type = 0;

	memcpy(&wh, skb->data, hdrlen);	/* Only copy hdrlen over */
	llc = (struct llc *) skb_pull(skb, hdrlen);
	if (skb->len >= LLC_SNAPFRAMELEN &&
	    llc->llc_dsap == LLC_SNAP_LSAP && llc->llc_ssap == LLC_SNAP_LSAP &&
	    llc->llc_control == LLC_UI && llc->llc_snap.org_code[0] == 0 &&
	    llc->llc_snap.org_code[1] == 0 && llc->llc_snap.org_code[2] == 0) {
		ether_type = llc->llc_un.type_snap.ether_type;
		skb_pull(skb, LLC_SNAPFRAMELEN);
		llc = NULL;
	}
	eh = (struct ether_header *) skb_push(skb, sizeof(struct ether_header));
	switch (wh.i_fc[1] & IEEE80211_FC1_DIR_MASK) {
	case IEEE80211_FC1_DIR_NODS:
		IEEE80211_ADDR_COPY(eh->ether_dhost, wh.i_addr1);
		/*
		 * for TDLS Function, TDLS link with third-party station
		 * which is 3-address mode.
		 */
		ic->ic_bridge_set_dest_addr(skb, (void *)eh);
		IEEE80211_ADDR_COPY(eh->ether_shost, wh.i_addr2);
		break;
	case IEEE80211_FC1_DIR_TODS:
		IEEE80211_ADDR_COPY(eh->ether_dhost, wh.i_addr3);
		IEEE80211_ADDR_COPY(eh->ether_shost, wh.i_addr2);
		break;
	case IEEE80211_FC1_DIR_FROMDS:
		IEEE80211_ADDR_COPY(eh->ether_dhost, wh.i_addr1);
		ic->ic_bridge_set_dest_addr(skb, (void *)eh);
		IEEE80211_ADDR_COPY(eh->ether_shost, wh.i_addr3);
		break;
	case IEEE80211_FC1_DIR_DSTODS:
		IEEE80211_ADDR_COPY(eh->ether_dhost, wh.i_addr3);
		/*
		 * for TDLS Function, associate with third-party AP
		 * which is 3-address mode.
		 */
		if (IEEE80211_ADDR_EQ(wh.i_addr1, wh.i_addr3))
			ic->ic_bridge_set_dest_addr(skb, (void *)eh);
		IEEE80211_ADDR_COPY(eh->ether_shost, wh.i_addr4);
		break;
	}
	if (!ALIGNED_POINTER(skb->data + sizeof(*eh), u_int32_t)) {
		struct sk_buff *n;

		/* XXX does this always work? */
		n = skb_copy(skb, GFP_ATOMIC);
		dev_kfree_skb(skb);
		if (n == NULL)
			return NULL;
		skb = n;
		eh = (struct ether_header *) skb->data;
	}
	if (llc != NULL)
		eh->ether_type = htons(skb->len - sizeof(*eh));
	else
		eh->ether_type = ether_type;
	return skb;
}

int
ieee80211_parse_rates(struct ieee80211_node *ni,
	const u_int8_t *rates, const u_int8_t *xrates)
{
	u_int8_t nrates = rates[1];
	u_int8_t nxrates = 0;
	struct ieee80211_rateset *rs = &ni->ni_rates;
	struct ieee80211vap *vap = ni->ni_vap;

	memset(rs, 0, sizeof(*rs));

	if (nrates > IEEE80211_RATE_MAXSIZE) {
		nrates = IEEE80211_RATE_MAXSIZE;
		IEEE80211_NOTE(vap, IEEE80211_MSG_XRATE, ni,
			"rate set too large;"
			" only using %u of %u rates",
			nrates, rates[1]);
		vap->iv_stats.is_rx_rstoobig++;
	}
	memcpy(rs->rs_rates, rates + 2, nrates);

	if (nrates < IEEE80211_RATE_MAXSIZE && xrates != NULL) {
		/*
		 * Tack on 11g extended supported rate element.
		 */
		nxrates = xrates[1];
		if (nrates + nxrates > IEEE80211_RATE_MAXSIZE) {
			nxrates = IEEE80211_RATE_MAXSIZE - nrates;
			IEEE80211_NOTE(vap, IEEE80211_MSG_XRATE, ni,
				"extended rate set too large;"
				" only using %u of %u rates",
				nxrates, xrates[1]);
			vap->iv_stats.is_rx_rstoobig++;
		}
		memcpy(rs->rs_rates + nrates, xrates + 2, nxrates);
	}

	rs->rs_nrates = nrates + nxrates;
	rs->rs_legacy_nrates = nrates + nxrates;

	return 1;
}

/*
 * Install received rate set information in the node's state block.
 */
int
ieee80211_setup_rates(struct ieee80211_node *ni,
	const u_int8_t *rates, const u_int8_t *xrates, int flags)
{
	struct ieee80211_rateset *rs = &ni->ni_rates;
	struct ieee80211vap *vap = ni->ni_vap;
	u_int8_t nrates = rates[1];
	u_int8_t nxrates = 0;

	if (nrates > IEEE80211_RATE_MAXSIZE) {
		nrates = IEEE80211_RATE_MAXSIZE;
		IEEE80211_NOTE(vap, IEEE80211_MSG_XRATE, ni,
			"rate set too large; only using %u of %u rates", nrates, rates[1]);
		vap->iv_stats.is_rx_rstoobig++;
	}
	memset(rs, 0, sizeof(*rs));
	rs->rs_nrates = nrates;
	rs->rs_legacy_nrates = nrates;
	memcpy(rs->rs_rates, rates + 2, rs->rs_nrates);
	if (xrates != NULL && rs->rs_nrates < IEEE80211_RATE_MAXSIZE) {
		/*
		 * Tack on 11g extended supported rate element.
		 */
		nxrates = xrates[1];
		if (rs->rs_nrates + nxrates > IEEE80211_RATE_MAXSIZE) {
			nxrates = IEEE80211_RATE_MAXSIZE - rs->rs_nrates;
			IEEE80211_NOTE(vap, IEEE80211_MSG_XRATE, ni,
				"extended rate set too large; only using %u of %u rates",
				nxrates, xrates[1]);
			vap->iv_stats.is_rx_rstoobig++;
		}
		memcpy(rs->rs_rates + rs->rs_nrates, xrates + 2, nxrates);
		rs->rs_nrates += nxrates;
		rs->rs_legacy_nrates += nxrates;
	}
	return ieee80211_fix_rate(ni, flags);
}

static void
ieee80211_auth_open(struct ieee80211_node *ni, struct ieee80211_frame *wh,
	int rssi, u_int32_t rstamp, u_int16_t seq, u_int16_t status, int skip_auth_resp)
{
	struct ieee80211vap *vap = ni->ni_vap;
	int node_reference_held = 0;
	struct ieee80211_rsnparms *vap_rsn = &vap->iv_bss->ni_rsn;

	if (ni->ni_authmode == IEEE80211_AUTH_SHARED) {
		IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
			ni->ni_macaddr, "open auth",
			"bad sta auth mode %u", ni->ni_authmode);
		vap->iv_stats.is_rx_bad_auth++;	/* XXX maybe a unique error? */
		if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
			/*
			 * To send the frame to the requesting STA we have to create a node
			 * for the station that we're going to reject.
			 */
			if (ni == vap->iv_bss) {
				ni = ieee80211_tmp_node(vap, wh->i_addr2);
				if (ni == NULL) {
					return;
				}
				node_reference_held = 1;
			}
			vap->iv_state_flags &= ~IEEE80211_VAP_STATE_F_EXT_AUTH_FRAME_SENT;
			IEEE80211_SEND_MGMT(ni,	IEEE80211_FC0_SUBTYPE_AUTH,
				(seq + 1) | (IEEE80211_STATUS_ALG << 16));

			if (node_reference_held) {
				ieee80211_free_node(ni);
			}
			return;
		}
	}
	switch (vap->iv_opmode) {
	case IEEE80211_M_IBSS:
		if (vap->iv_state != IEEE80211_S_RUN ||
		    seq != IEEE80211_AUTH_OPEN_REQUEST) {
			vap->iv_stats.is_rx_bad_auth++;
			return;
		}
		ieee80211_new_state(vap, IEEE80211_S_AUTH,
			wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK);
		break;

	case IEEE80211_M_AHDEMO:
	case IEEE80211_M_WDS:
		/* should not come here */
		break;

	case IEEE80211_M_HOSTAP:
		if (vap->iv_state != IEEE80211_S_RUN ||
		    seq != IEEE80211_AUTH_OPEN_REQUEST) {
			vap->iv_stats.is_rx_bad_auth++;
			mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_AUTH_FAILS, 1);
			return;
		}
		/* always accept open authentication requests */
		if (ni == vap->iv_bss) {
			ni = ieee80211_dup_bss(vap, wh->i_addr2);
			if (ni == NULL) {
				mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_AUTH_FAILS, 1);
				return;
			}
			ni->ni_node_type = IEEE80211_NODE_TYPE_STA;
			node_reference_held = 1;
		}

		IEEE80211_NOTE(vap, IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH,
				ni, "open authentication: %s",
				vap_rsn->rsn_keymgmtset == RSN_ASE_OWE ? "send to app":"success");

		if ((vap_rsn->rsn_keymgmtset != RSN_ASE_OWE) && !skip_auth_resp) {
			vap->iv_state_flags &= ~IEEE80211_VAP_STATE_F_EXT_AUTH_FRAME_SENT;
			IEEE80211_SEND_MGMT(ni, IEEE80211_FC0_SUBTYPE_AUTH, seq + 1);
			mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_AUTH, 1);
		}

		if (node_reference_held)
			ieee80211_free_node(ni);

		break;
	case IEEE80211_M_STA:
		if (vap->iv_state != IEEE80211_S_AUTH ||
		    seq != IEEE80211_AUTH_OPEN_RESPONSE) {
			vap->iv_stats.is_rx_bad_auth++;
			return;
		}
		if (status != 0) {
			IEEE80211_NOTE(vap,
				IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH, ni,
				"open auth failed (reason %d)", status);
			vap->iv_stats.is_rx_auth_fail++;
			ieee80211_new_state(vap, IEEE80211_S_SCAN,
				IEEE80211_SCAN_FAIL_STATUS);
			ieee80211_notify_connect_failure(vap, ni->ni_macaddr, status);
		} else {
			if (vap->iv_state_flags & IEEE80211_VAP_STATE_F_EXT_AUTH_FRAME_SENT) {
				vap->iv_state_flags &= ~IEEE80211_VAP_STATE_F_EXT_AUTH_FRAME_SENT;
				ieee80211_new_state(vap, IEEE80211_S_AUTH, 0);
			} else {
				ieee80211_new_state(vap, IEEE80211_S_ASSOC, 0);
			}
		}
		break;
	case IEEE80211_M_MONITOR:
		break;
	}
}

/*
 * Send a management frame error response to the specified
 * station.  If ni is associated with the station then use
 * it; otherwise allocate a temporary node suitable for
 * transmitting the frame and then free the reference so
 * it will go away as soon as the frame has been transmitted.
 */
static void
ieee80211_send_error(struct ieee80211_node *ni,
	const u_int8_t *mac, int subtype, int arg)
{
	struct ieee80211vap *vap = ni->ni_vap;
	int node_reference_held = 0;

	if (ni == vap->iv_bss) {
		if (vap->iv_opmode == IEEE80211_M_STA) {
			ni = _ieee80211_tmp_node(vap, mac, mac);
		} else {
			ni = ieee80211_tmp_node(vap, mac);
		}
		if (ni == NULL) {
			return;
		}
		node_reference_held = 1;
	}

	if (subtype == IEEE80211_FC0_SUBTYPE_AUTH)
		vap->iv_state_flags &= ~IEEE80211_VAP_STATE_F_EXT_AUTH_FRAME_SENT;

	IEEE80211_SEND_MGMT(ni, subtype, arg);

	if (node_reference_held) {
		ieee80211_free_node(ni);
	}
}

static int
alloc_challenge(struct ieee80211_node *ni)
{
	if (ni->ni_challenge == NULL)
		MALLOC(ni->ni_challenge, u_int32_t*, IEEE80211_CHALLENGE_LEN,
			M_DEVBUF, M_NOWAIT);
	if (ni->ni_challenge == NULL) {
		IEEE80211_NOTE(ni->ni_vap,
			IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH, ni,
			"%s", "shared key challenge alloc failed");
		/* XXX statistic */
	}
	return (ni->ni_challenge != NULL);
}

/* XXX TODO: add statistics */
static void
ieee80211_auth_shared(struct ieee80211_node *ni, struct ieee80211_frame *wh,
	u_int8_t *frm, u_int8_t *efrm, int rssi, u_int32_t rstamp,
	u_int16_t seq, u_int16_t status)
{
	struct ieee80211vap *vap = ni->ni_vap;
	u_int8_t *challenge;
	int node_reference_held = 0;
	int estatus;

	/*
	 * NB: this can happen as we allow pre-shared key
	 * authentication to be enabled w/o wep being turned
	 * on so that configuration of these can be done
	 * in any order.  It may be better to enforce the
	 * ordering in which case this check would just be
	 * for sanity/consistency.
	 */
	estatus = 0;			/* NB: silence compiler */
	if ((vap->iv_flags & IEEE80211_F_PRIVACY) == 0) {
		IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
			ni->ni_macaddr, "shared key auth",
			"%s", " PRIVACY is disabled");
		estatus = IEEE80211_STATUS_ALG;
		goto bad;
	}
	/*
	 * Pre-shared key authentication is evil; accept
	 * it only if explicitly configured (it is supported
	 * mainly for compatibility with clients like OS X).
	 */
	if (ni->ni_authmode != IEEE80211_AUTH_AUTO &&
	    ni->ni_authmode != IEEE80211_AUTH_SHARED) {
		IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
			ni->ni_macaddr, "shared key auth",
			"bad sta auth mode %u", ni->ni_authmode);
		vap->iv_stats.is_rx_bad_auth++;	/* XXX maybe a unique error? */
		estatus = IEEE80211_STATUS_ALG;
		goto bad;
	}

	challenge = NULL;
	if (frm + 1 < efrm) {
		if ((frm[1] + 2) > (efrm - frm)) {
			IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
				ni->ni_macaddr, "shared key auth",
				"ie %d/%d too long",
				frm[0], (frm[1] + 2) - (efrm - frm));
			vap->iv_stats.is_rx_bad_auth++;
			estatus = IEEE80211_STATUS_CHALLENGE;
			goto bad;
		}
		if (*frm == IEEE80211_ELEMID_CHALLENGE)
			challenge = frm;
		frm += frm[1] + 2;
	}
	switch (seq) {
	case IEEE80211_AUTH_SHARED_CHALLENGE:
	case IEEE80211_AUTH_SHARED_RESPONSE:
		if (challenge == NULL) {
			IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
				ni->ni_macaddr, "shared key auth",
				"%s", "no challenge");
			vap->iv_stats.is_rx_bad_auth++;
			estatus = IEEE80211_STATUS_CHALLENGE;
			goto bad;
		}
		if (challenge[1] != IEEE80211_CHALLENGE_LEN) {
			IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
				ni->ni_macaddr, "shared key auth",
				"bad challenge len %d", challenge[1]);
			vap->iv_stats.is_rx_bad_auth++;
			estatus = IEEE80211_STATUS_CHALLENGE;
			goto bad;
		}
	default:
		break;
	}
	switch (vap->iv_opmode) {
	case IEEE80211_M_MONITOR:
	case IEEE80211_M_AHDEMO:
	case IEEE80211_M_IBSS:
	case IEEE80211_M_WDS:
		IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
			ni->ni_macaddr, "shared key auth",
			"bad operating mode %u", vap->iv_opmode);
		return;
	case IEEE80211_M_HOSTAP:
		if (vap->iv_state != IEEE80211_S_RUN) {
			IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
				ni->ni_macaddr, "shared key auth",
				"bad state %u", vap->iv_state);
			estatus = IEEE80211_STATUS_ALG;	/* XXX */
			goto bad;
		}

		switch (seq) {
		case IEEE80211_AUTH_SHARED_REQUEST:
			if (ni == vap->iv_bss) {
				ni = ieee80211_dup_bss(vap, wh->i_addr2);
				if (ni == NULL) {
					return;
				}
				ni->ni_node_type = IEEE80211_NODE_TYPE_STA;
				node_reference_held = 1;
			}
			ni->ni_rssi = rssi;
			ni->ni_rstamp = rstamp;
			ni->ni_last_rx = jiffies;
			if (!alloc_challenge(ni)) {
				/* NB: don't return error so they rexmit */
				if (node_reference_held) {
					ieee80211_free_node(ni);
				}
				return;
			}
			get_random_bytes(ni->ni_challenge,
				IEEE80211_CHALLENGE_LEN);
			IEEE80211_NOTE(vap,
				IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH, ni,
				"shared key %sauth request", node_reference_held ? "" : "re");
			break;
		case IEEE80211_AUTH_SHARED_RESPONSE:
			if (ni == vap->iv_bss) {
				IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
					ni->ni_macaddr, "shared key response",
					"%s", "unknown station");
				/* NB: don't send a response */
				return;
			}
			if (ni->ni_challenge == NULL) {
				IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
					ni->ni_macaddr, "shared key response",
					"%s", "no challenge recorded");
				vap->iv_stats.is_rx_bad_auth++;
				estatus = IEEE80211_STATUS_CHALLENGE;
				goto bad;
			}
			if (memcmp(ni->ni_challenge, &challenge[2],
			    challenge[1]) != 0) {
				IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
					ni->ni_macaddr, "shared key response",
					"%s", "challenge mismatch");
				vap->iv_stats.is_rx_auth_fail++;
				estatus = IEEE80211_STATUS_CHALLENGE;
				goto bad;
			}
			IEEE80211_NOTE(vap,
				IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH, ni,
				"station authenticated (%s)", "shared key");
			ieee80211_node_authorize(ni);
			break;
		default:
			IEEE80211_DISCARD_MAC(vap, IEEE80211_MSG_AUTH,
				ni->ni_macaddr, "shared key auth",
				"bad seq %d", seq);
			vap->iv_stats.is_rx_bad_auth++;
			estatus = IEEE80211_STATUS_SEQUENCE;
			goto bad;
		}

		vap->iv_state_flags &= ~IEEE80211_VAP_STATE_F_EXT_AUTH_FRAME_SENT;
		IEEE80211_SEND_MGMT(ni, IEEE80211_FC0_SUBTYPE_AUTH, seq + 1);

		if (node_reference_held) {
			ieee80211_free_node(ni);
		}

		break;

	case IEEE80211_M_STA:
		if (vap->iv_state != IEEE80211_S_AUTH)
			return;
		switch (seq) {
		case IEEE80211_AUTH_SHARED_PASS:
			if (ni->ni_challenge != NULL) {
				FREE(ni->ni_challenge, M_DEVBUF);
				ni->ni_challenge = NULL;
			}
			if (status != 0) {
				IEEE80211_NOTE_MAC(vap,
					IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH,
					ieee80211_getbssid(vap, wh),
					"shared key auth failed (reason %d)",
					status);
				vap->iv_stats.is_rx_auth_fail++;
				/* XXX IEEE80211_SCAN_FAIL_STATUS */
				estatus = status;
				goto bad;
			}
			ieee80211_new_state(vap, IEEE80211_S_ASSOC, 0);
			break;
		case IEEE80211_AUTH_SHARED_CHALLENGE:
			if (!alloc_challenge(ni)) {
				estatus = IEEE80211_STATUS_OTHER;
				goto bad;
			}
			/* XXX could optimize by passing recvd challenge */
			memcpy(ni->ni_challenge, &challenge[2], challenge[1]);
			vap->iv_state_flags &= ~IEEE80211_VAP_STATE_F_EXT_AUTH_FRAME_SENT;
			IEEE80211_SEND_MGMT(ni,
				IEEE80211_FC0_SUBTYPE_AUTH, seq + 1);
			break;
		default:
			IEEE80211_DISCARD(vap, IEEE80211_MSG_AUTH,
				wh, "shared key auth", "bad seq %d", seq);
			vap->iv_stats.is_rx_bad_auth++;
			estatus = IEEE80211_STATUS_SEQUENCE;
			goto bad;
		}
		break;
	}
	if(vap->iv_opmode == IEEE80211_M_HOSTAP) {
		mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_AUTH, 1);
	}
	return;
bad:
	/*
	 * Send an error response; but only when operating as an AP.
	 */
	if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
		/* XXX hack to workaround calling convention */
		ieee80211_send_error(ni, wh->i_addr2,
			IEEE80211_FC0_SUBTYPE_AUTH,
			(seq + 1) | (estatus<<16));
		mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_AUTH_FAILS, 1);

	} else if (vap->iv_opmode == IEEE80211_M_STA) {
		/*
		 * Kick the state machine.  This short-circuits
		 * using the mgt frame timeout to trigger the
		 * state transition.
		 */
		if (vap->iv_state == IEEE80211_S_AUTH) {
			ieee80211_new_state(vap, IEEE80211_S_SCAN, 0);
			ieee80211_notify_connect_failure(vap, ni->ni_macaddr, estatus);
		}
	}
}

static int
ieee80211_verify_length(struct ieee80211vap *vap, int len, int minlen,
		struct ieee80211_frame *wh, int subtype)
{
	if (len < minlen) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_ELEMID,
				wh, ieee80211_mgt_subtype_name[subtype >>
				IEEE80211_FC0_SUBTYPE_SHIFT],
				"%s", "ie too short");
		vap->iv_stats.is_rx_elem_toosmall++;
		return 1;
	}
	return 0;
}

#define	IEEE80211_VERIFY_TDLS_LENGTH(_len, _minlen) do {			\
		if ((_len) < (_minlen)) {					\
			IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS,		\
			IEEE80211_TDLS_MSG_DBG, "%s: ie too short", __func__);	\
			vap->iv_stats.is_rx_elem_toosmall++;			\
			return;							\
		}								\
} while (0)

static int ieee80211_rx_public_action_frame(struct ieee80211_frame *wh, struct sk_buff *skb,
						uint8_t type, uint8_t subtype)
{
	uint8_t *frm = (u_int8_t *)&wh[1];
	struct ieee80211_action *ia;

	if (!(type == IEEE80211_FC0_TYPE_MGT && subtype == IEEE80211_FC0_SUBTYPE_ACTION))
		return 0;

	ia = (struct ieee80211_action *) (void *)frm;

	if (ia->ia_category == IEEE80211_ACTION_CAT_PUBLIC)
		return 1;

	return 0;
}

#ifdef IEEE80211_DEBUG
static void
ieee80211_ssid_mismatch(struct ieee80211vap *vap, const char *tag,
	u_int8_t mac[IEEE80211_ADDR_LEN], u_int8_t *ssid)
{
	printf("[%s] discard %s frame, ssid mismatch: ",
		ether_sprintf(mac), tag);
	ieee80211_print_essid(ssid + 2, ssid[1]);
	printf("\n");
}
#endif

enum ieee80211_verify_ssid_action {
	IEEE80211_VERIFY_SSID_ACTION_NO = 0,
	IEEE80211_VERIFY_SSID_ACTION_RETURN = 1,
	IEEE80211_VERIFY_SSID_ACTION_NODE_DEL_AND_RETURN = 2
};

static int ieee80211_verify_ssid(struct ieee80211vap *vap,
		struct ieee80211_node *ni,
		struct ieee80211_frame *wh,
		u_int8_t *ssid,
		int subtype)
{
	if (ssid[1] != 0 &&
	    (ssid[1] != (vap->iv_bss)->ni_esslen ||
	    memcmp(ssid + 2, (vap->iv_bss)->ni_essid, ssid[1]) != 0)) {
#ifdef IEEE80211_DEBUG
		if (ieee80211_msg_input(vap) &&
		    subtype != IEEE80211_FC0_SUBTYPE_PROBE_REQ) {
			ieee80211_ssid_mismatch(vap,
			    ieee80211_mgt_subtype_name[subtype >>
				IEEE80211_FC0_SUBTYPE_SHIFT],
				wh->i_addr2, ssid);
		}
#endif
		vap->iv_stats.is_rx_ssidmismatch++;
		if ((ni != vap->iv_bss) && ((subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ) ||
			    (subtype == IEEE80211_FC0_SUBTYPE_REASSOC_REQ))) {
			return IEEE80211_VERIFY_SSID_ACTION_NODE_DEL_AND_RETURN;
		} else {
			return IEEE80211_VERIFY_SSID_ACTION_RETURN;
		}
	} else if ((ssid[1] == 0) && (vap->iv_flags & IEEE80211_F_HIDESSID) &&
			(subtype == IEEE80211_FC0_SUBTYPE_PROBE_REQ)) {
		return IEEE80211_VERIFY_SSID_ACTION_RETURN;
	}

	/* Reject empty ssid in association requests */
	if ((vap->iv_qtn_options & IEEE80211_QTN_NO_SSID_ASSOC_DISABLED) &&
	    ((subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ) ||
	    (subtype == IEEE80211_FC0_SUBTYPE_REASSOC_REQ)) &&
	    (ssid[1] == 0)) {
		return IEEE80211_VERIFY_SSID_ACTION_RETURN;
	}

	return IEEE80211_VERIFY_SSID_ACTION_NO;
}

/* unaligned little endian access */
#define LE_READ_2(p)					\
	((u_int16_t)					\
	 ((((const u_int8_t *)(p))[0]      ) |		\
	  (((const u_int8_t *)(p))[1] <<  8)))
#define LE_READ_3(p)					\
	((u_int32_t)					\
	 ((((const u_int8_t *)(p))[0]      ) |		\
	  (((const u_int8_t *)(p))[1] <<  8) |		\
	  (((const u_int8_t *)(p))[2] << 16) | 0))
#define LE_READ_4(p)					\
	((u_int32_t)					\
	 ((((const u_int8_t *)(p))[0]      ) |		\
	  (((const u_int8_t *)(p))[1] <<  8) |		\
	  (((const u_int8_t *)(p))[2] << 16) |		\
	  (((const u_int8_t *)(p))[3] << 24)))

#define BE_READ_2(p)					\
	((u_int16_t)					\
	 ((((const u_int8_t *)(p))[1]      ) |		\
	  (((const u_int8_t *)(p))[0] <<  8)))
#define BE_READ_4(p)					\
	((u_int32_t)					\
	 ((((const u_int8_t *)(p))[3]      ) |		\
	  (((const u_int8_t *)(p))[2] <<  8) |		\
	  (((const u_int8_t *)(p))[1] << 16) |		\
	  (((const u_int8_t *)(p))[0] << 24)))

static __inline int
iswpaoui(const u_int8_t *frm)
{
	return frm[1] > 3 && LE_READ_4(frm+2) == ((WPA_RSN_OUI_TYPE<<24)|WPA_OUI);
}

static __inline int
iswmeoui(const u_int8_t *frm)
{
	return frm[1] > 3 && LE_READ_4(frm+2) == ((WME_OUI_TYPE<<24)|WME_OUI);
}

static __inline int
iswmeparam(const u_int8_t *frm)
{
	return frm[1] > 5 && LE_READ_4(frm+2) == ((WME_OUI_TYPE<<24)|WME_OUI) &&
		frm[6] == WME_PARAM_OUI_SUBTYPE;
}

static __inline int
iswmeinfo(const u_int8_t *frm)
{
	return frm[1] > 5 && LE_READ_4(frm+2) == ((WME_OUI_TYPE<<24)|WME_OUI) &&
		frm[6] == WME_INFO_OUI_SUBTYPE;
}

static __inline int
iswscoui(const u_int8_t *frm)
{
	return frm[1] > 3 && LE_READ_4(frm+2) == ((WSC_OUI_TYPE<<24)|WPA_OUI);
}

static __inline int
isatherosoui(const u_int8_t *frm)
{
	return frm[1] > 3 && LE_READ_4(frm+2) == ((ATH_OUI_TYPE<<24)|ATH_OUI);
}

static __inline int
isqtnie(const u_int8_t *frm)
{
	return (frm[1] > 3 &&
		((LE_READ_4(frm+2) & 0x00ffffff) == QTN_OUI) &&
		((frm[5] == QTN_OUI_CFG)));
}

static __inline int
isosenie(const u_int8_t *frm)
{
	return (frm[1] > 3 &&
		(LE_READ_3(frm + 2) == WFA_OUI) &&
		((frm[5] == WFA_TYPE_OSEN)));
}

static __inline int
is_mbo_oce(const u_int8_t *frm)
{
	return (frm[1] > 3 &&
		(LE_READ_3(frm + 2) == WFA_OUI) &&
		((frm[5] == WFA_MBO_OCE)));
}

static inline int
is_wfa_transition_mode(const u_int8_t *frm)
{
	return (frm[1] > 3 &&
		(LE_READ_3(frm + 2) == WFA_OUI) &&
		((frm[5] == WFA_TYPE_OWE_TRANS)));
}

static __inline int
ismapie(const u_int8_t *frm)
{
	return (frm[1] > 3 &&
		(LE_READ_3(frm + 2) == WFA_OUI) &&
		((frm[5] == WFA_TYPE_MAP)));
}

static inline int
is_peer_mrvl( u_int8_t *rlnk, void *bcmie, void *rtkie, struct ieee80211_ie_qtn *qtnie,
                struct ieee80211_ie_vhtcap *vhtcap, struct ieee80211_node *ni)
{
        if (unlikely(!bcmie && !qtnie && !rlnk && !rtkie && !ieee80211_node_is_intel(ni) &&
                 (ni->ni_flags & IEEE80211_NODE_VHT) &&
                !IEEE80211_VHTCAP_GET_SU_BEAMFORMER((struct ieee80211_ie_vhtcap *)vhtcap) &&
                 IEEE80211_VHTCAP_GET_SU_BEAMFORMEE((struct ieee80211_ie_vhtcap *)vhtcap) &&
                (IEEE80211_VHTCAP_GET_BFSTSCAP((struct ieee80211_ie_vhtcap *)vhtcap) == IEEE80211_VHTCAP_RX_STS_4)) &&
                !IEEE80211_VHT_HAS_3SS(ni->ni_vhtcap.rxmcsmap)) {
                        return 1;
                }
                return 0;
}

#ifdef CONFIG_QVSP
static __inline int
isvspie(const u_int8_t *frm)
{
	return (frm[1] > 3 &&
		((LE_READ_4(frm+2) & 0x00ffffff) == QTN_OUI) &&
		((frm[5] == QTN_OUI_VSP_CTRL)));
}

static __inline int
isqtnwmeie(const uint8_t *frm)
{
	return (frm[1] > 3 &&
		((LE_READ_4(frm + 2) & 0x00ffffff) == QTN_OUI) &&
		((frm[5] == QTN_OUI_QWME)));
}
#endif

static __inline int
is_qtn_scs_oui(const u_int8_t *frm)
{
	return (frm[1] > 3 &&
		((LE_READ_4(frm+2) & 0x00ffffff) == QTN_OUI) &&
		((frm[5] == QTN_OUI_SCS)));
}

static __inline int
isbroadcomoui(const u_int8_t *frm)
{
	return (frm[1] > 3 && (LE_READ_4(frm+2) & 0x00ffffff) == BCM_OUI);
}

static __inline int
isbroadcomoui2(const u_int8_t *frm)
{
	return (frm[1] > 3 && (LE_READ_4(frm+2) & 0x00ffffff) == BCM_OUI_2);
}

static __inline int
isappleoui(const u_int8_t *frm)
{
	return (frm[1] > 3 && (LE_READ_4(frm+2) & 0x00ffffff) == APPLE_OUI);
}

static __inline int
isqtnpairoui(const u_int8_t *frm)
{
	return (frm[1] > 3 &&
		((LE_READ_4(frm+2) & 0x00ffffff) == QTN_OUI) &&
		(frm[5] == QTN_OUI_PAIRING));
}

static __inline int
is_qtn_oui_tdls_brmacs(const u_int8_t *frm)
{
	return (frm[1] > 3 &&
		((LE_READ_4(frm+2) & 0x00ffffff) == QTN_OUI) &&
		((frm[5] == QTN_OUI_TDLS_BRMACS)));
}

static __inline int
is_qtn_oui_tdls_sta_info(const u_int8_t *frm)
{
	return (frm[1] > 3 &&
		((LE_READ_4(frm+2) & 0x00ffffff) == QTN_OUI) &&
		((frm[5] == QTN_OUI_TDLS)));
}

static __inline int
isrlnkoui(const u_int8_t *frm)
{
	return (frm[1] > 3 &&
		((LE_READ_4(frm+2) & 0x00ffffff) == RLNK_OUI));
}

static __inline int
is_qtn_ext_role_oui(const u_int8_t *frm)
{
	return ((frm[1] > 3) &&
		((LE_READ_4(frm+2) & 0x00ffffff) == QTN_OUI) &&
		(frm[5] == QTN_OUI_EXTENDER_ROLE));
}

static __inline int
is_qtn_ext_bssid_oui(const u_int8_t *frm)
{
	return (frm[1] > 3 &&
		((LE_READ_4(frm+2) & 0x00ffffff) == QTN_OUI) &&
		(frm[5] == QTN_OUI_EXTENDER_BSSID));
}

static __inline int
is_qtn_ext_state_oui(const u_int8_t *frm)
{
	return (frm[1] > 3 &&
		((LE_READ_4(frm+2) & 0x00ffffff) == QTN_OUI) &&
		(frm[5] == QTN_OUI_EXTENDER_STATE));
}

static __inline int
isrealtekoui(const u_int8_t *frm)
{
	return (frm[1] > 3 &&
		((LE_READ_4(frm+2) & 0x00ffffff) == RTK_OUI));
}

static __inline int
isqtnmrespoui(const u_int8_t *frm)
{
	return (frm[0] == IEEE80211_ELEMID_VENDOR) &&
			(frm[1] >= 5) && (LE_READ_3(&frm[2]) == QTN_OUI) &&
			(frm[6] == QTN_OUI_RM_SPCIAL || frm[6] == QTN_OUI_RM_ALL);
}

static __inline int
isbrcmvhtoui(const u_int8_t *frm)
{
	return (frm[0] == IEEE80211_ELEMID_VENDOR) &&
			(frm[1] >= 5) && (LE_READ_3(&frm[2]) == BCM_OUI) &&
			(LE_READ_2(&frm[5]) == BCM_OUI_VHT_TYPE);
}

static __inline int
is_qtn_ocac_state_ie(const u_int8_t *frm)
{
	return (frm[0] == IEEE80211_ELEMID_VENDOR) &&
			(frm[1] == OCAC_STATE_IE_LEN) &&
			(LE_READ_3(&frm[2]) == QTN_OUI) &&
			(frm[5] == QTN_OUI_OCAC_STATE);
}

static __inline int
is_qtn_repeater_cascade(const uint8_t *frm)
{
	return (frm[0] == IEEE80211_ELEMID_VENDOR &&
			frm[1] == QTN_REPEATER_CASCADE_IE_LEN &&
			LE_READ_3(&frm[2]) == QTN_OUI &&
			frm[5] == QTN_OUI_REPEATER_CASCADE) ;
}

static __inline int
is_qtn_rp_info(const uint8_t *frm)
{
	return (frm[0] == IEEE80211_ELEMID_VENDOR &&
			frm[1] == QTN_RP_INFO_IE_LEN &&
			LE_READ_3(&frm[2]) == QTN_OUI &&
			frm[5] == QTN_OUI_RP_INFO);
}

/*
 * Convert a WPA cipher selector OUI to an internal
 * cipher algorithm.  Where appropriate we also
 * record any key length.
 */
static int
wpa_cipher(u_int8_t *sel, u_int8_t *keylen)
{
#define	WPA_SEL(x)	(((x) << 24) | WPA_OUI)
	u_int32_t w = LE_READ_4(sel);

	switch (w) {
	case WPA_SEL(WPA_CSE_NULL):
		return IEEE80211_CIPHER_NONE;
	case WPA_SEL(WPA_CSE_WEP40):
		if (keylen)
			*keylen = 40 / NBBY;
		return IEEE80211_CIPHER_WEP;
	case WPA_SEL(WPA_CSE_WEP104):
		if (keylen)
			*keylen = 104 / NBBY;
		return IEEE80211_CIPHER_WEP;
	case WPA_SEL(WPA_CSE_TKIP):
		return IEEE80211_CIPHER_TKIP;
	case WPA_SEL(WPA_CSE_CCMP):
		return IEEE80211_CIPHER_AES_CCM;
	}
	return 32;		/* NB: so 1<< is discarded */
#undef WPA_SEL
}

/*
 * Convert a WPA key management/authentication algorithm
 * to an internal code.
 */
static u_int32_t
wpa_keymgmt(u_int8_t *sel)
{
#define	WPA_SEL(x)	(((x)<<24)|WPA_OUI)
	u_int32_t w = LE_READ_4(sel);

	switch (w) {
	case WPA_SEL(WPA_ASE_8021X_UNSPEC):
		return WPA_KEY_MGMT_IEEE8021X;
	case WPA_SEL(WPA_ASE_8021X_PSK):
		return WPA_KEY_MGMT_PSK;
	default:
		return 0;
	}
	return 0;		/* NB: so is discarded */
#undef WPA_SEL
}

/*
 * Parse a WPA information element to collect parameters
 * and validate the parameters against what has been
 * configured for the system.
 */
static int
ieee80211_parse_wpa(struct ieee80211vap *vap, u_int8_t *frm,
	struct ieee80211_rsnparms *rsn_parm, const struct ieee80211_frame *wh)
{
	u_int8_t len = frm[1];
	u_int32_t w;
	int n;
	struct ieee80211com *ic = vap->iv_ic;

	/*
	 * Check the length once for fixed parts: OUI, type,
	 * version, mcast cipher, and 2 selector counts.
	 * Other, variable-length data, must be checked separately.
	 */
	if (!(vap->iv_flags & IEEE80211_F_WPA1)) {
		IEEE80211_DISCARD_IE(vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
			wh, "WPA", "vap not WPA, flags 0x%x", vap->iv_flags);
		return IEEE80211_REASON_IE_INVALID;
	}

	if (len < 14) {
		IEEE80211_DISCARD_IE(vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
			wh, "WPA", "too short, len %u", len);
		return IEEE80211_REASON_IE_INVALID;
	}
	frm += 6, len -= 4;		/* NB: len is payload only */
	/* NB: iswapoui already validated the OUI and type */
	w = LE_READ_2(frm);
	if (w != WPA_VERSION) {
		IEEE80211_DISCARD_IE(vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
			wh, "WPA", "bad version %u", w);
		return IEEE80211_REASON_IE_INVALID;
	}
	frm += 2;
	len -= 2;

	/* multicast/group cipher */
	w = wpa_cipher(frm, &rsn_parm->rsn_mcastkeylen);
	if (w != rsn_parm->rsn_mcastcipher) {
		IEEE80211_DISCARD_IE(vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
			wh, "WPA", "mcast cipher mismatch; got %u, expected %u",
			w, rsn_parm->rsn_mcastcipher);
		return IEEE80211_REASON_IE_INVALID;
	}
	if (!IEEE80211_IS_TKIP_ALLOWED(ic)) {
		if (w == IEEE80211_CIPHER_TKIP)
			return IEEE80211_REASON_STA_CIPHER_NOT_SUPP;
	}
	frm += 4;
	len -= 4;

	/* unicast ciphers */
	n = LE_READ_2(frm);
	frm += 2;
	len -= 2;
	if (len < n*4+2) {
		IEEE80211_DISCARD_IE(vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
			wh, "WPA", "ucast cipher data too short; len %u, n %u",
			len, n);
		return IEEE80211_REASON_IE_INVALID;
	}
	w = 0;
	for (; n > 0; n--) {
		w |= 1 << wpa_cipher(frm, &rsn_parm->rsn_ucastkeylen);
		frm += 4;
		len -= 4;
	}
	w &= rsn_parm->rsn_ucastcipherset;
	if (w == 0) {
		IEEE80211_DISCARD_IE(vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
			wh, "WPA", "%s", "ucast cipher set empty");
		return IEEE80211_REASON_IE_INVALID;
	}
	if (w & (1 << IEEE80211_CIPHER_TKIP)) {
		if (!IEEE80211_IS_TKIP_ALLOWED(ic))
			return IEEE80211_REASON_STA_CIPHER_NOT_SUPP;
		else
			rsn_parm->rsn_ucastcipher = IEEE80211_CIPHER_TKIP;
	} else {
		rsn_parm->rsn_ucastcipher = IEEE80211_CIPHER_AES_CCM;
	}

	/* key management algorithms */
	n = LE_READ_2(frm);
	frm += 2;
	len -= 2;
	if (len < n * 4) {
		IEEE80211_DISCARD_IE(vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
			wh, "WPA", "key mgmt alg data too short; len %u, n %u",
			len, n);
		return IEEE80211_REASON_IE_INVALID;
	}
	w = 0;
	for (; n > 0; n--) {
		w |= wpa_keymgmt(frm);
		frm += 4;
		len -= 4;
	}
	w &= rsn_parm->rsn_keymgmtset;
	if (w == 0) {
		IEEE80211_DISCARD_IE(vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
			wh, "WPA", "%s", "no acceptable key mgmt alg");
		return IEEE80211_REASON_IE_INVALID;
	}
	if (w & WPA_KEY_MGMT_IEEE8021X)
		rsn_parm->rsn_keymgmt = WPA_KEY_MGMT_IEEE8021X;
	else
		rsn_parm->rsn_keymgmt = WPA_KEY_MGMT_PSK;

	if (len > 2)		/* optional capabilities */
		rsn_parm->rsn_caps = LE_READ_2(frm);

	return 0;
}

/*
 * Convert an RSN cipher selector OUI to an internal
 * cipher algorithm.  Where appropriate we also
 * record any key length.
 */
static int
rsn_cipher(u_int8_t *sel, u_int8_t *keylen)
{
#define	RSN_SEL(x)	(((x) << 24) | RSN_OUI)
	u_int32_t w = LE_READ_4(sel);

	switch (w) {
	case RSN_SEL(RSN_CSE_NULL):
		return IEEE80211_CIPHER_NONE;
	case RSN_SEL(RSN_CSE_WEP40):
		if (keylen)
			*keylen = 40 / NBBY;
		return IEEE80211_CIPHER_WEP;
	case RSN_SEL(RSN_CSE_WEP104):
		if (keylen)
			*keylen = 104 / NBBY;
		return IEEE80211_CIPHER_WEP;
	case RSN_SEL(RSN_CSE_TKIP):
		return IEEE80211_CIPHER_TKIP;
	case RSN_SEL(RSN_CSE_CCMP):
		return IEEE80211_CIPHER_AES_CCM;
	case RSN_SEL(RSN_CSE_WRAP):
		return IEEE80211_CIPHER_AES_OCB;
	}
	return 32;		/* NB: so 1<< is discarded */
#undef RSN_SEL
}

/*
 * Convert an RSN key management/authentication algorithm
 * to an internal code.
 */
static int
rsn_keymgmt(u_int8_t *sel)
{
#define	RSN_SEL(x)	(((x) << 24) | RSN_OUI)
#define RSN_WFA_SEL(x)	(((x) << 24) | WFA_OUI)

	u_int32_t w = LE_READ_4(sel);

	switch (w) {
	case RSN_SEL(RSN_ASE_8021X_UNSPEC):
		return WPA_KEY_MGMT_IEEE8021X;
	case RSN_SEL(RSN_ASE_8021X_PSK):
		return WPA_KEY_MGMT_PSK;
	case RSN_SEL(RSN_ASE_FT_PSK):
		return WPA_KEY_MGMT_FT_PSK;
	case RSN_SEL(RSN_ASE_FT_8021X):
		return WPA_KEY_MGMT_FT_IEEE8021X;
	case RSN_SEL(RSN_ASE_8021X_SHA256):
		return WPA_KEY_MGMT_IEEE8021X_SHA256;
	case RSN_SEL(RSN_ASE_8021X_PSK_SHA256):
		return WPA_KEY_MGMT_PSK_SHA256;
	case RSN_SEL(RSN_ASE_NONE):
		return WPA_KEY_MGMT_NONE;
	case RSN_SEL(RSN_ASE_SAE):
		return WPA_KEY_MGMT_SAE;
	case RSN_SEL(RSN_ASE_OWE):
		return WPA_KEY_MGMT_OWE;
	case RSN_WFA_SEL(WFA_AKM_TYPE_DPP):
		return WPA_KEY_MGMT_DPP;
	}
	return 0;		/* NB: so is discarded */
#undef RSN_SEL
#undef RSN_WFA_SEL
}


/*
 * Parse a WPA/RSN information element to collect parameters
 * and populate the rsn parameters in struct
 */
int
ieee80211_get_rsn_from_ie(struct ieee80211vap *vap, u_int8_t *frm,
	struct ieee80211_rsnparms *rsn_parm)
{
	u_int8_t len = frm[1];
	u_int32_t w;
	int n;

	/*
	 * Check the length once for fixed parts:
	 * version, mcast cipher, and 2 selector counts.
	 * Other, variable-length data, must be checked separately.
	 */
	if (!(vap->iv_flags & IEEE80211_F_WPA2)) {
		printk( "vap not RSN, flags 0x%x\n", vap->iv_flags);
		return IEEE80211_REASON_IE_INVALID;
	}

	if (len < 10) {
		printk( "too short, len %u\n", len);
		return IEEE80211_REASON_IE_INVALID;
	}
	frm += 2;
	w = LE_READ_2(frm);
	if (w != RSN_VERSION) {
		printk( "bad version %u\n", w);
		return IEEE80211_REASON_IE_INVALID;
	}
	frm += 2;
	len -= 2;

	/* multicast/group cipher */
	w = rsn_cipher(frm, &rsn_parm->rsn_mcastkeylen);
	rsn_parm->rsn_mcastcipher = w;
	frm += 4;
	len -= 4;

	/* unicast ciphers */
	n = LE_READ_2(frm);
	frm += 2;
	len -= 2;
	if (len < n * 4 + 2) {
		printk("ucast cipher data too short; len %u, n %u\n",
			len, n);
		return IEEE80211_REASON_IE_INVALID;
	}
	w = 0;
	for (; n > 0; n--) {
		w |= 1 << rsn_cipher(frm, &rsn_parm->rsn_ucastkeylen);
		frm += 4;
		len -= 4;
	}

	if (w == 0) {
		printk( "%s\n", "ucast cipher set empty");
		return IEEE80211_REASON_IE_INVALID;
	}
	rsn_parm->rsn_ucastcipherset = w;
	if (w & (1<<IEEE80211_CIPHER_TKIP))
		rsn_parm->rsn_ucastcipher = IEEE80211_CIPHER_TKIP;
	else
		rsn_parm->rsn_ucastcipher = IEEE80211_CIPHER_AES_CCM;

	/* key management algorithms */
	n = LE_READ_2(frm);
	frm += 2;
	len -= 2;
	if (len < n * 4) {
		printk( "key mgmt alg data too short; len %u, n %u\n",
			len, n);
		return IEEE80211_REASON_IE_INVALID;
	}
	w = 0;
	for (; n > 0; n--) {
		w |= rsn_keymgmt(frm);
		frm += 4;
		len -= 4;
	}

	if (w == 0) {
		printk("%s\n", "no acceptable key mgmt alg");
		return IEEE80211_REASON_IE_INVALID;
	}
	rsn_parm->rsn_keymgmtset = w;
	if (w & WPA_KEY_MGMT_IEEE8021X)
		rsn_parm->rsn_keymgmt = RSN_ASE_8021X_UNSPEC;
	if (w & WPA_KEY_MGMT_PSK)
		rsn_parm->rsn_keymgmt = RSN_ASE_8021X_PSK;
	if (w & WPA_KEY_MGMT_FT_PSK)
		rsn_parm->rsn_keymgmt = RSN_ASE_FT_PSK;
	if (w & WPA_KEY_MGMT_FT_IEEE8021X)
		rsn_parm->rsn_keymgmt = RSN_ASE_FT_8021X;
	if (w & WPA_KEY_MGMT_SAE)
		rsn_parm->rsn_keymgmt = RSN_ASE_SAE;
	if (w & WPA_KEY_MGMT_OWE)
		rsn_parm->rsn_keymgmt = RSN_ASE_OWE;
	if (w & WPA_KEY_MGMT_DPP)
		rsn_parm->rsn_keymgmt = RSN_ASE_DPP;

	/* optional RSN capabilities */
	if (len >= 2)
		rsn_parm->rsn_caps = LE_READ_2(frm);
	/* XXXPMKID */
	return 0;
}

/*
 * Parse a WPA/RSN information element to collect parameters
 * and validate the parameters against what has been
 * configured for the system.
 */
static int
ieee80211_parse_rsn(struct ieee80211vap *vap, u_int8_t *frm,
	struct ieee80211_rsnparms *rsn_parm, const struct ieee80211_frame *wh)
{
	struct ieee80211com *ic = vap->iv_ic;
	u_int8_t len = frm[1];
	u_int32_t w;
	int n;

	/*
	 * Check the length once for fixed parts:
	 * version, mcast cipher, and 2 selector counts.
	 * Other, variable-length data, must be checked separately.
	 */
	if (!(vap->iv_flags & IEEE80211_F_WPA2)) {
		IEEE80211_DISCARD_IE(vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
			wh, "RSN", "vap not RSN, flags 0x%x", vap->iv_flags);
		return IEEE80211_REASON_IE_INVALID;
	}

	if (len < 10) {
		IEEE80211_DISCARD_IE(vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
			wh, "RSN", "too short, len %u", len);
		return IEEE80211_REASON_IE_INVALID;
	}
	frm += 2;
	w = LE_READ_2(frm);
	if (w != RSN_VERSION) {
		IEEE80211_DISCARD_IE(vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
			wh, "RSN", "bad version %u", w);
		return IEEE80211_REASON_IE_INVALID;
	}
	frm += 2;
	len -= 2;

	/* multicast/group cipher */
	w = rsn_cipher(frm, &rsn_parm->rsn_mcastkeylen);
	if (w != rsn_parm->rsn_mcastcipher) {
		IEEE80211_DISCARD_IE(vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
			wh, "RSN", "mcast cipher mismatch; got %u, expected %u",
			w, rsn_parm->rsn_mcastcipher);
		return IEEE80211_REASON_IE_INVALID;
	}
	if (!IEEE80211_IS_TKIP_ALLOWED(ic)) {
		if (w == IEEE80211_CIPHER_TKIP) {
			return IEEE80211_REASON_STA_CIPHER_NOT_SUPP;
		}
	}
	frm += 4;
	len -= 4;

	/* unicast ciphers */
	n = LE_READ_2(frm);
	frm += 2;
	len -= 2;
	if (len < n * 4 + 2) {
		IEEE80211_DISCARD_IE(vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
			wh, "RSN", "ucast cipher data too short; len %u, n %u",
			len, n);
		return IEEE80211_REASON_IE_INVALID;
	}
	w = 0;
	for (; n > 0; n--) {
		w |= 1 << rsn_cipher(frm, &rsn_parm->rsn_ucastkeylen);
		frm += 4;
		len -= 4;
	}

	w &= rsn_parm->rsn_ucastcipherset;
	if (w == 0) {
		IEEE80211_DISCARD_IE(vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
			wh, "RSN", "%s", "ucast cipher set empty");
		return IEEE80211_REASON_IE_INVALID;
	}
        if (w & (1 << IEEE80211_CIPHER_TKIP)) {
		if (!IEEE80211_IS_TKIP_ALLOWED(ic))
                        return IEEE80211_REASON_STA_CIPHER_NOT_SUPP;
                else
                        rsn_parm->rsn_ucastcipher = IEEE80211_CIPHER_TKIP;
        } else {
                rsn_parm->rsn_ucastcipher = IEEE80211_CIPHER_AES_CCM;
        }

	/* key management algorithms */
	n = LE_READ_2(frm);
	frm += 2;
	len -= 2;
	if (len < n * 4) {
		IEEE80211_DISCARD_IE(vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
			wh, "RSN", "key mgmt alg data too short; len %u, n %u",
			len, n);
		return IEEE80211_REASON_IE_INVALID;
	}
	w = 0;
	for (; n > 0; n--) {
		w |= rsn_keymgmt(frm);
		frm += 4;
		len -= 4;
	}

	w &= rsn_parm->rsn_keymgmtset;
	if (w == 0) {
		IEEE80211_DISCARD_IE(vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
			wh, "RSN", "%s", "no acceptable key mgmt alg");
		return IEEE80211_REASON_IE_INVALID;
	}

	if (w & WPA_KEY_MGMT_IEEE8021X)
		rsn_parm->rsn_keymgmt = RSN_ASE_8021X_UNSPEC;
	if (w & WPA_KEY_MGMT_PSK)
		rsn_parm->rsn_keymgmt = RSN_ASE_8021X_PSK;
	if (w & WPA_KEY_MGMT_FT_PSK)
		rsn_parm->rsn_keymgmt = RSN_ASE_FT_PSK;
	if (w & WPA_KEY_MGMT_FT_IEEE8021X)
		rsn_parm->rsn_keymgmt = RSN_ASE_FT_8021X;
	if (w & WPA_KEY_MGMT_SAE)
		rsn_parm->rsn_keymgmt = RSN_ASE_SAE;
	if (w & WPA_KEY_MGMT_OWE)
		rsn_parm->rsn_keymgmt = RSN_ASE_OWE;
	if (w & WPA_KEY_MGMT_DPP)
		rsn_parm->rsn_keymgmt = RSN_ASE_DPP;

	/* optional RSN capabilities */
	if (len >= 2) {
		rsn_parm->rsn_caps = LE_READ_2(frm);
		frm += 2;
		len -= 2;
	} else if (len == 1) {
		return IEEE80211_REASON_IE_INVALID;
	}

	/* PMKID */
	n = 0;
	if (len >= 2) {
		n = LE_READ_2(frm);
		frm += 2;
		len -= 2;
	} else if (len == 1) {
		return IEEE80211_REASON_IE_INVALID;
	}

	if (n) {
		if (len < n * 16) {
			IEEE80211_DISCARD_IE(vap,
					IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
					wh, "RSN", "PMKID data too short; len %u, n %u",
					len, n);
			return IEEE80211_REASON_IE_INVALID;
		}

		/* Skip PMK ID cache, no need for driver */
		for (; n > 0; n--) {
			frm += 16;
			len -= 16;
		}
	}

	return 0;
}


#define IEEE80211_OSEN_IE_HEAD_LEN		4
#define IEEE80211_OSEN_IE_SUITE_LEN		4
#define IEEE80211_OSEN_IE_SUITE_COUNT_LEN	2
#define IEEE80211_IE_HEAD_LEN			2
#define IEEE80211_OSEN_IE_RSN_CAPS_LEN		2
#define IEEE80211_OSEN_IE_MIN_LEN		(IEEE80211_OSEN_IE_HEAD_LEN + \
						IEEE80211_OSEN_IE_SUITE_LEN + \
						IEEE80211_OSEN_IE_SUITE_COUNT_LEN)

static int
ieee80211_parse_osen(struct ieee80211vap *vap, u_int8_t *frm,
		struct ieee80211_rsnparms *rsn_parm, const struct ieee80211_frame *wh)
{
	uint8_t len = frm[1];
	uint32_t w;
	int n;

	if (len < IEEE80211_OSEN_IE_MIN_LEN) {
		IEEE80211_DISCARD_IE(vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
			wh, "OSEN", "too short, len %u", len);
		return IEEE80211_REASON_IE_INVALID;
	}

	if (!vap->iv_osen) {
		IEEE80211_DISCARD_IE(vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
			wh, "OSEN", "%s", "vap not OSEN");
		return IEEE80211_REASON_IE_INVALID;
	}

	frm += IEEE80211_IE_HEAD_LEN + IEEE80211_OSEN_IE_HEAD_LEN;
	len -= IEEE80211_OSEN_IE_HEAD_LEN;

	w = LE_READ_4(frm);
	if (w != ((RSN_CSE_GROUP_NOT_ALLOW << 24) | RSN_OUI)) {
		IEEE80211_DISCARD_IE(vap,
				IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
				wh, "OSEN", "mcast cipher mismatch; got %u, expected %u",
				w, RSN_CSE_GROUP_NOT_ALLOW);
			return IEEE80211_REASON_IE_INVALID;
	}

	frm += IEEE80211_OSEN_IE_SUITE_LEN;
	len -= IEEE80211_OSEN_IE_SUITE_LEN;

	/* unicast ciphers */
	n = LE_READ_2(frm);
	frm += IEEE80211_OSEN_IE_SUITE_COUNT_LEN;
	len -= IEEE80211_OSEN_IE_SUITE_COUNT_LEN;
	if (len < n * IEEE80211_OSEN_IE_SUITE_LEN + IEEE80211_OSEN_IE_SUITE_COUNT_LEN) {
		IEEE80211_DISCARD_IE(vap,
				IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
				wh, "OSEN", "ucast cipher data too short; len %u, n %u",
				len, n);
		return IEEE80211_REASON_IE_INVALID;
	}
	w = 0;
	for (; n > 0; n--) {
		w |= 1 << rsn_cipher(frm, &rsn_parm->rsn_ucastkeylen);
		frm += IEEE80211_OSEN_IE_SUITE_LEN;
		len -= IEEE80211_OSEN_IE_SUITE_LEN;
	}

	w &= rsn_parm->rsn_ucastcipherset;
	if (w == 0) {
		IEEE80211_DISCARD_IE(vap,
				IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
				wh, "OSEN", "%s", "ucast cipher set empty");
		return IEEE80211_REASON_IE_INVALID;
	}
	if (w & (1 << IEEE80211_CIPHER_TKIP))
		rsn_parm->rsn_ucastcipher = IEEE80211_CIPHER_TKIP;
	else
		rsn_parm->rsn_ucastcipher = IEEE80211_CIPHER_AES_CCM;

	/* key management algorithms */
	n = LE_READ_2(frm);
	frm += IEEE80211_OSEN_IE_SUITE_COUNT_LEN;
	len -= IEEE80211_OSEN_IE_SUITE_COUNT_LEN;
	if (len < n * IEEE80211_OSEN_IE_SUITE_LEN) {
		IEEE80211_DISCARD_IE(vap,
				IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
				wh, "OSEN", "key mgmt alg data too short; len %u, n %u",
				len, n);
		return IEEE80211_REASON_IE_INVALID;
	}

	if (LE_READ_4(frm) != ((WFA_AKM_TYPE_OSEN << 24) | WFA_OUI)) {
		IEEE80211_DISCARD_IE(vap,
				IEEE80211_MSG_ELEMID | IEEE80211_MSG_WPA,
				wh, "OSEN", "%s", "no acceptable key mgmt alg");
		return IEEE80211_REASON_IE_INVALID;
	}

	rsn_parm->rsn_keymgmt = RSN_ASE_8021X_UNSPEC;

	/* optional RSN capabilities */
	if (len >= IEEE80211_OSEN_IE_RSN_CAPS_LEN)
		rsn_parm->rsn_caps = LE_READ_2(frm);

	return 0;
}

void
ieee80211_saveie(u_int8_t **iep, const u_int8_t *ie)
{
	if (*iep == NULL)
	{
		if (ie != NULL)
			MALLOC(*iep, void*, ie[1] + 2, M_DEVBUF, M_ZERO);
	}
	else
	{
		if (((*iep)[1] != ie[1]) || (ie == NULL)) {
			FREE(*iep, M_DEVBUF);
			*iep = NULL;
			if (ie != NULL) {
				MALLOC(*iep, void*, ie[1] + 2, M_DEVBUF, M_ZERO);
			}
		}
	}

	if ((*iep != NULL) && (ie != NULL))
		memcpy(*iep, ie, ie[1] + 2);
}
EXPORT_SYMBOL(ieee80211_saveie);

static int
ieee80211_parse_wmeie(u_int8_t *frm, const struct ieee80211_frame *wh,
					  struct ieee80211_node *ni)
{
	u_int len = frm[1];

	if (len != 7) {
		IEEE80211_DISCARD_IE(ni->ni_vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_WME,
			wh, "WME IE", "too short, len %u", len);
		return -1;
	}
	ni->ni_uapsd = frm[WME_CAPINFO_IE_OFFSET];
	if (ni->ni_uapsd) {
		ni->ni_flags |= IEEE80211_NODE_UAPSD;
	}
	IEEE80211_NOTE(ni->ni_vap, IEEE80211_MSG_POWER, ni,
		"UAPSD bit settings from STA: %02x", ni->ni_uapsd);

	return 1;
}
/*
 * This function is only used on STA and the purpose is to save the cipher
 * info filled in ASSOC_REQ and apply it to node allocation once association
 * response received.
 * If TKIP, need two entries; If others, only need one entry
 */
void
ieee80211_parse_cipher_key(struct ieee80211vap *vap, void *ie, uint16_t len)
{
	struct ieee80211_rsnparms *ni_rsn = &(vap->iv_bss->ni_rsn);
	uint8_t type;
	uint8_t count;
	int16_t length = len;
	uint8_t *frm = ie;

	if (vap->iv_opmode != IEEE80211_M_STA)
		return;

	vap->iv_bss->ni_rsn.rsn_ucastcipher = IEEE80211_CIPHER_NONE;
	vap->iv_bss->ni_rsn.rsn_mcastcipher = IEEE80211_CIPHER_NONE;

	while(length > 0) {
		type = *frm;
		length -= 2;
		if (likely (type == IEEE80211_ELEMID_RSN) &&
				(length >= 10)) {
			/*
			 * fixed part for RSN IE. version, mcast cipher, and 2 selector counts.
			 * Other, variable-length data, must be checked separately.
			 */
			frm += 4;
			ni_rsn->rsn_mcastcipher = rsn_cipher(frm, NULL);
			frm += 4;
			count = LE_READ_2(frm);
			if (count != 1) {
				IEEE80211_DPRINTF(vap, IEEE80211_MSG_CRYPTO,
					"%s: more than one unicast cipher in optie RSN\n",
					__func__);
			}
			frm += 2;
			ni_rsn->rsn_ucastcipher = rsn_cipher(frm, NULL);
			return;
		} else if ((type == IEEE80211_ELEMID_VENDOR) && iswpaoui(frm) &&
			(length >= 14)) {
			/*
			 * Check the length once for fixed parts: OUI, type,
			 * version, mcast cipher, and 2 selector counts.
			 * Other, variable-length data, must be checked separately.
			 */
			frm += 8;
			ni_rsn->rsn_mcastcipher = wpa_cipher(frm, NULL);
			frm += 4;
			count = LE_READ_2(frm);
			if (count != 1) {
				IEEE80211_DPRINTF(vap, IEEE80211_MSG_CRYPTO,
					"%s: more than one unicast cipher in optie WPA\n",
					__func__);
			}
			frm += 2;
			ni_rsn->rsn_ucastcipher = wpa_cipher(frm, NULL);
			return;
		} else {
			length -= *(frm + 1);
			frm += (*(frm + 1) + 2);
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_CRYPTO,
				"%s: No WPA/RSN IE\n",
				__func__);
		}
	}

	return;
}

static int
ieee80211_parse_wmeparams(struct ieee80211vap *vap, u_int8_t *frm,
	const struct ieee80211_frame *wh, u_int8_t *qosinfo)
{
	struct ieee80211_wme_state *wme = &vap->iv_ic->ic_wme;
	u_int len = frm[1], qosinfo_count;
	int i;

	*qosinfo = 0;

	if (len < sizeof(struct ieee80211_wme_param)-2) {
		IEEE80211_DISCARD_IE(vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_WME,
			wh, "WME", "too short, len %u", len);
		return -1;
	}
	*qosinfo = frm[__offsetof(struct ieee80211_wme_param, param_qosInfo)];
	qosinfo_count = *qosinfo & WME_QOSINFO_COUNT;
	/* XXX do proper check for wraparound */
	if (qosinfo_count == wme->wme_wmeChanParams.cap_info_count) {
		return 0;
	}
	frm += __offsetof(struct ieee80211_wme_param, params_acParams);
	for (i = 0; i < WME_NUM_AC; i++) {
		struct qtn_wmm_params *wmep =
			&wme->wme_wmeChanParams.cap_wmeParams[i];
		/* NB: ACI not used */
		wmep->wmm_acm = MS(frm[0], WME_PARAM_ACM);
		wmep->wmm_aifsn = MS(frm[0], WME_PARAM_AIFSN);
		wmep->wmm_logcwmin = MS(frm[1], WME_PARAM_LOGCWMIN);
		wmep->wmm_logcwmax = MS(frm[1], WME_PARAM_LOGCWMAX);
		wmep->wmm_txopLimit = LE_READ_2(frm + 2);
		frm += 4;
	}
	wme->wme_wmeChanParams.cap_info_count = qosinfo_count;
	return 1;
}

static void
ieee80211_parse_athParams(struct ieee80211_node *ni, u_int8_t *ie)
{
	struct ieee80211_ie_athAdvCap *athIe =
		(struct ieee80211_ie_athAdvCap *) ie;

	ni->ni_ath_flags = athIe->athAdvCap_capability;
	if (ni->ni_ath_flags & IEEE80211_ATHC_COMP)
		ni->ni_ath_defkeyindex = LE_READ_2(&athIe->athAdvCap_defKeyIndex);
}

static void
ieee80211_skb_dev_set(struct net_device *dev, struct sk_buff *skb)
{
#if defined(CONFIG_BRIDGE) || defined(CONFIG_BRIDGE_MODULE)
	if (dev->br_port && dev->br_port->br)
		skb->dev = dev->br_port->br->dev;
	else
		skb->dev = dev;
#else
	skb->dev = dev;
#endif
}
static void
forward_mgmt_to_app_for_further_processing(struct ieee80211vap *vap, int subtype,
					   struct sk_buff *skb,
					   struct ieee80211_frame *wh,
					   int rssi)
{
	const struct ieee80211_channel *ch = vap->iv_ic->ic_curchan;
	struct net_device *dev = vap->iv_dev;
	struct ieee80211_frame *wh1;
	struct sk_buff *skb1;

	skb1 = skb_copy(skb, GFP_ATOMIC);
	if (skb1 == NULL)
		return;

	ieee80211_skb_dev_set(dev, skb1);
	skb1->orig_dev = dev;
	skb_reset_mac_header(skb1);
	skb1->ip_summed = CHECKSUM_NONE;
	skb1->pkt_type = PACKET_OTHERHOST;
	skb1->protocol = __constant_htons(0x0019);  /* ETH_P_80211_RAW */

	if (likely(ch)) {
		/* pass channel info to LHost app using the unused field wh1->i_dur */
		wh1 = (struct ieee80211_frame *)skb1->data;
		memcpy(wh1->i_dur, &ch->ic_freq, sizeof(wh1->i_dur));
		/* pass channel info to qlink-ep and qtnfmac host driver */
		skb1->qtn_cb.radio_info.freq = ch->ic_freq;
	}

	skb1->qtn_cb.radio_info.rssi = rssi;

	netif_rx(skb1);
}

static void
forward_mgmt_to_app(struct ieee80211vap *vap, int subtype, struct sk_buff *skb,
	struct ieee80211_frame *wh, int rssi)
{
	struct ieee80211_action *ia;
	int filter_type = 0;

	switch (subtype) {
	case IEEE80211_FC0_SUBTYPE_BEACON:
		filter_type = IEEE80211_FILTER_TYPE_BEACON;
		break;
	case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
		filter_type = IEEE80211_FILTER_TYPE_PROBE_REQ;
		break;
	case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
		filter_type = IEEE80211_FILTER_TYPE_PROBE_RESP;
		break;
	case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
	case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
		filter_type = IEEE80211_FILTER_TYPE_ASSOC_REQ;
		break;
	case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
	case IEEE80211_FC0_SUBTYPE_REASSOC_RESP:
		filter_type = IEEE80211_FILTER_TYPE_ASSOC_RESP;
		break;
	case IEEE80211_FC0_SUBTYPE_AUTH:
		filter_type = IEEE80211_FILTER_TYPE_AUTH;
		break;
	case IEEE80211_FC0_SUBTYPE_DEAUTH:
		filter_type = IEEE80211_FILTER_TYPE_DEAUTH;
		break;
	case IEEE80211_FC0_SUBTYPE_DISASSOC:
		filter_type = IEEE80211_FILTER_TYPE_DISASSOC;
		break;
	case IEEE80211_FC0_SUBTYPE_ACTION:
		if (ieee80211_mfr_is_forwarding_allowed(vap, subtype, skb))
			filter_type = IEEE80211_FILTER_TYPE_ACTION;

		ia = (struct ieee80211_action *)&wh[1];
		switch (ia->ia_category) {
		case IEEE80211_ACTION_CAT_WNM:
			filter_type |= IEEE80211_FILTER_TYPE_WNM_ACTION;
			break;
		default:
			break;
		}
	default:
		break;
	}

	if (filter_type && (vap->app_filter & filter_type))
		forward_mgmt_to_app_for_further_processing(vap, subtype, skb, wh, rssi);
}

void
ieee80211_saveath(struct ieee80211_node *ni, u_int8_t *ie)
{
	const struct ieee80211_ie_athAdvCap *athIe =
		(const struct ieee80211_ie_athAdvCap *) ie;

	ni->ni_ath_flags = athIe->athAdvCap_capability;
	if (ni->ni_ath_flags & IEEE80211_ATHC_COMP)
		ni->ni_ath_defkeyindex = LE_READ_2(&athIe->athAdvCap_defKeyIndex);
	ieee80211_saveie(&ni->ni_ath_ie, ie);
}

struct ieee80211_channel *
ieee80211_doth_findchan(struct ieee80211vap *vap, u_int8_t chan)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_channel *c;
	int flags, freq;

	KASSERT(ic->ic_bsschan != IEEE80211_CHAN_ANYC, ("BSS channel not set up"));

	/* NB: try first to preserve turbo */
	flags = ic->ic_bsschan->ic_flags & IEEE80211_CHAN_ALL;
	freq = ieee80211_ieee2mhz(chan, 0);
	c = ieee80211_find_channel(ic, freq, flags);
	if (c == NULL)
		c = ieee80211_find_channel(ic, freq, 0);
	return c;
}

int
ieee80211_parse_htcap(struct ieee80211_node *ni, u_int8_t *ie)
{
	struct ieee80211com *ic = ni->ni_ic;
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211_ie_htcap *htcap = (struct ieee80211_ie_htcap *)ie;
	u_int16_t peer_cap = IEEE80211_HTCAP_CAPABILITIES(htcap);
	u_int16_t merged_cap = peer_cap & ic->ic_htcap.cap;

	/* Compare with stored ie, return 0 if unchanged */
	if (memcmp(htcap, &ni->ni_ie_htcap, sizeof(struct ieee80211_ie_htcap)) == 0) {
		return 0;
	}

	if (ieee80211_extender_msg(vap, IEEE80211_EXTENDER_MSG_DBG)) {
		struct ieee80211_ie_htcap *lhtcap = &ni->ni_ie_htcap;
		struct ieee80211_ie_htcap *rhtcap = htcap;

		printk("htcap %pM\n", ni->ni_macaddr);

		if (memcmp(lhtcap->hc_cap, rhtcap->hc_cap, sizeof(lhtcap->hc_cap)))
			printk("cap\nold: %02x %02x\nnew: %02x %02x\n",
				lhtcap->hc_cap[0], lhtcap->hc_cap[1],
				rhtcap->hc_cap[0], rhtcap->hc_cap[1]);

		if (lhtcap->hc_ampdu != rhtcap->hc_ampdu)
			printk("ampdu\nold: %02x\nnew: %02x\n",
				lhtcap->hc_ampdu, rhtcap->hc_ampdu);

		if (memcmp(lhtcap->hc_mcsset, rhtcap->hc_mcsset, sizeof(lhtcap->hc_mcsset))) {
			int i;

			printk("mcsset\nold:");

			for (i = 0; i < ARRAY_SIZE(lhtcap->hc_mcsset); i++)
				printk(" %02x", lhtcap->hc_mcsset[i]);

			printk("\nnew:");

			for (i = 0; i < ARRAY_SIZE(rhtcap->hc_mcsset); i++)
				printk(" %02x", rhtcap->hc_mcsset[i]);

			printk("\n");
		}

		if (memcmp(lhtcap->hc_extcap, rhtcap->hc_extcap, sizeof(lhtcap->hc_extcap)))
			printk("extcap\nold: %02x %02x\nnew: %02x %02x\n",
				lhtcap->hc_extcap[0], lhtcap->hc_extcap[1],
				rhtcap->hc_extcap[0], rhtcap->hc_extcap[1]);

		if (memcmp(lhtcap->hc_txbf, rhtcap->hc_txbf, sizeof(lhtcap->hc_txbf)))
			printk("txbf\nold: %02x %02x %02x %02x\nnew: %02x %02x %02x %02x\n",
				lhtcap->hc_txbf[0], lhtcap->hc_txbf[1],
				lhtcap->hc_txbf[2], lhtcap->hc_txbf[3],
				rhtcap->hc_txbf[0], rhtcap->hc_txbf[1],
				rhtcap->hc_txbf[2], rhtcap->hc_txbf[3]);

		if (lhtcap->hc_antenna != rhtcap->hc_antenna)
			printk("antenna\nold: %02x\nnew: %02x\n",
				lhtcap->hc_antenna, rhtcap->hc_antenna);
	}

	memcpy(&ni->ni_ie_htcap, htcap, sizeof(ni->ni_ie_htcap));

	/* Take the combination of IC and STA parameters */
	/* set HT capabilities */
	ni->ni_htcap.cap = 0;

	/* set channel width */
	ni->ni_htcap.cap |= peer_cap & IEEE80211_HTCAP_C_CHWIDTH40;

	/* Set power save mode - STA determines this, not the AP. */
	if (vap->iv_opmode == IEEE80211_M_STA) {
		ni->ni_htcap.pwrsave = ic->ic_htcap.pwrsave;
	} else if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
		u_int8_t smps = IEEE80211_HTCAP_PWRSAVE_MODE(htcap);
		ni->ni_htcap.pwrsave = smps;
	} else if (vap->iv_opmode == IEEE80211_M_WDS) {
		/* WDS power save unsupported */
		ni->ni_htcap.pwrsave = IEEE80211_HTCAP_C_MIMOPWRSAVE_NONE;
	}

	/* Default invalid PS mode to NONE */
	if (ni->ni_htcap.pwrsave == IEEE80211_HTCAP_C_MIMOPWRSAVE_NA)
		ni->ni_htcap.pwrsave = IEEE80211_HTCAP_C_MIMOPWRSAVE_NONE;

	/* set SHORT GI options */
	ni->ni_htcap.cap |= merged_cap & IEEE80211_HTCAP_C_SHORTGI20;
	ni->ni_htcap.cap |= merged_cap & IEEE80211_HTCAP_C_SHORTGI40;

	/* Set STBC options */
	if ((ic->ic_htcap.cap & IEEE80211_HTCAP_C_TXSTBC)
			&& (IEEE80211_HTCAP_RX_STBC_MODE(htcap)))
	ni->ni_htcap.cap |= IEEE80211_HTCAP_C_TXSTBC;

	if (ic->ic_htcap.cap & IEEE80211_HTCAP_C_TXSTBC)
		ni->ni_htcap.numrxstbcstr = IEEE80211_HTCAP_RX_STBC_MODE(htcap);
	else
		ni->ni_htcap.numrxstbcstr = 0;

	/* delayed block ack */
	ni->ni_htcap.cap |= peer_cap & IEEE80211_HTCAP_C_DELAYEDBLKACK;

	/* Maximum A-MSDU size */
	if (peer_cap & IEEE80211_HTCAP_C_MAXAMSDUSIZE_8K)
		ni->ni_htcap.maxmsdu = 7935;
	else
		ni->ni_htcap.maxmsdu = 3839;

	/* DSSS/CCK mode in 40 MHz */
	ni->ni_htcap.cap |= peer_cap & IEEE80211_HTCAP_C_DSSSCCK40;

	/* PSMP support (only if AP supports) */
	ni->ni_htcap.cap |= peer_cap & IEEE80211_HTCAP_C_PSMP;

	/* set 40 MHz intolerant */
	ni->ni_htcap.cap |= peer_cap & IEEE80211_HTCAP_C_40_INTOLERANT;

	/* set L-SIG TXOP support */
	ni->ni_htcap.cap |= peer_cap & IEEE80211_HTCAP_C_LSIGTXOPPROT;

	/* set maximum A-MPDU size */
	ni->ni_htcap.maxampdu = IEEE80211_HTCAP_MAX_AMPDU_LEN(htcap);

	/* set maximum MPDU spacing */
	ni->ni_htcap.mpduspacing = IEEE80211_HTCAP_MIN_AMPDU_SPACING(htcap);

	/* set MCS rate indexes */
	ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_NSS1] =
		IEEE80211_HTCAP_MCS_VALUE(htcap, IEEE80211_HT_MCSSET_20_40_NSS1);
	ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_NSS2] =
		IEEE80211_HTCAP_MCS_VALUE(htcap, IEEE80211_HT_MCSSET_20_40_NSS2);
	ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_NSS3] =
		IEEE80211_HTCAP_MCS_VALUE(htcap, IEEE80211_HT_MCSSET_20_40_NSS3);
	ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_NSS4] =
		IEEE80211_HTCAP_MCS_VALUE(htcap, IEEE80211_HT_MCSSET_20_40_NSS4);
	ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_UEQM1] =
		IEEE80211_HTCAP_MCS_VALUE(htcap, IEEE80211_HT_MCSSET_20_40_UEQM1);
	ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_UEQM2] =
		IEEE80211_HTCAP_MCS_VALUE(htcap, IEEE80211_HT_MCSSET_20_40_UEQM2);
	ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_UEQM3] =
		IEEE80211_HTCAP_MCS_VALUE(htcap, IEEE80211_HT_MCSSET_20_40_UEQM3);
	ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_UEQM4] =
		IEEE80211_HTCAP_MCS_VALUE(htcap, IEEE80211_HT_MCSSET_20_40_UEQM4);
	ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_UEQM5] =
		IEEE80211_HTCAP_MCS_VALUE(htcap, IEEE80211_HT_MCSSET_20_40_UEQM5);
	ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_UEQM6] =
		IEEE80211_HTCAP_MCS_VALUE(htcap, IEEE80211_HT_MCSSET_20_40_UEQM6);

	/* set maximum data rate */
	ni->ni_htcap.maxdatarate = IEEE80211_HTCAP_HIGHEST_DATA_RATE(htcap);

	/* set MCS parameters */
	ni->ni_htcap.mcsparams = 0;

	if (IEEE80211_HTCAP_MCS_PARAMS(htcap) & IEEE80211_HTCAP_MCS_TX_SET_DEFINED) {
		ni->ni_htcap.mcsparams |= IEEE80211_HTCAP_MCS_TX_SET_DEFINED;

		/* set number of Tx spatial streams */
		if(IEEE80211_HTCAP_MCS_PARAMS(htcap) & IEEE80211_HTCAP_MCS_TX_RX_SET_NEQ) {
			ni->ni_htcap.numtxspstr = IEEE80211_HTCAP_MCS_STREAMS(htcap);
			ni->ni_htcap.mcsparams |= IEEE80211_HTCAP_MCS_TX_RX_SET_NEQ |
				(IEEE80211_HTCAP_MCS_PARAMS(htcap) & IEEE80211_HTCAP_MCS_TX_UNEQ_MOD);
		} else {
			ni->ni_htcap.numtxspstr = 0;
		}
	} else {
		ni->ni_htcap.numtxspstr = 0;
	}

	if (ni->ni_qtn_assoc_ie || (vap->iv_ht_flags & IEEE80211_HTF_LDPC_ALLOW_NON_QTN)) {
		ni->ni_htcap.cap |= peer_cap & IEEE80211_HTCAP_C_LDPCCODING;
	}

	ni->ni_htcap.hc_txbf[0] = ic->ic_htcap.hc_txbf[0] & htcap->hc_txbf[0];
	ni->ni_htcap.hc_txbf[1] = ic->ic_htcap.hc_txbf[1] & htcap->hc_txbf[1];
	ni->ni_htcap.hc_txbf[2] = ic->ic_htcap.hc_txbf[2] & htcap->hc_txbf[2];
	ni->ni_htcap.hc_txbf[3] = ic->ic_htcap.hc_txbf[3] & htcap->hc_txbf[3];

	return 1;
}
static u_int16_t
ieee80211_merge_vhtmcs(u_int16_t local_vhtmcs, u_int16_t far_vhtmcs)
{
	/* Spatial stream from 1-8 = 3 (not supported) */
	u_int16_t merge_vhtmcsmap = IEEE80211_VHTMCS_ALL_DISABLE;

	enum ieee80211_vht_nss vhtnss;
	enum ieee80211_vht_mcs_supported vhtmcs = IEEE80211_VHT_MCS_NA;

	for (vhtnss = IEEE80211_VHT_NSS1; vhtnss <= IEEE80211_VHT_NSS8; vhtnss++) {

		/* Check if perticular stream is not supported by peer */
		if (((local_vhtmcs & 0x0003) == IEEE80211_VHT_MCS_NA) ||
			((far_vhtmcs & 0x0003) == IEEE80211_VHT_MCS_NA)) {
			vhtmcs = IEEE80211_VHT_MCS_NA;
		} else {
			vhtmcs = min((local_vhtmcs & 0x0003), (far_vhtmcs & 0x0003));
		}

		switch(vhtnss) {
		case IEEE80211_VHT_NSS1:
			merge_vhtmcsmap &= 0xFFFC;
			merge_vhtmcsmap |= vhtmcs;
			break;
		case IEEE80211_VHT_NSS2:
			merge_vhtmcsmap &= 0xFFF3;
			merge_vhtmcsmap |= (vhtmcs << 2);
			break;
		case IEEE80211_VHT_NSS3:
			merge_vhtmcsmap &= 0xFFCF;
			merge_vhtmcsmap |= (vhtmcs << 4);
			break;
		case IEEE80211_VHT_NSS4:
			merge_vhtmcsmap &= 0xFF3F;
			merge_vhtmcsmap |= (vhtmcs << 6);
			break;
		case IEEE80211_VHT_NSS5:
			merge_vhtmcsmap &= 0xFCFF;
			merge_vhtmcsmap |= (vhtmcs << 8);
			break;
		case IEEE80211_VHT_NSS6:
			merge_vhtmcsmap &= 0xF3FF;
			merge_vhtmcsmap |= (vhtmcs << 10);
			break;
		case IEEE80211_VHT_NSS7:
			merge_vhtmcsmap &= 0xCFFF;
			merge_vhtmcsmap |= (vhtmcs << 12);
			break;
		case IEEE80211_VHT_NSS8:
			merge_vhtmcsmap &= 0x3FFF;
			merge_vhtmcsmap |= (vhtmcs << 14);
			break;
		}
		local_vhtmcs = local_vhtmcs >> 2;
		far_vhtmcs = far_vhtmcs >> 2;
	}

	return (merge_vhtmcsmap);
}


void
ieee80211_parse_vhtcap(struct ieee80211_node *ni, u_int8_t *ie)
{
	struct ieee80211com *ic = ni->ni_ic;
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211_ie_vhtcap *rvhtcap = (struct ieee80211_ie_vhtcap *)ie;
	u_int32_t peer_vhtcap = IEEE80211_VHTCAP_GET_CAPFLAGS(rvhtcap);
	struct ieee80211_vhtcap *ic_vhtcap = NULL;
	u_int32_t merged_cap;

	if (IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan))
	      ic_vhtcap = &ic->ic_vhtcap_24g;
	else
	      ic_vhtcap = &ic->ic_vhtcap;

	merged_cap = peer_vhtcap & ic_vhtcap->cap_flags;

	/* Following BF related fields require cross merging hence clear them first */
	merged_cap &= ~(IEEE80211_VHTCAP_C_SU_BEAM_FORMEE_CAP |
				IEEE80211_VHTCAP_C_SU_BEAM_FORMER_CAP |
				IEEE80211_VHTCAP_C_MU_BEAM_FORMEE_CAP |
				IEEE80211_VHTCAP_C_MU_BEAM_FORMER_CAP);

	memcpy(&ni->ni_ie_vhtcap, rvhtcap, sizeof(ni->ni_ie_vhtcap));

	/* Take the combination of IC and STA parameters */
	/* Set VHT capabilities in the node structure */
	ni->ni_vhtcap.cap_flags = merged_cap;

	ni->ni_vhtcap.maxmpdu = min(ic_vhtcap->maxmpdu,
					IEEE80211_VHTCAP_GET_MAXMPDU(rvhtcap));
	ni->ni_vhtcap.chanwidth = min(ic_vhtcap->chanwidth,
					IEEE80211_VHTCAP_GET_CHANWIDTH(rvhtcap));

	ni->ni_vhtcap.rxstbc = IEEE80211_VHTCAP_GET_RXSTBC(rvhtcap);
	ni->ni_vhtcap.bfstscap = IEEE80211_VHTCAP_GET_BFSTSCAP(rvhtcap);
	ni->ni_vhtcap.numsounding = IEEE80211_VHTCAP_GET_NUMSOUND(rvhtcap);
	ni->ni_vhtcap.maxampduexp = min(ic_vhtcap->maxampduexp,
					IEEE80211_VHTCAP_GET_MAXAMPDUEXP(rvhtcap));

	ni->ni_vhtcap.lnkadptcap = min(ic_vhtcap->lnkadptcap,
					IEEE80211_VHTCAP_GET_LNKADPTCAP(rvhtcap));

	if ((vap->iv_vht_flags & IEEE80211_VHTCAP_C_TX_STBC) &&
		(ni->ni_vhtcap.rxstbc)) {
		ni->ni_vhtcap.cap_flags |= IEEE80211_VHTCAP_C_TX_STBC;
	}

	if ((ic->ic_vhtcap.cap_flags & IEEE80211_VHTCAP_C_SU_BEAM_FORMEE_CAP) &&
		IEEE80211_VHTCAP_GET_SU_BEAMFORMER(rvhtcap)) {
		ni->ni_vhtcap.cap_flags |= IEEE80211_VHTCAP_C_SU_BEAM_FORMER_CAP;
	}

	if ((ic->ic_vhtcap.cap_flags & IEEE80211_VHTCAP_C_SU_BEAM_FORMER_CAP) &&
		IEEE80211_VHTCAP_GET_SU_BEAMFORMEE(rvhtcap)) {
		ni->ni_vhtcap.cap_flags |= IEEE80211_VHTCAP_C_SU_BEAM_FORMEE_CAP;
	}

	if ((ic->ic_vhtcap.cap_flags & IEEE80211_VHTCAP_C_MU_BEAM_FORMEE_CAP) &&
		IEEE80211_VHTCAP_GET_MU_BEAMFORMER(rvhtcap)) {
		ni->ni_vhtcap.cap_flags |= IEEE80211_VHTCAP_C_MU_BEAM_FORMER_CAP;
	}

	if ((ic->ic_vhtcap.cap_flags & IEEE80211_VHTCAP_C_MU_BEAM_FORMER_CAP) &&
		IEEE80211_VHTCAP_GET_MU_BEAMFORMEE(rvhtcap)) {
		ni->ni_vhtcap.cap_flags |= IEEE80211_VHTCAP_C_MU_BEAM_FORMEE_CAP;
	}

	ni->ni_vhtcap.txlgimaxrate = min(ic_vhtcap->rxlgimaxrate,
					IEEE80211_VHTCAP_GET_TX_LGIMAXRATE(rvhtcap));
	ni->ni_vhtcap.rxlgimaxrate = min(ic_vhtcap->txlgimaxrate,
					IEEE80211_VHTCAP_GET_RX_LGIMAXRATE(rvhtcap));
	ni->ni_vhtcap.txmcsmap = ieee80211_merge_vhtmcs(ic_vhtcap->rxmcsmap,
					IEEE80211_VHTCAP_GET_TX_MCS_NSS(rvhtcap));
	ni->ni_vhtcap.rxmcsmap = ieee80211_merge_vhtmcs(ic_vhtcap->txmcsmap,
					IEEE80211_VHTCAP_GET_RX_MCS_NSS(rvhtcap));

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
				"flags: local(0x%08x) remote(0x%08x) >> node(0x%08x)\n",
				ic_vhtcap->cap_flags,
				IEEE80211_VHTCAP_GET_CAPFLAGS(rvhtcap),
				ni->ni_vhtcap.cap_flags);

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
				"maxmpdu: local(%d) remote(%d) >> node(%d)\n",
				ic_vhtcap->maxmpdu,
				IEEE80211_VHTCAP_GET_MAXMPDU(rvhtcap),
				ni->ni_vhtcap.maxmpdu);

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
				"chanwidth: local(%d) remote(%d) >> node(%d)\n",
				ic_vhtcap->chanwidth,
				IEEE80211_VHTCAP_GET_CHANWIDTH(rvhtcap),
				ni->ni_vhtcap.chanwidth);

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
				"rxstbc: local(%d) remote(%d) >> node(%d)\n",
				ic_vhtcap->rxstbc,
				IEEE80211_VHTCAP_GET_RXSTBC(rvhtcap),
				ni->ni_vhtcap.rxstbc);

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
				"bfstscap: local(%d) remote(%d) >> node(%d)\n",
				ic_vhtcap->bfstscap,
				IEEE80211_VHTCAP_GET_BFSTSCAP(rvhtcap),
				ni->ni_vhtcap.bfstscap);

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
				"numsounding: local(%d) remote(%d) >> node(%d)\n",
				ic_vhtcap->numsounding,
				IEEE80211_VHTCAP_GET_NUMSOUND(rvhtcap),
				ni->ni_vhtcap.numsounding);

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
				"maxampduexp: local(%d) remote(%d) >> node(%d)\n",
				ic_vhtcap->maxampduexp,
				IEEE80211_VHTCAP_GET_MAXAMPDUEXP(rvhtcap),
				ni->ni_vhtcap.maxampduexp);

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
				"lnkadptcap: local(%d) remote(%d) >> node(%d)\n",
				ic_vhtcap->lnkadptcap,
				IEEE80211_VHTCAP_GET_LNKADPTCAP(rvhtcap),
				ni->ni_vhtcap.lnkadptcap);

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
				"rxlgimaxrate: local(%d) remote-tx(%d) >> node(%d)\n",
				ic_vhtcap->rxlgimaxrate,
				IEEE80211_VHTCAP_GET_TX_LGIMAXRATE(rvhtcap),
				ni->ni_vhtcap.rxlgimaxrate);

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
				"txlgimaxrate: local(%d) remote-rx(%d) >> node(%d)\n",
				ic_vhtcap->txlgimaxrate,
				IEEE80211_VHTCAP_GET_RX_LGIMAXRATE(rvhtcap),
				ni->ni_vhtcap.txlgimaxrate);

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
				"rxmcsmap: local(0x%08x) remote-tx(0x%08x) >> node(0x%08x)\n",
				ic_vhtcap->rxmcsmap,
				IEEE80211_VHTCAP_GET_TX_MCS_NSS(rvhtcap),
				ni->ni_vhtcap.rxmcsmap);

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
				"txmcsmap: local(0x%08x) remote-rx(0x%08x) >> node(0x%08x)\n",
				ic_vhtcap->txmcsmap,
				IEEE80211_VHTCAP_GET_RX_MCS_NSS(rvhtcap),
				ni->ni_vhtcap.txmcsmap);
}

static int ieee80211_check_and_parse_vhtop(struct ieee80211_node *ni, u_int8_t *ie)
{
	struct ieee80211_ie_vhtop *rvhtop = (struct ieee80211_ie_vhtop *)ie;
	struct ieee80211vap *vap = ni->ni_vap;

	/* Compare with stored ie, return 0 if unchanged */
	if (memcmp(rvhtop, &ni->ni_ie_vhtop, sizeof(struct ieee80211_ie_vhtop)) == 0)
		return 0;

	if (ieee80211_extender_msg(vap, IEEE80211_EXTENDER_MSG_DBG)) {
		struct ieee80211_ie_vhtop *lvhtop = &ni->ni_ie_vhtop;

		printk("vhtop %pM\n", ni->ni_macaddr);

		if (memcmp(lvhtop->vhtop_info, rvhtop->vhtop_info,
					sizeof(lvhtop->vhtop_info)))
			printk("info\nold: %02x %02x %02x\nnew: %02x %02x %02x\n",
				lvhtop->vhtop_info[0], lvhtop->vhtop_info[1],
				lvhtop->vhtop_info[2], rvhtop->vhtop_info[0],
				rvhtop->vhtop_info[1], rvhtop->vhtop_info[2]);

		if (memcmp(lvhtop->vhtop_bvhtmcs, rvhtop->vhtop_bvhtmcs,
					sizeof(lvhtop->vhtop_bvhtmcs)))
			printk("bvhtmcs\nold: %02x %02x\nnew: %02x %02x\n",
				lvhtop->vhtop_bvhtmcs[0], lvhtop->vhtop_bvhtmcs[1],
				rvhtop->vhtop_bvhtmcs[0], rvhtop->vhtop_bvhtmcs[1]);
	}

	ieee80211_parse_vhtop(ni, ie);
	return 1;
}

int
ieee80211_check_and_parse_vhtcap(struct ieee80211_node *ni, u_int8_t *ie)
{
	struct ieee80211_ie_vhtcap *rvhtcap = (struct ieee80211_ie_vhtcap *)ie;

	/* Compare with stored ie, return 0 if unchanged */
	if (memcmp(rvhtcap, &ni->ni_ie_vhtcap, sizeof(struct ieee80211_ie_vhtcap)) == 0) {
		return 0;
	}

	if (ieee80211_extender_msg(ni->ni_vap, IEEE80211_EXTENDER_MSG_DBG)) {
		struct ieee80211_ie_vhtcap *lvhtcap = &ni->ni_ie_vhtcap;

		printk("vhtcap %pM\n", ni->ni_macaddr);

		if (memcmp(lvhtcap->vht_cap, rvhtcap->vht_cap, sizeof(lvhtcap->vht_cap)))
			printk("cap\nold: %02x %02x %02x %02x\nnew: %02x %02x %02x %02x\n",
				lvhtcap->vht_cap[0], lvhtcap->vht_cap[1],
				lvhtcap->vht_cap[2], lvhtcap->vht_cap[3],
				rvhtcap->vht_cap[0], rvhtcap->vht_cap[1],
				rvhtcap->vht_cap[2], rvhtcap->vht_cap[3]);

		if (memcmp(lvhtcap->vht_mcs_nss_set, rvhtcap->vht_mcs_nss_set,
					sizeof(lvhtcap->vht_mcs_nss_set))) {
			int i;

			printk("mcs_nss_set\nold:");

			for (i = 0; i < ARRAY_SIZE(lvhtcap->vht_mcs_nss_set); i++)
				printk(" %02x", lvhtcap->vht_mcs_nss_set[i]);

			printk("\nnew:");

			for (i = 0; i < ARRAY_SIZE(rvhtcap->vht_mcs_nss_set); i++)
				printk(" %02x", rvhtcap->vht_mcs_nss_set[i]);

			printk("\n");
		}
	}

	ieee80211_parse_vhtcap(ni, ie);
	return 1;
}

static uint8_t *
ieee80211_get_vhtcap_from_brcmvht(struct ieee80211_node *ni, uint8_t *ie)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211_ie_brcm_vht *brcm_vht = (struct ieee80211_ie_brcm_vht *)ie;
	uint8_t *vhtie = brcm_vht->vht_ies;
	uint8_t *end = ie + ie[1];
	uint8_t *vhtcap = NULL;

	while (vhtie < end) {
		switch (*vhtie) {
		case IEEE80211_ELEMID_VHTCAP:
			vhtcap = vhtie;
			return vhtcap;
		default:
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
					"unhandled id %u, len %u\n", *vhtie, vhtie[1]);
			vap->iv_stats.is_rx_elem_unknown++;
			break;
		}
		vhtie += vhtie[1] + 2;
	}

	return vhtcap;
}

static uint8_t *
ieee80211_get_vhtop_from_brcmvht(struct ieee80211_node *ni, uint8_t *ie)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211_ie_brcm_vht *brcm_vht = (struct ieee80211_ie_brcm_vht *)ie;
	uint8_t *vhtie = brcm_vht->vht_ies;
	uint8_t *end = ie + ie[1];
	uint8_t *vhtop = NULL;

	while (vhtie < end) {
		switch (*vhtie) {
		case IEEE80211_ELEMID_VHTOP:
			vhtop = vhtie;
			return vhtop;
		default:
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
					"unhandled id %u, len %u\n", *vhtie, vhtie[1]);
			vap->iv_stats.is_rx_elem_unknown++;
			break;
		}
		vhtie += vhtie[1] + 2;
	}

	return vhtop;
}


void
ieee80211_parse_measinfo(struct ieee80211_node *ni, u_int8_t *ie)
{
#if defined(CONFIG_QTN_80211K_SUPPORT)
	struct ieee80211com *ic = ni->ni_ic;
	struct ieee80211_ie_measure_comm *ie_comm = (struct ieee80211_ie_measure_comm *)(void*) ie;
	struct ieee80211_ie_measreq *measinfo = (struct ieee80211_ie_measreq *)(void*) ie_comm->data;
	struct ieee80211_channel *ch;
	u_int32_t duration;
	u_int64_t tsf;

	if ( !(ic->ic_flags & IEEE80211_F_CCA) ) {
		ic->ic_flags |= IEEE80211_F_CCA;

		ch = findchannel(ic, measinfo->chan_num, ic->ic_des_mode);

		if (ie_comm->token - ic->ic_cca_token > 0) {
			ic->ic_cca_token = ie_comm->token;
			tsf = ntohll(measinfo->start_tsf);
			duration = ntohs(measinfo->duration_tu);
			duration = IEEE80211_TU_TO_MS(duration);
			ic->ic_set_start_cca_measurement(ic, ch,
							 tsf, duration);
		}
	}
#else
	struct ieee80211com *ic = ni->ni_ic;
	struct ieee80211_ie_measreq *measinfo = (struct ieee80211_ie_measreq *)(void*) ie;
	struct ieee80211_channel *ch;
	u_int32_t duration;
	u_int64_t tsf;

	if ( !(ic->ic_flags & IEEE80211_F_CCA) ) {
		ic->ic_flags |= IEEE80211_F_CCA;

		ch = findchannel(ic, measinfo->chan_num, ic->ic_des_mode);

		if (measinfo->meas_token - ic->ic_cca_token > 0) {
			ic->ic_cca_token = measinfo->meas_token;
			tsf = ntohll(measinfo->start_tsf);
			duration = ntohs(measinfo->duration_tu);
			duration = IEEE80211_TU_TO_MS(duration);
			ic->ic_set_start_cca_measurement(ic, ch,
							 tsf, duration);
		}
	}
#endif
}

int
ieee80211_parse_htinfo(struct ieee80211_node *ni, u_int8_t *ie)
{
	struct ieee80211com *ic = ni->ni_ic;
	struct ieee80211_ie_htinfo *htinfo = (struct ieee80211_ie_htinfo *)ie;

	/* Compare with stored ie, return 0 if unchanged */
	if (memcmp(htinfo, &ni->ni_ie_htinfo, sizeof(struct ieee80211_ie_htinfo)) == 0)
		return 0;

	if (ieee80211_extender_msg(ni->ni_vap, IEEE80211_EXTENDER_MSG_DBG)) {
		struct ieee80211_ie_htinfo *lhtinfo = &ni->ni_ie_htinfo;
		struct ieee80211_ie_htinfo *rhtinfo = htinfo;

		printk("htinfo %pM\n", ni->ni_macaddr);

		if (lhtinfo->hi_ctrlchannel != rhtinfo->hi_ctrlchannel)
			printk("ctrlchannel\nold: %02x\nnew: %02x\n",
					lhtinfo->hi_ctrlchannel, rhtinfo->hi_ctrlchannel);

		if (lhtinfo->hi_byte1 != rhtinfo->hi_byte1)
			printk("byte1\nold: %02x\nnew: %02x\n",
					lhtinfo->hi_byte1, rhtinfo->hi_byte1);

		if (lhtinfo->hi_byte2 != rhtinfo->hi_byte2)
			printk("byte2\nold: %02x\nnew: %02x\n",
					lhtinfo->hi_byte2, rhtinfo->hi_byte2);

		if (lhtinfo->hi_byte3 != rhtinfo->hi_byte3)
			printk("byte3\nold: %02x\nnew: %02x\n",
					lhtinfo->hi_byte3, rhtinfo->hi_byte3);

		if (lhtinfo->hi_byte4 != rhtinfo->hi_byte4)
			printk("byte4\nold: %02x\nnew: %02x\n",
					lhtinfo->hi_byte4, rhtinfo->hi_byte4);

		if (lhtinfo->hi_byte5 != rhtinfo->hi_byte5)
			printk("byte5\nold: %02x\nnew: %02x\n",
					lhtinfo->hi_byte5, rhtinfo->hi_byte5);

		if (memcmp(lhtinfo->hi_basicmcsset, rhtinfo->hi_basicmcsset,
					sizeof(lhtinfo->hi_basicmcsset))) {
			int i;

			printk("basic_mcsset\nold:");

			for (i = 0; i < ARRAY_SIZE(lhtinfo->hi_basicmcsset); i++)
				printk(" %02x", lhtinfo->hi_basicmcsset[i]);

			printk("\nnew:");

			for (i = 0; i < ARRAY_SIZE(rhtinfo->hi_basicmcsset); i++)
				printk(" %02x", rhtinfo->hi_basicmcsset[i]);

			printk("\n");
		}
	}

	memcpy(&ni->ni_ie_htinfo, htinfo, sizeof(ni->ni_ie_htinfo));

	/* set primary channel */
	ni->ni_htinfo.ctrlchannel = IEEE80211_HTINFO_PRIMARY_CHANNEL(htinfo);

	/* set byte 1 values */
	ni->ni_htinfo.byte1 = 0;

	/* set the channel width and secondary channel offset */
	if (IEEE80211_HTINFO_BYTE_ONE(htinfo) & IEEE80211_HTINFO_B1_REC_TXCHWIDTH_40) {
		ni->ni_htinfo.choffset = IEEE80211_HTINFO_B1_EXT_CHOFFSET(htinfo);
		ni->ni_htinfo.byte1 |= IEEE80211_HTINFO_B1_REC_TXCHWIDTH_40;
	} else {
		ni->ni_htinfo.choffset = 0;
	}

	/* force 20MHz bw if secondary channel offset is unknown */
	if ((ni->ni_htcap.cap & IEEE80211_HTCAP_C_CHWIDTH40) && !ni->ni_htinfo.choffset)
		ni->ni_htcap.cap &= ~IEEE80211_HTCAP_C_CHWIDTH40;

	/* XXX set the S-PSMP support */
	if (ni->ni_htcap.cap & IEEE80211_HTCAP_C_PSMP)
	{
		if (IEEE80211_HTINFO_BYTE_ONE(htinfo) & IEEE80211_HTINFO_B1_CONTROLLED_ACCESS)
			ni->ni_htinfo.byte1 |= (ic->ic_htinfo.byte1 & IEEE80211_HTINFO_B1_CONTROLLED_ACCESS);
	}

	/* service level granularity */
	if (ni->ni_htinfo.byte1 & IEEE80211_HTINFO_B1_CONTROLLED_ACCESS)
		ni->ni_htinfo.sigranularity = ic->ic_htinfo.sigranularity;

	/* set byte 2 values */
	ni->ni_htinfo.byte2 = 0;

	ni->ni_htinfo.opmode = IEEE80211_HTINFO_B2_OP_MODE(htinfo);
	ni->ni_htinfo.byte2 |= IEEE80211_HTINFO_BYTE_TWO(htinfo) & IEEE80211_HTINFO_B2_NON_GF_PRESENT;
	ni->ni_htinfo.byte2 |= IEEE80211_HTINFO_BYTE_TWO(htinfo) & IEEE80211_HTINFO_B2_OBSS_PROT;

	/* set byte 3 values */
	ni->ni_htinfo.byte3 = 0;

	/* set byte 4 values */
	ni->ni_htinfo.byte4 = 0;

	ni->ni_htinfo.byte4 |= IEEE80211_HTINFO_BYTE_FOUR(htinfo) & IEEE80211_HTINFO_B4_DUAL_BEACON;
	ni->ni_htinfo.byte4 |= IEEE80211_HTINFO_BYTE_FOUR(htinfo) & IEEE80211_HTINFO_B4_DUAL_CTS;

	/* set byte 5 values */
	ni->ni_htinfo.byte5 = 0;

	ni->ni_htinfo.byte5 |= IEEE80211_HTINFO_BYTE_FIVE(htinfo) & IEEE80211_HTINFO_B5_STBC_BEACON;
	ni->ni_htinfo.byte5 |= IEEE80211_HTINFO_BYTE_FIVE(htinfo) & IEEE80211_HTINFO_B5_LSIGTXOPPROT;
	ni->ni_htinfo.byte5 |= IEEE80211_HTINFO_BYTE_FIVE(htinfo) & IEEE80211_HTINFO_B5_PCO_ACTIVE;
	ni->ni_htinfo.byte5 |= IEEE80211_HTINFO_BYTE_FIVE(htinfo) & IEEE80211_HTINFO_B5_40MHZPHASE;

	/* set basic rates */
	/* CBW = 20/40 MHz, Nss = 1, Nes = 1, EQM/ No EQM */
	ni->ni_htinfo.basicmcsset[IEEE80211_HT_MCSSET_20_40_NSS1] =
					IEEE80211_HTINFO_BASIC_MCS_VALUE(htinfo, IEEE80211_HT_MCSSET_20_40_NSS1);

	/* CBW = 20/40 MHz, Nss = 2, Nes = 1, EQM */
	ni->ni_htinfo.basicmcsset[IEEE80211_HT_MCSSET_20_40_NSS2] =
					IEEE80211_HTINFO_BASIC_MCS_VALUE(htinfo, IEEE80211_HT_MCSSET_20_40_NSS2);

	/* Enable RTS-CTS if HT-protection bit is set */
	if (IEEE80211_11N_PROTECT_ENABLED(ic) &&
		ni->ni_htinfo.opmode && !ic->ic_local_rts &&
		(ni->ni_vap->iv_opmode == IEEE80211_M_STA ||
		ni->ni_vap->iv_opmode == IEEE80211_M_WDS)) {
		/* RTS-CTS can be enabled only when Rev B and later is used */
		if (get_hardware_revision() != HARDWARE_REVISION_RUBY_A) {
			ic->ic_local_rts = 1;
			ic->ic_use_rtscts(ic);
		}
	}
	/* Disable RTS-CTS if HT-protection bit is not set	*
	 * and if RTS-CTS is in use currently		*/
	if (IEEE80211_11N_PROTECT_ENABLED(ic) &&
		ic->ic_local_rts && !(ni->ni_htinfo.opmode) &&
		(ni->ni_vap->iv_opmode == IEEE80211_M_STA ||
		ni->ni_vap->iv_opmode == IEEE80211_M_WDS)) {
		/* RTS-CTS can be enabled only when Rev B and later is used */
		if (get_hardware_revision() != HARDWARE_REVISION_RUBY_A) {
			ic->ic_local_rts = 0;
			ic->ic_use_rtscts(ic);
		}
	}
	return 1;
}

void ieee80211_parse_vhtop(struct ieee80211_node *ni, u_int8_t *ie)
{
	struct ieee80211_ie_vhtop *rvhtop = (struct ieee80211_ie_vhtop *)ie;
	struct ieee80211vap *vap = ni->ni_vap;

	memcpy(&ni->ni_ie_vhtop, rvhtop, sizeof(ni->ni_ie_vhtop));

	ni->ni_vhtop.chanwidth = IEEE80211_VHTOP_GET_CHANWIDTH(rvhtop);
	ni->ni_vhtop.centerfreq0 = IEEE80211_VHTOP_GET_CENTERFREQ0(rvhtop);
	ni->ni_vhtop.centerfreq1 = IEEE80211_VHTOP_GET_CENTERFREQ1(rvhtop);
	ni->ni_vhtop.basicvhtmcsnssset = IEEE80211_VHTOP_GET_BASIC_MCS_NSS(rvhtop);

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
				"vht op: chan width: %d\n", ni->ni_vhtop.chanwidth);

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
				"vht op: center freq0: %d\n", ni->ni_vhtop.centerfreq0);


	IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
				"vht op: center freq1: %d\n", ni->ni_vhtop.centerfreq1);

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
				"vht op: basicvhtmcsnssset: 0x%08x\n", ni->ni_vhtop.basicvhtmcsnssset);
}

/*
static int
ieee80211_setup_vhtcap(struct ieee80211_node *ni, u_int8_t *ie)
{
	return 1;
}
*/

static int
ieee80211_setup_htcap(struct ieee80211_node *ni, u_int8_t *ie)
{
	struct ieee80211com *ic = ni->ni_ic;
	struct ieee80211_ie_htcap *htcap = (struct ieee80211_ie_htcap *)(void*) ie;
	struct ieee80211vap *vap = ni->ni_vap;
	int error = 0;
	u_int32_t flags = vap->iv_ht_flags;
	u_int16_t peer_cap = IEEE80211_HTCAP_CAPABILITIES(htcap);
	u_int16_t merged_cap = peer_cap & ic->ic_htcap.cap;

	/* save the original HT CAP IE */
	memcpy(&ni->ni_ie_htcap, htcap, sizeof(ni->ni_ie_htcap));
	/* Take the combination of IC and STA parameters */
	/* set HT capabilities */
	ni->ni_htcap.cap = 0;

	/* set channel width */
	if ((flags & IEEE80211_HTF_CBW_40MHZ_ONLY)
			&& !(peer_cap & IEEE80211_HTCAP_C_CHWIDTH40))
		error |= 0x0001;
	else
		ni->ni_htcap.cap |= (peer_cap & IEEE80211_HTCAP_C_CHWIDTH40);

	/* set power save mode */
	/* NOTE: only ever called when we're running as an AP - take the SM power save as
	 * being what the client advertises, NOT what the AP wants.
	 */
	{
		int pwrsave = IEEE80211_HTCAP_PWRSAVE_MODE(htcap);

		if (pwrsave == IEEE80211_HTCAP_C_MIMOPWRSAVE_NA)
		{
			/* Default to Dyanmic powersave if invalid value passed in the (re)association request */
			pwrsave = IEEE80211_HTCAP_C_MIMOPWRSAVE_NONE;
		}
		ni->ni_htcap.pwrsave = pwrsave;
	}

	/* set SHORT GI options */
	if ((flags & IEEE80211_HTF_SHORTGI20_ONLY) &&
			!(peer_cap & IEEE80211_HTCAP_C_SHORTGI20))
		error |= 0x0002;
	else
		ni->ni_htcap.cap |= (merged_cap & IEEE80211_HTCAP_C_SHORTGI20);

	if ((flags & IEEE80211_HTF_SHORTGI40_ONLY) &&
				!(peer_cap & IEEE80211_HTCAP_C_SHORTGI40))
		error |= 0x0004;
	else
		ni->ni_htcap.cap |= (merged_cap & IEEE80211_HTCAP_C_SHORTGI40);

	/* Set STBC options */
	if ((flags & IEEE80211_HTF_TXSTBC_ONLY) &&
				!(IEEE80211_HTCAP_RX_STBC_MODE(htcap)))
		error |= 0x0008;
	else {
		if ((vap->iv_ht_flags & IEEE80211_HTF_STBC_ENABLED) &&
								IEEE80211_HTCAP_RX_STBC_MODE(htcap))
			ni->ni_htcap.cap |= IEEE80211_HTCAP_C_TXSTBC;
	}

	if ((flags & IEEE80211_HTF_RXSTBC_ONLY) &&
					!(peer_cap & IEEE80211_HTCAP_C_TXSTBC))
		error |= 0x0010;
	else {
		if (vap->iv_ht_flags & IEEE80211_HTF_STBC_ENABLED) {
			ni->ni_htcap.numrxstbcstr = IEEE80211_HTCAP_RX_STBC_MODE(htcap);
			/* If STA is capable of receive more streams then we support for tx,
			   then limit our transmission to what we support */
			ni->ni_htcap.numrxstbcstr = (ni->ni_htcap.numrxstbcstr > IEEE80211_MAX_TX_STBC_SS) ?
						IEEE80211_MAX_TX_STBC_SS : ni->ni_htcap.numrxstbcstr;
		}
		else
			ni->ni_htcap.numrxstbcstr = 0;
	}

	if (IEEE80211_HTCAP_RX_STBC_MODE(htcap)) {
		ni->ni_htcap.cap |= IEEE80211_HTCAP_C_RXSTBC;
	}

	/* delayed block ack */
	ni->ni_htcap.cap |= (peer_cap & IEEE80211_HTCAP_C_DELAYEDBLKACK);

	/* Maximum A-MSDU size */
	if (peer_cap & IEEE80211_HTCAP_C_MAXAMSDUSIZE_8K)
		ni->ni_htcap.maxmsdu = 7935;
	else
		ni->ni_htcap.maxmsdu = 3839;

	/* DSSS/CCK mode in 40 MHz */
	if (flags & IEEE80211_HTF_DSSS_40MHZ_ONLY) {
		if (!(peer_cap & IEEE80211_HTCAP_C_DSSSCCK40))
			error |= 0x0020;
	}
	ni->ni_htcap.cap |= (peer_cap & IEEE80211_HTCAP_C_DSSSCCK40);

	/* PSMP support (only if AP supports) */
	if ((flags & IEEE80211_HTF_PSMP_SUPPORT_ONLY)
				&& !(peer_cap & IEEE80211_HTCAP_C_PSMP))
		error |= 0x0040;
	else
		ni->ni_htcap.cap |= (peer_cap & IEEE80211_HTCAP_C_PSMP);

	/* set 40 MHz intolerant */
	ni->ni_htcap.cap |= (peer_cap & IEEE80211_HTCAP_C_40_INTOLERANT);

	/* set L-SIG TXOP support */
	if ((flags & IEEE80211_HTF_LSIG_TXOP_ONLY)
					&& !(peer_cap & IEEE80211_HTCAP_C_LSIGTXOPPROT))
		error |= 0x0080;
	else
		ni->ni_htcap.cap |= (peer_cap & IEEE80211_HTCAP_C_LSIGTXOPPROT);

	/* set maximum A-MPDU size */
	ni->ni_htcap.maxampdu = IEEE80211_HTCAP_MAX_AMPDU_LEN(htcap);

	/* set maximum MPDU spacing */
	ni->ni_htcap.mpduspacing = IEEE80211_HTCAP_MIN_AMPDU_SPACING(htcap);

	/* set MCS rate indexes */
	ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_NSS1] =
		IEEE80211_HTCAP_MCS_VALUE(htcap,IEEE80211_HT_MCSSET_20_40_NSS1);
	ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_NSS2] =
		IEEE80211_HTCAP_MCS_VALUE(htcap,IEEE80211_HT_MCSSET_20_40_NSS2);
	ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_NSS3] =
		IEEE80211_HTCAP_MCS_VALUE(htcap,IEEE80211_HT_MCSSET_20_40_NSS3);
	ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_NSS4] =
		IEEE80211_HTCAP_MCS_VALUE(htcap,IEEE80211_HT_MCSSET_20_40_NSS4);
	ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_UEQM1] =
		IEEE80211_HTCAP_MCS_VALUE(htcap,IEEE80211_HT_MCSSET_20_40_UEQM1);
	ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_UEQM2] =
		IEEE80211_HTCAP_MCS_VALUE(htcap,IEEE80211_HT_MCSSET_20_40_UEQM2);
	ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_UEQM3] =
		IEEE80211_HTCAP_MCS_VALUE(htcap,IEEE80211_HT_MCSSET_20_40_UEQM3);
	ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_UEQM4] =
		IEEE80211_HTCAP_MCS_VALUE(htcap,IEEE80211_HT_MCSSET_20_40_UEQM4);
	ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_UEQM5] =
		IEEE80211_HTCAP_MCS_VALUE(htcap,IEEE80211_HT_MCSSET_20_40_UEQM5);
	ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_UEQM6] =
		IEEE80211_HTCAP_MCS_VALUE(htcap,IEEE80211_HT_MCSSET_20_40_UEQM6);

	/* set maximum data rate */
	ni->ni_htcap.maxdatarate = IEEE80211_HTCAP_HIGHEST_DATA_RATE(htcap);

	/* set MCS parameters */
	ni->ni_htcap.mcsparams = 0;

	if (IEEE80211_HTCAP_MCS_PARAMS(htcap) & IEEE80211_HTCAP_MCS_TX_SET_DEFINED)
	{
		ni->ni_htcap.mcsparams |= IEEE80211_HTCAP_MCS_TX_SET_DEFINED;

		/* set number of Tx spatial streams */
		if(IEEE80211_HTCAP_MCS_PARAMS(htcap) & IEEE80211_HTCAP_MCS_TX_RX_SET_NEQ)
		{
			ni->ni_htcap.numtxspstr = IEEE80211_HTCAP_MCS_STREAMS(htcap);
			ni->ni_htcap.mcsparams |= IEEE80211_HTCAP_MCS_TX_RX_SET_NEQ |
				(IEEE80211_HTCAP_MCS_PARAMS(htcap) & IEEE80211_HTCAP_MCS_TX_UNEQ_MOD);
		}
		else
			ni->ni_htcap.numtxspstr = 0;
	}
	else
		ni->ni_htcap.numtxspstr = 0;

	if ((flags & IEEE80211_HTF_LDPC_ENABLED) &&
			(peer_cap & IEEE80211_HTCAP_C_LDPCCODING)) {
		ni->ni_htcap.cap |= IEEE80211_HTCAP_C_LDPCCODING;
	}

	if ((flags & IEEE80211_HTF_NSS_2_ONLY) && (ni->ni_htcap.numrxstbcstr < 2))
		error |= 0x0100;

	if (ni->ni_vendor != PEER_VENDOR_RLNK) {
		ni->ni_htcap.hc_txbf[0] = ic->ic_htcap.hc_txbf[0] & htcap->hc_txbf[0];
		ni->ni_htcap.hc_txbf[1] = ic->ic_htcap.hc_txbf[1] & htcap->hc_txbf[1];
		ni->ni_htcap.hc_txbf[2] = ic->ic_htcap.hc_txbf[2] & htcap->hc_txbf[2];
		ni->ni_htcap.hc_txbf[3] = ic->ic_htcap.hc_txbf[3] & htcap->hc_txbf[3];
	}

	return error;
}

static inline int ieee80211_ssid_compare(struct ieee80211vap *vap, struct ieee80211_scanparams *p_scan)
{
	return ((vap->iv_des_ssid[0].len != p_scan->ssid[1]) ||
		(memcmp(vap->iv_des_ssid[0].ssid, p_scan->ssid + 2, p_scan->ssid[1]) != 0));
}

static int ieee80211_assoc_reject_prepare_send_event(struct ieee80211vap *vap, uint16_t reason_code,
					uint8_t *bssid,
					struct ieee80211_neighbor_report_trans_item *nr_item)
{
	struct qtn_assoc_reject_event_data *assocrej_evt_data;
	uint8_t	event_data[IEEE80211_MAX_EXT_EVENT_DATA_LEN];
	union iwreq_data wreq;

	if (!vap)
		return 0;

	memset(event_data, 0, sizeof(event_data));
	assocrej_evt_data = (struct qtn_assoc_reject_event_data *)event_data;

	strncpy(assocrej_evt_data->name, "ASSOCREJECT", sizeof(assocrej_evt_data->name));
	assocrej_evt_data->reason_code = reason_code;
	if (bssid)
		memcpy(assocrej_evt_data->bssid, bssid, IEEE80211_ADDR_LEN);

	if (nr_item)
		memcpy(&assocrej_evt_data->nr_item, nr_item,
						sizeof(assocrej_evt_data->nr_item));

	memset(&wreq, 0, sizeof(wreq));
	wreq.data.length = sizeof(*assocrej_evt_data);
	wireless_send_event(vap->iv_dev, IWEVCUSTOM, &wreq, (char *)&event_data);

	return 0;
}

static int ieee80211_auth_prepare_send_event(struct ieee80211vap *vap, uint16_t reason_code,
					uint8_t *bssid,
					struct ieee80211_neighbor_report_trans_item *nr_item)
{
	struct qtn_auth_event_data *auth_evt_data;
	uint8_t	event_data[IEEE80211_MAX_EXT_EVENT_DATA_LEN];
	union iwreq_data wreq;

	if (!vap)
		return 0;

	memset(event_data, 0, sizeof(event_data));
	auth_evt_data = (struct qtn_auth_event_data *)event_data;

	strncpy(auth_evt_data->name, "AUTHREJECT", sizeof(auth_evt_data->name));
	auth_evt_data->reason_code = reason_code;
	if (bssid)
		memcpy(auth_evt_data->bssid, bssid, IEEE80211_ADDR_LEN);

	if (nr_item)
		memcpy(&auth_evt_data->nr_item, nr_item,
						sizeof(auth_evt_data->nr_item));

	memset(&wreq, 0, sizeof(wreq));
	wreq.data.length = sizeof(*auth_evt_data);
	wireless_send_event(vap->iv_dev, IWEVCUSTOM, &wreq, (char *)&event_data);

	return 0;
}


static int ieee80211_deauth_send_event(struct ieee80211vap *vap, uint16_t reason_code,
							uint8_t *addr)
{
	struct qtn_deauth_event_data *deauth_evt_data;
	uint8_t	event_data[IEEE80211_MAX_EXT_EVENT_DATA_LEN];
	union iwreq_data wreq;

	if (!vap)
		return 0;

	memset(event_data, 0, sizeof(event_data));
	deauth_evt_data = (struct qtn_deauth_event_data *)event_data;

	strncpy(deauth_evt_data->name, "DEAUTH", sizeof(deauth_evt_data->name));
	deauth_evt_data->reason_code = reason_code;
	if (addr)
		memcpy(deauth_evt_data->addr, addr, IEEE80211_ADDR_LEN);

	memset(&wreq, 0, sizeof(wreq));
	wreq.data.length = sizeof(*deauth_evt_data);
	wireless_send_event(vap->iv_dev, IWEVCUSTOM, &wreq, (char *)&event_data);

	return 0;
}


void extender_event_data_prepare(struct ieee80211com *ic,
			struct ieee80211_scanparams *p_scan,
			struct qtn_wds_ext_event_data *data,
			uint8_t cmd,
			uint8_t *peer_mac)
{
	memset(data, 0, sizeof(struct qtn_wds_ext_event_data));
	strncpy(data->name, "QTN-WDS-EXT", sizeof(data->name) - 1);
	data->cmd = cmd;
	data->extender_role = ic->ic_extender_role;
	data->bandwidth = ic->ic_extender_rbs_bw;
	if (peer_mac)
		memcpy(data->mac, peer_mac, IEEE80211_ADDR_LEN);
	if (p_scan)
		data->channel = p_scan->bchan;
}

int ieee80211_extender_send_event(
	struct ieee80211vap *vap,
	const struct qtn_wds_ext_event_data *p_data, uint8_t *ie)
{
	struct qtn_wds_ext_event_data *wds_event_data;
	uint8_t	event_data[IEEE80211_MAX_EXT_EVENT_DATA_LEN];
	union iwreq_data wreq;

	if (!vap)
		return 0;

	memset(event_data, 0, sizeof(event_data));
	wds_event_data = (struct qtn_wds_ext_event_data *)event_data;

	if (sizeof(*p_data) > sizeof(event_data))
		return 0;
	memcpy(wds_event_data, p_data, sizeof(*p_data));

	if ((wds_event_data->cmd != WDS_EXT_LINK_STATUS_UPDATE) && ie) {
		wds_event_data->ie_len = ie[1] + 2;
		if ((sizeof(*p_data) + wds_event_data->ie_len) > sizeof(event_data))
			return 0;
		memcpy(event_data + sizeof(*p_data), ie, wds_event_data->ie_len);
	}

	memset(&wreq, 0, sizeof(wreq));
	wreq.data.length = sizeof(*wds_event_data) + (ie ? wds_event_data->ie_len : 0);
	wireless_send_event(vap->iv_dev, IWEVCUSTOM, &wreq, (char *)&event_data);

	return 0;
}

struct ieee80211_extender_wds_info *
ieee80211_extender_find_peer_wds_info(struct ieee80211com *ic, uint8_t *mac_addr)
{
	struct ieee80211_extender_wds_info *peer_wds = NULL;
	struct ieee80211vap *primary_vap = ieee80211_get_primary_vap(ic, 1);
	unsigned long flags;
	int hash;

	if (!primary_vap)
		return NULL;

	hash = IEEE80211_NODE_HASH(mac_addr);
	spin_lock_irqsave(&primary_vap->iv_extender_wds_lock, flags);
	LIST_FOREACH(peer_wds, &primary_vap->iv_extender_wds_hash[hash], peer_wds_hash) {
		if (IEEE80211_ADDR_EQ(mac_addr, peer_wds->peer_addr)) {
			break;
		}
	}
	spin_unlock_irqrestore(&primary_vap->iv_extender_wds_lock, flags);

	return peer_wds;
}

static struct ieee80211_extender_wds_info*
ieee80211_extender_create_peer_wds_info(struct ieee80211com *ic, uint8_t *mac_addr)
{
	struct ieee80211_extender_wds_info *peer_wds = NULL;
	struct ieee80211vap *primary_vap = ieee80211_get_primary_vap(ic, 1);
	unsigned long flags;
	int update_beacon = 0;
	int rbs_num = 0;
	int hash;
	int i;

	if (!primary_vap)
		return NULL;

	MALLOC(peer_wds, struct ieee80211_extender_wds_info *, sizeof(*peer_wds),
		M_DEVBUF, M_WAITOK);
	if (peer_wds) {
		hash = IEEE80211_NODE_HASH(mac_addr);
		memcpy(peer_wds->peer_addr, mac_addr, IEEE80211_ADDR_LEN);
		spin_lock_irqsave(&primary_vap->iv_extender_wds_lock, flags);
		LIST_INSERT_HEAD(&primary_vap->iv_extender_wds_hash[hash], peer_wds, peer_wds_hash);
		if ((ic->ic_extender_role == IEEE80211_EXTENDER_ROLE_MBS) &&
				(ic->ic_extender_rbs_num < QTN_MAX_RBS_NUM)) {
			for(i=0; i<QTN_MAX_RBS_NUM; i++) {
				if (is_zero_ether_addr(ic->ic_extender_rbs_bssid[i])) {
					IEEE80211_ADDR_COPY(ic->ic_extender_rbs_bssid[i], mac_addr);
					update_beacon = 1;
					break;
				}
			}

			for(i=0; i<QTN_MAX_RBS_NUM; i++) {
				if (!is_zero_ether_addr(ic->ic_extender_rbs_bssid[i]))
				      rbs_num++;
			}
			ic->ic_extender_rbs_num = rbs_num;
		}
		spin_unlock_irqrestore(&primary_vap->iv_extender_wds_lock, flags);

		if (ic->ic_extender_role == IEEE80211_EXTENDER_ROLE_RBS)
			IEEE80211_ADDR_COPY(ic->ic_extender_mbs_bssid, mac_addr);

		IEEE80211_EXTENDER_DPRINTF(primary_vap, IEEE80211_EXTENDER_MSG_DBG,
				"EXTENDER %s: add wds peer [%pM]\n", __func__,
				peer_wds->peer_addr);

		if (update_beacon)
			ic->ic_beacon_update(primary_vap);

		peer_wds->role_loss = 0;
	}
	return peer_wds;
}

int
ieee80211_extender_remove_peer_wds_info(struct ieee80211com *ic,
	uint8_t *mac_addr)
{
	struct ieee80211_extender_wds_info *peer_wds = NULL;
	struct ieee80211_extender_wds_info *peer_wds_tmp = NULL;
	struct ieee80211vap *primary_vap = ieee80211_get_primary_vap(ic, 1);
	unsigned long flags;
	int update_beacon = 0;
	int rbs_num = 0;
	int hash;
	int i;

	if (!primary_vap)
		return 0;

	hash = IEEE80211_NODE_HASH(mac_addr);
	spin_lock_irqsave(&primary_vap->iv_extender_wds_lock, flags);
	LIST_FOREACH_SAFE(peer_wds, &primary_vap->iv_extender_wds_hash[hash], peer_wds_hash, peer_wds_tmp) {
		if (IEEE80211_ADDR_EQ(mac_addr, peer_wds->peer_addr)) {
			LIST_REMOVE(peer_wds, peer_wds_hash);
			FREE(peer_wds, M_DEVBUF);

			if ((ic->ic_extender_role == IEEE80211_EXTENDER_ROLE_MBS) &&
					(ic->ic_extender_rbs_num > 0)) {
				for(i=0; i<QTN_MAX_RBS_NUM; i++) {
					if (IEEE80211_ADDR_EQ(ic->ic_extender_rbs_bssid[i], mac_addr)) {
						IEEE80211_ADDR_SET_NULL(ic->ic_extender_rbs_bssid[i]);
						update_beacon = 1;
						break;
					}
				}

				for(i=0; i<QTN_MAX_RBS_NUM; i++) {
					if (!is_zero_ether_addr(ic->ic_extender_rbs_bssid[i]))
					      rbs_num++;
				}
				ic->ic_extender_rbs_num = rbs_num;
			} else if (ic->ic_extender_role == IEEE80211_EXTENDER_ROLE_RBS) {
				IEEE80211_ADDR_SET_NULL(ic->ic_extender_mbs_bssid);
				ic->ic_extender_rbs_num = 0;
				for(i=0; i<QTN_MAX_RBS_NUM; i++)
					IEEE80211_ADDR_SET_NULL(ic->ic_extender_rbs_bssid[i]);
				update_beacon = (primary_vap->iv_opmode == IEEE80211_M_HOSTAP);
			}

			break;
		}
	}
	spin_unlock_irqrestore(&primary_vap->iv_extender_wds_lock, flags);

	if (update_beacon)
		ic->ic_beacon_update(primary_vap);

	return 0;
}

void
ieee80211_extender_notify_ext_role(struct ieee80211_node *ni)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct qtn_wds_ext_event_data extender_event_data;
	struct ieee80211_qtn_ext_bssid *ext_bssid_ie =
		(struct ieee80211_qtn_ext_bssid *)ni->ni_ext_bssid_ie;
	int i;

	memset(&extender_event_data, 0, sizeof(extender_event_data));
	extender_event_data.cmd = WDS_EXT_STA_UPDATE_EXT_INFO;
	extender_event_data.extender_role = ni->ni_ext_role;
	strncpy(extender_event_data.name, "QTN-WDS-EXT", sizeof(extender_event_data.name));
	memcpy(extender_event_data.mac, ni->ni_bssid, IEEE80211_ADDR_LEN);

	if (ext_bssid_ie) {
		IEEE80211_EXTENDER_DPRINTF(vap, IEEE80211_EXTENDER_MSG_DBG,
			"EXTENDER %s: trigger role info upate event, extender role [%u], "
			"mbs address [%pM], rbs num %u, rbs address: \n", __func__, ni->ni_ext_role,
			ext_bssid_ie->mbs_bssid, ext_bssid_ie->rbs_num);
		for (i=0; i<QTN_MAX_RBS_NUM; i++) {
			if (!is_zero_ether_addr(ext_bssid_ie->rbs_bssid[i])) {
				IEEE80211_EXTENDER_DPRINTF(vap, IEEE80211_EXTENDER_MSG_DBG, "%pM\n",
						ext_bssid_ie->rbs_bssid[i]);
			}
		}
	} else {
		IEEE80211_EXTENDER_DPRINTF(vap, IEEE80211_EXTENDER_MSG_DBG, "EXTENDER %s: "
			"trigger role info upate event, extender role: none\n", __func__);
	}

	ieee80211_extender_send_event(vap, &extender_event_data, (uint8_t *)ext_bssid_ie);
}

void
ieee80211_extender_sta_update_info(struct ieee80211_node *ni,
		const struct ieee80211_qtn_ext_role *ie_role,
		const struct ieee80211_qtn_ext_bssid *ie_bssid)
{
	struct ieee80211vap *vap = ni->ni_vap;
	int update = 0;
	if ((ni == vap->iv_bss) && (ni->ni_flags & IEEE80211_NODE_AUTH)) {
		if (ie_role) {
			if (ni->ni_ext_role != ie_role->role) {
				ni->ni_ext_role = ie_role->role;
				update = 1;
			}
		} else {
			if (ni->ni_ext_role != IEEE80211_EXTENDER_ROLE_NONE) {
				ni->ni_ext_role = IEEE80211_EXTENDER_ROLE_NONE;
				update = 1;
			}
		}

		if (ie_bssid) {
			if (!ni->ni_ext_bssid_ie || memcmp(ie_bssid, ni->ni_ext_bssid_ie, sizeof(*ie_bssid))) {
				ieee80211_saveie(&ni->ni_ext_bssid_ie, (uint8_t *)ie_bssid);
				update = 1;
			}
		} else {
			if (ni->ni_ext_bssid_ie != NULL) {
				FREE(ni->ni_ext_bssid_ie, M_DEVBUF);
				ni->ni_ext_bssid_ie = NULL;
				update = 1;
			}
		}

		if (update)
			ieee80211_extender_notify_ext_role(ni);
	}
}

void
ieee80211_extender_vdetach(struct ieee80211vap *vap)
{
	int i;
	unsigned long flags;
	struct ieee80211_extender_wds_info *peer_wds = NULL;
	struct ieee80211_extender_wds_info *peer_wds_tmp = NULL;

	spin_lock_irqsave(&vap->iv_extender_wds_lock, flags);
	for (i = 0; i < IEEE80211_NODE_HASHSIZE; i++) {
		LIST_FOREACH_SAFE(peer_wds, &vap->iv_extender_wds_hash[i], peer_wds_hash, peer_wds_tmp) {
			LIST_REMOVE(peer_wds, peer_wds_hash);
			FREE(peer_wds, M_DEVBUF);
		}
	}
	spin_unlock_irqrestore(&vap->iv_extender_wds_lock, flags);
}

static int extender_role_to_event_cmd(uint8_t role)
{
	if (role == IEEE80211_EXTENDER_ROLE_MBS)
		return WDS_EXT_RECEIVED_MBS_IE;
	else
		return WDS_EXT_RECEIVED_RBS_IE;
}

void ieee80211_extender_cleanup_wds_link(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211vap *pri_vap = ieee80211_get_primary_vap(ic, 1);
	struct ieee80211_extender_wds_info *peer_wds = NULL;
	struct ieee80211_extender_wds_info *peer_wds_tmp = NULL;
	struct qtn_wds_ext_event_data event_data;
	unsigned long flags;
	int i;

	if (!pri_vap)
		return;

	spin_lock_irqsave(&vap->iv_extender_wds_lock, flags);
	for (i = 0; i < IEEE80211_NODE_HASHSIZE; i++) {
		LIST_FOREACH_SAFE(peer_wds, &vap->iv_extender_wds_hash[i], peer_wds_hash, peer_wds_tmp) {
			extender_event_data_prepare(ic, NULL,
					&event_data,
					WDS_EXT_CLEANUP_WDS_LINK,
					peer_wds->peer_addr);
			ieee80211_extender_send_event(pri_vap, &event_data, NULL);
			LIST_REMOVE(peer_wds, peer_wds_hash);
			FREE(peer_wds, M_DEVBUF);
		}
	}
	spin_unlock_irqrestore(&vap->iv_extender_wds_lock, flags);
}

void ieee80211_extender_save_peer_ies(struct ieee80211_scanparams *scan,
			struct ieee80211_extender_wds_info *peer)
{
	if (scan->qtn != NULL) {
		/* different version of QTN IE has different length */
		if (sizeof(peer->ie_qtn_assoc) >= (scan->qtn[1] + 2))
			memcpy(&peer->ie_qtn_assoc, scan->qtn, scan->qtn[1] + 2);
	} else {
		memset(&peer->ie_qtn_assoc, 0, sizeof(peer->ie_qtn_assoc));
	}

	if (scan->htcap != NULL)
		memcpy(&peer->ie_htcap, scan->htcap, sizeof(peer->ie_htcap));
	else
		memset(&peer->ie_htcap, 0, sizeof(peer->ie_htcap));

	if (scan->htinfo != NULL)
		memcpy(&peer->ie_htinfo, scan->htinfo, sizeof(peer->ie_htinfo));
	else
		memset(&peer->ie_htinfo, 0, sizeof(peer->ie_htinfo));

	if (scan->vhtcap != NULL)
		memcpy(&peer->ie_vhtcap, scan->vhtcap, sizeof(peer->ie_vhtcap));
	else
		memset(&peer->ie_vhtcap, 0, sizeof(peer->ie_vhtcap));

	if (scan->vhtop != NULL)
		memcpy(&peer->ie_vhtop, scan->vhtop, sizeof(peer->ie_vhtop));
	else
		memset(&peer->ie_vhtop, 0, sizeof(peer->ie_vhtop));
}

void ieee80211_extender_restore_peer_ies(struct ieee80211_node *ni)
{
	struct ieee80211com *ic;
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211_extender_wds_info *peer;

	if (vap == NULL)
		return;
	ic = vap->iv_ic;

	peer = ieee80211_extender_find_peer_wds_info(ic, ni->ni_macaddr);
	/* it is possible that peer info not found, e.g., WDS case */
	if (peer == NULL)
		return;

	if (peer->ie_qtn_assoc.qtn_ie_id == IEEE80211_ELEMID_VENDOR)
		ieee80211_saveie(&ni->ni_qtn_assoc_ie, (u_int8_t *)&peer->ie_qtn_assoc);

	if (peer->ie_htcap.hc_id == IEEE80211_ELEMID_HTCAP)
		ieee80211_parse_htcap(ni, (u_int8_t *)&peer->ie_htcap);

	if (peer->ie_htinfo.hi_id == IEEE80211_ELEMID_HTINFO)
		ieee80211_parse_htinfo(ni, (u_int8_t *)&peer->ie_htinfo);

	if (IS_IEEE80211_VHT_ENABLED(ic)) {
		/* VHTCAP IE valid: peer supports VHT */
		if (peer->ie_vhtcap.vht_id == IEEE80211_ELEMID_VHTCAP) {
			ni->ni_flags |= IEEE80211_NODE_VHT;
			ieee80211_parse_vhtcap(ni, (u_int8_t *)&peer->ie_vhtcap);
		}

		if (peer->ie_vhtop.vhtop_id == IEEE80211_ELEMID_VHTOP)
			ieee80211_parse_vhtop(ni, (u_int8_t *)&peer->ie_vhtop);
	}
}

static int extender_check_rssi_change(struct ieee80211com *ic,
		struct ieee80211vap *vap, int rssi)
{
	if (vap->iv_opmode == IEEE80211_M_STA) {
		if (rssi <= ic->ic_extender_mbs_best_rssi) {
			ic->ic_extender_rssi_continue = 0;
			return 0;
		}
	} else {
		if (rssi >= ic->ic_extender_mbs_best_rssi - ic->ic_extender_mbs_rssi_margin) {
			ic->ic_extender_rssi_continue = 0;
			return 0;
		}
	}

	if (ic->ic_extender_rssi_continue++ < QTN_EXTENDER_RSSI_MAX_COUNT)
		return 0;

	ic->ic_extender_rssi_continue = 0;

	return 1;
}

static int ieee80211_trigger_extender_event(
	struct ieee80211vap *vap,
	const struct ieee80211_qtn_ext_role *ie,
	struct ieee80211_scanparams *p_scan,
	struct ieee80211_frame *wh,
	int rssi)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_extender_wds_info *peer_wds = NULL;
	struct qtn_wds_ext_event_data extender_event_data;

	peer_wds = ieee80211_extender_find_peer_wds_info(ic, wh->i_addr2);
	if (peer_wds) {
		if (memcmp(&peer_wds->extender_ie, ie, sizeof(*ie)) == 0)
			return 0;
	} else {
		if (vap->iv_opmode == IEEE80211_M_STA &&
				extender_check_rssi_change(ic, vap, rssi) == 0)
			return 0;

		peer_wds = ieee80211_extender_create_peer_wds_info(ic, wh->i_addr2);
		if (!peer_wds)
			return 0;
	}

	memcpy(&peer_wds->extender_ie, ie, sizeof(*ie));
	/*
	 * Save interested Information Elements of peer so that they can be
	 * used after peer node is created. See "ieee80211_create_wds_node".
	 */
	ieee80211_extender_save_peer_ies(p_scan, peer_wds);

	extender_event_data_prepare(ic, p_scan,
				&extender_event_data,
				extender_role_to_event_cmd(ie->role),
				wh->i_addr2);

	if ((p_scan->ssid != NULL) && (p_scan->ssid[1] > 0)) {
		if (p_scan->ssid[1] < sizeof(extender_event_data.ssid)) {
			memcpy(extender_event_data.ssid, p_scan->ssid + 2, p_scan->ssid[1]);
		} else {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_ELEMID, "%s : ssid is too long\n", __func__);
			memcpy(extender_event_data.ssid, p_scan->ssid + 2, sizeof(extender_event_data.ssid) - 1);
		}
	}

	ieee80211_extender_send_event(vap, &extender_event_data, (uint8_t *)ie);
	return 0;
}

static void ieee80211_extender_update_rbs_macs(struct ieee80211com *ic,
		const struct ieee80211_qtn_ext_role *ie_role,
		const struct ieee80211_qtn_ext_bssid *ie_bssid,
		const struct ieee80211_qtn_ext_state *ie_state)
{
	struct ieee80211vap *primary_vap = ieee80211_get_primary_vap(ic, 1);
	uint8_t ext_role = ie_role->role;
	int update_beacon = 0;

	if (!primary_vap)
		return;

	if (ic->ic_extender_role != IEEE80211_EXTENDER_ROLE_RBS)
		return;

	if (!ie_bssid || (ie_bssid->len < (sizeof(struct ieee80211_qtn_ext_bssid) - 2)))
		return;

	if (ext_role == IEEE80211_EXTENDER_ROLE_MBS) {
		if (memcmp(ic->ic_extender_mbs_bssid,
				ie_bssid->mbs_bssid, sizeof(ic->ic_extender_mbs_bssid))) {
			memcpy(ic->ic_extender_mbs_bssid,
				ie_bssid->mbs_bssid, sizeof(ic->ic_extender_mbs_bssid));
			update_beacon = 1;
		}

		if ((ic->ic_extender_rbs_num != ie_bssid->rbs_num) ||
				memcmp(ic->ic_extender_rbs_bssid[0],
					ie_bssid->rbs_bssid[0], sizeof(ic->ic_extender_rbs_bssid))) {
			ic->ic_extender_rbs_num = ie_bssid->rbs_num;
			memcpy(ic->ic_extender_rbs_bssid[0],
				ie_bssid->rbs_bssid[0], sizeof(ic->ic_extender_rbs_bssid));
			update_beacon = 1;
		}

		if (ie_state && !!(ie_state->state1 & QTN_EXT_MBS_OCAC) != ic->ic_extender_mbs_ocac) {
			ic->ic_extender_mbs_ocac = !!(ie_state->state1 & QTN_EXT_MBS_OCAC);
			update_beacon = 2;
		}
	}

	if (update_beacon == 1)
		ic->ic_beacon_update(primary_vap);
	else if (update_beacon == 2)
		ieee80211_beacon_update_all(ic);
}

static int
ieee80211_get_max_bandwidth(struct ieee80211com *ic, uint8_t channel)
{
	int max_glob_bw;
	int max_chan_bw;

	max_glob_bw = ieee80211_get_max_system_bw(ic);
	max_chan_bw = ieee80211_get_max_channel_bw(ic, channel);

	return MIN(max_glob_bw, max_chan_bw);
}

static int
ieee80211_parse_peer_bandwidth(u_int8_t *vhtop, u_int8_t *htinfo)
{
	if (vhtop != NULL) {
		struct ieee80211_ie_vhtop *vht_op = (struct ieee80211_ie_vhtop *)vhtop;

		/*
		 * Channel Width
		 */
		if (IEEE80211_VHTOP_GET_CHANWIDTH(vht_op))
			return BW_HT80;
	}

	if (htinfo != NULL) {
		struct ieee80211_ie_htinfo *ht_info = (struct ieee80211_ie_htinfo *)htinfo;

		/*
		 * Secondary Channel Offset
		 */
		if (IEEE80211_HTINFO_B1_EXT_CHOFFSET(ht_info))
			return BW_HT40;
	}

	return BW_HT20;
}

static int
ieee80211_parse_qtn_extender_ie(
	struct ieee80211_node *ni,
	const struct ieee80211_qtn_ext_role *ie,
	const struct ieee80211_qtn_ext_bssid *ext_bssid_ie,
	const struct ieee80211_qtn_ext_state *ie_state,
	struct ieee80211_scanparams *p_scan,
	struct ieee80211_frame *wh,
	int rssi)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211vap *primary_vap;
	struct ieee80211_extender_wds_info *peer_wds = NULL;
	struct qtn_wds_ext_event_data event_data;

	uint32_t mbs_bw;
	uint32_t rbs_bw;

	if (ie->len < (sizeof(*ie) - 2))
		return -1;

	p_scan->extender_role = ie->role;

	switch(vap->iv_opmode) {
	case IEEE80211_M_STA:
		if ((ic->ic_extender_role == IEEE80211_EXTENDER_ROLE_RBS) &&
				(ie->role == IEEE80211_EXTENDER_ROLE_MBS)) {
			if ((ni->ni_associd == 0) ||
					(vap->iv_state != IEEE80211_S_RUN) ||
					!(ni->ni_flags & IEEE80211_NODE_AUTH) ||
					!IEEE80211_ADDR_EQ(wh->i_addr2, ni->ni_bssid))
				return 0;
			/* need to verify the essid in the frame is the same to our */
			if ((p_scan->ssid == NULL) || (p_scan->ssid[1] == 0)) {
				return 0;
			} else {
				if (ieee80211_ssid_compare(vap, p_scan))
				return 0;
			}

			mbs_bw = ieee80211_parse_peer_bandwidth(p_scan->vhtop, p_scan->htinfo);
			rbs_bw = ieee80211_get_max_bandwidth(ic, p_scan->bchan);

			ic->ic_extender_rbs_bw = MIN(mbs_bw, rbs_bw);
			ieee80211_trigger_extender_event(vap, ie, p_scan, wh, rssi);
			ic->ic_extender_mbs_detected_jiffies = jiffies;
		}
		break;
	case IEEE80211_M_HOSTAP:
		if ((ic->ic_extender_role == IEEE80211_EXTENDER_ROLE_NONE))
			return 0;

		/* need to verify the essid in the frame is the same to our */
		if ((p_scan->ssid == NULL) || (p_scan->ssid[1] == 0)) {
			return 0;
		} else {
			if (ieee80211_ssid_compare(vap, p_scan))
				return 0;
		}

		if ((ic->ic_extender_role == IEEE80211_EXTENDER_ROLE_MBS &&
				ie->role == IEEE80211_EXTENDER_ROLE_RBS) ||
				(ic->ic_extender_role == IEEE80211_EXTENDER_ROLE_RBS &&
				ie->role == IEEE80211_EXTENDER_ROLE_MBS)) {
			if ((ni->ni_node_type == IEEE80211_NODE_TYPE_STA) &&
					(ie->role == IEEE80211_EXTENDER_ROLE_RBS)) {
				IEEE80211_EXTENDER_DPRINTF(vap,
						IEEE80211_EXTENDER_MSG_WARN,
						"QHop: peer %pM should disassociate first\n",
						wh->i_addr2);
				ieee80211_node_leave(ni);
			}
			/* ignore Beacon and Probe Response frames from other QHop networks */
			if (ext_bssid_ie != NULL) {
				if (IEEE80211_COM_WDS_IS_MBS(ic)) {
					/* ignore if we are NOT the announced MBS, or else we
					 * create WDS link for sender unexpectedly
					 */
					if (!IEEE80211_ADDR_EQ(ext_bssid_ie->mbs_bssid,
							vap->iv_myaddr))
						break;
				} else {
					/* ignore if we already use another MBS, or else we
					 * update MBS BSSID unexpectedly
					 */
					if (!IEEE80211_ADDR_EQ(ext_bssid_ie->mbs_bssid,
							ic->ic_extender_mbs_bssid)) {
						/* make an exception for RBS boots up as AP */
						if (!IEEE80211_ADDR_NULL(ic->ic_extender_mbs_bssid))
							break;
					}
				}
			}
			ieee80211_trigger_extender_event(vap, ie, p_scan, wh, 0);
			ic->ic_extender_mbs_detected_jiffies = jiffies;

			/* update extender bssid ie */
			if ((ic->ic_extender_role == IEEE80211_EXTENDER_ROLE_RBS) &&
					(ie->role == IEEE80211_EXTENDER_ROLE_MBS))
				ieee80211_extender_update_rbs_macs(ic, ie, ext_bssid_ie, ie_state);
		}
		break;
	case IEEE80211_M_WDS:
		if (ic->ic_extender_role != IEEE80211_EXTENDER_ROLE_RBS ||
			ie->role != IEEE80211_EXTENDER_ROLE_MBS ||
			!IEEE80211_ADDR_EQ(wh->i_addr2, vap->wds_mac)) {
			return 0;
		}
		primary_vap = ieee80211_get_primary_vap(ic, 1);
		if (!primary_vap)
			return 0;
		/* need to verify the essid in the frame is the same to our */

		if ((p_scan->ssid == NULL) || (p_scan->ssid[1] == 0)) {
			return 0;
		} else {
			if (ieee80211_ssid_compare(primary_vap, p_scan))
				return 0;
		}

		ic->ic_extender_mbs_detected_jiffies = jiffies;
		peer_wds = ieee80211_extender_find_peer_wds_info(ic, wh->i_addr2);
		if (!peer_wds) {
			peer_wds = ieee80211_extender_create_peer_wds_info(ic, wh->i_addr2);
			if (peer_wds)
				memcpy(&peer_wds->extender_ie, ie, sizeof(*ie));
		}

		/* update extender bssid ie */
		if ((ic->ic_extender_role == IEEE80211_EXTENDER_ROLE_RBS) &&
				(ie->role == IEEE80211_EXTENDER_ROLE_MBS))
			ieee80211_extender_update_rbs_macs(ic, ie, ext_bssid_ie, ie_state);

		if (unlikely(ic->ic_bsschan != IEEE80211_CHAN_ANYC &&
				ic->ic_bsschan != ic->ic_curchan)) {
			extender_event_data_prepare(ic, p_scan,
					&event_data,
					WDS_EXT_RBS_SET_CHANNEL,
					wh->i_addr2);
			ieee80211_extender_send_event(primary_vap, &event_data, NULL);
			return 0;
		}

		if (extender_check_rssi_change(ic, primary_vap, rssi)) {
			IEEE80211_EXTENDER_DPRINTF(vap, IEEE80211_EXTENDER_MSG_WARN,
					"QHop: MBS %pM rssi %d is out of BRR %u\n",
					wh->i_addr2, rssi, ic->ic_extender_mbs_best_rssi);
			extender_event_data_prepare(ic, NULL,
					&event_data,
					WDS_EXT_RBS_OUT_OF_BRR,
					wh->i_addr2);
			ieee80211_extender_send_event(primary_vap, &event_data, NULL);
			ieee80211_extender_remove_peer_wds_info(ic, wh->i_addr2);
			return 0;
		}
		break;
	default:
		break;
	}
	return 0;
}

static int ieee80211_extender_process(
	struct ieee80211_node *ni,
	const struct ieee80211_qtn_ext_role *ie_role,
	const struct ieee80211_qtn_ext_bssid *ie_bssid,
	const struct ieee80211_qtn_ext_state *ie_state,
	struct ieee80211_scanparams *p_scan,
	struct ieee80211_frame *wh,
	int rssi)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211vap *primary_vap = NULL;
	struct ieee80211_extender_wds_info *wds_info = NULL;
	struct qtn_wds_ext_event_data extender_event_data;

	p_scan->ext_bssid_ie = (uint8_t *)ie_bssid;

	if (ie_role) {
		ieee80211_parse_qtn_extender_ie(ni, ie_role, ie_bssid, ie_state, p_scan, wh, rssi);

		/* ignore Extender IE of non peer */
		if (vap->iv_opmode == IEEE80211_M_WDS) {
			wds_info = ieee80211_extender_find_peer_wds_info(ic, wh->i_addr2);
			/* loss counter reset */
			if (wds_info != NULL)
				wds_info->role_loss = 0;
		}
		/* TODO: logic optimization */
	} else {
		p_scan->extender_role = IEEE80211_EXTENDER_ROLE_NONE;
		if ((vap->iv_opmode == IEEE80211_M_HOSTAP) || (vap->iv_opmode == IEEE80211_M_WDS)) {
			primary_vap = ieee80211_get_primary_vap(ic, 1);
			if (!primary_vap)
				return 0;
			wds_info = ieee80211_extender_find_peer_wds_info(ic, wh->i_addr2);
			if (wds_info && (vap->iv_opmode == IEEE80211_M_WDS)) {
				/* for the sake of robustness */
				if (++wds_info->role_loss < ic->ic_extender_role_loss_thres) {
					IEEE80211_EXTENDER_DPRINTF(vap, IEEE80211_EXTENDER_MSG_DBG,
						"QHop: Extender IE of peer %pM missing %u\n",
						wh->i_addr2, wds_info->role_loss);
					return 0;
				}

				IEEE80211_EXTENDER_DPRINTF(vap, IEEE80211_EXTENDER_MSG_WARN,
						"QHop: Extender IE of peer %pM is missing\n",
						wh->i_addr2);
				extender_event_data_prepare(ic, NULL,
						&extender_event_data,
						WDS_EXT_LINK_STATUS_UPDATE,
						wh->i_addr2);
				ieee80211_extender_send_event(primary_vap, &extender_event_data, NULL);
				ieee80211_extender_remove_peer_wds_info(ic, wh->i_addr2);
			} else if (wds_info) {
				/* WDS link not created or already removed */
				IEEE80211_EXTENDER_DPRINTF(vap, IEEE80211_EXTENDER_MSG_WARN,
						"QHop: record info of addr %pM is removed\n",
						wh->i_addr2);
				ieee80211_extender_remove_peer_wds_info(ic, wh->i_addr2);
			}
		}
	}

	if (vap->iv_opmode == IEEE80211_M_STA)
		ieee80211_extender_sta_update_info(ni, ie_role, ie_bssid);

	return 0;
}

#ifndef ARTSMNG_SUPPORT
static void ieee80211_trigger_csa_bw_change(struct ieee80211com *ic)
{
	struct ieee80211vap *vap = TAILQ_FIRST(&ic->ic_vaps);

	if (ic->ic_csa_bw_change_pending) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH, "%s: updating bw to %u from csa\n",
					__func__, ic->ic_csa_bw);
		ieee80211_change_bw(vap, ic->ic_csa_bw, 1);
		ic->ic_csa_bw_change_pending = 0;
		ic->ic_csa_bw = ic->ic_bss_bw;
	}
}
#endif /* !ARTSMNG_SUPPORT */

void ieee80211_channel_switch_post(struct ieee80211com *ic)
{
	struct ieee80211vap *vap;

	ic->ic_prevchan = ic->ic_curchan;
	ic->ic_curchan = ic->ic_csa_chan;

	ic->ic_chan_switch_record(ic, ic->ic_csa_chan, IEEE80211_CSW_REASON_CSA);

	if (ic->ic_flags_qtn & IEEE80211_QTN_MONITOR)
		printk("switched to chan %u\n", ic->ic_csa_chan->ic_ieee);

	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
				"%s: switched to %d\n",
				__FUNCTION__, ic->ic_csa_chan->ic_ieee);
	}
}
EXPORT_SYMBOL(ieee80211_channel_switch_post);

static int
ieee80211_relay_csaie(struct ieee80211com *ic,
	struct ieee80211_channel* new_chan, uint8_t csa_mode, uint8_t csa_count)
{
	uint32_t flags = IEEE80211_CSA_F_ACTION;
	int ret;
	struct ieee80211vap *vap = ieee80211_get_primary_vap(ic, 1);

	if (!vap)
		return 0;

	if (csa_count)
		flags |= IEEE80211_CSA_F_BEACON;

	ret = ieee80211_enter_csa(ic, new_chan, NULL, IEEE80211_CSW_REASON_CSA,
			csa_count, csa_mode, flags);

	if (ret < 0) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
				"%s: fail to relay the CSA IE\n", __func__);
		return 0;
	}

	return 1;
}

static void ieee80211_dfs_trigger_channel_switch(unsigned long arg)
{
        struct ieee80211com *ic = (struct ieee80211com *)arg;

        ieee80211_finish_csa((unsigned long)ic);
	ic->ic_pm_reason = IEEE80211_PM_LEVEL_CSA_DFS_ACTION;
	ieee80211_pm_queue_work_custom(ic, BOARD_PM_WLAN_IDLE_TIMEOUT);
}

void
ieee80211_dfs_send_csa(struct ieee80211vap *vap, uint8_t new_chan)
{
	uint32_t flags = IEEE80211_CSA_F_ACTION | IEEE80211_CSA_F_BEACON;
	struct ieee80211_channel *c;

	c = ieee80211_doth_findchan(vap, new_chan);
	if (c == NULL) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
			"%s: channel %u lookup failed " "\n", __func__, new_chan);
		return;
	}

	ieee80211_enter_csa(vap->iv_ic, c, ieee80211_dfs_trigger_channel_switch,
		IEEE80211_CSW_REASON_DFS, vap->iv_ic->ic_dfs_csa_cnt,
		IEEE80211_CSA_MUST_STOP_TX, flags);
}
EXPORT_SYMBOL(ieee80211_dfs_send_csa);

static inline int
ieee80211_should_relay_csaie(struct ieee80211com *ic, struct ieee80211vap *vap)
{
	if (ic->ic_opmode == IEEE80211_M_HOSTAP && (IEEE80211_COM_WDS_IS_RBS(ic) ||
				IEEE80211_VAP_WDS_IS_RBS(vap))) {
		return true;
	}

	if (ieee80211_is_repeater(ic))
		return true;

	return false;
}

#if defined(PLATFORM_QFDR)
static DEFINE_TIMER(ieee80211_csa_otherband_timer, NULL, 0, 0);

static void ieee80211_csa_otherband_notify(unsigned long data)
{
	struct ieee80211vap *vap = (struct ieee80211vap *)data;
	struct ieee80211com *ic = vap->iv_ic;
	ic->ic_csa_count = 0;
	/* disassociate STA from RootAP */
	ieee80211_new_state(vap, IEEE80211_S_INIT, 0);
}
#endif

static qfdr_send_bss_info_hook_t qfdr_send_bss_info_hook = NULL;
void ieee80211_register_qfdr_send_bss_info_hook(qfdr_send_bss_info_hook_t hook)
{
	qfdr_send_bss_info_hook = hook;
}
EXPORT_SYMBOL(ieee80211_register_qfdr_send_bss_info_hook);

#define QTN_CSAIE_ERR_INVALID_IE	(-1)
#define QTN_CSAIE_ERR_CHAN_NOT_SUPP	(-2)
#define QTN_CSAIE_ERR_BSS_CHAN		(-3)
#define QTN_CSAIE_ERR_IDENTICAL_CHAN	(-4)
#define QTN_CSAIE_ERR_INVALID_MODE	(-5)
#define QTN_CSAIE_ERR_INVALID_BW	(-6)

#ifndef ARTSMNG_SUPPORT
static int
ieee80211_sta_handle_csa(struct ieee80211_node *ni,
	u_int8_t *csa_frm, u_int8_t *csa_tsf_frm)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_ie_csa *csa_ie =
		(struct ieee80211_ie_csa *)csa_frm;
	struct ieee80211_ie_qtn_csa_tsf *csa_tsf_ie =
		(struct ieee80211_ie_qtn_csa_tsf *)csa_tsf_frm;
	uint64_t tsf = 0;

	if (ic->ic_opmode != IEEE80211_M_STA)
		return -EINVAL;

	if (csa_tsf_ie && csa_tsf_ie->id == IEEE80211_ELEMID_VENDOR &&
			isqtnie((u_int8_t *)csa_tsf_ie)) {
		tsf = ntohll(csa_tsf_ie->tsf);
	} else {
		ic->ic_get_tsf(&tsf);
		tsf += IEEE80211_MS_TO_USEC(csa_ie->csa_count * ni->ni_intval);
	}

	if (ic->ic_flags_qtn & IEEE80211_QTN_MONITOR)
		printk("%s: switching to chan=%u\n", __func__,
			ic->ic_csa_chan->ic_ieee);

#if defined(PLATFORM_QFDR)
	int otherband = 0;
	if (isclr(ic->ic_chan_active, csa_ie->csa_chan)) {
		/* channel may switched into other band */
		otherband = 1;
	}

	if ((otherband) && (vap->iv_opmode == IEEE80211_M_STA)) {
		if (qfdr_send_bss_info_hook && !(ic->ic_csa_chan->ic_flags & IEEE80211_CHAN_DFS))
			qfdr_send_bss_info_hook(vap, ic->ic_csa_chan->ic_ieee);

		ieee80211_eventf(vap->iv_dev,
			"%s[CSA-OTHER-BAND] CHAN=%u FREQ=%u DELAY=%u MAC=%pM",
			QEVT_COMMON_PREFIX,
			ic->ic_csa_chan->ic_ieee,
			ic->ic_csa_chan->ic_freq,
			csa_ie->csa_count * ni->ni_intval,
			ni->ni_macaddr);

		init_timer(&ieee80211_csa_otherband_timer);
		ieee80211_csa_otherband_timer.function = ieee80211_csa_otherband_notify;
		ieee80211_csa_otherband_timer.data = (unsigned long)vap;
		ieee80211_csa_otherband_timer.expires = jiffies +
			IEEE80211_MS_TO_JIFFIES(csa_ie->csa_count * ni->ni_intval);
		add_timer(&ieee80211_csa_otherband_timer);

		return 0;
	}
#endif

	ieee80211_eventf(vap->iv_dev, "%s[CSA] switch to %u in %u TBTT, MAC: %pM",
		QEVT_COMMON_PREFIX, ic->ic_csa_chan->ic_ieee, csa_ie->csa_count,
		ni->ni_macaddr);

	ieee80211_trigger_csa_bw_change(ic);

	ic->ic_set_channel_deferred(ic, tsf, 0);

	return 0;
}
#endif /* !ARTSMNG_SUPPORT */

int ieee80211_csa_target_sanity_check(struct ieee80211com *ic,
		struct ieee80211vap *vap,
		struct ieee80211_channel *c)
{
	uint8_t target_chan;

#ifndef ARTSMNG_SUPPORT
	if (!(ic->ic_opmode == IEEE80211_M_STA ||
			(ic->ic_opmode == IEEE80211_M_HOSTAP &&
				 IEEE80211_VAP_WDS_IS_RBS(vap)))) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
				"%s: incorrect operation mode - ic %d vap %d, "
				"role %d, flags_ext 0x%x\n", __func__,
				ic->ic_opmode, vap->iv_opmode,
				ic->ic_extender_role, ic->ic_flags_ext);
		return QTN_CSAIE_ERR_INVALID_MODE;
	}
#endif /* ARTSMNG_SUPPORT */

	target_chan = c->ic_ieee;

	if (isclr(ic->ic_chan_avail, target_chan) ||
			isset(ic->ic_chan_pri_inactive, target_chan)) {
		return QTN_CSAIE_ERR_CHAN_NOT_SUPP;
	}

#if !defined(PLATFORM_QFDR)
	if (ieee80211_is_repeater_sta(vap)) {
		if (isclr(ic->ic_chan_active, target_chan) &&
				isclr(ic->ic_chan_active_20, target_chan))
			return QTN_CSAIE_ERR_CHAN_NOT_SUPP;
	} else if (isclr(ic->ic_chan_active, target_chan))
		return QTN_CSAIE_ERR_CHAN_NOT_SUPP;
#endif

#ifdef ARTSMNG_SUPPORT
	/* check for duplicate trigger for the same CSA event */
	if (c == ic->ic_bsschan)
		return QTN_CSAIE_ERR_BSS_CHAN;

	if ((ic->ic_csa_count == 0) && (c == ic->ic_csa_chan))
		return QTN_CSAIE_ERR_IDENTICAL_CHAN;
#endif /* ARTSMNG_SUPPORT */

	return 0;
}
EXPORT_SYMBOL(ieee80211_csa_target_sanity_check);

int ieee80211_csa_target_sanity_check_bw(struct ieee80211com *ic, struct ieee80211_channel *chan,
						int new_bw)
{
	uint8_t c = chan->ic_ieee;

	switch(new_bw) {
	case BW_HT20:
		if (!isset(ic->ic_chan_active_20, c))
			return QTN_CSAIE_ERR_INVALID_BW;
		break;
	case BW_HT40:
		if (!isset(ic->ic_chan_active_40, c))
			return QTN_CSAIE_ERR_INVALID_BW;
		break;
	case BW_HT80:
	case BW_HT160:
		if (!isset(ic->ic_chan_active_80, c))
			return QTN_CSAIE_ERR_INVALID_BW;
		break;
	}

	return 0;
}


static int ieee80211_parse_new_bw_from_csa_ie(struct ieee80211vap *vap, uint8_t *csa_sec_chan_ie,
						uint8_t *csa_wide_bw_ie)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_ie_wbchansw *csa_wide_bw = (void *)csa_wide_bw_ie;
	struct ieee80211_ie_sec_chan_off *csa_secchan_off = (void *)csa_sec_chan_ie;
	int cur_bw;
	int new_bw;

	cur_bw = ieee80211_get_bw(ic);

	if (!csa_sec_chan_ie)
		return cur_bw;

	if (csa_secchan_off->sco_off == IEEE80211_HTINFO_CHOFF_SCN)
		new_bw = BW_HT20;
	else
		new_bw = BW_HT40;

	if (csa_wide_bw) {
		switch (csa_wide_bw->wbcs_newchanw) {
		case IEEE80211_VHTOP_CHAN_WIDTH_20_40MHZ:
			new_bw = BW_HT40;
			break;
		case IEEE80211_VHTOP_CHAN_WIDTH_80MHZ:
			new_bw = BW_HT80;
			break;
		case IEEE80211_VHTOP_CHAN_WIDTH_160MHZ:
			new_bw = BW_HT160;
			break;
		default:
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
					"%s: unknown option %u in wide bw ie\n", __func__,
					csa_wide_bw->wbcs_newchanw);
			new_bw = cur_bw;
		}
	}

	return new_bw;
}

static int
ieee80211_trans_csa_ie_count(struct ieee80211_node *ni, int count)
{
	struct ieee80211com *ic = ni->ni_ic;

	if ((ic->ic_lintval != ni->ni_intval) && ic->ic_lintval && ni->ni_intval)
		return count * ni->ni_intval / ic->ic_lintval;
	else
		return count;
}

static int
ieee80211_parse_sec_chan_off_ie(struct ieee80211_ie_sec_chan_off *sec_chan_off_ie)
{
	switch (sec_chan_off_ie->sco_off) {
	case IEEE80211_HTINFO_EXTOFFSET_BELOW:
	case IEEE80211_HTINFO_EXTOFFSET_ABOVE:
		return sec_chan_off_ie->sco_off;
	default:
		return 0;
	}
}

static int
ieee80211_parse_csaie(struct ieee80211_node *ni, const struct ieee80211_frame *wh,
			uint8_t *csa_frm, uint8_t *csa_tsf_frm, uint8_t *csa_wider_bw_ie,
			uint8_t *csa_secchan_off_ie)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_channel *c;
	struct ieee80211_ie_csa *csa_ie = (struct ieee80211_ie_csa *)csa_frm;
	int subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
	int relay = 0;
#if defined(PLATFORM_QFDR)
	int otherband = 0;
#endif
	int ret;
	int new_bw;
	int sec_chan_offset = 0;

	if (!csa_ie) {
		if (ic->ic_csa_count)
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
				"%s: channel switch is scheduled, but we got "
				"Beacon without CSA IE!\n", __func__);
		return 0;
	}

	if (csa_ie->csa_len != 3) {
		IEEE80211_DISCARD_IE(vap,
			IEEE80211_MSG_ELEMID | IEEE80211_MSG_DOTH,
			wh, "channel switch", "invalid length %u",
			csa_ie->csa_len);
		return QTN_CSAIE_ERR_INVALID_IE;
	}

	ic->ic_csa_frame[(subtype == IEEE80211_FC0_SUBTYPE_BEACON)
		? IEEE80211_CSA_FRM_BEACON : IEEE80211_CSA_FRM_ACTION]++;

	c = ieee80211_doth_findchan(vap, csa_ie->csa_chan);
	if (!c) {
		IEEE80211_DISCARD_IE(vap,
				IEEE80211_MSG_ELEMID | IEEE80211_MSG_DOTH,
				wh, "channel switch",
				"channel %u lookup failed", csa_ie->csa_chan);
		return QTN_CSAIE_ERR_CHAN_NOT_SUPP;
	}

	ret = ieee80211_csa_target_sanity_check(ic, vap, c);
	if (ret != 0) {
		switch (ret) {
		case QTN_CSAIE_ERR_CHAN_NOT_SUPP:
			IEEE80211_DISCARD_IE(vap,
				IEEE80211_MSG_ELEMID | IEEE80211_MSG_DOTH,
				wh, "channel switch", "invalid channel %u",
				csa_ie->csa_chan);
			break;
#ifdef ARTSMNG_SUPPORT
		case QTN_CSAIE_ERR_BSS_CHAN:
			IEEE80211_DISCARD_IE(vap,
				IEEE80211_MSG_ELEMID | IEEE80211_MSG_DOTH,
				wh, "channel switch", "on same channel %u",
				csa_ie->csa_chan);
			break;
		case QTN_CSAIE_ERR_IDENTICAL_CHAN:
			IEEE80211_DISCARD_IE(vap,
				IEEE80211_MSG_ELEMID | IEEE80211_MSG_DOTH,
				wh, "", "previously triggered the same channel %u",
				csa_ie->csa_chan);
			break;
#endif
		case QTN_CSAIE_ERR_INVALID_MODE:
			break;
		default:
			KASSERT(0, ("Unexpected return value"));
			break;

		}
		return ret;
	}

	new_bw = ieee80211_parse_new_bw_from_csa_ie(vap, csa_secchan_off_ie, csa_wider_bw_ie);
	new_bw = MIN(new_bw, ic->ic_max_system_bw);
	if (ic->ic_bss_bw != new_bw) {
		ret = ieee80211_csa_target_sanity_check_bw(ic, c, new_bw);
		if (ret) {
			IEEE80211_DISCARD_IE(vap, IEEE80211_MSG_ELEMID | IEEE80211_MSG_DOTH,
					wh, "channel switch", "invalid bw %u for channel %u",
					new_bw, csa_ie->csa_chan);
			return ret;
		} else {
			ic->ic_csa_bw_change_pending = 1;
			ic->ic_csa_bw = new_bw;
		}
	}

	if (csa_secchan_off_ie &&
		IS_IEEE80211_24G_BAND(ic) &&
		ieee80211_dual_sec_chan_supported(ic, c) &&
		(new_bw == BW_HT40)) {
			sec_chan_offset = ieee80211_parse_sec_chan_off_ie((struct ieee80211_ie_sec_chan_off *)csa_secchan_off_ie);
			if (sec_chan_offset)
				ieee80211_update_sec_chan_offset(c, sec_chan_offset);
	}

	if ((ic->ic_csa_count == 0) && (ic->ic_flags & IEEE80211_F_CHANSWITCH)) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
			"%s: channel switch to %u in %u tbtt (mode %u) come late,"
			" trigger_frame=0x%x\n", __func__, csa_ie->csa_chan,
			csa_ie->csa_count, csa_ie->csa_mode, subtype);
		return 0;
	}

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
		"%s: channel switch to %u in %u tbtt (mode %u) announced,"
		" trigger_frame=0x%x\n", __func__, csa_ie->csa_chan,
		csa_ie->csa_count, csa_ie->csa_mode, subtype);

#if defined(PLATFORM_QFDR)
	/* channel may switched into other band */
	if (isclr(ic->ic_chan_active, csa_ie->csa_chan))
		otherband = 1;
#endif
	if (ic->ic_csa_count) {
		/* CSA was received recently */
		if (c != ic->ic_csa_chan) {
			/* XXX abuse? */
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
					"%s: channel switch channel "
					"changed from %u to %u!\n", __func__,
					ic->ic_csa_chan->ic_ieee,
					csa_ie->csa_chan);
#if defined(PLATFORM_QFDR)
			if (isclr(ic->ic_chan_active, ic->ic_csa_chan->ic_ieee)) {
				/* channel was switching to other band */
				del_timer(&ieee80211_csa_otherband_timer);
				ic->ic_csa_count = 0;
				return 0;
			}
#endif
			/* Delay the new coming CSA until current CSA finishes */
			ic->ic_pending_csa_chan = c;
			ic->ic_pending_csa_mode = csa_ie->csa_mode;
			return 0;
		}

		if (csa_ie->csa_mode != ic->ic_csa_mode) {
			/* Can be abused, but with no (to little) impact. */

			/* CS mode change has no influence on our actions since
			 * we don't respect cs modes at all (yet). Complain and
			 * forget. */
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
					"%s: channel switch mode changed from "
					"%u to %u!\n", __func__,
					ic->ic_csa_mode, csa_ie->csa_mode);
		}

		ic->ic_csa_count = ieee80211_trans_csa_ie_count(ni, csa_ie->csa_count);
		if (ic->ic_csa_count == 0) {
			/* keep ic_csa_count unzero to avoid 2nd csa trigger */
			ic->ic_csa_count = 1;
		}
	} else {
		/* CSA wasn't received recently, so this is the first one in
		 * the sequence. */
		ic->ic_csa_mode = csa_ie->csa_mode;
		ic->ic_csa_count = ieee80211_trans_csa_ie_count(ni, csa_ie->csa_count);
		ic->ic_csa_chan = c;

		if (is_ieee80211_chan_valid(ic->ic_pending_csa_chan) &&
				(ic->ic_pending_csa_chan == c)) {
			ic->ic_pending_csa_chan = IEEE80211_CHAN_ANYC;
			ic->ic_pending_csa_mode = 0;
		}

		relay = ieee80211_should_relay_csaie(ic, vap);
#if defined(PLATFORM_QFDR)
		relay = relay && !otherband;
#endif

		if (relay)
			relay = ieee80211_relay_csaie(ic, c,
					ic->ic_csa_mode, ic->ic_csa_count);
		else if (ic->ic_csa_mode == IEEE80211_CSA_MUST_STOP_TX)
			ic->ic_disable_xmit(ic, __func__);

		if (ic->ic_csa_count == 0) {
			/* keep ic_csa_count unzero to avoid 2nd csa trigger */
			ic->ic_csa_count = 1;
		}

#ifdef ARTSMNG_SUPPORT
		/*
		 * if CSA IE is received from a WDS peer, don't just forward the action packet
		 * to other WDS peers, but also enter csa state.
		 * This state shall ensure last x beacons to include CSA IE and broadcast
		 * a CSA action frame before switching the channel.
		 */
		if ((ic->ic_opmode == IEEE80211_M_HOSTAP) && (vap->iv_opmode == IEEE80211_M_WDS)) {
			ieee80211_enter_csa(TAILQ_FIRST(&ic->ic_vaps)->iv_ic, c, NULL,
					IEEE80211_CSW_REASON_CSA,
					IEEE80211_DEFAULT_CHANCHANGE_TBTT_COUNT,
					ic->ic_csa_mode,
					IEEE80211_CSA_F_ACTION | IEEE80211_CSA_F_BEACON);
		}
#else
		if (!relay)
			ieee80211_sta_handle_csa(ni, csa_frm, csa_tsf_frm);
#endif /* ARTSMNG_SUPPORT */
	}

	return 0;
}

void
ieee80211_trigger_pending_csa(struct ieee80211com *ic)
{
#define PENDING_CSA_COUNT 2
	struct ieee80211vap *sta_vap = ieee80211_get_sta_vap(ic);
	struct ieee80211vap *vap = ieee80211_get_primary_vap(ic, 1);
	uint64_t tsf = 0;
	int relay = 0;

	if (!vap)
		return;

	if (!is_ieee80211_chan_valid(ic->ic_pending_csa_chan))
		return;

	if (ic->ic_pending_csa_chan == ic->ic_bsschan) {
		ic->ic_pending_csa_chan = IEEE80211_CHAN_ANYC;
		ic->ic_pending_csa_mode = 0;
		return;
	}

	ic->ic_csa_chan = ic->ic_pending_csa_chan;
	ic->ic_csa_mode = ic->ic_pending_csa_mode;
	ic->ic_csa_count = PENDING_CSA_COUNT;

	ic->ic_pending_csa_chan = IEEE80211_CHAN_ANYC;
	ic->ic_pending_csa_mode = 0;

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
			"%s: Schedule a pending CSA to chan %d mode %d cnt %d\n", __func__,
			ic->ic_csa_chan->ic_ieee, ic->ic_csa_mode, ic->ic_csa_count);

	IEEE80211_LOCK_BH(ic);
	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
		relay = ieee80211_should_relay_csaie(ic, vap);
		if (relay)
			break;
	}
	IEEE80211_UNLOCK_BH(ic);

	if (relay)
		relay = ieee80211_relay_csaie(ic, ic->ic_csa_chan,
				ic->ic_csa_mode, ic->ic_csa_count);

	if (!relay && sta_vap) {
		ic->ic_get_tsf(&tsf);
		tsf += IEEE80211_MS_TO_USEC(ic->ic_csa_count * sta_vap->iv_bss->ni_intval);
		ic->ic_set_channel_deferred(ic, tsf, 0);
	}
}
EXPORT_SYMBOL(ieee80211_trigger_pending_csa);

static int
ieee80211_narrower_bw_supported(struct ieee80211_node *ni, u_int8_t *csa_frm, int cur_bw)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_ie_csa *csa_ie = (struct ieee80211_ie_csa *)csa_frm;

	switch (cur_bw) {
	case BW_HT80:
	case BW_HT40:
		if (isset(ic->ic_chan_active_20, csa_ie->csa_chan)) {
			return 1;
		}
		break;
	}
	return 0;
}
/* XXX. Not the right place for such a definition */
struct l2_update_frame {
	struct ether_header eh;
	u8 dsap;
	u8 ssap;
	u8 control;
	u8 xid[3];
}  __packed;

static void
ieee80211_deliver_l2uf(struct ieee80211_node *ni)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct net_device *dev = vap->iv_dev;
	struct sk_buff *skb;
	struct l2_update_frame *l2uf;
	struct ether_header *eh;

	skb = dev_alloc_skb(sizeof(*l2uf));
	if (!skb) {
		printk(KERN_INFO "ieee80211_deliver_l2uf: no buf available\n");
		return;
	}
	skb_put(skb, sizeof(*l2uf));
	l2uf = (struct l2_update_frame *)(skb->data);
	eh = &l2uf->eh;
	/* dst: Broadcast address */
	IEEE80211_ADDR_COPY(eh->ether_dhost, dev->broadcast);
	/* src: associated STA */
	IEEE80211_ADDR_COPY(eh->ether_shost, ni->ni_macaddr);
	eh->ether_type = htons(skb->len - sizeof(*eh));

	l2uf->dsap = 0;
	l2uf->ssap = 0;
	l2uf->control = 0xf5;
	l2uf->xid[0] = 0x81;
	l2uf->xid[1] = 0x80;
	l2uf->xid[2] = 0x00;

	ieee80211_skb_dev_set(dev, skb);
	skb->protocol = eth_type_trans(skb, skb->dev);
	skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);

	ieee80211_deliver_data(ni, skb);
	return;
}

static __inline int
contbgscan(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;

	return ((ic->ic_flags_ext & IEEE80211_FEXT_BGSCAN) &&
		time_after(jiffies, ic->ic_lastdata + vap->iv_bgscanidle));
}

static __inline int
startbgscan(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;

	if (ic->ic_scan_opchan_enable) {
		return (!IEEE80211_IS_CHAN_DTURBO(ic->ic_curchan) &&
			time_after(jiffies, ic->ic_lastscan + vap->iv_bgscanintvl));
	} else {
		return ((vap->iv_flags & IEEE80211_F_BGSCAN) &&
			!IEEE80211_IS_CHAN_DTURBO(ic->ic_curchan) &&
			time_after(jiffies, ic->ic_lastscan + vap->iv_bgscanintvl) &&
			time_after(jiffies, ic->ic_lastdata + vap->iv_bgscanidle));
	}
}

/*
 * Process beacon/probe response frames in:
 *    o AP mode, to check for non-HT APs on same channel
 *    o station mode when associated, to collect state updates such as 802.11g slot time
 *    o monitor/sniffer node, to handle CSA events
 *    o WDS mode, to set peer node capabilities and rates
 *    o adhoc mode, to discover neighbors
 *    o any mode, when scanning
 */
static int
ieee80211_beacon_should_discard(struct ieee80211_node *ni)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;

	switch (vap->iv_opmode) {
	case IEEE80211_M_HOSTAP:
		return 0;
		break;
	case IEEE80211_M_STA:
		if (ni->ni_associd)
			return 0;
		if (ic->ic_flags_qtn & IEEE80211_QTN_MONITOR)
			return 0;
		break;
	case IEEE80211_M_WDS:
		if (IEEE80211_ADDR_EQ(ni->ni_macaddr, vap->wds_mac))
			return 0;
		break;
	case IEEE80211_M_IBSS:
		return 0;
		break;
	default:
		break;
	}

	if (ieee80211_is_scanning(ic))
		return 0;

	return 1;
}

/*
 * FIXME
 * Ignore changes in Primary Channel and Secondary channel offset to skip node update
 * caused by channel switch.
 */
static int
ieee80211_wds_compare_htinfo(struct ieee80211_ie_htinfo *old,
		struct ieee80211_ie_htinfo *new)
{
	int ret;

	old->hi_ctrlchannel = new->hi_ctrlchannel;

	old->hi_byte1 &= ~IEEE80211_HTINFO_B1_SEC_CHAN_OFFSET;
	old->hi_byte1 |= new->hi_byte1 & IEEE80211_HTINFO_B1_SEC_CHAN_OFFSET;

	ret = memcmp(old, new, sizeof(struct ieee80211_ie_htinfo));

	return (ret != 0);
}

/*
 * FIXME
 * Ignore changes in Channel Center Segment 0/1 to skip node update
 * caused by channel switch.
 */
static int
ieee80211_wds_compare_vhtop(struct ieee80211_ie_vhtop *old,
		struct ieee80211_ie_vhtop *new)
{
	int ret;

	old->vhtop_info[1] = new->vhtop_info[1];
	old->vhtop_info[2] = new->vhtop_info[2];

	ret = memcmp(old, new, sizeof(struct ieee80211_ie_vhtop));

	return (ret != 0);
}

static void
ieee80211_update_wds_peer_node(struct ieee80211_node *ni,
		struct ieee80211_scanparams *scan)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	int ni_update_required = 0;
	int htinfo_update_required = 0;
	int vhtcap_update_required = 0;
	int htcap_update_required = 0;
	int vhtop_update_required = 0;
	struct ieee80211_ie_htinfo lhtinfo;

	if (IEEE80211_BINTVAL_VALID(scan->bintval) && ni->ni_intval != scan->bintval) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_NODE | IEEE80211_MSG_EXTDR,
				"Update wds peer beacon interval from %d to %d\n",
				ni->ni_intval, scan->bintval);
		ni->ni_intval = scan->bintval;
	}
	if (scan->qtn && ni->ni_qtn_assoc_ie == NULL) {
		ieee80211_saveie(&ni->ni_qtn_assoc_ie, scan->qtn);
		ni_update_required = 1;
	}

	if (scan->htcap && ieee80211_parse_htcap(ni, scan->htcap)) {
		htcap_update_required = 1;
		ni_update_required = 1;
	}

	memcpy(&lhtinfo, &ni->ni_ie_htinfo, sizeof(struct ieee80211_ie_htinfo));

	if (scan->htinfo && ieee80211_parse_htinfo(ni, scan->htinfo)) {
		htinfo_update_required = ieee80211_wds_compare_htinfo(&lhtinfo,
					(struct ieee80211_ie_htinfo *)scan->htinfo);
		ni_update_required = 1;
	}

	/* 802.11ac */
	if (scan->vhtcap && IS_IEEE80211_VHT_ENABLED(ic)) {
		ni->ni_flags |= IEEE80211_NODE_VHT;
		if (ieee80211_check_and_parse_vhtcap(ni, scan->vhtcap)) {
			vhtcap_update_required = 1;
			ni_update_required = 1;
		}
	}
	if (scan->vhtop && IS_IEEE80211_VHT_ENABLED(ic)) {
		struct ieee80211_ie_vhtop lvhtop;

		memcpy(&lvhtop, &ni->ni_ie_vhtop, sizeof(struct ieee80211_ie_vhtop));

		if (ieee80211_check_and_parse_vhtop(ni, scan->vhtop)) {
			vhtop_update_required = ieee80211_wds_compare_vhtop(&lvhtop,
						(struct ieee80211_ie_vhtop *)scan->vhtop);
			ni_update_required = 1;
		}
	}

	if ((ic->ic_peer_rts_mode == IEEE80211_PEER_RTS_PMP) &&
		((ic->ic_sta_assoc - ic->ic_nonqtn_sta) >= IEEE80211_MAX_STA_CCA_ENABLED)) {

		ic->ic_peer_rts = 1;
	}

	if (ni_update_required) {
		struct ieee80211_rateset old_ni_rates;	/* negotiated rate set */
		struct ieee80211_ht_rateset old_ni_htrates;	/* negotiated ht rate set */
		int ba_established = (ni->ni_ba_tx[IEEE80211_WDS_LINK_MAINTAIN_BA_TID].state == IEEE80211_BA_ESTABLISHED);
		uint8_t tid;
		uint8_t tid_mask[howmany(WME_NUM_TID, NBBY)] = { 0 };

		old_ni_rates = ni->ni_rates;
		old_ni_htrates = ni->ni_htrates;

		ieee80211_fix_rate(ni, IEEE80211_F_DOXSECT | IEEE80211_F_DODEL);
		ieee80211_fix_ht_rate(ni, IEEE80211_F_DOXSECT | IEEE80211_F_DODEL);

		ieee80211_update_current_mode(ni);

		if (ba_established &&
				(memcmp(&ni->ni_rates, &old_ni_rates, sizeof(old_ni_rates)) == 0) &&
				(memcmp(&ni->ni_htrates, &old_ni_htrates, sizeof(old_ni_htrates)) == 0) &&
				!vhtcap_update_required && !vhtop_update_required) {
			return;
		}

		IEEE80211_DPRINTF(vap, IEEE80211_MSG_NODE | IEEE80211_MSG_EXTDR,
				"Peer update: htinfo %d, vhtcap %d, htcap %d, vhtop %d\n",
				htinfo_update_required,
				vhtcap_update_required,
				htcap_update_required,
				vhtop_update_required);

		if (ic->ic_newassoc != NULL) {
			ic->ic_newassoc(ni, 0);

			/* update key peer WDS */
			if (vap->iv_wds_peer_key.wk_keylen != 0) {
				ieee80211_key_update_begin(vap);
				vap->iv_key_set(vap, &vap->iv_wds_peer_key, ni->ni_macaddr);
				ieee80211_key_update_end(vap);
			}
		}

		for (tid = 0; tid < WME_NUM_TID; tid++) {
			if (ni->ni_ba_rx[tid].state == IEEE80211_BA_ESTABLISHED)
				setbit(tid_mask, tid);
		}

		ieee80211_node_ba_state_clear(ni);

		for (tid = 0; tid < WME_NUM_TID; tid++) {
			/*
			 * Both tx and rx Block Ack are lost during node update,
			 * need to notify peer that previous BA become invalid
			 */
			if (isset(tid_mask, tid))
				ieee80211_send_delba(ni, tid, 1, IEEE80211_REASON_UNSPECIFIED);
		}
	}
}

void
ieee80211_update_tbtt(struct ieee80211vap *vap,
		struct ieee80211_node *ni)
{
	struct ieee80211com *ic = vap->iv_ic;
	uint64_t cur_tsf;

	ic->ic_get_tsf(&cur_tsf);
	ni->ni_tbtt = cur_tsf + IEEE80211_TU_TO_USEC(ni->ni_intval);

	if (vap->iv_dtim_count == 0)
		ni->ni_dtim_tbtt = cur_tsf +
			(uint32_t)vap->iv_dtim_period * IEEE80211_TU_TO_USEC(ni->ni_intval);
}

static int
ieee80211_get_band_chan_step(int chan)
{
	struct ieee80211_band_info *band;
	int band_idx;
	int temp_chan;
	int chan_cnt;
	int chan_step;

	for (band_idx = 0; band_idx < IEEE80211_BAND_IDX_MAX; band_idx++) {
		band = ieee80211_get_band_info(band_idx);
		if (band == NULL)
			continue;

		temp_chan = band->band_first_chan;
		chan_cnt = band->band_chan_cnt;
		chan_step = band->band_chan_step;

		while (chan_cnt--) {
			if (temp_chan == chan)
				return chan_step;
			temp_chan += chan_step;
		}
	}

	return -1;
}

int
ieee80211_parse_supp_chan(struct ieee80211_node *ni, uint8_t *ie)
{
	int chan_tuples;
	uint8_t *chan;
	uint8_t *chan_len;
	uint8_t chan_step;
	int i;

	if (!ni || !ie)
		return -1;

	chan_tuples = ie[1] / 2;
	for (i = 0; i < chan_tuples; i++) {
		chan = ie + 2 + i * 2;
		if (ieee80211_get_band_chan_step(*chan) < 0) {
			IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_ELEMID,
					"%s: Invalid channel: %u\n",
					__func__, *chan);
			return -1;
		}
	}

	memset(ni->ni_supp_chans, 0, sizeof(ni->ni_supp_chans));
	ni->ni_chan_num = 0;

	chan_tuples = ie[1] / 2;
	for (i = 0; i < chan_tuples; i++) {
		chan = ie + 2 + i * 2;
		chan_len = ie + 3 + i * 2;
		chan_step = ieee80211_get_band_chan_step(*chan);
		while ((*chan_len)--) {
			setbit(ni->ni_supp_chans, *chan);
			ni->ni_chan_num++;
			*chan += chan_step;
		}
	}

	return 0;
}
static int ieee80211_parse_80211_v(struct ieee80211_node *ni, uint8_t *frm)
{
	uint32_t extcap[howmany(IEEE80211_EXTCAP_IE_LEN, 4)] = {0};
	uint32_t temp_extcap = 0;
	uint8_t len = 0;
	uint8_t *ie = NULL;
	uint8_t i = 0;
	struct ieee80211vap *vap = ni->ni_vap;

	if (vap == NULL)
		return IEEE80211_REASON_IE_INVALID;

	ie = frm;
	len = ie[1];
	if ((len == 0) || (len > IEEE80211_EXTCAP_IE_LEN))
		return IEEE80211_REASON_IE_INVALID;

	ie += 2;
	for (i = 0; i < len; i++) {
		temp_extcap = ie[i];
		/* 4 bytes compose an extcap value, lower byte is on lower 8-bit of extcap value */
		temp_extcap <<= (i % 4) * 8;
		extcap[i / 4] |= temp_extcap;
	}

	if (extcap[0] & IEEE80211_EXTCAP1_BSS_TRANSITION) {
		ni->ni_ext_flags |= IEEE80211_NODE_BSS_TRANSITION;
	} else {
		ni->ni_ext_flags &= ~IEEE80211_NODE_BSS_TRANSITION;
	}
	return 0;

}

static int ieee80211_parse_bss_max_idle(struct ieee80211_node *ni, uint8_t *frm, uint8_t *bssid)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211_max_idle_ie *max_idle = (void *)frm;
	uint16_t max_idle_wnm_tu;

	if (vap == NULL)
		return IEEE80211_REASON_IE_INVALID;

	max_idle_wnm_tu = le16toh(max_idle->max_idle_period);
	ni->ni_max_idle_period_ms = ieee80211_wnm_convert_tu_to_msec(max_idle_wnm_tu);
	if (max_idle->idle_options)
		ni->ni_ext_flags |= IEEE80211_NODE_WNM_USE_PROT;
	else
		ni->ni_ext_flags &= ~IEEE80211_NODE_WNM_USE_PROT;

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_INACT | IEEE80211_MSG_INPUT,
				"%s: idle_period %u msec, wnm tu %u\n", __func__,
				ni->ni_max_idle_period_ms, max_idle_wnm_tu);

	return 0;
}

static int ieee80211_parse_extcap(struct ieee80211_node *ni, uint8_t *frm, uint8_t *bssid)
{
	uint32_t extcap[howmany(IEEE80211_EXTCAP_IE_LEN, 4)] = {0};
	uint32_t temp_extcap = 0;
	uint8_t len = 0;
	uint8_t *ie = NULL;
	uint8_t i = 0;
	struct ieee80211vap *vap = ni->ni_vap;

	if (vap == NULL)
		return IEEE80211_REASON_IE_INVALID;

	ie = frm;
	len = ie[1];

	if (len == IEEE80211_NODE_INTEL_726X_EXTCAP_IE_LEN)
		ni->ni_qtn_flags |= QTN_IS_NOT_INTEL_826X_NODE;
	if ((len == 0) || (len > IEEE80211_EXTCAP_IE_LEN))
		return IEEE80211_REASON_IE_INVALID;

	ie += 2;

	/* get maximum AMSDU number */
	if (len >= 9) {
		uint16_t msdu_bytes = (uint16_t)ie[7] | (((uint16_t)ie[8]) << NBBY);
                uint8_t max_msdu_in_amsdu_field = MS(msdu_bytes,
                                IEEE80211_EXTCAP_MAX_MSDU_IN_AMSDU_MASK);
		uint8_t max_msdu_in_amsdu = 0xFF; /* unlimited */
		if (max_msdu_in_amsdu_field <= 3) {
			max_msdu_in_amsdu = 8 << (3 - max_msdu_in_amsdu_field);
		}
		ni->ni_max_msdu_in_amsdu = max_msdu_in_amsdu;
	}

	/* check BSS transition management capbility and set node info */
	if ((len >= 3) && isset(ie, IEEE80211_EXTCAP_BTM))
		ni->ni_wnm_capability |= IEEE80211_NODE_WNM_BTM_CAPABLE;

	for (i = 0; i < len; i++) {
		temp_extcap = (uint32_t)ie[i];
		/* 4 bytes compose an extcap value, lower byte is on lower 8-bit of extcap value */
		temp_extcap <<= (i % 4) * 8;
		extcap[i / 4] |= temp_extcap;
	}

	if ((vap->iv_opmode == IEEE80211_M_STA) &&
			(vap->iv_state == IEEE80211_S_RUN) &&
			(IEEE80211_ADDR_EQ(vap->iv_bss->ni_bssid, bssid))) {
		if (extcap[1] & IEEE80211_EXTCAP2_TDLS_PROHIB) {
			if ((vap->iv_flags_ext & IEEE80211_FEXT_AP_TDLS_PROHIB) == 0) {
				if ((vap->iv_flags_ext & IEEE80211_FEXT_TDLS_PROHIB) == 0) {
					/* teardown the link and clear timer */
					ieee80211_tdls_teardown_all_link(vap);
					ieee80211_tdls_clear_disc_timer(vap);
					ieee80211_tdls_clear_node_expire_timer(vap);
				}
				vap->iv_flags_ext |= IEEE80211_FEXT_AP_TDLS_PROHIB;
			}
		} else {
			if ((vap->iv_flags_ext & IEEE80211_FEXT_AP_TDLS_PROHIB) != 0) {
				vap->iv_flags_ext &= ~IEEE80211_FEXT_AP_TDLS_PROHIB;
				if ((vap->iv_flags_ext & IEEE80211_FEXT_TDLS_DISABLED) == 0) {
					ieee80211_tdls_start_disc_timer(vap);
					ieee80211_tdls_start_node_expire_timer(vap);
				}
			}
		}

		if (extcap[1] & IEEE80211_EXTCAP2_TDLS_CS_PROHIB)
			vap->iv_flags_ext |= IEEE80211_FEXT_TDLS_CS_PROHIB;
		else
			vap->iv_flags_ext &= ~IEEE80211_FEXT_TDLS_CS_PROHIB;

		if (extcap[1] & IEEE80211_EXTCAP2_OP_MODE_NOTI)
			ni->ni_ext_flags |= IEEE80211_NODE_OP_MODE_NOTI;
		else
			ni->ni_ext_flags &= ~IEEE80211_NODE_OP_MODE_NOTI;
	}

	if ((vap->iv_opmode == IEEE80211_M_HOSTAP) &&
		IEEE80211_ADDR_EQ(ni->ni_macaddr, bssid)) {
		if (extcap[1] & IEEE80211_EXTCAP2_OP_MODE_NOTI)
			ni->ni_ext_flags |= IEEE80211_NODE_OP_MODE_NOTI;
		else
			ni->ni_ext_flags &= ~IEEE80211_NODE_OP_MODE_NOTI;
	}

	return 0;
}

/*
 * Parse the wireless header for a TDLS frame
 */
static void
ieee80211_parse_tdls_hdr(struct ieee80211vap *vap,
	struct ieee80211_tdls_params *tdls, struct ieee80211_frame *wh)
{
	struct ieee80211_frame_addr4 *wh4;

	switch (wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) {
	case IEEE80211_FC1_DIR_NODS:
		tdls->da = wh->i_addr1;
		tdls->sa = wh->i_addr2;
		break;
	case IEEE80211_FC1_DIR_TODS:
		tdls->sa = wh->i_addr2;
		tdls->da = wh->i_addr3;
		break;
	case IEEE80211_FC1_DIR_FROMDS:
		tdls->da = wh->i_addr1;
		tdls->sa = wh->i_addr3;
		break;
	case IEEE80211_FC1_DIR_DSTODS:
		wh4 = (struct ieee80211_frame_addr4 *)wh;
		tdls->da = wh4->i_addr3;
		tdls->sa = wh4->i_addr4;
		break;
	}
}

/*
 * Parse the TLVs in a TDLS action frame or public tdls action frame
 * Returns 0 if successful, else 1.
 */
static int
ieee80211_parse_tdls_tlvs(struct ieee80211vap *vap,
		struct ieee80211_tdls_params *tdls, uint8_t **frm_p, uint8_t *efrm,
	uint8_t ia_action)
{
	uint8_t *frm = *frm_p;
	uint32_t size = (uint32_t)efrm - (uint32_t)frm;
	char *elem_type = "none";

	IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_DBG, "TDLS %s: parse TLVs\n", __func__);
	/* Parse TLVs */
	while (frm < efrm) {
		if (size < frm[1])
			goto error;
		if (frm[1] > ieee80211_max_ie_len[*frm])
			goto error;
		switch (*frm) {
		case IEEE80211_ELEMID_RATES:
			elem_type = "rates";
			tdls->rates = frm;
			break;
		case IEEE80211_ELEMID_COUNTRY:
			elem_type = "country";
			tdls->country = frm;
			break;
		case IEEE80211_ELEMID_XRATES:
			elem_type = "xrates";
			tdls->xrates = frm;
			break;
		case IEEE80211_ELEMID_SUPPCHAN:
			elem_type = "suppchan";
			tdls->supp_chan = frm;
			break;
		case IEEE80211_ELEMID_SEC_CHAN_OFF:
			elem_type = "sec_chan_off";
			tdls->sec_chan_off = frm;
			break;
		case IEEE80211_ELEMID_RSN:
			elem_type = "rsn";
			tdls->rsn = frm;
			break;
		case IEEE80211_ELEMID_EXTCAP:
			elem_type = "ext cap";
			tdls->ext_cap = frm;
			break;
		case IEEE80211_ELEMID_EDCA:
			elem_type = "edca";
			tdls->edca = frm;
			break;
		case IEEE80211_ELEMID_QOSCAP:
			elem_type = "qoscap";
			tdls->qos_cap = frm;
			break;
		case IEEE80211_ELEMID_FTIE:
			elem_type = "ftie";
			tdls->ftie = frm;
			break;
		case IEEE80211_ELEMID_TIMEOUT_INT:
			elem_type = "timeout_int";
			tdls->tpk_timeout = frm;
			break;
		case IEEE80211_ELEMID_REG_CLASSES:
			elem_type = "reg_classes";
			tdls->sup_reg_class = frm;
			break;
		case IEEE80211_ELEMID_HTCAP:
			elem_type = "htcap";
			tdls->htcap = frm;
			break;
		case IEEE80211_ELEMID_HTINFO:
			elem_type = "htinfo";
			tdls->htinfo = frm;
			break;
		case IEEE80211_ELEMID_VHTCAP:
			elem_type = "vhtcap";
			tdls->vhtcap = frm;
			break;
		case IEEE80211_ELEMID_VHTOP:
			elem_type = "vhtop";
			tdls->vhtop = frm;
			break;
		case IEEE80211_ELEMID_20_40_BSS_COEX:
			elem_type = "20/40 bss coex";
			tdls->bss_2040_coex = frm;
			break;
		case IEEE80211_ELEMID_AID:
			elem_type = "aid";
			if (size < sizeof(*tdls->aid))
				goto error;
			tdls->aid = (struct ieee80211_ie_aid *)frm;
			break;
		case IEEE80211_ELEMID_TDLS_LINK_ID:
			elem_type = "link id";
			if (size < sizeof(*tdls->link_id))
				goto error;
			tdls->link_id = (struct ieee80211_tdls_link_id *)frm;
			break;
		case IEEE80211_ELEMID_TDLS_WKUP_SCHED:
			elem_type = "wkup sched";
			if (size < sizeof(*tdls->wkup_sched))
				goto error;
			tdls->wkup_sched = (struct ieee80211_tdls_wkup_sched *)frm;
			break;
		case IEEE80211_ELEMID_TDLS_CS_TIMING:
			elem_type = "cs timing";
			if (size < sizeof(*tdls->cs_timing))
				goto error;
			tdls->cs_timing = (struct ieee80211_tdls_cs_timing *)frm;
			break;
		case IEEE80211_ELEMID_TDLS_PTI_CTRL:
			elem_type = "pti ctrl";
			if (size < sizeof(*tdls->pti_ctrl))
				goto error;
			tdls->pti_ctrl = (struct ieee80211_tdls_pti_ctrl *)frm;
			break;
		case IEEE80211_ELEMID_TDLS_PU_BUF_STAT:
			elem_type = "pu buf stat";
			if (size < sizeof(*tdls->pu_buf_stat))
				goto error;
			tdls->pu_buf_stat = (struct ieee80211_tdls_pu_buf_stat *)frm;
			break;
		case IEEE80211_ELEMID_WBWCHANSWITCH:
			elem_type = "wide_bw_cs";
			if (size < sizeof(*tdls->wide_bw_cs))
				goto error;
			tdls->wide_bw_cs = (struct ieee80211_ie_wbchansw *)frm;
			break;
		case IEEE80211_ELEMID_VHTXMTPWRENVLP:
			elem_type = "vht_tx_pw_envelope";
			if (size < sizeof(*tdls->vht_tx_pw_env))
				goto error;
			tdls->vht_tx_pw_env = (struct ieee80211_ie_vtxpwren *)frm;
			break;
		case IEEE80211_ELEMID_VENDOR:
			elem_type = "vendor";
			/* Unsupported vendor IEs are silently ignored*/
			if (isqtnie(frm)) {
				tdls->qtn_info = frm;
			} else if (is_qtn_oui_tdls_brmacs(frm)) {
				tdls->qtn_brmacs = frm;
			} else {
				/* TDLS debugging */
				IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_WARN,
					"unhandled id %u, len %u", *frm, frm[1]);
				vap->iv_stats.is_rx_elem_unknown++;
			}
			break;
		default:
			elem_type = "unknown";
			IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_WARN,
				"unhandled id %u, len %u\n", *frm, frm[1]);
			vap->iv_stats.is_rx_elem_unknown++;
			break;
		}
		IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_DBG, "TDLS %s: got %s pos=%p "
			"id=%u len=%u\n", __func__, elem_type, frm, *frm, frm[1]);

		frm += frm[1] + 2;
	}

	if (frm > efrm) {
		IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_WARN, "TDLS %s: "
			"frame len invalid frm=%p efrm=%p\n", __func__, frm, efrm);
		vap->iv_stats.is_rx_elem_toobig++;
		return 1;
	}

	*frm_p = frm;

	return 0;

error:
	IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_WARN,
			"TDLS %s: ie (%s) too short\n", __func__, elem_type);
	vap->iv_stats.is_rx_elem_toosmall++;

	return 1;
}

/*
 * Process a public TDLS action frame
 */
static void
ieee80211_recv_action_public_tdls(struct ieee80211_node *ni, struct sk_buff *skb,
	struct ieee80211_frame *wh, struct ieee80211_action *ia, int rssi)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211_tdls_params tdls;
	uint8_t *frm = (u_int8_t *)(ia + 1);
	uint8_t *efrm = skb->data + skb->len;
	uint32_t dump_len = sizeof(struct ieee80211_ht_qosframe) + LLC_SNAPFRAMELEN;
	int subtype = IEEE80211_FC0_SUBTYPE_ACTION; /* for validation scripts */

	IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_DBG,
		"TDLS %s: got TDLS type %u\n", __func__, ia->ia_action);

	if (unlikely(ieee80211_msg(vap, IEEE80211_MSG_TDLS) && ieee80211_tdls_msg(vap, IEEE80211_TDLS_MSG_DBG))) {
		if (unlikely(skb->len < dump_len))
			dump_len = skb->len;
		ieee80211_dump_pkt(vap->iv_ic, skb->data, dump_len, -1, rssi);
	}

	if (vap->iv_opmode != IEEE80211_M_STA) {
		IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_WARN,
			"TDLS %s: ignoring public TDLS action frame - not STA\n", __func__);
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
			wh, ieee80211_tdls_action_name_get(ia->ia_action), "%s",
			"ignoring public TDLS action frame - not STA");
		vap->iv_stats.is_rx_mgtdiscard++;
		return;
	}
	if (ia->ia_action != IEEE80211_ACTION_PUB_TDLS_DISC_RESP) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_ANY,
			wh, ieee80211_mgt_subtype_name[
			IEEE80211_FC0_SUBTYPE_ACTION >> IEEE80211_FC0_SUBTYPE_SHIFT],
			"unsupported TDLS public action %u", ia->ia_action);
		IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_WARN,
			"TDLS %s: unsupported TDLS public action\n", __func__);
		vap->iv_stats.is_rx_badsubtype++;
		return;
	}

	memset(&tdls, 0, sizeof(tdls));

	ieee80211_parse_tdls_hdr(vap, &tdls, wh);

	if (ieee80211_verify_length(vap, efrm - frm,
			sizeof(tdls.diag_token) +
			sizeof(tdls.caps), wh, subtype))
		return;
	tdls.diag_token = *frm;
	frm += sizeof(tdls.diag_token);
	tdls.caps = le16toh(*(__le16 *)frm);
	frm += sizeof(tdls.caps);

	if (ieee80211_parse_tdls_tlvs(vap, &tdls, &frm, efrm, ia->ia_action)) {
		return;
	}

	ieee80211_tdls_recv_disc_resp(ni, skb, rssi, &tdls);
}

void
ieee80211_find_ht_pri_sec_chan(struct ieee80211vap *vap,
		const struct ieee80211_scan_entry *se,
		uint8_t *pri_chan, uint8_t *sec_chan)
{
	struct ieee80211_ie_htinfo *htinfo =
			(struct ieee80211_ie_htinfo *)se->se_htinfo_ie;
	uint8_t choff;

	if (!htinfo) {
		*pri_chan = se->se_chan->ic_ieee;
		*sec_chan = 0;
		return;
	}

	*pri_chan = IEEE80211_HTINFO_PRIMARY_CHANNEL(htinfo);
	choff = IEEE80211_HTINFO_B1_EXT_CHOFFSET(htinfo);
	if (choff == IEEE80211_HTINFO_EXTOFFSET_ABOVE)
		*sec_chan = *pri_chan + IEEE80211_CHAN_SEC_SHIFT;
	else if (choff == IEEE80211_HTINFO_EXTOFFSET_BELOW)
		*sec_chan = *pri_chan - IEEE80211_CHAN_SEC_SHIFT;
	else if (choff == IEEE80211_HTINFO_EXTOFFSET_NA)
		*sec_chan = 0;
	else
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
			"%s: wrong channel offset %u in htinfo IE\n",
			__func__, choff);

	if (*pri_chan != se->se_chan->ic_ieee)
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
			"%s: error - scan channel %u is different"
			" with primary channel in htinfo\n", __func__,
			se->se_chan->ic_ieee, pri_chan);
}

uint8_t
ieee80211_find_ht_center_chan(struct ieee80211vap *vap,
		const struct ieee80211_scan_entry *se)
{
	uint8_t pri_chan;
	uint8_t sec_chan;

	ieee80211_find_ht_pri_sec_chan(vap, se, &pri_chan, &sec_chan);

	if (sec_chan)
		return (pri_chan + sec_chan) / 2;
	else
		return pri_chan;
}

/*
 * Check if overlap occurs with scanned AP on an assigned channel,
 * please refer section 10.15.3.2 of standard IEEE802.11-2012
 */
static int
ieee80211_chan_scan_ap_nonoverlap(struct ieee80211com *ic,
	struct ieee80211_channel *chan, uint8_t se_pri_chan, uint8_t se_sec_chan)
{
	uint16_t affected_start;
	uint16_t affected_end;
	uint8_t pri_chan;
	uint8_t sec_chan;
	uint8_t cent_chan;
	uint8_t pri_allow = 0;
	uint8_t sec_allow = 0;

	pri_chan = chan->ic_ieee;
	if (ieee80211_is_chan40u(chan))
		sec_chan = pri_chan + IEEE80211_SEC_CHAN_OFFSET;
	else if (ieee80211_is_chan40d(chan))
		sec_chan = pri_chan - IEEE80211_SEC_CHAN_OFFSET;
	else
		return 0;

	/* Calculating the affected frequency range */
	cent_chan = (pri_chan + sec_chan) >> 1;
	if (cent_chan > IEEE80211_OBSS_AFFECT_CHAN_SPAN)
		affected_start = cent_chan - IEEE80211_OBSS_AFFECT_CHAN_SPAN;
	else
		affected_start = 1;
	affected_end = cent_chan + IEEE80211_OBSS_AFFECT_CHAN_SPAN;

	/*
	 * (P ?= OPi) in formula 10-2
	 * Check whether the 20M or 40M bandwidth interference AP shares
	 * same primary channel with current AP
	 */
	if ((se_pri_chan >= affected_start) && (se_pri_chan <= affected_end)) {
		if (pri_chan == se_pri_chan)
			pri_allow = 1;
		else
			pri_allow = 0;
	} else {
		pri_allow = 1;
	}

	/*
	 * (S ?= OSi) in formula 10-2
	 * Check whether the 40M bandwidth interference AP shares
	 * same secondary channel with current AP
	 */
	if ((se_sec_chan >= affected_start) && (se_sec_chan <= affected_end)) {
		if (sec_chan == se_sec_chan)
			sec_allow = 1;
		else
			sec_allow = 0;
	} else {
		sec_allow = 1;
	}

	return (pri_allow && sec_allow);
}

/*
 * Check if assigned channel is 40M BSS tolerant,
 * please refer section 10.15.3.2 of standard IEEE802.11-2012
 */
static int
ieee80211_chan_40M_tolerant(struct ieee80211com *ic,
	struct ieee80211_channel *chan)
{
	uint16_t affected_start;
	uint16_t affected_end;
	uint8_t pri_chan;
	uint8_t sec_chan;
	uint8_t cent_chan;
	uint8_t tolerant40 = 0;
	int i;

	pri_chan = chan->ic_ieee;
	if (ieee80211_is_chan40u(chan))
		sec_chan = pri_chan + IEEE80211_SEC_CHAN_OFFSET;
	else if (ieee80211_is_chan40d(chan))
		sec_chan = pri_chan - IEEE80211_SEC_CHAN_OFFSET;
	else
		return 0;

	/* Calculating the affected frequency range */
	cent_chan = (pri_chan + sec_chan) >> 1;
	if (cent_chan > IEEE80211_OBSS_AFFECT_CHAN_SPAN)
		affected_start = cent_chan - IEEE80211_OBSS_AFFECT_CHAN_SPAN;
	else
		affected_start = 1;
	affected_end = cent_chan + IEEE80211_OBSS_AFFECT_CHAN_SPAN;

	/*
	 * (P ?= OTi) in formula 10-2
	 * Check whether the candidate primary channel is overlapped
	 * with 40M intolerant channels
	 */
	for (i = 0; i < IEEE80211_CHAN_MAX; i++) {
		if (isset(ic->ic_chan_intole_40, i) &&
				((i >= affected_start) && (i <= affected_end))) {
			if (pri_chan == i) {
				tolerant40 = 1;
			} else {
				tolerant40 = 0;
				break;
			}
		} else {
			tolerant40 = 1;
		}
	}

	return tolerant40;
}

int
ieee80211_ap_chan_40_bw_permitted(struct ieee80211vap *vap,
	struct ieee80211_channel *chan)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_scan_state *ss = ic->ic_scan;
	struct ap_scan_entry *se;
	struct ap_state *as = ss->ss_priv;
	uint8_t se_pri_chan = 0;
	uint8_t se_sec_chan = 0;
	int overlap = 0;
	int intolerant40 = 0;
	int i;

	if (chan->ic_ieee > QTN_2G_LAST_OPERATING_CHAN)
		return 1;

	intolerant40 = !ieee80211_chan_40M_tolerant(ic, chan);
	if (intolerant40)
		return 0;

	for (i = 0; i < IEEE80211_CHAN_MAX; i++) {
		TAILQ_FOREACH(se, &as->as_scan_list[i].asl_head, ase_list) {
			ieee80211_find_ht_pri_sec_chan(vap, &se->base,
						&se_pri_chan, &se_sec_chan);
			overlap = !ieee80211_chan_scan_ap_nonoverlap(ic,
					chan, se_pri_chan, se_sec_chan);
			if (overlap)
				return 0;
		}
	}

	return 1;
}

void
ieee80211_sta_chan_40_bw_permitted(struct ieee80211vap *vap,
	struct ieee80211_channel *chan, uint16_t *ch_list)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct sta_table *st = ic->ic_scan->ss_priv;
	struct sta_entry *se, *next;
	uint8_t se_pri_chan = 0;
	uint8_t se_sec_chan = 0;
	int overlap = 0;

	if (!chan || chan->ic_ieee > QTN_2G_LAST_OPERATING_CHAN)
		return;

	TAILQ_FOREACH_SAFE(se, &st->st_entry, se_list, next) {
		if (!IEEE80211_ADDR_EQ(se->base.se_macaddr, vap->iv_bss->ni_macaddr) &&
				(se->base.se_chan->ic_ieee <= QTN_2G_LAST_OPERATING_CHAN)) {
			ieee80211_find_ht_pri_sec_chan(vap, &se->base,
						&se_pri_chan, &se_sec_chan);
			overlap = !ieee80211_chan_scan_ap_nonoverlap(ic,
					chan, se_pri_chan, se_sec_chan);
			if (overlap)
				*ch_list |= 1 << se->base.se_chan->ic_ieee;
		}
	}

	return;
}

void
ieee80211_check_20_40_bss_coexist(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	int permit_40 = 0;

	if (ic->ic_opmode != IEEE80211_M_HOSTAP)
		return;

	permit_40 = ieee80211_ap_chan_40_bw_permitted(vap, ic->ic_bsschan);

	if (!permit_40 && IS_IEEE80211_24G_40(ic) && (ic->ic_20_40_coex_enable)) {
		ieee80211_change_bw(vap, BW_HT20, 0);
		ic->ic_coex_stats_update(ic, WLAN_COEX_STATS_BW_SCAN);
	}
	ic->ic_obss_scan_count = 1;
}
EXPORT_SYMBOL(ieee80211_check_20_40_bss_coexist);

static int
ieee80211_parse_20_40_intol_chan_report(struct ieee80211vap *vap,
	struct ieee80211_20_40_in_ch_rep *ie)
{
	struct ieee80211com *ic = vap->iv_ic;
	int intol_40 = 0;
	int i;

	memset(ic->ic_chan_intole_40, 0, sizeof(ic->ic_chan_intole_40));
	for (i = 0; i < ie->param_len - 1; i++)
		setbit(ic->ic_chan_intole_40, ie->chan[i]);

	if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
		intol_40 = !ieee80211_ap_chan_40_bw_permitted(vap, ic->ic_bsschan);
	}

	return intol_40;
}

static void
ieee8011_parse_obss_scan(struct ieee80211_node *ni, u_int8_t *frm)
{
	struct ieee80211_obss_scan_ie *obss_scan = &ni->ni_obss_ie;
	struct ieee80211_obss_scan_ie *ie = (struct ieee80211_obss_scan_ie *)frm;

	obss_scan->param_id = ie->param_id;
	obss_scan->param_len = ie->param_len;
	obss_scan->obss_passive_dwell = le16toh(ie->obss_passive_dwell);
	obss_scan->obss_active_dwell = le16toh(ie->obss_active_dwell);
	obss_scan->obss_trigger_interval = le16toh(ie->obss_trigger_interval);
	obss_scan->obss_passive_total = le16toh(ie->obss_passive_total);
	obss_scan->obss_active_total = le16toh(ie->obss_active_total);
	obss_scan->obss_channel_width_delay = le16toh(ie->obss_channel_width_delay);
	obss_scan->obss_activity_threshold = le16toh(ie->obss_activity_threshold);
}

static uint8_t
is_ieee80211_obss_grant(struct ieee80211com *ic, struct ieee80211_node *ni)
{
	struct ieee80211_node *ni_tmp;
	struct ieee80211_node_table *nt = &ic->ic_sta;
	uint8_t retval = 0;

	IEEE80211_NODE_LOCK_BH(nt);
	TAILQ_FOREACH(ni_tmp, &nt->nt_node, ni_list) {
		if (ni_tmp->ni_vap->iv_opmode != IEEE80211_M_HOSTAP)
			continue;
		if (ni == ni_tmp)
			continue;
		if (ni_tmp->ni_associd == 0)
			continue;
		if (ni_tmp->ni_obss_scan & IEEE80211_NODE_OBSS_RUNNING)
			retval =  WLAN_20_40_BSS_COEX_OBSS_EXEMPT_GRNT;
	}
	IEEE80211_NODE_UNLOCK_BH(nt);

	return retval;
}

static void
ieee80211_recv_action_public_coex(struct ieee80211_node *ni, struct sk_buff *skb,
	struct ieee80211_frame *wh, struct ieee80211_action *ia, int rssi)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	uint8_t *frm = (u_int8_t *)(ia + 1);
	uint8_t *efrm = skb->data + skb->len;
	struct ieee80211_20_40_coex_param *coex_ie;
	int change_bw = 0;

	if ((efrm - (u_int8_t *)ia) < sizeof(struct ieee80211_20_40_coex_param)) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
			wh, "mgt", "%s", "20/40 coexistence action frame header too small");
		vap->iv_stats.is_rx_elem_toosmall++;
		return;
	}
	coex_ie = (struct ieee80211_20_40_coex_param *)frm;
	if (coex_ie->param_id != IEEE80211_ELEMID_20_40_BSS_COEX) {
		vap->iv_stats.is_rx_elem_unknown++;
		return;
	}
	ni->ni_coex =  coex_ie->coex_param;
	frm = (u_int8_t *)(coex_ie + 1);

	if (ic->ic_opmode == IEEE80211_M_STA) {
		if (coex_ie->coex_param & WLAN_20_40_BSS_COEX_INFO_REQ)
			ieee80211_send_20_40_bss_coex(vap, 0);
		if (coex_ie->coex_param & WLAN_20_40_BSS_COEX_OBSS_EXEMPT_GRNT)
			del_timer_sync(&ic->ic_obss_timer);
		return;
	}

	/* For element id and length */
	if ((efrm - frm > 3) && (*frm == IEEE80211_ELEMID_20_40_IT_CH_REP))
		change_bw = ieee80211_parse_20_40_intol_chan_report(vap,
				(struct ieee80211_20_40_in_ch_rep *)frm);

	if (coex_ie->coex_param &
		(WLAN_20_40_BSS_COEX_40MHZ_INTOL | WLAN_20_40_BSS_COEX_20MHZ_WIDTH_REQ))
		change_bw = 1;

	if (change_bw && IS_IEEE80211_24G_40(ic) && (ic->ic_20_40_coex_enable)) {
		ieee80211_change_bw(vap, BW_HT20, 0);
		ic->ic_coex_stats_update(ic, WLAN_COEX_STATS_BW_ACTION);
	}

	if (coex_ie->coex_param & WLAN_20_40_BSS_COEX_OBSS_EXEMPT_REQ)
		ieee80211_send_20_40_bss_coex(vap, is_ieee80211_obss_grant(ic, ni));
}

static void
ieee80211_recv_sta_action_public_vendor(struct ieee80211_node *ni, struct sk_buff *skb,
	struct ieee80211_frame *wh, struct ieee80211_action *ia, int rssi)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct net_device *dev = vap->iv_dev;
	struct sk_buff *skb1;
	struct ieee80211_frame *wh1;
	const struct ieee80211_channel *ch = vap->iv_ic->ic_curchan;

	skb1 = skb_copy(skb, GFP_ATOMIC);
	if (skb1 == NULL)
		return;

	wh1 = (struct ieee80211_frame *)skb1->data;
	if (likely(ch)) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION, "%s: freq %u\n", __func__,
					ch->ic_freq);
		memcpy(wh1->i_dur, &ch->ic_freq, sizeof(wh1->i_dur));
	}

	ieee80211_skb_dev_set(dev, skb1);
	skb1->orig_dev = dev;
	skb_reset_mac_header(skb1);
	skb1->ip_summed = CHECKSUM_NONE;
	skb1->pkt_type = PACKET_OTHERHOST;
	skb1->protocol = htons(0x0019);  /* ETH_P_80211_RAW */
	/* set radio info */
	if (likely(ch))
		skb1->qtn_cb.radio_info.freq = ch->ic_freq;
	skb1->qtn_cb.radio_info.rssi = rssi;

	netif_rx(skb1);
}

/*
 * Process a public action frame
 */
static void
ieee80211_recv_action_public(struct ieee80211_node *ni, struct sk_buff *skb,
	struct ieee80211_frame *wh, struct ieee80211_action *ia, int rssi)
{
	struct ieee80211vap *vap = ni->ni_vap;

	switch (ia->ia_action) {
	case IEEE80211_ACTION_PUB_20_40_COEX:
		ieee80211_recv_action_public_coex(ni, skb, wh, ia, rssi);
		break;
	case IEEE80211_ACTION_PUB_TDLS_DISC_RESP:
		ieee80211_recv_action_public_tdls(ni, skb, wh, ia, rssi);
		break;
	case IEEE80211_ACTION_PUB_VENDOR_SPEC:
	case IEEE80211_ACTION_PUB_GAS_IRESP:
		if (ni->ni_vap->iv_opmode == IEEE80211_M_STA &&
			!ieee80211_is_repeater_ap_up(vap->iv_ic))
			ieee80211_recv_sta_action_public_vendor(ni, skb, wh, ia, rssi);
		break;
	default:
		IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_WARN, "TDLS %s: "
			"Received unsupported public action frame type %u\n",
			__func__, ia->ia_action);
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
			wh, "mgt", "%s: Received unsupported public action frame type %u\n",
			ia->ia_action);
		vap->iv_stats.is_rx_mgtdiscard++;
		break;
	}
}

/*
 * Process a TDLS Action Frame.
 * Note: these are management frames encapsulated in data frames
 */
static void
ieee80211_recv_action_tdls(struct ieee80211_node *ni, struct sk_buff *skb,
	struct ieee80211_action *ia, int ieee80211_header, int rssi)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211_tdls_params tdls;
	uint8_t *frm = (uint8_t *)(ia + 1);
	uint8_t *efrm = skb->data + skb->len;
	struct ether_header *eh;
	struct ieee80211_frame *wh;

	if (ia->ia_category != IEEE80211_ACTION_CAT_TDLS) {
		vap->iv_stats.is_rx_mgtdiscard++;
		IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_WARN, "TDLS %s: "
			"invalid category %d!\n", __func__, ia->ia_category);
		return;
	}

	IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_DBG, "TDLS %s: "
		"got TDLS type %u\n", __func__, ia->ia_action);

	memset(&tdls, 0, sizeof(tdls));

	if (ieee80211_header) {
		wh = (struct ieee80211_frame *)skb->data;
		ieee80211_parse_tdls_hdr(vap, &tdls, wh);
	} else {
		eh = (struct ether_header *)skb->data;
		tdls.da = eh->ether_dhost;
		tdls.sa = eh->ether_shost;
	}

	tdls.act = ia->ia_action;

	/* Parse fixed length fields */
	switch (ia->ia_action) {
	case IEEE80211_ACTION_TDLS_SETUP_REQ:
		IEEE80211_VERIFY_TDLS_LENGTH(efrm - frm,
			sizeof(tdls.diag_token) +
			sizeof(tdls.caps));
		tdls.diag_token = *frm;
		frm += sizeof(tdls.diag_token);
		tdls.caps = le16toh(*(__le16 *)frm);
		frm += sizeof(tdls.caps);
		break;
	case IEEE80211_ACTION_TDLS_SETUP_RESP:
		IEEE80211_VERIFY_TDLS_LENGTH(efrm - frm,
			sizeof(tdls.status) +
			sizeof(tdls.diag_token));
		tdls.status = le16toh(*(__le16 *)frm);
		frm += sizeof(tdls.status);
		tdls.diag_token = *frm;
		frm += sizeof(tdls.diag_token);
		if (tdls.status == IEEE80211_STATUS_SUCCESS) {
			tdls.caps = le16toh(*(__le16 *)frm);
			frm += sizeof(tdls.caps);
		}
		break;
	case IEEE80211_ACTION_TDLS_SETUP_CONFIRM:
		IEEE80211_VERIFY_TDLS_LENGTH(efrm - frm,
			sizeof(tdls.status) +
			sizeof(tdls.diag_token));
		tdls.status = le16toh(*(__le16 *)frm);
		frm += sizeof(tdls.status);
		tdls.diag_token = *frm;
		frm += sizeof(tdls.diag_token);
		break;
	case IEEE80211_ACTION_TDLS_TEARDOWN:
		IEEE80211_VERIFY_TDLS_LENGTH(efrm - frm,
			sizeof(tdls.reason));
		tdls.reason = le16toh(*(__le16 *)frm);
		frm += sizeof(tdls.reason);
		break;
	case IEEE80211_ACTION_TDLS_PTI:
		IEEE80211_VERIFY_TDLS_LENGTH(efrm - frm,
			sizeof(tdls.diag_token));
		tdls.diag_token = *frm;
		frm += sizeof(tdls.diag_token);
		break;
	case IEEE80211_ACTION_TDLS_CS_REQ:
		IEEE80211_VERIFY_TDLS_LENGTH(efrm - frm,
			sizeof(tdls.target_chan) +
			sizeof(tdls.reg_class));
		tdls.target_chan = *frm;
		frm += sizeof(tdls.target_chan);
		tdls.reg_class = *frm;
		frm += sizeof(tdls.reg_class);
		break;
	case IEEE80211_ACTION_TDLS_CS_RESP:
		IEEE80211_VERIFY_TDLS_LENGTH(efrm - frm,
			sizeof(tdls.status));
		tdls.status = le16toh(*(__le16 *)frm);
		frm += sizeof(tdls.status);
		break;
	case IEEE80211_ACTION_TDLS_PEER_PSM_REQ:
		IEEE80211_VERIFY_TDLS_LENGTH(efrm - frm,
			sizeof(tdls.diag_token));
		tdls.diag_token = *frm;
		frm += sizeof(tdls.diag_token);
		break;
	case IEEE80211_ACTION_TDLS_PEER_PSM_RESP:
		IEEE80211_VERIFY_TDLS_LENGTH(efrm - frm,
			sizeof(tdls.diag_token) +
			sizeof(tdls.status));
		tdls.diag_token = *frm;
		frm += sizeof(tdls.diag_token);
		tdls.status = le16toh(*(__le16 *)frm);
		frm += sizeof(tdls.status);
		break;
	case IEEE80211_ACTION_TDLS_PEER_TRAF_RESP:
		IEEE80211_VERIFY_TDLS_LENGTH(efrm - frm,
			sizeof(tdls.diag_token));
		tdls.diag_token = *frm;
		frm += sizeof(tdls.diag_token);
		break;
	case IEEE80211_ACTION_TDLS_DISC_REQ:
		IEEE80211_VERIFY_TDLS_LENGTH(efrm - frm,
			sizeof(tdls.diag_token));
		tdls.diag_token = *frm;
		IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_DBG, "TDLS %s: "
			"disc req - diag_token=%u\n", __func__, tdls.diag_token);
		frm += sizeof(tdls.diag_token);
		break;
	default:
		IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_WARN, "TDLS %s: "
			"unsupported TDLS action %u\n", __func__, ia->ia_action);
		vap->iv_stats.is_rx_badsubtype++;
		return;
	}

	if (ieee80211_parse_tdls_tlvs(vap, &tdls, &frm, efrm, ia->ia_action)) {
		return;
	}

	IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_DBG,
		"TDLS %s: process frame %u\n", __func__, ia->ia_action);
	/* Process the frame */
	switch (ia->ia_action) {
	case IEEE80211_ACTION_TDLS_SETUP_REQ:
		IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_DBG,
			"TDLS %s: process setup_req\n", __func__);
		ieee80211_tdls_recv_setup_req(ni, skb, rssi, &tdls);
		break;
	case IEEE80211_ACTION_TDLS_SETUP_RESP:
		IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_DBG,
			"TDLS %s: process setup_resp\n", __func__);
		ieee80211_tdls_recv_setup_resp(ni, skb, rssi, &tdls);
		break;
	case IEEE80211_ACTION_TDLS_SETUP_CONFIRM:
		IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_DBG,
			"TDLS %s: process setup_confirm\n", __func__);
		ieee80211_tdls_recv_setup_confirm(ni, skb, rssi, &tdls);
		break;
	case IEEE80211_ACTION_TDLS_TEARDOWN:
		IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_DBG,
			"TDLS %s: process teardown\n", __func__);
		ieee80211_tdls_recv_teardown(ni, skb, rssi, &tdls);
		break;
	case IEEE80211_ACTION_TDLS_PTI:
		break;
	case IEEE80211_ACTION_TDLS_CS_REQ:
		ieee80211_tdls_recv_chan_switch_req(ni, skb, rssi, &tdls);
		break;
	case IEEE80211_ACTION_TDLS_CS_RESP:
		ieee80211_tdls_recv_chan_switch_resp(ni, skb, rssi, &tdls);
		break;
	case IEEE80211_ACTION_TDLS_PEER_PSM_REQ:
		break;
	case IEEE80211_ACTION_TDLS_PEER_PSM_RESP:
		break;
	case IEEE80211_ACTION_TDLS_PEER_TRAF_RESP:
		break;
	case IEEE80211_ACTION_TDLS_DISC_REQ:
		IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_DBG,
			"TDLS %s: process disc_req\n", __func__);
		ieee80211_tdls_recv_disc_req(ni, skb, rssi, &tdls);
		break;
	default:
		IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_WARN,
			"TDLS %s: unsupported TDLS action %u\n", __func__, ia->ia_action);
		vap->iv_stats.is_rx_badsubtype++;
		return;
	}

	vap->iv_stats.is_rx_tdls++;
	IEEE80211_NODE_STAT(ni, rx_tdls_action);
}

void ieee80211_recv_meas_basic_report(struct ieee80211_node *ni,
		struct ieee80211_ie_measrep_basic *meas_rep_basic)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;

	if (meas_rep_basic->basic_report & IEEE80211_MEASURE_BASIC_REPORT_RADAR) {
		if (meas_rep_basic->chan_num == ieee80211_chan2ieee(ic, ic->ic_bsschan)) {
			ic->ic_radar_detected(ic, 0);
		}
	}
}
static void
ieee80211_input_qtnie_common(struct ieee80211_node *ni, struct ieee80211_ie_qtn *qtnie)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;

	ni->ni_vsp_version = IEEE80211_QTN_VSP_V_NONE;

	if (IEEE80211_QTN_IE_GE_V3(qtnie) && (ic->ic_curmode >= IEEE80211_MODE_11NA)) {
		ni->ni_implicit_ba = qtnie->qtn_ie_implicit_ba_tid_h;
		ni->ni_implicit_ba_size = qtnie->qtn_ie_implicit_ba_size;
		ni->ni_implicit_ba_size = ni->ni_implicit_ba_size << IEEE80211_QTN_IE_BA_SIZE_SH;
	}

	if (IEEE80211_QTN_IE_GE_V4(qtnie)) {
		ni->ni_vsp_version = qtnie->qtn_ie_vsp_version;
	}

	if (IEEE80211_QTN_IE_GE_V5(qtnie)) {
		ni->ni_ver_sw = ntohl(get_unaligned(&qtnie->qtn_ie_ver_sw));
		ni->ni_ver_hw = ntohs(get_unaligned(&qtnie->qtn_ie_ver_hw));
		ni->ni_ver_platform_id = ntohs(get_unaligned(&qtnie->qtn_ie_ver_platform_id));
		ni->ni_ver_timestamp = ntohl(get_unaligned(&qtnie->qtn_ie_ver_timestamp));
		ni->ni_ver_flags = ntohl(get_unaligned(&qtnie->qtn_ie_ver_flags));
	} else {
		ni->ni_ver_sw = 0;
		ni->ni_ver_hw = 0;
		ni->ni_ver_platform_id = 0;
		ni->ni_ver_timestamp = 0;
		ni->ni_ver_flags = 0;
	}

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
		"[%pM] QTN IE flags 0x%x ba %u sw " DBGFMT_BYTEFLD4_P
		" hw 0x%x plat %u ts %u ver_flags 0x%08x\n",
		ni->ni_macaddr,
		qtnie->qtn_ie_my_flags,
		ni->ni_implicit_ba_size,
		DBGFMT_BYTEFLD4_V(ni->ni_ver_sw),
		ni->ni_ver_hw,
		ni->ni_ver_platform_id,
		ni->ni_ver_timestamp,
		ni->ni_ver_flags);
}

static int
ieee80211_input_update_lncb_4addr(struct ieee80211_node *ni, int lncb_4addr)
{
	if (ni->ni_associd && lncb_4addr != !!(ni->ni_ext_flags & IEEE80211_NODE_LNCB_4ADDR))
		return -EINVAL;

	if (lncb_4addr)
		ni->ni_ext_flags |= IEEE80211_NODE_LNCB_4ADDR;
	else
		ni->ni_ext_flags &= ~IEEE80211_NODE_LNCB_4ADDR;

	return 0;
}

static int
ieee80211_input_assoc_req_qtnie(struct ieee80211_node *ni, struct ieee80211vap *vap,
				struct ieee80211_ie_qtn *qtnie)
{
	struct ieee80211com *ic = vap->iv_ic;
	uint32_t ver = 0;
	int lncb_4addr;

	if (qtnie == NULL) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
			"%s: No QTN IE in assoc req\n", __func__);
		/* Flush any state from a previous association */
		FREE(ni->ni_qtn_assoc_ie, M_DEVBUF);
		ni->ni_qtn_assoc_ie = NULL;
		return ieee80211_input_update_lncb_4addr(ni, 0);
	}

	if (vap->iv_debug & IEEE80211_MSG_ASSOC) {
		if (IEEE80211_QTN_IE_GE_V5(qtnie))
			ver = 5;
		else if (IEEE80211_QTN_IE_GE_V4(qtnie))
			ver = 4;
		else if (IEEE80211_QTN_IE_GE_V3(qtnie))
			ver = 3;
		else if (IEEE80211_QTN_IE_GE_V2(qtnie))
			ver = 2;
		else
			ver = 1;

		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
			"%s: Received QTN IE v%u in assoc req, flags=%02x %02x\n",
			__func__, ver, qtnie->qtn_ie_flags,
			IEEE80211_QTN_TYPE_ENVY_LEGACY(qtnie) ?  0x0 : qtnie->qtn_ie_my_flags);
	}

	ieee80211_saveie(&ni->ni_qtn_assoc_ie, (u_int8_t *)qtnie);

	/*
	 * If the station requested bridge mode but it is not advertised,
	 * restart.  This could happen if the client is using a stale
	 * beacon.
	 */
	if ((qtnie->qtn_ie_flags & IEEE80211_QTN_BRIDGEMODE) &&
			!(vap->iv_flags_ext & IEEE80211_FEXT_WDS)) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
			"%s: Bridge mode required by remote peer but disabled on AP\n", __func__);

		return -EINVAL;
	}

	ni->ni_implicit_ba = 0;

	/* Implicit BA flags for the STA */
	if (IEEE80211_QTN_IE_GE_V2(qtnie) && (ic->ic_curmode >= IEEE80211_MODE_11NA)) {
		ni->ni_implicit_ba_valid = 1;
		ni->ni_implicit_ba = qtnie->qtn_ie_implicit_ba_tid;
	}
	lncb_4addr = 0;

	if (IEEE80211_QTN_TYPE_ENVY_LEGACY(qtnie))
		return ieee80211_input_update_lncb_4addr(ni, lncb_4addr);

	/* See whether to do 4 address LNCB encapsulation */
	if (qtnie->qtn_ie_my_flags & IEEE80211_QTN_LNCB) {
		lncb_4addr = 1;
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
			"Client " DBGMACVAR " supports 4 addr LNCB\n", DBGMACFMT(ni->ni_macaddr));
	}
	if (!(vap->iv_flags_ext & IEEE80211_FEXT_WDS)) {
		lncb_4addr = 0;
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
			"Client " DBGMACVAR " 4 addr flag cleared - I'm not a bridge\n",
			DBGMACFMT(ni->ni_macaddr));
	}

	ieee80211_input_qtnie_common(ni, qtnie);

	return ieee80211_input_update_lncb_4addr(ni, lncb_4addr);
}

static void
ieee80211_input_assoc_resp_qtnie(struct ieee80211_node *ni, struct ieee80211vap *vap,
				struct ieee80211_ie_qtn *qtnie)
{
	if (qtnie == NULL)
		return;

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
		"%s: Received QTN IE v%u in assoc resp, flags=%02x %02x\n",
		__func__,
		IEEE80211_QTN_TYPE_ENVY(qtnie) ?  1 : 2,
		qtnie->qtn_ie_flags,
		IEEE80211_QTN_TYPE_ENVY_LEGACY(qtnie) ?  0x0 : qtnie->qtn_ie_my_flags);

	ni->ni_ext_flags &= ~IEEE80211_NODE_LNCB_4ADDR;

	if (IEEE80211_QTN_TYPE_ENVY_LEGACY(qtnie)) {
		return;
	}

	/* LNCB with 4 addresses can only be done when the AP is a bridge. */
	if (qtnie->qtn_ie_my_flags & IEEE80211_QTN_LNCB) {
		ni->ni_ext_flags |= IEEE80211_NODE_LNCB_4ADDR;
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
			"AP " DBGMACVAR " supports 4 addr LNCB\n",
			DBGMACFMT(ni->ni_macaddr));
	}
	/* No 4 addr packets if not bridge mode */
	if (!(qtnie->qtn_ie_my_flags & IEEE80211_QTN_BRIDGEMODE)
			|| !(vap->iv_flags_ext & IEEE80211_FEXT_WDS)) {
		ni->ni_ext_flags &= ~IEEE80211_NODE_LNCB_4ADDR;
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
			"AP " DBGMACVAR " is not a bridge - clearing LNCB flag\n",
			DBGMACFMT(ni->ni_macaddr));
	}

	ieee80211_input_qtnie_common(ni, qtnie);
}

int
ieee80211_input_tdls_qtnie(struct ieee80211_node *ni, struct ieee80211vap *vap,
				struct ieee80211_ie_qtn *qtnie)
{
	if (qtnie == NULL) {
		IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_WARN,
			"%s: No QTN IE in TDLS action\n", __func__);
		/* Flush any state from a previous association */
		FREE(ni->ni_qtn_assoc_ie, M_DEVBUF);
		ni->ni_qtn_assoc_ie = NULL;
		return 1;
	}

	IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_DBG,
		"%s: Received QTN IE v%u in TDLS action, flags=%02x %02x\n",
		__func__,
		IEEE80211_QTN_TYPE_ENVY(qtnie) ?  1 : 2,
		qtnie->qtn_ie_flags,
		IEEE80211_QTN_TYPE_ENVY_LEGACY(qtnie) ?  0x0 : qtnie->qtn_ie_my_flags);

	ieee80211_saveie(&ni->ni_qtn_assoc_ie, (u_int8_t *)qtnie);

	ni->ni_implicit_ba = 0;
	/* Implicit BA flags for the STA */
	if (IEEE80211_QTN_IE_GE_V2(qtnie)) {
		ni->ni_implicit_ba_valid = 1;
		ni->ni_implicit_ba = qtnie->qtn_ie_implicit_ba_tid;
	}

	if (IEEE80211_QTN_TYPE_ENVY_LEGACY(qtnie)) {
		return 1;
	}

	ieee80211_input_qtnie_common(ni, qtnie);

	return 0;
}

#ifdef CONFIG_QVSP
static void
ieee80211_input_assoc_resp_vspie(struct ieee80211vap *vap, struct ieee80211_ie_vsp *vspie,
				uint8_t *efrm)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_ie_vsp_item *item_p = &vspie->item[0];
	int i;

	if ((vspie == NULL) || !ic->ic_vsp_set) {
		return;
	}

	for (i = 0; i < vspie->item_cnt; i++) {
		if ((uint8_t *)item_p > efrm) {
			printk(KERN_INFO "VSP: invalid count in assoc resp IE\n");
			return;
		}
		item_p++;
	}

	item_p = &vspie->item[0];
	for (i = 0; i < vspie->item_cnt; i++) {
		ic->ic_vsp_set(ic, item_p->index, ntohl(item_p->value));
		item_p++;
	}
}

static void ieee80211_recv_action_vsp(struct ieee80211_node *ni, uint8_t *frm, uint8_t *efrm)
{
	static const u_int8_t q_oui[3] =
		{QTN_OUI & 0xff, (QTN_OUI >> 8) & 0xff, (QTN_OUI >> 16) & 0xff};
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;

	if (sizeof(struct ieee80211_qvsp_act_header_s) > (efrm - frm)) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION,
				"no enough data for Quantenna VSP action field %lu\n", efrm - frm);
		vap->iv_stats.is_rx_elem_toosmall++;
		return;
	}
	struct ieee80211_qvsp_act_header_s *qa = (struct ieee80211_qvsp_act_header_s *)frm;

	if (memcmp(q_oui, qa->oui, sizeof(q_oui)) || qa->type != QVSP_ACTION_TYPE_VSP) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION,
			"Not Quantenna VSP action frame (%02x%02x%02x %u %u)\n",
			qa->oui[0], qa->oui[1], qa->oui[2], qa->type, qa->action);
		return;
	}

	switch (qa->action) {
	case QVSP_ACTION_STRM_CTRL: {
		struct ieee80211_qvsp_act_strm_ctrl_s *qsc =
				(struct ieee80211_qvsp_act_strm_ctrl_s *)qa;
		struct ieee80211_qvsp_strm_id *qsci = &qsc->strm_items[0];
		struct ieee80211_qvsp_strm_dis_attr attr;
		int i;

		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION, "%s",
			"VSP: received strm ctrl frame\n");
		if (frm >= efrm) {
			printk("VSP: strm ctrl frame overflow\n");
			return;
		}
		if (qsc->count == 0) {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION,
				"VSP: invalid stream count (%u)\n", qsc->count);
			return;
		}
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION,
			"VSP: set state to %u for %u streams\n",
			qsc->strm_state, qsc->count);

		if (!ic->ic_vsp_strm_state_set) {
			return;
		}

		attr.throt_policy = qsc->dis_attr.throt_policy;
		attr.throt_rate = qsc->dis_attr.throt_rate;
		attr.demote_rule = qsc->dis_attr.demote_rule;
		attr.demote_state = qsc->dis_attr.demote_state;
		for (i = 0; i < qsc->count; i++) {
			if ((uint8_t *)qsci >= efrm) {
				printk(KERN_WARNING "VSP: Frame overflow on input - discarding\n");
				return;
			}
			ic->ic_vsp_strm_state_set(ic, qsc->strm_state, qsci, &attr);
			qsci++;
		}
		break;
	}
	case QVSP_ACTION_VSP_CTRL: {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION, "%s",
			"VSP: Received VSP_ACTION_VSP_CTRL frame\n");
		struct ieee80211_qvsp_act_vsp_ctrl_s *qsc =
					(struct ieee80211_qvsp_act_vsp_ctrl_s *)qa;
		struct ieee80211_qvsp_act_vsp_ctrl_item_s *qsci = &qsc->ctrl_items[0];
		int i;

		if (frm >= efrm) {
			printk("VSP: ctrl frame overflow\n");
			return;
		}

		if (qsc->count) {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION,
				"VSP: %u config items\n", qsc->count);
		}

		if (!ic->ic_vsp_configure) {
			return;
		}

		for (i = 0; i < qsc->count; i++) {
			if ((uint8_t *)qsci >= efrm) {
				printk(KERN_WARNING "VSP: Frame overflow on input - discarding\n");
				return;
			}
			ic->ic_vsp_configure(ic, ntohl(qsci->index), ntohl(qsci->value));
			qsci++;
		}
		break;
	}
	default:
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION,
			"VSP: Unsupported VSP action type: %d\n", qa->type);
		break;
	}
}
#endif

void ieee80211_recv_action_sa_query(struct ieee80211_node *ni,
		struct ieee80211_action *ia,
		struct ieee80211_frame *wh,
		u_int8_t *efrm)
{
	struct ieee80211_action_sa_query *sa_query = (struct ieee80211_action_sa_query *)ia;
	uint16_t tid = le16toh(get_unaligned((__le16 *)&sa_query->at_tid));

	switch (ia->ia_action) {
	case IEEE80211_ACTION_W_SA_QUERY_REQ:
		ieee80211_send_sa_query(ni, IEEE80211_ACTION_W_SA_QUERY_RESP, tid);
	break;
	case IEEE80211_ACTION_W_SA_QUERY_RESP:
		if (tid == ni->ni_sa_query_tid &&
			(ni->ni_sa_query_timeout && time_before(jiffies, ni->ni_sa_query_timeout))) {
			del_timer(&ni->ni_sa_query_response_wait_timer);
			ni->ni_sa_query_timeout = 0;
		}
	break;
	default:
		return;
	}
}

/*
 * Handle an HT Action frame.
 */
void
ieee80211_action_ht(struct ieee80211_node *ni, struct sk_buff *skb,
			struct ieee80211_frame *wh, int subtype,
			struct ieee80211_action *ia, u_int8_t *frm, u_int8_t *efrm)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_action_ht_txchwidth *iachwidth;
	enum ieee80211_cwm_width  chwidth;
	u_int8_t new_val;
	int new_mode;

	switch (ia->ia_action) {
	case IEEE80211_ACTION_HT_TXCHWIDTH:
		if (ieee80211_verify_length(vap, efrm - frm,
				sizeof(struct ieee80211_action_ht_txchwidth), wh, subtype))
			return;

		iachwidth = (struct ieee80211_action_ht_txchwidth *) (void*)frm;
		chwidth = (iachwidth->at_chwidth == IEEE80211_A_HT_TXCHWIDTH_2040) ?
				IEEE80211_CWM_WIDTH40 : IEEE80211_CWM_WIDTH20;

		/* Check for channel width change */
		if (chwidth != ni->ni_chwidth) {
			ni->ni_newchwidth = 1;
		}

		/* update node's recommended tx channel width */
		ni->ni_chwidth = chwidth;

		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION,
				"process HT tx channel width %u from %pM\n",
				chwidth, ni->ni_macaddr);

		ieee80211_update_node_bw(ni, chwidth);

		break;
	case IEEE80211_ACTION_HT_MIMOPWRSAVE:
		/*
		 * Parsing of the input SM PS action frame. This moves the station in and out
		 * of SM Power Save and also changes the mode when enabled (dynamic, static).
		 */
		new_mode = IEEE80211_HTCAP_C_MIMOPWRSAVE_NONE;
		if (ieee80211_verify_length(vap, efrm - frm,
				sizeof(struct ieee80211_action_ht_mimopowersave), wh, subtype))
			return;
		frm += 2; /* action type, action category */
		new_val = *frm;
		/* Bit 0 - enabled/disabled */
		if (new_val & 0x1) {
			/* Bit 1 - static/dynamic */
			if (new_val & 0x2) {
				new_mode = IEEE80211_HTCAP_C_MIMOPWRSAVE_DYNAMIC;
			} else {
				new_mode = IEEE80211_HTCAP_C_MIMOPWRSAVE_STATIC;
			}
		} else {
			/* Disabled - don't care what the bit 1 value says */
			new_mode = IEEE80211_HTCAP_C_MIMOPWRSAVE_NONE;
		}
		/* Change the mode with the MUC if different from current mode */
		if (new_mode != ni->ni_htcap.pwrsave) {
			/* Inform the MUC */
			if (ic->ic_smps != NULL) {
				(*ic->ic_smps)(ni, new_mode);
			}
			ni->ni_htcap.pwrsave = new_mode;
		}
		break;
	case IEEE80211_ACTION_HT_NCBEAMFORMING:
		if (ieee80211_verify_length(vap, efrm - frm,
				sizeof(struct ieee80211_action_ht_bf), wh, subtype))
			return;

		/* Call the driver to do some stuff if it wants to */
		if (ic->ic_ncbeamforming != NULL) {
			(*ic->ic_ncbeamforming)(ni, skb);
		}
		break;
	default:
		vap->iv_stats.is_rx_mgtdiscard++;
		break;
	}
}

/*
 * True if the station is probably an Intel 5100 or 5300 device.
 */
static inline int
ieee80211_is_intel_old(struct ieee80211_node *ni, uint16_t peer_cap)
{
	return (ieee80211_node_is_intel(ni) &&
		!(peer_cap & IEEE80211_HTCAP_C_RXSTBC));
}

/*
 * Intel client type identification:
 * 620x:
 *   2x2, MCS 32, no TX STBC support, but support RX STBC: Action: send HT20 Channel Width Notification
 * 5100/5300:
 *   2x2(5100) or 3x3 (5300), MCS 32, no TX STBC support and no RX STBC support: Action: send HT20 Channel Width Notification,
 *   restrict to use 2 TX Chains, and use LGI for TX.
 * 6300:
 *   support 3x3, MCS 32, no TX STBC and SUPPORT RX STBC: treat it as normal client, Action: none
 */
static void
ieee80211_blacklist_ba(struct ieee80211_node *ni, u_int8_t tid)
{
	struct shared_params *params = qtn_mproc_sync_shared_params_get();
	struct ieee80211com *ic = ni->ni_ic;
	struct ieee80211vap *vap = ni->ni_vap;
	u_int16_t peer_cap = IEEE80211_HTCAP_CAPABILITIES(&ni->ni_ie_htcap);

	if ((ni->ni_qtn_flags & QTN_IS_BCM_NODE) && (params->iot_tweaks & QTN_IOT_BCM_NO_3SS_MCS_TWEAK)) {
		ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_NSS3] = 0x00;
	} else if ((ni->ni_vendor == PEER_VENDOR_RLNK) && (params->iot_tweaks & QTN_IOT_RLNK_NO_3SS_MCS_TWEAK) && !(IEEE80211_NODE_IS_VHT(ni))) {
		ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_NSS3] = 0x00;
	}
	/* WAR: 11n LDPC in IOT mode is allowed only if:
	        iwpriv wifi0 set_ldpc_non_qtn 1
		Node is BRCM
		BRCM node indicated support for LDPC  */
	if (!(vap->iv_ht_flags & IEEE80211_HTF_LDPC_ALLOW_NON_QTN) &&
		(ni->ni_qtn_assoc_ie == NULL) &&
		!(ni->ni_qtn_flags & QTN_IS_BCM_NODE) &&
		(ni->ni_htcap.cap & IEEE80211_HTCAP_C_LDPCCODING)) {
		/* Keep LDPC disabled for non-QTN, non-BRCM devices for now */
		ni->ni_htcap.cap &= ~IEEE80211_HTCAP_C_LDPCCODING;
	}

	if ((ni->ni_qtn_flags & QTN_IS_BCM_NODE) && (params->iot_tweaks & QTN_IOT_BCM_TWEAK)) {
		ieee80211_note(ni->ni_vap, "TX BA rejected for BCM client %s\n",
				ether_sprintf(ni->ni_macaddr));
		ieee80211_send_delba(ni, tid, 0, IEEE80211_REASON_STA_NOT_USE);
		ieee80211_node_tx_ba_set_state(ni, tid, IEEE80211_BA_BLOCKED, 0);
		return;
	}

	/*
	 * For Realtek devices, disable A-MSDU since we got better performance without A-MSDU,
	 * but this condition may be changed in future
	 */
	if ((ni->ni_qtn_flags & QTN_IS_REALTEK_NODE) && (params->iot_tweaks & QTN_IOT_RTK_NO_AMSDU_TWEAK)) {
		ni->ni_ba_tx[tid].flags &= ~QTN_BA_ARGS_F_AMSDU;
	}

	if (ieee80211_is_intel_old(ni, peer_cap)) {
		/*
		 * Old Intel devices do not Ack BBF QoS null frames. This can
		 * cause unstability and disconnections.
		 */
		ni->ni_bbf_disallowed = 1;
	}

	/* Try to identify problem peers - may cause other peer stations to be blacklisted */
	if ((((params->iot_tweaks & QTN_IOT_INTEL5100_TWEAK) && !(ni->ni_htcap.cap & IEEE80211_HTCAP_C_RXSTBC)) ||
			((params->iot_tweaks & QTN_IOT_INTEL6200_TWEAK) && (ni->ni_htcap.cap & IEEE80211_HTCAP_C_RXSTBC))) &&
			(ni->ni_qtn_assoc_ie == NULL) && !(ni->ni_qtn_flags & QTN_IS_BCM_NODE) &&
			(ni->ni_htcap.mpduspacing == 5) &&
			!(peer_cap & IEEE80211_HTCAP_C_TXSTBC) &&
			(peer_cap & IEEE80211_HTCAP_C_SHORTGI20) &&
			((ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_UEQM1] & 0x1) == 0x01) && /* Some Intel firmware versions support MCS 32 */
			(ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_UEQM2] == 0) &&
			(ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_UEQM3] == 0) &&
			(ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_UEQM4] == 0) &&
			(ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_UEQM5] == 0) &&
			(ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_UEQM6] == 0)) {
		/* Currently disabling BBF to intel. With BBF, it periodically sends delba every 30 seconds */
		ni->ni_bbf_disallowed = 1;
		/* TX BA does not work with Intel 5100 when running on HT40 mode */
		if (params->iot_tweaks & QTN_IOT_INTEL_SEND_NCW_ACTION) {
			ieee80211_note(ni->ni_vap, "TX Notify Chan Width Action to STA %s\n",
				       ether_sprintf(ni->ni_macaddr));
			ic->ic_send_notify_chan_width_action(ni->ni_vap, ni, 0);
		} else if (get_hardware_revision() <= HARDWARE_REVISION_RUBY_D) {
			ieee80211_note(ni->ni_vap, "TX BA rejected for incompatible peer %s\n",
				       ether_sprintf(ni->ni_macaddr));
			ieee80211_send_delba(ni, tid, 0, IEEE80211_REASON_STA_NOT_USE);
			ieee80211_node_tx_ba_set_state(ni, tid, IEEE80211_BA_BLOCKED, 0);
		}

		if (!(peer_cap & IEEE80211_HTCAP_C_RXSTBC)) {
			if (ni->ni_associd && (ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_NSS3] == 0)) {
				ni->ni_qtn_flags |= QTN_IS_INTEL_5100_NODE;
			} else {
				ni->ni_qtn_flags |= QTN_IS_INTEL_5300_NODE;
			}

			/* tell Muc only to use two 2 TX chain for Intel 5x00 client
			 * and turn off SGI for TX to them
			 */
			if (params->iot_tweaks & QTN_IOT_INTEL_NOAGG2TXCHAIN_TWEAK) {
				ni->ni_flags |= IEEE80211_NODE_2_TX_CHAINS;
				ieee80211_note(ni->ni_vap, "STA %s is Intel %s: disable TX side of SGI and restrict to 2 TX chains\n",
					       ether_sprintf(ni->ni_macaddr),
					       (ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_NSS3] == 0xFF) ? "5300" : "5100");
				/* disable 5100 aggregation */
				if ((ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_NSS3] == 0) && ni->ni_associd) {
					ieee80211_note(ni->ni_vap, "TX BA rejected for Intel 5100 %s\n",
						       ether_sprintf(ni->ni_macaddr));
					ieee80211_send_delba(ni, tid, 0, IEEE80211_REASON_STA_NOT_USE);
					ieee80211_node_tx_ba_set_state(ni, tid, IEEE80211_BA_BLOCKED, 0);
				}
			}
		}
	}
}

static inline u_int16_t lower_power_of_2(u_int16_t bsize)
{
	if (bsize && !((bsize - 1) & bsize)) {
		/* Already a power of 2 */
		return bsize;
	} else if (!bsize) {
		return 0;
	}

	bsize--;
	bsize |= bsize >> 1;
	bsize |= bsize >> 2;
	bsize |= bsize >> 4;
	bsize |= bsize >> 8;
	return (bsize - (bsize >> 1));
}

static __inline int ieee80211_action_ba_permitted(struct ieee80211_node *ni, u_int8_t tid)
{
	struct ieee80211vap *vap = ni->ni_vap;

	if (vap->rx_ba_decline) {
		return 0;
	}

	if (!(vap->iv_ba_control & (1 << tid))) {
		return 0;
	}

	if (ni->ni_ba_rx[tid].type != IEEE80211_BA_IMMEDIATE) {
		return 0;
	}

	if ((get_hardware_revision() <= HARDWARE_REVISION_RUBY_D) &&
			((ni->ni_qtn_flags & QTN_IS_INTEL_5300_NODE) ||
				(ni->ni_qtn_flags & QTN_IS_INTEL_5100_NODE))) {
		return 0;
	}

	return 1;
}

/*
 * Identify client during BA setup
 * For some IOT client, such as Intel6205 with some version, we cannot identify them during
 * association. But we can identify from BA setup. So it is necessary to update the node
 * information into MuC/AuC then.
 */
static void
ieee80211_node_identify_ba(struct ieee80211com *ic, struct ieee80211_node *ni, uint8_t tid)
{
	int changed = 0;

	if (!(ni->ni_qtn_flags & QTN_IS_INTEL_NODE) &&
		(ieee80211_node_is_intel(ni))) {
		changed = 1;
		ni->ni_vendor = PEER_VENDOR_INTEL;
	}

	/* let it decide whether to use any tweaks such as disable BBF */
	ieee80211_blacklist_ba(ni, tid);

	/* update into MuC/AuC if vendor changed */
	if (changed)
		ic->ic_node_update(ni);
}

/*
 * Handle a Block Acknowledgement Action frame.
 */
static void
ieee80211_action_ba(struct ieee80211_node *ni, struct ieee80211_frame *wh, int subtype,
			struct ieee80211_action *ia, u_int8_t *frm, u_int8_t *efrm)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	u_int8_t tid;
	u_int8_t initiator;
	u_int16_t reason;
	u_int16_t temp16;
	struct ba_action_resp ba_req_resp;
	struct ieee80211_action_ba_addba_resp *ba_resp;
	struct ieee80211_action_data act;
#ifdef CONFIG_QVSP
	struct ieee80211_ba_throt *ba_throt;
#endif

	switch (ia->ia_action) {
	case IEEE80211_ACTION_BA_ADDBA_REQ:
		if (ieee80211_verify_length(vap, efrm - frm,
				sizeof(struct ieee80211_action_ba_addba_req), wh, subtype))
			return;
		frm += 2; /* action type = 1 octet and category = 1 octet */

		temp16 = LE_READ_2((frm + 1)); /* ba parameter field is 1 octet ahead */
		tid = ((temp16) & IEEE80211_A_BA_TID_M) >> IEEE80211_A_BA_TID_S;
#ifdef CONFIG_QVSP
		ba_throt = &ni->ni_ba_rx[tid].ba_throt;
		if (ni->ni_vap->iv_opmode == IEEE80211_M_HOSTAP) {
			if (ba_throt->throt_intv &&
				ba_throt->last_setup_jiffies &&
				time_before(jiffies, (ba_throt->last_setup_jiffies +
						      msecs_to_jiffies(ba_throt->throt_intv)))) {
				IEEE80211_DPRINTF(vap, IEEE80211_MSG_VSP,
					"VSP: discard ADDBA REQ from node %u tid %d\n",
					IEEE80211_AID(ni->ni_associd), tid);
				break;
			}
		}
#endif
		ni->ni_ba_rx[tid].dlg_in = *frm;
		ni->ni_ba_rx[tid].type = (temp16 & IEEE80211_A_BA_IMMEDIATE) ? IEEE80211_BA_IMMEDIATE :
						IEEE80211_BA_DELAYED;
		ni->ni_ba_rx[tid].flags = (temp16 & IEEE80211_A_BA_AMSDU_SUPPORTED) ? QTN_BA_ARGS_F_AMSDU : 0;
		ni->ni_ba_rx[tid].buff_size =
			lower_power_of_2((((temp16) & IEEE80211_A_BA_BUFF_SIZE_M) >> IEEE80211_A_BA_BUFF_SIZE_S));
#ifdef CONFIG_QVSP
		ni->ni_ba_rx[tid].ba_throt.unthroted_win_size = ni->ni_ba_rx[tid].buff_size;
#endif
		if (ni->ni_vap->iv_opmode == IEEE80211_M_WDS && tid == IEEE80211_WDS_LINK_MAINTAIN_BA_TID &&
				ni->ni_qtn_assoc_ie) {
			/* For WDS, use larger buffer size for TID 0 to get more throughput */
			if ((ni->ni_ba_rx[tid].buff_size == 0) ||
					(ni->ni_ba_rx[tid].buff_size > IEEE80211_DEFAULT_BA_WINSIZE_H)) {
				ni->ni_ba_rx[tid].buff_size = IEEE80211_DEFAULT_BA_WINSIZE_H;
			}
		} else {
			if ((ni->ni_ba_rx[tid].buff_size == 0) ||
					(ni->ni_ba_rx[tid].buff_size > vap->iv_max_ba_win_size)) {
				ni->ni_ba_rx[tid].buff_size = vap->iv_max_ba_win_size;
			}
#ifdef CONFIG_QVSP
			if (ni->ni_vap->iv_opmode == IEEE80211_M_HOSTAP) {
				if (ba_throt->throt_win_size &&
					(ba_throt->throt_win_size < ni->ni_ba_rx[tid].buff_size)) {
					IEEE80211_DPRINTF(vap, IEEE80211_MSG_VSP,
						"VSP: limit node %u tid %d BA winsize from %u to %u\n",
						IEEE80211_AID(ni->ni_associd), tid, ni->ni_ba_rx[tid].buff_size,
						ba_throt->throt_win_size);
					ni->ni_ba_rx[tid].buff_size = ba_throt->throt_win_size;
				}
			}
#endif
		}

		frm += 3; /* dialog = 1 octet and ba parameters = 2 octets */
		temp16 = LE_READ_2((frm));
		ni->ni_ba_rx[tid].timeout = temp16;
		if(ni->ni_ba_rx[tid].timeout != 0) {
			ni->ni_ba_rx[tid].timeout = 0;
		}

		frm += 2; /* timeout = 2 octets */
		temp16 = LE_READ_2((frm));
		ni->ni_ba_rx[tid].frag = (temp16 & IEEE80211_A_BA_FRAG_M);
		ni->ni_ba_rx[tid].seq = (temp16 & IEEE80211_A_BA_SEQ_M) >> IEEE80211_A_BA_SEQ_S;

		if (ieee80211_action_ba_permitted(ni, tid)) {
			ni->ni_ba_rx[tid].state = IEEE80211_BA_ESTABLISHED;
			ba_req_resp.reason = IEEE80211_STATUS_SUCCESS;
			IEEE80211_NOTE(vap, IEEE80211_MSG_11N, ni,
				"block ack requested by peer tid accepted: %u size %u seq %u",
				tid, ni->ni_ba_rx[tid].buff_size, ni->ni_ba_rx[tid].seq);
			if (ni->ni_vap->iv_opmode == IEEE80211_M_WDS) {
		                ic->ic_pm_reason = IEEE80211_PM_LEVEL_RCVD_ADDBA_REQ;
				ieee80211_pm_queue_work(ic);
			}
		} else {
			ni->ni_ba_rx[tid].state = IEEE80211_BA_BLOCKED;
			ba_req_resp.reason = IEEE80211_STATUS_PEER_MECHANISM_REJECT;
			IEEE80211_NOTE(vap, IEEE80211_MSG_11N, ni,
				"block ack requested by peer tid denied: %u size %u seq %u",
				tid, ni->ni_ba_rx[tid].buff_size, ni->ni_ba_rx[tid].seq);
		}

#ifdef CONFIG_QVSP
		ba_throt->last_setup_jiffies = jiffies;
#endif

		/* Call the driver to inform the MuC */
		if (ic->ic_htaddba != NULL) {
			(*ic->ic_htaddba)(ni, tid, 0);
		}

		/* send the response */
		act.cat = IEEE80211_ACTION_CAT_BA;
		act.action = IEEE80211_ACTION_BA_ADDBA_RESP;
		ba_req_resp.type = ni->ni_ba_rx[tid].type;
		ba_req_resp.tid = tid;
		ba_req_resp.seq = ni->ni_ba_rx[tid].seq;
		ba_req_resp.frag = ni->ni_ba_rx[tid].frag;
		ba_req_resp.timeout = ni->ni_ba_rx[tid].timeout;
		ba_req_resp.buff_size = ni->ni_ba_rx[tid].buff_size;

		act.params = (void *)&ba_req_resp;
		IEEE80211_SEND_MGMT(ni, IEEE80211_FC0_SUBTYPE_ACTION, (int)&act);
		break;
	case IEEE80211_ACTION_BA_ADDBA_RESP:
		if (ieee80211_verify_length(vap, efrm - frm,
				sizeof(struct ieee80211_action_ba_addba_resp), wh, subtype))
			return;
		ba_resp  = (struct ieee80211_action_ba_addba_resp *)(void*)frm;
		frm += 2; /* action type = 1 octet and category = 1 octet */

		temp16 = LE_READ_2((frm + 3)); /* parameter field is 3 octet ahead */
		tid = ((temp16) & IEEE80211_A_BA_TID_M) >> IEEE80211_A_BA_TID_S;

		if (ni->ni_ba_tx[tid].dlg_out != (*frm)) {
			vap->iv_stats.is_rx_mgtdiscard++;
			break;
		}

		/* Delete addba request timer as addba response received */
		ni->ni_addba_req_timer[tid].count = 0;
		del_timer(&ni->ni_addba_req_timer[tid].timer);

		frm += 1; /* dialog = 1 octet */

		temp16 = LE_READ_2(frm);
		if (temp16 == 0) {
			ieee80211_node_tx_ba_set_state(ni, tid, IEEE80211_BA_ESTABLISHED, 0);
			if (ni->ni_vap->iv_opmode == IEEE80211_M_WDS) {
		                ic->ic_pm_reason = IEEE80211_PM_LEVEL_RCVD_ADDBA_RESP;
				ieee80211_pm_queue_work(ic);
			}
		} else {
			IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_INPUT, wh->i_addr2,
				"block ack not allowed by peer due to %d",temp16);
			if (temp16 == IEEE80211_STATUS_PEER_MECHANISM_REJECT) {
				ieee80211_node_tx_ba_set_state(ni, tid, IEEE80211_BA_BLOCKED, 0);
#ifdef ARTSMNG_SUPPORT
				/*
				 * BCM WDS interoperability
				 */
				if (QTN_IS_WDS_NI(ni)) {
					ieee80211_node_tx_ba_set_state(ni, tid,
						IEEE80211_BA_FAILED, 0);
				}
#endif /* ARTSMNG_SUPPORT */
			} else if (ni->ni_vap->iv_ba_control & (1 << tid)) {
				ieee80211_node_tx_ba_set_state(ni, tid, IEEE80211_BA_FAILED,
					IEEE80211_TX_BA_REQUEST_RETRY_TIMEOUT);
			} else {
				ieee80211_node_tx_ba_set_state(ni, tid, IEEE80211_BA_BLOCKED, 0);
#ifdef ARTSMNG_SUPPORT
				/*
				 * BCM WDS interoperability
				 */
				if (QTN_IS_WDS_NI(ni)) {
					ieee80211_node_tx_ba_set_state(ni, tid,
						IEEE80211_BA_FAILED, 0);
				}
#endif /* ARTSMNG_SUPPORT */
			}
			if (ic->ic_htaddba != NULL) {
				(*ic->ic_htaddba)(ni, tid, 1);
			}
			break;
		}

		frm += 2; /* status = 2 octets */

		temp16 = LE_READ_2(frm);
		ni->ni_ba_tx[tid].type = (temp16 & IEEE80211_A_BA_IMMEDIATE)?1:0;
		ni->ni_ba_tx[tid].buff_size =
			lower_power_of_2((((temp16) & IEEE80211_A_BA_BUFF_SIZE_M) >> IEEE80211_A_BA_BUFF_SIZE_S));
		ni->ni_ba_tx[tid].flags = (temp16 & IEEE80211_A_BA_AMSDU_SUPPORTED) ? QTN_BA_ARGS_F_AMSDU : 0;

		if ((ni->ni_qtn_flags & QTN_IS_BCM_NODE) && !IEEE80211_NODE_IS_VHT(ni) &&
			!ni->ni_htcap.mcsset[IEEE80211_HT_MCSSET_20_40_NSS3]) {
			/*
			 * IOT WAR: 1SS/2SS BCM devices that advertise window size as 32 have trouble
			 * handling SW retries in between next AMPDU. Based on experiments, the results
			 * are smooth if window size is set to 16. Scoreboard size in AuC should also be
			 * 16 for these devices. The fix is mainly targeted to BCM 2x2 11n based ipads.
			 */
			ni->ni_ba_tx[tid].buff_size = MIN(ni->ni_ba_tx[tid].buff_size, 16);
		}

		frm += 2; /* ba parameter = 2 octets */
		temp16 = LE_READ_2(frm);
		ni->ni_ba_tx[tid].timeout = temp16;

		ieee80211_note_mac(vap,  wh->i_addr2,
			"block ack allowed by peer tid: %d size %d type 0x%x flags 0x%x to %d",
			 tid, ni->ni_ba_tx[tid].buff_size,
			 ni->ni_ba_tx[tid].type, ni->ni_ba_tx[tid].flags, ni->ni_ba_tx[tid].timeout);

		ieee80211_node_identify_ba(ic, ni, tid);

		/* Call the driver to do some stuff if it wants to */
		if (ic->ic_htaddba != NULL) {
			(*ic->ic_htaddba)(ni, tid, 1);
		}
		break;
	case IEEE80211_ACTION_BA_DELBA:
		if (ieee80211_verify_length(vap, efrm - frm,
				sizeof(struct ieee80211_action_ba_delba), wh, subtype))
			return;
		frm += 2; /* action type = 1 octet and category = 1 octet */

		temp16 = LE_READ_2(frm);
		tid = MS(temp16, IEEE80211_A_BA_DELBA_TID);
		initiator = MS(temp16, IEEE80211_A_BA_INITIATOR);
		frm += 2;

		reason = LE_READ_2(frm);

		ieee80211_note_mac(vap, wh->i_addr2,
			"block ack deleted by peer tid: %d initiator %u reason %u",
			tid, initiator, reason);

		if (tid < WME_NUM_TID) {
			ieee80211_node_ba_del(ni, tid, !initiator, reason);
		}

		break;
	}
}

void ieee80211_parse_measure_request(struct ieee80211_node *ni,
		struct ieee80211_frame *wh,
		u_int8_t category,
		u_int8_t frame_token,
		u_int8_t *frm,
		u_int8_t *efrm)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_ie_measure_comm *meas_comm;
	struct ieee80211_global_measure_info *meas_info = &ic->ic_measure_info;

	if (sizeof(struct ieee80211_ie_measure_comm) > (efrm - frm)) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
			wh, "mgt", "%s", "no enough data for measurement common field");
		vap->iv_stats.is_rx_elem_toosmall++;
		return;
	}
	meas_comm = (struct ieee80211_ie_measure_comm*)frm;
	frm += sizeof(*meas_comm);

	if (meas_comm->id != IEEE80211_ELEMID_MEASREQ) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT, wh,
				"mgt", "%s", "measurement request ID mismatch\n");
		vap->iv_stats.is_rx_action++;
		return;
	}

	switch (meas_comm->type) {
	case IEEE80211_CCA_MEASTYPE_BASIC:
	{
		struct ieee80211_ie_measreq *meas_request;

		if (sizeof(struct ieee80211_ie_measreq) > (efrm - frm)) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT, wh,
					"mgmt", "%s", "no enough data for measuremet request ie common field\n");
			vap->iv_stats.is_rx_elem_toosmall++;
			return;
		}
		meas_request = (struct ieee80211_ie_measreq *)frm;
		frm += sizeof(struct ieee80211_ie_measreq);

		/* check current state */
		if (meas_info->status != MEAS_STATUS_IDLE) {
			ieee80211_action_measurement_report_fail(ni,
				meas_comm->type,
				IEEE80211_CCA_REPMODE_REFUSE,
				frame_token,
				meas_comm->token);
				return;
		}

		/* send autonomous response if enable=1 report=1, which is not against the standard */
		if ((meas_comm->mode & IEEE80211_CCA_REQMODE_ENABLE) &&
				(meas_comm->mode & IEEE80211_CCA_REQMODE_REPORT))
			meas_info->frame_token = 0;
		else
			meas_info->frame_token = frame_token;

		meas_info->ni = ni;
		meas_info->type = meas_comm->type;

		meas_info->param.basic.channel = meas_request->chan_num;
		meas_info->param.basic.tsf = le64toh(get_unaligned(&meas_request->start_tsf));
		meas_info->param.basic.duration_tu = LE_READ_2((u_int8_t *)&(meas_request->duration_tu));

		if (ieee80211_action_trigger_measurement(ic) != 0) {
			ieee80211_action_measurement_report_fail(ni,
				meas_comm->type,
				IEEE80211_CCA_REPMODE_REFUSE,
				frame_token,
				meas_comm->token);
		}
		break;
	}
	case IEEE80211_CCA_MEASTYPE_CCA:
	{
		/* Quantenna CCA Extension */
		if (category == IEEE80211_ACTION_CAT_RM) {
			if (ic->ic_scs.scs_stats_on) {
				struct shared_params *sp = qtn_mproc_sync_shared_params_get();
				struct qtn_scs_info_set *scs_info_lh = sp->scs_info_lhost;
				uint64_t tsf = 0;
				uint16_t cca_try;
				uint16_t cca_intf;

				ic->ic_get_tsf(&tsf);

				cca_try = (uint16_t)scs_info_lh->scs_info[scs_info_lh->valid_index].cca_try;
				if (cca_try == 0) {
					break;
				}

				cca_intf = (uint16_t)scs_info_lh->scs_info[scs_info_lh->valid_index].cca_interference;
				/* scale before sending */
				cca_intf = cca_intf * IEEE80211_SCS_CCA_INTF_SCALE / cca_try;
				ieee80211_send_action_cca_report(ni, frame_token, cca_intf,
						tsf, cca_try,
						ic->ic_scs.scs_sp_err_smthed,
						ic->ic_scs.scs_lp_err_smthed,
						0, NULL, 0);	/*TODO: Do we need to send others time?  */
				ieee80211_send_action_dfs_report(ni);
			}
		} else {
			struct ieee80211_ie_measreq *meas_request;

			if (sizeof(struct ieee80211_ie_measreq) > (efrm - frm)) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT, wh,
						"mgmt", "%s", "no enough data for measuremet request ie common field\n");
				vap->iv_stats.is_rx_elem_toosmall++;
				return;
			}
			meas_request = (struct ieee80211_ie_measreq *)frm;
			frm += sizeof(struct ieee80211_ie_measreq);

			/* check current state */
			if (meas_info->status != MEAS_STATUS_IDLE) {
				ieee80211_action_measurement_report_fail(ni, meas_comm->type,
					IEEE80211_CCA_REPMODE_REFUSE, frame_token, meas_comm->token);
					return;
			}

			/* send autonomous response if enable=1 report=1, which is not against the standard */
			if ((meas_comm->mode & IEEE80211_CCA_REQMODE_ENABLE) &&
					(meas_comm->mode & IEEE80211_CCA_REQMODE_REPORT))
				meas_info->frame_token = 0;
			else
				meas_info->frame_token = frame_token;

			meas_info->ni = ni;
			meas_info->type = meas_comm->type;

			meas_info->param.cca.channel = meas_request->chan_num;
			meas_info->param.cca.tsf = le64toh(get_unaligned(&meas_request->start_tsf));
			meas_info->param.cca.duration_tu = LE_READ_2((u_int8_t *)&(meas_request->duration_tu));

			if (ieee80211_action_trigger_measurement(ic) != 0) {
				ieee80211_action_measurement_report_fail(ni,
					meas_comm->type,
					IEEE80211_CCA_REPMODE_REFUSE,
					frame_token,
					meas_comm->token);
			}
		}
		break;
	}
	case IEEE80211_CCA_MEASTYPE_RPI:
	{
		struct ieee80211_ie_measreq *meas_request;

		if (sizeof(struct ieee80211_ie_measreq) > (efrm - frm)) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT, wh,
					"mgmt", "%s", "no enough data for measuremet request ie common field\n");
			vap->iv_stats.is_rx_elem_toosmall++;
			return;
		}
		meas_request = (struct ieee80211_ie_measreq *)frm;
		frm += sizeof(struct ieee80211_ie_measreq);

		/* check current state */
		if (meas_info->status != MEAS_STATUS_IDLE) {
			ieee80211_action_measurement_report_fail(ni,
				meas_comm->type,
				IEEE80211_CCA_REPMODE_REFUSE,
				frame_token,
				meas_comm->token);
				return;
		}

		/* send autonomous response if enable=1 report=1, which is not against the standard */
		if ((meas_comm->mode & IEEE80211_CCA_REQMODE_ENABLE) &&
				(meas_comm->mode & IEEE80211_CCA_REQMODE_REPORT))
			meas_info->frame_token = 0;
		else
			meas_info->frame_token = frame_token;

		meas_info->ni = ni;
		meas_info->type = meas_comm->type;

		meas_info->param.rpi.channel = meas_request->chan_num;
		meas_info->param.rpi.tsf = le64toh(get_unaligned(&meas_request->start_tsf));
		meas_info->param.rpi.duration_tu = LE_READ_2((u_int8_t *)&(meas_request->duration_tu));

		if (ieee80211_action_trigger_measurement(ic) != 0) {
			ieee80211_action_measurement_report_fail(ni,
				meas_comm->type,
				IEEE80211_CCA_REPMODE_REFUSE,
				frame_token,
				meas_comm->token);
		}
		break;
	}
	case IEEE80211_RM_MEASTYPE_STA:
	{
		struct ieee80211_ie_measreq_sta_stat *sta_stats_request;
		u_int8_t duration;
		u_int8_t group_id;
		u_int8_t measure_token;
		ieee80211_11k_sub_element_head se_head;
		ieee80211_11k_sub_element *p_se;

		measure_token = meas_comm->token;
		/* sta statistics request field */
		if (sizeof(struct ieee80211_ie_measreq_sta_stat) > (efrm - frm)) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT, wh,
					"mgmt", "%s", "no enough data for sta stats request field\n");
			vap->iv_stats.is_rx_action++;
			return;
		}
		sta_stats_request = (struct ieee80211_ie_measreq_sta_stat*)frm;
		frm += sizeof(struct ieee80211_ie_measreq_sta_stat);

		if (memcmp(vap->iv_myaddr, sta_stats_request->peer_mac, IEEE80211_ADDR_LEN)) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
				wh, "mgt", "%s-mac:%s", "Peer mac address un-match.",
				ether_sprintf(sta_stats_request->peer_mac));
			vap->iv_stats.is_rx_action++;
			return;
		}

		duration = sta_stats_request->duration_tu;
		group_id = sta_stats_request->group_id;

		SLIST_INIT(&se_head);
		/* sub element */
		while (frm < efrm) {
			if (efrm - frm < frm[1]) {
				IEEE80211_DPRINTF(vap, IEEE80211_MSG_ELEMID,
						"%s : ie too short\n", __func__);
				return;
			}
			switch (frm[0]) {
			case IEEE80211_ELEMID_VENDOR:
			{
				struct ieee80211_ie_qtn_rm_measure_sta *qtn_ie;
				u_int8_t sequence;
				u_int32_t vendor_flags;
				int32_t tlv_cnt, i;
				u_int8_t *tlv_frm;

				if (sizeof(struct ieee80211_ie_qtn_rm_measure_sta)
						> (efrm - frm)) {
					IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT, wh, "mgt", "%s",
							"no enough data for specific IE field");
					vap->iv_stats.is_rx_elem_toosmall++;
					return;
				}
				qtn_ie = (struct ieee80211_ie_qtn_rm_measure_sta *)frm;
				if (!isqtnmrespoui(frm)) {
					IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
						wh, "RM", "%s: id %u type %u OUI %02x:%02x:%02x",
						"specific IE incorrect",
						qtn_ie->id, qtn_ie->type, qtn_ie->qtn_ie_oui[0],
						qtn_ie->qtn_ie_oui[1], qtn_ie->qtn_ie_oui[2]);
					vap->iv_stats.is_rx_action++;
					break;
				}

				sequence = qtn_ie->seq;
				if (qtn_ie->type == QTN_OUI_RM_ALL) {
					vendor_flags = BIT(RM_QTN_MAX + 1) - 1;
				} else {
					if ((qtn_ie->len != (qtn_ie->data[0] * 2)
							+ sizeof(struct ieee80211_ie_qtn_rm_measure_sta) - 1)){
						IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
							wh, "RM", "%s: id %u type %u len %u cnt %u",
							"specific IE length-element count mis-match",
							qtn_ie->id, qtn_ie->type, qtn_ie->len, qtn_ie->data[0]);
						vap->iv_stats.is_rx_action++;
						break;
					}

					tlv_cnt = qtn_ie->data[0];
					tlv_frm = (u_int8_t *)&qtn_ie->data[1];
					vendor_flags = 0;

					for (i = 0; i < tlv_cnt; i++) {
						switch (tlv_frm[0]) {
						case RM_QTN_TX_STATS:
						case RM_QTN_RX_STATS:
						case RM_QTN_MAX_QUEUED:
						case RM_QTN_LINK_QUALITY:
						case RM_QTN_RSSI_DBM:
						case RM_QTN_BANDWIDTH:
						case RM_QTN_SNR:
						case RM_QTN_TX_PHY_RATE:
						case RM_QTN_RX_PHY_RATE:
						case RM_QTN_CCA:
						case RM_QTN_BR_IP:
						case RM_QTN_RSSI:
						case RM_QTN_HW_NOISE:
						case RM_QTN_SOC_MACADDR:
						case RM_QTN_SOC_IPADDR:
						case RM_QTN_RESET_CNTS:
						case RM_QTN_RESET_QUEUED:
						{
							vendor_flags |= BIT(tlv_frm[0]);
							tlv_frm += 2;
							break;
						}
						default:
							tlv_frm += 2;
							break;
						}
					}
				}

				p_se = (ieee80211_11k_sub_element *)kmalloc(sizeof(*p_se) + sizeof(struct stastats_subele_vendor), GFP_ATOMIC);
				if (p_se != NULL) {
					struct stastats_subele_vendor *vendor;

					p_se->sub_id = IEEE80211_ELEMID_VENDOR;
					vendor = (struct stastats_subele_vendor *)p_se->data;
					vendor->flags = vendor_flags;
					vendor->sequence = sequence;
					SLIST_INSERT_HEAD(&se_head, p_se, next);
				}
				break;
			}
			default:
				break;
			}
			frm += 2 + frm[1];
		}

		ieee80211_send_rm_rep_stastats(ni,
				0,
				frame_token,
				meas_comm->token,
				sta_stats_request->group_id,
				LE_READ_2((u_int8_t *)&(sta_stats_request->duration_tu)),
				(void *)&se_head);

		break;
	}
	case IEEE80211_RM_MEASTYPE_CH_LOAD:
	{
		struct ieee80211_ie_measreq_chan_load *cl;

		if (sizeof(struct ieee80211_ie_measreq_chan_load) > (efrm - frm)) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT, wh,
					"mgmt", "%s", "no enough data for channel load request field\n");
			vap->iv_stats.is_rx_action++;
			return;
		}
		cl = (struct ieee80211_ie_measreq_chan_load *)frm;
		frm += sizeof(struct ieee80211_ie_measreq_chan_load);

		/* check current state */
		if (meas_info->status != MEAS_STATUS_IDLE) {
			ieee80211_action_measurement_report_fail(ni,
				meas_comm->type,
				IEEE80211_CCA_REPMODE_REFUSE,
				frame_token,
				meas_comm->token);
				return;
		}

		/* send autonomous response if enable=1 report=1, which is not against the standard */
		if ((meas_comm->mode & IEEE80211_CCA_REQMODE_ENABLE) &&
				(meas_comm->mode & IEEE80211_CCA_REQMODE_REPORT))
			meas_info->frame_token = 0;
		else
			meas_info->frame_token = frame_token;

		meas_info->ni = ni;
		meas_info->type = meas_comm->type;

		meas_info->param.chan_load.op_class = cl->operating_class;
		meas_info->param.chan_load.channel = cl->channel_num;
		meas_info->param.chan_load.duration_tu = LE_READ_2((u_int8_t *)&(cl->duration_tu));
		meas_info->param.chan_load.upper_interval = LE_READ_2((u_int8_t *)&(cl->random_interval_tu));

		if (ieee80211_action_trigger_measurement(ic) != 0) {
			ieee80211_action_measurement_report_fail(ni,
				meas_comm->type,
				IEEE80211_CCA_REPMODE_REFUSE,
				frame_token,
				meas_comm->token);
		}

		break;
	}
	case IEEE80211_RM_MEASTYPE_NOISE:
	{
		struct ieee80211_ie_measreq_noise_his *nh;

		if (sizeof(struct ieee80211_ie_measreq_noise_his) > (efrm - frm)) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT, wh,
					"mgmt", "%s", "no enough data for noise hisgram request field\n");
			vap->iv_stats.is_rx_action++;
			return;
		}
		nh = (struct ieee80211_ie_measreq_noise_his *)frm;
		frm += sizeof(struct ieee80211_ie_measreq_noise_his);

		/* check current state */
		if (meas_info->status != MEAS_STATUS_IDLE) {
			ieee80211_action_measurement_report_fail(ni,
				meas_comm->type,
				IEEE80211_CCA_REPMODE_REFUSE,
				frame_token,
				meas_comm->token);
				return;
		}

		/* send autonomous response if enable=1 report=1, which is not against the standard */
		if ((meas_comm->mode & IEEE80211_CCA_REQMODE_ENABLE) &&
				(meas_comm->mode & IEEE80211_CCA_REQMODE_REPORT))
			meas_info->frame_token = 0;
		else
			meas_info->frame_token = frame_token;

		meas_info->ni = ni;
		meas_info->type = meas_comm->type;

		meas_info->param.noise_his.op_class = nh->operating_class;
		meas_info->param.noise_his.duration_tu = LE_READ_2((u_int8_t *)&(nh->duration_tu));
		meas_info->param.noise_his.upper_interval= LE_READ_2((u_int8_t *)&(nh->random_interval_tu));
		meas_info->param.noise_his.channel = nh->channel_num;

		if (ieee80211_action_trigger_measurement(ic) != 0) {
			ieee80211_action_measurement_report_fail(ni,
				meas_comm->type,
				IEEE80211_CCA_REPMODE_REFUSE,
				frame_token,
				meas_comm->token);
		}

		break;
	}
	case IEEE80211_RM_MEASTYPE_BEACON:
	{
		struct ieee80211_ie_measreq_beacon *beacon;
		u_int8_t parent_tsf[4] = {0};

		if (sizeof(struct ieee80211_ie_measreq_beacon) > (efrm - frm)) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT, wh,
					"mgmt", "%s", "no enough data for beacon report request field\n");
			vap->iv_stats.is_rx_action++;
			return;
		}
		beacon = (struct ieee80211_ie_measreq_beacon *)frm;
		frm += sizeof(struct ieee80211_ie_measreq_beacon);

		/*
		 * as described in 10.11.9.1:
		 * if the STA has no beacon information avaiilable then the STA may
		 * either refuse the request or send an empty Beacon Report.
		 * here we choose to refuse this request if there's no candidates
		 * */
		if (memcmp(beacon->bssid, IEEE80211_WILDCARD_BSSID, IEEE80211_ADDR_LEN) == 0) {
			/* if request wildcard bssid, at least one BSS could be reported */
			ieee80211_send_rm_rep_beacon(ni, 0, frame_token,
					meas_comm->token, beacon->operating_class,
					beacon->channel_num, beacon->duration_tu,
					0, 0, 0, ni->ni_vap->iv_bss->ni_bssid, 255, parent_tsf);
		} else {
			ieee80211_action_measurement_report_fail(ni, meas_comm->type,
					IEEE80211_CCA_REPMODE_REFUSE,
					frame_token, meas_comm->token);
		}

		break;
	}
	case IEEE80211_RM_MEASTYPE_FRAME:
	{
		struct ieee80211_ie_measreq_frame *frame;
		struct frame_report_subele_frame_count *entry;
		ieee80211_11k_sub_element_head se_head;
		ieee80211_11k_sub_element *p_se;

		if (sizeof(struct ieee80211_ie_measreq_frame) > (efrm - frm)) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT, wh,
					"mgmt", "%s", "no enough data for frame report request field\n");
			vap->iv_stats.is_rx_action++;
			return;
		}
		frame = (struct ieee80211_ie_measreq_frame *)frm;
		frm += sizeof(struct ieee80211_ie_measreq_frame);

		/* currently only frame count report is required */
		if (frame->frame_request_type != FRAME_COUNT_REPORT) {
			ieee80211_action_measurement_report_fail(ni,
					meas_comm->type, IEEE80211_CCA_REPMODE_REFUSE,
					frame_token, meas_comm->token);
			break;
		}

		SLIST_INIT(&se_head);
		p_se = (ieee80211_11k_sub_element *)kmalloc(sizeof(ieee80211_11k_sub_element) +
				sizeof(struct frame_report_subele_frame_count), GFP_ATOMIC);
		if (p_se != NULL) {
			p_se->sub_id = IEEE80211_FRAME_REPORT_SUBELE_FRAME_COUNT_REPORT;
			entry = (struct frame_report_subele_frame_count *)p_se->data;
			if (ni->ni_vap->iv_opmode == IEEE80211_M_HOSTAP) {
				memcpy(entry->ta, ni->ni_macaddr, IEEE80211_ADDR_LEN);
			} else {
				memcpy(entry->ta, ni->ni_vap->iv_bss->ni_macaddr, IEEE80211_ADDR_LEN);
			}
			memcpy(entry->bssid, ni->ni_vap->iv_bss->ni_macaddr, IEEE80211_ADDR_LEN);
			entry->phy_type = 0;
			entry->avg_rcpi = 0;
			entry->last_rsni = 0;
			entry->last_rcpi = 0;
			entry->antenna_id = 255;
			entry->frame_count = 1;
			SLIST_INSERT_HEAD(&se_head, p_se, next);
		}

		ieee80211_send_rm_rep_frame(ni, 0,
				frame_token, meas_comm->token,
				0, frame->channel_num,
				frame->duration_tu,
				(void *)&se_head);
		break;
	}
	case IEEE80211_RM_MEASTYPE_CATEGORY:
	{
		struct ieee80211_ie_measreq_trans_stream_cat *cat;
		struct ieee80211_meas_report_ctrl ctrl;
		struct ieee80211_action_data action_data;
		int32_t i;

		if (sizeof(struct ieee80211_ie_measreq_trans_stream_cat) > (efrm - frm)) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT, wh,
					"mgmt", "%s", "no enough data for transmit stream/category request field\n");
			vap->iv_stats.is_rx_action++;
			return;
		}
		cat = (struct ieee80211_ie_measreq_trans_stream_cat *)frm;
		frm += sizeof(struct ieee80211_ie_measreq_trans_stream_cat);

		memset(&ctrl, 0, sizeof(ctrl));
		ctrl.meas_type = IEEE80211_RM_MEASTYPE_CATEGORY;
		ctrl.report_mode = 0;
		ctrl.token = frame_token;
		ctrl.meas_token = meas_comm->token;
		ctrl.autonomous = 0;

		ctrl.u.tran_stream_cat.duration_tu = LE_READ_2((u_int8_t *)&(cat->duration_tu));
		memcpy(ctrl.u.tran_stream_cat.peer_sta, cat->peer_sta_addr, IEEE80211_ADDR_LEN);
		ctrl.u.tran_stream_cat.tid = cat->tid;
		ctrl.u.tran_stream_cat.reason = 0;
		ctrl.u.tran_stream_cat.tran_msdu_cnt = 0;
		ctrl.u.tran_stream_cat.msdu_discard_cnt = 0;
		ctrl.u.tran_stream_cat.msdu_fail_cnt = 0;
		ctrl.u.tran_stream_cat.msdu_mul_retry_cnt = 0;
		ctrl.u.tran_stream_cat.qos_lost_cnt = 0;
		ctrl.u.tran_stream_cat.avg_queue_delay = 0;
		ctrl.u.tran_stream_cat.avg_tran_delay = 0;
		ctrl.u.tran_stream_cat.bin0_range = cat->bin0_range;

		for (i = 0; i < ARRAY_SIZE(ctrl.u.tran_stream_cat.bins); i++)
			ctrl.u.tran_stream_cat.bins[i] = 0;

		action_data.cat = IEEE80211_ACTION_CAT_RM;
		action_data.action = IEEE80211_ACTION_R_MEASUREMENT_REPORT;
		action_data.params = &ctrl;

		IEEE80211_SEND_MGMT(ni, IEEE80211_FC0_SUBTYPE_ACTION, (int)&action_data);

		break;
	}
	case IEEE80211_RM_MEASTYPE_MUL_DIAG:
	{
		struct ieee80211_ie_measreq_multicast_diag *mul_diag;
		u_int16_t duration;

		if (sizeof(struct ieee80211_ie_measreq_multicast_diag) > (efrm - frm)) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT, wh,
					"mgmt", "%s", "no enough data for multicast diagnostics request field\n");
			vap->iv_stats.is_rx_action++;
			return;
		}
		mul_diag = (struct ieee80211_ie_measreq_multicast_diag *)frm;
		frm += sizeof(struct ieee80211_ie_measreq_multicast_diag);

		duration = LE_READ_2((u_int8_t *)&(mul_diag->duration_tu));

		ieee80211_send_rm_rep_multicast_diag(ni, 0, frame_token, meas_comm->token,
				duration, mul_diag->group_mac_addr,
				0, 0, 0, 0, 0);

		break;
	}
	case IEEE80211_RM_MEASTYPE_LCI:
	case IEEE80211_RM_MEASTYPE_LOC_CIVIC:
	case IEEE80211_RM_MEASTYPE_LOC_ID:
		ieee80211_action_measurement_report_fail(ni,
				meas_comm->type, IEEE80211_CCA_REPMODE_REFUSE,
				frame_token, meas_comm->token);
		break;
	default:
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT, wh,
				"mgmt", "%s", "unsupported type\n");
		vap->iv_stats.is_rx_action++;
		break;
	}
}

static void
ieee80211_parse_qtn_scs_intf_ie(struct ieee80211_node *ni, struct ieee80211_ie_qtn_scs *qtn_scs_ie)
{
	struct ieee80211com *ic = ni->ni_ic;
	uint8_t *qtn_extra_ie;
	uint8_t *qtn_extra_ie_end;

	if (qtn_scs_ie->len < (QTN_SCS_IE_STA_INTF_RPT_LEN_MIN - 2)) {
		SCSDBG(SCSLOG_NOTICE, "CCA: Node %pM reports SCS INTF IE with"
				" invalid length %u\n ", ni->ni_macaddr, qtn_scs_ie->len);
		return;
	}

	ic->ic_sta_cc = 1;
	ni->ni_recent_sp_fail = LE_READ_4((u_int8_t *)&qtn_scs_ie->u.cca_info.sp_fail);
	ni->ni_recent_lp_fail = LE_READ_4((u_int8_t *)&qtn_scs_ie->u.cca_info.lp_fail);
	ni->ni_recent_extender_traffic_time = LE_READ_2((u_int8_t *)&qtn_scs_ie->u.cca_info.others_time);

	if (ni->ni_recent_extender_traffic_time > ni->ni_extender_traffic_time_smth) {
		ni->ni_extender_traffic_time_smth = ni->ni_recent_extender_traffic_time;
	} else {
		ni->ni_extender_traffic_time_smth = IEEE80211_SCS_SMOOTH(
					ni->ni_extender_traffic_time_smth,
					ni->ni_recent_extender_traffic_time,
					IEEE80211_SCS_SMTH_RBS_TIME);
	}

	if ((qtn_scs_ie->extra_ie_len != 0) &&
			((qtn_scs_ie->extra_ie_len + sizeof(struct ieee80211_ie_qtn_scs)) <=
				(qtn_scs_ie->len + 2))) {
		qtn_extra_ie = qtn_scs_ie->extra_ie;
		qtn_extra_ie_end = qtn_scs_ie->extra_ie + qtn_scs_ie->extra_ie_len;

		while (qtn_extra_ie < qtn_extra_ie_end) {
			ieee80211_scs_update_tdls_stats(ic, (struct ieee80211_tdls_scs_stats *)qtn_extra_ie);
			qtn_extra_ie += sizeof(struct ieee80211_tdls_scs_stats);
		}
	}
	ni->ni_recent_state |= IEEE80211_NODE_SCS_BITMAP_INTF;
}

static void
ieee80211_parse_qtn_scs_fat_ie(struct ieee80211_node *ni, struct ieee80211_ie_qtn_scs *qtn_scs_ie)
{
	struct ieee80211com *ic = ni->ni_ic;
	int node_cca_idle;

	if (qtn_scs_ie->len < (QTN_SCS_IE_STA_FAT_RPT_LEN_MIN - 2)) {
		SCSDBG(SCSLOG_NOTICE, "CCA: Node %pM reports SCS INTF IE with"
				" invalid length %u\n ", ni->ni_macaddr, qtn_scs_ie->len);
		return;
	}

	node_cca_idle = LE_READ_2((u_int8_t *)&qtn_scs_ie->u.fat_info.free_airtime);
	if (node_cca_idle == SCS_CCA_IDLE_INVALID) {
		SCSDBG(SCSLOG_NOTICE, "CCA: Node %pM reports SCS FAT IE with"
				" invalid cca idle %u\n ", ni->ni_macaddr, qtn_scs_ie->len);
		return;
	}

	if (node_cca_idle > ni->ni_recent_cca_idle_smthed) {
		ni->ni_recent_cca_idle_smthed = node_cca_idle;
	} else {
		ni->ni_recent_cca_idle_smthed = IEEE80211_SCS_SMOOTH(ni->ni_recent_cca_idle_smthed,
				node_cca_idle, ic->ic_scs.scs_pmp_rpt_cca_smth_fctr);
	}
	ni->ni_recent_cca_idle = node_cca_idle;
	ni->ni_recent_cca_idle_smth_jiffies = jiffies;
	ni->ni_recent_state |= IEEE80211_NODE_SCS_BITMAP_FAT;
}

static void
ieee80211_parse_qtn_scs_trfc_ie(struct ieee80211_node *ni, struct ieee80211_ie_qtn_scs *qtn_scs_ie)
{
	struct ieee80211com *ic = ni->ni_ic;
	uint16_t cca_tx;
	uint16_t cca_rx;
	uint16_t cca_intf;
	uint16_t cca_idle;

	if (qtn_scs_ie->len < (QTN_SCS_IE_STA_TRFC_RPT_LEN_MIN - 2)) {
		SCSDBG(SCSLOG_NOTICE, "CCA: Node %pM reports SCS TRFC IE with"
				" invalid length %u\n ", ni->ni_macaddr, qtn_scs_ie->len);
		return;
	}

	cca_tx = LE_READ_2((u_int8_t *)&qtn_scs_ie->u.trfc_info.cca_tx);
	cca_rx = LE_READ_2((u_int8_t *)&qtn_scs_ie->u.trfc_info.cca_rx);
	cca_intf = LE_READ_2((u_int8_t *)&qtn_scs_ie->u.trfc_info.cca_intf);
	cca_idle = LE_READ_2((u_int8_t *)&qtn_scs_ie->u.trfc_info.cca_idle);

	ic->ic_sta_cc = 1;
	ni->ni_recent_trfc_tx_smthed = IEEE80211_SCS_SMOOTH(ni->ni_recent_trfc_tx_smthed,
			cca_tx, ic->ic_scs.scs_pmp_rpt_cca_smth_fctr);
	ni->ni_recent_trfc_rx_smthed = IEEE80211_SCS_SMOOTH(ni->ni_recent_trfc_rx_smthed,
			cca_rx, ic->ic_scs.scs_pmp_rpt_cca_smth_fctr);
	ni->ni_recent_trfc_intf_smthed = IEEE80211_SCS_SMOOTH(ni->ni_recent_trfc_intf_smthed,
			cca_intf, ic->ic_scs.scs_pmp_rpt_cca_smth_fctr);
	ni->ni_recent_trfc_idle_smthed = IEEE80211_SCS_SMOOTH(ni->ni_recent_trfc_idle_smthed,
			cca_idle, ic->ic_scs.scs_pmp_rpt_cca_smth_fctr);

	if (cca_rx > ni->ni_recent_trfc_rx_smthed)
		ni->ni_recent_trfc_rx_smthed = cca_rx;

	if (cca_idle > ni->ni_recent_trfc_idle_smthed)
		ni->ni_recent_trfc_idle_smthed = cca_idle;

	ni->ni_recent_trfc_smth_jiffies = jiffies;
	ni->ni_recent_state |= IEEE80211_NODE_SCS_BITMAP_TRFC;
}

/* Quantenna CCA Extension */
void ieee80211_parse_qtn_measure_report(struct ieee80211_node *ni,
		struct ieee80211_ie_measure_comm *meas_comm,
		u_int8_t *efrm)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct cca_rm_rep_data *cca_report;
	struct ieee80211_ie_qtn_scs *qtn_scs_ie;

	if (!ic->ic_scs.scs_stats_on)
		return;

	cca_report = (struct cca_rm_rep_data*)meas_comm->data;
	ni->ni_recent_cca_intf = (cca_report->busy_frac * IEEE80211_SCS_CCA_INTF_SCALE / IEEE80211_11K_CCA_INTF_SCALE);
	ni->ni_recent_cca_intf_jiffies = jiffies;
	qtn_scs_ie = (struct ieee80211_ie_qtn_scs*)(cca_report + 1);

	if (((efrm - (uint8_t*)qtn_scs_ie) >= QTN_SCS_IE_LEN_MIN) &&
				(qtn_scs_ie->id == IEEE80211_ELEMID_VENDOR) &&
				(qtn_scs_ie->len >= QTN_SCS_IE_LEN_MIN - 2) &&
				(is_qtn_scs_oui((uint8_t*)qtn_scs_ie))) {
		if (qtn_scs_ie->scs_ie_type == QTN_SCS_IE_TYPE_STA_INTF_RPT) {
			ieee80211_parse_qtn_scs_intf_ie(ni, qtn_scs_ie);
		} else if (qtn_scs_ie->scs_ie_type == QTN_SCS_IE_TYPE_STA_FAT_RPT) {
			ieee80211_parse_qtn_scs_fat_ie(ni, qtn_scs_ie);
		} else if (qtn_scs_ie->scs_ie_type == QTN_SCS_IE_TYPE_STA_TRFC_RPT) {
			ieee80211_parse_qtn_scs_trfc_ie(ni, qtn_scs_ie);
		} else if ((qtn_scs_ie->scs_ie_type == QTN_SCS_IE_TYPE_STA_DFS_RPT) &&
				(qtn_scs_ie->len >= (QTN_SCS_IE_STA_DFS_RPT_LEN_MIN - 2))) {
			/* let AP ignore the interference from DFS report */
			ni->ni_recent_cca_intf = SCS_CCA_INTF_INVALID;
			ni->ni_qtn_dfs_enabled = LE_READ_2(&qtn_scs_ie->u.dfs_info.dfs_enabled);
			ni->ni_txpower = qtn_scs_ie->u.dfs_info.max_txpower;
		}
	}

	switch (qtn_scs_ie->scs_ie_type) {
	case QTN_SCS_IE_TYPE_STA_INTF_RPT:
		SCSDBG(SCSLOG_NOTICE, "CCA: Node %pM reports SCS IE type %u cca_intf=%u "
					"pmbl_error=%u %u "
					"extender_traffic_time=%u "
					"extender_traffic_time_smth=%u\n",
					ni->ni_macaddr, qtn_scs_ie->scs_ie_type, ni->ni_recent_cca_intf,
					ni->ni_recent_sp_fail, ni->ni_recent_lp_fail,
					ni->ni_recent_extender_traffic_time,
					ni->ni_extender_traffic_time_smth);
		break;
	case QTN_SCS_IE_TYPE_STA_DFS_RPT:
		SCSDBG(SCSLOG_NOTICE, "DFS: Node %pM reports SCS IE type %u, DFS %s, TX power %d\n",
					ni->ni_macaddr,
					qtn_scs_ie->scs_ie_type,
					ni->ni_qtn_dfs_enabled ? "enabled" : "disabled",
					ni->ni_txpower);
		break;
	case QTN_SCS_IE_TYPE_STA_FAT_RPT:
		SCSDBG(SCSLOG_NOTICE, "CCA: Node %pM reports SCS IE type %u cca_intf %u cca_idle %d\n",
					ni->ni_macaddr, qtn_scs_ie->scs_ie_type, ni->ni_recent_cca_intf,
					ni->ni_recent_cca_idle);
		break;
	case QTN_SCS_IE_TYPE_STA_TRFC_RPT:
		SCSDBG(SCSLOG_NOTICE, "CCA: Node %pM reports SCS IE type %u cca tx %u rx %u intf %u idle %u\n",
					ni->ni_macaddr, qtn_scs_ie->scs_ie_type, ni->ni_recent_trfc_tx_smthed,
					ni->ni_recent_trfc_rx_smthed, ni->ni_recent_trfc_intf_smthed,
					ni->ni_recent_trfc_idle_smthed);
		break;
	default:
		SCSDBG(SCSLOG_NOTICE, "CCA: Device %pM reports invalid SCS IE type %u\n",
					ni->ni_macaddr, qtn_scs_ie->scs_ie_type);
		break;
	}
}

/* using dBm range -100~99 as check range */
#define RAW_RSSI_DBM_MIN		(-100 * 10 + 5)
#define RAW_RSSI_DBM_MAX		(99 * 10 - 5)
#define IS_VALID_RSSI_DBM(value)	(((int32_t)(value) >= RAW_RSSI_DBM_MIN) &&	\
						((int32_t)(value) <= RAW_RSSI_DBM_MAX))

static uint32_t ieee80211_rssidbm_endian_adaption(uint32_t value, int check_type)
{
	uint32_t val = 0;

	/* Auto-mode */
	if (check_type == DBM_ENDIAN_AUTO)
		val = (IS_VALID_RSSI_DBM(value)) ?
				LE_READ_4((u_int8_t *)&value) : BE_READ_4((u_int8_t *)&value);
	else if (check_type == DBM_ENDIAN_BIG)
		/* old endian flag */
		val = BE_READ_4((u_int8_t *)&value);
	else if (check_type == DBM_ENDIAN_LITTLE)
		/* new endian flag */
		val = LE_READ_4((u_int8_t *)&value);

	return val;
}

void ieee80211_parse_measure_report(struct ieee80211_node *ni,
		struct ieee80211_frame *wh,
		u_int8_t category,
		u_int8_t frame_token,
		u_int8_t *frm,
		u_int8_t *efrm)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211_ie_measure_comm *meas_comm;
	struct ieee80211com *ic = vap->iv_ic;

#define QTN_MREPORT_SUBIE_LEN(dlen)	\
			((uint8_t)(offsetof(struct ieee80211_ie_qtn_rm_measure_sta, data) - \
			offsetof(struct ieee80211_ie_qtn_rm_measure_sta, qtn_ie_oui) + (dlen)))

	if (sizeof(struct ieee80211_ie_measure_comm) > (efrm - frm)) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
			wh, "mgt", "%s", "no enough data for measurement common field");
		/* this counter is used incorrectly throughout the module, but not currently in use */
		vap->iv_stats.is_rx_action++;
		return;
	}
	meas_comm = (struct ieee80211_ie_measure_comm*)frm;
	frm += sizeof(*meas_comm);

	if (meas_comm->id != IEEE80211_ELEMID_MEASREP) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT, wh,
				"mgt", "%s", "measurement report ID mismatch\n");
		vap->iv_stats.is_rx_action++;
		return;
	}

	/* autonomous report frame should be handled seperately */
	if (meas_comm->token == 0) {
		switch (meas_comm->type) {
		case IEEE80211_CCA_MEASTYPE_BASIC:
		{
			struct ieee80211_ie_measrep_basic *meas_rep_basic;

			if (meas_comm->mode == 0) {
				if (sizeof(struct ieee80211_ie_measrep_basic) > (efrm - frm)) {
					IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
						wh, "mgt", "%s", "no enough data for measurement report field");
					vap->iv_stats.is_rx_action++;
					return;
				}
				meas_rep_basic = (struct ieee80211_ie_measrep_basic *)(frm);
				frm += sizeof(struct ieee80211_ie_measrep_basic);
				ieee80211_recv_meas_basic_report(ni, meas_rep_basic);
			}
			break;
		}
		case IEEE80211_CCA_MEASTYPE_CCA: {
			if (category == IEEE80211_ACTION_CAT_RM)
				ieee80211_parse_qtn_measure_report(ni, meas_comm, efrm);
			break;
		}
		default:
			printk("unsupport autonomous report, type=%d\n", meas_comm->type);
			break;
		}

		return;
	}

	ni->ni_meas_info.ni_meas_rep_mode = meas_comm->mode;
	ni->ni_meas_info.ni_meas_rep_time = jiffies;

	/* normal measurement report */
	switch (meas_comm->type) {
	case IEEE80211_CCA_MEASTYPE_BASIC:
	{
		struct ieee80211_ie_measrep_basic *meas_rep_basic;

		if (meas_comm->mode == 0) {
			if (sizeof(struct ieee80211_ie_measrep_basic) > (efrm - frm)) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "mgt", "%s", "no enough data for basic report field");
				vap->iv_stats.is_rx_elem_toosmall++;
				return;
			}
			meas_rep_basic = (struct ieee80211_ie_measrep_basic *)(frm);
			frm += sizeof(struct ieee80211_ie_measrep_basic);

			ni->ni_meas_info.rep.basic = meas_rep_basic->basic_report;

			IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG | IEEE80211_MSG_DOTH,
				"receive MEAS Report:type=basic, report_mode=%u, channel=%d, tsf=%llu, duration=%u, data=%u\n",
					ni->ni_meas_info.ni_meas_rep_mode,
					meas_rep_basic->chan_num,
					meas_rep_basic->start_tsf,
					meas_rep_basic->duration_tu,
					ni->ni_meas_info.rep.basic);
		}
		break;
	}
	case IEEE80211_CCA_MEASTYPE_CCA:
	{
		struct ieee80211_ie_measrep_cca *meas_rep_cca;

		if (meas_comm->mode == 0) {
			if (sizeof(struct ieee80211_ie_measrep_cca) > (efrm - frm)) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "mgt", "%s", "no enough data for cca report field");
				vap->iv_stats.is_rx_elem_toosmall++;
				return;
			}
			meas_rep_cca = (struct ieee80211_ie_measrep_cca *)(frm);
			frm += sizeof(struct ieee80211_ie_measrep_cca);

			ni->ni_meas_info.rep.cca = meas_rep_cca->cca_report;

			IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG | IEEE80211_MSG_DOTH,
				"receive MEAS Report:type=cca, report_mode=%u, channel=%d, tsf=%llu, duration=%u, data=%u\n",
					ni->ni_meas_info.ni_meas_rep_mode,
					meas_rep_cca->chan_num,
					meas_rep_cca->start_tsf,
					meas_rep_cca->duration_tu,
					ni->ni_meas_info.rep.cca);
		}
		break;
	}
	case IEEE80211_CCA_MEASTYPE_RPI:
	{
		struct ieee80211_ie_measrep_rpi *meas_rep_rpi;

		if (meas_comm->mode == 0) {
			if (sizeof(struct ieee80211_ie_measrep_rpi) > (efrm - frm)) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "mgt", "%s", "no enough data for rpi report field");
				vap->iv_stats.is_rx_elem_toosmall++;
				return;
			}
			meas_rep_rpi = (struct ieee80211_ie_measrep_rpi *)(frm);
			frm += sizeof(struct ieee80211_ie_measrep_rpi);

			memcpy(ni->ni_meas_info.rep.rpi, meas_rep_rpi->rpi_report, sizeof(ni->ni_meas_info.rep.rpi));

			IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG | IEEE80211_MSG_DOTH,
				"receive MEAS Report:type=rpi,	report_mode=%u, "
				"channel=%d, tsf=%llu, duration=%u, data=%u %u %u %u %u %u %u %u\n",
					ni->ni_meas_info.ni_meas_rep_mode,
					meas_rep_rpi->chan_num,
					meas_rep_rpi->start_tsf,
					meas_rep_rpi->duration_tu,
					ni->ni_meas_info.rep.rpi[0],
					ni->ni_meas_info.rep.rpi[1],
					ni->ni_meas_info.rep.rpi[2],
					ni->ni_meas_info.rep.rpi[3],
					ni->ni_meas_info.rep.rpi[4],
					ni->ni_meas_info.rep.rpi[5],
					ni->ni_meas_info.rep.rpi[6],
					ni->ni_meas_info.rep.rpi[7]);
		}
		break;
	}
	case IEEE80211_RM_MEASTYPE_STA:
	{
		const int32_t sta_stats_groupid_len[] = {
			[0] = sizeof(struct ieee80211_rm_sta_stats_group0),
			[1] = sizeof(struct ieee80211_rm_sta_stats_group1),
			[2 ... 9] = sizeof(struct ieee80211_rm_sta_stats_group2to9),
			[10] = sizeof(struct ieee80211_rm_sta_stats_group10),
			[11] = sizeof(struct ieee80211_rm_sta_stats_group11),
			[12] = sizeof(struct ieee80211_rm_sta_stats_group12),
			[13] = sizeof(struct ieee80211_rm_sta_stats_group13),
			[14] = sizeof(struct ieee80211_rm_sta_stats_group14),
			[15] = sizeof(struct ieee80211_rm_sta_stats_group15),
			[16] = sizeof(struct ieee80211_rm_sta_stats_group16),
		};
		struct ieee80211_ie_measrep_sta_stat *report = NULL;
		int status = 0;

		if (sizeof(struct ieee80211_ie_measrep_sta_stat) > (efrm - frm)) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
				wh, "RM", "insufficient data for %s", "sta stats report common field");
			vap->iv_stats.is_rx_action++;
			return;
		}
		report = (struct ieee80211_ie_measrep_sta_stat *)frm;
		frm += sizeof(struct ieee80211_ie_measrep_sta_stat);

		/* handle with group ID used for Cisco */
		if (report->group_id == 221) {
			if ((&report->data[0] + sizeof(ni->ni_rm_sta_grp221)) > efrm) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "RM", "insufficient data for %s", "group 221 STA stats");
				vap->iv_stats.is_rx_action++;
			} else {
				memcpy(&ni->ni_rm_sta_grp221, &report->data[0], sizeof(ni->ni_rm_sta_grp221));
			}
			return;
		}

		if (report->group_id >= ARRAY_SIZE(sta_stats_groupid_len)) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
				wh, "RM", "invalid group id %d", report->group_id);
			vap->iv_stats.is_rx_action++;
			return;
		}

		if (sta_stats_groupid_len[report->group_id] > (efrm - frm)) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
				wh, "RM", "insufficient data for %s", "sta stats group result field");
			vap->iv_stats.is_rx_action++;
			return;
		}
		frm += sta_stats_groupid_len[report->group_id];

		/* optional sub element */
		while ((frm + IEEE80211_RM_MEAS_SUBTYPE_LEN_MIN) <= efrm) {
			switch (frm[0]) {
			case IEEE80211_ELEMID_VENDOR:
			{
				struct ieee80211_ie_qtn_rm_measure_sta *qtn_comm;
				struct ieee80211_ie_qtn_rm_sta_all *remote;
				int i, cnt;
				uint8_t wme_ac;

				if ((frm + sizeof(*qtn_comm)) > efrm) {
					IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
						wh, "RM", "insufficient data for %s", "vendor subelement");
					vap->iv_stats.is_rx_action++;
					return;
				}

				qtn_comm = (struct ieee80211_ie_qtn_rm_measure_sta*)frm;
				if (!isqtnmrespoui(frm)) {
					IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
						wh, "RM", "%s: id %u type %u OUI %02x:%02x:%02x",
						"specific IE incorrect",
						qtn_comm->id, qtn_comm->type, qtn_comm->qtn_ie_oui[0],
						qtn_comm->qtn_ie_oui[1], qtn_comm->qtn_ie_oui[2]);
					vap->iv_stats.is_rx_action++;
					break;
				}

				remote = &ni->ni_qtn_rm_sta_all;	/* record the remote statistics to node */
				if (qtn_comm->type == QTN_OUI_RM_ALL) {
					if ((qtn_comm->data + sizeof(*remote)) > efrm ||
							qtn_comm->len != QTN_MREPORT_SUBIE_LEN(sizeof(*remote))) {
						IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
							wh, "RM", "%s", "QTN all group IE bad len");
						vap->iv_stats.is_rx_action++;
						break;
					}

					memcpy(remote, qtn_comm->data, sizeof(*remote));

					remote->tx_stats.tx_bytes = le64toh(get_unaligned(&remote->tx_stats.tx_bytes));
					remote->tx_stats.tx_pkts = LE_READ_4((u_int8_t *)&remote->tx_stats.tx_pkts);
					remote->tx_stats.tx_discard = LE_READ_4((u_int8_t *)&remote->tx_stats.tx_discard);
					for (wme_ac = 0; wme_ac < WME_AC_NUM; wme_ac++) {
						remote->tx_stats.tx_wifi_drop[wme_ac] = LE_READ_4((u_int8_t *)&remote->tx_stats.tx_wifi_drop[wme_ac]);
					}
					remote->tx_stats.tx_err = LE_READ_4((u_int8_t *)&remote->tx_stats.tx_err);
					remote->tx_stats.tx_ucast = LE_READ_4((u_int8_t *)&remote->tx_stats.tx_ucast);
					remote->tx_stats.tx_mcast = LE_READ_4((u_int8_t *)&remote->tx_stats.tx_mcast);
					remote->tx_stats.tx_bcast = LE_READ_4((u_int8_t *)&remote->tx_stats.tx_bcast);

					remote->rx_stats.rx_bytes = le64toh(get_unaligned(&remote->rx_stats.rx_bytes));
					remote->rx_stats.rx_pkts = LE_READ_4((u_int8_t *)&remote->rx_stats.rx_pkts);
					remote->rx_stats.rx_discard = LE_READ_4((u_int8_t *)&remote->rx_stats.rx_discard);
					remote->rx_stats.rx_err = LE_READ_4((u_int8_t *)&remote->rx_stats.rx_err);
					remote->rx_stats.rx_ucast = LE_READ_4((u_int8_t *)&remote->rx_stats.rx_ucast);
					remote->rx_stats.rx_mcast = LE_READ_4((u_int8_t *)&remote->rx_stats.rx_mcast);
					remote->rx_stats.rx_bcast = LE_READ_4((u_int8_t *)&remote->rx_stats.rx_bcast);

					remote->max_queued = LE_READ_4((u_int8_t *)&remote->max_queued);
					remote->link_quality = LE_READ_4((u_int8_t *)&remote->link_quality);
					remote->rssi_dbm =
						ieee80211_rssidbm_endian_adaption(remote->rssi_dbm,
									ic->rssi_dbm_endian);
					remote->bandwidth = LE_READ_4((u_int8_t *)&remote->bandwidth);
					remote->snr = LE_READ_4((u_int8_t *)&remote->snr);
					remote->tx_phy_rate = LE_READ_4((u_int8_t *)&remote->tx_phy_rate);
					remote->rx_phy_rate = LE_READ_4((u_int8_t *)&remote->rx_phy_rate);
					remote->cca = LE_READ_4((u_int8_t *)&remote->cca);
					remote->br_ip = LE_READ_4((u_int8_t *)&remote->br_ip);

					for (i = 0; i <= RM_QTN_MAX; i++ ) {
						ni->ni_last_update[i] = jiffies;
					}
				} else {
					u_int8_t *vendor_frm;
					uint8_t sie_type;
					uint8_t sie_len;

					vendor_frm = (u_int8_t*)qtn_comm->data;
					cnt = *vendor_frm++;

					if (cnt == 0) {
						status = -EPROTONOSUPPORT;
					} else if (cnt > (RM_QTN_CTRL_END + 1)) {
						cnt = RM_QTN_CTRL_END + 1;
					}

					for (i = 0; i < cnt; i++) {
						if ((vendor_frm + IEEE80211_RM_MEAS_SUBTYPE_LEN_MIN) > efrm) {
							IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
								wh, "RM", "insufficient data for %s", "QTN spcial group IE");
							vap->iv_stats.is_rx_action++;
							break;
						}

						sie_type = *vendor_frm++;
						sie_len = *vendor_frm++;

						if ((sie_type <= RM_QTN_CTRL_END && sie_type != RM_QTN_UNKNOWN &&
							sie_len != ieee80211_meas_sta_qtn_report_subtype_len[sie_type]) ||
									(vendor_frm + sie_len) > efrm) {
							/* Skip the whole IE in case a single bad sub-IE encountered */
							IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
								wh, "RM", "%s: %d bytes (must be %d)",
								"QTN spcial group IE bad len", sie_len,
								ieee80211_meas_sta_qtn_report_subtype_len[sie_type]);
							vap->iv_stats.is_rx_action++;
							break;
						}

						switch (sie_type) {
						case RM_QTN_TX_STATS:
						{
							memcpy(&remote->tx_stats, vendor_frm, sie_len);

							remote->tx_stats.tx_bytes = le64toh(get_unaligned(&remote->tx_stats.tx_bytes));
							remote->tx_stats.tx_pkts = LE_READ_4((u_int8_t *)&remote->tx_stats.tx_pkts);
							remote->tx_stats.tx_discard = LE_READ_4((u_int8_t *)&remote->tx_stats.tx_discard);
							for (wme_ac = 0; wme_ac < WME_AC_NUM; wme_ac++) {
								remote->tx_stats.tx_wifi_drop[wme_ac] =
											LE_READ_4((u_int8_t *)&remote->tx_stats.tx_wifi_drop[wme_ac]);
							}
							remote->tx_stats.tx_err = LE_READ_4((u_int8_t *)&remote->tx_stats.tx_err);
							remote->tx_stats.tx_ucast = LE_READ_4((u_int8_t *)&remote->tx_stats.tx_ucast);
							remote->tx_stats.tx_mcast = LE_READ_4((u_int8_t *)&remote->tx_stats.tx_mcast);
							remote->tx_stats.tx_bcast = LE_READ_4((u_int8_t *)&remote->tx_stats.tx_bcast);
							ni->ni_last_update[RM_QTN_TX_STATS] = jiffies;
							break;
						}
						case RM_QTN_RX_STATS:
						{
							memcpy(&remote->rx_stats, vendor_frm, sie_len);
							remote->rx_stats.rx_bytes = le64toh(get_unaligned(&remote->rx_stats.rx_bytes));
							remote->rx_stats.rx_pkts = LE_READ_4((u_int8_t *)&remote->rx_stats.rx_pkts);
							remote->rx_stats.rx_discard = LE_READ_4((u_int8_t *)&remote->rx_stats.rx_discard);
							remote->rx_stats.rx_err = LE_READ_4((u_int8_t *)&remote->rx_stats.rx_err);
							remote->rx_stats.rx_ucast = LE_READ_4((u_int8_t *)&remote->rx_stats.rx_ucast);
							remote->rx_stats.rx_mcast = LE_READ_4((u_int8_t *)&remote->rx_stats.rx_mcast);
							remote->rx_stats.rx_bcast = LE_READ_4((u_int8_t *)&remote->rx_stats.rx_bcast);
							ni->ni_last_update[RM_QTN_RX_STATS] = jiffies;
							break;
						}
						case RM_QTN_MAX_QUEUED:
						{
							memcpy(&remote->max_queued, vendor_frm, sie_len);
							remote->max_queued = LE_READ_4((u_int8_t *)&remote->max_queued);
							break;
						}
						case RM_QTN_LINK_QUALITY:
						{
							memcpy(&remote->link_quality, vendor_frm, sie_len);
							remote->link_quality = LE_READ_4((u_int8_t *)&remote->link_quality);
							break;
						}
						case RM_QTN_RSSI_DBM:
						{
							memcpy(&remote->rssi_dbm, vendor_frm, sie_len);
							remote->rssi_dbm =
								ieee80211_rssidbm_endian_adaption
									(remote->rssi_dbm,
									ic->rssi_dbm_endian);
							break;
						}
						case RM_QTN_BANDWIDTH:
						{
							memcpy(&remote->bandwidth, vendor_frm, sie_len);
							remote->bandwidth = LE_READ_4((u_int8_t *)&remote->bandwidth);
							break;
						}
						case RM_QTN_SNR:
						{
							memcpy(&remote->snr, vendor_frm, sie_len);
							remote->snr = LE_READ_4((u_int8_t *)&remote->snr);
							break;
						}
						case RM_QTN_TX_PHY_RATE:
						{
							memcpy(&remote->tx_phy_rate, vendor_frm, sie_len);
							remote->tx_phy_rate = LE_READ_4((u_int8_t *)&remote->tx_phy_rate);
							break;
						}
						case RM_QTN_RX_PHY_RATE:
						{
							memcpy(&remote->rx_phy_rate, vendor_frm, sie_len);
							remote->rx_phy_rate = LE_READ_4((u_int8_t *)&remote->rx_phy_rate);
							break;
						}
						case RM_QTN_CCA:
						{
							memcpy(&remote->cca, vendor_frm, sie_len);
							remote->cca = LE_READ_4((u_int8_t *)&remote->cca);
							break;
						}
						case RM_QTN_BR_IP:
						{
							memcpy(&remote->br_ip, vendor_frm, sie_len);
							remote->br_ip = LE_READ_4((u_int8_t *)&remote->br_ip);
							break;
						}
						case RM_QTN_RSSI:
						{
							memcpy(&remote->rssi, vendor_frm, sie_len);
							remote->rssi = LE_READ_4((u_int8_t *)&remote->rssi);
							break;
						}
						case RM_QTN_HW_NOISE:
						{
							memcpy(&remote->hw_noise, vendor_frm, sie_len);
							remote->hw_noise = LE_READ_4((u_int8_t *)&remote->hw_noise);
							break;
						}
						case RM_QTN_SOC_MACADDR:
						{
							memcpy(&remote->soc_macaddr, vendor_frm, sie_len);
							break;
						}
						case RM_QTN_SOC_IPADDR:
						{
							memcpy(&remote->soc_ipaddr, vendor_frm, sie_len);
							remote->soc_ipaddr = LE_READ_4((u_int8_t *)&remote->soc_ipaddr);
							break;
						}
						/* for control IE below */
						case RM_QTN_RESET_CNTS:
						{
							memcpy(&status, vendor_frm, sie_len);
							status = LE_READ_4((u_int8_t *)&status);
							break;
						}
						default:
							/* Just skip unknown subelement types - for compatibility reasons */
							break;
						}
						vendor_frm += sie_len;
					}
				}
				break;
			}
			default:
				break;
			}
			frm += 2 + frm[1];
		}

		break;
	}
	case IEEE80211_RM_MEASTYPE_CH_LOAD:
	{
		struct ieee80211_ie_measrep_chan_load *cl;

		if (meas_comm->mode == 0) {
			if (sizeof(struct ieee80211_ie_measrep_chan_load) > (efrm - frm)) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "mgt", "%s", "no enough data for channel load report field");
				vap->iv_stats.is_rx_action++;
				return;
			}
			cl = (struct ieee80211_ie_measrep_chan_load *)frm;
			frm += sizeof(struct ieee80211_ie_measrep_chan_load);

			ni->ni_meas_info.rep.chan_load = cl->channel_load;
		}

		break;
	}
	case IEEE80211_RM_MEASTYPE_NOISE:
	{
		struct ieee80211_ie_measrep_noise_his *nh;

		if (meas_comm->mode == 0) {
			if (sizeof(struct ieee80211_ie_measrep_noise_his) > (efrm - frm)) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "mgt", "%s", "no enough data for noise histogram report field");
				vap->iv_stats.is_rx_action++;
				return;
			}
			nh = (struct ieee80211_ie_measrep_noise_his *)frm;
			frm += sizeof(struct ieee80211_ie_measrep_noise_his);

			ni->ni_meas_info.rep.noise_his.antenna_id = nh->antenna_id;
			ni->ni_meas_info.rep.noise_his.anpi = nh->anpi;
			memcpy(ni->ni_meas_info.rep.noise_his.ipi, nh->ipi, sizeof(ni->ni_meas_info.rep.noise_his.ipi));
		}

		break;
	}
	case IEEE80211_RM_MEASTYPE_BEACON:
	{
		struct ieee80211_ie_measrep_beacon *beacon;
		struct ieee80211_rm_beacon_report_item *beacon_item;

		if (meas_comm->mode == 0) {
			if (ni->ni_meas_info.rep.beacon.flag != QTN_NIS_NODE_BCN_RPT_FLAG)
					ni->ni_meas_info.rep.beacon.item_num = 0;

			if (sizeof(struct ieee80211_ie_measrep_beacon) > (efrm - frm)) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "mgt", "%s", "no enough data for beacon report response field");
				vap->iv_stats.is_rx_action++;
				return;
			}
			if (ni->ni_meas_info.rep.beacon.item_num >=
					IEEE80211_RM_BEACON_REPORT_ITEM_MAX) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "mgt", "%s", "too much beacon report, only support 32 items");
				vap->iv_stats.is_rx_action++;
				return;
			}
			beacon = (struct ieee80211_ie_measrep_beacon *)frm;
			frm += sizeof(struct ieee80211_ie_measrep_beacon);

			beacon_item = ni->ni_meas_info.rep.beacon.item +
					ni->ni_meas_info.rep.beacon.item_num;
			beacon_item->reported_frame_info = beacon->reported_frame_info;
			beacon_item->rcpi = beacon->rcpi;
			beacon_item->rsni = beacon->rsni;
			memcpy(beacon_item->bssid, beacon->bssid, IEEE80211_ADDR_LEN);
			beacon_item->antenna_id = beacon->antenna_id;
			beacon_item->parent_tsf = LE_READ_4(beacon->parent_tsf);
			ni->ni_meas_info.rep.beacon.item_num++;
			ni->ni_meas_info.rep.beacon.total_report =
				IEEE80211_DIVIDE_N_CEIL(ni->ni_meas_info.rep.beacon.item_num,
						QTN_NIS_NODE_BCN_RPT_ENTRY_MAX);
			ni->ni_meas_info.rep.beacon.report_num =
					ni->ni_meas_info.rep.beacon.total_report;
			ni->ni_meas_info.rep.beacon.flag = QTN_NIS_NODE_BCN_RPT_FLAG;
		}

		break;
	}
	case IEEE80211_RM_MEASTYPE_FRAME:
	{
		if (meas_comm->mode == 0) {
			if (sizeof(struct ieee80211_ie_measrep_frame) > (efrm - frm)) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "mgt", "%s", "no enough data for frame report response field");
				vap->iv_stats.is_rx_action++;
				return;
			}
			frm += sizeof(struct ieee80211_ie_measrep_frame);

			ni->ni_meas_info.rep.frame_count.sub_ele_flag = 0;
			if ((efrm - frm) >= sizeof(struct ieee80211_subie_section_frame_entry)) {
				struct ieee80211_subie_section_frame_entry *entry;

				entry = (struct ieee80211_subie_section_frame_entry *)frm;
				frm += sizeof(struct ieee80211_subie_section_frame_entry);
				ni->ni_meas_info.rep.frame_count.sub_ele_flag = 1;
				memcpy(ni->ni_meas_info.rep.frame_count.ta, entry->transmit_address, IEEE80211_ADDR_LEN);
				memcpy(ni->ni_meas_info.rep.frame_count.bssid, entry->bssid, IEEE80211_ADDR_LEN);
				ni->ni_meas_info.rep.frame_count.phy_type = entry->phy_type;
				ni->ni_meas_info.rep.frame_count.avg_rcpi = entry->avg_rcpi;
				ni->ni_meas_info.rep.frame_count.last_rsni = entry->last_rsni;
				ni->ni_meas_info.rep.frame_count.last_rcpi = entry->last_rcpi;
				ni->ni_meas_info.rep.frame_count.antenna_id = entry->anntenna_id;
				ni->ni_meas_info.rep.frame_count.frame_count = LE_READ_2((u_int8_t *)&entry->frame_cnt);
			}
		}
		break;
	}
	case IEEE80211_RM_MEASTYPE_CATEGORY:
	{
		if (meas_comm->mode == 0) {
			struct ieee80211_ie_measrep_trans_stream_cat *cat;

			if (sizeof(struct ieee80211_ie_measrep_trans_stream_cat) > (efrm - frm)) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "mgt", "%s", "no enough data for transmit stream category response field");
				vap->iv_stats.is_rx_action++;
				return;
			}
			cat = (struct ieee80211_ie_measrep_trans_stream_cat *)frm;
			frm += sizeof(struct ieee80211_ie_measrep_trans_stream_cat);

			ni->ni_meas_info.rep.tran_stream_cat.reason = cat->reason;
			ni->ni_meas_info.rep.tran_stream_cat.tran_msdu_cnt = LE_READ_4((u_int8_t *)&cat->tran_msdu_cnt);
			ni->ni_meas_info.rep.tran_stream_cat.msdu_discard_cnt = LE_READ_4((u_int8_t *)&cat->msdu_discarded_cnt);
			ni->ni_meas_info.rep.tran_stream_cat.msdu_fail_cnt = LE_READ_4((u_int8_t *)&cat->msdu_failed_cnt);
			ni->ni_meas_info.rep.tran_stream_cat.msdu_mul_retry_cnt = LE_READ_4((u_int8_t *)&cat->msdu_mul_retry_cnt);
			ni->ni_meas_info.rep.tran_stream_cat.qos_lost_cnt= LE_READ_4((u_int8_t *)&cat->qos_cf_lost_cnt);
			ni->ni_meas_info.rep.tran_stream_cat.avg_queue_delay= LE_READ_4((u_int8_t *)&cat->avg_queue_delay);
			ni->ni_meas_info.rep.tran_stream_cat.avg_tran_delay= LE_READ_4((u_int8_t *)&cat->avg_trans_delay);
			ni->ni_meas_info.rep.tran_stream_cat.bin0_range= cat->bin0_range;
			ni->ni_meas_info.rep.tran_stream_cat.bins[0]= LE_READ_4((u_int8_t *)&cat->bin0);
			ni->ni_meas_info.rep.tran_stream_cat.bins[1]= LE_READ_4((u_int8_t *)&cat->bin1);
			ni->ni_meas_info.rep.tran_stream_cat.bins[2]= LE_READ_4((u_int8_t *)&cat->bin2);
			ni->ni_meas_info.rep.tran_stream_cat.bins[3]= LE_READ_4((u_int8_t *)&cat->bin3);
			ni->ni_meas_info.rep.tran_stream_cat.bins[4]= LE_READ_4((u_int8_t *)&cat->bin4);
			ni->ni_meas_info.rep.tran_stream_cat.bins[5]= LE_READ_4((u_int8_t *)&cat->bin5);
		}
		break;
	}
	case IEEE80211_RM_MEASTYPE_MUL_DIAG:
	{
		if (meas_comm->mode == 0) {
			struct ieee80211_ie_measrep_multicast_diag *mul_diag;

			if (sizeof(struct ieee80211_ie_measrep_multicast_diag) > (efrm - frm)) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "mgt", "%s", "no enough data for multicast diagnostics response field");
				vap->iv_stats.is_rx_action++;
				return;
			}
			mul_diag = (struct ieee80211_ie_measrep_multicast_diag *)frm;
			frm += sizeof(struct ieee80211_ie_measrep_multicast_diag);

			ni->ni_meas_info.rep.multicast_diag.reason = mul_diag->reason;
			ni->ni_meas_info.rep.multicast_diag.mul_rec_msdu_cnt = LE_READ_4((u_int8_t *)&mul_diag->mul_rx_msdu_cnt);
			ni->ni_meas_info.rep.multicast_diag.first_seq_num = LE_READ_2((u_int8_t *)&mul_diag->first_seq_num);
			ni->ni_meas_info.rep.multicast_diag.last_seq_num = LE_READ_2((u_int8_t *)&mul_diag->last_seq_num);
			ni->ni_meas_info.rep.multicast_diag.mul_rate= LE_READ_2((u_int8_t *)&mul_diag->mul_rate);
		}

		break;
	}
	case IEEE80211_RM_MEASTYPE_LCI:
	case IEEE80211_RM_MEASTYPE_LOC_CIVIC:
	case IEEE80211_RM_MEASTYPE_LOC_ID:
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
			wh, "mgt", "%s", "unsupported measurement frame, drop it");
		vap->iv_stats.is_rx_action++;
		break;
	default:
		break;
	}
}

void ieee80211_recv_action_measure_11h(struct ieee80211_node *ni,
		struct ieee80211_action *ia,
		struct ieee80211_frame *wh,
		u_int8_t *efrm)
{
	struct ieee80211vap *vap = ni->ni_vap;
	u_int8_t *meas_ie_frm;
	struct ieee80211_action_sm_measurement_header *sm_header;

	if ((efrm - (u_int8_t *)ia) < sizeof(struct ieee80211_action_sm_measurement_header)) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
			wh, "mgt", "%s", "11h measurement frame header too small");
		vap->iv_stats.is_rx_elem_toosmall++;
		return;
	}
	sm_header = (struct ieee80211_action_sm_measurement_header *)ia;
	meas_ie_frm = (u_int8_t *)(sm_header + 1);

	if (sm_header->ia_action == IEEE80211_ACTION_S_MEASUREMENT_REQUEST) {
		while (meas_ie_frm < efrm) {
			ieee80211_parse_measure_request(ni,
					wh,
					sm_header->ia_category,
					sm_header->am_token,
					meas_ie_frm,
					meas_ie_frm + meas_ie_frm[1] + 2);
			meas_ie_frm += meas_ie_frm[1] + 2;
		}
	} else {	/* 11h measurement report */
		while (meas_ie_frm < efrm) {
			ieee80211_parse_measure_report(ni,
					wh,
					sm_header->ia_category,
					sm_header->am_token,
					meas_ie_frm,
					meas_ie_frm + meas_ie_frm[1] + 2);
			meas_ie_frm += meas_ie_frm[1] + 2;
		}

		ieee80211_ppqueue_remove_with_response(&ni->ni_vap->iv_ppqueue,
				ni,
				ia->ia_category,
				ia->ia_action,
				sm_header->am_token);
	}
}

void ieee80211_recv_action_measure_11k(struct ieee80211_node *ni,
		struct ieee80211_action *ia,
		struct ieee80211_frame *wh,
		u_int8_t *efrm)
{
	struct ieee80211vap *vap = ni->ni_vap;
	u_int8_t *meas_ie_frm;
	struct ieee80211_action_radio_measure_request *rm_request;
	struct ieee80211_action_radio_measure_report *rm_report;

	if (ia->ia_action == IEEE80211_ACTION_R_MEASUREMENT_REQUEST) {
		if ((efrm - (u_int8_t *)ia) < sizeof(struct ieee80211_action_radio_measure_request)) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
				wh, "mgt", "%s", "11k measurement request frame header too small");
			vap->iv_stats.is_rx_elem_toosmall++;
			return;
		}
		rm_request = (struct ieee80211_action_radio_measure_request *)ia;
		meas_ie_frm = (u_int8_t *)rm_request->am_data;

		/* repeat one time */
		while (meas_ie_frm < efrm) {
			ieee80211_parse_measure_request(ni,
					wh,
					ia->ia_category,
					rm_request->am_token,
					meas_ie_frm,
					meas_ie_frm + meas_ie_frm[1] + 2);
			meas_ie_frm += meas_ie_frm[1] + 2;
		}
	} else {
		if ((efrm - (u_int8_t *)ia) < sizeof(struct ieee80211_action_radio_measure_report)) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
				wh, "mgt", "%s", "11k measurement report frame header too small");
			vap->iv_stats.is_rx_elem_toosmall++;
			return;
		}
		rm_report = (struct ieee80211_action_radio_measure_report *)ia;
		meas_ie_frm = (u_int8_t *)rm_report->am_data;

		while (meas_ie_frm < efrm) {
			ieee80211_parse_measure_report(ni,
					wh,
					ia->ia_category,
					rm_report->am_token,
					meas_ie_frm,
					meas_ie_frm + meas_ie_frm[1] + 2);
			meas_ie_frm += meas_ie_frm[1] + 2;
		}
		ieee80211_ppqueue_remove_with_response(&ni->ni_vap->iv_ppqueue,
				ni,
				ia->ia_category,
				ia->ia_action,
				rm_report->am_token);
	}
}

void ieee80211_recv_action_link_measure_request(struct ieee80211_node *ni,
		struct ieee80211_action *ia,
		struct ieee80211_frame *wh,
		u_int8_t *efrm)
{
	struct ieee80211_action_rm_link_measure_request *request;
	struct ieee80211_action_data action_data;
	struct ieee80211_link_measure_report report;
	struct ieee80211vap *vap = ni->ni_vap;

	if ((efrm - (u_int8_t *)ia) < sizeof(struct ieee80211_action_rm_link_measure_request)) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
			wh, "mgt", "%s", "link measurement request too small");
		vap->iv_stats.is_rx_elem_toosmall++;
		return;
	}
	request = (struct ieee80211_action_rm_link_measure_request *)ia;

	report.token = request->token;
	report.tpc_report.tx_power = ni->ni_ic->ic_get_local_txpow(ni->ni_ic);
	ni->ni_ic->ic_get_local_link_margin(ni, &report.tpc_report.link_margin);
	report.recv_antenna_id = 255;
	report.tran_antenna_id = 255;
	report.rcpi = 0;
	report.rsni = 0;

	action_data.cat = IEEE80211_ACTION_CAT_RM;
	action_data.action = IEEE80211_ACTION_R_LINKMEASURE_REPORT;
	action_data.params = &report;

	IEEE80211_SEND_MGMT(ni, IEEE80211_FC0_SUBTYPE_ACTION, (int)&action_data);
}

void ieee80211_recv_action_link_measure_report(struct ieee80211_node *ni,
		struct ieee80211_action *ia,
		struct ieee80211_frame *wh,
		u_int8_t *efrm)
{
	struct ieee80211_action_rm_link_measure_report *report;
	struct ieee80211vap *vap = ni->ni_vap;

	if ((efrm - (u_int8_t *)ia) < sizeof(struct ieee80211_action_rm_link_measure_report)) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
			wh, "mgt", "%s", "link measurement report too small");
		vap->iv_stats.is_rx_elem_toosmall++;
		return;
	}
	report = (struct ieee80211_action_rm_link_measure_report *)ia;

	ni->ni_lm.tpc_report.link_margin = report->tpc_report.link_margin;
	ni->ni_lm.tpc_report.tx_power = report->tpc_report.tran_power;
	ni->ni_lm.recv_antenna_id = report->recv_antenna_id;
	ni->ni_lm.tran_antenna_id = report->tran_antenna_id;
	ni->ni_lm.rcpi = report->rcpi;
	ni->ni_lm.rsni = report->rsni;

	ieee80211_ppqueue_remove_with_response(&ni->ni_vap->iv_ppqueue,
			ni,
			ia->ia_category,
			ia->ia_action,
			report->token);
}

struct ieee80211_nbr_entry {
	struct ieee80211_neighbor_report_request_item item;
	uint8_t channel_util;
	TAILQ_ENTRY(ieee80211_nbr_entry) next;
};

struct neighbor_list_head {
	struct ieee80211vap *vap;
	uint32_t pref_cand;
	TAILQ_HEAD(, ieee80211_nbr_entry) list;
};

static uint8_t
derive_operating_class(const struct ieee80211_scan_entry *se, const struct ieee80211com *ic)
{
	u_int16_t ccode = CTRY_DEFAULT;
	int bw = 20;

	if (!se || !ic)
		return 0;

	bw = ieee80211_parse_peer_bandwidth(se->se_vhtop_ie, se->se_htinfo_ie);
	if (likely(se->se_country_ie)) {
		struct ieee80211_ie_country *ci =
			(struct ieee80211_ie_country *)se->se_country_ie;
		char c_string[3];
		strlcpy(c_string, (char *)ci->country_str, 3);

		if (ieee80211_country_string_to_countryid(c_string, &ccode) == 0)
			return ieee80211_get_current_operating_class(ccode, se->se_chan->ic_ieee, bw);
	} else {
		return ieee80211_get_current_operating_class(ic->ic_country_code,
						se->se_chan->ic_ieee, bw);
	}
	return 0;
}

static int
derive_phy_type(const struct ieee80211_scan_entry *se)
{

	if (se->se_vhtop_ie)
		return IEEE80211_PHYTYPE_VHT;
	else if (se->se_htinfo_ie )
		return IEEE80211_PHYTYPE_HT;
	else if ( se->se_chan->ic_ieee >= 36 )
		return IEEE80211_PHYTYPE_OFDM;
	else {
		u_int8_t max, r;
		int i;
		int dsss_rate_present = 0;
		int hrdsss_rate_present = 0;
		max = 0;

		for (i = 0; i < se->se_rates[1]; i++) {
			r = (se->se_rates[2+i] & IEEE80211_RATE_VAL) / 2;
			if (r > max)
				max = r;
			if ( r == 1 || r == 2)
				dsss_rate_present = 1;
			if ( r == 5 || r == 11)
				hrdsss_rate_present = 1;
		}

		if (max >= 12) {
			if (dsss_rate_present && hrdsss_rate_present)
				return IEEE80211_PHYTYPE_ERP;
			else
				return IEEE80211_PHYTYPE_OFDM;
		} else if (hrdsss_rate_present) {
			return IEEE80211_PHYTYPE_HRDSSS;
		} else {
			return IEEE80211_PHYTYPE_DSSS;
		}
	}
}

static int
neighbor_scanentry_cb(void *arg, const struct ieee80211_scan_entry *se)
{
	struct ieee80211_nbr_entry *entry = NULL;
	struct ieee80211_nbr_entry *tentry = NULL;
	struct ieee80211_nbr_entry *mentry = NULL;
	struct neighbor_list_head *list = (struct neighbor_list_head *)arg;
	struct ieee80211vap *vap = list->vap;
	struct ieee80211_scan_ssid *vssid = &vap->iv_des_ssid[0];
	int found = 0;
	uint32_t match = 1;

	if (vap->iv_nbr_req_ssid->len)
		vssid = &vap->iv_nbr_req_ssid[0];

	if (list->pref_cand)
		match = !memcmp(&se->se_ssid[2], vssid->ssid, MIN(vssid->len, IEEE80211_NWID_LEN));

	if (match) {
		/* Search and if found and has old timestamp update with new scan info else don't add*/
		TAILQ_FOREACH_SAFE(entry, &list->list, next, tentry) {
			if (IEEE80211_ADDR_EQ(se->se_bssid, entry->item.bssid)) {
				found = 1;
				if (time_after((unsigned long)se->se_jiffies,
						(unsigned long)entry->item.jiffies)) {
					TAILQ_REMOVE(&list->list, entry, next);
					mentry = entry;
				}
				break;
			}
		}

		if (found && mentry) {
			entry = mentry;
		} else if (found) {
			return 0;
		} else {
			entry = (struct ieee80211_nbr_entry *)kmalloc(sizeof(*entry), GFP_ATOMIC);
		}

		if (entry != NULL) {
			memcpy(entry->item.bssid, se->se_bssid, IEEE80211_ADDR_LEN);
			entry->item.channel = se->se_chan->ic_ieee;
			entry->item.phy_type = derive_phy_type(se);
			entry->item.operating_class = derive_operating_class(se, vap->iv_ic);
			entry->item.bssid_info = (BSSID_INFO_AP_UNKNOWN
						| BSSID_INFO_SECURITY_COPY);		/* not sure */
			entry->item.jiffies = se->se_jiffies;
			if (se->se_capinfo & IEEE80211_CAPINFO_SPECTRUM_MGMT)
				entry->item.bssid_info |= BSSID_INFO_CAP_SPECTRUM_MANAGEMENT;
			if (se->se_capinfo & IEEE80211_CAPINFO_WME)
				entry->item.bssid_info |= BSSID_INFO_CAP_QOS;
			if (se->se_capinfo & IEEE80211_CAPINFO_APSD)
				entry->item.bssid_info |= BSSID_INFO_CAP_APSD;
			if (se->se_capinfo & IEEE80211_CAPINFO_RM)
				entry->item.bssid_info |= BSSID_INFO_CAP_RADIO_MEASUREMENT;
			if (se->se_capinfo & IEEE80211_CAPINFO_DELAYED_BA)
				entry->item.bssid_info |= BSSID_INFO_CAP_DELAYED_BA;
			if (se->se_capinfo & IEEE80211_CAPINFO_IMMEDIATE_BA)
				entry->item.bssid_info |= BSSID_INFO_CAP_IMMEDIATE_BA;
			if (se->se_md_ie)
				entry->item.bssid_info |= BSSID_INFO_MOBILITY_DOMAIN;
			if (se->se_htcap_ie)
				entry->item.bssid_info |= BSSID_INFO_HIGH_THROUGHPUT;
			if (se->se_vhtcap_ie)
				entry->item.bssid_info |= BSSID_INFO_VERY_HIGH_THROUGHPUT;
			if (se->se_md_ie) {
				struct ieee80211_md_ie *md = (struct ieee80211_md_ie *)se->se_md_ie;
				if (vap->iv_mdid == md->md_info)
					entry->item.bssid_info |= BSSID_INFO_MOBILITY_DOMAIN;
			}
			entry->channel_util = se->se_bss_load_ie ? *(se->se_bss_load_ie + 4) : 0;
			if (se->se_bss_load_ie) {
				IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION,
					"sta count %d chutil %d bssid info %x bssid: %pM\n",
					*(se->se_bss_load_ie + 2), *(se->se_bss_load_ie + 4),
					entry->item.bssid_info, entry->item.bssid);
			}
			TAILQ_INSERT_TAIL(&list->list, entry, next);
		}
	}

	return 0;
}

static void
ieee80211_parse_scan_cache_and_generate_neighbor_report_list(struct ieee80211com *ic,
		struct neighbor_list_head *list)
{
	ieee80211_scan_iterate(ic, neighbor_scanentry_cb, list);
}

static uint32_t
ieee80211_create_neighbor_reports(struct ieee80211_node *ni,
	struct ieee80211_neighbor_report_request_item **item_table, uint32_t num_items, uint32_t pref_cand)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct neighbor_list_head list;
	struct ieee80211_nbr_entry *entry = NULL;
	struct ieee80211_nbr_entry *tentry = NULL;
	struct ieee80211_neighbor_report_request_item *cache = NULL;
	struct ieee80211_neighbor_report_request_item *tcache = NULL;
	uint8_t bss_num = 0;
	int i;

	*item_table = NULL;
	cache = kmalloc(sizeof(struct ieee80211_neighbor_report_request_item) * num_items,
				GFP_ATOMIC);
	if (!cache) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION, "Failed to alloc size %d\n", num_items);
		return 0;
	}
	TAILQ_INIT(&list.list);
	list.vap = vap;
	list.pref_cand = pref_cand;
	ieee80211_parse_scan_cache_and_generate_neighbor_report_list(ic, &list);

	bss_num = 0;
	for (i = 0; i < num_items; i++) {
		uint8_t util = 255;
		tentry = NULL;
		/* get entry based on least channel utilization */
		TAILQ_FOREACH(entry, &list.list, next) {
			if (entry->channel_util < util) {
				tentry = entry;
				util = entry->channel_util;
			}
		}
		if (!tentry)
			break;
		TAILQ_REMOVE(&list.list, tentry, next);
		if (bss_num < num_items) {
			tcache = cache + bss_num;
			memcpy(tcache->bssid, tentry->item.bssid, IEEE80211_ADDR_LEN);
			tcache->bssid_info = tentry->item.bssid_info;
			tcache->channel = tentry->item.channel;
			tcache->operating_class = tentry->item.operating_class;
			tcache->phy_type = tentry->item.phy_type;
			bss_num++;
		}
		kfree(tentry);
	}
	*item_table = cache;

	TAILQ_FOREACH_SAFE(entry, &list.list, next, tentry) {
		TAILQ_REMOVE(&list.list, entry, next);
		kfree(entry);
	}

	return bss_num;
}

static int
ieee80211_neighbor_match_beacon_report(uint8_t bssid[IEEE80211_ADDR_LEN],
		struct ieee80211_rm_beacon_report_item *beacon, int item_num)
{
	int i;
	for (i = 0; i < item_num; i++)
		if (!memcmp(beacon[i].bssid, bssid, IEEE80211_ADDR_LEN))
			return 1;
	return 0;
}

void
ieee80211_beacon_request_callback_success(unsigned long ctx)
{
	struct ieee80211_node *ni = (struct ieee80211_node *)ctx;
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211_neighbor_report_request_item *item_cache = NULL;
	struct ieee80211_neighbor_report_request_item *item_table[NEIGH_REPORTS_MAX] = {NULL};
	int num_of_items = 0;
	int i;
	struct ieee80211_rm_beacon_report_item *beacon = ni->ni_meas_info.rep.beacon.item;
	int num_of_beacon = ni->ni_meas_info.rep.beacon.item_num;
	struct timer_list *delay = &ni->ni_meas_info.delay_timer;

	if (!!ni->ni_meas_info.delay_flag) {
		ni->ni_meas_info.delay_flag = 0;
		delay->function = ieee80211_beacon_request_callback_success;
		delay->data = ctx;
		mod_timer(delay, jiffies + msecs_to_jiffies(IEEE80211_RM_BEACON_REPORT_WAIT_TIME));
		return;
	} else
		del_timer(delay);

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION, "beacon report received for sta: %pM\n",
				ni->ni_macaddr);
	for (i = 0; i < num_of_beacon; i++) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION, "beacon report rcpi %hhu rsni %hhu BSSID: %pM\n",
				beacon[i].rcpi,
				beacon[i].rsni,
				beacon[i].bssid);
	}

	num_of_items = ieee80211_create_neighbor_reports(ni, &item_cache, NEIGH_REPORTS_MAX, 0);

	if (num_of_items > 0) {
		for (i = 0; i < num_of_items; i++) {
			/* mark reachability flag mathching becon report entry */
			if (ieee80211_neighbor_match_beacon_report(item_cache->bssid,
						beacon, num_of_beacon))
				item_cache->bssid_info |= BSSID_INFO_AP_REACHABLE;
			item_table[i] = item_cache + i;
		}
	}
	ni->ni_meas_info.rep.beacon.item_num = 0;
	ieee80211_send_neighbor_report_response(ni, ni->pending_beacon_req_token, num_of_items,
							item_table);
	if (item_cache) {
		kfree(item_cache);
		item_cache = NULL;
	}
}

void
ieee80211_beacon_request_callback_fail(void *ctx)
{
	struct ieee80211_node *ni = ctx;
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211_neighbor_report_request_item *item_cache = NULL;
	struct ieee80211_neighbor_report_request_item *item_table[NEIGH_REPORTS_MAX] = {NULL};
	int num_of_items = 0;
	int i;

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION, "beacon report failed for sta: %pM\n",
					ni->ni_macaddr);
	num_of_items = ieee80211_create_neighbor_reports(ni, &item_cache, NEIGH_REPORTS_MAX, 1);
	if (num_of_items > 0) {
		for (i = 0; i < num_of_items; i++)
			item_table[i] = item_cache + i;
	}
	ieee80211_send_neighbor_report_response(ni, ni->pending_beacon_req_token, num_of_items,
							item_table);
	if (item_cache) {
		kfree(item_cache);
		item_cache = NULL;
	}
}

#define BEACON_MEASURE_MODE_PASSIVE	0
#define BEACON_MEASURE_MODE_ACTIVE	1
#define BEACON_MEASURE_MODE_TABLE	2
#define BEACON_MEASURE_TIME		20 /* 20 msec */
#define BEACON_MEASURE_REQUEST_TIMEOUT	40 /* 40 msec */

void
ieee80211_create_and_send_neighbor_report_using_beacon_report(struct ieee80211_node *ni,
									uint8_t token)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211_scan_ssid *vssid = &vap->iv_des_ssid[0];

	ni->pending_beacon_req_token = token;
	ni->ni_meas_info.delay_flag = 1;
	/* send beacon report request - beacon table mode */
	ieee80211_send_rm_req_beacon(ni, 0, 0, BEACON_MEASURE_TIME, BEACON_MEASURE_MODE_TABLE, NULL,
		&vssid->ssid[0], vssid->len, BEACON_MEASURE_REQUEST_TIMEOUT,
		ieee80211_beacon_request_callback_success,
		ieee80211_beacon_request_callback_fail);

}

void
ieee80211_recv_action_neighbor_report_request(struct ieee80211_node *ni,
		struct ieee80211_action *ia,
		struct ieee80211_frame *wh,
		u_int8_t *efrm)
{
	struct ieee80211_action_rm_neighbor_report_request *request;
	uint8_t *ssid = NULL;
	struct ieee80211vap *vap = ni->ni_vap;

	if (vap->iv_opmode != IEEE80211_M_HOSTAP) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
			wh, "mgt", "%s", "wrong mode");
		vap->iv_stats.is_rx_mgtdiscard++;
		return;
	}

	if ((efrm - (u_int8_t *)ia) < sizeof(struct ieee80211_action_rm_neighbor_report_request)) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
			wh, "mgt", "%s", "neighbor report request too small");
		vap->iv_stats.is_rx_elem_toosmall++;
		return;
	}
	request = (struct ieee80211_action_rm_neighbor_report_request *)ia;

	if ((efrm - (u_int8_t *)ia) > sizeof(*request)) {
		if (request->data[0] == IEEE80211_ELEMID_SSID) {
			ssid = request->data;
			if ((efrm < (ssid + 2 + ssid[1])) || (ssid[1] > IEEE80211_NWID_LEN)) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "mgt", "%s", "neighbor report request invalid ssid IE");
				vap->iv_stats.is_rx_elem_toosmall++;
				return;
			}
			memcpy(&vap->iv_nbr_req_ssid->ssid, ssid + 2,
					MIN(ssid[1], IEEE80211_NWID_LEN));
			vap->iv_nbr_req_ssid->len = MIN(ssid[1], IEEE80211_NWID_LEN);
		}
	}

	if (ni->ni_rrm_capability & IEEE80211_NODE_BEACON_TABLE_REPORT_CAPABLE) {
		ieee80211_create_and_send_neighbor_report_using_beacon_report(ni, request->token);
	} else {
		struct ieee80211_neighbor_report_request_item *item_cache = NULL;
		struct ieee80211_neighbor_report_request_item *item_table[NEIGH_REPORTS_MAX] = {NULL};
		int num_of_items = 0;
		int i;

		num_of_items = ieee80211_create_neighbor_reports(ni,
					&item_cache, NEIGH_REPORTS_MAX, 1);
		if (num_of_items > 0) {
			for (i = 0; i < num_of_items; i++)
				item_table[i] = item_cache + i;
		}
		ieee80211_send_neighbor_report_response(ni, request->token,
			num_of_items, item_table);
		if (item_cache) {
			kfree(item_cache);
			item_cache = NULL;
		}
	}
	vap->iv_nbr_req_ssid->len = 0;
}

void ieee80211_recv_action_neighbor_report_response(struct ieee80211_node *ni,
		struct ieee80211_action *ia,
		struct ieee80211_frame *wh,
		u_int8_t *efrm)
{
	struct ieee80211_action_rm_neighbor_report_response *response;
	struct ieee80211_ie_neighbor_report *ie;
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211_neighbor_report_item *item;
	int subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
	u_int8_t *frm = (u_int8_t *)ia;
	u_int8_t i;
	u_int16_t ie_size;

	if ((efrm - frm) < sizeof(struct ieee80211_action_rm_neighbor_report_response)) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
			wh, "mgt", "%s", "neighbor report response too small");
		vap->iv_stats.is_rx_elem_toosmall++;
		return;
	}

	response = (struct ieee80211_action_rm_neighbor_report_response *)frm;
	frm += sizeof(struct ieee80211_action_rm_neighbor_report_response);

	if (ni->ni_neighbor.report_count != 0) {
		for (i = 0; i < ni->ni_neighbor.report_count; i++) {
			kfree(ni->ni_neighbor.item_table[i]);
			ni->ni_neighbor.item_table[i] = NULL;
		}
		ni->ni_neighbor.report_count = 0;
	}

	while (ni->ni_neighbor.report_count < IEEE80211_RM_NEIGHBOR_REPORT_ITEM_MAX) {
		ie = (struct ieee80211_ie_neighbor_report *)frm;
		ie_size = ie->len + IEEE80211_IE_ID_LEN_SIZE;

		if (ieee80211_verify_length(vap, efrm - frm, sizeof(*ie), wh, subtype))
			break;

		if (ie->id != IEEE80211_ELEMID_NEIGHBOR_REP)
			break;

		if (efrm - frm < ie_size || ie_size < sizeof(*ie))
			break;

		item = (struct ieee80211_neighbor_report_item *)kmalloc(sizeof(*item), GFP_ATOMIC);
		if (item == NULL)
			break;

		memcpy(item->bssid, ie->bssid, IEEE80211_ADDR_LEN);
		item->bssid_info = LE_READ_4((u_int8_t *)&ie->bssid_info);
		item->operating_class = ie->operating_class;
		item->channel = ie->channel;
		item->phy_type = ie->phy_type;
		ni->ni_neighbor.item_table[ni->ni_neighbor.report_count++] = item;
		frm += ie_size;
	}

	ieee80211_ppqueue_remove_with_response(&ni->ni_vap->iv_ppqueue,
			ni,
			ia->ia_category,
			ia->ia_action,
			response->token);
}

void ieee80211_recv_action_11k(struct ieee80211_node *ni,
		struct ieee80211_action *ia,
		struct ieee80211_frame *wh,
		u_int8_t *efrm)
{
	struct ieee80211vap *vap = ni->ni_vap;

	switch (ia->ia_action) {
	case IEEE80211_ACTION_R_MEASUREMENT_REQUEST:
	case IEEE80211_ACTION_R_MEASUREMENT_REPORT:
		ieee80211_recv_action_measure_11k(ni, ia, wh, efrm);
		break;
	case IEEE80211_ACTION_R_LINKMEASURE_REQUEST:
		ieee80211_recv_action_link_measure_request(ni, ia, wh, efrm);
		break;
	case IEEE80211_ACTION_R_LINKMEASURE_REPORT:
		ieee80211_recv_action_link_measure_report(ni, ia, wh, efrm);
		break;
	case IEEE80211_ACTION_R_NEIGHBOR_REQUEST:
		ieee80211_recv_action_neighbor_report_request(ni, ia, wh, efrm);
		break;
	case IEEE80211_ACTION_R_NEIGHBOR_REPORT:
		ieee80211_recv_action_neighbor_report_response(ni, ia, wh, efrm);
		break;
	default:
		vap->iv_stats.is_rx_mgtdiscard++;
		break;
	}
}

/*
 * Check whether non-ERP protection required or not
 * @scan OBSS beacon data
 * @return TRUE if non-ERP protection is required, FALSE if not required
 */
static __inline int is_non_erp_prot_required(struct ieee80211_scanparams *scan)
{
	int i;

#define IS_B_RATE(x) ( (((x) & ~0x80) == 0x02) || (((x) & ~0x80) == 0x04) || \
		       (((x) & ~0x80) == 0x0b) || (((x) & ~0x80) == 0x16) )

	/* If non erp sta present in obss */
	if (scan->erp & IEEE80211_ERP_NON_ERP_PRESENT) {
		return 1;
	}

	/* If beacon is from b-only ap where supported rates are
	 * 1, 2, 5.5 and 11 Mbps
	 */
	if (!scan->xrates && (scan->rates[1] <= 4)) {
		/* Check all the rates in the supported rate IE. If
		 * any of the rate is not the B rate, then return 0,
		 * otherwise return 1
		 */
		for (i = 0; i < scan->rates[1]; i++) {
			if (!IS_B_RATE(scan->rates[i+2]))  break;
		}
		if (i == scan->rates[1]) {
			return 1;
		}
	}

	return 0;
}

/*
 * Sets the station's VHT capability based on received assoc resp frame
 * If peer AP is non-VHT TX AMSDU will be disabled in station
 */
static void
ieee80211_input_sta_vht_set(struct ieee80211_node *ni,
			struct ieee80211vap *vap, uint8_t *vhtcap,
			uint8_t *vhtop, int vht_is_allowed)
{
	struct ieee80211com *ic = vap->iv_ic;
	/* 802.11ac */
	if (vhtcap && IS_IEEE80211_DUALBAND_VHT_ENABLED(ic) && vht_is_allowed) {
		ni->ni_flags |= IEEE80211_NODE_VHT;
		ieee80211_parse_vhtcap(ni, vhtcap);

		if (vhtop)
			ieee80211_parse_vhtop(ni, vhtop);

		IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
				"VHT Enabled: ni_flags = 0x%04x\n",
				ni->ni_flags);
	} else {
		ni->ni_flags &= ~IEEE80211_NODE_VHT;
	}
}

static int is_assoc_limit_reached(struct ieee80211com *ic, struct ieee80211vap *vap)
{
	int reserved = 0;
	int grp = vap->iv_ssid_group;
	int i;
	int r = 0;

	if ((ic->ic_sta_assoc - ic->ic_wds_links) >= ic->ic_sta_assoc_limit
			|| (ic->ic_ssid_grp[grp].assocs >= ic->ic_ssid_grp[grp].limit)) {
		return 1;
	}

	/* Get the total reservation count */
	for (i = 0; i < IEEE80211_MAX_BSS_GROUP; i++) {
		if (i == grp) {
			continue;
		}

		r = ic->ic_ssid_grp[i].reserve - ic->ic_ssid_grp[i].assocs;
		if (r > 0) {
			reserved += r;
		}
	}

	if ((ic->ic_sta_assoc - ic->ic_wds_links) >= (ic->ic_sta_assoc_limit - reserved)) {
		return 1;
	}

	return 0;
}

/*
 * This function is used to verify the HESSID and Access Network Type.
 * Probe Response is sent only if these parameters are matched or is Wildcard
**/
static int
ieee80211_verify_interworking(struct ieee80211vap *vap, u_int8_t *interw)
{
	struct ieee80211_ie *ie = (struct ieee80211_ie *)interw;
	u_int8_t interworking_len = ie->len;
	const u_int8_t *hessid;
	u_int8_t an_type; /* Access Network Type */

	/*
	 * Interworking Element
	 * El.ID | Length | AccessNetworkOpt | VenueInfo     | HESSID
	 * 1Byte | 1Byte  | 1 Byte	     | 2B (Optional) | 6B (Optional)
	 */

#define INTERWORKING_ANT_WILDCARD 15
	if (interworking_len >= 1) {
		an_type = ie->info[0] & 0x0f;
		if (an_type != INTERWORKING_ANT_WILDCARD &&
				an_type != vap->interw_info.an_type) {
			return -1;
		}
	}

	if (interworking_len == 7 || interworking_len == 9) {
		if (interworking_len == 7)
			hessid = &ie->info[1];
		else
			hessid = &ie->info[3];

		if (!IEEE80211_ADDR_NULL(vap->interw_info.hessid)) {
			if (!IEEE80211_ADDR_BCAST(hessid) &&
					!IEEE80211_ADDR_EQ(hessid, vap->interw_info.hessid)) {
				return -1;
			}
		} else if (!IEEE80211_ADDR_EQ(hessid, vap->iv_bss->ni_bssid) &&
				!IEEE80211_ADDR_BCAST(hessid)) {
			return -1;
		}
	}
#undef INTERWORKING_ANT_WILDCARD

	return 0;
}

static int ieee80211_input_mac_reserved(struct ieee80211vap *vap, struct ieee80211com *ic,
					struct ieee80211_node *ni, struct ieee80211_frame *wh)
{
	if (ic->ic_mac_reserved(wh->i_addr2)) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
			"%s: reject auth req from reserved mac %pM\n", __func__,
			wh->i_addr2);
		ieee80211_send_error(ni, wh->i_addr2,
				IEEE80211_FC0_SUBTYPE_DEAUTH,
				IEEE80211_REASON_UNSPECIFIED);
		return 1;
	}

	return 0;
}
static void
ieee80211_extdr_cac_check(struct ieee80211com *ic, struct ieee80211vap *vap, struct ieee80211_frame *wh)
{
	struct ieee80211vap *tmp_vap;

	if (ic->ic_extender_fast_cac == 0)
		return;

	if (IEEE80211_VAP_WDS_IS_RBS(vap) || IEEE80211_COM_WDS_IS_RBS(ic)) {
		if (IEEE80211_ADDR_EQ(ic->ic_extender_mbs_bssid, wh->i_addr2))
			ic->ic_complete_cac();
	} else if (ieee80211_is_repeater(ic)) {
		tmp_vap = ieee80211_get_primary_vap(ic, 0);
		if (!tmp_vap)
			return;

		if (tmp_vap->iv_state == IEEE80211_S_RUN ||
				tmp_vap->iv_state == IEEE80211_S_AUTH ||
				tmp_vap->iv_state == IEEE80211_S_ASSOC) {
			if (IEEE80211_ADDR_EQ(wh->i_addr2, tmp_vap->iv_bss->ni_macaddr)) {
				ic->ic_complete_cac();
				IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
						"%s: instantly complete CAC\n", __func__);
			}
		}
	}
}
/*
 * This function is used to check VHT and HT capabilites presence.
 * returns 1 if VHT or HT capablities are present.
 * returns 0 if VHT or HT capablities are not present.
 **/
uint8_t
ieee80211_phy_mode_allowed(struct ieee80211vap *vap, uint8_t *vhtcap, uint8_t *htcap)
{

	uint8_t retVal = 0;

	switch (vap->iv_11ac_and_11n_flag) {
	case IEEE80211_11AC_ONLY:
		if (vhtcap != NULL) {
			retVal = 1;
		}
		break;
	case IEEE80211_11N_ONLY:
		if (htcap != NULL) {
			retVal = 1;
		}
		break;
	default:
		retVal = 1;
		break;
	}

	return retVal;
}

/*
 * In case ocac_rx_state is either in BACKOFF or ONGOING state and has not been updated for atleast
 * 1 sec, we should reset it.
 *
 * One reason could be that we are no longer able to hear the AP that sent that beacon. We may or
 * may not hear again from that AP and hence we should forget about that AP and hence reset
 * ocac_rx_state
 */
static void iee80211_check_ocac_rx_state(struct ieee80211com *ic)
{
	uint64_t delta, now = jiffies;

	if (ic->ic_opmode != IEEE80211_M_HOSTAP)
		return;

	spin_lock(&ic->ic_ocac.ocac_lock);

	if (ic->ic_ocac.ocac_rx_state.state == OCAC_STATE_NONE) {
		spin_unlock(&ic->ic_ocac.ocac_lock);
		return;
	}

	/* To handle (one time) overflow */
	if (now >= ic->ic_ocac.ocac_rx_state.timestamp)
		delta = now - ic->ic_ocac.ocac_rx_state.timestamp;
	else
		delta = ic->ic_ocac.ocac_rx_state.timestamp - now;

	if (delta >= HZ)
		memset(&ic->ic_ocac.ocac_rx_state, 0, sizeof(ic->ic_ocac.ocac_rx_state));

	spin_unlock(&ic->ic_ocac.ocac_lock);
}

/*
 * Used to save the OCAC State IE from a received beacon frame, if relevant
 *
 * Should be called only if we are an AP
 *
 * ocac_rx_state is reset:
 * - on channel change
 * - when we are in BACKOFF or ONGOING state and we do not receive a beacon that updates
 *   ocac_rx_state for atleast 1 sec
 * - TBD: is there any other case?
 */
static void ieee80211_save_rx_ocac_state_ie(struct ieee80211com *ic, uint8_t *ta, uint8_t state,
					uint8_t param)
{
#define QTN_IS_EQ_TA(ta1, ta2)	!memcmp((ta1), (ta2), IEEE80211_ADDR_LEN)

#define QTN_RESET_RX_STATE	memset(old, 0, sizeof(*old))

#define QTN_SAVE_RX_STATE	memcpy(old, &new, sizeof(*old))

	struct ieee80211_ocac_rx_state new;
	struct ieee80211_ocac_rx_state *old = &ic->ic_ocac.ocac_rx_state;

	if (ic->ic_opmode != IEEE80211_M_HOSTAP)
		return;

	memcpy(new.ta, ta, IEEE80211_ADDR_LEN);
	new.state = state;
	new.param = param;
	new.timestamp = jiffies;

	spin_lock(&ic->ic_ocac.ocac_lock);

	switch (old->state) {
	case OCAC_STATE_NONE:
		switch (new.state) {
		case OCAC_STATE_NONE:
			break;

		case OCAC_STATE_BACKOFF:
		case OCAC_STATE_ONGOING:
			QTN_SAVE_RX_STATE;
			break;
		}

		break;

	case OCAC_STATE_BACKOFF:
		switch (new.state) {
		case OCAC_STATE_NONE:
			if (QTN_IS_EQ_TA(new.ta, old->ta))
				QTN_RESET_RX_STATE;
			break;

		case OCAC_STATE_BACKOFF:
			if (new.param < old->param)
				QTN_SAVE_RX_STATE;
			break;

		case OCAC_STATE_ONGOING:
			QTN_SAVE_RX_STATE;
			break;
		}

		break;

	case OCAC_STATE_ONGOING:
		switch (new.state) {
		case OCAC_STATE_NONE:
			if (QTN_IS_EQ_TA(new.ta, old->ta))
				QTN_RESET_RX_STATE;
			break;

		case OCAC_STATE_BACKOFF:
			if (QTN_IS_EQ_TA(new.ta, old->ta))
				QTN_SAVE_RX_STATE;
			break;

		case OCAC_STATE_ONGOING:
			break;
		}

		break;
	}

	spin_unlock(&ic->ic_ocac.ocac_lock);
}

int ieee80211_handle_csa_invalid_channel(struct ieee80211_node *ni, struct ieee80211_frame *wh)
{
	struct ieee80211vap *vap = ni->ni_vap;

	if (vap->iv_opmode == IEEE80211_M_HOSTAP)
		return -1;
	if (!ni->ni_associd)
		return -1;
	if (!IEEE80211_ADDR_EQ(wh->i_addr2, ni->ni_bssid))
		return -1;

	ieee80211_new_state(vap, IEEE80211_S_INIT, IEEE80211_REASON_DISASSOC_BAD_SUPP_CHAN);

	return 0;
}

#if defined(PLATFORM_QFDR)
static void qfdr_backup_beacon_frame(struct ieee80211_node *ni, struct sk_buff *skb)
{
	struct ieee80211vap *vap = ni->ni_vap;

	if (vap->iv_opmode != IEEE80211_M_STA || vap->iv_state != IEEE80211_S_RUN ||
	    IEEE80211_AID(ni->ni_associd) == 0 || !ieee80211_node_is_authorized(ni))
		return;

	if (ni->ni_beacon_frame) {
		if (skb->len != ni->ni_beacon_frame_len) {
			FREE(ni->ni_beacon_frame, M_DEVBUF);
			ni->ni_beacon_frame = NULL;
			ni->ni_beacon_frame_len = 0;
			ni->ni_beacon_backup_ts = 0;
		} else if (time_before(jiffies, ni->ni_beacon_backup_ts + (HZ * 5))) {
			/* refresh backup every 5 seconds */
			return;
		}
	}
	if (ni->ni_beacon_frame == NULL) {
		MALLOC(ni->ni_beacon_frame, void*, skb->len, M_DEVBUF, M_ZERO);
		if (!ni->ni_beacon_frame) {
			printk(KERN_ERR "%s: Failed to alloc buf to backup beacon frame\n", __func__);
			return;
		}
	}

	memcpy(ni->ni_beacon_frame, skb->data, skb->len);
	ni->ni_beacon_frame_len = skb->len;
	ni->ni_beacon_backup_ts = jiffies;
}

void qfdr_recv_bss_info(struct qfdr_bss_info *remote_bss_info)
{
	struct net_device *dev;
	struct ieee80211vap *vap;
	struct ieee80211com *ic;
	struct ieee80211_frame *wh;
	u_int8_t *frm, *efrm;
	int subtype;
	struct ieee80211_scanparams scan;
	struct ieee80211_scan_state *ss;

	dev = dev_get_by_name(&init_net, remote_bss_info->dev_name);
	if (!dev)
		return;
	vap = netdev_priv(dev);
	dev_put(dev);
	ic = vap->iv_ic;
	ss = ic->ic_scan;

	wh = (struct ieee80211_frame *) remote_bss_info->beacon;
	frm = (u_int8_t *)&wh[1];
	efrm = remote_bss_info->beacon + remote_bss_info->beacon_len;
	subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

	if (ieee80211_verify_length(vap, efrm - frm, 12, wh, subtype))
		return;
	memset(&scan, 0, sizeof(scan));
	scan.tstamp  = frm;
	frm += 8;
	scan.bintval = le16toh(*(__le16 *)frm);
	frm += 2;
	scan.capinfo = le16toh(*(__le16 *)frm);
	frm += 2;
	scan.bchan = ieee80211_chan2ieee(ic, ic->ic_curchan);

	while (frm < efrm) {
		/* Agere element in beacon */
		if ((*frm == IEEE80211_ELEMID_AGERE1) ||
		    (*frm == IEEE80211_ELEMID_AGERE2)) {
			frm = efrm;
			continue;
		}

		if (ieee80211_verify_length(vap, efrm - frm, frm[1], wh, subtype))
			return;
		if (!ieee80211_verify_ie_len(vap, wh, subtype, frm))
			return;

		switch (*frm) {
		case IEEE80211_ELEMID_SSID:
			scan.ssid = frm;
			break;
		case IEEE80211_ELEMID_RATES:
			scan.rates = frm;
			break;
		case IEEE80211_ELEMID_COUNTRY:
			scan.country = frm;
			break;
		case IEEE80211_ELEMID_PWRCNSTR:
			scan.pwr_constraint = frm;
			break;
		case IEEE80211_ELEMID_FHPARMS:
			if (ic->ic_phytype == IEEE80211_T_FH) {
				scan.fhdwell = LE_READ_2(&frm[2]);
				scan.chan = IEEE80211_FH_CHAN(frm[4], frm[5]);
				scan.fhindex = frm[6];
			}
			break;
		case IEEE80211_ELEMID_DSPARMS:
			/*
			 * XXX hack this since depending on phytype
			 * is problematic for multi-mode devices.
			 */
			if (ic->ic_phytype != IEEE80211_T_FH)
				scan.chan = frm[2];
			break;
		case IEEE80211_ELEMID_TIM:
			/* XXX ATIM? */
			scan.tim = frm;
			scan.timoff = frm - remote_bss_info->beacon;
			break;
		case IEEE80211_ELEMID_IBSSPARMS:
			break;
		case IEEE80211_ELEMID_XRATES:
			scan.xrates = frm;
			break;
		case IEEE80211_ELEMID_ERP:
			if (frm[1] != 1) {
				IEEE80211_DISCARD_IE(vap,
					IEEE80211_MSG_ELEMID, wh, "ERP",
					"bad len %u", frm[1]);
				vap->iv_stats.is_rx_elem_toobig++;
				break;
			}
			scan.erp = frm[2];
			break;
		case IEEE80211_ELEMID_RSN:
			scan.rsn = frm;
			break;
		case IEEE80211_ELEMID_OBSS_SCAN:
			scan.obss_scan = frm;
			break;
		case IEEE80211_ELEMID_BSS_LOAD:
			scan.bssload = frm;
			break;
		case IEEE80211_ELEMID_VENDOR:
			if (iswpaoui(frm))
				scan.wpa = frm;
			else if (iswmeparam(frm) || iswmeinfo(frm))
				scan.wme = frm;
			else if (iswscoui(frm))
				scan.wsc = frm;
			else if (isatherosoui(frm))
				scan.ath = frm;
			else if (isqtnie(frm))
				scan.qtn = frm;
			else if (isqtnpairoui(frm))
				scan.pairing_ie = frm;
#ifdef CONFIG_QVSP
			else if (isqtnwmeie(frm)) {
				/* override standard WME IE */
				if (ieee80211_verify_length(vap, efrm - frm,
						sizeof(struct ieee80211_ie_qtn_wme), wh, subtype))
					return;
				struct ieee80211_ie_qtn_wme *qwme = (struct ieee80211_ie_qtn_wme *)frm;
				scan.wme = (uint8_t *)&qwme->qtn_wme_ie;
			}
#endif
			/* Extract the OCAC State IE, if present */
			else if (is_qtn_ocac_state_ie(frm))
				ieee80211_save_rx_ocac_state_ie(ic, wh->i_addr3, frm[6],
					frm[7]);
			break;
		case IEEE80211_ELEMID_CHANSWITCHANN:
			scan.csa = frm;
			break;
		case IEEE80211_ELEMID_MEASREQ:
			scan.measreq = frm;
			break;
		case IEEE80211_ELEMID_HTCAP:
			scan.htcap = frm;
			break;
		case IEEE80211_ELEMID_HTINFO:
			scan.htinfo = frm;
			scan.chan = remote_bss_info->channel;
			break;
		case IEEE80211_ELEMID_VHTCAP:
			scan.vhtcap = frm;
			break;
		case IEEE80211_ELEMID_VHTOP:
			scan.vhtop = frm;
			break;
		/* Explicitly ignore some unhandled elements */
		case IEEE80211_ELEMID_TPCREP:
			break;
		case IEEE80211_ELEMID_MOBILITY_DOMAIN:
			scan.mdie = frm;
			break;
		default:
			IEEE80211_DISCARD_IE(vap, IEEE80211_MSG_ELEMID,
				wh, "unhandled",
				"id %u, len %u", *frm, frm[1]);
			vap->iv_stats.is_rx_elem_unknown++;
			break;
		}
		frm += frm[1] + 2;
	}
	if (frm > efrm)
		return;

	/* hidden SSID AP */
	if (!scan.ssid || !scan.ssid[1])
		scan.ssid = remote_bss_info->ssid;

	if (is_channel_valid(scan.chan)) {
		scan.rxchan = findchannel_any(ic, scan.chan, ic->ic_des_mode);
		if (!is_ieee80211_chan_valid(scan.rxchan))
			scan.rxchan = ic->ic_curchan;
	} else {
		scan.rxchan = ic->ic_curchan;
	}

	ss->ss_ops->scan_add(ss, &scan, wh, subtype, remote_bss_info->rssi, 0);
}
EXPORT_SYMBOL(qfdr_recv_bss_info);
#endif

static int ieee80211_allow_non_assoc_sta_notify(struct ieee80211com *ic)
{
	int retval = 1;

	if (time_before_eq(jiffies, (ic->ic_last_upkt_seen +
					ic->ic_dos_interval * HZ))) {
		if (ic->ic_dos_pkt_cnt < ic->ic_dos_max_pkt_cnt)
			ic->ic_dos_pkt_cnt++;
		else
			retval = 0;
	} else {
		ic->ic_last_upkt_seen = jiffies;
		ic->ic_dos_pkt_cnt = 1;

		if (ic->ic_dos_max_pkt_cnt == 0)
			retval = 0;
	}

	return retval;
}

static void update_current_mode(struct ieee80211_node *ni, uint8_t *opmode_notif_ie)
{
	if (opmode_notif_ie) {
		struct ieee80211_ie_vhtop_notif *ie =
					(struct ieee80211_ie_vhtop_notif *)opmode_notif_ie;
		uint8_t opmode = ieee80211_wireless_recalc_opmode(ni, ie->vhtop_notif_mode);

		ieee80211_param_to_qdrv(ni->ni_vap, IEEE80211_PARAM_NODE_OPMODE,
				opmode, ni->ni_macaddr, IEEE80211_ADDR_LEN);
		ni->ni_vhtop_notif_mode = ie->vhtop_notif_mode;
	} else {
		ni->ni_vhtop_notif_mode = IEEE80211_OPMODE_NOTIFY_INVALID;
	}

	IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_ASSOC, "update vhtop notif_mode 0x%#x\n",
				ni->ni_vhtop_notif_mode);
	ieee80211_update_current_mode(ni);
}

/*
 * FIXME
 * Corrupted "vht_bfrpt_frm" stored in SVD memory may cause device to transmit
 * oversized malformed Deauth/Disassoc frames.
 * We filter these frames in case of unexpected disconnections.
 */
static int verify_deauth_disassoc_param_len(struct ieee80211_node *ni,
		struct ieee80211_frame *wh, int par_len)
{
#define PAR_LEN_REASON	2	/* Reason code */
#define PAR_LEN_MME	18	/* Management MIC element */
	int len = PAR_LEN_REASON;

	if (!ieee80211_node_is_qtn(ni))
		return 0;

	if (ni->ni_vap->iv_pmf && RSN_IS_MFP(ni->ni_rsn.rsn_caps) &&
			IEEE80211_IS_MULTICAST(wh->i_addr1))
		len += PAR_LEN_MME;

	return (par_len > len);
}

static void
ieee80211_recv_beacon(struct ieee80211_node *ni, struct sk_buff *skb,
	int subtype, int rssi, u_int32_t rstamp)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_frame *wh = (struct ieee80211_frame *)skb->data;
	uint8_t *frm = (u_int8_t *)&wh[1];
	uint8_t *efrm = skb->data + skb->len;
	struct ieee80211_qtn_ext_role *qtn_ext_role = NULL;
	struct ieee80211_qtn_ext_bssid *qtn_ext_bssid = NULL;
	struct ieee80211_qtn_ext_state *qtn_ext_state = NULL;
	uint8_t *extcap = NULL;
	uint8_t *opmode_notif_ie = NULL;
	struct ieee80211_scanparams scan = {0};
	int node_reference_held = 0;
	u_int8_t qosinfo;
	u_int8_t beacon_update_required = 0;
	int8_t non_erp_present = 0;
	void *bcmie = NULL;
	void *rtkie = NULL;
	uint8_t *rlnk = NULL;
	struct ieee80211_mfr_entry *mfr_entry = NULL;

	/* Check if we need to reset ocac_rx_state */
	iee80211_check_ocac_rx_state(ic);

	/*
	 * When STA disconnects and boots up as AP, the DEAUTH/DISASSOC frame sent may get
	 * lost and AP can't create a WDS link with it since it's still "associated".
	 * This may be recovered by force leaving "STA" once we detect it became AP.
	 */
	if ((ni->ni_associd != 0) && (ni->ni_node_type == IEEE80211_NODE_TYPE_STA) &&
			ieee80211_node_is_qtn(ni)) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
			"force leave STA %pM as it became AP\n", ni->ni_macaddr);
		ieee80211_node_leave(ni);
		return;
	}

	if (ieee80211_beacon_should_discard(ni)) {
		vap->iv_stats.is_rx_mgtdiscard++;
		return;
	}

#ifdef ARTSMNG_SUPPORT
	/*
	 * discard rest of the MGMT packets if they are not coming over WDS interface,
	 * but not from my mesh peers
	 */
	if (vap->iv_opmode == IEEE80211_M_WDS) {
		struct ieee80211_node *ni_wds = ieee80211_find_node(&ic->ic_sta, wh->i_addr2);
		if (ni_wds == NULL) {
			vap->iv_stats.is_rx_mgtdiscard++;
			return;
		}
		ieee80211_free_node(ni_wds);
	}
#endif /* ARTSMNG_SUPPORT */

#if defined(PLATFORM_QFDR)
	if (subtype == IEEE80211_FC0_SUBTYPE_BEACON)
		qfdr_backup_beacon_frame(ni, skb);
#endif

	/*
	 * beacon/probe response frame format
	 *	[8] time stamp
	 *	[2] beacon interval
	 *	[2] capability information
	 *	[tlv] ssid
	 *	[tlv] supported rates
	 *	[tlv] country information
	 *	[tlv] parameter set (FH/DS)
	 *	[tlv] erp information
	 *	[tlv] extended supported rates
	 *	[tlv] power constraint
	 *	[tlv] WME
	 *	[tlv] WPA or RSN
	 *	[tlv] Atheros Advanced Capabilities
	 *	[tlv] Quantenna flags
	 */
	if (ieee80211_verify_length(vap, efrm - frm, 12, wh, subtype))
		return;
	memset(&scan, 0, sizeof(scan));
	scan.tstamp  = frm;
	frm += 8;
	scan.bintval = le16toh(*(__le16 *)frm);
	frm += 2;
	scan.capinfo = le16toh(*(__le16 *)frm);
	frm += 2;
	scan.bchan = ieee80211_chan2ieee(ic, ic->ic_curchan);

	ni->ni_flags &= ~IEEE80211_NODE_TPC;
	while (frm < efrm) {
		/* Agere element in beacon */
		if ((*frm == IEEE80211_ELEMID_AGERE1) ||
				(*frm == IEEE80211_ELEMID_AGERE2)) {
			frm = efrm;
			continue;
		}

		if (ieee80211_verify_length(vap, efrm - frm, frm[1], wh, subtype))
			return;
		/*
		 * WAR: treat differently IEEE80211_ELEMID_RATES as some
		 * routers in UY don't respect the standard and the RATES
		 * IE is longer than it should be (length > 8)
		 */
		if (*frm != IEEE80211_ELEMID_RATES) {
			if (!ieee80211_verify_ie_len(vap, wh, subtype, frm))
				return;
		}

		switch (*frm) {
		case IEEE80211_ELEMID_SSID:
			scan.ssid = frm;
			break;
		case IEEE80211_ELEMID_RATES:
			scan.rates = frm;
			break;
		case IEEE80211_ELEMID_COUNTRY:
			scan.country = frm;
			break;
		case IEEE80211_ELEMID_PWRCNSTR:
			scan.pwr_constraint = frm;
			ni->ni_flags |= IEEE80211_NODE_TPC;
			break;
		case IEEE80211_ELEMID_FHPARMS:
			if (ic->ic_phytype == IEEE80211_T_FH) {
				scan.fhdwell = LE_READ_2(&frm[2]);
				scan.chan = IEEE80211_FH_CHAN(frm[4], frm[5]);
				scan.fhindex = frm[6];
			}
			break;
		case IEEE80211_ELEMID_DSPARMS:
			/*
			 * XXX hack this since depending on phytype
			 * is problematic for multi-mode devices.
			 */
			if (ic->ic_phytype != IEEE80211_T_FH)
				scan.chan = frm[2];
			break;
		case IEEE80211_ELEMID_TIM:
			scan.tim = frm;
			scan.timoff = frm - skb->data;
			break;
		case IEEE80211_ELEMID_IBSSPARMS:
			break;
		case IEEE80211_ELEMID_XRATES:
			scan.xrates = frm;
			break;
		case IEEE80211_ELEMID_ERP:
			if (frm[1] != 1) {
				IEEE80211_DISCARD_IE(vap,
					IEEE80211_MSG_ELEMID, wh, "ERP",
					"bad len %u", frm[1]);
				vap->iv_stats.is_rx_elem_toobig++;
				break;
			}
			scan.erp = frm[2];
			break;
		case IEEE80211_ELEMID_RSN:
			scan.rsn = frm;
			break;
		case IEEE80211_ELEMID_OPMOD_NOTIF:
			opmode_notif_ie = frm;
			break;
		case IEEE80211_ELEMID_OBSS_SCAN:
			scan.obss_scan = frm;
			break;
		case IEEE80211_ELEMID_BSS_LOAD:
			scan.bssload = frm;
			break;
		case IEEE80211_ELEMID_VENDOR:
			if (iswpaoui(frm))
				scan.wpa = frm;
			else if (iswmeparam(frm) || iswmeinfo(frm))
				scan.wme = frm;
			else if (iswscoui(frm))
				scan.wsc = frm;
			else if (isatherosoui(frm))
				scan.ath = frm;
			else if (isqtnie(frm))
				scan.qtn = frm;
			else if (is_qtn_ext_role_oui(frm)) {
				if (ieee80211_verify_length(vap, efrm - frm,
						sizeof(struct ieee80211_qtn_ext_role),
						wh, subtype))
					return;
				qtn_ext_role = (struct ieee80211_qtn_ext_role *) frm;
			} else if (is_qtn_ext_bssid_oui(frm)) {
				if (ieee80211_verify_length(vap, efrm - frm,
						sizeof(struct ieee80211_qtn_ext_bssid),
						wh, subtype))
					return;
				qtn_ext_bssid = (struct ieee80211_qtn_ext_bssid *) frm;
			} else if (is_qtn_ext_state_oui(frm)) {
				if (ieee80211_verify_length(vap, efrm - frm,
						sizeof(struct ieee80211_qtn_ext_state),
						wh, subtype))
					return;
				qtn_ext_state = (struct ieee80211_qtn_ext_state *) frm;
			}
			else if (isqtnpairoui(frm))
				scan.pairing_ie = frm;
			else if (isbrcmvhtoui(frm)) {
				scan.vhtcap = ieee80211_get_vhtcap_from_brcmvht(ni, frm);
				scan.vhtop = ieee80211_get_vhtop_from_brcmvht(ni, frm);
			} else if (isbroadcomoui(frm))
				bcmie = frm;
			else if (isbroadcomoui2(frm))
				bcmie = frm;
			else if (isrealtekoui(frm))
				rtkie = frm;
			else if (isrlnkoui(frm))
				rlnk = frm;
#ifdef CONFIG_QVSP
			else if (isqtnwmeie(frm)) {
				/* override standard WME IE */
				if (ieee80211_verify_length(vap, efrm - frm,
						sizeof(struct ieee80211_ie_qtn_wme), wh, subtype))
					return;
				struct ieee80211_ie_qtn_wme *qwme = (struct ieee80211_ie_qtn_wme *)frm;
				IEEE80211_NOTE(vap, IEEE80211_MSG_WME | IEEE80211_MSG_ELEMID, ni,
						"%s: found QTN WME IE, version %u\n",
						__func__, qwme->qtn_wme_ie_version);
				scan.wme = (uint8_t *)&qwme->qtn_wme_ie;
			}
#endif
			/* Extract the OCAC State IE, if present */
			else if (is_qtn_ocac_state_ie(frm)) {
				ieee80211_save_rx_ocac_state_ie(ic, wh->i_addr3, frm[6], frm[7]);
			} else if (is_qtn_repeater_cascade(frm)) {
				scan.repeater = frm;
			} else if (is_wfa_transition_mode(frm)) {
				scan.owe_trans_mode = frm;
			} else if (is_qtn_rp_info(frm)) {
				scan.rp_info = frm;
			}
			break;
		case IEEE80211_ELEMID_CHANSWITCHANN:
			scan.csa = frm;
			break;
		case IEEE80211_ELEMID_MEASREQ:
			scan.measreq = frm;
			break;
		case IEEE80211_ELEMID_HTCAP:
			scan.htcap = frm;
			break;
		case IEEE80211_ELEMID_HTINFO:
			scan.htinfo = frm;
			// As DS_PARAM IE is optional for 5 GHZ, double check here
			scan.chan = frm[2];
			break;
		case IEEE80211_ELEMID_VHTCAP:
			scan.vhtcap = frm;
			break;
		case IEEE80211_ELEMID_VHTOP:
			scan.vhtop = frm;
			break;
		/* Explicitly ignore some unhandled elements */
		case IEEE80211_ELEMID_TPCREP:
			break;
		case IEEE80211_ELEMID_EXTCAP:
			extcap = frm;
			break;
		case IEEE80211_ELEMID_MOBILITY_DOMAIN:
			scan.mdie = frm;
			break;
		default:
			IEEE80211_DISCARD_IE(vap, IEEE80211_MSG_ELEMID,
				wh, "unhandled",
				"id %u, len %u", *frm, frm[1]);
			vap->iv_stats.is_rx_elem_unknown++;
			break;
		}
		frm += frm[1] + 2;
	}
	if (frm > efrm)
		return;

	if (!ieee80211_ie_exists(vap, wh, subtype, scan.ssid) ||
			!ieee80211_ie_exists(vap, wh, subtype, scan.rates))
		return;

#if IEEE80211_CHAN_MAX < 255
	if (scan.chan > IEEE80211_CHAN_MAX) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_ELEMID,
			wh, ieee80211_mgt_subtype_name[subtype >>
				IEEE80211_FC0_SUBTYPE_SHIFT],
			"invalid channel %u", scan.chan);
		vap->iv_stats.is_rx_badchan++;
		return;
	}
#endif

	/* beacon channel could be different with current channel,  recorrect it */
	if (is_channel_valid(scan.chan)) {
		scan.rxchan = findchannel_any(ic, scan.chan, ic->ic_des_mode);
		if (!is_ieee80211_chan_valid(scan.rxchan))
			scan.rxchan = ic->ic_curchan;
	} else {
		scan.rxchan = ic->ic_curchan;
	}

	/* Pure legacy 5GHz APs should not have a channel check. */
	/* Exception to this is 'BG' APs. */
	if ((ic->ic_phytype == IEEE80211_T_OFDM) &&
	    (scan.htcap == NULL) && (scan.htinfo == NULL)
			&& !(scan.chan)) {
		scan.chan = scan.bchan = 0;
	}

	if (scan.chan != scan.bchan &&
	    ic->ic_phytype != IEEE80211_T_FH) {

		/* The frame may have been received on the previous channel if the
		 * RX channel has been changed recently.
		 */
		u_int8_t older_chan = scan.bchan;
		scan.rxchan = ic->ic_prevchan;
		scan.bchan = ieee80211_chan2ieee(ic, ic->ic_prevchan);
#ifdef QTN_BG_SCAN
		if (scan.chan != scan.bchan) {
			if ((ic->ic_flags_qtn & IEEE80211_QTN_BGSCAN) && ic->ic_scanchan) {
				scan.rxchan = ic->ic_scanchan;
				scan.bchan = ieee80211_chan2ieee(ic, ic->ic_scanchan);
			}
		}
#endif /* QTN_BG_SCAN */
#ifdef QSCS_ENABLED
		if (scan.chan != scan.bchan) {
			if (ic->ic_scs.scs_smpl_enable) {
				scan.rxchan = &ic->ic_channels[ic->ic_scs.scs_des_smpl_chan];
				scan.bchan = ieee80211_chan2ieee(ic, scan.rxchan);
			}
		}
#endif /* QSCS_ENABLED */
		if (scan.chan != scan.bchan) {
			/*
			 * Frame was received on a channel different from the
			 * one indicated in the DS params element id;
			 * silently discard it.
			 *
			 * NB: this can happen due to signal leakage.
			 *     But we should take it for FH phy because
			 *     the rssi value should be correct even for
			 *     different hop pattern in FH.
			 */
			IEEE80211_DISCARD(vap, IEEE80211_MSG_ELEMID,
					wh, ieee80211_mgt_subtype_name[subtype >>
					IEEE80211_FC0_SUBTYPE_SHIFT],
					"for off-channel (cur chan:%u, bcn chan:%u last chan:%u)\n",
					older_chan, scan.chan, scan.bchan);
			vap->iv_stats.is_rx_chanmismatch++;
			return;
		} else {
			IEEE80211_DPRINTF(vap,
					IEEE80211_MSG_ELEMID,
					"accepted late bcn (cur chan:%u, bcn chan:%u last chan:%u)\n",
					older_chan, scan.chan, scan.bchan);
		}
	}

	if ((vap->iv_opmode == IEEE80211_M_STA) && (scan.rxchan == ic->ic_curchan)
			&& timer_pending(&ic->sta_dfs_info.sta_silence_timer)) {
		del_timer(&ic->sta_dfs_info.sta_silence_timer);
		ieee80211_sta_allow_beacon_reception(vap, 0);
		ic->ic_sta_set_xmit(true);
	}

	if ((ic->ic_flags & IEEE80211_F_DOTH) &&
			(ic->ic_flags_ext & IEEE80211_FEXT_TPC) &&
			(scan.country != NULL) && (scan.pwr_constraint != NULL))
		ieee80211_parse_local_max_txpwr(vap, &scan);

	ieee80211_extender_process(ni, qtn_ext_role,
			qtn_ext_bssid, qtn_ext_state, &scan, wh, rssi);

	if (IEEE80211_IS_CHAN_CAC_IN_PROGRESS(ic->ic_curchan) && scan.csa == NULL)
		ieee80211_extdr_cac_check(ic, vap, wh);

	/*
	 * IEEE802.11 does not specify the allowed range for
	 * beacon interval. We discard any beacons with a
	 * beacon interval outside of an arbitrary range in
	 * order to protect against attack.
	 *
	 * NB: Discarding beacon directly maybe not a good solution.
	 * It will lead to some IOT issues with AP whose beacon interval
	 * is not in this range, although most of AP will not set beacon
	 * interval out of this range.
	 */
	if (!(IEEE80211_BINTVAL_MIN <= scan.bintval &&
			scan.bintval <= IEEE80211_BINTVAL_MAX)) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_SCAN,
			wh, "beacon", "invalid beacon interval (%u)",
			scan.bintval);
		return;
	}

	mfr_entry = ieee80211_mfr_is_in_list(vap, subtype, 0, 0,
			IEEE80211_MFR_FLAG_RECV | IEEE80211_MFR_FLAG_SKB_COPY);
	if (mfr_entry)
		ieee80211_mfr_send_to_app(vap, mfr_entry, skb, rssi, 0, NULL);

	/*
	 * Count frame now that we know it's to be processed.
	 */
	if (subtype == IEEE80211_FC0_SUBTYPE_BEACON)
		IEEE80211_NODE_STAT(ni, rx_beacons);
	else
		IEEE80211_NODE_STAT(ni, rx_proberesp);

	if (ic->ic_flags_qtn & IEEE80211_QTN_MONITOR) {
		ni->ni_intval = scan.bintval;
		if (scan.csa)
			ieee80211_parse_csaie(ni, wh, scan.csa, scan.csa_tsf,
						NULL, NULL);
		return;
	}

	/*
	 * When operating in station mode, check for state updates.
	 * Be careful to ignore beacons received while doing a
	 * background scan.  We consider only 11g/WMM stuff right now.
	 */
	if (vap->iv_opmode == IEEE80211_M_STA && ni->ni_associd != 0 &&
			IEEE80211_ADDR_EQ(wh->i_addr2, ni->ni_bssid)) {
		/* record tsf of last beacon */
		memcpy(ni->ni_tstamp.data, scan.tstamp, sizeof(ni->ni_tstamp));

		if (ni->ni_intval != scan.bintval) {
			IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
				"beacon interval divergence: was %u, now %u",
				ni->ni_intval, scan.bintval);
			if (!ni->ni_intval_end) {
				int msecs = 0; /* silence compiler */
				ni->ni_intval_cnt = 0;
				ni->ni_intval_old = ni->ni_intval;
				msecs = (ni->ni_intval_old * 1024 * 10) / 1000;
				ni->ni_intval_end = jiffies + msecs_to_jiffies(msecs);
				IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
					"scheduling beacon interval measurement"
					" for %u msecs", msecs);
			}
			if (scan.bintval > ni->ni_intval) {
				ni->ni_intval = scan.bintval;
				vap->iv_flags_ext |= IEEE80211_FEXT_APPIE_UPDATE;
			}
		}

		if (ni->ni_intval_end) {
			if (scan.bintval == ni->ni_intval_old)
				ni->ni_intval_cnt++;

			if (!time_before(jiffies, ni->ni_intval_end)) {
				IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
						"beacon interval measurement finished,"
						" old value repeated: %u times",
						ni->ni_intval_cnt);
				ni->ni_intval_end = 0;
				if (ni->ni_intval_cnt == 0) {
					IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
						"reprogramming bmiss timer from %u to %u",
						ni->ni_intval_old, scan.bintval);
					ni->ni_intval = scan.bintval;
					vap->iv_flags_ext |= IEEE80211_FEXT_APPIE_UPDATE;
				} else {
					IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
						"ignoring the divergence (maybe someone"
						" tried to spoof the AP?)", 0);
				}
			}
		}

		/* update transmit power if necessary */
		if ((ic->ic_flags & IEEE80211_F_DOTH) &&
				(ic->ic_flags_ext & IEEE80211_FEXT_TPC) &&
				(scan.pwr_constraint != NULL) &&
				(vap->iv_local_max_txpow != scan.local_max_txpwr)) {
			if ((scan.local_max_txpwr >= ni->ni_chan->ic_maxpower_normal) &&
					(vap->iv_local_max_txpow < ni->ni_chan->ic_maxpower_normal)) {
				vap->iv_local_max_txpow = ni->ni_chan->ic_maxpower_normal;
			} else if ((scan.local_max_txpwr <= ni->ni_chan->ic_minpower_normal) &&
					(vap->iv_local_max_txpow > ni->ni_chan->ic_minpower_normal)) {
				vap->iv_local_max_txpow = ni->ni_chan->ic_minpower_normal;
			} else if (scan.local_max_txpwr < ni->ni_chan->ic_maxpower_normal &&
					(scan.local_max_txpwr > ni->ni_chan->ic_minpower_normal)){
				vap->iv_local_max_txpow = scan.local_max_txpwr;
			} else {
				/* do nothing */
			}
			ieee80211_update_tx_power(ic, vap->iv_local_max_txpow);
		}

		if (ni->ni_erp != scan.erp) {
			IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
				"erp change: was 0x%x, now 0x%x",
				ni->ni_erp, scan.erp);
			if (IEEE80211_BG_PROTECT_ENABLED(ic) &&
					(scan.erp & IEEE80211_ERP_USE_PROTECTION)) {
				ic->ic_flags |= IEEE80211_F_USEPROT;
				/* tell Muc to use ERP cts-to-self mechanism now */
				ic->ic_set_11g_erp(vap, 1);
			} else {
				ic->ic_flags &= ~IEEE80211_F_USEPROT;
				/* tell Muc to turn off ERP now */
				ic->ic_set_11g_erp(vap, 0);
			}
			ni->ni_erp = scan.erp;
			/* XXX statistic */
		}

		if ((ni->ni_capinfo ^ scan.capinfo) & IEEE80211_CAPINFO_SHORT_SLOTTIME) {
			IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
				"capabilities change: was 0x%x, now 0x%x",
				ni->ni_capinfo, scan.capinfo);
			/*
			 * NB: we assume short preamble doesn't
			 *     change dynamically
			 */
			ieee80211_set_shortslottime(ic,
				IEEE80211_IS_CHAN_A(ic->ic_bsschan) ||
				(ni->ni_capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME));
			ni->ni_capinfo = scan.capinfo;
			/* XXX statistic */
		}

		if (scan.wme != NULL && (ni->ni_flags & IEEE80211_NODE_QOS)) {
			int _retval = ieee80211_parse_wmeparams(vap, scan.wme, wh, &qosinfo);
			if (_retval >= 0) {
				if (qosinfo & WME_CAPINFO_UAPSD_EN)
					ni->ni_flags |= IEEE80211_NODE_UAPSD;

				if (_retval > 0 && (!scan.qtn ||
							!ieee80211_is_repeater_feature_enabled(ic,
								QTN_REP_TWEAK_WMM_PARAMS))) {
					ieee80211_wme_updateparams(vap, 0);
				}
			}
		} else {
			ni->ni_flags &= ~IEEE80211_NODE_UAPSD;
		}

		if (scan.ath != NULL)
			ieee80211_parse_athParams(ni, scan.ath);

		/* IEEE802.11n*/
		if (scan.htcap)
			ieee80211_parse_htcap(ni, scan.htcap);

		if (scan.htinfo) {
			ieee80211_parse_htinfo(ni, scan.htinfo);
			if ((ic->ic_opmode == IEEE80211_M_STA) &&
				(ic->ic_20_40_coex_enable) &&
				IS_IEEE80211_24G_40(ic) && vap->iv_bss &&
				IEEE80211_ADDR_EQ(ni->ni_macaddr, vap->iv_bss->ni_macaddr) &&
				(!ni->ni_htinfo.choffset)) {
				ieee80211_change_bw(vap, BW_HT20, 0);
				ic->ic_coex_stats_update(ic, WLAN_COEX_STATS_BW_SCAN);
			}
		}

		/* IEEE802.11ac */
		if (scan.vhtcap && IS_IEEE80211_DUALBAND_VHT_ENABLED(ic))
			ieee80211_check_and_parse_vhtcap(ni, scan.vhtcap);

		if (scan.vhtop && IS_IEEE80211_DUALBAND_VHT_ENABLED(ic))
			ieee80211_check_and_parse_vhtop(ni, scan.vhtop);

		if (scan.csa != NULL) {
			if (!ic->ic_csa_bw_change_pending) {
				int new_bw;

				new_bw = ieee80211_parse_peer_bandwidth(scan.vhtop, scan.htinfo);
				new_bw = MIN(new_bw, ic->ic_max_system_bw);
				if (ic->ic_bss_bw != new_bw) {
					IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
							"change in BW in CSA beacon: new bw %u\n", new_bw);
					ic->ic_csa_bw_change_pending = 1;
					ic->ic_csa_bw = new_bw;
				}
			}

			if (QTN_CSAIE_ERR_CHAN_NOT_SUPP ==
					ieee80211_parse_csaie(ni, wh, scan.csa, scan.csa_tsf,
						NULL, NULL)) {
				if (!ieee80211_handle_csa_invalid_channel(ni, wh))
					return;
			}
		}

		if (scan.measreq)
			ieee80211_parse_measinfo(ni, scan.measreq);

		if (scan.obss_scan)
			ieee8011_parse_obss_scan(ni, scan.obss_scan);

		if (scan.tim != NULL) {
			/*
			 * Check the TIM. For now we drop out of
			 * power save mode for any reason.
			 */
			struct ieee80211_tim_ie_full *tim =
			    (struct ieee80211_tim_ie_full *) scan.tim;
			int aid = IEEE80211_AID(ni->ni_associd);
			int ix = aid / NBBY;
			int min = tim->tim_bitctl & ~1;
			int max = tim->tim_len + min - 4;
			if (min <= ix && ix <= max &&
					isset(tim->tim_bitmap - min, aid)) {
				ieee80211_sta_pwrsave(vap, 0);
				vap->iv_ap_buffered = 1;
			} else {
				vap->iv_ap_buffered = 0;
			}
			vap->iv_dtim_count = tim->tim_count;
		}

		ieee80211_update_tbtt(vap, ni);

		/* WDS/Repeater: re-schedule software beacon timer for STA */
		if (vap->iv_state == IEEE80211_S_RUN &&
				vap->iv_flags_ext & IEEE80211_FEXT_SWBMISS) {
#if defined(QBMPS_ENABLE)
			if (vap->iv_swbmiss_bmps_warning) {
				/* if previously BMPS detects swbmiss */
				/* it will disable power-saving temporary */
				/* to help beacon RX */
				/* now it is time to reenable power-saving */
				vap->iv_swbmiss_bmps_warning = 0;
		                ic->ic_pm_reason = IEEE80211_PM_LEVEL_SWBCN_MISS;
				ieee80211_pm_queue_work(ic);
			}
#endif
			vap->iv_swbmiss_warnings = IEEE80211_SWBMISS_WARNINGS;
			mod_timer(&vap->iv_swbmiss, jiffies + vap->iv_swbmiss_period);
		}

		if (opmode_notif_ie) {
			struct ieee80211_ie_vhtop_notif *ie =
					(struct ieee80211_ie_vhtop_notif *)opmode_notif_ie;
			uint8_t opmode;

			opmode = ieee80211_wireless_recalc_opmode(ni,
					ie->vhtop_notif_mode);
			if (ni->ni_vhtop_notif_mode != ie->vhtop_notif_mode) {
				ieee80211_param_to_qdrv(ni->ni_vap,
					IEEE80211_PARAM_NODE_OPMODE, opmode,
					ni->ni_macaddr, IEEE80211_ADDR_LEN);
				ni->ni_vhtop_notif_mode = ie->vhtop_notif_mode;
			}
		}

		/*
		 * If scanning, pass the info to the scan module.
		 * Otherwise, check if it's the right time to do
		 * a background scan.  Background scanning must
		 * be enabled and we must not be operating in the
		 * turbo phase of dynamic turbo mode.  Then,
		 * it's been a while since the last background
		 * scan and if no data frames have come through
		 * recently, kick off a scan.  Note that this
		 * is the mechanism by which a background scan
		 * is started _and_ continued each time we
		 * return on-channel to receive a beacon from
		 * our ap.
		 */
		if (ieee80211_is_scanning(ic)) {
			ieee80211_add_scan(vap, &scan, wh,
				subtype, rssi, rstamp);
		} else if (contbgscan(vap) || startbgscan(vap)) {
			ieee80211_bg_scan(vap);
		}
		if (extcap != NULL)
			ieee80211_parse_extcap(ni, extcap, wh->i_addr3);
		ieee80211_repeater_process_cascade_ie(ic, ni, scan.repeater);
		ieee80211_repeater_process_rp_info_ie(ic, ni, scan.rp_info);
		return;
	}

	/*
	 * If scanning, pass information to the scan module.
	 */
	if (ieee80211_is_scanning(ic)) {
		/* In two cases station scan list will be updated.
		 * 1. when 11ac_and 11n flag is set and only vht or ht capabilities
		 *	are present in Beacon/Probe response.
		 * 2. When 11ac_and_11n flag is not set.
		 */
		if (ieee80211_phy_mode_allowed(vap, scan.vhtcap, scan.htcap))
			ieee80211_add_scan(vap, &scan, wh, subtype, rssi, rstamp);
		return;
	}

#ifdef QSCS_ENABLED
	if (ic->ic_scs.scs_smpl_enable)
		ieee80211_add_scs_off_chan(vap, &scan, wh, subtype, rssi, rstamp);
#endif

	if (vap->iv_opmode == IEEE80211_M_WDS) {
		int return_val = 0;

		ieee80211_update_wds_peer_node(ni, &scan);

		if (scan.qtn != NULL) {
			ni->ni_vendor = PEER_VENDOR_QTN;
		} else if (scan.ath != NULL) {
			ni->ni_vendor = PEER_VENDOR_ATH;
		} else if (bcmie != NULL) {
			ni->ni_vendor = PEER_VENDOR_BRCM;
			ni->ni_qtn_flags |= QTN_IS_BCM_NODE;
		} else if (rlnk != NULL) {
			ni->ni_vendor = PEER_VENDOR_RLNK;
		} else if (rtkie != NULL) {
			ni->ni_vendor = PEER_VENDOR_RTK;
		}

		if (unlikely(scan.csa != NULL) && IEEE80211_VAP_WDS_IS_RBS(vap))
			return_val = ieee80211_parse_csaie(ni, wh, scan.csa, scan.csa_tsf,
						NULL, NULL);
		if (QTN_CSAIE_ERR_CHAN_NOT_SUPP == return_val)
			if (!ieee80211_handle_csa_invalid_channel(ni, wh))
				return;

		return;
	}

	/* check beacon for non-ERP and non-HT non member protection mode
	 * non-ERP protection: OBSS non-ERP protection is set when
	 * a) non-ERP present bit is set in the OBSS AP
	 * b) B only AP is present
	 * non-HT non member protection is set when there is non HT BSS.
	 * Timer is used to reset the protection parameters after last
	 * non-ERP AP or non-HT BSS goes away.
	 */
	if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
		uint8_t nonht_obss;
		struct ieee80211_ie_htinfo *ht = (struct ieee80211_ie_htinfo *) scan.htinfo;
		nonht_obss = ((scan.htcap == NULL) || (ht == NULL) ||
			((ht->hi_byte2 & IEEE80211_HTINFO_OPMODE_HT_PROT_MIXED) ==
			IEEE80211_HTINFO_OPMODE_HT_PROT_MIXED));

		if (nonht_obss) {
			if (IS_IEEE80211_24G_40(ic) && ic->ic_20_40_coex_enable) {
				ieee80211_change_bw(vap, BW_HT20, 0);
				ic->ic_coex_stats_update(ic, WLAN_COEX_STATS_BW_SCAN);
			}

			/*Legacy AP is present */
			if (ic->ic_non_ht_non_member == 0) {
				/* First non-HT AP beacon received */
				beacon_update_required = 1;
				ic->ic_non_ht_non_member = 1;
				vap->iv_ht_flags |= IEEE80211_HTF_HTINFOUPDATE;
			}
		}

		/* Check non-ERP protection in 2 GHz band */
		if (IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan)) {
			non_erp_present = is_non_erp_prot_required(&scan);

			if (IEEE80211_BG_PROTECT_ENABLED(ic)
					&& non_erp_present
					&& !(ic->ic_flags & IEEE80211_F_USEPROT)) {
				/* First OBSS non-ERP AP beacon received */
				/* Set Use_Protection in ERP IE */
				ic->ic_flags |= IEEE80211_F_USEPROT;

				/* To call ieee80211_add_erp function */
				ic->ic_flags_ext |= IEEE80211_FEXT_ERPUPDATE;
				beacon_update_required = 1;
				/* tell Muc to use ERP cts-to-self mechanism now */
				ic->ic_set_11g_erp(vap, 1);
			}
		}

		if (vap->iv_state == IEEE80211_S_RUN) {
			/* Update beacon */
			if(beacon_update_required)
				ic->ic_beacon_update(vap);

			if (nonht_obss) {
				mod_timer(&vap->iv_swbmiss,
					jiffies + vap->iv_swbmiss_period);
			}

			if (non_erp_present) {
				mod_timer(&vap->iv_swberp,
					jiffies + vap->iv_swberp_period);
			}
		}
	}

	if ((vap->iv_opmode == IEEE80211_M_IBSS) &&
			(scan.capinfo & IEEE80211_CAPINFO_IBSS)) {
		if (!IEEE80211_ADDR_EQ(wh->i_addr2, ni->ni_macaddr)) {
			/* Create a new entry in the neighbor table. */
			ni = ieee80211_add_neighbor(vap, wh, &scan);
			node_reference_held = 1;
		} else {
			/*
			 * Copy data from beacon to neighbor table.
			 * Some of this information might change after
			 * ieee80211_add_neighbor(), so we just copy
			 * everything over to be safe.
			 */
			ni->ni_esslen = scan.ssid[1];
			memcpy(ni->ni_essid, scan.ssid + 2, scan.ssid[1]);
			IEEE80211_ADDR_COPY(ni->ni_bssid, wh->i_addr3);
			memcpy(ni->ni_tstamp.data, scan.tstamp,
				sizeof(ni->ni_tstamp));
			ni->ni_intval = IEEE80211_BINTVAL_SANITISE(scan.bintval);
			ni->ni_capinfo = scan.capinfo;
			ni->ni_chan = ic->ic_curchan;
			ni->ni_fhdwell = scan.fhdwell;
			ni->ni_fhindex = scan.fhindex;
			ni->ni_erp = scan.erp;
			ni->ni_timoff = scan.timoff;
			if (scan.wme != NULL)
				ieee80211_saveie(&ni->ni_wme_ie, scan.wme);
			if (scan.wpa != NULL)
				ieee80211_saveie(&ni->ni_wpa_ie, scan.wpa);
			if (scan.rsn != NULL)
				ieee80211_saveie(&ni->ni_rsn_ie, scan.rsn);
			if (scan.wsc != NULL)
				ieee80211_saveie(&ni->ni_wsc_ie, scan.wsc);
			if (scan.ath != NULL)
				ieee80211_saveath(ni, scan.ath);

			/* NB: must be after ni_chan is setup */
			ieee80211_setup_rates(ni, scan.rates,
				scan.xrates, IEEE80211_F_DOSORT);
		}

		if (ni != NULL) {
			ni->ni_rssi = rssi;
			ni->ni_rstamp = rstamp;
			ni->ni_last_rx = jiffies;
			if (node_reference_held)
				ieee80211_free_node(ni);
		}
	}

	ieee80211_repeater_process_cascade_ie(ic, ni, scan.repeater);
}

static void
ieee80211_recv_probe_req(struct ieee80211_node *ni, struct sk_buff *skb,
	int subtype, int rssi, u_int32_t rstamp)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_frame *wh = (struct ieee80211_frame *)skb->data;
	uint8_t *frm = (u_int8_t *)&wh[1];
	uint8_t *efrm = skb->data + skb->len;
	uint8_t *ssid = NULL;
	uint8_t *rates = NULL;
	uint8_t *xrates = NULL;
	uint8_t *ath = NULL;
	uint8_t *htcap = NULL;
	uint8_t *vhtcap = NULL;
	uint8_t *interw = NULL;
	int node_reference_held = 0;
	uint8_t rate;
	struct ieee80211_mfr_entry *mfr_entry;
	int filtered;

	if (vap->iv_opmode == IEEE80211_M_STA ||
			vap->iv_opmode == IEEE80211_M_AHDEMO ||
			vap->iv_opmode == IEEE80211_M_WDS ||
			vap->iv_state != IEEE80211_S_RUN ||
			vap->is_block_all_assoc) {
		vap->iv_stats.is_rx_mgtdiscard++;
		return;
	}

#if defined(PLATFORM_QFDR)
	if (ic->ic_reject_auth & QFDR_F_IGNORE_PROBE_REQ)
		return;
#endif

	if (vap->iv_acl != NULL && !vap->iv_acl->iac_check(vap, wh->i_addr2)) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_ACL, wh,
				"Probe Req", "%s", "disallowed by ACL");
		vap->iv_stats.is_rx_acl++;
		return;
	}

	/*
	 * prreq frame format
	 *	[tlv] ssid
	 *	[tlv] supported rates
	 *	[tlv] extended supported rates
	 *      [tlv] Atheros Advanced Capabilities
	 */
	while (frm < efrm) {
		if (ieee80211_verify_length(vap, efrm - frm, frm[1], wh, subtype))
			return;
		if (!ieee80211_verify_ie_len(vap, wh, subtype, frm))
			return;

		switch (*frm) {
		case IEEE80211_ELEMID_SSID:
			/* WAR: Null-paddings are interpreted as null SSID IEs */
			ssid = ssid ? ssid : frm;
			break;
		case IEEE80211_ELEMID_RATES:
			rates = frm;
			break;
		case IEEE80211_ELEMID_HTCAP:
			htcap = frm;
			break;
		case IEEE80211_ELEMID_VHTCAP:
			vhtcap = frm;
			break;
		case IEEE80211_ELEMID_XRATES:
			xrates = frm;
			break;
		case IEEE80211_ELEMID_INTERWORKING:
			interw = frm;
			break;
		case IEEE80211_ELEMID_VENDOR:
			if (isatherosoui(frm))
				ath = frm;
			break;
		}
		frm += frm[1] + 2;
	}
	if (frm > efrm)
		return;

	if (!ieee80211_ie_exists(vap, wh, subtype, ssid) ||
			!ieee80211_ie_exists(vap, wh, subtype, rates))
		return;

	mfr_entry = ieee80211_mfr_is_in_list(vap, subtype, 0, 0,
			IEEE80211_MFR_FLAG_RECV | IEEE80211_MFR_FLAG_SKB_COPY);
	if (mfr_entry) {
		filtered = ieee80211_mfr_send_to_app(vap, mfr_entry, skb, rssi, 1, NULL);
#ifdef CONFIG_QTN_BSA_SUPPORT
		if (vap->bsa_status == IEEE80211_QRPE_STATUS_ACTIVE) {
			if (filtered > BSA_ACTION_NONE) {
				vap->iv_stats.is_rx_mgtdiscard++;
				return;
			}
		}
#endif
	}
#if defined(CONFIG_QTN_BSA_SUPPORT)
	else if (vap->bsa_status == IEEE80211_QRPE_STATUS_ACTIVE) {
		uint8_t matched_result[ERW_CONTENT_MATCH_MAX_BUF_LEN] = { 0 };
		int ret = 0;

		ieee80211_bsa_macfilter_check(vap, wh->i_addr2, NULL, 0, subtype,
					rssi, &filtered, NULL,
					matched_result, ERW_CONTENT_MATCH_MAX_BUF_LEN);
		ret = ieee80211_bsa_probe_or_assoc_send(vap, skb, vap->iv_myaddr,
				subtype, wh->i_addr2, rssi, filtered);

		if (ret < 0)
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_INPUT,
					"send probe event failed for [%s]\n",
					ether_sprintf(wh->i_addr2));

		if (filtered != BSA_ACTION_NONE) {
			vap->iv_stats.is_rx_mgtdiscard++;
			return;
		}

	}
#endif

	if (ieee80211_verify_ssid(vap, ni, wh, ssid, subtype) ==
			IEEE80211_VERIFY_SSID_ACTION_RETURN)
		return;

	if (vap->interworking && interw != NULL) {
		if (ieee80211_verify_interworking(vap, interw))
			return;
	}

	if (ni == vap->iv_bss) {
		if (vap->iv_opmode == IEEE80211_M_IBSS) {
			/*
			 * XXX Cannot tell if the sender is operating
			 * in ibss mode.  But we need a new node to
			 * send the response so blindly add them to the
			 * neighbor table.
			 */
			ni = ieee80211_fakeup_adhoc_node(vap,
				wh->i_addr2);
		} else {
			ni = ieee80211_tmp_node(vap, wh->i_addr2);
		}

		if (ni == NULL)
			return;

		node_reference_held = 1;
	}

	IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_INPUT, wh->i_addr2,
		"%s", "recv probe req");

	ni->ni_rssi = rssi;
	ni->ni_rstamp = rstamp;
	ni->ni_last_rx = jiffies;
	rate = ieee80211_setup_rates(ni, rates, xrates,
			IEEE80211_F_DOSORT | IEEE80211_F_DOFRATE |
			IEEE80211_F_DONEGO | IEEE80211_F_DODEL);
	if (rate & IEEE80211_RATE_BASIC) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_XRATE,
			wh, ieee80211_mgt_subtype_name[subtype >>
			IEEE80211_FC0_SUBTYPE_SHIFT],
			"%s", "recv'd rate set invalid");
	} else {
		/*
		 * discard probereq during scan if not in home channel
		 */
		if ((ic->ic_flags & IEEE80211_F_SCAN) &&
				((ic->ic_des_chan == IEEE80211_CHAN_ANYC) ||
				(ic->ic_des_chan != ic->ic_curchan))) {
			if (node_reference_held)
				ieee80211_free_node(ni);
			return;
		}

		IEEE80211_SEND_MGMT(ni,
			IEEE80211_FC0_SUBTYPE_PROBE_RESP,
			ssid[1] == 0);
	}

	if (node_reference_held)
		ieee80211_free_node(ni);
	else if (ath != NULL)
		ieee80211_saveath(ni, ath);
}

static void
ieee80211_recv_auth(struct ieee80211_node *ni, struct sk_buff *skb,
	int subtype, int rssi, u_int32_t rstamp)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_frame *wh = (struct ieee80211_frame *)skb->data;
	uint8_t *frm = (u_int8_t *)&wh[1];
	uint8_t *efrm = skb->data + skb->len;
	uint16_t algo;
	uint16_t seq;
	uint16_t status;
	struct ieee80211_mfr_entry *mfr_entry = NULL;
	int filtered;
	uint16_t reject_code;
	struct ieee80211_rsnparms *vap_rsn = &vap->iv_bss->ni_rsn;
	struct ieee80211_ie_neighbor_report *nr_ie = NULL;

	/*
	 * auth frame format
	 *	[2] algorithm
	 *	[2] sequence
	 *	[2] status
	 *	[tlv*] challenge
	 */

	if (ieee80211_verify_length(vap, efrm - frm, 6, wh, subtype))
		return;
	if (!IEEE80211_ADDR_EQ(wh->i_addr3, vap->iv_bss->ni_bssid)) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_AUTH,
			wh, ieee80211_mgt_subtype_name[subtype >>
				IEEE80211_FC0_SUBTYPE_SHIFT],
			"%s", "wrong bssid");

		ieee80211_auth_bssid_mismatch(vap, wh, ni);
		return;
	}
	algo = le16toh(*(__le16 *)frm);
	seq = le16toh(*(__le16 *)(frm + 2));
	status = le16toh(*(__le16 *)(frm + 4));

	IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, wh->i_addr2,
		"recv auth frame with algorithm %d seq %d status %d", algo, seq, status);

#ifdef ARTSMNG_SUPPORT
	/* pass auth request packets to higher layer */
	artsmng_auth_copy(vap, wh->i_addr2, ((10 * rssi) - 900) / 10,
		ic->ic_curchan->ic_ieee, (char *)ni->ni_essid);
#endif /* ARTSMNG_SUPPORT */

	if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
		if (!(ic->ic_flags_ext & IEEE80211_FEXT_REPEATER)
				&& (ic->ic_curchan->ic_flags & IEEE80211_CHAN_DFS)
				&& (!IEEE80211_IS_CHAN_CACDONE(ic->ic_curchan))) {
			IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, wh->i_addr2,
				"During DFS CAC period(channel %3d), reject auth frame",
				ic->ic_curchan->ic_ieee);
			return;
		}

		if (unlikely(ieee80211_input_mac_reserved(vap, ic, ni, wh)))
			return;

		if (vap->is_block_all_assoc) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_AUTH, wh, "auth",
				"%s", "Dropped due to BSS is set to block all assoc");
			IEEE80211_SEND_MGMT(ni, IEEE80211_FC0_SUBTYPE_DEAUTH,
					IEEE80211_STATUS_DENIED);
			return;
		}

#if defined(PLATFORM_QFDR)
		if (ic->ic_reject_auth & QFDR_F_REJECT_AUTH) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_AUTH,
				wh, "auth", "%s", "Rejected auth frame");
			ieee80211_send_error(ni, wh->i_addr2,
				IEEE80211_FC0_SUBTYPE_AUTH,
				(seq+1) | (IEEE80211_STATUS_TOOMANY << 16));
			return;
		}
#endif /* PLATFORM_QFDR */

		mfr_entry = ieee80211_mfr_is_in_list(vap, subtype, 0, 0,
				IEEE80211_MFR_FLAG_RECV | IEEE80211_MFR_FLAG_SKB_COPY);
		if (mfr_entry) {
			filtered = ieee80211_mfr_send_to_app(vap, mfr_entry, skb, rssi, 1, &reject_code);
#if defined(CONFIG_QTN_BSA_SUPPORT)
			if (vap->bsa_status == IEEE80211_QRPE_STATUS_ACTIVE) {
				if (filtered == BSA_ACTION_WITHHOLD) {
					vap->iv_stats.is_rx_mgtdiscard++;
					IEEE80211_DISCARD(vap, IEEE80211_MSG_AUTH,
							wh, "auth", "%s", "BSA blocked auth from STA [%pM]",
							wh->i_addr2);
					return;
				} else if (filtered == BSA_ACTION_REJECT) {
					IEEE80211_DISCARD(vap, IEEE80211_MSG_AUTH,
							wh, "auth", "BSA AUTH STA %pM with status code %d",
							wh->i_addr2, reject_code);
					vap->iv_stats.is_rx_auth_fail++;
					ieee80211_send_error(ni, wh->i_addr2,
							IEEE80211_FC0_SUBTYPE_AUTH,
							(seq + 1) | (reject_code << 16));
					return;
				}
			}
#endif
		}
	} else if (vap->iv_opmode == IEEE80211_M_STA) {
		mfr_entry = ieee80211_mfr_is_in_list(vap, subtype, 0, 0,
				IEEE80211_MFR_FLAG_RECV | IEEE80211_MFR_FLAG_SKB_COPY);
		if (mfr_entry)
			ieee80211_mfr_send_to_app(vap, mfr_entry, skb, rssi, 0, NULL);
	}
#if defined(CONFIG_QTN_BSA_SUPPORT)
	if (!mfr_entry  && vap->bsa_status == IEEE80211_QRPE_STATUS_ACTIVE) {
		uint8_t matched_result[ERW_CONTENT_MATCH_MAX_BUF_LEN] = { 0 };
		int filtered = 0;

		ieee80211_bsa_macfilter_check(vap, wh->i_addr2, NULL, 0, subtype,
					rssi, &filtered, &reject_code, matched_result,
					ERW_CONTENT_MATCH_MAX_BUF_LEN);
		int ret = ieee80211_bsa_auth_event_send(vap, skb, vap->iv_myaddr,
				wh->i_addr2, rssi, filtered);

		if (ret < 0)
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_INPUT,
					"send auth event failed for [%s]\n",
					ether_sprintf(wh->i_addr2));

		if (filtered == BSA_ACTION_WITHHOLD) {
			vap->iv_stats.is_rx_mgtdiscard++;
			ieee80211_send_error(ni, wh->i_addr2,
					IEEE80211_FC0_SUBTYPE_DEAUTH,
					IEEE80211_REASON_NOT_AUTHORIZED_THIS_LOCATION);
			return;
		} else if (filtered == BSA_ACTION_REJECT) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_AUTH,
				wh, "auth", "BSA AUTH STA %pM with status code %d",
				wh->i_addr2, reject_code);
			vap->iv_stats.is_rx_auth_fail++;
			ieee80211_send_error(ni, wh->i_addr2,
				IEEE80211_FC0_SUBTYPE_AUTH,
				(seq + 1) | (reject_code << 16));
			return;
		}
	}
#endif

	/* Consult the ACL policy module if set up */
	if (vap->iv_acl != NULL && !vap->iv_acl->iac_check(vap, wh->i_addr2)) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_ACL,
			wh, "auth", "%s", "disallowed by ACL");
		vap->iv_stats.is_rx_acl++;
		ieee80211_eventf(vap->iv_dev, "%s[WLAN access denied] from MAC: %pM",
			QEVT_ACL_PREFIX, wh->i_addr2);
		return;
	} else {
		ieee80211_eventf(vap->iv_dev, "%s[WLAN access allowed] from MAC: %pM",
			QEVT_ACL_PREFIX, wh->i_addr2);
	}

	if (vap->iv_flags & IEEE80211_F_COUNTERM) {
		IEEE80211_DISCARD(vap,
			IEEE80211_MSG_AUTH | IEEE80211_MSG_CRYPTO,
			wh, "auth", "%s", "TKIP countermeasures enabled");
		vap->iv_stats.is_rx_auth_countermeasures++;
		if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
			/* This will include broadcast deauth frame queued on BSS node */
			IEEE80211_SEND_MGMT(ni, IEEE80211_FC0_SUBTYPE_DEAUTH,
					IEEE80211_REASON_MIC_FAILURE);
		}
		return;
	}

#ifdef ARTSMNG_SUPPORT
	/* auth req event should be passed to higher layers */
	ieee80211_eventf(vap->iv_dev, "%sClient auth-req [%pM]",
		QEVT_COMMON_PREFIX, wh->i_addr2);
#endif
	if (vap->iv_opmode == IEEE80211_M_STA && status == IEEE80211_STATUS_SUGGESTED_BSS_TRANS) {
		struct ieee80211_neighbor_report_trans_item item;

		if (vap->iv_state != IEEE80211_S_AUTH)
			return;
		memset(&item, 0, sizeof(struct ieee80211_neighbor_report_trans_item));

		frm = frm + 6;
		while (frm < efrm) {
			if (ieee80211_verify_length(vap, efrm - frm, frm[1], wh, subtype))
				return;
			if (!ieee80211_verify_ie_len(vap, wh, subtype, frm))
				return;
			switch (*frm) {
			case IEEE80211_ELEMID_NEIGHBOR_REP:
				nr_ie = (struct ieee80211_ie_neighbor_report *)frm;
				break;
			default:
				break;
			}
			frm += frm[1] + 2;
		}
		if (frm > efrm)
			return;

		if (nr_ie) {
			memcpy(item.bssid, nr_ie->bssid, IEEE80211_ADDR_LEN);
			item.operating_class = nr_ie->operating_class;
			item.channel = nr_ie->channel;
		}
		IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, wh->i_addr2,
					"Auth failed (reason %d)", status);
		vap->iv_stats.is_rx_auth_fail++;
		ieee80211_new_state(vap, IEEE80211_S_SCAN,
			IEEE80211_SCAN_FAIL_STATUS);
		ieee80211_notify_connect_failure(vap, ni->ni_macaddr, status);
		ieee80211_auth_prepare_send_event(vap, status, wh->i_addr2, &item);
		return;
	}


	if (algo == IEEE80211_AUTH_ALG_SHARED) {
		ieee80211_auth_shared(ni, wh, frm + 6, efrm, rssi,
			rstamp, seq, status);
	} else if (algo == IEEE80211_AUTH_ALG_OPEN) {
		int skip_drv_auth_resp = 0;
		if (IEEE80211_IS_ENABLE_11R(vap->iv_bss->ni_rsn.rsn_keymgmtset) ||
				ieee80211_keymgmt_req_app_processing(vap_rsn) ||
				(vap->iv_state_flags & IEEE80211_VAP_STATE_F_EXT_AUTH_FRAME_SENT)) {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
					  "[%pM] open auth req/resp sending up\n", wh->i_addr2);
			if ((vap->iv_opmode == IEEE80211_M_HOSTAP) && (ni == vap->iv_bss)) {
				ni = ieee80211_dup_bss(vap, wh->i_addr2);
				if (ni != NULL) {
					ni->ni_node_type = IEEE80211_NODE_TYPE_STA;
					ieee80211_free_node(ni);
				}
			}
			skip_drv_auth_resp = 1;
			forward_mgmt_to_app_for_further_processing(vap, subtype, skb, wh, rssi);
		}
		ieee80211_auth_open(ni, wh, rssi, rstamp, seq, status, skip_drv_auth_resp);
	} else if (algo == IEEE80211_AUTH_ALG_FT) {
		uint8_t cap = 0;
		uint16_t mdid = 0;
		frm += 6;
		/* Parse the auth req frame */
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
			"[%pM] FT auth request\n", wh->i_addr2);

		while (frm < efrm) {
			if (ieee80211_verify_length(vap, efrm - frm, frm[1], wh, subtype))
				return;
			if (!ieee80211_verify_ie_len(vap, wh, subtype, frm))
				return;

			switch (*frm) {
			case IEEE80211_ELEMID_MOBILITY_DOMAIN:
				if (frm[1] != IEEE80211_MDIE_LEN) {
					IEEE80211_DISCARD(vap, IEEE80211_MSG_AUTH, wh,
						"auth", "wrong len of MDID in auth req %d",
						frm[1]);
					return;
				}
				mdid = le16toh(*(u_int16_t *)(&frm[2]));
				if (mdid != ni->ni_vap->iv_mdid) {
					IEEE80211_DISCARD(vap, IEEE80211_MSG_AUTH, wh,
						"wrong", "mdid in auth %d, expected %d",
						mdid, ni->ni_vap->iv_mdid);

					return;
				}
				/* extract the ft policy and ft capability */
				cap = frm[4];
				ni->ni_ft_capability = cap;
				IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
					"[%pM] MDIE in the auth with the cap as %d, mdid %d \n",
					wh->i_addr2, cap, mdid);
				break;
			default:
				IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG,
					"[%pM] Received IE %d\n",
					wh->i_addr2,*frm);
				break;
			}
			frm += frm[1] + 2;
		}

		if (mdid == ni->ni_vap->iv_mdid) {
			if (ni == vap->iv_bss) {
				ni = ieee80211_dup_bss(vap, wh->i_addr2);
				if (ni != NULL) {
					ni->ni_node_type = IEEE80211_NODE_TYPE_STA;
					ieee80211_free_node(ni);
				}
			}
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
				"[%pM] FT auth request sending up\n", wh->i_addr2);
			forward_mgmt_to_app_for_further_processing(vap, subtype, skb, wh, rssi);
		}
	} else if (algo == IEEE80211_AUTH_ALG_SAE) {
		vap->iv_state_flags &= ~IEEE80211_VAP_STATE_F_EXT_AUTH_FRAME_SENT;
		forward_mgmt_to_app_for_further_processing(vap, subtype, skb, wh, rssi);
		return;
	} else {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
			wh, "auth", "unsupported alg %d", algo);
		vap->iv_stats.is_rx_auth_unsupported++;
		if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
			/* XXX not right */
			ieee80211_send_error(ni, wh->i_addr2,
				IEEE80211_FC0_SUBTYPE_AUTH,
				(seq+1) | (IEEE80211_STATUS_ALG << 16));
		}
		return;
	}

	ieee80211_off_channel_suspend(vap, IEEE80211_OFFCHAN_TIMEOUT_AUTH);

	if (ni != NULL)
		ni->ni_used_auth_algo = algo;
}

static void
ieee80211_reject_assoc_request(struct ieee80211_node *ni, uint8_t reason,
				struct ieee80211_frame *wh, int resp)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211_assoc_resp_data assoc_resp_data;

	memset(&assoc_resp_data, 0, sizeof(assoc_resp_data));

	assoc_resp_data.reject_code = IEEE80211_REASON_IE_INVALID;
	IEEE80211_SEND_MGMT(ni, resp, (int)&assoc_resp_data);
	ieee80211_node_leave(ni);
	vap->iv_stats.is_rx_assoc_capmismatch++;
	mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_ASSOC_FAILS, 1);
}

static int
ieee80211_handle_rsn_sae_or_owe(struct ieee80211_node *ni, struct sk_buff *skb,
		int rssi, struct ieee80211_frame *wh, int subtype)
{
	struct ieee80211vap *vap = ni->ni_vap;
	int resp;

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
				"[%pM]: key_mgmt %u, MFP %u\n",
				ni->ni_macaddr, ni->ni_rsn.rsn_keymgmt,
				RSN_IS_MFP(ni->ni_rsn.rsn_caps));

	if ((ni->ni_rsn.rsn_keymgmt != RSN_ASE_SAE) && (ni->ni_rsn.rsn_keymgmt != RSN_ASE_OWE) &&
		(ni->ni_rsn.rsn_keymgmt != RSN_ASE_DPP))
		return 0;

	if (RSN_IS_MFP(ni->ni_rsn.rsn_caps)) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
					"WPA3: [%pM] AKM : 0x%x send mgmt frame to hostapd\n",
					ni->ni_macaddr, ni->ni_rsn.rsn_keymgmt);
		forward_mgmt_to_app_for_further_processing(vap, subtype, skb, wh, rssi);
		ieee80211_update_current_mode(ni);
		return 1;
	}

	if ((subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ) ||
		(subtype == IEEE80211_FC0_SUBTYPE_REASSOC_REQ)) {

		if (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ)
			resp = IEEE80211_FC0_SUBTYPE_ASSOC_RESP;
		else
			resp = IEEE80211_FC0_SUBTYPE_REASSOC_RESP;

		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
			"[%pM] mgmt frame RSN OWE/SAE mismatch, MFP 0x%x, AKM 0x%x",
			wh->i_addr2, ni->ni_rsn.rsn_caps, ni->ni_rsn.rsn_keymgmt);
		ieee80211_reject_assoc_request(ni, IEEE80211_REASON_IE_INVALID, wh, resp);
		return 1;
	}

	return 0;
}


static uint8_t *ieee80211_parse_extie(uint8_t *frm, uint8_t check_id)
{
	uint8_t *pos = frm;
	uint8_t id = *(pos + 2);

	if (id == check_id)
		return frm;

	return NULL;
}

static inline uint8_t ieee80211_node_is_likely_ac88(struct ieee80211_node *ni)
{
	if ((ni->ni_qtn_flags & QTN_IS_BCM_NODE) &&
			IEEE80211_VHTCAP_GET_MU_BEAMFORMEE(&ni->ni_ie_vhtcap) &&
			ni->ni_vhtcap.bfstscap == IEEE80211_VHTCAP_RX_STS_4 &&
			ni->ni_vhtcap.numsounding == IEEE80211_VHTCAP_SNDDIM_4 &&
			IEEE80211_VHT_SUPPORTS_MCS0_9_FOR_4SS(ni->ni_vhtcap.rxmcsmap))
		return 1;
	return 0;
}

static inline uint8_t ieee80211_node_is_likely_s7_above(struct ieee80211_node *ni)
{
	if ((ni->ni_qtn_flags & QTN_IS_BCM_NODE) &&
			(ni->ni_flags & IEEE80211_NODE_VHT) &&
			IEEE80211_VHTCAP_GET_MU_BEAMFORMEE(&ni->ni_ie_vhtcap) &&
			(ni->ni_vhtcap.numsounding == IEEE80211_VHTCAP_SNDDIM_2))
		return 1;

	return 0;
}

static inline uint8_t *
ieee80211_choose_vht(struct ieee80211_node *ni, uint8_t *vht, uint8_t *bcm_vht)
{
	if (ni->ni_vendor == PEER_VENDOR_BRCM)
		return (bcm_vht ? bcm_vht : vht);
	else
		return (vht ? vht : bcm_vht);
}

static inline void ieee80211_node_is_likely_iphonex(struct ieee80211_node *ni, uint8_t *ie)
{
	struct ieee80211_ie_vhtcap *rvhtcap = (struct ieee80211_ie_vhtcap *)ie;

	if ((ni->ni_qtn_flags & QTN_IS_BCM_NODE) &&
		(ni->ni_qtn_flags & QTN_IS_APPLE_NODE) &&
		(ni->ni_flags & IEEE80211_NODE_VHT) &&
		(*(uint32_t *)rvhtcap->vht_cap == QTN_IPHONEX_VTH_CAP_FLAG)) {
		ni->ni_flags |= IEEE80211_NODE_IPHONE_X;
		IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_ASSOC,
			"[%pM] device is detected as iphonex\n",
			ni->ni_macaddr);
	}
}

static void
ieee80211_recv_assoc_req(struct ieee80211_node *ni, struct sk_buff *skb,
	int subtype, int rssi, u_int32_t rstamp)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_frame *wh = (struct ieee80211_frame *)skb->data;
	uint8_t *frm = (u_int8_t *)&wh[1];
	uint8_t *efrm = skb->data + skb->len;
	struct ieee80211_rsnparms rsn_parm;
	uint8_t interworking_ie_present = 0;
	struct ieee80211_20_40_coex_param *coex = NULL;
	enum ieee80211_verify_ssid_action ssid_verify_action;
	struct ieee80211_ie_power_capability *pwr_cap = NULL;
	struct ieee80211_ie_qtn_pairing *qtn_pairing_ie = NULL;
	struct ieee80211_ie_qtn *qtnie = NULL;
	uint16_t capinfo;
	uint16_t bintval;
	uint8_t reason;
	uint8_t *ssid = NULL;
	uint8_t *rates = NULL;
	uint8_t *xrates = NULL;
	uint8_t *wpa = NULL;
	uint8_t *rsn = NULL;
	uint8_t *osen = NULL;
	uint8_t *wme = NULL;
	uint8_t *ath = NULL;
	uint8_t *htcap = NULL;
	uint8_t *owedh = NULL;
	uint8_t *supp_chan_ie = NULL;
	uint8_t *reg_classes_ie = NULL;
	uint8_t *ftie = NULL;
	uint8_t *rlnk = NULL;
	uint8_t *vhtcap = NULL;
	uint8_t *vhtop = NULL;
	uint8_t *bcm_vhtcap = NULL;
	uint8_t *extcap = NULL;
	uint8_t *wscie = NULL;
	uint8_t *mdie = NULL;
	uint8_t *opmode_notif_ie = NULL;
	uint8_t *rrm_enabled = NULL;
	uint8_t *rep_cascade = NULL;
	void *bcmie = NULL;
	void *appleie = NULL;
	void *rtkie = NULL;
	int8_t min_txpwr;
	int8_t max_txpwr;
	int8_t local_max_txpwr;
	uint8_t rate;
	int error = 0;
	int reassoc;
	int resp;
	struct ieee80211_mfr_entry *mfr_entry;
	int filtered;
	uint16_t reject_code;
	int node_reference_held = 0;
	struct ieee80211_rsnparms *vap_rsn = &vap->iv_bss->ni_rsn;
	struct ieee80211_assoc_resp_data assoc_resp_data;

	memset(&assoc_resp_data, 0, sizeof(assoc_resp_data));

	if (vap->iv_opmode != IEEE80211_M_HOSTAP ||
			vap->iv_state != IEEE80211_S_RUN) {
		vap->iv_stats.is_rx_mgtdiscard++;
		return;
	}

	if (subtype == IEEE80211_FC0_SUBTYPE_REASSOC_REQ) {
		reassoc = 1;
		resp = IEEE80211_FC0_SUBTYPE_REASSOC_RESP;
	} else {
		reassoc = 0;
		resp = IEEE80211_FC0_SUBTYPE_ASSOC_RESP;
	}

	if ((ni == vap->iv_bss) && ieee80211_keymgmt_req_app_processing(vap_rsn)) {
		ni = ieee80211_find_node(&ic->ic_sta, wh->i_addr2);
		if (!ni) {
			ni = ieee80211_dup_bss(vap, wh->i_addr2);
			if (ni == NULL) {
				mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_ASSOC_FAILS, 1);
				return;
			}
			node_reference_held = 1;
			ni->ni_node_type = IEEE80211_NODE_TYPE_STA;
		}
	}

	if (reassoc)
		ieee80211_clear_frag(ni);

	mfr_entry = ieee80211_mfr_is_in_list(vap, subtype, 0, 0,
			IEEE80211_MFR_FLAG_RECV | IEEE80211_MFR_FLAG_SKB_COPY);
	if (mfr_entry) {
		filtered = ieee80211_mfr_send_to_app(vap, mfr_entry, skb, rssi, 1, &reject_code);
#if defined(CONFIG_QTN_BSA_SUPPORT)
		if (vap->bsa_status == IEEE80211_QRPE_STATUS_ACTIVE) {
			if (filtered == BSA_ACTION_WITHHOLD) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
						wh, ieee80211_mgt_subtype_name[subtype >>
						IEEE80211_FC0_SUBTYPE_SHIFT],
						"%s", "BSA blocked assoc req from STA [%pM]", wh->i_addr2);
				vap->iv_stats.is_rx_assoc_bss++;
				vap->iv_stats.is_rx_mgtdiscard++;
				if (ni != vap->iv_bss)
					ieee80211_node_leave(ni);
				return;
			} else if (filtered == BSA_ACTION_REJECT) {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
						wh, ieee80211_mgt_subtype_name[subtype >> IEEE80211_FC0_SUBTYPE_SHIFT],
						"BSA Associate STA %pM with status code %d", wh->i_addr2, reject_code);
				if (ni != vap->iv_bss) {
					assoc_resp_data.reject_code = reject_code;
					IEEE80211_SEND_MGMT(ni, resp, (int)&assoc_resp_data);
					ieee80211_node_leave(ni);
				}
				vap->iv_stats.is_rx_assoc_bss++;
				mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_ASSOC_FAILS, 1);
				return;
			}

		}
#endif
	}

	if (vap->is_block_all_assoc) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
			wh, ieee80211_mgt_subtype_name[subtype >>
				IEEE80211_FC0_SUBTYPE_SHIFT],
			"%s", "BSS is blocked for all association request");
		vap->iv_stats.is_rx_assoc_bss++;
		assoc_resp_data.reject_code = IEEE80211_STATUS_DENIED;
		IEEE80211_SEND_MGMT(ni, resp, (int)&assoc_resp_data);
		return;
	}
	/*
	 * asreq frame format
	 *	[2] capability information
	 *	[2] listen interval
	 *	[6*] current AP address (reassoc only)
	 *	[tlv] ssid
	 *	[tlv] supported rates
	 *	[tlv] extended supported rates
	 *	[tlv] power capability
	 *	[tlv] supported channels
	 *	[tlv] wpa or RSN
	 *	[tlv] WME
	 *	[tlv] Atheros Advanced Capabilities
	 *	[tlv] Quantenna flags
	 *	[tlv] U-Repeater Cascade IE
	 */
	if (ieee80211_verify_length(vap, efrm - frm, (reassoc ? 10 : 4), wh, subtype)) {
		if (node_reference_held)
			ieee80211_free_node(ni);
		return;
	}
	if (!IEEE80211_ADDR_EQ(wh->i_addr3, vap->iv_bss->ni_bssid)) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
			wh, ieee80211_mgt_subtype_name[subtype >>
				IEEE80211_FC0_SUBTYPE_SHIFT],
			"%s", "wrong bssid");
		vap->iv_stats.is_rx_assoc_bss++;
		mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_ASSOC_FAILS, 1);
		return;
	}
	if (vap->iv_pmf &&
		RSN_IS_MFP(ni->ni_rsn.rsn_caps) &&
		(ni->ni_associd) &&
		(!ni->ni_sa_query_timeout)) {

		assoc_resp_data.reject_code = IEEE80211_STATUS_PMF_REJECT_RETRY;
		IEEE80211_SEND_MGMT(ni, resp, (int)&assoc_resp_data);
		ieee80211_send_sa_query(ni, IEEE80211_ACTION_W_SA_QUERY_REQ,
				++ni->ni_sa_query_tid);
		ieee80211_start_sa_query_response_wait_timer(ni);
		return;
	}

	capinfo = le16toh(*(__le16 *)frm);
	frm += 2;
	bintval = le16toh(*(__le16 *)frm);
	frm += 2;
	if (reassoc)
		frm += 6;	/* ignore current AP info */
#if defined(CONFIG_QTN_BSA_SUPPORT)
	if (!mfr_entry && vap->bsa_status == IEEE80211_QRPE_STATUS_ACTIVE) {
		uint8_t matched_result[ERW_CONTENT_MATCH_MAX_BUF_LEN] = { 0 };
		int matched_type = ieee80211_bsa_macfilter_check(vap, wh->i_addr2, frm, efrm - frm,
					subtype, rssi, &filtered, &reject_code,
					matched_result, ERW_CONTENT_MATCH_MAX_BUF_LEN);
		int ret = ieee80211_bsa_probe_or_assoc_send(vap, skb,
					vap->iv_myaddr, subtype, wh->i_addr2, rssi, filtered);
		if (ret < 0)
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_INPUT,
					"send (re)assoc event failed for [%s]\n",
					ether_sprintf(wh->i_addr2));

		if (filtered == BSA_ACTION_WITHHOLD) {
			ieee80211_send_error(ni, wh->i_addr2,
				IEEE80211_FC0_SUBTYPE_DEAUTH,
				IEEE80211_REASON_NOT_AUTHORIZED_THIS_LOCATION);
			vap->iv_stats.is_rx_assoc_bss++;
			vap->iv_stats.is_rx_mgtdiscard++;
			if (ni != vap->iv_bss)
				ieee80211_node_leave(ni);

			return;
		} else if (filtered == BSA_ACTION_REJECT) {
			IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT, wh,
				ieee80211_mgt_subtype_name[subtype >> IEEE80211_FC0_SUBTYPE_SHIFT],
				"BSA Associate STA %pM with status code %d",
				wh->i_addr2, reject_code);
			if (ni != vap->iv_bss) {
				assoc_resp_data.reject_code = reject_code;
				assoc_resp_data.macfilter_matched_type = matched_type;
				assoc_resp_data.params = (void *)matched_result;
				IEEE80211_SEND_MGMT(ni, resp, (int)&assoc_resp_data);
				ieee80211_node_leave(ni);
			}
			vap->iv_stats.is_rx_assoc_bss++;
			mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_ASSOC_FAILS, 1);
			return;
		}
	}
#endif
	ni->ni_flags &= ~(IEEE80211_NODE_TPC | IEEE80211_NODE_PWR_MGT | IEEE80211_NODE_PS_POLL);

	while (frm < efrm) {
		if (ieee80211_verify_length(vap, efrm - frm, frm[1], wh, subtype)) {
			if (node_reference_held)
				ieee80211_free_node(ni);
			return;
		}
		if (!ieee80211_verify_ie_len(vap, wh, subtype, frm))
			return;

		switch (*frm) {
		case IEEE80211_ELEMID_SSID:
			ssid = frm;
			break;
		case IEEE80211_ELEMID_RATES:
			rates = frm;
			break;
		case IEEE80211_ELEMID_XRATES:
			xrates = frm;
			break;
		case IEEE80211_ELEMID_PWRCAP:
			pwr_cap = (struct ieee80211_ie_power_capability *)frm;
			ni->ni_flags |= IEEE80211_NODE_TPC;
			break;
		case IEEE80211_ELEMID_SUPPCHAN:
			supp_chan_ie = frm;
			break;
		case IEEE80211_ELEMID_INTERWORKING:
			interworking_ie_present = 1;
			break;
		/* XXX verify only one of RSN and WPA ie's? */
		case IEEE80211_ELEMID_RSN:
			if (vap->iv_flags & IEEE80211_F_WPA2)
				rsn = frm;
			else
				IEEE80211_DPRINTF(vap,
					IEEE80211_MSG_ASSOC | IEEE80211_MSG_WPA,
					"[%s] ignoring RSN IE in association request\n",
					ether_sprintf(wh->i_addr2));
			break;
		case IEEE80211_ELEMID_HTCAP:
			htcap = frm;
			break;
		case IEEE80211_ELEMID_VHTCAP:
			vhtcap = frm;
			break;
		case IEEE80211_ELEMID_VHTOP:
			vhtop = frm;
			break;
		case IEEE80211_ELEMID_OPMOD_NOTIF:
			opmode_notif_ie = frm;
			break;
		case IEEE80211_ELEMID_20_40_BSS_COEX:
			coex = (struct ieee80211_20_40_coex_param *)frm;
			break;
		case IEEE80211_ELEMID_VENDOR:
			/*
			 * don't override RSN element
			 * XXX: actually the driver should report both WPA versions,
			 * so wpa_supplicant can choose and also detect downgrade attacks
                         */
			if (iswpaoui(frm) && !wpa) {
				if (vap->iv_flags & IEEE80211_F_WPA1)
					wpa = frm;
				else
					IEEE80211_DPRINTF(vap,
						IEEE80211_MSG_ASSOC | IEEE80211_MSG_WPA,
						"[%s] ignoring WPA IE in association request\n",
						ether_sprintf(wh->i_addr2));
			} else if (isosenie(frm)) {
				osen = frm;
			} else if (is_mbo_oce(frm)) {
				ni->ni_qtn_flags |= QTN_NODE_IS_MBO;
			} else if (iswmeinfo(frm)) {
				wme = frm;
			} else if (isatherosoui(frm)) {
				ath = frm;
			} else if (isbroadcomoui(frm)) {
				bcmie = frm;
				if (isbrcmvhtoui(frm))
					bcm_vhtcap = ieee80211_get_vhtcap_from_brcmvht(ni, frm);
			} else if (isbroadcomoui2(frm)) {
				bcmie = frm;
			} else if (isappleoui(frm)) {
				appleie = frm;
			} else if (isrealtekoui(frm)) {
				rtkie = frm;
			} else if (isqtnie(frm)) {
				qtnie = (struct ieee80211_ie_qtn *)frm;
			/* For now just get the first WSC IE until we can handle multiple of these */
			} else if (iswscoui(frm) && !wscie) {
				wscie = frm;
			} else if (isqtnpairoui(frm)) {
				if (ieee80211_verify_length(vap, efrm - frm,
						sizeof(struct ieee80211_ie_qtn_pairing),
						wh, subtype)) {
					if (node_reference_held)
						ieee80211_free_node(ni);
					return;
				}
				qtn_pairing_ie = (struct ieee80211_ie_qtn_pairing *)frm;
			} else if (isrlnkoui(frm)) {
				rlnk = frm;
			} else if (is_qtn_repeater_cascade(frm)) {
				rep_cascade = frm;
			}
			break;
		case IEEE80211_ELEMID_EXTCAP:
			extcap = frm;
			if (extcap != NULL) {
				ieee80211_parse_extcap(ni, extcap, wh->i_addr2);
				ieee80211_parse_80211_v(ni, extcap);
			}
			break;
		case IEEE80211_ELEMID_EXTENSION:
			owedh = ieee80211_parse_extie(frm, IEEE80211_ELEMID_EXT_DH_PARAM);
			break;
		case IEEE80211_ELEMID_RRM_ENABLED:
			rrm_enabled = frm;
			break;
		case IEEE80211_ELEMID_MOBILITY_DOMAIN:
			mdie = frm;
			break;
		case IEEE80211_ELEMID_FTIE:
			ftie = frm;
			break;
		case IEEE80211_ELEMID_REG_CLASSES:
			reg_classes_ie = frm;
			break;

		}
		frm += frm[1] + 2;
	}
	if (frm > efrm)
		return;

	if (!ieee80211_ie_exists(vap, wh, subtype, ssid) ||
			!ieee80211_ie_exists(vap, wh, subtype, rates))
		return;

	ssid_verify_action = ieee80211_verify_ssid(vap, ni, wh, ssid, subtype);
	switch (ssid_verify_action) {
	case IEEE80211_VERIFY_SSID_ACTION_NODE_DEL_AND_RETURN:
		IEEE80211_SEND_MGMT(ni, IEEE80211_FC0_SUBTYPE_DEAUTH,
			IEEE80211_REASON_IE_INVALID);
		ieee80211_node_leave(ni);
		return;
	case IEEE80211_VERIFY_SSID_ACTION_RETURN:
		return;
	case IEEE80211_VERIFY_SSID_ACTION_NO:
	default:
		break;
	}

	if (ni == vap->iv_bss) {
		IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_INPUT | IEEE80211_MSG_ASSOC,
			wh->i_addr2, "deny %s request, sta not authenticated",
			reassoc ? "reassoc" : "assoc");
		ieee80211_send_error(ni, wh->i_addr2,
			IEEE80211_FC0_SUBTYPE_DEAUTH,
			IEEE80211_REASON_ASSOC_NOT_AUTHED);
		vap->iv_stats.is_rx_assoc_notauth++;
		mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_ASSOC_FAILS, 1);
		return;
	}

	if (is_assoc_limit_reached(ic, vap)) {
		IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_INPUT | IEEE80211_MSG_ASSOC,
			wh->i_addr2, "%s request denied, assoc limit %d reached,"
			" sta cnt %d", reassoc ? "reassoc" : "assoc",
			ic->ic_ssid_grp[vap->iv_ssid_group].limit,
			ic->ic_ssid_grp[vap->iv_ssid_group].assocs);
		assoc_resp_data.reject_code = IEEE80211_STATUS_TOOMANY;
		IEEE80211_SEND_MGMT(ni, resp, (int)&assoc_resp_data);
		ieee80211_node_leave(ni);
		vap->iv_stats.is_rx_assoc_toomany++;
		mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_ASSOC_FAILS, 1);

		return;
	}

	if (ieee80211_is_repeater(ic) &&
			rep_cascade &&
			ic->rep_curr_level >= ic->rep_max_level) {
		IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_INPUT | IEEE80211_MSG_ASSOC, wh->i_addr2,
			"%s request from a repeater denied, max level %u, current level %u",
			reassoc ? "reassoc" : "assoc",
			ic->rep_curr_level,
			ic->rep_max_level);
		ieee80211_send_error(ni, wh->i_addr2,
			IEEE80211_FC0_SUBTYPE_DEAUTH,
			IEEE80211_REASON_ASSOC_TOOMANY);
		ieee80211_node_leave(ni);
		vap->iv_stats.is_rx_assoc_toomany++;
		return;
	}

#if defined(PLATFORM_QFDR)
	if (ic->ic_reject_auth & QFDR_F_REJECT_AUTH) {
		IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_INPUT | IEEE80211_MSG_ASSOC,
			wh->i_addr2, "%s request rejected",
			reassoc ? "reassoc" : "assoc");
			assoc_resp_data.reject_code = IEEE80211_STATUS_TOOMANY;
			IEEE80211_SEND_MGMT(ni, resp, (int)&assoc_resp_data);
		ieee80211_node_leave(ni);
		return;
	}
#endif /* PLATFORM_QFDR */

	memset((u_int8_t*)&rsn_parm, 0, sizeof(rsn_parm));

	/* Validate power capability */
	/* power capability:ID|LEN|MIN TX CAP|MAX TX CAP */
	if ((ic->ic_flags & IEEE80211_F_DOTH) &&
			(ic->ic_flags_ext & IEEE80211_FEXT_TPC) &&
			pwr_cap != NULL) {
		TPC_DBG(vap, "[AP]channel=%d/regulatory power=%d/power"
			" constraint=%d/local max tx power=%d\n",
			ic->ic_bsschan->ic_ieee,
			ic->ic_bsschan->ic_maxregpower,
			ic->ic_pwr_constraint,
			ic->ic_bsschan->ic_maxregpower - ic->ic_pwr_constraint);

		/* check Power Cap IE Length */
		if (pwr_cap->len != 2) {
			TPC_DBG(vap, "[%s] invalid power capability, Discard it!\n",
					  ether_sprintf(wh->i_addr2));
			IEEE80211_SEND_MGMT(ni,
					IEEE80211_FC0_SUBTYPE_DEAUTH,
					IEEE80211_REASON_IE_INVALID);
			ieee80211_node_leave(ni);
			mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_ASSOC_FAILS, 1);
			return;
		} else {
			local_max_txpwr = ic->ic_bsschan->ic_maxregpower - ic->ic_pwr_constraint;
			min_txpwr = pwr_cap->min_txpwr;
			max_txpwr = pwr_cap->max_txpwr;
			TPC_DBG(vap, "[RECV ASSOC REQ]min power(%d) max power(%d) for mac(%s)\n",
					min_txpwr, max_txpwr, ether_sprintf(wh->i_addr2));

			if (min_txpwr > max_txpwr) {
				TPC_DBG(vap, "[AP] Warning,sta min power(%d) larger than"
					" max power(%d)!\n", min_txpwr,	max_txpwr);
			}

			if (min_txpwr > local_max_txpwr) {
				TPC_DBG(vap, "[AP] power capability unacceptable(min tx power=%d"
					" max tx power=%d), discard it!\n", min_txpwr, max_txpwr);
				IEEE80211_SEND_MGMT(ni,	IEEE80211_FC0_SUBTYPE_DEAUTH,
						IEEE80211_REASON_DISASSOC_BAD_POWER);
				ieee80211_node_leave(ni);
				vap->iv_stats.is_rx_assoc_capmismatch++;
				mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_ASSOC_FAILS, 1);
				return;
			} else {
				ni->ni_tpc_info.tpc_sta_cap.min_txpow = min_txpwr;
				ni->ni_tpc_info.tpc_sta_cap.max_txpow = max_txpwr;
			}
		}
	}

	/* Validate association security credentials */
	if ((rsn != NULL) || (wpa != NULL) || (osen != NULL)) {
		/*
		 * Parse WPA information element.  Note that
		 * we initialize the param block from the node
		 * state so that information in the IE overrides
		 * our defaults.  The resulting parameters are
		 * installed below after the association is assured.
		 */
		rsn_parm = ni->ni_rsn;

		if (rsn != NULL) {
			reason = ieee80211_parse_rsn(vap, rsn, &rsn_parm, wh);
		} else {
			if (wpa != NULL)
				reason = ieee80211_parse_wpa(vap, wpa, &rsn_parm, wh);
			else
				reason = ieee80211_parse_osen(vap, osen, &rsn_parm, wh);
		}

		if (reason != 0) {
			IEEE80211_DPRINTF(vap,
				  IEEE80211_MSG_ASSOC | IEEE80211_MSG_WPA,
				  "[%s] WPA/RSN IE mismatch in association request\n",
				  ether_sprintf(wh->i_addr2));
			IEEE80211_SEND_MGMT(ni,
				IEEE80211_FC0_SUBTYPE_DEAUTH, reason);
			ieee80211_node_leave(ni);
			/* XXX distinguish WPA/RSN? */
			vap->iv_stats.is_rx_assoc_badwpaie++;
			mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_ASSOC_FAILS, 1);
			return;
		}

		IEEE80211_NOTE_MAC(vap,
			IEEE80211_MSG_ASSOC | IEEE80211_MSG_WPA,
			wh->i_addr2,
			"%s ie: mc %u/%u uc %u/%u key %u caps 0x%x",
			rsn ?  "RSN" :
			wpa ?  "WPA" : "OSEN",
			rsn_parm.rsn_mcastcipher, rsn_parm.rsn_mcastkeylen,
			rsn_parm.rsn_ucastcipher, rsn_parm.rsn_ucastkeylen,
			rsn_parm.rsn_keymgmt, rsn_parm.rsn_caps);

		/* Reject association if using TKIP and HT */
		if ((rsn_parm.rsn_ucastcipher == IEEE80211_CIPHER_TKIP) && (htcap != NULL)) {
			IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_INPUT, wh->i_addr2,
				"deny %s request, TKIP and HT rates requested",
				reassoc ? "reassoc" : "assoc");
			assoc_resp_data.reject_code = IEEE80211_STATUS_OTHER;
			IEEE80211_SEND_MGMT(ni, resp, (int)&assoc_resp_data);
			ieee80211_node_leave(ni);
			vap->iv_stats.is_rx_assoc_tkiphtreject++;
			mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_ASSOC_FAILS, 1);
			return;
		}
	}

	/* discard challenge after association */
	if (ni->ni_challenge != NULL) {
		FREE(ni->ni_challenge, M_DEVBUF);
		ni->ni_challenge = NULL;
	}

	/* 802.11 spec says to ignore station's privacy bit */
	if ((capinfo & IEEE80211_CAPINFO_ESS) == 0) {
		IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_INPUT, wh->i_addr2,
			"deny %s request, capability mismatch 0x%x",
			reassoc ? "reassoc" : "assoc", capinfo);
		assoc_resp_data.reject_code = IEEE80211_STATUS_CAPINFO;
		IEEE80211_SEND_MGMT(ni, resp, (int)&assoc_resp_data);
		ieee80211_node_leave(ni);
		vap->iv_stats.is_rx_assoc_capmismatch++;
		mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_ASSOC_FAILS, 1);
		return;
	}

	rate = ieee80211_setup_rates(ni, rates, xrates,
		IEEE80211_F_DOSORT | IEEE80211_F_DOFRATE |
		IEEE80211_F_DONEGO | IEEE80211_F_DODEL);

	/*
	 * If constrained to 11g-only stations reject an
	 * 11b-only station.  We cheat a bit here by looking
	 * at the max negotiated xmit rate and assuming anyone
	 * with a best rate <24Mb/s is an 11b station.
	 */
	if ((rate & IEEE80211_RATE_BASIC) ||
			((vap->iv_flags & IEEE80211_F_PUREG) && rate < 48)) {
		IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_INPUT, wh->i_addr2,
			"deny %s request, rate set mismatch",
			reassoc ? "reassoc" : "assoc");
		assoc_resp_data.reject_code = IEEE80211_STATUS_BASIC_RATE;
		IEEE80211_SEND_MGMT(ni, resp, (int)&assoc_resp_data);
		ieee80211_node_leave(ni);
		vap->iv_stats.is_rx_assoc_norate++;
		mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_ASSOC_FAILS, 1);
		return;
	}

	if (ni->ni_associd != 0 && IEEE80211_IS_CHAN_ANYG(ic->ic_bsschan)) {
		if ((ni->ni_capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME)
		    != (capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME)) {
			IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_INPUT,
				wh->i_addr2,
				"deny %s request, short slot time "
				"capability mismatch 0x%x",
				reassoc ? "reassoc" : "assoc", capinfo);
			assoc_resp_data.reject_code = IEEE80211_STATUS_CAPINFO;
			IEEE80211_SEND_MGMT(ni, resp, (int)&assoc_resp_data);
			ieee80211_node_leave(ni);
			vap->iv_stats.is_rx_assoc_capmismatch++;
			mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_ASSOC_FAILS, 1);
			return;
		}
	}

	if (qtnie != NULL)
		ni->ni_vendor = PEER_VENDOR_QTN;
	else if (bcmie != NULL)
		ni->ni_vendor = PEER_VENDOR_BRCM;
	else if (rlnk != NULL)
		ni->ni_vendor = PEER_VENDOR_RLNK;
	else if (rtkie != NULL)
		ni->ni_vendor = PEER_VENDOR_RTK;
	else if (appleie != NULL)
		ni->ni_vendor = PEER_VENDOR_APPLE;
	else
		ni->ni_vendor = PEER_VENDOR_NONE;

	vhtcap = ieee80211_choose_vht(ni, vhtcap, bcm_vhtcap);

	if (unlikely(ieee80211_input_assoc_req_qtnie(ni, vap, qtnie))) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
			"%s: Bridge mode mismatch - restarting, flags=%02x\n", __func__,
			qtnie->qtn_ie_flags);

		IEEE80211_SEND_MGMT(ni, IEEE80211_FC0_SUBTYPE_DEAUTH,
			IEEE80211_REASON_IE_INVALID);
		ieee80211_node_leave(ni);
		vap->iv_stats.is_rx_assoc_capmismatch++;
		return;
	}

	if (IEEE80211_IS_CHAN_ANYN(ic->ic_curchan)) {
		/*
		 * Assoc request ignored when 11ac_and_11n flag is set and
		 * vht or ht capabilities are not-present in Assoc req/reassoc req packet.
		 */
		if (!ieee80211_phy_mode_allowed(vap, vhtcap, htcap)) {
			IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_INPUT, wh->i_addr2,
			"deny %s request, VHT or HT capability IE are not present = %d",
			reassoc ? "reassoc" : "assoc", error);
			assoc_resp_data.reject_code = IEEE80211_STATUS_OTHER;
			IEEE80211_SEND_MGMT(ni, resp, (int)&assoc_resp_data);
			ieee80211_node_leave(ni);
			mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_ASSOC_FAILS, 1);
			return;
		}

		if (htcap != NULL) {
			ni->ni_flags |= IEEE80211_NODE_HT;

			/* record capabilities, mark node as capable of HT */
			error = ieee80211_setup_htcap(ni, htcap);
			if (error) {
				IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_INPUT, wh->i_addr2,
					   "deny %s request, ht capability mismatch error = %d",
					   reassoc ? "reassoc" : "assoc", error);
				assoc_resp_data.reject_code = IEEE80211_STATUS_HT_FEATURE;
				IEEE80211_SEND_MGMT(ni, resp, (int)&assoc_resp_data);
				ieee80211_node_leave(ni);
				vap->iv_stats.is_rx_assoc_nohtcap++;
				mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_ASSOC_FAILS, 1);
				return;
			}

			if (vhtcap && IS_IEEE80211_DUALBAND_VHT_ENABLED(ic)) {
				ieee80211_parse_vhtcap(ni, vhtcap);
				ni->ni_flags |= IEEE80211_NODE_VHT;

				IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
					"VHT Enabled: ni_flags = 0x%04x\n",
					ni->ni_flags);
			} else {
				ni->ni_flags &= ~IEEE80211_NODE_VHT;

				IEEE80211_DPRINTF(vap, IEEE80211_MSG_VHT,
					"VHT Disabled: ni_flags = 0x%04x\n",
					ni->ni_flags);
			}
		} else {
			/*
			 * Flush any state from a previous association.
			 */
			memset(&ni->ni_htcap, 0, sizeof(struct ieee80211_htcap));
			memset(&ni->ni_htinfo, 0, sizeof(struct ieee80211_htinfo));

			ni->ni_flags &= ~IEEE80211_NODE_HT;
			ni->ni_flags &= ~IEEE80211_NODE_VHT;
		}
	}

	ni->ni_rstamp = rstamp;
	ni->ni_last_rx = jiffies;
	ieee80211_scs_node_clean_stats(IEEE80211_SCS_STATE_INIT, ni);
	ni->ni_raw_bintval = bintval;
	ni->ni_intval = IEEE80211_BINTVAL_SANITISE(bintval);
	ni->ni_capinfo = capinfo;
	ni->ni_chan = ic->ic_curchan;
	ni->ni_fhdwell = vap->iv_bss->ni_fhdwell;
	ni->ni_fhindex = vap->iv_bss->ni_fhindex;
	ni->ni_rsn = rsn_parm;

	if (extcap != NULL) {
		/* Record extcap of STA */
		 ieee80211_saveie(&ni->ni_ie_extcap, extcap);
	} else if (ni->ni_ie_extcap != NULL) {
		FREE(ni->ni_ie_extcap, M_DEVBUF);
		ni->ni_ie_extcap = NULL;
	}

	if (wpa != NULL) {
		/*
		 * Record WPA/RSN parameters for station, mark
		 * node as using WPA and record information element
		 * for applications that require it.
		 */
		ieee80211_saveie(&ni->ni_wpa_ie, wpa);
	} else if (ni->ni_wpa_ie != NULL) {
		/*
		 * Flush any state from a previous association.
		 */
		FREE(ni->ni_wpa_ie, M_DEVBUF);
		ni->ni_wpa_ie = NULL;
	}

	if (rsn != NULL) {
		/*
		 * Record WPA/RSN parameters for station, mark
		 * node as using WPA and record information element
		 * for applications that require it.
		 */
		ieee80211_saveie(&ni->ni_rsn_ie, rsn);
	} else if (ni->ni_rsn_ie != NULL) {
		/*
		 * Flush any state from a previous association.
		 */
		FREE(ni->ni_rsn_ie, M_DEVBUF);
		ni->ni_rsn_ie = NULL;
	}

	if (osen != NULL) {
		/*
		 * Record OSEN parameters for station, mark
		 * node as using OSEN and record information element
		 * for applications that require it.
		 */
		ieee80211_saveie(&ni->ni_osen_ie, osen);
	} else if (ni->ni_osen_ie != NULL) {
		/*
		 * Flush any state from a previous association.
		 */
		FREE(ni->ni_osen_ie, M_DEVBUF);
		ni->ni_osen_ie = NULL;
	}

	if (ni->ni_rx_md_ie != NULL) {
		/*
		 * Flush any state from a previous association.
		 */
		FREE(ni->ni_rx_md_ie, M_DEVBUF);
		ni->ni_rx_md_ie = NULL;
	}

	if (mdie != NULL)
		ieee80211_saveie(&ni->ni_rx_md_ie, mdie);

	if (coex != NULL)
		ni->ni_coex = coex->coex_param;

	if ((ni->ni_htcap.cap & IEEE80211_HTCAP_C_CHWIDTH40) &&
			IS_IEEE80211_24G_40(ic))
		ni->ni_obss_scan = IEEE80211_NODE_OBSS_CAPABLE |
					IEEE80211_NODE_OBSS_RUNNING;

	if (wme != NULL) {
		/*
		 * Record WME parameters for station, mark node
		 * as capable of QoS and record information
		 * element for applications that require it.
		 */
		ieee80211_saveie(&ni->ni_wme_ie, wme);
		if (ieee80211_parse_wmeie(wme, wh, ni) > 0)
			ni->ni_flags |= IEEE80211_NODE_QOS;
	} else if (ni->ni_wme_ie != NULL) {
		/*
		 * Flush any state from a previous association.
		 */
		FREE(ni->ni_wme_ie, M_DEVBUF);
		ni->ni_wme_ie = NULL;
		ni->ni_flags &= ~IEEE80211_NODE_QOS;
	}

	if (ath != NULL) {
		ieee80211_saveath(ni, ath);
		ni->ni_vendor = PEER_VENDOR_ATH;
	} else if (ni->ni_ath_ie != NULL) {
		/*
		 * Flush any state from a previous association.
		 */
		FREE(ni->ni_ath_ie, M_DEVBUF);
		ni->ni_ath_ie = NULL;
		ni->ni_ath_flags = 0;
	}

	if (wscie != NULL) {
		ieee80211_saveie(&ni->ni_wsc_ie, wscie);

		/* if wsc_ie exists, peer is intel device, and WPS is started */
		if (IEEE80211_IS_INTEL_MAC_ADDR(ni->ni_macaddr) &&
				(vap->iv_flags_ext2 & IEEE80211_FEXT2_WPS_ACTIVE)) {
			if (!IEEE80211_ADDR_EQ(ni->ni_macaddr, vap->wps_intel_war.mac))
				IEEE80211_ADDR_COPY(vap->wps_intel_war.mac, ni->ni_macaddr);
			vap->wps_intel_war.active = 1;
		}
	} else if (ni->ni_wsc_ie != NULL) {
		FREE(ni->ni_wsc_ie, M_DEVBUF);
		ni->ni_wsc_ie = NULL;
	}

	if (wscie == NULL && vap->wps_intel_war.active &&
			IEEE80211_ADDR_EQ(ni->ni_macaddr, vap->wps_intel_war.mac))
		vap->wps_intel_war.active = 0;

	if (qtn_pairing_ie != NULL) {
		ieee80211_saveie(&ni->ni_qtn_pairing_ie, (u_int8_t *)qtn_pairing_ie);
	} else if (ni->ni_qtn_pairing_ie != NULL) {
		FREE(ni->ni_qtn_pairing_ie, M_DEVBUF);
		ni->ni_qtn_pairing_ie = NULL;
	}

	if (ni->ni_rx_ft_ie != NULL) {
		FREE(ni->ni_rx_ft_ie, M_DEVBUF);
		ni->ni_rx_ft_ie = NULL;
	}

	if (ftie != NULL)
		ieee80211_saveie(&ni->ni_rx_ft_ie, ftie);

	if (supp_chan_ie != NULL)
		ieee80211_parse_supp_chan(ni, supp_chan_ie);

	if (owedh != NULL) {
		ieee80211_saveie(&ni->ni_rx_owe_dh, owedh);
	} else if (ni->ni_rx_owe_dh != NULL) {
		FREE(ni->ni_rx_owe_dh, M_DEVBUF);
		ni->ni_rx_owe_dh = NULL;
	}

	/* Send TGf L2UF frame on behalf of newly associated station */
	ieee80211_deliver_l2uf(ni);

	/* Clean up old block ack state */
	ieee80211_node_ba_state_clear(ni);

	/* Add the local implicit BA values */
	if (qtnie && ni->ni_implicit_ba_valid)
		ieee80211_node_implicit_ba_setup(ni);

	/* Check if it is a broadcom station */
	if (unlikely(bcmie)) {
		ni->ni_qtn_flags |= QTN_IS_BCM_NODE;
		/* Check if it is AC88 station */
		if (ieee80211_node_is_likely_ac88(ni))
			ni->ni_qtn_flags |= QTN_IS_AC88_NODE;
	}

	if (unlikely(ieee80211_node_is_realtek(ni)))
		ni->ni_qtn_flags |= QTN_IS_REALTEK_NODE;

	/* check if it is a apple device */
	if (unlikely(appleie))
		ni->ni_qtn_flags |= QTN_IS_APPLE_NODE;

	/*
	 * if it an Intel 5x00/620x client, we need to mark the flag
	 * to use 2 tx chain only before informing MuC
	 */
	if ((ni->ni_flags & IEEE80211_NODE_HT) || (ni->ni_flags & IEEE80211_NODE_VHT)) {
		ieee80211_blacklist_ba(ni, 0);
	} else {
		/* No BBF for legacy clients */
		ni->ni_bbf_disallowed = 1;
	}

	/* TODO: Probably we need to filter out vendor sugn from ni_qtn_flags and move it to ni_vendor
	 * to remove duplicate signs of vendor.
	 */
	if (unlikely((ni->ni_qtn_flags & QTN_IS_INTEL_NODE ||
			ni->ni_qtn_flags & QTN_IS_INTEL_5100_NODE ||
			ni->ni_qtn_flags & QTN_IS_INTEL_5300_NODE) &&
			ni->ni_vendor == PEER_VENDOR_NONE)) {
		ni->ni_vendor = PEER_VENDOR_INTEL;
	}

	if (unlikely((pwr_cap == NULL) && (supp_chan_ie == NULL) &&
			(rrm_enabled == NULL) && (reg_classes_ie == NULL) &&
			(extcap == NULL) && (opmode_notif_ie == NULL) &&
			(!interworking_ie_present) &&
			ieee80211_node_is_opti_node(ni))) {
		ni->ni_qtn_flags |= QTN_OPTI_NODE;
	}

	if (ieee80211_node_is_likely_s7_above(ni)) {
		ni->ni_flags |= IEEE80211_NODE_BRCM_S7_ABOVE;
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
			"%pM detected as Samsung Galaxy device\n", wh->i_addr2);
	}

	if (rep_cascade)
		ni->ni_qtn_flags |= QTN_IS_QTN_REPEATER;

	if (vhtcap) {
		enum ieee80211_vhtop_chanwidth assoc_vhtop_bw;

		switch (IEEE80211_VHTCAP_GET_CHANWIDTH(
				(struct ieee80211_ie_vhtcap*)vhtcap)) {
		case IEEE80211_VHTCAP_CW_160M:
			assoc_vhtop_bw = IEEE80211_VHTOP_CHAN_WIDTH_160MHZ;
			break;
		case IEEE80211_VHTCAP_CW_160_AND_80P80M:
			assoc_vhtop_bw = IEEE80211_VHTOP_CHAN_WIDTH_80PLUS80MHZ;
			break;
		case IEEE80211_VHTCAP_CW_80M_ONLY:
		default:
			assoc_vhtop_bw = IEEE80211_VHTOP_CHAN_WIDTH_80MHZ;
			break;
		}
		/*
		 * Low bandwidth QTN client marks "Supported Channel Width Set" of VHTCAP IE as 00
		 * and indicates its bandwidth in OMN IE. So, bypass check for IOT clients.
		 */
		if (assoc_vhtop_bw == IEEE80211_VHTOP_CHAN_WIDTH_80MHZ &&
				opmode_notif_ie && qtnie) {
			struct ieee80211_ie_vhtop_notif *notif =
				(struct ieee80211_ie_vhtop_notif *)opmode_notif_ie;
			int chwidth = MS(notif->vhtop_notif_mode, IEEE80211_VHT_OPMODE_CHWIDTH);

			if (chwidth == IEEE80211_CWM_WIDTH20 || chwidth == IEEE80211_CWM_WIDTH40)
				assoc_vhtop_bw = IEEE80211_VHTOP_CHAN_WIDTH_20_40MHZ;
		}

		ni->ni_vhtop.chanwidth = assoc_vhtop_bw;

		if (IS_IEEE80211_11NG_VHT_ENABLED(ic)) {
			assoc_vhtop_bw = IEEE80211_VHTOP_CHAN_WIDTH_20_40MHZ;
			ni->ni_vhtop.chanwidth = assoc_vhtop_bw;
		}

		/* check for iphonex */
		ieee80211_node_is_likely_iphonex(ni, vhtcap);
	}

	if (unlikely(rrm_enabled)) {
		uint8_t rrm_enabled_byte0 = *(rrm_enabled + 2);
		if (rrm_enabled_byte0 & IEEE80211_RM_NEIGH_REPORT_CAP)
			ni->ni_rrm_capability |= IEEE80211_NODE_NEIGHBOR_REPORT_CAPABLE;
		if (rrm_enabled_byte0 & IEEE80211_RM_BEACON_PASSIVE_REPORT_CAP)
			ni->ni_rrm_capability |= IEEE80211_NODE_BEACON_PASSIVE_REPORT_CAPABLE;
		if (rrm_enabled_byte0 & IEEE80211_RM_BEACON_ACTIVE_REPORT_CAP)
			ni->ni_rrm_capability |= IEEE80211_NODE_BEACON_ACTIVE_REPORT_CAPABLE;
		if (rrm_enabled_byte0 & IEEE80211_RM_BEACON_TABLE_REPORT_CAP)
			ni->ni_rrm_capability |= IEEE80211_NODE_BEACON_TABLE_REPORT_CAPABLE;
	}

	if (((ni->ni_coex & WLAN_20_40_BSS_COEX_40MHZ_INTOL) ||
			(ni->ni_coex & WLAN_20_40_BSS_COEX_20MHZ_WIDTH_REQ) ||
			(ni->ni_htcap.cap & IEEE80211_HTCAP_C_40_INTOLERANT)) &&
			IS_IEEE80211_24G_40(ic) && ic->ic_20_40_coex_enable) {
		ieee80211_change_bw(vap, BW_HT20, 0);
		ic->ic_coex_stats_update(ic, WLAN_COEX_STATS_BW_ASSOC);
	}

	/* Mobility domain present, then let hostapd handle rest of association process */
	if (IEEE80211_IS_ENABLE_11R(vap_rsn->rsn_keymgmtset)) {
		/* FT assoc/reassoc request */
		if (ni->ni_rx_md_ie != NULL) {
			uint16_t mdid = *((uint16_t *)(ni->ni_rx_md_ie + 2));
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
				"%pM %s request mdid 0x%x\n", wh->i_addr2,
				reassoc ? "reassoc" : "assoc", mdid);
			if (mdid == vap->iv_mdid) {
				forward_mgmt_to_app_for_further_processing(vap, subtype,
									   skb, wh, rssi);
				update_current_mode(ni, opmode_notif_ie);
				return;
			} else {
				IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
					"%pM %s request mdid mismatch request 0x%x "
					"vap's mdid 0x%x\n",
					wh->i_addr2, reassoc ? "reassoc" : "assoc",
					mdid, vap->iv_mdid);
				IEEE80211_SEND_MGMT(ni, IEEE80211_FC0_SUBTYPE_DEAUTH, 13);
				ieee80211_node_leave(ni);
				vap->iv_stats.is_rx_assoc_capmismatch++;
				mlme_stats_delayed_update(wh->i_addr2,
						MLME_STAT_ASSOC_FAILS, 1);
				return;
			}
		} else {
			/* non FT assoc/reassoc request , let hostapd handle rest of association*/
			forward_mgmt_to_app_for_further_processing(vap, subtype, skb, wh, rssi);
			update_current_mode(ni, opmode_notif_ie);
			return;
		}
	}


	ieee80211_param_to_qdrv(ni->ni_vap,
		IEEE80211_PARAM_MAX_MSDU_IN_AMSDU, ni->ni_max_msdu_in_amsdu,
		ni->ni_macaddr, IEEE80211_ADDR_LEN);

	if (ieee80211_handle_rsn_sae_or_owe(ni, skb, rssi, wh, subtype)) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
				  "%pM %s authmode sae/owe: send to app\n",
				  wh->i_addr2, reassoc ? "reassoc" : "assoc");
		if (node_reference_held)
			ieee80211_free_node(ni);
		return;
	}

	ieee80211_node_join(ni, resp);

	update_current_mode(ni, opmode_notif_ie);

	mlme_stats_delayed_update(wh->i_addr2, MLME_STAT_ASSOC, 1);
}

void ieee80211_send_assocresp_ie_event(struct ieee80211_node *ni, uint8_t *ies, uint16_t ielen)
{
	struct ieee80211vap *vap = ni->ni_vap;
	uint8_t assoc_resp_ie[IW_CUSTOM_MAX];
	union iwreq_data wreq;

	if (ielen > IW_CUSTOM_MAX)
		return;

	memset(&wreq, 0, sizeof(wreq));

	memcpy(&assoc_resp_ie, ies, ielen);
	wreq.data.length = ielen;

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC, "%s: pass assoc_resp ies to app\n", __func__);
	wireless_send_event(vap->iv_dev, IWEVASSOCRESPIE, &wreq, (char *)&assoc_resp_ie);
}

static void
ieee80211_recv_assoc_resp(struct ieee80211_node *ni, struct sk_buff *skb,
	int subtype, int rssi, u_int32_t rstamp)
{
#define	ISREASSOC(_st)	((_st) == IEEE80211_FC0_SUBTYPE_REASSOC_RESP)
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_frame *wh = (struct ieee80211_frame *)skb->data;
	uint8_t *frm = (u_int8_t *)&wh[1];
	uint8_t *efrm = skb->data + skb->len;
	struct ieee80211_ie_qtn_pairing *qtn_pairing_ie = NULL;
	struct ieee80211_ie_qtn *qtnie = NULL;
#ifdef CONFIG_QVSP
	struct ieee80211_ie_vsp *vspie = NULL;
#endif
	uint8_t *rates = NULL;
	uint8_t *xrates = NULL;
	uint8_t *wme = NULL;
	uint8_t *htcap = NULL;
	uint8_t *htinfo = NULL;
	uint8_t *vhtcap = NULL;
	uint8_t *vhtop = NULL;
	uint8_t *bcm_vhtcap = NULL;
	uint8_t *bcm_vhtop = NULL;
	uint8_t *rsn_ie = NULL;
	uint8_t *opmode_notif_ie = NULL;
	uint8_t *obss_scan = NULL;
	uint8_t *extcap = NULL;
	uint8_t *max_idle_cap = NULL;
	void *bcmie = NULL;
	void *rtkie = NULL;
	void *rlnkie = NULL;
	int sta_pure_tkip = 0;
	uint16_t capinfo;
	uint16_t associd;
	uint16_t status;
	uint8_t qosinfo;
	uint8_t rate;
	uint8_t ridx;
	uint8_t *owedh = NULL;
	uint8_t assoc_resp_ies[IW_CUSTOM_MAX - 1];
	uint16_t assoc_resp_ie_len = 0;
	uint16_t assoc_resp_ie_offset = 0;
	struct ieee80211_mfr_entry *mfr_entry;
	struct ieee80211_ie_neighbor_report *nr_ie = NULL;

	if (vap->iv_opmode != IEEE80211_M_STA || vap->iv_state != IEEE80211_S_ASSOC) {
		if (vap->iv_state < IEEE80211_S_ASSOC) {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH |
				IEEE80211_MSG_ASSOC,
				"%s: Received %sassoc resp when not authed - send deauth\n",
				__func__,
				subtype == IEEE80211_FC0_SUBTYPE_REASSOC_RESP ?  "re" : "");
			ieee80211_send_error(ni, wh->i_addr2,
					IEEE80211_FC0_SUBTYPE_DEAUTH,
					IEEE80211_REASON_NOT_AUTHED);
		}
		vap->iv_stats.is_rx_mgtdiscard++;
		return;
	}

	mfr_entry = ieee80211_mfr_is_in_list(vap, subtype, 0, 0,
			IEEE80211_MFR_FLAG_RECV | IEEE80211_MFR_FLAG_SKB_COPY);
	if (mfr_entry)
		ieee80211_mfr_send_to_app(vap, mfr_entry, skb, rssi, 0, NULL);
#if defined(CONFIG_QTN_BSA_SUPPORT)
	else if (vap->bsa_status == IEEE80211_QRPE_STATUS_ACTIVE)
		ieee80211_bsa_probe_or_assoc_send(vap, skb,
			vap->iv_myaddr, subtype, wh->i_addr2, rssi, BSA_ACTION_NONE);
#endif

	/*
	 * asresp frame format
	 *	[2] capability information
	 *	[2] status
	 *	[2] association ID
	 *	[tlv] supported rates
	 *	[tlv] extended supported rates
	 *	[tlv] WME
	 */
	if (ieee80211_verify_length(vap, efrm - frm, 6, wh, subtype))
		return;
	ni = vap->iv_bss;

	if (subtype == IEEE80211_FC0_SUBTYPE_REASSOC_RESP)
		ieee80211_clear_frag(ni);

	capinfo = le16toh(*(__le16 *)frm);
	frm += 2;
	status = le16toh(*(__le16 *)frm);
	frm += 2;
	if (status != 0 && status != IEEE80211_STATUS_SUGGESTED_BSS_TRANS) {
		IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ASSOC,
			wh->i_addr2,
			"%sassoc failed (reason %d)",
			ISREASSOC(subtype) ?  "re" : "", status);
		vap->iv_stats.is_rx_auth_fail++;
		ieee80211_new_state(vap, IEEE80211_S_SCAN,
			IEEE80211_SCAN_FAIL_STATUS);
		ieee80211_notify_connect_failure(vap, ni->ni_macaddr, status);

		ieee80211_assoc_reject_prepare_send_event(vap, status, wh->i_addr2, NULL);
		return;
	}
	associd = le16toh(*(__le16 *)frm);
	if (!status &&
		((IEEE80211_AID(associd) == 0) || (IEEE80211_AID(associd) > IEEE80211_AID_MAX))) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
			"%s: invalid associd %u\n", __func__, IEEE80211_AID(associd));
		IEEE80211_SEND_MGMT(ni,
			IEEE80211_FC0_SUBTYPE_DISASSOC,
			IEEE80211_REASON_UNSPECIFIED);
		return;
	}
	frm += 2;

	if (vap->iv_bss)
	      sta_pure_tkip = (vap->iv_bss->ni_rsn.rsn_ucastcipher ==
			IEEE80211_CIPHER_TKIP);

	while (frm < efrm) {
		/*
		 * Do not discard frames containing proprietary Agere
		 * elements 128 and 129, as the reported element length
		 * is often wrong. Skip rest of the frame, since we can
		 * not rely on the given element length making it impossible
		 * to know where the next element starts.
		 */
		if ((*frm == IEEE80211_ELEMID_AGERE1) ||
				(*frm == IEEE80211_ELEMID_AGERE2)) {
			frm = efrm;
			continue;
		}

		if (ieee80211_verify_length(vap, efrm - frm, frm[1], wh, subtype))
			return;
		/*
		 * WAR: treat differently IEEE80211_ELEMID_RATES as some
		 * routers in UY don't respect the standard and the RATES
		 * IE is longer than it should be (length > 8)
		 */
		if (*frm != IEEE80211_ELEMID_RATES) {
			if (!ieee80211_verify_ie_len(vap, wh, subtype, frm))
				return;
		}

		switch (*frm) {
		case IEEE80211_ELEMID_RATES:
			rates = frm;
			break;
		case IEEE80211_ELEMID_HTCAP:
			htcap = frm;
			break;
		case IEEE80211_ELEMID_HTINFO:
			htinfo = frm;
			break;
		case IEEE80211_ELEMID_VHTCAP:
			vhtcap = frm;
			break;
		case IEEE80211_ELEMID_VHTOP:
			vhtop = frm;
			break;
		case IEEE80211_ELEMID_XRATES:
			xrates = frm;
			break;
		case IEEE80211_ELEMID_OPMOD_NOTIF:
			opmode_notif_ie = frm;
			break;
		case IEEE80211_ELEMID_OBSS_SCAN:
			obss_scan = frm;
			break;
		case IEEE80211_ELEMID_VENDOR:
			if (iswmeoui(frm)) {
				wme = frm;
			} else if (isqtnie(frm)) {
				qtnie = (struct ieee80211_ie_qtn *)frm;
			} else if (isbroadcomoui(frm)) {
				bcmie = frm;
				if (isbrcmvhtoui(frm)) {
					bcm_vhtcap = ieee80211_get_vhtcap_from_brcmvht(ni, frm);
					bcm_vhtop = ieee80211_get_vhtop_from_brcmvht(ni, frm);
				}
			} else if (isbroadcomoui2(frm)) {
				bcmie = frm;
			} else if (isrealtekoui(frm)) {
				rtkie = frm;
			} else if (isrlnkoui(frm)) {
				rlnkie = frm;
			} else if (isqtnpairoui(frm)) {
				if (ieee80211_verify_length(vap, efrm - frm,
						sizeof(struct ieee80211_ie_qtn_pairing),
						wh, subtype))
					return;
				qtn_pairing_ie = (struct ieee80211_ie_qtn_pairing *)frm;
#ifdef CONFIG_QVSP
			} else if (isvspie(frm)) {
				if (ieee80211_verify_length(vap, efrm - frm,
						sizeof(struct ieee80211_ie_vsp), wh, subtype))
					return;
				vspie = (struct ieee80211_ie_vsp *)frm;
			} else if (isqtnwmeie(frm)) {
				/* override standard WME IE */
				if (ieee80211_verify_length(vap, efrm - frm,
						sizeof(struct ieee80211_ie_qtn_wme), wh, subtype))
					return;
				struct ieee80211_ie_qtn_wme *qwme =
						(struct ieee80211_ie_qtn_wme *)frm;
				IEEE80211_NOTE_MAC(vap,
					IEEE80211_MSG_ASSOC | IEEE80211_MSG_WME | IEEE80211_MSG_VSP,
					wh->i_addr2, "%s: found QTN WME IE, version %u\n",
					__func__, qwme->qtn_wme_ie_version);
				wme = (uint8_t *)&qwme->qtn_wme_ie;
#endif
			} else if (ismapie(frm)) {
				assoc_resp_ie_len = *(frm + 1) + 2;
				if ((assoc_resp_ie_len + assoc_resp_ie_offset) <
						sizeof(assoc_resp_ies)) {
					memcpy(assoc_resp_ies + assoc_resp_ie_offset, frm,
					assoc_resp_ie_len);
					assoc_resp_ie_offset += assoc_resp_ie_len;
				}
			}
			break;
		case IEEE80211_ELEMID_EXTCAP:
			extcap = frm;
			if (extcap != NULL)
				ieee80211_parse_extcap(ni, extcap, wh->i_addr3);
			break;
		case IEEE80211_ELEMID_BSS_MAX_IDLE_PERIOD:
			max_idle_cap = frm;
			if (max_idle_cap != NULL)
				ieee80211_parse_bss_max_idle(ni, max_idle_cap, wh->i_addr3);
			break;
		case IEEE80211_ELEMID_RSN:
			rsn_ie = frm;
			assoc_resp_ie_len = *(frm + 1) + 2;
			if ((assoc_resp_ie_len + assoc_resp_ie_offset) < sizeof(assoc_resp_ies)) {
				memcpy(assoc_resp_ies + assoc_resp_ie_offset, rsn_ie,
					assoc_resp_ie_len);
				assoc_resp_ie_offset += assoc_resp_ie_len;
			}
			break;
		case IEEE80211_ELEMID_EXTENSION:
			owedh = ieee80211_parse_extie(frm, IEEE80211_ELEMID_EXT_DH_PARAM);
			if (owedh) {
				assoc_resp_ie_len = *(frm + 1) + 2;
				if ((assoc_resp_ie_len + assoc_resp_ie_offset) <
					sizeof(assoc_resp_ies)) {
					memcpy(assoc_resp_ies + assoc_resp_ie_offset, owedh,
						assoc_resp_ie_len);
					assoc_resp_ie_offset += assoc_resp_ie_len;
				}
			}
			break;
		case IEEE80211_ELEMID_NEIGHBOR_REP:
			nr_ie = (struct ieee80211_ie_neighbor_report *)frm;
			break;
		}
		frm += frm[1] + 2;
	}
	if (frm > efrm)
		return;

	if (status == IEEE80211_STATUS_SUGGESTED_BSS_TRANS) {
		struct ieee80211_neighbor_report_trans_item item;

		memset(&item, 0, sizeof(struct ieee80211_neighbor_report_trans_item));
		if (nr_ie) {
			memcpy(item.bssid, nr_ie->bssid, IEEE80211_ADDR_LEN);
			item.operating_class = nr_ie->operating_class;
			item.channel = nr_ie->channel;
		}
		IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ASSOC, wh->i_addr2,
					"%sassoc failed (reason %d)",
					ISREASSOC(subtype) ?  "re" : "", status);
		vap->iv_stats.is_rx_auth_fail++;
		ieee80211_new_state(vap, IEEE80211_S_SCAN,
		IEEE80211_SCAN_FAIL_STATUS);
		ieee80211_notify_connect_failure(vap, ni->ni_macaddr, status);
		ieee80211_assoc_reject_prepare_send_event(vap, status, wh->i_addr2, &item);
		return;
	}

	if (!ieee80211_ie_exists(vap, wh, subtype, rates))
		return;

	if (qtnie != NULL) {
		ni->ni_vendor = PEER_VENDOR_QTN;
	} else if (rlnkie != NULL) {
		ni->ni_vendor = PEER_VENDOR_RLNK;
	} else if (rtkie != NULL) {
		ni->ni_vendor = PEER_VENDOR_RTK;
	} else if (bcmie != NULL) {
		ni->ni_vendor = PEER_VENDOR_BRCM;
		ni->ni_qtn_flags |= QTN_IS_BCM_NODE;
	} else {
		ni->ni_vendor = PEER_VENDOR_NONE;
	}

	vhtcap = ieee80211_choose_vht(ni, vhtcap, bcm_vhtcap);
	vhtop = ieee80211_choose_vht(ni, vhtop, bcm_vhtop);

	ieee80211_input_assoc_resp_qtnie(ni, vap, qtnie);
#ifdef CONFIG_QVSP
	ieee80211_input_assoc_resp_vspie(vap, vspie, efrm);
#endif

	rate = ieee80211_setup_rates(ni, rates, xrates,
		IEEE80211_F_DOSORT |
		IEEE80211_F_DONEGO | IEEE80211_F_DODEL);
	if (rate & IEEE80211_RATE_BASIC) {
		IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ASSOC,
			wh->i_addr2,
			"%sassoc failed (rate set mismatch)",
			ISREASSOC(subtype) ?  "re" : "");
		vap->iv_stats.is_rx_assoc_norate++;
		ieee80211_new_state(vap, IEEE80211_S_SCAN,
			IEEE80211_SCAN_FAIL_STATUS);
		ieee80211_notify_connect_failure(vap, ni->ni_macaddr, IEEE80211_STATUS_BASIC_RATE);
		return;
	}

	/* check to see if need to set up ERP flag */
	if (IEEE80211_IS_CHAN_ANYG(ic->ic_bsschan) &&
		ieee80211_iserp_rateset(ic, &ni->ni_rates)) {
		IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
			"%s STA is joing an ERP AP, set the ERP flag\n", __func__);
		ni->ni_flags |= IEEE80211_NODE_ERP;
	}

	ni->ni_capinfo = capinfo;
	ni->ni_associd = associd;

	if (wme != NULL) {
		ni->ni_flags |= IEEE80211_NODE_QOS;
		if (qtnie == NULL || !ieee80211_is_repeater_feature_enabled(ic,
					QTN_REP_TWEAK_WMM_PARAMS)) {
			if (ieee80211_parse_wmeparams(vap, wme, wh, &qosinfo) >= 0)
				ieee80211_wme_updateparams(vap, 0);
		}
	} else
		ni->ni_flags &= ~IEEE80211_NODE_QOS;
	/*
	 * Configure state now that we are associated.
	 *
	 * XXX may need different/additional driver callbacks?
	 */
	if (IEEE80211_IS_CHAN_A(ic->ic_curchan) ||
	    ((ni->ni_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE) &&
	    (ic->ic_caps & IEEE80211_C_SHPREAMBLE))) {
		ic->ic_flags |= IEEE80211_F_SHPREAMBLE;
		ic->ic_flags &= ~IEEE80211_F_USEBARKER;
	} else {
		ic->ic_flags &= ~IEEE80211_F_SHPREAMBLE;
		ic->ic_flags |= IEEE80211_F_USEBARKER;
	}
	ieee80211_set_shortslottime(ic,
		IEEE80211_IS_CHAN_A(ic->ic_curchan) ||
			(ni->ni_capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME));
	/*
	 * Honor ERP protection.
	 *
	 * NB: ni_erp should zero for non-11g operation
	 *     but we check the channel characteristics
	 *     just in case.
	 */
	if (IEEE80211_BG_PROTECT_ENABLED(ic)
			&& (IEEE80211_IS_CHAN_ANYG(ic->ic_curchan)
			|| IEEE80211_IS_CHAN_11NG(ic->ic_curchan))
			&& (ni->ni_erp & IEEE80211_ERP_USE_PROTECTION)) {
		ic->ic_flags |= IEEE80211_F_USEPROT;
		/* tell Muc to use ERP cts-to-self mechanism now */
		ic->ic_set_11g_erp(vap, 1);
	} else {
		ic->ic_flags &= ~IEEE80211_F_USEPROT;
		/* tell Muc to turn off ERP now */
		ic->ic_set_11g_erp(vap, 0);
	}

	IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_ASSOC, wh->i_addr2,
		"%sassoc success: %s preamble, %s slot time ampdu density"
		" %d %s%s%s%s%s%s%s",
		ISREASSOC(subtype) ? "re" : "",
		(ic->ic_flags&IEEE80211_F_SHPREAMBLE) &&
		(ni->ni_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE) ? "short" : "long",
		ic->ic_flags&IEEE80211_F_SHSLOT ? "short" : "long",
		ni->ni_htcap.mpduspacing,
		ic->ic_flags&IEEE80211_F_USEPROT ? ", protection" : "",
		ni->ni_flags & IEEE80211_NODE_QOS ? ", QoS" : "",
		IEEE80211_ATH_CAP(vap, ni, IEEE80211_NODE_TURBOP) ?
			", turbo" : "",
		IEEE80211_ATH_CAP(vap, ni, IEEE80211_NODE_COMP) ?
			", compression" : "",
		IEEE80211_ATH_CAP(vap, ni, IEEE80211_NODE_FF) ?
			", fast-frames" : "",
		IEEE80211_ATH_CAP(vap, ni, IEEE80211_NODE_XR) ?
			", XR" : "",
		IEEE80211_ATH_CAP(vap, ni, IEEE80211_NODE_AR) ?
			", AR" : ""
	);

	/* 11n */
	/* Both Q-Station and AP should support HT */
	if ((ic->ic_curmode >= IEEE80211_MODE_11NA) && (htcap != NULL) && !sta_pure_tkip) {
		ni->ni_flags |= IEEE80211_NODE_HT;
		ieee80211_parse_htcap(ni, htcap);
		ieee80211_parse_htinfo(ni, htinfo);
		if (rlnkie && bcmie)
		{
			/* Disable beamforming for Celeno AP */
			const uint8_t unmask = ~((IEEE80211_HTCAP_B_EXP_NCOMP_STEER
						| IEEE80211_HTCAP_B_EXP_COMP_STEER) >> 8);
			ni->ni_htcap.hc_txbf[1] &= unmask;
		}
		/* keep only the rates supported by both parties */
		ridx = ieee80211_fix_ht_rate(ni, IEEE80211_F_DOFRATE |
				IEEE80211_F_DODEL | IEEE80211_F_DOXSECT);
	} else {
		/*
		 * Flush any state from a previous association.
		 */
		memset(&ni->ni_htcap, 0, sizeof(struct ieee80211_htcap));
		memset(&ni->ni_htinfo, 0, sizeof(struct ieee80211_htinfo));
		ni->ni_flags &= ~IEEE80211_NODE_HT;
	}

	/* Sanity check - make sure bridge mode advertisement is as expected */
	if (vap->iv_is_qtn_dev) {
		if (qtnie) {
			ieee80211_saveie(&ni->ni_qtn_assoc_ie, (u_int8_t *)qtnie);
			if (((qtnie->qtn_ie_flags & IEEE80211_QTN_BRIDGEMODE)
					== IEEE80211_QTN_BRIDGEMODE) !=
				((vap->iv_flags_ext & IEEE80211_FEXT_WDS) ==
					IEEE80211_FEXT_WDS)) {
				IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
					"%s: QTN IE in assoc resp is invalid, %02x/%08x\n",
					__func__, qtnie->qtn_ie_flags, vap->iv_flags_ext);
			}
			ni->ni_implicit_ba = 0;
			/* Implicit BA flags for the AP */
			if (IEEE80211_QTN_IE_GE_V2(qtnie) &&
				(ni->ni_flags & IEEE80211_NODE_HT) && !sta_pure_tkip) {
				ni->ni_implicit_ba = qtnie->qtn_ie_implicit_ba_tid;
				ni->ni_implicit_ba_valid = 1;
			}
		} else {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
				"%s: QTN IE in assoc resp is missing\n", __func__);
		}
	} else if (qtnie) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
			"%s: Unexpected QTN IE in assoc resp\n", __func__);
	}

	if (qtn_pairing_ie != NULL) {
		ieee80211_saveie(&ni->ni_qtn_pairing_ie, (u_int8_t *)qtn_pairing_ie);
	} else if (ni->ni_qtn_pairing_ie != NULL) {
		FREE(ni->ni_qtn_pairing_ie, M_DEVBUF);
		ni->ni_qtn_pairing_ie = NULL;
	}


	if (assoc_resp_ie_offset)
		ieee80211_send_assocresp_ie_event(ni, assoc_resp_ies, assoc_resp_ie_offset);

	if (obss_scan)
		ieee8011_parse_obss_scan(ni, obss_scan);

	ieee80211_input_sta_vht_set(ni, vap, vhtcap, vhtop, !sta_pure_tkip);
	ieee80211_node_ba_state_clear(ni);

	/*
	 * Apply the implicit BA parameters to the local structure.
	 * Prevents the sending of addba request to the other side of the link.
	 */
	if (ni->ni_implicit_ba_valid && (ic->ic_curmode >= IEEE80211_MODE_11NA))
		ieee80211_node_implicit_ba_setup(ni);

	if ((ic->ic_flags & IEEE80211_F_DOTH) &&
			(ic->ic_flags_ext & IEEE80211_FEXT_TPC) &&
				(ni->ni_flags & IEEE80211_NODE_TPC)) {
		if (vap->iv_local_max_txpow >= ic->ic_curchan->ic_maxpower_normal) {
			vap->iv_local_max_txpow = ic->ic_curchan->ic_maxpower_normal;
		} else if (vap->iv_local_max_txpow < ic->ic_curchan->ic_minpower_normal) {
			vap->iv_local_max_txpow = ic->ic_curchan->ic_minpower_normal;
		} else {
			ieee80211_update_tx_power(ic, vap->iv_local_max_txpow);
		}
	}

	ni->ni_vhtop_notif_mode = IEEE80211_OPMODE_NOTIFY_INVALID;
	if (opmode_notif_ie) {
		struct ieee80211_ie_vhtop_notif *ie =
				(struct ieee80211_ie_vhtop_notif *)opmode_notif_ie;
		uint8_t opmode = ieee80211_wireless_recalc_opmode(ni, ie->vhtop_notif_mode);

		ieee80211_param_to_qdrv(ni->ni_vap, IEEE80211_PARAM_NODE_OPMODE,
				opmode, ni->ni_macaddr, IEEE80211_ADDR_LEN);
		ni->ni_vhtop_notif_mode = ie->vhtop_notif_mode;
	}

	ieee80211_new_state(vap, IEEE80211_S_RUN, subtype);

	ieee80211_update_current_mode(ni);

	ieee80211_param_to_qdrv(ni->ni_vap,
		IEEE80211_PARAM_MAX_MSDU_IN_AMSDU, ni->ni_max_msdu_in_amsdu,
		ni->ni_macaddr, IEEE80211_ADDR_LEN);

	/*For STA mode, record the start time of association with AP*/
	ni->ni_start_time_assoc = get_jiffies_64();
	if (IS_IEEE80211_24G_40(ic) && ic->ic_obss_scan_enable &&
			(ni->ni_htcap.cap & IEEE80211_HTCAP_C_CHWIDTH40) &&
			(ni->ni_obss_ie.param_id)) {
		ic->ic_obss_timer.function = ieee80211_obss_scan_timer;
		mod_timer(&ic->ic_obss_timer,
				jiffies + ni->ni_obss_ie.obss_trigger_interval * HZ);
		ic->ic_obss_timer.data = (unsigned long)vap;
	}
#undef ISREASSOC
}

static void
ieee80211_recv_deauth(struct ieee80211_node *ni, struct sk_buff *skb,
	int subtype, int rssi, u_int32_t rstamp)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_frame *wh = (struct ieee80211_frame *)skb->data;
	uint8_t *frm = (u_int8_t *)&wh[1];
	uint8_t *efrm = skb->data + skb->len;
	uint16_t reason;
	int tx_notify = 1;
	int arg;
	struct ieee80211_mfr_entry *mfr_entry;

	if (vap->iv_state == IEEE80211_S_SCAN) {
		vap->iv_stats.is_rx_mgtdiscard++;
		return;
	}

	if (verify_deauth_disassoc_param_len(ni, wh, efrm - frm)) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
			"drop deauthenticate (length %ld) from %pM\n",
			efrm - frm, wh->i_addr2);
		vap->iv_stats.is_rx_mgtdiscard++;
		return;
	}

	/*
	 * deauth frame format
	 *	[2] reason
	 */
	if (ieee80211_verify_length(vap, efrm - frm, 2, wh, subtype))
		return;
	reason = le16toh(*(__le16 *)frm);
	vap->iv_stats.is_rx_deauth++;
	IEEE80211_NODE_STAT(ni, rx_deauth);

	IEEE80211_NOTE(vap, IEEE80211_MSG_AUTH, ni,
		"recv deauthenticate (reason %d) for %s", reason,
		ether_sprintf(wh->i_addr1));

	switch (vap->iv_opmode) {
	case IEEE80211_M_STA:
		arg = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

		if (!IEEE80211_ADDR_EQ(vap->iv_bss->ni_bssid, wh->i_addr2)) {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
				"drop deauthenticate (reason %d) from unknown addr %pM\n",
				reason, wh->i_addr2);
			break;
		} else if (vap->iv_block_bss) {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
				"drop deauthenticate (reason %d) from %pM, BSS blocked\n",
				reason, wh->i_addr2);
			break;
		} else if (!IEEE80211_ADDR_EQ(wh->i_addr1, vap->iv_myaddr)) {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
				"drop deauthenticate (reason %d) to unknown addr %pM\n",
				reason, wh->i_addr1);
			break;
		}

		/*
		 * Don't keep retrying the auth if we receive a deauth.
		 * Let wpa_supplicant choose the next action.
		 */
		if (!ieee80211_tdls_pend_disassociation(vap, IEEE80211_S_INIT, arg))
			ieee80211_new_state(vap, IEEE80211_S_INIT, arg);

		ic->ic_disassoc_reason_record(ic, (const char *)wh->i_addr2, reason);

		mfr_entry = ieee80211_mfr_is_in_list(vap, subtype, 0, 0,
				IEEE80211_MFR_FLAG_RECV | IEEE80211_MFR_FLAG_SKB_COPY);
		if (mfr_entry) {
			ieee80211_eventf(vap->iv_dev, "%s addr=%s reason=%u\n", "STA-DISCONNECT",
				ether_sprintf(ni->ni_macaddr), reason);
			if (!IEEE80211_ADDR_EQ(ni->ni_macaddr, vap->iv_myaddr))
				ieee80211_mfr_send_to_app(vap, mfr_entry, skb, rssi, 0, NULL);
		} else {
			ieee80211_notify_sta_disconnect(ni, reason, subtype,
				IEEE80211_QRPE_PEER_GENERATED);
		}
		ieee80211_deauth_send_event(ni->ni_vap, reason, wh->i_addr2);
		ieee80211_dot11_msg_send(ni->ni_vap, (char *)ni->ni_macaddr,
				d11_m[IEEE80211_DOT11_MSG_AP_DISCONNECTED],
				d11_c[IEEE80211_DOT11_MSG_REASON_DEAUTHENTICATED],
				reason,
				(reason < IEEE80211_REASON_CODE_MAX) ? d11_r[reason] : "Reserved",
				NULL,
				NULL);
		break;
	case IEEE80211_M_HOSTAP:
		if (!IEEE80211_ADDR_EQ(wh->i_addr1, vap->iv_bss->ni_bssid)) {
			vap->iv_stats.is_rx_mgtdiscard++;
			return;
		}
		if (ni == vap->iv_bss) {
			tx_notify = ieee80211_allow_non_assoc_sta_notify(ic);

			IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
				"Receive deauthenticate (reason %d)"
				" from unknown addr %pM\n",
				reason, wh->i_addr2);
		}

		/* Sending notification to user space application */
		if (tx_notify) {
			ic->ic_disassoc_reason_record(ic, (const char *)wh->i_addr2, reason);

			ieee80211_handle_rsn_sae_or_owe(ni, skb, rssi, wh, subtype);
			/* Message to indicate STA sent the deauth */
			ieee80211_dot11_msg_send(ni->ni_vap,
				(char *)ni->ni_macaddr,
				d11_m[IEEE80211_DOT11_MSG_CLIENT_DISCONNECTED],
				d11_c[IEEE80211_DOT11_MSG_REASON_CLIENT_SENT_DEAUTH],
				reason,
				(reason < IEEE80211_REASON_CODE_MAX) ?
					d11_r[reason] : "Reserved",
				NULL,
				NULL);

			mfr_entry = ieee80211_mfr_is_in_list(vap, subtype, 0, 0,
					IEEE80211_MFR_FLAG_RECV | IEEE80211_MFR_FLAG_SKB_COPY);
			if (mfr_entry && !IEEE80211_ADDR_EQ(ni->ni_macaddr, vap->iv_myaddr)) {
				ieee80211_mfr_send_to_app(vap, mfr_entry, skb, rssi, 0, NULL);
			}
#if defined(CONFIG_QTN_BSA_SUPPORT)
			else if (vap->bsa_status == IEEE80211_QRPE_STATUS_ACTIVE &&
					memcmp(ni->ni_macaddr, vap->iv_myaddr, ETH_ALEN)) {
				ieee80211_bsa_disconnect_event_send(vap, ni, reason,
						IEEE80211_FC0_SUBTYPE_DEAUTH,
						IEEE80211_QRPE_PEER_GENERATED);
			}
#endif
			mlme_stats_delayed_update(wh->i_addr2,
					MLME_STAT_DEAUTH, 1);
		}

		if (ni != vap->iv_bss) {
			ieee80211_nofity_sta_require_leave(ni);
			ieee80211_node_leave(ni);
		} else {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
				"Receive deauthenticate (reason %d) from unknown addr %pM\n",
				reason, wh->i_addr2);
		}
		break;
	default:
		vap->iv_stats.is_rx_mgtdiscard++;
		break;
	}
}

static void
ieee80211_recv_disassoc(struct ieee80211_node *ni, struct sk_buff *skb,
	int subtype, int rssi, u_int32_t rstamp)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_frame *wh = (struct ieee80211_frame *)skb->data;
	uint8_t *frm = (u_int8_t *)&wh[1];
	uint8_t *efrm = skb->data + skb->len;
	uint16_t reason;
	int tx_notify = 1;
	struct ieee80211_mfr_entry *mfr_entry;

	/* if a disassoc request is received in the un-auth state
	 * a deauth should be sent by the sta */
	if (vap->iv_state < IEEE80211_S_ASSOC && vap->iv_opmode == IEEE80211_M_STA) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH |
					IEEE80211_MSG_ASSOC,
				"%s: receive disassoc in state-unauthed, send deauth \n",
				__func__);
		if (IEEE80211_ADDR_EQ(vap->iv_bss->ni_bssid, wh->i_addr3))
			ieee80211_send_error(ni, wh->i_addr2,
					IEEE80211_FC0_SUBTYPE_DEAUTH,
					IEEE80211_REASON_NOT_AUTHED);
		vap->iv_stats.is_rx_mgtdiscard++;
		return;
	}

	if (vap->iv_state != IEEE80211_S_RUN &&
	    vap->iv_state != IEEE80211_S_ASSOC &&
	    vap->iv_state != IEEE80211_S_AUTH) {
		vap->iv_stats.is_rx_mgtdiscard++;
		return;
	}

	if (verify_deauth_disassoc_param_len(ni, wh, efrm - frm)) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
			"drop disassociate (length %ld) from %pM\n",
			efrm - frm, wh->i_addr2);
		vap->iv_stats.is_rx_mgtdiscard++;
		return;
	}

	/*
	 * disassoc frame format
	 *	[2] reason
	 */
	if (ieee80211_verify_length(vap, efrm - frm, 2, wh, subtype))
		return;
	reason = le16toh(*(__le16 *)frm);
	vap->iv_stats.is_rx_disassoc++;
	IEEE80211_NODE_STAT(ni, rx_disassoc);

	vap->iv_disassoc_reason = reason;

	IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
		"recv disassociate (reason %d)", reason);

	switch (vap->iv_opmode) {
	case IEEE80211_M_STA:
		if (!IEEE80211_ADDR_EQ(vap->iv_bss->ni_bssid, wh->i_addr2)) {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
				"drop disassociate (reason %d) from unknown addr %pM\n",
				reason, wh->i_addr2);
			break;
		} else if (vap->iv_block_bss) {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
				"drop disassociate (reason %d) from %pM, BSS blocked\n",
				reason, wh->i_addr2);
			break;
		} else if (!IEEE80211_ADDR_EQ(wh->i_addr1, vap->iv_myaddr)) {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
				"drop disassociate (reason %d) to unknown addr %pM\n",
				reason, wh->i_addr1);
			break;
		}

		if (!ieee80211_tdls_pend_disassociation(vap, IEEE80211_S_ASSOC, 0))
			ieee80211_new_state(vap, IEEE80211_S_ASSOC, 0);

		ic->ic_disassoc_reason_record(ic, (const char *)wh->i_addr2, reason);

		mfr_entry = ieee80211_mfr_is_in_list(vap, subtype, 0, 0,
				IEEE80211_MFR_FLAG_RECV | IEEE80211_MFR_FLAG_SKB_COPY);
		if (mfr_entry) {
			ieee80211_eventf(vap->iv_dev, "%s addr=%s reason=%u\n", "STA-DISCONNECT",
				ether_sprintf(ni->ni_macaddr), reason);
			if (!IEEE80211_ADDR_EQ(ni->ni_macaddr, vap->iv_myaddr))
				ieee80211_mfr_send_to_app(vap, mfr_entry, skb, rssi, 0, NULL);
		} else {
			ieee80211_notify_sta_disconnect(ni, reason, subtype,
				IEEE80211_QRPE_PEER_GENERATED);
		}
		ieee80211_dot11_msg_send(ni->ni_vap, (char *)ni->ni_macaddr,
				d11_m[IEEE80211_DOT11_MSG_AP_DISCONNECTED],
				d11_c[IEEE80211_DOT11_MSG_REASON_DISASSOCIATED],
				reason,
				(reason < IEEE80211_REASON_CODE_MAX) ? d11_r[reason] : "Reserved",
				NULL,
				NULL);
		break;
	case IEEE80211_M_HOSTAP:
		if (ni == vap->iv_bss) {
			tx_notify = ieee80211_allow_non_assoc_sta_notify(ic);

			IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
				"Receive disassociate (reason %d) from unknown addr %pM\n",
				reason, wh->i_addr2);
		}
		/* Sending notification to user space application */
		if (tx_notify) {
			ic->ic_disassoc_reason_record(ic, (const char *)wh->i_addr2, reason);

			mfr_entry = ieee80211_mfr_is_in_list(vap, subtype, 0, 0,
					IEEE80211_MFR_FLAG_RECV | IEEE80211_MFR_FLAG_SKB_COPY);
			if (mfr_entry) {
				if (!IEEE80211_ADDR_EQ(ni->ni_macaddr, vap->iv_myaddr)) {
					ieee80211_mfr_send_to_app(vap, mfr_entry, skb, rssi, 0, NULL);
				}
			}
#if defined(CONFIG_QTN_BSA_SUPPORT)
			else if(vap->bsa_status == IEEE80211_QRPE_STATUS_ACTIVE &&
					memcmp(ni->ni_macaddr, vap->iv_myaddr, ETH_ALEN)) {
				ieee80211_bsa_disconnect_event_send(vap, ni, reason,
						IEEE80211_FC0_SUBTYPE_DISASSOC,
						IEEE80211_QRPE_PEER_GENERATED);
			}
#endif

			ieee80211_handle_rsn_sae_or_owe(ni, skb, rssi, wh, subtype);
			ieee80211_dot11_msg_send(ni->ni_vap, (char *)wh->i_addr2,
				d11_m[IEEE80211_DOT11_MSG_CLIENT_DISCONNECTED],
				d11_c[IEEE80211_DOT11_MSG_REASON_CLIENT_SENT_DISASSOC],
				reason,
				(reason < IEEE80211_REASON_CODE_MAX) ?
					d11_r[reason] : "Reserved",
				NULL,
				NULL);

			mlme_stats_delayed_update(wh->i_addr2,
						MLME_STAT_DIASSOC, 1);
		}
		if (ni != vap->iv_bss) {
			ieee80211_nofity_sta_require_leave(ni);
			ieee80211_node_leave(ni);
		} else {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
					"Receive disassociate (reason %d) from "
					"unknown addr %pM",
					reason, wh->i_addr2);
		}
		break;
	default:
		vap->iv_stats.is_rx_mgtdiscard++;
		break;
	}
}

static void
ieee80211_recv_action_spec_mgmt(struct ieee80211_node *ni,
	struct sk_buff *skb, int subtype, struct ieee80211_action *ia, int rssi)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_frame *wh = (struct ieee80211_frame *)skb->data;
	uint8_t *frm = (u_int8_t *)&wh[1];
	uint8_t *efrm = skb->data + skb->len;

	switch (ia->ia_action) {
	case IEEE80211_ACTION_S_CHANSWITCHANN:
	{
		uint8_t *csa_tsf_ie = NULL;
		uint8_t *csa_wider_bw_ie = NULL;
		uint8_t *csa_sec_chan_offset = NULL;
		uint8_t *opt_ie = NULL;
		int return_val = 0;
		int cur_bw;

		if ((efrm - frm) >= (sizeof(struct ieee80211_action) +
				sizeof(struct ieee80211_ie_csa) +
				sizeof(struct ieee80211_ie_qtn_csa_tsf))) {
			csa_tsf_ie = frm + sizeof(struct ieee80211_action) +
					sizeof(struct ieee80211_ie_csa);
		}

		opt_ie = frm + sizeof(struct ieee80211_action) + sizeof(struct ieee80211_ie_csa);
		while (opt_ie < efrm) {
			if ((opt_ie[0] == IEEE80211_ELEMID_WBWCHANSWITCH) &&
					(opt_ie[1] == sizeof(struct ieee80211_ie_wbchansw) - 2)) {
				csa_wider_bw_ie = opt_ie;
			}
			if ((opt_ie[0] == IEEE80211_ELEMID_SEC_CHAN_OFF) &&
					(opt_ie[1] == sizeof(struct ieee80211_ie_sec_chan_off) - 2)) {
				csa_sec_chan_offset = opt_ie;
			}
			opt_ie += opt_ie[1] + 2;
		}

		return_val = ieee80211_parse_csaie(ni, wh,
			frm + sizeof(struct ieee80211_action), csa_tsf_ie, csa_wider_bw_ie, csa_sec_chan_offset);

		if ((vap->iv_opmode == IEEE80211_M_STA) &&
			(return_val == QTN_CSAIE_ERR_CHAN_NOT_SUPP)) {
			ieee80211_param_from_qdrv(ni->ni_vap, IEEE80211_PARAM_BW_SEL_MUC,
							&cur_bw, NULL, 0);

			if (ieee80211_narrower_bw_supported(ni,
					frm + sizeof(struct ieee80211_action), cur_bw)) {
				/* reassociate */
				ieee80211_new_state(vap, IEEE80211_S_ASSOC, 0);
				return;
			} else if (!ieee80211_handle_csa_invalid_channel(ni, wh)) {
				return;
			}
		}
		break;
	}
	case IEEE80211_ACTION_S_TPC_REQUEST:
	{
		struct ieee80211_action_tpc_report tpc_report;
		struct ieee80211_action_data action_data;

		if ((ic->ic_flags & IEEE80211_F_DOTH) &&
				(ic->ic_flags_ext & IEEE80211_FEXT_TPC)) {
			frm = frm + sizeof(struct ieee80211_action);
			tpc_report.rx_token = *frm++;
			if (*frm == IEEE80211_ELEMID_TPCREQ) {
				tpc_report.tx_power = ic->ic_get_local_txpow(ic);
				ic->ic_get_local_link_margin(ni, &tpc_report.link_margin);
				action_data.cat = IEEE80211_ACTION_CAT_SPEC_MGMT;
				action_data.action = IEEE80211_ACTION_S_TPC_REPORT;
				action_data.params = &tpc_report;
				IEEE80211_SEND_MGMT(ni, IEEE80211_FC0_SUBTYPE_ACTION,
						(int)&action_data);
			} else {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
						wh, "mgt", "%s", "Missing TPC REQUEST Element"
						" in TPC Request action frame\n");
				vap->iv_stats.is_rx_elem_missing++;
			}
		} else {
			TPC_DBG(vap, "TPC Request: frame not supported, drop it\n");
			vap->iv_stats.is_rx_mgtdiscard++;
		}

		break;
	}
	case IEEE80211_ACTION_S_TPC_REPORT:
	{
		uint8_t tpc_report_token;
		if ((ic->ic_flags & IEEE80211_F_DOTH) &&
				(ic->ic_flags_ext & IEEE80211_FEXT_TPC)) {
			frm = frm + sizeof(struct ieee80211_action);
			tpc_report_token = *frm++;
			if (ieee80211_verify_length(vap, efrm - frm, 4, wh, subtype))
				return;
			if ((frm[0] == IEEE80211_ELEMID_TPCREP) && (frm[1] == 2)) {
				frm += 2;
				ni->ni_tpc_info.tpc_report.node_txpow = *frm++;
				ni->ni_tpc_info.tpc_report.node_link_margin = *frm++;

				ieee80211_ppqueue_remove_with_response(&ni->ni_vap->iv_ppqueue,
						ni,
						IEEE80211_ACTION_CAT_SPEC_MGMT,
						IEEE80211_ACTION_S_TPC_REPORT,
						tpc_report_token);
			} else {
				IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
						wh, "mgt", "%s", "Missing TPC REPORT Element"
						" in TPC Report action frame\n");
				vap->iv_stats.is_rx_elem_missing++;
			}
		} else {
			TPC_DBG(vap, "TPC Report: frame not supported, drop it\n");
			vap->iv_stats.is_rx_mgtdiscard++;
		}
		break;
	}
	case IEEE80211_ACTION_S_MEASUREMENT_REPORT:
	case IEEE80211_ACTION_S_MEASUREMENT_REQUEST:
		ieee80211_recv_action_measure_11h(ni, ia, wh, efrm);
		break;
	default:
		vap->iv_stats.is_rx_mgtdiscard++;
	}
}

void
ieee80211_recv_action(struct ieee80211_node *ni, struct sk_buff *skb,
	int subtype, int rssi, u_int32_t rstamp)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_frame *wh = (struct ieee80211_frame *)skb->data;
	uint8_t *frm = (u_int8_t *)&wh[1];
	uint8_t *efrm = skb->data + skb->len;
	struct ieee80211_action *ia;
	struct ieee80211_mfr_entry *mfr_entry;

	if (ieee80211_verify_length(vap, efrm - frm, sizeof(struct ieee80211_action),
			wh, subtype))
		return;
	ia = (struct ieee80211_action *) (void*)frm;

	if (vap->iv_state != IEEE80211_S_RUN &&
			vap->iv_state != IEEE80211_S_ASSOC &&
			vap->iv_state != IEEE80211_S_AUTH &&
			!(ic->ic_flags_qtn & IEEE80211_QTN_MONITOR) &&
			(ia->ia_category != IEEE80211_ACTION_CAT_PUBLIC)) {
		vap->iv_stats.is_rx_mgtdiscard++;
		return;
	}
	if (vap->iv_opmode == IEEE80211_M_HOSTAP && ni == vap->iv_bss &&
		!(IEEE80211_IS_MULTICAST(wh->i_addr1)) &&
		(ia->ia_category != IEEE80211_ACTION_CAT_PUBLIC)) {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
					wh, "mgt", "%s", "src same as bss");
		if (vap->iv_state == IEEE80211_S_RUN)
			ieee80211_send_error(ni, wh->i_addr2,
					IEEE80211_FC0_SUBTYPE_DEAUTH,
					IEEE80211_REASON_NOT_AUTHED);
		vap->iv_stats.is_rx_notassoc++;
		return;
	}

	memcpy(&ni->ni_action, ia, sizeof(struct ieee80211_action));

	vap->iv_stats.is_rx_action++;
	IEEE80211_NODE_STAT(ni, rx_action);

	mfr_entry = ieee80211_mfr_is_in_list(vap, subtype, ia->ia_category, ia->ia_action,
			IEEE80211_MFR_FLAG_RECV | IEEE80211_MFR_FLAG_BYPASS);
	if (mfr_entry) {
		ieee80211_mfr_send_to_app(vap, mfr_entry, skb, rssi, 0, NULL);
		/*
		 * SONiQ will register Radio Measrement Reports, but SCS in driver needs such
		 * frame either,so do not return here,let driver continue process it.And also
		 * driver will not send response frame, so there will be no effect on SONiQ.
		 */
		if (!(ia->ia_category == IEEE80211_ACTION_CAT_RM &&
				ia->ia_action == IEEE80211_ACTION_R_MEASUREMENT_REPORT))
			return;
	}

	switch (ia->ia_category) {
	case IEEE80211_ACTION_CAT_PUBLIC:
		ieee80211_recv_action_public(ni, skb, wh, ia, rssi);
		break;
	case IEEE80211_ACTION_CAT_TDLS:
		IEEE80211_TDLS_DPRINTF(vap, IEEE80211_MSG_TDLS, IEEE80211_TDLS_MSG_WARN,
			"TDLS %s: Ignoring TDLS MGMT frame\n", __func__);
		IEEE80211_DISCARD(vap, IEEE80211_MSG_ANY,
				wh, "mgt", "%s frame not allowed", "TDLS Action");
		vap->iv_stats.is_rx_mgtdiscard++;
		break;
	case IEEE80211_ACTION_CAT_SPEC_MGMT:
		ieee80211_recv_action_spec_mgmt(ni, skb, subtype, ia, rssi);
		break;
	case IEEE80211_ACTION_CAT_QOS:
		vap->iv_stats.is_rx_mgtdiscard++;
		break;
	case IEEE80211_ACTION_CAT_HT:
		ieee80211_action_ht(ni, skb, wh, subtype, ia, frm, efrm);
		break;
	case IEEE80211_ACTION_CAT_BA:
		ieee80211_action_ba(ni, wh, subtype, ia, frm, efrm);
		break;
	case IEEE80211_ACTION_CAT_RM:
		ieee80211_recv_action_11k(ni, ia, wh, efrm);
		break;
	case IEEE80211_ACTION_CAT_VENDOR: {
		struct qdrv_vendor_action_header *va;
		if (ieee80211_verify_length(vap, efrm - frm,
				sizeof(struct qdrv_vendor_action_header), wh, subtype))
			return;
		va = (struct qdrv_vendor_action_header *) (void*)frm;
#ifdef CONFIG_QHOP
		if (va->type == QDRV_ACTION_TYPE_QHOP) {
			if (va->action == QDRV_ACTION_QHOP_DFS_REPORT) {
				if (IEEE80211_VAP_WDS_IS_MBS(vap))
					ic->ic_radar_detected(ic, 0);
			}
		}
#endif
#ifdef CONFIG_QVSP
		if (va->type != QDRV_ACTION_TYPE_QHOP) {
			ieee80211_recv_action_vsp(ni, frm, efrm);
		}
#endif
		break;
	}
	case IEEE80211_ACTION_CAT_SA_QUERY:
		ieee80211_recv_action_sa_query(ni, ia, wh, efrm);
		break;
	case IEEE80211_ACTION_CAT_VHT:
		ieee80211_recv_action_vht(ni, ia, subtype, wh, frm, efrm);
		break;
	case IEEE80211_ACTION_CAT_WNM:
#ifdef ARTSMNG_SUPPORT
	case IEEE80211_ACTION_CAT_WNM | IEEE80211_ACTION_CAT_ERR_MASK:
#endif
		ieee80211_recv_action_wnm(ni, ia, subtype, wh, frm, efrm);
		break;
	default:
		vap->iv_stats.is_rx_mgtdiscard++;
		break;
	}
}

/*
 * Context: SoftIRQ
 */
void
ieee80211_recv_mgmt(struct ieee80211_node *ni, struct sk_buff *skb,
	int subtype, int rssi, u_int32_t rstamp)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211_frame *wh = (struct ieee80211_frame *)skb->data;

#ifdef ARTSMNG_SUPPORT
	struct ieee80211com *ic = vap->iv_ic;

	/*
	 * FIXME: add PMF check
	 * Remove WDS link if related node acts as STA AND destined to us
	 * to ensure it can connect as a STA
	 */
	if ((vap->iv_opmode == IEEE80211_M_WDS) && (ni != vap->iv_bss) &&
			(!compare_ether_addr(wh->i_addr1, ic->ic_myaddr))) {
		struct ieee80211_node_table *nt = &ic->ic_sta;
		struct ieee80211_node *temp_ni;

		if (subtype == IEEE80211_FC0_SUBTYPE_AUTH ||
		    subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ ||
		    subtype == IEEE80211_FC0_SUBTYPE_REASSOC_REQ) {
			temp_ni = ieee80211_find_node(nt, wh->i_addr2);
			if (temp_ni) {
				printk_ratelimited("[%pM] Removing WDS link subtype=0x%02X\n",
					temp_ni->ni_macaddr, subtype);
				ieee80211_node_leave(ni);
				ieee80211_free_node(temp_ni);
			}
			vap->iv_stats.is_rx_mgtdiscard++;
			return;
		}
	}
#endif /* ARTSMNG_SUPPORT */

	/* forward management frame to application */
	if (vap->iv_opmode != IEEE80211_M_MONITOR)
		forward_mgmt_to_app(vap, subtype, skb, wh, rssi);

	switch (subtype) {
	case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
	case IEEE80211_FC0_SUBTYPE_BEACON:
		ieee80211_recv_beacon(ni, skb, subtype, rssi, rstamp);
		break;
	case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
		ieee80211_recv_probe_req(ni, skb, subtype, rssi, rstamp);
		break;
	case IEEE80211_FC0_SUBTYPE_AUTH:
		ieee80211_recv_auth(ni, skb, subtype, rssi, rstamp);
		break;
	case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
	case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
		ieee80211_recv_assoc_req(ni, skb, subtype, rssi, rstamp);
		break;
	case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
	case IEEE80211_FC0_SUBTYPE_REASSOC_RESP:
		ieee80211_recv_assoc_resp(ni, skb, subtype, rssi, rstamp);
		break;
	case IEEE80211_FC0_SUBTYPE_DEAUTH:
		ieee80211_recv_deauth(ni, skb, subtype, rssi, rstamp);
		break;
	case IEEE80211_FC0_SUBTYPE_DISASSOC:
		ieee80211_recv_disassoc(ni, skb, subtype, rssi, rstamp);
		break;
	case IEEE80211_FC0_SUBTYPE_ACTION:
		ieee80211_recv_action(ni, skb, subtype, rssi, rstamp);
		break;
	default:
		IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
			wh, "mgt", "subtype 0x%x not handled", subtype);
		vap->iv_stats.is_rx_badsubtype++;
		break;
	}
}

/*
 * Process a received ps-poll frame.
 */
static void
ieee80211_recv_pspoll(struct ieee80211_node *ni, struct sk_buff *skb0)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211_frame_min *wh;
	struct sk_buff *skb;
	u_int16_t aid;
	int qlen;

	wh = (struct ieee80211_frame_min *)skb0->data;
	if (ni->ni_associd == 0) {
		IEEE80211_DISCARD(vap,
			IEEE80211_MSG_POWER | IEEE80211_MSG_DEBUG,
			(struct ieee80211_frame *) wh, "ps-poll",
			"%s", "unassociated station");
		vap->iv_stats.is_ps_unassoc++;
		IEEE80211_SEND_MGMT(ni, IEEE80211_FC0_SUBTYPE_DEAUTH,
			IEEE80211_REASON_NOT_ASSOCED);
		return;
	}

	aid = le16toh(*(__le16 *)wh->i_dur);
	if (aid != ni->ni_associd) {
		IEEE80211_DISCARD(vap,
			IEEE80211_MSG_POWER | IEEE80211_MSG_DEBUG,
			(struct ieee80211_frame *) wh, "ps-poll",
			"aid mismatch: sta aid 0x%x poll aid 0x%x",
			ni->ni_associd, aid);
		vap->iv_stats.is_ps_badaid++;
		IEEE80211_SEND_MGMT(ni, IEEE80211_FC0_SUBTYPE_DEAUTH,
			IEEE80211_REASON_NOT_ASSOCED);
		return;
	}

	/* Okay, take the first queued packet and put it out... */
	IEEE80211_NODE_SAVEQ_LOCK(ni);
	IEEE80211_NODE_SAVEQ_DEQUEUE(ni, skb, qlen);
	IEEE80211_NODE_SAVEQ_UNLOCK(ni);
	if (skb == NULL) {
		IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_POWER, wh->i_addr2,
			"%s", "recv ps-poll, but queue empty");
		ieee80211_ref_node(ni);
		ieee80211_send_nulldata(ni);
		vap->iv_stats.is_ps_qempty++;	/* XXX node stat */
		if (vap->iv_set_tim != NULL)
			vap->iv_set_tim(ni, 0);		/* just in case */
		return;
	}
	/*
	 * If there are more packets, set the more packets bit
	 * in the packet dispatched to the station; otherwise
	 * turn off the TIM bit.
	 */
	if (qlen != 0) {
		IEEE80211_NOTE(vap, IEEE80211_MSG_POWER, ni,
			"recv ps-poll, send packet, %u still queued", qlen);
		/*
		 * NB: More-data bit will be set during encap.
		 */
	} else {
		IEEE80211_NOTE(vap, IEEE80211_MSG_POWER, ni,
			"%s", "recv ps-poll, send packet, queue empty");
		if (vap->iv_set_tim != NULL)
			vap->iv_set_tim(ni, 0);
	}
	M_PWR_SAV_SET(skb);		/* ensure MORE_DATA bit is set correctly */

	ieee80211_parent_queue_xmit(skb);	/* Submit to parent device, including updating stats */
}

#ifdef USE_HEADERLEN_RESV
/*
 * The kernel version of this function alters the skb in a manner
 * inconsistent with dev->hard_header_len header reservation. This
 * is a rewrite of the portion of eth_type_trans() that we need.
 */
static __be16
ath_eth_type_trans(struct sk_buff *skb, struct net_device *dev)
{
	struct ethhdr *eth;

	skb_reset_mac_header(skb);
	skb_pull(skb, ETH_HLEN);
	/*
	 * NB: mac.ethernet is replaced in 2.6.9 by eth_hdr but
	 *     since that's an inline and not a define there's
	 *     no easy way to do this cleanly.
	 */
	eth = (struct ethhdr *)skb_mac_header(skb);

	if (*eth->h_dest & 1)
		if (memcmp(eth->h_dest, dev->broadcast, ETH_ALEN) == 0)
			skb->pkt_type = PACKET_BROADCAST;
		else
			skb->pkt_type = PACKET_MULTICAST;
	else
		if (memcmp(eth->h_dest, dev->dev_addr, ETH_ALEN))
			skb->pkt_type = PACKET_OTHERHOST;

	return eth->h_proto;
}
#endif

#ifdef IEEE80211_DEBUG
/*
 * Debugging support.
 */

/*
 * Return the bssid of a frame.
 */
static const u_int8_t *
ieee80211_getbssid(struct ieee80211vap *vap, const struct ieee80211_frame *wh)
{
	if (vap->iv_opmode == IEEE80211_M_STA)
		return wh->i_addr2;
	if ((wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) != IEEE80211_FC1_DIR_NODS)
		return wh->i_addr1;
	if ((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) == IEEE80211_FC0_SUBTYPE_PS_POLL)
		return wh->i_addr1;
	return wh->i_addr3;
}

/* used for send formatted string custom event IWEVCUSTOM */
int ieee80211_eventf(struct net_device *dev, const char *fmt, ...)
{
	va_list args;
	int i;
	union iwreq_data wreq;
	char buffer[IW_CUSTOM_MAX];

	if (dev == NULL || dev_net(dev) == NULL)
		return 0;

	/* Format the custom wireless event */
	memset(&wreq, 0, sizeof(wreq));

	va_start(args, fmt);
	i = vsnprintf(buffer, IW_CUSTOM_MAX, fmt, args);
	va_end(args);

	wreq.data.length = strnlen(buffer, IW_CUSTOM_MAX);
	wireless_send_event(dev, IWEVCUSTOM, &wreq, buffer);
	return i;
}
EXPORT_SYMBOL(ieee80211_eventf);

#if defined(CONFIG_QTN_BSA_SUPPORT)
void ieee80211_build_qrpe_event_head(struct ieee80211vap *vap, struct ieee80211_qrpe_event_data *head,
	uint16_t event_id, uint16_t len)
{
	strncpy(head->name, IEEE80211_QRPE_EVENT_GROUP_NAME, sizeof(head->name));
	head->event_id = event_id;

	memcpy(head->bssid, vap->iv_myaddr, IEEE80211_ADDR_LEN);
	head->len = len;
}
EXPORT_SYMBOL(ieee80211_build_qrpe_event_head);

int ieee80211_send_qrpe_event(unsigned int group, uint8_t *event, int len)
{
	return bsa_send_genl_multicast_event(group, event, len);
}
EXPORT_SYMBOL(ieee80211_send_qrpe_event);
#endif

void
ieee80211_note(struct ieee80211vap *vap, const char *fmt, ...)
{
	char buf[128];		/* XXX */
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	printk("%s: %s", vap->iv_dev->name, buf);	/* NB: no \n */
}
EXPORT_SYMBOL(ieee80211_note);

void
ieee80211_note_frame(struct ieee80211vap *vap, const struct ieee80211_frame *wh,
	const char *fmt, ...)
{
	char buf[128];		/* XXX */
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	printk("%s: [%s] %s\n", vap->iv_dev->name,
		ether_sprintf(ieee80211_getbssid(vap, wh)), buf);
}
EXPORT_SYMBOL(ieee80211_note_frame);

void
ieee80211_note_mac(struct ieee80211vap *vap, const u_int8_t mac[IEEE80211_ADDR_LEN],
	const char *fmt, ...)
{
	char buf[128];		/* XXX */
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	printk("%s: [%s] %s\n", vap->iv_dev->name, ether_sprintf(mac), buf);
}
EXPORT_SYMBOL(ieee80211_note_mac);

static void
ieee80211_discard_frame(struct ieee80211vap *vap, const struct ieee80211_frame *wh,
	const char *type, const char *fmt, ...)
{
	char buf[128];		/* XXX */
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (type != NULL)
		printk("[%s:%s] discard %s frame, %s\n", vap->iv_dev->name,
			ether_sprintf(ieee80211_getbssid(vap, wh)), type, buf);
	else
		printk("[%s:%s] discard frame, %s\n", vap->iv_dev->name,
			ether_sprintf(ieee80211_getbssid(vap, wh)), buf);
}

static void
ieee80211_discard_ie(struct ieee80211vap *vap, const struct ieee80211_frame *wh,
	const char *type, const char *fmt, ...)
{
	char buf[128];		/* XXX */
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (type != NULL)
		printk("[%s:%s] discard %s information element, %s\n",
			vap->iv_dev->name,
			ether_sprintf(ieee80211_getbssid(vap, wh)), type, buf);
	else
		printk("[%s:%s] discard information element, %s\n",
			vap->iv_dev->name,
			ether_sprintf(ieee80211_getbssid(vap, wh)), buf);
}

static void
ieee80211_discard_mac(struct ieee80211vap *vap, const u_int8_t mac[IEEE80211_ADDR_LEN],
	const char *type, const char *fmt, ...)
{
	char buf[128];		/* XXX */
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (type != NULL)
		printk("[%s:%s] discard %s frame, %s\n", vap->iv_dev->name,
			ether_sprintf(mac), type, buf);
	else
		printk("[%s:%s] discard frame, %s\n", vap->iv_dev->name,
			ether_sprintf(mac), buf);
}
#endif /* IEEE80211_DEBUG */

static void ieee80211_process_vht_opmode_notif(struct ieee80211_node *ni, u_int8_t *frm)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = ni->ni_ic;
	struct ieee80211_action_vht_opmode_notification *opmode_notif = (void *)frm;
	int bss_bw;
	uint8_t opmode_chw;
	uint8_t opmode;

	if (ni->ni_vhtop_notif_mode == opmode_notif->am_opmode)
		return;

	opmode_chw = MS(opmode_notif->am_opmode, IEEE80211_VHT_OPMODE_CHWIDTH);
	if (ieee80211_cwm_to_bw(opmode_chw) > ic->ic_max_system_bw)
		return;

	if ((vap->iv_opmode == IEEE80211_M_STA) &&
		IEEE80211_ADDR_EQ(ni->ni_macaddr, vap->iv_bss->ni_bssid)) {
		ieee80211_param_from_qdrv(ni->ni_vap, IEEE80211_PARAM_BSS_BW, &bss_bw, NULL, 0);
		if (opmode_chw != bss_bw)
			ieee80211_param_to_qdrv(ni->ni_vap, IEEE80211_PARAM_BSS_BW, opmode_chw, NULL, 0);
	}

	opmode = ieee80211_wireless_recalc_opmode(ni, opmode_notif->am_opmode);
	ieee80211_param_to_qdrv(ni->ni_vap, IEEE80211_PARAM_NODE_OPMODE,
				opmode, ni->ni_macaddr, IEEE80211_ADDR_LEN);

	ni->ni_vhtop_notif_mode = opmode_notif->am_opmode;
}

static void ieee80211_recv_action_vht(struct ieee80211_node *ni,
				      struct ieee80211_action *ia,
				      int subtype,
				      struct ieee80211_frame *wh,
				      u_int8_t *frm,
				      u_int8_t *efrm)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211_vht_mu_grp *mu_grp;
	struct ieee80211com *ic = ni->ni_ic;

	switch (ia->ia_action) {
	case IEEE80211_ACTION_VHT_CBEAMFORMING:
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION,
				  "VHT: Not handling compressed beamforming frame \
					from station %pM\n", ni->ni_macaddr);
		vap->iv_stats.is_rx_mgtdiscard++;
		break;
	case IEEE80211_ACTION_VHT_OPMODE_NOTIFICATION:
		if (ieee80211_verify_length(vap, efrm - frm,
					sizeof(struct ieee80211_action_vht_opmode_notification),
					wh, subtype))
			return;

		ieee80211_process_vht_opmode_notif(ni, frm);
		break;
	case IEEE80211_ACTION_VHT_MU_GRP_ID:
		if ((vap->iv_opmode == IEEE80211_M_STA) &&
				ieee80211_swfeat_is_supported(SWFEAT_ID_MU_MIMO, 0)) {
			/* AP sends me my MU group and position arrays, push it down to Muc/HW */
			mu_grp = (struct ieee80211_vht_mu_grp *)(ia + 1);
			memcpy(&vap->iv_bss->ni_mu_grp, mu_grp, sizeof(struct ieee80211_vht_mu_grp));
			ic->ic_setparam(ni, IEEE80211_PARAM_UPDATE_MU_GRP, 1,
				(unsigned char *)&vap->iv_bss->ni_mu_grp,
				sizeof(struct ieee80211_vht_mu_grp));
		}
		break;
	default:
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION,
				  "VHT: Invalid action frame(%d) from station %pM\n",
				  ia->ia_action, ni->ni_macaddr);
		vap->iv_stats.is_rx_mgtdiscard++;
		break;
	}
}

#if defined(CONFIG_QTN_BSA_SUPPORT)
uint32_t ieee80211_wlan_vht_mcs_streams(uint16_t mcsmap)
{
	uint32_t nss = 8;

	while ((nss > 0) && ((mcsmap & BSA_VHT_MCSMAP_MASK) == BSA_VHT_MCSMAP_NOT_SUPPORT)) {
		nss--;
		mcsmap <<= 2;
	};
	return nss;
}

uint32_t ieee80211_wlan_vht_rxstreams(struct ieee80211_ie_vhtcap *vhtcap)
{
	uint16_t mcsmap = (u_int16_t)IEEE80211_VHTCAP_GET_RX_MCS_NSS(vhtcap);

	return ieee80211_wlan_vht_mcs_streams(mcsmap);
}
EXPORT_SYMBOL(ieee80211_wlan_vht_rxstreams);

uint32_t ieee80211_wlan_vht_rx_maxrate(struct ieee80211_ie_vhtcap *vhtcap)
{
	int chan_mode = 0;
	uint32_t max = 0;
	uint8_t sgi = 0;
	int k;
	int r;
	uint16_t mask = BSA_VHT_MCSMAP_MASK;

	if (vhtcap) {
		u_int16_t mcsmap = 0;
		r = 0;
		/* 80+80 or 160 Mhz */
		if (IEEE80211_VHTCAP_GET_CHANWIDTH(vhtcap)) {
			chan_mode = 1;
			sgi = IEEE80211_VHTCAP_GET_SGI_160MHZ(vhtcap);
		} else {
			sgi = IEEE80211_VHTCAP_GET_SGI_80MHZ(vhtcap);
		}
		mcsmap = (u_int16_t)IEEE80211_VHTCAP_GET_RX_MCS_NSS(vhtcap);
		for (k = 8; k > 0; k--) {
			if ((mcsmap & mask) != mask) {
				int rate = 0;
				int val = ((mcsmap & mask) >> ((k-1) * 2));
				r = (val == 2) ? 9: (val == 1) ? 8 : 7;
				rate = ieee80211_mcs2rate(r, chan_mode, sgi, 1);
				if (rate >= 0) {
					rate = (rate / 2) * k;
					if (max < rate)
						max = rate;
					break;
				}
			}
			mask = mask >> 2;
		}
	}
		return max;
}
EXPORT_SYMBOL(ieee80211_wlan_vht_rx_maxrate);

uint32_t ieee80211_wlan_ht_rx_maxrate(struct ieee80211_ie_htcap *htcap, uint32_t *rx_ss)
{
	int chan_mode = 0, j;
	uint32_t max = 0;
	uint8_t sgi = 0;
	int k;
	int r;
	u_int16_t mask;

	if (htcap) {
		r = 0;
		if (htcap->hc_cap[0] & IEEE80211_HTCAP_C_CHWIDTH40) {
			chan_mode = 1;
			sgi = htcap->hc_cap[0] & IEEE80211_HTCAP_C_SHORTGI40 ? 1 : 0;
		} else {
			sgi = htcap->hc_cap[0] & IEEE80211_HTCAP_C_SHORTGI20 ? 1 : 0;
		}
		for (j = IEEE80211_HT_MCSSET_20_40_NSS1; j <= IEEE80211_HT_MCSSET_20_40_NSS4; j++) {
			mask = 1;
			for (k = 0; k < 8; k++, r++) {
				if (htcap->hc_mcsset[j] & mask) {
					/* Copy HT rates */
					int rate = ieee80211_mcs2rate(r, chan_mode, sgi, 0) / 2;
					if (rate >= 0 && max < rate)
						max = rate;
					*rx_ss = j+1;
				}
				mask = mask << 1;
			}
		}
	}
	return max;
}
EXPORT_SYMBOL(ieee80211_wlan_ht_rx_maxrate);

static uint32_t ieee80211_bsa_build_frame_cookie(struct ieee80211_qrpe_frame_cookie *cookie,
					struct sk_buff *skb, int filtered, int probe_wild_ssid,
					int append_payload)
{
	uint32_t ret_len = sizeof(*cookie);
	if (filtered)
		cookie->flags |= IEEE80211_QRPE_COOKIE_WITHHELD;
	else
		cookie->flags &= ~IEEE80211_QRPE_COOKIE_WITHHELD;

	if (probe_wild_ssid)
		cookie->flags |= IEEE80211_QRPE_COOKIE_PROBE_WILD_SSID;
	else
		cookie->flags &= ~IEEE80211_QRPE_COOKIE_PROBE_WILD_SSID;

	if (append_payload && (skb != NULL)) {
		cookie->flags &= ~IEEE80211_QRPE_COOKIE_NO_PAYLOAD;
		memcpy(cookie->frm, skb->data, skb->len);
		ret_len += skb->len;
	} else
		cookie->flags |= IEEE80211_QRPE_COOKIE_NO_PAYLOAD;

	return ret_len;
}

int ieee80211_bsa_probe_or_assoc_send(struct ieee80211vap *vap, struct sk_buff *skb, uint8_t *bssid,
		int subtype, uint8_t *sta_mac, int rssi, int filtered)
{
	struct ieee80211_frame *wh;
	uint8_t *frm;
	uint8_t *efrm;
	uint8_t *htcap = NULL;
	uint8_t *htinfo = NULL;
	uint8_t *vhtcap = NULL;
	uint8_t *vhtop = NULL;
	uint8_t chan=0;
	struct ieee80211_ie_htcap *htcap_ie = NULL;
	struct ieee80211_ie_vhtcap *vhtcap_ie = NULL;
	uint8_t *extcap = NULL;
	struct ieee80211_qrpe_event_data *p_data;
	struct ieee80211_qrpe_event_probe_req *pevent;
	uint32_t max_ht_phy_rate = 54;
	uint32_t max_vht_phy_rate = 0;
	uint32_t max_ht_ss = 1;
	uint32_t max_vht_ss = 0;
	struct ieee80211com *ic;
	uint16_t bandwidth = 1;
	int ret = 0;
	struct ieee80211_qrpe_frame_cookie *cookie;
	int len;
	uint8_t *event_data;
	uint16_t event_id = IEEE80211_QRPE_EVENT_PROBE_REQ;
	unsigned int group_id = BSA_MCGRP_DRV_EVENT;
	uint8_t *ssid = NULL;
	struct ieee80211_ie_ssid *ssid_ie = NULL;
	int probe_wild_ssid = 0;
	int append_payload = 0;

	if (subtype != IEEE80211_FC0_SUBTYPE_PROBE_REQ
		&& subtype != IEEE80211_FC0_SUBTYPE_ASSOC_REQ
		&& subtype != IEEE80211_FC0_SUBTYPE_REASSOC_REQ
		&& subtype != IEEE80211_FC0_SUBTYPE_ASSOC_RESP
		&& subtype != IEEE80211_FC0_SUBTYPE_REASSOC_RESP)
		return -1;

	len = sizeof(*p_data) + sizeof(*pevent) + sizeof(*cookie);
	/*
	 * Never append the payload for PROBE_REQ, otherwise the netlink
	 * buffer is easy to be overflow in noise environment.
	 */
	if (subtype != IEEE80211_FC0_SUBTYPE_PROBE_REQ) {
		append_payload = 1;
		len += skb->len;		/* for whole frame in cookie */
	}

	event_data = kmalloc(len, GFP_ATOMIC);

	if (!event_data)
		return -ENOMEM;

	ic = vap->iv_ic;

	p_data = (struct ieee80211_qrpe_event_data *)event_data;
	pevent = (struct ieee80211_qrpe_event_probe_req *)(p_data->event);
	memset(pevent, 0, sizeof(*pevent) + sizeof(*cookie));

	wh = (struct ieee80211_frame *)skb->data;
	frm = (u_int8_t *)&wh[1];
	if ((subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ) ||
			(subtype == IEEE80211_FC0_SUBTYPE_REASSOC_REQ)) {
		frm += 2 + 2;
		if (subtype == IEEE80211_FC0_SUBTYPE_REASSOC_REQ)
			frm += ETH_ALEN;
		event_id = IEEE80211_QRPE_EVENT_ASSOC_REQ_OR_RESP;
	} else if ((subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP) ||
			(subtype == IEEE80211_FC0_SUBTYPE_REASSOC_RESP)) {
		/* skip cap (2) + status code (2) + assoc ID (2) */
		frm += 2 + 2 + 2;
		event_id = IEEE80211_QRPE_EVENT_ASSOC_REQ_OR_RESP;
	}
	efrm = skb->data + skb->len;

	if (sta_mac)
		memcpy(pevent->mac, sta_mac, IEEE80211_ADDR_LEN);

	while (frm < efrm) {
		if (efrm - frm < frm[1]) {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_ELEMID,
					"%s : ie too short\n", __func__);
			kfree(event_data);
			return -1;
		}
		if (!ieee80211_verify_ie_len(vap, wh, subtype, frm)) {
			kfree(event_data);
			return -1;
		}

		switch (*frm) {
		case IEEE80211_ELEMID_SSID:
			if (subtype == IEEE80211_FC0_SUBTYPE_PROBE_REQ)
				ssid = frm;
			break;
		case IEEE80211_ELEMID_FHPARMS:
			chan = IEEE80211_FH_CHAN(frm[4], frm[5]);
			break;
		case IEEE80211_ELEMID_DSPARMS:
			chan = frm[2];
			break;
		case IEEE80211_ELEMID_HTCAP:
			htcap = frm;
			break;
		case IEEE80211_ELEMID_VHTCAP:
			vhtcap = frm;
			break;
		case IEEE80211_ELEMID_VHTOP:
			vhtop = frm;
			break;
		case IEEE80211_ELEMID_HTINFO:
			htinfo = frm;
			break;
		case IEEE80211_ELEMID_EXTCAP:
			extcap = frm;
			break;
		default:
			break;
		}

		frm += frm[1] + 2;
	}

	/* convert the pseudo rssi to calculated rssi */
	rssi -= 90;
	pevent->rssi = rssi;
	if (extcap) {
		uint8_t value;
		value = extcap[1];
		if (value >= 3) {
			if (isset(&extcap[IEEE80211_IE_ID_LEN_SIZE], IEEE80211_EXTCAP_BTM))
				pevent->support_11v = 1;
		}
	}

	if (htcap != NULL) {
		pevent->support_ht = 1;
		htcap_ie = (struct ieee80211_ie_htcap *) htcap;
		max_ht_phy_rate = ieee80211_wlan_ht_rx_maxrate(htcap_ie, &max_ht_ss);
		bandwidth = ((htcap_ie->hc_cap[0] & 0x2) >> 1);
	}

	if (vhtcap != NULL) {
		pevent->support_vht = 1;
		vhtcap_ie = (struct ieee80211_ie_vhtcap * ) vhtcap;
		max_vht_phy_rate = ieee80211_wlan_vht_rx_maxrate(vhtcap_ie);
		pevent->mumimo_capab = ((vhtcap_ie->vht_cap[2] & 0x18) >> 3);
		max_vht_ss = ieee80211_wlan_vht_rxstreams(vhtcap_ie);
		bandwidth |= ((vhtcap_ie->vht_cap[0] & 0xc) >> 1);
	}
	pevent->band_width = bandwidth;
	pevent->max_phy_rate = (max_vht_phy_rate > max_ht_phy_rate) ? max_vht_phy_rate : max_ht_phy_rate;
	pevent->nss = (max_ht_ss > max_vht_ss) ? max_ht_ss : max_vht_ss;

	if (ssid != NULL) {
		ssid_ie = (struct ieee80211_ie_ssid *)ssid;
		if (ssid_ie->len == 0)
			probe_wild_ssid = 1;
	}

	if (ic && is_ieee80211_chan_valid(ic->ic_curchan)) {
		if (IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan))
			pevent->band = IEEE80211_QRPE_BAND_5G;
		else
			pevent->band = IEEE80211_QRPE_BAND_2G;
		if (ic->ic_flags_qtn & IEEE80211_QTN_BGSCAN) {
			struct shared_params *sp = qtn_mproc_sync_shared_params_get();
			struct qtn_scan_chan_info *scan_host = sp->chan_scan_lhost;
			struct qtn_off_chan_info *off_chan_info = &scan_host->base;
			pevent->channel = QTNCHAN_TO_IEEENUM(off_chan_info->channel);
		} else {
			pevent->channel = ic->ic_curchan->ic_ieee;
		}
	}

	cookie = (struct ieee80211_qrpe_frame_cookie *)pevent->cookie;
	pevent->cookie_len = ieee80211_bsa_build_frame_cookie(cookie, skb, filtered,
					probe_wild_ssid, append_payload);

	ieee80211_build_qrpe_event_head(vap, p_data,
		event_id, len - sizeof(struct ieee80211_qrpe_event_data));
	if (event_id == IEEE80211_QRPE_EVENT_PROBE_REQ &&
		g_bsa_probe_event_tunnel == QRPE_PROBE_TUNNEL_ENABLED)
		group_id = BSA_MCGRP_DRV_PROBE_EVENT;
	ret = ieee80211_send_qrpe_event(group_id, (uint8_t *)p_data, len);

	kfree(event_data);
	return ret;
}

int ieee80211_bsa_auth_event_send(struct ieee80211vap *vap, struct sk_buff *skb, uint8_t *bssid,
							uint8_t *sta_mac, int rssi, int filtered)
{
	struct ieee80211_qrpe_event_data *p_data;
	struct ieee80211_qrpe_event_auth *pevent;
	struct ieee80211com *ic;
	int ret = 0;
	struct ieee80211_qrpe_frame_cookie *cookie;

	int len = sizeof(*p_data) + sizeof(*pevent)
		+ sizeof(*cookie)
		+ skb->len;		/* for whole frame in cookie */
	uint8_t *event_data = kmalloc(len, GFP_ATOMIC);

	if (!event_data)
		return -ENOMEM;

	p_data = (struct ieee80211_qrpe_event_data *)event_data;
	pevent = (struct ieee80211_qrpe_event_auth *)(p_data->event);
	memset(pevent, 0, sizeof(*pevent) + sizeof(*cookie));

	if (sta_mac)
		memcpy(pevent->mac, sta_mac, IEEE80211_ADDR_LEN);

	/* convert the pseudo rssi to calculated rssi */
	rssi -= 90;
	pevent->rssi = rssi;
	ic = vap->iv_ic;
	if (ic && is_ieee80211_chan_valid(ic->ic_curchan)) {
		if (IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan))
			pevent->band = IEEE80211_QRPE_BAND_5G;
		else
			pevent->band = IEEE80211_QRPE_BAND_2G;
		pevent->channel = ic->ic_curchan->ic_ieee;
	}
	cookie = (struct ieee80211_qrpe_frame_cookie *)pevent->cookie;
	pevent->cookie_len = ieee80211_bsa_build_frame_cookie(cookie, skb, filtered, 0, 1);

	ieee80211_build_qrpe_event_head(vap, p_data,
		IEEE80211_QRPE_EVENT_AUTH, len - sizeof(struct ieee80211_qrpe_event_data));
	ret = ieee80211_send_qrpe_event(BSA_MCGRP_DRV_EVENT, (uint8_t *)p_data, len);

	kfree(event_data);
	return ret;
}
#endif

/* BSS transition management query reasons ieee80211 2102 spec Table 8-138 */
char *btm_query_reason[] = {
	"Unspecified",
	"Excessive frame loss rates and/or poor conditions",
	"Excessive delay for current traffic streams",
	"Insufficient QoS capacity for current traffic streams (TSPEC rejected)",
	"First association to ESS (the association initiated by an Association "
		"Request message instead of a Reassociation Request message)",
	"Load balancing",
	"Better AP found",
	"Deauthenticated or Disassociated from the previous AP",
	"AP failed IEEE 802.1X EAP Authentication",
	"AP failed 4-Way Handshake",
	"Received too many replay counter failures",
	"Received too many data MIC failures",
	"Exceeded maximum number of retransmissions",
	"Received too many broadcast disassociations",
	"Received too many broadcast deauthentications",
	"Previous transition failed",
	"Low RSSI",
	"Roam from a non IEEE 802.11 system",
	"Transition due to received BSS Transition Request frame",
	"Preferred BSS transition candidate list included",
	"Leaving ESS",
	"Reserved"
};
#define WNM_BTM_QUERY_REASON_CODE_MAX		ARRAY_SIZE(btm_query_reason)

/* BTM response codes */
char *btm_resp_status_codes[] = {
	"Accept",
	"Reject - Unspecified reject reason",
	"Reject - Insufficient Beacon or Probe Response frames received from all candidates",
	"Reject - Insufficient available capacity from all candidates",
	"Reject - BSS termination undesired",
	"Reject - BSS Termination delay requested",
	"Reject - STA BSS Transition Candidate List provided",
	"Reject - No suitable BSS transition candidates",
	"Reject - Leaving ESS",
	"Reserved"
};
#define WNM_BTM_RESPONSE_STATUS_CODE_MAX	ARRAY_SIZE(btm_resp_status_codes)

int
ieee80211_wnm_btm_create_pref_candidate_list(struct ieee80211_node *ni, uint8_t **list)
{
	struct ieee80211_neighbor_report_request_item *item_cache = NULL;
	struct ieee80211_neighbor_report_request_item *tcache = NULL;
	int i = 0;
	uint32_t num_items = 0;
	uint8_t *neigh_repo = NULL;
	int neigh_repo_size = 0;
	uint8_t pref = 255;

	num_items = ieee80211_create_neighbor_reports(ni, &item_cache,
				NEIGH_REPORTS_MAX, 1);
	if (num_items == 0) {
		kfree(item_cache);
		*list = NULL;
		return 0;
	}

	neigh_repo_size = (sizeof(struct ieee80211_ie_neighbor_report)
			+ sizeof(struct ieee80211_subie_pref)) * num_items;
	*list = kmalloc(neigh_repo_size, GFP_ATOMIC);
	if (*list == NULL) {
		kfree(item_cache);
		return 0;
	}

	neigh_repo = *list;
	tcache = item_cache;
	for (i = 0; i < num_items; i++) {
		*neigh_repo++ = IEEE80211_ELEMID_NEIGHBOR_REP;
		*neigh_repo++ = sizeof(struct ieee80211_ie_neighbor_report)
				+ sizeof(struct ieee80211_subie_pref)
				- IEEE80211_IE_ID_LEN_SIZE;
		memcpy(neigh_repo, tcache->bssid, IEEE80211_ADDR_LEN);
		neigh_repo += IEEE80211_ADDR_LEN;
		ADDINT32(neigh_repo, tcache->bssid_info);
		*neigh_repo++ = tcache->operating_class;
		*neigh_repo++ = tcache->channel;
		*neigh_repo++ = tcache->phy_type;
		/* fill preference sub element */
		*neigh_repo++ =  WNM_NEIGHBOR_BTM_CANDIDATE_PREFERENCE;
		*neigh_repo++ = 1;
		*neigh_repo++ = pref--;
		tcache++;
	}

	kfree(item_cache);

	return neigh_repo_size;
}

#ifndef ARTSMNG_SUPPORT
static void
ieee80211_handle_btm_query(struct ieee80211_node *ni, struct ieee80211_action_btm_query *query)
{
	uint8_t rcode = 0;
	uint8_t mode = BTM_REQ_ABRIDGED;
	int nsize = 0;
	uint8_t *neigh_repos = NULL;

	rcode = (query->btm_query_param.reason < WNM_BTM_QUERY_REASON_CODE_MAX) ?
			query->btm_query_param.reason :
			(WNM_BTM_QUERY_REASON_CODE_MAX - 1);
	IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_ACTION,
			"WNM: Received BSS Transition management query from station %pM token: %u reason %s\n",
			ni->ni_macaddr, query->btm_query_param.dialog_token,
			btm_query_reason[rcode]);
	nsize = ieee80211_wnm_btm_create_pref_candidate_list(ni, &neigh_repos);

	if (nsize == 0)
		mode &= ~BTM_REQ_PREF_CAND_LIST_INCLUDED;

	if (ieee80211_send_wnm_bss_tm_solicited_req(ni, mode, 0,
						WNM_BTM_DEFAULT_VAL_INTVAL,
						NULL, NULL, neigh_repos,
						nsize,
						query->btm_query_param.dialog_token))
		IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_ACTION, "WNM: Failed to send BTM request %pM\n",
						ni->ni_macaddr);
	kfree(neigh_repos);

}

#if defined(CONFIG_QTN_BSA_SUPPORT)
int ieee80211_bsa_btm_resp_event(struct ieee80211vap *vap,struct ieee80211_node *ni, uint8_t status)
{
	struct ieee80211_qrpe_event_data *p_data;
	struct ieee80211_qrpe_event_btm_status *pevent;
	int ret = 0;
	uint8_t *event_data = kmalloc(sizeof(*p_data) + sizeof(*pevent), GFP_ATOMIC);

	if (!event_data)
		return -ENOMEM;

	p_data = (struct ieee80211_qrpe_event_data *)event_data;
	pevent = (struct ieee80211_qrpe_event_btm_status *)(p_data->event);

	memcpy(pevent->mac, ni->ni_macaddr, IEEE80211_ADDR_LEN);
	pevent->status = status;

	ieee80211_build_qrpe_event_head(vap, p_data,
		IEEE80211_QRPE_EVENT_BTM_STATUS, sizeof(*pevent));
	ret = ieee80211_send_qrpe_event(BSA_MCGRP_DRV_EVENT, (uint8_t *)p_data,
			sizeof(*pevent) + sizeof(*p_data));

	kfree(event_data);
	return ret;
}
#endif

static void
ieee80211_hanle_btm_resp(struct ieee80211_node *ni, struct ieee80211_action_btm_rsp *rsp)
{
	uint8_t scode = 0;

	scode = (rsp->btm_rsp_param.status_code >= WNM_BTM_RESPONSE_STATUS_CODE_MAX) ?
			(WNM_BTM_RESPONSE_STATUS_CODE_MAX - 1) :
			rsp->btm_rsp_param.status_code;
	IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_ACTION,
			"WNM: Received BSS Transition management response from station %pM token: %u status code %s\n",
			ni->ni_macaddr, rsp->btm_rsp_param.dialog_token, btm_resp_status_codes[scode]);
	/*
	 * TBD: we don't have full WNM upper layer information or management control for now
	 * we are just logging and clearing pending BTM request
	 */
	if ((ni->ni_btm_req != 0) && (ni->ni_btm_req == rsp->btm_rsp_param.dialog_token)) {
		del_timer_sync(&ni->ni_btm_resp_wait_timer);
		ni->ni_btm_req = 0;
#if defined(CONFIG_QTN_BSA_SUPPORT)
		ieee80211_bsa_btm_resp_event(ni->ni_vap, ni, scode);
#endif
	}
}
#endif /* !ARTSMNG_SUPPORT */

#ifdef ARTSMNG_SUPPORT
static void
ieee80211_recv_action_wnm(struct ieee80211_node *ni,
			struct ieee80211_action *ia,
			int subtype,
			struct ieee80211_frame *wh,
			u_int8_t *frm,
			u_int8_t *efrm)
{
	artsmng_recv_action_wnm(ni, ia, subtype, wh, frm, efrm);
}
#else
static void
ieee80211_recv_action_wnm(struct ieee80211_node *ni,
			struct ieee80211_action *ia,
			int subtype,
			struct ieee80211_frame *wh,
			u_int8_t *frm,
			u_int8_t *efrm)
{
	struct ieee80211vap *vap = ni->ni_vap;

	switch (ia->ia_action) {
	case IEEE80211_WNM_BSS_TRANS_MGMT_QUERY: {
		if (ieee80211_verify_length(vap, efrm - frm,
				sizeof(struct ieee80211_action_btm_query), wh, subtype))
			return;
		struct ieee80211_action_btm_query *query = (struct ieee80211_action_btm_query *)frm;
		ieee80211_handle_btm_query(ni, query);
		break;
	}
	case IEEE80211_WNM_BSS_TRANS_MGMT_RESP: {
		if (ieee80211_verify_length(vap, efrm - frm,
				sizeof(struct ieee80211_action_btm_rsp), wh, subtype))
			return;
		struct ieee80211_action_btm_rsp *rsp = (struct ieee80211_action_btm_rsp *)frm;
		ieee80211_hanle_btm_resp(ni, rsp);
		break;
	}
	default:
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION, "WNM: Invalid action frame(%d) from station %pM\n",
					ia->ia_action, ni->ni_macaddr);
		vap->iv_stats.is_rx_mgtdiscard++;
		break;
	}
}
#endif /* ARTSMNG_SUPPORT */
