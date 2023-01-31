/**
 * Copyright (c) 2008 - 2017 Quantenna Communications Inc
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 **/

#ifndef __QTN_DECAP_H__
#define __QTN_DECAP_H__

#include <net80211/ieee80211.h>
#include <net80211/if_ethersubr.h>
#include <net80211/if_llc.h>

#include <qtn/qtn_net_packet.h>
#include <qtn/qtn_vlan.h>

/*
 * Length of received frame that requires dcache invalidate on receive.
 * The amount that must be read is:
 * - VLAN encap case: MAX_VLANS * (LLC + 2b) + LLC
 * - 802.11 MPDU, no amsdu: LLC + max l3 depth
 * - 802.11 AMSDU: msdu header + LLC + max l3 depth
 *
 * The max of these three is the VLAN case. There is also an assumption
 * here that if VLANs are processed, there is no need to process L3 header
 */
#define QTN_RX_LLC_DCACHE_INV_LEN	(((LLC_SNAPFRAMELEN + 2) * QTN_MAX_VLANS) + LLC_SNAPFRAMELEN)
#define QTN_RX_MPDU_DCACHE_INV_LEN	(QTN_RX_LLC_DCACHE_INV_LEN + sizeof(struct ieee80211_qosframe_addr4))
#define QTN_RX_MSDU_DCACHE_INV_LEN	(QTN_RX_LLC_DCACHE_INV_LEN + sizeof(struct ether_header))

#define QTN_80211_TDLS_PAYLOAD	0x2

/* Addressing A-MSDU Security Vulnerability */
#define QTN_AMSDU_SUBFRM_SNAP_CHECK BIT(0)
#define QTN_AMSDU_SUBFRM_CHECK_INIT (QTN_AMSDU_SUBFRM_SNAP_CHECK)

struct qtn_rx_decap_info {
	void		*start;
	uint16_t	len;
	struct ether_header eh;			/* the eth header to be written to the packet */
	uint32_t	vlanh[QTN_MAX_VLANS];	/* space for vlan headers (must be after eh) */
	const void	*l3hdr;			/* pointer to layer 3 header in the payload */
	uint16_t	l3_ether_type;		/* l3 header type (may not match eh.ether_type for 802.3 */
	int8_t		tid;
	int8_t		nvlans;
	uint16_t	vlan_tci;		/* to which VLAN te msdu belongs */
	uint8_t		first_msdu	:1,	/* first msdu in an amsdu */
			last_msdu	:1,	/* last msdu in an amsdu */
			decapped	:1,	/* start is decapped eh, not wireless header */
			no_amsdu	:1;	/* amsdu should not be used */
};

static __inline__ int qtn_rx_da_is_snap_header(const uint8_t *p)
{
	return ((p[0] == 0xAA) && (p[1] == 0xAA) && (p[2] == 0x03) &&
		(p[3] == 0x00) && (p[4] == 0x00) && (p[5] == 0x00 || p[5] == 0xF8));
}

static __inline__ uint16_t
qtn_rx_decap_newhdr_size(const struct qtn_rx_decap_info *const di)
{
	return sizeof(struct ether_header) + (sizeof(struct qtn_8021q) * di->nvlans);
}

static __inline__ const struct qtn_8021q *
qtn_rx_decap_vlan(const struct qtn_rx_decap_info *const di, int8_t index)
{
	const struct qtn_8021q *v = (const void *) &di->eh.ether_type;
	return &v[index];
}

static __inline__ uint16_t qtn_rx_decap_header_size(const struct ieee80211_qosframe_addr4 *const wh)
{
	uint16_t size;
	const uint8_t dir = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;

	size = sizeof(struct ieee80211_frame);

	if (dir == IEEE80211_FC1_DIR_DSTODS)
		size += IEEE80211_ADDR_LEN;
	if (IEEE80211_QOS_HAS_SEQ(wh)) {
		size += sizeof(uint16_t);
		if ((wh->i_fc[1] & IEEE80211_FC1_ORDER) == IEEE80211_FC1_ORDER)
			/* Frame has HT control field in the header */
			size += sizeof(uint32_t);
	}

	return size;
}

#define DECAP_VLAN_ACTION_NONE	0
#define DECAP_VLAN_ADD_TAG	BIT(0)
#define DECAP_VLAN_STRIP_TAG	BIT(1)
#define DECAP_VLAN_REPLACE_TAG	(DECAP_VLAN_ADD_TAG | DECAP_VLAN_STRIP_TAG)

#define DECAP_PRIO_TAGGED	0
#define DECAP_NON_PRIO_TAGGED	1
#define DECAP_UNTAGGED		2
#define DECAP_TAG_MAX		3

#ifdef MUC_BUILD
#pragma Data(DATA,".fast_cache_data")
#endif
RUBY_WEAK(decap_vlan_action)
const uint8_t decap_vlan_action[DECAP_TAG_MAX][DECAP_TAG_MAX] = {
	/* Rx: priority tagged */
	{DECAP_VLAN_ACTION_NONE, DECAP_VLAN_REPLACE_TAG, DECAP_VLAN_STRIP_TAG},
	/* Rx: non-priority tagged */
	{DECAP_VLAN_REPLACE_TAG, DECAP_VLAN_ACTION_NONE, DECAP_VLAN_STRIP_TAG},
	/* Rx: untagged */
	{DECAP_VLAN_ADD_TAG, DECAP_VLAN_ADD_TAG, DECAP_VLAN_ACTION_NONE}
};
#ifdef MUC_BUILD
#pragma Data
#endif

static __inline__ uint8_t
qtn_rx_decap_vlan_action(uint16_t ether_type_l3, const uint8_t *vlan_tci, uint16_t ptci, struct qtn_vlan_info *vlan_info,
	uint16_t *pkt_tci, uint16_t *out_tci)
{
	uint8_t rx;
	uint8_t tx;
	uint16_t tag_tci;
	int tagrx;

	if (ether_type_l3 == htons(ETHERTYPE_8021Q)) {
		tag_tci = ((vlan_tci[1] << 0) | (vlan_tci[0] << 8));
		if ((tag_tci & QVLAN_MASK_VID) != QVLAN_PRIO_VID) {
			*pkt_tci = tag_tci;
			rx = DECAP_NON_PRIO_TAGGED;
		} else {
			*pkt_tci = ptci;
			rx = DECAP_PRIO_TAGGED;
		}
	} else {
		*pkt_tci = ptci;
		rx = DECAP_UNTAGGED;
	}

	tagrx = qtn_vlan_get_tagrx(vlan_info->vlan_tagrx_bitmap, *pkt_tci & QVLAN_MASK_VID);
	if (tagrx == QVLAN_TAGRX_UNTOUCH) {
		return DECAP_VLAN_ACTION_NONE;
	} else if (tagrx == QVLAN_TAGRX_TAG) {
		tx = DECAP_NON_PRIO_TAGGED;
		*out_tci = *pkt_tci;
	} else {
		tagrx = qtn_vlan_get_tagrx(vlan_info->vlan_tagrx_bitmap, QVLAN_PRIO_VID);
		if (tagrx == QVLAN_TAGRX_TAG) {
			tx = DECAP_PRIO_TAGGED;
			*out_tci = QVLAN_PRIO_VID | (ptci & ~QVLAN_MASK_VID);
		} else {
			tx = DECAP_UNTAGGED;
		}
	}

	return decap_vlan_action[rx][tx];
}

#define LLC_ENCAP_RFC1042	0x0
#define LLC_ENCAP_BRIDGE_TUNNEL	0xF8

/*
 * Remove the LLC/SNAP header (if present) and replace with an Ethernet header
 *
 * See IEEE 802.1H for LLC/SNAP encapsulation/decapsulation.
 *   Ethernet-II SNAP header (RFC1042 for most Ethertypes)
 *   Bridge-Tunnel header (for Ethertypes ETH_P_AARP and ETH_P_IPX
 *   No encapsulation header if Ethertype < 0x600 (=length)
 */
static void *
qtn_rx_decap_set_eth_hdr(struct qtn_rx_decap_info *di, const uint8_t *llc, const uint16_t llclen,
				uint16_t ptci, struct qtn_vlan_info *vlan_info, uint8_t vlan_enabled,
				void *token, void **rate_train)
{
	uint16_t *newhdrp = &di->eh.ether_type;
	int8_t llc_l3_gap = 0;
	uint16_t ether_type_l3;

	uint8_t last_byte = llc[5];
	uint16_t ether_type_eh;
	bool is_llc_snap_e;
	uint8_t vlan_hdr = 0;

	ether_type_l3 = (llc[6] << 0) | (llc[7] << 8);
	ether_type_eh = ether_type_l3;

	di->nvlans = 0;
	di->vlan_tci = 0;

	/*
	 * For EAPOL and VLAN frames we do not want to add 802.1Q header.
	 * Otherwise, the frame won't go through a driver.
	 */
	if (vlan_enabled) {
		uint16_t out_tci = 0;
		uint8_t action = qtn_rx_decap_vlan_action(ether_type_l3, &llc[8], ptci,
			vlan_info, &di->vlan_tci, &out_tci);

		if (action & DECAP_VLAN_STRIP_TAG) {
			ether_type_l3 = ((llc[10] << 0) | (llc[11] << 8));
			ether_type_eh = ether_type_l3;
			vlan_hdr = 4;
		}

		if (action & DECAP_VLAN_ADD_TAG) {
			if (ether_type_l3 != htons(ETHERTYPE_PAE)) {
				*newhdrp++ = htons(ETHERTYPE_8021Q);
				*newhdrp++ = htons(out_tci);
				di->nvlans++;
			}
		}
	}

	/*
	* Common part of the header - RFC1042 (final byte is 0x0) or
	* bridge tunnel encapsulation (final byte is 0xF8)
	*/
	is_llc_snap_e = llc[0] == LLC_SNAP_LSAP && llc[1] == LLC_SNAP_LSAP &&
		llc[2] == LLC_UI && llc[3] == 0x0 && llc[4] == 0x0;

	if (unlikely(ether_type_eh == htons(ETHERTYPE_80211MGT))) {
		if (llc[8] == QTN_80211_TDLS_PAYLOAD)
			di->no_amsdu = 1;
	}

	if (likely(is_llc_snap_e &&
				((last_byte == LLC_ENCAP_BRIDGE_TUNNEL) ||
				 (last_byte == LLC_ENCAP_RFC1042 &&
				  ether_type_eh != htons(ETHERTYPE_AARP) &&
				  ether_type_eh != htons(ETHERTYPE_IPX))))) {
		if (last_byte == LLC_ENCAP_RFC1042 && ether_type_eh == htons(ETHERTYPE_802A)) {
			struct oui_extended_ethertype *pe = (struct oui_extended_ethertype *)&llc[8];
			if (pe->oui[0] == (QTN_OUI & 0xff) &&
					pe->oui[1] == ((QTN_OUI >> 8) & 0xff) &&
					pe->oui[2] == ((QTN_OUI >> 16) & 0xff) &&
					pe->type == ntohs(QTN_OUIE_TYPE_TRAINING)) {
				/* Pass back pointer to start of training data */
				if (rate_train)
					*rate_train = (pe + 1);
				return NULL;
			}
		}

		llc += (LLC_SNAPFRAMELEN + vlan_hdr);
		*newhdrp++ = ether_type_eh;
	} else {
		ether_type_eh = htons(llclen);
		*newhdrp++ = ether_type_eh;
		llc_l3_gap = LLC_SNAPFRAMELEN;
	}

	di->l3hdr = llc + llc_l3_gap;
	di->l3_ether_type = ether_type_l3;
	di->start = (void *) (llc - qtn_rx_decap_newhdr_size(di));

	return di->start;
}

#ifdef MUC_BUILD
#pragma Alloc_text(".fast_text_set_0", qtn_rx_decap_set_eth_hdr)
#endif

typedef int (*decap_handler_t)(struct qtn_rx_decap_info *, void *);

#define QTN_RX_DECAP_AMSDU	(0)
#define QTN_RX_DECAP_MPDU	(-1)
#define QTN_RX_DECAP_TRAINING	(-2)
#define QTN_RX_DECAP_NOT_DATA	(-3)
#define QTN_RX_DECAP_RUNT	(-4)
#define QTN_RX_DECAP_ABORTED	(-5)
#define QTN_RX_DECAP_SNAP_DROP	(-6)
#define QTN_RX_DECAP_ERROR(x)	((x) <= QTN_RX_DECAP_NOT_DATA)

#ifndef QTN_RX_DECAP_FNQUAL
#ifdef __KERNEL__
#define QTN_RX_DECAP_FNQUAL	static __sram_text
#define	qtn_rx_decap_inv_dcache_safe(a,b)
#else
#define QTN_RX_DECAP_FNQUAL	static __inline__
#define	qtn_rx_decap_inv_dcache_safe	invalidate_dcache_range_safe
#endif
#endif

static int qtn_rx_pre_decap_amsdu_check(struct ether_header *msdu_header,
		const void *const rxdata,
		const uint16_t rxlen, uint16_t header_size)
{
	uint16_t total_decapped_len = header_size;
	uint16_t subframe_padding;
	uint16_t subframe_len;
	uint16_t msdu_len;
	int msdu;

	for (msdu = 0; total_decapped_len < rxlen; msdu++) {
		qtn_rx_decap_inv_dcache_safe(msdu_header, QTN_RX_MSDU_DCACHE_INV_LEN);
		if (unlikely(qtn_rx_da_is_snap_header(msdu_header->ether_dhost)))
			return 1;

		msdu_len = ntohs(msdu_header->ether_type);
		subframe_len = sizeof(*msdu_header) + msdu_len;
		if (unlikely(subframe_len < sizeof(*msdu_header) ||
				subframe_len > (rxlen - total_decapped_len) ||
				subframe_len > (ETHER_JUMBO_MAX_LEN + LLC_SNAPFRAMELEN))) {
			break;
		}

		subframe_padding = ((subframe_len + 0x3) & ~0x3) - subframe_len;
#pragma Off(Behaved)
		msdu_header = (struct ether_header *)((uint8_t *)msdu_header +
				subframe_len + subframe_padding);
#pragma On(Behaved)
		total_decapped_len = ((uint8_t *)msdu_header) - ((uint8_t *)rxdata);
	}
	return 0;
}

QTN_RX_DECAP_FNQUAL int qtn_rx_decap(const struct ieee80211_qosframe_addr4 *const wh_copy,
		const void *const rxdata, const uint16_t rxlen,
		uint16_t ptci, struct qtn_vlan_info *vlan_info, uint8_t vlan_enabled,
		decap_handler_t handler, void *token, void **rate_train, uint8_t snap_check)
{
	const uint8_t *llc;
	const uint8_t type = wh_copy->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
	const uint8_t subtype = wh_copy->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
	const uint8_t dir = wh_copy->i_fc[1] & IEEE80211_FC1_DIR_MASK;
	uint8_t qosctrl0 = 0;
	int8_t tid;
	bool is_amsdu = false;
	size_t header_size;
	int msdu;
	struct qtn_rx_decap_info __di[2];
	int dii	= 0;
	uint8_t *decap_start;

	/* only attempt to decap data frames */
	if (unlikely(type != IEEE80211_FC0_TYPE_DATA ||
			!(subtype == IEEE80211_FC0_SUBTYPE_DATA ||
			subtype == IEEE80211_FC0_SUBTYPE_QOS))) {
		return QTN_RX_DECAP_NOT_DATA;
	}

	/* find qos ctrl field */
	if (IEEE80211_QOS_HAS_SEQ(wh_copy)){
		if (IEEE80211_IS_4ADDRESS(wh_copy)) {
			qosctrl0 = ((struct ieee80211_qosframe_addr4 *)wh_copy)->i_qos[0];
		} else {
			qosctrl0 = ((struct ieee80211_qosframe *)wh_copy)->i_qos[0];
		}
		tid = qosctrl0 & IEEE80211_QOS_TID;
		if (qosctrl0 & IEEE80211_QOS_A_MSDU_PRESENT) {
			is_amsdu = true;
		}
	} else {
		tid = WME_TID_NONQOS;
	}
#ifdef MUC_BUILD
	tid = QTN_TID_MAP_80211(tid);
#endif
	header_size = qtn_rx_decap_header_size(wh_copy);

	if (unlikely(header_size >= rxlen)) {
		return QTN_RX_DECAP_RUNT;
	}

	if (!is_amsdu) {
		const uint8_t *wh_eth_src;
		const uint8_t *wh_eth_dest;
		struct qtn_rx_decap_info *di = &__di[dii];

		switch (dir) {
		case IEEE80211_FC1_DIR_DSTODS:
			wh_eth_dest = wh_copy->i_addr3;
			wh_eth_src = wh_copy->i_addr4;
			break;
		case IEEE80211_FC1_DIR_TODS:
			wh_eth_dest = wh_copy->i_addr3;
			wh_eth_src = wh_copy->i_addr2;
			break;
		case IEEE80211_FC1_DIR_NODS:
			wh_eth_dest = wh_copy->i_addr1;
			wh_eth_src = wh_copy->i_addr2;
			break;
		case IEEE80211_FC1_DIR_FROMDS:
			wh_eth_src = wh_copy->i_addr3;
			wh_eth_dest = wh_copy->i_addr1;
			break;
		default:
			return QTN_RX_DECAP_ABORTED;
		}

		IEEE80211_ADDR_COPY(di->eh.ether_dhost, wh_eth_dest);
		IEEE80211_ADDR_COPY(di->eh.ether_shost, wh_eth_src);
		llc = ((uint8_t *) rxdata) + header_size;
		decap_start = qtn_rx_decap_set_eth_hdr(di, llc, rxlen - header_size,
							ptci, vlan_info, vlan_enabled, token, rate_train);
		if (unlikely(!decap_start)) {
			return QTN_RX_DECAP_TRAINING;
		}

		di->len = (((uint8_t *) rxdata) + rxlen) - decap_start;
		di->tid = tid;
		di->first_msdu = 1;
		di->last_msdu = 1;
		di->decapped = 1;

		if (handler(di, token)) {
			return QTN_RX_DECAP_ABORTED;
		}

		return QTN_RX_DECAP_MPDU;
	} else {
		/* amsdu */
		struct ether_header *msdu_header;
		struct ether_header *next_msdu_header;
		struct qtn_rx_decap_info *prev_di = NULL;
		uint16_t msdu_len;
		uint16_t subframe_len;
		uint16_t subframe_padding;
		uint16_t total_decapped_len = header_size;

		MUC_UPDATE_STATS(uc_rx_stats.rx_amsdu, 1);
		next_msdu_header = (struct ether_header *)(((uint8_t *)rxdata) + header_size);

		if (unlikely(snap_check && qtn_rx_pre_decap_amsdu_check(next_msdu_header, rxdata,
						rxlen, header_size)))
			return QTN_RX_DECAP_SNAP_DROP;

		for (msdu = 0; total_decapped_len < rxlen; msdu++) {
			struct qtn_rx_decap_info *di = &__di[dii];

			msdu_header = next_msdu_header;
			llc = (uint8_t *)(msdu_header + 1);

			if (unlikely(!snap_check)) {
				qtn_rx_decap_inv_dcache_safe(msdu_header,
						QTN_RX_MSDU_DCACHE_INV_LEN);
			}

			msdu_len = ntohs(msdu_header->ether_type);
			subframe_len = sizeof(*msdu_header) + msdu_len;
			if (subframe_len < sizeof(*msdu_header) ||
					subframe_len > (rxlen - total_decapped_len) ||
					subframe_len > (ETHER_JUMBO_MAX_LEN + LLC_SNAPFRAMELEN)) {
				break;
			}
			subframe_padding = ((subframe_len + 0x3) & ~0x3) - subframe_len;
			next_msdu_header = (struct ether_header *)(llc + msdu_len + subframe_padding);
			/* decapped length includes subframe padding */
			total_decapped_len = ((uint8_t *)next_msdu_header) - ((uint8_t *)rxdata);

			decap_start = qtn_rx_decap_set_eth_hdr(di, llc, msdu_len, ptci, vlan_info, vlan_enabled,
								token, rate_train);
			if (unlikely(!decap_start)) {
				return QTN_RX_DECAP_TRAINING;
			}

			IEEE80211_ADDR_COPY(di->eh.ether_dhost, msdu_header->ether_dhost);
			IEEE80211_ADDR_COPY(di->eh.ether_shost, msdu_header->ether_shost);
			di->len = ((uint8_t *)next_msdu_header - decap_start) - subframe_padding;
			di->tid = tid;
			di->first_msdu = (prev_di == NULL);
			di->last_msdu = 0;
			di->decapped = 1;

			if (prev_di) {
				if (handler(prev_di, token))
					return QTN_RX_DECAP_ABORTED;
			}

			prev_di = di;
			dii = !dii;
		}

		if (prev_di) {
			prev_di->last_msdu = 1;
			if (handler(prev_di, token)) {
				return QTN_RX_DECAP_ABORTED;
			}
		} else {
			return QTN_RX_DECAP_ABORTED;
		}

		return QTN_RX_DECAP_AMSDU;
	}
}

#endif	// __QTN_DECAP_H__

