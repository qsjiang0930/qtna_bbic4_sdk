/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2011 - 2012 Quantenna Communications, Inc.          **
**                            All Rights Reserved                            **
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

#ifndef __QDRV_SCH_H
#define __QDRV_SCH_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#ifdef CONFIG_IPV6
#include <linux/ipv6.h>
#endif
#include <net/pkt_sched.h>

#include "net80211/if_ethersubr.h"
#include "net80211/if_llc.h"

#include <linux/if_vlan.h>

#include <qtn/qtn_global.h>

#include <qtn/qdrv_sch_data.h>
#include "qdrv_sch_const.h"
#include <qtn/iputil.h>
#include <qtn/qtn_net_packet.h>
#include <qtn/topaz_tqe_cpuif.h>
#include <qtn/topaz_vlan_cpuif.h>
#include <common/topaz_emac.h>
#include <asm/hardware.h>
#define ETHER_TYPE_UNKNOWN			0XFFFF
#define IPTOS_PREC_SHIFT			5

#define IP_DSCP_SHIFT		2
#define IP_DSCP(_pri)           (((_pri) & 0xFF) >> IP_DSCP_SHIFT)
#define IP_DSCP_MAPPING_SIZE	IP_DSCP_NUM >> 1
#define VLANID_INDEX_INITVAL	4096
/* 4-bits are used to store TID */
#define QDRV_IP_DSCP_MAPPING_SHIFT	4
#define QDRV_IP_DSCP_INDEX_SHIFT	3

#define QDRV_SCH_RESERVED_TOKEN_PER_USER	64

#define QDRV_SCH_EMAC0_IN_USE	1
#define QDRV_SCH_EMAC1_IN_USE	2

extern __sram_data uint8_t qdrv_sch_tos2ac[];
extern __sram_data uint8_t qdrv_vap_vlan_max;
extern __sram_data uint8_t qdrv_sch_dscp2tid[QTN_MAX_BSS_VAPS][IP_DSCP_MAPPING_SIZE];
extern __sram_data uint16_t qdrv_sch_vlan2index[QTN_MAX_BSS_VAPS];

/*
 * Refactoring of emac_wr(struct emac_common *arapc, int reg, u32 val)
 * We can't visit the emac_common structure here.
 */
__always_inline static void qtn_emac_wr(uint32_t vbase, int reg, u32 val)
{
	writel(val, IO_ADDRESS(vbase + reg));
	/* HW bug workaround - dummy access breaks up bus transactions. */
	readl(RUBY_SYS_CTL_BASE_ADDR);
}

__always_inline static uint32_t qtn_emac_rd(uint32_t vbase, int reg)
{
	/*
	 *HW bug workaround , sometimes we can't get the correct register value
	 * so we need to do an extra readl
	 */
	readl(RUBY_SYS_CTL_BASE_ADDR);
	return readl(IO_ADDRESS(vbase + reg));
}

static inline struct Qdisc *qdrv_tx_sch_vap_get_qdisc(const struct net_device *dev)
{
	/* This assumes 1 tx netdev queue per vap */
	return netdev_get_tx_queue(dev, 0)->qdisc;
}

static inline int qdrv_sch_tclass_to_ac(const uint8_t dscp)
{
	int wme_ac;
	uint8_t dot1p_up;
	static const uint8_t qdrv_sch_dscp2dot1p[] = {
		/* 000xxx */
		0, 0, 0, 0, 0, 0, 0, 0,
		/* 001xxx */
		1, 1, 1, 1, 1, 1, 1, 1,
		/* 010xxx */
		2, 2, 2, 2, 2, 2, 2, 2,
		/* 011xxx */
		3, 3, 3, 3, 3, 3, 3, 3,
		/* 100xxx */
		4, 4, 4, 4, 4, 4, 4, 4,
		/* 101xxx */
		5, 5, 5, 5, 5, 5, 5, 5,
		/* 110xxx */
		6, 6, 6, 6, 6, 6, 6, 6,
		/* 111xxx */
		7, 7, 7, 7, 7, 7, 7, 7
	};

	dot1p_up = qdrv_sch_dscp2dot1p[IP_DSCP(dscp)];
	if (dot1p_up < IEEE8021P_PRIORITY_NUM)
		wme_ac = qdrv_sch_tos2ac[dot1p_up];
	else
		wme_ac = qdrv_sch_tos2ac[IPTOS_PREC(dscp) >> IPTOS_PREC_SHIFT];

	return wme_ac;
}

#define QTN_ETHER_IS_ARTSMNG(_eth_type)	(_eth_type == __constant_htons(0x7373) || \
					_eth_type == __constant_htons(0x7374))

#define QTN_ETHER_IS_BPDU(_addr)	(_addr[0] == 0x01 && _addr[1] == 0x80 && \
					_addr[2] == 0xc2)

static inline int
qdrv_sch_classify_ctrl(struct sk_buff *skb)
{
	uint16_t ether_type = QTN_SKB_CB_ETHERTYPE(skb);
	uint8_t ip_protocol;

	if (likely(iputil_eth_is_ipv4or6(ether_type))) {
		ip_protocol = QTN_SKB_CB_IPPROTO(skb);
		if (unlikely((ip_protocol == IPPROTO_ICMP) ||
				(ip_protocol == IPPROTO_ICMPV6) ||
				(ip_protocol == IPPROTO_IGMP))) {
			return 1;
		}
	} else if ((ether_type == __constant_htons(ETH_P_ARP)) ||
#ifdef ARTSMNG_SUPPORT
			QTN_ETHER_IS_ARTSMNG(ether_type) ||
#endif
			(ether_type == __constant_htons(ETH_P_PAE))) {
		return 1;
	}

#ifdef ARTSMNG_SUPPORT
	if (QTN_ETHER_IS_BPDU(skb->data)) {
		return 1;
	}
#endif

	return 0;
}

static inline uint8_t qdrv_sch_mask_gettid(uint8_t ifindex, uint8_t dscp)
{
	uint8_t index;
	uint32_t curval;
	uint8_t	tid;

	index = (dscp >> 1);
	curval = qdrv_sch_dscp2tid[ifindex][index];

	if (dscp & 0x1)
		tid  = (curval & 0xf);
	else
		tid = (curval >> QDRV_IP_DSCP_MAPPING_SHIFT) & 0xf;

	return tid;
}

/* Multiple VLAN tags are not currently supported */
static inline uint8_t topaz_tqe_vlan_gettid(void *data)
{
	struct vlan_ethhdr *vhd;
	uint16_t vid = 0;
	uint8_t ip_dscp = 0;
	uint8_t vlan_index = 0;
	int i;
	const struct ether_header *eh = data;
	uint16_t ether_type = eh->ether_type;
	const void *iphdr = eh + 1;

	if (ether_type == htons(ETH_P_8021Q)) {
		vhd = data;
		iphdr = vhd + 1;
		ether_type = vhd->h_vlan_encapsulated_proto;
		vid = ntohs(vhd->h_vlan_TCI) & VLAN_VID_MASK;
		for (i = 0; i < qdrv_vap_vlan_max; i++) {
			if (qdrv_sch_vlan2index[i] == vid) {
				vlan_index = i;
				break;
			}
		}
	}

	if (ether_type == htons(ETH_P_IP)) {
		const struct qtn_ipv4 *ipv4 = (const struct qtn_ipv4 *) iphdr;
		ip_dscp = IP_DSCP(ipv4->dscp);
	} else if (ether_type == htons(ETH_P_IPV6)) {
		const struct qtn_ipv6 *ipv6 = (const struct qtn_ipv6 *) iphdr;
		ip_dscp = qtn_ipv6_tclass(ipv6);
	} else if ((ether_type == htons(ETH_P_ARP)) || (ether_type == htons(ETH_P_PAE))) {
		return WME_AC_TO_TID(WMM_AC_VO);
	} else {
		return WME_AC_TO_TID(WMM_AC_BE);
	}

	return qdrv_sch_mask_gettid(vlan_index, ip_dscp);
}

static inline void
qdrv_sch_classify(struct sk_buff *skb, uint16_t ether_type, uint8_t *data_start)
{
	uint8_t wme_ac = WME_AC_BE;
	uint8_t tid;

	if (M_FLAG_ISSET(skb, M_CLASSIFY)) {
		return;
	}
	M_FLAG_SET(skb, M_CLASSIFY);

	QTN_SKB_CB_ETHERTYPE(skb) = ether_type;

	if (ether_type == __constant_htons(ETH_P_IP)) {
		struct iphdr *iphdr_p = (struct iphdr *)data_start;

		if ((skb->len >= (data_start - skb->data) + sizeof(*iphdr_p)) &&
				(iphdr_p->version == 4))
			QTN_SKB_CB_IPPROTO(skb) = iphdr_p->protocol;
	}
#ifdef CONFIG_IPV6
	else if (ether_type == __constant_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ipv6hdr_p = (struct ipv6hdr *)data_start;

		if (skb->len >= (data_start - skb->data) + sizeof(struct ipv6hdr) &&
				(ipv6hdr_p->version == 6)) {
			uint8_t nexthdr;

			iputil_v6_skip_exthdr(ipv6hdr_p, sizeof(struct ipv6hdr), &nexthdr,
				(skb->len - ((uint8_t *)ipv6hdr_p - skb->data)), NULL, NULL);
			QTN_SKB_CB_IPPROTO(skb) = nexthdr;
		}
	}
#endif

	if (qdrv_sch_classify_ctrl(skb)) {
		wme_ac = QTN_AC_MGMT;
	} else {
		tid = topaz_tqe_vlan_gettid(skb->data);
		wme_ac = TID_TO_WMM_AC(tid);
	}

	skb->priority = wme_ac;
}

static inline void
qdrv_sch_classify_bk(struct sk_buff *skb)
{
	M_FLAG_SET(skb, M_CLASSIFY);
	skb->priority = QDRV_BAND_AC_BK;
}

/*
 * Skip over L2 headers in a buffer
 *   Returns Ethernet type and a pointer to the payload
 */
static inline void *
qdrv_sch_find_data_start(struct sk_buff *skb,
		struct ether_header *eh, u16 *ether_type)
{
	struct llc *llc_p;
	struct vlan_ethhdr *vlan_ethhdr_p;

	if (ntohs(eh->ether_type) < ETHER_MAX_LEN) {
		llc_p = (struct llc *)(eh + 1);
		if ((skb->len >= LLC_SNAPFRAMELEN) &&
		    (llc_p->llc_dsap == LLC_SNAP_LSAP) &&
		    (llc_p->llc_ssap == LLC_SNAP_LSAP)) {
			*ether_type = llc_p->llc_un.type_snap.ether_type;
			return (void *)((char *)(eh + 1) - sizeof(ether_type) + LLC_SNAPFRAMELEN);
		} else {
			*ether_type = ETHER_TYPE_UNKNOWN;
			return (void *)(eh + 1);
		}
	} else if (ntohs(eh->ether_type) == ETH_P_8021Q) {
		vlan_ethhdr_p = (struct vlan_ethhdr *)eh;
		*ether_type = vlan_ethhdr_p->h_vlan_encapsulated_proto;
		skb->vlan_tci = ntohs(get_unaligned((__be16 *)(&vlan_ethhdr_p->h_vlan_TCI)));
		return (void *)(vlan_ethhdr_p + 1);
	} else {
		*ether_type = eh->ether_type;
		return (void *)(eh + 1);
	}
}

static inline uint8_t qdrv_dscp2tid_default(const uint8_t dscp)
{
	const uint8_t tclass = dscp << IP_DSCP_SHIFT;
	const uint8_t ac = qdrv_sch_tclass_to_ac(tclass);
	const uint8_t tid = WME_AC_TO_TID(ac);

	return tid;
}

/* Each byte contains 2 4-bit DSCP mapping values */
static inline void qdrv_dscp2tid_setvalue(uint8_t ifindex , uint8_t dscp, uint8_t tid)
{
	uint8_t curval = 0;
	uint8_t index = 0;

	index = dscp >> 1;
	curval = qdrv_sch_dscp2tid[ifindex][index];

	if (dscp & 0x1) {
		qdrv_sch_dscp2tid[ifindex][index] = (curval & ~0xf) | tid;
	} else {
		qdrv_sch_dscp2tid[ifindex][index] = (curval & ~(0xf << QDRV_IP_DSCP_MAPPING_SHIFT)) |
			(tid << QDRV_IP_DSCP_MAPPING_SHIFT);
	}
}

static inline void qdrv_dscp2tid_map_init(void)
{
	uint8_t ifindex;
	uint8_t dscp;
	uint8_t tid = 0;

	for (dscp = 0; dscp < IP_DSCP_NUM; dscp++) {
		tid =  qdrv_dscp2tid_default(dscp);
		qdrv_dscp2tid_setvalue(0, dscp, tid);
	}

	for (ifindex = 1; ifindex < QTN_MAX_BSS_VAPS; ifindex++) {
		memcpy(&qdrv_sch_dscp2tid[ifindex][0], &qdrv_sch_dscp2tid[0][0], sizeof(qdrv_sch_dscp2tid[0]));
	}
}

#if !defined(CONFIG_TOPAZ_PCIE_HOST) && !defined(CONFIG_TOPAZ_PCIE_TARGET)
/* conversion is only needed for tables that are different to the first table */
static inline void qdrv_sch_set_vlanpath(void)
{
	int i;
	union topaz_vlan_entry vlan_entry;
	uint16_t vid;

	/*
	 * This comparison must be done again if the user changes wifi0 config to
	 * be the same as some other interfaces.
	 */
	for (i = 1; i < QTN_MAX_BSS_VAPS; i++) {
		vid = qdrv_sch_vlan2index[i];
		if (vid == VLANID_INDEX_INITVAL) {
			continue;
		}

		vlan_entry = topaz_vlan_get_entry(vid);
		if (memcmp(&qdrv_sch_dscp2tid[0][0], &qdrv_sch_dscp2tid[i][0], sizeof(qdrv_sch_dscp2tid[0]))) {
			vlan_entry.data.valid = 1;
			vlan_entry.data.out_port = TOPAZ_TQE_LHOST_PORT;
		} else {
			vlan_entry.data.valid = 0;
		}
		topaz_vlan_clear_entry(vid);
		topaz_vlan_set_entry(vid, vlan_entry);
	}
}

/*
 * Configure the HW DSCP to TID table, which is used for wifi0
 * and any other TIDs that use the same config.
 */
static inline void qdrv_sch_set_dscp_hwtbl(uint8_t dscp, uint8_t tid, uint32_t reg_base)
{
	uint32_t dscp_reg_val = 0;
	uint8_t dscp_reg_index = dscp >> QDRV_IP_DSCP_INDEX_SHIFT;
	uint8_t dscp_nibble_index = dscp - (dscp_reg_index << QDRV_IP_DSCP_INDEX_SHIFT);

	dscp_reg_val = qtn_emac_rd(reg_base, TOPAZ_EMAC_RXP_IP_DIFF_SRV_TID_REG(dscp_reg_index));

	dscp_reg_val &= ~(0xF <<
		(dscp_nibble_index << TOPAZ_EMAC_IPDSCP_HWT_SHIFT));
	dscp_reg_val |= (tid & 0xF) <<
		(dscp_nibble_index << TOPAZ_EMAC_IPDSCP_HWT_SHIFT);

	qtn_emac_wr(reg_base, TOPAZ_EMAC_RXP_IP_DIFF_SRV_TID_REG(dscp_reg_index), dscp_reg_val);
}
#endif

static inline void qdrv_sch_mask_settid(uint8_t ifindex, uint8_t dscp, uint8_t tid,
		uint32_t emac_in_use)
{
	qdrv_dscp2tid_setvalue(ifindex, dscp, tid);
#if !defined(CONFIG_TOPAZ_PCIE_HOST) && !defined(CONFIG_TOPAZ_PCIE_TARGET)
	qdrv_sch_set_vlanpath();
	if (ifindex == 0) {
		if (emac_in_use & QDRV_SCH_EMAC0_IN_USE) {
			qdrv_sch_set_dscp_hwtbl(dscp, tid, RUBY_ENET0_BASE_ADDR);
		}
		if (emac_in_use & QDRV_SCH_EMAC1_IN_USE) {
			qdrv_sch_set_dscp_hwtbl(dscp, tid, RUBY_ENET1_BASE_ADDR);
		}
	}
#endif
}

const char *qdrv_sch_tos2ac_str(int tos);
void qdrv_sch_set_ac_map(int tos, int aid);

int qdrv_sch_set_dscp2ac_map(const uint8_t vapid, uint8_t *ip_dscp, uint8_t listlen, uint8_t ac);
int qdrv_sch_get_dscp2ac_map(const uint8_t vapid, uint8_t *dscp2ac);

void qdrv_sch_set_dscp2tid_map(const uint8_t vapid, const uint8_t *dscp2tid);
void qdrv_sch_get_dscp2tid_map(const uint8_t vapid, uint8_t *dscp2tid);

#endif

