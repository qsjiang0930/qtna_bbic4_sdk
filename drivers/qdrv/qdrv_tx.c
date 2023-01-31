/**
  Copyright (c) 2008 - 2013 Quantenna Communications Inc
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

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/version.h>

#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/jhash.h>
#include <net/sch_generic.h>
#include <net/ip6_checksum.h>
#include <asm/hardware.h>
#include <asm/board/dma_cache_ops.h>
#include "qdrv_features.h"
#include "qdrv_debug.h"
#include "qdrv_mac.h"
#include "qdrv_soc.h"
#include "qdrv_comm.h"
#include "qdrv_wlan.h"
#include "qdrv_vap.h"
#include "qtn/qdrv_sch.h"
#include "qdrv_bridge.h"
#include "qdrv_muc_stats.h"
#include "qdrv_pktlogger.h"
#include "qdrv_vlan.h"
#include <qtn/qtn_buffers.h>
#include <qtn/qtn_global.h>
#include <qtn/registers.h>
#include <qtn/lhost_muc_comm.h>
#include <qtn/qtn_vlan.h>
#include <qtn/iputil.h>
#include <net80211/if_llc.h>
#include <net80211/if_ethersubr.h>
#include <common/queue.h>
#include <asm/cacheflush.h>
#include <linux/if_arp.h>
#include <net/arp.h>
#include <linux/inetdevice.h>
#include <trace/skb.h>
#include <trace/ippkt.h>
#include "qtn/shared_defs.h"
#ifdef CONFIG_IPV6
#include <net/addrconf.h>
#endif

#include <qtn/topaz_tqe.h>
#include <qtn/topaz_hbm.h>
#include <qtn/topaz_fwt_sw.h>

#define QDRV_WBSP_CTRL_DISABLED	0
#define QDRV_WBSP_CTRL_ENABLED	1
extern int qdrv_wbsp_ctrl;

#define HTTPS_PORT 443
#define ETHER_TYPE_UNKNOWN 0XFFFF
#define QTN_RSSI_FOR_AMPDU_91DBM (-910)
#define QTN_RSSI_FOR_AMPDU_88DBM (-880)
#define QTN_RSSI_FOR_AMPDU_80DBM (-800)

static int qos_acm_remap[4] = {
	WMM_AC_BK,
	WMM_AC_BK,
	WMM_AC_BE,
	WMM_AC_VI
};

static inline uint32_t qdrv_tx_data_max_count(const struct qdrv_wlan *qw)
{
	return qw->tx_if.list_max_size - 1;
}

static inline uint32_t qdrv_tx_80211_max_count(const struct qdrv_wlan *qw)
{
	return QDRV_MAX_QUEUED_MGMT_FRAMES;
}

static inline bool is_qtn_oui_packet(unsigned char *pkt_header)
{
	if ((pkt_header[0] == (QTN_OUI & 0xFF)) &&
		(pkt_header[1] == ((QTN_OUI >> 8) & 0xFF)) &&
		(pkt_header[2] == ((QTN_OUI >> 16) & 0xFF)) &&
		(pkt_header[3] >= QTN_OUIE_WIFI_CONTROL_MIN) &&
		(pkt_header[3] <= QTN_OUIE_WIFI_CONTROL_MAX))
		return true;
	else
		return false;
}

/*
 * Find the first IP address for a device.
 */
__be32 qdrv_dev_ipaddr_get(struct net_device *dev)
{
	struct in_device *in_dev;
	__be32 addr = 0;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);
	if (in_dev && in_dev->ifa_list) {
		addr = in_dev->ifa_list->ifa_address;
	}
	rcu_read_unlock();

	return addr;
}

int qdrv_get_br_ipaddr(struct qdrv_wlan *qw, __be32 *ipaddr) {
	if (qw->br_dev) {
		*ipaddr = qdrv_dev_ipaddr_get(qw->br_dev);
	} else {
		return -1;
	}

	return 0;
}

int qdrv_is_bridge_ipaddr(struct qdrv_wlan *qw, __be32 ipaddr) {
	struct in_device *in_dev;
	struct in_ifaddr *addr;
	int match = 0;

	if (!qw->br_dev)
		return 0;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(qw->br_dev);
	if (in_dev) {
		for (addr = in_dev->ifa_list; addr; addr = addr->ifa_next) {
			if (addr->ifa_address == ipaddr) {
				match = 1;
				break;
			}
		}
	}
	rcu_read_unlock();

	return match;
}

static __sram_text void qdrv_tx_skb_return(struct qdrv_wlan *qw, struct sk_buff *skb)
{
        struct ieee80211_node *ni = QTN_SKB_CB_NI(skb);
        struct qtn_skb_recycle_list *recycle_list = qtn_get_shared_recycle_list();

        if (likely(ni)) {
                QTN_SKB_CB_NI(skb) = NULL;
                ieee80211_free_node(ni);
        }

        if (qtn_skb_recycle_list_push(recycle_list, &recycle_list->stats_qdrv, skb)) {
                if (likely(qw)) {
                        qw->tx_stats.tx_min_cl_cnt = skb_queue_len(&recycle_list->list);
                }
        } else {
                dev_kfree_skb_any(skb);
        }
}

/*
 * Special handling for ARP packets when in 3-address mode.
 * Returns 0 if OK, or 1 if the frame should be dropped.
 * The original skb may be copied and modified.
 */
static int __sram_text qdrv_tx_3addr_check_arp(struct sk_buff **skb, struct qdrv_wlan *qw,
	uint8_t *data_start)
{
	struct ether_arp *arp = (struct ether_arp *)data_start;
	struct sk_buff *skb1 = *skb;
	struct sk_buff *skb2;
	struct ieee80211_node *ni;
	__be32 ipaddr = 0;

	if ((skb1->len < (data_start - skb1->data) + sizeof(*arp)) ||
		 (!(arp->ea_hdr.ar_op == __constant_htons(ARPOP_REQUEST)) &&
			 !(arp->ea_hdr.ar_op == __constant_htons(ARPOP_REPLY)))) {
		return 0;
	}

	DBGPRINTF(DBG_LL_CRIT, QDRV_LF_BRIDGE,
		"ARP hrd=%04x pro=%04x ln=%02x/%02x op=%04x sha=%pM tha=%pM\n",
		arp->ea_hdr.ar_hrd, arp->ea_hdr.ar_pro, arp->ea_hdr.ar_hln,
		arp->ea_hdr.ar_pln, arp->ea_hdr.ar_op,
		arp->arp_sha, arp->arp_tha);
	DBGPRINTF(DBG_LL_CRIT, QDRV_LF_BRIDGE,
		"    sip=" NIPQUAD_FMT " tip=" NIPQUAD_FMT " new sha=%pM\n",
		NIPQUAD(arp->arp_spa), NIPQUAD(arp->arp_tpa), qw->ic.ic_myaddr);

	if (QDRV_FLAG_3ADDR_BRIDGE_ENABLED()) {
		/* update the qdrv bridge table if doing 3-address mode bridging */
		qdrv_br_uc_update_from_arp(&qw->bridge_table, arp);
	} else {
		/*
		 * In basic 3-address mode, don't send ARP requests for our own
		 * bridge IP address to the wireless network because the hack
		 * below will associate it with the wireless MAC, making the
		 * bridge IP address unreachable.  The bridge module will
		 * respond to the request.
		 */
		if (arp->ea_hdr.ar_op == __constant_htons(ARPOP_REQUEST)) {
			ipaddr = get_unaligned((uint32_t *)&arp->arp_tpa);
			if (qdrv_is_bridge_ipaddr(qw, ipaddr)) {
				DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_BRIDGE,
						"Not forwarding ARP request for bridge IP ("
						NIPQUAD_FMT ")\n",
						NIPQUAD(ipaddr));
				return 1;
			}
		}
	}

	/*
	 * ### Hack alert ###
	 * In 3-addr mode, the source host address in upstream ARP packets from
	 * the STA must be changed to the local wireless address.  Use a new
	 * skb to avoid modifying the bridge's copy of the frame.
	 */
	skb2 = skb_copy(skb1, GFP_ATOMIC);
	if (!skb2) {
		DBGPRINTF_E("ARP buffer copy failed\n");
		return 1;
	}
	ni = QTN_SKB_CB_NI(skb1);
	if (ni) {
		ieee80211_ref_node(ni);
	}

	/* The offset of the arp structure in the new skb is the same as in the old skb */
	arp = (struct ether_arp *)(skb2->data + ((unsigned char *)arp - skb1->data));
	IEEE80211_ADDR_COPY(&arp->arp_sha[0], qw->ic.ic_myaddr);

	qdrv_tx_skb_return(qw, skb1);
	*skb = skb2;

	return 0;
}

#if defined(CONFIG_IPV6)
static inline
struct nd_opt_hdr *qdrv_tx_icmpv6_masq_opt(struct icmp6hdr *icmpv6h, int icmp6_len)
{
	switch (icmpv6h->icmp6_type) {
	case NDISC_NEIGHBOUR_SOLICITATION:
		return iputil_ipv6_ndisc_get_opt(
			(struct nd_opt_hdr *)(((uint8_t *)icmpv6h) + sizeof(struct nd_msg)),
			icmp6_len - sizeof(struct nd_msg), ND_OPT_SOURCE_LL_ADDR);
	case NDISC_NEIGHBOUR_ADVERTISEMENT:
		return iputil_ipv6_ndisc_get_opt(
			(struct nd_opt_hdr *)(((uint8_t *)icmpv6h) + sizeof(struct nd_msg)),
			icmp6_len - sizeof(struct nd_msg), ND_OPT_TARGET_LL_ADDR);
	case NDISC_ROUTER_SOLICITATION:
		return iputil_ipv6_ndisc_get_opt(
			(struct nd_opt_hdr *)(((uint8_t *)icmpv6h) + sizeof(struct rs_msg)),
			icmp6_len - sizeof(struct rs_msg), ND_OPT_SOURCE_LL_ADDR);
	case NDISC_ROUTER_ADVERTISEMENT:
		return iputil_ipv6_ndisc_get_opt(
			(struct nd_opt_hdr *)(((uint8_t *)icmpv6h) + sizeof(struct ra_msg)),
			icmp6_len - sizeof(struct ra_msg), ND_OPT_SOURCE_LL_ADDR);
	default:
		return NULL;
	}
}

/*
 * Special handling for IPv6 packets when in 3-address mode.
 * Returns 0 if OK, or 1 if the frame should be dropped.
 * The original skb may be copied and modified.
 */
static int __sram_text qdrv_tx_3addr_check_ipv6(struct sk_buff **skb, struct qdrv_wlan *qw,
			uint8_t *data_start)
{
	struct sk_buff *skb1 = *skb;
	struct ethhdr *eth = (struct ethhdr *)skb1->data;
	struct ipv6hdr *ipv6h;
	struct sk_buff *skb2;
	struct ieee80211_node *ni;
	struct icmp6hdr *icmpv6h;
	struct nd_opt_hdr *opt;
	int l3hdr_off = data_start - skb1->data;
	int l4hdr_off;
	int icmpv6_len;
	uint8_t nexthdr;

	if (skb1->len < l3hdr_off + sizeof(struct ipv6hdr))
		return 0;

	skb2 = skb_copy(skb1, GFP_ATOMIC);
	if (!skb2) {
		DBGPRINTF_E("SKB buffer copy failed\n");
		return 1;
	}

	ni = QTN_SKB_CB_NI(skb1);
	if (ni) {
		ieee80211_ref_node(ni);
	}

	data_start = skb2->data + (data_start - skb1->data);

	qdrv_tx_skb_return(qw, skb1);

	eth = (struct ethhdr *)(skb2->data);
	ipv6h = (struct ipv6hdr *)data_start;

	qdrv_br_ipv6uc_update_from_dst_ipv6(&qw->bridge_table, eth, ipv6h);

	l4hdr_off = iputil_v6_skip_exthdr(ipv6h, sizeof(struct ipv6hdr),
			&nexthdr, skb2->len - l3hdr_off, NULL, NULL);

	if (nexthdr == IPPROTO_ICMPV6) {
		icmpv6h = (struct icmp6hdr *)(data_start + l4hdr_off);

		opt = qdrv_tx_icmpv6_masq_opt(icmpv6h, skb2->len - l3hdr_off - l4hdr_off);

		if (opt) {
			IEEE80211_ADDR_COPY((uint8_t *)(opt + 1), qw->ic.ic_myaddr);
			icmpv6_len = skb2->len - l3hdr_off - l4hdr_off;

			icmpv6h->icmp6_cksum = 0;
			icmpv6h->icmp6_cksum = csum_ipv6_magic(&ipv6h->saddr, &ipv6h->daddr,
					icmpv6_len, IPPROTO_ICMPV6,
					csum_partial(icmpv6h, icmpv6_len, 0));
		}
	}

	IEEE80211_ADDR_COPY(eth->h_source, qw->ic.ic_myaddr);
	*skb = skb2;

	return 0;
}
#endif

/*
 * Special handling for IP packets when in 3-address mode.
 * Returns 0 if OK, or 1 if the frame should be dropped.
 */
static int __sram_text qdrv_tx_3addr_check_ip(struct sk_buff *skb,
	struct qdrv_wlan *qw, struct ether_header *eh, uint8_t *data_start)
{
	struct iphdr *p_iphdr = (struct iphdr *)data_start;
	int updated = 0;

	if (skb->len < (data_start - skb->data) + sizeof(*p_iphdr))
		return 0;

	switch (p_iphdr->protocol) {
	case IPPROTO_UDP:
		updated = qdrv_br_uc_update_from_dhcp(&qw->bridge_table, skb, p_iphdr);
		break;
	case IPPROTO_IGMP:
		if (qdrv_br_mc_update_from_igmp(&qw->bridge_table,
						skb, eh, p_iphdr) != 0) {
			DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_BRIDGE|QDRV_LF_PKT_TX,
					"Dropping IGMP packet - "
					"not last downstream client to unsubscribe\n");
			return 1;
		}
		break;
	default:
		break;
	}

	if (!updated)
		qdrv_br_uc_update_from_dst_ip(&qw->bridge_table, skb, eh, p_iphdr);

	return 0;
}

static void __sram_text qdrv_tx_stop_queue(struct qdrv_wlan *qw)
{
	struct qdrv_mac *mac = qw->mac;
	int i;

	QDRV_TX_CTR_INC(8);

	for (i = 0; i <= mac->vnet_last; ++i) {
		if (mac->vnet[i]) {
			netif_stop_queue(mac->vnet[i]);
		}
	}
}

static void __sram_text qdrv_tx_wake_queue(struct qdrv_wlan *qw)
{
	struct qdrv_mac *mac = qw->mac;
	int i;

	QDRV_TX_CTR_INC(9);

	for (i = 0; i <= mac->vnet_last; ++i) {
		if (mac->vnet[i]) {
			netif_wake_queue(mac->vnet[i]);
		}
	}
}

static void __sram_text qdrv_tx_disable_queues(struct qdrv_wlan *qw)
{
	struct host_txif *txif = &qw->tx_if;
	unsigned long flags;

	if (qw->queue_enabled == 0) {
		return;
	}

	TXSTAT(qw, tx_queue_stop);

	QDRV_TX_CTR_INC(10);
	spin_lock_irqsave(&qw->lock, flags);

	qdrv_tx_stop_queue(qw);

	qw->queue_enabled = 0;

	if (unlikely(txif->txdesc_cnt[QDRV_TXDESC_MGMT] == 0)) {
		printk_once(DBGEFMT "MuC is dead!\n", DBGARG);
		qw->mac->mgmt_dead = 1;
		qdrv_mac_disable_irq(qw->mac, qw->txdoneirq);
		qdrv_mac_die_action(qw->mac);
	}

	spin_unlock_irqrestore(&qw->lock, flags);
}

static void __sram_text qdrv_tx_enable_queues(struct qdrv_wlan *qw)
{
	qw->queue_enabled = 1;
	qdrv_tx_wake_queue(qw);

	QDRV_TX_CTR_INC(11);
	TXSTAT(qw, tx_done_enable_queues);
}

static __always_inline struct lhost_txdesc *qdrv_tx_done_mbox(struct qdrv_wlan *qw)
{
	uint32_t ret = readl(qw->scan_if.sc_req_mbox);

	if (likely(ret)) {
		writel_wmb(0, qw->scan_if.sc_req_mbox);
	}

	return (struct lhost_txdesc*)ret;
}

static __sram_text void qdrv_tx_free_txdesc(struct qdrv_wlan *qw, struct lhost_txdesc *txdesc,
						int is_80211_encap)
{
	struct host_txif *txif = &qw->tx_if;

	++qw->tx_if.txdesc_cnt[is_80211_encap];

	if (likely(!is_80211_encap)) {
		txdesc->next = NULL;
		if (txif->df_txdesc_list_tail) {
			txif->df_txdesc_list_tail->next = txdesc;
			txif->df_txdesc_list_tail = txdesc;
		} else {
			txif->df_txdesc_list_head = txdesc;
			txif->df_txdesc_list_tail = txdesc;
		}
	} else {
		dma_pool_free(txif->df_txdesc_cache,
			txdesc->hw_desc.hd_va, txdesc->hw_desc.hd_pa);
	}
}

static __sram_text struct lhost_txdesc *qdrv_tx_alloc_txdesc(struct qdrv_wlan *qw, int is_80211_encap)
{
	struct host_txif *txif = &qw->tx_if;
	struct lhost_txdesc *ret = NULL;
	unsigned long flags;

	local_irq_save(flags);

	if (likely(txif->df_txdesc_list_head)) {
		ret = txif->df_txdesc_list_head;
		txif->df_txdesc_list_head = txif->df_txdesc_list_head->next;
		if (!txif->df_txdesc_list_head) {
			txif->df_txdesc_list_tail = NULL;
		}
	} else {
		dma_addr_t phys;
		ret = (struct lhost_txdesc*)
			dma_pool_alloc(txif->df_txdesc_cache, GFP_ATOMIC | GFP_DMA, &phys);
		if (ret) {
			ret->hw_desc.hd_pa = phys;
			ret->hw_desc.hd_va = ret;
		}
	}

	if (likely(ret)) {
		--qw->tx_if.txdesc_cnt[is_80211_encap];
	}

	local_irq_restore(flags);

	return ret;
}

void __sram_text qdrv_tx_release_txdesc(struct qdrv_wlan *qw, struct lhost_txdesc* txdesc)
{
	int is_80211_encap = 1;
	struct sk_buff *skb = txdesc->skb;
	struct ieee80211_node *ni;

	skb = txdesc->skb;
	QDRV_TX_CTR_INC(38);

	if (likely(skb)) {
		QDRV_TX_CTR_INC(39);
		is_80211_encap = QTN_SKB_ENCAP_IS_80211(skb);

		trace_skb_perf_stamp_call(skb);
		trace_skb_perf_finish(skb);

		ni = QTN_SKB_CB_NI(skb);
		if (likely(ni)) {
			if (txdesc->hw_desc.hd_txstatus == QTN_TXSTATUS_TX_SUCCESS) {
				TXSTAT(qw, tx_done_success);
			}
		}

		qdrv_tx_skb_return(qw, skb);
	}

	qdrv_tx_free_txdesc(qw, txdesc, is_80211_encap);
}

static __always_inline void qdrv_tx_done(struct qdrv_wlan *qw)
{
	struct lhost_txdesc *iter;
	struct lhost_txdesc *txdesc;
	uint32_t cnt = 0;

	QDRV_TX_CTR_INC(36);

	iter = qdrv_tx_done_mbox(qw);

	while (iter) {
		QDRV_TX_CTR_INC(37);
		txdesc = iter;
		iter = (struct lhost_txdesc*)txdesc->hw_desc.hd_nextva_rev;
		cnt++;

		if (txdesc->hw_desc.hd_status == MUC_TXSTATUS_DONE) {
			qdrv_tx_release_txdesc(qw, txdesc);
			TXSTAT(qw, tx_complete);
		} else {
			TXSTAT(qw, tx_done_muc_ready_err);
		}
	}

	if (!qw->queue_enabled && (cnt > 0)) {
		QDRV_TX_CTR_INC(17);
		qdrv_tx_enable_queues(qw);
	}
}

static void __sram_text qdrv_tx_done_irq(void *arg1, void *arg2)
{
	struct qdrv_mac *mac = (struct qdrv_mac *)arg1;
	struct qdrv_wlan *qw = mac->data;

	QDRV_TX_CTR_INC(13);
	qdrv_tx_done(qw);
}

static __always_inline int qdrv_txdesc_queue_is_empty(struct qdrv_wlan *qw)
{
	struct host_txif *txif = &qw->tx_if;

	if ((txif->txdesc_cnt[QDRV_TXDESC_DATA] == 0) ||
			(txif->txdesc_cnt[QDRV_TXDESC_MGMT] == 0)) {
		return 1;
	}

	return 0;
}

static int __sram_text qdrv_tx_done_chk(struct qdrv_wlan *qw)
{
	if (unlikely(qdrv_txdesc_queue_is_empty(qw))) {
		QDRV_TX_CTR_INC(42);
		qdrv_tx_disable_queues(qw);
		return -1;
	}

	return 0;
}

static void qdrv_tx_done_flush_vap_fail(struct qdrv_wlan *qw,
		struct qdrv_vap *qv, unsigned long time_start)
{
	struct host_txif *txif = &qw->tx_if;

	panic(KERN_ERR
		"%s MuC packets not returned: data %d/%d mgmt %d/%d muc_queued vap %u %u msecs\n",
		__FUNCTION__,
		txif->txdesc_cnt[QDRV_TXDESC_DATA],
		qdrv_tx_data_max_count(qw),
		txif->txdesc_cnt[QDRV_TXDESC_MGMT],
		qdrv_tx_80211_max_count(qw),
		qv->muc_queued,
		jiffies_to_msecs((long)jiffies - (long)time_start));
}

void qdrv_tx_done_flush_vap(struct qdrv_vap *qv)
{
	struct qdrv_wlan *qw = qv->parent;
	unsigned long time_start = jiffies;
	unsigned long time_limit = time_start + HZ * 5;
	int muc_queued_start = qv->muc_queued;
	int muc_queued_last = muc_queued_start;
	int delta;
	unsigned long flags;

	while (1) {
		local_irq_save(flags);
		qdrv_tx_done(qw);
		local_irq_restore(flags);

		delta = muc_queued_last - qv->muc_queued;
		if (delta) {
			time_limit = jiffies + HZ * 5;
		}
		muc_queued_last = qv->muc_queued;

		if (qv->muc_queued == 0) {
			break;
		} else if (time_after(jiffies, time_limit)) {
			qdrv_tx_done_flush_vap_fail(qw, qv, time_start);
		}

		msleep(1000 / HZ);
	}

	printk(KERN_INFO "%s: %d bufs retrieved in %u msecs\n",
			__FUNCTION__, muc_queued_start,
			jiffies_to_msecs(jiffies - time_start));
}

static __always_inline struct host_txdesc *qdrv_tx_prepare_hostdesc(
	struct qdrv_wlan *qw, struct sk_buff *skb,
	uint8_t devid, uint8_t tid, uint8_t ac, uint16_t node_idx_mapped, int is_80211_encap)
{
	struct lhost_txdesc *lhost_txdesc = qdrv_tx_alloc_txdesc(qw, is_80211_encap);
	struct host_txdesc *txdesc;

	QDRV_TX_CTR_INC(27);
	if (!lhost_txdesc) {
		QDRV_TX_CTR_INC(28);
		return NULL;
	}

	lhost_txdesc->skb = skb;

	txdesc = &lhost_txdesc->hw_desc;
	txdesc->hd_tid = tid;
	txdesc->hd_node_idx = IEEE80211_NODE_IDX_UNMAP(node_idx_mapped);
	txdesc->hd_txstatus = QTN_TXSTATUS_TX_ON_MUC;
	txdesc->hd_wmmac = ac;
	txdesc->hd_pktlen = skb->len;
	txdesc->hd_ts = jiffies;
	txdesc->hd_nextpa = 0;
	txdesc->hd_seglen[0] = skb->len;
	txdesc->hd_flags = 0;
	txdesc->hd_muc_txdone_cb = NULL;
	txdesc->hd_status = MUC_TXSTATUS_READY;

	return txdesc;
}

static int qdrv_is_old_intel(struct ieee80211_node *ni)
{
	u_int16_t peer_cap = IEEE80211_HTCAP_CAPABILITIES(&ni->ni_ie_htcap);

	return (ieee80211_node_is_intel(ni) &&
		!(peer_cap & IEEE80211_HTCAP_C_RXSTBC));
}

static int qdrv_tx_rssi_is_good_for_ba(struct ieee80211_node *ni, uint8_t tid)
{
	struct ieee80211com *ic = ni->ni_ic;
	int setup = 1;

	if ((ni->rssi_avg_dbm <= QTN_RSSI_FOR_AMPDU_91DBM) ||
		(ni->rssi_avg_dbm <= QTN_RSSI_FOR_AMPDU_80DBM &&
			qdrv_is_old_intel(ni))) {
		setup = 0;
	} else {
		if (ni->ni_ba_tx[tid].state == IEEE80211_BA_BLOCKED) {
			ieee80211_node_tx_ba_set_state(ni, tid, IEEE80211_BA_NOT_ESTABLISHED, 0);
		}
	}

	if (!setup) {
		ieee80211_node_tx_ba_set_state(ni, tid, IEEE80211_BA_BLOCKED, 0);
		if (ic->ic_htaddba)
			(*ic->ic_htaddba)(ni, tid, 1);
	}

	return setup;
}

static __always_inline int
qdrv_tx_ba_should_establish(struct ieee80211_node *ni, uint8_t tid, enum ieee80211_ba_state state)
{
	struct ieee80211vap *vap = ni->ni_vap;

	if (vap->tx_ba_disable) {
		return 0;
	}

	if ((ni->ni_qtn_flags & QTN_IS_INTEL_NODE)
				&& !IEEE80211_NODE_IS_VHT(ni)) {
		if (!qdrv_tx_rssi_is_good_for_ba(ni, tid))
			return 0;
	}

	return ((state == IEEE80211_BA_NOT_ESTABLISHED) ||
		(state == IEEE80211_BA_REQUESTED) ||
		(state == IEEE80211_BA_FAILED));
}

/*
 * Start block ack negotiation if needed.
 */
void qdrv_tx_ba_establish(struct qdrv_vap *qv,
		struct ieee80211_node *ni, uint8_t tid)
{
	struct ieee80211_ba_tid *ba = &ni->ni_ba_tx[tid];
	struct ieee80211vap *vap = &qv->iv;

	if (unlikely(qdrv_tx_ba_should_establish(ni, tid, ba->state) &&
			ieee80211_node_is_authorized(ni) &&
			((ni->ni_flags & IEEE80211_NODE_HT) ||
			(ni->ni_flags & IEEE80211_NODE_VHT)))) {

		enum ieee80211_ba_state state;
		unsigned long state_deadline;
		unsigned int seq;

		do {
			seq = read_seqbegin(&ba->state_lock);
			state = ba->state;
			state_deadline = ba->state_deadline;
		} while (read_seqretry(&ba->state_lock, seq));

		if (unlikely(qdrv_tx_ba_should_establish(ni, tid, state) &&
				((state_deadline == 0) ||
				 time_after_eq(jiffies, state_deadline)))) {
			IEEE80211_NOTE(vap, IEEE80211_MSG_OUTPUT, ni,
					"start block ack negotiation on aid %d node_idx %d tid %d",
					IEEE80211_NODE_AID(ni),
					IEEE80211_NODE_IDX_UNMAP(ni->ni_node_idx),
					tid);
			ieee80211_node_tx_ba_set_state(ni, tid, IEEE80211_BA_REQUESTED,
					IEEE80211_TX_BA_REQUEST_RETRY_TIMEOUT);
			ieee80211_ref_node(ni);
			if (!schedule_work(&ni->ni_tx_addba_task)) {
				/* Already scheduled */
				ieee80211_free_node(ni);
			}
		}
	}
}

static __sram_text void qdrv_tx_dropped(struct ieee80211vap *vap, struct qdrv_wlan *qw,
					struct ieee80211_node *ni)
{
	QDRV_TX_CTR_INC(58);
	if (vap) {
		vap->iv_devstats.tx_dropped++;
	}

	if (ni) {
		QDRV_TX_CTR_INC(59);
		IEEE80211_NODE_STAT(ni, tx_dropped);
	}

	if (qw) {
		TXSTAT(qw, tx_drop_total);
	}
}

/* If ACM bit is set for this AC, then this AC can't be  used. Lower the priority */
static __always_inline void qdrv_acm_bit_qos_remap(struct sk_buff *skb, struct ieee80211com *ic)
{
	while (ic->ic_wme.wme_chanParams.cap_wmeParams[skb->priority].wmm_acm &&
		(skb->priority != WMM_AC_BK)) {
		skb->priority = qos_acm_remap[skb->priority];
	}
}

static void qdrv_tx_store_soc_ipaddr(struct ether_arp *arp, struct ieee80211_node *ni)
{
	struct ieee80211com *ic = ni->ni_ic;

	if (arp->ea_hdr.ar_op == __constant_htons(ARPOP_REQUEST) ||
			arp->ea_hdr.ar_op == __constant_htons(ARPOP_REPLY)) {
		if (IEEE80211_ADDR_EQ(&arp->arp_sha[0], &ic->soc_addr[0])) {
			ic->ic_soc_ipaddr = (arp->arp_spa[3] << 24) |
					(arp->arp_spa[2] << 16) |
					(arp->arp_spa[1] << 8) |
					arp->arp_spa[0];
			DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_PKT_TX,
				"client soc mac=%pM ip=" NIPQUAD_FMT "\n",
				arp->arp_sha, NIPQUAD(arp->arp_spa));
		}
	}
}

static __sram_text void qdrv_tx_skb_drop(struct ieee80211vap *vap, struct qdrv_wlan *qw,
					struct ieee80211_node *ni, struct sk_buff *skb,
					enum trace_ippkt_drop_rsn drop_rsn)
{
	QDRV_TX_DBG(0, ni, "drop_rsn=%u\n", drop_rsn);
	if (drop_rsn != TRACE_IPPKT_DROP_RSN_SHOULD_DROP) {
		qdrv_tx_dropped(vap, qw, ni);
		trace_ippkt_dropped(drop_rsn, 1, 0);
	}

	if (skb) {
		qdrv_tx_skb_return(qw, skb);
	}
}

static uint8_t qdrv_tx_peer_use_4addr(const struct ieee80211_node *ni)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211_ie_qtn *qtnie = (struct ieee80211_ie_qtn *)(ni->ni_qtn_assoc_ie);

	if (vap->iv_opmode == IEEE80211_M_WDS)
		return 1;

	if (qtnie && (qtnie->qtn_ie_flags & IEEE80211_QTN_BRIDGEMODE)
			&& (vap->iv_flags_ext & IEEE80211_FEXT_WDS))
		return 1;

	if (!IEEE80211_CFG_4ADDR_ENABLED(vap))
		return 0;

	/* If 4-address headers are configured, always use in STA mode */
	if (vap->iv_opmode == IEEE80211_M_STA)
		return 1;

	/*
	 * Only use 4-address headers in AP mode if frames have beeen received from the STA with
	 * 4-address headers.
	 */
	if (!ni->ni_shared_stats->cfg_4addr)
		return 0;

	return 1;
}

static int qdrv_tx_fwt_use_4addr(void *_mac, uint8_t port, uint8_t node_num)
{
	struct qdrv_mac *mac = _mac;
	struct qdrv_wlan *qw = mac->data;
	struct ieee80211_node *ni;
	uint8_t use_4addr;

	if (port != TOPAZ_TQE_WMAC_PORT)
		return 0;

	ni = ieee80211_find_node_by_idx(&qw->ic, NULL, node_num);
	if (ni) {
		use_4addr = qdrv_tx_peer_use_4addr(ni);
		ieee80211_free_node(ni);
		return use_4addr;
	}

	return -EINVAL;
}

/*
 * This path is used in station mode.  In AP mode, EAPOL packets are sent directly from hostapd to
 * ieee80211_ioctl_txeapol() in the WLAN driver.
 */
static struct sk_buff *qdrv_tx_encap_eapol(struct qdrv_vap *const qv,
		struct ieee80211_node *const ni, struct sk_buff *const skb)
{
	struct qdrv_wlan *qw = qv->parent;
	const struct ether_header *const eh = (const struct ether_header *) skb->data;

	/* Ignore EAPOLs to WDS peers and EAPOLs not originating from the BSS node */
	if (qv->iv.iv_opmode == IEEE80211_M_WDS ||
			memcmp(eh->ether_shost, qv->iv.iv_myaddr, ETH_ALEN) != 0) {
		return skb;
	}

	ieee80211_eap_output(qv->iv.iv_dev, skb->data, skb->len);
	qdrv_tx_skb_drop(&qv->iv, qw, ni, skb, TRACE_IPPKT_DROP_RSN_AUTH);

	return NULL;
}

static __sram_text int qdrv_tx_to_auc(struct qdrv_vap *qv, struct sk_buff *skb)
{
	union topaz_tqe_cpuif_ppctl ctl;
	struct ieee80211_node *ni = QTN_SKB_CB_NI(skb);
	uint8_t port;
	uint8_t node;
	uint8_t tid;
	uint8_t use_4addr = 0;
	uint16_t misc_user = 0;
	int tqe_queued;

	if (likely(IEEE80211_NODE_IDX_VALID(skb->dest_port))) {
		node = IEEE80211_NODE_IDX_UNMAP(skb->dest_port);
		if (unlikely(node >= QTN_NCIDX_MAX)) {
			DBGPRINTF_LIMIT_E("%s: invalid idx %u\n", __func__,
				skb->dest_port);
			node = IEEE80211_NODE_IDX_UNMAP(qv->iv.iv_vapnode_idx);
		}
	} else {
		node = IEEE80211_NODE_IDX_UNMAP(qv->iv.iv_vapnode_idx);
	}

	if (QTN_SKB_ENCAP_IS_80211(skb)) {
		port = TOPAZ_TQE_MUC_PORT;
		misc_user = node;
		if (QTN_SKB_ENCAP_IS_80211_MGMT(skb) || !(ni->ni_flags & IEEE80211_NODE_QOS))
			tid = QTN_TID_MGMT;
		else
			tid = QTN_TID_WLAN;
	} else {
		port = TOPAZ_TQE_WMAC_PORT;
                tid = WME_AC_TO_TID(skb->priority);
		use_4addr = qdrv_tx_peer_use_4addr(ni);
		/* No AMSDU aggregation during training */
		if (unlikely(M_FLAG_ISSET(skb, M_NO_AMSDU)))
			misc_user |= TQE_MISCUSER_L2A_NO_AMSDU;

		if (unlikely(M_FLAG_ISSET(skb, M_RATE_TRAINING)))
			misc_user |= TQE_MISCUSER_ANY2A_MAY_APPEND;

		if (unlikely(QTN_SKB_CB_ETHERTYPE(skb) == htons(ETH_P_ARP)))
			misc_user |= TQE_MISCUSER_L2A_ARP;
	}

	if (likely(ni)) {
		/* always free ref when passing to TQE */
		ieee80211_free_node(ni);
	}

	topaz_tqe_cpuif_ppctl_init(&ctl,
			port, &node, 1, tid,
			use_4addr, 1, TOPAZ_HBM_BUF_EMAC_RX_POOL, 1, misc_user);
	tqe_queued = tqe_tx(&ctl, skb);

	/* FIXME: VLAN needs a rework not to copy the skb, before that we free it if failed */
	if (tqe_queued == NETDEV_TX_BUSY)
		kfree_skb(skb);

	return NET_XMIT_SUCCESS;
}

static __sram_text void qdrv_tx_stats_prot(struct net_device *vdev, struct sk_buff *skb)
{
	struct qdrv_vap *qv = netdev_priv(vdev);
	struct qdrv_wlan *qw = qv->parent;
	uint16_t ether_type = QTN_SKB_CB_ETHERTYPE(skb);
	uint8_t ip_proto = QTN_SKB_CB_IPPROTO(skb);

	qdrv_wlan_stats_prot(qw, 1, ether_type, ip_proto);
}

/*
 * A node reference must be held before calling this function.  It will be released
 * during tx_done processing.
 */
static __sram_text int qdrv_tx_enqueue_to_node(struct qdrv_wlan *qw,
		struct ieee80211_node *ni, struct sk_buff *skb)
{
	struct qdrv_vap *qv = container_of(ni->ni_vap, struct qdrv_vap, iv);
	struct net_device *dev = qv->iv.iv_dev;

	QDRV_TX_CTR_INC(53);
	skb->dev = dev;

	if (!QTN_SKB_ENCAP_IS_80211(skb))
		qdrv_tx_stats_prot(skb->dev, skb);

	return qdrv_tx_to_auc(qv, skb);
}

static __always_inline bool
qdrv_tx_is_unauth_bcast_allowed(const struct ieee80211vap *vap, const struct ieee80211_node *ni)
{
	return ((ni == vap->iv_bss) && (vap->iv_opmode != IEEE80211_M_STA));
}

static __sram_text int
qdrv_tx_unauth_node_data_drop(struct qdrv_wlan *qw, struct ieee80211_node *ni, struct sk_buff *skb)
{
	struct ieee80211vap *vap = ni->ni_vap;

	if (unlikely(!ieee80211_node_is_authorized(ni) &&
			!qdrv_tx_is_unauth_bcast_allowed(vap, ni) &&
			(QTN_SKB_CB_ETHERTYPE(skb) != __constant_htons(ETH_P_PAE)))) {
		vap->iv_stats.is_tx_unauth++;
		vap->iv_devstats.tx_errors++;
		IEEE80211_NODE_STAT(ni, tx_unauth);
		IEEE80211_NODE_STAT(ni, tx_errors);
		qdrv_tx_skb_drop(vap, qw, ni, skb, TRACE_IPPKT_DROP_RSN_AUTH);
		TXSTAT(qw, tx_drop_auth);
		return -1;
	}

	return 0;
}

static int qdrv_tx_is_br_isolate(struct qdrv_wlan *qw, struct sk_buff *skb,
		uint16_t ether_type, uint8_t *l3_data_start)
{
	/*
	 * The RGMII bridge interface is only used for RPC communication with the host
	 * device, so do not forward ARP requests or replies to the wireless interface.
	 */
	if ((qw->br_isolate & QDRV_BR_ISOLATE_NORMAL)
			&& (ether_type == __constant_htons(ETH_P_ARP))) {
		struct ether_arp *arp = (struct ether_arp *)l3_data_start;
		__be32 ipaddr = 0;

		if (arp->ea_hdr.ar_op == __constant_htons(ARPOP_REQUEST)) {
			ipaddr = get_unaligned((uint32_t *)&arp->arp_tpa);
		} else if (arp->ea_hdr.ar_op == __constant_htons(ARPOP_REPLY)) {
			ipaddr = get_unaligned((uint32_t *)&arp->arp_spa);
		}

		if (qdrv_is_bridge_ipaddr(qw, ipaddr))
			return 1;
	}


	if (qw->br_isolate & QDRV_BR_ISOLATE_VLAN) {
		uint16_t vlanid;

		if (skb->vlan_tci && qw->br_isolate_vid == QVLAN_VID_ALL)
			return 1;

		vlanid = skb->vlan_tci & VLAN_VID_MASK;
		if (qw->br_isolate_vid == vlanid)
			return 1;
	}

	return 0;
}

/*
 * Prepare and enqueue a data frame for transmission.
 * If a node pointer is passed in, a node reference must have been acquired.
 * Returns NET_XMIT_SUCCESS if the frame is enqueued.
 * Returns NET_XMIT_DROP if the frame is dropped, in which case the skb and noderef have been freed.
 */
static __sram_text int qdrv_tx_prepare_data_frame(struct qdrv_wlan *qw, struct qdrv_vap *qv,
		struct ieee80211_node *ni, struct sk_buff *skb)
{
	struct ieee80211vap *vap = &qv->iv;
	struct ether_header *eh = (struct ether_header *) skb->data;
	uint16_t ether_type;
	uint8_t *data_start = qdrv_sch_find_data_start(skb, eh, &ether_type);
	struct iphdr *iphdr_p = (struct iphdr *) data_start;
	void *proto_data = NULL;
	uint8_t ip_proto = iputil_proto_info(iphdr_p, skb, &proto_data, NULL, NULL);
	struct udphdr *udph = proto_data;
	struct dhcp_message *dhcp_msg = (struct dhcp_message*)((uint8_t*)udph +
					sizeof(struct udphdr));
	struct ether_arp *arp = (struct ether_arp *)data_start;
	uint8_t tid = 0;
	uint8_t ac = 0;
	uint32_t ipaddr;
	uint32_t data_len;
	int drop = 0;

	qdrv_sch_classify(skb, ether_type, data_start);

	if (qv->iv.iv_opmode == IEEE80211_M_STA) {
		qdrv_acm_bit_qos_remap(skb, vap->iv_ic);
	}
	if ((ether_type == __constant_htons(ETH_P_IP)) &&
			(skb->len >= (data_start - skb->data) + sizeof(*iphdr_p)) &&
			(ip_proto == IPPROTO_IGMP)) {
		TXSTAT(qw, tx_igmp);
#ifdef CONFIG_IPV6
	} else if (ether_type == __constant_htons(ETH_P_IPV6)) {
		data_len = skb->len - (data_start - skb->data);
		if (iputil_eth_is_v6_mld(data_start, data_len)) {
			TXSTAT(qw, tx_igmp);
		}
#endif
	}

	/* drop Wi-Fi control messages */
	if (unlikely((qv->iv.iv_opmode == IEEE80211_M_STA) &&
			(ether_type == __constant_htons(ETHERTYPE_802A)) &&
			(data_start[0] == (QTN_OUI & 0xFF)) &&
			(data_start[1] == ((QTN_OUI >> 8) & 0xFF)) &&
			(data_start[2] == ((QTN_OUI >> 16) & 0xFF)) &&
			(data_start[3] >= QTN_OUIE_WIFI_CONTROL_MIN) &&
			(data_start[3] <= QTN_OUIE_WIFI_CONTROL_MAX))) {
		qdrv_tx_skb_drop(vap, qw, ni, skb, TRACE_IPPKT_DROP_RSN_CTRL);
		return NET_XMIT_DROP;
	}

	if (qdrv_tx_is_br_isolate(qw, skb, ether_type, data_start)) {
		qdrv_tx_skb_drop(vap, qw, ni, skb, TRACE_IPPKT_DROP_RSN_RGMII);
		return NET_XMIT_DROP;
	}

	if ((vap->iv_opmode == IEEE80211_M_STA) &&
			!(vap->iv_flags_ext & IEEE80211_FEXT_WDS) &&
			!IEEE80211_IS_MULTICAST(eh->ether_shost) &&
			!IEEE80211_CFG_4ADDR_ENABLED(vap)) {

		if (QDRV_FLAG_3ADDR_BRIDGE_ENABLED()) {
			if (ether_type == __constant_htons(ETH_P_IP)) {
				drop = qdrv_tx_3addr_check_ip(skb, qw, eh, data_start);
			}
#if defined(CONFIG_IPV6)
			else if (ether_type == __constant_htons(ETH_P_IPV6)) {
				drop = qdrv_tx_3addr_check_ipv6(&skb, qw, data_start);
			}
#endif

			if (drop) {
				qdrv_tx_skb_drop(vap, qw, ni, skb, TRACE_IPPKT_DROP_RSN_3ADDR);
				TXSTAT(qw, tx_drop_3addr);
				return NET_XMIT_DROP;
			}
		}

		if (ether_type == __constant_htons(ETH_P_ARP)) {
			if (qdrv_tx_3addr_check_arp(&skb, qw, data_start) != 0) {
				qdrv_tx_skb_drop(vap, qw, ni, skb, TRACE_IPPKT_DROP_RSN_3ADDR);
				TXSTAT(qw, tx_drop_3addr);
				return NET_XMIT_DROP;
			}
		}

		/* skb may have been modified - adjust pointers */
		eh = (struct ether_header *)skb->data;

	} else if (qv->iv.iv_opmode == IEEE80211_M_HOSTAP && ni) {
		if (ether_type == __constant_htons(ETH_P_IP) &&
				ip_proto == IPPROTO_UDP &&
				udph->dest == __constant_htons(DHCPCLIENT_PORT) &&
				!memcmp(&ni->ni_macaddr[0], &dhcp_msg->chaddr[0], ETHER_ADDR_LEN)) {

			ni->ni_ip_addr = dhcp_msg->yiaddr;
			ni->ni_ip_addr_filter = IEEE80211_IP_ADDR_FILTER_DHCP_RSP;
		}

		if (ether_type == __constant_htons(ETH_P_ARP) &&
				arp->ea_hdr.ar_op == __constant_htons(ARPOP_REPLY) &&
				!memcmp(&ni->ni_macaddr[0], &arp->arp_tha[0], ETHER_ADDR_LEN)) {

			ipaddr = (arp->arp_tpa[3] << 24) |
				(arp->arp_tpa[2] << 16) |
				(arp->arp_tpa[1] << 8) |
				arp->arp_tpa[0];

			if (ipaddr && ni->ni_ip_addr != ipaddr) {
				ni->ni_ip_addr = ipaddr;
				ni->ni_ip_addr_filter = IEEE80211_IP_ADDR_FILTER_ARP_RSP;
			}
		}
	} else if (unlikely(ether_type == __constant_htons(ETH_P_ARP)) && (qv->iv.iv_opmode == IEEE80211_M_STA)) {
		qdrv_tx_store_soc_ipaddr(arp, ni);
	}

	if (unlikely(qdrv_tx_unauth_node_data_drop(qw, ni, skb) != 0)) {
		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_BRIDGE | QDRV_LF_PKT_TX,
			"drop Tx to unauth node S=%pM D=%pM type=0x%04x\n",
			eh->ether_shost, eh->ether_dhost, ether_type);
		return NET_XMIT_DROP;
	}

	if (vap->disable_dgaf &&
			IEEE80211_IS_MULTICAST(eh->ether_dhost) &&
			!ni->ni_qtn_assoc_ie) {
		qdrv_tx_skb_drop(vap, qw, ni, skb, TRACE_IPPKT_DROP_RSN_SHOULD_DROP);
		return NET_XMIT_DROP;
	}

	if ((ni->ni_qtn_flags & QTN_IS_INTEL_NODE) &&
			(ether_type == __constant_htons(ETH_P_ARP)) &&
		(qv->iv.iv_opmode == IEEE80211_M_HOSTAP)) {
			skb->priority = WMM_AC_BE;
	}

	ac = skb->priority;
	tid = (ni->ni_flags & IEEE80211_NODE_QOS) ? WMM_AC_TO_TID(ac) : 0;

	ni->ni_stats.ns_tx_data++;
	ni->ni_stats.ns_tx_bytes += skb->len;

	if (ether_type != __constant_htons(ETH_P_PAE)) {
		qdrv_tx_ba_establish(qv, ni, tid);
	} else {
		skb = qdrv_tx_encap_eapol(qv, ni, skb);
		if (skb == NULL) {
			return NET_XMIT_DROP;
		}
	}

	if (ETHER_IS_MULTICAST(eh->ether_dhost)) {
		if (!compare_ether_addr(eh->ether_dhost, vap->iv_dev->broadcast)) {
			vap->iv_devstats.tx_broadcast_packets++;
			ni->ni_stats.ns_tx_bcast++;
		} else {
			vap->iv_devstats.tx_multicast_packets++;
			ni->ni_stats.ns_tx_mcast++;
		}
	} else {
		vap->iv_devstats.tx_unicast_packets++;
		ni->ni_stats.ns_tx_ucast++;
	}

	DBGPRINTF(DBG_LL_INFO, QDRV_LF_BRIDGE | QDRV_LF_PKT_TX,
			"src=%pM dst=%pM to Node_idx %d: %pM TID=%d AC=%d type=%04x\n",
			eh->ether_shost, eh->ether_dhost,
			IEEE80211_NODE_IDX_UNMAP(ni->ni_node_idx), ni->ni_macaddr, tid, ac,
			ntohs(ether_type));

	return qdrv_tx_enqueue_to_node(qw, ni, skb);
}

/*
 * Duplicate a packet so it can be sent as a directed reliable frame to a given node.
 */
static __always_inline void qdrv_copy_to_node(struct ieee80211_node *ni,
			struct sk_buff *skb_orig, int convert_to_uc)
{
	struct qdrv_vap *qv = container_of(ni->ni_vap, struct qdrv_vap, iv);
	struct qdrv_wlan *qw = qv->parent;
	struct ether_header *eh;
	struct sk_buff *skb;

	skb = skb_copy(skb_orig, GFP_ATOMIC);
	if (!skb) {
		qdrv_tx_dropped(&qv->iv, qw, ni);
		TXSTAT(qw, tx_copy_fail);
		return;
	}

	skb->dest_port = ni->ni_node_idx;
	skb->is_recyclable = 1;

	if (convert_to_uc && !ni->ni_qtn_assoc_ie) {
		eh = (struct ether_header *)skb->data;
		IEEE80211_ADDR_COPY(eh->ether_dhost, ni->ni_macaddr);
		TXSTAT(qw, tx_copy_uc);
	} else {
		TXSTAT(qw, tx_copy4);
	}

	ieee80211_ref_node(ni);
	QTN_SKB_CB_NI(skb) = ni;

	qdrv_tx_prepare_data_frame(qw, qv, ni, skb);
}

/*
 * Periodically attempt to discover the location of unknown destination MAC addresses.
 */
static void __sram_text qdrv_tx_mac_discover(struct qdrv_wlan *qw, void *p_data)
{
	struct iphdr *p_iphdr = p_data;
	uint32_t ipaddr;
	__be32 addr;
#ifdef CONFIG_IPV6
	struct ipv6hdr *ip6hdr_p = p_data;
	struct in6_addr mcaddr;
	struct in6_addr *target;
#endif

	if (!qw->br_dev)
		return;

	if (likely(p_iphdr->version == 4)) {
		addr = qdrv_dev_ipaddr_get(qw->br_dev);
		if (!addr)
			return;
		ipaddr = get_unaligned((uint32_t *)&p_iphdr->daddr);

		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_BRIDGE,
				"sending ARP from " NIPQUAD_FMT " for " NIPQUAD_FMT " (%08x)\n",
				NIPQUAD(addr), NIPQUAD(ipaddr), ipaddr);

		TXSTAT(qw, tx_arp_req);

		arp_send(ARPOP_REQUEST, ETH_P_ARP,
				ipaddr,
				qw->br_dev,
				addr,
				NULL, qw->br_dev->dev_addr, NULL);
#ifdef CONFIG_IPV6
	} else if (p_iphdr->version == 6) {
		target = &ip6hdr_p->daddr;

		addrconf_addr_solict_mult(target, &mcaddr);
		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_BRIDGE,
				"sending neighbour solicitation from dev %s to IP "
				NIPV6OCTA_FMT "\n", qw->br_dev->name, NIPV6OCTA(target));
		TXSTAT(qw, tx_arp_req);

		ndisc_send_ns(qw->br_dev, NULL, target, &mcaddr, NULL);
#endif
	}
}

struct qdrv_tx_copy_params {
	struct sk_buff *skb;
	uint16_t check_flags;
	uint16_t check_4addr;
	uint32_t dbg_flags;
	const char *dbg_msg;
	uint16_t copy_cnt;
	uint16_t convert_to_uc;
};

static inline int
qdrv_tx_should_copy_4addr(struct ieee80211_node *ni, uint16_t check_4addr)
{
	return (check_4addr && ni->ni_shared_stats->cfg_4addr);
}

static void qdrv_tx_copy_to_node_cb(void *data, struct ieee80211_node *ni)
{
	struct qdrv_tx_copy_params *param = data;
	struct sk_buff *skb = param->skb;

	if (skb->src_port == ni->ni_node_idx)
		return;

	if (!(ni->ni_ext_flags & IEEE80211_NODE_IN_AUTH_STATE))
		return;

	if (!(ni->ni_ext_flags & param->check_flags) &&
			!qdrv_tx_should_copy_4addr(ni, param->check_4addr))
		return;

	param->copy_cnt++;

	DBGPRINTF(DBG_LL_NOTICE, param->dbg_flags,
		"%s to %pM\n",
		param->dbg_msg,
		ni->ni_macaddr);

	qdrv_copy_to_node(ni, skb, param->convert_to_uc);
}

static uint16_t
qdrv_tx_copy_to_multiple_nodes(struct ieee80211vap *vap, struct sk_buff *skb,
	uint16_t check_flags, uint16_t check_4addr, uint16_t convert_to_uc,
	uint32_t dbg_flags, const char *dbg_msg,
	const char *msg)
{
	struct qdrv_tx_copy_params param;

	if (msg)
		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_PKT_TX, "%s\n", msg);

	param.skb = skb;
	param.check_flags = check_flags;
	param.check_4addr = check_4addr;
	param.dbg_flags = dbg_flags;
	param.dbg_msg = dbg_msg;
	param.copy_cnt = 0;
	param.convert_to_uc = convert_to_uc;

	vap->iv_ic->ic_iterate_dev_nodes(vap->iv_dev, &vap->iv_ic->ic_sta,
		qdrv_tx_copy_to_node_cb, &param, 1);

	return param.copy_cnt;
}

/*
 * Copy a unicast packet to all bridge nodes.
 */
static __always_inline int qdrv_tx_copy_unknown_uc_to_nodes(struct qdrv_vap *qv,
		struct qdrv_wlan *qw, struct sk_buff *skb, struct net_device *dev,
		uint16_t ether_type, uint8_t *data_start)
{
	uint16_t copy_cnt;

	if (qw->flags_ext & QDRV_WLAN_FLAG_UNKNOWN_ARP) {
		if (time_after_eq(jiffies, qw->arp_last_sent + msecs_to_jiffies(qw->discover_intval))) {
			if (iputil_eth_is_ipv4or6(ether_type)) {
				qdrv_tx_mac_discover(qw, data_start);
				qw->arp_last_sent = jiffies;
			}
		}
	}

	if (qv->ni_bridge_cnt && (qw->flags_ext & QDRV_WLAN_FLAG_UNKNOWN_FWD)) {
		copy_cnt = qdrv_tx_copy_to_multiple_nodes(&qv->iv, skb,
			IEEE80211_NODE_QTN_BR, 0, 0,
			QDRV_LF_PKT_TX, "", NULL);
		TXSTAT_ADD(qw, tx_copy4_unknown, copy_cnt);
		return 0;
	}

	return 1;
}

static int qdrv_tx_uc_dhcp(struct ieee80211vap *vap, struct iphdr *p_iphdr,
			struct sk_buff *skb, uint8_t ip_proto, void *proto_data,
			uint8_t *p_dest_mac, uint16_t ether_type)
{
	struct udphdr *udph = proto_data;
	struct dhcp_message *dhcp_msg;
	struct ieee80211_node *ni;

	if (udph && IEEE80211_ADDR_BCAST(p_dest_mac) &&
			ether_type == __constant_htons(ETH_P_IP) &&
			ip_proto == IPPROTO_UDP &&
			udph->dest == __constant_htons(DHCPCLIENT_PORT)) {
		dhcp_msg = (struct dhcp_message*)((uint8_t*)udph +
						sizeof(struct udphdr));

		ni = ieee80211_find_node(&vap->iv_ic->ic_sta, &dhcp_msg->chaddr[0]);
		if (ni && (IEEE80211_AID(ni->ni_associd) != 0) &&
				IEEE80211_ADDR_EQ(vap->iv_myaddr, ni->ni_bssid)) {
			qdrv_copy_to_node(ni, skb, 1);
			ieee80211_free_node(ni);
			return 1;
		} else if (ni) {
			ieee80211_free_node(ni);
		}
	}

	return 0;
}

static int qdrv_handle_dgaf(struct ieee80211vap *vap, struct iphdr *p_iphdr,
		struct sk_buff *skb, uint8_t *p_dest_mac, uint16_t ether_type,
		uint8_t ip_proto, void *proto_data)
{
	struct icmp6hdr *icmp6hdr;

	/*
	 * Assume that DHCP server always runs in back end or in the AP.
	 * if DHCP packet from server to client is having broadcast
	 * destination address then convert to unicast to client
	 */
	if (qdrv_tx_uc_dhcp(vap, p_iphdr, skb, ip_proto,
				proto_data, p_dest_mac, ether_type)) {
		return 1;
	}

#ifdef CONFIG_IPV6
	if (ip_proto == IPPROTO_ICMPV6 && iputil_ipv6_is_ll_all_nodes_mc(p_dest_mac, p_iphdr)) {
		icmp6hdr = (struct icmp6hdr*)proto_data;
		if (icmp6hdr->icmp6_type == NDISC_ROUTER_ADVERTISEMENT) {
			qdrv_tx_copy_to_multiple_nodes(vap, skb,
				IEEE80211_NODE_IN_AUTH_STATE, 0, 1,
				QDRV_LF_PKT_TX, "", "Router Advertisement ucast");
			return 1; /* don't send as multicast */
		}
	}
#endif

	return 0;
}

static inline int qdrv_tx_sub_port_check(struct ieee80211vap *vap,
		struct ieee80211_node *ni, struct sk_buff *skb)
{
	int ret;
	int src_port;
	int dst_port;
	int ni_port;
	int vap_port;

	src_port = IEEE80211_NODE_IDX_UNMAP(skb->src_port);
	ni_port = IEEE80211_NODE_IDX_UNMAP(ni->ni_node_idx);
	dst_port = IEEE80211_NODE_IDX_UNMAP(skb->dest_port);
	vap_port = IEEE80211_NODE_IDX_UNMAP(vap->iv_vapnode_idx);

	ret = src_port && (src_port == ni_port) && (src_port != vap_port);

	if (!ret && dst_port && dst_port != ni_port && dst_port != vap_port)
		ret = 1;

	return ret;
}

static inline struct ieee80211_node *qdrv_tx_node_get_and_ref(struct ieee80211vap *vap,
			struct qdrv_wlan *qw, struct sk_buff *skb, uint8_t *p_dest_mac, uint8_t *vlan_group)
{
	struct ieee80211_node *ni = NULL;
	struct ieee80211_node *src_ni = NULL;
	struct qdrv_vap *qv = container_of(vap, struct qdrv_vap, iv);
	struct qtn_vlan_pkt *pkt;
	uint8_t vlan_group_mac[ETH_ALEN];
	int fwt_idx;
	fwt_db_entry *fwt_db;

	*vlan_group = 0;

	switch (vap->iv_opmode) {
	case IEEE80211_M_STA:
		if (!IEEE80211_IS_MULTICAST(p_dest_mac)) {
			if (skb->dest_port) {
				QDRV_TX_CTR_INC(50);
				ni = ieee80211_find_node_by_node_idx(vap, skb->dest_port);
			} else if (!IEEE80211_IS_MULTICAST(p_dest_mac)) {
				QDRV_TX_CTR_INC(51);
				ni = ieee80211_find_node(&vap->iv_ic->ic_sta, p_dest_mac);
			}

			if (ni && !ieee80211_node_is_running(ni)) {
				ieee80211_free_node(ni);
				ni = NULL;
			}
		}

		if (!ni) {
			QDRV_TX_CTR_INC(52);
			ni = vap->iv_bss;
			if (unlikely(!ni)) {
				TXSTAT(qw, tx_dropped_config);
				qdrv_tx_skb_drop(vap, qw, NULL, skb, TRACE_IPPKT_DROP_RSN_RECONFIG);
				return NULL;
			}
			ieee80211_ref_node(ni);
		}

		/* Drop packets from a TDLS peer that are destined for the AP or other TDLS peers. */
		if (unlikely(IEEE80211_NODE_IDX_VALID(skb->src_port))) {
			src_ni = ieee80211_find_node_by_node_idx(vap, skb->src_port);
			if (src_ni) {
				if (unlikely(!IEEE80211_NODE_IS_NONE_TDLS(src_ni))) {
					ieee80211_free_node(ni);
					ieee80211_free_node(src_ni);
					return NULL;
				}
				ieee80211_free_node(src_ni);
			}
		}

		if (qdrv_tx_sub_port_check(vap, ni, skb)) {
			TXSTAT(qw, tx_dropped_config);
			qdrv_tx_skb_drop(vap, qw, NULL, skb, TRACE_IPPKT_DROP_RSN_RECONFIG);
			ieee80211_free_node(ni);
			return NULL;
		}
		break;
	case IEEE80211_M_WDS:
		ni = ieee80211_get_wds_peer_node_ref(vap);
		if (unlikely(!ni)) {
			TXSTAT(qw, tx_drop_wds);
			qdrv_tx_skb_drop(vap, qw, NULL, skb, TRACE_IPPKT_DROP_RSN_NO_WDS);
			return NULL;
		}
		break;
	case IEEE80211_M_HOSTAP:
	default:
		if (skb->dest_port) {
			QDRV_TX_CTR_INC(50);
			ni = ieee80211_find_node_by_node_idx(vap, skb->dest_port);
			if (!ni) {
				DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_BRIDGE | QDRV_LF_PKT_TX,
					"dropping pkt to %pM - node_idx 0x%x is stale\n",
					p_dest_mac, skb->dest_port);
				TXSTAT(qw, tx_drop_aid);
				qdrv_tx_skb_drop(vap, qw, NULL, skb, TRACE_IPPKT_DROP_RSN_AID_STALE);
				return NULL;
			}
		} else if (!IEEE80211_IS_MULTICAST(p_dest_mac)) {
			QDRV_TX_CTR_INC(51);
			ni = ieee80211_find_node(&vap->iv_ic->ic_sta, p_dest_mac);
		}

		if (!ni) {
			QDRV_TX_CTR_INC(52);

			struct qtn_vlan_dev *vlandev = vdev_tbl_lhost[QDRV_WLANID_FROM_DEVID(qv->devid)];

			if (QVLAN_IS_DYNAMIC(vlandev) && M_FLAG_ISSET(skb, M_VLAN_TAGGED)) {
				pkt = qtn_vlan_get_info(skb->data);
				BUG_ON(pkt->magic != QVLAN_PKT_MAGIC);

				qtn_vlan_gen_group_addr(vlan_group_mac,
					pkt->vlan_info & QVLAN_MASK_VID, vap->iv_dev->dev_id);

				ni = ieee80211_find_node(&vap->iv_ic->ic_sta, vlan_group_mac);
				if (ni) {
					*vlan_group = 1;
				} else {
					qdrv_tx_skb_drop(vap, qw, NULL, skb, TRACE_IPPKT_DROP_RSN_INVALID);
					return NULL;
				}
			} else {
				fwt_idx = fwt_sw_get_index_from_mac_be(p_dest_mac);
				if (!(FWT_IF_ERROR(fwt_idx))) {
					fwt_db = fwt_db_get_table_entry(fwt_idx);
					if (fwt_db)
						ni = ieee80211_find_node_by_node_idx(vap,
									fwt_db->out_node);
				}

				if (!ni) {
					ni = vap->iv_bss;
					if (unlikely(!ni)) {
						TXSTAT(qw, tx_dropped_config);
						qdrv_tx_skb_drop(vap, qw, NULL, skb,
								TRACE_IPPKT_DROP_RSN_RECONFIG);
						return NULL;
					}
					ieee80211_ref_node(ni);
				}
			}
		}
		break;
	}
	if (qdrv_tx_sub_port_check(vap, ni, skb)) {
		TXSTAT(qw, tx_dropped_config);
		qdrv_tx_skb_drop(vap, qw, NULL, skb, TRACE_IPPKT_DROP_RSN_RECONFIG);
		ieee80211_free_node(ni);
		return NULL;
	}
	return ni;
}

/*
 * Unicast a layer 2 multicast frame to selected stations or to every station on the vap.
 *
 *     if multicast-to-unicast is disabled
 *         send a single group-addressed frame
 *     else if SSDP (239.255.255.250 and MAC address 01:00:5e:74:ff:fa)
 *         unicast to every station and drop the multicast packet
 *     else if LNCB (224.0.0.0/24)
 *             or non-snooped multicast (224.0.0.0/4) and 'forward unknown multicast' flag is set
 *                 - e.g. IGMP
 *             or L2 broadcast (ff:ff:ff:ff:ff:ff) and the 'reliable broadcast' flag is set
 *                 - e.g. ARP, DHCP
 *         if the 'multicast to unicast' flag is set
 *             unicast to every station and drop the multicast packet
 *         else
 *             unicast to each QSTA and send a group-addressed frame for 3rd party stations
 *                 (these group-addressed frames are always ignored by QSTAs)
 *     else
 *         send a single group-addressed frame
 *
 *     Snooped multicast and IP flood-forwarding are handled in switch_tqe and do not come through
 *     here.
 *
 * Returns 0 if a group-addressed frame should be transmitted.
 * Returns 1 if a group-addressed frame should not be transmitted.
 */
static int qdrv_tx_multicast_to_unicast(struct qdrv_vap *qv, struct qdrv_wlan *qw,
					struct sk_buff *skb, struct ieee80211vap *vap,
					struct ieee80211_node *ni, int is_4addr_mc,
					uint8_t *data_start)
{
	int igmp_type;
	struct ether_header *eh = (struct ether_header*)skb->data;
	struct iphdr *p_iphdr = (struct iphdr *)data_start;
	uint16_t copy_cnt;

	if (vap->iv_mc_to_uc == IEEE80211_QTN_MC_TO_UC_NEVER)
		return 0;

	if (iputil_is_ssdp(eh->ether_dhost, p_iphdr)) {
		qdrv_tx_copy_to_multiple_nodes(vap, skb, IEEE80211_NODE_IN_AUTH_STATE, 0,
			1, QDRV_LF_PKT_TX, "", "SSDP ucast");
		TXSTAT(qw, tx_copy_ssdp);
		return 1;
	}

	if (!is_4addr_mc)
		return 0;

	if (vap->iv_mc_to_uc == IEEE80211_QTN_MC_TO_UC_ALWAYS) {
		/* unicast to all stations */
		qdrv_tx_copy_to_multiple_nodes(vap, skb, IEEE80211_NODE_IN_AUTH_STATE, 0,
			1, QDRV_LF_PKT_TX, "", "mc to uc");
		TXSTAT(qw, tx_copy_mc_to_uc);
		return 1;
	}

	/* unicast to each QSTA */
	igmp_type = qdrv_igmp_type(p_iphdr, skb->len - sizeof(*eh));
	copy_cnt = qdrv_tx_copy_to_multiple_nodes(vap, skb,
		IEEE80211_NODE_LNCB_4ADDR_AUTH, IEEE80211_CFG_4ADDR_ENABLED(vap), 0,
		QDRV_LF_IGMP, qdrv_igmp_type_to_string(igmp_type), NULL);

	if (copy_cnt > 0) {
		TXSTAT(qw, tx_copy_mc_to_uc);

		if (igmp_type != 0)
			TXSTAT_ADD(qw, tx_copy4_igmp, copy_cnt);
		else
			TXSTAT_ADD(qw, tx_copy4_mc, copy_cnt);

		if (qv->iv_3addr_count > 0) {
			if (igmp_type != 0)
				TXSTAT(qw, tx_copy3_igmp);
			else
				TXSTAT(qw, tx_copy3_mc);
		}
	}

	return 0;
}

static void qdrv_tx_unicast_to_unknown(struct qdrv_vap *qv, struct qdrv_wlan *qw,
					struct sk_buff *skb, struct ieee80211vap *vap,
					struct ieee80211_node *ni, uint16_t ether_type,
					uint8_t *data_start)
{
	TXSTAT(qw, tx_unknown);

	/* unicast to unknown endpoint - broadcast to bridge STAs only */
	if (qdrv_tx_copy_unknown_uc_to_nodes(qv, qw, skb, vap->iv_dev, ether_type, data_start) != 0)
		qdrv_tx_skb_drop(vap, qw, ni, skb, TRACE_IPPKT_DROP_RSN_NO_DEST);
	else
		qdrv_tx_skb_drop(vap, qw, ni, skb, TRACE_IPPKT_DROP_RSN_SHOULD_DROP);
}

/*
 * Enqueue a data frame
 * Returns NET_XMIT_SUCCESS if the frame is enqueued.
 * Returns NET_XMIT_DROP if the frame is dropped, in which case the skb and noderef have been freed.
 *
 * If the skb contains a node pointer, the caller must have already incremented
 * the node reference count.
 * It the skb does not contain a node pointer, this function will find the destination
 * node, and increment the node reference count
 */
static inline int qdrv_tx_enqueue_data(struct qdrv_wlan *qw, struct qdrv_vap *qv_tx,
		struct ieee80211_node *ni, struct sk_buff *skb)
{
	struct qdrv_vap *qv;
	struct ieee80211vap *vap;
	uint16_t ether_type;
	struct ether_header *eh;
	uint8_t *data_start;
	uint8_t *p_dest_mac;
	int is_4addr_mc;
	struct iphdr *p_iphdr;
	uint32_t node_idx_mapped;
	int is_vap_node;
	uint8_t vlan_group = 0;
	uint8_t ip_proto;
	void *proto_data = NULL;
	struct qtn_vlan_dev *vlandev = vdev_tbl_lhost[QDRV_WLANID_FROM_DEVID(qv_tx->devid)];

	TXSTAT(qw, tx_enqueue_data);

	eh = (struct ether_header*)skb->data;
	p_dest_mac = eh->ether_dhost;
	data_start = qdrv_sch_find_data_start(skb, eh, &ether_type);
	p_iphdr = (struct iphdr *)data_start;

	if (likely(!ni)) {
		ni = qdrv_tx_node_get_and_ref(&qv_tx->iv, qw, skb, p_dest_mac, &vlan_group);
		if (!ni)
			return NET_XMIT_DROP;
		QTN_SKB_CB_NI(skb) = ni;
	} else {
		QDRV_TX_CTR_INC(49);
	}

	skb = switch_vlan_from_proto_stack(skb, vlandev, IEEE80211_NODE_IDX_UNMAP(ni->ni_node_idx));
	if (!skb) {
		ieee80211_free_node(ni);
		return NET_XMIT_DROP;
	}

	node_idx_mapped = ni->ni_node_idx;
	skb->dest_port = node_idx_mapped;
	vap = ni->ni_vap;
	qv = container_of(vap, struct qdrv_vap, iv);

	is_vap_node = (vlan_group || (ni == vap->iv_bss));
	ip_proto = iputil_proto_info(p_iphdr, skb, &proto_data, NULL, NULL);

	if (bcast_pps_should_drop(p_dest_mac, &vap->bcast_pps, ether_type,
				ip_proto, proto_data, 0)) {
		qdrv_tx_skb_return(qw, skb);
		return NET_XMIT_DROP;
	}

	if (vap->disable_dgaf) {
		if (qdrv_handle_dgaf(vap, p_iphdr, skb, p_dest_mac, ether_type,
					ip_proto, proto_data)) {
			qdrv_tx_skb_drop(vap, qw, ni, skb, TRACE_IPPKT_DROP_RSN_SHOULD_DROP);
			return NET_XMIT_DROP;
		}
	}

	if (vap->proxy_arp) {
		if (ether_type == __constant_htons(ETH_P_ARP)) {
			struct ether_arp *arp = (struct ether_arp *)data_start;
			if (qdrv_proxy_arp(vap, qw, NULL, data_start) ||
					arp->ea_hdr.ar_op == __constant_htons(ARPOP_REQUEST)) {
				qdrv_tx_skb_drop(vap, qw, ni, skb, TRACE_IPPKT_DROP_RSN_PROXY_ARP);
				return NET_XMIT_DROP;
			}
#ifdef CONFIG_IPV6
		} else if (ether_type == __constant_htons(ETH_P_IPV6)) {
			if (qdrv_wlan_handle_neigh_msg(vap, qw, data_start, 1, skb,
							ip_proto, proto_data)) {
				qdrv_tx_skb_drop(vap, qw, ni, skb, TRACE_IPPKT_DROP_RSN_PROXY_ARP);
				return NET_XMIT_DROP;
			}
#endif
		}
	}

	if (!M_FLAG_ISSET(skb, M_IPFF)) {
		if (qdrv_wlan_mc_should_drop(eh, p_iphdr, &qv->iv, is_vap_node, ip_proto)) {
			/* Flood-forwarding of unknown IP multicast is disabled */
			qdrv_tx_skb_drop(vap, qw, ni, skb, TRACE_IPPKT_DROP_RSN_NO_DEST);
			return NET_XMIT_DROP;
		}
	}

	is_4addr_mc = M_FLAG_ISSET(skb, M_IPFF) ||
			qdrv_wlan_is_4addr_mc(eh, data_start, &qv->iv, is_vap_node);

	if (qv->iv.iv_opmode == IEEE80211_M_HOSTAP && is_vap_node &&
			(vap->iv_flags_ext & IEEE80211_FEXT_WDS)) {

		if (unlikely(!IEEE80211_IS_MULTICAST(p_dest_mac))) {
			qdrv_tx_unicast_to_unknown(qv, qw, skb, vap, ni, ether_type, data_start);
			return NET_XMIT_DROP;
		}

		if (qdrv_tx_multicast_to_unicast(qv, qw, skb, vap, ni, is_4addr_mc, data_start)) {
			qdrv_tx_skb_drop(vap, qw, ni, skb, TRACE_IPPKT_DROP_RSN_COPY);
			return NET_XMIT_DROP;
		}

		if (unlikely(is_4addr_mc && (vap->iv_mc_to_uc == IEEE80211_QTN_MC_TO_UC_LEGACY))) {
			if (qv->iv_3addr_count > 0) {
				TXSTAT(qw, tx_copy3);
			} else {
				qdrv_tx_skb_drop(vap, qw, ni, skb, TRACE_IPPKT_DROP_RSN_SHOULD_DROP);
				return NET_XMIT_DROP;
			}
		}

		/* drop through to send as L2 multicast */
		TXSTAT(qw, tx_copy_mc);
	}

	return qdrv_tx_prepare_data_frame(qw, qv, ni, skb);
}

/*
 * Enqueue a locally generated 802.11-encapped management or data frame.
 * A node reference must have been acquired.
 * Returns NET_XMIT_SUCCESS if the frame is enqueued.
 * Returns NET_XMIT_DROP if the frame is dropped, in which case the skb has been freed.
 */
static inline int qdrv_tx_enqueue_80211(struct qdrv_wlan *qw, struct ieee80211_node *ni, struct sk_buff *skb)
{
	struct ieee80211_frame *pwh;
	uint32_t type;
	uint32_t subtype;
	uint8_t ac;

	if (unlikely(!ni)) {
		qdrv_tx_skb_return(qw, skb);
		return NET_XMIT_DROP;
	}

	if (QTN_SKB_ENCAP_IS_80211_MGMT(skb))
		TXSTAT(qw, tx_enqueue_mgmt);
	else
		TXSTAT(qw, tx_enqueue_80211_data);

	if (DBG_LOG_LEVEL >= DBG_LL_INFO) {
		pwh = (struct ieee80211_frame *)skb->data;
		type = pwh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
		subtype = pwh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
		ac = skb->priority;
		DBGPRINTF(DBG_LL_INFO, QDRV_LF_PKT_TX,
			"a1=%pM a2=%pM a3=%pM aid=%u ac=%u encap=%u type=0x%x subtype=0x%x\n",
			pwh->i_addr1, pwh->i_addr2, pwh->i_addr3,
			IEEE80211_NODE_AID(ni), ac, QTN_SKB_ENCAP(skb), type, subtype);
	}

	return qdrv_tx_enqueue_to_node(qw, ni, skb);
}

/*
 * This is the entry point for wireless transmission.
 */
netdev_tx_t qdrv_tx_hardstart(struct sk_buff *skb, struct net_device *dev)
{
	struct qdrv_vap *qv;
	struct qdrv_wlan *qw;
	struct ieee80211vap *vap;
	int is_80211_encap = QTN_SKB_ENCAP_IS_80211(skb);
	struct ieee80211_node *ni = QTN_SKB_CB_NI(skb);

	QDRV_TX_CTR_INC(2);
	trace_skb_perf_stamp_call(skb);

	if (unlikely(ni && is_80211_encap))
		ieee80211_ref_node(ni);

	if (unlikely(!dev)) {
		DBGPRINTF_LIMIT_E("[%s] missing dev\n",
			ni ? ether_sprintf(ni->ni_macaddr) : "");
		QDRV_TX_CTR_INC(3);
		qdrv_tx_skb_drop(NULL, NULL, QTN_SKB_CB_NI(skb), skb, TRACE_IPPKT_DROP_RSN_RECONFIG);
		return NETDEV_TX_OK;
	}

	qv = netdev_priv(dev);
	qw = qv->parent;
	vap = &qv->iv;

	QDRV_TX_CTR_INC(4);

	if (unlikely(qw->mac->dead || qw->mac->mgmt_dead)) {
		TXSTAT(qw, tx_dropped_mac_dead);
		qdrv_tx_skb_drop(vap, qw, ni, skb, TRACE_IPPKT_DROP_RSN_MAC_DEAD);
		return NETDEV_TX_OK;
	}

	/* drop any WBSP control packet (Ethernet type 88b7)
	Quantenna OUI (00 26 86) is located at data[14-16] followed by 1-byte type field [17] */
	if (unlikely(qdrv_wbsp_ctrl == QDRV_WBSP_CTRL_ENABLED &&
		     skb->protocol == __constant_htons(ETHERTYPE_802A) &&
		     skb->len > 17 && is_qtn_oui_packet(&skb->data[14]))) {
		qdrv_tx_skb_drop(vap, qw, ni, skb, TRACE_IPPKT_DROP_RSN_SHOULD_DROP);
		return NETDEV_TX_OK;
	}

	if (likely(!is_80211_encap))
		qdrv_tx_enqueue_data(qw, qv, ni, skb);
	else
		qdrv_tx_enqueue_80211(qw, ni, skb);

	return NETDEV_TX_OK;
}

/*
 * Get a txdesc for this managment frame, but don't add this
 * txdesc to tx mbox, just return it
 */
struct host_txdesc *qdrv_tx_get_mgt_txdesc(struct sk_buff *skb, struct net_device *dev)
{
	struct qdrv_vap *qv = netdev_priv(dev);
	struct qdrv_wlan *qw = qv->parent;
	struct host_txdesc *txdesc = NULL;
	struct ieee80211_frame *pwh = (struct ieee80211_frame *)skb->data;
	uint8_t ac = skb->priority;
	uint16_t node_idx_mapped = skb->dest_port;

	trace_skb_perf_stamp_call(skb);
	QDRV_TX_CTR_INC(47);

	/* MAC is dead. Drop packets. */
	if (unlikely(qw->mac->dead || qw->mac->mgmt_dead)) {
		TXSTAT(qw, tx_dropped_mac_dead);
		trace_ippkt_dropped(TRACE_IPPKT_DROP_RSN_MAC_DEAD, 1, 0);
		return NULL;
	}

	if (qdrv_tx_done_chk(qw) != 0) {
		return NULL;
	}

	/* Make sure the device is set on the skb (for flow control) */
	skb->dev = dev;
	pwh = (struct ieee80211_frame *)skb->data;

	txdesc = qdrv_tx_prepare_hostdesc(qw, skb, qv->iv.iv_unit, QTN_TID_MGMT, ac,
						node_idx_mapped, 1);
	if (unlikely(!txdesc)) {
		trace_ippkt_dropped(TRACE_IPPKT_DROP_RSN_NO_DESC, 1, 0);
		TXSTAT(qw, tx_drop_nodesc);
		return NULL;
	}

	if (IFF_DUMPPKTS_XMIT_MGT(pwh, DBG_LOG_FUNC)) {
		ieee80211_dump_pkt(&qw->ic, skb->data,
			skb->len>g_dbg_dump_pkt_len ? g_dbg_dump_pkt_len : skb->len, -1, -1);
	}

	txdesc->hd_segaddr[0] = cache_op_before_tx(skb->head,
		skb_headroom(skb) + skb->len) + skb_headroom(skb);
	skb->cache_is_cleaned = 1;
	dev->trans_start = jiffies;

	return txdesc;
}

int qdrv_tx_start(struct qdrv_mac *mac)
{
	struct int_handler int_handler;
	struct qdrv_wlan *qw = (struct qdrv_wlan *) mac->data;
	int irq = qw->txdoneirq;

	memset(&int_handler, 0, sizeof(int_handler));
	int_handler.handler = qdrv_tx_done_irq;
	int_handler.arg1 = mac;
	int_handler.arg2 = NULL;

	if (qdrv_mac_set_handler(mac, irq, &int_handler) != 0) {
		DBGPRINTF_E("Failed to register IRQ handler for %d\n", irq);
		return -1;
	}

	qdrv_mac_enable_irq(mac, qw->txdoneirq);

	return 0;
}

int qdrv_tx_stop(struct qdrv_mac *mac)
{
	struct qdrv_wlan *qw = (struct qdrv_wlan *) mac->data;

	qdrv_mac_disable_irq(mac, qw->txdoneirq);

	return 0;
}

int qdrv_tx_init(struct qdrv_mac *mac, struct host_ioctl_hifinfo *hifinfo, uint32_t arg2)
{
	struct qdrv_wlan *qw = mac->data;
	struct host_txif *txif = &qw->tx_if;
	unsigned int txif_list_size;

	/* Read in the tx list max length */
	txif_list_size = mac->params.txif_list_max;

	if ((txif_list_size >= QNET_TXLIST_ENTRIES_MIN) &&
			(txif_list_size <= QNET_TXLIST_ENTRIES_MAX)) {
		txif->list_max_size = txif_list_size;
	} else {
		txif->list_max_size = QNET_TXLIST_ENTRIES_DEFAULT;
	}

	if (txif->list_max_size != QNET_TXLIST_ENTRIES_DEFAULT) {
		DBGPRINTF_E("Non default MuC tx list size: %d\n", txif->list_max_size);
	} else {
		DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_PKT_TX,
				"MuC tx list max len: %d\n", txif->list_max_size);
	}

	txif->muc_thresh_high = txif->list_max_size;
	txif->muc_thresh_low = txif->list_max_size - QDRV_TXDESC_THRESH_MIN_DIFF;

	/* Initialize TX mailbox */
	txif->tx_mbox = ioremap_nocache(muc_to_lhost(hifinfo->hi_mboxstart), HOST_MBOX_SIZE);

	DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_TRACE,
			"qw 0x%p txif 0x%p mbox 0x%p hifinfo->hi_mboxstart 0x%x\n",
			qw, txif, txif->tx_mbox, hifinfo->hi_mboxstart);

	memset((void *) txif->tx_mbox, 0, HOST_MBOX_SIZE);

	qw->txdoneirq = hifinfo->hi_txdoneirq;
	DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_PKT_TX,
			"txdoneirq %u\n", qw->txdoneirq);

	/* hw fix: make sure that packet header does not goes over 1K boundary */
	txif->df_txdesc_cache = dma_pool_create("txdesc", NULL,
						sizeof(struct lhost_txdesc), 8, 1024);

	txif->df_txdesc_list_tail = NULL;
	txif->df_txdesc_list_head = NULL;

	txif->txdesc_cnt[QDRV_TXDESC_DATA] = qdrv_tx_data_max_count(qw);
	txif->txdesc_cnt[QDRV_TXDESC_MGMT] = qdrv_tx_80211_max_count(qw);
	qw->tx_stats.tx_min_cl_cnt = qw->tx_if.list_max_size;

	fwt_sw_4addr_callback_set(&qdrv_tx_fwt_use_4addr, mac);

	return 0;
}

int qdrv_tx_exit(struct qdrv_wlan *qw)
{
	struct host_txif *txif = &qw->tx_if;

	fwt_sw_4addr_callback_set(NULL, NULL);

	while(txif->df_txdesc_list_head) {
		struct lhost_txdesc *tmp = txif->df_txdesc_list_head;
		txif->df_txdesc_list_head = txif->df_txdesc_list_head->next;
		dma_pool_free(txif->df_txdesc_cache, tmp->hw_desc.hd_va, tmp->hw_desc.hd_pa);
	}
	txif->df_txdesc_list_tail = NULL;

	dma_pool_destroy(txif->df_txdesc_cache);

	if (txif->tx_mbox) {
		iounmap(txif->tx_mbox);
		txif->tx_mbox = 0;
	}

	return 0;
}
