/**
 * Copyright (c) 2011-2012 Quantenna Communications, Inc.
 * All rights reserved.
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

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/io.h>
#include <linux/kernel.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <asm/system.h>
#include <qtn/dmautil.h>
#include <drivers/ruby/dma_cache_ops.h>

#include "topaz_test.h"
#include <qtn/topaz_fwt_sw.h>
#include <qtn/topaz_fwt_db.h>
#include <qtn/topaz_tqe_cpuif.h>
#include <qtn/topaz_tqe.h>
#include <qtn/topaz_hbm_cpuif.h>
#include <qtn/topaz_hbm.h>
#include <qtn/topaz_fwt.h>
#include <qtn/topaz_vlan_cpuif.h>
#include "net80211/ieee80211.h"
#include "net80211/if_ethersubr.h"
#include <qtn/qtn_net_packet.h>
#include <qtn/qdrv_sch.h>
#include <qtn/topaz_congest_queue.h>
#include <qtn/qtn_wowlan.h>
#include <qtn/iputil.h>
#include <qtn/mproc_sync.h>
#include <qtn/qtn_vlan.h>
#include "linux/net/bridge/br_public.h"

int g_dscp_flag = 0;
int g_dscp_value[2];
uint16_t g_wowlan_host_state = 0;
uint16_t g_wowlan_match_type = 0;
uint16_t g_wowlan_l2_ether_type = 0x0842;
uint16_t g_wowlan_l3_udp_port = 0xffff;
uint8_t g_l2_ext_filter = 0;
uint8_t g_l2_ext_filter_port = TOPAZ_TQE_NUM_PORTS;
EXPORT_SYMBOL(g_l2_ext_filter);
EXPORT_SYMBOL(g_l2_ext_filter_port);
EXPORT_SYMBOL(g_wowlan_host_state);
EXPORT_SYMBOL(g_wowlan_match_type);
EXPORT_SYMBOL(g_wowlan_l2_ether_type);
EXPORT_SYMBOL(g_wowlan_l3_udp_port);
EXPORT_SYMBOL(g_dscp_flag);
EXPORT_SYMBOL(g_dscp_value);

int tqe_sem_en = 0;
module_param(tqe_sem_en, int, S_IRWXU);

typedef ALIGNED_DMA_DESC(union, topaz_tqe_cpuif_descr) aligned_dma_topaz_tqe_cpuif_descr;

struct tqe_netdev_priv {
	struct napi_struct napi;
#ifdef TOPAZ_CTRLPKT_TQE
	struct napi_struct auc_napi;
#endif
	struct net_device_stats stats;

	struct topaz_congest_queue *congest_queue;

	aligned_dma_topaz_tqe_cpuif_descr rx;
#ifdef TOPAZ_CTRLPKT_TQE
	aligned_dma_topaz_tqe_cpuif_descr auc_rx;
#endif
};

static tqe_fwt_get_mcast_hook g_tqe_fwt_get_mcast_hook = NULL;
static tqe_fwt_get_mcast_ff_hook g_tqe_fwt_get_mcast_ff_hook = NULL;
static tqe_fwt_get_ucast_hook g_tqe_fwt_get_ucast_hook = NULL;
static tqe_fwt_false_miss_hook g_tqe_fwt_false_miss_hook = NULL;
static tqe_fwt_get_from_mac_hook g_tqe_fwt_get_from_mac_hook = NULL;
static tqe_fwt_add_from_mac_hook g_tqe_fwt_add_from_mac_hook = NULL;
static tqe_fwt_del_from_mac_hook g_tqe_fwt_del_from_mac_hook = NULL;
static tqe_hbm_buf_append_meta_mcast_handler g_tqe_mcast_do_frame_meta_append = NULL;

static tqe_mac_reserved_hook g_tqe_mac_reserved_hook = NULL;
static void tqe_rx_pkt_drop(const union topaz_tqe_cpuif_descr *desc);

#ifdef TOPAZ_CONGE_CONFIG
#define __may_sram_text		__attribute__((section(".sram.text")))
#else
#define __may_sram_text
#endif

struct {
	tqe_port_handler handler;
	void *token;
	int32_t group;
} tqe_port_handlers[TOPAZ_TQE_NUM_PORTS];

static inline int tqe_frames_need_meta_info(unsigned int out_port)
{
	return g_tqe_mcast_do_frame_meta_append != NULL && TOPAZ_TQE_PORT_IS_PCIE(out_port);
}

void tqe_register_mcast_do_frame_meta_append(tqe_hbm_buf_append_meta_mcast_handler func)
{
	g_tqe_mcast_do_frame_meta_append = func;
}
EXPORT_SYMBOL(tqe_register_mcast_do_frame_meta_append);

static int bonding = 0;

void tqe_set_bonding(int is_bonding)
{
	bonding = is_bonding;
}
EXPORT_SYMBOL(tqe_set_bonding);

int tqe_port_add_handler(enum topaz_tqe_port port, tqe_port_handler handler, void *token)
{
	if (port >= TOPAZ_TQE_NUM_PORTS || !handler) {
		return -EINVAL;
	}

	tqe_port_handlers[port].handler = handler;
	tqe_port_handlers[port].token = token;

	return 0;
}
EXPORT_SYMBOL(tqe_port_add_handler);

void tqe_port_remove_handler(enum topaz_tqe_port port)
{
	if (port >= TOPAZ_TQE_NUM_PORTS || !tqe_port_handlers[port].handler) {
		printk(KERN_ERR "%s: invalid port %u\n", __FUNCTION__, port);
		return;
	}

	tqe_port_handlers[port].handler = NULL;
	tqe_port_handlers[port].token = NULL;
}
EXPORT_SYMBOL(tqe_port_remove_handler);

static void tqe_port_set(const enum topaz_tqe_port port, const uint8_t enable)
{
	struct topaz_fwt_sw_mcast_entry *mcast_ent;

	if (!g_tqe_fwt_get_mcast_ff_hook) {
		return;
	}

	mcast_ent = g_tqe_fwt_get_mcast_ff_hook();
	if (unlikely(!mcast_ent)) {
		return;
	}
	if (enable) {
		topaz_fwt_sw_mcast_port_set(mcast_ent, port);
	} else {
		topaz_fwt_sw_mcast_port_clear(mcast_ent, port);
	}
	topaz_fwt_sw_mcast_flush(mcast_ent);
}

void tqe_port_set_group(const enum topaz_tqe_port port, int32_t group)
{
	if ((port < TOPAZ_TQE_NUM_PORTS) && (group > 0))
		tqe_port_handlers[port].group = group;
}
EXPORT_SYMBOL(tqe_port_set_group);

void tqe_port_clear_group(const enum topaz_tqe_port port)
{
	if (port < TOPAZ_TQE_NUM_PORTS)
		tqe_port_handlers[port].group = 0;
}
EXPORT_SYMBOL(tqe_port_clear_group);

void tqe_port_register(const enum topaz_tqe_port port)
{
	tqe_port_set(port, 1);
}
EXPORT_SYMBOL(tqe_port_register);

void tqe_port_unregister(const enum topaz_tqe_port port)
{
	tqe_port_set(port, 0);
}
EXPORT_SYMBOL(tqe_port_unregister);

struct update_multicast_tx_stats {
	void (*fn)(void *ctx, uint8_t node);
	void *ctx;
};

struct update_multicast_tx_stats update_multicast;

void tqe_reg_multicast_tx_stats(void (*fn)(void *ctx, uint8_t), void *ctx)
{
	update_multicast.fn = fn;
	update_multicast.ctx = ctx;
}
EXPORT_SYMBOL(tqe_reg_multicast_tx_stats);

#if defined(CONFIG_ARCH_TOPAZ_SWITCH_TEST) || defined(CONFIG_ARCH_TOPAZ_SWITCH_TEST_MODULE)
static void topaz_tqe_test_ctrl(const uint8_t *buff_virt_rx)
{
	const uint8_t ctrl_dstmac[ETH_ALEN] = TOPAZ_TEST_CTRL_DSTMAC;
	const uint8_t ctrl_srcmac[ETH_ALEN] = TOPAZ_TEST_CTRL_SRCMAC;

	if (memcmp(&buff_virt_rx[ETH_ALEN * 0], ctrl_dstmac, ETH_ALEN) == 0 &&
		memcmp(&buff_virt_rx[ETH_ALEN * 1], ctrl_srcmac, ETH_ALEN) == 0) {

		const char *test_str = (const char *)&buff_virt_rx[128];
		unsigned long len;
		char *cmd = NULL;
		char **words = NULL;
		int rc;
		int word_count;
		int (*parse)(int, char**) = NULL;

		len = strlen(test_str);
		cmd = kmalloc(len + 1, GFP_KERNEL);
		words = kmalloc(len * sizeof(char *) / 2, GFP_KERNEL);
		if (!cmd || !words) {
			rc = -ENOMEM;
			goto out;
		}

		strcpy(cmd, test_str);
		word_count = topaz_test_split_words(words, cmd);

		if (strcmp(words[0], "dpi_test") == 0) {
			parse = &topaz_dpi_test_parse;
		} else if (strcmp(words[0], "fwt_test") == 0) {
			parse = &topaz_fwt_test_parse;
		} else if (strcmp(words[0], "ipprt_emac0") == 0) {
			parse = &topaz_ipprt_emac0_test_parse;
		} else if (strcmp(words[0], "ipprt_emac1") == 0) {
			parse = &topaz_ipprt_emac1_test_parse;
		} else if (strcmp(words[0], "vlan_test") == 0) {
			parse = &topaz_vlan_test_parse;
		} else {
			printk("%s: invalid ctrl packet\n", __FUNCTION__);
		}

		if (parse) {
			rc = parse(word_count - 1, words + 1);
			printk("%s: rc %d '%s'\n", __FUNCTION__, rc, test_str);
		}
out:
		if (cmd)
			kfree(cmd);
		if (words)
			kfree(words);
	}
}
#endif

#ifdef CONFIG_TOPAZ_PCIE_TARGET
uint32_t
switch_tqe_multi_proc_sem_down(const char * funcname, int linenum)
{
	uint32_t prtcnt;

	if (tqe_sem_en == 0)
		return 1;

	prtcnt = 0;
	while (_qtn_mproc_3way_tqe_sem_down(TOPAZ_MPROC_TQE_SEM_LHOST) == 0) {
		if ((prtcnt & 0xff) == 0)
			printk("%s line %d fail to get tqe semaphore\n", funcname, linenum);
		prtcnt++;
	}
	return 1;
}

EXPORT_SYMBOL(switch_tqe_multi_proc_sem_down);

uint32_t
switch_tqe_multi_proc_sem_up(void)
{
	if (tqe_sem_en == 0)
		return 1;

	if (_qtn_mproc_3way_tqe_sem_up(TOPAZ_MPROC_TQE_SEM_LHOST)) {
		return 1;
	} else {
		WARN_ONCE(1, "%s failed to relese HW semaphore\n", __func__);
		return 0;
	}
}

EXPORT_SYMBOL(switch_tqe_multi_proc_sem_up);
#endif

static void tqe_buf_set_refcounts(void *buf_start, int32_t enqueue, int32_t free)
{
	uint32_t *p = buf_start;
	uint32_t *_m = topaz_hbm_buf_get_meta(p);
	uint32_t *enqueuep = _m - HBM_HR_OFFSET_ENQ_CNT;
	uint32_t *freep = _m - HBM_HR_OFFSET_FREE_CNT;

	if (enqueue >= 0)
		arc_write_uncached_32(enqueuep, enqueue);
	if (free >= 0)
		arc_write_uncached_32(freep, free);
}

__attribute__((section(".sram.data"))) atomic_t tqe_xmit_success_counter = ATOMIC_INIT(0);
EXPORT_SYMBOL(tqe_xmit_success_counter);

static noinline void
topaz_tqe_wait_and_start(const char *caller, int line, union topaz_tqe_cpuif_ppctl *pp_cntl)
{
	topaz_tqe_wait();
	switch_tqe_multi_proc_sem_down(caller, line);
	topaz_tqe_cpuif_tx_start(pp_cntl);
	switch_tqe_multi_proc_sem_up();
}

#ifndef CONFIG_TOPAZ_PCIE_HOST
static __may_sram_text int
topaz_tqe_xmit(union topaz_tqe_cpuif_ppctl *pp_cntl)
{
	int push_success = 0;

	topaz_tqe_wait();
	switch_tqe_multi_proc_sem_down("topaz_tqe_xmit",__LINE__);
	topaz_tqe_cpuif_tx_start(pp_cntl);
	switch_tqe_multi_proc_sem_up();

	wmb();

	push_success = topaz_tqe_cpuif_tx_success(NULL);
	if (!push_success) {
		return NET_XMIT_CN;
	} else {
		/*
		 * atomic_inc is deprecated as it requires a critical section in which
		 * IRQ must be disabled
		 */
		atomic_set(&tqe_xmit_success_counter, atomic_read(&tqe_xmit_success_counter) + 1);
		return NET_XMIT_SUCCESS;
	}
}
#endif

void topaz_tqe_congest_queue_process(const union topaz_tqe_cpuif_descr *desc,
		void *queue, uint8_t node, uint8_t tqe_tid,
		union topaz_tqe_cpuif_ppctl *ppctl, uint8_t is_unicast)
{
	struct topaz_congest_queue *congest_queue = (struct topaz_congest_queue *)queue;
	struct topaz_congest_q_desc *q_desc;
	int8_t re_sched = 0;
	int8_t ret = 0;

	if (topaz_queue_congested(congest_queue, node, tqe_tid)) {
		q_desc = topaz_get_congest_queue(congest_queue, node, tqe_tid);
		ret = topaz_congest_enqueue(q_desc, ppctl);
		if (ret == NET_XMIT_CN) {
			topaz_hbm_congest_queue_put_buf(ppctl);
		}

		re_sched = topaz_congest_queue_xmit(q_desc, TOPAZ_SOFTIRQ_BUDGET);
		if (re_sched)
			tasklet_schedule(&congest_queue->congest_tx);

	} else {
		ret = congest_queue->xmit_func(ppctl);

		if (unlikely(ret != NET_XMIT_SUCCESS)) {
			if (is_unicast)
				q_desc = topaz_congest_alloc_unicast_queue(congest_queue,
										node, tqe_tid);
			else
				q_desc = topaz_congest_alloc_queue(congest_queue, node, tqe_tid);

			if (!q_desc) {
				topaz_hbm_congest_queue_put_buf(ppctl);
			} else {
				ret = topaz_congest_enqueue(q_desc, ppctl);

				if (ret == NET_XMIT_CN) {
					topaz_hbm_congest_queue_put_buf(ppctl);
				} else {
					congest_queue->cong_state++;
					tasklet_schedule(&congest_queue->congest_tx);
				}
			}
		}
	}
}

static inline struct qtn_vlan_dev *tqe_get_vlandev(uint8_t port, uint8_t node)
{
	if (TOPAZ_TQE_PORT_IS_WIRED(port))
		return vport_tbl_lhost[port];
	else
		return switch_vlan_dev_from_node(node);
}

static noinline void
topaz_tqew_move_buf(union topaz_tqe_cpuif_descr *descr, int16_t offset)
{
	descr->data.buff_ptr_offset -= offset;
	descr->data.length -= offset;
	descr->data.pkt = (uint8_t *)descr->data.pkt + offset;
}

static noinline uint16_t
topaz_toemac_tag_vlan_tci(struct qtn_vlan_pkt *pkt, uint16_t vlan_action)
{
	uint16_t vlan_tci;

	if (vlan_action & TQE_MISCUSER_ANY2A_VLAN_TAG_VLAN0) {
		vlan_tci = htons(QVLAN_PRIO_VID | (pkt->vlan_info & ~QVLAN_PKT_VID_MASK));
		pkt->flag &= ~QVLAN_PKT_TAGGED;
		pkt->flag |= QVLAN_PKT_ZERO_TAGGED;
	} else {
		vlan_tci = htons(pkt->vlan_info);
		pkt->flag &= ~QVLAN_PKT_ZERO_TAGGED;
		pkt->flag |= QVLAN_PKT_TAGGED;
	}

	return vlan_tci;
}

static noinline uint16_t
topaz_toemac_vlan_handle(struct qtn_vlan_dev *vdev,
	union topaz_tqe_cpuif_descr *desc, uint16_t vlan_action)
{
	uint8_t *data = bus_to_virt((uintptr_t)(desc->data.pkt));
	struct qtn_vlan_pkt *pkt = qtn_vlan_get_info(data);
	struct vlan_ethhdr *veth = (struct vlan_ethhdr *)data;
	uint16_t vlan_tci;
	uint16_t cache_op_size = 0;

	COMPILE_TIME_ASSERT(QVLAN_PKTCTRL_LEN + VLAN_HLEN <= TOPAZ_HBM_PAYLOAD_HEADROOM);

	if ((vlan_action & TQE_MISCUSER_ANY2A_VLAN_REPLACE)
			== TQE_MISCUSER_ANY2A_VLAN_REPLACE) {
		vlan_tci = topaz_toemac_tag_vlan_tci(pkt, vlan_action);
		veth->h_vlan_TCI = vlan_tci;

		cache_op_size = ETH_ALEN * 2 + VLAN_HLEN;
	} else if (vlan_action & TQE_MISCUSER_ANY2A_VLAN_TAG) {
		vlan_tci = topaz_toemac_tag_vlan_tci(pkt, vlan_action);

		memmove((uint8_t *)pkt - VLAN_HLEN, pkt, QVLAN_PKTCTRL_LEN + ETH_ALEN * 2);
		topaz_tqew_move_buf(desc, -VLAN_HLEN);

		data -= VLAN_HLEN;
		veth = (struct vlan_ethhdr *)data;
		veth->h_vlan_proto = htons(ETH_P_8021Q);
		veth->h_vlan_TCI = vlan_tci;

		cache_op_size = ETH_ALEN * 2 + VLAN_HLEN;
	} else if (vlan_action & TQE_MISCUSER_ANY2A_VLAN_UNTAG) {
		pkt->flag &= ~(QVLAN_PKT_TAGGED | QVLAN_PKT_ZERO_TAGGED);
		memmove((uint8_t *)pkt + VLAN_HLEN, pkt, QVLAN_PKTCTRL_LEN + ETH_ALEN * 2);
		topaz_tqew_move_buf(desc, VLAN_HLEN);

		cache_op_size = ETH_ALEN * 2;
	}

	return cache_op_size;
}

static noinline uint16_t
topaz_mcast_vlan_prepare(union topaz_tqe_cpuif_descr *desc, uint8_t port_bitmap)
{
	uint8_t *buf_virt_rx = bus_to_virt((unsigned long)desc->data.pkt);
	uint8_t out_port;
	uint16_t misc_user = 0;
	struct qtn_vlan_dev *vdev;

	if (port_bitmap & BIT(TOPAZ_TQE_EMAC_0_PORT))
		out_port = TOPAZ_TQE_EMAC_0_PORT;
	else if (port_bitmap & BIT(TOPAZ_TQE_EMAC_1_PORT))
		out_port = TOPAZ_TQE_EMAC_1_PORT;
	else
		return 0;

	vdev = tqe_get_vlandev(out_port, 0);

	if (unlikely(!qtn_vlan_egress(vdev, 0, buf_virt_rx, &misc_user, 0)))
		return 0;

	return topaz_toemac_vlan_handle(vdev, desc, misc_user);
}

/*
 * Push a packet to the TQE
 */
static __may_sram_text void
tqe_push_mcast(const void *token1, void *token2, uint8_t port, uint8_t node, uint8_t tid)
{
	const union topaz_tqe_cpuif_descr *desc = token1;
	union topaz_tqe_cpuif_ppctl ppctl;
	const uint8_t portal = 0;	/* not used */
	uint16_t misc_user = 0;
	void *queue = token2;
	uint8_t tqe_free = queue ? 0 : 1;
	struct qtn_vlan_dev *vdev;

	if (vlan_enabled) {
		vdev = tqe_get_vlandev(port, node);
		if (!qtn_vlan_egress(vdev, node, bus_to_virt((uintptr_t)desc->data.pkt),
				TOPAZ_TQE_PORT_IS_WMAC(vdev->port) ? &misc_user : NULL, 1)) {
			tqe_rx_pkt_drop(desc);
			return;
		}
	}

	topaz_tqe_cpuif_ppctl_init(&ppctl,
			port, &node, 1, tid,
			portal, 1, TOPAZ_HBM_EMAC_TX_DONE_POOL, tqe_free, misc_user);

	ppctl.data.pkt = desc->data.pkt;
	ppctl.data.length = desc->data.length;
	ppctl.data.buff_ptr_offset = desc->data.buff_ptr_offset;
	if (tqe_frames_need_meta_info(port))
		ppctl.data.length = g_tqe_mcast_do_frame_meta_append(desc);

	if (queue) {
		topaz_tqe_congest_queue_process(desc, queue, node, tid, &ppctl, 0);
	} else {
		topaz_tqe_wait_and_start(__func__, __LINE__, &ppctl);
	}

	if (port == TOPAZ_TQE_WMAC_PORT && update_multicast.fn)
		update_multicast.fn(update_multicast.ctx, node);
}

/*
 * returns the number of TQE pushes; 0 means buffer is not consumed here
 */
static __may_sram_text uint32_t tqe_push_mc_ports(void *queue,
		const struct topaz_fwt_sw_mcast_entry *mcast_ent_shared,
		union topaz_tqe_cpuif_descr *desc, uint8_t tid, uint8_t in_node,
		uint32_t header_access_bytes)
{
	struct topaz_fwt_sw_mcast_entry mcast_ent;
	enum topaz_tqe_port in_port = desc->data.in_port;
	uint32_t push_count;
	uint32_t pushes = 0;
	uint8_t port = TOPAZ_TQE_FIRST_PORT;
	void *buf_virt_rx = bus_to_virt((unsigned long)desc->data.pkt);
	const struct ether_header *eh;
	uint32_t cache_op_size;

	COMPILE_TIME_ASSERT(sizeof(mcast_ent.port_bitmap) * NBBY >= TOPAZ_TQE_NUM_PORTS);

	mcast_ent = *mcast_ent_shared;

	/* The MuC handles snooped multicast directly */
	if (in_port == TOPAZ_TQE_WMAC_PORT || in_port == TOPAZ_TQE_MUC_PORT) {
		eh = buf_virt_rx;
		printk_ratelimited(KERN_WARNING "%s: mcast pkt from mac t=%04x d=%pM s=%pM\n",
			__func__,
			eh->ether_type, eh->ether_dhost, eh->ether_shost);
		return 0;
	} else if (bonding) {
		if (in_port == TOPAZ_TQE_EMAC_0_PORT)
			mcast_ent.port_bitmap &= ~BIT(TOPAZ_TQE_EMAC_1_PORT);
		else if (in_port == TOPAZ_TQE_EMAC_1_PORT)
			mcast_ent.port_bitmap &= ~BIT(TOPAZ_TQE_EMAC_0_PORT);
	}

	/* find the expected enqueue count and set the HBM buffer reference count */
	push_count = topaz_fwt_sw_mcast_enqueues(&mcast_ent, mcast_ent.port_bitmap,
						in_port, in_node);
	if (unlikely(!push_count))
		return 0;

	if (vlan_enabled) {
		cache_op_size = topaz_mcast_vlan_prepare(desc, mcast_ent.port_bitmap);
		header_access_bytes = max(header_access_bytes, cache_op_size);
		buf_virt_rx = bus_to_virt((unsigned long)desc->data.pkt);
	}

	tqe_buf_set_refcounts((uint8_t *)buf_virt_rx + desc->data.buff_ptr_offset,
		push_count, 0);

	if (header_access_bytes) {
		flush_and_inv_dcache_range((unsigned long)buf_virt_rx,
			(unsigned long)(buf_virt_rx + header_access_bytes));
	}

	/* push this packet to the tqe for each port/node */
	while (mcast_ent.port_bitmap) {
		if (mcast_ent.port_bitmap & 0x1) {
			if (topaz_fwt_sw_mcast_port_has_nodes(port)) {
				pushes += topaz_fwt_sw_mcast_do_per_node(tqe_push_mcast,
							&mcast_ent, desc, queue, in_node, port, tid);
			} else {
				if (port != in_port)  {
					tqe_push_mcast(desc, NULL, port, 0, 0);
					++pushes;
				}
			}
		}
		mcast_ent.port_bitmap >>= 1;
		port++;
	}

	if (unlikely(pushes != push_count)) {
		printk(KERN_CRIT "%s: pushes %u push_count %u, buffer leak imminent\n",
				__FUNCTION__, pushes, push_count);
	}

	return push_count;
}

static int __sram_text tqe_rx_get_node_id(const struct ether_header *eh)
{
	const struct fwt_db_entry *fwt_ent = NULL;

	if (likely(g_tqe_fwt_get_ucast_hook)) {
		fwt_ent = g_tqe_fwt_get_ucast_hook(eh->ether_shost, eh->ether_shost);
		if (likely(fwt_ent) && fwt_ent->valid)
			return fwt_ent->out_node;
	}

	return 0;
}

static inline
const uint16_t *
tqe_rx_ether_type_skip_vlan(const struct ether_header *eh, uint32_t len)
{
	const uint16_t *ether_type = &eh->ether_type;

	if (len < sizeof(struct ether_header))
		return NULL;

	if (qtn_ether_type_is_vlan(*ether_type)) {
		if (len < sizeof(struct ether_header) + VLAN_HLEN)
			return NULL;

		ether_type += VLAN_HLEN / sizeof(*ether_type);
	}

	/* coverity[illegal_address] */
	return ether_type;
}

#define TQE_RX_MCAST_CACHE_OP_SIZE	64

__may_sram_text int
tqe_rx_multicast(void *congest_queue, union topaz_tqe_cpuif_descr *desc,
		const uint16_t *ether_type, int cache_op)
{
	int timeout;
	union topaz_fwt_lookup fwt_lu;
	const struct topaz_fwt_sw_mcast_entry *mcast_ent = NULL;
	const struct ether_header *eh = bus_to_virt((uintptr_t) desc->data.pkt);
	const enum topaz_tqe_port in_port = desc->data.in_port;
	const void *ipaddr = NULL;
	uint8_t tid = 0;
	const void *iphdr = NULL;
	uint8_t in_node = 0;
	uint32_t ether_payload_length = 0;
	uint8_t false_miss = 0;

	COMPILE_TIME_ASSERT(sizeof(struct qtn_ipv6) >= sizeof(struct qtn_ipv4));
	COMPILE_TIME_ASSERT(TQE_RX_MCAST_CACHE_OP_SIZE >=
		sizeof(struct vlan_hdr) + sizeof(struct qtn_ipv6));

	iphdr = ether_type + 1;
	ether_payload_length = desc->data.length - ((char *)iphdr - (char *)eh);

	/* FIXME: this won't work for 802.3 frames */
	if (*ether_type == __constant_htons(ETH_P_IP)
			&& iputil_mac_is_v4_multicast(eh->ether_dhost)
			&& (ether_payload_length >= sizeof(struct qtn_ipv4))) {
		const struct qtn_ipv4 *ipv4 = (const struct qtn_ipv4 *)iphdr;
		/* do not accelerate IGMP */
		if (ipv4->proto == QTN_IP_PROTO_IGMP) {
			return 0;
		}
		ipaddr = &ipv4->dstip;
	} else if (*ether_type == __constant_htons(ETH_P_IPV6)
			&& iputil_mac_is_v6_multicast(eh->ether_dhost)
			&& (ether_payload_length >= sizeof(struct qtn_ipv6))) {
		const struct qtn_ipv6 *ipv6 = (const struct qtn_ipv6 *)iphdr;
		ipaddr = &ipv6->dstip;
	}

	if (ipaddr) {
		tid = topaz_tqe_vlan_gettid(bus_to_virt((uintptr_t)(desc->data.pkt)));
		fwt_lu = topaz_fwt_hw_lookup_wait_be(eh->ether_dhost, &timeout, &false_miss);
		if (fwt_lu.data.valid && !timeout) {
#ifndef TOPAZ_DISABLE_FWT_WAR
			if (unlikely(false_miss && g_tqe_fwt_false_miss_hook))
				g_tqe_fwt_false_miss_hook(fwt_lu.data.entry_addr, false_miss);
#endif

			if (g_tqe_fwt_get_mcast_hook)
				mcast_ent = g_tqe_fwt_get_mcast_hook(fwt_lu.data.entry_addr,
						ipaddr, *ether_type);

			if (mcast_ent) {
				if ((mcast_ent->flood_forward) && (in_port == TOPAZ_TQE_MUC_PORT)) {
					in_node = tqe_rx_get_node_id(eh);
					if (in_node == 0)
						return 0;
				}
				return tqe_push_mc_ports(congest_queue, mcast_ent, desc,
							tid, in_node,
							cache_op ? TQE_RX_MCAST_CACHE_OP_SIZE : 0);
			}
		}
	}

	return 0;
}
EXPORT_SYMBOL(tqe_rx_multicast);

static noinline void
tqe_rx_pkt_drop(const union topaz_tqe_cpuif_descr *desc)
{
	void *buf_virt_rx = bus_to_virt((unsigned long) desc->data.pkt);
	uint16_t buflen = desc->data.length;
	const int8_t dest_pool = topaz_hbm_payload_get_pool_bus(desc->data.pkt);
	void *buf_bus = topaz_hbm_payload_store_align_bus(desc->data.pkt, dest_pool, 0);

	cache_op_before_rx(buf_virt_rx, buflen, 0);

	topaz_hbm_filter_txdone_buf(buf_bus);
}

void tqe_register_mac_reserved_cbk(tqe_mac_reserved_hook cbk_func)
{
	g_tqe_mac_reserved_hook = cbk_func;
}
EXPORT_SYMBOL(tqe_register_mac_reserved_cbk);

void tqe_register_ucastfwt_cbk(tqe_fwt_get_ucast_hook cbk_func)
{
	g_tqe_fwt_get_ucast_hook = cbk_func;
}
EXPORT_SYMBOL(tqe_register_ucastfwt_cbk);

void tqe_register_macfwt_cbk(tqe_fwt_get_from_mac_hook cbk_func,
			tqe_fwt_add_from_mac_hook add_func, tqe_fwt_del_from_mac_hook del_func)
{
	 g_tqe_fwt_get_from_mac_hook = cbk_func;
	 g_tqe_fwt_add_from_mac_hook = add_func;
	 g_tqe_fwt_del_from_mac_hook = del_func;
}
EXPORT_SYMBOL(tqe_register_macfwt_cbk);

static __may_sram_text int
topaz_swfwd_tqe_xmit(const fwt_db_entry *fwt_ent,
				union topaz_tqe_cpuif_descr *desc,
				void *queue)
{
	uint8_t tid = 0;
	union topaz_tqe_cpuif_ppctl ctl;
	uint8_t tqe_free = queue ? 0 : 1;
	struct qtn_vlan_dev *vdev;
	uint8_t port;
	uint16_t misc_user = 0;
	uint16_t cache_op_size;

	if (unlikely(fwt_ent->out_port == TOPAZ_TQE_LHOST_PORT))
		return 0;

	if (vlan_enabled) {
		vdev = tqe_get_vlandev(fwt_ent->out_port, fwt_ent->out_node);
		if (unlikely(vdev == NULL)) {
			printk(KERN_CRIT "%s: vdev is null. port:%u node:%u\n",
					__FUNCTION__, fwt_ent->out_port, fwt_ent->out_node);
			if (g_tqe_fwt_del_from_mac_hook)
				g_tqe_fwt_del_from_mac_hook(fwt_ent->mac_id);

			tqe_rx_pkt_drop(desc);
			return 1;
		}

		if (unlikely(!qtn_vlan_egress(vdev, fwt_ent->out_node,
				bus_to_virt((uintptr_t)desc->data.pkt),
				&misc_user, 1))) {
			tqe_rx_pkt_drop(desc);
			return 1;
		}

		if (TOPAZ_TQE_PORT_IS_EMAC(vdev->port)) {
			cache_op_size = topaz_toemac_vlan_handle(vdev, desc, misc_user);
			flush_dcache_sizerange_safe(
				bus_to_virt((uintptr_t)desc->data.pkt), cache_op_size);
		}
	}

	if (g_dscp_flag)
		tid = (g_dscp_value[desc->data.in_port] & 0xFF);
	else
		tid = topaz_tqe_vlan_gettid(bus_to_virt((uintptr_t)(desc->data.pkt)));

	port = fwt_ent->out_port;
	misc_user |= (TOPAZ_TQE_PORT_IS_WMAC(port) ? TQE_MISCUSER_ANY2A_MAY_APPEND : 0);
	topaz_tqe_cpuif_ppctl_init(&ctl,
			port, &fwt_ent->out_node, 1, tid,
			fwt_ent->portal, 1, 0, tqe_free, misc_user);

	ctl.data.pkt = (void *)desc->data.pkt;
	ctl.data.buff_ptr_offset = desc->data.buff_ptr_offset;
	ctl.data.length = desc->data.length;
	ctl.data.buff_pool_num = TOPAZ_HBM_EMAC_TX_DONE_POOL;

	if (queue) {
		topaz_tqe_congest_queue_process(desc, queue, fwt_ent->out_node, tid, &ctl, 1);
	} else {
		topaz_tqe_wait_and_start(__func__, __LINE__, &ctl);
	}

	return 1;
}

struct tqe_unknown_dst_entry {
	unsigned char dst_mac[ETH_ALEN];
	unsigned long updated;
	STAILQ_ENTRY(tqe_unknown_dst_entry) next;
};

typedef STAILQ_HEAD(, tqe_unknown_dst_entry) tqe_unknown_dst_entry_head;

static int tqe_unknown_dst_entry_tot = 0;
static int tqe_unknown_dst_entry_max = 32;
module_param(tqe_unknown_dst_entry_max, int, S_IRWXU);
static int tqe_unknown_dst_expiry = HZ;
module_param(tqe_unknown_dst_expiry, int, S_IRWXU);

static spinlock_t tqe_unknown_dst_lock;
static tqe_unknown_dst_entry_head tqe_unknown_dst_entries;
static struct timer_list tqe_unknown_dst_timer;

static int tqe_unknown_dst_entry_add(const unsigned char *mac)
{
	struct tqe_unknown_dst_entry *entry;

	if (tqe_unknown_dst_entry_tot >= tqe_unknown_dst_entry_max)
		return -EBUSY;

	STAILQ_FOREACH(entry, &tqe_unknown_dst_entries, next) {
		if (memcmp(entry->dst_mac, mac, ETH_ALEN) == 0) {
			entry->updated = jiffies;
			return 0;
		}
	}

	entry = kmalloc(sizeof(struct tqe_unknown_dst_entry), GFP_ATOMIC);
	if (entry == NULL)
		return -ENOMEM;

	memcpy(entry->dst_mac, mac, ETH_ALEN);
	entry->updated = jiffies;
	STAILQ_INSERT_TAIL(&tqe_unknown_dst_entries, entry, next);

	tqe_unknown_dst_entry_tot++;

	if (tqe_unknown_dst_entry_tot == 1)
		mod_timer(&tqe_unknown_dst_timer, jiffies + tqe_unknown_dst_expiry);

	return 0;
}

static int tqe_unknown_dst_entry_del(struct tqe_unknown_dst_entry *entry)
{
	if (entry == NULL)
		return -EINVAL;

	KASSERT(tqe_unknown_dst_entry_tot > 0, ("should not be 0"));

	STAILQ_REMOVE(&tqe_unknown_dst_entries, entry, tqe_unknown_dst_entry, next);
	kfree(entry);

	tqe_unknown_dst_entry_tot--;

	return 0;
}

/* RCU lock must be held */
static struct net_bridge *tqe_find_bridge(const struct net_device *ndev)
{
	struct net_bridge *br = NULL;

	if ((ndev->flags & IFF_SLAVE) && ndev->master)
		ndev = ndev->master;

	if (rcu_dereference(ndev->br_port) != NULL)
		br = ndev->br_port->br;

	return br;
}

static int tqe_unknown_dst_local_find(const struct net_device *dev, unsigned char *mac)
{
	struct net_bridge_fdb_entry *fdb;
	struct net_bridge *br;

	int is_local = 0;

	if ((br_fdb_get_hook == NULL) || (br_fdb_put_hook == NULL))
		return 0;

	if (dev == NULL)
		return 0;

	rcu_read_lock();

	br = tqe_find_bridge(dev);
	if (!br)
		goto out;

	fdb = br_fdb_get_hook(br, NULL, mac);
	if (fdb == NULL)
		goto out;

	is_local = fdb->is_local;

	br_fdb_put_hook(fdb);

out:
	rcu_read_unlock();

	return is_local;
}

static void tqe_unknown_dst_timer_func(unsigned long data)
{
	struct tqe_unknown_dst_entry *cur_entry;
	struct tqe_unknown_dst_entry *tmp_entry;

	const struct fwt_db_entry *fwt_entry;

	if ((g_tqe_fwt_get_from_mac_hook == NULL) || (g_tqe_fwt_del_from_mac_hook == NULL))
		return;

	spin_lock(&tqe_unknown_dst_lock);

	STAILQ_FOREACH_SAFE(cur_entry, &tqe_unknown_dst_entries, next, tmp_entry) {
		if (time_before(jiffies, cur_entry->updated + tqe_unknown_dst_expiry))
			continue;

		fwt_entry = g_tqe_fwt_get_from_mac_hook(cur_entry->dst_mac);
		/*
		 * keep the "drop" FWT entry if it has been updated
		 * with correct destination port
		 */
		if ((fwt_entry != NULL) && (fwt_entry->out_port == TOPAZ_TQE_DROP_PORT))
			g_tqe_fwt_del_from_mac_hook(cur_entry->dst_mac);

		tqe_unknown_dst_entry_del(cur_entry);
	}

	if (tqe_unknown_dst_entry_tot > 0)
		mod_timer(&tqe_unknown_dst_timer, jiffies + tqe_unknown_dst_expiry);

	spin_unlock(&tqe_unknown_dst_lock);
}

static void tqe_unknown_dst_entry_init(void)
{
	STAILQ_INIT(&tqe_unknown_dst_entries);

	spin_lock_init(&tqe_unknown_dst_lock);

	init_timer(&tqe_unknown_dst_timer);

	tqe_unknown_dst_timer.function = tqe_unknown_dst_timer_func;
}

static noinline int topaz_tx_unknown_unicast(const union topaz_tqe_cpuif_descr *desc,
			const struct fwt_db_entry *fwt_ent)
{
	const struct fwt_db_entry *fwt_dst;

	struct ether_header *eth;
	struct net_device *dev;

	int ret;

	if (tqe_unknown_dst_entry_max == 0)
		return 0;

	if ((fwt_ent != NULL) && (fwt_ent->out_port == TOPAZ_TQE_DROP_PORT)) {
		/*
		 * Few packets may still be pushed to LHost before the "drop"
		 * FWT entry takes effect
		 */
		tqe_rx_pkt_drop(desc);

		return 1;
	}

	dev = (struct net_device *)tqe_port_handlers[desc->data.in_port].token;
	eth = bus_to_virt((uintptr_t)desc->data.pkt);
	/*
	 * Local addresses of Linux bridge don't have corresponding hardware FWT entries,
	 * hence they are always "unknown"
	 */
	if (tqe_unknown_dst_local_find(dev, eth->ether_dhost))
		return 0;

	if ((g_tqe_fwt_get_from_mac_hook == NULL) || (g_tqe_fwt_add_from_mac_hook == NULL))
		return 0;
	/*
	 * TODO fwt_ent is NULL in two cases:
	 *	src MAC address is not found in FWT
	 *	dst MAC address is not found in FWT
	 */
	fwt_dst = g_tqe_fwt_get_from_mac_hook(eth->ether_dhost);
	/*
	 * dst MAC address is found in FWT, but src MAC address is not: pass up for
	 * src MAC learning
	 */
	if (fwt_dst != NULL)
		return 0;

	spin_lock(&tqe_unknown_dst_lock);
	ret = tqe_unknown_dst_entry_add(eth->ether_dhost);
	spin_unlock(&tqe_unknown_dst_lock);

	if (ret < 0)
		return 0;
	/*
	 * add a "drop" FWT entry to push packets destined to same dst
	 * MAC address to "drop" port and drop them
	 */
	g_tqe_fwt_add_from_mac_hook(eth->ether_dhost, TOPAZ_TQE_DROP_PORT, 0, NULL);

	return 0;
}

#ifndef TOPAZ_CTRLPKT_TQE
#ifdef CONFIG_IPV6
static inline int topaz_ipv6_not_accel(const struct ipv6hdr *ipv6h, int seg_len)
{
	uint8_t nexthdr;
	const struct udphdr *udph;
	int nhdr_off;

	nhdr_off = iputil_v6_skip_exthdr(ipv6h, sizeof(struct ipv6hdr),
			&nexthdr, seg_len, NULL, NULL);

	if (nexthdr == IPPROTO_UDP) {
		udph = (const struct udphdr *)((const uint8_t *)ipv6h + nhdr_off);
		if (udph->source == __constant_htons(DHCPV6SERVER_PORT)
				&& udph->dest == __constant_htons(DHCPV6CLIENT_PORT))
			return 1;
	} else if (nexthdr == IPPROTO_ICMPV6) {
		return 1;
	}

	return 0;
}
#endif	/* CONFIG_IPV6 */
#endif	/* TOPAZ_CTRLPKT_TQE */

static inline int tqe_rx_is_ctrl_pkt(const struct ether_header *eh, unsigned int length)
{
#ifndef TOPAZ_CTRLPKT_TQE
	const struct vlan_ethhdr *vlan_hdr = (struct vlan_ethhdr *)eh;
	const struct iphdr *ipv4h;
	const struct ipv6hdr *ipv6h;
	uint16_t ether_type;
	uint16_t ether_hdrlen;

	ether_type = eh->ether_type;
	if (ether_type == __constant_htons(ETH_P_8021Q)) {
		ether_type = vlan_hdr->h_vlan_encapsulated_proto;
		ipv4h = (const struct iphdr *)(vlan_hdr + 1);
		ipv6h = (const struct ipv6hdr *)(vlan_hdr + 1);
		ether_hdrlen = sizeof(struct vlan_ethhdr);
	} else {
		ipv4h = (const struct iphdr *)(eh + 1);
		ipv6h = (const struct ipv6hdr *)(eh + 1);
		ether_hdrlen = sizeof(struct ether_header);
	}

	if (ether_type == __constant_htons(ETH_P_ARP))
		return 1;

	if (ether_type == __constant_htons(ETH_P_IP)
			&& iputil_ip_is_dhcp(ipv4h))
		return 1;

#ifdef CONFIG_IPV6
	if (ether_type == __constant_htons(ETH_P_IPV6)
			&& topaz_ipv6_not_accel(ipv6h, length - ether_hdrlen))
		return 1;
#endif
#endif

	return 0;
}

static __may_sram_text int
tqe_rx_pktfwd(void *queue, union topaz_tqe_cpuif_descr *desc)
{
	enum topaz_tqe_port in_port = desc->data.in_port;
	const struct fwt_db_entry *fwt_ent;
	const struct ether_header *eh = bus_to_virt((uintptr_t) desc->data.pkt);

	if (unlikely(!TOPAZ_TQE_PORT_IS_EMAC(in_port)))
		return 0;

	if (unlikely(tqe_rx_is_ctrl_pkt(eh, desc->data.length)))
		return 0;

	if (unlikely(!g_tqe_fwt_get_ucast_hook))
		return 0;

	fwt_ent = g_tqe_fwt_get_ucast_hook(eh->ether_shost, eh->ether_dhost);
	if (unlikely(!fwt_ent || (fwt_ent->out_port == TOPAZ_TQE_DROP_PORT)))
		return topaz_tx_unknown_unicast(desc, fwt_ent);

	/* Don't return to sender */
	if (unlikely((in_port == fwt_ent->out_port) ||
		((tqe_port_handlers[in_port].group > 0) &&
			tqe_port_handlers[in_port].group ==
				tqe_port_handlers[fwt_ent->out_port].group))) {
		tqe_rx_pkt_drop(desc);
		return 1;
	}

	return topaz_swfwd_tqe_xmit(fwt_ent, desc, queue);
}

static int wowlan_magic_packet_check(const union topaz_tqe_cpuif_descr *desc, const uint16_t *ether_type)
{
	const struct ether_header *eh = bus_to_virt((uintptr_t) desc->data.pkt);
	const void *iphdr = NULL;
	uint32_t ether_payload_length = 0;

	if (likely(!g_wowlan_host_state) ||
			(desc->data.in_port != TOPAZ_TQE_MUC_PORT))
		return 0;

	iphdr = (void *)(ether_type + 1);
	ether_payload_length = desc->data.length - ((char *)iphdr - (char *)eh);
	if ((*ether_type == __constant_htons(ETH_P_IP))
			&& (ether_payload_length < sizeof(struct iphdr))) {
		return 0;
	}

	return wowlan_is_magic_packet(*ether_type, eh, iphdr,
			g_wowlan_match_type,
			g_wowlan_l2_ether_type,
			g_wowlan_l3_udp_port);
}

static int tqe_rx_l2_ext_filter_handler(union topaz_tqe_cpuif_descr *desc, struct sk_buff *skb)
{
	enum topaz_tqe_port in_port = desc->data.in_port;
	const struct fwt_db_entry *fwt_ent;
	const struct ether_header *eh = bus_to_virt((uintptr_t) desc->data.pkt);

	if (in_port != g_l2_ext_filter_port)
		return 0;

	if (unlikely(!g_tqe_fwt_get_from_mac_hook))
		return 0;

	fwt_ent = g_tqe_fwt_get_from_mac_hook(eh->ether_shost);
	if (unlikely(!fwt_ent))
		return 0;

	if (TOPAZ_TQE_PORT_IS_WMAC(fwt_ent->out_port)) {
		/* Change the in port to prevent FWT updates */
		desc->data.in_port = TOPAZ_TQE_MUC_PORT;
		desc->data.misc_user = fwt_ent->out_node;
		skb->ext_l2_filter = 1;
		return 1;
	}

	return 0;
}

int __sram_text tqe_rx_l2_ext_filter(union topaz_tqe_cpuif_descr *desc, struct sk_buff *skb)
{
	if (unlikely(g_l2_ext_filter))
		return tqe_rx_l2_ext_filter_handler(desc, skb);

	return 0;
}
EXPORT_SYMBOL(tqe_rx_l2_ext_filter);

void __sram_text tqe_rx_call_port_handler(union topaz_tqe_cpuif_descr *desc,
		struct sk_buff *skb, uint8_t *whole_frm_hdr)
{
	enum topaz_tqe_port in_port = desc->data.in_port;

	tqe_port_handlers[in_port].handler(tqe_port_handlers[in_port].token,
						desc, skb, whole_frm_hdr);
}
EXPORT_SYMBOL(tqe_rx_call_port_handler);

static int tqe_rx_is_ext_filter_hairpin(union topaz_tqe_cpuif_descr *desc, struct sk_buff *skb)
{
	const struct ether_header *eh = bus_to_virt((uintptr_t)desc->data.pkt);
	const struct fwt_db_entry *fwt_ent;
	struct qtn_vlan_dev *vdev;
	struct net_device *dev;
	int vid = skb->vlan_tci & QVLAN_MASK_VID;
	int ret;

	if (desc->data.in_port != g_l2_ext_filter_port)
		return 0;

	if (unlikely(!g_tqe_fwt_get_from_mac_hook))
		return 0;
	fwt_ent = g_tqe_fwt_get_from_mac_hook(eh->ether_shost);
	if (!fwt_ent)
		return 0;

	vdev = tqe_get_vlandev(fwt_ent->out_port, fwt_ent->out_node);
	if (!vdev)
		return 0;
	if (vdev->pvid != vid)
		return 0;

	dev = dev_get_by_index(&init_net, vdev->ifindex);
	if (!dev)
		return 0;

	ret = QTN_FLAG_IS_L2_EXT_FILTER(dev->qtn_flags);
	dev_put(dev);

	return ret;
}

static noinline int tqe_rx_slow_path(union topaz_tqe_cpuif_descr *desc)
{
	void *buf_bus_rx = desc->data.pkt;
	void *buf_virt_rx = bus_to_virt((unsigned long) buf_bus_rx);
	uint16_t buflen = desc->data.length;
	const int8_t pool = topaz_hbm_payload_get_pool_bus(buf_bus_rx);
	struct sk_buff *skb = NULL;
	uint8_t *whole_frm_hdr = NULL;
	uint8_t vinfo_hdr =0;

	if (vlan_enabled)
		vinfo_hdr = QVLAN_PKTCTRL_LEN;

#if TOPAZ_HBM_BUF_WMAC_RX_QUARANTINE
	if (pool == TOPAZ_HBM_BUF_WMAC_RX_POOL) {
		skb = topaz_hbm_attach_skb_quarantine(buf_virt_rx, pool, buflen, &whole_frm_hdr);
		/* now desc doesn't link to the new skb data buffer */
		if (skb) {
			/* new buf is used, no need for original one */
			tqe_rx_pkt_drop(desc);
		}
	} else
#endif
	if (TOPAZ_TQE_PORT_IS_EMAC(desc->data.in_port)) {
		skb = topaz_hbm_attach_skb_ipalign((uint8_t *)buf_virt_rx, pool, buflen, vinfo_hdr, &whole_frm_hdr);
		/* The skb and its data buffer is allocated from kernel, hbm is not needed later */
		if (skb)
			tqe_rx_pkt_drop(desc);
	} else {
		skb = topaz_hbm_attach_skb((uint8_t *)buf_virt_rx, pool, vinfo_hdr);
		if (skb)
			whole_frm_hdr = skb->head;
	}

	if (skb) {
		/* attach VLAN information to skb */
		skb_put(skb, buflen);
		if (vlan_enabled) {
			struct qtn_vlan_pkt *pkt = qtn_vlan_get_info(skb->data);
			if (unlikely(pkt->magic != QVLAN_PKT_MAGIC)) {
				if (printk_ratelimit())
					printk(KERN_WARNING "%s: magic not right. \
						magic 0x%02x, flag 0x%02x\n",
						__func__, pkt->magic, pkt->flag);
			} else {
				skb->vlan_tci = pkt->vlan_info & QVLAN_MASK_VID;

				if (tqe_rx_is_ext_filter_hairpin(desc, skb))
					M_FLAG_SET(skb, M_L2_EXT_FILTER);
			}
			M_FLAG_SET(skb, M_VLAN_TAGGED);
		}

		/* Frame received from external L2 filter will not have MAC header */
		if (tqe_rx_l2_ext_filter(desc, skb))
			whole_frm_hdr = NULL;

		tqe_rx_call_port_handler(desc, skb, whole_frm_hdr);
		return 1;
	}

	return 0;
}

static __may_sram_text int
tqe_rx_desc_handler(const struct tqe_netdev_priv *priv,
	union topaz_tqe_cpuif_descr *desc, int to_stack)
{
	enum topaz_tqe_port in_port = desc->data.in_port;
	void *buf_bus_rx = desc->data.pkt;
	void *buf_virt_rx = bus_to_virt((unsigned long) buf_bus_rx);
	uint16_t buflen = desc->data.length;
	const int8_t pool = topaz_hbm_payload_get_pool_bus(buf_bus_rx);
	const struct ether_header *eh = bus_to_virt((uintptr_t) desc->data.pkt);
	const uint16_t *ether_type;

	if (unlikely(buf_bus_rx == NULL)) {
		printk_ratelimited(KERN_CRIT "%s: NULL buffer from TQE, len %u in_port %u",
			__func__, buflen, in_port);
		return -1;
	}

	if (unlikely(buflen < ETH_HLEN)) {
		printk_ratelimited(KERN_WARNING "%s: buffer from TQE too small, len %u in_port %u",
			__func__, buflen, in_port);
		return -1;
	}

	if (unlikely(!topaz_hbm_pool_valid(pool))) {
		printk_ratelimited(KERN_CRIT "%s: invalid pool buffer from TQE: 0x%p",
			__func__, buf_bus_rx);
		return -1;
	}

	if (likely((in_port < TOPAZ_TQE_NUM_PORTS) && tqe_port_handlers[in_port].handler)) {

		topaz_hbm_debug_stamp(topaz_hbm_payload_store_align_virt(buf_virt_rx, pool, 0),
				TOPAZ_HBM_OWNER_LH_RX_TQE, buflen);

		/* invalidate enough for l3 packet inspection for multicast frames */
		inv_dcache_sizerange_safe(buf_virt_rx, 64);

#if defined(CONFIG_ARCH_TOPAZ_SWITCH_TEST) || defined(CONFIG_ARCH_TOPAZ_SWITCH_TEST_MODULE)
		topaz_tqe_test_ctrl(buf_virt_rx);
#endif
		if (likely(TOPAZ_TQE_PORT_IS_EMAC(in_port))) {
			if (vlan_enabled) {
				struct qtn_vlan_dev *vdev = vport_tbl_lhost[in_port];
				BUG_ON(vdev == NULL);

				if (qtn_vlan_should_drop_stag(vdev, buf_virt_rx, vlan_drop_stag))
					return 0;

				if (!qtn_vlan_ingress(vdev, 0,
						buf_virt_rx, 0, 0, is_not_cache_aligned(buf_virt_rx))) {
					tqe_rx_pkt_drop(desc);
					return 0;
				}
			}
		} else if (in_port == TOPAZ_TQE_WMAC_PORT || in_port == TOPAZ_TQE_MUC_PORT) {
			if (g_tqe_mac_reserved_hook && g_tqe_mac_reserved_hook(eh->ether_shost)) {
				tqe_rx_pkt_drop(desc);
				return 0;
			}
		} else {
			BUG_ON(1);
		}

		ether_type = tqe_rx_ether_type_skip_vlan(eh, desc->data.length);

		if (likely(ether_type && !to_stack && !wowlan_magic_packet_check(desc, ether_type))) {
			if (is_multicast_ether_addr((uint8_t *)eh)) {
#ifdef CONFIG_TOPAZ_PCIE_HOST
				if (tqe_rx_multicast(NULL, desc, ether_type, 0))
#else
				if (tqe_rx_multicast(priv->congest_queue, desc, ether_type, 0))
#endif
					return 0;
			} else if (tqe_rx_pktfwd(priv->congest_queue, desc)) {
				return 0;
			}
		}

		if (tqe_rx_slow_path(desc))
			return 0;

	} else {
		printk_ratelimited(KERN_ERR
			"%s: input from unhandled port %u misc %u\n",
			__func__, in_port, (unsigned int)desc->data.misc_user);
	}

	tqe_rx_pkt_drop(desc);

	return 0;
}

static void tqe_irq_enable(void)
{
	topaz_tqe_cpuif_setup_irq(1, 0);
}

static void tqe_irq_disable(void)
{
	topaz_tqe_cpuif_setup_irq(0, 0);
}

static __may_sram_text int
tqe_napi(struct tqe_netdev_priv *priv, int budget, int port, int to_stack)
{
	int processed = 0;

	while (processed < budget) {
		union topaz_tqe_cpuif_status status;
		union topaz_tqe_cpuif_descr __iomem *desc_bus;
		union topaz_tqe_cpuif_descr *desc_virt;
		union topaz_tqe_cpuif_descr desc_local;
		uintptr_t inv_start;
		size_t inv_size;

		status = __topaz_tqe_cpuif_get_status(port);
		if (status.data.empty) {
			break;
		}

		desc_bus = __topaz_tqe_cpuif_get_curr(port);
		desc_virt = bus_to_virt((uintptr_t) desc_bus);

		/* invalidate descriptor and copy to the stack */
		inv_start = (uintptr_t) align_buf_cache(desc_virt);
		inv_size = align_buf_cache_size(desc_virt, sizeof(*desc_virt));
		inv_dcache_range(inv_start, inv_start + inv_size);
		memcpy(&desc_local, desc_virt, sizeof(*desc_virt));

		if (likely(desc_local.data.own)) {
			__topaz_tqe_cpuif_put_back(port, desc_bus);
			tqe_rx_desc_handler(priv, &desc_local, to_stack);
			++processed;
		} else {
			printk("%s unowned descriptor? desc_bus 0x%p 0x%08x 0x%08x 0x%08x 0x%08x\n",
					__FUNCTION__, desc_bus,
					desc_local.raw.dw0, desc_local.raw.dw1,
					desc_local.raw.dw2, desc_local.raw.dw3);
			break;
		}
	}

	return processed;
}

static __may_sram_text int
tqe_rx_napi_handler(struct napi_struct *napi, int budget)
{
	struct tqe_netdev_priv *priv = container_of(napi, struct tqe_netdev_priv, napi);
	int processed;

	processed = tqe_napi(priv, budget, TOPAZ_TQE_LHOST_PORT, 0);
	if (processed < budget) {
		napi_complete(napi);
		tqe_irq_enable();
	}

	return processed;
}

static irqreturn_t __sram_text tqe_irqh(int irq, void *_dev)
{
	struct net_device *dev = _dev;
	struct tqe_netdev_priv *priv = netdev_priv(dev);

	napi_schedule(&priv->napi);
	tqe_irq_disable();

	return IRQ_HANDLED;
}

#ifdef TOPAZ_CTRLPKT_TQE
static int tqe_rx_auc_napi_handler(struct napi_struct *napi, int budget)
{
	struct tqe_netdev_priv *priv = container_of(napi, struct tqe_netdev_priv, auc_napi);
	int processed;

	/*
	 * Lhost must be the only consumer of AuC ring.
	 */
	processed = tqe_napi(priv, budget, TOPAZ_TQE_AUC_PORT, 1);
	if (processed < budget) {
		napi_complete(napi);
		__topaz_tqe_cpuif_setup_irq(TOPAZ_TQE_AUC_PORT, 1, 0);
	}

	return processed;
}

static irqreturn_t tqe_auc_irqh(int irq, void *_dev)
{
	struct tqe_netdev_priv *priv;
	uint32_t status;

	status = readl(TOPAZ_LH_IPC4_INT);
	writel(status << 16, TOPAZ_LH_IPC4_INT);

	priv = netdev_priv((struct net_device *)_dev);

	napi_schedule(&priv->auc_napi);

	return IRQ_HANDLED;
}
#endif

/*
 * TQE network device ops
 */
static int tqe_ndo_open(struct net_device *dev)
{
	return -ENODEV;
}

static int tqe_ndo_stop(struct net_device *dev)
{
	return -ENODEV;
}

static int tqe_tx_buf(union topaz_tqe_cpuif_ppctl *ppctl,
		void __iomem *virt_buf, unsigned long data_len, int8_t pool)
{
	const uintptr_t bus_data_start = virt_to_bus(virt_buf);
	const long buff_ptr_offset = topaz_hbm_payload_buff_ptr_offset_bus((void *)bus_data_start, pool, NULL);

	ppctl->data.pkt = (void *) bus_data_start;
	ppctl->data.buff_ptr_offset = buff_ptr_offset;
	ppctl->data.length = data_len;
	/* always free to txdone pool */
	ppctl->data.buff_pool_num = TOPAZ_HBM_EMAC_TX_DONE_POOL;

	topaz_tqe_wait_and_start(__func__, __LINE__, ppctl);

	return 0;
}

void tqe_register_fwt_cbk(tqe_fwt_get_mcast_hook get_mcast_cbk_func,
				tqe_fwt_get_mcast_ff_hook get_mcast_ff_cbk_func,
				tqe_fwt_false_miss_hook false_miss_func)
{
	g_tqe_fwt_get_mcast_hook = get_mcast_cbk_func;
	g_tqe_fwt_get_mcast_ff_hook = get_mcast_ff_cbk_func;
	g_tqe_fwt_false_miss_hook = false_miss_func;
}
EXPORT_SYMBOL(tqe_register_fwt_cbk);

int tqe_tx(union topaz_tqe_cpuif_ppctl *ppctl, struct sk_buff *skb)
{
	unsigned int data_len = skb->len;
	void *buf_virt = skb->data;
	void *buf_bus = (void *) virt_to_bus(buf_virt);
	void *buf_virt_vlan;
	int8_t pool = topaz_hbm_payload_get_pool_bus(buf_bus);
	const bool hbm_can_use = !vlan_enabled &&
		topaz_hbm_pool_valid(pool) &&
		(atomic_read(&skb->users) == 1) &&
		(atomic_read(&skb_shinfo(skb)->dataref) == 1);

	if (tqe_frames_need_meta_info(ppctl->data.out_port) &&
	    !M_FLAG_ISSET(skb, M_HAS_RADIO_INFO)) {
		pr_warning_ratelimited("%s: no meta info; proto=0x%x\n",
				       __func__, ntohs(skb->protocol));
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	if (hbm_can_use) {
		/*
		 * skb is otherwise unused; clear to send out tqe.
		 * Set flag such that payload isn't returned to the hbm on free
		 */
		skb->hbm_no_free = 1;

		topaz_hbm_flush_skb_cache(skb);
	} else {
		void *hbm_buf_virt;
		uintptr_t flush_start;
		size_t flush_size;

		if (data_len <= topaz_hbm_pool_buf_max_size(TOPAZ_HBM_BUF_EMAC_RX_POOL)) {
			pool = TOPAZ_HBM_BUF_EMAC_RX_POOL;
		} else {
			printk_ratelimited(
				KERN_ERR "%s: [%s] drop oversize tx, %u bytes to port %u\n",
				__func__, skb->dev->name, data_len,
				ppctl->data.out_port);
			kfree_skb(skb);
			return NETDEV_TX_OK;
		}

		hbm_buf_virt = topaz_hbm_get_payload_virt(pool);
		if (unlikely(!hbm_buf_virt)) {
			/* buffer will be stored in gso_skb and re-attempted for xmit */
			return NETDEV_TX_BUSY;
		}

		topaz_hbm_debug_stamp(hbm_buf_virt, TOPAZ_HBM_OWNER_LH_TX_TQE, data_len);

		memcpy(hbm_buf_virt, buf_virt, data_len);
		buf_virt = hbm_buf_virt;

		if (M_FLAG_ISSET(skb, M_VLAN_TAGGED)) {
			buf_virt_vlan = qtn_vlan_get_info(buf_virt);
			memcpy(buf_virt_vlan, (uint8_t *)qtn_vlan_get_info(skb->data),
					QVLAN_PKTCTRL_LEN);
			flush_start = (uintptr_t) align_buf_cache(buf_virt_vlan);
			flush_size = align_buf_cache_size(buf_virt_vlan, data_len + QVLAN_PKTCTRL_LEN);
		} else {
			flush_start = (uintptr_t) align_buf_cache(buf_virt);
			flush_size = align_buf_cache_size(buf_virt, data_len);
		}

		flush_and_inv_dcache_range(flush_start, flush_start + flush_size);
	}

	if (tqe_frames_need_meta_info(ppctl->data.out_port))
		hbm_buf_append_meta_info(buf_virt, &data_len, skb->qtn_cb.radio_info.macid,
				skb->qtn_cb.radio_info.ifidx);

	dev_kfree_skb(skb);

	tqe_tx_buf(ppctl, buf_virt, data_len, pool);

	return NETDEV_TX_OK;
}
EXPORT_SYMBOL(tqe_tx);

static netdev_tx_t tqe_ndo_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static const struct net_device_ops tqe_ndo = {
	.ndo_open = tqe_ndo_open,
	.ndo_stop = tqe_ndo_stop,
	.ndo_start_xmit = tqe_ndo_start_xmit,
	.ndo_set_mac_address = eth_mac_addr,
};

static int tqe_descs_alloc(struct tqe_netdev_priv *priv)
{
	int i;
	union topaz_tqe_cpuif_descr __iomem *bus_descs;

	if (ALIGNED_DMA_DESC_ALLOC(&priv->rx, QTN_BUFS_LHOST_TQE_RX_RING, TOPAZ_TQE_CPUIF_RXDESC_ALIGN, 1)) {
		return -ENOMEM;
	}

	bus_descs = (void *)priv->rx.descs_dma_addr;
	for (i = 0; i < QTN_BUFS_LHOST_TQE_RX_RING; i++) {
		priv->rx.descs[i].data.next = &bus_descs[(i + 1) % QTN_BUFS_LHOST_TQE_RX_RING];
	}

	printk(KERN_INFO "%s: %u tqe_rx_descriptors at kern uncached 0x%p bus 0x%p\n",
			__FUNCTION__, priv->rx.desc_count, priv->rx.descs, bus_descs);

	topaz_tqe_cpuif_setup_ring((void *)priv->rx.descs_dma_addr, priv->rx.desc_count);

	return 0;
}

static void tqe_descs_free(struct tqe_netdev_priv *priv)
{
	if (priv->rx.descs) {
		ALIGNED_DMA_DESC_FREE(&priv->rx);
	}
}

void print_tqe_counters(struct tqe_netdev_priv *priv)
{
	int i;

	if (priv->congest_queue == NULL)
		return;

	for (i = 0; i < TOPAZ_CONGEST_QUEUE_NUM; i++)
		printk("rx_congest_fwd %d:\t%08x \t%d\n",
			i, priv->congest_queue->queues[i].congest_xmit,
			priv->congest_queue->queues[i].qlen);

	for (i = 0; i < TOPAZ_CONGEST_QUEUE_NUM; i++)
		printk("rx_congest_drop %d:\t%08x\n",
			i, priv->congest_queue->queues[i].congest_drop);

	for (i = 0; i < TOPAZ_CONGEST_QUEUE_NUM; i++)
		printk("rx_congest_enq_fail %d:\t%08x\n",
			i, priv->congest_queue->queues[i].congest_enq_fail);

	/* Congest Queue */
	printk("rx_congest_entry:\t%08x\n", priv->congest_queue->func_entry);
	printk("rx_congest_retry:\t%08x\n", priv->congest_queue->cnt_retries);
	printk("rx_congest_state:\t%08x\n", priv->congest_queue->cong_state);
	printk("total len:\t%08x \tunicast count:%d\n",
			priv->congest_queue->total_qlen,
			priv->congest_queue->unicast_qcount);
}

static ssize_t tqe_dbg_show(struct device *dev, struct device_attribute *attr,
						char *buff)
{
	return 0;
}

static void tqe_init_port_handler(void)
{
	memset(tqe_port_handlers, 0, sizeof(tqe_port_handlers));
	return;
}

static ssize_t tqe_dbg_set(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct net_device *ndev = container_of(dev, struct net_device, dev);
	struct tqe_netdev_priv *priv = netdev_priv(ndev);
	char buffer[128];
	char *str = buffer;
	char *token;
	uint32_t cmd;

	strncpy(str, buf, sizeof(buffer) - 1);

	token = strsep(&str, " ,\n");
	cmd = (uint32_t)simple_strtoul(token, NULL, 10);
	switch (cmd) {
	case 0:
		print_tqe_counters(priv);
		break;
	case 1:
		topaz_congest_dump(priv->congest_queue);
		break;
	case 2:
		topaz_congest_node(priv->congest_queue);
		break;
	default:
		break;
	}

	return count;
}
DEVICE_ATTR(dbg, S_IWUSR | S_IRUSR, tqe_dbg_show, tqe_dbg_set); /* dev_attr_dbg */

#ifdef TOPAZ_CTRLPKT_TQE
#define TOPAZ_TQE_CTRLPKT_QLEN	64
static int tqe_prepare_auc(struct tqe_netdev_priv *priv)
{
	int i;
	union topaz_tqe_cpuif_descr __iomem *bus_descs;

	if (ALIGNED_DMA_DESC_ALLOC(&priv->auc_rx, TOPAZ_TQE_CTRLPKT_QLEN,
			TOPAZ_TQE_CPUIF_RXDESC_ALIGN, 1)) {
		printk(KERN_INFO"%s:allocation failed\n",__func__);
		return -ENOMEM;
	}

	bus_descs = (void *)priv->auc_rx.descs_dma_addr;
	for (i = 0; i < TOPAZ_TQE_CTRLPKT_QLEN; i++) {
		priv->auc_rx.descs[i].data.next = &bus_descs[(i + 1) % TOPAZ_TQE_CTRLPKT_QLEN];
	}

	/* Initialise TQE */
	__topaz_tqe_cpuif_setup_reset(TOPAZ_TQE_AUC_PORT, 1);
	__topaz_tqe_cpuif_setup_reset(TOPAZ_TQE_AUC_PORT, 0);

	/* Set descriptor ring up */
	__topaz_tqe_cpuif_setup_ring(TOPAZ_TQE_AUC_PORT,
		(void *)priv->auc_rx.descs_dma_addr, priv->auc_rx.desc_count);

	/* postpone IRQ enabling */

	return 0;
}

static void tqe_unprepare_auc(struct tqe_netdev_priv *priv)
{
	if (priv->auc_rx.descs) {
		ALIGNED_DMA_DESC_FREE(&priv->auc_rx);
	}
}
#endif

static struct net_device * __init tqe_netdev_init(void)
{
	int rc = 0;
	struct net_device *dev = NULL;
	struct tqe_netdev_priv *priv;
	static const int tqe_netdev_irq = TOPAZ_IRQ_TQE;

	tqe_init_port_handler();

	dev = alloc_netdev(sizeof(struct tqe_netdev_priv), "tqe", &ether_setup);
	if (!dev) {
		printk(KERN_ERR "%s: unable to allocate dev\n", __FUNCTION__);
		goto netdev_alloc_error;
	}
	priv = netdev_priv(dev);

	dev->base_addr = 0;
	dev->irq = tqe_netdev_irq;
	dev->watchdog_timeo = 60 * HZ;
	dev->tx_queue_len = 1;
	dev->netdev_ops = &tqe_ndo;

	/* Initialise TQE */
	topaz_tqe_cpuif_setup_reset(1);
	topaz_tqe_cpuif_setup_reset(0);

	if (tqe_descs_alloc(priv))
		goto desc_alloc_error;

#ifdef TOPAZ_CTRLPKT_TQE
	if (tqe_prepare_auc(priv))
		goto auc_prepare_error;
#endif

	rc = request_irq(dev->irq, &tqe_irqh, 0, dev->name, dev);
	if (rc) {
		printk(KERN_ERR "%s: unable to get %s IRQ %d\n",
				__FUNCTION__, dev->name, tqe_netdev_irq);
		goto irq_request_error;
	}

#ifdef TOPAZ_CTRLPKT_TQE
	rc = request_irq(TOPAZ_IRQ_IPC4, tqe_auc_irqh, 0, "AuC TQE", dev);
	if (rc) {
		printk(KERN_ERR"%s: unable to get Lhost IPC4 IRQ %d\n",
			__FUNCTION__, TOPAZ_IRQ_IPC4);
		goto irq_ipchi_request_error;
	}
#endif

#ifndef CONFIG_TOPAZ_PCIE_HOST
	/* Initialize congestion queue */
	priv->congest_queue = topaz_congest_queue_init();
	if (priv->congest_queue == NULL) {
		printk(KERN_ERR "LHOST TQE: Can't allocate congest queue\n");
		goto congest_queue_alloc_error;
	}
	priv->congest_queue->xmit_func = topaz_tqe_xmit;
#endif
	rc = register_netdev(dev);
	if (rc) {
		printk(KERN_ERR "%s: Cannot register net device '%s', error %d\n",
				__FUNCTION__, dev->name, rc);
		goto netdev_register_error;
	}

	netif_napi_add(dev, &priv->napi, tqe_rx_napi_handler, 8);
	napi_enable(&priv->napi);

	tqe_irq_enable();

#ifdef TOPAZ_CTRLPKT_TQE
	netif_napi_add(dev, &priv->auc_napi, tqe_rx_auc_napi_handler, 8);
	napi_enable(&priv->auc_napi);

	writel(1, TOPAZ_LH_IPC4_INT_MASK);
	__topaz_tqe_cpuif_setup_irq(TOPAZ_TQE_AUC_PORT, 1, 0);
#endif

	device_create_file(&dev->dev, &dev_attr_dbg);

	tqe_unknown_dst_entry_init();

	return dev;

netdev_register_error:
	topaz_congest_queue_exit(priv->congest_queue);
#ifndef CONFIG_TOPAZ_PCIE_HOST
congest_queue_alloc_error:
#ifdef TOPAZ_CTRLPKT_TQE
	free_irq(TOPAZ_IRQ_IPC4, dev);
#endif
#endif
#ifdef TOPAZ_CTRLPKT_TQE
irq_ipchi_request_error:
#endif
	free_irq(dev->irq, dev);
irq_request_error:
#ifdef TOPAZ_CTRLPKT_TQE
	tqe_unprepare_auc(priv);
auc_prepare_error:
#endif
	tqe_descs_free(priv);
desc_alloc_error:
	free_netdev(dev);
netdev_alloc_error:
	return NULL;
}


static void __exit tqe_netdev_exit(struct net_device *dev)
{
	struct tqe_netdev_priv *priv  = netdev_priv(dev);

	device_remove_file(&dev->dev, &dev_attr_dbg);
	__topaz_tqe_cpuif_setup_irq(TOPAZ_TQE_AUC_PORT, 0, 0);
	writel(0, TOPAZ_LH_IPC4_INT_MASK);
	tqe_irq_disable();
	napi_disable(&priv->napi);
	free_irq(dev->irq, dev);
#ifdef TOPAZ_CTRLPKT_TQE
	napi_disable(&priv->auc_napi);
	free_irq(TOPAZ_IRQ_IPC4, dev);
#endif
	free_netdev(dev);
	topaz_congest_queue_exit(priv->congest_queue);
}

static struct net_device *tqe_netdev;

static int __init tqe_module_init(void)
{
	tqe_netdev = tqe_netdev_init();

	return tqe_netdev ? 0 : -EFAULT;
}

static void __exit tqe_module_exit(void)
{
	tqe_netdev_exit(tqe_netdev);
}

module_init(tqe_module_init);
module_exit(tqe_module_exit);

MODULE_LICENSE("GPL");

