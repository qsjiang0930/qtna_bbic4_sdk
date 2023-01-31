/**
 * Copyright (c) 2012-2013 Quantenna Communications, Inc.
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

#include <linux/timer.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <qtn/dmautil.h>
#include <drivers/ruby/dma_cache_ops.h>
#include <asm/board/board_config.h>
#include "net80211/ieee80211.h"

#include <qtn/topaz_tqe.h>
#include <qtn/topaz_fwt_sw.h>
#include <qtn/topaz_hbm_cpuif.h>
#include <qtn/topaz_hbm.h>
#include <qtn/topaz_qfp.h>
#include "topaz_pcie_tqe.h"
#include "topaz_vnet.h"
#include <linux/if_vlan.h>
#include <qtn/qdrv_sch.h>
#include <qtn/mproc_sync.h>
#include <qtn/qtn_vlan.h>

extern int tqe_sem_en;

static struct net_device *g_tqe_pcie_ndev = NULL;

struct tqe_netdev_priv {
	struct napi_struct napi;
	struct net_device_stats stats;
	struct net_device *pcie_ndev;

	ALIGNED_DMA_DESC(union, topaz_tqe_pcieif_descr) rx;

	uint32_t tqe_xmit_cnt;
	uint32_t fail_get_sem_cnt;
	uint32_t fail_rel_sem_cnt;
};

RUBY_INLINE uint32_t
topaz_pcie_tqe_multi_proc_sem_down(void)
{
	if (tqe_sem_en == 0)
		return 1;

	return _qtn_mproc_3way_tqe_sem_down(TOPAZ_MPROC_TQE_SEM_LHOST);
}

RUBY_INLINE uint32_t
topaz_pcie_tqe_multi_proc_sem_up(void)
{
	if (tqe_sem_en == 0)
		return 1;

	if (_qtn_mproc_3way_tqe_sem_up(TOPAZ_MPROC_TQE_SEM_LHOST)) {
		return 1;
	} else {
		WARN_ONCE(1, "%s failed to release HW semaphore\n", __func__);
		return 0;
	}
}

static void pcie_tqe_dbg_print(struct tqe_netdev_priv *priv)
{
	printk("tqe xmit count: %u\n", priv->tqe_xmit_cnt);
	printk("tqe failed to get HW semaphore %u\n",priv->fail_get_sem_cnt);
	printk("tqe failed to release HW semaphore %u\n",priv->fail_rel_sem_cnt);
}

/* used for PCIE_TQE_INTR_WORKAROUND */
void tqe_dsp_irq_enable(void)
{
	__topaz_tqe_cpuif_setup_irq(TOPAZ_TQE_DSP_PORT, 1, 0);
}

/* used for non-PCIE_TQE_INTR_WORKAROUND */
void tqe_pcie_irq_enable(void)
{
	__topaz_tqe_cpuif_setup_irq(TOPAZ_TQE_PCIE_PORT, 1, 0);
}

/* used for PCIE_TQE_INTR_WORKAROUND */
#define tqe_dsp_irq_disable()

/* used for non-PCIE_TQE_INTR_WORKAROUND */
RUBY_INLINE void tqe_pcie_irq_disable(void)
{
	__topaz_tqe_cpuif_setup_irq(TOPAZ_TQE_PCIE_REL_PORT, 0, 0);
}

static union topaz_tqe_pcieif_descr * desc_bus_to_uncached(struct tqe_netdev_priv *priv, void *_bus_desc)
{
	unsigned long bus_desc = (unsigned long)_bus_desc;
	unsigned long bus_start = priv->rx.descs_dma_addr;
	unsigned long virt_start = (unsigned long)&priv->rx.descs[0];
	return (void *)(bus_desc - bus_start + virt_start);
}

#ifdef CONFIG_TOPAZ_DBDC_HOST
extern const struct topaz_fwt_sw_mcast_entry *fwt_sw_get_mcast_entry(uint16_t fwt_index, const void *addr, uint16_t ether_type, uint8_t vap_idx);
extern struct net_device *get_qfp_netdev_by_id(uint8_t id);
extern int qfp_has_virtual_network(void);
extern int qfp_throttle_check_tx(struct sk_buff *skb, int dev_id);
extern int qfp_tx(struct sk_buff *skb, struct net_device *ndev);
/* Forcibly save topaz_dbdc_pcie_tx_mcast_per_dev in ram becuase sram don't have enough space */
__attribute__((section(".text"))) void topaz_dbdc_pcie_tx_mcast_per_dev(struct sk_buff *skb)
{
	struct net_device *ndev;
	struct sk_buff *newskb;
	int fwt_index;
	const struct topaz_fwt_sw_mcast_entry *mcast_ent_shared = NULL;
	struct topaz_fwt_sw_mcast_entry mcast_ent;
	const struct ethhdr *eh = eth_hdr(skb);
	const struct vlan_ethhdr *vlan_hdr = (struct vlan_ethhdr *)eh;
	const struct iphdr *ipv4h;
	const struct ipv6hdr *ipv6h;
	uint16_t ether_type;
	const void *ipaddr = NULL;
	uint8_t dev_id;

	ether_type = eh->h_proto;
	if (ether_type == __constant_htons(ETH_P_8021Q)) {
		ether_type = vlan_hdr->h_vlan_encapsulated_proto;
		ipv4h = (const struct iphdr *)(vlan_hdr + 1);
		ipv6h = (const struct ipv6hdr *)(vlan_hdr + 1);
	} else {
		ipv4h = (const struct iphdr *)(eh + 1);
		ipv6h = (const struct ipv6hdr *)(eh + 1);
	}

	if (ether_type == __constant_htons(ETH_P_IP))
		ipaddr = &ipv4h->daddr;
	else if (ether_type == __constant_htons(ETH_P_IPV6))
		ipaddr = &ipv6h->daddr;

	fwt_index = fwt_sw_get_index_from_mac_be(eh->h_dest);
	if (unlikely(fwt_index < 0))
		goto out;

	mcast_ent_shared = fwt_sw_get_mcast_entry(fwt_index, ipaddr, ether_type, 0);
	if (unlikely(!mcast_ent_shared))
		goto out;

	mcast_ent = *mcast_ent_shared;
	for (dev_id = 0; dev_id < MAX_QFP_NETDEV; ++dev_id) {
		if (topaz_fwt_sw_mcast_dev_is_set(&mcast_ent, dev_id)) {
			topaz_fwt_sw_mcast_dev_clear(&mcast_ent, dev_id);

			if (!qfp_throttle_check_tx(skb, dev_id))
				continue;

			ndev = get_qfp_netdev_by_id(dev_id);
			if (unlikely(!ndev))
				continue;

			if (vlan_enabled && !qtn_vlan_egress(vdev_tbl_lhost[QFP_VDEV_IDX(dev_id)], 0, skb->data, 0, 0))
				continue;

			if (topaz_fwt_sw_mcast_dev_is_empty(&mcast_ent) && !vlan_enabled) {
				newskb = skb;
				skb = NULL;
			} else {
				newskb = skb_copy(skb, GFP_ATOMIC);
			}
			if (unlikely(!newskb))
				continue;

			if (qfp_tx(newskb, ndev) != 0) {
				dev_kfree_skb_any(newskb);
				continue;
			}
		}
	}
out:
	if (skb)
		dev_kfree_skb_any(skb);
}

static void topaz_dbdc_pcie_tx(void *pkt_handle, struct net_device *ndev)
{
	uint32_t baddr, vaddr;
	union topaz_tqe_pcieif_descr *tqe_desc
		= (union topaz_tqe_pcieif_descr *)pkt_handle;
	baddr = (uint32_t)tqe_desc->data.pkt;
	vaddr = (uint32_t)bus_to_virt(baddr);
	int8_t pool;
	struct sk_buff *skb = NULL;
	fwt_db_entry *entry = NULL;
	struct net_device *real_ndev = NULL;
	int dev_id = 0;

	pool = topaz_hbm_payload_get_pool_bus((void *)baddr);
	if (pool < 0) {
		if (printk_ratelimit())
			printk(KERN_ERR "%s: Pool not found!\n", __func__);
		return;
	}

	KASSERT((tqe_desc->data.need_to_free == 1), ("tqe desc need_to_free is 0"));

	skb = topaz_hbm_attach_skb_for_qfp((void *)vaddr, (uint32_t)tqe_desc->data.length, pool, 1,
					   vlan_enabled ? QVLAN_PKTCTRL_LEN : 0);
	if (likely(skb)) {
		skb_put(skb, tqe_desc->data.length);
		skb->protocol = eth_type_trans(skb, ndev);
		skb_push(skb, ETH_HLEN);

		if (qfp_has_virtual_network()) {
			if (likely(!is_multicast_ether_addr(eth_hdr(skb)->h_dest)))
				entry = fwt_sw_fast_get_ucast_entry(eth_hdr(skb)->h_source,
						eth_hdr(skb)->h_dest);
			else
				return topaz_dbdc_pcie_tx_mcast_per_dev(skb);

			if (entry) {
				dev_id = entry->dev_id;
				real_ndev = get_qfp_netdev_by_id(entry->dev_id);
				if (real_ndev)
					ndev = real_ndev;
			}
		}
		if (ndev) {
			if (!qfp_throttle_check_tx(skb, dev_id))
				goto bail;

			if (qfp_tx(skb, ndev) == NETDEV_TX_BUSY)
				goto bail;
		} else {
			goto bail;
		}
	} else {
		goto bail;
	}
	return;
bail:
	if (skb) {
		dev_kfree_skb_any(skb);
	} else {
		topaz_hbm_release_buf_safe((void *)baddr);
	}
}
#endif

static int __attribute__((section(".sram.pcietx.text"))) tqe_rx_napi_handler(struct napi_struct *napi, int budget)
{
	int processed = 0;
	struct tqe_netdev_priv *priv = container_of(napi, struct tqe_netdev_priv, napi);
#ifndef CONFIG_TOPAZ_DBDC_HOST
	struct vmac_priv *vmp = netdev_priv(priv->pcie_ndev);
#endif
	int tqe_has_pkt = 1;

	topaz_hbm_filter_txdone_pool(0);

	while (processed < budget) {
		union topaz_tqe_cpuif_status status;
		union topaz_tqe_pcieif_descr __iomem *bus_desc;
		union topaz_tqe_pcieif_descr *uncached_virt_desc;

		status = topaz_tqe_pcieif_get_status();
		if (status.data.empty) {
			tqe_has_pkt = 0;
			break;
		}

#ifndef CONFIG_TOPAZ_DBDC_HOST
		if (vmp->txqueue_stopped)
			break;
#endif

		bus_desc = topaz_tqe_pcieif_get_curr();
		uncached_virt_desc = desc_bus_to_uncached(priv, bus_desc);

		if (likely(uncached_virt_desc->data.own)) {
#ifndef CONFIG_TOPAZ_DBDC_HOST
			if (vmac_tx(uncached_virt_desc, priv->pcie_ndev, PKT_TQE)
				== NETDEV_TX_OK) {
				topaz_tqe_pcieif_put_back(bus_desc);
			} else {
				break;
			}

#else
			topaz_dbdc_pcie_tx(uncached_virt_desc, priv->pcie_ndev);
			topaz_tqe_pcieif_put_back(bus_desc);
#endif
		/* TODO: when the code compiled for EP, vmac_tx may return VMAC_RC_BUSY
		 * Currently, we increase processed and don't complete napi.
		 * Need implement wake up in RC side
		 * If RC is strong enough, vmac_tx seldom return VMAC_RC_BUSY.
		 */

			++processed;

		} else {
			printk("%s unowned descriptor? bus_desc 0x%p\n",
				__FUNCTION__, bus_desc);
			break;
		}
	}

	if (processed < budget)	{
		uint32_t flags;
		napi_complete(napi);

		local_irq_save(flags);
#ifndef CONFIG_TOPAZ_DBDC_HOST
		if (vmp->txqueue_stopped)
			vmp->tqe_flag = (tqe_has_pkt) ? TQE_NAPI_SCHED : TQE_ENABLE_INTR;
		else
			vmp->tqe_irq_enable();
#else
		if (PCIE_TQE_INTR_WORKAROUND)
			tqe_dsp_irq_enable();
		else
			tqe_pcie_irq_enable();
#endif
		local_irq_restore(flags);
	}

	return processed;
}

/* used for handle tqe irq on board with PCIE_TQE_INTR_WORKAROUND */
static irqreturn_t
__attribute__((section(".sram.pcietx.text"))) tqe_irqh_workaround(int irq, void *_dev)
{
	struct net_device *dev = _dev;
	struct tqe_netdev_priv *priv = netdev_priv(dev);
	uint32_t ipcstat;

	ipcstat = readl(TOPAZ_LH_IPC3_INT) & 0xffff;
	if (ipcstat) {
		writel(ipcstat << 16, TOPAZ_LH_IPC3_INT);

		if(ipcstat & 0x1) {
			napi_schedule(&priv->napi);
			tqe_dsp_irq_disable();
		}
	}

	return IRQ_HANDLED;
}

/* used for handle tqe irq on board without PCIE_TQE_INTR_WORKAROUND */
static irqreturn_t
__attribute__((section(".sram.pcietx.text"))) tqe_irqh(int irq, void *_dev)
{
	struct net_device *dev = _dev;
	struct tqe_netdev_priv *priv = netdev_priv(dev);
	uint32_t pciestat;

	pciestat = readl(TOPAZ_SYS_CTL_PCIE_INT_STATUS) & TOPAZ_SYS_CTL_TQE_INT_STATS_BIT;
	if (pciestat) {
		napi_schedule(&priv->napi);
		tqe_pcie_irq_disable();
	}

	return IRQ_HANDLED;
}

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

extern int fwt_sw_get_index_from_mac_be(const uint8_t *mac_be);
fwt_db_entry *vmac_get_tqe_ent(const unsigned char *src_mac_be, const unsigned char *dst_mac_be)
{
	int index = 0;
	fwt_db_entry *fwt_ent, *fwt_ent_out;

	index = fwt_sw_get_index_from_mac_be(dst_mac_be);
	if (index < 0) {
		return NULL;
	}
	fwt_ent = fwt_db_get_table_entry(index);
	if (fwt_ent && fwt_ent->valid) {
		fwt_ent_out = fwt_ent;
	} else {
		return NULL;
	}

	index = fwt_sw_get_index_from_mac_be(src_mac_be);
	if (index < 0) {
		return NULL;
	}
	fwt_ent = fwt_db_get_table_entry(index);
	if (!fwt_ent || !fwt_ent->valid)
		return NULL;

	return fwt_ent_out;
}

__attribute__((section(".sram.pcierx.text")))
void topaz_pcie_prepare_pp_cntl(union topaz_tqe_cpuif_ppctl *pp_cntl,
	uint32_t tid, fwt_db_entry *fwt_ent, void *data_bus, int data_len,
	uint16_t vlan_miscuser)
{
	uint8_t port;
	uint8_t node;
	uint8_t portal;
	int8_t pool = topaz_hbm_payload_get_pool_bus(data_bus);
	const long buff_ptr_offset =
		topaz_hbm_payload_buff_ptr_offset_bus(data_bus, pool, NULL);
#if defined (CONFIG_TOPAZ_PCIE_TARGET) || defined (CONFIG_TOPAZ_DBDC_HOST)
	uint16_t misc_user = (TQE_MISCUSER_ANY2A_MAY_APPEND | vlan_miscuser);
#else
	uint16_t misc_user = vlan_miscuser;
#endif
#if defined CONFIG_TOPAZ_PCIE_TARGET
	uint8_t tqe_full_free = 0;
#else
	uint8_t tqe_full_free = 1;
#endif

	port = fwt_ent->out_port;
	node = fwt_ent->out_node;
	portal = fwt_ent->portal;

	topaz_tqe_cpuif_ppctl_init(pp_cntl,
			port, &node, 1, tid,
			portal, 1, 0, tqe_full_free, misc_user);

	pp_cntl->data.pkt = (void *)data_bus;
	pp_cntl->data.buff_ptr_offset = buff_ptr_offset;
	pp_cntl->data.length = data_len;
	pp_cntl->data.buff_pool_num = pool;
}

#if defined (CONFIG_TOPAZ_PCIE_HOST) || defined (CONFIG_TOPAZ_DBDC_HOST)
__attribute__((section(".sram.text"))) int topaz_pcie_tqe_xmit(fwt_db_entry *fwt_ent,
	void *data_bus, int data_len, uint16_t vlan_miscuser)
{
	union topaz_tqe_cpuif_ppctl ctl;
	uint8_t tid;

	tid = topaz_tqe_vlan_gettid(bus_to_virt((uintptr_t)data_bus));

	topaz_pcie_prepare_pp_cntl(&ctl, tid, fwt_ent, data_bus, data_len, vlan_miscuser);

	topaz_tqe_pcieif_wait();

	topaz_tqe_pcieif_tx_start(&ctl);

	return NET_XMIT_SUCCESS;
}
#else
static int topaz_tqe_pcieif_tx_fail(void)
{
	return !(topaz_tqe_cpuif_tx_success_cpu_port(NULL, TOPAZ_TQE_PCIE_REL_PORT));
}

#define MAX_TQE_RDY_TRY		0xffff
#define MAX_PCIE_TQE_SEMA_TRY	0xff
__attribute__((section(".sram.pcierx.text"))) int topaz_pcie_tqe_xmit(union topaz_tqe_cpuif_ppctl *pp_cntl)
{
	struct net_device *dev = g_tqe_pcie_ndev;
	struct tqe_netdev_priv *priv = NULL;
	uint32_t retry = 0;

	BUG_ON(NULL == dev);

	priv = netdev_priv(dev);
	priv->tqe_xmit_cnt++;

	topaz_tqe_pcieif_wait();

	while ((0 == topaz_pcie_tqe_multi_proc_sem_down()) && (retry++ < MAX_PCIE_TQE_SEMA_TRY)) {
		priv->fail_get_sem_cnt++;
	}

	if (retry < MAX_PCIE_TQE_SEMA_TRY)
		topaz_tqe_pcieif_tx_start(pp_cntl);
	else
		return NET_XMIT_DROP;

	topaz_pcie_tqe_multi_proc_sem_up();

	if (topaz_tqe_pcieif_tx_fail())
		return NET_XMIT_CN;
	else
		return NET_XMIT_SUCCESS;
}
#endif

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
	union topaz_tqe_pcieif_descr __iomem *bus_descs;

	if (ALIGNED_DMA_DESC_ALLOC(&priv->rx, QTN_BUFS_PCIE_TQE_RX_RING, TOPAZ_TQE_CPUIF_RXDESC_ALIGN, 0)) {
		return -ENOMEM;
	}

	bus_descs = (void *)priv->rx.descs_dma_addr;
	for (i = 0; i < QTN_BUFS_PCIE_TQE_RX_RING; i++) {
		priv->rx.descs[i].data.next = &bus_descs[(i + 1) % QTN_BUFS_PCIE_TQE_RX_RING];
	}

	printk(KERN_INFO "%s: %u tqe_rx_descriptors at kern uncached 0x%p bus 0x%p\n",
			__FUNCTION__, priv->rx.desc_count, priv->rx.descs, bus_descs);

	topaz_tqe_pcieif_setup_ring((void *)priv->rx.descs_dma_addr, priv->rx.desc_count);

	return 0;
}

static void tqe_descs_free(struct tqe_netdev_priv *priv)
{
	if (priv->rx.descs) {
		ALIGNED_DMA_DESC_FREE(&priv->rx);
	}
}

static ssize_t pcie_tqe_dbg_show(struct device *dev, struct device_attribute *attr, char *buff)
{
	struct net_device *ndev = container_of(dev, struct net_device, dev);
	struct tqe_netdev_priv *priv = netdev_priv(ndev);

	pcie_tqe_dbg_print(priv);

	return 0;
}

DEVICE_ATTR(tqedbg, S_IWUSR | S_IRUSR, pcie_tqe_dbg_show, NULL); /* dev_attr_tqedbg */

struct net_device * tqe_pcie_netdev_init( struct net_device *pcie_ndev)
{
	int rc = 0;
	struct net_device *dev = NULL;
	struct tqe_netdev_priv *priv;
	static int tqe_netdev_irq;
	if (PCIE_TQE_INTR_WORKAROUND)
		/* workaround: use tqe dsp port to replace tqe pcie port */
		/* so tqe packet arrival INT is sent to dsp port, dsp fw */
		/* then foreward INT to lhost by IPC3 (irq num 18)       */
		tqe_netdev_irq = 18;
	else
		/* by default: use tqe pcie port. tqe packet arrival INT */
		/* is sent to pcie port INT, whose irq num is 30         */
		tqe_netdev_irq = 30;
#ifdef TOPAZ_PCIE_HDP_TX_QUEUE
	struct tqe_queue *tx_queue;
#endif
#ifndef CONFIG_TOPAZ_DBDC_HOST
	struct vmac_priv *vmp = netdev_priv(pcie_ndev);
#endif

	dev = alloc_netdev(sizeof(struct tqe_netdev_priv), "tqe_pcie", &ether_setup);
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
	topaz_tqe_pcieif_setup_reset(1);
	topaz_tqe_pcieif_setup_reset(0);

	if (tqe_descs_alloc(priv)) {
		goto desc_alloc_error;
	}

	if (PCIE_TQE_INTR_WORKAROUND)
		rc = request_irq(dev->irq, &tqe_irqh_workaround, 0, dev->name, dev);
	else
		rc = request_irq(dev->irq, &tqe_irqh, 0, dev->name, dev);

	if (rc) {
		printk(KERN_ERR "%s: unable to get %s IRQ %d, error %d\n",
				__FUNCTION__, dev->name, tqe_netdev_irq, rc);
		goto irq_request_error;
	}

	rc = register_netdev(dev);
	if (rc) {
		printk(KERN_ERR "%s: Cannot register net device '%s', error %d\n",
				__FUNCTION__, dev->name, rc);
		goto netdev_register_error;
	}

	priv->pcie_ndev = pcie_ndev;
#ifndef CONFIG_TOPAZ_DBDC_HOST
	vmp->tqe_napi = &priv->napi;
#endif

#ifdef TOPAZ_PCIE_HDP_TX_QUEUE
	tx_queue = &priv->tqe_tx_queue;
	tx_queue->queue_in = 0;
	tx_queue->queue_out = 0;
	tx_queue->pkt_num = 0;
	init_timer(&tx_queue->tx_timer);
	tx_queue->tx_timer.data = (unsigned long)priv;
	tx_queue->tx_timer.function = (void (*)(unsigned long))&tqe_queue_start_tx;
#endif

	qdrv_dscp2tid_map_init();

#ifdef CONFIG_TOPAZ_PCIE_TARGET
	netif_napi_add(dev, &priv->napi, &tqe_rx_napi_handler, 10);
	tqe_port_register(TOPAZ_TQE_PCIE_REL_PORT);
	device_create_file(&dev->dev, &dev_attr_tqedbg);
#elif defined (CONFIG_TOPAZ_PCIE_HOST) || defined (CONFIG_TOPAZ_DBDC_HOST)
	netif_napi_add(dev, &priv->napi, &tqe_rx_napi_handler, board_napi_budget());
#endif

	napi_enable(&priv->napi);
#if defined (CONFIG_TOPAZ_DBDC_HOST)
	if (PCIE_TQE_INTR_WORKAROUND)
		tqe_dsp_irq_enable();
	else
		tqe_pcie_irq_enable();
#else
	vmp->tqe_irq_enable();
#endif
	if (PCIE_TQE_INTR_WORKAROUND)
		writel(readl(TOPAZ_LH_IPC3_INT_MASK) | 0x1, TOPAZ_LH_IPC3_INT_MASK);
	g_tqe_pcie_ndev = dev;

#ifndef CONFIG_TOPAZ_PCIE_HOST
	printk("%s: tqe_sem_en %d\n", __FUNCTION__, tqe_sem_en);
#endif
	return dev;

netdev_register_error:
	free_irq(dev->irq, dev);
irq_request_error:
	tqe_descs_free(priv);
desc_alloc_error:
	free_netdev(dev);
netdev_alloc_error:
	return NULL;
}
EXPORT_SYMBOL(tqe_pcie_netdev_init);

void tqe_pcie_netdev_term( struct net_device *pcie_ndev)
{
#ifdef CONFIG_TOPAZ_PCIE_TARGET
	tqe_port_unregister(TOPAZ_TQE_PCIE_REL_PORT);
#endif
}
EXPORT_SYMBOL(tqe_pcie_netdev_term);

void tqe_netdev_exit(void)
{
	struct net_device *dev = g_tqe_pcie_ndev;
	struct tqe_netdev_priv *priv;

	if (dev == NULL)
		return;
	priv = netdev_priv(dev);
	unregister_netdev(dev);
	free_irq(dev->irq, dev);
	tqe_descs_free(priv);
	free_netdev(dev);

	g_tqe_pcie_ndev = NULL;
}
EXPORT_SYMBOL(tqe_netdev_exit);

