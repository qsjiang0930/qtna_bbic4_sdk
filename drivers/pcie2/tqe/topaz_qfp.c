/**
 * Copyright (c) 2015 Quantenna Communications, Inc.
 * All rights reserved.
 *
 **/

#include "net80211/ieee80211.h"
#include "net80211/ieee80211.h"

#include <qtn/topaz_tqe.h>
#include <qtn/topaz_fwt_sw.h>
#include <qtn/topaz_hbm_cpuif.h>
#include <qtn/topaz_hbm.h>
#include "qdpc_platform.h"
#include "net80211/if_ethersubr.h"
#include <qtn/topaz_qfp.h>
#include <linux/pci.h>
#include <linux/swap.h>
#include <linux/etherdevice.h>
#include <../../tqe/topaz_pcie_tqe.h>
#include <linux/net/bridge/br_public.h>
#include <linux/if_vlan.h>
#include <qtn/qtn_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#define SRAM_OPT
#undef __sram_text
#ifdef SRAM_OPT
#define __sram_text             __attribute__ ((__section__ (__sram_text_sect_name)))
#else
#define __sram_text
#endif

#define MSI_BIT_S (10)
#define LEGACY_INT_S (11)

#define DRV_AUTHOR	"Quantenna Communications Inc."
#define DRV_DESC	"QFP driver"

MODULE_AUTHOR(DRV_AUTHOR);
MODULE_DESCRIPTION(DRV_DESC);
MODULE_LICENSE("Proprietary");


static unsigned int hdp = 1;
module_param(hdp, uint, 0644);
MODULE_PARM_DESC(hdp, "enable tqe-pcie accelerate: (default 1: enabled)");

PCIE_TQE_INTR_WORKAROUND_DEF;
int tqe_sem_en = 0;
module_param(tqe_sem_en, int, S_IRWXU);

static inline void qfp_throttle_init(void);
static inline void qfp_throttle_deinit(void);
int qfp_throttle_check_rx(struct sk_buff *skb);
static unsigned long min_free_pages = 200;
extern void fwt_register_pcie_rel_port(const enum topaz_tqe_port tqe_port);
extern void tqe_register_pcie_rel_port(const enum topaz_tqe_port tqe_port);

/*
 * Quantenna platform specific function
 */
static void topaz_pcie_enable_int(int msi)
{
	uint32_t temp = readl(QDPC_RC_SYS_CTL_PCIE_INT_MASK);

	if (msi) {
		temp |= BIT(MSI_BIT_S); /* MSI */
	} else {
		temp |= BIT(LEGACY_INT_S); /* Legacy INTx */
	}
	writel(temp, QDPC_RC_SYS_CTL_PCIE_INT_MASK);
}

static void topaz_pcie_disable_int(int msi)
{
	uint32_t temp = readl(QDPC_RC_SYS_CTL_PCIE_INT_MASK);

	if (msi) {
		temp &= ~BIT(MSI_BIT_S); /* MSI */
	} else {
		temp &= ~BIT(LEGACY_INT_S); /* Legacy INTx */
	}
	writel(temp, QDPC_RC_SYS_CTL_PCIE_INT_MASK);
}

static int topaz_pcie_find_rc_capability(int cap)
{
	uint32_t pos;
	uint32_t cap_found;

	pos = (readl(RUBY_PCIE_REG_BASE + PCI_CAPABILITY_LIST) & 0x000000ff);
	while (pos) {
		cap_found = (readl(RUBY_PCIE_REG_BASE + pos) & 0x0000ffff);
		if ((cap_found & 0x000000ff)== (uint32_t)cap)
			break;

		pos = ((cap_found >> 8) & 0x000000ff);
	}
	return pos;
}
#ifdef DEBUG
/* Quantenna to dump PCI configuration space*/
#define TOPAZ_PCIE_CONFIGSPACE_DUMP_MAX_SIZE 256
static inline void topaz_pcie_dump_pci_config_space(struct e1000_adapter *adapter)
{
	int i = 0;
	uint32_t cs = 0;

	/* Read PCIe configuration space header */
	for (i = 0; i <= TOPAZ_PCIE_CONFIGSPACE_DUMP_MAX_SIZE; i += 4) {
		pci_read_config_dword(adapter->pdev, i, &cs);
		printk("%s: adapter->pdev:0x%p config_space offset:0x%02x value:0x%08x\n", __func__, adapter->pdev, i, cs);
	}
	printk("\n");
}
#endif

/* Quantenna to set tlp MPS */
static void topaz_pcie_config_mps(struct pci_dev *pdev)
{
	int pos = 0;
	int ppos = 0;
	uint32_t dev_cap, pcap;
	uint16_t dev_ctl, pctl;
	unsigned int mps = 0;
#define BIT_TO_MPS(m) (1 << ((m) + 7))

	pos = pci_find_capability(pdev, PCI_CAP_ID_EXP);
	if (!pos) {
		printk(KERN_ERR "The device %x does not have PCI Express capability\n",
				pdev->device);
	} else {
		printk(KERN_INFO "The device %x has PCI Express capability\n", pdev->device);
	}

	ppos = topaz_pcie_find_rc_capability(PCI_CAP_ID_EXP);
	if ((ppos) && (pos)) {
		/* Quantenna to read RC MPS setting */
		pcap = readl(RUBY_PCIE_REG_BASE + ppos + PCI_EXP_DEVCAP);

		pci_read_config_dword(pdev, pos + PCI_EXP_DEVCAP, &dev_cap);
		printk(KERN_INFO "RC cap:%u, dev cap:%u\n",
				BIT_TO_MPS(pcap & PCI_EXP_DEVCAP_PAYLOAD), BIT_TO_MPS(dev_cap & PCI_EXP_DEVCAP_PAYLOAD));
		mps = min(BIT_TO_MPS(dev_cap & PCI_EXP_DEVCAP_PAYLOAD), BIT_TO_MPS(pcap & PCI_EXP_DEVCAP_PAYLOAD));
	}

	if (mps == 0) {
		mps = 128;	//default to 128 byte
	}

	printk(KERN_INFO"Setting MPS to %u\n", mps);
	/*
	 * Set Max_Payload_Size
	 * Max_Payload_Size_in_effect = 1 << ( ( (dev_ctl >> 5) & 0x07) + 7);
	 */
	mps = (((mps >> 7) - 1) << 5);
	pci_read_config_word(pdev, pos + PCI_EXP_DEVCTL, &dev_ctl);
	dev_ctl = ((dev_ctl & ~PCI_EXP_DEVCTL_PAYLOAD) | mps);
	pci_write_config_word(pdev, pos + PCI_EXP_DEVCTL, dev_ctl);

	/* Quantenna to write back to RC MPS value*/
	if (ppos) {
		pctl = readl(RUBY_PCIE_REG_BASE + ppos + PCI_EXP_DEVCTL);
		pctl= ((pctl & ~PCI_EXP_DEVCTL_PAYLOAD) | mps);
		writel(pctl, RUBY_PCIE_REG_BASE + ppos + PCI_EXP_DEVCTL);
	}
}

int qfp_init(struct pci_dev * pci_dev, int msi)
{
	int ret = -1;
	PCIE_TQE_INTR_WORKAROUND_DETECT;
	fwt_register_pcie_rel_port(TOPAZ_TQE_PCIE_REL_PORT);
	tqe_register_pcie_rel_port(TOPAZ_TQE_PCIE_REL_PORT);
	if (pci_dev) {
		topaz_pcie_config_mps(pci_dev);
		topaz_pcie_enable_int(msi);
		ret = 0;
	}
	qfp_throttle_init();
	return ret;
}
EXPORT_SYMBOL(qfp_init);

void qfp_deinit(struct pci_dev * pci_dev, int msi)
{
	struct qtn_vlan_dev *vdev = vport_tbl_lhost[TOPAZ_TQE_PCIE_REL_PORT];

	if (pci_dev) {
		topaz_pcie_disable_int(msi);
	}
	qfp_throttle_deinit();

	if (vdev)
		switch_free_vlan_dev(vdev);

}
EXPORT_SYMBOL(qfp_deinit);

static inline struct qtn_vlan_dev *tqe_get_vlandev(uint8_t port, uint8_t node)
{
	if (TOPAZ_TQE_PORT_IS_WIRED(port))
		return vport_tbl_lhost[port];
	else
		return switch_vlan_dev_from_node(node);
}

static inline int qfp_rx_vlan_egress(fwt_db_entry *fwt_ent, void *data, uint16_t *misc_user)
{
	struct qtn_vlan_dev *vdev;

	vdev = tqe_get_vlandev(fwt_ent->out_port, fwt_ent->out_node);
	if (vdev == NULL)
		return 0;

	return qtn_vlan_egress(vdev, fwt_ent->out_node, data,
			TOPAZ_TQE_PORT_IS_WMAC(vdev->port) ? misc_user : NULL, 1);
}

static int __sram_text topaz_qfp_should_accelerate(struct sk_buff *skb)
{
	struct iphdr *ip_h;
	struct ethhdr *eth_h;
	struct ipv6hdr *ipv6_h;

	eth_h = (struct ethhdr *)(skb->mac_header);
	ip_h = (struct iphdr *)(skb->mac_header + sizeof(struct ethhdr));
	ipv6_h = (struct ipv6hdr *)(skb->mac_header + sizeof(struct ethhdr));

	if (((eth_h->h_proto == __constant_htons(ETH_P_IP))
		&& ((ip_h->protocol == IPPROTO_ICMP)
		||(ip_h->protocol == IPPROTO_IGMP)))
		|| (eth_h->h_proto == __constant_htons(ETH_P_ARP)))
		return 0;

	if ((eth_h->h_proto == htons(ETH_P_IPV6))
		&& (ipv6_h->nexthdr == IPPROTO_ICMPV6))
		return 0;

	return 1;
}

static inline const uint16_t *
vmac_rx_find_ether_type(const struct ethhdr *eth, uint32_t len)
{
	const uint16_t *ether_type = &eth->h_proto;

	if (len < sizeof(struct ethhdr))
		return NULL;

	if (qtn_ether_type_is_vlan(*ether_type)) {
		if (len < sizeof(struct ethhdr) + VLAN_HLEN)
			return NULL;

		ether_type += VLAN_HLEN / sizeof(*ether_type);
	}

	return ether_type;
}

static int __sram_text topaz_pcie_rx_forward(struct sk_buff * skb)
{
	int ret = -1;
	struct ethhdr *eth = eth_hdr(skb);
	int8_t pool;
	uint32_t bdata;
	unsigned int len = skb->len + sizeof(*eth);
	const uint16_t *ether_type;

	if (unlikely((hdp == 0) || (skb_cloned(skb)) ||
		skb_shared(skb) || (eth==NULL)))
		goto out;

	if (unlikely(!topaz_qfp_should_accelerate(skb)))
		goto out;

	bdata = virt_to_bus(eth);
	pool = topaz_hbm_payload_get_pool_bus((void *)bdata);

	if (unlikely(pool < 0))
		goto out;

	topaz_hbm_flush_skb_cache(skb);
	if (unlikely(is_multicast_ether_addr(eth->h_dest))) {
		union topaz_tqe_cpuif_descr desc;

		memset(&desc, 0, sizeof(desc));
		desc.data.buff_ptr_offset = topaz_hbm_payload_buff_ptr_offset_bus((void *)bdata,
				pool, NULL);
		desc.data.length = len;
		desc.data.in_port = TOPAZ_TQE_PCIE_REL_PORT;
		desc.data.pkt = (void *)bdata;

		ether_type = vmac_rx_find_ether_type(eth, len);
		if (unlikely(!ether_type))
			goto out;

		if (tqe_rx_multicast(NULL, &desc, ether_type, 1) <= 0) {
			goto out;
		}
	} else {
		fwt_db_entry * fwt_ent;
		uint16_t vlan_miscuser = 0;

		fwt_ent = fwt_sw_fast_get_ucast_entry(eth->h_source, eth->h_dest);
		if (likely(fwt_ent)) {
			if (vlan_enabled && !qfp_rx_vlan_egress(fwt_ent, eth, &vlan_miscuser)) {
				ret = 1;
				goto out;
			}
			topaz_pcie_tqe_xmit(fwt_ent, (void *)bdata, len, vlan_miscuser);
		}
		else
			goto out;
	}
	ret = 0;
out:
	return ret;
}

static void qfp_strip_vlan_tag(struct sk_buff *skb)
{
	uint16_t proto;
	unsigned char *rawp;
	uint8_t *mac_hdr = skb_mac_header(skb);

	if (eth_hdr(skb)->h_proto != htons(ETH_P_8021Q))
		return;

	proto = vlan_eth_hdr(skb)->h_vlan_encapsulated_proto;
	if (ntohs(proto) >= 1536)
		skb->protocol = proto;
	else {
		rawp = mac_hdr + VLAN_ETH_HLEN;
		if (*(unsigned short *)rawp == 0xFFFF)
			skb->protocol = htons(ETH_P_802_3);
		else
			skb->protocol = htons(ETH_P_802_2);
	}
	memmove(mac_hdr + VLAN_HLEN, mac_hdr, 2 * VLAN_ETH_ALEN);
	skb->mac_header += VLAN_HLEN;
	__skb_pull(skb, VLAN_HLEN);
}

int qfp_rx_vlan_ingress(struct sk_buff *skb, uint16_t *pvid)
{
	uint8_t dev_id = 0;
	struct qtn_vlan_dev *vdev;
	struct vlan_ethhdr *veth;
	int tagrx;

	dev_id = EXTRACT_DEV_ID_FROM_PORT_ID(skb->dev->if_port);

	vdev = vdev_tbl_lhost[QFP_VDEV_IDX(dev_id)];
	*pvid = vdev->pvid;
	tagrx = qtn_vlan_get_tagrx(qtn_vlan_info.vlan_tagrx_bitmap, *pvid);
	if (tagrx == QVLAN_TAGRX_TAG) {
		if (eth_hdr(skb)->h_proto != htons(ETH_P_8021Q)) {
			if (skb_mac_header(skb) - skb->head < QVLAN_PKTCTRL_LEN)
				return 0;

			skb->protocol = htons(ETH_P_8021Q);
			memmove(skb_mac_header(skb) - VLAN_HLEN, skb_mac_header(skb), 2 * VLAN_ETH_ALEN);
			skb->mac_header -= VLAN_HLEN;
			__skb_push(skb, VLAN_HLEN);

			veth = vlan_eth_hdr(skb);
			veth->h_vlan_proto = htons(ETH_P_8021Q);
			veth->h_vlan_TCI = htons(*pvid);
		}
	} else if (tagrx == QVLAN_TAGRX_STRIP)
		qfp_strip_vlan_tag(skb);

	if (skb_mac_header(skb) - skb->head < QVLAN_PKTCTRL_LEN)
		return 0;

	if (!qtn_vlan_ingress(vdev, 0, skb_mac_header(skb), 1, *pvid, 1))
		return 0;

	return 1;
}

int __sram_text qfp_rx(struct sk_buff * skb)
{
	int ret = 0;
	uint16_t pvid = 1;

	if (!skb_mac_header_was_set(skb))
		skb_reset_mac_header(skb);

	if (!qfp_throttle_check_rx(skb))
		goto free_out;

	if (vlan_enabled) {
		if (!qfp_rx_vlan_ingress(skb, &pvid))
			goto free_out;
	}

	ret = topaz_pcie_rx_forward(skb);
	if (ret == 0) {
		skb->hbm_no_free = 1;
		goto free_out;
	} else if (ret == 1) {
		ret = 0;
		goto free_out;
	}
	if (vlan_enabled) {
		/* going to pass up to LHOST net stack */
		M_FLAG_SET(skb, M_VLAN_TAGGED);
		skb->vlan_tci = pvid;
		if (!switch_vlan_to_proto_stack(skb))
			return 0;
	}

free_out:
	if (!ret)
		dev_kfree_skb_any(skb);
	return ret;
}
EXPORT_SYMBOL(qfp_rx);

static struct sk_buff * __sram_text _qfp_alloc_skb_from_pool(unsigned int size, int8_t pool)
{
	struct sk_buff * skb = NULL;

	if (size <= topaz_hbm_pool_buf_max_size(pool)) {
		void * bus = topaz_hbm_get_payload_bus(pool);
		if (bus) {
			void * virt = (void *)bus_to_virt((uint32_t)bus);
			skb = topaz_hbm_attach_skb_for_qfp(virt, size, pool, 0, vlan_enabled ? QVLAN_PKTCTRL_LEN * 2 : 0);
			if (unlikely(skb == NULL))
				topaz_hbm_put_payload_realign_bus(bus, pool);
		}
	}
	return skb;
}

struct sk_buff * __sram_text qfp_alloc_skb(unsigned int size)
{
	struct sk_buff * skb = NULL;

	if (min_free_pages != 0 && nr_free_pages() < min_free_pages)
		return NULL;

	if (hdp) {
		skb = _qfp_alloc_skb_from_pool(size, TOPAZ_HBM_BUF_EMAC_RX_POOL);
	} else {
		skb = dev_alloc_skb(size);
	}
	return skb;
}
EXPORT_SYMBOL(qfp_alloc_skb);

static struct topaz_qfp_netdev_ops qfp_netdev_ops_list[MAX_QFP_NETDEV];
static struct net_device *qfp_netdev_list[MAX_QFP_NETDEV] = {NULL};
static int qfp_virtual_netdev_num = 0;

static inline uint8_t get_free_qfp_netdev_id(void)
{
	uint8_t id = 1;
	/* the first pcie device always is the root device */
	for (id = 1; id < MAX_QFP_NETDEV; ++id)
		if (qfp_netdev_list[id] == NULL)
			break;
	return id;
}

struct net_device *get_qfp_netdev_by_id(uint8_t id)
{
	if (id < MAX_QFP_NETDEV)
		return qfp_netdev_list[id];
	return NULL;
}

int qfp_has_virtual_network(void)
{
	return (qfp_virtual_netdev_num > 0);
}

struct sk_buff *qfp_tx_vlan_egress(struct sk_buff *skb, struct net_device *ndev, uint8_t dev_id)
{
	struct sk_buff *skb2;

	if (M_FLAG_ISSET(skb, M_ORIG_BR))
		return skb;

	if (!qtn_vlan_egress(vdev_tbl_lhost[QFP_VDEV_IDX(dev_id)], 0, skb->data, NULL, 0)) {
		dev_kfree_skb_any(skb);
		ndev->stats.tx_dropped++;
		return NULL;
	}

	if (eth_hdr(skb)->h_proto == htons(ETH_P_8021Q) && skb_cloned(skb)) {
		skb2 = skb_copy(skb, GFP_ATOMIC);
		dev_kfree_skb_any(skb);
		if (!skb2) {
			ndev->stats.tx_dropped++;
			return NULL;
		}
		skb = skb2;
	}

	qfp_strip_vlan_tag(skb);

	return skb;
}

int __sram_text qfp_tx(struct sk_buff *skb, struct net_device *ndev)
{
	uint8_t dev_id = EXTRACT_DEV_ID_FROM_PORT_ID(ndev->if_port);
	struct topaz_qfp_netdev_ops *qfp_netdev_ops = &qfp_netdev_ops_list[dev_id];

	if (!skb_mac_header_was_set(skb))
		skb_reset_mac_header(skb);

	if (vlan_enabled) {
		skb = qfp_tx_vlan_egress(skb, ndev, dev_id);
		if (!skb)
			return NETDEV_TX_OK;
	}

	return qfp_netdev_ops->orig_netdev_ops->ndo_start_xmit(skb, ndev);
}

int qfp_vlan_init(void)
{
	struct qtn_vlan_dev *vdev = vport_tbl_lhost[TOPAZ_TQE_PCIE_REL_PORT];

	if (vdev)
		return 0;

	vdev = switch_alloc_vlan_dev(TOPAZ_TQE_PCIE_REL_PORT, QFP_VDEV_IDX(0), 0);
	if (!vdev) {
		printk(KERN_ERR "Fail to allocate QTN VLAN device for root pcie port\n");
		BUG();
		return -1;
	}
	switch_vlan_add_member(vdev, QVLAN_VID_ALL, 0);

	return 0;
}

int qfp_vlan_attach(struct net_device *ndev)
{
	uint8_t dev_id = EXTRACT_DEV_ID_FROM_PORT_ID(ndev->if_port);
	struct topaz_qfp_netdev_ops *qfp_netdev_ops = &qfp_netdev_ops_list[dev_id];

	if (qfp_vlan_init() != 0)
		return -1;

	if (switch_alloc_vlan_dev(TOPAZ_TQE_PCIE_REL_PORT, QFP_VDEV_IDX(dev_id), ndev->ifindex) == NULL) {
		printk(KERN_ERR "Fail to allocate QTN VLAN device for %s\n", ndev->name);
		BUG();
		return -1;
	}

	memcpy(&qfp_netdev_ops->netdev_ops, ndev->netdev_ops, sizeof(struct net_device_ops));
	qfp_netdev_ops->netdev_ops.ndo_start_xmit = qfp_tx;
	qfp_netdev_ops->orig_netdev_ops = ndev->netdev_ops;
	ndev->netdev_ops = &qfp_netdev_ops->netdev_ops;

	return 0;
}

int qfp_register_virtual_netdev(struct net_device *net_dev)
{
	uint8_t id;
	if (net_dev) {
		if (hdp) {
			id = get_free_qfp_netdev_id();
			if (id < MAX_QFP_NETDEV) {
				INJECT_DEV_ID_TO_PORT_ID(TOPAZ_TQE_PCIE_REL_PORT, id, net_dev->if_port);
				qfp_netdev_list[id] = net_dev;
				qfp_virtual_netdev_num++;
				qfp_vlan_attach(net_dev);
			} else {
				/* packet to the device that can not be handled
				 * TQE will be handled by LHOST */
				net_dev->if_port = TOPAZ_TQE_LHOST_PORT;
				printk(KERN_WARNING "Warning: packet to device %s "
					"will be handled by local host\n",
					net_dev->name);
			}
		} else {
			net_dev->if_port = TOPAZ_TQE_LHOST_PORT;
		}
		return 0;
	}
	return -1;
}
EXPORT_SYMBOL(qfp_register_virtual_netdev);

void qfp_unregister_virtual_netdev(struct net_device *net_dev)
{
	uint8_t id = 1;

	if ((!net_dev) || (hdp == 0))
		return;

	for (id = 1; id < MAX_QFP_NETDEV; ++id) {
		if (qfp_netdev_list[id] == net_dev) {
			switch_free_vlan_dev_by_idx(QFP_VDEV_IDX(id));
			qfp_netdev_list[id] = NULL;
			qfp_virtual_netdev_num--;
			break;
		}
	}
}
EXPORT_SYMBOL(qfp_unregister_virtual_netdev);

int qfp_register_netdev(struct net_device *net_dev)
{
	PCIE_TQE_INTR_WORKAROUND_DETECT;
	fwt_register_pcie_rel_port(TOPAZ_TQE_PCIE_REL_PORT);
	tqe_register_pcie_rel_port(TOPAZ_TQE_PCIE_REL_PORT);

	if (net_dev) {
		if (hdp) {
			net_dev->if_port = TOPAZ_TQE_PCIE_REL_PORT;
			qfp_netdev_list[0] = net_dev;
			tqe_pcie_netdev_init(net_dev);
			qfp_vlan_attach(net_dev);
		} else {
			net_dev->if_port = TOPAZ_TQE_LHOST_PORT;
		}
		return 0;
	}
	return -1;

}
EXPORT_SYMBOL(qfp_register_netdev);

void qfp_unregister_netdev(struct net_device * net_dev)
{
	if (hdp) {
		switch_free_vlan_dev_by_idx(QFP_VDEV_IDX(0));
		qfp_netdev_list[0] = NULL;
		tqe_netdev_exit();
	}
}
EXPORT_SYMBOL(qfp_unregister_netdev);

typedef enum {
	THROTTLE_BW = 0,
	THROTTLE_PPS,
} qfp_throttle_type;

struct qfp_throttle {
	qfp_throttle_type type;		/* throttle type, bw or pps */
	unsigned long allowed;		/* pps or bw allowed, 0 means don't throttle */
	unsigned long max_token;	/* max token can be put in bucket */
	unsigned long speed;		/* token per second */
	unsigned long token_bucket;	/* token in bucket */
	unsigned long produce_time;	/* time when product token in last time */
};

static struct qfp_throttle g_qfp_throttle_tx[MAX_QFP_NETDEV];
static struct qfp_throttle g_qfp_throttle_rx[MAX_QFP_NETDEV];
#define QFP_THROTTLE_PROC_NAME "qfp_throttle"

static inline void qfp_throttle_update(struct qfp_throttle *throttle, unsigned long value)
{
	throttle->allowed = value;
	if (throttle->type == THROTTLE_BW)
		throttle->max_token = throttle->allowed * (1000 * 1024 / 8);
	else if (throttle->type == THROTTLE_PPS)
		throttle->max_token = throttle->allowed;
	throttle->speed = throttle->max_token / (HZ);
	throttle->token_bucket = throttle->max_token;
	throttle->produce_time = jiffies;
}

static inline void qfp_throttle_update_type(struct qfp_throttle *throttle, qfp_throttle_type type)
{
	throttle->type = type;

	/* Update throttle values */
	qfp_throttle_update(throttle, throttle->allowed);
}

/*
 * Usage 1: set min_free_pages
 * echo "min_free_pages number" > /proc/qfp_throttle
 * min_free_pages: const string "min_free_pages"
 * number: qfp_alloc_skb return NULL when the free pages is less than this decimal number
 *
 * Usage 2: set throttle type
 * echo "ifname throttle_type=throttle_type" > /proc/qfp_throttle
 * ifname: name of the qfp netdev
 * throttle_type: 0 for BW, 1 for PPS
 *
 * Usage 3: set tx and rx throttling values
 * echo "ifname txvalue:rxvalue" > /proc/qfp_throttle
 * ifname: name of the qfp netdev
 * txvalue: bandwidth or pps for tx, unit Mbps or PPS, 0 means don't throttle
 * rxvalue: bandwidth or pps for rx, unit Mbps or PPS, 0 means don't throttle
 */

static int qfp_throttle_write_proc(struct file *file, const char __user *buffer,
		unsigned long count, void *_unused)
{
	int type = -1, num = -1, value_tx = -1, value_rx = -1;
	int dev_id;
	char *buf, *input, *token;

	buf = kmalloc(count, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	if (copy_from_user(buf, buffer, count))
		goto out;

	input = buf;
	token = strsep(&input, " ");

	if (!token || !input) {
		printk("Invalid input\n");
		goto out;
	}

	if (strcmp(token, "min_free_pages") == 0) {
		/* Usage 1: set min_free_pages */
		sscanf(input, "%d", &num);
		if (num < 0) {
			printk("Invalid number of min_free_pages\n");
			goto out;
		}
		min_free_pages = num;
	} else {
		if (hdp == 0) {
			printk("Warning: throttle don't support multiple device because hdp is disabled\n");
			goto out;
		}
		for (dev_id = 0; dev_id < MAX_QFP_NETDEV; ++dev_id)
			if (qfp_netdev_list[dev_id] != NULL && strcmp(token, qfp_netdev_list[dev_id]->name) == 0)
				break;
		if (dev_id == MAX_QFP_NETDEV) {
			printk("%s is not supported or not registered as a qfp device\n", token);
			goto out;
		}

		/* Usage 2: set throttle type */
		if (strncmp(input, "throttle_type=", 14) == 0) {
			sscanf(input, "throttle_type=%d", &type);

			if (type != THROTTLE_BW && type != THROTTLE_PPS) {
				printk("Invalid throttle type\n");
				goto out;
			}

			qfp_throttle_update_type(&g_qfp_throttle_tx[dev_id], type);
			qfp_throttle_update_type(&g_qfp_throttle_rx[dev_id], type);
		} else { /* Usage 3: set tx and rx throttling values */
			sscanf(input, "%d:%d", &value_tx, &value_rx);

			if (value_tx < 0) {
				printk("Invalid tx value\n");
				goto out;
			}
			if (value_rx < 0) {
				printk("Invalid rx value\n");
				goto out;
			}

			qfp_throttle_update(&g_qfp_throttle_tx[dev_id], value_tx);
			qfp_throttle_update(&g_qfp_throttle_rx[dev_id], value_rx);
		}
	}

out:
	kfree(buf);

	return count;
}

static int qfp_throttle_read_proc(char *page, char **start, off_t off,
		int count, int *eof, void *_unused)
{
	int i, len = 0;

	len = sprintf(page, "ifname throttle_type=value\n");
	len += sprintf(page + len, "ifname txvalue:rxvalue\n");
	for (i = 0; i < MAX_QFP_NETDEV; ++i) {
		if (qfp_netdev_list[i] == NULL)
			continue;
		len += sprintf(page + len, "%s throttle_type=%d\n", qfp_netdev_list[i]->name,
				(g_qfp_throttle_tx[i].type == THROTTLE_BW) ? THROTTLE_BW : THROTTLE_PPS);
		len += sprintf(page + len, "%s %lu:%lu\n", qfp_netdev_list[i]->name,
				g_qfp_throttle_tx[i].allowed, g_qfp_throttle_rx[i].allowed);
	}
	len += sprintf(page + len, "min_free_pages %lu\n", min_free_pages);

	return len;
}

static inline void qfp_throttle_init(void)
{
	struct proc_dir_entry *entry;

	/* Throttle type by default is BW (0) */
	memset(&g_qfp_throttle_tx, 0, sizeof(g_qfp_throttle_tx));
	memset(&g_qfp_throttle_rx, 0, sizeof(g_qfp_throttle_rx));

	entry = create_proc_entry(QFP_THROTTLE_PROC_NAME, 0600, NULL);
	if (entry) {
		entry->write_proc = qfp_throttle_write_proc;
		entry->read_proc = qfp_throttle_read_proc;
	}
}

static inline void qfp_throttle_deinit(void)
{
	remove_proc_entry(QFP_THROTTLE_PROC_NAME, NULL);
}

static void qfp_throttle_produce_token(struct qfp_throttle *throttle)
{
	unsigned long interval;

	if (time_after(jiffies, throttle->produce_time)) {
		interval = (long)jiffies - (long)throttle->produce_time;
		throttle->token_bucket += interval * throttle->speed;
		if (throttle->token_bucket > throttle->max_token)
			throttle->token_bucket = throttle->max_token;
		throttle->produce_time = jiffies;
	}
}

static inline int qfp_throttle_get_token(struct qfp_throttle *throttle, int token)
{
	if (throttle->allowed == 0)
		return 1;

	/* Throttling per packet count, return always 1 token */
	if (throttle->type == THROTTLE_PPS)
		token = 1;

	qfp_throttle_produce_token(throttle);
	if (token > throttle->token_bucket)
		return 0;

	throttle->token_bucket -= token;

	return 1;
}

int qfp_throttle_check_tx(struct sk_buff *skb, int dev_id)
{
	if (unlikely(dev_id >= MAX_QFP_NETDEV))
		return 1;

	return qfp_throttle_get_token(&g_qfp_throttle_tx[dev_id], skb->len - ETH_HLEN);
}

int qfp_throttle_check_rx(struct sk_buff *skb)
{
	int dev_id = 0;

	if (likely(skb->dev)) {
		dev_id = EXTRACT_DEV_ID_FROM_PORT_ID(skb->dev->if_port);
		if (unlikely(dev_id >= MAX_QFP_NETDEV))
			return 1;
	}

	return qfp_throttle_get_token(&g_qfp_throttle_rx[dev_id], skb->len - ETH_HLEN);
}
