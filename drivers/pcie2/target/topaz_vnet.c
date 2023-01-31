/**
 * Copyright (c) 2012-2012 Quantenna Communications, Inc.
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

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/ioport.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/skbuff.h>
#include <linux/delay.h>
#include <linux/crc32.h>
#include <linux/phy.h>
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/if_bridge.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/ktime.h>
#include <linux/pci.h>
#include <linux/moduleloader.h>
#include <linux/reboot.h>
#include <linux/workqueue.h>
#include <linux/udp.h>
#include <linux/if_vlan.h>
#include <linux/pm_qos_params.h>

#include <net80211/ieee80211.h>

#include <trace/skb.h>
#include <trace/ippkt.h>

#include <qtn/shared_defs.h>
#include <qtn/topaz_hbm.h>
#include <qtn/qdrv_sch.h>
#include <qtn/iputil.h>

#include <asm/irq.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <linux/func_stat.h>

#include <asm/cache.h>		/* For cache line size definitions */
#include <asm/cacheflush.h>	/* For cache flushing functions */
#include <asm/hardware.h>

#include <asm/board/platform.h>
#include <asm/board/soc.h>
#include <asm/board/board_config.h>
#include <asm/board/dma_cache_ops.h>

#include <linux/net/bridge/br_private.h>

#include <common/queue.h>
#include <common/ruby_pm.h>
#include <qtn/topaz_hbm_cpuif.h>
#include <qtn/topaz_tqe.h>
#include <qtn/topaz_fwt_sw.h>

#include <qtn/skb_recycle.h>
#include <qtn/qtn_global.h>
#include <qtn/shared_params.h>
#include <qtn/qtn_vlan.h>
#include <asm/arcregs.h>
#include <qdpc_config.h>
#include <common/topaz_platform.h>
#include "topaz_vnet.h"
#include "topaz_pcie_dma.h"
#include "qdpc_config.h"
#include "qdpc_debug.h"
#include "../tqe/topaz_pcie_tqe.h"

#define DRV_NAME	"topaz_vnet"
#define DRV_VERSION	"1.0"
#define DRV_AUTHOR	"Quantenna Communications Inc."
#define DRV_DESC	"PCIe virtual Ethernet port driver"
MODULE_AUTHOR(DRV_AUTHOR);
MODULE_DESCRIPTION(DRV_DESC);
MODULE_LICENSE("GPL");

typedef enum {
	WPS_BUTTON_NONE_EVENT = 0,
	WPS_BUTTON_WIRELESS_EVENT,
	WPS_BUTTON_DBGDUMP_EVENT,
	WPS_BUTTON_INVALIDE_EVENT
} WPS_Button_Event;
#define WPS_BUTTON_VALID(e) (WPS_BUTTON_NONE_EVENT < (e) && (e) < WPS_BUTTON_INVALIDE_EVENT)

static int vmac_rdma_poll(struct napi_struct *napi, int budget);
static int vmac_rx_poll(struct napi_struct *napi, int budget);
static irqreturn_t vmac_interrupt(int irq, void *dev_id);
static void vmac_tx_timeout(struct net_device *ndev);
static int __init vmac_init_module(void);
static int vmac_get_settings(struct net_device *ndev, struct ethtool_cmd *cmd);
static int vmac_set_settings(struct net_device *ndev, struct ethtool_cmd *cmd);
static void vmac_get_drvinfo(struct net_device *ndev, struct ethtool_drvinfo *info);
static struct net_device* vmac_net_init(struct pci_dev *pdev);
static void free_tx_skbs(struct vmac_priv *vmp);
static void free_rx_skbs(struct vmac_priv *vmp);
static void release_all(struct net_device *ndev);
static void bring_up_interface(struct net_device *ndev);
static void shut_down_interface(struct net_device *ndev);
static int vmac_open(struct net_device *ndev);
static int vmac_close(struct net_device *ndev);
static struct net_device_stats *vmac_get_stats(struct net_device *ndev);
static void __exit vmac_cleanup_module(void);
static int vmac_ioctl(struct net_device *ndev, struct ifreq *rq, int cmd);
static int vmac_change_mtu(struct net_device *ndev, int new_mtu);
static int vmac_xmit(struct sk_buff *skb, struct net_device *ndev);
static void vmac_pcie_ep_resume(void);
static void vmac_wps_button_event_notifier(WPS_Button_Event event);
static void vmac_wps_button_device_file_create(struct net_device *ndev);

#define VMAC_BD_LEN		(sizeof(struct vmac_bd))
#define BDA_SHMEM_ADDR		(0x80010000)
#define VMAC_SCHED_TIMEOUT	(HZ/2)

#define RC2EP_MMAP(x)	((x) + vmp->rc2ep_offset)

#define EP_SHMEM_LEN		0x10000
#define QTN_GLOBAL_INIT_EMAC_TX_QUEUE_LEN (256)
#define QTN_TOPAZ_PCIE_EP_NAPI_BUDGET	(4)
#define QTN_TOPAZ_PCIE_RDMA_BUDGET	(4)

/*
 * eDMA bandwidth will increase whith src, dst and len changed on the boundary 4, 8, 16, ...
 * Bandwidth on 128 or above boundary is best.
 */
#define TOPAZ_BOUNDARY_128		(0x1 << 7)
#define TOPAZ_BOUNDARY_64		(0x1 << 6)

#define TOPAZ_DEF_TX_CONGEST_THRESH	128
#define TOPAZ_DEF_RX_CONGEST_THRESH	99
#define TOPAZ_DEF_RX_PKTS_PER_INTR	4
#define TOPAZ_DEF_RX_SOFTIRQ_BUDGET	8

#define TOPAZ_PCIE_TX_PKT_LEN_MAX	2048

/* It takes about 10uS to pend a packet to driver*/
#define COUNTER_PER_PKT		(RUBY_FIXED_CPU_CLK / 100000)
#define SET_TRIG_INTERVAL(interval, x) do { \
		if (x) \
			(interval) = (x) * COUNTER_PER_PKT; \
		else \
			(interval) = (vmp)->tx_bd_num * COUNTER_PER_PKT; \
	} while (0)

#define VMAC_DEBUG_MODE
/* Tx dump flag */
#define DMP_FLG_TX_BD		(0x1 << ( 0)) /* vmac s 32 */
#define DMP_FLG_TX_SKB		(0x1 << ( 1)) /* vmac s 33 */
/* Rx dump flag */
#define DMP_FLG_RX_BD		(0x1 << (16)) /* vmac s 48 */
#define DMP_FLG_RX_SKB		(0x1 << (17)) /* vmac s 49 */
#define DMP_FLG_RX_INT		(0x1 << (18)) /* vmac s 50 */


#define SHOW_TX_BD		(16)
#define SHOW_RX_BD		(17)
#define SHOW_VMAC_STATS		(18)
#define SHOW_TX_STATS		(20)
#define SHOW_WDMAPT		(22)
#define SHOW_RDMAPT		(23)
#define SHOW_WDMAPT_ALL		(24)
#define SHOW_RDMAPT_ALL		(25)
#define SHOW_RX_STATS		(26)
#define SHOW_RX_STATS_BACK	(27)

#ifdef VMAC_DEBUG_MODE

#define dump_tx_bd(vmp) do { \
		if (unlikely((vmp)->dbg_flg & DMP_FLG_TX_BD)) { \
			txbd2str(vmp); \
		} \
	} while (0)

#define dump_tx_buf(vmp, baddr, len) do { \
		if (unlikely(((vmp)->dbg_flg & DMP_FLG_TX_SKB))) \
			dump_pkt(baddr, len, "Tx"); \
	} while(0)

#define dump_rx_bd(vmp) do { \
		if (unlikely((vmp)->dbg_flg & DMP_FLG_RX_BD)) { \
			rxbd2str(vmp); \
		} \
	} while (0)

#define dump_rx_buf(vmp, baddr, len) do { \
		if (unlikely((vmp)->dbg_flg & DMP_FLG_RX_SKB)) \
			dump_pkt(baddr, len, "Rx"); \
	} while(0)

#define dump_rx_int(vmp) do { \
		if (unlikely((vmp)->dbg_flg & DMP_FLG_RX_INT)) \
			dump_rx_interrupt(vmp); \
	} while (0)

#else
#define dump_tx_bd(vmp)
#define dump_tx_buf(vmp, skb)
#define dump_rx_bd(vmp)
#define dump_rx_buf(vmp, skb)
#define dump_rx_int(vmp)
#endif

struct pcie_vmac_cfg vmac_cfg = {
	 TOPAZ_IRQ_PCIE_DMA, TOPAZ_IRQ_IPC4,
	"pcie%d", NULL
};

struct net_device *g_ndev = NULL;

/*
 * Controls whether frames transmitted over PCIe need to include meta information like
 * radio ID and interface ID.
 */
static bool frames_meta_info;
module_param(frames_meta_info, bool, 0700);

/* enable Tx done interrupt to Rc */
static bool tx_done_en;
module_param(tx_done_en, bool, 0700);

int tqe_sem_en = 0;
module_param(tqe_sem_en, int, S_IRWXU);

char *qdpc_mac0addr = NULL;
module_param(qdpc_mac0addr, charp, 0);
uint8_t veth_basemac[ETH_ALEN] = {'\0', 'R', 'U', 'B', 'Y', '%'};

static struct work_struct rc_rmmod_work;

/* Alignment helper functions */
__always_inline static unsigned long align_up_off(unsigned long val, unsigned long step)
{
	return (((val + (step - 1)) & (~(step - 1))) - val);
}

__always_inline static unsigned long align_down_off(unsigned long val, unsigned long step)
{
	return ((val) & ((step) - 1));
}

static void qdpc_nl_recv_msg(struct sk_buff *skb)
{
	struct net_device *ndev = g_ndev;
	struct vmac_priv *vmp = netdev_priv(ndev);
	struct nlmsghdr *nlh  = (struct nlmsghdr*)skb->data;
	struct sk_buff *skb2;
	unsigned int data_len;
	unsigned int offset;
	qdpc_cmd_hdr_t *cmd_hdr;
	uint16_t rpc_type;

	/* Parsing the netlink message */

	PRINT_DBG(KERN_INFO "%s line %d Netlink received pid:%d, size:%d, type:%d\n",
		__FUNCTION__, __LINE__, nlh->nlmsg_pid, nlh->nlmsg_len, nlh->nlmsg_type);

	switch (nlh->nlmsg_type) {
		case QDPC_NL_TYPE_SVC_STR_REG:
		case QDPC_NL_TYPE_SVC_LIB_REG:
			if (nlh->nlmsg_type == QDPC_NL_TYPE_SVC_STR_REG)
				vmp->str_call_nl_pid = nlh->nlmsg_pid;
			else
				vmp->lib_call_nl_pid = nlh->nlmsg_pid;
			return;
		case QDPC_NL_TYPE_SVC_STR_REQ:
		case QDPC_NL_TYPE_SVC_LIB_REQ:
			break;
		default:
			PRINT_DBG(KERN_INFO "%s line %d Netlink Invalid type %d\n",
				__FUNCTION__, __LINE__, nlh->nlmsg_type);
			return;
	}

	/*
	 * make new skbs; Fragment if necessary.
	 * The original skb will be freed in netlink_unicast_kernel,
	 * we hold the new skbs until DMA transfer is done
	 */
	offset = sizeof(struct nlmsghdr);
	data_len = nlh->nlmsg_len;

	while (data_len > 0) {
		unsigned int len = min_t(unsigned int, data_len, ndev->mtu);
		unsigned int skb2_len = len + sizeof(qdpc_cmd_hdr_t);

		skb2 = alloc_skb(skb2_len + QVLAN_PKTCTRL_LEN * 2, GFP_ATOMIC);
		if (!skb2) {
			printk(KERN_INFO "%s: skb alloc failed\n", __func__);
			return;
		}
		skb_reserve(skb2, QVLAN_PKTCTRL_LEN);

		data_len -= len;

		rpc_type = nlh->nlmsg_type & QDPC_RPC_TYPE_MASK;
		rpc_type |= (data_len > 0 ? QDPC_RPC_TYPE_FRAG : 0);

		cmd_hdr = (qdpc_cmd_hdr_t *)skb2->data;
		memcpy(cmd_hdr->dst_magic, QDPC_NETLINK_DST_MAGIC, ETH_ALEN);
		memcpy(cmd_hdr->src_magic, QDPC_NETLINK_SRC_MAGIC, ETH_ALEN);
		cmd_hdr->type = __constant_htons(QDPC_APP_NETLINK_TYPE);
		cmd_hdr->len = htons((uint16_t)len);
		cmd_hdr->rpc_type = htons(rpc_type);
		cmd_hdr->total_len = htons((uint16_t)(nlh->nlmsg_len));

		memcpy((uint8_t *)(cmd_hdr + 1), skb->data + offset, len);

		offset += len;

		skb_put(skb2, skb2_len);
		skb_reset_mac_header(skb2);
		skb_reset_network_header(skb2);
		skb2->protocol = __constant_htons(QDPC_APP_NETLINK_TYPE);
		skb2->dev = ndev;

		if (vlan_enabled) {
			struct qtn_vlan_pkt *pkt = qtn_vlan_get_info(skb2->data);

			pkt->magic = QVLAN_PKT_MAGIC;
			pkt->flag = QVLAN_PKT_SKIP_CHECK;
			pkt->vlan_info = 0;
		}

		dev_queue_xmit(skb2);
	}
}

static inline bool check_netlink_magic(qdpc_cmd_hdr_t *cmd_hdr)
{
	return ((memcmp(cmd_hdr->dst_magic, QDPC_NETLINK_DST_MAGIC, ETH_ALEN) == 0)
		&& (memcmp(cmd_hdr->src_magic, QDPC_NETLINK_SRC_MAGIC, ETH_ALEN) == 0));
}

static void vmac_netlink_rx(struct net_device *ndev, void *buf, size_t len, uint16_t rpc_type, uint32_t total_len)
{
	struct vmac_priv *priv = netdev_priv(ndev);
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	u32 pid = 0;
	int frag = (rpc_type & QDPC_RPC_TYPE_FRAG_MASK);

	rpc_type &= QDPC_RPC_TYPE_MASK;

	if (unlikely(total_len > VMAC_NL_BUF_SIZE)) {
		printk(KERN_INFO"%s: total length %u exceeds buffer length %u\n", __func__,
			total_len, VMAC_NL_BUF_SIZE);
		goto reset_nlbuf;
	}

        if (unlikely(priv->nl_len + len > total_len)) {
                printk(KERN_INFO"%s: frag length %u exceeds total length %u\n", __func__,
                        priv->nl_len + len, total_len);
                goto reset_nlbuf;
        }

	memcpy(priv->nl_buf + priv->nl_len, buf, len);
	priv->nl_len += len;

	if (frag)
		return;

	/* last fragment -- hand it to upper layer */
	buf = priv->nl_buf;
	len = priv->nl_len;

	skb = nlmsg_new(len, GFP_ATOMIC);
	if (skb == NULL) {
		DBGPRINTF("WARNING: out of netlink SKBs\n");
		goto reset_nlbuf;
	}

	nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, len, 0);
	memcpy(nlmsg_data(nlh), buf, len);
	NETLINK_CB(skb).dst_group = 0;

	if (rpc_type == QDPC_RPC_TYPE_STRCALL)
		pid = priv->str_call_nl_pid;
	else if (rpc_type == QDPC_RPC_TYPE_LIBCALL)
		pid = priv->lib_call_nl_pid;

	if (unlikely(pid == 0)) {
		kfree_skb(skb);
		goto reset_nlbuf;
	}

	nlmsg_unicast(priv->nl_socket, skb, pid);

reset_nlbuf:
	priv->nl_len = 0;
}

static int txbd2str_range(struct vmac_priv *vmp, uint16_t s, int num)
{
	int i;
	int j;
	char idxflg[5];
	int count;

	count = printk("txindex\ttbdaddr\t\tbuff\t\tinfo\t\tflag\t\ttx_handle\n");
	for (i = 0; i < num; i++) {
		j = 0;
		if (s == vmp->tx_toDMA_s)
			idxflg[j++] = 's';
		if (s == vmp->tx_toDMA_e)
			idxflg[j++] = 'e';
		idxflg[j] = 0;

		count += printk("%3d %s\t@%p\t%08x\t%08x\t%08x\t%08x\n",
			    s, idxflg, &vmp->rc_rx_bd_base[s],
			    arc_read_uncached_32(&vmp->rc_rx_bd_base[s].buff_addr),
			    arc_read_uncached_32(&vmp->rc_rx_bd_base[s].buff_info),
			    arc_read_uncached_32(&vmp->tx_flag_va[s]),
				vmp->tx_buf[s].handle);
		VMAC_INDX_INC(s, vmp->tx_bd_num);
	}

	return 0;
}

static int txbd2str(struct vmac_priv *vmp)
{
	int num;
	uint16_t s;

	s = VMAC_INDX_MINUS(vmp->tx_toDMA_s, 2, vmp->tx_bd_num);
	num  = VMAC_INDX_MINUS(vmp->tx_toDMA_e + 5, vmp->tx_toDMA_s, vmp->tx_bd_num);
	if (num > 16)
		num = 16;

	return txbd2str_range(vmp, s, num);
}

static int txbd2str_all(struct vmac_priv *vmp)
{
	return txbd2str_range(vmp, 0, vmp->tx_bd_num);
}

static int rxbd2str_range(struct vmac_priv *vmp, uint16_t s, int num)
{
	int i;
	int j;
	char idxflg[5];
	int count;

	count = printk("rxindx\trbdaddr\t\tbuff\t\tinfo\t\tflag\t\trx_handle\n");
	for (i = 0; i < num; i++) {
		struct vmac_pkt_info *pkt_info;

		j = 0;
		if (s == vmp->rx_pkt_index)
			idxflg[j++] = 'n';
		if (s == vmp->rx_toDMA_s)
			idxflg[j++] = 's';
		if (s == vmp->rx_toDMA_e)
			idxflg[j++] = 'e';
		if (s == vmp->rx_DMAing)
			idxflg[j++] = 'D';
		idxflg[j] = 0;

		pkt_info = vmp->request_queue + s;
		count += printk("%3d %s\t@%p\t%08x\t%08x\t%08x\n",
			    s, idxflg, pkt_info,
			    arc_read_uncached_32(&pkt_info->addr),
			    arc_read_uncached_32(&pkt_info->info),
			    vmp->rx_buf[s].baddr);
		VMAC_INDX_INC(s, vmp->rx_bd_num);
	}
	return 0;
}

static int rxbd2str(struct vmac_priv *vmp)
{
	int num;
	uint16_t s;

	num  = VMAC_INDX_MINUS(vmp->rx_toDMA_e + 5, vmp->rx_DMAing, vmp->rx_bd_num);
	if (num > 16)
		num = 16;
	s = VMAC_INDX_MINUS(vmp->rx_DMAing, 2, vmp->rx_bd_num);
	return rxbd2str_range(vmp, s, num);
}

static int rxbd2str_all(struct vmac_priv *vmp)
{
	return rxbd2str_range(vmp, 0, vmp->rx_bd_num);
}

static int counter2str(struct vmac_priv *vmp, char *buff)
{
	int count;
	count = sprintf(buff, "wdma_busy_cnt:\t%08x\n", vmp->wdma_busy_cnt);
	count += sprintf(buff + count, "tx_rc_bd_busy:\t%08x\n",
			vmp->tx_rc_bd_busy);
	count += sprintf(buff + count, "rdma_busy_cnt:\t%08x\n", vmp->rdma_busy_cnt);
	count += sprintf(buff + count, "ipc_cnt:\t%08x\n", vmp->ipc_cnt);
	count += sprintf(buff + count, "rdma_dn_cnt:\t%08x\n", vmp->rdma_dn_cnt);
	count += sprintf(buff + count, "rdma_ab_cnt:\t%08x\n", vmp->rdma_ab_cnt);
	count += sprintf(buff + count, "hbm_alloc_fail:\t%08x\n",
			vmp->rx_hbm_alloc_fail);
	count += sprintf(buff + count, "fwt_loss_cnt:\t%08x\n", vmp->fwt_loss_cnt);
	count += sprintf(buff + count, "tx_ll_full:\t%08x\n", vmp->tx_ll_full);

	count += sprintf(buff + count, "wdma_done_cnt:\t%08x\n", vmp->wdma_done_cnt);
	count += sprintf(buff + count, "wdma_intr_trig:\t%08x\n", vmp->wdma_intr_trig);
	count += sprintf(buff + count, "wdma_soft_trig:\t%08x\n", vmp->wdma_softirq_trig);
	count += sprintf(buff + count, "wdma_done_idle:\t%08x\n", vmp->wdma_done_idle);
	count += sprintf(buff + count, "vmac_tx_entries:\t%08x\n", vmp->vmac_tx_entries);
	count += sprintf(buff + count, "wdma_running:\t%08x\n", atomic_read(&vmp->wdma_running));
	count += sprintf(buff + count, "tqe_rx_napi:\t%08x\n", vmp->tqe_rx_napi_cnt);
	count += sprintf(buff + count, "tx_queue_len:\t%08x\n", vmp->tx_queue_len);
	count += sprintf(buff + count, "tx_tqe_no_pkt:\t%08x\n", vmp->tx_tqe_no_pkt);
	count += sprintf(buff + count, "tx_dma_reserved:\t%08x\n", vmp->tx_dma_reserved);
	count += sprintf(buff + count, "txqueue_stopped:\t%x\n", vmp->txqueue_stopped);
	count += sprintf(buff + count, "rc_txqueue_stopped:\t%x\n", vmp->rc_txqueue_stopped);
	count += sprintf(buff + count, "rc_txbd_avail_cnt:\t%x\n", vmp->rc_txbd_avail_cnt);
	count += sprintf(buff + count, "rc_txbd_wake_th:\t%x\n", vmp->rc_txbd_wake_th);
	count += sprintf(buff + count, "rc_txqueue_wake:\t%x\n", *vmp->rc_txqueue_wake);
	count += sprintf(buff + count, "tx_intr_rc_th:\t%x\n", vmp->tx_intr_rc_th);
	count += sprintf(buff + count, "rx_channel_num:\t%x\n", vmp->rx_channel_num);
	return count;
}

static int vmac_parse_mac(const char *mac_str, uint8_t *mac)
{
        unsigned int tmparray[ETH_ALEN];

        if (mac_str == NULL)
                return -1;

        if (sscanf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                        &tmparray[0],
                        &tmparray[1],
                        &tmparray[2],
                        &tmparray[3],
                        &tmparray[4],
                        &tmparray[5]) != ETH_ALEN) {
                return -1;
        }

        mac[0] = tmparray[0];
        mac[1] = tmparray[1];
        mac[2] = tmparray[2];
        mac[3] = tmparray[3];
        mac[4] = tmparray[4];
        mac[5] = tmparray[5];

        return 0;
}

void vmac_set_macaddr(struct net_device *ndev, uint8_t *addr)
{
	unsigned char macaddr[ETH_ALEN];

        if (qdpc_mac0addr != NULL) {
                vmac_parse_mac(qdpc_mac0addr, veth_basemac);
        }

        memcpy(macaddr, veth_basemac, ETH_ALEN);
        macaddr[0] = (macaddr[0] & 0x1F) | (((macaddr[0] & 0xE0) + 0x20) & 0xE0) | 0x02;
        memcpy(ndev->dev_addr, macaddr, ETH_ALEN);
}

static int vmac_tx_stat2str(struct vmac_priv *vmp, char *buff)
{
	int count;
	int i;

	count = sprintf(buff, "%20s:\t%d\n", "vmac_tx_func_entries", vmp->vmac_tx_entries);
	count += sprintf(buff + count, "%20s:\t%u\n", "wdma_busy_cnt", vmp->wdma_busy_cnt);
	count += sprintf(buff + count, "%20s:\t%d\n", "tx_rc_bd_busy", vmp->tx_rc_bd_busy);
	count += sprintf(buff + count, "%20s:\t%d\n", "tx_ll_full", vmp->tx_ll_full);
	count += sprintf(buff + count, "%20s:\t%d\n", "tx_dma_pkts", vmp->tx_dma_pkts);

	count += sprintf(buff + count, "LL issue number log:\n");
	for (i = 0; i < PCIE_DMA_ISSUE_LOG_NUM; i++)
		count += sprintf(buff + count, "%20d:\t%d\n", i + 1, vmp->tx_dma_issue_log[i]);

	return count;
}

static int vmac_rx_stat2str(struct vmac_priv *vmp, char *buff)
{
	int count = 0;
	int i;

	count += sprintf(buff + count, "LL issue number log:\n");
	for (i = 0; i < PCIE_DMA_ISSUE_LOG_NUM; i++)
		count += sprintf(buff + count, "%20d:\t%d\n", i + 1, vmp->rx_dma_issue_log[i]);

	return count;
}

static int vmac_rx_stat2str_back(struct vmac_priv *vmp, char *buff)
{
	int count = 0;
	int i;

	count += sprintf(buff + count, "LL issue number log:\n");
	for (i=PCIE_DMA_ISSUE_LOG_NUM-1; i>=0; i--)
		count += sprintf(buff + count, "%20d:\t%d\n", i + 1, vmp->rx_dma_issue_log[i]);

	return count;
}

static ssize_t vmac_dbg_show(struct device *dev, struct device_attribute *attr,
						char *buff)
{
	struct net_device *ndev = container_of(dev, struct net_device, dev);
	struct vmac_priv *vmp = netdev_priv(ndev);
	int count = 0;
	switch (vmp->show_item) {
	case SHOW_TX_BD:/* show Tx BD */
		count = (ssize_t)txbd2str_all(vmp);
		break;
	case SHOW_RX_BD:/* show Rx BD */
		count = (ssize_t)rxbd2str_all(vmp);
		break;
	case SHOW_VMAC_STATS:/* show vmac statistic info */
		count = counter2str(vmp, buff);
		break;
	case SHOW_TX_STATS:
		count = vmac_tx_stat2str(vmp, buff);
		break;
	case SHOW_RX_STATS:
		count = vmac_rx_stat2str(vmp, buff);
		break;
	case SHOW_RX_STATS_BACK:
		count = vmac_rx_stat2str_back(vmp, buff);
		break;
	case SHOW_WDMAPT:
		vmac_wdmapt_print(vmp);
		break;
	case SHOW_RDMAPT:
		vmac_rdmapt_print(vmp);
		break;
	case SHOW_WDMAPT_ALL:
		vmac_wdmapt_print_all(vmp);
		break;
	case SHOW_RDMAPT_ALL:
		vmac_rdmapt_print_all(vmp);
		break;
	default:
		break;
	}
	return count;
}

void vmac_clear_rx_counter(struct vmac_priv *vmp) {
	struct net_device *ndev = vmp->ndev;

	vmp->ipc_cnt = 0;
	vmp->rdma_dn_cnt = 0;
	vmp->rdma_ab_cnt = 0;

	vmp->rx_napi_func = 0;
	vmp->rx_napi_poll = 0;
	vmp->rx_dma_busy = 0;
	ndev->stats.rx_packets = 0;

	vmp->rx_dma_funcs = 0;
	vmp->rdma_trigger = 0;
	vmp->rdma_busy_cnt = 0;

	vmp->rx_dma_while = 0;
	vmp->rx_queue_max = 0;
	vmp->rx_slow_rc = 0;

	vmp->rx_hbm_alloc_fail = 0;
	vmp->fwt_loss_cnt = 0;
}

void vmac_print_rx_counter(struct vmac_priv *vmp) {
	struct net_device *ndev = vmp->ndev;
	int i = 0;

	/* Rx Interrupt Counter */
	printk("ipc_cnt:\t\t\t%08x\n", vmp->ipc_cnt);
	printk("rdma_dn_cnt:\t\t%08x\n", vmp->rdma_dn_cnt);
	printk("rdma_ab_cnt:\t\t%08x\n", vmp->rdma_ab_cnt);

	/* Rx DMA Counter */
	printk("vmac_start_rdma:\t\t%08x\n", vmp->rx_dma_funcs);
	printk("start_rdma_loop:\t\t%08x\n", vmp->rx_dma_while);
	printk("rx_queue_max:\t\t%08x\n", vmp->rx_queue_max);
	printk("rx_slow_rc:\t\t%08x\n", vmp->rx_slow_rc);

	printk("rdma_trigger:\t\t%08x\n", vmp->rdma_trigger);
	printk("rdma_intr_trig:\t\t%08x\n", vmp->rdma_intr_trig);
	printk("rdma_softirq_trig:\t%08x\n", vmp->rdma_softirq_trig);
	printk("rdma_chan_busy:\t\t%08x\n", vmp->rdma_busy_cnt);
	printk("rx_dma_reserved:\t\t%08x\n", vmp->rx_dma_reserved);
	printk("ave_dma_len:\t\t%lu\n", (ndev->stats.rx_packets / vmp->rdma_trigger));

	/* Rx Packet Handle counter */
	printk("vmac_rx_poll:\t\t%08x\n", vmp->rx_napi_func);
	printk("rx_poll_while:\t\t%08x\n", vmp->rx_napi_poll);
	printk("pkt_dmaing:\t\t%08x\n", vmp->rx_dma_busy);

	printk("rx_pkts:\t\t\t%lx\n", ndev->stats.rx_packets);
	printk("rx_tqe_fwd:\t\t%08x\n", vmp->rx_tqe_fwd);
	for (i = 0; i < TOPAZ_CONGEST_QUEUE_NUM; i++)
		printk("rx_congest_fwd %d:\t%08x\n", i, vmp->congest_queue->queues[i].congest_xmit);

	printk("rx_pcie_drop:\t\t%08x\n", vmp->rx_pcie_drop);
	for (i = 0; i < TOPAZ_CONGEST_QUEUE_NUM; i++)
		printk("rx_congest_drop %d:\t%08x\n", i, vmp->congest_queue->queues[i].congest_drop);

	/* Congest Queue */
	printk("rx_congest_entry:\t%08x\n", vmp->congest_queue->func_entry);
	printk("rx_congest_retry:\t%08x\n", vmp->congest_queue->cnt_retries);
	printk("congest_xmit_entry:\t%08x\n", vmp->congest_queue->xmit_entry);
	printk("retry_failure_0:\t\t%08x\n", (vmp->congest_queue->cnt_retries - vmp->congest_queue->queues[0].congest_xmit));

	/* Misc */
	printk("hbm_alloc_fail:\t\t%08x\n", vmp->rx_hbm_alloc_fail);
	printk("fwt_loss_cnt:\t\t%08x\n", vmp->fwt_loss_cnt);
}

void print_request_queue(struct vmac_priv *vmp) {
	struct vmac_pkt_info *pkt_info;
	int i;

	printk("%8s:\t%10s:\t%10s\n", "Address", "Valid", "Length");
	for (i = 0; i < vmp->rx_bd_num; i++) {
		pkt_info = vmp->request_queue + i;
		printk("0x%08x:\t%10s:\t%d\n", pkt_info->addr, (pkt_info->info & PCIE_TX_VALID_PKT) ? "Valid" : "Invalid", pkt_info->info & 0xffff);
	}
}

static void vmac_aspm_l1_enable(enum l1_entry_latency entry_time)
{
	uint32_t l1_ctrl;
	uint32_t link_ctrl;

	/* Enter L1 frpm L0 and set the entry latency */
	l1_ctrl = readl(PCIE_ASPM_L1_CTRL);

	l1_ctrl &= 0x7FFFFFF;
	l1_ctrl |= (PCIE_ASPM_L1_FROM_L0 | entry_time) << 27;

	writel(l1_ctrl, PCIE_ASPM_L1_CTRL);

	/* Enable the L1 entry field of the Link control register */
	link_ctrl = readl(PCIE_ASPM_LINK_CTRL);

	link_ctrl &= 0xFFFFFFFC;
	link_ctrl |= PCIE_ASPM_L1_ENABLE;

	writel(link_ctrl, PCIE_ASPM_LINK_CTRL);
}

static void vmac_aspm_l1_disable(void)
{
	uint32_t link_ctrl;

	link_ctrl = readl(PCIE_ASPM_LINK_CTRL);
	link_ctrl &= 0xFFFFFFFC;
	writel(link_ctrl, PCIE_ASPM_LINK_CTRL);
}

/* parameter local: value 0, the L1 enter originate from RC
 *                  power save request
 *                  otherwise, the L1 enter originate from
 *                  EP local power save request
 */
static inline void vmac_enter_l1(int local)
{
	uint32_t l1_substate_ctrl1;
	uint32_t link_state;
	uint32_t pm_pmcsr;

	writel(0x0, RUBY_SYS_CTL_PCIE_CFG4);

	/* enables PCI-PM L1.1 and L1.2 Required
	 * for both Upstream and Downstream Ports
	 * Read modify Write  2'b11 to bit [1:0]
	 * of PCIE_L1SUB_CTRL1 register
	 * (Address E900_0150)
	 */
	l1_substate_ctrl1 = readl(PCIE_L1SUB_CTRL1);
	l1_substate_ctrl1 |= 0x03;
	writel(l1_substate_ctrl1, PCIE_L1SUB_CTRL1);

	/* Enable Clock Power Management: device
	 * is permitted to use CLKREQ# signal to
	 * power manage Link clock
	 * Read modify write  1'b1 to bit 8 of
	 * PCIE_LINKCTLSTS register
	 * (Address E900_0080)
	 */
	link_state = readl(PCIE_LINK_STAT);
	link_state |= 0x100;
	writel(link_state, PCIE_LINK_STAT);

	/* enable PME assert and set power state to D3hot
	 * Read modify write 1'b1 & 2'b11 to
	 * bit 8 & bits[1:0] pf PCIE_PMCSR register
	 *  (Address E900_0044)
	 */
	if (local) {
		pm_pmcsr = readl(PCIE_PMCSR);
		writel((pm_pmcsr & ~PCI_PM_CTRL_STATE_MASK) | (PCI_D3hot | PCI_PM_CTRL_PME_ENABLE), PCIE_PMCSR);
	}

	/* enable PCIE clock */
	writel(0x10000, RUBY_SYS_CTL_PCIE_CFG4);
}

/* parameter local: value 0, the L1 exit originate from RC
 *                  power resume request
 *                  otherwise, the L1 exit originate from
 *                  EP local power resume request
 */
static inline void vmac_exit_l1(int local)
{
	uint32_t pm_pmcsr;

	/* disable PME assert and set power state to D0
	 * Read modify write 1'b0 & 2'b00 to
	 * bit 8 & bits[1:0] pf PCIE_PMCSR register
	 *  (Address E900_0044)
	 */
	if (local) {
		pm_pmcsr = readl(PCIE_PMCSR);
		writel((pm_pmcsr & ~PCI_PM_CTRL_STATE_MASK) | (PCI_D0 | PCI_PM_CTRL_PME_ENABLE), PCIE_PMCSR);
	}

	writel(0x0, RUBY_SYS_CTL_PCIE_CFG4);
}

#define PMSTATE_CHECK_INTERVAL (HZ/5)
#define PMSTATE_CHECK_INIT 0
#define PMSTATE_CHECK_ACTIVE 1
#define PMSTATE_CHECK_END 2

static void vmac_pmstate_checker(unsigned long dummy)
{
	static int flag = PMSTATE_CHECK_INIT;
	uint32_t pm_pmcsr = 0;
	struct vmac_priv *vmp = NULL;

	vmp = netdev_priv(g_ndev);
	pm_pmcsr = readl(PCIE_PMCSR);

	switch (flag) {
	case PMSTATE_CHECK_INIT:
		if ((pm_pmcsr & PCI_PM_CTRL_STATE_MASK) == PCI_D3hot)
			flag = PMSTATE_CHECK_ACTIVE;
		break;
	case PMSTATE_CHECK_ACTIVE:
		if ((pm_pmcsr & PCI_PM_CTRL_STATE_MASK) == PCI_D0) {
			vmac_pcie_ep_resume();
			netif_wake_queue(g_ndev);
			flag = PMSTATE_CHECK_END;
		}
		break;
	default:
		printk(KERN_ERR "pmstate\n");
		return;
	}

	if (unlikely(flag == PMSTATE_CHECK_END)) {
		flag = PMSTATE_CHECK_INIT;
	} else {
		vmp->pmstate_ck_timer.expires = jiffies + PMSTATE_CHECK_INTERVAL;
		add_timer(&(vmp->pmstate_ck_timer));
	}
}

static void vmac_pcie_ep_suspend(void)
{
	struct vmac_priv *vmp = NULL;

	printk("Start PCIE ep power management suspend.\n");

	vmp = netdev_priv(g_ndev);

	/* Set PCIE link to L1 state */
	if ((readl(RUBY_SYS_CTL_CSR) & 0xff) == TOPAZ_BOARD_REVB) {
		vmac_aspm_l1_enable(LATENCY_4US);
	} else {
		vmac_enter_l1(0);
		vmp->pmstate_ck_timer.expires = jiffies + PMSTATE_CHECK_INTERVAL;
		add_timer(&(vmp->pmstate_ck_timer));
	}

	/* Enable WLAN suspend mode */
	pm_qos_update_requirement(PM_QOS_POWER_SAVE, BOARD_PM_GOVERNOR_PCIE_EP, BOARD_PM_LEVEL_SUSPEND);
}

static void vmac_pcie_ep_resume(void)
{
	printk("Start PCIE ep power management resume.\n");

	/* Set PCIE link to L0 state */
	if ((readl(RUBY_SYS_CTL_CSR) & 0xff) == TOPAZ_BOARD_REVB)
		vmac_aspm_l1_disable();
	else
		vmac_exit_l1(0);

	/* Enable WLAN full power mode */
	pm_qos_update_requirement(PM_QOS_POWER_SAVE, BOARD_PM_GOVERNOR_PCIE_EP, BOARD_PM_LEVEL_NO);
}

static ssize_t vmac_dbg_set(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct net_device *ndev = container_of(dev, struct net_device, dev);
	struct vmac_priv *vmp = netdev_priv(ndev);
	char buffer[128];
	char *str = buffer;
	char *token;
	uint32_t cmd;
	uint32_t num = 0;
	int latency;

	strncpy(str, buf, sizeof(buffer) - 1);

	token = strsep(&str, " ,\n");
	cmd = (uint32_t)simple_strtoul(token, NULL, 10);

	if (cmd < 16) {
		switch(cmd) {
		case 0:
			vmp->dbg_flg = 0; /* disable all of runtime dump */
			break;
		case 1:
			napi_schedule(&vmp->rx_napi);
			break;
		case 2:
			vmp->wdma_busy_cnt = 0;
			vmp->tx_rc_bd_busy = 0;
			vmp->ipc_cnt = 0;
			vmp->rdma_dn_cnt = 0;
			vmp->rdma_ab_cnt = 0;
			vmp->rx_hbm_alloc_fail = 0;
			vmp->fwt_loss_cnt = 0;
			vmp->tx_ll_full = 0;
			vmp->wdma_done_cnt = 0;
			vmp->wdma_intr_trig = 0;
			vmp->wdma_softirq_trig = 0;
			vmp->wdma_done_idle = 0;
			vmp->vmac_tx_entries = 0;
			vmp->rdma_busy_cnt = 0;
			vmp->rx_hbm_alloc_fail = 0;
			break;
		default:
			break;
		}

	} else if (cmd < 32) {/* used for vmac_dbg_show */
		vmp->show_item = cmd;
	} else if (cmd < 64) {/* used for runtime dump */
		vmp->dbg_flg |= (0x1 << (cmd - 32));
	} else if (cmd == 64) {/* enable all of runtime dump */
		vmp->dbg_flg = -1;
	} else if (cmd == 65) {
		print_request_queue(vmp);
	} else if (cmd == 66) {
		vmac_clear_rx_counter(vmp);
	} else if (cmd == 67) {
		vmac_print_rx_counter(vmp);
	} else if (cmd == 68) {
		topaz_congest_dump(vmp->congest_queue);
	} else if (cmd == 81) {
		token = strsep(&str, " ,\n");
		if (token) {
			num = (uint32_t)simple_strtoul(token, NULL, 10);
			vmp->tx_intr_rc_th = (uint16_t)num;
		}
	} else if (cmd == 82) {
#ifdef VMAC_DDMA_CHANNEL
		token = strsep(&str, " ,\n");
		if (token) {
			num = (uint32_t)simple_strtoul(token, NULL, 10);
			vmp->rx_channel_num = (uint8_t)num;
		}
#endif
	} else if (cmd == VMAC_ASPM_ENABLE_CMD) {
		if (str && (token = strsep(&str, " ,\n"))) {
			latency = (int)simple_strtoul(token, NULL, 10);
			if (latency < 7 && latency >= 0) {
				vmac_aspm_l1_enable((enum l1_entry_latency)latency);
			} else {
				printk("latency time exceeds the limitation \n");
			}
		}
	} else if (cmd == VMAC_ASPM_DISABLE_CMD) {
		vmac_aspm_l1_disable();
	} else if (cmd == 71) {
		vmac_enter_l1(1);
	} else if (cmd == 72) {
		vmac_exit_l1(1);
	}

	return count;
}
DEVICE_ATTR(dbg, S_IWUSR | S_IRUSR, vmac_dbg_show, vmac_dbg_set); /* dev_attr_dbg */

#ifdef VMAC_DEBUG_MODE
static void noinline dump_pkt(uint32_t baddr, int len, char * s)
{
	int i;
	char * data = (char *)bus_to_virt(baddr);

	printk("%spkt start %p len %u>\n", s, data, len);
	if (len > 128)
		len = 128;
	for (i = 0; i < len;) {
		printk("%02x ", data[i]);
		if ((++i % 16) == 0)
			printk("\n");
	}
	inv_dcache_range((uint32_t)data, (uint32_t)data + len);
	printk("<%spkt end\n", s);
}

void dump_rx_interrupt(struct vmac_priv *vmp)
{
	printk("ipc_cnt:\t%08x\n", vmp->ipc_cnt);
	printk("rdma_dn_cnt:\t%08x\n", vmp->rdma_dn_cnt);
	printk("rdma_ab_cnt:\t%08x\n", vmp->rdma_ab_cnt);
}
#endif

struct vmac_params {
	const char *param_name;
	uint32_t offset;
#define VMAC_P_VPRIV	0
#define VMAC_P_CONGQ	1
	int type;
};
static struct vmac_params params[] = {
	{"tx_congest_thresh", offsetof(struct vmac_priv, tx_congest_thresh), VMAC_P_VPRIV},
	{"rx_congest_thresh", offsetof(struct vmac_priv, rx_congest_thresh), VMAC_P_VPRIV},
	{"rx_intr_pktnr", offsetof(struct vmac_priv, rx_intr_pktnr), VMAC_P_VPRIV},
	{"congest_tasklet_budget", offsetof(struct topaz_congest_queue, tasklet_budget), VMAC_P_CONGQ},
	{"congest_softirq_budget", offsetof(struct vmac_priv, rx_congsirq_budget), VMAC_P_VPRIV},
	{"congest_queue_timeout", offsetof(struct topaz_congest_queue, congest_timeout), VMAC_P_CONGQ},
};

static ssize_t vmac_params_show(struct device *dev, struct device_attribute *attr,
                                                char *buff)
{
	struct net_device *ndev = container_of(dev, struct net_device, dev);
	struct vmac_priv *vmp = netdev_priv(ndev);
	struct topaz_congest_queue *congest_queue = vmp->congest_queue;
	uint8_t *base = NULL;
	ssize_t count = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(params); i++) {
		if (params[i].type == VMAC_P_VPRIV)
			base = (uint8_t *)vmp;
		else if (params[i].type == VMAC_P_CONGQ)
			base = (uint8_t *)congest_queue;
		else
			continue;
		count += sprintf(buff + count, "%s:\t0x%08x\n", params[i].param_name, *(uint32_t *)(base + params[i].offset));
	}

	return count;
}

static ssize_t vmac_params_set(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct net_device *ndev = container_of(dev, struct net_device, dev);
	struct vmac_priv *vmp = netdev_priv(ndev);
	struct topaz_congest_queue *congest_queue = vmp->congest_queue;
	int i;
	char *str;
	uint32_t val;
	uint8_t *base;

	for (i = 0; i < ARRAY_SIZE(params); i++) {
		str = strstr(buf, params[i].param_name);
		if (str) {
			str += strlen(params[i].param_name);
			str = strim(str);
			val = simple_strtoul(str, NULL, 10);
			if (params[i].type == VMAC_P_VPRIV)
				base = (uint8_t *)vmp;
			else if (params[i].type == VMAC_P_CONGQ)
				base = (uint8_t *)congest_queue;
			else
				break;
			*(uint32_t *)(base + params[i].offset) = val;
			break;
		}
	}

	return count;
}

DEVICE_ATTR(parameters, S_IWUSR | S_IRUSR, vmac_params_show, vmac_params_set);

static inline void vmac_intr_rc(struct vmac_priv *vmp)
{
	if (vmp->msi_enabled)
		writew(vmp->msi_data, vmp->msi_addr);
	else
		qdpc_assert_intx();
}
/* Rx packet interrupt API */
static inline void vmac_ipc_intr_rx_en(void)
{
	set_bit(IPC_BIT_EP_RX_PKT, (void *)TOPAZ_LH_IPC4_INT_MASK);
}
static inline void vmac_ipc_intr_rx_dis(void)
{
	clear_bit(IPC_BIT_EP_RX_PKT, (void *)TOPAZ_LH_IPC4_INT_MASK);
}

/* Tx done interrupt API */
static inline void vmac_ipc_intr_txdone_en(void)
{
	set_bit(IPC_BIT_RC_RX_DONE, (void *)TOPAZ_LH_IPC4_INT_MASK);
}
static inline void vmac_ipc_intr_txdone_dis(void)
{
	clear_bit(IPC_BIT_RC_RX_DONE, (void *)TOPAZ_LH_IPC4_INT_MASK);
}
/* Reset EP and PM interrupts  */
static inline void vmac_ipc_intr_reset_pm_en(void)
{
	uint32_t ipc_int_mask = readl(TOPAZ_LH_IPC4_INT_MASK);
	ipc_int_mask |= (IPC_RESET_EP | IPC_EP_PM_CTRL);
	writel(ipc_int_mask, TOPAZ_LH_IPC4_INT_MASK);
}
static inline void vmac_ipc_intr_reset_pm_dis(void)
{
	uint32_t ipc_int_mask = readl(TOPAZ_LH_IPC4_INT_MASK);
	ipc_int_mask &= ~(IPC_RESET_EP | IPC_EP_PM_CTRL);
	writel(ipc_int_mask, TOPAZ_LH_IPC4_INT_MASK);
}
/* offline dump event interrupts  */
static inline void vmac_ipc_intr_offline_dump_en(void)
{
	set_bit(IPC_BIT_OFFLINE_DBG, (void *)TOPAZ_LH_IPC4_INT_MASK);
}
static inline void vmac_ipc_intr_offline_dump_dis(void)
{
	clear_bit(IPC_BIT_OFFLINE_DBG, (void *)TOPAZ_LH_IPC4_INT_MASK);
}
void inline vmac_ipc_clr_txdone_irq(void)
{
	uint32_t ipcstat;
	ipcstat = readl(TOPAZ_LH_IPC4_INT) & IPC_RC_RX_DONE;
	if (ipcstat)
		writel(ipcstat << 16, TOPAZ_LH_IPC4_INT);
}

static inline void vmac_dma_intr_en(void)
{
	__set_bit(12, (void *)RUBY_SYS_CTL_PCIE_INT_MASK);
}
static inline void vmac_dma_intr_dis(void)
{
	__clear_bit(12, (void *)RUBY_SYS_CTL_PCIE_INT_MASK);
}

static __attribute__((section(".sram.pcierx.text"))) int vmac_rdma_poll(struct napi_struct *napi, int budget)
{
	struct vmac_priv *vmp = container_of(napi, struct vmac_priv, rdma_napi);
	uint32_t src;
	uint32_t len;
	uint32_t dst;
	uint32_t dmaoff;
	uint32_t i;
	struct pcie_dma_ll_data *ptd;
	struct pcie_dma_ll_desc *ptp;
	struct vmac_pkt_info *pkt_info;
	int processed = 0;
	uint32_t flags;
	uint32_t src_align;
	uint8_t hbm_alloc_fail = 0;

	vmp->rx_dma_funcs++;
	i = vmp->rx_toDMA_e;
	while (processed < budget) {
		vmp->rx_dma_while++;

		/* EP is congested      */
		if (vmp->rx_occupy_len >= vmp->rx_congest_thresh) {
			vmp->rx_queue_full = 1;
			vmp->rx_queue_max++;
			break;
		}

		/* Slow RC              */
		pkt_info = vmp->request_queue + i;
		if (!(pkt_info->info & PCIE_TX_VALID_PKT)) {
			vmp->rx_slow_rc++;
			break;
		}

		dst = (uint32_t)topaz_hbm_get_payload_bus(TOPAZ_HBM_BUF_EMAC_RX_POOL);
		if (!dst) {
			vmp->rx_hbm_alloc_fail++;
			hbm_alloc_fail = 1;
			break;
		}
		src = pkt_info->addr;
		src_align = vmp->eDMA_src_align;
		dmaoff = align_down_off(src, src_align) +
				align_up_off(dst, TOPAZ_BOUNDARY_128);
		len = pkt_info->info & PCIE_PKT_LEN_MASK;

		vmp->rx_buf[i].baddr = dst;
		vmp->rx_buf[i].offset = dmaoff;
		vmp->rx_buf[i].len = len;

		ptd = &vmp->rx_dmapt_va[i];
		ptd->ll_trans_size = align_val_up(len + align_down_off(src, src_align),
						TOPAZ_BOUNDARY_64);
		ptd->ll_sar_low = RC2EP_MMAP(align_val_down(src, src_align));
		ptd->ll_dar_low = align_val_up(dst, TOPAZ_BOUNDARY_128);

		local_irq_save(flags);

		if (vmp->rx_queue_len % vmp->rx_intr_pktnr == 0)
			ptd->data_info = vmp->rx_DMA_ctrl | DMA_LL_DATA_LIE;
		else
			ptd->data_info = vmp->rx_DMA_ctrl;

		vmp->rx_last_ptd = ptd;

		if (++i >= vmp->rx_bd_num) {
			ptp = (struct pcie_dma_ll_desc *)(ptd + 1);
			ptp->desc_info = (vmp->rx_DMA_ctrl & DMA_LL_DATA_CB)
					| DMA_LL_DESC_LLP;
			i = 0;
		}
		vmp->rx_queue_len++;
		vmp->rx_toDMA_e = i;
		vmp->rx_occupy_len++;

		local_irq_restore(flags);

		processed++;
	}

	local_irq_save(flags);
	if (vmp->rx_queue_len > 0) {
		barrier();
		if (pcie_rDMA_ready(vmp)) {
			pcie_rDMA_trigger(vmp);
#ifdef VMAC_DDMA_CHANNEL
			uint32_t rdma_ch = vmp->rx_channel_index;
			vmp->rx_channel_index = ++rdma_ch >= vmp->rx_channel_num ? 0 : rdma_ch;
#endif
			vmp->rdma_softirq_trig++;
		} else {
			vmp->rdma_busy_cnt++;
		}
	}
	local_irq_restore(flags);

	if (processed < budget && !hbm_alloc_fail) {
		napi_complete(napi);

		if (vmp->rx_queue_full != 1)
			vmac_ipc_intr_rx_en();
	}

	return processed;
}

static inline int vmac_rx_should_accel(struct vmac_priv *vmp, const void *vdata, uint16_t len)
{
	const struct ethhdr *eth = vdata;
	const uint16_t *ether_type = &eth->h_proto;
	const struct iphdr *ipv4h;
	const struct ipv6hdr *ipv6h;
	const struct udphdr *udph;
	const struct icmp6hdr *icmph;
	uint8_t nexthdr;
	uint16_t eth_hdrlen = sizeof(struct ethhdr);
	int nhdr_off;

	if (*ether_type == __constant_htons(ETH_P_8021Q)) {
		vmp->dcache_dirty_sz += sizeof(struct vlan_hdr);
		eth_hdrlen += 4;
		ether_type += 2;
	}

	/* coverity[overrun-local] */
	if (unlikely(*ether_type == __constant_htons(ETH_P_ARP)))
		return 0;

	/* IPv4 DHCP to Lhost */
	if (*ether_type == __constant_htons(ETH_P_IP)) {
		ipv4h = (const struct iphdr *)(ether_type + 1);
		vmp->dcache_dirty_sz += sizeof(struct iphdr);
		if (ipv4h->protocol == IPPROTO_UDP) {
			udph = (const struct udphdr *)((uint8_t *)ipv4h + (ipv4h->ihl << 2));
			vmp->dcache_dirty_sz += (ipv4h->ihl << 2) - sizeof(struct iphdr);
			if (udph->dest == __constant_htons(DHCPCLIENT_PORT)
					|| udph->dest == __constant_htons(DHCPSERVER_PORT)) {
				return 0;
			}
		}
	}
#ifdef CONFIG_IPV6
	else if (*ether_type == __constant_htons(ETH_P_IPV6)) {
		ipv6h = (const struct ipv6hdr *)(ether_type + 1);

		nhdr_off = iputil_v6_skip_exthdr(ipv6h, sizeof(struct ipv6hdr),
				&nexthdr, (int)(len - eth_hdrlen), NULL, NULL);
		vmp->dcache_dirty_sz += nhdr_off;

		if (nexthdr == IPPROTO_UDP) {
			udph = (const struct udphdr *)((const uint8_t *)ipv6h + nhdr_off);
			vmp->dcache_dirty_sz += 4;
			if (udph->dest == __constant_htons(DHCPV6CLIENT_PORT)
					|| udph->dest == __constant_htons(DHCPV6SERVER_PORT))
				return 0;
		} else if (nexthdr == IPPROTO_ICMPV6) {
			icmph = (const struct icmp6hdr *)((const uint8_t *)ipv6h + nhdr_off);
			vmp->dcache_dirty_sz += 1;
			if (icmph->icmp6_type == NDISC_NEIGHBOUR_SOLICITATION
					|| icmph->icmp6_type == NDISC_NEIGHBOUR_ADVERTISEMENT)
				return 0;
		}
	}
#endif

	return 1;
}

static inline
void vmac_rx_init_tqe_desc(union topaz_tqe_cpuif_descr *desc, void *bdata, uint16_t len)
{
	int8_t pool = topaz_hbm_payload_get_pool_bus(bdata);

	memset(desc, 0, sizeof(*desc));
	desc->data.buff_ptr_offset = topaz_hbm_payload_buff_ptr_offset_bus(bdata, pool, NULL);
	desc->data.length = len;
	desc->data.in_port = TOPAZ_TQE_PCIE_REL_PORT;
	desc->data.pkt = bdata;
}

static noinline void vmac_rx_lookup_miss(struct vmac_priv *vmp, void *vdata, uint16_t len, void *bdata)
{
	union topaz_tqe_cpuif_descr desc;
	struct sk_buff *skb;

	skb = topaz_hbm_attach_skb(vdata, TOPAZ_HBM_BUF_EMAC_RX_POOL,
					vlan_enabled ? QVLAN_PKTCTRL_LEN : 0);
	if (likely(skb)) {
		skb_put(skb, len);

		vmac_rx_init_tqe_desc(&desc, bdata, len);
		if (tqe_rx_l2_ext_filter(&desc, skb)) {
			tqe_rx_call_port_handler(&desc, skb, NULL);
			return;
		}

		skb->protocol = eth_type_trans(skb, vmp->ndev);
		skb->src_port = 0;
		if (vlan_enabled) {
			struct qtn_vlan_pkt *pkt = qtn_vlan_get_info(skb->data);
			skb->vlan_tci = pkt->vlan_info & QVLAN_MASK_VID;
			M_FLAG_SET(skb, M_VLAN_TAGGED);

			skb = switch_vlan_to_proto_stack(skb);
			if (!skb)
				return;
		}
		netif_receive_skb(skb);
	} else {
		printk(KERN_ERR"Failed to attach skb\n");
		topaz_hbm_put_buf(topaz_hbm_payload_store_align_bus((void *)bdata, TOPAZ_HBM_BUF_EMAC_RX_POOL, 0),
			TOPAZ_HBM_BUF_EMAC_RX_POOL);
	}
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

static noinline int vmac_rx_multicast(struct vmac_priv *vmp, const struct ethhdr *eth,
	void *bdata, uint16_t len)
{
	union topaz_tqe_cpuif_descr desc;
	const uint16_t *ether_type;

	vmac_rx_init_tqe_desc(&desc, bdata, len);

	ether_type = vmac_rx_find_ether_type(eth, len);
	if (unlikely(!ether_type))
		return 0;

	return tqe_rx_multicast(vmp->congest_queue, &desc, ether_type, 1);
}

static inline struct qtn_vlan_dev *tqe_get_vlandev(uint8_t port, uint8_t node)
{
	if (TOPAZ_TQE_PORT_IS_WIRED(port))
		return vport_tbl_lhost[port];
	else
		return switch_vlan_dev_from_node(node);
}

static __attribute__((section(".sram.pcierx.text"))) void
vmac_rx_forward(struct vmac_priv *vmp, void *bdata, void *bbase, uint16_t len, void *vdata)
{
	const struct ethhdr *eth;
	struct topaz_congest_q_desc *queue;
	union topaz_tqe_cpuif_ppctl pp_cntl;
	fwt_db_entry *fwt_ent;
	struct qtn_vlan_dev *vdev;
	int ret;
	int re_sched;
	uint8_t tid;
	uint16_t vlan_miscuser = 0;

	eth = vdata;
	vmp->dcache_dirty_sz = ETH_HLEN;

	if (vlan_enabled) {
		vmp->dcache_dirty_sz += sizeof(struct vlan_hdr);
		vdev = vport_tbl_lhost[TOPAZ_TQE_PCIE_REL_PORT];
		if (qtn_vlan_should_drop_stag(vdev, vdata, vlan_drop_stag))
			goto inv_drop;
		if (!qtn_vlan_ingress(vdev, 0, vdata, 0, 0, 1)) {
			goto inv_drop;
		}
	}

	if (is_multicast_ether_addr(eth->h_dest)) {
		if (vmac_rx_multicast(vmp, eth, bdata, len) > 0)
			return;
	} else if (vmac_rx_should_accel(vmp, vdata, len)) {
		fwt_ent = fwt_sw_fast_get_ucast_entry(eth->h_source, eth->h_dest);
		if (likely(fwt_ent)) {
			/* Discard the packet if the source and destination port are same to avoid reflection */
			if (unlikely(fwt_ent->out_port == TOPAZ_TQE_PCIE_REL_PORT))
				goto inv_drop;

			if (vlan_enabled) {
				vdev = tqe_get_vlandev(fwt_ent->out_port, fwt_ent->out_node);
				if (unlikely(!vdev))
					goto inv_drop;

				if (!qtn_vlan_egress(vdev, fwt_ent->out_node, vdata,
						TOPAZ_TQE_PORT_IS_WMAC(vdev->port)
						? &vlan_miscuser : 0, 1))
					goto inv_drop;
			}

			tid = topaz_tqe_vlan_gettid(bus_to_virt((uintptr_t)bdata));
			topaz_pcie_prepare_pp_cntl(&pp_cntl, tid, fwt_ent, bdata, len,
				vlan_miscuser);

			inv_dcache_range((unsigned long)vdata, (unsigned long)(vdata + vmp->dcache_dirty_sz));
			if (topaz_queue_congested(vmp->congest_queue, fwt_ent->out_node, tid)) {
				queue = topaz_get_congest_queue(vmp->congest_queue, fwt_ent->out_node, tid);
				ret = topaz_congest_enqueue(queue, &pp_cntl);

				if (ret == NET_XMIT_CN) {
					topaz_hbm_put_buf(bbase, TOPAZ_HBM_BUF_EMAC_RX_POOL);
					vmp->rx_pcie_drop++;
				}

				/* Try to transmit at most vmp->rx_congsirq_budget packets in the congestion queue */
				re_sched = topaz_congest_queue_xmit(queue, vmp->rx_congsirq_budget);
				if (re_sched == 1)
					tasklet_schedule(&vmp->congest_queue->congest_tx);
			} else {
				ret = topaz_pcie_tqe_xmit(&pp_cntl);

				if (ret == NET_XMIT_SUCCESS) {
					vmp->rx_tqe_fwd++;
				} else if (ret == NET_XMIT_CN) {
					queue = topaz_congest_alloc_queue(vmp->congest_queue, fwt_ent->out_node, tid);
					if (queue == NULL) {
						goto drop;
					} else {
						ret = topaz_congest_enqueue(queue, &pp_cntl);
						if (ret == NET_XMIT_CN) {
							goto drop;
						} else {
							tasklet_schedule(&vmp->congest_queue->congest_tx);
						}
					}
				} else {
					goto drop;
				}
			}

			return;
		} else {
			vmp->fwt_loss_cnt++;
		}
	}

	vmac_rx_lookup_miss(vmp, vdata, len, bdata);
	return;

inv_drop:
	inv_dcache_range((unsigned long)vdata, (unsigned long)(vdata + vmp->dcache_dirty_sz));
drop:
	topaz_hbm_put_buf(bbase, TOPAZ_HBM_BUF_EMAC_RX_POOL);
	vmp->rx_pcie_drop++;
}

static inline void vmac_check_rc_txqueue(struct vmac_priv *vmp)
{
	if (vmp->rc_txqueue_stopped) {
		if (++vmp->rc_txbd_avail_cnt > vmp->rc_txbd_wake_th) {
			*vmp->rc_txqueue_wake = 1;
			barrier();

			vmac_intr_rc(vmp);
			vmp->rc_txqueue_stopped = 0;
		}
	} else {
		uint32_t ipcstat;
		ipcstat = readl(TOPAZ_LH_IPC4_INT) & IPC_RC_STOP_TX;
		if(ipcstat) {
			writel(ipcstat << 16, TOPAZ_LH_IPC4_INT);
			vmp->rc_txqueue_stopped = 1;
			vmp->rc_txbd_avail_cnt = 0;
		}
	}
}

static noinline void vmac_rx_netlink(struct net_device *ndev, uint32_t vdata, uint32_t baddr, uint16_t len)
{
	qdpc_cmd_hdr_t *cmd_hdr;

	/* Double Check if it's netlink packet*/
	cmd_hdr = (qdpc_cmd_hdr_t *)vdata;
	if (check_netlink_magic(cmd_hdr)) {
		vmac_netlink_rx(ndev,
			(uint8_t*)cmd_hdr + sizeof(qdpc_cmd_hdr_t),
			ntohs(cmd_hdr->len),
			ntohs(cmd_hdr->rpc_type),
			ntohs(cmd_hdr->total_len));
	}
	inv_dcache_range((unsigned long)vdata, (unsigned long)vdata + len);
	topaz_hbm_put_buf((void *)baddr, TOPAZ_HBM_BUF_EMAC_RX_POOL);
}

static __attribute__((section(".sram.pcierx.text"))) int vmac_rx_poll(struct napi_struct *napi, int budget)
{
	struct vmac_priv *vmp = container_of(napi, struct vmac_priv, rx_napi);
	struct net_device *ndev = vmp->ndev;
	struct ethhdr *eth;
	int processed = 0;
	uint32_t i;
	uint32_t baddr;
	uint32_t vdata;
	uint32_t bdata;
	uint32_t len;
	struct vmac_pkt_info *pkt_info;
	uint32_t flags;

	vmp->rx_napi_func++;
	i = vmp->rx_pkt_index;

	while (processed < budget) {
		vmp->rx_napi_poll++;

		/* If packet is not DMA finished */
		if (i == vmp->rx_DMAing) {
			vmp->rx_dma_busy++;
			break;
		}

		/* Clear info of entry in the request queue */
		pkt_info = vmp->request_queue + i;
		arc_write_uncached_32(&pkt_info->info, 0);

		baddr = vmp->rx_buf[i].baddr;
		len = vmp->rx_buf[i].len;

		bdata = baddr + vmp->rx_buf[i].offset;
		vdata = (uint32_t)bus_to_virt(baddr) + vmp->rx_buf[i].offset;

		dump_rx_bd(vmp);
		dump_rx_buf(vmp, bdata, len);
		eth = (struct ethhdr *)(vdata);
		vmp->dcache_dirty_sz = ETH_HLEN;

		if (unlikely(ntohs(eth->h_proto) == QDPC_APP_NETLINK_TYPE)) {
			vmac_rx_netlink(ndev, vdata, baddr, len);
		} else {
			vmac_rx_forward(vmp, (void *) bdata, (void *) baddr, len, (void *) vdata);

			ndev->stats.rx_packets++;
			ndev->stats.rx_bytes += len;
		}

		ndev->last_rx = jiffies;

		VMAC_INDX_INC(i, vmp->rx_bd_num);
		vmp->rx_pkt_index = i;

		processed++;
		vmac_check_rc_txqueue(vmp);
	}

	if (processed > 0) {
		/* Update index in RC's memory */
		arc_write_uncached_32(vmp->next_rx_pkt, vmp->rx_pkt_index);
		vmp->rx_occupy_len -= processed;

		/* Notify RC about buffer reclaim possibility */
		if (tx_done_en)
			vmac_intr_rc(vmp);

		if (vmp->rx_queue_full == 1) {
			vmp->rx_queue_full = 0;
			napi_schedule(&vmp->rdma_napi);
		}
	}

	local_irq_save(flags);

	/* When processed < budget, vmp->rx_DMAing may not equal vmp->rx_pkt_index.
	* This situation will occur when a rDMA done ISR is executed between poll() while loop
	* and the following if() check.
	*/
	if (processed < budget && vmp->rx_DMAing == vmp->rx_pkt_index)
		napi_complete(napi);

	local_irq_restore(flags);

	return processed;

}

extern void topaz_hbm_filter_txdone_buf(void *const buf_bus);
void __attribute__((section(".sram.pcietx.text")))
vmac_tx_free_payload(void *bus_addr)
{
	const int8_t dest_pool = topaz_hbm_payload_get_pool_bus(bus_addr);
	void *buf_bus = topaz_hbm_payload_store_align_bus(bus_addr, dest_pool, 0);

	topaz_hbm_filter_txdone_buf(buf_bus);

}

void inline vmac_try_wake_tx(struct vmac_priv *vmp, int bit)
{
	__clear_bit(bit, (void *)&vmp->txqueue_stopped);
	if (!vmp->txqueue_stopped) {
		if (vmp->tqe_flag == TQE_ENABLE_INTR)
			vmp->tqe_irq_enable();
		else if (vmp->tqe_flag == TQE_NAPI_SCHED)
			napi_schedule(vmp->tqe_napi);
		vmp->tqe_flag = 0;
		netif_wake_queue(vmp->ndev);
	}
}

static netdev_tx_t vmac_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	int ret;
	struct sk_buff *skb2 = skb;

	if (vlan_enabled) {
		struct qtn_vlan_dev *vdev = vport_tbl_lhost[TOPAZ_TQE_PCIE_REL_PORT];

		skb2 = switch_vlan_from_proto_stack(skb, vdev, 0);
		if (!skb2) {
			ndev->stats.tx_dropped++;
			return NETDEV_TX_OK;
		}
	}

	ret = vmac_tx(skb2, ndev, PKT_SKB);

	/* FIXME: VLAN needs a rework not to copy the skb, before that we free it if failed */
	if (unlikely(ret == NETDEV_TX_BUSY && skb2 != skb)) {
		dev_kfree_skb(skb2);
		ndev->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}

	return ret;
}

netdev_tx_t __attribute__((section(".sram.pcietx.text")))
vmac_tx(void *pkt_handle, struct net_device *ndev, enum pkt_type pkt_type)
{
	struct vmac_priv *vmp = netdev_priv(ndev);
	volatile struct vmac_bd *rcrxbd; /* Tx BD pointer */
	uint32_t descw1;
	uint32_t dst;/* DMA dst address */
	uint32_t src;
	int len;
	uint32_t dmaoff;/* offset of buffer */
	uint16_t i; /* tbd index */
	struct pcie_dma_ll_data *ptd;
	struct pcie_dma_ll_desc *ptp;
	netdev_tx_t ret = NETDEV_TX_OK;
	uint32_t flags;
	uint32_t tx_dma_ctrl;
	uint32_t src_align;
	uint8_t *pkt_data;

	vmp->vmac_tx_entries++;

	dump_tx_bd(vmp);

	i = vmp->tx_toDMA_e;

	/* Release transmitted packet previously */
	if (vmp->tx_buf[i].handle) {
		if (vmp->tx_buf[i].type == PKT_TQE)
			vmac_tx_free_payload((void *)vmp->tx_buf[i].handle);
		else if (vmp->tx_buf[i].type == PKT_SKB)
			dev_kfree_skb((struct sk_buff *)vmp->tx_buf[i].handle);
		vmp->tx_buf[i].handle = 0;
	}

	local_irq_save(flags);
	if (vmp->tx_queue_len >= vmp->tx_congest_thresh) {
		netif_stop_queue(ndev);
		__set_bit(BIT_DMA_BUSY, (void *)&vmp->txqueue_stopped);
		vmp->tx_ll_full++;
		if (unlikely(vmp->tx_queue_len >= vmp->tx_congest_thresh + 1)) {
			ret = NETDEV_TX_BUSY;
			local_irq_restore(flags);
			printk(KERN_WARNING "wdma is congested\n");
			goto exit;
		}
	}
	local_irq_restore(flags);

	rcrxbd = &vmp->rc_rx_bd_base[i];
	if (!(vmp->cur_rc_bd_info & VMAC_BD_EMPTY)) {
		if (unlikely(!(arc_read_uncached_32(&rcrxbd->buff_info) & VMAC_BD_EMPTY))) {
			ret = NETDEV_TX_BUSY;
			printk(KERN_WARNING "RC is slow\n");
			goto rc_is_slow;
		}
	}

	if (pkt_type == PKT_SKB) {
		struct sk_buff *skb = (struct sk_buff *)pkt_handle;

		if (frames_meta_info) {
			struct hbm_buf_frame_meta_info *meta;

			if (!M_FLAG_ISSET(skb, M_HAS_RADIO_INFO)) {
				pr_warning_ratelimited("%s: no meta info; proto=0x%x\n",
						       __func__, ntohs(skb->protocol));
				dev_kfree_skb(skb);
				ndev->stats.tx_dropped++;
				return NETDEV_TX_OK;
			}

			if ((skb_tailroom(skb) < sizeof(*meta)) &&
			     pskb_expand_head(skb, 0, sizeof(*meta), GFP_ATOMIC)) {
				pr_warning_ratelimited("%s: can't expand SKB len=%u\n",
						       __func__, skb->len);
				dev_kfree_skb(skb);
				ndev->stats.tx_dropped++;
				return NETDEV_TX_OK;
			}

			meta = (struct hbm_buf_frame_meta_info *)(skb_tail_pointer(skb));
			meta->magic_s = HBM_FRAME_META_MAGIC_PATTERN_S;
			meta->magic_e = HBM_FRAME_META_MAGIC_PATTERN_E;
			meta->macid = skb->qtn_cb.radio_info.macid;
			meta->ifidx = skb->qtn_cb.radio_info.ifidx;
			skb_put(skb, sizeof(*meta));
		}

		vmp->tx_buf[i].type = PKT_SKB;
		len = skb->len;
		src = (uint32_t)cache_op_before_tx(align_buf_cache(skb->head),
			align_buf_cache_size(skb->head, skb_headroom(skb) + len)) +
			align_buf_cache_offset(skb->head) + skb_headroom(skb);
		pkt_data = skb->data;
		skb->cache_is_cleaned = 1;
		vmp->tx_buf[i].handle = (uint32_t)skb;
	} else {
		union topaz_tqe_pcieif_descr *tqe_desc
			 = (union topaz_tqe_pcieif_descr *)pkt_handle;
		src = (uint32_t)tqe_desc->data.pkt;
		pkt_data = bus_to_virt(src);
		len = tqe_desc->data.length;
		vmp->tx_buf[i].type = PKT_TQE;
		vmp->tx_buf[i].handle = src;
	}

	if (unlikely(len > TOPAZ_PCIE_TX_PKT_LEN_MAX)) {
		if (vmp->tx_buf[i].handle) {
			if (vmp->tx_buf[i].type == PKT_TQE)
				vmac_tx_free_payload((void *)vmp->tx_buf[i].handle);
			else if (vmp->tx_buf[i].type == PKT_SKB)
				dev_kfree_skb((struct sk_buff *)vmp->tx_buf[i].handle);
			vmp->tx_buf[i].handle = 0;
		}
		ndev->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}

	dump_tx_buf(vmp, src, len);

	dst = arc_read_uncached_32(&rcrxbd->buff_addr);
	src_align = vmp->eDMA_src_align;
	dmaoff =  align_up_off(dst, TOPAZ_BOUNDARY_128) +
			align_down_off(src, src_align);

	descw1 = VMAC_SET_LEN(len) | VMAC_SET_OFFSET(dmaoff);
	if (vmp->tx_bd_num - i == 1)
		descw1 |=  VMAC_BD_WRAP;

	vmp->tx_flag_va[i] = descw1;

	ptd = &vmp->tx_dmapt_va[2 * i];
	ptd->ll_trans_size = align_val_up(len + align_down_off(src, src_align),
				TOPAZ_BOUNDARY_64);
	ptd->ll_sar_low = align_val_down(src, src_align);
	ptd->ll_dar_low = RC2EP_MMAP(align_val_up(dst, TOPAZ_BOUNDARY_128));

	local_irq_save(flags);
	ptd->data_info = (uint32_t)vmp->tx_DMA_ctrl;
	ptd++;
	tx_dma_ctrl = (uint32_t)vmp->tx_DMA_ctrl;
	if (++vmp->tx_intr_rc_i >= vmp->tx_intr_rc_th) {
		if (vmp->msi_enabled)
			tx_dma_ctrl |= DMA_LL_DATA_RIE;
		else
			tx_dma_ctrl |= DMA_LL_DATA_LIE;
		vmp->tx_intr_rc_i = 0;
	}
	ptd->data_info = tx_dma_ctrl;

	vmp->tx_last_ptd = ptd;

	vmp->tx_queue_len++;

	if (++i >= vmp->tx_bd_num) {
		ptp = (struct pcie_dma_ll_desc *)(ptd + 1);
		ptp->desc_info = (uint32_t)(vmp->tx_DMA_ctrl & DMA_LL_DATA_CB)
					| DMA_LL_DESC_LLP;
		i = 0;
	}
	vmp->tx_toDMA_e = i;

	local_irq_restore(flags);

	ndev->stats.tx_packets++;
	ndev->stats.tx_bytes += len;

	ret = NETDEV_TX_OK;

	rcrxbd = &vmp->rc_rx_bd_base[i];
	vmp->cur_rc_bd_info = arc_read_uncached_32(&rcrxbd->buff_info);
	if (vmp->cur_rc_bd_info & VMAC_BD_EMPTY)
		goto trigger_pcie_wdma;

rc_is_slow:
	netif_stop_queue(ndev);
	vmac_ipc_clr_txdone_irq();
	set_bit(BIT_RC_BUSY, (void *)&vmp->txqueue_stopped);
	vmac_ipc_intr_txdone_en();
	vmp->tx_rc_bd_busy++;

trigger_pcie_wdma:
	local_irq_save(flags);
	if (vmp->tx_queue_len != 0) {
		if (pcie_wDMA_ready(vmp)) {
			pcie_wDMA_trigger(vmp);
			vmac_try_wake_tx(vmp, BIT_DMA_BUSY);
			vmp->wdma_softirq_trig++;
		} else {
			vmp->wdma_busy_cnt++;
		}
	}
	local_irq_restore(flags);

	ndev->trans_start = jiffies;

exit:
	return ret;
}

static irqreturn_t __attribute__((section(".sram.pcierx.text"))) vmac_ipc_isr(int irq, void *dev_id)
{
	struct net_device *ndev = dev_id;
	struct vmac_priv *vmp = netdev_priv(ndev);
	uint32_t ipcstat;

	ipcstat = readl(TOPAZ_LH_IPC4_INT) & readl(TOPAZ_LH_IPC4_INT_MASK);

	if (ipcstat) {
		writel(ipcstat << 16, TOPAZ_LH_IPC4_INT);
		if (ipcstat & IPC_RESET_EP) {
			netif_stop_queue(ndev);
			schedule_work(&rc_rmmod_work);
			return IRQ_HANDLED;
		}

		if(ipcstat & IPC_EP_RX_PKT) {
			vmac_ipc_intr_rx_dis();
			napi_schedule(&vmp->rdma_napi);
		}

		if (ipcstat & IPC_RC_RX_DONE) {
			vmac_ipc_intr_txdone_dis();
			vmac_try_wake_tx(vmp, BIT_RC_BUSY);
		}

		if(unlikely(ipcstat & IPC_EP_PM_CTRL)) {
			if (le32_to_cpu(*vmp->ep_pmstate) == PCI_D3hot) {
				netif_device_detach(ndev);
				vmac_pcie_ep_suspend();
			} else if (le32_to_cpu(*vmp->ep_pmstate) == PCI_D0) {
				vmac_pcie_ep_resume();
				netif_device_attach(ndev);
			}
		}

		if(unlikely(ipcstat & IPC_OFFLINE_DBG)) {
			vmac_wps_button_event_notifier(WPS_BUTTON_DBGDUMP_EVENT);
		}

		vmp->ipc_cnt++;
	}


	return IRQ_HANDLED;
}

/* Return the index of element to be DMAed */
inline __attribute__((section(".sram.pcierx.text"))) uint32_t vmac_get_DMAing_idx(struct vmac_priv *vmp)
{
	struct pcie_dma_ll_data *ptr;
	uint32_t ret;
	uint32_t rdma_ch = vmp->rx_channel_index;

	topaz_ep_pcie_writel(DmaChDirRd | rdma_ch, PCIE_DMA_CH_CTXT_IDX);
	ptr = (struct pcie_dma_ll_data *)topaz_ep_pcie_readl(PCIE_DMA_LL_PTR_LOW);
	ret = ptr - vmp->rx_dmapt_ba;

	BUG_ON(ret > vmp->rx_bd_num);

	if (unlikely(ret == vmp->rx_bd_num))
		ret = 0;
	return ret;
}

static irqreturn_t __attribute__((section(".sram.pcierx.text"))) vmac_interrupt(int irq, void *dev_id)
{
	struct vmac_priv *vmp = (struct vmac_priv *)dev_id;
	uint32_t rdma_stat;
	uint32_t rdma_done_stat;
	uint32_t wdma_stat;
	struct vmac_pkt_info *pkt_info;

	rdma_stat = topaz_ep_pcie_readl(PCIE_DMA_RD_INTR_STATUS);
	wdma_stat = topaz_ep_pcie_readl(PCIE_DMA_WR_INTR_STATUS);
	if (rdma_stat) {
		if (rdma_stat & vmp->rx_dma_abort_mask)
			pcie_dma_rd_aie_handle(vmp);

		rdma_done_stat = rdma_stat & vmp->rx_dma_done_mask;
		if (rdma_done_stat) {
			topaz_ep_pcie_writel(rdma_done_stat, PCIE_DMA_RD_INTR_CLR);

			vmp->rdma_dn_cnt++;

			/* Schedule rDMA napi if there are more packets to handle */
			pkt_info = vmp->request_queue + vmp->rx_toDMA_e;
			if ((vmp->rx_occupy_len < vmp->rx_congest_thresh) && (pkt_info->info & PCIE_TX_VALID_PKT))
				napi_schedule(&vmp->rdma_napi);

			/* Notify rx napi to handle a new packet */
			napi_schedule(&vmp->rx_napi);

			/* Trigger rDMA if there is pending request
			* Note that: If pcie_rDMA_ready_no_lock(vmp) is called at the beggining
			* of ISR, it will likely get RESERVED DMA channel status. Even we delayed
			* calling the function here, sometimes it can still return RESERVED status.
			*
			* RESERVED status is uncertain but seems no harm currently. However, we'd
			* better avoid this status.
			*/
			if (vmp->rx_queue_len > 0 && pcie_rDMA_ready_no_lock(vmp)) {
				vmp->rx_DMAing = vmp->rx_toDMA_s;
				pcie_rDMA_trigger(vmp);
				vmp->rdma_intr_trig++;
			} else {
				vmp->rx_DMAing = vmac_get_DMAing_idx(vmp);
			}
		}
	}

	if (wdma_stat) {
		topaz_ep_pcie_writel(wdma_stat, PCIE_DMA_WR_INTR_CLR);

		if (wdma_stat & vmp->tx_dma_done_mask) {
			if (vmp->msi_enabled || pcie_wDMA_ready_raw(vmp)) {
				if (vmp->tx_queue_len != 0) {
					pcie_wDMA_trigger(vmp);
					vmac_try_wake_tx(vmp, BIT_DMA_BUSY);
					vmp->wdma_intr_trig++;
				} else {
					atomic_set(&vmp->wdma_running, 0);
					vmp->wdma_done_idle++;
					if (topaz_ep_pcie_readl(PCIE_DMA_RD_DONE_IMWR_ADDR_LOW) ==
							vmp->msi_addr)
						vmac_intr_rc(vmp);
					vmp->tx_intr_rc_i = 0;
				}
				vmp->wdma_done_cnt++;
			} else if (topaz_ep_pcie_readl(PCIE_DMA_RD_DONE_IMWR_ADDR_LOW) ==
						vmp->msi_addr) {
					qdpc_assert_intx();
			}

		} else if (wdma_stat & vmp->tx_dma_abort_mask) {
			pcie_dma_wr_aie_handle(vmp);
		}
	}

	return IRQ_HANDLED;
}

/*
 * The Tx ring has been full longer than the watchdog timeout
 * value. The transmitter must be hung?
 */
inline static void vmac_tx_timeout(struct net_device *ndev)
{
	ndev->trans_start = jiffies;
}

extern void pcie_notify_rc_rdy(struct net_device *ndev);

static int __init vmac_init_module(void)
{
	struct net_device* ndev;
	struct vmac_priv *vmp;

	if ((ndev = vmac_net_init(NULL)) == NULL)
		return -1;

	pcie_dma_dev_init(ndev);

	pcie_notify_rc_rdy(ndev);

	vmp = netdev_priv(ndev);
	if (!(tqe_pcie_netdev_init(ndev)))
		return -1;

	/*
	 * To use the function profiler, CONFIG_FUNC_PROFILER_STATS needs to
	 * be enabled in include/linux/func_stat.h of kernel.
	 */
#ifdef CONFIG_FUNC_PROFILER_STATS
	create_proc_read_entry("func_profiler", 0444, NULL, func_pf_get_stats, NULL);
#endif /* CONFIG_FUNC_PROFILER_STATS */

	vmac_wps_button_device_file_create(ndev);

	return 0;
}

/* ethtools support */
static int vmac_get_settings(struct net_device *ndev, struct ethtool_cmd *cmd)
{
	return -EINVAL;
}

static int vmac_set_settings(struct net_device *ndev, struct ethtool_cmd *cmd)
{

	if (!capable(CAP_NET_ADMIN)) {
		return -EPERM;
	}

	return -EINVAL;
}

static int vmac_ioctl(struct net_device *ndev, struct ifreq *rq, int cmd)
{
	return -EINVAL;
}

static void vmac_get_drvinfo(struct net_device *ndev, struct ethtool_drvinfo *info)
{
	struct vmac_priv *vmp = netdev_priv(ndev);

	strcpy(info->driver, DRV_NAME);
	strcpy(info->version, DRV_VERSION);
	info->fw_version[0] = '\0';
	sprintf(info->bus_info, "%s %d", DRV_NAME, vmp->mac_id);
	info->regdump_len = 0;
}

static const struct ethtool_ops vmac_ethtool_ops = {
	.get_settings = vmac_get_settings,
	.set_settings = vmac_set_settings,
	.get_drvinfo = vmac_get_drvinfo,
	.get_link = ethtool_op_get_link,
};

static const struct net_device_ops vmac_device_ops = {
	.ndo_open = vmac_open,
	.ndo_stop = vmac_close,
	.ndo_start_xmit = vmac_xmit,
	.ndo_change_mtu = vmac_change_mtu,
	.ndo_do_ioctl = vmac_ioctl,
	.ndo_tx_timeout = vmac_tx_timeout,
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_get_stats = vmac_get_stats,
};

#define VMAC_MTU_MAX	\
	(min((uint32_t)NPU_MAX_BUF_SIZE, \
		topaz_hbm_pool_buf_max_size(TOPAZ_HBM_BUF_EMAC_RX_POOL)) \
	- TOPAZ_HBM_PAYLOAD_HEADROOM)
/*
 * @ndev: network interface device structure
 * @new_mtu: new value for new MTU size
 */
static int vmac_change_mtu(struct net_device *ndev, int new_mtu)
{
	if (new_mtu < ETH_ZLEN || new_mtu > VMAC_MTU_MAX) {
		printk(KERN_ERR "[%s] set mtu %d rejected - must be between %d and %d\n",
				ndev->name, new_mtu, ETH_ZLEN, VMAC_MTU_MAX);
		return -EINVAL;
	}

	ndev->mtu = new_mtu;

	printk(KERN_NOTICE "[%s] set mtu %d\n", ndev->name, ndev->mtu);

	return 0;
}

static void vmac_set_eth_addr(struct net_device *ndev)
{
	memcpy(ndev->dev_addr, get_ethernet_addr(), ETH_ALEN);
}

static void init_rx_flag(struct vmac_priv *vmp)
{
	int i;
	for (i = 0; i < vmp->rx_bd_num; i++) {
		vmp->rx_flag_va[i] = VMAC_BD_EMPTY;
	}
	vmp->rx_flag_va[i - 1] |= VMAC_BD_WRAP;
}

static uint32_t setup_atu_hostbd_late(uint32_t host_bd_start)
{
	uint32_t val = 0x0;
	uint32_t host_addr = align_val_down(host_bd_start, PCIE_ATU_BAR_MIN_SIZE);

	/* Select shared mem region */
	writel(PCIE_HOSTBD_REGION, RUBY_PCIE_ATU_VIEW);

	/* Memory mapped area in Host*/
	writel(host_addr, RUBY_PCIE_ATU_TARGET_LO);
	writel(PCIE_HOSTBD_START_HI, RUBY_PCIE_ATU_TARGET_HI);

	/* Enable BAR mapped region */
	writel(PCIE_HOSTBD_REGION_ENABLE, RUBY_PCIE_ATU_CTL2);
	val = readl(RUBY_PCIE_ATU_CTL2);
	printk("ATU outband region %u (Host BD): EP(0x%x->0x%x) Host(0x%x->0x%x)\n",
		PCIE_HOSTBD_REGION,
		readl(RUBY_PCIE_ATU_BASE_LO), readl(RUBY_PCIE_ATU_BASE_LIMIT),
		host_addr, host_addr + PCIE_HOSTBD_SIZE_MASK);

	return readl(RUBY_PCIE_ATU_BASE_LO)
		+ align_down_off(host_bd_start, PCIE_ATU_BAR_MIN_SIZE);
}

static int vmac_mem_alloc_init(struct vmac_priv *vmp)
{
	uint32_t vaddr;
	uint32_t baddr;
	int len;

	len = vmp->tx_bd_num * sizeof(struct vmac_tx_buf)
		+ vmp->rx_bd_num * sizeof(struct vmac_rx_buf);

	vaddr  = (uint32_t)kzalloc(len, GFP_KERNEL);
	if (!vaddr)
		return -1;

	vmp->tx_buf  = (struct vmac_tx_buf *)vaddr;
	vaddr += vmp->tx_bd_num * sizeof(struct vmac_tx_buf);

	vmp->rx_buf = (struct vmac_rx_buf *)vaddr;
	vaddr += vmp->rx_bd_num * sizeof(struct vmac_rx_buf);

	len = (vmp->tx_bd_num + vmp->rx_bd_num) * sizeof(uint32_t);

	vaddr = (uint32_t)dma_alloc_coherent(&vmp->ndev->dev, len,
			(dma_addr_t *)&baddr, GFP_KERNEL | __GFP_ZERO);
	if (!vaddr) {
		kfree((void *)vmp->tx_buf);
		return -1;
	}

	vmp->tx_flag_va = (uint32_t *)vaddr;
	vmp->tx_flag_ba = (uint32_t *)baddr;
	vaddr += vmp->tx_bd_num * sizeof(uint32_t);
	baddr += vmp->tx_bd_num * sizeof(uint32_t);

	vmp->rx_flag_va = (uint32_t *)vaddr;
	vmp->rx_flag_ba = (uint32_t *)baddr;
	vaddr += vmp->rx_bd_num * sizeof(uint32_t);
	baddr += vmp->rx_bd_num * sizeof(uint32_t);

/* here we try to alloc LL element in the SRAM*/
	void *sram_addr;
	unsigned long paddr;

	len = SIZE_OF_WDMA_PT(vmp->tx_bd_num) + SIZE_OF_RDMA_PT(vmp->rx_bd_num);

	sram_addr = heap_sram_alloc(len);
	if (!sram_addr) {
		printk("sram alloc for the LL element failed !");
		kfree((void *)vmp->tx_buf);

		len = (vmp->tx_bd_num + vmp->rx_bd_num) * sizeof(uint32_t);
		dma_free_coherent(&vmp->ndev->dev, len, (void *)vmp->tx_flag_va,
			(dma_addr_t)vmp->tx_flag_ba);

		return -1;
	}
	memset(sram_addr, 0, len);

	paddr = virt_to_phys(sram_addr);
	baddr = virt_to_bus(sram_addr);
	vaddr = (uint32_t)ioremap_nocache(paddr, len);
	vmp->tx_dmapt_va = (struct pcie_dma_ll_data *)vaddr;
	vmp->tx_dmapt_ba = (struct pcie_dma_ll_data *)baddr;

	vaddr += SIZE_OF_WDMA_PT(vmp->tx_bd_num);
	baddr += SIZE_OF_WDMA_PT(vmp->tx_bd_num);

	vmp->rx_dmapt_va = (struct pcie_dma_ll_data *)vaddr;
	vmp->rx_dmapt_ba = (struct pcie_dma_ll_data *)baddr;
	return 0;
}

static void vmac_mem_free(struct vmac_priv *vmp)
{
	int len;

	kfree((void *)vmp->tx_buf);

	len = (vmp->tx_bd_num + vmp->rx_bd_num) * sizeof(uint32_t);

	dma_free_coherent(&vmp->ndev->dev, len, (void *)vmp->tx_flag_va,
		(dma_addr_t)vmp->tx_flag_ba);

	/*add free buffer from sram*/
	iounmap(vmp->tx_dmapt_va);
	iounmap(vmp->rx_dmapt_va);
	heap_sram_free(bus_to_virt((uint32_t)vmp->tx_dmapt_ba));
	heap_sram_free(bus_to_virt((uint32_t)vmp->rx_dmapt_ba));

}

static int call_ep_reset(void *data)
{
	kernel_restart("EP reboot caused by RC");

	return 0;
}

void vmac_request_queue_init(volatile qdpc_pcie_bda_t *bda)
{
	int i;

	for (i = 0; i < bda->bda_rc_tx_bd_num; i++) {
		bda->request[i].addr = 0;
		bda->request[i].info = 0;
	}
}

PCIE_TQE_INTR_WORKAROUND_DEF;

static struct net_device* vmac_net_init(struct pci_dev *pdev)
{
	struct vmac_priv *vmp = NULL;
	struct net_device *ndev = NULL;
	int err;
	uint32_t addr;
	volatile qdpc_pcie_bda_t *bda;
	uint8_t channel;

	printk(KERN_INFO"%s version %s %s\n", DRV_NAME, DRV_VERSION, DRV_AUTHOR);

	/* Allocate device structure */
	ndev = alloc_netdev(sizeof(struct vmac_priv), vmac_cfg.ifname, ether_setup);
	if (!ndev) {
		printk(KERN_ERR "%s: alloc_etherdev failed\n", DRV_NAME);
		goto vnet_init_err_0;
	}

	g_ndev = ndev;

	PCIE_TQE_INTR_WORKAROUND_DETECT;

	/* Initialize device structure fields */
	vmac_set_eth_addr(ndev);

	ndev->netdev_ops = &vmac_device_ops;
	ndev->tx_queue_len = QTN_GLOBAL_INIT_EMAC_TX_QUEUE_LEN;
	SET_ETHTOOL_OPS(ndev, &vmac_ethtool_ops);

	/* Initialize private data */
	vmp = netdev_priv(ndev);
	if (PCIE_TQE_INTR_WORKAROUND)
		vmp->tqe_irq_enable = tqe_dsp_irq_enable;
	else
		vmp->tqe_irq_enable = tqe_pcie_irq_enable;
	vmp->pdev = pdev;
	vmp->ndev = ndev;

	vmac_set_macaddr(ndev, veth_basemac);

	vmp->pcfg = &vmac_cfg;
	vmp->ipc_irq = vmp->pcfg->ipc_irq;
	ndev->irq = vmp->pcfg->rdma_irq;
	ndev->if_port = VMAC_PCIE_PORT_ID;
	ndev->watchdog_timeo = 60 * HZ;

	bda = (qdpc_pcie_bda_t *)ioremap_nocache(BDA_SHMEM_ADDR, EP_SHMEM_LEN);
	if (!bda) {
		goto vnet_init_err_1;
	}
	vmp->bda = bda;

	vmp->rc2ep_offset = bda->bda_dma_offset;

	while(!bda->bda_rc_rx_bd_num || !bda->bda_rc_tx_bd_num
		|| !bda->bda_rc_rx_bd_base || !bda->bda_rc_tx_bd_base) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(VMAC_SCHED_TIMEOUT);
	}

	vmp->tx_bd_num = bda->bda_rc_rx_bd_num;
	vmp->rx_bd_num = bda->bda_rc_tx_bd_num;

	/* Initial multiple WDMA and RDMA channes data */
	vmp->tx_channel_num = QTN_TOPAZ_WDMA_CHANNEL_NUM;
	vmp->rx_channel_num = QTN_TOPAZ_RDMA_CHANNEL_NUM;
	vmp->tx_channel_index = WD_DMA_CH;
	vmp->rx_channel_index = R_DMA_CH;

	vmp->tx_dma_done_mask = 0;
	vmp->tx_dma_abort_mask = 0;
	for (channel = 0; channel < QTN_TOPAZ_WDMA_CHANNEL_NUM; channel++) {
		vmp->tx_dma_done_mask |= DMA_DONE_MSK(channel);
		vmp->tx_dma_abort_mask |= DMA_ABORT_MSK(channel);
	}
	vmp->rx_dma_done_mask = 0;
	vmp->rx_dma_abort_mask = 0;
	for (channel = 0; channel < QTN_TOPAZ_RDMA_CHANNEL_NUM; channel++) {
		vmp->rx_dma_done_mask |= DMA_DONE_MSK(channel);
		vmp->rx_dma_abort_mask |= DMA_ABORT_MSK(channel);
	}

	addr = setup_atu_hostbd_late(bda->bda_rc_tx_bd_base);
	vmp->rc_tx_bd_base = (struct vmac_bd *)addr;
	printk("Tx Descriptor table: uncache virtual addr: 0x%08x bda_rc_tx_bd_num: %d\n", (uint32_t)vmp->rc_tx_bd_base, bda->bda_rc_tx_bd_num);
	addr += bda->bda_rc_tx_bd_num * VMAC_BD_LEN;

	vmp->rc_rx_bd_base = (struct vmac_bd *)addr;
	printk("Rx Descriptor table: uncache virtual addr: 0x%08x\n", (uint32_t)vmp->rc_rx_bd_base);
	addr += bda->bda_rc_rx_bd_num * VMAC_BD_LEN;

	vmp->next_rx_pkt = (uint32_t *)addr;
	printk("EP Handled idx: uncache virtual addr: 0x%08x\n", (uint32_t)vmp->next_rx_pkt);
	addr += sizeof(uint32_t);

	vmp->rc_txqueue_wake = (uint32_t *)addr;
	printk("RC tqxqueue wake flag address: uncache virtual addr: 0x%08x\n", (uint32_t)vmp->rc_txqueue_wake);
	addr += sizeof(uint32_t);

	vmp->ep_pmstate = (uint32_t *)addr;
	printk("EP pm state address: uncache virtual addr: 0x%08x\n", (uint32_t)vmp->ep_pmstate);

	vmp->request_queue = (struct vmac_pkt_info *)bda->request;

	vmac_request_queue_init(bda);

	vmp->tx_congest_thresh = TOPAZ_DEF_TX_CONGEST_THRESH;
	vmp->rx_congest_thresh = TOPAZ_DEF_RX_CONGEST_THRESH;
	vmp->rx_intr_pktnr = TOPAZ_DEF_RX_PKTS_PER_INTR;
	vmp->rx_congsirq_budget = TOPAZ_DEF_RX_SOFTIRQ_BUDGET;

	if (vmac_mem_alloc_init(vmp))
		goto vnet_init_err_2;

	/* Initialize interrupt capability */
	qdpc_pcie_init_intr_cap(vmp);
	qdpc_pcie_set_src_align(vmp);

	init_rx_flag(vmp);
	vmac_tx_dmapt_init(vmp);
	vmac_rx_dmapt_init(vmp);

	/* Initialize congestion queue */
	vmp->congest_queue = topaz_congest_queue_get();
	if (vmp->congest_queue == NULL){
		printk(KERN_ERR "%s: Congest queue is not initilized\n", DRV_NAME);
		goto vnet_init_err_3;
	}

	vmp->congest_queue->xmit_func = topaz_pcie_tqe_xmit;

	/* Initialize NAPI */
	netif_napi_add(ndev, &vmp->rx_napi, vmac_rx_poll, QTN_TOPAZ_PCIE_EP_NAPI_BUDGET);
	netif_napi_add(ndev, &vmp->rdma_napi, vmac_rdma_poll, QTN_TOPAZ_PCIE_RDMA_BUDGET);

	/* Register device */
	if ((err = register_netdev(ndev)) != 0) {
		printk(KERN_ERR "%s: Cannot register net device, error %d\n", DRV_NAME, err);
		goto vnet_init_err_4;
	}
	printk(KERN_INFO"%s: Vmac Ethernet found\n", ndev->name);

	if (switch_alloc_vlan_dev(TOPAZ_TQE_PCIE_REL_PORT, PCIE_VDEV_IDX, ndev->ifindex) == NULL) {
		printk(KERN_ERR "%s: switch_alloc_vlan_dev returns error\n", __FUNCTION__);
		goto vnet_init_err_5;
	}

	vmp->show_item = SHOW_VMAC_STATS;
	device_create_file(&ndev->dev, &dev_attr_dbg);
	device_create_file(&ndev->dev, &dev_attr_parameters);

	/* pre-alloc netlink data buffer */
	vmp->nl_buf = kmalloc(VMAC_NL_BUF_SIZE, GFP_KERNEL);
	if (!vmp->nl_buf)
		goto vnet_init_err_6;

	/* Create netlink & register with kernel */
	vmp->nl_socket = netlink_kernel_create(&init_net,
				QDPC_NETLINK_RPC_PCI_SVC, 0, qdpc_nl_recv_msg,
				NULL, THIS_MODULE);
	if (!vmp->nl_socket) {
		goto vnet_init_err_6;
	}

	INIT_WORK(&rc_rmmod_work, (work_func_t)call_ep_reset);

	init_timer(&(vmp->pmstate_ck_timer));
	vmp->pmstate_ck_timer.function = vmac_pmstate_checker;
	vmp->pmstate_ck_timer.data = 0;
	pm_qos_add_requirement(PM_QOS_POWER_SAVE, BOARD_PM_GOVERNOR_PCIE_EP, BOARD_PM_LEVEL_NO);

	return ndev;

vnet_init_err_6:
	switch_free_vlan_dev_by_idx(PCIE_VDEV_IDX);
vnet_init_err_5:
	kfree(vmp->nl_buf);
	unregister_netdev(ndev);
vnet_init_err_4:
	topaz_congest_queue_exit(vmp->congest_queue);
vnet_init_err_3:
	vmac_mem_free(vmp);
vnet_init_err_2:
	iounmap(vmp->bda);
vnet_init_err_1:
	free_netdev(ndev);
vnet_init_err_0:

	return NULL;
}

static void free_tx_skbs(struct vmac_priv *vmp)
{
	/* All Ethernet activity should have ceased before calling
	 * this function
	 */
	uint16_t i;
	for (i = 0; i < vmp->tx_bd_num; i++) {
		if (vmp->tx_buf[i].handle) {
			if (vmp->tx_buf[i].type == PKT_TQE)
				vmac_tx_free_payload((void *)vmp->tx_buf[i].handle);
			else
				dev_kfree_skb((struct sk_buff *)vmp->tx_buf[i].handle);

			vmp->tx_buf[i].handle = 0;
		}
	}
}

static void free_rx_skbs(struct vmac_priv *vmp)
{
	/* All Ethernet activity should have ceased before calling
	 * this function
	 */
	uint16_t i;
	for (i = 0; i < vmp->rx_bd_num; i++)
		if (vmp->rx_buf[i].baddr)
			topaz_hbm_put_buf((void *)vmp->rx_buf[i].baddr,
				TOPAZ_HBM_BUF_EMAC_RX_POOL);

}

static void release_all(struct net_device *ndev)
{
	struct vmac_priv *vmp = NULL;

	if (!ndev) {
		return;
	}

	tqe_pcie_netdev_term(ndev);

	vmp = netdev_priv(ndev);

	if (vmp->nl_socket) {
		/* release netlink socket */
		netlink_kernel_release(vmp->nl_socket);
	}

	device_remove_file(&ndev->dev, &dev_attr_dbg);
	device_remove_file(&ndev->dev, &dev_attr_parameters);

	kfree(vmp->nl_buf);

	switch_free_vlan_dev_by_idx(PCIE_VDEV_IDX);
	unregister_netdev(ndev);

	topaz_congest_queue_exit(vmp->congest_queue);

	shut_down_interface(ndev);

	netif_napi_del(&vmp->rx_napi);
	netif_napi_del(&vmp->rdma_napi);

	free_rx_skbs(vmp);

	free_tx_skbs(vmp);

	iounmap((void *)vmp->addr_uncache);

	iounmap(vmp->bda);

	free_netdev(ndev);
}

static void bring_up_interface(struct net_device *ndev)
{
	/* Interface will be ready to send/receive data, but will need hooking
	 * up to the interrupts before anything will happen.
	 */
	vmac_dma_intr_en();
	vmac_ipc_intr_rx_en();
	vmac_ipc_intr_reset_pm_en();
	vmac_ipc_intr_offline_dump_en();
}

static void shut_down_interface(struct net_device *ndev)
{
	/* Close down MAC and DMA activity and clear all data. */
	vmac_ipc_intr_rx_dis();
	vmac_dma_intr_dis();
	vmac_ipc_intr_reset_pm_dis();
	vmac_ipc_intr_offline_dump_dis();
}

static int vmac_open(struct net_device *ndev)
{
	int retval = 0;
	struct vmac_priv *vmp = netdev_priv(ndev);

	bring_up_interface(ndev);

	napi_enable(&vmp->rx_napi);
	napi_enable(&vmp->rdma_napi);

	retval = request_irq(ndev->irq, &vmac_interrupt, 0, ndev->name, vmp);
	if (retval) {
		printk(KERN_ERR "%s: unable to get IRQ %d\n",
			ndev->name, ndev->irq);
		goto err_out;
	}

	retval = request_irq(vmp->ipc_irq, &vmac_ipc_isr, 0, ndev->name, ndev);
	if (retval) {
		printk(KERN_ERR "%s: unable to get IRQ %d\n",
			ndev->name, vmp->ipc_irq);
		free_irq(ndev->irq, ndev);
		goto err_out;
	}
	set_bit(IPC_BIT_RESET_EP, (void *)TOPAZ_LH_IPC4_INT_MASK);

	*vmp->rc_txqueue_wake = 1;
	barrier();
	vmac_intr_rc(vmp);
	vmp->rc_txqueue_stopped = 0;
	vmp->rc_txbd_wake_th = vmp->rx_bd_num * 2 / 5;

	netif_start_queue(ndev);

	return 0;
err_out:
	napi_disable(&vmp->rdma_napi);
	napi_disable(&vmp->rx_napi);
	return retval;
}

static int vmac_close(struct net_device *ndev)
{
	struct vmac_priv *const vmp = netdev_priv(ndev);

	napi_disable(&vmp->rdma_napi);
	napi_disable(&vmp->rx_napi);

	shut_down_interface(ndev);

	netif_stop_queue(ndev);

	free_irq(ndev->irq, ndev);
	free_irq(vmp->ipc_irq, ndev);

	return 0;
}

static struct net_device_stats *vmac_get_stats(struct net_device *ndev)
{
	return &(ndev->stats);
}

static void __exit vmac_cleanup_module(void)
{
	release_all(vmac_cfg.dev);
}

/*
* Queue of processes who access wps_button file
*/
DECLARE_WAIT_QUEUE_HEAD(WPS_Button_WaitQ);
static WPS_Button_Event wps_button_event = WPS_BUTTON_NONE_EVENT;

static void vmac_wps_button_event_notifier(WPS_Button_Event event)
{
	if (!WPS_BUTTON_VALID(event))
		return;

	/* notify local watcher */
	wps_button_event = event;
	wake_up_all(&WPS_Button_WaitQ);
}

static ssize_t vmac_wps_button_read(struct device *dev,
				    struct device_attribute *attr,
				    char *buff)
{
	int i = 0;

	/* As usual, this read is always blocked untill wps button is pressed
	 * so increase the module reference to prevent it being unload during
	 * blocking read
	 */
	if (!try_module_get(THIS_MODULE))
		return 0;

	/* wait for valid WPS button event */
	wait_event_interruptible(WPS_Button_WaitQ, WPS_BUTTON_VALID(wps_button_event));

	/* read back empty string in signal wakeup case */
	for (i = 0; i < _NSIG_WORDS; i++) {
		if (current->pending.signal.sig[i] & ~current->blocked.sig[i]) {
			module_put(THIS_MODULE);
			return 0;
		}
	}

	sprintf(buff, "%d\n", wps_button_event);

	/* after new event been handled, reset to none event */
	wps_button_event = WPS_BUTTON_NONE_EVENT;

	module_put(THIS_MODULE);

	return strlen(buff);
}

DEVICE_ATTR(wps_button, S_IWUSR | S_IRUSR, vmac_wps_button_read, NULL); /* dev_attr_wps_button */

static void vmac_wps_button_device_file_create(struct net_device *ndev)
{
	device_create_file(&(ndev->dev), &dev_attr_wps_button);
}

module_init(vmac_init_module);
module_exit(vmac_cleanup_module);

