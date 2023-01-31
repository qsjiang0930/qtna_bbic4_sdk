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

#ifndef __DRIVERS_NET_TOPAZ_VNET_H
#define __DRIVERS_NET_TOPAZ_VNET_H	1

#define ETH_TX_TIMEOUT (100*HZ)
#define MULTICAST_FILTER_LIMIT 64

#include <linux/slab.h>
#include <linux/skbuff.h>

#include <qdpc_config.h>

#include <topaz_netcom.h>
#include <qtn/topaz_congest_queue.h>

#define PROC_NAME_SIZE		(32)
#define VMAC_BD_EMPTY		((uint32_t)0x00000001)
#define VMAC_BD_WRAP		((uint32_t)0x00000002)
#define VMAC_BD_MASK_LEN	((uint32_t)0xFFFF0000)
#define VMAC_BD_MASK_OFFSET ((uint32_t)0x0000FF00)

#define PKTS_NUM_PER_RC_INTR	(4)
/* Macro defines for the ASPM parameters */
#define VMAC_ASPM_ENABLE_CMD	(69)
#define VMAC_ASPM_DISABLE_CMD	(70)
#define PCIE_ASPM_L1_ENABLE	(0x2)
#define PCIE_ASPM_L1_DISABLE	(0)
#define PCIE_ASPM_L1_FROM_L0	(1 << 3)

enum l1_entry_latency {
	LATENCY_1US = 0,
	LATENCY_2US,
	LATENCY_4US,
	LATENCY_8US,
	LATENCY_16US,
	LATENCY_32US,
	LATENCY_64US
};

/* Following magic number should be different with NETDEV_TX_OK and NETDEV_TX_BUSY */
#define VMAC_GET_LEN(x)		(((x) >> 16) & 0xFFFF)
#define VMAC_GET_OFFSET(x)	(((x) >> 8) & 0xFF)
#define VMAC_SET_LEN(len)	(((len) & 0xFFFF) << 16)
#define VMAC_SET_OFFSET(of)	(((of) & 0xFF) << 8)

#define VMAC_INDX_MINUS(x, y, m) (((x) + (m) - (y)) % (m))
#define VMAC_INDX_INC(index, m) do {	\
		if (++(index) >= (m))	\
			(index) = 0;	\
	} while(0)

#define BIT_DMA_BUSY		(0)
#define BIT_RC_BUSY		(1)

#define VMAC_NL_BUF_SIZE	USHRT_MAX

enum pkt_type {
        PKT_SKB = 0,
        PKT_TQE
};

struct vmac_tx_buf {
        uint32_t handle;
        uint8_t type; /* 1 payload only, 0 skb */
        uint8_t rsv;
        uint16_t len;
};

struct pcie_vmac_cfg {
	int rdma_irq;
	int ipc_irq;
	char ifname[PROC_NAME_SIZE];
	struct net_device *dev;
};

struct vmac_priv {
	struct vmac_tx_buf *tx_buf;
	volatile uint32_t *tx_flag_va; /* Tx flag, used to update the RC Rx BD */
	uint32_t *tx_flag_ba; /* Tx flag bus address  */

	volatile struct vmac_bd *rc_rx_bd_base; /* Tx buffer descriptor, bus  address */
	uint32_t cur_rc_bd_info;
	/* A pointer to RC's memory specifying next packet index EP to be handled */
	uint32_t *next_rx_pkt;
	struct vmac_pkt_info *request_queue;
	struct topaz_congest_queue* congest_queue;

	struct pcie_dma_ll_data *tx_dmapt_va;
	struct pcie_dma_ll_data *tx_dmapt_ba;

	uint8_t tx_DMA_ctrl; /* CCS information */
	uint16_t eDMA_src_align;
	uint16_t tx_intr_rc_th;
	uint16_t tx_intr_rc_i; /* last index by which EP interrupt RC */

	uint16_t tx_toDMA_s; /* Start index of pending packet */
	uint16_t tx_toDMA_e; /* End index of pending packet */
	uint16_t tx_bd_num;
	struct pcie_dma_ll_data *tx_last_ptd;
	struct pcie_dma_ll_data *rx_last_ptd;
	atomic_t wdma_running;	/* 0: wDMA is idle. 1: wDMA is undergoing */
	atomic_t tx_congest;
	uint32_t tx_congest_thresh;
	uint32_t enable_tqe_intr; /* Indicate when enable tqe interrupt when wDMA is done */
	uint32_t txqueue_stopped;
	uint8_t tqe_flag;
	void *tqe_napi;

	/* used for PCIE_TQE_INTR_WORKAROUND */
	void (*tqe_irq_enable) (void); /* pointer of func tqe_irq_enable */

	uint32_t rc2ep_offset; /* EP access the RC DDR address by addr + rc2ep_offset */

	/* Tx counter */
	uint32_t wdma_busy_cnt; /* fail to get write DMA */
	uint32_t tx_rc_bd_busy; /* tx BD unavailable */
	uint32_t tx_ll_full;
	uint32_t tx_dma_issue_log[PCIE_DMA_ISSUE_LOG_NUM];
	uint32_t tx_dma_pkts;
	uint32_t tqe_rx_napi_cnt;
	uint32_t vmac_tx_entries;
	uint32_t wdma_softirq_trig;
	uint32_t wdma_intr_trig;
	uint32_t wdma_done_idle;
	uint32_t tx_queue_len;
	uint32_t tx_tqe_no_pkt;
	uint32_t tx_dma_reserved;

	struct vmac_rx_buf *rx_buf;

	volatile uint32_t *rx_flag_va; /* Rx flag, copied from RC Tx BD */
	uint32_t *rx_flag_ba; /* Rx flag, bus address */

	volatile struct vmac_bd *rc_tx_bd_base; /* Rx buffer descriptor  */

	struct pcie_dma_ll_data *rx_dmapt_va;
	struct pcie_dma_ll_data *rx_dmapt_ba;

	/* Multiple RDMA and WDMA channels support */
	uint8_t tx_channel_num;
	uint8_t rx_channel_num;
	uint8_t tx_channel_index;
	uint8_t rx_channel_index;
	uint32_t tx_dma_done_mask;
	uint32_t tx_dma_abort_mask;
	uint32_t rx_dma_done_mask;
	uint32_t rx_dma_abort_mask;

	uint32_t rx_DMA_ctrl; /* CCS information */

	uint32_t rx_pkt_index;
	uint32_t rx_DMAing;
	uint32_t rx_queue_full;
	uint32_t rx_pcie_drop;
	uint32_t rx_tqe_fwd;
	uint32_t rx_toDMA_s;
	uint32_t rx_toDMA_e;
	uint32_t dcache_dirty_sz;	/* The footprint on dcache for one packet */
	uint32_t rx_bd_num;
	uint32_t rx_dma_issue_log[PCIE_DMA_ISSUE_LOG_NUM];
	uint32_t rx_dma_funcs;
	uint32_t rx_napi_poll;
	uint32_t rx_dma_while;
	uint32_t rx_slow_rc;
	uint32_t rx_dma_busy;
	uint32_t rx_queue_len;
	uint32_t rx_occupy_len;
	uint32_t rx_queue_max;
	uint32_t rx_napi_func;
	uint32_t rx_dma_reserved;
	uint32_t rdma_intr_trig;
	uint32_t rdma_softirq_trig;
	uint32_t rx_congest_thresh;
	uint32_t rx_intr_pktnr;
	uint32_t rx_congsirq_budget;
	uint32_t rx_congest_timeout;
	uint8_t rc_txqueue_stopped;
	uint16_t rc_txbd_avail_cnt; /* rc txbd available counter */
	uint16_t rc_txbd_wake_th; /* rc tx queue wakeup threshold */
	uint32_t *rc_txqueue_wake; /* wake rc tx queue flag */
	volatile uint32_t *ep_pmstate; /* ep suspend or resume */

	struct timer_list pmstate_ck_timer; /* check ep pmstate during L1 */

	/* Rx counter */
	uint32_t ipc_cnt; /* ipc interrupt counter */
	uint32_t rdma_dn_cnt; /* rdma done counter */
	uint32_t rdma_ab_cnt; /* rdma abort counter */
	uint32_t wdma_ab_cnt; /* wdma abort counter */
	uint32_t wdma_done_cnt;
	uint32_t rdma_busy_cnt;
	uint32_t rdma_trigger;
	uint32_t fwt_loss_cnt;

	uint32_t rx_hbm_alloc_fail;
	int ipc_irq;
	uint32_t dbg_flg;

	int link; /* link status */
	struct net_device *ndev;
	struct pci_dev	*pdev;
	struct sock *nl_socket; /*netlink socket for rpcd*/
	uint32_t str_call_nl_pid;
	uint32_t lib_call_nl_pid;

	int mac_id;
	struct napi_struct rdma_napi;
	struct napi_struct rx_napi;
	struct pcie_vmac_cfg *pcfg;
	volatile qdpc_pcie_bda_t *bda;
	uint32_t addr_kmalloc;
	uint32_t addr_uncache;
	uint8_t show_item;

	uint8_t	msi_enabled; /* PCIe MSI: 1 - Enabled, 0 - Disabled */
	uint16_t msi_data;
	uint32_t msi_addr;

	uint8_t *nl_buf;
	size_t nl_len;
};

extern netdev_tx_t vmac_tx(void *pkt_handle, struct net_device *ndev, enum pkt_type);
extern void vmac_tx_free_payload(void *bus_addr);
extern void qdpc_pcie_init_intr_cap(struct vmac_priv *priv);
extern void qdpc_pcie_set_src_align(struct vmac_priv *priv);
#endif

