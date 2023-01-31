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

#ifndef TOPAZ_PCIE_DMA_H_
#define TOPAZ_PCIE_DMA_H_

#include <linux/spinlock.h>
#include <asm/cache.h>

#define PCIE_CHAN_MAX_NUM	2
#define QPCIE_MODULE_VERSION              "1.0"
#define LL_MODE_WR	0
#define LL_MODE_RD	1
#define TEST_BUF_MAX_LEN 4096
#define PROC_CMD_MAX_LEN 32
#define QPCIE_DMA_DBG
#define RD_MODE_BIT_SHIFT	7

/* DMA channel status*/
#define PCIE_DMA_RESERVED	0x0
#define PCIE_DMA_RUNNING	0x1
#define PCIE_DMA_HALTED		0x2
#define PCIE_DMA_STOPPED	0x3

#define PCIE_INTR_MSK_REG	0xe00000c0
#define BIT_PCIE_FATAL_ERR	5
#define BIT_PCIE_NONFATAL_ERR	6
#define DMA_RESET_WAIT_CNT	10000

#define PCIE_REG_CFG_BASE	0xe9000000
#define PCIE_LOGIC_PORT_CFG_BASE	(PCIE_REG_CFG_BASE + 0x700)
#define PCIE_IATU_CTRL2		(PCIE_LOGIC_PORT_CFG_BASE + 0x208)

/* DMA global register offsets*/
/* write channel global control*/
#define PCIE_DMA_WR_ENGINE_ENABLE	0x27c
#define PCIE_DMA_WR_DBELL		0x280
#define PCIE_DMA_WR_ENGINE_CAW_LOW	0x288
#define PCIE_DMA_WR_ENGINE_CAW_HIGH	0x28c

/* read channel global control */
#define PCIE_DMA_RD_ENGINE_ENABLE	0x29c
#define PCIE_DMA_RD_DBELL		0x2a0
#define PCIE_DMA_RD_ENGINE_CAW_LOW	0x2a8
#define PCIE_DMA_RD_ENGINE_CAW_HIGH	0x2ac

/* DMA interrupt register offsets*/
#define PCIE_DMA_WR_INTR_STATUS		0x2bc
#define PCIE_DMA_WR_INTR_MASK		0x2c4
#define PCIE_DMA_WR_INTR_CLR		0x2c8
#define PCIE_DMA_WR_ERR_STATUS		0x2cc
#define PCIE_DMA_WR_DONE_IMWR_ADDR_LOW	0x2d0
#define PCIE_DMA_WR_DONE_IMWR_ADDR_HIGH	0x2d4
#define PCIE_DMA_WR_ABORT_IMWR_ADDR_LOW	0x2d8
#define PCIE_DMA_WR_ABORT_IMWR_ADDR_HIGH	0x2dc
#define PCIE_DMA_WR_CH_1_0_IMWR_DATA	0x2e0
#define PCIE_DMA_WR_CH_3_2_IMWR_DATA	0x2e4
#define PCIE_DMA_WR_CH_5_4_IMWR_DATA	0x2e8
#define PCIE_DMA_WR_CH_7_6_IMWR_DATA	0x2ec
#define PCIE_DMA_WR_LL_ERR_ENABLE	0x300
#define PCIE_DMA_RD_INTR_STATUS		0x310
#define PCIE_DMA_RD_INTR_MASK		0x318
#define PCIE_DMA_RD_INTR_CLR		0x31c
#define PCIE_DMA_RD_ERR_STATUS_LOW	0x324
#define PCIE_DMA_RD_ERR_STATUS_HIGH	0x328
#define PCIE_DMA_RD_LL_ERR_ENABLE	0x334
#define PCIE_DMA_RD_DONE_IMWR_ADDR_LOW	0x33c
#define PCIE_DMA_RD_DONE_IMWR_ADDR_HIGH	0x340
#define PCIE_DMA_RD_ABORT_IMWR_ADDR_LOW	0x344
#define PCIE_DMA_RD_ABORT_IMWR_ADDR_HIGH	0x348
#define PCIE_DMA_RD_CH_1_0_IMWR_DATA	0x34c
#define PCIE_DMA_RD_CH_3_2_IMWR_DATA	0x350
#define PCIE_DMA_RD_CH_5_4_IMWR_DATA	0x354
#define PCIE_DMA_RD_CH_7_6_IMWR_DATA	0x358

/* DMA channel context register for each channel*/
#define PCIE_DMA_CH_CTXT_IDX		0x36c
#define PCIE_DMA_CH_CTRL_1_REG		0x370
#define PCIE_DMA_CH_CTRL_2_REG		0x374
#define PCIE_DMA_TRANS_SIZE		0x378
#define PCIE_DMA_SAR_LOW		0x37c
#define PCIE_DMA_SAR_HIGH		0x380
#define PCIE_DMA_DAR_LOW		0x384
#define PCIE_DMA_DAR_HIGH		0x388
#define PCIE_DMA_LL_PTR_LOW		0x38c
#define PCIE_DMA_LL_PTR_HIGH		0x390

/* Linked list Element/Descriptor structure */
#define DMA_LL_DATA_RIE		(1 << 4)
#define DMA_LL_DATA_LIE		(1 << 3)
#define DMA_LL_DESC_LLP		(1 << 2)
#define DMA_LL_DESC_TCB		(1 << 1)
#define DMA_LL_DATA_CB		(1 << 0)

#define WD_DMA_CH		(0)
#define R_DMA_CH		(0)

#define DMA_DONE_MSK(ch)	(0x1 << (ch))
#define DMA_ABORT_MSK(ch)	(0x1 << (16 + (ch)))

/* write DMA back door register */
#define DMA_WR_BKD_BASE			(0xe9008000)
#define DMA_WR_BKD_CHNL_CNTRL(ch)	(DMA_WR_BKD_BASE + 0x20 * (ch) + 0x0)
#define DMA_WR_BKD_XFR_SIZE(ch)		(DMA_WR_BKD_BASE + 0x20 * (ch) + 0x4)
#define DMA_WR_BKD_SAR_LOW(ch)		(DMA_WR_BKD_BASE + 0x20 * (ch) +  0x8)
#define DMA_WR_BKD_SAR_HIGH(ch)		(DMA_WR_BKD_BASE + 0x20 * (ch) +  0xc)
#define DMA_WR_BKD_DAR_LOW(ch)		(DMA_WR_BKD_BASE + 0x20 * (ch) +  0x10)
#define DMA_WR_BKD_DAR_HIGH(ch)		(DMA_WR_BKD_BASE + 0x20 * (ch) +  0x14)
#define DMA_WR_BKD_LLPTR_LOW(ch)	(DMA_WR_BKD_BASE + 0x20 * (ch) +  0x18)
#define DMA_WR_BKD_LLPTR_HIGH(ch)	(DMA_WR_BKD_BASE + 0x20 * (ch) +  0x1c)

/*
 * Multiple RDMA and WDMA channels support.
 */
#define QTN_TOPAZ_WDMA_CHANNEL_NUM		1
#define QTN_TOPAZ_RDMA_CHANNEL_NUM		1

 /*linked list element structure*/
struct pcie_dma_ll_data {
	uint32_t data_info;
	uint32_t ll_trans_size;	/* transfer size for the data block pointed by the sar */
	uint32_t ll_sar_low;	/* low source address in local memory for data element; */
	uint32_t ll_sar_high;	/* high source address in local memory for data element*/
	uint32_t ll_dar_low;	/* low source address in the remote memory for data element */
	uint32_t ll_dar_high;	/* high source address in the remote memory for data element */
};

struct pcie_dma_ll_desc {
	uint32_t desc_info;
	uint32_t rsvd1;			/* reserved for descriptor element */
	uint32_t ll_elem_ptr_low;	/* low  pointer value for the LL element */
	uint32_t ll_elem_ptr_high;	/* high pointer value for the LL element */
	uint32_t rsvd2[2];
};

/* DMA channel context */
struct dma_chan_ctx {
	uint32_t data_len;
	uint32_t sar_low;
	uint32_t sar_high;
	uint32_t dar_low;
	uint32_t dar_high;
};

#define SIZE_OF_WDMA_PT(bdnum) ((2 * (bdnum)) * sizeof(struct pcie_dma_ll_data)\
				+ sizeof(struct pcie_dma_ll_desc))
#define SIZE_OF_RDMA_PT(bdnum) ((bdnum) * sizeof(struct pcie_dma_ll_data)\
				+ sizeof(struct pcie_dma_ll_desc))

enum dma_dir {
	DMA_WR_MODE = 0,
	DMA_RD_MODE = 1
};

enum PcieDmaRegVals {
	/* DMA Write Engine Enable Register */
	DmaWrEngDisable = 0,
	DmaWrEngEnable = 1 << 0,

	/* DMA Write Door bell Register*/
	DmaWrDbellStop = 1 << 31,

	/* DMA Read Engine Enable Register */
	DmaRdEngDisable = 0,
	DmaRdEngenable = 1 << 0,

	/* DMA Read Door bell Register */
	DmaRdDbellStop = 1 << 31,

	/* DMA write interrupt status/mask/clear register*/
	dmawrdoneintrstatusmask = 0xff,
	dmawrabortintrstatusmask = 0xff << 16,

	/* DMA write error status register */
	dmawrerrstatusapprdmask = 0xff,
	dmawrerrstatusllelemfetchmask = 0xff << 16,

	/* DMA Read interrupt Status/Mask/Clear Register */
	DmaRdDoneIntrStatusMask = 0xFF,
	DmaRdAbortIntrStatusMask = 0xFF << 16,

	/* DMA Read Error Status Low/High Register */
	DmaRdErrStatusAppRdMask = 0xFF,
	DmaRdErrStatusLLElemFetchMask = 0xFF << 16,
	DmaRdErrStatusUnsprtReqMask = 0xFF,
	DmaRdErrStatusCplAbortMask = 0xFF << 8,
	DmaRdErrStatusCplTmoutMask = 0xFF << 16,
	DmaRdErrStatusDataPoisonMask = 0xFF << 24,

	/* DMA Channel Context Index Register */
	DmaChDirRd = 1 << 31,
	DmaChDirWr = 0,

	/* DMA Channel Context Control 1 Register */
	DmaChCtrlMaskCB = 1 << 0,
	DmaChCtrlMaskTCB = 1 << 1,
	DmaChCtrlMaskLLP = 1 << 2,
	DmaChCtrlMaskLIE = 1 << 3,
	DmaChCtrlMaskRIE = 1 << 4,
	DmaChCtrlMaskCS =  2 << 5,
	DmaChCtrlMaskCCS = 1 << 8,
	DmaChCtrlMaskLLe = 1 << 9,
	DmaChCtrlMaskTD = 1 << 26,
};

static inline void topaz_ep_pcie_writel(unsigned int val, unsigned int offset)
{
	arc_write_uncached_32((PCIE_LOGIC_PORT_CFG_BASE + offset), val);
}

static inline uint32_t topaz_ep_pcie_readl(unsigned int offset)
{
	return arc_read_uncached_32(PCIE_LOGIC_PORT_CFG_BASE + offset);
}

static inline int pcie_wDMA_ready_raw(struct vmac_priv *vmp)
{
	uint32_t regval;
	uint32_t wdma_ch = vmp->tx_channel_index;

	topaz_ep_pcie_writel(DmaChDirWr | wdma_ch, PCIE_DMA_CH_CTXT_IDX);
	regval = (topaz_ep_pcie_readl(PCIE_DMA_CH_CTRL_1_REG) >> 5) & 0x3;

	if (unlikely(regval == PCIE_DMA_RESERVED))
		vmp->tx_dma_reserved++;

	return (regval == PCIE_DMA_STOPPED);
}

static inline int pcie_wDMA_ready(struct vmac_priv *vmp)
{
	if (vmp->msi_enabled)
		return (atomic_read(&vmp->wdma_running) == 0);
	else
		return pcie_wDMA_ready_raw(vmp);
}

extern int pcie_rDMA_ready_no_lock(struct vmac_priv *vmp);
extern int pcie_rDMA_ready(struct vmac_priv *vmp);
extern int pcie_rDMA_busy(struct vmac_priv *vmp);

extern void pcie_wDMA_trigger(struct vmac_priv *vmp);

static inline void pcie_rDMA_trigger(struct vmac_priv *vmp)
{
	struct pcie_dma_ll_data *ptd;
	uint32_t ctrl_val;
	uint32_t temp;
	uint32_t rdma_ch = vmp->rx_channel_index;

	vmp->rx_last_ptd->data_info |= DMA_LL_DATA_LIE;

	temp = vmp->rx_DMA_ctrl;
	if (temp & DMA_LL_DATA_CB)
		ctrl_val = (DmaChCtrlMaskLLe | DmaChCtrlMaskTD | DmaChCtrlMaskCCS);
	else
		ctrl_val = (DmaChCtrlMaskLLe | DmaChCtrlMaskTD);

	/* Mark the end of DMA by reverting CB bit */
	temp ^= DMA_LL_DATA_CB;
	vmp->rx_DMA_ctrl = temp;
	ptd = &vmp->rx_dmapt_va[vmp->rx_toDMA_e];
	ptd->data_info = vmp->rx_DMA_ctrl;

	/* Program PCIe Context Register to trigger one DMA operation */
	topaz_ep_pcie_writel(DmaChDirRd | rdma_ch, PCIE_DMA_CH_CTXT_IDX);
	topaz_ep_pcie_writel(ctrl_val, PCIE_DMA_CH_CTRL_1_REG);
	topaz_ep_pcie_writel((unsigned int)&vmp->rx_dmapt_ba[vmp->rx_toDMA_s],
			PCIE_DMA_LL_PTR_LOW);
	topaz_ep_pcie_writel(rdma_ch, PCIE_DMA_RD_DBELL);

	vmp->rx_toDMA_s = vmp->rx_toDMA_e;

	vmp->rdma_trigger++;

	if (vmp->rx_queue_len < PCIE_DMA_ISSUE_LOG_NUM)
		vmp->rx_dma_issue_log[vmp->rx_queue_len - 1]++;
	vmp->rx_queue_len = 0;

}

static inline void qdpc_assert_intx(void)
{
	unsigned long pcie_cfg0 = readl(RUBY_SYS_CTL_PCIE_CFG0);

	pcie_cfg0 |= BIT(9);
	writel(pcie_cfg0, RUBY_SYS_CTL_PCIE_CFG0);
}

static inline void qdpc_deassert_intx(void)
{
	unsigned long pcie_cfg0 = readl(RUBY_SYS_CTL_PCIE_CFG0);

	pcie_cfg0 &= ~BIT(9);
	writel(pcie_cfg0, RUBY_SYS_CTL_PCIE_CFG0);
}

static inline void vmac_pcie_edma_enable(void)
{
	topaz_ep_pcie_writel(0x00000000, PCIE_DMA_WR_INTR_MASK);
}

extern void vmac_wdmapt_print(struct vmac_priv *vmp);
extern void vmac_wdmapt_print_all(struct vmac_priv *vmp);
extern void vmac_rdmapt_print(struct vmac_priv *vmp);
extern void vmac_rdmapt_print_all(struct vmac_priv *vmp);
extern void vmac_tx_dmapt_init(struct vmac_priv *vmp);
extern void vmac_rx_dmapt_init(struct vmac_priv *vmp);
extern void pcie_dma_rd_aie_handle(struct vmac_priv *vmp);
extern void pcie_dma_wr_aie_handle(struct vmac_priv *vmp);
extern int pcie_dma_dev_init(struct net_device *);
extern void pcie_dma_dev_exit(void);

#endif /* DWC_PCIE_DMA_H_ */
