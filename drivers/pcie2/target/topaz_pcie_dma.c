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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/ctype.h>
#include <linux/interrupt.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <asm/io.h>
#include <linux/moduleloader.h>
#include <asm/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/system.h>

#include "qdpc_config.h"
#include "topaz_vnet.h"
#include "topaz_pcie_dma.h"

#include "../tqe/topaz_pcie_tqe.h"

static void wdmapt_print_range(struct vmac_priv *vmp, uint16_t s, int num)
{
	int i;
	int j;
	char idxflg[5];
	uint16_t n = s;
	struct pcie_dma_ll_data *ptd;

	printk("wDMA:vaddr baddr\t\tctrl\t\tsize\t\tsrc\t\tdst\n");
	for (i = 0; i < num; i++) {
		j = 0;
		if (n == vmp->tx_toDMA_s)
			idxflg[j++] = 's';
		if (n == vmp->tx_toDMA_e)
			idxflg[j++] = 'e';
		idxflg[j] = 0;

		printk("%d %s\n", n, idxflg);
		ptd = &vmp->tx_dmapt_va[2 * n];
		printk("%p\t%p:\t%08x\t%08x\t%08x\t%08x\n",
			ptd, &vmp->tx_dmapt_ba[2 * n],
			ptd->data_info, ptd->ll_trans_size,
			ptd->ll_sar_low, ptd->ll_dar_low);
		ptd++;
		printk("%p\t%p:\t%08x\t%08x\t%08x\t%08x\n",
			ptd, &vmp->tx_dmapt_ba[2 * n + 1],
			ptd->data_info, ptd->ll_trans_size,
			ptd->ll_sar_low, ptd->ll_dar_low);

		VMAC_INDX_INC(n, vmp->tx_bd_num);
	}
}

void vmac_wdmapt_print(struct vmac_priv *vmp)
{
	uint16_t s;
	int num;

	num  = VMAC_INDX_MINUS(vmp->tx_toDMA_e + 5, vmp->tx_toDMA_s, vmp->tx_bd_num);
	if (num > 16)
		num = 16;
	s = VMAC_INDX_MINUS(vmp->tx_toDMA_s, 2, vmp->tx_bd_num);

	wdmapt_print_range(vmp, s, num);
}

void vmac_wdmapt_print_all(struct vmac_priv *vmp)
{
	wdmapt_print_range(vmp, 0, vmp->tx_bd_num);
}

static void rdmapt_print_range(struct vmac_priv *vmp, uint16_t s, int num)
{
	int i;
	int j;
	char idxflg[5];
	uint16_t n = s;
	struct pcie_dma_ll_data *ptd;

	printk("rDMA:vaddr baddr\t\tctrl\t\tsize\t\tsrc\t\tdst\n");
	for (i = 0; i < num; i++) {
		j = 0;
		if (n == vmp->rx_toDMA_s)
			idxflg[j++] = 's';
		if (n == vmp->rx_toDMA_e)
			idxflg[j++] = 'e';
		if (n == vmp->rx_DMAing)
			idxflg[j++] = 'D';
		idxflg[j] = 0;

		printk("%d %s\n", n, idxflg);
		ptd = &vmp->rx_dmapt_va[n];
		printk("%p\t%p:\t%08x\t%08x\t%08x\t%08x\n",
			ptd, &vmp->rx_dmapt_ba[n],
			ptd->data_info, ptd->ll_trans_size,
			ptd->ll_sar_low, ptd->ll_dar_low);

		VMAC_INDX_INC(n, vmp->rx_bd_num);
	}
}

int __attribute__((section(".sram.pcierx.text"))) pcie_rDMA_ready_no_lock(struct vmac_priv *vmp)
{
	uint32_t regval;
	uint32_t rdma_ch = vmp->rx_channel_index;

	topaz_ep_pcie_writel(DmaChDirRd | rdma_ch, PCIE_DMA_CH_CTXT_IDX);
	regval = (topaz_ep_pcie_readl(PCIE_DMA_CH_CTRL_1_REG) >> 5) & 0x3;

	if (unlikely(regval == PCIE_DMA_RESERVED))
		vmp->rx_dma_reserved++;

	return (regval == PCIE_DMA_STOPPED);
}

int __attribute__((section(".sram.pcierx.text"))) pcie_rDMA_ready(struct vmac_priv *vmp)
{
	uint32_t ret;
	uint32_t flags;

	local_irq_save(flags);

	ret = pcie_rDMA_ready_no_lock(vmp);

	local_irq_restore(flags);

	return ret;
}

int __attribute__((section(".sram.pcierx.text"))) pcie_rDMA_busy(struct vmac_priv *vmp)
{
	uint32_t regval;
	uint32_t flags;
	uint32_t rdma_ch = vmp->rx_channel_index;

	local_irq_save(flags);

	topaz_ep_pcie_writel(DmaChDirRd | rdma_ch, PCIE_DMA_CH_CTXT_IDX);
	regval = (topaz_ep_pcie_readl(PCIE_DMA_CH_CTRL_1_REG) >> 5) & 0x3;

	local_irq_restore(flags);

	return (regval == PCIE_DMA_RUNNING);
}

void __attribute__((section(".sram.pcietx.text"))) pcie_wDMA_trigger(struct vmac_priv *vmp)
{
        struct pcie_dma_ll_data *ptd;
        uint32_t ctrl_val;
        uint32_t temp;
	uint32_t wdma_ch = vmp->tx_channel_index;

	/* last element generate interrupt */
	temp = (uint32_t)vmp->tx_DMA_ctrl;
	vmp->tx_last_ptd->data_info = temp | DMA_LL_DATA_LIE;

	topaz_ep_pcie_writel(DmaChDirWr | wdma_ch, PCIE_DMA_CH_CTXT_IDX);

	if (temp & DMA_LL_DATA_CB)
		ctrl_val = (DmaChCtrlMaskLLe | DmaChCtrlMaskTD | DmaChCtrlMaskCCS);
	else
		ctrl_val = (DmaChCtrlMaskLLe | DmaChCtrlMaskTD);

	topaz_ep_pcie_writel(ctrl_val, PCIE_DMA_CH_CTRL_1_REG);

	temp ^= DMA_LL_DATA_CB;
	ptd = &vmp->tx_dmapt_va[vmp->tx_toDMA_e * 2];
	ptd->data_info = temp;
	vmp->tx_DMA_ctrl = (uint8_t)temp;

	topaz_ep_pcie_writel((unsigned int)&vmp->tx_dmapt_ba[vmp->tx_toDMA_s * 2], PCIE_DMA_LL_PTR_LOW);

	topaz_ep_pcie_writel(wdma_ch, PCIE_DMA_WR_DBELL);

	vmp->tx_dma_pkts += vmp->tx_queue_len;
	if (vmp->tx_queue_len <= PCIE_DMA_ISSUE_LOG_NUM)
		vmp->tx_dma_issue_log[vmp->tx_queue_len - 1]++;
	vmp->tx_queue_len = 0;

	atomic_set(&vmp->wdma_running, 1);
	vmp->tx_toDMA_s = vmp->tx_toDMA_e;
}


void vmac_rdmapt_print(struct vmac_priv *vmp)
{
	int num;
	uint16_t s;

	num  = VMAC_INDX_MINUS(vmp->rx_toDMA_e + 5, vmp->rx_toDMA_s, vmp->rx_bd_num);
	if (num > 16)
		num = 16;
	s = VMAC_INDX_MINUS(vmp->rx_toDMA_s, 2, vmp->rx_bd_num);

	rdmapt_print_range(vmp, s, num);
}

void vmac_rdmapt_print_all(struct vmac_priv *vmp)
{
	rdmapt_print_range(vmp, 0, vmp->rx_bd_num);
}


ssize_t vmac_dmareg2str(struct vmac_priv *vmp, char *buff)
{
	return 0;
}

void vmac_tx_dmapt_init(struct vmac_priv *vmp)
{
	uint16_t i;
	struct pcie_dma_ll_data *ptd;
	struct pcie_dma_ll_desc *ptp;

	ptd = vmp->tx_dmapt_va;

	memset(ptd, 0, SIZE_OF_WDMA_PT(vmp->tx_bd_num));

	for (i = 0; i < vmp->tx_bd_num; i++) {
		ptd = &vmp->tx_dmapt_va[2 * i + 1];
		ptd->ll_trans_size = sizeof(uint32_t);
		ptd->ll_sar_low = (uint32_t)&vmp->tx_flag_ba[i];
		ptd->ll_dar_low = (uint32_t)&vmp->rc_rx_bd_base[i].buff_info;
	}

	ptp = (struct pcie_dma_ll_desc *)(ptd + 1);
	ptp->desc_info = DMA_LL_DESC_LLP;
	ptp->ll_elem_ptr_low = (uint32_t)vmp->tx_dmapt_ba;
	vmp->tx_intr_rc_th = PKTS_NUM_PER_RC_INTR;
}

void vmac_rx_dmapt_init(struct vmac_priv *vmp)
{
	struct pcie_dma_ll_desc *ptp;

	memset(vmp->rx_dmapt_va, 0, SIZE_OF_RDMA_PT(vmp->rx_bd_num));

	ptp = (struct pcie_dma_ll_desc *)(&vmp->rx_dmapt_va[vmp->rx_bd_num]);
	ptp->desc_info = DMA_LL_DESC_LLP;
	ptp->ll_elem_ptr_low = (uint32_t)vmp->rx_dmapt_ba;
	vmp->rx_DMA_ctrl = 0;
	vmp->rx_DMAing = 0;
}

static void pcie_soft_dma_reset(int wr_rd)
{
	uint32_t regval;
	int wait_cnt = 0;

	if (wr_rd == DMA_WR_MODE) {
		topaz_ep_pcie_writel(0x0, PCIE_DMA_WR_ENGINE_ENABLE);
		while ((regval = topaz_ep_pcie_readl(PCIE_DMA_WR_ENGINE_ENABLE)) != 0) {
			if (wait_cnt++ > DMA_RESET_WAIT_CNT) {
				printk("WR DMA soft reset failed! \n");
				break;
			}
		}

		if (wait_cnt <= DMA_RESET_WAIT_CNT) {
			topaz_ep_pcie_writel(0x1, PCIE_DMA_WR_ENGINE_ENABLE);
		}
	} else {
		topaz_ep_pcie_writel(0x0, PCIE_DMA_RD_ENGINE_ENABLE);
		while ((regval = topaz_ep_pcie_readl(PCIE_DMA_RD_ENGINE_ENABLE)) != 0) {
			if (wait_cnt++ > DMA_RESET_WAIT_CNT) {
				printk("RD DMA soft reset failed! \n");
				break;
			}
		}

		if (wait_cnt <= DMA_RESET_WAIT_CNT) {
			topaz_ep_pcie_writel(0x1, PCIE_DMA_RD_ENGINE_ENABLE);
		}
	}
}

static void pcie_init_dma_channel(void)
{
	int32_t regval;
	int i;

	topaz_ep_pcie_writel(0x000001FF, PCIE_DMA_WR_ENGINE_CAW_LOW);
	topaz_ep_pcie_writel(0x00000000, PCIE_DMA_WR_ENGINE_CAW_HIGH);
	topaz_ep_pcie_writel(0x000001FF, PCIE_DMA_RD_ENGINE_CAW_LOW);
	topaz_ep_pcie_writel(0x00000000, PCIE_DMA_RD_ENGINE_CAW_HIGH);
	/* Init DMA writing and reading channel */
	for (i=0; i < PCIE_CHAN_MAX_NUM; i++) {
		regval = i;
		topaz_ep_pcie_writel(regval, PCIE_DMA_CH_CTXT_IDX);
		topaz_ep_pcie_writel((PCIE_DMA_STOPPED << 5), PCIE_DMA_CH_CTRL_1_REG);

		regval = (DmaChDirRd | i);
		wmb();
		topaz_ep_pcie_writel(regval, PCIE_DMA_CH_CTXT_IDX);
		topaz_ep_pcie_writel((PCIE_DMA_STOPPED << 5), PCIE_DMA_CH_CTRL_1_REG);
	}

}

void pcie_dma_rd_aie_handle(struct vmac_priv *vmp)
{
	uint32_t rstat_l;
	uint32_t rstat_h;
	uint32_t abort_stat;
	uint32_t ch_stat;
	int data_len;

	printk("rDMA Abort\n");

	vmp->rdma_ab_cnt++;
	abort_stat = topaz_ep_pcie_readl(PCIE_DMA_RD_INTR_STATUS) & vmp->rx_dma_abort_mask;
	rstat_l = topaz_ep_pcie_readl(PCIE_DMA_RD_ERR_STATUS_LOW);
	rstat_h = topaz_ep_pcie_readl(PCIE_DMA_RD_ERR_STATUS_HIGH);

	printk("Abort Stat: 0x%08x. Error Status Low: 0x%08x High: 0x%08x\n",
		abort_stat, rstat_l, rstat_h);

	topaz_ep_pcie_writel(abort_stat, PCIE_DMA_RD_INTR_CLR);

	if (rstat_l) {
		/* Fatal error, need to be soft reset */
		printk("Fatal read error, need to reset the DMA \n");
		pcie_soft_dma_reset(DMA_RD_MODE);
	} else if (rstat_h) {
		/* Non-Fatal error, need to be retransmitted */
		topaz_ep_pcie_writel(DmaChDirRd, PCIE_DMA_CH_CTXT_IDX);

		ch_stat = (topaz_ep_pcie_readl(PCIE_DMA_CH_CTRL_1_REG) >> 5) & 0x3;
		data_len = topaz_ep_pcie_readl(PCIE_DMA_TRANS_SIZE);
		printk("Channel Status: %d Transfer_len: %d\n", ch_stat, data_len);

		if (data_len != 0)
			topaz_ep_pcie_writel(R_DMA_CH, PCIE_DMA_RD_DBELL);
	}
}

void pcie_dma_wr_aie_handle(struct vmac_priv *vmp)
{
	uint32_t wstat;

	printk("WR DMA Abort interrupt \n");

	wstat = topaz_ep_pcie_readl(PCIE_DMA_WR_ERR_STATUS);

	if (wstat) {
		/* Fatal error, need to be soft reset */
		printk("Fatal Write error, need to reset the DMA \n");
		pcie_soft_dma_reset(DMA_WR_MODE);
	}

	/*
	 * After DMA soft reset, deassert Legacy INTx
	 * and clear PCIe EDMA IRQ mask.
	 */
	if(!vmp->msi_enabled) {
		qdpc_deassert_intx();
		vmac_pcie_edma_enable();
	}
}

int pcie_dma_dev_init(struct net_device *ndev)
{
	uint32_t regval;
	struct vmac_priv *vmp;
	volatile qdpc_pcie_bda_t *bda;
	uint32_t msi_data;

	vmp = netdev_priv(ndev);
	bda = vmp->bda;

	/* PCIE_MSI_BASE should be kept in sync with uboot definition*/
#define PCIE_MSI_BASE 0xE9000050
#define PCIE_MSI_DATA_MASK 0x0000ffff
#define PCIE_MSI_DATA_BITS 16
	msi_data = readl(PCIE_MSI_BASE + PCI_MSI_DATA_64);
	msi_data &= PCIE_MSI_DATA_MASK;
	vmp->msi_data = (uint16_t)msi_data;
	vmp->msi_addr = bda->bda_msi_addr;
	msi_data = ((msi_data << PCIE_MSI_DATA_BITS) | msi_data);

	/* set PCIe Interrupt mask for Fatal error and non-Fatal error */
	regval = readl(PCIE_INTR_MSK_REG);
	regval |= ((1 << BIT_PCIE_FATAL_ERR) | (1 << BIT_PCIE_NONFATAL_ERR));
	writel(regval, PCIE_INTR_MSK_REG);
	/* DMA Write Engine Enable */
	topaz_ep_pcie_writel(0x1, PCIE_DMA_WR_ENGINE_ENABLE);
	/* DMA read Engine Enable */
	topaz_ep_pcie_writel(0x1, PCIE_DMA_RD_ENGINE_ENABLE);

	/* Enable wDMA Done Interrupt */
	topaz_ep_pcie_writel(0x00000000, PCIE_DMA_WR_INTR_MASK);

	/* set msi address register for write channel */
	topaz_ep_pcie_writel(bda->bda_msi_addr, PCIE_DMA_WR_DONE_IMWR_ADDR_LOW);
	topaz_ep_pcie_writel(0x00000000, PCIE_DMA_WR_DONE_IMWR_ADDR_HIGH);
	topaz_ep_pcie_writel(bda->bda_msi_addr, PCIE_DMA_WR_ABORT_IMWR_ADDR_LOW);
	topaz_ep_pcie_writel(0x00000000, PCIE_DMA_WR_ABORT_IMWR_ADDR_HIGH);
	/* set msi data register for write channel */
	topaz_ep_pcie_writel(msi_data, PCIE_DMA_WR_CH_1_0_IMWR_DATA);
	topaz_ep_pcie_writel(msi_data, PCIE_DMA_WR_CH_3_2_IMWR_DATA);
	topaz_ep_pcie_writel(msi_data, PCIE_DMA_WR_CH_5_4_IMWR_DATA);
	topaz_ep_pcie_writel(msi_data, PCIE_DMA_WR_CH_7_6_IMWR_DATA);

	/* set interrup mask for read channel */
	topaz_ep_pcie_writel(0x00000000, PCIE_DMA_RD_INTR_MASK);
	/* set msi address register for read channel */
	topaz_ep_pcie_writel(bda->bda_msi_addr, PCIE_DMA_RD_DONE_IMWR_ADDR_LOW);
	topaz_ep_pcie_writel(0x00000000, PCIE_DMA_RD_DONE_IMWR_ADDR_HIGH);
	topaz_ep_pcie_writel(bda->bda_msi_addr, PCIE_DMA_RD_ABORT_IMWR_ADDR_LOW);
	topaz_ep_pcie_writel(0x00000000, PCIE_DMA_RD_ABORT_IMWR_ADDR_HIGH);
	/* set msi data register for read channel */
	topaz_ep_pcie_writel(msi_data, PCIE_DMA_RD_CH_1_0_IMWR_DATA);
	topaz_ep_pcie_writel(msi_data, PCIE_DMA_RD_CH_3_2_IMWR_DATA);
	topaz_ep_pcie_writel(msi_data, PCIE_DMA_RD_CH_5_4_IMWR_DATA);
	topaz_ep_pcie_writel(msi_data, PCIE_DMA_RD_CH_7_6_IMWR_DATA);

	/* set write linked list abort error enable register
	 * Enable the LLLAIE abort interrupt for Write/Read DMA
	 */
	topaz_ep_pcie_writel((0xFF << 16), PCIE_DMA_WR_LL_ERR_ENABLE);
	topaz_ep_pcie_writel((0xFF << 16), PCIE_DMA_RD_LL_ERR_ENABLE);

	pcie_init_dma_channel();

	regval = readl(RUBY_SYS_CTL_PCIE_INT_MASK);
	writel(regval | (0x1 << 12), RUBY_SYS_CTL_PCIE_INT_MASK); /* Enable pcie dma interrupt */
	/* put index at read channel 0 */
	topaz_ep_pcie_writel(DmaChDirRd, PCIE_DMA_CH_CTXT_IDX);
	return 0;
}
