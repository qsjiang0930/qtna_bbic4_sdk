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
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/kthread.h>


#include <common/topaz_platform.h>
#include <qtn/mproc_sync.h>
#include <asm/hardware.h>

#include "qdpc_config.h"
#include "qdpc_debug.h"
#include "topaz_vnet.h"

#define le32_readl(x)		le32_to_cpu(readl((x)))
#define le32_writel(x, addr)	writel(cpu_to_le32((x)), addr)

void qdpc_pcie_init_intr_cap(struct vmac_priv *priv)
{
    uint16_t flag = 0;

    /* Set default to use Legacy INTx interrupt */
    priv->msi_enabled = 0;

    /* Check if the device has enabled MSI */
    flag = le32_readl(TOPAZ_PCIE_MSI_CAP) >> 16;
    if (!(flag & TOPAZ_PCIE_MSI_EN)) {
        PRINT_INFO("PCIe Legacy INTx Interrupt Enabled\n");
    } else {
        PRINT_INFO("PCIe MSI Interrupt Enabled\n");
        priv->msi_enabled = 1;
    }
}

/* Get Max Payload Size of pcie link, then set DMA src address boundary */
void qdpc_pcie_set_src_align(struct vmac_priv *priv)
{
	int devctl = le32_readl(TOPAZ_PCIE_EXP_DEVCTL);
	devctl = (((devctl & PCI_EXP_DEVCTL_PAYLOAD) >> 5) + 1) << 7;
	priv->eDMA_src_align = devctl >> 1;
}

static inline void qdpc_pcie_posted_write(uint32_t val, void *basereg)
{
	arc_write_uncached_32(basereg, val);
}

static inline int qdpc_isbootstate(struct vmac_priv *p, uint32_t state) {
	__iomem uint32_t *status = (__iomem uint32_t *)&p->bda->bda_bootstate;
	uint32_t s = le32_readl(status);
	return ( s == state);
}

extern uint8_t veth_basemac[];

static inline void qdpc_setbootstate(struct vmac_priv *p, uint32_t state) {
	__iomem qdpc_pcie_bda_t *bda = (__iomem qdpc_pcie_bda_t *)p->bda;

	qdpc_pcie_posted_write(state, &bda->bda_bootstate);
}

static  int qdpc_bootpoll(struct vmac_priv *p, uint32_t state)
{
	unsigned long timeout = jiffies + 20 * HZ;

	while (qdpc_isbootstate(p,state) == 0) {
		if (time_after(jiffies, timeout))
			panic("Polling state %u timeout\n", state);

		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ / 20);
	}

	return 0;
}

static int qdpc_init_work(void *data)
{
	struct vmac_priv *priv = (struct vmac_priv *)data;
	unsigned char macaddr[ETH_ALEN];

	PRINT_INFO("Waiting for host start signal\n");
	qdpc_bootpoll(priv, QDPC_BDA_FW_START);

	//qdpc_pcie_irqsetup(priv->ndev);

	qdpc_setbootstate(priv, QDPC_BDA_FW_CONFIG);

	PRINT_INFO("Enable DMA engines\n");
	qdpc_bootpoll(priv, QDPC_BDA_FW_RUN);
	//qdpc_emac_enable(priv);
	//netif_start_queue(priv->ndev);

	/* Set MAC address used by host side */
	memcpy(macaddr, veth_basemac, ETH_ALEN);
	macaddr[0] = (macaddr[0] & 0x1F) | (((macaddr[0] & 0xE0) + 0x40) & 0xE0) | 0x02;
	/*
	 * The bda_pci_pre_status and bda_pci_endian fields are not used at runtime, so the
	 * MAC address is stored here in order to avoid updating the bootloader.
	 */
	memcpy((void *)&priv->bda->bda_pci_pre_status, macaddr, ETH_ALEN);

	/* Enable IRQ */
	//writel(QDPC_H2EP_INTERRUPT_MASK, RUBY_SYS_CTL_D2L_INT_MASK);

	qdpc_setbootstate(priv, QDPC_BDA_FW_RUNNING);
	PRINT_INFO("Connection established with Host\n");

	return 0;
}

void pcie_notify_rc_rdy(struct net_device *ndev)
{
	struct vmac_priv *priv = netdev_priv(ndev);

	qdpc_init_work(priv);
}

