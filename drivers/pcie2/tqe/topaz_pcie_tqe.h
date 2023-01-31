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

#ifndef __TOPAZ_PCIE_TQE_H
#define __TOPAZ_PCIE_TQE_H

#include <qtn/topaz_tqe_cpuif.h>
#include <qtn/topaz_fwt_db.h>

extern int topaz_tqe_pcie_rel_port;

#define PCIE_TQE_INTR_WORKAROUND_DEF \
int __attribute__((section(".sram.data"))) topaz_tqe_pcie_rel_port = TOPAZ_TQE_DSP_PORT;

#define PCIE_TQE_INTR_WORKAROUND_DETECT \
do { \
  topaz_tqe_pcie_rel_port = ((readl(RUBY_SYS_CTL_CSR) & 0xff) == TOPAZ_BOARD_REVB) ? TOPAZ_TQE_DSP_PORT : TOPAZ_TQE_PCIE_PORT; \
} while(0)

#define PCIE_TQE_INTR_WORKAROUND (topaz_tqe_pcie_rel_port == TOPAZ_TQE_DSP_PORT)
#define TOPAZ_TQE_PCIE_REL_PORT topaz_tqe_pcie_rel_port

#define VMAC_PCIE_PORT_ID	TOPAZ_TQE_PCIE_REL_PORT
#define topaz_tqe_pcieif_descr topaz_tqe_cpuif_descr

RUBY_INLINE int
topaz_tqe_pcieif_ppctl_write(const union topaz_tqe_cpuif_ppctl *ctl)
{
	return __topaz_tqe_cpuif_ppctl_write(TOPAZ_TQE_PCIE_REL_PORT, ctl);
}

RUBY_INLINE void
__topaz_tqe_pcieif_tx_start(enum topaz_tqe_port port, const union topaz_tqe_cpuif_ppctl *ctl)
{
	int num = __topaz_tqe_cpuif_ppctl_write(port, ctl);
	qtn_mproc_sync_mem_write(TOPAZ_TQE_CPUIF_TXSTART(num), TOPAZ_TQE_CPUIF_TX_START_NREADY);
}

RUBY_INLINE void
topaz_tqe_pcieif_tx_start(const union topaz_tqe_cpuif_ppctl *ctl)
{
	__topaz_tqe_pcieif_tx_start(TOPAZ_TQE_PCIE_REL_PORT, ctl);
}

RUBY_INLINE void
topaz_tqe_pcieif_setup_reset(int reset)
{
	__topaz_tqe_cpuif_setup_reset(TOPAZ_TQE_PCIE_REL_PORT, reset);
}

RUBY_INLINE void
topaz_tqe_pcieif_setup_ring(union topaz_tqe_cpuif_descr *base, uint16_t count)
{
	__topaz_tqe_cpuif_setup_ring(TOPAZ_TQE_PCIE_REL_PORT, base, count);
}

RUBY_INLINE union topaz_tqe_cpuif_descr*
topaz_tqe_pcieif_get_curr(void)
{
	return __topaz_tqe_cpuif_get_curr(TOPAZ_TQE_PCIE_REL_PORT);
}


RUBY_INLINE void
topaz_tqe_pcieif_put_back(union topaz_tqe_cpuif_descr * descr)
{
	__topaz_tqe_cpuif_put_back(TOPAZ_TQE_PCIE_REL_PORT, descr);
}


RUBY_INLINE union topaz_tqe_cpuif_status
topaz_tqe_pcieif_get_status(void)
{
	return __topaz_tqe_cpuif_get_status(TOPAZ_TQE_PCIE_REL_PORT);
}

RUBY_INLINE void
topaz_tqe_pcieif_wait(void)
{
	topaz_tqe_cpuif_tx_success_cpu_port(NULL, TOPAZ_TQE_PCIE_REL_PORT);
}

#ifdef CONFIG_TOPAZ_PCIE_TARGET
void topaz_pcie_prepare_pp_cntl(union topaz_tqe_cpuif_ppctl *pp_cntl, uint32_t tid,
	fwt_db_entry *fwt_ent, void *data_bus, int data_len, uint16_t misc_user);
int topaz_pcie_tqe_xmit(union topaz_tqe_cpuif_ppctl *pp_cntl);
#else
int topaz_pcie_tqe_xmit(fwt_db_entry *fwt_ent, void *data_bus, int data_len,
	uint16_t vlan_miscuser);
#endif

fwt_db_entry *vmac_get_tqe_ent(const unsigned char *src_mac_be, const unsigned char *dst_mac_be);
struct net_device *tqe_pcie_netdev_init( struct net_device *pcie_ndev);
void tqe_pcie_netdev_term( struct net_device *pcie_ndev);
void tqe_netdev_exit(void);
extern void tqe_pcie_irq_enable(void);
extern void tqe_dsp_irq_enable(void);

struct topaz_qfp_netdev_ops {
	struct net_device_ops       netdev_ops;
	const struct net_device_ops *orig_netdev_ops;
};

#endif

