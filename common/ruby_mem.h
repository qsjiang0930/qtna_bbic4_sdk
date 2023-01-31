/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2009 - 2017 Quantenna Communications, Inc.          **
**                                                                           **
**  File        : ruby_mem.h                                                 **
**  Description :                                                            **
**                                                                           **
*******************************************************************************
**                                                                           **
**  Redistribution and use in source and binary forms, with or without       **
**  modification, are permitted provided that the following conditions       **
**  are met:                                                                 **
**  1. Redistributions of source code must retain the above copyright        **
**     notice, this list of conditions and the following disclaimer.         **
**  2. Redistributions in binary form must reproduce the above copyright     **
**     notice, this list of conditions and the following disclaimer in the   **
**     documentation and/or other materials provided with the distribution.  **
**  3. The name of the author may not be used to endorse or promote products **
**     derived from this software without specific prior written permission. **
**                                                                           **
**  Alternatively, this software may be distributed under the terms of the   **
**  GNU General Public License ("GPL") version 2, or (at your option) any    **
**  later version as published by the Free Software Foundation.              **
**                                                                           **
**  In the case this software is distributed under the GPL license,          **
**  you should have received a copy of the GNU General Public License        **
**  along with this software; if not, write to the Free Software             **
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  **
**                                                                           **
**  THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR       **
**  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES**
**  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  **
**  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,         **
**  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT **
**  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,**
**  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY    **
**  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT      **
**  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF **
**  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.        **
**                                                                           **
*******************************************************************************
EH0*/

/*
 * Header file which describes Ruby platform.
 * Has to be used by runtime firmware.
 */

#ifndef __RUBY_MEM_H
#define __RUBY_MEM_H

#include "common_mem.h"

/* FIXME: Move CPU related macros to a separate header file. */
#define ARC_DCACHE_LINE_LENGTH			32

/* NEVTBD - put in real XYMEM values */
#define RUBY_DSP_XYMEM_BEGIN			0xD0000000
#define RUBY_DSP_XYMEM_END			0xDFFFFFFF

/* SRAM layout */

#ifdef QTN_RC_ENABLE_HDP
#define TOPAZ_HBM_BUF_EMAC_RX_COUNT_S		(14)
#define TOPAZ_HBM_BUF_WMAC_RX_COUNT_S		(0)
#else
#define TOPAZ_HBM_BUF_EMAC_RX_COUNT_S		(13)
#define TOPAZ_HBM_BUF_WMAC_RX_COUNT_S		(11)
#endif
#define TOPAZ_HBM_EMAC_TX_DONE_COUNT_S		(12)

#define TOPAZ_HBM_BUF_EMAC_RX_COUNT		(1 << TOPAZ_HBM_BUF_EMAC_RX_COUNT_S)
#define TOPAZ_HBM_BUF_WMAC_RX_COUNT		(1 << TOPAZ_HBM_BUF_WMAC_RX_COUNT_S)
#define TOPAZ_HBM_EMAC_TX_DONE_COUNT		(1 << TOPAZ_HBM_EMAC_TX_DONE_COUNT_S)

/* dedicated SRAM space for HBM pointer pools */
#define TOPAZ_HBM_POOL_PTR_SIZE			4	/* sizeof(void *), 32 bit arch */
#define TOPAZ_HBM_POOL_EMAC_RX_START		0x00000000
#define TOPAZ_HBM_POOL_EMAC_RX_SIZE		(TOPAZ_HBM_BUF_EMAC_RX_COUNT * TOPAZ_HBM_POOL_PTR_SIZE)
#define TOPAZ_HBM_POOL_EMAC_RX_END		(TOPAZ_HBM_POOL_EMAC_RX_START + TOPAZ_HBM_POOL_EMAC_RX_SIZE)
#define TOPAZ_HBM_POOL_WMAC_RX_START		TOPAZ_HBM_POOL_EMAC_RX_END
#define TOPAZ_HBM_POOL_WMAC_RX_SIZE		(TOPAZ_HBM_BUF_WMAC_RX_COUNT * TOPAZ_HBM_POOL_PTR_SIZE)
#define TOPAZ_HBM_POOL_WMAC_RX_END		(TOPAZ_HBM_POOL_WMAC_RX_START + TOPAZ_HBM_POOL_WMAC_RX_SIZE)
#define TOPAZ_HBM_POOL_EMAC_TX_DONE_START	TOPAZ_HBM_POOL_WMAC_RX_END
#define TOPAZ_HBM_POOL_EMAC_TX_DONE_SIZE	(TOPAZ_HBM_EMAC_TX_DONE_COUNT * TOPAZ_HBM_POOL_PTR_SIZE)
#define TOPAZ_HBM_POOL_EMAC_TX_DONE_END		(TOPAZ_HBM_POOL_EMAC_TX_DONE_START + TOPAZ_HBM_POOL_EMAC_TX_DONE_SIZE)
#define TOPAZ_FWT_SW_START			TOPAZ_HBM_POOL_EMAC_TX_DONE_END
#define TOPAZ_FWT_SW_SIZE			(4096)
#define TOPAZ_FWT_SW_END			(TOPAZ_FWT_SW_START + TOPAZ_FWT_SW_SIZE)

#define CONFIG_MUC_EXTRA_RES_BASE		TOPAZ_FWT_SW_END
#define CONFIG_MUC_EXTRA_RESERVE_SIZE		(8 * 1024)
#define CONFIG_MUC_EXTRA_RES_END		(CONFIG_MUC_EXTRA_RES_BASE + CONFIG_MUC_EXTRA_RESERVE_SIZE)

#define CONFIG_ARC_KERNEL_SRAM_B1_BASE		ROUNDUP(CONFIG_MUC_EXTRA_RES_END, CONFIG_ARC_KERNEL_PAGE_SIZE)
#define CONFIG_ARC_KERNEL_SRAM_B1_SIZE		(22 * 1024)
#define CONFIG_ARC_KERNEL_SRAM_B1_END		(CONFIG_ARC_KERNEL_SRAM_B1_BASE + CONFIG_ARC_KERNEL_SRAM_B1_SIZE)

#define CONFIG_ARC_KERNEL_SRAM_FRAG1_BASE	ROUNDUP(CONFIG_MUC_EXTRA_RES_END, ARC_DCACHE_LINE_LENGTH)
#if (CONFIG_ARC_KERNEL_SRAM_FRAG1_BASE + ARC_DCACHE_LINE_LENGTH >= CONFIG_ARC_KERNEL_SRAM_B1_BASE)
#define CONFIG_ARC_KERNEL_SRAM_FRAG1_SIZE	0
#else
#define CONFIG_ARC_KERNEL_SRAM_FRAG1_SIZE	(CONFIG_ARC_KERNEL_SRAM_B1_BASE - CONFIG_ARC_KERNEL_SRAM_FRAG1_BASE)
#endif
#define CONFIG_ARC_KERNEL_SRAM_FRAG1_END	(CONFIG_ARC_KERNEL_SRAM_FRAG1_BASE + CONFIG_ARC_KERNEL_SRAM_FRAG1_SIZE)

#define CONFIG_ARC_KERNEL_SRAM_B2_BASE		CONFIG_ARC_KERNEL_SRAM_B1_END
#define CONFIG_ARC_KERNEL_SRAM_B2_END		ROUNDUP(CONFIG_ARC_KERNEL_SRAM_B2_BASE, RUBY_SRAM_BANK_SIZE)
#define CONFIG_ARC_KERNEL_SRAM_B2_SIZE		(CONFIG_ARC_KERNEL_SRAM_B2_END - CONFIG_ARC_KERNEL_SRAM_B2_BASE)
#define CONFIG_ARC_MUC_SRAM_B1_BASE		ROUNDUP(CONFIG_ARC_KERNEL_SRAM_B2_END, CONFIG_ARC_KERNEL_PAGE_SIZE)
#define CONFIG_ARC_MUC_SRAM_B1_END		ROUNDUP(CONFIG_ARC_MUC_SRAM_B1_BASE + 1, RUBY_SRAM_BANK_SIZE)
#define CONFIG_ARC_MUC_SRAM_B1_SIZE		(CONFIG_ARC_MUC_SRAM_B1_END - CONFIG_ARC_MUC_SRAM_B1_BASE)
#define CONFIG_ARC_MUC_SRAM_B2_BASE		ROUNDUP(CONFIG_ARC_MUC_SRAM_B1_END, RUBY_SRAM_BANK_SIZE)
#define CONFIG_ARC_MUC_SRAM_B2_SIZE		(RUBY_SRAM_BANK_SAFE_SIZE - RUBY_CRUMBS_SIZE)
#define CONFIG_ARC_MUC_SRAM_B2_END		(CONFIG_ARC_MUC_SRAM_B2_BASE + CONFIG_ARC_MUC_SRAM_B2_SIZE)
#define CONFIG_ARC_AUC_SRAM_BASE		ROUNDUP(CONFIG_ARC_MUC_SRAM_B2_END, RUBY_SRAM_BANK_SIZE)

#define CONFIG_ARC_AUC_MU_SRAM_SIZE		(3 * RUBY_SRAM_BANK_SIZE)
#define CONFIG_ARC_AUC_MU_SRAM_END		(CONFIG_ARC_AUC_SRAM_BASE + CONFIG_ARC_AUC_MU_SRAM_SIZE)
#define CONFIG_ARC_AUC_NOMU_SRAM_SIZE		(4 * RUBY_SRAM_BANK_SIZE)
#define CONFIG_ARC_AUC_NOMU_SRAM_END		(CONFIG_ARC_AUC_SRAM_BASE + CONFIG_ARC_AUC_NOMU_SRAM_SIZE)

/* MU TxBF qmatrix is stored at the last bank of SRAM, DSP writes to it, has to use SRAM BUS addr.
 * WARN: CONFIG_ARC_MU_QMAT_* defines are only valid if MU-enabled AuC FW is running,
 * since in non-MU AuC FW case MU QMat SRAM bank is used by AuC.
 */
#define CONFIG_ARC_MU_QMAT_BASE		(RUBY_SRAM_BUS_BEGIN + 7 * RUBY_SRAM_BANK_SIZE)
#define CONFIG_ARC_MU_QMAT_SIZE		RUBY_SRAM_BANK_SIZE
#define CONFIG_ARC_MU_QMAT_END		(CONFIG_ARC_MU_QMAT_BASE + CONFIG_ARC_MU_QMAT_SIZE)

#define CONFIG_ARC_SRAM_END		RUBY_SRAM_SIZE

#if TOPAZ_RX_ACCELERATE
	/* TODO FIXME - MuC crashed when copying data between SRAM and DDR */
	#define CONFIG_ARC_MUC_STACK_OFFSET		(CONFIG_ARC_MUC_SRAM_B2_END - 2048)
#else
	#define CONFIG_ARC_MUC_STACK_OFFSET		(CONFIG_ARC_MUC_SRAM_B2_END)
#endif

#if CONFIG_ARC_MUC_STACK_OFFSET_UBOOT != CONFIG_ARC_MUC_STACK_OFFSET
	#error "CONFIG_ARC_MUC_STACK_OFFSET_UBOOT must be equal to CONFIG_ARC_MUC_STACK_OFFSET!"
#endif

#define CONFIG_ARC_MUC_STACK_INIT	(RUBY_SRAM_BEGIN + CONFIG_ARC_MUC_STACK_OFFSET)

#define RUBY_CRUMBS_OFFSET		(CONFIG_ARC_MUC_SRAM_B2_END)

#if RUBY_CRUMBS_OFFSET != RUBY_CRUMBS_OFFSET_UBOOT
	#error "RUBY_CRUMBS_OFFSET_UBOOT must be equal to RUBY_CRUMBS_OFFSET!"
#endif

#define RUBY_CRUMBS_ADDR		(RUBY_SRAM_BEGIN + RUBY_CRUMBS_OFFSET)

/* DDR layout  */
#define CONFIG_ARC_PCIE_RSVD_SIZE	(64 * 1024)
#define CONFIG_ARC_DSP_BASE		(CONFIG_ARC_NULL_END + CONFIG_ARC_PCIE_RSVD_SIZE)
#define CONFIG_ARC_DSP_SIZE		(768 * 1024)
#define CONFIG_ARC_DSP_END		(CONFIG_ARC_DSP_BASE + CONFIG_ARC_DSP_SIZE)
#define CONFIG_ARC_MUC_BASE		CONFIG_ARC_DSP_END
#ifdef TOPAZ_128_NODE_MODE
#define CONFIG_ARC_MUC_SIZE		((3 * 1024 * 1024) + (584 * 1024))
#else
#define CONFIG_ARC_MUC_SIZE		((2 * 1024 * 1024) + (772 * 1024))
#endif
#define MUC_DRAM_RX_RESVERED_RELOC_SIZE		(8 * 1024)
#define CONFIG_ARC_MUC_END		(CONFIG_ARC_MUC_BASE + CONFIG_ARC_MUC_SIZE)
#define CONFIG_ARC_MUC_MAPPED_BASE	CONFIG_ARC_MUC_BASE
#define CONFIG_ARC_MUC_MAPPED_SIZE	(RUBY_MAX_DRAM_SIZE - CONFIG_ARC_MUC_MAPPED_BASE)

#define CONFIG_ARC_AUC_BASE		CONFIG_ARC_MUC_END
#define CONFIG_ARC_AUC_SIZE		(1024 * 1024 + 768 * 1024 + 40 * 1024)
#define CONFIG_ARC_AUC_END		(CONFIG_ARC_AUC_BASE + CONFIG_ARC_AUC_SIZE)
#define TOPAZ_HBM_BUF_ALIGN		(1 * 1024)

#define TOPAZ_HBM_BUF_EMAC_RX_POOL	0
#define TOPAZ_HBM_BUF_WMAC_RX_POOL	1
#define TOPAZ_HBM_AUC_FEEDBACK_POOL	2
#define TOPAZ_HBM_EMAC_TX_DONE_POOL	3

#define TOPAZ_HBM_BUF_EMAC_RX_SIZE	(2 * 1024)
#define TOPAZ_HBM_BUF_WMAC_RX_SIZE	(17 * 1024)

#define TOPAZ_HBM_BUF_META_SIZE		64		/* keep it 2^n */
#define TOPAZ_HBM_POOL_GUARD_SIZE	(64 * 1024)

#define TOPAZ_HBM_BUF_EMAC_RX_TOTAL	(TOPAZ_HBM_BUF_EMAC_RX_COUNT *	\
						TOPAZ_HBM_BUF_EMAC_RX_SIZE)
#define TOPAZ_HBM_BUF_WMAC_RX_TOTAL	(TOPAZ_HBM_BUF_WMAC_RX_COUNT *	\
						TOPAZ_HBM_BUF_WMAC_RX_SIZE)
#ifdef QTN_RC_ENABLE_HDP
#define TOPAZ_ARC_AUC_DESCR_POOL2_SIZE		(32 * 1024 * 1024)
#define TOPAZ_ARC_AUC_DESCR_POOL2_GUARD_SIZE	0
#define TOPAZ_ARC_AUC_IPC_TEXT_SIZE		0
#define TOPAZ_ARC_AUC_IPC_TEXT_GUARD_SIZE	0
#else
#define TOPAZ_ARC_AUC_DESCR_POOL2_SIZE		(14 * 1024 * 1024 + 512 * 1024)
#define TOPAZ_ARC_AUC_DESCR_POOL2_GUARD_SIZE	(512 * 1024)
#define TOPAZ_ARC_AUC_IPC_TEXT_SIZE		(512 * 1024)
#define TOPAZ_ARC_AUC_IPC_TEXT_GUARD_SIZE	(512 * 1024)
#endif

#define TOPAZ_HBM_BUF_META_BASE		CONFIG_ARC_AUC_END

#define TOPAZ_HBM_BUF_META_EMAC_RX_BASE		(TOPAZ_HBM_BUF_META_BASE + TOPAZ_HBM_BUF_META_SIZE)
#define TOPAZ_HBM_BUF_META_EMAC_RX_BASE_VIRT	(RUBY_DRAM_BEGIN + TOPAZ_HBM_BUF_META_EMAC_RX_BASE)
#define TOPAZ_HBM_BUF_META_EMAC_RX_TOTAL	(TOPAZ_HBM_BUF_EMAC_RX_COUNT * \
							TOPAZ_HBM_BUF_META_SIZE)
#define TOPAZ_HBM_BUF_META_EMAC_RX_END		(TOPAZ_HBM_BUF_META_EMAC_RX_BASE + \
							TOPAZ_HBM_BUF_META_EMAC_RX_TOTAL)

#define TOPAZ_HBM_BUF_META_WMAC_RX_BASE		(TOPAZ_HBM_BUF_META_EMAC_RX_END + TOPAZ_HBM_BUF_META_SIZE)
#define TOPAZ_HBM_BUF_META_WMAC_RX_BASE_VIRT	(RUBY_DRAM_BEGIN + TOPAZ_HBM_BUF_META_WMAC_RX_BASE)
#define TOPAZ_HBM_BUF_META_WMAC_RX_TOTAL	(TOPAZ_HBM_BUF_WMAC_RX_COUNT * \
							TOPAZ_HBM_BUF_META_SIZE)
#define TOPAZ_HBM_BUF_META_WMAC_RX_END		(TOPAZ_HBM_BUF_META_WMAC_RX_BASE + \
							TOPAZ_HBM_BUF_META_WMAC_RX_TOTAL)

#define TOPAZ_HBM_BUF_META_END		(TOPAZ_HBM_BUF_META_WMAC_RX_END + TOPAZ_HBM_BUF_META_SIZE)
#define TOPAZ_HBM_BUF_META_TOTAL	(TOPAZ_HBM_BUF_META_END - TOPAZ_HBM_BUF_META_BASE)

#define CONFIG_ARC_AUC_DESCR_POOL2_BASE	TOPAZ_HBM_BUF_META_END
#define CONFIG_ARC_AUC_DESCR_POOL2_END	(CONFIG_ARC_AUC_DESCR_POOL2_BASE + TOPAZ_ARC_AUC_DESCR_POOL2_SIZE)

#define CONFIG_ARC_AUC_IPC_TEXT_BASE	(CONFIG_ARC_AUC_DESCR_POOL2_END + TOPAZ_ARC_AUC_DESCR_POOL2_GUARD_SIZE)
#define CONFIG_ARC_AUC_IPC_TEXT_END	(CONFIG_ARC_AUC_IPC_TEXT_BASE + TOPAZ_ARC_AUC_IPC_TEXT_SIZE)

#define TOPAZ_HBM_BUF_BASE		ROUNDUP(CONFIG_ARC_AUC_IPC_TEXT_END				\
						+ TOPAZ_ARC_AUC_IPC_TEXT_GUARD_SIZE, TOPAZ_HBM_BUF_ALIGN) + \
						TOPAZ_HBM_POOL_GUARD_SIZE

#define TOPAZ_HBM_BUF_EMAC_RX_BASE	TOPAZ_HBM_BUF_BASE
#define TOPAZ_HBM_BUF_EMAC_RX_BASE_VIRT	(RUBY_DRAM_BEGIN + TOPAZ_HBM_BUF_EMAC_RX_BASE)
#define TOPAZ_HBM_BUF_EMAC_RX_END	(TOPAZ_HBM_BUF_EMAC_RX_BASE +	\
						TOPAZ_HBM_BUF_EMAC_RX_TOTAL)

#define TOPAZ_HBM_BUF_WMAC_RX_BASE	(TOPAZ_HBM_BUF_EMAC_RX_END + TOPAZ_HBM_POOL_GUARD_SIZE)
#define TOPAZ_HBM_BUF_WMAC_RX_BASE_VIRT	(RUBY_DRAM_BEGIN + TOPAZ_HBM_BUF_WMAC_RX_BASE)
#define TOPAZ_HBM_BUF_WMAC_RX_END	(TOPAZ_HBM_BUF_WMAC_RX_BASE +	\
						TOPAZ_HBM_BUF_WMAC_RX_TOTAL)

#define TOPAZ_HBM_BUF_END		(TOPAZ_HBM_BUF_WMAC_RX_END + TOPAZ_HBM_POOL_GUARD_SIZE)

#define TOPAZ_FWT_MCAST_ENTRIES		2048
#define TOPAZ_FWT_MCAST_FF_ENTRIES	1	/* one for all FF addresses */
#define TOPAZ_FWT_MCAST_IPMAP_ENT_SIZE	64	/* sizeof(struct topaz_fwt_sw_ipmap) */
#define TOPAZ_FWT_MCAST_TQE_ENT_SIZE	20	/* sizeof(struct topaz_fwt_sw_mcast_entry) */
/* Tables are cache-line aligned to ensure proper memory flushing. */
#define TOPAZ_FWT_MCAST_IPMAP_SIZE	\
	ROUNDUP(TOPAZ_FWT_MCAST_ENTRIES * TOPAZ_FWT_MCAST_IPMAP_ENT_SIZE,	\
			ARC_DCACHE_LINE_LENGTH)
#define TOPAZ_FWT_MCAST_TQE_SIZE	\
	ROUNDUP(TOPAZ_FWT_MCAST_ENTRIES * TOPAZ_FWT_MCAST_TQE_ENT_SIZE,		\
			ARC_DCACHE_LINE_LENGTH)
#define TOPAZ_FWT_MCAST_TQE_FF_SIZE	\
	ROUNDUP(TOPAZ_FWT_MCAST_FF_ENTRIES * TOPAZ_FWT_MCAST_TQE_ENT_SIZE,	\
			ARC_DCACHE_LINE_LENGTH)

#define TOPAZ_FWT_MCAST_IPMAP_BASE	TOPAZ_HBM_BUF_END
#define TOPAZ_FWT_MCAST_IPMAP_END	(TOPAZ_FWT_MCAST_IPMAP_BASE + TOPAZ_FWT_MCAST_IPMAP_SIZE)
#define TOPAZ_FWT_MCAST_TQE_BASE	TOPAZ_FWT_MCAST_IPMAP_END
#define TOPAZ_FWT_MCAST_TQE_END		(TOPAZ_FWT_MCAST_TQE_BASE + TOPAZ_FWT_MCAST_TQE_SIZE)
#define TOPAZ_FWT_MCAST_TQE_FF_BASE	TOPAZ_FWT_MCAST_TQE_END
#define TOPAZ_FWT_MCAST_TQE_FF_END	(TOPAZ_FWT_MCAST_TQE_FF_BASE + TOPAZ_FWT_MCAST_TQE_FF_SIZE)
#define TOPAZ_FWT_MCAST_END		TOPAZ_FWT_MCAST_TQE_FF_END

/* Offset from DDR beginning, from which memory start to belong to Linux */
#define CONFIG_ARC_KERNEL_MEM_BASE	TOPAZ_FWT_MCAST_END

#if TOPAZ_HBM_BUF_EMAC_RX_BASE & (TOPAZ_HBM_BUF_ALIGN - 1)
	#error EMAC Buffer start not aligned
#endif
#if TOPAZ_HBM_BUF_WMAC_RX_BASE & (TOPAZ_HBM_BUF_ALIGN - 1)
	#error WMAC Buffer start not aligned
#endif
#define CONFIG_ARC_UBOOT_RESERVED_SPACE	(8 * 1024)

/* Linux kernel u-boot image start address, for uncompressed images */
#define CONFIG_ARC_KERNEL_BOOT_BASE	ROUNDUP(CONFIG_ARC_KERNEL_MEM_BASE, \
						CONFIG_ARC_KERNEL_PAGE_SIZE)
/* Linux kernel image start */
#define CONFIG_ARC_KERNEL_BASE		(CONFIG_ARC_KERNEL_BOOT_BASE + CONFIG_ARC_UBOOT_RESERVED_SPACE)
#define CONFIG_ARC_KERNEL_MAX_SIZE	(RUBY_MAX_DRAM_SIZE - CONFIG_ARC_KERNEL_MEM_BASE)
#define CONFIG_ARC_KERNEL_MIN_SIZE	(RUBY_MIN_DRAM_SIZE - CONFIG_ARC_KERNEL_MEM_BASE)

/* AuC tightly coupled memory specification */
#define TOPAZ_AUC_IMEM_ADDR		0xE5000000
#define TOPAZ_AUC_IMEM_SIZE		(32 * 1024)
/* BBIC4 A1 AuC DMEM bottom 4KB: 0xE510_0000 to 0xE510_0FFF is aliased with Wmac1 TCM 0xE514_0000
 * exclude the bottom 4K from DMEM, and reduce the size from 16KB to 12KB.
 * This is fixed in A2.
 */
#define TOPAZ_AUC_DMEM_ADDR		0xE5101000
#define TOPAZ_AUC_DMEM_SIZE		(12 * 1024)
#define TOPAZ_AUC_ALIAS_FIXED_DMEM_SIZE	(16 * 1024)
#define TOPAZ_AUC_MAX_DMEM_SIZE		(16 * 1024)
/***************/

/* Utility functions */
#ifndef __ASSEMBLY__

	#if defined(__CHECKER__)
		#define __sram_text
		#define __sram_data
	#elif defined(__GNUC__)
		/*GCC*/
		#if defined(CONFIG_ARCH_RUBY_NUMA) && defined(__KERNEL__) && defined(__linux__)
			/* Kernel is compiled with -mlong-calls option, so we can make calls between code fragments placed in different memories */
			#define __sram_text_sect_name	".sram.text"
			#define __sram_data_sect_name	".sram.data"
			#define __sram_text
			#define __sram_data
		#else
			#define __sram_text_sect_name	".text"
			#define __sram_data_sect_name	".data"
			#define __sram_text
			#define __sram_data
		#endif
	#else
		#pragma Offwarn(428)
	#endif

	#define __in_mem_range_sram(addr)		__in_mem_range(addr, RUBY_SRAM_BEGIN, RUBY_SRAM_SIZE)
	#define __in_mem_range_sram_nocache(addr)	__in_mem_range(addr, RUBY_SRAM_NOCACHE_BEGIN, RUBY_SRAM_SIZE)
	#define __in_mem_range_dram(addr)		__in_mem_range(addr, RUBY_DRAM_BEGIN, RUBY_MAX_DRAM_SIZE)
	#define __in_mem_range_dram_nocache(addr)	__in_mem_range(addr, RUBY_DRAM_NOCACHE_BEGIN, RUBY_MAX_DRAM_SIZE)
	RUBY_INLINE int is_valid_mem_addr(unsigned long addr)
	{
		if (__in_mem_range(addr, RUBY_SRAM_BEGIN, RUBY_SRAM_SIZE)) {
			return 1;
		} else if (__in_mem_range(addr, RUBY_DRAM_BEGIN, RUBY_MAX_DRAM_SIZE)) {
			return 1;
		}
		return 0;
	}

	#if TOPAZ_MMAP_UNIFIED
		RUBY_WEAK(virt_to_nocache) void* virt_to_nocache(const void *addr)
		{
			unsigned long ret = (unsigned long)addr;
			if (__in_mem_range(ret, RUBY_SRAM_BEGIN, RUBY_SRAM_SIZE)) {
				ret = ret - RUBY_SRAM_BEGIN + RUBY_SRAM_NOCACHE_BEGIN;
			} else if (__in_mem_range(ret, RUBY_DRAM_BEGIN, RUBY_MAX_DRAM_SIZE)) {
				ret = ret - RUBY_DRAM_BEGIN + RUBY_DRAM_NOCACHE_BEGIN;
			} else if (ret < RUBY_HARDWARE_BEGIN) {
				ret = (unsigned long)RUBY_BAD_VIRT_ADDR;
			}
			return (void*)ret;
		}
		RUBY_WEAK(nocache_to_virt) void* nocache_to_virt(const void *addr)
		{
			unsigned long ret = (unsigned long)addr;
			if (__in_mem_range(ret, RUBY_SRAM_NOCACHE_BEGIN, RUBY_SRAM_SIZE)) {
				ret = ret - RUBY_SRAM_NOCACHE_BEGIN + RUBY_SRAM_BEGIN;
			} else if (__in_mem_range(ret, RUBY_DRAM_NOCACHE_BEGIN, RUBY_MAX_DRAM_SIZE)) {
				ret = ret - RUBY_DRAM_NOCACHE_BEGIN + RUBY_DRAM_BEGIN;
			} else if (ret < RUBY_HARDWARE_BEGIN) {
				ret = (unsigned long)RUBY_BAD_VIRT_ADDR;
			}
			return (void*)ret;
		}
	#endif

	#if RUBY_MUC_TLB_ENABLE
		#if TOPAZ_MMAP_UNIFIED
#define is_muc_nocached_address(addr) \
	(__in_mem_range((unsigned long )addr, RUBY_SRAM_NOCACHE_BEGIN, RUBY_SRAM_SIZE) || \
	 (__in_mem_range((unsigned long )addr, RUBY_DRAM_NOCACHE_BEGIN, RUBY_MAX_DRAM_SIZE)))
#define is_muc_cached_address(addr) \
	((unsigned long)addr > RUBY_DRAM_BEGIN) && ((unsigned long)addr < RUBY_HARDWARE_BEGIN)
			#define muc_to_nocache virt_to_nocache
			#define nocache_to_muc nocache_to_virt
		#else
#define is_muc_nocached_address(addr) \
	((muc_to_nocache(addr) == RUBY_BAD_VIRT_ADDR) ? 1 : 0)
#define is_muc_cached_address(addr) \
	((nocache_to_muc(addr) == RUBY_BAD_VIRT_ADDR) ? 1 : 0)

			RUBY_WEAK(muc_to_nocache) void* muc_to_nocache(const void *addr)
			{
				unsigned long ret = (unsigned long)addr;
				if (__in_mem_range(ret, RUBY_SRAM_NOFLIP_BEGIN, RUBY_SRAM_SIZE)) {
					ret = ret - RUBY_SRAM_NOFLIP_BEGIN + RUBY_SRAM_NOFLIP_NOCACHE_BEGIN;
				} else if (__in_mem_range(ret, RUBY_DRAM_NOFLIP_BEGIN, RUBY_MAX_DRAM_SIZE)) {
					ret = ret - RUBY_DRAM_NOFLIP_BEGIN + RUBY_DRAM_NOFLIP_NOCACHE_BEGIN;
				} else if (ret < RUBY_HARDWARE_BEGIN) {
					ret = (unsigned long)RUBY_BAD_VIRT_ADDR;
				}
				return (void*)ret;
			}
			RUBY_WEAK(nocache_to_muc) void* nocache_to_muc(const void *addr)
			{
				unsigned long ret = (unsigned long)addr;
				if (__in_mem_range(ret, RUBY_SRAM_NOFLIP_NOCACHE_BEGIN, RUBY_SRAM_SIZE)) {
					ret = ret - RUBY_SRAM_NOFLIP_NOCACHE_BEGIN + RUBY_SRAM_NOFLIP_BEGIN;
				} else if (__in_mem_range(ret, RUBY_DRAM_NOFLIP_NOCACHE_BEGIN, RUBY_MAX_DRAM_SIZE)) {
					ret = ret - RUBY_DRAM_NOFLIP_NOCACHE_BEGIN + RUBY_DRAM_NOFLIP_BEGIN;
				} else if (ret < RUBY_HARDWARE_BEGIN) {
					ret = (unsigned long)RUBY_BAD_VIRT_ADDR;
				}
				return (void*)ret;
			}
		#endif
		#ifndef MUC_BUILD
			RUBY_INLINE unsigned long muc_to_lhost(unsigned long addr)
			{
				void *tmp = nocache_to_muc((void*)addr);
				if (tmp != RUBY_BAD_VIRT_ADDR) {
					addr = (unsigned long)tmp;
				}
				return (unsigned long)bus_to_virt(addr);
			}
		#endif // #ifndef MUC_BUILD
	#else
		#define muc_to_nocache(x) ((void*)(x))
		#define nocache_to_muc(x) ((void*)(x))
		#ifndef MUC_BUILD
			#define muc_to_lhost(x)   ((unsigned long)bus_to_virt((unsigned long)(x)))
		#endif // #ifndef MUC_BUILD
	#endif // #if RUBY_MUC_TLB_ENABLE

	#ifndef __GNUC__
		/*MCC*/
		#pragma Popwarn()
	#endif

#endif // #ifndef __ASSEMBLY__

/*
 * "Write memory barrier" instruction emulation.
 * Ruby platform has complex net of connected buses.
 * Write transactions are buffered.
 * qtn_wmb() guarantees that all issued earlier and pending writes
 * to system controller, to SRAM and to DDR are completed
 * before qtn_wmb() is finished.
 * For complete safety Linux's wmb() should be defined
 * through qtn_wmb(), but I afraid it would kill performance.
 */
#ifndef __ASSEMBLY__
	#define RUBY_SYS_CTL_SAFE_READ_REGISTER 0xE0000000
	#if defined(__GNUC__) && defined(__i386__)
		#define qtn_wmb()		do {} while(0)
		static inline unsigned long _qtn_addr_wmb(unsigned long *addr) { return *addr; }
		#define qtn_addr_wmb(addr)	_qtn_addr_wmb((unsigned long *)(addr))
		#define qtn_pipeline_drain()	do {} while(0)
	#elif defined(__GNUC__)
		/*GCC*/
		#if defined(__arc__)
			#define qtn_wmb() \
			({ \
				unsigned long temp; \
				__asm__ __volatile__ ( \
					"ld.di %0, [%1]\n\t" \
					"ld.di %0, [%2]\n\t" \
					"ld.di %0, [%3]\n\t" \
					"sync\n\t" \
					: "=r"(temp) \
					: "i"(RUBY_DRAM_BEGIN + CONFIG_ARC_KERNEL_MEM_BASE), "i"(RUBY_SRAM_BEGIN + CONFIG_ARC_KERNEL_SRAM_B1_BASE), "i"(RUBY_SYS_CTL_SAFE_READ_REGISTER) \
					: "memory"); \
			})
			#define qtn_addr_wmb(addr) \
			({ \
				unsigned long temp; \
				__asm__ __volatile__ ( \
					"ld.di %0, [%1]\n\t" \
					"sync\n\t" \
					: "=r"(temp) \
					: "r"(addr) \
					: "memory"); \
				temp; \
			})
			#define qtn_pipeline_drain() \
			({ \
				__asm__ __volatile__ ( \
					"sync\n\t" \
					: : : "memory"); \
			})
		#else
			#define qtn_wmb()
			#define qtn_addr_wmb(addr)	*((volatile uint32_t*)addr)
			#define qtn_pipeline_drain()
		#endif
	#else
		/*MCC*/
		#if _ARCVER >= 0x31/*ARC7*/
			#define _qtn_pipeline_drain() \
				sync
		#else
			#define _qtn_pipeline_drain() \
				nop_s; nop_s; nop_s
		#endif
		_Asm void qtn_wmb(void)
		{
			/*r12 is temporary register, so we can use it inside this function freely*/
			ld.di %r12, [RUBY_DRAM_BEGIN + CONFIG_ARC_MUC_BASE]
			ld.di %r12, [RUBY_SRAM_BEGIN + CONFIG_ARC_MUC_SRAM_B1_BASE]
			ld.di %r12, [RUBY_SYS_CTL_SAFE_READ_REGISTER]
			_qtn_pipeline_drain()
		}
		_Asm u_int32_t qtn_addr_wmb(unsigned long addr)
		{
			%reg addr;
			ld.di %r0, [addr]
			_qtn_pipeline_drain()
		}
		_Asm void qtn_pipeline_drain(void)
		{
			_qtn_pipeline_drain()
		}
	#endif
#endif

#ifndef __ASSEMBLY__
#ifdef __GNUC__
RUBY_INLINE void qtn_cache_topaz_war_dcache_lock(unsigned long aux_reg, unsigned long val)
{
	unsigned long addr;
	unsigned long way_iter;
	unsigned long line_iter;

	asm volatile (
		"	sr	%4, [%3]\n"
		"	mov	%0, 0xA0000000\n"
		"	mov	%1, 0\n"
		"1:	add	%0, %0, 2048\n"
		"	mov	%2, 0\n"
		"2:	sr	%0, [0x49]\n"
		"	add	%0, %0, 32\n"
		"	add	%2, %2, 1\n"
		"	cmp	%2, 64\n"
		"	bne	2b\n"
		"	add	%1, %1, 1\n"
		"	cmp	%1, 4\n"
		"	bne	1b\n"
		: "=r"(addr), "=r"(way_iter), "=r"(line_iter)
		: "r"(aux_reg), "r"(val)
	);
}
#else
_Inline _Asm  void qtn_cache_topaz_war_dcache_lock(unsigned long aux_reg, unsigned long val)
{
	% reg aux_reg, reg val;

	sr	val, [aux_reg]
	mov	%r0, 0xA0000000
	mov	%r1, 0
	1:	add	%r0, %r0, 2048
	mov	%r2, 0
	2:	sr	%r0, [0x49]
	add	%r0, %r0, 32
	add	%r2, %r2, 1
	cmp	%r2, 64
	bne	2b
	add	%r1, %r1, 1
	cmp	%r1, 4
	bne	1b
}
#endif // #ifdef __GNUC__
#endif // #ifndef __ASSEMBLY__

#endif // #ifndef __RUBY_MEM_H
