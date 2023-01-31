/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2009 - 2017 Quantenna Communications, Inc.          **
**                                                                           **
**  File        : topaz_config.h                                             **
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
 * Header file which describes Topaz platform.
 * Has to be used by both kernel and bootloader.
 */

#ifndef __TOPAZ_CONFIG_H
#define __TOPAZ_CONFIG_H

#include "current_platform.h"

#if !TOPAZ_FPGA_PLATFORM
#undef TOPAZ_ICACHE_WORKAROUND
#endif

/*
 * Control registers move depending on unified + alias bit
 */
#if TOPAZ_SUPPORT_UMM
#define TOPAZ_MMAP_UNIFIED	1
#else
#define TOPAZ_MMAP_UNIFIED	0
#endif

#define TOPAZ_MMAP_ALIAS	0
#define TOPAZ_RX_ACCELERATE	1

/* If MU-MIMO done in HDP or SDP */
#define QTN_HDP_MU		1

#if TOPAZ_MMAP_UNIFIED
	#define RUBY_MMAP_FLIP		0
	#define TOPAZ_UBOOT_UNIFIED_MAP		1
#else
	#if !(defined(MUC_BUILD) || defined(DSP_BUILD) || defined(AUC_BUILD))
		#define RUBY_MMAP_FLIP		1
	#else
		#define RUBY_MMAP_FLIP		0
	#endif
	#define TOPAZ_UBOOT_UNIFIED_MAP		0
#endif

#if TOPAZ_MMAP_ALIAS && (defined(__linux__) || TOPAZ_UBOOT_UNIFIED_MAP)
	#define RUBY_SYS_CTL_MMAP_REGVAL	(TOPAZ_SYS_CTL_UNIFIED_MAP | TOPAZ_SYS_CTL_ALIAS_MAP)
#elif TOPAZ_MMAP_UNIFIED && (defined(__linux__) || TOPAZ_UBOOT_UNIFIED_MAP)
	#define RUBY_SYS_CTL_MMAP_REGVAL	TOPAZ_SYS_CTL_UNIFIED_MAP
#elif RUBY_MMAP_FLIP || defined(TOPAZ_PLATFORM)
	#define RUBY_SYS_CTL_MMAP_REGVAL	RUBY_SYS_CTL_LINUX_MAP(0x1)
#else
	#undef RUBY_SYS_CTL_MMAP_REGVAL
#endif

#if TOPAZ_MMAP_ALIAS && !TOPAZ_MMAP_UNIFIED
	#error Alias map requires unified map
#endif

#if TOPAZ_MMAP_ALIAS
	#define TOPAZ_ALIAS_MAP_SWITCH(a, b)	(b)
#else
	#define TOPAZ_ALIAS_MAP_SWITCH(a, b)	(a)
#endif

/* Topaz fixed phy addresses */
#define TOPAZ_FPGAA_PHY0_ADDR		2
#define TOPAZ_FPGAA_PHY1_ADDR		3
#define TOPAZ_FPGAB_PHY0_ADDR		4
#define TOPAZ_FPGAB_PHY1_ADDR		1
#define TOPAZ_PHY0_ADDR				1
#define TOPAZ_PHY1_ADDR				3

#ifndef TOPAZ_FPGA_PLATFORM
	#define TOPAZ_FPGA_PLATFORM	0
#endif

/* Definition indicates that Topaz platform is FPGA */
#if TOPAZ_FPGA_PLATFORM
	/* CLK speeds are in MHz and 1/10th the speed of actual ASIC */
	#define TOPAZ_SERIAL_BAUD	38400
	#define TOPAZ_APB_CLK		12500000
	#define TOPAZ_AHB_CLK		25000000
	#define TOPAZ_CPU_CLK		50000000
	#define RUBY_FPGA_DDR
#else
	#define TOPAZ_SERIAL_BAUD	115200
	#define TOPAZ_APB_CLK		125000000
	#define TOPAZ_AHB_CLK		250000000
	#define TOPAZ_CPU_CLK		500000000
	#define RUBY_ASIC_DDR
#endif /* #if TOPAZ_FPGA_PLATFORM */

/*
 * Setting UPF_SPD_FLAG gives a developer the option to set the
 * flag to match a UPF_ define from <linux>/include/linux/serial_core.h
 * or set the value to 0 to use the default baud rate setting DEFAULT_BAUD
 */
#define UPF_SPD_FLAG	0
#define DEFAULT_BAUD	TOPAZ_SERIAL_BAUD

/*
 * Re-use Ruby defines to simplify the number of changes required
 * to compile new binaries for Topaz
 */
#define RUBY_SERIAL_BAUD	TOPAZ_SERIAL_BAUD
#define RUBY_FIXED_DEV_CLK	TOPAZ_APB_CLK
#define RUBY_FIXED_CPU_CLK	TOPAZ_CPU_CLK

#ifdef PLATFORM_DEFAULT_BOARD_ID
        #define DEFAULT_BOARD_ID	PLATFORM_DEFAULT_BOARD_ID
#else
	/* Default board id used to match Topaz setting if there is no SPI Flash */
	#define DEFAULT_BOARD_ID	QTN_TOPAZ_BB_BOARD
#endif /* TOPAZ_DEFAULT_BOARD_ID */

#ifndef PLATFORM_ARC7_MMU_VER
	#define PLATFORM_ARC7_MMU_VER	2
#endif

#define CONFIG_RUBY_BROKEN_IPC_IRQS	0

#define RUBY_IPC_HI_IRQ(bit_num)	((bit_num) + 8)
#define RUBY_M2L_IPC_HI_IRQ(bit_num)	(bit_num)

#define PLATFORM_REG_SWITCH(reg1, reg2)	(reg2)

#define writel_topaz(a, b)		writel(a, b)
#define writel_ruby(a, b)

#define QTN_VLAN_LLC_ENCAP		1

#define TOPAZ_128_NODE_MODE		1

#define TOPAZ_ETH_REFLECT_SW_FWD	0

#define DSP_ENABLE_STATS		1

#endif /* #ifndef __TOPAZ_CONFIG_H */

