/*
 * (C) Copyright 2007-2017 Quantenna Communications Inc.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */
#define TOPAZ_PLATFORM
#define TOPAZ_FPGA_PLATFORM 0
#define TOPAZ_EMAC_NULL_BUF_WR
#undef TOPAZ_FPGA_UMCTL1
#define PLATFORM_WMAC_MODE ap
#undef PLATFORM_DEFAULT_BOARD_ID
#define ARC_HW_REV_NEEDS_TLBMISS_FIX
#define TOPAZ_SUPPORT_UMM 0
#define TOPAZ_SUPPORT_256MB_DDR 0
#define FLASH_SUPPORT_64KB
#define WPA_TKIP_SUPPORT 0
#define SIGMA_TESTBED_SUPPORT 0
#define TOPAZ_CTRLPKT_TQE
