/**
 * Copyright (c) 2016 - 2017 Quantenna Communications Inc
 * All Rights Reserved
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

/*
 * This file defines a firmware information section, which contains
 * firmware version for sanity checking.
 */
#ifndef _QTN_FW_INFO_H_
#define _QTN_FW_INFO_H_

#define FW_INFO_SECTION		".fwinfo"
/*
 * defining memory address for this section is to make sure it is easy
 * to be found and won't be stripped, we won't actually load the section.
 */
#define FW_INFO_MEM_ADDR	0xFFFF0000
#define FW_INFO_MEM_SIZE	0xFFFF
#define FW_INFO_MEMORY		FWINFO_MEM: ORIGIN=FW_INFO_MEM_ADDR LENGTH=FW_INFO_MEM_SIZE
#define FW_INFO_ADD_SECTION	GROUP : { FW_INFO_SECTION ALIGN(4): { *(FW_INFO_SECTION) } } > FWINFO_MEM

#ifndef __ASSEMBLY__
#include <qtn/qdrv_bld.h>

#define FW_INFO_IDENT		"FWINFO"
#define FW_INFO_IDENT_SIZE	8
#define FW_INFO_REV		1

struct qtn_fw_info {
	char fwinfo_ident[FW_INFO_IDENT_SIZE];
	uint32_t fwinfo_rev;
	uint32_t fwinfo_fw_version;
};

#define FW_INFO_DATA_SIZE (sizeof(struct qtn_fw_info))

#define FW_INFO_SEGMENT_FOUND(_vaddr, _filesz, _pdata) \
	(((_vaddr) == FW_INFO_MEM_ADDR) && \
	 ((_filesz) >= FW_INFO_DATA_SIZE) && \
	 !strncmp(((struct qtn_fw_info *)(_pdata))->fwinfo_ident, FW_INFO_IDENT, strlen(FW_INFO_IDENT)))

#define FW_INFO_CHECK_DATA(_fwinfo, _match, _print)	do {			\
	if ((_fwinfo)->fwinfo_rev != FW_INFO_REV)				\
		_print("Mismatched fw info revision 0x%x - expected 0x%x\n",	\
			(_fwinfo)->fwinfo_rev, FW_INFO_REV);			\
	else if ((_fwinfo)->fwinfo_fw_version != QDRV_BLD_VER)			\
		_print("Firmware version 0x%x does not match lhost version 0x%x\n",	\
				(_fwinfo)->fwinfo_fw_version, QDRV_BLD_VER);	\
	else			\
		_match = 1;	\
} while(0)

#define FW_INFO_ADD_DATA	\
	struct qtn_fw_info _fwinfo = {	\
		FW_INFO_IDENT,		\
		FW_INFO_REV,		\
		QDRV_BLD_VER		\
	}
#endif /* __ASSEMBLY__ */
#endif /* _QTN_FW_INFO_H_ */
