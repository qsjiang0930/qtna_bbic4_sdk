/**
 * Copyright (c) 2016 Quantenna Communications, Inc.
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
 **/

#ifndef _QTN_PCIE_SHM_DEFS_H_
#define _QTN_PCIE_SHM_DEFS_H_

#define QTN_SHM_REG_HDR_SZ	(32)
#define QTN_SHM_REG_SZ		(4096)
#define QTN_SHM_MAX_DATA_SZ	(QTN_SHM_REG_SZ - QTN_SHM_REG_HDR_SZ)

struct qtn_pcie_shm_region_header {
	__le32 flags;
	__le16 data_len;
} __attribute__((__packed__));

union qtn_pcie_shm_region_headroom {
	struct qtn_pcie_shm_region_header hdr;
	u8 headroom[QTN_SHM_REG_HDR_SZ];
} __attribute__((__packed__));

struct qtn_pcie_shm_region {
	union qtn_pcie_shm_region_headroom headroom;
	u8 data[QTN_SHM_MAX_DATA_SZ];
} __attribute__((__packed__));

#endif
