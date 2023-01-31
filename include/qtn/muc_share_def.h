/**
 * Copyright (c) 2014 - 2017 Quantenna Communications Inc
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

#ifndef _MUC_SHARE_DEF_H_
#define _MUUC_SHARE_DEF_H_

#include "../common/ruby_mem.h"

#define QTN_FW_WMAC_RX_Q_MGMT		0
#define QTN_FW_WMAC_RX_Q_CTRL		1
#define QTN_FW_WMAC_RX_Q_DATA		2
#define QTN_FW_WMAC_RX_QNUM		3
#define QTN_FW_WMAC_RX_QDEEP_MGMT	9
#define QTN_FW_WMAC_RX_QDEEP_CTRL	9
#define QTN_FW_WMAC_RX_QDEEP_DATA	394
#define QTN_FW_WMAC_RX_DESC_NUM	(QTN_FW_WMAC_RX_QDEEP_MGMT + \
	QTN_FW_WMAC_RX_QDEEP_CTRL + QTN_FW_WMAC_RX_QDEEP_DATA)

#endif // #ifndef _MUC_SHARE_DEF_H_

