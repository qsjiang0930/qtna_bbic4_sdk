/**
 * Copyright (c) 2017 Quantenna Communications Inc
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

#ifndef __QTN_QVSP_CFG_H__
#define __QTN_QVSP_CFG_H__

#include "qvsp_private.h"

int qvsp_ioctl_cmd(struct qvsp_c *qvsp, enum qvsp_cfg_param_e param);
void qvsp_invoke_cfg_cb(struct qvsp_c *qvsp, uint32_t index, uint32_t value);

#endif
