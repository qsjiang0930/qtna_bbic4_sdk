/**
 * Copyright (c) 2011-2017 Quantenna Communications Inc
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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include "qvsp_nl.h"
#include "qvsp_private.h"

void qvsp_netdbg_exit(struct qvsp_c *qvsp)
{
	if (qvsp == NULL) {
		return;
	}
	qvsp_nl_netdbg_exit(qvsp);
}
EXPORT_SYMBOL(qvsp_netdbg_exit);

int qvsp_netdbg_init(struct qvsp_c *qvsp,
		void (*cb_logger)(void *token, void *vsp_data, uint32_t size),
		uint32_t interval)
{

	if (qvsp == NULL) {
		return 0;
	}
	qvsp->cb_logger = cb_logger;
	qvsp_nl_netdbg_init(qvsp, interval);

	return 0;
}
EXPORT_SYMBOL(qvsp_netdbg_init);

