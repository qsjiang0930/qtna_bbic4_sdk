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

#ifndef __QTN_QVSP_NL_H__
#define __QTN_QVSP_NL_H__

#include "qvsp_private.h"

void qvsp_lock(void);
void qvsp_unlock(void);

int qvsp_nl_bus_init(void);
void qvsp_nl_bus_exit(void);
int qvsp_nl_service_init(struct qvsp_c *qvsp);
void qvsp_nl_service_exit(struct qvsp_c *qvsp);
void qvsp_nl_fat_set(struct qvsp_c *qvsp, uint32_t fat, uint32_t intf_ms, uint8_t chan);
void qvsp_nl_stats_update_add(struct qvsp_c *qvsp, struct ieee80211_node *ni, uint16_t node,
				uint8_t tid, uint32_t pkts, uint32_t bytes,
				uint32_t sent_pkts, uint32_t sent_bytes);
void qvsp_nl_stats_node_update_begin(struct qvsp_c *qvsp, struct ieee80211_node *ni);
void qvsp_nl_stats_node_update_end(struct qvsp_c *qvsp, struct ieee80211_node *ni);
void qvsp_nl_stats_node_del(struct qvsp_c *qvsp, struct ieee80211_node *ni);
void qvsp_nl_node_init(struct ieee80211_node *ni);
void qvsp_nl_node_del(struct qvsp_c *qvsp, struct ieee80211_node *ni);
void qvsp_nl_cfg_set(struct qvsp_c *qvsp, uint32_t index, uint32_t value);
void qvsp_nl_inactive_flag_set(struct qvsp_c *qvsp, uint32_t value);
void qvsp_nl_stamode_change(struct qvsp_c *qvsp, uint8_t stamode);
void qvsp_nl_strm_reset(struct qvsp_c *qvsp);
void qvsp_nl_netdbg_init(struct qvsp_c *qvsp, uint32_t interval);
void qvsp_nl_netdbg_exit(struct qvsp_c *qvsp);

#endif
