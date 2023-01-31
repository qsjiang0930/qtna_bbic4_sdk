/*
 *		link_switch_sm.h
 *
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */


#ifndef LINK_SWITCH_SM_H
#define LINK_SWITCH_SM_H

#include "commons.h"

#define LINK_SWITCH_PROBE_TIMEOUT	120
#define LINK_SWITCH_PROBE_INTERVAL	10
#define LINK_SWITCH_PROBE_SUCCESS_THRE	2
#define LINK_SWITCH_SYNC_INTERVAL	10
#define LINK_SWITCH_SYNC_RETRIES_THRE	3
#define LINK_SWITCH_ALIVE_INTERVAL	10
#define LINK_SWITCH_ALIVE_FAIL_THRE	3


enum link_sw_state
{
	LINK_SW_INIT = 0,
	LINK_SW_PROBE = 1,
	LINK_SW_SYNC = 2,
	LINK_SW_LOCAL_PARSE = 3,
	LINK_SW_UPDATE = 4,
	LINK_SW_ALIVE = 5,
	LINK_SW_RESTORE = 6,
};

struct link_config_device
{
	struct dl_list list;

	uint8_t dev_addr[ETH_ALEN];
	int probe_success;
};

struct link_sw_data
{
	void *ctx;	/* back pointer */
	char ifname[IFNAMSIZ + 1];

	int state;

	uint8_t dest_addr[ETH_ALEN];

	int probe_interval;
	int probe_dev_num;
	struct dl_list config_devs;

	int sync_interval;
	int sync_retry;
	int sync_success;

	int local_parse_success;

	int alive_fail;
};


static inline void
link_switch_set_dest_addr(struct link_sw_data *data, uint8_t *dest)
{
	memcpy(data->dest_addr, dest, ETH_ALEN);
}

char *link_switch_state2str(int state);
int link_switch_sm_step(struct link_sw_data *data, int new_state);
int link_switch_get_state(struct link_sw_data *data);
void link_switch_reset_state(struct link_sw_data *data);
void link_switch_update_frm_exch_state(struct link_sw_data *data,
		int frm_state,  uint8_t *source_addr);
int link_switch_sm_init(struct link_sw_data *data, const char *ifname, void *ctx);
void link_switch_sm_deinit(struct link_sw_data *data);
int link_switch_get_config_devices(struct link_sw_data *data, char *buf, int buf_size);


#endif /* LINK_SWITCH_SM_H */
