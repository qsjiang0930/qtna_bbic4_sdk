/**
 * Copyright (c) 2015-2016 Quantenna Communications, Inc.
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

#ifndef QLINK_EP_EVENTS_H_
#define QLINK_EP_EVENTS_H_

#include <linux/types.h>

#include "qlink_priv.h"

struct scan_event_item {
	struct list_head list;
	struct qlink_event *qevent;
};

struct scan_complete_ctx {
	unsigned int macid;
	unsigned int ifidx;
	unsigned int se_cnt;
	struct list_head packet_list;
};

int qlink_events_init(struct qlink_server *qs);
void qlink_events_deinit(struct qlink_server *qs);
int qlink_events_eapol_frame_listen(struct qlink_bss *bss);
void qlink_events_eapol_frame_stop_listen(struct qlink_bss *bss);
int qlink_events_mgmt_init(struct qlink_server *qs);
void qlink_events_mgmt_deinit(struct qlink_server *qs);
void qlink_events_mgmt_bss_deinit(struct qlink_bss *bss);
int qlink_event_sysfs_register(struct device *dev);
void qlink_event_sysfs_unregister(struct device *dev);

#endif /* QLINK_EP_EVENTS_H_ */
