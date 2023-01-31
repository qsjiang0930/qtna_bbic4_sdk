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

#ifndef _QLINK_EP_COMMAND_H_
#define _QLINK_EP_COMMAND_H_

#include <linux/types.h>
#include <linux/device.h>

#include "qlink_priv.h"

void qlink_process_command(struct qlink_server *qs, const struct qlink_cmd *cmd);
int qlink_cmd_sysfs_register(struct device *dev);
void qlink_cmd_sysfs_unregister(struct device *dev);

extern void br_fdb_delete_by_port(struct net_bridge *br,
				  const struct net_bridge_port *p, int do_all);

#endif /* _QLINK_EP_COMMAND_H_ */
