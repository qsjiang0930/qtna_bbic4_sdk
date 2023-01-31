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

#ifndef _QLINK_EP_NETDEV_OPS_H_
#define _QLINK_EP_NETDEV_OPS_H_

#include <linux/netdevice.h>

int qlink_bridge_addif(struct net_device *br, struct net_device *ndev);
int qlink_bridge_delif(struct net_device *br, struct net_device *ndev);

int qlink_if_up(struct net_device *ndev);
int qlink_if_down(struct net_device *ndev);

#endif /* _QLINK_EP_NETDEV_OPS_H_ */
