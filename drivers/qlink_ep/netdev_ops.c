/**
 * Copyright (c) 2015 - 2016 Quantenna Communications, Inc.
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
 **/

#define pr_fmt(fmt)	"%s: " fmt, __func__

#include <linux/netdevice.h>
#include <linux/rtnetlink.h>

#include "netdev_ops.h"

int qlink_bridge_addif(struct net_device *br, struct net_device *ndev)
{
	struct ifreq ifr;
	int ret;

	ifr.ifr_ifindex = ndev->ifindex;

	if (!br->netdev_ops->ndo_do_ioctl) {
		pr_err("invalid operation for %s\n", netdev_name(br));
		return -EIO;
	}

	rtnl_lock();
	ret = br->netdev_ops->ndo_do_ioctl(br, &ifr, SIOCBRADDIF);
	rtnl_unlock();

	return ret;
}

int qlink_bridge_delif(struct net_device *br, struct net_device *ndev)
{
	struct ifreq ifr;
	int ret;

	ifr.ifr_ifindex = ndev->ifindex;

	if (!br->netdev_ops->ndo_do_ioctl) {
		pr_err("invalid operation for %s\n", netdev_name(br));
		return -EIO;
	}

	rtnl_lock();
	ret = br->netdev_ops->ndo_do_ioctl(br, &ifr, SIOCBRDELIF);
	rtnl_unlock();

	return ret;
}

int qlink_if_up(struct net_device *ndev)
{
	unsigned int flags;
	int ret = 0;

	rtnl_lock();

	flags = dev_get_flags(ndev);
	if (flags & IFF_UP) {
		rtnl_unlock();
		return 0;
	}

	flags |= IFF_UP;

	ret = dev_change_flags(ndev, flags);
	rtnl_unlock();

	return ret;
}

int qlink_if_down(struct net_device *ndev)
{
	unsigned int flags;
	int ret = 0;

	rtnl_lock();

	flags = dev_get_flags(ndev);
	if (!(flags & IFF_UP)) {
		rtnl_unlock();
		return 0;
	}

	flags &= ~IFF_UP;

	ret = dev_change_flags(ndev, flags);
	rtnl_unlock();

	return ret;
}
