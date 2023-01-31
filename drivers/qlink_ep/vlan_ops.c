/**
 * Copyright (c) 2015 - 2017 Quantenna Communications, Inc.
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

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>

#include "qlink_priv.h"
#include "vlan_ops.h"

static char *envp[] = { "HOME=/", "PATH=/sbin:/usr/sbin:/bin:/usr/bin:/scripts", NULL };

/*
 * Add VLAN tag to trunk VLAN network interface:
 * $ qvlan <dev_name> trunk <vlanid> add tag none
 *
 */
int qlink_qvlan_trunk_add(char *dev_name, u16 vlan_id)
{
	char *argv[] = { QTNF_QVLAN_SCRIPT, NULL, "trunk", NULL, "add", "tag", "none", NULL };
	char vlan_str[5] = { 0 };

	snprintf(vlan_str, sizeof(vlan_str), "%d", vlan_id);
	argv[1] = dev_name;
	argv[3] = vlan_str;

	return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

/*
 * Remove VLAN tag from trunk VLAN network interface:
 * $ qvlan <dev_name> trunk <vlanid> del tag none
 *
 */
int qlink_qvlan_trunk_del(char *dev_name, u16 vlan_id)
{
	char *argv[] = { QTNF_QVLAN_SCRIPT, NULL, "trunk", NULL, "del", "tag", "none", NULL };
	char vlan_str[5] = { 0 };

	snprintf(vlan_str, sizeof(vlan_str), "%d", vlan_id);
	argv[1] = dev_name;
	argv[3] = vlan_str;

	return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

/*
 * Add VLAN tag to dynamic VLAN network interface:
 * $ qvlan <dev_name> dynamic <vlanid> add
 *
 */
int qlink_qvlan_dynamic_add(char *dev_name, u16 vlan_id)
{
	char *argv[] = { QTNF_QVLAN_SCRIPT, NULL, "dynamic", NULL, "add", NULL };
	char vlan_str[5] = { 0 };

	snprintf(vlan_str, sizeof(vlan_str), "%d", vlan_id);
	argv[1] = dev_name;
	argv[3] = vlan_str;

	return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

/*
 * Remove VLAN tag to dynamic VLAN network interface:
 * $ qvlan <dev_name> dynamic <vlanid> del
 *
 */
int qlink_qvlan_dynamic_del(char *dev_name, u16 vlan_id)
{
	char *argv[] = { QTNF_QVLAN_SCRIPT, NULL, "dynamic", NULL, "del", NULL };
	char vlan_str[5] = { 0 };

	snprintf(vlan_str, sizeof(vlan_str), "%d", vlan_id);
	argv[1] = dev_name;
	argv[3] = vlan_str;

	return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}
