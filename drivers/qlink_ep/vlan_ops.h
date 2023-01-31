/**
 * Copyright (c) 2015-2017 Quantenna Communications, Inc.
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

#ifndef _QLINK_EP_VLAN_OPS_H_
#define _QLINK_EP_VLAN_OPS_H_

int qlink_qvlan_trunk_add(char *dev_name, u16 vlan_id);
int qlink_qvlan_trunk_del(char *dev_name, u16 vlan_id);

int qlink_qvlan_dynamic_add(char *dev_name, u16 vlan_id);
int qlink_qvlan_dynamic_del(char *dev_name, u16 vlan_id);

#endif /* _QLINK_EP_VLAN_OPS_H_ */
