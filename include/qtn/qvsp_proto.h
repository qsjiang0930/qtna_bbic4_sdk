/**
 * Copyright (c) 2012 - 2017 Quantenna Communications Inc
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

#ifndef _QVSP_PROTO_H_
#define _QVSP_PROTO_H_

#include <linux/if_ether.h>

#define QTM_GENL_FAMILY		"QTM"
#define QTM_GENL_VERSION	1
#define QTM_NETLINK_PORT	0x2686
#define QTM_NETLINK_TIMEOUT	1

enum {
	QTM_ATTR_UNSPEC,
	QTM_ATTR_CTL_INDEX,
	QTM_ATTR_CTL_COUNT,
	QTM_ATTR_CTL_VALUE,
	QTM_ATTR_CTL_PARAM,
	QTM_ATTR_CTL_STATUS,

	QTM_ATTR_NODE_INFO,
	QTM_ATTR_TID_INFO,
	QTM_ATTR_FAT_INFO,
	QTM_ATTR_THROT_METHOD,
	QTM_ATTR_NETDBG_INFO,

	QTM_ATTR_PID,
	QTM_ATTR_VAP_INDEX,
	QTM_ATTR_VAP_MODE,
	QTM_ATTR_VAP_NAME,

	__QTM_ATTR_MAX,
};
#define QTM_ATTR_MAX (__QTM_ATTR_MAX - 1)

#define QTM_ATTR_POLICY { \
	[QTM_ATTR_CTL_INDEX] = {.type = NLA_U32}, \
	[QTM_ATTR_CTL_COUNT] = {.type = NLA_U32}, \
	[QTM_ATTR_CTL_VALUE] = {.type = NLA_U32}, \
	[QTM_ATTR_CTL_STATUS] = {.type = NLA_U32}, \
	[QTM_ATTR_PID] = {.type = NLA_U32}, \
	[QTM_ATTR_VAP_INDEX] = {.type = NLA_U8}, \
	[QTM_ATTR_VAP_MODE] = {.type = NLA_U32}, \
	[QTM_ATTR_VAP_NAME] = {.type = NLA_NUL_STRING}, \
}

enum {
	QTM_CMD_UNSPEC,
	QTM_CMD_REGISTER,
	QTM_CMD_UNREGISTER,
	QTM_CMD_SERVER_GET,
	QTM_CMD_VAP_INIT,
	QTM_CMD_VAP_DEINIT,
	QTM_CMD_NODE_STATS,
	QTM_CMD_FAT_SET,
	QTM_CMD_NODE_INIT,
	QTM_CMD_NODE_DEL,
	QTM_CMD_STATS_NODE_DEL,
	QTM_CMD_STRM_RESET,
	QTM_CMD_STRM_CHECK,
	QTM_CMD_CFG_CB,
	QTM_CMD_THROT_EXT,
	QTM_CMD_STATE_GET,
	QTM_CMD_STATE_SET,
	QTM_CMD_CFG_GET,
	QTM_CMD_CFG_SET,
	QTM_CMD_RULE_ADD,
	QTM_CMD_RULE_DEL,
	QTM_CMD_RULE_DEL_INDEX,
	QTM_CMD_RULE_GETLIST,
	QTM_CMD_STRM_GETLIST,
	QTM_CMD_STRM_GETLIST_SAFE,
	QTM_CMD_STRM_GETLIST_ALL,
	QTM_CMD_STRM_GETLIST_ALL_SAFE,
	QTM_CMD_STATS_GET,
	QTM_CMD_INACTIVE_FLAGS_GET,
	QTM_CMD_INACTIVE_FLAGS_SET,
	QTM_CMD_STAMODE_SET,
	QTM_CMD_NETDBG_INIT,
	QTM_CMD_NETDBG_EXIT,
	QTM_CMD_NETDBG_LOG,
	__QTM_CMD_MAX,
};
#define QTM_CMD_MAX (__QTM_CMD_MAX - 1)

#endif
