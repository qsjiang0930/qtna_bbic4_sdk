/*
 *		qdata.h
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


#ifndef QDATA_H
#define QDATA_H

#include "qserver_frame.h"
#include "qserver_ctrl_iface.h"
#include "link_switch_sm.h"

#include <net/if.h>
#include <linux/netlink.h>


#define QEV_DEV_CAPA_RESP 0x00000001	/* Capability of responsing the exchange fame*/
#define QTN_WDS_EXT_CMD_LEN 256
#define QTN_FILENAME_LENGTH_MAX 255

enum qserver_dev_mode
{
	QSVR_DEV_UNKNOWN = 0,
	QSVR_DEV_MBS = 1,
	QSVR_DEV_RBS = 2,
	QSVR_DEV_REPEATER = 3,
	QSVR_DEV_864_HOST = 4,
	QSVR_DEV_864_CLIENT = 5,
};

enum qserver_connect_status
{
	QSVR_DEV_UNCONNECT = 0,
	QSVR_DEV_WIFI_CONNECT = 1,
	QSVR_DEV_ETH_CONNECT = 2,
};

struct rtnl_handle
{
	int fd;
	struct sockaddr_nl local;
	struct sockaddr_nl peer;
	uint32_t seq;
};

struct qserver_driver_ops
{
	/* name of the driver interface */
	const char *name;
	/* one line discription of the driver interface */
	const char *desc;

	/*
	 * init - initialize the driver interface
	 * @ctx: context to be used to qserver related functions
	 * @ifname: assigned interface name
	 *
	 * Returns: private driver interface data pointer on success,
	 * NULL pointer on failure
	 */
	void * (*init)(void *ctx, const char *ifname);
	/*
	 * deinit - deinitialize the driver interface
	 * @priv: private driver interface data pointer
	 *
	 * Returns: NULL
	 */
	void (*deinit)(void *priv);
	/*
	 * get_device_mode - get device mode
	 * @priv: context to be used to qserver related functions
	 * @mode: returned device mode
	 *
	 * Returns: 0 on success, -1 on failure
	 */
	int (*get_device_mode)(void *priv, int *mode);
	/*
	 * get_device_capa - get device capabilities
	 * @priv: context to be used to qserver related functions
	 * @capas: returned device capabilities
	 *
	 * Returns: 0 on success, -1 on failure
	 */
	int (*get_device_capas)(void *priv, int *capas);
	/*
	 * get_device_connect_status - get device connection status
	 * @priv: context to be used to qserver related functions
	 * @capas: returned device connection status
	 *
	 * Returns: 0 on success, -1 on failure
	 */
	int (*get_device_connect_status)(void *priv, int *status);
	/*
	 * get_device_params - get device parameters
	 * @priv: context to be used to qserver related functions
	 *
	 * Returns: device parameters pointer on success,
	 * NULL pointer on failure
	 *
	 * Note: the returned device parameters pointer must be freed
	 * by using the subsequent callback "free_device_params"
	 */
	struct qserver_device_params * (*get_device_params)(void *priv,
			struct qserver_frm_params *params);

	/*
	 * save_device_params_to_file - save synced params from remote peer to
	 * a local file
	 * @priv: context to be used to qserver related functions
	 * @params_filename: filename path to save params
	 * @params: frame params parsed from query frame
	 *
	 * Returns: NULL
	 */
	void (*save_device_params_to_file)(void *priv,
			const char *params_filename,
			struct qserver_device_params *params);
	/*
	 * local_parse_device_params - get device parameters by
	 * parsing local configuration instead of getting from remote device
	 * @priv: context to be used to qserver related functions
	 *
	 * Returns: device parameters pointer on success,
	 * NULL pointer on failure
	 *
	 * Note: a) the returned device parameters pointer must be freed
	 * by using the subsequent callback "free_device_params" b) the local
	 * parse operation can only works on STA mode and can only get the
	 * primary BSS parameters instead of complete MBSS parameters.
	 */
	struct qserver_device_params * (*local_parse_device_params)(void *priv);
	/*
	 * free_device_params - free the memory which is pointed
	 * by the "params" pointer
	 * @priv: context to be used to qserver related functions
	 * @params: the device parameters pointer which needs to be freed
	 *
	 * Returns: NULL
	 */
	void (*free_device_params)(void *priv, struct qserver_device_params *params);
	/*
	 * should_deliver_device_params - check if the device parameters should
	 * be delivered.
	 * @priv: context to be used to qserver related functions
	 * @params: the frame parameters pointer which parsed from QUERY frame
	 * @deliver: returned deliver state
	 *
	 * Returns: 0 on success, -1 on failure
	 */
	int (*should_deliver_device_params)(void *priv,
			struct qserver_frm_params *params, int *deliver);
	/*
	 * should_accept_device_params - check if the device parameters should
	 * be accepted.
	 * @priv: context to be used to qserver related functions
	 * @params: the frame parameters pointer which parsed from UPDATE frame
	 * @accepted: returned accepted state
	 *
	 * Returns: 0 on success, -1 on failure
	 */
	int (*should_accept_device_params)(void *priv,
			struct qserver_frm_params *params, int *accepted);
	/*
	 * set_device_secu_daemon_params - configure security daemon parameters to device
	 * @priv: context to be used to qserver related functions
	 * @params: the MBSS parameters pointer which needs to be configured
	 *
	 * Returns: 0 on success, -1 on failure
	 */
	int (*set_device_secu_daemon_params)(void *priv, struct qserver_device_params *params);
	/*
	 * set_device_runtime_params - configure runtime parameters to device
	 * @priv: context to be used to qserver related functions
	 * @params: the MBSS parameters pointer which needs to be configured
	 *
	 * Returns: 0 on success, -1 on failure
	 */
	int (*set_device_runtime_params)(void *priv, struct qserver_device_params *params);
	/*
	 * update_device - update device to assigned state
	 * @priv: context to be used to qserver related functions
	 *
	 * Returns: 0 on success, -1 on failure
	 */
	int (*update_device)(void *priv);
	/*
	 * restore_device - restore device to the default state,
	 * it's the opposite operation of "update_device"
	 * @priv: context to be used to qserver related functions
	 *
	 * Returns: 0 on success, -1 on failure
	 */
	int (*restore_device)(void *priv);
};

struct qserver_data
{
	char ifname[IFNAMSIZ + 1];
	int dev_mode;
	int dev_capas;
	int save_params;
	char params_filename[QTN_FILENAME_LENGTH_MAX + 1];

	struct rtnl_handle rth;
	struct qserver_frame_data frm_data;
	struct qserver_ctrl_iface_data ctrl_iface;

	struct qserver_driver_ops *driver;
	void *driver_priv;

	struct link_sw_data ls_data;
};

struct qtn_drv_data
{
	void *ctx; /* back pointer */

	char ifname[IFNAMSIZ + 1];

	char pending_cmd[QTN_WDS_EXT_CMD_LEN];/* pending QHop event(s) */

	int ap_secu_param_changed;
};

static inline char *
qserver_dev_mode2str(int mode)
{
	char *modestr;

	switch (mode) {
	case QSVR_DEV_MBS:
		modestr = "MBS";
		break;
	case QSVR_DEV_RBS:
		modestr = "RBS";
		break;
	case QSVR_DEV_REPEATER:
		modestr = "REPEATER";
		break;
	case QSVR_DEV_864_HOST:
		modestr = "864_HOST";
		break;
	case QSVR_DEV_864_CLIENT:
		modestr = "864_CLIENT";
		break;
	default:
		modestr = "unknown";
		break;
	}

	return modestr;
}

#endif /* QDATA_H */

