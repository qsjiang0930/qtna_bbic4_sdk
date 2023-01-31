/*
 *	qserver internal driver interface wrappers
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

#ifndef DRIVER_H
#define DRIVER_H

#include "qdata.h"


/* driver_ops */

static inline void *
qserver_drv_init(struct qserver_data *qserver,
				  const char *ifname)
{
	if (qserver->driver->init)
		return qserver->driver->init(qserver, ifname);
	return NULL;
}

static inline void
qserver_drv_deinit(struct qserver_data *qserver)
{
	if (qserver->driver->deinit)
		qserver->driver->deinit(qserver->driver_priv);
}

static inline int
qserver_drv_get_device_mode(struct qserver_data *qserver, int *mode)
{
	if (qserver->driver->get_device_mode)
		return qserver->driver->get_device_mode(qserver->driver_priv, mode);
	return 0;
}

static inline int
qserver_drv_get_device_capas(struct qserver_data *qserver, int *capas)
{
	if (qserver->driver->get_device_capas)
		return qserver->driver->get_device_capas(qserver->driver_priv, capas);
	return 0;
}

static inline int
qserver_drv_get_device_connect_status(struct qserver_data *qserver,
	int *status)
{
	if (qserver->driver->get_device_connect_status)
		return qserver->driver->get_device_connect_status(qserver->driver_priv,
				status);
	return 0;
}

static inline struct qserver_device_params *
qserver_drv_get_device_params(struct qserver_data *qserver, struct qserver_frm_params *params)
{
	if (qserver->driver->get_device_params)
		return qserver->driver->get_device_params(qserver->driver_priv, params);
	return NULL;
}

static inline struct qserver_device_params *
qserver_drv_local_parse_device_params(struct qserver_data *qserver)
{
	if (qserver->driver->local_parse_device_params)
		return qserver->driver->local_parse_device_params(qserver->driver_priv);
	return NULL;
}

static inline void
qserver_drv_free_device_params(struct qserver_data *qserver,
	struct qserver_device_params *params)
{
	if (qserver->driver->free_device_params)
		qserver->driver->free_device_params(qserver->driver_priv, params);
}

static inline int
qserver_drv_should_deliver_device_params(struct qserver_data *qserver,
	struct qserver_frm_params *params, int *deliver)
{
	if (qserver->driver->should_deliver_device_params)
		return qserver->driver->should_deliver_device_params(qserver->driver_priv,
				params, deliver);
	return 0;
}

static inline int
qserver_drv_should_accept_device_params(struct qserver_data *qserver,
	struct qserver_frm_params *params, int *deliver)
{
	if (qserver->driver->should_accept_device_params)
		return qserver->driver->should_accept_device_params(qserver->driver_priv,
				params, deliver);
	return 0;
}

static inline void
qserver_drv_save_device_params_to_file(struct qserver_data *qserver,
		struct qserver_device_params *params)
{
	if (qserver->driver->save_device_params_to_file)
		return qserver->driver->save_device_params_to_file(
				qserver->driver_priv,
				qserver->params_filename,
				params);
}

static inline int
qserver_drv_set_device_secu_daemon_params(struct qserver_data *qserver,
	struct qserver_device_params *params)
{
	if (qserver->driver->set_device_secu_daemon_params)
		return qserver->driver->set_device_secu_daemon_params(qserver->driver_priv,
				params);
	return 0;
}

static inline int
qserver_drv_set_device_runtime_params(struct qserver_data *qserver,
	struct qserver_device_params *params)
{
	if (qserver->driver->set_device_runtime_params)
		return qserver->driver->set_device_runtime_params(qserver->driver_priv,
				params);
	return 0;
}

static inline int
qserver_drv_update_device(struct qserver_data *qserver)
{
	if (qserver->driver->update_device)
		return qserver->driver->update_device(qserver->driver_priv);
	return 0;
}

static inline int
qserver_drv_restore_device(struct qserver_data *qserver)
{
	if (qserver->driver->restore_device)
		return qserver->driver->restore_device(qserver->driver_priv);
	return 0;
}


#endif	/* DRIVER_H */
