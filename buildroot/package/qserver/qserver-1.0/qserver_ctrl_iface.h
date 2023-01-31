/*
 *		qserver_ctrl_iface.h
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


#ifndef QSERVER_CTRL_IFACE_H
#define QSERVER_CTRL_IFACE_H

#include "commons.h"

#include <net/if.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <grp.h>


#define QSERVER_CTRL_IFACE_DIR "/var/run/qserver"
#define QSERVER_CTRL_IFACE_MSG_BUFSIZE 1024

struct qserver_ctrl_iface_data {
	void *ctx;	/* back pointer */

	int sock;
	char ifname[IFNAMSIZ + 1];
	char un_path[QSERVER_PATH_MAX + 1];
};

int qserver_ctrl_iface_init(struct qserver_ctrl_iface_data *ciface,
	const char *ifname, void *ctx);
void qserver_ctrl_iface_deinit(struct qserver_ctrl_iface_data *ciface);


#endif /* QSERVER_CTRL_IFACE_H */
