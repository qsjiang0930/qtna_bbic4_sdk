/*
 *		qhop.h
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


#ifndef QHOP_H
#define QHOP_H

#include "commons.h"

#define MD5_MAC_LEN 16
#define MD5_STR_BUF_LEN (MD5_MAC_LEN * 2 + 1)
#define SHA1_ITERATION_NUM 4096

#define QTN_WDS_EXT_SCRIPT "qtn_wds_ext.sh"
#define QTN_WDS_KEY_LEN 32
#define QTN_WPA_PASSPHRASE_MIN_LEN 8
#define QTN_WPA_PASSPHRASE_MAX_LEN 63
#define QTN_WPA_PSK_LEN 64
#define QTN_SSID_MAX_LEN 32
#define PMK_LEN 32

void qserver_handle_wds_ext_event(void *custom);
void *qserver_get_context(void);
void qhop_handle_wds_ext_event(const char *ifname, void *custom);

#endif /* QHOP_H */
