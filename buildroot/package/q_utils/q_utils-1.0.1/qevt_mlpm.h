/**
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
**/

#ifndef __QEVT_MLPM_H_
#define __QEVT_MLPM_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <arpa/inet.h>

#define QEVT_DEFAULT_PORT	3490
#define QEVT_RX_BUF_SIZE	1024
#define QEVT_CON_RETRY_DELAY	5U
#define QEVT_MAX_LOG_SIZE	256
#define QEVT_DEF_LOG_DIR	"/mnt/jffs2"
#define QEVT_DEF_LOG_FILE	"mlpm_msg"
#define QEVT_DEF_BAK_LOG_FILE	"mlpm_msg.1"
#define QEVT_DEF_LOG_SIZE	(5*1024)
#define	QEVT_MAX_LOG_FILE_LEN	32
#define	QEVT_MAX_IPADDR_LEN	32
#define QEVT_ID_LEN		4
#define ENABLE_CONFIG_CMD	1
#define ENABLE_CONFIG_EVENT_ID	2

#define MAX_VERSION_LEN		5
#define QEVT_CLIENT_VERSION	"v1.10"
#define QEVT_CONFIG		"QEVT_CONFIG"
#define QEVT_CONFIG_RESET	QEVT_CONFIG"_RESET"
#define QEVT_VERSION		"QEVT_VERSION"
#define QEVT_DEFAULT_CONFIG	QEVT_CONFIG" WPACTRL3:-\n"
#define QEVT_CONFIG_EVENT_ID	"QEVT_CONFIG_EVENT_ID"
#define QEVT_DEFAULT_CONFIG_EVENT_ID	"default:+"
#define CAC_PROMT		"dfs available channel"
#define RADAR_PROMT		"RADAR"
#define CAC_DONE_PROMT		"CAC completed for channel"
#define RADAR_DETECTED		"radar detected, not available channel"
#define CMD_BUFFER_LEN_MAX	128

typedef enum {
	QEVT_GENERAL_FAIL = -2,
	QEVT_PARSING_FAIL = -1,
	QEVT_PARSING_SUCCESS = 0,
	QEVT_PARSING_MAX,
}QEVT_RET_E;

struct qevt_client_config {
	struct sockaddr_in	dest;
	struct in_addr		ip_addr;
	int			client_socket;
	uint16_t		port;
	int			fd;
	char			rxbuffer[QEVT_RX_BUF_SIZE + 1];
	char			*qevt_config_cmd;
};
#endif /* _QEVT_MLPM_H_ */
