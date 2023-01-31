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

#ifndef __QPROC_MON_H_
#define __QPROC_MON_H_
#define _GNU_SOURCE

#include <sys/socket.h>
#include <sys/param.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>
#include <stdarg.h>
#include <qtn_logging.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <syslog.h>

#define QPROC_MON_MAX_CMD_LEN			1024
#define QPROC_MON_MAX_ARGS			32

/* Default list of processes to be monitored */
#define QPROC_MON_CONFIG			"/etc/qproc_mon.conf"
#define QPROC_MON_STATE_FILE			"/tmp/qproc_mon_state"
#define QPROC_MON_STATE_FILE_TEMP		"/tmp/qproc_mon_state_temp"

#define QEVT_MAX_MSG_LEN			1024
#define QEVT_SEND_EVENT_CMD			"/sbin/qevt_send_event"

#define QPROC_MON_PROJ_ID			104 /* Magic number, using for generating MQ key */
#define QPROC_MON_LAUNCH_START_MSG_TYPE		1
#define QPROC_MON_LAUNCH_STOP_MSG_TYPE		2
#define QPROC_MON_CONFIG_VERBOSITY_MSG_TYPE	3

#define QPROC_MON_FIFO				"/tmp/qproc_mon_fifo"

#define log_message(level, fmt, ...) _qproc_mon_log_message(level, fmt"\n", ##__VA_ARGS__)

enum {
	MESG_INFO, MESG_ERROR
};

struct  __attribute__((__packed__)) qproc_mon_message {
	unsigned int	type;
	unsigned int	cmd_args_len;
	char		cmd_args[QPROC_MON_MAX_CMD_LEN];
};

struct qproc_mon_mq_buffer {
	long				mtype;
	struct qproc_mon_message	message;
};

struct qproc_mon_pid_node {
	pid_t	pid;
	struct qproc_mon_pid_node *next;
};

struct qproc_mon_node {
	struct qproc_mon_pid_node	*pid_head;
	int				exec_flag;
	char				cmd_args[QPROC_MON_MAX_CMD_LEN];
	struct qproc_mon_node		*next;
};

struct qproc_mon_state {
	int			conn_sock;
	int			launch_fifo_fd;
	int			launch_mqid;
	struct qproc_mon_node	*active_list;
	struct qproc_mon_node	*pending_list;
};

#endif /* __QPROC_MON_H_ */

