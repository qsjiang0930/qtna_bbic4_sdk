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

#include "qproc_mon.h"

void qproc_mon_send_event_usage()
{
	fprintf(stderr, "Usage: qproc_mon_send_event <start> <\"app_name app_arguments\">\n"
			"       qproc_mon_send_event <stop> <\"app_name\">\n"
			"       qproc_mon_send_event <verbosity> <0|1>\n"
			"NOTE: app_name should be with absolute path\n");
}

int main(int argc, char *argv[])
{
	int ret;
	int mqid;
	key_t mq_key;
	size_t len;
	struct qproc_mon_mq_buffer mq_cmd;
	int fd;
	struct qproc_mon_message *msg = &mq_cmd.message;

	if (argc < 3) {
		qproc_mon_send_event_usage();
		return -1;
	}

	memset(msg, 0, sizeof(*msg));

	if (!strcmp(argv[1], "start")) {
		msg->type = QPROC_MON_LAUNCH_START_MSG_TYPE;
	} else if (!strcmp(argv[1], "stop")) {
		msg->type = QPROC_MON_LAUNCH_STOP_MSG_TYPE;
	} else if (!strncmp(argv[1], "verb", 4)) {
		msg->type = QPROC_MON_CONFIG_VERBOSITY_MSG_TYPE;
	} else {
		return -1;
	}

	msg->cmd_args_len = strlen(argv[2]);
	len = msg->cmd_args_len + 1;
	if (len == 1 || len > QPROC_MON_MAX_CMD_LEN)
		return -1;

	strncpy(msg->cmd_args, argv[2], sizeof(msg->cmd_args) - 1);
	len += (sizeof(*msg) - sizeof(msg->cmd_args));

	fd = open(QPROC_MON_FIFO, O_WRONLY | O_NONBLOCK);
	if (fd <= 0) {
		fprintf(stderr, "Failed to open fifo file: %s : %s : %s\n",
					argv[1], argv[2], strerror(errno));
	} else {
		ret = write(fd, msg, len);
		close(fd);
		if (ret == len) {
			return 0;
		}
	}

	mq_key = ftok(QPROC_MON_CONFIG, QPROC_MON_PROJ_ID);
	if (mq_key == -1)
		return -1;

	mqid = msgget(mq_key, IPC_CREAT | 0666);
	if (mqid < 0) {
		fprintf(stderr, "Failed to get message queue: %s : %s : %s\n",
					argv[1], argv[2], strerror(errno));
		return -1;
	}

	mq_cmd.mtype = 1;

	/* len <= 1032, sizeof(struct qproc_mon_message) is 1032, so it's not overrun-buffer. */
	/* coverity[overrun-buffer-arg] */
	ret = msgsnd(mqid, &mq_cmd, len, IPC_NOWAIT);
	if (ret < 0) {
		fprintf(stderr, "Failed to send launch event: %s : %s : %s\n",
					argv[1], argv[2], strerror(errno));
		return -1;
	}

	/*
	 * NB: Don't remove/close the mqid, since it will remove the queue.
	 * Message queue is expected be present until qproc_mon process
	 * reads the messages
	 */

	return 0;
}
