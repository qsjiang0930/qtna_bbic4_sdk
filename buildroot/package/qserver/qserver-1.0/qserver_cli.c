/*
 *	Qserver command line interface
 *
 * It's mainly used to send the user commands to qserver
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


#include "qserver_ctrl_iface.h"


#define QSERVER_CLI_CTRL_IFACE_CLIENT_DIR "/tmp"
#define QSERVER_CLI_CTRL_IFACE_CLIENT_PREFIX "qserver_cli_ctrl_"
#define QSERVER_CLI_CTRL_IFACE_CMD_BUFSIZE 512

struct qserver_cli_ctrl {
	int s;
	struct sockaddr_un local;
	struct sockaddr_un dest;
};

enum qserver_cli_cmd_flags {
	cli_cmd_flag_none = 0x00,
	cli_cmd_flag_sensitive = 0x01
};

struct qserver_cli_cmd {
	const char *cmd;
	int (*handler)(struct qserver_cli_ctrl *ctrl, int argc, char *argv[]);
	enum qserver_cli_cmd_flags flags;
	const char *usage;
};

static const struct option long_opts_qserver_cli[] = {
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{NULL, 0, NULL, 0 }
};


static inline void
qserver_cli_msg_cb(char *msg, size_t len UNUSED_PARAM)
{
	printf("%s\n", msg);
}

static int qserver_ctrl_request(struct qserver_cli_ctrl *ctrl,
	const char *cmd, size_t cmd_len, char *reply,
	size_t *reply_len, void (*msg_cb)(char *msg, size_t len))
{
	struct timeval tv;
	int res;
	fd_set rfds;

	if (send(ctrl->s, cmd, cmd_len, 0) < 0) {
		printf("%s: fail to send command to qserver control interface\n",
				__func__);
		return -1;
	}

	for (;;) {
		tv.tv_sec = 35;
		tv.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_SET(ctrl->s, &rfds);
		res = select(ctrl->s + 1, &rfds, NULL, NULL, &tv);
		if (res < 0)
			return res;

		if (FD_ISSET(ctrl->s, &rfds)) {
			res = recv(ctrl->s, reply, *reply_len, 0);
			if (res < 0)
				return res;

			if (res > 0 && reply[0] == '<') {
				/* This is an unsolicited message from
				 * qserver, not the reply to the
				 * request. Use msg_cb to report this to the
				 * caller. */
				if (msg_cb) {
					/* Make sure the message is nul
					 * terminated. */
					if ((size_t) res == *reply_len)
						res = (*reply_len) - 1;
					reply[res] = '\0';
					msg_cb(reply, res);
				}
				continue;
			}
			*reply_len = res;
			break;
		} else {
			return -2;
		}
	}

	return 0;
}

static int
qserver_ctrl_command(struct qserver_cli_ctrl *ctrl, char *cmd)
{
	char buf[QSERVER_CLI_CTRL_IFACE_CMD_BUFSIZE] = {0};
	size_t len;
	int ret;

	if (ctrl == NULL) {
		printf("%s: not connected to qserver - command dropped.\n", __func__);
		return -1;
	}

	len = sizeof(buf) - 1;
	ret = qserver_ctrl_request(ctrl, cmd, strlen(cmd), buf, &len,
			       qserver_cli_msg_cb);
	if (ret == -2) {
		printf("%s: '%s' command timed out.\n", __func__, cmd);
		return -2;
	} else if (ret < 0) {
		printf("%s: '%s' command failed.\n", __func__, cmd);
		return -1;
	} else {
		buf[len] = '\0';
		printf("%s", buf);
	}

	return 0;
}

static int
qserver_cli_cmd_help(struct qserver_cli_ctrl *ctrl,
	int argc, char *argv[]);

static int
qserver_cli_cmd_reset_state(struct qserver_cli_ctrl *ctrl,
	int argc UNUSED_PARAM, char *argv[] UNUSED_PARAM)
{
	return qserver_ctrl_command(ctrl, "RESET_STATE");
}

static int
qserver_cli_cmd_start_probe(struct qserver_cli_ctrl *ctrl,
	int argc, char *argv[])
{
	char cmd[QSERVER_CLI_CTRL_IFACE_CMD_BUFSIZE] = {0};
	int res;

	if (argc == 0) {
		printf("%s: need one argument (dest_mac) at least\n", __func__);
		return 0;
	}

	if (argc == 1)
		res = snprintf(cmd, sizeof(cmd), "START_PROBE %s", argv[0]);
	else
		res = snprintf(cmd, sizeof(cmd), "START_PROBE %s %s",
				  argv[0], argv[1]);

	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("%s: too long START_PROBE command\n", __func__);
		return -1;
	}

	return qserver_ctrl_command(ctrl, cmd);
}

static int
qserver_cli_cmd_start_sync(struct qserver_cli_ctrl *ctrl,
	int argc, char *argv[])
{
	char cmd[QSERVER_CLI_CTRL_IFACE_CMD_BUFSIZE] = {0};
	int res;

	if (argc == 0) {
		printf("%s: need one argument (dest_mac) at least\n", __func__);
		return 0;
	}

	if (argc == 1)
		res = snprintf(cmd, sizeof(cmd), "START_SYNC %s", argv[0]);
	else
		res = snprintf(cmd, sizeof(cmd), "START_SYNC %s %s",
				  argv[0], argv[1]);

	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("%s: too long START_SYNC command\n", __func__);
		return -1;
	}

	return qserver_ctrl_command(ctrl, cmd);
}

static int
qserver_cli_cmd_start_update(struct qserver_cli_ctrl *ctrl,
	int argc UNUSED_PARAM, char *argv[] UNUSED_PARAM)
{
	return qserver_ctrl_command(ctrl, "START_UPDATE");
}

static int
qserver_cli_cmd_get_state(struct qserver_cli_ctrl *ctrl,
	int argc UNUSED_PARAM, char *argv[] UNUSED_PARAM)
{
	return qserver_ctrl_command(ctrl, "GET_STATE");
}

static int
qserver_cli_cmd_get_config_devices(struct qserver_cli_ctrl *ctrl,
	int argc UNUSED_PARAM, char *argv[] UNUSED_PARAM)
{
	return qserver_ctrl_command(ctrl, "GET_CONFIG_DEVICES");
}

static int
qserver_cli_cmd_get_sync_result(struct qserver_cli_ctrl *ctrl,
	int argc UNUSED_PARAM, char *argv[] UNUSED_PARAM)
{
	return qserver_ctrl_command(ctrl, "GET_SYNC_RESULT");
}

static struct qserver_cli_cmd qserver_cli_commands[] = {
	{ "help", qserver_cli_cmd_help,
	  cli_cmd_flag_none,
	  " = show this usage help" },
	{ "reset_state", qserver_cli_cmd_reset_state,
	  cli_cmd_flag_none,
	  " = reset state machine" },
	{ "start_probe", qserver_cli_cmd_start_probe,
	  cli_cmd_flag_none,
	  "<dest_mac> [interval]  = start probe with"
	  " <dest_mac> and [interval]" },
	{ "start_sync", qserver_cli_cmd_start_sync,
	  cli_cmd_flag_none,
	  "<dest_mac> [interval]  = start synchronization"
	  " with <dest_mac> and [interval]" },
	{ "start_update", qserver_cli_cmd_start_update,
	  cli_cmd_flag_none,
	  " = start update device" },
	{ "get_state", qserver_cli_cmd_get_state,
	  cli_cmd_flag_none,
	  " = get current state of state machine" },
	{ "get_config_devices", qserver_cli_cmd_get_config_devices,
	  cli_cmd_flag_none,
	  " = get config devices" },
	{ "get_sync_result", qserver_cli_cmd_get_sync_result,
	  cli_cmd_flag_none,
	  " = get synchronization result" },
	{ NULL, NULL, cli_cmd_flag_none, NULL },
};

static int
qserver_cli_cmd_help(struct qserver_cli_ctrl *ctrl UNUSED_PARAM,
	int argc UNUSED_PARAM, char *argv[] UNUSED_PARAM)
{
	int i;

	printf("commands:\n");
	for (i = 0; qserver_cli_commands[i].cmd; i++) {
		printf("%s ", qserver_cli_commands[i].cmd);
		printf("%s\n", qserver_cli_commands[i].usage);
	}

	return 0;
}

static int
qserver_cli_request(struct qserver_cli_ctrl *ctrl, int argc, char *argv[])
{
	struct qserver_cli_cmd *cmd = NULL;
	struct qserver_cli_cmd *match = NULL;
	int count = 0;
	int ret = 0;

	cmd = qserver_cli_commands;
	while (cmd->cmd) {
		if (strncasecmp(argv[0], cmd->cmd, strlen(argv[0])) == 0) {
			match = cmd;
			if (strcasecmp(cmd->cmd, argv[0]) == 0) {
				/* we have an exact match */
				count = 1;
				break;
			}
			count++;
		}
		cmd++;
	}

	if (count > 1) {
		printf("%s: ambiguous command '%s'; possible commands:",
			__func__, argv[0]);

		cmd = qserver_cli_commands;
		while (cmd->cmd) {
			if (strncasecmp(argv[0], cmd->cmd, strlen(argv[0])) == 0)
				printf(" %s", cmd->cmd);
			cmd++;
		}
		printf("\n");
		ret = 1;
	} else if (count == 0) {
		printf("%s: unknown command '%s'\n", __func__, argv[0]);
		ret = 1;
	} else {
		ret = match->handler(ctrl, argc - 1, &argv[1]);
	}

	return ret;
}

static struct qserver_cli_ctrl *
qserver_cli_ctrl_open(const char *ctrl_path)
{
	struct qserver_cli_ctrl *ctrl;
	static int counter = 0;
	int ret;
	size_t res;
	int tries = 0;

	ctrl = os_zalloc(sizeof(*ctrl));
	if (ctrl == NULL)
		return NULL;

	ctrl->s = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (ctrl->s < 0) {
		free(ctrl);
		return NULL;
	}

	ctrl->local.sun_family = AF_UNIX;
	counter++;

try_again:
	ret = snprintf(ctrl->local.sun_path, sizeof(ctrl->local.sun_path),
			  QSERVER_CLI_CTRL_IFACE_CLIENT_DIR "/"
			  QSERVER_CLI_CTRL_IFACE_CLIENT_PREFIX "%d-%d",
			  (int)getpid(), counter);
	if (ret < 0 || (size_t)ret >= sizeof(ctrl->local.sun_path))
		goto fail2;

	tries++;
	if (bind(ctrl->s, (struct sockaddr *)&ctrl->local,
		    sizeof(ctrl->local)) < 0) {
		if (errno == EADDRINUSE && tries < 2) {
			/*
			 * getpid() returns unique identifier for this instance
			 * of qserver_cli_ctrl, so the existing socket file must have
			 * been left by unclean termination of an earlier run.
			 * Remove the file and try again.
			 */
			unlink(ctrl->local.sun_path);
			goto try_again;
		}
		goto fail2;
	}

	ctrl->dest.sun_family = AF_UNIX;
	res = strlcpy(ctrl->dest.sun_path, ctrl_path, sizeof(ctrl->dest.sun_path));
	if (res >= sizeof(ctrl->dest.sun_path))
		goto fail1;

	if (connect(ctrl->s, (struct sockaddr *)&ctrl->dest, sizeof(ctrl->dest)) < 0)
		goto fail1;

	return ctrl;

fail1:
	unlink(ctrl->local.sun_path);

fail2:
	close(ctrl->s);
	free(ctrl);

	return NULL;
}


static void
qserver_cli_ctrl_close(struct qserver_cli_ctrl *ctrl)
{
	if (ctrl == NULL)
		return;
	unlink(ctrl->local.sun_path);
	if (ctrl->s >= 0)
		close(ctrl->s);
	free(ctrl);
}

static inline void
qserver_cli_usage(int status)
{
	fprintf(status ? stderr : stdout,
		"Usage: qserver_cli [-hv] [commands ...]\n"
		"   Transmits commands to qserver daemon\n"
		"   -h,--help      Print this message.\n"
		"   -v,--version   Show version of this program.\n"
		);
	exit(status);
}

static inline void
qserver_cli_version(int status)
{
	fprintf(stdout, "qserver_cli: 1.0\n");
	exit(status);
}

int
main(int argc, char * argv[])
{
	struct qserver_cli_ctrl *qserver_ctrl = NULL;
	char qserver_ctrl_path[QSERVER_PATH_MAX] = {0};
	int ret = 0;
	int opt;

	/* Check command line options */
	while((opt = getopt_long(argc, argv, "hv",
			long_opts_qserver_cli, NULL)) > 0) {
		switch(opt) {
		case 'h':
			qserver_cli_usage(0);
			break;
		case 'v':
			qserver_cli_version(0);
			break;
		default:
			qserver_cli_usage(1);
			break;
		}
	}

	snprintf(qserver_ctrl_path, QSERVER_PATH_MAX, "%s/%s",
			QSERVER_CTRL_IFACE_DIR, QSERVER_DEFAULT_IFACE);
	qserver_ctrl = qserver_cli_ctrl_open(qserver_ctrl_path);
	if (qserver_ctrl == NULL) {
		fprintf(stderr, "qserver_cli: fail to open control interface\n");
		return -1;
	}

	if ((argc - optind) > 0)
		ret = qserver_cli_request(qserver_ctrl, argc - optind, &argv[optind]);

	qserver_cli_ctrl_close(qserver_ctrl);

	return 0;
}

