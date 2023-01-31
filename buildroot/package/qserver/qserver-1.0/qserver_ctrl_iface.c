/*
 *		qserver control interface
 *
 * It's mainly used to receive the commands from qserver_cli
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
#include "qdata.h"
#include "eloop.h"
#include "list.h"


static int
qserver_ctrl_iface_reset_state(struct qserver_data *qserver)
{
	link_switch_reset_state(&qserver->ls_data);

	return 0;
}

static int
qserver_ctrl_iface_start_probe(
	struct qserver_data *qserver, char *buf)
{
	uint8_t dest[ETH_ALEN];
	int interval = 0;
	char *pos;

	pos = strchr(buf, ' ');
	if (pos) {
		*pos++ = '\0';
		interval = atoi(pos);
	}

	if (os_hwaddr_aton(buf, dest)) {
		os_fprintf(stderr, "%s: invalid address %s\n",
				__func__, buf);
		return -1;
	}

	link_switch_reset_state(&qserver->ls_data);
	link_switch_set_dest_addr(&qserver->ls_data, dest);
	if (interval != 0)
		qserver->ls_data.probe_interval = interval;

	link_switch_sm_step(&qserver->ls_data, LINK_SW_PROBE);

	return 0;
}

static int
qserver_ctrl_iface_start_sync(
	struct qserver_data *qserver, char *buf)
{
	uint8_t dest[ETH_ALEN];
	int interval = 0;
	char *pos;

	pos = strchr(buf, ' ');
	if (pos) {
		*pos++ = '\0';
		interval = atoi(pos);
	}

	if (os_hwaddr_aton(buf, dest)) {
		os_fprintf(stderr, "%s: invalid address %s\n",
				__func__, buf);
		return -1;
	}

	link_switch_reset_state(&qserver->ls_data);
	link_switch_set_dest_addr(&qserver->ls_data, dest);
	if (interval != 0)
		qserver->ls_data.sync_interval = interval;

	link_switch_sm_step(&qserver->ls_data, LINK_SW_SYNC);

	return 0;
}

static int
qserver_ctrl_iface_start_update(struct qserver_data *qserver)
{
	link_switch_reset_state(&qserver->ls_data);

	link_switch_sm_step(&qserver->ls_data, LINK_SW_UPDATE);

	return 0;
}

static int
qserver_ctrl_iface_get_state(struct qserver_data *qserver,
	char *reply, int reply_size)
{
	struct link_sw_data *ls_data = &qserver->ls_data;
	char *state_str;

	state_str = link_switch_state2str(ls_data->state);
	snprintf(reply, reply_size, "%s\n", state_str);

	return strnlen(reply, reply_size);
}

static int
qserver_ctrl_iface_get_config_devices(struct qserver_data *qserver,
	char *reply, int reply_size)
{
	return link_switch_get_config_devices(&qserver->ls_data, reply, reply_size);
}

static int
qserver_ctrl_iface_get_sync_result(struct qserver_data *qserver,
	char *reply, int reply_size)
{
	struct link_sw_data *ls_data = &qserver->ls_data;
	char *result;

	if ((ls_data->state == LINK_SW_INIT) ||
		(ls_data->state == LINK_SW_PROBE))
		result = "INITIAL";
	else if (ls_data->sync_success != 0)
		result = "SYNC_SUCCESS";
	else if (ls_data->state == LINK_SW_SYNC)
		result = "SYNC_PROGRESS";
	else if (ls_data->local_parse_success != 0)
		result = "LOCAL_PARSE_SUCCESS";
	else
		result = "FAILURE";

	snprintf(reply, reply_size, "%s\n", result);

	return strnlen(reply, reply_size);
}

static char *
qserver_ctrl_iface_process(struct qserver_data *qserver_d,
	char *buf, size_t *resp_len)
{
	int reply_size = QSERVER_CTRL_IFACE_MSG_BUFSIZE;
	char *reply;
	int reply_len;

	reply = os_zalloc(reply_size);
	if (reply == NULL) {
		*resp_len = 1;
		return NULL;
	}

	memcpy(reply, "OK\n", 3);
	reply_len = 3;

	if (strncmp(buf, "START_PROBE ", 12) == 0) {
		if (qserver_ctrl_iface_start_probe(qserver_d, buf + 12))
			reply_len = -1;
	} else if (strncmp(buf, "START_SYNC ", 11) == 0) {
		if (qserver_ctrl_iface_start_sync(qserver_d, buf + 11))
			reply_len = -1;
	} else if (strncmp(buf, "START_UPDATE", 12) == 0) {
		if (qserver_ctrl_iface_start_update(qserver_d))
			reply_len = -1;
	} else if (strncmp(buf, "RESET_STATE", 11) == 0) {
		if (qserver_ctrl_iface_reset_state(qserver_d))
			reply_len = -1;
	} else if (strncmp(buf, "GET_STATE", 9) == 0) {
		reply_len = qserver_ctrl_iface_get_state(qserver_d,
					reply, reply_size);
	} else if (strncmp(buf, "GET_CONFIG_DEVICES", 18) == 0) {
		reply_len = qserver_ctrl_iface_get_config_devices(qserver_d,
					reply, reply_size);
	} else if (strncmp(buf, "GET_SYNC_RESULT", 15) == 0) {
		reply_len = qserver_ctrl_iface_get_sync_result(qserver_d,
					reply, reply_size);
	} else {
		memcpy(reply, "UNKNOWN COMMAND\n", 16);
		reply_len = 16;
	}

	if (reply_len < 0) {
		memcpy(reply, "FAIL\n", 5);
		reply_len = 5;
	}

	*resp_len = reply_len;

	return reply;
}


static void
qserver_ctrl_iface_receive(int sock, void *eloop_ctx,
		void *sock_ctx UNUSED_PARAM)
{
	struct qserver_ctrl_iface_data *ciface =
			(struct qserver_ctrl_iface_data *)eloop_ctx;
	struct qserver_data *qserver_d =
			(struct qserver_data *)ciface->ctx;
	struct sockaddr_un from;
	socklen_t fromlen = sizeof(from);
	char buf[QSERVER_CTRL_IFACE_MSG_BUFSIZE] = {0};
	char *reply = NULL;
	size_t reply_len = 0;
	int res;

	res = recvfrom(sock, buf, sizeof(buf) - 1, 0,
		       (struct sockaddr *)&from, &fromlen);
	if (res < 0) {
		perror("recvfrom(ctrl_iface)");
		return;
	}
	buf[res] = '\0';

	reply = qserver_ctrl_iface_process(qserver_d, buf, &reply_len);
	if (reply) {
		sendto(sock, reply, reply_len, 0, (struct sockaddr *)&from,
		       fromlen);
		free(reply);
	} else if (reply_len == 1) {
		sendto(sock, "FAIL\n", 5, 0, (struct sockaddr *)&from,
		       fromlen);
	}
}


int
qserver_ctrl_iface_init(struct qserver_ctrl_iface_data *ciface,
	const char *ifname, void *ctx)
{
	struct sockaddr_un addr;

	strncpy(ciface->ifname, ifname, IFNAMSIZ);
	snprintf(ciface->un_path, QSERVER_PATH_MAX, "%s/%s",
			QSERVER_CTRL_IFACE_DIR, ifname);

	ciface->sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (ciface->sock < 0) {
		os_fprintf(stderr, "%s: fail to open unix socket\n", __func__);
		goto fail;
	}

	if (mkdir(QSERVER_CTRL_IFACE_DIR, S_IRWXU | S_IRWXG) < 0) {
		if (errno == EEXIST) {
			os_fprintf(stdout, "%s: using existing control "
				   "interface directory\n", __func__);
		} else {
			perror("mkdir[ctrl_interface]");
			goto fail;
		}
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, ciface->un_path, sizeof(addr.sun_path));
	if (bind(ciface->sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		os_fprintf(stderr, "%s: fail to bind unix socket with path %s"
			" since %s\n", __func__, ciface->un_path, strerror(errno));
		if (connect(ciface->sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			os_fprintf(stderr, "%s: unix socket exists, but does not"
				   " allow connections - assuming it was left"
				   "over from forced program termination", __func__);

			if (unlink(ciface->un_path) < 0) {
				perror("unlink[ctrl_iface]");
				os_fprintf(stderr, "Could not unlink existing "
					   "ctrl_iface '%s'", ciface->un_path);
				goto fail;
			}

			if (bind(ciface->sock, (struct sockaddr *)&addr,
					sizeof(addr)) < 0) {
				perror("bind(ctrl_iface)");
				goto fail;
			}
			os_fprintf(stderr, "%s: successfully replaced leftover "
				   "ctrl_iface socket '%s'", ciface->un_path);
		} else {
			os_fprintf(stderr, "%s: ctrl_iface %s exists and seems to "
				   "be in use - cannot override it", __func__,
				   ciface->un_path);
			os_fprintf(stderr, "%s: delete '%s' manually if it is "
				   "not used anymore", __func__, ciface->un_path);

			goto fail;
		}
	}

	if (chmod(ciface->un_path, S_IRWXU | S_IRWXG) < 0) {
		perror("chmod[ctrl_iface]");
		goto fail;
	}

	os_fprintf(stdout, "%s: open control interface to recieve commands\n",
				__func__);

	ciface->ctx = ctx;

	eloop_register_read_sock(ciface->sock, qserver_ctrl_iface_receive,
				 ciface, NULL);

	return 0;

fail:
	ciface->ctx = NULL;

	if (ciface->sock >= 0) {
		close(ciface->sock);
		ciface->sock = -1;
	}

	if (strlen(ciface->un_path)) {
		unlink(ciface->un_path);
		memset(ciface->un_path, 0, sizeof(ciface->un_path));
	}

	return -1;
}


void
qserver_ctrl_iface_deinit(struct qserver_ctrl_iface_data *ciface)
{
	os_fprintf(stdout, "%s: close control interface\n", __func__);

	ciface->ctx = NULL;

	if (ciface->sock > -1) {
		eloop_unregister_read_sock(ciface->sock);

		close(ciface->sock);
		ciface->sock = -1;
	}

	if (strlen(ciface->un_path)) {
		unlink(ciface->un_path);
		memset(ciface->un_path, 0, sizeof(ciface->un_path));

		if (rmdir(QSERVER_CTRL_IFACE_DIR) < 0) {
			if (errno == ENOTEMPTY)
				os_fprintf(stdout, "%s: control interface "
					   "directory not empty - leaving it behind\n",
					   __func__);
			else
				perror("rmdir[ctrl_interface]");
		}

	}
}


