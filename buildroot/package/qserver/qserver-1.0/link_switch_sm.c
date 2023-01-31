/*
 *		link switch state machine
 *
 * It's mainly used to manage the link switch of quantenna
 * private connection.
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

#include "eloop.h"
#include "qdata.h"
#include "driver.h"


static struct link_config_device *
link_switch_find_config_device(struct link_sw_data *data, uint8_t *mac_addr)
{
	struct link_config_device *dev = NULL;
	struct link_config_device *tmp, *priv;

	if (data->probe_dev_num > 0) {
		dl_list_for_each_safe(tmp, priv, &data->config_devs,
				struct link_config_device, list) {
			if (memcmp(mac_addr, tmp->dev_addr, ETH_ALEN) == 0) {
				dev = tmp;
				break;
			}
		}
	}

	return dev;
}

static struct link_config_device *
link_switch_add_config_device(struct link_sw_data *data, uint8_t *mac_addr)
{
	struct link_config_device *dev = NULL;

	dev = link_switch_find_config_device(data, mac_addr);
	if (!dev) {
		dev = os_zalloc(sizeof(*dev));
		if (dev == NULL) {
			os_fprintf(stderr, "%s: fail to allocate config deivce\n",
				__func__);
			return dev;
		}

		os_fprintf(stdout, "%s: add new config device "MACSTR"\n",
			__func__, MAC2STR(mac_addr));

		memcpy(dev->dev_addr, mac_addr, ETH_ALEN);
		dl_list_add_tail(&data->config_devs, &dev->list);
		data->probe_dev_num++;
	}

	return dev;
}

static void
link_switch_destroy_config_devices(struct link_sw_data *data)
{
	struct link_config_device *dev, *prev;

	if (data->probe_dev_num == 0)
		return;

	dl_list_for_each_safe(dev, prev, &data->config_devs,
			      struct link_config_device, list) {
		dl_list_del(&dev->list);
		free(dev);
	}
	data->probe_dev_num = 0;
}

static void
link_switch_dump_config_devices(struct link_sw_data *data)
{
	struct link_config_device *dev, *prev;
	int i = 0;

	if (data->probe_dev_num == 0) {
		os_fprintf(stdout, "No config device is found\n");
		return;
	} else if (data->probe_dev_num == 1) {
		os_fprintf(stdout, "One config device is found\n");
	} else {
		os_fprintf(stdout, "%u config devices are found,"
			" please select one config device from below:\n",
			data->probe_dev_num);
	}

	dl_list_for_each_safe(dev, prev, &data->config_devs,
			      struct link_config_device, list) {
		os_fprintf(stdout, "Device %u: "MACSTR"\n",
				i, MAC2STR(dev->dev_addr));
		i++;
	}

	if (i > data->probe_dev_num)
		os_fprintf(stdout, "%s: incorrect probe_dev_num\n", __func__);
}

int
link_switch_get_config_devices(struct link_sw_data *data,
	char *buf, int buf_size)
{
	struct link_config_device *dev, *prev;
	int len = 0;
	int i = 0;

	snprintf(buf, buf_size, "%d config devices found\n", data->probe_dev_num);

	dl_list_for_each_safe(dev, prev, &data->config_devs,
			      struct link_config_device, list) {
		len = strnlen(buf, buf_size);
		snprintf(buf + len, buf_size - len, "Device %u: "MACSTR"\n",
				i, MAC2STR(dev->dev_addr));
		i++;
	}

	len = strnlen(buf, buf_size);

	return len;
}

static void
link_switch_state_init(struct link_sw_data *data)
{
	os_fprintf(stdout, "%s: enter INIT state\n", __func__);

	data->state = LINK_SW_INIT;

	memcpy(data->dest_addr, broadcast_ethaddr, ETH_ALEN);
	data->probe_interval = LINK_SWITCH_PROBE_INTERVAL;
	data->sync_interval = LINK_SWITCH_SYNC_INTERVAL;
}

static void
link_switch_probe_timeout(void *eloop_ctx, void *timeout_ctx UNUSED_PARAM)
{
	struct qserver_data *qserver = (struct qserver_data *)eloop_ctx;
	struct link_sw_data *data = &qserver->ls_data;
	struct link_config_device *config_dev = NULL;
	int connect_status = QSVR_DEV_UNCONNECT;

	eloop_cancel_timeout(link_switch_probe_timeout, qserver, NULL);
	qserver_stop_query_polling(&qserver->frm_data, data->dest_addr);

	qserver_drv_get_device_connect_status(qserver, &connect_status);
	switch (connect_status) {
	case QSVR_DEV_UNCONNECT:
		link_switch_sm_step(data, LINK_SW_PROBE);
		break;
	case QSVR_DEV_WIFI_CONNECT:
		if (data->probe_dev_num == 0) {
			link_switch_sm_step(data, LINK_SW_PROBE);
		} else if (data->probe_dev_num == 1) {
			config_dev = dl_list_first(&data->config_devs,
					struct link_config_device, list);

			if (config_dev) {
				memcpy(data->dest_addr, config_dev->dev_addr, ETH_ALEN);
				link_switch_sm_step(data, LINK_SW_LOCAL_PARSE);
			} else {
				os_fprintf(stderr, "%s: null config device\n", __func__);
				link_switch_sm_step(data, LINK_SW_INIT);
			}
		} else {
			link_switch_dump_config_devices(data);
			link_switch_sm_step(data, LINK_SW_INIT);
		}
		break;
	case QSVR_DEV_ETH_CONNECT:
		break;
	default:
		break;
	}
}

static void
link_switch_state_probe(struct link_sw_data *data)
{
	struct qserver_data *qserver = (struct qserver_data *)data->ctx;

	os_fprintf(stdout, "%s: enter PROBE state\n", __func__);

	data->state = LINK_SW_PROBE;
	link_switch_destroy_config_devices(data);

	qserver_start_query_polling(&qserver->frm_data,
			data->dest_addr, data->probe_interval);
	eloop_register_timeout(LINK_SWITCH_PROBE_TIMEOUT, 0,
				link_switch_probe_timeout, qserver, NULL);
}

static void
link_switch_state_sync(struct link_sw_data *data)
{
	struct qserver_data *qserver = (struct qserver_data *)data->ctx;

	os_fprintf(stdout, "%s: enter SYNC state\n", __func__);

	data->state = LINK_SW_SYNC;

	data->sync_retry = 0;
	data->sync_success = 0;
	qserver_send_query_frame(&qserver->frm_data, data->dest_addr);
}

static void
link_switch_state_local_parse(struct link_sw_data *data)
{
	struct qserver_data *qserver = (struct qserver_data *)data->ctx;
	struct qserver_device_params *params = NULL;
	int ret;

	os_fprintf(stdout, "%s: enter LOCAL_PARSE state\n", __func__);

	data->state = LINK_SW_LOCAL_PARSE;
	data->local_parse_success = 0;

	params = qserver_drv_local_parse_device_params(qserver);
	if (!params) {
		os_fprintf(stderr, "%s: fail to parse parameter from local\n",
				__func__);
		link_switch_sm_step(data, LINK_SW_INIT);
	} else {
		ret = qserver_store_device_params(&qserver->frm_data, params);
		qserver_drv_free_device_params(qserver, params);

		if (ret < 0) {
			os_fprintf(stderr, "%s: fail to set parameter\n", __func__);
			link_switch_sm_step(data, LINK_SW_INIT);
		} else {
			data->local_parse_success = 1;
			link_switch_sm_step(data, LINK_SW_UPDATE);
		}
	}
}

static int
link_switch_should_goto_keep_alive(struct link_sw_data *data)
{
	struct qserver_data *qserver = (struct qserver_data *)data->ctx;
	int mode = QSVR_DEV_UNKNOWN;
	int keep_alive = 1;
	int ret = 0;

	ret = qserver_drv_get_device_mode(qserver, &mode);
	if (ret >= 0) {
		switch (mode) {
		case QSVR_DEV_MBS:
		case QSVR_DEV_RBS:
		case QSVR_DEV_REPEATER:
			keep_alive = 0;
			break;
		default:
			break;
		}
	}

	os_fprintf(stdout, "%s: state machine would%s go to keep-alive state\n",
			__func__, keep_alive ? "" : " not");

	return keep_alive;
}

static int
link_switch_state_update(struct link_sw_data *data)
{
	struct qserver_data *qserver = (struct qserver_data *)data->ctx;
	int ret;

	os_fprintf(stdout, "%s: enter UPDATE state\n", __func__);

	data->state = LINK_SW_UPDATE;

	ret = qserver_drv_set_device_secu_daemon_params(qserver,
			qserver->frm_data.params);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to set security daemon"
			" parameters\n", __func__);
		goto error;
	}

	ret = qserver_drv_update_device(qserver);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to update device\n", __func__);
		goto error;
	}

	ret = qserver_drv_set_device_runtime_params(qserver,
			qserver->frm_data.params);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to set runtime parameters\n",
				__func__);
		goto error;
	}

	if (link_switch_should_goto_keep_alive(data))
		link_switch_sm_step(data, LINK_SW_ALIVE);

	return 0;

error:
	link_switch_sm_step(data, LINK_SW_INIT);
	return ret;
}

static void
link_switch_state_alive(struct link_sw_data *data)
{
	struct qserver_data *qserver = (struct qserver_data *)data->ctx;

	os_fprintf(stdout, "%s: enter ALIVE state\n", __func__);

	data->state = LINK_SW_ALIVE;

	data->alive_fail = 0;
	qserver_start_query_polling(&qserver->frm_data,
			data->dest_addr, LINK_SWITCH_ALIVE_INTERVAL);
}

static void
link_switch_state_restore(struct link_sw_data *data)
{
	struct qserver_data *qserver = (struct qserver_data *)data->ctx;

	os_fprintf(stdout, "%s: enter RESTORE state\n", __func__);

	data->state = LINK_SW_RESTORE;

	qserver_drv_restore_device(qserver);
	link_switch_sm_step(data, LINK_SW_PROBE);
}

int
link_switch_sm_step(struct link_sw_data *data, int new_state)
{
	switch (new_state) {
	case LINK_SW_INIT:
		link_switch_state_init(data);
		break;
	case LINK_SW_PROBE:
		link_switch_state_probe(data);
		break;
	case LINK_SW_SYNC:
		link_switch_state_sync(data);
		break;
	case LINK_SW_LOCAL_PARSE:
		link_switch_state_local_parse(data);
		break;
	case LINK_SW_UPDATE:
		link_switch_state_update(data);
		break;
	case LINK_SW_ALIVE:
		link_switch_state_alive(data);
		break;
	case LINK_SW_RESTORE:
		link_switch_state_restore(data);
		break;
	default:
		break;
	}

	return 0;
}

int
link_switch_get_state(struct link_sw_data *data)
{
	return data->state;
}

char *
link_switch_state2str(int state)
{
	char *state_str;

	switch (state) {
	case LINK_SW_INIT:
		state_str = "INIT";
		break;
	case LINK_SW_PROBE:
		state_str = "PROBE";
		break;
	case LINK_SW_SYNC:
		state_str = "SYNC";
		break;
	case LINK_SW_LOCAL_PARSE:
		state_str = "LOCAL_PARSE";
		break;
	case LINK_SW_UPDATE:
		state_str = "UPDATE";
		break;
	case LINK_SW_ALIVE:
		state_str = "KEEP_ALIVE";
		break;
	case LINK_SW_RESTORE:
		state_str = "RESTORE";
		break;
	default:
		state_str = "UNKNOWN";
		break;
	}

	return state_str;
}

void
link_switch_reset_state(struct link_sw_data *data)
{
	struct qserver_data *qserver = (struct qserver_data *)data->ctx;

	eloop_cancel_timeout(link_switch_probe_timeout, qserver, NULL);
	qserver_stop_query_polling(&qserver->frm_data, data->dest_addr);

	if ((data->state == LINK_SW_UPDATE) ||
			(data->state == LINK_SW_ALIVE))
		qserver_drv_restore_device(qserver);

	link_switch_sm_step(data, LINK_SW_INIT);
}

static void
link_switch_sync_retry(void *eloop_ctx, void *timeout_ctx UNUSED_PARAM)
{
	struct qserver_data *qserver = (struct qserver_data *)eloop_ctx;
	struct link_sw_data *data = &qserver->ls_data;

	eloop_cancel_timeout(link_switch_sync_retry, qserver, NULL);

	os_fprintf(stdout, "%s: SYNC fails and retry again\n", __func__);
	qserver_send_query_frame(&qserver->frm_data, data->dest_addr);
}

void
link_switch_update_frm_exch_state(struct link_sw_data *data,
	int frm_state, uint8_t *source_addr)
{
	struct qserver_data *qserver = (struct qserver_data *)data->ctx;
	struct link_config_device *probe_dev = NULL;
	struct link_config_device *config_dev = NULL;

	switch (data->state) {
	case LINK_SW_PROBE:
		if (source_addr) {
			probe_dev = link_switch_add_config_device(data, source_addr);
			if (!probe_dev) {
				os_fprintf(stderr, "%s: fail to add probe device\n",
						__func__);
				break;
			}

			if (frm_state == RECV_ACK)
				probe_dev->probe_success++;
		}

		if (data->probe_dev_num == 1) {
			config_dev = dl_list_first(&data->config_devs,
					struct link_config_device, list);
		}

		if (config_dev && (config_dev->probe_success >
				LINK_SWITCH_PROBE_SUCCESS_THRE)) {
			qserver_stop_query_polling(&qserver->frm_data, data->dest_addr);
			eloop_cancel_timeout(link_switch_probe_timeout, qserver, NULL);

			memcpy(data->dest_addr, config_dev->dev_addr, ETH_ALEN);
			link_switch_sm_step(data, LINK_SW_SYNC);
		}
		break;
	case LINK_SW_SYNC:
		if (frm_state == SEND_ACK) {
			data->sync_success++;
			link_switch_sm_step(data, LINK_SW_UPDATE);
		} else {
			data->sync_retry++;
			if (data->sync_retry <= LINK_SWITCH_SYNC_RETRIES_THRE) {
				eloop_register_timeout(data->sync_interval, 0,
					link_switch_sync_retry, qserver, NULL);
			} else {
				os_fprintf(stdout, "%s: fail to sync with remote\n",
					__func__);
				link_switch_sm_step(data, LINK_SW_LOCAL_PARSE);
			}
		}
		break;
	case LINK_SW_ALIVE:
		if (frm_state != RECV_ACK)
			data->alive_fail++;
		else
			data->alive_fail = 0;

		if (data->alive_fail > LINK_SWITCH_ALIVE_FAIL_THRE) {
			os_fprintf(stdout, "%s: link lost and start to restore\n",
					__func__);
			qserver_stop_query_polling(&qserver->frm_data, data->dest_addr);
			link_switch_sm_step(data, LINK_SW_RESTORE);
		}
		break;
	default:
		break;
	}
}

int
link_switch_sm_init(struct link_sw_data *data, const char *ifname, void *ctx)
{
	os_fprintf(stdout, "%s: initalize link_sw state machine\n", __func__);

	data->ctx = ctx;
	strncpy(data->ifname, ifname, IFNAMSIZ);
	dl_list_init(&data->config_devs);

	link_switch_sm_step(data, LINK_SW_INIT);

	return 0;
}

void
link_switch_sm_deinit(struct link_sw_data *data)
{
	link_switch_destroy_config_devices(data);
	data->ctx = NULL;

	os_fprintf(stdout, "%s: deinitalize link_sw state machine\n", __func__);
}


