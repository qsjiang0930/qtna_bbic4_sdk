/*
 *		qserver raw packet
 *
 * It's mainly used to implement the reception and transmitting
 * for qserver raw packet.
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

#include "qdata.h"
#include "driver.h"
#include "qcsapi.h"
#include "net80211/ieee80211_ioctl.h"
#include "eloop.h"

static uint8_t *
qserver_copy_tlv(uint8_t *pos)
{
	uint8_t *tlv;
	int len;

	if (!pos)
		return NULL;

	len = TLV_LEN(pos);
	tlv = os_zalloc(len);
	if (!tlv)
		return NULL;

	memcpy(tlv, pos, len);

	return tlv;
}

static inline int
is_qserver_raw_frame(struct oui_ext_ethtype *ouie)
{
	if ((ouie->oui[0] == (QTN_OUI & 0xff)) &&
		(ouie->oui[1] == ((QTN_OUI >> 8) & 0xff)) &&
		(ouie->oui[2] == ((QTN_OUI >> 16) & 0xff)) &&
			(ouie->type == htons(QTN_OUIE_TYPE_QSERVER)))
		return 1;

	return 0;
}

static int
qserver_linux_br_get(char *brname, const char *ifname)
{
	char path[QSERVER_PATH_MAX] = {0};
	char brlink[QSERVER_PATH_MAX] = {0};
	char *pos = NULL;

	snprintf(path, sizeof(path),
		"/sys/class/net/%s/brport/bridge", ifname);
	if (readlink(path, brlink, sizeof(brlink) - 1) < 0)
		return -1;
	pos = strrchr(brlink, '/');
	if (pos == NULL)
		return -1;
	pos++;
	strlcpy(brname, pos, IFNAMSIZ);
	return 0;
}

static int
qserver_get_current_role(struct qserver_data *qserver,
	uint8_t *role)
{
	int mode = QSVR_DEV_UNKNOWN;
	int ret;

	ret = qserver_drv_get_device_mode(qserver, &mode);
	if (ret < 0)
		return ret;

	*role = (uint8_t)mode;

	return 0;
}

static int
qserver_get_current_state(struct qserver_data *qserver,
	uint8_t *state)
{
	*state = link_switch_get_state(&qserver->ls_data);
	return 0;
}

static int
qserver_should_deliver_config_params(struct qserver_frame_data *frm_data,
	struct qserver_frm_params *params)
{
	struct qserver_data *qserver = (struct qserver_data *)frm_data->ctx;
	int deliver = 1;

	qserver_drv_get_device_capas(qserver, &qserver->dev_capas);
	if (!(qserver->dev_capas & QEV_DEV_CAPA_RESP)) {
		os_fprintf(stdout, "%s: device incapable of responding\n", __func__);
		deliver = 0;
		goto out;
	}

	qserver_drv_should_deliver_device_params(qserver, params, &deliver);

out:
	os_fprintf(stdout, "%s: should%s deliver the configure parameters\n",
			__func__, deliver ? "" : " not");

	return deliver;
}

static void
qserver_inform_frame_state(struct qserver_frame_data *frm_data,
	int state, uint8_t *source_addr)
{
	struct qserver_data *qserver = (struct qserver_data *)frm_data->ctx;

	link_switch_update_frm_exch_state(&qserver->ls_data, state, source_addr);
}

static uint8_t *
qserver_init_frame_header(struct qserver_frame_data *frm_data,
	uint8_t *dest_addr, uint8_t *pos, uint8_t type, uint32_t seq)
{
	struct qserver_data *qserver = (struct qserver_data *)frm_data->ctx;
	struct qserver_frm_header *frm = (struct qserver_frm_header *)pos;
	uint16_t frm_len = sizeof(struct qserver_frm_header) -
				offsetof(struct qserver_frm_header, seq);
	uint8_t own_addr[ETH_ALEN];
	uint8_t role = 0;
	uint8_t state = 0;

	l2_packet_get_own_addr(frm_data->l2, own_addr);
	qserver_get_current_role(qserver, &role);
	qserver_get_current_state(qserver, &state);

	memcpy(frm->ethhdr.h_dest, dest_addr, ETH_ALEN);
	memcpy(frm->ethhdr.h_source, own_addr, ETH_ALEN);
	frm->ethhdr.h_proto = htons(QTN_ETH_P_ETHER_802A);

	frm->ouie.oui[0] = QTN_OUI & 0xff;
	frm->ouie.oui[1] = (QTN_OUI >> 8) & 0xff;
	frm->ouie.oui[2] = (QTN_OUI >> 16) & 0xff;
	frm->ouie.type = htons(QTN_OUIE_TYPE_QSERVER);

	frm->type = type;
	OS_PUT_LE16(frm->len, frm_len);
	OS_PUT_LE32(frm->seq, seq);
	frm->role = role;
	frm->state = state;

	return pos + sizeof(*frm);
}

static void
qserver_frame_retry_timeout(void *eloop_ctx, void *timeout_ctx UNUSED_PARAM)
{
	struct qserver_frame_data *frm_data = (struct qserver_frame_data *)eloop_ctx;
	char *frm_str = qserver_frame_type_str(frm_data->rty.frm_type);

	if (frm_data->rty.count) {
		frm_data->rty.count--;
		frm_data->rty.timer = QSERVER_FRAME_RETRY_INTER;

		os_fprintf(stdout, "%s: retrying to send %s frame\n",
			__func__, frm_str);

		if (frm_data->rty.frame == NULL) {
			os_fprintf(stderr, "%s: no retry buffer available for %s frame\n",
				   __func__, frm_str);
			eloop_cancel_timeout(qserver_frame_retry_timeout, frm_data, NULL);
			return;
		}

		/* resend qvent raw packet to peer */
		if (l2_packet_send(frm_data->l2, NULL, 0, frm_data->rty.frame,
				frm_data->rty.frm_len) < 0)
			os_fprintf(stderr, "%s: fail to retransmit\n", __func__);

		eloop_cancel_timeout(qserver_frame_retry_timeout, frm_data, NULL);
		eloop_register_timeout(frm_data->rty.timer, 0,
					qserver_frame_retry_timeout, frm_data, NULL);
	} else {
		eloop_cancel_timeout(qserver_frame_retry_timeout, frm_data, NULL);
		os_fprintf(stdout, "%s: all retries for %s frame fail\n", __func__, frm_str);
		qserver_inform_frame_state(frm_data, frm_data->state, NULL);
	}
}

static void
qserver_frame_retry_timeout_cancel(struct qserver_frame_data *frm_data)
{
	/* Cancel Timeout registered */
	eloop_cancel_timeout(qserver_frame_retry_timeout, frm_data, NULL);

	/* free all resources meant for retry */
	free(frm_data->rty.frame);
	frm_data->rty.frame = NULL;

	frm_data->rty.count = 0;
	frm_data->rty.timer = 0;
	frm_data->rty.frm_len = 0;
	frm_data->rty.frm_type = QSERVER_UNKNOWN_FRAME;
}

static inline uint8_t *
qserver_encap_attribute(uint8_t *tlv, uint8_t *pos, uint8_t *end, int *len)
{
	int att_len;

	*len = 0;
	if (tlv) {
		att_len = TLV_LEN(tlv);
		if ((pos + att_len) > end)
			return pos;

		memcpy(pos, tlv, att_len);
		pos += att_len;
		*len += att_len;
	}

	return pos;
}

static uint8_t *
qserver_encap_query_frame_payload(uint8_t *pos, uint8_t *end,
	struct qserver_device_params *params)
{
	int i;
	int att_len;

	if (!params)
		return pos;

	if ((params->num == 0) || (params->bss == NULL))
		return pos;

	for (i = 0; i < params->num; i++) {
		pos = qserver_encap_attribute(params->bss[i].ifidx, pos, end, &att_len);
		if (att_len == 0)
			break;
		pos = qserver_encap_attribute(params->bss[i].band, pos, end, &att_len);
		pos = qserver_encap_attribute(params->bss[i].mac_addr, pos, end, &att_len);
		pos = qserver_encap_attribute(params->bss[i].ext, pos, end, &att_len);
	}

	return pos;
}

static uint8_t *
qserver_encap_update_frame_payload(uint8_t *pos, uint8_t *end,
	struct qserver_device_params *params)
{
	int i;
	int att_len;

	if (!params)
		return pos;

	pos = qserver_encap_attribute(params->qtm, pos, end, &att_len);

	if ((params->num == 0) || (params->bss == NULL))
		return pos;

	for (i = 0; i < params->num; i++) {
		pos = qserver_encap_attribute(params->bss[i].ifidx, pos, end, &att_len);
		if (att_len == 0)
			break;
		pos = qserver_encap_attribute(params->bss[i].band, pos, end, &att_len);
		pos = qserver_encap_attribute(params->bss[i].ssid, pos, end, &att_len);
		pos = qserver_encap_attribute(params->bss[i].sec, pos, end, &att_len);
		pos = qserver_encap_attribute(params->bss[i].pwd, pos, end, &att_len);
		pos = qserver_encap_attribute(params->bss[i].rekey, pos, end, &att_len);
		pos = qserver_encap_attribute(params->bss[i].pri, pos, end, &att_len);
		pos = qserver_encap_attribute(params->bss[i].wmm_own, pos, end, &att_len);
		pos = qserver_encap_attribute(params->bss[i].wmm_bss, pos, end, &att_len);
		pos = qserver_encap_attribute(params->bss[i].pmf, pos, end, &att_len);
		pos = qserver_encap_attribute(params->bss[i].mac_addr, pos, end, &att_len);
		pos = qserver_encap_attribute(params->bss[i].mdid, pos, end, &att_len);
		pos = qserver_encap_attribute(params->bss[i].ext, pos, end, &att_len);
	}

	return pos;
}

int
qserver_store_device_params(struct qserver_frame_data *frm_data,
	struct qserver_device_params *device)
{
	struct qserver_data *qserver = (struct qserver_data *)frm_data->ctx;
	struct qserver_device_params *params;
	int i;

	qserver_free_device_params(frm_data->params);
	frm_data->params = NULL;

	params = os_zalloc(sizeof(struct qserver_device_params));
	if (params == NULL) {
		os_fprintf(stderr, "%s: fail to allocate device params\n", __func__);
		return -1;
	}

	params->qtm = qserver_copy_tlv(device->qtm);

	params->bss = os_zalloc(device->num * sizeof(struct qserver_bss_params));
	if (params->bss == NULL) {
		os_fprintf(stderr, "%s: fail to allocate bss params\n", __func__);
		free(params);
		return -1;
	}

	params->num = device->num;
	for (i = 0; i < params->num; i++) {
		params->bss[i].ifidx = qserver_copy_tlv(device->bss[i].ifidx);
		params->bss[i].band = qserver_copy_tlv(device->bss[i].band);
		params->bss[i].ssid = qserver_copy_tlv(device->bss[i].ssid);
		params->bss[i].sec = qserver_copy_tlv(device->bss[i].sec);
		params->bss[i].pwd = qserver_copy_tlv(device->bss[i].pwd);
		params->bss[i].rekey = qserver_copy_tlv(device->bss[i].rekey);
		params->bss[i].pri = qserver_copy_tlv(device->bss[i].pri);
		params->bss[i].wmm_own = qserver_copy_tlv(device->bss[i].wmm_own);
		params->bss[i].wmm_bss = qserver_copy_tlv(device->bss[i].wmm_bss);
		params->bss[i].pmf = qserver_copy_tlv(device->bss[i].pmf);
		params->bss[i].mac_addr = qserver_copy_tlv(device->bss[i].mac_addr);
		params->bss[i].mdid = qserver_copy_tlv(device->bss[i].mdid);
		params->bss[i].ext = qserver_copy_tlv(device->bss[i].ext);
	}

	frm_data->params = params;

	if (qserver->save_params)
		qserver_drv_save_device_params_to_file(qserver, params);

	return 0;
}

void
qserver_free_device_params(struct qserver_device_params *params)
{
	int i;

	if (!params)
		return;

	free(params->qtm);

	if (params->bss) {
		for (i = 0; i < params->num; i++) {
			free(params->bss[i].ifidx);
			free(params->bss[i].band);
			free(params->bss[i].ssid);
			free(params->bss[i].sec);
			free(params->bss[i].pwd);
			free(params->bss[i].rekey);
			free(params->bss[i].pri);
			free(params->bss[i].wmm_own);
			free(params->bss[i].wmm_bss);
			free(params->bss[i].pmf);
			free(params->bss[i].mac_addr);
			free(params->bss[i].mdid);
			free(params->bss[i].ext);
		}
		free(params->bss);
	}

	free(params);
}

static int
qserver_send_raw_frame(struct qserver_frame_data *frm_data,
	int frame, uint8_t *dest_mac, uint8_t *buf, int len)
{
	char *frm_str = qserver_frame_type_str(frame);

	if (l2_packet_send(frm_data->l2, dest_mac, 0, buf, len) < 0) {
		os_fprintf(stdout, "%s: fail to send %s frame"
			" to device "MACSTR"\n", __func__,
			frm_str, MAC2STR(dest_mac));
		return -1;
	}

	if (frame == QSERVER_ACK_FRAME)
		return 0;

	qserver_frame_retry_timeout_cancel(frm_data);

	frm_data->rty.count = QSERVER_FRAME_RETRY_COUNT;
	frm_data->rty.timer = QSERVER_FRAME_RETRY_INTER;
	frm_data->rty.frm_len = len;
	frm_data->rty.frm_type = frame;
	frm_data->rty.frame = os_zalloc(len);
	if (frm_data->rty.frame == NULL) {
		os_fprintf(stdout, "%s: fail to allocte retry buffer",
			" for %s frame\n", __func__, frm_str);
		return -1;
	}
	memcpy(frm_data->rty.frame, buf, len);
	eloop_register_timeout(frm_data->rty.timer, 0,
				qserver_frame_retry_timeout, frm_data, NULL);

	return 0;
}

int
qserver_send_query_frame(struct qserver_frame_data *frm_data,
	uint8_t *dest_mac)
{
	struct qserver_data *qserver = (struct qserver_data *)frm_data->ctx;
	struct qserver_device_params *params = NULL;
	struct qserver_frm_header *frm = NULL;
	uint8_t *start = NULL;
	uint8_t *end = NULL;
	uint8_t *pos = NULL;
	static uint32_t seq = 0;
	int frm_len = 0;

	start = os_zalloc(QSERVER_FRAME_BUF_SIZE);
	if (start == NULL) {
		os_fprintf(stderr, "%s: failed to allocate"
			" frame buffer\n", __func__);
		return -1;
	}
	end = start + QSERVER_FRAME_BUF_SIZE;

	os_fprintf(stdout, "%s: send query frame to device "
			MACSTR"\n", __func__, MAC2STR(dest_mac));

	frm = (struct qserver_frm_header *)start;
	params = qserver_drv_get_device_params(qserver, NULL);
	pos = qserver_init_frame_header(frm_data, dest_mac, start,
			QSERVER_QUERY_FRAME, seq++);
	pos = qserver_encap_query_frame_payload(pos, end, params);

	if (pos > end) {
		os_fprintf(stderr, "%s: payload length exceeds buffer size\n",
			__func__);
		qserver_drv_free_device_params(qserver, params);
		free(start);
		return -1;
	}

	frm_len = pos - start - offsetof(struct qserver_frm_header, seq);
	OS_PUT_LE16(frm->len, frm_len);

	frm_data->state = SEND_QUERY;
	qserver_send_raw_frame(frm_data, QSERVER_QUERY_FRAME,
			dest_mac, start, pos - start);

	qserver_drv_free_device_params(qserver, params);
	free(start);

	return 0;
}

static int
qserver_send_update_frame(struct qserver_frame_data *frm_data,
	uint8_t *dest_mac, uint32_t seq, struct qserver_frm_params *frm_params)
{
	struct qserver_data *qserver = (struct qserver_data *)frm_data->ctx;
	struct qserver_device_params *params = NULL;
	struct qserver_frm_header *frm = NULL;
	uint8_t *start = NULL;
	uint8_t *end = NULL;
	uint8_t *pos = NULL;
	int frm_len = 0;

	start = os_zalloc(QSERVER_FRAME_BUF_SIZE);
	if (start == NULL) {
		os_fprintf(stderr, "%s: failed to allocate"
			" frame buffer\n", __func__);
		return -1;
	}
	end = start + QSERVER_FRAME_BUF_SIZE;

	os_fprintf(stdout, "%s: send update frame to device "
			MACSTR"\n", __func__, MAC2STR(dest_mac));

	frm = (struct qserver_frm_header *)start;
	params = qserver_drv_get_device_params(qserver, frm_params);
	pos = qserver_init_frame_header(frm_data, dest_mac, start,
			QSERVER_UPDATE_FRAME, seq);
	pos = qserver_encap_update_frame_payload(pos, end, params);

	if (pos > end) {
		os_fprintf(stderr, "%s: payload length exceeds buffer size\n",
			__func__);
		qserver_drv_free_device_params(qserver, params);
		free(start);
		return -1;
	}

	frm_len = pos - start - offsetof(struct qserver_frm_header, seq);
	OS_PUT_LE16(frm->len, frm_len);

	frm_data->state = SEND_UPDATE;
	qserver_send_raw_frame(frm_data, QSERVER_UPDATE_FRAME,
			dest_mac, start, pos - start);

	qserver_drv_free_device_params(qserver, params);
	free(start);

	return 0;
}

static int
qserver_send_ack_frame(struct qserver_frame_data *frm_data,
	uint8_t *dest_mac, uint32_t seq)
{
	struct qserver_frm_header *frm = NULL;
	uint8_t *start = NULL;
	uint8_t *pos = NULL;
	int frm_len = 0;

	start = os_zalloc(QSERVER_FRAME_BUF_SIZE);
	if (start == NULL) {
		os_fprintf(stderr, "%s: failed to allocate"
			" frame buffer\n", __func__);
		return -1;
	}

	os_fprintf(stdout, "%s: send ack frame to device "
			MACSTR"\n", __func__, MAC2STR(dest_mac));

	frm = (struct qserver_frm_header *)start;
	pos = qserver_init_frame_header(frm_data, dest_mac, start,
			QSERVER_ACK_FRAME, seq);

	if (pos > (start + QSERVER_FRAME_BUF_SIZE)) {
		os_fprintf(stderr, "%s: payload length exceeds buffer size\n",
			__func__);
		free(start);
		return -1;
	}

	frm_len = pos - start - offsetof(struct qserver_frm_header, seq);
	OS_PUT_LE16(frm->len, frm_len);

	frm_data->state = SEND_ACK;
	qserver_send_raw_frame(frm_data, QSERVER_ACK_FRAME,
			dest_mac, start, pos - start);

	free(start);

	return 0;
}

static struct qserver_frm_params *
qserver_parse_raw_frame(struct qserver_frame_data *frm_data UNUSED_PARAM,
	const uint8_t *buf, size_t len)
{
	struct qserver_frm_params *params;
	struct qserver_frm_header *frm;
	int bss_index = 0;
	uint32_t param_len = 0;
	uint8_t *pos;
	uint8_t *end;
	char *type;
	uint16_t att_type;

	if (len < sizeof(*frm))
		return NULL;

	params = os_zalloc(sizeof(*params));
	if (params == NULL) {
		os_fprintf(stderr, "%s: failed to allocate"
			" frame params\n", __func__);
		return NULL;
	}

	frm = (struct qserver_frm_header *)buf;
	params->sa = frm->ethhdr.h_source;
	params->da = frm->ethhdr.h_dest;
	params->type = frm->type;
	params->len = OS_GET_LE16(frm->len);
	params->seq = OS_GET_LE32(frm->seq);
	params->role = frm->role;
	params->state = frm->state;

	param_len = params->len - (sizeof(struct qserver_frm_header)
			- offsetof(struct qserver_frm_header, seq));
	param_len = MIN(param_len, len);

	/* calculate bss number */
	pos = frm->buf;
	end = frm->buf + param_len;
	while (pos < end) {
		att_type = tlv_get_type(pos);

		switch (att_type) {
		case QEV_ATTR_BSS_IFINDEX:
			params->device.num++;
			break;
		default:
			break;
		}
		pos += TLV_LEN(pos);
	}

	if (params->device.num == 0)
		return params;

	params->device.bss = os_zalloc(params->device.num *
				sizeof(*(params->device.bss)));
	if (params->device.bss == NULL) {
		os_fprintf(stderr, "%s: failed to allocate"
			" bss params\n", __func__);
		free(params);
		return NULL;
	}

	pos = frm->buf;
	while (pos < end) {
		att_type = tlv_get_type(pos);
		switch (att_type) {
		case QEV_ATTR_QTM:
			type = "QTM";
			params->device.qtm = pos;
			break;
		case QEV_ATTR_BSS_IFINDEX:
			type = "IF_index";
			bss_index++;
			params->device.bss[bss_index - 1].ifidx = pos;
			break;
		case QEV_ATTR_BSS_BAND:
			type = "band";
			params->device.bss[bss_index - 1].band = pos;
			break;
		case QEV_ATTR_BSS_SSID:
			type = "SSID";
			params->device.bss[bss_index - 1].ssid = pos;
			break;
		case QEV_ATTR_BSS_SECURITY:
			type = "security";
			params->device.bss[bss_index - 1].sec = pos;
			break;
		case QEV_ATTR_BSS_PASSWORD:
			type = "password";
			params->device.bss[bss_index - 1].pwd = pos;
			break;
		case QEV_ATTR_BSS_REKEY_INTV:
			type = "rekey_interval";
			params->device.bss[bss_index - 1].rekey = pos;
			break;
		case QEV_ATTR_BSS_PRIORITY:
			type = "priority";
			params->device.bss[bss_index - 1].pri = pos;
			break;
		case QEV_ATTR_BSS_WMM_OWN:
			type = "wmm_parameter_own";
			params->device.bss[bss_index - 1].wmm_own = pos;
			break;
		case QEV_ATTR_BSS_WMM_BSS:
			type = "wmm_parameter_bss";
			params->device.bss[bss_index - 1].wmm_bss = pos;
			break;
		case QEV_ATTR_BSS_PMF:
			type = "PMF";
			params->device.bss[bss_index - 1].pmf = pos;
			break;
		case QEV_ATTR_BSS_MAC_ADDR:
			type = "MAC_ADDR";
			params->device.bss[bss_index - 1].mac_addr = pos;
			break;
		case QEV_ATTR_BSS_MDID:
			type = "MDID";
			params->device.bss[bss_index - 1].mdid = pos;
			break;
		case QEV_ATTR_BSS_EXT:
			type = "bss_ext";
			params->device.bss[bss_index - 1].ext = pos;
			break;
		default:
			type = "unknown";
			os_fprintf(stdout, "%s: unknown element %d\n",
				__func__, att_type);
			break;
		}

		if (strcmp(type, "IF_index") == 0)
			os_fprintf(stdout, "%s: new interface %d\n",
					__func__, bss_index - 1);
		else
			os_fprintf(stdout, "%s: attribute \"%s\", id %d, len %d\n",
				__func__, type, att_type, tlv_get_vlen(pos));

		pos += TLV_LEN(pos);
	}

	if (pos > end) {
		os_fprintf(stderr, "%s: invalid element length\n", __func__);
		free(params->device.bss);
		free(params);
		return NULL;
	}

	return params;
}

static void
qserver_receive_query_frame(struct qserver_frame_data *frm_data,
	struct qserver_frm_params *params)
{
	os_fprintf(stdout, "%s: receive qserver query frame from device "
			MACSTR"\n", __func__, MAC2STR(params->sa));

	frm_data->state = RECV_QUERY;
	qserver_frame_retry_timeout_cancel(frm_data);

	if (!qserver_should_deliver_config_params(frm_data, params))
		return;

	if (params->state == LINK_SW_SYNC)
		qserver_send_update_frame(frm_data, params->sa, params->seq, params);
	else if ((params->state == LINK_SW_PROBE) ||
			(params->state == LINK_SW_ALIVE))
		qserver_send_ack_frame(frm_data, params->sa, params->seq);
}

static void
qserver_receive_update_frame(struct qserver_frame_data *frm_data,
	struct qserver_frm_params *params)
{
	struct qserver_data *qserver = (struct qserver_data *)frm_data->ctx;
	int accepted = 1;
	int ret;

	os_fprintf(stdout, "%s: receive qserver update frame from device "
			MACSTR"\n", __func__, MAC2STR(params->sa));

	qserver_drv_should_accept_device_params(qserver, params, &accepted);
	if (accepted == 0) {
		os_fprintf(stdout, "%s: discard qserver update frame from device "
			MACSTR"\n", __func__, MAC2STR(params->sa));
		return;
	}

	frm_data->state = RECV_UPDATE;
	qserver_frame_retry_timeout_cancel(frm_data);

	qserver_send_ack_frame(frm_data, params->sa, params->seq);

	ret = qserver_store_device_params(frm_data, &params->device);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to set device parameters\n",
				__func__, MAC2STR(params->sa));
		qserver_inform_frame_state(frm_data, SEND_QUERY, params->sa);
	} else {
		qserver_inform_frame_state(frm_data, frm_data->state, params->sa);
	}
}

static void
qserver_receive_ack_frame(struct qserver_frame_data *frm_data,
	struct qserver_frm_params *params)
{
	os_fprintf(stdout, "%s: receive qserver ack frame from device "
			MACSTR"\n", __func__, MAC2STR(params->sa));

	frm_data->state = RECV_ACK;
	qserver_frame_retry_timeout_cancel(frm_data);

	qserver_inform_frame_state(frm_data, frm_data->state, params->sa);
}

static void
qserver_receive_raw_frame(void *ctx, const uint8_t *src_addr,
			const uint8_t *buf, size_t len)
{
	struct qserver_frame_data *frm_data =
			(struct qserver_frame_data *)ctx;
	struct qserver_frm_header *frm = (struct qserver_frm_header *)buf;
	struct qserver_frm_params *params = NULL;

	os_fprintf(stdout, "%s: receive qserver raw frame from device "
		MACSTR"\n", __func__, MAC2STR(src_addr));

	if (len < sizeof(struct qserver_frm_header) ||
			!is_qserver_raw_frame(&frm->ouie))
		return;

	params = qserver_parse_raw_frame(frm_data, buf, len);
	if (params == NULL) {
		os_fprintf(stderr, "%s: invalid qserver raw frame\n", __func__);
		return;
	}

	switch (params->type) {
	case QSERVER_QUERY_FRAME:
		qserver_receive_query_frame(frm_data, params);
		break;
	case QSERVER_UPDATE_FRAME:
		qserver_receive_update_frame(frm_data, params);
		break;
	case QSERVER_ACK_FRAME:
		qserver_receive_ack_frame(frm_data, params);
		break;
	default:
		os_fprintf(stdout, "%s: unknown qserver raw frame %u\n",
			__func__, params->type);
		break;
	}

	free(params->device.bss);
	free(params);
}

static void
qserver_query_polling_timeout(void *eloop_ctx, void *timeout_ctx UNUSED_PARAM)
{
	struct qserver_frame_data *frm_data =
			(struct qserver_frame_data *)eloop_ctx;

	qserver_send_query_frame(frm_data, frm_data->polling_dest);

	eloop_cancel_timeout(qserver_query_polling_timeout,
			frm_data, NULL);
	eloop_register_timeout(frm_data->polling_timer, 0,
			qserver_query_polling_timeout, frm_data, NULL);
}


int
qserver_start_query_polling(struct qserver_frame_data *frm_data,
	uint8_t *dest_mac, int interval)
{
	os_fprintf(stdout, "%s: start query polling ("MACSTR
		") with interval %d\n", __func__, MAC2STR(dest_mac),
		interval);

	frm_data->polling_timer = interval;
	memcpy(frm_data->polling_dest, dest_mac, ETH_ALEN);

	qserver_query_polling_timeout(frm_data, NULL);

	return 0;
}

int
qserver_stop_query_polling(struct qserver_frame_data *frm_data,
	uint8_t *dest_mac)
{
	os_fprintf(stdout, "%s: stop query polling ("MACSTR")\n",
		__func__, MAC2STR(dest_mac));

	eloop_cancel_timeout(qserver_query_polling_timeout, frm_data, NULL);

	frm_data->polling_timer = 0;
	memset(frm_data->polling_dest, 0, ETH_ALEN);

	return 0;
}

int
qserver_raw_frame_init(struct qserver_frame_data *frm_data,
		const char *ifname, void *ctx)
{
	char brname[IFNAMSIZ + 1] = {0};

	if (ifname == NULL)
		return -1;

	if (qserver_linux_br_get(brname, ifname) == 0) {
		os_fprintf(stdout, "%s: open qserver raw socket with interface %s\n",
			__func__, brname);

		memcpy(frm_data->ifname, ifname, IFNAMSIZ);
		memcpy(frm_data->brname, brname, IFNAMSIZ);
		frm_data->l2 = l2_packet_init(brname, NULL, QTN_ETH_P_ETHER_802A,
					qserver_receive_raw_frame, frm_data, 1);
	} else {
		os_fprintf(stderr, "%s: fail to get bridge name with"
			" interface name %s\n", __func__, ifname);
		return -1;
	}

	if (frm_data->l2 == NULL) {
		os_fprintf(stderr, "%s: fail to create l2 socket for qserver\n",
			__func__, ifname);
		return -1;
	}

	frm_data->ctx = ctx;
	frm_data->params = NULL;

	return 0;
}

void
qserver_raw_frame_deinit(struct qserver_frame_data *frm_data)
{
	os_fprintf(stdout, "%s: close qserver saw socket\n", __func__);

	frm_data->ctx = NULL;
	free(frm_data->rty.frame);
	l2_packet_deinit(frm_data->l2);

	qserver_free_device_params(frm_data->params);
	frm_data->params = NULL;
}

