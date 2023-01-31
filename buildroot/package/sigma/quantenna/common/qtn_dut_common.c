/****************************************************************************
*
* Copyright (c) 2015  Quantenna Communications, Inc.
*
* Permission to use, copy, modify, and/or distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
* SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
* RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
* NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
* USE OR PERFORMANCE OF THIS SOFTWARE.
*
*****************************************************************************/

#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#include <net80211/ieee80211.h>
#include "wfa_types.h"
#include "wfa_tlv.h"
#include "qtn/qcsapi.h"
#include "qtn_dut_common.h"
#include "common/qsigma_log.h"

#define QTN_DUT_CONFIG_TABSIZE		8

static struct qtn_dut_config qtn_dut_config_table[QTN_DUT_CONFIG_TABSIZE];

static int qtn_dut_config_head = 0;
static int qtn_dut_config_tail = 0;

void qtn_dut_reset_config(struct qtn_dut_config *conf)
{
	if (conf) {
		conf->bws_enable = 0;
		conf->bws_dynamic = 0;
		conf->force_rts = 0;
		conf->update_settings = 0;
		conf->bws = QTN_BW_MAX;
		if (conf->dpp_config)
			free(conf->dpp_config);
		conf->dpp_config = NULL;
	}
}

struct qtn_dut_config * qtn_dut_get_config(const char* ifname)
{
	int len = strlen(ifname);

	if ((len > 0) && (len < sizeof(((struct qtn_dut_config*)NULL)->ifname))) {
		int i;
		struct qtn_dut_config *conf;

		for (i = qtn_dut_config_head;
				i != qtn_dut_config_tail;
				i = (i + 1) % QTN_DUT_CONFIG_TABSIZE) {

			conf = &qtn_dut_config_table[i];

			if (strncasecmp(conf->ifname, ifname, len) == 0)
				if (strlen(conf->ifname) == len)
					return conf;
		}

		/* there is no config, allocate next */
		conf = &qtn_dut_config_table[qtn_dut_config_tail];

		qtn_dut_reset_config(conf);

		strncpy(conf->ifname, ifname, len);
		conf->ifname[len] = 0;

		qtn_dut_config_tail = (qtn_dut_config_tail + 1) % QTN_DUT_CONFIG_TABSIZE;

		if (qtn_dut_config_head == qtn_dut_config_tail) {
			qtn_dut_config_head = (qtn_dut_config_head + 1) % QTN_DUT_CONFIG_TABSIZE;
		}

		return conf;
	}

	return NULL;
}

static
int qtn_dut_print_base_response(char *buf_ptr, int buf_size, int status, int err_code)
{
	int rsp_len;
	const char *status_str;
	int need_err_code = 0;

	switch (status) {
	case STATUS_RUNNING:
		status_str = "RUNNING";
		break;

	case STATUS_INVALID:
		status_str = "INVALID";
		need_err_code = (err_code != 0);
		break;

	case STATUS_ERROR:
		status_str = "ERROR";
		need_err_code = (err_code != 0);
		break;

	case STATUS_COMPLETE:
		status_str = "COMPLETE";
		break;

	default:
		status_str = "INVALID";
		break;
	}

	if (need_err_code)
		rsp_len = snprintf(buf_ptr, buf_size, "%s,errorCode,%d", status_str, err_code);
	else
		rsp_len = snprintf(buf_ptr, buf_size, "%s", status_str);

	return rsp_len;
}

void qtn_dut_make_response_none(int tag, int status, int err_code, int *out_len,
	unsigned char *out_buf)
{
	char rsp_buf[128];
	int rsp_len;

	rsp_len = qtn_dut_print_base_response(rsp_buf, sizeof(rsp_buf), status, err_code);

	if (rsp_len > 0) {
		wfaEncodeTLV(tag, rsp_len, (BYTE *) rsp_buf, out_buf);
		*out_len = WFA_TLV_HDR_LEN + rsp_len;
	}
}

void qtn_dut_make_response_macaddr(int tag, int status, int err_code, const unsigned char *macaddr,
	int *out_len, unsigned char *out_buf)
{
	char rsp_buf[128];
	int rsp_len;

	rsp_len = qtn_dut_print_base_response(rsp_buf, sizeof(rsp_buf), status, err_code);

	if (rsp_len > 0) {
		if (status == STATUS_COMPLETE) {
			int len = snprintf(rsp_buf + rsp_len, sizeof(rsp_buf) - rsp_len,
				",mac,%02x:%02x:%02x:%02x:%02x:%02x",
				macaddr[0], macaddr[1], macaddr[2],
				macaddr[3], macaddr[4], macaddr[5]);

			if (len > 0)
				rsp_len += len;
		}

		wfaEncodeTLV(tag, rsp_len, (BYTE *) rsp_buf, out_buf);
		*out_len = WFA_TLV_HDR_LEN + rsp_len;
	}
}

void qtn_dut_make_response_vendor_info(int tag, int status, int err_code, const char *vendor_info,
	int *out_len, unsigned char *out_buf)
{
	char rsp_buf[512];
	int rsp_len;

	rsp_len = qtn_dut_print_base_response(rsp_buf, sizeof(rsp_buf), status, err_code);

	if (rsp_len > 0) {
		if ((status == STATUS_COMPLETE) && vendor_info && *vendor_info) {
			int len = snprintf(rsp_buf + rsp_len, sizeof(rsp_buf) - rsp_len,
				",%s", vendor_info);

			if (len > 0)
				rsp_len += len;
		}

		wfaEncodeTLV(tag, rsp_len, (BYTE *) rsp_buf, out_buf);
		*out_len = WFA_TLV_HDR_LEN + rsp_len;
	}
}

void qtn_dut_make_response_str(int tag, int status, int err_code, char *dpp_resp,
					int resp, int *out_len, unsigned char *out_buf)
{
	char rsp_buf[QTN_MAX_BUF_LEN] = {0};
	int rsp_len;

	rsp_len = qtn_dut_print_base_response(rsp_buf, sizeof(rsp_buf), status, err_code);

	if (rsp_len > 0) {
		if (dpp_resp && resp) {
			int len = snprintf(rsp_buf + rsp_len, sizeof(rsp_buf) - rsp_len,
				",%s", dpp_resp);

			qtn_error("%s: final resp len=%d, resp=%s", __func__, len, rsp_buf);
			if (len > 0)
				rsp_len += len;
		}

		wfaEncodeTLV(tag, rsp_len, (BYTE *) rsp_buf, out_buf);
		*out_len = WFA_TLV_HDR_LEN + rsp_len;
	}

}

void qtn_dut_make_response_mid(int tag, int status, int err_code, char *mid,
	int *out_len, unsigned char *out_buf)
{
	char rsp_buf[QTN_MAX_BUF_LEN] = {0};
	int rsp_len;

	rsp_len = qtn_dut_print_base_response(rsp_buf, sizeof(rsp_buf), status, err_code);

	if (rsp_len > 0) {
		if (status == STATUS_COMPLETE) {
			int len = snprintf(rsp_buf + rsp_len, sizeof(rsp_buf) - rsp_len,
				",MID,%s", mid);

			if (len > 0)
				rsp_len += len;
		}

		wfaEncodeTLV(tag, rsp_len, (BYTE *) rsp_buf, out_buf);
		*out_len = WFA_TLV_HDR_LEN + rsp_len;
	}
}

int qtn_parse_mac(const char *mac_str, unsigned char *mac)
{
	unsigned int tmparray[IEEE80211_ADDR_LEN];

	if (mac_str == NULL)
		return -EINVAL;

	if (sscanf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
			&tmparray[0],
			&tmparray[1],
			&tmparray[2],
			&tmparray[3], &tmparray[4], &tmparray[5]) != IEEE80211_ADDR_LEN) {
		return -EINVAL;
	}

	mac[0] = tmparray[0];
	mac[1] = tmparray[1];
	mac[2] = tmparray[2];
	mac[3] = tmparray[3];
	mac[4] = tmparray[4];
	mac[5] = tmparray[5];

	return 0;
}

void qtn_set_rts_settings(const char* ifname, struct qtn_dut_config* conf)
{
	/* 1. RTS with BW signaling:
		iwpriv wifi0 set_rts_bw 0xFXYZ
	Where:
		F: 1 - signalled BW is fixed and does not depend on data BW
		X: 1 - do not force RTS sending.
		Y: 2 -- 80MHz, 1 -- 40MHz, 0 -- 20MHz
		Z: 1 -- dynamic, 0 -- static */

	uint16_t bw_sign = QTN_BW_RTS_SIG_NFORCE | QTN_BW_RTS_FIXED_BW;

	if (conf->bws_enable) {
		bw_sign |= SM(conf->bws, QTN_BW_RTS_SIG);
	}

	if (conf->bws_enable && conf->bws_dynamic) {
		bw_sign |= QTN_BW_RTS_SIG_DYN;
	}

	if (conf->force_rts) {
		bw_sign &= ~QTN_BW_RTS_SIG_NFORCE;
	}

	if (conf->bws_enable && !conf->bws_dynamic) {
		/* WAR: WFA expect that when static bw signalling is used DUT will stay only
		 * at fixed bw i.e. 80MHz.
		 */
		system("set_fixed_bw -b 80");
	} else {
		system("set_fixed_bw -b auto");
	}

	char tmp[128];
	snprintf(tmp, sizeof(tmp), "iwpriv %s set_rts_bw 0x%x", ifname, bw_sign);
	system(tmp);

	conf->update_settings = 0;
}

int qtn_set_mu_enable(int enable)
{
	char tmp[128];
	snprintf(tmp, sizeof(tmp), "mu %s", enable ? "enable" : "disable");
	return system(tmp);
}

int set_tx_bandwidth(const char* ifname, unsigned bandwidth)
{
	qcsapi_unsigned_int current_bw;
	int ret;
	char cmd[128];

	if (qcsapi_wifi_get_bw(ifname, &current_bw) < 0) {
		current_bw = 0;
		qtn_error("can't get current bw");
	}

	/* change bw only when current is not wide enough */
	if (bandwidth > current_bw
		&& (ret = qcsapi_wifi_set_bw(ifname, bandwidth)) < 0) {
		qtn_error("can't set bandwidth to %d, error %d", bandwidth, ret);
		return ret;
	}

	/* force RA to use only specified bandwidth */
	snprintf(cmd, sizeof(cmd), "set_fixed_bw -b %d", bandwidth);
	system(cmd);

	return 0;
}

const char* qtn_get_sigma_interface(void)
{
	static char ifname[128];

	if (ifname[0] == '\0') {
		qcsapi_get_primary_interface(ifname, sizeof(ifname));
	}

	return ifname;
}

const char* qtn_get_sigma_vap_interface(unsigned vap_index)
{
	static char qtn_dut_sigma_vap[IFNAMSIZ];

	if (vap_index == 0)
		return qtn_get_sigma_interface();

	sprintf(qtn_dut_sigma_vap, "wifi%u", vap_index);

	char status[32] = {0};
	if (qcsapi_interface_get_status(qtn_dut_sigma_vap, status) < 0) {
		qtn_error("failed to get vap interface if_index = %d", vap_index);
		return qtn_get_sigma_interface();
	}

	return qtn_dut_sigma_vap;
}
int qtn_set_rf_enable(int enable)
{
	char cmd[128];

	snprintf(cmd, sizeof(cmd), "/scripts/rfenable %d > /dev/console &", enable);
	system(cmd);

	/* WAR: let system to UP/DOWN completely */
	sleep(5);

	return 0;
}

#define QTN_DUT_RADIO_UP_TRY_COUNT	3

void qtn_bring_up_radio_if_needed(void)
{
	qcsapi_rf_status rf_status;

	/* Status of the radio could be one of the following:
	 *  QCSAPI_RFSTATUS_OFF
	 *  QCSAPI_RFSTATUS_ON
	 *  QCSAPI_RFSTATUS_TURNING_OFF
	 *  QCSAPI_RFSTATUS_TURNING_ON
	 */
	if ((qcsapi_wifi_rfstatus(&rf_status) == 0) && (rf_status != QCSAPI_RFSTATUS_ON)) {
		qtn_log("enable RF");

		int try_count;

		for (try_count = 1; try_count <= QTN_DUT_RADIO_UP_TRY_COUNT; try_count++) {
			/* enable radio */
			qtn_set_rf_enable(1);

			/* check status for another 5 seconds */
			int timeout = 5;
			while (timeout-- > 0) {
				if ((qcsapi_wifi_rfstatus(&rf_status) == 0) && (rf_status == QCSAPI_RFSTATUS_ON)) {
					/* radio is up */
					return;
				}

				qtn_log("wait RF, status %d", rf_status);

				sleep(1);
			}

			qtn_log("try to enable RF again");
		}

		qtn_log("unable to bring up RF after %d tries", try_count);
	}
}

/*
 * The function checks if "defer" mode for security configuration is "active".
 * Then it apply "deferred" security configuration for specified interface.
 * Usually "deferred" configuration is used for "stateless" mode.
 */
void qtn_check_defer_mode_apply_config(const char* ifname)
{
	int defer_mode;
	int ret = qcsapi_wifi_get_security_defer_mode(ifname, &defer_mode);

	if (ret < 0) {
		qtn_error("unable to obtain defer_mode, error %d", ret);
		return;
	}

	if (defer_mode) {
		ret = qcsapi_wifi_apply_security_config(ifname);
		if (ret < 0) {
			qtn_error("unable to apply deffered security config, error %d", ret);
			return;
		}
	}
}
