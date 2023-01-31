/****************************************************************************
 *
 * All Rights Reserved.
 * Licensed under the Clear BSD license. See README for more details.
 *****************************************************************************
 */

#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "qtn_dut_sta_handler.h"
#include "common/qtn_cmd_parser.h"
#include "common/qtn_dut_common.h"
#include "common/qtn_defconf.h"

#include "common/qsigma_log.h"
#include "common/qsigma_tags.h"
#include "common/qsigma_common.h"
#include "wfa_types.h"
#include "wfa_tlv.h"
#include "wfa_tg.h"
#include "wfa_cmds.h"

#include "qtn/qdrv_bld.h"
#include "qtn/qcsapi.h"
#include <linux/wireless.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <sys/ioctl.h>

#include "qtn_wpa_ctrl.h"

#define QTN_LISTEN_CHAN_DUR_MS		1000
#define QTN_DPP_DEF_TIMEOUT		120
#define QTN_AP_CONFIG_DELAY		10
#define QTN_AP_CHAN_CFG_DELAY		2
#define QTN_WPA_MSG_MAX_SIZE		2000

#define QTN_DPP_DEF_FREQ_5G_QRCODE	5180
#define QTN_DPP_DEF_FREQ_5G_PKEX	5220
#define QTN_DPP_DEF_FREQ_24G		2437

char *supp_ctrl = "/var/run/wpa_supplicant/";
char *hapd_ctrl = "/var/run/hostapd/";


void qtn_dpp_close_wpa_mon(struct wpa_ctrl *ctrl)
{
	qtn_log("%s: ctrl=%p", __func__, ctrl);

	if (ctrl == NULL)
		return;
	unlink(ctrl->local.sun_path);
	if (ctrl->s >= 0)
		close(ctrl->s);
	free(ctrl);
}

struct wpa_ctrl *qtn_dpp_open_wpa_mon(char *ifname)
{
	qcsapi_wifi_mode current_mode;
	struct wpa_ctrl *ctrl;
	char path[256];
	int ret;

	ret = qcsapi_wifi_get_mode(ifname, &current_mode);
	if (ret < 0) {
		qtn_error("can't get mode, error %d", ret);
		return NULL;
	}

	if (current_mode == qcsapi_access_point)
		snprintf(path, sizeof(path), "%s%s", hapd_ctrl, ifname);
	else
		snprintf(path, sizeof(path), "%s%s", supp_ctrl, ifname);

	ctrl = wpa_ctrl_open(path);
	if (ctrl == NULL)
		return NULL;

	if (wpa_ctrl_attach(ctrl) < 0) {
		wpa_ctrl_close(ctrl);
		return NULL;
	}

	return ctrl;
}

static unsigned int qtn_dpp_get_curve(struct qtn_cmd_request *cmd_req)
{
	char dpp_curve[16] = {0};

	if (qtn_get_value_text(cmd_req, QTN_TOK_DPP_CRYPTOID, dpp_curve,
				sizeof(dpp_curve)) <= 0)
		qtn_error("can't get DPP bootstrapping crypto curve; setting default P-256");

	if (strcasecmp(dpp_curve, "BP-256R1") == 0)
		return QCSAPI_DPP_CRYPTO_BP256;
	else if (strcasecmp(dpp_curve, "BP-384R1") == 0)
		return QCSAPI_DPP_CRYPTO_BP384;
	else if (strcasecmp(dpp_curve, "BP-512R1") == 0)
		return QCSAPI_DPP_CRYPTO_BP512;

	return QCSAPI_DPP_CRYPTO_P256;
}

static int qtn_dpp_wait_tx(struct wpa_ctrl *ctrl, int timeout, int frame_type)
{
	int res;
	char tmp[20];
	char wpa_buf[QTN_WPA_MSG_MAX_SIZE];
	static const char *tx_events[] = {
		"DPP-TX",
		NULL
	};

	qtn_log("%s: frame_type=%d", __func__, frame_type);
	snprintf(tmp, sizeof(tmp), "type=%d", frame_type);
	for (;;) {
		res = get_wpa_cli_events(ctrl, timeout, tx_events, wpa_buf, sizeof(wpa_buf));
		if (res < 0) {
			qtn_error("DPP_WAIT_TX: timeout/error waiting for event");
			return -1;
		}

		if (strstr(wpa_buf, tmp) != NULL)
			break;
	}

	qtn_log("DPP_WAIT_TX: %s", wpa_buf);
	return 0;
}

static int qtn_dpp_wait_tx_status(struct wpa_ctrl *ctrl, int timeout, int frame_type)
{
	int res;
	char wpa_buf[QTN_WPA_MSG_MAX_SIZE];
	static const char *tx_status_events[] = {
		"DPP-TX-STATUS",
		NULL
	};

	qtn_log("%s: frame_type=%d", __func__, frame_type);
	res = qtn_dpp_wait_tx(ctrl, timeout, frame_type);
	if (res < 0) {
		qtn_error("DPP_WAIT_TXSTATUS: timeout/error waiting for event");
		return -1;
	}

	qtn_log("DPP_WAIT_TXSTATUS1: %s", wpa_buf);

	res = get_wpa_cli_events(ctrl, timeout, tx_status_events, wpa_buf, sizeof(wpa_buf));
	if (res < 0 || strstr(wpa_buf, "result=FAILED") != NULL) {
		qtn_error("DPP_WAIT_TXSTATUS: timeout/error waiting for event");
		return -1;
	}

	qtn_log("DPP_WAIT_TXSTATUS2: %s", wpa_buf);
	return 0;
}

/* Process DPP AUTH messages */
static int qtn_dpp_process_auth_events(struct wpa_ctrl *ctrl, int timeout, int check_mutual,
					char *resp)
{
	int res;
	char wpa_buf[QTN_WPA_MSG_MAX_SIZE];

	static const char *auth_events[] = {
		"DPP-AUTH-SUCCESS",
		"DPP-NOT-COMPATIBLE",
		"DPP-RESPONSE-PENDING",
		"DPP-SCAN-PEER-QR-CODE",
		"DPP-AUTH-DIRECTION",
		NULL
	};

	res = get_wpa_cli_events(ctrl, timeout, auth_events, wpa_buf, sizeof(wpa_buf));
	if (res < 0) {
		snprintf(resp, QTN_MAX_BUF_LEN, "%s", "BootstrapResult,OK,AuthResult,Timeout");
		return -1;
	}

	qtn_log("DPP auth result1: %s", wpa_buf);

	if (strstr(wpa_buf, "DPP-RESPONSE-PENDING")) {
		qtn_error("DPP: manual DPP/ability to scan QR code during AUTH not supported");
		snprintf(resp, QTN_MAX_BUF_LEN, "%s", "BootstrapResult,OK,AuthResult,FAILED");
		return -1;
	}

	if (check_mutual) {
		if (strstr(wpa_buf, "DPP-NOT-COMPATIBLE")) {
			snprintf(resp, QTN_MAX_BUF_LEN, "%s",
				"BootstrapResult,OK,AuthResult,ROLES_NOT_COMPATIBLE");
			return -1;
		}

		if (!strstr(wpa_buf, "DPP-AUTH-DIRECTION")) {
			snprintf(resp, QTN_MAX_BUF_LEN, "%s",
				"BootstrapResult,OK,AuthResult,errorCode,No event for auth direction seen");
			return -1;
		}

		qtn_log("DPP auth direction: %s", wpa_buf);
		if (strstr(wpa_buf, "mutual=1") == NULL) {
			snprintf(resp, QTN_MAX_BUF_LEN, "%s",
				"BootstrapResult,OK,AuthResult,errorCode,Peer did not use mutual authentication");
			return -1;
		}
	}

	if (strstr(wpa_buf, "DPP-AUTH-DIRECTION")) {
		res = get_wpa_cli_events(ctrl, timeout, auth_events, wpa_buf, sizeof(wpa_buf));
		if (res < 0) {
			snprintf(resp, QTN_MAX_BUF_LEN, "%s",
					"BootstrapResult,OK,AuthResult,Timeout");
			return -1;
		}

		qtn_log("DPP auth result2: %s", wpa_buf);
	}

	if (strstr(wpa_buf, "DPP-NOT-COMPATIBLE")) {
		snprintf(resp, QTN_MAX_BUF_LEN, "%s",
			"BootstrapResult,OK,AuthResult,ROLES_NOT_COMPATIBLE");
		return -1;
	}

	if (!strstr(wpa_buf, "DPP-AUTH-SUCCESS")) {
		snprintf(resp, QTN_MAX_BUF_LEN, "%s",
			"BootstrapResult,OK,AuthResult,FAILED");
		return -1;
	}

	return 0;
}

/* Process DPP CONF messages */
static int qtn_dpp_process_ap_config_events(struct wpa_ctrl *ctrl, int timeout, char *resp)
{
	int ret;
	char wpa_buf[QTN_WPA_MSG_MAX_SIZE];
	struct timeval tv;
	static const char *ap_events[] = {
		"AP-ENABLED",
		NULL
	};

	qtn_log("%s: waiting for AP to reconfigure", __func__);

	ret = get_wpa_cli_events(ctrl, 10, ap_events, wpa_buf, sizeof(wpa_buf));
	if (ret < 0)
		qtn_error("Timeout waiting for AP-ENABLED event");
	else
		qtn_log("AP configure result: %s", wpa_buf);

	/* If we dont wait here and return,TB-STA immediately scans for new beacons and test fails
	 * Let AP reconfigure with new credentials; Add non-blocking wait for AP to start beaconing
	 */

	tv.tv_sec = QTN_AP_CONFIG_DELAY;
	tv.tv_usec = 0;
	select(0, NULL, NULL, NULL, &tv);

	snprintf(resp, QTN_MAX_BUF_LEN, "%s", "BootstrapResult,OK,AuthResult,OK,ConfResult,OK");

	return 0;
}

/* Process DPP CONF messages */
static int qtn_dpp_process_conf_events(struct wpa_ctrl *ctrl, int timeout, char *resp)
{
	int ret;
	char wpa_buf[QTN_WPA_MSG_MAX_SIZE];
	static const char *conf_events[] = {
		"DPP-CONF-RECEIVED",
		"DPP-CONF-SENT",
		"DPP-CONF-FAILED",
		NULL
	};

	ret = get_wpa_cli_events(ctrl, timeout, conf_events, wpa_buf, sizeof(wpa_buf));
	if (ret < 0) {
		snprintf(resp, QTN_MAX_BUF_LEN, "%s",
				"BootstrapResult,OK,AuthResult,OK,ConfResult,Timeout");
		return -1;
	}
	qtn_log("DPP conf result: %s", wpa_buf);

	if (!strstr(wpa_buf, "DPP-CONF-SENT") &&
		!strstr(wpa_buf, "DPP-CONF-RECEIVED")) {
		snprintf(resp, QTN_MAX_BUF_LEN, "%s",
				"BootstrapResult,OK,AuthResult,OK,ConfResult,FAILED");
		return -1;
	}

	return 0;
}

static int qtn_dpp_is_auth_mode_dpp(char *ifname, int *dpp_akm, char *resp)
{
	int ret;
	string_32 auth_mode;
	qcsapi_SSID current_SSID;


	ret = qcsapi_wifi_get_SSID(ifname, current_SSID);
	if (ret < 0) {
		snprintf(resp, QTN_MAX_BUF_LEN, "%s",
			  "BootstrapResult,OK,AuthResult,OK,ConfResult,OK,NetworkIntroResult,Timeout,NetworkConnectResult,FAILED");
		return -1;
	}

	ret = qcsapi_SSID_get_authentication_mode(ifname, current_SSID, auth_mode);
	if (ret < 0) {
		snprintf(resp, QTN_MAX_BUF_LEN, "%s",
			  "BootstrapResult,OK,AuthResult,OK,ConfResult,OK,NetworkIntroResult,Timeout,NetworkConnectResult,FAILED");
		return -1;
	}

	if (strcasecmp(auth_mode, "DPPAuthentication") == 0) {
		qtn_log("DPP: configured in authmode DPP");
		*dpp_akm = 1;
	} else {
		qtn_log("DPP: configured auth_mode %s", auth_mode);
		*dpp_akm = 0;
	}

	return 0;
}

/* Process DPP CONF messages */
static int qtn_dpp_process_connect_events(char *ifname, struct wpa_ctrl *ctrl,
					struct qcsapi_dpp_cfg *qcsapi_dpp, int timeout, char *resp)
{
	int ret;
	int dpp_akm = 0;
	char wpa_buf[QTN_WPA_MSG_MAX_SIZE];
	static const char *conn_events[] = {
		"PMKSA-CACHE-ADDED",
		"CTRL-EVENT-CONNECTED",
		NULL
	};

	ret = get_wpa_cli_events(ctrl, timeout, conn_events, wpa_buf, sizeof(wpa_buf));
	if (ret < 0) {
		snprintf(resp, QTN_MAX_BUF_LEN, "%s",
			  "BootstrapResult,OK,AuthResult,OK,ConfResult,OK,NetworkIntroResult,Timeout,NetworkConnectResult,Timeout");
		return -1;
	}

	qtn_log("DPP connect result1: %s", wpa_buf);

	if (strstr(wpa_buf, "CTRL-EVENT-CONNECTED"))
		goto success;

	/* This is PMKSA-CACHE-ADDED event; wait for CTRL-EVENT-CONNECTED*/
	ret = get_wpa_cli_events(ctrl, timeout, conn_events, wpa_buf, sizeof(wpa_buf));
	if (ret < 0)
		goto fail;

	qtn_log("DPP connect result2: %s", wpa_buf);
	if (strstr(wpa_buf, "CTRL-EVENT-CONNECTED"))
		goto success;

fail:
	ret = qtn_dpp_is_auth_mode_dpp(ifname, &dpp_akm, resp);
	if (ret)
		return -1;

	snprintf(resp, QTN_MAX_BUF_LEN, "%s",
			  dpp_akm ?
			  "BootstrapResult,OK,AuthResult,OK,ConfResult,OK,NetworkIntroResult,OK,NetworkConnectResult,Timeout" :
			  "BootstrapResult,OK,AuthResult,OK,ConfResult,OK,NetworkConnectResult,Timeout");
	return -1;

success:
	ret = qtn_dpp_is_auth_mode_dpp(ifname, &dpp_akm, resp);
	if (ret)
		return -1;

	snprintf(resp, QTN_MAX_BUF_LEN, "%s",
		  dpp_akm ?
		  "BootstrapResult,OK,AuthResult,OK,ConfResult,OK,NetworkIntroResult,OK,NetworkConnectResult,OK" :
		  "BootstrapResult,OK,AuthResult,OK,ConfResult,OK,NetworkConnectResult,OK");
	return 0;
}

static int qtn_dpp_get_local_bootstrap(struct qtn_cmd_request *cmd_req, char *ifname,
					char *resp, int *resp_len)
{
	int ret, len = 0;
	struct qtn_dut_dpp_config *dpp_config;
	char dpp_bs_type[16] = {0};
	unsigned char macaddr[IEEE80211_ADDR_LEN];
	qcsapi_wifi_mode current_mode;
	struct qcsapi_dpp_cfg *qcsapi_dpp = NULL;
	unsigned int curve = qtn_dpp_get_curve(cmd_req);
	struct qtn_dut_config *conf = qtn_dut_get_config(ifname);
	char dpp_status[16];
	char dpp_uri[QTN_MAX_BUF_LEN];
	char dpp_uri_hex[QTN_MAX_BUF_LEN];

	qtn_log("%s", __func__);

	memset(dpp_uri, 0, sizeof(dpp_uri));
	memset(dpp_uri_hex, 0, sizeof(dpp_uri_hex));

	if (!conf || !conf->dpp_config) {
		qtn_error("could not get qtn_dut_config or dpp_config");
		goto fail;
	}

	ret = qcsapi_wifi_get_mode(ifname, &current_mode);
	if (ret < 0) {
		qtn_error("can't get mode, error %d", ret);
		goto fail;
	}

	ret = qcsapi_interface_get_mac_addr(ifname, macaddr);
	if (ret  < 0) {
		qtn_error("can't get mac address, error %d", ret);
		goto fail;
	}

	dpp_config = conf->dpp_config;

	if (qtn_get_value_text(cmd_req, QTN_TOK_DPP_BS, dpp_bs_type,
				sizeof(dpp_bs_type)) <= 0) {
		qtn_error("can't get DPP bootstrapping method type");
		goto fail;
	}

	if (strcasecmp(dpp_bs_type, "QR") == 0) {
		dpp_config->bs_method = QCSAPI_DPP_BOOTSTRAP_QRCODE;
	} else if (strcasecmp(dpp_bs_type, "PKEX") == 0) {
		dpp_config->bs_method = QCSAPI_DPP_BOOTSTRAP_PKEX;
	} else {
		qtn_error("unsupported DPP bootstrapping method");
		goto fail;
	}

	qcsapi_dpp = (struct qcsapi_dpp_cfg *)malloc(sizeof(*qcsapi_dpp));
	if (!qcsapi_dpp) {
		qtn_error("Failed to allocate memory\n");
		goto fail;
	}

	memcpy(qcsapi_dpp->mac_addr, macaddr, sizeof(qcsapi_dpp->mac_addr));
	qcsapi_dpp->curve = curve;
	qcsapi_dpp->method = dpp_config->bs_method;

	ret = qcsapi_dpp_configure_param(ifname, QCSAPI_DPP_BOOTSTRAP_GEN, qcsapi_dpp,
						NULL, dpp_status, sizeof(dpp_status));
	if (ret || (strncasecmp(dpp_status, "FAIL", 4) == 0)) {
		qtn_error("Failed to generate DPP bootstrap\n");
		free(qcsapi_dpp);
		goto fail;
	}

	dpp_config->local_bootstrap = atoi(dpp_status);
	qcsapi_dpp->local_bootstrap = dpp_config->local_bootstrap;
	qtn_log("DPP bootstrap gen successful; id=%d", dpp_config->local_bootstrap);

	ret = qcsapi_dpp_configure_param(ifname, QCSAPI_DPP_GET_URI, qcsapi_dpp, NULL, dpp_uri,
						sizeof(dpp_uri));
	if (ret || (strncasecmp(dpp_uri, "FAIL", 4) == 0)) {
		qtn_error("Failed to get DPP URI\n");
		dpp_config->local_bootstrap = 0;
		free(qcsapi_dpp);
		goto fail;
	}

	qtn_log("DPP get_uri successful; id=%d", dpp_config->local_bootstrap);
	qtn_error("DPP URI: %s", dpp_uri);
	snprintf(dpp_config->local_uri, sizeof(dpp_config->local_uri), "%s", dpp_uri);

	len = 0;
	qtn_ascii_to_hexstr(dpp_config->local_uri, dpp_uri_hex);

	qtn_log("DPP URI hex; len=%zu str=%s", strlen(dpp_uri_hex), dpp_uri_hex);

	snprintf(resp, QTN_MAX_BUF_LEN, "BootstrappingData,%s", dpp_uri_hex);

	*resp_len = strlen(resp);
	qtn_log("AP1: DPP URI len=%zu, final dppstr=%s, bufferlen=%d", strlen(resp),
			resp, *resp_len);

	free(qcsapi_dpp);
	return ret;
fail:
	return -1;
}

static int qtn_dpp_set_peer_bootstrap(struct qtn_cmd_request *cmd_req, char *ifname,
					char *resp, int *resp_len)
{
	char uri[1024];
	int len;
	struct qtn_dut_dpp_config *dpp_config;
	struct qtn_dut_config *conf = qtn_dut_get_config(ifname);
	char dpp_bs_type[16] = {0};

	qtn_log("%s", __func__);

	if (!conf || !conf->dpp_config) {
		qtn_error("could not get qtn_dut_config or dpp_config");
		goto fail;
	}

	dpp_config = conf->dpp_config;

	if (qtn_get_value_text(cmd_req, QTN_TOK_DPP_BS, dpp_bs_type,
				sizeof(dpp_bs_type)) <= 0) {
		qtn_error("can't get DPP bootstrapping method type");
		goto fail;
	}

	if (strcasecmp(dpp_bs_type, "QR") == 0) {
		dpp_config->bs_method = QCSAPI_DPP_BOOTSTRAP_QRCODE;
	} else if (strcasecmp(dpp_bs_type, "PKEX") == 0) {
		dpp_config->bs_method = QCSAPI_DPP_BOOTSTRAP_PKEX;
	} else {
		qtn_error("unsupported DPP bootstrapping method");
		goto fail;
	}

	if (qtn_get_value_text(cmd_req, QTN_TOK_DPP_BSDATA, uri,
				sizeof(uri)) <= 0) {
		qtn_error("can't get DPP bootstrapping data");
		goto fail;
	}

	memset(dpp_config->peer_uri, 0, sizeof(dpp_config->peer_uri));
	len = qtn_hexstr_to_ascii(uri, dpp_config->peer_uri, sizeof(dpp_config->peer_uri));
	if (len < 0 || len >= (sizeof(dpp_config->peer_uri))) {
		qtn_error("failed to convert DPP URI into ascii");
		goto fail;
	}

	dpp_config->peer_uri[len] = '\0';
	qtn_error("Bootstrap peer URI %s", dpp_config->peer_uri);

	return 0;
fail:
	return -1;
}

static int qtn_dpp_init_manual_exchange(struct qtn_cmd_request *cmd_req, char *ifname,
					char *resp, int *resp_len)
{
	qtn_error("QTN DUT does not support manual DPP exchange");
	return -1;
}

static int
qtn_dpp_parse_network_conf(struct qtn_cmd_request *cmd_req, char *ifname, int enrollee_ap)
{
	struct qtn_dut_dpp_config *dpp_config;
	struct qcsapi_dpp_bss_config *bss_conf;
	struct qtn_dut_config *conf = qtn_dut_get_config(ifname);
	int dpp_conf_idx = -1;
	char hex_out[256] = "";

	if (!conf || !conf->dpp_config)
		return -1;

	dpp_config = conf->dpp_config;
	if (qtn_get_value_int(cmd_req, QTN_TOK_DPP_CONFIDX, &dpp_conf_idx) <= 0) {
		qtn_log("No DPP config index attribute");
		dpp_config->bss_conf = NULL;
		return 0;
	}

	qtn_log("DPP: Config index=%d", dpp_conf_idx);

	bss_conf = (struct qcsapi_dpp_bss_config *)malloc(sizeof(*bss_conf));
	if (!bss_conf)
		return -1;
	memset(bss_conf, 0, sizeof(*bss_conf));

	switch (dpp_conf_idx) {
	case 1:
		qtn_ascii_to_hexstr("DPPNET01", hex_out);
		snprintf((char *)bss_conf->ssid, sizeof(bss_conf->ssid), "ssid=%s", hex_out);
		if (enrollee_ap)
			snprintf(bss_conf->conf_role, sizeof(bss_conf->conf_role), "%s", "ap-dpp");
		else
			snprintf(bss_conf->conf_role, sizeof(bss_conf->conf_role), "%s", "sta-dpp");
		strcpy(bss_conf->psk, "");
		snprintf(bss_conf->group_id, sizeof(bss_conf->group_id), "%s",
				"DPPGROUP_DPP_INFRA");
		break;
	case 2:
		qtn_ascii_to_hexstr("DPPNET01", hex_out);
		snprintf((char *)bss_conf->ssid, sizeof(bss_conf->ssid), "ssid=%s", hex_out);
		snprintf(bss_conf->psk, sizeof(bss_conf->psk), "%s",
			"psk=10506e102ad1e7f95112f6b127675bb8344dacacea60403f3fa4055aec85b0fc");
		if (enrollee_ap)
			snprintf(bss_conf->conf_role, sizeof(bss_conf->conf_role), "%s", "ap-psk");
		else
			snprintf(bss_conf->conf_role, sizeof(bss_conf->conf_role), "%s", "sta-psk");
		break;
	case 3:
		qtn_ascii_to_hexstr("DPPNET01", hex_out);
		snprintf((char *)bss_conf->ssid, sizeof(bss_conf->ssid), "ssid=%s", hex_out);
		if (enrollee_ap)
			snprintf(bss_conf->conf_role, sizeof(bss_conf->conf_role), "%s", "ap-psk");
		else
			snprintf(bss_conf->conf_role, sizeof(bss_conf->conf_role), "%s", "sta-psk");
		qtn_ascii_to_hexstr("ThisIsDppPassphrase", hex_out);
		snprintf(bss_conf->psk, sizeof(bss_conf->psk), "pass=%s", hex_out);
		break;
	case 4:
		qtn_ascii_to_hexstr("DPPNET01", hex_out);
		snprintf((char *)bss_conf->ssid, sizeof(bss_conf->ssid), "ssid=%s", hex_out);
		if (enrollee_ap)
			snprintf(bss_conf->conf_role, sizeof(bss_conf->conf_role), "%s", "ap-dpp");
		else
			snprintf(bss_conf->conf_role, sizeof(bss_conf->conf_role), "%s", "sta-dpp");
		strcpy(bss_conf->psk, "");
		snprintf(bss_conf->group_id, sizeof(bss_conf->group_id), "%s",
				"DPPGROUP_DPP_INFRA2");
		break;
	case 5:
		qtn_ascii_to_hexstr("DPPNET01", hex_out);
		snprintf((char *)bss_conf->ssid, sizeof(bss_conf->ssid), "ssid=%s", hex_out);
		if (enrollee_ap)
			snprintf(bss_conf->conf_role, sizeof(bss_conf->conf_role), "%s", "ap-sae");
		else
			snprintf(bss_conf->conf_role, sizeof(bss_conf->conf_role), "%s", "sta-sae");
		qtn_ascii_to_hexstr("ThisIsDppPassphrase", hex_out);
		snprintf(bss_conf->psk, sizeof(bss_conf->psk), "pass=%s", hex_out);
		break;
	case 6:
		qtn_ascii_to_hexstr("DPPNET01", hex_out);
		snprintf((char *)bss_conf->ssid, sizeof(bss_conf->ssid), "ssid=%s", hex_out);
		if (enrollee_ap)
			snprintf(bss_conf->conf_role, sizeof(bss_conf->conf_role), "%s",
					"ap-psk-sae");
		else
			snprintf(bss_conf->conf_role, sizeof(bss_conf->conf_role), "%s",
					"sta-psk-sae");
		qtn_ascii_to_hexstr("ThisIsDppPassphrase", hex_out);
		snprintf(bss_conf->psk, sizeof(bss_conf->psk), "pass=%s", hex_out);
		break;
	default:
		qtn_error("Unsupported DPPConfIndex");
		goto out;

	}

	dpp_config->bss_conf = bss_conf;
	return 0;
out:
	free(bss_conf);
	bss_conf = NULL;
	return -1;
}

static int qtn_dpp_is_device_24g_capable(char *ifname)
{
	int ret;
	string_32 bands;

	ret = qcsapi_wifi_get_supported_freq_bands(ifname, bands);
	if (ret || !strstr(bands, "2.4G")) {
		qtn_log("DPP: assuming platform as single band(5G)");
		return 0;
	}

	qtn_log("DPP: platform 2.4G capable");
	return 1;
}

static int qtn_dpp_deduce_listen_freq(struct qtn_cmd_request *cmd_req, char *ifname,
					int bootstrap, int *freq)
{
	int listen_freq = 0;
	int listen_chan = 0;
	char dpp_listen_chan[8];
	int retval = 0;
	int device_24g_capable;

	device_24g_capable = qtn_dpp_is_device_24g_capable(ifname);
	if (device_24g_capable) {
		listen_freq = QTN_DPP_DEF_FREQ_24G;
	} else {
		if (bootstrap == QCSAPI_DPP_BOOTSTRAP_PKEX)
			listen_freq = QTN_DPP_DEF_FREQ_5G_PKEX;
		else
			listen_freq = QTN_DPP_DEF_FREQ_5G_QRCODE;
	}

	if (qtn_get_value_text(cmd_req, QTN_TOK_DPP_LISTENCHAN, dpp_listen_chan,
			sizeof(dpp_listen_chan)) <= 0) {
		qtn_log("DPP listen channel not specified; bootstrap=%s, use default freq %d",
			(bootstrap == QCSAPI_DPP_BOOTSTRAP_QRCODE) ?
			"QRCODE" : "PKEX", listen_freq);
	} else {
		listen_chan = atoi(dpp_listen_chan);

		if (!listen_chan || (listen_chan <= QTN_24G_CHAN_END && !device_24g_capable)) {
			retval = -1;
			goto done;
		}

		if (listen_chan <= QTN_24G_CHAN_END)
			listen_freq = QTN_24GCHAN_TO_FREQ(listen_chan);
		else if (listen_chan >= QTN_5G_CHAN_START && listen_chan <= QTN_5G_CHAN_END)
			listen_freq = QTN_5GCHAN_TO_FREQ(listen_chan);
		else
			retval = -1;

		qtn_log("DPP listen channel present; bootstrap=%s, chan=%d, freq=%d",
			(bootstrap == QCSAPI_DPP_BOOTSTRAP_QRCODE) ?
			"QRCODE" : "PKEX", listen_chan, listen_freq);
	}

	*freq = listen_freq;

done:
	if (retval)
		qtn_error("DPP: failed to parse listen channel information");

	return retval;
}

static int qtn_dpp_configure_default_channel(char *ifname, int dpp_bootstrap_method)
{
	int channel = DEFAULT_VHT_CHANNEL;
	struct timeval tv;
	int ret;
	char dev_phy_mode[32] = "";

	if (dpp_bootstrap_method == QCSAPI_DPP_BOOTSTRAP_PKEX)
		channel = DEFAULT_DPP_PKEX_CHANNEL;

	if (qtn_dpp_is_device_24g_capable(ifname))
		channel = DEFAULT_DPP_24G_CHANNEL;

	ret = qcsapi_wifi_get_phy_mode(ifname, dev_phy_mode);
	if (ret < 0) {
		qtn_error("DPP: failed to get phymode from driver");
		return ret;
	}

	qtn_log("DPP: current phymode %s", dev_phy_mode);

	if (channel == DEFAULT_DPP_24G_CHANNEL && !strstr(dev_phy_mode, "11ng")) {
		ret = qcsapi_wifi_set_phy_mode(ifname, "11ng");
	} else if ((channel == DEFAULT_DPP_PKEX_CHANNEL || channel == DEFAULT_VHT_CHANNEL) &&
			!strstr(dev_phy_mode, "11ac")) {
		ret = qcsapi_wifi_set_phy_mode(ifname, "11ac");
	}

	if (ret < 0) {
		qtn_error("DPP: failed to set phymode for channel %d, current mode %s",
				channel, dev_phy_mode);
		return ret;
	}

	ret = qcsapi_wifi_set_channel(ifname, channel);
	if (ret)
		return ret;

	/* Delay for setting AP channel */
	tv.tv_sec = QTN_AP_CHAN_CFG_DELAY;
	tv.tv_usec = 0;
	select(0, NULL, NULL, NULL, &tv);

	return 0;
}

static int qtn_dpp_init_automatic_exchange(struct qtn_cmd_request *cmd_req, char *ifname,
					char *resp, int *resp_len)
{
	int ret = 0;
	int enrollee_ap;
	int self_config;
	int check_mutual;
	int wait_connect;
	int dpp_timeout = 0;
	char dpp_bs[8] = {0};
	char dpp_pkex_code[64] = {0};
	char dpp_pkex_id[16] = {0};
	char dpp_prov_role[16] = {0};
	char dpp_auth_role[16] = {0};
	char dpp_self_conf[8] = {0};
	char dpp_conf_role[8] = {0};
	char dpp_wpa_resp[4] = {0};
	char dpp_peer_id[8] = {0};
	char dpp_auth_dir[8] = {0};
	char wait_for_connect[8] = {0};
	struct qcsapi_dpp_cfg *qcsapi_dpp = NULL;
	unsigned int curve = qtn_dpp_get_curve(cmd_req);
	struct qtn_dut_config *conf = qtn_dut_get_config(ifname);
	struct qtn_dut_dpp_config *dpp_config;
	qcsapi_wifi_mode current_mode;
	struct wpa_ctrl *ctrl = NULL;

	qtn_log("%s", __func__);

	if (!conf || !conf->dpp_config) {
		qtn_error("could not get qtn_dut_config or dpp_config");
		return -1;
	}
	dpp_config = conf->dpp_config;

	ctrl = qtn_dpp_open_wpa_mon(ifname);
	if (!ctrl) {
		qtn_error("could not allocate wpa_ctrl");
		goto fail;
	}

	qcsapi_dpp = (struct qcsapi_dpp_cfg *)malloc(sizeof(*qcsapi_dpp));
	if (!qcsapi_dpp) {
		qtn_error("Failed to generate DPP bootstrap\n");
		goto fail;
	}
	memset(qcsapi_dpp, 0, sizeof(*qcsapi_dpp));

	ret = qcsapi_wifi_get_mode(ifname, &current_mode);
	if (ret < 0) {
		qtn_error("can't get mode, error %d", ret);
		goto fail;
	}

	if (qtn_get_value_text(cmd_req, QTN_TOK_DPP_BS, dpp_bs,
				sizeof(dpp_bs)) <= 0) {
		qtn_error("can't get DPP bootstrap type");
		return -1;
	}

	if (strcasecmp(dpp_bs, "QR") == 0) {
		dpp_config->bs_method = QCSAPI_DPP_BOOTSTRAP_QRCODE;
	} else if (strcasecmp(dpp_bs, "PKEX") == 0) {
		dpp_config->bs_method = QCSAPI_DPP_BOOTSTRAP_PKEX;
	} else {
		qtn_error("unsupported DPP bootstrapping method");
		ret = -1;
		goto fail;
	}
	qcsapi_dpp->method = dpp_config->bs_method;

	if (qtn_get_value_text(cmd_req, QTN_TOK_DPP_AUTHROLE, dpp_auth_role,
				sizeof(dpp_auth_role)) <= 0) {
		qtn_error("can't get DPP Auth role");
		ret = -1;
		goto fail;
	}
	qtn_log("DPP: Auth role=%s", dpp_auth_role);

	if (qtn_get_value_text(cmd_req, QTN_TOK_DPP_PROVROLE, dpp_prov_role,
				sizeof(dpp_prov_role)) <= 0) {
		qtn_error("can't get DPP provisioning role");
		ret = -1;
		goto fail;
	}
	qtn_log("DPP: Prov role=%s", dpp_prov_role);

	if (qtn_get_value_int(cmd_req, QTN_TOK_DPP_TIMEOUT, &dpp_timeout) <= 0) {
		qtn_log("No DPPTimeout set; use default %ds", QTN_DPP_DEF_TIMEOUT);
		dpp_timeout = QTN_DPP_DEF_TIMEOUT;
	}

	if (qtn_get_value_text(cmd_req, QTN_TOK_DPP_WAITCONNECT, wait_for_connect,
				sizeof(dpp_prov_role)) <= 0) {
		qtn_log("No wait_for_connect option; set No");
	}
	wait_connect = (strcasecmp(wait_for_connect, "Yes") == 0);

	if (qtn_get_value_text(cmd_req, QTN_TOK_DPP_AUTHDIR, dpp_auth_dir,
				sizeof(dpp_auth_dir)) <= 0) {
		qtn_log("No DPP Auth direction option");
	}
	check_mutual = (strcasecmp(dpp_auth_dir, "Mutual") == 0);

	if (qtn_get_value_text(cmd_req, QTN_TOK_DPP_SELFCONFIG, dpp_self_conf,
				sizeof(dpp_self_conf)) <= 0) {
		qtn_log("No DPP Self config attribute");
	}
	qtn_log("DPP: SelfConfig=%s", dpp_self_conf);

	if (strcasecmp(dpp_self_conf, "YES") == 0)
		self_config = 1;
	else
		self_config = 0;

	if (qtn_get_value_text(cmd_req, QTN_TOK_DPP_CONFENROLLEEROLE, dpp_conf_role,
				sizeof(dpp_conf_role)) <= 0) {
		qtn_log("No DPP conf-enrollee role option");
	}
	qtn_log("DPP: ConfEnrollee role=%s", dpp_conf_role);

	if (strcasecmp(dpp_conf_role, "AP") == 0)
		enrollee_ap = 1;
	else
		enrollee_ap = 0;

	if (dpp_config->bs_method == QCSAPI_DPP_BOOTSTRAP_PKEX) {
		int ret = 0;
		char dpp_status[16];

		if (qtn_get_value_text(cmd_req, QTN_TOK_DPP_PKEXCODE, dpp_pkex_code,
					sizeof(dpp_pkex_code)) <= 0) {
			qtn_error("can't get DPP PKEX code for bootstrapping PKEX");
			ret = -1;
			goto fail;
		}
		strcpy(qcsapi_dpp->pkex_code, dpp_pkex_code);

		if (qtn_get_value_text(cmd_req, QTN_TOK_DPP_PKEXCODEIDENTIFIER, dpp_pkex_id,
					sizeof(dpp_pkex_id)) <= 0) {
			qtn_log("No DPP PKEX code identifier option");
			qcsapi_dpp->pkex_id[0] = '\0';
		} else {
			strcpy(qcsapi_dpp->pkex_id, dpp_pkex_id);
		}

		memset(qcsapi_dpp->mac_addr, 0xff, sizeof(qcsapi_dpp->mac_addr));
		qcsapi_dpp->curve = curve;
		qcsapi_dpp->method = dpp_config->bs_method;

		ret = qcsapi_dpp_configure_param(ifname, QCSAPI_DPP_BOOTSTRAP_GEN, qcsapi_dpp,
							NULL, dpp_status, sizeof(dpp_status));
		if (ret || (strncasecmp(dpp_wpa_resp, "FAIL", 4) == 0)) {
			qtn_error("Failed to generate DPP bootstrap\n");
			ret = -1;
			goto fail;
		}

		dpp_config->local_bootstrap = atoi(dpp_status);
		qcsapi_dpp->local_bootstrap = dpp_config->local_bootstrap;
		qtn_log("DPP bootstrap gen successful; id=%d", dpp_config->local_bootstrap);
	}

	if (self_config) {
		ret = qcsapi_dpp_configure_param(ifname, QCSAPI_DPP_ADD_CONFIGURATOR, qcsapi_dpp,
							NULL, dpp_wpa_resp, sizeof(dpp_wpa_resp));
		if (ret || (strncasecmp(dpp_wpa_resp, "FAIL", 4) == 0)) {
			qtn_error("Failed to add DPP configurator\n");
			ret = -1;
			goto fail;
		}

		dpp_config->config_id = atoi(dpp_wpa_resp);
		qcsapi_dpp->configurator_id = dpp_config->config_id;
		qtn_log("DPP adding configurator successful; id=%d", dpp_config->config_id);

		if (current_mode == qcsapi_access_point)
			enrollee_ap = 1;
	}

	if (qtn_dpp_parse_network_conf(cmd_req, ifname, enrollee_ap)) {
		qtn_error("failed to parse DPP config");
		ret = -1;
		goto fail;
	}

	if (!dpp_config->bss_conf &&
		(strcasecmp(dpp_prov_role, "Configurator") == 0 ||
		strcasecmp(dpp_prov_role, "Both") == 0)) {
		qtn_error("No BSS config found for provisioning role=configurator/both");
		ret = -1;
		goto fail;
	}

	if ((strcasecmp(dpp_prov_role, "Configurator") == 0) ||
		strcasecmp(dpp_prov_role, "Both") == 0) {
		if (!dpp_config->config_id) {
			ret = qcsapi_dpp_configure_param(ifname, QCSAPI_DPP_ADD_CONFIGURATOR,
								qcsapi_dpp, NULL, dpp_wpa_resp,
								sizeof(dpp_wpa_resp));
			if (ret || (strncasecmp(dpp_wpa_resp, "FAIL", 4) == 0)) {
				qtn_error("Failed to add DPP configurator\n");
				ret = -1;
				goto fail;
			}

			dpp_config->config_id = atoi(dpp_wpa_resp);
			qtn_log("DPP adding configurator successful; id=%d", dpp_config->config_id);
		}
		if (strcasecmp(dpp_prov_role, "Configurator") == 0)
			dpp_config->role = QCSAPI_DPP_ROLE_CONFIGURATOR;
		else
			dpp_config->role = QCSAPI_DPP_ROLE_BOTH;

		qtn_log("DPP: setting configurator id=%d", dpp_config->config_id);
		qcsapi_dpp->configurator_id = dpp_config->config_id;
		qcsapi_dpp->prov_role = dpp_config->role;
	} else if (strcasecmp(dpp_prov_role, "Enrollee") == 0) {
		dpp_config->role = QCSAPI_DPP_ROLE_ENROLLEE;
		dpp_config->config_id = 0;

		qcsapi_dpp->configurator_id = 0;
		qcsapi_dpp->prov_role = QCSAPI_DPP_ROLE_ENROLLEE;
	}

	if (current_mode == qcsapi_access_point || strcasecmp(dpp_auth_role, "Initiator") == 0) {
		ret = qtn_dpp_configure_default_channel(ifname, dpp_config->bs_method);
		if (ret) {
			qtn_error("DPP: could not configure default channel");
			ret = -1;
			goto fail;
		}
	}

	if (self_config) {
		if (strcasecmp(dpp_prov_role, "Configurator") != 0) {
			qtn_error("DPP: self-confi valid only with provisioning role as config");
			ret = -1;
			goto fail;
		}
		if (!dpp_config->bss_conf) {
			qtn_error("DPP: could not get valid confindex for DPP self-configuration");
			ret = -1;
			goto fail;
		}

		ret = qcsapi_dpp_configure_param(ifname, QCSAPI_DPP_SELF_CONFIGURE, qcsapi_dpp,
							dpp_config->bss_conf, dpp_wpa_resp,
							sizeof(dpp_wpa_resp));
		if (ret || (strncasecmp(dpp_wpa_resp, "FAIL", 4) == 0)) {
			qtn_error("Failed to perform self-configuration id=%d",
					dpp_config->config_id);
			ret = -1;
			goto fail;
		}

		ret = qtn_dpp_process_ap_config_events(ctrl, dpp_timeout, resp);
		if (ret) {
			qtn_error("Failed to process apconf events");
			ret = 0;
			goto fail;
		}

		goto success;
	} else if (strcasecmp(dpp_auth_role, "Initiator") == 0) {
		qcsapi_dpp->auth_init = 1;

		if (dpp_config->bs_method == QCSAPI_DPP_BOOTSTRAP_QRCODE) {
			if (!strlen(dpp_config->peer_uri)) {
				qtn_error("DPP: No URI information found for peer");
				ret = -1;
				goto fail;
			}
			qtn_error("DPP_AUTH_INIT URI %s", dpp_config->peer_uri);
			strcpy(qcsapi_dpp->peer_uri, dpp_config->peer_uri);
			ret = qcsapi_dpp_configure_param(ifname, QCSAPI_DPP_SET_QRCODE, qcsapi_dpp,
								NULL, dpp_peer_id,
								sizeof(dpp_peer_id));
			if (ret || (strncasecmp(dpp_peer_id, "FAIL", 4) == 0)) {
				qtn_error("DPP: Failed to set QRCODE");
				dpp_config->peer_bootstrap = 0;
				ret = -1;
				goto fail;
			}
			dpp_config->peer_bootstrap = atoi(dpp_peer_id);
			qcsapi_dpp->peer_bootstrap = dpp_config->peer_bootstrap;
			qtn_log("DPP QR code operation successful; id=%d",
					dpp_config->peer_bootstrap);

			qcsapi_dpp->configurator_id = dpp_config->config_id;
			ret = qcsapi_dpp_configure_param(ifname, QCSAPI_DPP_AUTH_INIT, qcsapi_dpp,
						dpp_config->bss_conf, dpp_wpa_resp,
						sizeof(dpp_wpa_resp));
			if (ret || (strncasecmp(dpp_wpa_resp, "FAIL", 4) == 0)) {
				qtn_error("Failed to initiate DPP auth");
				ret = -1;
				goto fail;
			}
		} else {
			ret = qcsapi_dpp_configure_param(ifname, QCSAPI_DPP_PKEX_ADD, qcsapi_dpp,
								dpp_config->bss_conf, dpp_wpa_resp,
								sizeof(dpp_wpa_resp));
			if (ret || (strncasecmp(dpp_wpa_resp, "FAIL", 4) == 0)) {
				qtn_error("Failed to add PKEX config");
				ret = -1;
				goto fail;
			}
		}
	} else if (strcasecmp(dpp_auth_role, "Responder") == 0) {
		int listen_freq = 0;

		qcsapi_dpp->auth_init = 0;
		if (dpp_config->bs_method == QCSAPI_DPP_BOOTSTRAP_QRCODE) {
			if (strlen(dpp_config->peer_uri)) {

				qtn_error("DPP_RESP_AUTH URI %s", dpp_config->peer_uri);
				strcpy(qcsapi_dpp->peer_uri, dpp_config->peer_uri);
				ret = qcsapi_dpp_configure_param(ifname, QCSAPI_DPP_SET_QRCODE,
								qcsapi_dpp, NULL,
								dpp_peer_id, sizeof(dpp_peer_id));
				if (ret || (strncasecmp(dpp_peer_id, "FAIL", 4) == 0)) {
					qtn_error("DPP: Failed to set QRCODE");
					dpp_config->peer_bootstrap = 0;
					ret = -1;
					goto fail;
				}

				dpp_config->peer_bootstrap = atoi(dpp_peer_id);
				qcsapi_dpp->peer_bootstrap = dpp_config->peer_bootstrap;
				qtn_log("DPP QR code operation successful; id=%d",
						dpp_config->peer_bootstrap);
			}
		} else {
			ret = qcsapi_dpp_configure_param(ifname, QCSAPI_DPP_PKEX_ADD,
							qcsapi_dpp, dpp_config->bss_conf,
							dpp_wpa_resp, sizeof(dpp_wpa_resp));
			if (ret || (strncasecmp(dpp_wpa_resp, "FAIL", 4) == 0)) {
				qtn_error("Failed to add PKEX config");
				ret = -1;
				goto fail;
			}
		}

		if (strcasecmp(dpp_prov_role, "Configurator") == 0) {
			if (!dpp_config->bss_conf) {
				qtn_error("DPP: invalid confindex for DPP self-configuration");
				ret = -1;
				goto fail;
			}

			qcsapi_dpp->configurator_id = dpp_config->config_id;

			ret = qcsapi_dpp_configure_param(ifname, QCSAPI_DPP_SET_CONFIGURATOR_PARAMS,
								qcsapi_dpp, dpp_config->bss_conf,
								dpp_wpa_resp, sizeof(dpp_wpa_resp));
			if (ret || (strncasecmp(dpp_wpa_resp, "FAIL", 4) == 0)) {
				qtn_error("Failed to set DPP configurator params");
				goto fail;
			}
		}

		if (dpp_config->bs_method == QCSAPI_DPP_BOOTSTRAP_QRCODE && check_mutual)
			strcpy(qcsapi_dpp->qrcode_str, "qr=mutual");
		else
			strcpy(qcsapi_dpp->qrcode_str, " ");

		if (qtn_dpp_deduce_listen_freq(cmd_req, ifname, dpp_config->bs_method,
						&listen_freq)) {
			qtn_error("Failed to parse listen channel information");
			snprintf(resp, QTN_MAX_BUF_LEN, "%s", "command parsing failed");
			goto fail;
		}

		qcsapi_dpp->listen_freq = listen_freq;
		qcsapi_dpp->listen_enable = 1;
		qcsapi_dpp->listen_dur = QTN_LISTEN_CHAN_DUR_MS;
		ret = qcsapi_dpp_configure_param(ifname, QCSAPI_DPP_CONFIG_REMAIN_CHAN, qcsapi_dpp,
							NULL, dpp_wpa_resp, sizeof(dpp_wpa_resp));
		if (ret || (strncasecmp(dpp_wpa_resp, "FAIL", 4) == 0)) {
			qtn_error("Failed to configure remain channel");
			goto fail;
		}
	} else {
		qtn_error("DPP: Unknown DPPAuthRole in automatic DPP exchange");
		goto fail;
	}

	if (!self_config && dpp_config->bs_method == QCSAPI_DPP_BOOTSTRAP_PKEX) {
		/* Handle PKEX commit request/response/confirm failures */
		if (strcasecmp(dpp_auth_role, "Initiator") == 0) {
			qtn_log("DPP: PKEX, role=init");
			if (qtn_dpp_wait_tx(ctrl, dpp_timeout, 0)) {
				snprintf(resp, QTN_MAX_BUF_LEN, "%s", "BootstrapResult,Timeout");
				ret = 0;
				goto fail;
			}
		} else if (strcasecmp(dpp_auth_role, "Responder") == 0) {
			qtn_log("DPP: PKEX, role=respond");
			if (qtn_dpp_wait_tx_status(ctrl, dpp_timeout, 10)) {
				snprintf(resp, QTN_MAX_BUF_LEN, "%s", "BootstrapResult,Timeout");
				ret = 0;
				goto fail;
			}
		}
	}

	ret = qtn_dpp_process_auth_events(ctrl, dpp_timeout, check_mutual, resp);
	if (ret) {
		qtn_error("Failed to process auth events");
		ret = 0;
		goto fail;
	}

	ret = qtn_dpp_process_conf_events(ctrl, dpp_timeout, resp);
	if (ret) {
		qtn_error("Failed to process conf events");
		ret = 0;
		goto fail;
	}

	if (current_mode == qcsapi_access_point &&
		strcasecmp(dpp_prov_role, "Enrollee") == 0) {
		ret = qtn_dpp_process_ap_config_events(ctrl, dpp_timeout, resp);
		if (ret) {
			qtn_error("Failed to process apconf events");
			ret = 0;
			goto fail;
		}
		goto success;
	}

	if (wait_connect && current_mode == qcsapi_station &&
		strcasecmp(dpp_prov_role, "Enrollee") == 0) {
		ret = qtn_dpp_process_connect_events(ifname, ctrl, qcsapi_dpp, dpp_timeout, resp);
		if (ret) {
			qtn_error("Failed to process connect events");
			ret = 0;
			goto fail;
		}
	} else {
		snprintf(resp, QTN_MAX_BUF_LEN, "%s",
			"BootstrapResult,OK,AuthResult,OK,ConfResult,OK,NetworkConnectResult,OK");
	}

success:
	qtn_log("DPP exchange successful, auth_role=%s, prov_role=%s", dpp_auth_role,
			dpp_prov_role);
	qtn_log("DPP response=%s", resp);

fail:
	*resp_len = strlen(resp);
	free(qcsapi_dpp);
	free(dpp_config->bss_conf);
	qtn_dpp_close_wpa_mon(ctrl);
	return ret;
}

int qtn_handle_dpp_dev_action(struct qtn_cmd_request *cmd_req, char *ifname,
				char *resp, int *resp_len)
{
	char dpp_act_type[64] = {0};

	if (qtn_get_value_text(cmd_req, QTN_TOK_DPP_ACTTYPE, dpp_act_type,
				sizeof(dpp_act_type)) <= 0) {
		qtn_error("can't get DPP action type");
		goto fail;
	}

	qtn_log("dpp_dev_action: action type : %s", dpp_act_type);

	if (strcasecmp(dpp_act_type, "GETLOCALBOOTSTRAP") == 0)
		return qtn_dpp_get_local_bootstrap(cmd_req, ifname, resp, resp_len);
	else if (strcasecmp(dpp_act_type, "SETPEERBOOTSTRAP") == 0)
		return qtn_dpp_set_peer_bootstrap(cmd_req, ifname, resp, resp_len);
	else if (strcasecmp(dpp_act_type, "MANUALDPP") == 0)
		return qtn_dpp_init_manual_exchange(cmd_req, ifname, resp, resp_len);
	else if (strcasecmp(dpp_act_type, "AUTOMATICDPP") == 0)
		return qtn_dpp_init_automatic_exchange(cmd_req, ifname, resp, resp_len);

	qtn_error("dpp_dev_action: unsupported action %s", dpp_act_type);
fail:
	return -1;
}
