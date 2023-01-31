/****************************************************************************
*
* Copyright (c) 2017  Quantenna Communications, Inc.
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

#include "qtn_ap_handler.h"

#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <qcsapi.h>
#include <net80211/ieee80211.h>

#include "qtn_cmd_parser.h"
#include "qtn_log.h"
#include "qtn_defconf.h"
#include "qtn_common.h"

static void qtn_handle_ap_get_info(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_ap_set_radius(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_ap_set_wireless(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_ap_set_security(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_ap_reboot(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_ap_reset_default(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_ap_set_11n_wireless(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_ap_set_staqos(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_ap_set_apqos(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_ap_config_commit(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_ap_get_mac_address(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_ap_set_rfeature(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_ap_set_pmf(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_ap_ca_version(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_ap_send_addba_req(const char *params, int len, struct qtn_response *resp);


static const struct qtn_cmd_handler qtn_ap_handler_map[] = {
	{"AP_GET_INFO", qtn_handle_ap_get_info},
	{"AP_SET_RADIUS", qtn_handle_ap_set_radius},
	{"AP_SET_WIRELESS", qtn_handle_ap_set_wireless},
	{"AP_SET_SECURITY", qtn_handle_ap_set_security},
	{"AP_RESET_DEFAULT", qtn_handle_ap_reset_default},
	{"AP_SET_11N_WIRELESS", qtn_handle_ap_set_11n_wireless},
	{"AP_REBOOT", qtn_handle_ap_reboot},
	{"AP_SET_APQOS", qtn_handle_ap_set_apqos},
	{"AP_SET_STAQOS", qtn_handle_ap_set_staqos},
	{"AP_CONFIG_COMMIT", qtn_handle_ap_config_commit},
	{"AP_GET_MAC_ADDRESS", qtn_handle_ap_get_mac_address},
	{"AP_SET_RFEATURE", qtn_handle_ap_set_rfeature},
	{"AP_CA_VERSION", qtn_handle_ap_ca_version},
	{"AP_SET_PMF", qtn_handle_ap_set_pmf},
	{"AP_SEND_ADDBA_REQ", qtn_handle_ap_send_addba_req},
};

#define N_ARRAY(arr)			(sizeof(arr)/sizeof(arr[0]))

const struct qtn_cmd_handler * qtn_lookup_ap_handler(const char *cmd, int len)
{
	return qtn_lookup_cmd_handler(cmd, len, qtn_ap_handler_map,
			N_ARRAY(qtn_ap_handler_map));
}

#define IEEE80211_TXOP_TO_US(_txop)	(uint32_t)(_txop) << 5

static
const char *promote_auth_for_pmf(const char *auth)
{
	if (strcasecmp(auth, "PSKAuthentication") == 0)
		return "SHA256PSKAuthentication";

	if (strcasecmp(auth, "EAPAuthentication") == 0)
		return "SHA256EAPAuthentication";

	return auth;
}

static
int set_keymgnt(const char *if_name, const char *keymgnt, int pmf_required)
{
	int result;
	int i;
	static const struct {
		const char *keymgnt;
		const char *beacon;
		const char *auth;
		const char *enc;
	} keymgnt_map[] = {
		{
		.keymgnt = "NONE",.beacon = "Basic",.auth = "PSKAuthentication",.enc =
				"AESEncryption"}, {
		.keymgnt = "WPA-PSK-disabled",.beacon = "WPA",.auth =
				"PSKAuthentication",.enc = "TKIPEncryption"}, {
		.keymgnt = "WPA2-PSK",.beacon = "11i",.auth = "PSKAuthentication",.enc =
				"AESEncryption"}, {
		.keymgnt = "WPA-ENT",.beacon = "WPA",.auth = "EAPAuthentication",.enc =
				"TKIPEncryption"}, {
		.keymgnt = "WPA2-ENT",.beacon = "11i",.auth = "EAPAuthentication",.enc =
				"AESEncryption"}, {
		.keymgnt = "WPA2-PSK-Mixed",.beacon = "WPAand11i",.auth =
				"PSKAuthentication",.enc = "TKIPandAESEncryption"}, {
		.keymgnt = "WPA2-Mixed",.beacon = "WPAand11i",.auth =
				"PSKAuthentication",.enc = "TKIPandAESEncryption"}, {
		.keymgnt = "OSEN",.beacon = "Basic",
				.auth = "EAPAuthentication",.enc = "AESEncryption"}, {
		NULL}
	};

	for (i = 0; keymgnt_map[i].keymgnt != NULL; ++i) {
		if (strcasecmp(keymgnt, keymgnt_map[i].keymgnt) == 0) {
			break;
		}
	}

	if (keymgnt_map[i].keymgnt == NULL) {
		return -EINVAL;
	}

	if ((result = qcsapi_wifi_set_beacon_type(if_name, keymgnt_map[i].beacon)) < 0) {
		qtn_error("can't set beacon_type to %s, error %d", keymgnt_map[i].beacon, result);
		return result;
	}

	const char *auth = keymgnt_map[i].auth;

	if (pmf_required)
		auth = promote_auth_for_pmf(auth);

	if ((result = qcsapi_wifi_set_WPA_authentication_mode(if_name, auth)) < 0) {
		qtn_error("can't set authentication to %s, error %d", keymgnt_map[i].auth, result);
		return result;
	}

	if ((result = qcsapi_wifi_set_WPA_encryption_modes(if_name, keymgnt_map[i].enc)) < 0) {
		qtn_error("can't set encryption to %s, error %d", keymgnt_map[i].enc, result);
		return result;
	}

	if (strcasecmp(keymgnt, "OSEN") == 0) {
		if ((result = qcsapi_wifi_set_hs20_params(if_name, "osen", "1", "", "", "", "", "")) < 0) {
			qtn_error("can't enable OSEN, error %d", result);
			return result;
		}
		if ((result = qcsapi_wifi_set_hs20_params(if_name, "disable_dgaf",
							"1", "", "", "", "", "")) < 0 ) {
			qtn_error("can't disable DGAF, error %d", result);
			return result;
		}
	}

	return result;
}

static
int set_ap_encryption(const char *if_name, const char *enc)
{
	int i;

	static const struct {
		const char *sigma_enc;
		const char *encryption;
	} map[] = {
		{
		.sigma_enc = "TKIP",.encryption = "TKIPEncryption"}, {
		.sigma_enc = "AES",.encryption = "AESEncryption"}, {
		NULL}
	};

	for (i = 0; map[i].sigma_enc != NULL; ++i) {
		if (strcasecmp(enc, map[i].sigma_enc) == 0) {
			break;
		}
	}

	if (map[i].sigma_enc == NULL) {
		return -EINVAL;
	}

	return qcsapi_wifi_set_WPA_encryption_modes(if_name, map[i].encryption);
}

static
int set_channel(const char *ifname, int channel)
{
	int ret = 0;
	char region[16];
	char channel_str[16];

	if ((ret = qcsapi_wifi_get_regulatory_region(ifname, region)) < 0) {
		qtn_error("can't get regulatory region, error %d", ret);
		return ret;
	}

	qcsapi_wifi_wait_scan_completes(ifname, QTN_SCAN_TIMEOUT_SEC);

	snprintf(channel_str, sizeof(channel_str), "%d", channel);
	if (strcasecmp(region, "none") == 0) {
		ret = qcsapi_wifi_set_channel(ifname, channel);
		if (ret > 0) {
			ret = qcsapi_config_update_parameter(ifname, "channel", channel_str);
		} else {
			qtn_error("can't set channel to %d, error %d", channel, ret);
		}

		return ret;
	}

	ret = qcsapi_regulatory_set_regulatory_channel(ifname, channel, region, 0);
	if (ret == -qcsapi_region_database_not_found) {
		ret = qcsapi_wifi_set_regulatory_channel(ifname, channel, region, 0);
	}

	if (ret < 0) {
		qtn_error("can't set regulatory channel to %d, error %d", channel, ret);
	} else if ((ret = qcsapi_config_update_parameter(ifname, "channel", channel_str)) < 0) {
		qtn_error("can't update channel, error %d", ret);
	}

	/* Wait for CSA to finish after channel switch */
	if (ret >= 0)
		sleep(2);

	return ret;
}

static
int safe_channel_switch(const char *ifname, int channel)
{
	/* try to swith channel safely and handle case when current bandwidth
	 * can't be use on desired channel */
	int res = set_channel(ifname, channel);
	if (res < 0) {
		/* looks like we can't switch to the channel, try to reduce bandwidth to
		 * minimin and switch again */
		if (qcsapi_wifi_set_bw(ifname, qcsapi_bw_20MHz) < 0)
			qtn_error("failed to set bandwidth to 20MHz");

		qtn_log("reduce bw to 20MHz to be able to switch to channel %d", channel);
		res = set_channel(ifname, channel);
	}

	return res;
}

static
int set_country_code(const char *ifname, const char *country_code)
{
	int ret;
	char region[16];

	if ((ret = qcsapi_wifi_get_regulatory_region(ifname, region)) < 0) {
		qtn_error("can't get regulatory region, error %d", ret);
		return ret;
	}

	if (strcasecmp(region, country_code) != 0 &&
		(ret = qcsapi_config_update_parameter(ifname, "region", country_code)) < 0) {
		qtn_error("can't update regulatory region, error %d", ret);
		return ret;
	}

	return 0;
}

static
void qtn_handle_ap_get_info(const char *params, int len, struct qtn_response *resp)
{
	char firmware_version[QTN_VERSION_LEN];
	char interface_list[QTN_INTERFACE_LIST_LEN] = {0};
	char if_name[QTN_INTERFACE_LIST_LEN];
	const char *band = "5G";
	string_64 chipid;
	unsigned int idx;

	if (qcsapi_firmware_get_version(firmware_version, sizeof(firmware_version)) < 0) {
		snprintf(firmware_version, sizeof(firmware_version), "unknown");
	}

	if (qcsapi_get_board_parameter(qcsapi_rf_chipid, chipid) == 0) {
		if (strcmp(chipid, "0") == 0) {
			band = "24G";
		} else if (strcmp(chipid, "1") == 0) {
			band = "5G";
		} else if (strcmp(chipid, "2") == 0) {
			band = "any";
		}
	}

	for (idx = 0; qcsapi_get_interface_by_index(idx, if_name, sizeof(if_name)) == 0; ++idx) {
		const size_t have = strlen(interface_list);
		const size_t left = sizeof(interface_list) - have;
		char *dest = interface_list + have;
		/* should build string like: 'wifi0_5G wifi1_24G wifi2_any' */
		snprintf(dest, left, "%s%s_%s", idx == 0 ? "" : " ", if_name, band);
	}

	resp->status = STATUS_COMPLETE;

	snprintf(resp->param_buf, sizeof(resp->param_buf),
		"interface,%s,firmware,%s,agent,%s",
		interface_list,
		firmware_version,
		CA_VERSION);
}

static
int clear_radius(const char *if_name)
{
	static string_1024 all_radius_cfg;
	int ret = 0;

	qtn_log("clearing RADIUS servers");

	ret = qcsapi_wifi_get_radius_auth_server_cfg(if_name, all_radius_cfg);
	if (ret < 0) {
		if (ret == -qcsapi_parameter_not_found) {
			return 0;
		} else {
			qtn_error("error: failed to get RADIUS server config, if_name %s, error %d",
				  if_name, ret);
			return ret;
		}
	}

	char *cfg_saveptr;
	char *fields_saveptr;
	char *cfg;
#define RADIUS_CFG_FIELDS_NUM 3
	const char *fields[RADIUS_CFG_FIELDS_NUM];

	for (cfg = strtok_r(all_radius_cfg, "\n", &cfg_saveptr);
		cfg;
		cfg = strtok_r(NULL, "\n", &cfg_saveptr)) {
		for (int i = 0; i < RADIUS_CFG_FIELDS_NUM; ++i)
			fields[i] = strtok_r(i == 0 ? cfg : NULL, " ", &fields_saveptr);

		const char *ip = fields[0];
		const char *port = fields[1];
		if (!ip || !port) {
			qtn_error("error: failed to parse RADIUS server config, %s", cfg);
			return -EFAULT;
		}

		qtn_log("removing RADIUS server: ip %s, port %s", ip, port);
		ret = qcsapi_wifi_del_radius_auth_server_cfg(if_name, ip, port);
		if (ret < 0) {
			qtn_error("error: failed to remove RADIUS server, ip %s, port %s", ip, port);
			return ret;
		}
	}

	return 0;
}

void qtn_handle_ap_set_radius(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char ip[QTN_IP_LEN];
	int port;
	char password[QTN_PASSWORD_LEN];
	char ifname_buf[QTN_INTERFACE_LEN];
	int vap_index;
	const char* ifname;

	ret = qtn_init_cmd_request(&cmd_req, params, len);

	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	/* mandatory IP Address of RADIUS server */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_IPADDR, ip, sizeof(ip)) <= 0) {
		resp->status = STATUS_ERROR;
		resp->error_code = -EINVAL;
		return;
	}

	/* mandatory Port number of RADIUS service */
	if (qtn_get_value_int(&cmd_req, QTN_TOK_PORT, &port) <= 0) {
		resp->status = STATUS_ERROR;
		resp->error_code = -EINVAL;
		return;
	}

	/* mandatory Shared secret between RADIUS server and AP */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_PASSWORD, password, sizeof(password)) <= 0) {
		resp->status = STATUS_ERROR;
		resp->error_code = -EINVAL;
		return;
	}

	/* optional radio H/W interface */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname_buf, sizeof(ifname_buf)) <= 0) {
		*ifname_buf = 0;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_WLAN_TAG, &vap_index) > 0)
		vap_index -= 1;
	else
		vap_index = 0;

	/* interface is optional, so it can be empty */
	ifname = (*ifname_buf == 0) ?
		qtn_get_sigma_vap_interface(vap_index) : ifname_buf;

	ret = clear_radius(ifname);

	if (ret < 0) {
		qtn_error("error: failed to clear RADIUS servers, if_name %s", ifname);
		resp->status = STATUS_ERROR;
		resp->error_code = ret;
		return;
	}

	qtn_log("try to set radius: ip %s, port %d, pwd %s, if %s/%s",
		ip, port, password, ifname_buf, ifname);

	char port_str[16];
	snprintf(port_str, sizeof(port_str), "%d", port);

	ret = qcsapi_wifi_add_radius_auth_server_cfg(ifname, ip, port_str, password);
	if (ret < 0) {
		qtn_error("can't set radius ip, error %d", ret);
		resp->status = STATUS_ERROR;
		resp->error_code = ret;
		return;
	}

	resp->status = STATUS_COMPLETE;
}

static int set_phy_mode(const char *if_name, const char *mode)
{
	int ret;
	qcsapi_unsigned_int old_bw;

	if (qcsapi_wifi_get_bw(if_name, &old_bw) < 0) {
		old_bw = 80;
	}

	ret = qcsapi_wifi_set_phy_mode(if_name, mode);

	if (ret >= 0
		&& (!strcasecmp(mode, "11ac")
			|| !strcasecmp(mode, "11ng")
			|| !strcasecmp(mode, "11na"))) {
		// restore old bandwidth
		if (qcsapi_wifi_set_bw(if_name, old_bw) < 0)
			qtn_error("failed to restore old bandwidth");
	}

	return ret;
}

int qtn_create_vap(uint32_t vap_index)
{
	int ret = 0;

	if (vap_index == 0)
		return 0;

	char ifname[IFNAMSIZ] = {0};
	sprintf(ifname, "wifi%u", vap_index);

	char status[32] = {0};
	ret = qcsapi_interface_get_status(ifname, status);
	if (ret >= 0)
		return 0;

	uint8_t mac_addr[MAC_ADDR_SIZE];
	ret = qcsapi_interface_get_mac_addr(qtn_get_sigma_interface(), mac_addr);
	if (ret < 0) {
		qtn_error("failed to get primary interface mac address, ifname = %s",
			  qtn_get_sigma_interface());
		return ret;
	}
	mac_addr[5]++;

	return qcsapi_wifi_create_bss(ifname, mac_addr);
}

void qtn_handle_ap_set_wireless(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char cert_prog[32];
	int vht_prog;
	char ifname_buf[QTN_INTERFACE_LEN];
	int vap_index;
	const char *ifname;
	qcsapi_SSID ssid;
	char val_text[128];
	int val_int;
	int nss_tx;
	int nss_rx;

	ret = qtn_init_cmd_request(&cmd_req, params, len);

	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	qtn_bring_up_radio_if_needed();

	if (qtn_get_value_text(&cmd_req, QTN_TOK_PROGRAM, cert_prog, sizeof(cert_prog)) <= 0) {
		*cert_prog = 0;
	}

	vht_prog = (strcasecmp(cert_prog, "VHT") == 0) ? 1 : 0;

	if (qtn_get_value_text(&cmd_req, QTN_TOK_MODE, val_text, sizeof(val_text)) > 0) {
		/* 11b, 11bg, 11bgn, 11a, 11na, 11ac
		 * or 11ac;11ng
		 */
		char mode[2][10];

		if (strstr(val_text, ";") != NULL)
			sscanf(val_text, "%9[^;];%9[^;]", mode[0], mode[1]);
		else
			snprintf(mode[0], sizeof(mode[0]), "%s", val_text);

		ret = set_phy_mode(qtn_get_sigma_interface(), mode[0]);
		if (ret < 0) {
			qtn_error("can't set phy_mode to %s, error %d", mode[0], ret);
			goto respond;
		}
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_WLAN_TAG, &vap_index) > 0) {
		vap_index -= 1;

		if ((vap_index > 0) && ((ret = qtn_create_vap(vap_index)) < 0)) {
			qtn_error("failed to create vap, vap_index = %u", vap_index);
			goto respond;
		}
	} else
		vap_index = 0;

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname_buf, sizeof(ifname_buf)) <= 0) {
		*ifname_buf = 0;
	}

	ifname = (*ifname_buf) ? ifname_buf : qtn_get_sigma_vap_interface(vap_index);

	if (qtn_get_value_text(&cmd_req, QTN_TOK_SSID, ssid, sizeof(ssid)) > 0) {
		ret = qcsapi_wifi_set_SSID(ifname, ssid);
		if (ret < 0) {
			qtn_error("can't set SSID %s, error %d", ssid, ret);
			goto respond;
		}
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_CHANNEL, val_text, sizeof(val_text)) > 0) {
		/* channel number,
		 * separated for dual band: 36;6
		 */
		int chan[2] = {0, 0};
		if (strstr(val_text, ";") != NULL)
			sscanf(val_text, "%d;%d", &chan[0], &chan[1]);
		else
			sscanf(val_text, "%d", &chan[0]);

		ret = safe_channel_switch(ifname, chan[0]);

		if (ret < 0) {
			qtn_error("can't set channel %d, error %d", chan[0], ret);
			goto respond;
		}
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_COUNTRY_CODE, val_text, sizeof(val_text)) > 0) {
		/* 2 character country code in Country Information Element
		 * String: For Example  US
		 */
		ret = set_country_code(ifname, val_text);

		if (ret < 0) {
			qtn_error("can't set country code to %s, error %d", val_text, ret);
			goto respond;
		}
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_WME, val_text, sizeof(val_text)) > 0) {
		/* WME on/off , String */
		int wmm_on = (strcasecmp(val_text, "on") == 0) ? 1 : 0;
		ret = qcsapi_wifi_set_option(ifname, qcsapi_wmm, wmm_on);

		if (ret < 0) {
			qtn_error("can't set wmm to %d, error %d", wmm_on, ret);
			goto respond;
		}
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_WMMPS, val_text, sizeof(val_text)) > 0) {
		/* APSD on/off , String */
		int apsd_on = (strcasecmp(val_text, "on") == 0) ? 1 : 0;
		ret = qcsapi_wifi_set_option(ifname, qcsapi_uapsd, apsd_on);

		if (ret < 0) {
			qtn_error("can't set apsd to %d, error %d", apsd_on, ret);
			goto respond;
		}
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_RTS, &val_int) > 0) {
		/* Threshold, Short Integer */
		ret = qcsapi_wifi_set_rts_threshold(ifname, (qcsapi_unsigned_int)val_int);

		if (ret < 0) {
			qtn_error("can't set rts_threshold to %d, error %d", val_int, ret);
			goto respond;
		}
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_PWRSAVE, val_text, sizeof(val_text)) > 0) {
		/* Power Save, String */
		int power_save = strcasecmp(val_text, "off") != 0;
		ret = qcsapi_pm_set_mode(power_save ? QCSAPI_PM_MODE_AUTO :
				QCSAPI_PM_MODE_DISABLE);

		if (ret < 0) {
			qtn_error("can't set pm to %d, error %d", power_save, ret);
			goto respond;
		}
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_BCNINT, &val_int) > 0) {
		/* Beacon Interval */
		ret = qcsapi_wifi_set_beacon_interval(ifname, (qcsapi_unsigned_int)val_int);

		if (ret < 0) {
			qtn_error("can't set beacon_interval to %d, error %d", val_int, ret);
			goto respond;
		}
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_RADIO, val_text, sizeof(val_text)) > 0) {
		/* On/Off the radio of given interface */
		int rf_enable = strcasecmp(val_text, "off") != 0;
		ret = qtn_set_rf_enable(rf_enable);

		if (ret < 0) {
			qtn_error("can't set rf_enable to %d, error %d", rf_enable, ret);
			goto respond;
		}
	}

	if (qtn_get_value_enable(&cmd_req, QTN_TOK_AMSDU, &val_int, NULL) > 0) {
		/* AMSDU Aggregation: Enable, Disable */
		ret = qcsapi_wifi_set_tx_amsdu(ifname, val_int);

		if (ret < 0) {
			qtn_error("can't set amsdu to %d, error %d", val_int, ret);
			goto respond;
		}
	}

	/* SPATIAL_TX_STREAM, (1SS/2SS/3SS) */
	nss_tx = 0;

	if (qtn_get_value_text(&cmd_req, QTN_TOK_SPATIAL_TX_STREAM, val_text, sizeof(val_text)) > 0) {
		// Depending upon the MODE' parameter, two options.
		// For mode=11na - Sets the Tx spacial streams of the AP and which means the Tx MCS Rates capability.
		// For mode=11ac - Sets the Tx spacial streams of the AP. No inter-dependency of number of spatial streams and MCS rates.
		if (sscanf(val_text, "%dSS", &nss_tx) != 1) {
			qtn_error("invalid nss for tx %s", val_text);
			ret = -EINVAL;
			goto respond;
		}

	}

	/* SPATIAL_RX_STREAM, (1SS/2SS/3SS) */
	nss_rx = 0;
	
	if (qtn_get_value_text(&cmd_req, QTN_TOK_SPATIAL_RX_STREAM, val_text, sizeof(val_text)) > 0) {
		// Depending upon the MODE' parameter, two options.
		// For mode=11na - Sets the Rx spacial streams of the AP and
		// which means the Rx MCS Rates capability.
		// For mode=11ac - Sets the Rx spacial streams of the AP.
		// No inter-dependency of number of spatial streams and MCS rates.
		if (sscanf(val_text, "%dSS", &nss_rx) != 1) {
			qtn_error("invalid nss for rx %s", val_text);
			ret = -EINVAL;
			goto respond;
		}
	}

	if (nss_tx > 0 || nss_rx > 0) {
		qcsapi_mimo_type mt = vht_prog ? qcsapi_mimo_vht : qcsapi_mimo_ht;
		
		/* TODO: looks like we cannot setup NSS separatly for RX and TX */
		if (nss_tx != nss_rx) {
			qtn_error("can't set different nss for tx %d and rx %d", nss_tx, nss_rx);
			ret = -EINVAL;
			goto respond;
		}

		ret = qcsapi_wifi_set_nss_cap(ifname, mt, nss_tx);

		if (ret < 0) {
			qtn_error("can't set tx nss to %d, mimo_type %d, error %d", nss_tx, mt, ret);
			goto respond;
		}

		ret = qcsapi_wifi_set_rx_nss_cap(ifname, mt, nss_rx);

		if (ret < 0) {
			qtn_error("can't set rx nss to %d, mimo_type %d, error %d", nss_rx, mt, ret);
			goto respond;
		}
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_WIDTH, val_text, sizeof(val_text)) > 0) {
		/* channel width: 20, 40, 80, 160, Auto */
		unsigned int bw_cap;

		if (strcasecmp(val_text, "auto") == 0) {
			bw_cap = vht_prog ? 80 : 40;
		} else if (sscanf(val_text, "%u", &bw_cap) != 1) {
			qtn_error("invalid channel width: %s", val_text);
			ret = -EINVAL;
			goto respond;
		}

		ret = qcsapi_wifi_set_bw(ifname, bw_cap);
		if (ret < 0) {
			qtn_error("can't set bandwidth to %d, error %d", bw_cap, ret);
			goto respond;
		}
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_DTIM, val_text, sizeof(val_text)) > 0) {
		unsigned int dtim;
		if (sscanf(val_text, "%u", &dtim) != 1) {
			qtn_error("invalid DTIM: %s", val_text);
			ret = -EINVAL;
			goto respond;
		}

		ret = qcsapi_wifi_set_dtim(ifname, dtim);
		if (ret < 0) {
			qtn_error("can't set dtim to %d, error %d", dtim, ret);
			goto respond;
		}
	}

	if (qtn_get_value_enable(&cmd_req, QTN_TOK_SGI80, &val_int, NULL) > 0) {
		/* Enable Short guard interval at 80 Mhz. String Enable/Disable */
		ret = qcsapi_wifi_set_option(ifname, qcsapi_short_GI, val_int);

		if (ret < 0) {
			qtn_error("can't set short_gi to %d, error %d", val_int, ret);
			goto respond;
		}
	}

	if (qtn_get_value_enable(&cmd_req, QTN_TOK_TXBF, &val_int, NULL) > 0) {
		/* To enable or disable SU TxBF beamformer capability with explicit feedback.
		 * String: Enable/Disable
		 */
		ret = qcsapi_wifi_set_option(ifname, qcsapi_beamforming, val_int);

		if (ret < 0) {
			qtn_error("can't set SU TxBF cap to %d, error %d", val_int, ret);
			goto respond;
		}
	}

	/* MU_TxBF, (enable/disable) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_MU_TXBF, val_text, sizeof(val_text)) > 0) {
		/* enable/disable Multi User (MU) TxBF beamformee capability
		 * with explicit feedback
		 */
		int su_status = 0;

		val_int = (strcasecmp(val_text, "Enable") == 0) ? 1 : 0;

		if ((qcsapi_wifi_get_option(ifname, qcsapi_beamforming, &su_status) >= 0)
				&& (su_status == 0)
				&& val_int) {
			/* have to have SU enabled if we enable MU */
			ret = qcsapi_wifi_set_option(ifname, qcsapi_beamforming, 1);
			if (ret < 0) {
				qtn_error("can't enable TxBF, error %d", ret);
				ret = 0;
			}
		}

		ret = qcsapi_wfa_cert_feature(ifname, "MU_TxBF", val_text);
		if (ret < 0) {
			qtn_error("cannot set MU_TxBF to %s, error %d", val_text, ret);
			goto respond;
		}
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_STBC_TX, val_text, sizeof(val_text)) > 0) {
		/* STBC Transmit Streams */
		int stbc_tx[2];

		if (sscanf(val_text, "%d;%d", &stbc_tx[0], &stbc_tx[1]) != 2) {
			qtn_error("invalid STBC_TX: %s", val_text);
			ret = -EINVAL;
			goto respond;
		}

		ret = qcsapi_wifi_set_option(ifname, qcsapi_stbc, 1);

		if (ret < 0) {
			qtn_error("can't enable qcsapi_stbc, error %d", ret);
			goto respond;
		}
	}

	if (qtn_get_value_enable(&cmd_req, QTN_TOK_LDPC, &val_int, NULL) > 0) {
		/* Enable the use of LDPC code at the physical layer for both Tx and Rx side.
		 * String: Enable/Disable
		 */
	}

	if (qtn_get_value_enable(&cmd_req, QTN_TOK_ADDBA_REJECT, &val_int, NULL) > 0) {
		/* Reject any ADDBA request by sending ADDBA response with status decline
		 * String: Enable/Disable
		 */
		ret = qcsapi_wifi_set_rxba_decline(ifname, val_int);

		if (ret < 0) {
			qtn_error("can't set rxba_decline to %d, error %d", val_int, ret);
			goto respond;
		}
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_AMPDU, val_text, sizeof(val_text)) > 0) {
		/* AMPDU Aggregation
		 * String: Enable/Disable
		 */
		ret = qcsapi_wfa_cert_feature(ifname, "AMPDU", val_text);
		if (ret < 0) {
			qtn_error("cannot set ampdu to %s, error %d", val_text, ret);
			goto respond;
		}
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_OFFSET, val_text, sizeof(val_text)) > 0) {
		/* Secondary channel offset: Above, Below */
		int offset = strcasecmp(val_text, "Above") == 0 ? 0 : 1;

		qcsapi_unsigned_int current_channel;

		qcsapi_wifi_wait_scan_completes(ifname, QTN_SCAN_TIMEOUT_SEC);

		if ((ret = qcsapi_wifi_get_channel(ifname, &current_channel)) < 0) {
			qtn_error("can't get current channel, error %d", ret);
			goto respond;;
		}

		if ((ret = qcsapi_wifi_set_sec_chan(ifname, current_channel, offset)) < 0) {
			qtn_error("can't set channel %d offset %d, error %d",
				current_channel, offset, ret);
			/* ignore error since UCC can configure secondary channel for 5GHz too. */
			ret = 0;
		}
	}

	/* BW_SGNL, (enable/disable) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_BW_SGNL, val_text, sizeof(val_text)) > 0) {
		ret = qcsapi_wfa_cert_feature(ifname, "BW_SGNL", val_text);
		if (ret < 0) {
			qtn_log("cannot set BW_SGNL to %s, error %d", val_text, ret);
			goto respond;
		}
	}

	/* DYN_BW_SGNL, (enable/disable) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_DYN_BW_SGNL, val_text, sizeof(val_text)) > 0) {
		ret = qcsapi_wfa_cert_feature(ifname, "DYN_BW_SGNL", val_text);
		if (ret < 0) {
			qtn_log("cannot set DYN_BW_SGNL to %s, error %d", val_text, ret);
			goto respond;
		}
	}

	/* RTS_FORCE, (enable/disable) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_RTS_FORCE, val_text, sizeof(val_text)) > 0) {
		ret = qcsapi_wfa_cert_feature(ifname, "RTS_FORCE", val_text);
		if (ret < 0) {
			qtn_log("cannot set RTS_FORCE to %s, error %d", val_text, ret);
			goto respond;
		}
	}

respond:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}

void qtn_handle_ap_set_security(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char val_text[128];
	char ifname_buf[QTN_INTERFACE_LEN];
	int vap_index;
	const char* ifname;
	char keymgnt[QTN_KEYMGNT_LEN];
	qcsapi_SSID ssid;
	qcsapi_pmf pmf;
	int has_pmf = 0;

	ret = qtn_init_cmd_request(&cmd_req, params, len);

	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_WLAN_TAG, &vap_index) > 0)
		vap_index -= 1;
	else
		vap_index = 0;

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname_buf, sizeof(ifname_buf)) <= 0) {
		*ifname_buf = 0;
	}

	ifname = (*ifname_buf) ? ifname_buf : qtn_get_sigma_vap_interface(vap_index);

	qtn_log("set security for %s", ifname);

	if (qtn_get_value_text(&cmd_req, QTN_TOK_PMF, val_text, sizeof(val_text)) > 0) {
		/* Required, Optional, Disabled */
		has_pmf = 1;
		if (strcasecmp(val_text, "Required") == 0)
			pmf = qcsapi_pmf_required;
		else if (strcasecmp(val_text, "Optional") == 0)
			pmf = qcsapi_pmf_optional;
		else if (strcasecmp(val_text, "Disabled") == 0)
			pmf = qcsapi_pmf_disabled;
		else
			has_pmf = 0;
	}

	/* Mandatory KEYMGNT */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_KEYMGNT, keymgnt, sizeof(keymgnt)) <= 0) {
		qtn_error("missing mandatory argument: keymgnt");
		ret = -EINVAL;
		goto exit;
	}

	ret = set_keymgnt(ifname, keymgnt, (has_pmf && (pmf == qcsapi_pmf_required)));

	if (ret < 0) {
		qtn_error("can't set keymgnt to %s, error %d", keymgnt, ret);
		goto exit;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_PSK, val_text, sizeof(val_text)) > 0) {
		if ((ret = qcsapi_wifi_set_key_passphrase(ifname, 0, val_text)) < 0) {
			qtn_error("can't set passphrase to %s, error %d", val_text, ret);
			goto exit;
		}
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_WEPKEY, val_text, sizeof(val_text)) > 0) {
		if ((ret = qcsapi_wifi_set_WEP_key_passphrase(ifname, val_text)) < 0) {
			qtn_error("can't set wepkey to %s, error %d", val_text, ret);
			ret = -EINVAL;
			goto exit;
		}
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_SSID, ssid, sizeof(ssid)) > 0) {
		if ((ret = qcsapi_wifi_set_SSID(ifname, ssid)) < 0) {
			qtn_error("can't set SSID %s, error %d", ssid, ret);
			goto exit;
		}
	}

	if (has_pmf && (ret = qcsapi_wifi_set_pmf(ifname, pmf)) < 0) {
		qtn_error("can't set pmf to %d, error %d", pmf, ret);
		goto exit;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_ENCRYPT, val_text, sizeof(val_text)) > 0) {
		if ((ret = set_ap_encryption(ifname, val_text)) < 0) {
			qtn_error("can't set encryption to %s, error %d", val_text, ret);
			goto exit;
		}
	}

exit:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}

void qtn_handle_ap_reboot(const char *params, int len, struct qtn_response *resp)
{
	/* we need some time to send response before actual reboot */
	/* TODO: system("sync ; reboot -d 2&"); */

	resp->status = STATUS_COMPLETE;
}

static
int qtn_reset_other_ap_options(const char *ifname)
{
	int result = 0;

	if ((result = qcsapi_wifi_set_beacon_type(ifname, "11i")) < 0) {
		qtn_error("can't set beacon_type to, error %d", result);
		return result;
	}

	if ((result = qcsapi_wifi_set_WPA_authentication_mode(ifname, "PSKAuthentication")) < 0) {
		qtn_error("can't set PSK authentication, error %d", result);
		return result;
	}

	if ((result = qcsapi_wifi_set_WPA_encryption_modes(ifname, "AESEncryption")) < 0) {
		qtn_error("can't set AES encryption, error %d", result);
		return result;
	}

	if ((result = qcsapi_wifi_set_option(ifname, qcsapi_autorate_fallback, 1)) < 0) {
		qtn_error("can't set autorate, error %d", result);
		return result;
	}

	for (int timeout = 120; timeout > 0; --timeout) {
		int cacstatus;
		if (qcsapi_wifi_get_cac_status(ifname, &cacstatus) < 0 || cacstatus == 0) {
			break;
		}

		sleep(1);
	}

	return result;
}

void qtn_handle_ap_reset_default(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	qcsapi_wifi_mode current_mode;
	char ifname[IFNAMSIZ];
	char cert_prog[16];
	char conf_type[16];

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	qtn_bring_up_radio_if_needed();

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	if ((ret = qcsapi_wifi_get_mode(ifname, &current_mode)) < 0) {
		qtn_error("can't get mode, error %d", ret);
		goto exit;
	}

	if (current_mode != qcsapi_access_point) {
		qtn_error("mode %d is wrong, should be AP", current_mode);
		ret = -qcsapi_only_on_AP;
		goto exit;
	}

	/* mandatory certification program, e.g. VHT */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_PROGRAM, cert_prog, sizeof(cert_prog)) <= 0
		&& qtn_get_value_text(&cmd_req, QTN_TOK_PROG, cert_prog, sizeof(cert_prog)) <= 0) {
		ret = -EINVAL;
		goto exit;
	}

	/* optional configuration type, e.g. DUT or Testbed */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_TYPE, conf_type, sizeof(conf_type)) <= 0) {
		/* not specified */
		*conf_type = 0;
	}

	/* allow BA */
	qcsapi_wifi_set_rxba_decline(ifname, 0);

	if (strcasecmp(cert_prog, "VHT") == 0) {
		ret = qtn_defconf_vht_dut_ap(ifname);
		if (ret < 0) {
			qtn_error("error: default configuration, errcode %d", ret);
			goto exit;
		}
	} else if (strcasecmp(cert_prog, "PMF") == 0) {
		ret = qtn_defconf_pmf_dut(ifname);
		if (ret < 0) {
			qtn_error("error: default configuration, errcode %d", ret);
			goto exit;
		}
	} else if (strcasecmp(cert_prog, "HS2") == 0 || strcasecmp(cert_prog, "HS2-R2") == 0) {
		ret = qtn_defconf_hs2_dut(ifname);
		if (ret < 0) {
			qtn_error("error: default configuration, errcode %d", ret);
			goto exit;
		}
	} else if (strcasecmp(cert_prog, "11n") == 0) {
		ret = qtn_defconf_11n_dut(ifname);
		if (ret < 0) {
			qtn_error("error: default configuration, errcode %d", ret);
			goto exit;
		}
	} else {
		/* processing for other programs */
		ret = -ENOTSUP;
		goto exit;
	}

	/* Other options */
	ret = qtn_reset_other_ap_options(ifname);
	if (ret < 0) {
		goto exit;
	}

exit:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}

void qtn_handle_ap_set_11n_wireless(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	char ifname[16];
	char val_str[128];
	int val_int;
	int ret;
	int rx_ss = 0;
	int tx_ss = 0;
	int feature_enable;
	int conv_err = 0;

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	*ifname = 0;
	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_MODE, val_str, sizeof(val_str)) > 0 &&
		(ret = qcsapi_wifi_set_phy_mode(ifname, val_str)) < 0) {
		qtn_error("can't set mode to %s, error %d", val_str, ret);
		goto exit;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_WIDTH, val_str, sizeof(val_str)) > 0 &&
		sscanf(val_str, "%d", &val_int) == 1 &&
		(ret = qcsapi_wifi_set_bw(ifname, val_int)) < 0) {
		qtn_error("can't set bandwidth to %d, error %d", val_int, ret);
		goto exit;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_CHANNEL, val_str, sizeof(val_str)) > 0 &&
		sscanf(val_str, "%d", &val_int) == 1 &&
		(ret = qcsapi_wifi_set_channel(ifname, val_int)) < 0) {
		qtn_error("can't set channel to %d, error %d", val_int, ret);
		goto exit;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_SSID, val_str, sizeof(val_str)) > 0 &&
		(ret = qcsapi_wifi_set_SSID(ifname, val_str)) < 0) {
		qtn_error("can't set SSID to %s, error %d", val_str, ret);
		goto exit;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_BCNINT, val_str, sizeof(val_str)) > 0 &&
		sscanf(val_str, "%d", &val_int) == 1 &&
		(ret = qcsapi_wifi_set_beacon_interval(ifname, val_int)) < 0) {
		qtn_error("can't set beacon interval to %d, error %d", val_int, ret);
		goto exit;
	}

	if (qtn_get_value_enable(&cmd_req, QTN_TOK_SGI20, &feature_enable, &conv_err) > 0 &&
		(ret = qcsapi_wifi_set_option(ifname, qcsapi_short_GI, feature_enable)) < 0) {

		qtn_error("error: can't set SGI to %d, error %d", feature_enable, ret);
		goto exit;
	} else if (conv_err < 0) {
		ret = conv_err;
		goto exit;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_SPATIAL_RX_STREAM, val_str, sizeof(val_str)) > 0 &&
		sscanf(val_str, "%dSS", &val_int) == 1) {
		rx_ss = val_int;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_SPATIAL_TX_STREAM, val_str, sizeof(val_str)) > 0 &&
		sscanf(val_str, "%dSS", &val_int) == 1) {
		tx_ss = val_int;
	}

	if (rx_ss > 0 || tx_ss > 0) {
		if (tx_ss != rx_ss) {
			qtn_error("can't set different nss for rx %d and tx %d", rx_ss, tx_ss);
			ret = -EINVAL;
			goto exit;
		}

		if ((ret = qcsapi_wifi_set_nss_cap(ifname, qcsapi_mimo_ht, tx_ss)) < 0) {
			qtn_error("can't set tx nss to %d, error %d", tx_ss, ret);
			goto exit;
		}

		if ((ret = qcsapi_wifi_set_rx_nss_cap(ifname, qcsapi_mimo_ht, rx_ss)) < 0) {
			qtn_error("can't set rx nss to %d, error %d", rx_ss, ret);
			goto exit;
		}
	}

exit:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}

struct qtn_qos_desc {
	enum qtn_token arg_tok;
	int qos_stream_class;
	int qos_param_id;
};

static
const struct qtn_qos_desc qtn_qos_table[] = {
	{QTN_TOK_CWMIN_VO, WME_AC_VO, IEEE80211_WMMPARAMS_CWMIN},
	{QTN_TOK_CWMIN_VI, WME_AC_VI, IEEE80211_WMMPARAMS_CWMIN},
	{QTN_TOK_CWMIN_BE, WME_AC_BE, IEEE80211_WMMPARAMS_CWMIN},
	{QTN_TOK_CWMIN_BK, WME_AC_BK, IEEE80211_WMMPARAMS_CWMIN},
	{QTN_TOK_CWMAX_VO, WME_AC_VO, IEEE80211_WMMPARAMS_CWMAX},
	{QTN_TOK_CWMAX_VI, WME_AC_VI, IEEE80211_WMMPARAMS_CWMAX},
	{QTN_TOK_CWMAX_BE, WME_AC_BE, IEEE80211_WMMPARAMS_CWMAX},
	{QTN_TOK_CWMAX_BK, WME_AC_BK, IEEE80211_WMMPARAMS_CWMAX},
	{QTN_TOK_AIFS_VO,  WME_AC_VO, IEEE80211_WMMPARAMS_AIFS},
	{QTN_TOK_AIFS_VI,  WME_AC_VI, IEEE80211_WMMPARAMS_AIFS},
	{QTN_TOK_AIFS_BE,  WME_AC_BE, IEEE80211_WMMPARAMS_AIFS},
	{QTN_TOK_AIFS_BK,  WME_AC_BK, IEEE80211_WMMPARAMS_AIFS},
	{QTN_TOK_TxOP_VO,  WME_AC_VO, IEEE80211_WMMPARAMS_TXOPLIMIT},
	{QTN_TOK_TxOP_VI,  WME_AC_VI, IEEE80211_WMMPARAMS_TXOPLIMIT},
	{QTN_TOK_TxOP_BE,  WME_AC_BE, IEEE80211_WMMPARAMS_TXOPLIMIT},
	{QTN_TOK_TxOP_BK,  WME_AC_BK, IEEE80211_WMMPARAMS_TXOPLIMIT},
	{QTN_TOK_ACM_VO,   WME_AC_VO, IEEE80211_WMMPARAMS_ACM},
	{QTN_TOK_ACM_VI,   WME_AC_VI, IEEE80211_WMMPARAMS_ACM},
	{QTN_TOK_ACM_BE,   WME_AC_BE, IEEE80211_WMMPARAMS_ACM},
	{QTN_TOK_ACM_BK,   WME_AC_BK, IEEE80211_WMMPARAMS_ACM},
};

static
void qtn_handle_ap_set_qos(int bss, const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	char ifname_buf[16];
	const char *ifname;
	char param_buf[32];
	int param_val;
	int ret;
	int i;

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	*ifname_buf = 0;
	ret = qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname_buf, sizeof(ifname_buf));

	ifname = (ret > 0) ? ifname_buf : qtn_get_sigma_interface();

	if ((ret = qcsapi_wifi_set_option(ifname, qcsapi_wmm, 1)) < 0) {
		goto exit;
	}

	for (i = 0; i < N_ARRAY(qtn_qos_table); i++) {
		const struct qtn_qos_desc *qos_desc = &qtn_qos_table[i];

		*param_buf = 0;
		ret = qtn_get_value_text(&cmd_req, qos_desc->arg_tok,
			param_buf, sizeof(param_buf));

		if (ret > 0) {
			/* workaround. we can't really set ACM for AP. */
			const int ap_bss_flag =
				qos_desc->qos_param_id == IEEE80211_WMMPARAMS_ACM ? 1 : bss;

			if (qos_desc->qos_param_id == IEEE80211_WMMPARAMS_ACM)
				param_val = (strncasecmp(param_buf, "on", 2) == 0) ? 1 : 0;
			else
				param_val = atoi(param_buf);

			if (qos_desc->qos_param_id == IEEE80211_WMMPARAMS_TXOPLIMIT) {
				param_val = IEEE80211_TXOP_TO_US(param_val);
			}

			ret = qcsapi_wifi_qos_set_param(ifname,
				qos_desc->qos_stream_class,
				qos_desc->qos_param_id, ap_bss_flag, param_val);

			if (ret < 0) {
				qtn_error("class %d, param_id %d, value %s, bss %d, error %d",
					qos_desc->qos_stream_class, qos_desc->qos_param_id,
					param_buf, ap_bss_flag, ret);
				goto exit;
			}
		}
	}
	/* it was OK if we reached here */
	ret = 0;
exit:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}

void qtn_handle_ap_set_staqos(const char *params, int len, struct qtn_response *resp)
{
	qtn_handle_ap_set_qos(1, params, len, resp);
}

void qtn_handle_ap_set_apqos(const char *params, int len, struct qtn_response *resp)
{
	qtn_handle_ap_set_qos(0, params, len, resp);
}

void qtn_handle_ap_config_commit(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char ifname[16] = { 0 };

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	qcsapi_wifi_wait_scan_completes(ifname, QTN_SCAN_TIMEOUT_SEC);

	for (int timeout = 120; timeout > 0; --timeout) {
		int cacstatus;
		if (qcsapi_wifi_get_cac_status(ifname, &cacstatus) < 0 || cacstatus == 0) {
			break;
		}

		sleep(1);
	}

	qtn_check_defer_mode_apply_config(ifname);

	resp->status = STATUS_COMPLETE;
}

void qtn_handle_ap_get_mac_address(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char ifname_buf[16];
	const char *ifname;
	unsigned char macaddr[IEEE80211_ADDR_LEN];

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	*ifname_buf = 0;
	ret = qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname_buf, sizeof(ifname_buf));

	ifname = (ret > 0) ? ifname_buf : qtn_get_sigma_interface();

	ret = qcsapi_interface_get_mac_addr(ifname, macaddr);

	if (ret < 0) {
		resp->status = STATUS_ERROR;
		resp->error_code = ret;
		return;
	}

	resp->status = STATUS_COMPLETE;

	snprintf(resp->param_buf, sizeof(resp->param_buf),
		 "mac,%02x:%02x:%02x:%02x:%02x:%02x",
		 macaddr[0], macaddr[1], macaddr[2],
		 macaddr[3], macaddr[4], macaddr[5]);
}

void
qtn_handle_ap_set_rfeature(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	char val_str[256];
	int ret;
	int channel;
	int bandwidth;
	int mcs;
	int num_ss;
	int feature_val;
	char ifname_buf[16];

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	const char *if_name = qtn_get_sigma_interface();

	ret = qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname_buf, sizeof(ifname_buf));
	if_name = (ret > 0) ? ifname_buf : qtn_get_sigma_interface();
	ret = 0;

	if (qtn_get_value_text(&cmd_req, QTN_TOK_CHNUM_BAND, val_str, sizeof(val_str)) > 0 &&
		sscanf(val_str, "%d;%d", &channel, &bandwidth) == 2) {
		qcsapi_unsigned_int current_channel;

		qtn_log("switch to channel %d, bw %d", channel, bandwidth);

		qcsapi_wifi_wait_scan_completes(if_name, QTN_SCAN_TIMEOUT_SEC);
		if (qcsapi_wifi_get_channel(if_name, &current_channel) < 0) {
			qtn_error("can't get current channel");
			current_channel = 0;
		}

		if (channel != current_channel &&
			(ret = safe_channel_switch(if_name, channel)) < 0) {
			qtn_error("can't set channel to %d, error %d", channel, ret);
			goto respond;
		}

		if ((ret = qtn_set_tx_bandwidth(if_name, bandwidth)) < 0) {
			qtn_error("can't set bandwidth to %d, error %d", bandwidth, ret);
			goto respond;
		}
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_NSS_MCS_OPT, val_str, sizeof(val_str)) > 0 &&
		sscanf(val_str, "%d;%d", &num_ss, &mcs) == 2) {

		snprintf(val_str, sizeof(val_str), "MCS%d0%d", num_ss, mcs);
		if ((ret = qcsapi_wifi_set_mcs_rate(if_name, val_str)) < 0) {
			qtn_error("can't set mcs rate to %s, error %d", val_str, ret);
			goto respond;
		}
	}


	if (qtn_get_value_int(&cmd_req, QTN_TOK_TXBANDWIDTH, &feature_val) > 0 &&
		(ret = qtn_set_tx_bandwidth(if_name, feature_val)) < 0) {
		qtn_error("can't set bandwidth to %d, error %d", feature_val, ret);
		goto respond;
	}

respond:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}


void qtn_handle_ap_ca_version(const char *params, int len, struct qtn_response *resp)
{
	resp->status = STATUS_COMPLETE;
	snprintf(resp->param_buf, sizeof(resp->param_buf),
		"version,%s", CA_VERSION);
}

void qtn_handle_ap_set_pmf(const char *params, int len, struct qtn_response *resp)
{
	/* according to CAPI:
	 This command is used to configure the AP PMF setting.
	 If an AP device already handles PMF setting through AP_SET_SECURITY,
	 this command shall be ignored.*/

	resp->status = STATUS_COMPLETE;
}

void qtn_handle_ap_send_addba_req(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char sta_mac[128];
	int tid;
	char ifname[IFNAMSIZ];

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_STA_MAC_ADDRESS, sta_mac, sizeof(sta_mac)) <= 0) {
		qtn_error("no STA MAC in request");
		resp->status = STATUS_ERROR;
		resp->error_code = -EINVAL;
		return;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_TID, &tid) <= 0) {
		qtn_error("no TID in request");
		resp->status = STATUS_ERROR;
		resp->error_code = -EINVAL;
		return;
	}

	snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());

	ret = qcsapi_wfa_cert_send_addba(ifname, tid, sta_mac);

	if (ret < 0) {
		resp->status = STATUS_ERROR;
		resp->error_code = ret;
		qtn_log("can't send addba, tid %d, mac %s, error %d", tid, sta_mac, ret);
		return;
	}

	resp->status = STATUS_COMPLETE;
}
