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

#include "qtn_sta_handler.h"

static void qtn_handle_ca_get_version(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_reset_default(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_disconnect(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_send_addba(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_set_rfeature(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_set_ip_config(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_set_psk(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_associate(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_set_encryption(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_dev_send_frame(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_reassoc(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_set_systime(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_set_radio(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_set_macaddr(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_set_uapsd(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_reset_parm(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_set_11n(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_device_list_interfaces(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_preset_testparameters(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_get_mac_address(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_get_info(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_set_wireless(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_set_power_save(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_sta_set_sleep(const char *params, int len, struct qtn_response *resp);
static void qtn_handle_device_get_info(const char *params, int len, struct qtn_response *resp);


static const struct qtn_cmd_handler qtn_sta_handler_map[] = {
	{"CA_GET_VERSION", qtn_handle_ca_get_version},
	{"STA_RESET_DEFAULT", qtn_handle_sta_reset_default},
	{"DEVICE_LIST_INTERFACES", qtn_handle_device_list_interfaces},
	{"STA_PRESET_TESTPARAMETERS",qtn_handle_sta_preset_testparameters},
	{"STA_DISCONNECT", qtn_handle_sta_disconnect},
	{"STA_SEND_ADDBA", qtn_handle_sta_send_addba},
	{"STA_GET_MAC_ADDRESS", qtn_handle_sta_get_mac_address},
	{"STA_GET_INFO", qtn_handle_sta_get_info},
	{"STA_SET_WIRELESS", qtn_handle_sta_set_wireless},
	{"STA_SET_RFEATURE", qtn_handle_sta_set_rfeature},
	{"STA_SET_IP_CONFIG", qtn_handle_sta_set_ip_config},
	{"STA_SET_PSK", qtn_handle_sta_set_psk},
	{"STA_ASSOCIATE", qtn_handle_sta_associate},
	{"STA_SET_ENCRYPTION", qtn_handle_sta_set_encryption},
	{"DEV_SEND_FRAME", qtn_handle_dev_send_frame},
	{"STA_REASSOC", qtn_handle_sta_reassoc},
	{"STA_SET_SYSTIME", qtn_handle_sta_set_systime},
	{"STA_SET_RADIO", qtn_handle_sta_set_radio},
	{"STA_SET_MACADDR", qtn_handle_sta_set_macaddr},
	{"STA_SET_UAPSD", qtn_handle_sta_set_uapsd},
	{"STA_RESET_PARM", qtn_handle_sta_reset_parm},
	{"STA_SET_11N", qtn_handle_sta_set_11n},
	{"SET_POWER_SAVE", qtn_handle_sta_set_power_save},
	{"STA_SET_SLEEP", qtn_handle_sta_set_sleep},
	{"DEVICE_GET_INFO", qtn_handle_device_get_info},
};

#define N_ARRAY(arr)			(sizeof(arr)/sizeof(arr[0]))

const struct qtn_cmd_handler * qtn_lookup_sta_handler(const char *cmd, int len)
{
	return qtn_lookup_cmd_handler(cmd, len, qtn_sta_handler_map,
			N_ARRAY(qtn_sta_handler_map));
}

void qtn_handle_ca_get_version(const char *params, int len, struct qtn_response *resp)
{
	resp->status = STATUS_COMPLETE;
	snprintf(resp->param_buf, sizeof(resp->param_buf),
		"version,%s", CA_VERSION);
}

static
int set_sta_encryption(const char *ifname, const char* ssid, const char *enc)
{
	int i;

	static const struct {
		const char *sigma_enc;
		const char *encryption;
	} map[] = {
		{
		.sigma_enc = "tkip",.encryption = "TKIPEncryption"}, {
		.sigma_enc = "aes-ccmp",.encryption = "AESEncryption"}, {
		.sigma_enc = "aes-ccmp-tkip",.encryption = "TKIPandAESEncryption"}, {
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

	return qcsapi_SSID_set_encryption_modes(ifname, ssid, map[i].encryption);
}

void qtn_handle_device_list_interfaces(const char *params, int len, struct qtn_response *resp)
{
	resp->status = STATUS_COMPLETE;
	snprintf(resp->param_buf, sizeof(resp->param_buf),
			"interfaceType,802.11,interfaceID,%s", qtn_get_sigma_interface());
}

void qtn_handle_sta_reset_default(const char *params, int len, struct qtn_response *resp)
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

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	qtn_bring_up_radio_if_needed();

	if ((ret = qcsapi_wifi_get_mode(ifname, &current_mode)) < 0) {
		qtn_error("can't get mode, error %d", ret);
		goto respond;
	}

	if (current_mode != qcsapi_station) {
		qtn_error("mode %d is wrong, should be STA", current_mode);
		ret = -qcsapi_only_on_STA;
		goto respond;
	}

	/* disassociate to be sure that we start disassociated. possible error is ignored. */
	qcsapi_wifi_disassociate(ifname);

	/* mandatory certification program, e.g. VHT */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_PROG, cert_prog, sizeof(cert_prog)) <= 0) {
		ret = -EINVAL;
		goto respond;
	}

	/* optional configuration type, e.g. DUT or Testbed */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_TYPE, conf_type, sizeof(conf_type)) <= 0) {
		/* not specified */
		*conf_type = 0;
	}

	/* Certification program shall be: PMF, WFD, P2P or VHT */
	if (strcasecmp(cert_prog, "VHT") == 0) {
		ret = qtn_defconf_vht_dut_sta(ifname);
		if (ret < 0) {
			qtn_error("error: default configuration, errcode %d", ret);
			goto respond;
		}
	} else if (strcasecmp(cert_prog, "11n") == 0) {
		ret = qtn_defconf_11n_dut(ifname);
		if (ret < 0) {
			qtn_error("error: default configuration, errcode %d", ret);
			goto respond;
		}
	} else if (strcasecmp(cert_prog, "PMF") == 0) {
		ret = qtn_defconf_pmf_dut(ifname);
		if (ret < 0) {
			qtn_error("error: default configuration, errcode %d", ret);
			goto respond;
		}
	} else if (strcasecmp(cert_prog, "TDLS") == 0) {
		ret = qtn_defconf_tdls_dut(ifname);
		if (ret < 0) {
			qtn_error("error: default configuration, errcode %d", ret);
			goto respond;
		}
	} else {
		/* processing for other programs */
		qtn_error("error: prog %s is not supported", cert_prog);
		ret = -ENOTSUP;
		goto respond;
	}

	/* Other options */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_autorate_fallback, 1);
	if (ret < 0) {
		qtn_error("error: cannot set autorate, errcode %d", ret);
		goto respond;
	}

respond:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}

void qtn_handle_sta_disconnect(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char ifname[IFNAMSIZ];

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	if ((ret = qcsapi_wifi_disassociate(ifname)) < 0) {
		qtn_error("can't disassociate interface %s, error %d", ifname, ret);
		resp->status = STATUS_ERROR;
		resp->error_code = ret;
		return;
	}

	resp->status = STATUS_COMPLETE;
}

void qtn_handle_sta_send_addba(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char ifname[IFNAMSIZ];
	int tid;

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_TID, &tid) <= 0) {
		qtn_error("no TID in request");
		resp->status = STATUS_ERROR;
		resp->error_code = -EINVAL;
		return;
	}

	ret = qcsapi_wfa_cert_send_addba(ifname, tid, "NULL");

	if (ret != 0) {
		resp->status = STATUS_ERROR;
		resp->error_code = ret;
		qtn_log("can't send addba, error %d", ret);
		return;
	}

	resp->status = STATUS_COMPLETE;
}

void qtn_handle_sta_preset_testparameters(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	char ifname[IFNAMSIZ];
	char val_buf[32];
	int val_int;
	int ret;

	ret = qtn_init_cmd_request(&cmd_req, params, len);

	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_MODE, val_buf, sizeof(val_buf)) > 0) {
		const char *phy_mode = val_buf;
		qcsapi_unsigned_int old_bw;
		if (qcsapi_wifi_get_bw(ifname, &old_bw) < 0) {
			old_bw = 80;
		}

		if ((ret = qcsapi_wifi_set_phy_mode(ifname, phy_mode)) < 0) {
			goto respond;
		}

		qtn_log("try to restore %d mode since phy change", old_bw);
		ret = qcsapi_wifi_set_bw(ifname, old_bw);

		if (ret < 0) {
			qtn_error("failed to restore old width, error %d", ret);
			ret = 0;
		}
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_WMM, val_buf, sizeof(val_buf)) > 0) {
		if ((ret = qcsapi_wfa_cert_feature(ifname, "WMM", val_buf)) < 0) {
			qtn_error("can't set wmm to %s, error %d", val_buf, ret);
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

	/* TODO: FRGMNT
	 *   sta_preset_testparameters,interface,eth0,supplicant,ZeroConfig,mode,11ac,FRGMNT,2346
	 */

respond:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}

void qtn_handle_sta_get_mac_address(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char ifname[IFNAMSIZ];
	unsigned char macaddr[IEEE80211_ADDR_LEN];

	ret = qtn_init_cmd_request(&cmd_req, params, len);

	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	if ((ret = qcsapi_interface_get_mac_addr(ifname, macaddr)) < 0) {
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

void qtn_handle_sta_get_info(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char ifname[IFNAMSIZ];
	char firmware_version[QTN_VERSION_LEN];

	ret = qtn_init_cmd_request(&cmd_req, params, len);

	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	if (qcsapi_firmware_get_version(firmware_version, sizeof(firmware_version)) < 0) {
		snprintf(firmware_version, sizeof(firmware_version), "unknown");
	}

	/* TODO: add other information */
	snprintf(resp->param_buf, sizeof(resp->param_buf),
			"vendor,%s,build_name,%s",
			"Quantenna", firmware_version);

	resp->status = STATUS_COMPLETE;
}

void qtn_handle_sta_set_wireless(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char ifname[IFNAMSIZ];
	char cert_prog[32];
	int vht_prog;
	int feature_enable;
	int feature_val;
	char val_buf[128];
	int conv_err = 0;

	ret = qtn_init_cmd_request(&cmd_req, params, len);

	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_PROGRAM, cert_prog, sizeof(cert_prog)) <= 0) {
		/* mandatory parameter */
		ret = -EINVAL;
		goto respond;
	}

	vht_prog = (strcasecmp(cert_prog, "VHT") == 0) ? 1 : 0;

	/*  ADDBA_REJECT, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_ADDBA_REJECT, &feature_enable, &conv_err) > 0) {
		/* it is not necessary for DUT sta_set_wireless */
		ret = -ENOTSUP;
		qtn_error("ADDBA_REJECT not supported");
		goto respond;

	} else if (conv_err < 0) {
		ret = conv_err;
		goto respond;
	}

	/* AMPDU, (enable/disable) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_AMPDU, val_buf, sizeof(val_buf)) > 0) {
		ret = qcsapi_wfa_cert_feature(ifname, "AMPDU", val_buf);
		if (ret < 0) {
			qtn_error("cannot set ampdu to %s, error %d", val_buf, ret);
			goto respond;
		}
	}

	/* AMSDU, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_AMSDU, &feature_enable, &conv_err) > 0) {
		ret = qcsapi_wifi_set_tx_amsdu(ifname, feature_enable);

		if (ret < 0) {
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		goto respond;
	}

	/* STBC_RX, int (0/1) */
	if (qtn_get_value_int(&cmd_req, QTN_TOK_STBC_RX, &feature_val) > 0) {
		/* enable/disable STBC */
		ret = qcsapi_wifi_set_option(ifname, qcsapi_stbc, feature_val);

		if (ret < 0) {
			goto respond;
		}
	}

	/* WIDTH, int (80/40/20) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_WIDTH, val_buf, sizeof(val_buf)) > 0) {
		/* channel width */
		int bw_cap = atoi(val_buf);

		ret = qcsapi_wifi_set_bw(ifname, (unsigned) bw_cap);
		if (ret < 0) {
			qtn_log("can't set width to %d, error %d", bw_cap, ret);
			goto respond;
		}

		ret = qcsapi_wfa_cert_feature(ifname, "FIXED_BW", val_buf);
		if (ret < 0) {
			qtn_log("cannot set ampdu to %s, error %d", val_buf, ret);
			goto respond;
		}
	}

	/* SMPS, SM Power Save Mode, NOT Supported */
	if (qtn_get_value_int(&cmd_req, QTN_TOK_SMPS, &feature_val) > 0) {
		ret = -EOPNOTSUPP;
		goto respond;
	}

	/* TXSP_STREAM, (1SS/2SS/3SS) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_TXSP_STREAM, val_buf, sizeof(val_buf)) > 0) {
		int nss = 0;
		qcsapi_mimo_type mt = vht_prog ? qcsapi_mimo_vht : qcsapi_mimo_ht;

		if (sscanf(val_buf, "%dSS", &nss) != 1) {
			ret = -EINVAL;
			goto respond;
		}

		ret = qcsapi_wifi_set_nss_cap(ifname, mt, nss);

		if (ret < 0) {
			goto respond;
		}
	}

	/* RXSP_STREAM, (1SS/2SS/3SS) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_RXSP_STREAM, val_buf, sizeof(val_buf)) > 0) {
		int nss = 0;
		qcsapi_mimo_type mt = vht_prog ? qcsapi_mimo_vht : qcsapi_mimo_ht;

		if (sscanf(val_buf, "%dSS", &nss) != 1) {
			ret = -EINVAL;
			goto respond;
		}

		ret = qcsapi_wifi_set_rx_nss_cap(ifname, mt, nss);

		if (ret < 0) {
			goto respond;
		}
	}

	/* Band, NOT Supported */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_BAND, val_buf, sizeof(val_buf)) > 0) {
		ret = -EOPNOTSUPP;
		goto respond;
	}

	/* BW_SGNL, (enable/disable) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_BW_SGNL, val_buf, sizeof(val_buf)) > 0) {
		ret = qcsapi_wfa_cert_feature(ifname, "BW_SGNL", val_buf);
		if (ret < 0) {
			qtn_log("cannot set BW_SGNL to %s, error %d", val_buf, ret);
			goto respond;
		}
	}

	/* DYN_BW_SGNL, (enable/disable) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_DYN_BW_SGNL, val_buf, sizeof(val_buf)) > 0) {
		ret = qcsapi_wfa_cert_feature(ifname, "DYN_BW_SGNL", val_buf);
		if (ret < 0) {
			qtn_log("cannot set DYN_BW_SGNL to %s, error %d", val_buf, ret);
			goto respond;
		}
	}

	/* RTS_FORCE, (enable/disable) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_RTS_FORCE, val_buf, sizeof(val_buf)) > 0) {
		ret = qcsapi_wfa_cert_feature(ifname, "RTS_FORCE", val_buf);
		if (ret < 0) {
			qtn_log("cannot set RTS_FORCE to %s, error %d", val_buf, ret);
			goto respond;
		}
	}

	/* SGI80, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_SGI80, &feature_enable, &conv_err) > 0) {
		/* disable dynamic GI selection */
		ret = qcsapi_wifi_set_option(ifname, qcsapi_GI_probing, 0);
		if (ret < 0) {
			qtn_error("can't disable dynamic GI selection, error %d", ret);
			ret = 0;
			/* ^^ ignore error since qcsapi_GI_probing does not work for RFIC6 */
		}

		/* it sets general capability for short GI, not only SGI80 */
		ret = qcsapi_wifi_set_option(ifname, qcsapi_short_GI, feature_enable);

		if (ret < 0) {
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		goto respond;
	}

	/* TxBF, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_TXBF, &feature_enable, &conv_err) > 0) {
		/* enable/disable SU TxBF beamformee capability */
		ret = qcsapi_wifi_set_option(ifname, qcsapi_beamforming, feature_enable);

		if (ret < 0) {
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		goto respond;
	}

	/* MU_TxBF, (enable/disable) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_MU_TXBF, val_buf, sizeof(val_buf)) > 0) {
		/* enable/disable Multi User (MU) TxBF beamformee capability
		 * with explicit feedback
		 */
		int su_status = 0;

		feature_enable = (strcasecmp(val_buf, "Enable") == 0) ? 1 : 0;

		if ((qcsapi_wifi_get_option(ifname, qcsapi_beamforming, &su_status) >= 0)
				&& (su_status == 0)
				&& feature_enable) {
			/* have to have SU enabled if we enable MU */
			ret = qcsapi_wifi_set_option(ifname, qcsapi_beamforming, 1);
			if (ret < 0) {
				qtn_error("can't enable beamforming, error %d", ret);
				ret = 0;
			}
		}

		ret = qcsapi_wfa_cert_feature(ifname, "MU_TxBF", val_buf);
		if (ret < 0) {
			qtn_log("cannot set MU_TxBF to %s, error %d", val_buf, ret);
			goto respond;
		}
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_TXBANDWIDTH, &feature_val) > 0 &&
		(ret = qtn_set_tx_bandwidth(ifname, feature_val)) < 0) {
		qtn_error("can't set bandwidth to %d, error %d", feature_val, ret);
		goto respond;
	}

respond:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}

void qtn_handle_sta_set_rfeature(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char ifname[IFNAMSIZ];
	char val_str[128];
	int feature_val;
	int conv_err;
	int num_ss;
	int mcs;
	int need_tdls_channel_switch = 0;

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_NSS_MCS_OPT, val_str, sizeof(val_str)) > 0 &&
		sscanf(val_str, "%d;%d", &num_ss, &mcs) == 2) {

		snprintf(val_str, sizeof(val_str), "MCS%d0%d", num_ss, mcs);
		if ((ret = qcsapi_wifi_set_mcs_rate(ifname, val_str)) < 0) {
			qtn_error("can't set mcs rate to %s, error %d", val_str, ret);
			goto respond;
		}
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_CHSWITCHMODE, val_str, sizeof(val_str)) > 0) {

		int mode = 0;
		if (strcasecmp(val_str, "Initiate") == 0) {
			mode = 0;
			need_tdls_channel_switch = 1;
		} else if (strcasecmp(val_str, "Passive") == 0) {
			char peer[128];
			mode = 2;

			if (qtn_get_value_text(&cmd_req, QTN_TOK_PEER, peer, sizeof(peer)) > 0) {
				qcsapi_wifi_set_tdls_params(ifname,
					qcsapi_tdls_chan_switch_off_chan, 0);
				qcsapi_wifi_set_tdls_params(ifname,
					qcsapi_tdls_chan_switch_off_chan_bw, 0);
				qcsapi_wifi_tdls_operate(ifname,
					qcsapi_tdls_oper_switch_chan, peer, 0);
			}
		}

		ret = qcsapi_wifi_set_tdls_params(ifname, qcsapi_tdls_chan_switch_mode, mode);
		if (ret < 0) {
			qtn_error("can't tdls_chan_switch_mode to %s, error %d", val_str, ret);
			goto respond;
		}
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_OFFCHNUM, &feature_val) > 0) {
		ret = qcsapi_wifi_set_tdls_params(ifname, qcsapi_tdls_chan_switch_off_chan,
				feature_val);
		if (ret < 0) {
			qtn_error("can't off_chan to %d, error %d", feature_val, ret);
			goto respond;
		}
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_SECCHOFFSET, val_str, sizeof(val_str)) > 0) {
		int off_chan_bw = -1;
		qcsapi_unsigned_int current_bw = 0;
		if (strcasecmp(val_str, "40above") == 0 || strcasecmp(val_str, "40below") == 0) {
			off_chan_bw = 40;
		} else if (strcasecmp(val_str, "20") == 0) {
			off_chan_bw = 20;
		}

		ret = qcsapi_wifi_get_bw(ifname, &current_bw);
		if (ret < 0) {
			qtn_error("unable to get bw capability, error %d", ret);
			ret = 0;
			current_bw = 0;
		}

		if (current_bw < off_chan_bw) {
			ret = qcsapi_wifi_set_bw(ifname, off_chan_bw);
			if (ret < 0) {
				qtn_log("can't set width to %d, error %d", off_chan_bw, ret);
				ret = 0;
			}
		}

		ret = qcsapi_wifi_set_tdls_params(ifname, qcsapi_tdls_chan_switch_off_chan_bw,
							off_chan_bw);
		if (ret < 0) {
			qtn_error("can't tdls_chan_switch_off_chan_bw to %d, error %d",
				off_chan_bw, ret);
			goto respond;
		}
	}

	if (need_tdls_channel_switch &&
		qtn_get_value_text(&cmd_req, QTN_TOK_PEER, val_str, sizeof(val_str)) > 0) {
		ret = qcsapi_wifi_tdls_operate(ifname, qcsapi_tdls_oper_switch_chan, val_str, 1000);
		if (ret < 0) {
			qtn_error("can't run switch_chan, error %d", ret);
			goto respond;
		}
	}

	if (qtn_get_value_enable(&cmd_req, QTN_TOK_UAPSD, &feature_val, &conv_err) > 0) {
		ret = qcsapi_wifi_set_option(ifname, qcsapi_uapsd, feature_val);
		if (ret < 0) {
			qtn_error("can't set uapsd to %d, error %d", feature_val, ret);
			goto respond;
		}
	} else if (conv_err < 0) {
		ret = conv_err;
		goto respond;
	}

respond:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}

void qtn_handle_sta_set_ip_config(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	/* Put your implementation below */

	resp->status = STATUS_COMPLETE;
}

void qtn_handle_sta_set_psk(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char ifname[IFNAMSIZ];
	char ssid_str[128];
	char pass_str[128];
	char key_type[128];
	char enc_type[128];
	char pmf_type[128];

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_SSID, ssid_str, sizeof(ssid_str)) <= 0) {
		ret = -EINVAL;
		qtn_error("can't get ssid");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_PASSPHRASE, pass_str, sizeof(pass_str)) <= 0) {
		ret = -EINVAL;
		qtn_error("can't get pass phrase");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_KEYMGMTTYPE, key_type, sizeof(key_type)) <= 0) {
		ret = -EINVAL;
		qtn_error("can't get pass key_type");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_ENCPTYPE, enc_type, sizeof(enc_type)) <= 0) {
		ret = -EINVAL;
		qtn_error("can't get enc_type");
		goto respond;
	}

	if (qcsapi_SSID_verify_SSID(ifname, ssid_str) < 0 &&
			(ret = qcsapi_SSID_create_SSID(ifname, ssid_str)) < 0) {
		qtn_error("can't create SSID %s, error %d", ssid_str, ret);
		goto respond;
	}

	if ((ret = set_sta_encryption(ifname, ssid_str, enc_type)) < 0) {
		qtn_error("can't set enc to %s, error %d", enc_type, ret);
		goto respond;
	}

	if ((ret = qcsapi_SSID_set_authentication_mode(ifname, ssid_str, "PSKAuthentication")) < 0) {
		qtn_error("can't set PSK authentication, error %d", ret);
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_PMF, pmf_type, sizeof(pmf_type)) > 0) {
		int pmf_cap = -1;
		/* pmf_cap values according to wpa_supplicant manual:
			0 = disabled (default unless changed with the global pmf parameter)
			1 = optional
			2 = required
		*/

		if (strcasecmp(pmf_type, "Required") == 0
			|| strcasecmp(pmf_type, "Forced_Required") == 0) {
			pmf_cap = 2;
		} else if (strcasecmp(pmf_type, "Optional") == 0) {
			pmf_cap = 1;
		} else if (strcasecmp(pmf_type, "Disable") == 0
			|| strcasecmp(pmf_type, "Forced_Disabled") == 0) {
			pmf_cap = 0;
		}

		if (pmf_cap != -1 && (ret = qcsapi_SSID_set_pmf(ifname, ssid_str, pmf_cap)) < 0) {
			qtn_error("can't set pmf to %d, error %d, ssid %s", pmf_cap, ret, ssid_str);
			goto respond;
		}

		if (pmf_cap > 0 && (ret = qcsapi_SSID_set_authentication_mode(
			ifname, ssid_str, "SHA256PSKAuthenticationMixed")) < 0) {
			qtn_error("can't set authentication for PMF, error %d, ssid %s",
					ret, ssid_str);
			goto respond;
		}
	}

	if ((ret = qcsapi_SSID_set_key_passphrase(ifname, ssid_str, 0, pass_str)) < 0) {
		qtn_error("can't set pass: ifname %s, ssid %s, key_type %s, pass %s, error %d",
			ifname, ssid_str, key_type, pass_str, ret);
	}

respond:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}

void qtn_handle_sta_associate(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char ifname[IFNAMSIZ];
	char ssid_str[128];

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_SSID, ssid_str, sizeof(ssid_str)) <= 0) {
		ret = -EINVAL;
		qtn_error("can't get ssid");
		goto respond;
	}

	/* take into account deferred security configuration */
	qtn_check_defer_mode_apply_config(ifname);

	if ((ret = qcsapi_wifi_associate(ifname, ssid_str)) < 0) {
		qtn_error("can't associate, ifname %s, ssid %s, error %d", ifname, ssid_str, ret);
		goto respond;
	}

respond:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}

void qtn_handle_sta_set_encryption(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret = 0;
	char ifname[IFNAMSIZ];
	char ssid_str[128];
	char encryption[128];

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_SSID, ssid_str, sizeof(ssid_str)) <= 0) {
		ret = -EINVAL;
		qtn_error("can't get ssid");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_ENCPTYPE, encryption, sizeof(encryption)) <= 0) {
		ret = -EINVAL;
		qtn_error("can't get encryption");
		goto respond;
	}

	if (strcasecmp(encryption, "wep") == 0) {
		ret = -ENOTSUP;
		qtn_log("wep is not supported");
		goto respond;
	}

	if (qcsapi_SSID_verify_SSID(ifname, ssid_str) < 0 &&
			(ret = qcsapi_SSID_create_SSID(ifname, ssid_str)) < 0) {
		qtn_error("can't create SSID %s, error %d", ssid_str, ret);
		goto respond;
	}

	if (strcasecmp(encryption, "none") == 0 &&
			(ret = qcsapi_SSID_set_authentication_mode(ifname, ssid_str, "NONE")) < 0) {
		qtn_log("can't set authentication to %s, ssid %s error %d",
				encryption, ssid_str, ret);
	}

respond:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}

void qtn_handle_dev_send_frame(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char ifname[IFNAMSIZ];
	char program[16];
	char val_text[128];
	char peer[128];

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	ret = qtn_get_value_text(&cmd_req, QTN_TOK_PROGRAM, program, sizeof(program));
	if (ret <= 0) {
		/* mandatory parameter */
		ret = -EINVAL;
		qtn_error("can't get program");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_TYPE, val_text, sizeof(val_text)) > 0 &&
		qtn_get_value_text(&cmd_req, QTN_TOK_PEER, peer, sizeof(peer)) > 0) {

		qcsapi_tdls_oper oper = qcsapi_tdls_nosuch_oper;

		if (strcasecmp(val_text, "Setup") == 0) {
			oper = qcsapi_tdls_oper_setup;
		} else if (strcasecmp(val_text, "channelSwitchReq") == 0) {
			oper = qcsapi_tdls_oper_switch_chan;
		} else if (strcasecmp(val_text, "discovery") == 0) {
			oper = qcsapi_tdls_oper_discover;
		}  else if (strcasecmp(val_text, "teardown") == 0) {
			oper = qcsapi_tdls_oper_teardown;
		}

		if (oper != qcsapi_tdls_nosuch_oper &&
				(ret = qcsapi_wifi_tdls_operate(ifname, oper, peer, 1000)) < 0) {
			qtn_error("can't set tdls_operate to %s, error %d", val_text, ret);
			goto respond;
		}
	}

respond:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}

void qtn_handle_sta_reassoc(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret = 0;
	char ifname[IFNAMSIZ];
	char bssid[64];

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_BSSID, bssid, sizeof(bssid)) <= 0) {
		ret = -EINVAL;
		qtn_error("can't get bssid");
		goto respond;
	}

	if ((ret = qcsapi_wifi_reassociate(ifname)) < 0) {
		qtn_error("can't reassociate, error %d", ret);
		goto respond;
	}

respond:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}

void qtn_handle_sta_set_systime(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char cmd[128];
	int month;
	int date;
	int year;
	int hours;
	int minutes;
	int seconds;

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_YEAR, &year) <= 0) {
		ret = -EINVAL;
		qtn_error("can't get year");
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_MONTH, &month) <= 0) {
		ret = -EINVAL;
		qtn_error("can't get month");
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_DATE, &date) <= 0) {
		ret = -EINVAL;
		qtn_error("can't get date");
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_HOURS, &hours) <= 0) {
		ret = -EINVAL;
		qtn_error("can't get hours");
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_MINUTES, &minutes) <= 0) {
		ret = -EINVAL;
		qtn_error("can't get minutes");
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_SECONDS, &seconds) <= 0) {
		ret = -EINVAL;
		qtn_error("can't get seconds");
		goto respond;
	}

	/* TODO: check */
	snprintf(cmd, sizeof(cmd), "date -s %2.2d%2.2d%2.2d%2.2d%4.4d.%2.2d",
		month, date, hours, minutes, year, seconds);
	ret = system(cmd);
	if (ret != 0) {
		qtn_error("can't set time. error %d, cmd %s", ret, cmd);
	}

respond:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}

void qtn_handle_sta_set_radio(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char mode[64];

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_MODE, mode, sizeof(mode)) <= 0) {
		resp->status = STATUS_ERROR;
		resp->error_code = -EINVAL;
		qtn_error("can't get mode");
		return;
	}

	if ((ret = qtn_set_rf_enable(strcasecmp(mode, "On") == 0 ? 1 : 0)) < 0) {
		resp->status = STATUS_ERROR;
		resp->error_code = ret;
		qtn_error("can't set rf to %s, error %d", mode, ret);
		return;
	}

	resp->status = STATUS_COMPLETE;
}

void qtn_handle_sta_set_macaddr(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char ifname[IFNAMSIZ];
	char mac_str[64];
	qcsapi_mac_addr mac;

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		ret = -EINVAL;
		qtn_error("can't get ifname");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_MAC, mac_str, sizeof(mac_str)) <= 0) {
		ret = -EINVAL;
		qtn_error("can't get mac");
		goto respond;
	}

	if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
		ret = -EINVAL;
		qtn_error("can't parse mac_str %s", mac_str);
		goto respond;
	}

	qtn_log("try to set mac on %s to %s", ifname, mac_str);

	if ((ret = qcsapi_interface_set_mac_addr(ifname, mac)) < 0) {
		qtn_error("can't set mac to %s, error %d", mac_str, ret);
	}

respond:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}

void qtn_handle_sta_set_uapsd(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char ifname[IFNAMSIZ];
	int maxsplength;
	int acbe;
	int acbk;
	int acvi;
	int acvo;
	char val_buf[64];

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		qtn_error("can't get ifname");
		resp->status = STATUS_ERROR;
		resp->error_code = -EINVAL;
		return;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_MAXSPLENGTH, &maxsplength) <= 0)
		maxsplength = 4;

	if (qtn_get_value_int(&cmd_req, QTN_TOK_ACBE, &acbe) <= 0)
		acbe = 1;

	if (qtn_get_value_int(&cmd_req, QTN_TOK_ACBK, &acbk) <= 0)
		acbk = 1;

	if (qtn_get_value_int(&cmd_req, QTN_TOK_ACVI, &acvi) <= 0)
		acvi = 1;

	if (qtn_get_value_int(&cmd_req, QTN_TOK_ACVO, &acvo) <= 0)
		acvo = 1;

	snprintf(val_buf, sizeof(val_buf), "%d,%d,%d,%d,%d",
			maxsplength, acbe, acbk, acvi, acvo);

	ret = qcsapi_wfa_cert_feature(ifname, "UAPSD", val_buf);

	if (ret < 0) {
		qtn_error("can't set uapsd into: %s, error: %d", val_buf, ret);
		resp->status = STATUS_ERROR;
		resp->error_code = ret;
		return;
	}

	resp->status = STATUS_COMPLETE;
}

void qtn_handle_sta_reset_parm(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char ifname[IFNAMSIZ];
	char arp[64];
	char cmd[128];

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		ret = -EINVAL;
		qtn_error("can't get ifname");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_ARP, arp, sizeof(arp)) <= 0) {
		ret = -EINVAL;
		qtn_error("can't get arp");
		goto respond;
	}

	/* TODO: check */
	if (strcasecmp(arp, "all") == 0) {
		snprintf(cmd, sizeof(cmd), "for ip in `grep %s /proc/net/arp | awk '{print $1}'`; "
				"do arp -i %s -d $ip; done", ifname, ifname);
	} else {
		snprintf(cmd, sizeof(cmd), "arp -i %s -d %s", ifname, arp);
	}

	ret = system(cmd);

respond:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}

void qtn_handle_sta_set_11n(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char ifname[IFNAMSIZ];
	char val_str[128];
	int tx_ss = 0;
	int rx_ss = 0;

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		ret = -EINVAL;
		qtn_error("can't get ifname");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_WIDTH, val_str, sizeof(val_str)) > 0) {
		qcsapi_unsigned_int bw;
		if (strcasecmp(val_str, "auto") == 0) {
			bw = 40;
		} else {
			sscanf(val_str, "%u", &bw);
		}

		if ((ret = qcsapi_wifi_set_bw(ifname, bw)) < 0) {
			qtn_error("can't set bw to %d, error %d", bw, ret);
			goto respond;
		}
	}

	/* TXSP_STREAM, (1SS/2SS/3SS) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_TXSP_STREAM, val_str, sizeof(val_str)) > 0) {
		if (sscanf(val_str, "%dSS", &tx_ss) != 1) {
			ret = -EINVAL;
			qtn_error("can't get tx_ss from %s", val_str);
			goto respond;
		}
	}

	/* RXSP_STREAM, (1SS/2SS/3SS) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_RXSP_STREAM, val_str, sizeof(val_str)) > 0) {
		if (sscanf(val_str, "%dSS", &rx_ss) != 1) {
			ret = -EINVAL;
			qtn_error("can't get rx_ss from %s", val_str);
			goto respond;
		}
	}

	if (tx_ss > 0 || rx_ss > 0) {
		if (tx_ss != rx_ss) {
			ret = -EINVAL;
			qtn_error("can't handle number of SS separatly for RX and TX");
			goto respond;
		}

		/* sta_set_11n is used only for 11n, so hardcode qcsapi_mimo_ht */
		ret = qcsapi_wifi_set_nss_cap(ifname, qcsapi_mimo_ht, tx_ss);
		if (ret < 0) {
			qtn_error("can't set tx NSS to %d, error %d", tx_ss, ret);
			goto respond;
		}
		ret = qcsapi_wifi_set_rx_nss_cap(ifname, qcsapi_mimo_ht, rx_ss);
		if (ret < 0) {
			qtn_error("can't set rx NSS to %d, error %d", rx_ss, ret);
			goto respond;
		}
	}

respond:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}

void qtn_handle_sta_set_power_save(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char ifname[IFNAMSIZ];
	char val_str[128];

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		ret = -EINVAL;
		qtn_error("can't get ifname");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_POWERSAVE, val_str, sizeof(val_str)) > 0) {
		if (strcasecmp(val_str, "off") == 0) {
			// power save does not exist by default
			ret = 0;
		} else {
			ret = -EOPNOTSUPP;
			qtn_error("can't set power save to %s since poser save is not supported",
				val_str);
			goto respond;
		}
	}

respond:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}

void qtn_handle_sta_set_sleep(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char ifname[IFNAMSIZ];

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	ret = qcsapi_wfa_cert_feature(ifname, "SLEEP", "NULL");

	if (ret < 0) {
		qtn_error("can't set sleep, error: %d", ret);
		resp->status = STATUS_ERROR;
		resp->error_code = ret;
		return;
	}

	resp->status = STATUS_COMPLETE;
}

void qtn_handle_device_get_info(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char firmware_version[128] = {0};
	string_64 hw_version;
	static const char vendor[] = "Quantenna";

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	ret = qcsapi_firmware_get_version(firmware_version, sizeof(firmware_version));
	if (ret < 0) {
		qtn_error("can't get fw version, error %d", ret);
		goto respond;
	}

	ret = qcsapi_get_board_parameter(qcsapi_hw_id, hw_version);
	if (ret < 0) {
		qtn_error("can't get HW id, error %d", ret);
		goto respond;
	}

	snprintf(resp->param_buf, sizeof(resp->param_buf),
			"vendor,%s,model,%s,version,%s",
			vendor, hw_version, firmware_version);

	ret = 0;

respond:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}
