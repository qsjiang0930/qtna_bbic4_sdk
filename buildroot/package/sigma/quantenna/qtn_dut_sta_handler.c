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
#include <netinet/ether.h>

extern struct qtn_npu_config qtn_dut_npu_cfg;

static int set_sta_encryption(const char *ifname, const char* ssid, const char *enc)
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

static int set_sta_keymgmt(const char *ifname, const char *ssid, const char *type)
{
	int i;
	static const struct {
		const char *keymgnt;
		const char *auth;
	} keymgnt_map[] = {
		{ .keymgnt = "NONE",	.auth = "NONE"},
		{ .keymgnt = "OPEN",	.auth = "NONE"},
		{ .keymgnt = "PSK",	.auth = "PSKAuthentication"},
		{ .keymgnt = "WPA-PSK",	.auth = "PSKAuthentication"},
		{ .keymgnt = "SAE",	.auth = "SAEAuthentication"},
		{ .keymgnt = "PSK-SAE",	.auth = "SAEandPSKAuthentication"},
		{ .keymgnt = "OWE",	.auth = "OPENandOWEAuthentication"},
		{ NULL}
	};

	for (i = 0; keymgnt_map[i].keymgnt != NULL; ++i) {
		if (strcasecmp(type, keymgnt_map[i].keymgnt) == 0)
			break;
	}

	if (keymgnt_map[i].keymgnt == NULL)
		return -EINVAL;

	return qcsapi_SSID_set_authentication_mode(ifname, ssid, keymgnt_map[i].auth);

}

static int set_sta_protocol(const char *ifname, const char *ssid, const char *keymgmt)
{
	int i;
	static const struct {
		const char *keymgmt;
		const char *proto;
	} proto_map[] = {
		{ .keymgmt = "WPA",		.proto = "WPAand11i"},
		{ .keymgmt = "WPA-PSK",		.proto = "WPAand11i"},
		{ .keymgmt = "WPA2-WPA-PSK",	.proto = "WPAand11i"},
		{ .keymgmt = "SAE",		.proto = "11i"},
		{ .keymgmt = "OWE",		.proto = "11i"},
		{ NULL}
	};

	if (strcmp(keymgmt, "") == 0)
		return 0;

	for (i = 0; proto_map[i].keymgmt != NULL; ++i) {
		if (strcasecmp(keymgmt, proto_map[i].keymgmt) == 0)
			break;
	}

	if (proto_map[i].keymgmt == NULL)
		return 0;

	return qcsapi_SSID_set_protocol(ifname, ssid, proto_map[i].proto);
}

void qnat_sta_device_list_interfaces(int tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_dut_response rsp = { 0 };

	/* can't use qcsapi_get_interface_by_index() since it works for AP only */
	snprintf(rsp.ap_info.interface_list, sizeof(rsp.ap_info.interface_list), "%s",
		qtn_get_sigma_interface());

	rsp.status = STATUS_COMPLETE;
	wfaEncodeTLV(tag, sizeof(rsp), (BYTE *) & rsp, out);

	*out_len = WFA_TLV_HDR_LEN + sizeof(rsp);
}

void qtn_handle_sta_reset_default(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int ret;
	qcsapi_wifi_mode current_mode;
	char ifname[IFNAMSIZ];
	char cert_prog[16];
	char conf_type[16];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	qtn_bring_up_radio_if_needed();

	if ((ret = qcsapi_wifi_get_mode(ifname, &current_mode)) < 0) {
		qtn_error("can't get mode, error %d", ret);
		status = STATUS_ERROR;
		goto respond;
	}

	if (current_mode != qcsapi_station) {
		qtn_error("mode %d is wrong, should be STA", current_mode);
		status = STATUS_ERROR;
		ret = -qcsapi_only_on_STA;
		goto respond;
	}

	/* disassociate to be sure that we start disassociated. possible error is ignored. */
	qcsapi_wifi_disassociate(ifname);

	/* mandatory certification program, e.g. VHT */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_PROG, cert_prog, sizeof(cert_prog)) <= 0) {
		ret = -EINVAL;
		status = STATUS_ERROR;
		goto respond;
	}

	/* optional configuration type, e.g. DUT or Testbed */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_TYPE, conf_type, sizeof(conf_type)) <= 0) {
		/* not specified */
		*conf_type = 0;
	}

	/* Certification program shall be: PMF, WFD, P2P or VHT */
	if (strcasecmp(cert_prog, "VHT") == 0) {
		if (strcasecmp(conf_type, "Testbed") == 0)
			ret = qtn_defconf_vht_testbed_sta(ifname);
		else
			ret = qtn_defconf_vht_dut_sta(ifname);

		if (ret < 0) {
			qtn_error("error: default configuration, errcode %d", ret);
			status = STATUS_ERROR;
			goto respond;
		}
	} else if (strcasecmp(cert_prog, "11n") == 0) {
		if (strcasecmp(conf_type, "Testbed") == 0) {
			ret = qtn_defconf_11n_testbed(ifname);
		} else {
			ret = qtn_defconf_11n_dut(ifname);
		}

		if (ret < 0) {
			qtn_error("error: default configuration, errcode %d", ret);
			status = STATUS_ERROR;
			goto respond;
		}
	} else if (strcasecmp(cert_prog, "PMF") == 0) {
		ret = qtn_defconf_pmf_dut(ifname);
		if (ret < 0) {
			qtn_error("error: default configuration, errcode %d", ret);
			status = STATUS_ERROR;
			goto respond;
		}
	} else if (strcasecmp(cert_prog, "TDLS") == 0) {
		ret = qtn_defconf_tdls_dut(ifname);
		if (ret < 0) {
			qtn_error("error: default configuration, errcode %d", ret);
			status = STATUS_ERROR;
			goto respond;
		}
	} else if (strcasecmp(cert_prog, "WPA3") == 0) {
		ret = qtn_defconf_wpa3_dut_sta(ifname);
		if (ret < 0) {
			qtn_error("error: default configuration, errcode %d", ret);
			status = STATUS_ERROR;
			goto respond;
		}
	} else if (strcasecmp(cert_prog, "DPP") == 0) {
		ret = qtn_defconf_dpp(ifname);
		if (ret < 0) {
			qtn_error("error: default configuration, errcode %d", ret);
			status = STATUS_ERROR;
			goto respond;
		}
	} else {
		/* TODO: processing for other programs */
		qtn_error("error: prog %s is not supported", cert_prog);
		ret = -ENOTSUP;
		status = STATUS_ERROR;
		goto respond;
	}

	/* TODO: Other options */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_autorate_fallback, 1);
	if (ret < 0) {
		qtn_error("error: cannot set autorate, errcode %d", ret);
		status = STATUS_ERROR;
		goto respond;
	}

	status = STATUS_COMPLETE;

respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_disconnect(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int ret;
	char ifname[IFNAMSIZ];
	char maintain_profile[16] = "0";

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_MAINTAIN_PROFILE,
				maintain_profile, sizeof(maintain_profile)) <= 0)
		qtn_log("no maintain_profile");

	qtn_log("maintain_profile is %s", maintain_profile);

	if (strcmp(maintain_profile, "1") != 0) {
		ret = qcsapi_wifi_disassociate(ifname);
		if (ret < 0)
			qtn_error("can't disassociate interface %s, error %d", ifname, ret);
	}

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_send_addba(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int ret;
	char ifname[IFNAMSIZ];
	char cmd[128];
	int tid;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_TID, &tid) <= 0) {
		qtn_error("no TID in request");
		status = STATUS_INVALID;
		goto respond;
	}

	snprintf(cmd, sizeof(cmd), "iwpriv %s htba_addba %d", ifname, tid);
	ret = system(cmd);
	if (ret != 0) {
		qtn_log("can't send addba using [%s], error %d", cmd, ret);
	}

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_preset_testparameters(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	char ifname_buf[IFNAMSIZ];
	const char *ifname;
	char val_buf[32];
	int ret;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);

	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	ret = qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname_buf, sizeof(ifname_buf));
	ifname = (ret > 0) ? ifname_buf : qtn_get_sigma_interface();

	ret = qtn_get_value_text(&cmd_req, QTN_TOK_MODE, val_buf, sizeof(val_buf));
	if (ret > 0) {
		const char *phy_mode = val_buf;
		qcsapi_unsigned_int old_bw;
		if (qcsapi_wifi_get_bw(ifname, &old_bw) < 0) {
			old_bw = 80;
		}

		ret = qcsapi_wifi_set_phy_mode(ifname, phy_mode);

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

		qtn_log("try to restore %d mode since phy change", old_bw);
		ret = qcsapi_wifi_set_bw(ifname, old_bw);

		if (ret < 0) {
			qtn_error("failed to restore old width, error %d", ret);
			ret = 0;
		}
	}

	ret = qtn_get_value_text(&cmd_req, QTN_TOK_WMM, val_buf, sizeof(val_buf));
	if (ret > 0) {
		char tmpbuf[64];
		int wmm_on = (strncasecmp(val_buf, "on", 2) == 0) ? 1 : 0;

		/* TODO: qcsapi specifies enable/disable WMM only for AP */
		snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s wmm %d", ifname, wmm_on);
		system(tmpbuf);
	}

	/* TODO: RTS FRGMNT
	 *   sta_preset_testparameters,interface,rtl8192s ,supplicant,ZeroConfig,mode,11ac,RTS,500
	 */
	ret = qtn_get_value_text(&cmd_req, QTN_TOK_RTS, val_buf, sizeof(val_buf));
	if (ret > 0){
		qcsapi_wifi_set_rts_threshold(ifname, atoi(val_buf));
	}

	/* TODO: FRGMNT
	 *   sta_preset_testparameters,interface,eth0,supplicant,ZeroConfig,mode,11ac,FRGMNT,2346
	 */

	status = STATUS_COMPLETE;

respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_get_mac_address(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int ret;
	char ifname_buf[16];
	const char *ifname;
	unsigned char macaddr[IEEE80211_ADDR_LEN];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);

	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	*ifname_buf = 0;
	ret = qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname_buf, sizeof(ifname_buf));

	ifname = (ret > 0) ? ifname_buf : qtn_get_sigma_interface();

	ret = qcsapi_interface_get_mac_addr(ifname, macaddr);

	if (ret < 0) {
		status = STATUS_ERROR;
		goto respond;
	}

	status = STATUS_COMPLETE;

respond:
	qtn_dut_make_response_macaddr(cmd_tag, status, ret, macaddr, out_len, out);
}

void qtn_handle_sta_get_info(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int ret;
	char ifname_buf[16];
	const char *ifname;
	char info_buf[128] = {0};
	int info_len = 0;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);

	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	*ifname_buf = 0;
	ret = qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname_buf, sizeof(ifname_buf));

	ifname = (ret > 0) ? ifname_buf : qtn_get_sigma_interface();

	ret = snprintf(info_buf + info_len, sizeof(info_buf) - info_len,
			"vendor,%s,build_name,%s", "Quantenna", QDRV_BLD_NAME);

	if (ret < 0) {
		status = STATUS_ERROR;
		goto respond;
	}

	info_len += ret;

	/* TODO: add other information */

	status = STATUS_COMPLETE;

respond:
	qtn_dut_make_response_vendor_info(cmd_tag, status, ret, info_buf, out_len, out);
}

void qtn_handle_sta_set_wireless(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int ret;
	char ifname_buf[16];
	const char *ifname;
	char cert_prog[32];
	int vht_prog;
	int feature_enable;
	int feature_val;
	char val_buf[128];
	char cmd[128];
	int conv_err = 0;
	int num_ss;
	int mcs;
	struct qtn_dut_config *conf;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);

	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	*ifname_buf = 0;
	ret = qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname_buf, sizeof(ifname_buf));

	ifname = (ret > 0) ? ifname_buf : qtn_get_sigma_interface();
	conf = qtn_dut_get_config(ifname);

	ret = qtn_get_value_text(&cmd_req, QTN_TOK_PROGRAM, cert_prog, sizeof(cert_prog));
	if (ret <= 0) {
		/* mandatory parameter */
		status = STATUS_ERROR;
		goto respond;
	}

	vht_prog = (strcasecmp(cert_prog, "VHT") == 0) ? 1 : 0;

	/* ADDBA_REJECT, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_ADDBA_REJECT, &feature_enable, &conv_err) > 0) {
		char tmpbuf[64];
		int ba_control;

		/* ADDBA_REJECT:enabled => ADDBA.Request:disabled */
		ba_control = (feature_enable) ? 0 : 0xFFFF;

		snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s ba_control %d", ifname, ba_control);
		system(tmpbuf);

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* AMPDU, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_AMPDU, &feature_enable, &conv_err) > 0) {
		char tmpbuf[64];
		int ba_control;

		/* AMPDU:enabled => ADDBA.Request:enabled */
		ba_control = (feature_enable) ? 0xFFFF : 0;

		snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s ba_control %d", ifname, ba_control);
		system(tmpbuf);

		/* TODO: check if AuC is able to make AMSDU aggregation for VHT single AMPDU */

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* AMSDU, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_AMSDU, &feature_enable, &conv_err) > 0) {
		ret = qcsapi_wifi_set_tx_amsdu(ifname, feature_enable);

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* STBC_RX, int (0/1) */
	if (qtn_get_value_int(&cmd_req, QTN_TOK_STBC_RX, &feature_val) > 0) {
		/* enable/disable STBC */
		ret = qcsapi_wifi_set_option(ifname, qcsapi_stbc, feature_val);

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

		if (feature_val > 0) {
			/* TODO: set number of STBC Receive Streams */
		}
	}

	/* WIDTH, int (80/40/20) */
	if (qtn_get_value_int(&cmd_req, QTN_TOK_WIDTH, &feature_val) > 0) {
		if (!conf) {
			ret = -EFAULT;
			status = STATUS_ERROR;
			goto respond;
		}

		/* channel width */
		ret = qcsapi_wifi_set_bw(ifname, (unsigned) feature_val);
		if (ret < 0) {
			status = STATUS_ERROR;
			qtn_log("can't set width to %d, error %d", feature_val, ret);
			goto respond;
		}

		snprintf(cmd, sizeof(cmd), "set_fixed_bw -b %d", feature_val);
		system(cmd);

		switch (feature_val) {
		case 0:
			conf->bws = QTN_BW_MAX;
			break;
		case 20:
			conf->bws = QTN_BW_20M;
			break;
		case 40:
			conf->bws = QTN_BW_40M;
			break;
		case 80:
			conf->bws = QTN_BW_80M;
			break;
		default:
			break;
		}
		conf->update_settings = 1;
	}

	/* SMPS, SM Power Save Mode, NOT Supported */
	if (qtn_get_value_int(&cmd_req, QTN_TOK_SMPS, &feature_val) > 0) {
		ret = -EOPNOTSUPP;

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}
	}

	/* TXSP_STREAM, (1SS/2SS/3SS) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_TXSP_STREAM, val_buf, sizeof(val_buf)) > 0) {
		int nss = 0;
		qcsapi_mimo_type mt = vht_prog ? qcsapi_mimo_vht : qcsapi_mimo_ht;

		ret = sscanf(val_buf, "%dSS", &nss);

		if (ret != 1) {
			ret = -EINVAL;
			status = STATUS_ERROR;
			goto respond;
		}

		ret = qcsapi_wifi_set_nss_cap(ifname, mt, nss);

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}
	}

	/* RXSP_STREAM, (1SS/2SS/3SS) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_RXSP_STREAM, val_buf, sizeof(val_buf)) > 0) {
		int nss = 0;
		qcsapi_mimo_type mt = vht_prog ? qcsapi_mimo_vht : qcsapi_mimo_ht;

		ret = sscanf(val_buf, "%dSS", &nss);

		if (ret != 1) {
			ret = -EINVAL;
			status = STATUS_ERROR;
			goto respond;
		}

		ret = qcsapi_wifi_set_rx_nss_cap(ifname, mt, nss);

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}
	}

	/* Band, NOT Supported */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_BAND, val_buf, sizeof(val_buf)) > 0) {
		ret = -EOPNOTSUPP;

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}
	}

	/* DYN_BW_SGNL, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_DYN_BW_SGNL, &feature_enable, &conv_err) > 0) {
		if (conf) {
			conf->bws_dynamic = (unsigned char)feature_enable;
			conf->update_settings = 1;
		} else {
			ret = -EFAULT;
			status = STATUS_ERROR;
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* BW_SGNL, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_BW_SGNL, &feature_enable, &conv_err) > 0) {
		if (conf) {
			conf->bws_enable = (unsigned char)feature_enable;
			conf->update_settings = 1;
		} else {
			ret = -EFAULT;
			status = STATUS_ERROR;
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	if (qtn_get_value_enable(&cmd_req, QTN_TOK_RTS_FORCE, &feature_enable, &conv_err) > 0) {
		if (conf) {
			conf->force_rts = (unsigned char)feature_enable;
			conf->update_settings = 1;
		} else {
			ret = -EFAULT;
			status = STATUS_ERROR;
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}


	if (conf && conf->update_settings) {
		qtn_set_rts_settings(ifname, conf);
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


		/* TODO: it sets general capability for short GI, not only SGI80 */
		ret = qcsapi_wifi_set_option(ifname, qcsapi_short_GI, feature_enable);

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* TxBF, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_TXBF, &feature_enable, &conv_err) > 0) {
		/* TODO: check, that we enable/disable SU TxBF beamformee capability
		 * with explicit feedback */
		ret = qcsapi_wifi_set_option(ifname, qcsapi_beamforming, feature_enable);

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* LDPC, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_LDPC, &feature_enable, &conv_err) > 0) {
		char tmpbuf[64];

		snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s set_ldpc %d", ifname, feature_enable);
		system(tmpbuf);

		/* TODO: what about IEEE80211_PARAM_LDPC_ALLOW_NON_QTN ?
		 *       Allow non QTN nodes to use LDPC */

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* Opt_md_notif_ie, (NSS=1 & BW=20Mhz => 1;20) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_OPT_MD_NOTIF_IE, val_buf, sizeof(val_buf)) > 0) {
		int nss = 0;
		int bw = 0;
		uint8_t chwidth;
		uint8_t rxnss;
		uint8_t rxnss_type = 0;
		uint8_t vhtop_notif_mode;
		char tmpbuf[64];

		ret = sscanf(val_buf, "%d;%d", &nss, &bw);

		if (ret != 2) {
			ret = -EINVAL;
			status = STATUS_ERROR;
			goto respond;
		}

		switch (bw) {
		case 20:
			chwidth = IEEE80211_CWM_WIDTH20;
			break;
		case 40:
			chwidth = IEEE80211_CWM_WIDTH40;
			break;
		case 80:
			chwidth = IEEE80211_CWM_WIDTH80;
			break;
		default:
			ret = -EINVAL;
			status = STATUS_ERROR;
			goto respond;
		}

		if ((nss < 1) || (nss > IEEE80211_AC_MCS_NSS_MAX)) {
			ret = -EINVAL;
			status = STATUS_ERROR;
			goto respond;
		}

		rxnss = nss - 1;

		vhtop_notif_mode = SM(chwidth, IEEE80211_VHT_OPMODE_CHWIDTH) |
				SM(rxnss, IEEE80211_VHT_OPMODE_RXNSS) |
				SM(rxnss_type, IEEE80211_VHT_OPMODE_RXNSS_TYPE);

		snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s set_vht_opmntf %d",
				ifname,
				vhtop_notif_mode);
		system(tmpbuf);
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_MCS_FIXEDRATE, &feature_val) > 0) {
		char tmpbuf[64];
		snprintf(tmpbuf, sizeof(tmpbuf), "MCS%d", feature_val);
		ret = qcsapi_wifi_set_mcs_rate(ifname, tmpbuf);
		if (ret < 0) {
			status = STATUS_ERROR;
			qtn_error("can't set mcs to %d, error %d", feature_val, ret);
			goto respond;
		}
	}

	/* nss_mcs_cap, (nss_capabilty;mcs_capability => 2;0-9) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_NSS_MCS_CAP, val_buf, sizeof(val_buf)) > 0) {
		int nss = 0;
		int mcs_high = 0;
		int mcs_cap;
		char tmpbuf[64];

		ret = sscanf(val_buf, "%d;0-%d", &nss, &mcs_high);

		if (ret != 2) {
			ret = -EINVAL;
			status = STATUS_ERROR;
			goto respond;
		}

		/* NSS capability */
		ret = qcsapi_wifi_set_nss_cap(ifname, qcsapi_mimo_vht, nss);

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

		/* MCS capability */
		switch (mcs_high) {
		case 7:
			mcs_cap = IEEE80211_VHT_MCS_0_7;
			break;
		case 8:
			mcs_cap = IEEE80211_VHT_MCS_0_8;
			break;
		case 9:
			mcs_cap = IEEE80211_VHT_MCS_0_9;
			break;
		default:
			ret = -EINVAL;
			status = STATUS_ERROR;
			goto respond;
		}

		snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s set_vht_mcs_cap %d",
						ifname,
						mcs_cap);
		system(tmpbuf);
	}

	/* Tx_lgi_rate, int (0) */
	if (qtn_get_value_int(&cmd_req, QTN_TOK_TX_LGI_RATE, &feature_val) > 0) {
		/* setting Tx Highest Supported Long GI Data Rate
		 */
		if (feature_val != 0) {
			/* we support only 0 */
			ret = -EOPNOTSUPP;
			status = STATUS_ERROR;
			goto respond;
		}
	}

	/* Zero_crc (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_ZERO_CRC, &feature_enable, &conv_err) > 0) {
		/* setting VHT SIGB CRC to fixed value (e.g. all "0") not supported
		 * for current hardware platform
		 * VHT SIGB CRC is always calculated
		 * tests: 4.2.26
		 */

		ret = -EOPNOTSUPP;

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* Vht_tkip (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_VHT_TKIP, &feature_enable, &conv_err) > 0) {
		/* enable TKIP in VHT mode
		 * Tests: 4.2.44
		 * Testbed Wi-Fi CERTIFIED ac with the capability of setting TKIP and VHT
		 * and ability to generate a probe request.
		 */
		char tmpbuf[64];

		snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s set_vht_tkip %d",
				ifname, feature_enable);
		system(tmpbuf);

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* Vht_wep, (enable/disable), NOT USED IN TESTS (as STA testbed) */

	/* BW_SGNL, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_BW_SGNL, &feature_enable, &conv_err) > 0) {
		/* Tests: 4.2.51
		 * STA1: Testbed Wi-Fi CERTIFIED ac STA supporting the optional feature RTS
		 *       with BW signaling
		 */

		struct qtn_dut_config *conf = qtn_dut_get_config(ifname);

		if (conf) {
			conf->bws_enable = (unsigned char)feature_enable;
		} else {
			ret = -EFAULT;
			status = STATUS_ERROR;
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* MU_TxBF, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_MU_TXBF, &feature_enable, &conv_err) > 0) {
		/* TODO: enable/disable Multi User (MU) TxBF beamformee capability
		 * with explicit feedback
		 *
		 * Tests: 4.2.56
		 */
		int su_status = 0;
		if (feature_enable &&
			qcsapi_wifi_get_option(ifname, qcsapi_beamforming, &su_status) >= 0
			&& su_status == 0) {
			/* have to have SU enabled if we enable MU */
			ret = qcsapi_wifi_set_option(ifname, qcsapi_beamforming, 1);
			if (ret < 0) {
				qtn_error("can't enable beamforming, error %d", ret);
				ret = 0;
			}
		}

		ret = qtn_set_mu_enable((unsigned)feature_enable);

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* CTS_WIDTH, int (0) */
	if (qtn_get_value_int(&cmd_req, QTN_TOK_CTS_WIDTH, &feature_val) > 0) {
		char tmpbuf[64];

		snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s set_cts_bw %d",
				ifname, feature_val);
		system(tmpbuf);
	}


	/* RTS_BWS, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_RTS_BWS, &feature_enable, &conv_err) > 0) {
		/* TODO: enable RTS with Bandwidth Signaling Feature
		 *
		 * Tests: 4.2.59
		 */

		ret = -EOPNOTSUPP;

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_NSS_MCS_OPT, val_buf, sizeof(val_buf)) > 0 &&
		sscanf(val_buf, "%d;%d", &num_ss, &mcs) == 2) {

		snprintf(val_buf, sizeof(val_buf), "MCS%d0%d", num_ss, mcs);
		if ((ret = qcsapi_wifi_set_mcs_rate(ifname, val_buf)) < 0) {
			qtn_error("can't set mcs rate to %s, error %d", val_buf, ret);
			status = STATUS_ERROR;
			goto respond;
		}
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_TXBANDWIDTH, &feature_val) > 0 &&
		(ret = set_tx_bandwidth(ifname, feature_val)) < 0) {
		qtn_error("can't set bandwidth to %d, error %d", feature_val, ret);
		status = STATUS_ERROR;
		goto respond;
	}

	status = STATUS_COMPLETE;

respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_rfeature(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret;
	char ifname[IFNAMSIZ];
	char val_str[128];
	int feature_val;
	int conv_err;
	int num_ss;
	int mcs;
	int need_tdls_channel_switch = 0;


	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0)
		goto respond;

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
	status = ret < 0 ? STATUS_ERROR : STATUS_COMPLETE;
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_ip_config(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0)
		goto respond;

	/* empty for now */

respond:
	status = ret < 0 ? STATUS_ERROR : STATUS_COMPLETE;
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_psk(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret;
	int set_pmf = 0;
	int pmf_cap = qcsapi_pmf_disabled;
	char ifname[IFNAMSIZ];
	char ssid_str[128];
	char pass_str[128];
	char key_type[128];
	char enc_type[128];
	char pmf_type[128];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_SSID, ssid_str, sizeof(ssid_str)) <= 0) {
		qtn_error("can't get ssid");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_PASSPHRASE, pass_str, sizeof(pass_str)) <= 0) {
		qtn_error("can't get pass phrase");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_KEYMGMTTYPE, key_type, sizeof(key_type)) <= 0) {
		qtn_error("can't get pass key_type");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_ENCPTYPE, enc_type, sizeof(enc_type)) <= 0) {
		qtn_error("can't get enc_type");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_PMF, pmf_type, sizeof(pmf_type)) > 0) {
		set_pmf = 1;
		if (strcasecmp(pmf_type, "Required") == 0
			|| strcasecmp(pmf_type, "Forced_Required") == 0) {
			pmf_cap = qcsapi_pmf_required;
		} else if (strcasecmp(pmf_type, "Optional") == 0) {
			pmf_cap = qcsapi_pmf_optional;
		} else if (strcasecmp(pmf_type, "Disable") == 0
			|| strcasecmp(pmf_type, "Forced_Disabled") == 0) {
			pmf_cap = qcsapi_pmf_disabled;
		} else {
			qtn_error("can't parse pmf type %s", pmf_type);
			goto respond;
		}
	}

	status = STATUS_ERROR;

	if (qcsapi_SSID_verify_SSID(ifname, ssid_str) < 0 &&
			(ret = qcsapi_SSID_create_SSID(ifname, ssid_str)) < 0) {
		qtn_error("can't create SSID %s, error %d", ssid_str, ret);
		goto respond;
	}

	if ((ret = set_sta_encryption(ifname, ssid_str, enc_type)) < 0) {
		qtn_error("can't set enc to %s, error %d", enc_type, ret);
		goto respond;
	}

	/* possible values for key_type: wpa/wpa2/wpa-psk/wpa2-psk/wpa2-ft/wpa2-wpa-psk */
	const int is_wpa_key_type = strcasecmp(key_type, "wpa") == 0 ||
					strcasecmp(key_type, "wpa-psk") == 0 ||
					strcasecmp(key_type, "wpa2-wpa-psk") == 0;

	if (is_wpa_key_type && (ret = qcsapi_SSID_set_protocol(ifname, ssid_str, "WPAand11i")) < 0) {
		qtn_error("can't set proto for %s key type, error %d", key_type, ret);
		goto respond;
	}

	if ((ret = qcsapi_SSID_set_authentication_mode(ifname, ssid_str, "PSKAuthentication")) < 0) {
		qtn_error("can't set PSK authentication, error %d", ret);
		goto respond;
	}

	if (set_pmf) {
		ret = qcsapi_SSID_set_pmf(ifname, ssid_str, pmf_cap);
		if (ret < 0) {
			qtn_error("can't set pmf to %d, error %d, ssid %s", pmf_cap, ret, ssid_str);
			goto respond;
		}
		if (pmf_cap != qcsapi_pmf_disabled) {
			ret = qcsapi_SSID_set_authentication_mode(
				ifname, ssid_str, "SHA256PSKAuthenticationMixed");
			if (ret < 0) {
				qtn_error("can't set authentication for PMF, error %d, ssid %s",
						ret, ssid_str);
				goto respond;
			}
		}
	}

	if ((ret = qcsapi_SSID_set_key_passphrase(ifname, ssid_str, 0, pass_str)) < 0) {
		qtn_error("can't set pass: ifname %s, ssid %s, key_type %s, pass %s, error %d",
			ifname, ssid_str, key_type, pass_str, ret);
	}

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_associate(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int ret;
	char ifname[IFNAMSIZ];
	char ssid_str[128];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_SSID, ssid_str, sizeof(ssid_str)) <= 0) {
		qtn_error("can't get ssid");
		status = STATUS_INVALID;
		goto respond;
	}

	/* take into account deferred security configuration */
	qtn_check_defer_mode_apply_config(ifname);

	if ((ret = qcsapi_wifi_associate(ifname, ssid_str)) < 0) {
		qtn_error("can't associate, ifname %s, ssid %s, error %d", ifname, ssid_str, ret);
	}

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_encryption(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int ret = 0;
	char ifname[IFNAMSIZ];
	char ssid_str[128];
	char encryption[128];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_SSID, ssid_str, sizeof(ssid_str)) <= 0) {
		qtn_error("can't get ssid");
		status = STATUS_INVALID;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_ENCPTYPE, encryption, sizeof(encryption)) <= 0) {
		qtn_error("can't get encryption");
		status = STATUS_INVALID;
		goto respond;
	}

	status = STATUS_ERROR;

	if (strcasecmp(encryption, "wep") == 0) {
		qtn_log("wep is not supported");
		ret = -EINVAL;
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

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

static
int qtn_send_vht_opmode_action(const char* ifname, const unsigned char *dest_mac, int cbw, int nss, int rxnss)
{
	struct iwreq iwr;
	unsigned char frame_buf[64];
	struct app_action_frame_buf *action_frm = (struct app_action_frame_buf*)frame_buf;
	int ioctl_sock;
	uint8_t chwidth;
	uint8_t rxnss_type = 0;
	uint8_t vhtop_notif_mode;
	int ret;

	switch (cbw) {
	case 20:
		chwidth = IEEE80211_CWM_WIDTH20;
		break;
	case 40:
		chwidth = IEEE80211_CWM_WIDTH40;
		break;
	case 80:
		chwidth = IEEE80211_CWM_WIDTH80;
		break;
	default:
		return -EINVAL;
	}

	if ((nss < 1) || (nss > IEEE80211_AC_MCS_NSS_MAX)) {
		return -EINVAL;
	}

	vhtop_notif_mode = SM(chwidth, IEEE80211_VHT_OPMODE_CHWIDTH) |
			SM(rxnss, IEEE80211_VHT_OPMODE_RXNSS) |
			SM(rxnss_type, IEEE80211_VHT_OPMODE_RXNSS_TYPE);

	ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);

	if (ioctl_sock < 0)
		return -errno;

	action_frm->cat = IEEE80211_ACTION_CAT_VHT;
	action_frm->action = IEEE80211_ACTION_VHT_OPMODE_NOTIFICATION;
	memcpy(action_frm->dst_mac_addr, dest_mac, IEEE80211_ADDR_LEN);
	action_frm->frm_payload.length = 1;
	action_frm->frm_payload.data[0] = vhtop_notif_mode;

	/* send action frame */
	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ - 1);

	iwr.u.data.flags = SIOCDEV_SUBIO_SEND_ACTION_FRAME;
	iwr.u.data.pointer = action_frm;
	iwr.u.data.length = sizeof(struct app_action_frame_buf) + action_frm->frm_payload.length;

	ret = ioctl(ioctl_sock, IEEE80211_IOCTL_EXT, &iwr);
	if (ret < 0) {
		qtn_error("failed to send action frame");
	}

	close(ioctl_sock);

	return ret;
}

static
int qtn_send_bcnrep_request(const char* ifname, struct qtn_bcnreport_req* bcnreq_param)
{
#define IS_EMPTY_PARAM(_param)	(0 == memcmp(_param, "\x00", 1))
	int i, ret = 0;
	char cmd[256];

	if (access(QTN_MBO_TEST_CLI, X_OK) != 0) {
		qtn_error("failed to send bcnrep request: %s can't access", QTN_MBO_TEST_CLI);
		return -EINVAL;
	}

	if (!IS_EMPTY_PARAM(bcnreq_param->chans)) {
		for (i = 0; i < strlen(bcnreq_param->chans); ++i) {
			if (bcnreq_param->chans[i]
				== '_') {
				bcnreq_param->chans[i] = ',';
			}
		}
	}

	if (!IS_EMPTY_PARAM(bcnreq_param->reqinfo)) {
		for (i = 0; i < strlen(bcnreq_param->reqinfo); ++i) {
			if (bcnreq_param->reqinfo[i]
				== '_') {
				bcnreq_param->reqinfo[i] = ',';
			}
		}
	}

	ret = snprintf(cmd, sizeof(cmd), "%s test beacon_req %s opclass=%d chan=%d bssid=%s "
			"interval=%d duration=%d mode=%s detail=%d %s %s %s",
			QTN_MBO_TEST_CLI, bcnreq_param->dest_mac, bcnreq_param->opclass, bcnreq_param->chan,
			bcnreq_param->bssid, bcnreq_param->interval, bcnreq_param->duration,
			bcnreq_param->mode, bcnreq_param->detail,
			IS_EMPTY_PARAM(bcnreq_param->ssid) ? "" : bcnreq_param->ssid,
			IS_EMPTY_PARAM(bcnreq_param->chans) ? "" : bcnreq_param->chans,
			IS_EMPTY_PARAM(bcnreq_param->reqinfo) ? "" : bcnreq_param->reqinfo);

	if (bcnreq_param->last_beacon_rpt_ind)
		strcat(cmd, " last_bcn=1");

	qtn_log("MBO test cmd[%s]", cmd);

	ret = system(cmd);
	if (ret != 0) {
		qtn_error("failed to send bcnrep request: system command error");
	}

	return ret;
}

static
int qtn_send_btm_request(const char* ifname, char *dest_mac, int cand_list)
{
	char str[256], cmd[128];
	unsigned long val = 0;
	FILE *filep = NULL;
	int ret = 0;

	if (access(QTN_MBO_TEST_CLI, X_OK) != 0) {
		qtn_error("failed to send BTM request: %s can't access", QTN_MBO_TEST_CLI);
		return -EINVAL;
	}

	filep = popen("iwpriv wifi0 get_btm_delay", "r");
	if (NULL == filep) {
		qtn_error("iwpriv wifi0 get_btm_delay failed");
		return -EINVAL;
	} else {
		if (fgets(str, 128, filep) != NULL)
			qtn_log("iwpriv get btm delay value[%s]", str);
		pclose(filep);
	}

	if (str[0] != '\0') {
		char *token = strtok(str, ":");
		while(NULL != token) {
			val = strtoul(token, NULL, 10);
			token = strtok(NULL, ":");
		}
	}

	if (val == 5) {
		ret = snprintf(cmd, sizeof(cmd), "ifconfig %s down", ifname);
	} else
		ret = snprintf(cmd, sizeof(cmd), "%s test actuate 11v %s",
			QTN_MBO_TEST_CLI, dest_mac);

	qtn_log("MBO test cmd[%s %d]", cmd, cand_list);

	ret = system(cmd);
	if (ret)
		qtn_error("failed to send bcnrep request: system command error");

	return ret;
}

void qtn_handle_dev_send_frame(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	struct qtn_bcnreport_req bcnreq_param;
	int status;
	int ret;
	char ifname_buf[IFNAMSIZ];
	const char *ifname;
	char program[16];
	char tmpbuf[128];
	char peer[128];
	unsigned char dest_mac[IEEE80211_ADDR_LEN];
	char mac_str[18];
	int cand_list;
	int chan_width;
	int nss;
	qcsapi_unsigned_int rx_nss_cap;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	*ifname_buf = 0;
	ret = qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname_buf, sizeof(ifname_buf));

	ifname = (ret > 0) ? ifname_buf : qtn_get_sigma_interface();
	if ((strcasecmp(ifname, "5G") == 0) || (strcasecmp(ifname, "50G") == 0)) {
		ifname = "wifi0";
	} else if (strcasecmp(ifname, "24G") == 0) {
		ifname = "wlan0";
	}

	status = STATUS_ERROR;

	ret = qtn_get_value_text(&cmd_req, QTN_TOK_PROGRAM, program, sizeof(program));
	if (ret <= 0) {
		/* mandatory parameter */
		qtn_error("can't get program");
		status = STATUS_ERROR;
		goto respond;
	}

	if (strcasecmp(program, "MBO") == 0) {
		/* process FrameName */
		if (qtn_get_value_text(&cmd_req, QTN_TOK_FRAMENAME,
			tmpbuf,	sizeof(tmpbuf)) <= 0) {
			qtn_error("can't get frame_name");
			status = STATUS_ERROR;
			goto respond;
		}

		if (strcasecmp(tmpbuf, "BTMReq") == 0) {
			if (qtn_get_value_text(&cmd_req, QTN_TOK_DEST_MAC,
				mac_str, sizeof(mac_str)) <= 0) {
				qtn_error("can't get dest_mac");
				status = STATUS_ERROR;
				goto respond;
			}

			if (qtn_get_value_int(&cmd_req, QTN_TOK_CANDIDATE_LIST,
				&cand_list) <= 0) {
				qtn_error("can't get candidate list");
				status = STATUS_ERROR;
				goto respond;
			}
			/* send BTM request */
			ret = qtn_send_btm_request(ifname, mac_str, cand_list);
			if (ret < 0) {
				status = STATUS_ERROR;
				goto respond;
			}

		} else if (strcasecmp(tmpbuf, "BcnRptReq") == 0) {
			memset(&bcnreq_param, 0, sizeof(bcnreq_param));

			if (qtn_get_value_text(&cmd_req, QTN_TOK_DEST_MAC,
				bcnreq_param.dest_mac, sizeof(bcnreq_param.dest_mac)) <= 0) {
				qtn_error("can't get dest_mac");
				status = STATUS_ERROR;
				goto respond;
			}

			if (qtn_get_value_int(&cmd_req, QTN_TOK_REGULATORY_CLASS,
				&bcnreq_param.opclass) <= 0) {
				qtn_error("can't get regulatory class");
				status = STATUS_ERROR;
				goto respond;
			}

			if (qtn_get_value_text(&cmd_req, QTN_TOK_CHANNEL,
				tmpbuf, sizeof(tmpbuf)) > 0 &&
				sscanf(tmpbuf, "%d", &bcnreq_param.chan) != 1) {
				qtn_error("can't get channel number");
				status = STATUS_ERROR;
				goto respond;
			}

			if (qtn_get_value_int(&cmd_req, QTN_TOK_RAND_INTERVAL,
				&bcnreq_param.interval) <= 0) {
				qtn_error("can't get randomization interval");
				status = STATUS_ERROR;
				goto respond;
			}

			if (qtn_get_value_int(&cmd_req, QTN_TOK_MEAS_DURATION,
				&bcnreq_param.duration) <= 0) {
				qtn_error("can't get measurement duration");
				status = STATUS_ERROR;
				goto respond;
			}

			if (qtn_get_value_text(&cmd_req, QTN_TOK_MEAS_MODE,
				bcnreq_param.mode, sizeof(bcnreq_param.mode)) <= 0) {
				qtn_error("can't get measurement mode");
				status = STATUS_ERROR;
				goto respond;
			}

			if (qtn_get_value_text(&cmd_req, QTN_TOK_BSSID,
				bcnreq_param.bssid, sizeof(bcnreq_param.bssid)) <= 0) {
				qtn_error("can't get BSSID");
				status = STATUS_ERROR;
				goto respond;
			}

			if (qtn_get_value_int(&cmd_req, QTN_TOK_REPORT_DETAIL,
				&bcnreq_param.detail) <= 0) {
				qtn_error("can't get reporting detail");
				status = STATUS_ERROR;
				goto respond;
			}

			/* optional configuration type, ssid=Wi-Fi */
			if (qtn_get_value_text(&cmd_req, QTN_TOK_SSID,
				bcnreq_param.ssid, sizeof(bcnreq_param.ssid)) > 0) {
				snprintf(tmpbuf, sizeof(tmpbuf), "ssid=%s", bcnreq_param.ssid);
				memcpy(bcnreq_param.ssid, tmpbuf, QTN_BCNRPT_STR_LEN);
			}

			/* optional configuration type, chans=36_48 */
			if (qtn_get_value_text(&cmd_req, QTN_TOK_AP_CHAN_REPORT,
				bcnreq_param.chans, sizeof(bcnreq_param.chans)) > 0) {
				snprintf(tmpbuf, sizeof(tmpbuf), "chans=%s", bcnreq_param.chans);
				memcpy(bcnreq_param.chans, tmpbuf, QTN_BCNRPT_STR_LEN);
			}

			/* optional configuration type, info=0_221 */
			if (qtn_get_value_text(&cmd_req, QTN_TOK_REQUEST_INFO,
				bcnreq_param.reqinfo, sizeof(bcnreq_param.reqinfo)) > 0) {
				snprintf(tmpbuf, sizeof(tmpbuf), "info=%s", bcnreq_param.reqinfo);
				memcpy(bcnreq_param.reqinfo, tmpbuf, QTN_BCNRPT_STR_LEN);
			}

			/* optional configuration type, LastBeaconRptIndication=1 */
			if (qtn_get_value_int(&cmd_req, QTN_TOK_LAST_BEACON_REPORT_INDICATION,
				&bcnreq_param.last_beacon_rpt_ind) <= 0)
				bcnreq_param.last_beacon_rpt_ind = 0;

			/* send beacon report request */
			ret = qtn_send_bcnrep_request(ifname, &bcnreq_param);
			if (ret < 0) {
				status = STATUS_ERROR;
				goto respond;
			}
		}

	}

	if (strcasecmp(program, "VHT") == 0) {
		/* Two mandatory arguments: FrameName and Dest_mac */
		ret = qtn_get_value_text(&cmd_req, QTN_TOK_FRAMENAME, tmpbuf,
				sizeof(tmpbuf));

		if (ret <= 0) {
			qtn_error("can't get frame_name");
			status = STATUS_ERROR;
			goto respond;
		}

		/* we support only "Op_md_notif_frm" */
		if (strcasecmp(tmpbuf, "Op_md_notif_frm") != 0) {
			qtn_error("support only Op_md_notif_frm");
			ret = -EOPNOTSUPP;
			status = STATUS_ERROR;
			goto respond;
		}

		ret = qtn_get_value_text(&cmd_req, QTN_TOK_DEST_MAC, tmpbuf, sizeof(tmpbuf));
		if (ret <= 0) {
			qtn_error("can't get dest_mac");
			status = STATUS_ERROR;
			goto respond;
		}

		ret = qtn_parse_mac(tmpbuf, dest_mac);
		if (ret < 0) {
			qtn_error("invalid macaddr");
			status = STATUS_ERROR;
			goto respond;
		}

		/* optional arguments */
		if (qtn_get_value_int(&cmd_req, QTN_TOK_CHANNEL_WIDTH, &chan_width) <= 0) {
			/* get current bw capability */
			qcsapi_unsigned_int bw_cap;

			ret = qcsapi_wifi_get_bw(ifname, &bw_cap);

			if (ret < 0) {
				qtn_error("unable to get bw capability");
				status = STATUS_ERROR;
				goto respond;
			}

			chan_width = (int)bw_cap;
		}

		if (qtn_get_value_int(&cmd_req, QTN_TOK_NSS, &nss) <= 0) {
			/* get current nss capability */
			qcsapi_unsigned_int nss_cap;


			ret = qcsapi_wifi_get_nss_cap(ifname, qcsapi_mimo_vht, &nss_cap);
			if (ret < 0) {
				qtn_error("unable to get nss capability");
				status = STATUS_ERROR;
				goto respond;
			}
			nss = (int)nss_cap;
		}

		ret = qcsapi_wifi_get_rx_nss_cap(ifname, qcsapi_mimo_vht, &rx_nss_cap);
		if (ret < 0) {
			qtn_error("unable to get rx nss capability");
			status = STATUS_ERROR;
			goto respond;
		}

		/* send action frame */
		ret = qtn_send_vht_opmode_action(ifname, dest_mac, chan_width, nss, (int)rx_nss_cap);

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_TYPE, tmpbuf, sizeof(tmpbuf)) > 0 &&
		qtn_get_value_text(&cmd_req, QTN_TOK_PEER, peer, sizeof(peer)) > 0) {

		qcsapi_tdls_oper oper = qcsapi_tdls_nosuch_oper;

		if (strcasecmp(tmpbuf, "Setup") == 0) {
			oper = qcsapi_tdls_oper_setup;
		} else if (strcasecmp(tmpbuf, "channelSwitchReq") == 0) {
			oper = qcsapi_tdls_oper_switch_chan;
		} else if (strcasecmp(tmpbuf, "discovery") == 0) {
			oper = qcsapi_tdls_oper_discover;
		}  else if (strcasecmp(tmpbuf, "teardown") == 0) {
			oper = qcsapi_tdls_oper_teardown;
		}

		if (oper != qcsapi_tdls_nosuch_oper &&
				(ret = qcsapi_wifi_tdls_operate(ifname, oper, peer, 1000)) < 0) {
			qtn_error("can't set tdls_operate to %s, error %d", tmpbuf, ret);
			goto respond;
		}
	}

	status = STATUS_COMPLETE;

respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_reassoc(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret = 0;
	char ifname[IFNAMSIZ];
	char bssid[64];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_BSSID, bssid, sizeof(bssid)) <= 0) {
		qtn_error("can't get bssid");
		goto respond;
	}

	if ((ret = qcsapi_wifi_reassociate(ifname)) < 0) {
		qtn_error("can't reassociate, error %d", ret);
	}

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_systime(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret = 0;
	char cmd[128];
	int month;
	int date;
	int year;
	int hours;
	int minutes;
	int seconds;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_YEAR, &year) <= 0) {
		qtn_error("can't get year");
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_MONTH, &month) <= 0) {
		qtn_error("can't get month");
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_DATE, &date) <= 0) {
		qtn_error("can't get date");
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_HOURS, &hours) <= 0) {
		qtn_error("can't get hours");
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_MINUTES, &minutes) <= 0) {
		qtn_error("can't get minutes");
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_SECONDS, &seconds) <= 0) {
		qtn_error("can't get seconds");
		goto respond;
	}

	snprintf(cmd, sizeof(cmd), "date -s %2.2d%2.2d%2.2d%2.2d%4.4d.%2.2d",
		month, date, hours, minutes, year, seconds);
	ret = system(cmd);
	if (ret != 0) {
		qtn_error("can't set time. error %d, cmd %s", ret, cmd);
	}

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_radio(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret = 0;
	char mode[64];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_MODE, mode, sizeof(mode)) <= 0) {
		qtn_error("can't get mode");
		goto respond;
	}

	if ((ret = qtn_set_rf_enable(strcasecmp(mode, "On") == 0 ? 1 : 0)) < 0) {
		qtn_error("can't set rf to %s, error %d", mode, ret);
	}

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_macaddr(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret = 0;
	char ifname[IFNAMSIZ];
	char mac_str[64];
	qcsapi_mac_addr mac;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		qtn_error("can't get ifname");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_MAC, mac_str, sizeof(mac_str)) <= 0) {
		qtn_error("can't get mac");
		goto respond;
	}

	if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
		qtn_error("can't parse mac_str %s", mac_str);
		goto respond;
	}

	qtn_log("try to set mac on %s to %s", ifname, mac_str);

	if ((ret = qcsapi_interface_set_mac_addr(ifname, mac)) < 0) {
		qtn_error("can't set mac to %s, error %d", mac_str, ret);
	}

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_uapsd(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret = 0;
	char ifname[IFNAMSIZ];
	char cmd[128];
	int maxsplength;
	int acbe;
	int acbk;
	int acvi;
	int acvo;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		qtn_error("can't get ifname");
		goto respond;
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

	uint8_t uapsdinfo = WME_CAPINFO_UAPSD_EN;
	if (acbe) {
		uapsdinfo |= WME_CAPINFO_UAPSD_BE;
	}

	if (acbk) {
		uapsdinfo |= WME_CAPINFO_UAPSD_BK;
	}

	if (acvi) {
		uapsdinfo |= WME_CAPINFO_UAPSD_VI;
	}

	if (acvo) {
		uapsdinfo |= WME_CAPINFO_UAPSD_VO;
	}

	uapsdinfo |= (maxsplength & WME_CAPINFO_UAPSD_MAXSP_MASK) << WME_CAPINFO_UAPSD_MAXSP_SHIFT;

	snprintf(cmd, sizeof(cmd), "iwpriv %s setparam %d %d",
			ifname, IEEE80211_PARAM_UAPSDINFO, uapsdinfo);
	ret = system(cmd);

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_reset_parm(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret = 0;
	char ifname[IFNAMSIZ];
	char arp[64];
	char cmd[128];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		qtn_error("can't get ifname");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_ARP, arp, sizeof(arp)) <= 0) {
		qtn_error("can't get arp");
		goto respond;
	}

	if (strcasecmp(arp, "all") == 0) {
		snprintf(cmd, sizeof(cmd), "for ip in `grep %s /proc/net/arp | awk '{print $1}'`; "
				"do arp -i %s -d $ip; done", ifname, ifname);
	} else {
		snprintf(cmd, sizeof(cmd), "arp -i %s -d %s", ifname, arp);
	}

	ret = system(cmd);
	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_11n(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret = 0;
	char ifname[IFNAMSIZ];
	char width_str[128];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		qtn_error("can't get ifname");
		goto respond;
	}

	status = STATUS_ERROR;

	if (qtn_get_value_text(&cmd_req, QTN_TOK_WIDTH, width_str, sizeof(width_str)) > 0) {
		qcsapi_unsigned_int bw;
		if (strcasecmp(width_str, "auto") == 0) {
			bw = 40;
		} else {
			sscanf(width_str, "%u", &bw);
		}

		if ((ret = qcsapi_wifi_set_bw(ifname, bw)) < 0) {
			qtn_error("can't set bw to %d, error %d", bw, ret);
			goto respond;
		}
	}

	int tx_ss;
	int rx_ss;

	if (qtn_get_value_int(&cmd_req, QTN_TOK_TXSP_STREAM, &tx_ss) <= 0)
		tx_ss = -1;

	if (qtn_get_value_int(&cmd_req, QTN_TOK_RXSP_STREAM, &rx_ss) <= 0)
		rx_ss = -1;

	if (tx_ss == rx_ss && tx_ss > 0) {
		/* sta_set_11n is used only for 11n, so hardcode qcsapi_mimo_ht */
		ret = qcsapi_wifi_set_nss_cap(ifname, qcsapi_mimo_ht, tx_ss);
		if (ret < 0) {
			qtn_error("can't set tx NSS to %d, error %d", tx_ss, ret);
		}
		ret = qcsapi_wifi_set_rx_nss_cap(ifname, qcsapi_mimo_ht, rx_ss);
		if (ret < 0) {
			qtn_error("can't set rx NSS to %d, error %d", rx_ss, ret);
		}
	} else if (tx_ss != rx_ss) {
		qtn_error("can't handle number of SS separatly for RX and TX");
		ret = -EINVAL;
	}

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_power_save(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret;
	char ifname[IFNAMSIZ];
	char val_str[128];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0)
		goto respond;

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		qtn_error("can't get ifname");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_POWERSAVE, val_str, sizeof(val_str)) > 0) {
		if (strcasecmp(val_str, "off") == 0) {
			// power save does not exist by default
			ret = 0;
		} else {
			qtn_error("can't set power save to %s since poser save is not supported",
				val_str);
			ret = -EOPNOTSUPP;
			goto respond;
		}
	}

respond:
	status = ret < 0 ? STATUS_ERROR : STATUS_COMPLETE;
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_sleep(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_COMPLETE;
	int ret;
	char ifname[IFNAMSIZ];
	char cmd[128];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());
	}

	snprintf(cmd, sizeof(cmd), "iwpriv %s sleep 0", ifname);
	ret = system(cmd);
	if (ret != 0) {
		qtn_error("can't set sleep, error %d", ret);
		goto respond;
	}

respond:
	status = ret < 0 ? STATUS_ERROR : STATUS_COMPLETE;
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_security(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret;
	char ifname[IFNAMSIZ];
	char ssid_str[64] = {0};
	char type_str[64] = {0};
	char pass_str[128] = {0};
	char keymgmt_type[64] = {0};
	char enc_type[64] = {0};
	char ecc_grps[64] = {0};
	struct qcsapi_set_parameters set_params;
	int defer = 0;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0)
		goto respond;

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0)
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());

	if (qtn_get_value_text(&cmd_req, QTN_TOK_SSID, ssid_str, sizeof(ssid_str)) <= 0) {
		qtn_error("can't get ssid");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_TYPE, type_str, sizeof(type_str)) <= 0) {
		qtn_error("can't get type");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_KEYMGMTTYPE, keymgmt_type,
				sizeof(keymgmt_type)) <= 0)
		qtn_log("no keymgmt_type");

	if (qtn_get_value_text(&cmd_req, QTN_TOK_ENCPTYPE, enc_type, sizeof(enc_type)) <= 0)
		qtn_error("no enc_type");

	if (qtn_get_value_text(&cmd_req, QTN_TOK_PASSPHRASE, pass_str, sizeof(pass_str)) <= 0)
		qtn_error("no pass_phrase");

	if (qtn_get_value_text(&cmd_req, QTN_TOK_ECGROUPID, ecc_grps, sizeof(ecc_grps)) <= 0)
		qtn_log("no ecc group");

	status = STATUS_ERROR;

	ret = qcsapi_wifi_set_security_defer_mode(ifname, 1);
	if (ret < 0) {
		qtn_error("can't set security defer mode, error %d", ret);
		goto respond;
	}
	defer = 1;

	if (qcsapi_SSID_verify_SSID(ifname, ssid_str) < 0) {
		ret = qcsapi_SSID_create_SSID(ifname, ssid_str);
		if (ret < 0) {
			qtn_error("can't create SSID %s, error %d", ssid_str, ret);
			goto respond;
		}
	}

	if (strcmp(pass_str, "") != 0) {
		ret = qcsapi_SSID_set_key_passphrase(ifname, ssid_str, 0, pass_str);
		if (ret < 0) {
			qtn_error("can't set passphrase: ifname %s, passphrase %s, error %d",
					ifname, pass_str, ret);
		}
	}

	if (strcmp(enc_type, "") != 0) {
		ret = set_sta_encryption(ifname, ssid_str, enc_type);
		if (ret < 0) {
			qtn_error("can't set enc to %s, error %d", enc_type, ret);
			goto respond;
		}
	}

	ret = set_sta_protocol(ifname, ssid_str, keymgmt_type);
	if (ret < 0) {
		qtn_error("can't set protocol for ssid %s, error %d", ssid_str, ret);
		goto respond;
	}

	if ((strcmp(ecc_grps, "") != 0) &&
			((strcasecmp(type_str, "owe") == 0) ||
			 (strcasecmp(type_str, "sae") == 0))) {
		int i;

		memset(&set_params, 0, sizeof(set_params));

		if (strcasecmp(type_str, "sae") == 0)
			strncpy(set_params.param[0].key, "sae_groups",
						sizeof(set_params.param[0].key) - 1);
		else if (strcasecmp(type_str, "owe") == 0)
			strncpy(set_params.param[0].key, "owe_group",
						sizeof(set_params.param[0].key) - 1);

		strncpy(set_params.param[0].value, ecc_grps,
					sizeof(set_params.param[0].value) - 1);
		for (i = 0; i < sizeof(set_params.param[0].value); i++) {
			if (set_params.param[0].value[i] == ' ')
				set_params.param[0].value[i] = ',';
		}

		ret = qcsapi_set_params(ifname, ssid_str, &set_params);
		if (ret < 0) {
			qtn_error("can't set ecc groups %s for keymgmt %s", ecc_grps, type_str);
			goto respond;
		}
	}

	if (strcasecmp(type_str, "owe") == 0) {
		memset(&set_params, 0, sizeof(set_params));

		strncpy(set_params.param[0].key, "auth_alg", sizeof(set_params.param[0].key) - 1);
		strncpy(set_params.param[0].value, "OPEN", sizeof(set_params.param[0].value) - 1);

		ret = qcsapi_set_params(ifname, ssid_str, &set_params);
		if (ret < 0) {
			qtn_error("can't set auth_alg for owe, ret %d", ret);
			goto respond;
		}
	}

	if ((strcasecmp(type_str, "sae") == 0) || (strcasecmp(type_str, "owe") == 0)) {
		qtn_log("forcing pmf as required");
		ret = qcsapi_SSID_set_pmf(ifname, ssid_str, qcsapi_pmf_required);
		if (ret < 0) {
			qtn_error("can't set pmf, error %d, ssid %s", ret, ssid_str);
			goto respond;
		}
	}

	ret = qcsapi_wifi_set_security_defer_mode(ifname, 0);
	if (ret < 0) {
		qtn_error("can't set security defer mode, error %d", ret);
		goto respond;
	}
	defer = 0;

	ret = set_sta_keymgmt(ifname, ssid_str, type_str);
	if (ret < 0) {
		qtn_error("can't set keymgmt to %s, error %d", type_str, ret);
		goto respond;
	}

	status = STATUS_COMPLETE;
respond:
	if (defer && qcsapi_wifi_set_security_defer_mode(ifname, 0) < 0)
		qtn_error("can't disable security defer mode");

	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}


void qtn_handle_sta_scan(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret = 0;
	char ifname[IFNAMSIZ];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0)
		goto respond;

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0)
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());

	status = STATUS_ERROR;

	ret = qcsapi_wifi_start_scan(ifname);
	if (ret < 0) {
		qtn_error("can't scan, error %d", ret);
		goto respond;
	}

	status = STATUS_COMPLETE;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);

}


void qtn_handle_device_get_info(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int ret;
	char info_buf[128] = {0};
	char firmware_version[128] = {0};
	string_64 hw_version;
	static const char vendor[] = "Quantenna";

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	ret = qcsapi_firmware_get_version(firmware_version, sizeof(firmware_version));
	if (ret < 0) {
		qtn_error("can't get fw version, error %d", ret);
		status = STATUS_ERROR;
		goto respond;
	}

	ret = qcsapi_get_board_parameter(qcsapi_hw_id, hw_version);
	if (ret < 0) {
		qtn_error("can't get HW id, error %d", ret);
		status = STATUS_ERROR;
		goto respond;
	}

	ret = snprintf(info_buf, sizeof(info_buf),
			"vendor,%s,model,%s,version,%s", vendor, hw_version, firmware_version);
	if (ret < 0) {
		status = STATUS_ERROR;
		goto respond;
	}

	status = STATUS_COMPLETE;

respond:
	qtn_dut_make_response_vendor_info(cmd_tag, status, ret, info_buf, out_len, out);
}

void qtn_handle_dev_exec_action(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret = 0;
	char ifname[IFNAMSIZ];
	char program[16] = {0};
	int resp_len = 0;
	char *resp = NULL;

	qtn_log("%s", __func__);
	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0)
		goto respond;

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0)
		snprintf(ifname, sizeof(ifname), "%s", qtn_get_sigma_interface());

	ret = qtn_get_value_text(&cmd_req, QTN_TOK_PROGRAM, program, sizeof(program));
	if (ret <= 0) {
		/* mandatory parameter */
		qtn_error("can't get program");
		status = STATUS_ERROR;
		goto respond;
	}

	resp = (char *)calloc(1, sizeof(char) * QTN_MAX_BUF_LEN);
	if (!resp) {
		qtn_error("can't alloc resp string");
		status = STATUS_ERROR;
		goto respond;
	}

	if (strcasecmp(program, "DPP") == 0) {
		ret = qtn_handle_dpp_dev_action(&cmd_req, ifname, resp, &resp_len);
		if (ret) {
			/* mandatory parameter */
			qtn_error("failed to execute DPP dev action");
			status = STATUS_ERROR;
			goto respond;
		}
		status = STATUS_COMPLETE;
	} else {
		qtn_error("dev_exec_action: no other program except DPP supported");
		status = STATUS_INVALID;
	}

respond:
	if (resp_len)
		qtn_dut_make_response_str(cmd_tag, status, ret, resp, resp_len, out_len, out);
	else
		qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);

	if (resp)
		free(resp);
}

static int system_cmd(const char *cli, char *cli_sfx, char *resp, int resp_len)
{
	FILE *fp;
	char buf[QTN_MAP_MAX_BUF], cmd[4*QTN_MAX_CMD_BUF+128];

	sprintf(cmd, "%s %s", cli, cli_sfx);
	qtn_log("%s %s", __func__, cmd);

	resp[0] = 0;
	fp = popen(cmd, "r");
	if (fp) {
		while (fgets(buf, QTN_MAP_MAX_BUF, fp) != NULL) {
			if (strlen(resp) + strlen(buf) > resp_len)
				break;
			strcat(resp, buf);
		}
		pclose(fp);
		fp = NULL;
	} else {
		qtn_error("fail to execute %s command, popen error", cmd);
		return -EINVAL;
	}
	return 0;
}

void qtn_handle_dev_reset_default(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_COMPLETE;
	char cert_prog[16], dev_role[16], conf_type[16];
	char cmd[512];
	int ret = 0;

	qtn_log("%s", __func__);
	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0)
		goto respond;

	qtn_bring_up_radio_if_needed();

	/* mandatory certification program, e.g. MAP */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_PROGRAM, cert_prog, sizeof(cert_prog)) <= 0) {
		ret = -EINVAL;
		goto respond;
	}
	if (qtn_get_value_text(&cmd_req, QTN_TOK_DEV_ROLE, dev_role, sizeof(dev_role)) <= 0) {
		ret = -EINVAL;
		goto respond;
	}
	/* configuration type, e.g. DUT or Testbed */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_TYPE, conf_type, sizeof(conf_type)) <= 0) {
		/* not specified */
		*conf_type = 0;
	}

	ret = qtn_defconf_easymesh("wifi0");
	if (ret < 0) {
		qtn_error("error: default configuration, errcode %d", ret);
		goto respond;
	}

	/* reset default configuration for rlt2.4 */
	if (access(QTN_EXTRTL_CONFIG, X_OK) == 0
		&& access(QTN_EXTRTL_ACTION, X_OK) == 0) {
		snprintf(cmd, sizeof(cmd), "%s default", QTN_EXTRTL_CONFIG);
		ret = system(cmd);
		if (!ret) {
			snprintf(cmd, sizeof(cmd), "%s set channel.wlan1 %d",
				QTN_EXTRTL_CONFIG, DEFAULT_MAP_HT_CHANNEL);
			system(cmd);

			snprintf(cmd, sizeof(cmd), "%s set ssid.wlan1 MAP-2G",
				QTN_EXTRTL_CONFIG);
			system(cmd);

			snprintf(cmd, sizeof(cmd), "%s wlan1 commit", QTN_EXTRTL_ACTION);
			system(cmd);
		}
	}

	if (strcasecmp(dev_role, "agent") == 0) {
		if (qtn_dut_npu_cfg.npu_topology)
			snprintf(cmd, sizeof(cmd), "%s%s "
				"\'sh -c \"start_mapagent_npu restart >/dev/null 2>&1\" &\'",
				qtn_dut_npu_cfg.ssh_cli, qtn_dut_npu_cfg.br_ipaddr);
		else
			snprintf(cmd, sizeof(cmd), "/scripts/start_mapagent restart");

		ret = system(cmd);
		if (ret < 0) {
			qtn_error("start map agent failed, errcode %d", ret);
			goto respond;
		}
	} else if (strcasecmp(dev_role, "controller") == 0) {
		if (qtn_dut_npu_cfg.npu_topology)
			snprintf(cmd, sizeof(cmd), "%s%s "
				"\'sh -c \"start_mapcontroller_npu restart >/dev/null 2>&1\" &\'",
				qtn_dut_npu_cfg.ssh_cli, qtn_dut_npu_cfg.br_ipaddr);
		else
			snprintf(cmd, sizeof(cmd), "/scripts/start_mapcontroller restart");

		ret = system(cmd);
		if (ret < 0) {
			qtn_error("start map controller failed, errcode %d", ret);
			goto respond;
		}
	}
	qtn_log("%s", cmd);

respond:
	status = ret < 0 ? STATUS_ERROR : STATUS_COMPLETE;
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

static int qtn_get_macaddr_by_params(char *param, char *ssid,
	unsigned char *macaddr, int is_24g)
{
	int i, ret = -1;
	int max_bsses = 0;
	char macstr[18];
	qcsapi_SSID curr_SSID;
	char ifname[IFNAMSIZ] = "wifi0";
	char cli[128] = "get ssid.wlan1";

	if (is_24g) {
		for (i = 0; i < 5; i++) {
			if (i > 0)
				sprintf(cli, "get ssid.vap%d.wlan1", i - 1);
			ret = system_cmd(QTN_EXTRTL_CONFIG, cli, curr_SSID, sizeof(curr_SSID));
			if (ret == 0 && !strncmp(curr_SSID, ssid, strlen(curr_SSID))) {
				strcpy(cli, "/sys/class/net/wlan0/address");
				if (i > 0)
					sprintf(cli, "/sys/class/net/wlan0-va%d/address",
							i - 1);
				ret = system_cmd("/bin/cat", cli,
						macstr, sizeof(macstr));
				if (ether_aton_r(macstr, (struct ether_addr *)macaddr) == NULL)
					ret = -EINVAL;
				break;
			}
		}
	} else {
		if (qcsapi_wifi_verify_repeater_mode() == 1)
			strcpy(ifname, "wifi1");
		qcsapi_wifi_get_parameter(ifname, qcsapi_wifi_param_max_bss_num, &max_bsses);

		for (i = (max_bsses == 7 ? 1 : 0); i < max_bsses; i++) {
			sprintf(ifname, "wifi%u", i);
			ret = qcsapi_wifi_get_SSID(ifname, curr_SSID);
			if (ret == 0 && !strncmp(curr_SSID, ssid, strlen(curr_SSID))) {
				if (strcasecmp(param, "macaddr") == 0)
					ret = qcsapi_interface_get_mac_addr(ifname, macaddr);
				else
					ret = qcsapi_wifi_get_BSSID(ifname, macaddr);
				break;
			}
		}
	}

	return ret;
}

void qtn_handle_dev_get_parameter(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_COMPLETE;
	int ret = 0;
	char cert_prog[16];
	char param_str[16];
	char ssid_str[33];
	char ruid[16];
	char ifname[IFNAMSIZ] = "wifi0";
	unsigned char macaddr[IEEE80211_ADDR_LEN] = {0x00, 0x22, 0x33, 0x44, 0x55, 0x66};

	qtn_log("%s", __func__);
	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0)
		goto respond;

	/* mandatory certification program, e.g. MAP */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_PROGRAM, cert_prog, sizeof(cert_prog)) <= 0) {
		ret = -EINVAL;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_PARAMETER, param_str, sizeof(param_str)) <= 0) {
		ret = -EINVAL;
		goto respond;
	}

	if (strcasecmp(param_str, "ALid") == 0) {
		if (qtn_dut_npu_cfg.npu_topology)
			memcpy(macaddr, qtn_dut_npu_cfg.al_macaddr, ETH_ALEN);
		else
			ret = qcsapi_interface_get_mac_addr("br0", macaddr);
		goto respond;
	} else if ((strcasecmp(param_str, "macaddr") == 0) || strcasecmp(param_str, "bssid") == 0) {
		if (qtn_get_value_text(&cmd_req, QTN_TOK_RUID, ruid, sizeof(ruid)) > 0) {
			if (qtn_get_value_text(&cmd_req, QTN_TOK_SSID, ssid_str,
					sizeof(ssid_str)) <= 0) {
				ret = qcsapi_interface_get_mac_addr(ifname, macaddr);
				goto respond;
			}
			if (strncasecmp(ruid, "0x002686", 8) == 0)
				ret = qtn_get_macaddr_by_params(param_str, ssid_str, macaddr, 0);
			else if (strncasecmp(ruid, "0x5cf370", 8) == 0)
				ret = qtn_get_macaddr_by_params(param_str, ssid_str, macaddr, 1);
		} else {
			ret = -EINVAL;
			qtn_error("cannot get ruid and ssid string, error %d", ret);
			goto respond;
		}
	} else {
		ret = -EINVAL;
		qtn_error("cannot get parameter string, error %d", ret);
		goto respond;
	}

respond:
	status = ret < 0 ? STATUS_ERROR : STATUS_COMPLETE;
	qtn_dut_make_response_macaddr(cmd_tag, status, ret, macaddr, out_len, out);
}

void qtn_handle_dev_set_config(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
#define MAX_SUPP_BSS_INFO	12
	struct qtn_cmd_request cmd_req;
	int status = STATUS_COMPLETE;
	int i = MAX_SUPP_BSS_INFO, ind = 0, ret = 0;
	char cert_prog[16], backhaul[16];
	char bss_info[128];
	char resp[256];

	qtn_log("%s", __func__);
	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0)
		goto respond;

	/* mandatory certification program, e.g. MAP */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_PROGRAM, cert_prog, sizeof(cert_prog)) <= 0) {
		ret = -EINVAL;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_BACKHAUL, backhaul, sizeof(backhaul)) > 0) {
		if (strcasecmp(backhaul, "eth") == 0) {
			/* trigger eth onboarding */
			snprintf(g_cmdbuf, sizeof(g_cmdbuf),
				"ubus call map.cli test \'{\"subcmd\":\"reconfig\"}\'");
			if (qtn_dut_npu_cfg.npu_topology) {
				snprintf(g_cmdbuf, sizeof(g_cmdbuf), "%s%s ubus "
					"call map.cli test "
					"\\\'{\\\"subcmd\\\":\\\"reconfig\\\"}\\\'",
					qtn_dut_npu_cfg.ssh_cli, qtn_dut_npu_cfg.br_ipaddr);
			}
			ret = system(g_cmdbuf);
			if (ret != 0)
				goto respond;
			/* time to wait for a device to authenticate and auto-configure */
			sleep(60);
		} else if (strncasecmp(backhaul, "0x", 2) == 0) {
			if (qcsapi_wifi_verify_repeater_mode() != 1) {
				ret = -EINVAL;
				qtn_error("only support set backhaul on repeter, error %d", ret);
				goto respond;
			}
			ret = qcsapi_wifi_set_parameter("wifi0",
					qcsapi_wifi_param_multiap_backhaul_sta, 1);
			if (ret < 0) {
				qtn_error("set backhaul sta failed, error %d", ret);
				goto respond;
			}
		}
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_BSS_INFO1, bss_info, sizeof(bss_info)) > 0) {
		if (qtn_dut_npu_cfg.npu_topology) {
			snprintf(g_cmdbuf, sizeof(g_cmdbuf), "%s%s ubus ",
				qtn_dut_npu_cfg.ssh_cli, qtn_dut_npu_cfg.br_ipaddr);
			strcat(g_cmdbuf, "call map.cli set_conf \\\'{\\\"wsc_bssinfos\\\":[");
			do {
				enum qtn_token token =
					(enum qtn_token)((int)QTN_TOK_BSS_INFO12 - i + 1);

				if (qtn_get_value_text(&cmd_req, token, bss_info,
					sizeof(bss_info)) > 0) {
					char *bssinfo_saveptr;
					char *bssinfo_ptr = strtok_r(bss_info, " ",
						&bssinfo_saveptr);

					strcat(g_cmdbuf, "{");
					for (ind = 0; bssinfo_ptr != NULL; bssinfo_ptr =
						strtok_r(NULL, " ", &bssinfo_saveptr), ind++) {
						char s[128] = {0,};

						switch (ind) {
						case 0:
							sprintf(s, "\\\"al_mac\\\":"
								"\\\"%s\\\",", bssinfo_ptr);
							break;
						case 1:
							sprintf(s, "\\\"opclass\\\":"
								"\\\"%s\\\",", bssinfo_ptr);
							break;
						case 2:
							sprintf(s, "\\\"ssid\\\":"
								"\\\"%s\\\",", bssinfo_ptr);
							break;
						case 3:
							sprintf(s, "\\\"auth_mode\\\":"
								"\\\"wpa2psk\\\",");
							break;
						case 4:
							sprintf(s, "\\\"encr_mode\\\":"
								"\\\"aes\\\",");
							break;
						case 5:
							sprintf(s, "\\\"key\\\":"
								"\\\"%s\\\",", bssinfo_ptr);
							break;
						case 6:
							sprintf(s, "\\\"backhaul\\\":%s,",
								bssinfo_ptr);
							break;
						case 7:
							sprintf(s, "\\\"fronthaul\\\":%s",
								bssinfo_ptr);
							break;
						default:
							break;
						}
						strcat(g_cmdbuf, s);
					}
					strcat(g_cmdbuf, "},");
				}
			} while (i--);
			strcat(g_cmdbuf, "]}\\\'");
			ret = system(g_cmdbuf);
		} else {
			strcpy(g_cmdbuf, "call map.cli set_conf \'{\"wsc_bssinfos\":[");
			do {
				enum qtn_token token =
					(enum qtn_token)((int)QTN_TOK_BSS_INFO12 - i + 1);

				if (qtn_get_value_text(&cmd_req, token,
					bss_info, sizeof(bss_info)) > 0) {
					char *bssinfo_saveptr;
					char *bssinfo_ptr = strtok_r(bss_info, " ",
						&bssinfo_saveptr);

					strcat(g_cmdbuf, "{");
					for (ind = 0; bssinfo_ptr != NULL; bssinfo_ptr =
						strtok_r(NULL, " ", &bssinfo_saveptr), ind++) {
						char s[128] = {0,};

						switch (ind) {
						case 0:
							sprintf(s, "\"al_mac\":\"%s\",",
								bssinfo_ptr);
							break;
						case 1:
							sprintf(s, "\"opclass\":\"%s\",",
								bssinfo_ptr);
							break;
						case 2:
							sprintf(s, "\"ssid\":\"%s\",",
								bssinfo_ptr);
							break;
						case 3:
							sprintf(s, "\"auth_mode\":"
								"\"wpa2psk\",");
							break;
						case 4:
							sprintf(s, "\"encr_mode\":\"aes\",");
							break;
						case 5:
							sprintf(s, "\"key\":\"%s\",",
								bssinfo_ptr);
							break;
						case 6:
							sprintf(s, "\"backhaul\":%s,",
								bssinfo_ptr);
							break;
						case 7:
							sprintf(s, "\"fronthaul\":%s",
								bssinfo_ptr);
							break;
						default:
							break;
						}
						strcat(g_cmdbuf, s);
					}
					strcat(g_cmdbuf, "},");
				}
			} while (i--);
			strcat(g_cmdbuf, "]}\'");
			ret = system_cmd(QTN_UBUS_TEST_CLI, g_cmdbuf, resp, sizeof(resp));
		}
	}
	qtn_log("%s", g_cmdbuf);

respond:
	status = ret < 0 ? STATUS_ERROR : STATUS_COMPLETE;
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void remsubstr(char *string, char *sub)
{
	char *match;
	int len = strlen(sub);

	while ((match = strstr(string, sub))) {
		*match = '\0';
		strcat(string, match+len);
	}
}

void insertsubstr(char *string, char *sub, int pos)
{
	int sublen = strlen(sub);
	char *product = (char *)malloc(strlen(string) + sublen + 1);

	strncpy(product, string, pos);
	product[pos] = '\0';
	strcat(product, sub);
	strcat(product, string + pos);

	strcpy(string, product);
	free(product);
}

/* must have enough space in str */
void qtn_rebuid_tlv_value(char *str)
{
	int i, count;

	remsubstr(str, "{");
	remsubstr(str, ":");
	remsubstr(str, " ");
	remsubstr(str, "0x");
	remsubstr(str, "}");

	count = strlen(str) / 2;
	for (i = 1; i < count; i++)
		insertsubstr(str, " ", 3 * i - 1);
}

static int get_mid_field_value(char *in, char *field, char *out)
{
	char *rc, *pos;
	char mid_str[32] = {0,};
	uint16_t mid;

	if (!in || !field)
		return -1;

	rc = strstr(in, "\"rc\"");
	pos = strstr(in, field);

	rc = rc + strlen("\"rc\"");
	if (strncmp(rc, ": \"Successed\"", 13))
		return -1;

	pos = pos + strlen(field);
	remsubstr(pos, " ");
	remsubstr(pos, "}");
	mid = strtoul(pos, NULL, 10);
	qtn_log("get mid %u", mid);
	sprintf(mid_str, "%0x", mid);
	insertsubstr(mid_str, "0x", 0);
	strncpy(out, mid_str, strlen(mid_str));

	return 0;
}

void qtn_handle_dev_send_1905(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
#define MAX_SUPP_TLV_NUM	5
	struct qtn_cmd_request cmd_req;
	int status = STATUS_COMPLETE;
	int i = MAX_SUPP_TLV_NUM, ret = 0;
	char dest_alid[18], msg_type[8];
	char tlv_type[6], tlv_length[8], tlv_value[QTN_MAP_MAX_BUF+1024];
	char ssh_cmd[64], cli[QTN_MAP_MAX_BUF+1024];
	char mid[32], resp[256];

	qtn_log("%s", __func__);
	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0)
		goto respond;

	if (qtn_dut_npu_cfg.npu_topology)
		snprintf(ssh_cmd, sizeof(ssh_cmd), "%s%s ubus",
			qtn_dut_npu_cfg.ssh_cli, qtn_dut_npu_cfg.br_ipaddr);

	if (qtn_get_value_text(&cmd_req, QTN_TOK_DEST_ALID, dest_alid, sizeof(dest_alid)) > 0) {
		if (qtn_get_value_text(&cmd_req, QTN_TOK_MESSAGE_TYPE_VALUE,
			msg_type, sizeof(msg_type)) <= 0) {
			ret = -EINVAL;
			goto respond;
		}
		if (qtn_get_value_text(&cmd_req, QTN_TOK_TLV_TYPE,
				tlv_type, sizeof(tlv_type)) > 0) {
			if (qtn_get_value_text(&cmd_req, QTN_TOK_TLV_LENGTH,
				tlv_length, sizeof(tlv_length)) <= 0) {
				ret = -EINVAL;
				goto respond;
			}
			if (qtn_get_value_text(&cmd_req, QTN_TOK_TLV_VALUE,
				tlv_value, sizeof(tlv_value)) <= 0) {
				ret = -EINVAL;
				goto respond;
			}
			qtn_rebuid_tlv_value(tlv_value);
			if (qtn_dut_npu_cfg.npu_topology) {
				snprintf(cli, sizeof(cli),
					"call map.cli send_1905 \\\'{\\\"DestALid\\\":\\\"%s\\\","
					"\\\"MessageTypeValue\\\":%lu,"
					"\\\"TLVs\\\":[{\\\"tlv_type\\\":%lu,\\\"tlv_length\\\":"
					"%lu,\\\"tlv_value\\\":\\\"%s\\\"},]}\\\'",
					dest_alid, strtoul(msg_type, NULL, 0),
					strtoul(tlv_type, NULL, 0), strtoul(tlv_length, NULL, 0),
					tlv_value);
				ret = system_cmd(ssh_cmd, cli, resp, sizeof(resp));
			} else {
				sprintf(cli, "call map.cli send_1905 \'{\"DestALid\":\"%s\","
					"\"MessageTypeValue\":%lu,\"TLVs\":[{\"tlv_type\":%lu,"
					"\"tlv_length\":%lu,\"tlv_value\":\"%s\"},]}\'",
					dest_alid, strtoul(msg_type, NULL, 0),
					strtoul(tlv_type, NULL, 0),
					strtoul(tlv_length, NULL, 0), tlv_value);
				ret = system_cmd(QTN_UBUS_TEST_CLI, cli, resp, sizeof(resp));
			}
		} else if (qtn_get_value_text(&cmd_req, QTN_TOK_TLV_TYPE1,
				tlv_type, sizeof(tlv_type)) > 0) {
			if (qtn_dut_npu_cfg.npu_topology) {
				snprintf(cli, sizeof(cli),
					"call map.cli send_1905 \\\'{\\\"DestALid\\\":\\\"%s\\\","
					"\\\"MessageTypeValue\\\":%lu,",
					dest_alid, strtoul(msg_type, NULL, 0));
				strcat(cli, "\\\"TLVs\\\":[");
				do {
					enum qtn_token type_tok =
						(enum qtn_token)((int)QTN_TOK_TLV_TYPE5 - i + 1);
					enum qtn_token length_tok =
						(enum qtn_token)((int)QTN_TOK_TLV_LENGTH5 - i + 1);
					enum qtn_token value_tok =
						(enum qtn_token)((int)QTN_TOK_TLV_VALUE5 - i + 1);
					char s[1024] = {0,};

					if (qtn_get_value_text(&cmd_req, type_tok,
						tlv_type, sizeof(tlv_type)) > 0) {
						strcat(cli, "{");
						if (qtn_get_value_text(&cmd_req, length_tok,
							tlv_length, sizeof(tlv_length)) <= 0) {
							ret = -EINVAL;
							goto respond;
						}
						if (qtn_get_value_text(&cmd_req, value_tok,
							tlv_value, sizeof(tlv_value)) <= 0) {
							ret = -EINVAL;
							goto respond;
						}
						qtn_rebuid_tlv_value(tlv_value);
						sprintf(s, "\\\"tlv_type\\\":%lu,"
							"\\\"tlv_length\\\":"
							"%lu,\\\"tlv_value\\\":\\\"%s\\\"},",
							strtoul(tlv_type, NULL, 0),
							strtoul(tlv_length, NULL, 0), tlv_value);
						strcat(cli, s);
					}
				} while (i--);
				strcat(cli, "]}\\\'");
				ret = system_cmd(ssh_cmd, cli, resp, sizeof(resp));
			} else {
				sprintf(cli, "call map.cli send_1905 \'{\"DestALid\":\"%s\","
					"\"MessageTypeValue\":%lu,",
					dest_alid, strtoul(msg_type, NULL, 0));
				strcat(cli, "\"TLVs\":[");
				do {
					enum qtn_token type_tok =
						(enum qtn_token)((int)QTN_TOK_TLV_TYPE5 - i + 1);
					enum qtn_token length_tok =
						(enum qtn_token)((int)QTN_TOK_TLV_LENGTH5 - i + 1);
					enum qtn_token value_tok =
						(enum qtn_token)((int)QTN_TOK_TLV_VALUE5 - i + 1);
					char s[1024] = {0,};

					if (qtn_get_value_text(&cmd_req, type_tok,
						tlv_type, sizeof(tlv_type)) > 0) {
						strcat(cli, "{");
						if (qtn_get_value_text(&cmd_req, length_tok,
							tlv_length, sizeof(tlv_length)) <= 0) {
							ret = -EINVAL;
							goto respond;
						}
						if (qtn_get_value_text(&cmd_req, value_tok,
							tlv_value, sizeof(tlv_value)) <= 0) {
							ret = -EINVAL;
							goto respond;
						}
						qtn_rebuid_tlv_value(tlv_value);
						sprintf(s, "\"tlv_type\":%lu,\"tlv_length\":%lu,"
							"\"tlv_value\":\"%s\"},",
							strtoul(tlv_type, NULL, 0),
							strtoul(tlv_length, NULL, 0), tlv_value);
						strcat(cli, s);
					}
				} while (i--);
				strcat(cli, "]}\'");
				ret = system_cmd(QTN_UBUS_TEST_CLI, cli, resp, sizeof(resp));
			}
		} else {
			if (qtn_dut_npu_cfg.npu_topology) {
				snprintf(cli, sizeof(cli),
				"call map.cli send_1905 \\\'{\\\"DestALid\\\":\\\"%s\\\","
				"\\\"MessageTypeValue\\\":%lu}\\\'",
				dest_alid, strtoul(msg_type, NULL, 0));
				ret = system_cmd(ssh_cmd, cli, resp, sizeof(resp));
			} else {
				sprintf(cli, "call map.cli send_1905 \'{\"DestALid\":\"%s\","
					"\"MessageTypeValue\":%lu}\'",
					dest_alid, strtoul(msg_type, NULL, 0));
				ret = system_cmd(QTN_UBUS_TEST_CLI, cli, resp, sizeof(resp));
			}
		}
		ret = get_mid_field_value(resp, "\"mid\":", mid);
	} else {
		ret = -EINVAL;
	}

respond:
	status = ret < 0 ? STATUS_ERROR : STATUS_COMPLETE;
	qtn_dut_make_response_mid(cmd_tag, status, ret, mid, out_len, out);
}

void qtn_handle_start_wps_registration(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	char ifname[IFNAMSIZ], band_str[16], wps_role[16], wps_method[16], cli[128];
	unsigned char bssid[IEEE80211_ADDR_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	unsigned char mac[IEEE80211_ADDR_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	int repeater = 0, ret = 0, status = STATUS_COMPLETE;

	qtn_log("%s", __func__);
	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0)
		goto respond;

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) > 0) {
		if (qtn_get_value_text(&cmd_req, QTN_TOK_WPS_ROLE,
			wps_role, sizeof(wps_role)) <= 0) {
			ret = -EINVAL;
			goto respond;
		}
		/* empty for now */
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_BAND, band_str, sizeof(band_str)) > 0) {
		if (qtn_get_value_text(&cmd_req, QTN_TOK_WPS_CONFIG_METHOD,
			wps_method, sizeof(wps_method)) <= 0) {
			ret = -EINVAL;
			goto respond;
		}

		if ((strncasecmp(band_str, "5GL", 3) == 0)
			|| (strncasecmp(band_str, "5GH", 3) == 0)) {
			strncpy(ifname, "wifi0", sizeof(ifname));
			repeater = qcsapi_wifi_verify_repeater_mode();
			if (repeater) {
				ret = qcsapi_wifi_get_BSSID("wifi0", bssid);
				if (!ret && memcmp(mac, bssid, IEEE80211_ADDR_LEN))
					strncpy(ifname, "wifi1", IFNAMSIZ - 1);
			}

			if (qtn_dut_npu_cfg.npu_topology) {
				snprintf(cli, sizeof(cli), "%s%s ubus "
					"call map.cli start_wps \\\'{\\\"ifname\\\":"
					"\\\"%s\\\"}\\\'",
					qtn_dut_npu_cfg.ssh_cli, qtn_dut_npu_cfg.br_ipaddr, ifname);
			} else {
				snprintf(cli, sizeof(cli),
					"ubus call map.cli start_wps \'{\"ifname\":"
					"\"%s\"}\'", ifname);
			}
			qtn_log("%s", cli);
			ret = system(cli);
		} else if (strncasecmp(band_str, "24G", 3) == 0) {
			ret = -EINVAL;
			goto respond;
		}
	}

respond:
	status = ret < 0 ? STATUS_ERROR : STATUS_COMPLETE;
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}
