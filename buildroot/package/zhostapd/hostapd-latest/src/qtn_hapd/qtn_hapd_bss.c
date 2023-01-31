/*SH1
*******************************************************************************
**                                                                           **
**         Copyright (c) 2009 - 2018 Quantenna Communications, Inc.          **
**                                                                           **
**  File        : qtn_hapd_bss.c                                             **
**  Description :                                                            **
**                                                                           **
*******************************************************************************
**  Copyright 1992-2014 The FreeBSD Project. All rights reserved.            **
**  Redistribution and use in source and binary forms, with or without       **
**  modification, are permitted provided that the following conditions       **
**  are met:                                                                 **
**  1. Redistributions of source code must retain the above copyright        **
**     notice, this list of conditions and the following disclaimer.         **
**  2. Redistributions in binary form must reproduce the above copyright     **
**     notice, this list of conditions and the following disclaimer in the   **
**     documentation and/or other materials provided with the distribution.  **
**  3. The name of the author may not be used to endorse or promote products **
**     derived from this software without specific prior written permission. **
**                                                                           **
**  Alternatively, this software may also be distributed under the terms of  **
**  the GNU General Public License ("GPL") version 2, or (at your option)    **
**  any later version as published by the Free Software Foundation.          **
**                                                                           **
*******************************************************************************
EH1*/


#ifdef CONFIG_QTNA_WIFI

#include "utils/includes.h"
#include <net/if.h>
#include <sys/ioctl.h>
#include <net80211/ieee80211_ioctl.h>
#include "utils/common.h"
#include "utils/eloop.h"
#include "common/ieee802_11_defs.h"
#include "common/wpa_ctrl.h"
#include "radius/radius_client.h"
#include "drivers/driver.h"
#include "ap/hostapd.h"
#include "ap/authsrv.h"
#include "ap/sta_info.h"
#include "ap/accounting.h"
#include "ap/ap_list.h"
#include "ap/beacon.h"
#include "ap/iapp.h"
#include "ap/ieee802_1x.h"
#include "ap/ieee802_11_auth.h"
#include "ap/vlan_init.h"
#include "ap/wpa_auth.h"
#include "ap/wps_hostapd.h"
#include "ap/hw_features.h"
#include "ap/wpa_auth_glue.h"
#include "ap/ap_drv_ops.h"
#include "ap/ap_config.h"
#include "ap/p2p_hostapd.h"
#include "qtn_hapd_bss.h"

static int hostapd_set_ap_isolate(struct hostapd_data *hapd, int value)
{
        if (hapd->driver == NULL || hapd->driver->set_intra_bss == NULL) {
                return 0;
        }

        if (!hapd->primary_interface) {
                return 0;
        }

        return hapd->driver->set_intra_bss(hapd->drv_priv, value);
}

static int hostapd_set_intra_bss_isolate(struct hostapd_data *hapd, int value)
{
	if (hapd->driver == NULL || hapd->driver->set_intra_per_bss == NULL)
		return 0;

	return hapd->driver->set_intra_per_bss(hapd->drv_priv, value);
}

static int hostapd_set_bss_isolate(struct hostapd_data *hapd, int value)
{
	if (hapd->driver == NULL || hapd->driver->set_bss_isolate == NULL)
		return 0;

	return hapd->driver->set_bss_isolate(hapd->drv_priv, value);
}

static int hostapd_set_dynamic_vlan(struct hostapd_data *hapd, const char *ifname, int enable)
{
	if (hapd->driver == NULL || hapd->driver->set_dyn_vlan == NULL)
		return 0;

	return hapd->driver->set_dyn_vlan(hapd->drv_priv, ifname, enable);
}

int hostapd_set_total_assoc_limit(struct hostapd_data *hapd, int limit)
{
        if (hapd->driver == NULL || hapd->driver->set_total_assoc_limit == NULL) {
                return 0;
        }

        if (!hapd->primary_interface) {
                return 0;
        }

        return hapd->driver->set_total_assoc_limit(hapd->drv_priv, limit);
}

int hostapd_set_bss_assoc_limit(struct hostapd_data *hapd, int limit)
{
        if (hapd->driver == NULL || hapd->driver->set_bss_assoc_limit == NULL) {
                return 0;
        }

        return hapd->driver->set_bss_assoc_limit(hapd->drv_priv, limit);
}

int hostapd_set_bss_params(struct hostapd_data *hapd)
{
        int ret = 0;

        if (hostapd_set_ap_isolate(hapd, hapd->conf->isolate) &&
            hapd->conf->isolate) {
                wpa_printf(MSG_ERROR, "Could not enable AP isolation in "
                        "kernel driver");
                ret = -1;
        }

	if (hostapd_set_intra_bss_isolate(hapd, hapd->conf->intra_bss_isolate) &&
			hapd->conf->intra_bss_isolate) {
		wpa_printf(MSG_ERROR, "Could not enable intra-bss isolation in "
			"kernel driver");
		ret = -1;
	}

	if (hostapd_set_bss_isolate(hapd, hapd->conf->bss_isolate) &&
			hapd->conf->bss_isolate) {
		wpa_printf(MSG_ERROR, "Could not enable bss isolation in "
			   "kernel driver");
		ret = -1;
	}

	if (hostapd_set_dynamic_vlan(hapd, hapd->conf->iface, hapd->conf->ssid.dynamic_vlan)) {
		wpa_printf(MSG_ERROR, "Could not enable/disable BSS dynamic mode\n");
		ret = -1;
	}

        return ret;
}

int qtn_hapd_acl_reject(struct hostapd_data *hapd, const u8 *own_addr)
{
	int allowed;

#if 0 /* FIXME:  Making this change for compilation */
	allowed = hostapd_allowed_address(hapd, own_addr, NULL, 0, NULL,
			NULL, NULL, NULL, NULL, NULL);
#else
	allowed = hostapd_allowed_address(hapd, own_addr, NULL, 0, NULL,
			NULL, NULL, NULL, NULL, NULL, 0);
#endif
	if (allowed == HOSTAPD_ACL_REJECT) {
		hostapd_notif_disassoc(hapd, own_addr);
	}

	return (allowed == HOSTAPD_ACL_REJECT);
}

void hostapd_send_wlan_msg(struct hostapd_data *hapd, const char *msg)
{
	if (hapd->driver != NULL && hapd->driver->send_log != NULL) {
		hapd->driver->send_log(hapd->drv_priv, (char *)msg);
	}
}

int hostapd_set_broadcast_ssid(struct hostapd_data *hapd, int value)
{
	if (hapd->driver == NULL || hapd->driver->set_broadcast_ssid == NULL)
		return 0;
	return hapd->driver->set_broadcast_ssid(hapd->drv_priv, value);
}

static char *hapd_config_write_string(const u8 *value, size_t len)
{
	char *buf;

	if (value == NULL)
		return NULL;

	buf = os_malloc(len + 1);
	if (buf == NULL)
		return NULL;

	os_memcpy(buf, value, len);
	buf[len] = '\0';

	return buf;
}

#ifdef CONFIG_WPS
void hapd_wps_write_new_config(FILE *file, const void *p)
{
	const struct wps_credential *cred = (struct wps_credential *)p;
	int wpa;
	int i;

	fprintf(file, "# WPS configuration - START\n");
	fprintf(file, "wps_state=2\n");

	if (is_hex(cred->ssid, cred->ssid_len, 1)) {
		fprintf(file, "ssid2=");
		for (i = 0; i < cred->ssid_len; i++)
			fprintf(file, "%02x", cred->ssid[i]);
		fprintf(file, "\n");
	} else {
		fprintf(file, "ssid=");
		for (i = 0; i < cred->ssid_len; i++)
			fputc(cred->ssid[i], file);
		fprintf(file, "\n");
	}

	if ((cred->auth_type & (WPS_AUTH_WPA2 | WPS_AUTH_WPA2PSK)) &&
	    (cred->auth_type & (WPS_AUTH_WPA | WPS_AUTH_WPAPSK)))
		wpa = 3;
	else if (cred->auth_type & (WPS_AUTH_WPA2 | WPS_AUTH_WPA2PSK))
		wpa = 2;
	else if (cred->auth_type & (WPS_AUTH_WPA | WPS_AUTH_WPAPSK))
		wpa = 1;
	else
		wpa = 0;

	fprintf(file, "wpa=%d\n", wpa);

	if (wpa) {
		char *prefix;

		fprintf(file, "wpa_key_mgmt=");
		prefix = "";

		if (cred->auth_type & (WPS_AUTH_WPA2 | WPS_AUTH_WPA)) {
			fprintf(file, "WPA-EAP");
			prefix = " ";
		}

		if (cred->auth_type & (WPS_AUTH_WPA2PSK | WPS_AUTH_WPAPSK))
			fprintf(file, "%sWPA-PSK", prefix);

		fprintf(file, "\n");

		fprintf(file, "wpa_pairwise=");
		prefix = "";

		if (cred->encr_type & WPS_ENCR_AES) {
			fprintf(file, "CCMP");
			prefix = " ";
		}

		if (cred->encr_type & WPS_ENCR_TKIP)
			fprintf(file, "%sTKIP", prefix);

		fprintf(file, "\n");

		if (cred->key_len >= 8 && cred->key_len < 64) {
			fprintf(file, "wpa_passphrase=");
			for (i = 0; i < cred->key_len; i++)
				fputc(cred->key[i], file);
			fprintf(file, "\n");
		} else if (cred->key_len == 64) {
			fprintf(file, "wpa_psk=");
			for (i = 0; i < cred->key_len; i++)
				fputc(cred->key[i], file);
			fprintf(file, "\n");
		} else {
			wpa_printf(MSG_WARNING, "WPS: Invalid key length %lu for WPA/WPA2",
					(unsigned long) cred->key_len);
		}

		fprintf(file, "auth_algs=1\n");
	} else {
		if ((cred->auth_type & WPS_AUTH_OPEN) &&
		    (cred->auth_type & WPS_AUTH_SHARED))
			fprintf(file, "auth_algs=3\n");
		else if (cred->auth_type & WPS_AUTH_SHARED)
			fprintf(file, "auth_algs=2\n");
		else
			fprintf(file, "auth_algs=1\n");

		if (cred->encr_type & WPS_ENCR_WEP && cred->key_idx <= 4) {
			int key_idx = cred->key_idx;

			if (key_idx)
				key_idx--;
			fprintf(file, "wep_default_key=%d\n", key_idx);
			fprintf(file, "wep_key%d=", key_idx);
			if (cred->key_len == 10 || cred->key_len == 26) {
				/* WEP key as a hex string */
				for (i = 0; i < cred->key_len; i++)
					fputc(cred->key[i], file);
			} else {
				/* Raw WEP key; convert to hex */
				for (i = 0; i < cred->key_len; i++)
					fprintf(file, "%02x", cred->key[i]);
			}
			fprintf(file, "\n");
		} else {
			fprintf(file, "wpa_key_mgmt=WPA-PSK\n");
			fprintf(file, "wpa_pairwise=CCMP\n");
			fprintf(file, "wpa_passphrase=qtn01234\n");
		}
	}
	fprintf(file, "# WPS configuration - END\n");
}
#endif /* CONFIG_WPS */

#ifdef CONFIG_DPP
void hapd_dpp_write_new_config(FILE *file, const void *p)
{
	const struct dpp_credential *cred = (struct dpp_credential *)p;
	char *print_buf;
	int wpa;
	int i;

	wpa_printf(MSG_DEBUG, "hapd_dpp_write_new_config");

	if (is_hex(cred->ssid, cred->ssid_len, 1)) {
		fprintf(file, "ssid2=");
		for (i = 0; i < cred->ssid_len; i++)
			fprintf(file, "%02x", cred->ssid[i]);
		fprintf(file, "\n");
	} else {
		fprintf(file, "ssid=");
		for (i = 0; i < cred->ssid_len; i++)
			fputc(cred->ssid[i], file);
		fprintf(file, "\n");
	}

	wpa = 2;

	fprintf(file, "wpa=%d\n", wpa);
	fprintf(file, "auth_algs=1\n");
	fprintf(file, "ieee80211w=2\n");

	if (wpa) {
		char *prefix;

		fprintf(file, "wpa_key_mgmt=");
		prefix = "";
		switch (cred->dpp_akm) {
		case DPP_AKM_DPP:
			fprintf(file, "%sDPP", prefix);
			fprintf(file, "\n");
			break;
		case DPP_AKM_PSK:
			fprintf(file, "%sWPA-PSK", prefix);
			fprintf(file, "\n");
			break;
		case DPP_AKM_SAE:
			fprintf(file, "%sSAE", prefix);
			fprintf(file, "\n");
			break;
		case DPP_AKM_PSK_SAE:
			fprintf(file, "%sSAE WPA-PSK", prefix);
			fprintf(file, "\n");
			break;
		case DPP_AKM_UNKNOWN:
		default:
			wpa_printf(MSG_WARNING, "Unknown DPP AKM type\n");
		}

		fprintf(file, "rsn_pairwise=CCMP");
		fprintf(file, "\n");

		switch (cred->dpp_secret_type) {
		case DPP_SECRET_TYPE_CONNECTOR:
			fprintf(file, "dpp_connector=");
			for (i = 0; i < wpabuf_len(cred->secret); i++)
				fputc(cred->secret->buf[i], file);
			fprintf(file, "\n");
			break;
		case DPP_SECRET_TYPE_PASSPHRASE:
			fprintf(file, "wpa_passphrase=");
			for (i = 0; i < wpabuf_len(cred->secret); i++)
				fputc(cred->secret->buf[i], file);
			fprintf(file, "\n");
			break;
		case DPP_SECRET_TYPE_PSK:
			if (wpabuf_len(cred->secret)) {
				print_buf = hapd_config_write_string(wpabuf_head(cred->secret),
									wpabuf_len(cred->secret));
				if (print_buf) {
					wpa_printf(MSG_DEBUG, "DPP WPA-PSK %s", print_buf);
					fprintf(file, "wpa_psk=%s\n", print_buf);
					free(print_buf);
				}
			}
			break;
		default:
			wpa_printf(MSG_WARNING, "DPP: Unknown secret type");
		}

		if (cred->dpp_akm == DPP_AKM_DPP && wpabuf_len(cred->csign_key)) {
			print_buf = hapd_config_write_string(wpabuf_head(cred->csign_key),
								wpabuf_len(cred->csign_key));
			if (print_buf) {
				wpa_printf(MSG_DEBUG, "DPP csign-key %s", print_buf);
				fprintf(file, "dpp_csign=%s\n", print_buf);
				free(print_buf);
			}
		}

		if (cred->dpp_akm == DPP_AKM_DPP && wpabuf_len(cred->net_accesskey)) {
			print_buf = hapd_config_write_string(wpabuf_head(cred->net_accesskey),
								wpabuf_len(cred->net_accesskey));
			if (print_buf) {
				wpa_printf(MSG_DEBUG, "DPP netaccesskey %s", print_buf);
				fprintf(file, "dpp_netaccesskey=%s\n", print_buf);
				free(print_buf);
			}
		}
	}
}
#endif /* CONFIG_DPP */

#if defined(CONFIG_DPP) || defined(CONFIG_WPS)
void hostapd_update_config(void *eloop_data, void *user_ctx)
{
	struct hostapd_iface *iface = eloop_data;
	struct hostapd_cfg_ctx *cfg_ctx = (struct hostapd_cfg_ctx *)user_ctx;
	int i;

	if (cfg_ctx->config_type == HAPD_CFG_TYPE_WPS)
		wpa_printf(MSG_DEBUG, "WPS: Reload configuration data");
	else
		wpa_printf(MSG_DEBUG, "DPP: Reload configuration data");

	if (iface->interfaces == NULL ||
		iface->interfaces->update_config(iface, cfg_ctx->ifname) < 0) {
		if (cfg_ctx->config_type == HAPD_CFG_TYPE_WPS)
			wpa_printf(MSG_WARNING, "WPS: Failed to update interface %s",
					cfg_ctx->ifname);
		else
			wpa_printf(MSG_WARNING, "DPP: Failed to update interface %s",
					cfg_ctx->ifname);
	}

	for (i = 0; i < iface->num_bss; i++) {
		struct hostapd_data *hapd = iface->bss[i];

		if (hapd && (strncmp(cfg_ctx->ifname, hapd->conf->iface, IFNAMSIZ) == 0)) {
			if (cfg_ctx->config_type == HAPD_CFG_TYPE_WPS)
				hostapd_send_wlan_msg(hapd, "WPS ER CRED UPDATED");
			else
				hostapd_send_wlan_msg(hapd, "DPP Enrollee CRED UPDATED");

			wpa_msg(hapd->msg_ctx, MSG_INFO, AP_EVENT_ENABLED);
			break;
		}
	}

	os_free(cfg_ctx->ifname);
	os_free(cfg_ctx);
}

static int hapd_skip_old_config_line(char *buf, int conf_type)
{
	if (conf_type == HAPD_CFG_TYPE_WPS) {
		if (str_starts(buf, "ssid=") ||
			str_starts(buf, "ssid2=") ||
			str_starts(buf, "auth_algs=") ||
			str_starts(buf, "wep_default_key=") ||
			str_starts(buf, "wep_key") ||
			str_starts(buf, "wps_state=") ||
			str_starts(buf, "wpa=") ||
			str_starts(buf, "wpa_psk=") ||
			str_starts(buf, "wpa_pairwise=") ||
			str_starts(buf, "rsn_pairwise=") ||
			str_starts(buf, "wpa_key_mgmt=") ||
			str_starts(buf, "wpa_passphrase=")) {
			return 1;
		}
	} else if (conf_type == HAPD_CFG_TYPE_DPP) {
		if (str_starts(buf, "ssid=") ||
			str_starts(buf, "ssid2=") ||
			str_starts(buf, "auth_algs=") ||
			str_starts(buf, "dpp_connector=") ||
			str_starts(buf, "dpp_csign=") ||
			str_starts(buf, "dpp_netaccesskey=") ||
			str_starts(buf, "ieee80211w=") ||
			str_starts(buf, "wpa=") ||
			str_starts(buf, "wpa_psk=") ||
			str_starts(buf, "rsn_pairwise=") ||
			str_starts(buf, "wpa_key_mgmt=") ||
			str_starts(buf, "wpa_passphrase=")) {
			return 1;
		}
	}

	return 0;
}

void hapd_parse_and_write_new_config(struct hostapd_data *hapd, FILE *oconf, FILE *nconf,
					const void *cred, int conf_type)
{
	char buf[1024];
	char bss[32];
	static enum hapd_cred_write_back_state state;

	state = HAPD_CRED_SEARCH;
	snprintf(bss, sizeof(bss), "bss=%s", hapd->conf->iface);
	if (hapd->primary_interface) {
		wpa_printf(MSG_WARNING, "[cred] found primary interface (%s)",
				hapd->conf->iface);
		if (conf_type == HAPD_CFG_TYPE_WPS)
			hapd_wps_write_new_config(nconf, cred);
		else
			hapd_dpp_write_new_config(nconf, cred);
		state = HAPD_CRED_FOUND;
	}

	while (fgets(buf, sizeof(buf), oconf)) {
		switch (state) {
		case HAPD_CRED_SEARCH:
			if (str_starts(buf, bss)) {
				wpa_printf(MSG_DEBUG, "[cred] found bss--%s",
						buf);
				fprintf(nconf, "%s", buf);
				if (conf_type == HAPD_CFG_TYPE_WPS)
					hapd_wps_write_new_config(nconf, cred);
				else
					hapd_dpp_write_new_config(nconf, cred);
				state = HAPD_CRED_FOUND;
				wpa_printf(MSG_DEBUG, "[cred] mode switch, search->found");
			} else {
				fprintf(nconf, "%s", buf);
			}
			break;
		case HAPD_CRED_FOUND:
			if (str_starts(buf, "bss=")) {
				wpa_printf(MSG_DEBUG, "[cred] found another bss--%s", buf);
				fprintf(nconf, "%s", buf);
				state = HAPD_CRED_DONE;
				wpa_printf(MSG_DEBUG, "[cred] mode switch, found->done");
			} else if (hapd_skip_old_config_line(buf, conf_type)) {
				/* Discard old config */
				wpa_printf(MSG_DEBUG, "[cred] skip field--%s", buf);
			} else {
				fprintf(nconf, "%s", buf);
			}
			break;
		case HAPD_CRED_DONE:
			fprintf(nconf, "%s", buf);
			break;
		default:
			break;
		}
	}

}
#endif /* CONFIG_DPP || CONFIG_WPS */

#endif /* CONFIG_QTNA_WIFI */
