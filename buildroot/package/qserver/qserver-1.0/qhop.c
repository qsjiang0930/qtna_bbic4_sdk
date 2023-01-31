/*
 *		Qhop connection management
 *
 * It's mainly used to receive the qhop related events from driver
 * and control the qhop link switch.
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

#include <net/if.h>

#include "qhop.h"
#include "qcsapi.h"
#include "net80211/ieee80211_ioctl.h"
#include "qdata.h"
#include "driver.h"
#include "crypto.h"

static int
qhop_md5_sum(const char *passphrase, int len, char *res_buf)
{
        int i;
        char *psk_use;
        unsigned char hex_buf[MD5_MAC_LEN];
        const uint8_t *passphrase_vec[2];
        size_t len_vec[2];
        char buf_use[MD5_STR_BUF_LEN] = {0};
        char *pos, *end;
        int ret;

        psk_use = (char *)malloc(len + 1);
        if (!psk_use) {
                os_fprintf(stderr, "%s: memory alloction fails\n", __func__);
                return -1;
        }

        memcpy(psk_use, passphrase, len);
        psk_use[len] = '\n';
        passphrase_vec[0] = (uint8_t *)psk_use;
        len_vec[0] = len + 1;

        if(md5_vector(1, passphrase_vec, len_vec, hex_buf) < 0) {
                os_fprintf(stderr, "%s: MD5 conversion fails\n", __func__);
                free(psk_use);
                return -1;
        }

        pos = buf_use;
        end = pos + sizeof(buf_use);
        for(i = 0; i < MD5_MAC_LEN; i++) {
                ret = snprintf(pos, (end - pos), "%02x", hex_buf[i]);
                if (ret < 0 || ret > (end - pos)) {
                        os_fprintf(stderr, "%s: hex to str error\n");
                        free(psk_use);
                        return -1;
                }
                pos += ret;
        }
        memcpy(res_buf, buf_use, (MD5_STR_BUF_LEN - 1));
        free(psk_use);

        return 0;
}

static int
qhop_md5_convert_passphrase(const string_64 psk_web, string_64 pre_shared_key)
{
        int key_size;
        char passphrase_md5_res[MD5_STR_BUF_LEN] = {0};

        if (!psk_web || !pre_shared_key)
                return -1;

        key_size = strlen(psk_web);
        if ((key_size < QTN_WPA_PASSPHRASE_MIN_LEN) || (key_size > QTN_WPA_PSK_LEN))
                return -1;

        memset(pre_shared_key, 0, sizeof(string_64));
        if (qhop_md5_sum(psk_web, key_size, passphrase_md5_res) < 0) {
                os_fprintf(stderr, "%s: PSK MD5 convertion fails\n", __func__);
                return -1;
        }

        os_fprintf(stderr, "MD5 conversion of PSK is %s\n", passphrase_md5_res);

        if (key_size <= (MD5_STR_BUF_LEN - 1)) {
                memcpy(pre_shared_key, passphrase_md5_res, key_size);
        } else {
                memcpy(pre_shared_key, passphrase_md5_res, (MD5_STR_BUF_LEN - 1));
                strncpy(pre_shared_key + (MD5_STR_BUF_LEN - 1),
			psk_web + (MD5_STR_BUF_LEN - 1),
			key_size - (MD5_STR_BUF_LEN - 1));
        }

        return 0;
}

static int
qhop_get_pmk(const char *ifname, qcsapi_wifi_mode mode, uint8_t *pmk)
{
	qcsapi_SSID ssid = {'\0'};
	string_64 psk = {'\0'};
	string_64 psk_md5 = {'\0'};
	uint8_t psk_len = 0;
	uint8_t ssid_len = 0;

	if (qcsapi_wifi_get_SSID(ifname, ssid) < 0) {
		os_fprintf(stderr, "%s: Failed to get the SSID\n", __func__);
		return -1;
	}

	os_fprintf(stdout, "%s: SSID %s\n", __func__, ssid);

	if (mode == qcsapi_station) {
		if ((qcsapi_SSID_get_pre_shared_key(ifname, ssid, 0, psk) == 0) &&
				(strnlen(psk, QTN_WPA_PSK_LEN) == QTN_WPA_PSK_LEN)) {
			os_fprintf(stdout, "%s: STA PSK %s\n", __func__, psk);

			if (qhop_md5_convert_passphrase(psk, psk_md5) < 0) {
				os_fprintf(stderr, "%s: MD5 coversion for STA PSK fails\n",
					__func__);
				return -1;
			}

			os_fprintf(stdout, "%s: STA PSK_MD5 %s\n", __func__, psk_md5);

			if (os_hexstr2bin(psk_md5, pmk, PMK_LEN) < 0) {
				os_fprintf(stderr, "%s: failed to convert the psk"
					" string to hex for STA\n", __func__);
				return -1;
			}
		} else {
			os_fprintf(stdout, "%s: don't find psk and try to"
				" get passphrase for STA\n", __func__);

			if (qcsapi_SSID_get_key_passphrase(ifname, ssid, 0, psk)) {
				os_fprintf(stderr, "%s: Failed to get psk or"
					" passphrase for STA\n", __func__);
				return -1;
			}

			os_fprintf(stdout, "%s: STA Passphrase %s\n", __func__, psk);

			if (qhop_md5_convert_passphrase(psk, psk_md5) < 0) {
				os_fprintf(stderr, "%s: MD5 coversion for STA"
					" passphrase fails\n", __func__);
				return -1;
			}

			os_fprintf(stdout, "%s: STA Passphrase_MD5 %s\n", __func__, psk_md5);

			psk_len = strnlen(psk, QTN_WPA_PSK_LEN);
			if ((psk_len < QTN_WPA_PASSPHRASE_MIN_LEN) ||
				(psk_len > QTN_WPA_PASSPHRASE_MAX_LEN)) {
				os_fprintf(stderr, "%s: invalid passpharse for STA\n",
					__func__);
				return -1;
			}

			ssid_len = strnlen(ssid, QTN_SSID_MAX_LEN);
			pbkdf2_sha1(psk_md5, (uint8_t *)ssid, ssid_len, SHA1_ITERATION_NUM, pmk, PMK_LEN);
		}
	} else if (mode == qcsapi_access_point) {
		if (qcsapi_wifi_get_pre_shared_key(ifname, 0, psk) == 0) {
			os_fprintf(stdout, "%s: AP PSK %s\n", __func__, psk);

			if (qhop_md5_convert_passphrase(psk, psk_md5) < 0) {
				os_fprintf(stderr, "%s: MD5 coversion for AP PSK fails\n",
					__func__);
				return -1;
			}

			os_fprintf(stdout, "%s: AP PSK_MD5 %s\n", __func__, psk_md5);

			if (os_hexstr2bin(psk_md5, pmk, PMK_LEN) < 0) {
				os_fprintf(stderr, "%s: failed to convert the psk"
					" string to hex for AP\n", __func__);
				return -1;
			}
		} else {
			os_fprintf(stdout, "%s: don't find psk and try to"
				" get passphrase for AP\n", __func__);

			if (qcsapi_wifi_get_key_passphrase(ifname, 0, psk)) {
				os_fprintf(stderr, "%s: Failed to get psk"
					" or passphrase for AP\n", __func__);
				return -1;
			}

			os_fprintf(stdout, "%s: AP Passphrase %s\n", __func__, psk);

			if (qhop_md5_convert_passphrase(psk, psk_md5) < 0) {
				os_fprintf(stderr, "%s: MD5 coversion for AP"
					" passphrase fails\n", __func__);
				return -1;
			}

			os_fprintf(stdout, "%s: AP Passphrase_MD5 %s\n", __func__, psk_md5);

			psk_len = strnlen(psk, QTN_WPA_PSK_LEN);
			if ((psk_len < QTN_WPA_PASSPHRASE_MIN_LEN) ||
				(psk_len > QTN_WPA_PASSPHRASE_MAX_LEN)) {
				os_fprintf(stderr, "%s: invalid passpharse for AP\n",
					__func__);
				return -1;
			}

			ssid_len = strnlen(ssid, QTN_SSID_MAX_LEN);
			pbkdf2_sha1(psk_md5, (uint8_t *)ssid, ssid_len, SHA1_ITERATION_NUM, pmk, PMK_LEN);
		}
	} else {
		os_fprintf(stderr, "%s: invalid wifi mode %u\n", __func__, mode);
		return -1;
	}

	return 0;
}

static int
qhop_generate_wds_key(const char *ifname,
	uint8_t *mbs_addr, uint8_t *rbs_addr, uint8_t *wds_key)
{
	qcsapi_wifi_mode mode = qcsapi_nosuch_mode;
	uint8_t pmk[PMK_LEN] = {0};
	const uint8_t *addr[3];
	size_t len[3];

	if (qcsapi_wifi_get_mode(ifname, &mode) < 0) {
	      os_fprintf(stderr, "%s: failed to get wifi mode\n", __func__);
		return -1;
	}

	if (qhop_get_pmk(ifname, mode, pmk) < 0) {
		os_fprintf(stderr, "%s: failed to get pmk\n", __func__);
		return -1;
	}

	addr[0] = mbs_addr;
	len[0] = ETH_ALEN;
	addr[1] = rbs_addr;
	len[1] = ETH_ALEN;
	addr[2] = pmk;
	len[2] = PMK_LEN;

	sha256_vector(3, addr, len, wds_key);

	return 0;
}

/*
 * RBS cares about following events
 *     WDS_EXT_RECEIVED_MBS_IE
 *     WDS_EXT_LINK_STATUS_UPDATE
 *     WDS_EXT_RBS_OUT_OF_BRR
 *     WDS_EXT_RBS_SET_CHANNEL
 *     WDS_EXT_CLEANUP_WDS_LINK
 *     WDS_EXT_STA_UPDATE_EXT_INFO
 * but only the first one depends on SM to retrieve configurations from MBS
 */
static int
qhop_rbs_suspend_wds_ext_event(struct qserver_data *qhop_ctx,
	 qcsapi_wifi_mode wifi_mode, struct qtn_wds_ext_event_data *event_data, char *cmd)
{
	struct link_sw_data *link_data = &qhop_ctx->ls_data;
	struct qtn_drv_data *qdrv_priv = (struct qtn_drv_data *)qhop_ctx->driver_priv;

	/* configurations already sync */
	if (wifi_mode != qcsapi_station)
		return 0;

	if (event_data->cmd != WDS_EXT_RECEIVED_MBS_IE)
		return 0;

	/* SM may be out of order */
	link_switch_reset_state(link_data);

	/* Set the dest address of Query frame to MBS MAC address */
	link_switch_set_dest_addr(link_data, event_data->mac);

	/* start Configuration Sync */
	link_switch_sm_step(link_data, LINK_SW_SYNC);

	/* save cmd and call it in state LINK_SW_UPDATE */
	strncpy(qdrv_priv->pending_cmd, cmd, QTN_WDS_EXT_CMD_LEN);
	qdrv_priv->pending_cmd[QTN_WDS_EXT_CMD_LEN - 1] = '\0';

	return 1;
}

static int
qhop_suspend_wds_ext_event(qcsapi_wifi_mode wifi_mode,
	struct qtn_wds_ext_event_data *event_data, char *cmd)
{
	struct qserver_data *qhop_ctx;
	int ret;
	int mode = QSVR_DEV_UNKNOWN;

	qhop_ctx = (struct qserver_data *)qserver_get_context();
	if (qhop_ctx == NULL)
		return 0;

	ret = qserver_drv_get_device_mode(qhop_ctx, &mode);
	if (ret < 0)
		return 0;

	/*
	 * Note: RBS behaves differently when it receives event
	 * "WDS_EXT_RECEIVED_MBS_IE" according to current WiFi mode.
	 * STA mode:
	 *     1) trigger Configuration Sync with MBS
	 *     2) suspend until configurations synced
	 * AP mode:
	 *     just go ahead since configurations already synced
	 */
	if (mode == QSVR_DEV_RBS) {
		return qhop_rbs_suspend_wds_ext_event(qhop_ctx,
				wifi_mode, event_data, cmd);
	}

	return 0;
}

static int
qhop_prepare_wds_key(const char *ifname, string_16 wpa_encrypt, uint8_t *mbs_addr,
	uint8_t *rbs_addr, uint8_t *wds_key, uint8_t wds_key_len, char *wds_key_hex,
	uint8_t wds_key_hex_len)
{
	if (strncmp(wpa_encrypt, "Basic", 5) && strncmp(wpa_encrypt, "NONE", 4)) {
		if (qhop_generate_wds_key(ifname, mbs_addr, rbs_addr, wds_key) < 0) {
			os_fprintf(stderr, "%s: failed to generate wds key\n", __func__);
			return -1;
		}
		os_snprintf_hex(wds_key_hex, wds_key_hex_len, wds_key, wds_key_len);
	} else {
		snprintf(wds_key_hex, wds_key_hex_len, "NULL");
	}

	return 0;
}

static void
qhop_ap_process_wds_ext_event(const char *ifname,
	struct qtn_wds_ext_event_data *event_data, char *cmd, uint8_t len)
{
	uint8_t own_addr[ETH_ALEN] = {0};
	uint8_t wds_key[QTN_WDS_KEY_LEN] = {0};
	char wds_key_hex[QTN_WDS_KEY_LEN * 2 + 1] = {'\0'};
	string_16 wpa_encrypt = "Basic";

	if (qcsapi_interface_get_mac_addr(ifname, own_addr) < 0) {
		os_fprintf(stderr, "%s: failed to get own mac address\n", __func__);
		return;
	}
	qcsapi_wifi_get_beacon_type(ifname, wpa_encrypt);

	switch (event_data->cmd) {
	case WDS_EXT_RECEIVED_MBS_IE:
		if (strncmp(wpa_encrypt, "Basic", 5)) {
			if (qhop_generate_wds_key(ifname, event_data->mac,
					own_addr, wds_key) < 0) {
				os_fprintf(stderr, "%s: failed to generate wds key\n",
					__func__);
				return;
			}
			os_snprintf_hex(wds_key_hex, sizeof(wds_key_hex),
						wds_key, sizeof(wds_key));
		} else {
			snprintf(wds_key_hex, sizeof(wds_key_hex), "NULL");
		}

		snprintf(cmd, len, "%s %s peer=" MACSTR " channel=%d wds_key=%s",
				QTN_WDS_EXT_SCRIPT, "RBS-CREATE-WDS-LINK",
				MAC2STR(event_data->mac), event_data->channel,
				wds_key_hex);
		break;
	case WDS_EXT_RECEIVED_RBS_IE:
		if (strncmp(wpa_encrypt, "Basic", 5)) {
			if (qhop_generate_wds_key(ifname, own_addr,
					event_data->mac, wds_key) < 0) {
				os_fprintf(stderr, "%s: failed to generate wds key\n",
					__func__);
				return;
			}
			os_snprintf_hex(wds_key_hex, sizeof(wds_key_hex),
						wds_key, sizeof(wds_key));
		} else {
			snprintf(wds_key_hex, sizeof(wds_key_hex), "NULL");
		}

		snprintf(cmd, len, "%s %s peer=" MACSTR " wds_key=%s",
				QTN_WDS_EXT_SCRIPT, "MBS-CREATE-WDS-LINK",
				MAC2STR(event_data->mac), wds_key_hex);
		break;
	case WDS_EXT_LINK_STATUS_UPDATE:
		if (event_data->extender_role == IEEE80211_EXTENDER_ROLE_MBS) {
			snprintf(cmd, len, "%s %s peer=" MACSTR,
					QTN_WDS_EXT_SCRIPT, "MBS-REMOVE-WDS-LINK",
					MAC2STR(event_data->mac));
		} else if (event_data->extender_role == IEEE80211_EXTENDER_ROLE_RBS) {
			snprintf(cmd, len, "%s %s peer=" MACSTR,
					QTN_WDS_EXT_SCRIPT, "RBS-REMOVE-WDS-LINK",
					MAC2STR(event_data->mac));
		}
		break;
	case WDS_EXT_RBS_OUT_OF_BRR:
		snprintf(cmd, len, "%s %s peer=" MACSTR,
				QTN_WDS_EXT_SCRIPT, "START-STA-RBS",
				MAC2STR(event_data->mac));
		break;
	case WDS_EXT_RBS_SET_CHANNEL:
		snprintf(cmd, len, "%s %s channel=%d",
				QTN_WDS_EXT_SCRIPT, "RBS-SET-CHANNEL",
				event_data->channel);
		break;
	case WDS_EXT_CLEANUP_WDS_LINK:
		snprintf(cmd, len, "%s %s peer=" MACSTR,
				QTN_WDS_EXT_SCRIPT, "REMOVE-WDS-LINK",
				MAC2STR(event_data->mac));
		break;
	case WDS_EXT_MBS_UPDATE_WDS_KEY:
		if (qhop_prepare_wds_key(ifname, wpa_encrypt, own_addr, event_data->mac,
				wds_key, sizeof(wds_key), wds_key_hex, sizeof(wds_key_hex)) < 0)
			break;

		snprintf(cmd, len, "%s %s peer=" MACSTR " wds_key=%s", QTN_WDS_EXT_SCRIPT,
				"MBS-UPDATE-WDS-KEY", MAC2STR(event_data->mac), wds_key_hex);
		break;
	case WDS_EXT_RBS_UPDATE_WDS_KEY:
		if (qhop_prepare_wds_key(ifname, wpa_encrypt, event_data->mac, own_addr,
				wds_key, sizeof(wds_key), wds_key_hex, sizeof(wds_key_hex)) < 0)
			break;

		snprintf(cmd, len, "%s %s peer=" MACSTR " wds_key=%s", QTN_WDS_EXT_SCRIPT,
				"RBS-UPDATE-WDS-KEY", MAC2STR(event_data->mac), wds_key_hex);
		break;
	default:
		os_fprintf(stderr, "%s: unsupported event command %d\n",
			__func__, event_data->cmd);
		break;
	}

	if (qhop_suspend_wds_ext_event(qcsapi_access_point, event_data, cmd)) {
		os_fprintf(stdout, "%s: suspend event %u in AP mode\n",
			__func__, event_data->cmd);
		cmd[0] = '\0';
		return;
	}
}

static void
qhop_sta_process_wds_ext_event(const char *ifname,
	struct qtn_wds_ext_event_data *event_data, char *cmd, uint8_t len)
{
	qcsapi_SSID ssid = {'\0'};
	qcsapi_mac_addr bssid = {0};
	uint8_t own_addr[ETH_ALEN] = {0};
	uint8_t wds_key[QTN_WDS_KEY_LEN] = {0};
	char wds_key_hex[QTN_WDS_KEY_LEN * 2 + 1] = {'\0'};
	string_32 wpa_encrypt = "NONE";

	if (qcsapi_interface_get_mac_addr(ifname, own_addr) < 0) {
		os_fprintf(stderr, "%s: failed to get own mac address\n", __func__);
		return;
	}

	if (qcsapi_wifi_get_SSID(ifname, ssid) < 0) {
		os_fprintf(stderr, "%s: Failed to get the SSID\n", __func__);
		return;
	}

	qcsapi_SSID_get_authentication_mode(ifname, ssid, wpa_encrypt);

	switch (event_data->cmd) {
	case WDS_EXT_RECEIVED_MBS_IE:
		if (qcsapi_wifi_get_BSSID(ifname, bssid) < 0)
			return;

		if (memcmp(bssid, event_data->mac, sizeof(bssid))) {
			os_fprintf(stderr, "%s: STA assoicated BSSID " MACSTR
				" is not matched with MBS " MACSTR
				" in event WDS_EXT_RECEIVED_MBS_IE\n",
				__func__, MAC2STR(bssid), MAC2STR(event_data->mac));
			return;
		}

		if (strncmp(wpa_encrypt, "NONE", 4)) {
			if (qhop_generate_wds_key(ifname, event_data->mac,
					own_addr, wds_key) < 0) {
				os_fprintf(stderr, "%s: failed to generate wds key\n",
					__func__);
				return;
			}
			os_snprintf_hex(wds_key_hex, sizeof(wds_key_hex),
						wds_key, sizeof(wds_key));
		} else {
			snprintf(wds_key_hex, sizeof(wds_key_hex), "NULL");
		}

		snprintf(cmd, len, "%s %s peer=" MACSTR " wds_key=%s channel=%d bw=%d",
			QTN_WDS_EXT_SCRIPT, "START-AP-RBS", MAC2STR(event_data->mac),
			wds_key_hex, event_data->channel, event_data->bandwidth);
		break;
	case WDS_EXT_LINK_STATUS_UPDATE:
		snprintf(cmd, len, "%s %s",
			QTN_WDS_EXT_SCRIPT, "START-STA-RBS");
		break;
	default:
		os_fprintf(stderr, "%s: unsupported event command %d\n",
			__func__, event_data->cmd);
		break;
	}

	if (qhop_suspend_wds_ext_event(qcsapi_station, event_data, cmd)) {
		os_fprintf(stdout, "%s: suspend event %u in STA mode\n",
			__func__, event_data->cmd);
		cmd[0] = '\0';
		return;
	}
}

void
qhop_handle_wds_ext_event(const char *ifname, void *custom)
{
	char cmd[QTN_WDS_EXT_CMD_LEN] = {'\0'};
	qcsapi_wifi_mode mode = qcsapi_nosuch_mode;
	char *mode_str = "invalid";

	struct qtn_wds_ext_event_data *event_data =
		(struct qtn_wds_ext_event_data*)custom;

	qcsapi_wifi_get_mode(ifname, &mode);
	if (mode == qcsapi_access_point) {
		mode_str = "AP";
	} else if (mode == qcsapi_station) {
		mode_str = "STA";
	} else {
		os_fprintf(stderr, "%s: invalid wifi mode %d\n",
			__func__, mode);
		return;
	}

	os_fprintf(stdout, "%s: %s received QTN-WDS-EXT message, "
			"cmd = %d, mac = " MACSTR " local role=%d\n",
			__func__, mode_str, event_data->cmd,
			MAC2STR(event_data->mac),
			event_data->extender_role);

	if (mode == qcsapi_access_point)
		qhop_ap_process_wds_ext_event(ifname,
			event_data, cmd, QTN_WDS_EXT_CMD_LEN - 1);
	else if (mode == qcsapi_station)
		qhop_sta_process_wds_ext_event(ifname,
			event_data, cmd, QTN_WDS_EXT_CMD_LEN - 1);

	os_fprintf(stdout, "%s: call command - %s\n", __func__, cmd);
	system(cmd);
}


