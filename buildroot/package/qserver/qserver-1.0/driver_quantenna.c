/*
 *	qserver driver interaction for Quantenna
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
#include "qcsapi.h"
#include "wireless.h"
#include "net80211/ieee80211.h"
#include "net80211/ieee80211_ioctl.h"


#define QTN_SYS_NET_PATH "/sys/class/net"
#define QTN_WIFI_INTERFACE_NAME "wifi"
#define QTN_SERIAL_NUM_LEN 16
#define QTN_REKEY_STR_LEN 12
#define QTN_MAX_BSSID 8
#define QTN_PARAMS_FILENAME_DEFAULT "/var/tmp/qserver_device_params"


static struct security_filed_entry qserver_key_mgmt_table[] =
{
	{ QEV_KM_NONE, "NONE", "WPA-PSK", "NONE" },
	{ QEV_KM_WPA_PSK, "WPA-PSK", "WPA-PSK", "PSKAuthentication" },
	{ QEV_KM_WPA_EAP, "WPA-EAP", "WPA-EAP", "EAPAuthentication" },
	{ QEV_KM_WPA_PSK_SHA256, "WPA-PSK-SHA256", "WPA-PSK-SHA256",
		"SHA256PSKAuthentication" },
	{ QEV_KM_WPA_PSK_MIXED, "WPA-PSK WPA-PSK-SHA256",
		"WPA-PSK WPA-PSK-SHA256", "SHA256PSKAuthenticationMixed" },
	{ QEV_KM_SAE, "SAE", "SAE", "SAEAuthentication" },
	{ QEV_KM_OWE, "OWE", "OWE", "OPENandOWEAuthentication" },
	{ QEV_KM_SAE_TRANSITION, "SAE WPA-PSK", "SAE WPA-PSK", "SAEandPSKAuthentication" },
	{ QEV_KM_INVALID, NULL, NULL, NULL },
};

static struct security_filed_entry qserver_proto_table[] =
{
	{ QEV_PT_NONE, "RSN", "0", "Basic" },
	{ QEV_PT_WPA, "WPA", "1", "WPA" },
	{ QEV_PT_RSN, "RSN", "2", "11i" },
	{ QEV_PT_WPA_RSN, "WPA RSN", "3", "WPAand11i" },
	{ QEV_PT_INVALID, NULL, NULL, NULL },
};

static struct security_filed_entry qserver_encrypt_table[] =
{
	{ QEV_EP_NONE, "CCMP", "CCMP", "NONE" },
	{ QEV_EP_WEP40, "WEP40", "WEP40", "WEP40" },
	{ QEV_EP_WEP104, "WEP104", "WEP104", "WEP104" },
	{ QEV_EP_TKIP, "TKIP", "TKIP","TKIPEncryption" },
	{ QEV_EP_CCMP, "CCMP", "CCMP","AESEncryption" },
	{ QEV_EP_TKIP_CCMP, "TKIP CCMP", "TKIP CCMP","TKIPandAESEncryption" },
	{ QEV_EP_INVALID, NULL,	NULL, NULL },
};


static uint8_t
lookup_security_item_index(struct security_filed_entry *table,
	const char *item_str, const char *desc)
{
	uint8_t item_index = QEV_KM_INVALID;
	int i;

	if (!table) {
		os_fprintf(stderr, "%s: null %s table\n",
			__func__, desc);
		return item_index;
	}

	for (i = 0; table[i].qcsapi_str; i++) {
		if (strcasecmp(item_str, table[i].qcsapi_str) == 0) {
			item_index = table[i].index;
			break;
		}
	}

	os_fprintf(stdout, "%s: %s %s - %d\n", __func__, desc,
		item_str != NULL ? item_str : "NULL", item_index);

	return item_index;
}

static int
qtn_get_band(const char *ifname UNUSED_PARAM, uint8_t *band)
{
	*band = QEV_BAND_5G_LOW;

	return 0;
}

static int
qtn_get_security_key_mgmt(const char *ifname, uint8_t *key_mgmt)
{
	qcsapi_wifi_mode mode = qcsapi_nosuch_mode;
	string_32 key_mgmt_str = {0};
	qcsapi_SSID ssid = {0};
	int ret;

	ret = qcsapi_wifi_get_mode(ifname, &mode);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to get wifi mode - errno %d\n",
				__func__, ret);
		return -1;
	}

	ret = qcsapi_wifi_get_SSID(ifname, ssid);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to get SSID - errno %d\n",
				__func__, ret);
		return -1;
	}

	if (mode == qcsapi_access_point) {
		ret = qcsapi_wifi_get_WPA_authentication_mode(ifname, key_mgmt_str);
		if (ret < 0) {
			os_fprintf(stderr, "%s: fail to get key managment - errno %d\n",
					__func__, ret);
			return -1;
		}
	} else if (mode == qcsapi_station) {
		ret = qcsapi_SSID_get_authentication_mode(ifname, ssid, key_mgmt_str);
		if (ret < 0) {
			os_fprintf(stderr, "%s: fail to get key managment - errno %d\n",
					__func__, ret);
			return -1;
		}
	} else {
		os_fprintf(stderr, "%s: invalid mode %d\n", __func__, mode);
		return -1;
	}

	*key_mgmt = lookup_security_item_index(qserver_key_mgmt_table,
			key_mgmt_str, "key_mgmt");

	return 0;
}

static int
qtn_get_security_proto(const char *ifname, uint8_t *proto)
{
	qcsapi_wifi_mode mode = qcsapi_nosuch_mode;
	string_16 proto_str = {0};
	qcsapi_SSID ssid = {0};
	int ret;

	ret = qcsapi_wifi_get_mode(ifname, &mode);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to get wifi mode - errno %d\n",
				__func__, ret);
		return -1;
	}

	ret = qcsapi_wifi_get_SSID(ifname, ssid);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to get SSID - errno %d\n",
				__func__, ret);
		return -1;
	}

	if (mode == qcsapi_access_point) {
		ret = qcsapi_wifi_get_beacon_type(ifname, proto_str);
		if (ret < 0) {
			os_fprintf(stderr, "%s: fail to get proto - errno %d\n",
				__func__, ret);
			return -1;
		}
	} else if (mode == qcsapi_station) {
		ret = qcsapi_SSID_get_protocol(ifname, ssid, proto_str);
		if (ret == -qcsapi_configuration_error) {
			/* None security */
			strncpy(proto_str, "Basic", sizeof(proto_str) - 1);
		} else if (ret < 0) {
			os_fprintf(stderr, "%s: fail to get proto - errno %d\n",
				__func__, ret);
			return -1;
		}
	} else {
		os_fprintf(stderr, "%s: invalid mode %d\n", __func__, mode);
		return -1;
	}

	*proto = lookup_security_item_index(qserver_proto_table, proto_str, "proto");

	return 0;
}

static int
qtn_get_security_pairwise(const char *ifname, uint8_t *pairwise)
{
	qcsapi_wifi_mode mode = qcsapi_nosuch_mode;
	string_32 pairwise_str = {0};
	qcsapi_SSID ssid = {0};
	int ret;

	ret = qcsapi_wifi_get_mode(ifname, &mode);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to get wifi mode - errno %d\n",
				__func__, ret);
		return -1;
	}

	ret = qcsapi_wifi_get_SSID(ifname, ssid);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to get SSID - errno %d\n",
				__func__, ret);
		return -1;
	}

	if (mode == qcsapi_access_point) {
		ret = qcsapi_wifi_get_WPA_encryption_modes(ifname, pairwise_str);
		if (ret < 0) {
			os_fprintf(stderr, "%s: fail to get pairwise encryption"
				" - errno %d\n", __func__, ret);
			return -1;
		}
	} else if (mode == qcsapi_station) {
		ret = qcsapi_SSID_get_encryption_modes(ifname, ssid, pairwise_str);
		if (ret == -qcsapi_configuration_error) {
			/* None security */
			strncpy(pairwise_str, "NONE", sizeof(pairwise_str) - 1);
		} else if (ret < 0) {
			os_fprintf(stderr, "%s: fail to get pairwise encryption"
				" - errno %d\n", __func__, ret);
			return -1;
		}
	} else {
		os_fprintf(stderr, "%s: invalid mode %d\n", __func__, mode);
		return -1;
	}

	*pairwise = lookup_security_item_index(qserver_encrypt_table,
			pairwise_str, "pairwise encryption");

	return 0;
}

static int
qtn_get_password(const char *ifname, uint8_t *passwd, int *len)
{
	qcsapi_wifi_mode mode = qcsapi_nosuch_mode;
	qcsapi_SSID ssid = {0};
	int ret;
	string_64 password;

	ret = qcsapi_wifi_get_mode(ifname, &mode);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to get wifi mode - errno %d\n",
				__func__, ret);
		return -1;
	}

	ret = qcsapi_wifi_get_SSID(ifname, ssid);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to get SSID - errno %d\n",
				__func__, ret);
		return -1;
	}

	if (mode == qcsapi_access_point) {
		ret = qcsapi_wifi_get_key_passphrase(ifname, 0, password);
		if (ret == 0) {
			*len = strnlen(password, QTN_PASSWORD_MAX_LEN);
		} else {
			ret = qcsapi_wifi_get_pre_shared_key(ifname, 0, password);
			if (ret == 0) {
				*len = QTN_PASSWORD_MAX_LEN;
			} else {
				os_fprintf(stderr, "%s: fail to get password on AP mode"
					" - errono %d\n", __func__, ret);
				return -1;
			}
		}
	} else if (mode == qcsapi_station) {
		ret = qcsapi_SSID_get_key_passphrase(ifname, ssid, 0, password);
		if (ret == 0) {
			*len = strnlen(password, QTN_PASSWORD_MAX_LEN);
		} else {
			ret = qcsapi_SSID_get_key_passphrase(ifname, ssid, 0, password);
			if (ret == 0) {
				*len = QTN_PASSWORD_MAX_LEN;
			} else {
				os_fprintf(stderr, "%s: fail to get password on STA mode"
					" - errno %d\n", __func__, ret);
				return -1;
			}
		}
	} else {
		os_fprintf(stderr, "%s: invalid mode %d\n", __func__, mode);
		return -1;
	}

	strncpy((char *)passwd, password, *len);

	return 0;
}

#define QTN_WPA3_CAP_SAE	 0x01
#define QTN_WPA3_CAP_OWE	 0x02
#define QTN_WPA3_CAP_ALL	 (QTN_WPA3_CAP_SAE | QTN_WPA3_CAP_OWE)

static int qtn_get_comp_key_mgmt(int key_mgmt, int wpa3_cap)
{
	switch (key_mgmt) {
	case QEV_KM_SAE:
		if (!(wpa3_cap & QTN_WPA3_CAP_SAE))
			return QEV_KM_INVALID;
		break;
	case QEV_KM_OWE:
		if (!(wpa3_cap & QTN_WPA3_CAP_OWE))
			return QEV_KM_INVALID;
		break;
	case QEV_KM_SAE_TRANSITION:
		if (!(wpa3_cap & QTN_WPA3_CAP_SAE))
			return QEV_KM_WPA_PSK;
		break;
	default:
		break;
	}

	return key_mgmt;
}

static int qtn_get_peer_ver_flags(const char *ifname, uint8_t *macaddr)
{
	struct ieee8011req_sta_ver_flags req_sta;
	struct iwreq iwr;
	int fd = -1;
	int ret;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	memcpy(req_sta.macaddr, macaddr, sizeof(req_sta.macaddr));
	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name) - 1);
	iwr.u.data.flags = SIOCDEV_SUBIO_GET_STA_VER_FLAGS;
	iwr.u.data.pointer = &req_sta;
	iwr.u.data.length = sizeof(req_sta);

	ret = ioctl(fd, IEEE80211_IOCTL_EXT, &iwr);
	if (ret < 0) {
		close(fd);
		return -1;
	}

	close(fd);
	os_fprintf(stdout, "%s: " MACSTR " ver_flags 0x%x\n", __func__,
		MAC2STR(macaddr), req_sta.ver_flags);
	return req_sta.ver_flags;
}

static int qtn_get_peer_wpa3_cap(const char *ifname,
		struct qserver_frm_params *frm_params)
{
	int ver_flags;
	int cap = 0;

	if (frm_params->role != QSVR_DEV_RBS)
		return QTN_WPA3_CAP_ALL;
	ver_flags = qtn_get_peer_ver_flags(ifname, frm_params->sa);
	if (ver_flags <= 0)
		return cap;

	if (ver_flags & QTN_IE_VER_FLAG_SW_WPA3_SAE)
		cap |= QTN_WPA3_CAP_SAE;
	if (ver_flags & QTN_IE_VER_FLAG_SW_WPA3_OWE)
		cap |= QTN_WPA3_CAP_OWE;

	os_fprintf(stdout, "%s: " MACSTR " WPA3 capability 0x%x\n", __func__,
		MAC2STR(frm_params->sa), cap);
	return cap;
}

static uint8_t *
qtn_build_ifindex_attr(const char *ifname UNUSED_PARAM, uint8_t index)
{
	uint8_t *att = os_zalloc(sizeof(struct attr_ifindex));
	struct attr_ifindex *at_index = (struct attr_ifindex *)att;

	if (att == NULL) {
		os_fprintf(stderr, "%s: fail to allocate attr_ifindex\n",
				__func__);
		return NULL;
	}

	os_fprintf(stdout, "%s: ifindex - %d\n", __func__, index);

	at_index->type = tlv_build_type(QEV_ATTR_BSS_IFINDEX);
	at_index->len = tlv_build_vlen(sizeof(*at_index) - 4);
	at_index->index = index;

	return att;
}

static uint8_t *
qtn_build_band_attr(const char *ifname)
{
	uint8_t *att = os_zalloc(sizeof(struct attr_band));
	struct attr_band *at_band = (struct attr_band *)att;
	uint8_t band = QEV_BAND_5G_LOW;

	if (att == NULL) {
		os_fprintf(stderr, "%s: fail to allocate attr_band\n",
				__func__);
		return NULL;
	}

	if (qtn_get_band(ifname, &band)) {
		os_fprintf(stderr, "%s: fail to get band\n", __func__);
		free(att);
		return NULL;
	}

	os_fprintf(stdout, "%s: band - %d\n", __func__, band);

	at_band->type = tlv_build_type(QEV_ATTR_BSS_BAND);
	at_band->len = tlv_build_vlen(sizeof(*at_band) - 4);
	at_band->band = band;

	return att;
}

static uint8_t *
qtn_build_ssid_attr(const char *ifname)
{
	uint8_t *att = os_zalloc(sizeof(struct attr_ssid));
	struct attr_ssid *at_ssid = (struct attr_ssid *)att;

	qcsapi_SSID ssid = {0};

	if (att == NULL) {
		os_fprintf(stderr, "%s: fail to allocate attr_ssid\n",
				__func__);
		return NULL;
	}

	if (qcsapi_wifi_get_SSID(ifname, ssid)) {
		os_fprintf(stderr, "%s: fail to get SSID\n", __func__);
		free(att);
		return NULL;
	}

	os_fprintf(stdout, "%s: SSID - %s\n", __func__, ssid);

	at_ssid->type = tlv_build_type(QEV_ATTR_BSS_SSID);
	at_ssid->len = tlv_build_vlen(strnlen(ssid, QTN_SSID_LEN));
	memcpy(at_ssid->ssid, ssid, at_ssid->len);

	return att;
}

static uint8_t *
qtn_build_security_attr(const char *ifname, int wpa3_cap)
{
	uint8_t *att = os_zalloc(sizeof(struct attr_security));
	struct attr_security *at_sec = (struct attr_security *)att;
	uint8_t key_mgmt = QEV_KM_INVALID;
	uint8_t proto = QEV_PT_INVALID;
	uint8_t pairwise = QEV_EP_INVALID;

	if (att == NULL) {
		os_fprintf(stderr, "%s: fail to allocate attr_security\n",
				__func__);
		return NULL;
	}

	if (qtn_get_security_key_mgmt(ifname, &key_mgmt) < 0) {
		os_fprintf(stderr, "%s: fail to get key_mgmt\n", __func__);
		free(att);
		return NULL;
	}
	key_mgmt = qtn_get_comp_key_mgmt(key_mgmt, wpa3_cap);
	if (key_mgmt == QEV_KM_INVALID) {
		free(att);
		return NULL;
	}

	if (qtn_get_security_proto(ifname, &proto) < 0) {
		os_fprintf(stderr, "%s: fail to get proto\n", __func__);
		free(att);
		return NULL;
	}

	if (qtn_get_security_pairwise(ifname, &pairwise) < 0) {
		os_fprintf(stderr, "%s: fail to get pairwise\n", __func__);
		free(att);
		return NULL;
	}

	at_sec->type = tlv_build_type(QEV_ATTR_BSS_SECURITY);
	at_sec->len = tlv_build_vlen(sizeof(*at_sec) - 4);
	at_sec->key_mgmt = key_mgmt;
	at_sec->proto = proto;
	at_sec->pairwise = pairwise;

	os_fprintf(stdout, "%s: key_mgmt - %d, proto - %d, pairwise - %d\n",
		__func__, key_mgmt, proto, pairwise);

	return att;
}

static uint8_t *
qtn_build_password_attr(const char *ifname)
{
	uint8_t *att = os_zalloc(sizeof(struct attr_password));
	struct attr_password *at_pwd = (struct attr_password *)att;
	uint8_t pwd[QTN_PASSWORD_MAX_LEN + 1] = {0};
	int len = 0;

	if (att == NULL) {
		os_fprintf(stderr, "%s: fail to allocate attr_password\n",
				__func__);
		return NULL;
	}

	if (qtn_get_password(ifname, pwd, &len) < 0) {
		os_fprintf(stderr, "%s: fail to get password\n", __func__);
		free(att);
		return NULL;
	}

	os_fprintf(stdout, "%s: password - %s, len - %d\n",
			__func__, pwd, len);

	at_pwd->type = tlv_build_type(QEV_ATTR_BSS_PASSWORD);
	at_pwd->len = tlv_build_vlen(len);
	memcpy(at_pwd->pwd, pwd, len);

	return att;
}

static uint8_t *
qtn_build_rekey_interval_attr(const char *ifname)
{
	uint8_t *att = os_zalloc(sizeof(struct attr_rekey_intv));
	struct attr_rekey_intv *at_rekey = (struct attr_rekey_intv *)att;
	uint32_t pairwise_intv = QEV_INVALID_REKEY_TIME;
	uint32_t group_intv = QEV_INVALID_REKEY_TIME;

	if (att == NULL) {
		os_fprintf(stderr, "%s: fail to allocate attr_rekey_intv\n",
				__func__);
		return NULL;
	}

	if (qcsapi_wifi_get_pairwise_key_interval(ifname, &pairwise_intv) < 0)
		os_fprintf(stderr, "%s: fail to get pairwise rekey interval\n",
				__func__);

	if (qcsapi_wifi_get_group_key_interval(ifname, &group_intv) < 0)
		os_fprintf(stderr, "%s: fail to get group rekey interval\n",
				__func__);

	os_fprintf(stdout, "%s: rekey interval - pairwise %d, group %d\n",
			__func__, pairwise_intv, group_intv);

	at_rekey->type = tlv_build_type(QEV_ATTR_BSS_REKEY_INTV);
	at_rekey->len = tlv_build_vlen(sizeof(*at_rekey) - 4);
	OS_PUT_LE32(at_rekey->pairwise, pairwise_intv);
	OS_PUT_LE32(at_rekey->group, group_intv);

	return att;
}

static uint8_t *
qtn_build_priority_attr(const char *ifname)
{
	uint8_t *att = os_zalloc(sizeof(struct attr_priority));
	struct attr_priority *at_pri = (struct attr_priority *)att;
	uint8_t bss_pri = 0;

	if (at_pri == NULL) {
		os_fprintf(stderr, "%s: fail to allocate attr_priority\n", __func__);
		return NULL;
	}

	if (qcsapi_wifi_get_priority(ifname, &bss_pri) < 0) {
		os_fprintf(stderr, "%s: fail to get priority\n", __func__);
	}

	os_fprintf(stdout, "%s: priority - %u\n", __func__, bss_pri);

	at_pri->type = tlv_build_type(QEV_ATTR_BSS_PRIORITY);
	at_pri->len = tlv_build_vlen(sizeof(*at_pri) - 4);
	at_pri->pri = bss_pri;

	return att;
}

static uint8_t *
qtn_build_wmm_params_attr(const char *ifname, int bss)
{
	uint8_t *att = os_zalloc(sizeof(struct attr_wmm_params));
	struct attr_wmm_params *at_wmm = (struct attr_wmm_params *)att;
	int ac;
	int val;

	if (at_wmm == NULL) {
		os_fprintf(stderr, "%s: fail to allocate attr_wmm_params\n", __func__);
		return NULL;
	}

	if (bss)
		at_wmm->type = tlv_build_type(QEV_ATTR_BSS_WMM_BSS);
	else
		at_wmm->type = tlv_build_type(QEV_ATTR_BSS_WMM_OWN);

	at_wmm->len = tlv_build_vlen(sizeof(*at_wmm) - 4);

	for (ac = WME_AC_BE; ac < WME_AC_NUM; ac++) {
		if (qcsapi_wifi_qos_get_param(ifname, ac, IEEE80211_WMMPARAMS_CWMIN,
						bss, &val) < 0) {
			os_fprintf(stderr, "%s: fail to get ECWMin(%d/%d) of BSS %s\n",
						__func__, bss, ac, ifname);
			goto out;
		}
		at_wmm->logcwmin[ac] = val;

		if (qcsapi_wifi_qos_get_param(ifname, ac, IEEE80211_WMMPARAMS_CWMAX,
						bss, &val) < 0) {
			os_fprintf(stderr, "%s: fail to get ECWMax(%d/%d) of BSS %s\n",
						__func__, bss, ac, ifname);
			goto out;
		}
		at_wmm->logcwmax[ac] = val;

		if (qcsapi_wifi_qos_get_param(ifname, ac, IEEE80211_WMMPARAMS_AIFS,
						bss, &val) < 0) {
			os_fprintf(stderr, "%s: fail to get AIFS(%d/%d) of BSS %s\n",
						__func__, bss, ac, ifname);
			goto out;
		}
		at_wmm->aifsn[ac] = val;

		if (qcsapi_wifi_qos_get_param(ifname, ac, IEEE80211_WMMPARAMS_TXOPLIMIT,
						bss, &val) < 0) {
			os_fprintf(stderr, "%s: fail to get TXOP(%d/%d) of BSS %s",
						__func__, bss, ac, ifname);
			goto out;
		}
		OS_PUT_LE16((uint8_t *)&at_wmm->txopLimit[ac], val);

		if (bss) {
			/* it's not allowed to query ACM parameter of "Self params" */
			if (qcsapi_wifi_qos_get_param(ifname, ac, IEEE80211_WMMPARAMS_ACM,
							bss, &val) < 0) {
				os_fprintf(stderr, "%s: fail to get ACM(%d/%d) of BSS %s\n",
							__func__, bss, ac, ifname);
				goto out;
			}
			at_wmm->acm[ac] = val;
		} else {
			/* it's not allowed to query AckPolicy parameter of "BSS params" */
			if (qcsapi_wifi_qos_get_param(ifname, ac, IEEE80211_WMMPARAMS_NOACKPOLICY,
							bss, &val) < 0) {
				os_fprintf(stderr, "%s: fail to get AckPolicy(%d/%d) of BSS %s\n",
							__func__, bss, ac, ifname);
				goto out;
			}
			at_wmm->noackPolicy[ac] = val;
		}
	}

	return att;
out:
	free(att);
	return NULL;
}

static uint8_t *
qtn_build_qtm_attr(const char *ifname)
{
	uint8_t *att = os_zalloc(sizeof(struct attr_qtm));
	struct attr_qtm *att_qtm = (struct attr_qtm *)att;
	struct qcsapi_int_array768 *rules_buf;
	struct qcsapi_int_array256 *cfg_buf;
	int attr_qtm_len;
	int nr_rules;
	int err = 0;
	int i;

	if (!att_qtm) {
		os_fprintf(stderr, "%s: fail to allocate att_qtm\n", __func__);
		err = -1;
		goto out_free;
	}

	cfg_buf = os_zalloc(sizeof(struct qcsapi_int_array256));
	if (!cfg_buf) {
		os_fprintf(stderr, "%s: fail to allocate qtm config buf\n", __func__);
		err = -1;
		goto out_free;
	}

	if (qcsapi_qtm_safe_get_config_all(ifname, cfg_buf, QVSP_CFG_MAX)) {
		os_fprintf(stderr, "%s: fail to get qtm config\n", __func__);
		err = -1;
		goto out_free_cfg;
	}

	rules_buf = os_zalloc(sizeof(struct qcsapi_int_array768));
	if (!rules_buf) {
		os_fprintf(stderr, "%s: fail to allocate qtm rules buf\n", __func__);
		err = -1;
		goto out_free_cfg;
	}

	nr_rules = qcsapi_qtm_safe_get_rule(ifname, rules_buf, QTN_QTM_MAX_RULES);
	if (nr_rules < 0) {
		os_fprintf(stderr, "%s: fail to get qtm rules\n", __func__);
		err = -1;
		goto out_free_rules;
	}

	attr_qtm_len = QVSP_CFG_MAX * sizeof(int32_t);
	attr_qtm_len += nr_rules * QVSP_RULE_PARAM_MAX * sizeof(int32_t);
	attr_qtm_len += sizeof(att_qtm->nr_rules);

	att_qtm->type = tlv_build_type(QEV_ATTR_QTM);
	att_qtm->len = tlv_build_vlen(attr_qtm_len);
	OS_PUT_LE32((uint8_t *)&(att_qtm->nr_rules), nr_rules);

	for (i = 0; i < QVSP_CFG_MAX; i++)
		OS_PUT_LE32((uint8_t *)&(att_qtm->cfg[i]), cfg_buf->val[i]);

	for (i = 0; i < nr_rules * QVSP_RULE_PARAM_MAX; i++)
		OS_PUT_LE32((uint8_t *)&(att_qtm->rule[i]), rules_buf->val[i]);

out_free_rules:
	free(rules_buf);
out_free_cfg:
	free(cfg_buf);
out_free:
	if (err) {
		if (att)
			free(att);
		return NULL;
	} else {
		return att;
	}
}

static uint8_t *
qtn_build_pmf_attr(const char *ifname)
{
	uint8_t *att = os_zalloc(sizeof(struct attr_pmf));
	struct attr_pmf *at_pmf = (struct attr_pmf *)att;
	int bss_pmf = 0;

	if (at_pmf == NULL) {
		os_fprintf(stderr, "%s: fail to allocate attr_pmf\n", __func__);
		return NULL;
	}

	if (qcsapi_wifi_get_pmf(ifname, &bss_pmf) < 0) {
		os_fprintf(stderr, "%s: fail to get pmf\n", __func__);
		free(att);
		return NULL;
	}

	os_fprintf(stdout, "%s: pmf - %d\n", __func__, bss_pmf);

	at_pmf->type = tlv_build_type(QEV_ATTR_BSS_PMF);
	at_pmf->len = tlv_build_vlen(sizeof(*at_pmf) - 4);
	at_pmf->pmf = bss_pmf;

	return att;
}

static uint8_t *
qtn_build_mac_addr_attr(const char *ifname)
{
	uint8_t *att = os_zalloc(sizeof(struct attr_mac_addr));
	struct attr_mac_addr *at_mac_addr = (struct attr_mac_addr *)att;
	qcsapi_mac_addr mac_addr = {0};

	if (at_mac_addr == NULL) {
		os_fprintf(stderr, "%s: fail to allocate attr_mac_addr\n", __func__);
		return NULL;
	}

	if (qcsapi_interface_get_mac_addr(ifname, mac_addr) < 0) {
		os_fprintf(stderr, "%s: fail to get mac address for interface %s\n",
				__func__, ifname);
		free(att);
		return NULL;
	}

	os_fprintf(stdout, "%s: interface %s mac address - " MACSTR "\n",
			__func__, ifname, MAC2STR(mac_addr));

	at_mac_addr->type = tlv_build_type(QEV_ATTR_BSS_MAC_ADDR);
	at_mac_addr->len = tlv_build_vlen(sizeof(*at_mac_addr) - 4);
	memcpy(at_mac_addr->mac_addr, mac_addr, sizeof(at_mac_addr->mac_addr));

	return att;
}

static uint8_t *
qtn_build_mdid_attr(const char *ifname)
{
	uint8_t *att = os_zalloc(sizeof(struct attr_mdid));
	struct attr_mdid *at_mdid = (struct attr_mdid *)att;
	string_16 mdid = {'\0'};

	if (at_mdid == NULL) {
		os_fprintf(stderr, "%s: fail to allocate attr_mdid\n", __func__);
		return NULL;
	}

	if (qcsapi_wifi_get_ieee80211r_mobility_domain(ifname, mdid) < 0) {
		os_fprintf(stderr, "%s: fail to get mdid for interface %s\n",
				__func__, ifname);
		free(att);
		return NULL;
	}

	os_fprintf(stdout, "%s: interface %s mdid - %s\n",
			__func__, ifname, mdid);

	at_mdid->type = tlv_build_type(QEV_ATTR_BSS_MDID);
	at_mdid->len = tlv_build_vlen(strnlen(mdid, QTN_MDID_MAX_LEN));
	memcpy(at_mdid->mdid, mdid, at_mdid->len);

	return att;
}

static struct qserver_device_params *
qtn_driver_get_device_params(void *priv, struct qserver_frm_params *frm_params)
{
	struct qtn_drv_data *drv = (struct qtn_drv_data *)priv;
	struct qserver_device_params *params = NULL;
	char ifname_list[QTN_MAX_BSSID][IFNAMSIZ + 1] = {{0}};
	char path[QSERVER_PATH_MAX + 1] = {0};
	FILE *fh = NULL;
	int bss_num = 0;
	int i;
	int ret;
	int sync_allowed;
	int wpa3_cap = QTN_WPA3_CAP_ALL;
	uint8_t key_mgmt;

	if (frm_params)
		wpa3_cap = qtn_get_peer_wpa3_cap(drv->ifname, frm_params);

	for (i = 0; i < QTN_MAX_BSSID; i++) {
		snprintf(path, QSERVER_PATH_MAX, "%s/%s%d",
			QTN_SYS_NET_PATH, QTN_WIFI_INTERFACE_NAME, i);
		fh = fopen(path, "r");
		if (fh != NULL) {
			snprintf(ifname_list[bss_num], IFNAMSIZ, "wifi%d", i);
			ret = qcsapi_wifi_get_option(ifname_list[bss_num],
						qcsapi_sync_config, &sync_allowed);
			if (ret < 0) {
				os_fprintf(stderr, "fail to get sync_config of BSS %s\n",
						__func__, ifname_list[bss_num]);
				sync_allowed = 0;
			}
			ret = qtn_get_security_key_mgmt(ifname_list[bss_num], &key_mgmt);
			if (ret == 0) {
				key_mgmt = qtn_get_comp_key_mgmt(key_mgmt, wpa3_cap);
				if (key_mgmt == QEV_KM_INVALID)
					sync_allowed = 0;
			}
			bss_num += !!sync_allowed;
			fclose(fh);
		}
	}

	if (bss_num == 0) {
		os_fprintf(stderr, "%s: don't find any wifi interface\n", __func__);
		return NULL;
	}

	os_fprintf(stdout, "%s: find %d wifi interface\n", __func__, bss_num);

	params = os_zalloc(sizeof(struct qserver_device_params));
	if (params == NULL) {
		os_fprintf(stderr, "%s: fail to allocate device params\n", __func__);
		return NULL;
	}

	params->qtm = qtn_build_qtm_attr(drv->ifname);

	params->num = bss_num;
	params->bss = os_zalloc(params->num * sizeof(struct qserver_bss_params));
	if (params->bss == NULL) {
		os_fprintf(stderr, "%s: fail to allocate bss params\n", __func__);
		free(params->qtm);
		free(params);
		return NULL;
	}

	for (i = 0; i < params->num; i++) {
		os_fprintf(stdout, "%s: BSS %s\n", __func__, ifname_list[i]);

		params->bss[i].ifidx = qtn_build_ifindex_attr(ifname_list[i], i);
		params->bss[i].band = qtn_build_band_attr(ifname_list[i]);
		params->bss[i].ssid = qtn_build_ssid_attr(ifname_list[i]);
		params->bss[i].sec = qtn_build_security_attr(ifname_list[i], wpa3_cap);
		params->bss[i].pwd = qtn_build_password_attr(ifname_list[i]);
		params->bss[i].rekey = qtn_build_rekey_interval_attr(ifname_list[i]);
		params->bss[i].pri = qtn_build_priority_attr(ifname_list[i]);
		params->bss[i].wmm_own = qtn_build_wmm_params_attr(ifname_list[i], 0);
		params->bss[i].wmm_bss = qtn_build_wmm_params_attr(ifname_list[i], 1);
		params->bss[i].pmf = qtn_build_pmf_attr(ifname_list[i]);
		params->bss[i].mac_addr = qtn_build_mac_addr_attr(ifname_list[i]);
		params->bss[i].mdid = qtn_build_mdid_attr(ifname_list[i]);
	}

	return params;
}

static struct qserver_device_params *
qtn_driver_local_parse_device_params(void *priv UNUSED_PARAM)
{
	struct qserver_device_params *params = NULL;
	char bss_name[IFNAMSIZ + 1] = {0};
	int i;

	params = os_zalloc(sizeof(struct qserver_device_params));
	if (params == NULL) {
		os_fprintf(stderr, "%s: fail to allocate device params\n",
				__func__);
		return NULL;
	}

	params->num = 1;
	params->bss = os_zalloc(params->num * sizeof(struct qserver_bss_params));
	if (params->bss == NULL) {
		os_fprintf(stderr, "%s: fail to allocate bss params\n", __func__);
		free(params);
		return NULL;
	}

	for (i = 0; i < params->num; i++) {
		snprintf(bss_name, sizeof(bss_name), "%s%d",
					QTN_WIFI_INTERFACE_NAME, i);

		os_fprintf(stdout, "%s: BSS %s\n", __func__, bss_name);

		params->bss[i].ifidx = qtn_build_ifindex_attr(bss_name, i);
		params->bss[i].band = qtn_build_band_attr(bss_name);
		params->bss[i].ssid = qtn_build_ssid_attr(bss_name);
		params->bss[i].sec = qtn_build_security_attr(bss_name, QTN_WPA3_CAP_ALL);
		params->bss[i].pwd = qtn_build_password_attr(bss_name);
		params->bss[i].rekey = qtn_build_rekey_interval_attr(bss_name);
	}

	return params;
}

static void
qtn_driver_free_device_params(void *priv UNUSED_PARAM, struct qserver_device_params *params)
{
	qserver_free_device_params(params);
}

static void
qtn_save_bss_params(FILE *fp, struct qserver_bss_params *params)
{
	const char *ac_str[] = {"BE", "BK", "VI", "VO"};
	struct attr_rekey_intv *p_rekey;
	struct attr_password *p_passwd;
	struct attr_ifindex *p_ifindex;
	struct attr_wmm_params *p_wmm;
	struct attr_security *p_sec;
	struct attr_priority *p_pri;
	struct attr_band *p_band;
	struct attr_ssid *p_ssid;
	struct attr_pmf *p_pmf;
	struct attr_mac_addr *p_mac_addr;
	struct attr_mdid *p_mdid;
	int ac;

	if (params->ifidx) {
		p_ifindex = (struct attr_ifindex *)params->ifidx;
		fprintf(fp, "ifindex=%u\n", p_ifindex->index);
	}

	if (params->band) {
		p_band = (struct attr_band *)params->band;
		fprintf(fp, "band=%u\n", p_band->band);
	}

	if (params->ssid) {
		p_ssid = (struct attr_ssid *)params->ssid;
		fprintf(fp, "ssid=%s\n", p_ssid->ssid);
	}

	if (params->sec) {
		p_sec = (struct attr_security *)params->sec;
		fprintf(fp, "key_mgmt=%u\n", p_sec->key_mgmt);
		fprintf(fp, "proto=%u\n", p_sec->proto);
		fprintf(fp, "pairwise=%u\n", p_sec->pairwise);
	}

	if (params->pwd) {
		char pwd[QTN_PASSWORD_MAX_LEN + 1] = {0};
		p_passwd = (struct attr_password *)params->pwd;
		memcpy(pwd, p_passwd->pwd, tlv_get_vlen(params->pwd));
		fprintf(fp, "password=%s\n", pwd);
	}

	if (params->rekey) {
		p_rekey = (struct attr_rekey_intv *)params->rekey;
		fprintf(fp, "wpa_ptk_rekey=%d\n",
				OS_GET_LE32((uint8_t *)&(p_rekey->pairwise)));
		fprintf(fp, "wpa_group_rekey=%d\n",
				OS_GET_LE32((uint8_t *)&(p_rekey->group)));
	}

	if (params->pri) {
		p_pri = (struct attr_priority *)params->pri;
		fprintf(fp, "vap_pri=%u\n", p_pri->pri);
	}

	if (params->pmf) {
		p_pmf = (struct attr_pmf *)params->pmf;
		fprintf(fp, "pmf=%u\n", p_pmf->pmf);
	}

	if (params->mac_addr) {
		p_mac_addr = (struct attr_mac_addr *)params->mac_addr;
		fprintf(fp, "mac_addr=" MACSTR "\n", MAC2STR(p_mac_addr->mac_addr));
	}

	if (params->wmm_own) {
		fprintf(fp, "# own WMM parameters\n");
		p_wmm = (struct attr_wmm_params *)params->wmm_own;
		for (ac = WME_AC_BE; ac < WME_AC_NUM; ac++) {
			fprintf(fp, "CWmin[%s]=%u\n", ac_str[ac], p_wmm->logcwmin[ac]);
			fprintf(fp, "CWmax[%s]=%u\n", ac_str[ac], p_wmm->logcwmax[ac]);
			fprintf(fp, "AIFS[%s]=%u\n", ac_str[ac], p_wmm->aifsn[ac]);
			fprintf(fp, "TXOP[%s]=%u\n", ac_str[ac],
					OS_GET_LE16((uint8_t *)&(p_wmm->txopLimit[ac])));
			fprintf(fp, "ACM[%s]=%u\n", ac_str[ac], p_wmm->acm[ac]);
			fprintf(fp, "AckPolicy[%s]=%u\n", ac_str[ac], p_wmm->noackPolicy[ac]);
		}
	}

	if (params->wmm_bss) {
		fprintf(fp, "# bss WMM parameters\n");
		p_wmm = (struct attr_wmm_params *)params->wmm_bss;
		for (ac = WME_AC_BE; ac < WME_AC_NUM; ac++) {
			fprintf(fp, "CWmin[%s]=%u\n", ac_str[ac], p_wmm->logcwmin[ac]);
			fprintf(fp, "CWmax[%s]=%u\n", ac_str[ac], p_wmm->logcwmax[ac]);
			fprintf(fp, "AIFS[%s]=%u\n", ac_str[ac], p_wmm->aifsn[ac]);
			fprintf(fp, "TXOP[%s]=%u\n", ac_str[ac],
					OS_GET_LE16((uint8_t *)&(p_wmm->txopLimit[ac])));
			fprintf(fp, "ACM[%s]=%u\n", ac_str[ac], p_wmm->acm[ac]);
			fprintf(fp, "AckPolicy[%s]=%u\n", ac_str[ac], p_wmm->noackPolicy[ac]);
		}
	}

	if (params->mdid) {
		fprintf(fp, "# bss mobility domain parameters\n");
		p_mdid = (struct attr_mdid *)params->mdid;
		fprintf(fp, "mobility_domain=%s\n", p_mdid->mdid);
	}

	/* save more BSS TLVs here */

	fprintf(fp, "\n");
}

static void
qtn_save_qtm_params(FILE *fp, uint8_t *qtm_tlv)
{
	const struct qvsp_rule_param rules[] = QVSP_RULE_PARAMS;
	const struct qvsp_cfg_param cfgs[] = QVSP_CFG_PARAMS;
	struct attr_qtm *p_qtm = (struct attr_qtm *)qtm_tlv;
	struct qvsp_rule_flds *p_rule;
	int nr_rules;
	int i;
	int j;

	fprintf(fp, "# QTM configs\n");
	for (i = 0; i < QVSP_CFG_MAX; i++)
		fprintf(fp, "%s=%d\n", cfgs[i].name,
				OS_GET_LE32((uint8_t *)&(p_qtm->cfg[i])));

	nr_rules = OS_GET_LE32((uint8_t *)&(p_qtm->nr_rules));
	p_rule = (struct qvsp_rule_flds *)(p_qtm->rule);

	for (i = 0; i < nr_rules; i++) {
		fprintf(fp, "# QTM rules %d\n", i);
		for (j = QVSP_RULE_PARAM_DIR; j < QVSP_RULE_PARAM_MAX; j++) {
			fprintf(fp, "%s=%d\n", rules[j].name,
					OS_GET_LE32((uint8_t *)&(p_rule->param[j])));
		}
		p_rule++;
	}
}

static void
qtn_driver_save_device_params_to_file(void *priv UNUSED_PARAM,
		const char *params_filename,
		struct qserver_device_params *params)
{
	const char *filepath = NULL;
	FILE *fp = NULL;
	int i;

	if (!params) {
		os_fprintf(stderr, "%s: NULL params\n", __func__);
		return;
	}

	if (params_filename && params_filename[0] != '\0')
		filepath = params_filename;
	else
		filepath = QTN_PARAMS_FILENAME_DEFAULT;

	os_fprintf(stdout, "%s: save device params to %s\n", __func__, filepath);

	fp = fopen(filepath, "w+");
	if (!fp) {
		os_fprintf(stderr, "%s: fail to open %s - error %s\n", __func__,
				filepath, strerror(errno));
		return;
	}

	for (i = 0; i < params->num; i++)
		qtn_save_bss_params(fp, &params->bss[i]);

	if (params->qtm)
		qtn_save_qtm_params(fp, params->qtm);


	/* save more TLVs here */

	fclose(fp);
}


static int
qtn_set_bss_ssid(void *priv, uint8_t *tlv, char *bss_name)
{
	struct qtn_drv_data *drv = (struct qtn_drv_data *)priv;
	struct attr_ssid *att_ssid = (struct attr_ssid *)tlv;
	qcsapi_SSID ssid = {'\0'};
	qcsapi_SSID cur_ssid = {'\0'};
	uint16_t ssid_len;
	int ret;

	if (tlv == NULL) {
		os_fprintf(stdout, "%s: null ssid attribute\n", __func__);
		return 0;
	}

	ssid_len = tlv_get_vlen(tlv);
	if (ssid_len > QTN_SSID_LEN) {
		os_fprintf(stderr, "%s: invalid SSID length %d\n",
				__func__, ssid_len);
		return -1;
	}

	/* Get current SSID of assigned BSS */
	ret = qcsapi_wifi_get_bss_cfg(drv->ifname, qcsapi_access_point,
					bss_name, "ssid", cur_ssid, sizeof(cur_ssid));
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to get current SSID for bss %s"
				" - errno %d\n", __func__, bss_name, ret);
		goto update;
	}

	/* Check if new SSID needs to be updated */
	memcpy(ssid, att_ssid->ssid, ssid_len);
	if ((ssid_len == strlen(cur_ssid)) && (!strncmp(ssid, cur_ssid, ssid_len))) {
		os_fprintf(stdout, "%s: no difference on SSID for BSS %s\n",
			__func__, bss_name);
		return 0;
	}

update:
	/* Update new SSID into security daemon configuration file */
	os_fprintf(stdout, "%s: set BSS %s \"SSID\" %s\n", __func__, bss_name, ssid);

	ret = qcsapi_wifi_update_bss_cfg(drv->ifname, qcsapi_access_point,
				bss_name, "ssid", ssid, NULL);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to set \"SSID\" %s for bss %s"
				" - errno %d\n", __func__, ssid, bss_name, ret);
		return ret;
	}

	return 1;
}

static int
qtn_set_bss_security(void *priv, uint8_t *tlv, char *bss_name)
{
	struct qtn_drv_data *drv = (struct qtn_drv_data *)priv;
	struct attr_security *att_sec = (struct attr_security *)tlv;
	char cur_key_mgmt_str[32]= {'\0'};
	char cur_proto_str[32]= {'\0'};
	char cur_pairwise_str[32]= {'\0'};
	char *key_mgmt_str = NULL;
	char *proto_str = NULL;
	char *pairwise_str = NULL;
	uint16_t sec_len;
	int updated = 0;
	int ret;

	if (tlv == NULL) {
		os_fprintf(stdout, "%s: null security attribute\n", __func__);
		return 0;
	}

	sec_len = tlv_get_vlen(tlv);
	if (sec_len != (sizeof(*att_sec) - 4)) {
		os_fprintf(stderr, "%s: invalid security attribute length %d\n",
				__func__, sec_len);
		return -1;
	}

	if ((att_sec->key_mgmt != QEV_KM_INVALID) &&
		(att_sec->key_mgmt < ARRAYSIZE(qserver_key_mgmt_table))) {
		key_mgmt_str = qserver_key_mgmt_table[att_sec->key_mgmt].hostapd_str;
	} else {
		os_fprintf(stderr, "%s: invalid key_mgmt index %d\n",
				__func__, att_sec->key_mgmt);
		return -1;
	}

	if ((att_sec->proto != QEV_PT_INVALID) &&
		(att_sec->proto < ARRAYSIZE(qserver_proto_table))) {
		proto_str = qserver_proto_table[att_sec->proto].hostapd_str;
	} else {
		os_fprintf(stderr, "%s: invalid proto index %d\n",
				__func__, att_sec->proto);
		return -1;
	}

	if ((att_sec->pairwise != QEV_EP_INVALID) &&
		(att_sec->pairwise < ARRAYSIZE(qserver_encrypt_table))) {
		pairwise_str = qserver_encrypt_table[att_sec->pairwise].hostapd_str;
	} else {
		os_fprintf(stderr, "%s: invalid pairwise encryption index %d\n",
				__func__, att_sec->pairwise);
		return -1;
	}

	ret = qcsapi_wifi_get_bss_cfg(drv->ifname, qcsapi_access_point,
				bss_name, "wpa_key_mgmt", cur_key_mgmt_str,
				sizeof(cur_key_mgmt_str));
	if ((ret < 0) || strcmp(key_mgmt_str, cur_key_mgmt_str)) {
		os_fprintf(stdout, "%s: set BSS %s \"wpa_key_mgmt\" %s\n",
			__func__, bss_name, key_mgmt_str);

		ret = qcsapi_wifi_update_bss_cfg(drv->ifname, qcsapi_access_point,
				bss_name, "wpa_key_mgmt", key_mgmt_str, NULL);
		if (ret < 0) {
			os_fprintf(stderr, "%s: fail to set \"wpa_key_mgmt\" %s "
				"for bss %s - errno %d\n", __func__,
				key_mgmt_str, bss_name, ret);
			return ret;
		}
		updated = 1;
	}

	ret = qcsapi_wifi_get_bss_cfg(drv->ifname, qcsapi_access_point, bss_name,
				"wpa", cur_proto_str, sizeof(cur_proto_str));
	if ((ret < 0) || strcmp(proto_str, cur_proto_str)) {
		os_fprintf(stdout, "%s: set BSS %s \"wpa\" %s\n",
			__func__, bss_name, proto_str);

		ret = qcsapi_wifi_update_bss_cfg(drv->ifname, qcsapi_access_point,
				bss_name, "wpa", proto_str, NULL);
		if (ret < 0) {
			os_fprintf(stderr, "%s: fail to set \"wpa\" %s for bss %s"
				" - errno %d\n", __func__, proto_str, bss_name, ret);
			return ret;
		}
		updated = 1;
	}

	ret = qcsapi_wifi_get_bss_cfg(drv->ifname, qcsapi_access_point, bss_name,
					"wpa_pairwise", cur_pairwise_str,
					sizeof(cur_pairwise_str));
	if ((ret < 0) || strcmp(pairwise_str, cur_pairwise_str)) {
		os_fprintf(stdout, "%s: set BSS %s \"wpa_pairwise\" %s\n",
			__func__, bss_name, pairwise_str);

		ret = qcsapi_wifi_update_bss_cfg(drv->ifname, qcsapi_access_point,
				bss_name, "wpa_pairwise", pairwise_str, NULL);
		if (ret < 0) {
			os_fprintf(stderr, "%s: fail to set \"wpa_pairwise\" %s"
					" for bss %s - errno %d\n", __func__,
					pairwise_str, bss_name, ret);
			return ret;
		}
		updated = 1;
	}

	if (updated == 0)
		os_fprintf(stdout, "%s: no difference on secuirty information"
			" for bss %s\n", __func__, bss_name);

	return updated;
}

static int
qtn_set_bss_password(void *priv, uint8_t *tlv, char *bss_name)
{
	struct qtn_drv_data *drv = (struct qtn_drv_data *)priv;
	struct attr_password *att_pwd = (struct attr_password *)tlv;
	char pwd[QTN_PASSWORD_MAX_LEN + 1] = {'\0'};
	char cur_pwd[QTN_PASSWORD_MAX_LEN + 1] = {'\0'};
	char *pwd_name_str = NULL;
	char *alt_pwd_name_str = NULL;
	uint16_t pwd_len;
	int ret;

	if (tlv == NULL) {
		os_fprintf(stdout, "%s: null password attribute\n", __func__);
		return 0;
	}

	pwd_len = tlv_get_vlen(tlv);
	if ((pwd_len < QTN_PASSWORD_MIN_LEN) ||
			(pwd_len > QTN_PASSWORD_MAX_LEN)) {
		os_fprintf(stderr, "%s: invalid password length %d\n",
				__func__, pwd_len);
		return -1;
	}

	memcpy(pwd, att_pwd->pwd, pwd_len);
	if (pwd_len == QTN_PASSWORD_MAX_LEN) {
		pwd_name_str = "wpa_psk";
		alt_pwd_name_str = "wpa_passphrase";
	} else {
		pwd_name_str = "wpa_passphrase";
		alt_pwd_name_str = "wpa_psk";
	}

	/* Get current password of assigned BSS */
	ret = qcsapi_wifi_get_bss_cfg(drv->ifname, qcsapi_access_point,
					bss_name, pwd_name_str, cur_pwd,
					sizeof(cur_pwd));
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to get current password for bss %s"
				" - errno %d\n", __func__, bss_name, ret);
		goto update;
	}

	/* Check if new security information needs to be updated */
	if (!strcmp(pwd, cur_pwd)) {
		os_fprintf(stdout, "%s: no difference on password for BSS %s\n",
			__func__, bss_name);
		return 0;
	}

update:
	/* Update new password into security daemon configuration file */
	os_fprintf(stdout, "%s: set BSS %s \"%s\" %s\n", __func__,
			bss_name, pwd_name_str, pwd);

	qcsapi_wifi_update_bss_cfg(drv->ifname, qcsapi_access_point,
				bss_name, alt_pwd_name_str, "null", NULL);
	ret = qcsapi_wifi_update_bss_cfg(drv->ifname, qcsapi_access_point,
				bss_name, pwd_name_str, pwd, NULL);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to set \"%s\" %s for bss %s"
			" - errno %d\n", __func__, att_pwd, pwd, bss_name, ret);
		return ret;
	}

	return 1;
}

static int
qtn_set_bss_rekey_interval(void *priv, uint8_t *tlv, char *bss_name)
{
	struct qtn_drv_data *drv = (struct qtn_drv_data *)priv;
	struct attr_rekey_intv *att_rekey = (struct attr_rekey_intv *)tlv;
	char cur_group_intv[QTN_REKEY_STR_LEN] = {'\0'};
	char cur_ptk_intv[QTN_REKEY_STR_LEN] = {'\0'};
	char group_intv[QTN_REKEY_STR_LEN] = {'\0'};
	char ptk_intv[QTN_REKEY_STR_LEN] = {'\0'};
	uint16_t rekey_len;
	int updated = 0;
	int ret;

	if (tlv == NULL) {
		os_fprintf(stdout, "%s: null rekey interval attribute\n",
				__func__);
		return 0;
	}

	rekey_len = tlv_get_vlen(tlv);
	if (rekey_len != (sizeof(*att_rekey) - 4)) {
		os_fprintf(stderr, "%s: invalid rekey attribute length %d\n",
				__func__, rekey_len);
		return -1;
	}

	snprintf(ptk_intv, sizeof(ptk_intv), "%d", OS_GET_LE32(att_rekey->pairwise));
	snprintf(group_intv, sizeof(group_intv), "%d", OS_GET_LE32(att_rekey->group));

	if (OS_GET_LE32(att_rekey->group) != (uint32_t)QEV_INVALID_REKEY_TIME) {
		ret = qcsapi_wifi_get_bss_cfg(drv->ifname, qcsapi_access_point,
				bss_name, "wpa_group_rekey", cur_group_intv,
				sizeof(cur_group_intv));
		if ((ret < 0) || strcmp(group_intv, cur_group_intv)) {
			os_fprintf(stdout, "%s: set BSS %s \"wpa_group_rekey\" %s\n",
				__func__, bss_name, group_intv);

			ret = qcsapi_wifi_update_bss_cfg(drv->ifname, qcsapi_access_point,
					bss_name, "wpa_group_rekey", group_intv, NULL);
			if (ret < 0) {
				os_fprintf(stderr, "%s: fail to set \"wpa_group_rekey\""
					" %s for bss %s - errno %d\n", __func__,
					group_intv, bss_name, ret);
				return ret;
			}
			updated = 1;
		}
	}

	if (OS_GET_LE32(att_rekey->pairwise) != (uint32_t)QEV_INVALID_REKEY_TIME) {
		ret = qcsapi_wifi_get_bss_cfg(drv->ifname, qcsapi_access_point,
					bss_name, "wpa_ptk_rekey", cur_ptk_intv,
					sizeof(cur_ptk_intv));
		if ((ret < 0) || strcmp(ptk_intv, cur_ptk_intv)) {
			os_fprintf(stdout, "%s: set BSS %s \"wpa_ptk_rekey\" %s\n",
				__func__, bss_name, ptk_intv);

			ret = qcsapi_wifi_update_bss_cfg(drv->ifname, qcsapi_access_point,
					bss_name, "wpa_ptk_rekey", ptk_intv, NULL);
			if (ret < 0) {
				os_fprintf(stderr, "%s: fail to set \"wpa_ptk_rekey\""
					" %s for bss %s - errno %d\n", __func__,
					ptk_intv, bss_name, ret);
				return ret;
			}
			updated = 1;
		}
	}

	if (updated == 0)
		os_fprintf(stdout, "%s: no difference on rekey time for bss %s\n",
			__func__, bss_name);

	return updated;
}

static int
qtn_set_bss_priority(void *priv UNUSED_PARAM, uint8_t *tlv, char *bss_name)
{
	struct attr_priority *att_pri = (struct attr_priority *)tlv;
	uint16_t pri_len;
	int ret;

	if (tlv == NULL) {
		os_fprintf(stdout, "%s: null VAP priority\n", __func__);
		return 0;
	}

	pri_len = tlv_get_vlen(tlv);
	if (pri_len != (sizeof(*att_pri) - 4)) {
		os_fprintf(stderr, "%s: invalid priority attribute length %u\n",
				__func__, pri_len);
		return -1;
	}

	os_fprintf(stdout, "%s: set BSS %s \"priority\" %u\n", __func__,
				bss_name, att_pri->pri);

	ret = qcsapi_wifi_set_priority(bss_name, att_pri->pri);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to set \"priority\" %u "
			"for bss %s - errno %d\n", __func__, att_pri->pri,
			bss_name, ret);
		return ret;
	}

	return 0;
}

static int
qtn_set_bss_wmm_params(void *priv UNUSED_PARAM, uint8_t *tlv, char *bss_name, int bss)
{
	struct attr_wmm_params *att_wmm = (struct attr_wmm_params *)tlv;
	int ac;
	int val;
	int ret;
	uint16_t wmm_len;

	if (tlv == NULL) {
		os_fprintf(stdout, "%s: null WMM parameters\n", __func__);
		return 0;
	}

	wmm_len = tlv_get_vlen(tlv);
	if (wmm_len != (sizeof(*att_wmm) - 4)) {
		os_fprintf(stderr, "%s: invalid WMM parameter attribute length %u\n",
				__func__, wmm_len);
		return -1;
	}

	for (ac = WME_AC_BE; ac < WME_AC_NUM; ac++) {
		val = att_wmm->logcwmin[ac];
		os_fprintf(stdout, "%s: set BSS %s AC %d/%d \"ECWMin\" %u\n",
					__func__, bss_name, bss, ac, val);
		ret = qcsapi_wifi_qos_set_param(bss_name, ac, IEEE80211_WMMPARAMS_CWMIN,
					bss, val);
		if (ret < 0) {
			os_fprintf(stderr, "%s: fail to set AC %d/%d \"ECWMin\" %u ",
						"for BSS %s - errno %d\n",
						__func__, bss, ac, val, bss_name, ret);
			return ret;
		}

		val = att_wmm->logcwmax[ac];
		os_fprintf(stdout, "%s: set BSS %s AC %d/%d \"ECWMax\" %u\n",
					__func__, bss_name, bss, ac, val);
		ret = qcsapi_wifi_qos_set_param(bss_name, ac, IEEE80211_WMMPARAMS_CWMAX,
					bss, val);
		if (ret < 0) {
			os_fprintf(stderr, "%s: fail to set AC %d/%d \"ECWMax\" %u "
						"for BSS %s - errno %d\n",
						__func__, bss, ac, val, bss_name, ret);
			return ret;
		}

		val = att_wmm->aifsn[ac];
		os_fprintf(stdout, "%s: set BSS %s AC %d/%d \"AIFS\" %u\n",
					__func__, bss_name, bss, ac, val);
		ret = qcsapi_wifi_qos_set_param(bss_name, ac, IEEE80211_WMMPARAMS_AIFS,
					bss, val);
		if (ret < 0) {
			os_fprintf(stderr, "%s: fail to set AC %d/%d \"AIFS\" %u ",
						"for BSS %s - errno %d\n",
						__func__, bss, ac, val, bss_name, ret);
			return ret;
		}

		val = OS_GET_LE16((uint8_t *)&att_wmm->txopLimit[ac]);
		os_fprintf(stdout, "%s: set BSS %s AC %d/%d \"TXOP\" %u\n",
					__func__, bss_name, bss, ac, val);
		ret = qcsapi_wifi_qos_set_param(bss_name, ac, IEEE80211_WMMPARAMS_TXOPLIMIT,
					bss, val);
		if (ret < 0) {
			os_fprintf(stderr, "%s: fail to set AC %d/%d \"TXOP\" %u "
						"for BSS %s - errno %d\n",
						__func__, bss, ac, val, bss_name, ret);
			return ret;
		}

		if (bss) {
			/* it's not allowed to set ACM parameter of "Self params" */
			val = att_wmm->acm[ac];
			os_fprintf(stdout, "%s: set BSS %s AC %d/%d \"ACM\" %u\n",
						__func__, bss_name, bss, ac, val);
			ret = qcsapi_wifi_qos_set_param(bss_name, ac,
						IEEE80211_WMMPARAMS_ACM, bss, val);
			if (ret < 0) {
				os_fprintf(stderr, "%s: fail to set AC %d/%d \"ACM\" %u "
							"for BSS %s - errno %d\n",
							__func__, bss, ac, val, bss_name, ret);
				return ret;
			}
		} else {
			/* it's not allowed to set AckPolicy parameter of "BSS params" */
			val = att_wmm->noackPolicy[ac];
			os_fprintf(stdout, "%s: set BSS %s AC %d/%d \"AckPolicy\" %u\n",
						__func__, bss_name, bss, ac, val);
			ret = qcsapi_wifi_qos_set_param(bss_name, ac,
						IEEE80211_WMMPARAMS_NOACKPOLICY, bss, val);
			if (ret < 0) {
				os_fprintf(stderr, "%s: fail to set AC %d/%d \"AckPolicy\" %u "
							"for BSS %s - errno %d\n",
							__func__, bss, ac, val, bss_name, ret);
				return ret;
			}
		}
	}

	return 0;
}

static int
qtn_set_bss_pmf(void *priv UNUSED_PARAM, uint8_t *tlv, char *bss_name)
{
	struct qtn_drv_data *drv = (struct qtn_drv_data *)priv;
	struct attr_pmf *att_pmf = (struct attr_pmf *)tlv;
	char cur_pmf_str[QTN_PMF_MAX_LEN + 1] = {0};
	char pmf_str[QTN_PMF_MAX_LEN + 1] = {0};
	int ret;

	if (tlv == NULL) {
		os_fprintf(stdout, "%s: null PMF\n", __func__);
		return 0;
	}

	if (att_pmf->len != (sizeof(*att_pmf) - 4)) {
		os_fprintf(stderr, "%s: invalid PMF attribute length %u\n",
				__func__, att_pmf->len);
		return -1;
	}

	snprintf(pmf_str, sizeof(pmf_str), "%u", att_pmf->pmf);

	/* Get current password of assigned BSS */
	ret = qcsapi_wifi_get_bss_cfg(drv->ifname, qcsapi_access_point,
					bss_name, "ieee80211w", cur_pmf_str,
					sizeof(cur_pmf_str));
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to get current ieee80211w for bss %s"
				" - errno %d\n", __func__, bss_name, ret);
		goto update;
	}

	/* Check if new ieee80211w needs to be updated */
	if (!strcmp(pmf_str, cur_pmf_str)) {
		os_fprintf(stdout, "%s: no difference on ieee80211w for BSS %s\n",
			__func__, bss_name);
		return 0;
	}

update:
	/* Update new ieee80211w into security daemon configuration file */
	os_fprintf(stdout, "%s: set BSS %s \"ieee80211w\" %u\n", __func__,
				bss_name, att_pmf->pmf);

	ret = qcsapi_wifi_update_bss_cfg(drv->ifname, qcsapi_access_point,
				bss_name, "ieee80211w", pmf_str, NULL);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to set \"ieee80211w\" %s "
			"for bss %s - errno %d\n", __func__, pmf_str,
			bss_name, ret);
		return ret;
	}

	return 1;
}

static int
qtn_set_bss_mdid(void *priv UNUSED_PARAM, uint8_t *tlv, char *bss_name)
{
	struct qtn_drv_data *drv = (struct qtn_drv_data *)priv;
	struct attr_mdid *att_mdid = (struct attr_mdid *)tlv;
	string_16 cur_mdid = {'\0'};
	string_16 mdid = {'\0'};
	uint16_t mdid_len;
	int ret;

	if (tlv == NULL) {
		os_fprintf(stdout, "%s: null MDID\n", __func__);
		return 0;
	}

	mdid_len = tlv_get_vlen(tlv);
	if (mdid_len > QTN_MDID_MAX_LEN) {
		os_fprintf(stderr, "%s: invalid MDID length %d\n",
				__func__, mdid_len);
		return -1;
	}

	memcpy(mdid, att_mdid->mdid, mdid_len);

	/* Get current mdid of assigned BSS */
	ret = qcsapi_wifi_get_ieee80211r_mobility_domain(drv->ifname, cur_mdid);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to get current mobility_domain for bss %s"
				" - errno %d\n", __func__, bss_name, ret);
		goto update;
	}

	/* Check if new mobility_domain needs to be updated */
	if (!strcmp(mdid, cur_mdid)) {
		os_fprintf(stdout, "%s: no difference on mdid for BSS %s\n",
			__func__, bss_name);
		return 0;
	}

update:
	/* Update new mobility_domain into security daemon configuration file */
	os_fprintf(stdout, "%s: set BSS %s \"mobility_domain\" %s\n", __func__,
			bss_name, mdid);

	ret = qcsapi_wifi_update_bss_cfg(drv->ifname, qcsapi_access_point,
				bss_name, "mobility_domain", mdid, NULL);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to set \"mobility_domain\" %s "
			"for bss %s - errno %d\n", __func__, mdid,
			bss_name, ret);
		return ret;
	}

	return 1;
}

static int
qtn_set_bss_params(void *priv, char *bss_name,
	struct qserver_bss_params *params)
{
	int param_changed = 0;
	int ret;

	os_fprintf(stdout, "%s: start to update BSS %s parameters\n",
			__func__, bss_name);

	ret = qtn_set_bss_ssid(priv, params->ssid, bss_name);
	if (ret < 0)
		goto fail;
	else if (ret > 0)
		param_changed = 1;

	ret = qtn_set_bss_security(priv, params->sec, bss_name);
	if (ret < 0)
		goto fail;
	else if (ret > 0)
		param_changed = 1;

	ret = qtn_set_bss_password(priv, params->pwd, bss_name);
	if (ret < 0)
		goto fail;
	else if (ret > 0)
		param_changed = 1;

	ret = qtn_set_bss_rekey_interval(priv, params->rekey, bss_name);
	if (ret < 0)
		goto fail;
	else if (ret > 0)
		param_changed = 1;

	ret = qtn_set_bss_pmf(priv, params->pmf, bss_name);
	if (ret < 0)
		goto fail;
	else if (ret > 0)
		param_changed = 1;

	ret = qtn_set_bss_mdid(priv, params->mdid, bss_name);
	if (ret < 0)
		goto fail;
	else if (ret > 0)
		param_changed = 1;

	if (param_changed == 0)
		os_fprintf(stdout, "%s: nothing change for bss %s\n",
			__func__, bss_name);

	return param_changed;

fail:
	return ret;
}

static int qtn_set_qtm_config(void *priv, uint8_t *tlv)
{
	struct qtn_drv_data *drv = (struct qtn_drv_data *)priv;
	struct attr_qtm *p_qtm = (struct attr_qtm *)tlv;
	int ret = 0;
	int value;
	int i;

	for (i = QVSP_CFG_ENABLED; i < QVSP_CFG_MAX; i++) {
		value = OS_GET_LE32((uint8_t *)&(p_qtm->cfg[i]));
		os_fprintf(stdout, "%s: set param %d value %d\n", __func__, i, value);
		ret = qcsapi_qtm_set_config(drv->ifname, i, value);
		if (ret < 0) {
			if (ret == -qcsapi_not_supported) {
				os_fprintf(stderr, "%s: param %d is not supported\n", __func__, i);
			} else {
				os_fprintf(stderr, "%s: failed to set param %d\n", __func__, i);
			}
		}
	}

	return 0;
}

static int qtn_set_qtm_rules(void *priv, uint8_t *tlv)
{
	struct qtn_drv_data *drv = (struct qtn_drv_data *)priv;
	struct attr_qtm *p_qtm = (struct attr_qtm *)tlv;
	struct qcsapi_int_array32 rule_buf;
	struct qvsp_rule_flds *p_rule;
	struct qvsp_rule_flds rule;
	int nr_rules;
	int ret = 0;
	int i;
	int j;

	/* delete all existing rules first */
	qcsapi_qtm_del_rule_index(drv->ifname, ~0);

	nr_rules = OS_GET_LE32((uint8_t *)&(p_qtm->nr_rules));

	p_rule = (struct qvsp_rule_flds *)(p_qtm->rule);

	for (i = 0; i < nr_rules; i++) {
		for (j = QVSP_RULE_PARAM_DIR; j < QVSP_RULE_PARAM_MAX; j++)
			rule.param[j] = OS_GET_LE32((uint8_t *)&(p_rule->param[j]));

		memcpy(rule_buf.val, &rule, sizeof(rule_buf.val));
		ret = qcsapi_qtm_safe_add_rule(drv->ifname, &rule_buf);
		if (ret < 0) {
			os_fprintf(stderr, "%s: failed to add rule %d\n", __func__, i);
			return ret;
		}
		p_rule++;
	}

	return 0;
}

static int qtn_set_qtm(void *priv, uint8_t *tlv)
{
	int ret = 0;

	if (!tlv) {
		os_fprintf(stderr, "%s: qtm tlv is null\n", __func__);
		return -1;
	}

	ret = qtn_set_qtm_config(priv, tlv);
	if (ret < 0)
		return ret;

	ret = qtn_set_qtm_rules(priv, tlv);
	if (ret < 0)
		return ret;

	return 0;
}

static int
qtn_init_wps_serial_num(void *priv, const char *bss_name, int bss_index)
{
	struct qtn_drv_data *drv = (struct qtn_drv_data *)priv;
	char serial_number[QTN_SERIAL_NUM_LEN] = {0};
	qcsapi_mac_addr mac_addr = {0};
	int ret;

	os_random_array(mac_addr, sizeof(mac_addr), bss_index);
	snprintf(serial_number, sizeof(serial_number),
		"%02x%02x%02x%02x%02x%02x",
		mac_addr[0], mac_addr[1], mac_addr[2],
		mac_addr[3], mac_addr[4], mac_addr[5]);

	ret = qcsapi_wifi_update_bss_cfg(drv->ifname, qcsapi_access_point,
		bss_name, "serial_number", serial_number, NULL);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to set serial number %s "
			"for BSS %s - errno %d\n", __func__,
			serial_number, bss_name, ret);
		return ret;
	}

	return 0;
}

static int
qtn_driver_get_device_mode(void *priv, int *mode)
{
	struct qtn_drv_data *drv = (struct qtn_drv_data *)priv;
	string_64 board_name = {0};
	int ret;
	qcsapi_dev_mode dev_mode;

	*mode = QSVR_DEV_UNKNOWN;

	ret = qcsapi_get_device_mode(drv->ifname, &dev_mode);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to get device mode\n", __func__);
		return -1;
	}

	*mode = dev_mode;

	if (*mode == QSVR_DEV_UNKNOWN) {
		ret = qcsapi_get_board_parameter(qcsapi_name, board_name);
		if (ret < 0)
			os_fprintf(stdout, "%s: fail to get board name\n",
				__func__);

		if (!strcasecmp(board_name, "QHS864_HOST"))
			*mode = QSVR_DEV_864_HOST;
		else if (!strcasecmp(board_name, "QHS864_CLIENT"))
			*mode = QSVR_DEV_864_CLIENT;
	}

	os_fprintf(stdout, "%s: device %s mode %d\n", __func__,
			drv->ifname, *mode);

	return 0;
}

static int
qtn_driver_get_device_capas(void *priv, int *capas)
{
	struct qtn_drv_data *drv = (struct qtn_drv_data *)priv;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	int ret;

	*capas = 0;

	ret = qcsapi_wifi_get_mode(drv->ifname, &wifi_mode);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to get wifi mode for interface %s"
			" - errno %d\n", __func__, drv->ifname, ret);
		return ret;
	} else {
		if (wifi_mode == qcsapi_access_point)
			*capas |= QEV_DEV_CAPA_RESP;
	}

	os_fprintf(stdout, "%s: device %s capabilities 0x%08x\n", __func__,
			drv->ifname, *capas);

	return 0;
}

static int
qtn_driver_get_device_connect_status(void *priv, int *status)
{
	struct qtn_drv_data *drv = (struct qtn_drv_data *)priv;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	qcsapi_unsigned_int count = 0;
	int ret;

	*status = QSVR_DEV_UNCONNECT;

	ret = qcsapi_wifi_get_mode(drv->ifname, &wifi_mode);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to get wifi mode for interface %s"
			" - errno %d\n", __func__, drv->ifname, ret);
		return ret;
	}

	if (wifi_mode != qcsapi_station) {
		os_fprintf(stderr, "%s: only STA mode allowed", __func__);
		return -1;
	}

	ret = qcsapi_wifi_get_count_associations(drv->ifname, &count);
	if ((ret >= 0) && (count > 0))
		*status = QSVR_DEV_WIFI_CONNECT;

	os_fprintf(stdout, "%s: device %s connect status %u\n", __func__,
			drv->ifname, *status);

	return ret;
}

static int
qtn_qhop_should_deliver_device_params(void *priv UNUSED_PARAM,
	struct qserver_frm_params *params, int role)
{
	int deliver = 0;

	if ((role == QSVR_DEV_MBS) && (params->role == QSVR_DEV_RBS))
		deliver = 1;

	os_fprintf(stdout, "%s: %s would%s deliver device parameters "
			"to %s " MACSTR "\n", __func__, qserver_dev_mode2str(role),
			deliver ? "" : " not", qserver_dev_mode2str(params->role),
			MAC2STR(params->sa));

	return deliver;
}

static int
qtn_qhop_should_accept_device_params(void *priv,
	struct qserver_frm_params *params, int role)
{
	struct qtn_drv_data *drv = (struct qtn_drv_data *)priv;
	struct attr_ssid *att_ssid;
	struct attr_mac_addr *att_mac;
	qcsapi_SSID ssid = {'\0'};
	qcsapi_SSID tmp_ssid = {'\0'};
	qcsapi_mac_addr bssid = {0};
	qcsapi_mac_addr null_mac = {0};
	qcsapi_mac_addr tmp_mac = {0};
	int accepted = 0;
	int i;

	if ((role == QSVR_DEV_RBS) && (params->role == QSVR_DEV_MBS)) {
		if (qcsapi_wifi_get_SSID(drv->ifname, ssid) < 0)
			goto out;

		if (qcsapi_wifi_get_BSSID(drv->ifname, bssid) < 0)
			goto out;

		if (memcmp(bssid, null_mac, sizeof(bssid)) == 0)
			goto out;

		os_fprintf(stdout, "%s: BSSID " MACSTR " SSID %s\n",
				__func__, MAC2STR(bssid), ssid);

		for (i = 0; i < params->device.num; i++) {
			att_ssid = (struct attr_ssid *)params->device.bss[i].ssid;
			att_mac = (struct attr_mac_addr *)params->device.bss[i].mac_addr;

			if (att_ssid)
				strncpy(tmp_ssid, att_ssid->ssid, att_ssid->len);
			else
				tmp_ssid[0] = '\0';

			if (att_mac)
				memcpy(tmp_mac, att_mac->mac_addr, sizeof(tmp_mac));
			else
				memcpy(tmp_mac, null_mac, sizeof(tmp_mac));

			os_fprintf(stdout, "%s: BSS %d BSSID " MACSTR " SSID %s\n",
				__func__, i, MAC2STR(tmp_mac), tmp_ssid);

			if (att_ssid && !strncmp(att_ssid->ssid,
					ssid, att_ssid->len)) {
				/*
				 * Besides SSID matching, also check BSSID matching
				 * when it exists
				 */
				if (!att_mac || !memcmp(att_mac->mac_addr,
						bssid, ETH_ALEN)) {
					accepted = 1;
					break;
				}
			}
		}
	}

out:
	os_fprintf(stdout, "%s: %s would%s accept device parameters "
		"from %s " MACSTR "\n", __func__, qserver_dev_mode2str(role),
		accepted ? "" : " not", qserver_dev_mode2str(params->role),
		MAC2STR(params->sa));

	return accepted;
}

static int
qtn_driver_should_deliver_device_params(void *priv,
	struct qserver_frm_params *params, int *deliver)
{
	int role = QSVR_DEV_UNKNOWN;

	*deliver = 1;

	qtn_driver_get_device_mode(priv, &role);
	if ((role == QSVR_DEV_MBS) || (role == QSVR_DEV_RBS))
		*deliver = qtn_qhop_should_deliver_device_params(priv, params, role);

	os_fprintf(stdout, "%s: should%s deliver the device parameters\n",
			__func__, *deliver ? "" : " not");

	return 0;
}

static int
qtn_driver_should_accept_device_params(void *priv,
	struct qserver_frm_params *params, int *accepted)
{
	int role = QSVR_DEV_UNKNOWN;

	*accepted = 1;

	qtn_driver_get_device_mode(priv, &role);

	if ((role == QSVR_DEV_MBS) || (role == QSVR_DEV_RBS))
		*accepted = qtn_qhop_should_accept_device_params(priv, params, role);

	os_fprintf(stdout, "%s: should%s accept the device parameters\n",
			__func__, *accepted ? "" : " not");

	return 0;
}

/*
 * QTN Repeater implements wifi0 as primary interface and
 * STA role of repeater. When applying AP parameters from
 * qserver, we need to get first real vap ifindex so that
 * parameters can be applied correctly.
 *
 * TODO Use QCSAPI to get the needed information.
 * As of now for repeater mode, we assume and hardcode
 * vap ifindex from 1, like wifi1, wifi2, etc. For other modes,
 * vap ifindex from 0, like wifi0, wifi1 and etc.
 */
static int
qtn_driver_get_first_vap_ifindex(void *priv UNUSED_PARAM, int dev_mode,
		int *first_vap_ifindex)
{
	if (!first_vap_ifindex) {
		os_fprintf(stderr, "%s: input parameter is null\n", __func__);
		return -1;
	}

	switch (dev_mode) {
		case QSVR_DEV_REPEATER:
			*first_vap_ifindex = 1;
			break;
		default:
			*first_vap_ifindex = 0;
			break;
	}

	return 0;
}

static int
qtn_restore_current_bss_configuration(void *priv,
	struct qserver_device_params *params)
{
	struct qtn_drv_data *drv = (struct qtn_drv_data *)priv;
	struct qserver_data *qserver = (struct qserver_data *)drv->ctx;
	char bss_name[IFNAMSIZ + 1] = {'\0'};
	char if_name[IFNAMSIZ + 1]= {'\0'};
	int primay_ap_ifindex = 0;
	int ap_num = 0;
	int need_restore = 0;
	int ret = 0;
	int i;

	/* Figure out the first AP index */
	qtn_driver_get_first_vap_ifindex(priv,
			qserver->dev_mode, &primay_ap_ifindex);

	/* Get the bss number in current configuration */
	for (i = primay_ap_ifindex; i < QTN_MAX_BSSID; i++) {
		memset(if_name, 0, sizeof(if_name));
		snprintf(bss_name, sizeof(bss_name), "%s%d",
				QTN_WIFI_INTERFACE_NAME, i);
		if (i == primay_ap_ifindex) {
			ret = qcsapi_wifi_get_bss_cfg(drv->ifname,
					qcsapi_access_point, bss_name,
					"interface", if_name, sizeof(if_name));
			if (ret < 0)
				continue;
		} else {
			ret = qcsapi_wifi_get_bss_cfg(drv->ifname,
					qcsapi_access_point, bss_name,
					"bss", if_name, sizeof(if_name));
			if (ret < 0)
				continue;
		}

		ap_num++;
	}

	/* Check if need to add/remove bss interfaces */
	if (ap_num != params->num) {
		os_fprintf(stdout, "%s: current bss number %u is not equal"
			" with required bss number %d\n", __func__, ap_num,
			params->num);
		need_restore = 1;
		goto restore;
	}

	/* Check if current BSS interfaces are correctly named */
	for (i = 0; i < params->num; i++, primay_ap_ifindex++) {
		memset(if_name, 0, sizeof(if_name));
		snprintf(bss_name, sizeof(bss_name), "%s%d",
				QTN_WIFI_INTERFACE_NAME, primay_ap_ifindex);
		if (i == 0) {
			ret = qcsapi_wifi_get_bss_cfg(drv->ifname,
					qcsapi_access_point, bss_name,
					"interface", if_name, sizeof(if_name));
			if (ret < 0) {
				os_fprintf(stderr, "%s: fail to find get primary"
					" AP name %s\n", __func__, bss_name);
				need_restore = 1;
				goto restore;
			}

			if (strcasecmp(bss_name, if_name)) {
				os_fprintf(stderr, "%s: incorrect primary interface"
					" name %s\n", __func__, if_name);
				need_restore = 1;
				goto restore;
			}
		} else {
			ret = qcsapi_wifi_get_bss_cfg(drv->ifname,
					qcsapi_access_point, bss_name,
					"bss", if_name, sizeof(if_name));
			if (ret < 0) {
				os_fprintf(stderr, "%s: fail to find get bss"
					" name %s\n", __func__, bss_name);
				need_restore = 1;
				goto restore;
			}
		}
	}

	if (!need_restore)
		return 0;

restore:
	ret = qcsapi_restore_default_config(QCSAPI_RESTORE_FG_SEC_DAEMON |
					QCSAPI_RESTORE_FG_AP);
	if (ret < 0) {
		os_fprintf(stderr, "%s: fail to restore default config"
			" - errno %d\n", __func__, ret);
		return ret;
	}

	return 1;
}

static int
qtn_driver_set_device_secu_daemon_params(void *priv,
	struct qserver_device_params *params)
{
	struct qtn_drv_data *drv = (struct qtn_drv_data *)priv;
	struct qserver_data *qserver = (struct qserver_data *)drv->ctx;
	char bss_name[IFNAMSIZ + 1] = {0};
	int vap_ifindex = 0;
	int restored = 0;
	int ret;
	int i;

	if (!params) {
		os_fprintf(stderr, "%s: null parameter pointer\n", __func__);
		return -1;
	}

	if (qtn_driver_get_device_mode(priv, &qserver->dev_mode) < 0) {
		os_fprintf(stdout, "%s: fail to get device mode\n", __func__);
		return -1;
	}

	os_fprintf(stderr, "%s: start to set security daemon parameters\n", __func__);

	drv->ap_secu_param_changed = 0;

	ret = qtn_restore_current_bss_configuration(priv, params);
	if (ret > 0) {
		os_fprintf(stdout, "%s: restore current configuration to default\n",
				__func__);
		restored = 1;
		drv->ap_secu_param_changed = 1;
	}

	if (params->bss) {
		if (qtn_driver_get_first_vap_ifindex(priv, qserver->dev_mode,
					&vap_ifindex) < 0) {
			os_fprintf(stderr, "%s: failed to get first vap ifindex\n",
					__func__);
			return -1;
		}

		for (i = 0; i < params->num; i++, vap_ifindex++) {
			snprintf(bss_name, sizeof(bss_name), "%s%d",
						QTN_WIFI_INTERFACE_NAME, vap_ifindex);
			if (restored) {
				if (i == 0) {
					/*
					 * Interface name in hostapd could be restored
					 * to default and need to set it to first real
					 * vap interface name.
					 */
					os_fprintf(stdout, "%s: update primary bss"
						" name to %s\n", __func__, bss_name);
					ret = qcsapi_wifi_update_bss_cfg(drv->ifname,
						qcsapi_access_point, bss_name,
						"interface", bss_name, NULL);
					if (ret < 0) {
						os_fprintf(stderr, "%s: failed to update hostapd"
								" interface name\n", __func__);
						return ret;
					}
				} else {
					os_fprintf(stdout, "%s: create bss %s\n",
							__func__, bss_name);
					ret = qcsapi_wifi_update_bss_cfg(drv->ifname,
						qcsapi_access_point, bss_name,
						"bss", bss_name, NULL);
					if (ret < 0) {
						os_fprintf(stderr, "%s: fail to create bss %s"
							" - errno %d\n", __func__, bss_name, ret);
						return ret;
					}

					qtn_init_wps_serial_num(priv, bss_name, vap_ifindex);
				}
			}

			ret = qtn_set_bss_params(priv, bss_name, &params->bss[i]);
			if (ret > 0) {
				drv->ap_secu_param_changed = 1;
				os_fprintf(stdout, "%s: bss %s parameters updated\n",
					__func__, bss_name);
			} else if (ret < 0) {
				os_fprintf(stderr, "%s: fail to set bss %s parameters"
					" - errno %d\n", __func__, bss_name, ret);
				return ret;
			}
		}
	}

	return 0;
}

static int
qtn_driver_set_device_runtime_params(void *priv,
	struct qserver_device_params *params)
{
	struct qtn_drv_data *drv = (struct qtn_drv_data *)priv;
	struct qserver_data *qserver = (struct qserver_data *)drv->ctx;
	char bss_name[IFNAMSIZ + 1] = {0};
	int vap_ifindex;
	int ret;
	int i;

	if (!params) {
		os_fprintf(stderr, "%s: null parameter pointer\n", __func__);
		return -1;
	}

	if (qtn_driver_get_device_mode(priv, &qserver->dev_mode) < 0) {
		os_fprintf(stdout, "%s: fail to get device mode\n", __func__);
		return -1;
	}

	os_fprintf(stdout, "%s: start to set runtime parameters\n", __func__);

	if (params->qtm) {
		ret = qtn_set_qtm(priv, params->qtm);
		if (ret < 0)
			return ret;
	}

	if (params->bss) {
		if (qtn_driver_get_first_vap_ifindex(priv, qserver->dev_mode,
					&vap_ifindex) < 0) {
			os_fprintf(stderr, "%s: failed to get first vap"
					" ifindex\n", __func__);
			return -1;
		}

		for (i = 0; i < params->num; i++, vap_ifindex++) {
			snprintf(bss_name, sizeof(bss_name), "%s%d",
						QTN_WIFI_INTERFACE_NAME, vap_ifindex);

			/* set runtime parameters */
			ret = qtn_set_bss_priority(priv, params->bss[i].pri, bss_name);
			if (ret < 0)
				return ret;

			ret = qtn_set_bss_wmm_params(priv, params->bss[i].wmm_own, bss_name, 0);
			if (ret < 0)
				return ret;

			ret = qtn_set_bss_wmm_params(priv, params->bss[i].wmm_bss, bss_name, 1);
			if (ret < 0)
				return ret;
		}
	}

	return 0;
}

static int
qtn_driver_update_device(void *priv)
{
	struct qtn_drv_data *drv = (struct qtn_drv_data *)priv;
	struct qserver_data *qserver = (struct qserver_data *)drv->ctx;
	char ifname[IFNAMSIZ + 1] = {0};
	int vap_ifindex = 0;
	int ret = 0;

	if (qtn_driver_get_device_mode(priv, &qserver->dev_mode) < 0) {
		os_fprintf(stdout, "%s: fail to get device mode\n", __func__);
		return -1;
	}

	os_fprintf(stdout, "%s: start to update device %s\n",
			__func__, qserver_dev_mode2str(qserver->dev_mode));

	switch (qserver->dev_mode) {
	case QSVR_DEV_MBS:
		/* MBS actions */
		break;
	case QSVR_DEV_RBS:
		/* RBS actions */
		if (drv->pending_cmd[0] != '\0') {
			ret = system(drv->pending_cmd);
			drv->pending_cmd[0] = '\0';
		}
		break;
	case QSVR_DEV_REPEATER:
		/* Repeater actions */
		if (drv->ap_secu_param_changed == 0)
			break;

		if (qtn_driver_get_first_vap_ifindex(priv, qserver->dev_mode,
					&vap_ifindex) < 0) {
			os_fprintf(stderr, "%s: failed to get first vap"
					" ifindex\n", __func__);
			return -1;
		}

		snprintf(ifname, sizeof(ifname), "%s%d",
				QTN_WIFI_INTERFACE_NAME, vap_ifindex);
		ret = qcsapi_wifi_reload_security_config(ifname);
		break;
	case QSVR_DEV_864_HOST:
		/* 864_HOST actions */
		if (drv->ap_secu_param_changed == 0)
			break;

		ret = qcsapi_wifi_reload_in_mode(qserver->ifname,
				qcsapi_access_point);
		break;
	case QSVR_DEV_864_CLIENT:
		/* 864_CLIENT actions */
		if (drv->ap_secu_param_changed == 0)
			break;

		ret = qcsapi_wifi_reload_in_mode(qserver->ifname,
				qcsapi_access_point);
		if (ret >= 0)
			ret = qcsapi_wifi_rfenable(QCSAPI_TRUE);
		break;
	default:
		break;
	}

	return ret;
}

static int
qtn_driver_restore_device(void *priv)
{
	struct qtn_drv_data *drv = (struct qtn_drv_data *)priv;
	struct qserver_data *qserver = (struct qserver_data *)drv->ctx;
	int ret = 0;

	if (qtn_driver_get_device_mode(priv, &qserver->dev_mode) < 0) {
		os_fprintf(stdout, "%s: fail to get device mode\n", __func__);
		return -1;
	}

	os_fprintf(stdout, "%s: start to restore device %s\n",
			__func__, qserver_dev_mode2str(qserver->dev_mode));

	switch (qserver->dev_mode) {
	case QSVR_DEV_MBS:
		/* MBS actions */
		break;
	case QSVR_DEV_RBS:
		/* RBS actions */
		drv->pending_cmd[0] = '\0';
		break;
	case QSVR_DEV_REPEATER:
		/* Repeater actions */
		break;
	case QSVR_DEV_864_HOST:
		/* 864_HOST actions */
		break;
	case QSVR_DEV_864_CLIENT:
		/* 864_CLIENT actions */
		break;
	default:
		break;
	}

	return ret;
}

static void *
qtn_driver_init(void *ctx, const char *ifname)
{
	struct qtn_drv_data *priv = NULL;

	priv = os_zalloc(sizeof(*priv));
	if (priv == NULL) {
		os_fprintf(stderr, "%s: failed to allocate private "
				"driver data\n", __func__);
		return NULL;
	}

	os_fprintf(stdout, "%s: initalize quantenna driver interface\n", __func__);

	priv->ctx = ctx;
	strncpy(priv->ifname, ifname, IFNAMSIZ);

	return priv;
}

static void
qtn_driver_deinit(void *priv)
{
	os_fprintf(stdout, "%s: deinitalize quantenna driver interface\n",
			__func__);

	free(priv);
}

struct qserver_driver_ops qserver_qtn_driver_ops =
{
	.name = "Quantenna",
	.desc = "qserver driver support for Quantenna",

	.init = qtn_driver_init,
	.deinit =  qtn_driver_deinit,
	.get_device_mode = qtn_driver_get_device_mode,
	.get_device_capas = qtn_driver_get_device_capas,
	.get_device_params = qtn_driver_get_device_params,
	.get_device_connect_status = qtn_driver_get_device_connect_status,
	.local_parse_device_params = qtn_driver_local_parse_device_params,
	.free_device_params = qtn_driver_free_device_params,
	.should_deliver_device_params = qtn_driver_should_deliver_device_params,
	.should_accept_device_params = qtn_driver_should_accept_device_params,
	.set_device_secu_daemon_params = qtn_driver_set_device_secu_daemon_params,
	.set_device_runtime_params = qtn_driver_set_device_runtime_params,
	.update_device = qtn_driver_update_device,
	.restore_device = qtn_driver_restore_device,
	.save_device_params_to_file = qtn_driver_save_device_params_to_file,
};


