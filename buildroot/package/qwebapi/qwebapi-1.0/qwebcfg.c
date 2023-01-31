/*SH1
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications Inc                   **
**                                                                           **
**  File        : qwebcfg.c                                                  **
**  Description :                                                            **
**                                                                           **
*******************************************************************************
**                                                                           **
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
**  Alternatively, this software may be distributed under the terms of the   **
**  GNU General Public License ("GPL") version 2, or (at your option) any    **
**  later version as published by the Free Software Foundation.              **
**                                                                           **
**  In the case this software is distributed under the GPL license,          **
**  you should have received a copy of the GNU General Public License        **
**  along with this software; if not, write to the Free Software             **
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  **
**                                                                           **
**  THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR       **
**  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES**
**  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  **
**  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,         **
**  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT **
**  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,**
**  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY    **
**  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT      **
**  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF **
**  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.        **
**                                                                           **
*******************************************************************************
EH1*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>

#include "qwebapi.h"
#include "qwebapi_core.h"
#include "qwebapi_util.h"

#define QTN_5G_RADIO_NAME "wifi0"
#define IS_JSON_STRING_EMPTY(s) (strcmp(s, "\"\"") ? 0 : 1)

#define IEEE80211_EXTENDER_ROLE_NONE 0
#define IEEE80211_EXTENDER_ROLE_MBS 1
#define IEEE80211_EXTENDER_ROLE_RBS 2

#define MODE_UNKNOW	0
#define MODE_AP		1
#define MODE_STA	2
#define MODE_REPEATER	3
#define MODE_QHOP_MBS	4
#define MODE_QHOP_RBS	5
#define MODE_QHOP_STA	6

#define BSS_NUM_OF_5G	8
#define BSS_NUM_OF_24G	5
#define TOTAL_BSS_NUM		(BSS_NUM_OF_5G + BSS_NUM_OF_24G)

extern int qweb_set_obj(char *path, JSON *obj);
extern int qweb_apply_for_change(char *path);

int get_work_mode()
{
	int ret;
	int role = IEEE80211_EXTENDER_ROLE_NONE;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;

	if (qcsapi_wifi_verify_repeater_mode() == 1)
		return MODE_REPEATER;

	ret = qcsapi_wifi_get_mode(QTN_5G_RADIO_NAME, &wifi_mode);
	if(ret < 0)
		return MODE_UNKNOW;

	qcsapi_wifi_get_extender_params(QTN_5G_RADIO_NAME, qcsapi_extender_role, &role);

	if (wifi_mode == qcsapi_access_point) {
		switch (role) {
		case IEEE80211_EXTENDER_ROLE_MBS:
			return MODE_QHOP_MBS;
		case IEEE80211_EXTENDER_ROLE_RBS:
			return MODE_QHOP_RBS;
		default:
			return MODE_AP;
		}
	} else if (wifi_mode == qcsapi_station) {
		switch (role) {
		case IEEE80211_EXTENDER_ROLE_RBS:
			return MODE_QHOP_STA;
		default:
			return MODE_STA;
		}
	}

	return MODE_UNKNOW;
}

int update_sta_cfg(JSON *json_cfg)
{
#define UPDATE_PARAM_WITH_QUOTE  "1"
	JSON *obj_ssid_array, *obj_ap_array, *obj_main_ssid, *obj_main_security, *obj_ssid, *obj_mode, *obj_key, *obj_psk;
	const char *ssid = NULL, *security_mode = NULL, *security_key = NULL, *security_psk = NULL;
	qcsapi_SSID cur_ssid;

	JSON_GET_OBJ(json_cfg, "SSID", &obj_ssid_array);
	JSON_GET_OBJ(json_cfg, "AccessPoint", &obj_ap_array);

	obj_main_ssid = JSON_GET_ITEM(obj_ssid_array, 0);
	obj_main_security = JSON_GET_ITEM(obj_ap_array, 0);
	JSON_GET_OBJ(obj_main_ssid, "SSID", &obj_ssid);
	JSON_GET_OBJ(obj_main_security, "Security", &obj_main_security);
	JSON_GET_OBJ(obj_main_security, "ModeEnabled", &obj_mode);
	JSON_GET_OBJ(obj_main_security, "KeyPassphrase", &obj_key);
	JSON_GET_OBJ(obj_main_security, "PreSharedKey", &obj_psk);

	ssid = JSON_GET_STRING(obj_ssid);
	security_mode = JSON_GET_STRING(obj_mode);
	security_key = JSON_GET_STRING(obj_key);
	security_psk = JSON_GET_STRING(obj_psk);

	memset(cur_ssid, 0, sizeof(cur_ssid));
	if (qcsapi_wifi_get_SSID(QTN_5G_RADIO_NAME, cur_ssid) >= 0) {
		if (cur_ssid[0] != 0 && strcmp(cur_ssid, ssid) != 0)
			qcsapi_wifi_update_bss_cfg(QTN_5G_RADIO_NAME, qcsapi_station,
					cur_ssid, "ssid", "", NULL);
	}
	qcsapi_wifi_update_bss_cfg(QTN_5G_RADIO_NAME, qcsapi_station, ssid, "ssid", ssid, NULL);

	if (!strcmp(security_mode, "None")) {
		qcsapi_wifi_update_bss_cfg(QTN_5G_RADIO_NAME, qcsapi_station, ssid, "key_mgmt", "NONE", NULL);
	} else if (!strcmp(security_mode, "WPA2-Personal")) {
		qcsapi_wifi_update_bss_cfg(QTN_5G_RADIO_NAME, qcsapi_station, ssid, "key_mgmt", "WPA-PSK", NULL);
		qcsapi_wifi_update_bss_cfg(QTN_5G_RADIO_NAME, qcsapi_station, ssid, "proto", "WPA2", NULL);
		qcsapi_wifi_update_bss_cfg(QTN_5G_RADIO_NAME, qcsapi_station, ssid, "pairwise", "CCMP", NULL);
	} else if (!strcmp(security_mode, "WPA-WPA2-Personal")) {
		qcsapi_wifi_update_bss_cfg(QTN_5G_RADIO_NAME, qcsapi_station, ssid, "key_mgmt", "WPA-PSK", NULL);
		qcsapi_wifi_update_bss_cfg(QTN_5G_RADIO_NAME, qcsapi_station, ssid, "proto", "WPA WPA2", NULL);
		qcsapi_wifi_update_bss_cfg(QTN_5G_RADIO_NAME, qcsapi_station, ssid, "pairwise", "TKIP CCMP", NULL);
	}

	if (security_key)
		qcsapi_wifi_update_bss_cfg(QTN_5G_RADIO_NAME, qcsapi_station, ssid, "psk",
				security_key, UPDATE_PARAM_WITH_QUOTE);
	if (security_psk)
		qcsapi_wifi_update_bss_cfg(QTN_5G_RADIO_NAME, qcsapi_station, ssid, "psk",
				security_psk, UPDATE_PARAM_WITH_QUOTE);

	return 0;
}

static int is_sta_cfg_changed(JSON *json_cfg)
{
	JSON *obj_ssid_array, *obj_ap_array, *obj_main_ssid, *obj_main_security, *obj_ssid, *obj_mode, *obj_key, *obj_psk;
	const char *ssid, *security_mode, *security_key, *security_psk;
	char encryption_modes[36], authentication_mode[36];
	string_16 protocol;
	string_64 passphrase;
	string_64 preshared_key;
	int qcsapi_retval;
	int changed = 1;

	JSON_GET_OBJ(json_cfg, "SSID", &obj_ssid_array);
	JSON_GET_OBJ(json_cfg, "AccessPoint", &obj_ap_array);

	obj_main_ssid = JSON_GET_ITEM(obj_ssid_array, 0);
	obj_main_security = JSON_GET_ITEM(obj_ap_array, 0);
	JSON_GET_OBJ(obj_main_ssid, "SSID", &obj_ssid);
	JSON_GET_OBJ(obj_main_security, "Security", &obj_main_security);
	JSON_GET_OBJ(obj_main_security, "ModeEnabled", &obj_mode);
	JSON_GET_OBJ(obj_main_security, "KeyPassphrase", &obj_key);
	JSON_GET_OBJ(obj_main_security, "PreSharedKey", &obj_psk);

	ssid = JSON_GET_STRING(obj_ssid);
	security_mode = JSON_GET_STRING(obj_mode);
	security_key = JSON_GET_STRING(obj_key);
	security_psk = JSON_GET_STRING(obj_psk);

	qcsapi_retval = qcsapi_SSID_get_authentication_mode(QTN_5G_RADIO_NAME, ssid, authentication_mode);
	if (qcsapi_retval < 0) goto __out;
	qcsapi_retval = qcsapi_SSID_get_encryption_modes(QTN_5G_RADIO_NAME, ssid, encryption_modes);
	if (qcsapi_retval < 0) goto __out;
	qcsapi_retval = qcsapi_SSID_get_protocol(QTN_5G_RADIO_NAME, ssid, protocol);
	if (qcsapi_retval < 0) goto __out;

	if (security_key) {
		qcsapi_retval = qcsapi_SSID_get_key_passphrase(QTN_5G_RADIO_NAME, ssid, 0, passphrase);
		if (qcsapi_retval < 0
			|| strcmp(passphrase, security_key))
			goto __out;
	}
	if (security_psk) {
		qcsapi_retval = qcsapi_wifi_get_pre_shared_key(QTN_5G_RADIO_NAME, 0, preshared_key);
		if (qcsapi_retval < 0
			|| strcmp(preshared_key, security_psk))
			goto __out;
	}

	if (!strcmp(security_mode, "None")) {
		if (strcmp(authentication_mode, "NONE"))
			goto __out;
	} else if (!strcmp(security_mode, "WPA2-Personal")) {
		if (strcmp(authentication_mode, "PSKAuthentication")
			|| strcmp(protocol, "11i")
			|| strcmp(encryption_modes, "AESEncryption"))
			goto __out;
	} else if (!strcmp(security_mode, "WPA-WPA2-Personal")) {
		if (strcmp(authentication_mode, "PSKAuthentication")
			|| strcmp(protocol, "WPAand11i")
			|| strcmp(encryption_modes, "TKIPandAESEncryption"))
			goto __out;
	}

	changed = 0;
__out:

	return changed;
}

int is_main_ap_cfg_changed(JSON *json_cfg)
{
	JSON *obj_ssid_array, *obj_ap_array, *obj_main_ssid, *obj_main_security, *obj_ssid, *obj_mode, *obj_key, *obj_psk;
	const char *ssid, *security_mode, *security_key, *security_psk;
	char *cur_ssid = NULL, *cur_security_mode = NULL, *cur_security_key = NULL, *cur_preshared_key = NULL;
	int changed = 0;

	if (qweb_get("Device.WiFi.SSID.{0}.SSID", &cur_ssid) < 0) {
		free(cur_ssid);
		return 1;
	}

	if (qweb_get("Device.WiFi.AccessPoint.{0}.Security.ModeEnabled", &cur_security_mode) < 0) {
		free(cur_ssid);
		free(cur_security_mode);
		return 1;
	}

	if (qweb_get("Device.WiFi.AccessPoint.{0}.Security.KeyPassphrase", &cur_security_key) < 0) {
		free(cur_ssid);
		free(cur_security_mode);
		free(cur_security_key);
		return 1;
	}

	if (qweb_get("Device.WiFi.AccessPoint.{0}.Security.PreSharedKey", &cur_preshared_key) < 0) {
		free(cur_ssid);
		free(cur_security_mode);
		free(cur_security_key);
		free(cur_preshared_key);
		return 1;
	}

	JSON_GET_OBJ(json_cfg, "SSID", &obj_ssid_array);
	JSON_GET_OBJ(json_cfg, "AccessPoint", &obj_ap_array);

	obj_main_ssid = JSON_GET_ITEM(obj_ssid_array, 0);
	obj_main_security = JSON_GET_ITEM(obj_ap_array, 0);
	JSON_GET_OBJ(obj_main_ssid, "SSID", &obj_ssid);
	JSON_GET_OBJ(obj_main_security, "Security", &obj_main_security);
	JSON_GET_OBJ(obj_main_security, "ModeEnabled", &obj_mode);
	JSON_GET_OBJ(obj_main_security, "KeyPassphrase", &obj_key);
	JSON_GET_OBJ(obj_main_security, "PreSharedKey", &obj_psk);

	ssid = JSON_GET_STRING(obj_ssid);
	security_mode = JSON_GET_STRING(obj_mode);
	security_key = JSON_GET_STRING(obj_key);
	security_psk = JSON_GET_STRING(obj_psk);

	if (strcmp(ssid, cur_ssid)
		|| strcmp(security_mode, cur_security_mode))
		changed = 1;

	if (security_key && strcmp(security_key, cur_security_key))
		changed = 1;

	if (security_psk && strcmp(security_psk, cur_preshared_key))
		changed = 1;

	free(cur_ssid);
	free(cur_security_mode);
	if (cur_security_key)
		free(cur_security_key);
	if (cur_preshared_key)
		free(cur_preshared_key);

	return changed;
}

#define RADIO_5G_ONLY		1
#define RADIO_24G_ONLY		2
#define RADIO_5G_AND_24G	3
int build_ap(JSON *json_cfg, int band)
{
	int i;
	JSON *obj_ssid_array, *obj_ssid;
	char param[32];

	JSON_GET_OBJ(json_cfg, "SSID", &obj_ssid_array);

	for (i = (band == RADIO_24G_ONLY ? BSS_NUM_OF_5G : 0);
		i < (band == RADIO_5G_ONLY ? BSS_NUM_OF_5G : TOTAL_BSS_NUM); ++i) {
		sprintf(param, "Device.WiFi.SSID.{%d}", i);
		obj_ssid = JSON_GET_ITEM(obj_ssid_array, i);
		JSON_GET_OBJ(obj_ssid, "SSID", &obj_ssid);
		if (obj_ssid)
			qweb_add(param, i < BSS_NUM_OF_5G ? "\"radio0\"" : "\"radio1\"");
		else
			qweb_del(param);
	}
	return 0;
}

int update_24g_ap_cfg(JSON *json_cfg)
{
	int i;
	JSON *obj_ssid_array, *obj_ap_array;

	JSON_GET_OBJ(json_cfg, "SSID", &obj_ssid_array);
	JSON_GET_OBJ(json_cfg, "AccessPoint", &obj_ap_array);

	for (i = 0; i < BSS_NUM_OF_5G; ++i) {
		json_object_array_put_idx(obj_ssid_array, i, json_object_new_object());
		json_object_array_put_idx(obj_ap_array, i, json_object_new_object());
	}

	build_ap(json_cfg, RADIO_24G_ONLY);
	return qweb_set_obj("Device.WiFi", json_cfg);
}

int update_rp_ap_cfg(JSON *json_cfg)
{
	int i;
	JSON *obj_ssid_array, *obj_ap_array, *obj_ssid, *obj_security;

	JSON_GET_OBJ(json_cfg, "SSID", &obj_ssid_array);
	JSON_GET_OBJ(json_cfg, "AccessPoint", &obj_ap_array);

	for (i = BSS_NUM_OF_5G - 1; i > 0; i--) {
		obj_ssid = JSON_GET_ITEM(obj_ssid_array, i - 1);
		obj_security = JSON_GET_ITEM(obj_ap_array, i - 1);
		JSON_GET_REF(obj_ssid);
		JSON_GET_REF(obj_security);
		json_object_array_put_idx(obj_ssid_array, i, obj_ssid);
		json_object_array_put_idx(obj_ap_array, i, obj_security);
	}

	json_object_array_put_idx(obj_ssid_array, 0, json_object_new_object());
	json_object_array_put_idx(obj_ap_array, 0, json_object_new_object());

	build_ap(json_cfg, RADIO_5G_AND_24G);
	qweb_set_obj("Device.WiFi", json_cfg);

	/* need reload hostapd configuration for repeater */
	return qcsapi_wifi_reload_security_config("wifi1");
}

#ifdef TOPAZ_QFDR
static int update_qfdr_client_sta_cfg(void)
{
	int status;

	status = system("perform_cmd_on_remote \"qfdr_sync_config supplicant with-apply\"");
	if (status == -1 || !WIFEXITED(status)) {
		printf("Error: qfdr sync client wpa_supplicant script error\n");
		return -1;
	}

	return 0;
}

static int update_qfdr_client_ap_cfg(void)
{
	int status, ret = 0;

	status = system("perform_cmd_on_remote \"qfdr_sync_config hostapd with-apply\"");
	if (status == -1 || !WIFEXITED(status)) {
		printf("Error: qfdr sync client hostapd script error\n");
		ret = -1;
	}

	status = system("perform_cmd_on_remote \"qfdr_sync_config qwe with-apply\"");
	if (status == -1 || !WIFEXITED(status)) {
		printf("Error: qfdr sync client hostapd script error\n");
		ret = -1;
	}

	return ret;
}
#endif

int add_ssid_cfg(FILE *fp, int index)
{
	char *ssid = NULL;
	char param[32];
	int n;

	sprintf(param, "Device.WiFi.SSID.{%d}.SSID", index);
	if (qweb_get(param, &ssid) < 0){
		free(ssid);
		return fprintf(fp, "{},");
	}

	n = fprintf(fp, "{\"SSID\":%s},", ssid);
	free(ssid);

	return n;
}

int add_ap_cfg(FILE *fp, int index)
{
	char *mode = NULL, *passphrase = NULL, *preshared_key = NULL, *dot11r = NULL, *dot11r_mdid = NULL;
	char *inact_passphrase = NULL, *inact_preshared_key = NULL;
	char param[64], param1[64];
	int n;

	sprintf(param, "Device.WiFi.AccessPoint.{%d}.Security.ModeEnabled", index);
	if (qweb_get(param, &mode) < 0) {
		free(mode);
		return fprintf(fp, "{},");
	}

	sprintf(param, "Device.WiFi.AccessPoint.{%d}.Security.KeyPassphrase", index);
	sprintf(param1, "Device.WiFi.AccessPoint.{%d}.Security.PreSharedKey", index);
	if (qweb_get_inactive_mode()) {
		/* coverity[check_return] - Permit */
		qweb_get(param, &inact_passphrase);
		qweb_get(param1, &inact_preshared_key);
		if (!IS_JSON_STRING_EMPTY(inact_preshared_key)) {
			fprintf(fp, "{\"Security\":{\"ModeEnabled\":%s,\"PreSharedKey\":%s},",
				mode, inact_preshared_key);
		} else if (!IS_JSON_STRING_EMPTY(inact_passphrase)) {
			fprintf(fp, "{\"Security\":{\"ModeEnabled\":%s,\"KeyPassphrase\":%s},",
				mode, inact_passphrase);
		} else {
			qweb_set_inactive_mode(0);
			if (qweb_get(param, &passphrase) >= 0)
				fprintf(fp, "{\"Security\":{\"ModeEnabled\":%s,\"KeyPassphrase\":%s},",
					mode, passphrase);
			else if (qweb_get(param1, &preshared_key) >= 0)
				fprintf(fp, "{\"Security\":{\"ModeEnabled\":%s,\"PreSharedKey\":%s},",
					mode, preshared_key);
			qweb_set_inactive_mode(1);
		}
	} else {
		if (qweb_get(param, &passphrase) >= 0)
			fprintf(fp, "{\"Security\":{\"ModeEnabled\":%s,\"KeyPassphrase\":%s},",
				mode, passphrase);
		else if (qweb_get(param1, &preshared_key) >= 0)
			fprintf(fp, "{\"Security\":{\"ModeEnabled\":%s,\"PreSharedKey\":%s},",
				mode, preshared_key);
	}

	sprintf(param, "Device.WiFi.AccessPoint.{%d}.X_QUANTENNA_COM_80211r_enable", index);
	if (qweb_get(param, &dot11r) >= 0) {
		fprintf(fp, "\"X_QUANTENNA_COM_80211r_enable\":%s,", dot11r);
	} else {
		fprintf(fp, "\"X_QUANTENNA_COM_80211r_enable\":\"0\",");
	}

	sprintf(param, "Device.WiFi.AccessPoint.{%d}.X_QUANTENNA_COM_80211r_mdid", index);
	if (qweb_get(param, &dot11r_mdid) >= 0) {
		fprintf(fp, "\"X_QUANTENNA_COM_80211r_mdid\":%s,", dot11r_mdid);
	} else {
		fprintf(fp, "\"X_QUANTENNA_COM_80211r_mdid\":\"0000\",");
	}
	n = fprintf(fp, "},");

	free(mode);
	free(inact_preshared_key);
	free(inact_passphrase);
	free(preshared_key);
	free(passphrase);
	if (dot11r)
		free(dot11r);
	if (dot11r_mdid)
		free(dot11r_mdid);

	return n;
}

int get_cfg(char *path)
{
	int i;
	FILE *fp;
	int mode;
	int start_ind = 0;

	mode = get_work_mode();

	if (mode != MODE_AP && mode != MODE_QHOP_MBS
		&& mode != MODE_REPEATER) {
		printf("Can only get ap cfg on AP or MBS or REPEATER mode, current mode is %d\n", mode);
		return -1;
	}

	/* skip the first interface(sta mode) for repeater */
	if (mode == MODE_REPEATER)
		start_ind = 1;

	fp = fopen(path, "w");
	if (!fp) {
		printf("Cannot open %s for write: %s\n", path, strerror(errno));
		return -1;
	}
	fprintf(fp, "{\"SSID\":[");
	for (i = start_ind; i < BSS_NUM_OF_5G; ++i)
		add_ssid_cfg(fp, i);
	/* REPEATER mode only support BSS_NUM_OF_5G - 1 AP mode bss */
	if (mode == MODE_REPEATER)
		fprintf(fp, "{},");
#ifdef TOPAZ_DBDC
	for (i = BSS_NUM_OF_5G; i < TOTAL_BSS_NUM; ++i)
		add_ssid_cfg(fp, i);
#endif
	fprintf(fp, "]");

	fprintf(fp, ",\"AccessPoint\":[");
	for (i = start_ind; i < BSS_NUM_OF_5G; ++i)
		add_ap_cfg(fp, i);
	/* REPEATER mode only support BSS_NUM_OF_5G - 1 AP mode bss */
	if (mode == MODE_REPEATER)
		fprintf(fp, "{},");
#ifdef TOPAZ_DBDC
	for (i = BSS_NUM_OF_5G; i < TOTAL_BSS_NUM; ++i)
		add_ap_cfg(fp, i);
#endif
	fprintf(fp, "]}");
	fclose(fp);

	return 0;
}

int set_cfg(char *path)
{
	int mode;
	FILE *fp = NULL;
	char *cfg = NULL;
	struct stat st;
	int ret = -1;
	int main_ap_cfg_changed = 0;
	unsigned char zeros_addr[6] = { 0 };
	JSON *json_cfg = NULL;

	fp = fopen(path, "r");
	if (!fp) {
		printf("Cannot open %s for read: %s\n", path, strerror(errno));
		goto out;
	}

	if (stat(path, &st) != 0) {
		printf("Failed to get status of %s: %s\n", path, strerror(errno));
		fclose(fp);
		return -1;
	}
	cfg = malloc(st.st_size + 1);
	if (!cfg) {
		printf("Failed to allocate memory for read cfg\n");
		fclose(fp);
		return -1;
	}

	if (fread(cfg, 1, st.st_size, fp) != st.st_size) {
		printf("Failed to get AP cfg\n");
		goto out;
	}
	cfg[st.st_size] = 0;

	json_cfg = JSON_PARSE(cfg);
	if (json_cfg == NULL) {
		printf("cfg is invalid json format\n");
		goto out;
	}

	mode = get_work_mode();

#ifdef TOPAZ_DBDC
	qweb_set_defer_mode(1);
#endif
	switch (mode) {
	case MODE_AP:
	case MODE_QHOP_MBS:
#ifdef TOPAZ_DBDC
		if (qweb_get_bss_count(json_cfg) == BSS_NUM_OF_5G)
			build_ap(json_cfg, RADIO_5G_ONLY);
		else
			build_ap(json_cfg, RADIO_5G_AND_24G);
#else
		build_ap(json_cfg, RADIO_5G_ONLY);
#endif
		ret = qweb_set_obj("Device.WiFi", json_cfg);
		if (mode == MODE_QHOP_MBS)
			ret = qcsapi_wifi_set_extender_key(QTN_5G_RADIO_NAME, zeros_addr);
#ifdef TOPAZ_QFDR
		ret = update_qfdr_client_ap_cfg();
#endif
		break;
	case MODE_STA:
	case MODE_QHOP_STA:
		if (is_sta_cfg_changed(json_cfg)) {
			ret = update_sta_cfg(json_cfg);
			ret = qcsapi_wifi_apply_security_config(QTN_5G_RADIO_NAME);
		}
		ret = update_24g_ap_cfg(json_cfg);
		break;
	case MODE_QHOP_RBS:
		if (is_main_ap_cfg_changed(json_cfg)) {
			main_ap_cfg_changed = 1;
			ret = update_sta_cfg(json_cfg);
		}
#ifdef TOPAZ_DBDC
		if (qweb_get_bss_count(json_cfg) == BSS_NUM_OF_5G)
			build_ap(json_cfg, RADIO_5G_ONLY);
		else
			build_ap(json_cfg, RADIO_5G_AND_24G);
#else
		build_ap(json_cfg, RADIO_5G_ONLY);
#endif
		ret = qweb_set_obj("Device.WiFi", json_cfg);
		if (main_ap_cfg_changed)
			ret = qcsapi_wifi_set_extender_key(QTN_5G_RADIO_NAME, zeros_addr);
		break;
	case MODE_REPEATER:
		if (is_sta_cfg_changed(json_cfg)) {
			ret = update_sta_cfg(json_cfg);
			ret = qcsapi_wifi_apply_security_config(QTN_5G_RADIO_NAME);
#ifdef TOPAZ_QFDR
			ret = update_qfdr_client_sta_cfg();
#endif
		}
		ret = update_rp_ap_cfg(json_cfg);
#ifdef TOPAZ_QFDR
		ret = update_qfdr_client_ap_cfg();
#endif
		break;
	default:
		printf("Error: failed to get working mode\n");
	}

#ifdef TOPAZ_DBDC
	qweb_set_defer_mode(0);
	qweb_apply_for_change(NULL);
#endif
out:
	if(fp)
		fclose(fp);
	if (cfg)
		free(cfg);
	if (json_cfg)
		JSON_PUT_REF(json_cfg);

	if (ret < 0)
		return ret;
	return 0;
}

void print_usage(char *name)
{
	printf("Usage: %s <get | set> FILE\n", name);
}

int main(int argc, char *argv[])
{
	char *cmd = argv[1];

	if (argc != 3) {
		print_usage(argv[0]);
		return -1;
	}

	if (strcmp(cmd, "get") == 0)
		return get_cfg(argv[2]);
	else if (strcmp(cmd, "get_inactive") == 0) {
		qweb_set_inactive_mode(1);
		return get_cfg(argv[2]);
	} else if (strcmp(cmd, "set") == 0)
		return set_cfg(argv[2]);
	else
		print_usage(argv[0]);

	return -1;
}
