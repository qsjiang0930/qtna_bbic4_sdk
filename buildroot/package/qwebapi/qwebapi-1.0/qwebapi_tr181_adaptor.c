/*SH1
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications Inc                   **
**                                                                           **
**  File        : qwebapi_tr181_adaptor.c                                    **
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

#define _GNU_SOURCE
#include "qwebapi_tr181_adaptor.h"

#define QWEBAPI_TR181_MODE_NAME                         ("Quantenna Wireless Adapter")
#define QWEBAPI_SSID_ALIAS                              ("cpe-quantenna")
#define QWEBAPI_COMMA                                   (",")
#define QWEBAPI_COLON                                   (":")
#define QWEBAPI_ENTER                                   ("\n")
#define QWEBAPI_SPACE                                   (" ")
#define QWEBAPI_EQUAL                                   ("=")
#define QWEBAPI_DELETE_IP                               ("0.0.0.0")
#define QWEBAPI_ALL_ZERO_MAC                            ("00:00:00:00:00:00")
#define QWEBAPI_OP_CODE_ADD                             ("add")
#define QWEBAPI_OP_CODE_DEL                             ("del")

#ifdef TOPAZ_DBDC		/* QV860 */
#define QWEBAPI_OP_CONFIG                               ("qweconfig")
#define QWEBAPI_OP_ACTION                               ("qweaction")
#define QWEBAPI_OP_SET                                  ("set")
#define QWEBAPI_OP_GET                                  ("get")
#define QWEBAPI_OP_COMMIT                               ("commit")

#define TOPAZ_DBDC_5G_RADIO_NAME			"wifi0"
#endif

#define QWEBAPI_DHCPV4_CLIENT_COUNT                     (1)
#ifdef PEARL_PLATFORM		/* BBIC5 */
#define QWEBAPI_RADIO_COUNT                             (3)
#elif defined (TOPAZ_DBDC)	/* QV860 */
#define QWEBAPI_RADIO_COUNT                             (2)
#else				/* OTHER/QV840 */
#define QWEBAPI_RADIO_COUNT                             (1)
#endif
#define QWEBAPI_ETH_INTERFACE_COUNT                     (4)
#define QWEBAPI_DEFAULT_SSID_LIST_SIZE                  (10)

#define CHECK_VALUE(item)                               (item?item:"0")

typedef struct radius_server_config {
	char ip_addr[QWEBAPI_TR181_IP_STR_MAX_LEN + 1];
	unsigned int port;
	char key[QWEBAPI_TR181_PASSPHRASE_MAX_LEN + 1];
} radius_server_cfg;

typedef enum Radius_Type {
	RADIUS_TYPE_ERROR = -1,
	//Radius Accounting Server
	RADIUS_ACCT_SERVER = 0,
	//Radius Auth Server
	RADIUS_AUTH_SERVER = 1
} radius_type;

#ifdef PEARL_PLATFORM
static char *radio_if_mapping[] = {
	"wifi0",
	"wifi1",
	"wifi2",
	NULL
};
#elif defined (TOPAZ_DBDC)
static char *radio_if_mapping[] = {
	"radio0",
	"wlan0",
	NULL
};

static int need_to_apply_for_24G = 0;
#else
static char *radio0 = "radio0";
#endif
static char *if_wifi = "wifi";
static char *if_wds = "wds";
static char *if_eth = "eth";

static qcsapi_SSID array_ssids[QWEBAPI_DEFAULT_SSID_LIST_SIZE];

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static char qweb_ifname[QWEBAPI_IFNAME_MAX_LEN + 1];
static char string_value_buf[QWEBAPI_TR181_STRING_MAX_LEN];
static int qweb_set_beacon_auth_encry(char *ifname, char *beacon_type,
				      char *auth_type, char *encry_type);

static char *qweb_get_radius_value(char *path, int index);
static int qweb_get_radius_cfg(char *cfg_string, char *ip, char *port,
			       char *key);
static int qweb_add_radius_value(char *path, radius_server_cfg * server_cfg,
				 int index);
static int qweb_del_radius_value(char *path, int index);
static int qweb_set_80211u_parameter(char *path, char *param, char *value);
static int qweb_remove_80211u_parameter(char *path, char *param);
static char *qweb_get_80211u_parameter(char *path, char *param, int *perr);
static void qweb_print_vlan_config(string_2048 str);
static int qweb_vlan_parser(const char *value, int cmd);
static int qweb_get_vlanid_value(char *vlanid, int all);
static char *qweb_get_endpoint_ssid_by_index(char *path, int index);
static int qweb_get_endpoint_ssid_list(char *path, char **list_ssid);
static char *qweb_get_endpoint_profile_curr_ssid(char *path, int *perr);
static int qweb_connect_ap(char *ifname, char *curr_ssid);
static int qweb_disconnect_ap(char *ifname);
#ifdef TOPAZ_DBDC
static int qweb_check_if_available_24G(char *path, char *ifname);
#endif

/* Global variable */
static radius_server_cfg server_cfg;

static char *qweb_get_wifi_ifname(char *path, char *array_name)
{
	int index = 0;

	if (array_name) {
		index = qweb_get_key_index(path, array_name);
	} else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, index is wrong, index = %d\n",
			   __func__, __LINE__, index);
		return "";
	}

#ifdef PEARL_PLATFORM		/* BBIC5 */
	if (!strcmp(array_name, ITEM_NAME_RADIO)
	    || !strcmp(array_name, ITEM_NAME_ENDPOINT)) {
		if (index < QWEBAPI_RADIO_COUNT) {
			snprintf(qweb_ifname, QWEBAPI_IFNAME_MAX_LEN, "%s_%d",
				 radio_if_mapping[index], 0);
		} else {
			qwebprintf(DBG_LEVEL_VERBOSE,
				   "%s(), %d, index is wrong, index = %d\n",
				   __func__, __LINE__, index);
			return "";
		}
		return qweb_ifname;
	}

	if (index <= 7)
		snprintf(qweb_ifname, QWEBAPI_IFNAME_MAX_LEN, "%s_%d",
			 radio_if_mapping[0], index);
	else if (index <= 15)
		snprintf(qweb_ifname, QWEBAPI_IFNAME_MAX_LEN, "%s_%d",
			 radio_if_mapping[1], index - QWEBAPI_MAX_BSSID);
	else if (index <= 23)
		snprintf(qweb_ifname, QWEBAPI_IFNAME_MAX_LEN, "%s_%d",
			 radio_if_mapping[2], index - (2 * QWEBAPI_MAX_BSSID));
	else
		return "";
#elif defined (TOPAZ_DBDC)	/* QV860 */
	if (index <= 7)
		snprintf(qweb_ifname, QWEBAPI_IFNAME_MAX_LEN, "%s%d", if_wifi,
			 index);
	else if (index == 8)
		snprintf(qweb_ifname, QWEBAPI_IFNAME_MAX_LEN, "wlan1");
	else if (index <= 12)
		snprintf(qweb_ifname, QWEBAPI_IFNAME_MAX_LEN, "vap%d.wlan1",
			 index - 9);
	else
		return "";
#else
	snprintf(qweb_ifname, QWEBAPI_IFNAME_MAX_LEN, "%s%d", if_wifi, index);
#endif

	return qweb_ifname;
}

static char *qweb_get_ethernet_ifname(char *path, char *array_name)
{
	int index = 0;

	if (array_name)
		index = qweb_get_key_index(path, array_name);

	snprintf(qweb_ifname, QWEBAPI_IFNAME_MAX_LEN, "%s1_%d", if_eth, index);

	return qweb_ifname;
}

static char *qweb_get_wds_ifname_by_index(char *path, int index)
{
	if (index >= QWEBAPI_MAX_WDS_LINKS) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, wds index wrong, index = %d \n",
			   __func__, __LINE__, index);
		return "";
	}

	snprintf(qweb_ifname, QWEBAPI_IFNAME_MAX_LEN, "%s%d", if_wds, index);

	return qweb_ifname;
}

#define CALL_QCSAPI(func, err, ...)\
do { \
	pthread_mutex_lock(&mutex); \
	qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, call qcsapi_%s() start\n", __func__, __LINE__, #func);\
	err = (qcsapi_##func)( __VA_ARGS__ );\
	if (err < 0) {\
		qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, call qcsapi_%s() failed, err code = %d[%s]\n", __func__, __LINE__, #func, (err), strerror((errno)));\
	} else {\
		qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, call qcsapi_%s() ok.\n", __func__, __LINE__, #func);\
	}\
	pthread_mutex_unlock(&mutex);  \
} while (0)

#define QWEBAPI_SET_RETURN(ret) \
do { \
	if (ret) { \
		qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, ret is wrong. path = %s, ret = %d\n", __func__, __LINE__, path, ret); \
		if (ret == -22) /* Invalid argument */ \
			return QWEBAPI_ERR_INVALID_VALUE; \
		else if (ret == -1003) /* Operation only available on an AP */ \
		{ \
			qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, Operation only available on an AP!!!\n", __func__, __LINE__);\
			return QWEBAPI_ERR_NOT_AVALIABLE; \
		} \
		else if (ret == -1004) /* Operation only available on an STA */ \
		{ \
			qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, Operation only available on an STA!!!\n", __func__, __LINE__);\
			return QWEBAPI_ERR_NOT_AVALIABLE; \
		} \
		else \
			return QWEBAPI_ERR_NOT_AVALIABLE; \
	} \
} while (0)

#define QWEBAPI_GET_RETURN(ret, default_return_value) \
do {\
	if (ret) { \
		qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, ret is wrong. path = %s, ret = %d\n", __func__, __LINE__, path, ret); \
		if (ret == -1005) /* Configuration error */ \
			qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, Configuration error!!!\n", __func__, __LINE__);\
		else if (ret == -1003) /* Operation only available on an AP */ \
			qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, Operation only available on an AP!!!\n", __func__, __LINE__);\
		else if (ret == -1004) /* Operation only available on an STA */ \
			qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, Operation only available on an STA!!!\n", __func__, __LINE__);\
		else if (ret == -1001) /* Parameter not found */ \
			qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, Parameter not found!!!\n", __func__, __LINE__);\
		else if (ret == -1028) /* Operation only available on a WDS device */ \
			qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, Operation only available on a WDS device!!!\n", __func__, __LINE__);\
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;\
		return default_return_value;\
	}\
} while (0)

#define QWEBAPI_CHECK_MODE(mode_type, default_value) \
do { \
	qcsapi_wifi_mode mode; \
	CALL_QCSAPI(wifi_get_mode, ret, ifname, &mode); \
	if (!ret && mode != mode_type) { \
		qwebprintf(DBG_LEVEL_VERBOSE,\
			"%s(), %d, this API is only available on %d, current mode is %d.\n", __func__, __LINE__, mode_type, mode); \
		return default_value;\
	} else if (ret != 0) {\
		qwebprintf(DBG_LEVEL_VERBOSE,\
			"%s(), %d, call qcsapi_wifi_get_mode() failed, ret = %d.\n", __func__, __LINE__, ret); \
		return default_value;\
	} \
} while (0)

#define QWEBAPI_SET_INT_OBJ_FUNC(func_name, qcsapi_name, array_name)  \
int qweb_set_##func_name##_obj(char *path, JSON * obj) \
{ \
	int ret; \
	int value; \
	value = JSON_GET_INT(obj); \
	CALL_QCSAPI(wifi_set_##qcsapi_name, ret, qweb_get_wifi_ifname(path, array_name), value);\
	QWEBAPI_SET_RETURN(ret); \
	return ret; \
}

#define QWEBAPI_GET_UINT_OBJ_FUNC(func_name, qcsapi_name, array_name)  \
JSON *qweb_get_##func_name##_obj(char *path, int *perr) \
{ \
	int ret; \
	unsigned int uint_value; \
	CALL_QCSAPI(wifi_get_##qcsapi_name, ret, qweb_get_wifi_ifname(path, array_name), &uint_value);\
	QWEBAPI_GET_RETURN(ret, NULL); \
	return JSON_NEW_INT(uint_value); \
}

#define QWEBAPI_GET_INT_OBJ_FUNC(func_name, qcsapi_name, array_name)  \
JSON *qweb_get_##func_name##_obj(char *path, int *perr) \
{ \
	int ret; \
	int int_value; \
	CALL_QCSAPI(wifi_get_##qcsapi_name, ret, qweb_get_wifi_ifname(path, array_name), &int_value);\
	QWEBAPI_GET_RETURN(ret, NULL); \
	return JSON_NEW_INT(int_value); \
}

#define QWEBAPI_SET_STRING_OBJ_FUNC(func_name, qcsapi_name, array_name)  \
int qweb_set_##func_name##_obj(char *path, JSON *obj) \
{ \
	int ret; \
	char *value; \
	value = (char *)JSON_GET_STRING(obj);\
	if (value == NULL) {\
		return QWEBAPI_ERR_INVALID_VALUE;\
	}\
	CALL_QCSAPI(wifi_set_##qcsapi_name, ret, qweb_get_wifi_ifname(path, array_name), value);\
	QWEBAPI_SET_RETURN(ret); \
}

#define QWEBAPI_GET_STRING_OBJ_FUNC(func_name, qcsapi_name, array_name)  \
JSON *qweb_get_##func_name##_obj(char *path, int *perr)\
{\
	int ret;\
	CALL_QCSAPI(wifi_get_##qcsapi_name, ret, qweb_get_wifi_ifname(path, array_name), string_value_buf);\
	QWEBAPI_GET_RETURN(ret, NULL); \
	return JSON_NEW_STRING(string_value_buf);\
}

#define QWEBAPI_SET_INT_FUNC(name, func_name, qcsapi_name, array_name)  \
int qweb_set_##func_name(char *path, int value) \
{ \
	int ret; \
	CALL_QCSAPI(name##_set_##qcsapi_name, ret, qweb_get_wifi_ifname(path, array_name), value);\
	QWEBAPI_SET_RETURN(ret); \
	return ret; \
}

#define QWEBAPI_WIFI_SET_INT_FUNC(func_name, qcsapi_name, array_name)  \
QWEBAPI_SET_INT_FUNC(wifi, func_name, qcsapi_name, array_name)

#define QWEBAPI_SET_UINT8_FUNC(name, func_name, qcsapi_name, array_name)  \
int qweb_set_##func_name(char *path, unsigned int value) \
{ \
	int ret; \
	CALL_QCSAPI(name##_set_##qcsapi_name, ret, qweb_get_wifi_ifname(path, array_name), (uint8_t)value);\
	QWEBAPI_SET_RETURN(ret); \
	return ret; \
}

#define QWEBAPI_WIFI_SET_UINT8_FUNC(func_name, qcsapi_name, array_name)  \
QWEBAPI_SET_UINT8_FUNC(wifi, func_name, qcsapi_name, array_name)

#define QWEBAPI_GET_UINT8_FUNC(name, func_name, qcsapi_name, array_name)  \
unsigned int qweb_get_##func_name(char *path, int *perr) \
{ \
	int ret; \
	uint8_t uint_value; \
	CALL_QCSAPI(name##_get_##qcsapi_name, ret, qweb_get_wifi_ifname(path, array_name), &uint_value);\
	QWEBAPI_GET_RETURN(ret, 0); \
	return (unsigned int)uint_value; \
}

#define QWEBAPI_WIFI_GET_UINT8_FUNC(func_name, qcsapi_name, array_name)  \
QWEBAPI_GET_UINT8_FUNC(wifi, func_name, qcsapi_name, array_name)

#define QWEBAPI_SET_UINT_FUNC(name, func_name, qcsapi_name, array_name)  \
int qweb_set_##func_name(char *path, unsigned int value) \
{ \
	int ret; \
	CALL_QCSAPI(name##_set_##qcsapi_name, ret, qweb_get_wifi_ifname(path, array_name), value);\
	QWEBAPI_SET_RETURN(ret); \
	return ret; \
}

#define QWEBAPI_WIFI_SET_UINT_FUNC(func_name, qcsapi_name, array_name)  \
QWEBAPI_SET_UINT_FUNC(wifi, func_name, qcsapi_name, array_name)

#define QWEBAPI_GET_UINT_FUNC(name, func_name, qcsapi_name, array_name)  \
unsigned int qweb_get_##func_name(char *path, int *perr) \
{ \
	int ret; \
	unsigned int uint_value; \
	CALL_QCSAPI(name##_get_##qcsapi_name, ret, qweb_get_wifi_ifname(path, array_name), &uint_value);\
	QWEBAPI_GET_RETURN(ret, 0); \
	return uint_value; \
}

#define QWEBAPI_WIFI_GET_UINT_FUNC(func_name, qcsapi_name, array_name)  \
QWEBAPI_GET_UINT_FUNC(wifi, func_name, qcsapi_name, array_name)

#define QWEBAPI_GET_INT_FUNC(name, func_name, qcsapi_name, array_name)  \
int qweb_get_##func_name(char *path, int *perr) \
{ \
	int ret;\
	int int_value;\
	CALL_QCSAPI(name##_get_##qcsapi_name, ret, qweb_get_wifi_ifname(path, array_name), &int_value);\
	QWEBAPI_GET_RETURN(ret, 0); \
	return int_value; \
}

#define QWEBAPI_WIFI_GET_INT_FUNC(func_name, qcsapi_name, array_name)  \
QWEBAPI_GET_INT_FUNC(wifi, func_name, qcsapi_name, array_name)

#define QWEBAPI_SET_STRING_FUNC(name, func_name, qcsapi_name, array_name)  \
int qweb_set_##func_name(char *path, char *value) \
{ \
	int ret; \
	CALL_QCSAPI(name##_set_##qcsapi_name, ret, qweb_get_wifi_ifname(path, array_name), value);\
	QWEBAPI_SET_RETURN(ret); \
	return ret;\
}

#define QWEBAPI_WIFI_SET_STRING_FUNC(func_name, qcsapi_name, array_name)  \
QWEBAPI_SET_STRING_FUNC(wifi, func_name, qcsapi_name, array_name)

#define QWEBAPI_GET_STRING_FUNC(name, func_name, qcsapi_name, array_name)  \
char *qweb_get_##func_name(char *path, int *perr)\
{\
	int ret;\
	CALL_QCSAPI(name##_get_##qcsapi_name, ret, qweb_get_wifi_ifname(path, array_name), string_value_buf);\
	QWEBAPI_GET_RETURN(ret, ""); \
	return string_value_buf;\
}

#define QWEBAPI_WIFI_GET_STRING_FUNC(func_name, qcsapi_name, array_name)  \
QWEBAPI_GET_STRING_FUNC(wifi, func_name, qcsapi_name, array_name)

#define QWEBAPI_GET_STRING_WITH_LEN_FUNC(name, func_name, qcsapi_name, array_name, max_len)  \
char *qweb_get_##func_name(char *path, int *perr)\
{\
	int ret;\
	CALL_QCSAPI(name##_get_##qcsapi_name, ret, qweb_get_wifi_ifname(path, array_name), string_value_buf, max_len);\
	QWEBAPI_GET_RETURN(ret, ""); \
	return string_value_buf;\
}

#define QWEBAPI_WPS_SET_STRING_FUNC(func_name, qcsapi_name, array_name)  \
QWEBAPI_SET_STRING_FUNC(wps, func_name, qcsapi_name, array_name)

#define QWEBAPI_WPS_GET_STRING_FUNC(func_name, qcsapi_name, array_name)  \
QWEBAPI_GET_STRING_FUNC(wps, func_name, qcsapi_name, array_name)

#define QWEBAPI_WPS_GET_STRING_WITH_LEN_FUNC(func_name, qcsapi_name, array_name, max_len)  \
QWEBAPI_GET_STRING_WITH_LEN_FUNC(wps, func_name, qcsapi_name, array_name, max_len)

#define QWEBAPI_SET_OPTION(name, func_name, option_type, array_name) \
int qweb_set_option_##func_name(char *path, int value)\
{\
	int ret;\
	char *ifname;\
\
	ifname = qweb_get_wifi_ifname(path, array_name);\
	CALL_QCSAPI(name##_set_option, ret, ifname, option_type, value);\
	QWEBAPI_SET_RETURN(ret); \
	return ret;\
}

#define QWEBAPI_WIFI_SET_OPTION(func_name, qcsapi_name, array_name)  \
QWEBAPI_SET_OPTION(wifi, func_name, qcsapi_name, array_name)

#define QWEBAPI_GET_OPTION(name, func_name, option_type, array_name) \
int qweb_get_option_##func_name(char *path, int *perr)\
{\
	int ret;\
	int option;\
	char *ifname;\
\
	ifname = qweb_get_wifi_ifname(path, array_name);\
	CALL_QCSAPI(name##_get_option, ret, ifname, option_type, &option);\
	QWEBAPI_GET_RETURN(ret, 0); \
	return option;\
}

#define QWEBAPI_WIFI_GET_OPTION(func_name, qcsapi_name, array_name)  \
QWEBAPI_GET_OPTION(wifi, func_name, qcsapi_name, array_name)

#define QWEBAPI_GET_UINT64_COUNTER_PER_ASSOC_FUNC(func_name, qcsapi_name)  \
uint64_t qweb_get_assoc_device_##func_name(char *path, int *perr) \
{ \
	int ret; \
	char *ifname;\
	uint64_t value;\
	int device_index = 0;\
\
	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);\
	device_index = qweb_get_key_index(path, ITEM_NAME_ASSOCIATED_DEVICE);\
	CALL_QCSAPI(wifi_get_##qcsapi_name##_per_association, ret, ifname, device_index, &value);\
\
	if (ret) {\
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;\
	}\
\
	return value;\
}

#define QWEBAPI_GET_UINT_COUNTER_PER_ASSOC_FUNC(func_name, qcsapi_name)  \
unsigned int qweb_get_assoc_device_##func_name(char *path, int *perr) \
{ \
	int ret; \
	char *ifname;\
	unsigned int value;\
	int device_index = 0;\
\
	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);\
	device_index = qweb_get_key_index(path, ITEM_NAME_ASSOCIATED_DEVICE);\
	CALL_QCSAPI(wifi_get_##qcsapi_name##_per_association, ret, ifname, device_index, &value);\
	if (ret) {\
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;\
	}\
\
	return value;\
}

#define QWEBAPI_GET_INTERFACE_COUNTER64(func_name, counter_type) \
uint64_t qweb_get_##func_name(char *path, int *perr) \
{\
	int ret;\
	char *ifname;\
	uint64_t value;\
\
	if (strstr(path, ITEM_NAME_RADIO)) \
		ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);\
	else if (strstr(path, ITEM_NAME_SSID)) \
		ifname = qweb_get_wifi_ifname(path, ITEM_NAME_SSID);\
	else {\
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;\
		return 0;\
	}\
\
	CALL_QCSAPI(interface_get_counter64, ret, ifname, counter_type, &value);\
	if (ret) {\
		qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, path = %s, ret = %d\n", __func__, __LINE__, path, ret);\
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;\
		return 0;\
	}\
\
	return value;\
}

#define QWEBAPI_GET_INTERFACE_STATS(func_name, stats_item) \
uint64_t qweb_get_##func_name(char *path, int *perr) \
{\
	int ret;\
	char *ifname;\
	qcsapi_interface_stats stats;\
\
	if (strstr(path, ITEM_NAME_RADIO)) \
		ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);\
	else if (strstr(path, ITEM_NAME_SSID)) \
		ifname = qweb_get_wifi_ifname(path, ITEM_NAME_SSID);\
	else {\
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;\
		return 0;\
	}\
\
	CALL_QCSAPI(get_interface_stats, ret, ifname, &stats);\
	if (ret) {\
		qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, path = %s, ret = %d\n", __func__, __LINE__, path, ret);\
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;\
		return 0;\
	}\
\
	return stats.stats_item;\
}

#define QWEBAPI_SET_STRING_FUNC_WITH_NOT_SUPPORT(func_name) \
int qweb_set_##func_name(char *path, char *value) \
{\
	return QWEBAPI_ERR_NOT_SUPPORT;\
}

#define QWEBAPI_GET_STRING_FUNC_WITH_NOT_SUPPORT(func_name) \
char *qweb_get_##func_name(char *path, int *perr) \
{\
	*perr = QWEBAPI_ERR_NOT_SUPPORT;\
	return "";\
}

#define QWEBAPI_SET_UINT_FUNC_WITH_NOT_SUPPORT(func_name) \
int qweb_set_##func_name(char *path, unsigned int value) \
{\
	return QWEBAPI_ERR_NOT_SUPPORT;\
}

#define QWEBAPI_GET_UINT_FUNC_WITH_NOT_SUPPORT(func_name) \
unsigned int qweb_get_##func_name(char *path, int *perr) \
{\
	*perr = QWEBAPI_ERR_NOT_SUPPORT;\
	return 0;\
}

#if defined (TOPAZ_DBDC)
static qcsapi_wifi_mode qweb_get_wifi_mode(void)
{
	qcsapi_wifi_mode mode = qcsapi_nosuch_mode;
	int is_repeater = 0;
	int ret;

	CALL_QCSAPI(wifi_verify_repeater_mode, is_repeater);
	if (1 == is_repeater)
		mode = qcsapi_repeater;
	else
		CALL_QCSAPI(wifi_get_mode, ret, TOPAZ_DBDC_5G_RADIO_NAME, &mode);

	return mode;
}
#endif

/* Device.DeviceInfo */
/* Model Name */
char *qweb_get_model_name(char *path, int *perr)
{
	return QWEBAPI_TR181_MODE_NAME;
}

/* UpTime */
int qweb_get_uptime(char *path, int *perr)
{
	struct sysinfo s_info;

	*perr = sysinfo(&s_info);
	if (*perr != 0) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), line = %d, code error = %d\n", __func__,
			   __LINE__, *perr);
		return 0;
	}

	return s_info.uptime;
}

/* Software Version */
char *qweb_get_software_version(char *path, int *perr)
{
	int ret;

	CALL_QCSAPI(firmware_get_version, ret, string_value_buf,
		    QWEBAPI_TR181_VERSION_MAX_LEN);
	QWEBAPI_GET_RETURN(ret, "");

	return string_value_buf;
}

/* Device.WiFi.RadioNumberOfEntries */
unsigned int qweb_get_radio_number_of_entries(char *path, int *perr)
{
	return qweb_get_radio_num(path);
}

/* Device.WiFi.SSIDNumberOfEntries */
unsigned int qweb_get_ssid_number_of_entries(char *path, int *perr)
{
	int i;
	int ret;
	int ssid_cnt = 0;
	char ssid_str[QWEBAPI_SSID_MAX_LEN + 1];

#ifdef PEARL_PLATFORM		/* BBIC5 */
	int iter = 0;
	while (radio_if_mapping[iter]) {
		for (i = 0; i < QWEBAPI_MAX_BSSID; i++) {
			snprintf(qweb_ifname, QWEBAPI_IFNAME_MAX_LEN, "%s_%d",
				 radio_if_mapping[iter], i);
			CALL_QCSAPI(wifi_get_SSID, ret, qweb_ifname, ssid_str);
			if (!ret) {
				ssid_cnt++;
			}
		}
		iter++;
	}
#elif defined (TOPAZ_DBDC)	/* QV860 */
	//calculate number of AP on 5G
	for (i = 0; i < QWEBAPI_MAX_BSSID; i++) {
		snprintf(qweb_ifname, QWEBAPI_IFNAME_MAX_LEN, "%s%d", if_wifi,
			 i);
		CALL_QCSAPI(wifi_get_SSID, ret, qweb_ifname, ssid_str);
		if (!ret) {
			ssid_cnt++;
		}
	}

	//calculate number of AP on 3rd 2.4G
	CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG, QWEBAPI_OP_GET,
		    "enable.wlan1", NULL, string_value_buf,
		    QWEBAPI_TR181_STRING_MAX_LEN);
	if (!ret) {
		if (!strcmp(string_value_buf, "1")) {
			ssid_cnt++;
		}
	}

	for (i = 0; i < QWEBAPI_MAX_24G_VAP; i++) {
		snprintf(qweb_ifname, QWEBAPI_IFNAME_MAX_LEN,
			 "enable.vap%d.wlan1", i);
		CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG, QWEBAPI_OP_GET,
			    qweb_ifname, NULL, string_value_buf,
			    QWEBAPI_TR181_STRING_MAX_LEN);
		if (!ret) {
			if (!strcmp(string_value_buf, "1")) {
				ssid_cnt++;
			}
		}
	}
#else
	for (i = 0; i < QWEBAPI_MAX_BSSID; i++) {
		snprintf(qweb_ifname, QWEBAPI_IFNAME_MAX_LEN, "%s%d", if_wifi,
			 i);
		CALL_QCSAPI(wifi_get_SSID, ret, qweb_ifname, ssid_str);
		if (!ret) {
			ssid_cnt++;
		}
	}
#endif
	return ssid_cnt;
}

/* Device.WiFi.AccessPointNumberOfEntries */
unsigned int qweb_get_ap_number_of_entries(char *path, int *perr)
{
	return qweb_get_ssid_number_of_entries(path, perr);
}

/* Device.WiFi.EndPointNumberOfEntries */
unsigned int qweb_get_endpoint_number_of_entries(char *path, int *perr)
{
#ifdef PEARL_PLATFORM
	return 3;
#else
	return 1;
#endif
}

/* Device.WiFi.Radio */
int qweb_get_radio_num(char *path)
{
	return QWEBAPI_RADIO_COUNT;
}

/* Device.WiFi.Radio.{i}.Enable */
int qweb_set_radio_enable(char *path, unsigned int value)
{
	int ret;

	if (!(value == 0 || value == 1)) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value = %d, the value is out of the range[0,1].\n",
			   __func__, __LINE__);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	CALL_QCSAPI(wifi_rfenable, ret, value);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

unsigned int qweb_get_radio_enable(char *path, int *perr)
{
	int ret;
	unsigned int status;

	CALL_QCSAPI(wifi_rfstatus, ret, &status);
	QWEBAPI_GET_RETURN(ret, 0);

	return status;
}

/* Device.WiFi.Radio.{i}.Status */
char *qweb_get_radio_status(char *path, int *perr)
{
	int ret;
	char *ifname;
	char interface_status[32];

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(interface_get_status, ret, ifname, interface_status);
	if (ret) {
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		return ITEM_VALUE_UNKNOWN;
	}

	if (strcmp(interface_status, ITEM_VALUE_UP) == 0)
		return ITEM_VALUE_UP;
	else if (strcmp(interface_status, ITEM_VALUE_DISABLED) == 0)
		return ITEM_VALUE_DOWN;
	else if (strcmp(interface_status, ITEM_VALUE_ERROR) == 0)
		return ITEM_VALUE_ERROR;
	else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, the status is not up and disabled.\n",
			   __func__, __LINE__);
		*perr = QWEBAPI_ERR_INVALID_VALUE;
		return ITEM_VALUE_UNKNOWN;
	}
}

/* Device.WiFi.Radio.{i}.Alias */
QWEBAPI_SET_STRING_FUNC_WITH_NOT_SUPPORT(radio_alias);
QWEBAPI_GET_STRING_FUNC_WITH_NOT_SUPPORT(radio_alias);

/* Device.WiFi.Radio.{i}.LastChange */
QWEBAPI_GET_UINT_FUNC_WITH_NOT_SUPPORT(radio_last_change);

/* Device.WiFi.Radio.{i}.Upstream */
QWEBAPI_GET_UINT_FUNC_WITH_NOT_SUPPORT(radio_up_stream);

/* Device.WiFi.Radio.{i}.Name */
char *qweb_get_radio_name(char *path, int *perr)
{
#if defined (PEARL_PLATFORM) || defined (TOPAZ_DBDC)
	int index;

	index = qweb_get_key_index(path, ITEM_NAME_RADIO);
	if (index >= QWEBAPI_RADIO_COUNT) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, index is wrong, index = %d\n",
			   __func__, __LINE__, index);
		*perr = QWEBAPI_ERR_INVALID_VALUE;
		return "";
	}

	return radio_if_mapping[index];
#else
	int ret;

	CALL_QCSAPI(wifi_get_ap_interface_name, ret, string_value_buf);
	QWEBAPI_GET_RETURN(ret, "");

	return string_value_buf;
#endif
}

/* Device.WiFi.Radio.{i}.LowerLayers */
char *qweb_get_radio_lower_layers(char *path, int *perr)
{
#if defined (PEARL_PLATFORM) || defined (TOPAZ_DBDC)
	int index;

	index = qweb_get_key_index(path, ITEM_NAME_RADIO);
	if (index >= QWEBAPI_RADIO_COUNT) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, index is wrong, index = %d\n",
			   __func__, __LINE__, index);
		*perr = QWEBAPI_ERR_INVALID_VALUE;
		return "";
	}

	return radio_if_mapping[index];
#else
	return radio0;
#endif
}

/* Device.WiFi.Radio.{i}.MaxBitRate */
char *qweb_get_max_bit_rate(char *path, int *perr)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);

	memset(string_value_buf, 0, QWEBAPI_TR181_STRING_MAX_LEN);
	CALL_QCSAPI(get_max_bitrate, ret, ifname, string_value_buf,
		    QWEBAPI_MAX_BITRATE_STR_MIN_LEN);
	QWEBAPI_GET_RETURN(ret, "");

	return string_value_buf;
}

/* Device.WiFi.Radio.{i}.SupportedFrequencyBands */
char *qweb_get_supported_frequency_bands(char *path, int *perr)
{
	int ret;
	char *start;
	char *ifname;
	char bands[32 + 1];
	int need_comma = 0;

#ifdef TOPAZ_DBDC
	int index;
	index = qweb_get_key_index(path, ITEM_NAME_RADIO);

	if (index == 1) {
		return ITEM_NAME_OPERATING_BAND_24G;
	}
#endif

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(wifi_get_supported_freq_bands, ret, ifname, bands);
	QWEBAPI_GET_RETURN(ret, "");

	string_value_buf[0] = '\0';
	if ((start = strstr(bands, "2.4G"))) {
		strncat(string_value_buf, ITEM_NAME_OPERATING_BAND_24G,
			strlen(ITEM_NAME_OPERATING_BAND_24G));
		need_comma = 1;
	}

	if ((start = strstr(bands, "5G"))) {
		if (need_comma)
			strncat(string_value_buf, ",", strlen(","));

		strncat(string_value_buf, ITEM_NAME_OPERATING_BAND_5G,
			strlen(ITEM_NAME_OPERATING_BAND_5G));
	}

	return string_value_buf;
}

/* Device.WiFi.Radio.{i}.OperatingBand */
int qweb_set_operating_band(char *path, char *value)
{
	int ret;
	char *ifname;
	qcsapi_pref_band band;

	if (strcasecmp(value, ITEM_NAME_OPERATING_BAND_24G) == 0)
		band = qcsapi_band_2_4ghz;
	else if (strcasecmp(value, ITEM_NAME_OPERATING_BAND_5G) == 0)
		band = qcsapi_band_5ghz;
	else
		return QWEBAPI_ERR_INVALID_VALUE;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(wifi_set_pref_band, ret, ifname, band);
	if (ret)
		ret = QWEBAPI_ERR_NOT_AVALIABLE;

	return ret;
}

char *qweb_get_operating_band(char *path, int *perr)
{
	int ret;
	char *ifname;
	qcsapi_pref_band band;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(wifi_get_pref_band, ret, ifname, &band);
	if (ret) {
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		return "";
	}

	if (band == qcsapi_band_2_4ghz)
		return ITEM_NAME_OPERATING_BAND_24G;
	else if (band == qcsapi_band_5ghz)
		return ITEM_NAME_OPERATING_BAND_5G;
	else {
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		return "";
	}
}

/* Device.WiFi.Radio.{i}.SupportedStandards */
char *qweb_get_supported_standards(char *path, int *perr)
{
	int ret;
	char vht[64];
	char chipid[64];

#ifdef TOPAZ_DBDC
	int index;
	index = qweb_get_key_index(path, ITEM_NAME_RADIO);
	if (index == 1) {
		return ITEM_NAME_STANDARDS_NG;
	}
#endif
	CALL_QCSAPI(get_board_parameter, ret, qcsapi_rf_chipid, chipid);
	if (ret)
		ret = QWEBAPI_ERR_NOT_AVALIABLE;

	CALL_QCSAPI(get_board_parameter, ret, qcsapi_vht, vht);
	if (ret)
		ret = QWEBAPI_ERR_NOT_AVALIABLE;

	if (strcmp(chipid, "2") == 0) {
		snprintf(string_value_buf, QWEBAPI_TR181_STRING_MAX_LEN,
			 "%s,%s,%s,%s,%s", ITEM_NAME_STANDARDS_A,
			 ITEM_NAME_STANDARDS_B, ITEM_NAME_STANDARDS_G,
			 ITEM_NAME_STANDARDS_NA, ITEM_NAME_STANDARDS_NG);
		if (strcmp(vht, "1") == 0) {
			strcat(string_value_buf, QWEBAPI_COMMA);
			strcat(string_value_buf, ITEM_NAME_STANDARDS_AC);
		}
	} else if (strcmp(chipid, "0") == 0) {
		snprintf(string_value_buf, QWEBAPI_TR181_STRING_MAX_LEN,
			 "%s,%s,%s", ITEM_NAME_STANDARDS_NG,
			 ITEM_NAME_STANDARDS_B, ITEM_NAME_STANDARDS_BG);
	} else {

		if (strcmp(vht, "1") == 0) {
			snprintf(string_value_buf, QWEBAPI_TR181_STRING_MAX_LEN,
				 "%s,%s,%s", ITEM_NAME_STANDARDS_AC,
				 ITEM_NAME_STANDARDS_NA, ITEM_NAME_STANDARDS_A);
		} else {
			snprintf(string_value_buf, QWEBAPI_TR181_STRING_MAX_LEN,
				 "%s,%s", ITEM_NAME_STANDARDS_NA,
				 ITEM_NAME_STANDARDS_A);
		}
	}

	return string_value_buf;
}

/* Device.WiFi.Radio.{i}.OperatingStandards */
int qweb_set_operating_standards(char *path, char *value)
{
	int ret;
	char *ifname;
	char *band;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);

	if (!strcasecmp(value, ITEM_NAME_STANDARDS_A))
		band = ITEM_NAME_STANDARDS_80211_A;
	else if (!strcasecmp(value, ITEM_NAME_STANDARDS_NA))
		band = ITEM_NAME_STANDARDS_80211_NA;
	else if (!strcasecmp(value, ITEM_NAME_STANDARDS_B))
		band = ITEM_NAME_STANDARDS_80211_B;
	else if (!strcasecmp(value, ITEM_NAME_STANDARDS_G))
		band = ITEM_NAME_STANDARDS_80211_G;
	else if (!strcasecmp(value, ITEM_NAME_STANDARDS_NG))
		band = ITEM_NAME_STANDARDS_80211_NG;
	else if (!strcasecmp(value, ITEM_NAME_STANDARDS_AC))
		band = ITEM_NAME_STANDARDS_80211_AC;
	else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%(), %d, value is wrong, value = %s\n",
			   __func__, __LINE__, value);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	CALL_QCSAPI(wifi_set_phy_mode, ret, ifname, band);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

char *qweb_get_operating_standards(char *path, int *perr)
{
	int ret;
	char *ifname;

#ifdef TOPAZ_DBDC
	int index;
	index = qweb_get_key_index(path, ITEM_NAME_RADIO);
	if (index == 1) {
		return ITEM_NAME_STANDARDS_NG;
	}
#endif

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(wifi_get_phy_mode, ret, ifname, string_value_buf);

	QWEBAPI_GET_RETURN(ret, "");

	if (strstr(string_value_buf, ITEM_NAME_STANDARDS_80211_AC))
		return ITEM_NAME_STANDARDS_AC;
	else if (strstr(string_value_buf, ITEM_NAME_STANDARDS_80211_NA))
		return ITEM_NAME_STANDARDS_NA;
	else if (strstr(string_value_buf, ITEM_NAME_STANDARDS_80211_NG))
		return ITEM_NAME_STANDARDS_NG;
	else if (strstr(string_value_buf, ITEM_NAME_STANDARDS_80211_B))
		return ITEM_NAME_STANDARDS_B;
	else if (strstr(string_value_buf, ITEM_NAME_STANDARDS_80211_G))
		return ITEM_NAME_STANDARDS_G;
	else if (strstr(string_value_buf, ITEM_NAME_STANDARDS_80211_A))
		return ITEM_NAME_STANDARDS_A;
	else
		return "";
}

/* Device.WiFi.Radio.{i}.ChannelsInUse */
QWEBAPI_WIFI_GET_STRING_FUNC(channels_in_use, list_channels, ITEM_NAME_RADIO);

/* Device.WiFi.Radio.{i}.Channel */
int qweb_set_channel(char *path, unsigned int value)
{
	int ret1;
	int ret2;
	char tmp[4];
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(wifi_set_channel, ret1, ifname, value);
	snprintf(tmp, 4, "%d", value);
	CALL_QCSAPI(config_update_parameter, ret2, ifname,
		    ITEM_VALUE_CHANNEL, tmp);
	if (ret1 || ret2) {
		if (ret1 == -22)
			ret1 = QWEBAPI_ERR_INVALID_VALUE;
		else
			ret2 = QWEBAPI_ERR_NOT_AVALIABLE;
	} else {
		CALL_QCSAPI(config_update_parameter, ret1, ifname,
			    ITEM_VALUE_CHANNEL, tmp);
	}

	return ret1;
}

QWEBAPI_WIFI_GET_UINT_FUNC(channel, channel, ITEM_NAME_RADIO);

/* Device.WiFi.Radio.{i}.AutoChannelSupported */
unsigned int qweb_get_auto_channel_supported(char *path, int *perr)
{
	return 1;
}

/* Device.WiFi.Radio.{i}.AutoChannelEnable */
int qweb_set_auto_channel_enable(char *path, unsigned int value)
{
	int ret1;
	int ret2;
	char tmp[4];
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(config_get_parameter, ret1, ifname,
		    ITEM_VALUE_CHANNEL, tmp, 4);

	if (value == 1 && atoi(tmp) != 0) {
		CALL_QCSAPI(wifi_set_channel, ret1, ifname, 0);
		CALL_QCSAPI(config_update_parameter, ret2, ifname,
			    ITEM_VALUE_CHANNEL, "0");
		if (ret1 || ret2)
			return QWEBAPI_ERR_NOT_AVALIABLE;

		snprintf(tmp, 4, "%d", 0);
	} else if (value == 1 && atoi(tmp) == 0) {
		return QWEBAPI_OK;
	} else if (value == 0 && atoi(tmp) == 0) {
		int default_chan = 100;

		CALL_QCSAPI(wifi_set_channel, ret1, ifname, default_chan);
		snprintf(tmp, 4, "%d", default_chan);
		CALL_QCSAPI(config_update_parameter, ret2, ifname,
			    ITEM_VALUE_CHANNEL, tmp);
		if (ret1 || ret2)
			return QWEBAPI_ERR_NOT_AVALIABLE;
	} else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is wrong, value = %s\n",
			   __func__, __LINE__, value);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	CALL_QCSAPI(config_update_parameter, ret1, ifname,
		    ITEM_VALUE_CHANNEL, tmp);
	if (ret1)
		return QWEBAPI_ERR_NOT_AVALIABLE;

	return ret1;
}

unsigned int qweb_get_auto_channel_enable(char *path, int *perr)
{
	int ret;
	char *ifname;
	char auto_channel[4] = { 0x00 };

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(config_get_parameter, ret, ifname, ITEM_VALUE_CHANNEL,
		    auto_channel, 4);
	if (ret)
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;

	return (atoi(auto_channel)) ? 0 : 1;
}

/* Device.WiFi.Radio.{i}.AutoChannelRefreshPeriod */
QWEBAPI_SET_UINT_FUNC_WITH_NOT_SUPPORT(auto_channel_refresh_period);
QWEBAPI_GET_UINT_FUNC_WITH_NOT_SUPPORT(auto_channel_refresh_period);

/* Device.WiFi.Radio.{i}.OperatingChannelBandwidth */
int qweb_set_bw(char *path, char *value)
{
	int ret;
	char *ifname;
	unsigned int bandwidth;

	if (strcasecmp(value, ITEM_NAME_BW_20M) == 0)
		bandwidth = ITEM_VALUE_BW_20M;
	else if (strcasecmp(value, ITEM_NAME_BW_40M) == 0)
		bandwidth = ITEM_VALUE_BW_40M;
	else if (strcasecmp(value, ITEM_NAME_BW_80M) == 0)
		bandwidth = ITEM_VALUE_BW_80M;
	else if (strcasecmp(value, ITEM_NAME_BW_160M) == 0)
		bandwidth = ITEM_VALUE_BW_160M;
	else
		return QWEBAPI_ERR_INVALID_VALUE;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(wifi_set_bw, ret, ifname, bandwidth);
	if (ret)
		ret = QWEBAPI_ERR_NOT_AVALIABLE;

	return ret;
}

char *qweb_get_bw(char *path, int *perr)
{
	int ret;
	char *ifname;
	unsigned int bandwidth;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(wifi_get_bw, ret, ifname, &bandwidth);
	if (ret) {
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		return "";
	}

	if (bandwidth == ITEM_VALUE_BW_20M)
		strncpy(string_value_buf, ITEM_NAME_BW_20M,
			QWEBAPI_TR181_STRING_MAX_LEN);
	else if (bandwidth == ITEM_VALUE_BW_40M)
		strncpy(string_value_buf, ITEM_NAME_BW_40M,
			QWEBAPI_TR181_STRING_MAX_LEN);
	else if (bandwidth == ITEM_VALUE_BW_80M)
		strncpy(string_value_buf, ITEM_NAME_BW_80M,
			QWEBAPI_TR181_STRING_MAX_LEN);
	else if (bandwidth == ITEM_VALUE_BW_160M)
		strncpy(string_value_buf, ITEM_NAME_BW_160M,
			QWEBAPI_TR181_STRING_MAX_LEN);
	else {
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		return "";
	}

	return string_value_buf;
}

/* Device.WiFi.Radio.{i}.ExtensionChannel */
QWEBAPI_SET_STRING_FUNC_WITH_NOT_SUPPORT(extension_channel);
QWEBAPI_GET_STRING_FUNC_WITH_NOT_SUPPORT(extension_channel);

/* Device.WiFi.Radio.{i}.GuardInterval */
int qweb_set_gi(char *path, char *value)
{
	int ret;
	int short_gi;
	char *ifname;

	if (strcasecmp(value, ITEM_VALUE_GI_400) == 0
	    || strcasecmp(value, ITEM_VALUE_GI_AUTO) == 0) {
		short_gi = 1;
	} else if (strcasecmp(value, ITEM_VALUE_GI_800) == 0) {
		short_gi = 0;
	} else {
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(wifi_set_option, ret, ifname, qcsapi_short_GI, short_gi);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

char *qweb_get_gi(char *path, int *perr)
{
	int ret;
	int short_gi;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(wifi_get_option, ret, ifname, qcsapi_short_GI, &short_gi);
	QWEBAPI_GET_RETURN(ret, "");

	if (short_gi == 1) {
		return ITEM_VALUE_GI_400;
	} else if (short_gi == 0) {
		return ITEM_VALUE_GI_800;
	} else {
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		return "";
	}
}

/* Device.WiFi.Radio.{i}.MCS */
int qweb_set_mcs(char *path, int value)
{
	int ret;
	char *ifname;
	char mcs_string[8];

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);

	if (value == -1) {
		CALL_QCSAPI(wifi_set_option, ret, ifname,
			    qcsapi_autorate_fallback, 1);
	} else {
		snprintf(mcs_string, 8, "%s%d", ITEM_NAME_MCS, value);
		CALL_QCSAPI(wifi_set_mcs_rate, ret, ifname, mcs_string);
	}

	QWEBAPI_SET_RETURN(ret);

	return ret;
}

int qweb_get_mcs(char *path, int *perr)
{
	int ret;
	int mcs;
	char *ifname;
	char mcs_string[8];

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(wifi_get_mcs_rate, ret, ifname, mcs_string);
	if (ret == 0) {
		sscanf(mcs_string, "MCS%d", &mcs);

		return mcs;
	} else if (ret == -1005) {
		int autorate;
		CALL_QCSAPI(wifi_get_option, ret, ifname,
			    qcsapi_autorate_fallback, &autorate);
		if (ret) {
			qwebprintf(DBG_LEVEL_VERBOSE,
				   "%s(), %d, get option failed. ret = %d\n",
				   __func__, __LINE__, ret);
			*perr = QWEBAPI_ERR_NOT_AVALIABLE;
			return 0;
		}

		if (autorate == 1)
			return -1;
		else
			return 0;
	} else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, get option failed. ret = %d\n",
			   __func__, __LINE__, ret);
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		return 0;
	}
}

/* Device.WiFi.Radio.{i}.TransmitPowerSupported */
QWEBAPI_WIFI_GET_STRING_FUNC(transmit_power_supported,
			     supported_tx_power_levels, ITEM_NAME_RADIO);

/* Device.WiFi.Radio.{i}.TransmitPower */
int qweb_set_transmit_power(char *path, unsigned int tx_power)
{
	/* It doesn't support to set tx power  */
	return QWEBAPI_ERR_NOT_AVALIABLE;
}

QWEBAPI_WIFI_GET_UINT_FUNC(transmit_power,
			   current_tx_power_level, ITEM_NAME_RADIO);

/* Device.WiFi.Radio.{i}.IEEE80211hSupported */
unsigned int qweb_get_option_80211h_supported(char *path, int *perr)
{
	/* always return 1 */
	return 1;
}

/* Device.WiFi.Radio.{i}.IEEE80211hEnabled */
int qweb_set_doth_enable(char *path, unsigned int value)
{
	int ret;
	char *ifname;
	char regulatory_region[8];

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(wifi_get_regulatory_region, ret, ifname, regulatory_region);
	if (ret)
		goto failed;
	else if (!strcmp(regulatory_region, ITEM_VALUE_NONE))
		goto failed;

	CALL_QCSAPI(wifi_set_option, ret, ifname, qcsapi_802_11h, value);
	QWEBAPI_SET_RETURN(ret);

	return ret;

 failed:
	qwebprintf(DBG_LEVEL_VERBOSE,
		   "%s(), %d, get region failed. region = %s\n", __func__,
		   __LINE__, regulatory_region);
	return QWEBAPI_ERR_NOT_AVALIABLE;
}

unsigned int qweb_get_doth_enable(char *path, int *perr)
{
	int ret;
	int value;
	char *ifname;
	char regulatory_region[8];

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(wifi_get_regulatory_region, ret, ifname, regulatory_region);
	if (ret)
		goto failed;
	else if (!strcmp(regulatory_region, ITEM_VALUE_NONE))
		goto failed;

	CALL_QCSAPI(wifi_get_option, ret, ifname, qcsapi_802_11h, &value);
	QWEBAPI_GET_RETURN(ret, 0);

	return value;

 failed:
	qwebprintf(DBG_LEVEL_VERBOSE,
		   "%s(), %d, get region failed. region = %s\n", __func__,
		   __LINE__, regulatory_region);
	return 0;
}

/* Device.WiFi.Radio.{i}.BeaconInterval */
QWEBAPI_WIFI_SET_UINT_FUNC(beacon_interval, beacon_interval, ITEM_NAME_RADIO);
QWEBAPI_WIFI_GET_UINT_FUNC(beacon_interval, beacon_interval, ITEM_NAME_RADIO);

/* Device.WiFi.Radio.{i}.DTIM */
QWEBAPI_WIFI_SET_UINT_FUNC(dtim, dtim, ITEM_NAME_RADIO);
QWEBAPI_WIFI_GET_UINT_FUNC(dtim, dtim, ITEM_NAME_RADIO);

/* Device.WiFi.Radio.{i}.PreambleType */
int qweb_set_preamble_type(char *path, char *value)
{
	int ret;
	int preamble;
	char *ifname;

	if (strcasecmp(value, ITEM_VALUE_PREAMBLE_TYPE_SHORT) == 0
	    || strcasecmp(value, ITEM_VALUE_PREAMBLE_TYPE_AUTO) == 0) {
		preamble = 1;
	} else if (strcasecmp(value, ITEM_VALUE_PREAMBLE_TYPE_LONG) == 0) {
		preamble = 0;
	} else {
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(wifi_set_option, ret, ifname, qcsapi_short_preamble,
		    preamble);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

char *qweb_get_preamble_type(char *path, int *perr)
{
	int ret;
	int preamble;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(wifi_get_option, ret, ifname, qcsapi_short_preamble,
		    &preamble);
	QWEBAPI_GET_RETURN(ret, "");

	if (preamble == 1) {
		return ITEM_VALUE_PREAMBLE_TYPE_SHORT;
	} else if (preamble == 0) {
		return ITEM_VALUE_PREAMBLE_TYPE_LONG;
	} else {
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		return "";
	}
}

/* Device.WiFi.Radio.{i}.X_QUANTENNA_COM_Mode */
int qweb_set_mode(char *path, char *value)
{
	int ret;
	char *ifname;
	qcsapi_wifi_mode mode;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(wifi_get_mode, ret, ifname, &mode);
	if (ret)
		goto qcsapi_err;

	if (strcmp(value, ITEM_NAME_AP) == 0) {
		if (mode != qcsapi_access_point) {
			CALL_QCSAPI(config_update_parameter, ret, ifname,
				    ITEM_VALUE_MODE, ITEM_NAME_AP);
			if (ret)
				goto qcsapi_err;
		} else {
			qwebprintf(DBG_LEVEL_VERBOSE,
				   "%s(), %d, current mode is ap\n",
				   __func__, __LINE__, value);
			return 0;
		}
	} else if (strcmp(value, ITEM_NAME_STA) == 0 && mode != qcsapi_station) {
		CALL_QCSAPI(config_update_parameter, ret, ifname,
				ITEM_VALUE_MODE, ITEM_NAME_STA);
		if (ret)
			goto qcsapi_err;
	} else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is wrong. value = %s\n",
			   __func__, __LINE__, value);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	return 0;

 qcsapi_err:
	return QWEBAPI_ERR_NOT_AVALIABLE;
}

char *qweb_get_mode(char *path, int *perr)
{
	int ret;
	char *ifname;
	qcsapi_wifi_mode mode;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(wifi_get_mode, ret, ifname, &mode);

	switch (mode) {
	case qcsapi_access_point:
		return ITEM_NAME_AP;
	case qcsapi_station:
		return ITEM_NAME_STA;
	case qcsapi_wds:
		return ITEM_NAME_WDS;
	case qcsapi_repeater:
		return ITEM_NAME_REPEATER;
	default:
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		return "";
	}
}

/* Device.WiFi.Radio.{i}.X_QUANTENNA_COM_PMF */
QWEBAPI_WIFI_SET_INT_FUNC(pmf, pmf, ITEM_NAME_RADIO);
QWEBAPI_WIFI_GET_INT_FUNC(pmf, pmf, ITEM_NAME_RADIO);

/* Device.WiFi.Radio.{i}.X_QUANTENNA_COM_NSS */
int qweb_set_nss(char *path, char *value)
{
	int ret;
	char *nss;
	char *modulation;
	char *ifname;

	modulation = strtok(value, QWEBAPI_SPACE);
	nss = strtok(NULL, QWEBAPI_SPACE);

	if (modulation == NULL || nss == NULL) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is wrong. value = %s\n",
			   __func__, __LINE__, value);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	if (strcasecmp(modulation, ITEM_NAME_HT) == 0) {
		CALL_QCSAPI(wifi_set_nss_cap, ret, ifname, qcsapi_mimo_ht,
			    (unsigned int)atoi(nss));
		if (ret)
			return QWEBAPI_ERR_NOT_AVALIABLE;
	} else if (strcasecmp(modulation, ITEM_NAME_VHT) == 0) {
		CALL_QCSAPI(wifi_set_nss_cap, ret, ifname, qcsapi_mimo_vht,
			    (unsigned int)atoi(nss));
		if (ret)
			return QWEBAPI_ERR_NOT_AVALIABLE;
	} else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is wrong. value = %s\n",
			   __func__, __LINE__, value);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	return 0;
}

char *qweb_get_nss(char *path, int *perr)
{
	int ret;
	char *ifname;
	unsigned int ht_nss;
	unsigned int vht_nss;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(wifi_get_nss_cap, ret, ifname, qcsapi_mimo_ht, &ht_nss);
	if (ret)
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;

	CALL_QCSAPI(wifi_get_nss_cap, ret, ifname, qcsapi_mimo_vht, &vht_nss);
	if (ret)
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;

	snprintf(string_value_buf, QWEBAPI_TR181_STRING_MAX_LEN, "%s:%d,%s:%d",
		 ITEM_NAME_HT, ht_nss, ITEM_NAME_VHT, vht_nss);

	return string_value_buf;
}

/* Device.WiFi.Radio.{i}.X_QUANTENNA_COM_Auto_rate */
QWEBAPI_WIFI_SET_OPTION(auto_rate, qcsapi_autorate_fallback, ITEM_NAME_RADIO);
QWEBAPI_WIFI_GET_OPTION(auto_rate, qcsapi_autorate_fallback, ITEM_NAME_RADIO);

/* Device.WiFi.Radio.{i}.X_QUANTENNA_COM_SupportedBandwidth */
char *qweb_get_supported_bw(char *path, int *perr)
{
#ifdef PEARL_PLATFORM
	int index;

	index = qweb_get_key_index(path, ITEM_NAME_RADIO);
	if (index == 0 || index == 1) {
		snprintf(string_value_buf, QWEBAPI_TR181_STRING_MAX_LEN,
			 "%s,%s,%s", ITEM_NAME_BW_20M, ITEM_NAME_BW_40M,
			 ITEM_NAME_BW_80M);
	} else if (index == 2) {
		snprintf(string_value_buf, QWEBAPI_TR181_STRING_MAX_LEN,
			 "%s,%s", ITEM_NAME_BW_20M, ITEM_NAME_BW_40M);
	} else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, index is wrong. path = %s\n",
			   __func__, __LINE__, path);
		*perr = QWEBAPI_ERR_INVALID_PATH;
		return "";
	}
#else
	snprintf(string_value_buf, QWEBAPI_TR181_STRING_MAX_LEN, "%s,%s,%s",
		 ITEM_NAME_BW_20M, ITEM_NAME_BW_40M, ITEM_NAME_BW_80M);
#endif
	return string_value_buf;
}

/* Device.WiFi.Radio.{i}.RegulatoryDomain */
int qweb_set_regulatory_region(char *path, char *value)
{
	int ret;
	char *ifname;
	char domain[3] = { 0 };

	strncpy(domain, value, 2);

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(regulatory_set_regulatory_region, ret, ifname, domain);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

QWEBAPI_WIFI_GET_STRING_FUNC(regulatory_region, regulatory_region,
			     ITEM_NAME_RADIO);

/* Device.WiFi.Radio.{i}.X_QUANTENNA_COM_Regulatory_channel */
int qweb_set_regulatory_channel(char *path, char *value)
{
	int ret;
	char *ifname;
	char *channel;
	char *region;
	char *offset;

	channel = strtok(value, QWEBAPI_SPACE);
	region = strtok(NULL, QWEBAPI_SPACE);
	offset = strtok(NULL, QWEBAPI_SPACE);

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(wifi_set_regulatory_channel, ret, ifname,
		    atoi(channel), region, atoi(offset));

	QWEBAPI_SET_RETURN(ret);

	return ret;
}

char *qweb_get_regulatory_channel(char *path, int *perr)
{
	int ret;
	int len;
	char *buf;
	char *ifname;
	char region[32];

	buf = calloc(1024, sizeof(char));
	if (buf == NULL) {
		qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, calloc failed.\n",
			   __func__, __LINE__);
		return "";
	}

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_RADIO);
	CALL_QCSAPI(wifi_get_regulatory_region, ret, ifname, region);
	if (ret) {
		qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, get region failed.\n",
			   __func__, __LINE__);
		safe_free(buf);
		return "";
	}

	string_value_buf[0] = '\0';
	CALL_QCSAPI(wifi_get_list_regulatory_channels, ret, region, 20, buf);
	if (ret == 0 && (strlen(string_value_buf)
			 + strlen("Bandwidth(20MHz):")
			 + strlen(buf)
			 + strlen(QWEBAPI_ENTER)
			 < sizeof(string_value_buf) - 1)) {
		strcat(string_value_buf, "Bandwidth(20MHz):");
		strncat(string_value_buf, buf, strlen(buf));
		strcat(string_value_buf, QWEBAPI_ENTER);
	}

	CALL_QCSAPI(wifi_get_list_regulatory_channels, ret, region, 40, buf);
	if (ret == 0 && (strlen(string_value_buf)
			 + strlen("Bandwidth(40MHz):")
			 + strlen(buf)
			 + strlen(QWEBAPI_SPACE)
			 < sizeof(string_value_buf) - 1)) {
		strcat(string_value_buf, "Bandwidth(40MHz):");
		strncat(string_value_buf, buf, strlen(buf));
		strcat(string_value_buf, QWEBAPI_SPACE);
	}

	len = strlen(string_value_buf);
	if (len > 0)
		string_value_buf[len - 1] = '\0';

	safe_free(buf);
	return string_value_buf;
}

/* Device.WiFi.SSID.{i} */
int qweb_get_ssid_max_num(char *path)
{
#ifdef PEARL_PLATFORM
	return 3 * QWEBAPI_MAX_BSSID;
#elif defined (TOPAZ_DBDC)
	return QWEBAPI_MAX_BSSID + QWEBAPI_MAX_24G_BSSID;
#else
	return QWEBAPI_MAX_BSSID;
#endif
}

#ifdef TOPAZ_DBDC
static int qweb_entry_is_exist_24G(char *path, char *ifname, char *arr_name)
{
	int ret = 0;
	int index;

	index = qweb_get_key_index(path, arr_name);
	if (index <= 7) {
		CALL_QCSAPI(wifi_get_SSID, ret, ifname, string_value_buf);
	} else if (index <= 12) {
		char qweb_cmd[QWEBAPI_CMD_MAX_LEN];
		snprintf(qweb_cmd, QWEBAPI_CMD_MAX_LEN, "enable.%s", ifname);
		CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG, QWEBAPI_OP_GET,
			    qweb_cmd, NULL, string_value_buf,
			    QWEBAPI_TR181_STRING_MAX_LEN);

		if (ret) {
			return 0;
		}
		return strcmp(string_value_buf, "1") ? 0 : 1;
	}
	return (ret) ? 0 : 1;
}
#endif

int qweb_ssid_exist(char *path)
{
	char *ifname;
	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_SSID);
#ifdef TOPAZ_DBDC
	return qweb_entry_is_exist_24G(path, ifname, ITEM_NAME_SSID);
#else
	int ret;
	CALL_QCSAPI(wifi_get_SSID, ret, ifname, string_value_buf);
	return (ret) ? 0 : 1;
#endif
}

static int qweb_add_ap_entry(char *path, char *array_name)
{
	int ret;
	long int index = 0;
	int is_exist = 0;
	int max_index = QWEBAPI_MAX_BSSID;
	int curr_index = 0;
	char *ifname;
	char tmp_path[32];

	index = strtol(path + strlen(path) - 3, NULL, 10);
	if(index == -1) {
#ifdef TOPAZ_DBDC
		max_index += QWEBAPI_MAX_24G_BSSID;
#endif
#ifdef PEARL_PLATFORM
		max_index = 3 * QWEBAPI_MAX_BSSID;
#endif
		for(; curr_index < max_index; curr_index++) {
#ifdef PEARL_PLATFORM
			if(curr_index >= QWEBAPI_MAX_BSSID && curr_index < 2 * QWEBAPI_MAX_BSSID) {
				continue;
			}
#endif
			sprintf(tmp_path, "%s%s%s%d%s", "Device.WiFi.", "SSID", ".{", curr_index, "}");
			is_exist = qweb_ssid_exist(tmp_path);
			sprintf(tmp_path, "%s%s%s%d%s", "Device.WiFi.", array_name, ".{", curr_index, "}");
			if(!is_exist) {
				path = tmp_path;
				break;
			}
		}
		if(is_exist) {
			return QWEBAPI_ERR_NOT_AVALIABLE;
		}
	}
	ifname = qweb_get_wifi_ifname(path, array_name);
#ifdef TOPAZ_DBDC
	int idx;
	idx = qweb_get_key_index(path, array_name);
	if (idx < QWEBAPI_MAX_BSSID + QWEBAPI_MAX_24G_BSSID
	    && idx >= QWEBAPI_MAX_BSSID) {
		ret = qweb_entry_is_exist_24G(path, ifname, array_name);
		if (!ret) {
			char qweb_cmd[QWEBAPI_CMD_MAX_LEN];
			snprintf(qweb_cmd, QWEBAPI_CMD_MAX_LEN, "enable.%s",
				 ifname);
			CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG,
				    QWEBAPI_OP_SET, qweb_cmd, "1",
				    string_value_buf,
				    QWEBAPI_TR181_STRING_MAX_LEN);

			need_to_apply_for_24G = 1;
			if(ret == 0 && index == -1) {
				ret = curr_index;
			}
			return ret;
		} else {
			qwebprintf(DBG_LEVEL_VERBOSE,
				   "%s(), %d, ret = %d, ret is wrong. Invalid BSS name",
				   __func__, __LINE__, ret);
			return QWEBAPI_ERR_NOT_AVALIABLE;
		}
	}
	if (qweb_get_wifi_mode() == qcsapi_station) {
		CALL_QCSAPI(wifi_update_bss_cfg, ret, TOPAZ_DBDC_5G_RADIO_NAME,
			qcsapi_access_point, ifname, "bss", ifname, NULL);
		if(ret == 0 && index == -1) {
			ret = curr_index;
		}
		return ret;
	}
#endif
	qcsapi_SSID SSID_str;
	CALL_QCSAPI(wifi_get_SSID, ret, ifname, SSID_str);
	if (ret) {
		CALL_QCSAPI(wifi_create_bss, ret, ifname, NULL);
		if (ret == -1031) {
			qwebprintf(DBG_LEVEL_VERBOSE,
				   "%s(), %d, ret = %d, ret is wrong. Invalid BSS name",
				   __func__, __LINE__, ret);
			return QWEBAPI_ERR_NOT_AVALIABLE;
		}
		if(ret == 0 && index == -1) {
			ret = curr_index;
		}
	}
	return ret;
}

static int qweb_del_ap_entry(char *path, char *array_name)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, array_name);
#ifdef TOPAZ_DBDC
	int idx;
	idx = qweb_get_key_index(path, array_name);
	if (idx < QWEBAPI_MAX_BSSID + QWEBAPI_MAX_24G_BSSID
	    && idx >= QWEBAPI_MAX_BSSID) {
		ret = qweb_entry_is_exist_24G(path, ifname, array_name);
		if (ret) {
			char qweb_cmd[QWEBAPI_CMD_MAX_LEN];
			snprintf(qweb_cmd, QWEBAPI_CMD_MAX_LEN, "enable.%s",
				 ifname);
			CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG,
				    QWEBAPI_OP_SET, qweb_cmd, "0",
				    string_value_buf,
				    QWEBAPI_TR181_STRING_MAX_LEN);

			need_to_apply_for_24G = 1;
		} else {
			qwebprintf(DBG_LEVEL_VERBOSE,
				   "%s(), %d, ret = %d, this VAP(%s) doesn't exist.\n",
				   __func__, __LINE__, ret, ifname);
			return QWEBAPI_ERR_INVALID_VALUE;
		}
		return ret;
	}
	if (qweb_get_wifi_mode() == qcsapi_station) {
		CALL_QCSAPI(wifi_update_bss_cfg, ret, TOPAZ_DBDC_5G_RADIO_NAME, qcsapi_access_point, ifname, "bss", "", NULL);
		return ret;
	}
#endif

	qcsapi_SSID SSID_str;
	CALL_QCSAPI(wifi_get_SSID, ret, ifname, SSID_str);
	if (!ret) {
		CALL_QCSAPI(wifi_remove_bss, ret, ifname);
		if (ret == -1030) {
			qwebprintf(DBG_LEVEL_VERBOSE,
				   "%s(), %d, ret = %d, Operation is not available on the primary interface",
				   __func__, __LINE__, ret);
			return QWEBAPI_ERR_NOT_AVALIABLE;
		} else if (ret == -1031) {
			qwebprintf(DBG_LEVEL_VERBOSE,
				   "%s(), %d, ret = %d, ret is wrong. Invalid BSS name",
				   __func__, __LINE__, ret);
			return QWEBAPI_ERR_NOT_AVALIABLE;
		}

		QWEBAPI_SET_RETURN(ret);
	}
	return ret;
}

int qweb_add_ssid_entry(char *path, char *value)
{
	return qweb_add_ap_entry(path, ITEM_NAME_SSID);
}

int qweb_del_ssid_entry(char *path)
{
	return qweb_del_ap_entry(path, ITEM_NAME_SSID);
}

/* Device.WiFi.SSID.{i}.Enable */
static int qweb_set_interface_enable(char *path, char *array_name,
				     unsigned int value)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, array_name);
	CALL_QCSAPI(interface_enable, ret, ifname, value);
	QWEBAPI_SET_RETURN(ret);
	return ret;
}

int qweb_set_SSID_enable(char *path, unsigned int value)
{
	return qweb_set_interface_enable(path, ITEM_NAME_SSID, value);
}

static int qweb_get_interface_enable(char *path, char *array_name, int *perr)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, array_name);
	CALL_QCSAPI(interface_get_status, ret, ifname, string_value_buf);
	QWEBAPI_GET_RETURN(ret, 0);

	if (!strcasecmp(string_value_buf, ITEM_VALUE_DISABLED))
		return 0;
	else if (!strcasecmp(string_value_buf, ITEM_VALUE_UP))
		return 1;
	else {
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, return value is wrong. buf = %s\n",
			   __func__, __LINE__, string_value_buf);
		return 0;
	}
}

unsigned int qweb_get_SSID_enable(char *path, int *perr)
{
	return qweb_get_interface_enable(path, ITEM_NAME_SSID, perr);
}

/* Device.WiFi.SSID.{i}.Status */
static char *qweb_get_interface_status(char *path, char *array_name, int *perr)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, array_name);
	CALL_QCSAPI(interface_get_status, ret, ifname, string_value_buf);
	QWEBAPI_GET_RETURN(ret, "");

	if (!strcasecmp(string_value_buf, ITEM_VALUE_DISABLED))
		return ITEM_VALUE_DOWN;
	else if (!strcasecmp(string_value_buf, ITEM_VALUE_UP))
		return ITEM_VALUE_UP;
	else
		return ITEM_VALUE_ERROR;
}

char *qweb_get_SSID_status(char *path, int *perr)
{
	return qweb_get_interface_status(path, ITEM_NAME_SSID, perr);
}

/* Device.WiFi.SSID.{i}.Alias */
char *qweb_get_SSID_alias(char *path, int *perr)
{
	return QWEBAPI_SSID_ALIAS;
}

/* Device.WiFi.SSID.{i}.Name */
QWEBAPI_WIFI_GET_STRING_FUNC(SSID_name, SSID, ITEM_NAME_SSID);

/* Device.WiFi.SSID.{i}.LastChange */
QWEBAPI_GET_UINT_FUNC_WITH_NOT_SUPPORT(SSID_last_change);

/* Device.WiFi.SSID.{i}.LowerLayers */
char *qweb_get_SSID_lower_layers(char *path, int *perr)
{
#if defined (PEARL_PLATFORM) || defined (TOPAZ_DBDC)
	int index;

	index = qweb_get_key_index(path, ITEM_NAME_SSID);
	if (index <= 7)
		return radio_if_mapping[0];
	else if (index <= 15)
		return radio_if_mapping[1];
	else if (index <= 23)
		return radio_if_mapping[2];
	else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, index is wroing, index = %s\n",
			   __func__, __LINE__, index);
		*perr = QWEBAPI_ERR_INVALID_VALUE;
		return "";
	}
#else
	return radio0;
#endif
}

/* Device.WiFi.SSID.{i}.BSSID */
char *qweb_get_bssid(char *path, int *perr)
{
	int ret;
	char *ifname;
	qcsapi_mac_addr mac_addr;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_SSID);
	CALL_QCSAPI(wifi_get_BSSID, ret, ifname, mac_addr);
	QWEBAPI_GET_RETURN(ret, "");

	qweb_dump_mac_addr(mac_addr, string_value_buf);
	return string_value_buf;
}

/* Device.WiFi.SSID.{i}.MACAddress */
char *qweb_get_mac_addr(char *path, int *perr)
{
	int ret;
	char *ifname;
	qcsapi_mac_addr mac_addr;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_SSID);
	CALL_QCSAPI(interface_get_mac_addr, ret, ifname, mac_addr);
	QWEBAPI_GET_RETURN(ret, "");

	qweb_dump_mac_addr(mac_addr, string_value_buf);
	return string_value_buf;
}

/* Device.WiFi.SSID.{i}.SSID */
int qweb_set_ssid(char *path, char *value)
{
	int ret = -1;
	char *ifname;
	char buf[32 + 1];

	if (qweb_get_inactive_mode() == 1)
		return qweb_set_inactive_cfg(path, value);
#ifdef TOPAZ_DBDC		/*QV860 */
	int index;

	index = qweb_get_key_index(path, ITEM_NAME_SSID);
	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_SSID);

	if (index <= 7) {
		if (qweb_get_wifi_mode() == qcsapi_station) {
			CALL_QCSAPI(wifi_update_bss_cfg, ret, TOPAZ_DBDC_5G_RADIO_NAME, qcsapi_access_point,
				ifname, "ssid", value, NULL);
			return ret;
		}

		CALL_QCSAPI(wifi_get_SSID, ret, ifname, buf);
		if (ret) {
			return QWEBAPI_ERR_NOT_AVALIABLE;
		}

		if (strcmp(value, buf)) {
			CALL_QCSAPI(wifi_set_SSID, ret, ifname, value);
			QWEBAPI_SET_RETURN(ret);
		}
	} else if (index <= 12) {
		char qweb_cmd[QWEBAPI_CMD_MAX_LEN];
		ret = qweb_check_if_available_24G(path, ifname);
		if (ret) {
			return ret;
		}
		/* Get original SSID */
		snprintf(qweb_cmd, QWEBAPI_CMD_MAX_LEN, "ssid.%s", ifname);
		CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG, QWEBAPI_OP_GET,
			    qweb_cmd, NULL, string_value_buf,
			    QWEBAPI_TR181_STRING_MAX_LEN);

		if (strcmp(value, string_value_buf)) {
			CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG,
				    QWEBAPI_OP_SET, qweb_cmd, value,
				    string_value_buf,
				    QWEBAPI_TR181_STRING_MAX_LEN);

			QWEBAPI_SET_RETURN(ret);
			need_to_apply_for_24G = 1;
		}
		return ret;
	}
#else				/*BBIC5 and other */
	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_SSID);
	CALL_QCSAPI(wifi_get_SSID, ret, ifname, buf);
	if (ret) {
		return QWEBAPI_ERR_NOT_AVALIABLE;
	}

	if (strcmp(value, buf)) {
		CALL_QCSAPI(wifi_set_SSID, ret, ifname, value);
		QWEBAPI_SET_RETURN(ret);
	}
#endif

	return ret;
}

char *qweb_get_ssid(char *path, int *perr)
{
	int ret = -1;
	char *ifname;

	if (qweb_get_inactive_mode() == 1) {
		ret = qweb_get_inactive_cfg(path, string_value_buf, sizeof(string_value_buf));
		if (ret == 0)
			return string_value_buf;
	}

#ifdef TOPAZ_DBDC
	int index;

	index = qweb_get_key_index(path, ITEM_NAME_SSID);
	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_SSID);

	if (index <= 7) {
		CALL_QCSAPI(wifi_get_SSID, ret, ifname, string_value_buf);
	} else if (index <= 12) {
		char qweb_cmd[QWEBAPI_CMD_MAX_LEN];
		ret = qweb_check_if_available_24G(path, ifname);
		if (ret) {
			*perr = ret;
			return "";
		}

		snprintf(qweb_cmd, QWEBAPI_CMD_MAX_LEN, "ssid.%s", ifname);
		CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG, QWEBAPI_OP_GET,
			    qweb_cmd, NULL, string_value_buf,
			    QWEBAPI_TR181_STRING_MAX_LEN);
	}

	QWEBAPI_GET_RETURN(ret, "");
	return string_value_buf;
#else
	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_SSID);
	CALL_QCSAPI(wifi_get_SSID, ret, ifname, string_value_buf);

	QWEBAPI_GET_RETURN(ret, "");
	return string_value_buf;
#endif
}

int qweb_check_ssid(char *path, JSON * obj)
{
	int len;
	int ret = 0;
	const char *ssid;

	ssid = JSON_GET_STRING(obj);

	//The SSID must be a string with between 1 and 32 characters.
	//Control characters (^C, ^M, etc.) are not permitted.
	len = strlen(ssid);
	if (len < QWEBAPI_SSID_MIN_LEN || len > QWEBAPI_SSID_MAX_LEN) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, the length of ssid is error.\n", __func__,
			   __LINE__);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	return ret;
}

/* Device.WiFi.SSID.{i}.X_QUANTENNA_COM_Priority */
QWEBAPI_WIFI_SET_UINT8_FUNC(priority, priority, ITEM_NAME_SSID);
QWEBAPI_WIFI_GET_UINT8_FUNC(priority, priority, ITEM_NAME_SSID);

int qweb_check_priority(char *path, JSON * obj)
{
	int pro;

	pro = JSON_GET_INT(obj);
	if (pro < 0 || pro > 3) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, priority is wrong. priority = %d\n",
			   __func__, __LINE__, pro);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	return 0;
}

/* Device.WiFi.SSID.{i}.X_QUANTENNA_COM_Primary_interface */
char *qweb_get_primary_interface(char *path, int *perr)
{
	int ret = -1;
#ifdef TOPAZ_DBDC
	int index;
	index = qweb_get_key_index(path, ITEM_NAME_SSID);
	if (index <= 7) {
		CALL_QCSAPI(get_primary_interface, ret, string_value_buf, 32);
	} else if (index <= 12) {
		return radio_if_mapping[1];
	}
#else
	CALL_QCSAPI(get_primary_interface, ret, string_value_buf, 32);
#endif
	QWEBAPI_GET_RETURN(ret, "");
	return string_value_buf;
}

/* Device.WiFi.AccessPoint */
int qweb_get_ap_max_num(char *path)
{
#ifdef PEARL_PLATFORM
	return 3 * QWEBAPI_MAX_BSSID;
#elif defined (TOPAZ_DBDC)
	return QWEBAPI_MAX_BSSID + QWEBAPI_MAX_24G_BSSID;
#else
	return QWEBAPI_MAX_BSSID;
#endif
}

int qweb_add_accesspoint_entry(char *path, char *value)
{
	return qweb_add_ap_entry(path, ITEM_NAME_ACCESSPOINT);
}

int qweb_del_accesspoint_entry(char *path)
{
	return qweb_del_ap_entry(path, ITEM_NAME_ACCESSPOINT);
}

int qweb_accesspoint_exist(char *path)
{
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
#ifdef TOPAZ_DBDC
	return qweb_entry_is_exist_24G(path, ifname, ITEM_NAME_ACCESSPOINT);
#else
	int ret;
	char ssid_str[QWEBAPI_SSID_MAX_LEN + 1];
	CALL_QCSAPI(wifi_get_SSID, ret, ifname, ssid_str);
	return (ret) ? 0 : 1;
#endif
}

/* Device.WiFi.AccessPoint.{i}.Enable */
int qweb_set_accesspoint_enable(char *path, unsigned int value)
{
	return qweb_set_interface_enable(path, ITEM_NAME_ACCESSPOINT, value);
}

unsigned int qweb_get_accesspoint_enable(char *path, int *perr)
{
	return qweb_get_interface_enable(path, ITEM_NAME_ACCESSPOINT, perr);
}

/* Device.WiFi.AccessPoint.{i}.Status */
char *qweb_get_accesspoint_status(char *path, int *perr)
{
	return qweb_get_interface_status(path, ITEM_NAME_ACCESSPOINT, perr);
}

/* Device.WiFi.AccessPoint.{i}.Alias */
char *qweb_get_accesspoint_alias(char *path, int *perr)
{
	return QWEBAPI_SSID_ALIAS;
}

/* Device.WiFi.AccessPoint.{i}.SSIDReference */
QWEBAPI_WIFI_GET_STRING_FUNC(ap_ssid_reference, SSID, ITEM_NAME_ACCESSPOINT);

/* Device.WiFi.AccessPoint.{i}.SSIDAdvertisementEnabled */
QWEBAPI_WIFI_SET_OPTION(broadcast_ssid, qcsapi_SSID_broadcast,
			ITEM_NAME_ACCESSPOINT);
QWEBAPI_WIFI_GET_OPTION(broadcast_ssid, qcsapi_SSID_broadcast,
			ITEM_NAME_ACCESSPOINT);

/* Device.WiFi.AccessPoint.{i}.RetryLimit */
QWEBAPI_SET_UINT_FUNC_WITH_NOT_SUPPORT(accesspoint_retry_limit);
QWEBAPI_GET_UINT_FUNC_WITH_NOT_SUPPORT(accesspoint_retry_limit);

/* Device.WiFi.AccessPoint.{i}.WMMCapability */
unsigned int qweb_get_wmm_capability(char *path, int *perr)
{
	/* always supported WiFi Multimedia (WMM) Access Categories (AC). */
	return 1;
}

/* Device.WiFi.AccessPoint.{i}.UAPSDCapability*/
unsigned int qweb_get_uapsd_capability(char *path, int *perr)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	/* always supported WiFi WMM Unscheduled Automatic Power Save Delivery */
	return 1;
}

/* Device.WiFi.AccessPoint.{i}.WMMEnable */
QWEBAPI_WIFI_SET_OPTION(wmm_enable, qcsapi_wmm, ITEM_NAME_ACCESSPOINT);
QWEBAPI_WIFI_GET_OPTION(wmm_enable, qcsapi_wmm, ITEM_NAME_ACCESSPOINT);

/* Device.WiFi.AccessPoint.{i}.UAPSDEnable */
QWEBAPI_WIFI_SET_OPTION(uapsd_enable, qcsapi_uapsd, ITEM_NAME_ACCESSPOINT);
QWEBAPI_WIFI_GET_OPTION(uapsd_enable, qcsapi_uapsd, ITEM_NAME_ACCESSPOINT);

/* Device.WiFi.AccessPoint.{i}.AssociatedDeviceNumberOfEntries */
QWEBAPI_WIFI_GET_UINT_FUNC(count_associations, count_associations,
			   ITEM_NAME_ACCESSPOINT);

/* Device.WiFi.AccessPoint.{i}.MaxAssociatedDevices */
QWEBAPI_WIFI_SET_UINT_FUNC(max_assoc_devices, assoc_limit,
			   ITEM_NAME_ACCESSPOINT);
QWEBAPI_WIFI_GET_UINT_FUNC(max_assoc_devices, assoc_limit,
			   ITEM_NAME_ACCESSPOINT);

/* Device.WiFi.AccessPoint.{i}.MaxAssociatedDevices */
QWEBAPI_WIFI_SET_INT_FUNC(isolation_enable, ap_isolate, ITEM_NAME_ACCESSPOINT);
QWEBAPI_WIFI_GET_INT_FUNC(isolation_enable, ap_isolate, ITEM_NAME_ACCESSPOINT);

/* Device.WiFi.AccessPoint.{i}.MACAddressControlEnabled */
int qweb_set_macaddr_filter_before(char *path)
{
	return qcsapi_init();
}

int qweb_get_macaddr_filter_before(char *path)
{
	return qcsapi_init();
}

int qweb_set_macaddr_filter(char *path, unsigned int value)
{
	int ret;
	char *ifname;

	if (value > qcsapi_deny_mac_address_unless_authorized)
		return QWEBAPI_ERR_INVALID_VALUE;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	CALL_QCSAPI(wifi_set_mac_address_filtering, ret, ifname, value);
	if (ret)
		ret = QWEBAPI_ERR_NOT_AVALIABLE;
	return ret;
}

unsigned int qweb_get_macaddr_filter(char *path, int *perr)
{
	int ret;
	char *ifname;
	qcsapi_mac_address_filtering mode;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);
	CALL_QCSAPI(wifi_get_mac_address_filtering, ret, ifname, &mode);
	QWEBAPI_GET_RETURN(ret, 0);

	if (mode < qcsapi_disable_mac_address_filtering
	    || mode > qcsapi_deny_mac_address_unless_authorized) {
		*perr = QWEBAPI_ERR_INVALID_VALUE;
		return 0;
	}

	return mode;
}

/* Device.WiFi.AccessPoint.{i}.AllowedMACAddress */
int qweb_set_allowed_macaddr_before(char *path)
{
	return qcsapi_init();
}

int qweb_get_allowed_macaddr_before(char *path)
{
	return qcsapi_init();
}

int qweb_set_allowed_macaddr(char *path, char *value)
{
	int ret;
	char *ifname;
	char *token;
	qcsapi_mac_addr mac_addr;
	struct ether_addr *mac;

	//check mac list inputed
	strncpy(string_value_buf, value, QWEBAPI_TR181_STRING_MAX_LEN - 1);
	token = strtok(string_value_buf, QWEBAPI_TR181_STR_DELIM);
	while (token != NULL) {
		mac = ether_aton(string_trim(token));
		if (mac == NULL)
			goto invalid_value;

		/* Get next token */
		token = strtok(NULL, QWEBAPI_TR181_STR_DELIM);
	}

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);

	//get all items from list
	CALL_QCSAPI(wifi_get_denied_mac_addresses, ret, ifname,
		    string_value_buf, QWEBAPI_TR181_STRING_MAX_LEN);
	if (ret)
		goto qcsapi_fail;

	//clear all items
	token = strtok(string_value_buf, QWEBAPI_TR181_STR_DELIM);
	while (token != NULL) {
		mac = ether_aton(string_trim(token));
		if (mac == NULL)
			goto invalid_value;

		memcpy(mac_addr, mac, MAC_ADDR_SIZE);
		CALL_QCSAPI(wifi_remove_mac_address, ret, ifname, mac_addr);
		if (ret)
			goto qcsapi_fail;

		/* Get next token */
		token = strtok(NULL, QWEBAPI_TR181_STR_DELIM);
	}

	// add items to list
	token = strtok(value, QWEBAPI_TR181_STR_DELIM);
	while (token != NULL) {
		mac = ether_aton(string_trim(token));
		if (mac == NULL)
			goto invalid_value;

		memcpy(mac_addr, mac, MAC_ADDR_SIZE);

		CALL_QCSAPI(wifi_deny_mac_address, ret, ifname, mac_addr);
		if (ret)
			goto qcsapi_fail;

		/* Get next token */
		token = strtok(NULL, QWEBAPI_TR181_STR_DELIM);
	}

	return ret;

 qcsapi_fail:
	return QWEBAPI_ERR_NOT_AVALIABLE;
 invalid_value:
	qwebprintf(DBG_LEVEL_VERBOSE,
		   "%s(), %d, parse mac addr failed.\n", __func__, __LINE__);
	return QWEBAPI_ERR_INVALID_VALUE;
}

char *qweb_get_allowed_macaddr(char *path, int *perr)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");
	CALL_QCSAPI(wifi_get_denied_mac_addresses, ret, ifname,
		    string_value_buf, QWEBAPI_TR181_STRING_MAX_LEN);
	QWEBAPI_GET_RETURN(ret, "");

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_vlan_config */
static int qweb_get_vlanid_value(char *vlanid, int all)
{
	int vid;

	if (all && !strcasecmp(vlanid, "all"))
		return QVLAN_VID_ALL;

	vid = atoi(vlanid);
	if (vid >= 0 && vid < QVLAN_VID_MAX)
		return vid;
	else
		return -1;
}

static int
qweb_vlan_parser(const char *value, int cmd)
{
	if (!strcasecmp(value, ITEM_NAME_DEFAULT))
		cmd |= e_qcsapi_vlan_pvid;
	else if (!strcasecmp(value, ITEM_NAME_TAG))
		cmd |= e_qcsapi_vlan_tag;
	else if (!strcasecmp(value, ITEM_NAME_UNTAG))
		cmd |= e_qcsapi_vlan_untag;
	else if (!strcasecmp(value, ITEM_NAME_DELETE))
		cmd |= e_qcsapi_vlan_del;
	else
		cmd = 0;

	return cmd;
}

int qweb_set_vlan_config(char *path, char *value)
{
	int ret;
	int param_count;
	char *ifname;
	char param_list[10][32];
	char *token;
	int index = 0;
	int vlanid = 0;
	qcsapi_vlan_cmd cmd;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);

	token = strtok(value, QWEBAPI_SPACE);
	while (token && index < 10) {
		memcpy(param_list[index], token, strlen(token) + 1);

		//get next item
		token = strtok(NULL, QWEBAPI_SPACE);
		index++;
	}
	param_count = index;
	if (param_count <= 0) {
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	if (!strcasecmp(param_list[0], ITEM_NAME_ENABLE))
		cmd = e_qcsapi_vlan_enable;
	else if (!strcasecmp(param_list[0], ITEM_NAME_DISABLE))
		cmd = e_qcsapi_vlan_disable;
	else if (!strcasecmp(param_list[0], ITEM_NAME_RESET))
		cmd = e_qcsapi_vlan_reset;
	else if (!strcasecmp(param_list[0], ITEM_NAME_BIND)) {
		vlanid = qweb_get_vlanid_value(param_list[1], 0);
		if (vlanid < 0 || param_count > 2) {
			cmd = 0;
		} else {
			cmd =
			    e_qcsapi_vlan_access | e_qcsapi_vlan_untag |
			    e_qcsapi_vlan_pvid;
		}
	} else if (!strcasecmp(param_list[0], ITEM_NAME_UNBIND)) {
		vlanid = qweb_get_vlanid_value(param_list[1], 0);
		if (vlanid < 0 || param_count > 2)
			cmd = 0;
		else
			cmd = e_qcsapi_vlan_access | e_qcsapi_vlan_del |
			    e_qcsapi_vlan_untag | e_qcsapi_vlan_pvid;
	} else if (!strcasecmp(param_list[0], ITEM_NAME_DYNAMIC)) {
		if (param_count > 2) {
			cmd = 0;
		} else {
			if (atoi(param_list[1]))
				cmd = e_qcsapi_vlan_dynamic;
			else
				cmd = e_qcsapi_vlan_undynamic;
		}
	} else if (!strcasecmp(param_list[0], ITEM_NAME_ACCESS)) {
		vlanid = qweb_get_vlanid_value(param_list[1], 0);
		if (param_count != 2 || vlanid < 0) {
			cmd = 0;
		} else {
			cmd =
			    e_qcsapi_vlan_access | e_qcsapi_vlan_untag |
			    e_qcsapi_vlan_pvid;
		}
	} else if (!strcasecmp(param_list[0], ITEM_NAME_TRUNK)
			|| !strcasecmp(param_list[0], ITEM_NAME_HYBRID)) {
		vlanid = qweb_get_vlanid_value(param_list[1], 1);
		if (param_count > 5 || param_count < 2 || vlanid < 0) {
			cmd = 0;
		} else {
			cmd = e_qcsapi_vlan_trunk;
			for (index = 2; index < param_count; index++)
				cmd = qweb_vlan_parser(param_list[index], cmd);

			if ((vlanid == QVLAN_VID_ALL)
					&& (cmd & e_qcsapi_vlan_pvid))
				cmd = 0;
		}
	} else {
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	CALL_QCSAPI(wifi_vlan_config, ret, ifname, cmd, vlanid);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

static void qweb_print_vlan_config(string_2048 str)
{
	uint16_t vid;
	uint16_t i, j;
	uint32_t tagrx;
	uint16_t vmode;
	char tmp_string[64];
	struct qtn_vlan_config *vcfg = (struct qtn_vlan_config *)str;

	if (vcfg->vlan_cfg) {
		vmode =
		    ((vcfg->vlan_cfg & QVLAN_MASK_MODE) >> QVLAN_SHIFT_MODE);
		vid = (vcfg->vlan_cfg & QVLAN_MASK_VID);
	} else {
		snprintf(string_value_buf, QWEBAPI_TR181_STRING_MAX_LEN,
			 "tagrx VLAN:");
		for (i = 0, j = 0; i < QVLAN_VID_MAX; i++) {
			tagrx = qtn_vlan_get_tagrx(vcfg->u.tagrx_config, i);
			if (tagrx) {
				if ((j++ & 0xF) == 0)
					strncat(string_value_buf, "\n\t",
						sizeof(string_value_buf) -
						strlen(string_value_buf) - 1);
				snprintf(tmp_string, 64, "%u-%u, ", i, tagrx);
				strncat(string_value_buf, tmp_string,
					sizeof(string_value_buf) -
					strlen(string_value_buf) - 1);
			}
		}
		strncat(string_value_buf, "\n", sizeof(string_value_buf)
			- strlen(string_value_buf) - 1);
		return;
	}

	switch (vmode) {
	case QVLAN_MODE_TRUNK:
		snprintf(string_value_buf, QWEBAPI_TR181_STRING_MAX_LEN,
			 "%s, default VLAN %u\n", QVLAN_MODE_STR_TRUNK,
			 vid);
		strncat(string_value_buf, "Member of VLANs: ",
			sizeof(string_value_buf)
			- strlen(string_value_buf) - 1);
		for (i = 0, j = 0; i < QVLAN_VID_MAX; i++) {
			if (is_set_a(vcfg->u.dev_config.member_bitmap, i)) {
				if ((j++ & 0xF) == 0)
					strncat(string_value_buf, "\n\t",
						sizeof(string_value_buf) -
						strlen(string_value_buf) - 1);
				snprintf(tmp_string, 64, "%u,", i);
				strncat(string_value_buf, tmp_string,
					sizeof(string_value_buf) -
					strlen(string_value_buf) - 1);
			}
		}
		strncat(string_value_buf, "\n",
			sizeof(string_value_buf) -
			strlen(string_value_buf) - 1);

		strncat(string_value_buf, "\nUntagged VLAN(s): ",
			sizeof(string_value_buf)
			- strlen(string_value_buf) - 1);
		for (i = 0, j = 0; i < QVLAN_VID_MAX; i++) {
			if (is_set_a(vcfg->u.dev_config.member_bitmap, i) &&
			    is_clr_a(vcfg->u.dev_config.tag_bitmap, i)) {
				if ((j++ & 0xF) == 0)
					strncat(string_value_buf, "\n\t",
						sizeof(string_value_buf) -
						strlen(string_value_buf) - 1);
				snprintf(tmp_string, 64, "%u,", i);
				strncat(string_value_buf, tmp_string,
					sizeof(string_value_buf) -
					strlen(string_value_buf) - 1);
			}
		}
		strncat(string_value_buf, "\n", sizeof(string_value_buf)
			- strlen(string_value_buf) - 1);
		break;

	case QVLAN_MODE_ACCESS:
		snprintf(string_value_buf, QWEBAPI_TR181_STRING_MAX_LEN,
			 "%s, VLAN %u\n", QVLAN_MODE_STR_ACCESS, vid);
		break;

	case QVLAN_MODE_DYNAMIC:
		snprintf(string_value_buf, QWEBAPI_TR181_STRING_MAX_LEN, "%s\n",
			 QVLAN_MODE_STR_DYNAMIC);
		break;

	default:
		snprintf(string_value_buf, QWEBAPI_TR181_STRING_MAX_LEN,
			 "VLAN disabled\n");
		break;
	}
}

char *qweb_get_vlan_config(char *path, int *perr)
{
	int ret;
	char *ifname;
	struct qtn_vlan_config *vcfg;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);

	vcfg =
	    (struct qtn_vlan_config *)calloc(1,
					     sizeof(struct
						    qcsapi_data_2Kbytes));
	if (vcfg == NULL) {
		qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, calloc failed.\n",
			   __func__, __LINE__);
		return "";
	}

	CALL_QCSAPI(wifi_show_vlan_config, ret, ifname,
		    (struct qcsapi_data_2Kbytes *)vcfg, NULL);
	if (ret < 0)
		snprintf(string_value_buf, QWEBAPI_TR181_STRING_MAX_LEN,
			 "VLAN disabled\n");
	else
		qweb_print_vlan_config((char *)vcfg);

	if (strstr(string_value_buf, QWEBAPI_ENTER)) {
		string_value_buf[strlen(string_value_buf) - 1] = '\0';
	}

	safe_free(vcfg);

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_vlan_tagrx_config */
char *qweb_get_vlan_tagrx_config(char *path, int *perr)
{
	int ret;
	char *ifname;
	struct qtn_vlan_config *vcfg;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);

	vcfg =
	    (struct qtn_vlan_config *)calloc(1,
					     sizeof(struct
						    qcsapi_data_2Kbytes));
	if (vcfg == NULL) {
		qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, calloc failed.\n",
			   __func__, __LINE__);
		return "";
	}

	CALL_QCSAPI(wifi_show_vlan_config, ret, ifname,
		    (struct qcsapi_data_2Kbytes *)vcfg, ITEM_NAME_TAGRX);
	if (ret < 0)
		snprintf(string_value_buf, QWEBAPI_TR181_STRING_MAX_LEN,
			 "VLAN disabled\n");
	else
		qweb_print_vlan_config((char *)vcfg);

	if (strstr(string_value_buf, QWEBAPI_ENTER)) {
		string_value_buf[strlen(string_value_buf) - 1] = '\0';
	}

	safe_free(vcfg);

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_interworking */
int qweb_set_interworking(char *path, char *value)
{
	int ret;
	char *ifname;
	char *status;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	if (strcasecmp(value, ITEM_NAME_DISABLE) == 0) {
		status = "0";
	} else if (strcasecmp(value, ITEM_NAME_ENABLE) == 0) {
		status = "1";
	} else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is wrong. value = %s\n",
			   __func__, __LINE__, value);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	CALL_QCSAPI(wifi_set_interworking, ret, ifname, status);

	QWEBAPI_SET_RETURN(ret);
	return ret;
}

char *qweb_get_interworking(char *path, int *perr)
{
	int ret;
	char *ifname;
	char status[4];

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");

	CALL_QCSAPI(wifi_get_interworking, ret, ifname, status);
	if (ret == -1001) {
		/* Parameter not found */
		return ITEM_NAME_DISABLE;
	}

	QWEBAPI_GET_RETURN(ret, "");

	if (strcasecmp(status, "0") == 0) {
		return ITEM_NAME_DISABLE;
	} else if (strcasecmp(status, "1") == 0) {
		return ITEM_NAME_ENABLE;
	} else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, return value is wrong. return value = %s\n",
			   __func__, __LINE__, status);
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		return "";
	}
}

/* Device.WiFi.AccessPoint.{i} for 802.11u */
static int qweb_set_80211u_parameter(char *path, char *param, char *value)
{
	int ret;
	char *ifname;
	char *value1;
	char *value2;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	if (value == NULL)
		goto fail;

	value1 = strtok(value, QWEBAPI_SPACE);
	value2 = strtok(NULL, QWEBAPI_SPACE);

	if (value1 == NULL)
		goto fail;

	CALL_QCSAPI(wifi_set_80211u_params, ret, ifname, param, value1, value2);
	QWEBAPI_SET_RETURN(ret);

	return ret;
 fail:
	qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, value is wrong. value = %s\n",
		   __func__, __LINE__);
	return QWEBAPI_ERR_INVALID_VALUE;
}

static int qweb_remove_80211u_parameter(char *path, char *param)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	CALL_QCSAPI(remove_11u_param, ret, ifname, param);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

static char *qweb_get_80211u_parameter(char *path, char *param, int *perr)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");

	CALL_QCSAPI(wifi_get_80211u_params, ret, ifname, param,
		    string_value_buf);
	if (ret == -1001) {
		/* Parameter not found */
		return "";
	}
	QWEBAPI_GET_RETURN(ret, "");

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_internet_access */
int qweb_set_internet_access(char *path, char *value)
{
	char *status;

	if (strcasecmp(value, ITEM_NAME_DISABLE) == 0) {
		status = "0";
	} else if (strcasecmp(value, ITEM_NAME_ENABLE) == 0) {
		status = "1";
	} else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is wrong. value = %s\n",
			   __func__, __LINE__, value);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	return qweb_set_80211u_parameter(path, ITEM_NAME_INTERNET, status);
}

char *qweb_get_internet_access(char *path, int *perr)
{
	char *status;
	status = qweb_get_80211u_parameter(path, ITEM_NAME_INTERNET, perr);

	if (strcasecmp(status, "0") == 0 || strlen(status) == 0) {
		return ITEM_NAME_DISABLE;
	} else if (strcasecmp(status, "1") == 0) {
		return ITEM_NAME_ENABLE;
	} else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, return value is wrong. return value = %s\n",
			   __func__, __LINE__, status);
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		return "";
	}
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_access_network_type */
int qweb_set_access_network_type(char *path, char *value)
{
	return qweb_set_80211u_parameter(path,
					 ITEM_NAME_ACCESS_NETWORK_TYPE, value);
}

char *qweb_get_access_network_type(char *path, int *perr)
{
	return qweb_get_80211u_parameter(path,
					 ITEM_NAME_ACCESS_NETWORK_TYPE, perr);
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_network_auth_type */
int qweb_set_network_auth_type(char *path, char *value)
{
	return qweb_set_80211u_parameter(path,
					 ITEM_NAME_NETWORK_AUTH_TYPE, value);
}

char *qweb_get_network_auth_type(char *path, int *perr)
{
	return qweb_get_80211u_parameter(path,
					 ITEM_NAME_NETWORK_AUTH_TYPE, perr);
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211u_hessid */
int qweb_check_hessid(char *path, JSON * obj)
{
	const char *mac_addr;
	struct ether_addr *mac;

	mac_addr = JSON_GET_STRING(obj);
	mac = ether_aton(mac_addr);
	if (mac == NULL)
		return QWEBAPI_ERR_INVALID_VALUE;
	else
		return QWEBAPI_OK;
}

int qweb_set_hessid(char *path, char *value)
{
	if (strlen(value) == 0)
		return qweb_remove_80211u_parameter(path, ITEM_NAME_HESSID);
	else
		return qweb_set_80211u_parameter(path, ITEM_NAME_HESSID, value);
}

char *qweb_get_hessid(char *path, int *perr)
{
	return qweb_get_80211u_parameter(path, ITEM_NAME_HESSID, perr);
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211u_domain_name */
int qweb_set_domain_name(char *path, char *value)
{
	if (strlen(value) == 0)
		return qweb_remove_80211u_parameter(path,
						    ITEM_NAME_DOMAIN_NAME);
	else
		return qweb_set_80211u_parameter(path,
						 ITEM_NAME_DOMAIN_NAME, value);
}

char *qweb_get_domain_name(char *path, int *perr)
{
	return qweb_get_80211u_parameter(path, ITEM_NAME_DOMAIN_NAME, perr);
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211u_ipaddr_type_availability */
int qweb_set_ipaddr_type_availability(char *path, char *value)
{
	return qweb_set_80211u_parameter(path,
					 ITEM_NAME_IPADDR_TYPE_AVAILABILITY,
					 value);
}

char *qweb_get_ipaddr_type_availability(char *path, int *perr)
{
	int ip_type;
	int ipv4_type;
	int ipv6_type;
	char *value;

	value = qweb_get_80211u_parameter(path,
					  ITEM_NAME_IPADDR_TYPE_AVAILABILITY,
					  perr);

	ip_type = atoi(value);
	sscanf(value, "%x", &ip_type);

	ipv4_type = (ip_type >> 2) & 0x03F;
	ipv6_type = ip_type & 0x03;

	snprintf(string_value_buf, QWEBAPI_TR181_STRING_MAX_LEN, "%d %d",
		 ipv4_type, ipv6_type);

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211u_anqp_3gpp_cell_net */
int qweb_set_anqp_3gpp_cell_net(char *path, char *value)
{
	if (strlen(value) == 0)
		return qweb_remove_80211u_parameter(path,
						    ITEM_NAME_ANQP_3GPP_CELL_NET);
	else
		return qweb_set_80211u_parameter(path,
						 ITEM_NAME_ANQP_3GPP_CELL_NET,
						 value);
}

char *qweb_get_anqp_3gpp_cell_net(char *path, int *perr)
{
	return qweb_get_80211u_parameter(path,
					 ITEM_NAME_ANQP_3GPP_CELL_NET, perr);
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211u_venue_group */
int qweb_set_venue_group(char *path, char *value)
{
	return qweb_set_80211u_parameter(path, ITEM_NAME_VENUE_GROUP, value);
}

char *qweb_get_venue_group(char *path, int *perr)
{
	return qweb_get_80211u_parameter(path, ITEM_NAME_VENUE_GROUP, perr);
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211u_venue_type */
int qweb_set_venue_type(char *path, char *value)
{
	return qweb_set_80211u_parameter(path, ITEM_NAME_VENUE_TYPE, value);
}

char *qweb_get_venue_type(char *path, int *perr)
{
	return qweb_get_80211u_parameter(path, ITEM_NAME_VENUE_TYPE, perr);
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211u_venue_name */
static int qweb_add_venue_name(char *path, char *lang_code, char *venue_name)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	CALL_QCSAPI(security_add_venue_name, ret, ifname, lang_code,
		    venue_name);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

static int qweb_del_venue_name(char *path, char *lang_code, char *venue_name)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	CALL_QCSAPI(security_del_venue_name, ret, ifname, lang_code,
		    venue_name);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

int qweb_set_venue_name(char *path, char *value)
{
	int ret;
	char *ifname;
	char *op_code;
	char *lang_code;
	char *venue_name;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	op_code = strtok(value, QWEBAPI_SPACE);
	lang_code = strtok(NULL, QWEBAPI_SPACE);
	venue_name = strtok(NULL, QWEBAPI_SPACE);
	if (op_code == NULL || lang_code == NULL || venue_name == NULL) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is wrong. value = %s\n", __func__,
			   __LINE__, value);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	if (strcasecmp(op_code, QWEBAPI_OP_CODE_ADD) == 0) {
		return qweb_add_venue_name(path, lang_code, venue_name);
	} else if (strcasecmp(op_code, QWEBAPI_OP_CODE_DEL) == 0) {
		return qweb_del_venue_name(path, lang_code, venue_name);
	} else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is wrong. value = %s\n", __func__,
			   __LINE__, value);
		return QWEBAPI_ERR_INVALID_VALUE;
	}
}

char *qweb_get_venue_name(char *path, int *perr)
{
	int ret;
	int len;
	char *ifname;
	char *token;
	char *buf;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");

	buf = calloc(4096, sizeof(char));
	if (buf == NULL) {
		qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, calloc failed!!!\n",
			   __func__, __LINE__);
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		return "";
	}

	CALL_QCSAPI(security_get_venue_name, ret, ifname, buf);
	if (ret) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, get venue name failed.\n",
			   __func__, __LINE__);
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		safe_free(buf);
		return "";
	}

	string_value_buf[0] = '\0';
	token = strtok(buf, QWEBAPI_ENTER);
	while (token != NULL) {
		char *start, *end;

		start = strstr(token, "P\"");
		end = strstr(start + 2, "\"");

		strncat(string_value_buf, start + 2, end - start - 2);
		strcat(string_value_buf, QWEBAPI_SPACE);

		//get next
		token = strtok(NULL, QWEBAPI_ENTER);
	}

	len = strlen(string_value_buf);
	if (len > 0)
		string_value_buf[len - 1] = '\0';

	safe_free(buf);

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211u_gas_comeback_delay */
int qweb_set_gas_comeback_delay(char *path, char *value)
{
	if (strlen(value) == 0)
		return qweb_remove_80211u_parameter(path,
						    ITEM_NAME_GAS_COMEBACK_DELAY);
	else
		return qweb_set_80211u_parameter(path,
						 ITEM_NAME_GAS_COMEBACK_DELAY,
						 value);
}

char *qweb_get_gas_comeback_delay(char *path, int *perr)
{
	return qweb_get_80211u_parameter(path,
					 ITEM_NAME_GAS_COMEBACK_DELAY, perr);
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_nai_realm */
static int qweb_add_nai_realm(char *path, char *encoding, char *nai_realm,
			      char *eap_method)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	CALL_QCSAPI(security_add_nai_realm, ret, ifname, atoi(encoding),
		    nai_realm, eap_method);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

static int qweb_del_nai_realm(char *path, char *nai_realm)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	CALL_QCSAPI(security_del_nai_realm, ret, ifname, nai_realm);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

int qweb_set_nai_realm(char *path, char *value)
{
	int ret;
	char *ifname;
	char *op_code;
	char *encoding;
	char *nai_realm;
	char *eap_method;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	op_code = strtok(value, QWEBAPI_SPACE);

	if (strcasecmp(op_code, QWEBAPI_OP_CODE_ADD) == 0) {
		encoding = strtok(NULL, QWEBAPI_SPACE);
		nai_realm = strtok(NULL, QWEBAPI_SPACE);
		eap_method = strtok(NULL, QWEBAPI_SPACE);

		if (!(encoding && nai_realm && eap_method))
			goto fail;
		return qweb_add_nai_realm(path, encoding, nai_realm,
					  eap_method);
	} else if (strcasecmp(op_code, QWEBAPI_OP_CODE_DEL) == 0) {
		nai_realm = strtok(NULL, QWEBAPI_SPACE);
		if (nai_realm == NULL)
			goto fail;
		return qweb_del_nai_realm(path, nai_realm);
	} else
		goto fail;

 fail:
	qwebprintf(DBG_LEVEL_VERBOSE,
		   "%s(), %d, value is wrong. value = %s\n",
		   __func__, __LINE__, value);
	return QWEBAPI_ERR_INVALID_VALUE;
}

char *qweb_get_nai_realm(char *path, int *perr)
{
	int ret;
	char *buf;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");

	buf = calloc(4096, sizeof(char));
	if (buf == NULL) {
		qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, calloc failed!!!\n",
			   __func__, __LINE__);
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		return "";
	}

	CALL_QCSAPI(security_get_nai_realms, ret, ifname, buf);
	if (ret) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, get nai_realms failed\n",
			   __func__, __LINE__);
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		safe_free(buf);

		return "";
	}

	if (strstr(buf, QWEBAPI_ENTER)) {
		buf[strlen(buf) - 1] = '\0';
	}

	memcpy(string_value_buf, buf, 1024);
	safe_free(buf);

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_roaming_consortium */
static int qweb_add_roaming_consortium(char *path, char *value)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	CALL_QCSAPI(security_add_roaming_consortium, ret, ifname, value);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

static int qweb_del_roaming_consortium(char *path, char *value)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	CALL_QCSAPI(security_del_roaming_consortium, ret, ifname, value);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

int qweb_set_roaming_consortium(char *path, char *value)
{
	int ret;
	char *ifname;
	char *op_code;
	char *consortium;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	op_code = strtok(value, QWEBAPI_SPACE);
	consortium = strtok(NULL, QWEBAPI_SPACE);
	if (op_code == NULL || consortium == NULL)
		goto fail;

	if (strcasecmp(op_code, QWEBAPI_OP_CODE_ADD) == 0) {
		return qweb_add_roaming_consortium(path, consortium);
	} else if (strcasecmp(op_code, QWEBAPI_OP_CODE_DEL) == 0) {
		return qweb_del_roaming_consortium(path, consortium);
	} else
		goto fail;

 fail:
	qwebprintf(DBG_LEVEL_VERBOSE,
		   "%s(), %d, value is wrong. value = %s\n",
		   __func__, __LINE__, value);
	return QWEBAPI_ERR_INVALID_VALUE;
}

char *qweb_get_roaming_consortium(char *path, int *perr)
{
	int ret;
	int len;
	char *buf;
	char *ifname;
	char *token;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");

	buf = calloc(1024, sizeof(char));
	if (buf == NULL) {
		qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, calloc failed!!!\n",
			   __func__, __LINE__);
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		return "";
	}

	CALL_QCSAPI(security_get_roaming_consortium, ret, ifname, buf);
	if (ret) {
		qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, get roaming failed\n",
			   __func__, __LINE__);
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		safe_free(buf);

		return "";
	}

	string_value_buf[0] = '\0';
	token = strtok(buf, QWEBAPI_ENTER);
	while (token != NULL) {
		if (strlen(string_value_buf) + strlen(token)
		    + strlen(QWEBAPI_SPACE) < sizeof(string_value_buf) - 1) {
			strcat(string_value_buf, token);
			strcat(string_value_buf, QWEBAPI_SPACE);
		}
		//get next
		token = strtok(NULL, QWEBAPI_ENTER);
	}

	len = strlen(string_value_buf);
	if (len > 0)
		string_value_buf[len - 1] = '\0';

	safe_free(buf);

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_hs20_status */
int qweb_set_hs20_status(char *path, char *value)
{
	int ret;
	char *ifname;
	char status[32];

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	if (!strcasecmp(value, ITEM_NAME_ENABLE)) {
		strncpy(status, "1", 32);
	} else if (!strcasecmp(value, ITEM_NAME_DISABLE)) {
		strncpy(status, "0", 32);
	} else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is wrong. value = %s\n",
			   __func__, __LINE__, value);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	CALL_QCSAPI(wifi_set_hs20_status, ret, ifname, status);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

char *qweb_get_hs20_status(char *path, int *perr)
{
	int ret;
	char *ifname;
	char status[32];

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");
	CALL_QCSAPI(wifi_get_hs20_status, ret, ifname, status);
	QWEBAPI_GET_RETURN(ret, "");

	if (!strcasecmp(status, "1")) {
		return ITEM_NAME_ENABLE;
	} else if (!strcasecmp(status, "0")) {
		return ITEM_NAME_DISABLE;
	} else
		return "";
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_oper_friendly_name */
static int qweb_add_oper_friendly_name(char *path, char *lang_code,
				       char *oper_friendly_name)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	CALL_QCSAPI(security_add_oper_friendly_name, ret, ifname, lang_code,
		    oper_friendly_name);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

static int qweb_del_oper_friendly_name(char *path, char *lang_code,
				       char *oper_friendly_name)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	CALL_QCSAPI(security_del_oper_friendly_name, ret, ifname, lang_code,
		    oper_friendly_name);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

int qweb_set_oper_friendly_name(char *path, char *value)
{
	int ret;
	char *ifname;
	char *op_code;
	char *lang_code;
	char *oper_friendly_name;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	op_code = strtok(value, QWEBAPI_SPACE);
	lang_code = strtok(NULL, QWEBAPI_SPACE);
	oper_friendly_name = strtok(NULL, QWEBAPI_SPACE);
	if (op_code == NULL || lang_code == NULL || oper_friendly_name == NULL) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is wrong. value = %s\n", __func__,
			   __LINE__, value);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	if (strcasecmp(op_code, QWEBAPI_OP_CODE_ADD) == 0) {
		return qweb_add_oper_friendly_name(path, lang_code,
						   oper_friendly_name);
	} else if (strcasecmp(op_code, QWEBAPI_OP_CODE_DEL) == 0) {
		return qweb_del_oper_friendly_name(path, lang_code,
						   oper_friendly_name);
	} else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is wrong. value = %s\n",
			   __func__, __LINE__, value);
		return QWEBAPI_ERR_INVALID_VALUE;
	}
}

char *qweb_get_oper_friendly_name(char *path, int *perr)
{
	int ret;
	int len;
	char *ifname;
	char *token;
	char *buf;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");

	buf = calloc(4096, sizeof(char));
	if (buf == NULL) {
		qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, calloc failed!!!\n",
			   __func__, __LINE__);
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		return "";
	}

	CALL_QCSAPI(security_get_oper_friendly_name, ret, ifname, buf);
	if (ret) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, get friendly name failed\n",
			   __func__, __LINE__);
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		safe_free(buf);

		return "";
	}

	string_value_buf[0] = '\0';
	token = strtok(buf, QWEBAPI_ENTER);
	while (token != NULL) {
		if (strlen(string_value_buf) + strlen(token)
		    + strlen(QWEBAPI_SPACE) < sizeof(string_value_buf) - 1) {
			strncat(string_value_buf, token, strlen(token));
			strcat(string_value_buf, QWEBAPI_SPACE);
		}
		//get next
		token = strtok(NULL, QWEBAPI_ENTER);
	}

	len = strlen(string_value_buf);
	if (len > 0)
		string_value_buf[len - 1] = '\0';

	safe_free(buf);

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_hs20_wan_metrics */
int qweb_set_hs20_wan_metrics(char *path, char *value)
{
	int ret;
	int wan;
	char *ifname;
	char wan_info[64];
	char *link_status;
	char *downlink_speed;
	char *uplink_speed;
	char *downlink_load;
	char *uplink_load;
	char *load_measurement;
	char *symm_link_status;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	if (strlen(value) == 0) {
		/* remove this param */
		CALL_QCSAPI(remove_hs20_param, ret, ifname,
			    ITEM_NAME_HS20_WAN_METRICS);
	}

	link_status = strtok(value, QWEBAPI_COLON);
	symm_link_status = strtok(NULL, QWEBAPI_COLON);
	downlink_speed = strtok(NULL, QWEBAPI_COLON);
	uplink_speed = strtok(NULL, QWEBAPI_COLON);
	downlink_load = strtok(NULL, QWEBAPI_COLON);
	uplink_load = strtok(NULL, QWEBAPI_COLON);
	load_measurement = strtok(NULL, QWEBAPI_COLON);

	if (link_status && symm_link_status)
		wan = atoi(link_status) | atoi(symm_link_status) << 2;
	else
		wan = 0;

	snprintf(wan_info, 64, "0%d", wan);
	CALL_QCSAPI(wifi_set_hs20_params, ret, ifname,
		    ITEM_NAME_HS20_WAN_METRICS, wan_info,
		    CHECK_VALUE(downlink_speed), CHECK_VALUE(uplink_speed),
		    CHECK_VALUE(downlink_load), CHECK_VALUE(uplink_load),
		    CHECK_VALUE(load_measurement));
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

char *qweb_get_hs20_wan_metrics(char *path, int *perr)
{
	int ret;
	int len;
	char *ifname;
	char buf[32];
	char *wan_info;
	char *downlink_speed;
	char *uplink_speed;
	char *downlink_load;
	char *uplink_load;
	char *load_measurement;
	char tmp_string[32];

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");
	CALL_QCSAPI(wifi_get_hs20_params, ret, ifname,
		    ITEM_NAME_HS20_WAN_METRICS, buf);

	if (ret == -1001) {	/* Parameter not found */
		/* always return all zero. */
		return "0:0:0:0:0:0:0";
	}

	wan_info = strtok(buf, QWEBAPI_COLON);
	downlink_speed = strtok(NULL, QWEBAPI_COLON);
	uplink_speed = strtok(NULL, QWEBAPI_COLON);
	downlink_load = strtok(NULL, QWEBAPI_COLON);
	uplink_load = strtok(NULL, QWEBAPI_COLON);
	load_measurement = strtok(NULL, QWEBAPI_COLON);

	string_value_buf[0] = '\0';
	if (wan_info) {
		snprintf(tmp_string, 32, "%d:%d:",
			 atoi(wan_info) & 0x03, atoi(wan_info) >> 2);
		strncat(string_value_buf, tmp_string, strlen(tmp_string));
	}

	if (downlink_speed && (strlen(string_value_buf)
			       + strlen(downlink_speed)
			       + strlen(QWEBAPI_COLON))
	    < sizeof(string_value_buf) - 1) {
		strncat(string_value_buf, downlink_speed,
			strlen(downlink_speed));
		strncat(string_value_buf, QWEBAPI_COLON, strlen(QWEBAPI_COLON));
	} else
		strncat(string_value_buf, "0:", 2);

	if (uplink_speed && (strlen(string_value_buf)
			     + strlen(uplink_speed)
			     + strlen(QWEBAPI_COLON))
	    < sizeof(string_value_buf) - 1) {
		strncat(string_value_buf, uplink_speed, strlen(uplink_speed));
		strncat(string_value_buf, QWEBAPI_COLON, strlen(QWEBAPI_COLON));
	} else
		strncat(string_value_buf, "0:", 2);

	if (downlink_load && (strlen(string_value_buf)
			      + strlen(downlink_load)
			      + strlen(QWEBAPI_COLON))
	    < sizeof(string_value_buf) - 1) {
		strncat(string_value_buf, downlink_load, strlen(downlink_load));
		strncat(string_value_buf, QWEBAPI_COLON, strlen(QWEBAPI_COLON));
	} else
		strncat(string_value_buf, "0:", 2);

	if (uplink_load && (strlen(string_value_buf)
			    + strlen(uplink_load)
			    + strlen(QWEBAPI_COLON))
	    < sizeof(string_value_buf) - 1) {
		strncat(string_value_buf, uplink_load, strlen(uplink_load));
		strncat(string_value_buf, QWEBAPI_COLON, strlen(QWEBAPI_COLON));
	} else
		strncat(string_value_buf, "0:", 2);

	if (load_measurement && (strlen(string_value_buf)
				 + strlen(load_measurement)
				 + strlen(QWEBAPI_COLON))
	    < sizeof(string_value_buf) - 1) {
		strncat(string_value_buf, load_measurement,
			strlen(load_measurement));
		strncat(string_value_buf, QWEBAPI_COLON, strlen(QWEBAPI_COLON));
	} else
		strncat(string_value_buf, "0:", 2);

	len = strlen(string_value_buf);
	if (string_value_buf[len - 1] == ':') {
		string_value_buf[len - 1] = '\0';
	}

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_hs20_disable_dgaf */
int qweb_set_hs20_disable_dgaf(char *path, char *value)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	if (strlen(value) == 0) {
		/* remove this param */
		CALL_QCSAPI(remove_hs20_param, ret, ifname,
			    ITEM_NAME_HS20_DISABLE_DGAF);
	} else {
		/* add this param */
		CALL_QCSAPI(wifi_set_hs20_params, ret, ifname,
			    ITEM_NAME_HS20_DISABLE_DGAF, value, NULL, NULL,
			    NULL, NULL, NULL);
	}
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

char *qweb_get_hs20_disable_dgaf(char *path, int *perr)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");
	CALL_QCSAPI(wifi_get_hs20_params, ret, ifname,
		    ITEM_NAME_HS20_DISABLE_DGAF, string_value_buf);

	QWEBAPI_GET_RETURN(ret, "");

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_hs20_osen */
int qweb_set_hs20_osen(char *path, char *value)
{
	int ret;
	char *val;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	if (strlen(value) == 0) {
		/* remove this param */
		CALL_QCSAPI(remove_hs20_param, ret, ifname,
			    ITEM_NAME_HS20_OSEN);
	} else {
		/* add this param */
		if (!strcasecmp(value, ITEM_NAME_ENABLE)) {
			val = "1";
		} else if (!strcasecmp(value, ITEM_NAME_DISABLE)) {
			val = "0";
		} else {
			qwebprintf(DBG_LEVEL_VERBOSE,
				   "%s(), %d, value is wrong, value = %s!!!\n",
				   __func__, __LINE__, value);
			return QWEBAPI_ERR_INVALID_VALUE;
		}

		CALL_QCSAPI(wifi_set_hs20_params, ret, ifname,
			    ITEM_NAME_HS20_OSEN, val,
			    NULL, NULL, NULL, NULL, NULL);
	}
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

char *qweb_get_hs20_osen(char *path, int *perr)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");
	CALL_QCSAPI(wifi_get_hs20_params, ret, ifname,
		    ITEM_NAME_HS20_OSEN, string_value_buf);

	QWEBAPI_GET_RETURN(ret, "");

	if (!strcasecmp(string_value_buf, "1")) {
		return ITEM_NAME_ENABLE;
	} else if (!strcasecmp(string_value_buf, "0")) {
		return ITEM_NAME_DISABLE;
	} else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is wrong, value = %s!!!\n",
			   __func__, __LINE__, string_value_buf);
		return "";
	}
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_hs20_deauth_req_timeout */
int qweb_set_hs20_deauth_req_timeout(char *path, char *value)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);
	if (strlen(value) == 0) {
		/* remove this param */
		CALL_QCSAPI(remove_hs20_param, ret, ifname,
			    ITEM_NAME_HS20_DEAUTH_REQ_TIMEOUT);
	} else {
		/* add this param */
		CALL_QCSAPI(wifi_set_hs20_params, ret, ifname,
			    ITEM_NAME_HS20_DEAUTH_REQ_TIMEOUT, value,
			    NULL, NULL, NULL, NULL, NULL);
	}
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

char *qweb_get_hs20_deauth_req_timeout(char *path, int *perr)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");
	CALL_QCSAPI(wifi_get_hs20_params, ret, ifname,
		    ITEM_NAME_HS20_DEAUTH_REQ_TIMEOUT, string_value_buf);

	QWEBAPI_GET_RETURN(ret, "");
	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_hs20_operating_class */
int qweb_set_hs20_operating_class(char *path, char *value)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);
	if (strlen(value) == 0) {
		/* remove this param */
		CALL_QCSAPI(remove_hs20_param, ret, ifname,
			    ITEM_NAME_HS20_OPERATING_CLASS);
	} else {
		/* add this param */
		char *band24g;
		char *band5g;

		band24g = strtok(value, QWEBAPI_SPACE);
		band5g = strtok(NULL, QWEBAPI_SPACE);
		if (band24g == NULL) {
			qwebprintf(DBG_LEVEL_VERBOSE,
				   "%s(), %d, value is wrong, value = %s!!!\n",
				   __func__, __LINE__, string_value_buf);

		}
		CALL_QCSAPI(wifi_set_hs20_params, ret, ifname,
			    ITEM_NAME_HS20_OPERATING_CLASS, band24g,
			    band5g, NULL, NULL, NULL, NULL);
	}
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

char *qweb_get_hs20_operating_class(char *path, int *perr)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");
	CALL_QCSAPI(wifi_get_hs20_params, ret, ifname,
		    ITEM_NAME_HS20_OPERATING_CLASS, string_value_buf);

	QWEBAPI_GET_RETURN(ret, "");
	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_hs20_osu_ssid */
int qweb_set_hs20_osu_ssid(char *path, char *value)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);
	if (strlen(value) == 0) {
		/* remove this param */
		CALL_QCSAPI(remove_hs20_param, ret, ifname,
			    ITEM_NAME_HS20_OSU_SSID);
	} else {
		/* add this param */
		CALL_QCSAPI(wifi_set_hs20_params, ret, ifname,
			    ITEM_NAME_HS20_OSU_SSID, value,
			    NULL, NULL, NULL, NULL, NULL);
	}
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

char *qweb_get_hs20_osu_ssid(char *path, int *perr)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");
	CALL_QCSAPI(wifi_get_hs20_params, ret, ifname,
		    ITEM_NAME_HS20_OSU_SSID, string_value_buf);

	QWEBAPI_GET_RETURN(ret, "");
	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_hs20_conn_capab */
static int qweb_add_hs20_conn_capab(char *path, char *ip_proto,
				    char *port_num, char *status)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	CALL_QCSAPI(security_add_hs20_conn_capab, ret, ifname, ip_proto,
		    port_num, status);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

static int qweb_del_hs20_conn_capab(char *path, char *ip_proto,
				    char *port_num, char *status)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	CALL_QCSAPI(security_del_hs20_conn_capab, ret, ifname, ip_proto,
		    port_num, status);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

int qweb_set_hs20_conn_capab(char *path, char *value)
{
	int ret;
	char *ifname;
	char *status;
	char *op_code;
	char *ip_proto;
	char *port_num;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	op_code = strtok(value, QWEBAPI_SPACE);
	ip_proto = strtok(NULL, QWEBAPI_SPACE);
	port_num = strtok(NULL, QWEBAPI_SPACE);
	status = strtok(NULL, QWEBAPI_SPACE);

	if (!(op_code || ip_proto || port_num || status)) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is wrong. value = %s\n", __func__,
			   __LINE__, value);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	if (op_code && strcasecmp(op_code, QWEBAPI_OP_CODE_ADD) == 0) {
		return qweb_add_hs20_conn_capab(path, ip_proto,
						port_num, status);
	} else if (op_code && strcasecmp(op_code, QWEBAPI_OP_CODE_DEL) == 0) {
		return qweb_del_hs20_conn_capab(path, ip_proto,
						port_num, status);
	} else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is wrong. value = %s\n",
			   __func__, __LINE__, value);
		return QWEBAPI_ERR_INVALID_VALUE;
	}
}

char *qweb_get_hs20_conn_capab(char *path, int *perr)
{
	int ret;
	int len;
	char *ifname;
	char *token;
	char *buf;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");

	buf = calloc(4096, sizeof(char));
	if (buf == NULL) {
		qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, calloc failed!!!\n",
			   __func__, __LINE__);
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		return "";
	}

	CALL_QCSAPI(security_get_hs20_conn_capab, ret, ifname, buf);
	if (ret) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, get hs20 conn capab failed.\n",
			   __func__, __LINE__);
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		safe_free(buf);

		return "";
	}

	string_value_buf[0] = '\0';
	token = strtok(buf, QWEBAPI_ENTER);
	while (token != NULL) {
		if (strlen(string_value_buf) + strlen(token)
		    + strlen(QWEBAPI_SPACE) < sizeof(string_value_buf) - 1) {
			strncat(string_value_buf, token, strlen(token));
			strcat(string_value_buf, QWEBAPI_SPACE);
		}
		//get next
		token = strtok(NULL, QWEBAPI_ENTER);
	}

	len = strlen(string_value_buf);
	if (len > 0)
		string_value_buf[len - 1] = '\0';

	safe_free(buf);

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_proxy_arp*/
QWEBAPI_WIFI_SET_STRING_FUNC(proxy_arp, proxy_arp, ITEM_NAME_ACCESSPOINT);
QWEBAPI_WIFI_GET_STRING_FUNC(proxy_arp, proxy_arp, ITEM_NAME_ACCESSPOINT);

/* Device.WiFi.AccessPoint.{i}.Security.Reset */
QWEBAPI_SET_UINT_FUNC_WITH_NOT_SUPPORT(security_reset);
QWEBAPI_GET_UINT_FUNC_WITH_NOT_SUPPORT(security_reset);

/* Device.WiFi.AccessPoint.{i}.Security.ModesSupported */
char *qweb_get_accesspoint_mode_supported(char *path, int *perr)
{
	int ret;
	int len;
	char *ifname;
	int pmf_value;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");
	CALL_QCSAPI(wifi_get_pmf, ret, ifname, &pmf_value);

	string_value_buf[0] = '\0';
	if (pmf_value == qcsapi_pmf_disabled) {
		/* NONE-OPEN */
		strcat(string_value_buf, ITEM_NAME_MODE_NONE);
		strcat(string_value_buf, QWEBAPI_COMMA);

		/* WPA2-AES */
		strcat(string_value_buf, ITEM_NAME_MODE_WPA2_AES);
		strcat(string_value_buf, QWEBAPI_COMMA);

#if 0				/* current version does not display this mode */
		/* WPA2 + WPA (mixed mode) */
		strcat(string_value_buf, ITEM_NAME_MODE_WPA2_WPA);
		strcat(string_value_buf, QWEBAPI_COMMA);
#endif

		/* WPA2-AES Enterprise */
		strcat(string_value_buf, ITEM_NAME_MODE_WPA2_AES_ENTERPRISE);
		strcat(string_value_buf, QWEBAPI_COMMA);

#if 0				/* current version does not display this mode */
		/* WPA2 + WPA Enterprise */
		strcat(string_value_buf, ITEM_NAME_MODE_WPA2_WPA_ENTERPRISE);
		strcat(string_value_buf, QWEBAPI_COMMA);
#endif
	} else if (pmf_value == qcsapi_pmf_optional) {
		/* NONE-OPEN */
		strcat(string_value_buf, ITEM_NAME_MODE_NONE);
		strcat(string_value_buf, QWEBAPI_COMMA);

		/* WPA2-AES */
		strcat(string_value_buf, ITEM_NAME_MODE_WPA2_AES);
		strcat(string_value_buf, QWEBAPI_COMMA);

		/* WPA2-AES Enterprise */
		strcat(string_value_buf, ITEM_NAME_MODE_WPA2_AES_ENTERPRISE);
		strcat(string_value_buf, QWEBAPI_COMMA);

		/* SAE */
		strcat(string_value_buf, ITEM_NAME_MODE_SAE);
		strcat(string_value_buf, QWEBAPI_COMMA);

		/* SAE-WPA-PSK */
		strcat(string_value_buf, ITEM_NAME_MODE_SAE_WPA_PSK);
		strcat(string_value_buf, QWEBAPI_COMMA);

		/* OWE */
		strcat(string_value_buf, ITEM_NAME_MODE_OWE);
		strcat(string_value_buf, QWEBAPI_COMMA);
	} else if (pmf_value == qcsapi_pmf_required) {
		/* NONE-OPEN */
		strcat(string_value_buf, ITEM_NAME_MODE_NONE);
		strcat(string_value_buf, QWEBAPI_COMMA);

#if 0				/* current version does not display this mode */
		/* WPA2-AES-SHA256 */
		strcat(string_value_buf, ITEM_NAME_MODE_WPA2_AES_SHA256);
		strcat(string_value_buf, QWEBAPI_COMMA);
#endif
		/* WPA2-AES Enterprise */
		strcat(string_value_buf, ITEM_NAME_MODE_WPA2_AES_ENTERPRISE);
		strcat(string_value_buf, QWEBAPI_COMMA);

		/* SAE */
		strcat(string_value_buf, ITEM_NAME_MODE_SAE);
		strcat(string_value_buf, QWEBAPI_COMMA);

		/* SAE-WPA_PSK */
		strcat(string_value_buf, ITEM_NAME_MODE_SAE_WPA_PSK);
		strcat(string_value_buf, QWEBAPI_COMMA);

		/* OWE */
		strcat(string_value_buf, ITEM_NAME_MODE_OWE);
		strcat(string_value_buf, QWEBAPI_COMMA);
	} else {
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		return "";
	}

	len = strlen(string_value_buf);
	if (len > 0)
		string_value_buf[len - 1] = '\0';

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.Security.ModeEnabled */
static int qweb_set_beacon_auth_encry(char *ifname, char *beacon_type,
				      char *auth_type, char *encry_type)
{
	int ret;
	char buf[32 + 1];

	/* set beacon type */
	CALL_QCSAPI(wifi_get_beacon_type, ret, ifname, buf);
	if (ret) {
		goto qcsapi_failed;
	}
	if (strcmp(buf, beacon_type)) {
		CALL_QCSAPI(wifi_set_beacon_type, ret, ifname, beacon_type);
		if (ret) {
			goto qcsapi_failed;
		}
	}

	/* authentication mode */
	CALL_QCSAPI(wifi_get_WPA_authentication_mode, ret, ifname, buf);
	if (ret) {
		goto qcsapi_failed;
	}

	if (strcmp(buf, auth_type)) {
		CALL_QCSAPI(wifi_set_WPA_authentication_mode, ret, ifname,
			    auth_type);
		if (ret) {
			goto qcsapi_failed;
		}
	}
	/* encryption mode */
	CALL_QCSAPI(wifi_get_WPA_encryption_modes, ret, ifname, buf);
	if (ret) {
		goto qcsapi_failed;
	}
	if (strcmp(buf, encry_type)) {
		CALL_QCSAPI(wifi_set_WPA_encryption_modes, ret, ifname,
			    encry_type);
		if (ret) {
			goto qcsapi_failed;
		}
	}

	return ret;

 qcsapi_failed:
	qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, call qcsapi failed.\n",
		   __func__, __LINE__);
	return QWEBAPI_ERR_NOT_AVALIABLE;
}

int qweb_set_mode_enabled(char *path, char *value)
{
	int ret = 0;
	char *ifname;
	char ipaddr[16];

	if (qweb_get_inactive_mode() == 1)
		return qweb_set_inactive_cfg(path, value);

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
#ifdef TOPAZ_DBDC
	char *key_mgmt_str = NULL;
	char *proto_str = NULL;
	char *pairwise_str = NULL;
	int idx;
	idx = qweb_get_key_index(path, ITEM_NAME_ACCESSPOINT);
	if (idx < QWEBAPI_MAX_BSSID + QWEBAPI_MAX_24G_BSSID
	    && idx >= QWEBAPI_MAX_BSSID) {
		char qweb_cmd[QWEBAPI_CMD_MAX_LEN];
		ret = qweb_check_if_available_24G(path, ifname);
		if (ret) {
			return ret;
		}

		if (!ret) {
			char *mode;
			if (!strcmp(value, ITEM_NAME_MODE_WPA2_AES)) {
				mode = ITEM_NAME_MODE_WPA2_AES_24G;
			} else if (!strcmp(value, ITEM_NAME_MODE_WPA2_TKIP)) {
				mode = ITEM_NAME_MODE_WPA2_TKIP_24G;
			} else if (!strcmp(value, ITEM_NAME_MODE_WPA_AES)) {
				mode = ITEM_NAME_MODE_WPA_AES_24G;
			} else if (!strcmp(value, ITEM_NAME_MODE_WPA_TKIP)) {
				mode = ITEM_NAME_MODE_WPA_TKIP_24G;
			} else if (!strcmp(value, ITEM_NAME_MODE_WPA2_WPA)) {
				mode = ITEM_NAME_MODE_WPA2_WPA_24G;
			} else if (!strcmp(value, ITEM_NAME_MODE_NONE)) {
				mode = ITEM_NAME_MODE_NONE_24G;
			} else if (!strcmp(value, ITEM_NAME_MODE_SAE)) {
				mode = ITEM_NAME_MODE_SAE_24G;
			} else if (!strcmp(value, ITEM_NAME_MODE_SAE_WPA_PSK)) {
				mode = ITEM_NAME_MODE_SAE_WPA_PSK_24G;
			} else if (!strcmp(value, ITEM_NAME_MODE_OWE)) {
				mode = ITEM_NAME_MODE_OWE_24G;
			} else {
				return QWEBAPI_ERR_NOT_AVALIABLE;
			}

			snprintf(qweb_cmd, QWEBAPI_CMD_MAX_LEN, "encryption.%s",
				 ifname);
			/* Get original encryption */
			CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG, QWEBAPI_OP_GET,
				    qweb_cmd, NULL, string_value_buf,
				    QWEBAPI_TR181_STRING_MAX_LEN);

			if (strcmp(mode, string_value_buf)) {
				CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG,
					    QWEBAPI_OP_SET, qweb_cmd, mode,
					    string_value_buf,
					    QWEBAPI_TR181_STRING_MAX_LEN);

				QWEBAPI_SET_RETURN(ret);
				need_to_apply_for_24G = 1;
			}
			return ret;
		}
	}

	if (qweb_get_wifi_mode() == qcsapi_station) {
		if (strcasecmp(value, ITEM_NAME_MODE_NONE) == 0) {
			key_mgmt_str = "WPA-PSK";
			proto_str = "0";
			pairwise_str = "CCMP";
		} else if (strcasecmp(value, ITEM_NAME_MODE_WPA2_AES) == 0) {
			key_mgmt_str = "WPA-PSK";
			proto_str = "2";
			pairwise_str = "CCMP";
		} else if (strcasecmp(value, ITEM_NAME_MODE_WPA2_WPA) == 0) {
			key_mgmt_str = "WPA-PSK";
			proto_str = "3";
			pairwise_str = "TKIP CCMP";
		} else if (strcasecmp(value, ITEM_NAME_MODE_SAE) == 0) {
			key_mgmt_str = "SAE";
			proto_str = "4";
			pairwise_str = "CCMP";
		} else if (strcasecmp(value, ITEM_NAME_MODE_SAE_WPA_PSK) == 0) {
			key_mgmt_str = "SAE WPA-PSK";
			proto_str = "5";
			pairwise_str = "CCMP";
		} else if (strcasecmp(value, ITEM_NAME_MODE_OWE) == 0) {
			key_mgmt_str = "OWE";
			proto_str = "6";
			pairwise_str = "CCMP";
		} else {
			return QWEBAPI_ERR_INVALID_VALUE;
		}

		CALL_QCSAPI(wifi_update_bss_cfg, ret, TOPAZ_DBDC_5G_RADIO_NAME, qcsapi_access_point,
					ifname, "wpa_key_mgmt", key_mgmt_str, NULL);
		CALL_QCSAPI(wifi_update_bss_cfg, ret, TOPAZ_DBDC_5G_RADIO_NAME, qcsapi_access_point,
					ifname, "wpa", proto_str, NULL);
		CALL_QCSAPI(wifi_update_bss_cfg, ret, TOPAZ_DBDC_5G_RADIO_NAME, qcsapi_access_point,
					ifname, "wpa_pairwise", pairwise_str, NULL);
		return ret;
	}
#endif

	if (strcasecmp(value, ITEM_NAME_MODE_NONE) == 0) {
		ret =
		    qweb_set_beacon_auth_encry(ifname,
					       ITEM_NAME_AUTH_PROTO_BASIC,
					       ITEM_NAME_AUTH_TYPE_PSK,
					       ITEM_NAME_ENCRY_TYPE_AES);
	} else if (strcasecmp(value, ITEM_NAME_MODE_WPA2_AES) == 0) {
		ret =
		    qweb_set_beacon_auth_encry(ifname, ITEM_NAME_AUTH_PROTO_11I,
					       ITEM_NAME_AUTH_TYPE_PSK,
					       ITEM_NAME_ENCRY_TYPE_AES);
	} else if (strcasecmp(value, ITEM_NAME_MODE_WPA2_AES_SHA256) == 0) {
		ret =
		    qweb_set_beacon_auth_encry(ifname, ITEM_NAME_AUTH_PROTO_11I,
					       ITEM_NAME_AUTH_TYPE_SHA256PSK,
					       ITEM_NAME_ENCRY_TYPE_AES);
	} else if (strcasecmp(value, ITEM_NAME_MODE_WPA2_WPA) == 0) {
		ret =
		    qweb_set_beacon_auth_encry(ifname,
					       ITEM_NAME_AUTH_PROTO_WPA_AND_11I,
					       ITEM_NAME_AUTH_TYPE_PSK,
					       ITEM_NAME_ENCRY_TYPE_TKIP_AES);

	} else if (strcasecmp(value, ITEM_NAME_MODE_WPA2_AES_ENTERPRISE) == 0) {
		ret =
		    qweb_set_beacon_auth_encry(ifname,
					       ITEM_NAME_AUTH_PROTO_WPA_AND_11I,
					       ITEM_NAME_AUTH_TYPE_EAP,
					       ITEM_NAME_ENCRY_TYPE_AES);
		if (ret)
			return ret;

		/* ip addr */
		qweb_get_ip_addr(ipaddr);
		CALL_QCSAPI(wifi_set_own_ip_addr, ret, ifname, ipaddr);
	} else if (strcasecmp(value, ITEM_NAME_MODE_WPA2_WPA_ENTERPRISE) == 0) {
		ret =
		    qweb_set_beacon_auth_encry(ifname,
					       ITEM_NAME_AUTH_PROTO_WPA_AND_11I,
					       ITEM_NAME_AUTH_TYPE_EAP,
					       ITEM_NAME_ENCRY_TYPE_TKIP_AES);

		/* ip addr */
		qweb_get_ip_addr(ipaddr);
		CALL_QCSAPI(wifi_set_own_ip_addr, ret, ifname, ipaddr);
	} else if (strlen(value) > 0) {
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	return ret;
}

char *qweb_get_mode_enabled(char *path, int *perr)
{
	int ret;
	char *ifname;
	char beacon_type[16];
	char encryption_modes[33];
	char authentication_mode[33];

	if (qweb_get_inactive_mode() == 1) {
		ret = qweb_get_inactive_cfg(path, string_value_buf, sizeof(string_value_buf));
		if (ret == 0)
			return string_value_buf;
	}

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
#ifdef TOPAZ_DBDC
	int idx;
	idx = qweb_get_key_index(path, ITEM_NAME_ACCESSPOINT);
	if (idx < QWEBAPI_MAX_BSSID + QWEBAPI_MAX_24G_BSSID
	    && idx >= QWEBAPI_MAX_BSSID) {
		char qweb_cmd[QWEBAPI_CMD_MAX_LEN];
		ret = qweb_check_if_available_24G(path, ifname);
		if (ret) {
			*perr = ret;
		}

		snprintf(qweb_cmd, QWEBAPI_CMD_MAX_LEN, "encryption.%s",
			 ifname);
		CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG, QWEBAPI_OP_GET,
			    qweb_cmd, NULL, string_value_buf,
			    QWEBAPI_TR181_STRING_MAX_LEN);

		if (!ret) {
			if (!strcmp(string_value_buf, ITEM_NAME_MODE_WPA2_AES_24G)) {
				return ITEM_NAME_MODE_WPA2_AES;
			} else if (!strcmp(string_value_buf, ITEM_NAME_MODE_WPA2_TKIP_24G)) {
				return ITEM_NAME_MODE_WPA2_TKIP;
			} else if (!strcmp(string_value_buf, ITEM_NAME_MODE_WPA_AES_24G)) {
				return ITEM_NAME_MODE_WPA_AES;
			} else if (!strcmp(string_value_buf, ITEM_NAME_MODE_WPA_TKIP_24G)) {
				return ITEM_NAME_MODE_WPA_TKIP;
			} else if (!strcmp(string_value_buf, ITEM_NAME_MODE_WPA2_WPA_24G)) {
				return ITEM_NAME_MODE_WPA2_WPA;
			} else if (!strcmp(string_value_buf, ITEM_NAME_MODE_NONE_24G)) {
				return ITEM_NAME_MODE_NONE;
			} else if (!strcmp(string_value_buf, ITEM_NAME_MODE_SAE_24G)) {
				return ITEM_NAME_MODE_SAE;
			} else if (!strcmp(string_value_buf, ITEM_NAME_MODE_SAE_WPA_PSK_24G)) {
				return ITEM_NAME_MODE_SAE_WPA_PSK;
			} else if (!strcmp(string_value_buf, ITEM_NAME_MODE_OWE_24G)) {
				return ITEM_NAME_MODE_OWE;
			} else {
				*perr = QWEBAPI_ERR_NOT_AVALIABLE;
				return "";
			}
		}
	}
#endif

	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");
	CALL_QCSAPI(wifi_get_beacon_type, ret, ifname, beacon_type);
	if (ret)
		goto bail;

	CALL_QCSAPI(wifi_get_WPA_authentication_mode, ret, ifname,
		    authentication_mode);
	if (ret)
		goto bail;

	CALL_QCSAPI(wifi_get_WPA_encryption_modes, ret, ifname,
		    encryption_modes);
	if (ret)
		goto bail;

	if (strcmp(beacon_type, ITEM_NAME_AUTH_PROTO_BASIC) == 0) {
		return ITEM_NAME_MODE_NONE;
	} else if (strcmp(authentication_mode, ITEM_NAME_AUTH_TYPE_EAP) == 0
		   && strcmp(encryption_modes,
			     ITEM_NAME_ENCRY_TYPE_TKIP_AES) == 0) {
		return ITEM_NAME_MODE_WPA2_WPA_ENTERPRISE;
	} else if (strcmp(authentication_mode, ITEM_NAME_AUTH_TYPE_EAP) == 0
		   && strcmp(encryption_modes, ITEM_NAME_ENCRY_TYPE_AES) == 0) {
		return ITEM_NAME_MODE_WPA2_AES_ENTERPRISE;
	} else if (strcmp(beacon_type, ITEM_NAME_AUTH_PROTO_11I) == 0
		   && strcmp(authentication_mode, ITEM_NAME_AUTH_TYPE_PSK) == 0
		   && strcmp(encryption_modes, ITEM_NAME_ENCRY_TYPE_AES) == 0) {
		return ITEM_NAME_MODE_WPA2_AES;
	} else if (strcmp(beacon_type, ITEM_NAME_AUTH_PROTO_11I) == 0
		   && strcmp(authentication_mode,
			     ITEM_NAME_AUTH_TYPE_SHA256PSK) == 0
		   && strcmp(encryption_modes, ITEM_NAME_ENCRY_TYPE_AES) == 0) {
		return ITEM_NAME_MODE_WPA2_AES_SHA256;
	} else if (strcmp(beacon_type, ITEM_NAME_AUTH_PROTO_WPA_AND_11I) == 0
		   && strcmp(encryption_modes,
			     ITEM_NAME_ENCRY_TYPE_TKIP_AES) == 0) {
		return ITEM_NAME_MODE_WPA2_WPA;
	} else if (strcmp(beacon_type, ITEM_NAME_AUTH_PROTO_11I) == 0
		   && strcmp(encryption_modes,
			     ITEM_NAME_ENCRY_TYPE_AES) == 0) {
		return ITEM_NAME_MODE_SAE;
	} else if (strcmp(beacon_type, ITEM_NAME_AUTH_PROTO_11I) == 0
		   && strcmp(encryption_modes,
			     ITEM_NAME_ENCRY_TYPE_AES) == 0) {
		return ITEM_NAME_MODE_SAE_WPA_PSK;
	} else if (strcmp(beacon_type, ITEM_NAME_AUTH_PROTO_11I) == 0
		   && strcmp(encryption_modes,
			     ITEM_NAME_ENCRY_TYPE_AES) == 0) {
		return ITEM_NAME_MODE_OWE;
	} else
		goto bail;

 bail:
	*perr = QWEBAPI_ERR_NOT_AVALIABLE;
	return "";
}

/* Device.WiFi.AccessPoint.{i}.Security.WEBKey */
QWEBAPI_SET_STRING_FUNC_WITH_NOT_SUPPORT(wep_key);
QWEBAPI_GET_STRING_FUNC_WITH_NOT_SUPPORT(wep_key);

/* Device.WiFi.AccessPoint.{i}.Security.PreSharedKey */
int qweb_set_pre_shared_key(char *path, char *value)
{
	int ret;
	char *ifname;
	char buf[64 + 1] = {0x00};

	if (qweb_get_inactive_mode() == 1)
		return qweb_set_inactive_cfg(path, value);

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, 0);

	CALL_QCSAPI(wifi_get_pre_shared_key, ret, ifname, 0, buf);
	if (ret == -qcsapi_only_on_AP)
		return QWEBAPI_ERR_NOT_AVALIABLE;
	else if (ret == -qcsapi_parameter_not_found)
		;/* do nothing */

	if (strcmp(buf, value)) {
		CALL_QCSAPI(wifi_set_pre_shared_key, ret, ifname, 0, value);
		QWEBAPI_SET_RETURN(ret);
	}

	return ret;
}

char *qweb_get_pre_shared_key(char *path, int *perr)
{
	int ret;
	char *ifname;

	if (qweb_get_inactive_mode() == 1) {
		ret = qweb_get_inactive_cfg(path, string_value_buf, sizeof(string_value_buf));
		if (ret == 0)
			return string_value_buf;
		else
			return "";
	}

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");
	CALL_QCSAPI(wifi_get_pre_shared_key, ret, ifname, 0, string_value_buf);
	QWEBAPI_GET_RETURN(ret, "");

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.Security.KeyPassphrase */
#ifdef TOPAZ_DBDC
static int qweb_check_if_available_24G(char *path, char *ifname)
{
	int ret;
	char qweb_cmd[QWEBAPI_CMD_MAX_LEN];
	snprintf(qweb_cmd, QWEBAPI_CMD_MAX_LEN, "enable.%s", ifname);
	CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG, QWEBAPI_OP_GET,
		    qweb_cmd, NULL, string_value_buf,
		    QWEBAPI_TR181_STRING_MAX_LEN);

	//To judge the VAP weather exist or not
	if (ret || strcmp(string_value_buf, "1")) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, call qwe_command failed.",
			   __func__, __LINE__);
		return QWEBAPI_ERR_NOT_AVALIABLE;
	}
	return 0;
}
#endif

int qweb_set_key_passphrase(char *path, char *value)
{
	int ret;
	char *ifname;
	char buf[64 + 1] = { 0x00 };

	if (qweb_get_inactive_mode() == 1)
		return qweb_set_inactive_cfg(path, value);

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);

#ifdef TOPAZ_DBDC
	int idx;
	idx = qweb_get_key_index(path, ITEM_NAME_ACCESSPOINT);
	if (idx < QWEBAPI_MAX_BSSID + QWEBAPI_MAX_24G_BSSID
	    && idx >= QWEBAPI_MAX_BSSID) {
		char qweb_cmd[QWEBAPI_CMD_MAX_LEN];
		ret = qweb_check_if_available_24G(path, ifname);
		if (ret) {
			return ret;
		}

		snprintf(qweb_cmd, QWEBAPI_CMD_MAX_LEN, "passphrase.%s",
			 ifname);
		/* Get original passphrase */
		CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG, QWEBAPI_OP_GET,
			    qweb_cmd, NULL, string_value_buf,
			    QWEBAPI_TR181_STRING_MAX_LEN);

		if (strcmp(value, string_value_buf)) {
			CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG, QWEBAPI_OP_SET,
				    qweb_cmd, value, string_value_buf,
				    QWEBAPI_TR181_STRING_MAX_LEN);

			QWEBAPI_SET_RETURN(ret);
			need_to_apply_for_24G = 1;
		}

		return ret;
	}
	if (qweb_get_wifi_mode() == qcsapi_station) {
		CALL_QCSAPI(wifi_update_bss_cfg, ret, TOPAZ_DBDC_5G_RADIO_NAME, qcsapi_access_point,
					ifname, "wpa_psk", "null", NULL);
		CALL_QCSAPI(wifi_update_bss_cfg, ret, TOPAZ_DBDC_5G_RADIO_NAME, qcsapi_access_point,
					ifname, "wpa_passphrase", value, NULL);
		return ret;
	}
#endif

	CALL_QCSAPI(wifi_get_key_passphrase, ret, ifname, 0, buf);
	if (ret == -qcsapi_only_on_AP)
		return QWEBAPI_ERR_NOT_AVALIABLE;
	else if (ret == -qcsapi_parameter_not_found)
		;/* do nothing */
	else if (ret == -19)
		return 0;/* No such device */

	if (strcmp(buf, value)) {
		CALL_QCSAPI(wifi_set_key_passphrase, ret, ifname, 0, value);
		QWEBAPI_SET_RETURN(ret);
	}

	return ret;
}

char *qweb_get_key_passphrase(char *path, int *perr)
{
	int ret;
	char *ifname;

	if (qweb_get_inactive_mode() == 1) {
		ret = qweb_get_inactive_cfg(path, string_value_buf, sizeof(string_value_buf));
		if (ret == 0)
			return string_value_buf;
		else
			return "";
	}

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
#ifdef TOPAZ_DBDC
	int idx;
	idx = qweb_get_key_index(path, ITEM_NAME_ACCESSPOINT);
	if (idx < QWEBAPI_MAX_BSSID + QWEBAPI_MAX_24G_BSSID
	    && idx >= QWEBAPI_MAX_BSSID) {
		char qweb_cmd[QWEBAPI_CMD_MAX_LEN];
		ret = qweb_check_if_available_24G(path, ifname);
		if (ret) {
			*perr = ret;
		}

		snprintf(qweb_cmd, QWEBAPI_CMD_MAX_LEN, "passphrase.%s",
			 ifname);
		CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG, QWEBAPI_OP_GET,
			    qweb_cmd, NULL, string_value_buf,
			    QWEBAPI_TR181_STRING_MAX_LEN);

		if (ret) {
			*perr = QWEBAPI_ERR_NOT_AVALIABLE;
			return "";
		} else {
			return string_value_buf;
		}
	}
#endif
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");
	CALL_QCSAPI(wifi_get_key_passphrase, ret, ifname, 0, string_value_buf);
	QWEBAPI_GET_RETURN(ret, "");

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.Security.RekeyingInterval */
QWEBAPI_WIFI_SET_UINT_FUNC(rekeying_interval, group_key_interval,
			   ITEM_NAME_ACCESSPOINT);
QWEBAPI_WIFI_GET_UINT_FUNC(rekeying_interval, group_key_interval,
			   ITEM_NAME_ACCESSPOINT);

/* Device.WiFi.AccessPoint.{i}.Security.RadiusServerIPAddr */
static radius_type qweb_get_raidus_type(char *path)
{
	if (strstr(path, ITEM_NAME_SECURITY))
		return RADIUS_AUTH_SERVER;
	else if (strstr(path, ITEM_NAME_ACCOUNTING))
		return RADIUS_ACCT_SERVER;
	else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, radius_type is wrong, path = %s\n",
			   __func__, __LINE__, path);
		return RADIUS_TYPE_ERROR;
	}
}

static char *qweb_get_radius_value(char *path, int index)
{
	int ret;
	char *ifname;
	radius_type op_flag;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	op_flag = qweb_get_raidus_type(path);
	if (op_flag == RADIUS_AUTH_SERVER)
		CALL_QCSAPI(wifi_get_radius_auth_server_cfg, ret, ifname,
			    string_value_buf);
	else
		CALL_QCSAPI(wifi_get_radius_acct_server_cfg, ret, ifname,
			    string_value_buf);
	if (ret)
		return NULL;

	if (index == 0) {
		return strtok(string_value_buf, QWEBAPI_ENTER);
	} else if (index == 1) {
		strtok(string_value_buf, QWEBAPI_ENTER);
		return strtok(NULL, QWEBAPI_ENTER);
	} else
		return "";
}

static int qweb_get_radius_cfg(char *cfg_string, char *ip, char *port,
			       char *key)
{
	strncpy(ip, strtok(cfg_string, QWEBAPI_SPACE),
		QWEBAPI_TR181_IP_STR_MAX_LEN);
	strncpy(port, strtok(NULL, QWEBAPI_SPACE),
		QWEBAPI_TR181_PORT_STR_MAX_LEN);
	strncpy(key, strtok(NULL, QWEBAPI_SPACE),
		QWEBAPI_TR181_PASSPHRASE_MAX_LEN);

	return 0;
}

static int qweb_replace_radius_value1(char *path, char *config0,
				      radius_server_cfg * server_cfg, int index,
				      radius_type op_flag)
{
	int ret;
	char *ifname;
	char ip[QWEBAPI_TR181_IP_STR_MAX_LEN];
	char port[QWEBAPI_TR181_PORT_STR_MAX_LEN];
	char key[QWEBAPI_TR181_PASSPHRASE_MAX_LEN];
	char tmp_port[QWEBAPI_TR181_PORT_STR_MAX_LEN];

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);

	if (index == 0) {
		//delete index0
		qweb_get_radius_cfg(config0, ip, port, key);

		//del index0
		if (op_flag == RADIUS_AUTH_SERVER)
			CALL_QCSAPI(wifi_del_radius_auth_server_cfg, ret,
				    ifname, ip, port);
		else
			CALL_QCSAPI(wifi_del_radius_acct_server_cfg, ret,
				    ifname, ip, port);

		if (ret)
			return QWEBAPI_ERR_NOT_AVALIABLE;
	}
	//add index0 or index1
	snprintf(tmp_port,
		 QWEBAPI_TR181_PORT_STR_MAX_LEN, "%d", server_cfg->port);
	if (op_flag == RADIUS_AUTH_SERVER)
		CALL_QCSAPI(wifi_add_radius_auth_server_cfg, ret, ifname,
			    server_cfg->ip_addr, tmp_port, server_cfg->key);
	else
		CALL_QCSAPI(wifi_add_radius_acct_server_cfg, ret, ifname,
			    server_cfg->ip_addr, tmp_port, server_cfg->key);
	if (ret)
		return QWEBAPI_ERR_NOT_AVALIABLE;
	else {
		memset(&server_cfg, 0x00, sizeof(server_cfg));
		return 0;
	}
}

static int qweb_replace_radius_value2(char *path, char *config0, char *config1,
				      radius_server_cfg * server_cfg, int index,
				      radius_type op_flag)
{
	int ret;
	char *ifname;
	char ip[QWEBAPI_TR181_IP_STR_MAX_LEN];
	char port[QWEBAPI_TR181_PORT_STR_MAX_LEN];
	char key[QWEBAPI_TR181_PASSPHRASE_MAX_LEN];
	char tmp_port[QWEBAPI_TR181_PORT_STR_MAX_LEN];

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	if (index == 0) {
		//get index0
		qweb_get_radius_cfg(config0, ip, port, key);

		//del index0
		if (op_flag == RADIUS_AUTH_SERVER)
			CALL_QCSAPI(wifi_del_radius_auth_server_cfg, ret,
				    ifname, ip, port);
		else
			CALL_QCSAPI(wifi_del_radius_acct_server_cfg, ret,
				    ifname, ip, port);

		if (ret)
			goto qcsapi_err;

		//get index1
		qweb_get_radius_cfg(config1, ip, port, key);

		//del index1
		if (op_flag == RADIUS_AUTH_SERVER)
			CALL_QCSAPI(wifi_del_radius_auth_server_cfg, ret,
				    ifname, ip, port);
		else
			CALL_QCSAPI(wifi_del_radius_acct_server_cfg, ret,
				    ifname, ip, port);

		if (ret)
			goto qcsapi_err;

		//add index0
		snprintf(tmp_port,
			 QWEBAPI_TR181_PORT_STR_MAX_LEN,
			 "%d", server_cfg->port);
		if (op_flag == RADIUS_AUTH_SERVER)
			CALL_QCSAPI(wifi_add_radius_auth_server_cfg, ret,
				    ifname, server_cfg->ip_addr, tmp_port,
				    server_cfg->key);
		else
			CALL_QCSAPI(wifi_add_radius_acct_server_cfg, ret,
				    ifname, server_cfg->ip_addr, tmp_port,
				    server_cfg->key);
		if (ret)
			goto qcsapi_err;

		//add index1
		if (op_flag == RADIUS_AUTH_SERVER)
			CALL_QCSAPI(wifi_add_radius_auth_server_cfg, ret,
				    ifname, ip, port, key);
		else
			CALL_QCSAPI(wifi_add_radius_acct_server_cfg, ret,
				    ifname, ip, port, key);

		if (ret)
			goto qcsapi_err;
		else
			goto add_ok;

	} else if (index == 1) {
		//delete index 1
		qweb_get_radius_cfg(config1, ip, port, key);

		//del index1
		if (op_flag == RADIUS_AUTH_SERVER)
			CALL_QCSAPI(wifi_del_radius_auth_server_cfg, ret,
				    ifname, ip, port);
		else
			CALL_QCSAPI(wifi_del_radius_acct_server_cfg, ret,
				    ifname, ip, port);
		if (ret)
			goto qcsapi_err;

		//add index1
		snprintf(tmp_port,
			 QWEBAPI_TR181_PORT_STR_MAX_LEN,
			 "%d", server_cfg->port);
		if (op_flag == RADIUS_AUTH_SERVER)
			CALL_QCSAPI(wifi_add_radius_auth_server_cfg, ret,
				    ifname, server_cfg->ip_addr, tmp_port,
				    server_cfg->key);
		else
			CALL_QCSAPI(wifi_add_radius_acct_server_cfg, ret,
				    ifname, server_cfg->ip_addr, tmp_port,
				    server_cfg->key);

		if (ret)
			goto qcsapi_err;
		else
			goto add_ok;
	}

 qcsapi_err:
	return QWEBAPI_ERR_NOT_AVALIABLE;
 add_ok:
	memset(&server_cfg, 0x00, sizeof(server_cfg));
	return 0;
}

static int qweb_add_radius_value(char *path, radius_server_cfg * server_cfg,
				 int index)
{
	int ret;
	char *ifname;
	radius_type op_flag;
	char tmp_config[128];
	char *config0, *config1;
	char tmp_port[QWEBAPI_TR181_PORT_STR_MAX_LEN];

	if (!
	    (strlen(server_cfg->ip_addr) > 0 && server_cfg->port > 0
	     && strlen(server_cfg->key) > 0)) {
		return 0;
	}

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	snprintf(tmp_config, 128, "%s %d %s", server_cfg->ip_addr,
		 server_cfg->port, server_cfg->key);

	op_flag = qweb_get_raidus_type(path);
	if (op_flag == RADIUS_AUTH_SERVER)
		CALL_QCSAPI(wifi_get_radius_auth_server_cfg, ret,
			    ifname, string_value_buf);
	else
		CALL_QCSAPI(wifi_get_radius_acct_server_cfg, ret,
			    ifname, string_value_buf);

	if (ret == -1001) {
		// param was not found.
		snprintf(tmp_port, QWEBAPI_TR181_PORT_STR_MAX_LEN, "%d",
			 server_cfg->port);
		if (op_flag == RADIUS_AUTH_SERVER)
			CALL_QCSAPI(wifi_add_radius_auth_server_cfg,
				    ret, ifname, server_cfg->ip_addr,
				    tmp_port, server_cfg->key);
		else
			CALL_QCSAPI(wifi_add_radius_acct_server_cfg,
				    ret, ifname, server_cfg->ip_addr,
				    tmp_port, server_cfg->key);
		if (ret)
			goto qcsapi_err;
		else
			goto add_ok;
	} else {
		config0 = strtok(string_value_buf, QWEBAPI_ENTER);
		config1 = strtok(NULL, QWEBAPI_ENTER);

		if (config0 && config1) {
			if (strcmp(tmp_config, config0) == 0
			    || strcmp(tmp_config, config1) == 0) {
				// this config already exist in the configure
				qwebprintf(DBG_LEVEL_VERBOSE,
					   "%s(), line = %d, the value already exist in config0 & config1\n",
					   __func__, __LINE__);
				return 0;
			} else {
				return qweb_replace_radius_value2(path, config0,
								  config1,
								  server_cfg,
								  index,
								  op_flag);
			}
		} else if (config0) {
			if (strcmp(tmp_config, config0) == 0) {
				// this config already exist in the configure
				qwebprintf(DBG_LEVEL_VERBOSE,
					   "%s(), line = %d, the value already exist in config1\n",
					   __func__, __LINE__);
				return 0;
			} else {
				return qweb_replace_radius_value1(path, config0,
								  server_cfg,
								  index,
								  op_flag);
			}
		} else {
			snprintf(tmp_port, QWEBAPI_TR181_PORT_STR_MAX_LEN, "%d",
				 server_cfg->port);
			if (op_flag == RADIUS_AUTH_SERVER)
				CALL_QCSAPI(wifi_add_radius_auth_server_cfg,
					    ret, ifname, server_cfg->ip_addr,
					    tmp_port, server_cfg->key);
			else
				CALL_QCSAPI(wifi_add_radius_acct_server_cfg,
					    ret, ifname, server_cfg->ip_addr,
					    tmp_port, server_cfg->key);
			if (ret)
				goto qcsapi_err;
			else
				goto add_ok;
		}
	}
	return 0;
 qcsapi_err:
	return QWEBAPI_ERR_NOT_AVALIABLE;
 add_ok:
	memset(&server_cfg, 0x00, sizeof(server_cfg));
	return 0;
}

static int qweb_del_radius_value(char *path, int index)
{
	int ret;
	char *ifname;
	char *config0, *config1;
	radius_type op_flag;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	op_flag = qweb_get_raidus_type(path);

	if (op_flag == RADIUS_AUTH_SERVER)
		CALL_QCSAPI(wifi_get_radius_auth_server_cfg, ret, ifname,
			    string_value_buf);
	else
		CALL_QCSAPI(wifi_get_radius_acct_server_cfg, ret, ifname,
			    string_value_buf);

	if (ret == -1001) {
		// param was not found.
		goto del_ok;
	} else {
		char ip[QWEBAPI_TR181_IP_STR_MAX_LEN];
		char port[QWEBAPI_TR181_PORT_STR_MAX_LEN];
		char key[QWEBAPI_TR181_PASSPHRASE_MAX_LEN];

		config0 = strtok(string_value_buf, QWEBAPI_ENTER);
		config1 = strtok(NULL, QWEBAPI_ENTER);

		if (config0 && config1) {
			char *p_cfg;
			//get index
			if (index == 0)
				p_cfg = config0;
			else if (index == 1)
				p_cfg = config1;
			else
				return QWEBAPI_ERR_INVALID_VALUE;

			qweb_get_radius_cfg(p_cfg, ip, port, key);
			if (op_flag == RADIUS_AUTH_SERVER)
				CALL_QCSAPI(wifi_del_radius_auth_server_cfg,
					    ret, ifname, ip, port);
			else
				CALL_QCSAPI(wifi_del_radius_acct_server_cfg,
					    ret, ifname, ip, port);
			if (ret)
				goto qcsapi_err;
			else
				goto del_ok;
		} else if (config0) {
			qweb_get_radius_cfg(config0, ip, port, key);
			if (op_flag == RADIUS_AUTH_SERVER)
				CALL_QCSAPI(wifi_del_radius_auth_server_cfg,
					    ret, ifname, ip, port);
			else
				CALL_QCSAPI(wifi_del_radius_acct_server_cfg,
					    ret, ifname, ip, port);

			if (ret)
				goto qcsapi_err;
			else
				goto del_ok;

		} else {
			qwebprintf(DBG_LEVEL_VERBOSE,
				   "%s(), %d, else error. \n", __func__,
				   __LINE__);
			return QWEBAPI_ERR_INVALID_VALUE;
		}

	}
 qcsapi_err:
	qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, else error. \n", __func__,
		   __LINE__);
	return QWEBAPI_ERR_NOT_AVALIABLE;

 del_ok:
	memset(&server_cfg, 0x00, sizeof(server_cfg));
	return 0;
}

/**
 * * \brief Set IP addr to Radius server.
 * *
 * *	if ip_addr equals 0.0.0.0, then delete this configuration
 * *    otherwise, add this configuration.
 * *
 * */
int qweb_set_radius_server_ip(char *path, char *value, int index)
{
	if (strcmp(value, QWEBAPI_DELETE_IP) == 0) {
		return qweb_del_radius_value(path, index);
	} else {
		strncpy(server_cfg.ip_addr, value,
			QWEBAPI_TR181_IP_STR_MAX_LEN);
		return qweb_add_radius_value(path, &server_cfg, index);
	}
}

int qweb_set_radius_auth_server_ip(char *path, char *value)
{
	return qweb_set_radius_server_ip(path, value, 0);
}

char *qweb_get_radius_server_ip(char *path, int *perr, int index)
{
	char *p;
	char *cfg_string;

	cfg_string = qweb_get_radius_value(path, index);
	if (cfg_string == NULL) {
		return "";
	}

	p = strtok(cfg_string, QWEBAPI_SPACE);
	return p;
}

char *qweb_get_radius_auth_server_ip(char *path, int *perr)
{
	return qweb_get_radius_server_ip(path, perr, 0);
}

/* Device.WiFi.AccessPoint.{i}.Security.RadiusServerPort */
int qweb_set_radius_server_port(char *path, unsigned int port, int index)
{
	server_cfg.port = port;
	return qweb_add_radius_value(path, &server_cfg, index);
}

int qweb_set_radius_auth_server_port(char *path, unsigned int port)
{
	return qweb_set_radius_server_port(path, port, 0);
}

unsigned int qweb_get_radius_server_port(char *path, int *perr, int index)
{
	char *p;
	char *cfg_string;

	cfg_string = qweb_get_radius_value(path, index);
	if (cfg_string == NULL) {
		return 0;
	}

	p = strtok(cfg_string, QWEBAPI_SPACE);
	p = strtok(NULL, QWEBAPI_SPACE);
	return atoi(p);
}

unsigned int qweb_get_radius_auth_server_port(char *path, int *perr)
{
	return qweb_get_radius_server_port(path, perr, 0);
}

/* Device.WiFi.AccessPoint.{i}.Security.RadiusSecret */
int qweb_set_radius_server_secret(char *path, char *value, int index)
{
	strncpy(server_cfg.key, value, QWEBAPI_TR181_PASSPHRASE_MAX_LEN);
	return qweb_add_radius_value(path, &server_cfg, index);
}

int qweb_set_radius_auth_server_secret(char *path, char *value)
{
	return qweb_set_radius_server_secret(path, value, 0);
}

char *qweb_get_radius_server_secret(char *path, int *perr, int index)
{
	char *p;
	char *cfg_string;

	cfg_string = qweb_get_radius_value(path, index);
	if (cfg_string == NULL) {
		return "";
	}

	p = strtok(cfg_string, QWEBAPI_SPACE);
	p = strtok(NULL, QWEBAPI_SPACE);
	p = strtok(NULL, QWEBAPI_SPACE);

	return p;
}

char *qweb_get_radius_auth_server_secret(char *path, int *perr)
{
	return qweb_get_radius_server_secret(path, perr, 0);
}

/* Device.WiFi.AccessPoint.{i}.Security.SecondaryRadiusServerIPAddr */
/**
 * * \brief Set IP addr to Radius server.
 * *
 * *	if ip_addr equals 0.0.0.0, then delete this configuration
 * *    otherwise, add this configuration.
 * *
 * */
int qweb_set_secondary_radius_auth_server_ip(char *path, char *value)
{
	return qweb_set_radius_server_ip(path, value, 1);
}

char *qweb_get_secondary_radius_auth_server_ip(char *path, int *perr)
{
	return qweb_get_radius_server_ip(path, perr, 1);
}

/* Device.WiFi.AccessPoint.{i}.Security.RadiusServerPort */
int qweb_set_secondary_radius_auth_server_port(char *path, unsigned int port)
{
	return qweb_set_radius_server_port(path, port, 1);
}

unsigned int qweb_get_secondary_radius_auth_server_port(char *path, int *perr)
{
	return qweb_get_radius_server_port(path, perr, 1);
}

/* Device.WiFi.AccessPoint.{i}.Security.RadiusSecret */
int qweb_set_secondary_radius_auth_server_secret(char *path, char *value)
{
	return qweb_set_radius_server_secret(path, value, 1);
}

char *qweb_get_secondary_radius_auth_server_secret(char *path, int *perr)
{
	return qweb_get_radius_server_secret(path, perr, 1);
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_beacon_type */
QWEBAPI_WIFI_SET_STRING_FUNC(beacon_type, beacon_type, ITEM_NAME_ACCESSPOINT);
QWEBAPI_WIFI_GET_STRING_FUNC(beacon_type, beacon_type, ITEM_NAME_ACCESSPOINT);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_WPA_encryption_modes */
QWEBAPI_WIFI_SET_STRING_FUNC(WPA_encryption_modes, WPA_encryption_modes,
			     ITEM_NAME_ACCESSPOINT);
QWEBAPI_WIFI_GET_STRING_FUNC(WPA_encryption_modes, WPA_encryption_modes,
			     ITEM_NAME_ACCESSPOINT);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_WPA_authentication_mode */
QWEBAPI_WIFI_SET_STRING_FUNC(WPA_authentication_mode, WPA_authentication_mode,
			     ITEM_NAME_ACCESSPOINT);
QWEBAPI_WIFI_GET_STRING_FUNC(WPA_authentication_mode, WPA_authentication_mode,
			     ITEM_NAME_ACCESSPOINT);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_WPA_own_ip_addr */
QWEBAPI_WIFI_SET_STRING_FUNC(own_ip_addr, own_ip_addr, ITEM_NAME_ACCESSPOINT);
char *qweb_get_own_ip_addr(char *path, int *perr)
{
	/* The user shouldn't call this function. So it always return null string */
	return "";
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_WDS_peer */
int qweb_set_wds_peer(char *path, char *value)
{
	int ret;
	char *ifname;
	char *op_code;
	char *mac_string;
	struct ether_addr *mac;
	qcsapi_mac_addr mac_addr;

	op_code = strtok(value, QWEBAPI_SPACE);
	mac_string = strtok(NULL, QWEBAPI_SPACE);

	if (!(op_code && mac_string)) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is wrong. value = %s\n",
			   __func__, __LINE__, value);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);

	mac = ether_aton(mac_string);
	if (mac == NULL) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, mac_string is wrong. mac = %s\n",
			   __func__, __LINE__, mac_string);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	memcpy(mac_addr, mac, MAC_ADDR_SIZE);

	if (!strcasecmp(op_code, QWEBAPI_OP_CODE_ADD))
		CALL_QCSAPI(wds_add_peer, ret, ifname, mac_addr);
	else if (!strcasecmp(op_code, QWEBAPI_OP_CODE_DEL))
		CALL_QCSAPI(wds_remove_peer, ret, ifname, mac_addr);
	else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, mac_string is wrong. mac = %s\n",
			   __func__, __LINE__, mac_string);
		return QWEBAPI_ERR_NOT_AVALIABLE;
	}
	QWEBAPI_SET_RETURN(ret);
	return ret;
}

char *qweb_get_wds_peer(char *path, int *perr)
{
	int i;
	int len;
	int ret;
	char *ifname;
	char mac_string[32];
	qcsapi_mac_addr peer_addr;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);

	string_value_buf[0] = '\0';
	for (i = 0; i < QWEBAPI_MAX_WDS_LINKS; i++) {
		CALL_QCSAPI(wds_get_peer_address, ret, ifname, i, peer_addr);
		if (ret == 0) {
			snprintf(mac_string, 32,
				 "WDS%d: %02X:%02X:%02X:%02X:%02X:%02X", i,
				 peer_addr[0], peer_addr[1], peer_addr[2],
				 peer_addr[3], peer_addr[4], peer_addr[5]);
			strncat(string_value_buf, mac_string,
				strlen(mac_string));
			strcat(string_value_buf, QWEBAPI_SPACE);
		}
	}

	len = strlen(string_value_buf);
	if (len > 0)
		string_value_buf[len - 1] = '\0';

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_WDS_psk */
int qweb_set_wds_psk(char *path, char *value)
{
	int ret;
	char *psk;
	char *ifname;
	char *mac_string;
	struct ether_addr *mac;
	qcsapi_mac_addr mac_addr;

	mac_string = strtok(value, QWEBAPI_SPACE);
	psk = strtok(NULL, QWEBAPI_SPACE);

	if (mac_string == NULL) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is wrong. value = %s\n",
			   __func__, __LINE__, value);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);

	mac = ether_aton(mac_string);
	if (mac == NULL) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, mac_string is wrong. mac = %s\n",
			   __func__, __LINE__, mac_string);
		return QWEBAPI_ERR_INVALID_VALUE;
	}
	memcpy(mac_addr, mac, MAC_ADDR_SIZE);

	CALL_QCSAPI(wifi_wds_set_psk, ret, ifname, mac_addr, psk);
	QWEBAPI_SET_RETURN(ret);
	return ret;
}

char *qweb_get_wds_psk(char *path, int *perr)
{
	/* it always return null stirng. you should call its Get function */
	return "";
}

/* Device.WiFi.AccessPoint.{i}.Accounting */
/* Device.WiFi.AccessPoint.{i}.Accounting.Enable */
int qweb_set_acct_enable(char *path, unsigned int value)
{
	/* It doesn't support to set FALSE to Radius Accounting Server,
	 * becaust this function always is opened. */
	if (value != 1)
		return QWEBAPI_ERR_INVALID_VALUE;

	return QWEBAPI_OK;
}

unsigned qweb_get_acct_enable(char *path, int *perr)
{
	/* It always return 1,
	 * becaust this function always is opened. */
	return 1;
}

/* Device.WiFi.AccessPoint.{i}.Accounting.ServerIPAddr */
int qweb_set_radius_acct_server_ip(char *path, char *value)
{
	return qweb_set_radius_server_ip(path, value, 0);
}

char *qweb_get_radius_acct_server_ip(char *path, int *perr)
{
	return qweb_get_radius_server_ip(path, perr, 0);
}

/* Device.WiFi.AccessPoint.{i}.Accounting.SecondaryServerIPAddr */
int qweb_set_secondary_radius_acct_server_ip(char *path, char *value)
{
	return qweb_set_radius_server_ip(path, value, 1);
}

char *qweb_get_secondary_radius_acct_server_ip(char *path, int *perr)
{
	return qweb_get_radius_server_ip(path, perr, 1);
}

/* Device.WiFi.AccessPoint.{i}.Accounting.ServerPort */
int qweb_set_radius_acct_server_port(char *path, unsigned int port)
{
	return qweb_set_radius_server_port(path, port, 0);
}

unsigned int qweb_get_radius_acct_server_port(char *path, int *perr)
{
	return qweb_get_radius_server_port(path, perr, 0);
}

/* Device.WiFi.AccessPoint.{i}.Accounting.SecondaryServerPort */
int qweb_set_secondary_radius_acct_server_port(char *path, unsigned int port)
{
	return qweb_set_radius_server_port(path, port, 1);
}

unsigned int qweb_get_secondary_radius_acct_server_port(char *path, int *perr)
{
	return qweb_get_radius_server_port(path, perr, 1);
}

/* Device.WiFi.AccessPoint.{i}.Accounting.Secret */
int qweb_set_radius_acct_server_secret(char *path, char *value)
{
	return qweb_set_radius_server_secret(path, value, 0);
}

char *qweb_get_radius_acct_server_secret(char *path, int *perr)
{
	return qweb_get_radius_server_secret(path, perr, 0);
}

/* Device.WiFi.AccessPoint.{i}.Accounting.SecondarySecret */
int qweb_set_secondary_radius_acct_server_secret(char *path, char *value)
{
	return qweb_set_radius_server_secret(path, value, 1);
}

char *qweb_get_secondary_radius_acct_server_secret(char *path, int *perr)
{
	return qweb_get_radius_server_secret(path, perr, 1);
}

/* Device.WiFi.AccessPoint.{i}.Accounting.InterimInterval */
#ifdef PEARL_PLATFORM
QWEBAPI_SET_UINT_FUNC_WITH_NOT_SUPPORT(acct_interim_interval);
QWEBAPI_GET_UINT_FUNC_WITH_NOT_SUPPORT(acct_interim_interval);
#else
int qweb_set_acct_interim_interval(char *path, unsigned int interval)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);

	CALL_QCSAPI(wifi_set_radius_acct_interim_interval,
		    ret, ifname, interval);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

unsigned int qweb_get_acct_interim_interval(char *path, int *perr)
{
	int ret;
	char *ifname;
	unsigned int interval;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);

	CALL_QCSAPI(wifi_get_radius_acct_interim_interval,
		    ret, ifname, &interval);
	QWEBAPI_GET_RETURN(ret, 0);

	return interval;
}
#endif

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_WDS_mode */
static int qweb_wds_extdr_combinate(uint16_t flags, uint16_t mask)
{
	return (mask << QWEBAPI_QTN_EXTDR_MASK_SHIFT) | flags;
}

int qweb_set_wds_mode(char *path, char *value)
{
	int ret;
	int rbs_mode;
	int rbs_mask;
	char *mode;
	char *ifname;
	char *mac_string;
	struct ether_addr *mac;
	qcsapi_mac_addr peer_address;

	mac_string = strtok(value, QWEBAPI_SPACE);
	mode = strtok(NULL, QWEBAPI_SPACE);

	if (!(mac_string && mode))
		goto invalid_value;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);

	mac = ether_aton(mac_string);
	if (mac == NULL)
		goto invalid_value;

	memcpy(peer_address, mac, MAC_ADDR_SIZE);

	if (strcasecmp(mode, ITEM_NAME_RBS) == 0) {
		rbs_mode = QWEBAPI_QTN_WDS_RBS;
		rbs_mask = QWEBAPI_QTN_WDS_MASK;
	} else if (strcasecmp(mode, ITEM_NAME_MBS) == 0) {
		rbs_mode = QWEBAPI_QTN_WDS_MBS;
		rbs_mask = QWEBAPI_QTN_WDS_MASK;
	} else if (strcasecmp(mode, ITEM_NAME_WDS) == 0) {
		rbs_mode = QWEBAPI_QTN_WDS_ONLY;
		rbs_mask = QWEBAPI_QTN_WDS_MASK;
	} else if (strcasecmp(mode, ITEM_NAME_RESET) == 0) {
		rbs_mode = 0;
		rbs_mask = QWEBAPI_QTN_EXTDR_ALLMASK;
	} else {
		goto invalid_value;
	}

	CALL_QCSAPI(wds_set_mode, ret, ifname, peer_address,
		    qweb_wds_extdr_combinate(rbs_mode, rbs_mask));
	QWEBAPI_SET_RETURN(ret);

	return ret;

 invalid_value:
	qwebprintf(DBG_LEVEL_VERBOSE,
		   "%s(), %d, mac_string is wrong. mac = %s\n", __func__,
		   __LINE__, mac_string);
	return QWEBAPI_ERR_INVALID_VALUE;
}

char *qweb_get_wds_mode(char *path, int *perr)
{
	int i;
	int len;
	int ret;
	int mode;
	char buf[32];
	char *ifname;
	const char *mode_str[] = { "mbs", "rbs", "none" };

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);

	string_value_buf[0] = '\0';
	for (i = 0; i < QWEBAPI_MAX_WDS_LINKS; i++) {
		CALL_QCSAPI(wds_get_mode, ret, ifname, i, &mode);
		if (ret == 0) {
			snprintf(buf, 32, "WDS%d:%s ", i, mode_str[mode]);
			strncat(string_value_buf, buf, strlen(buf));
		}
	}

	len = strlen(string_value_buf);
	if (len > 0)
		string_value_buf[len - 1] = '\0';

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_WDS_rssi */
char *qweb_get_wds_rssi(char *path, int *perr)
{
	int i;
	int len;
	int ret;
	int rssi;
	char buf[32];
	char *ifname;

	string_value_buf[0] = '\0';
	for (i = 0; i < QWEBAPI_MAX_WDS_LINKS; i++) {
		ifname = qweb_get_wds_ifname_by_index(path, i);
		CALL_QCSAPI(wifi_get_rssi_in_dbm_per_association,
			    ret, ifname, 0, &rssi);
		if (ret == 0) {
			snprintf(buf, 32, "WDS%d-RSSI:%d ", i, rssi);
			strncat(string_value_buf, buf, strlen(buf));
		}
	}

	len = strlen(string_value_buf);
	if (len > 0)
		string_value_buf[len - 1] = '\0';

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211r_enable */
int qweb_set_80211r_enable(char *path, char *value)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
#ifdef TOPAZ_DBDC
	int idx;
	idx = qweb_get_key_index(path, ITEM_NAME_ACCESSPOINT);
	if (idx < QWEBAPI_MAX_BSSID + QWEBAPI_MAX_24G_BSSID
	    && idx >= QWEBAPI_MAX_BSSID) {
		char qweb_cmd[QWEBAPI_CMD_MAX_LEN];
		ret = qweb_check_if_available_24G(path, ifname);
		if (ret) {
			return ret;
		}

		snprintf(qweb_cmd, QWEBAPI_CMD_MAX_LEN, "80211r.%s",
			 ifname);

		CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG, QWEBAPI_OP_GET,
			    qweb_cmd, NULL, string_value_buf,
			    QWEBAPI_TR181_STRING_MAX_LEN);

		if (strcmp(value, string_value_buf)) {
			CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG, QWEBAPI_OP_SET,
				    qweb_cmd, value, string_value_buf,
				    QWEBAPI_TR181_STRING_MAX_LEN);

			QWEBAPI_SET_RETURN(ret);
			need_to_apply_for_24G = 1;
		}

		return ret;
	}
#endif
	CALL_QCSAPI(wifi_get_ieee80211r, ret, ifname, string_value_buf);
	if (ret) {
		/*
		 * Treat 11r as "0" if qcsapi_wifi_get_ieee80211r() return failure,
		 * because 11r is disabled by default.
		 */
		strcpy(string_value_buf, "0");
	}
	if (strcmp(string_value_buf, value) == 0)
		return QWEBAPI_OK;

	CALL_QCSAPI(wifi_set_ieee80211r,
		    ret, ifname, value);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211r_enable */
char *qweb_get_80211r_enable(char *path, int *perr)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
#ifdef TOPAZ_DBDC
	int idx;
	idx = qweb_get_key_index(path, ITEM_NAME_ACCESSPOINT);
	if (idx < QWEBAPI_MAX_BSSID + QWEBAPI_MAX_24G_BSSID
	    && idx >= QWEBAPI_MAX_BSSID) {
		char qweb_cmd[QWEBAPI_CMD_MAX_LEN];
		ret = qweb_check_if_available_24G(path, ifname);
		if (ret) {
			*perr = ret;
			return "";
		}

		snprintf(qweb_cmd, QWEBAPI_CMD_MAX_LEN, "80211r.%s",
			 ifname);

		CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG, QWEBAPI_OP_GET,
			    qweb_cmd, NULL, string_value_buf,
			    QWEBAPI_TR181_STRING_MAX_LEN);
		QWEBAPI_GET_RETURN(ret, "0");

		return string_value_buf;
	}
#endif
	strcpy(string_value_buf, "0");
	CALL_QCSAPI(wifi_get_ieee80211r,
		    ret, ifname, string_value_buf);
	/*
	 * if the parameter ieee80211r is not in hostapd config file, call_qcsapi to
	 * get 11r status was treated same as ieee80211r=0, but no filled string_value_buf
	 * which cause error contents to return, using the default value in this situation.
	 */
	strcpy(string_value_buf, ((atoi(string_value_buf) == 1) ? "1" : "0"));
	QWEBAPI_GET_RETURN(ret, "0");

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211r_mdid */
int qweb_set_80211r_mdid(char *path, char *value)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
#ifdef TOPAZ_DBDC
	int idx;
	idx = qweb_get_key_index(path, ITEM_NAME_ACCESSPOINT);
	if (idx < QWEBAPI_MAX_BSSID + QWEBAPI_MAX_24G_BSSID
	    && idx >= QWEBAPI_MAX_BSSID) {
		char qweb_cmd[QWEBAPI_CMD_MAX_LEN];
		ret = qweb_check_if_available_24G(path, ifname);
		if (ret) {
			return ret;
		}

		snprintf(qweb_cmd, QWEBAPI_CMD_MAX_LEN, "80211rmdid.%s",
			 ifname);

		CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG, QWEBAPI_OP_GET,
			    qweb_cmd, NULL, string_value_buf,
			    QWEBAPI_TR181_STRING_MAX_LEN);

		if (strcmp(value, string_value_buf)) {
			CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG, QWEBAPI_OP_SET,
				    qweb_cmd, value, string_value_buf,
				    QWEBAPI_TR181_STRING_MAX_LEN);

			QWEBAPI_SET_RETURN(ret);
			need_to_apply_for_24G = 1;
		}

		return ret;
	}
#endif

	CALL_QCSAPI(wifi_get_ieee80211r_mobility_domain, ret, ifname, string_value_buf);
	if (ret) {
		/*
		 * Treat mobility domain as "0000" if qcsapi_wifi_get_ieee80211r_mobility_domain() return failure,
		 * because mobility domain is "0000" by default.
		 */
		strcpy(string_value_buf, "0000");
	}
	if (strcmp(string_value_buf, value) == 0)
		return QWEBAPI_OK;

	CALL_QCSAPI(wifi_set_ieee80211r_mobility_domain,
		    ret, ifname, value);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211r_mdid */
char *qweb_get_80211r_mdid(char *path, int *perr)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
#ifdef TOPAZ_DBDC
	int idx;
	idx = qweb_get_key_index(path, ITEM_NAME_ACCESSPOINT);
	if (idx < QWEBAPI_MAX_BSSID + QWEBAPI_MAX_24G_BSSID
	    && idx >= QWEBAPI_MAX_BSSID) {
		char qweb_cmd[QWEBAPI_CMD_MAX_LEN];
		ret = qweb_check_if_available_24G(path, ifname);
		if (ret) {
			*perr = ret;
			return "";
		}

		snprintf(qweb_cmd, QWEBAPI_CMD_MAX_LEN, "80211rmdid.%s",
			 ifname);

		CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_CONFIG, QWEBAPI_OP_GET,
			    qweb_cmd, NULL, string_value_buf,
			    QWEBAPI_TR181_STRING_MAX_LEN);
		QWEBAPI_GET_RETURN(ret, "0000");

		return string_value_buf;
	}
#endif

	CALL_QCSAPI(wifi_get_ieee80211r_mobility_domain,
		    ret, ifname, string_value_buf);
	QWEBAPI_GET_RETURN(ret, "0000");

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.WPS.Enable */
int qweb_set_ap_wps_enable(char *path, int value)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	CALL_QCSAPI(wifi_disable_wps, ret, ifname, value ? 0 : 1);
	QWEBAPI_SET_RETURN(ret);
	return ret;
}

int qweb_get_ap_wps_enable(char *path, int *perr)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, -1);

	CALL_QCSAPI(wps_get_configured_state, ret, ifname,
		    string_value_buf, QWEBAPI_TR181_STRING_MAX_LEN);
	QWEBAPI_GET_RETURN(ret, 0);

	if (strcasecmp(string_value_buf, ITEM_NAME_CONFIGURED) == 0
	    || strcasecmp(string_value_buf, ITEM_NAME_NOT_CONFIGURED) == 0) {
		return 1;
	} else if (strcasecmp(string_value_buf, ITEM_NAME_DISABLED) == 0)
		return 0;
	else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is wrong. value = %s\n",
			   __func__, __LINE__, string_value_buf);
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		return 0;
	}
}

/* Device.WiFi.AccessPoint.{i}.WPS.ConfigMethodsSupported */
static char *qweb_get_wps_config_methods_supported(char *path, int *perr)
{
	snprintf(string_value_buf, QWEBAPI_TR181_STRING_MAX_LEN, "%s,%s",
		 ITEM_NAME_WPS_PBC, ITEM_NAME_WPS_PIN);
	return string_value_buf;
}

char *qweb_get_ap_wps_config_methods_supported(char *path, int *perr)
{
	return qweb_get_wps_config_methods_supported(path, perr);
}

/* Device.WiFi.AccessPoint.{i}.WPS.ConfigMethodsEnabled */
static int qweb_set_wps_config_methods_enabled(char *path, char *value,
					       char *array)
{
	int ret;
	int len;
	char *ifname;
	char config_methods[128] = { 0x00 };

	ifname = qweb_get_wifi_ifname(path, array);
	if (strstr(value, ITEM_NAME_WPS_PBC)) {
		snprintf(config_methods, 127, "%s,%s,%s,",
			 ITEM_NAME_WPS_CONFIG_VALUE_PBC,
			 ITEM_NAME_WPS_CONFIG_VALUE_V_PBC,
			 ITEM_NAME_WPS_CONFIG_VALUE_P_PBC);
	}

	len = strlen(config_methods);
	if (strstr(value, ITEM_NAME_WPS_PIN)) {
		snprintf(&config_methods[len], 127, "%s,%s,%s,%s,",
			 ITEM_NAME_WPS_CONFIG_VALUE_LABEL,
			 ITEM_NAME_WPS_CONFIG_VALUE_DISPLAY,
			 ITEM_NAME_WPS_CONFIG_VALUE_V_DISPLAY,
			 ITEM_NAME_WPS_CONFIG_VALUE_KEYPAD);
	}

	len = strlen(config_methods);
	if (len > 0)
		config_methods[len - 1] = '\0';
	else
		return QWEBAPI_ERR_INVALID_VALUE;

	CALL_QCSAPI(wps_set_param, ret, ifname,
		    qcsapi_wps_config_methods, config_methods);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

int qweb_set_ap_wps_config_methods_enabled(char *path, char *value)
{
	return qweb_set_wps_config_methods_enabled(path, value,
						   ITEM_NAME_ACCESSPOINT);
}

static char *qweb_get_wps_config_methods_enabled(char *path, int *perr,
						 char *array)
{
	int ret;
	int len;
	char *ifname;
	char config_methods[128];

	ifname = qweb_get_wifi_ifname(path, array);
	CALL_QCSAPI(wps_get_param, ret, ifname,
		    qcsapi_wps_config_methods, config_methods, 128);
	QWEBAPI_GET_RETURN(ret, "");

	if (strstr(config_methods, "FAIL")) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, get config_methods, return FAIL.\n",
			   __func__, __LINE__);
		return "";
	}

	string_value_buf[0] = '\0';
	if (strstr(config_methods, ITEM_NAME_WPS_CONFIG_VALUE_PBC)
	    || strstr(config_methods, ITEM_NAME_WPS_CONFIG_VALUE_V_PBC)
	    || strstr(config_methods, ITEM_NAME_WPS_CONFIG_VALUE_P_PBC)) {
		strcat(string_value_buf, ITEM_NAME_WPS_PBC);
		strcat(string_value_buf, QWEBAPI_COMMA);
	}

	if (strstr(config_methods, ITEM_NAME_WPS_CONFIG_VALUE_LABEL)
	    || strstr(config_methods, ITEM_NAME_WPS_CONFIG_VALUE_DISPLAY)
	    || strstr(config_methods, ITEM_NAME_WPS_CONFIG_VALUE_V_DISPLAY)
	    || strstr(config_methods, ITEM_NAME_WPS_CONFIG_VALUE_KEYPAD)) {
		strcat(string_value_buf, ITEM_NAME_WPS_PIN);
		strcat(string_value_buf, QWEBAPI_COMMA);
	}

	len = strlen(string_value_buf);
	if (len > 0)
		string_value_buf[len - 1] = '\0';
	else
		goto fail;

	return string_value_buf;
 fail:
	*perr = QWEBAPI_ERR_NOT_AVALIABLE;
	return "";
}

char *qweb_get_ap_wps_config_methods_enabled(char *path, int *perr)
{
	return qweb_get_wps_config_methods_enabled(path, perr,
						   ITEM_NAME_ACCESSPOINT);
}

/* Device.WiFi.AccessPoint.{i}.WPS.X_QUANTENNA_COM_WPS_Runtime_State */
char *qweb_get_wps_runtime_state(char *path, int *perr)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");

	CALL_QCSAPI(wps_get_runtime_state, ret, ifname, string_value_buf, 64);
	QWEBAPI_GET_RETURN(ret, "");

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.WPS.X_QUANTENNA_COM_AP_PIN */
QWEBAPI_WPS_SET_STRING_FUNC(wps_ap_pin, ap_pin, ITEM_NAME_ACCESSPOINT);
char *qweb_get_wps_ap_pin(char *path, int *perr)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");

	CALL_QCSAPI(wps_get_ap_pin, ret, ifname, string_value_buf, 0);
	QWEBAPI_GET_RETURN(ret, "");

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.WPS.X_QUANTENNA_COM_Regenerate_PIN */
char *qweb_get_wps_regenerate_pin(char *path, int *perr)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");

	CALL_QCSAPI(wps_get_ap_pin, ret, ifname, string_value_buf, 1);
	QWEBAPI_GET_RETURN(ret, "");

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.WPS.X_QUANTENNA_COM_State */
char *qweb_get_wps_state(char *path, int *perr)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");

	CALL_QCSAPI(wps_get_state, ret, ifname, string_value_buf, 64);
	QWEBAPI_GET_RETURN(ret, "");

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.WPS.X_QUANTENNA_COM_Configured_State */
int qweb_set_wps_configured_state(char *path, char *value)
{
	int ret;
	char *ifname;
	int configured_state;

	if (strcasecmp(value, ITEM_NAME_DISABLED) == 0) {
		configured_state = 0;
	} else if (strcasecmp(value, ITEM_NAME_NOT_CONFIGURED) == 0) {
		configured_state = 1;
	} else if (strcasecmp(value, ITEM_NAME_CONFIGURED) == 0) {
		configured_state = 2;
	} else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is wrong. value = %s\n",
			   __func__, __LINE__, value);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	CALL_QCSAPI(wps_set_configured_state, ret, ifname, configured_state);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

char *qweb_get_wps_configured_state(char *path, int *perr)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");

	CALL_QCSAPI(wps_get_configured_state, ret, ifname, string_value_buf,
		    64);
	QWEBAPI_GET_RETURN(ret, "");

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.WPS.X_QUANTENNA_COM_REG_report_button_press */
int qweb_set_wps_registrar_report_button_press(char *path, char *value)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, -1);

	CALL_QCSAPI(wps_registrar_report_button_press, ret, ifname);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

char *qweb_get_wps_registrar_report_button_press(char *path, int *perr)
{
	/* always return null string */
	return "";
}

/* Device.WiFi.AccessPoint.{i}.WPS.X_QUANTENNA_COM_REG_report_pin */
int qweb_set_wps_registrar_report_pin(char *path, char *value)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, -1);

	CALL_QCSAPI(wps_registrar_report_pin, ret, ifname, value);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

char *qweb_get_wps_registrar_report_pin(char *path, int *perr)
{
	/* always return null string */
	return "";
}

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice */
int qweb_get_associated_device_num(char *path)
{
	int ret;
	char *ifname;
	unsigned int cnt;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	CALL_QCSAPI(wifi_get_count_associations, ret, ifname, &cnt);
	if (ret)
		return 0;
	return cnt;
}

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.OperatingStandard */
QWEBAPI_GET_STRING_FUNC_WITH_NOT_SUPPORT(assoc_device_operating_standard);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.MACAddress */
char *qweb_get_assoc_device_mac_addr(char *path, int *perr)
{
	int ret;
	char *ifname;
	int device_index = 0;
	qcsapi_wifi_mode mode;
	qcsapi_mac_addr mac_addr;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	CALL_QCSAPI(wifi_get_mode, ret, ifname, &mode);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");

	device_index = qweb_get_key_index(path, ITEM_NAME_ASSOCIATED_DEVICE);
	CALL_QCSAPI(wifi_get_associated_device_mac_addr, ret, ifname,
		    device_index, mac_addr);
	if (ret) {
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
	}

	qweb_dump_mac_addr(mac_addr, string_value_buf);
	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.AuthenticationState */
char *qweb_get_assoc_device_auth_state(char *path, int *perr)
{
	int i;
	int len;
	int ret;
	char *ifname;
	unsigned int cnt;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_access_point, "");

	CALL_QCSAPI(wifi_get_count_associations, ret, ifname, &cnt);
	if (ret) {
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
		return "";
	}

	string_value_buf[0] = '\0';
	for (i = 0; i < cnt; i++) {
		qcsapi_mac_addr mac_addr;
		char mac_str[QWEBAPI_MAC_ADDR_STR_LEN + 1];

		CALL_QCSAPI(wifi_get_associated_device_mac_addr, ret, ifname, i,
			    mac_addr);
		if (ret) {
			*perr = QWEBAPI_ERR_NOT_AVALIABLE;
			return "";
		}

		qweb_dump_mac_addr(mac_addr, mac_str);
		strncat(string_value_buf, mac_str, QWEBAPI_MAC_ADDR_STR_LEN);
		strncat(string_value_buf, QWEBAPI_SPACE, strlen(QWEBAPI_SPACE));
	}

	len = strlen(string_value_buf);
	if (len > 0)
		string_value_buf[len - 1] = '\0';

	return string_value_buf;
}

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.LastDataDownlinkRate */
unsigned int qweb_get_assoc_device_tx_phy_rate(char *path, int *perr)
{
	int ret;
	char *ifname;
	unsigned int rate;
	int device_index = 0;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	device_index = qweb_get_key_index(path, ITEM_NAME_ASSOCIATED_DEVICE);
	CALL_QCSAPI(wifi_get_tx_phy_rate_per_association, ret, ifname,
		    device_index, &rate);
	if (ret) {
		qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, call qcsapi error.\n",
			   __func__, __LINE__);
		return 0;
	}

	/* unit:kbps in TR181, Mbps in qcsapi */
	return rate * 1024;
}

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.LastDataUplinkRate */
unsigned int qweb_get_assoc_device_rx_phy_rate(char *path, int *perr)
{
	int ret;
	char *ifname;
	unsigned int rate;
	int device_index = 0;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	device_index = qweb_get_key_index(path, ITEM_NAME_ASSOCIATED_DEVICE);
	CALL_QCSAPI(wifi_get_rx_phy_rate_per_association, ret, ifname,
		    device_index, &rate);
	if (ret) {
		qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, call qcsapi error.\n",
			   __func__, __LINE__);
		return 0;
	}

	/* unit:kbps in TR181, Mbps in qcsapi */
	return rate * 1024;
}

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.SignalStrength */
int qweb_get_rssi_in_dbm_per_association(char *path, int *perr)
{
	int ret;
	char *ifname;
	int device_index = 0;
	int rssi;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ACCESSPOINT);
	device_index = qweb_get_key_index(path, ITEM_NAME_ASSOCIATED_DEVICE);
	CALL_QCSAPI(wifi_get_rssi_in_dbm_per_association, ret, ifname,
		    device_index, &rssi);
	if (ret) {
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
	}

	return rssi;
}

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Retransmissions */
QWEBAPI_GET_UINT_FUNC_WITH_NOT_SUPPORT(assoc_device_retransmissions);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Active */
QWEBAPI_GET_UINT_FUNC_WITH_NOT_SUPPORT(assoc_device_active);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.BytesSent */
QWEBAPI_GET_UINT64_COUNTER_PER_ASSOC_FUNC(bytes_sent, tx_bytes);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.BytesReceived */
QWEBAPI_GET_UINT64_COUNTER_PER_ASSOC_FUNC(bytes_received, rx_bytes);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.PacketsSent */
QWEBAPI_GET_UINT_COUNTER_PER_ASSOC_FUNC(packets_sent, tx_packets);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.PacketsReceived */
QWEBAPI_GET_UINT_COUNTER_PER_ASSOC_FUNC(packets_received, rx_packets);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.ErrorsSent */
QWEBAPI_GET_UINT_COUNTER_PER_ASSOC_FUNC(errors_sent, tx_err_packets);

/* Device.WiFi.Radio.{i}.Stats.BytesSent */
QWEBAPI_GET_INTERFACE_COUNTER64(interface_bytes_sent, qcsapi_total_bytes_sent);

/* Device.WiFi.Radio.{i}.Stats.BytesReceived */
QWEBAPI_GET_INTERFACE_COUNTER64(interface_bytes_received,
				qcsapi_total_bytes_received);

/* Device.WiFi.Radio.{i}.Stats.PacketsSent */
QWEBAPI_GET_INTERFACE_COUNTER64(interface_packets_sent,
				qcsapi_total_packets_sent);

/* Device.WiFi.Radio.{i}.Stats.PacketsReceived */
QWEBAPI_GET_INTERFACE_COUNTER64(interface_packets_received,
				qcsapi_total_packets_received);

/* Device.WiFi.Radio.{i}.Stats.ErrorsSent */
QWEBAPI_GET_INTERFACE_COUNTER64(interface_errors_sent,
				qcsapi_error_packets_sent);

/* Device.WiFi.Radio.{i}.Stats.ErrorsReceived */
QWEBAPI_GET_INTERFACE_COUNTER64(interface_errors_received,
				qcsapi_error_packets_received);

/* Device.WiFi.Radio.{i}.Stats.DiscardPacketsSent */
QWEBAPI_GET_INTERFACE_COUNTER64(interface_discard_packets_sent,
				qcsapi_discard_packets_sent);

/* Device.WiFi.Radio.{i}.Stats.DiscardPacketsReceived */
QWEBAPI_GET_INTERFACE_COUNTER64(interface_discard_packets_received,
				qcsapi_discard_packets_received);

/* Device.WiFi.Radio.{i}.Noise */
QWEBAPI_WIFI_GET_INT_FUNC(noise, noise, ITEM_NAME_RADIO);

/* Device.WiFi.SSID.{i}.Stats.BytesSent */
QWEBAPI_GET_INTERFACE_STATS(interface_stats_bytes_sent, tx_bytes);

/* Device.WiFi.SSID.{i}.Stats.BytesReceived */
QWEBAPI_GET_INTERFACE_STATS(interface_stats_bytes_received, rx_bytes);

/* Device.WiFi.SSID.{i}.Stats.PacketsSent */
QWEBAPI_GET_INTERFACE_STATS(interface_stats_packets_sent, tx_pkts);

/* Device.WiFi.SSID.{i}.Stats.PacketsReceived */
QWEBAPI_GET_INTERFACE_STATS(interface_stats_packets_received, rx_pkts);

/* Device.WiFi.SSID.{i}.Stats.ErrorsSent */
QWEBAPI_GET_INTERFACE_STATS(interface_stats_errors_sent, tx_err);

/* Device.WiFi.SSID.{i}.Stats.ErrorsReceived */
QWEBAPI_GET_INTERFACE_STATS(interface_stats_errors_received, rx_err);

/* Device.WiFi.SSID.{i}.Stats.UnicastPacketsSent */
QWEBAPI_GET_INTERFACE_STATS(interface_stats_unicast_pkts_tx, tx_unicast);

/* Device.WiFi.SSID.{i}.Stats.UnicastPacketsReceived */
QWEBAPI_GET_INTERFACE_STATS(interface_stats_unicast_pkts_rx, rx_unicast);

/* Device.WiFi.SSID.{i}.Stats.DiscardPacketsSent */
QWEBAPI_GET_INTERFACE_STATS(interface_stats_discard_pkts_tx, tx_discard);

/* Device.WiFi.SSID.{i}.Stats.DiscardPacketsReceived */
QWEBAPI_GET_INTERFACE_STATS(interface_stats_discard_pkts_rx, rx_discard);

/* Device.WiFi.SSID.{i}.Stats.MulticastPacketsSent */
QWEBAPI_GET_INTERFACE_STATS(interface_stats_multicast_pkts_tx, tx_multicast);

/* Device.WiFi.SSID.{i}.Stats.MulticastPacketsReceived */
QWEBAPI_GET_INTERFACE_STATS(interface_stats_multicast_pkts_rx, rx_multicast);

/* Device.WiFi.SSID.{i}.Stats.BroadcastPacketsSent */
QWEBAPI_GET_INTERFACE_STATS(interface_stats_broadcast_pkts_tx, tx_broadcast);

/* Device.WiFi.SSID.{i}.Stats.BroadcastPacketsReceived */
QWEBAPI_GET_INTERFACE_STATS(interface_stats_broadcast_pkts_rx, rx_broadcast);

/* Device.WiFi.SSID.{i}.Stats.UnknownProtoPacketsReceived */
QWEBAPI_GET_INTERFACE_STATS(interface_stats_unknown_pkts_rx, rx_unknown);

/* Device.DHCPv4 */
int qweb_get_dhcpv4_client_num(char *path)
{
	return QWEBAPI_DHCPV4_CLIENT_COUNT;
}

static char *qweb_get_dhcpv4_ip_info(char *path, int *perr, const char *type)
{
	int i;
	int ret;
	char *ifname[] = { "br0", "eth1_0", "eth1_1" };

	i = qweb_get_key_index(path, ITEM_NAME_CLIENT);
	CALL_QCSAPI(interface_get_ip4, ret, ifname[i], type, string_value_buf);
	QWEBAPI_GET_RETURN(ret, "");

	return string_value_buf;
}

/* Device.DHCPv4..Client.{i}.Enable */
int qweb_set_dhcpv4_enable(char *path, unsigned int value)
{
	int ret;
	char buf[4];
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_CLIENT);

	snprintf(buf, 4, "%d", value);
	CALL_QCSAPI(config_update_parameter, ret, ifname,
		    ITEM_VALUE_STATIC_IP, buf);

	QWEBAPI_SET_RETURN(ret);
	return ret;
}

unsigned int qweb_get_dhcpv4_enable(char *path, int *perr)
{
	int ret;
	char buf[4];
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_CLIENT);
	CALL_QCSAPI(config_get_parameter, ret, ifname,
		    ITEM_VALUE_STATIC_IP, buf, 4);

	QWEBAPI_GET_RETURN(ret, 0);
	return atoi(buf);
}

/* Device.DHCPv4.Client.{i}.IPAddress */
char *qweb_get_dhcpv4_ip(char *path, int *perr)
{
	return qweb_get_dhcpv4_ip_info(path, perr, ITEM_VALUE_IPADDR);
}

/* Device.DHCPv4.Client.{i}.SubnetMask */
char *qweb_get_dhcpv4_netmask(char *path, int *perr)
{
	return qweb_get_dhcpv4_ip_info(path, perr, ITEM_VALUE_NETMASK);
}

/* Device.Ethernet */
int qweb_get_interface_num(char *path)
{
	return QWEBAPI_ETH_INTERFACE_COUNT;
}

/* Device.Ethernet.Interface.{i}.MACAddress */
char *qweb_get_ethernet_mac(char *path, int *perr)
{
	int ret;
	char *ifname;
	qcsapi_mac_addr mac_addr;

	ifname = qweb_get_ethernet_ifname(path, ITEM_NAME_INTERFACE);
	CALL_QCSAPI(interface_get_mac_addr, ret, ifname, mac_addr);
	QWEBAPI_GET_RETURN(ret, "");

	qweb_dump_mac_addr(mac_addr, string_value_buf);
	return string_value_buf;
}

/* Device.WiFi.EndPoint */
int qweb_get_sta_max_num(char *path)
{
#ifdef PEARL_PLATFORM
	return 3;
#else
	return 1;
#endif
}

int qweb_endpoint_exist(char *path)
{
	int ret;
	char *ifname;
	char ssid_str[QWEBAPI_SSID_MAX_LEN + 1];

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);
	CALL_QCSAPI(wifi_get_SSID, ret, ifname, ssid_str);

	return (ret) ? 0 : 1;
}

/**
 * * \brief add Object of EndpOint
 * *
 * *	param: value is SSID as a string.
 * *
 * */
int qweb_add_endpoint_profile_entry(char *path, char *value)
{
	int ret;
	char *ssid;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);

	//get ssid
	ssid = value;

	CALL_QCSAPI(SSID_create_SSID, ret, ifname, ssid);
	if (ret == -1031) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, ret = %d, ret is wrong. Invalid BSS name",
			   __func__, __LINE__, ret);
		return QWEBAPI_ERR_NOT_AVALIABLE;
	}

	QWEBAPI_SET_RETURN(ret);
	return ret;
}

int qweb_del_endpoint_profile_entry(char *path)
{
	int ret;
	int perr;
	char *ifname;
	char *curr_ssid;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);

	perr = QWEBAPI_OK;
	curr_ssid = qweb_get_endpoint_profile_curr_ssid(path, &perr);
	CALL_QCSAPI(SSID_remove_SSID, ret, ifname, curr_ssid);
	if (ret == -1030) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, ret = %d, Operation is not available on the primary interface",
			   __func__, __LINE__, ret);
		return QWEBAPI_ERR_NOT_AVALIABLE;
	} else if (ret == -1031) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, ret = %d, ret is wrong. Invalid BSS name",
			   __func__, __LINE__, ret);
		return QWEBAPI_ERR_NOT_AVALIABLE;
	}

	QWEBAPI_SET_RETURN(ret);
	return ret;

}

/* Device.WiFi.EndPoint.{i}.Enable */
int qweb_set_endpoint_enable(char *path, unsigned int value)
{
	return qweb_set_interface_enable(path, ITEM_NAME_ENDPOINT, value);
}

unsigned int qweb_get_endpoint_enable(char *path, int *perr)
{
	return qweb_get_interface_enable(path, ITEM_NAME_ENDPOINT, perr);
}

/* Device.WiFi.EndPoint.{i}.Status */
char *qweb_get_endpoint_status(char *path, int *perr)
{
	return qweb_get_interface_status(path, ITEM_NAME_ENDPOINT, perr);
}

/* Device.WiFi.EndPoint.{i}.Alias */
QWEBAPI_SET_STRING_FUNC_WITH_NOT_SUPPORT(endpoint_alias);
QWEBAPI_GET_STRING_FUNC_WITH_NOT_SUPPORT(endpoint_alias);

/* Device.WiFi.Endpoint.{i}.ProfileReference */
static int qweb_get_endpoint_active_profile(char *path, char *connected_ssid)
{

	int iter;
	int ssid_cnt = 0;
	char *list_ssids[QWEBAPI_DEFAULT_SSID_LIST_SIZE + 1];
	for (iter = 0; iter < QWEBAPI_DEFAULT_SSID_LIST_SIZE; iter++) {
		list_ssids[iter] = array_ssids[iter];
		*(list_ssids[iter]) = '\0';
	}

	if ((list_ssids[0] == NULL) || strlen(list_ssids[0]) < 1) {
		ssid_cnt = qweb_get_endpoint_ssid_list(path, &list_ssids[0]);
	}

	for (iter = 0; iter < ssid_cnt; iter++) {
		if (strcmp(list_ssids[iter], connected_ssid) == 0) {
			return iter;
		}
	}

	return -1;
}

int qweb_set_endpoint_profile_reference(char *path, char *value)
{
	int ret;
	char *ifname;
	char *curr_ssid;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);

	curr_ssid = qweb_get_endpoint_ssid_by_index(path, atoi(value));

	ret = qweb_connect_ap(ifname, curr_ssid);

	return ret;
}

char *qweb_get_endpoint_profile_reference(char *path, int *perr)
{
	int ret;
	int iter;
	char *ifname;
	qcsapi_SSID connected_ssid = { 0x00 };

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);

	//get connected SSID
	CALL_QCSAPI(wifi_get_SSID, ret, ifname, connected_ssid);
	if (ret || strlen(connected_ssid) <= 0) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, get_ssid failed, ret = %d\n",
			   __func__, __LINE__, ret);
		return "";
	}

	iter = qweb_get_endpoint_active_profile(path, connected_ssid);
	if (iter < 0) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, get_ssid failed, ret = %d\n",
			   __func__, __LINE__, ret);
		return "";
	}

	sprintf(string_value_buf, "%d", iter);

	return string_value_buf;
}

/* Device.WiFi.Endpoint.{i}.SSIDReference */
QWEBAPI_WIFI_GET_STRING_FUNC(endpoint_ssid_reference, SSID, ITEM_NAME_ENDPOINT);

/* Device.WiFi.EndPoint.{i}.ProfileNumberOfEntries */
static int qweb_get_endpoint_ssid_list(char *path, char **list_ssid)
{
	int ret;
	int iter;
	int list_cnt;
	int ssid_cnt;
	char *ifname;
	char *list_ssids[QWEBAPI_DEFAULT_SSID_LIST_SIZE + 1];

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);

	ssid_cnt = 0;
	list_cnt = QWEBAPI_DEFAULT_SSID_LIST_SIZE;
	for (iter = 0; iter < list_cnt; iter++) {
		list_ssids[iter] = array_ssids[iter];
		*(list_ssids[iter]) = '\0';
	}

	CALL_QCSAPI(SSID_get_SSID_list, ret, ifname, list_cnt, &list_ssids[0]);
	if (ret)
		return ret;

	for (iter = 0; iter < list_cnt; iter++) {
		if ((list_ssids[iter] == NULL) || strlen(list_ssids[iter]) < 1) {
			break;
		}
		ssid_cnt++;
	}
	return ssid_cnt;
}

static unsigned int qweb_get_endpoint_profile_count(char *path)
{
	int iter;
	int ssid_cnt;
	char *list_ssids[QWEBAPI_DEFAULT_SSID_LIST_SIZE + 1];

	for (iter = 0; iter < QWEBAPI_DEFAULT_SSID_LIST_SIZE; iter++) {
		list_ssids[iter] = array_ssids[iter];
		*(list_ssids[iter]) = '\0';
	}

	if ((list_ssids[0] == NULL) || strlen(list_ssids[0]) < 1) {
		return qweb_get_endpoint_ssid_list(path, &list_ssids[0]);
	}

	ssid_cnt = 0;
	for (iter = 0; iter < QWEBAPI_DEFAULT_SSID_LIST_SIZE; iter++) {
		if ((list_ssids[iter] == NULL) || strlen(list_ssids[iter]) < 1) {
			break;
		}
		ssid_cnt++;
	}
	return ssid_cnt;
}

unsigned int qweb_get_endpoint_profile_num(char *path, int *perr)
{
	return qweb_get_endpoint_profile_count(path);
}

/* Device.WiFi.EndPointi.{i}.Stats */
/* Device.WiFi.EndPointi.{i}.Stats.LastDataDownlinkRate */
unsigned int qweb_get_endpoint_rx_phy_rate(char *path, int *perr)
{
	int ret;
	char *ifname;
	unsigned int rate;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);
	CALL_QCSAPI(wifi_get_rx_phy_rate_per_association, ret, ifname, 0,
		    &rate);
	QWEBAPI_GET_RETURN(ret, 0);

	/* unit:kbps in TR181, Mbps in qcsapi */
	return rate * 1024;
}

/* Device.WiFi.EndPointi.{i}.Stats.LastDataUplinkRate */
unsigned int qweb_get_endpoint_tx_phy_rate(char *path, int *perr)
{
	int ret;
	char *ifname;
	unsigned int rate;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);
	CALL_QCSAPI(wifi_get_tx_phy_rate_per_association, ret, ifname, 0,
		    &rate);
	QWEBAPI_GET_RETURN(ret, 0);

	/* unit:kbps in TR181, Mbps in qcsapi */
	return rate * 1024;
}

/* Device.WiFi.EndPointi.{i}.Stats.SignalStrength */
int qweb_get_endpoint_rssi(char *path, int *perr)
{
	int ret;
	int rssi;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);
	CALL_QCSAPI(wifi_get_rssi_in_dbm_per_association, ret, ifname, 0,
		    &rssi);
	QWEBAPI_GET_RETURN(ret, 0);

	return rssi;
}

/* Device.WiFi.EndPointi.{i}.Stats.Retransmissions */
QWEBAPI_GET_UINT_FUNC_WITH_NOT_SUPPORT(endpoint_retransmissions);

/* Device.WiFi.EndPoint.{i}.Security.ModesSupported */
char *qweb_get_endpoint_mode_supported(char *path, int *perr)
{
	int ret;
	int len;
	char *ifname;
	int pmf_value;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_station, "");
	CALL_QCSAPI(wifi_get_pmf, ret, ifname, &pmf_value);

	string_value_buf[0] = '\0';
	if (pmf_value != qcsapi_pmf_disabled) {
		/* NONE-OPEN */
		strcat(string_value_buf, ITEM_NAME_MODE_NONE);
		strcat(string_value_buf, QWEBAPI_COMMA);

		/* WPA2-AES-SHA256 */
		strcat(string_value_buf, ITEM_NAME_MODE_WPA2_AES_SHA256);
		strcat(string_value_buf, QWEBAPI_COMMA);
	} else {
		/* NONE-OPEN */
		strcat(string_value_buf, ITEM_NAME_MODE_NONE);
		strcat(string_value_buf, QWEBAPI_COMMA);

		/* WPA2-AES */
		strcat(string_value_buf, ITEM_NAME_MODE_WPA2_AES);
		strcat(string_value_buf, QWEBAPI_COMMA);

		/* WPA2 + WPA (mixed mode) */
		strcat(string_value_buf, ITEM_NAME_MODE_WPA2_WPA);
		strcat(string_value_buf, QWEBAPI_COMMA);
	}

	len = strlen(string_value_buf);
	if (len > 0)
		string_value_buf[len - 1] = '\0';

	return string_value_buf;
}

/* Device.WiFi.EndPoint.{i}.Profile.{i} */
int qweb_get_profile_num(char *path)
{
	return qweb_get_endpoint_profile_count(path);
}

static char *qweb_get_endpoint_profile_curr_ssid(char *path, int *perr)
{
	int index;
	char *curr_ssid;

	index = qweb_get_key_index(path, ITEM_NAME_ENDPOINT_PROFILE);
	if (index < 0) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, index < 0, index = %d\n",
			   __func__, __LINE__, index);
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
	}

	curr_ssid = qweb_get_endpoint_ssid_by_index(path, index);
	if (strlen(curr_ssid) <= 0) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, curr_ssid's len < 0, curr_ssid = %s\n",
			   __func__, __LINE__, curr_ssid);
		*perr = QWEBAPI_ERR_NOT_AVALIABLE;
	}

	return curr_ssid;
}

/* Device.WiFi.EndPoint.{i}.Profile.{i}.Enable */
static int qweb_connect_ap(char *ifname, char *curr_ssid)
{
	int ret;
	char auth_mode[32];
	qcsapi_SSID connected_ssid;

	//get connected SSID
	CALL_QCSAPI(wifi_get_SSID, ret, ifname, connected_ssid);

	if (strcmp(curr_ssid, connected_ssid) == 0) {
		//connect to the same AP, then keep the current state and do noting.
		return QWEBAPI_OK;
	}

	CALL_QCSAPI(SSID_get_authentication_mode, ret, ifname, curr_ssid,
		    auth_mode);
	if (ret) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, ret < 0, ret = %d\n", __func__,
			   __LINE__, ret);
		return QWEBAPI_ERR_NOT_AVALIABLE;
	}

	if (strcmp(auth_mode, ITEM_NAME_AUTH_PROTO_NONE) == 0) {
		CALL_QCSAPI(SSID_set_authentication_mode, ret, ifname,
			    curr_ssid, ITEM_NAME_AUTH_PROTO_NONE);
	} else {
		char psk[64 + 1];
		char protocol[16 + 1];
		char encryption[32 + 1];

		CALL_QCSAPI(SSID_set_authentication_mode, ret, ifname,
			    curr_ssid, auth_mode);
		if (ret)
			goto qcsapi_failed;

		//set protocol
		CALL_QCSAPI(SSID_get_protocol, ret, ifname, curr_ssid,
			    protocol);
		if (ret)
			goto qcsapi_failed;
		CALL_QCSAPI(SSID_set_protocol, ret, ifname, curr_ssid,
			    protocol);
		if (ret)
			goto qcsapi_failed;

		//set encryption
		CALL_QCSAPI(SSID_get_encryption_modes, ret, ifname, curr_ssid,
			    encryption);
		if (ret)
			goto qcsapi_failed;
		CALL_QCSAPI(SSID_set_encryption_modes, ret, ifname, curr_ssid,
			    encryption);
		if (ret)
			goto qcsapi_failed;

		//set psk
		CALL_QCSAPI(SSID_get_key_passphrase, ret, ifname, curr_ssid, 0,
			    psk);
		if (ret)
			goto qcsapi_failed;
		if (strlen(psk) > 0) {
			CALL_QCSAPI(SSID_set_key_passphrase, ret, ifname,
				    curr_ssid, 0, psk);
			if (ret)
				goto qcsapi_failed;
		} else {
			CALL_QCSAPI(SSID_get_pre_shared_key, ret, ifname,
				    curr_ssid, 0, psk);
			if (ret)
				goto qcsapi_failed;

			if (strlen(psk) > 0) {
				CALL_QCSAPI(SSID_set_pre_shared_key, ret,
					    ifname, curr_ssid, 0, psk);
				if (ret)
					goto qcsapi_failed;
			}
		}
	}

	// associate
	CALL_QCSAPI(wifi_associate, ret, ifname, curr_ssid);
	if (ret)
		goto qcsapi_failed;

	return QWEBAPI_OK;

 qcsapi_failed:
	qwebprintf(DBG_LEVEL_VERBOSE,
		   "%s(), %d, call qcsapi error.\n", __func__, __LINE__);
	return QWEBAPI_ERR_NOT_AVALIABLE;
}

static int qweb_disconnect_ap(char *ifname)
{
	int ret;
	CALL_QCSAPI(wifi_disassociate, ret, ifname);

	return ret;
}

int qweb_set_endpoint_profile_enable(char *path, unsigned int value)
{
	int ret;
	char *ifname;
	qcsapi_SSID SSID_str = { 0x00 };

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);
	if (value == 0) {
		CALL_QCSAPI(wifi_get_SSID, ret, ifname, SSID_str);
		if (ret)
			goto qcsapi_failed;

		if (strlen(SSID_str) > 0) {
			ret = qweb_disconnect_ap(ifname);
			if (ret)
				goto qcsapi_failed;
			return QWEBAPI_OK;
		} else
			return QWEBAPI_OK;

	} else if (value == 1) {
		int perr;
		char *curr_ssid;

		perr = QWEBAPI_OK;
		curr_ssid = qweb_get_endpoint_profile_curr_ssid(path, &perr);
		ret = qweb_connect_ap(ifname, curr_ssid);
	} else {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is wrong. value = %d\n",
			   __func__, __LINE__, value);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	return ret;
 qcsapi_failed:
	qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, value is wrong. value = %d\n",
		   __func__, __LINE__, value);
	return QWEBAPI_ERR_INVALID_VALUE;

}

unsigned int qweb_get_endpoint_profile_enable(char *path, int *perr)
{
	int ret;
	char *ifname;
	char *curr_ssid;
	qcsapi_SSID SSID_str;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);

	CALL_QCSAPI(wifi_get_SSID, ret, ifname, SSID_str);
	QWEBAPI_GET_RETURN(ret, 0);

	curr_ssid = qweb_get_endpoint_profile_curr_ssid(path, perr);

	if (strcmp(SSID_str, curr_ssid) == 0) {
		return 1;
	} else {
		return 0;
	}
}

/* Device.WiFi.EndPoint.{i}.Profile.{i}.Status */
char *qweb_get_endpoint_profile_status(char *path, int *perr)
{
	int ret;
	char *ifname;
	char *curr_ssid;
	qcsapi_SSID SSID_str;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);

	CALL_QCSAPI(wifi_get_SSID, ret, ifname, SSID_str);
	QWEBAPI_GET_RETURN(ret, "");

	curr_ssid = qweb_get_endpoint_profile_curr_ssid(path, perr);

	if (strcmp(SSID_str, curr_ssid) == 0) {
		return ITEM_NAME_ACTIVE;
	} else {
		return ITEM_NAME_AVAILABLE;
	}
}

/* Device.WiFi.EndPoint.{i}.Profile.{i}.Alias */
QWEBAPI_SET_STRING_FUNC_WITH_NOT_SUPPORT(endpoint_profile_alias);
QWEBAPI_GET_STRING_FUNC_WITH_NOT_SUPPORT(endpoint_profile_alias);

/* Device.WiFi.EndPoint.{i}.Profile.{i}.SSID */
int qweb_set_endpoint_profile_ssid(char *path, char *value)
{
	int ret;
	int perr;
	char *ifname;
	char *new_ssid;
	char *curr_ssid;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_station, 0);

	perr = QWEBAPI_OK;
	curr_ssid = qweb_get_endpoint_profile_curr_ssid(path, &perr);

	/* must init ret as 0 */
	ret = 0;
	new_ssid = value;
	if (strcmp(curr_ssid, new_ssid)) {
		CALL_QCSAPI(SSID_rename_SSID, ret, ifname, curr_ssid, new_ssid);
		QWEBAPI_SET_RETURN(ret);
	}

	return ret;

}

char *qweb_get_endpoint_profile_ssid(char *path, int *perr)
{
	int ret;
	char *ifname;
	char *curr_ssid;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_station, 0);

	curr_ssid = qweb_get_endpoint_profile_curr_ssid(path, perr);

	return curr_ssid;
}

/* Device.WiFi.EndPoint.{i}.Profile.{i}.Location */
QWEBAPI_SET_STRING_FUNC_WITH_NOT_SUPPORT(endpoint_profile_location);
QWEBAPI_GET_STRING_FUNC_WITH_NOT_SUPPORT(endpoint_profile_location);

/* Device.WiFi.EndPoint.{i}.Profile.{i}.Priority */
QWEBAPI_SET_UINT_FUNC_WITH_NOT_SUPPORT(endpoint_priority);
QWEBAPI_GET_UINT_FUNC_WITH_NOT_SUPPORT(endpoint_priority);

/* Device.WiFi.EndPoint.{i}.Profile.{i}.Security */
/* Device.WiFi.EndPoint.{i}.Profile.{i}.Security.ModeEnabled */
static char *qweb_get_endpoint_ssid_by_index(char *path, int index)
{
	int iter;
	int ssid_cnt = 0;
	char *list_ssids[QWEBAPI_DEFAULT_SSID_LIST_SIZE + 1];

	for (iter = 0; iter < QWEBAPI_DEFAULT_SSID_LIST_SIZE; iter++) {
		list_ssids[iter] = array_ssids[iter];
		*(list_ssids[iter]) = '\0';
	}

	if ((list_ssids[0] == NULL) || strlen(list_ssids[0]) < 1) {
		ssid_cnt = qweb_get_endpoint_ssid_list(path, &list_ssids[0]);
	}

	for (iter = 0; iter < ssid_cnt; iter++) {
		if (iter == index) {
			if ((list_ssids[iter] == NULL)
			    || strlen(list_ssids[iter]) < 1) {
				return "";
			} else {
				return list_ssids[iter];
			}
			break;
		}
	}
	return "";
}

static int qweb_set_endpoint_security(char *ifname, char *curr_ssid, char *auth,
				      char *proto, char *encry)
{
	int ret1, ret2, ret3;
	char buf[64 + 1];

	/* init local variable */
	ret1 = ret2 = ret3 = 0;

	if (auth && !proto && !encry) {
		// NONE
		CALL_QCSAPI(SSID_get_authentication_mode, ret1, ifname,
			    curr_ssid, buf);
		if (ret1) {
			goto qcsapi_failed;
		}

		if (strcmp(buf, auth)) {
			CALL_QCSAPI(SSID_set_authentication_mode, ret1, ifname,
				    curr_ssid, auth);
		}
	} else if (auth && proto && encry) {
		CALL_QCSAPI(SSID_get_authentication_mode, ret1, ifname,
			    curr_ssid, buf);
		if (ret1) {
			goto qcsapi_failed;
		}

		if (strcmp(buf, auth)) {
			CALL_QCSAPI(SSID_set_authentication_mode, ret1, ifname,
				    curr_ssid, auth);
		}

		CALL_QCSAPI(SSID_get_protocol, ret2, ifname, curr_ssid, buf);
		if (ret2) {
			goto qcsapi_failed;
		}

		if (strcmp(buf, proto)) {
			CALL_QCSAPI(SSID_set_protocol, ret2, ifname, curr_ssid,
				    proto);
		}

		CALL_QCSAPI(SSID_get_encryption_modes, ret3, ifname, curr_ssid,
			    buf);
		if (ret3) {
			goto qcsapi_failed;
		}

		if (strcmp(buf, encry)) {
			CALL_QCSAPI(SSID_set_encryption_modes, ret3, ifname,
				    curr_ssid, encry);
		}
	}

	if (ret1 || ret2 || ret3) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, ret are wrong. ret1 = %d, ret2 = %d, ret3 = %d\n",
			   __func__, __LINE__, ret1, ret2, ret3);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	return QWEBAPI_OK;

 qcsapi_failed:
	qwebprintf(DBG_LEVEL_VERBOSE, "%s(), %d, call qcsapi failed.\n",
		   __func__, __LINE__);
	return QWEBAPI_ERR_INVALID_VALUE;
}

int qweb_set_endpoint_mode_enabled(char *path, char *value)
{
	int perr;
	char *ifname;
	char *curr_ssid;

	if (value == NULL) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, value is NULL\n", __func__, __LINE__);
		return QWEBAPI_ERR_INVALID_VALUE;
	}

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);

	perr = QWEBAPI_OK;
	curr_ssid = qweb_get_endpoint_profile_curr_ssid(path, &perr);

	if (!strcmp(value, ITEM_NAME_MODE_NONE)) {
		// None
		qweb_set_endpoint_security(ifname, curr_ssid,
					   ITEM_NAME_AUTH_PROTO_NONE,
					   NULL, NULL);
	} else if (!strcmp(value, ITEM_NAME_MODE_WPA2_AES)) {
		// WPA2-Personal
		qweb_set_endpoint_security(ifname, curr_ssid,
					   ITEM_NAME_AUTH_TYPE_PSK,
					   ITEM_NAME_AUTH_PROTO_11I,
					   ITEM_NAME_ENCRY_TYPE_AES);
	} else if (!strcmp(value, ITEM_NAME_MODE_WPA2_WPA)) {
		// WPA-WPA2-Personal
		qweb_set_endpoint_security(ifname, curr_ssid,
					   ITEM_NAME_AUTH_TYPE_PSK,
					   ITEM_NAME_AUTH_PROTO_WPA_AND_11I,
					   ITEM_NAME_ENCRY_TYPE_TKIP_AES);
	}

	return QWEBAPI_OK;
}

char *qweb_get_endpoint_mode_enabled(char *path, int *perr)
{
	int ret1;
	int ret2;
	char *ifname;
	char *curr_ssid;
	char *mode_enabled;
	char protocol[16];
	char encryption[32];

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);

	curr_ssid = qweb_get_endpoint_profile_curr_ssid(path, perr);

	//get encryption modes of current SSID
	CALL_QCSAPI(SSID_get_protocol, ret1, ifname, curr_ssid, protocol);
	if (ret1 == -1005) {
		return ITEM_NAME_MODE_NONE;
	}

	CALL_QCSAPI(SSID_get_encryption_modes, ret2, ifname, curr_ssid,
		    encryption);
	if (ret1 || ret2) {
		qwebprintf(DBG_LEVEL_VERBOSE,
			   "%s(), %d, ret are wrong. ret1 = %d, ret2 = %d\n",
			   __func__, __LINE__, ret1, ret2);
	}

	if (!strcmp(protocol, ITEM_NAME_AUTH_PROTO_WPA)) {
		if (!strcmp(encryption, ITEM_NAME_ENCRY_TYPE_TKIP)) {
			mode_enabled = ITEM_NAME_MODE_WPA_TKIP;
		} else {
			mode_enabled = ITEM_NAME_MODE_WPA_AES;
		}
	} else if (!strcmp(protocol, ITEM_NAME_AUTH_PROTO_11I)) {
		if (!strcmp(encryption, ITEM_NAME_ENCRY_TYPE_TKIP)) {
			mode_enabled = ITEM_NAME_MODE_WPA2_TKIP;
		} else {
			mode_enabled = ITEM_NAME_MODE_WPA2_AES;
		}
	} else if (!strcmp(protocol, ITEM_NAME_AUTH_PROTO_WPA_AND_11I)) {
		//if (!strcmp(encryption, ITEM_NAME_ENCRY_TYPE_TKIP_AES))
		mode_enabled = ITEM_NAME_MODE_WPA2_WPA;
	} else {
		mode_enabled = ITEM_NAME_MODE_WPA2_AES;
	}

	return mode_enabled;
}

/* Device.WiFi.EndPoint.{i}.Profile.{i}.Security.WEPKey */
QWEBAPI_SET_STRING_FUNC_WITH_NOT_SUPPORT(endpoint_wep_key);
QWEBAPI_GET_STRING_FUNC_WITH_NOT_SUPPORT(endpoint_wep_key);

/* Device.WiFi.EndPoint.{i}.Profile.{i}.Security.PreSharedKey */
int qweb_set_endpoint_pre_shared_key(char *path, char *value)
{
	int ret;
	int perr;
	char *ifname;
	char *curr_ssid;
	char buf[64 + 1];

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_station, -1);

	perr = QWEBAPI_OK;
	curr_ssid = qweb_get_endpoint_profile_curr_ssid(path, &perr);

	CALL_QCSAPI(SSID_get_pre_shared_key, ret, ifname, curr_ssid, 0, buf);
	if (ret) {
		return QWEBAPI_ERR_NOT_AVALIABLE;
	}

	if (strcmp(buf, value)) {
		CALL_QCSAPI(SSID_set_pre_shared_key, ret, ifname,
			    curr_ssid, 0, value);
		QWEBAPI_SET_RETURN(ret);
	}

	return ret;
}

char *qweb_get_endpoint_pre_shared_key(char *path, int *perr)
{
	int ret;
	char *ifname;
	char *curr_ssid;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_station, 0);

	curr_ssid = qweb_get_endpoint_profile_curr_ssid(path, perr);

	CALL_QCSAPI(SSID_get_pre_shared_key, ret, ifname,
		    curr_ssid, 0, string_value_buf);
	QWEBAPI_GET_RETURN(ret, "");

	return string_value_buf;
}

/* Device.WiFi.EndPoint.{i}.Profile.{i}.Security.KeyPassphrase */
int qweb_set_endpoint_key_passphrase(char *path, char *value)
{
	int ret;
	int perr;
	char *ifname;
	char *curr_ssid;
	char buf[64 + 1];

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_station, -1);

	perr = QWEBAPI_OK;
	curr_ssid = qweb_get_endpoint_profile_curr_ssid(path, &perr);

	CALL_QCSAPI(SSID_get_key_passphrase, ret, ifname, curr_ssid, 0, buf);
	if (ret) {
		return QWEBAPI_ERR_NOT_AVALIABLE;
	}

	if (strcmp(buf, value)) {
		CALL_QCSAPI(SSID_set_key_passphrase, ret, ifname,
			    curr_ssid, 0, value);
		QWEBAPI_SET_RETURN(ret);
	}

	return ret;
}

char *qweb_get_endpoint_key_passphrase(char *path, int *perr)
{
	int ret;
	char *ifname;
	char *curr_ssid;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_station, 0);

	curr_ssid = qweb_get_endpoint_profile_curr_ssid(path, perr);

	CALL_QCSAPI(SSID_get_key_passphrase, ret, ifname,
		    curr_ssid, 0, string_value_buf);
	QWEBAPI_GET_RETURN(ret, "");

	return string_value_buf;
}

/* Device.WiFi.EndPoint.{i}.WPS */
/* Device.WiFi.EndPoint.{i}.WPS.Enable */
unsigned int qweb_get_endpoint_wps_enable(char *path, int *perr)
{
	return 1;
}

/* Device.WiFi.Endpoint.{i}.WPS.ConfigMethodsSupported */
char *qweb_get_endpoint_wps_config_methods_supported(char *path, int *perr)
{
	return qweb_get_wps_config_methods_supported(path, perr);
}

/* Device.WiFi.Endpoint.{i}.WPS.ConfigMethodsEnabled */
int qweb_set_endpoint_wps_config_methods_enabled(char *path, char *value)
{
	return qweb_set_wps_config_methods_enabled(path, value,
						   ITEM_NAME_ENDPOINT);
}

char *qweb_get_endpoint_wps_config_methods_enabled(char *path, int *perr)
{
	return qweb_get_wps_config_methods_enabled(path, perr,
						   ITEM_NAME_ENDPOINT);
}

/* Device.WiFi.EndPoint.{i}.WPS.X_QUANTENNA_COM_STA_PIN */
char *qweb_get_wps_sta_pin(char *path, int *perr)
{
	int ret;
	char *ifname;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_station, "");

	CALL_QCSAPI(wps_get_sta_pin, ret, ifname, string_value_buf);
	QWEBAPI_GET_RETURN(ret, "");

	return string_value_buf;
}

/* Device.WiFi.EndPoint.{i}.WPS.X_QUANTENNA_COM_ENR_report_button_press */
int qweb_set_wps_enrollee_report_button_press(char *path, char *value)
{
	int ret;
	char *ifname;
	struct ether_addr *mac;
	qcsapi_mac_addr mac_addr;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_station, QWEBAPI_ERR_NOT_AVALIABLE);

	mac = ether_aton(QWEBAPI_ALL_ZERO_MAC);
	if (mac == NULL)
		return QWEBAPI_ERR_INVALID_VALUE;

	memcpy(mac_addr, mac, MAC_ADDR_SIZE);
	CALL_QCSAPI(wps_enrollee_report_button_press, ret, ifname, mac_addr);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

char *qweb_get_wps_enrollee_report_button_press(char *path, int *perr)
{
	/* always return null string */
	return "";
}

/* Device.WiFi.EndPoint.{i}.WPS.X_QUANTENNA_COM_ENR_report_pin */
int qweb_set_wps_enrollee_report_pin(char *path, char *value)
{
	int ret;
	char *ifname;
	struct ether_addr *mac;
	qcsapi_mac_addr mac_addr;

	ifname = qweb_get_wifi_ifname(path, ITEM_NAME_ENDPOINT);
	QWEBAPI_CHECK_MODE(qcsapi_station, QWEBAPI_ERR_NOT_AVALIABLE);

	mac = ether_aton(QWEBAPI_ALL_ZERO_MAC);
	if (mac == NULL)
		return QWEBAPI_ERR_INVALID_VALUE;

	memcpy(mac_addr, mac, MAC_ADDR_SIZE);
	CALL_QCSAPI(wps_enrollee_report_pin, ret, ifname, mac_addr, value);
	QWEBAPI_SET_RETURN(ret);

	return ret;
}

char *qweb_get_wps_enrollee_report_pin(char *path, int *perr)
{
	/* always return null string */
	return "";
}

#ifdef TOPAZ_DBDC
int qweb_apply_for_change(char *path)
{
	int ret = 0 /* init its value as 0 */ ;

	if (qweb_get_defer_mode() == 1)
		return ret;

	if (need_to_apply_for_24G) {
		char qweb_cmd[QWEBAPI_CMD_MAX_LEN];

		snprintf(qweb_cmd, QWEBAPI_CMD_MAX_LEN, "wlan1");
		CALL_QCSAPI(qwe_command, ret, QWEBAPI_OP_ACTION, qweb_cmd,
			    QWEBAPI_OP_COMMIT, NULL, string_value_buf,
			    QWEBAPI_TR181_STRING_MAX_LEN);
	}

	/* recover to init value */
	need_to_apply_for_24G = 0;

	return ret;
}
#endif
