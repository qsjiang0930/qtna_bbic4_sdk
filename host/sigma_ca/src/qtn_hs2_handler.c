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

#include "qtn_hs2_handler.h"

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
#include "qtn_ca_config.h"

static void qtn_handle_ap_set_hs2(const char *params, int len, struct qtn_response *resp);

static const struct qtn_cmd_handler qtn_hs2_handler_map[] = {
	{"AP_SET_HS2", qtn_handle_ap_set_hs2},
};

#define N_ARRAY(arr)			(sizeof(arr)/sizeof(arr[0]))

const struct qtn_cmd_handler * qtn_lookup_hs2_handler(const char *cmd, int len)
{
	return qtn_lookup_cmd_handler(cmd, len, qtn_hs2_handler_map,
			N_ARRAY(qtn_hs2_handler_map));
}

static
int hs2_set_network_auth_type(const char* ifname, int id)
{
	/*
	# Network Authentication Type
	# This parameter indicates what type of network authentication is used in the
	# network.
	# format: <network auth type indicator (1-octet hex str)> [redirect URL]
	# Network Authentication Type Indicator values:
	# 00 = Acceptance of terms and conditions
	# 01 = On-line enrollment supported
	# 02 = http/https redirection
	# 03 = DNS redirection
	#network_auth_type=00
	#network_auth_type=02http://www.example.com/redirect/me/here/
	*/

	static const char* network_auth[] = {
		/* ID#1.	Acceptance of terms and conditions is required.
			The URL is https://tandc-server.wi-fi.org*/
		"00https://tandc-server.wi-fi.org",

		/* ID#2.	On-line enrolment supported */
		"01"
	};

	id--; // fist valid id is 1

	if (id < 0 || id >= N_ARRAY(network_auth)) {
		qtn_error("can't set network_auth_type, id %d is invalid", id);
		return -ENOTSUP;
	}

	return qcsapi_wifi_set_80211u_params(ifname, "network_auth_type", network_auth[id], "");
}

static
int hs2_set_nai_realm(const char* ifname, int id)
{
	struct nai_realm_entry {
		const char* nai_realm;
		const char* eap_method;
	};

	const struct nai_realm_entry* realms = NULL;
	int realms_size = 0;

	/* NAI Realm List from HS2.0 test plan Appdex B.1 */
	if (id == 1) {
		/*
		mail.example.com, EAP-TTLS/MSCHAPv2, username and password credential
		cisco.com,	  EAP-TTLS/MSCHAPv2, username and password credential
		wi-fi.org,	  EAP-TTLS/MSCHAPv2, username and password credential
		wi-fi.org,	  EAP-TLS, certificate credential
		example.com,	  EAP-TLS, certificate credential
		*/

		static const struct nai_realm_entry nai_realms_id1[] = {
			{.nai_realm = "mail.example.com", .eap_method = "21[2:4][5:7]"},
			{.nai_realm = "cisco.com", .eap_method = "21[2:4][5:7]"},
			{.nai_realm = "wi-fi.org", .eap_method = "21[2:4][5:7]"},
			{.nai_realm = "wi-fi.org", .eap_method = "13[5:6]"},
			{.nai_realm = "example.com", .eap_method = "13[5:6]"},
		};

		realms_size = N_ARRAY(nai_realms_id1);
		realms = nai_realms_id1;

	} else if (id == 2) {
		/* wi-fi.org, EAP-TTLS/MSCHAPv2, username and password credential */
		static const struct nai_realm_entry nai_realms_id2[] = {
			{.nai_realm = "wi-fi.org", .eap_method = "21[2:4][5:7]"},
		};

		realms_size = N_ARRAY(nai_realms_id2);
		realms = nai_realms_id2;
	} else if (id == 3) {
		/*
		cisco.com, EAP-TTLS/MSCHAPv2, username and password credential
		wi-fi.org, EAP-TTLS/MSCHAPv2, username and password credential
		wi-fi.org, EAP-TLS, certificate credential
		example.com, EAP-TLS, certificate credential
		*/

		static const struct nai_realm_entry nai_realms_id3[] = {
			{.nai_realm = "cisco.com", .eap_method = "21[2:4][5:7]"},
			{.nai_realm = "wi-fi.org", .eap_method = "21[2:4][5:7]"},
			{.nai_realm = "wi-fi.org", .eap_method = "13[5:6]"},
			{.nai_realm = "example.com", .eap_method = "13[5:6]"},
		};

		realms_size = N_ARRAY(nai_realms_id3);
		realms = nai_realms_id3;
	} else if (id == 4) {
		/*
		mail.example.com, EAP-TTLS/MSCHAPv2, username and password credential and
			EAP-TLS, certificate credential
		*/

		static const struct nai_realm_entry nai_realms_id4[] = {
			{.nai_realm = "mail.example.com",
						.eap_method = "21[2:4][5:7],13[5:6]"}
		};

		realms_size = N_ARRAY(nai_realms_id4);
		realms = nai_realms_id4;
	} else if (id == 5) {
		/*
		wi-fi.org, EAP-TTLS/MSCHAPv2, username and password credential
		ruckuswireless.com, EAP-TTLS/MSCHAPv2, username and password credential
		*/

		static const struct nai_realm_entry nai_realms_id5[] = {
			{.nai_realm = "wi-fi.org", .eap_method = "21[2:4][5:7]"},
			{.nai_realm = "ruckuswireless.com", .eap_method = "21[2:4][5:7]"},
		};

		realms_size = N_ARRAY(nai_realms_id5);
		realms = nai_realms_id5;

	} else if (id == 6) {
		/*
		wi-fi.org, EAP-TTLS/MSCHAPv2, username and password credential
		mail.example.com, EAP-TTLS/MSCHAPv2, username and password credential
		*/

		static const struct nai_realm_entry nai_realms_id6[] = {
			{.nai_realm = "wi-fi.org", .eap_method = "21[2:4][5:7]"},
			{.nai_realm = "mail.example.com", .eap_method = "21[2:4][5:7]"},
		};

		realms_size = N_ARRAY(nai_realms_id6);
		realms = nai_realms_id6;

	} else if (id == 7) {
		/*
		wi-fi.org, EAP-TLS, certificate credential
		wi-fi.org, EAP-TTLS/MSCHAPv2, username and password credential
		*/

		static const struct nai_realm_entry nai_realms_id7[] = {
			{.nai_realm = "wi-fi.org", .eap_method = "13[5:6]"},
			{.nai_realm = "wi-fi.org", .eap_method = "21[2:4][5:7]"},
		};

		realms_size = N_ARRAY(nai_realms_id7);
		realms = nai_realms_id7;
	} else {
		qtn_error("can't set NAI_REALM, invalid id %d", id);
		return -ENOTSUP;
	}

	for (int i = 0; i < realms_size; ++i) {
		int ret = qcsapi_security_add_nai_realm(
			ifname, 0, realms[i].nai_realm, realms[i].eap_method);
		if (ret < 0) {
			qtn_error("can't add nai_realm %d, index %d, error %d",
				id, i, ret);
			return ret;
		}
	}

	return 0;
}

static
int hs2_set_wan_metrics(const char* ifname, int id)
{
	// WAN Metrics
	// format: <WAN Info>:<DL Speed>:<UL Speed>:<DL Load>:<UL Load>:<LMD>
	// WAN Info: B0-B1: Link Status, B2: Symmetric Link, B3: At Capabity
	//    (encoded as two hex digits)
	//    Link Status: 1 = Link up, 2 = Link down, 3 = Link in test state
	// Downlink Speed: Estimate of WAN backhaul link current downlink speed in kbps;
	//	1..4294967295; 0 = unknown
	// Uplink Speed: Estimate of WAN backhaul link current uplink speed in kbps
	//	1..4294967295; 0 = unknown
	// Downlink Load: Current load of downlink WAN connection (scaled to 255 = 100%)
	// Uplink Load: Current load of uplink WAN connection (scaled to 255 = 100%)
	// Load Measurement Duration: Duration for measuring downlink/uplink load in
	// tenths of a second (1..65535); 0 if load cannot be determined
	//
	//hs20_wan_metrics=01:8000:1000:80:240:3000

	static char *wan_metrics_table[][6] = {
		{ "01", "2500", "384", "0", "0", "1" },
		{ "01", "1500", "384", "51", "51", "1" },
		{ "01", "2000", "1000", "51", "51", "1" },
		{ "01", "8000", "1000", "51", "51", "1" },
		{ "01", "9000", "5000", "51", "51", "1" },
	};

	id--;

	if (id < 0 || id >= N_ARRAY(wan_metrics_table)) {
		qtn_error("can't set wan_metric, id %d is invalid", id);
		return -EINVAL;
	}

	char **wan_metrics = wan_metrics_table[id];

	return qcsapi_wifi_set_hs20_params(ifname, "hs20_wan_metrics",
					wan_metrics[0],	wan_metrics[1], wan_metrics[2],
					wan_metrics[3],	wan_metrics[4], wan_metrics[5]);
}

static
int hs2_set_connection_capability(const char* ifname, int id)
{
	// Connection Capability
	// This can be used to advertise what type of IP traffic can be sent through the
	// hotspot (e.g., due to firewall allowing/blocking protocols/ports).
	// format: <IP Protocol>:<Port Number>:<Status>
	// IP Protocol: 1 = ICMP, 6 = TCP, 17 = UDP
	// Port Number: 0..65535
	// Status: 0 = Closed, 1 = Open, 2 = Unknown
	// Each hs20_conn_capab line is added to the list of advertised tuples.
	//hs20_conn_capab=1:0:2
	//hs20_conn_capab=6:22:1
	//hs20_conn_capab=17:5060:0

	struct connection_capability_entry {
		const char* proto;
		const char* port;
		const char* status;
	};

	static const struct connection_capability_entry id1[] = {
		{.proto = "6", .port = "20", .status = "1"},
		{.proto = "6", .port = "80", .status = "1"},
		{.proto = "6", .port = "443", .status = "1"},
		{.proto = "17", .port = "4500", .status = "1"},
		{.proto = "17", .port = "5060", .status = "1"},
		{.proto = "50", .port = "0", .status = "1"},
		{.proto = NULL}
	};

	static const struct connection_capability_entry id2[] = {
		{.proto = "6", .port = "80", .status = "1"},
		{.proto = "6", .port = "443", .status = "1"},
		{.proto = "17", .port = "5060", .status = "1"},
		{.proto = "6", .port = "5060", .status = "1"},
		{.proto = NULL}
	};

	static const struct connection_capability_entry id3[] = {
		{.proto = "6", .port = "80", .status = "1"},
		{.proto = "6", .port = "443", .status = "1"},
		{.proto = NULL}
	};

	static const struct connection_capability_entry id4[] = {
		{.proto = "6", .port = "80", .status = "1"},
		{.proto = "6", .port = "443", .status = "1"},
		{.proto = "6", .port = "5060", .status = "1"},
		{.proto = "17", .port = "5060", .status = "1"},
		{.proto = NULL}
	};

	static const struct connection_capability_entry id5[] = {
		{.proto = NULL}
	};


	static const struct connection_capability_entry* connection_capabilities[] =
		{id1, id2, id3, id4, id5 };

	id--;

	if (id < 0 || id >= N_ARRAY(connection_capabilities)) {
		qtn_error("can't set connection_capability, id %d is invalid", id);
		return -EINVAL;
	}

	for (const struct connection_capability_entry* cc = connection_capabilities[id];
		cc->proto != NULL; ++cc) {

		int ret = qcsapi_security_add_hs20_conn_capab(
						ifname,
						cc->proto,
						cc->port,
						cc->status);
		if (ret < 0) {
			qtn_error("can't set hs20_conn_capab, ind %d, error %d",
				id, ret);
			return ret;
		}
	}

	return 0;
}

static
int hs2_set_mcc_mnc(const char* ifname, char* mcc_list, char* mnc_list)
{
	char mcc_mnc_list[1024];
	char* dest = mcc_mnc_list;

	char* mcc_saveptr;
	char* mnc_saveptr;

	char* mcc = strtok_r(mcc_list, ";", &mcc_saveptr);
	char* mnc = strtok_r(mnc_list, ";", &mnc_saveptr);

	for (; mcc != NULL && mnc != NULL; mcc = strtok_r(NULL, ";", &mcc_saveptr),
					   mnc = strtok_r(NULL, ";", &mnc_saveptr)) {
		const size_t available_space = mcc_mnc_list + sizeof(mcc_mnc_list) - dest;
		const int first_entry = mcc_mnc_list == dest;
		int added = snprintf(dest, available_space, "%s%s,%s", first_entry ? "" : ";",
				mcc, mnc);

		if (added < available_space) {
			dest += added;
		}
	}

	qtn_log("try to set anqp_3gpp_cell_net to %s", mcc_mnc_list);
	return qcsapi_wifi_set_80211u_params(ifname, "anqp_3gpp_cell_net", mcc_mnc_list, "");
}

static
int hs2_clear_roaming_consortium(const char *ifname)
{
	int ret = 0;
#define ROAM_CONS_LIST_LEN 1024
	char *roaming_cons_list = malloc(ROAM_CONS_LIST_LEN);

	memset(roaming_cons_list, 0, ROAM_CONS_LIST_LEN);

	if ((ret = qcsapi_security_get_roaming_consortium(ifname, roaming_cons_list)) < 0) {
		qtn_error("can't get existing roaming consortium");
		goto out;
	}
	char *roaming_cons_save;
	const char *roaming_cons = strtok_r(roaming_cons_list, "\n", &roaming_cons_save);
	while (roaming_cons) {
		ret = qcsapi_security_del_roaming_consortium(ifname, roaming_cons);
		if (ret < 0) {
			qtn_error("can't delete roaming consortium");
			goto out;
		}
		roaming_cons = strtok_r(NULL, "\n", &roaming_cons_save);
	}

out:
	free(roaming_cons_list);
	return ret;
}

static
int hs2_set_roaming_consortium(const char *ifname, const char *str_val)
{
	if (strcasecmp(str_val, "disabled") == 0) {
		return hs2_clear_roaming_consortium(ifname);
	} else {
		return qcsapi_security_add_roaming_consortium(ifname, str_val);
	}

	return 0;
}

static
int hs2_set_oper_friendly_name(const char *ifname, int id)
{
	int ret = 0;

	if (id == 1) {
		/* Already set by default */
	} else {
		ret = ENOTSUP;
	}

	return ret;
}

static
int hs2_set_venue_name(const char *ifname, int id)
{
	int ret = 0;

	if (id != 1)
		return ENOTSUP;

	static const char venue_name_eng[] = "Wi-Fi Alliance\\n"
					     "2989 Copper Road\\n"
					     "Santa Clara, CA 95051, USA";

	static const char venue_name_chi[] = "Wi-Fi联盟实验室\\n"
					     "二九八九年库柏路\\n"
					     "圣克拉拉, 加利福尼亚95051, 美国";

	if ((ret = qcsapi_security_add_venue_name(ifname, "eng", venue_name_eng)) < 0) {
		qtn_error("can't add lang eng, name %s, error %d", venue_name_eng, ret);
		return ret;
	}

	if ((ret = qcsapi_security_add_venue_name(ifname, "chi", venue_name_chi)) < 0) {
		qtn_error("can't add lang chi, name %s, error %d", venue_name_chi, ret);
		return ret;
	}

	if ((ret = qcsapi_wifi_set_80211u_params(
		     ifname, "venue_group", "2", "")) < 0) {
		qtn_error("can't set venue_type to 8, error %d", ret);
		return ret;
	}

	if ((ret = qcsapi_wifi_set_80211u_params(
		     ifname, "venue_type", "8", "")) < 0) {
		qtn_error("can't set venue_type to 8, error %d", ret);
	}

	return ret;
}

struct osu_icon {
	const char *name;
	int width;
	int height;
	const char *lang;
	const char *type;
};

static
int hs2_set_osu_provider_list(const char *ifname, int id)
{
	int ret = 0;
	const char *osu_server_uri;
	struct osu_icon *icons;
	unsigned icons_count;
	char **friendly_names;
	unsigned friendly_names_count;
	char **service_desc;
	unsigned service_desc_count;
	const char *osu_nai = NULL;

	/* TODO: configurable icons path */
	static struct osu_icon icons_1[] = {
		{
			.width = 160,
			.height = 76,
			.lang = "eng",
			.type = "image/png",
			.name = "icon_red_eng.png",
		},
		{
			.width = 128,
			.height = 61,
			.lang = "zxx",
			.type = "image/png",
			.name = "icon_red_zxx.png",
		}
	};

	static char *friendly_names_1[] = {
		"eng:SP Red Test Only",
		"kor:SP 빨강 테스트 전용"
	};

	static char *service_desc_1[] = {
		"eng:Free service for test purpose",
		"kor:테스트 목적으로 무료 서비스"
	};

	/* TODO: configurable icons path */
	static struct osu_icon icons_9[] = {
		{
			.width = 128,
			.height = 64,
			.lang = "zxx",
			.type = "image/png",
			.name = "icon_orange_zxx.png",
		},
	};

	static char *friendly_names_9[] = {
		"eng:SP Orange Test Only",
	};

	static char *service_desc_9[] = {
		"eng:Free service for test purpose",
	};

	if (id == 1) {
		osu_server_uri = "https://osu-server.r2-testbed-rks.wi-fi.org:9446/OnlineSignup/services/newUser/digest";
		icons = icons_1;
		icons_count = N_ARRAY(icons_1);
		friendly_names = friendly_names_1;
		friendly_names_count = N_ARRAY(friendly_names_1);
		service_desc = service_desc_1;
		service_desc_count = N_ARRAY(service_desc_1);
	} else if (id == 9) {
		osu_server_uri = "https://osu-server.r2-testbed.wi-fi.org/";
		icons = icons_9;
		icons_count = N_ARRAY(icons_9);
		friendly_names = friendly_names_9;
		friendly_names_count = N_ARRAY(friendly_names_9);
		service_desc = service_desc_9;
		service_desc_count = N_ARRAY(service_desc_9);
		osu_nai = "test-anonymous@wi-fi.org";
	} else {
		return ENOTSUP;
	}

	int i;
	for (i = 0; i < icons_count; i++) {
		char icon_persist_path[256];
		char icon_tmp_path[64];
		static char cmd[512];

		const char *icons_folder = qtn_config_get_option("icons_folder");
		if (!icons_folder)
			icons_folder = ".";

		ret = snprintf(icon_persist_path, sizeof(icon_persist_path), "%s/%s",
				icons_folder, icons[i].name);

		if (ret < 0 || ret >= sizeof(icon_persist_path)) {
			qtn_error("invalid icon path");
			return EFAULT;
		}

		ret = snprintf(icon_tmp_path, sizeof(icon_tmp_path), "/tmp/%s",
				icons[i].name);

		if (ret < 0 || ret >= sizeof(icon_tmp_path)) {
			qtn_error("invalid icon path");
			return EFAULT;
		}

		ret = snprintf(cmd, sizeof(cmd),
			"test -f %1$s && cp %1$s %2$s || dd if=/dev/urandom of=%2$s bs=1024 count=11",
			icon_persist_path, icon_tmp_path);

		if (ret < 0 || ret >= sizeof(cmd)) {
			qtn_error("invalid command");
			return EFAULT;
		}

		ret = system(cmd);
		if (ret != 0) {
			qtn_error("failed command: %s", cmd);
			return EFAULT;
		}

		ret = qcsapi_security_add_hs20_icon(ifname,
						    icons[i].width,
						    icons[i].height,
						    icons[i].lang,
						    icons[i].type,
						    icons[i].name,
						    icon_tmp_path);
		if (ret < 0) {
			qtn_error("failed to add hs20_icon");
			return ret;
		}
	}

	ret = qcsapi_security_add_osu_server_uri(ifname, osu_server_uri);
	if (ret < 0) {
		qtn_error("failed to add osu_server_uri: %s", osu_server_uri);
		return ret;
	}

	ret = qcsapi_security_add_osu_server_param(ifname, osu_server_uri,
						   "osu_method_list", "1");
	if (ret < 0) {
		qtn_error("failed to add osu_method_list");
		return ret;
	}

	for (i = 0; i < friendly_names_count; i++) {
		ret = qcsapi_security_add_osu_server_param(ifname, osu_server_uri,
							   "osu_friendly_name", friendly_names[i]);
		if (ret < 0) {
			qtn_error("failed to add osu_friendly_name: %s", friendly_names[i]);
			return ret;
		}
	}

	for (i = 0; i < service_desc_count; i++) {
		ret = qcsapi_security_add_osu_server_param(ifname, osu_server_uri,
							   "osu_service_desc", service_desc[i]);
		if (ret < 0) {
			qtn_error("failed to add osu_service_desc: %s", service_desc[i]);
			return ret;
		}
	}

	for (i = 0; i < icons_count; i++) {
		ret = qcsapi_security_add_osu_server_param(ifname, osu_server_uri,
							   "osu_icon", icons[i].name);
		if (ret < 0) {
			qtn_error("failed to add osu_icon: %s", icons[i].name);
			return ret;
		}
	}

	if (osu_nai) {
		ret = qcsapi_security_add_osu_server_param(ifname, osu_server_uri,
							   "osu_nai", osu_nai);
		if (ret < 0) {
			qtn_error("failed to add osu_nai: %s", osu_nai);
			return ret;
		}
	}

	return ret;
}

static
int hs2_set_qos_map_set(const char* ifname, int id)
{
	int ret = 0;
	const char *qos_map_str;

	if (id == 1) {
		qos_map_str = "53,2,22,6,8,15,0,7,255,255,16,31,32,39,255,255,40,47,255,255";
	} else if (id == 2) {
		qos_map_str = "8,15,0,7,255,255,16,31,32,39,255,255,40,47,48,63";
	} else {
		return ENOTSUP;
	}

	ret = qcsapi_wifi_set_qos_map(ifname, qos_map_str);
	if (ret < 0) {
		qtn_error("error: qcsapi_wifi_set_qos_map");
		return ret;
	}

	unsigned retry_count = 5;
	unsigned assoc_count = 0;
	while (!assoc_count && retry_count--) {
		ret = qcsapi_wifi_get_count_associations(ifname, &assoc_count);
		if (ret < 0) {
			qtn_error("failed to get assoc count");
			return ret;
		}
		if (!assoc_count)
			sleep(10);
	}

	unsigned i;
	for (i = 0; i < assoc_count; i++) {
		uint8_t sta_mac_addr[ETH_ALEN];
		ret = qcsapi_wifi_get_associated_device_mac_addr(ifname, i, sta_mac_addr);
		if (ret < 0) {
			qtn_error("failed to get sta mac addr, index = %u", i);
			return ret;
		}

		ret = qcsapi_wifi_send_qos_map_conf(ifname, sta_mac_addr);
		if (ret < 0) {
			qtn_error("failed to send qos_map_conf, index = %u", i);
			return ret;
		}
	}

	return ret;
}

void qtn_handle_ap_set_hs2(const char *params, int len, struct qtn_response *resp)
{
	struct qtn_cmd_request cmd_req;
	int ret;
	char ifname_buf[16];
	const char *ifname;
	char str_val[128];
	int int_val;
	char mcc[128];
	char mnc[128];

	ret = qtn_init_cmd_request(&cmd_req, params, len);
	if (ret != 0) {
		resp->status = STATUS_INVALID;
		resp->error_code = ret;
		return;
	}

	unsigned vap_index = 0;
	if (qtn_get_value_int(&cmd_req, QTN_TOK_WLAN_TAG, &int_val) > 0) {
		if (int_val < 1) {
			ret = ENOTSUP;
			goto respond;
		}

		vap_index = int_val - 1;
	}

	*ifname_buf = 0;
	ret = qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname_buf, sizeof(ifname_buf));

	ifname = (ret > 0) ? ifname_buf : qtn_get_sigma_vap_interface(vap_index);

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERWORKING, str_val, sizeof(str_val)) > 0 &&
		(ret = qcsapi_wifi_set_interworking(ifname, str_val)) < 0) {
		qtn_error("can't set interworking to %s, error %d", str_val, ret);
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_ACCS_NET_TYPE, str_val, sizeof(str_val)) > 0 &&
		(ret = qcsapi_wifi_set_80211u_params(
				ifname, "access_network_type", str_val, "")) < 0) {
		qtn_error("can't set access_network_type to %s, error %d", str_val, ret);
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERNET, str_val, sizeof(str_val)) > 0 &&
		(ret = qcsapi_wifi_set_80211u_params(
				ifname, "internet", str_val, "")) < 0) {
		qtn_error("can't set internet to %s, error %d", str_val, ret);
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_VENUE_GRP, str_val, sizeof(str_val)) > 0 &&
		(ret = qcsapi_wifi_set_80211u_params(
				ifname, "venue_group", str_val, "")) < 0) {
		qtn_error("can't set venue_group to %s, error %d", str_val, ret);
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_VENUE_TYPE, str_val, sizeof(str_val)) > 0 &&
		(ret = qcsapi_wifi_set_80211u_params(
				ifname, "venue_type", str_val, "")) < 0) {
		qtn_error("can't set venue_type to %s, error %d", str_val, ret);
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_HESSID, str_val, sizeof(str_val)) > 0 &&
		(ret = qcsapi_wifi_set_80211u_params(
				ifname, "hessid", str_val, "")) < 0) {
		qtn_error("can't set hessid to %s, error %d", str_val, ret);
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_ROAMING_CONS, str_val, sizeof(str_val)) > 0 &&
		(ret = hs2_set_roaming_consortium(ifname, str_val)) < 0) {
		qtn_error("can't set roaming_consortium to %s, error %d", str_val, ret);
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_DGAF_DISABLE, str_val, sizeof(str_val)) > 0 &&
		(ret = qcsapi_wifi_set_hs20_params(ifname, "disable_dgaf", str_val, "", "", "", "",
			"")) < 0) {
		qtn_error("can't set disable_dgaf to %s, error %d", str_val, ret);
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_NET_AUTH_TYPE, &int_val) > 0 &&
		(ret = hs2_set_network_auth_type(ifname, int_val)) < 0) {
		qtn_error("can't set network_auth_type to %d, error %d", int_val, ret);
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_NAI_REALM_LIST, &int_val) > 0 &&
		(ret = hs2_set_nai_realm(ifname, int_val)) < 0) {

		qtn_error("can't set nai_realm, error %d", ret);
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_OPER_NAME, &int_val) > 0) {
		ret = hs2_set_oper_friendly_name(ifname, int_val);
		if (ret < 0) {
			qtn_error("can't set OPER_NAME, id %d, error %d", int_val, ret);
			goto respond;
		}
	}

	if (qtn_get_value_int(&cmd_req,  QTN_TOK_VENUE_NAME, &int_val) > 0) {
		ret = hs2_set_venue_name(ifname, int_val);
		if (ret < 0) {
			qtn_error("can't set VENUE_NAME, id %d, error %d", int_val, ret);
			goto respond;
		}
	}

	if (qtn_get_value_int(&cmd_req,  QTN_TOK_WAN_METRICS, &int_val) > 0 &&
		(ret = hs2_set_wan_metrics(ifname, int_val)) < 0) {

		qtn_error("can't set wan metrics, id %d, error %d", int_val, ret);
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req,  QTN_TOK_CONN_CAP, &int_val) > 0 &&
		(ret = hs2_set_connection_capability(ifname, int_val)) < 0) {

		qtn_error("can't set connection_capability, id %d, error %d", int_val, ret);
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req,  QTN_TOK_IP_ADD_TYPE_AVAIL, &int_val) > 0) {
		if (int_val == 1) {
			/*
			The following information is conveyed by this element:
				- Single NATed private IPv4 address available
				- IPv6 address is not available
			*/

			ret = qcsapi_wifi_set_80211u_params(
						ifname, "ipaddr_type_availability", "3", "0");
			if (ret < 0) {
				qtn_error("can't set ipaddr_type_availability, error %d", ret);
				goto respond;
			}
		} else {
			ret = ENOTSUP;
			qtn_error("can't set ADD_TYPE_AVAIL, id %d, error %d", int_val, ret);
			goto respond;
		}
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_DOMAIN_LIST, str_val, sizeof(str_val)) > 0 &&
		(ret = qcsapi_wifi_set_80211u_params(ifname, "domain_name", str_val, "")) < 0) {
		qtn_error("can't set domain_name to %s, error %d", str_val, ret);
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_GAS_CB_DELAY, str_val, sizeof(str_val)) > 0 &&
		(ret = qcsapi_wifi_set_80211u_params(ifname, "gas_comeback_delay", str_val,
			"")) < 0) {
		qtn_error("can't set gas_comeback_delay to %s, error %d", str_val, ret);
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_PLMN_MCC, mcc, sizeof(mcc)) > 0 &&
			qtn_get_value_text(&cmd_req, QTN_TOK_PLMN_MNC, mnc, sizeof(mnc)) > 0 &&
			(ret = hs2_set_mcc_mnc(ifname, mcc, mnc)) < 0) {
		qtn_error("can't set mcc %s and mnc %s, error %d", mcc, mnc, ret);
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_PROXY_ARP, str_val, sizeof(str_val)) > 0 &&
		(ret = qcsapi_wifi_set_proxy_arp(ifname, str_val)) < 0) {
		qtn_error("can't set proxy_arp to %s, error %d", str_val, ret);
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_OSU_SSID, str_val, sizeof(str_val)) > 0 &&
		(ret = qcsapi_wifi_set_hs20_params(ifname, "osu_ssid", str_val,
						   "", "", "", "", "")) < 0) {
		qtn_error("can't set proxy_arp to %s, error %d", str_val, ret);
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_OSU_PROVIDER_LIST, &int_val) > 0 &&
		(ret = hs2_set_osu_provider_list(ifname, int_val)) < 0) {
		qtn_error("can't set OSU provider list to %d, error %d", int_val, ret);
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_L2_TRAFFIC_INSPECT, str_val, sizeof(str_val)) > 0 &&
		(ret = qcsapi_wifi_set_l2_ext_filter(ifname, "status", str_val)) < 0) {
		qtn_error("can't set L2 external filtering to %s, error %d", str_val, ret);
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_QOS_MAP_SET, &int_val) > 0 &&
		(ret = hs2_set_qos_map_set(ifname, int_val)) < 0) {
		qtn_error("can't set qos_map_set to %d, error %d", int_val, ret);
		goto respond;
	}

respond:
	resp->status = (ret == 0) ? STATUS_COMPLETE : STATUS_ERROR;
	resp->error_code = ret;
}
