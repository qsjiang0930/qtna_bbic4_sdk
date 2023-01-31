/**
  Copyright (c) 2020 Quantenna Communications Inc
  All Rights Reserved

  This software may be distributed under the terms of the BSD license.
  See README for more details.

  Hexadecimal parsing code is based on hostapd utils parser
  Copyright (c) 2003-2013, Jouni Malinen <j@w1.fi>
 **/

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/wireless.h>
#include <string.h>
#include <errno.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_qrpe.h>
#include "map_erw_test.h"
#include "map_api_test.h"
#include "map_util_test.h"

static int ioctl_sock = -1;
static uint8_t data_buf[BUF_SIZE] = {0};
static uint8_t mac_addr[ETH_ALEN] = {0};

static void map_erw_help()
{
	fprintf(stderr,
		"Usage: map_api_test cmd erw <params>\n"
		"	cmd erw <help>				: help for erw test command\n"
		"	cmd erw wifi0 add <MAC> [<IE>]  [<subie>] ... [<subie>]\n"
		"	cmd erw wifi0 del <MAC> [<IE>]  [<subie>] ... [<subie>]\n"
		"	cmd erw wifi0 get <MAC>\n"
		"	cmd erw wifi0 clear <MAC>\n"
		"		format of ie:\n"
		"			ID; CODE; PRESENT; NUM_SUBIE; NR_ID_MAK; NUM_SUBIE; SUBIE_OFFSET; MATCH_OFFSET; MATCH_LEN; MATCH;\n"
		"			#ID: id of IE (1Byte)\n"
		"			#CODE: indicate reject mode (1Byte)\n"
		"			#PRESENT: ie is present or not(1 Bytes)\n"
		"			#NR_ID_MASK: valid when CODE=82, indicate neighbor should be report to sta, each bit present one neighbor (4 Bytes)\n"
		"			#NUM_SUBIE: num of subie each ie(1 Bytes)\n"
		"			#SUBIE_OFFSET: offset start of subie (2 Bytes)\n"
		"			#MATCH_OFFSET: offset start from payload of ie (2 Bytes)\n"
		"			#MATCH_LEN: length of match (2 Bytes)\n"
		"			#MATCH: the content that need to be compare (20 Bytes at most)\n"
		"		format of subie:\n"
		"			ID; CODE; PRESENT; NR_ID_MASK; MATCH_TYPE; MATCH_OFFSET; MATCH_LEN; MATCH;\n"
		"			#ID: id of SUBIE (1Byte)\n"
		"			#CODE: indicate reject mode (1Byte)\n"
		"			#PRESENT: subie is present or not(1 Bytes)\n"
		"			#NR_ID_MASK: valid when CODE=82, indicate neighbor should be report to sta, each bit present one neighbor (4 Bytes)\n"
		"			#MATCH_TYPE: 0: equal, 1: non-equal, 2 smaller than, 3 bigger than (1 Bytes)\n"
		"			#MATCH_OFFSET: offset start from payload of ie (2 Bytes)\n"
		"			#MATCH_LEN: length of match (2 Bytes)\n"
		"			#MATCH: the content that need to be compare (20 Bytes at most)\n"
		"		example of command:\n"
		"			map_api_test cmd erw wifi0 add 00:26:86:F0:CF:84  dd5200ffffffff02000400000004506f9a1b\n"
		"			map_api_test cmd erw wifi0 add 00:26:86:F0:CF:84  dd5201ffffffff02000400000004506f9a1b  065200aabbccdd0000000003060180\n"
		"			map_api_test cmd erw wifi0 del 00:26:86:F0:CF:84  dd5201ffffffff01000400000004506f9a1b  065200aabbccdd0000000003060180\n"
		"			map_api_test cmd erw wifi0 get 00:26:86:F0:CF:84\n"
		"			map_api_test cmd erw wifi0 clear 00:26:86:F0:CF:84\n"
		"\n");
}


static int erw_init(char *ifname)
{
	int status = 1;
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, (IFNAMSIZ - 1));
	iwr.u.data.flags = SIOCDEV_SUBIO_SET_BSA_STATUS;
	iwr.u.data.pointer = (caddr_t)&status;
	iwr.u.data.length = sizeof(status);

	if (ioctl(ioctl_sock, IEEE80211_IOCTL_EXT, &iwr) < 0) {
		printf("%s: %s\n", __FUNCTION__, strerror(errno));
		return -errno;
	}

	return 0;
}

static void erw_dump_ie(uint8_t *ie, int ie_len)
{
	char buf[BUF_SIZE] = {0};
	int offset = 0;
	int j = 0;

	offset += snprintf(buf + offset, BUF_SIZE - offset, "{");
	if (offset >= sizeof(buf))
		goto done;

	for (j = 0; j < ie_len; j++) {
		offset += snprintf(buf + offset, BUF_SIZE - offset, "%2.2x,", ie[j]);
		if (offset >= sizeof(buf))
			goto done;
		if (j < ie_len -1)
			offset += snprintf(buf + offset, BUF_SIZE - offset, ",");
		if (offset >= sizeof(buf))
			goto done;
	}

	offset += snprintf(buf + offset, BUF_SIZE - offset, "}");
done:
	printf("%s", buf);
}

static void show_erw_content_ie(struct ieee80211_req_erw_content_ie *ie)
{
	if (!ie)
		return;
	printf("ERW IE: ie[%d] mode=%#x, match_offset=%d, match_len= %d num_subie=%d, subel_offset %d match=",
		ie->ie_id, ie->reject_mode, ie->match_offset,
		ie->match_len, ie->num_subie, ie->subel_offset);
	erw_dump_ie(ie->match, ie->match_len);
	printf("\n");
}

static void show_erw_content_subie(struct ieee80211_req_erw_content_subie *subie)
{
	if (!subie)
		return;

	printf("ERW SUBIE ie[%d]:  mode=%#x, match_offset=%d, sub_type %d match_len=%d match=",
		subie->subie_id, subie->reject_mode, subie->match_offset,
		subie->match_type, subie->match_len);
	erw_dump_ie(subie->match, subie->match_len);
	printf("\n");
}

static int erw_parse_mac(const char *mac_str, uint8_t *mac)
{
	unsigned int tmparray[ETH_ALEN];

	if (mac_str == NULL)
		return -1;

	if (sscanf(mac_str, REQ_MACSTR_INPUT_FMT,
			&tmparray[0],
			&tmparray[1],
			&tmparray[2],
			&tmparray[3],
			&tmparray[4],
		&tmparray[5]) != ETH_ALEN) {
		return -1;
	}

	mac[0] = tmparray[0];
	mac[1] = tmparray[1];
	mac[2] = tmparray[2];
	mac[3] = tmparray[3];
	mac[4] = tmparray[4];
	mac[5] = tmparray[5];

	return 0;
}

static int hex2num(char unsigned c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}



static int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}


static int hexstr2bin(const char *hex, uint8_t *buf, int len)
{
	int i, a;
	const char *ipos = hex;
	uint8_t *opos = buf;

	for (i = 0; i < len; i++) {
		a = hex2byte(ipos);
		if (a < 0)
			return -1;
		*opos++ = a;
		ipos += 2;
	}
	return 0;
}

static int erw_parse_ie(const char *str, int str_len, struct ieee80211_req_erw_content_ie *ie)
{
	int offset = 0;
	uint8_t buf[BUF_SIZE] = {0};
	int buflen = str_len/2;

	if (!str || !ie || buflen > sizeof(buf)) {
		printf("%s: parameter invalid\n", __func__);
		return -1;
	}

	if (hexstr2bin(str, buf, buflen) < 0) {
		printf("%s: failed\n", __func__);
		return -1;
	}

	ie->ie_id = *(uint8_t *)(buf + offset);
	offset += 1;

	ie->reject_mode = *(uint8_t *)(buf + offset);
	offset += 1;

	ie->ie_present = *(uint8_t *)(buf + offset);
	offset += 1;

	ie->idx_mask = BE_READ_4(buf + offset);
	offset += 4;

	ie->num_subie = *(uint8_t *)(buf + offset);
	offset += 1;

	ie->subel_offset = BE_READ_2(buf + offset);
	offset += 2;

	ie->match_offset = BE_READ_2(buf + offset);
	offset += 2;

	ie->match_len = BE_READ_2(buf + offset);
	offset += 2;

	if (ie->match_len > sizeof(ie->match))
		ie->match_len = sizeof(ie->match);

	if ((offset + ie->match_len) < sizeof(buf))
		memcpy(ie->match, buf + offset, ie->match_len);

	return 0;
}

static int erw_parse_subie(const char *str, int str_len,
			struct ieee80211_req_erw_content_subie *subie)
{
	uint8_t buf[BUF_SIZE] = {0};
	int offset = 0;
	int buflen = str_len/2;

	if (!str || !subie || buflen > sizeof(buf)) {
		printf("%s: parameter invalid\n", __func__);
		return -1;
	}

	if (hexstr2bin(str, buf, str_len/2) < 0) {
		printf("%s: failed\n", __func__);
		return -1;
	}
	subie->subie_id = *(uint8_t *)(buf + offset);
	offset += 1;

	subie->reject_mode = *(uint8_t *)(buf + offset);
	offset += 1;

	subie->subie_present = *(uint8_t *)(buf + offset);
	offset += 1;

	subie->idx_mask = BE_READ_4(buf + offset);
	offset += 4;

	subie->match_type = *(uint8_t *)(buf + offset);
	offset += 1;

	subie->match_offset = BE_READ_2(buf + offset);
	offset += 2;

	subie->match_len = BE_READ_2(buf + offset);
	offset += 2;

	if (subie->match_len > sizeof(subie->match))
		subie->match_len = sizeof(subie->match);

	if ((offset + subie->match_len) < sizeof(buf))
		memcpy(subie->match, buf + offset, subie->match_len);

	return 0;
}

static void erw_parse_content_result(struct ieee80211_qrpe_req_erw *req_erw)
{
	struct ieee80211_req_erw_content_result *req_content_result = NULL;
	struct ieee80211_req_erw_content_ie *ie = NULL;
	struct ieee80211_req_erw_content_subie *subie = NULL;
	int offset = 0;
	int c = 0;

	if (!req_erw) {
		printf("%s: param invaid\n" ,__func__);
		return;
	}

	printf("recved data_len=%d\n", req_erw->data_len);
	req_content_result = (struct ieee80211_req_erw_content_result *)req_erw->data;
	ie = (struct ieee80211_req_erw_content_ie *)(req_content_result->ie + offset);
	while (ie->ie_id && offset < (req_erw->data_len - sizeof(*req_content_result))) {
		ie = (struct ieee80211_req_erw_content_ie *)(req_content_result->ie + offset);
		show_erw_content_ie(ie);
		offset += IEEE80211_BSA_REQ_IE_LEN;
		for (c = 0; c < ie->num_subie; c++) {
			subie = (struct ieee80211_req_erw_content_subie *)
						(req_content_result->ie + offset);
			show_erw_content_subie(subie);
			offset += IEEE80211_BSA_REQ_SUBIE_LEN;
		}
	}
}
static int map_erw_do_ioctl(const char *ifname, struct ieee80211_qrpe_req_erw *req_erw)
{
	struct iwreq iwr;

	if (!req_erw) {
		printf("%s: param invaid\n" ,__func__);
		return -1;
	}
	if (ioctl_sock < 0) {
		printf("%s: socket invaid\n", __func__);
		return -1;
	}
	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, (IFNAMSIZ - 1));
	iwr.u.data.flags = SIOCDEV_SUBIO_ERW_ENTRY;
	iwr.u.data.pointer = (caddr_t)req_erw;
	iwr.u.data.length = req_erw->data_len + sizeof(*req_erw);
	printf("%s: req data_len %d\n", __func__, req_erw->data_len);

	if (ioctl(ioctl_sock, IEEE80211_IOCTL_EXT, &iwr) < 0) {
		printf("%s: %s\n", __func__, strerror(errno));
		return -errno;
	}
	if (req_erw->req != IEEE80211_ERW_CONTENT_REQ_GET)
		return 0;


	erw_parse_content_result(req_erw);

	return 0;
}

int map_erw_test(int argc, char *argv[])
{
	struct ieee80211_qrpe_req_erw *req_erw;
	struct ieee80211_req_erw_content_ie *ie = NULL;
	struct ieee80211_req_erw_content_subie *subie = NULL;
	struct ieee80211_req_erw_content *req_content;
	struct ieee80211_req_erw_content_result *req_content_result;

	static char ifname[IFNAMSIZ] = {0};
	char mac_str[BUF_SIZE] = {0};
	char ie_buf[BUF_SIZE] = {0};
	char subie_buf[BUF_SIZE] = {0};
	int c = 0;

	memset(data_buf, '\0', sizeof(data_buf));
	req_erw = (struct ieee80211_qrpe_req_erw *)data_buf;

	req_content = (struct ieee80211_req_erw_content *)req_erw->data;
	req_content_result = (struct ieee80211_req_erw_content_result *)req_erw->data;
	ie = (struct ieee80211_req_erw_content_ie *)&req_content->req_ie;
	subie = (struct ieee80211_req_erw_content_subie *)(req_content->req_ie.req_subie);

	for (c = 0; c < argc; c++)
		DebugPrintf("argv[%d]: %s\n", c, argv[c]);

	if (argc < 3) {
		map_erw_help();
		return -1;
	}
	strncpy(ifname, argv[0], sizeof(ifname) -1);

	strncpy(mac_str, argv[2], sizeof(mac_str) -1);
	if (erw_parse_mac(mac_str, mac_addr)) {
		printf("mac addr invalid\n");
		return -1;
	}

	if (memcmp(argv[1], "add", 3) == 0) {
		req_erw->req = IEEE80211_ERW_CONTENT_REQ_SET;
		memcpy(req_content->mac_addr, mac_addr, ETH_ALEN);
		if (argc < 4) {
			printf("param num not correct when set\n");
			return -1;
		}
		strncpy(ie_buf, argv[3], sizeof(ie_buf) -1);
		erw_parse_ie(ie_buf, strlen(ie_buf), ie);
		ie->num_subie = 0;
		for (c = 4; c < argc && argv[c]; c++) {
			strncpy(subie_buf, argv[c], sizeof(subie_buf) -1);
			erw_parse_subie(subie_buf, strlen(subie_buf), subie);
			ie->num_subie++;
			subie++;
		}
	} else if (memcmp(argv[1], "del", 3) == 0) {
		req_erw->req = IEEE80211_ERW_CONTENT_REQ_REMOVE;
		memcpy(req_content->mac_addr, mac_addr, ETH_ALEN);
		if (argc < 4) {
			printf("param num not correct when remove\n");
			return -1;
		}
		strncpy(ie_buf, argv[3], sizeof(ie_buf) -1);
		erw_parse_ie(ie_buf, strlen(ie_buf), ie);
		ie->num_subie = 0;
		for (c = 4; c < argc && argv[c]; c++) {
			strncpy(subie_buf, argv[c], sizeof(subie_buf) -1);
			erw_parse_subie(subie_buf, strlen(subie_buf), subie);
			ie->num_subie++;
			subie++;
		}
	} else if (memcmp(argv[1], "get", 3) == 0) {
		req_erw->req = IEEE80211_ERW_CONTENT_REQ_GET;
		memcpy(req_content_result->mac_addr, mac_addr, ETH_ALEN);
	} else if (memcmp(argv[1], "clear", 5) == 0) {
		req_erw->req = IEEE80211_ERW_CONTENT_REQ_CLEAR;
		memcpy(req_content->mac_addr, mac_addr, ETH_ALEN);
	} else {
		map_erw_help();
		return -1;
	}

	ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);

	if (ioctl_sock < 0) {
		printf("%s: Failed to create ioctl socket\n", __func__);
		return -1;
	}
	erw_init(ifname);

	if (req_erw->req == IEEE80211_ERW_CONTENT_REQ_GET)
		req_erw->data_len = BUF_SIZE - sizeof(*req_erw);
	else
		req_erw->data_len = sizeof(*req_content) +
			req_content->req_ie.num_subie * sizeof(*subie);

	if (!map_erw_do_ioctl(ifname, req_erw))
		printf("Command execute successfully");

	close(ioctl_sock);
	return 0;
}
