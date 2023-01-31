/*
 *		qserver_frame.h
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


#ifndef QSERVER_FRAME_H
#define QSERVER_FRAME_H

#include "list.h"
#include "l2_packet.h"
#include "qtn/qvsp_data.h"

#include <net/if.h>
#include <net80211/ieee80211_qos.h>

#define	QTN_OUI 0x862600		/* Quantenna OUI */
#define QTN_ETH_P_ETHER_802A 0x88b7	/* qserver specific raw frames comes under this category */
#define QTN_OUIE_TYPE_QSERVER 0x2	/* qserver specific raw frames */

#define QTN_SSID_LEN		32
#define QTN_PASSWORD_MIN_LEN	8
#define QTN_PASSWORD_MAX_LEN	64
#define QTN_QTM_MAX_RULES       64
#define QTN_QTM_MAX_LEN         (QVSP_RULE_PARAM_MAX * QTN_QTM_MAX_RULES)
#define QTN_PMF_MAX_LEN		1
#define QTN_MDID_MAX_LEN	17

#define QSERVER_FRAME_BUF_SIZE 2048
#define QSERVER_FRAME_RETRY_COUNT 2	/* retry times */
#define QSERVER_FRAME_RETRY_INTER 2	/* Timeout time (second unit) for frame retry */

enum attritute_type
{
	QEV_ATTR_QTM = 0,
	QEV_ATTR_BSS_IFINDEX = 1,
	QEV_ATTR_BSS_BAND = 2,
	QEV_ATTR_BSS_SSID = 3,
	QEV_ATTR_BSS_SECURITY = 4,
	QEV_ATTR_BSS_PASSWORD = 5,
	QEV_ATTR_BSS_REKEY_INTV = 6,
	QEV_ATTR_BSS_PRIORITY = 7,
	QEV_ATTR_BSS_WMM_OWN = 8,
	QEV_ATTR_BSS_WMM_BSS = 9,
	QEV_ATTR_BSS_PMF = 10,
	QEV_ATTR_BSS_MAC_ADDR = 11,
	QEV_ATTR_BSS_MDID = 12,
	/* must be last one */
	QEV_ATTR_BSS_EXT = 0xff,
};

enum attribute_band_type
{
	QEV_BAND_INVALID = 0,
	QEV_BAND_5G_LOW = 1,
	QEV_BAND_5G_HIGH = 2,
	QEV_BAND_5G = 3,
	QEV_BAND_24G = 4,
};

enum attribute_key_mgmt_type
{
	QEV_KM_NONE = 0,
	QEV_KM_WPA_PSK = 1,
	QEV_KM_WPA_EAP = 2,
	QEV_KM_WPA_PSK_SHA256 = 3,
	QEV_KM_WPA_PSK_MIXED = 4,
	QEV_KM_SAE = 5,
	QEV_KM_OWE = 6,
	QEV_KM_SAE_TRANSITION = 7,
	QEV_KM_INVALID = 0xff,
};

enum attribute_proto_type
{
	QEV_PT_NONE = 0,
	QEV_PT_WPA = 1,
	QEV_PT_RSN = 2,
	QEV_PT_WPA_RSN = 3,
	QEV_PT_INVALID = 0xff,
};

enum attribute_encrypt_type
{
	QEV_EP_NONE = 0,
	QEV_EP_WEP40 = 1,
	QEV_EP_WEP104 = 2,
	QEV_EP_TKIP = 3,
	QEV_EP_CCMP = 4,
	QEV_EP_TKIP_CCMP = 5,
	QEV_EP_INVALID = 0xff,
};

struct security_filed_entry
{
	uint8_t index;

	char *wpa_supp_str;
	char *hostapd_str;
	char *qcsapi_str;
};

struct attr_ifindex
{
	uint16_t type;
	uint16_t len;
	uint8_t index;
} __attribute__ ((packed));

struct attr_band
{
	uint16_t type;
	uint16_t len;
	uint8_t band;
} __attribute__ ((packed));

struct attr_ssid
{
	uint16_t type;
	uint16_t len;
	char ssid[QTN_SSID_LEN];
} __attribute__ ((packed));

struct attr_security
{
	uint16_t type;
	uint16_t len;
	uint8_t key_mgmt;
	uint8_t proto;
	uint8_t pairwise;
} __attribute__ ((packed));

struct attr_password
{
	uint16_t type;
	uint16_t len;
	uint8_t pwd[QTN_PASSWORD_MAX_LEN];
} __attribute__ ((packed));


#define QEV_INVALID_REKEY_TIME	(-1)

struct attr_rekey_intv
{
	uint16_t type;
	uint16_t len;
	uint8_t pairwise[4];
	uint8_t group[4];
} __attribute__ ((packed));

struct attr_priority
{
	uint16_t type;
	uint16_t len;
	uint8_t pri;
} __attribute__ ((packed));

struct attr_wmm_params
{
	uint16_t  type;
	uint16_t  len;
	uint8_t  logcwmin[WME_AC_NUM];
	uint8_t  logcwmax[WME_AC_NUM];
	uint8_t  aifsn[WME_AC_NUM];
	uint16_t txopLimit[WME_AC_NUM];
	uint8_t  acm[WME_AC_NUM];
	uint8_t  noackPolicy[WME_AC_NUM];
} __attribute__ ((packed));

struct attr_qtm
{
	uint16_t type;
	uint16_t len;
	int32_t  cfg[QVSP_CFG_MAX];
	int32_t  nr_rules;
	int32_t  rule[QTN_QTM_MAX_LEN];
} __attribute__ ((packed));

struct attr_pmf
{
	uint16_t type;
	uint16_t len;
	uint8_t pmf;
} __attribute__ ((packed));

struct attr_mac_addr
{
	uint16_t type;
	uint16_t len;
	uint8_t mac_addr[ETH_ALEN];
} __attribute__ ((packed));

struct attr_mdid
{
	uint16_t type;
	uint16_t len;
	char mdid[QTN_MDID_MAX_LEN];
} __attribute__ ((packed));

enum qserver_frame_type
{
	QSERVER_QUERY_FRAME = 0,
	QSERVER_UPDATE_FRAME = 1,
	QSERVER_ACK_FRAME = 2,
	QSERVER_UNKNOWN_FRAME = 3,
};

struct qserver_bss_params
{
	/* TLVs */
	uint8_t *ifidx;
	uint8_t *band;
	uint8_t *ssid;
	uint8_t *sec;
	uint8_t *pwd;
	uint8_t *rekey;
	uint8_t *pri;
	uint8_t *wmm_own;
	uint8_t *wmm_bss;
	uint8_t *pmf;
	uint8_t *mac_addr;
	uint8_t	*mdid;
	uint8_t *ext;
};

struct qserver_device_params
{
	uint8_t *qtm;

	int num;
	struct qserver_bss_params *bss;
};

struct qserver_frm_params
{
	uint8_t *sa;
	uint8_t *da;
	uint8_t type;
	uint16_t len;
	uint32_t seq;
	uint8_t role;
	uint8_t state;

	struct qserver_device_params device;
};

struct oui_ext_ethtype
{
	uint8_t oui[3];
	uint16_t type;
} __attribute__ ((packed));

struct qserver_frm_header
{
	struct l2_ethhdr ethhdr;
	struct oui_ext_ethtype ouie;

	uint8_t type;
	uint8_t len[2];
	uint8_t seq[4];
	uint8_t role;
	uint8_t state;
	uint8_t buf[0];
} __attribute__ ((packed));

struct qserver_frm_rty
{
	int count;
	int timer;

	int frm_type;
	int frm_len;
	uint8_t *frame;
};

enum qserver_frm_state
{
	SEND_QUERY = 0,
	RECV_QUERY = 1,
	SEND_UPDATE = 2,
	RECV_UPDATE = 3,
	SEND_ACK = 4,
	RECV_ACK = 5,
};

struct qserver_frame_data
{
	void *ctx;	/* back pointer */

	char ifname[IFNAMSIZ + 1];
	char brname[IFNAMSIZ + 1];

	struct l2_packet_data *l2;
	struct qserver_frm_rty rty;
	int state;

	int polling_timer;
	uint8_t polling_dest[ETH_ALEN];

	struct qserver_device_params *params;
};

static inline uint16_t tlv_build_type(uint16_t type)
{
	uint16_t retval;

	OS_PUT_LE16((uint8_t *)&retval, type);
	return retval;
}

static inline uint16_t tlv_build_vlen(uint16_t vlen)
{
	uint16_t retval;

	OS_PUT_LE16((uint8_t *)&retval, vlen);
	return retval;
}

static inline uint16_t tlv_get_type(const uint8_t *tlv)
{
	return OS_GET_LE16(tlv);
}

static inline uint16_t tlv_get_vlen(const uint8_t *tlv)
{
	return OS_GET_LE16(tlv + 2);
}

#define TLV_LEN(a) (tlv_get_vlen(a) + 4)

static inline char *
qserver_frame_type_str(int frame)
{
	char *frm_str;

	switch (frame) {
	case QSERVER_QUERY_FRAME:
		frm_str = "query";
		break;
	case QSERVER_UPDATE_FRAME:
		frm_str = "update";
		break;
	case QSERVER_ACK_FRAME:
		frm_str = "ack";
		break;
	default:
		frm_str = "unknown";
		break;
	}

	return frm_str;
}

int qserver_store_device_params(struct qserver_frame_data *frm_data,
	struct qserver_device_params *device);
void qserver_free_device_params(struct qserver_device_params *params);
int qserver_send_query_frame(struct qserver_frame_data *frm_data,
		uint8_t *dest_mac);
int qserver_start_query_polling(struct qserver_frame_data *frm_data,
		uint8_t *dest_mac, int interval);
int qserver_stop_query_polling(struct qserver_frame_data *frm_data,
		uint8_t *dest_mac);
int qserver_raw_frame_init(struct qserver_frame_data *frm_data,
		const char *ifname, void *ctx);
void qserver_raw_frame_deinit(struct qserver_frame_data *frm_data);

#endif /* QSERVER_FRAME_H */
