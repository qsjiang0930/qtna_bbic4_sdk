/**
 * Copyright (c) 2016 Quantenna Communications, Inc.
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
 **/

#ifndef QLINK_PRIV_H_
#define QLINK_PRIV_H_

#include <linux/netdevice.h>

#include <net80211/_ieee80211.h>
#include <qdrv/qdrv_mac.h>
#include <qtn/wlan_ioctl.h>

#include <ruby_pcie_bda.h>

#include "qlink.h"
#include "shm_ipc.h"

#define QLINK_MAX_PACKET_SIZE		2048

#define QTNF_MAX_BSS_NUM		QDRV_MAX_BSS_VAPS
#define QTNF_MAX_VSIE_LEN		255
#define QTNF_MAC_NUM			MAC_UNITS
#define QTNF_SCAN_RESULTS_DEFAULT	4096
#define QTNF_SCAN_RESULTS_MAX		65536

#define QLINK_BIP_IPN_LEN		6
#define QLINK_NUM_BIP_KEYS		2


#define QTNF_WOWLAN_MAX_MAGIC_LEN	MAX_USER_DEFINED_MAGIC_LEN

#define MAX_QDRV_CMD 256
#define MAX_DEV_NAME 32

#define QLINK_PHY_FRAG_CHANGED		BIT(0)
#define QLINK_PHY_RTS_CHANGED		BIT(1)
#define QLINK_PHY_CCLASS_CHANGED	BIT(2)
#define QLINK_PHY_SRETRY_CHANGED	BIT(3)
#define QLINK_PHY_LRETRY_CHANGED	BIT(4)

#define QTNF_QVLAN_SCRIPT	"/scripts/qvlan"
#define QTNF_PCIE_IFNAME	"pcie0"
#define QTNF_QBR_IFNAME		"br0"

typedef enum {
	QTN_WMAC_UNIT0 = 0,
	QTN_WMAC_UNIT1 = 1,
	QTN_WMAC_UNIT2 = 2,
} qlink_wmac_unit;

typedef enum {
	QLINK_STATUS_FW_INIT_DONE = BIT(0),
} qlink_server_status;

typedef enum {
	QLINK_BSS_ADDED		= BIT(0),
	QLINK_BSS_STARTED	= BIT(1),
	QLINK_BSS_SCANNING	= BIT(2),
	QLINK_BSS_CONNECTING	= BIT(3),
	QLINK_BSS_RUNNING	= BIT(4),
	QLINK_BSS_IGNORE_NEXTDEAUTH	= BIT(5),
	QLINK_BSS_OWE_PROCESSING	= BIT(7),
	QLINK_BSS_SAE_PROCESSING	= BIT(8),
} qlink_bss_status;

enum qlink_auth_type {
	QLINK_AUTHTYPE_OPEN_SYSTEM,
	QLINK_AUTHTYPE_SHARED_KEY,
	QLINK_AUTHTYPE_FT,
	QLINK_AUTHTYPE_NETWORK_EAP,
	QLINK_AUTHTYPE_SAE,

	/* keep last */
	__QLINK_AUTHTYPE_NUM,
	QLINK_AUTHTYPE_MAX = __QLINK_AUTHTYPE_NUM - 1,
	QLINK_AUTHTYPE_AUTOMATIC
};

enum qlink_del_sta_subtype {
	QLINK_STA_DISASSOC = 10,
	QLINK_STA_DEAUTH = 12
};

enum qlink_external_auth_req {
	QLINK_EXTERNAL_AUTH_START,
	QLINK_EXTERNAL_AUTH_ABORT,
};

struct qlink_mac;

struct qlink_bss {
	struct qlink_mac *mac;
	struct ieee80211vap *vap;
	struct socket *eapol_frame_sock;
	struct work_struct eapol_frame_work;
	int mode;
	u32 status;
	u8 ssid[IEEE80211_MAX_SSID_LEN + 1];
	size_t ssid_len;
	u8 rates[IEEE80211_RATE_SIZE];
	size_t rates_num;
	u8 ds_params;
	u8 mac_addr[ETH_ALEN];
	u8 bssid[IEEE80211_ADDR_LEN];
	struct net_device *dev;
	int bg_scan_period;
	u16 sae_chan_ieee;
	struct crypto_cipher *igtk[QLINK_NUM_BIP_KEYS];
	u8 igtk_ipn[QLINK_NUM_BIP_KEYS][QLINK_BIP_IPN_LEN];
};

struct qlink_phy_params {
	u8 sretry;
	u8 lretry;
	u8 cclass;
	u32 frag_thresh;
	u32 rts_thresh;
};

struct qlink_mac {
	struct net_device *dev;
	struct ieee80211com *ic;
	struct qlink_server *qs;
	struct qlink_bss bss[QTNF_MAX_BSS_NUM];
	struct qlink_phy_params phy;
	bool phyparams_set;
	struct qlink_chandef host_chandef;
};

struct qlink_server {
	struct device *qdrv_dev;
	u32 qs_status;
	int host_tqe_port;
	int host_slave_radar;
	struct qlink_mac maclist[QTNF_MAC_NUM];
	struct mutex mlock;
	struct sk_buff_head cmd_list;
	struct socket *event_sock;
	struct workqueue_struct *workqueue;
	struct work_struct event_work;

	/* SHM IPC via PCIe */
	volatile qdpc_pcie_bda_t *bda;
	struct qlink_shm_ipc shm_ipc_ep_in;
	struct qlink_shm_ipc shm_ipc_ep_out;

	struct net_device *br_dev;
	struct socket *mgmt_frame_sock;
	struct work_struct mgmt_frame_work;
	struct shared_params *sp;

	u16 msi_data;
	u8 pwr_save;
};

struct qlink_scan_freq_list {
	u32 n_freqs;
	u32 freqs[IEEE80211_MAX_DUAL_CHANNELS];
};

int qlink_server_init(struct qlink_server *qs);
void qlink_server_deinit(struct qlink_server *qs);
ssize_t qlink_xmit(void *buf, size_t size);

static inline int bss_has_status(const struct qlink_bss *bss, qlink_bss_status status)
{
	return !!(bss->status & status);
}

static inline int bss_has_status_mask(const struct qlink_bss *bss, u32 status_mask)
{
	return (bss->status & status_mask) == status_mask;
}

static inline void bss_set_status(struct qlink_bss *bss, qlink_bss_status status)
{
	bss->status |= status;
}

static inline void bss_clr_status(struct qlink_bss *bss, qlink_bss_status status)
{
	bss->status &= ~status;
}

#define qlink_for_each_tlv(_tlv, _start, _datalen)			\
	for (_tlv = (const struct qlink_tlv_hdr *)(_start);		\
	     (const u8 *)(_start) + (_datalen) - (const u8 *)_tlv >=	\
		(int)sizeof(*_tlv) &&					\
	     (const u8 *)(_start) + (_datalen) - (const u8 *)_tlv >=	\
		(int)sizeof(*_tlv) + le16_to_cpu(_tlv->len);		\
	     _tlv = (const struct qlink_tlv_hdr *)(_tlv->val +		\
		round_up(le16_to_cpu(_tlv->len), QLINK_ALIGN)))

#define qlink_tlv_parsing_ok(_tlv_last, _start, _datalen)	\
	((const u8 *)(_tlv_last) == \
		(const u8 *)(_start) + round_up(_datalen, QLINK_ALIGN))

#endif /* QLINK_PRIV_H_ */
