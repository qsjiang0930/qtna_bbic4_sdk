/*
 * WPA Supplicant - driver interaction with MADWIFI 802.11 driver
 * Copyright (c) 2004, Sam Leffler <sam@errno.com>
 * Copyright (c) 2004, Video54 Technologies
 * Copyright (c) 2004-2007, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 *
 * While this driver wrapper supports both AP (hostapd) and station
 * (wpa_supplicant) operations, the station side is deprecated and
 * driver_wext.c should be used instead. This driver wrapper should only be
 * used with hostapd for AP mode functionality.
 */

#ifdef CONFIG_QTNA_WIFI

#include "includes.h"
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include "common.h"
#include "driver.h"
#include "driver_wext.h"
#include "eloop.h"
#include "common/ieee802_11_defs.h"
#include "linux_wext.h"

#include "ap/hostapd.h"
#include "ap/ap_config.h"
#include "ap/ieee802_11_auth.h"
#include "ap/wps_hostapd.h"
#include "crypto/crypto.h"
#include "qtn_hapd/qtn_hapd_bss.h"
#include "qtn_hapd/qtn_hapd_pp.h"

#ifndef HOSTAPD
#include "wpa_supplicant_i.h"
#include "utils/os.h"
#endif /* HOSTAPD */

/*
 * Avoid conflicts with wpa_supplicant definitions by undefining a definition.
 */
#undef WME_OUI_TYPE

#include <net80211/ieee80211.h>
#include <net80211/ieee80211_crypto.h>
#include <net80211/ieee80211_ioctl.h>

#include "crypto/aes_wrap.h"
#include <netpacket/packet.h>
#include "priv_netlink.h"
#include "netlink.h"
#include "linux_ioctl.h"
#include "l2_packet/l2_packet.h"
#ifndef ETH_P_80211_RAW
#define ETH_P_80211_RAW 0x0019
#endif

/*
 * Avoid conflicts with hostapd definitions by undefining couple of defines
 * from madwifi header files.
 */
#undef RSN_VERSION
#undef WPA_VERSION
#undef WPA_OUI_TYPE
#undef WME_OUI_TYPE

#define WPA_KEY_RSC_LEN			8

#define WPA_MADWIFI_FIRST_2G4_CHAN	1
#define WPA_MADWIFI_LAST_2G4_CHAN	14
#define WPA_MADWIFI_FIRST_5G_CHAN	36
#define WPA_MADWIFI_LAST_5G_CHAN	169

#define QTN_MADWIFI_11A_RATES_NUM	8
#define QTN_MADWIFI_11B_RATES_NUM	4
#define QTN_MADWIFI_11G_RATES_NUM	12


#ifdef HOSTAPD

#include "priv_netlink.h"
#include "netlink.h"
#include "linux_ioctl.h"
#include "l2_packet/l2_packet.h"
#include "utils/list.h"

#define MADWIFI_CMD_BUF_SIZE		128
#define MADWIFI_CMD_WDS_EXT_LEN		256
#define QTN_DRV_CONTROL_FILE		"/sys/devices/qdrv/control"

struct madwifi_bss {
	struct madwifi_driver_data	*drv;
	struct dl_list			list;

	void	*bss_ctx;
	char	ifname[IFNAMSIZ];
	int	ifindex;
	u8	bssid[ETH_ALEN];
	char	brname[IFNAMSIZ];
	u8	acct_mac[ETH_ALEN];
	int	added_if_into_bridge;
	int	sock_ioctl;	/* socket for ioctl() use */

	struct hostap_sta_driver_data	acct_data;
	struct netlink_data		*netlink;

	struct l2_packet_data	*sock_xmit;	/* raw packet xmit socket */
	struct l2_packet_data	*sock_recv;	/* raw packet recv socket */
	struct l2_packet_data	*sock_raw;	/* raw 802.11 management frames */
};

#else
#define IEEE80211_IOCTL_POSTEVENT	(SIOCIWFIRSTPRIV+19)
#define BIP_AAD_LEN			20
#define IEEE80211_3ADDR_LEN		24
#define BIP_MIC_LEN			8
#define BIP_IPN_LEN			6

#ifdef CONFIG_TDLS
/* This must be kept in sync with action field value. */
char *tdls_action_string[] = {
	"TDLS_SETUP_REQUEST",
	"TDLS_SETUP_RESPONSE",
	"TDLS_SETUP_CONFIRM",
	"TDLS_TEARDOWN",
	"TDLS_PEER_TRAFFIC_INDICATION",
	"TDLS_CHANNEL_SWITCH_REQUEST",
	"TDLS_CHANNEL_SWITCH_RESPONSE",
	"TDLS_PEER_PSM_REQUEST",
	"TDLS_PEER_PSM_RESPONSE",
	"TDLS_PEER_TRAFFIC_RESPONSE",
	"TDLS_DISCOVERY_REQUEST",
	"",
	"",
	"",
	"TDLS_DISCOVERY_RESPONSE"
};

/* This must be kept in sync with ieee80211_tdls_operation. */
char *tlds_operation_string[] = {
	"TDLS_DISCOVERY_REQ",
	"TDLS_SETUP",
	"TDLS_TEARDOWN",
	"TDLS_ENABLE_LINK",
	"TDLS_DISABLE_LINK",
	"TDLS_ENABLE",
	"TDLS_DISABLE",
	"TDLS_SWITCH_CHAN",
};
#endif /* CONFIG_TDLS */
#endif /* HOSTAPD */

struct madwifi_driver_data {
#ifdef HOSTAPD
	struct dl_list	bss;
	int	we_version;
	u8	*extended_capa;
	u8	*extended_capa_mask;
	u8	extended_capa_len;
#else
	void	*wext; /* private data for driver_wext */
	void	*ctx;
	char	ifname[IFNAMSIZ + 1];
	int	sock_ioctl;
	char	ipn[BIP_IPN_LEN];
	pid_t	hostapd_pid;

	struct l2_packet_data	*sock_raw;	/* raw 802.11 management frames */
	struct ieee80211req_key	drv_igtk_wk;
#endif /* HOSTAPD */
};

char *drv_ioctl_names[] = {
	"ioctl[IEEE80211_IOCTL_SETPARAM]",
	"ioctl[IEEE80211_IOCTL_GETPARAM]",
	"ioctl[IEEE80211_IOCTL_SETMODE]",
	"ioctl[IEEE80211_IOCTL_GETMODE]",
	"ioctl[IEEE80211_IOCTL_SETWMMPARAMS]",
	"ioctl[IEEE80211_IOCTL_GETWMMPARAMS]",
	"ioctl[IEEE80211_IOCTL_SETCHANLIST]",
	"ioctl[IEEE80211_IOCTL_GETCHANLIST]",
	"ioctl[IEEE80211_IOCTL_CHANSWITCH]",
	"ioctl[IEEE80211_IOCTL_GET_APPIEBUF]",
	"ioctl[IEEE80211_IOCTL_SET_APPIEBUF]",
	"ioctl[unknown???]",
	"ioctl[IEEE80211_IOCTL_FILTERFRAME]",
	"ioctl[IEEE80211_IOCTL_GETCHANINFO]",
	"ioctl[IEEE80211_IOCTL_SETOPTIE]",
	"ioctl[IEEE80211_IOCTL_GETOPTIE]",
	"ioctl[IEEE80211_IOCTL_SETMLME]",
	"ioctl[IEEE80211_IOCTL_RADAR]",
	"ioctl[IEEE80211_IOCTL_SETKEY]",
	"ioctl[IEEE80211_IOCTL_POSTEVENT]",
	"ioctl[IEEE80211_IOCTL_DELKEY]",
	"ioctl[IEEE80211_IOCTL_TXEAPOL]",
	"ioctl[IEEE80211_IOCTL_ADDMAC]",
	"ioctl[IEEE80211_IOCTL_STARTCCA]",
	"ioctl[IEEE80211_IOCTL_DELMAC]",
	"ioctl[IEEE80211_IOCTL_GETSTASTATISTIC]",
	"ioctl[IEEE80211_IOCTL_WDSADDMAC]",
	"ioctl[IEEE80211_IOCTL_WDSDELMAC]",
	"ioctl[IEEE80211_IOCTL_GETBLOCK]",
	"ioctl[IEEE80211_IOCTL_KICKMAC]",
	"ioctl[IEEE80211_IOCTL_DFSACTSCAN]",
};


static void
__madwifi_print_ioctl_error(int op)
{
	int first_ioctl = IEEE80211_IOCTL_SETPARAM;
	int no_of_ioctls = (int)ARRAY_SIZE(drv_ioctl_names);
	const char *ioctl_name;

	if ((op >= first_ioctl) && (op < (first_ioctl + no_of_ioctls)))
		ioctl_name = drv_ioctl_names[op - first_ioctl];
	else
		ioctl_name = "ioctl[unknown???]";

	wpa_printf(MSG_DEBUG, "%s: op 0x%#x returned error %d: %s\n",
			ioctl_name, op, errno, strerror(errno));
}

static int
__madwifi_set80211priv(void *priv, int op, void *data, int len)
{
	struct iwreq iwr;
#ifdef HOSTAPD
	struct madwifi_bss *ctxt = (struct madwifi_bss *)priv;
#else
	struct madwifi_driver_data *ctxt = (struct madwifi_driver_data *)priv;
#endif
	int sock = ctxt->sock_ioctl;

	os_memset(&iwr, 0, sizeof(iwr));

	os_strlcpy(iwr.ifr_name, ctxt->ifname, IFNAMSIZ);

	if ((len < IFNAMSIZ) &&
		((op != IEEE80211_IOCTL_FILTERFRAME) &&
		 (op != IEEE80211_IOCTL_SET_APPIEBUF) &&
		 (op != IEEE80211_IOCTL_POSTEVENT) &&
		 (op != IEEE80211_IOCTL_TXEAPOL))) {
		/* Argument data fits inline; put it there */
		os_memcpy(iwr.u.name, data, len);
	} else {
		/*
		 * Argument data too big for inline transfer; setup a
		 * parameter block instead; the kernel will transfer
		 * the data for the driver.
		 */
		iwr.u.data.pointer = data;
		iwr.u.data.length = len;
	}

	if (ioctl(sock, op, &iwr) < 0) {
		__madwifi_print_ioctl_error(op);
		return -1;
	}
	return 0;
}

static int
__madwifi_get80211param(void *priv, int op, int *value)
{
	struct iwreq iwr;
#ifdef HOSTAPD
	struct madwifi_bss *ctxt = (struct madwifi_bss *)priv;
#else
	struct madwifi_driver_data *ctxt = (struct madwifi_driver_data *)priv;
#endif
	int sock = ctxt->sock_ioctl;

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, ctxt->ifname, IFNAMSIZ);
	iwr.u.mode = op;

	if (ioctl(sock, IEEE80211_IOCTL_GETPARAM, &iwr) < 0) {
		wpa_printf(MSG_ERROR, "%s: Failed to get parameter (op %d)", __func__, op);
		return -1;
	}

	*value = (int)iwr.u.mode;

	return 0;
}

void wpa_driver_wext_process_event_tx_status(struct qtn_tx_status_event_data *event_data,
					union wpa_event_data *data)
{
	struct ieee80211_frame *frm = (void *)&event_data->hdr;

	os_memset(data, 0, sizeof(*data));
	data->tx_status.type = frm->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
	data->tx_status.stype = (frm->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) >>
					IEEE80211_FC0_SUBTYPE_SHIFT;
	data->tx_status.dst = frm->i_addr1;
	data->tx_status.data = (uint8_t *)frm;
	data->tx_status.data_len = event_data->payload_len + sizeof(*frm);
	data->tx_status.ack = event_data->tx_status;

	wpa_printf(MSG_DEBUG, "WEXT: TXSTATUS: dst=" MACSTR "fc type=%#x, subtype=%#x",
			MAC2STR(data->tx_status.dst), data->tx_status.type,
			data->tx_status.stype);

}

static int
__madwifi_set80211param(void *priv, int op, int arg)
{
	struct iwreq iwr;
#ifdef HOSTAPD
	struct madwifi_bss *ctxt = (struct madwifi_bss *)priv;
#else
	struct madwifi_driver_data *ctxt = (struct madwifi_driver_data *)priv;
#endif
	int sock = ctxt->sock_ioctl;

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, ctxt->ifname, IFNAMSIZ);
	iwr.u.mode = op;
	os_memcpy(iwr.u.name+sizeof(u32), &arg, sizeof(arg));

	if (ioctl(sock, IEEE80211_IOCTL_SETPARAM, &iwr) < 0) {
		__madwifi_print_ioctl_error(IEEE80211_IOCTL_SETPARAM);
		return -1;
	}
	return 0;
}


static const char *
__madwfi_ether_sprintf(const u8 *addr)
{
	static char buf[sizeof(MACSTR)];

	if (addr != NULL)
		snprintf(buf, sizeof(buf), MACSTR, MAC2STR(addr));
	else
		snprintf(buf, sizeof(buf), MACSTR, 0,0,0,0,0,0);
	return buf;
}


#ifdef HOSTAPD
static int
__madwifi_del_key(void *priv, const u8 *addr, int key_idx)
{
	struct ieee80211req_del_key wk;
	int ret;

	wpa_printf(MSG_DEBUG, "%s: addr=%s key_idx=%d",
		   __func__, __madwfi_ether_sprintf(addr), key_idx);

	os_memset(&wk, 0, sizeof(wk));
	if (addr != NULL) {
		os_memcpy(wk.idk_macaddr, addr, IEEE80211_ADDR_LEN);
		wk.idk_keyix = (u8) IEEE80211_KEYIX_NONE;
	} else {
		wk.idk_keyix = key_idx;
		os_memset(wk.idk_macaddr, 0xff, IEEE80211_ADDR_LEN);
	}

	ret = __madwifi_set80211priv(priv, IEEE80211_IOCTL_DELKEY, &wk, sizeof(wk));
	if (ret < 0) {
		wpa_printf(MSG_ERROR, "%s: Failed to delete key (addr %s key_idx %d)",
				__func__, __madwfi_ether_sprintf(addr), key_idx);
	}

	return ret;
}
#endif /* HOSTAPD */


static int
madwifi_set_key(const char *ifname, void *priv, enum wpa_alg alg,
			   const u8 *addr, int key_idx, int set_tx,
			   const u8 *seq, size_t seq_len,
			   const u8 *key, size_t key_len)
{
	struct ieee80211req_key wk;
	u_int8_t	cipher;
	int		ret = 0;
#ifdef HOSTAPD
	const char	*vlanif;
	int		vlanid;
#else
	struct madwifi_driver_data *drv = priv;
#endif /* HOSTAPD */

	wpa_printf(MSG_DEBUG, "%s: alg=%d addr=%s key_idx=%d, set_tx=%d, seq_len=%d, key_len=%d",
			__func__, alg, __madwfi_ether_sprintf(addr), key_idx,
			set_tx, (int)seq_len, (int)key_len);
	if (alg != WPA_ALG_NONE)
		wpa_hexdump_key(MSG_DEBUG, "set-key", key, key_len);

	switch (alg) {
	case WPA_ALG_NONE:
#ifdef HOSTAPD
		ret = __madwifi_del_key(priv, addr, key_idx);
#else
		/* Keys cleared at init and disassociate, so no need to do them here */
		if (key_idx == 4 || key_idx == 5)
			os_memset(&drv->drv_igtk_wk, 0, sizeof(wk));  /* Clear bip key */
#endif /* HOSTAPD */
		return ret;
	case WPA_ALG_WEP:
#ifndef HOSTAPD
		if ((addr == NULL) ||
			(os_memcmp(addr, "\xff\xff\xff\xff\xff\xff", ETH_ALEN) == 0)) {
				/*
				 * madwifi did not seem to like static WEP key
				 * configuration with IEEE80211_IOCTL_SETKEY, so use
				 * Linux wireless extensions ioctl for this.
				 */
				return wpa_driver_wext_set_key(ifname, drv->wext, alg,
						addr, key_idx, set_tx, seq, seq_len,
						key, key_len);
		}
#endif /* HOSTAPD */
		cipher = IEEE80211_CIPHER_WEP;
		break;
	case WPA_ALG_TKIP:
		cipher = IEEE80211_CIPHER_TKIP;
		break;
	case WPA_ALG_CCMP:
		cipher = IEEE80211_CIPHER_AES_CCM;
		break;
	case WPA_ALG_IGTK:
		cipher = IEEE80211_CIPHER_AES_CMAC;
		break;
	default:
		wpa_printf(MSG_ERROR, "%s: unknown/unsupported algorithm %d",
			__func__, alg);
		return -1;
	}

	if (seq_len > sizeof(u_int64_t)) {
		wpa_printf(MSG_ERROR, "%s: seq_len %lu too big",
			   __func__, (unsigned long) seq_len);
		return -2;
	}

	if (key_len > sizeof(wk.ik_keydata)) {
		wpa_printf(MSG_ERROR, "%s: key length %lu too big\n", __func__,
		       (unsigned long) key_len);
		return -3;
	}

	os_memset(&wk, 0, sizeof(wk));
	wk.ik_type = cipher;
	wk.ik_flags = IEEE80211_KEY_RECV;

#ifdef HOSTAPD
	wk.ik_flags |= IEEE80211_KEY_XMIT;
	if (addr == NULL || is_broadcast_ether_addr(addr)) {
		os_memset(wk.ik_macaddr, 0xff, IEEE80211_ADDR_LEN);
		wk.ik_keyix = key_idx;
		wk.ik_flags |= IEEE80211_KEY_DEFAULT;
	} else {
		os_memcpy(wk.ik_macaddr, addr, IEEE80211_ADDR_LEN);
		wk.ik_keyix = IEEE80211_KEYIX_NONE;
	}

	vlanif = strstr(ifname, "vlan");
	if (vlanif) {
		ret = sscanf(ifname, "vlan%d", &vlanid);
		if (ret != 1) {
			wpa_printf(MSG_ERROR, "%s: invalid vlanid", __func__);
			return -1;
		}
		os_memset(wk.ik_macaddr, 0xff, IEEE80211_ADDR_LEN);
		wk.ik_vlan = (uint16_t)vlanid;
		wk.ik_flags |= (IEEE80211_KEY_VLANGROUP | IEEE80211_KEY_GROUP);
	}
#else
	if (addr == NULL ||
	    os_memcmp(addr, "\xff\xff\xff\xff\xff\xff", ETH_ALEN) == 0)
		wk.ik_flags |= IEEE80211_KEY_GROUP;
	if (set_tx) {
		wk.ik_flags |= IEEE80211_KEY_XMIT | IEEE80211_KEY_DEFAULT;
		os_memcpy(wk.ik_macaddr, addr, IEEE80211_ADDR_LEN);
	} else {
		os_memset(wk.ik_macaddr, 0, IEEE80211_ADDR_LEN);
	}
	wk.ik_keyix = key_idx;

	if (seq) {
#ifdef WORDS_BIGENDIAN
		size_t i;
		u8 tmp[WPA_KEY_RSC_LEN];

		os_memset(tmp, 0, sizeof(tmp));
		for (i = 0; i < seq_len; i++)
			tmp[WPA_KEY_RSC_LEN - i - 1] = seq[i];
		os_memcpy(&wk.ik_keyrsc, tmp, WPA_KEY_RSC_LEN);
#else
		os_memcpy(&wk.ik_keyrsc, seq, seq_len);
#endif /* WORDS_BIGENDIAN */
	}

#endif /* HOSTAPD */

	/* FIXME:  Commenting out for compilation */
	/* wk.ik_keyrsc = seq; */

	wk.ik_keylen = key_len;
	os_memcpy(wk.ik_keydata, key, key_len);

#ifndef HOSTAPD
	/* save IGTK in driver context for BIP processing */
	if (alg == WPA_ALG_IGTK)
		os_memcpy(&drv->drv_igtk_wk, &wk, sizeof(wk));
#endif /* HOSTAPD */

	ret = __madwifi_set80211priv(priv, IEEE80211_IOCTL_SETKEY, &wk, sizeof(wk));
	if (ret < 0) {
		wpa_printf(MSG_ERROR,
			"%s: Failed to set key (addr=%s key_idx=%d alg=%d key_len=%lu set_tx=%d)",
			__func__, __madwfi_ether_sprintf(wk.ik_macaddr),
			key_idx, alg, (unsigned long) key_len, set_tx);
	}

	return ret;
}


static int madwifi_set_pairing_hash_ie(void *priv, const u8 *pairing_hash,
							size_t ies_len)
{
	struct ieee80211req_getset_appiebuf *pairing_hash_ie;
	int ret = 0;

	wpa_printf(MSG_DEBUG, "%s: ies_len=%d", __func__, (int)ies_len);

	pairing_hash_ie = os_zalloc(sizeof(*pairing_hash_ie) + ies_len);
	if (pairing_hash_ie == NULL)
		return -1;

#ifdef HOSTAPD
	pairing_hash_ie->app_frmtype = IEEE80211_APPIE_FRAME_ASSOC_RESP;
#else
	pairing_hash_ie->app_frmtype = IEEE80211_APPIE_FRAME_ASSOC_REQ;
#endif
	pairing_hash_ie->app_buflen = ies_len;
	pairing_hash_ie->flags = F_QTN_IEEE80211_PAIRING_IE;
	os_memcpy(pairing_hash_ie->app_buf, pairing_hash, ies_len);

	ret = __madwifi_set80211priv(priv, IEEE80211_IOCTL_SET_APPIEBUF, pairing_hash_ie,
			   sizeof(struct ieee80211req_getset_appiebuf) +
			   ies_len);

	os_free(pairing_hash_ie);

	return ret;
}


static int
madwifi_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr,
		   int reason_code)
{
#ifdef HOSTAPD
	struct madwifi_bss *ctxt = (struct madwifi_bss *)priv;
#else
	struct madwifi_driver_data *ctxt = (struct madwifi_driver_data *)priv;
#endif
	int sock = ctxt->sock_ioctl;
	struct ieee80211req_mlme mlme;
	int ret;

	if (priv == NULL)
		return 0;

	if (sock < 0)
		return -1;

	if (!linux_iface_up(sock, ctxt->ifname)) {
		wpa_printf(MSG_ERROR, "%s: Interface not up.", __func__);
		return 0;
	}

	wpa_printf(MSG_DEBUG, "%s: addr=%s reason_code=%d",
		   __func__, __madwfi_ether_sprintf(addr), reason_code);

	mlme.im_op = IEEE80211_MLME_DEAUTH;
	mlme.im_reason = reason_code;
	os_memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
	ret = __madwifi_set80211priv(priv, IEEE80211_IOCTL_SETMLME, &mlme, sizeof(mlme));
	if (ret < 0) {
		wpa_printf(MSG_ERROR, "%s: Failed to deauth STA (addr " MACSTR
			   " reason %d)",
			   __func__, MAC2STR(addr), reason_code);
	}

	return ret;
}


static int __madwifi_send_assoc_resp(void *priv, const u8 *data,
					size_t data_len, int reassoc)
{
#ifdef HOSTAPD
	struct madwifi_bss *ctxt = (struct madwifi_bss *)priv;
#else
	struct madwifi_driver_data *ctxt = (struct madwifi_driver_data *)priv;
#endif
	int sock = ctxt->sock_ioctl;
	struct iwreq iwr;
	int ret = 0;
	u8 *buf = NULL;

	wpa_printf(MSG_DEBUG, "%s: reassoc=%d", __func__, reassoc);

	buf = os_malloc(data_len);
	if (!buf)
		return -ENOMEM;

	os_memcpy(buf, data, data_len);

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, ctxt->ifname, IFNAMSIZ);
	if (reassoc)
		iwr.u.data.flags = SIOCDEV_SUBIO_SET_REASSOC_RESP;
	else
		iwr.u.data.flags = SIOCDEV_SUBIO_SET_ASSOC_RESP;
	iwr.u.data.pointer = buf;
	iwr.u.data.length = data_len;

	if (ioctl(sock, IEEE80211_IOCTL_EXT, &iwr) < 0) {
		wpa_printf(MSG_ERROR, "%s: Failed to send assoc resp", __func__);
		ret = -1;
	}

	os_free(buf);
	return ret;
}


/* To send Auth Req/Resp frames */
static int  __madwifi_send_auth_frame(void *priv, const u8 *data, size_t data_len)
{
#ifdef HOSTAPD
	struct madwifi_bss *ctxt = (struct madwifi_bss *)priv;
#else
	struct madwifi_driver_data *ctxt = (struct madwifi_driver_data *)priv;
#endif
	int sock = ctxt->sock_ioctl;

	struct iwreq iwr;
	int ret = 0;
	u8 *buf = NULL;

	wpa_printf(MSG_DEBUG, "%s: data_len=%d", __func__, (int)data_len);

	buf = os_malloc(data_len);
	if (!buf)
		return -ENOMEM;

	os_memcpy(buf, data, data_len);

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, ctxt->ifname, IFNAMSIZ);
	iwr.u.data.flags = SIOCDEV_SUBIO_SET_AUTH;
	iwr.u.data.pointer = buf;
	iwr.u.data.length = data_len;

	if (ioctl(sock, IEEE80211_IOCTL_EXT, &iwr) < 0) {
		wpa_printf(MSG_ERROR, "%s: ioctl failed", __func__);
		ret = -1;
	}

	os_free(buf);
	return ret;
}


#ifdef HOSTAPD
/*
 * app_buf = [struct app_action_frm_buf] + [Action Frame Payload]
 * Action Frame Payload = WLAN_ACTION_PUBLIC (u8) + action (u8) + dialog token (u8) +
 * status code (u8) + Info
 */
static int
madwifi_hostapd_send_action(void *priv, unsigned int freq,
			unsigned int wait_time, const u8 *dst_mac, const u8 *src_mac,
			const u8 *bssid, const u8 *data, size_t data_len, int no_cck)
{
	struct madwifi_bss *bss = priv;
	struct iwreq iwr;
	struct app_action_frame_buf *app_action_frm_buf;
	int ret = 0;

	wpa_printf(MSG_DEBUG, "%s:", __func__);

	app_action_frm_buf = os_malloc(data_len  + sizeof(struct app_action_frame_buf));
	if (!app_action_frm_buf) {
		wpa_printf(MSG_ERROR, "%s: malloc failed", __func__);
		return -1;
	}

	/*
	 * data is Action frame payload. First byte of the data is action frame category
	 * and the second byte is action
	 */
	app_action_frm_buf->cat = *data;
	app_action_frm_buf->action = *(data + 1);
	os_memcpy(app_action_frm_buf->dst_mac_addr, dst_mac, ETH_ALEN);

	app_action_frm_buf->frm_payload.length = (u16)data_len;
	os_memcpy(app_action_frm_buf->frm_payload.data, data, data_len);

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, bss->ifname, IFNAMSIZ);
	iwr.u.data.flags = SIOCDEV_SUBIO_SEND_ACTION_FRAME;
	iwr.u.data.pointer = app_action_frm_buf;
	iwr.u.data.length = data_len + sizeof(struct app_action_frame_buf);

	if (ioctl(bss->sock_ioctl, IEEE80211_IOCTL_EXT, &iwr) < 0) {
		wpa_printf(MSG_ERROR, "%s: ioctl failed", __func__);
		ret = -1;
	}

	os_free(app_action_frm_buf);

	return ret;
}

#endif /* HOSTAPD */

static int madwifi_send_mlme(void *priv, const u8 *msg, size_t len, int noack,
		unsigned int freq, const u16 *csa_offs, size_t csa_offs_len)
{
#ifdef HOSTAPD
	struct madwifi_bss *bss = priv;
#endif
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)msg;
	uint16_t fc;

	wpa_printf(MSG_DEBUG, "%s: len=%d", __func__, (int)len);

	if (!priv || !msg)
		return -1;

	wpa_hexdump(MSG_DEBUG, "madwifi_send_mlme", msg, len);

	if (len < offsetof(struct ieee80211_mgmt, u))
		return -1;

	fc = le_to_host16(mgmt->frame_control);

	if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT)
		return -1;

	if (WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_ASSOC_RESP)
		return __madwifi_send_assoc_resp(priv, msg, len, 0);

	if (WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_REASSOC_RESP)
		return __madwifi_send_assoc_resp(priv, msg, len, 1);

	if (WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_AUTH)
		return  __madwifi_send_auth_frame(priv, msg, len);

	if (WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_DEAUTH) {
		struct ieee80211_mgmt *reply = (struct ieee80211_mgmt *)msg;

		return madwifi_sta_deauth(priv, reply->sa,
					reply->da, reply->u.deauth.reason_code);
	}

#ifdef HOSTAPD
	if (WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_ACTION) {
		size_t data_len = len - offsetof(struct ieee80211_mgmt, u);
		struct hostapd_data *hapd = bss->bss_ctx;

		return madwifi_hostapd_send_action(priv, hapd->iface->freq, 0,
					mgmt->da, mgmt->sa,
					mgmt->bssid, (u8 *)&mgmt->u.action,
					data_len, 0);
	}
#endif /* HOSTAPD */

	return -1;
}


static int madwifi_set_freq(void *priv, struct hostapd_freq_params *freq)
{
#ifdef HOSTAPD
	struct madwifi_bss *ctxt = (struct madwifi_bss *)priv;
#else
	struct madwifi_driver_data *ctxt = (struct madwifi_driver_data *)priv;
#endif
	int sock = ctxt->sock_ioctl;
	struct iwreq iwr;

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, ctxt->ifname, IFNAMSIZ);
	iwr.u.freq.m = freq->channel;
	iwr.u.freq.e = 0;
#ifdef CONFIG_QTNA_WIFI
#ifndef HOSTAPD
	iwr.u.freq.flags |= IW_FREQ_STA_SET_FLAG;
#endif
#endif /* CONFIG_QTNA_WIFI */

	if (ioctl(sock, SIOCSIWFREQ, &iwr) < 0) {
		wpa_printf(MSG_ERROR, "%s: ioctl failed", __func__);
		return -1;
	}

	return 0;
}


#ifdef HOSTAPD
static int
__madwifi_hostapd_write_to_qdrv_control(const char *cmd)
{
	FILE	*qdrv_control;
	int	ret;

	qdrv_control = fopen(QTN_DRV_CONTROL_FILE, "w");
	if (!qdrv_control)
		return -1;

	ret = fwrite(cmd, strlen(cmd), 1, qdrv_control);
	fclose(qdrv_control);

	if (!ret)
		return -1;

	return 0;
}


/* Configure WPA parameters. */
static int
__madwifi_hostapd_config_wpa(struct madwifi_bss *bss,
		      struct wpa_bss_params *params)
{
	int v;

	wpa_printf(MSG_DEBUG, "%s: wpa_group=0x%x", __func__, params->wpa_group);

	switch (params->wpa_group) {
	case WPA_CIPHER_CCMP:
		v = IEEE80211_CIPHER_AES_CCM;
		break;
	case WPA_CIPHER_TKIP:
		v = IEEE80211_CIPHER_TKIP;
		break;
	case WPA_CIPHER_WEP104:
		v = IEEE80211_CIPHER_WEP;
		break;
	case WPA_CIPHER_WEP40:
		v = IEEE80211_CIPHER_WEP;
		break;
	case WPA_CIPHER_NONE:
		v = IEEE80211_CIPHER_NONE;
		break;
	default:
		wpa_printf(MSG_ERROR, "Unknown group key cipher %u",
			   params->wpa_group);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "%s: group key cipher=%d", __func__, v);
	if (__madwifi_set80211param(bss, IEEE80211_PARAM_MCASTCIPHER, v)) {
		wpa_printf(MSG_ERROR, "Unable to set group key cipher to %u\n", v);
		return -1;
	}
	if (v == IEEE80211_CIPHER_WEP) {
		/* key length is done only for specific ciphers */
		v = (params->wpa_group == WPA_CIPHER_WEP104 ? 13 : 5);
		if (__madwifi_set80211param(bss, IEEE80211_PARAM_MCASTKEYLEN, v)) {
			wpa_printf(MSG_ERROR, "Unable to set group key length to %u\n", v);
			return -1;
		}
	}

	v = 0;
	if (params->wpa_pairwise & WPA_CIPHER_CCMP)
		v |= 1<<IEEE80211_CIPHER_AES_CCM;
	if (params->wpa_pairwise & WPA_CIPHER_TKIP)
		v |= 1<<IEEE80211_CIPHER_TKIP;
	if (params->wpa_pairwise & WPA_CIPHER_NONE)
		v |= 1<<IEEE80211_CIPHER_NONE;
	wpa_printf(MSG_DEBUG, "%s: pairwise key ciphers=0x%x", __func__, v);

	if (__madwifi_set80211param(bss, IEEE80211_PARAM_UCASTCIPHERS, v)) {
		wpa_printf(MSG_ERROR, "Unable to set pairwise key ciphers to 0x%x\n", v);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "%s: key management algorithms=0x%x",
		   __func__, params->wpa_key_mgmt);
	if (__madwifi_set80211param(bss, IEEE80211_PARAM_KEYMGTALGS,
			  params->wpa_key_mgmt)) {
		wpa_printf(MSG_ERROR, "Unable to set key management algorithms to 0x%x\n",
			params->wpa_key_mgmt);
		return -1;
	}

	v = 0;
	if (params->rsn_preauth)
		v |= BIT(0);
	wpa_printf(MSG_DEBUG, "%s: rsn capabilities=0x%x",
		   __func__, params->rsn_preauth);
	if (__madwifi_set80211param(bss, IEEE80211_PARAM_RSNCAPS, v)) {
		wpa_printf(MSG_ERROR, "Unable to set RSN capabilities to 0x%x\n", v);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "%s: enable WPA=0x%x", __func__, params->wpa);
	if (__madwifi_set80211param(bss, IEEE80211_PARAM_WPA, params->wpa)) {
		wpa_printf(MSG_ERROR, "Unable to set WPA to %u\n", params->wpa);
		return -1;
	}
	return 0;
}


static int
madwifi_hostapd_set_ieee8021x(void *priv, struct wpa_bss_params *params)
{
	struct madwifi_bss *bss = (struct madwifi_bss *)priv;
	int value;

	if (priv == NULL)
		return 0;

	wpa_printf(MSG_DEBUG, "%s: enabled=%d", __func__, params->enabled);

	if (!params->enabled) {
		/* XXX restore state */
		wpa_printf(MSG_DEBUG, "%s: set authmode %d", __func__, IEEE80211_AUTH_AUTO);
		return __madwifi_set80211param(bss, IEEE80211_PARAM_AUTHMODE,
			IEEE80211_AUTH_AUTO);
	}
	if (!params->wpa && !params->ieee802_1x) {
		wpa_printf(MSG_WARNING, "No 802.1X or WPA enabled!");
		return -1;
	}

	value = (params->ieee80211w ? params->ieee80211w + 1 : 0);
	wpa_printf(MSG_DEBUG, "%s: set pmf %d", __func__, value);
	if (__madwifi_set80211param(bss, IEEE80211_PARAM_CONFIG_PMF, value)) {
		wpa_printf(MSG_WARNING, "Error enabling PMF");
		return -1;
	}

	if (params->wpa && __madwifi_hostapd_config_wpa(bss, params) != 0) {
		wpa_printf(MSG_WARNING, "Error configuring WPA state!");
		return -1;
	}

	value = (params->wpa ? IEEE80211_AUTH_WPA : IEEE80211_AUTH_8021X);
	wpa_printf(MSG_DEBUG, "%s: set authmode %d", __func__, value);
	if (__madwifi_set80211param(bss, IEEE80211_PARAM_AUTHMODE, value)) {
		wpa_printf(MSG_WARNING, "Error enabling WPA/802.1X!");
		return -1;
	}

	return 0;
}


static int
madwifi_hostapd_set_privacy(void *priv, int enabled)
{
	if (priv == NULL)
		return 0;

	struct madwifi_bss *bss = priv;

	wpa_printf(MSG_DEBUG, "%s: enabled=%d", __func__, enabled);

	return __madwifi_set80211param(bss, IEEE80211_PARAM_PRIVACY, enabled);
}


static int
__madwifi_hostapd_set_sta_authorized(void *priv, const u8 *addr, int authorized)
{
	struct madwifi_bss *bss = priv;
	struct ieee80211req_mlme mlme;
	int ret;

	wpa_printf(MSG_DEBUG, "%s: addr=%s authorized=%d",
		   __func__, __madwfi_ether_sprintf(addr), authorized);

	if (authorized)
		mlme.im_op = IEEE80211_MLME_AUTHORIZE;
	else
		mlme.im_op = IEEE80211_MLME_UNAUTHORIZE;
	mlme.im_reason = 0;
	os_memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
	ret = __madwifi_set80211priv(bss, IEEE80211_IOCTL_SETMLME, &mlme, sizeof(mlme));
	if (ret < 0) {
		wpa_printf(MSG_ERROR, "%s: Failed to %sauthorize STA " MACSTR,
			   __func__, authorized ? "" : "un", MAC2STR(addr));
	}

	return ret;
}


static int
madwifi_hostapd_set_brcm_ioctl(void *priv, uint8_t *data, uint32_t len)
{
	struct iwreq iwr;
	struct madwifi_bss *bss = (struct madwifi_bss *)priv;

	wpa_printf(MSG_DEBUG, "%s: len=%d", __func__, len);

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, bss->ifname, IFNAMSIZ);
	iwr.u.data.flags = SIOCDEV_SUBIO_SET_BRCM_IOCTL;
	iwr.u.data.pointer = data;
	iwr.u.data.length = len;

	if (ioctl(bss->sock_ioctl, IEEE80211_IOCTL_EXT, &iwr) < 0) {
		wpa_printf(MSG_ERROR, "%s: Failed to do brcm info ioctl", __func__);
		return -1;
	}
	return 0;
}


static int
madwifi_hostapd_sta_set_flags(void *priv, const u8 *addr,
		      unsigned int total_flags, unsigned int flags_or,
		      unsigned int flags_and)
{
	wpa_printf(MSG_DEBUG, "%s: total_flags=%d, flags_or=0x%x, flags_and=0x%x",
			__func__, total_flags, flags_or, flags_and);

	/* For now, only support setting Authorized flag */
	if (flags_or & WPA_STA_AUTHORIZED)
		return __madwifi_hostapd_set_sta_authorized(priv, addr, 1);
	if (!(flags_and & WPA_STA_AUTHORIZED))
		return __madwifi_hostapd_set_sta_authorized(priv, addr, 0);
	return 0;
}


static int
madwifi_hostapd_get_seqnum(const char *ifname, void *priv, const u8 *addr, int idx,
		   u8 *seq)
{
	struct madwifi_bss *bss = priv;
	struct ieee80211req_key wk;

	wpa_printf(MSG_DEBUG, "%s: addr=%s idx=%d",
		   __func__, __madwfi_ether_sprintf(addr), idx);

	os_memset(&wk, 0, sizeof(wk));
	if (addr == NULL)
		os_memset(wk.ik_macaddr, 0xff, IEEE80211_ADDR_LEN);
	else
		os_memcpy(wk.ik_macaddr, addr, IEEE80211_ADDR_LEN);
	wk.ik_keyix = idx;

	if (__madwifi_set80211priv(bss, IEEE80211_IOCTL_GETKEY, &wk, sizeof(wk))) {
		wpa_printf(MSG_ERROR, "%s: Failed to get encryption data "
			   "(addr " MACSTR " key_idx %d)",
			   __func__, MAC2STR(wk.ik_macaddr), idx);
		return -1;
	}

#ifdef WORDS_BIGENDIAN
	{
		/*
		 * wk.ik_keytsc is in host byte order (big endian), need to
		 * swap it to match with the byte order used in WPA.
		 */
		int i;
		u8 tmp[WPA_KEY_RSC_LEN];

		os_memcpy(tmp, &wk.ik_keytsc, sizeof(wk.ik_keytsc));
		for (i = 0; i < WPA_KEY_RSC_LEN; i++) {
			seq[i] = tmp[WPA_KEY_RSC_LEN - i - 1];
		}
	}
#else /* WORDS_BIGENDIAN */
	os_memcpy(seq, &wk.ik_keytsc, sizeof(wk.ik_keytsc));
#endif /* WORDS_BIGENDIAN */
	return 0;
}


static int
madwifi_hostapd_read_sta_data(void *priv, struct hostap_sta_driver_data *data,
			     const u8 *addr)
{
	struct madwifi_bss *bss = priv;
	struct ieee80211req_sta_stats stats;

	os_memset(data, 0, sizeof(*data));

	/*
	 * Fetch statistics for station from the system.
	 */
	os_memset(&stats, 0, sizeof(stats));
	os_memcpy(stats.is_u.macaddr, addr, IEEE80211_ADDR_LEN);
	if (__madwifi_set80211priv(bss,
			 IEEE80211_IOCTL_STA_STATS,
			 &stats, sizeof(stats))) {
		wpa_printf(MSG_ERROR, "%s: Failed to fetch STA stats (addr "
			   MACSTR ")", __func__, MAC2STR(addr));
		if (os_memcmp(addr, bss->acct_mac, ETH_ALEN) == 0) {
			os_memcpy(data, &bss->acct_data, sizeof(*data));
			return 0;
		}

		wpa_printf(MSG_ERROR, "Failed to get station stats");
		return -1;
	}

	data->rx_packets = stats.is_stats.ns_rx_data;
	data->rx_bytes = stats.is_stats.ns_rx_bytes;
	data->tx_packets = stats.is_stats.ns_tx_data;
	data->tx_bytes = stats.is_stats.ns_tx_bytes;
	return 0;
}


static int
madwifi_hostapd_sta_clear_stats(void *priv, const u8 *addr)
{
	int ret = 0;
#if defined(IEEE80211_MLME_CLEAR_STATS)
	struct madwifi_bss *bss = priv;
	struct ieee80211req_mlme mlme;

	wpa_printf(MSG_DEBUG, "%s: addr=%s", __func__, __madwfi_ether_sprintf(addr));

	mlme.im_op = IEEE80211_MLME_CLEAR_STATS;
	os_memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
	ret = __madwifi_set80211priv(bss, IEEE80211_IOCTL_SETMLME, &mlme,
			   sizeof(mlme));
	if (ret < 0) {
		wpa_printf(MSG_ERROR, "%s: Failed to clear STA stats (addr "
			   MACSTR ")", __func__, MAC2STR(addr));
	}
#endif /* IEEE80211_MLME_CLEAR_STATS */
	return ret;
}


static int
madwifi_hostapd_sta_disassoc(void *priv, const u8 *own_addr, const u8 *addr,
		     int reason_code)
{
	struct ieee80211req_mlme mlme;
	int ret;

	wpa_printf(MSG_DEBUG, "%s: addr=%s reason_code=%d",
		   __func__, __madwfi_ether_sprintf(addr), reason_code);

	mlme.im_op = IEEE80211_MLME_DISASSOC;
	mlme.im_reason = reason_code;
	os_memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
	ret = __madwifi_set80211priv(priv, IEEE80211_IOCTL_SETMLME, &mlme, sizeof(mlme));
	if (ret < 0) {
		wpa_printf(MSG_ERROR, "%s: Failed to disassoc STA (addr "
			   MACSTR " reason %d)",
			   __func__, MAC2STR(addr), reason_code);
	}

	return ret;
}


static int
madwifi_hostapd_flush(void *priv)
{
	u8 allsta[IEEE80211_ADDR_LEN];

	wpa_printf(MSG_DEBUG, "%s:", __func__);

	os_memset(allsta, 0xff, IEEE80211_ADDR_LEN);
	return madwifi_sta_deauth(priv, NULL, allsta,
				  IEEE80211_REASON_AUTH_LEAVE);
}


#ifdef IEEE80211_IOCTL_FILTERFRAME
#ifdef CONFIG_WPS
/**
* return 0 if Probe request packet is received and handled
* return -1 if frame is not a probe request frame
*/
static int __madwifi_hostapd_recv_probe_req(void *ctx, const u8 *src_addr, const u8 *buf,
				size_t len)
{
	struct madwifi_bss *bss = ctx;
	const struct ieee80211_mgmt *mgmt;
	u16 fc;
	union wpa_event_data event;

	/* Send Probe Request information to WPS processing */

	if (len < IEEE80211_HDRLEN + sizeof(mgmt->u.probe_req))
		return -1;
	mgmt = (const struct ieee80211_mgmt *) buf;

	fc = le_to_host16(mgmt->frame_control);
	if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT ||
	    WLAN_FC_GET_STYPE(fc) != WLAN_FC_STYPE_PROBE_REQ)
		return -1;

	os_memset(&event, 0, sizeof(event));
	event.rx_probe_req.sa = mgmt->sa;
	event.rx_probe_req.da = mgmt->da;
	event.rx_probe_req.bssid = mgmt->bssid;
	event.rx_probe_req.ie = mgmt->u.probe_req.variable;
	event.rx_probe_req.ie_len =
		len - (IEEE80211_HDRLEN + sizeof(mgmt->u.probe_req));
	wpa_supplicant_event(bss->bss_ctx, EVENT_RX_PROBE_REQ, &event);

	return 0;
}
#endif /* CONFIG_WPS */

#if defined(CONFIG_IEEE80211R) || defined(CONFIG_OWE) || defined(CONFIG_SAE)
static int __madwifi_hostapd_recv_mgmt(void *ctx, const u8 *src_addr, const u8 *buf,
				size_t len)
{
	struct madwifi_bss *bss = ctx;
	const struct ieee80211_mgmt *mgmt;
	union wpa_event_data event;
	u16 fc;

	mgmt = (const struct ieee80211_mgmt *) buf;

	fc = le_to_host16(mgmt->frame_control);

	wpa_printf(MSG_DEBUG, "%s: type=%d, subtype=%d, len=%d",
			__func__, WLAN_FC_GET_TYPE(fc), WLAN_FC_GET_STYPE(fc), (int)len);

	if ((WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT) &&(
		(WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_AUTH)
		|| (WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_ASSOC_REQ)
		|| (WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_REASSOC_REQ))) {

		mgmt = (const struct ieee80211_mgmt *) buf;
		wpa_printf(MSG_ERROR, "%s: RX MGMT subtype %u", __func__, WLAN_FC_GET_STYPE(fc));
		if (os_memcmp(bss->bssid, mgmt->da, IEEE80211_ADDR_LEN) == 0) {
			os_memset(&event, 0, sizeof(event));
			event.rx_mgmt.frame = (const u8 *) mgmt;
			event.rx_mgmt.frame_len = len;
			wpa_supplicant_event(bss->bss_ctx, EVENT_RX_MGMT, &event);
			return 0;
		}
	}

	return -1;
}
#endif /* CONFIG_IEEE80211R | CONFIG_OWE  | CONFIG_SAE */

#if defined(CONFIG_HS20) || defined(CONFIG_IEEE80211R)
static int __madwifi_hostapd_recv_action(void *ctx, const u8 *src_addr, const u8 *buf,
					size_t len)
{
	struct madwifi_bss *bss = ctx;
	const struct ieee80211_mgmt *mgmt;
	union wpa_event_data event;
	u16 fc;
	const u8 *bssid = get_hdr_bssid((const struct ieee80211_hdr *)buf, len);

	if (!bssid || (os_memcmp(bssid, bss->bssid, IEEE80211_ADDR_LEN) &&
			!is_broadcast_ether_addr(bssid)))
		return -1;

	/* Send the Action frame for HS20 processing */

	if (len < IEEE80211_HDRLEN + sizeof(mgmt->u.action.category) +
			sizeof(mgmt->u.action.u.public_action))
		return -1;

	mgmt = (const struct ieee80211_mgmt *) buf;

	fc = le_to_host16(mgmt->frame_control);

	if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT ||
			WLAN_FC_GET_STYPE(fc) != WLAN_FC_STYPE_ACTION)
		return -1;

	wpa_printf(MSG_DEBUG, "%s: Received action frame - category %u",
			__func__, mgmt->u.action.category);
	if ((mgmt->u.action.category == WLAN_ACTION_FT) ||
		(mgmt->u.action.category == WLAN_ACTION_PUBLIC)) {
		os_memset(&event, 0, sizeof(event));
		event.rx_mgmt.frame = (const u8 *) mgmt;
		event.rx_mgmt.frame_len = len;
		event.rx_mgmt.freq = mgmt->duration;
		wpa_hexdump(MSG_DEBUG, "RX ACTION ",
				mgmt, len);
		wpa_supplicant_event(bss->bss_ctx, EVENT_RX_MGMT, &event);
		return 0;
	}

	return -1;
}
#endif


static void __madwifi_hostapd_recv_raw_pkt(void *ctx, const u8 *src_addr, const u8 *buf,
				size_t len)
{
	const struct ieee80211_mgmt *mgmt;
	u16 fc;

	if (len < IEEE80211_HDRLEN)
		return;

	mgmt = (const struct ieee80211_mgmt *)buf;
	fc = le_to_host16(mgmt->frame_control);
	if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT)
		return;

#ifdef CONFIG_WPS
	if ((WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_PROBE_REQ) &&
		__madwifi_hostapd_recv_probe_req(ctx, src_addr, buf, len) == 0)
		return;
#endif

#if defined(CONFIG_HS20) || defined(CONFIG_IEEE80211R)
	if ((WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_ACTION) &&
		__madwifi_hostapd_recv_action(ctx, src_addr, buf, len) == 0)
		return;
#endif
#if defined(CONFIG_IEEE80211R) || defined(CONFIG_OWE) || defined(CONFIG_SAE)
	__madwifi_hostapd_recv_mgmt(ctx, src_addr, buf, len);
#endif
}
#endif /* IEEE80211_IOCTL_FILTERFRAME */


static int __madwifi_hostapd_recv_pkt(struct madwifi_bss *bss)
{
	int ret = 0;
#ifdef IEEE80211_IOCTL_FILTERFRAME
	struct ieee80211req_set_filter filt;
	struct hostapd_data *hapd = bss->bss_ctx;

	filt.app_filterype = 0;
#ifdef CONFIG_WPS
	filt.app_filterype = IEEE80211_FILTER_TYPE_PROBE_REQ;
#endif /* CONFIG_WPS */
#if	defined(CONFIG_HS20) || defined(CONFIG_IEEE80211R)
	filt.app_filterype |= IEEE80211_FILTER_TYPE_ACTION;
#endif

	ret = __madwifi_set80211priv(bss, IEEE80211_IOCTL_FILTERFRAME, &filt,
			   sizeof(struct ieee80211req_set_filter));
	if (ret)
		return ret;

	bss->sock_raw = l2_packet_init(hapd->conf->bridge, NULL, ETH_P_80211_RAW,
				       __madwifi_hostapd_recv_raw_pkt, bss, 1);
	if (bss->sock_raw == NULL)
		return -1;
#endif /* IEEE80211_IOCTL_FILTERFRAME */
	return ret;
}


#ifdef CONFIG_WPS
static int
__madwifi_hostapd_set_wps_ie(void *priv, const u8 *ie, size_t len, u32 frametype)
{
	struct madwifi_bss *bss = priv;
	u8 buf[1024];
	struct ieee80211req_getset_appiebuf *beac_ie;

	if ((len + sizeof(*beac_ie)) > sizeof(buf)) {
		wpa_printf(MSG_ERROR, "%s WPS IE length %lu exceeds the buffer size %lu",
			__func__, (unsigned long)len, sizeof(buf));
		return -1;
	}

	wpa_printf(MSG_DEBUG, "%s WPS IE length = %lu", __func__, (unsigned long)len);

	os_memset(buf, 0, sizeof(buf));
	beac_ie = (struct ieee80211req_getset_appiebuf *) buf;
	beac_ie->app_frmtype = frametype;
	beac_ie->app_buflen = len;
	os_memcpy(&(beac_ie->app_buf[0]), ie, len);

	return __madwifi_set80211priv(bss, IEEE80211_IOCTL_SET_APPIEBUF, beac_ie,
			    sizeof(struct ieee80211req_getset_appiebuf) + len);
}


static int
madwifi_hostapd_set_ap_wps_ie(void *priv, const struct wpabuf *beacon,
		      const struct wpabuf *proberesp,
		      const struct wpabuf *assocresp)
{
	wpa_printf(MSG_DEBUG, "%s:", __func__);

	if (__madwifi_hostapd_set_wps_ie(priv, beacon ? wpabuf_head(beacon) : NULL,
			       beacon ? wpabuf_len(beacon) : 0,
			       IEEE80211_APPIE_FRAME_BEACON) < 0)
		return -1;

	if (__madwifi_hostapd_set_wps_ie(priv,
				  proberesp ? wpabuf_head(proberesp) : NULL,
				  proberesp ? wpabuf_len(proberesp) : 0,
				  IEEE80211_APPIE_FRAME_PROBE_RESP) < 0)
		return -1;

	return __madwifi_hostapd_set_wps_ie(priv,
				  assocresp ? wpabuf_head(assocresp) : NULL,
				  assocresp ? wpabuf_len(assocresp) : 0,
				  IEEE80211_APPIE_FRAME_ASSOC_RESP);
}
#endif /* CONFIG_WPS */


#ifndef CONFIG_NO_VLAN
static int madwifi_hostapd_set_sta_vlan(void *priv, const u8 *addr,
			const char *ifname, int vlan_id)
{
	char mac[20];
	char buf[MADWIFI_CMD_BUF_SIZE];
	int ret;

	snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
			addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	wpa_printf(MSG_DEBUG, "%s: Bind %s with VLAN %d\n",
			ifname, mac, vlan_id);

	snprintf(buf, sizeof(buf), "set dyn-vlan %s %d\n", mac, vlan_id);

	ret = __madwifi_hostapd_write_to_qdrv_control(buf);
	if (ret < 0) {
		wpa_printf(MSG_ERROR, "%s: Bind STA VLAN failed\n", ifname);
		return -1;
	}

	return 0;
}


static int madwifi_hostapd_set_dyn_vlan(void *priv, const char *ifname, int enable)
{
	char buf[MADWIFI_CMD_BUF_SIZE];
	const char *cmd;
	int ret;

	cmd = (enable ? "enable" : "disable");
	wpa_printf(MSG_DEBUG, "%s: %s dynamic VLAN ", ifname, cmd);

	snprintf(buf, sizeof(buf), "set vlan %s %s 1", ifname, enable ? "dynamic" : "undynamic");

	ret = __madwifi_hostapd_write_to_qdrv_control(buf);
	if (ret < 0) {
		wpa_printf(MSG_ERROR, "%s: %s dynamic VLAN failed", ifname, cmd);
		return -1;
	}

	return 0;
}


static int madwifi_hostapd_vlan_group_add(void *priv, const char *ifname, int vlan_id)
{
	char buf[MADWIFI_CMD_BUF_SIZE];
	int ret;

	wpa_printf(MSG_DEBUG, "%s: set vlan-group %d", ifname, vlan_id);

	snprintf(buf, sizeof(buf), "set vlan-group %s %d 1", ifname, vlan_id);

	ret = __madwifi_hostapd_write_to_qdrv_control(buf);
	if (ret < 0) {
		wpa_printf(MSG_ERROR, "set vlan group %d failed\n", vlan_id);
		return -1;
	}

	return 0;
}


static int madwifi_hostapd_vlan_group_remove(void *priv, const char *ifname, int vlan_id)
{
	char buf[MADWIFI_CMD_BUF_SIZE];
	int ret;

	wpa_printf(MSG_DEBUG, "%s: remove vlan-group %d", ifname, vlan_id);

	snprintf(buf, sizeof(buf), "set vlan-group %s %d 0", ifname, vlan_id);

	ret = __madwifi_hostapd_write_to_qdrv_control(buf);
	if (ret < 0) {
		wpa_printf(MSG_ERROR, "set vlan group %d failed\n", vlan_id);
		return -1;
	}

	return 0;
}
#endif /* CONFIG_NO_VLAN */


static int
__madwifi_hostapd_get_sta_ext_cap_ie(struct madwifi_bss *bss, uint8_t addr[IEEE80211_ADDR_LEN],
				unsigned out_buf_len, uint8_t *out_buf, unsigned *ext_cap_ie_len)
{
	uint8_t buf[IEEE80211_MAX_OPT_IE] = {0};
	struct iwreq iwr;

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, bss->ifname, IFNAMSIZ);
	os_memcpy(buf, addr, IEEE80211_ADDR_LEN);
	iwr.u.data.flags = SIOCDEV_SUBIO_GET_STA_EXT_CAP_IE;
	iwr.u.data.pointer = buf;
	iwr.u.data.length = sizeof(buf);

	if (ioctl(bss->sock_ioctl, IEEE80211_IOCTL_EXT, &iwr) < 0) {
		wpa_printf(MSG_ERROR, "%s: Failed to get STA ext. capability IE"
			" from driver ", __func__);
		return -1;
	}

	if (buf[0] == IEEE80211_ELEMID_EXTCAP) {
		*ext_cap_ie_len = buf[1] + IEEE80211_IE_ID_LEN_SIZE;
		if (*ext_cap_ie_len > out_buf_len) {
			wpa_printf(MSG_ERROR, "%s: no space to get STA ext. capability IE",
				__func__);
		} else {
			os_memcpy(out_buf, buf, *ext_cap_ie_len);
		}
	} else {
		return -1;
	}

	return 0;
}


static void
__madwifi_hostapd_new_sta(struct madwifi_bss *bss, u8 addr[IEEE80211_ADDR_LEN])
{
	struct ieee80211req_wpaie ie;
	int ielen = 0;
	u8 *iebuf = NULL;
	int res;
	struct hostapd_data *hapd = bss->bss_ctx;
	u8 *buf = NULL;
	u8 *buf_cur = NULL;
	unsigned buf_len = 0;
	unsigned buf_fill_len = 0;
	unsigned ext_cap_ie_len = 0;

	wpa_printf(MSG_DEBUG, "%s: mac addr=%s", __func__, __madwfi_ether_sprintf(addr));

	if (qtn_hapd_acl_reject(hapd, addr)){
		/* This reason code is used only by the driver, for blacklisting */
		res = madwifi_hostapd_sta_disassoc(bss, hapd->own_addr, addr, WLAN_REASON_DENIED);
		if (res < 0) {
			wpa_printf(MSG_ERROR, "%s: Failed to disassociate STA (addr " MACSTR
				   " that is denied by MAC address ACLs)",
				   __func__, MAC2STR(addr));
		}
		return;
	}

	/*
	 * Fetch negotiated WPA/RSN parameters from the system.
	 */
	os_memset(&ie, 0, sizeof(ie));
	os_memcpy(ie.wpa_macaddr, addr, IEEE80211_ADDR_LEN);
	if (__madwifi_set80211priv(bss, IEEE80211_IOCTL_GETWPAIE, &ie, sizeof(ie))) {
		wpa_printf(MSG_DEBUG, "%s: Failed to get WPA/RSN IE",
			   __func__);
		goto no_ie;
	}

	/*
	 * Handling Pairing hash IE here.
	 */
	if (qtn_hapd_pairingie_handle(bss, hapd, addr, &ie) < 0){
		madwifi_hostapd_sta_disassoc(bss, hapd->own_addr,
					addr, IEEE80211_REASON_IE_INVALID);
		return;
	}
	wpa_hexdump(MSG_MSGDUMP, "madwifi req WPA IE",
		    ie.wpa_ie, IEEE80211_MAX_OPT_IE);
	iebuf = ie.wpa_ie;
	/* madwifi seems to return some random data if WPA/RSN IE is not set.
	 * Assume the IE was not included if the IE type is unknown. */
	if (iebuf[0] != WLAN_EID_VENDOR_SPECIFIC)
		iebuf[1] = 0;

	wpa_hexdump(MSG_MSGDUMP, "madwifi req RSN IE",
		    ie.rsn_ie, IEEE80211_MAX_OPT_IE);
	if (iebuf[1] == 0 && ie.rsn_ie[1] > 0) {
		/* madwifi-ng svn #1453 added rsn_ie. Use it, if wpa_ie was not
		 * set. This is needed for WPA2. */
		iebuf = ie.rsn_ie;
		if (iebuf[0] != WLAN_EID_RSN)
			iebuf[1] = 0;
	}

	ielen = iebuf[1];

	if (ie.wps_ie &&
	    ((ie.wps_ie[1] > 0) &&
	     (ie.wps_ie[0] == WLAN_EID_VENDOR_SPECIFIC))) {
		iebuf = ie.wps_ie;
		ielen = ie.wps_ie[1];
	}

#ifdef CONFIG_HS20
	wpa_hexdump(MSG_MSGDUMP, "madwifi req OSEN IE",
			    ie.osen_ie, IEEE80211_MAX_OPT_IE);
	if (ielen == 0 && ie.osen_ie[1] > 0) {
		iebuf = ie.osen_ie;
		ielen = ie.osen_ie[1];
	}
#endif
	/* append MDIE */
	if (ie.mdie[1] > 0 && ie.mdie[0] == WLAN_EID_MOBILITY_DOMAIN ) {
		os_memcpy(iebuf + ielen + IEEE80211_IE_ID_LEN_SIZE, ie.mdie,
			sizeof(struct ieee80211_md_ie));
		ielen += sizeof(struct ieee80211_md_ie);
	}
	/* append FTIE */
	if (ie.ftie[1] > 0 && ie.ftie[0] == WLAN_EID_FAST_BSS_TRANSITION) {
		os_memcpy(iebuf + ielen + IEEE80211_IE_ID_LEN_SIZE, ie.ftie,
			ie.ftie[1] + IEEE80211_IE_ID_LEN_SIZE);
		ielen += ie.ftie[1] + IEEE80211_IE_ID_LEN_SIZE;
	}

#ifdef CONFIG_OWE
	if (ie.owe_dh && (ie.owe_dh[0] == WLAN_EID_EXTENSION) &&
			(ie.owe_dh[1] > IEEE80211_IE_ID_LEN_SIZE) &&
			(ie.owe_dh[2] == WLAN_EID_EXT_OWE_DH_PARAM)) {
		wpa_hexdump(MSG_ERROR, "new_sta OWE DH: ", ie.owe_dh, ie.owe_dh[1] +
					IEEE80211_IE_ID_LEN_SIZE);
		memcpy(iebuf + ielen + IEEE80211_IE_ID_LEN_SIZE, ie.owe_dh,
			ie.owe_dh[1] + IEEE80211_IE_ID_LEN_SIZE);
		ielen += ie.owe_dh[1] + IEEE80211_IE_ID_LEN_SIZE;
	}
#endif

	if (ielen == 0)
		iebuf = NULL;
	else
		ielen += 2;

no_ie:
	buf_len = IEEE80211_MAX_OPT_IE * 2;
	buf = os_zalloc(buf_len);
	buf_cur = buf;
	if (iebuf) {
		os_memcpy(buf_cur, iebuf, ielen);
		buf_cur += ielen;
		buf_fill_len += ielen;
	}

	if (__madwifi_hostapd_get_sta_ext_cap_ie(bss, addr,
				buf_len - buf_fill_len,
				buf_cur, &ext_cap_ie_len) == 0) {
		buf_cur += ext_cap_ie_len;
		buf_fill_len += ext_cap_ie_len;
		wpa_printf(MSG_ERROR, "New station ext cap");
	}

	drv_event_assoc(bss->bss_ctx, addr, buf, buf_fill_len, 0);

	os_free(buf);

	if (os_memcmp(addr, bss->acct_mac, ETH_ALEN) == 0) {
		/* Cached accounting data is not valid anymore. */
		os_memset(bss->acct_mac, 0, ETH_ALEN);
		os_memset(&bss->acct_data, 0, sizeof(bss->acct_data));
	}
}


static void
__madwifi_hostapd_wireless_event_custom(struct madwifi_bss *bss,
				       char *custom)
{
	wpa_printf(MSG_DEBUG, "Custom wireless event: '%s'", custom);

	if (strncmp(custom, "MLME-MICHAELMICFAILURE.indication", 33) == 0) {
		char *pos;
		/* Local - default to 'yes' */
		int local = 1;
		u8 addr[ETH_ALEN];

		pos = strstr(custom, "addr=");
		if (pos == NULL) {
			wpa_printf(MSG_DEBUG,
				   "MLME-MICHAELMICFAILURE.indication "
				   "without sender address ignored");
			return;
		}
		pos += 5;

		/* Quantenna - go into countermeasures regardless */

		/* Ensure for Quantenna devices we don't check the MAC address */
		if (strstr(custom, "qtn=1"))
			local = 0;

		if (hwaddr_aton(pos, addr) == 0) {
			union wpa_event_data data;
			os_memset(&data, 0, sizeof(data));
			data.michael_mic_failure.unicast = 1;
			data.michael_mic_failure.local = local;
			data.michael_mic_failure.src = addr;
			wpa_supplicant_event(bss->bss_ctx,
					     EVENT_MICHAEL_MIC_FAILURE, &data);
		} else {
			wpa_printf(MSG_DEBUG,
				   "MLME-MICHAELMICFAILURE.indication "
				   "with invalid MAC address");
		}
	} else if (strncmp(custom, "STA-TRAFFIC-STAT", 16) == 0) {
		char *key, *value;
		u8 addr[ETH_ALEN];
		u32 val;
		key = custom;
		while ((key = strchr(key, '\n')) != NULL) {
			key++;
			value = strchr(key, '=');
			if (value == NULL)
				continue;
			*value++ = '\0';
			val = strtoul(value, NULL, 10);
			if (strcmp(key, "mac") == 0) {
				if (hwaddr_aton(value, addr) == 0) {
					os_memcpy(bss->acct_mac, addr, ETH_ALEN);
				} else {
					wpa_printf(MSG_DEBUG,
						   "STA-TRAFFIC-STAT "
					           "with invalid MAC address");
				}
			} else if (strcmp(key, "rx_packets") == 0)
				bss->acct_data.rx_packets = val;
			else if (strcmp(key, "tx_packets") == 0)
				bss->acct_data.tx_packets = val;
			else if (strcmp(key, "rx_bytes") == 0)
				bss->acct_data.rx_bytes = val;
			else if (strcmp(key, "tx_bytes") == 0)
				bss->acct_data.tx_bytes = val;
			key = value;
		}
	} else if (os_strncmp(custom, "WPS-BUTTON.indication", 21) == 0) {
		struct hostapd_data *hapd = bss->bss_ctx;
		if (hapd->ignore_hw_pbc) {
			wpa_printf(MSG_DEBUG, "MADWIFI: ignore WPS-BUTTON.indication "
				   "event due to ignore_hw_pbc is set");
			return;
		}
		hostapd_wps_button_pushed(bss->bss_ctx, NULL);
	} else if (os_strncmp(custom, "STA-REQUIRE-LEAVE", 17) == 0) {
		u8 addr[ETH_ALEN];
		char *addr_str;
		addr_str = os_strchr(custom, '=');
		if (addr_str != NULL) {
			addr_str++;
			if (hwaddr_aton(addr_str, addr) == 0) {
				hostapd_sta_require_leave(bss->bss_ctx, addr);
			} else {
				wpa_printf(MSG_DEBUG, "STA-REQUIRE-LEAVE "
					   "with invalid MAC address");
			}
		}
	} else if (os_strncmp(custom, "TXSTATUS", 9) == 0) {
		union wpa_event_data data;
		struct qtn_tx_status_event_data *event_data =
				(struct qtn_tx_status_event_data *)custom;

		wpa_driver_wext_process_event_tx_status(event_data, &data);
		wpa_supplicant_event(bss->bss_ctx, EVENT_TX_STATUS, &data);
	}
}


static void
__madwifi_hostapd_wireless_event_wireless(struct madwifi_bss *bss,
					    char *data, int len)
{
	struct madwifi_driver_data *drv = bss->drv;
	struct iw_event iwe_buf, *iwe = &iwe_buf;
	char *pos, *end, *custom, *buf;

	pos = data;
	end = data + len;

	while (pos + IW_EV_LCP_LEN <= end) {
		/* Event data may be unaligned, so make a local, aligned copy
		 * before processing. */
		os_memcpy(&iwe_buf, pos, IW_EV_LCP_LEN);
		wpa_printf(MSG_MSGDUMP, "Wireless event: cmd=0x%x len=%d",
			   iwe->cmd, iwe->len);
		if (iwe->len <= IW_EV_LCP_LEN)
			return;

		custom = pos + IW_EV_POINT_LEN;
		if (drv->we_version > 18 &&
		    (iwe->cmd == IWEVMICHAELMICFAILURE ||
		     iwe->cmd == IWEVCUSTOM)) {
			/* WE-19 removed the pointer from struct iw_point */
			char *dpos = (char *) &iwe_buf.u.data.length;
			int dlen = dpos - (char *) &iwe_buf;
			os_memcpy(dpos, pos + IW_EV_LCP_LEN,
			       sizeof(struct iw_event) - dlen);
		} else {
			os_memcpy(&iwe_buf, pos, sizeof(struct iw_event));
			custom += IW_EV_POINT_OFF;
		}

		switch (iwe->cmd) {
			case IWEVEXPIRED:
				drv_event_disassoc(bss->bss_ctx,
						   (u8 *) iwe->u.addr.sa_data);
				break;
			case IWEVREGISTERED:
				__madwifi_hostapd_new_sta(bss, (u8 *) iwe->u.addr.sa_data);
				break;
			case IWEVCUSTOM:
				if (custom + iwe->u.data.length > end)
					return;
				buf = malloc(iwe->u.data.length + 1);
				if (buf == NULL)
					return;		/* XXX */
				os_memcpy(buf, custom, iwe->u.data.length);
				buf[iwe->u.data.length] = '\0';
				__madwifi_hostapd_wireless_event_custom(bss, buf);
				free(buf);
				break;
		}

		pos += iwe->len;
	}
}


static void
__madwifi_hostapd_wireless_event_rtm_newlink(void *ctx, struct ifinfomsg *ifi,
				   u8 *buf, size_t len)
{
	struct madwifi_bss *bss = ctx;
	int attrlen, rta_len;
	struct rtattr *attr;

	if (ifi->ifi_index != bss->ifindex)
		return;

	attrlen = len;
	attr = (struct rtattr *) buf;

	rta_len = RTA_ALIGN(sizeof(struct rtattr));
	while (RTA_OK(attr, attrlen)) {
		if (attr->rta_type == IFLA_WIRELESS) {
			__madwifi_hostapd_wireless_event_wireless(
				bss, ((char *) attr) + rta_len,
				attr->rta_len - rta_len);
		}
		attr = RTA_NEXT(attr, attrlen);
	}
}


static int
__madwifi_hostapd_get_we_version(struct madwifi_driver_data *drv)
{
	struct madwifi_bss *bss;
	struct iw_range *range;
	struct iwreq iwr;
	int minlen;
	size_t buflen;

	bss = dl_list_first(&drv->bss, struct madwifi_bss, list);
	drv->we_version = 0;

	/*
	 * Use larger buffer than struct iw_range in order to allow the
	 * structure to grow in the future.
	 */
	buflen = sizeof(struct iw_range) + 500;
	range = os_zalloc(buflen);
	if (range == NULL)
		return -1;

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, bss->ifname, IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) range;
	iwr.u.data.length = buflen;

	minlen = ((char *) &range->enc_capa) - (char *) range +
		sizeof(range->enc_capa);

	if (ioctl(bss->sock_ioctl, SIOCGIWRANGE, &iwr) < 0) {
		perror("ioctl[SIOCGIWRANGE]");
		free(range);
		return -1;
	} else if (iwr.u.data.length >= minlen &&
		   range->we_version_compiled >= 18) {
		wpa_printf(MSG_DEBUG, "SIOCGIWRANGE: WE(compiled)=%d "
			   "WE(source)=%d enc_capa=0x%x",
			   range->we_version_compiled,
			   range->we_version_source,
			   range->enc_capa);
		drv->we_version = range->we_version_compiled;
	}

	free(range);
	return 0;
}


static int
__madwifi_hostapd_wireless_event_init(struct madwifi_bss *bss)
{
	struct netlink_config *cfg;

	__madwifi_hostapd_get_we_version(bss->drv);

	cfg = os_zalloc(sizeof(*cfg));
	if (cfg == NULL)
		return -1;
	cfg->ctx = bss;
	cfg->newlink_cb = __madwifi_hostapd_wireless_event_rtm_newlink;
	bss->netlink = netlink_init(cfg);
	if (bss->netlink == NULL) {
		os_free(cfg);
		return -1;
	}

	return 0;
}


static int
madwifi_hostapd_send_eapol(void *priv, const u8 *addr, const u8 *data, size_t data_len,
		   int encrypt, const u8 *own_addr, u32 flags)
{
	struct madwifi_bss *bss = priv;
	unsigned char buf[3000];
	unsigned char *bp = buf;
	struct l2_ethhdr *eth;
	size_t len;
	int status;

	/*
	 * Prepend the Ethernet header.  If the caller left us
	 * space at the front we could just insert it but since
	 * we don't know we copy to a local buffer.  Given the frequency
	 * and size of frames this probably doesn't matter.
	 */
	len = data_len + sizeof(struct l2_ethhdr);
	if (len > sizeof(buf)) {
		bp = malloc(len);
		if (bp == NULL) {
			wpa_printf(MSG_ERROR, "EAPOL frame discarded, cannot malloc temp "
			       "buffer of size %lu!\n", (unsigned long) len);
			return -1;
		}
	}
	eth = (struct l2_ethhdr *) bp;
	os_memcpy(eth->h_dest, addr, ETH_ALEN);
	os_memcpy(eth->h_source, own_addr, ETH_ALEN);
	eth->h_proto = host_to_be16(ETH_P_EAPOL);
	os_memcpy(eth+1, data, data_len);

	wpa_hexdump(MSG_MSGDUMP, "TX EAPOL", bp, len);

	/* FIXME this currently only supports EAPOL frames up to 2047 bytes */
	if (data_len > 2047) {
		if (bp != buf)
			free(bp);

		return -1;
	}

#define QTN_WPA_FAST_PATH	/* Send directly to the wlan driver */
#ifdef QTN_WPA_FAST_PATH
		status = __madwifi_set80211priv(bss, IEEE80211_IOCTL_TXEAPOL, bp, len);
#else
		status = l2_packet_send(bss->sock_xmit, addr, ETH_P_EAPOL, bp, len);
#endif

	if (bp != buf)
		free(bp);
	return status;
}


static void
__madwifi_hostapd_eapol_recv_proc(void *ctx, const u8 *src_addr, const u8 *buf, size_t len)
{
	struct madwifi_bss *bss = ctx;
	drv_event_eapol_rx(bss->bss_ctx, src_addr, buf + sizeof(struct l2_ethhdr),
			   len - sizeof(struct l2_ethhdr));
}


static int __madwifi_hostapd_init_bss_bridge(struct madwifi_bss *bss, const char *ifname)
{
	char in_br[IFNAMSIZ + 1];
	const char* brname = bss->brname;
	int add_bridge_required = 1;

	if (brname[0] == 0)
		add_bridge_required = 0;

	if (linux_br_get(in_br, ifname) == 0) {
		/* it is in a bridge already */
		if (os_strcmp(in_br, brname) == 0) {
			add_bridge_required = 0;
		} else {
			/* but not the desired bridge; remove */
			wpa_printf(MSG_DEBUG, "%s: Removing interface %s from bridge %s",
					__func__, ifname, in_br);
			if (linux_br_del_if(bss->sock_ioctl, in_br, ifname) < 0) {
				wpa_printf(MSG_ERROR, "%s: Failed to "
						"remove interface %s from bridge %s: %s",
						__func__, ifname, brname, strerror(errno));
				return -1;
			}
		}
	}

	if (add_bridge_required) {
		wpa_printf(MSG_DEBUG, "%s: Adding interface %s into bridge %s",
				__func__, ifname, brname);
		if (linux_br_add_if(bss->sock_ioctl, brname, ifname) < 0) {
			wpa_printf(MSG_ERROR, "%s: Failed to add interface %s "
					"into bridge %s: %s",
					__func__, ifname, brname, strerror(errno));
			return -1;
		}
		bss->added_if_into_bridge = 1;
	}

	return 0;
}


static int __madwifi_hostapd_deinit_bss_bridge(struct madwifi_bss *bss, const char *ifname)
{
	const char* brname = bss->brname;

	if (bss->added_if_into_bridge) {
		if (linux_br_del_if(bss->sock_ioctl, brname, ifname) < 0) {
			wpa_printf(MSG_ERROR, "%s: Failed to "
					"remove interface %s from bridge %s: %s",
					__func__, ifname, brname, strerror(errno));
			return -1;
		}
		bss->added_if_into_bridge = 0;
	}

	return 0;
}


static void *
__madwifi_hostapd_init_bss(struct madwifi_driver_data *drv, struct hostapd_data *hapd,
				const char *name, const char *brname)
{
	struct madwifi_bss *bss;
	struct ifreq ifr;

	bss = os_zalloc(sizeof(struct madwifi_bss));
	if (bss == NULL)
		return NULL;

	dl_list_add(&drv->bss, &bss->list);
	bss->bss_ctx = hapd;
	bss->drv = drv;

	bss->sock_ioctl = socket(PF_INET, SOCK_DGRAM, 0);
	if (bss->sock_ioctl < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		goto bad;
	}
	os_memcpy(bss->ifname, name, sizeof(bss->ifname));

	os_memset(bss->brname, 0, sizeof(bss->brname));
	if (brname)
		strncpy(bss->brname, brname, sizeof(bss->brname));

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, bss->ifname, sizeof(ifr.ifr_name));
	if (ioctl(bss->sock_ioctl, SIOCGIFINDEX, &ifr) != 0) {
		perror("ioctl(SIOCGIFINDEX)");
		goto bad;
	}
	bss->ifindex = ifr.ifr_ifindex;

	bss->sock_xmit = l2_packet_init(bss->ifname, NULL, ETH_P_EAPOL,
					__madwifi_hostapd_eapol_recv_proc, bss, 1);
	if (bss->sock_xmit == NULL)
		goto bad;

	bss->sock_recv = bss->sock_xmit;

	/* mark down during setup */
	linux_set_iface_flags(bss->sock_ioctl, bss->ifname, 0);
	madwifi_hostapd_set_privacy(bss, 0); /* default to no privacy */

	__madwifi_hostapd_recv_pkt(bss);

	if (__madwifi_hostapd_wireless_event_init(bss))
		goto bad;

	if (__madwifi_hostapd_init_bss_bridge(bss, name))
		goto bad;

	return bss;
bad:
	if (bss->sock_xmit != NULL)
		l2_packet_deinit(bss->sock_xmit);
	if (bss->sock_ioctl >= 0)
		close(bss->sock_ioctl);
	dl_list_del(&bss->list);
	if (bss)
		os_free(bss);

	return NULL;
}


static int __madwifi_hostapd_bss_add(void *priv, const char *ifname, const u8 *bssid,
				void *bss_ctx, void **drv_priv, u8 *ifaddr, const char *bridge)
{
	struct madwifi_bss *primary_bss = priv;
	struct madwifi_driver_data *drv = primary_bss->drv;
	struct madwifi_bss *new_bss = NULL;
	char bssid_str[20] = {0};
	char buf[MADWIFI_CMD_BUF_SIZE];
	int ret;

	wpa_printf(MSG_DEBUG, "%s: ifname=%s, bssid=%s",
				__func__, ifname, __madwfi_ether_sprintf(bssid));

	if (hostapd_mac_comp_empty(bssid) == 0) {
		snprintf(buf, sizeof(buf), "start 0 ap %s\n", ifname);
	} else {
		snprintf(bssid_str, sizeof(bssid_str), "%02x:%02x:%02x:%02x:%02x:%02x",
			bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
		snprintf(buf, sizeof(buf), "start 0 ap %s %s\n", ifname, bssid_str);
	}

	ret = __madwifi_hostapd_write_to_qdrv_control(buf);
	if (ret < 0) {
		wpa_printf(MSG_ERROR, "%s: VAP create failed, "
				"couldn't write to qdrv control",
				__func__);
		return 1;
	}

	snprintf(buf, sizeof(buf),
			"echo 1 > /proc/sys/net/ipv6/conf/%s/disable_ipv6", ifname);
	system(buf);

	new_bss = __madwifi_hostapd_init_bss(drv, bss_ctx, ifname, bridge);
	if (new_bss == NULL) {
		wpa_printf(MSG_ERROR, "%s: new BSS is null", __func__);

		os_memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf) - 1, "stop 0 %s\n", ifname);

		ret = __madwifi_hostapd_write_to_qdrv_control(buf);
		if (ret < 0)
			wpa_printf(MSG_ERROR, "%s: VAP '%s' remove failed, "
				"couldn't write to qdrv control", __func__, ifname);

		if (drv_priv)
			*drv_priv = NULL;

		return 1;
	}

	if (linux_get_ifhwaddr(new_bss->sock_ioctl, new_bss->ifname, ifaddr)) {
		wpa_printf(MSG_ERROR, "%s: failed to get iface hw address",
				__func__);
		return 1;
	}

	os_memcpy(new_bss->bssid, ifaddr, ETH_ALEN);

	if (drv_priv)
		*drv_priv = new_bss;

	snprintf(buf, sizeof(buf), "/scripts/tc_prio -dev %s -join > /dev/null", ifname);
	system(buf);

	return 0;
}


static int __madwifi_hostapd_bss_remove(void *priv, const char *ifname)
{
	struct madwifi_bss *bss = priv;
	char buf[MADWIFI_CMD_BUF_SIZE];
	int ret;

	wpa_printf(MSG_DEBUG, "%s: ifname=%s", __func__, ifname);

	__madwifi_hostapd_deinit_bss_bridge(bss, ifname);
	madwifi_hostapd_set_privacy(bss, 0);
	netlink_deinit(bss->netlink);
	bss->netlink = NULL;
	(void) linux_set_iface_flags(bss->sock_ioctl, bss->ifname, 0);
	if (bss->sock_ioctl >= 0) {
		close(bss->sock_ioctl);
		bss->sock_ioctl = -1;
	}
	if (bss->sock_recv != NULL && bss->sock_recv != bss->sock_xmit) {
		l2_packet_deinit(bss->sock_recv);
		bss->sock_recv = NULL;
	}
	if (bss->sock_xmit != NULL) {
		l2_packet_deinit(bss->sock_xmit);
		bss->sock_xmit = NULL;
	}
	if (bss->sock_raw) {
		l2_packet_deinit(bss->sock_raw);
		bss->sock_raw = NULL;
	}
	dl_list_del(&bss->list);
	os_free(bss);

	os_memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1, "stop 0 %s\n", ifname);

	ret = __madwifi_hostapd_write_to_qdrv_control(buf);
	if (ret < 0) {
		wpa_printf(MSG_ERROR, "%s: VAP remove failed, "
				"couldn't write to qdrv control",
				__func__);
		return 1;
	}

	return 0;
}


static int madwifi_hostapd_if_add(void *priv, enum wpa_driver_if_type type,
			      const char *ifname, const u8 *addr,
			      void *bss_ctx, void **drv_priv,
			      char *force_ifname, u8 *if_addr,
			      const char *bridge, int use_existing, int setup_ap)
{
	wpa_printf(MSG_DEBUG, "%s(type=%d ifname=%s bss_ctx=%p)\n",
		   __func__, type, ifname, bss_ctx);

	if (type == WPA_IF_AP_BSS) {
		return __madwifi_hostapd_bss_add(priv, ifname, addr, bss_ctx,
				drv_priv, if_addr, bridge);
	}

	return 0;
}


static int madwifi_hostapd_if_remove(void *priv, enum wpa_driver_if_type type,
				 const char *ifname)
{
	wpa_printf(MSG_DEBUG, "%s(type=%d ifname=%s)", __func__, type, ifname);

	if (priv == NULL)
		return 0;

	if (type == WPA_IF_AP_BSS)
		return __madwifi_hostapd_bss_remove(priv, ifname);

	return 0;
}


static int
__madwifi_hostapd_get_driver_capa_info(struct madwifi_bss *bss)
{
	struct madwifi_driver_data *drv = bss->drv;
	struct iwreq iwr;
	u8 buf[MADWIFI_CMD_BUF_SIZE];
	u8 *pos = buf;
	u8 *end;
	u32 data_len;

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, bss->ifname, IFNAMSIZ);

	iwr.u.data.flags = SIOCDEV_SUBIO_GET_DRIVER_CAPABILITY;
	iwr.u.data.pointer = &buf;
	iwr.u.data.length = sizeof(buf);

	if (ioctl(bss->sock_ioctl, IEEE80211_IOCTL_EXT, &iwr) < 0) {
		wpa_printf(MSG_ERROR, "%s: Failed to get Ext capability"
			" from driver ", __func__);
		return -1;
	}

	data_len = (u32)*pos;
	end = pos + data_len;
	pos += sizeof(u32);

	while (pos < end) {
		switch (*pos) {
			case IEEE80211_ELEMID_EXTCAP:
				pos++;
				drv->extended_capa_len = *pos++;
				drv->extended_capa = os_zalloc(drv->extended_capa_len);

				if (drv->extended_capa) {
					os_memcpy(drv->extended_capa, pos,
								drv->extended_capa_len);
					pos += drv->extended_capa_len;
				}

				drv->extended_capa_mask = os_zalloc(drv->extended_capa_len);

				if (drv->extended_capa_mask) {
					os_memcpy(drv->extended_capa_mask, pos,
						drv->extended_capa_len);
					pos += drv->extended_capa_len;
				} else {
					os_free(drv->extended_capa);
					drv->extended_capa = NULL;
					drv->extended_capa_len = 0;
				}
				break;
			default:
				wpa_printf(MSG_DEBUG, "Not handling other data %d\n", *pos);
				pos = end; /* Exit here */
				break;
		}
	}

	return 0;
}


static void *
madwifi_hostapd_init(struct hostapd_data *hapd, struct wpa_init_params *params)
{
	struct madwifi_driver_data *drv;
	struct madwifi_bss *bss;
	char brname[IFNAMSIZ];

	wpa_printf(MSG_DEBUG, "%s:", __func__);

	drv = os_zalloc(sizeof(struct madwifi_driver_data));
	if (drv == NULL) {
		wpa_printf(MSG_ERROR, "Could not allocate memory for madwifi driver data\n");
		return NULL;
	}

	dl_list_init(&drv->bss);

	bss = __madwifi_hostapd_init_bss(drv, hapd, params->ifname, hapd->conf->bridge);
	if (bss == NULL) {
		os_free(drv);
		return NULL;
	}

	/* FIXME: handle this for the new BSS case too */
	if (l2_packet_get_own_addr(bss->sock_xmit, params->own_addr))
		goto bad;
	if (params->bridge[0]) {
		wpa_printf(MSG_DEBUG, "Configure bridge %s for EAPOL traffic.",
			   params->bridge[0]);
		bss->sock_recv = l2_packet_init(params->bridge[0], NULL,
						ETH_P_EAPOL, __madwifi_hostapd_eapol_recv_proc, bss,
						1);
		if (bss->sock_recv == NULL)
			goto bad;
	} else if (linux_br_get(brname, bss->ifname) == 0) {
		wpa_printf(MSG_DEBUG, "Interface in bridge %s; configure for "
			   "EAPOL receive", brname);
		bss->sock_recv = l2_packet_init(brname, NULL, ETH_P_EAPOL,
						__madwifi_hostapd_eapol_recv_proc, bss, 1);
		if (bss->sock_recv == NULL)
			goto bad;
	} else {
		bss->sock_recv = bss->sock_xmit;
	}

	os_memcpy(bss->bssid, params->own_addr, ETH_ALEN);

	if (__madwifi_hostapd_get_driver_capa_info(bss))
		goto bad;

	__madwifi_set80211param(bss, IEEE80211_PARAM_HOSTAP_STARTED, 1);

	return bss;
bad:
	__madwifi_hostapd_bss_remove(bss, params->ifname);
	os_free(drv);
	return NULL;
}


static void
madwifi_hostapd_deinit(void *priv)
{
	/*
	 * This function cleans up the primary BSS.
	 * Secondary BSSes will be cleaned up in madwifi_hostapd_if_remove()
	 */
	struct madwifi_bss *bss = priv;
	struct madwifi_driver_data *drv = bss->drv;

	wpa_printf(MSG_DEBUG, "%s:", __func__);

	__madwifi_set80211param(bss, IEEE80211_PARAM_HOSTAP_STARTED, 0);

	netlink_deinit(bss->netlink);
	bss->netlink = NULL;
	(void) linux_set_iface_flags(bss->sock_ioctl, bss->ifname, 0);
	if (bss->sock_ioctl >= 0) {
		close(bss->sock_ioctl);
		bss->sock_ioctl = -1;
	}

	if (bss->sock_recv != NULL && bss->sock_recv != bss->sock_xmit) {
		l2_packet_deinit(bss->sock_recv);
		bss->sock_recv = NULL;
	}

	if (bss->sock_xmit != NULL) {
		l2_packet_deinit(bss->sock_xmit);
		bss->sock_xmit = NULL;
	}

	if (bss->sock_raw) {
		l2_packet_deinit(bss->sock_raw);
		bss->sock_raw = NULL;
	}

	if (drv->extended_capa)
		os_free(drv->extended_capa);

	if (drv->extended_capa_mask)
		os_free(drv->extended_capa_mask);

	dl_list_del(&bss->list);
	os_free(bss);
	free(drv);
}


static int
madwifi_hostapd_set_ssid(void *priv, const u8 *buf, int len)
{
	struct madwifi_bss *bss = priv;
	struct iwreq iwr;

	wpa_printf(MSG_DEBUG, "%s: ifname=%s, ssid=%s", __func__, bss->ifname, buf);

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, bss->ifname, IFNAMSIZ);
	iwr.u.essid.flags = 1; /* SSID active */
	iwr.u.essid.pointer = (caddr_t) buf;
	iwr.u.essid.length = len;

	if (ioctl(bss->sock_ioctl, SIOCSIWESSID, &iwr) < 0) {
		perror("ioctl[SIOCSIWESSID]");
		printf("len=%d\n", len);
		return -1;
	}
	return 0;
}


static int
madwifi_hostapd_get_ssid(void *priv, u8 *buf, int len)
{
	struct madwifi_bss *bss = priv;
	struct iwreq iwr;
	int ret = 0;

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, bss->ifname, IFNAMSIZ);
	iwr.u.essid.pointer = (caddr_t) buf;
	iwr.u.essid.length = len;

	if (ioctl(bss->sock_ioctl, SIOCGIWESSID, &iwr) < 0) {
		perror("ioctl[SIOCGIWESSID]");
		ret = -1;
	} else
		ret = iwr.u.essid.length;

	return ret;
}


static int
madwifi_hostapd_set_countermeasures(void *priv, int enabled)
{
	struct madwifi_bss *bss = priv;

	wpa_printf(MSG_DEBUG, "%s: enabled=%d", __func__, enabled);
	return __madwifi_set80211param(bss, IEEE80211_PARAM_COUNTERMEASURES, enabled);
}


static int
madwifi_get_default_if_state(const char *ifname)
{
	char cmd_buf[64];
	int up_flag = 1;
	FILE *popen_output;

	snprintf(cmd_buf, sizeof(cmd_buf), "/scripts/get_wifi_config %s default_up", ifname);
	popen_output = popen(cmd_buf, "r");
	if (!popen_output)
		return 1;

	fscanf(popen_output, "%d", &up_flag);
	pclose(popen_output);

	return !!up_flag;
}

static int
madwifi_hostapd_commit(void *priv)
{
	struct madwifi_bss *bss = priv;
	int up_flag = madwifi_get_default_if_state(bss->ifname);

	wpa_printf(MSG_DEBUG, "%s:", __func__);
	return linux_set_iface_flags(bss->sock_ioctl, bss->ifname, up_flag);
}


static int
madwifi_hostapd_set_intra_bss(void *priv, int enabled)
{
	struct madwifi_bss *bss = priv;

	wpa_printf(MSG_DEBUG, "%s: enabled=%d", __func__, enabled);
	return __madwifi_set80211param(bss, IEEE80211_PARAM_AP_ISOLATE, enabled);
}


static int
madwifi_hostapd_set_intra_per_bss(void *priv, int enabled)
{
	struct madwifi_bss *bss = priv;

	wpa_printf(MSG_DEBUG, "%s: enabled=%d", __func__, enabled);
	__madwifi_set80211param(bss, IEEE80211_PARAM_INTRA_BSS_ISOLATE, enabled);

	return 0;
}


static int
madwifi_hostapd_set_bss_isolate(void *priv, int enabled)
{
	struct madwifi_bss *bss = priv;

	wpa_printf(MSG_DEBUG, "%s: enabled=%d", __func__, enabled);
	__madwifi_set80211param(bss, IEEE80211_PARAM_BSS_ISOLATE, enabled);

	return 0;
}


static int
madwifi_hostapd_set_bss_assoc_limit(void *priv, int limit)
{
	struct madwifi_bss *bss = priv;

	wpa_printf(MSG_DEBUG, "%s: limit=%d", __func__, limit);
	return __madwifi_set80211param(bss, IEEE80211_PARAM_BSS_ASSOC_LIMIT, limit);
}


static int
madwifi_hostapd_set_total_assoc_limit(void *priv, int limit)
{
	struct madwifi_bss *bss = priv;

	wpa_printf(MSG_DEBUG, "%s: limit=%d", __func__, limit);
	return __madwifi_set80211param(bss, IEEE80211_PARAM_ASSOC_LIMIT, limit);
}


static int
madwifi_hostapd_set_broadcast_ssid(void *priv, int value)
{
	struct madwifi_bss *bss = priv;

	wpa_printf(MSG_DEBUG, "%s: value=0x%x", __func__, value);
	return __madwifi_set80211param(bss, IEEE80211_PARAM_HIDESSID, value);
}


static void madwifi_hostapd_send_log(void *priv, const char *msg)
{
	struct madwifi_bss *bss = priv;
	__madwifi_set80211priv(bss, IEEE80211_IOCTL_POSTEVENT, (void *) msg,
			os_strnlen(msg, MAX_WLAN_MSG_LEN));
}


#ifdef CONFIG_IEEE80211R
static int madwifi_hostapd_add_sta_node(void *priv, const u8 *addr, u16 auth_alg)
{
	struct madwifi_bss *bss = priv;
	struct iwreq iwr;
	int ret = 0;
	u8 *buf = NULL;

	wpa_printf(MSG_DEBUG, "%s: auth_alg=%d", __func__, auth_alg);

	buf = os_malloc(IEEE80211_ADDR_LEN);
	if (!buf)
		return -ENOMEM;

	os_memcpy(buf, addr, IEEE80211_ADDR_LEN);
	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, bss->ifname, IFNAMSIZ);
	iwr.u.data.flags = SIOCDEV_SUBIO_SET_FT_ADD_NODE;
	iwr.u.data.pointer = buf;
	iwr.u.data.length = IEEE80211_ADDR_LEN;

	if (ioctl(bss->sock_ioctl, IEEE80211_IOCTL_EXT, &iwr) < 0) {
		wpa_printf(MSG_ERROR, "%s: Failed FT add node\n", __func__);
		ret = -1;
	}

	os_free(buf);
	return ret;
}
#endif


static int
madwifi_hostapd_get_capa(void *priv, struct wpa_driver_capa *capa)
{
	struct madwifi_bss *bss = priv;
	struct madwifi_driver_data *drv = bss->drv;
	int drv_24g_capab = 0;

	if (drv->extended_capa) {
		capa->extended_capa_len = drv->extended_capa_len;
		capa->extended_capa = drv->extended_capa;
		capa->extended_capa_mask = drv->extended_capa_mask;
	} else {
		return -1;
	}

	if (__madwifi_get80211param(priv, IEEE80211_PARAM_2_4G_CAPAB, &drv_24g_capab))
		wpa_printf(MSG_WARNING, "%s: failed to get 2.4G capability from driver", __func__);

	capa->hw_capab_24g = drv_24g_capab;

	return 0;
}


static int
__madwifi_hostapd_set_interworking(struct madwifi_bss *bss,
			struct wpa_driver_ap_params *params)
{
	struct iwreq iwr;
	struct app_ie ie;

	wpa_printf(MSG_DEBUG, "%s:", __func__);

	os_memset(&ie, 0, sizeof(struct app_ie));

	ie.id = WLAN_EID_INTERWORKING;		/* IE ID */
	ie.u.interw.interworking = params->interworking;
	ie.len++;

	if (params->interworking) {
		ie.u.interw.an_type = params->access_network_type;
		ie.len++;

		if (params->hessid) {
			os_memcpy(ie.u.interw.hessid, params->hessid, ETH_ALEN);
			ie.len += ETH_ALEN;
		}
	}

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, bss->ifname, IFNAMSIZ);
	iwr.u.data.flags = SIOCDEV_SUBIO_SET_AP_INFO;
	iwr.u.data.pointer = &ie;
	iwr.u.data.length = ie.len + 1 + 2;	/* IE data len + IE ID + IE len */

	if (ioctl(bss->sock_ioctl, IEEE80211_IOCTL_EXT, &iwr) < 0) {
		wpa_printf(MSG_ERROR, "%s: Failed to set interworking"
				"info ioctl", __func__);
		return -1;
	}

	return 0;
}


static int
madwifi_hostapd_set_ap(void *priv, struct wpa_driver_ap_params *params)
{
	struct madwifi_bss *bss = priv;

	wpa_printf(MSG_DEBUG, "%s:", __func__);

	/* TODO As of now this function is used for setting HESSID and
	* Access Network Type. It can be used for other elements in future
	* like set_authmode, set_privacy, set_ieee8021x, set_generic_elem
	* and hapd_set_ssid */

	if (__madwifi_hostapd_set_interworking(bss, params))
		return -1;

	if (__madwifi_set80211param(bss, IEEE80211_PARAM_HS2, params->hs20_enable)) {
		wpa_printf(MSG_ERROR, "%s: Unable to set hs20 enabled to %d\n",
					__func__, params->hs20_enable);
		return -1;
	}

	if (__madwifi_set80211param(bss, IEEE80211_PARAM_DGAF_CONTROL,
					params->disable_dgaf)) {
		wpa_printf(MSG_ERROR, "%s: Unable to set disable dgaf to %u\n",
					__func__, params->disable_dgaf);
		return -1;
	}

	if (__madwifi_set80211param(bss, IEEE80211_PARAM_PROXY_ARP,
					params->proxy_arp)) {
		wpa_printf(MSG_ERROR, "%s: Unable to set proxy ARP to %u\n",
					__func__, params->proxy_arp);
		return -1;
	}

	if (__madwifi_set80211param(bss, IEEE80211_PARAM_DTIM_PERIOD,
					params->dtim_period)) {
		wpa_printf(MSG_ERROR, "%s: Unable to set DTIM period to %u\n",
					__func__, params->dtim_period);
		return -1;
	}

#ifdef CONFIG_HS20
	if (params->osen) {
		struct wpa_bss_params wpa_params;
		os_memset(&wpa_params, 0, sizeof(wpa_params));

		wpa_params.enabled = 1;
		wpa_params.wpa = 2;
		wpa_params.ieee802_1x = 1;
		wpa_params.wpa_group = WPA_CIPHER_CCMP;
		wpa_params.wpa_pairwise = WPA_CIPHER_CCMP;
		wpa_params.wpa_key_mgmt = WPA_KEY_MGMT_IEEE8021X;
		if (madwifi_hostapd_set_privacy(priv, 1)) {
			wpa_printf(MSG_ERROR, "%s: Unable to enable privacy\n", __func__);
			return -1;
		}
		if (madwifi_hostapd_set_ieee8021x(priv, &wpa_params)) {
			wpa_printf(MSG_ERROR, "%s: Unable to set 802.1X params\n", __func__);
			return -1;
		}
		if (__madwifi_set80211param(bss, IEEE80211_PARAM_OSEN, 1)) {
			wpa_printf(MSG_ERROR, "%s: Unable to set OSEN\n", __func__);
			return -1;
		}
	}
#endif
#ifdef CONFIG_IEEE80211R
	if (__madwifi_set80211param(bss, IEEE80211_PARAM_MOBILITY_DOMAIN,
					params->mdid)) {
		wpa_printf(MSG_ERROR, "%s: Unable to set mobility domain id to %u\n",
					__func__, params->mdid);
		return -1;
	}
	if (__madwifi_set80211param(bss, IEEE80211_PARAM_FT_OVER_DS,
					params->ft_over_ds)) {
		wpa_printf(MSG_ERROR, "%s: Unable to set ft over ds value: %u\n",
					__func__, params->ft_over_ds);
		return -1;
	}
#endif

	return 0;
}


int madwifi_hostapd_set_qos_map(void *priv, const u8 *qos_map_set,
			   u8 qos_map_set_len)
{
	struct madwifi_bss *bss = priv;
	u8 dscp2up[IP_DSCP_NUM];
	struct iwreq iwr;
	int up_start_idx;
	const u8 *up_map;
	u8 up;
	u8 dscp;
	u8 dscp_low;
	u8 dscp_high;
	int i;

	wpa_printf(MSG_DEBUG, "%s:", __func__);

	if (qos_map_set_len < (IEEE8021P_PRIORITY_NUM * 2) ||
	    qos_map_set_len > ((IEEE8021P_PRIORITY_NUM + IEEE80211_DSCP_MAX_EXCEPTIONS) * 2) ||
	    (qos_map_set_len & 1)) {
		wpa_printf(MSG_ERROR, "%s invalid QoS Map length\n", __func__);
		return -1;
	}

	up_start_idx = qos_map_set_len - IEEE8021P_PRIORITY_NUM * 2;
	up_map = &qos_map_set[up_start_idx];
	os_memset(dscp2up, IEEE8021P_PRIORITY_NUM, sizeof(dscp2up));

	for (up = 0; up < IEEE8021P_PRIORITY_NUM; up++) {
		dscp_low = up_map[up * 2];
		dscp_high = up_map[up * 2 + 1];
		if (dscp_low < IP_DSCP_NUM &&
		    dscp_high < IP_DSCP_NUM &&
		    dscp_low <= dscp_high) {
			os_memset(&dscp2up[dscp_low], up, dscp_high - dscp_low + 1);
		}
	}
	for (i = 0; i < up_start_idx; i += 2) {
		dscp = qos_map_set[i];
		up = qos_map_set[i + 1];
		if (dscp < IP_DSCP_NUM) {
			dscp2up[dscp] = up;
		}
	}

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, bss->ifname, IFNAMSIZ);
	iwr.u.data.flags = SIOCDEV_SUBIO_SET_DSCP2TID_MAP;
	iwr.u.data.pointer = dscp2up;
	iwr.u.data.length = IP_DSCP_NUM;

	if (ioctl(bss->sock_ioctl, IEEE80211_IOCTL_EXT, &iwr) < 0) {
		wpa_printf(MSG_ERROR, "%s: Failed to call SIOCDEV_SUBIO_SET_DSCP2TID_MAP",
			__func__);
		return -1;
	}

	return 0;
}


int madwifi_hostapd_set_acl(void *priv, struct hostapd_acl_params *params)
{
	struct madwifi_bss *bss = priv;
	struct ieee80211_acl_params *acl_params;
	struct iwreq iwr;
	int len = sizeof(*acl_params) +
		(sizeof(acl_params->mac_acl[0]) * (params->num_mac_acl + params->num_oui_acl));
	int ret = 0;
	int i;

	wpa_printf(MSG_DEBUG, "%s:", __func__);

	acl_params = os_zalloc(len);
	if (!acl_params) {
		wpa_printf(MSG_ERROR, "%s: malloc failed", __func__);
		return -ENOMEM;
	}

	switch (params->acl_policy) {
		case ACCEPT_UNLESS_DENIED:
			if (params->num_mac_acl > 0)
				acl_params->acl_policy = IEEE80211_MACCMD_POLICY_DENY;
			else
				acl_params->acl_policy = IEEE80211_MACCMD_POLICY_OPEN;
			break;
		case DENY_UNLESS_ACCEPTED:
			acl_params->acl_policy = IEEE80211_MACCMD_POLICY_ALLOW;
			break;
		default:
			wpa_printf(MSG_ERROR, "%s: Invalid mac filter policy", __func__);
			ret = -1;
			goto end;
	}

	acl_params->num_mac_acl = params->num_mac_acl;
	acl_params->num_oui_acl = params->num_oui_acl;

	for (i = 0; i < params->num_mac_acl + params->num_oui_acl; i++)
		os_memcpy(acl_params->mac_acl[i].addr, params->mac_acl[i].addr, ETH_ALEN);

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, bss->ifname, IFNAMSIZ);
	iwr.u.data.flags = SIOCDEV_SUBIO_SET_MAC_ADDR_ACL;
	iwr.u.data.pointer = acl_params;
	iwr.u.data.length = len;

	if (ioctl(bss->sock_ioctl, IEEE80211_IOCTL_EXT, &iwr) < 0) {
		wpa_printf(MSG_ERROR, "%s: Failed to call SIOCDEV_SUBIO_SET_MAC_ACL", __func__);
		ret = -1;
	}

end:
	os_free(acl_params);
	return ret;
}


#else /* HOSTAPD */
static int
__madwifi_supplicant_authalg_to_authmode(int auth_alg)
{
	int auth_mode = IEEE80211_AUTH_AUTO;

	if ((auth_alg & WPA_AUTH_ALG_OPEN) && (auth_alg & WPA_AUTH_ALG_SHARED))
		auth_mode = IEEE80211_AUTH_AUTO;
	else if (auth_alg & WPA_AUTH_ALG_SHARED)
		auth_mode = IEEE80211_AUTH_SHARED;
	else if (auth_alg & WPA_AUTH_ALG_SAE)
		auth_mode = IEEE80211_AUTH_SAE;
	else
		auth_mode = IEEE80211_AUTH_OPEN;

	return auth_mode;
}

static int
__madwifi_supplicant_set_auth_alg(void *priv, int auth_alg, unsigned int key_mgmt_suite)
{
	struct madwifi_driver_data *drv = priv;
	int authmode;

	wpa_printf(MSG_DEBUG, "%s: auth_alg=0x%x, key_mgmt_suite=0x%x",
				__func__, auth_alg, key_mgmt_suite);

	authmode = __madwifi_supplicant_authalg_to_authmode(auth_alg);

	wpa_printf(MSG_DEBUG, "%s: set authmode %d", __func__, authmode);
	return __madwifi_set80211param(drv, IEEE80211_PARAM_AUTHMODE, authmode);
}


static int
__madwifi_supplicant_set_wpa_ie(struct madwifi_driver_data *drv,
			      const u8 *wpa_ie, size_t wpa_ie_len)
{
	struct iwreq iwr;

	wpa_printf(MSG_DEBUG, "%s: wpa_ie_len=%d", __func__, (int)wpa_ie_len);

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
	/* NB: SETOPTIE is not fixed-size so must not be inlined */
	iwr.u.data.pointer = (void *) wpa_ie;
	iwr.u.data.length = wpa_ie_len;

	if (ioctl(drv->sock_ioctl, IEEE80211_IOCTL_SETOPTIE, &iwr) < 0) {
		perror("ioctl[IEEE80211_IOCTL_SETOPTIE]");
		return -1;
	}
	return 0;
}


static int __madwifi_supplicant_set_probe_req_ie(void *priv, const u8 *ies,
					       size_t ies_len)
{
	struct ieee80211req_getset_appiebuf *probe_req_ie;
	int ret;

	wpa_printf(MSG_DEBUG, "%s: ies_len=%d", __func__, (int)ies_len);

	probe_req_ie = os_zalloc(sizeof(*probe_req_ie) + ies_len);
	if (probe_req_ie == NULL)
		return -1;

	probe_req_ie->app_frmtype = IEEE80211_APPIE_FRAME_PROBE_REQ;
	probe_req_ie->app_buflen = ies_len;
	os_memcpy(probe_req_ie->app_buf, ies, ies_len);

	ret = __madwifi_set80211priv(priv, IEEE80211_IOCTL_SET_APPIEBUF, probe_req_ie,
			   sizeof(struct ieee80211req_getset_appiebuf) +
			   ies_len);

	os_free(probe_req_ie);

	return ret;
}


static int
madwifi_supplicant_set_countermeasures(void *priv, int enabled)
{
	struct madwifi_driver_data *drv = priv;

	wpa_printf(MSG_DEBUG, "%s: enabled=%d", __func__, enabled);
	return __madwifi_set80211param(drv, IEEE80211_PARAM_COUNTERMEASURES, enabled);
}


static int
madwifi_supplicant_deauthenticate(void *priv, const u8 *addr, int reason_code)
{
	struct madwifi_driver_data *drv = priv;
	struct ieee80211req_mlme mlme;

	wpa_printf(MSG_DEBUG, "%s: addr=%s reason_code=%d",
				__func__, __madwfi_ether_sprintf(addr), reason_code);

	mlme.im_op = IEEE80211_MLME_DEAUTH;
	mlme.im_reason = reason_code;
	os_memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
	return __madwifi_set80211priv(drv, IEEE80211_IOCTL_SETMLME, &mlme, sizeof(mlme));
}


static int
madwifi_supplicant_disassociate(void *priv, const u8 *addr, int reason_code)
{
	struct madwifi_driver_data *drv = priv;
	struct ieee80211req_mlme mlme;

	wpa_printf(MSG_DEBUG, "%s: addr=%s reason_code=%d",
				__func__, __madwfi_ether_sprintf(addr), reason_code);

	mlme.im_op = IEEE80211_MLME_DISASSOC;
	mlme.im_reason = reason_code;
	os_memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
	return __madwifi_set80211priv(drv, IEEE80211_IOCTL_SETMLME, &mlme, sizeof(mlme));
}


static int
__madwifi_supplicant_check_mmie_mic(const u8 *igtk, const u8 *data, size_t len)
{
	u8 *buf;
	u8 mic[16];
	u16 fc;
	const struct ieee80211_hdr *hdr;

	buf = os_malloc(len + BIP_AAD_LEN - IEEE80211_3ADDR_LEN);
	if (buf == NULL)
		return -1;

	/* BIP AAD: FC(masked) A1 A2 A3 */
	hdr = (const struct ieee80211_hdr *) data;
	fc = le_to_host16(hdr->frame_control);
	fc &= ~(WLAN_FC_RETRY | WLAN_FC_PWRMGT | WLAN_FC_MOREDATA);
	WPA_PUT_LE16(buf, fc);
	os_memcpy(buf + 2, hdr->addr1, 3 * ETH_ALEN);

	/* Frame body with MMIE MIC masked to zero */
	os_memcpy(buf + BIP_AAD_LEN, data + IEEE80211_3ADDR_LEN, len - IEEE80211_3ADDR_LEN - BIP_MIC_LEN);
	os_memset(buf + BIP_AAD_LEN + len - IEEE80211_3ADDR_LEN - BIP_MIC_LEN, 0, BIP_MIC_LEN);

	wpa_hexdump(MSG_MSGDUMP, "BIP: AAD|Body(masked)", buf, len + BIP_AAD_LEN - IEEE80211_3ADDR_LEN);
	/* MIC = L(AES-128-CMAC(AAD || Frame Body(masked)), 0, 64) */
	if (omac1_aes_128(igtk, buf, len + BIP_AAD_LEN - IEEE80211_3ADDR_LEN, mic) < 0) {
		os_free(buf);
		return -1;
	}

	os_free(buf);

	if (os_memcmp(data + len - BIP_MIC_LEN, mic, BIP_MIC_LEN) != 0)
		return -1;

	return 0;
}


static int
__madwifi_supplicant_check_bip(struct madwifi_driver_data *drv, const u8 *data, size_t len)
{
	const struct ieee80211_mgmt *mgmt;
	u16 fc, stype;
	const u8 *mmie;
	u16 keyid;
	struct ieee80211req_key *igtk = &drv->drv_igtk_wk;

	mgmt = (const struct ieee80211_mgmt *) data;
	fc = le_to_host16(mgmt->frame_control);
	stype = WLAN_FC_GET_STYPE(fc);

	if (!igtk || !igtk->ik_keylen) {
		wpa_printf(MSG_DEBUG, "No IGTK known to validate BIP frame");
		return 0;
	}

	if (len < IEEE80211_3ADDR_LEN + 18 || data[len - 18] != WLAN_EID_MMIE ||
	    data[len - 17] != 16) {
		/* No MMIE */
		wpa_printf(MSG_INFO, "Robust group-addressed "
				   "management frame sent without BIP by "
				   MACSTR, MAC2STR(mgmt->sa));
		return -1;
	}

	mmie = data + len - 16;
	keyid = WPA_GET_LE16(mmie);
	if (keyid & 0xf000) {
		wpa_printf(MSG_INFO, "MMIE KeyID reserved bits not zero "
			   "(%04x) from " MACSTR, keyid, MAC2STR(mgmt->sa));
		keyid &= 0x0fff;
	}
	if (keyid < 4 || keyid > 5) {
		wpa_printf(MSG_INFO, "Unexpected MMIE KeyID %u from " MACSTR,
			   keyid, MAC2STR(mgmt->sa));
		return 0;
	}
	wpa_printf(MSG_DEBUG, "MMIE KeyID %u", keyid);
	wpa_hexdump(MSG_MSGDUMP, "MMIE IPN", mmie + 2, BIP_IPN_LEN);
	wpa_hexdump(MSG_MSGDUMP, "MMIE MIC", mmie + 8, BIP_MIC_LEN);


	if (os_memcmp(mmie + 2, drv->ipn, BIP_IPN_LEN) <= 0) {
		wpa_printf(MSG_INFO, "BIP replay detected: SA=" MACSTR,
			   MAC2STR(mgmt->sa));
		wpa_hexdump(MSG_INFO, "RX IPN", mmie + 2, BIP_IPN_LEN);
		wpa_hexdump(MSG_INFO, "Last RX IPN", drv->ipn, BIP_IPN_LEN);
	}


	if (__madwifi_supplicant_check_mmie_mic(igtk->ik_keydata, data, len) < 0) {
		wpa_printf(MSG_INFO, "Invalid MMIE MIC in a frame from "
			   MACSTR, MAC2STR(mgmt->sa));
		return -1;
	}

	wpa_printf(MSG_DEBUG, "Valid MMIE MIC");
	os_memcpy(drv->ipn, mmie + 2, BIP_IPN_LEN);

	return 1;
}


static void
__madwifi_supplicant_rx_action(struct madwifi_driver_data *drv, const u8 *data, size_t len)
{
	const struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)data;
	union wpa_event_data event;
	const u8 *pos;
	u8 cat;
	u8 act;

	if (len < IEEE80211_3ADDR_LEN)
		return;

	cat = mgmt->u.action.category;
	pos = &mgmt->u.action.category;
	act = *(++pos);

	switch (cat) {
		case WLAN_ACTION_WNM:
			/* Currently only process BTM request frame */
			if (act != WNM_BSS_TRANS_MGMT_REQ)
				break;

			wpa_printf(MSG_DEBUG, "RX_MGMT WNM: sa="MACSTR" freq %d",
					MAC2STR(mgmt->sa), mgmt->duration);
			os_memset(&event, 0, sizeof(event));
			event.rx_action.sa = mgmt->sa;
			event.rx_action.da = mgmt->da;
			event.rx_action.bssid = mgmt->bssid;
			event.rx_action.category = cat;
			event.rx_action.data = data;
			event.rx_action.len = len;
			event.rx_action.freq = mgmt->duration;
			wpa_supplicant_event(drv->ctx, EVENT_RX_ACTION, &event);
			break;
		case WLAN_ACTION_PUBLIC:
			wpa_printf(MSG_DEBUG, "RX_MGMT PUBACT: sa="MACSTR" freq %d",
					MAC2STR(mgmt->sa), mgmt->duration);
			os_memset(&event, 0, sizeof(event));
			event.rx_mgmt.frame = (const u8 *) mgmt;
			event.rx_mgmt.frame_len = len;
			event.rx_mgmt.freq = mgmt->duration;
			wpa_supplicant_event(drv->ctx, EVENT_RX_MGMT, &event);
			break;
		default:
			break;
	}
}


static void
__madwifi_supplicant_rx_mgmt(struct madwifi_driver_data *drv, const u8 *data, size_t len)
{
	const struct ieee80211_hdr *hdr;
	u16 fc;
	u16 stype;

	if (len < IEEE80211_3ADDR_LEN)
		return;

	hdr = (const struct ieee80211_hdr *) data;
	fc = le_to_host16(hdr->frame_control);

	stype = WLAN_FC_GET_STYPE(fc);

	wpa_printf(MSG_DEBUG, "%s: RX MGMT subtype=%u, len=%d", __func__, stype, (int)len);

	wpa_hexdump(MSG_DEBUG, "__madwifi_supplicant_rx_mgmt", data, len);

	/* Check BIP for broadcast deauth/disassoc only */
	if ((hdr->addr1[0] & 0x01) &&
	    (stype == WLAN_FC_STYPE_DEAUTH ||
	     stype == WLAN_FC_STYPE_DISASSOC)) {
		if (__madwifi_supplicant_check_bip(drv, data, len) > 0)
			madwifi_supplicant_deauthenticate(drv, hdr->IEEE80211_SA_FROMDS, 2);

	} else if (stype == WLAN_FC_STYPE_AUTH) {
		const struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)data;
		union wpa_event_data evt_data;

		os_memset(&evt_data, 0, sizeof(evt_data));
		os_memcpy(evt_data.auth.peer, mgmt->sa, ETH_ALEN);
		os_memcpy(evt_data.auth.bssid, mgmt->bssid, ETH_ALEN);
		evt_data.auth.auth_type = mgmt->u.auth.auth_alg;
		evt_data.auth.auth_transaction = mgmt->u.auth.auth_transaction;
		evt_data.auth.status_code = mgmt->u.auth.status_code;
		evt_data.auth.ies = mgmt->u.auth.variable;
		evt_data.auth.ies_len = len - (IEEE80211_HDRLEN + sizeof(mgmt->u.auth));
#ifdef CONFIG_QTNA_WIFI
		evt_data.auth.auth_event_source = AUTH_FROM_L2PCAP_EVENT;
#endif
		wpa_supplicant_event(drv->ctx, EVENT_AUTH, &evt_data);
	}
}


static void
__madwifi_supplicant_mgmt_receive(void *ctx, const u8 *src_addr, const u8 *buf,
				size_t len)
{
	struct madwifi_driver_data *drv = ctx;
	const struct ieee80211_mgmt *mgmt;
	u16 fc;

	mgmt = (const struct ieee80211_mgmt *)buf;

	fc = le_to_host16(mgmt->frame_control);

	wpa_printf(MSG_DEBUG, "%s: src_addr=%s len=%d, fc=0x%04x",
				__func__, __madwfi_ether_sprintf(src_addr), (int)len, fc);

	if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT)
		return;

	if (WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_AUTH ||
			WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_DEAUTH ||
			WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_DISASSOC) {
		__madwifi_supplicant_rx_mgmt(drv, buf, len);
	} else if (WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_ACTION) {
		__madwifi_supplicant_rx_action(drv, buf, len);
	}
}


static int
__madwifi_supplicant_set_mgmt_recv_filter(struct madwifi_driver_data *drv,
				struct wpa_driver_associate_params *params)
{
	struct ieee80211req_set_filter filt;
	int btm_cap = 0;
	int ret;

	os_memset(&filt, 0, sizeof(filt));

	__madwifi_get80211param(drv, IEEE80211_PARAM_80211V_BTM, &btm_cap);
	if (btm_cap != 0)
		filt.app_filterype |= IEEE80211_FILTER_TYPE_WNM_ACTION;

	/* enable mgmt filter only when PMF/SHA-256 is enabled for BIP check */
	if (params->key_mgmt_suite & (WPA_KEY_MGMT_IEEE8021X_SHA256 | WPA_KEY_MGMT_PSK_SHA256))
		filt.app_filterype |= (IEEE80211_FILTER_TYPE_DEAUTH |
					IEEE80211_FILTER_TYPE_DISASSOC);

	ret = __madwifi_set80211priv(drv, IEEE80211_IOCTL_FILTERFRAME, &filt,
			   sizeof(struct ieee80211req_set_filter));
	if (ret < 0) {
		wpa_printf(MSG_ERROR, "%s: IOCTL FILTERFRAME failed", __func__);
		return -1;
	}

	return 0;
}


static int
madwifi_supplicant_associate(void *priv,
			     struct wpa_driver_associate_params *params)
{
	struct madwifi_driver_data *drv = priv;
	struct ieee80211req_mlme mlme;
	int ret = 0, privacy = 1, wpa = 0;

	wpa_printf(MSG_DEBUG, "%s: auth_alg=0x%x, pair_suite=0x%x, grp_suite=%d, key_mgmt_suite=%d",
				__func__, params->auth_alg, params->pairwise_suite,
				params->group_suite, params->key_mgmt_suite);

	if (__madwifi_set80211param(drv, IEEE80211_PARAM_DROPUNENCRYPTED,
			  params->drop_unencrypted) < 0)
		ret = -1;

	if (__madwifi_supplicant_set_auth_alg(drv, params->auth_alg, params->key_mgmt_suite) < 0)
		ret = -1;

	/*
	 * NB: Don't need to set the freq or cipher-related state as
	 *     this is implied by the bssid which is used to locate
	 *     the scanned node state which holds it.  The ssid is
	 *     needed to disambiguate an AP that broadcasts multiple
	 *     ssid's but uses the same bssid.
	 */
	/* XXX error handling is wrong but unclear what to do... */
	if (__madwifi_supplicant_set_wpa_ie(drv, params->wpa_ie,
					  params->wpa_ie_len) < 0)
		ret = -1;

	if (params->pairwise_suite == WPA_CIPHER_NONE &&
		params->group_suite == WPA_CIPHER_NONE &&
		params->key_mgmt_suite == WPA_KEY_MGMT_NONE) {
		wpa_printf(MSG_DEBUG, "%s: disabling privacy and WPA", __func__);
		privacy = 0;
	} else {
		wpa_printf(MSG_DEBUG, "%s: enabling privacy and WPA", __func__);
		if (params->wpa_ie_len) {
			wpa_printf(MSG_DEBUG, "%s: enabling WPA eid=0x%x", __func__,
					params->wpa_ie[0]);
			wpa = (params->wpa_ie[0] == WLAN_EID_RSN )? 2 : 1;
		}
	}

	if (__madwifi_set80211param(drv, IEEE80211_PARAM_PRIVACY, privacy) < 0)
		ret = -1;

	if (__madwifi_set80211param(drv, IEEE80211_PARAM_WPA, wpa) < 0)
		ret = -1;

	if (params->bssid == NULL) {
		/* ap_scan=2 mode - driver takes care of AP selection and
		 * roaming */
		/* FIX: this does not seem to work; would probably need to
		 * change something in the driver */
		if (__madwifi_set80211param(drv, IEEE80211_PARAM_ROAMING,
				IEEE80211_ROAMING_DEVICE) < 0)
			ret = -1;

		if (wpa_driver_wext_set_ssid(drv->wext, params->ssid,
					     params->ssid_len) < 0)
			ret = -1;
	} else {
		if (__madwifi_set80211param(drv, IEEE80211_PARAM_ROAMING,
				IEEE80211_ROAMING_MANUAL) < 0)
			ret = -1;
		if (wpa_driver_wext_set_ssid(drv->wext, params->ssid,
					     params->ssid_len) < 0)
			ret = -1;
		os_memset(&mlme, 0, sizeof(mlme));
		mlme.im_op = IEEE80211_MLME_ASSOC;
		os_memcpy(mlme.im_macaddr, params->bssid, IEEE80211_ADDR_LEN);
		if (__madwifi_set80211priv(drv, IEEE80211_IOCTL_SETMLME, &mlme,
				 sizeof(mlme)) < 0) {
			wpa_printf(MSG_ERROR, "%s: SETMLME[ASSOC] failed",
				   __func__);
			ret = -1;
		}
	}

	__madwifi_supplicant_set_mgmt_recv_filter(drv, params);

	return ret;
}


static int
madwifi_supplicant_authenticate(void *priv,
				       struct wpa_driver_auth_params *params)
{
	struct madwifi_driver_data *drv = priv;
	struct ieee80211req_mlme mlme;
	struct hostapd_freq_params freq;
	u8 channel;
	int ret;

	wpa_printf(MSG_DEBUG, "%s: freq=%d bssid=%s auth_alg=0x%x, auth_data_len=%d",
				__func__, params->freq, __madwfi_ether_sprintf(params->bssid),
				params->auth_alg, (int)params->auth_data_len);

	if (params->auth_data && (params->auth_data_len >= IEEE80211_MAX_OPT_IE)) {
		wpa_printf(MSG_ERROR, "%s: auth_data error", __func__);
		return -1;
	}

	/* Set the channel */
	os_memset(&freq, 0, sizeof(freq));
	ieee80211_freq_to_chan(params->freq, &channel);
	freq.channel = channel;

	wpa_printf(MSG_DEBUG, "%s: set channel %d", __func__, freq.channel);
	ret = madwifi_set_freq(priv, &freq);
	if (ret) {
		wpa_printf(MSG_ERROR, "%s: set channel failed, ret %d", __func__, ret);
		return ret;
	}

	wpa_hexdump(MSG_DEBUG, "__madwifi_supplicant_rx_mgmt Opt IE",
				params->auth_data, params->auth_data_len);

	/* Send Auth frame */
	os_memset(&mlme, 0, sizeof(mlme));
	mlme.im_op = IEEE80211_MLME_AUTH;
	mlme.im_param1 = __madwifi_supplicant_authalg_to_authmode(params->auth_alg);
	if ((params->ssid_len > 0) && (params->ssid_len < IEEE80211_NWID_LEN)) {
		os_memcpy(mlme.im_ssid, params->ssid, IEEE80211_NWID_LEN);
		mlme.im_ssid_len = params->ssid_len;
	}
	os_memcpy(mlme.im_macaddr, params->bssid, IEEE80211_ADDR_LEN);
	if ((params->auth_data_len > 0) && (params->auth_data_len < IEEE80211_MAX_OPT_IE)) {
		os_memcpy(mlme.im_optie, params->auth_data, params->auth_data_len);
		mlme.im_optie_len = params->auth_data_len;
	}

	ret = __madwifi_set80211priv(drv, IEEE80211_IOCTL_SETMLME, &mlme, sizeof(mlme));
	if (ret < 0)
		wpa_printf(MSG_ERROR, "%s: set mlme failed, ret %d", __func__, ret);

	return ret;
}


static int
__madwifi_supplicant_set_scan_freqs(void *priv, int *freqs)
{
	struct madwifi_driver_data *drv = priv;
	struct ieee80211_scan_freqs *scan_freqs;
	struct iwreq iwr;
	int freq_num = 0;
	int ret = 0;
	int i;

	wpa_printf(MSG_DEBUG, "%s:", __func__);

	if (!freqs) {
		wpa_printf(MSG_DEBUG, "%s: no specific scan freqs", __func__);
		return 0;
	}

	while (freqs[freq_num] != 0)
		freq_num++;

	scan_freqs = os_zalloc(sizeof(*scan_freqs) +
			freq_num * sizeof(scan_freqs->freqs[0]));
	if (!scan_freqs) {
		wpa_printf(MSG_ERROR, "%s: failed to allocate memory", __func__);
		return -1;
	}

	scan_freqs->num = freq_num;
	for (i = 0; i < freq_num; i++)
		scan_freqs->freqs[i] = freqs[i];

	os_memset(&iwr, 0, sizeof(iwr));
	os_strncpy(iwr.ifr_name, drv->ifname, IFNAMSIZ - 1);
	iwr.u.data.flags = SIOCDEV_SUBIO_SET_SCAN_FREQS;
	iwr.u.data.pointer = scan_freqs;
	iwr.u.data.length = sizeof(*scan_freqs) +
			freq_num * sizeof(scan_freqs->freqs[0]);

	if (ioctl(drv->sock_ioctl, IEEE80211_IOCTL_EXT, &iwr) < 0) {
		wpa_printf(MSG_ERROR, "%s: failed to set scan freqs", __func__);
		ret = -1;
	}

	os_free(scan_freqs);

	return ret;
}


static int
madwifi_supplicant_scan2(void *priv, struct wpa_driver_scan_params *params)
{
	struct madwifi_driver_data *drv = priv;
	struct iwreq iwr;
	int ret = 0;
	const u8 *ssid = params->ssids[0].ssid;
	size_t ssid_len = params->ssids[0].ssid_len;

	wpa_printf(MSG_DEBUG, "%s:", __func__);

	__madwifi_supplicant_set_probe_req_ie(drv, params->extra_ies,
					    params->extra_ies_len);

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);

	/* set desired ssid before scan */
	/* FIX: scan should not break the current association, so using
	 * set_ssid may not be the best way of doing this.. */
	if (wpa_driver_wext_set_ssid(drv->wext, ssid, ssid_len) < 0)
		ret = -1;

	/* set specific scan freqs */
	if (__madwifi_supplicant_set_scan_freqs(priv, params->freqs) < 0)
		ret = -1;

	if (ioctl(drv->sock_ioctl, SIOCSIWSCAN, &iwr) < 0) {
		perror("ioctl[SIOCSIWSCAN]");
		ret = -1;
	}

	/*
	 * madwifi delivers a scan complete event so no need to poll, but
	 * register a backup timeout anyway to make sure that we recover even
	 * if the driver does not send this event for any reason. This timeout
	 * will only be used if the event is not delivered (event handler will
	 * cancel the timeout).
	 */
	eloop_cancel_timeout(wpa_driver_wext_scan_timeout, drv->wext,
			     drv->ctx);
	eloop_register_timeout(30, 0, wpa_driver_wext_scan_timeout, drv->wext,
			       drv->ctx);

	return ret;
}


static int madwifi_supplicant_get_bssid(void *priv, u8 *bssid)
{
	struct madwifi_driver_data *drv = priv;
	return wpa_driver_wext_get_bssid(drv->wext, bssid);
}


static int madwifi_supplicant_get_ssid(void *priv, u8 *ssid)
{
	struct madwifi_driver_data *drv = priv;
	return wpa_driver_wext_get_ssid(drv->wext, ssid);
}


static struct wpa_scan_results *
madwifi_supplicant_get_scan_results2(void *priv)
{
	struct madwifi_driver_data *drv = priv;
	return wpa_driver_wext_get_scan_results(drv->wext);
}


static int madwifi_supplicant_get_capa(void *priv, struct wpa_driver_capa *capa)
{
	struct madwifi_driver_data *drv = priv;
	int drv_24g_capab = 0;
	int mfp_options = MGMT_FRAME_PROTECTION_DEFAULT;

	capa->key_mgmt = WPA_DRIVER_CAPA_KEY_MGMT_WPA |
		WPA_DRIVER_CAPA_KEY_MGMT_WPA_PSK |
		WPA_DRIVER_CAPA_KEY_MGMT_WPA2 |
		WPA_DRIVER_CAPA_KEY_MGMT_WPA2_PSK;
	capa->enc = WPA_DRIVER_CAPA_ENC_TKIP |
		WPA_DRIVER_CAPA_ENC_CCMP;
	capa->auth = WPA_DRIVER_AUTH_OPEN |
		WPA_DRIVER_AUTH_SHARED;

	capa->flags = 0;
#ifdef CONFIG_TDLS
	capa->flags |= (WPA_DRIVER_FLAGS_TDLS_SUPPORT | WPA_DRIVER_FLAGS_TDLS_EXTERNAL_SETUP);
#endif /* CONFIG_TDLS */
#ifdef CONFIG_SAE
	capa->flags |= WPA_DRIVER_FLAGS_SAE;
#endif /* CONFIG_SAE */

	__madwifi_get80211param(drv, IEEE80211_PARAM_CONFIG_PMF, &mfp_options);

	if (mfp_options == IEEE80211_MFP_PROTECT_REQUIRE)
	      capa->mfp_options = MGMT_FRAME_PROTECTION_REQUIRED;
	else if (mfp_options == IEEE80211_MFP_PROTECT_CAPABLE)
	      capa->mfp_options = MGMT_FRAME_PROTECTION_OPTIONAL;
	else
	      capa->mfp_options = NO_MGMT_FRAME_PROTECTION;

	if  (__madwifi_get80211param(priv, IEEE80211_PARAM_2_4G_CAPAB, &drv_24g_capab))
		wpa_printf(MSG_WARNING, "%s: failed to get 2.4G capability from driver", __func__);

	capa->hw_capab_24g = drv_24g_capab;

	return 0;
}


static struct hostapd_hw_modes *
madwifi_supplicant_get_hw_feature_data(void *priv, u16 *num_modes, u16 *flags, u8 *dfs)
{
	struct madwifi_driver_data *drv =
		(struct madwifi_driver_data *)priv;
	struct wpa_driver_wext_data *wext =
		(struct wpa_driver_wext_data *)drv->wext;
	struct hostapd_hw_modes *modes = NULL;
	int chan_2g4[QTN_FREQ_RANGE_MAX_NUM] = {0};
	int chan_5g[QTN_FREQ_RANGE_MAX_NUM] = {0};
	int chan_2g4_num = 0;
	int chan_5g_num = 0;
	int mode = 0;
	size_t i;

	wpa_printf(MSG_DEBUG, "%s:", __func__);

	if (!num_modes || !flags)
		return NULL;

	*flags = HOSTAPD_HW_FLAG_SKIP_RATE_CHECK;
	*num_modes = 0;

	for (i = 0; i < wext->num_frequency; i++) {
		if ((wext->freq[i].i >= WPA_MADWIFI_FIRST_2G4_CHAN) &&
				(wext->freq[i].i <= WPA_MADWIFI_LAST_2G4_CHAN))
			chan_2g4[chan_2g4_num++] = wext->freq[i].i;
		else if ((wext->freq[i].i >= WPA_MADWIFI_FIRST_5G_CHAN) &&
				(wext->freq[i].i <= WPA_MADWIFI_LAST_5G_CHAN))
			chan_5g[chan_5g_num++] = wext->freq[i].i;
	}

	if (chan_2g4_num > 0)
		(*num_modes) += 2;

	if (chan_5g_num > 0)
		(*num_modes)++;

	if (*num_modes == 0)
		return NULL;

	modes = os_zalloc(*num_modes * sizeof(struct hostapd_hw_modes));
	if (modes == NULL)
		return NULL;

	if (chan_2g4_num > 0) {
		modes[mode].mode = HOSTAPD_MODE_IEEE80211G;
		modes[mode].num_channels = chan_2g4_num;
		modes[mode].num_rates = QTN_MADWIFI_11G_RATES_NUM;
		modes[mode].channels =
			os_zalloc(chan_2g4_num * sizeof(struct hostapd_channel_data));
		modes[mode].rates = os_zalloc(modes[mode].num_rates * sizeof(int));
		if (modes[mode].channels == NULL || modes[mode].rates == NULL)
			goto fail;
		for (i = 0; i < chan_2g4_num; i++) {
			modes[mode].channels[i].chan = chan_2g4[i];
			modes[mode].channels[i].freq = 2407 + 5 * chan_2g4[i];
			modes[mode].channels[i].flag = 0;
		}
		modes[mode].rates[0] = 10;
		modes[mode].rates[1] = 20;
		modes[mode].rates[2] = 55;
		modes[mode].rates[3] = 110;
		modes[mode].rates[4] = 60;
		modes[mode].rates[5] = 90;
		modes[mode].rates[6] = 120;
		modes[mode].rates[7] = 180;
		modes[mode].rates[8] = 240;
		modes[mode].rates[9] = 360;
		modes[mode].rates[10] = 480;
		modes[mode].rates[11] = 540;

		mode++;

		modes[mode].mode = HOSTAPD_MODE_IEEE80211B;
		modes[mode].num_channels = chan_2g4_num;
		modes[mode].num_rates = QTN_MADWIFI_11B_RATES_NUM;
		modes[mode].channels =
			os_zalloc(chan_2g4_num * sizeof(struct hostapd_channel_data));
		modes[mode].rates = os_zalloc(modes[mode].num_rates * sizeof(int));
		if (modes[mode].channels == NULL || modes[mode].rates == NULL)
			goto fail;
		for (i = 0; i < chan_2g4_num; i++) {
			modes[mode].channels[i].chan = chan_2g4[i];
			modes[mode].channels[i].freq = 2407 + 5 * chan_2g4[i];
			modes[mode].channels[i].flag = 0;
		}
		modes[mode].rates[0] = 10;
		modes[mode].rates[1] = 20;
		modes[mode].rates[2] = 55;
		modes[mode].rates[3] = 110;

		mode++;
	}

	if (chan_5g_num > 0) {
		modes[mode].mode = HOSTAPD_MODE_IEEE80211A;
		modes[mode].num_channels = chan_5g_num;
		modes[mode].num_rates = QTN_MADWIFI_11A_RATES_NUM;
		modes[mode].channels =
			os_zalloc(chan_5g_num * sizeof(struct hostapd_channel_data));
		modes[mode].rates = os_zalloc(modes[mode].num_rates * sizeof(int));
		if (modes[mode].channels == NULL || modes[mode].rates == NULL)
			goto fail;

		for (i = 0; i < chan_5g_num; i++) {
			modes[mode].channels[i].chan = chan_5g[i];
			modes[mode].channels[i].freq = 5000 + 5 * chan_5g[i];
			modes[mode].channels[i].flag = 0;
		}

		modes[mode].rates[0] = 60;
		modes[mode].rates[1] = 90;
		modes[mode].rates[2] = 120;
		modes[mode].rates[3] = 180;
		modes[mode].rates[4] = 240;
		modes[mode].rates[5] = 360;
		modes[mode].rates[6] = 480;
		modes[mode].rates[7] = 540;

		mode++;
	}

	return modes;

fail:
	if (modes) {
		for (i = 0; i < *num_modes; i++) {
			os_free(modes[i].channels);
			os_free(modes[i].rates);
		}
		os_free(modes);
	}
	return NULL;
}


static int madwifi_supplicant_set_operstate(void *priv, int state)
{
	struct madwifi_driver_data *drv = priv;

	wpa_printf(MSG_DEBUG, "%s: state=%d", __func__, state);
	return wpa_driver_wext_set_operstate(drv->wext, state);
}


static int madwifi_supplicant_get_pairing_hash_ie(void *priv, u8 *pairing_hash,
							size_t ies_len, u8 *addr)
{
	struct ieee80211req_wpaie ie;
	int ret = 0;
	u8 peering_ie_exist;

	wpa_printf(MSG_DEBUG, "%s:", __func__);

	os_memset(&ie, 0, sizeof(ie));
	os_memcpy(ie.wpa_macaddr, addr, IEEE80211_ADDR_LEN);
	if (__madwifi_set80211priv(priv, IEEE80211_IOCTL_GETWPAIE, &ie, sizeof(ie))) {
		wpa_printf(MSG_ERROR, "%s: Failed to get WPA/RSN IE",
			   __func__);
		return -1;
	}

	peering_ie_exist = ie.has_pairing_ie;

	if (peering_ie_exist && pairing_hash) {
		os_memcpy(pairing_hash, ie.qtn_pairing_ie, ies_len);
	}

	ret = peering_ie_exist;

	return ret;
}


static int
__madwifi_supplicant_init_mgmt_recv(struct madwifi_driver_data *drv)
{
	if (!drv->sock_raw)
		drv->sock_raw = l2_packet_init("br0", NULL, ETH_P_80211_RAW,
				       __madwifi_supplicant_mgmt_receive, drv, 1);
	if (drv->sock_raw == NULL) {
		wpa_printf(MSG_ERROR, "%s: failed to initialize raw socket", __func__);
		return -1;
	}

	return 0;
}


static void *madwifi_supplicant_init(void *ctx, const char *ifname)
{
	struct madwifi_driver_data *drv;

	wpa_printf(MSG_DEBUG, "%s:", __func__);

	drv = os_zalloc(sizeof(*drv));
	if (drv == NULL)
		return NULL;
	drv->wext = wpa_driver_wext_init(ctx, ifname);
	if (drv->wext == NULL)
		goto fail;

	drv->ctx = ctx;
	os_strlcpy(drv->ifname, ifname, sizeof(drv->ifname));
	drv->sock_ioctl = socket(PF_INET, SOCK_DGRAM, 0);
	if (drv->sock_ioctl < 0)
		goto fail2;

	if (__madwifi_set80211param(drv, IEEE80211_PARAM_ROAMING,
			IEEE80211_ROAMING_MANUAL) < 0) {
		wpa_printf(MSG_ERROR, "%s: failed to set wpa_supplicant-based roaming", __func__);
		goto fail3;
	}

	if (__madwifi_set80211param(drv, IEEE80211_PARAM_WPA, 3) < 0) {
		wpa_printf(MSG_ERROR, "%s: failed to enable WPA support", __func__);
		goto fail3;
	}

	if (__madwifi_set80211param(drv, IEEE80211_PARAM_WPA_STARTED, 1) < 0) {
		wpa_printf(MSG_ERROR, "%s: failed to set WPA state", __func__);
		goto fail3;
	}

	if (__madwifi_supplicant_init_mgmt_recv(drv) != 0) {
		wpa_printf(MSG_ERROR, "%s: failed to init mgmt recv", __func__);
		goto fail3;
	}

	return drv;

fail3:
	close(drv->sock_ioctl);
fail2:
	wpa_driver_wext_deinit(drv->wext);
fail:
	os_free(drv);
	return NULL;
}


static void madwifi_supplicant_deinit(void *priv)
{
	struct madwifi_driver_data *drv = priv;

	wpa_printf(MSG_DEBUG, "%s:", __func__);

	if (__madwifi_supplicant_set_wpa_ie(drv, NULL, 0) < 0)
		wpa_printf(MSG_ERROR, "%s: failed to clear WPA IE", __func__);

	if (__madwifi_set80211param(drv, IEEE80211_PARAM_ROAMING,
			IEEE80211_ROAMING_DEVICE) < 0)
		wpa_printf(MSG_ERROR, "%s: failed to enable driver-based roaming", __func__);

	if (__madwifi_set80211param(drv, IEEE80211_PARAM_PRIVACY, 0) < 0)
		wpa_printf(MSG_ERROR, "%s: failed to disable forced Privacy flag", __func__);

	if (__madwifi_set80211param(drv, IEEE80211_PARAM_WPA, 0) < 0)
		wpa_printf(MSG_ERROR, "%s: failed to disable WPA", __func__);

	if (__madwifi_set80211param(drv, IEEE80211_PARAM_WPA_STARTED, 0) < 0)
		wpa_printf(MSG_ERROR, "%s: failed to clear WPA state", __func__);

	wpa_driver_wext_deinit(drv->wext);

	if (drv->sock_raw)
		l2_packet_deinit(drv->sock_raw);

	close(drv->sock_ioctl);
	os_free(drv);
}


/*
 * This function does NOT set MLME protection, but is used as a convenient (and unused) function
 * to pass messages from the core WPA state machine to the driver without hacking across the
 * layers.
 */
static int madwifi_supplicant_mlme_setprotection(void *priv, const u8 *addr, int protect_type,
		                                  int key_type, const char *msg)
{
	struct madwifi_driver_data *drv = priv;

	wpa_printf(MSG_DEBUG, "%s: protect_type=%d", __func__, protect_type);

	/* Open the port to traffic - we have both TX and RX keys and have completed negotiation. */
	if (protect_type == MLME_SETPROTECTION_PROTECT_TYPE_RX_TX) {
		const char *open_port_msg = "WPA-PORT-ENABLE";

		__madwifi_set80211priv(drv, IEEE80211_IOCTL_POSTEVENT, (void *)open_port_msg,
				os_strnlen(open_port_msg, MAX_WLAN_MSG_LEN));
	}

	/* Messages for sending via iwevent */
	if (msg) {
		return __madwifi_set80211priv(drv, IEEE80211_IOCTL_POSTEVENT,
					(void *)msg, os_strnlen(msg, MAX_WLAN_MSG_LEN));
	}

	return 0;
}


static int
madwifi_supplicant_set_fast_reassoc(void *priv, const int value, int *cur_value)
{
	struct madwifi_driver_data *drv = priv;
	int fast_reassoc = 0;

	wpa_printf(MSG_DEBUG, "%s: value=%d", __func__, value);

	__madwifi_get80211param(drv, IEEE80211_PARAM_FAST_REASSOC, &fast_reassoc);
	if (cur_value)
		*cur_value = fast_reassoc;

	if (fast_reassoc != value)
		return __madwifi_set80211param(drv, IEEE80211_PARAM_FAST_REASSOC, value);

	return 0;
}


static int
madwifi_supplicant_set_pmf(void *priv, const int value)
{
	struct madwifi_driver_data *drv = priv;
	int curr_pmf = 0;
	int new_pmf;

	/* Convert pmf state to corresponding driver state */
	new_pmf = value ? (value + 1) : 0;

	__madwifi_get80211param(drv, IEEE80211_PARAM_CONFIG_PMF, &curr_pmf);

	wpa_printf(MSG_DEBUG, "%s: curr_pmf=%d new_pmf=%d", __func__, curr_pmf, new_pmf);

	if (curr_pmf != new_pmf)
		return __madwifi_set80211param(drv, IEEE80211_PARAM_CONFIG_PMF, new_pmf);

	return 0;
}

static int
madwifi_supplicant_get_pmf(void *priv)
{
	struct madwifi_driver_data *drv = priv;
	int curr_pmf = 0;

	__madwifi_get80211param(drv, IEEE80211_PARAM_CONFIG_PMF, &curr_pmf);

	/* Convert driver state to pmf */
	curr_pmf = curr_pmf ? (curr_pmf - 1) : 0;

	return curr_pmf;
}

/**
* app_buf = [struct app_action_frm_buf] + [Action Frame Payload]
* Action Frame Payload = category (u8) + action (u8) + dialog token (u8) +
* status code (u8) + Info
*/
static int
madwifi_supplicant_send_action(void *priv, unsigned int freq, unsigned int wait_time,
	const u8 *dst_mac, const u8 *src_mac, const u8 *bssid,
	const u8 *data, size_t data_len, int no_cck)
{
	struct madwifi_driver_data *drv = priv;
	struct iwreq iwr;
	struct app_action_frame_buf *app_action_frm_buf;
	int ret = 0;

	app_action_frm_buf = os_malloc(data_len + sizeof(struct app_action_frame_buf));
	if (!app_action_frm_buf) {
		wpa_printf(MSG_ERROR, "%s: failed to allocate memory", __func__);
		return -1;
	}

	/* data is Action frame payload. First byte of the data is action frame category
	 * and the second byte is action */
	app_action_frm_buf->cat = *data;
	app_action_frm_buf->action = *(data + 1);
	os_memcpy(app_action_frm_buf->dst_mac_addr, dst_mac, ETH_ALEN);

	app_action_frm_buf->frm_payload.length = (u16)data_len;
	os_memcpy(app_action_frm_buf->frm_payload.data, data, data_len);

	os_memset(&iwr, 0, sizeof(iwr));
	os_strncpy(iwr.ifr_name, drv->ifname, IFNAMSIZ - 1);
	iwr.u.data.flags = SIOCDEV_SUBIO_SEND_ACTION_FRAME;
	iwr.u.data.pointer = app_action_frm_buf;
	iwr.u.data.length = data_len + sizeof(struct app_action_frame_buf);

	if (ioctl(drv->sock_ioctl, IEEE80211_IOCTL_EXT, &iwr) < 0) {
		wpa_printf(MSG_ERROR, "%s: failed to send action frame", __func__);
		ret = -1;
	}

	os_free(app_action_frm_buf);

	return ret;
}


#ifdef CONFIG_TDLS
static int madwifi_supplicant_send_tdls_mgmt(void *priv,
					const u8 *dst, u8 action_code,
					u8 dialog_token, u16 status_code,
					u32 peer_capab, int initiator,
					const u8 *buf, size_t len)
{
	struct ieee80211req_getset_appiebuf *tdls_act;
	struct ieee80211_tdls_action_data *action_data;
	int ret = 0;

	if (!dst)
		return -EINVAL;

	wpa_printf(MSG_DEBUG, "TDLS: %s Send TDLS action frame %s to peer "
			MACSTR "\n", __func__, tdls_action_string[action_code], MAC2STR(dst));

	tdls_act = os_zalloc(sizeof(*tdls_act) + sizeof(*action_data) + len);
	if (tdls_act == NULL)
		return -ENOBUFS;

	tdls_act->app_frmtype = IEEE80211_APPIE_FRAME_TDLS_ACT;
	tdls_act->app_buflen = sizeof(*action_data) + len;

	action_data = (struct ieee80211_tdls_action_data *)tdls_act->app_buf;
	os_memcpy(action_data->dest_mac, dst, sizeof(action_data->dest_mac));
	action_data->action = action_code;
	action_data->status = host_to_le16(status_code);
	action_data->dtoken = dialog_token;
	action_data->ie_buflen = len;
	os_memcpy(action_data->ie_buf, buf, len);

	ret = __madwifi_set80211priv(priv, IEEE80211_IOCTL_SET_APPIEBUF, tdls_act,
			   sizeof(*tdls_act) + sizeof(*action_data) + len);

	os_free(tdls_act);

	return ret;
}


static int madwifi_supplicant_tdls_oper(void *priv,
			enum tdls_oper oper, const u8 *peer)
{
	struct madwifi_driver_data *drv = priv;
	struct ieee80211_tdls_oper_data ieee80211_oper;
	struct iwreq iwr;

	if ((NULL == peer)) {
		if ((oper != TDLS_ENABLE) && (oper != TDLS_DISABLE))
			return -EINVAL;
	} else {
		wpa_printf(MSG_DEBUG, "TDLS: %s run tdls operation %s for peer "
			MACSTR "\n", __func__, tlds_operation_string[oper], MAC2STR(peer));
		os_memcpy(ieee80211_oper.dest_mac, peer, sizeof(ieee80211_oper.dest_mac));
	}

	switch (oper) {
		case TDLS_DISCOVERY_REQ:
			ieee80211_oper.oper = IEEE80211_TDLS_DISCOVERY_REQ;
			break;
		case TDLS_SETUP:
			ieee80211_oper.oper = IEEE80211_TDLS_SETUP;
			break;
		case TDLS_TEARDOWN:
			ieee80211_oper.oper = IEEE80211_TDLS_TEARDOWN;
			break;
		case TDLS_ENABLE_LINK:
			ieee80211_oper.oper = IEEE80211_TDLS_ENABLE_LINK;
			break;
		case TDLS_DISABLE_LINK:
			ieee80211_oper.oper = IEEE80211_TDLS_DISABLE_LINK;
			break;
		case TDLS_ENABLE:
			ieee80211_oper.oper = IEEE80211_TDLS_ENABLE;
			break;
		case TDLS_DISABLE:
			ieee80211_oper.oper = IEEE80211_TDLS_DISABLE;
			break;
		case TDLS_SWITCH_CHAN:
			ieee80211_oper.oper = IEEE80211_TDLS_SWITCH_CHAN;
			break;
		default:
			return -EINVAL;
	}

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
	iwr.u.data.flags = SIOCDEV_SUBIO_SET_TDLS_OPER;
	iwr.u.data.pointer = &ieee80211_oper;
	iwr.u.data.length = sizeof(ieee80211_oper);

	if (ioctl(drv->sock_ioctl, IEEE80211_IOCTL_EXT, &iwr) < 0) {
		wpa_printf(MSG_ERROR, "%s: Failed to set tdls operation", __func__);
		return -1;
	}

	return 0;
}
#endif /* CONFIG TDLS */

static int
wpa_driver_madwifi_set_app_ie(void *priv, u_int8_t subtype, const struct wpabuf *appie)
{
	u8 buf[256];
	struct ieee80211req_getset_appiebuf *cfg_appie;
	int len;
	struct iwreq wrq;

	if (!appie)
		len = 0;
	else
		len = wpabuf_len(appie);

	if ((len + sizeof(*cfg_appie)) > sizeof(buf)) {
		wpa_printf(MSG_ERROR, "%s APP IE length %u exceeds the buffer size %u",
			__func__, len, (unsigned int)sizeof(buf));
		return -1;
	}

	os_memset(buf, 0, sizeof(buf));
	memset(&wrq, 0, sizeof(wrq));

	cfg_appie = (struct ieee80211req_getset_appiebuf *) buf;
	cfg_appie->app_frmtype = subtype;
	cfg_appie->app_buflen = len;
	cfg_appie->flags = F_QTN_IEEE80211_RPE_APPIE;
	if (appie) {
		os_memcpy(cfg_appie->app_buf, wpabuf_head(appie), len);
		wpa_hexdump(MSG_MSGDUMP, "madwifi APP IE",
				wpabuf_head(appie), len);
	}

	return __madwifi_set80211priv(priv, IEEE80211_IOCTL_SET_APPIEBUF, cfg_appie,
			sizeof(struct ieee80211req_getset_appiebuf) + len);
}


int madwifi_supplicant_cancel_remain_on_channel(void *priv)
{
	struct iwreq iwr;
	struct madwifi_driver_data *drv = priv;

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
	iwr.u.data.flags = SIOCDEV_SUBIO_SET_CANCEL_REMAIN_ON_CHAN;
	iwr.u.data.pointer = NULL;
	iwr.u.data.length = 0;

	if (ioctl(drv->sock_ioctl, IEEE80211_IOCTL_EXT, &iwr) < 0) {
		wpa_printf(MSG_ERROR, "%s: failed to cancel remain on channel", __func__);
		return -1;
	}

	return 0;
}

int madwifi_supplicant_remain_on_channel(void *priv, unsigned int freq,
						unsigned int duration)
{
	struct iwreq iwr;
	struct ieee80211_remain_chan_info *chan_info;
	struct madwifi_driver_data *drv = priv;
	int ret = 0;

	chan_info = calloc(1, sizeof(struct ieee80211_remain_chan_info));
	if (!chan_info)
		return -1;

	chan_info->frequency = freq;
	chan_info->duration = duration;

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
	iwr.u.data.flags = SIOCDEV_SUBIO_SET_REMAIN_ON_CHAN;
	iwr.u.data.pointer = chan_info;
	iwr.u.data.length = sizeof(struct ieee80211_remain_chan_info);

	if (ioctl(drv->sock_ioctl, IEEE80211_IOCTL_EXT, &iwr) < 0) {
		wpa_printf(MSG_ERROR, "%s: failed to set remain on channel", __func__);
		ret = -1;
	}

	free(chan_info);
	return ret;
}
#endif /* HOSTAPD */


const struct wpa_driver_ops wpa_driver_madwifi_ops = {
	.name			= "madwifi",
	.desc			= "MADWIFI 802.11 support (Atheros, etc.)",
	.set_key		= madwifi_set_key,
	.set_pairing_hash_ie	= madwifi_set_pairing_hash_ie,
	.send_mlme		= madwifi_send_mlme,
	.sta_deauth		= madwifi_sta_deauth,
	.set_freq		= madwifi_set_freq,

#ifdef HOSTAPD
	.hapd_init		= madwifi_hostapd_init,
	.hapd_deinit		= madwifi_hostapd_deinit,
	.set_ieee8021x		= madwifi_hostapd_set_ieee8021x,
	.set_privacy		= madwifi_hostapd_set_privacy,
	.get_seqnum		= madwifi_hostapd_get_seqnum,
	.if_add			= madwifi_hostapd_if_add,
	.if_remove		= madwifi_hostapd_if_remove,
	.flush			= madwifi_hostapd_flush,
	.sta_set_flags		= madwifi_hostapd_sta_set_flags,
	.read_sta_data		= madwifi_hostapd_read_sta_data,
	.hapd_send_eapol	= madwifi_hostapd_send_eapol,
	.sta_disassoc		= madwifi_hostapd_sta_disassoc,
	.hapd_set_ssid		= madwifi_hostapd_set_ssid,
	.hapd_get_ssid		= madwifi_hostapd_get_ssid,
	.hapd_set_countermeasures	= madwifi_hostapd_set_countermeasures,
	.sta_clear_stats        = madwifi_hostapd_sta_clear_stats,
	.commit			= madwifi_hostapd_commit,
#ifdef CONFIG_WPS
	.set_ap_wps_ie		= madwifi_hostapd_set_ap_wps_ie,
#endif /* CONFIG_WPS */
	.set_intra_bss		= madwifi_hostapd_set_intra_bss,
	.set_intra_per_bss	= madwifi_hostapd_set_intra_per_bss,
	.set_bss_isolate	= madwifi_hostapd_set_bss_isolate,
	.set_bss_assoc_limit	= madwifi_hostapd_set_bss_assoc_limit,
	.set_total_assoc_limit	= madwifi_hostapd_set_total_assoc_limit,
	.set_brcm_ioctl		= madwifi_hostapd_set_brcm_ioctl,
#ifndef CONFIG_NO_VLAN
	.set_sta_vlan		= madwifi_hostapd_set_sta_vlan,
	.set_dyn_vlan		= madwifi_hostapd_set_dyn_vlan,
	.vlan_group_add		= madwifi_hostapd_vlan_group_add,
	.vlan_group_remove	= madwifi_hostapd_vlan_group_remove,
#endif /* CONFIG_NO_VLAN */
	.set_broadcast_ssid	= madwifi_hostapd_set_broadcast_ssid,
	.send_log		= madwifi_hostapd_send_log,
	.send_action		= madwifi_hostapd_send_action,
	.get_capa		= madwifi_hostapd_get_capa,
	.set_ap			= madwifi_hostapd_set_ap,
	.set_qos_map		= madwifi_hostapd_set_qos_map,
	.set_acl		= madwifi_hostapd_set_acl,
#ifdef CONFIG_IEEE80211R
	.add_sta_node		= madwifi_hostapd_add_sta_node,
#endif /* CONFIG_IEEE80211R */

#else /* HOSTAPD */
	.get_bssid		= madwifi_supplicant_get_bssid,
	.get_ssid		= madwifi_supplicant_get_ssid,
	.init			= madwifi_supplicant_init,
	.deinit			= madwifi_supplicant_deinit,
	.set_countermeasures	= madwifi_supplicant_set_countermeasures,
	.scan2			= madwifi_supplicant_scan2,
	.get_scan_results2	= madwifi_supplicant_get_scan_results2,
	.authenticate		= madwifi_supplicant_authenticate,
	.deauthenticate		= madwifi_supplicant_deauthenticate,
	.disassociate		= madwifi_supplicant_disassociate,
	.associate		= madwifi_supplicant_associate,
	.get_capa		= madwifi_supplicant_get_capa,
	.get_hw_feature_data	= madwifi_supplicant_get_hw_feature_data,
	.set_operstate		= madwifi_supplicant_set_operstate,
	.mlme_setprotection	= madwifi_supplicant_mlme_setprotection,
	.get_pairing_hash_ie	= madwifi_supplicant_get_pairing_hash_ie,
	.set_fast_reassoc       = madwifi_supplicant_set_fast_reassoc,
	.set_pmf		= madwifi_supplicant_set_pmf,
	.get_pmf		= madwifi_supplicant_get_pmf,
	.send_action		= madwifi_supplicant_send_action,
#ifdef CONFIG_TDLS
	.send_tdls_mgmt		= madwifi_supplicant_send_tdls_mgmt,
	.tdls_oper		= madwifi_supplicant_tdls_oper,
#endif /* CONFIG_TDLS */
	.set_app_ie		= wpa_driver_madwifi_set_app_ie,
	.remain_on_channel	= madwifi_supplicant_remain_on_channel,
	.cancel_remain_on_channel = madwifi_supplicant_cancel_remain_on_channel,
#endif /* HOSTAPD */
};

#endif /* CONFIG_QTNA_WIFI */
