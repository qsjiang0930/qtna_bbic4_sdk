/**
 * Copyright (c) 2015 - 2016 Quantenna Communications, Inc.
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
 **/

#define pr_fmt(fmt)	"%s: " fmt, __func__

#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/etherdevice.h>
#include <net/sock.h>

#include <common/ruby_mem.h>

#include <net80211/ieee80211_var.h>
#include <qtn/topaz_tqe.h>
#include <qtn_logging.h>

#include <qdrv/qdrv_control.h>
#include "qdrv/qdrv_radar.h"

#include "qlink_priv.h"
#include "events.h"
#include "ie.h"
#include "utils.h"
#include "wlan_ops.h"
#include "crypto.h"

#ifndef ETH_P_80211_RAW
#define ETH_P_80211_RAW		0x0019
#endif

static struct qlink_event *qlink_event_prepare(size_t size, gfp_t gfp)
{
	struct qlink_event *event;

	event = kmalloc(size, gfp);
	if (!event) {
		pr_err("cannot allocate xmit buffer\n");
		return NULL;
	}

	memset(event, 0, sizeof(*event));
	event->mhdr.type = cpu_to_le16(QLINK_MSG_TYPE_EVENT);
	return event;
}

/* see:
 *  - qtn_stats_get_calculated_rssi in macfw/qtn/if_qtn_stats.c
 *  - Bug 21893
 *  - Bug 22616
 */

#define QTN_PSEUDO_RSSI_MIN		1
#define QTN_PSEUDO_RSSI_MAX		69
#define QTN_PSEUDO_RSSI_TO_RSSI_DBM(pseudo_rssi)        ((int)(((int)(pseudo_rssi)) - 90))

static int8_t qlink_pseudo_rssi_to_rssi(int pseudo_rssi)
{
	if (pseudo_rssi < QTN_PSEUDO_RSSI_MIN)
		pseudo_rssi = QTN_PSEUDO_RSSI_MIN;

	if (pseudo_rssi > QTN_PSEUDO_RSSI_MAX)
		pseudo_rssi = QTN_PSEUDO_RSSI_MAX;

	return QTN_PSEUDO_RSSI_TO_RSSI_DBM(pseudo_rssi);
}

static void qlink_event_external_auth_send(struct qlink_bss *bss,
					   struct qlink_event *qevent,
					   enum qlink_external_auth_req action)
{
	struct qlink_event_external_auth *payload;

	qevent->event_id = cpu_to_le16(QLINK_EVENT_EXTERNAL_AUTH);
	qevent->mhdr.len = cpu_to_le16(sizeof(*payload));

	payload = (struct qlink_event_external_auth *)qevent;
	if (bss->ssid_len > 0) {
		payload->ssid_len = bss->ssid_len;
		memcpy(payload->ssid, bss->ssid, bss->ssid_len);
	}

	/* host wpa_s expects akm_suite in BE32 */
	payload->akm_suite = cpu_to_le32(cpu_to_be32(WLAN_AKM_SUITE_SAE));
	payload->action = action;
	ether_addr_copy(payload->bssid, bss->bssid);

	qlink_xmit(qevent, le16_to_cpu(qevent->mhdr.len));
}

static void qlink_event_connect_fail_send(struct qlink_bss *bss,
					    struct qlink_event *qevent,
					    u8 *mac, u16 status)
{
	struct qlink_event_bss_join *payload;

	qevent->event_id = cpu_to_le16(QLINK_EVENT_BSS_JOIN);
	qevent->mhdr.len = cpu_to_le16(sizeof(*payload));

	payload = (struct qlink_event_bss_join *)qevent;
	ether_addr_copy(payload->bssid, mac);
	payload->status = cpu_to_le16(status);
	/* channe info is not needed on host in the case of failure */
	memset(&payload->chan, 0x0, sizeof(payload->chan));

	qlink_bss_connection_drop(bss);
	ieee80211_new_state(bss->vap, IEEE80211_S_INIT, -1);

	qlink_xmit(qevent, le16_to_cpu(qevent->mhdr.len));
}

static void qlink_event_handle_sta_assoc(struct iw_event *event, unsigned int macid,
					 unsigned int ifidx)
{
	struct qlink_event *qevent;
	struct qlink_event_sta_assoc *assoc_ev;
	struct ieee80211com *ic;
	struct ieee80211_node *sta_node;
	struct qlink_tlv_ie_set *ies_tlv;
	u8 *ies;

	pr_debug("QEVENT: STA_ASSOCIATED %pM\n", event->u.addr.sa_data);

	ic = qdrv_get_ic(macid);
	if (unlikely(!ic)) {
		pr_err("internal error cannot get ic\n");
		return;
	}

	sta_node = ieee80211_find_node(&ic->ic_sta, (uint8_t *)event->u.addr.sa_data);

	if (unlikely(!sta_node)) {
		pr_err("STA not found: %pM\n", event->u.addr.sa_data);
		return;
	}

	qevent = qlink_event_prepare(QLINK_MAX_PACKET_SIZE, GFP_KERNEL);
	if (!qevent) {
		pr_err("failed to allocate qlink event\n");
		ieee80211_free_node(sta_node);
		return;
	}

	qevent->macid = macid;
	qevent->vifid = ifidx;
	assoc_ev = (struct qlink_event_sta_assoc *)qevent;

	qevent->event_id = cpu_to_le16(QLINK_EVENT_STA_ASSOCIATED);
	qevent->mhdr.len = cpu_to_le16(sizeof(*assoc_ev));
	ether_addr_copy(assoc_ev->sta_addr, (u8 *)event->u.addr.sa_data);
	assoc_ev->frame_control = 0; /* TODO remove */

	/* Include ASSOC IEs */
	ies_tlv = (struct qlink_tlv_ie_set *)assoc_ev->ies;
	ies_tlv->hdr.type = cpu_to_le16(QTN_TLV_ID_IE_SET);
	ies_tlv->hdr.len = cpu_to_le16(sizeof(*ies_tlv) - sizeof(ies_tlv->hdr));
	ies_tlv->type = QLINK_IE_SET_ASSOC_REQ;
	ies = ies_tlv->ie_data;
	ies += qlink_add_tlv_ie(ies, sta_node->ni_wpa_ie, &ies_tlv->hdr.len);
	ies += qlink_add_tlv_ie(ies, sta_node->ni_rsn_ie, &ies_tlv->hdr.len);
	ies += qlink_add_tlv_ie(ies, sta_node->ni_osen_ie, &ies_tlv->hdr.len);
	ies += qlink_add_tlv_ie(ies, sta_node->ni_wsc_ie, &ies_tlv->hdr.len);
	ies += qlink_add_tlv_ie(ies, sta_node->ni_qtn_pairing_ie, &ies_tlv->hdr.len);

	if (ies != ies_tlv->ie_data)
		le16_add_cpu(&qevent->mhdr.len, ies - assoc_ev->ies);
	ieee80211_free_node(sta_node);
	qlink_xmit(qevent, le16_to_cpu(qevent->mhdr.len));
}

static void qlink_event_handle_sta_deauth(struct iw_event *event,
					  unsigned int macid, unsigned int ifidx)
{
	struct qlink_event *qevent;
	struct qlink_event_sta_deauth *deauth_e;

	pr_debug("QEVENT: STA_DEAUTH %pM\n", event->u.addr.sa_data);

	qevent = qlink_event_prepare(QLINK_MAX_PACKET_SIZE, GFP_KERNEL);
	if (!qevent) {
		pr_err("failed to allocate qlink event\n");
		return;
	}

	qevent->macid = macid;
	qevent->vifid = ifidx;
	deauth_e = (struct qlink_event_sta_deauth *)qevent;

	qevent->event_id = cpu_to_le16(QLINK_EVENT_STA_DEAUTH);
	qevent->mhdr.len = cpu_to_le16(sizeof(*deauth_e));
	ether_addr_copy(deauth_e->sta_addr, (u8 *)event->u.addr.sa_data);
	/* TODO figure out real reason code */
	deauth_e->reason = cpu_to_le16(IEEE80211_REASON_UNSPECIFIED);

	qlink_xmit(qevent, le16_to_cpu(qevent->mhdr.len));
}

static void qlink_event_handle_assoc_resp(struct qlink_server *qs,
					  struct iw_event *event,
					  unsigned int macid, unsigned int ifidx)
{
	struct qlink_bss *bss = &qs->maclist[macid].bss[ifidx];
	struct qlink_event_bss_join *join_ev;
	struct qlink_tlv_ie_set *ies_tlv;
	struct qlink_event *qevent;

	pr_debug("QEVENT: IWEVASSOCRESPIE\n");

	if (!bss_has_status(bss, QLINK_BSS_CONNECTING)) {
		pr_warn("[VIF%u.%u] unexpected event: no connect in progress\n",
			macid, ifidx);
		return;
	}

	qevent = qlink_event_prepare(QLINK_MAX_PACKET_SIZE, GFP_KERNEL);
	if (!qevent) {
		pr_err("failed to allocate qlink event\n");
		return;
	}

	qevent->macid = macid;
	qevent->vifid = ifidx;
	qevent->event_id = cpu_to_le16(QLINK_EVENT_BSS_JOIN);
	qevent->mhdr.len = cpu_to_le16(sizeof(*join_ev));

	join_ev = (struct qlink_event_bss_join *)qevent;
	ether_addr_copy(join_ev->bssid, (u8 *)bss->bssid);
	join_ev->status = cpu_to_le16(IEEE80211_STATUS_SUCCESS);

	if (qlink_vap_chandef_fill(bss->vap, &join_ev->chan)) {
		pr_warn("connect failure: invalid BSS channel\n");
		qlink_event_connect_fail_send(bss, qevent, (u8 *)bss->bssid,
					      IEEE80211_STATUS_UNSPECIFIED);
		return;
	}

	/* append ASSOC RESP IEs */
	ies_tlv = (struct qlink_tlv_ie_set *)join_ev->ies;
	ies_tlv->hdr.type = cpu_to_le16(QTN_TLV_ID_IE_SET);
	ies_tlv->hdr.len = cpu_to_le16(sizeof(*ies_tlv) - sizeof(ies_tlv->hdr));

	ies_tlv->type = QLINK_IE_SET_ASSOC_RESP;
	memcpy(ies_tlv->ie_data, (char *)event + IW_EV_POINT_LEN,
	       event->len - IW_EV_POINT_LEN);
	le16_add_cpu(&ies_tlv->hdr.len, event->len - IW_EV_POINT_LEN);

	pr_info("connection completed: chan:%u\n", join_ev->chan.chan.hw_value);
	bss_set_status(bss, QLINK_BSS_OWE_PROCESSING);

	le16_add_cpu(&qevent->mhdr.len,
		     le16_to_cpu(ies_tlv->hdr.len) + sizeof(ies_tlv->hdr));
	qlink_xmit(qevent, le16_to_cpu(qevent->mhdr.len));
}

static void qlink_event_handle_join_leave(struct qlink_server *qs,
					  struct iw_event *event,
					  unsigned int macid, unsigned int ifidx)
{
	struct qlink_bss *bss = &qs->maclist[macid].bss[ifidx];
	struct qlink_event *qevent;
	struct qlink_event_bss_join *join_ev;

	pr_debug("QEVENT: BSS_JOIN_LEAVE %pM\n", event->u.addr.sa_data);

	if (bss_has_status(bss, QLINK_BSS_OWE_PROCESSING)) {
		pr_debug("skip: WPA3/OWE processing is already in progress\n");
		return;
	}

	/* Only "join" events are handled this way. "Leave" events (when the address is zero)
	 * are handled with IWEVCUSTOM
	 */
	if (!is_zero_ether_addr((u8 *)event->u.addr.sa_data)) {
		qevent = qlink_event_prepare(QLINK_MAX_PACKET_SIZE, GFP_KERNEL);
		if (!qevent) {
			pr_err("failed to allocate qlink event\n");
			return;
		}

		qevent->macid = macid;
		qevent->vifid = ifidx;
		qevent->event_id = cpu_to_le16(QLINK_EVENT_BSS_JOIN);
		qevent->mhdr.len = cpu_to_le16(sizeof(*join_ev));

		join_ev = (struct qlink_event_bss_join *)qevent;
		ether_addr_copy(join_ev->bssid, (u8 *)event->u.addr.sa_data);
		join_ev->status = cpu_to_le16(IEEE80211_STATUS_SUCCESS);

		if (qlink_vap_chandef_fill(bss->vap, &join_ev->chan)) {
			pr_warn("connect failure: invalid BSS channel\n");
			qlink_event_connect_fail_send(bss, qevent, (u8 *)event->u.addr.sa_data,
						      IEEE80211_STATUS_UNSPECIFIED);
			return;
		}

		pr_info("connection completed: BSS:%pM chan:%u\n",
			event->u.addr.sa_data, join_ev->chan.chan.hw_value);

		qlink_xmit(qevent, le16_to_cpu(qevent->mhdr.len));
	}
}

static void qlink_scan_process_ctx_packets(struct scan_complete_ctx *ctx, bool send)
{
	struct list_head *p, *n;
	struct scan_event_item *item;

	list_for_each_safe(p, n, &ctx->packet_list) {
		item = list_entry(p, struct scan_event_item, list);

		if (send)
			qlink_xmit(item->qevent, le16_to_cpu(item->qevent->mhdr.len));
		else
			kfree(item->qevent);

		list_del(p);
		kfree(item);
	}
}

static size_t qlink_scan_result_tlv_size(const struct ieee80211_scan_entry *se)
{
	size_t len = 0;

	len += qlink_ieee_tlv_len(se->se_ssid);
	len += qlink_ieee_tlv_len(se->se_rates);

	/* Non-zero extended rates. Add EXT rates IE */
	if (se->se_xrates[1] != 0)
		len += qlink_ieee_tlv_len(se->se_xrates);

	len += qlink_ieee_tlv_len(se->se_wme_ie);
	len += qlink_ieee_tlv_len(se->se_wpa_ie);
	len += qlink_ieee_tlv_len(se->se_rsn_ie);
	len += qlink_ieee_tlv_len(se->se_wsc_ie);
	len += qlink_ieee_tlv_len(se->se_ath_ie);
	len += qlink_ieee_tlv_len(se->se_htcap_ie);
	len += qlink_ieee_tlv_len(se->se_htinfo_ie);
	len += qlink_ieee_tlv_len(se->se_vhtcap_ie);
	len += qlink_ieee_tlv_len(se->se_vhtop_ie);
	len += qlink_ieee_tlv_len(se->se_ext_bssid_ie);
	len += qlink_ieee_tlv_len(se->se_owe_trans_ie);
	len += qlink_ieee_tlv_len(se->se_obss_scan);

	return len;
}

/* This function need to be atomic since it's called as a callback inside scan_iterate()
 * which is holding a spinlock while calling callback.
 */
static int qlink_send_scan_result(void *arg, const struct ieee80211_scan_entry *se)
{
	size_t packet_size;
	struct scan_complete_ctx *ctx = arg;
	struct qlink_event *qevent;
	struct scan_event_item *packet_item;
	struct qlink_event_scan_result *qse;
	struct qlink_tlv_ie_set *ies_tlv;
	u8 *ies;

	packet_size = sizeof(*qse);
	packet_size += sizeof(*ies_tlv);
	packet_size += qlink_scan_result_tlv_size(se);

	if (packet_size > QLINK_MAX_PACKET_SIZE) {
		pr_err("too big scan result event packet: %u\n", packet_size);
		return -E2BIG;
	}

	packet_item = kmalloc(sizeof(*packet_item), GFP_ATOMIC);
	if (!packet_item) {
		pr_err("failed to allocate packet item\n");
		return -ENOMEM;
	}

	qevent = qlink_event_prepare(packet_size, GFP_ATOMIC);
	if (!qevent) {
		kfree(packet_item);
		pr_err("failed to allocate qlink event\n");
		return -ENOMEM;
	}

	packet_item->qevent = qevent;

	qevent->macid = ctx->macid;
	qevent->vifid = ctx->ifidx;
	qevent->event_id = cpu_to_le16(QLINK_EVENT_SCAN_RESULTS);
	qevent->mhdr.len = cpu_to_le16(sizeof(*qse));

	qse = (struct qlink_event_scan_result *)qevent;
	IEEE80211_ADDR_COPY(qse->bssid, se->se_macaddr);
	qse->ssid_len = se->se_ssid[1];

	if (qse->ssid_len > IEEE80211_NWID_LEN)
		qse->ssid_len = IEEE80211_NWID_LEN;

	memcpy(qse->ssid, (char *)se->se_ssid + 2, qse->ssid_len);
	qse->capab = cpu_to_le16(se->se_capinfo);
	qse->bintval = cpu_to_le16(se->se_intval);
	qse->sig_dbm = qlink_pseudo_rssi_to_rssi(se->se_rssi);
	qse->freq = cpu_to_le16(se->se_chan->ic_freq);
	memcpy(&qse->tsf, se->se_tstamp.data, sizeof(qse->tsf));

	ies_tlv = (struct qlink_tlv_ie_set *)qse->payload;
	ies_tlv->hdr.type = cpu_to_le16(QTN_TLV_ID_IE_SET);
	ies_tlv->hdr.len = cpu_to_le16(sizeof(*ies_tlv) - sizeof(ies_tlv->hdr));
	 /* FIXME: wlan driver does not save this value */
	ies_tlv->type = QLINK_IE_SET_UNKNOWN;
	ies = ies_tlv->ie_data;

	/* we need to keep in sync list of IEs with qlink_scan_result_tlv_size() */
	ies += qlink_add_tlv_ie(ies, se->se_ssid, &ies_tlv->hdr.len);
	ies += qlink_add_tlv_ie(ies, se->se_rates, &ies_tlv->hdr.len);

	/* Non-zero extended rates. Add EXT rates IE */
	if (se->se_xrates[1] != 0)
		ies += qlink_add_tlv_ie(ies, se->se_xrates, &ies_tlv->hdr.len);

	ies += qlink_add_tlv_ie(ies, se->se_wme_ie, &ies_tlv->hdr.len);
	ies += qlink_add_tlv_ie(ies, se->se_wpa_ie, &ies_tlv->hdr.len);
	ies += qlink_add_tlv_ie(ies, se->se_rsn_ie, &ies_tlv->hdr.len);
	ies += qlink_add_tlv_ie(ies, se->se_wsc_ie, &ies_tlv->hdr.len);
	ies += qlink_add_tlv_ie(ies, se->se_ath_ie, &ies_tlv->hdr.len);
	ies += qlink_add_tlv_ie(ies, se->se_htcap_ie, &ies_tlv->hdr.len);
	ies += qlink_add_tlv_ie(ies, se->se_htinfo_ie, &ies_tlv->hdr.len);
	ies += qlink_add_tlv_ie(ies, se->se_vhtcap_ie, &ies_tlv->hdr.len);
	ies += qlink_add_tlv_ie(ies, se->se_vhtop_ie, &ies_tlv->hdr.len);
	ies += qlink_add_tlv_ie(ies, se->se_ext_bssid_ie, &ies_tlv->hdr.len);
	ies += qlink_add_tlv_ie(ies, se->se_owe_trans_ie, &ies_tlv->hdr.len);
	ies += qlink_add_tlv_ie(ies, se->se_obss_scan, &ies_tlv->hdr.len);

	if (ies != ies_tlv->ie_data)
		le16_add_cpu(&qevent->mhdr.len, ies - qse->payload);

	/* initial estimation of packet size should match final packet size */
	WARN_ON(le16_to_cpu(qevent->mhdr.len) != packet_size);

	ctx->se_cnt++;
	list_add_tail(&packet_item->list, &ctx->packet_list);
	qtn_pipeline_drain();

	return 0;
}

static void qlink_event_handle_scan_complete(struct qlink_server *qs, struct ieee80211vap *vap,
					     unsigned int macid, unsigned int ifidx)
{
	struct qlink_bss *bss = &qs->maclist[macid].bss[ifidx];
	struct qlink_event_scan_complete *scan_ev;
	struct qlink_event *qevent;
	struct scan_complete_ctx ctx;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_scan_state *ss = ic->ic_scan;
	int ret = 0;

	if (!bss->dev) {
		pr_err("no device assigned to wmac %u\n", macid);
		return;
	}

	if (bss_has_status(bss, QLINK_BSS_CONNECTING)) {
		if (bss_has_status(bss, QLINK_BSS_SAE_PROCESSING)) {
			qevent = qlink_event_prepare(QLINK_MAX_PACKET_SIZE, GFP_KERNEL);
			if (!qevent)
				return;

			qlink_event_external_auth_send(bss, qevent, QLINK_EXTERNAL_AUTH_START);
		} else {
			ret = qlink_wifi_associate(bss->dev, bss->bssid);
			pr_info("[VIF%u.%u] CONNECT %s BSSID=%pM (%d)\n",
				macid, ifidx, ret ? "fail" : "OK", bss->bssid, ret);
			if (ret) {
				qevent = qlink_event_prepare(QLINK_MAX_PACKET_SIZE, GFP_KERNEL);
				if (!qevent)
					return;

				qlink_event_connect_fail_send(bss, qevent, bss->bssid,
							      IEEE80211_STATUS_TIMEOUT);
				return;
			}
		}
	}

	if (!bss_has_status(bss, QLINK_BSS_SCANNING | QLINK_BSS_CONNECTING)) {
		pr_warn("[VIF%u.%u] unexpected SCAN done\n", macid, ifidx);
		return;
	}

	ctx.se_cnt = 0;
	ctx.macid = macid;
	ctx.ifidx = ifidx;
	INIT_LIST_HEAD(&ctx.packet_list);

	bss_clr_status(bss, QLINK_BSS_SCANNING);

	if (ss->ss_ops != NULL) {
		/* prepare packet list to be sended */
		ret = ss->ss_ops->scan_iterate(ss, qlink_send_scan_result, &ctx);
	}

	if (ret) {
		pr_err("error %d retrieving scan results\n", ret);
		 /* free packet list without sending */
		qlink_scan_process_ctx_packets(&ctx, false);
		goto out;
	}

	pr_info("[VIF%u.%u] SCAN done: results num %d\n",
		macid, ifidx, ctx.se_cnt);

	/* send and free prepared packet list */
	qlink_scan_process_ctx_packets(&ctx, true);

	/* no pending scans on host when connection is in progress */
	if (bss_has_status(bss, QLINK_BSS_CONNECTING))
		return;

	qevent = qlink_event_prepare(QLINK_MAX_PACKET_SIZE, GFP_KERNEL);
	if (!qevent) {
		pr_err("failed to allocate qlink event\n");
		goto out;
	}

	qevent->macid = macid;
	qevent->vifid = ifidx;
	qevent->event_id = cpu_to_le16(QLINK_EVENT_SCAN_COMPLETE);
	qevent->mhdr.len = cpu_to_le16(sizeof(*scan_ev));

	scan_ev = (struct qlink_event_scan_complete *)qevent;
	scan_ev->flags = 0;

	qlink_xmit(qevent, le16_to_cpu(qevent->mhdr.len));
out:
	if (!bss_has_status(bss, QLINK_BSS_STARTED))
		ieee80211_new_state(bss->vap, IEEE80211_S_INIT, -1);
}

static void qlink_event_handle_scan_abort(struct qlink_bss *bss,
					  struct qlink_event *qevent)
{
	struct qlink_event_scan_complete *scan_ev =
			(struct qlink_event_scan_complete *)qevent;

	if (!bss_has_status(bss, QLINK_BSS_SCANNING)) {
		pr_warn("[VIF%u.%u] unexpected SCAN abort\n",
			qevent->macid, qevent->vifid);
		kfree(qevent);
		return;
	}

	bss_clr_status(bss, QLINK_BSS_SCANNING);
	pr_info("[VIF%u.%u] SCAN aborted\n", qevent->macid, qevent->vifid);

	qevent->event_id = cpu_to_le16(QLINK_EVENT_SCAN_COMPLETE);
	qevent->mhdr.len = cpu_to_le16(sizeof(*scan_ev));
	scan_ev->flags = cpu_to_le32(QLINK_SCAN_ABORTED);

	qlink_xmit(qevent, sizeof(*scan_ev));
}

static int qlink_str2mac(const char *str, u8 *mac)
{
	return (sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3],
		&mac[4], &mac[5]) == 6);
}

static void qlink_event_handle_connect_fail(struct qlink_bss *bss,
					    struct qlink_event *qevent,
					    const char *event_msg)
{
	u8 mac[ETH_ALEN];
	char *pos;
	u16 status;

	pos = strstr(event_msg, "addr=");
	if (pos == NULL)
		goto error;

	pos += 5;
	if (!qlink_str2mac(pos, mac))
		goto error;

	pos = strstr(event_msg, "status=");
	if (pos == NULL)
		goto error;

	pos += 7;
	if (sscanf(pos, "%hd", &status) != 1)
		goto error;

	pr_info("[%s]%s CONNECT failed %pM status=%u\n",
		netdev_name(bss->vap->iv_dev),
		bss_has_status(bss, QLINK_BSS_CONNECTING) ? " Ignore" : "",
		mac,
		status);

	if (!bss_has_status(bss, QLINK_BSS_CONNECTING)) {
		kfree(qevent);
		return;
	}

	qlink_event_connect_fail_send(bss, qevent, mac, status);

	return;

error:
	pr_err("[%s] bad msg:\n%s\n", netdev_name(bss->vap->iv_dev), event_msg);
	kfree(qevent);
}

static void qlink_event_disconnected(struct qlink_bss *bss,
		  struct qlink_event *qevent, const u8 *mac, u16 message_reason)
{
	struct qlink_event_bss_leave *payload =
		(struct qlink_event_bss_leave *)qevent;
	enum ieee80211_state old_state = bss->vap->iv_state;

	ieee80211_new_state(bss->vap, IEEE80211_S_INIT, message_reason);

	if (old_state >= IEEE80211_S_ASSOC) {
		/* Notify host only after disconnected completely */
		kfree(qevent);
		return;
	}

	qevent->event_id = cpu_to_le16(QLINK_EVENT_BSS_LEAVE);
	qevent->mhdr.len = cpu_to_le16(sizeof(*payload));
	payload->reason = cpu_to_le16(message_reason);
	pr_info("[%s] BSS leave %pM reason=%d\n",
		netdev_name(bss->vap->iv_dev),
		mac,
		message_reason);

	qlink_bss_connection_drop(bss);
	qlink_xmit(qevent, le16_to_cpu(qevent->mhdr.len));
}

static void qlink_event_handle_disconnect(struct qlink_bss *bss,
					  struct qlink_event *qevent,
					  const char *event_msg)
{
	u8 mac[ETH_ALEN];
	int message_reason = IEEE80211_REASON_UNSPECIFIED;
	char *pos;

	pos = strstr(event_msg, " [");
	if (pos == NULL)
		goto error;

	pos += 2;
	if (!qlink_str2mac(pos, mac))
		goto error;

	pos = strstr(event_msg, " - ");
	if (pos != NULL) {
		pos += 3;
		sscanf(pos, "%d", &message_reason);
	}

	if (message_reason < 0 || message_reason >= IEEE80211_REASON_CODE_MAX)
		message_reason = IEEE80211_REASON_UNSPECIFIED;

	if (bss_has_status(bss, QLINK_BSS_RUNNING)) {
		qlink_event_disconnected(bss, qevent, mac, message_reason);
	} else if (bss_has_status(bss, QLINK_BSS_CONNECTING)) {
		pr_info("[%s]%s BSS connect failed %pM reason=%d\n",
			netdev_name(bss->vap->iv_dev),
			bss_has_status(bss, QLINK_BSS_IGNORE_NEXTDEAUTH) ? " Ignore" : "",
			mac,
			message_reason);

		if (bss_has_status(bss, QLINK_BSS_IGNORE_NEXTDEAUTH)) {
			bss_clr_status(bss, QLINK_BSS_IGNORE_NEXTDEAUTH);
			kfree(qevent);
			return;
		}

		/* fast rejoin attempt: do not notify host */
		if ((message_reason == IEEE80211_REASON_NOT_AUTHED ||
		    (message_reason == IEEE80211_REASON_NOT_ASSOCED)) &&
		    !is_zero_ether_addr(bss->bssid) &&
		    !memcmp(bss->vap->iv_sta_fast_rejoin_bssid, bss->bssid, sizeof(bss->bssid))) {
			pr_info("skip failure: BSS fast rejoin attempt...\n");
			bss_set_status(bss, QLINK_BSS_IGNORE_NEXTDEAUTH);
			kfree(qevent);
			return;
		}

		qlink_event_connect_fail_send(bss, qevent, mac,
					      IEEE80211_STATUS_UNSPECIFIED);
	} else {
		kfree(qevent);
	}

	return;

error:
	pr_err("[%s] bad msg:\n%s\n", netdev_name(bss->vap->iv_dev), event_msg);
	kfree(qevent);
}

static void qlink_event_handle_change_chan(struct qlink_bss *bss,
					   struct qlink_event *qevent)
{
	struct qlink_event_freq_change *freq_e;

	freq_e = (struct qlink_event_freq_change *)qevent;

	if (qlink_vap_chandef_fill(bss->vap, &freq_e->chan)) {
		kfree(qevent);
		return;
	}

	bss->mac->host_chandef = freq_e->chan;

	qevent->event_id = cpu_to_le16(QLINK_EVENT_FREQ_CHANGE);
	qevent->mhdr.len = cpu_to_le16(sizeof(*freq_e));

	pr_info("[%s] chan change pri=%u cf1=%u cf2=%u bw=%u\n",
		netdev_name(bss->vap->iv_dev),
		le16_to_cpu(freq_e->chan.chan.hw_value),
		le16_to_cpu(freq_e->chan.center_freq1),
		le16_to_cpu(freq_e->chan.center_freq2),
		freq_e->chan.width);

	qlink_xmit(qevent, sizeof(*freq_e));
}

static void qlink_event_handle_mic_failure(struct qlink_bss *bss,
					   struct qlink_event *qevent,
					   const char *event_msg)
{
	struct qlink_event_mic_failure *mic_ev =
		(struct qlink_event_mic_failure *)qevent;
	u8 src[ETH_ALEN];
	u8 pairwise;
	u8 key_idx;
	char *pos;

	pos = strstr(event_msg, "addr=");
	if (pos == NULL)
		goto error;

	pos += 5;
	if (!qlink_str2mac(pos, src))
		goto error;

	pos = strstr(event_msg, "keyid=");
	if (pos == NULL)
		goto error;

	pos += 6;
	if (sscanf(pos, "%hhu", &key_idx) != 1)
		goto error;

	if (strstr(event_msg, "unicast"))
		pairwise = 1;
	else if (strstr(event_msg, "broadcast"))
		pairwise = 0;
	else
		goto error;

	qevent->event_id = cpu_to_le16(QLINK_EVENT_MIC_FAILURE);
	qevent->mhdr.len = cpu_to_le16(sizeof(*mic_ev));

	pr_info("[%s] mic failure: src[%pM] key_idx[%u]\n",
		netdev_name(bss->vap->iv_dev), src, key_idx);

	ether_addr_copy(mic_ev->src, src);
	mic_ev->pairwise = pairwise;
	mic_ev->key_index = key_idx;

	qlink_xmit(qevent, sizeof(*mic_ev));

	return;

error:
	pr_err("[%s] bad msg:\n%s\n", netdev_name(bss->vap->iv_dev), event_msg);
	kfree(qevent);
}

static void qlink_event_handle_custom(struct qlink_server *qs, struct iw_event *event,
				      unsigned int macid, unsigned int ifidx)
{
	struct qlink_mac *mac = &qs->maclist[macid];
	struct qlink_bss *bss = &mac->bss[ifidx];
	struct qlink_event *qevent;
	const char *event_msg = ((char *)event) + IW_EV_POINT_LEN;
	static const char conn_fail_tag[] = "STA-CONNECT-FAIL";
	static const char disconnect_tag[] = QEVT_COMMON_PREFIX"Disconnected from AP";
	static const char change_chan_tag[] = QEVT_TAG_CHAN_CHANGED;
	static const char *mic_failure_tag = "MLME-MICHAELMICFAILURE.indication";

	pr_debug("[%s] received event:\n%s\n",
		 netdev_name(bss->vap->iv_dev), event_msg ? event_msg : "null");

	qevent = qlink_event_prepare(QLINK_MAX_PACKET_SIZE, GFP_KERNEL);
	if (!qevent) {
		pr_err("%s: failed to allocate qlink event\n", bss->dev->name);
		return;
	}

	qevent->macid = macid;
	qevent->vifid = ifidx;

	if (!strncmp(event_msg, conn_fail_tag, sizeof(conn_fail_tag) - 1))
		qlink_event_handle_connect_fail(bss, qevent, event_msg);
	else if (!strncmp(event_msg, disconnect_tag, sizeof(disconnect_tag) - 1))
		qlink_event_handle_disconnect(bss, qevent, event_msg);
	else if (!strncmp(event_msg, change_chan_tag, sizeof(change_chan_tag) - 1))
		qlink_event_handle_change_chan(bss, qevent);
	else if (!strcmp(event_msg, IEEE80211_EVENT_SCAN_ABORT_TAG))
		qlink_event_handle_scan_abort(bss, qevent);
	else if (!strncmp(event_msg, mic_failure_tag, sizeof(mic_failure_tag) - 1))
		qlink_event_handle_mic_failure(bss, qevent, event_msg);
	else
		kfree(qevent);
}

static void
qlink_event_handle_wireless(struct qlink_server *qs, struct ieee80211vap *vap,
			    struct iw_event *iwevent)
{
	unsigned int macid;
	unsigned int ifidx;

	macid = ieee80211_vap_get_macid(vap);
	ifidx = ieee80211_vap_get_vapidx(vap);

	pr_debug("QEVENT: type=0x%x len=%u macid=%u ifidx=%u\n",
		iwevent->cmd, iwevent->len, macid, ifidx);

	switch (iwevent->cmd) {
	case IWEVREGISTERED:
		qlink_event_handle_sta_assoc(iwevent, macid, ifidx);
		break;
	case IWEVEXPIRED:
		qlink_event_handle_sta_deauth(iwevent, macid, ifidx);
		break;
	case IWEVASSOCRESPIE:
		qlink_event_handle_assoc_resp(qs, iwevent, macid, ifidx);
		break;
	case SIOCGIWAP:
		qlink_event_handle_join_leave(qs, iwevent, macid, ifidx);
		break;
	case IWEVCUSTOM:
		qlink_event_handle_custom(qs, iwevent, macid, ifidx);
		break;
	case SIOCGIWSCAN:
		qlink_event_handle_scan_complete(qs, vap, macid, ifidx);
		break;
	default:
		pr_warn("QEVENT: unhandled event type=0x%x len=%u macid=%u ifidx=%u\n",
			iwevent->cmd, iwevent->len, macid, ifidx);
	}
}

static void qlink_event_rtnetlink_receive(struct qlink_server *qs, struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifm;
	char ifname[IFNAMSIZ];
	int ret;
	struct nlattr *tb[IFLA_WIRELESS + 1];
	struct ieee80211vap *vap;
	struct net_device *dev;

	nlh = nlmsg_hdr(skb);

	if (skb->len < nlmsg_total_size(sizeof(*ifm)) ||
			nlh->nlmsg_len < NLMSG_HDRLEN ||
			skb->len < nlh->nlmsg_len)
		return;

	if (nlh->nlmsg_type != RTM_NEWLINK)
		return;

	ret = nlmsg_parse(nlh, sizeof(*ifm), tb, IFLA_WIRELESS, ifla_policy);
	if (ret < 0) {
		pr_warn("QEVENT: failed to parse NLMSG %d\n", ret);
		return;
	}

	if (!tb[IFLA_IFNAME] || !tb[IFLA_WIRELESS])
		return;

	nla_strlcpy(ifname, tb[IFLA_IFNAME], IFNAMSIZ);

	mutex_lock(&qs->mlock);

	dev = __dev_get_by_name(sock_net(skb->sk), ifname);
	if (!dev) {
		pr_warn("QEVENT: failed to get device for %s\n", ifname);
		goto mutex_unlock;
	}

	vap = netdev_priv(dev);
	if (!vap) {
		pr_warn("QEVENT: failed to get VAP for %s\n", ifname);
		goto mutex_unlock;
	}

	qlink_event_handle_wireless(qs, vap, nla_data(tb[IFLA_WIRELESS]));

mutex_unlock:
	mutex_unlock(&qs->mlock);
}

static void qlink_event_dequeue_work(struct work_struct *work)
{
	struct qlink_server *qs =
		container_of(work, struct qlink_server, event_work);
	struct sk_buff_head *queue = &qs->event_sock->sk->sk_receive_queue;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(queue)))  {
		qlink_event_rtnetlink_receive(qs, skb);
		skb_free_datagram(qs->event_sock->sk, skb);
	}
}

static void qlink_event_rtnetlink_data_ready(struct sock *sk, int bytes)
{
	struct qlink_server *qs = sk->sk_user_data;

	queue_work(qs->workqueue, &qs->event_work);
}

int qlink_events_init(struct qlink_server *qs)
{
	int ret;
	struct sockaddr_nl nlsock_addr;
	struct sock *sk;

	ret = sock_create_kern(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE, &qs->event_sock);
	if (ret < 0) {
		pr_err("failed to create event socket: %d\n", ret);
		goto out;
	}

	memset(&nlsock_addr, 0, sizeof(nlsock_addr));
	nlsock_addr.nl_family = AF_NETLINK;
	nlsock_addr.nl_groups = RTNLGRP_LINK;

	/* Note: warning for another kernel code path,
	 * see comment for unix_mkname in linux_2.6.35.12/net/unix/af_unix.c
	 */

	/* coverity[overrun-buffer-arg] */
	ret = kernel_bind(qs->event_sock, (struct sockaddr *)&nlsock_addr, sizeof(nlsock_addr));
	if (ret < 0) {
		pr_err("failed to bind event socket: %d\n", ret);
		sk_release_kernel(qs->event_sock->sk);
		qs->event_sock = NULL;
		goto out;
	}

	sk = qs->event_sock->sk;
	sk->sk_data_ready = qlink_event_rtnetlink_data_ready;
	sk->sk_user_data = qs;

	INIT_WORK(&qs->event_work, qlink_event_dequeue_work);
	ret = 0;

	pr_info("QLINK: start listening for events\n");

out:
	return ret;
}

void qlink_events_deinit(struct qlink_server *qs)
{
	if (!qs->event_sock)
		return;

	rtnl_lock();
	cancel_work_sync(&qs->event_work);
	sk_release_kernel(qs->event_sock->sk);
	qs->event_sock = NULL;
	rtnl_unlock();
}

static void qlink_event_mgmt_send_to_host(struct qlink_server *qs,
					  u8 macid, u8 ifidx, struct sk_buff *skb)
{
	struct qlink_event *qevent;
	struct qlink_event_rxmgmt *mgmt_ev;
	const struct ieee80211_frame *frame = (void *)skb->data;
	size_t packet_len = sizeof(*mgmt_ev);
	u8 subtype = frame->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
	struct qlink_bss *bss;

	pr_debug("MAC %u; IF %u; FRAME LEN %u; FC: %.2X %.2X\n",
		 macid, ifidx, skb->len, frame->i_fc[0], frame->i_fc[1]);

	bss = &qs->maclist[macid].bss[ifidx];

	if (unlikely(!bss_has_status(bss, QLINK_BSS_ADDED))) {
		pr_err("bss (MAC: %u; IF: %u) is not added\n", macid, ifidx);
		return;
	}

	/* Broadcast PMF: check BIP for broadcast DEAUTH/DISASSOC only */
	if (IEEE80211_IS_MULTICAST(frame->i_addr1) &&
	    (subtype == IEEE80211_FC0_SUBTYPE_DEAUTH ||
	     subtype == IEEE80211_FC0_SUBTYPE_DISASSOC)) {
		if (qlink_mgmt_bip_is_valid(bss, skb->data, skb->len))
			qlink_wifi_sta_deauth(bss->dev, (u8 *)frame->i_addr3,
					      IEEE80211_REASON_AUTH_EXPIRE);
		return;
	}

	packet_len += skb->len;
	if (unlikely(packet_len > QLINK_MAX_PACKET_SIZE)) {
		pr_err("too big mgmt frame, unable to send: %u bytes\n", packet_len);
		return;
	}

	qevent = qlink_event_prepare(QLINK_MAX_PACKET_SIZE, GFP_KERNEL);
	if (unlikely(!qevent)) {
		pr_err("failed to allocate qlink event\n");
		return;
	}

	mgmt_ev = (struct qlink_event_rxmgmt *)qevent;

	qevent->mhdr.len = cpu_to_le16(packet_len);
	qevent->event_id = cpu_to_le16(QLINK_EVENT_MGMT_RECEIVED);
	qevent->macid = macid;
	qevent->vifid = ifidx;

	mgmt_ev->freq = cpu_to_le32(skb->qtn_cb.radio_info.freq);
	mgmt_ev->sig_dbm = qlink_pseudo_rssi_to_rssi(skb->qtn_cb.radio_info.rssi);

	switch (subtype) {
	case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
		if (bss->mode == QLINK_IFTYPE_AP)
			mgmt_ev->flags |= QLINK_RXMGMT_FLAG_ANSWERED;
		break;
	default:
		mgmt_ev->flags = 0;
		break;
	}

	memcpy(mgmt_ev->frame_data, skb->data, skb->len);

	qlink_xmit(qevent, packet_len);
}

static void qlink_event_mgmt_frame_receive(struct qlink_server *qs, struct sk_buff *skb)
{
	struct ieee80211vap *vap;
	u8 macid;
	u8 ifidx;

	if (unlikely(!skb->orig_dev)) {
		pr_err("no orig dev\n");
		return;
	}

	vap = netdev_priv(skb->orig_dev);
	if (unlikely(!vap)) {
		pr_err("unable to get vap\n");
		return;
	}

	macid = ieee80211_vap_get_macid(vap);
	ifidx = ieee80211_vap_get_vapidx(vap);

	qlink_event_mgmt_send_to_host(qs, macid, ifidx, skb);
}

static void qlink_event_mgmt_frame_dequeue_work(struct work_struct *work)
{
	struct qlink_server *qs = container_of(work, struct qlink_server, mgmt_frame_work);
	struct socket *sock = qs->mgmt_frame_sock;
	struct sk_buff_head *queue = &sock->sk->sk_receive_queue;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(queue)))  {
		qlink_event_mgmt_frame_receive(qs, skb);
		skb_free_datagram(sock->sk, skb);
	}
}

static void qlink_event_mgmt_frame_data_ready(struct sock *sk, int bytes)
{
	struct qlink_server *qs = sk->sk_user_data;

	queue_work(qs->workqueue, &qs->mgmt_frame_work);
}

int qlink_events_mgmt_init(struct qlink_server *qs)
{
	struct sockaddr_ll ll_addr;
	struct sock *sk;
	int ret;

	ret = sock_create_kern(AF_PACKET, SOCK_RAW, htons(ETH_P_80211_RAW),
			       &qs->mgmt_frame_sock);
	if (ret < 0) {
		pr_err("failed to create mgmt frame socket: %d\n", ret);
		return ret;
	}

	memset(&ll_addr, 0, sizeof(ll_addr));
	ll_addr.sll_family = PF_PACKET;
	ll_addr.sll_ifindex = qs->br_dev->ifindex;
	ll_addr.sll_protocol = htons(ETH_P_80211_RAW);

	/* Note: warning for another kernel code path,
	 * see comment for unix_mkname in linux_2.6.35.12/net/unix/af_unix.c
	 */

	/* coverity[overrun-buffer-arg] */
	ret = kernel_bind(qs->mgmt_frame_sock, (struct sockaddr *)&ll_addr, sizeof(ll_addr));
	if (ret < 0) {
		pr_err("failed to bind mgmt frame socket: %d\n", ret);
		goto error;
	}

	sk = qs->mgmt_frame_sock->sk;
	sk->sk_data_ready = qlink_event_mgmt_frame_data_ready;
	sk->sk_user_data = qs;

	INIT_WORK(&qs->mgmt_frame_work, qlink_event_mgmt_frame_dequeue_work);

	pr_info("QLINK: start listening for mgmt frames on %s\n", qs->br_dev->name);

	return 0;

error:
	sk_release_kernel(qs->mgmt_frame_sock->sk);
	qs->mgmt_frame_sock = NULL;
	return ret;
}

void qlink_events_mgmt_deinit(struct qlink_server *qs)
{
	if (!qs->mgmt_frame_sock)
		return;

	rtnl_lock();

	cancel_work_sync(&qs->mgmt_frame_work);
	sk_release_kernel(qs->mgmt_frame_sock->sk);
	qs->mgmt_frame_sock = NULL;

	rtnl_unlock();
}

void qlink_events_mgmt_bss_deinit(struct qlink_bss *bss)
{
	bss->vap->app_filter &= ~IEEE80211_FILTER_TYPE_ALL;
}

/* sysfs test interface */

static ssize_t qlink_event_sysfs_handle(const char *buf, size_t count)
{
	static char tlv_rates[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	struct qlink_event_sta_assoc *assoc;
	struct qlink_event_sta_deauth *deauth;
	struct qlink_event_mic_failure *mic;
	struct qlink_event *event;
	char cmd_buf[MAX_QDRV_CMD];
	u8 src[ETH_ALEN];
	u8 *ptlv;
	char *p;

	if (count < 1)
		return (ssize_t)count;

	if (count >= MAX_QDRV_CMD) {
		pr_err("command is too long\n");
		return (ssize_t)count;
	}

	/* Copy to a buffer to make a proper C string */
	memcpy(cmd_buf, buf, count);
	cmd_buf[count] = '\0';

	/* Kill '\n' if there is one */
	p = strrchr(cmd_buf, '\n');
	if (p)
		*p = '\0';

	if (!strcmp(cmd_buf, "assoc")) {
		pr_info("ASSOC event injected\n");
		event = qlink_event_prepare(QLINK_MAX_PACKET_SIZE, GFP_KERNEL);
		if (event) {
			event->vifid = 0;
			event->macid = 0;
			event->event_id = QLINK_EVENT_STA_ASSOCIATED;
			assoc = (struct qlink_event_sta_assoc *)event;
			/* MAC = "00:26:86:F0:45:79" */
			assoc->sta_addr[0] = 0x00;
			assoc->sta_addr[1] = 0x26;
			assoc->sta_addr[2] = 0x86;
			assoc->sta_addr[3] = 0xF0;
			assoc->sta_addr[4] = 0x45;
			assoc->sta_addr[5] = 0x79;
			assoc->frame_control = cpu_to_le16(0x0100);
			ptlv = (u8 *)(assoc->ies);
			ptlv = qlink_encode_tlv_str(ptlv, WLAN_EID_SSID, "test_bss", 8);
			ptlv = qlink_encode_tlv_str(ptlv, WLAN_EID_SUPP_RATES, tlv_rates, 8);

			event->mhdr.len = cpu_to_le16(ptlv - (u8 *)event);
			qlink_xmit(event, ptlv - (u8 *)event);

		}
	} else if (!strcmp(cmd_buf, "deauth")) {
		pr_info("DEAUTH event injected\n");
		event = qlink_event_prepare(QLINK_MAX_PACKET_SIZE, GFP_KERNEL);
		if (event) {
			event->vifid = 0;
			event->macid = 0;
			event->event_id = QLINK_EVENT_STA_DEAUTH;
			deauth = (struct qlink_event_sta_deauth *)event;
			deauth->sta_addr[0] = 0x00;
			deauth->sta_addr[1] = 0x26;
			deauth->sta_addr[2] = 0x86;
			deauth->sta_addr[3] = 0xF0;
			deauth->sta_addr[4] = 0x45;
			deauth->sta_addr[5] = 0x79;
			deauth->reason = cpu_to_le16(8); // WLAN_REASON_DISASSOC_STA_HAS_LEFT
			event->mhdr.len = cpu_to_le16(sizeof(*deauth));
			qlink_xmit(event, sizeof(*deauth));
		}
	} else if (!strncmp(cmd_buf, "mic", 3)) {
		pr_info("MIC_FAILURE event injected\n");
		event = qlink_event_prepare(QLINK_MAX_PACKET_SIZE, GFP_KERNEL);
		if (event) {
			event->vifid = 0;
			event->macid = 0;
			event->event_id = QLINK_EVENT_MIC_FAILURE;
			mic = (struct qlink_event_mic_failure *)event;

			p = strstr(cmd_buf, "addr=");
			if (p && qlink_str2mac(p + 5, src)) {
				ether_addr_copy(mic->src, src);
			} else {
				mic->src[0] = 0x00;
				mic->src[1] = 0x26;
				mic->src[2] = 0x86;
				mic->src[3] = 0xF0;
				mic->src[4] = 0x45;
				mic->src[5] = 0x79;
			}

			mic->key_index = 0;
			mic->pairwise = 1;

			event->mhdr.len = cpu_to_le16(sizeof(*mic));
			qlink_xmit(event, sizeof(*mic));
		}

	} else {
		pr_info("unknown event: discarded\n");
	}

	return (ssize_t)count;
}

static ssize_t qlink_sysfs_store_event(struct device *dev, struct device_attribute *attr,
				       const char *buf, size_t count)
{
	return qlink_event_sysfs_handle(buf, count);
}

static ssize_t qlink_sysfs_show_event(struct device *dev, struct device_attribute *attr,
				      char *buf)
{
	return snprintf(buf, PAGE_SIZE, "Available events:\n"
			" assoc\n deauth\n");
}

static DEVICE_ATTR(event, 0644, qlink_sysfs_show_event, qlink_sysfs_store_event);

int qlink_event_sysfs_register(struct device *dev)
{
	return device_create_file(dev, &dev_attr_event);
}

void qlink_event_sysfs_unregister(struct device *dev)
{
	device_remove_file(dev, &dev_attr_event);
}
