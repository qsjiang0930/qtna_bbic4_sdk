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
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ctype.h>
#include <linux/nl80211.h>
#include <linux/crypto.h>
#include <net/regulatory.h>
#include <asm/unaligned.h>

#include <net80211/ieee80211_var.h>
#include <qdrv/qdrv_radar.h>
#include <qdrv/qdrv_soc.h>
#include <qdrv/qdrv_wlan.h>
#include <qdrv/qdrv_control.h>

#include <common/qtn_hw_mod.h>

#include "qlink_priv.h"
#include "command.h"
#include "events.h"
#include "wlan_ops.h"
#include "netdev_ops.h"
#include "vlan_ops.h"
#include "ie.h"
#include "utils.h"
#include "reg_utils.h"
#include "crypto.h"

ssize_t qlink_xmit(void *buf, size_t size);
static void qlink_cmd_fw_init(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_fw_deinit(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_register_mgmt(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_send_frame(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_mgmt_set_appie(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_add_if(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_change_if(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_del_if(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_updown_if(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_start_ap(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_stop_ap(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_get_hw_info(const struct qlink_server *qs,
		const struct qlink_cmd *cmd);
static void qlink_cmd_get_wmac_info(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_get_sta_info(const struct qlink_cmd *cmd);
static void qlink_cmd_phy_params_set(struct qlink_server *qs,
				     const struct qlink_cmd *cmd);
static void qlink_cmd_band_info_get(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_mac_chan_stats(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_scan(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_connect(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_disconnect(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_apply_bss_config(struct qlink_bss *bss, const struct qlink_cmd_start_ap *cmd);
static void qlink_load_default_bss_settings(struct qlink_bss *bss);
static void qlink_cmd_add_key(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_del_key(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_set_def_key(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_set_def_mgmt_key(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_change_station(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_del_station(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_ap_stop(struct qlink_bss *bss);
static void qlink_cmd_regd_change_notify(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_chan_switch(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_chan_get(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_pm_set(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_pta_param_setget(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_wowlan_set(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_tid_config(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_txpwr(struct qlink_server *qs, const struct qlink_cmd *cmd);
static void qlink_cmd_external_auth(struct qlink_server *qs, const struct qlink_cmd *cmd);

static struct qlink_resp *qlink_prepare_reply(const struct qlink_cmd *cmd);

static void qlink_process_invalid_cmd(const struct qlink_cmd *cmd, u16 error_code)
{
	struct qlink_resp *reply;

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	reply->result = cpu_to_le16(error_code);
	qlink_xmit(reply, sizeof(*reply));
}


void qlink_process_command(struct qlink_server *qs, const struct qlink_cmd *cmd)
{
	u16 cmd_id = le16_to_cpu(cmd->cmd_id);

	/* ignore all commands before FW_INIT */
	if (!(qs->qs_status & QLINK_STATUS_FW_INIT_DONE) &&
	    (cmd_id != QLINK_CMD_FW_INIT)) {
		qlink_process_invalid_cmd(cmd, QLINK_CMD_RESULT_INVALID);
		return;
	}

	/* calibration mode: only limited set of commands is supported */
	if (qs->sp->calstate == QTN_CALSTATE_CALIB) {
		switch (cmd_id) {
		case QLINK_CMD_FW_INIT:
		case QLINK_CMD_GET_HW_INFO:
		case QLINK_CMD_FW_DEINIT:
			break;
		default:
			qlink_process_invalid_cmd(cmd, QLINK_CMD_RESULT_ENOTFOUND);
			return;
		}
	}

	switch (cmd_id) {
	case QLINK_CMD_FW_INIT:
		pr_info("FW_INIT command received\n");
		qlink_cmd_fw_init(qs, cmd);
		break;
	case QLINK_CMD_GET_HW_INFO:
		pr_info("HW_INFO command received\n");
		qlink_cmd_get_hw_info(qs, cmd);
		break;
	case QLINK_CMD_MAC_INFO:
		pr_info("MAC_INFO command received\n");
		qlink_cmd_get_wmac_info(qs, cmd);
		break;
	case QLINK_CMD_GET_STA_INFO:
		pr_debug("GET_STA_INFO command received\n");
		qlink_cmd_get_sta_info(cmd);
		break;
	case QLINK_CMD_FW_DEINIT:
		pr_info("FW_DEINIT command received\n");
		qlink_cmd_fw_deinit(qs, cmd);
		break;
	case QLINK_CMD_REGISTER_MGMT:
		pr_info("REGISTER_MGMT command received\n");
		qlink_cmd_register_mgmt(qs, cmd);
		break;
	case QLINK_CMD_SEND_FRAME:
		pr_debug("SEND_FRAME command received\n");
		qlink_cmd_send_frame(qs, cmd);
		break;
	case QLINK_CMD_MGMT_SET_APPIE:
		pr_info("MGMT_SET_APPIE command received\n");
		qlink_cmd_mgmt_set_appie(qs, cmd);
		break;
	case QLINK_CMD_ADD_INTF:
		pr_info("ADD_IF command received\n");
		qlink_cmd_add_if(qs, cmd);
		break;
	case QLINK_CMD_CHANGE_INTF:
		pr_info("CHANGE_IF command received\n");
		qlink_cmd_change_if(qs, cmd);
		break;
	case QLINK_CMD_DEL_INTF:
		pr_info("DEL_IF command received\n");
		qlink_cmd_del_if(qs, cmd);
		break;
	case QLINK_CMD_UPDOWN_INTF:
		pr_info("UPDOWN_IF command received\n");
		qlink_cmd_updown_if(qs, cmd);
		break;
	case QLINK_CMD_START_AP:
		pr_info("START_AP command received\n");
		qlink_cmd_start_ap(qs, cmd);
		break;
	case QLINK_CMD_STOP_AP:
		pr_info("STOP_AP command received\n");
		qlink_cmd_stop_ap(qs, cmd);
		break;
	case QLINK_CMD_PHY_PARAMS_SET:
		pr_info("PHY_PARAMS_SET command received\n");
		qlink_cmd_phy_params_set(qs, cmd);
		break;
	case QLINK_CMD_ADD_KEY:
		pr_info("ADD_KEY command received\n");
		qlink_cmd_add_key(qs, cmd);
		break;
	case QLINK_CMD_DEL_KEY:
		pr_info("DEL_KEY command received\n");
		qlink_cmd_del_key(qs, cmd);
		break;
	case QLINK_CMD_SET_DEFAULT_KEY:
		pr_info("SET_DEFAULT_KEY command received\n");
		qlink_cmd_set_def_key(qs, cmd);
		break;
	case QLINK_CMD_SET_DEFAULT_MGMT_KEY:
		pr_info("SET_DEFAULT_MGMT_KEY command received\n");
		qlink_cmd_set_def_mgmt_key(qs, cmd);
		break;
	case QLINK_CMD_CHANGE_STA:
		pr_info("CHANGE_STA command received\n");
		qlink_cmd_change_station(qs, cmd);
		break;
	case QLINK_CMD_DEL_STA:
		pr_info("DEL_STA command received\n");
		qlink_cmd_del_station(qs, cmd);
		break;
	case QLINK_CMD_SCAN:
		pr_info("SCAN command received\n");
		qlink_cmd_scan(qs, cmd);
		break;
	case QLINK_CMD_CONNECT:
		qlink_cmd_connect(qs, cmd);
		break;
	case QLINK_CMD_EXTERNAL_AUTH:
		qlink_cmd_external_auth(qs, cmd);
		break;
	case QLINK_CMD_DISCONNECT:
		pr_info("DISCONNECT command received\n");
		qlink_cmd_disconnect(qs, cmd);
		break;
	case QLINK_CMD_REG_NOTIFY:
		pr_info("REG_NOTIFY command received\n");
		qlink_cmd_regd_change_notify(qs, cmd);
		break;
	case QLINK_CMD_BAND_INFO_GET:
		pr_info("BAND_INFO_GET command received\n");
		qlink_cmd_band_info_get(qs, cmd);
		break;
	case QLINK_CMD_CHAN_STATS:
		pr_debug("MAC_CHAN_STATS command received\n");
		qlink_cmd_mac_chan_stats(qs, cmd);
		break;
	case QLINK_CMD_CHAN_SWITCH:
		pr_info("MAC_CHAN_SWITCH command received\n");
		qlink_cmd_chan_switch(qs, cmd);
		break;
	case QLINK_CMD_CHAN_GET:
		pr_info("CHAN_GET command received\n");
		qlink_cmd_chan_get(qs, cmd);
		break;
	case QLINK_CMD_PM_SET:
		pr_info("PM_SET command received\n");
		qlink_cmd_pm_set(qs, cmd);
		break;
	case QLINK_CMD_WOWLAN_SET:
		pr_info("WOWLAN_SET command received\n");
		qlink_cmd_wowlan_set(qs, cmd);
		break;
	case QLINK_CMD_START_CAC:
		pr_info("START_CAC command not implemented\n");
		qlink_process_invalid_cmd(cmd, QLINK_CMD_RESULT_ENOTSUPP);
		break;
	case QLINK_CMD_SET_MAC_ACL:
		pr_info("SET_MAC_ACL command not implemented\n");
		qlink_process_invalid_cmd(cmd, QLINK_CMD_RESULT_ENOTSUPP);
		break;
	case QLINK_CMD_PTA_PARAM:
		pr_info("PTA_PARAM command received\n");
		qlink_cmd_pta_param_setget(qs, cmd);
		break;
	case QLINK_CMD_TID_CFG:
		pr_info("TID_CFG command received\n");
		qlink_cmd_tid_config(qs, cmd);
		break;
	case QLINK_CMD_TXPWR:
		pr_info("TXPWR command received\n");
		qlink_cmd_txpwr(qs, cmd);
		break;
	default:
		pr_warn("unknown command received: 0x%x\n", cmd_id);
		qlink_process_invalid_cmd(cmd, QLINK_CMD_RESULT_ENOTSUPP);
		break;
	}
}

static struct qlink_resp *qlink_prepare_reply(const struct qlink_cmd *cmd)
{
	struct qlink_resp *reply;

	reply = kmalloc(QLINK_MAX_PACKET_SIZE, GFP_KERNEL | __GFP_ZERO);
	if (!reply) {
		pr_err("cannot allocate xmit buffer\n");
		return NULL;
	}

	reply->mhdr.type = cpu_to_le16(QLINK_MSG_TYPE_CMDRSP);
	reply->mhdr.len = cpu_to_le16(sizeof(struct qlink_resp));

	reply->seq_num = cmd->seq_num;
	reply->cmd_id = cmd->cmd_id;
	reply->result = cpu_to_le16(QLINK_CMD_RESULT_OK);
	reply->macid = cmd->macid;
	reply->vifid = cmd->vifid;

	return reply;
}

static int qlink_is_macid_valid(const struct qlink_cmd *cmd)
{
	if (cmd->macid >= qdrv_get_num_macs()) {
		pr_err("Bad MAC ID %d\n", cmd->macid);
		return 0;
	}

	return 1;
}

static int qlink_check_mac_if(const struct qlink_cmd *cmd)
{
	if (cmd->vifid >= QTNF_MAX_BSS_NUM || !qlink_is_macid_valid(cmd))
		return 0;

	return 1;
}

static bool qlink_convert_rssi_u8(int32_t rssi, u8 *val)
{
	if (rssi < -1 && rssi > -1200) {
		*val = (rssi - 5) / 10 + QLINK_RSSI_OFFSET;
		return true;
	}

	return false;
}

static void qlink_get_sta_state(const struct ieee80211_node *node, u32 *mask, u32 *value)
{
	struct ieee80211com *ic = node->ni_ic;
	struct ieee80211vap *vap = node->ni_vap;

	*mask = 0;
	*value = 0;

	*mask |= QLINK_STA_FLAG_AUTHENTICATED;
	if (vap->iv_state >= IEEE80211_S_ASSOC)
		*value |= QLINK_STA_FLAG_AUTHENTICATED;

	*mask |= QLINK_STA_FLAG_ASSOCIATED;
	if (vap->iv_state >= IEEE80211_S_RUN)
		*value |= QLINK_STA_FLAG_ASSOCIATED;

	*mask |= QLINK_STA_FLAG_AUTHORIZED;
	if (ieee80211_node_is_authorized(node))
		*value |= QLINK_STA_FLAG_AUTHORIZED;

	*mask |= QLINK_STA_FLAG_WME;
	if (node->ni_flags & IEEE80211_NODE_QOS)
		*value |= QLINK_STA_FLAG_WME;

	*mask |= QLINK_STA_FLAG_TDLS_PEER;
	if (!IEEE80211_NODE_IS_NONE_TDLS(node))
		*value |= QLINK_STA_FLAG_TDLS_PEER;

	*mask |= QLINK_STA_FLAG_SHORT_PREAMBLE;
	if ((node->ni_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE) &&
	    (ic->ic_flags & IEEE80211_F_SHPREAMBLE))
		*value |= QLINK_STA_FLAG_SHORT_PREAMBLE;

	*mask |= QLINK_STA_FLAG_MFP;
	if (RSN_IS_MFP(node->ni_rsn.rsn_caps))
		*value |= QLINK_STA_FLAG_MFP;
}

static void qlink_fill_sta_rate(u32 last_mcs, u32 last_sgi, struct qlink_sta_info_rate *rate)
{
	uint8_t nss = MS(last_mcs, QTN_PHY_STATS_MCS_NSS);
	uint8_t mcs = MS(last_mcs, QTN_STATS_MCS_RATE_MASK);
	uint16_t phyrate = MS(last_mcs, QTN_PHY_STATS_MCS_PHYRATE);
	uint8_t mode = MS(last_mcs, QTN_PHY_STATS_MCS_MODE);
	uint8_t bw = MS(last_mcs, QTN_PHY_STATS_MCS_BW);

	memset((void *)rate, 0, sizeof(*rate));

	put_unaligned_le16(phyrate, &rate->rate);
	rate->mcs = mcs;
	rate->nss = nss;

	switch (bw) {
	case QTN_BW_20M:
		rate->bw = QLINK_CHAN_WIDTH_20;
		break;
	case QTN_BW_40M:
		rate->bw = QLINK_CHAN_WIDTH_40;
		break;
	case QTN_BW_80M:
		rate->bw = QLINK_CHAN_WIDTH_80;
		break;
	}

	switch (mode) {
	case QTN_PHY_STATS_MODE_11N:
		rate->flags |= QLINK_STA_INFO_RATE_FLAG_HT_MCS;
		break;
	case QTN_PHY_STATS_MODE_11AC:
		rate->flags |= QLINK_STA_INFO_RATE_FLAG_VHT_MCS;
		break;
	}

	if (last_sgi)
		rate->flags |= QLINK_STA_INFO_RATE_FLAG_SHORT_GI;
}

static u16 qlink_cmd_sta_info_fill(u8 *buf, struct ieee80211_node *ni)
{
	const struct ieee80211com *ic = ni->ni_ic;
	const struct qtn_node_shared_stats_rx *srx;
	const struct qtn_node_shared_stats_tx *stx;
	const struct ieee80211_nodestats *nistat;
	u32 sta_state_mask, sta_state_value;
	u32 timediff;
	u8 *ptr;
	struct qlink_sta_stats *si;
	u8 *filled;

	/* update node stats from shared data */
	if (ic->ic_get_shared_node_stats)
		ic->ic_get_shared_node_stats(ni);

	nistat = &ni->ni_stats;
	srx = &ni->ni_shared_stats->rx[STATS_MIN];
	stx = &ni->ni_shared_stats->tx[STATS_MIN];

	ptr = qlink_append_tlv_buf(buf, QTN_TLV_ID_STA_STATS,
			(u8 **)&si, sizeof(*si));
	ptr = qlink_append_tlv_buf(ptr, QTN_TLV_ID_BITMAP,
			&filled,
			ALIGN(QLINK_STA_INFO_NUM / BITS_PER_BYTE + 4, 4));

	timediff = (u32)div_u64(get_jiffies_64() -
				ni->ni_start_time_assoc, HZ);
	si->connected_time = cpu_to_le32(timediff);
	qlink_utils_set_arr_bit(filled, QLINK_STA_INFO_CONNECTED_TIME);

	si->rx_bytes = cpu_to_le64(nistat->ns_rx_bytes);
	qlink_utils_set_arr_bit(filled, QLINK_STA_INFO_RX_BYTES64);

	si->tx_bytes = cpu_to_le64(nistat->ns_tx_bytes);
	qlink_utils_set_arr_bit(filled, QLINK_STA_INFO_TX_BYTES64);

	si->rx_beacon = cpu_to_le64(nistat->ns_rx_beacons);
	qlink_utils_set_arr_bit(filled, QLINK_STA_INFO_BEACON_RX);

	si->rx_packets = cpu_to_le32(nistat->ns_rx_data);
	qlink_utils_set_arr_bit(filled, QLINK_STA_INFO_RX_PACKETS);

	si->tx_packets = cpu_to_le32(nistat->ns_tx_data);
	qlink_utils_set_arr_bit(filled, QLINK_STA_INFO_TX_PACKETS);

	si->tx_failed = cpu_to_le32(nistat->ns_tx_dropped);
	qlink_utils_set_arr_bit(filled, QLINK_STA_INFO_TX_FAILED);

	si->rx_dropped_misc = cpu_to_le32(nistat->ns_rx_dropped +
					  nistat->ns_rx_errors);
	qlink_utils_set_arr_bit(filled, QLINK_STA_INFO_RX_DROP_MISC);

	if (qlink_convert_rssi_u8(ic->ic_rssi(ni), &si->signal))
		qlink_utils_set_arr_bit(filled, QLINK_STA_INFO_SIGNAL);

	if (qlink_convert_rssi_u8(ic->ic_smoothed_rssi(ni), &si->signal_avg))
		qlink_utils_set_arr_bit(filled, QLINK_STA_INFO_SIGNAL_AVG);

	qlink_get_sta_state(ni, &sta_state_mask, &sta_state_value);
	si->sta_flags.mask = cpu_to_le32(sta_state_mask);
	si->sta_flags.value = cpu_to_le32(sta_state_value);
	qlink_utils_set_arr_bit(filled, QLINK_STA_INFO_STA_FLAGS);

	qlink_fill_sta_rate(srx[STATS_SU].last_mcs, srx[STATS_SU].last_sgi, &si->rxrate);
	qlink_utils_set_arr_bit(filled, QLINK_STA_INFO_RX_BITRATE);

	qlink_fill_sta_rate(stx[STATS_SU].last_mcs, stx[STATS_SU].last_sgi, &si->txrate);
	qlink_utils_set_arr_bit(filled, QLINK_STA_INFO_TX_BITRATE);

	return ptr - buf;
}

static void qlink_cmd_fw_init(struct qlink_server *qs, const struct qlink_cmd *cmd)
{
	const struct qlink_cmd_init_fw *req;
	struct qlink_resp_init_fw *resp;
	u32 host_qlink_ver;
	int ret = 0;

	resp = (struct qlink_resp_init_fw *)qlink_prepare_reply(cmd);
	if (!resp)
		return;

	req = (const struct qlink_cmd_init_fw *)cmd;
	host_qlink_ver = le32_to_cpu(req->qlink_proto_ver);
	resp->qlink_proto_ver = cpu_to_le32(QLINK_PROTO_VER);
	resp->rhdr.mhdr.len = cpu_to_le16(sizeof(*resp));

	pr_info("FW_INIT QLINK version host=%u.%u FW=%u.%u\n",
		QLINK_VER_MAJOR(host_qlink_ver), QLINK_VER_MINOR(host_qlink_ver),
		QLINK_PROTO_VER_MAJOR, QLINK_PROTO_VER_MINOR);

	ret = qlink_server_init(qs);
	if (ret) {
		pr_err("failed to init qlink server\n");
		goto out;
	}

out:
	resp->rhdr.result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(resp, sizeof(*resp));
}

static void qlink_cmd_fw_deinit(struct qlink_server *qs, const struct qlink_cmd *cmd)
{
	struct qlink_resp *reply;

	qlink_server_deinit(qs);

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	qlink_xmit(reply, sizeof(*reply));
}

static void qlink_cmd_register_mgmt(struct qlink_server *qs,
				    const struct qlink_cmd *cmd)
{
	const struct qlink_cmd_mgmt_frame_register *req;
	struct qlink_resp *reply;
	struct qlink_bss *bss;
	u16 frame_type;
	u32 app_filter = 0;
	u16 result = QLINK_CMD_RESULT_INVALID;

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	if (unlikely(!qlink_check_mac_if(cmd))) {
		pr_err("invalid mac/if: %u %u\n", cmd->macid, cmd->vifid);
		goto out;
	}

	if (unlikely(le16_to_cpu(cmd->mhdr.len) < sizeof(*req))) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmd->mhdr.len));
		goto out;
	}

	bss = &qs->maclist[cmd->macid].bss[cmd->vifid];

	if (unlikely(!bss_has_status(bss, QLINK_BSS_ADDED))) {
		pr_err("bss is not added; mac: %u; if: %u\n", cmd->macid, cmd->vifid);
		goto out;
	}

	if (unlikely(!bss->vap)) {
		pr_err("bss vap is not ready; mac: %u; if: %u\n", cmd->macid, cmd->vifid);
		goto out;
	}

	req = (const struct qlink_cmd_mgmt_frame_register *)cmd;
	frame_type = le16_to_cpu(req->frame_type);

	switch (frame_type) {
	case QLINK_MGMT_FRAME_ASSOC_REQ:
		app_filter = IEEE80211_FILTER_TYPE_ASSOC_REQ;
		break;
	case QLINK_MGMT_FRAME_ASSOC_RESP:
		app_filter = IEEE80211_FILTER_TYPE_ASSOC_RESP;
		break;
	case QLINK_MGMT_FRAME_PROBE_REQ:
		app_filter = IEEE80211_FILTER_TYPE_PROBE_REQ;
		break;
	case QLINK_MGMT_FRAME_PROBE_RESP:
		app_filter = IEEE80211_FILTER_TYPE_PROBE_RESP;
		break;
	case QLINK_MGMT_FRAME_BEACON:
		app_filter = IEEE80211_FILTER_TYPE_BEACON;
		break;
	case QLINK_MGMT_FRAME_DISASSOC:
		app_filter = IEEE80211_FILTER_TYPE_DISASSOC;
		break;
	case QLINK_MGMT_FRAME_AUTH:
		app_filter = IEEE80211_FILTER_TYPE_AUTH;
		break;
	case QLINK_MGMT_FRAME_DEAUTH:
		app_filter = IEEE80211_FILTER_TYPE_DEAUTH;
		break;
	case QLINK_MGMT_FRAME_ACTION:
		app_filter = IEEE80211_FILTER_TYPE_ACTION;
		break;
	case QLINK_MGMT_FRAME_REASSOC_REQ:
	case QLINK_MGMT_FRAME_REASSOC_RESP:
	case QLINK_MGMT_FRAME_ATIM:
		pr_warn("0x%X mgmt frame requested: not supported\n", frame_type);
		goto out;
	default:
		pr_err("invalid mgmt frame type requested: %.4X\n", frame_type);
		goto out;
	}

	if (req->do_register) {
		pr_info("MAC %u; IF %u; reg mask %.4X +%.4X\n",
			cmd->macid, cmd->vifid, bss->vap->app_filter, app_filter);
		bss->vap->app_filter |= app_filter;
	} else {
		pr_info("MAC %u; IF %u; unreg mask %.4X -%.4X\n",
			cmd->macid, cmd->vifid, bss->vap->app_filter, app_filter);
		bss->vap->app_filter &= ~app_filter;
	}

	result = QLINK_CMD_RESULT_OK;

out:
	reply->result = cpu_to_le16(result);

	qlink_xmit(reply, sizeof(*reply));
}

static int qlink_mgmt_tx(struct qlink_bss *bss, u32 cookie, uint16_t freq,
			  const uint8_t *frame, size_t len)
{
	const struct ieee80211_frame *frame_hdr = (const struct ieee80211_frame *)frame;
	uint8_t subtype = frame_hdr->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
	const uint8_t *daddr = frame_hdr->i_addr1;
	struct ieee80211com *ic = bss->mac->ic;
	struct ieee80211vap *vap = bss->vap;
	struct ieee80211_node *ni = NULL;
	struct sk_buff *skb = NULL;
	uint8_t *skb_data = NULL;
	u16 chan;
	int ret;

	if (unlikely(len < sizeof(*frame_hdr))) {
		pr_err("too small frame: %u < %zu\n", len, sizeof(struct ieee80211_frame));
		return -EMSGSIZE;
	}

	ni = ieee80211_find_node(&ic->ic_sta, daddr);
	if (!ni || (ni == vap->iv_bss)) {
		/* release vap->iv_bss node */
		if (ni)
			ieee80211_free_node(ni);

		ni = ieee80211_tmp_node(vap, daddr);
		if (unlikely(!ni)) {
			pr_err("cannot create temp node for %pM\n", daddr);
			ret = -ENOMEM;
			goto err;
		}

		IEEE80211_ADDR_COPY(vap->iv_bss->ni_bssid, frame_hdr->i_addr3);
		IEEE80211_ADDR_COPY(ni->ni_bssid, frame_hdr->i_addr3);
	}

	frame += sizeof(*frame_hdr);
	len -= sizeof(*frame_hdr);

	skb = ieee80211_getmgtframe(&skb_data, len);
	if (unlikely(!skb)) {
		pr_err("cannot allocate management frame\n");
		ret = -ENOMEM;
		goto err;
	}

	memcpy(skb_data, frame, len);

	switch (subtype) {
	case IEEE80211_FC0_SUBTYPE_AUTH:
		if (!bss_has_status(bss, QLINK_BSS_SAE_PROCESSING))
			break;

		/* SAE: make sure AUTH_REQ is sent on the correct channel */
		if (freq != 0)
			chan = ieee80211_mhz2ieee(freq,
						  (freq < IEEE80211_5GBAND_START_FREQ) ?
						  IEEE80211_CHAN_2GHZ : IEEE80211_CHAN_5GHZ);
		else if (bss->sae_chan_ieee != 0)
			chan = bss->sae_chan_ieee;
		else
			break;

		ret = qlink_wifi_set_chan(bss->dev, chan);
		if (ret) {
			pr_err("failed to set channel\n");
			goto err;
		}

		break;
	default:
		break;
	}

	pr_debug("TYPE: %.2X; LEN %u; DA %pM; SA %pM; BSS %pM\n",
		 subtype, len, daddr, ni->ni_vap->iv_myaddr, ni->ni_bssid);

	ieee80211_mgmt_output(ni, skb, subtype, daddr);

	switch (subtype) {
	case IEEE80211_FC0_SUBTYPE_AUTH:
		if (!bss_has_status(bss, QLINK_BSS_SAE_PROCESSING))
			break;

		vap->iv_state_flags |= IEEE80211_VAP_STATE_F_EXT_AUTH_FRAME_SENT;
		ieee80211_new_state(vap, IEEE80211_S_AUTH, 0);
		break;
	}

	return 0;

err:
	if (ni)
		ieee80211_free_node(ni);

	if (skb)
		dev_kfree_skb_any(skb);

	return ret;
}

static int qlink_data_frame_tx(struct qlink_bss *bss, const uint8_t *frame, size_t len)
{
	const struct ether_header *eh = (const struct ether_header *)frame;

	if (len < sizeof(*eh)) {
		pr_err("[%s] too small %u\n", netdev_name(bss->vap->iv_dev), len);
		return -EMSGSIZE;
	}

	if (eh->ether_type != htons(ETH_P_PAE)) {
		pr_err("[%s] unsupported frame type %x\n", netdev_name(bss->vap->iv_dev),
		       ntohs(eh->ether_type));
		return -EOPNOTSUPP;
	}

	pr_debug("[%s] send EAPOL sa=%pM da=%pM\n", netdev_name(bss->vap->iv_dev),
		 eh->ether_shost, eh->ether_dhost);

	ieee80211_eap_output(bss->vap->iv_dev, frame, len);

	return 0;
}

static void qlink_cmd_send_frame(struct qlink_server *qs, const struct qlink_cmd *cmd)
{
	const struct qlink_cmd_frame_tx *req;
	struct qlink_resp *reply;
	struct qlink_bss *bss;
	size_t frame_len;
	u16 flags;
	int ret = -EINVAL;

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	if (unlikely(!qlink_check_mac_if(cmd))) {
		pr_err("invalid mac/if: %u %u\n", cmd->macid, cmd->vifid);
		goto out;
	}

	if (unlikely(le16_to_cpu(cmd->mhdr.len) < sizeof(*req))) {
		pr_err("payload is too small: %u\n", le16_to_cpu(cmd->mhdr.len));
		goto out;
	}

	bss = &qs->maclist[cmd->macid].bss[cmd->vifid];

	if (unlikely(!bss_has_status(bss, QLINK_BSS_STARTED))) {
		pr_err("bss is not started; mac: %u; if: %u\n", cmd->macid, cmd->vifid);
		goto out;
	}

	req = (const struct qlink_cmd_frame_tx *)cmd;
	frame_len = le16_to_cpu(cmd->mhdr.len) - sizeof(*req);
	flags = le16_to_cpu(req->flags);

	if (flags & QLINK_FRAME_TX_FLAG_8023)
		ret = qlink_data_frame_tx(bss, req->frame_data, frame_len);
	else
		ret = qlink_mgmt_tx(bss, le32_to_cpu(req->cookie), le16_to_cpu(req->freq),
				    req->frame_data, frame_len);

out:
	reply->result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(reply, sizeof(*reply));
}

static int
qlink_cmd_append_ie_do(struct qlink_bss *bss,
		       const struct qlink_tlv_ie_set *req)
{
	unsigned int tlv_len = le16_to_cpu(req->hdr.len);
	const u8 *ie_buf;
	size_t ie_buf_size;
	u32 frame_type;

	if (tlv_len < sizeof(*req)) {
		pr_warn("%s: not enough data %u\n", bss->dev->name, tlv_len);
		return -ENOSPC;
	}

	ie_buf_size = tlv_len - (sizeof(*req) - sizeof(req->hdr));
	ie_buf = req->ie_data;

	switch (req->type) {
	case QLINK_IE_SET_BEACON_IES:
		frame_type = IEEE80211_APPIE_FRAME_BEACON;
		break;
	case QLINK_IE_SET_PROBE_RESP_IES:
		frame_type = IEEE80211_APPIE_FRAME_PROBE_RESP;
		break;
	case QLINK_IE_SET_ASSOC_RESP:
		frame_type = IEEE80211_APPIE_FRAME_ASSOC_RESP;
		break;
	case QLINK_IE_SET_PROBE_REQ:
		frame_type = IEEE80211_APPIE_FRAME_PROBE_REQ;
		break;
	case QLINK_IE_SET_ASSOC_REQ:
		qlink_ie_mgmt_process(bss->vap, ie_buf, ie_buf_size);
		qlink_wifi_set_opt_ie(bss->dev, req->ie_data, ie_buf_size);
		return 0;
	case QLINK_IE_SET_BEACON_TAIL:
		qlink_ie_mgmt_process(bss->vap, ie_buf, ie_buf_size);
		return 0;
	default:
		pr_debug("%s: bad MGMT type %.4X\n", bss->dev->name, req->type);
		return 0;
	}

	return qlink_ie_mgmt_handle_appie(bss, frame_type, ie_buf, ie_buf_size);
}

static void qlink_cmd_mgmt_set_appie(struct qlink_server *qs, const struct qlink_cmd *cmd)
{
	const struct qlink_tlv_hdr *tlvh;
	struct qlink_resp *reply;
	struct qlink_bss *bss;
	u16 result = QLINK_CMD_RESULT_INVALID;
	unsigned int payload_len;
	const u8 *data;

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	if (unlikely(!qlink_check_mac_if(cmd))) {
		pr_err("invalid mac/if: %u %u\n", cmd->macid, cmd->vifid);
		goto out;
	}

	bss = &qs->maclist[cmd->macid].bss[cmd->vifid];

	if (unlikely(!bss_has_status(bss, QLINK_BSS_ADDED))) {
		pr_err("bss is not added; mac: %u; if: %u\n", cmd->macid, cmd->vifid);
		goto out;
	}

	if (unlikely(!bss->vap)) {
		pr_err("bss vap is not ready; mac: %u; if: %u\n", cmd->macid, cmd->vifid);
		goto out;
	}

	data = (u8 *)(cmd + 1);
	payload_len = le16_to_cpu(cmd->mhdr.len) - sizeof(*cmd);

	qlink_for_each_tlv(tlvh, data, payload_len) {
		switch (le16_to_cpu(tlvh->type)) {
		case QTN_TLV_ID_IE_SET:
			if (qlink_cmd_append_ie_do(bss,
				(const struct qlink_tlv_ie_set *)tlvh))
				goto out;
			break;
		default:
			break;
		}
	}

	result = QLINK_CMD_RESULT_OK;

out:
	reply->result = cpu_to_le16(result);

	qlink_xmit(reply, sizeof(*reply));
}

static void qlink_get_vif_name(char *name, int mac_id, int if_idx)
{
	snprintf(name, MAX_DEV_NAME, "wifi%d", if_idx);
}

static int
qlink_add_bss_iface(struct qlink_server *qs, int mac_id, int if_idx,
		    enum qlink_iface_type mode, const u8 *addr)
{
	struct net_device *dev;
	struct qlink_bss *bss;
	struct qlink_mac *mac;
	struct net_bridge_port *br_port;
	char dev_name[MAX_DEV_NAME];
	char cmd_buf[MAX_QDRV_CMD];
	char if_mode[4];
	int ret;

	mac = &qs->maclist[mac_id];
	bss = &mac->bss[if_idx];
	qlink_get_vif_name(dev_name, mac_id, if_idx);

	if (bss_has_status(bss, QLINK_BSS_ADDED)) {
		pr_err("interface %s already added\n", dev_name);
		return -1;
	}

	if (if_idx == 0)
		mac->ic = qdrv_get_ic(mac_id);

	if (unlikely(!mac->ic)) {
		pr_err("internal error: cannot get ic\n");
		return -1;
	}

	memset(bss, 0, sizeof(*bss));

	switch (mode) {
	case QLINK_IFTYPE_AP:
		snprintf(if_mode, sizeof(if_mode), "%s", "ap");
		break;
	case QLINK_IFTYPE_STATION:
		snprintf(if_mode, sizeof(if_mode), "%s", "sta");
		break;
	default:
		pr_err("Invalid iftype: %d", mode);
		return -1;
	}

	/* create virtual interface wifiX_Y */

	dev = dev_get_by_name(&init_net, dev_name);
	if (dev) {
		dev_put(dev);
		pr_err("interface %s already exists\n", dev_name);
		return -1;
	}

	pr_info("create interface %s\n", dev_name);
	mutex_lock(&qs->mlock);
	if (if_idx == 0)
		snprintf(cmd_buf, MAX_QDRV_CMD, "start %d %s %s", mac_id, if_mode, dev_name);
	else
		snprintf(cmd_buf, MAX_QDRV_CMD, "start %d %s %s %pM", mac_id, if_mode, dev_name,
			 addr);

	ret = qdrv_control_input(qs->qdrv_dev, cmd_buf, strlen(cmd_buf));
	mutex_unlock(&qs->mlock);

	if (ret) {
		pr_err("qdrv command \"%s\" failed.\n", cmd_buf);
		return -1;
	}

	bss->dev = dev_get_by_name(&init_net, dev_name);
	if (!bss->dev) {
		pr_err("failed to create interface %s\n", dev_name);
		goto out_err_cleanup;
	}

	pr_info("add interface %s to bridge %s\n", dev_name, qs->br_dev->name);
	if (qlink_bridge_addif(qs->br_dev, bss->dev)) {
		pr_err("failed to add %s to bridge\n", dev_name);
		goto out_err_cleanup;
	}

	br_port = bss->dev->br_port;
	if (!br_port) {
		pr_err("could't find bridge port for %s\n", dev_name);
		goto out_err_cleanup;
	}

	/*
	 * Wireless interface on host side uses the same MAC address as wifi interface on
	 * our side.
	 * There already should be a "local" fdb entry in bridge for this MAC address, this will
	 * prevent bridge from forwarding frames coming from remote host.
	 * Remove local entry so that it can be replaced with remote entry later.
	 */
	br_fdb_delete_by_port(br_port->br, br_port, 1);

	/* setup bss data */
	bss->vap = netdev_priv(bss->dev);
	bss->mode = mode;
	bss->mac = mac;
	bss_set_status(bss, QLINK_BSS_ADDED);
	IEEE80211_ADDR_COPY(bss->mac_addr, bss->vap->iv_myaddr);

	switch (mode) {
	case QLINK_IFTYPE_AP:
		qlink_load_default_bss_settings(bss);
		break;
	case QLINK_IFTYPE_STATION:
		qlink_load_default_bss_settings(bss);
		bss_set_status(bss, QLINK_BSS_STARTED);
		break;
	/* coverity[dead_error_begin : FALSE] - remain future-proof and catch newly added modes */
	default:
		pr_err("Invalid iftype: %d", mode);
		return -1;
	}

	/* setup mac data */
	if (if_idx == 0) {
		mac->dev = bss->dev;
		mac->qs = qs;

		if (!mac->phyparams_set)
			qlink_mac_phyparams_apply_default(mac);

		if (mode == QLINK_IFTYPE_AP) {
			qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_BA_SETUP_ENABLE, 1);
			qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_RESTRICTED_MODE, 1);
		}

		qlink_wifi_scs_config(bss->dev, IEEE80211_SCS_SET_ENABLE, 0);
		qlink_wifi_scs_config(bss->dev, IEEE80211_SCS_SET_SAMPLE_ENABLE, 1);
		qlink_wifi_scs_config(bss->dev, IEEE80211_SCS_SET_STATS_START, 1);

		/* Enable VHT 2.4GHz */
		if (mac->ic->ic_rf_chipid == CHIPID_DUAL ||
		    mac->ic->ic_rf_chipid == CHIPID_2_4_GHZ)
			qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_VHT_2_4GHZ, 1);
	}

	/* Tell WLAN driver that 802.11 state machine is controlled
	 * by a host. this needs to be done each time a new VIF is added
	 * as QDRV will overwrite this flag
	 */
	mac->ic->ic_roaming = IEEE80211_ROAMING_MANUAL;
	mac->ic->ic_flags_ext2 |= IEEE80211_FEXT2_NO_80211_SM;

	/* Disable all WoWLAN triggers */
	mac->ic->ic_wowlan.mask = 0;

	/* Use PCIe PME for host wakeup */
	mac->ic->ic_wowlan.wakeup_type = WOWLAN_PCIE_PME_HOST_WAKEUP;

	qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_IMPLICITBA, 0);

	return 0;

out_err_cleanup:

	if (bss->dev) {
		dev_put(bss->dev);
		bss->dev = NULL;
	}

	mutex_lock(&qs->mlock);
	snprintf(cmd_buf, MAX_QDRV_CMD, "stop %d %s", mac_id, dev_name);
	/* coverity[check_return] */
	qdrv_control_input(qs->qdrv_dev, cmd_buf, strlen(cmd_buf));
	mutex_unlock(&qs->mlock);

	return -1;
}

static void qlink_cmd_add_if(struct qlink_server *qs, const struct qlink_cmd *cmd)
{
	struct qlink_cmd_manage_intf *cmd_params;
	struct qlink_resp_manage_intf *resp;
	struct qlink_bss *bss;
	struct qlink_mac *mac;
	enum qlink_iface_type iftype;
	u16 vlanid;
	int ret = 0;

	resp = (struct qlink_resp_manage_intf *)qlink_prepare_reply(cmd);
	if (!resp)
		return;

	if (!qlink_check_mac_if(cmd)) {
		pr_err("invalid mac/if: %u %u\n", cmd->macid, cmd->vifid);
		ret = -EINVAL;
		goto out;
	}

	if (unlikely(le16_to_cpu(cmd->mhdr.len) < sizeof(*cmd_params))) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmd->mhdr.len));
		ret = -EFAULT;
		goto out;
	}

	cmd_params = (struct qlink_cmd_manage_intf *)cmd;

	iftype = le16_to_cpu(cmd_params->intf_info.if_type);
	vlanid = le16_to_cpu(cmd_params->intf_info.vlanid);

	mac = &qs->maclist[cmd->macid];
	bss = &mac->bss[cmd->vifid];

	memset(&resp->intf_info, 0, sizeof(resp->intf_info));
	resp->rhdr.mhdr.len = cpu_to_le16(sizeof(*resp));
	resp->intf_info.if_type = cmd_params->intf_info.if_type;
	resp->intf_info.vlanid = cmd_params->intf_info.vlanid;

	switch (iftype) {
	case QLINK_IFTYPE_AP:
		pr_info("adding VAP %u to MAC %u\n", cmd->vifid, cmd->macid);
		ret = qlink_add_bss_iface(qs, cmd->macid, cmd->vifid, iftype,
					  cmd_params->intf_info.mac_addr);
		if (ret)
			goto out;

		IEEE80211_ADDR_COPY(resp->intf_info.mac_addr, bss->mac_addr);
		break;
	case QLINK_IFTYPE_STATION:
		pr_info("adding STA to MAC %u\n", cmd->macid);
		ret = qlink_add_bss_iface(qs, cmd->macid, cmd->vifid, iftype,
					  cmd_params->intf_info.mac_addr);
		if (ret)
			goto out;

		IEEE80211_ADDR_COPY(resp->intf_info.mac_addr, bss->mac_addr);
		break;
	case QLINK_IFTYPE_AP_VLAN:
		pr_err("AP_VLAN interface type is not implemented\n");
		IEEE80211_ADDR_SET_NULL(resp->intf_info.mac_addr);
		ret = -EOPNOTSUPP;
		break;
	default:
		pr_err("unexpected if_type %u\n", iftype);
		ret = -EINVAL;
		goto out;
	}

	pr_info("EP: MAC(%pM)\n", resp->intf_info.mac_addr);

out:
	resp->rhdr.result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(resp, sizeof(*resp));
}

static int qlink_del_bss_iface(struct qlink_server *qs, int mac_id, int if_idx)
{
	struct qlink_bss *bss;
	struct qlink_mac *mac;
	char dev_name[MAX_DEV_NAME];
	char cmd_buf[MAX_QDRV_CMD];
	int ret;
	size_t bss_total;

	mac = &qs->maclist[mac_id];
	bss = &mac->bss[if_idx];

	qlink_get_vif_name(dev_name, mac_id, if_idx);

	if (!bss_has_status(bss, QLINK_BSS_ADDED)) {
		pr_err("interface %s not registered\n", dev_name);
		return -1;
	}

	bss_total = qlink_mac_bss_added_count(mac);

	if (!bss->vap)
		goto cleanup_bss;

	/* stop AP/STA if necessary and then delete interface */

	if (bss_has_status(bss, QLINK_BSS_STARTED)) {
		if (bss->mode == QLINK_IFTYPE_AP) {
			qlink_ap_stop(bss);
		} else if (bss->mode == QLINK_IFTYPE_STATION) {
			qlink_wifi_sta_deauth(bss->dev, bss->mac_addr,
					      IEEE80211_REASON_AUTH_LEAVE);
			bss_clr_status(bss, QLINK_BSS_STARTED);
		}
	}


	/* make sure virtual interface wifiX_Y is down */
	if (qlink_if_down(bss->dev))
		pr_err("%s: bring-down interface failed\n",
		       bss->dev->name);

	qlink_events_mgmt_bss_deinit(bss);
	if (bss_total <= 1) {
		ieee80211_cancel_scan_no_wait(bss->vap);

		qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_OCAC,
				    IEEE80211_OCAC_SET_DISABLE << 16);
		qlink_wifi_setparam(bss->dev,
				    IEEE80211_PARAM_BA_SETUP_ENABLE, 0);
		qlink_wifi_setparam(bss->dev,
				    IEEE80211_PARAM_RESTRICTED_MODE, 0);

		qlink_wifi_scs_config(bss->dev, IEEE80211_SCS_SET_SAMPLE_ENABLE, 0);
		qlink_wifi_scs_config(bss->dev, IEEE80211_SCS_SET_STATS_START, 0);
		qlink_wifi_scs_config(bss->dev, IEEE80211_SCS_SET_ENABLE, 0);
		qlink_wifi_setparam(mac->dev, IEEE80211_PARAM_MARKDFS, 0);
	}

	dev_put(bss->dev);

	/* Stop a single VAP interface */
	mutex_lock(&qs->mlock);
	snprintf(cmd_buf, MAX_QDRV_CMD, "stop %d %s", mac_id, dev_name);
	ret = qdrv_control_input(qs->qdrv_dev, cmd_buf, strlen(cmd_buf));
	mutex_unlock(&qs->mlock);
	if (ret) {
		pr_err("qdrv command \"%s\" failed.\n", cmd_buf);
		return -1;
	}

cleanup_bss:
	/* cleanup bss data */
	bss->mode = QLINK_IFTYPE_STATION;
	bss->dev = NULL;
	bss->vap = NULL;
	bss->mac = NULL;
	bss_clr_status(bss, QLINK_BSS_ADDED);

	/* cleanup mac data */

	if (bss_total <= 1) {
		mac->dev = NULL;
		mac->ic = NULL;
		mac->qs = NULL;
	}
	return 0;
}

static void qlink_cmd_del_if(struct qlink_server *qs, const struct qlink_cmd *cmd)
{
	struct qlink_cmd_manage_intf *cmd_params;
	struct qlink_resp_manage_intf *resp;
	enum qlink_iface_type iftype;
	u16 vlanid;

	resp = (struct qlink_resp_manage_intf *)qlink_prepare_reply(cmd);
	if (!resp)
		return;

	if (!qlink_check_mac_if(cmd)) {
		pr_err("invalid mac/if: %u %u\n", cmd->macid, cmd->vifid);
		goto out_err;
	}

	if (unlikely(le16_to_cpu(cmd->mhdr.len) < sizeof(*cmd_params))) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmd->mhdr.len));
		goto out_err;
	}

	cmd_params = (struct qlink_cmd_manage_intf *)cmd;

	iftype = le16_to_cpu(cmd_params->intf_info.if_type);
	vlanid = le16_to_cpu(cmd_params->intf_info.vlanid);

	memset(&resp->intf_info, 0, sizeof(resp->intf_info));
	resp->intf_info.if_type = cmd_params->intf_info.if_type;
	resp->intf_info.vlanid = cmd_params->intf_info.vlanid;
	resp->rhdr.mhdr.len = cpu_to_le16(sizeof(*resp));

	switch (iftype) {
	case QLINK_IFTYPE_AP:
		pr_info("delete VAP %u on MAC %u\n", cmd->vifid, cmd->macid);
		if (qlink_del_bss_iface(qs, cmd->macid, cmd->vifid))
			goto out_err;
		break;
	case QLINK_IFTYPE_STATION:
		pr_info("delete STA on MAC %u\n", cmd->macid);
		if (qlink_del_bss_iface(qs, cmd->macid, cmd->vifid))
			goto out_err;

		break;
	case QLINK_IFTYPE_AP_VLAN:
		pr_err("AP_VLAN interface type is not implemented\n");
		resp->rhdr.result = cpu_to_le16(QLINK_CMD_RESULT_ENOTSUPP);
		break;
	default:
		pr_err("unexpected if_type %u\n", iftype);
		goto out_err;
	}

	qlink_xmit(resp, sizeof(*resp));
	return;

out_err:
	resp->rhdr.result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
	qlink_xmit(resp, sizeof(*resp));
}

static int qlink_change_iface(struct qlink_server *qs, int mac_id, int if_idx,
			      int mode, u8 *addr)
{
	struct qlink_bss *bss;
	struct qlink_mac *mac;
	int if_up = 0;
	int ret = 0;
	int need_update_pwr = 0;

	mac = &qs->maclist[mac_id];
	bss = &mac->bss[if_idx];

	if ((mode == bss->mode) && IEEE80211_ADDR_EQ(addr, bss->mac_addr))
		return 0;

	if (mode == QLINK_IFTYPE_STATION) {
		/* Check that no virtual interfaces exist before switching to STA mode */
		if (qlink_mac_bss_added_count(mac) > 1)
			return -EINVAL;
	}

	/* Tx power limits may differ between modes */
	if (mode != bss->mode && mac->ic->ic_country_code != CTRY_DEFAULT)
		need_update_pwr = 1;

	if (IEEE80211_DEV_IS_UP(bss->dev))
		if_up = 1;

	ret = qlink_del_bss_iface(qs, mac_id, if_idx);
	if (ret)
		return ret;

	ret = qlink_add_bss_iface(qs, mac_id, if_idx, mode, addr);
	if (ret)
		return ret;

	if (need_update_pwr) {
		if (mode == QLINK_IFTYPE_STATION)
			qlink_wifi_setparam(mac->dev, IEEE80211_PARAM_STA_DFS,
					qs->host_slave_radar);
		else
			qlink_wifi_setparam(mac->dev, IEEE80211_PARAM_MARKDFS, 1);

		qlink_reg_update_tx_power(mac);
	}

	/* restore previous interface state */
	if (if_up)
		ret = qlink_if_up(bss->dev);

	return ret;
}

static void qlink_cmd_change_if(struct qlink_server *qs, const struct qlink_cmd *cmd)
{
	struct qlink_cmd_manage_intf *cmd_params;
	struct qlink_resp_manage_intf *resp;
	enum qlink_iface_type iftype;
	struct qlink_bss *bss;
	int ret = 0;

	resp = (struct qlink_resp_manage_intf *)qlink_prepare_reply(cmd);
	if (!resp)
		return;

	if (!qlink_check_mac_if(cmd)) {
		pr_err("VIF%u.%u: invalid\n", cmd->macid, cmd->vifid);
		ret = -EINVAL;
		goto out_err;
	}

	if (unlikely(le16_to_cpu(cmd->mhdr.len) < sizeof(*cmd_params))) {
		pr_err("VIF%u.%u: cmd payload is too small: %u\n",
		       cmd->macid, cmd->vifid, le16_to_cpu(cmd->mhdr.len));
		ret = -ENOBUFS;
		goto out_err;
	}

	bss = &qs->maclist[cmd->macid].bss[cmd->vifid];
	if (!bss->vap) {
		pr_err("VIF%u.%u: not registered\n", cmd->macid, cmd->vifid);
		ret = -ENOENT;
		goto out_err;
	}

	cmd_params = (struct qlink_cmd_manage_intf *)cmd;
	iftype = le16_to_cpu(cmd_params->intf_info.if_type);

	pr_info("RC requests MAC = %pM\n", cmd_params->intf_info.mac_addr);

	memset(&resp->intf_info, 0, sizeof(resp->intf_info));
	resp->rhdr.mhdr.len = cpu_to_le16(sizeof(*resp));
	resp->intf_info.if_type = cmd_params->intf_info.if_type;

	if (iftype != QLINK_IFTYPE_AP && iftype != QLINK_IFTYPE_STATION) {
		pr_err("VIF%u.%u: unexpected iftype %u\n", cmd->macid, cmd->vifid, iftype);
		ret = -EINVAL;
		goto out_err;
	}

	if (bss_has_status(bss, QLINK_BSS_STARTED) && (bss->mode == QLINK_IFTYPE_AP)) {
		pr_err("VIF%u.%u: can't switch to STA: VAP started\n", cmd->macid, cmd->vifid);
		ret = -EINVAL;
		goto out_err;
	}

	if (iftype == QLINK_IFTYPE_STATION && cmd->vifid != 0) {
		pr_err("VIF%u.%u: can't switch to STA\n", cmd->macid, cmd->vifid);
		ret = -EINVAL;
		goto out_err;
	}

	pr_info("VIF%u.%u change: MAC %pM -> %pM, mode %u -> %u\n",
		cmd->macid, cmd->vifid, bss->mac_addr,
		cmd_params->intf_info.mac_addr,
		bss->mode, iftype);

	ret = qlink_change_iface(qs, cmd->macid, cmd->vifid, iftype,
				 cmd_params->intf_info.mac_addr);

	IEEE80211_ADDR_COPY(resp->intf_info.mac_addr, bss->mac_addr);
	pr_info("VIF%u.%u: change %s (MAC %pM)\n", cmd->macid, cmd->vifid,
		ret ? "FAIL" : "OK", bss->mac_addr);

out_err:
	resp->rhdr.result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(resp, sizeof(*resp));
}

static void qlink_cmd_updown_if(struct qlink_server *qs, const struct qlink_cmd *cmd)
{
	struct qlink_cmd_updown *cmd_params;
	struct qlink_resp *reply;
	struct qlink_bss *bss;
	int ret = 0;

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	if (!qlink_check_mac_if(cmd)) {
		ret = -EINVAL;
		goto out;
	}

	if (le16_to_cpu(cmd->mhdr.len) < sizeof(*cmd_params)) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmd->mhdr.len));
		ret = -EINVAL;
		goto out;
	}

	cmd_params = (struct qlink_cmd_updown *)cmd;

	bss = &qs->maclist[cmd->macid].bss[cmd->vifid];
	if (!bss_has_status(bss, QLINK_BSS_ADDED)) {
		ret = -ENOENT;
		goto out;
	}

	if (cmd_params->if_up)
		ret = qlink_if_up(bss->dev);
	else
		ret = qlink_if_down(bss->dev);

	pr_info("%s: bring %s %s\n", bss->dev->name,
		cmd_params->if_up ? "UP" : "DOWN",
		ret ? "failed" : "OK");
out:
	reply->result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(reply, le16_to_cpu(reply->mhdr.len));
}

static int qlink_cipher_suite2drv(u32 suite, u32 *cipher)
{
	int ret = 0;

	switch (suite) {
	case WLAN_CIPHER_SUITE_WEP40:
		*cipher = IEEE80211_CIPHER_WEP;
		break;
	case WLAN_CIPHER_SUITE_TKIP:
		*cipher = IEEE80211_CIPHER_TKIP;
		break;
	case WLAN_CIPHER_SUITE_CCMP:
		*cipher = IEEE80211_CIPHER_AES_CCM;
		break;
	case WLAN_CIPHER_SUITE_WEP104:
		*cipher = IEEE80211_CIPHER_WEP;
		break;
	case WLAN_CIPHER_SUITE_AES_CMAC:
		*cipher = IEEE80211_CIPHER_AES_CMAC;
		break;
	case WLAN_CIPHER_SUITE_CCMP_256:
		*cipher = IEEE80211_CIPHER_AES_CCM;
		break;
	default:
		*cipher = IEEE80211_CIPHER_NONE;
		ret = -1;
		break;
	}

	return ret;
}

static void qlink_load_default_bss_privacy(struct qlink_bss *bss)
{
	qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_AUTHMODE,	IEEE80211_AUTH_AUTO);
	qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_PRIVACY, 0);
}

static void qlink_load_default_bss_settings(struct qlink_bss *bss)
{
	memcpy(bss->ssid, "qtn_wifi", 9);
	bss->ssid_len = 9;
	memset(bss->rates, 0, IEEE80211_RATE_SIZE);
	bss->rates_num = 0;
	bss->ds_params = 0;
	qlink_load_default_bss_privacy(bss);
}

static int qlink_apply_bss_privacy(struct qlink_bss *bss,
				   const struct qlink_auth_encr *aen,
				   enum ieee80211_mfp_capabilities mfp)
{
	int drop_unencrypted = 1;
	unsigned int n_ciphers_pairwise;
	u32 cipher_set = 0;
	u32 group_cipher;
	enum ieee80211_authmode authmode;
	u32 wpa_versions;
	u32 akm_set = 0;
	unsigned int n_akm_suites;
	unsigned int i;

	pr_info("%s: mode=%d privacy=%u auth_type=%u mfp=%u\n",
		bss->dev->name, bss->mode, aen->privacy,
		aen->auth_type, mfp);

	if (!aen->privacy) {
		qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_PRIVACY, 0);
		qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_KEYMGTALGS, 0);
		qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_RSNCAPS, 0);
		qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_AUTHMODE,	IEEE80211_AUTH_OPEN);
		qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_CONFIG_PMF, 0);
		return 0;
	}

	n_ciphers_pairwise = le32_to_cpu(aen->n_ciphers_pairwise);
	if (n_ciphers_pairwise > QLINK_MAX_NR_CIPHER_SUITES) {
		pr_warn("%s: num ciphers limited %u->%u\n", bss->dev->name,
			n_ciphers_pairwise, QLINK_MAX_NR_CIPHER_SUITES);
		n_ciphers_pairwise = QLINK_MAX_NR_CIPHER_SUITES;
	}

	for (i = 0; i < n_ciphers_pairwise; ++i) {
		switch (le32_to_cpu(aen->ciphers_pairwise[i])) {
		case WLAN_CIPHER_SUITE_CCMP_256:
		case WLAN_CIPHER_SUITE_CCMP:
			cipher_set |= BIT(IEEE80211_CIPHER_AES_CCM);
			break;
		case WLAN_CIPHER_SUITE_TKIP:
			cipher_set |= BIT(IEEE80211_CIPHER_TKIP);
			break;
		case WLAN_CIPHER_SUITE_AES_CMAC:
			cipher_set |= BIT(IEEE80211_CIPHER_AES_CMAC);
			break;
		case 0:
			break;
		default:
			pr_warn("%s: unsupported cipher 0x%x\n", bss->dev->name,
				le32_to_cpu(aen->ciphers_pairwise[i]));
			break;
		}
	}

	group_cipher = le32_to_cpu(aen->cipher_group);
	switch (group_cipher) {
	case WLAN_CIPHER_SUITE_CCMP:
		group_cipher = IEEE80211_CIPHER_AES_CCM;
		break;
	case WLAN_CIPHER_SUITE_TKIP:
		group_cipher = IEEE80211_CIPHER_TKIP;
		break;
	case 0:
		break;
	default:
		pr_warn("%s: unsupported group cipher 0x%x\n", bss->dev->name,
			group_cipher);
		return -EINVAL;
	}

	n_akm_suites = le32_to_cpu(aen->n_akm_suites);
	if (n_akm_suites > QLINK_MAX_NR_AKM_SUITES) {
		pr_warn("%s: num AMK suites limited %u->%u\n", bss->dev->name,
			n_akm_suites, QLINK_MAX_NR_AKM_SUITES);
		n_akm_suites = QLINK_MAX_NR_AKM_SUITES;
	}

	for (i = 0; i < n_akm_suites; i++) {
		switch (le32_to_cpu(aen->akm_suites[i])) {
		case WLAN_AKM_SUITE_8021X:
			akm_set |= WPA_KEY_MGMT_IEEE8021X;
			break;
		case WLAN_AKM_SUITE_PSK:
			akm_set |= WPA_KEY_MGMT_PSK;
			break;
		case WLAN_AKM_SUITE_8021X_SHA256:
			akm_set |= WPA_KEY_MGMT_IEEE8021X_SHA256;
			break;
		case WLAN_AKM_SUITE_PSK_SHA256:
			akm_set |= WPA_KEY_MGMT_PSK_SHA256;
			break;
		case WLAN_AKM_SUITE_SAE:
			akm_set |= WPA_KEY_MGMT_SAE;
			break;
		default:
			pr_warn("%s: bad AKM suite 0x%x\n", bss->dev->name,
				le32_to_cpu(aen->akm_suites[i]));
			break;
		}
	}

	wpa_versions = le32_to_cpu(aen->wpa_versions);
	if (wpa_versions & ~(NL80211_WPA_VERSION_1 | NL80211_WPA_VERSION_2)) {
		pr_err("%s: invalid wpa_versions = %u\n", bss->dev->name, wpa_versions);
		return -EINVAL;
	}

	switch (aen->auth_type) {
	case QLINK_AUTHTYPE_OPEN_SYSTEM:
		if (wpa_versions)
			authmode = IEEE80211_AUTH_WPA;
		else if ((akm_set & WPA_KEY_MGMT_IEEE8021X) ||
			 (akm_set & WPA_KEY_MGMT_IEEE8021X_SHA256))
			authmode = IEEE80211_AUTH_8021X;
		else
			authmode = IEEE80211_AUTH_OPEN;
		break;
	case QLINK_AUTHTYPE_FT:
		if (wpa_versions)
			authmode = IEEE80211_AUTH_WPA;
		else
			authmode = IEEE80211_AUTH_8021X;
		break;
	case QLINK_AUTHTYPE_NETWORK_EAP:
		authmode = IEEE80211_AUTH_8021X;
		break;
	case QLINK_AUTHTYPE_SAE:
		authmode = IEEE80211_AUTH_SAE;
		break;
	case QLINK_AUTHTYPE_AUTOMATIC:
		authmode = IEEE80211_AUTH_AUTO;
		break;
	default:
		pr_err("%s: bad auth type %u\n", bss->dev->name, aen->auth_type);
		return -EINVAL;
	}

	if (cipher_set == 0 && group_cipher == 0)
		drop_unencrypted = 0;

	pr_info("  cipher_set=0x%x\n"
		"  cipher_group=0x%x\n"
		"  auth_type=%u\n"
		"  wpa_versions=0x%x\n"
		"  control_port=%u\n"
		"  control_port_no_encrypt=%u\n"
		"  control_port_ethertype=0x%x\n",
		cipher_set, group_cipher, authmode, wpa_versions,
		aen->control_port, aen->control_port_no_encrypt,
		le16_to_cpu(aen->control_port_ethertype));

	if (bss->mode == QLINK_IFTYPE_AP) {
		qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_MCASTCIPHER, group_cipher);
		qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_UCASTCIPHERS, cipher_set);
		qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_KEYMGTALGS, akm_set);
	} else if (bss->mode == QLINK_IFTYPE_STATION) {
		qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_DROPUNENCRYPTED, drop_unencrypted);
		/* EP ieee80211_mfp_capabilities enum values differ from HOST nl80211_mfp */
		qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_CONFIG_PMF, mfp);
	}

	qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_PRIVACY, aen->privacy);
	qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_WPA, wpa_versions);
	qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_AUTHMODE, authmode);

	return 0;
}

static void qlink_apply_bss_config(struct qlink_bss *bss,
				   const struct qlink_cmd_start_ap *cmd)
{
	pr_info("%s:\n  ssid=%s bcn=%u dtim=%u inact=%u\n", bss->dev->name,
		bss->ssid, le16_to_cpu(cmd->beacon_interval),
		le16_to_cpu(cmd->dtim_period),
		le16_to_cpu(cmd->inactivity_timeout));

	qlink_wifi_set_ssid(bss->dev, bss->ssid, bss->ssid_len);

	qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_BEACON_INTERVAL,
			    le16_to_cpu(cmd->beacon_interval));
	qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_DTIM_PERIOD,
			    le16_to_cpu(cmd->dtim_period));
	qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_INACT,
			    le16_to_cpu(cmd->inactivity_timeout));
	qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_INACT_AUTH,
			    le16_to_cpu(cmd->inactivity_timeout));
	qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_INACT_INIT,
			    le16_to_cpu(cmd->inactivity_timeout));
}

static int qlink_bss_chandef_apply(const struct qlink_bss *bss,
				   const struct qlink_chandef *chdef,
				   const struct ieee80211_ht_cap *ht_cap,
				   const struct ieee80211_vht_cap *vht_cap)
{
	struct ieee80211com *ic = bss->vap->iv_ic;
	struct ieee80211_channel *c;
	unsigned int pri = le16_to_cpu(chdef->chan.center_freq);
	enum qlink_band qlink_band;
	unsigned int bw;
	const char *band;
	int sgi_20 = 0;
	int sgi_40 = 0;
	int sgi_80 = 0;
	int ldpc = 0;
	int stbc = 0;
	int sgi;
	int ret;

	ret = qlink_chan_q2ieee(ic, chdef, &c, &bw);
	if (ret)
		return ret;

	if (!qlink_utils_is_channel_usable(ic, c, bw)) {
		pr_warn("%s: channel is not usable ieee=%u bw=%u\n",
			bss->dev->name, c->ic_ieee, bw);
		return -EINVAL;
	}

	if (chdef->width == QLINK_CHAN_WIDTH_20_NOHT)
		ht_cap = NULL;

	if (!vht_cap && bw > BW_HT40) {
		pr_warn("VHT disabled: lower BW to 40MHz from %u\n", bw);
		bw = BW_HT40;
	}

	if (!ht_cap && bw > BW_HT20) {
		pr_warn("HT disabled: lower BW to 20MHz from %u\n", bw);
		bw = BW_HT20;
	}

	band = qlink_chan_identify_band(c, bw, vht_cap != NULL, ht_cap != NULL);

	pr_info("%s: chan=%u bw=%u band=%s ht=%u vht=%u\n",
		bss->vap->iv_dev->name, c->ic_ieee, bw, band,
		ht_cap != NULL, vht_cap != NULL);

	qlink_utils_chandef_set(bss->mac->ic, bss->vap->iv_dev, c, bw, band);

	qlink_band = pri < IEEE80211_5GBAND_START_FREQ ? QLINK_BAND_2GHZ :
							 QLINK_BAND_5GHZ;

	if (ht_cap) {
		ret = qlink_bss_ht_conf_apply(bss, ht_cap, &sgi_20, &sgi_40,
					      &ldpc, &stbc);
		if (ret) {
			pr_err("%s: failed to apply HT configuration\n",
			       bss->dev->name);
			goto restore_default;
		}
	}

	if (vht_cap) {
		ret = qlink_bss_vht_conf_apply(bss, vht_cap, &sgi_80, &ldpc,
					       &stbc, qlink_band == QLINK_BAND_2GHZ);
		if (ret) {
			pr_err("%s: failed to apply VHT configuration\n",
			       bss->dev->name);
			goto restore_default;
		}
	}

	if (ht_cap || vht_cap) {
		sgi = (sgi_20 && (bw == BW_HT20)) ||
			(sgi_40 && (bw == BW_HT40)) ||
			(sgi_80 && (bw == BW_HT80));

		ret = qlink_bss_global_conf_apply(bss,
						  sgi,
						  ldpc,
						  stbc);
		if (ret) {
			pr_err("%s: failed to apply global HT/VHT configuration\n",
			       bss->dev->name);
			goto restore_default;
		}
	}

	ieee80211_param_to_qdrv(bss->vap, IEEE80211_PARAM_MODE,
				vht_cap != NULL, NULL, 0);

	ic->ic_des_chan = ic->ic_curchan;
	return 0;

restore_default:
	qlink_mac_phyparams_apply_default(bss->mac);

	return ret;
}

static int qlink_cmd_start_ap_process_tlvs(struct qlink_bss *bss,
					   const struct qlink_cmd_start_ap *cmd)
{
	unsigned int payload_len = le16_to_cpu(cmd->chdr.mhdr.len) - sizeof(*cmd);
	const struct ieee80211_vht_cap *vht_cap = NULL;
	const struct ieee80211_ht_cap *ht_cap = NULL;
	const struct qlink_chandef *chdef = NULL;
	const struct qlink_tlv_hdr *ptlv;
	unsigned int vlen;
	int ret;

	qlink_for_each_tlv(ptlv, cmd->info, payload_len) {
		vlen = le16_to_cpu(ptlv->len);

		switch (le16_to_cpu(ptlv->type)) {
		case WLAN_EID_SSID:
			if (vlen >= sizeof(bss->ssid)) {
				pr_err("WLAN_EID_SSID bad length %d\n", vlen);
				break;
			}

			memcpy(bss->ssid, ptlv->val, vlen);
			bss->ssid[vlen] = '\0';
			bss->ssid_len = vlen;
			break;
		case QTN_TLV_ID_CHANDEF:
			if (vlen != sizeof(*chdef)) {
				pr_err("QTN_TLV_ID_CHANDEF bad length %d\n", vlen);
				break;
			}

			chdef = (struct qlink_chandef *)ptlv->val;
			break;
		case WLAN_EID_HT_CAPABILITY:
			if (vlen != sizeof(*ht_cap)) {
				pr_err("WLAN_EID_HT_CAPABILITY bad length %d\n", vlen);
				break;
			}

			ht_cap = (const struct ieee80211_ht_cap *)ptlv->val;
			break;
		case WLAN_EID_VHT_CAPABILITY:
			if (vlen != sizeof(*vht_cap)) {
				pr_err("WLAN_EID_VHT_CAPABILITY bad length %d\n", vlen);
				break;
			}

			vht_cap = (const struct ieee80211_vht_cap *)ptlv->val;
			break;
		case QTN_TLV_ID_IE_SET:
			ret = qlink_cmd_append_ie_do(bss,
				(const struct qlink_tlv_ie_set *)ptlv);
			if (ret) {
				pr_err("%s: QTN_TLV_ID_IE_SET error %d\n",
				       bss->dev->name, ret);
				return ret;
			}
			break;
		}
	}

	/* Only apply PHY settings for "primary" interface on a single radio */
	if (cmd->chdr.vifid == 0 && chdef) {
		ret = qlink_bss_chandef_apply(bss, chdef, ht_cap, vht_cap);
		if (ret)
			return ret;
	}

	return 0;
}

static void qlink_cmd_start_ap(struct qlink_server *qs, const struct qlink_cmd *cmdh)
{
	struct qlink_resp *reply;
	struct qlink_bss *bss;
	const struct qlink_cmd_start_ap *cmd =
		(const struct qlink_cmd_start_ap *)cmdh;
	unsigned int result = QLINK_CMD_RESULT_INVALID;

	reply = qlink_prepare_reply(cmdh);
	if (!reply)
		return;

	if (!qlink_check_mac_if(cmdh)) {
		pr_err("invalid mac/if: %u %u\n", cmdh->macid, cmdh->vifid);
		goto out;
	}

	if (unlikely(le16_to_cpu(cmdh->mhdr.len) < sizeof(*cmd))) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmdh->mhdr.len));
		goto out;
	}

	bss = &qs->maclist[cmdh->macid].bss[cmdh->vifid];

	if (!bss->dev) {
		pr_err("VIF%u.%u: no dev assigned\n", cmdh->macid, cmdh->vifid);
		goto out;
	}

	if (!bss_has_status(bss, QLINK_BSS_ADDED) || (bss->mode != QLINK_IFTYPE_AP)) {
		pr_err("%s: invalid state\n", bss->dev->name);
		goto out;
	}

	if (bss_has_status(bss, QLINK_BSS_STARTED)) {
		pr_warn("%s: already started, stop\n", bss->dev->name);
		qlink_ap_stop(bss);
	}

	/* Make sure interface is UP and in init state first */
	qlink_if_up(bss->dev);
	ieee80211_new_state(bss->vap, IEEE80211_S_INIT, -1);

	if (qlink_apply_bss_privacy(bss, &cmd->aen, 0 /* not used for AP */))
		goto out;

	if (qlink_cmd_start_ap_process_tlvs(bss, cmd))
		goto out;

	qlink_apply_bss_config(bss, cmd);
	/* Putting interface into RUN state will trigger BSS creation */
	ieee80211_new_state(bss->vap, IEEE80211_S_RUN, -1);

	bss_set_status(bss, QLINK_BSS_STARTED);
	result = QLINK_CMD_RESULT_OK;

out:
	reply->result = cpu_to_le16(result);
	qlink_xmit(reply, le16_to_cpu(reply->mhdr.len));
}

static void qlink_ap_stop(struct qlink_bss *bss)
{
	if (!bss_has_status(bss, QLINK_BSS_STARTED)) {
		pr_warn("%s: bss already stopped\n", bss->dev->name);
		return;
	}

	ieee80211_new_state(bss->vap, IEEE80211_S_INIT, -1);
	qlink_load_default_bss_privacy(bss);
	bss_clr_status(bss, QLINK_BSS_STARTED);
}

static void qlink_cmd_stop_ap(struct qlink_server *qs, const struct qlink_cmd *cmd)
{
	struct qlink_resp *reply;
	struct qlink_bss *bss;

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	if (!qlink_check_mac_if(cmd)) {
		pr_err("invalid mac/if: %u %u\n", cmd->macid, cmd->vifid);
		reply->result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
		goto out;
	}

	bss = &qs->maclist[cmd->macid].bss[cmd->vifid];

	/* As a workaround of strange hostapd logic of first deleting a virtual interface
	 * and then stopping a VAP on it we return OK if VAP was stopped before with
	 * interface removal.
	 */
	if (!bss_has_status(bss, QLINK_BSS_ADDED))
		goto out;

	if (bss->mode != QLINK_IFTYPE_AP) {
		reply->result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
		goto out;
	}

	qlink_ap_stop(bss);
out:
	qlink_xmit(reply, le16_to_cpu(reply->mhdr.len));
}

static size_t qlink_cmd_bldinfo_fill(const struct device *dev,
				     struct qlink_resp_get_hw_info *hw_info,
				     u8 *payload)
{
	const char *bld_name;
	const char *bld_rev;
	const char *bld_type;
	const char *bld_label;
	u32 bld_tmstamp;
	u32 plat_id;
	const char *hw_id;
	const char *calibration_ver;
	const char *uboot_ver;
	u32 hw_ver;
	u8 *ptr = payload;

	qdrv_get_build_info(dev,
			    &bld_name, &bld_rev, &bld_type,
			    &bld_label, &bld_tmstamp,
			    &plat_id, &hw_id,
			    &calibration_ver, &uboot_ver, &hw_ver);

	hw_info->bld_tmstamp = cpu_to_le32(bld_tmstamp);
	hw_info->plat_id = cpu_to_le32(plat_id);
	hw_info->hw_ver = cpu_to_le32(hw_ver);

	ptr = qlink_encode_tlv_str(ptr, QTN_TLV_ID_BUILD_NAME,
				   bld_name, strlen(bld_name) + 1);
	ptr = qlink_encode_tlv_str(ptr, QTN_TLV_ID_BUILD_REV,
				   bld_rev, strlen(bld_rev) + 1);
	ptr = qlink_encode_tlv_str(ptr, QTN_TLV_ID_BUILD_TYPE,
				   bld_type, strlen(bld_type) + 1);
	ptr = qlink_encode_tlv_str(ptr, QTN_TLV_ID_BUILD_LABEL,
				   bld_label, strlen(bld_label) + 1);
	ptr = qlink_encode_tlv_str(ptr, QTN_TLV_ID_HW_ID,
				   hw_id, strlen(hw_id) + 1);
	ptr = qlink_encode_tlv_str(ptr, QTN_TLV_ID_CALIBRATION_VER,
				   calibration_ver, strlen(calibration_ver) + 1);
	ptr = qlink_encode_tlv_str(ptr, QTN_TLV_ID_UBOOT_VER,
				   uboot_ver, strlen(uboot_ver) + 1);

	return ptr - payload;
}

static size_t qlink_hw_capab_fill(u8 *payload, bool svc_mode)
{
	u8 *caps;
	u8 *end;

	end = qlink_append_tlv_buf(payload, QTN_TLV_ID_BITMAP, &caps,
				   QLINK_HW_CAPAB_NUM / BITS_PER_BYTE + 1);

	qlink_utils_set_arr_bit(caps, QLINK_HW_CAPAB_REG_UPDATE);
	qlink_utils_set_arr_bit(caps, QLINK_HW_CAPAB_STA_INACT_TIMEOUT);
	qlink_utils_set_arr_bit(caps, QLINK_HW_CAPAB_SCAN_RANDOM_MAC_ADDR);
	qlink_utils_set_arr_bit(caps, QLINK_HW_CAPAB_PWR_MGMT);
	qlink_utils_set_arr_bit(caps, QLINK_HW_CAPAB_SCAN_DWELL);
	qlink_utils_set_arr_bit(caps, QLINK_HW_CAPAB_AGGR_CTRL);
	qlink_utils_set_arr_bit(caps, QLINK_HW_CAPAB_SAE);

	if (svc_mode)
		qlink_utils_set_arr_bit(caps, QLINK_HW_CAPAB_SVC_MODE);

	return end - payload;
}

static void qlink_cmd_get_hw_info(const struct qlink_server *qs,
		const struct qlink_cmd *cmd)
{
	const struct device *dev = qs->qdrv_dev;
	struct qlink_resp_get_hw_info *hw_info;
	size_t payload_size = 0;
	bool svc_mode = false;
	unsigned int i;

	hw_info = (struct qlink_resp_get_hw_info *)qlink_prepare_reply(cmd);
	if (!hw_info)
		return;

	hw_info->fw_ver = cpu_to_le32(qdrv_get_fw_version());
	hw_info->num_mac = qdrv_get_num_macs();

	for (i = QTN_WMAC_UNIT0; i < hw_info->num_mac; ++i)
		hw_info->mac_bitmap |= BIT(i);

	/* Number of Tx/Rx chains for MAC0 is a total number of chains on device */
	hw_info->total_rx_chain = qdrv_get_num_rx_chains(QTN_WMAC_UNIT0);
	hw_info->total_tx_chain = qdrv_get_num_tx_chains(QTN_WMAC_UNIT0);

	if (qs->sp->calstate == QTN_CALSTATE_CALIB) {
		pr_info("calibration mode: wireless operations are not supported\n");
		svc_mode = true;
	}

	payload_size += qlink_cmd_bldinfo_fill(dev, hw_info,
					       hw_info->info + payload_size);
	payload_size += qlink_hw_capab_fill(hw_info->info + payload_size,
					    svc_mode);

	pr_info("HW INFO: MACs map 0x%x, chains Tx=%u Rx=%u\n",
		hw_info->mac_bitmap, hw_info->total_tx_chain,
		hw_info->total_rx_chain);

	hw_info->rhdr.mhdr.len = cpu_to_le16(sizeof(*hw_info) + payload_size);
	qlink_xmit(hw_info, le16_to_cpu(hw_info->rhdr.mhdr.len));
}

static void qlink_wmac_get_ext_capa(u8 *ext_capa,
				    u8 *ext_capa_mask,
				    u8 *ext_capa_len)
{
	static const u8 EXT_CAPA[] = { 0, 0, IEEE80211_EXTCAP_TO_BIT(IEEE80211_EXTCAP_BTM)};
	static const u8 EXT_CAPA_LEN = sizeof(EXT_CAPA);

	if (ext_capa) {
		memcpy(ext_capa, EXT_CAPA, EXT_CAPA_LEN);
		if (ext_capa_mask)
			memcpy(ext_capa_mask, EXT_CAPA, EXT_CAPA_LEN);
	} else if (ext_capa_len) {
		*ext_capa_len = EXT_CAPA_LEN;
	}
}

static size_t qlink_wmac_info_append_extra_info(u8 *payload,
						unsigned int *iface_comb_num)
{
	struct qlink_iface_limit *limit;
	struct qlink_iface_limit_record *list;
	struct qlink_wowlan_capab_data *wowl_data;
	struct qlink_wowlan_support *wowl_supp;
	u8 ext_capa_len;
	u8 *ext_capa;
	u8 *ext_capa_mask;
	u8 *ptr = payload;

	*iface_comb_num = 0;

	/* Enable STA interface combination
	 * {
	 *	{
	 *		.max = 1,
	 *		.types = QLINK_IFTYPE_STA
	 *	},
	 * }
	 */

	++*iface_comb_num;
	ptr = qlink_append_tlv_buf(ptr, QTN_TLV_ID_IFACE_LIMIT,
				   (u8 **)&list, sizeof(*list) + sizeof(*limit));

	put_unaligned_le16(1, &list->max_interfaces);
	list->n_limits = 1;
	list->num_different_channels = 1;

	limit = list->limits;
	put_unaligned_le16(QLINK_IFTYPE_STATION, &limit[0].type);
	put_unaligned_le16(1, &limit[0].max_num);

	/* append Extended Capabilities */

	qlink_wmac_get_ext_capa(NULL, NULL, &ext_capa_len);
	ptr = qlink_append_tlv_buf(ptr, WLAN_EID_EXT_CAPABILITY,
				   &ext_capa, ext_capa_len);
	ptr = qlink_append_tlv_buf(ptr, QTN_TLV_ID_EXT_CAPABILITY_MASK,
				   &ext_capa_mask, ext_capa_len);
	qlink_wmac_get_ext_capa(ext_capa, ext_capa_mask, &ext_capa_len);

	/* append WoWLAN capabilities */

	ptr = qlink_append_tlv_buf(ptr, QTN_TLV_ID_WOWLAN_CAPAB,
				   (u8 **)&wowl_data,
				   sizeof(*wowl_data) + sizeof(*wowl_supp));
	put_unaligned_le16(0x1, &wowl_data->version);
	put_unaligned_le16(sizeof(*wowl_supp), &wowl_data->len);

	wowl_supp = (struct qlink_wowlan_support *)wowl_data->data;
	put_unaligned_le32(1, &wowl_supp->n_patterns);
	put_unaligned_le32(1, &wowl_supp->pattern_min_len);
	put_unaligned_le32(QTNF_WOWLAN_MAX_MAGIC_LEN,
			   &wowl_supp->pattern_max_len);

	return ptr - payload;
}

static void qlink_cmd_get_wmac_info(struct qlink_server *qs,
				    const struct qlink_cmd *cmd)
{
	struct qlink_resp_get_mac_info *mac_info;
	unsigned int iface_comb_num;
	struct qlink_resp *reply;
	size_t payload_size = 0;
	struct qlink_mac *mac;
	unsigned int mac_idx;
	uint16_t rfchip_info;
	u8 rfchip_id;
	int phy_val;
	int ret = 0;

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	mac_info = (struct qlink_resp_get_mac_info *)reply;

	mac_idx = cmd->macid;
	if (!qlink_is_macid_valid(cmd)) {
		ret = -EINVAL;
		goto out;
	}

	mac = &qs->maclist[cmd->macid];
	if (!mac->dev) {
		pr_err("[MAC%u] not registered\n", cmd->macid);
		ret = -EINVAL;
		goto out;
	}

	rfchip_info = qdrv_get_rfchip_info(mac_idx);
	if (rfchip_info == 0xFFFF) {
		pr_err("mac_idx=%d, unknown chipid\n", mac_idx);
		ret = -EINVAL;
		goto out;
	}

	rfchip_id = (uint8_t)((rfchip_info & 0xFF00) >> 8);

	switch (rfchip_id) {
	case CHIPID_2_4_GHZ:
		pr_info("mac_idx=%d, CHIPID_2_4_GHZ\n", mac_idx);
		mac_info->bands_cap = QLINK_BAND_2GHZ;
		break;
	case CHIPID_5_GHZ:
		pr_info("mac_idx=%d, CHIPID_5_GHZ\n", mac_idx);
		mac_info->bands_cap = QLINK_BAND_5GHZ;
		break;
	case CHIPID_DUAL:
		pr_info("mac_idx=%d, CHIPID_DUAL\n", mac_idx);
		mac_info->bands_cap = QLINK_BAND_2GHZ | QLINK_BAND_5GHZ;
		break;
	default:
		pr_warn("mac_idx=%d, unknown chipid\n", mac_idx);
		ret = -EINVAL;
		goto out;
	}

	mac_info->num_rx_chain = qdrv_get_num_rx_chains(mac_idx);
	mac_info->num_tx_chain = qdrv_get_num_tx_chains(mac_idx);
	mac_info->max_scan_ssids = IEEE80211_ACTIVE_SCAN_MAX_SSID;
	mac_info->max_ap_assoc_sta = cpu_to_le16(qdrv_get_max_ap_assoc_sta(mac_idx));
	mac_info->radar_detect_widths =
				cpu_to_le16(BIT(QLINK_CHAN_WIDTH_20_NOHT) |
					    BIT(QLINK_CHAN_WIDTH_20) |
					    BIT(QLINK_CHAN_WIDTH_40) |
					    BIT(QLINK_CHAN_WIDTH_80));

	/* MAC ACL is currently disabled on BBIC4 */
	mac_info->max_acl_mac_addrs = cpu_to_le32(0);

	qlink_wmac_info_htcap_mod_mask_fill(&mac_info->ht_cap_mod_mask,
					    mac_info->num_rx_chain);
	qlink_wmac_info_vhtcap_mod_mask_fill(&mac_info->vht_cap_mod_mask,
					     mac_info->num_rx_chain,
					     mac_info->num_tx_chain);

	if (!qlink_phy_get_rts_thre(mac->dev, &phy_val))
		mac_info->rts_threshold = cpu_to_le32((u32)phy_val);

	if (!qlink_phy_get_frag_thre(mac->dev, &phy_val))
		mac_info->frag_threshold = cpu_to_le32((u32)phy_val);

	if (!qlink_phy_get_retry(mac->dev, &phy_val)) {
		mac_info->retry_short = phy_val;
		mac_info->retry_long = phy_val;
	}

	if (!qlink_wifi_getparam(mac->dev, IEEE80211_PARAM_COVERAGE_CLASS,
				 &phy_val))
		mac_info->coverage_class = phy_val;

	qdrv_get_mac_addr(mac_idx, mac_info->dev_mac);
	pr_info("EP responds MAC = %pM\n", mac_info->dev_mac);

	payload_size += qlink_wmac_info_append_extra_info(mac_info->var_info,
							  &iface_comb_num);
	payload_size += qlink_reg_mac_info_fill(mac->ic, mac_info,
						payload_size);
	mac_info->n_iface_combinations = iface_comb_num;

out:
	payload_size += sizeof(*mac_info);
	reply->mhdr.len = cpu_to_le16(payload_size);
	reply->result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(reply, payload_size);
}

static void qlink_cmd_get_sta_info(const struct qlink_cmd *cmd)
{
	struct qlink_cmd_get_sta_info *req;
	struct qlink_resp_get_sta_info *sta_info;
	struct qlink_resp *reply;
	struct ieee80211com *ic;
	struct ieee80211_node *sta_node;
	u16 resp_len = sizeof(*sta_info);

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	if (!qlink_check_mac_if(cmd)) {
		pr_err("invalid mac/if: %u %u\n", cmd->macid, cmd->vifid);
		reply->result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
		goto out;
	}

	if (unlikely(le16_to_cpu(cmd->mhdr.len) < sizeof(*req))) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmd->mhdr.len));
		reply->result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
		goto out;
	}

	req = (struct qlink_cmd_get_sta_info *)cmd;
	sta_info = (struct qlink_resp_get_sta_info *)reply;
	ether_addr_copy(sta_info->sta_addr, req->sta_addr);

	ic = qdrv_get_ic(cmd->macid);
	if (unlikely(!ic)) {
		pr_err("internal error: cannot get ic\n");
		reply->result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
		goto out;
	}

	sta_node = ieee80211_find_node(&ic->ic_sta, req->sta_addr);

	if (unlikely(!sta_node)) {
		pr_err("STA not found: %pM\n", req->sta_addr);
		reply->result = cpu_to_le16(QLINK_CMD_RESULT_ENOTFOUND);
		goto out;
	}

	resp_len += qlink_cmd_sta_info_fill(sta_info->info, sta_node);

	ieee80211_free_node(sta_node);

out:
	reply->mhdr.len = cpu_to_le16(resp_len);
	qlink_xmit(reply, resp_len);
}

static int qlink_cmd_regd_channels_parse(struct qlink_mac *mac, const u8 *buf,
					 unsigned int payload_len,
					 unsigned int num_channels)
{
	const struct qlink_tlv_hdr *tlv;
	const struct qlink_channel *qch;

	qlink_for_each_tlv(tlv, buf, payload_len) {
		if (num_channels == 0)
			break;

		switch (le16_to_cpu(tlv->type)) {
		case QTN_TLV_ID_CHANNEL:
			if (le16_to_cpu(tlv->len) < sizeof(*qch))
				break;

			qch = (const struct qlink_channel *)tlv->val;
			qlink_reg_chan_update(mac, qch);
			--num_channels;
			break;
		default:
			break;
		}
	}

	return 0;
}

static void qlink_cmd_regd_change_notify(struct qlink_server *qs,
		const struct qlink_cmd *cmd)
{
	const struct qlink_cmd_reg_notify *req;
	struct qlink_resp *reply;
	struct qlink_mac *mac;
	struct qlink_bss *bss;
	char alpha2[3];
	int ret = 0;

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	if (!qlink_is_macid_valid(cmd)) {
		ret = -EINVAL;
		goto out;
	}

	if (le16_to_cpu(cmd->mhdr.len) < sizeof(*req)) {
		pr_err("MAC%u: CMD too short: %u\n", cmd->macid, le16_to_cpu(cmd->mhdr.len));
		ret = -EMSGSIZE;
		goto out;
	}

	mac = &qs->maclist[cmd->macid];
	if (!mac->dev) {
		ret = -ENODEV;
		goto out;
	}

	bss = &mac->bss[0];
	if (unlikely(!bss_has_status(bss, QLINK_BSS_ADDED))) {
		pr_err("[MAC%u] primary bss is not added\n", cmd->macid);
		ret = -ENOENT;
		goto out;
	}

	ieee80211_cancel_scan_no_wait(bss->vap);

	req = (const struct qlink_cmd_reg_notify *)cmd;
	alpha2[0] = tolower(req->alpha2[0]);
	alpha2[1] = tolower(req->alpha2[1]);
	alpha2[2] = '\0';

	pr_info("MAC%u: region change to \"%s\" slave_radar=%u dfs=%u\n",
		cmd->macid, alpha2, req->slave_radar, req->dfs_region);

	ret = qlink_reg_region_update(mac, alpha2, req->slave_radar, req->dfs_region);
	if (ret)
		goto out;

	ret = qlink_cmd_regd_channels_parse(mac, req->info,
		le16_to_cpu(cmd->mhdr.len) - sizeof(*req), req->num_channels);
	if (ret)
		goto out;

	mac->ic->ic_mark_dfs_channels(mac->ic);

out:
	reply->result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(reply, le16_to_cpu(reply->mhdr.len));
}

static int qlink_phy_params_set(struct qlink_server *qs, const struct qlink_cmd *cmd)
{
	const u8 *tlv_buf = (const u8 *)cmd + sizeof(*cmd);
	struct qlink_mac *mac = &qs->maclist[cmd->macid];
	uint16_t payload_len, vlen;
	uint16_t change_done = 0;
	uint16_t change_req = 0;
	const struct qlink_tlv_hdr *ptlv;
	struct qlink_phy_params phy_new;
	struct qlink_phy_params phy_old;
	int ret = 0;

	payload_len = le16_to_cpu(cmd->mhdr.len) - sizeof(*cmd);
	qlink_dump_tlvs(tlv_buf, payload_len);
	mac = &qs->maclist[cmd->macid];
	memset(&phy_old, 0, sizeof(phy_old));
	memset(&phy_new, 0, sizeof(phy_new));

	qlink_for_each_tlv(ptlv, tlv_buf, payload_len) {
		vlen = le16_to_cpu(ptlv->len);

		switch (le16_to_cpu(ptlv->type)) {
		case QTN_TLV_ID_SRETRY_LIMIT:
			if (vlen != sizeof(u32)) {
				pr_warn("QTN_TLV_ID_SRETRY_LIMIT invalid length");
				break;
			}

			change_req |= QLINK_PHY_SRETRY_CHANGED;
			phy_new.sretry = le32_to_cpu(*((u32 *)ptlv->val));
			pr_debug("QTN_TLV_ID_SRETRY_LIMIT %u\n", phy_new.sretry);
			break;
		case QTN_TLV_ID_LRETRY_LIMIT:
			if (vlen != sizeof(u32)) {
				pr_warn("QTN_TLV_ID_LRETRY_LIMIT invalid length");
				break;
			}

			change_req |= QLINK_PHY_LRETRY_CHANGED;
			phy_new.lretry = le32_to_cpu(*((u32 *)ptlv->val));
			pr_debug("QTN_TLV_ID_LRETRY_LIMIT %u\n", phy_new.lretry);
			break;
		case QTN_TLV_ID_FRAG_THRESH:
			if (vlen != sizeof(u32)) {
				pr_warn("QTN_TLV_ID_FRAG_THRESH invalid length");
				break;
			}

			change_req |= QLINK_PHY_FRAG_CHANGED;
			phy_new.frag_thresh = le32_to_cpu(*((u32 *)ptlv->val));
			pr_debug("QTN_TLV_ID_FRAG_THRESH %u\n", phy_new.frag_thresh);
			break;
		case QTN_TLV_ID_RTS_THRESH:
			if (vlen != sizeof(u32)) {
				pr_warn("QTN_TLV_ID_RTS_THRESH invalid length");
				break;
			}

			change_req |= QLINK_PHY_RTS_CHANGED;
			phy_new.rts_thresh = le32_to_cpu(*((u32 *)ptlv->val));
			pr_debug("QTN_TLV_ID_RTS_THRESH %u\n", phy_new.rts_thresh);
			break;
		case QTN_TLV_ID_COVERAGE_CLASS:
			if (vlen != sizeof(u32)) {
				pr_warn("QTN_TLV_ID_COVERAGE_CLASS invalid length");
				break;
			}

			change_req |= QLINK_PHY_CCLASS_CHANGED;
			phy_new.cclass = le32_to_cpu(*((u32 *)ptlv->val));
			pr_debug("QTN_TLV_ID_CLASS %u\n", phy_new.cclass);
			break;
		default:
			pr_info("unknown TLV ID received: %u\n", le16_to_cpu(ptlv->type));
			break;
		};
	}

	/* follow host expectations: rollback successful changes on any failure */

	if (change_req & QLINK_PHY_SRETRY_CHANGED) {
		pr_warn("setting SRETRY not supported\n");
		goto out_rollback;
	}

	if (change_req & QLINK_PHY_LRETRY_CHANGED) {
		pr_warn("setting LRETRY not supported\n");
		goto out_rollback;
	}

	if (change_req & QLINK_PHY_FRAG_CHANGED) {
		phy_old.frag_thresh = mac->phy.frag_thresh;
		ret = qlink_phy_apply_frag_thre(mac->dev, phy_new.frag_thresh);
		if (ret) {
			pr_warn("failed to set frag threshold");
			goto out_rollback;
		} else {
			mac->phy.frag_thresh = phy_new.frag_thresh;
			change_done |= QLINK_PHY_FRAG_CHANGED;
		}
	}

	if (change_req & QLINK_PHY_RTS_CHANGED) {
		phy_old.rts_thresh = mac->phy.rts_thresh;
		/* adapt host value for 'disabled' to firmware definition */
		if (phy_new.rts_thresh == (u32)-1)
			phy_new.rts_thresh = IEEE80211_RTS_THRESH_OFF;

		ret = qlink_phy_apply_rts_thre(mac->dev, phy_new.rts_thresh);
		if (ret) {
			pr_warn("failed to set RTS threshold");
			goto out_rollback;
		} else {
			mac->phy.rts_thresh = phy_new.rts_thresh;
			change_done |= QLINK_PHY_RTS_CHANGED;
		}
	}

	if (change_req & QLINK_PHY_CCLASS_CHANGED) {
		phy_old.cclass = mac->phy.cclass;
		ret = qlink_wifi_set_cclass(mac->dev, phy_new.cclass);
		if (ret) {
			pr_warn("failed to set coverage class");
			goto out_rollback;
		} else {
			mac->phy.cclass = phy_new.cclass;
			change_done |= QLINK_PHY_CCLASS_CHANGED;
		}
	}

	/* all applied: report success */
	return 0;

out_rollback:
	if (change_done & QLINK_PHY_FRAG_CHANGED) {
		ret = qlink_phy_apply_frag_thre(mac->dev, phy_old.frag_thresh);
		if (ret)
			pr_warn("failed to restore frag threshold");
		else
			mac->phy.frag_thresh = phy_old.frag_thresh;
	}

	if (change_done & QLINK_PHY_RTS_CHANGED) {
		ret = qlink_phy_apply_rts_thre(mac->dev, phy_old.rts_thresh);
		if (ret)
			pr_warn("failed to restore RTS threshold");
		else
			mac->phy.rts_thresh = phy_old.rts_thresh;
	}

	/* coverity[dead_error_begin : FALSE] - remain future-proof and catch newly added params */
	if (change_done & QLINK_PHY_CCLASS_CHANGED) {
		ret = qlink_wifi_set_cclass(mac->dev, phy_old.cclass);
		if (ret)
			pr_warn("failed to set coverage class");
		else
			mac->phy.cclass = phy_old.cclass;
	}

	return -EINVAL;
}

static int qlink_mac_chan_stats_get(struct qlink_mac *mac,
				    const struct ieee80211_channel *chan,
				    u8 *data)
{
	struct qtn_scs_scan_info scs_scan_info;
	struct qlink_chan_stats *chan_stat;
	struct ieee80211com *ic = mac->ic;
	s8 chan_noise;
	u32 cca_try = 0;
	u32 cca_busy;
	u32 cca_intf;
	u32 cca_rx;
	u32 cca_tx;
	u8 *filled;
	u8 *ptr;
	int ret;

	if (isset(ic->ic_chan_disabled, chan->ic_ieee) ||
	    isclr(ic->ic_chan_active, chan->ic_ieee)) {
		pr_debug("%s: no stats for disabled channel %d\n",
			 mac->dev->name, chan->ic_ieee);
		return 0;
	}

	/* get the latest stats from SCS data whenever possible */
	if (ic->ic_scs.scs_stats_on) {
		struct shared_params *sp = mac->qs->sp;
		struct qtn_scs_info *scs_info;
		struct qtn_scs_info_set *scs_info_lh;

		scs_info = kmalloc(sizeof(*scs_info), GFP_KERNEL);
		if (!scs_info) {
			pr_err("%s: SCS info alloc failed\n", mac->dev->name);
			return 0;
		}

		scs_info_lh = sp->scs_info_lhost;
		memcpy((void *)scs_info,
		       &scs_info_lh->scs_info[scs_info_lh->valid_index],
		       sizeof(*scs_info));

		if ((chan == ic->ic_curchan) && scs_info->cca_try) {
			chan_noise = (s8)scs_info->hw_noise;
			cca_busy = IEEE80211_SCS_NORMALIZE(scs_info->cca_busy,
							   scs_info->cca_try);
			cca_intf = IEEE80211_SCS_NORMALIZE(scs_info->cca_interference,
							   scs_info->cca_try);
			cca_rx = cca_busy - cca_intf;
			cca_tx = IEEE80211_SCS_NORMALIZE(scs_info->cca_tx,
							 scs_info->cca_try);
			cca_try = IEEE80211_SCS_CCA_INTF_SCALE;

			kfree(scs_info);
			goto done;
		}

		if (scs_info->oc_info_count) {
			struct qtn_scs_oc_info *p_oc_info;
			int i;

			for (i = 0; i < scs_info->oc_info_count; i++) {
				p_oc_info = &scs_info->oc_info[i];

				if (chan->ic_ieee != p_oc_info->off_channel)
					continue;

				if (!p_oc_info->off_chan_cca_try_cnt)
					break;

				ieee80211_scs_scale_offchan_data(ic, p_oc_info);

				chan_noise = (s8)p_oc_info->off_chan_hw_noise;
				cca_try = p_oc_info->off_chan_cca_try_cnt;
				cca_tx = cca_try - p_oc_info->off_chan_cca_sample_cnt;
				cca_intf = p_oc_info->off_chan_cca_busy;
				cca_rx = 0;

				kfree(scs_info);
				goto done;
			}
		}

		kfree(scs_info);
	}

	/* use scan stats as a common fallback */
	ret = ieee80211_scs_get_scaled_scan_info(ic, chan->ic_ieee, &scs_scan_info);
	if (!ret) {
		chan_noise = (s8)scs_scan_info.hw_noise;
		cca_try = scs_scan_info.cca_try;
		cca_tx = scs_scan_info.cca_tx;
		cca_rx = scs_scan_info.cca_busy - scs_scan_info.cca_intf;
		cca_intf = scs_scan_info.cca_intf;
	}

done:
	if (!cca_try) {
		pr_debug("empty stats for channel %d\n", chan->ic_ieee);
		return 0;
	}

	ptr = qlink_append_tlv_buf(data, QTN_TLV_ID_CHANNEL_STATS,
			(u8 **)&chan_stat, sizeof(*chan_stat));
	ptr = qlink_append_tlv_buf(ptr, QTN_TLV_ID_BITMAP,
			&filled, QLINK_CHAN_STAT_NUM / BITS_PER_BYTE + 1);

	chan_stat->time_on = cpu_to_le64(cca_try);
	qlink_utils_set_arr_bit(filled, QLINK_CHAN_STAT_TIME_ON);
	chan_stat->time_tx = cpu_to_le64(cca_tx);
	qlink_utils_set_arr_bit(filled, QLINK_CHAN_STAT_TIME_TX);
	chan_stat->time_rx = cpu_to_le64(cca_rx);
	qlink_utils_set_arr_bit(filled, QLINK_CHAN_STAT_TIME_RX);
	chan_stat->cca_busy = cpu_to_le64(cca_intf);
	qlink_utils_set_arr_bit(filled, QLINK_CHAN_STAT_CCA_BUSY);
	chan_stat->chan_noise = chan_noise;
	qlink_utils_set_arr_bit(filled, QLINK_CHAN_STAT_CHAN_NOISE);

	pr_debug("channel(%u) cca_try(%u) cca_intf(%u) noise(%d)\n",
		 chan->ic_ieee, cca_try, cca_intf, chan_noise);

	return ptr - data;
}

static u16 qlink_band_channels_info_fill(const struct ieee80211com *ic,
					 enum qlink_band band,
					 struct qlink_resp_band_info_get *reply,
					 u8 *buf_start)
{
	struct ieee80211_channel *chan;
	struct qlink_tlv_channel *qchan;
	unsigned int i;
	u32 flags;

	reply->band = band;
	reply->num_chans = 0;
	qchan = (struct qlink_tlv_channel *)buf_start;

	for (i = 0; i < ic->ic_nchans; ++i) {
		chan = &ic->ic_channels[i];

		if (isclr(ic->ic_chan_avail, chan->ic_ieee))
			continue;

		switch (band) {
		case QLINK_BAND_2GHZ:
			if (!QTN_CHAN_IS_2G(chan->ic_ieee))
				continue;
			break;
		case QLINK_BAND_5GHZ:
			if (!QTN_CHAN_IS_5G(chan->ic_ieee))
				continue;
			break;
		default:
			continue;
		}

		++reply->num_chans;
		flags = 0;

		if (isclr(ic->ic_chan_active_20, chan->ic_ieee))
			flags |= QLINK_CHAN_DISABLED;

		if (chan->ic_flags & IEEE80211_CHAN_PASSIVE)
			flags |= QLINK_CHAN_NO_IR;

		if (chan->ic_flags & IEEE80211_CHAN_DFS)
			flags |= QLINK_CHAN_RADAR;

		if (!(chan->ic_flags & IEEE80211_CHAN_HT40U))
			flags |= QLINK_CHAN_NO_HT40PLUS;

		if (!(chan->ic_flags & IEEE80211_CHAN_HT40D))
			flags |= QLINK_CHAN_NO_HT40MINUS;

		if (!(chan->ic_flags & IEEE80211_CHAN_OFDM))
			flags |= QLINK_CHAN_NO_OFDM;

		if (!(chan->ic_flags & IEEE80211_CHAN_VHT80))
			flags |= QLINK_CHAN_NO_80MHZ;

		if (!(chan->ic_flags & IEEE80211_CHAN_VHT160))
			flags |= QLINK_CHAN_NO_160MHZ;

		if (!(chan->ic_flags & IEEE80211_CHAN_HT20))
			flags |= QLINK_CHAN_NO_20MHZ;

		qchan->hdr.type = cpu_to_le16(QTN_TLV_ID_CHANNEL);
		qchan->hdr.len = cpu_to_le16(sizeof(*qchan) - sizeof(qchan->hdr));
		qchan->chan.hw_value = cpu_to_le16(chan->ic_ieee);
		qchan->chan.band = band;
		qchan->chan.center_freq = cpu_to_le16(chan->ic_freq);
		qchan->chan.flags = cpu_to_le32(flags);
		qchan->chan.max_antenna_gain = (u8)qdrv_wlan_get_tx_antenna_gain(ic->ic_unit);
		qchan->chan.max_reg_power = (u8)chan->ic_maxregpower;
		qchan->chan.max_power = (u8)chan->ic_maxregpower;
		qchan->chan.beacon_found = 0;
		qchan->chan.dfs_state = QLINK_DFS_USABLE;
		qchan->chan.dfs_cac_ms = 0;

		if (chan->ic_flags & IEEE80211_CHAN_DFS) {
			if (chan->ic_flags & IEEE80211_CHAN_RADAR)
				qchan->chan.dfs_state = QLINK_DFS_UNAVAILABLE;
			else if (chan->ic_flags & IEEE80211_CHAN_DFS_CAC_DONE)
				qchan->chan.dfs_state = QLINK_DFS_AVAILABLE;
			if ((chan->ic_flags & IEEE80211_CHAN_WEATHER) && qdrv_dfs_is_eu_region())
				qchan->chan.dfs_cac_ms =
					cpu_to_le32(jiffies_to_msecs(CAC_WEATHER_PERIOD_EU));
			else
				qchan->chan.dfs_cac_ms =
					cpu_to_le32(jiffies_to_msecs(CAC_PERIOD));
		}

		pr_debug("chan=%d flags=%#x max_pow=%u max_reg_pow=%u\n",
			 qchan->chan.hw_value, flags, qchan->chan.max_power,
			 qchan->chan.max_reg_power);

		++qchan;
	}

	return (u16)((u8 *)qchan - buf_start);
}

static u16 qlink_band_htcap_info_fill(const struct ieee80211com *ic,
				      u8 *buf_start)
{
	struct ieee80211_ht_cap *ht_cap_ie;
	struct ieee80211_htcap htcap;
	struct qlink_tlv_hdr *tlv;

	tlv = (struct qlink_tlv_hdr *)buf_start;
	tlv->type = cpu_to_le16(WLAN_EID_HT_CAPABILITY);
	tlv->len = cpu_to_le16(sizeof(*ht_cap_ie));
	ht_cap_ie = (struct ieee80211_ht_cap *)tlv->val;

	/* convert current ieee80211_htcap caps to ieee80211_ht_cap IE */
	memset(&htcap, 0, sizeof(htcap));
	qdrv_wlan_80211_cfg_ht(ic, &htcap, NULL, NULL);
	qlink_htcap_to_ht_cap(&htcap,
			      IEEE80211_HTF_LDPC_ENABLED | IEEE80211_HTF_STBC_ENABLED,
			      ht_cap_ie);

	return round_up(sizeof(*ht_cap_ie), QLINK_ALIGN) + sizeof(*tlv);
}

static u16 qlink_band_vhtcap_info_fill(struct qlink_server *qs,
				       const struct ieee80211com *ic,
				       u8 *buf_start)
{
	struct ieee80211_vht_cap *vht_cap_ie;
	struct ieee80211_vhtcap vhtcap;
	enum ieee80211_vht_nss tx_max_nss;
	enum ieee80211_vht_nss rx_max_nss;
	struct qlink_tlv_hdr *tlv;
	int mu_supp = 0;

	if (qtn_hw_mod_bf_is_supported_in_5g(qs->sp->hardware_options) && !qs->sp->fw_no_mu)
		mu_supp = 1;

	tlv = (struct qlink_tlv_hdr *)buf_start;
	tlv->type = cpu_to_le16(WLAN_EID_VHT_CAPABILITY);
	tlv->len = cpu_to_le16(sizeof(*vht_cap_ie));
	vht_cap_ie = (struct ieee80211_vht_cap *)tlv->val;

	/* convert current ieee80211_vhtcap caps to ieee80211_vht_cap IE */
	memset(&vhtcap, 0, sizeof(vhtcap));
	qdrv_wlan_80211_cfg_vht(ic, &vhtcap, NULL, &tx_max_nss, &rx_max_nss,
				0, ic->ic_opmode, mu_supp);
	qlink_vhtcap_to_vht_cap(&vhtcap, tx_max_nss, rx_max_nss,
				vhtcap.cap_flags, vht_cap_ie);

	return sizeof(*vht_cap_ie) + sizeof(*tlv);
}

static void qlink_cmd_mac_chan_stats(struct qlink_server *qs,
				     const struct qlink_cmd *cmdh)
{
	struct qlink_resp_get_chan_stats *reply;
	const struct ieee80211_channel *chan;
	struct qlink_cmd_get_chan_stats *cmd;
	u16 resp_size = sizeof(*reply);
	struct qlink_mac *mac;
	int ret = 0;

	reply = (struct qlink_resp_get_chan_stats *)qlink_prepare_reply(cmdh);
	if (!reply)
		return;

	if (cmdh->vifid != QLINK_VIFID_RSVD || cmdh->macid >= QTNF_MAC_NUM) {
		pr_err("invalid mac/if: %u %u\n", cmdh->macid, cmdh->vifid);
		ret = -EINVAL;
		goto out;
	}

	mac = &qs->maclist[cmdh->macid];
	if (!mac->dev || !mac->ic) {
		pr_err("MAC%u: not registered\n", cmdh->macid);
		ret = -ENOENT;
		goto out;
	}

	if (unlikely(le16_to_cpu(cmdh->mhdr.len) < sizeof(*cmd))) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmdh->mhdr.len));
		ret = -EINVAL;
		goto out;
	}

	cmd = (struct qlink_cmd_get_chan_stats *)cmdh;
	reply->chan_freq = cmd->channel_freq;

	chan = ieee80211_find_channel(mac->ic, le32_to_cpu(cmd->channel_freq), 0);
	if (!chan) {
		pr_debug("[MAC%u] channel not found freq=%u\n", cmdh->macid,
			 le32_to_cpu(cmd->channel_freq));
		goto out;
	}

	resp_size += qlink_mac_chan_stats_get(mac, chan, reply->info);

out:
	reply->rhdr.result = cpu_to_le16(qlink_utils_retval2q(ret));
	reply->rhdr.mhdr.len = cpu_to_le16(resp_size);
	qlink_xmit(reply, resp_size);
}

static void qlink_cmd_band_info_get(struct qlink_server *qs,
				    const struct qlink_cmd *chdr)
{
	const struct qlink_cmd_band_info_get *cmd;
	struct qlink_resp_band_info_get *resp;
	struct ieee80211com *ic;
	struct qlink_resp *rhdr;
	u16 resp_len = 0;
	int ret = 0;

	rhdr = qlink_prepare_reply(chdr);
	if (!rhdr)
		return;

	if (!qlink_is_macid_valid(chdr)) {
		pr_err("invalid mac/if: %u %u\n", chdr->macid, chdr->vifid);
		ret = -EINVAL;
		goto out;
	}

	if (!qs->maclist[chdr->macid].dev) {
		pr_err("phy %u is not registered\n", chdr->macid);
		ret = -ENOENT;
		goto out;
	}

	if (unlikely(le16_to_cpu(chdr->mhdr.len) < sizeof(*cmd))) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(chdr->mhdr.len));
		ret = -EINVAL;
		goto out;
	}

	ic = qdrv_get_ic(chdr->macid);
	if (!ic) {
		pr_err("internal error: cannot get ic\n");
		ret = -EINVAL;
		goto out;
	}

	cmd = (const struct qlink_cmd_band_info_get *)chdr;
	resp = (struct qlink_resp_band_info_get *)rhdr;

	resp_len += qlink_band_channels_info_fill(ic, cmd->band, resp,
						  resp->info);
	resp_len += qlink_band_htcap_info_fill(ic, resp->info + resp_len);

	if (cmd->band == QLINK_BAND_5GHZ) {
		if (ieee80211_swfeat_is_supported(SWFEAT_ID_VHT, 1))
			resp_len += qlink_band_vhtcap_info_fill(qs, ic, resp->info + resp_len);
	}

out:
	resp_len += sizeof(*resp);
	rhdr->mhdr.len = cpu_to_le16(resp_len);
	rhdr->result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(rhdr, resp_len);
}

static void qlink_cmd_chan_switch(struct qlink_server *qs, const struct qlink_cmd *cmd)
{
	struct ieee80211_channel *newchan;
	struct ieee80211com *ic;
	struct qlink_cmd_chan_switch *cmd_params;
	struct qlink_resp *reply;
	struct qlink_mac *mac;
	u16 newchan_ieee;
	u8 csa_count;
	u8 block_tx;
	u64 flags;
	int ret;

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	if (unlikely(le16_to_cpu(cmd->mhdr.len) < sizeof(*cmd_params))) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmd->mhdr.len));
		reply->result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
		goto out;
	}

	if (unlikely(!qlink_check_mac_if(cmd))) {
		pr_err("invalid mac/vif: %u/%u\n", cmd->macid, cmd->vifid);
		reply->result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
		goto out;
	}

	ic = qdrv_get_ic(cmd->macid);
	if (unlikely(!ic)) {
		pr_err("internal error: cannot get ic\n");
		reply->result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
		goto out;
	}

	mac = &qs->maclist[cmd->macid];

	cmd_params = (struct qlink_cmd_chan_switch *)cmd;
	newchan_ieee = le16_to_cpu(cmd_params->channel.chan.hw_value);
	csa_count = cmd_params->beacon_count;
	flags = le64_to_cpu(cmd_params->flags);

	if (flags & QLINK_CHAN_SW_BLOCK_TX)
		block_tx = IEEE80211_CSA_MUST_STOP_TX;
	else
		block_tx = IEEE80211_CSA_CAN_STOP_TX;

	newchan = findchannel(ic, newchan_ieee, ic->ic_des_mode);
	if (!newchan) {
		pr_err("could not get channel by ieeee (%u)\n", newchan_ieee);
		reply->result = cpu_to_le16(QLINK_CMD_RESULT_ENOTFOUND);
		goto out;
	}

	if (ic->ic_chan_compare_equality(ic, ic->ic_curchan, newchan)) {
		pr_err("channel (%u) is already set\n", newchan_ieee);
		reply->result = cpu_to_le16(QLINK_CMD_RESULT_EALREADY);
		goto out;
	}

	ret = ieee80211_enter_csa(ic, newchan, NULL, IEEE80211_CSW_REASON_CSA,
		csa_count, block_tx, IEEE80211_CSA_F_BEACON | IEEE80211_CSA_F_ACTION);
	if (ret == -EBUSY) {
		if (ic->ic_csa_chan != newchan) {
			pr_err("CSA is already active\n");
			reply->result = cpu_to_le16(QLINK_CMD_RESULT_EALREADY);
		}
	} else if (ret) {
		pr_err("csa enter failed\n");
		reply->result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
	}

out:
	qlink_xmit(reply, le16_to_cpu(reply->mhdr.len));
}

static void qlink_cmd_chan_get(struct qlink_server *qs,
			       const struct qlink_cmd *cmd)
{
	struct qlink_resp *resph;
	struct qlink_resp_channel_get *resp;
	struct ieee80211vap *vap = NULL;
	int ret = 0;

	resph = qlink_prepare_reply(cmd);
	if (!resph)
		return;

	if (unlikely(!qlink_check_mac_if(cmd))) {
		pr_err("invalid mac/vif: %u/%u\n", cmd->macid, cmd->vifid);
		ret = -EINVAL;
		goto out;
	}

	vap = qs->maclist[cmd->macid].bss[cmd->vifid].vap;
	if (!vap) {
		struct ieee80211com *ic = qdrv_get_ic(cmd->macid);

		if (ic)
			vap = TAILQ_FIRST(&ic->ic_vaps);
	}

	if (!vap) {
		ret = -EINVAL;
		goto out;
	}

	resp = (struct qlink_resp_channel_get *)resph;
	resph->mhdr.len = cpu_to_le16(sizeof(*resp));

	if (qlink_vap_chandef_fill(vap, &resp->chan)) {
		ret = -EINVAL;
		goto out;
	}

	qs->maclist[cmd->macid].host_chandef = resp->chan;

	pr_info("VIF%u.%u: freq=%u bw=%u\n", cmd->macid, cmd->vifid,
		resp->chan.center_freq1, resp->chan.width);

out:
	resph->result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(resph, sizeof(*resp));
}

static void qlink_cmd_phy_params_set(struct qlink_server *qs,
				     const struct qlink_cmd *cmd)
{
	struct qlink_resp *reply;
	int ret;

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	if (!qlink_check_mac_if(cmd)) {
		pr_err("invalid mac/if: %u %u\n", cmd->macid, cmd->vifid);
		ret = -EINVAL;
		goto out;
	}

	if (!qs->maclist[cmd->macid].dev) {
		pr_err("phy %u is not registered\n", cmd->macid);
		ret = -ENOENT;
		goto out;
	}

	if (unlikely(le16_to_cpu(cmd->mhdr.len) < sizeof(*cmd))) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmd->mhdr.len));
		ret = -EINVAL;
		goto out;
	}

	ret = qlink_phy_params_set(qs, cmd);

out:
	reply->result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(reply, le16_to_cpu(reply->mhdr.len));
}

static void qlink_cmd_add_key(struct qlink_server *qs, const struct qlink_cmd *cmd)
{
	const struct qlink_cmd_add_key *cmd_params;
	struct qlink_resp *reply;
	struct qlink_bss *bss;
	const struct qlink_tlv_hdr *ptlv;
	int payload_len;
	int vlen;
	int type;
	const u8 *key = NULL;
	int key_len = 0;
	const u8 *seq = NULL;
	int seq_len = 0;
	struct ieee80211req_key wk;
	u32 cipher;
	int ret;
	u8 local_mac[IEEE80211_ADDR_LEN];
	u16 vlanid = 0;

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	if (!qlink_check_mac_if(cmd)) {
		pr_err("invalid mac/if: %u %u\n", cmd->macid, cmd->vifid);
		ret = -EINVAL;
		goto out;
	}

	if (unlikely(le16_to_cpu(cmd->mhdr.len) < sizeof(*cmd_params))) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmd->mhdr.len));
		ret = -EINVAL;
		goto out;
	}

	cmd_params = (const struct qlink_cmd_add_key *)cmd;
	payload_len = le16_to_cpu(cmd->mhdr.len) - sizeof(*cmd_params);

	bss = &qs->maclist[cmd->macid].bss[cmd->vifid];
	if (!bss_has_status(bss, QLINK_BSS_ADDED)) {
		pr_err("interface wifi %d/%d not registered\n", cmd->macid, cmd->vifid);
		ret = -ENODEV;
		goto out;
	}

	if (cmd_params->pairwise && cmd_params->key_index >= IEEE80211_WEP_NKID) {
		pr_warn("key index %d is out of bounds\n", cmd_params->key_index);
		ret = -ENOENT;
		goto out;
	}

	qlink_for_each_tlv(ptlv, cmd_params->key_data, payload_len) {
		vlen = le16_to_cpu(ptlv->len);
		type = le16_to_cpu(ptlv->type);

		switch (type) {
		case QTN_TLV_ID_KEY:
			if (vlen > sizeof(wk.ik_keydata)) {
				pr_warn("QTN_TLV_ID_KEY length (%d) out of range\n", vlen);
				break;
			}
			key = ptlv->val;
			key_len = vlen;
			break;
		case QTN_TLV_ID_SEQ:
			if (vlen > sizeof(wk.ik_keyrsc)) {
				pr_warn("QTN_TLV_ID_SEQ length (%d) out of range\n", vlen);
				break;
			}
			seq = ptlv->val;
			seq_len = vlen;
			break;
		default:
			pr_debug("unused TLV ID: 0x%x\n", type);
			break;
		}
	}

	if ((key == NULL) || (key_len == 0)) {
		pr_err("key not found in ADD_KEY parameters\n");
		ret = -EINVAL;
		goto out;
	}

	if (qlink_cipher_suite2drv(get_unaligned_le32(&cmd_params->cipher), &cipher) != 0) {
		pr_err("cipher %x not supported\n", get_unaligned_le32(&cmd_params->cipher));
		ret = -EOPNOTSUPP;
		goto out;
	}

	/* BIP key for PMF broadcast frames: not handled by WLAN */
	if (cmd_params->key_index >= IEEE80211_WEP_NKID) {
		int key_idx = cmd_params->key_index - IEEE80211_WEP_NKID;

		if (cipher != IEEE80211_CIPHER_AES_CMAC) {
			pr_err("Unsupported cipher for broadcast packets: %u\n", cipher);
			ret = -EINVAL;
			goto out;
		}

		if (seq_len != QLINK_BIP_IPN_LEN) {
			pr_err("Invalid IPN length for BIP packets: %u\n", seq_len);
			ret = -EINVAL;
			goto out;
		}

		if (key_idx >= QLINK_NUM_BIP_KEYS) {
			pr_err("Invalid IGTK key index: %u\n", cmd_params->key_index);
			ret = -EINVAL;
			goto out;
		}

		if (bss->igtk[key_idx]) {
			pr_err("IGTK key %u already added\n", cmd_params->key_index);
			ret = -EINVAL;
			goto out;
		}

		pr_debug("add IGTK key %u: wifi=%u/%u cipher=%u seq_len=%u seq[%pM]\n",
			 cmd_params->key_index, cmd->macid, cmd->vifid,
			 cipher, seq_len, seq);

		bss->igtk[key_idx] = crypto_alloc_cipher("aes", 0, CRYPTO_ALG_ASYNC);
		if (IS_ERR(bss->igtk[key_idx])) {
			pr_err("failed to allocate AES cipher for IGTK key %u\n",
			       cmd_params->key_index);
			bss->igtk[key_idx] = NULL;
			ret = -EINVAL;
			goto out;
		}

		ret = crypto_cipher_setkey(bss->igtk[key_idx], key, key_len);
		if (ret < 0) {
			pr_err("failed to set AES IGTK key %u\n",
			       cmd_params->key_index);
			crypto_free_cipher(bss->igtk[key_idx]);
			bss->igtk[key_idx] = NULL;
			ret = -EINVAL;
			goto out;
		}

		bss->vap->app_filter |=
			IEEE80211_FILTER_TYPE_DISASSOC | IEEE80211_FILTER_TYPE_DEAUTH;
		memcpy(bss->igtk_ipn[key_idx], seq, seq_len);
		ret = QLINK_CMD_RESULT_OK;
		goto out;
	}

	memcpy(local_mac, cmd_params->addr, sizeof(local_mac));
	memset(&wk, 0, sizeof(wk));
	wk.ik_type = cipher;
	wk.ik_flags = IEEE80211_KEY_RECV | IEEE80211_KEY_XMIT;
	if (is_broadcast_ether_addr(local_mac) || (!cmd_params->pairwise)) {
		memset(wk.ik_macaddr, 0xff, IEEE80211_ADDR_LEN);
		wk.ik_keyix = cmd_params->key_index;
		wk.ik_flags |= IEEE80211_KEY_DEFAULT | IEEE80211_KEY_GROUP;
	} else {
		memcpy(wk.ik_macaddr, local_mac, IEEE80211_ADDR_LEN);
		wk.ik_keyix = IEEE80211_KEYIX_NONE;
	}

	vlanid = get_unaligned_le16(&cmd_params->vlanid);
	if (vlanid) {
		memset(wk.ik_macaddr, 0xff, IEEE80211_ADDR_LEN);
		wk.ik_vlan = vlanid;
		wk.ik_flags |= (IEEE80211_KEY_VLANGROUP | IEEE80211_KEY_GROUP);
	}

	if (wk.ik_flags & IEEE80211_KEY_GROUP)
		pr_info("add group key %u: wifi=%u/%u cipher=%u vlanid=%u\n",
			cmd_params->key_index, cmd->macid, cmd->vifid, cipher, vlanid);
	else
		pr_info("add key %u: wifi=%u/%u cipher=%u mac_addr=%pM\n",
			cmd_params->key_index, cmd->macid, cmd->vifid, cipher, local_mac);


	wk.ik_keylen = key_len;
	memcpy(wk.ik_keydata, key, key_len);

	ret = qlink_wifi_setpriv(bss->dev, IEEE80211_IOCTL_SETKEY, &wk, sizeof(wk));
	if (ret == 1) {
		/* add/del key operations return 1 on success */
		ret = QLINK_CMD_RESULT_OK;
	} else {
		pr_err("failed to add key %u\n", cmd_params->key_index);
		goto out;
	}

out:
	reply->result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(reply, le16_to_cpu(reply->mhdr.len));
}

static void qlink_cmd_del_key(struct qlink_server *qs, const struct qlink_cmd *cmd)
{
	struct qlink_cmd_del_key *cmd_params;
	struct qlink_resp *reply;
	struct qlink_bss *bss;
	struct ieee80211req_del_key wk;
	int ret;
	u8 local_mac[IEEE80211_ADDR_LEN];

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	if (!qlink_check_mac_if(cmd)) {
		pr_err("invalid mac/if: %u %u\n", cmd->macid, cmd->vifid);
		ret = -EINVAL;
		goto out;
	}

	if (unlikely(le16_to_cpu(cmd->mhdr.len) < sizeof(*cmd_params))) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmd->mhdr.len));
		ret = -EINVAL;
		goto out;
	}

	cmd_params = (struct qlink_cmd_del_key *)cmd;

	bss = &qs->maclist[cmd->macid].bss[cmd->vifid];
	if (!bss_has_status(bss, QLINK_BSS_ADDED)) {
		pr_err("interface wifi %d/%d not registered\n", cmd->macid, cmd->vifid);
		ret = -ENODEV;
		goto out;
	}

	/* BIP key for PMF broadcast frames: not handled by WLAN */
	if (cmd_params->key_index >= IEEE80211_WEP_NKID) {
		int key_idx = cmd_params->key_index - IEEE80211_WEP_NKID;

		if (key_idx >= QLINK_NUM_BIP_KEYS) {
			pr_err("Invalid IGTK key index: %u\n", cmd_params->key_index);
			ret = -EINVAL;
			goto out;
		}

		if (!bss->igtk[key_idx]) {
			pr_err("no IGTK key %u\n", cmd_params->key_index);
			ret = -ENOENT;
			goto out;
		}

		pr_debug("delete IGTK key %u: wifi %u/%u\n",
			 cmd_params->key_index, cmd->macid, cmd->vifid);

		crypto_free_cipher(bss->igtk[key_idx]);
		bss->igtk[key_idx] = NULL;
		bss->vap->app_filter &=
			~(IEEE80211_FILTER_TYPE_DISASSOC | IEEE80211_FILTER_TYPE_DEAUTH);
		memset(bss->igtk_ipn[key_idx], 0, sizeof(bss->igtk_ipn[key_idx]));
		ret = QLINK_CMD_RESULT_OK;

		goto out;
	}

	memcpy(local_mac, cmd_params->addr, sizeof(local_mac));
	memset(&wk, 0, sizeof(wk));

	if (is_broadcast_ether_addr(local_mac) || (!cmd_params->pairwise)) {
		memset(wk.idk_macaddr, 0xff, IEEE80211_ADDR_LEN);
		wk.idk_keyix = cmd_params->key_index;
	} else {
		memcpy(wk.idk_macaddr, local_mac, IEEE80211_ADDR_LEN);
		wk.idk_keyix = IEEE80211_KEYIX_NONE;
	}

	pr_info("delete key %u: wifi %u/%u\n", cmd_params->key_index, cmd->macid, cmd->vifid);

	ret = qlink_wifi_setpriv(bss->dev, IEEE80211_IOCTL_DELKEY, &wk, sizeof(wk));
	if (ret == 1) {
		/* add/del key operations return 1 on success */
		ret = QLINK_CMD_RESULT_OK;
	} else {
		pr_err("failed to delete key %u\n", cmd_params->key_index);
		goto out;
	}

out:
	reply->result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(reply, le16_to_cpu(reply->mhdr.len));
}

static void qlink_cmd_set_def_key(struct qlink_server *qs, const struct qlink_cmd *cmd)
{
	struct qlink_cmd_set_def_key *cmd_params;
	struct qlink_resp *reply;
	struct qlink_bss *bss;
	int ret;

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	if (!qlink_check_mac_if(cmd)) {
		pr_err("invalid mac/if: %u %u\n", cmd->macid, cmd->vifid);
		ret = -EINVAL;
		goto out;
	}

	if (unlikely(le16_to_cpu(cmd->mhdr.len) < sizeof(*cmd_params))) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmd->mhdr.len));
		ret = -EINVAL;
		goto out;
	}

	cmd_params = (struct qlink_cmd_set_def_key *)cmd;

	bss = &qs->maclist[cmd->macid].bss[cmd->vifid];
	if (!bss_has_status(bss, QLINK_BSS_ADDED)) {
		pr_err("interface wifi %d/%d not registered\n", cmd->macid, cmd->vifid);
		ret = -ENODEV;
		goto out;
	}

	pr_info("add default key %u: wifi=%u/%u mcast=%u ucast=%u\n",
		cmd_params->key_index, cmd->macid, cmd->vifid,
		cmd_params->multicast, cmd_params->unicast);

	/* driver does not support setting default key but return OK */
	ret = 0;

out:
	reply->result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(reply, le16_to_cpu(reply->mhdr.len));
}

static void qlink_cmd_set_def_mgmt_key(struct qlink_server *qs, const struct qlink_cmd *cmd)
{
	struct qlink_cmd_set_def_mgmt_key *cmd_params;
	struct qlink_resp *reply;
	struct qlink_bss *bss;
	int ret;

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	if (!qlink_check_mac_if(cmd)) {
		pr_err("invalid mac/if: %u %u\n", cmd->macid, cmd->vifid);
		ret = -EINVAL;
		goto out;
	}

	if (unlikely(le16_to_cpu(cmd->mhdr.len) < sizeof(*cmd_params))) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmd->mhdr.len));
		ret = -EINVAL;
		goto out;
	}

	cmd_params = (struct qlink_cmd_set_def_mgmt_key *)cmd;

	bss = &qs->maclist[cmd->macid].bss[cmd->vifid];
	if (!bss_has_status(bss, QLINK_BSS_ADDED)) {
		pr_err("interface wifi %d/%d not registered\n", cmd->macid, cmd->vifid);
		ret = -ENODEV;
		goto out;
	}

	pr_info("add default mgmt key %u: wifi=%u/%u\n",
		cmd_params->key_index, cmd->macid, cmd->vifid);

	/* driver does not support setting default mgmt key but return OK */
	ret = 0;

out:
	reply->result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(reply, le16_to_cpu(reply->mhdr.len));
}

static int qlink_change_sta_flags(struct qlink_server *qs, int mac_id, int if_idx,
				  u32 sta_flags_set, u32 sta_flags_mask, const u8 *sta_addr)
{
	struct ieee80211_node *ni;
	struct qlink_mac *mac;
	struct qlink_bss *bss;

	mac = &qs->maclist[mac_id];
	bss = &mac->bss[if_idx];

	pr_info("change STA %pM: flags=%x mask=%x\n", sta_addr, sta_flags_set, sta_flags_mask);

	if (sta_flags_mask & QLINK_STA_FLAG_AUTHORIZED) {
		if (bss->mode == QLINK_IFTYPE_STATION) {
			bss_clr_status(bss, QLINK_BSS_CONNECTING);
			bss_clr_status(bss, QLINK_BSS_OWE_PROCESSING);
			bss_set_status(bss, QLINK_BSS_RUNNING);
			ni = bss->vap->iv_bss;
			if (sta_flags_set & QLINK_STA_FLAG_AUTHORIZED)
				ieee80211_node_authorize(ni);
			else
				ieee80211_node_unauthorize(ni);
		} else if (bss->mode == QLINK_IFTYPE_AP) {
			ni = ieee80211_find_node(&mac->ic->ic_sta, sta_addr);
			if (sta_flags_set & QLINK_STA_FLAG_AUTHORIZED) {
				if (ni) {
					ieee80211_node_authorize(ni);
					ieee80211_free_node(ni);
				} else {
					pr_err("node lookup failure\n");
					return -1;
				}
			} else {
				if (ni) {
					ieee80211_node_unauthorize(ni);
					ieee80211_free_node(ni);
				}
				/* Suppress error messages when trying to
				 * unauthorize STA that has already been
				 * deauthenticated
				 */
			}
		} else {
			return -1;
		}
	}

	return 0;
}

static void qlink_cmd_change_station(struct qlink_server *qs, const struct qlink_cmd *cmd)
{
	struct qlink_cmd_change_sta *cmd_params;
	struct qlink_resp *reply;
	enum qlink_iface_type iftype;
	struct qlink_mac *mac;
	struct qlink_bss *bss;
	u32 sta_flags_set;
	u32 sta_flags_mask;
	u16 vlanid;

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	if (!qlink_check_mac_if(cmd)) {
		pr_err("invalid mac/if: %u %u\n", cmd->macid, cmd->vifid);
		goto out_err;
	}

	if (unlikely(le16_to_cpu(cmd->mhdr.len) < sizeof(*cmd_params))) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmd->mhdr.len));
		goto out_err;
	}

	mac = &qs->maclist[cmd->macid];
	bss = &mac->bss[cmd->vifid];
	if (!bss_has_status(bss, QLINK_BSS_ADDED)) {
		pr_err("interface wifi %d/%d not registered\n", cmd->macid, cmd->vifid);
		goto out_err;
	}

	cmd_params = (struct qlink_cmd_change_sta *)cmd;

	iftype = le16_to_cpu(cmd_params->if_type);
	vlanid = le16_to_cpu(cmd_params->vlanid);
	sta_flags_set = le32_to_cpu(cmd_params->flag_update.value);
	sta_flags_mask = le32_to_cpu(cmd_params->flag_update.mask);

	pr_info("RC: change STA %pM\n", cmd_params->sta_addr);

	switch (iftype) {
	case QLINK_IFTYPE_AP:
	case QLINK_IFTYPE_STATION:
		if (qlink_change_sta_flags(qs, cmd->macid, cmd->vifid,
					   sta_flags_set, sta_flags_mask, cmd_params->sta_addr))
			goto out_err;
		break;
	case QLINK_IFTYPE_AP_VLAN:
		pr_err("AP_VLAN interface type is not implemented\n");
		reply->result = cpu_to_le16(QLINK_CMD_RESULT_ENOTSUPP);
		break;
	default:
		pr_err("unexpected if_type %u\n", iftype);
		goto out_err;
	}

	qlink_xmit(reply, le16_to_cpu(reply->mhdr.len));
	return;

out_err:
	reply->result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
	qlink_xmit(reply, le16_to_cpu(reply->mhdr.len));

}

static void qlink_cmd_del_station(struct qlink_server *qs, const struct qlink_cmd *cmd)
{
	struct qlink_cmd_del_sta *params;
	struct qlink_bss *bss;
	struct qlink_resp *reply;
	u8 local_mac[IEEE80211_ADDR_LEN];

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	if (!qlink_check_mac_if(cmd)) {
		reply->result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
		goto out;
	}

	if (le16_to_cpu(cmd->mhdr.len) < sizeof(*params)) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmd->mhdr.len));
		reply->result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
		goto out;
	}

	params = (struct qlink_cmd_del_sta *)cmd;
	bss = &qs->maclist[cmd->macid].bss[cmd->vifid];

	/* BSS is flushed before starting so we do not check 'started' flag */
	if (!bss_has_status(bss, QLINK_BSS_ADDED)) {
		reply->result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
		goto out;
	}

	memcpy(local_mac, params->sta_addr, sizeof(local_mac));
	/* host passes ff's in sta_addr to indicate flush action */
	if (is_broadcast_ether_addr(local_mac)) {
		if (qlink_wifi_sta_deauth(bss->dev, local_mac,
					  IEEE80211_REASON_AUTH_LEAVE) != 0) {
			reply->result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
		}
	} else if (params->subtype == QLINK_STA_DISASSOC) {
		if (qlink_wifi_sta_disassoc(bss->dev, local_mac,
					    get_unaligned_le16(&params->reason_code)) != 0) {
			reply->result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
		}
	} else if (params->subtype == QLINK_STA_DEAUTH) {
		if (qlink_wifi_sta_deauth(bss->dev, local_mac,
					  get_unaligned_le16(&params->reason_code)) != 0) {
			reply->result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
		}
	} else {
		reply->result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
	}
	if (reply->result == cpu_to_le16(QLINK_CMD_RESULT_INVALID))
		pr_err("failed to delete STA %pM\n", params->sta_addr);
out:
	qlink_xmit(reply, le16_to_cpu(reply->mhdr.len));
}

static void qlink_cmd_scan(struct qlink_server *qs, const struct qlink_cmd *cmdh)
{
	struct qlink_resp *reply;
	const struct qlink_cmd_scan *cmd;
	struct ieee80211_scan_state *ss;
	struct qlink_bss *bss;
	int payload_len;
	const struct qlink_tlv_hdr *ptlv;
	uint16_t vlen;
	struct qlink_tlv_ie_set *ie_set;
	struct qlink_channel *channel;
	struct qlink_random_mac_addr *randmac;
	int ret;
	int scan_flags = IEEE80211_SCAN_ACTIVE | IEEE80211_SCAN_ONCE | IEEE80211_SCAN_NOPICK;
	u16 pick_flags = 0;
	struct qlink_scan_freq_list freq_list;

	reply = qlink_prepare_reply(cmdh);
	if (!reply)
		return;

	if (cmdh->vifid != QLINK_VIFID_RSVD || cmdh->macid >= QTNF_MAC_NUM) {
		pr_err("invalid mac/if: %u %u\n", cmdh->macid, cmdh->vifid);
		ret = -EINVAL;
		goto out;
	}

	if (le16_to_cpu(cmdh->mhdr.len) < sizeof(*cmd)) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmdh->mhdr.len));
		ret = -EINVAL;
		goto out;
	}

	bss = &qs->maclist[cmdh->macid].bss[0];
	if (unlikely(!bss_has_status(bss, QLINK_BSS_ADDED))) {
		pr_err("[MAC%u] primary bss is not added\n", cmdh->macid);
		ret = -ENOENT;
		goto out;
	}

	if (bss_has_status(bss, QLINK_BSS_CONNECTING)) {
		pr_warn("[MAC%u] ignore SCAN while connecting\n", cmdh->macid);
		ret = -EBUSY;
		goto out;
	}

	ret = qlink_wifi_scan_ssid_clear(bss->vap->iv_dev);
	if (ret)
		goto out;

	memset(&freq_list, 0, sizeof(freq_list));

	cmd = (const struct qlink_cmd_scan *)cmdh;
	payload_len = le16_to_cpu(cmdh->mhdr.len) - sizeof(*cmd);

	qlink_for_each_tlv(ptlv, cmd->var_info, payload_len) {
		vlen = le16_to_cpu(ptlv->len);

		switch (le16_to_cpu(ptlv->type)) {
		case WLAN_EID_SSID:
			if (vlen > IEEE80211_NWID_LEN) {
				pr_err("WLAN_EID_SSID bad length %d\n", vlen);
				ret = -EINVAL;
				goto out;
			}

			if (!vlen)
				break;

			pr_debug("WLAN_EID_SSID:\n");
			print_hex_dump(KERN_DEBUG, "SSID: ", DUMP_PREFIX_NONE,
					16, 1, ptlv->val, vlen, 1);

			ret = qlink_wifi_scan_ssid_add(bss->vap->iv_dev, (u8 *)ptlv->val, vlen);
			if (ret) {
				pr_warn("[MAC%u] SSID entry skipped\n", cmdh->macid);
				print_hex_dump(KERN_WARNING, "SSID: ", DUMP_PREFIX_NONE,
						16, 1, ptlv->val, vlen, 1);
			}
			break;
		case QTN_TLV_ID_IE_SET:
			ie_set = (struct qlink_tlv_ie_set *)ptlv;
			qlink_dump_ies(ie_set->ie_data,
				vlen - (sizeof(*ie_set) - sizeof(ie_set->hdr)), 1);
			ret = qlink_cmd_append_ie_do(bss, ie_set);
			if (ret) {
				pr_err("%s: QTN_TLV_ID_IE_SET error %d\n",
				       bss->dev->name, ret);
				ret = -EINVAL;
				goto out;
			}
			break;
		case QTN_TLV_ID_CHANNEL:
			if (vlen != sizeof(*channel)) {
				pr_err("QTN_TLV_ID_CHANNEL invalid length (%d)\n", vlen);
				ret = -EINVAL;
				goto out;
			}

			channel = (struct qlink_channel *)ptlv->val;

			if (freq_list.n_freqs >= ARRAY_SIZE(freq_list.freqs)) {
				pr_warn("[MAC%u] channel skipped %u\n", cmdh->macid,
					get_unaligned_le16(&channel->hw_value));
				break;
			}

			freq_list.freqs[freq_list.n_freqs] =
				get_unaligned_le16(&channel->center_freq);
			pr_debug("QTN_CHANNEL_SCAN freqs[%u] = %u\n",
				freq_list.n_freqs, freq_list.freqs[freq_list.n_freqs]);

			++freq_list.n_freqs;
			break;
		case QTN_TLV_ID_RANDOM_MAC_ADDR:
			if (vlen != sizeof(*randmac)) {
				pr_err("QTN_TLV_ID_RANDOM_MAC_ADDR invalid length (%d)\n", vlen);
				ret = -EINVAL;
				goto out;
			}

			randmac = (struct qlink_random_mac_addr *)ptlv->val;
			scan_flags |= IEEE80211_SCAN_ACTIVE_RANDOM;
			pr_debug("random addr=%pM, mask=%pM\n",
				randmac->mac_addr, randmac->mac_addr_mask);
			break;
		default:
			pr_info("unknown TLV ID received: 0x%x\n", le16_to_cpu(ptlv->type));
			break;
		}
	}

	ret = qlink_wifi_scan_freq_set(bss->vap->iv_dev,
				(struct ieee80211_scan_freqs *)&freq_list);
	if (ret)
		goto out;

	/* If host asked for a SCAN, then it assumes interface is UP.
	 * Make sure it is.
	 */
	qlink_if_up(bss->dev);

	/* Use background scan for associated station */
	if (bss->vap->iv_opmode == IEEE80211_M_STA &&
	    bss->vap->iv_state == IEEE80211_S_RUN) {
		scan_flags |= IEEE80211_SCAN_QTN_BGSCAN;
		pick_flags = IEEE80211_BGSCAN_MODE_FAKE_PS << IEEE80211_PICK_BG_MODE_SHIFT;
	}

	/* Always flush local cache so that we will report only new entries to host */
	scan_flags |= IEEE80211_SCAN_FLUSH;

	ss = bss->vap->iv_ic->ic_scan;
	IEEE80211_ADDR_COPY(ss->ss_bssid, bss->dev->broadcast);
	ss->is_scan_valid = 1;
	ss->ss_pick_flags = pick_flags;
	ss->ss_dwell_active_override = IEEE80211_TU_TO_MS(le16_to_cpu(cmd->active_dwell));
	ss->ss_dwell_passive_override = IEEE80211_TU_TO_MS(le16_to_cpu(cmd->passive_dwell));
	ss->ss_sample_duration_override = IEEE80211_TU_TO_MS(le16_to_cpu(cmd->sample_duration));

	ieee80211_start_scan(bss->vap, scan_flags, IEEE80211_SCAN_FOREVER,
				bss->vap->iv_des_nssid, bss->vap->iv_des_ssid);

	if (!bss_has_status(bss, QLINK_BSS_STARTED))
		ieee80211_new_state(bss->vap, IEEE80211_S_SCAN, 0);

	bss_set_status(bss, QLINK_BSS_SCANNING);

out:
	reply->result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(reply, le16_to_cpu(reply->mhdr.len));
}

static void qlink_bss_sta_conf_apply_overrides(struct qlink_bss *bss,
					      u32 flags,
					      int is_24g_band,
					      const struct ieee80211_ht_cap *ht_capa,
					      const struct ieee80211_ht_cap *ht_capa_mask,
					      const struct ieee80211_vht_cap *vht_capa,
					      const struct ieee80211_vht_cap *vht_capa_mask)
{
	struct ieee80211com *ic = bss->vap->iv_ic;
	bool ht_enabled = !(flags & QLINK_STA_CONNECT_DISABLE_HT);
	bool vht_enabled = !(flags & QLINK_STA_CONNECT_DISABLE_VHT);
	struct ieee80211_vht_cap vht_conf;
	struct ieee80211_ht_cap ht_conf;
	int sgi_20 = 0;
	int sgi_40 = 0;
	int sgi_80 = 0;
	int ldpc = 0;
	int stbc = 0;
	int ret;

	/*
	 * For STA mode we always configure device to max BW allowed for a
	 * specified HT/VHT config. It is a maximum capabilities advertised by a
	 * STA; operational BW is selected by AP.
	 */
	unsigned int bandwidth = BW_HT20;

	if (ht_enabled) {
		/* get current HT caps, merge with HT overrides from host, apply HT caps */
		qlink_htcap_to_ht_cap(&ic->ic_htcap, bss->vap->iv_ht_flags,
				      &ht_conf);
		qlink_merge_bits(&ht_conf, ht_capa, ht_capa_mask, sizeof(ht_conf));
		qlink_bss_ht_conf_apply(bss, &ht_conf, &sgi_20, &sgi_40,
					&ldpc, &stbc);

		if (ic->ic_htcap.cap & IEEE80211_HT_CAP_SUP_WIDTH_20_40)
			bandwidth = BW_HT40;
	} else {
		vht_enabled = 0;
	}

	if (vht_enabled) {
		/* get current VHT caps, merge with overrides from host, apply VHT caps */
		if (is_24g_band)
			qlink_vhtcap_to_vht_cap(&ic->ic_vhtcap_24g,
						ic->ic_vht_nss_cap_24g,
						ic->ic_vht_rx_nss_cap_24g,
						bss->vap->iv_vht_flags,
						&vht_conf);
		else
			qlink_vhtcap_to_vht_cap(&ic->ic_vhtcap,
						ic->ic_vht_nss_cap,
						ic->ic_vht_rx_nss_cap,
						bss->vap->iv_vht_flags,
						&vht_conf);

		qlink_merge_bits(&vht_conf, vht_capa, vht_capa_mask, sizeof(vht_conf));
		qlink_bss_vht_conf_apply(bss, &vht_conf,
					 &sgi_80, &ldpc, &stbc, is_24g_band);

		if (!is_24g_band)
			bandwidth = BW_HT80;
	}

	ret = qlink_bss_global_conf_apply(bss,
					  sgi_20 | sgi_40 | sgi_80,
					  ldpc, stbc);
	if (ret)
		pr_warn("%s: failed to apply global HT/VHT configuration: %d\n",
			bss->dev->name, ret);

	pr_info("%s: max device bandwidth (%d)\n", bss->dev->name, bandwidth);

	ret = qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_MAX_DEVICE_BW, bandwidth);
	if (ret)
		pr_warn("%s: failed to set max bw to %d: %d\n",
			bss->dev->name, bandwidth, ret);

	if (ht_enabled) {
		qlink_htcap_to_ht_cap(&ic->ic_htcap, bss->vap->iv_ht_flags,
				      &ht_conf);
		qlink_dump_ht_caps(&ht_conf);
	}

	if (vht_enabled) {
		if (is_24g_band)
			qlink_vhtcap_to_vht_cap(&ic->ic_vhtcap_24g,
						ic->ic_vht_nss_cap_24g,
						ic->ic_vht_rx_nss_cap_24g,
						bss->vap->iv_vht_flags,
						&vht_conf);
		else
			qlink_vhtcap_to_vht_cap(&ic->ic_vhtcap,
						ic->ic_vht_nss_cap,
						ic->ic_vht_rx_nss_cap,
						bss->vap->iv_vht_flags,
						&vht_conf);
		qlink_dump_vht_caps(&vht_conf);
	}
}

static void qlink_cmd_connect(struct qlink_server *qs, const struct qlink_cmd *cmd)
{
	struct qlink_cmd_connect *cmd_params;
	const struct qlink_tlv_ie_set *ie_set;
	struct qlink_channel *qchan = NULL;
	struct qlink_resp *reply;
	struct qlink_bss *bss;
	uint16_t vlen;
	const struct qlink_tlv_hdr *ptlv;
	uint16_t payload_len;
	int ret = 0;
	unsigned int chan_ieee = 0;

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	if (!qlink_check_mac_if(cmd)) {
		reply->result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
		goto out;
	}

	if (le16_to_cpu(cmd->mhdr.len) < sizeof(*cmd_params)) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmd->mhdr.len));
		reply->result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
		goto out;
	}

	cmd_params = (struct qlink_cmd_connect *)cmd;

	bss = &qs->maclist[cmd->macid].bss[cmd->vifid];
	if (!bss_has_status(bss, QLINK_BSS_ADDED) || (bss->mode != QLINK_IFTYPE_STATION)) {
		reply->result = cpu_to_le16(QLINK_CMD_RESULT_INVALID);
		goto out;
	}

	pr_info("[VIF%u.%u] %sCONNECT in state %u\n",
		cmd->macid, cmd->vifid,
		bss->vap->iv_state == IEEE80211_S_INIT ? "" : "RE-",
		bss->vap->iv_state);

	bss->bg_scan_period = get_unaligned_le16(&cmd_params->bg_scan_period);
	bss_clr_status(bss, QLINK_BSS_IGNORE_NEXTDEAUTH);

	/*
	 * When reconnecting to the same BSSID, transition to
	 * INIT state will generate CONNECT_FAIL event that will wrongly be
	 * matched with new CONNECT request. Set a flag to ignore next CONNECT_FAIL
	 * event and not send it to host.
	 */
	if ((bss->vap->iv_state == IEEE80211_S_RUN ||
	    bss->vap->iv_state == IEEE80211_S_ASSOC) &&
	    !is_zero_ether_addr(bss->bssid) &&
	    !memcmp(cmd_params->bssid, bss->bssid, sizeof(bss->bssid)))
		bss_set_status(bss, QLINK_BSS_IGNORE_NEXTDEAUTH);

	ieee80211_cancel_scan_no_wait(bss->vap);
	qlink_bss_connection_drop(bss);
	ieee80211_new_state(bss->vap, IEEE80211_S_INIT, -1);

	payload_len = le16_to_cpu(cmd->mhdr.len) - sizeof(*cmd_params);

	qlink_for_each_tlv(ptlv, cmd_params->payload, payload_len) {
		vlen = le16_to_cpu(ptlv->len);

		switch (le16_to_cpu(ptlv->type)) {
		case WLAN_EID_SSID:
			if (vlen > IEEE80211_NWID_LEN) {
				pr_warn("WLAN_EID_SSID length (%u) out of range\n", vlen);
				break;
			}

			memcpy(bss->ssid, ptlv->val, vlen);
			bss->ssid[vlen] = '\0';
			bss->ssid_len = vlen;
			qlink_wifi_set_ssid(bss->dev, (u8 *)ptlv->val, vlen);
			break;
		case QTN_TLV_ID_IE_SET:
			ie_set = (const struct qlink_tlv_ie_set *)ptlv;

			if (ie_set->type != QLINK_IE_SET_ASSOC_REQ)
				pr_warn("%s: bad IE type %u\n",
					bss->dev->name, ie_set->type);

			qlink_dump_ies(ie_set->ie_data,
				vlen - (sizeof(*ie_set) - sizeof(ie_set->hdr)), 1);
			ret = qlink_cmd_append_ie_do(bss, ie_set);
			if (ret) {
				pr_err("%s: QTN_TLV_ID_IE_SET error %d\n",
				       bss->dev->name, ret);
				goto out;
			}
			break;
		case QTN_TLV_ID_CHANNEL:
			if (vlen != sizeof(*qchan))
				break;

			qchan = (struct qlink_channel *)ptlv->val;
			break;
		}
	}

	if (qchan)
		chan_ieee = le16_to_cpu(qchan->hw_value);

	pr_info("%s: ssid=%s\n  bssid=%pM prev_bssid=%pM bgscan=%d flags=0x%x chan=%u\n",
		bss->dev->name, bss->ssid, cmd_params->bssid,
		cmd_params->prev_bssid,
		bss->bg_scan_period,
		le32_to_cpu(cmd_params->flags),
		chan_ieee);

	ret = qlink_apply_bss_privacy(bss, &cmd_params->aen,
				      qlink_utils_mfp_conv(cmd_params->mfp));
	if (ret) {
		ret = -EINVAL;
		goto out;
	}

	qlink_bss_sta_conf_apply_overrides(bss,
					   le32_to_cpu(cmd_params->flags),
					   QTN_CHAN_IS_2G(chan_ieee),
					   &cmd_params->ht_capa,
					   &cmd_params->ht_capa_mask,
					   &cmd_params->vht_capa,
					   &cmd_params->vht_capa_mask);

	/*
	 * BBIC4 background scan causes periodical traffic drops,
	 * so we ignore this setting until clarification of application area
	 * for this functionality
	 */
	pr_debug("VIF%u.%u: ignore setting background scan period to %d\n",
		 cmd->macid, cmd->vifid, bss->bg_scan_period);

	memcpy(bss->bssid, cmd_params->bssid, sizeof(bss->bssid));

	if (is_zero_ether_addr(bss->bssid)) {
		ret = -EINVAL;
		pr_err("failed to connect: BSSID not set\n");
		goto out;
	}

	bss_set_status(bss, QLINK_BSS_CONNECTING);

	if (cmd_params->aen.auth_type == QLINK_AUTHTYPE_SAE) {
		bss_set_status(bss, QLINK_BSS_SAE_PROCESSING);
		bss->sae_chan_ieee = chan_ieee;
	}

	ret = qlink_utils_scan_before_connect(bss->vap, bss->ssid, bss->ssid_len,
				qchan ? le16_to_cpu(qchan->center_freq) : 0);
	if (ret) {
		bss_clr_status(bss, QLINK_BSS_CONNECTING);
		bss_clr_status(bss, QLINK_BSS_SAE_PROCESSING);
		pr_err("failed to connect to BSSID %pM\n", bss->bssid);
	}

out:
	reply->result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(reply, le16_to_cpu(reply->mhdr.len));
}

static void qlink_cmd_external_auth(struct qlink_server *qs,
				    const struct qlink_cmd *cmd)
{
	struct qlink_cmd_external_auth *cmd_params;
	struct qlink_bss *bss = NULL;
	struct qlink_resp *reply;
	u16 status;
	int ret = 0;

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	if (!qlink_check_mac_if(cmd)) {
		pr_err("invalid mac/if: %u %u\n", cmd->macid, cmd->vifid);
		ret = -EINVAL;
		goto out;
	}

	if (le16_to_cpu(cmd->mhdr.len) < sizeof(*cmd_params)) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmd->mhdr.len));
		ret = -EINVAL;
		goto out;
	}

	bss = &qs->maclist[cmd->macid].bss[cmd->vifid];
	cmd_params = (struct qlink_cmd_external_auth *)cmd;
	status = le16_to_cpu(cmd_params->status);

	if (!bss_has_status(bss, QLINK_BSS_ADDED) || (bss->mode != QLINK_IFTYPE_STATION)) {
		ret = -EINVAL;
		goto out;
	}

	if (status != WLAN_STATUS_SUCCESS) {
		pr_info("external auth attempt failed: %u\n", status);
		goto out;
	}

	bss_clr_status(bss, QLINK_BSS_SAE_PROCESSING);

	ret = qlink_wifi_associate(bss->dev, bss->bssid);
	pr_info("[VIF%u.%u] CONNECT %s BSSID=%pM (%d)\n",
		cmd->macid, cmd->vifid, ret ? "fail" : "OK",
		bss->bssid, ret);
	if (ret) {
		ret = -EINVAL;
		goto out;
	}

out:
	reply->result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(reply, le16_to_cpu(reply->mhdr.len));
}

static void qlink_cmd_disconnect(struct qlink_server *qs, const struct qlink_cmd *cmd)
{
	struct qlink_cmd_disconnect *cmd_params;
	struct qlink_resp *reply;
	struct qlink_bss *bss;
	int ret = -EINVAL;

	reply = qlink_prepare_reply(cmd);
	if (!reply)
		return;

	if (!qlink_check_mac_if(cmd))
		goto out;

	if (le16_to_cpu(cmd->mhdr.len) < sizeof(*cmd_params)) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmd->mhdr.len));
		goto out;
	}

	cmd_params = (struct qlink_cmd_disconnect *)cmd;

	bss = &qs->maclist[cmd->macid].bss[cmd->vifid];
	if (!bss_has_status(bss, QLINK_BSS_ADDED) || (bss->mode != QLINK_IFTYPE_STATION)) {
		ret = -ENOENT;
		goto out;
	}

	ret = qlink_wifi_sta_deauth(bss->dev, bss->mac_addr,
				    get_unaligned_le16(&cmd_params->reason));
	qlink_bss_connection_drop(bss);
out:
	reply->result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(reply, le16_to_cpu(reply->mhdr.len));
}

static void qlink_cmd_pm_set(struct qlink_server *qs,
			     const struct qlink_cmd *cmd)
{
	const struct qlink_cmd_pm_set *cmd_params;
	struct qlink_resp *resp;
	struct qlink_bss *bss;
	int ret = 0;

	resp = qlink_prepare_reply(cmd);
	if (!resp)
		return;

	if (!qlink_check_mac_if(cmd)) {
		pr_err("invalid mac/if: %u %u\n", cmd->macid, cmd->vifid);
		ret = -EINVAL;
		goto out;
	}

	if (le16_to_cpu(cmd->mhdr.len) < sizeof(*cmd_params)) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmd->mhdr.len));
		ret = -EINVAL;
		goto out;
	}

	bss = &qs->maclist[cmd->macid].bss[cmd->vifid];
	if (!bss_has_status(bss, QLINK_BSS_ADDED)) {
		ret = -EINVAL;
		goto out;
	}

	cmd_params = (const struct qlink_cmd_pm_set *)cmd;

	if (bss->mode == QLINK_IFTYPE_STATION) {
		qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_STA_BMPS,
				    cmd_params->pm_mode ? BMPS_MODE_AUTO : BMPS_MODE_OFF);
		qs->pwr_save = cmd_params->pm_mode ? BMPS_MODE_AUTO : BMPS_MODE_OFF;
	}

out:
	resp->result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(resp, sizeof(*resp));
}

static void qlink_cmd_pta_param_setget(struct qlink_server *qs,
				       const struct qlink_cmd *cmd)
{
	struct qlink_resp_pta_param *resp;
	struct qlink_mac *mac;
	const struct qlink_cmd_pta_param *pta_cmd;
	int param_id;
	int param_value;
	int ret = 0;

	resp = (struct qlink_resp_pta_param *)qlink_prepare_reply(cmd);
	if (!resp)
		return;

	resp->rhdr.mhdr.len = cpu_to_le16(sizeof(*resp));

	if (le16_to_cpu(cmd->mhdr.len) < sizeof(*pta_cmd)) {
		pr_err("cmd payload is too small: %u\n",
		       le16_to_cpu(cmd->mhdr.len));
		ret = -EINVAL;
		goto out;
	}

	mac = &qs->maclist[cmd->macid];
	pta_cmd = (const struct qlink_cmd_pta_param *)cmd;
	resp->pta_param_id = pta_cmd->pta_param_id;

	/* convert QLINK parameter ID into native */
	switch (pta_cmd->pta_param_id) {
	case QLINK_PTA_PARAM_MODE:
		param_id = QTN_PTA_PARAM_MODE;
		break;
	case QLINK_PTA_PARAM_REQ_POL:
		param_id = QTN_PTA_PARAM_REQ_POL;
		break;
	case QLINK_PTA_PARAM_GNT_POL:
		param_id = QTN_PTA_PARAM_GNT_POL;
		break;
	case QLINK_PTA_PARAM_REQ_TIMEOUT:
		param_id = QTN_PTA_PARAM_REQ_TIMEOUT;
		break;
	case QLINK_PTA_PARAM_GNT_TIMEOUT:
		param_id = QTN_PTA_PARAM_GNT_TIMEOUT;
		break;
	case QLINK_PTA_PARAM_IFS_TIMEOUT:
		param_id = QTN_PTA_PARAM_IFS_TIMEOUT;
		break;
	default:
		pr_err("MAC%u: unknown PTA param: %u\n",
		       cmd->macid, pta_cmd->pta_param_id);
		ret = -EOPNOTSUPP;
		goto out;
	}

	if (pta_cmd->set_op) {
		int tmpval = le32_to_cpu(pta_cmd->pta_param_value);

		if (param_id == QTN_PTA_PARAM_MODE) {
			/* convert QLINK parameter value into native */
			switch (tmpval) {
			case QLINK_PTA_MODE_DISABLED:
				param_value = PTA_MODE_DISABLED;
				break;
			case QLINK_PTA_MODE_2_WIRE:
				param_value = PTA_MODE_2_WIRE;
				break;
			default:
				pr_err("MAC%u: unknown PTA mode: %d\n",
				       cmd->macid, tmpval);
				ret = -EOPNOTSUPP;
				goto out;
			}
		} else {
			param_value = tmpval;
		}

		ret = qlink_phy_set_pta_param(mac->dev, param_id,
					      param_value);
	} else {
		param_value = 0;
		ret = qlink_phy_get_pta_param(mac->dev, param_id,
					      &param_value);
	}

	if (ret == 0)
		resp->pta_param_value = cpu_to_le32(param_value);
out:
	resp->rhdr.result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(resp, sizeof(*resp));
}

static void qlink_cmd_wowlan_set(struct qlink_server *qs,
				 const struct qlink_cmd *cmd)
{
	const struct qlink_cmd_wowlan_set *cmd_params;
	struct ieee80211com *ic;
	struct qlink_resp *resp;
	struct qlink_bss *bss;
	const struct qlink_tlv_hdr *ptlv;
	int payload_len;
	u16 vlen;
	u16 type;
	u32 triggers = 0;
	const u8 *pkt = NULL;
	int pkt_len = 0;
	int ret = 0;

	resp = qlink_prepare_reply(cmd);
	if (!resp)
		return;

	if (!qlink_check_mac_if(cmd)) {
		pr_err("invalid mac/if: %u %u\n", cmd->macid, cmd->vifid);
		ret = -EINVAL;
		goto out;
	}

	if (le16_to_cpu(cmd->mhdr.len) < sizeof(*cmd_params)) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmd->mhdr.len));
		ret = -EINVAL;
		goto out;
	}

	bss = &qs->maclist[cmd->macid].bss[cmd->vifid];
	if (!bss_has_status(bss, QLINK_BSS_ADDED)) {
		ret = -EINVAL;
		goto out;
	}

	ic = bss->vap->iv_ic;
	if (unlikely(!ic)) {
		pr_err("internal error: cannot get ic\n");
		ret = -EINVAL;
		goto out;
	}

	cmd_params = (const struct qlink_cmd_wowlan_set *)cmd;
	payload_len = le16_to_cpu(cmd->mhdr.len) - sizeof(*cmd_params);

	triggers = get_unaligned_le32(&cmd_params->triggers);
	if (!triggers) {
		pr_debug("reset WoWLAN params: pwr_save(%u)\n", qs->pwr_save);
		ret = qlink_wowlan_config(bss->dev, qs->pwr_save, NULL, 0);
		ic->ic_wowlan.mask = 0;
		goto out;
	}

	qlink_for_each_tlv(ptlv, cmd_params->data, payload_len) {
		vlen = le16_to_cpu(ptlv->len);
		type = le16_to_cpu(ptlv->type);

		switch (type) {
		case QTN_TLV_ID_WOWLAN_PATTERN:
			if (!(triggers & QLINK_WOWLAN_TRIG_PATTERN_PKT))
				break;

			pkt = ptlv->val;
			pkt_len = vlen;
			print_hex_dump(KERN_WARNING, "PATTERN: ", DUMP_PREFIX_NONE,
				       16, 1, pkt, pkt_len, 1);

			break;
		default:
			pr_info("unknown TLV ID received: 0x%x\n", type);
			break;
		}
	}

	ret = qlink_wowlan_config(bss->dev, triggers, pkt, pkt_len);
	if (ret == 0) {
		ic->ic_wowlan.mask = 0;

		if (triggers & QLINK_WOWLAN_TRIG_DISCONNECT)
			ic->ic_wowlan.mask |= WOWLAN_TRIG_DISCONNECT;

		if (triggers & QLINK_WOWLAN_TRIG_MAGIC_PKT)
			ic->ic_wowlan.mask |= WOWLAN_TRIG_MAGIC;

		if (triggers & QLINK_WOWLAN_TRIG_PATTERN_PKT)
			ic->ic_wowlan.mask |= WOWLAN_TRIG_PATTERN;
	}

out:
	resp->result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(resp, sizeof(*resp));
}

static void qlink_cmd_tid_config(struct qlink_server *qs,
				      const struct qlink_cmd *cmd)
{
	struct qlink_cmd_tid_cfg *cmd_params;
	const struct qlink_tlv_hdr *ptlv;
	struct qlink_resp *resp;
	struct qlink_mac *mac;
	uint16_t payload_len;
	uint16_t vlen;
	uint16_t type;
	int ampdu = -1;
	int amsdu = -1;
	int ret = 0;

	resp = qlink_prepare_reply(cmd);
	if (!resp)
		return;

	if (unlikely(le16_to_cpu(cmd->mhdr.len) < sizeof(*cmd_params))) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmd->mhdr.len));
		ret = -EINVAL;
		goto out;
	}

	if (unlikely(!qlink_check_mac_if(cmd))) {
		pr_err("invalid mac/vif: %u/%u\n", cmd->macid, cmd->vifid);
		ret = -EINVAL;
		goto out;
	}

	if (!qs->maclist[cmd->macid].dev) {
		pr_err("phy %u is not registered\n", cmd->macid);
		ret = -ENOENT;
		goto out;
	}

	mac = &qs->maclist[cmd->macid];
	cmd_params = (struct qlink_cmd_tid_cfg *)cmd;
	payload_len = le16_to_cpu(cmd->mhdr.len) - sizeof(*cmd_params);

	/* currently only global A-MPDU/A-MSDU configuration is supported */
	if ((cmd_params->tid != 0xff) || !is_broadcast_ether_addr(cmd_params->addr)) {
		pr_err("per-TID/per-STA setup is not yet supported\n");
		ret = -ENOTSUPP;
		goto out;
	}

	qlink_dump_tlvs(cmd_params->data, payload_len);

	qlink_for_each_tlv(ptlv, cmd_params->data, payload_len) {
		vlen = le16_to_cpu(ptlv->len);
		type = le16_to_cpu(ptlv->type);

		switch (type) {
		case QTN_TLV_ID_AMPDU_LEN:
			if (vlen != sizeof(u32)) {
				pr_warn("QTN_TLV_ID_AMPDU_LEN invalid length");
				break;
			}

			ampdu = le32_to_cpu(*(u32 *)(ptlv->val));
			pr_info("QTN_TLV_ID_AMPDU_LEN %d\n", ampdu);
			break;
		case QTN_TLV_ID_AMSDU_LEN:
			if (vlen != sizeof(u32)) {
				pr_warn("QTN_TLV_ID_AMSDU_LEN invalid length");
				break;
			}

			amsdu = le32_to_cpu(*(u32 *)(ptlv->val));
			pr_info("QTN_TLV_ID_AMSDU_LEN %d\n", amsdu);
			break;
		default:
			pr_info("unknown TLV ID received: 0x%x\n", type);
			break;
		}
	}

	if (ampdu >= 0) {
		ret = qlink_wifi_set_ampdu(mac->dev, ampdu);
		if (ret) {
			pr_warn("failed to set AMPDU operating status");
			goto out;
		}
	}

	if (amsdu >= 0) {
		ret = qlink_wifi_set_amsdu(mac->dev, amsdu ? 1 : 0);
		if (ret) {
			pr_warn("failed to set AMSDU operating status");
			goto out;
		}
	}

out:
	resp->result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(resp, sizeof(*resp));
}

static void qlink_cmd_txpwr(struct qlink_server *qs, const struct qlink_cmd *cmdh)
{
	struct qlink_resp_txpwr *resp;
	const struct qlink_cmd_txpwr *cmd;
	struct qlink_mac *mac;
	int ret = 0;
	int dbm;

	resp = (struct qlink_resp_txpwr *)qlink_prepare_reply(cmdh);
	if (!resp)
		return;

	resp->rhdr.mhdr.len = cpu_to_le16(sizeof(*resp));

	if (unlikely(!qlink_check_mac_if(cmdh))) {
		pr_err("invalid mac/vif: %u/%u\n", cmdh->macid, cmdh->vifid);
		ret = -EINVAL;
		goto out;
	}

	if (le16_to_cpu(cmdh->mhdr.len) < sizeof(*cmd)) {
		pr_err("cmd payload is too small: %u\n", le16_to_cpu(cmdh->mhdr.len));
		ret = -EINVAL;
		goto out;
	}

	mac = &qs->maclist[cmdh->macid];
	cmd = (const struct qlink_cmd_txpwr *)cmdh;

	switch (cmd->op_type) {
	case QLINK_TXPWR_GET:
		dbm = qlink_reg_eirp_from_pchain_dbm(mac->ic->ic_unit,
				mac->ic->ic_curchan->ic_maxpower);
		resp->txpwr = cpu_to_le32(DBM_TO_MBM(dbm));
		break;
	case QLINK_TXPWR_SET:
		ret = -EOPNOTSUPP;
		break;
	default:
		pr_info("VIF%u.%u: invalid Tx power operation type: %u\n",
				cmdh->macid, cmdh->vifid, cmd->op_type);
		ret = -EINVAL;
		goto out;
	}

out:
	resp->rhdr.result = cpu_to_le16(qlink_utils_retval2q(ret));
	qlink_xmit(resp, sizeof(*resp));
}


/* sysfs test interface */

static ssize_t qlink_cmd_sysfs_handle(struct qlink_server *qs, const char *buf, size_t count)
{
	struct qlink_bss *bss = &qs->maclist[0].bss[0];
	struct qlink_cmd_manage_intf *add_if_params;
	struct qlink_cmd_manage_intf *del_if_params;
	struct qlink_cmd_get_sta_info *sta_info_req;
	struct qlink_cmd *cmd;
	static u8 qlink_skb[1024];
	char cmd_buf[MAX_QDRV_CMD];
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

	cmd = (struct qlink_cmd *)qlink_skb;

	cmd->mhdr.len = cpu_to_le16(sizeof(*cmd));
	cmd->mhdr.type = cpu_to_le16(QLINK_MSG_TYPE_CMD);
	cmd->cmd_id = 0;
	cmd->macid = 0;
	cmd->vifid = 0;
	cmd->seq_num = 0;

	add_if_params = (struct qlink_cmd_manage_intf *)cmd;
	del_if_params = (struct qlink_cmd_manage_intf *)cmd;
	sta_info_req = (struct qlink_cmd_get_sta_info *)cmd;

	if (!strcmp(cmd_buf, "fw_init")) {
		pr_info("FW_INIT command injected\n");
		cmd->cmd_id = QLINK_CMD_FW_INIT;
		qlink_cmd_fw_init(qs, cmd);
	} else if (!strcmp(cmd_buf, "hw_info")) {
		pr_info("GET_HW_INFO command injected\n");
		cmd->cmd_id = QLINK_CMD_GET_HW_INFO;
		qlink_cmd_get_hw_info(qs, cmd);
	} else if (!strcmp(cmd_buf, "mac_info")) {
		pr_info("GET_WMAC_INFO command injected\n");
		cmd->cmd_id = QLINK_CMD_MAC_INFO;
		qlink_cmd_get_wmac_info(qs, cmd);
	} else if (!strcmp(cmd_buf, "add_if")) {
		pr_info("ADD_IF command injected\n");
		cmd->cmd_id = QLINK_CMD_ADD_INTF;
		add_if_params->intf_info.if_type = cpu_to_le16(QLINK_IFTYPE_AP);
		add_if_params->intf_info.vlanid = cpu_to_le16(0);
		add_if_params->intf_info.mac_addr[0] = 0x98;
		add_if_params->intf_info.mac_addr[1] = 0x90;
		add_if_params->intf_info.mac_addr[2] = 0x96;
		add_if_params->intf_info.mac_addr[3] = 0xe0;
		add_if_params->intf_info.mac_addr[4] = 0x8b;
		add_if_params->intf_info.mac_addr[5] = 0xc6;
		cmd->mhdr.len = cpu_to_le16(sizeof(*add_if_params));
		qlink_cmd_add_if(qs, cmd);
	} else if (!strcmp(cmd_buf, "del_if")) {
		pr_info("DEL_IF command injected\n");
		cmd->cmd_id = QLINK_CMD_DEL_INTF;
		del_if_params->intf_info.if_type = cpu_to_le16(QLINK_IFTYPE_AP);
		del_if_params->intf_info.vlanid = cpu_to_le16(0);
		cmd->mhdr.len = cpu_to_le16(sizeof(*del_if_params));
		qlink_cmd_del_if(qs, cmd);
	} else if (!strcmp(cmd_buf, "start_ap")) {
		pr_info("START_AP command injected\n");
		cmd->cmd_id = QLINK_CMD_START_AP;
		qlink_cmd_start_ap(qs, cmd);
	} else if (!strcmp(cmd_buf, "stop_ap")) {
		pr_info("STOP_AP command injected\n");
		cmd->cmd_id = QLINK_CMD_STOP_AP;
		qlink_cmd_stop_ap(qs, cmd);
	} else if (!strcmp(cmd_buf, "get_sta")) {
		pr_info("GET_STA_INFO command injected\n");
		cmd->cmd_id = QLINK_CMD_GET_STA_INFO;
		sta_info_req->sta_addr[0] = 0xc0;
		sta_info_req->sta_addr[1] = 0xee;
		sta_info_req->sta_addr[2] = 0xfb;
		sta_info_req->sta_addr[3] = 0x5a;
		sta_info_req->sta_addr[4] = 0x2b;
		sta_info_req->sta_addr[5] = 0xbc;
		cmd->mhdr.len = cpu_to_le16(sizeof(*sta_info_req));
		qlink_cmd_get_sta_info(cmd);
	} else if (!strcmp(cmd_buf, "send_mgmt")) {
		uint8_t buf[sizeof(struct ieee80211_frame) + sizeof(struct ieee80211_action)];
		struct ieee80211_frame *frame_hdr = (void *)buf;
		struct ieee80211_action *action_frame =
			(void *)(buf + sizeof(struct ieee80211_frame));

		pr_info("SEND_MGMT_FRAME command injected\n");

		frame_hdr->i_fc[0] = IEEE80211_FC0_SUBTYPE_ACTION;
		frame_hdr->i_addr1[0] = 0x01;
		frame_hdr->i_addr1[1] = 0x02;
		frame_hdr->i_addr1[2] = 0x03;
		frame_hdr->i_addr1[3] = 0x04;
		frame_hdr->i_addr1[4] = 0x05;
		frame_hdr->i_addr1[5] = 0x06;

		action_frame->ia_category = IEEE80211_ACTION_CAT_SA_QUERY;
		action_frame->ia_action = 0xDE;

		if (!bss_has_status(bss, QLINK_BSS_STARTED))
			pr_err("bss is not started\n");
		else
			qlink_mgmt_tx(bss, 0xDEADBEEF, 0, buf, sizeof(buf));
	} else {
		pr_info("unknown command: discarded\n");
	}

	return (ssize_t)count;
}

static ssize_t
qlink_sysfs_store_cmd(struct device *dev, struct device_attribute *attr,
		      const char *buf, size_t count)
{
	struct qlink_server *qs = (struct qlink_server *)dev_get_platdata(dev);

	return qlink_cmd_sysfs_handle(qs, buf, count);
}

static ssize_t
qlink_sysfs_show_cmd(struct device *dev, struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "Available commands:\n"
			"fw_init\n hw_info\n mac_info\n add_if\n del_if\n start_ap\n stop_ap\n"
			" get_sta\n send_mgmt\n");
}

static DEVICE_ATTR(cmd, 0644, qlink_sysfs_show_cmd, qlink_sysfs_store_cmd);

int qlink_cmd_sysfs_register(struct device *dev)
{
	return device_create_file(dev, &dev_attr_cmd);
}

void qlink_cmd_sysfs_unregister(struct device *dev)
{
	device_remove_file(dev, &dev_attr_cmd);
}
