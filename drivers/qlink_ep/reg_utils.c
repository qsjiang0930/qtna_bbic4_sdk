/**
 * Copyright (c) 2018 Quantenna Communications, Inc.
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
 **/

#define pr_fmt(fmt)	"%s: " fmt, __func__

#include <linux/netdevice.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/nl80211.h>
#include <net/regulatory.h>
#include <net80211/ieee80211_var.h>

#include <qdrv/qdrv_mac.h>
#include <qdrv/qdrv_wlan.h>
#include <qdrv/qdrv_radar.h>
#include "qlink_priv.h"
#include "wlan_ops.h"
#include "reg_utils.h"

void qlink_reg_update_tx_power(struct qlink_mac *mac)
{
	struct net_device *ndev = mac->dev;
	char *path = "/sbin/call_qcsapi";
	const char * const argv[] = {
		"/sbin/call_qcsapi", "restore_regulatory_tx_power", ndev->name, NULL };
	const char * const envp[] = {
		"HOME=/", "PATH=/sbin:/usr/sbin:/bin:/usr/bin:/scripts", NULL };
	int ret;

	ret = call_usermodehelper(path, (char **)argv, (char **)envp, UMH_WAIT_PROC);
	if (ret)
		pr_err("%s: failed to update Tx power ret=%d\n", ndev->name, ret);
}

static void qlink_reg_region_change_prepare(struct qlink_mac *mac)
{
	struct ieee80211com *ic = mac->ic;

	qlink_wifi_setparam(mac->dev, IEEE80211_PARAM_MARKDFS, 0);
	ic->ic_country_code = CTRY_DEFAULT;
	memset(ic->ic_chan_dfs_required, 0, sizeof(ic->ic_chan_dfs_required));
	memset(ic->ic_chan_weather_radar, 0, sizeof(ic->ic_chan_weather_radar));
}

/* Firmware does not support reconfiguring radar block for a different DFS region */
static int qlink_reg_verify_dfs_can_set(enum qlink_dfs_regions new_dfs_region)
{
	if (!qdrv_dfs_is_region_set())
		return 1;

	switch (new_dfs_region) {
	case QLINK_DFS_FCC:
		return qdrv_dfs_is_us_region();
	case QLINK_DFS_ETSI:
		return qdrv_dfs_is_eu_region();
	case QLINK_DFS_JP:
		return qdrv_dfs_is_jp_region();
	default:
		return 1;
	}
}

static int qlink_reg_is_world_domain(const char alpha2[2])
{
	return alpha2[0] == '0' && alpha2[1] == '0';
}

int qlink_reg_region_update(struct qlink_mac *mac, char *alpha2, int slave_radar,
	enum qlink_dfs_regions new_dfs_region)
{
	uint16_t iso_code = CTRY_DEFAULT;
	struct ieee80211com *ic = mac->ic;
	int slave_radar_old = 0;
	int ret;

	if (qlink_reg_is_world_domain(alpha2)) {
		qlink_reg_regulatory_reset(mac);
		return 0;
	}

	if (!qlink_reg_verify_dfs_can_set(new_dfs_region))
		return -EOPNOTSUPP;

	ret = ieee80211_country_string_to_countryid(alpha2, &iso_code);
	if (ret) {
		pr_warn("MAC%u: unknown alpha2 \"%s\"\n", ic->ic_unit, alpha2);
		return ret;
	}

	if (ic->ic_country_code != iso_code) {
		pr_info("MAC%u: iso_code %u->%u\n", ic->ic_unit,
			ic->ic_country_code, iso_code);
		qlink_reg_region_change_prepare(mac);
		qdrv_wlan_region_update(mac->dev, iso_code, mac->ic->ic_opmode);
	}

	qlink_wifi_getparam(mac->dev, IEEE80211_PARAM_STA_DFS, &slave_radar_old);

	if (slave_radar != slave_radar_old) {
		ret = qlink_wifi_setparam(mac->dev, IEEE80211_PARAM_STA_DFS, slave_radar);
		if (ret == 0) {
			qlink_reg_update_tx_power(mac);
			pr_info("MAC%u: slave_radar %u->%u\n", ic->ic_unit,
				slave_radar_old, slave_radar);
		}
	}

	return 0;
}

/* Convert internal region string representation into the ISO / IEC 3166 alpha2 country code */
static void qlink_reg_mac_get_alpha2_code(struct ieee80211com *ic, u8 alpha2[2])
{
	char region[3];
	int ret;

	/* default: specific alpha2 is not set yet */
	alpha2[0] = '9';
	alpha2[1] = '7';

	if (ic->ic_country_code == CTRY_DEFAULT)
		return;

	ret = ieee80211_countryid_to_country_string(ic->ic_country_code, region);
	if (ret == 0) {
		alpha2[0] = toupper(region[0]);
		alpha2[1] = toupper(region[1]);
	}
}

#define QLINK_ANT_NUM_LIMIT	4
/*
 * Calculate EIRP based on per-chain max Tx power, antenna gain and number of
 * transmit chains. Use formula approximation:
 * EIRP = max_pwr + antenna_gain + 10 * log10(ant_num) - 0.5
 */
int qlink_reg_eirp_from_pchain_dbm(unsigned int macid, int max_pwr)
{
	int8_t ant_gain = qdrv_wlan_get_tx_antenna_gain(macid);
	unsigned int chain_idx = qdrv_wlan_get_hw_tx_chains(macid) - 1;
	static const int ant_10log10minus05_lookup[QLINK_ANT_NUM_LIMIT] = {
		0, 3, 4, 6
	};

	if (chain_idx >= QLINK_ANT_NUM_LIMIT)
		chain_idx = QLINK_ANT_NUM_LIMIT - 1;

	return max_pwr + ant_gain + ant_10log10minus05_lookup[chain_idx];
}

/* max_pwr = EIRP - antenna_gain - 10 * log10(ant_num) + 0.5 */
static int qlink_reg_pchain_from_eirp_dbm(unsigned int macid, int eirp)
{
	int8_t ant_gain = qdrv_wlan_get_tx_antenna_gain(macid);
	unsigned int chain_idx = qdrv_wlan_get_hw_tx_chains(macid) - 1;
	static const int ant_10log10plus05_lookup[QLINK_ANT_NUM_LIMIT] = {
		1, 4, 5, 7
	};

	if (chain_idx >= QLINK_ANT_NUM_LIMIT)
		chain_idx = QLINK_ANT_NUM_LIMIT - 1;

	return eirp - ant_gain - ant_10log10plus05_lookup[chain_idx];
}

/*
 * Regulatory rules only specify some of HW limits for channels. Additional regulatory
 * information (DFS, HT40PLUS, HT40MINUS etc) is set for each channel separately.
 */
static void qlink_reg_regrule_start(unsigned int macid,
	struct qlink_tlv_reg_rule *tlv_rule, const struct ieee80211_channel *chi)
{
	u32 maxbw = 0;
	u32 flags = 0;
	int max_pwr = qdrv_wlan_get_max_tx_power_by_chan(macid, chi->ic_ieee);

	memset(tlv_rule, 0, sizeof(*tlv_rule));
	tlv_rule->hdr.type = cpu_to_le16(QTN_TLV_ID_REG_RULE);
	tlv_rule->hdr.len = cpu_to_le16(sizeof(*tlv_rule) -
			sizeof(struct qlink_tlv_hdr));
	tlv_rule->start_freq_khz = cpu_to_le32(MHZ_TO_KHZ(chi->ic_freq - 10));

	if (chi->ic_flags & IEEE80211_CHAN_VHT160)
		maxbw = MHZ_TO_KHZ(160);
	else
		flags |= QLINK_RRF_NO_160MHZ;

	if (chi->ic_flags & IEEE80211_CHAN_VHT80)
		maxbw = MAX(MHZ_TO_KHZ(80), maxbw);
	else
		flags |= QLINK_RRF_NO_80MHZ;

	if (chi->ic_flags & IEEE80211_CHAN_HT40)
		maxbw = MAX(MHZ_TO_KHZ(40), maxbw);

	if (chi->ic_flags & IEEE80211_CHAN_HT20)
		maxbw = MAX(MHZ_TO_KHZ(20), maxbw);

	tlv_rule->flags = cpu_to_le32(flags);
	tlv_rule->max_bandwidth_khz = cpu_to_le32(maxbw);

	tlv_rule->max_antenna_gain =
		cpu_to_le32(DBI_TO_MBI(qdrv_wlan_get_tx_antenna_gain(macid)));
	tlv_rule->max_eirp =
		cpu_to_le32(DBM_TO_MBM(qlink_reg_eirp_from_pchain_dbm(macid, max_pwr)));
}

static bool qlink_reg_regrule_done(const struct ieee80211_channel *chi_prev,
		const struct ieee80211_channel *chi_cur)
{
	if (QTN_CHAN_IS_2G(chi_prev->ic_ieee) && !QTN_CHAN_IS_2G(chi_cur->ic_ieee))
		return true;

	if (QTN_CHAN_IS_5G(chi_prev->ic_ieee) && !QTN_CHAN_IS_5G(chi_cur->ic_ieee))
		return true;

	if ((chi_prev->ic_flags & (IEEE80211_CHAN_HT20 | IEEE80211_CHAN_HT40 |
			IEEE80211_CHAN_VHT80 | IEEE80211_CHAN_VHT160)) !=
		(chi_cur->ic_flags & (IEEE80211_CHAN_HT20 | IEEE80211_CHAN_HT40 |
				IEEE80211_CHAN_VHT80 | IEEE80211_CHAN_VHT160)))
		return true;

	return false;
}

static void qlink_reg_regrule_finish(unsigned int macid,
				struct qlink_tlv_reg_rule *tlv_rule,
				const struct ieee80211_channel *chi)
{
	tlv_rule->end_freq_khz = cpu_to_le32(MHZ_TO_KHZ(chi->ic_freq + 10));

	pr_info("MAC%u: new reg rule: s=%u e=%u bw=%u flags=0x%x gain=%u\n",
			macid,
			le32_to_cpu(tlv_rule->start_freq_khz),
			le32_to_cpu(tlv_rule->end_freq_khz),
			le32_to_cpu(tlv_rule->max_bandwidth_khz),
			le32_to_cpu(tlv_rule->flags),
			le32_to_cpu(tlv_rule->max_antenna_gain));
}

size_t qlink_reg_mac_info_fill(struct ieee80211com *ic,
	struct qlink_resp_get_mac_info *info, unsigned int offset)
{
	struct qlink_tlv_reg_rule *tlv_rule;
	const struct ieee80211_channel *chi_cur;
	const struct ieee80211_channel *chi_prev = NULL;
	unsigned int i;
	unsigned int num_rules = 0;

	tlv_rule = (struct qlink_tlv_reg_rule *)(info->var_info + offset);

	for (i = 0; i < ic->ic_nchans; ++i) {
		chi_cur = &ic->ic_channels[i];

		if (!chi_prev) {
			qlink_reg_regrule_start(ic->ic_unit, tlv_rule, chi_cur);
		} else if (qlink_reg_regrule_done(chi_prev, chi_cur)) {
			qlink_reg_regrule_finish(ic->ic_unit, tlv_rule, chi_prev);
			++num_rules;
			++tlv_rule;
			qlink_reg_regrule_start(ic->ic_unit, tlv_rule, chi_cur);
		}

		if (i == (ic->ic_nchans - 1)) {
			qlink_reg_regrule_finish(ic->ic_unit, tlv_rule, chi_cur);
			++num_rules;
		} else {
			chi_prev = chi_cur;
		}
	}

	qlink_reg_mac_get_alpha2_code(ic, &info->alpha2[0]);
	info->n_reg_rules = num_rules;

	if (qdrv_dfs_is_us_region())
		info->dfs_region = QLINK_DFS_FCC;
	else if (qdrv_dfs_is_eu_region())
		info->dfs_region = QLINK_DFS_ETSI;
	else if (qdrv_dfs_is_jp_region())
		info->dfs_region = QLINK_DFS_JP;
	else
		info->dfs_region = QLINK_DFS_UNSET;

	pr_info("MAC%u: alpha2=\"%c%c\" nrules=%u dfs=%u\n",
		ic->ic_unit,
		info->alpha2[0], info->alpha2[1],
		info->n_reg_rules, info->dfs_region);

	return sizeof(*tlv_rule) * num_rules;
}

void qlink_reg_chan_update(struct qlink_mac *mac, const struct qlink_channel *qch)
{
	u32 flags = le32_to_cpu(qch->flags);
	unsigned int ieee = le16_to_cpu(qch->hw_value);
	struct ieee80211com *ic = mac->ic;
	struct ieee80211_channel *ch = ic->ic_findchannel(ic, ieee, IEEE80211_MODE_AUTO);

	if (!is_ieee80211_chan_valid(ch)) {
		pr_warn("MAC%u: can't find chan %u\n", ic->ic_unit, ieee);
		return;
	}

	pr_debug("MAC%u: chan=%u pwr=%u reg_pwr=%u flags=0x%x", ic->ic_unit,
		ieee, qch->max_power, qch->max_reg_power, flags);

	if ((flags & QLINK_CHAN_DISABLED) && isset(ic->ic_chan_active_20, ieee)) {
		pr_debug(" +disabled");
		clrbit(ic->ic_chan_active, ieee);
		clrbit(ic->ic_chan_active_20, ieee);
		clrbit(ic->ic_chan_active_40, ieee);
		clrbit(ic->ic_chan_active_80, ieee);
	}

	if ((flags & QLINK_CHAN_NO_IR) && !(ch->ic_flags & IEEE80211_CHAN_PASSIVE)) {
		pr_debug(" +passive");
		ch->ic_flags |= IEEE80211_CHAN_PASSIVE;
	}

	if (flags & QLINK_CHAN_RADAR) {
		if (!(ch->ic_flags & IEEE80211_CHAN_DFS)) {
			setbit(ic->ic_chan_dfs_required, ieee);
			pr_debug(" +dfs (%u)", qch->dfs_state);
		}

		switch (qch->dfs_state) {
		case QLINK_DFS_AVAILABLE:
			ic->ic_chan_availability_status[ieee] =
				IEEE80211_CHANNEL_STATUS_AVAILABLE;
			ch->ic_flags |= IEEE80211_CHAN_DFS_CAC_DONE;
			ch->ic_flags &= ~(IEEE80211_CHAN_RADAR |
				IEEE80211_CHAN_DFS_CAC_IN_PROGRESS);
			break;
		case QLINK_DFS_UNAVAILABLE:
			ic->ic_chan_availability_status[ieee] =
				IEEE80211_CHANNEL_STATUS_NOT_AVAILABLE_RADAR_DETECTED;
			ch->ic_flags |= IEEE80211_CHAN_RADAR;
			ch->ic_flags &= ~(IEEE80211_CHAN_DFS_CAC_DONE |
				IEEE80211_CHAN_DFS_CAC_IN_PROGRESS);
			break;
		case QLINK_DFS_USABLE:
			ic->ic_chan_availability_status[ieee] =
				IEEE80211_CHANNEL_STATUS_NOT_AVAILABLE_CAC_REQUIRED;
			ch->ic_flags &= ~(IEEE80211_CHAN_RADAR |
				IEEE80211_CHAN_DFS_CAC_IN_PROGRESS |
				IEEE80211_CHAN_DFS_CAC_DONE);
			break;
		}
	}

	/* Do not touch Tx power if region was set, fully trust EP settings */
	if (ic->ic_country_code == CTRY_DEFAULT) {
		int pwr_host = qlink_reg_pchain_from_eirp_dbm(ic->ic_unit,
								qch->max_power);
		int max_pwr = qdrv_wlan_get_max_tx_power_by_chan(ic->ic_unit, ieee);

		qlink_wifi_set_reguatory_txpwr(mac->dev, ieee, ieee, qch->max_reg_power);
		qlink_wifi_init_txpwr_table(mac->dev, ieee, MIN(max_pwr, pwr_host));
	}
	pr_debug("\n");
}

void qlink_reg_regulatory_reset(struct qlink_mac *mac)
{
	struct ieee80211com *ic = mac->ic;
	int chain_pwr;

	qlink_reg_region_change_prepare(mac);
	qdrv_wlan_region_update(mac->dev, CTRY_DEFAULT, ic->ic_opmode);
	ic->ic_mark_dfs_channels(ic);
	ic->ic_mark_weather_radar_chans(ic);
	ieee80211_mark_all_channel_status(ic, BW_HT20);

	chain_pwr = qdrv_wlan_get_max_tx_power(ic->ic_unit, QDRV_BAND_2G);
	qlink_wifi_set_reguatory_txpwr(mac->dev, QTN_2G_FIRST_OPERATING_CHAN,
			QTN_2G_LAST_OPERATING_CHAN,
			qlink_reg_eirp_from_pchain_dbm(ic->ic_unit, chain_pwr));

	chain_pwr = qdrv_wlan_get_max_tx_power(ic->ic_unit, QDRV_BAND_5G);
	qlink_wifi_set_reguatory_txpwr(mac->dev, QTN_5G_FIRST_OPERATING_CHAN,
			QTN_5G_LAST_OPERATING_CHAN,
			qlink_reg_eirp_from_pchain_dbm(ic->ic_unit, chain_pwr));
}
