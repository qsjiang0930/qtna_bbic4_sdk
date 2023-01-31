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
#include <asm/unaligned.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_qrpe.h>
#include <net80211/ieee80211_bsa.h>

#include "qdrv/qdrv_radar.h"
#include "qdrv/qdrv_wlan.h"
#include <qdrv/qdrv_control.h>
#include <qdrv/qdrv_vap.h>

#include <common/qtn_hw_mod.h>

#include <common/qtn_hw_mod.h>

#include "utils.h"
#include "wlan_ops.h"
#include "netdev_ops.h"
#include "events.h"
#include "reg_utils.h"

#define QLINK_MAX_COUNTRY_LEN	32

void qlink_dump_tlvs(const u8 *tlv_buf, size_t buf_len)
{
	uint16_t vlen;
	const struct qlink_tlv_hdr *ptlv;
	u8 ssid_buf[IEEE80211_MAX_SSID_LEN + 1];
	u8 country_buf[QLINK_MAX_COUNTRY_LEN + 1];

	qlink_for_each_tlv(ptlv, tlv_buf, buf_len) {
		vlen = le16_to_cpu(ptlv->len);

		switch (le16_to_cpu(ptlv->type)) {
		case WLAN_EID_SSID:
			if (vlen > IEEE80211_MAX_SSID_LEN) {
				pr_warn("IEEE_EID_SSID length out of range\n");
				break;
			}
			memcpy(ssid_buf, ptlv->val, vlen);
			ssid_buf[vlen] = '\0';
			pr_debug("IEEE_EID_SSID %s\n", ssid_buf);
			break;
		case WLAN_EID_SUPP_RATES:
			print_hex_dump(KERN_DEBUG, "IEEE_EID_RATES ", DUMP_PREFIX_NONE,
				       16, 1, ptlv->val, vlen, 1);
			break;
		case WLAN_EID_DS_PARAMS:
			if (vlen != sizeof(u8)) {
				pr_warn("IEEE_EID_DS_PARAMS invalid length\n");
				break;
			}
			pr_debug("IEEE_DS_PARAMS %x\n", ptlv->val[0]);
			break;
		case WLAN_EID_COUNTRY:
			if (vlen > QLINK_MAX_COUNTRY_LEN) {
				pr_warn("IEEE_EID_COUNTRY length out of range\n");
				break;
			}
			memcpy(country_buf, ptlv->val, vlen);
			country_buf[vlen] = '\0';
			pr_debug("IEEE_EID_COUNTRY %s\n", country_buf);
			break;
		case WLAN_EID_EXT_SUPP_RATES:
			if ((vlen == 0) || (vlen > 255)) {
				pr_warn("IEEE_EID_EXT_RATES length out of range\n");
				break;
			}
			pr_debug("IEEE_EID_EXT_RATES %d bytes\n", vlen);
			break;
		case QTN_TLV_ID_SRETRY_LIMIT:
			if (vlen != sizeof(u32)) {
				pr_warn("QTN_TLV_ID_SRETRY_LIMIT invalid length\n");
				break;
			}
			pr_debug("QTN_TLV_ID_SRETRY_LIMIT %u\n", le32_to_cpu(*((u32 *)ptlv->val)));
			break;
		case QTN_TLV_ID_LRETRY_LIMIT:
			if (vlen != sizeof(u32)) {
				pr_warn("QTN_TLV_ID_LRETRY_LIMIT invalid length\n");
				break;
			}
			pr_debug("QTN_TLV_ID_LRETRY_LIMIT %u\n", le32_to_cpu(*((u32 *)ptlv->val)));
			break;
		case QTN_TLV_ID_FRAG_THRESH:
			if (vlen != sizeof(u32)) {
				pr_warn("QTN_TLV_ID_FRAG_THRESH invalid length\n");
				break;
			}
			pr_debug("QTN_TLV_ID_FRAG_THRESH %x\n",
				 get_unaligned_le32(ptlv->val));
			break;
		case QTN_TLV_ID_RTS_THRESH:
			if (vlen != sizeof(u32)) {
				pr_warn("QTN_TLV_ID_RTS_THRESH invalid length\n");
				break;
			}
			pr_debug("QTN_TLV_ID_RTS_THRESH %x\n",
				 get_unaligned_le32(ptlv->val));
			break;
		case QTN_TLV_ID_CHANNEL:
			if ((vlen == 0) || (vlen > 255)) {
				pr_warn("QTN_TLV_ID_CHANNEL_CFG length out of range\n");
				break;
			}
			pr_debug("QTN_TLV_ID_CHANNEL_CFG %d bytes\n", vlen);
			break;
		case QTN_TLV_ID_COVERAGE_CLASS:
			if (vlen != sizeof(u32)) {
				pr_warn("QTN_TLV_ID_CCLASS invalid length\n");
				break;
			}
			pr_debug("QTN_TLV_ID_CLASS %d\n", le32_to_cpu(*((u32 *)ptlv->val)));
			break;
		case QTN_TLV_ID_AMPDU_LEN:
			if (vlen != sizeof(u32)) {
				pr_warn("QTN_TLV_ID_AMPDU_LEN invalid length\n");
				break;
			}
			pr_debug("QTN_TLV_ID_AMPDU_LEN %x\n",
				 get_unaligned_le32(ptlv->val));
			break;
		case QTN_TLV_ID_AMSDU_LEN:
			if (vlen != sizeof(u32)) {
				pr_warn("QTN_TLV_ID_AMSDU_LEN invalid length\n");
				break;
			}
			pr_debug("QTN_TLV_ID_AMSDU_LEN %x\n",
				 get_unaligned_le32(ptlv->val));
			break;
		default:
			pr_debug("unknown TLV ID received: 0x%x\n", le16_to_cpu(ptlv->type));
		};
	}
}

#define IE_TYPE(n)[n] = #n

static const char * const ie_names[] = {
	IE_TYPE(IEEE80211_ELEMID_SSID),
	IE_TYPE(IEEE80211_ELEMID_RATES),
	IE_TYPE(IEEE80211_ELEMID_FHPARMS),
	IE_TYPE(IEEE80211_ELEMID_DSPARMS),
	IE_TYPE(IEEE80211_ELEMID_CFPARMS),
	IE_TYPE(IEEE80211_ELEMID_TIM),
	IE_TYPE(IEEE80211_ELEMID_IBSSPARMS),
	IE_TYPE(IEEE80211_ELEMID_COUNTRY),
	IE_TYPE(IEEE80211_ELEMID_REQINFO),
	IE_TYPE(IEEE80211_ELEMID_BSS_LOAD),
	IE_TYPE(IEEE80211_ELEMID_EDCA),
	IE_TYPE(IEEE80211_ELEMID_CHALLENGE),
	IE_TYPE(IEEE80211_ELEMID_PWRCNSTR),
	IE_TYPE(IEEE80211_ELEMID_PWRCAP),
	IE_TYPE(IEEE80211_ELEMID_TPCREQ),
	IE_TYPE(IEEE80211_ELEMID_TPCREP),
	IE_TYPE(IEEE80211_ELEMID_SUPPCHAN),
	IE_TYPE(IEEE80211_ELEMID_CHANSWITCHANN),
	IE_TYPE(IEEE80211_ELEMID_MEASREQ),
	IE_TYPE(IEEE80211_ELEMID_MEASREP),
	IE_TYPE(IEEE80211_ELEMID_QUIET),
	IE_TYPE(IEEE80211_ELEMID_IBSSDFS),
	IE_TYPE(IEEE80211_ELEMID_ERP),
	IE_TYPE(IEEE80211_ELEMID_HTCAP),
	IE_TYPE(IEEE80211_ELEMID_QOSCAP),
	IE_TYPE(IEEE80211_ELEMID_RSN),
	IE_TYPE(IEEE80211_ELEMID_XRATES),
	IE_TYPE(IEEE80211_ELEMID_NEIGHBOR_REP),
	IE_TYPE(IEEE80211_ELEMID_FTIE),
	IE_TYPE(IEEE80211_ELEMID_TIMEOUT_INT),
	IE_TYPE(IEEE80211_ELEMID_REG_CLASSES),
	IE_TYPE(IEEE80211_ELEMID_HTINFO),
	IE_TYPE(IEEE80211_ELEMID_SEC_CHAN_OFF),
	IE_TYPE(IEEE80211_ELEMID_20_40_BSS_COEX),
	IE_TYPE(IEEE80211_ELEMID_20_40_IT_CH_REP),
	IE_TYPE(IEEE80211_ELEMID_OBSS_SCAN),
	IE_TYPE(IEEE80211_ELEMID_TDLS_LINK_ID),
	IE_TYPE(IEEE80211_ELEMID_TDLS_WKUP_SCHED),
	IE_TYPE(IEEE80211_ELEMID_TDLS_CS_TIMING),
	IE_TYPE(IEEE80211_ELEMID_TDLS_PTI_CTRL),
	IE_TYPE(IEEE80211_ELEMID_TDLS_PU_BUF_STAT),
	IE_TYPE(IEEE80211_ELEMID_INTERWORKING),
	IE_TYPE(IEEE80211_ELEMID_EXTCAP),
	IE_TYPE(IEEE80211_ELEMID_AGERE1),
	IE_TYPE(IEEE80211_ELEMID_AGERE2),
	IE_TYPE(IEEE80211_ELEMID_TPC),
	IE_TYPE(IEEE80211_ELEMID_CCKM),
	IE_TYPE(IEEE80211_ELEMID_VHTCAP),
	IE_TYPE(IEEE80211_ELEMID_VHTOP),
	IE_TYPE(IEEE80211_ELEMID_EXTBSSLOAD),
	IE_TYPE(IEEE80211_ELEMID_WBWCHANSWITCH),
	IE_TYPE(IEEE80211_ELEMID_VHTXMTPWRENVLP),
	IE_TYPE(IEEE80211_ELEMID_CHANSWITCHWRP),
	IE_TYPE(IEEE80211_ELEMID_AID),
	IE_TYPE(IEEE80211_ELEMID_QUIETCHAN),
	IE_TYPE(IEEE80211_ELEMID_OPMOD_NOTIF),
	IE_TYPE(IEEE80211_ELEMID_VENDOR),
	IE_TYPE(IEEE80211_ELEMID_EXTENSION),
};

static const char * const ie_ext_names[] = {
	IE_TYPE(IEEE80211_ELEMID_EST_SVC_PARAM),
	IE_TYPE(IEEE80211_ELEMID_CHAN_GUIDE),
	IE_TYPE(IEEE80211_ELEMID_EXT_DH_PARAM),
	IE_TYPE(IEEE80211_ELEMID_MAX_CHAN_SWITCH_TIME),
};

void qlink_dump_rsn_ie(const u8 *ie, size_t len)
{
	u_int32_t w;
	size_t n;

	if (len < 10) {
		pr_warn("RSN is too short, len %u", len);
		return;
	}
	w = get_unaligned_le16(ie);
	pr_debug("RSN version %u\n", w);
	ie += 2;
	len -= 2;

	/* multicast/group cipher */
	w = get_unaligned_be32(ie);
	pr_debug("group cipher %08x\n", w);
	ie += 4;
	len -= 4;

	/* unicast ciphers */
	n = get_unaligned_le16(ie);
	ie += 2;
	len -= 2;
	if (len < n * 4 + 2) {
		pr_warn("cipher list corrupted\n");
		return;
	}
	if (n == 0)
		pr_warn("unicast cipher list is empty\n");
	for (; n != 0; n--) {
		w = get_unaligned_be32(ie);
		pr_debug("unicast cipher %08x\n", w);
		ie += 4;
		len -= 4;
	}

	/* key management algorithms */
	n = get_unaligned_le16(ie);
	ie += 2;
	len -= 2;
	if (len < n * 4) {
		pr_warn("key mgmt list corrupted\n");
		return;
	}
	if (n == 0)
		pr_warn("key mgmt list is empty\n");
	for (; n > 0; n--) {
		w = get_unaligned_be32(ie);
		pr_debug("key mgmt %08x\n", w);
		ie += 4;
		len -= 4;
	}

	/* optional RSN capabilities */
	if (len >= 2)
		w = get_unaligned_le16(ie);

	pr_debug("RSN caps %04x\n", w);
}

void qlink_dump_ies(const u8 *ie_buf, size_t buf_len, int dump_val)
{
	const u8 *endbuf = ie_buf + buf_len;
	const char *ie_name = "UNKNOWN";
	const u8 *ie = ie_buf;
	const u8 *ie_val;
	u8 ie_type;
	u8 ie_len;

	pr_debug("IE set begin\n");
	while (ie < endbuf) {
		if (endbuf - ie < 2) {
			pr_err("the last IE is too short\n");
			break;
		}

		ie_type = ie[0];
		ie_len = ie[1];
		ie_val = &ie[2];

		if (endbuf - ie_val < ie_len) {
			pr_err("the last IE is corrupted\n");
			break;
		}

		if (ie_names[ie_type] != NULL)
			ie_name = ie_names[ie_type];

		if (ie_type == IEEE80211_ELEMID_EXTENSION) {
			ie_type = ie_val[0];
			if (ie_ext_names[ie_type] != NULL)
				ie_name = ie_ext_names[ie_type];
		}

		pr_debug("[%s], %u bytes\n", ie_name, ie_len + 2);
		if (dump_val)
			print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_NONE,
				       16, 1, ie_val, ie_len, 1);

		switch (ie_type) {
		case IEEE80211_ELEMID_RSN:
			qlink_dump_rsn_ie(ie_val, ie_len);
		}
		ie += ie_len + 2;
	}
	pr_debug("IE set end\n");
}

void qlink_dump_ht_caps(const struct ieee80211_ht_cap *ht_conf)
{
	uint16_t cap = le16_to_cpu(ht_conf->cap_info);
	uint8_t ampdu = ht_conf->ampdu_params_info;

	pr_info("ldpc=%u 20_40=%u grn_fld=%u sgi20=%u sgi40=%u\n"
		"  tx_stbc=%u delay_ba=%u max_amsdu=%u dssscck=%u 40_intol=%u lsig_txop_prot=%u\n"
		"  sm_ps=0x%x rx_stbc=0x%x ampdu_factor=%u ampdu_density=%u\n",
		!!(cap & IEEE80211_HT_CAP_LDPC_CODING),
		!!(cap & IEEE80211_HT_CAP_SUP_WIDTH_20_40),
		!!(cap & IEEE80211_HT_CAP_GRN_FLD),
		!!(cap & IEEE80211_HT_CAP_SGI_20),
		!!(cap & IEEE80211_HT_CAP_SGI_40),
		!!(cap & IEEE80211_HT_CAP_TX_STBC),
		!!(cap & IEEE80211_HT_CAP_DELAY_BA),
		!!(cap & IEEE80211_HT_CAP_MAX_AMSDU),
		!!(cap & IEEE80211_HT_CAP_DSSSCCK40),
		!!(cap & IEEE80211_HT_CAP_40MHZ_INTOLERANT),
		!!(cap & IEEE80211_HT_CAP_LSIG_TXOP_PROT),
		(cap & IEEE80211_HT_CAP_SM_PS) >> IEEE80211_HT_CAP_SM_PS_SHIFT,
		(cap & IEEE80211_HT_CAP_RX_STBC) >> IEEE80211_HT_CAP_RX_STBC_SHIFT,
		ampdu & IEEE80211_HT_AMPDU_PARM_FACTOR,
		(ampdu & IEEE80211_HT_AMPDU_PARM_DENSITY) >> IEEE80211_HT_AMPDU_PARM_DENSITY_SHIFT);
}

void qlink_dump_vht_caps(const struct ieee80211_vht_cap *vht_conf)
{
	uint32_t cap = le32_to_cpu(vht_conf->vht_cap_info);

	pr_info("mpdu_7991=%u mpdu_11454=%u 160mhz=%u 160_80p80=%u\n"
		"  rxldpc=%u sgi80=%u sgi160=%u txstbc=%u su_bfer=%u su_bfee=%u\n"
		"  mu_bfer=%u mu_bfee=%u txop_ps=%u htc=%u link_adapt=%u\n"
		"  rx_ant_pat=%u tx_ant_pat=%u rx_stbc_m=0x%x bfee_sts_m=0x%x snd_m=0x%x\n"
		"  ampdu_exp_m=0x%x rx_mcs_map=0x%04x tx_mcs_map=0x%04x\n",
		!!(cap & IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_7991),
		!!(cap & IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_11454),
		!!(cap & IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ),
		!!(cap & IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ),
		!!(cap & IEEE80211_VHT_CAP_RXLDPC),
		!!(cap & IEEE80211_VHT_CAP_SHORT_GI_80),
		!!(cap & IEEE80211_VHT_CAP_SHORT_GI_160),
		!!(cap & IEEE80211_VHT_CAP_TXSTBC),
		!!(cap & IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE),
		!!(cap & IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE),
		!!(cap & IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE),
		!!(cap & IEEE80211_VHT_CAP_MU_BEAMFORMEE_CAPABLE),
		!!(cap & IEEE80211_VHT_CAP_VHT_TXOP_PS),
		!!(cap & IEEE80211_VHT_CAP_HTC_VHT),
		(cap & IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_MRQ_MFB) >> 26,
		!!(cap & IEEE80211_VHT_CAP_RX_ANTENNA_PATTERN),
		!!(cap & IEEE80211_VHT_CAP_TX_ANTENNA_PATTERN),
		(cap & IEEE80211_VHT_CAP_RXSTBC_MASK) >> 0x8,
		(cap & IEEE80211_VHT_CAP_BEAMFORMEE_STS_MASK) >>
		IEEE80211_VHT_CAP_BEAMFORMEE_STS_SHIFT,
		(cap & IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_MASK) >>
		IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_SHIFT,
		(cap & IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK) >>
		IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT,
		le16_to_cpu(vht_conf->supp_mcs.rx_mcs_map),
		le16_to_cpu(vht_conf->supp_mcs.tx_mcs_map));
}

int qlink_vap_chandef_fill(struct ieee80211vap *vap, struct qlink_chandef *chan)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_channel *ch = ic->ic_curchan;
	int bw;
	int ret;
	u16 qlink_cf1;
	u8 qlink_bw;

	if (!vap->iv_dev)
		return -ENOENT;

	if (ieee80211_is_scanning(ic)) {
		if (vap->iv_state == IEEE80211_S_RUN &&
		    is_ieee80211_chan_valid(ic->ic_bsschan))
			ch = ic->ic_bsschan;
		else if (is_ieee80211_chan_valid(ic->ic_des_chan))
			ch = ic->ic_des_chan;
	}

	if (!is_ieee80211_chan_valid(ch))
		return -EBUSY;

	ret = qlink_wifi_getparam(vap->iv_dev, IEEE80211_PARAM_BW_SEL_MUC,
				  &bw);
	if (ret) {
		pr_err("%s: failed to get BW\n", vap->iv_dev->name);
		return ret;
	}

	switch (bw) {
	case BW_HT80:
		qlink_bw = QLINK_CHAN_WIDTH_80;
		qlink_cf1 = ieee80211_ieee2mhz(ch->cchan_80, 0);
		break;
	case BW_HT40:
		qlink_bw = QLINK_CHAN_WIDTH_40;
		qlink_cf1 = ieee80211_ieee2mhz(ch->cchan_40, 0);
		break;
	case BW_HT20:
		qlink_bw = QLINK_CHAN_WIDTH_20;
		qlink_cf1 = ch->ic_freq;
		break;
	default:
		pr_err("%s: bad BW=%u\n", vap->iv_dev->name, bw);
		return -EINVAL;
	}

	chan->chan.hw_value = cpu_to_le16(ch->ic_ieee);
	chan->chan.center_freq = cpu_to_le16(ch->ic_freq);
	chan->center_freq1 = cpu_to_le16(qlink_cf1);
	chan->center_freq2 = 0;
	chan->width = qlink_bw;

	return 0;
}

const char *qlink_chan_identify_band(struct ieee80211_channel *c,
				     unsigned int bw, bool vht_en, bool ht_en)
{
	const char *band;

	if (c->ic_freq < IEEE80211_5GBAND_START_FREQ) {
		if (ht_en) {
			switch (bw) {
			case BW_HT40:
				band = "11ng40";
				break;
			default:
				band = "11ng";
				break;
			}
		} else {
			band = "11g";
		}
	} else {
		if (vht_en) {
			switch (bw) {
			case BW_HT40:
				band = "11ac40";
				break;
			case BW_HT80:
				if (IEEE80211_IS_CHAN_11AC_VHT80_EDGEPLUS(c))
					band = "11AC80EDGE+";
				else if (IEEE80211_IS_CHAN_11AC_VHT80_CNTRPLUS(c))
					band = "11AC80CNTR+";
				else if (IEEE80211_IS_CHAN_11AC_VHT80_CNTRMINUS(c))
					band = "11AC80CNTR-";
				else if (IEEE80211_IS_CHAN_11AC_VHT80_EDGEMINUS(c))
					band = "11AC80EDGE-";
				else
					band = "11ac80";
				break;
			default:
				band = "11ac20";
				break;
			}
		} else if (ht_en) {
			switch (bw) {
			case BW_HT40:
				band = "11na40";
				break;
			default:
				band = "11na";
				break;
			}
		} else {
			band = "11a";
		}
	}

	return band;
}

enum qlink_cmd_result qlink_utils_retval2q(int retval)
{
	switch (retval) {
	case 0:
		return QLINK_CMD_RESULT_OK;
	case -ENOENT:
		return QLINK_CMD_RESULT_ENOTFOUND;
	case -EOPNOTSUPP:
		return QLINK_CMD_RESULT_ENOTSUPP;
	case -EALREADY:
		return QLINK_CMD_RESULT_EALREADY;
	case -EADDRINUSE:
		return QLINK_CMD_RESULT_EADDRINUSE;
	case -EADDRNOTAVAIL:
		return QLINK_CMD_RESULT_EADDRNOTAVAIL;
	case -EBUSY:
		return QLINK_CMD_RESULT_EBUSY;
	default:
		return QLINK_CMD_RESULT_INVALID;
	}
}

void qlink_mac_bf_config(struct net_device *dev, bool bfon)
{
	struct shared_params *sp = qtn_mproc_sync_shared_params_get();

	if (!qtn_hw_mod_bf_is_supported_in_5g(sp->hardware_options))
		return;

	qlink_wifi_setparam(dev, IEEE80211_PARAM_TXBF_PERIOD, bfon ? 10 : 0);
	qlink_wifi_setparam(dev, IEEE80211_PARAM_EXP_MAT_SEL, bfon);
}

void qlink_mac_mu_config(struct net_device *dev, bool enable)
{
	struct shared_params *sp = qtn_mproc_sync_shared_params_get();

	if (!qtn_hw_mod_bf_is_supported_in_5g(sp->hardware_options))
		return;

	if (sp->fw_no_mu)
		return;

	if (enable) {
		qlink_wifi_setparam(dev, IEEE80211_PARAM_MU_ENABLE, 1);
		/* enable 'wait for buddy' */
		qlink_wifi_setparam(dev, IEEE80211_PARAM_MU_DEBUG_FLAG,
				    0x8002000f);
		/* enable mu_retries */
		qlink_wifi_setparam(dev, IEEE80211_PARAM_MU_DEBUG_FLAG,
				    0x80002000);
	} else {
		qlink_wifi_setparam(dev, IEEE80211_PARAM_MU_ENABLE, 0);
		qlink_wifi_setparam(dev, IEEE80211_PARAM_MU_DEBUG_FLAG,
				    0x000200ff);
	}
}

void qlink_wmac_info_htcap_mod_mask_fill(struct ieee80211_ht_cap *mask,
					 u8 rx_chains)
{
	struct ieee80211_htcap htcap;
	u16 cap_info;

	memset(mask, 0, sizeof(*mask));

	cap_info = IEEE80211_HT_CAP_LDPC_CODING |
		IEEE80211_HT_CAP_SUP_WIDTH_20_40 |
		IEEE80211_HT_CAP_SGI_20 |
		IEEE80211_HT_CAP_SGI_40 |
		IEEE80211_HT_CAP_TX_STBC |
		IEEE80211_HT_CAP_RX_STBC |
		IEEE80211_HT_CAP_MAX_AMSDU;

	mask->cap_info = cpu_to_le16(cap_info);
	mask->ampdu_params_info = IEEE80211_HT_AMPDU_PARM_FACTOR |
				 IEEE80211_HT_AMPDU_PARM_DENSITY;

	qdrv_wlan_80211_set_ht_mcsset(MIN(rx_chains, QTN_GLOBAL_RATE_NSS_MAX),
				      1, &htcap);
	memcpy(mask->mcs.rx_mask, htcap.mcsset, sizeof(mask->mcs.rx_mask));
}

void qlink_wmac_info_vhtcap_mod_mask_fill(struct ieee80211_vht_cap *mask,
				      u8 rx_chains, u8 tx_chains)
{
	struct shared_params *sp;
	u32 cap_info;
	u16 mcs_map;
	u8 i;

	sp = qtn_mproc_sync_shared_params_get();

	memset(mask, 0, sizeof(*mask));
	cap_info = IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_7991 |
		IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_11454 |
		IEEE80211_VHT_CAP_RXLDPC |
		IEEE80211_VHT_CAP_SHORT_GI_80 |
		IEEE80211_VHT_CAP_TXSTBC |
		IEEE80211_VHT_CAP_RXSTBC_MASK |
		IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK;

	if (qtn_hw_mod_bf_is_supported_in_5g(sp->hardware_options)) {
		cap_info |=
			IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE |
			IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE |
			IEEE80211_VHT_CAP_BEAMFORMEE_STS_MASK |
			IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_MASK;

		if (!sp->fw_no_mu) {
			cap_info |=
				IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE |
				IEEE80211_VHT_CAP_MU_BEAMFORMEE_CAPABLE;
		}
	}

	mask->vht_cap_info = cpu_to_le32(cap_info);

	mcs_map = 0;
	for (i = 0; i < rx_chains; i++)
		mcs_map |= (3 << 2 * i);

	mask->supp_mcs.rx_mcs_map = cpu_to_le16(mcs_map);

	mcs_map = 0;
	for (i = 0; i < tx_chains; i++)
		mcs_map |= (3 << 2 * i);

	mask->supp_mcs.tx_mcs_map = cpu_to_le16(mcs_map);
}

void qlink_htcap_to_ht_cap(const struct ieee80211_htcap *htcap,
			   u32 vap_ht_flags,
			   struct ieee80211_ht_cap *ht_cap)
{
	memset(ht_cap, 0, sizeof(*ht_cap));

	ht_cap->cap_info = cpu_to_le16(htcap->cap);

	if (vap_ht_flags & IEEE80211_HTF_LDPC_ENABLED)
		ht_cap->cap_info |= IEEE80211_HT_CAP_LDPC_CODING;
	else
		ht_cap->cap_info &= ~IEEE80211_HT_CAP_LDPC_CODING;

	if (vap_ht_flags & IEEE80211_HTF_STBC_ENABLED)
		ht_cap->cap_info |= (IEEE80211_HT_CAP_TX_STBC | IEEE80211_HT_CAP_RX_STBC);
	else
		ht_cap->cap_info &= ~(IEEE80211_HT_CAP_TX_STBC | IEEE80211_HT_CAP_RX_STBC);

	ht_cap->ampdu_params_info =
		(htcap->maxampdu & IEEE80211_HT_AMPDU_PARM_FACTOR) |
		((htcap->mpduspacing << IEEE80211_HT_AMPDU_PARM_DENSITY_SHIFT) &
		IEEE80211_HT_AMPDU_PARM_DENSITY);
	memcpy(ht_cap->mcs.rx_mask, htcap->mcsset, sizeof(ht_cap->mcs.rx_mask));
	ht_cap->mcs.rx_highest =
		cpu_to_le16(htcap->maxdatarate & IEEE80211_HT_MCS_RX_HIGHEST_MASK);
	ht_cap->mcs.tx_params = (htcap->mcsparams & ~IEEE80211_HT_MCS_TX_MAX_STREAMS_MASK) |
		((htcap->numtxspstr << IEEE80211_HT_MCS_TX_MAX_STREAMS_SHIFT) &
			IEEE80211_HT_MCS_TX_MAX_STREAMS_MASK);
	ht_cap->tx_BF_cap_info = htcap->hc_txbf[0] | (htcap->hc_txbf[1] << 8) |
			(htcap->hc_txbf[2] << 16) | (htcap->hc_txbf[3] << 24);

	ht_cap->extended_ht_cap_info = cpu_to_le16(htcap->extcap);
	ht_cap->antenna_selection_info = 0; // XXX what is this?
}

static inline
int qlink_get_nss_mcs(uint16_t mcsmap, enum ieee80211_vht_nss nss)
{
	int mcs;

	mcs = ((mcsmap >> (2 * (nss - 1))) & 0x3);
	switch (mcs) {
	case IEEE80211_VHT_MCS_0_7:
		mcs = 7;
		break;
	case IEEE80211_VHT_MCS_0_8:
		mcs = 8;
		break;
	case IEEE80211_VHT_MCS_0_9:
		mcs = 9;
		break;
	case IEEE80211_VHT_MCS_NA:
		/* fall through */
	default:
		mcs = -1;
		break;
	}

	return mcs;
}

/*
 * MPDU mask seems not defined in current kernel.
 */
#ifndef IEEE80211_VHT_CAP_MAX_MPDU_MASK
#define IEEE80211_VHT_CAP_MAX_MPDU_MASK 0x3
#endif

void qlink_vhtcap_to_vht_cap(const struct ieee80211_vhtcap *vhtcap,
			     enum ieee80211_vht_nss tx_max_nss,
			     enum ieee80211_vht_nss rx_max_nss,
			     u32 vap_vht_flags,
			     struct ieee80211_vht_cap *vht_cap)
{
	u16 rate;
	int mcs;
	u32 cap;

	memset(vht_cap, 0, sizeof(*vht_cap));

	cap = vhtcap->cap_flags;
	cap = (cap & ~IEEE80211_VHT_CAP_MAX_MPDU_MASK) |
		(vhtcap->maxmpdu & IEEE80211_VHT_CAP_MAX_MPDU_MASK);
	cap = (cap & ~IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_MASK) |
		((vhtcap->chanwidth << 2) & IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_MASK);
	cap = (cap & ~IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK) |
		((vhtcap->maxampduexp << IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT) &
			IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK);

	/* Tx and Rx STBC parameters can only be configured together */
	cap &= ~(IEEE80211_VHT_CAP_TXSTBC | IEEE80211_VHT_CAP_RXSTBC_MASK);
	if (vap_vht_flags & IEEE80211_VHTCAP_C_TX_STBC) {
		cap |= IEEE80211_VHT_CAP_TXSTBC;
		cap |= (vhtcap->rxstbc << 8) & IEEE80211_VHT_CAP_RXSTBC_MASK;
	}

	if (vap_vht_flags & IEEE80211_VHTCAP_C_RX_LDPC)
		cap |= IEEE80211_VHT_CAP_RXLDPC;
	else
		cap &= ~IEEE80211_VHT_CAP_RXLDPC;

	cap &= ~IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_MRQ_MFB;
	if (cap & IEEE80211_VHT_CAP_HTC_VHT) {
		cap |= (vhtcap->lnkadptcap << 26) &
			IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_MRQ_MFB;
	}

	cap &= ~IEEE80211_VHT_CAP_BEAMFORMEE_STS_MASK;
	if (cap & IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE) {
		cap |= (vhtcap->bfstscap << IEEE80211_VHT_CAP_BEAMFORMEE_STS_SHIFT) &
			IEEE80211_VHT_CAP_BEAMFORMEE_STS_MASK;
	}

	cap &= ~IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_MASK;
	if (cap & IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE) {
		cap |= (vhtcap->numsounding << IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_SHIFT) &
			IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_MASK;
	}

	vht_cap->vht_cap_info = cpu_to_le32(cap);

	mcs = qlink_get_nss_mcs(vhtcap->rxmcsmap, rx_max_nss);
	if (mcs > 0) {
		/* mcs2rate returns doubled rate */
		rate = rx_max_nss *
			ieee80211_mcs2rate(mcs, 0 /* VHT_MODE_CHAN_80 */,
					   0 /* LGI */, 1 /* VHT */) / 2;
	} else {
		rate = 0;
	}

	vht_cap->supp_mcs.rx_highest = cpu_to_le16(rate);
	vht_cap->supp_mcs.rx_mcs_map = cpu_to_le16(vhtcap->rxmcsmap);

	mcs = qlink_get_nss_mcs(vhtcap->txmcsmap, tx_max_nss);
	if (mcs > 0) {
		/* mcs2rate returns doubled rate */
		rate = tx_max_nss *
			ieee80211_mcs2rate(mcs, 0 /* VHT_MODE_CHAN_80 */,
					   0 /* LGI */, 1 /* VHT */) / 2;
	} else {
		rate = 0;
	}

	vht_cap->supp_mcs.tx_highest = cpu_to_le16(rate);
	vht_cap->supp_mcs.tx_mcs_map = cpu_to_le16(vhtcap->txmcsmap);
}

static inline int qlink_update_cap_bit(u32 cur_caps, u32 hw, u32 conf, u32 cap_bit,
					int *val)
{
	u32 req_cap = conf & cap_bit;
	u32 chg_req = (cur_caps ^ conf) & cap_bit;

	if (chg_req & ~hw) {
		*val = !!(cur_caps & cap_bit);
		return 0;
	}

	*val = !!req_cap;

	return 1;
}

static inline int qlink_update_cap_field(u32 cur_caps, u32 hw, u32 conf, u32 cap_bits,
					u32 cap_shift, int *val)
{
	u32 req_cap = conf & cap_bits;
	u32 chg_req = (cur_caps ^ conf) & cap_bits;

	if (chg_req & ~hw) {
		*val = (cur_caps & cap_bits) >> cap_shift;
		return 0;
	}

	*val = req_cap >> cap_shift;

	return 1;
}

#define __update_cap_bit(_cap_bit, _dst) \
	do { \
		if (!qlink_update_cap_bit(cur_caps, hw, conf, _cap_bit, _dst)) { \
			pr_warn("%s: " # _cap_bit " unsupported value\n", bss->dev->name); \
		} \
	} while (0)

#define __update_cap_field(_cap_name, _cap_bits, _cap_shift, _dst) \
	do { \
		if (!qlink_update_cap_field(cur_caps, hw, conf, _cap_bits, _cap_shift, _dst)) { \
			pr_warn("%s: " # _cap_name " unsupported value\n", bss->dev->name); \
		} \
	} while (0)

int qlink_bss_ht_conf_apply(const struct qlink_bss *bss,
			    const struct ieee80211_ht_cap *ht_conf,
			    int *sgi_20,
			    int *sgi_40,
			    int *ldpc,
			    int *stbc)
{
	struct ieee80211com *ic = bss->vap->iv_ic;
	struct ieee80211_ht_cap ht_cap_hw;
	u16 cur_caps;
	u16 conf;
	u16 hw;
	int tmp;
	int _sgi_20;
	int _sgi_40;
	int _ldpc;
	int txstbc;
	int rxstbc;
	int max_amsdu;
	int i;

	qlink_wmac_info_htcap_mod_mask_fill(&ht_cap_hw,
					    qdrv_get_num_rx_chains(QTN_WMAC_UNIT0));

	conf = le16_to_cpu(ht_conf->cap_info);
	hw = le16_to_cpu(ht_cap_hw.cap_info);
	cur_caps = ic->ic_htcap.cap;

	/* check that host does not attempt to set unsupported capabilities */
	__update_cap_bit(IEEE80211_HT_CAP_SUP_WIDTH_20_40, &tmp);
	__update_cap_bit(IEEE80211_HT_CAP_GRN_FLD, &tmp);
	__update_cap_bit(IEEE80211_HT_CAP_DELAY_BA, &tmp);
	__update_cap_bit(IEEE80211_HT_CAP_DSSSCCK40, &tmp);
	__update_cap_bit(IEEE80211_HT_CAP_40MHZ_INTOLERANT, &tmp);
	__update_cap_bit(IEEE80211_HT_CAP_LSIG_TXOP_PROT, &tmp);

	__update_cap_bit(IEEE80211_HT_CAP_LDPC_CODING, &_ldpc);
	__update_cap_bit(IEEE80211_HT_CAP_SGI_20, &_sgi_20);
	__update_cap_bit(IEEE80211_HT_CAP_SGI_40, &_sgi_40);
	__update_cap_bit(IEEE80211_HT_CAP_TX_STBC, &txstbc);
	__update_cap_bit(IEEE80211_HT_CAP_MAX_AMSDU, &max_amsdu);

	__update_cap_field(IEEE80211_HT_CAP_RX_STBC,
			   IEEE80211_HT_CAP_RX_STBC,
			   IEEE80211_HT_CAP_RX_STBC_SHIFT,
			   &rxstbc);

	__update_cap_field(IEEE80211_HT_CAP_SM_PS,
			   IEEE80211_HT_CAP_SM_PS,
			   IEEE80211_HT_CAP_SM_PS_SHIFT,
			   &tmp);

	ic->ic_htcap.cap = conf & hw;
	ic->ic_htcap.maxmsdu = max_amsdu ? IEEE80211_MSDU_SIZE_7935 :
		IEEE80211_MSDU_SIZE_3839;

	if (ht_conf->ampdu_params_info & IEEE80211_HT_AMPDU_PARM_FACTOR) {
		ic->ic_htcap.maxampdu = ht_conf->ampdu_params_info &
			IEEE80211_HT_AMPDU_PARM_FACTOR;
	}

	if (ht_conf->ampdu_params_info & IEEE80211_HT_AMPDU_PARM_DENSITY) {
		ic->ic_htcap.mpduspacing = (ht_conf->ampdu_params_info &
			IEEE80211_HT_AMPDU_PARM_DENSITY) >>
			IEEE80211_HT_AMPDU_PARM_DENSITY_SHIFT;
	}

	for (i = 0; i < IEEE80211_HT_MAXMCS_SET_SUPPORTED; i++) {
		ic->ic_htcap.mcsset[i] =
			ht_cap_hw.mcs.rx_mask[i] & ht_conf->mcs.rx_mask[i];
	}

	if (sgi_20)
		*sgi_20 = _sgi_20;

	if (sgi_40)
		*sgi_40 = _sgi_40;

	*ldpc |= _ldpc;
	*stbc |= rxstbc | txstbc;

	return 0;
}

static inline
int qlink_get_max_mcs(uint8_t nss, uint16_t mcsmap)
{
	int mcs = IEEE80211_VHT_MCS_0_7;
	int s;
	int m;

	for (s = 1; s <= nss; s++) {
		m = ((mcsmap >> (2 * (s - 1))) & 0x3);
		if ((m >= 0) && (m > mcs))
			mcs = m;
	}

	return mcs;
}

int qlink_bss_vht_conf_apply(const struct qlink_bss *bss,
			     const struct ieee80211_vht_cap *vht_conf,
			     int *sgi_80,
			     int *ldpc,
			     int *stbc,
			     int is_24g_band)
{
	struct ieee80211com *ic = bss->vap->iv_ic;
	struct ieee80211_vht_cap vht_cap_cur;
	struct ieee80211_vht_cap vht_cap_hw;
	u32 cur_caps;
	u32 conf;
	u32 hw;
	int tmp;
	int max_mpdu_len;
	int rxldpc;
	int _sgi_80;
	int txstbc;
	int rxstbc;
	int su_bmfr;
	int su_bmfe;
	int nsts;
	int sound_dim;
	int mu_bmfr;
	int mu_bmfe;
	int ampdu_factor;
	int ret;
	uint16_t mcs_m;
	uint16_t mcs_n;
	uint8_t rx_nss;
	uint8_t tx_nss;
	int rx_mcs;
	int tx_mcs;

	qlink_wmac_info_vhtcap_mod_mask_fill(&vht_cap_hw,
					     qdrv_get_num_rx_chains(QTN_WMAC_UNIT0),
					     qdrv_get_num_tx_chains(QTN_WMAC_UNIT0));
	conf = le32_to_cpu(vht_conf->vht_cap_info);
	hw = le32_to_cpu(vht_cap_hw.vht_cap_info);

	if (is_24g_band) {
		qlink_vhtcap_to_vht_cap(&ic->ic_vhtcap_24g,
					ic->ic_vht_nss_cap_24g,
					ic->ic_vht_rx_nss_cap_24g,
					bss->vap->iv_vht_flags,
					&vht_cap_cur);
	} else {
		qlink_vhtcap_to_vht_cap(&ic->ic_vhtcap,
					ic->ic_vht_nss_cap,
					ic->ic_vht_rx_nss_cap,
					bss->vap->iv_vht_flags,
					&vht_cap_cur);
	}

	cur_caps = le32_to_cpu(vht_cap_cur.vht_cap_info);

	/* check that host does not attempt to set unsupported capabilities */
	__update_cap_bit(IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ, &tmp);
	__update_cap_bit(IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ, &tmp);
	__update_cap_bit(IEEE80211_VHT_CAP_SHORT_GI_160, &tmp);
	__update_cap_bit(IEEE80211_VHT_CAP_RX_ANTENNA_PATTERN, &tmp);
	__update_cap_bit(IEEE80211_VHT_CAP_TX_ANTENNA_PATTERN, &tmp);
	__update_cap_bit(IEEE80211_VHT_CAP_VHT_TXOP_PS, &tmp);
	__update_cap_bit(IEEE80211_VHT_CAP_HTC_VHT, &tmp);
	__update_cap_field(IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_MRQ_MFB,
			   IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_MRQ_MFB,
			   26,
			   &tmp);

	__update_cap_bit(IEEE80211_VHT_CAP_RXLDPC, &rxldpc);
	__update_cap_bit(IEEE80211_VHT_CAP_SHORT_GI_80, &_sgi_80);
	__update_cap_bit(IEEE80211_VHT_CAP_TXSTBC, &txstbc);
	__update_cap_bit(IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE, &su_bmfr);
	__update_cap_bit(IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE, &su_bmfe);
	__update_cap_bit(IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE, &mu_bmfr);
	__update_cap_bit(IEEE80211_VHT_CAP_MU_BEAMFORMEE_CAPABLE, &mu_bmfe);

	__update_cap_field(IEEE80211_VHT_CAP_MAX_MPDU,
			   IEEE80211_VHT_CAP_MAX_MPDU_MASK,
			   0 /*IEEE80211_VHT_CAP_MAX_MPDU_SHIFT*/,
			   &max_mpdu_len);
	__update_cap_field(IEEE80211_VHT_CAP_RXSTBC,
			   IEEE80211_VHT_CAP_RXSTBC_MASK,
			   8 /*IEEE80211_VHT_CAP_RXSTBC_SHIFT*/,
			   &rxstbc);
	__update_cap_field(IEEE80211_VHT_CAP_BEAMFORMEE_STS,
			   IEEE80211_VHT_CAP_BEAMFORMEE_STS_MASK,
			   IEEE80211_VHT_CAP_BEAMFORMEE_STS_SHIFT,
			   &nsts);
	__update_cap_field(IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS,
			   IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_MASK,
			   IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_SHIFT,
			&sound_dim);
	__update_cap_field(IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT,
			   IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK,
			   IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT,
			   &ampdu_factor);

	if (is_24g_band)
		ic->ic_vhtcap_24g.cap_flags = conf & hw;
	else
		ic->ic_vhtcap.cap_flags = conf & hw;

	/*
	 * IEEE80211_PARAM_TX_MAXMPDU does not have a getter.
	 */
	ret = qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_TX_MAXMPDU, max_mpdu_len);
	if (ret) {
		pr_err("%s: failed to set TX_MAXMPDU\n", bss->dev->name);
		return ret;
	}

	/* apply MCS changes: sanitize input values using mod mask */

	mcs_m = le16_to_cpu(vht_cap_hw.supp_mcs.tx_mcs_map);
	mcs_n = le16_to_cpu(vht_conf->supp_mcs.tx_mcs_map);
	mcs_n = mcs_n | ~mcs_m;

	if (IEEE80211_VHT_HAS_4SS(mcs_n))
		tx_nss = 4;
	else if (IEEE80211_VHT_HAS_3SS(mcs_n))
		tx_nss = 3;
	else if (IEEE80211_VHT_HAS_2SS(mcs_n))
		tx_nss = 2;
	else
		tx_nss = 1;

	tx_mcs = qlink_get_max_mcs(tx_nss, mcs_n);

	mcs_m = le16_to_cpu(vht_cap_hw.supp_mcs.rx_mcs_map);
	mcs_n = le16_to_cpu(vht_conf->supp_mcs.rx_mcs_map);
	mcs_n = mcs_n | ~mcs_m;

	if (IEEE80211_VHT_HAS_4SS(mcs_n))
		rx_nss = 4;
	else if (IEEE80211_VHT_HAS_3SS(mcs_n))
		rx_nss = 3;
	else if (IEEE80211_VHT_HAS_2SS(mcs_n))
		rx_nss = 2;
	else
		rx_nss = 1;

	rx_mcs = qlink_get_max_mcs(rx_nss, mcs_n);

	/* Note:
	 * Firmware supports only single MCS for all NSS,
	 * so use max requested value
	 */

	qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_VHT_RX_NSS_CAP, rx_nss);
	qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_VHT_NSS_CAP, tx_nss);
	qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_VHT_MCS_CAP, max(rx_mcs, tx_mcs));

	/* */

	ic->ic_vhtcap_24g.maxmpdu = max_mpdu_len;
	ic->ic_vhtcap_24g.maxampduexp = ampdu_factor;
	ic->ic_vhtcap.maxmpdu = max_mpdu_len;
	ic->ic_vhtcap.maxampduexp = ampdu_factor;

	if (su_bmfe)
		qlink_wifi_setparam(bss->dev, IEEE80211_PARAM_BF_RX_STS, nsts);

	qlink_mac_bf_config(bss->dev, su_bmfr || su_bmfe || mu_bmfr || mu_bmfe);
	qlink_mac_mu_config(bss->dev, mu_bmfr || mu_bmfe);

	if (sgi_80)
		*sgi_80 = _sgi_80;

	*ldpc |= rxldpc;
	*stbc |= rxstbc | txstbc;

	return 0;
}

#undef __update_cap_bit
#undef __update_cap_field

/*
 * LDPC, SGI and STBC parameters can only be applied globally irrespective
 * to what has been provided in the configuration. Currently the driver does not
 * allow to set them individually for HT or VHT. If any of these options are
 * enabled, they will be advertized for all the supported bandwidths, RX/TX,
 * etc. In order not to break the existing functionality, the following approach
 * will be used:
 *  - SGI will be setup only if the enabled HT/VHT capabilities correspond to
 *    the chosen bandwidth.
 *  - LDPC and STBC will be enabled if at least one of the corresponding
 *    capabilities is present in either HT or VHT.
 */
int qlink_bss_global_conf_apply(const struct qlink_bss *bss,
				int sgi,
				int ldpc,
				int stbc)
{
	int ret;

	ret = qlink_wifi_updparam(bss->dev, IEEE80211_PARAM_SHORT_GI, !!sgi);
	if (ret) {
		pr_err("%s: failed to set SGI\n", bss->dev->name);
		return ret;
	}

	ret = qlink_wifi_updparam(bss->dev, IEEE80211_PARAM_LDPC, !!ldpc);
	if (ret) {
		pr_err("%s: failed to set LDPC\n", bss->dev->name);
		return ret;
	}

	ret = qlink_wifi_updparam(bss->dev, IEEE80211_PARAM_STBC, !!stbc);
	if (ret) {
		pr_err("%s: failed to set STBC\n", bss->dev->name);
		return ret;
	}

	return 0;
}

int qlink_chan_q2ieee(struct ieee80211com *ic,
		      const struct qlink_chandef *chdef,
		      struct ieee80211_channel **ieee_chan,
		      unsigned int *bw)
{
	struct ieee80211_channel *c = NULL;
	unsigned int pri = le16_to_cpu(chdef->chan.center_freq);
	unsigned int cf1 = le16_to_cpu(chdef->center_freq1);
	unsigned int ieee_cf1;
	unsigned int ieee_pri;
	unsigned int i;

	ieee_cf1 = ieee80211_mhz2ieee(cf1, (cf1 < IEEE80211_5GBAND_START_FREQ) ?
				IEEE80211_CHAN_2GHZ : IEEE80211_CHAN_5GHZ);
	ieee_pri = ieee80211_mhz2ieee(pri, (pri < IEEE80211_5GBAND_START_FREQ) ?
				IEEE80211_CHAN_2GHZ : IEEE80211_CHAN_5GHZ);

	switch (chdef->width) {
	case QLINK_CHAN_WIDTH_80:
		*bw = BW_HT80;

		for (i = 0; i < ic->ic_nchans; ++i) {
			c = &ic->ic_channels[i];

			if ((c->ic_ieee == ieee_pri) && (c->cchan_80 == ieee_cf1))
				break;
		}
		break;
	case QLINK_CHAN_WIDTH_40:
		*bw = BW_HT40;

		for (i = 0; i < ic->ic_nchans; ++i) {
			c = &ic->ic_channels[i];

			if ((c->ic_ieee == ieee_pri) && (c->cchan_40 == ieee_cf1))
				break;
		}
		break;
	case QLINK_CHAN_WIDTH_20_NOHT:
	case QLINK_CHAN_WIDTH_20:
		*bw = BW_HT20;

		for (i = 0; i < ic->ic_nchans; ++i) {
			c = &ic->ic_channels[i];

			if (c->ic_ieee == ieee_pri)
				break;
		}
		break;
	default:
		pr_err("unsupported BW %u\n", chdef->width);
		return -EOPNOTSUPP;
	}

	if (i == ic->ic_nchans) {
		pr_err("channel not found ieee=%u freq=%u cf1=%u bw=%u\n",
		       ieee_pri, pri, cf1, *bw);
		return -ENOENT;
	}

	*ieee_chan = c;

	return 0;
}

int qlink_utils_is_channel_usable(struct ieee80211com *ic,
				  struct ieee80211_channel *chan,
				  int bw)
{
	switch (bw) {
	case BW_HT80:
		if (!isset(ic->ic_chan_active_80, chan->ic_ieee))
			return 0;
		break;
	case BW_HT40:
		if (!isset(ic->ic_chan_active_40, chan->ic_ieee))
			return 0;
		break;
	case BW_HT20:
		if (!isset(ic->ic_chan_active_20, chan->ic_ieee))
			return 0;
		break;
	default:
		return 0;
	}

	return 1;
}

void qlink_utils_chandef_set(struct ieee80211com *ic,
			    struct net_device *ndev,
			    struct ieee80211_channel *c,
			    unsigned int bw,
			    const char *mode)
{
	int ret = 0;

	pr_info("%s: chan: %u->%u, bw: %u->%u, mode: %s\n", ndev->name,
		is_ieee80211_chan_valid(ic->ic_curchan) ? ic->ic_curchan->ic_ieee : 0,
		c->ic_ieee, ieee80211_get_bw(ic), bw, mode);


	/* We need to set channel here so that further checks in set_mode,
	 * set_bw etc are done for a proper channel. Channel change itself
	 * will actually happen during setting BW.
	 */
	if (is_ieee80211_chan_valid(c) && (ic->ic_curchan != c)) {
		ic->ic_prevchan = ic->ic_curchan;
		ic->ic_curchan = c;
		ic->ic_des_chan = c;
	}

	ret = qlink_wifi_set_802_11_mode(ndev, mode);
	if (ret)
		pr_warn("%s: failed to set mode to %s: %d\n",
			ndev->name, mode, ret);

	ret = qlink_wifi_setparam(ndev, IEEE80211_PARAM_BW_SEL, bw);
	if (ret)
		pr_warn("%s: failed to set bw to %d: %d\n",
			ndev->name, bw, ret);
}

void qlink_mac_phyparams_apply_default(struct qlink_mac *mac)
{
	struct net_device *dev = mac->dev;

	/* No need to select a default channel here: rely on whatever was
	 * selected by QDRV when interface was created.
	 * Channel will be propagated to lower levels together with
	 * BW setting
	 */
	mac->ic->ic_des_chan = mac->ic->ic_curchan;

	/* Rely on host to perform OBSS scanning */
	mac->ic->ic_obss_scan_enable = 0;

	/* Use 20MHz BW by default as it's safe to use with any channel */
	qlink_wifi_setparam(dev, IEEE80211_PARAM_BW_SEL, BW_HT20);
	/*
	 * Setting BW to 20MHz clears 40MHz capability flag. It will be
	 * configured by host later, but before it does we don't want to
	 * advertise that we do not support 40MHz, so restore the flags.
	 */
	mac->ic->ic_htcap.cap |= IEEE80211_HTCAP_C_CHWIDTH40 |
				IEEE80211_HTCAP_C_SHORTGI40;

	qlink_wifi_setparam(dev, IEEE80211_PARAM_80211V_BTM, 0);

	if (qlink_wifi_set_rate(dev, -1, 0))
		pr_warn("%s: failed to set autorate\n", dev->name);

	qlink_mac_bf_config(dev, 0);
	qlink_mac_mu_config(dev, 0);

	qlink_reg_regulatory_reset(mac);

	mac->phyparams_set = true;
}

void qlink_bss_connection_drop(struct qlink_bss *bss)
{
	bss_clr_status(bss, QLINK_BSS_RUNNING);
	bss_clr_status(bss, QLINK_BSS_CONNECTING);
	bss_clr_status(bss, QLINK_BSS_OWE_PROCESSING);
	bss_clr_status(bss, QLINK_BSS_SAE_PROCESSING);

	memset(bss->bssid, 0, sizeof(bss->bssid));
}

bool qlink_utils_chandef_identical(struct qlink_chandef *old,
				   struct qlink_chandef *new)
{
	if (old->center_freq1 != new->center_freq1)
		return false;

	if (old->center_freq2 != new->center_freq2)
		return false;

	if (old->width != new->width)
		return false;

	if (old->chan.hw_value != new->chan.hw_value)
		return false;

	return true;
}

int qlink_utils_scan_before_connect(struct ieee80211vap *vap, u8 *ssid,
				   size_t ssid_len, u32 center_freq)
{
	struct net_device *ndev = vap->iv_dev;
	int ret;
	struct qlink_scan_freq_list freq_list;

	if (center_freq) {
		freq_list.n_freqs = 1;
		freq_list.freqs[0] = center_freq;
	} else {
		freq_list.n_freqs = 0;
	}

	ret = qlink_wifi_scan_ssid_clear(ndev);
	if (ret)
		return ret;

	ret = qlink_wifi_scan_ssid_add(ndev, ssid, ssid_len);
	if (ret)
		return ret;

	ret = qlink_wifi_scan_freq_set(ndev, (struct ieee80211_scan_freqs *)&freq_list);
	if (ret)
		return ret;

	ieee80211_start_scan(vap,
		IEEE80211_SCAN_ACTIVE | IEEE80211_SCAN_NOPICK | IEEE80211_SCAN_ONCE,
		IEEE80211_SCAN_FOREVER, vap->iv_des_nssid, vap->iv_des_ssid);

	return 0;
}

enum ieee80211_mfp_capabilities qlink_utils_mfp_conv(u8 mfp)
{
	enum ieee80211_mfp_capabilities val;

	switch (mfp) {
	case 0:
		val = IEEE80211_MFP_NO_PROTECT;
		break;
	case 1:
		val = IEEE80211_MFP_PROTECT_REQUIRE;
		break;
	case 2:
		val = IEEE80211_MFP_PROTECT_CAPABLE;
		break;
	default:
		pr_warn("unexpected MFP option %u\n", mfp);
		val = IEEE80211_MFP_NO_PROTECT;
		break;
	}

	return val;
}
