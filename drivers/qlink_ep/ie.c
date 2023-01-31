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

#include <linux/netdevice.h>
#include <linux/module.h>

#include <net80211/ieee80211_var.h>

#include "ie.h"
#include "wlan_ops.h"

/* copy of is_sys_ie() from drivers/wlan/ieee80211_wireless.c */
static bool qlink_ie_is_sys(u_int8_t ie_id)
{
	switch (ie_id) {
	case IEEE80211_ELEMID_SSID:
	case IEEE80211_ELEMID_RATES:
	case IEEE80211_ELEMID_FHPARMS:
	case IEEE80211_ELEMID_DSPARMS:
	case IEEE80211_ELEMID_CFPARMS:
	case IEEE80211_ELEMID_TIM:
	case IEEE80211_ELEMID_IBSSPARMS:
	case IEEE80211_ELEMID_COUNTRY:
	case IEEE80211_ELEMID_REQINFO:
	case IEEE80211_ELEMID_CHALLENGE:
	case IEEE80211_ELEMID_PWRCNSTR:
	case IEEE80211_ELEMID_PWRCAP:
	case IEEE80211_ELEMID_TPCREQ:
	case IEEE80211_ELEMID_TPCREP:
	case IEEE80211_ELEMID_SUPPCHAN:
	case IEEE80211_ELEMID_CHANSWITCHANN:
	case IEEE80211_ELEMID_MEASREQ:
	case IEEE80211_ELEMID_MEASREP:
	case IEEE80211_ELEMID_QUIET:
	case IEEE80211_ELEMID_IBSSDFS:
	case IEEE80211_ELEMID_ERP:
	case IEEE80211_ELEMID_RSN:
	case IEEE80211_ELEMID_XRATES:
	case IEEE80211_ELEMID_TPC:
	case IEEE80211_ELEMID_CCKM:
		return true;
	default:
		return false;
	}
}

static enum qlink_ie_handling_action
qlink_ie_app_handle(struct net_device *dev,
		    u32 frame_type,
		    const struct ieee80211_ie *ie)
{
	bool btm;

	if (qlink_ie_is_sys(ie->id))
		return QLINK_IE_HANDLING_ACTION_DROP;

	switch (ie->id) {
	case IEEE80211_ELEMID_EXTCAP:
		if (ie->len >= 3) {
			btm = !!(ie->info[2] & IEEE80211_EXTCAP_BTM);
			if (qlink_wifi_updparam(dev,
						IEEE80211_PARAM_80211V_BTM,
						btm))
				return QLINK_IE_HANDLING_ACTION_ERROR;
		}
		/* fall through */
	default:
		return QLINK_IE_HANDLING_ACTION_KEEP;
	}
}

#define IEEE80211_RSN_IE_MIN_LEN	10

static void qlink_ie_mgmt_process_rsn(struct ieee80211vap *vap, const u8 *ie,
				      unsigned int len)
{
	unsigned int n;
	u16 val;

	if (len < IEEE80211_RSN_IE_MIN_LEN) {
		pr_warn("RSN is too short len=%u", len);
		return;
	}

	/* RSN version */
	ie += 2;
	len -= 2;
	/* multicast/group cipher */
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
	ie += n * 4;
	len -= n * 4;

	/* key management algorithms */
	n = get_unaligned_le16(ie);
	ie += 2;
	len -= 2;
	if (len < n * 4) {
		pr_warn("key mgmt list corrupted\n");
		return;
	}
	ie += n * 4;
	len -= n * 4;

	/* optional RSN capabilities */
	if (len < 2)
		return;

	val = get_unaligned_le16(ie);
	pr_info("%s: set RSNCAPS=0x%x\n", vap->iv_dev->name, val);
	qlink_wifi_setparam(vap->iv_dev, IEEE80211_PARAM_RSNCAPS, val);
}

void qlink_ie_mgmt_process(struct ieee80211vap *vap, const u8 *buf, size_t len)
{
	const struct ieee80211_ie *ie = (void *)buf;

	while (len >= sizeof(*ie)) {
		size_t ie_elem_len = sizeof(*ie) + ie->len;

		if (unlikely(len < ie_elem_len)) {
			pr_warn("malformed IE 0x%.2X; LEN: %u\n", ie->id, ie->len);
			return;
		}

		switch (ie->id) {
		case IEEE80211_ELEMID_RSN:
			qlink_ie_mgmt_process_rsn(vap, ie->info, ie->len);
			break;
		default:
			break;
		}

		len -= ie_elem_len;
		ie = (const struct ieee80211_ie *)(ie->info + ie->len);
	}
}

int qlink_ie_mgmt_handle_appie(struct qlink_bss *bss, u32 frame_type, const u8 *buf, size_t len)
{
	struct net_device *dev = bss->dev;
	const struct ieee80211_ie *ie = (void *)buf;
	u8 *res_buf = NULL;
	size_t res_buf_pos = 0;
	int ret;

	if (len == 0) {
		pr_debug("resetting 0x%X\n", frame_type);
		return qlink_wifi_set_appie(dev, frame_type, NULL, 0);
	}

	while (len >= sizeof(*ie)) {
		size_t ie_elem_len = sizeof(*ie) + ie->len;

		if (unlikely(len < ie_elem_len)) {
			pr_warn("malformed IE 0x%.2X; LEN: %u\n", ie->id, ie->len);
			ret = -EINVAL;
			goto out;
		}

		switch (qlink_ie_app_handle(dev, frame_type, ie)) {
		case QLINK_IE_HANDLING_ACTION_DROP:
			break;
		case QLINK_IE_HANDLING_ACTION_KEEP:
			if (!res_buf) {
				res_buf = kmalloc(IEEE80211_APPIE_MAX, GFP_KERNEL);

				if (!res_buf)
					return -ENOMEM;
			}

			if (unlikely((res_buf_pos + ie_elem_len) > IEEE80211_APPIE_MAX)) {
				pr_warn("type: 0x%X; too big IE buf: %u\n",
					frame_type, res_buf_pos + ie_elem_len);
				ret = -E2BIG;
				goto out;
			}

			memcpy(res_buf + res_buf_pos, ie, ie_elem_len);
			res_buf_pos += ie_elem_len;
			break;
		case QLINK_IE_HANDLING_ACTION_ERROR:
			ret = -EINVAL;
			pr_warn("type: 0x%X; error during handling IE 0x%.2X; LEN: %u\n",
				frame_type, ie->id, ie->len);
			goto out;
		}

		len -= ie_elem_len;
		ie = (const struct ieee80211_ie *)(ie->info + ie->len);
	}

	if (len != 0) {
		ret = -EINVAL;
		pr_warn("type: 0x%X; malformed IEs buf; bytes left: %u\n",
			frame_type, len);
		goto out;
	}

	ret = qlink_wifi_set_appie(dev, frame_type, res_buf, res_buf_pos);

	pr_debug("type: 0x%X; ret: %d; in bytes: %u; out bytes: %u\n",
		 frame_type, ret, len, res_buf_pos);

out:
	kfree(res_buf);
	return ret;
}
