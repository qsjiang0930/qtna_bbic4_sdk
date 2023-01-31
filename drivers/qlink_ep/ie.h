/**
 * Copyright (c) 2015-2016 Quantenna Communications, Inc.
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

#ifndef QLINK_EP_IE_H_
#define QLINK_EP_IE_H_

#include <linux/types.h>
#include <asm/unaligned.h>

#include "qlink_priv.h"

enum qlink_ie_handling_action {
	QLINK_IE_HANDLING_ACTION_KEEP,
	QLINK_IE_HANDLING_ACTION_DROP,
	QLINK_IE_HANDLING_ACTION_ERROR
};

void qlink_ie_mgmt_process(struct ieee80211vap *vap, const u8 *buf, size_t len);
int qlink_ie_mgmt_handle_appie(struct qlink_bss *bss, u32 frame_type, const u8 *buf, size_t len);

static inline size_t qlink_ieee_tlv_len(const u8 *ie_buf)
{
	const struct ieee80211_ie *ie = (const struct ieee80211_ie *)ie_buf;

	return ie ? ie->len + sizeof(struct ieee80211_ie) : 0;
}

static inline int qlink_add_tlv_ie(u8 *tlv_data, const u8 *ie_buf, __le16 *tlv_len)
{
	const struct ieee80211_ie *ie = (struct ieee80211_ie *)ie_buf;
	size_t ie_len = 0;

	if (ie) {
		ie_len = ie->len + sizeof(struct ieee80211_ie);
		memcpy(tlv_data, ie, ie_len);
		put_unaligned_le16(get_unaligned_le16(tlv_len) + ie_len, tlv_len);
	}
	return ie_len;
}

#endif /* QLINK_EP_IE_H_ */
