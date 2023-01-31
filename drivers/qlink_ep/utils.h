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

#ifndef _QLINK_EP_UTILS_H_
#define _QLINK_EP_UTILS_H_

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>

#include "qlink.h"
#include "qlink_priv.h"

struct ieee80211_channel;

void qlink_dump_tlvs(const u8 *tlv_buf, size_t buf_len);
void qlink_dump_ies(const u8 *ie_buf, size_t buf_len, int dump_val);
void qlink_dump_ht_caps(const struct ieee80211_ht_cap *ht_conf);
void qlink_dump_vht_caps(const struct ieee80211_vht_cap *vht_conf);

int qlink_vap_chandef_fill(struct ieee80211vap *vap, struct qlink_chandef *chan);
const char *qlink_chan_identify_band(struct ieee80211_channel *c,
				     unsigned int bw, bool vht_en, bool ht_en);
enum qlink_cmd_result qlink_utils_retval2q(int retval);
int qlink_chan_q2ieee(struct ieee80211com *ic,
		      const struct qlink_chandef *chdef,
		      struct ieee80211_channel **ieee_chan,
		      unsigned int *bw);
int qlink_utils_is_channel_usable(struct ieee80211com *ic,
				  struct ieee80211_channel *chan,
				  int bw);
void qlink_utils_chandef_set(struct ieee80211com *ic,
			    struct net_device *ndev,
			    struct ieee80211_channel *c,
			    unsigned int bw,
			    const char *mode);
static inline void ether_addr_copy(u8 *dst, const u8 *src)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	*(u32 *)dst = *(const u32 *)src;
	*(u16 *)(dst + 4) = *(const u16 *)(src + 4);
#else
	u16 *a = (u16 *)dst;
	const u16 *b = (const u16 *)src;

	a[0] = b[0];
	a[1] = b[1];
	a[2] = b[2];
#endif
}

static inline void eth_broadcast_addr(u8 *addr)
{
	memset(addr, 0xff, ETH_ALEN);
}

static inline u8 *qlink_encode_tlv_u32(u8 *buf, u16 tlv_id, u32 value)
{
	struct qlink_tlv_hdr *header = (struct qlink_tlv_hdr *)buf;

	header->type = cpu_to_le16(tlv_id);
	header->len = cpu_to_le16(sizeof(value));
	memcpy(header->val, (void *)&value, sizeof(value));
	buf += sizeof(struct qlink_tlv_hdr) + sizeof(value);
	return buf;
}

static inline u8 *qlink_encode_tlv_str(u8 *buf, u16 tlv_id, const char *str, size_t len)
{
	struct qlink_tlv_hdr *header = (struct qlink_tlv_hdr *)buf;

	header->type = cpu_to_le16(tlv_id);
	header->len = cpu_to_le16(len);
	memcpy(header->val, str, len);
	buf += sizeof(struct qlink_tlv_hdr) + round_up(len, QLINK_ALIGN);
	return buf;
}

static inline u8 *qlink_append_tlv_buf(u8 *buf, u16 tlv_id, u8 **data, u16 data_size)
{
	struct qlink_tlv_hdr *header = (struct qlink_tlv_hdr *)buf;

	header->type = cpu_to_le16(tlv_id);
	header->len = cpu_to_le16(data_size);
	*data = header->val;
	return buf + sizeof(*header) + round_up(data_size, QLINK_ALIGN);
}

static inline void qlink_utils_set_arr_bit(u8 *arr, unsigned int bit)
{
	unsigned int idx = bit / BITS_PER_BYTE;
	u8 mask = 1 << (bit - (idx * BITS_PER_BYTE));

	arr[idx] |= mask;
}

void qlink_mac_bf_config(struct net_device *dev, bool bfon);
void qlink_mac_mu_config(struct net_device *dev, bool enable);

bool qlink_utils_chandef_identical(struct qlink_chandef *old,
				 struct qlink_chandef *new);

/*
 * Modifiable HT/VHT capabilities
 */

void qlink_wmac_info_htcap_mod_mask_fill(struct ieee80211_ht_cap *mask,
					 u8 rx_chains);
void qlink_wmac_info_vhtcap_mod_mask_fill(struct ieee80211_vht_cap *mask,
					  u8 rx_chains, u8 tx_chains);

/*
 * Convert HT/VHT caps: QTN to IEEE80211
 */

void qlink_htcap_to_ht_cap(const struct ieee80211_htcap *htcap,
			   u32 vap_ht_flags,
			   struct ieee80211_ht_cap *ht_cap);
void qlink_vhtcap_to_vht_cap(const struct ieee80211_vhtcap *vhtcap,
			     enum ieee80211_vht_nss tx_max_nss,
			     enum ieee80211_vht_nss rx_max_nss,
			     u32 vap_vht_flags,
			     struct ieee80211_vht_cap *vht_cap);

/*
 * Apply HT/VHT configuration
 */

int qlink_bss_ht_conf_apply(const struct qlink_bss *bss,
			    const struct ieee80211_ht_cap *ht_conf,
			    int *sgi_20,
			    int *sgi_40,
			    int *ldpc,
			    int *stbc);
int qlink_bss_vht_conf_apply(const struct qlink_bss *bss,
			     const struct ieee80211_vht_cap *vht_conf,
			     int *sgi_80,
			     int *ldpc,
			     int *stbc,
			     int is_24g_band);
int qlink_bss_global_conf_apply(const struct qlink_bss *bss,
				int sgi,
				int ldpc,
				int stbc);

void qlink_bss_connection_drop(struct qlink_bss *bss);
void qlink_mac_phyparams_apply_default(struct qlink_mac *mac);

int qlink_utils_scan_before_connect(struct ieee80211vap *vap, u8 *ssid,
				   size_t ssid_len, u32 center_freq);

static inline size_t qlink_mac_bss_added_count(const struct qlink_mac *mac)
{
	size_t i;
	size_t bss_added = 0;

	for (i = 0; i < QTNF_MAX_BSS_NUM; i++)
		if (bss_has_status(&mac->bss[i], QLINK_BSS_ADDED))
			bss_added++;

	return bss_added;
}

static inline void
qlink_merge_bits(void *dest, const void *src, const void *mask, int len)
{
	uint8_t *p1, *p2, *p3;
	int i;

	p1 = (uint8_t *)dest;
	p2 = (uint8_t *)src;
	p3 = (uint8_t *)mask;

	for (i = 0; i < len; i++) {
		if (p3[i])
			p1[i] = (p1[i] & ~p3[i]) | (p2[i] & p3[i]);
	}
}

enum ieee80211_mfp_capabilities qlink_utils_mfp_conv(u8 mfp);

#endif /* _QLINK_EP_UTILS_H_ */
