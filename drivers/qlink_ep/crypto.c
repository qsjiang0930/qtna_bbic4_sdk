/*
 * AES-128-CMAC with TLen 16 for IEEE 802.11w BIP
 *
 * Copyright (c) 2008 Jouni Malinen <j@w1.fi>
 * Copyright (c) 2019 Quantenna Communications, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt)	"%s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/ieee80211.h>

#include "qlink_priv.h"

#define AES_BLOCK_SIZE 16
#define AES_CMAC_KEY_LEN 16
#define CMAC_TLEN 8 /* CMAC TLen = 64 bits (8 octets) */
#define AAD_LEN 20

static void gf_mulx(u8 *pad)
{
	int i, carry;

	carry = pad[0] & 0x80;
	for (i = 0; i < AES_BLOCK_SIZE - 1; i++)
		pad[i] = (pad[i] << 1) | (pad[i + 1] >> 7);
	pad[AES_BLOCK_SIZE - 1] <<= 1;
	if (carry)
		pad[AES_BLOCK_SIZE - 1] ^= 0x87;
}


static void aes_128_cmac_vector(struct crypto_cipher *tfm, u8 *scratch,
				size_t num_elem,
				const u8 *addr[], const size_t *len, u8 *mac)
{
	u8 *cbc, *pad;
	const u8 *pos, *end;
	size_t i, e, left, total_len;

	cbc = scratch;
	pad = scratch + AES_BLOCK_SIZE;

	memset(cbc, 0, AES_BLOCK_SIZE);

	total_len = 0;
	for (e = 0; e < num_elem; e++)
		total_len += len[e];
	left = total_len;

	e = 0;
	pos = addr[0];
	end = pos + len[0];

	while (left >= AES_BLOCK_SIZE) {
		for (i = 0; i < AES_BLOCK_SIZE; i++) {
			cbc[i] ^= *pos++;
			if (pos >= end) {
				e++;
				pos = addr[e];
				end = pos + len[e];
			}
		}
		if (left > AES_BLOCK_SIZE)
			crypto_cipher_encrypt_one(tfm, cbc, cbc);
		left -= AES_BLOCK_SIZE;
	}

	memset(pad, 0, AES_BLOCK_SIZE);
	crypto_cipher_encrypt_one(tfm, pad, pad);
	gf_mulx(pad);

	if (left || total_len == 0) {
		for (i = 0; i < left; i++) {
			cbc[i] ^= *pos++;
			if (pos >= end) {
				e++;
				pos = addr[e];
				end = pos + len[e];
			}
		}
		cbc[left] ^= 0x80;
		gf_mulx(pad);
	}

	for (i = 0; i < AES_BLOCK_SIZE; i++)
		pad[i] ^= cbc[i];
	crypto_cipher_encrypt_one(tfm, pad, pad);
	memcpy(mac, pad, CMAC_TLEN);
}


static void
ieee80211_aes_cmac(struct crypto_cipher *tfm, const u8 *aad, const u8 *data,
		   size_t data_len, u8 *mic)
{
	u8 scratch[2 * AES_BLOCK_SIZE];
	const u8 *addr[3];
	size_t len[3];
	u8 zero[CMAC_TLEN];

	memset(zero, 0, CMAC_TLEN);
	addr[0] = aad;
	len[0] = AAD_LEN;
	addr[1] = data;
	len[1] = data_len - CMAC_TLEN;
	addr[2] = zero;
	len[2] = CMAC_TLEN;

	aes_128_cmac_vector(tfm, scratch, 3, addr, len, mic);
}

static inline void bip_ipn_swap(u8 *d, const u8 *s)
{
	*d++ = s[5];
	*d++ = s[4];
	*d++ = s[3];
	*d++ = s[2];
	*d++ = s[1];
	*d = s[0];
}

static void bip_aad(const u8 *data, u8 *aad)
{
	/* BIP AAD: FC(masked) || A1 || A2 || A3 */

	/* FC type/subtype */
	aad[0] = data[0];

	/* Mask FC Retry, PwrMgt, MoreData flags to zero */
	aad[1] = data[1] & ~(BIT(4) | BIT(5) | BIT(6));

	/* A1 || A2 || A3 */
	memcpy(aad + 2, data + 4, 3 * ETH_ALEN);
}

int qlink_mgmt_bip_is_valid(struct qlink_bss *bss, const u8 *data, size_t len)
{
	struct ieee80211_mmie *mmie;
	u8 ipnc[6], ipnn[8];
	u8 aad[20], mic[8];
	u8 key_idx;

	if (len < 24 + sizeof(*mmie)) {
		pr_warn("BIP frame: invalid length %u\n", len);
		return 0;
	}

	mmie = (struct ieee80211_mmie *)(data + len - sizeof(*mmie));
	pr_debug("MMIE: EID:%u LEN:%u KEY_ID:%u IPN:%pM\n",
		 mmie->element_id, mmie->length, mmie->key_id,
		 mmie->sequence_number);

	if (mmie->element_id != WLAN_EID_MMIE || mmie->length != sizeof(*mmie) - 2) {
		pr_warn("BIP frame: missing MMIE\n");
		return 0;
	}

	if (mmie->key_id < 4 || mmie->key_id > 5) {
		pr_warn("BIP frame: unexpected MMIE key ID %u\n", mmie->key_id);
		return 0;
	}

	key_idx = mmie->key_id - 4;

	if (!bss->igtk[key_idx]) {
		pr_warn("No IGTK %u known to validate BIP frame\n", mmie->key_id);
		return 0;
	}

	bip_ipn_swap(ipnn, mmie->sequence_number);
	bip_ipn_swap(ipnc, bss->igtk_ipn[key_idx]);

	if (memcmp(ipnn, ipnc, 6) <= 0) {
		pr_warn("BIP frame replay detected: ipn curr [%pM], ipn recv [%pM]\n",
			ipnc, ipnn);
		return 0;
	}

	bip_aad(data, aad);
	ieee80211_aes_cmac(bss->igtk[key_idx], aad, data + 24, len - 24, mic);
	if (memcmp(mic, mmie->mic, sizeof(mmie->mic)) != 0) {
		pr_warn("BIP frame: mic error detected\n");
		return 0;
	}

	memcpy(bss->igtk_ipn[key_idx], mmie->sequence_number, 6);

	return 1;
}
