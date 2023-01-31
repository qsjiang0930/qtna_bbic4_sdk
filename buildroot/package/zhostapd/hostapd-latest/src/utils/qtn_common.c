/*SH1
 *******************************************************************************
 **                                                                           **
 **         Copyright (c) 2009 - 2018 Quantenna Communications, Inc.          **
 **                                                                           **
 **  File        : qtn_common.c                                               **
 **  Description :                                                            **
 **                                                                           **
 *******************************************************************************
 **  Copyright 1992-2014 The FreeBSD Project. All rights reserved.            **
 **  Redistribution and use in source and binary forms, with or without       **
 **  modification, are permitted provided that the following conditions       **
 **  are met:                                                                 **
 **  1. Redistributions of source code must retain the above copyright        **
 **     notice, this list of conditions and the following disclaimer.         **
 **  2. Redistributions in binary form must reproduce the above copyright     **
 **     notice, this list of conditions and the following disclaimer in the   **
 **     documentation and/or other materials provided with the distribution.  **
 **  3. The name of the author may not be used to endorse or promote products **
 **     derived from this software without specific prior written permission. **
 **                                                                           **
 **  Alternatively, this software may also be distributed under the terms of  **
 **  the GNU General Public License ("GPL") version 2, or (at your option)    **
 **  any later version as published by the Free Software Foundation.          **
 **                                                                           **
 *******************************************************************************
 EH1
 */

#ifdef CONFIG_QTNA_WIFI
#include "includes.h"
#include "common.h"
#include "crypto/md5.h"
#include "crypto/crypto.h"

#include "qtn_common.h"
static int __qtn_md5_sum(const char *passphrase, int len, char *res_buf)
{
	int i;
	char *psk_use;
	u8 hex_buf[MD5_MAC_LEN];
	const u8 *passphrase_vec[2];
	size_t len_vec[2];
	char buf_use[QTN_MD5_STR_BUF_LEN] = {0};
	char *pos, *end;
	int ret;

	psk_use = (char *)os_malloc(len+1);
	if (!psk_use) {
		wpa_printf(MSG_DEBUG, "%s: malloc fail", __func__);
		return -1;
	}

	memcpy(psk_use, passphrase, len);
	psk_use[len] = '\n';
	passphrase_vec[0] = (u8 *)psk_use;
	len_vec[0] = len + 1;

	if (md5_vector(1, passphrase_vec, len_vec, hex_buf) < 0) {
		wpa_printf(MSG_DEBUG, "%s: md5_vector fail", __func__);
		os_free(psk_use);
		return -1;
	}

	pos = buf_use;
	end = pos + sizeof(buf_use);
	for (i = 0; i < MD5_MAC_LEN; i++) {
		ret = os_snprintf(pos, (end - pos), "%02x", hex_buf[i]);
		if (ret < 0 || ret > (end - pos)) {
			wpa_printf(MSG_DEBUG, "%s: hex to str error", __func__);
			os_free(psk_use);
			return -1;
		}
		pos += ret;
	}
	memcpy(res_buf, buf_use, (QTN_MD5_STR_BUF_LEN - 1));
	os_free(psk_use);

	return 0;
}


int qtn_util_md5_convert_passphrase(const string_64 psk_web, string_64 pre_shared_key)
{
	int key_size;
	char passphrase_md5_res[QTN_MD5_STR_BUF_LEN] = {0};

	if (!psk_web || !pre_shared_key)
		return -1;

	key_size = os_strlen(psk_web);
	if (key_size < 8 || key_size > 64)
		return -1;

	memset(pre_shared_key, 0, sizeof(string_64));
	if (__qtn_md5_sum(psk_web, key_size, passphrase_md5_res) < 0) {
		wpa_printf(MSG_DEBUG, "%s: failed", __func__);
		return -1;
	}
	wpa_printf(MSG_DEBUG, "passphrase after md5 function is %s", passphrase_md5_res);

	if (key_size <= (QTN_MD5_STR_BUF_LEN - 1)) {
		memcpy(pre_shared_key, passphrase_md5_res, key_size);
	} else {
		memcpy(pre_shared_key, passphrase_md5_res, (QTN_MD5_STR_BUF_LEN - 1));
		strncpy(pre_shared_key + (QTN_MD5_STR_BUF_LEN - 1),
				psk_web + (QTN_MD5_STR_BUF_LEN - 1),
				key_size - (QTN_MD5_STR_BUF_LEN - 1));
	}

	return 0;
}
#endif /* CONFIG_QTNA_WIFI */

