/****************************************************************************
*
* Copyright (c) 2017  Quantenna Communications, Inc.
*
* Permission to use, copy, modify, and/or distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
* SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
* RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
* NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
* USE OR PERFORMANCE OF THIS SOFTWARE.
*
*****************************************************************************/

#ifndef QTN_DEFCONF_H_
#define QTN_DEFCONF_H_

int qtn_defconf_vht_dut_sta(const char* ifname);
int qtn_defconf_vht_dut_ap(const char* ifname);
int qtn_defconf_pmf_dut(const char* ifname);
int qtn_defconf_hs2_dut(const char* ifname);
int qtn_defconf_11n_dut(const char* ifname);
int qtn_defconf_tdls_dut(const char* ifname);

#endif /* QTN_DEFCONF_H_ */
