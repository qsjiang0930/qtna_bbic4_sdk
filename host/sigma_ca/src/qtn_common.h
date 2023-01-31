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

#ifndef QTN_COMMON_H_
#define QTN_COMMON_H_

#define CA_VERSION	"3.0"

enum {
	QTN_VERSION_LEN = 32,
	QTN_PROGRAMM_NAME_LEN = 16,
	QTN_IP_LEN = sizeof("xxx.xxx.xxx.xxx"),
	QTN_PASSWORD_LEN = 128,
	QTN_INTERFACE_LEN = 32,
	QNT_SSID_LEN = 64,
	QNT_ENCRYPTION_LEN = 32,
	QNT_NS_LEN = 64,
	QTN_MX_INTERFACES = 4,
	QTN_INTERFACE_LIST_LEN = QTN_INTERFACE_LEN * QTN_MX_INTERFACES,
	QTN_KEYMGNT_LEN = 64,
	QTN_COUNTRY_CODE_LEN = 16,
	QTN_SCAN_TIMEOUT_SEC = 100,
};

int qtn_parse_mac(const char *mac_str, unsigned char *mac);
const char* qtn_get_sigma_interface(void);
const char* qtn_get_sigma_vap_interface(unsigned vap_index);
int qtn_set_tx_bandwidth(const char* ifname, unsigned bandwidth);
int qtn_set_rf_enable(int enable);
void qtn_bring_up_radio_if_needed(void);
void qtn_check_defer_mode_apply_config(const char* ifname);
int qtn_run_script(const char* script_name, const char* arg1);

#endif	/* QTN_COMMON_H_ */
