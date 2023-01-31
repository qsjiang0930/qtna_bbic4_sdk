/****************************************************************************
*
* Copyright (c) 2015  Quantenna Communications, Inc.
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

#ifndef QTN_DUT_COMMON_H_
#define QTN_DUT_COMMON_H_

#define	SM(_v, _f)	(((_v) << _f##_S) & _f)
#define	MS(_v, _f)	(((_v) & _f) >> _f##_S)

#define QTN_BW_RTS_SIG         0x030
#define QTN_BW_RTS_SIG_S       4
#define QTN_BW_RTS_SIG_DYN     0x001
#define QTN_BW_RTS_SIG_NFORCE  0x100
#define QTN_BW_RTS_FIXED_BW	0x1000

#define QTN_MBO_TEST_CLI	"/usr/sbin/qsl_cli"
#define QTN_UBUS_TEST_CLI	"/usr/bin/ubus"

#define QTN_SSH_CMD_BUF	(48)
#define QTN_MAX_CMD_BUF	(1024)
#define QTN_MAP_MAX_BUF	(3*1024)

char g_cmdbuf[QTN_MAX_CMD_BUF];
struct qtn_npu_config {
	char br_ipaddr[sizeof("xxx.xxx.xxx.xxx")];
	unsigned char al_macaddr[6];
	char ssh_cli[QTN_SSH_CMD_BUF];
	int npu_topology;
};

#define QTN_EXTRTL_CONFIG	"/bin/qweconfig"
#define QTN_EXTRTL_ACTION	"/bin/qweaction"

#define QTN_MAX_BUF_LEN		512

#define QTN_5G_CHAN_START		36
#define QTN_5G_CHAN_END			161
#define QTN_24G_CHAN_END		11
#define QTN_5GCHAN_TO_FREQ(_ch)		((5000) + (_ch * 5))
#define QTN_24GCHAN_TO_FREQ(_ch)	((2407) + (_ch * 5))

struct qtn_dut_dpp_config {
	unsigned short bs_method;
	unsigned short config_id;
	unsigned short role;
	unsigned short peer_bootstrap;
	unsigned short local_bootstrap;
	struct qcsapi_dpp_bss_config *bss_conf;
	char peer_uri[QTN_MAX_BUF_LEN];
	char local_uri[QTN_MAX_BUF_LEN];
};

struct qtn_dut_config {
	char ifname[8];
	unsigned char bws_enable;
	unsigned char bws_dynamic;
	unsigned char force_rts;
	unsigned char update_settings;
	unsigned char bws;
	struct qtn_dut_dpp_config *dpp_config;
};

void qtn_dut_reset_config(struct qtn_dut_config *conf);
struct qtn_dut_config * qtn_dut_get_config(const char* ifname);

void qtn_dut_make_response_none(int tag, int status, int err_code, int *out_len,
	unsigned char *out_buf);

void qtn_dut_make_response_macaddr(int tag, int status, int err_code, const unsigned char *macaddr,
	int *out_len, unsigned char *out_buf);

void qtn_dut_make_response_vendor_info(int tag, int status, int err_code,
	const char *vendor_info, int *out_len, unsigned char *out_buf);
void qtn_dut_make_response_str(int tag, int status, int err_code, char *res,
					int res_len, int *out_len, unsigned char *out_buf);
void qtn_dut_make_response_mid(int tag, int status, int err_code, char *mid,
	int *out_len, unsigned char *out_buf);

int qtn_parse_mac(const char *mac_str, unsigned char *mac);

void qtn_set_rts_settings(const char* ifname, struct qtn_dut_config* conf);
const char* qtn_get_sigma_interface(void);
const char* qtn_get_sigma_vap_interface(unsigned vap_index);
int set_tx_bandwidth(const char* ifname, unsigned bandwidth);
int qtn_set_rf_enable(int enable);
int qtn_set_mu_enable(int enable);
void qtn_bring_up_radio_if_needed(void);

void qtn_check_defer_mode_apply_config(const char* ifname);

#endif				/* QTN_DUT_COMMON_H_ */
