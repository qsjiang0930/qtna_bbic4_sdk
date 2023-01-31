#ifndef QTN_DEFCONF_H_
#define QTN_DEFCONF_H_

#define QTN_DEFCONF_CMDBUF_LEN		512

enum {
	DEFAULT_DPP_24G_CHANNEL = 6,
	DEFAULT_VHT_CHANNEL = 36,
	DEFAULT_MAP_HT_CHANNEL  = 6,
	DEFAULT_MAP_VHT_CHANNEL = 36,
	DEFAULT_DPP_PKEX_CHANNEL = 44
};

int qtn_defconf_mbo_dut_ap_all(void);
int qtn_defconf_vht_testbed_sta(const char* ifname);
int qtn_defconf_vht_testbed_ap(const char* ifname);
int qtn_defconf_vht_dut_sta(const char* ifname);
int qtn_defconf_vht_dut_ap(const char* ifname);
int qtn_defconf_pmf_dut(const char* ifname);
int qtn_defconf_hs2_dut(const char* ifname);
int qtn_defconf_11n_dut(const char* ifname);
int qtn_defconf_11n_testbed(const char* ifname);
int qtn_defconf_tdls_dut(const char* ifname);
int qtn_defconf_wpa3_dut_ap(const char *ifname);
int qtn_defconf_wpa3_dut_sta(const char *ifname);
int qtn_defconf_dpp(const char *ifname);
int qtn_defconf_easymesh(const char *ifname);

#endif /* QTN_DEFCONF_H_ */
