#ifndef _QLINK_EP_DRIVER_OPS_H_
#define _QLINK_EP_DRIVER_OPS_H_

#include <linux/netdevice.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>

int qlink_wext_ioctl(struct net_device *dev, unsigned int cmd, struct iwreq *iwr);

int qlink_wifi_getparam(struct net_device *dev, const int param, int *p_value);
int qlink_wifi_setparam(struct net_device *dev, const int param, const int value);
int qlink_wifi_updparam(struct net_device *dev, const int param, const int value);
int qlink_wifi_setpriv(struct net_device *dev, int op, const void *data, int len);
int qlink_wifi_get_802_11_mode(struct net_device *dev, char *wifi_802_11_mode, int max_mode_len);
int qlink_wifi_set_802_11_mode(struct net_device *dev, const char *wifi_802_11_mode);
int qlink_wifi_set_cclass(struct net_device *dev, u8 class);
int qlink_phy_apply_rts_thre(struct net_device *dev, u32 rts_thresh);
int qlink_phy_apply_frag_thre(struct net_device *dev, u32 frag_thresh);
int qlink_phy_get_rts_thre(struct net_device *dev, int *rts_thresh);
int qlink_phy_get_frag_thre(struct net_device *dev, int *frag_thresh);
int qlink_phy_get_retry(struct net_device *dev, int *retry);
int qlink_wifi_set_ssid(struct net_device *dev, u8 *ssid, size_t len);
int qlink_wifi_set_rate(struct net_device *dev, s32 value, u8 fixed);
int qlink_wifi_set_sta_authorized(struct net_device *dev, u8 *sta_addr, u32 authorized);
int qlink_wifi_associate(struct net_device *dev, u8 *bssid);
int qlink_wifi_sta_deauth(struct net_device *dev, u8 *sta_addr, u8 reason_code);
int qlink_wifi_sta_disassoc(struct net_device *dev, u8 *sta_addr, u8 reason_code);
int qlink_wifi_set_appie(struct net_device *dev, u32 frmtype, const u8 *buf, size_t buf_len);
int qlink_wifi_set_opt_ie(struct net_device *dev, const u8 *ies, size_t ies_len);
int qlink_wifi_scan_ssid_clear(struct net_device *dev);
int qlink_wifi_scan_ssid_add(struct net_device *dev, u8 *ssid, u16 ssid_len);
int qlink_wifi_scan_freq_set(struct net_device *dev,
			     struct ieee80211_scan_freqs *scan_freqs);
int qlink_scs_ioctl(struct net_device *dev, uint32_t op, void *data, int len);
int qlink_wifi_scs_config(struct net_device *dev, unsigned int cmd, int val);
int qlink_phy_get_pta_param(struct net_device *dev, int param_id, int *param_val);
int qlink_phy_set_pta_param(struct net_device *dev, int param_id, int param_val);
int qlink_wowlan_config(struct net_device *dev, u32 enable, const u8 *pkt, int len);
int qlink_wifi_set_ampdu(struct net_device *dev, u8 ampdu);
int qlink_wifi_set_amsdu(struct net_device *dev, u8 amsdu);
int qlink_wifi_set_chan(struct net_device *dev, u16 ieee);
int qlink_wifi_init_txpwr_table(struct net_device *dev, unsigned int ieee, int pwr);
int qlink_wifi_set_reguatory_txpwr(struct net_device *dev, unsigned int ieee_start,
	unsigned int ieee_end, int pwr);

#endif /* _QLINK_EP_DRIVER_OPS_H_ */
