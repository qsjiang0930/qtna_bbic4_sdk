/*
 * hostapd / IEEE 802.11 authentication (ACL)
 * Copyright (c) 2003-2005, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef IEEE802_11_AUTH_H
#define IEEE802_11_AUTH_H

#ifdef CONFIG_QTNA_WIFI
#define MAC_OUI_LEN 3
#endif /* CONFIG_QTNA_WIFI */

enum {
	HOSTAPD_ACL_REJECT = 0,
	HOSTAPD_ACL_ACCEPT = 1,
	HOSTAPD_ACL_PENDING = 2,
	HOSTAPD_ACL_ACCEPT_TIMEOUT = 3
};

int hostapd_check_acl(struct hostapd_data *hapd, const u8 *addr,
		      struct vlan_description *vlan_id);
int hostapd_allowed_address(struct hostapd_data *hapd, const u8 *addr,
			    const u8 *msg, size_t len, u32 *session_timeout,
			    u32 *acct_interim_interval,
			    struct vlan_description *vlan_id,
			    struct hostapd_sta_wpa_psk_short **psk,
			    char **identity, char **radius_cui,
			    int is_probe_req);
int hostapd_acl_init(struct hostapd_data *hapd);
void hostapd_acl_deinit(struct hostapd_data *hapd);
void hostapd_free_psk_list(struct hostapd_sta_wpa_psk_short *psk);
void hostapd_acl_expire(struct hostapd_data *hapd);

#ifdef CONFIG_QTNA_WIFI
#ifdef CONFIG_SAE
void sae_faillist_remove_mac(struct hostapd_data *hapd, const u8 *addr);
void sae_faillist_deinit(struct hostapd_data *hapd);
void sae_blacklist_deinit(struct hostapd_data *hapd);
int sae_auth_blacklist_process(struct hostapd_data *hapd,
		const u8 *addr, const os_time_t lockout_period);
void sae_process_auth_failure(struct hostapd_data *hapd,
		const u8 *addr, const u32 max_fail_num, const os_time_t fail_period);
#endif /* CONFIG_SAE */
#endif /* CONFIG_QTNA_WIFI */

#endif /* IEEE802_11_AUTH_H */
