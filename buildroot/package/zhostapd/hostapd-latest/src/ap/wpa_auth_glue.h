/*
 * hostapd / WPA authenticator glue code
 * Copyright (c) 2002-2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPA_AUTH_GLUE_H
#define WPA_AUTH_GLUE_H

int hostapd_setup_wpa(struct hostapd_data *hapd);
void hostapd_reconfig_wpa(struct hostapd_data *hapd);
void hostapd_deinit_wpa(struct hostapd_data *hapd);
#ifdef CONFIG_QTNA_WIFI
#ifdef CONFIG_IEEE80211R
int hostapd_reconfig_rrb_socket(struct hostapd_data *hapd);
#endif /* CONFIG_IEEE80211R */
#endif /* CONFIG_QTNA_WIFI */

#endif /* WPA_AUTH_GLUE_H */
