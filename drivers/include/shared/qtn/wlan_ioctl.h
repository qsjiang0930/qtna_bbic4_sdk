/**
 * Copyright (c) 2014 - 2017 Quantenna Communications Inc
 * All Rights Reserved
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 **/

#ifndef __WLAN_IOCTL_H__
#define __WLAN_IOCTL_H__

#define IEEE80211_ADDR_LEN	6

enum ieee80211_wifi_mode {
	IEEE80211_WIFI_MODE_NONE = 0,
	IEEE80211_WIFI_MODE_A,
	IEEE80211_WIFI_MODE_B,
	IEEE80211_WIFI_MODE_G,
	IEEE80211_WIFI_MODE_NA,
	IEEE80211_WIFI_MODE_NG,
	IEEE80211_WIFI_MODE_AC,
	IEEE80211_WIFI_MODE_MAX,
};

#define WLAN_WIFI_MODES_STRINGS		{		\
	[IEEE80211_WIFI_MODE_NONE] = "-",		\
	[IEEE80211_WIFI_MODE_A] = "a",			\
	[IEEE80211_WIFI_MODE_B] = "b",			\
	[IEEE80211_WIFI_MODE_G] = "g",			\
	[IEEE80211_WIFI_MODE_NA] = "na",		\
	[IEEE80211_WIFI_MODE_NG] = "ng",		\
	[IEEE80211_WIFI_MODE_AC] = "ac",		\
}

#define IEEE80211_WIFI_MODE_LEGACY(mode)	((mode == IEEE80211_WIFI_MODE_A)	\
						|| (mode == IEEE80211_WIFI_MODE_G)	\
						|| (mode == IEEE80211_WIFI_MODE_B))


#define IEEE80211_HTCAP_IE_LENGTH	28
#define IEEE80211_VHTCAP_IE_LENGTH	14

struct ieee8011req_sta_tput_caps {
	uint8_t	macaddr[IEEE80211_ADDR_LEN];
	uint8_t	mode;
	uint8_t	htcap_ie[IEEE80211_HTCAP_IE_LENGTH];
	uint8_t	vhtcap_ie[IEEE80211_VHTCAP_IE_LENGTH];
};

#ifndef USHRT_MAX
#define USHRT_MAX	((uint16_t)(~0U))
#endif

/**@addtogroup ScanAPIs
 *@{*/
/**
 * \brief SSID configuration options.
 */
typedef enum {
	/**
	 * Remove the active SSID.
	 */
	IEEE80211_SSID_OP_DEL = 0,

	/**
	 * Set the active SSID.
	 */
	IEEE80211_SSID_OP_SET = 0x01,

	/**
	 * Add an SSID to the scan list.
	 */
	IEEE80211_SSID_OP_SCAN_ADD = USHRT_MAX - 2,

	/**
	 * Remove an SSID from the scan list.
	 */
	IEEE80211_SSID_OP_SCAN_REMOVE = USHRT_MAX - 1,

	/**
	 * Clear all SSIDs from the scan list.
	 */
	IEEE80211_SSID_OP_SCAN_CLEAR = USHRT_MAX,
} ieee80211_scan_cfg;

#define IEEE80211_ACTIVE_SCAN_MAX_SSID	16
#define IEEE80211_SSID_LEN 32

struct qtn_ssid_entry {
	uint8_t ssid[IEEE80211_SSID_LEN];
};

struct qtn_ssid_list {
	uint16_t cnt;
	struct qtn_ssid_entry ssid_entry[IEEE80211_ACTIVE_SCAN_MAX_SSID];
};
/**@}*/

enum ieee80211_wifi_cfg_4addr_mode {
	IEEE80211_CFG_4ADDR_MODE_MIN = 0,
	IEEE80211_CFG_4ADDR_MODE_DISABLE = 0,
	IEEE80211_CFG_4ADDR_MODE_ENABLE = 1,
	IEEE80211_CFG_4ADDR_MODE_ENABLE_AMSDU = 2,
	IEEE80211_CFG_4ADDR_MODE_MAX = IEEE80211_CFG_4ADDR_MODE_ENABLE_AMSDU
};

#ifndef USHRT_MAX
#define USHRT_MAX	((uint16_t)(~0U))
#endif

#endif /* __WLAN_IOCTL_H__ */
