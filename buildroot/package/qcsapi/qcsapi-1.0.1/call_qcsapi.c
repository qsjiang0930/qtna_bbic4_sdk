/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2009 - 2015 Quantenna Communications, Inc.          **
**                                                                           **
**  File        : call_qcsapi.c                                              **
**  Description :                                                            **
**                                                                           **
*******************************************************************************
**                                                                           **
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
**  Alternatively, this software may be distributed under the terms of the   **
**  GNU General Public License ("GPL") version 2, or (at your option) any    **
**  later version as published by the Free Software Foundation.              **
**                                                                           **
**  In the case this software is distributed under the GPL license,          **
**  you should have received a copy of the GNU General Public License        **
**  along with this software; if not, write to the Free Software             **
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  **
**                                                                           **
**  THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR       **
**  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES**
**  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  **
**  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,         **
**  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT **
**  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,**
**  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY    **
**  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT      **
**  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF **
**  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.        **
**                                                                           **
*******************************************************************************
EH0*/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net80211/ieee80211_qos.h>
#include <net80211/ieee80211_dfs_reentry.h>
#include <net80211/ieee80211_ioctl.h>

#include <qtn/lhost_muc_comm.h>
#include <qtn/qtn_monitor.h>

#include "qcsapi.h"
#include <qtn/qtnis.h>
#include "qcsapi_driver.h"
#include "call_qcsapi.h"
#include "qcsapi_sem.h"
#include "qcsapi_util.h"
#include "qcsapi_grabber.h"

#include <qtn/qtn_vlan.h>
#include <qtn/muc_phy_stats.h>
#include <common/qtn_bits.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))
#endif

#ifndef IS_MULTIPLE_BITS_SET
#define IS_MULTIPLE_BITS_SET(_x)	(((unsigned)(_x)) & (((unsigned)(_x)) - 1))
#endif

#define printf	Do_not_use_printf
#define fprintf	Do_not_use_fprintf

#define IP_ADDR_STR_LEN 16
#define BEACON_INTERVAL_WARNING_LOWER_LIMIT	24
#define BEACON_INTERVAL_WARNING_UPPER_LIMIT	100

#define MAX_BCAST_PPS_LIMIT	500

#define VOPT_CONFIG_S		(0x4)
#define VOPT_STATUS_MASK	(0xf)

static const struct
{
	qcsapi_entry_point	 e_entry_point;
	const char		*api_name;
} qcsapi_entry_name[] =
{
	{ e_qcsapi_errno_get_message,		"get_error_message" },
	{ e_qcsapi_store_ipaddr,		"store_ipaddr" },
	{ e_qcsapi_get_stored_ipaddr,		"get_stored_ipaddr" },
	{ e_qcsapi_set_ip_route,		"static_route" },
	{ e_qcsapi_set_ip_route,		"set_ip_route" },
	{ e_qcsapi_get_ip_route,		"get_ip_route" },
	{ e_qcsapi_set_ip_dns,			"set_ip_dns" },
	{ e_qcsapi_get_ip_dns,			"get_ip_dns" },
	{ e_qcsapi_interface_enable,		"enable_interface" },
	{ e_qcsapi_interface_get_BSSID,		"interface_BSSID" },
	{ e_qcsapi_interface_get_mac_addr,	"get_mac_addr" },
	{ e_qcsapi_interface_get_mac_addr,	"get_macaddr" },
	{ e_qcsapi_interface_set_mac_addr,	"set_mac_addr" },
	{ e_qcsapi_interface_set_mac_addr,	"set_macaddr" },
	{ e_qcsapi_interface_get_counter,	"get_counter" },
	{ e_qcsapi_interface_get_counter64,	"get_counter64" },
	{ e_qcsapi_pm_get_counter,		"get_pm_counter" },
	{ e_qcsapi_pm_get_elapsed_time,		"get_pm_elapsed_time" },
	{ e_qcsapi_flash_image_update,		"flash_image_update" },
	{ e_qcsapi_firmware_get_version,	"get_firmware_version" },
	{ e_qcsapi_system_get_time_since_start,	"get_time_since_start" },
	{ e_qcsapi_get_system_status,		"get_system_status" },
	{ e_qcsapi_get_random_seed,		"get_random_seed" },
	{ e_qcsapi_set_random_seed,		"set_random_seed" },
	{ e_qcsapi_led_get,			"get_LED" },
	{ e_qcsapi_led_set,			"set_LED" },
	{ e_qcsapi_led_pwm_enable,		"set_LED_PWM" },
	{ e_qcsapi_led_brightness,		"set_LED_brightness" },
	{ e_qcsapi_gpio_get_config,		"get_GPIO_config" },
	{ e_qcsapi_gpio_set_config,		"set_GPIO_config" },
	{ e_qcsapi_gpio_monitor_reset_device,	"monitor_reset_device" },
	{ e_qcsapi_gpio_enable_wps_push_button,	"enable_wps_push_button" },
	{ e_qcsapi_file_path_get_config,	"get_file_path" },
	{ e_qcsapi_file_path_set_config,	"set_file_path" },
	{ e_qcsapi_wifi_set_wifi_macaddr,	"set_wifi_mac_addr" },
	{ e_qcsapi_wifi_set_wifi_macaddr,	"set_wifi_macaddr" },
	{ e_qcsapi_wifi_create_restricted_bss,	"wifi_create_restricted_bss"},
	{ e_qcsapi_wifi_create_bss,		"wifi_create_bss"},
	{ e_qcsapi_wifi_remove_bss,		"wifi_remove_bss"},
	{ e_qcsapi_wifi_get_primary_interface,	"get_primary_interface"},
	{ e_qcsapi_wifi_get_interface_by_index,	"get_interface_by_index"},
	{ e_qcsapi_wifi_get_interface_by_index_all, "get_interface_by_index_all"},
	{ e_qcsapi_wifi_get_mode,		"get_mode" },
	{ e_qcsapi_wifi_set_mode,		"set_mode" },
	{ e_qcsapi_wifi_get_phy_mode,		"get_phy_mode" },
	{ e_qcsapi_wifi_set_phy_mode,		"set_phy_mode" },
	{ e_qcsapi_wifi_reload_in_mode,		"reload_in_mode" },
	{ e_qcsapi_wifi_rfenable,		"rfenable" },
	{ e_qcsapi_service_control,             "service_control" },
	{ e_qcsapi_wfa_cert,			"wfa_cert" },
	{ e_qcsapi_wifi_rfstatus,		"rfstatus" },
	{ e_qcsapi_wifi_startprod,		"startprod" },
	{ e_qcsapi_wifi_get_freq_bands,		"get_supported_freq_bands" },
	{ e_qcsapi_wifi_get_bw,			"get_bw" },
	{ e_qcsapi_wifi_set_bw,			"set_bw" },
	{ e_qcsapi_wifi_get_24g_bw,		"get_24g_bw" },
	{ e_qcsapi_wifi_set_24g_bw,		"set_24g_bw" },
	{ e_qcsapi_wifi_get_BSSID,		"get_BSSID" },
	{ e_qcsapi_wifi_get_config_BSSID,	"get_config_BSSID" },
	{ e_qcsapi_wifi_ssid_get_bssid,		"get_ssid_bssid" },
	{ e_qcsapi_wifi_ssid_set_bssid,		"set_ssid_bssid" },
	{ e_qcsapi_wifi_get_SSID,		"get_SSID" },
	{ e_qcsapi_wifi_set_SSID,		"set_SSID" },
	{ e_qcsapi_wifi_get_scan_SSID_cfg,	"get_scan_SSID_cfg" },
	{ e_qcsapi_wifi_set_scan_SSID_cfg,	"set_scan_SSID_cfg" },
	{ e_qcsapi_wifi_get_channel,		"get_channel" },
	{ e_qcsapi_wifi_set_channel,		"set_channel" },
	{ e_qcsapi_wifi_set_channel_and_bw,	"set_chan_and_bw" },
	{ e_qcsapi_wifi_get_channel_and_bw,	"get_chan_and_bw" },
	{ e_qcsapi_wifi_set_wea_cac_en,		"set_wea_cac_en" },
	{ e_qcsapi_wifi_get_auto_channel,	"get_auto_channel" },
	{ e_qcsapi_wifi_set_auto_channel,	"set_auto_channel" },
	{ e_qcsapi_wifi_get_standard,		"get_standard" },
	{ e_qcsapi_wifi_get_standard,		"get_802.11" },
	{ e_qcsapi_wifi_get_dtim,		"get_dtim" },
	{ e_qcsapi_wifi_set_dtim,		"set_dtim" },
	{ e_qcsapi_wifi_get_assoc_limit,	"get_dev_assoc_limit" },
	{ e_qcsapi_wifi_set_assoc_limit,	"set_dev_assoc_limit" },
	{ e_qcsapi_wifi_get_bss_assoc_limit,	"get_bss_assoc_limit" },
	{ e_qcsapi_wifi_set_bss_assoc_limit,	"set_bss_assoc_limit" },
	{ e_qcsapi_wifi_set_SSID_group_id,	"set_SSID_group_id" },
	{ e_qcsapi_wifi_get_SSID_group_id,	"get_SSID_group_id" },
	{ e_qcsapi_wifi_set_SSID_assoc_reserve,	"set_SSID_assoc_reserve" },
	{ e_qcsapi_wifi_get_SSID_assoc_reserve,	"get_SSID_assoc_reserve" },
	{ e_qcsapi_interface_get_status,	"get_status" },
	{ e_qcsapi_interface_set_ip4,		"set_ip" },
	{ e_qcsapi_interface_get_ip4,		"get_ip" },
	{ e_qcsapi_interface_set_mtu,		"set_mtu" },
	{ e_qcsapi_interface_get_mtu,		"get_mtu" },
	{ e_qcsapi_wifi_get_list_channels,	"get_list_of_channels" },
	{ e_qcsapi_wifi_get_list_channels,	"get_channel_list" },
	{ e_qcsapi_wifi_get_supp_chans,		"get_supp_chan" },
	{ e_qcsapi_wifi_get_mode_switch,	"get_mode_switch" },
	{ e_qcsapi_wifi_get_mode_switch,	"get_wifi_mode_switch" },
	{ e_qcsapi_wifi_get_noise,		"get_noise" },
	{ e_qcsapi_wifi_get_rssi_by_chain,	"get_rssi_by_chain" },
	{ e_qcsapi_wifi_get_avg_snr,		"get_avg_snr" },
	{ e_qcsapi_wifi_get_option,		"get_option" },
	{ e_qcsapi_wifi_set_option,		"set_option" },
	{ e_qcsapi_wifi_set_parameter,		"set_wifi_param"},
	{ e_qcsapi_wifi_get_parameter,		"get_wifi_param"},
	{ e_qcsapi_wifi_get_rates,		"get_rates" },
	{ e_qcsapi_wifi_set_rates,		"set_rates" },
	{ e_qcsapi_wifi_get_max_bitrate,	"get_max_bitrate" },
	{ e_qcsapi_wifi_set_max_bitrate,	"set_max_bitrate" },
	{ e_qcsapi_wifi_get_beacon_type,	"get_beacon_type" },
	{ e_qcsapi_wifi_get_beacon_type,	"get_beacon" },
	{ e_qcsapi_wifi_set_beacon_type,	"set_beacon_type" },
	{ e_qcsapi_wifi_set_beacon_type,	"set_beacon" },
	{ e_qcsapi_wifi_get_beacon_interval,		"get_beacon_interval" },
	{ e_qcsapi_wifi_set_beacon_interval,		"set_beacon_interval" },
	{ e_qcsapi_wifi_get_list_regulatory_regions,
						"get_regulatory_regions" },
	{ e_qcsapi_wifi_get_list_regulatory_regions,
						"get_list_regulatory_regions" },
	{ e_qcsapi_wifi_get_regulatory_tx_power,
						"get_regulatory_tx_power" },
	{ e_qcsapi_wifi_get_configured_tx_power,
						"get_configured_tx_power" },
	{ e_qcsapi_wifi_set_regulatory_channel, "set_regulatory_channel" },
	{ e_qcsapi_wifi_set_regulatory_region,	"set_regulatory_region" },
	{ e_qcsapi_wifi_get_regulatory_region,	"get_regulatory_region" },
	{ e_qcsapi_wifi_overwrite_country_code,	"overwrite_country_code" },
	{ e_qcsapi_wifi_get_list_regulatory_channels,
						"get_list_regulatory_channels" },
	{ e_qcsapi_wifi_get_list_regulatory_bands,
						"get_list_regulatory_bands" },
	{ e_qcsapi_wifi_get_regulatory_db_version,
						"get_regulatory_db_version" },
	{ e_qcsapi_wifi_set_regulatory_tx_power_cap,
						"apply_regulatory_cap" },
	{ e_qcsapi_wifi_restore_regulatory_tx_power,
						"restore_regulatory_tx_power"},
	{ e_qcsapi_wifi_set_chan_pri_inactive,  "set_chan_pri_inactive" },
	{ e_qcsapi_wifi_get_chan_pri_inactive,  "get_chan_pri_inactive" },
	{ e_qcsapi_wifi_set_chan_disabled,	"set_chan_disabled" },
	{ e_qcsapi_wifi_get_chan_disabled,	"get_chan_disabled" },
	{ e_qcsapi_wifi_get_chan_usable,	"get_chan_usable" },

	{ e_qcsapi_wifi_get_tx_power,		"get_tx_power" },
	{ e_qcsapi_wifi_set_tx_power,		"set_tx_power" },
	{ e_qcsapi_wifi_get_tx_power_ext,	"get_tx_power_ext" },
	{ e_qcsapi_wifi_set_tx_power_ext,	"set_tx_power_ext" },
	{ e_qcsapi_reg_chan_txpower_get,	"get_chan_power_table" },
	{ e_qcsapi_wifi_set_chan_power_table,	"set_chan_power_table" },
	{ e_qcsapi_reg_chan_txpower_get,	"reg_chan_txpower_get" },
	{ e_qcsapi_reg_chan_txpower_set,	"reg_chan_txpower_set" },
	{ e_qcsapi_reg_chan_txpower_path_get,	"reg_chan_txpower_path_get" },
	{ e_qcsapi_wifi_get_bw_power,		"get_bw_power" },
	{ e_qcsapi_wifi_set_bw_power,		"set_bw_power" },
	{ e_qcsapi_wifi_get_bf_power,		"get_bf_power" },
	{ e_qcsapi_wifi_set_bf_power,		"set_bf_power" },
	{ e_qcsapi_wifi_get_power_selection,	"get_power_selection" },
	{ e_qcsapi_wifi_set_power_selection,	"set_power_selection" },
	{ e_qcsapi_wifi_get_carrier_interference,		"get_carrier_db" },
	{ e_qcsapi_wifi_get_congestion_idx,		"get_congest_idx" },
	{ e_qcsapi_wifi_get_supported_tx_power_levels, "get_supported_tx_power" },
	{ e_qcsapi_wifi_get_current_tx_power_level, "get_current_tx_power" },
	{ e_qcsapi_wifi_set_current_tx_power_level, "set_current_tx_power" },
	{ e_qcsapi_wifi_set_power_constraint, "set_power_constraint"},
	{ e_qcsapi_wifi_get_power_constraint, "get_power_constraint"},
	{ e_qcsapi_wifi_set_tpc_interval, "set_tpc_query_interval"},
	{ e_qcsapi_wifi_get_tpc_interval, "get_tpc_query_interval"},
	{ e_qcsapi_wifi_get_assoc_records,	"get_assoc_records" },
	{ e_qcsapi_wifi_get_disassoc_records,	"get_disassoc_records" },
	{ e_qcsapi_wifi_get_list_DFS_channels,	"get_list_DFS_channels" },
	{ e_qcsapi_wifi_is_channel_DFS,		"is_channel_DFS" },
	{ e_qcsapi_wifi_get_DFS_alt_channel,	"get_DFS_alt_channel" },
	{ e_qcsapi_wifi_set_DFS_alt_channel,	"set_DFS_alt_channel" },
	{ e_qcsapi_wifi_set_DFS_reentry,	"start_dfsreentry"},
	{ e_qcsapi_wifi_get_scs_cce_channels,	"get_scs_cce_channels" },
	{ e_qcsapi_wifi_get_dfs_cce_channels,	"get_dfs_cce_channels" },
	{ e_qcsapi_wifi_get_csw_records,	"get_csw_records" },
	{ e_qcsapi_wifi_get_radar_status,	"get_radar_status" },
	{ e_qcsapi_wifi_get_WEP_encryption_level,
						"get_WEP_encryption_level" },
	{ e_qcsapi_wifi_get_WPA_encryption_modes, "get_WPA_encryption_modes" },
	{ e_qcsapi_wifi_set_WPA_encryption_modes, "set_WPA_encryption_modes" },
	{ e_qcsapi_wifi_get_WPA_authentication_mode, "get_WPA_authentication_mode" },
	{ e_qcsapi_wifi_set_WPA_authentication_mode, "set_WPA_authentication_mode" },

	{ e_qcsapi_wifi_get_params, "get_params" },
	{ e_qcsapi_wifi_set_params, "set_params" },

	{ e_qcsapi_wifi_get_interworking, "get_interworking" },
	{ e_qcsapi_wifi_set_interworking, "set_interworking" },
	{ e_qcsapi_wifi_get_80211u_params, "get_80211u_params" },
	{ e_qcsapi_wifi_set_80211u_params, "set_80211u_params" },
	{ e_qcsapi_security_get_nai_realms, "get_nai_realms" },
	{ e_qcsapi_security_add_nai_realm, "add_nai_realm" },
	{ e_qcsapi_security_del_nai_realm, "del_nai_realm" },
	{ e_qcsapi_security_add_roaming_consortium, "add_roaming_consortium" },
	{ e_qcsapi_security_del_roaming_consortium, "del_roaming_consortium" },
	{ e_qcsapi_security_get_roaming_consortium, "get_roaming_consortium" },
	{ e_qcsapi_security_get_venue_name, "get_venue_name" },
	{ e_qcsapi_security_add_venue_name, "add_venue_name" },
	{ e_qcsapi_security_del_venue_name, "del_venue_name" },
	{ e_qcsapi_security_get_oper_friendly_name, "get_oper_friendly_name" },
	{ e_qcsapi_security_add_oper_friendly_name, "add_oper_friendly_name" },
	{ e_qcsapi_security_del_oper_friendly_name, "del_oper_friendly_name" },
	{ e_qcsapi_security_get_hs20_conn_capab, "get_hs20_conn_capab" },
	{ e_qcsapi_security_add_hs20_conn_capab, "add_hs20_conn_capab" },
	{ e_qcsapi_security_del_hs20_conn_capab, "del_hs20_conn_capab" },

	{ e_qcsapi_security_add_hs20_icon, "add_hs20_icon" },
	{ e_qcsapi_security_get_hs20_icon, "get_hs20_icon" },
	{ e_qcsapi_security_del_hs20_icon, "del_hs20_icon" },

	{ e_qcsapi_security_add_osu_server_uri, "add_osu_server_uri" },
	{ e_qcsapi_security_get_osu_server_uri, "get_osu_server_uri" },
	{ e_qcsapi_security_del_osu_server_uri, "del_osu_server_uri" },

	{ e_qcsapi_security_add_osu_server_param, "add_osu_server_param" },
	{ e_qcsapi_security_get_osu_server_param, "get_osu_server_param" },
	{ e_qcsapi_security_del_osu_server_param, "del_osu_server_param" },

	{ e_qcsapi_wifi_get_hs20_status, "get_hs20_status" },
	{ e_qcsapi_wifi_set_hs20_status, "set_hs20_status" },
	{ e_qcsapi_wifi_get_hs20_params, "get_hs20_params" },
	{ e_qcsapi_wifi_set_hs20_params, "set_hs20_params" },

	{ e_qcsapi_remove_11u_param, "remove_11u_param" },
	{ e_qcsapi_remove_hs20_param, "remove_hs20_param" },

	{ e_qcsapi_wifi_set_proxy_arp, "set_proxy_arp" },
	{ e_qcsapi_wifi_get_proxy_arp, "get_proxy_arp" },
	{ e_qcsapi_wifi_get_l2_ext_filter, "get_l2_ext_filter" },
	{ e_qcsapi_wifi_set_l2_ext_filter, "set_l2_ext_filter" },

	{ e_qcsapi_wifi_get_IEEE11i_encryption_modes, "get_IEEE11i_encryption_modes" },
	{ e_qcsapi_wifi_set_IEEE11i_encryption_modes, "set_IEEE11i_encryption_modes" },
	{ e_qcsapi_wifi_get_IEEE11i_authentication_mode, "get_IEEE11i_authentication_mode" },
	{ e_qcsapi_wifi_set_IEEE11i_authentication_mode, "set_IEEE11i_authentication_mode" },
	{ e_qcsapi_wifi_get_michael_errcnt, "get_michael_errcnt" },
	{ e_qcsapi_wifi_get_pre_shared_key,	"get_pre_shared_key" },
	{ e_qcsapi_wifi_set_pre_shared_key,	"set_pre_shared_key" },
	{ e_qcsapi_wifi_add_radius_auth_server_cfg,	"add_radius_auth_server_cfg" },
	{ e_qcsapi_wifi_del_radius_auth_server_cfg,	"del_radius_auth_server_cfg" },
	{ e_qcsapi_wifi_get_radius_auth_server_cfg,	"get_radius_auth_server_cfg" },
	{ e_qcsapi_wifi_add_radius_acct_server_cfg,	"add_radius_acct_server_cfg" },
	{ e_qcsapi_wifi_del_radius_acct_server_cfg,	"del_radius_acct_server_cfg" },
	{ e_qcsapi_wifi_get_radius_acct_server_cfg,	"get_radius_acct_server_cfg" },
	{ e_qcsapi_wifi_get_radius_acct_interim_interval, "get_radius_acct_interim_interval" },
	{ e_qcsapi_wifi_set_radius_acct_interim_interval, "set_radius_acct_interim_interval" },
	{ e_qcsapi_wifi_set_eap_own_ip_addr,	"set_own_ip_addr" },
	{ e_qcsapi_wifi_set_eap_own_ip_addr,	"set_eap_own_ip_addr" },
	{ e_qcsapi_wifi_get_eap_own_ip_addr,	"get_eap_own_ip_addr" },
	{ e_qcsapi_wifi_get_psk_auth_failures,	"get_psk_auth_failures" },
	{ e_qcsapi_wifi_get_pre_shared_key,	"get_PSK" },
	{ e_qcsapi_wifi_set_pre_shared_key,	"set_PSK" },
	{ e_qcsapi_wifi_get_key_passphrase,	"get_passphrase" },
	{ e_qcsapi_wifi_get_key_passphrase,	"get_key_passphrase" },
	{ e_qcsapi_wifi_set_key_passphrase,	"set_passphrase" },
	{ e_qcsapi_wifi_set_key_passphrase,	"set_key_passphrase" },
	{ e_qcsapi_wifi_get_group_key_interval, "get_group_key_interval" },
	{ e_qcsapi_wifi_set_group_key_interval, "set_group_key_interval" },
	{ e_qcsapi_wifi_get_pairwise_key_interval, "get_pairwise_key_interval" },
	{ e_qcsapi_wifi_set_pairwise_key_interval, "set_pairwise_key_interval" },
	{ e_qcsapi_wifi_get_pmf,	"get_pmf" },
	{ e_qcsapi_wifi_set_pmf,	"set_pmf" },
	{ e_qcsapi_wifi_get_count_associations,	"get_count_assoc" },
	{ e_qcsapi_wifi_get_count_associations,	"get_count_associations" },
	{ e_qcsapi_wifi_get_count_associations,	"get_association_count" },
	{ e_qcsapi_wifi_get_associated_device_mac_addr,	"get_associated_device_mac_addr" },
	{ e_qcsapi_wifi_get_associated_device_mac_addr,	"get_station_mac_addr" },
	{ e_qcsapi_wifi_get_associated_device_ip_addr,	"get_associated_device_ip_addr" },
	{ e_qcsapi_wifi_get_associated_device_ip_addr,	"get_station_ip_addr" },
	{ e_qcsapi_wifi_get_link_quality,	"get_link_quality" },
	{ e_qcsapi_wifi_get_rssi_per_association, "get_rssi" },
	{ e_qcsapi_wifi_get_hw_noise_per_association, "get_hw_noise" },
	{ e_qcsapi_wifi_get_rssi_in_dbm_per_association, "get_rssi_dbm" },
	{ e_qcsapi_wifi_get_snr_per_association, "get_snr" },
	{ e_qcsapi_wifi_get_rx_bytes_per_association, "get_rx_bytes" },
	{ e_qcsapi_wifi_get_rx_bytes_per_association, "get_assoc_rx_bytes" },
	{ e_qcsapi_wifi_get_tx_bytes_per_association, "get_tx_bytes" },
	{ e_qcsapi_wifi_get_tx_bytes_per_association, "get_assoc_tx_bytes" },
	{ e_qcsapi_wifi_get_rx_packets_per_association, "get_rx_packets" },
	{ e_qcsapi_wifi_get_rx_packets_per_association, "get_assoc_rx_packets" },
	{ e_qcsapi_wifi_get_tx_packets_per_association, "get_tx_packets" },
	{ e_qcsapi_wifi_get_tx_packets_per_association, "get_assoc_tx_packets" },
	{ e_qcsapi_wifi_get_tx_err_packets_per_association,
						"get_tx_err_packets" },
	{ e_qcsapi_wifi_get_tx_err_packets_per_association,
						"get_assoc_tx_err_packets" },
	{ e_qcsapi_wifi_get_bw_per_association, "get_assoc_bw" },
	{ e_qcsapi_wifi_get_tx_phy_rate_per_association, "get_tx_phy_rate" },
	{ e_qcsapi_wifi_get_rx_phy_rate_per_association, "get_rx_phy_rate" },
	{ e_qcsapi_wifi_get_tx_mcs_per_association, "get_tx_mcs" },
	{ e_qcsapi_wifi_get_rx_mcs_per_association, "get_rx_mcs" },
	{ e_qcsapi_wifi_get_achievable_tx_phy_rate_per_association,
						"get_achievable_tx_phy_rate" },
	{ e_qcsapi_wifi_get_achievable_rx_phy_rate_per_association,
						"get_achievable_rx_phy_rate" },
	{ e_qcsapi_wifi_get_auth_enc_per_association, "get_auth_enc_per_assoc" },
	{ e_qcsapi_wifi_get_tput_caps,	"get_tput_caps" },
	{ e_qcsapi_wifi_get_connection_mode,	"get_connection_mode" },
	{ e_qcsapi_wifi_get_vendor_per_association, "get_vendor" },
	{ e_qcsapi_wifi_get_max_mimo,	"get_max_mimo" },

	{ e_qcsapi_wifi_get_node_counter,	"get_node_counter" },
	{ e_qcsapi_wifi_get_node_param,		"get_node_param" },
	{ e_qcsapi_wifi_get_node_stats,		"get_node_stats" },
	{ e_qcsapi_wifi_get_node_infoset,	"get_node_infoset" },
	{ e_qcsapi_wifi_get_node_infoset_all,	"get_node_infoset_all" },

	{ e_qcsapi_wifi_get_max_queued,		"get_max_queued" },

	{ e_qcsapi_wifi_disassociate,		"disassociate" },
	{ e_qcsapi_wifi_disassociate_sta,	"disassociate_sta" },
	{ e_qcsapi_wifi_reassociate,		"reassociate" },

	{ e_qcsapi_wifi_associate,		"associate" },
	{ e_qcsapi_wifi_associate_noscan,	"associate_noscan" },

	{ e_qcsapi_wifi_get_mac_address_filtering, "get_macaddr_filter" },
	{ e_qcsapi_wifi_set_mac_address_filtering, "set_macaddr_filter" },
	{ e_qcsapi_wifi_is_mac_address_authorized, "is_mac_addr_authorized" },
	{ e_qcsapi_wifi_is_mac_address_authorized, "is_macaddr_authorized" },
	{ e_qcsapi_wifi_get_authorized_mac_addresses, "get_authorized_mac_addr" },
	{ e_qcsapi_wifi_get_authorized_mac_addresses, "get_authorized_macaddr" },
	{ e_qcsapi_wifi_get_denied_mac_addresses, "get_blocked_mac_addr" },
	{ e_qcsapi_wifi_get_denied_mac_addresses, "get_blocked_macaddr" },
	{ e_qcsapi_wifi_get_denied_mac_addresses, "get_denied_mac_addr" },
	{ e_qcsapi_wifi_get_denied_mac_addresses, "get_denied_macaddr" },
	{ e_qcsapi_wifi_authorize_mac_address,	"authorize_mac_addr" },
	{ e_qcsapi_wifi_authorize_mac_address,	"authorize_macaddr" },
	{ e_qcsapi_wifi_authorize_mac_address_ext,	"authorize_mac_address" },
	{ e_qcsapi_wifi_deny_mac_address,	"block_macaddr" },
	{ e_qcsapi_wifi_deny_mac_address,	"block_mac_addr" },
	{ e_qcsapi_wifi_deny_mac_address,	"deny_macaddr" },
	{ e_qcsapi_wifi_deny_mac_address,	"deny_mac_addr" },
	{ e_qcsapi_wifi_deny_mac_address_ext,	"deny_mac_address" },
	{ e_qcsapi_wifi_remove_mac_address,	"remove_mac_addr" },
	{ e_qcsapi_wifi_remove_mac_address,	"remove_macaddr" },
	{ e_qcsapi_wifi_remove_mac_address_ext,	"remove_mac_address" },
	{ e_qcsapi_wifi_clear_mac_address_filters,	"clear_mac_filters" },
	{ e_qcsapi_wifi_set_mac_address_reserve,	"set_macaddr_reserve" },
	{ e_qcsapi_wifi_get_mac_address_reserve,	"get_macaddr_reserve" },
	{ e_qcsapi_wifi_clear_mac_address_reserve,	"clear_macaddr_reserve" },
	{ e_qcsapi_wifi_add_temp_acl_macaddr,	"add_temp_acl_macaddr" },
	{ e_qcsapi_wifi_del_temp_acl_macaddr,	"del_temp_acl_macaddr" },

	{ e_qcsapi_wifi_backoff_fail_max,	"backoff_fail_max" },
	{ e_qcsapi_wifi_backoff_timeout,	"backoff_timeout" },
	{ e_qcsapi_wifi_get_wpa_status,		"get_wpa_status" },
	{ e_qcsapi_wifi_get_auth_state,		"get_auth_state" },
	{ e_qcsapi_wifi_get_disconn_info,	"get_disconn_info" },
	{ e_qcsapi_wifi_reset_disconn_info,	"reset_disconn_info" },
	{ e_qcsapi_wifi_get_pairing_id,		"get_pairing_id"},
	{ e_qcsapi_wifi_set_pairing_id,		"set_pairing_id"},
	{ e_qcsapi_wifi_get_pairing_enable,	"get_pairing_enable"},
	{ e_qcsapi_wifi_set_pairing_enable,	"set_pairing_enable"},

	{ e_qcsapi_wifi_set_txqos_sched_tbl,	"set_txqos_sched_tbl" },
	{ e_qcsapi_wifi_get_txqos_sched_tbl,	"get_txqos_sched_tbl" },

	{ e_qcsapi_wps_registrar_report_button_press, "registrar_report_button_press" },
	{ e_qcsapi_wps_registrar_report_button_press, "registrar_report_pbc" },
	{ e_qcsapi_wps_registrar_report_pin,	"registrar_report_pin" },
	{ e_qcsapi_wps_registrar_get_pp_devname, "registrar_get_pp_devname" },
	{ e_qcsapi_wps_registrar_set_pp_devname, "registrar_set_pp_devname" },
	{ e_qcsapi_wps_enrollee_report_button_press, "enrollee_report_button_press" },
	{ e_qcsapi_wps_enrollee_report_button_press, "enrollee_report_pbc" },
	{ e_qcsapi_wps_enrollee_report_pin,	"enrollee_report_pin" },
	{ e_qcsapi_wps_enrollee_generate_pin,	"enrollee_generate_pin" },
	{ e_qcsapi_wps_get_ap_pin,		"get_wps_ap_pin" },
	{ e_qcsapi_wps_set_ap_pin,		"set_wps_ap_pin" },
	{ e_qcsapi_wps_save_ap_pin,		"save_wps_ap_pin" },
	{ e_qcsapi_wps_enable_ap_pin,		"enable_wps_ap_pin" },
	{ e_qcsapi_wps_get_sta_pin,	"get_wps_sta_pin" },
	{ e_qcsapi_wps_configure_ap,	"wps_configure_ap"},
	{ e_qcsapi_wps_get_state,		"get_wps_state" },
	{ e_qcsapi_wps_get_configured_state,	"get_wps_configured_state" },
	{ e_qcsapi_wps_set_configured_state,	"set_wps_configured_state" },
	{ e_qcsapi_wps_get_runtime_state,	"get_wps_runtime_state" },
	{ e_qcsapi_wps_get_allow_pbc_overlap_status,		"get_allow_pbc_overlap_status" },
	{ e_qcsapi_wps_allow_pbc_overlap,		"allow_pbc_overlap" },
	{ e_qcsapi_wps_get_param,		"get_wps_param" },
	{ e_qcsapi_wps_set_param,		"set_wps_param" },
	{ e_qcsapi_wps_set_access_control,	"set_wps_access_control" },
	{ e_qcsapi_wps_get_access_control,	"get_wps_access_control" },
	{ e_qcsapi_non_wps_set_pp_enable,	"set_non_wps_pp_enable" },
	{ e_qcsapi_non_wps_get_pp_enable,	"get_non_wps_pp_enable" },
	{ e_qcsapi_wps_cancel,			"wps_cancel" },
	{ e_qcsapi_wps_set_pbc_in_srcm,		"set_wps_pbc_in_srcm" },
	{ e_qcsapi_wps_get_pbc_in_srcm,		"get_wps_pbc_in_srcm" },
	{ e_qcsapi_wps_timeout,			"wps_set_timeout" },
	{ e_qcsapi_wps_on_hidden_ssid,		"wps_on_hidden_ssid" },
	{ e_qcsapi_wps_on_hidden_ssid_status,	"wps_on_hidden_ssid_status" },
	{ e_qcsapi_wps_upnp_enable,		"wps_upnp_enable" },
	{ e_qcsapi_wps_upnp_status,		"wps_upnp_status" },
	{ e_qcsapi_wps_registrar_set_dfl_pbc_bss, "registrar_set_default_pbc_bss"},
	{ e_qcsapi_wps_registrar_get_dfl_pbc_bss, "registrar_get_default_pbc_bss"},
	{ e_qcsapi_wps_set_dfl_pbc_bss,		"wps_set_default_pbc_bss"},
	{ e_qcsapi_wps_get_dfl_pbc_bss,		"wps_get_default_pbc_bss"},

	{ e_qcsapi_wifi_set_dwell_times,	"set_dwell_times" },
	{ e_qcsapi_wifi_get_dwell_times,	"get_dwell_times" },
	{ e_qcsapi_wifi_set_bgscan_dwell_times,	"set_bgscan_dwell_times" },
	{ e_qcsapi_wifi_get_bgscan_dwell_times,	"get_bgscan_dwell_times" },
	{ e_qcsapi_wifi_get_scan_chan_list,	"get_scan_chan_list" },
	{ e_qcsapi_wifi_set_scan_chan_list,	"set_scan_chan_list" },
	{ e_qcsapi_wifi_start_scan,		"start_scan" },
	{ e_qcsapi_wifi_cancel_scan,		"cancel_scan" },
	{ e_qcsapi_wifi_get_scan_status,	"get_scanstatus" },
	{ e_qcsapi_wifi_get_cac_status,		"get_cacstatus" },
	{ e_qcsapi_wifi_set_dfs_available_channel,	"set_dfs_available_channel" },
	{ e_qcsapi_wifi_wait_scan_completes,	"wait_scan_completes" },
	{ e_qcsapi_wifi_set_scan_chk_inv,	"set_scan_chk_inv" },
	{ e_qcsapi_wifi_get_scan_chk_inv,	"get_scan_chk_inv" },

	{ e_qcsapi_wifi_update_bss_cfg,		"update_bss_cfg" },
	{ e_qcsapi_wifi_get_bss_cfg,		"get_bss_cfg" },

        { e_qcsapi_SSID_create_SSID,		"SSID_create_SSID" },
        { e_qcsapi_SSID_create_SSID,		"create_SSID" },
	{ e_qcsapi_SSID_remove_SSID,		"remove_SSID" },
        { e_qcsapi_SSID_verify_SSID,		"SSID_verify_SSID" },
        { e_qcsapi_SSID_verify_SSID,		"verify_SSID" },
        { e_qcsapi_SSID_rename_SSID,		"SSID_rename_SSID" },
        { e_qcsapi_SSID_rename_SSID,		"rename_SSID" },
        { e_qcsapi_SSID_get_SSID_list,		"get_SSID_list" },
        { e_qcsapi_SSID_get_protocol,		"get_SSID_proto" },
        { e_qcsapi_SSID_get_protocol,		"SSID_get_proto" },
        { e_qcsapi_SSID_set_protocol,		"set_SSID_proto" },
        { e_qcsapi_SSID_set_protocol,		"SSID_set_proto" },
        { e_qcsapi_SSID_get_encryption_modes,	"SSID_get_encryption_modes" },
        { e_qcsapi_SSID_set_encryption_modes,	"SSID_set_encryption_modes" },
        { e_qcsapi_SSID_get_group_encryption,	"SSID_get_group_encryption" },
        { e_qcsapi_SSID_set_group_encryption,	"SSID_set_group_encryption" },
        { e_qcsapi_SSID_get_authentication_mode, "SSID_get_authentication_mode" },
        { e_qcsapi_SSID_set_authentication_mode, "SSID_set_authentication_mode" },
        { e_qcsapi_SSID_get_pre_shared_key,	"SSID_get_pre_shared_key" },
        { e_qcsapi_SSID_set_pre_shared_key,	"SSID_set_pre_shared_key" },
        { e_qcsapi_SSID_get_key_passphrase,	"SSID_get_key_passphrase" },
        { e_qcsapi_SSID_get_key_passphrase,	"SSID_get_passphrase" },
        { e_qcsapi_SSID_set_key_passphrase,	"SSID_set_key_passphrase" },
        { e_qcsapi_SSID_set_key_passphrase,	"SSID_set_passphrase" },
        { e_qcsapi_SSID_get_pmf,		"SSID_get_pmf" },
        { e_qcsapi_SSID_set_pmf,		"SSID_set_pmf" },
        { e_qcsapi_SSID_get_wps_SSID,		"SSID_get_WPS_SSID" },
	{ e_qcsapi_SSID_get_params,		"SSID_get_params" },
	{ e_qcsapi_SSID_set_params,		"SSID_set_params" },
        { e_qcsapi_wifi_vlan_config,		"vlan_config" },
	{ e_qcsapi_wifi_show_vlan_config,	"show_vlan_config" },

        { e_qcsapi_wifi_start_cca,		"start_cca" },
        { e_qcsapi_wifi_disable_wps,		"disable_wps" },
        { e_qcsapi_wifi_get_results_AP_scan,	"get_results_AP_scan" },
	{ e_qcsapi_wifi_get_count_APs_scanned,	"get_count_APs_scanned" },
	{ e_qcsapi_wifi_get_properties_AP,	"get_properties_AP" },
	{ e_qcsapi_wifi_get_wps_ie_scanned_AP,	"get_wps_ie_scanned_AP" },

	{e_qcsapi_wifi_get_time_associated_per_association, "get_time_associated" },

	{ e_qcsapi_wifi_wds_add_peer,		"wds_add_peer"},
	{ e_qcsapi_wifi_wds_remove_peer,	"wds_remove_peer"},
	{ e_qcsapi_wifi_wds_get_peer_address,	"wds_get_peer_address"},
	{ e_qcsapi_wifi_wds_get_psk,		"wds_get_psk"},
	{ e_qcsapi_wifi_wds_set_psk,		"wds_set_psk"},
	{ e_qcsapi_wifi_wds_set_mode,		"wds_set_mode"},
	{ e_qcsapi_wifi_wds_get_mode,		"wds_get_mode"},

	{ e_qcsapi_wifi_qos_get_param,		"get_qos_param" },
	{ e_qcsapi_wifi_qos_set_param,		"set_qos_param" },

	{ e_qcsapi_wifi_get_wmm_ac_map,		"get_wmm_ac_map" },
	{ e_qcsapi_wifi_set_wmm_ac_map,		"set_wmm_ac_map" },

	{ e_qcsapi_wifi_get_dscp_8021p_map,	"get_dscp_8021p_map" },
	{ e_qcsapi_wifi_set_dscp_8021p_map,	"set_dscp_8021p_map" },
	{ e_qcsapi_wifi_get_dscp_ac_map,	"get_dscp_ac_map" },
	{ e_qcsapi_wifi_set_dscp_ac_map,	"set_dscp_ac_map" },

	{ e_qcsapi_wifi_get_ac_agg_hold_time,	"get_ac_agg_hold_time" },
	{ e_qcsapi_wifi_set_ac_agg_hold_time,	"set_ac_agg_hold_time" },

	{ e_qcsapi_wifi_set_qos_map,		"set_qos_map" },
	{ e_qcsapi_wifi_del_qos_map,		"del_qos_map" },
	{ e_qcsapi_wifi_get_qos_map,		"get_qos_map" },
	{ e_qcsapi_wifi_send_qos_map_conf,	"send_qos_map_conf" },
	{ e_qcsapi_wifi_get_dscp_tid_map,	"get_dscp_tid_map" },

	{ e_qcsapi_wifi_get_priority,		"get_priority" },
	{ e_qcsapi_wifi_set_priority,		"set_priority" },
	{ e_qcsapi_wifi_get_airfair,		"get_airfair" },
	{ e_qcsapi_wifi_set_airfair,		"set_airfair" },

	{ e_qcsapi_config_get_parameter,	"get_config_param"},
	{ e_qcsapi_config_get_parameter,	"get_persistent_param"},
	{ e_qcsapi_config_update_parameter,	"update_config_param"},
	{ e_qcsapi_config_update_parameter,	"update_persistent_param"},
	{ e_qcsapi_get_qfdr_parameter,		"get_qfdr_param"},
	{ e_qcsapi_set_qfdr_parameter,		"set_qfdr_param"},
	{ e_qcsapi_get_qfdr_state,		"get_qfdr_state" },
	{ e_qcsapi_bootcfg_get_parameter,	"get_bootcfg_param"},
	{ e_qcsapi_bootcfg_update_parameter,	"update_bootcfg_param"},
	{ e_qcsapi_bootcfg_commit,		"commit_bootcfg"},
	{ e_qcsapi_wifi_get_mcs_rate,		"get_mcs_rate" },
	{ e_qcsapi_wifi_set_mcs_rate,		"set_mcs_rate" },
	{ e_qcsapi_config_get_ssid_parameter,		"get_persistent_ssid_param"},
	{ e_qcsapi_config_update_ssid_parameter,	"update_persistent_ssid_param"},

	{ e_qcsapi_wifi_enable_scs,			"enable_scs" },
	{ e_qcsapi_wifi_scs_switch_channel,		"scs_switch_chan" },
	{ e_qcsapi_wifi_scs_pick_best_channel,		"scs_pick_chan" },
	{ e_qcsapi_wifi_set_scs_verbose,		"set_scs_verbose" },
	{ e_qcsapi_wifi_get_scs_status,			"get_scs_status" },
	{ e_qcsapi_wifi_set_scs_smpl_enable,		"set_scs_smpl_enable" },
	{ e_qcsapi_wifi_set_scs_active_chan_list,	"set_scs_active_chan_list"},
	{ e_qcsapi_wifi_get_scs_active_chan_list,	"get_scs_active_chan_list"},
	{ e_qcsapi_wifi_set_scs_smpl_dwell_time,	"set_scs_smpl_dwell_time" },
	{ e_qcsapi_wifi_set_scs_smpl_intv,		"set_scs_smpl_intv" },
	{ e_qcsapi_wifi_get_scs_smpl_intv,		"get_scs_smpl_intv" },
	{ e_qcsapi_wifi_set_scs_smpl_type,		"set_scs_smpl_type" },
	{ e_qcsapi_wifi_set_scs_intf_detect_intv,	"set_scs_intf_detect_intv" },
	{ e_qcsapi_wifi_set_scs_thrshld,		"set_scs_thrshld" },
	{ e_qcsapi_wifi_set_scs_report_only,		"set_scs_report_only" },
	{ e_qcsapi_wifi_set_scs_override_mode,		"set_scs_override_mode" },
	{ e_qcsapi_wifi_get_scs_report_stat,		"get_scs_report" },
	{ e_qcsapi_wifi_set_scs_cca_intf_smth_fctr,	"set_scs_cca_intf_smth_fctr" },
	{ e_qcsapi_wifi_set_scs_chan_mtrc_mrgn,		"set_scs_chan_mtrc_mrgn" },
	{ e_qcsapi_wifi_set_scs_inband_chan_mtrc_mrgn,	"set_scs_inband_chan_mtrc_mrgn" },
	{ e_qcsapi_wifi_set_scs_band_margin_check,	"set_scs_band_margin_check" },
	{ e_qcsapi_wifi_set_scs_band_margin,		"set_scs_band_margin" },
	{ e_qcsapi_wifi_set_scs_nac_monitor_mode,	"set_scs_nac_monitor_mode" },
	{ e_qcsapi_wifi_set_scs_obss_check_enable,	"set_scs_obss_check_enable" },
	{ e_qcsapi_wifi_set_scs_pmbl_smth_enable,	"set_scs_pmbl_smth_enable" },
	{ e_qcsapi_wifi_get_scs_dfs_reentry_request,	"get_scs_dfs_reentry_request" },
	{ e_qcsapi_wifi_get_scs_cca_intf,		"get_scs_cca_intf" },
	{ e_qcsapi_wifi_get_scs_param,			"get_scs_params" },
	{ e_qcsapi_wifi_set_scs_stats,			"set_scs_stats" },
	{ e_qcsapi_wifi_set_scs_burst_enable,		"set_scs_burst_enable" },
	{ e_qcsapi_wifi_set_scs_burst_window,		"set_scs_burst_window" },
	{ e_qcsapi_wifi_set_scs_burst_thresh,		"set_scs_burst_thresh" },
	{ e_qcsapi_wifi_set_scs_burst_pause,		"set_scs_burst_pause_time" },
	{ e_qcsapi_wifi_set_scs_burst_switch,		"set_scs_burst_force_switch" },
	{ e_qcsapi_wifi_set_scs_chan_weight,		"set_scs_chan_weight" },
	{ e_qcsapi_wifi_get_scs_chan_weights,		"get_scs_chan_weights" },

	{ e_qcsapi_wifi_start_ocac,			"start_ocac" },
	{ e_qcsapi_wifi_stop_ocac,			"stop_ocac" },
	{ e_qcsapi_wifi_get_ocac_status,		"get_ocac_status" },
	{ e_qcsapi_wifi_set_ocac_threshold,		"set_ocac_thrshld" },
	{ e_qcsapi_wifi_set_ocac_dwell_time,		"set_ocac_dwell_time" },
	{ e_qcsapi_wifi_set_ocac_duration,		"set_ocac_duration" },
	{ e_qcsapi_wifi_set_ocac_cac_time,		"set_ocac_cac_time" },
	{ e_qcsapi_wifi_set_ocac_report_only,		"set_ocac_report_only" },

	{ e_qcsapi_wifi_start_dfs_s_radio,		"start_dfs_s_radio" },
	{ e_qcsapi_wifi_stop_dfs_s_radio,		"stop_dfs_s_radio" },
	{ e_qcsapi_wifi_get_dfs_s_radio_status,		"get_dfs_s_radio_status" },
	{ e_qcsapi_wifi_get_dfs_s_radio_availability,	"get_dfs_s_radio_availability" },
	{ e_qcsapi_wifi_set_dfs_s_radio_threshold,	"set_dfs_s_radio_thrshld" },
	{ e_qcsapi_wifi_set_dfs_s_radio_dwell_time,	"set_dfs_s_radio_dwell_time" },
	{ e_qcsapi_wifi_set_dfs_s_radio_duration,	"set_dfs_s_radio_duration" },
	{ e_qcsapi_wifi_set_dfs_s_radio_cac_time,	"set_dfs_s_radio_cac_time" },
	{ e_qcsapi_wifi_set_dfs_s_radio_report_only,	"set_dfs_s_radio_report_only" },
	{ e_qcsapi_wifi_set_dfs_s_radio_wea_duration,	"set_dfs_s_radio_wea_duration" },
	{ e_qcsapi_wifi_set_dfs_s_radio_wea_cac_time,	"set_dfs_s_radio_wea_cac_time" },
	{ e_qcsapi_wifi_set_dfs_s_radio_wea_dwell_time,	"set_dfs_s_radio_wea_dwell_time" },
	{ e_qcsapi_wifi_set_dfs_s_radio_chan_off,	"set_dfs_s_radio_chan_off" },
	{ e_qcsapi_wifi_get_dfs_s_radio_chan_off,	"get_dfs_s_radio_chan_off" },

	{ e_qcsapi_wifi_xcac_set,			"xcac_set" },
	{ e_qcsapi_wifi_xcac_get,			"xcac_get" },

	{ e_qcsapi_wifi_set_vendor_fix,			"set_vendor_fix" },
	{ e_qcsapi_wifi_get_rts_threshold,		"get_rts_threshold" },
	{ e_qcsapi_wifi_set_rts_threshold,		"set_rts_threshold" },
	{ e_qcsapi_set_soc_macaddr,			"set_soc_macaddr" },

	{ e_qcsapi_get_interface_stats,			"get_interface_stats" },
	{ e_qcsapi_wifi_get_if_infoset,		        "get_if_infoset" },
	{ e_qcsapi_get_phy_stats,			"get_phy_stats" },
	{ e_qcsapi_wifi_set_ap_isolate,			"set_ap_isolate" },
	{ e_qcsapi_wifi_get_ap_isolate,			"get_ap_isolate" },
	{ e_qcsapi_power_save,				"pm" },
	{ e_qcsapi_qpm_level,				"qpm_level" },
	{ e_qcsapi_reset_all_stats,			"reset_all_stats" },
	{ e_qcsapi_eth_phy_power_off,			"eth_phy_power_off" },
	{ e_qcsapi_aspm_l1,				"set_aspm_l1"},
	{ e_qcsapi_l1,					"set_l1"},
	{ e_qcsapi_telnet_enable,			"enable_telnet" },
	{ e_qcsapi_restore_default_config,		"restore_default_config" },
	{ e_qcsapi_run_script,				"run_script" },
	{ e_qcsapi_qtm,					"qtm" },
	{ e_qcsapi_test_traffic,			"test_traffic" },
	{ e_qcsapi_get_temperature,			"get_temperature" },
	{ e_qcsapi_set_accept_oui_filter,		"set_accept_oui_filter" },
	{ e_qcsapi_get_accept_oui_filter,		"get_accept_oui_filter" },

	{ e_qcsapi_get_swfeat_list,			"get_swfeat_list" },

	{ e_qcsapi_wifi_set_vht,			"set_vht" },
	{ e_qcsapi_wifi_get_vht,			"get_vht" },

	{ e_qcsapi_calcmd_check_rfic_health,		"check_rfic_health" },
	{ e_qcsapi_calcmd_set_test_mode,		"set_test_mode" },
	{ e_qcsapi_calcmd_show_test_packet,		"show_test_packet" },
	{ e_qcsapi_calcmd_send_test_packet,		"send_test_packet" },
	{ e_qcsapi_calcmd_stop_test_packet,		"stop_test_packet" },
	{ e_qcsapi_calcmd_send_dc_cw_signal,		"send_dc_cw_signal" },
	{ e_qcsapi_calcmd_stop_dc_cw_signal,		"stop_dc_cw_signal" },
	{ e_qcsapi_calcmd_get_test_mode_antenna_sel,	"get_test_mode_antenna_sel" },
	{ e_qcsapi_calcmd_get_test_mode_mcs,		"get_test_mode_mcs" },
	{ e_qcsapi_calcmd_get_test_mode_bw,		"get_test_mode_bw" },
	{ e_qcsapi_calcmd_get_tx_power,			"get_test_mode_tx_power" },
	{ e_qcsapi_calcmd_set_tx_power,			"set_test_mode_tx_power" },
	{ e_qcsapi_calcmd_get_test_mode_rssi,		"get_test_mode_rssi" },
	{ e_qcsapi_calcmd_set_mac_filter,		"calcmd_set_mac_filter" },
	{ e_qcsapi_calcmd_get_antenna_count,		"get_test_mode_antenna_count" },
	{ e_qcsapi_calcmd_clear_counter,		"calcmd_clear_counter" },
	{ e_qcsapi_calcmd_get_info,                     "get_info" },
	{ e_qcsapi_wifi_disable_dfs_channels,		"disable_dfs_channels" },
	{ e_qcsapi_wifi_get_dfs_channels_status,	"get_dfs_channels_status" },

	{ e_qcsapi_br_vlan_promisc,			"enable_vlan_promisc" },
	{ e_qcsapi_add_multicast,			"add_multicast"},
	{ e_qcsapi_del_multicast,			"del_multicast"},
	{ e_qcsapi_get_multicast_list,			"get_multicast_list"},
	{ e_qcsapi_add_ipff,				"add_ipff" },
	{ e_qcsapi_del_ipff,				"del_ipff" },
	{ e_qcsapi_get_ipff,				"get_ipff" },
	{ e_qcsapi_get_carrier_id,			"get_carrier_id" },
	{ e_qcsapi_set_carrier_id,			"set_carrier_id" },
	{ e_qcsapi_get_platform_id,			"get_platform_id" },
	{ e_qcsapi_get_spinor_jedecid,			"get_spinor_jedecid" },
	{ e_qcsapi_get_custom_value,			"get_custom_value" },
	{ e_qcsapi_set_custom_value,			"set_custom_value" },
	{ e_qcsapi_get_vco_lock_detect_mode,		"get_vco_lock_detect_mode" },
	{ e_qcsapi_set_vco_lock_detect_mode,		"set_vco_lock_detect_mode" },

	{ e_qcsapi_wifi_enable_tdls,			"enable_tdls" },
	{ e_qcsapi_wifi_enable_tdls_over_qhop,		"enable_tdls_over_qhop" },
	{ e_qcsapi_wifi_get_tdls_status,		"get_tdls_status" },
	{ e_qcsapi_wifi_set_tdls_params,		"set_tdls_params" },
	{ e_qcsapi_wifi_get_tdls_params,		"get_tdls_params" },
	{ e_qcsapi_wifi_tdls_operate,			"tdls_operate" },

	{ e_qcsapi_wifi_get_mlme_stats_per_mac,				"get_mlme_stats_per_mac" },
	{ e_qcsapi_wifi_get_mlme_stats_per_association,		"get_mlme_stats_per_association" },
	{ e_qcsapi_wifi_get_mlme_stats_macs_list,			"get_mlme_stats_macs_list" },

	{ e_qcsapi_get_nss_cap,				"get_nss_cap"},
	{ e_qcsapi_set_nss_cap,				"set_nss_cap"},
	{ e_qcsapi_get_rx_nss_cap,			"get_rx_nss_cap"},
	{ e_qcsapi_set_rx_nss_cap,			"set_rx_nss_cap"},

	{ e_qcsapi_get_security_defer_mode,		"get_security_defer_mode"},
	{ e_qcsapi_set_security_defer_mode,		"set_security_defer_mode"},
	{ e_qcsapi_apply_security_config,		"apply_security_config"},

	{ e_qcsapi_get_board_parameter,			"get_board_parameter" },
	{ e_qcsapi_wifi_set_intra_bss_isolate,		"set_intra_bss_isolate" },
	{ e_qcsapi_wifi_get_intra_bss_isolate,		"get_intra_bss_isolate" },
	{ e_qcsapi_wifi_set_bss_isolate,		"set_bss_isolate" },
	{ e_qcsapi_wifi_get_bss_isolate,		"get_bss_isolate" },

	{ e_qcsapi_wowlan_host_state,			"wowlan_host_state" },
	{ e_qcsapi_wowlan_match_type,			"wowlan_match_type" },
	{ e_qcsapi_wowlan_L2_type,			"wowlan_L2_type" },
	{ e_qcsapi_wowlan_udp_port,			"wowlan_udp_port" },
	{ e_qcsapi_wowlan_pattern,			"wowlan_pattern" },
	{ e_qcsapi_wowlan_get_host_state,		"wowlan_get_host_state" },
	{ e_qcsapi_wowlan_get_match_type,		"wowlan_get_match_type" },
	{ e_qcsapi_wowlan_get_L2_type,			"wowlan_get_L2_type" },
	{ e_qcsapi_wowlan_get_udp_port,			"wowlan_get_udp_port" },
	{ e_qcsapi_wowlan_get_pattern,			"wowlan_get_pattern" },

	{ e_qcsapi_wifi_set_extender_params,		"set_extender_params" },
	{ e_qcsapi_wifi_get_extender_status,		"get_extender_status" },
	{ e_qcsapi_wifi_set_extender_key,		"set_extender_key" },

	{ e_qcsapi_wifi_set_autochan_params,		"set_autochan_params" },
	{ e_qcsapi_wifi_get_autochan_params,		"get_autochan_params" },
	{ e_qcsapi_wifi_update_autochan_params,		"update_autochan_params" },

	{ e_qcsapi_wifi_enable_bgscan,			"enable_bgscan" },
	{ e_qcsapi_wifi_get_bgscan_status,		"get_bgscan_status" },

	{ e_qcsapi_get_uboot_info,			"get_uboot_info"},
	{ e_qcsapi_wifi_get_disassoc_reason,		"disassoc_reason"},

	{ e_qcsapi_is_startprod_done,			"is_startprod_done"},

	{ e_qcsapi_get_bb_param,			"get_bb_param" },
	{ e_qcsapi_set_bb_param,			"set_bb_param" },
	{ e_qcsapi_wifi_get_tx_amsdu,			"get_tx_amsdu" },
	{ e_qcsapi_wifi_set_tx_amsdu,			"set_tx_amsdu" },

	{ e_qcsapi_wifi_set_scan_buf_max_size,		"set_scan_buf_max_size" },
	{ e_qcsapi_wifi_get_scan_buf_max_size,		"get_scan_buf_max_size" },
	{ e_qcsapi_wifi_set_scan_table_max_len,		"set_scan_table_max_len" },
	{ e_qcsapi_wifi_get_scan_table_max_len,		"get_scan_table_max_len" },
	{ e_qcsapi_wifi_set_pref_band,                  "set_pref_band" },
	{ e_qcsapi_wifi_get_pref_band,                  "get_pref_band" },

	{ e_qcsapi_wifi_set_enable_mu,			"set_enable_mu" },
	{ e_qcsapi_wifi_get_enable_mu,			"get_enable_mu" },
	{ e_qcsapi_wifi_set_mu_use_precode,		"set_mu_use_precode" },
	{ e_qcsapi_wifi_get_mu_use_precode,		"get_mu_use_precode" },
	{ e_qcsapi_wifi_set_mu_use_eq,			"set_mu_use_eq" },
	{ e_qcsapi_wifi_get_mu_use_eq,			"get_mu_use_eq" },
	{ e_qcsapi_wifi_get_mu_groups,			"get_mu_groups" },
	{ e_qcsapi_set_emac_switch,			"set_emac_switch" },
	{ e_qcsapi_get_emac_switch,			"get_emac_switch" },
	{ e_qcsapi_eth_dscp_map,			"eth_dscp_map" },

	{ e_qcsapi_send_file,				"send_file" },
	{ e_qcsapi_wifi_verify_repeater_mode,		"verify_repeater_mode" },
	{ e_qcsapi_wifi_set_repeater_ifreset,		"set_repeater_ifreset" },
	{ e_qcsapi_wifi_get_repeater_ifreset,		"get_repeater_ifreset" },
	{ e_qcsapi_wifi_set_ap_interface_name,		"set_ap_interface_name" },
	{ e_qcsapi_wifi_get_ap_interface_name,		"get_ap_interface_name" },

	{ e_qcsapi_set_optim_stats,			"set_optim_stats" },

	{ e_qcsapi_set_sys_time,			"set_sys_time" },
	{ e_qcsapi_get_sys_time,			"get_sys_time" },
	{ e_qcsapi_get_eth_info,			"get_eth_info" },
	{ e_qcsapi_wifi_block_bss,			"block_bss" },
	{ e_qcsapi_wifi_get_block_bss,			"get_block_bss" },
	{ e_qcsapi_wifi_set_txba_disable,		"txba_disable" },
	{ e_qcsapi_wifi_get_txba_disable,		"get_txba_disable" },
	{ e_qcsapi_wifi_set_rxba_decline,		"rxba_decline" },
	{ e_qcsapi_wifi_get_rxba_decline,		"get_rxba_decline" },
	{ e_qcsapi_wifi_set_txburst,			"set_txburst" },
	{ e_qcsapi_wifi_get_txburst,			"get_txburst" },

	{ e_qcsapi_wifi_get_sec_chan,			"get_sec_chan" },
	{ e_qcsapi_wifi_set_sec_chan,			"set_sec_chan" },
	{ e_qcsapi_wifi_set_vap_default_state,		"set_vap_default_state" },
	{ e_qcsapi_wifi_get_vap_default_state,		"get_vap_default_state" },
	{ e_qcsapi_wifi_set_vap_state,			"set_vap_state" },
	{ e_qcsapi_wifi_get_vap_state,			"get_vap_state" },
	{ e_qcsapi_wifi_get_txrx_airtime,               "get_txrx_airtime"},
	{ e_qcsapi_wifi_get_node_stat,			"get_node_stat"},

	{ e_qcsapi_qwe_command,                         "qwe"},
	{ e_qcsapi_get_client_mac_list,			"get_client_mac_list"},
	{ e_qcsapi_get_core_dump,                       "get_core_dump"},
	{ e_qcsapi_get_app_core_dump,			"get_app_core_dump"},
	{ e_qcsapi_get_sys_log,				"get_sys_log"},

	{ e_qcsapi_wifi_sample_all_clients,		"sample_all_clients"},
	{ e_qcsapi_wifi_get_per_assoc_data,		"get_sampled_assoc_data"},

	{ e_qcsapi_wifi_set_tx_chains,			"set_tx_chains" },
	{ e_qcsapi_wifi_get_tx_chains,                  "get_tx_chains" },
	{ e_qcsapi_get_wifi_ready,			"is_wifi_ready" },

	{ e_qcsapi_get_cca_stats,                       "get_cca_stats" },

	{ e_qcsapi_get_ep_status,			"get_ep_status" },

	{ e_qcsapi_get_igmp_snooping_state,		"get_igmp_snooping_state" },
	{ e_qcsapi_set_igmp_snooping_state,		"set_igmp_snooping_state" },

	{ e_qcsapi_set_max_bcast_pps,		"set_max_bcast_pps"},
	{ e_qcsapi_wifi_set_scs_leavedfs_chan_mtrc_mrgn, "set_scs_leavedfs_chan_mtrc_mrgn" },

	{ e_qcsapi_set_max_boot_cac_duration,		"set_max_boot_cac_duration"},
	{ e_qcsapi_set_log_level,			"set_log_level"},
	{ e_qcsapi_get_log_level,			"get_log_level"},
	{ e_qcsapi_set_remote_logging,                  "set_remote_logging"},
	{ e_qcsapi_set_console,				"set_console"},

	{ e_qcsapi_set_vopt,				"set_vopt"},
	{ e_qcsapi_get_vopt,				"get_vopt"},

	{ e_qcsapi_wifi_set_threshold_of_neighborhood_type,"set_threshold_of_neighborhood_type"},
	{ e_qcsapi_wifi_get_threshold_of_neighborhood_type,"get_threshold_of_neighborhood_type"},
	{ e_qcsapi_wifi_get_neighborhood_type,		"get_neighborhood_type"},

	{ e_qcsapi_do_system_action,			"do_system_action"},
	{ e_qcsapi_get_device_mode,			"get_device_mode" },

	{ e_qcsapi_wifi_is_weather_channel,		"is_weather_channel"},

	{ e_qcsapi_wifi_set_br_isolate,			"set_br_isolate" },
	{ e_qcsapi_wifi_get_br_isolate,			"get_br_isolate"},

	{ e_qcsapi_wifi_get_tx_max_amsdu,		"get_tx_max_amsdu" },
	{ e_qcsapi_wifi_set_tx_max_amsdu,		"set_tx_max_amsdu" },

	{ e_qcsapi_wifi_show_access_points,		"show_access_points" },
	{ e_qcsapi_wifi_get_nac_mon_mode,		"get_nac_mon_mode" },
	{ e_qcsapi_wifi_set_nac_mon_mode,		"set_nac_mon_mode" },
	{ e_qcsapi_wifi_get_nac_stats,			"get_nac_stats" },

	{ e_qcsapi_wifi_set_ieee80211r,			"set_ieee80211r" },
	{ e_qcsapi_wifi_get_ieee80211r,			"get_ieee80211r" },
	{ e_qcsapi_wifi_set_11r_mobility_domain,	"set_11r_mobility_domain" },
	{ e_qcsapi_wifi_get_11r_mobility_domain,	"get_11r_mobility_domain" },
	{ e_qcsapi_wifi_set_11r_nas_id,			"set_11r_nas_id" },
	{ e_qcsapi_wifi_get_11r_nas_id,			"get_11r_nas_id" },
	{ e_qcsapi_wifi_set_11r_ft_over_ds,		"set_11r_ft_over_ds" },
	{ e_qcsapi_wifi_get_11r_ft_over_ds,		"get_11r_ft_over_ds" },

	{ e_qcsapi_set_report_flood_interval,		"set_report_flood_interval" },
	{ e_qcsapi_get_report_flood_interval,		"get_report_flood_interval" },

	{ e_qcsapi_wifi_get_btm_cap,			"get_btm_cap" },
	{ e_qcsapi_wifi_set_btm_cap,			"set_btm_cap" },

	{ e_qcsapi_wifi_get_rm_neigh_report,		"get_rm_neigh_report" },
	{ e_qcsapi_wifi_set_rm_neigh_report,		"set_rm_neigh_report" },

	{ e_qcsapi_wifi_add_11r_neighbour,		"add_11r_neighbour" },
	{ e_qcsapi_wifi_del_11r_neighbour,		"del_11r_neighbour" },
	{ e_qcsapi_wifi_get_11r_neighbour,		"get_11r_neighbour" },

	{ e_qcsapi_wifi_set_11r_r1_key_holder,		"set_11r_r1_key_holder" },
	{ e_qcsapi_wifi_get_11r_r1_key_holder,		"get_11r_r1_key_holder" },

	{ e_qcsapi_get_pd_voltage_level,		"get_pd_voltage_level" },

	{ e_qcsapi_reload_security_config,		"reload_security_config"},

	{ e_qcsapi_get_icac_status,			"get_icac_status"},
	{ e_qcsapi_enable_emac_sdp,			"enable_emac_sdp"},
	{ e_qcsapi_set_bss_rxchan,			"set_bss_rxchan"},

	{ e_qcsapi_set_unknown_dest_discover_intval,	"set_unknown_dest_discover_intval"},
	{ e_qcsapi_get_unknown_dest_discover_intval,	"get_unknown_dest_discover_intval"},

	{ e_qcsapi_set_3addr_br_config,			"set_3addr_br_config" },
	{ e_qcsapi_get_3addr_br_config,			"get_3addr_br_config" },

	{ e_qcsapi_wifi_get_pta_param,			"get_pta_param" },
	{ e_qcsapi_wifi_set_pta_param,			"set_pta_param" },

	{ e_qcsapi_wifi_get_sec_cca_param,		"get_sec_cca_param" },
	{ e_qcsapi_wifi_set_sec_cca_param,		"set_sec_cca_param" },

	{ e_qcsapi_wifi_repeater_mode_cfg,		"repeater_mode_cfg"},
	{ e_qcsapi_wifi_set_urepeater_params,		"set_urepeater_params"},
	{ e_qcsapi_wifi_get_urepeater_params,		"get_urepeater_params"},

	{ e_qcsapi_set_ac_inheritance,			"set_ac_inheritance"},

	{ e_qcsapi_set_dynamic_wmm,			"set_dyn_wmm"},
	{ e_qcsapi_wifi_set_oper_bw,			"set_oper_bw"},

	{ e_qcsapi_grab_config,				"grab_config" },

	{ e_qcsapi_wifi_get_current_band,		"get_current_band" },
	{ e_qcsapi_wifi_get_restrict_wlan_ip,		"get_restrict_wlan_ip" },
	{ e_qcsapi_wifi_set_restrict_wlan_ip,		"set_restrict_wlan_ip" },

	{ e_qcsapi_wifi_get_phy_param,			"get_phy_param" },
	{ e_qcsapi_wifi_set_phy_param,			"set_phy_param" },

	{ e_qcsapi_get_reboot_cause,			"get_reboot_cause"},

	{ e_qcsapi_wifi_add_wps_pbc_ssid_filter,	"add_wps_pbc_ssid_filter"},
	{ e_qcsapi_wifi_del_wps_pbc_ssid_filter,	"del_wps_pbc_ssid_filter"},
	{ e_qcsapi_wifi_show_wps_pbc_ssid_filters,	"show_wps_pbc_ssid_filters"},

	{ e_qcsapi_wifi_enable_repeater_ap,	"enable_repeater_ap"},
	{ e_qcsapi_wifi_disable_repeater_ap,	"disable_repeater_ap"},

	{ e_qcsapi_wifi_get_beacon_power_backoff,	"get_beacon_power_backoff" },
	{ e_qcsapi_wifi_set_beacon_power_backoff,	"set_beacon_power_backoff" },
	{ e_qcsapi_wifi_get_mgmt_power_backoff,		"get_mgmt_power_backoff" },
	{ e_qcsapi_wifi_set_mgmt_power_backoff,		"set_mgmt_power_backoff" },
	{ e_qcsapi_wifi_dpp_parameter,			"dpp_param"},

	{ e_qcsapi_wifi_multi_psk_info_append,		"multi_psk_info_append" },
	{ e_qcsapi_wifi_multi_psk_info_read,		"multi_psk_info_read" },
	{ e_qcsapi_wifi_multi_psk_info_replace,		"multi_psk_info_replace" },
	{ e_qcsapi_wifi_start_phy_scan,			"start_phy_scan" },

	{ e_qcsapi_wifi_get_chan_phy_info,		"get_chan_phy_info" },

	{ e_qcsapi_nosuch_api, NULL }
};

static const struct
{
	qcsapi_counter_type	 counter_type;
	const char		*counter_name;
} qcsapi_counter_name[] =
{
	{ qcsapi_total_bytes_sent,		"tx_bytes" },
	{ qcsapi_total_bytes_received,		"rx_bytes" },
	{ qcsapi_total_packets_sent,		"tx_packets" },
	{ qcsapi_total_packets_received,	"rx_packets" },
	{ qcsapi_discard_packets_sent,		"tx_discard" },
	{ qcsapi_discard_packets_received,	"rx_discard" },
	{ qcsapi_error_packets_sent,		"tx_errors" },
	{ qcsapi_error_packets_received,	"rx_errors" },
	{ qcsapi_vlan_frames_received,		"rx_vlan_pkts" },
	{ qcsapi_fragment_frames_received,	"rx_fragment_pkts" },
	{ qcsapi_nosuch_counter,	 NULL }
};

static const struct
{
	qcsapi_option_type	 option_type;
	const char		*option_name;
} qcsapi_option_name[] =
{
	{ qcsapi_channel_refresh,	"channel_refresh" },
	{ qcsapi_DFS,			"DFS" },
	{ qcsapi_wmm,			"WiFi_MultiMedia" },
	{ qcsapi_wmm,			"WMM" },
	{ qcsapi_beacon_advertise,	"beacon_advertise" },
	{ qcsapi_beacon_advertise,	"beacon" },
	{ qcsapi_wifi_radio,		"radio" },
	{ qcsapi_autorate_fallback,	"autorate_fallback" },
	{ qcsapi_autorate_fallback,	"autorate" },
	{ qcsapi_security,		"security" },
	{ qcsapi_SSID_broadcast,	"broadcast_SSID" },
	{ qcsapi_SSID_broadcast,	"SSID_broadcast" },
	{ qcsapi_short_GI,		"shortGI" },
	{ qcsapi_short_GI,		"short_GI" },
	{ qcsapi_802_11h,		"802_11h" },
	{ qcsapi_tpc_query,		"tpc_query" },
	{ qcsapi_dfs_fast_channel_switch, "dfs_fast_switch" },
	{ qcsapi_dfs_avoid_dfs_scan,	"avoid_dfs_scan" },
	{ qcsapi_uapsd,			"uapsd" },
	{ qcsapi_sta_dfs,		"sta_dfs" },
	{ qcsapi_specific_scan,		"specific_scan" },
	{ qcsapi_GI_probing,		"GI_probing" },
	{ qcsapi_GI_fixed,		"GI_fixed" },
	{ qcsapi_stbc,			"stbc" },
	{ qcsapi_beamforming,		"beamforming" },
	{ qcsapi_short_slot,		"short_slot" },
	{ qcsapi_short_preamble,	"short_preamble" },
	{ qcsapi_rts_cts,		"rts_cts" },
	{ qcsapi_40M_only,		"40M_bw_only" },
	{ qcsapi_20_40_coex,		"20_40_coex" },
	{ qcsapi_obss_scan,		"obss_scan" },
	{ qcsapi_11g_protection,	"11g_protection" },
	{ qcsapi_11n_protection,	"11n_protection" },
	{ qcsapi_qlink,			"qlink" },
	{ qcsapi_sta_dfs_strict,	"sta_dfs_strict" },
	{ qcsapi_sync_config,		"sync_config" },
	{ qcsapi_txamsdu_11n,		"tx_amsdu_11n" },
	{ qcsapi_4addr_mode,		"4addr_mode" },
	{ qcsapi_auto_cca,		"auto_cca" },
	{ qcsapi_tx_enable,		"tx_enable" },
	{ qcsapi_dup_rts,		"dup_rts" },
	{ qcsapi_mu_qm_bypass,		"mu_qm_bypass" },
	{ qcsapi_nosuch_option,		 NULL }
};

static const struct
{
	qcsapi_board_parameter_type	board_param;
	const char			*board_param_name;
} qcsapi_board_parameter_name[] =
{
	{ qcsapi_hw_revision,		"hw_revision" },
	{ qcsapi_hw_id,			"hw_id" },
	{ qcsapi_hw_desc,		"hw_desc" },
	{ qcsapi_rf_chipid,		"rf_chipid" },
	{ qcsapi_bond_opt,              "bond_opt" },
	{ qcsapi_vht,                   "vht_status" },
	{ qcsapi_bandwidth,             "bw_supported" },
	{ qcsapi_spatial_stream,        "spatial_stream" },
	{ qcsapi_interface_types,	"interface_types" },
	{ qcsapi_rf_chip_verid,         "rf_chip_verid" },
	{ qcsapi_name,			"name" },
	{ qcsapi_board_id,		"board_id" },
	{ qcsapi_platform_id,	"platform_id" },
	{ qcsapi_nosuch_parameter,      NULL }
};

static const struct
{
	qcsapi_rate_type	 rate_type;
	const char		*rate_name;
} qcsapi_rate_types_name[] =
{
	{ qcsapi_basic_rates,		"basic_rates" },
	{ qcsapi_basic_rates,		"basic" },
	{ qcsapi_operational_rates,	"operational_rates" },
	{ qcsapi_operational_rates,	"operational" },
	{ qcsapi_possible_rates,	"possible_rates" },
	{ qcsapi_possible_rates,	"possible" },
	{ qcsapi_nosuch_rate,		 NULL }
};

static const struct {
	qcsapi_mimo_type std_type;
	const char *std_name;
} qcsapi_wifi_std_name[] = {
	{qcsapi_mimo_ht, "ht"},
	{qcsapi_mimo_vht, "vht"},
	{qcsapi_nosuch_standard, NULL}
};

static const struct
{
	qcsapi_flash_partiton_type	 partition_type;
	const char			*partition_name;
} qcsapi_partition_name[] =
{
	{ qcsapi_image_linux_live,	"live" },
	{ qcsapi_image_linux_safety,	"safety" },
	{ qcsapi_image_uboot_live,	"uboot_live" },
	{ qcsapi_image_uboot_safety,	"uboot_safety" },
	{ qcsapi_image_uboot,		"uboot" },
	{ qcsapi_nosuch_partition,	 NULL }
};

static const struct
{
	int		 qos_queue_type;
	const char	*qos_queue_name;
} qcsapi_qos_queue_table[] =
{
	{ WME_AC_BE,	"BE" },
	{ WME_AC_BK,	"BK" },
	{ WME_AC_VI,	"VI" },
	{ WME_AC_VO,	"VO" },
	{ WME_AC_BE,	"besteffort" },
	{ WME_AC_BK,	"background" },
	{ WME_AC_VI,	"video" },
	{ WME_AC_VO,	"voice" }
};

static const struct
{
	const char	*fix_name;
	unsigned	fix_idx;
} qcsapi_vendor_fix_table[] =
{
	{ "brcm_dhcp",	VENDOR_FIX_IDX_BRCM_DHCP},
	{ "brcm_igmp",	VENDOR_FIX_IDX_BRCM_IGMP},
};

static const struct
{
	int		 qos_param_type;
	const char	*qos_param_name;
} qcsapi_qos_param_table[] =
{
	{ IEEE80211_WMMPARAMS_CWMIN,	"cwmin" },
	{ IEEE80211_WMMPARAMS_CWMAX,	"cwmax" },
	{ IEEE80211_WMMPARAMS_AIFS,	"aifs" },
	{ IEEE80211_WMMPARAMS_TXOPLIMIT, "tx_op" },
	{ IEEE80211_WMMPARAMS_TXOPLIMIT, "txoplimit" },
	{ IEEE80211_WMMPARAMS_ACM, "acm" },
	{ IEEE80211_WMMPARAMS_NOACKPOLICY, "noackpolicy" }
};

static const struct{
	qcsapi_system_status bit_id;
	char *description;
} qcsapi_sys_status_table[] =
{
	{qcsapi_sys_status_ethernet, "Ethernet interface"},
	{qcsapi_sys_status_pcie_ep, "PCIE EP driver"},
	{qcsapi_sys_status_pcie_rc, "PCIE RC driver"},
	{qcsapi_sys_status_wifi, "WiFi driver"},
	{qcsapi_sys_status_rpcd, "Rpcd server"},
	{qcsapi_sys_status_cal_mode, "Calstate mode"},
	{qcsapi_sys_status_completed, "System boot up completely"},
};

static const struct{
	const char		*name;
	enum qscs_cfg_param_e	index;
} qcsapi_scs_param_names_table[] =
{
	{"scs_smpl_dwell_time",			SCS_SMPL_DWELL_TIME},
	{"scs_sample_intv",			SCS_SAMPLE_INTV},
	{"scs_sample_type",			SCS_SAMPLE_TYPE},
	{"scs_thrshld_smpl_pktnum",		SCS_THRSHLD_SMPL_PKTNUM},
	{"scs_thrshld_smpl_airtime",		SCS_THRSHLD_SMPL_AIRTIME},
	{"scs_thrshld_atten_inc",		SCS_THRSHLD_ATTEN_INC},
	{"scs_thrshld_dfs_reentry",		SCS_THRSHLD_DFS_REENTRY},
	{"scs_thrshld_dfs_reentry_minrate",	SCS_THRSHLD_DFS_REENTRY_MINRATE},
	{"scs_thrshld_dfs_reentry_intf",	SCS_THRSHLD_DFS_REENTRY_INTF},
	{"scs_thrshld_loaded",			SCS_THRSHLD_LOADED},
	{"scs_thrshld_aging_nor",		SCS_THRSHLD_AGING_NOR},
	{"scs_thrshld_aging_dfsreent",		SCS_THRSHLD_AGING_DFSREENT},
	{"scs_enable",				SCS_ENABLE},
	{"scs_debug_enable",			SCS_DEBUG_ENABLE},
	{"scs_smpl_enable",			SCS_SMPL_ENABLE},
	{"scs_report_only",			SCS_REPORT_ONLY},
	{"scs_cca_idle_thrshld",		SCS_CCA_IDLE_THRSHLD},
	{"scs_cca_intf_abs_thrshld",		SCS_CCA_INTF_ABS_THRSHLD},
	{"scs_cca_intf_hi_thrshld",		SCS_CCA_INTF_HI_THRSHLD},
	{"scs_cca_intf_lo_thrshld",		SCS_CCA_INTF_LO_THRSHLD},
	{"scs_cca_intf_ratio",			SCS_CCA_INTF_RATIO},
	{"scs_cca_intf_dfs_margin",		SCS_CCA_INTF_DFS_MARGIN},
	{"scs_pmbl_err_thrshld",		SCS_PMBL_ERR_THRSHLD},
	{"scs_cca_sample_dur",			SCS_CCA_SAMPLE_DUR},
	{"scs_cca_intf_smth_fctr",		SCS_CCA_INTF_SMTH_NOXP},
	{"scs_cca_intf_smth_fctr",		SCS_CCA_INTF_SMTH_XPED},
	{"scs_rssi_smth_fctr",			SCS_RSSI_SMTH_UP},
	{"scs_rssi_smth_fctr",			SCS_RSSI_SMTH_DOWN},
	{"scs_chan_mtrc_mrgn",			SCS_CHAN_MTRC_MRGN},
	{"scs_inband_chan_mtrc_mrgn",		SCS_INBAND_CHAN_MTRC_MRGN},
	{"scs_atten_adjust",			SCS_ATTEN_ADJUST},
	{"scs_atten_sw_enable",			SCS_ATTEN_SW_ENABLE},
	{"scs_pmbl_err_smth_fctr",		SCS_PMBL_ERR_SMTH_FCTR},
	{"scs_pmbl_err_range",			SCS_PMBL_ERR_RANGE},
	{"scs_pmbl_err_mapped_intf_range",	SCS_PMBL_ERR_MAPPED_INTF_RANGE},
	{"scs_sp_wf",				SCS_SP_WF},
	{"scs_lp_wf",				SCS_LP_WF},
	{"scs_pmp_rpt_cca_smth_fctr",		SCS_PMP_RPT_CCA_SMTH_FCTR},
	{"scs_pmp_rx_time_smth_fctr",		SCS_PMP_RX_TIME_SMTH_FCTR},
	{"scs_pmp_tx_time_smth_fctr",		SCS_PMP_TX_TIME_SMTH_FCTR},
	{"scs_pmp_stats_stable_percent",	SCS_PMP_STATS_STABLE_PERCENT},
	{"scs_pmp_stats_stable_range",		SCS_PMP_STATS_STABLE_RANGE},
	{"scs_pmp_stats_clear_interval",	SCS_PMP_STATS_CLEAR_INTERVAL},
	{"scs_as_rx_time_smth_fctr",		SCS_AS_RX_TIME_SMTH_FCTR},
	{"scs_as_tx_time_smth_fctr",		SCS_AS_TX_TIME_SMTH_FCTR},
	{"scs_cca_idle_smth_fctr",		SCS_CCA_IDLE_SMTH_FCTR},
	{"scs_tx_time_compensation",		SCS_TX_TIME_COMPENSTATION_START},
	{"scs_rx_time_compensation",		SCS_RX_TIME_COMPENSTATION_START},
	{"scs_tdls_time_compensation",		SCS_TDLS_TIME_COMPENSTATION_START},
	{"scs_leavedfs_chan_mtrc_mrgn",		SCS_LEAVE_DFS_CHAN_MTRC_MRGN},
	{"scs_cca_threshold_type",		SCS_CCA_THRESHOD_TYPE},
	{"scs_burst_enable",			SCS_BURST_ENABLE},
	{"scs_burst_window",			SCS_BURST_WINDOW},
	{"scs_burst_thresh",			SCS_BURST_THRESH},
	{"scs_burst_pause_time",		SCS_BURST_PAUSE_TIME},
	{"scs_burst_force_switch",		SCS_BURST_FORCE_SWITCH},
	{"scs_nac_monitor_mode",		SCS_NAC_MONITOR_MODE},
	{"scs_override_mode",			SCS_OVERRIDE_MODE},
	{"scs_check_band_mrgn",			SCS_CHECK_BAND_MRGN},
	{"scs_out_of_band_mrgn",		SCS_OUT_OF_BAND_MRGN},
	{"scs_obss_check",			SCS_OBSS_CHECK},
	{"scs_pmbl_err_smth_winsize",		SCS_PMBL_ERR_SMTH_WINSIZE},
};

static const struct
{
	qcsapi_extender_type param_type;
	const char *param_name;
} qcsapi_extender_param_table[] =
{
	{qcsapi_extender_role,	"role"},
	{qcsapi_extender_mbs_best_rssi,	"mbs_best_rssi"},
	{qcsapi_extender_rbs_best_rssi,	"rbs_best_rssi"},
	{qcsapi_extender_mbs_wgt,	"mbs_wgt"},
	{qcsapi_extender_rbs_wgt,	"rbs_wgt"},
	{qcsapi_extender_roaming,	"roaming"},
	{qcsapi_extender_bgscan_interval,	"bgscan_interval"},
	{qcsapi_extender_verbose,	"verbose"},
	{qcsapi_extender_mbs_rssi_margin,	"mbs_rssi_margin"},
	{qcsapi_extender_short_retry_limit,	"short_retry"},
	{qcsapi_extender_long_retry_limit,	"long_retry"},
	{qcsapi_extender_scan_mbs_intvl,	"scan_mbs_interval"},
	{qcsapi_extender_scan_mbs_mode,	"scan_mbs_mode"},
	{qcsapi_extender_scan_mbs_expiry,	"scan_mbs_expiry"},
	{qcsapi_extender_fast_cac,	"fast_cac"},
	{qcsapi_extender_nosuch_param,	NULL},
};

static const struct
{
	qcsapi_autochan_type param_type;
	const char *param_name;
} qcsapi_autochan_param_table[] =
{
	{qcsapi_autochan_cci_instnt,	"cci_instnt"},
	{qcsapi_autochan_aci_instnt,	"aci_instnt"},
	{qcsapi_autochan_cci_longterm,	"cci_longterm"},
	{qcsapi_autochan_aci_longterm,	"aci_longterm"},
	{qcsapi_autochan_range_cost,	"range_cost"},
	{qcsapi_autochan_dfs_cost,	"dfs_cost"},
	{qcsapi_autochan_min_cci_rssi,	"min_cci_rssi"},
	{qcsapi_autochan_maxbw_minbenefit,	"maxbw_minbenefit"},
	{qcsapi_autochan_dense_cci_span,	"dense_cci_span"},
	{qcsapi_autochan_dbg_level,	"dbg_level"},
	{qcsapi_autochan_obss_check,	"obss_check"},
	{qcsapi_autochan_check_margin,	"check_margin"},
	{qcsapi_autochan_chan_weights,	"chan_weight"},
	{qcsapi_autochan_nosuch_param,	NULL},
};

static const struct {
	qcsapi_wifi_param_type param_type;
	const char *param_name;
} qcsapi_wifi_param_table[] = {
	{qcsapi_wifi_param_dtim_period,		"dtim_period"},
	{qcsapi_wifi_param_cfg_4addr,		"cfg_4addr"},
	{qcsapi_wifi_param_max_bss_idle,	"max_bss_idle"},
	{qcsapi_wifi_param_dfs_csa_cnt,		"dfs_csa_cnt"},
	{qcsapi_wifi_param_bg_scan_idle,	"bg_scan_idle"},
	{qcsapi_wifi_param_scan_valid,		"scan_valid"},
	{qcsapi_wifi_param_scanonly_freq,	"scanonly_freq"},
	{qcsapi_wifi_param_roam_rssi_11a,	"roam_rssi_11a"},
	{qcsapi_wifi_param_roam_rssi_11b,	"roam_rssi_11b"},
	{qcsapi_wifi_param_roam_rssi_11g,	"roam_rssi_11g"},
	{qcsapi_wifi_param_roam_rate_11a,	"roam_rate_11a"},
	{qcsapi_wifi_param_roam_rate_11b,	"roam_rate_11b"},
	{qcsapi_wifi_param_roam_rate_11g,	"roam_rate_11g"},
	{qcsapi_wifi_param_max_bss_num,		"max_bss_num"},
	{qcsapi_wifi_param_tmic_check,		"tmic_check"},
	{qcsapi_wifi_param_obss_flag,		"obss_flag"},
	{qcsapi_wifi_param_multiap_backhaul_sta, "multiap_backhaul_sta"},
	{qcsapi_wifi_param_multiap_backhaul_sta_profile, "multiap_backhaul_sta_profile"},
	{qcsapi_wifi_param_rssi_dbm_endian,	"rssi_dbm_endian"},
	{qcsapi_wifi_param_eap_vlan_tag,	"eap_vlan_tag"},
	{qcsapi_wifi_param_sch_bss_suppress,	"sch_bss_suppress"},
	{qcsapi_wifi_param_sch_tid_suppress,	"sch_tid_suppress"},
	{qcsapi_wifi_param_3addr_mc_msdu_da_rep, "3addr_mc_msdu_da_rep"},
	{qcsapi_wifi_nosuch_parameter,		NULL},
};

static const struct
{
	qcsapi_eth_info_result result_type;
	const char *result_label;
	const char *result_bit_set;
	const char *result_bit_unset;
} qcsapi_eth_info_result_table[] =
{
	{qcsapi_eth_info_connected,	"Connected",		"yes",		"no"},
	{qcsapi_eth_info_speed_unknown,	"Speed",		"unknown",	NULL},
	{qcsapi_eth_info_speed_10M,	"Speed",		"10Mb/s",	NULL},
	{qcsapi_eth_info_speed_100M,	"Speed",		"100Mb/s",	NULL},
	{qcsapi_eth_info_speed_1000M,	"Speed",		"1000Mb/s",	NULL},
	{qcsapi_eth_info_speed_10000M,	"Speed",		"10000Mb/s",	NULL},
	{qcsapi_eth_info_duplex_full,	"Duplex",		"full",		"half"},
	{qcsapi_eth_info_autoneg_on,	"Auto-negotiation",	NULL,		"disabled"},
	{qcsapi_eth_info_autoneg_success,"Auto-negotiation",	"completed",	"failed"},
};

static const struct
{
	qcsapi_eth_info_type type;
	qcsapi_eth_info_type_mask mask;
} qcsapi_eth_info_type_mask_table[] =
{
	{qcsapi_eth_info_link,		qcsapi_eth_info_link_mask},
	{qcsapi_eth_info_speed,		qcsapi_eth_info_speed_mask},
	{qcsapi_eth_info_duplex,	qcsapi_eth_info_duplex_mask},
	{qcsapi_eth_info_autoneg,	qcsapi_eth_info_autoneg_mask},
	{qcsapi_eth_info_all,		qcsapi_eth_info_all_mask},
};

static const struct
{
        int	reason_code;
        const char              *reason_string;
} qcsapi_disassoc_reason_list[] =
{
	{  0, "No disassoc reason reported" },
	{  1, "Unspecified reason" },
	{  2, "Previous authentication no longer valid" },
	{  3, "Deauthenticated because sending STA is leaving (or has left) IBSS or ESS" },
	{  4, "Disassociated due to inactivity" },
	{  5, "Disassociated because AP is unable to handle all currently associated STAs" },
	{  6, "Class 2 frame received from nonauthenticated STA" },
	{  7, "Class 3 frame received from nonassociated STA" },
	{  8, "Disassociated because sending STA is leaving (or has left) BSS" },
	{  9, "STA requesting (re)association is not authenticated with responding STA" },
	{ 10, "Disassociated because the information in the Power Capability element is unacceptable" },
	{ 11, "Disassociated because the information in the Supported Channels element is unacceptable" },
	{ 12, "Reserved" },
	{ 13, "Invalid information element, i.e., an information element defined in this standard for which the content does not meet the specifications in Clause 7" },
	{ 14, "Message integrity code (MIC) failure" },
	{ 15, "4-Way Handshake timeout" },
	{ 16, "Group Key Handshake timeout" },
	{ 17, "Information element in 4-Way Handshake different from (Re)Association Request/Probe Response/Beacon frame" },
	{ 18, "Invalid group cipher" },
	{ 19, "Invalid pairwise cipher" },
	{ 20, "Invalid AKMP" },
	{ 21, "Unsupported RSN information element version" },
	{ 22, "Invalid RSN information element capabilities" },
	{ 23, "IEEE 802.1X authentication failed" },
	{ 24, "Cipher suite rejected because of the security policy" },
	{ 25, "TDLS direct-link teardown due to TDLS peer STA unreachable via the TDLS direct link" },
	{ 26, "TDLS direct-link teardown for unspecified reason" },
	{ 27, "Disassociated because session terminated by SSP request" },
	{ 28, "Disassociated because of lack of SSP roaming agreement" },
	{ 29, "Requested service rejected because of SSP cipher suite or AKM requirement " },
	{ 30, "Requested service not authorized in this location" },
	{ 31, "TS deleted because QoS AP lacks sufficient bandwidth for this QoS STA due to a change in BSS service characteristics or operational mode" },
	{ 32, "Disassociated for unspecified, QoS-related reason" },
	{ 33, "Disassociated because QoS AP lacks sufficient bandwidth for this QoS STA" },
	{ 34, "Disassociated because excessive number of frames need to be acknowledged, but are not acknowledged due to AP transmissions and/or poor channel conditions" },
	{ 35, "Disassociated because STA is transmitting outside the limits of its TXOPs" },
	{ 36, "Requested from peer STA as the STA is leaving the BSS (or resetting)" },
	{ 37, "Requested from peer STA as it does not want to use the mechanism" },
	{ 38, "Requested from peer STA as the STA received frames using the mechanism for which a setup is required" },
	{ 39, "Requested from peer STA due to timeout" },
	{ 45, "Peer STA does not support the requested cipher suite" },
	{ 46, "Disassociated because authorized access limit reached" },
	{ 47, "Disassociated due to external service requirements" },
	{ 48, "Invalid FT Action frame count" },
	{ 49, "Invalid pairwise master key identifier (PMKI)" },
	{ 50, "Invalid MDE" },
	{ 51, "Invalid FTE" },
	{ 52, "SME cancels the mesh peering instance with the reason other than reaching the maximum number of peer mesh STAs" },
	{ 53, "The mesh STA has reached the supported maximum number of peer mesh STAs" },
	{ 54, "The received information violates the Mesh Configuration policy configured in the mesh STA profile" },
	{ 55, "The mesh STA has received a Mesh Peering Close message requesting to close the mesh peering" },
	{ 56, "The mesh STA has re-sent dot11MeshMaxRetries Mesh Peering Open messages, without receiving a Mesh Peering Confirm message" },
	{ 57, "The confirmTimer for the mesh peering instance times out" },
	{ 58, "The mesh STA fails to unwrap the GTK or the values in the wrapped contents do not match" },
	{ 59, "The mesh STA receives inconsistent information about the mesh parameters between Mesh Peering Management frames" },
	{ 60, "The mesh STA fails the authenticated mesh peering exchange because due to failure in selecting either the pairwise ciphersuite or group ciphersuite" },
	{ 61, "The mesh STA does not have proxy information for this external destination" },
	{ 62, "The mesh STA does not have forwarding information for this destination" },
	{ 63, "The mesh STA determines that the link to the next hop of an active path in its forwarding information is no longer usable" },
	{ 64, "The Deauthentication frame was sent because the MAC address of the STA already exists in the mesh BSS. See 11.3.3 (Additional mechanisms for an AP collocated with a mesh STA)" },
	{ 65, "The mesh STA performs channel switch to meet regulatory requirements" },
	{ 66, "The mesh STA performs channel switch with unspecified reason" },
};

static const struct
{
	qcsapi_tdls_type param_type;
	const char *param_name;
} qcsapi_tdls_param_table[] =
{
	{qcsapi_tdls_over_qhop_enabled,	"tdls_over_qhop"},
	{qcsapi_tdls_indication_window,	"indication_window"},
	{qcsapi_tdls_chan_switch_mode, "chan_switch_mode"},
	{qcsapi_tdls_chan_switch_off_chan, "chan_switch_off_chan"},
	{qcsapi_tdls_chan_switch_off_chan_bw, "chan_switch_off_chan_bw"},
	{qcsapi_tdls_link_timeout_time,	"link_timeout_time"},
	{qcsapi_tdls_verbose, "verbose"},
	{qcsapi_tdls_discovery_interval, "disc_interval"},
	{qcsapi_tdls_node_life_cycle, "node_life_cycle"},
	{qcsapi_tdls_mode, "mode"},
	{qcsapi_tdls_min_rssi, "min_valid_rssi"},
	{qcsapi_tdls_link_weight, "link_weight"},
	{qcsapi_tdls_rate_weight, "phy_rate_weight"},
	{qcsapi_tdls_training_pkt_cnt, "training_pkt_cnt"},
	{qcsapi_tdls_switch_ints, "link_switch_ints"},
	{qcsapi_tdls_path_select_pps_thrshld, "path_sel_pps_thrshld"},
	{qcsapi_tdls_path_select_rate_thrshld, "path_sel_rate_thrshld"},
};

static const struct
{
	qcsapi_tdls_oper oper;
	const char *oper_name;
} qcsapi_tdls_oper_table[] =
{
	{qcsapi_tdls_oper_discover, "discover"},
	{qcsapi_tdls_oper_setup, "setup"},
	{qcsapi_tdls_oper_teardown, "teardown"},
	{qcsapi_tdls_oper_switch_chan, "switch_chan"},
};

static const char *qcsapi_auth_algo_list[] = {
	"OPEN",
	"SHARED",
};

static const char *qcsapi_auth_keyproto_list[] = {
	"NONE",
	"WPA",
	"WPA2",
};

static const char *qcsapi_auth_keymgmt_list[] = {
	"NONE",
	"WPA-EAP",
	"WPA-PSK",
	"WEP",
};

static const char *qcsapi_auth_cipher_list[] = {
	"WEP",
	"TKIP",
	"OCB",
	"CCMP",
	"CMAC",
	"CKIP",
};

static const char *qcsapi_wifi_modes_strings[] = WLAN_WIFI_MODES_STRINGS;


static const char*
qcsapi_csw_reason_list[] = {
	[IEEE80211_CSW_REASON_UNKNOWN] = "UNKNOWN",
	[IEEE80211_CSW_REASON_SCS] = "SCS",
	[IEEE80211_CSW_REASON_DFS] = "DFS",
	[IEEE80211_CSW_REASON_MANUAL] = "MANUAL",
	[IEEE80211_CSW_REASON_CONFIG] = "CONFIG",
	[IEEE80211_CSW_REASON_SCAN] = "SCAN",
	[IEEE80211_CSW_REASON_OCAC] = "SDFS",
	[IEEE80211_CSW_REASON_CSA] = "CSA",
	[IEEE80211_CSW_REASON_TDLS_CS] = "TDLS",
	[IEEE80211_CSW_REASON_COC] = "COC",
};

const int qtn_nis_val_result_idx[] = {
	/* Set 0 */
	0,
	/* Set 1 */
	0,
	/* Set 2 */
	QTN_NIS_S2_basic,
	/* Set 3 */
	QTN_NIS_S3_cca,
	/* Set 4 */
	QTN_NIS_S4_rpi_size,
	/* Set 5 */
	QTN_NIS_S5_chan_load,
	/* Set 6 */
	QTN_NIS_S6_antenna_id,
	/* Set 7 */
	QTN_NIS_S7_item_num,
	/* Set 8 */
	QTN_NIS_S8_sub_ele_report,
	/* Set 9 */
	QTN_NIS_S9_reason,
	/* Set 10 */
	QTN_NIS_S10_reason,
	/* Set 11 */
	QTN_NIS_S11_tx_power,
	/* Set 12 */
	QTN_NIS_S12_item_num,
	/* Set 13 */
	QTN_NIS_S13_status,
	/* Set 14 */
	QTN_NIS_S14_common_b1,
};

/**
 * Node information set labels
 * This table must be kept in sync with Node Information Set enums (e.g. qtn_nis_s0_e).
 */
const struct qtn_nis_meta_data qtn_nis_meta[][QTN_NIS_VAL_MAX] = {
	{ /* Set 0 */
	[QTN_NIS_S0_assoc_id] =		{QTN_NIS_VAL_UNSIGNED, "Association ID"},
	[QTN_NIS_S0_bw] =		{QTN_NIS_VAL_UNSIGNED, "Bandwidth"},

	[QTN_NIS_S0_tx_bytes] =		{QTN_NIS_VAL_UNSIGNED, "Tx bytes"},
	[QTN_NIS_S0_tx_packets] =	{QTN_NIS_VAL_UNSIGNED, "Tx packets"},
	[QTN_NIS_S0_tx_amsdu_msdus] =	{QTN_NIS_VAL_UNSIGNED, "Tx aggregated MSDUs"},
	[QTN_NIS_S0_tx_mpdus] =		{QTN_NIS_VAL_UNSIGNED, "Tx MPDUs"},
	[QTN_NIS_S0_tx_ppdus] =		{QTN_NIS_VAL_UNSIGNED, "Tx PPDUs"},
	[QTN_NIS_S0_tx_dropped] =	{QTN_NIS_VAL_UNSIGNED, "Tx discards"},
	[QTN_NIS_S0_tx_wifi_drop1] =	{QTN_NIS_VAL_UNSIGNED, "Packets failed to transmit on AC 1"},
	[QTN_NIS_S0_tx_wifi_drop2] =	{QTN_NIS_VAL_UNSIGNED, "Packets failed to transmit on AC 2"},
	[QTN_NIS_S0_tx_wifi_drop3] =	{QTN_NIS_VAL_UNSIGNED, "Packets failed to transmit on AC 3"},
	[QTN_NIS_S0_tx_wifi_drop4] =	{QTN_NIS_VAL_UNSIGNED, "Packets failed to transmit on AC 4"},
	[QTN_NIS_S0_tx_errors] =	{QTN_NIS_VAL_UNSIGNED, "Tx errors"},
	[QTN_NIS_S0_tx_ucast] =		{QTN_NIS_VAL_UNSIGNED, "Tx unicast"},
	[QTN_NIS_S0_tx_mcast] =		{QTN_NIS_VAL_UNSIGNED, "Tx multicast"},
	[QTN_NIS_S0_tx_bcast] =		{QTN_NIS_VAL_UNSIGNED, "Tx broadcast"},
	[QTN_NIS_S0_tx_max_phy_rate] =	{QTN_NIS_VAL_UNSIGNED, "Tx max PHY rate (kbps)"},
	[QTN_NIS_S0_tx_max_nss] =	{QTN_NIS_VAL_UNSIGNED, "Tx max NSS"},
	[QTN_NIS_S0_tx_max_mcs] =	{QTN_NIS_VAL_UNSIGNED, "Tx max MCS"},
	[QTN_NIS_S0_tx_last_phy_rate] =	{QTN_NIS_VAL_UNSIGNED, "Tx last PHY rate (Mbps)"},
	[QTN_NIS_S0_tx_last_nss] =	{QTN_NIS_VAL_UNSIGNED, "Tx last NSS"},
	[QTN_NIS_S0_tx_last_mcs] =	{QTN_NIS_VAL_UNSIGNED, "Tx last MCS"},
	[QTN_NIS_S0_rx_flags] =		{QTN_NIS_VAL_UNSIGNED, "Rx flags"},
	[QTN_NIS_S0_tx_retries] =	{QTN_NIS_VAL_UNSIGNED, "Tx retries"},
	[QTN_NIS_S0_tx_bw] =		{QTN_NIS_VAL_UNSIGNED, "Tx bandwidth"},

	[QTN_NIS_S0_timestamp_last_rx] =        {QTN_NIS_VAL_UNSIGNED, "Timestamp last rx"},
	[QTN_NIS_S0_timestamp_last_tx] =	{QTN_NIS_VAL_UNSIGNED, "Timestamp last tx"},
	[QTN_NIS_S0_average_tx_phyrate] =	{QTN_NIS_VAL_UNSIGNED, "Average tx phyrate"},
	[QTN_NIS_S0_average_rx_phyrate] =	{QTN_NIS_VAL_UNSIGNED, "Average rx phyrate"},
	[QTN_NIS_S0_average_rssi] =	{QTN_NIS_VAL_SIGNED, "Average rssi"},
	[QTN_NIS_S0_pkts_per_sec] =	{QTN_NIS_VAL_UNSIGNED, "Packets per second"},
	[QTN_NIS_S0_tx_pkt_errors] =	{QTN_NIS_VAL_UNSIGNED, "Tx packet errors"},
	[QTN_NIS_S0_tx_airtime] =	{QTN_NIS_VAL_UNSIGNED, "Utilization Transmit (1000 units)"},
	[QTN_NIS_S0_rx_airtime] =	{QTN_NIS_VAL_UNSIGNED, "Utilization Receive (1000 units)"},
	[QTN_NIS_S0_tx_last_rate] =	{QTN_NIS_VAL_UNSIGNED, "LastDataUplinkRate (kbps)"},
	[QTN_NIS_S0_rx_last_rate] =	{QTN_NIS_VAL_UNSIGNED, "LastDataDownlinkRate (kbps)"},
	[QTN_NIS_S0_tx_retry_cnt] =	{QTN_NIS_VAL_UNSIGNED, "Retransmission Count"},

	[QTN_NIS_S0_rx_bytes] =		{QTN_NIS_VAL_UNSIGNED, "Rx bytes"},
	[QTN_NIS_S0_rx_packets] =	{QTN_NIS_VAL_UNSIGNED, "Rx packets"},
	[QTN_NIS_S0_rx_amsdu_msdus] =	{QTN_NIS_VAL_UNSIGNED, "Rx aggregated MSDUs"},
	[QTN_NIS_S0_rx_mpdus] =		{QTN_NIS_VAL_UNSIGNED, "Rx MPDUs"},
	[QTN_NIS_S0_rx_ppdus] =		{QTN_NIS_VAL_UNSIGNED, "Rx PPDUs"},
	[QTN_NIS_S0_rx_dropped] =	{QTN_NIS_VAL_UNSIGNED, "Rx discards"},
	[QTN_NIS_S0_rx_errors] =	{QTN_NIS_VAL_UNSIGNED, "Rx errors"},
	[QTN_NIS_S0_rx_ucast] =		{QTN_NIS_VAL_UNSIGNED, "Rx unicast"},
	[QTN_NIS_S0_rx_mcast] =		{QTN_NIS_VAL_UNSIGNED, "Rx multicast"},
	[QTN_NIS_S0_rx_bcast] =		{QTN_NIS_VAL_UNSIGNED, "Rx broadcast"},
	[QTN_NIS_S0_rx_unknown] =	{QTN_NIS_VAL_UNSIGNED, "Rx unknown data"},
	[QTN_NIS_S0_rx_max_phy_rate] =	{QTN_NIS_VAL_UNSIGNED, "Rx max PHY rate (kbps)"},
	[QTN_NIS_S0_rx_max_nss] =	{QTN_NIS_VAL_UNSIGNED, "Rx max NSS"},
	[QTN_NIS_S0_rx_max_mcs] =	{QTN_NIS_VAL_UNSIGNED, "Rx max MCS"},
	[QTN_NIS_S0_rx_last_phy_rate] =	{QTN_NIS_VAL_UNSIGNED, "Rx last PHY rate (Mbps)"},
	[QTN_NIS_S0_rx_last_nss] =	{QTN_NIS_VAL_UNSIGNED, "Rx last NSS"},
	[QTN_NIS_S0_rx_last_mcs] =	{QTN_NIS_VAL_UNSIGNED, "Rx last MCS"},
	[QTN_NIS_S0_rx_smthd_rssi] =	{QTN_NIS_VAL_UNSIGNED, "Rx smoothed RSSI (-ve)"},
	[QTN_NIS_S0_rx_flags] =		{QTN_NIS_VAL_UNSIGNED, "Rx flags"},
	[QTN_NIS_S0_rx_retries] =	{QTN_NIS_VAL_UNSIGNED, "Rx retries"},
	[QTN_NIS_S0_rx_bw] =		{QTN_NIS_VAL_UNSIGNED, "Rx bandwidth"},
	[QTN_NIS_S0_rx_last_rssi] =	{QTN_NIS_VAL_UNSIGNED, "Rx last RSSI (-ve)"},
	[QTN_NIS_S0_rx_last_rssi_tot] =	{QTN_NIS_VAL_UNSIGNED, "Rx last total RSSI (-ve)"},
	[QTN_NIS_S0_rx_smthd_rssi_tot] ={QTN_NIS_VAL_UNSIGNED, "Rx smoothed total RSSI (-ve)"},
	},
	{ /* Set 1 */
	[QTN_NIS_S1_tx_tid0_bytes] =	{QTN_NIS_VAL_UNSIGNED, "Tx TID0 bytes"},
	[QTN_NIS_S1_tx_tid1_bytes] =	{QTN_NIS_VAL_UNSIGNED, "Tx TID1 bytes"},
	[QTN_NIS_S1_tx_tid2_bytes] =	{QTN_NIS_VAL_UNSIGNED, "Tx TID2 bytes"},
	[QTN_NIS_S1_tx_tid3_bytes] =	{QTN_NIS_VAL_UNSIGNED, "Tx TID3 bytes"},
	[QTN_NIS_S1_tx_tid4_bytes] =	{QTN_NIS_VAL_UNSIGNED, "Tx TID4 bytes"},
	[QTN_NIS_S1_tx_tid5_bytes] =	{QTN_NIS_VAL_UNSIGNED, "Tx TID5 bytes"},
	[QTN_NIS_S1_tx_tid6_bytes] =	{QTN_NIS_VAL_UNSIGNED, "Tx TID6 bytes"},
	[QTN_NIS_S1_tx_tid7_bytes] =	{QTN_NIS_VAL_UNSIGNED, "Tx TID7 bytes"},

	[QTN_NIS_S1_rx_tid0_bytes] =	{QTN_NIS_VAL_UNSIGNED, "Rx TID0 bytes"},
	[QTN_NIS_S1_rx_tid1_bytes] =	{QTN_NIS_VAL_UNSIGNED, "Rx TID1 bytes"},
	[QTN_NIS_S1_rx_tid2_bytes] =	{QTN_NIS_VAL_UNSIGNED, "Rx TID2 bytes"},
	[QTN_NIS_S1_rx_tid3_bytes] =	{QTN_NIS_VAL_UNSIGNED, "Rx TID3 bytes"},
	[QTN_NIS_S1_rx_tid4_bytes] =	{QTN_NIS_VAL_UNSIGNED, "Rx TID4 bytes"},
	[QTN_NIS_S1_rx_tid5_bytes] =	{QTN_NIS_VAL_UNSIGNED, "Rx TID5 bytes"},
	[QTN_NIS_S1_rx_tid6_bytes] =	{QTN_NIS_VAL_UNSIGNED, "Rx TID6 bytes"},
	[QTN_NIS_S1_rx_tid7_bytes] =	{QTN_NIS_VAL_UNSIGNED, "Rx TID7 bytes"},
	},
	{ /* Set 2 */
	[QTN_NIS_S2_offset] =		{QTN_NIS_VAL_UNSIGNED, "Offset"},
	[QTN_NIS_S2_duration] =		{QTN_NIS_VAL_UNSIGNED, "Duration"},
	[QTN_NIS_S2_channel] =		{QTN_NIS_VAL_UNSIGNED, "Channel"},
	/* result */
	[QTN_NIS_S2_basic] =		{QTN_NIS_VAL_UNSIGNED, "Measured basic"},
	},
	{ /* Set 3 */
	[QTN_NIS_S3_offset] =		{QTN_NIS_VAL_UNSIGNED, "Offset"},
	[QTN_NIS_S3_duration] =		{QTN_NIS_VAL_UNSIGNED, "Duration"},
	[QTN_NIS_S3_channel] =		{QTN_NIS_VAL_UNSIGNED, "Channel"},
	/* result */
	[QTN_NIS_S3_cca] =		{QTN_NIS_VAL_UNSIGNED, "Measured CCA"},
	},
	{ /* Set 4 */
	[QTN_NIS_S4_offset] =		{QTN_NIS_VAL_UNSIGNED, "Offset"},
	[QTN_NIS_S4_duration] =		{QTN_NIS_VAL_UNSIGNED, "Duration"},
	[QTN_NIS_S4_channel] =		{QTN_NIS_VAL_UNSIGNED, "Channel"},
	/* result */
	[QTN_NIS_S4_rpi_size] =		{QTN_NIS_VAL_INDEX, "RPI size"},
	[QTN_NIS_S4_rpi_1] =		{QTN_NIS_VAL_UNSIGNED, "RPI 1"},
	[QTN_NIS_S4_rpi_2] =		{QTN_NIS_VAL_UNSIGNED, "RPI 2"},
	[QTN_NIS_S4_rpi_3] =		{QTN_NIS_VAL_UNSIGNED, "RPI 3"},
	[QTN_NIS_S4_rpi_4] =		{QTN_NIS_VAL_UNSIGNED, "RPI 4"},
	[QTN_NIS_S4_rpi_5] =		{QTN_NIS_VAL_UNSIGNED, "RPI 5"},
	[QTN_NIS_S4_rpi_6] =		{QTN_NIS_VAL_UNSIGNED, "RPI 6"},
	[QTN_NIS_S4_rpi_7] =		{QTN_NIS_VAL_UNSIGNED, "RPI 7"},
	[QTN_NIS_S4_rpi_8] =		{QTN_NIS_VAL_UNSIGNED, "RPI 8"},
	},
	{ /* Set 5 */
	[QTN_NIS_S5_op_class] =		{QTN_NIS_VAL_UNSIGNED, "Operating class"},
	[QTN_NIS_S5_channel] =		{QTN_NIS_VAL_UNSIGNED, "Channel"},
	[QTN_NIS_S5_duration] =		{QTN_NIS_VAL_UNSIGNED, "Duration"},
	/* result */
	[QTN_NIS_S5_chan_load] =	{QTN_NIS_VAL_UNSIGNED, "Channel load"},
	},
	{ /* Set 6 */
	[QTN_NIS_S6_op_class] =		{QTN_NIS_VAL_UNSIGNED, "Operating class"},
	[QTN_NIS_S6_channel] =		{QTN_NIS_VAL_UNSIGNED, "Channel"},
	[QTN_NIS_S6_duration] =		{QTN_NIS_VAL_UNSIGNED, "Duration"},
	/* result */
	[QTN_NIS_S6_antenna_id] =	{QTN_NIS_VAL_UNSIGNED, "Antenna ID"},
	[QTN_NIS_S6_anpi] =		{QTN_NIS_VAL_UNSIGNED, "ANPI"},
	[QTN_NIS_S6_ipi_size] =		{QTN_NIS_VAL_INDEX, "IPI Size"},
	[QTN_NIS_S6_ipi_1] =		{QTN_NIS_VAL_UNSIGNED, "IPI 1"},
	[QTN_NIS_S6_ipi_2] =		{QTN_NIS_VAL_UNSIGNED, "IPI 2"},
	[QTN_NIS_S6_ipi_3] =		{QTN_NIS_VAL_UNSIGNED, "IPI 3"},
	[QTN_NIS_S6_ipi_4] =		{QTN_NIS_VAL_UNSIGNED, "IPI 4"},
	[QTN_NIS_S6_ipi_5] =		{QTN_NIS_VAL_UNSIGNED, "IPI 5"},
	[QTN_NIS_S6_ipi_6] =		{QTN_NIS_VAL_UNSIGNED, "IPI 6"},
	[QTN_NIS_S6_ipi_7] =		{QTN_NIS_VAL_UNSIGNED, "IPI 7"},
	[QTN_NIS_S6_ipi_8] =		{QTN_NIS_VAL_UNSIGNED, "IPI 8"},
	[QTN_NIS_S6_ipi_9] =		{QTN_NIS_VAL_UNSIGNED, "IPI 9"},
	[QTN_NIS_S6_ipi_10] =		{QTN_NIS_VAL_UNSIGNED, "IPI 10"},
	[QTN_NIS_S6_ipi_11] =		{QTN_NIS_VAL_UNSIGNED, "IPI 11"},
	},
	{ /* Set 7 */
	[QTN_NIS_S7_op_class] =		{QTN_NIS_VAL_UNSIGNED, "Operating class"},
	[QTN_NIS_S7_channel] =		{QTN_NIS_VAL_UNSIGNED, "Channel"},
	[QTN_NIS_S7_duration] =		{QTN_NIS_VAL_UNSIGNED, "Duration"},
	[QTN_NIS_S7_mode] =		{QTN_NIS_VAL_UNSIGNED, "Mode"},
	[QTN_NIS_S7_bssid] =		{QTN_NIS_VAL_MACADDR, "BSSID"},
	 /* result */
	[QTN_NIS_S7_item_num] =		{QTN_NIS_VAL_UNSIGNED, "Item number"},
	[QTN_NIS_S7_total_reports] =	{QTN_NIS_VAL_UNSIGNED, "Total reports"},
	[QTN_NIS_S7_report_num] =	{QTN_NIS_VAL_UNSIGNED, "Report number"},
	[QTN_NIS_S7_rep_frame_info_1] =	{QTN_NIS_VAL_UNSIGNED, "Report frame info 1"},
	[QTN_NIS_S7_rcpi_1] =		{QTN_NIS_VAL_UNSIGNED, "RCPI 1"},
	[QTN_NIS_S7_rsni_1] =		{QTN_NIS_VAL_UNSIGNED, "RSNI 1"},
	[QTN_NIS_S7_bssid_result_1] =	{QTN_NIS_VAL_MACADDR, "BSSID 1"},
	[QTN_NIS_S7_antenna_id_1] =	{QTN_NIS_VAL_UNSIGNED, "Antenna ID 1"},
	[QTN_NIS_S7_parent_tsf_1] =	{QTN_NIS_VAL_UNSIGNED, "Parent TSF 1"},
	[QTN_NIS_S7_rep_frame_info_2] =	{QTN_NIS_VAL_UNSIGNED, "Report frame info 2"},
	[QTN_NIS_S7_rcpi_2] =		{QTN_NIS_VAL_UNSIGNED, "RCPI 2"},
	[QTN_NIS_S7_rsni_2] =		{QTN_NIS_VAL_UNSIGNED, "RSNI 2"},
	[QTN_NIS_S7_bssid_result_2] =	{QTN_NIS_VAL_MACADDR, "BSSID 2"},
	[QTN_NIS_S7_antenna_id_2] =	{QTN_NIS_VAL_UNSIGNED, "Antenna ID 2"},
	[QTN_NIS_S7_parent_tsf_2] =	{QTN_NIS_VAL_UNSIGNED, "Parent TSF 2"},
	[QTN_NIS_S7_rep_frame_info_3] =	{QTN_NIS_VAL_UNSIGNED, "Report frame info 3"},
	[QTN_NIS_S7_rcpi_3] =		{QTN_NIS_VAL_UNSIGNED, "RCPI 3"},
	[QTN_NIS_S7_rsni_3] =		{QTN_NIS_VAL_UNSIGNED, "RSNI 3"},
	[QTN_NIS_S7_bssid_result_3] =	{QTN_NIS_VAL_MACADDR, "BSSID 3"},
	[QTN_NIS_S7_antenna_id_3] =	{QTN_NIS_VAL_UNSIGNED, "Antenna ID 3"},
	[QTN_NIS_S7_parent_tsf_3] =	{QTN_NIS_VAL_UNSIGNED, "Parent TSF 3"},
	[QTN_NIS_S7_rep_frame_info_4] =	{QTN_NIS_VAL_UNSIGNED, "Report frame info 4"},
	[QTN_NIS_S7_rcpi_4] =		{QTN_NIS_VAL_UNSIGNED, "RCPI 4"},
	[QTN_NIS_S7_rsni_4] =		{QTN_NIS_VAL_UNSIGNED, "RSNI 4"},
	[QTN_NIS_S7_bssid_result_4] =	{QTN_NIS_VAL_MACADDR, "BSSID 4"},
	[QTN_NIS_S7_antenna_id_4] =	{QTN_NIS_VAL_UNSIGNED, "Antenna ID 4"},
	[QTN_NIS_S7_parent_tsf_4] =	{QTN_NIS_VAL_UNSIGNED, "Parent TSF 4"},
	[QTN_NIS_S7_rep_frame_info_5] =	{QTN_NIS_VAL_UNSIGNED, "Report frame info 5"},
	[QTN_NIS_S7_rcpi_5] =		{QTN_NIS_VAL_UNSIGNED, "RCPI 5"},
	[QTN_NIS_S7_rsni_5] =		{QTN_NIS_VAL_UNSIGNED, "RSNI 5"},
	[QTN_NIS_S7_bssid_result_5] =	{QTN_NIS_VAL_MACADDR, "BSSID 5"},
	[QTN_NIS_S7_antenna_id_5] =	{QTN_NIS_VAL_UNSIGNED, "Antenna ID 5"},
	[QTN_NIS_S7_parent_tsf_5] =	{QTN_NIS_VAL_UNSIGNED, "Parent TSF 5"},
	[QTN_NIS_S7_rep_frame_info_6] =	{QTN_NIS_VAL_UNSIGNED, "Report frame info 6"},
	[QTN_NIS_S7_rcpi_6] =		{QTN_NIS_VAL_UNSIGNED, "RCPI 6"},
	[QTN_NIS_S7_rsni_6] =		{QTN_NIS_VAL_UNSIGNED, "RSNI 6"},
	[QTN_NIS_S7_bssid_result_6] =	{QTN_NIS_VAL_MACADDR, "BSSID 6"},
	[QTN_NIS_S7_antenna_id_6] =	{QTN_NIS_VAL_UNSIGNED, "Antenna ID 6"},
	[QTN_NIS_S7_parent_tsf_6] =	{QTN_NIS_VAL_UNSIGNED, "Parent TSF 6"},
	[QTN_NIS_S7_rep_frame_info_7] =	{QTN_NIS_VAL_UNSIGNED, "Report frame info 7"},
	[QTN_NIS_S7_rcpi_7] =		{QTN_NIS_VAL_UNSIGNED, "RCPI 7"},
	[QTN_NIS_S7_rsni_7] =		{QTN_NIS_VAL_UNSIGNED, "RSNI 7"},
	[QTN_NIS_S7_bssid_result_7] =	{QTN_NIS_VAL_MACADDR, "BSSID 7"},
	[QTN_NIS_S7_antenna_id_7] =	{QTN_NIS_VAL_UNSIGNED, "Antenna ID 7"},
	[QTN_NIS_S7_parent_tsf_7] =	{QTN_NIS_VAL_UNSIGNED, "Parent TSF 7"},
	[QTN_NIS_S7_rep_frame_info_8] =	{QTN_NIS_VAL_UNSIGNED, "Report frame info 8"},
	[QTN_NIS_S7_rcpi_8] =		{QTN_NIS_VAL_UNSIGNED, "RCPI 8"},
	[QTN_NIS_S7_rsni_8] =		{QTN_NIS_VAL_UNSIGNED, "RSNI 8"},
	[QTN_NIS_S7_bssid_result_8] =	{QTN_NIS_VAL_MACADDR, "BSSID 8"},
	[QTN_NIS_S7_antenna_id_8] =	{QTN_NIS_VAL_UNSIGNED, "Antenna ID 8"},
	[QTN_NIS_S7_parent_tsf_8] =	{QTN_NIS_VAL_UNSIGNED, "Parent TSF 8"},
	[QTN_NIS_S7_rep_frame_info_9] =	{QTN_NIS_VAL_UNSIGNED, "Report frame info 9"},
	[QTN_NIS_S7_rcpi_9] =		{QTN_NIS_VAL_UNSIGNED, "RCPI 9"},
	[QTN_NIS_S7_rsni_9] =		{QTN_NIS_VAL_UNSIGNED, "RSNI 9"},
	[QTN_NIS_S7_bssid_result_9] =	{QTN_NIS_VAL_MACADDR, "BSSID 9"},
	[QTN_NIS_S7_antenna_id_9] =	{QTN_NIS_VAL_UNSIGNED, "Antenna ID 9"},
	[QTN_NIS_S7_parent_tsf_9] =	{QTN_NIS_VAL_UNSIGNED, "Parent TSF 9"},
	},
	{ /* Set 8 */
	[QTN_NIS_S8_op_class] =		{QTN_NIS_VAL_FLAG, "Operating class"},
	[QTN_NIS_S8_channel] =		{QTN_NIS_VAL_UNSIGNED, "Channel"},
	[QTN_NIS_S8_duration] =		{QTN_NIS_VAL_UNSIGNED, "Duration"},
	[QTN_NIS_S8_type] =		{QTN_NIS_VAL_UNSIGNED, "Type"},
	[QTN_NIS_S8_mac_addr] =		{QTN_NIS_VAL_MACADDR, "MAC address"},
	/* result */
	[QTN_NIS_S8_sub_ele_report] =	{QTN_NIS_VAL_FLAG, "Sub element report"},
	[QTN_NIS_S8_ta] =		{QTN_NIS_VAL_MACADDR, "TA address"},
	[QTN_NIS_S8_bssid] =		{QTN_NIS_VAL_MACADDR, "BSSID"},
	[QTN_NIS_S8_phy_type] =		{QTN_NIS_VAL_UNSIGNED, "PHY type"},
	[QTN_NIS_S8_avg_rcpi] =		{QTN_NIS_VAL_UNSIGNED, "Average RCPI"},
	[QTN_NIS_S8_last_rcpi] =	{QTN_NIS_VAL_UNSIGNED, "Last RCPI"},
	[QTN_NIS_S8_last_rsni] =	{QTN_NIS_VAL_UNSIGNED, "Last RSNI"},
	[QTN_NIS_S8_antenna_id] =	{QTN_NIS_VAL_UNSIGNED, "Antenna ID"},
	[QTN_NIS_S8_frame_count] =	{QTN_NIS_VAL_UNSIGNED, "Frame count"},
	},
	{ /* Set 9 */
	[QTN_NIS_S9_duration] =		{QTN_NIS_VAL_UNSIGNED, "Duration"},
	[QTN_NIS_S9_peer_sta] =		{QTN_NIS_VAL_MACADDR, "Peer station"},
	[QTN_NIS_S9_tid] =		{QTN_NIS_VAL_UNSIGNED, "TID"},
	[QTN_NIS_S9_bin0] =		{QTN_NIS_VAL_UNSIGNED, "Bin0"},
	 /* result */
	[QTN_NIS_S9_reason] =		{QTN_NIS_VAL_UNSIGNED, "Reason"},
	[QTN_NIS_S9_tran_msdu_cnt] =	{QTN_NIS_VAL_UNSIGNED, "Transmitted MSDU count"},
	[QTN_NIS_S9_msdu_discard_cnt] =	{QTN_NIS_VAL_UNSIGNED, "MSDU discarded count"},
	[QTN_NIS_S9_msdu_fail_cnt] =	{QTN_NIS_VAL_UNSIGNED, "MSDU failed count"},
	[QTN_NIS_S9_msdu_mul_retry_cnt] ={QTN_NIS_VAL_UNSIGNED, "MSDU multiple retry count"},
	[QTN_NIS_S9_qos_lost_cnt] =	{QTN_NIS_VAL_UNSIGNED, "MSDU QoS CF-polls lost count"},
	[QTN_NIS_S9_avg_queue_delay] =	{QTN_NIS_VAL_UNSIGNED, "Average queue delay"},
	[QTN_NIS_S9_avg_tran_delay] =	{QTN_NIS_VAL_UNSIGNED, "Average transmit delay"},
	[QTN_NIS_S9_bin0_range] =	{QTN_NIS_VAL_UNSIGNED, "Bin range"},
	[QTN_NIS_S9_bin_1] =		{QTN_NIS_VAL_UNSIGNED, "Bin 1"},
	[QTN_NIS_S9_bin_2] =		{QTN_NIS_VAL_UNSIGNED, "Bin 2"},
	[QTN_NIS_S9_bin_3] =		{QTN_NIS_VAL_UNSIGNED, "Bin 3"},
	[QTN_NIS_S9_bin_4] =		{QTN_NIS_VAL_UNSIGNED, "Bin 4"},
	[QTN_NIS_S9_bin_5] =		{QTN_NIS_VAL_UNSIGNED, "Bin 5"},
	[QTN_NIS_S9_bin_6] =		{QTN_NIS_VAL_UNSIGNED, "Bin 6"},
	},
	{ /* Set 10 */
	[QTN_NIS_S10_duration] =	{QTN_NIS_VAL_UNSIGNED, "Duration"},
	[QTN_NIS_S10_group_mac] =	{QTN_NIS_VAL_MACADDR, "Group MAC"},
	 /* result */
	[QTN_NIS_S10_reason] =		{QTN_NIS_VAL_UNSIGNED, "Reason"},
	[QTN_NIS_S10_mul_rec_msdu_cnt] ={QTN_NIS_VAL_UNSIGNED, "Multicast received MSDU count"},
	[QTN_NIS_S10_first_seq_num] =	{QTN_NIS_VAL_UNSIGNED, "First sequence number"},
	[QTN_NIS_S10_last_seq_num] =	{QTN_NIS_VAL_UNSIGNED, "Last sequence number"},
	[QTN_NIS_S10_mul_rate] =	{QTN_NIS_VAL_UNSIGNED, "Multicast rate"},
	},
	{ /* Set 11 */
	[QTN_NIS_S11_tx_power] =	{QTN_NIS_VAL_UNSIGNED, "Transmit power"},
	[QTN_NIS_S11_link_margin] =	{QTN_NIS_VAL_UNSIGNED, "Link margin"},
	[QTN_NIS_S11_recv_antenna_id] =	{QTN_NIS_VAL_UNSIGNED, "Receive antenna ID"},
	[QTN_NIS_S11_tran_antenna_id] =	{QTN_NIS_VAL_UNSIGNED, "Transmit antenna ID"},
	[QTN_NIS_S11_rcpi] =		{QTN_NIS_VAL_UNSIGNED, "RCPI"},
	[QTN_NIS_S11_rsni] =		{QTN_NIS_VAL_UNSIGNED, "RSNI"},
	},
	{ /* Set 12 */
	[QTN_NIS_S12_item_num] =	{QTN_NIS_VAL_INDEX, "Item number"},
	[QTN_NIS_S12_bssid] =		{QTN_NIS_VAL_MACADDR, "BSSID"},
	[QTN_NIS_S12_bssid_info] =	{QTN_NIS_VAL_UNSIGNED, "BSSID info"},
	[QTN_NIS_S12_operating_class] =	{QTN_NIS_VAL_UNSIGNED, "Operating class"},
	[QTN_NIS_S12_channel] =		{QTN_NIS_VAL_UNSIGNED, "Channel"},
	[QTN_NIS_S12_phy_type] =	{QTN_NIS_VAL_UNSIGNED, "PHY type"},
	},
	{ /* Set 13 */
	[QTN_NIS_S13_status] =		{QTN_NIS_VAL_UNSIGNED, "Status"},
	[QTN_NIS_S13_tx_power] =	{QTN_NIS_VAL_SIGNED, "Transmit power in dBm"},
	[QTN_NIS_S13_link_margin] =	{QTN_NIS_VAL_SIGNED, "Link margin in dB"},
	},
	{ /* Set 14 */
	[QTN_NIS_S14_common_b1] =	{QTN_NIS_VAL_SIGNED, ""},
	[QTN_NIS_S14_common_b2] =	{QTN_NIS_VAL_SIGNED, ""},
	[QTN_NIS_S14_common_b3] =	{QTN_NIS_VAL_SIGNED, ""},
	}
};

/**
 * Interface information set labels
 */
#define QTNIS_IF_LABEL_LEN	35

/**
 * Interface information set labels
 * This table must be kept in sync with Interface Information Set enums (e.g. qtnis_if_s0_e).
 */
const char *qtnis_if_label[][QTNIS_IF_VAL_MAX] = {
	{ /* Set 0 */
	[QTNIS_S0_assoc_id] = "",
	[QTNIS_S0_bw] = "",

	[QTNIS_S0_tx_bytes] = "",
	[QTNIS_S0_tx_packets] = "",
	[QTNIS_S0_tx_amsdu_msdus] = "",
	[QTNIS_S0_tx_mpdus] = "",
	[QTNIS_S0_tx_ppdus] = "",
	[QTNIS_S0_tx_wifi_sent_be] = "",
	[QTNIS_S0_tx_wifi_sent_bk] = "",
	[QTNIS_S0_tx_wifi_sent_vi] = "",
	[QTNIS_S0_tx_wifi_sent_vo] = "",
	[QTNIS_S0_tx_dropped] = "",
	[QTNIS_S0_tx_wifi_drop_be] = "",
	[QTNIS_S0_tx_wifi_drop_bk] = "",
	[QTNIS_S0_tx_wifi_drop_vi] = "",
	[QTNIS_S0_tx_wifi_drop_vo] = "",
	[QTNIS_S0_tx_errors] = "",
	[QTNIS_S0_tx_ucast] = "",
	[QTNIS_S0_tx_mcast] = "",
	[QTNIS_S0_tx_bcast] = "",
	[QTNIS_S0_tx_ucast_bytes] = "UnicastBytesSent",
	[QTNIS_S0_tx_mcast_bytes] = "MulticastBytesSent",
	[QTNIS_S0_tx_bcast_bytes] = "BroadcastBytesSent",
	[QTNIS_S0_tx_max_phy_rate] = "",
	[QTNIS_S0_tx_max_nss] = "",
	[QTNIS_S0_tx_max_mcs] = "",
	[QTNIS_S0_tx_last_phy_rate] = "",
	[QTNIS_S0_tx_last_nss] = "",
	[QTNIS_S0_tx_last_mcs] = "",
	[QTNIS_S0_tx_flags] = "",
	[QTNIS_S0_tx_retries] = "",
	[QTNIS_S0_tx_bw] = "",

	[QTNIS_S0_rx_bytes] = "",
	[QTNIS_S0_rx_packets] = "",
	[QTNIS_S0_rx_amsdu_msdus] = "",
	[QTNIS_S0_rx_mpdus] = "",
	[QTNIS_S0_rx_ppdus] = "",
	[QTNIS_S0_rx_dropped] = "",
	[QTNIS_S0_rx_errors] = "",
	[QTNIS_S0_rx_ucast] = "",
	[QTNIS_S0_rx_mcast] = "",
	[QTNIS_S0_rx_bcast] = "",
	[QTNIS_S0_rx_ucast_bytes] = "UnicastBytesReceived",
	[QTNIS_S0_rx_mcast_bytes] = "MulticastBytesReceived",
	[QTNIS_S0_rx_bcast_bytes] = "BroadcastBytesReceived",
	[QTNIS_S0_rx_unknown] = "",
	[QTNIS_S0_rx_max_phy_rate] = "",
	[QTNIS_S0_rx_max_nss] = "",
	[QTNIS_S0_rx_max_mcs] = "",
	[QTNIS_S0_rx_last_phy_rate] = "",
	[QTNIS_S0_rx_last_nss] = "",
	[QTNIS_S0_rx_last_mcs] = "",
	[QTNIS_S0_rx_smthd_rssi] = "",
	[QTNIS_S0_rx_flags] = "",
	[QTNIS_S0_rx_retries] = "",
	[QTNIS_S0_rx_bw] = "",
	[QTNIS_S0_rx_last_rssi] = "",
	[QTNIS_S0_rx_last_rssi_tot] = "",
	[QTNIS_S0_rx_smthd_rssi_tot] = "",
	},
	{ /* Set 1 */
	[QTNIS_S1_offset] = "",
	[QTNIS_S1_duration] = "",
	[QTNIS_S1_channel] = "",

	[QTNIS_S1_basic] = "",
	},
	{ /* Set 2 */
	[QTNIS_S2_tx_ack_failures] = "ACK failures",
	[QTNIS_S2_rx_invalid_mac_header] = "Rx with invalid MAC header",
	[QTNIS_S2_rx_non_assoc_packets] = "Rx non-assoc packets",
	[QTNIS_S2_rx_plcp_errors] = "Rx with PLCP errors",
	[QTNIS_S2_rx_fcs_errors] = "Rx with FCS errors",
	},
	{ /* Set 3 */
	[QTNIS_S3_cap_scan_auto_scan] = "Auto scan",
	[QTNIS_S3_cap0_scan_boot] = "Cap 0 only at boot",
	[QTNIS_S3_cap0_scan_impact] = "Cap 0 scan impact",
	[QTNIS_S3_cap0_scan_min_scan_intv] = "Cap 0 min scan intv",
	[QTNIS_S3_cap0_reserved_0] = "Cap 0 reserved for future use",
	[QTNIS_S3_cap0_reserved_1] = "Cap 0 reserved for future use",
	[QTNIS_S3_cap0_reserved_2] = "Cap 0 reserved for future use",
	[QTNIS_S3_cap1_scan_boot] = "Cap 1 only at boot",
	[QTNIS_S3_cap1_scan_impact] = "Cap 1 scan impact",
	[QTNIS_S3_cap1_scan_min_scan_intv] = "Cap 1 min scan intv",
	[QTNIS_S3_cap1_reserved_0] = "Cap 1 reserved for future use",
	[QTNIS_S3_cap1_reserved_1] = "Cap 1 reserved for future use",
	[QTNIS_S3_cap1_reserved_2] = "Cap 1 reserved for future use",
	[QTNIS_S3_cap2_scan_boot] = "Cap 2 only at boot",
	[QTNIS_S3_cap2_scan_impact] = "Cap 2 scan impact",
	[QTNIS_S3_cap2_scan_min_scan_intv] = "Capability 2 min scan intv",
	[QTNIS_S3_cap2_reserved_0] = "Cap 2 reserved for future use",
	[QTNIS_S3_cap2_reserved_1] = "Cap 2 reserved for future use",
	[QTNIS_S3_cap2_reserved_2] = "Cap 2 reserved for future use",
	[QTNIS_S3_cap3_scan_boot] = "Cap 3 only at boot",
	[QTNIS_S3_cap3_scan_impact] = "Cap 3 scan impact",
	[QTNIS_S3_cap3_scan_min_scan_intv] = "Cap 3 min scan intv",
	[QTNIS_S3_cap3_reserved_0] = "Cap 3 reserved for future use",
	[QTNIS_S3_cap3_reserved_1] = "Cap 3 reserved for future use",
	[QTNIS_S3_cap3_reserved_2] = "Cap 3 reserved for future use",
	},
	{ /* Set 4 */
	[QTNIS_S4_cap0_cac_type] = "Cap 0 CAC type",
	[QTNIS_S4_cap0_cac_dur] = "Cap 0 CAC dur",
	[QTNIS_S4_cap0_cac_dur_wea] = "Cap 0 CAC dur in wea chan",
	[QTNIS_S4_cap0_cac_nop_dur] = "Cap 0 non-occupancy dur",
	[QTNIS_S4_cap0_cac_nop_dur_wea] = "Cap 0 non-occupancy dur in wea chan",
	[QTNIS_S4_cap0_reserved_0] = "Cap 0 reserved for future use",
	[QTNIS_S4_cap0_reserved_1] = "Cap 0 reserved for future use",
	[QTNIS_S4_cap1_cac_type] = "Cap 1 CAC type",
	[QTNIS_S4_cap1_cac_dur] = "Cap 1 CAC dur",
	[QTNIS_S4_cap1_cac_dur_wea] = "Cap 1 CAC dur in wea chan",
	[QTNIS_S4_cap1_cac_nop_dur] = "Cap 1 non-occupancy dur",
	[QTNIS_S4_cap1_cac_nop_dur_wea] = "Cap 1 non-occupancy dur in wea chan",
	[QTNIS_S4_cap1_reserved_0] = "Cap 1 reserved for future use",
	[QTNIS_S4_cap1_reserved_1] = "Cap 1 reserved for future use",
	[QTNIS_S4_cap2_cac_type] = "Cap 2 CAC type",
	[QTNIS_S4_cap2_cac_dur] = "Cap 2 CAC dur",
	[QTNIS_S4_cap2_cac_dur_wea] = "Cap 2 CAC dur in wea chan",
	[QTNIS_S4_cap2_cac_nop_dur] = "Cap 2 non-occupy dur",
	[QTNIS_S4_cap2_cac_nop_dur_wea] = "Cap 2 non-occupancy dur in wea chan",
	[QTNIS_S4_cap2_reserved_0] = "Cap 2 reserved for future use",
	[QTNIS_S4_cap2_reserved_1] = "Cap 2 reserved for future use",
	[QTNIS_S4_cap3_cac_type] = "Cap 3 CAC type",
	[QTNIS_S4_cap3_cac_dur] = "Cap 3 CAC dur",
	[QTNIS_S4_cap3_cac_dur_wea] = "Cap 3 CAC dur in wea chan",
	[QTNIS_S4_cap3_cac_nop_dur] = "Cap 3 non-occupancy dur",
	[QTNIS_S4_cap3_cac_nop_dur_wea] = "Cap 3 non-occupancy dur in wea chan",
	[QTNIS_S4_cap3_reserved_0] = "Cap 3 reserved for future use",
	[QTNIS_S4_cap3_reserved_1] = "Cap 3 reserved for future use",
	}
};

/**
 * All-node information set labels
 * This table must be kept in sync with All-node Information Set enums (e.g. qtn_nis_all_s0_e).
 */
const struct qtn_nis_meta_data qtn_nis_all_meta[][QTN_NIS_ALL_FIELD_MAX] = {
	{ /* Set 0 */
	[QTN_NIS_ALL_S0_rsn_caps] =	{QTN_NIS_VAL_RSN_CAPS, "RSN Capabilities"},
	}
};

static int		verbose_flag = 0;
static unsigned int	call_count = 1;
static unsigned int	delay_time = 0;

static unsigned int	call_qcsapi_init_count = 1;

char *qcsapi_80211u_params[] = {
		"internet",
		"access_network_type",
		"network_auth_type",
		"hessid",
		"domain_name",
		"ipaddr_type_availability",
		"anqp_3gpp_cell_net",
		"venue_group",
		"venue_type",
		"gas_comeback_delay",
		NULL
};

char *qcsapi_hs20_params[] = {
		"hs20_wan_metrics",
		"disable_dgaf",
		"hs20_operating_class",
		"osu_ssid",
		"osen",
		"hs20_deauth_req_timeout"
};

static const char *qcsapi_dev_modes[] = {
	"unknown",	/* qcsapi_dev_mode_unknown */
	"mbs",		/* qcsapi_dev_mode_mbs */
	"rbs",		/* qcsapi_dev_mode_rbs */
	"repeater",	/* qcsapi_dev_mode_repeater */
	"dbdc_5g_hi",	/* qcsapi_dev_mode_dbdc_5g_hi */
	"dbdc_5g_lo"	/* qcsapi_dev_mode_dbdc_5g_lo */
};

static const struct {
	qcsapi_vopt_action action_type;
	const char *action_name;
} vopt_action_tbl[] =
{
	{QCSAPI_VOPT_ENABLE, "enable"},
	{QCSAPI_VOPT_DISABLE, "disable"},
	{QCSAPI_VOPT_AUTO, "auto"}
};

static const struct{
	const char		*name;
	qcsapi_node_stat_e	index;
} qcsapi_node_stat_names_table[] =
{
	{"txrx_airtime", QCSAPI_NODE_STAT_TXRX_AIRTIME},
	{"tx_retries", QCSAPI_NODE_STAT_TX_RETRIES},
	{"ip_addr", QCSAPI_NODE_STAT_IP_ADDR},
};

/* returns 1 if successful; 0 if failure */
static int local_verify_enable_or_disable(const char *str, uint8_t *result, qcsapi_output *print)
{
        if (!strcmp(str, "1") || !strcmp(str, "enable")) {
                *result = 1;
        } else if (!strcmp(str, "0") || !strcmp(str, "disable")) {
		*result = 0;
	} else {
		print_err(print, "Invalid value %s: must be 0 or 1\n", str);
		return -EINVAL;
	}

	return 0;
}

static int local_atou32_verify_numeric_range(char *str, uint32_t *p, qcsapi_output *print,
		uint32_t min, uint32_t max)
{
	uint32_t v;

	if ((qcsapi_verify_numeric(str) < 0) || (qcsapi_util_str_to_uint32(str, &v) < 0)) {
		print_err(print, "Invalid parameter %s - must be an unsigned integer\n", str);
		return -EINVAL;
	}

	if (v < min || v > max) {
		print_err(print, "Invalid parameter %s - value must be between %u and %u\n", str, min, max);
		return -ERANGE;
	}

	*p = v;

	return 0;
}

static int safe_atou16(char *str, uint16_t *p, qcsapi_output *print, uint16_t min, uint16_t max)
{
	uint32_t v;

	if (local_atou32_verify_numeric_range(str, &v, print, min, max) == 0) {
		*p = (uint16_t)v;
		return 1;
	}

	return 0;
}

static int local_atoi32_verify_numeric_range(const char *str, int32_t *result,
				qcsapi_output *print, int32_t min, int32_t max)
{
	int retval = 0;

	retval = qcsapi_util_str_to_int32(str, result);
	if (retval < 0) {
		print_err(print, "Invalid parameter %s - must be a signed integer\n", str);
		return retval;
	}

	if (*result < min || *result > max) {
		print_err(print, "Value is out of range: %s not in [%d, %d]\n", str, min, max);
		return -ERANGE;
	}

	return 0;
}

int local_str_to_uint32(const char *str, uint32_t *result, qcsapi_output *print, const char *desc)
{
	int retval;

	retval = qcsapi_util_str_to_uint32(str, result);
	if (retval < 0) {
		print_err(print, "Invalid %s (%s)\n", desc, str);
		return retval;
	}

	return 0;
}

int local_str_to_int32(const char *str, int32_t *result, qcsapi_output *print, const char *desc)
{
	int retval;

	retval = qcsapi_util_str_to_int32(str, result);
	if (retval < 0) {
		print_err(print, "Invalid %s (%s)\n", desc, str);
		return retval;
	}

	return 0;
}

static int
name_to_entry_point_enum( char *lookup_name, qcsapi_entry_point *p_entry_point )
{
	int		retval = 1;
	int		found_entry = 0, proposed_enum = (int) e_qcsapi_nosuch_api;
	unsigned int	iter;
  /*
   * Silently skip over "qscapi_" ...
   */
	if (strncasecmp( lookup_name, "qscapi_", 7 ) == 0)
	  lookup_name += 7;

	for (iter = 0; qcsapi_entry_name[ iter ].api_name != NULL && found_entry == 0; iter++)
	{
		if (strcasecmp( qcsapi_entry_name[ iter ].api_name, lookup_name ) == 0)
		{
			found_entry = 1;
			*p_entry_point = qcsapi_entry_name[ iter ].e_entry_point;
		}
	}

	if (found_entry == 0)
	{
		*p_entry_point = proposed_enum;
		retval = 0;
	}

	return( retval );
}

/* Guaranteed to return a valid string address */

static const char *
entry_point_enum_to_name( qcsapi_entry_point e_qcsapi_entry_point )
{
	const char	*retaddr = "No such QCSAPI";
	int		 found_entry = 0;
	unsigned int	 iter;

	for (iter = 0; qcsapi_entry_name[ iter ].api_name != NULL && found_entry == 0; iter++)
	{
		if (qcsapi_entry_name[ iter ].e_entry_point == e_qcsapi_entry_point)
		{
			found_entry = 1;
			retaddr = qcsapi_entry_name[ iter ].api_name;
		}
	}

	return( retaddr );
}

static void
list_entry_point_names(qcsapi_output *print)
{
	unsigned int	 iter;

	print_out( print, "API entry point names (more than one name can refer to the same entry point):\n" );

	for (iter = 0; qcsapi_entry_name[ iter ].api_name != NULL; iter++)
	{
		print_out( print, "\t%s\n", qcsapi_entry_name[ iter ].api_name );
	}
}

static void
grep_entry_point_names(qcsapi_output *print, const char *reg)
{
	unsigned int	 iter;

	print_out( print, "API entry point names (more than one name can refer to the same entry point):\n" );

	for (iter = 0; qcsapi_entry_name[ iter ].api_name != NULL; iter++)
	{
		if ( strstr(qcsapi_entry_name[ iter ].api_name, reg) )
			print_out( print, "\t%s\n", qcsapi_entry_name[ iter ].api_name );
	}
}

/* returns 1 if successful; 0 if failure */

static int
name_to_counter_enum( char *lookup_name, qcsapi_counter_type *p_counter_type )
{
	int		retval = 0;
	int		found_entry = 0;
	unsigned int	iter;

	for (iter = 0; qcsapi_counter_name[ iter ].counter_name != NULL && found_entry == 0; iter++)
	{
		if (strcasecmp( qcsapi_counter_name[ iter ].counter_name, lookup_name ) == 0)
		{
			found_entry = 1;
			*p_counter_type = qcsapi_counter_name[ iter ].counter_type;
		}
	}

	if (found_entry)
	  retval = 1;

	return( retval );
}

/* Guaranteed to return a valid string address */

static const char *
counter_enum_to_name( qcsapi_counter_type the_counter_type )
{
	const char	*retaddr = "No such QCSAPI counter";
	int		 found_entry = 0;
	unsigned int	 iter;

	for (iter = 0; qcsapi_counter_name[ iter ].counter_name != NULL && found_entry == 0; iter++)
	{
		if (qcsapi_counter_name[ iter ].counter_type  == the_counter_type)
		{
			found_entry = 1;
			retaddr = qcsapi_counter_name[ iter ].counter_name;
		}
	}

	return( retaddr );
}

static void
list_counter_names(qcsapi_output *print)
{
	unsigned int	 iter;

	print_out( print, "API counters:\n" );

	for (iter = 0; qcsapi_counter_name[ iter ].counter_name != NULL; iter++) {
		print_out( print, "\t%s\n", qcsapi_counter_name[ iter ].counter_name );
	}
}

static void
list_per_node_param_names(qcsapi_output *print)
{
	unsigned int	 iter;

	print_out(print, "Per-node parameters:\n");

	for (iter = 0; iter < ARRAY_SIZE(qcsapi_pa_param_table); iter++) {
		print_out(print, "\t%s\n", qcsapi_pa_param_table[ iter ].pa_name);
	}
}

/* returns 1 if successful; 0 if failure */

static int
name_to_option_enum( char *lookup_name, qcsapi_option_type *p_option )
{
	int		retval = 0;
	int		found_entry = 0;
	unsigned int	iter;

	for (iter = 0; qcsapi_option_name[ iter ].option_name != NULL && found_entry == 0; iter++)
	{
		if (strcasecmp( qcsapi_option_name[ iter ].option_name, lookup_name ) == 0)
		{
			found_entry = 1;
			*p_option = qcsapi_option_name[ iter ].option_type;
		}
	}

	if (found_entry)
	  retval = 1;

	return( retval );
}

/* Guaranteed to return a valid string address */

static const char *
option_enum_to_name( qcsapi_option_type the_option_type )
{
	const char	*retaddr = "No such QCSAPI option";
	int		 found_entry = 0;
	unsigned int	 iter;

	for (iter = 0; qcsapi_option_name[ iter ].option_name != NULL && found_entry == 0; iter++)
	{
		if (qcsapi_option_name[ iter ].option_type == the_option_type)
		{
			found_entry = 1;
			retaddr = qcsapi_option_name[ iter ].option_name;
		}
	}

	return( retaddr );
}

static void
list_option_names(qcsapi_output *print)
{
	unsigned int	 iter;

	print_out( print, "API options (more than one name can refer to the same option):\n" );

	for (iter = 0; qcsapi_option_name[ iter ].option_name != NULL; iter++)
	{
		print_out( print, "\t%s\n", qcsapi_option_name[ iter ].option_name );
	}
}

/* returns 1 if successful; 0 if failure */
static int
name_to_board_parameter_enum( char *lookup_name, qcsapi_board_parameter_type *p_boardparam )
{
	int		retval = 0;
	int		found_entry = 0;
	unsigned int	iter;

	for (iter = 0;
	     qcsapi_board_parameter_name[ iter ].board_param_name != NULL && (found_entry == 0);
	     iter++)
	{
		if (strcasecmp( qcsapi_board_parameter_name[ iter ].board_param_name, lookup_name ) == 0)
		{
			found_entry = 1;
			*p_boardparam = qcsapi_board_parameter_name[ iter ].board_param;
		}
	}

	if (found_entry)
	  retval = 1;

	return( retval );
}

static const char *
board_paramter_enum_to_name( qcsapi_board_parameter_type the_board_param )
{
	const char	*retaddr = "No such QCSAPI option";
	int		 found_entry = 0;
	unsigned int	 iter;

	for (iter = 0;
	     qcsapi_board_parameter_name[ iter ].board_param_name != NULL && found_entry == 0;
	     iter++)
	{
		if (qcsapi_board_parameter_name[ iter ].board_param == the_board_param)
		{
			found_entry = 1;
			retaddr = qcsapi_board_parameter_name[ iter ].board_param_name;
		}
	}

	return( retaddr );
}

static const char *
local_dpp_parameter_enum_to_name(enum qcsapi_dpp_cmd_param_type dpp_param)
{
	const char *retaddr = "No such QCSAPI option";
	int found_entry = 0;
	unsigned int iter;

	for (iter = 0; qcsapi_dpp_param_table[iter].param_name != NULL && found_entry == 0;
			iter++) {
		if (qcsapi_dpp_param_table[iter].param_type == dpp_param) {
			found_entry = 1;
			retaddr = qcsapi_dpp_param_table[iter].param_name;
		}
	}

	return retaddr;
}

static void
list_board_parameter_names( qcsapi_output *print )
{
	unsigned int	iter;

	for (iter = 0; qcsapi_board_parameter_name[ iter ].board_param_name != NULL; iter++)
	{
		print_out( print, "\t%s\n", qcsapi_board_parameter_name[ iter ].board_param_name );
	}
}

static void
list_wifi_parameter_names(qcsapi_output *print)
{
	uint32_t i;

	for (i = 0; qcsapi_wifi_param_table[i].param_name != NULL; i++) {
		print_out(print, "\t%s\n", qcsapi_wifi_param_table[i].param_name);
	}
}

/* returns 1 if successful; 0 if failure */

static int
name_to_rates_enum( char *lookup_name, qcsapi_rate_type *p_rates )
{
	int		retval = 0;
	int		found_entry = 0;
	unsigned int	iter;

	for (iter = 0; qcsapi_rate_types_name[ iter ].rate_name != NULL && found_entry == 0; iter++)
	{
		if (strcasecmp( qcsapi_rate_types_name[ iter ].rate_name, lookup_name ) == 0)
		{
			found_entry = 1;
			*p_rates = qcsapi_rate_types_name[ iter ].rate_type;
		}
	}

	if (found_entry)
	  retval = 1;

	return( retval );
}

/* Guaranteed to return a valid string address */

static const char *
rates_enum_to_name( qcsapi_rate_type the_option_type )
{
	const char	*retaddr = "No such type of rates";
	int		 found_entry = 0;
	unsigned int	 iter;

	for (iter = 0; qcsapi_rate_types_name[ iter ].rate_name != NULL && found_entry == 0; iter++)
	{
		if (qcsapi_rate_types_name[ iter ].rate_type == the_option_type)
		{
			found_entry = 1;
			retaddr = qcsapi_rate_types_name[ iter ].rate_name;
		}
	}

	return( retaddr );
}

static int
name_to_wifi_std_enum(const char *lookup_name, qcsapi_mimo_type *p_modulation)
{
	unsigned int iter = 0;
	unsigned int found_entry = 0;

	while (qcsapi_wifi_std_name[iter].std_name && !found_entry) {
		if (!strcasecmp(qcsapi_wifi_std_name[iter].std_name, lookup_name)) {
			*p_modulation = qcsapi_wifi_std_name[iter].std_type;
			found_entry = 1;
		}
		++iter;
	}

	return found_entry;
}

static const char*
wifi_std_enum_to_name(const qcsapi_mimo_type lookup_type)
{
	unsigned int iter = 0;
	const char *ret_name = "No such type of standard";

	while (qcsapi_wifi_std_name[iter].std_name) {
		if (qcsapi_wifi_std_name[iter].std_type == lookup_type) {
			ret_name = qcsapi_wifi_std_name[iter].std_name;
			break;
		}
		++iter;
	}

	return ret_name;
}


/* returns 1 if successful; 0 if failure */
static int
name_to_partition_type( char *lookup_name, qcsapi_flash_partiton_type *p_partition_type )
{
	int		retval = 0;
	unsigned int	iter;

	for (iter = 0; qcsapi_partition_name[ iter ].partition_name != NULL && retval == 0; iter++)
	{
		if (strcasecmp( qcsapi_partition_name[ iter ].partition_name, lookup_name ) == 0)
		{
			retval = 1;
			*p_partition_type = qcsapi_partition_name[ iter ].partition_type;
		}
	}

	return( retval );
}

static int name_to_qos_queue_type(char *lookup_name, int *p_qos_queue_type)
{
	int		retval = 0;
	unsigned int	iter;

	for (iter = 0; iter < ARRAY_SIZE(qcsapi_qos_queue_table); iter++) {
		if (strcasecmp(qcsapi_qos_queue_table[iter].qos_queue_name, lookup_name) == 0) {
			*p_qos_queue_type = qcsapi_qos_queue_table[iter].qos_queue_type;
			retval = 1;
			break;
		}
	}

	return retval;
}

static int name_to_qos_param_type(char *lookup_name, int *p_qos_param_type)
{
	int		retval = 0;
	unsigned int	iter;

	for (iter = 0; iter < ARRAY_SIZE(qcsapi_qos_param_table); iter++) {
		if (strcasecmp(qcsapi_qos_param_table[iter].qos_param_name, lookup_name) == 0) {
			*p_qos_param_type = qcsapi_qos_param_table[iter].qos_param_type;
			retval = 1;
			break;
		}
	}

	return retval;
}

static int name_to_vendor_fix_idx(char *lookup_name, int *p_vendor_fix_idx)
{
	int		retval = 0;
	unsigned int	iter;

	for (iter = 0; iter < ARRAY_SIZE(qcsapi_vendor_fix_table); iter++) {
		if (strcasecmp(qcsapi_vendor_fix_table[iter].fix_name, lookup_name) == 0) {
			*p_vendor_fix_idx = qcsapi_vendor_fix_table[iter].fix_idx;
			retval = 1;
			break;
		}
	}

	return retval;
}

static int name_to_per_assoc_parameter(const char *param_name,
	 			       qcsapi_per_assoc_param *p_per_assoc_param)
{
	unsigned int	iter;

	for (iter = 0; iter < ARRAY_SIZE(qcsapi_pa_param_table); iter++) {
		if (strcasecmp(qcsapi_pa_param_table[iter].pa_name, param_name) == 0) {
			*p_per_assoc_param = qcsapi_pa_param_table[iter].pa_param;
			return 1;
		}
	}

	return 0;
}

static int parse_local_remote_flag(qcsapi_output *print, const char *local_remote_str, int *p_local_remote_flag)
{
	int	local_remote_flag = QCSAPI_LOCAL_NODE;

	if (strcasecmp(local_remote_str, "remote") == 0) {
		local_remote_flag = QCSAPI_REMOTE_NODE;
	} else if (strcasecmp(local_remote_str, "local") == 0) {
		local_remote_flag = QCSAPI_LOCAL_NODE;
	} else if (local_verify_enable_or_disable(local_remote_str,
					(uint8_t *) &local_remote_flag, print) < 0) {
		print_err(print, "Invalid value %s for local/remote flag\n", local_remote_str);
		return -1;
	}

	*p_local_remote_flag = local_remote_flag;
	return 0;
}

static int name_to_tdls_param_enum(char *lookup_name, qcsapi_tdls_type *p_tdls_type)
{
	int retval = 0;
	int found_entry = 0;
	unsigned int iter;

	for (iter = 0; qcsapi_tdls_param_table[iter].param_name != NULL && found_entry == 0; iter++) {
		if (strcasecmp(qcsapi_tdls_param_table[iter].param_name, lookup_name) == 0) {
			found_entry = 1;
			*p_tdls_type = qcsapi_tdls_param_table[iter].param_type;
			break;
		}
	}

	if (found_entry)
		retval = 1;

	return (retval);
}

static int name_to_tdls_oper_enum(char *lookup_name, qcsapi_tdls_oper *p_tdls_oper)
{
	int retval = 0;
	int found_entry = 0;
	unsigned int iter;
	unsigned int table_size = 0;

	table_size = TABLE_SIZE(qcsapi_tdls_oper_table);

	for (iter = 0; iter < table_size; iter++) {
		if (strcasecmp(qcsapi_tdls_oper_table[iter].oper_name, lookup_name) == 0) {
			found_entry = 1;
			*p_tdls_oper = qcsapi_tdls_oper_table[iter].oper;
			break;
		}
	}

	if (found_entry)
		retval = 1;

	return (retval);
}

static int name_to_extender_param_enum(char *lookup_name, qcsapi_extender_type *p_extender_type)
{
	unsigned int iter;

	for (iter = 0; qcsapi_extender_param_table[iter].param_name != NULL; iter++) {
		if (strcasecmp(qcsapi_extender_param_table[iter].param_name,
				lookup_name) == 0) {
			*p_extender_type = qcsapi_extender_param_table[iter].param_type;
			return 1;
		}
	}

	return 0;
}

static int name_to_autochan_param_enum(char *lookup_name, qcsapi_autochan_type *p_autochan_type)
{
	unsigned int iter;

	for (iter = 0; qcsapi_autochan_param_table[iter].param_name != NULL; iter++) {
		if (strcasecmp(qcsapi_autochan_param_table[iter].param_name,
				lookup_name) == 0) {
			*p_autochan_type = qcsapi_autochan_param_table[iter].param_type;
			return 1;
		}
	}

	return 0;
}

static int name_to_wifi_param_enum(char *lookup_name, qcsapi_wifi_param_type *p_type)
{
	uint32_t iter;

	for (iter = 0; qcsapi_wifi_param_table[iter].param_name != NULL; iter++) {
		if (strcasecmp(qcsapi_wifi_param_table[iter].param_name,
				lookup_name) == 0) {
			*p_type = qcsapi_wifi_param_table[iter].param_type;
			return 1;
		}
	}

	return 0;
}

static int name_to_dpp_param_enum(char *lookup_name, enum qcsapi_dpp_cmd_param_type *p_type)
{
	uint32_t iter;

	for (iter = 0; qcsapi_dpp_param_table[iter].param_name != NULL; iter++) {
		if (strcasecmp(qcsapi_dpp_param_table[iter].param_name,
				lookup_name) == 0) {
			*p_type = qcsapi_dpp_param_table[iter].param_type;
			return 1;
		}
	}

	return 0;
}

static int
parse_generic_parameter_name(qcsapi_output *print, char *generic_parameter_name, qcsapi_generic_parameter *p_generic_parameter )
{
	int			retval = 1;
	qcsapi_unsigned_int	tmpuval = 0;
	qcsapi_tdls_type *p_tdls_type = NULL;
	qcsapi_tdls_oper *p_tdls_oper = NULL;
	qcsapi_extender_type *p_extender_type = NULL;
	qcsapi_autochan_type *p_autochan_type = NULL;
	qcsapi_wifi_param_type *p_wifi_type = NULL;
	enum qcsapi_dpp_cmd_param_type *p_dpp_type = NULL;

	switch( p_generic_parameter->generic_parameter_type )
	{
	  case e_qcsapi_option:
		retval = name_to_option_enum( generic_parameter_name, &(p_generic_parameter->parameter_type.option) );
		if (retval == 0)
		  print_err( print, "Invalid QCSAPI option %s\n", generic_parameter_name );
		break;

	  case e_qcsapi_counter:
		retval = name_to_counter_enum( generic_parameter_name, &(p_generic_parameter->parameter_type.counter) );
		if (retval == 0)
		  print_err( print, "Invalid QCSAPI counter %s\n", generic_parameter_name );
		break;

	  case e_qcsapi_rates:
		retval = name_to_rates_enum( generic_parameter_name, &(p_generic_parameter->parameter_type.typeof_rates) );
		if (retval == 0)
		  print_err( print, "Invalid QCSAPI type of rates %s\n", generic_parameter_name );
		break;

	  case e_qcsapi_modulation:
		retval = name_to_wifi_std_enum(generic_parameter_name,
						&p_generic_parameter->parameter_type.modulation);
		if (!retval)
			print_err(print, "Invalid QCSAPI MIMO modulation %s\n",
					generic_parameter_name);
		break;

	  case e_qcsapi_index:
	  case e_qcsapi_LED:
		if (qcsapi_util_str_to_uint32(generic_parameter_name, &tmpuval) < 0) {
			if (e_qcsapi_option == e_qcsapi_LED) {
				print_err(print, "LED must be a numeric value\n");
			} else {
				print_err(print, "Node index must be a numeric value\n");
			}
			retval = 0;
		} else {
			if ((p_generic_parameter->generic_parameter_type == e_qcsapi_LED) &&
					(tmpuval > QCSAPI_MAX_LED)) {
				print_err(print, "Invalid QSCAPI LED %u\n", tmpuval);
				retval = 0;
			} else {
				p_generic_parameter->index = tmpuval;
			}
		}
		break;

	  case e_qcsapi_select_SSID:
	  case e_qcsapi_SSID_index:
	  /*
	   * APIs with generic parameter type of e_qcsapi_SSID_index expect both an SSID and an index.
	   * Get the SSID now.  Get the index in the individual call_qcsapi routines.
	   */
		strncpy(
			&(p_generic_parameter->parameter_type.the_SSID[ 0 ]),
			 generic_parameter_name,
			 sizeof( p_generic_parameter->parameter_type.the_SSID ) - 1
		);
		p_generic_parameter->parameter_type.the_SSID[ sizeof( p_generic_parameter->parameter_type.the_SSID ) - 1 ] = '\0';
		break;

	  case e_qcsapi_file_path_config:
		if (strcasecmp( "security", generic_parameter_name ) != 0)
		{
			print_err( print, "Invalid QCSAPI file path configuration %s\n", generic_parameter_name );
			retval = 0;
		}
		else
		  p_generic_parameter->index = (qcsapi_unsigned_int) qcsapi_security_configuration_path;
		break;

	  case e_qcsapi_tdls_params:
		p_tdls_type = &(p_generic_parameter->parameter_type.type_of_tdls);
		retval = name_to_tdls_param_enum(generic_parameter_name, p_tdls_type);
		if (retval == 0)
			print_err(print, "Invalid QCSAPI tdls param %s\n", generic_parameter_name);
		break;
	  case e_qcsapi_tdls_oper:
		p_tdls_oper = &(p_generic_parameter->parameter_type.tdls_oper);
		retval = name_to_tdls_oper_enum(generic_parameter_name, p_tdls_oper);
		if (retval == 0)
			print_err(print, "Invalid QCSAPI tdls oper %s\n", generic_parameter_name);
		break;


	  case e_qcsapi_board_parameter:
		retval = name_to_board_parameter_enum(generic_parameter_name,
				&(p_generic_parameter->parameter_type.board_param) );
		if (retval == 0)
		  print_err( print, "Invalid QCSAPI option %s\n", generic_parameter_name );
		break;

	  case e_qcsapi_extender_params:
		p_extender_type = &(p_generic_parameter->parameter_type.type_of_extender);
		retval = name_to_extender_param_enum(generic_parameter_name,
			p_extender_type);
		if (retval == 0)
			print_err(print, "Invalid QCSAPI extender param %s\n",
				generic_parameter_name);
		break;

	  case e_qcsapi_autochan_params:
		p_autochan_type = &(p_generic_parameter->parameter_type.autochan_type);
		retval = name_to_autochan_param_enum(generic_parameter_name,
			p_autochan_type);
		if (retval == 0)
			print_err(print, "Invalid QCSAPI autochan param %s\n",
				generic_parameter_name);
		break;

	  case e_qcsapi_wifi_parameter:
		p_wifi_type = &(p_generic_parameter->parameter_type.wifi_param_type);
		retval = name_to_wifi_param_enum(generic_parameter_name, p_wifi_type);
		if (retval == 0)
			print_err(print, "Invalid QCSAPI wifi parameter %s\n", generic_parameter_name);
		break;

	  case e_qcsapi_dpp_parameter:
		p_dpp_type = &(p_generic_parameter->parameter_type.dpp_param_type);
		retval = name_to_dpp_param_enum(generic_parameter_name, p_dpp_type);
		if (retval == 0)
			print_err(print, "Invalid QCSAPI DPP parameter %s\n",
					generic_parameter_name);
		break;

	  case e_qcsapi_none:
	  default:
		print_err( print, "Programming error in parse generic parameter name:\n" );
		if (p_generic_parameter->generic_parameter_type == e_qcsapi_none)
		{
			print_err( print, "Called with generic parameter type of none.\n" );
		}
		else
		{
			print_err( print, "Called with unknown parameter type %d.\n",
					p_generic_parameter->generic_parameter_type );
		}
		retval = 0;
		break;
	}

	return( retval );
}

static const char *
wifi_mode_to_string(qcsapi_output *print, qcsapi_wifi_mode current_wifi_mode )
{
	const char	*retaddr = "Unknown WIFI mode";

	switch (current_wifi_mode)
	{
	  case qcsapi_mode_not_defined:
		retaddr = "WIFI mode not defined";
		break;

	  case qcsapi_access_point:
		retaddr = "Access point";
		break;

	  case qcsapi_station:
		retaddr = "Station";
		break;

	  case qcsapi_wds:
		retaddr = "WDS";
		break;

	  case qcsapi_nosuch_mode:
	  default:
		print_out( print, "Unknown WIFI mode\n" );
		break;
	}

	return( retaddr );
}

static qcsapi_wifi_mode
string_to_wifi_mode(const char* str)
{
	if (strcasecmp(str, "ap") == 0) {
		return qcsapi_access_point;
	} else if (strcasecmp(str, "access_point") == 0) {
		return qcsapi_access_point;
	} else if (strcasecmp(str, "access point") == 0) {
		return qcsapi_access_point;
	} else if (strcasecmp(str, "sta") == 0) {
		return qcsapi_station;
	} else if (strcasecmp(str, "station") == 0) {
		return qcsapi_station;
	} else if (strcasecmp(str, "repeater") == 0) {
		return qcsapi_repeater;
	} else {
		return qcsapi_nosuch_mode;
	}
}

static qcsapi_pref_band
string_to_wifi_band(const char* str)
{
	if (strcasecmp(str, "2.4ghz") == 0) {
		return qcsapi_band_2_4ghz;
	} else if (strcasecmp(str, "5ghz") == 0) {
		return qcsapi_band_5ghz;
	} else {
		return qcsapi_nosuch_band;
	}
}

static qcsapi_rf_chip_id
string_to_rf_chipid(const char* str)
{
	if (strcasecmp(str, "0") == 0) {
                return qcsapi_rf_chipid_2_4ghz;
        } else if (strcasecmp(str, "1") == 0) {
                return qcsapi_rf_chipid_5ghz;
        } else if (strcasecmp(str, "2") == 0) {
		return qcsapi_rf_chipid_dual;
	} else {
                return qcsapi_nosuch_chipid;
        }
}

static int local_string_to_list(void *input_str, uint8_t *output_list, unsigned int *number)
{
	uint8_t list_number = 0;
	char *pcur = NULL, *pend = NULL;
	char buffer[256] = {0};
	char *input_end;
	int single_len = 0;
	int32_t val = -1;

	if (!input_str || !output_list || !number)
		return -EINVAL;

	input_end = input_str + strnlen(input_str, 1024);
	pcur = input_str;
	do {
		pend = strchr(pcur, ',');
		if (pend) {
			single_len = pend - pcur;
			strncpy(buffer, pcur, single_len);
			buffer[single_len] = 0;
			pend++;

			if (qcsapi_util_str_to_int32(buffer, (int32_t *) &val) < 0)
				return -EINVAL;
			else
				output_list[list_number++] = val;

			pcur = pend;
		} else if (pcur) {
			if (qcsapi_util_str_to_int32(pcur, (int32_t *) &val) < 0)
				return -EINVAL;
			else
				output_list[list_number++] = val;
		}
	} while (pend && pend < input_end);

	*number = list_number;

	return 0;
}

static int
dump_generic_parameter_name(qcsapi_output *print, qcsapi_generic_parameter *p_generic_parameter )
{
	int	retval = 1;
	int dpp_param_type;

	switch( p_generic_parameter->generic_parameter_type )
	{
	  case e_qcsapi_option:
		print_out( print, "%s", option_enum_to_name( p_generic_parameter->parameter_type.option ) );
		break;

	  case e_qcsapi_counter:
		print_out( print, "%s", counter_enum_to_name( p_generic_parameter->parameter_type.counter ) );
		break;

	  case e_qcsapi_rates:
		print_out( print, "%s", rates_enum_to_name( p_generic_parameter->parameter_type.typeof_rates ) );
		break;

	  case e_qcsapi_modulation:
		print_out(print, "%s", wifi_std_enum_to_name(
						p_generic_parameter->parameter_type.modulation));
		break;

	  case e_qcsapi_index:
	  case e_qcsapi_LED:
		print_out( print, "%u", p_generic_parameter->index );
		break;

	  case e_qcsapi_file_path_config:
		print_out( print, "security" );
		break;

	  case e_qcsapi_select_SSID:
	  case e_qcsapi_SSID_index:
		print_out( print, "%s", &(p_generic_parameter->parameter_type.the_SSID[ 0 ]) );
		break;

	  case e_qcsapi_board_parameter:
		print_out( print, "%s", board_paramter_enum_to_name( p_generic_parameter->parameter_type.board_param ) );
		break;

	  case e_qcsapi_dpp_parameter:
		dpp_param_type = p_generic_parameter->parameter_type.dpp_param_type;
		print_out(print, "%s", local_dpp_parameter_enum_to_name(dpp_param_type));
		break;

	  case e_qcsapi_none:
	  default:
		print_out( print, "Programming error in dump generic parameter name:\n" );
		if (p_generic_parameter->generic_parameter_type == e_qcsapi_none)
		{
			print_out( print, "Called with generic parameter type of none.\n" );
		}
		else
		{
			print_out( print, "Called with unknown parameter type %d.\n", p_generic_parameter->generic_parameter_type );
		}
		retval = 0;
		break;
	}

	return( retval );
}

static void
dump_mac_addr(qcsapi_output *print, qcsapi_mac_addr mac_addr )
{
	  print_out( print, "%02X:%02X:%02X:%02X:%02X:%02X\n",
		mac_addr[ 0 ], mac_addr[ 1 ], mac_addr[ 2 ],
		mac_addr[ 3 ], mac_addr[ 4 ], mac_addr[ 5 ]
	  );
}

static void dump_data_array(qcsapi_output *print, uint8_t *data, int size, int order, char delimiter)
{
	int i;

	if (data == NULL)
		return;

	i = 0;
	if (order == 10) {
		do {
			print_out(print, "%d%c", data[i], delimiter);
			i++;
		} while (i < (size - 1));
		print_out(print, "%d", data[i]);
	} else {
		do {
			print_out(print, "0x%x%c", data[i], delimiter);
			i++;
		} while (i < (size - 1));
		print_out(print, "0x%x", data[i]);
	}

	print_out(print, "\n");
}

static void
dump_scs_param(qcsapi_output *print, qcsapi_scs_param_rpt *p_rpt)
{
#define MAX_SCS_PARAM_DESC 35
	int j, loop;
	uint32_t str_len = 0;
	const char *name;
	uint32_t index;

	for (j = 0; j < TABLE_SIZE(qcsapi_scs_param_names_table); j++) {
		name = qcsapi_scs_param_names_table[j].name;
		index = qcsapi_scs_param_names_table[j].index;

		str_len = min(strlen(name), strlen("scs_tdls_time_compensation"));
		if (!strncmp(name, "scs_tx_time_compensation", str_len) ||
				!strncmp(name, "scs_rx_time_compensation", str_len) ||
				 !strncmp(name, "scs_tdls_time_compensation", str_len)) {
			print_out(print, "%-*s ", MAX_SCS_PARAM_DESC, name);
			loop = SCS_MAX_TXTIME_COMP_INDEX;
			do {
				print_out(print, "%u ", p_rpt[index++].scs_cfg_param);
				loop--;
			} while (loop);
			print_out(print, "\n");
		} else {
			if (p_rpt[index].scs_signed_param_flag == 0) {
				print_out(print, "%-*s %u\n", MAX_SCS_PARAM_DESC, name, p_rpt[index].scs_cfg_param);
			}
			else if (p_rpt[index].scs_signed_param_flag == 1) {
				print_out(print, "%-*s %d\n", MAX_SCS_PARAM_DESC, name, p_rpt[index].scs_cfg_param);
			}
			else {
				print_out(print, "invalid param flag!\n");
			}
		}
	}
}
static void
report_qcsapi_error( const call_qcsapi_bundle *p_calling_bundle, const int qcsapi_errorval )
{
	char	error_msg[ 128 ] = { '\0' };
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_errno_get_message( qcsapi_errorval, &error_msg[ 0 ], sizeof( error_msg ) );
	print_out( print, "QCS API error %d: %s\n", 0 - qcsapi_errorval, &error_msg[ 0 ] );
}

static void
qcsapi_report_parameter_count(const call_qcsapi_bundle *p_calling_bundle, const int num)
{
	print_out(p_calling_bundle->caller_output,
			"Not enough parameters in call qcsapi %s, count is %d\n",
			entry_point_enum_to_name(p_calling_bundle->caller_qcsapi),
			num);
}

static void
qcsapi_report_usage(const call_qcsapi_bundle *p_calling_bundle, const char *params)
{
	print_out(p_calling_bundle->caller_output,
			"Usage: call_qcsapi %s %s\n",
			entry_point_enum_to_name(p_calling_bundle->caller_qcsapi),
			params);
}

static int
qcsapi_report_complete(const call_qcsapi_bundle *p_calling_bundle, int qcsapi_retval)
{
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(p_calling_bundle->caller_output, "complete\n");
		}
		return 0;
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}
}

static int
qcsapi_report_str_or_error(const call_qcsapi_bundle *p_calling_bundle, int qcsapi_retval,
		const char *str)
{
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(p_calling_bundle->caller_output, "%s\n", str);
		}
		return 0;
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}
}

static void
print_start_scan_usage(qcsapi_output* print)
{
	print_out(print, "Usage:\n"
		"    call_qcsapi start_scan <interface> <algorithm> <channels> <flags>\n"
		"Parameters:\n"
		"    <algorithm> reentry, clearest (default), no_pick, background\n"
		"    <channels>  dfs, non_dfs, all (default)\n"
		"    <flags>     flush, active, random, fast, normal, slow, check\n");
}

static void
print_cancel_scan_usage(qcsapi_output* print)
{
	print_out(print, "Usage: call_qcsapi cancel_scan <interface> [force]\n");
}

static const char *
csw_reason_to_string(uint32_t reason_id)
{
	COMPILE_TIME_ASSERT(ARRAY_SIZE(qcsapi_csw_reason_list) == IEEE80211_CSW_REASON_MAX);

	if (reason_id < ARRAY_SIZE(qcsapi_csw_reason_list))
		return qcsapi_csw_reason_list[reason_id];

	return qcsapi_csw_reason_list[IEEE80211_CSW_REASON_UNKNOWN];
}



static void
scs_reason_to_string(uint32_t scs_reason_id, char *scs_reason_str)
{
	if (!scs_reason_str)
		return ;
	sprintf(scs_reason_str, "SCS");

	if (scs_reason_id & IEEE80211_SCS_STA_CCA_REQ_CC) {
		strcat(scs_reason_str, "|STA_interfered");
	}
	if (scs_reason_id & IEEE80211_SCS_SELF_CCA_CC) {
		strcat(scs_reason_str, "|AP_interfered");
	}
	if (scs_reason_id & IEEE80211_SCS_ATTEN_INC_CC) {
		strcat(scs_reason_str, "|Attenuation");
	}
	if (scs_reason_id & IEEE80211_SCS_BRCM_STA_TRIGGER_CC) {
		strcat(scs_reason_str, "|BRCM_STA_interfered");
	}
	return ;
}

/* interface programs to call individual QCSAPIs */

static int
call_qcsapi_errno_get_message(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	int arg_retval;
	int32_t qcsapi_errorval = 0;
	char *error_str = NULL;
	uint32_t message_size = QCSAPI_MSG_BUFSIZE;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		qcsapi_report_parameter_count(p_calling_bundle, argc);
		qcsapi_report_usage(p_calling_bundle, "<returned error value> [size of message buffer]");
		return 1;
	}

	arg_retval = local_atoi32_verify_numeric_range(argv[0], &qcsapi_errorval, print, INT_MIN, -1);
	if (arg_retval < 0) {
		report_qcsapi_error(p_calling_bundle, arg_retval);
		return 1;
	}

        if (argc >= 2) {
		if ((local_atou32_verify_numeric_range(argv[1], &message_size, print, 1,
				QCSAPI_MSG_BUFSIZE)) < 0) {
			return 1;
		}
	}

	error_str = malloc(message_size);
	if (error_str == NULL) {
		print_err(print, "Failed to allocate %u chars\n", message_size);
		return 1;
	}

	qcsapi_retval = qcsapi_errno_get_message(qcsapi_errorval, error_str, message_size);

	statval = qcsapi_report_str_or_error(p_calling_bundle, qcsapi_retval, error_str);

	free(error_str);

	return statval;
}

#define QCSAPI_IP_NMASK_LEN_MIN	1
#define QCSAPI_IP_NMASK_LEN_MAX	32

static int
local_parse_ip_and_netmask(const call_qcsapi_bundle *p_calling_bundle,
					char *str, uint32_t *ipaddr, uint32_t *netmask)
{
	uint32_t netmask_len;
	char *slash;
	char *p_netmask;
	int arg_retval;
	qcsapi_output *print = p_calling_bundle->caller_output;

	slash = strstr(str, "/");
	if (slash != NULL) {
		*slash = '\0';
		p_netmask = slash + 1;
		if (strstr(p_netmask, ".") != NULL) {
			if ((inet_pton(AF_INET, p_netmask, netmask) != 1) ||
						(*netmask == 0)) {
				print_err(print, "Invalid netmask address %s\n", p_netmask);
				return -EINVAL;
			}
		} else {
			arg_retval = local_atou32_verify_numeric_range(p_netmask, &netmask_len,
					print, QCSAPI_IP_NMASK_LEN_MIN, QCSAPI_IP_NMASK_LEN_MAX);
			if (arg_retval < 0) {
				report_qcsapi_error(p_calling_bundle, arg_retval);
				return 1;
			}
			*netmask = htonl(~((1 << (32 - netmask_len)) - 1));
		}
	} else {
		*netmask = 0;
	}

	if ((inet_pton(AF_INET, str, ipaddr) != 1) || (*ipaddr == 0)) {
		print_err(print, "Invalid IPv4 address %s\n", str);
		return -EINVAL;
	}

	return 0;
}

static int
call_qcsapi_store_ipaddr(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	uint32_t ipaddr = 0;
	uint32_t netmask = 0;
	char *usage = "<ip_address>[/<netmask>]";

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return -EINVAL;
	}

	qcsapi_retval = local_parse_ip_and_netmask(p_calling_bundle, argv[0], &ipaddr, &netmask);
	if (qcsapi_retval >= 0) {
		if (netmask == 0)
			netmask = htonl(0xFFFFFF00);

		qcsapi_retval = qcsapi_store_ipaddr(ipaddr, netmask);
	}

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}


static int
call_qcsapi_get_stored_ipaddr(call_qcsapi_bundle *call, int argc, char *argv[])
{
#define IPADDR_AND_NETMASK_MAX_LEN 64
	int		statval = 0;
	int		qcsapi_retval;
	char		ipaddr[IPADDR_AND_NETMASK_MAX_LEN + 1] = {0};
	qcsapi_output	*print = call->caller_output;

	qcsapi_retval = qcsapi_get_stored_ipaddr(&ipaddr[0], IPADDR_AND_NETMASK_MAX_LEN);

	if (qcsapi_retval >= 0) {
		print_out(print, "%s\n", ipaddr);
	} else {
		report_qcsapi_error(call, qcsapi_retval);
		statval = 1;
	}

	return statval;
#undef IPADDR_AND_NETMASK_MAX_LEN
}

static int
call_qcsapi_interface_enable(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	uint8_t enable_flag;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (local_verify_enable_or_disable(argv[0], &enable_flag, print) < 0)
		return 1;

	/*
	 * This program is a model for all programs that call a QCSAPI.
	 * If the verbose flag is less than 0, do not report nominal (non-error) results.
	 *
	 * Like this, one can test for aging (sockets, files not closed) without
	 * seemingly endless output of "complete", etc.
	 *
	 * And if you want to see that output, just avoid enabling quiet mode.
	 *
	 * Errors though are ALWAYS reported (else how can you see if the aging test failed?)
	 * And keep trying the test; we may want to ensure a test case that is expected to
	 * cause an error does not itself have aging problems.
	 */
	qcsapi_retval = qcsapi_interface_enable(the_interface, enable_flag);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_interface_get_BSSID( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_mac_addr		 the_mac_addr;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	if (argc > 0 && strcmp( argv[ 0 ], "NULL" ) == 0)
	  qcsapi_retval = qcsapi_interface_get_BSSID( the_interface, NULL );
	else
	  qcsapi_retval = qcsapi_interface_get_BSSID( the_interface, the_mac_addr );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			dump_mac_addr(print, the_mac_addr );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_interface_get_mac_addr( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_mac_addr		 the_mac_addr;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	if (argc > 0 && strcmp( argv[ 0 ], "NULL" ) == 0)
	  qcsapi_retval = qcsapi_interface_get_mac_addr( the_interface, NULL );
	else
	  qcsapi_retval = qcsapi_interface_get_mac_addr( the_interface, the_mac_addr );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			dump_mac_addr(print, the_mac_addr );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_interface_set_mac_addr( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi interface set mac address, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		int			qcsapi_retval;
		qcsapi_mac_addr	the_mac_addr;
		const char	*the_interface = p_calling_bundle->caller_interface;

		if (strcmp( argv[0], "NULL" ) == 0)
			qcsapi_retval = qcsapi_interface_set_mac_addr( the_interface, NULL );
		else
		{
			int ival = parse_mac_addr( argv[0], the_mac_addr );
			if (ival >= 0)
				qcsapi_retval = qcsapi_interface_set_mac_addr( the_interface, the_mac_addr );
			else {
				print_out( print, "Error parsing MAC address %s\n", argv[0]);
				statval = 1;
			}

			if (ival >= 0)
			{
				if (qcsapi_retval >= 0)
				{
					if (verbose_flag >= 0)
					{
						print_out( print, "complete\n" );
					}
				}
				else
				{
					report_qcsapi_error( p_calling_bundle, qcsapi_retval );
					statval = 1;
				}
			}
		}
	}

	return( statval );
}

static int
call_qcsapi_interface_get_counter( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_unsigned_int	 counter_value;
	qcsapi_unsigned_int	*p_counter_value = NULL;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_counter_type	 the_counter_type = p_calling_bundle->caller_generic_parameter.parameter_type.counter;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_counter_value = &counter_value;

	qcsapi_retval = qcsapi_interface_get_counter( the_interface, the_counter_type, p_counter_value );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%u\n", (unsigned int) counter_value );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_interface_get_counter64( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	uint64_t counter_value;
	uint64_t *p_counter_value = NULL;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_counter_type the_counter_type =
			p_calling_bundle->caller_generic_parameter.parameter_type.counter;

	if (argc < 1 || strcmp(argv[0], "NULL") != 0)
		p_counter_value = &counter_value;

	qcsapi_retval = qcsapi_interface_get_counter64(the_interface, the_counter_type,
			p_counter_value);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%llu\n", counter_value);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_pm_get_counter( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			 statval = 0;
	qcsapi_unsigned_int	 counter_value;
	qcsapi_unsigned_int	*p_counter_value = NULL;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_counter_type	 the_counter_type = p_calling_bundle->caller_generic_parameter.parameter_type.counter;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	const char		*the_pm_interval = NULL;

	if (argc < 1) {
		print_err(print, "Usage: call_qcsapi pm_get_counter <WiFi interface> <counter> <PM interval>\n");
		return 1;
	}

	if (strcmp(argv[0], "NULL") != 0) {
		the_pm_interval = argv[0];
	}

	if (argc < 2 || (strcmp(argv[1], "NULL") != 0)) {
		p_counter_value = &counter_value;
	}

	qcsapi_retval = qcsapi_pm_get_counter(the_interface, the_counter_type, the_pm_interval, p_counter_value);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%u\n", (unsigned int) counter_value);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_pm_get_elapsed_time( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			 statval = 0;
	int			 qcsapi_retval;
	const char		*the_pm_interval = NULL;
	qcsapi_unsigned_int	 elapsed_time;
	qcsapi_unsigned_int	*p_elapsed_time = NULL;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err(print, "Usage: call_qcsapi pm_get_elapsed_time <PM interval>\n");
		return 1;
	}

	if (strcmp(argv[0], "NULL") != 0) {
		the_pm_interval = argv[0];
	}

	if (argc < 2 || (strcmp(argv[1], "NULL") != 0)) {
		p_elapsed_time = &elapsed_time;
	}

	qcsapi_retval = qcsapi_pm_get_elapsed_time(the_pm_interval, p_elapsed_time);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%u\n", (unsigned int) elapsed_time);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}


static int
call_qcsapi_flash_image_update( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	int				 qcsapi_retval;
	qcsapi_flash_partiton_type	 partition_type = qcsapi_nosuch_partition;
	const char			*image_file_path = NULL;
	qcsapi_output			*print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err( print, "Not enough parameters in call qcsapi flash image update, count is %d\n", argc );
		print_err( print, "Usage: call_qcsapi flash_image_update <image file path> <live | "\
					"safety | uboot>\n" );
		statval = 1;
	} else {
		if (strcmp( argv[ 0 ], "NULL" ) != 0) {
			image_file_path = argv[ 0 ];
		}

		if (name_to_partition_type( argv[ 1 ], &partition_type ) == 0) {
			print_err( print, "Unrecognized flash memory partition type %s\n", argv[ 1 ] );
			statval = 1;
		} else {
			qcsapi_retval = qcsapi_flash_image_update( image_file_path, partition_type );
			if (qcsapi_retval >= 0) {
				if (verbose_flag >= 0) {
					print_out( print, "complete\n" );
				}
			} else {
				report_qcsapi_error( p_calling_bundle, qcsapi_retval );
				statval = 1;
			}
		}
	}

	return( statval );
}

#define QCSAPI_FW_VERSION_LEN_MIN	3
#define QCSAPI_FW_VERSION_LEN_MAX	40

static int
call_qcsapi_firmware_get_version(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	uint32_t version_size = QCSAPI_FW_VERSION_LEN_MAX;
	char firmware_version[QCSAPI_FW_VERSION_LEN_MAX];
	char *p_firmware_version = &firmware_version[0];
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc > 0) {
		if (local_atou32_verify_numeric_range(argv[0], &version_size, print,
				QCSAPI_FW_VERSION_LEN_MIN, QCSAPI_FW_VERSION_LEN_MAX) < 0) {
			return 1;
		}
	}

	qcsapi_retval = qcsapi_firmware_get_version(p_firmware_version, version_size);

	return qcsapi_report_str_or_error(p_calling_bundle, qcsapi_retval, p_firmware_version);
}

static int
call_qcsapi_system_get_time_since_start(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int			 statval = 0;
	int			 qcsapi_retval;
	qcsapi_unsigned_int	 time_since_startup;
	qcsapi_unsigned_int	*p_time_since_startup = &time_since_startup;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	if (argc > 0 && strcmp(argv[0], "NULL") == 0) {
		p_time_since_startup = NULL;
	}

	qcsapi_retval = qcsapi_system_get_time_since_start(p_time_since_startup);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%u\n", time_since_startup);
		}
	}
	else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_get_system_status(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	qcsapi_unsigned_int status;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_get_system_status(&status);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%X\n", status);
			int id;
			for (id = 0; id < TABLE_SIZE(qcsapi_sys_status_table); id++) {
				print_out(print, "bit %-2d - %s\n", qcsapi_sys_status_table[id].bit_id,
						qcsapi_sys_status_table[id].description);
			}
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_get_random_seed(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	qcsapi_output *print = p_calling_bundle->caller_output;
	struct qcsapi_data_512bytes *random_buf;
	int i;

	random_buf = malloc(sizeof(*random_buf));

	if (!random_buf) {
		print_err(print, "Failed to allocate %u bytes\n", sizeof(*random_buf));
		return 1;
	}

	qcsapi_retval = qcsapi_get_random_seed(random_buf);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			for (i = 0; i < sizeof(random_buf->data); i++) {
				print_out(print, "%c", random_buf->data[i]);
			}
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	free(random_buf);

	return statval;
}

static int
call_qcsapi_set_random_seed(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	uint32_t entropy = 0;
	int qcsapi_retval;
	struct qcsapi_data_512bytes *random_buf;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		qcsapi_report_usage(p_calling_bundle, "<random_string> <entropy>");
		return 1;
	}

	if (local_str_to_uint32(argv[1], &entropy, print, "entropy value") < 0)
		return 1;

	random_buf = malloc(sizeof(*random_buf));
	if (!random_buf) {
		print_err(print, "Failed to allocate %u bytes\n", sizeof(*random_buf));
		return 1;
	}

	memset(random_buf, 0, sizeof(*random_buf));
	memcpy((void *)random_buf->data, (void *)argv[0],
			min(sizeof(random_buf->data), strlen(argv[0])));

	qcsapi_retval = qcsapi_set_random_seed(random_buf, entropy);

	statval = qcsapi_report_complete(p_calling_bundle, qcsapi_retval);

	free(random_buf);

	return statval;
}

static int
call_qcsapi_led_get( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int		statval = 0;
	int		qcsapi_retval;
	uint8_t		the_led = (uint8_t) (p_calling_bundle->caller_generic_parameter.index);
	uint8_t		led_value, *p_led_value = NULL;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_led_value = &led_value;

	qcsapi_retval = qcsapi_led_get( the_led, p_led_value );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%u\n", led_value );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_led_set(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	uint8_t new_value;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint8_t the_led = (uint8_t) (p_calling_bundle->caller_generic_parameter.index);

	if (argc < 1) {
		qcsapi_report_usage(p_calling_bundle, "<LED / GPIO pin number> {0 | 1}");
		return 1;
	}

	if (local_verify_enable_or_disable(argv[0], &new_value, print) < 0)
		return 1;

	qcsapi_retval = qcsapi_led_set(the_led, new_value);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_led_pwm_enable( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval = 0;
	uint8_t led_ident = (uint8_t) (p_calling_bundle->caller_generic_parameter.index);
	qcsapi_unsigned_int onoff = 0;
	qcsapi_unsigned_int high_count = 0;
	qcsapi_unsigned_int low_count = 0;

	if (argc < 1)
		goto usage;
	if (sscanf(argv[0], "%u", &onoff) != 1)
		goto usage;
	if (onoff != 0 && argc < 3)
		goto usage;
	if (onoff != 0) {
		if (sscanf(argv[1], "%u", &high_count) != 1)
			goto usage;
		if (sscanf(argv[2], "%u", &low_count) != 1)
			goto usage;
	}

	qcsapi_retval = qcsapi_led_pwm_enable(led_ident, (uint8_t)onoff, high_count, low_count);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out( print, "complete\n" );
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return (statval);

usage:
	print_err(print, "Usage: call_qcsapi set_LED_PWM <led_ident> (1|0) <high_count> <low_count>\n");
	statval = 1;

	return (statval);
}

static int
call_qcsapi_led_brightness( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval = 0;
	uint8_t led_ident = (uint8_t) (p_calling_bundle->caller_generic_parameter.index);
	qcsapi_unsigned_int level = 0;

	if (argc < 1)
		goto usage;
	if (sscanf(argv[0], "%u", &level) != 1)
		goto usage;

	qcsapi_retval = qcsapi_led_brightness(led_ident, level);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out( print, "complete\n" );
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return (statval);

usage:
	print_err(print, "Usage: call_qcsapi set_LED_brightness <led_ident> <level>\n");
	statval = 1;

	return (statval);
}

static int
call_qcsapi_gpio_get_config( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	int			qcsapi_retval;
	uint8_t			the_gpio = (uint8_t) (p_calling_bundle->caller_generic_parameter.index);
	qcsapi_gpio_config	gpio_config, *p_gpio_config = NULL;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_gpio_config = &gpio_config;

	qcsapi_retval = qcsapi_gpio_get_config( the_gpio, p_gpio_config );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%u\n", gpio_config );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_gpio_set_config(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	int32_t new_value = 0;
	uint8_t the_gpio = (uint8_t) (p_calling_bundle->caller_generic_parameter.index);
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		qcsapi_report_usage(p_calling_bundle, "<GPIO pin number> <configuration>");
		return 1;
	}

	if (local_str_to_int32(argv[0], &new_value, print, "gpio configuration value") < 0)
		return 1;

	qcsapi_retval = qcsapi_gpio_set_config(the_gpio, (qcsapi_gpio_config) new_value);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_gpio_enable_wps_push_button( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int qcsapi_retval;
	uint8_t active_logic = 0;
	uint8_t use_interrupt_flag = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint8_t wps_push_button = (uint8_t) (p_calling_bundle->caller_generic_parameter.index);

	if (argc < 1) {
		qcsapi_report_parameter_count(p_calling_bundle, argc);
		return 1;
	}

	if (local_verify_enable_or_disable(argv[0], &active_logic, print) < 0)
		return 1;

	if (argc > 1 && strcasecmp(argv[1], "intr") == 0)
		use_interrupt_flag = 1;

	qcsapi_retval = qcsapi_gpio_enable_wps_push_button(wps_push_button, active_logic, use_interrupt_flag);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_file_path_get_config( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	int			qcsapi_retval;
	qcsapi_file_path_config	the_file_path_config =
			(qcsapi_file_path_config) (p_calling_bundle->caller_generic_parameter.index);
	char			file_path[ 80 ], *p_file_path = NULL;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_file_path = &file_path[ 0 ];

	qcsapi_retval = qcsapi_file_path_get_config( the_file_path_config, p_file_path, sizeof( file_path ) );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%s\n", &file_path[ 0 ] );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_file_path_set_config( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi file path set config, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		int			qcsapi_retval;
		qcsapi_file_path_config	the_file_path_config =
				(qcsapi_file_path_config) (p_calling_bundle->caller_generic_parameter.index);

		qcsapi_retval = qcsapi_file_path_set_config( the_file_path_config, argv[ 0 ] );
		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_wifi_macaddr(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi file path set config, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		qcsapi_mac_addr new_mac_addr;
		int		qcsapi_retval;
		int		ival = 0;

		if (strcmp( "NULL", argv[ 0 ] ) == 0)
		  qcsapi_retval = qcsapi_wifi_set_wifi_macaddr( NULL );
		else
		{
			ival = parse_mac_addr( argv[ 0 ], new_mac_addr );
			if (ival >= 0)
			  qcsapi_retval = qcsapi_wifi_set_wifi_macaddr( new_mac_addr );
			else
			{
				print_out( print, "Error parsing MAC address %s\n", argv[ 0 ] );
				statval = 1;
			}
		}

		if (ival >= 0)
		{
			if (qcsapi_retval >= 0)
			{
				if (verbose_flag >= 0)
				{
					print_out( print, "complete\n" );
				}
			}
			else
			{
				report_qcsapi_error( p_calling_bundle, qcsapi_retval );
				statval = 1;
			}
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_create_restricted_bss(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_mac_addr mac_addr = {0};

	if (argc == 1) {
		qcsapi_retval = parse_mac_addr( argv[ 0 ], mac_addr );
		if (qcsapi_retval < 0) {
			print_out( print, "Error parsing MAC address %s\n", argv[ 0 ] );
			statval = 1;
		}
	}

	if (qcsapi_retval >= 0) {
		qcsapi_retval = qcsapi_wifi_create_restricted_bss(the_interface, mac_addr);
	}

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "complete\n");
		}
	}
	else
	{
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_create_bss(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_mac_addr mac_addr = {0};
	int ifup = QCSAPI_TRUE;

	while (argc > 0) {
		if (strcmp(argv[0], "down") == 0) {
			ifup = QCSAPI_FALSE;
		} else if (strcmp(argv[0], "up") == 0) {
			ifup = QCSAPI_TRUE;
		} else {
			qcsapi_retval = parse_mac_addr(argv[0], mac_addr);
			if (qcsapi_retval < 0) {
				statval = 1;
				break;
			}
		}
		argv++;
		argc--;
	}

	if (qcsapi_retval >= 0) {
		qcsapi_retval = qcsapi_wifi_create_bss_with_ifstate(the_interface, mac_addr, ifup);
	} else {
		qcsapi_report_usage(p_calling_bundle, "<ifname> [MAC address] [{down | up}]");
	}

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_remove_bss(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_remove_bss(the_interface);
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "complete\n");
		}
	}
	else
	{
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_primary_interface(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	char ifname[IFNAMSIZ];
	qcsapi_output *print = p_calling_bundle->caller_output;

	memset(ifname, 0, IFNAMSIZ);
	qcsapi_retval = qcsapi_get_primary_interface(ifname, IFNAMSIZ - 1);
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%s\n", ifname);
		}
	}
	else
	{
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_interface_by_index(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	char ifname[IFNAMSIZ];
	qcsapi_unsigned_int if_index = p_calling_bundle->caller_generic_parameter.index;
	qcsapi_output *print = p_calling_bundle->caller_output;

	memset(ifname, 0, IFNAMSIZ);
	qcsapi_retval = qcsapi_get_interface_by_index(if_index, ifname, IFNAMSIZ - 1);

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%s\n", ifname);
		}
	}
	else
	{
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_interface_by_index_all(const call_qcsapi_bundle *p_calling_bundle,
	int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	char ifname[IFNAMSIZ];
	qcsapi_unsigned_int if_index = p_calling_bundle->caller_generic_parameter.index;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int radio;
	qcsapi_unsigned_int radio_id = 0;

	if (argc > 0) {
		radio = atoi(argv[0]);
		if (radio < 0)
			qcsapi_retval = -qcsapi_param_value_invalid;

		radio_id = (unsigned int)radio;
	}

	if (qcsapi_retval >= 0) {
		memset(ifname, 0, IFNAMSIZ);
		qcsapi_retval = qcsapi_radio_get_interface_by_index_all(radio_id, if_index, ifname, IFNAMSIZ - 1);
	}

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%s\n", ifname);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_mode( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_wifi_mode	 current_wifi_mode, *p_wifi_mode = NULL;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_wifi_mode = &current_wifi_mode;
	qcsapi_retval = qcsapi_wifi_get_mode( the_interface, p_wifi_mode );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 1)
		{
			print_out( print, "%d (%s)\n", (int) current_wifi_mode,
					wifi_mode_to_string(print, current_wifi_mode ) );
		}
		else if (verbose_flag >= 0)
		{
			print_out( print, "%s\n",
					wifi_mode_to_string(print, current_wifi_mode ) );
		}
	  /*
	   * Else display nothing in quiet mode (verbose flag < 0)
	   */
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_mode( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi WiFi set mode, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		qcsapi_wifi_mode new_wifi_mode;

		new_wifi_mode = string_to_wifi_mode(argv[0]);

		if (new_wifi_mode == qcsapi_nosuch_mode) {
			print_err( print, "Unrecognized WiFi mode %s\n", argv[ 0 ] );
			statval = 1;
			return( statval );
		}

		qcsapi_retval = qcsapi_wifi_set_mode( the_interface, new_wifi_mode );
		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_phy_mode( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int				statval = 0;
	int				qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	string_64		phy_mode;

	if (argc > 0 && (strcmp(argv[ 0 ], "NULL") == 0))
	{
		qcsapi_retval = -EFAULT;
	}
	else
	{
		memset(phy_mode, 0 , sizeof(phy_mode));
		qcsapi_retval = qcsapi_wifi_get_phy_mode( the_interface, phy_mode );
	}

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
			print_out( print, "%s\n", phy_mode );
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_phy_mode( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int     statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi WiFi set phy mode, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		int			qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		const char	*mode = argv[0];

		qcsapi_retval = qcsapi_wifi_set_phy_mode( the_interface, mode );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_reload_in_mode( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi WiFi reload in mode, count is %d\n", argc );
		statval = 1;
	} else {
		int		qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		qcsapi_wifi_mode new_wifi_mode;

		new_wifi_mode = string_to_wifi_mode(argv[0]);

		if (new_wifi_mode == qcsapi_nosuch_mode) {
			print_err( print, "Unrecognized WiFi mode %s\n", argv[ 0 ] );
			statval = 1;
			return( statval );
		}

		qcsapi_retval = qcsapi_wifi_reload_in_mode( the_interface, new_wifi_mode );
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_rfenable(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	uint8_t onoff = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (local_verify_enable_or_disable(argv[0], &onoff, print) < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_rfenable((qcsapi_unsigned_int) onoff);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_wifi_rfstatus(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int 		qcsapi_retval;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	qcsapi_rf_status rfstatus = QCSAPI_RFSTATUS_OFF;

	qcsapi_retval = qcsapi_wifi_rfstatus( &rfstatus );
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			switch (rfstatus) {
			case QCSAPI_RFSTATUS_OFF:
				print_out( print, "%s\n", "Off" );
				break;
			case QCSAPI_RFSTATUS_ON:
				print_out( print, "%s\n", "On" );
				break;
			case QCSAPI_RFSTATUS_TURNING_OFF:
				print_out( print, "%s\n", "Turning off" );
				break;
			case QCSAPI_RFSTATUS_TURNING_ON:
				print_out( print, "%s\n", "Turning on" );
				break;
			default:
				print_out( print, "%s\n", "Unknown status" );
			}
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_startprod(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	int		qcsapi_retval;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_startprod();

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_supported_freq_bands( call_qcsapi_bundle *p_calling_bundle,
			int argc, char *argv[] )
{
	int	statval = 0;
	int	qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	string_32 bands = {0};

	qcsapi_retval = qcsapi_wifi_get_supported_freq_bands(the_interface, bands);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%s\n", bands);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_oper_bw(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi WiFi set oper bw, count is %d\n", argc );
		print_err( print, "Usage: call_qcsapi set_oper_bw <WiFi interface> <{80 | 40 | 20}>\n" );
		statval = 1;
	}
	else
	{
		qcsapi_unsigned_int	 current_bw = (qcsapi_unsigned_int) atoi( argv[ 0 ] );
		int			 qcsapi_retval;
		const char		*the_interface = p_calling_bundle->caller_interface;

		qcsapi_retval = qcsapi_wifi_set_oper_bw(the_interface, (qcsapi_unsigned_int) current_bw);
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0)
				print_out(print, "complete\n");
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wifi_get_bw( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_unsigned_int	 current_bw = 0, *p_bw = NULL;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_bw = &current_bw;
	qcsapi_retval = qcsapi_wifi_get_bw( the_interface, p_bw );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%u\n", current_bw );
		}
	  /*
	   * Else display nothing in quiet mode (verbose flag < 0)
	   */
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_bw(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	uint32_t current_bw = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (local_str_to_uint32(argv[0], &current_bw, print, "bandwidth value") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_bw(the_interface, (qcsapi_unsigned_int) current_bw);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_wifi_get_24g_bw( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int statval = 0;
	qcsapi_unsigned_int current_bw = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	string_64 p_buffer;
	qcsapi_rf_chip_id rf_chipid;

	qcsapi_get_board_parameter(qcsapi_rf_chipid, p_buffer);
	rf_chipid = string_to_rf_chipid(p_buffer);
	qcsapi_wifi_get_mode(the_interface, &wifi_mode);

	/* Check operating mode is station and dual band is supported */
	if ((wifi_mode != qcsapi_station) && (rf_chipid != CHIPID_DUAL)) {
		print_out(print,"!!ERROR Mode should be station and Band should be Dual Band  \n");
		qcsapi_retval = -EINVAL;
	}

	if (qcsapi_retval >= 0)
		qcsapi_retval = qcsapi_wifi_get_24g_bw( the_interface, &current_bw );

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out( print, "%u\n", current_bw );
	} else {
	        report_qcsapi_error( p_calling_bundle, qcsapi_retval );
	        statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_24g_bw(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	uint32_t cur_bw;
	string_64 p_buffer;
	int retval = 0;
	qcsapi_rf_chip_id rf_chipid;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;

	qcsapi_get_board_parameter(qcsapi_rf_chipid, p_buffer);
	rf_chipid = string_to_rf_chipid(p_buffer);
	qcsapi_wifi_get_mode(the_interface, &wifi_mode);

	/* Check operating mode is station and dual band is supported */
	if ((wifi_mode != qcsapi_station) && (rf_chipid != CHIPID_DUAL)) {
		print_out(print,"!!ERROR Mode should be station and Band should be Dual Band\n");
		retval = -EINVAL;
	}

	if (retval >= 0)
		retval = qcsapi_util_str_to_uint32(argv[0], &cur_bw);

	if (retval >= 0)
		retval = qcsapi_wifi_set_24g_bw(the_interface, (qcsapi_unsigned_int) cur_bw);

	return qcsapi_report_complete(p_calling_bundle, retval);
}

static int
call_qcsapi_wifi_get_BSSID( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_mac_addr	 the_mac_addr;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;

	if (argc > 0 && strcmp( argv[ 0 ], "NULL" ) == 0)
	  qcsapi_retval = qcsapi_wifi_get_BSSID( the_interface, NULL );
	else
	  qcsapi_retval = qcsapi_wifi_get_BSSID( the_interface, the_mac_addr );

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			dump_mac_addr(p_calling_bundle->caller_output, the_mac_addr );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_config_BSSID( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_mac_addr	 the_mac_addr;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;

	if (argc > 0 && strcmp(argv[0], "NULL" ) == 0) {
		qcsapi_retval = qcsapi_wifi_get_config_BSSID( the_interface, NULL );
	} else {
		qcsapi_retval = qcsapi_wifi_get_config_BSSID( the_interface, the_mac_addr );
	}

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			dump_mac_addr(p_calling_bundle->caller_output, the_mac_addr );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_ssid_get_bssid(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	qcsapi_mac_addr	the_mac_addr;
	int		qcsapi_retval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	const char	*SSID = p_calling_bundle->caller_generic_parameter.parameter_type.the_SSID;

	qcsapi_retval = qcsapi_wifi_ssid_get_bssid(the_interface, SSID, the_mac_addr);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			dump_mac_addr(p_calling_bundle->caller_output, the_mac_addr);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_ssid_set_bssid(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	qcsapi_mac_addr	the_mac_addr;
	int		qcsapi_retval = 0;
	int		ival = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	const char	*SSID = p_calling_bundle->caller_generic_parameter.parameter_type.the_SSID;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	ival = parse_mac_addr(argv[0], the_mac_addr);

	if (ival >= 0) {
		qcsapi_retval = qcsapi_wifi_ssid_set_bssid(the_interface, SSID, the_mac_addr);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}

	} else {
		print_out( print, "Error parsing MAC address %s\n", argv[0]);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_SSID( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int statval = 0;
	qcsapi_SSID current_SSID;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	memset(current_SSID, 0, sizeof(current_SSID));
	if (argc > 0 && strcmp( argv[ 0 ], "NULL" ) == 0)
	  qcsapi_retval = qcsapi_wifi_get_SSID( the_interface, NULL );
	else
	  qcsapi_retval = qcsapi_wifi_get_SSID( the_interface, current_SSID );

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%s\n", current_SSID );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_SSID( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi WiFi set SSID, count is %d\n", argc );
		statval = 1;
	} else {
		char *new_SSID = argv[0];

		qcsapi_retval = qcsapi_wifi_set_SSID(the_interface, new_SSID);
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0)
				print_out( print, "complete\n" );
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_scan_SSID_cfg(const call_qcsapi_bundle *p_calling_bundle,
							int argc, char *argv[])
{
	int qcsapi_retval;
	int i;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	struct qtn_ssid_list ssid_list;
	memset(&ssid_list, 0, sizeof(ssid_list));

	qcsapi_retval = qcsapi_wifi_get_scan_SSID_cfg(the_interface, &ssid_list);
	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	if (ssid_list.cnt > ARRAY_SIZE(ssid_list.ssid_entry)) {
		report_qcsapi_error(p_calling_bundle, -E2BIG);
		return 1;
	}

	for (i = 0; i < ssid_list.cnt; i++)
		print_out(print, "   %s\n", ssid_list.ssid_entry[i].ssid);

	return 0;
}

static int
call_qcsapi_wifi_set_scan_SSID_cfg(const call_qcsapi_bundle *p_calling_bundle,
					int argc, char *argv[])
{
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	ieee80211_scan_cfg cfg_flag;
	char *new_SSID;
	size_t ssid_len;

	if (argc == 2 && !strcmp(argv[0], "add")) {
		cfg_flag = IEEE80211_SSID_OP_SCAN_ADD;
		new_SSID = argv[1];
	} else if (argc == 2 && !strcmp(argv[0], "remove")) {
		cfg_flag = IEEE80211_SSID_OP_SCAN_REMOVE;
		new_SSID = argv[1];
	} else if (argc == 1 && !strcmp(argv[0], "clear")) {
		cfg_flag = IEEE80211_SSID_OP_SCAN_CLEAR;
		new_SSID = "EmptySSID";
	} else {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> { add | remove | clear } <SSID>\n");
		return 1;
	}

	ssid_len = strnlen( new_SSID, IW_ESSID_MAX_SIZE + 1 );
	if (ssid_len > IW_ESSID_MAX_SIZE || ssid_len < 1) {
		print_err( print, "Error: not supported SSID length\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_scan_SSID_cfg(the_interface, new_SSID, cfg_flag);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out( print, "complete\n" );
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_get_channel( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			 statval = 0;
	qcsapi_unsigned_int	 channel_value, *p_channel_value = NULL;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_channel_value = &channel_value;
	qcsapi_retval = qcsapi_wifi_get_channel( the_interface, p_channel_value );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%d\n", channel_value );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_channel(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int retval;
	uint32_t chan;
	const char *the_interface = p_calling_bundle->caller_interface;

	retval = qcsapi_util_str_to_uint32(argv[0], &chan);
	if (retval >= 0)
		retval = qcsapi_wifi_set_channel(the_interface, (qcsapi_unsigned_int) chan);

	return qcsapi_report_complete(p_calling_bundle, retval);
}

static int
call_qcsapi_wifi_get_current_band( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			statval = 0;
	qcsapi_unsigned_int	band_value, *p_band_value = NULL;
	int			qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
		p_band_value = &band_value;
	qcsapi_retval = qcsapi_wifi_get_current_band( the_interface, p_band_value );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
				if (band_value == qcsapi_band_2_4ghz)
					print_out( print, "2.4ghz\n");
				else if (band_value == qcsapi_band_5ghz)
					print_out( print, "5ghz\n");
				else
					print_out( print, "unknown band\n");
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_channel_and_bw(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	struct qcsapi_data_32bytes chan_bw;
	int			qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	memset(&chan_bw, 0, sizeof(struct qcsapi_data_32bytes));
	qcsapi_retval = qcsapi_wifi_get_channel_and_bw(the_interface, &chan_bw);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%s\n", (char *)chan_bw.data);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
	}

	return qcsapi_retval;
}

static int
call_qcsapi_wifi_set_channel_and_bw(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	int32_t chan;
	int32_t bw;
	int			qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;

	if (argc < 2) {
		qcsapi_report_usage(p_calling_bundle,
				"Not enough parameters, format is <chan> <bw>\n");
		return -1;
	}

	if (local_atoi32_verify_numeric_range(argv[0], &chan, print,
			QCSAPI_MIN_CHANNEL, QCSAPI_MAX_CHANNEL) < 0)
		return -1;

	if (local_atoi32_verify_numeric_range(argv[1], &bw, print,
			qcsapi_bw_20MHz, qcsapi_bw_80MHz) < 0)
		return -1;

	qcsapi_retval = qcsapi_wifi_set_channel_and_bw(the_interface, chan, bw);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
	}

	return qcsapi_retval;
}

static int
call_qcsapi_wifi_set_wea_cac_en(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	 en_value;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;

	if ((local_atou32_verify_numeric_range(argv[0], &en_value, print, 0, 1)) < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_wea_cac_en(the_interface, en_value);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_auto_channel( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int		 statval = 0;
	int		 qcsapi_retval;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	const char	*the_interface = p_calling_bundle->caller_interface;
	char		 channel_value_str[QCSAPI_MAX_PARAMETER_VALUE_LEN] = {0};
	qcsapi_unsigned_int current_channel;

	qcsapi_retval = qcsapi_config_get_parameter(the_interface,
						    "channel",
						    channel_value_str,
						    sizeof(channel_value_str));

	if (qcsapi_retval >= 0)
	{
		sscanf(channel_value_str, "%u", &current_channel);

		if (verbose_flag >= 0) {
			print_out( print, "%s\n", current_channel==0 ? "enabled" : "disabled" );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_dfs_s_radio_chan_off(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	uint32_t i;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;
	struct qcsapi_data_32bytes chans;

	memset(&chans, 0, sizeof(chans));

	if (argc != 0) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface>");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_get_dfs_s_radio_chan_off(the_interface, &chans);

	if (qcsapi_retval >= 0) {
		for (i = 1; i < IEEE80211_CHAN_MAX; i++) {
			if (isset(chans.data, i))
				print_out(print, "%d ", i);
		}
		print_out(print, "\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_auto_channel( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int		 statval = 0;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int current_channel;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	char		 channel_value_str[QCSAPI_MAX_PARAMETER_VALUE_LEN] = {0};
	char		*param = argv[0];

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi WiFi set auto channel,"
				" count is %d\n", argc );
		statval = 1;
		return( statval );
	}

	qcsapi_retval = qcsapi_config_get_parameter(the_interface,
						    "channel",
						    channel_value_str,
						    sizeof(channel_value_str));

	if (qcsapi_retval >= 0) {
		sscanf( channel_value_str, "%u", &current_channel );
	}

	if (qcsapi_retval >= 0 && strncmp( param, "enable", strlen(param) ) == 0) {
		if (current_channel > 0) {

			qcsapi_retval = qcsapi_config_update_parameter( the_interface, "channel", "0" );
			if (qcsapi_retval >= 0) {
				qcsapi_retval = qcsapi_wifi_set_channel( the_interface, 0 );
			}
		}
	} else if (qcsapi_retval >= 0 && strncmp( param, "disable", strlen(param) ) == 0) {
		if (current_channel == 0) {

			qcsapi_retval = qcsapi_wifi_get_channel( the_interface, &current_channel );
			if (qcsapi_retval >= 0) {
				sprintf( channel_value_str, "%u", current_channel );
				qcsapi_retval = qcsapi_config_update_parameter( the_interface,
										"channel",
										channel_value_str );
			}
		}
	} else if (qcsapi_retval >= 0) {
		qcsapi_retval = -qcsapi_parameter_not_found;
	}

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n" );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_dfs_s_radio_chan_off( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int channel_value;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	uint32_t disable = 1;

	if (argc != 2) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <channel> <0 | 1>");
		return 1;
	}

	if (local_atou32_verify_numeric_range(argv[0], &channel_value, print, QCSAPI_MIN_CHANNEL, QCSAPI_MAX_CHANNEL) < 0)
		return 1;

	if (local_atou32_verify_numeric_range(argv[1], &disable, print, 0, 1) < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_dfs_s_radio_chan_off(the_interface,
				channel_value, disable);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_chan_pri_inactive(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	int i;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;
	struct ieee80211_inactive_chanlist the_list_channels;

	COMPILE_TIME_ASSERT(sizeof(struct qcsapi_data_256bytes) >= sizeof(struct ieee80211_inactive_chanlist));

	memset(&the_list_channels, 0, sizeof(the_list_channels));

	if (argc != 0) {
		print_out(print, "call_qcsapi get_chan_pri_inactive wifi0\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_get_chan_pri_inactive(the_interface, (struct qcsapi_data_256bytes *)&the_list_channels);

	if (qcsapi_retval >= 0) {
		for (i = 1; i < IEEE80211_CHAN_MAX; i++) {
			if (the_list_channels.channels[i] & CHAN_PRI_INACTIVE_CFG_USER_OVERRIDE) {
				print_out(print, "%d%s,", i,
					(the_list_channels.channels[i] & CHAN_PRI_INACTIVE_CFG_AUTOCHAN_ONLY) ?
						"(auto)" : "");
			}
		}
		print_out(print, "\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_chan_pri_inactive(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int arg_retval;
	int qcsapi_retval;
	uint8_t inactive = 1;
	uint32_t channel_value;
	uint32_t flags = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;
	const char *usage = "wifi0 <channel> <1 (inactive) | 0 (active)> [autochan]";

	arg_retval = local_atou32_verify_numeric_range(argv[0], &channel_value, print,
					QCSAPI_MIN_CHANNEL, QCSAPI_MAX_CHANNEL);
	if (arg_retval < 0) {
		qcsapi_report_usage(p_calling_bundle, usage);
		report_qcsapi_error(p_calling_bundle, arg_retval);
		return 1;
	}

	if (argc >= 2) {
		if (local_verify_enable_or_disable(argv[1], &inactive, print) < 0)
			return 1;
	}

	if (argc >= 3) {
		if (strcasecmp(argv[2], "autochan") != 0) {
			qcsapi_report_usage(p_calling_bundle, usage);
			return 1;
		}

		flags = QCSAPI_CHAN_PRI_INACTIVE_AUTOCHAN;
	}

	qcsapi_retval = qcsapi_wifi_set_chan_pri_inactive_ext(the_interface,
				channel_value, inactive, flags);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_wifi_set_chan_disabled(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int retval;
	uint32_t listlen = 0;
	uint8_t control_flag = 0;
	struct qcsapi_data_256bytes chan_list;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;
	const char *usage = "<WiFi interface> <channel list> {0 (enable) | 1 (disable)}";

	if (argc != 2) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return 1;
	}

	if (local_verify_enable_or_disable(argv[1], &control_flag, print) < 0)
		return 1;

	memset(&chan_list, 0, sizeof(chan_list));
	retval = local_string_to_list(argv[0], chan_list.data, &listlen);

	if (retval >= 0)
		retval = qcsapi_wifi_chan_control(the_interface, &chan_list, listlen, control_flag);

	return qcsapi_report_complete(p_calling_bundle, retval);
}

static void
dump_disabled_chanlist(qcsapi_output *print, uint8_t *data, uint8_t cnt)
{
	int loop;

	if (cnt > 0) {
		print_out(print, "%d", data[0]);
		for (loop = 1; loop < cnt; loop++) {
			print_out(print, ",%d", data[loop]);
		}
		print_out(print, "\n");
	}
}

static int
call_qcsapi_wifi_get_chan_disabled( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	struct qcsapi_data_256bytes chan_list;
	uint8_t cnt = 0;

	qcsapi_retval = qcsapi_wifi_get_chan_disabled(the_interface, &chan_list, &cnt);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			dump_disabled_chanlist(print, chan_list.data, cnt);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static void
dump_usable_chanlist(qcsapi_output *print, uint8_t *data)
{
	int loop;

	for (loop = 1; loop < IEEE80211_CHAN_MAX; loop++) {
		if (isset(data, loop))
			print_out(print, "%d,", loop);
	}
	print_out(print, "\n");
}

static int
call_qcsapi_wifi_get_chan_usable(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int			 statval = 0;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	struct qcsapi_data_32bytes chan_list = {{0}};

	COMPILE_TIME_ASSERT(sizeof(chan_list) >= IEEE80211_CHAN_MAX / NBBY);

	qcsapi_retval = qcsapi_wifi_get_chan_usable(the_interface, &chan_list);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			dump_usable_chanlist(print, chan_list.data);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_standard( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	char		 ieee_standard[ 16 ], *p_standard = NULL;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_standard = &ieee_standard[ 0 ];
	qcsapi_retval = qcsapi_wifi_get_IEEE_802_11_standard( the_interface, p_standard );

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%s\n", &ieee_standard[ 0 ] );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_dtim(call_qcsapi_bundle * p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	qcsapi_unsigned_int dtim;
	qcsapi_unsigned_int *p_dtim = NULL;
	const char *interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp(argv[0], "NULL") != 0)
		p_dtim = &dtim;

	qcsapi_retval = qcsapi_wifi_get_dtim(interface, p_dtim);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%d\n", dtim);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_dtim(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	uint32_t dtim;
	int retval;
	const char *interface = p_calling_bundle->caller_interface;

	retval = qcsapi_util_str_to_uint32(argv[0], &dtim);

	if (retval >= 0)
		retval = qcsapi_wifi_set_dtim(interface, (qcsapi_unsigned_int) dtim);

	return qcsapi_report_complete(p_calling_bundle, retval);
}

static int
call_qcsapi_wifi_get_assoc_limit(call_qcsapi_bundle * p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	qcsapi_unsigned_int assoc_limit;
	qcsapi_unsigned_int *p_assoc_limit = NULL;
	const char *interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp(argv[0], "NULL") != 0)
		p_assoc_limit = &assoc_limit;

	qcsapi_retval = qcsapi_wifi_get_assoc_limit(interface, p_assoc_limit);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%d\n", assoc_limit);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_assoc_limit(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int retval;
	uint32_t assoc_limit;
	const char *interface = p_calling_bundle->caller_interface;

	retval = qcsapi_util_str_to_uint32(argv[0], &assoc_limit);

	if (retval >= 0)
		retval = qcsapi_wifi_set_assoc_limit(interface,	(qcsapi_unsigned_int) assoc_limit);

	return qcsapi_report_complete(p_calling_bundle, retval);
}

static int
call_qcsapi_wifi_get_bss_assoc_limit(call_qcsapi_bundle * p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval;
	qcsapi_unsigned_int assoc_limit;
	qcsapi_unsigned_int group;

	if (argc < 1) {
		print_err(print, "Not enough parameters in call qcsapi get bss_assoc_limit,"
									" count is %d\n", argc);
		return 1;
	}

	if (local_str_to_uint32(argv[0], &group, print, "group") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_get_bss_assoc_limit(group, &assoc_limit);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "group assoc_limit %d\n", assoc_limit);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_set_bss_assoc_limit(call_qcsapi_bundle * p_calling_bundle,
							int argc, char *argv[])
{
	qcsapi_unsigned_int limit;
	qcsapi_unsigned_int group;
	int qcsapi_retval;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err(print, "Not enough parameters in call qcsapi set bss_assoc_limit,"
									" count is %d\n", argc);
		return 1;
	}

	if (local_str_to_uint32(argv[0], &group, print, "group") < 0)
		return 1;

	if (local_str_to_uint32(argv[1], &limit, print, "limit") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_bss_assoc_limit(group, limit);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_set_SSID_group_id(call_qcsapi_bundle * p_calling_bundle, int argc, char *argv[])
{
	qcsapi_unsigned_int group;
	int qcsapi_retval;
	const char *interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err(print, "Not enough parameters in call qcsapi WiFi set SSID_group_id,"
									" count is %d\n", argc);
		return 1;
	}

	if (local_str_to_uint32(argv[0], &group, print, "group"))
		return 1;

	qcsapi_retval = qcsapi_wifi_set_SSID_group_id(interface, group);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_get_SSID_group_id(call_qcsapi_bundle * p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	qcsapi_unsigned_int group;
	qcsapi_unsigned_int *p_group = &group;
	const char *interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_SSID_group_id(interface, p_group);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "group_id %d\n", group);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_set_SSID_assoc_reserve(call_qcsapi_bundle * p_calling_bundle,
							int argc, char *argv[])
{
	qcsapi_unsigned_int group;
	qcsapi_unsigned_int value;
	int qcsapi_retval;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err(print, "Not enough parameters in call qcsapi set_SSID_assoc_reserve,"
									" count is %d\n", argc);
		return 1;
	}

	if (local_str_to_uint32(argv[0], &group, print, "group") < 0)
		return 1;

	if (local_str_to_uint32(argv[1], &value, print, "value") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_SSID_assoc_reserve(group, value);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_get_SSID_assoc_reserve(call_qcsapi_bundle * p_calling_bundle,
							int argc, char *argv[])
{
	qcsapi_unsigned_int group;
	qcsapi_unsigned_int value;
	int qcsapi_retval;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err(print, "Not enough parameters in call qcsapi get_SSID_assoc_reserve,"
									" count is %d\n", argc);
		return 1;
	}

	if (local_str_to_uint32(argv[0], &group, print, "group") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_get_SSID_assoc_reserve(group, &value);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "group assoc reserved value : %u\n", value);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_interface_get_status( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	char		 interface_status[ 16 ], *p_status = NULL;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_status = &interface_status[ 0 ];
	qcsapi_retval = qcsapi_interface_get_status( the_interface, p_status );

	if (qcsapi_retval >= 0)
	{
		print_out( print, "%s\n", &interface_status[ 0 ] );
	}
	else
	{
		if (verbose_flag >= 0)
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		}

		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_interface_set_ip4( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int     statval = 0;
	uint32_t        if_param_val;
	uint32_t        if_param_val_ne;
	int              qcsapi_retval;
	char            *if_param = NULL;
	const char      *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output   *print = p_calling_bundle->caller_output;
	if (argc < 2) {
		print_err( print, "Not enough parameters in call qcsapi set_ip\n" );
		print_err( print,
			"Usage: call_qcsapi set_ip <interface> <ipaddr | netmask> <ip_val | netmask_val> \n"
			);
		statval = 1;
	} else {
		if (strcmp(argv[0], "NULL") != 0)
			if_param = argv[ 0 ];

		if (inet_pton(AF_INET, argv[1], &if_param_val) != 1) {
			print_err(print, "invalid IPv4 argument %s\n", argv[1]);
			return -EINVAL;
		}
		if_param_val_ne = htonl(if_param_val);

		qcsapi_retval = qcsapi_interface_set_ip4(the_interface, if_param, if_param_val_ne);

		if (qcsapi_retval >= 0)
		{
			print_out(print, "complete\n");
		}
		else
		{
			if (verbose_flag >= 0)
			{
				report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			}
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_interface_get_ip4( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int     statval = 0;
	string_64       if_param_val;
	char            *p_if_param_val = &if_param_val[ 0 ];
	int              qcsapi_retval;
	char		*if_param = NULL;
	const char      *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output   *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		if_param = argv[0];
	}

	qcsapi_retval = qcsapi_interface_get_ip4(the_interface, if_param, p_if_param_val);

	if (qcsapi_retval >= 0)
	{
		print_out(print, "%s\n", p_if_param_val);
	}
	else
	{
		if (verbose_flag >= 0)
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		}
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_interface_set_mtu(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	const char *the_interface = p_calling_bundle->caller_interface;
	int retval;
	uint32_t mtu;

	if (qcsapi_util_str_to_uint32(argv[0], &mtu) < 0) {
		qcsapi_report_usage(p_calling_bundle, "<interface> <mtu>");
		return 1;
	}

	retval = qcsapi_interface_set_mtu(the_interface, mtu);

	return qcsapi_report_complete(p_calling_bundle, retval);
}

static int
call_qcsapi_interface_get_mtu(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int retval;
	uint32_t mtu;

	if (argc != 0) {
		qcsapi_report_usage(p_calling_bundle, "<interface>");
		return 1;
	}

	retval = qcsapi_interface_get_mtu(the_interface, &mtu);
	if (retval < 0) {
		report_qcsapi_error(p_calling_bundle, retval);
		return 1;
	}

	print_out(print, "%u\n", mtu);

	return 0;
}

static int
call_qcsapi_set_ip_route(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	qcsapi_ip_route_flags flags = qcsapi_ip_route_flag_none;
	const char *the_interface = p_calling_bundle->caller_interface;
	char *ipaddr_str = NULL;
	uint32_t ipaddr;
	uint32_t netmask;
	const char usage[] = "<ifname> { add | del } [default] <ipaddr>[/<netmask>]";

	if (argc < 2) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return 1;
	}

	if (strcmp(argv[1], "default") == 0) {
		if (argc < 3) {
			qcsapi_report_usage(p_calling_bundle, usage);
			return 1;
		}
		flags = qcsapi_ip_route_flag_default_gw;
		ipaddr_str = argv[2];
	} else {
		ipaddr_str = argv[1];
	}

	qcsapi_retval = local_parse_ip_and_netmask(p_calling_bundle, ipaddr_str, &ipaddr, &netmask);
	if (qcsapi_retval >= 0)
		qcsapi_retval = qcsapi_set_ip_route(the_interface, argv[0], ipaddr, netmask, flags, 0);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_get_ip_route( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int             qcsapi_retval;
	string_4096	route_buf = {0};
	qcsapi_output   *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_get_ip_route(route_buf, sizeof(route_buf));

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%s\n", route_buf);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_set_ip_dns(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;

	if (argc < 2) {
		qcsapi_report_usage(p_calling_bundle, "{ add | del } <ipaddr>\n");
		return 1;
	}

	qcsapi_retval = qcsapi_set_ip_dns(argv[0], argv[1]);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_get_ip_dns(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int             qcsapi_retval;
	string_4096	dns_buf = {0};
	qcsapi_output   *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_get_ip_dns(dns_buf, sizeof(dns_buf));

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%s", dns_buf);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_get_list_channels( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	static string_1024 chans = {0};
	int value = 0;
	const int *ptr;

	if (argc > 0 && argv[0]) {
		retval = qcsapi_util_str_to_int32(argv[0], &value);

		if (retval < 0) {
			qcsapi_report_usage(p_calling_bundle, "<interface> [ <bandwidth> ]\n");
			return 1;
		}
	}

	ptr = &value;
	retval = qcsapi_wifi_get_chan_list_for_bw(the_interface, chans, *ptr);

	if (retval < 0) {
		report_qcsapi_error(p_calling_bundle, retval);
		return 1;
	}

	print_out(print, "%s\n", chans);

	return 0;
}

static int
call_qcsapi_wifi_get_supp_chans( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			ival;
	int			statval = 0;
	char			*p_list_channels = NULL;
	int			qcsapi_retval = 0;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	static string_1024	the_list_channels;
	qcsapi_mac_addr		mac_address;

	if (argc < 1) {
		qcsapi_retval = -EFAULT;
	} else {
		p_list_channels = &the_list_channels[0];
		memset(p_list_channels, 0, sizeof(the_list_channels));
	}
	if (qcsapi_retval >= 0) {
		ival = parse_mac_addr(argv[0], mac_address);
		if (ival < 0) {
			print_out( print, "Error parsing MAC address %s\n", argv[ 0 ]);
			qcsapi_retval = -EFAULT;
		} else {
			qcsapi_retval = qcsapi_wifi_get_supp_chans(the_interface,
					mac_address, p_list_channels);
		}
	}

	if (qcsapi_retval >= 0) {
		print_out(print, "%s\n", &the_list_channels[0]);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_mode_switch( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	uint8_t			 wifi_mode, *p_wifi_mode = NULL;
	int			 qcsapi_retval;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_wifi_mode = &wifi_mode;
	qcsapi_retval = qcsapi_wifi_get_mode_switch( p_wifi_mode );

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%x\n", wifi_mode );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_option( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	int			 wifi_option, *p_wifi_option = NULL;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_option_type	 the_option = p_calling_bundle->caller_generic_parameter.parameter_type.option;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_wifi_option = &wifi_option;
	qcsapi_retval = qcsapi_wifi_get_option( the_interface, the_option, p_wifi_option );

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			if (wifi_option == 0)
			  print_out( print, "FALSE\n" );
			else
			  print_out( print, "TRUE\n" );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_dpp_parameter(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int i;
	int j;
	int  qcsapi_retval;
	char resp[QCSAPI_DPP_MAX_BUF_SIZE];
	const char *the_interface = p_calling_bundle->caller_interface;
	struct qcsapi_dpp_set_parameters dpp_params;
	enum qcsapi_dpp_cmd_param_type cmd =
		p_calling_bundle->caller_generic_parameter.parameter_type.dpp_param_type;
	const char usage1[] = "<WiFi interface> cfg_get <param1>";
	const char usage2[] = "<WiFi interface> cfg_set <param1> <value1>";
	const char usage3[] =
		"<WiFi interface> <dpp_command> <param1> <value1> ... [<param8> <value8>]";

	memset(&dpp_params, 0, sizeof(dpp_params));

	if (cmd == qcsapi_dpp_cmd_get_config) {
		if (argc != 1) {
			qcsapi_report_usage(p_calling_bundle, usage1);
			qcsapi_report_usage(p_calling_bundle, usage2);
			qcsapi_report_usage(p_calling_bundle, usage3);
			return 1;
		}
		strncpy(dpp_params.param[0].key, argv[0], sizeof(dpp_params.param[0].key) - 1);
	} else {
		if (argc < 2 || argc > (2 * ARRAY_SIZE(dpp_params.param)) || !!(argc % 2)) {
			qcsapi_report_usage(p_calling_bundle, usage1);
			qcsapi_report_usage(p_calling_bundle, usage2);
			qcsapi_report_usage(p_calling_bundle, usage3);
			return 1;
		}

		for (i = 0, j = 0; i < ARRAY_SIZE(dpp_params.param) && j < argc; i++, j += 2) {
			strncpy(dpp_params.param[i].key, argv[j],
				sizeof(dpp_params.param[i].key) - 1);
			strncpy(dpp_params.param[i].value, argv[j + 1],
				sizeof(dpp_params.param[i].value) - 1);
		}
	}

	qcsapi_retval = qcsapi_wifi_dpp_parameter(the_interface, cmd, &dpp_params,
							resp, sizeof(resp));

	/* Successful set/dpp_command response */
	if (qcsapi_retval >= 0 && (strcasecmp(resp, "OK") == 0))
		snprintf(resp, sizeof(resp), "%s", "complete");

	return qcsapi_report_str_or_error(p_calling_bundle, qcsapi_retval, resp);
}

static int
call_qcsapi_wifi_get_parameter(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int			 statval = 0;
	int			 qcsapi_retval;
	int			 value;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_wifi_param_type	type = p_calling_bundle->caller_generic_parameter.parameter_type.wifi_param_type;

	if (argc > 0) {
		qcsapi_report_usage(p_calling_bundle, "<ifname> <parameter name>");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_get_parameter(the_interface, type, &value);

	if (qcsapi_retval >= 0) {
		print_out(print, "%d\n", value);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_parameter(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int			 statval = 0;
	int			 qcsapi_retval;
	int			 value;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_wifi_param_type	type = p_calling_bundle->caller_generic_parameter.parameter_type.wifi_param_type;

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle, "<ifname> <parameter name> <parameter value>");
		return 1;
	}

	qcsapi_retval = sscanf(argv[0], "%i", &value);

	if (qcsapi_retval <= 0) {
		print_err(print, "Invalid parameter - must be a signed integer\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_parameter(the_interface, type, value);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

# define BUF_MAX_LEN	40

static int
call_qcsapi_get_board_parameter(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int                             statval = 0;
	int                             qcsapi_retval = 0;
	qcsapi_output                   *print = p_calling_bundle->caller_output;
	qcsapi_board_parameter_type     the_boardparam = p_calling_bundle->caller_generic_parameter.parameter_type.board_param;
	string_64                       p_buffer;

	if (argc > 0 && (strcmp(argv[ 0 ], "NULL") == 0))
	{
		qcsapi_retval = -EFAULT;
	}
	else
	{
		memset(p_buffer, 0, sizeof(p_buffer));
		qcsapi_retval = qcsapi_get_board_parameter(the_boardparam, p_buffer);
	}

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out(print, "%s\n", p_buffer);
		}
	}
	else
	{
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return(statval);
}

static int
call_qcsapi_wifi_get_noise( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	int		 qcsapi_retval;
	int		 current_noise, *p_noise = NULL;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0) {
		p_noise = &current_noise;
	}

	qcsapi_retval = qcsapi_wifi_get_noise( the_interface, p_noise );
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%d\n", current_noise );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_rssi_by_chain(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int retval;
	int32_t rf_chain;
	int current_rssi = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <RF chain>");
		return 1;
	}

	retval = qcsapi_util_str_to_int32(argv[0], &rf_chain);
	if (retval >= 0)
		retval = qcsapi_wifi_get_rssi_by_chain(the_interface, (int) rf_chain, &current_rssi);

	if (retval < 0) {
		report_qcsapi_error(p_calling_bundle, retval);
		return 1;
	}

	print_out(print, "%d\n", current_rssi);

	return 0;
}

static int
call_qcsapi_wifi_get_avg_snr( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int		 statval = 0;
	int		 qcsapi_retval;
	int		 current_snr, *p_snr = NULL;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0) {
		p_snr = &current_snr;
	}

	qcsapi_retval = qcsapi_wifi_get_avg_snr( the_interface, p_snr );
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%d\n", current_snr );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_option( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	int			 wifi_option;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_option_type	 the_option = p_calling_bundle->caller_generic_parameter.parameter_type.option;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi WiFi set option, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		if ((strcasecmp(argv[0], "TRUE") == 0) || (strcasecmp(argv[0], "YES") == 0) ||
				(strcmp(argv[0], "1") == 0))
			wifi_option = 1;
		else if ((strcasecmp(argv[0], "FALSE") == 0) || (strcasecmp(argv[0], "NO") == 0) ||
				(strcmp(argv[0], "0") == 0))
			wifi_option = 0;
		else {
			print_err( print, "Invalid input arguments\n" );
			return 1;
		}

		qcsapi_retval = qcsapi_wifi_set_option( the_interface, the_option, wifi_option );
		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_rates( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	char			*p_rates = NULL;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_rate_type	 the_rates_type = p_calling_bundle->caller_generic_parameter.parameter_type.typeof_rates;
	static string_2048	the_rates;
/*
 * Prefer a non-reentrant program to allocating 2049 bytes on the stack.
 */
	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0) {
		p_rates = &the_rates[ 0 ];
	}

	qcsapi_retval = qcsapi_wifi_get_rates( the_interface, the_rates_type, p_rates );

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%s\n", the_rates );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return (statval);
}

/**
 * validate_rates return 1 on success and 0 on failure
 */
static int
validate_rates(char *input_rate[], int num_rates)
{
        int rates[] = {2,4,11,12,18,22,24,36,48,72,96,108};
        int found = 0, i, j, rate;

        for (i = 0; i < num_rates; i++) {
		if (qcsapi_util_str_to_int32(input_rate[i], &rate) < 0)
			break;

                found = 0;
                for (j = 0; j < ARRAY_SIZE(rates); j++) {
                        if (rate == rates[j]) {
                                found = 1;
                                break;
                        }

                }

                if (!found) {
			break;
		}
        }
        return found;
}

static int
call_qcsapi_wifi_set_rates( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_rate_type	 the_rates_type = p_calling_bundle->caller_generic_parameter.parameter_type.typeof_rates;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi WiFi set rates, count is %d\n", argc );
		statval = 1;
	} else {
		char	*p_rates = argv[ 0 ];

		if (!validate_rates(argv, argc)) {
			print_err (print, "Invalid input rates, valid rates are 2,4,11,12,18,22,24,36,48,72,96,108 in 500Kbps units\n");
			return 1;
		}

		qcsapi_retval = qcsapi_wifi_set_rates( the_interface, the_rates_type, p_rates, argc);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return (statval);
}

static int
call_qcsapi_wifi_get_max_bitrate( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			statval = 0;
	int			qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	char max_bitrate_str[QCSAPI_MAX_BITRATE_STR_MIN_LEN + 1] = {0};

	qcsapi_retval = qcsapi_get_max_bitrate(the_interface, max_bitrate_str, QCSAPI_MAX_BITRATE_STR_MIN_LEN);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%s\n", &max_bitrate_str[ 0 ] );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_max_bitrate( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			statval = 0;
	int			qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi wifi set max bitrate, count is %d\n", argc );
		statval = 1;
	}

	qcsapi_retval = qcsapi_set_max_bitrate(the_interface, argv[0]);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_beacon_type( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	char		 beacon_type[ 16 ], *p_beacon = NULL;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_beacon = &beacon_type[ 0 ];
	qcsapi_retval = qcsapi_wifi_get_beacon_type( the_interface, p_beacon );

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%s\n", &beacon_type[ 0 ] );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_beacon_type( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi WiFi set beacon, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		char		 *p_beacon = argv[ 0 ];

	  /* Beacon type will not be NULL ... */

		if (strcmp( argv[ 0 ], "NULL" ) == 0)
		  p_beacon = NULL;
		qcsapi_retval = qcsapi_wifi_set_beacon_type( the_interface, p_beacon );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_beacon_interval( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_unsigned_int	bintval_value, *p_bintval_value = NULL;
	int	qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_bintval_value = &bintval_value;

	qcsapi_output	*print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_beacon_interval(the_interface,p_bintval_value);

	if( qcsapi_retval>=0 ){
		print_out( print,"%d\n",bintval_value );
	}else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_beacon_interval(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	uint32_t bcn_int;
	int qcsapi_retval;
	const char *interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (local_str_to_uint32(argv[0], &bcn_int, print, "beacon interval value") < 0)
		return 1;

	if ((bcn_int > BEACON_INTERVAL_WARNING_LOWER_LIMIT) &&
			(bcn_int < BEACON_INTERVAL_WARNING_UPPER_LIMIT)) {
		print_out(print, "Warning, beacon interval less than 100ms may cause network "
			"performance degradation\n");
	}

	qcsapi_retval = qcsapi_wifi_set_beacon_interval(interface, (qcsapi_unsigned_int) bcn_int);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int call_qcsapi_wifi_get_list_regulatory_regions(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	string_2048 supported_regions;
	int qcsapi_retval;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp(argv[0], "NULL") != 0) {
		qcsapi_retval = qcsapi_regulatory_get_list_regulatory_regions_ext(
					supported_regions);

		if (qcsapi_retval == -qcsapi_region_database_not_found)
			qcsapi_retval = qcsapi_wifi_get_list_regulatory_regions(
						supported_regions);

	} else {
		qcsapi_retval = qcsapi_regulatory_get_list_regulatory_regions_ext(
					NULL);

		if (qcsapi_retval == -qcsapi_region_database_not_found)
			qcsapi_retval = qcsapi_wifi_get_list_regulatory_regions(NULL);
	}

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	print_out(print, "%s\n", supported_regions);

	return 0;
}

static int
call_qcsapi_wifi_get_regulatory_tx_power(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	uint32_t the_channel;
	int tx_power = 0;
	const char *regulatory_region = NULL;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;

	if (argc != 2) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <channel> <regulatory region>");
		return 1;
	}

	if (local_str_to_uint32(argv[0], &the_channel, print, "channel number") < 0)
		return 1;

	regulatory_region = argv[1];

	qcsapi_retval = qcsapi_regulatory_get_regulatory_tx_power(
			the_interface,
			(qcsapi_unsigned_int) the_channel,
			regulatory_region,
			&tx_power
			);

	if (qcsapi_retval == -qcsapi_region_database_not_found) {
		qcsapi_retval = qcsapi_wifi_get_regulatory_tx_power(
				the_interface,
				(qcsapi_unsigned_int) the_channel,
				regulatory_region,
				&tx_power
				);
	}

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	print_out(print, "%d\n", tx_power);

	return 0;
}

static int
call_qcsapi_wifi_get_configured_tx_power(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *iface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int channel;
	const char *region;
	qcsapi_unsigned_int the_bw = 0;
	qcsapi_unsigned_int bf_on;
	qcsapi_unsigned_int number_ss;
	int retval;
	int tx_power = 0;

	const char *msg_usage_mandatory_params =
			"Not enough parameters in call qcsapi get_configured_tx_power\n"
			"Usage: call_qcsapi get_configured_tx_power"
			" <WiFi interface> <channel> <regulatory region>";

	if (argc < 2) {
		print_err(print, "%s [bandwidth] [bf_on] [number_ss]\n",
				msg_usage_mandatory_params);

		statval = 1;
		goto finish;
	}

	if (local_str_to_uint32(argv[0], &channel, print, "channel number") < 0)
		return 1;

	region = argv[1];

	if (argc < 3) {
		retval = qcsapi_wifi_get_bw(iface, &the_bw);

		/* Call to get the BW might fail if the interface is wrong */
		if (retval < 0) {
			if ((retval == -ENODEV) || (retval == -EOPNOTSUPP)) {
				print_out(print, "Interface %s does not exist"
						"or not a Wireless Extension interface\n",
						iface);
			} else
				report_qcsapi_error(p_calling_bundle, retval);

			statval = 1;
			goto finish;
		}
	} else {
		if (local_str_to_uint32(argv[2], &the_bw, print, "bandwidth value") < 0)
			return 1;
	}

	if (argc < 4) {
		/* additional parameters are not specified: beamforming off, one spatial stream */
		bf_on = 0;
		number_ss = 1;
	} else if (argc >= 5) {
		if (local_str_to_uint32(argv[3], &bf_on, print, "beamforming on/off value") < 0)
			return 1;

		if (local_str_to_uint32(argv[4], &number_ss, print, "spatial stream value") < 0)
			return 1;
	} else {
		/* beamforming and spatial stream must be specified */
		print_err(print, "%s <bandwidth> <bf_on> <number_ss>\n",
				msg_usage_mandatory_params);

		statval = 1;
		goto finish;
	}

	retval = qcsapi_regulatory_get_configured_tx_power_ext(
			iface,
			channel,
			region,
			the_bw,
			bf_on,
			number_ss,
			&tx_power);

	if (retval == -qcsapi_region_database_not_found) {
		retval = qcsapi_wifi_get_configured_tx_power(
				iface,
				channel,
				region,
				the_bw,
				&tx_power);
	}

	if (retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%d\n", tx_power);
	} else {
		report_qcsapi_error(p_calling_bundle, retval);
		statval = 1;
	}

finish:

	return statval;
}

static int
call_qcsapi_wifi_set_regulatory_channel( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2)
	{
		print_err( print, "Not enough parameters in call qcsapi set regulatory channel\n" );
		print_err( print,
	   "Usage: call_qcsapi set_regulatory_channel <WiFi interface> <channel> <regulatory region> <TX power offset>\n"
		);
		statval = 1;
	}
	else
	{
		int			 qcsapi_retval;
		const char		*the_interface = p_calling_bundle->caller_interface;
		qcsapi_unsigned_int	 the_channel;
		const char		*regulatory_region = NULL;
		qcsapi_unsigned_int	 tx_power_offset = 0;

		if (local_str_to_uint32(argv[0], &the_channel, print, "channel number") < 0)
			return 1;

		if ((argc >= 3) && (local_str_to_uint32(argv[2], &tx_power_offset, print,
						"tx_power_offset value") < 0))
				return 1;

		if (strcmp( argv[ 1 ], "NULL" ) != 0)
		  regulatory_region = argv[ 1 ];

		qcsapi_retval = qcsapi_regulatory_set_regulatory_channel(
				the_interface,
				the_channel,
				regulatory_region,
				tx_power_offset
			);

		if (qcsapi_retval == -qcsapi_region_database_not_found) {

			qcsapi_retval = qcsapi_wifi_set_regulatory_channel(
				the_interface,
				the_channel,
				regulatory_region,
				tx_power_offset
			);
		}



		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_regulatory_region( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi set regulatory region\n" );
		print_err( print,
	   "Usage: call_qcsapi set_regulatory_region <WiFi interface> <regulatory region>\n"
		);
		statval = 1;
	}
	else
	{
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		const char	*regulatory_region = NULL;

		if (strcmp( argv[ 0 ], "NULL" ) != 0)
		  regulatory_region = argv[ 0 ];

		qcsapi_retval = qcsapi_regulatory_set_regulatory_region(
			the_interface,
			regulatory_region
		);

		if (qcsapi_retval == -EOPNOTSUPP)
			print_out( print, "Not allowed to change regulatory domain at runtime\n" );

		if (qcsapi_retval == -qcsapi_region_database_not_found) {
			qcsapi_retval = qcsapi_wifi_set_regulatory_region(
				the_interface,
				regulatory_region
			);
		}

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_restore_regulatory_tx_power( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;

	qcsapi_retval = qcsapi_regulatory_restore_regulatory_tx_power(the_interface);

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "complete\n" );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_regulatory_region( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;

	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	char		 regulatory_region[6];
	char		*p_regulatory_region = NULL;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0) {
		p_regulatory_region = &regulatory_region[ 0 ];
	}

	qcsapi_retval = qcsapi_wifi_get_regulatory_region( the_interface, p_regulatory_region );

	if (qcsapi_retval >= 0) {
		print_out( print, "%s\n", p_regulatory_region );
	}
	else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_overwrite_country_code( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi overwrite coutnry code\n" );
		print_err( print,
	   "Usage: call_qcsapi overwrite_country_code <WiFi interface> <curr_country_name> <new_country_name>\n"
		);
		statval = 1;
	}
	else
	{
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		const char	*curr_country_name = NULL;
		const char	*new_country_name = NULL;

		if (strcmp( argv[ 0 ], "NULL" ) != 0)
			curr_country_name = argv[0];
		if (strcmp( argv[ 1 ], "NULL" ) != 0)
			new_country_name = argv[1];

		qcsapi_retval = qcsapi_regulatory_overwrite_country_code(
			the_interface,
			curr_country_name,
			new_country_name
		);

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
				print_out( print, "complete\n" );
		} else if (qcsapi_retval == -qcsapi_configuration_error) {
			print_err( print, "Error: can't overwrite country code for provision board\n" );
			statval = 1;
		} else if (qcsapi_retval == -qcsapi_region_not_supported) {
			print_err( print, "Error: current region is not %s\n", curr_country_name);
			statval = 1;
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}


static int
call_qcsapi_wifi_get_list_regulatory_channels( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi get list regulatory channels\n" );
		print_err( print, "Usage: call_qcsapi get_list_regulatory_channels <regulatory region> [bandwidth]\n" );
		statval = 1;
	}
	else
	{
		int			 qcsapi_retval = 0;
		char			*p_list_channels = NULL;
		const char		*regulatory_region = NULL;
		qcsapi_unsigned_int	 the_bw = 0;
		/* Prefer a non-reentrant program to allocating 1025 bytes on the stack. */
		static string_1024	 the_list_channels;

		if (strcmp( argv[ 0 ], "NULL" ) != 0)
		  regulatory_region = argv[ 0 ];

		if (argc < 2)
			qcsapi_retval = qcsapi_wifi_get_bw( "wifi0", &the_bw );
		else
			if (local_str_to_uint32(argv[1], &the_bw, print, "bandwidth value") < 0)
				return 1;

		if (argc < 3 || strcmp( argv[ 2 ], "NULL" ) != 0) {
			p_list_channels = &the_list_channels[ 0 ];
		}


		if (qcsapi_retval >= 0) {
			qcsapi_retval = qcsapi_regulatory_get_list_regulatory_channels( regulatory_region, the_bw, p_list_channels );
		}

		if (qcsapi_retval == -qcsapi_region_database_not_found) {
			qcsapi_retval = qcsapi_wifi_get_list_regulatory_channels(regulatory_region, the_bw, p_list_channels);
		}

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "%s\n", the_list_channels );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_list_regulatory_bands( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi get list regulatory channels\n" );
		print_err( print, "Usage: call_qcsapi get_list_regulatory_channels <regulatory region>\n" );
		statval = 1;

	} else {
		int qcsapi_retval;
		char *p_list_bands = NULL;
		const char *regulatory_region = NULL;

		/* Prefer a non-reentrant program to allocating 1025 bytes on the stack. */
		static string_128 the_list_bands;

		if (strcmp(argv[ 0 ], "NULL") != 0) {
			regulatory_region = argv[0];
		}

		if (argc < 3 || strcmp( argv[2], "NULL") != 0) {
			p_list_bands = &the_list_bands[0];
		}

		qcsapi_retval = qcsapi_regulatory_get_list_regulatory_bands(regulatory_region, p_list_bands);

		if (qcsapi_retval >= 0) {

			if (verbose_flag >= 0) {
				print_out( print, "%s\n", the_list_bands );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_regulatory_db_version( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int	qcsapi_retval;
	int	version = 0;
	int	index = 0;
	int	retval = 0;
	char	ch='v';
	int	*p_qcsapi_retval = &qcsapi_retval;
	const char *format[2] = { "%c%d", "0%c%x" };

	if (argc > 0) {
		if (local_str_to_int32(argv[0], &index, print, "index") < 0)
                        return 1;

		ch='x';
	}

	if (verbose_flag >= 0)
		print_out(print, "Regulatory db version: ");

	do {
		*p_qcsapi_retval = qcsapi_regulatory_get_db_version(&version, index++);
		if (qcsapi_retval == -1 || retval < 0)
			break;

		print_out(print, format[argc > 0], ch, version);

		ch = '.';
		p_qcsapi_retval = &retval;
	} while (argc == 0 && qcsapi_retval >= 0);

	if (qcsapi_retval == -1) {
		print_out(print, "database not available");
	}

	print_out(print, "\n");

	if (qcsapi_retval < 0)
		statval = 1;

	return statval;
}

static int
call_qcsapi_wifi_set_regulatory_tx_power_cap( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		qcsapi_unsigned_int	 capped = 0;
		int			 qcsapi_retval;

		if (local_verify_enable_or_disable(argv[0], (uint8_t *) &capped, print) < 0) {
			print_err(print, "Invalid regulatory cap value\n");
			return 1;
		}

		qcsapi_retval = qcsapi_regulatory_apply_tx_power_cap( capped );
		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_tx_power( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi get TX power\n" );
		print_err( print, "Usage: call_qcsapi get_tx_power <interface> <channel>\n" );
		statval = 1;
	}
	else {
		int			 qcsapi_retval;
		const char		*the_interface = p_calling_bundle->caller_interface;
		qcsapi_unsigned_int	 the_channel = 0;
		int			 the_tx_power = 0;
		int			*p_tx_power = NULL;

		if (local_str_to_uint32(argv[0], &the_channel, print, "channel number") < 0)
			return 1;

		if (argc < 2 || strcmp( argv[ 1 ], "NULL" ) != 0) {
			p_tx_power = &the_tx_power;
		}

		qcsapi_retval = qcsapi_wifi_get_tx_power( the_interface, the_channel, p_tx_power );
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "%d\n", the_tx_power );
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_tx_power(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int	qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int channel = 0;
	int tx_power = 0;

	if (argc < 2) {
		print_err(print, "Not enough parameters in call qcsapi set_tx_power\n");
		return 1;
	}

	if (local_str_to_uint32(argv[0], &channel, print, "channel number") < 0)
		return 1;

	if (local_str_to_int32(argv[1], &tx_power, print, "tx power value") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_tx_power(the_interface, channel, tx_power);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_bw_power( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi get_bw_power\n" );
		print_err( print, "Usage: call_qcsapi get_bw_power <interface> <channel>\n" );
		statval = 1;
	}
	else {
		int			qcsapi_retval;
		const char		*the_interface = p_calling_bundle->caller_interface;
		qcsapi_unsigned_int	the_channel = 0;
		int			power_20M = 0;
		int			power_40M = 0;
		int			power_80M = 0;

		if (local_str_to_uint32(argv[0], &the_channel, print, "channel number") < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_get_bw_power( the_interface, the_channel,
				&power_20M, &power_40M, &power_80M );
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, " pwr_20M  pwr_40M  pwr_80M\n %7d  %7d  %7d\n",
						power_20M, power_40M, power_80M );
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_bw_power(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int	qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int channel;
	int power_20M = 0;
	int power_40M = 0;
	int power_80M = 0;

	if (argc < 2) {
		print_err(print, "Not enough parameters in call qcsapi set_bw_power\n");
		print_err( print, "Usage: call_qcsapi set_bw_power <interface> <channel>"
				" <power_20M> <power_40M> <power_80M>\n" );
		return 1;
	}

	if (local_str_to_uint32(argv[0], &channel, print, "channel number") < 0)
		return 1;

	if (local_str_to_int32(argv[1], &power_20M, print, "power 20m value") < 0)
		return 1;

	if (argc >= 3) {
		if (local_str_to_int32(argv[2], &power_40M, print, "power 40m value") < 0)
			return 1;

		if ((argc >= 4) && (local_str_to_int32(argv[3], &power_80M, print,
						"power 80m value") < 0))
				return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_bw_power(the_interface, channel,
			power_20M, power_40M, power_80M);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_bf_power( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err( print, "Not enough parameters in call qcsapi get_bf_power\n" );
		print_err( print, "Usage: call_qcsapi get_bf_power <interface> <channel> <number_ss>\n" );
		statval = 1;
	}
	else {
		int qcsapi_retval;
		const char *the_interface = p_calling_bundle->caller_interface;
		qcsapi_unsigned_int the_channel;
		int number_ss = 0;
		int power_20M = 0;
		int power_40M = 0;
		int power_80M = 0;

		if (local_str_to_uint32(argv[0], &the_channel, print, "channel number") < 0)
			return 1;

		if (local_str_to_int32(argv[1], &number_ss, print, "spatial stream value") < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_get_bf_power( the_interface, the_channel,
				number_ss, &power_20M, &power_40M, &power_80M );
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, " pwr_20M  pwr_40M  pwr_80M\n %7d  %7d  %7d\n",
						power_20M, power_40M, power_80M );
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_bf_power(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int channel;
	int power_20M = 0;
	int power_40M = 0;
	int power_80M = 0;
	int number_ss = 0;

	if (argc < 3) {
		print_err(print, "Not enough parameters in call qcsapi set_bf_power\n");
		print_err( print, "Usage: call_qcsapi set_bf_power <interface> <channel>"
				" <number_ss> <power_20M> <power_40M> <power_80M>\n" );
		return 1;
	}

	if (local_str_to_uint32(argv[0], &channel, print, "channel number") < 0)
		return 1;

	if (local_str_to_int32(argv[1], &number_ss, print, "spatial stream value") < 0)
		return 1;

	if (local_str_to_int32(argv[2], &power_20M, print, "power 20m value") < 0)
		return 1;

	if (argc >= 4) {
		if (local_str_to_int32(argv[3], &power_40M, print, "power 40m value") < 0)
			return 1;

		if ((argc >= 5) && (local_str_to_int32(argv[4], &power_80M, print,
						"power 80m value") < 0))
				return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_bf_power(the_interface, channel,
			number_ss, power_20M, power_40M, power_80M);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_tx_power_ext( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 3) {
		print_err( print, "Not enough parameters in call_qcsapi get_tx_power_ext\n" );
		print_err( print, "Usage: call_qcsapi get_tx_power_ext <interface> <channel> <bf_on> <number_ss>\n" );
		statval = 1;
	} else {
		int qcsapi_retval;
		const char *the_interface = p_calling_bundle->caller_interface;
		qcsapi_unsigned_int the_channel;
		uint8_t bf_on;
		int number_ss;
		int power_20M = 0;
		int power_40M = 0;
		int power_80M = 0;

		if (local_str_to_uint32(argv[0], &the_channel, print, "channel number") < 0)
			return 1;

		if (local_verify_enable_or_disable(argv[1], &bf_on, print) < 0)
                        return 1;

		if (local_str_to_int32(argv[2], &number_ss, print, "spatial stream value") < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_get_tx_power_ext( the_interface, the_channel,
				bf_on, number_ss, &power_20M, &power_40M, &power_80M );
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, " pwr_20M  pwr_40M  pwr_80M\n %7d  %7d  %7d\n",
						power_20M, power_40M, power_80M );
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_tx_power_ext(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int channel;
	int power_20M = 0;
	int power_40M = 0;
	int power_80M = 0;
	uint8_t bf_on = 0;
	int number_ss = 0;

	if (argc < 4) {
		print_err(print, "Not enough parameters in call_qcsapi set_tx_power_ext\n");
		print_err( print, "Usage: call_qcsapi set_tx_power_ext <interface> <channel>"
				" <bf_on> <number_ss> <power_20M> <power_40M> <power_80M>\n" );
		return 1;
	}

	if (local_str_to_uint32(argv[0], &channel, print, "channel number") < 0)
		return 1;

	if (local_verify_enable_or_disable(argv[1], &bf_on, print) < 0)
		return 1;

	if (local_str_to_int32(argv[2], &number_ss, print, "spatial stream value") < 0)
		return 1;

	if (local_str_to_int32(argv[3], &power_20M, print, "power 20m value") < 0)
                return 1;

	if (argc >= 5) {
		if (local_str_to_int32(argv[4], &power_40M, print, "power 40m value") < 0)
			return 1;

		if ((argc >= 6) && (local_str_to_int32(argv[5], &power_80M, print,
						"power 80m value") < 0))
				return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_tx_power_ext(the_interface, channel, bf_on, number_ss,
					power_20M, power_40M, power_80M);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static unsigned regulatory_chan_txpower_input_parse(char *input_str,
		const unsigned num_bits, unsigned long (*transform_func)(unsigned long input))
{
	char *cur;
	unsigned bitmap = 0;
	uint32_t tmp_val;
	char *saved_p;

	if (!input_str)
		goto out;

	cur = strtok_r(input_str, ",", &saved_p);
	if (!cur)
		goto out;

	if (*cur == '*' && *(cur + 1) == '\0') {
		bitmap |= (1 << num_bits) - 1;
	} else {
		do {
			if (qcsapi_util_str_to_uint32(cur, &tmp_val) < 0) {
				bitmap = 0;
				goto out;
			}

			if (transform_func)
				tmp_val = transform_func((unsigned long) tmp_val);

			if (tmp_val >= num_bits) {
				bitmap = 0;
				goto out;
			}

			bitmap |= (1 << tmp_val);
			cur = strtok_r(NULL, ",", &saved_p);
		} while (cur);
	}
out:
	return bitmap;
}

unsigned long regulatory_chan_txpower_input_nss_to_ssidx(unsigned long input)
{
	return input - 1;
}

unsigned long regulatory_chan_txpower_input_bw_to_bwidx(unsigned long input)
{
	unsigned long ret;

	switch (input) {
	case 20:
		ret = QCSAPI_PWR_BW_20M;
		break;
	case 40:
		ret = QCSAPI_PWR_BW_40M;
		break;
	case 80:
		ret = QCSAPI_PWR_BW_80M;
		break;
	default:
		ret = -1;
		break;
	}

	return ret;
}

static int regulatory_chan_txpower_input_parse_bitmap(char *input, qcsapi_output *print,
		uint8_t *chan, unsigned *ss_map, unsigned *bf_map, unsigned *fem_pri_map,
		unsigned *bw_map)
{
	char *cur;
	uint32_t value;

	cur = strtok(input, ":");
	if (!cur)
		goto error;

	if (local_atou32_verify_numeric_range(cur, &value, print, 0, 255) < 0)
		goto error;

	*chan = value;

	cur = strtok(NULL, ":");
	if (!cur) {
		/* Specifying channel number only equals to specifying <chan:*:*:*:*> */
		*ss_map = (1 << QCSAPI_PWR_IDX_SS_NUM) - 1;
		*bf_map = (1 << QCSAPI_PWR_IDX_BF_NUM) - 1;
		*fem_pri_map = (1 << QCSAPI_PWR_IDX_FEM_PRIPOS_NUM) - 1;
		*bw_map = (1 << QCSAPI_PWR_BW_NUM) - 1;
		return 0;
	}

	*ss_map = regulatory_chan_txpower_input_parse(cur,
			QCSAPI_PWR_IDX_SS_NUM,
			&regulatory_chan_txpower_input_nss_to_ssidx);
	if (!*ss_map) {
		print_err(print, "Bad NSS\n");
		goto error;
	}

	cur = strtok(NULL, ":");
	if (!cur)
		goto error;

	*bf_map = regulatory_chan_txpower_input_parse(cur,
			QCSAPI_PWR_IDX_BF_NUM, NULL);
	if (!*bf_map) {
		print_err(print, "Bad BF\n");
		goto error;
	}

	cur = strtok(NULL, ":");
	if (!cur)
		goto error;

	*fem_pri_map = regulatory_chan_txpower_input_parse(cur,
			QCSAPI_PWR_IDX_FEM_PRIPOS_NUM, NULL);
	if (!*fem_pri_map) {
		print_err(print, "Bad FEM/PRI\n");
		goto error;
	}

	cur = strtok(NULL, ":");
	if (!cur)
		goto error;

	*bw_map = regulatory_chan_txpower_input_parse(cur,
			QCSAPI_PWR_BW_NUM,
			&regulatory_chan_txpower_input_bw_to_bwidx);
	if (!*bw_map) {
		print_err(print, "Bad BW\n");
		goto error;
	}

	cur = strtok(NULL, ":");
	if (cur != NULL && cur[0] != '\0')
		goto error;

	return 0;

error:
	return -1;
}

static int
call_qcsapi_reg_chan_txpower_set(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	int32_t power;
	char *cur;
	unsigned fem_pri_map;
	unsigned bf_map;
	unsigned ss_map;
	unsigned bw_map;
	unsigned fem_pri, bf, ss, bw;
	struct qcsapi_chan_tx_powers_info info;
	qcsapi_chan_powers *pwrs = (qcsapi_chan_powers *)&info.maxpwr;

	if (argc != 2) {
		qcsapi_report_parameter_count(p_calling_bundle, argc);
		goto usage;
	}

	memset(&info, 0, sizeof(info));

	if (regulatory_chan_txpower_input_parse_bitmap(argv[0], print, &info.channel, &ss_map,
			&bf_map, &fem_pri_map, &bw_map))
		goto usage;

	cur = strtok(argv[1], ",");

	for (ss = 0; ss < QCSAPI_PWR_IDX_SS_NUM; ++ss) {
		if (!(ss_map & (1 << ss)))
			continue;

		for (bf = 0; bf < QCSAPI_PWR_IDX_BF_NUM; ++bf) {
			if (!(bf_map & (1 << bf)))
				continue;

			for (fem_pri = 0; fem_pri < QCSAPI_PWR_IDX_FEM_PRIPOS_NUM; ++fem_pri) {
				if (!(fem_pri_map & (1 << fem_pri)))
					continue;

				for (bw = 0; bw < QCSAPI_PWR_BW_NUM; ++bw) {
					if (!(bw_map & (1 << bw)))
						continue;

					if (!cur) {
						print_err(print, "Not enough PWR values\n");
						goto usage;
					}

					if (local_atoi32_verify_numeric_range(cur, &power, print,
								INT8_MIN, INT8_MAX) < 0)
						goto usage;

					cur = strtok(NULL, ",");

					(*pwrs)[fem_pri][bf][ss][bw] = power;
				}
			}
		}
	}

	if (cur) {
		print_err(print, "Too many PWR values\n");
		goto usage;
	}

	qcsapi_retval = qcsapi_regulatory_chan_txpower_set(the_interface, &info,
			QCSAPI_PWR_VALUE_TYPE_ACTIVE);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;

usage:
	qcsapi_report_usage(p_calling_bundle, "<interface> <chan:nss:bf:fem_pri:bw> <power>\n");
	return 1;
}

static int
call_qcsapi_reg_chan_txpower_path_get(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;
	char file_path[ 80 ];
	char *p_file_path = NULL;
	uint32_t path_len;
	int qcsapi_retval;

	if ((argc != 0) || (the_interface == NULL)) {
		qcsapi_report_parameter_count(p_calling_bundle, argc);
		goto usage;
	}

	p_file_path = file_path;
	*p_file_path = 0;
	path_len = (uint32_t) sizeof(file_path);

	qcsapi_retval = qcsapi_regulatory_chan_txpower_path_get(the_interface, p_file_path, path_len);

	if (qcsapi_retval >= 0) {
		print_out(print, "%s\n", p_file_path);
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;

usage:
	qcsapi_report_usage(p_calling_bundle, "\n");
	return 1;
}

static inline void reg_chan_txpower_get_print_header(qcsapi_output *print, unsigned print_map)
{
	unsigned bw;

	print_out(print, "Ch:ss:bf:fp ");

	for (bw = QCSAPI_PWR_BW_80M; print_map; --bw) {
		if (!(print_map & (1 << bw)))
			continue;

		print_map &= ~(1 << bw);
		switch (bw) {
		case QCSAPI_PWR_BW_80M:
			print_out(print, "80M  ");
			break;
		case QCSAPI_PWR_BW_40M:
			print_out(print, "40M  ");
			break;
		case QCSAPI_PWR_BW_20M:
			print_out(print, "20M");
			break;
		}
	}

	print_out(print, "\n");
}

static int
// call_qcsapi_wifi_get_chan_power_table( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
call_qcsapi_reg_chan_txpower_get( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval;
	unsigned arg_idx = 0;
	int print_hdr = 1;
	unsigned fem_pri_map;
	unsigned bf_map;
	unsigned ss_map;
	unsigned bw_map;
	unsigned fem_pri, bf, ss, bw;
	struct qcsapi_chan_tx_powers_info info;
	qcsapi_chan_powers *pwrs = (qcsapi_chan_powers *)&info.maxpwr;
	qcsapi_txpwr_value_type report_type = QCSAPI_PWR_VALUE_TYPE_ACTIVE;

	if (argc < 1) {
		qcsapi_report_parameter_count(p_calling_bundle, argc);
		goto usage;
	}

	while (arg_idx < argc) {
		if (argv[arg_idx][0] != '-')
			break;

		if (!strcmp(argv[arg_idx], "-n")) {
			print_hdr = 0;
		} else if (!strcmp(argv[arg_idx], "-f")) {
			if (++arg_idx == argc) {
				qcsapi_report_parameter_count(p_calling_bundle, argc);
				goto usage;
			}

			if (!strcmp(argv[arg_idx], "active")) {
				report_type = QCSAPI_PWR_VALUE_TYPE_ACTIVE;
			} else if (!strcmp(argv[arg_idx], "configured")) {
				report_type = QCSAPI_PWR_VALUE_TYPE_CONFIGURED;
			} else {
				print_err(print, "Bad format %s\n", argv[arg_idx]);
				goto usage;
			}
		} else {
			print_err(print, "Invalid option %s\n", argv[arg_idx]);
			goto usage;
		}

		++arg_idx;
	}

	if ((arg_idx + 1) != argc) {
		qcsapi_report_parameter_count(p_calling_bundle, argc);
		goto usage;
	}

	memset(&info, 0, sizeof(info));

	if (regulatory_chan_txpower_input_parse_bitmap(argv[arg_idx], print, &info.channel, &ss_map,
			&bf_map, &fem_pri_map, &bw_map))
		goto usage;

	qcsapi_retval = qcsapi_regulatory_chan_txpower_get(p_calling_bundle->caller_interface,
			&info, report_type);
	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	if (print_hdr)
		reg_chan_txpower_get_print_header(print, bw_map);

	for (fem_pri = 0; fem_pri < QCSAPI_PWR_IDX_FEM_PRIPOS_NUM; ++fem_pri) {
		if (!(fem_pri_map & (1 << fem_pri)))
			continue;

		for (bf = 0; bf < QCSAPI_PWR_IDX_BF_NUM; ++bf) {
			if (!(bf_map & (1 << bf)))
				continue;

			for (ss = 0; ss < QCSAPI_PWR_IDX_SS_NUM; ++ss) {
				if (!(ss_map & (1 << ss)))
					continue;

				print_out(print, "%3d:%d:%d:%d ",
					info.channel, ss + 1, bf, fem_pri);

				for (bw = QCSAPI_PWR_BW_80M; bw < QCSAPI_PWR_BW_NUM; --bw) {
					if (!(bw_map & (1 << bw)))
						continue;

					print_out(print, "%4d ", (*pwrs)[fem_pri][bf][ss][bw]);
				}

				print_out(print, "\n");
			}
		}
	}

	return 0;

usage:
	qcsapi_report_usage(p_calling_bundle,
		"<interface> [-n -f <type>] <channel:nss:bf:fem_pri:bw>\nwhere\n"
		"-n: do not print header (default is to print header)\n"
		"-f active|configured: Tx power values report format (default active)\n");
	return 1;

}

static int
call_qcsapi_wifi_set_chan_power_table(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_channel_power_table power_table;
	int statval = 0;
	int qcsapi_retval;
	unsigned int channel;
	int max_power;
	int backoff;
	uint32_t backoff_20m = 0;
	uint32_t backoff_40m = 0;
	uint32_t backoff_80m = 0;
	int i;
	int offset;

	if (argc < 5) {
		print_err(print, "Not enough parameters in call_qcsapi set_chan_power_table\n");
		print_err( print, "Usage: call_qcsapi set_chan_power_table <interface> <channel>"
				" <max_power> <backoff_20M> <backoff_40M> <backoff_80M>\n" );
		print_err( print, "backoff_20M/40M/80M is a 32bits unsigned value, and every 4bits "
				"indicate the backoff from the max_power for a bf/ss case.\n"
				"The least significant 4 bits are for bfoff 1ss, and "
				"the most significant 4 bits are for bfon 4ss, and so forth.\n"
				"For example, max_power 23 and backoff_20M 0x54324321 means:\n"
				"  the power for 20Mhz bfoff 1ss: 23 - 1 = 22dBm\n"
				"  the power for 20Mhz bfoff 2ss: 23 - 2 = 21dBm\n"
				"  the power for 20Mhz bfoff 3ss: 23 - 3 = 20dBm\n"
				"  the power for 20Mhz bfoff 4ss: 23 - 4 = 19dBm\n"
				"  the power for 20Mhz bfon  1ss: 23 - 2 = 21dBm\n"
				"  the power for 20Mhz bfon  2ss: 23 - 3 = 20dBm\n"
				"  the power for 20Mhz bfon  3ss: 23 - 4 = 19dBm\n"
				"  the power for 20Mhz bfon  4ss: 23 - 5 = 18dBm\n");
		return 1;
	}

	if (local_atou32_verify_numeric_range(argv[0], &channel, print, 0, 255) < 0) {
		print_err(print, "Invalid channel number\n");
		return 1;
	}

	if (local_str_to_int32(argv[1], &max_power, print, "power value") < 0)
		return 1;

	if (local_str_to_uint32(argv[2], &backoff_20m, print, "backoff_20m value") < 0)
		return 1;

	if (local_str_to_uint32(argv[3], &backoff_40m, print, "backoff_40m value") < 0)
		return 1;

	if (local_str_to_uint32(argv[4], &backoff_80m, print, "backoff_80m value") < 0)
		return 1;

	power_table.channel = channel;

	if (max_power <= 0) {
		print_err(print, "Invalid max_power %d\n", max_power);
		return 1;
	}

	for (i = 0, offset = 0; i < QCSAPI_POWER_TOTAL; i++, offset += 4) {
		backoff = (backoff_20m >> offset) & 0xf;
		if (max_power <= backoff) {
			print_err(print, "Invalid backoff_20m, too large backoff"
					" for power index %d, backoff %d\n", i, backoff);
			return 1;
		}
		power_table.power_20M[i] = max_power - backoff;

		backoff = (backoff_40m >> offset) & 0xf;
		if (max_power <= backoff) {
			print_err(print, "Invalid backoff_40m, too large backoff"
					" for power index %d, backoff %d\n", i, backoff);
			return 1;
		}
		power_table.power_40M[i] = max_power - backoff;

		backoff = (backoff_80m >> offset) & 0xf;
		if (max_power <= backoff) {
			print_err(print, "Invalid backoff_80m, too large backoff"
					" for power index %d, backoff %d\n", i, backoff);
			return 1;
		}
		power_table.power_80M[i] = max_power - backoff;
	}

	qcsapi_retval = qcsapi_wifi_set_chan_power_table(the_interface, &power_table);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_power_selection( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			 statval = 0;
	qcsapi_unsigned_int	 power_selection;
	int			 qcsapi_retval;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_power_selection( &power_selection );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%d\n", power_selection );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_power_selection( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc != 1)
	{
		print_err( print, "Incorrect parameters in call qcsapi set power selection\n");
		print_err( print, "Usage: call_qcsapi set_power_selection <0/1/2/3>\n" );
		statval = 1;
	}
	else
	{
		qcsapi_unsigned_int	 power_selection;
		int			 qcsapi_retval;

		if (local_str_to_uint32(argv[0], &power_selection, print,
				"power selection value") < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_set_power_selection( power_selection );
		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_carrier_interference(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int	qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	int ci = 0;

	qcsapi_retval = qcsapi_wifi_get_carrier_interference(the_interface, &ci);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%ddb\n", ci);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_congestion_idx(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int	qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	int ci;

	qcsapi_retval = qcsapi_wifi_get_congestion_index(the_interface, &ci);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%d\n", ci);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_supported_tx_power_levels( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int		statval = 0;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	string_128	power_available = "";
	char		*p_power_available = &power_available[0];

	if (argc > 0 && strcmp(argv[ 0 ], "NULL") == 0) {
		p_power_available = NULL;
	}

	qcsapi_retval = qcsapi_wifi_get_supported_tx_power_levels(the_interface, p_power_available);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%s\n", p_power_available);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_current_tx_power_level( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			statval = 0;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	int			qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int	current_percentage = 0, *p_current_percentage = &current_percentage;

	if (argc > 0 && strcmp(argv[ 0 ], "NULL") == 0) {
		p_current_percentage = NULL;
	}

	qcsapi_retval = qcsapi_wifi_get_current_tx_power_level(the_interface, p_current_percentage);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%d\n", (int) current_percentage);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_current_tx_power_level( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			statval = 0;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	int			qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int	txpower_percentage = 0;

	if (local_str_to_uint32(argv[0], &txpower_percentage, print, "value") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_current_tx_power_level(the_interface, txpower_percentage);
	if (qcsapi_retval >= 0) {
		print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_power_constraint(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err(print, "Not enough parameters in call qcsapi WiFi set power constraint, count is %d\n", argc);
		statval = 1;
	} else {
		qcsapi_unsigned_int pwr_constraint;

		if (local_str_to_uint32(argv[0], &pwr_constraint, print, "value") < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_set_power_constraint(the_interface, pwr_constraint);
		if (qcsapi_retval >= 0) {
			print_out(print, "complete\n");
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wifi_get_power_constraint(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	qcsapi_unsigned_int pwr_constraint, *p_pwr_constraint = NULL;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;

	if (argc < 1 || strcmp(argv[0], "NULL") != 0)
		p_pwr_constraint = &pwr_constraint;

	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_power_constraint(the_interface, p_pwr_constraint);

	if (qcsapi_retval >= 0) {
		print_out(print, "%d\n", pwr_constraint);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_tpc_interval(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err(print, "Not enough parameters in call qcsapi WiFi set tpc interval, count is %d\n", argc);
		statval = 1;
	} else {
		int interval;

		if (local_str_to_int32(argv[0], &interval, print, "tpc interval value") < 0)
			return 1;

		if (interval <= 0)
			qcsapi_retval = -EINVAL;
		else
			qcsapi_retval = qcsapi_wifi_set_tpc_interval(the_interface, interval);

		if (qcsapi_retval >= 0) {
			print_out(print, "complete\n");
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wifi_get_tpc_interval(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	qcsapi_unsigned_int tpc_interval, *p_tpc_interval = NULL;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;

	if (argc < 1 || strcmp(argv[0], "NULL") != 0)
		p_tpc_interval = &tpc_interval;

	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_tpc_interval(the_interface, p_tpc_interval);

	if (qcsapi_retval >= 0) {
		print_out(print, "%d\n", tpc_interval);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scan_chk_inv(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err(print, "call_qcsapi set_scan_chk_inv wifi0 <scan_chk_inv>\n", argc);
		statval = 1;
	} else {
		int interval;

		if (local_atoi32_verify_numeric_range(argv[0], &interval, print,
					1, (24 * 60 * 60)) < 0) {
			print_err(print, "value should be limited from 1 second to 24 hours\n");
			return 1;
		}

		qcsapi_retval = qcsapi_wifi_set_scan_chk_inv(the_interface, interval);
		if (qcsapi_retval >= 0) {
			print_out(print, "complete\n");
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wifi_get_scan_chk_inv(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int scan_chk_inv, *p = NULL;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;

	if (argc < 1 || strcmp(argv[0], "NULL") != 0)
		p = &scan_chk_inv;

	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_scan_chk_inv(the_interface, p);

	if (qcsapi_retval >= 0) {
		print_out(print, "%d\n", scan_chk_inv);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}


static void
local_display_assoc_records(qcsapi_output *print, const struct qcsapi_assoc_records *p_assoc_records)
{
	int	iter;

	for (iter = 0; iter < QCSAPI_ASSOC_MAX_RECORDS; iter++) {
		if (p_assoc_records->timestamp[iter] <= 0) {
			return;
		}

		char	 mac_addr_string[ 24 ];

		snprintf( &mac_addr_string[ 0 ], sizeof(mac_addr_string), MACFILTERINGMACFMT,
			  p_assoc_records->addr[iter][0],
			  p_assoc_records->addr[iter][1],
			  p_assoc_records->addr[iter][2],
			  p_assoc_records->addr[iter][3],
			  p_assoc_records->addr[iter][4],
			  p_assoc_records->addr[iter][5]
		);

		print_out(print, "%s: %d\n", &mac_addr_string[0], (int) p_assoc_records->timestamp[iter]);
	}
}

static int
call_qcsapi_wifi_get_assoc_records(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int				statval = 0;
	qcsapi_output			*print = p_calling_bundle->caller_output;
	int				qcsapi_retval;
	const char			*the_interface = p_calling_bundle->caller_interface;
	int				reset_flag = 0;
	struct qcsapi_assoc_records	assoc_records;
	struct qcsapi_assoc_records	*p_assoc_records = &assoc_records;

	if ((argc > 0) && (local_str_to_int32(argv[0], &reset_flag, print,
					"reset flag value") < 0))
			return 1;

	if (argc > 1 && strcmp(argv[1], "NULL") == 0) {
		p_assoc_records = NULL;
	}

	qcsapi_retval = qcsapi_wifi_get_assoc_records(the_interface, reset_flag, p_assoc_records);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			local_display_assoc_records(print, &assoc_records);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_disassoc_records(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_disassoc_records records;
	uint8_t reset = 0;
	int qcsapi_retval;
	int i;

	if (argc > 1) {
		qcsapi_report_usage(p_calling_bundle, "<interface> [ <reset> ]\n");
		return 1;
	}

	if (argc) {
		if (local_verify_enable_or_disable(argv[0], &reset, print) < 0)
			return 1;
	}

	qcsapi_retval = qcsapi_wifi_get_disassoc_records(the_interface, (int)reset, &records);
	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	print_out(print, "MAC                Reason code       Count   Timestamp\n");
	for (i = 0; i < ARRAY_SIZE(records.reason); i++) {
		if (records.timestamp[i] <= 0)
			break;

		print_out(print, MACSTR "   %10u  %10u  %10u\n", MAC2STR(records.addr[i]),
			records.reason[i],
			records.disassoc_num[i],
			records.timestamp[i]);
	}

	return 0;
}

static int
call_qcsapi_wifi_get_list_DFS_channels( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2)
	{
		print_err( print, "Not enough parameters in call qcsapi get list DFS channels\n" );
		print_err( print, "Usage: call_qcsapi get_list_DFS_channels <regulatory region> <0 | 1> <bandwidth>\n" );
		statval = 1;
	}
	else
	{
		int			 qcsapi_retval;
		char			*p_list_channels = NULL;
		const char		*regulatory_region = NULL;
		uint8_t			 dfs_flag = 0;
		qcsapi_unsigned_int	 the_bw = 0;
/*
 * Prefer a non-reentrant program to allocating 1025 bytes on the stack.
 */
		static string_1024	 the_list_channels;

		if (strcmp( argv[ 0 ], "NULL" ) != 0)
		  regulatory_region = argv[ 0 ];

		if (local_verify_enable_or_disable(argv[1], &dfs_flag, print) < 0)
			return 1;

		if (argc < 3) {
			qcsapi_retval = qcsapi_wifi_get_bw("wifi0", &the_bw);
			if (qcsapi_retval < 0)
				the_bw = 40;
		} else if (local_str_to_uint32(argv[2], &the_bw, print, "bandwidth value") < 0) {
			return 1;
		}

		if (argc < 4 || strcmp( argv[ 3 ], "NULL" ) != 0)
		  p_list_channels = &the_list_channels[ 0 ];

		qcsapi_retval = qcsapi_regulatory_get_list_DFS_channels(regulatory_region,
						dfs_flag, the_bw, p_list_channels);

		if (qcsapi_retval == -qcsapi_region_database_not_found) {
			qcsapi_retval = qcsapi_wifi_get_list_DFS_channels(regulatory_region,
							dfs_flag, the_bw, p_list_channels);
		}

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "%s\n", the_list_channels );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_is_channel_DFS( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2)
	{
		print_err( print, "Not enough parameters in call qcsapi is channel DFS\n" );
		print_err( print, "Usage: call_qcsapi is_channel_DFS <regulatory region> <channel>\n" );
		statval = 1;
	}
	else
	{
		int			 qcsapi_retval;
		const char		*regulatory_region = NULL;
		int			 DFS_flag = 0;
		int			*p_DFS_flag = NULL;
		qcsapi_unsigned_int	 the_channel;

		if (local_str_to_uint32(argv[1], &the_channel, print, "channel number") < 0)
			return 1;

		if (strcmp( argv[ 0 ], "NULL" ) != 0)
		  regulatory_region = argv[ 0 ];

		if (argc < 3 || strcmp( argv[ 2 ], "NULL" ) != 0)
		  p_DFS_flag = &DFS_flag;

		qcsapi_retval = qcsapi_regulatory_is_channel_DFS( regulatory_region, the_channel, p_DFS_flag );

		if (qcsapi_retval == -qcsapi_region_database_not_found) {

			qcsapi_retval = qcsapi_wifi_is_channel_DFS( regulatory_region, the_channel, p_DFS_flag );
		}

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "%d\n", DFS_flag );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_DFS_alt_channel( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			 statval = 0;
	qcsapi_unsigned_int	 channel_value, *p_channel_value = NULL;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_channel_value = &channel_value;
	qcsapi_retval = qcsapi_wifi_get_DFS_alt_channel( the_interface, p_channel_value );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%d\n", channel_value );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_DFS_alt_channel( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi WiFi set DFS alt channel, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		qcsapi_unsigned_int	 dfs_alt_chan;
		int			 qcsapi_retval;
		const char		*the_interface = p_calling_bundle->caller_interface;

		if (local_str_to_uint32(argv[0], &dfs_alt_chan, print, "dfs_alt_chan value") < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_set_DFS_alt_channel( the_interface, dfs_alt_chan );
		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_dfs_reentry( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	int qcsapi_retval;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char	*the_interface = p_calling_bundle->caller_interface;

	qcsapi_retval = qcsapi_wifi_start_dfs_reentry(the_interface);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_scs_cce_channels( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			statval = 0;
	int			qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	prev_chan = 0;
	qcsapi_unsigned_int	cur_chan = 0;
	qcsapi_unsigned_int	*p_prev_chan = &prev_chan;
	qcsapi_unsigned_int	*p_cur_chan = &cur_chan;

	if (argc >= 2) {
		if (strcmp(argv[1], "NULL") == 0) {
			p_cur_chan = NULL;
		}
	}

	if (argc >= 1) {
		if (strcmp(argv[0], "NULL") == 0) {
			p_prev_chan = NULL;
		}
	}

	qcsapi_retval = qcsapi_wifi_get_scs_cce_channels(the_interface, p_prev_chan, p_cur_chan);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%d %d\n", (int) prev_chan, (int) cur_chan);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_dfs_cce_channels( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			statval = 0;
	int			qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	prev_chan = 0;
	qcsapi_unsigned_int	cur_chan = 0;
	qcsapi_unsigned_int	*p_prev_chan = &prev_chan;
	qcsapi_unsigned_int	*p_cur_chan = &cur_chan;

	if (argc >= 2) {
		if (strcmp(argv[1], "NULL") == 0) {
			p_cur_chan = NULL;
		}
	}

	if (argc >= 1) {
		if (strcmp(argv[0], "NULL") == 0) {
			p_prev_chan = NULL;
		}
	}

	qcsapi_retval = qcsapi_wifi_get_dfs_cce_channels(the_interface, p_prev_chan, p_cur_chan);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%d %d\n", (int) prev_chan, (int) cur_chan);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return statval;
}

void local_printout_get_params(qcsapi_output *print, struct qcsapi_set_parameters *get_params)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(get_params->param); i++) {
		if (get_params->param[i].key[0] == 0)
			break;

		print_out(print, "%s: %s\n", get_params->param[i].key,
				get_params->param[i].value);
	}
}

static int local_get_params(call_qcsapi_bundle *p_calling_bundle, const char *SSID,
				int argc, char *argv[])
{
	int i;
	int j;
	int qcsapi_retval = 0;
	int statval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	struct qcsapi_set_parameters get_params;
	const char usage1[] = "<WiFi interface> <param1> [<param2> ... <param8>]";
	const char usage2[] = "<WiFi interface> <ssid> [<param1> <param2> ... <param8>]";

	if (argc < 1 || argc > ARRAY_SIZE(get_params.param)) {
		if (!SSID)
			qcsapi_report_usage(p_calling_bundle, usage1);
		else
			qcsapi_report_usage(p_calling_bundle, usage2);
		return 1;
	}

	memset(&get_params, 0, sizeof(get_params));

	for (i = 0, j = 0; i < ARRAY_SIZE(get_params.param) && j < argc; i++, j++)
		strncpy(get_params.param[i].key, argv[j], sizeof(get_params.param[i].key) - 1);

	qcsapi_retval = qcsapi_get_params(the_interface, SSID, &get_params);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			local_printout_get_params(print, &get_params);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}


static int
call_qcsapi_wifi_get_params(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	return local_get_params(p_calling_bundle, NULL, argc, argv);
}

static int
call_qcsapi_wifi_set_params(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int i;
	int k;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	struct qcsapi_set_parameters set_params;
	const char usage[] =
		"<WiFi interface> <param1> <value1> [<param2> <value2>]... [<param8> <value8>]";

	if (argc < 2 || argc > (2 * ARRAY_SIZE(set_params.param)) || !!(argc % 2)) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return 1;
	}

	memset(&set_params, 0, sizeof(set_params));

	for (i = 0, k = 0; i < ARRAY_SIZE(set_params.param) && k < argc; i++, k += 2) {
		strncpy(set_params.param[i].key, argv[k], sizeof(set_params.param[i].key) - 1);
		strncpy(set_params.param[i].value, argv[k + 1],
				sizeof(set_params.param[i].value) - 1);
	}

	qcsapi_retval = qcsapi_set_params(the_interface, NULL, &set_params);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_SSID_get_params(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	const char *p_SSID = p_calling_bundle->caller_generic_parameter.parameter_type.the_SSID;

	return local_get_params(p_calling_bundle, p_SSID, argc, argv);
}

static int
call_qcsapi_SSID_set_params(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int i;
	int k;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	const char *p_SSID = p_calling_bundle->caller_generic_parameter.parameter_type.the_SSID;
	struct qcsapi_set_parameters set_params;
	const char usage[] =
	"<WiFi interface> <ssid> <param1> <value1> [<param2> <value2>]...[<param8> <value8>]";

	if (argc < 2 || argc > (2 * ARRAY_SIZE(set_params.param)) || !!(argc % 2)) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return 1;
	}

	memset(&set_params, 0, sizeof(set_params));

	for (i = 0, k = 0; i < ARRAY_SIZE(set_params.param) && k < argc; i++, k += 2) {
		strncpy(set_params.param[i].key, argv[k], sizeof(set_params.param[i].key) - 1);
		strncpy(set_params.param[i].value, argv[k + 1],
				sizeof(set_params.param[i].value) - 1);
	}

	qcsapi_retval = qcsapi_set_params(the_interface, p_SSID, &set_params);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_wifi_get_csw_records( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int statval = 0;
	int qcsapi_retval;
	int reset=0;
	int i, scs_reason;
	char scs_reason_str[CSW_SCS_FLAG_STRING_MAX] = {0};
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_csw_record records;

	if (argc >= 1) {
		if (strcmp(argv[0], "1") == 0) {
			reset = 1;
		}
	}

	qcsapi_retval = qcsapi_wifi_get_csw_records(the_interface, reset, &records);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "channel switch history record count : %d\n", records.cnt);
			int index = records.index;
			int indextmp = 0;
			for (i = 0; i < records.cnt; i++){
				indextmp = (index + QCSAPI_CSW_MAX_RECORDS - i) % QCSAPI_CSW_MAX_RECORDS;
				if (IEEE80211_CSW_REASON_SCS == (records.reason[indextmp] & CSW_REASON_MASK)) {
					scs_reason = CSW_REASON_GET_SCS_FLAG(records.reason[indextmp]);
					scs_reason_to_string(scs_reason, scs_reason_str);
					if ( (scs_reason & IEEE80211_SCS_STA_CCA_REQ_CC)
							|| (scs_reason & IEEE80211_SCS_BRCM_STA_TRIGGER_CC)) {
						print_out(print, "time=%u channel=%u reason=%s record mac "MACFILTERINGMACFMT" \n",
								records.timestamp[indextmp],
								records.channel[indextmp],
								scs_reason_str,
								records.csw_record_mac[indextmp][0], records.csw_record_mac[indextmp][1],
								records.csw_record_mac[indextmp][2], records.csw_record_mac[indextmp][3],
								records.csw_record_mac[indextmp][4], records.csw_record_mac[indextmp][5]);
					} else {
						print_out(print, "time=%u channel=%u reason=%s\n",
								records.timestamp[indextmp],
								records.channel[indextmp],
								scs_reason_str);
					}
				} else {
					print_out(print, "time=%u channel=%u reason=%s\n",
							records.timestamp[indextmp],
							records.channel[indextmp],
							csw_reason_to_string(records.reason[indextmp]));
				}
			}

			if (reset) {
				print_out(print, "clear records complete\n");
			}
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval );
		statval = 1;
	}
	return statval;
}

static int
call_qcsapi_wifi_get_radar_status( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_radar_status rdstatus;

	if (argc < 1) {
		print_err(print, "Not enough parameters\n");
		statval = 1;
	} else {
		memset(&rdstatus, 0, sizeof(rdstatus));

		if (local_str_to_uint32(argv[0], &rdstatus.channel, print, "channel number") < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_get_radar_status(the_interface, &rdstatus);

		if(qcsapi_retval >= 0) {
			print_out(print, "channel %d:\nradar_status=%d\nradar_count=%d\n", rdstatus.channel, rdstatus.flags, rdstatus.ic_radardetected);
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wifi_get_WEP_encryption_level( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	string_64	 WEP_encryption_level;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc > 0 && strcmp( argv[ 0 ], "NULL" ) == 0)
	  qcsapi_retval = qcsapi_wifi_get_WEP_encryption_level( the_interface, NULL );
	else
	  qcsapi_retval = qcsapi_wifi_get_WEP_encryption_level( the_interface, WEP_encryption_level );

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%s\n", WEP_encryption_level );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_WPA_encryption_modes( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	char		 encryption_modes[ 36 ], *p_encryption_modes = NULL;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_encryption_modes = &encryption_modes[ 0 ];
	qcsapi_retval = qcsapi_wifi_get_WPA_encryption_modes( the_interface, p_encryption_modes );

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%s\n", &encryption_modes[ 0 ] );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_WPA_encryption_modes( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi WiFi set encryption mode, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*p_encryption_modes = argv[ 0 ];

	  /* Encryption modes will not be NULL ... */

		if (strcmp( argv[ 0 ], "NULL" ) == 0)
		  p_encryption_modes = NULL;
		qcsapi_retval = qcsapi_wifi_set_WPA_encryption_modes( the_interface, p_encryption_modes );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_WPA_authentication_mode( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	char		 authentication_mode[ 36 ], *p_authentication_mode = NULL;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_authentication_mode = &authentication_mode[ 0 ];
	qcsapi_retval = qcsapi_wifi_get_WPA_authentication_mode( the_interface, p_authentication_mode );

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%s\n", &authentication_mode[ 0 ] );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_WPA_authentication_mode( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi WiFi set authentication mode, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*p_authentication_mode = argv[ 0 ];

	  /* Authentication mode will not be NULL ... */

		if (strcmp( argv[ 0 ], "NULL" ) == 0)
		  p_authentication_mode = NULL;
		qcsapi_retval = qcsapi_wifi_set_WPA_authentication_mode( the_interface, p_authentication_mode );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_interworking( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
        int             statval = 0;
        char            interworking[2],*p_interworking = NULL;
        int             qcsapi_retval;
        const char      *the_interface = p_calling_bundle->caller_interface;
        qcsapi_output   *print = p_calling_bundle->caller_output;

        if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
                p_interworking = &interworking[0];

        qcsapi_retval = qcsapi_wifi_get_interworking( the_interface, p_interworking );

        if (qcsapi_retval >= 0) {
                if (verbose_flag >= 0) {
                        print_out( print, "%s\n", &interworking );
                }
        } else {
                report_qcsapi_error( p_calling_bundle, qcsapi_retval );
                statval = 1;
        }

        return( statval );
}

static int
call_qcsapi_wifi_set_interworking( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi WiFi set interworking, count is %d\n", argc );
		statval = 1;
	} else {
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*p_interworking = argv[ 0 ];

		if (strcmp( argv[ 0 ], "NULL" ) == 0)
			p_interworking = NULL;

		qcsapi_retval = qcsapi_wifi_set_interworking( the_interface, p_interworking );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
is_80211u_param( char *lookup_name )
{
	int retval = 1;
	unsigned int iter;

	for (iter = 0; qcsapi_80211u_params[iter] != NULL; iter++) {
		if (strcmp(qcsapi_80211u_params[iter], lookup_name) == 0) {
			retval = 0;
			break;
		}
	}

	return retval;
}

static int
call_qcsapi_wifi_get_80211u_params( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int		statval = 0;
	string_256	value;
	char		*p_buffer = NULL;
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_out( print, "Usage : call_qcsapi get_80211u_params "
					"<interface> <80211u_param>");
		return 1;
	}

	if (is_80211u_param( argv[0] )) {
		print_out( print, "\n %s is not 80211u parameter",argv[0] );
		return 1;
	}

	if (strcmp( argv[ 0 ], "NULL" ) != 0)
		p_buffer = &value[ 0 ];

	qcsapi_retval = qcsapi_wifi_get_80211u_params( the_interface, argv[0], p_buffer );

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%s\n", value );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_80211u_params( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int		statval = 0;

	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err( print, "Not enough parameters in call qcsapi WiFi "
					"set_80211u_params, count is %d\n", argc );
		print_err(print, "Usage: call_qcsapi set_80211u_params "
					"<interface> <param> <value>\n");
		statval = 1;
	} else {
		int		qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*p_11u_param = argv[ 0 ];

		if (strcmp( argv[ 0 ], "NULL" ) == 0)
			p_11u_param = NULL;

		if (is_80211u_param( argv[0] )) {
			print_err( print, "%s is not a valid 802.11u parameter\n",argv[0]);
			statval = 1;
		} else {
			if (!strcmp(argv[0], "ipaddr_type_availability")) {
				if (argc < 3) {
					print_err( print, "%s expects 2 arguments\n", argv[0]);
					return 1;
				}
			}

			qcsapi_retval = qcsapi_wifi_set_80211u_params( the_interface, p_11u_param,
									argv[1], argv[2] );

			if (qcsapi_retval >= 0) {
				if (verbose_flag >= 0) {
					print_out( print, "complete\n" );
				}
			} else {
				report_qcsapi_error( p_calling_bundle, qcsapi_retval );
				statval = 1;
			}
		}
	}

	return( statval );
}

static int
call_qcsapi_security_get_nai_realms( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int             statval = 0;
	string_4096	nai_value;
	char            *p_buffer = &nai_value[0];
	int             qcsapi_retval;
	const char      *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output   *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_security_get_nai_realms( the_interface,  p_buffer );

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%s\n", p_buffer );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	 return( statval );
}

static int
call_qcsapi_security_add_nai_realm( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int		statval = 0;

	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 3) {
		print_err( print, "Not enough parameters in call qcsapi WiFi add_nai_realm,"
				"count is %d\n", argc );
		statval = 1;
	} else {
		int		 qcsapi_retval = 0;
		const char	*the_interface = p_calling_bundle->caller_interface;
		uint8_t		encoding;
		char		*p_nai_realm = argv[1];
		char		*p_eap_method = argv[2];

		if (local_verify_enable_or_disable(argv[0], &encoding, print) < 0)
			return 1;

		if (strcmp( argv[ 1 ], "NULL" ) == 0)
			p_nai_realm = NULL;

		if (strcmp( argv[ 2 ], "NULL" ) == 0)
			p_eap_method = NULL;

		qcsapi_retval = qcsapi_security_add_nai_realm( the_interface,
								encoding,
								p_nai_realm,
								p_eap_method );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_security_del_nai_realm( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int		statval = 0;

	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi WiFi del_nai_realm,"
					"count is %d\n", argc );
		statval = 1;
	} else {
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*p_nai_realm = argv[0];

		if (strcmp( argv[ 0 ], "NULL" ) == 0)
			p_nai_realm = NULL;

		qcsapi_retval = qcsapi_security_del_nai_realm( the_interface, p_nai_realm );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_security_get_roaming_consortium( call_qcsapi_bundle *p_calling_bundle,
					     int argc, char *argv[] )
{
	int             statval = 0;
	string_1024	roaming_value;
	char            *p_buffer = &roaming_value[ 0 ];
	int             qcsapi_retval;
	const char      *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output   *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_security_get_roaming_consortium( the_interface,  p_buffer );

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%s\n", p_buffer );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	 return( statval );
}

static int
call_qcsapi_security_add_roaming_consortium( call_qcsapi_bundle *p_calling_bundle,
					     int argc, char *argv[] )
{
	int		statval = 0;

	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi WiFi "
				   "add_roaming_consortium count is %d\n", argc );
		statval = 1;
	} else {
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*p_value = argv[0];

		if (strcmp( argv[ 0 ], "NULL" ) == 0)
			p_value = NULL;

		qcsapi_retval = qcsapi_security_add_roaming_consortium( the_interface, p_value );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}


static int
call_qcsapi_security_del_roaming_consortium( call_qcsapi_bundle *p_calling_bundle,
					     int argc, char *argv[] )
{
	int		statval = 0;

	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi WiFi "
				   "del_roaming_consortium count is %d\n", argc );
		statval = 1;
	} else {
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*p_value = argv[0];

		if (strcmp( argv[ 0 ], "NULL" ) == 0)
			p_value = NULL;

		qcsapi_retval = qcsapi_security_del_roaming_consortium( the_interface, p_value );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_security_get_venue_name( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int		statval = 0;
	string_4096	venue_name;
	char            *p_venue_name = &venue_name[0];
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_security_get_venue_name( the_interface, p_venue_name );

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%s\n",venue_name);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_security_add_venue_name( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err( print, "Not enough parameters in call qcsapi WiFi "
				  "add_venue_name, count is %d\n", argc);
		statval = 1;
	} else {
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*p_lang_code = argv[0];
		char		*p_venue_name = argv[1];

		if (strcmp( argv[0], "NULL" ) == 0)
			p_lang_code = NULL;

		if (strcmp( argv[1], "NULL" ) == 0)
			p_venue_name = NULL;

		qcsapi_retval = qcsapi_security_add_venue_name( the_interface, p_lang_code, p_venue_name );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_security_del_venue_name( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err( print, "Not enough parameters in call qcsapi WiFi "
				  "del_venue_name, count is %d\n", argc);
		statval = 1;
	} else {
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*p_lang_code = argv[0];
		char		*p_venue_name = argv[1];

		if (strcmp( argv[0], "NULL" ) == 0)
			p_lang_code = NULL;

		if (strcmp( argv[1], "NULL" ) == 0)
			p_venue_name = NULL;

		qcsapi_retval = qcsapi_security_del_venue_name( the_interface, p_lang_code, p_venue_name );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_security_get_oper_friendly_name( call_qcsapi_bundle *p_calling_bundle,
					     int argc, char *argv[] )
{
	int             statval = 0;
	string_4096	value;
	char            *p_value = &value[0];
	int             qcsapi_retval;
	const char      *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output   *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_security_get_oper_friendly_name( the_interface, p_value );

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%s\n", value);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_security_add_oper_friendly_name( call_qcsapi_bundle *p_calling_bundle,
					     int argc, char *argv[] )
{
	int		statval = 0;

	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err( print, "Not enough parameters in call qcsapi WiFi "
				   "add_oper_friendly_name count is %d\n", argc);
		statval = 1;
	} else {
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*p_lang_code = argv[0];
		char		*p_oper_friendly_name = argv[1];

		if (strcmp( argv[0], "NULL" ) == 0)
			p_lang_code = NULL;

		if (strcmp( argv[1], "NULL" ) == 0)
			p_oper_friendly_name = NULL;

		qcsapi_retval = qcsapi_security_add_oper_friendly_name( the_interface,
									p_lang_code,
									p_oper_friendly_name );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_security_del_oper_friendly_name( call_qcsapi_bundle *p_calling_bundle,
					     int argc, char *argv[] )
{
	int		statval = 0;

	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err( print, "Not enough parameters in call qcsapi WiFi "
				  "del_oper_friendly_name count is %d\n", argc);
		statval = 1;
	} else {
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*p_lang_code = argv[0];
		char		*p_oper_friendly_name = argv[1];

		if (strcmp( argv[0], "NULL" ) == 0)
			p_lang_code = NULL;

		if (strcmp( argv[1], "NULL" ) == 0)
			p_oper_friendly_name = NULL;

		qcsapi_retval = qcsapi_security_del_oper_friendly_name( the_interface,
									p_lang_code,
									p_oper_friendly_name );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}


static int
call_qcsapi_security_get_hs20_conn_capab( call_qcsapi_bundle *p_calling_bundle,
					     int argc, char *argv[] )
{
	int		statval = 0;
	string_4096	value;
	char            *p_value = &value[0];
	int             qcsapi_retval;
	const char      *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output   *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_security_get_hs20_conn_capab( the_interface, p_value );

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%s\n", value);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_security_add_hs20_conn_capab( call_qcsapi_bundle *p_calling_bundle,
					     int argc, char *argv[] )
{
	int			statval = 0;
	qcsapi_output		*print	= p_calling_bundle->caller_output;

	if (argc < 3) {
		print_err( print, "Not enough parameters in call qcsapi WiFi "
				   "add_hs20_conn_capab count is %d\n", argc);
		statval = 1;
	} else {
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*p_ip_proto = argv[0];
		char		*p_port_num = argv[1];
		char		*p_status = argv[2];

		if (strcmp( argv[0], "NULL" ) == 0)
			p_ip_proto = NULL;

		if (strcmp( argv[1], "NULL" ) == 0)
			p_port_num = NULL;

		if (strcmp( argv[2], "NULL" ) == 0)
			p_status = NULL;

		qcsapi_retval = qcsapi_security_add_hs20_conn_capab( the_interface,
									p_ip_proto,
									p_port_num,
									p_status );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_security_del_hs20_conn_capab( call_qcsapi_bundle *p_calling_bundle,
					     int argc, char *argv[] )
{
	int		statval = 0;
	qcsapi_output	*print	= p_calling_bundle->caller_output;

	if (argc < 3) {
		print_err( print, "Not enough parameters in call qcsapi WiFi "
				   "del_hs20_conn_capab count is %d\n", argc);
		statval = 1;
	} else {
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*p_ip_proto = argv[0];
		char		*p_port_num = argv[1];
		char		*p_status = argv[2];

		if (strcmp( argv[0], "NULL" ) == 0)
			p_ip_proto = NULL;

		if (strcmp( argv[1], "NULL" ) == 0)
			p_port_num = NULL;

		if (strcmp( argv[2], "NULL" ) == 0)
			p_status = NULL;

		qcsapi_retval = qcsapi_security_del_hs20_conn_capab( the_interface,
									p_ip_proto,
									p_port_num,
									p_status );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return ( statval );
}

static int
call_qcsapi_security_add_hs20_icon(call_qcsapi_bundle *p_calling_bundle,
					     int argc, char *argv[])
{
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print	= p_calling_bundle->caller_output;
	qcsapi_unsigned_int width;
	qcsapi_unsigned_int height;

	if (argc < 6) {
		qcsapi_report_parameter_count(p_calling_bundle, argc);
		qcsapi_report_usage(p_calling_bundle,
				"<Icon Width> <Icon Height> <Language Code> "
				"<Icon Type> <Name> <File Path>");
		return 1;
	}

	if (local_str_to_uint32(argv[0], &width, print, "Icon Width value") < 0)
		return 1;

	if (local_str_to_uint32(argv[1], &height, print, "Icon Height") < 0)
		return 1;

	qcsapi_retval = qcsapi_security_add_hs20_icon(the_interface, width, height,
			argv[2], argv[3], argv[4], argv[5]);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_security_get_hs20_icon(call_qcsapi_bundle *p_calling_bundle,
					     int argc, char *argv[])
{
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	string_1024	output_buf = {0};
	char		*param = NULL;

	if (argc < 1 || strcmp(argv[0], "NULL"))
		param = output_buf;

	qcsapi_retval = qcsapi_security_get_hs20_icon(the_interface, param);

	return qcsapi_report_str_or_error(p_calling_bundle, qcsapi_retval, output_buf);
}

static int
call_qcsapi_security_del_hs20_icon(call_qcsapi_bundle *p_calling_bundle,
					     int argc, char *argv[])
{
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;

	if (argc < 1) {
		qcsapi_report_usage(p_calling_bundle, "<Icon Name>");
		return 1;
	}

	qcsapi_retval = qcsapi_security_del_hs20_icon(the_interface, argv[0]);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_security_add_osu_server_uri(call_qcsapi_bundle *p_calling_bundle,
					     int argc, char *argv[])
{
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;

	if (argc < 1) {
		qcsapi_report_usage(p_calling_bundle, "<OSU Server URI>");
		return 1;
	}

	qcsapi_retval = qcsapi_security_add_osu_server_uri(the_interface, argv[0]);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_security_get_osu_server_uri(call_qcsapi_bundle *p_calling_bundle,
					     int argc, char *argv[])
{
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	string_1024	output_buf = {0};
	char		*param = NULL;

	if (argc < 1 || strcmp(argv[0], "NULL"))
		param = output_buf;

	qcsapi_retval = qcsapi_security_get_osu_server_uri(the_interface, param);

	return qcsapi_report_str_or_error(p_calling_bundle, qcsapi_retval, output_buf);
}

static int
call_qcsapi_security_del_osu_server_uri(call_qcsapi_bundle *p_calling_bundle,
					     int argc, char *argv[])
{
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;

	if (argc < 1) {
		qcsapi_report_usage(p_calling_bundle, "<OSU Server URI>");
		return 1;
	}

	qcsapi_retval = qcsapi_security_del_osu_server_uri(the_interface, argv[0]);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_security_add_osu_server_param(call_qcsapi_bundle *p_calling_bundle,
					     int argc, char *argv[])
{
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;

	if (argc < 3) {
		qcsapi_report_usage(p_calling_bundle, "<OSU Server URI> <param> <value>");
		return 1;
	}

	qcsapi_retval = qcsapi_security_add_osu_server_param(the_interface,
			argv[0], argv[1], argv[2]);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_security_get_osu_server_param(call_qcsapi_bundle *p_calling_bundle,
					     int argc, char *argv[])
{
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	string_1024	output_buf = {0};
	char		*param = NULL;

	if (argc < 2) {
		qcsapi_report_usage(p_calling_bundle, "<OSU Server URI> <param>");
		return 1;
	}

	if (argc < 3 || strcmp(argv[1], "NULL"))
		param = output_buf;

	qcsapi_retval = qcsapi_security_get_osu_server_param(the_interface, argv[0],
			argv[1], param);

	return qcsapi_report_str_or_error(p_calling_bundle, qcsapi_retval, output_buf);
}

static int
call_qcsapi_security_del_osu_server_param(call_qcsapi_bundle *p_calling_bundle,
					     int argc, char *argv[])
{
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	const char	*value = NULL;

	if (argc < 2) {
		qcsapi_report_usage(p_calling_bundle, "<OSU Server URI> <param> [<value>]");
		return 1;
	}
	if (argc >= 3) {
		value = argv[2];
	}

	qcsapi_retval = qcsapi_security_del_osu_server_param(the_interface,
			argv[0], argv[1], value);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_wifi_get_hs20_status( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int		statval = 0;
	char		hs20[2];
	char		*p_hs20 = NULL;
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
		p_hs20 = &hs20[0];
	qcsapi_retval = qcsapi_wifi_get_hs20_status( the_interface, p_hs20 );

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%s\n", p_hs20 );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_hs20_status( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi WiFi set hotspot, count is %d\n", argc );
		statval = 1;
	} else {
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*p_hs20 = argv[ 0 ];

		if (strcmp( argv[ 0 ], "NULL" ) == 0)
			p_hs20 = NULL;

		qcsapi_retval = qcsapi_wifi_set_hs20_status( the_interface, p_hs20 );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_proxy_arp( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		qcsapi_report_parameter_count(p_calling_bundle, argc);
		statval = 1;
	} else {
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*proxy_arp = argv[ 0 ];
		uint8_t		result;

		if (local_verify_enable_or_disable(argv[0], &result, print) < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_set_proxy_arp( the_interface, proxy_arp );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_proxy_arp( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int		statval = 0;
	char		proxy_arp[2];
	char		*p_proxy_arp = NULL;
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc > 0) {
		qcsapi_retval = -EFAULT;
	} else {
		p_proxy_arp = &proxy_arp[0];

		qcsapi_retval = qcsapi_wifi_get_proxy_arp( the_interface, p_proxy_arp );
	}

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%s\n", p_proxy_arp );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_l2_ext_filter( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int		statval = 0;
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	string_32       value;

	if (argc < 1) {
		print_err(print, "Not enough parameters in qcsapi get_l2_ext_filter, count is %d\n", argc);
		statval = 1;
	} else {
		char	*p_value = value;
		char	*p_param = argv[0];

		if (strcmp(p_param, "NULL") == 0)
			p_param = NULL;

		qcsapi_retval = qcsapi_wifi_get_l2_ext_filter( the_interface, p_param, p_value );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "%s\n", p_value );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}


static int
call_qcsapi_wifi_set_l2_ext_filter( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err(print, "Not enough parameters in qcsapi set_l2_ext_filter, count is %d\n", argc);
		statval = 1;
	} else {
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char            *p_param = argv[0];
		char            *p_value = argv[1];

		if (strcmp( argv[ 0 ], "NULL" ) == 0)
			p_param = NULL;

		if (strcmp( argv[ 1 ], "NULL" ) == 0)
			p_value = NULL;

		qcsapi_retval = qcsapi_wifi_set_l2_ext_filter( the_interface, p_param, p_value );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
check_hs20_param( char *lookup_name )
{
        int retval = 1;
        unsigned int iter;

	int hs20_param_count = TABLE_SIZE( qcsapi_hs20_params );

        for (iter = 0; iter < hs20_param_count; iter++) {
                if (strcmp(qcsapi_hs20_params[iter], lookup_name) == 0) {
                        retval = 0;
                        break;
                }
        }
        return retval;
}


static int
call_qcsapi_wifi_get_hs20_params( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int		statval = 0;
	string_64	value;
	char		*p_value = NULL;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc != 1) {
		print_out(print, "\n call_qcsapi get_hs20_params <interface>"
				" <hs20_param>\n");
		return 1;
	}

	p_value = &value[ 0 ];

	if (check_hs20_param( argv[0] )) {
		print_out( print, "\n %s is not hs20 parameter\n", argv[0]);
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_get_hs20_params( the_interface, argv[0], p_value );

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%s\n", p_value );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_hs20_params( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err( print, "Not enough parameters in call qcsapi WiFi set_hs20_params, count is %d\n", argc );
		statval = 1;
	} else {
		int		qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;

		if (check_hs20_param( argv[0] )) {
			print_out( print, "\n %s is not hs20 parameter\n", argv[0]);
			return 1;
		}

		 if (!strcmp(argv[0], "hs20_wan_metrics")) {
			if (argc != 7) {
				print_out(print, "\n call_qcsapi set_hs20_params <interface>"
						" hs20_wan_metrics <WAN_info> <uplink_speed> "
						"<downlink_speed> <uplink_load> "
						"<downlink_load> <LMD>\n");
				return 1;
			}
		}

		if (!strcmp(argv[0], "disable_dgaf")) {
			if (argc != 2) {
				print_out(print, "\n call_qcsapi set_hs20_params "
						"<interface> disable_dgaf <0:disable 1:enable>\n");
				return 1;
			}
		}

		qcsapi_retval = qcsapi_wifi_set_hs20_params( the_interface, argv[0],
					argv[1], argv[2], argv[3], argv[4], argv[5], argv[6] );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_remove_11u_param( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	int	qcsapi_retval;

	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err(print, "Not enough parameters in call qcsapi remove 11u_param, count is %d\n", argc);
		statval = 1;
	}

	if (is_80211u_param( argv[0] )) {
		print_out( print, "%s is not 80211u parameter\n",argv[0]);
		statval = 1;
	} else {
		char *param = argv[0];

		qcsapi_retval = qcsapi_remove_11u_param( the_interface, param );

                if (qcsapi_retval >= 0) {
                        if (verbose_flag >= 0) {
                                print_out(print, "complete\n");
                        }
                } else {
                        report_qcsapi_error( p_calling_bundle, qcsapi_retval );
                        statval = 1;
                }
	}

	return ( statval );
}

static int
call_qcsapi_remove_hs20_param( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
        int	qcsapi_retval;

	const char *the_interface = p_calling_bundle->caller_interface;
        qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
                print_err(print, "Not enough parameters in call qcsapi remove hs20_param, count is %d\n", argc);
                statval = 1;
        }

	if (check_hs20_param( argv[0] )) {
		print_out( print, "%s is not hs20 parameter\n",argv[0]);
		statval = 1;
	} else {
		char *param = argv[0];

                qcsapi_retval = qcsapi_remove_hs20_param( the_interface, param );

                if (qcsapi_retval >= 0) {
                        if (verbose_flag >= 0) {
                                print_out(print, "complete\n");
                        }
                } else {
                        report_qcsapi_error( p_calling_bundle, qcsapi_retval );
                        statval = 1;
                }
	}

	return ( statval );

}

static int
call_qcsapi_wifi_get_IEEE11i_encryption_modes( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int		 statval = 0;
	char		 encryption_modes[ 36 ], *p_encryption_modes = NULL;
	int		 qcsapi_retval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
		p_encryption_modes = &encryption_modes[ 0 ];

	qcsapi_retval = qcsapi_wifi_get_IEEE11i_encryption_modes( the_interface, p_encryption_modes );

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%s\n", &encryption_modes[ 0 ] );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_IEEE11i_encryption_modes( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int		 statval = 0;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	char		*p_encryption_mode = argv[ 0 ];
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi WiFi set authentication mode, count is %d\n", argc );
		statval = 1;
	} else {
		if (strcmp( argv[ 0 ], "NULL" ) == 0)
			p_encryption_mode = NULL;

		qcsapi_retval = qcsapi_wifi_set_IEEE11i_encryption_modes( the_interface, p_encryption_mode );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_IEEE11i_authentication_mode( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int		 statval = 0;
	char		 authentication_mode[ 36 ], *p_authentication_mode = NULL;
	int		 qcsapi_retval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
		p_authentication_mode = &authentication_mode[ 0 ];

	qcsapi_retval = qcsapi_wifi_get_IEEE11i_authentication_mode( the_interface, p_authentication_mode );

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%s\n", &authentication_mode[ 0 ] );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_IEEE11i_authentication_mode( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int		 statval = 0;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	char		*p_authentication_mode = argv[ 0 ];
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi WiFi set authentication mode, count is %d\n", argc );
		statval = 1;
	} else {
		if (strcmp( argv[ 0 ], "NULL" ) == 0)
			p_authentication_mode = NULL;

		qcsapi_retval = qcsapi_wifi_set_IEEE11i_authentication_mode( the_interface, p_authentication_mode );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_michael_errcnt( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int	qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	uint32_t errcnt;

	qcsapi_retval = qcsapi_wifi_get_michael_errcnt(the_interface, &errcnt);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%u\n", errcnt);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_pre_shared_key( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	char			 pre_shared_key[ 68 ], *p_pre_shared_key = NULL;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	 the_index = p_calling_bundle->caller_generic_parameter.index;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_pre_shared_key = &pre_shared_key[ 0 ];
	qcsapi_retval = qcsapi_wifi_get_pre_shared_key( the_interface, the_index, p_pre_shared_key );

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%s\n", &pre_shared_key[ 0 ] );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_pre_shared_key( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi WiFi set pre-shared key, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		int			 qcsapi_retval;
		const char		*the_interface = p_calling_bundle->caller_interface;
		char			*p_pre_shared_key = argv[ 0 ];
		qcsapi_unsigned_int	 the_index = p_calling_bundle->caller_generic_parameter.index;

	  /* PSK will not be NULL ... */

		if (strcmp( argv[ 0 ], "NULL" ) == 0)
		  p_pre_shared_key = NULL;
		qcsapi_retval = qcsapi_wifi_set_pre_shared_key( the_interface, the_index, p_pre_shared_key );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_psk_auth_failures(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int psk_auth_failure_cnt = 0;

	qcsapi_retval = qcsapi_wifi_get_psk_auth_failures(the_interface, &psk_auth_failure_cnt);
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
			print_out(print, "%u\n", psk_auth_failure_cnt);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_key_passphrase( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	char			 passphrase[ 68 ], *p_passphrase = NULL;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	 the_index = p_calling_bundle->caller_generic_parameter.index;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_passphrase = &passphrase[ 0 ];
	qcsapi_retval = qcsapi_wifi_get_key_passphrase( the_interface, the_index, p_passphrase );

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%s\n", &passphrase[ 0 ] );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_key_passphrase( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi WiFi set passphrase, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		int			 qcsapi_retval;
		const char		*the_interface = p_calling_bundle->caller_interface;
		qcsapi_unsigned_int	 the_index = p_calling_bundle->caller_generic_parameter.index;
		char			*p_passphrase = argv[ 0 ];

	  /* No, you cannot has a passphrase of NULL.  Too bad !! */

		if (strcmp( argv[ 0 ], "NULL" ) == 0)
		  p_passphrase = NULL;
		qcsapi_retval = qcsapi_wifi_set_key_passphrase( the_interface, the_index, p_passphrase );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
local_get_key_interval( int (*p_key_get_hook)(const char *, unsigned int *), call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
        int                     statval = 0;
        unsigned int            key_interval;
        int                     qcsapi_retval;
        const char              *the_interface = p_calling_bundle->caller_interface;
        qcsapi_output           *print = p_calling_bundle->caller_output;

        qcsapi_retval = p_key_get_hook( the_interface, &key_interval );

        if (qcsapi_retval >= 0)
        {
                if (verbose_flag >= 0)
                {
                        print_out( print, "%u\n", key_interval );
                }
        }
	else
        {
                report_qcsapi_error( p_calling_bundle, qcsapi_retval );
                statval = 1;
        }

        return( statval );
}

static int
call_qcsapi_wifi_get_group_key_interval( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	return local_get_key_interval(qcsapi_wifi_get_group_key_interval, p_calling_bundle, argc, argv);
}

static int
call_qcsapi_wifi_get_pairwise_key_interval( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	return local_get_key_interval(qcsapi_wifi_get_pairwise_key_interval, p_calling_bundle, argc, argv);
}

static int
local_set_key_interval( int (*p_key_set_hook)(const char *, unsigned int), call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	const char              *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	int                     key_interval;
        int                     qcsapi_retval;

	if (local_str_to_int32(argv[0], &key_interval, print, "key interval value") < 0)
		return 1;

	qcsapi_retval = p_key_set_hook(the_interface, key_interval);

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "complete\n" );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		return 1;
        }

	return 0;
}

static int
call_qcsapi_wifi_set_group_key_interval( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
        qcsapi_output *print = p_calling_bundle->caller_output;

        if (argc < 1)
        {
                print_err( print, "Not enough parameters in call qcsapi set group key interval, count is %d\n", argc);
                print_err( print, "Usage: call_qcsapi set_group_key_interval <WiFi interface> <group key interval>\n");
                print_err( print, " group key interval is in seconds, set to zero to disable group key rotation\n");
                return 1;
        }
	return local_set_key_interval(qcsapi_wifi_set_group_key_interval, p_calling_bundle, argc, argv);
}

static int
call_qcsapi_wifi_set_pairwise_key_interval( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
        qcsapi_output *print = p_calling_bundle->caller_output;

        if (argc < 1)
        {
                print_err( print, "Not enough parameters in call qcsapi set pairwise key interval, count is %d\n", argc);
                print_err( print, "Usage: call_qcsapi set_pairwise_key_interval <WiFi interface> <pairwise key interval>\n");
                print_err( print, " pairwise key interval is in seconds, set to zero to disable pairwise key rotation\n");
                return 1;
        }
	return local_set_key_interval(qcsapi_wifi_set_pairwise_key_interval, p_calling_bundle, argc, argv);
}

static int
call_qcsapi_wifi_get_pmf( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int		statval = 0;
	int		pmf_cap = 0;
	int		*p_pmf_cap = NULL;
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
		p_pmf_cap = &pmf_cap;

	qcsapi_retval = qcsapi_wifi_get_pmf( the_interface, p_pmf_cap);

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%d\n", pmf_cap );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_pmf( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi WiFi set pmf, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		int			 qcsapi_retval;
		const char		*the_interface = p_calling_bundle->caller_interface;
		qcsapi_unsigned_int	 pmf_cap;

		if (local_str_to_uint32(argv[0], &pmf_cap, print, "PMF cap value") < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_set_pmf( the_interface, pmf_cap );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}



static int
call_qcsapi_wifi_get_pairing_id( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	char			 pairing_id[ 33 ];
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_pairing_id( the_interface, pairing_id );

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%s\n", pairing_id );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_pairing_id( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi WiFi set pairing ID, count is %d\n", argc );
		statval = 1;
	} else {
		int			 qcsapi_retval;
		const char		*the_interface = p_calling_bundle->caller_interface;
		char			*pairing_id = argv[ 0 ];

		qcsapi_retval = qcsapi_wifi_set_pairing_id( the_interface, pairing_id );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

#define  PAIRING_ENABLE_MAX_LEN	129
static int
call_qcsapi_wifi_get_pairing_enable( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	char			 pairing_enable[ PAIRING_ENABLE_MAX_LEN ];
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_pairing_enable( the_interface, pairing_enable );

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%s\n", pairing_enable );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_pairing_enable( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi WiFi set pairing enalbe flag, count is %d\n", argc );
		statval = 1;
	} else {
		int			 qcsapi_retval;
		const char		*the_interface = p_calling_bundle->caller_interface;
		char			*pairing_enable = argv[ 0 ];

		qcsapi_retval = qcsapi_wifi_set_pairing_enable( the_interface, pairing_enable );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_txqos_sched_tbl( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi set txqos sched table\n" );
		print_err( print,
	   "Usage: call_qcsapi set_txqos_sched_tbl <WiFi interface> [1|2]\n"
		);
		statval = 1;
	}
	else
	{
		const char	*the_interface = p_calling_bundle->caller_interface;
		int              index;
		string_64	cmd;

		if (local_str_to_int32(argv[0], &index, print, "index") < 0)
			return 1;

		sprintf(cmd, "iwpriv %s set_txqos_sched %d\n", the_interface, index);
		statval = system(cmd);

		if (statval == 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_txqos_sched_tbl( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc != 0)
	{
		print_err( print, "No need to give parameters for this command\n" );
		print_err( print, "Usage: call_qcsapi get_txqos_sched_tbl <WiFi interface>\n"
		);
		statval = 1;
	}
	else
	{
		const char	*the_interface = p_calling_bundle->caller_interface;
		string_64	cmd;

		sprintf(cmd, "iwpriv %s get_txqos_sched\n", the_interface);
		statval = system(cmd);

		if (statval == 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		}
	}

	return( statval );
}

static int
call_qcsapi_eth_phy_power_off( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	const char	*the_interface = p_calling_bundle->caller_interface;

	if (argc < 1) {
		qcsapi_report_usage(p_calling_bundle, "<eth ifname> {0 | 1}");
		statval = 1;
	} else {
		int			qcsapi_retval;
		unsigned char		on_off;

		if (local_verify_enable_or_disable(argv[0], &on_off, print) < 0)
			return 1;

		qcsapi_retval = qcsapi_eth_phy_power_control(on_off, the_interface);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_set_aspm_l1( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int statval = 0;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters for the call_qcsapi set_aspm_l1 %d\n", argc );
		print_err( print, "Format: call_qcsapi set_aspm_l1 enable/disable [latency] \n" );
		print_err( print, "1 - enable, 0 - disable; latency(0~6) \n" );
		statval = 1;
	} else {
		int		qcsapi_retval;
		uint8_t		enable;
		int		latency = 0;

		if (local_verify_enable_or_disable(argv[0], &enable, print) < 0)
			return 1;

		if (enable && argc == 1) {
			print_err( print, "please enter latency value \n" );
			statval = 1;
			goto end;
		}

		if (enable && (local_str_to_int32(argv[1], &latency, print, "latency value") < 0))
				return 1;

		qcsapi_retval = qcsapi_set_aspm_l1(enable, latency);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}

	}
end:
	return ( statval );
}

static int
call_qcsapi_set_l1( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval;
	uint8_t enter;

	if (argc < 1) {
		print_err( print, "Not enough parameters for the call_qcsapi set_l1 %d\n", argc );
		print_err( print, "Format: call_qcsapi set_l1 enter/exit \n" );
		print_err( print, "1 - enter, 0 - exit \n" );
		goto call_qcsapi_set_l1_error;
	}

	if (local_verify_enable_or_disable(argv[0], &enter, print) < 0)
		goto call_qcsapi_set_l1_error;

	qcsapi_retval = qcsapi_set_l1(enter);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n" );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		goto call_qcsapi_set_l1_error;
	}


	return ( statval );

 call_qcsapi_set_l1_error:
	statval = 1;
	return ( statval );
}

static int
call_qcsapi_wifi_get_mac_address_filtering( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_mac_address_filtering	 current_mac_address_filtering, *p_current_mac_address_filtering = NULL;
	int				 qcsapi_retval;
	const char			*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output			*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_current_mac_address_filtering = &current_mac_address_filtering;
	qcsapi_retval = qcsapi_wifi_get_mac_address_filtering( the_interface, p_current_mac_address_filtering );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%d\n", (int) current_mac_address_filtering );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_mac_address_filtering( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print,
	   "Not enough parameters in call qcsapi WiFi set MAC address filtering, count is %d\n", argc
		);
		statval = 1;
	}
	else
	{
		int qcsapi_retval;
		const char *the_interface = p_calling_bundle->caller_interface;
		int result;
		qcsapi_mac_address_filtering current_mac_address_filtering;

		if (qcsapi_util_str_to_int32(argv[0], &result) < 0) {
			qcsapi_report_usage(p_calling_bundle, "<ifname> {0 | 1 | 2}");
			return 1;
		}

		current_mac_address_filtering = (qcsapi_mac_address_filtering) result;

		qcsapi_retval = qcsapi_wifi_set_mac_address_filtering( the_interface, current_mac_address_filtering );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_is_mac_address_authorized(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print,
	   "Not enough parameters in call qcsapi WiFi is MAC address authorized, count is %d\n", argc
		);
		statval = 1;
	}
	else
	{
		const char	*the_interface = p_calling_bundle->caller_interface;
		qcsapi_mac_addr  the_mac_addr;
		int		 qcsapi_retval;
		int		 ival = 0, is_authorized = -1;

		if (strcmp( "NULL", argv[ 0 ] ) == 0)
		  qcsapi_retval = qcsapi_wifi_is_mac_address_authorized( the_interface, NULL, &is_authorized );
		else
		{
			ival = parse_mac_addr( argv[ 0 ], the_mac_addr );
			if (ival >= 0)
			  qcsapi_retval = qcsapi_wifi_is_mac_address_authorized(
				the_interface, the_mac_addr, &is_authorized
			  );
			else
			{
				print_out( print, "Error parsing MAC address %s\n", argv[ 0 ] );
				statval = 1;
			}
		}

		if (ival >= 0)
		{
			if (qcsapi_retval >= 0)
			{
				if (verbose_flag >= 0)
				{
					print_out( print, "%d\n", is_authorized );
				}
			}
			else
			{
				report_qcsapi_error( p_calling_bundle, qcsapi_retval );
				statval = 1;
			}
		}
	}

	return( statval );
}

#define QCSAPI_AUTH_MAC_ADDR_SIZE 126
static int
call_qcsapi_wifi_get_authorized_mac_addresses(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	char *authorized_mac_addresses = NULL;
	unsigned int sizeof_authorized_mac_addresses = QCSAPI_AUTH_MAC_ADDR_SIZE;

	if (argc > 0) {
		uint32_t usr_input = 0;

		if (local_str_to_uint32(argv[0], &usr_input, print, "size") < 0)
			return 1;

		sizeof_authorized_mac_addresses = (usr_input < QCSAPI_MSG_BUFSIZE) ?
			usr_input : QCSAPI_MSG_BUFSIZE;
	}

	authorized_mac_addresses = malloc(sizeof_authorized_mac_addresses);
	if (authorized_mac_addresses == NULL) {
		print_err(print, "Failed to allocate %u chars\n", sizeof_authorized_mac_addresses);
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_get_authorized_mac_addresses(
			the_interface, authorized_mac_addresses, sizeof_authorized_mac_addresses);

        if (qcsapi_report_str_or_error(p_calling_bundle, qcsapi_retval, authorized_mac_addresses))
		statval = 1;

	free(authorized_mac_addresses);

	return statval;
}

static int
call_qcsapi_wifi_get_denied_mac_addresses( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	char *denied_mac_addresses = NULL;
	unsigned int sizeof_denied_mac_addresses = QCSAPI_AUTH_MAC_ADDR_SIZE;

	if (argc > 0) {
		uint32_t usr_input = 0;

		if (local_str_to_uint32(argv[0], &usr_input, print, "size") < 0)
			return 1;

		sizeof_denied_mac_addresses = usr_input < QCSAPI_MSG_BUFSIZE ?
			usr_input : QCSAPI_MSG_BUFSIZE;
	}

	denied_mac_addresses = malloc(sizeof_denied_mac_addresses);
	if (denied_mac_addresses == NULL) {
		print_err(print, "Failed to allocate %u chars\n", sizeof_denied_mac_addresses);
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_get_denied_mac_addresses(
			the_interface, denied_mac_addresses, sizeof_denied_mac_addresses);

        if (qcsapi_report_str_or_error(p_calling_bundle, qcsapi_retval, denied_mac_addresses))
		statval = 1;

	free(denied_mac_addresses);

	return statval;
}

static int
call_qcsapi_wifi_authorize_mac_address( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print,
	   "Not enough parameters in call qcsapi WiFi authorize MAC address,count is %d\n", argc
		);
		statval = 1;
	}
	else
	{
		const char		*the_interface = p_calling_bundle->caller_interface;
		qcsapi_mac_addr_list	the_mac_addr_list;
		int			qcsapi_retval = 0;
		int		 	count = 0;

		if (strcmp( "NULL", argv[ 0 ] ) == 0)
		  qcsapi_retval = qcsapi_wifi_authorize_mac_address_list( the_interface, 0, NULL );
		else
		{
			for (count = 0; count < MIN(argc, MAC_ADDR_LIST_SIZE); count++) {
				qcsapi_retval = parse_mac_addr(argv[count],
						&the_mac_addr_list[count * MAC_ADDR_SIZE]);
				if (qcsapi_retval < 0)
					break;
			}

			if (count > 0) {
				qcsapi_retval = qcsapi_wifi_authorize_mac_address_list(
							the_interface, count, the_mac_addr_list);
			} else {
				print_out( print, "Error parsing MAC address %s\n", argv[ count ] );
				statval = 1;
			}
		}

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_authorize_mac_address_ext( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			statval = 0;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	const char		*the_interface = p_calling_bundle->caller_interface;
	int			qcsapi_retval = 0;
	int			count = 0;
	struct qcsapi_mac_list	*mlist = NULL;

	if (argc < 1) {
		print_err(print, "Not enough parameters in call qcsapi WiFi authorize MAC address,"
									" count is %d\n", argc);
		return 1;
	}

	if (strcmp( "NULL", argv[ 0 ] ) == 0) {
		qcsapi_retval = qcsapi_wifi_authorize_mac_address_list_ext(the_interface, NULL);
	} else {
		mlist = (struct qcsapi_mac_list*)calloc(1, sizeof(struct qcsapi_mac_list));
		if (mlist == NULL) {
			print_err(print, "Failed to allocate memory in call qcsapi "
							"WiFi authorize MAC address\n");
			return 1;
		}

		for (count = 0; count < MIN(argc, QCSAPI_MAX_MACS_IN_LIST); count++) {
			qcsapi_retval = parse_mac_addr(argv[count],
						&mlist->macaddr[count * MAC_ADDR_SIZE]);
			if (qcsapi_retval < 0)
				break;
		}

		if (count > 0) {
			mlist->num_entries = count;
			qcsapi_retval = qcsapi_wifi_authorize_mac_address_list_ext(the_interface,
											mlist);
		} else {
			print_out( print, "Error parsing MAC address %s\n", argv[count]);
			statval = 1;
		}
	}

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n" );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	if (mlist) {
		free(mlist);
	}

	return( statval );
}

static int
call_qcsapi_wifi_deny_mac_address( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print,
	   "Not enough parameters in call qcsapi WiFi deny MAC address, count is %d\n", argc
		);
		statval = 1;
	}
	else
	{
		const char		*the_interface = p_calling_bundle->caller_interface;
		qcsapi_mac_addr_list	the_mac_addr_list;
		int			qcsapi_retval = 0;
		int		 	count = 0;

		if (strcmp( "NULL", argv[ 0 ] ) == 0)
		  qcsapi_retval = qcsapi_wifi_deny_mac_address_list( the_interface, 0, NULL );
		else
		{
			for (count = 0; count < MIN(argc, MAC_ADDR_LIST_SIZE); count++) {
				qcsapi_retval = parse_mac_addr(argv[count],
						&the_mac_addr_list[count * MAC_ADDR_SIZE]);
				if (qcsapi_retval < 0)
					break;
			}

			if (count > 0) {
				qcsapi_retval = qcsapi_wifi_deny_mac_address_list(
							the_interface, count, the_mac_addr_list);
			} else {
				print_out( print, "Error parsing MAC address %s\n", argv[ count ] );
				statval = 1;
			}
		}

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_deny_mac_address_ext( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			statval = 0;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	const char		*the_interface = p_calling_bundle->caller_interface;
	struct qcsapi_mac_list	*mlist = NULL;
	int			qcsapi_retval = 0;
	int			count = 0;

	if (argc < 1) {
		print_err(print, "Not enough parameters in call qcsapi WiFi deny MAC address,"
									" count is %d\n", argc);
		return 1;
	}

	if (strcmp( "NULL", argv[ 0 ] ) == 0) {
		qcsapi_retval = qcsapi_wifi_deny_mac_address_list_ext(the_interface, NULL);
	} else {
		mlist = (struct qcsapi_mac_list*)calloc(1, sizeof(struct qcsapi_mac_list));
		if (mlist == NULL) {
			print_err(print, "Failed to allocate memory in call qcsapi "
							"WiFi deny MAC address\n");
			return 1;
		}

		for (count = 0; count < MIN(argc, QCSAPI_MAX_MACS_IN_LIST); count++) {
			qcsapi_retval = parse_mac_addr(argv[count],
						&mlist->macaddr[count * MAC_ADDR_SIZE]);
			if (qcsapi_retval < 0)
				break;
		}

		if (count > 0) {
			mlist->num_entries = count;
			qcsapi_retval = qcsapi_wifi_deny_mac_address_list_ext(the_interface,
											mlist);
		} else {
			print_out( print, "Error parsing MAC address %s\n", argv[ count ] );
			statval = 1;
		}
	}

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n" );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	if (mlist) {
		free(mlist);
	}

	return( statval );
}

static int
call_qcsapi_wifi_remove_mac_address( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print,
	   "Not enough parameters in call qcsapi WiFi remove MAC address, count is %d\n", argc
		);
		statval = 1;
	}
	else
	{
		const char		*the_interface = p_calling_bundle->caller_interface;
		qcsapi_mac_addr_list	the_mac_addr_list;
		int			qcsapi_retval = 0;
		int			count = 0;

		if (strcmp( "NULL", argv[ 0 ] ) == 0)
		  qcsapi_retval = qcsapi_wifi_remove_mac_address_list( the_interface, 0, NULL );
		else
		{
			for (count = 0; count < MIN(argc, MAC_ADDR_LIST_SIZE); count++) {
				qcsapi_retval = parse_mac_addr(argv[count],
						&the_mac_addr_list[count * MAC_ADDR_SIZE]);
				if (qcsapi_retval < 0)
					break;
			}

			if (count > 0) {
				qcsapi_retval = qcsapi_wifi_remove_mac_address_list(
							the_interface, count, the_mac_addr_list);
			} else {
				print_out( print, "Error parsing MAC address %s\n", argv[ count ] );
				statval = 1;
			}
		}

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_remove_mac_address_ext( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			statval = 0;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	const char		*the_interface = p_calling_bundle->caller_interface;
	struct qcsapi_mac_list	*mlist = NULL;
	int			qcsapi_retval = 0;
	int			count = 0;

	if (argc < 1) {
		print_err(print, "Not enough parameters in call qcsapi WiFi remove MAC address,"
									" count is %d\n", argc);
		return 1;
	}

	if (strcmp( "NULL", argv[ 0 ] ) == 0) {
		qcsapi_retval = qcsapi_wifi_remove_mac_address_list_ext(the_interface, NULL);
	} else {
		mlist = (struct qcsapi_mac_list*)calloc(1, sizeof(struct qcsapi_mac_list));
		if (mlist == NULL) {
			print_err(print, "Failed to allocate memory in call qcsapi "
							"WiFi deny MAC address\n");
			return 1;
		}

		for (count = 0; count < MIN(argc, QCSAPI_MAX_MACS_IN_LIST); count++) {
			qcsapi_retval = parse_mac_addr(argv[count],
						&mlist->macaddr[count * MAC_ADDR_SIZE]);
			if (qcsapi_retval < 0)
				break;
		}

		if (count > 0) {
			mlist->num_entries = count;
			qcsapi_retval = qcsapi_wifi_remove_mac_address_list_ext(the_interface, mlist);
		} else {
			print_out( print, "Error parsing MAC address %s\n", argv[ count ] );
			statval = 1;
		}
	}

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n" );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	if (mlist) {
		free(mlist);
	}

	return( statval );
}

static int
call_qcsapi_wifi_clear_mac_address_filters( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	int				 qcsapi_retval;
	const char			*the_interface = p_calling_bundle->caller_interface;

	qcsapi_retval = qcsapi_wifi_clear_mac_address_filters( the_interface );

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n" );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_add_temp_acl_macaddr(call_qcsapi_bundle *p_calling_bundle,
	int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *ifname = p_calling_bundle->caller_interface;
	qcsapi_mac_addr mac_addr;
	int qcsapi_retval = 0;
	int statval = 0;

	if (argc < 2) {
		qcsapi_report_usage(p_calling_bundle, "<ifname> {accept | deny} <mac_addr>");
		return 1;
	}

	qcsapi_retval = parse_mac_addr(argv[1], mac_addr);
	if (qcsapi_retval >= 0)
		qcsapi_retval = qcsapi_wifi_add_temporary_mac_filter_addr(ifname,
					argv[0], mac_addr);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_del_temp_acl_macaddr(call_qcsapi_bundle *p_calling_bundle,
	int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *ifname = p_calling_bundle->caller_interface;
	qcsapi_mac_addr mac_addr;
	int qcsapi_retval = 0;
	int statval = 0;

	if (argc < 2) {
		qcsapi_report_usage(p_calling_bundle, "<ifname> {accept | deny} <mac_addr>");
		return 1;
	}

	qcsapi_retval = parse_mac_addr(argv[1], mac_addr);
	if (qcsapi_retval >= 0)
		qcsapi_retval = qcsapi_wifi_del_temporary_mac_filter_addr(ifname,
					argv[0], mac_addr);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_mac_address_reserve(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;

	int qcsapi_retval;

	if (argc < 1) {
		print_err(print,
			"Not enough parameters in call qcsapi WiFi reserve MAC address, count is %d\n",
				argc);
		return 1;
	} else if (argc == 1) {
		qcsapi_retval = qcsapi_wifi_set_mac_address_reserve(the_interface, argv[0], "");
	} else {
		qcsapi_retval = qcsapi_wifi_set_mac_address_reserve(the_interface, argv[0], argv[1]);
	}

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	if (verbose_flag >= 0)
		print_out(print, "complete\n");

	return 0;
}

static int
call_qcsapi_wifi_get_mac_address_reserve(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;
	string_256 buf;
	int qcsapi_retval;

	qcsapi_retval = qcsapi_wifi_get_mac_address_reserve(the_interface, buf);
	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	print_out(print, "%s", buf);

	return 0;
}

static int
call_qcsapi_wifi_clear_mac_address_reserve(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;

	int qcsapi_retval;

	qcsapi_retval = qcsapi_wifi_clear_mac_address_reserve(the_interface);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	if (verbose_flag >= 0)
		print_out(print, "complete\n");

	return 0;
}

static int
call_qcsapi_wifi_backoff_fail_max( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print,
	   "Not enough parameters in call qcsapi backoff fail max, count is %d\n", argc
		);
		statval = 1;
	}
	else
	{
		const char	*the_interface = p_calling_bundle->caller_interface;
		int		 qcsapi_retval;
		int		 backoff_fail_max;

		if (qcsapi_util_str_to_int32(argv[0], &backoff_fail_max) < 0) {
			qcsapi_report_usage(p_calling_bundle, "<ifname> <max failure count>");
			return 1;
		}

		qcsapi_retval = qcsapi_wifi_backoff_fail_max( the_interface, backoff_fail_max );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_backoff_timeout( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print,
	   "Not enough parameters in call qcsapi backoff timeout, count is %d\n", argc
		);
		statval = 1;
	}
	else
	{
		const char	*the_interface = p_calling_bundle->caller_interface;
		int		 qcsapi_retval;
		int		 backoff_timeout;

		if (qcsapi_util_str_to_int32(argv[0], &backoff_timeout) < 0) {
			qcsapi_report_usage(p_calling_bundle, "<ifname> <backoff timeout>");
			return 1;
		}

		qcsapi_retval = qcsapi_wifi_backoff_timeout( the_interface, backoff_timeout );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wps_registrar_report_button_press( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		 qcsapi_retval = qcsapi_wps_registrar_report_button_press( the_interface );

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n" );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wps_registrar_report_pin( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "registrar report pin: required WPS PIN not present\n" );
		statval = 1;
	}
	else {
		const char	*the_interface = p_calling_bundle->caller_interface;
		const char	*p_wps_pin = NULL;
		int		 qcsapi_retval;

		if (strcmp( argv[ 0 ], "NULL" ) != 0) {
			p_wps_pin = argv[ 0 ];
		}

		qcsapi_retval = qcsapi_wps_registrar_report_pin( the_interface, p_wps_pin );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wps_registrar_get_pp_devname(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		 statval = 0;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	string_128	 pp_devname = "";
	char		*p_pp_devname = &pp_devname[0];
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		 blacklist = 0;

	if (argc >= 1) {
		if (strcmp(argv[0], "blacklist") == 0) {
			blacklist = 1;
	       } else {
			print_err(print, "Usage: call_qcsapi registrar_get_pp_devname "
							"<WiFi interface> [blacklist] \n");
			return 1;
	       }
	}

	qcsapi_retval = qcsapi_wps_registrar_get_pp_devname(the_interface,
							blacklist, p_pp_devname);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%s\n", p_pp_devname);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wps_registrar_set_pp_devname(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		 statval = 0;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	char		*p_pp_devname = NULL;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	uint32_t	wps_pp_status;
	int		update_blacklist = 0;

	if (argc == 1) {
		p_pp_devname = strcmp(argv[0], "NULL") == 0 ? NULL : argv[0];
	} else if (argc == 2 && strcmp(argv[0], "blacklist") == 0) {
		update_blacklist = 1;
		p_pp_devname = strcmp(argv[1], "NULL") == 0 ? NULL : argv[1];
	} else {
		print_err(print, "WPS Registrar Set PP Devname: \n"
				"setting white-list: call_qcsapi registrar_set_pp_devname <device name list>\n"
				"setting black-list: call_qcsapi registrar_set_pp_devname blacklist <device name list>\n");
		return 0;
	}

	qcsapi_retval = qcsapi_wps_get_access_control( the_interface, &wps_pp_status );
	if (qcsapi_retval >= 0) {
		if (wps_pp_status == 0) {
			print_err(print, "enable WPS Pairing Protection before setting device name list\n");
			return 1;
		}
	}

	if (qcsapi_retval >= 0)
		qcsapi_retval = qcsapi_wps_registrar_set_pp_devname(the_interface, update_blacklist, p_pp_devname);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return statval;
}


static int
call_qcsapi_wps_enrollee_report_button_press( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	int		 ival = 0;
	qcsapi_mac_addr	 local_bssid = { 0, 0, 0, 0, 0, 0 };
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc > 0) {
		/*
		 * Interpret BSSID parameter of "any" as direction to pass BSSID of all zeros to the API -
		 * so the WPS process will associate with any registrar.
		 */
		if (strcasecmp( argv[ 0 ], "any" ) != 0) {
			ival = parse_mac_addr( argv[ 0 ], local_bssid );

			if (ival < 0) {
				print_out( print, "Error parsing MAC address %s\n", argv[ 0 ] );
				statval = 1;
			}
		}
	}

	if (ival >= 0) {
		const char	*the_interface = p_calling_bundle->caller_interface;
		int		 qcsapi_retval = qcsapi_wps_enrollee_report_button_press(the_interface,
											 local_bssid);
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wps_enrollee_report_pin( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "enrollee report pin: required WPS PIN not present\n" );
		statval = 1;
	} else {
		int		 qcsapi_retval = 0;
		const char	*the_interface = p_calling_bundle->caller_interface;
		qcsapi_mac_addr	 local_bssid = { 0, 0, 0, 0, 0, 0 };
		const char	*p_wps_pin = NULL;
		int		 ival = 0;
		int		 pin_argv_index = 0;

		if (argc > 1) {
			if (strcasecmp( argv[ 0 ], "any" ) != 0) {
				ival = parse_mac_addr( argv[ 0 ], local_bssid );
			}

			if (ival < 0) {
				print_out( print, "Error parsing MAC address %s\n", argv[ 0 ] );
				statval = 1;
			} else {
				pin_argv_index = 1;
			}
		}

		if (ival >= 0) {
			if (strcmp( argv[ pin_argv_index ], "NULL" ) != 0) {
				p_wps_pin = argv[ pin_argv_index ];
			}

			qcsapi_retval = qcsapi_wps_enrollee_report_pin( the_interface,
									local_bssid,
									p_wps_pin );
			if (qcsapi_retval >= 0) {
				if (verbose_flag >= 0) {
					print_out( print, "complete\n" );
				}
			} else {
				report_qcsapi_error( p_calling_bundle, qcsapi_retval );
				statval = 1;
			}
		}
	}

	return( statval );
}

static int
call_qcsapi_wps_enrollee_generate_pin( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	int		 ival = 0;
	qcsapi_mac_addr	 local_bssid = { 0, 0, 0, 0, 0, 0 };
	char		 generated_pin[ QCSAPI_WPS_MAX_PIN_LEN + 1 ];
	char		*p_generated_pin = NULL;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc > 0) {
		if (argc < 2 || strcmp( argv[ 1 ], "NULL" ) != 0) {
			p_generated_pin = &generated_pin[ 0 ];
		}
		/*
		 * Interpret BSSID parameter of "any" as direction to pass BSSID of all zeros to the API -
		 * so the WPS process will associate with any registrar.
		 */
		if (strcasecmp( argv[ 0 ], "any" ) != 0) {
			ival = parse_mac_addr( argv[ 0 ], local_bssid );

			if (ival < 0) {
				print_out( print, "Error parsing MAC address %s\n", argv[ 0 ] );
				statval = 1;
			}
		}
	} else {
		p_generated_pin = &generated_pin[ 0 ];
	}

	if (ival >= 0) {
		const char	*the_interface = p_calling_bundle->caller_interface;
		int		 qcsapi_retval = qcsapi_wps_enrollee_generate_pin(the_interface,
										  local_bssid,
										  p_generated_pin);
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "%s\n", &generated_pin[0 ] );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wps_get_ap_pin(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *iface = p_calling_bundle->caller_interface;
	char generated_pin[QCSAPI_WPS_MAX_PIN_LEN + 1];
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint8_t force_regenerate = 0;

	if (argc == 1) {
		if (local_verify_enable_or_disable(argv[0], &force_regenerate, print) < 0)
			return 1;
	} else if (argc > 1) {
		print_err(print, "Too many arguments for wps_get_ap_pin\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wps_get_ap_pin(iface, generated_pin, force_regenerate);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%s\n", generated_pin);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static void local_set_wps_ap_pin_usage(qcsapi_output *print, int out)
{
	if (!out) {
		print_out(print, "usage: call_qscapi set_wps_ap_pin <AP PIN>\n"
				"AP PIN: 8bit or 4 bit digits\n");
	} else {
		print_err(print, "usage: call_qscapi set_wps_ap_pin <AP PIN>\n"
				"AP PIN: 8bit or 4 bit digits\n");
	}
}

static int
call_qcsapi_wps_set_ap_pin(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *iface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	char wps_pin[2 * QCSAPI_WPS_MAX_PIN_LEN] = {0};

	if (argc <= 0) {
		local_set_wps_ap_pin_usage(print, 1);
		return 1;
	}

	strncpy(wps_pin, argv[0], sizeof(wps_pin) - 1);

	qcsapi_retval = qcsapi_wps_set_ap_pin(iface, wps_pin);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static void local_configure_wps_ap_usage(qcsapi_output *print)
{
	char *usage = "Usage: call_qscapi wps_configure_ap <Interface> <AP BSSID> <AP PIN> "
			"<new SSID> <auth> <encr> <new key>\n"
			"\t<auth> must be one of the following: OPEN WPAPSK WPA2PSK\n"
			"\t<encr> must be one of the following: NONE CCMP\n";

	print_err(print, usage);
}

static int
call_qcsapi_wps_configure_ap(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *iface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	char *bssid;
	char *ap_pin;
	char *new_SSID;
	char *new_encr;
	char *new_auth;
	char *new_passphrase;

	if (argc != 6) {
		local_configure_wps_ap_usage(print);
		return 1;
	}

	bssid = argv[0];
	ap_pin = argv[1];
	new_SSID = argv[2];
	new_auth = argv[3];
	new_encr = argv[4];
	new_passphrase = argv[5];

	qcsapi_retval = qcsapi_wps_configure_ap(iface,
						bssid,
						ap_pin,
						new_SSID,
						new_auth,
						new_encr,
						new_passphrase);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
		if (qcsapi_retval == -EINVAL)
			local_configure_wps_ap_usage(print);
	}

	return statval;
}

static int
call_qcsapi_wps_save_ap_pin(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *iface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc != 0) {
		print_err(print, "usage: call_qscapi save_wps_ap_pin\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wps_save_ap_pin(iface);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		if (qcsapi_retval == -qcsapi_parameter_not_found)
			print_err(print, "no ap PIN exists, set or generate one\n");
		else
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wps_enable_ap_pin(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *iface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint8_t enable;

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle, "{0 | 1}");
		return 1;
	}

	if (local_verify_enable_or_disable(argv[0], &enable, print) < 0)
		return 1;

	qcsapi_retval = qcsapi_wps_enable_ap_pin(iface, enable);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wps_generate_random_pin(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *iface = p_calling_bundle->caller_interface;
	char generated_pin[QCSAPI_WPS_MAX_PIN_LEN + 1];
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wps_get_sta_pin(iface, generated_pin);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%s\n", generated_pin);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wps_get_state( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	int			 qcsapi_retval;
	qcsapi_unsigned_int	 message_len = WPS_GET_STATE_MAX_LENGTH;
	char			 wps_state[ WPS_GET_STATE_MAX_LENGTH ] = "";
	char			*p_wps_state = &wps_state[ 0 ];

	if (argc > 0) {
		if (strcmp( argv[ 0 ], "NULL" ) == 0 ) {
			p_wps_state = NULL;
		} else {
			if (qcsapi_util_str_to_uint32(argv[0], &message_len) < 0) {
				qcsapi_report_usage(p_calling_bundle, "[size of message buffer]");
				return 1;
			}
		}
	}

	qcsapi_retval = qcsapi_wps_get_state( the_interface, p_wps_state, message_len );

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%s\n", p_wps_state );
		}
	}
	else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

#define  MAC_ADDR_STR_LEN		17
static int
call_qcsapi_wifi_get_wpa_status( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			statval = 0;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	int			 qcsapi_retval;
	qcsapi_unsigned_int	 message_len = WPA_GET_STATUS_MAX_LEN;
	char			 wpa_status[ WPA_GET_STATUS_MAX_LEN ] = "";
	char			*p_wpa_status = &wpa_status[ 0 ];
	char			mac_addr[MAC_ADDR_STR_LEN + 1] = {0};

	if (argc > 0) {
		if (argc == 2) {
			if (qcsapi_util_str_to_uint32(argv[1], &message_len) < 0) {
				qcsapi_report_usage(p_calling_bundle, "[size of message buffer]");
				return 1;
			}
		}

		if (strnlen( argv[ 0 ], MAC_ADDR_STR_LEN + 1 ) == MAC_ADDR_STR_LEN ) {
			strcpy( mac_addr, argv[ 0 ] );
		} else {
			print_out( print, "mac address input error \n");
			return( statval );
		}
	}

	qcsapi_retval = qcsapi_wifi_get_wpa_status( the_interface, p_wpa_status, mac_addr, message_len );

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%s\n", p_wpa_status );
		}
	}
	else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_auth_state( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			statval = 0;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	int			 qcsapi_retval;
	char			 mac_addr[MAC_ADDR_STR_LEN + 1] = {0};
	int			 auth_state = 0;

	if (argc > 0) {
		if (strnlen( argv[ 0 ], (MAC_ADDR_STR_LEN + 1) ) == MAC_ADDR_STR_LEN ) {
			strcpy( mac_addr, argv[ 0 ] );
		} else {
			print_out( print, "Mac address input is invalid!\n" );
			return( statval );
		}
	} else {
		print_out( print, "Mac address should be input!\n" );
		return( statval );
	}

	qcsapi_retval = qcsapi_wifi_get_auth_state( the_interface, mac_addr, &auth_state );

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%d\n", auth_state );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_disconn_info(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int	qcsapi_retval;
	qcsapi_disconn_info info;

	memset(&info, 0, sizeof(info));
	qcsapi_retval = qcsapi_wifi_get_disconn_info(the_interface, &info);

	if (qcsapi_retval >= 0) {
		print_out( print, "association\t%d\n"
				"disconnect\t%d\n"
				"sequence\t%d\n"
				"uptime\t%d\n", info.asso_sta_count, info.disconn_count, info.sequence,
				info.up_time);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_reset_disconn_info(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int	qcsapi_retval;
	qcsapi_disconn_info info;

	memset(&info, 0, sizeof(info));
	info.resetflag = 1;
	qcsapi_retval = qcsapi_wifi_get_disconn_info(the_interface, &info);

	if (qcsapi_retval >= 0) {
		print_out( print, "Reset complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wps_get_configured_state(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval;
	qcsapi_unsigned_int message_len = WPS_GET_STATE_MAX_LENGTH;
	char wps_state[WPS_GET_STATE_MAX_LENGTH] = "";
	char *p_wps_state = &wps_state[0];

	if (argc > 0) {
		if (strcmp(argv[0], "NULL") == 0) {
			p_wps_state = NULL;
		} else {
			if (qcsapi_util_str_to_uint32(argv[0], &message_len) < 0) {
				qcsapi_report_usage(p_calling_bundle, "[size of message buffer]");
				return 1;
			}
		}
	}

	qcsapi_retval = qcsapi_wps_get_configured_state(the_interface, p_wps_state, message_len);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%s\n", p_wps_state);
		}
	}
	else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wps_get_runtime_state(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval;
	qcsapi_unsigned_int message_len = WPS_GET_STATE_MAX_LENGTH;
	char wps_state[WPS_GET_STATE_MAX_LENGTH] = "";
	char *p_wps_state = &wps_state[0];

	if (argc > 0) {
		if (strcmp(argv[0], "NULL") == 0) {
			p_wps_state = NULL;
		} else {
			if (qcsapi_util_str_to_uint32(argv[0], &message_len) < 0) {
				qcsapi_report_usage(p_calling_bundle, "[size of message buffer]");
                                return 1;
                        }
		}
	}

	qcsapi_retval = qcsapi_wps_get_runtime_state(the_interface, p_wps_state, message_len);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%s\n", p_wps_state);
		}
	}
	else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wps_allow_pbc_overlap(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	uint8_t		allow;

	if (local_verify_enable_or_disable(argv[0], &allow, print) < 0)
		return 1;

	qcsapi_retval = qcsapi_wps_allow_pbc_overlap(the_interface, allow);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}


static int
call_qcsapi_wps_get_allow_pbc_overlap_status(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	int status = -1;
	const char *iface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wps_get_allow_pbc_overlap_status(iface, &status);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%d\n", status);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}


#define WPS_GET_CFG_MAX_LEN 100

static int
local_wps_param_str_to_type(const char *param_name, qcsapi_wps_param_type *param_type)
{
	int iter;

	for (iter = 0; iter < ARRAY_SIZE(qcsapi_wps_param_map_tbl); iter++) {
		if (strcmp(param_name, qcsapi_wps_param_map_tbl[iter].param_name) == 0) {
			*param_type = qcsapi_wps_param_map_tbl[iter].param_type;
			return 1;
		}
	}

	return 0;
}

static int
call_qcsapi_wps_get_param(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	int qcsapi_retval;
	qcsapi_unsigned_int message_len = WPS_GET_CFG_MAX_LEN;
	qcsapi_wps_param_type wps_cfg_str_id;
	qcsapi_output *print = p_calling_bundle->caller_output;
	char wps_cfg_str[WPS_GET_CFG_MAX_LEN] = "";
	const char *usage = "<WiFi interface> <WPS parameter name>\n";

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return 1;
	}

	if (!local_wps_param_str_to_type(argv[0], &wps_cfg_str_id)) {
		report_qcsapi_error(p_calling_bundle, -EINVAL);
		return 1;
	}

	qcsapi_retval = qcsapi_wps_get_param(the_interface, wps_cfg_str_id, wps_cfg_str, message_len);

	if (qcsapi_retval >= 0) {
			print_out(print, "%s\n", wps_cfg_str);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wps_set_param(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	int qcsapi_retval;
	qcsapi_wps_param_type wps_cfg_str_id;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *usage =
		"{ <WiFi interface> | all } <WPS parameter name> <WPS parameter value>\n";

	if (argc != 2) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return 1;
	}

	if (!local_wps_param_str_to_type(argv[0], &wps_cfg_str_id)) {
		report_qcsapi_error(p_calling_bundle, -EINVAL);
		return 1;
	}
	qcsapi_retval = qcsapi_wps_set_param(the_interface, wps_cfg_str_id, argv[1]);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wps_set_configured_state(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	const char *interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint32_t new_value;
	int qcsapi_retval;

	if (argc < 1) {
		print_err( print, "New WPS state argument required");
		return 1;
	}

	if (qcsapi_util_str_to_uint32(argv[0], &new_value) < 0) {
		qcsapi_report_usage(p_calling_bundle, "<ifname> {0 | 1 | 2}");
		return 1;
	}

	qcsapi_retval = qcsapi_wps_set_configured_state(interface, new_value);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_set_dwell_times( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		qcsapi_retval;
	unsigned int	max_dwell_time_active_chan;
	unsigned int	min_dwell_time_active_chan;
	unsigned int	max_dwell_time_passive_chan;
	unsigned int	min_dwell_time_passive_chan;
	int		statval = 0;

	if (argc < 4) {
		print_err( print, "STA Set Dwell Times requires 4 dwell times\n" );
		return(1);
	}

	if (local_str_to_uint32(argv[0], &max_dwell_time_active_chan, print,
			"Max dwell time for active scans") < 0)
		return 1;

	if (local_str_to_uint32(argv[1], &min_dwell_time_active_chan, print,
			"Min dwell time for active scans") < 0)
		return 1;

	if (local_str_to_uint32(argv[2], &max_dwell_time_passive_chan, print,
			"Max dwell time for passive scans") < 0)
		return 1;

	if (local_str_to_uint32(argv[3], &min_dwell_time_passive_chan, print,
			"Min dwell time for passive scans") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_dwell_times(the_interface,
							max_dwell_time_active_chan,
							min_dwell_time_active_chan,
							max_dwell_time_passive_chan,
							min_dwell_time_passive_chan);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n" );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_dwell_times( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		qcsapi_retval;
	unsigned int	max_dwell_time_active_chan;
	unsigned int	min_dwell_time_active_chan;
	unsigned int	max_dwell_time_passive_chan;
	unsigned int	min_dwell_time_passive_chan;
	int		statval = 0;

	qcsapi_retval = qcsapi_wifi_get_dwell_times(the_interface,
							&max_dwell_time_active_chan,
							&min_dwell_time_active_chan,
							&max_dwell_time_passive_chan,
							&min_dwell_time_passive_chan);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%d %d %d %d\n",
				 max_dwell_time_active_chan,
				 min_dwell_time_active_chan,
				 max_dwell_time_passive_chan,
				 min_dwell_time_passive_chan);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_bgscan_dwell_times( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		qcsapi_retval;
	unsigned int	dwell_time_active_chan;
	unsigned int	dwell_time_passive_chan;
	int		statval = 0;

	if (argc < 2) {
		print_err( print, "STA Set BGScan Dwell Times requires 2 dwell times\n" );
		return(1);
	}

	if (local_str_to_uint32(argv[0], &dwell_time_active_chan, print,
			"dwell time for active scans") < 0)
		return 1;

	if (local_str_to_uint32(argv[1], &dwell_time_passive_chan, print,
			"dwell time for passive scans") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_bgscan_dwell_times(the_interface,
			dwell_time_active_chan,	dwell_time_passive_chan);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n" );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_bgscan_dwell_times( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		qcsapi_retval;
	unsigned int	dwell_time_active_chan;
	unsigned int	dwell_time_passive_chan;
	int		statval = 0;

	qcsapi_retval = qcsapi_wifi_get_bgscan_dwell_times(the_interface,
			&dwell_time_active_chan, &dwell_time_passive_chan);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%d %d\n",
				 dwell_time_active_chan, dwell_time_passive_chan);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_count_associations( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_unsigned_int	 association_count, *p_association_count = NULL;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_association_count = &association_count;
	qcsapi_retval = qcsapi_wifi_get_count_associations( the_interface, p_association_count );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%u\n", (unsigned int) association_count );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_associated_device_mac_addr( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_mac_addr		 the_mac_addr;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int	 device_index = p_calling_bundle->caller_generic_parameter.index;

	if (argc > 0 && strcmp( argv[ 0 ], "NULL" ) == 0)
	  qcsapi_retval = qcsapi_wifi_get_associated_device_mac_addr( the_interface, device_index, NULL );
	else
	  qcsapi_retval = qcsapi_wifi_get_associated_device_mac_addr( the_interface, device_index, the_mac_addr );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			dump_mac_addr(p_calling_bundle->caller_output, the_mac_addr );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_associated_device_ip_addr(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int			 statval = 0;
	unsigned int		 ip_addr = 0;
	char			 ip_str[IP_ADDR_STR_LEN + 1];
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int	 device_index = p_calling_bundle->caller_generic_parameter.index;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	if (argc > 0 && strcmp(argv[0], "NULL") == 0)
		qcsapi_retval = qcsapi_wifi_get_associated_device_ip_addr(the_interface, device_index, NULL);
	else
		qcsapi_retval = qcsapi_wifi_get_associated_device_ip_addr(the_interface, device_index, &ip_addr);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			inet_ntop(AF_INET, &ip_addr, ip_str, IP_ADDR_STR_LEN);
			print_out(print, "%s\n", ip_str);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return(statval);
}

static int
call_qcsapi_wifi_get_link_quality( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_unsigned_int	 link_quality, *p_link_quality = NULL;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	 association_index = p_calling_bundle->caller_generic_parameter.index;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_link_quality = &link_quality;
	qcsapi_retval = qcsapi_wifi_get_link_quality( the_interface, association_index, p_link_quality );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%u\n", link_quality );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_rssi_per_association( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_unsigned_int	 rssi, *p_rssi = NULL;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	 association_index = p_calling_bundle->caller_generic_parameter.index;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_rssi = &rssi;
	qcsapi_retval = qcsapi_wifi_get_rssi_per_association( the_interface, association_index, p_rssi );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%u\n", rssi );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_rssi_in_dbm_per_association( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			 statval = 0;
	int			 rssi, *p_rssi = NULL;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int	 association_index = p_calling_bundle->caller_generic_parameter.index;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0) {
		p_rssi = &rssi;
	}

	qcsapi_retval = qcsapi_wifi_get_rssi_in_dbm_per_association( the_interface, association_index, p_rssi );
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%d\n", rssi );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_snr_per_association( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			 statval = 0;
	int			 snr, *p_snr = NULL;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int	 association_index = p_calling_bundle->caller_generic_parameter.index;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_snr = &snr;
	qcsapi_retval = qcsapi_wifi_get_snr_per_association( the_interface, association_index, p_snr );
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%d\n", snr );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_hw_noise_per_association( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	int	 hw_noise;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	 association_index = p_calling_bundle->caller_generic_parameter.index;

	qcsapi_retval = qcsapi_wifi_get_hw_noise_per_association( the_interface, association_index, &hw_noise );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%d.%d\n", hw_noise/10, abs(hw_noise%10) );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_rx_bytes_per_association( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	u_int64_t		 rx_bytes, *p_rx_bytes = NULL;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	 association_index = p_calling_bundle->caller_generic_parameter.index;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_rx_bytes = &rx_bytes;
	qcsapi_retval = qcsapi_wifi_get_rx_bytes_per_association( the_interface, association_index, p_rx_bytes );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%llu\n", rx_bytes );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_tx_bytes_per_association( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	u_int64_t		 tx_bytes, *p_tx_bytes = NULL;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	 association_index = p_calling_bundle->caller_generic_parameter.index;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_tx_bytes = &tx_bytes;
	qcsapi_retval = qcsapi_wifi_get_tx_bytes_per_association( the_interface, association_index, p_tx_bytes );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%llu\n", tx_bytes );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_rx_packets_per_association( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_unsigned_int	rx_packets, *p_rx_packets = NULL;
	int			qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	association_index = p_calling_bundle->caller_generic_parameter.index;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_rx_packets = &rx_packets;

	qcsapi_retval = qcsapi_wifi_get_rx_packets_per_association( the_interface, association_index, p_rx_packets );
	if (qcsapi_retval >= 0)	{
		if (verbose_flag >= 0) {
			print_out(print, "%u\n", rx_packets);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_tx_packets_per_association( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			statval = 0;
	qcsapi_unsigned_int	tx_packets, *p_tx_packets = NULL;
	int			qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	association_index = p_calling_bundle->caller_generic_parameter.index;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_tx_packets = &tx_packets;
	qcsapi_retval = qcsapi_wifi_get_tx_packets_per_association( the_interface, association_index, p_tx_packets );
	if (qcsapi_retval >= 0)	{
		if (verbose_flag >= 0) {
			print_out(print, "%u\n", tx_packets);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_tx_err_packets_per_association( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			statval = 0;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	tx_err_packets, *p_tx_err_packets = NULL;
	int			qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int	association_index = p_calling_bundle->caller_generic_parameter.index;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
		p_tx_err_packets = &tx_err_packets;

	qcsapi_retval = qcsapi_wifi_get_tx_err_packets_per_association( the_interface, association_index, p_tx_err_packets );
	if (qcsapi_retval >= 0)	{
		if (verbose_flag >= 0) {
			print_out(print, "%u\n", tx_err_packets);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_bw_per_association( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			 statval = 0;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	 association_index = p_calling_bundle->caller_generic_parameter.index;
	qcsapi_unsigned_int	 bw, *p_bw = NULL;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_bw = &bw;
	qcsapi_retval = qcsapi_wifi_get_bw_per_association( the_interface, association_index, p_bw );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%u\n", bw );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_tx_phy_rate_per_association( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			 statval = 0;
	qcsapi_unsigned_int	 tx_rate, *p_tx_rate = NULL;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	int		 	 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int	 association_index = p_calling_bundle->caller_generic_parameter.index;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_tx_rate = &tx_rate;
	qcsapi_retval = qcsapi_wifi_get_tx_phy_rate_per_association( the_interface, association_index, p_tx_rate );
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%u\n", tx_rate);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_rx_phy_rate_per_association( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			 statval = 0;
	qcsapi_unsigned_int	 rx_rate, *p_rx_rate = NULL;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	int		 	 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int	 association_index = p_calling_bundle->caller_generic_parameter.index;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_rx_rate = &rx_rate;
	qcsapi_retval = qcsapi_wifi_get_rx_phy_rate_per_association( the_interface, association_index, p_rx_rate );
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%u\n", rx_rate);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_tx_mcs_per_association( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int statval = 0;
	qcsapi_unsigned_int tx_mcs;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int association_index = p_calling_bundle->caller_generic_parameter.index;

	qcsapi_retval = qcsapi_wifi_get_tx_mcs_per_association(the_interface,
			association_index, &tx_mcs);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%u\n", tx_mcs);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_rx_mcs_per_association(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	qcsapi_unsigned_int rx_mcs;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int association_index = p_calling_bundle->caller_generic_parameter.index;

	qcsapi_retval = qcsapi_wifi_get_rx_mcs_per_association(the_interface,
			association_index, &rx_mcs);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%u\n", rx_mcs);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_achievable_tx_phy_rate_per_association( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			 statval = 0;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	 achievable_tx_rate, *p_achievable_tx_rate = NULL;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int	 association_index = p_calling_bundle->caller_generic_parameter.index;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
		p_achievable_tx_rate = &achievable_tx_rate;

	qcsapi_retval = qcsapi_wifi_get_achievable_tx_phy_rate_per_association( the_interface, association_index, p_achievable_tx_rate );
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%u\n", achievable_tx_rate);
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_achievable_rx_phy_rate_per_association( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			 statval = 0;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	 achievable_rx_rate, *p_achievable_rx_rate = NULL;
	int	 		 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int	 association_index = p_calling_bundle->caller_generic_parameter.index;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
		p_achievable_rx_rate = &achievable_rx_rate;

	qcsapi_retval = qcsapi_wifi_get_achievable_rx_phy_rate_per_association( the_interface, association_index, p_achievable_rx_rate );
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%u\n", achievable_rx_rate);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_auth_enc_per_association( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			 statval = 0;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int	 association_index = p_calling_bundle->caller_generic_parameter.index;
	qcsapi_unsigned_int	 auth_enc;
	uint8_t			*casted_ptr = (uint8_t*)&auth_enc;

	qcsapi_retval = qcsapi_wifi_get_auth_enc_per_association( the_interface, association_index, &auth_enc );
	if (qcsapi_retval >= 0) {
		if (casted_ptr[IEEE80211_AUTHDESCR_ALGO_POS] >= ARRAY_SIZE(qcsapi_auth_algo_list) ||
		    casted_ptr[IEEE80211_AUTHDESCR_KEYMGMT_POS] >= ARRAY_SIZE(qcsapi_auth_keymgmt_list) ||
		    casted_ptr[IEEE80211_AUTHDESCR_KEYPROTO_POS] >=  ARRAY_SIZE(qcsapi_auth_keyproto_list) ||
		    casted_ptr[IEEE80211_AUTHDESCR_CIPHER_POS] >= ARRAY_SIZE(qcsapi_auth_cipher_list)) {

			print_err(print, "error:unknown auth enc value \"%08X\"\n", auth_enc);
			return 1;
		}

		if (verbose_flag >= 0) {
			if (casted_ptr[IEEE80211_AUTHDESCR_KEYPROTO_POS]) {
				print_out(print, "%s/%s with %s\n",
					  qcsapi_auth_keyproto_list[casted_ptr[IEEE80211_AUTHDESCR_KEYPROTO_POS]],
					  qcsapi_auth_keymgmt_list[casted_ptr[IEEE80211_AUTHDESCR_KEYMGMT_POS]],
					  qcsapi_auth_cipher_list[casted_ptr[IEEE80211_AUTHDESCR_CIPHER_POS]]);
			} else {
				print_out(print, "%s/%s\n",
					  qcsapi_auth_algo_list[casted_ptr[IEEE80211_AUTHDESCR_ALGO_POS]],
					  qcsapi_auth_keymgmt_list[casted_ptr[IEEE80211_AUTHDESCR_KEYMGMT_POS]]);
			}
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_vendor_per_association( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			 statval = 0;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int	 association_index = p_calling_bundle->caller_generic_parameter.index;
	qcsapi_unsigned_int	 vendor;

	qcsapi_retval = qcsapi_wifi_get_vendor_per_association(the_interface, association_index, &vendor);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			switch (vendor) {
			case PEER_VENDOR_QTN:
				print_out(print, "quantenna\n");
				break;
			case PEER_VENDOR_BRCM:
				print_out(print, "broadcom\n");
				break;
			case PEER_VENDOR_ATH:
				print_out(print, "atheros\n");
				break;
			case PEER_VENDOR_RLNK:
				print_out(print, "ralink\n");
				break;
			case PEER_VENDOR_RTK:
				print_out(print, "realtek\n");
				break;
			case PEER_VENDOR_INTEL:
				print_out(print, "intel\n");
				break;
			case PEER_VENDOR_APPLE:
				print_out(print, "apple\n");
				break;
			default:
				print_out(print, "unknown\n");
				break;
			}
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}
	return( statval );
}

static int
call_qcsapi_wifi_get_max_mimo( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			 statval = 0;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int	 association_index = p_calling_bundle->caller_generic_parameter.index;
	string_16		max_mimo;

	qcsapi_retval = qcsapi_wifi_get_max_mimo(the_interface, association_index, max_mimo);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%s\n", max_mimo);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}
	return statval;
}

static int
call_qcsapi_wifi_get_tput_caps(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int association_index = p_calling_bundle->caller_generic_parameter.index;
	int qcsapi_retval;
	struct ieee8011req_sta_tput_caps tput_caps;
	struct ieee80211_ie_vhtcap *ie_vhtcap;
	struct ieee80211_ie_htcap *ie_htcap;

	qcsapi_retval = qcsapi_wifi_get_tput_caps(the_interface, association_index, &tput_caps);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			switch (tput_caps.mode) {
			case IEEE80211_WIFI_MODE_AC:
				print_out(print, "Mode: VHT\n");
				ie_vhtcap = (struct ieee80211_ie_vhtcap*)tput_caps.vhtcap_ie;

				print_out(print, "VHT Capabilities Info: ");
				dump_data_array(print, ie_vhtcap->vht_cap,
						sizeof(ie_vhtcap->vht_cap), 16, ' ');

				print_out(print, "Supported VHT MCS & NSS Set: ");
				dump_data_array(print, ie_vhtcap->vht_mcs_nss_set,
						sizeof(ie_vhtcap->vht_mcs_nss_set), 16, ' ');
				/* Fall through */
			case IEEE80211_WIFI_MODE_NA:
				/* Fall through */
			case IEEE80211_WIFI_MODE_NG:
				if (tput_caps.mode != IEEE80211_WIFI_MODE_AC) {
					print_out(print, "Mode: HT\n");
				}
				ie_htcap = (struct ieee80211_ie_htcap*)tput_caps.htcap_ie;

				print_out(print, "HT Capabilities Info: ");
				dump_data_array(print, ie_htcap->hc_cap,
						sizeof(ie_htcap->hc_cap), 16, ' ');

				print_out(print, "A-MPDU Parameters: %02X\n", ie_htcap->hc_ampdu);

				print_out(print, "Supported MCS Set: ");
				dump_data_array(print, ie_htcap->hc_mcsset,
						sizeof(ie_htcap->hc_mcsset), 16, ' ');

				print_out(print, "HT Extended Capabilities: ");
				dump_data_array(print, ie_htcap->hc_extcap,
						sizeof(ie_htcap->hc_extcap), 16, ' ');

				print_out(print, "Transmit Beamforming Capabilities: ");
				dump_data_array(print, ie_htcap->hc_txbf,
						sizeof(ie_htcap->hc_txbf), 16, ' ');

				print_out(print, "ASEL Capabilities: %02X\n", ie_htcap->hc_antenna);
				break;
			default:
				print_out(print, "Mode: non HT\n");
				break;
			}
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}
	return statval;
}

static int
call_qcsapi_wifi_get_connection_mode(call_qcsapi_bundle *p_calling_bundle,
				     int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int association_index = p_calling_bundle->caller_generic_parameter.index;
	int qcsapi_retval;
	qcsapi_unsigned_int connection_mode;

	qcsapi_retval = qcsapi_wifi_get_connection_mode(the_interface,
							association_index,
							&connection_mode);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			if (connection_mode >= IEEE80211_WIFI_MODE_MAX) {
				connection_mode = IEEE80211_WIFI_MODE_NONE;
			}
			print_out(print, "%s\n", qcsapi_wifi_modes_strings[connection_mode]);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}
	return statval;
}

static int
call_qcsapi_wifi_get_node_counter(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int node_index = p_calling_bundle->caller_generic_parameter.index;
	qcsapi_counter_type counter_type = QCSAPI_NOSUCH_COUNTER;
	int local_remote_flag = QCSAPI_LOCAL_NODE;
	uint64_t counter_value = 0;
	uint64_t *p_counter_value = &counter_value;

	if (argc < 1) {
		print_err(print, "Get Counter Per Association: type of counter required\n");
		return 1;
	}

	if (name_to_counter_enum(argv[0], &counter_type ) == 0) {
		print_err(print, "No such counter type %s\n", argv[0]);
		return 1;
	}

	if (argc > 1) {
		if (parse_local_remote_flag(print, argv[1], &local_remote_flag) < 0) {
			return 1;
		}
	}

	if (argc > 2 && strcmp(argv[2], "NULL" ) == 0) {
		p_counter_value = NULL;
	}

	qcsapi_retval = qcsapi_wifi_get_node_counter(the_interface,
						     node_index,
						     counter_type,
						     local_remote_flag,
						     p_counter_value);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%llu\n", counter_value);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int parse_measure_request_param(qcsapi_output *print, qcsapi_per_assoc_param type,
		int argc, char *argv[], uint16_t *set_id, struct qtn_nis_set *nis)
{
	int i;
	int ret = 0;
	int qualified = 0;
	int pre_len;
	int bad_format = 0;
	int mac[6];
	uint64_t tmp;

	switch (type) {
	case QCSAPI_NODE_MEAS_BASIC:
		*set_id = QTN_NIS_11H_11K_BASIC;
		for (i = 0; i < argc; i++) {
			if ((strncmp(argv[i], "ch=", (pre_len = strlen("ch="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 2, channel, atoi(argv[i] + pre_len));
			} else if ((strncmp(argv[i], "off=", (pre_len = strlen("off="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 2, offset, atoi(argv[i] + pre_len));
			} else if ((strncmp(argv[i], "du=", (pre_len = strlen("du="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 2, duration, atoi(argv[i] + pre_len));
				qualified++;
			} else {
				print_err(print, "error:unknown parameter \"%s\"\n", argv[i]);
				bad_format = 1;
				break;
			}
		}

		if (!qualified || bad_format) {
			print_out(print, "basic measurement param:\n"
					"<du=duration> [ch=channel] "
					"[off=offset to start measuremnt]\n");
			ret = 1;
		}
		break;
	case QCSAPI_NODE_MEAS_CCA:
		*set_id = QTN_NIS_11H_11K_CCA;
		for (i = 0; i < argc; i++) {
			if ((strncmp(argv[i], "ch=", (pre_len = strlen("ch="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 3, channel, atoi(argv[i] + pre_len));
			} else if ((strncmp(argv[i], "off=", (pre_len = strlen("off="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 3, offset, atoi(argv[i] + pre_len));
			} else if ((strncmp(argv[i], "du=", (pre_len = strlen("du="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 3, duration, atoi(argv[i] + pre_len));
				qualified++;
			} else {
				print_err(print, "error:unknown parameter \"%s\"\n", argv[i]);
				bad_format = 1;
				break;
			}
		}

		if (!qualified || bad_format) {
			print_out(print, "cca measurement param:\n"
					"<du=duration> [ch=channel] "
					"[off=offset to start measuremnt]\n");
			ret = 1;
		}
		break;
	case QCSAPI_NODE_MEAS_RPI:
		*set_id = QTN_NIS_11H_11K_RPI;
		for (i = 0; i < argc; i++) {
			if ((strncmp(argv[i], "ch=", (pre_len = strlen("ch="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 4, channel, atoi(argv[i] + pre_len));
			} else if ((strncmp(argv[i], "off=", (pre_len = strlen("off="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 4, offset, atoi(argv[i] + pre_len));
			} else if ((strncmp(argv[i], "du=", (pre_len = strlen("du="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 4, duration, atoi(argv[i] + pre_len));
				qualified++;
			} else {
				print_err(print, "error:unknown parameter \"%s\"\n", argv[i]);
				bad_format = 1;
			}
		}

		if (!qualified || bad_format) {
			print_out(print, "rpi measurement param:\n"
					"<du=duration> [ch=channel] "
					"[off=offset to start measuremnt]\n");
			ret = 1;
		}
		break;
	case QCSAPI_NODE_MEAS_CHAN_LOAD:
		*set_id = QTN_NIS_11H_11K_CHAN_LOAD;
		for (i = 0; i < argc; i++) {
			if ((strncmp(argv[i], "ch=", (pre_len = strlen("ch="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 5, channel, atoi(argv[i] + pre_len));
			} else if ((strncmp(argv[i], "op=", (pre_len = strlen("op="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 5, op_class, atoi(argv[i] + pre_len));
			} else if ((strncmp(argv[i], "du=", (pre_len = strlen("du="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 5, duration, atoi(argv[i] + pre_len));
				qualified++;
			} else {
				print_err(print, "error:unknown parameter \"%s\"\n", argv[i]);
				bad_format = 1;
				break;
			}
		}

		if (!qualified || bad_format) {
			print_out(print, "channel load measurement param:\n"
					"<du=duration> [ch=channel] "
					"[op=operating class]\n");
			ret = 1;
		}
		break;
	case QCSAPI_NODE_MEAS_NOISE_HIS:
		*set_id = QTN_NIS_11H_11K_NOISE_HIS;
		for (i = 0; i < argc; i++) {
			if ((strncmp(argv[i], "ch=", (pre_len = strlen("ch="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 6, channel, atoi(argv[i] + pre_len));
			} else if ((strncmp(argv[i], "op=", (pre_len = strlen("op="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 6, op_class, atoi(argv[i] + pre_len));
			} else if ((strncmp(argv[i], "du=", (pre_len = strlen("du="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 6, duration, atoi(argv[i] + pre_len));
				qualified++;
			} else {
				print_err(print, "error:unknown parameter \"%s\"\n", argv[i]);
				bad_format = 1;
				break;
			}
		}

		if (!qualified || bad_format) {
			print_out(print, "noise histogram measurement param:\n"
					"<du=duration> [ch=channel] "
					"[op=operating class]\n");
			ret = 1;
		}
		break;
	case QCSAPI_NODE_MEAS_BEACON:
		*set_id = QTN_NIS_11H_11K_BEACON;
		for (i = 0; i < argc; i++) {
			if ((strncmp(argv[i], "ch=", (pre_len = strlen("ch="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 7, channel, atoi(argv[i] + pre_len));
			} else if ((strncmp(argv[i], "op=", (pre_len = strlen("op="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 7, op_class, atoi(argv[i] + pre_len));
			} else if ((strncmp(argv[i], "du=", (pre_len = strlen("du="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 7, duration, atoi(argv[i] + pre_len));
				qualified++;
			} else if ((strncmp(argv[i], "mode=", (pre_len = strlen("mode="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 7, mode, atoi(argv[i] + pre_len));
			} else {
				bad_format = 1;
				print_err(print, "error:unknown parameter \"%s\"\n", argv[i]);
				break;
			}
		}

		if (!qualified || bad_format) {
			print_out(print, "beacon measurement param:\n"
					"<du=duration> [ch=channel] "
					"[mode=beacon measurement mode][op=operating class]\n");
			ret = 1;
		}
		break;
	case QCSAPI_NODE_MEAS_FRAME:
		*set_id = QTN_NIS_11H_11K_FRAME;
		for (i = 0; i < argc; i++) {
			if ((strncmp(argv[i], "ch=", (pre_len = strlen("ch="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 8, channel, atoi(argv[i] + pre_len));
			} else if ((strncmp(argv[i], "op=", (pre_len = strlen("op="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 8, op_class, atoi(argv[i] + pre_len));
			} else if ((strncmp(argv[i], "du=", (pre_len = strlen("du="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 8, duration, atoi(argv[i] + pre_len));
				qualified++;
			} else if ((strncmp(argv[i], "type=", (pre_len = strlen("type="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 8, type, atoi(argv[i] + pre_len));
				qualified++;
			} else if ((strncmp(argv[i], "mac=", (pre_len = strlen("mac="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				if (sscanf(argv[i] + pre_len, "%x:%x:%x:%x:%x:%x", &mac[0],
							&mac[1],
							&mac[2],
							&mac[3],
							&mac[4],
							&mac[5]) != 6){
					bad_format = 1;
					break;
				}

				memcpy(&tmp, mac, sizeof(IEEE80211_ADDR_LEN));
				QTN_NIS_SET(nis, 8, mac_addr, tmp);
			} else {
				bad_format = 1;
				print_err(print, "error:unknown parameter \"%s\"\n", argv[i]);
				break;
			}
		}

		if ((qualified < 2) || bad_format) {
			print_out(print, "frame measurement param:\n"
					"<du=duration>\n"
					"<type=measurement frame type, only 1 supported currently>\n"
					"[ch=channel] [op=operating class] [mac=specified mac address]\n");
			ret = 1;
		}
		break;
	case QCSAPI_NODE_MEAS_TRAN_STREAM_CAT:
		*set_id = QTN_NIS_11H_11K_TRANS_STREAM_CAT;
		for (i = 0; i < argc; i++) {
			if ((strncmp(argv[i], "tid=", (pre_len = strlen("tid="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 9, tid, atoi(argv[i] + pre_len));
				qualified++;
			} else if ((strncmp(argv[i], "bin0=", (pre_len = strlen("bin0="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 9, bin0, atoi(argv[i] + pre_len));
			} else if ((strncmp(argv[i], "du=", (pre_len = strlen("du="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 9, duration, atoi(argv[i] + pre_len));
				qualified++;
			} else if ((strncmp(argv[i], "peer_sta=", (pre_len = strlen("peer_sta="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				if (sscanf(argv[i] + pre_len, "%x:%x:%x:%x:%x:%x", &mac[0],
							&mac[1],
							&mac[2],
							&mac[3],
							&mac[4],
							&mac[5]) != 6) {
					bad_format = 1;
					break;
				}

				memcpy(&tmp, mac, sizeof(IEEE80211_ADDR_LEN));
				QTN_NIS_SET(nis, 9, peer_sta, tmp);
			} else {
				bad_format = 1;
				print_err(print, "error:unknown parameter \"%s\"\n", argv[i]);
				break;
			}
		}

		if ((qualified < 2) || bad_format) {
			print_out(print, "transmit stream category measurement param:\n"
					"<du=duration>\n"
					"<tid=traffic id>\n"
					"[peer_sta=peer station mac address] [bin0=bin0 range]\n");
			ret = 1;
		}
		break;
	case QCSAPI_NODE_MEAS_MULTICAST_DIAG:
		*set_id = QTN_NIS_11H_11K_MULTICAST_DIAG;
		for (i = 0; i < argc; i++) {
			if ((strncmp(argv[i], "du=", (pre_len = strlen("du="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				QTN_NIS_SET(nis, 10, duration, atoi(argv[i] + pre_len));
				qualified++;
			} else if ((strncmp(argv[i], "group_mac=", (pre_len = strlen("group_mac="))) == 0) &&
					(strlen(argv[i]) > pre_len)) {
				if (sscanf(argv[i] + pre_len, "%x:%x:%x:%x:%x:%x", &mac[0],
							&mac[1],
							&mac[2],
							&mac[3],
							&mac[4],
							&mac[5]) != 6) {
					bad_format = 1;
					break;
				}

				memcpy(&tmp, mac, sizeof(IEEE80211_ADDR_LEN));
				QTN_NIS_SET(nis, 10, group_mac, tmp);
				qualified++;
			} else {
				bad_format = 1;
				print_err(print, "error:unknown parameter \"%s\"\n", argv[i]);
				break;
			}
		}

		if ((qualified < 2) || bad_format) {
			print_out(print, "multicast diagnostic measurement param:\n"
					"<du=duration>\n"
					"<group_mac=group mac address>\n");
			ret = 1;
		}
		break;
	case QCSAPI_NODE_LINK_MEASURE:
		*set_id = QTN_NIS_11H_11K_LINK;
		break;
	case QCSAPI_NODE_NEIGHBOR_REP:
		*set_id = QTN_NIS_11H_11K_NEIGHBOR;
		break;
	case QCSAPI_NODE_TPC_REP:
		*set_id = QTN_NIS_11H_11K_TPC;
		break;
	default:
		*set_id = QTN_NIS_11H_11K_COMMON;
		break;
	}

	return ret;
}

static void local_node_infoset_11h_11k_common_print(qcsapi_output *print,
				qcsapi_per_assoc_param param_type,
				const uint16_t set_id,
				struct qtn_nis_set *nis)
{
	int64_t  *p_param_value = (int64_t*)&nis->val[0];
	qcsapi_mac_addr	macaddr;

	switch (param_type) {
	case QCSAPI_SOC_MAC_ADDR:
		memcpy(macaddr, p_param_value, sizeof(qcsapi_mac_addr));
		dump_mac_addr(print, macaddr);
		break;
	case QCSAPI_SOC_IP_ADDR:
		print_out(print, "IPv4 address " NIPQUAD_FMT "\n", NIPQUAD(p_param_value));
		break;
	case QCSAPI_NODE_SGI_CAPS:
		/**
		 * The variable 'report_result.common[0]' returns the SGI Capability of the node.
		 *	- If 'report_result.common[0]' is 0, the station is not SGI capable.
		 *	- If 'report_result.common[0]' is non-zero, the station is SGI capable.
		 *	  The following bitmap represents SGI capabilities in different Bandwidths
		 *		- if bit 0 is set, the Station is SGI capable in 20MHz
		 *		- if bit 1 is set, the Station is SGI capable in 40MHz
		 *		- if bit 2 is set, the Station is SGI capable in 80MHz
		 *		- if bit 3 is set, the Station is SGI capable in 160MHz
		 */
		print_out(print, "sgi_caps = 0x%llx\n", *p_param_value);
		break;
	default:
		print_out(print, "%lld\n", *p_param_value);
		break;
	}
}

static char *
local_node_infoset_print_type_mfp(uint64_t val)
{
	if (val & RSN_CAP_MFP_REQ)
		return "required";
	else if (val & RSN_CAP_MFP_CAP)
		return "capable";

	return "disabled";
}

static void
local_node_infoset_print_core(qcsapi_output *print, enum qtn_nis_val_type_s nis_type,
			char *label, const uint16_t set_id, int fld, uint64_t val)
{
	uint8_t *macaddr;
	uint16_t val16;

	print_out(print, "%-*s: ", QTN_NIS_LABEL_LEN, label);

	switch (nis_type) {
	case QTN_NIS_VAL_UNSIGNED:
		print_out(print, "%llu\n", val);
		break;
	case QTN_NIS_VAL_SIGNED:
		print_out(print, "%lld\n", (int64_t)val);
		break;
	case QTN_NIS_VAL_FLAG:
		print_out(print, "%llu%s\n", val, val ? "" : ", no result reported");
		break;
	case QTN_NIS_VAL_MACADDR:
		macaddr = (uint8_t *)&val;
		print_out(print, MACSTR "\n", MAC2STR(macaddr));
		break;
	case QTN_NIS_VAL_INDEX:
		print_out(print, "%lld\n", (int64_t)val);
		break;
	case QTN_NIS_VAL_RSN_CAPS:
		val16 = val;
		print_out(print, "0x%04x MFP:%s\n", val16,
			local_node_infoset_print_type_mfp(val));
		break;
	}

	return;
}

static int
local_node_infoset_print(qcsapi_output *print, const uint16_t set_id,
				struct qtn_nis_set *nis)
{
	int index;

	COMPILE_TIME_ASSERT(ARRAY_SIZE(qtn_nis_meta) < ARRAY_SIZE(nis->val));

	if (set_id > (ARRAY_SIZE(qtn_nis_meta) - 1)) {
		print_out(print, "Invalid set id %u\n", set_id);
		return 1;
	}

	print_out(print, "%-*s: " MACSTR "\n", QTN_NIS_LABEL_LEN,
			"MAC address", MAC2STR(nis->mac_addr));
	print_out(print, "%-*s: %u\n", QTN_NIS_LABEL_LEN, "Node index", nis->node_index);

	index = qtn_nis_val_result_idx[set_id];
	for (; index < ARRAY_SIZE(nis->val); index++) {
		if (QTN_NIS_IS_SET(nis, index)) {
			local_node_infoset_print_core(print,
						qtn_nis_meta[set_id][index].type,
						qtn_nis_meta[set_id][index].label,
						set_id, index, nis->val[index]);
		}
	}

	return 0;
}

static int
local_wifi_more_infoset_print(call_qcsapi_bundle *p_calling_bundle,
	const char *ifname, const uint16_t node_index, const qcsapi_mac_addr mac_addr,
	struct qtn_nis_set *nis, qcsapi_output *print, qcsapi_per_assoc_param param_type)
{
	int qcsapi_retval;
	int i;
	uint8_t total_reports;
	uint8_t report_num;

	total_reports = nis->val[QTN_NIS_S7_total_reports];
	report_num = nis->val[QTN_NIS_S7_report_num];
	for (i = report_num; i < total_reports; i++) {
		nis->bitmap = 0;
		qcsapi_retval = qcsapi_wifi_get_node_infoset(ifname, node_index,
				mac_addr, nis->set_id, nis);
		if (qcsapi_retval < 0) {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			return 1;
		}

		if (local_node_infoset_print(print, nis->set_id, nis) != 0)
			return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_get_node_param(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint32_t node_index = 0;
	qcsapi_per_assoc_param param_type = QCSAPI_NO_SUCH_PER_ASSOC_PARAM;
	const char *usage = "<WiFi interface> { <MAC addr> | <node index> } <parameter name> "
				"<local remote flag> <parameters indicated by type>";
	int local_remote_flag = QCSAPI_LOCAL_NODE;
	qcsapi_mac_addr mac_addr;
	struct qtn_nis_set nis;
	uint16_t set_id = QTN_NIS_SET_ID_INVALID;

	memset(&nis, 0, sizeof(nis));

	if (argc < 2) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return 1;
	}

	if (qcsapi_util_str_to_uint32(argv[0], &node_index) < 0 || node_index == 0) {
		statval = parse_mac_addr(argv[0], mac_addr);
		if (statval < 0) {
			qcsapi_report_usage(p_calling_bundle, usage);
			return 1;
		}
	}

	if (name_to_per_assoc_parameter(argv[1], &param_type) == 0) {
		print_err(print, "No such parameter type %s\n", argv[1]);
		return 1;
	}

	if (argc > 2 && parse_local_remote_flag(print, argv[2], &local_remote_flag) < 0)
		return 1;

	nis.flags |= SM(local_remote_flag, QTN_NIS_FLAG_MEAS_TYPE);

	if (argc >= 3) {
		argc -= 3;
		argv += 3;
		if (parse_measure_request_param(print, param_type, argc, argv, &set_id, &nis))
			return 1;
	}

	if (set_id == QTN_NIS_SET_ID_INVALID) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return 1;
	}

	nis.set_id = set_id;
	nis.flags |= SM(param_type, QTN_NIS_FLAG_MEAS_PARAM_TYPE);

	qcsapi_retval = qcsapi_wifi_get_node_infoset(the_interface, node_index, mac_addr,
				nis.set_id, &nis);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	if (nis.set_id == QTN_NIS_11H_11K_COMMON)
		local_node_infoset_11h_11k_common_print(print, param_type, nis.set_id, &nis);
	else
		statval = local_node_infoset_print(print, nis.set_id, &nis);

	/*
	* Special handle for beacon measurement report where multiple qcsapi calls
	* might be needed to get all returned results.
	*/
	if (nis.set_id == QTN_NIS_11H_11K_BEACON)
		statval = local_wifi_more_infoset_print(p_calling_bundle,
			the_interface, node_index, mac_addr, &nis, print, param_type);

	return statval;
}

#define CALL_QCSAPI_NODE_STATS_LABEL_LEN			20

#define CALL_QCSAPI_NODE_STATS_PRINT(_name, _type, _val)	\
	print_out(print, "%-*s%s%" _type "\n",			\
		CALL_QCSAPI_NODE_STATS_LABEL_LEN, _name, ": ", _val)

static void print_mcs_mode(qcsapi_output *print, uint8_t is_tx, uint8_t mcs_mode)
{
	switch(mcs_mode) {
		case QTN_PHY_STATS_MODE_11N:
			is_tx ? CALL_QCSAPI_NODE_STATS_PRINT("tx_mcs_mode", "s", "11N") :
				CALL_QCSAPI_NODE_STATS_PRINT("rx_mcs_mode", "s", "11N");
			break;
		case QTN_PHY_STATS_MODE_11AC:
			is_tx ? CALL_QCSAPI_NODE_STATS_PRINT("tx_mcs_mode", "s", "11AC") :
				CALL_QCSAPI_NODE_STATS_PRINT("rx_mcs_mode", "s", "11AC");
			break;
		default:
			is_tx ? CALL_QCSAPI_NODE_STATS_PRINT("tx_mcs_mode", "s", "UNKNOWN") :
				CALL_QCSAPI_NODE_STATS_PRINT("rx_mcs_mode", "s", "UNKNOWN");
			break;
	}
}

static int
call_qcsapi_wifi_get_node_stats(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int				 statval = 0;
	int				 qcsapi_retval;
	const char			*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output			*print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int		 node_index = p_calling_bundle->caller_generic_parameter.index;
	int				 local_remote_flag = QCSAPI_LOCAL_NODE;
	struct qcsapi_node_stats	 node_stats, *p_node_stats = &node_stats;

	memset(&node_stats, 0, sizeof(node_stats));

	if (argc > 0) {
		if (parse_local_remote_flag(print, argv[0], &local_remote_flag) < 0) {
			return 1;
		}
	}

	if (argc > 1 && strcmp(argv[1], "NULL" ) == 0) {
		p_node_stats = NULL;
	}

	qcsapi_retval = qcsapi_wifi_get_node_stats(the_interface,
						   node_index,
						   local_remote_flag,
						   p_node_stats);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			if (node_stats.snr < 0) {
				node_stats.snr = (node_stats.snr - QCSAPI_RSSI_OR_SNR_NZERO_CORRECT_VALUE) / QCSAPI_RSSI_OR_SNR_FACTOR;
			} else {
				node_stats.snr = (node_stats.snr + QCSAPI_RSSI_OR_SNR_NZERO_CORRECT_VALUE) / QCSAPI_RSSI_OR_SNR_FACTOR;
			}
			node_stats.snr = (0 - node_stats.snr);

			if (node_stats.rssi < 0) {
				node_stats.rssi = 0;
			} else {
				node_stats.rssi = (qcsapi_unsigned_int)(node_stats.rssi +
							QCSAPI_RSSI_OR_SNR_NZERO_CORRECT_VALUE) / QCSAPI_RSSI_OR_SNR_FACTOR;
			}
			CALL_QCSAPI_NODE_STATS_PRINT("tx_bytes", "llu", node_stats.tx_bytes);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_pkts", "lu", node_stats.tx_pkts);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_discard", "lu", node_stats.tx_discard);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_wifi_sent_be", "lu",
							node_stats.tx_wifi_sent[WMM_AC_BE]);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_wifi_sent_bk", "lu",
							node_stats.tx_wifi_sent[WMM_AC_BK]);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_wifi_sent_vi", "lu",
							node_stats.tx_wifi_sent[WMM_AC_VI]);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_wifi_sent_vo", "lu",
							node_stats.tx_wifi_sent[WMM_AC_VO]);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_wifi_drop_be", "lu",
							node_stats.tx_wifi_drop[WMM_AC_BE]);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_wifi_drop_bk", "lu",
							node_stats.tx_wifi_drop[WMM_AC_BK]);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_wifi_drop_vi", "lu",
							node_stats.tx_wifi_drop[WMM_AC_VI]);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_wifi_drop_vo", "lu",
							node_stats.tx_wifi_drop[WMM_AC_VO]);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_wifi_drop_be_xattempts", "u",
							node_stats.tx_wifi_drop_xattempts[WMM_AC_BE]);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_wifi_drop_bk_xattempts", "u",
							node_stats.tx_wifi_drop_xattempts[WMM_AC_BK]);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_wifi_drop_vi_xattempts", "u",
							node_stats.tx_wifi_drop_xattempts[WMM_AC_VI]);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_wifi_drop_vo_xattempts", "u",
							node_stats.tx_wifi_drop_xattempts[WMM_AC_VO]);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_err", "lu", node_stats.tx_err);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_unicast", "lu", node_stats.tx_unicast);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_multicast", "lu", node_stats.tx_multicast);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_broadcast", "lu", node_stats.tx_broadcast);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_phy_rate", "lu", node_stats.tx_phy_rate);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_mgmt", "lu", node_stats.tx_mgmt);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_mcs_index", "lu", node_stats.tx_mcs);
			print_mcs_mode(print, 1, node_stats.tx_mcs_mode);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_nss", "lu", node_stats.tx_nss);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_bw", "lu", node_stats.tx_bw);
			CALL_QCSAPI_NODE_STATS_PRINT("tx_sgi", "lu", node_stats.tx_sgi);
			CALL_QCSAPI_NODE_STATS_PRINT("rx_bytes", "llu", node_stats.rx_bytes);
			CALL_QCSAPI_NODE_STATS_PRINT("rx_pkts", "lu", node_stats.rx_pkts);
			CALL_QCSAPI_NODE_STATS_PRINT("rx_discard", "lu", node_stats.rx_discard);
			CALL_QCSAPI_NODE_STATS_PRINT("rx_err", "lu", node_stats.rx_err);
			CALL_QCSAPI_NODE_STATS_PRINT("rx_unicast", "lu", node_stats.rx_unicast);
			CALL_QCSAPI_NODE_STATS_PRINT("rx_multicast", "lu", node_stats.rx_multicast);
			CALL_QCSAPI_NODE_STATS_PRINT("rx_broadcast", "lu", node_stats.rx_broadcast);
			CALL_QCSAPI_NODE_STATS_PRINT("rx_unknown", "u", node_stats.rx_unknown);
			CALL_QCSAPI_NODE_STATS_PRINT("rx_phy_rate", "lu", node_stats.rx_phy_rate);
			CALL_QCSAPI_NODE_STATS_PRINT("rx_mgmt", "lu", node_stats.rx_mgmt);
			CALL_QCSAPI_NODE_STATS_PRINT("rx_ctrl", "lu", node_stats.rx_ctrl);
			CALL_QCSAPI_NODE_STATS_PRINT("rx_mcs_index", "lu", node_stats.rx_mcs);
			print_mcs_mode(print, 0, node_stats.rx_mcs_mode);
			CALL_QCSAPI_NODE_STATS_PRINT("rx_nss", "lu", node_stats.rx_nss);
			CALL_QCSAPI_NODE_STATS_PRINT("rx_bw", "lu", node_stats.rx_bw);
			CALL_QCSAPI_NODE_STATS_PRINT("rx_sgi", "lu", node_stats.rx_sgi);
			print_out(print, "%-*s: %d.%d\n",
				CALL_QCSAPI_NODE_STATS_LABEL_LEN,
				"hw_noise",
				(node_stats.hw_noise/10),
				abs(node_stats.hw_noise%10));
			CALL_QCSAPI_NODE_STATS_PRINT("snr", "d", node_stats.snr);
			CALL_QCSAPI_NODE_STATS_PRINT("rssi", "d", node_stats.rssi);
			CALL_QCSAPI_NODE_STATS_PRINT("bw", "d", node_stats.bw);
			print_out(print, "%-*s: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
					CALL_QCSAPI_NODE_STATS_LABEL_LEN,
					"mac_addr",
					node_stats.mac_addr[0],
					node_stats.mac_addr[1],
					node_stats.mac_addr[2],
					node_stats.mac_addr[3],
					node_stats.mac_addr[4],
					node_stats.mac_addr[5]
				);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_node_infoset(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	struct qtn_nis_set nis;
	const char *usage = "<WiFi interface> {<MAC addr> | <node index>} <set id>";
	qcsapi_mac_addr mac_addr;
	uint32_t node_index = 0;
	uint16_t set_id;

	if (argc != 2) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return 1;
	}

	if (qcsapi_util_str_to_uint32(argv[0], &node_index) < 0 || node_index == 0) {
		retval = parse_mac_addr(argv[0], mac_addr);
		if (retval < 0) {
			qcsapi_report_usage(p_calling_bundle, usage);
			return 1;
		}
	}

	if (safe_atou16(argv[1], &set_id, print, 0, QTN_NIS_SET_ID_MAX - 1) <= 0) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return 1;
	}

	retval = qcsapi_wifi_get_node_infoset(the_interface, node_index, mac_addr, set_id, &nis);
	if (retval < 0) {
		report_qcsapi_error(p_calling_bundle, retval);
		return 1;
	}

	local_node_infoset_print(p_calling_bundle->caller_output, set_id, &nis);

	return retval;
}

static int
local_node_infoset_all_print(call_qcsapi_bundle *p_calling_bundle, const uint16_t set_id,
				struct qtn_nis_all_set *nis)
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	struct qtn_nis_all_node *node;
	uint16_t node_idx = 0;
	int node_num;
	int fld;

	COMPILE_TIME_ASSERT(ARRAY_SIZE(qtn_nis_all_meta) <= ARRAY_SIZE(nis->node[0].val));

	if (set_id > (ARRAY_SIZE(qtn_nis_all_meta) - 1)) {
		print_out(print, "Invalid set id %u\n", set_id);
		return 0;
	}

	for (node_num = 0; node_num < nis->node_cnt; node_num++) {
		node = &nis->node[node_num];
		node_idx = node->node_index;
		for (fld = 0; fld < ARRAY_SIZE(node->val); fld++) {
			if (QTN_NIS_IS_SET(node, fld)) {
				print_out(print, MACSTR " %4u ",
					MAC2STR(node->mac_addr), node_idx);
				local_node_infoset_print_core(print,
							qtn_nis_all_meta[set_id][fld].type,
							qtn_nis_all_meta[set_id][fld].label,
							set_id, fld, node->val[fld]);
			}
		}
	}

	/* If the report contains max nodes, there may be more to come. */
	if (nis->node_cnt == ARRAY_SIZE(nis->node))
		return node_idx + 1;

	return 0;
}

static int
local_node_infoset_all_print_all_nodes(call_qcsapi_bundle *p_calling_bundle, const uint16_t set_id,
				struct qtn_nis_all_set *nis)
{
	const char *the_interface = p_calling_bundle->caller_interface;
	int retval;
	int first_node_index = 0;

	do {
		retval = qcsapi_wifi_get_node_infoset_all(the_interface, first_node_index,
								set_id, 0, nis);
		if (retval < 0) {
			report_qcsapi_error(p_calling_bundle, retval);
			return 1;
		}
		first_node_index = local_node_infoset_all_print(p_calling_bundle, set_id, nis);
	} while (first_node_index);

	return 0;
}

static int
call_qcsapi_wifi_get_node_infoset_all(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	struct qtn_nis_all_set nis;
	const char *usage = "<WiFi interface> <set id>";
	uint16_t set_id;

	if ((argc != 1)) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return 1;
	}

	if (safe_atou16(argv[0], &set_id, print, 0, QTN_NIS_ALL_SET_ID_MAX - 1) <= 0) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return 1;
	}

	if (local_node_infoset_all_print_all_nodes(p_calling_bundle, set_id, &nis) < 0)
		return 1;

	return 0;
}

static int
call_qcsapi_wifi_get_max_queued(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		 statval = 0;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	uint32_t	 node_index = p_calling_bundle->caller_generic_parameter.index;
	int		 local_remote_flag = QCSAPI_LOCAL_NODE;
	int		 reset_flag = 0;
	uint32_t	 max_queued, *p_max_queued = &max_queued;

	if (argc > 0) {
		if (parse_local_remote_flag(print, argv[0], &local_remote_flag) < 0) {
			return 1;
		}
	}

	if (argc > 1) {
		if (local_str_to_int32(argv[1], &reset_flag, print, "reset flag") < 0)
			return 1;
	}

	if (argc > 2 && strcmp(argv[2], "NULL") == 0) {
		p_max_queued = NULL;
	}

	qcsapi_retval = qcsapi_wifi_get_max_queued(the_interface,
						   node_index,
						   local_remote_flag,
						   reset_flag,
						   p_max_queued);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%d\n", max_queued);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_associate(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi associate,"
				 " count is %d\n", argc );
		statval = 1;
	} else {
		char *join_ssid = argv[0];

		qcsapi_retval = qcsapi_wifi_associate(the_interface, join_ssid);
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_disassociate(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_disassociate(the_interface);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_disassociate_sta(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int                  statval = 1;
	int                  qcsapi_retval;
	const char*          the_interface = p_calling_bundle->caller_interface;
	qcsapi_output*       print = p_calling_bundle->caller_output;
	qcsapi_mac_addr      mac_addr = {0};

	if (argc < 1) {
		print_err( print, "MAC address required to be passed as a parameter\n");
	} else {
		qcsapi_retval = parse_mac_addr( argv[ 0 ], mac_addr );

		if (qcsapi_retval >= 0) {
			qcsapi_retval = qcsapi_wifi_disassociate_sta(the_interface, mac_addr);
			if (qcsapi_retval >= 0) {
				statval = 0;

				if (verbose_flag >= 0) {
					print_out( print, "complete\n");
				}
			} else {
				report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			}
		} else {
			print_out( print, "Error parsing MAC address %s\n", argv[ 0 ] );
		}
	}

	return statval;
}

static int
call_qcsapi_wifi_reassociate(call_qcsapi_bundle *p_calling_bundle,
	int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char* the_interface = p_calling_bundle->caller_interface;
	qcsapi_output* print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_reassociate(the_interface);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_associate_noscan(call_qcsapi_bundle *p_calling_bundle,
	int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char* the_interface = p_calling_bundle->caller_interface;
	qcsapi_output* print = p_calling_bundle->caller_output;

	if (argc < 1) {
		qcsapi_report_usage(p_calling_bundle, "<ifname> <SSID>");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_associate_noscan(the_interface, argv[0]);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_update_bss_cfg(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 1;
	int qcsapi_retval = 0;
	const char* the_interface = p_calling_bundle->caller_interface;
	qcsapi_output* print = p_calling_bundle->caller_output;
	qcsapi_wifi_mode mode;
	const char *ifname;
	const char *bss_id;
	const char *param_name;
	const char *param_value;
	const char *param_type;

	if (argc >= 4) {
		ifname = the_interface;
		bss_id = argv[1];
		if (!strcasecmp(argv[0], "ap"))
			mode = qcsapi_access_point;
		else if (!strcasecmp(argv[0], "sta"))
			mode = qcsapi_station;
		else
			qcsapi_retval = -qcsapi_invalid_wifi_mode;

		if (qcsapi_retval >= 0) {
			param_name = argv[2];
			param_value = argv[3];
			if (argc > 4)
				param_type = argv[4];
			else
				param_type = NULL;

			qcsapi_retval = qcsapi_wifi_update_bss_cfg(ifname, mode, bss_id,
						param_name, param_value, param_type);
		}

		if (qcsapi_retval >= 0) {
			print_out(print, "complete\n");
			statval = 0;
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		}
	}

	if (statval) {
		print_err(print, "call_qcsapi update_bss_cfg <ifname> "
				"<ap | sta> <bss_id> <param_name> "
				"<param_value> [param_type]\n");
	}
	return statval;
}

static int
call_qcsapi_wifi_get_bss_cfg(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char* the_interface = p_calling_bundle->caller_interface;
	qcsapi_output* print = p_calling_bundle->caller_output;
	qcsapi_wifi_mode mode;
	const char *ifname;
	const char *bss_id;
	const char *param_name;
	string_128 param_value = {'\0'};

	if (argc < 3) {
		qcsapi_report_usage(p_calling_bundle,
			"<ifname> <ap | sta> <bss_id> <param_name>");
		return 1;
	}

	ifname = the_interface;
	if (!strcasecmp(argv[0], "ap"))
		mode = qcsapi_access_point;
	else if (!strcasecmp(argv[0], "sta"))
		mode = qcsapi_station;
	else
		qcsapi_retval = -qcsapi_invalid_wifi_mode;

	if (qcsapi_retval >= 0) {
		bss_id = argv[1];
		param_name = argv[2];
		qcsapi_retval = qcsapi_wifi_get_bss_cfg(ifname, mode, bss_id,
					param_name, param_value, sizeof(param_value));
	}

	if (qcsapi_retval >= 0) {
		print_out(print, "%s\n", param_value);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}


static int
call_qcsapi_SSID_create_SSID( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi SSID create SSID, count is %d\n", argc );
		statval = 1;
	} else {
		char *new_SSID = argv[0];

		qcsapi_retval = qcsapi_SSID_create_SSID( the_interface, new_SSID );
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0)
				print_out( print, "complete\n" );
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_SSID_remove_SSID(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err(print, "Not enough parameters in call qcsapi SSID remove SSID, count is %d\n", argc);
		statval = 1;
	} else {
		char *del_SSID = argv[0];

		qcsapi_retval = qcsapi_SSID_remove_SSID(the_interface, del_SSID);
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out(print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return (statval);
}

static int
call_qcsapi_SSID_verify_SSID( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi SSID verify SSID, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		char *existing_SSID = argv[0];

		qcsapi_retval = qcsapi_SSID_verify_SSID( the_interface, existing_SSID );
		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_SSID_rename_SSID( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi SSID rename SSID, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		int		 qcsapi_retval;
		char		*new_SSID = argv[ 0 ];
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*existing_SSID = p_calling_bundle->caller_generic_parameter.parameter_type.the_SSID;

		qcsapi_retval = qcsapi_SSID_rename_SSID( the_interface, existing_SSID, new_SSID );
		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

#define MAX_SSID_LIST_SIZE	10

static int
call_qcsapi_SSID_get_SSID_list(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	/*
	 *  array_SSIDs has the space that receives the SSIDs from the API.
	 *  Let this get as large as required, without affecting the integrity of the stack.
	 */
	static qcsapi_SSID	 array_ssids[MAX_SSID_LIST_SIZE];
	int			 qcsapi_retval;
	unsigned int		 iter;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int	 sizeof_list = MAX_SSID_LIST_SIZE;
	char			*list_ssids[MAX_SSID_LIST_SIZE + 1];

	if (argc > 0) {
		if (local_str_to_uint32(argv[0], &sizeof_list, print, "size of list") < 0)
			return 1;

		if (sizeof_list > MAX_SSID_LIST_SIZE) {
			print_err(print,
				 "SSID Get List of (configured) SSIDs: cannot exceed max list size of %d\n",
				  MAX_SSID_LIST_SIZE);
			return 1;
		}
	}

	for (iter = 0; iter < sizeof_list; iter++) {
		list_ssids[iter] = array_ssids[iter];
		*(list_ssids[iter]) = '\0';
	}

	qcsapi_retval = qcsapi_SSID_get_SSID_list(the_interface, sizeof_list, &list_ssids[0]);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			for (iter = 0; iter < sizeof_list; iter++) {
				if ((list_ssids[iter] == NULL) || strlen(list_ssids[iter]) < 1) {
					break;
				}

				print_out(print, "%s\n", list_ssids[iter]);
			}
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_SSID_get_protocol( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	string_16	 SSID_proto;
	char		*p_SSID_proto = NULL;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	char		*p_SSID = p_calling_bundle->caller_generic_parameter.parameter_type.the_SSID;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_SSID_proto = &SSID_proto[ 0 ];
	qcsapi_retval = qcsapi_SSID_get_protocol( the_interface, p_SSID, p_SSID_proto );

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%s\n", &SSID_proto[ 0 ] );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_SSID_get_encryption_modes( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	char		 encryption_modes[ 36 ], *p_encryption_modes = NULL;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	char		*p_SSID = p_calling_bundle->caller_generic_parameter.parameter_type.the_SSID;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_encryption_modes = &encryption_modes[ 0 ];
	qcsapi_retval = qcsapi_SSID_get_encryption_modes( the_interface, p_SSID, p_encryption_modes );

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%s\n", &encryption_modes[ 0 ] );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_SSID_get_group_encryption( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	char		 group_encryption[ 36 ], *p_group_encryption = NULL;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	char		*p_SSID = p_calling_bundle->caller_generic_parameter.parameter_type.the_SSID;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_group_encryption = &group_encryption[ 0 ];
	qcsapi_retval = qcsapi_SSID_get_group_encryption( the_interface, p_SSID, p_group_encryption );

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%s\n", &group_encryption[ 0 ] );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_SSID_get_authentication_mode( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	char		 authentication_mode[ 36 ], *p_authentication_mode = NULL;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	char		*p_SSID = p_calling_bundle->caller_generic_parameter.parameter_type.the_SSID;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_authentication_mode = &authentication_mode[ 0 ];
	qcsapi_retval = qcsapi_SSID_get_authentication_mode( the_interface, p_SSID, p_authentication_mode );

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%s\n", &authentication_mode[ 0 ] );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_SSID_set_protocol( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi SSID set protocol, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*p_SSID = p_calling_bundle->caller_generic_parameter.parameter_type.the_SSID;
		char		*p_SSID_proto = argv[ 0 ];

	    /* SSID protocol will not be NULL ... */

		if (strcmp( argv[ 0 ], "NULL" ) == 0)
		  p_SSID_proto = NULL;
		qcsapi_retval = qcsapi_SSID_set_protocol( the_interface, p_SSID, p_SSID_proto );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_SSID_set_encryption_modes( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi SSID set encryption modes, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*p_SSID = p_calling_bundle->caller_generic_parameter.parameter_type.the_SSID;
		char		*p_encryption_modes = argv[ 0 ];

	  /* Encryption modes will not be NULL ... */

		if (strcmp( argv[ 0 ], "NULL" ) == 0)
		  p_encryption_modes = NULL;
		qcsapi_retval = qcsapi_SSID_set_encryption_modes( the_interface, p_SSID, p_encryption_modes );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_SSID_set_group_encryption( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi SSID set group encryption\n" );
		print_err( print, "Usage: call_qcsapi SSID_set_group_encryption <WiFi interface> <SSID> <\"TKIP\"|\"CCMP\">\n" );
		statval = 1;
	}
	else
	{
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*p_SSID = p_calling_bundle->caller_generic_parameter.parameter_type.the_SSID;
		char		*p_group_encryption = argv[ 0 ];

	  /* Group encryption will not be NULL ... */

		if (strcmp( argv[ 0 ], "NULL" ) == 0)
		  p_group_encryption = NULL;
		qcsapi_retval = qcsapi_SSID_set_group_encryption( the_interface, p_SSID, p_group_encryption );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_SSID_set_authentication_mode( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi SSID set authentication mode, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*p_SSID = p_calling_bundle->caller_generic_parameter.parameter_type.the_SSID;
		char		*p_authentication_mode = argv[ 0 ];


	  /* Authentication mode will not be NULL ... */

		if (strcmp( argv[ 0 ], "NULL" ) == 0)
		  p_authentication_mode = NULL;
		qcsapi_retval = qcsapi_SSID_set_authentication_mode( the_interface, p_SSID, p_authentication_mode );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_SSID_get_pre_shared_key( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

  /*
   * Argument list needs to have the index.
   */
	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi SSID get key passphrase, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		char			 pre_shared_key[ 68 ], *p_pre_shared_key = NULL;
		int			 qcsapi_retval;
		const char		*the_interface = p_calling_bundle->caller_interface;
		char			*p_SSID = p_calling_bundle->caller_generic_parameter.parameter_type.the_SSID;
		qcsapi_unsigned_int	 the_index;

		if (local_str_to_uint32(argv[0], &the_index, print, "index") < 0)
                        return 1;

		if (argc < 2 || strcmp( argv[ 1 ], "NULL" ) != 0)
		  p_pre_shared_key = &pre_shared_key[ 0 ];
		qcsapi_retval = qcsapi_SSID_get_pre_shared_key( the_interface, p_SSID, the_index, p_pre_shared_key );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "%s\n", &pre_shared_key[ 0 ] );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_SSID_get_key_passphrase( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

  /*
   * Argument list needs to have the index.
   */
	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi SSID get key passphrase, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		char			 passphrase[ 68 ], *p_passphrase = NULL;
		int			 qcsapi_retval;
		const char		*the_interface = p_calling_bundle->caller_interface;
		char			*p_SSID = p_calling_bundle->caller_generic_parameter.parameter_type.the_SSID;
		qcsapi_unsigned_int	 the_index;

		if (local_str_to_uint32(argv[0], &the_index, print, "index") < 0)
			return 1;

		if (argc < 2 || strcmp( argv[ 1 ], "NULL" ) != 0)
		  p_passphrase = &passphrase[ 0 ];
		qcsapi_retval = qcsapi_SSID_get_key_passphrase( the_interface, p_SSID, the_index, p_passphrase );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "%s\n", &passphrase[ 0 ] );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_SSID_set_pre_shared_key( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

  /*
   * Argument list needs to have both the index and the PSK.
   */
	if (argc < 2)
	{
		print_err( print, "Not enough parameters in call qcsapi SSID set key passphrase, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		int			 qcsapi_retval;
		const char		*the_interface = p_calling_bundle->caller_interface;
		char			*p_SSID = p_calling_bundle->caller_generic_parameter.parameter_type.the_SSID;
		qcsapi_unsigned_int	 the_index;
		char			*p_PSK = argv[ 1 ];

		if (local_str_to_uint32(argv[0], &the_index, print, "index") < 0)
			return 1;

	  /* PSK will not be NULL.  */

		if (strcmp( argv[ 1 ], "NULL" ) == 0)
		  p_PSK = NULL;
		qcsapi_retval = qcsapi_SSID_set_pre_shared_key( the_interface, p_SSID, the_index, p_PSK );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_add_radius_auth_server_cfg(call_qcsapi_bundle *p_calling_bundle,
					    int argc, char *argv[])
{
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;

	if (argc < 3) {
		qcsapi_report_usage(p_calling_bundle,
				"<WiFi interface> <ipaddr> <port> <shared-key>\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_add_radius_auth_server_cfg(the_interface,
								argv[0],
								argv[1],
								argv[2]);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_wifi_del_radius_auth_server_cfg(call_qcsapi_bundle *p_calling_bundle,
					    int argc, char *argv[])
{
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;

	if (argc < 2) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <ipaddr> <port>\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_del_radius_auth_server_cfg(the_interface,
								argv[0],
								argv[1]);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_wifi_get_radius_auth_server_cfg(call_qcsapi_bundle *p_calling_bundle,
					    int argc, char *argv[])
{
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	string_1024 radius_auth_server_cfg;

	qcsapi_retval = qcsapi_wifi_get_radius_auth_server_cfg(the_interface,
							radius_auth_server_cfg);

	return qcsapi_report_str_or_error(p_calling_bundle, qcsapi_retval,
			radius_auth_server_cfg);
}

static int
call_qcsapi_wifi_get_radius_acct_interim_interval(call_qcsapi_bundle *p_calling_bundle,
						  int argc, char *argv[])
{
	int statval = 0;
	qcsapi_unsigned_int value;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_radius_acct_interim_interval(the_interface,
									&value);

	if (qcsapi_retval >= 0) {
		print_out(print, "%u\n", value);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_radius_acct_interim_interval(call_qcsapi_bundle *p_calling_bundle,
						  int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	qcsapi_unsigned_int interval;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;

	if (local_atou32_verify_numeric_range(argv[0], &interval, print, 0, 0xFFFFFFFF) < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_radius_acct_interim_interval(the_interface, interval);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_add_radius_acct_server_cfg(call_qcsapi_bundle *p_calling_bundle,
					    int argc, char *argv[])
{
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;

	if (argc < 3) {
		qcsapi_report_usage(p_calling_bundle,
				"<WiFi interface> <ipaddr> <port> <shared-key>\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_add_radius_acct_server_cfg(the_interface,
								argv[0],
								argv[1],
								argv[2]);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_wifi_del_radius_acct_server_cfg(call_qcsapi_bundle *p_calling_bundle,
					    int argc, char *argv[])
{
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;

	if (argc < 2) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <ipaddr> <port>\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_del_radius_acct_server_cfg(the_interface,
								argv[0],
								argv[1]);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_wifi_get_radius_acct_server_cfg(call_qcsapi_bundle *p_calling_bundle,
					    int argc, char *argv[])
{
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	string_1024 radius_server_cfg;

	qcsapi_retval = qcsapi_wifi_get_radius_acct_server_cfg(the_interface,
							radius_server_cfg);

	return qcsapi_report_str_or_error(p_calling_bundle, qcsapi_retval,
			radius_server_cfg);
}

static int
call_qcsapi_wifi_set_eap_own_ip_addr( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi set own ip addr, count is %d\n", argc);
		print_err( print, "Usage: call_qcsapi set_own_ip_addr <WiFi interface> <ipaddr>\n");
		statval = 1;
	}
	else
	{
		int			qcsapi_retval;
		const char		*the_interface = p_calling_bundle->caller_interface;
		char			*p_own_ip_addr = argv[ 0 ];

		if (strcmp( argv[ 0 ], "NULL" ) == 0)
			p_own_ip_addr = NULL;
		qcsapi_retval = qcsapi_wifi_set_eap_own_ip_addr( the_interface, p_own_ip_addr );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_eap_own_ip_addr( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	string_16 eap_own_ip_addr;

	qcsapi_retval = qcsapi_wifi_get_eap_own_ip_addr(the_interface, eap_own_ip_addr);

	if (qcsapi_retval >= 0) {
		print_out(print, "%s\n", eap_own_ip_addr);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_SSID_set_key_passphrase( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

  /*
   * Argument list needs to have both the index and the passphrase.
   */
	if (argc < 2)
	{
		print_err( print, "Not enough parameters in call qcsapi SSID set key passphrase, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		int			 qcsapi_retval;
		const char		*the_interface = p_calling_bundle->caller_interface;
		char			*p_SSID = p_calling_bundle->caller_generic_parameter.parameter_type.the_SSID;
		qcsapi_unsigned_int	 the_index = (qcsapi_unsigned_int) atoi( argv[ 0 ] );
		char			*p_passphrase = argv[ 1 ];

	  /* Passphrase of NULL is not valid.  */

		if (strcmp( argv[ 1 ], "NULL" ) == 0)
		  p_passphrase = NULL;
		qcsapi_retval = qcsapi_SSID_set_key_passphrase( the_interface, p_SSID, the_index, p_passphrase );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_SSID_get_pmf( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int		statval = 0;
	int		pmf_cap = 0;
	int		*p_pmf_cap = NULL;
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	char		*p_SSID = p_calling_bundle->caller_generic_parameter.parameter_type.the_SSID;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
		p_pmf_cap = &pmf_cap;

	qcsapi_retval = qcsapi_SSID_get_pmf( the_interface, p_SSID, p_pmf_cap);

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%d\n", pmf_cap );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_SSID_set_pmf( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
        int qcsapi_retval;
        const char *the_interface = p_calling_bundle->caller_interface;
        char *p_SSID = p_calling_bundle->caller_generic_parameter.parameter_type.the_SSID;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi SSID set pmf mode, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		qcsapi_unsigned_int	 pmf_cap;

		if (local_str_to_uint32(argv[0], &pmf_cap, print, "flag") < 0)
			return 1;

		qcsapi_retval = qcsapi_SSID_set_pmf( the_interface, p_SSID, pmf_cap );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_SSID_get_wps_SSID( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_SSID	 the_wps_SSID = "";
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc > 0 && strcmp( argv[ 0 ], "NULL" ) == 0)
	  qcsapi_retval = qcsapi_SSID_get_wps_SSID( the_interface, NULL );
	else
	  qcsapi_retval = qcsapi_SSID_get_wps_SSID( the_interface, the_wps_SSID );

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%s\n", the_wps_SSID );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_vlanid_valid(char* vlanid, int all, qcsapi_output *print)
{
	int vid;

	if (all && !strcasecmp(vlanid, "all"))
		return QVLAN_VID_ALL;

	if (local_str_to_int32(vlanid, &vid, print, "vlan ID") < 0)
		return -EINVAL;

	if (vid >= 0 && vid < QVLAN_VID_MAX)
		return vid;
	else
		return -EFAULT;
}

static int
call_qcsapi_wifi_vlan_trunk_parser(const char *argv, int cmd)
{
	if (!strcasecmp(argv, "default"))
		cmd |= e_qcsapi_vlan_pvid;
	else if (!strcasecmp(argv, "tag"))
		cmd |= e_qcsapi_vlan_tag;
	else if (!strcasecmp(argv, "untag"))
		cmd |= e_qcsapi_vlan_untag;
	else if (!strcasecmp(argv, "delete"))
		cmd |= e_qcsapi_vlan_del;
	else
		cmd = 0;

	return cmd;
}

static int
call_qcsapi_wifi_vlan_config(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	qcsapi_vlan_cmd cmd = 0;
	int vlanid = 0;
	int onoff;
	int index;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *usage = "Usage:\n"
		"    call_qcsapi vlan_config wifi0 enable\n"
		"    call_qcsapi vlan_config wifi0 disable\n"
		"    call_qcsapi vlan_config <interface> reset\n"
		"    call_qcsapi vlan_config <interface> access <VLAN ID>\n"
		"    call_qcsapi vlan_config <interface> trunk <VLAN ID> "
							"[ { tag | untag } ] [default] [delete]\n"
		"    call_qcsapi vlan_config <interface> dynamic { 0 | 1 }\n"
		"    call_qcsapi vlan_config <interface> default_priority { 0 | 1 | ... | 7 }\n"
		"    call_qcsapi vlan_config <interface> priority_tag_tx { 0 | 1 }\n"
		"    call_qcsapi vlan_config <interface> hybrid <VLAN ID>   (deprecated)\n"
		"    call_qcsapi vlan_config <interface> bind <VLAN ID>     (deprecated)\n"
		"    call_qcsapi vlan_config <interface> unbind <VLAN ID>   (deprecated)\n"
		"    call_qcsapi vlan_config wifi0 drop_stag { 0 | 1 }\n";

	if (argc < 2) {
		if (!strcasecmp(argv[0], "enable"))
			cmd = e_qcsapi_vlan_enable;
		else if (!strcasecmp(argv[0], "disable"))
			cmd = e_qcsapi_vlan_disable;
		else if (!strcasecmp(argv[0], "reset"))
			cmd = e_qcsapi_vlan_reset;
		else
			cmd = 0;
	} else if (!strcasecmp(argv[0], "bind")) {
		vlanid = call_qcsapi_wifi_vlanid_valid(argv[1], 0, print);
		if (vlanid < 0 || argc > 2) {
			cmd = 0;
		} else {
			cmd = e_qcsapi_vlan_access |
				e_qcsapi_vlan_untag | e_qcsapi_vlan_pvid;
		}
	} else if (!strcasecmp(argv[0], "unbind")) {
		vlanid = call_qcsapi_wifi_vlanid_valid(argv[1], 0, print);
		if (vlanid < 0 || argc > 2)
			cmd = 0;
		else
			cmd = e_qcsapi_vlan_access | e_qcsapi_vlan_del |
				e_qcsapi_vlan_untag | e_qcsapi_vlan_pvid;
	} else if (!strcasecmp(argv[0], "dynamic")) {
		if (argc > 2) {
			cmd = 0;
		} else {
			uint8_t enable;

			if (local_verify_enable_or_disable(argv[1], &enable, print) < 0)
				return 1;

			if (enable)
				cmd = e_qcsapi_vlan_dynamic;
			else
				cmd = e_qcsapi_vlan_undynamic;
		}
	} else if (!strcasecmp(argv[0], "access")) {
		vlanid = call_qcsapi_wifi_vlanid_valid(argv[1], 0, print);
		if (argc != 2 || vlanid < 0) {
			cmd = 0;
		} else {
			cmd = e_qcsapi_vlan_access | e_qcsapi_vlan_untag | e_qcsapi_vlan_pvid;
		}
	} else if (!strcasecmp(argv[0], "trunk") || !strcasecmp(argv[0], "hybrid")) {
		vlanid = call_qcsapi_wifi_vlanid_valid(argv[1], 1, print);
		if (argc > 5 || argc < 2 || vlanid < 0) {
			cmd = 0;
		} else {
			cmd = e_qcsapi_vlan_trunk;
			for (index = 2; index < argc; index++)
				cmd = call_qcsapi_wifi_vlan_trunk_parser(argv[index], cmd);

			if ((vlanid == QVLAN_VID_ALL) && (cmd & e_qcsapi_vlan_pvid))
				cmd = 0;
		}
	} else if (!strcasecmp(argv[0], "default_priority")) {
		vlanid = call_qcsapi_wifi_vlanid_valid(argv[1], 0, print);
		if (vlanid >= 0 && vlanid <= QVLAN_PRIO_MAX && argc == 2) {
			cmd = e_qcsapi_vlan_default_priority;
		}
	} else if (!strcasecmp(argv[0], "priority_tag_tx")) {
		onoff = call_qcsapi_wifi_vlanid_valid(argv[1], 0, print);
		if ((onoff == 0 || onoff == 1) && argc == 2) {
			cmd = e_qcsapi_vlan_hybrid;
			vlanid = QVLAN_PRIO_VID;
			if (onoff)
				cmd |= e_qcsapi_vlan_tag;
			else
				cmd |= e_qcsapi_vlan_untag;
		}
	} else if (!strcasecmp(argv[0], "drop_stag")) {
		if (argc > 2) {
			cmd = 0;
		} else {
			uint8_t enable;

			if (local_verify_enable_or_disable(argv[1], &enable, print) < 0)
				return 1;

			if (enable)
				cmd = e_qcsapi_vlan_drop_stag;
			else
				cmd = e_qcsapi_vlan_undrop_stag;
		}
	}

	qcsapi_retval = qcsapi_wifi_vlan_config(the_interface, cmd, vlanid);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else if (qcsapi_retval == -qcsapi_param_value_invalid) {
		print_err(print, usage);
		statval = -EINVAL;
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
	}

	return statval;
}

static void
call_qcsapi_wifi_print_vlan_config(const call_qcsapi_bundle *p_calling_bundle, const char *ifname, struct qcsapi_data_2Kbytes *byte)
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	struct qtn_vlan_config *vcfg = (struct qtn_vlan_config *)byte;
	uint16_t vmode;
	uint16_t vid;
	uint16_t i;
	uint16_t j;
	uint32_t tagrx;
	uint32_t priority;
	uint8_t drop_stag;

	if (vcfg->vlan_cfg) {
		vmode = ((vcfg->vlan_cfg & QVLAN_MASK_MODE) >> QVLAN_SHIFT_MODE);
		vid = (vcfg->vlan_cfg & QVLAN_MASK_VID);
		priority = vcfg->priority;
		drop_stag = vcfg->drop_stag;
	} else {
		print_out(print, "tagrx VLAN:");
		for (i = 0, j = 0; i < QVLAN_VID_MAX; i++) {
			tagrx = qtn_vlan_get_tagrx(vcfg->u.tagrx_config, i);
			if (tagrx) {
				if ((j++ & 0xF) == 0)
					print_out(print, "\n\t");
				print_out(print, "%u-%u, ", i, tagrx);
			}
		}
		print_out(print, "\n");
		return;
	}

	switch (vmode) {
	case QVLAN_MODE_TRUNK:
		print_out(print, "%s, default VLAN %u\n",
				QVLAN_MODE_STR_TRUNK, vid);
		print_out(print, "Member of VLANs: ");
		for (i = 0, j = 0; i < QVLAN_VID_MAX; i++) {
			if (is_set_a(vcfg->u.dev_config.member_bitmap, i)) {
				if ((j++ & 0xF) == 0)
					print_out(print, "\n\t");
				print_out(print, "%u,", i);
			}
		}

		print_out(print, "\nUntagged VLANs: ");
		for (i = 0, j = 0; i < QVLAN_VID_MAX; i++) {
			if (is_set_a(vcfg->u.dev_config.member_bitmap, i) &&
					is_clr_a(vcfg->u.dev_config.tag_bitmap, i)) {
				if ((j++ & 0xF) == 0)
					print_out(print, "\n\t");
				print_out(print, "%u,", i);
			}
		}
		print_out(print, "\n");
		break;
	case QVLAN_MODE_ACCESS:
		print_out(print, "%s, VLAN %u\n", QVLAN_MODE_STR_ACCESS, vid);
		break;
	case QVLAN_MODE_DYNAMIC:
		print_out(print, "%s\n", QVLAN_MODE_STR_DYNAMIC);
		break;
	default:
		print_out(print, "VLAN disabled\n");
		break;
	}

	print_out(print, "Default priority: %u\n", priority);
	print_out(print, "Tx Priority tagging: %s\n",
		is_set_a(vcfg->u.dev_config.tag_bitmap, QVLAN_PRIO_VID) ? "On" : "Off");
	print_out(print, "Drop S-tagged packets: %u\n", drop_stag);
}

static int
call_qcsapi_wifi_show_vlan_config(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	struct qtn_vlan_config *vcfg;
	const char *ifname = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc > 1) {
		print_err(print, "Too many parameters for show_vlan_config command\n");
		qcsapi_retval = 1;
	} else {
		vcfg = (struct qtn_vlan_config *)malloc(sizeof(struct qcsapi_data_2Kbytes));
		if (!vcfg) {
			print_err(print, "Not enough memory to execute the API\n");
			return -1;
		}

		memset(vcfg, 0, sizeof(*vcfg));

		if (argc == 1 && !strcmp(argv[0], "tagrx")) {
			qcsapi_retval = qcsapi_wifi_show_vlan_config(ifname, (struct qcsapi_data_2Kbytes *)vcfg, argv[0]);
			qtn_vlan_config_ntohl(vcfg, 1);
		} else if (argc == 0) {
			qcsapi_retval = qcsapi_wifi_show_vlan_config(ifname, (struct qcsapi_data_2Kbytes *)vcfg, NULL);
			qtn_vlan_config_ntohl(vcfg, 0);
		} else {
			qcsapi_retval = -1;
		}

		if (qcsapi_retval < 0) {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			qcsapi_retval = 1;
		} else {
			call_qcsapi_wifi_print_vlan_config(p_calling_bundle, ifname, (struct qcsapi_data_2Kbytes *)vcfg);
			qcsapi_retval = 0;
		}
		free(vcfg);
	}

	return qcsapi_retval;
}

static int
call_qcsapi_enable_vlan_promisc(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint8_t enabled;

	if (local_verify_enable_or_disable(argv[0], &enabled, print) < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_vlan_promisc(enabled);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_set_multicast(call_qcsapi_bundle *p_calling_bundle, int add, int argc, char *argv[])
{
	int qcsapi_retval;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint32_t ipaddr;
	uint32_t ipaddr_ne;
	qcsapi_mac_addr mac_addr = { 0 };
	char *usage = "Usage: call_qcsapi [add_multicast | del_multicast ] "
						"<IP address> <MAC address>\n";

	/* FIXME subnets and IPv6 are not yet supported */

	if (argc != 2) {
		print_err(print, usage);
		return -EINVAL;
	}

	if (inet_pton(AF_INET, argv[0], &ipaddr_ne) != 1) {
		/* FIXME support IPv6 */
		print_err(print, "invalid IPv4 address %s\n", argv[0]);
		return -EINVAL;
	}
	ipaddr = ntohl(ipaddr_ne);

	if (!IN_MULTICAST(ipaddr)) {
		print_err(print, "invalid multicast IPv4 address " NIPQUAD_FMT "\n",
			NIPQUAD(ipaddr_ne));
		return -EINVAL;
	}

	qcsapi_retval = parse_mac_addr(argv[1], mac_addr);
	if (qcsapi_retval < 0) {
		print_err(print, "Error parsing MAC address %s\n", argv[1]);
		return qcsapi_retval;
	}

	if (add)
		qcsapi_retval = qcsapi_wifi_add_multicast(ipaddr, mac_addr);
	else
		qcsapi_retval = qcsapi_wifi_del_multicast(ipaddr, mac_addr);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	if (verbose_flag >= 0)
		print_out(print, "complete\n");

	return 0;
}

#define QCSAPI_FWT_GET_MAX	4096

static int
call_qcsapi_get_multicast_list(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval;
	char buf[QCSAPI_FWT_GET_MAX];

	qcsapi_retval = qcsapi_wifi_get_multicast_list(buf, sizeof(buf));
	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	print_out(print, "%s", buf);

	if (verbose_flag >= 0)
		print_out( print, "complete\n");

	return 0;
}


static int
call_qcsapi_set_ipff(call_qcsapi_bundle *p_calling_bundle, int add, int argc, char *argv[])
{
	int qcsapi_retval;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint32_t ipaddr;
	uint32_t ipaddr_ne;
	const char *usage = "Usage: call_qcsapi [add_ipff | del_ipff ] <ip_address>\n";

	/* FIXME subnets and IPv6 are not yet supported */

	if (argc != 1) {
		print_err(print, usage);
		return -EINVAL;
	}

	if (inet_pton(AF_INET, argv[0], &ipaddr_ne) != 1) {
		print_err(print, "invalid IPv4 address %s\n", argv[0]);
		return -EINVAL;
	}
	ipaddr = ntohl(ipaddr_ne);

	if (!IN_MULTICAST(ipaddr)) {
		print_err(print, "invalid multicast IPv4 address " NIPQUAD_FMT "\n",
			NIPQUAD(ipaddr_ne));
		return -EINVAL;
	}

	if (add) {
		qcsapi_retval = qcsapi_wifi_add_ipff(ipaddr);
	} else {
		qcsapi_retval = qcsapi_wifi_del_ipff(ipaddr);
	}

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	if (verbose_flag >= 0) {
		print_out(print, "complete\n");
	}

	return 0;
}

static int
call_qcsapi_get_ipff(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
#define QCSAPI_IPFF_GET_MAX	256
	char buf[IP_ADDR_STR_LEN * QCSAPI_IPFF_GET_MAX];

	qcsapi_wifi_get_ipff(buf, sizeof(buf));

	print_out(print, "%s", buf);

	if (verbose_flag >= 0) {
		print_out( print, "complete\n");
	}

	return 0;
}

static int
call_qcsapi_wifi_get_rts_threshold(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int rts_threshold;

	qcsapi_retval = qcsapi_wifi_get_rts_threshold(the_interface, &rts_threshold);
	if (qcsapi_retval >= 0) {
		print_out(print, "%d\n", rts_threshold);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return qcsapi_retval;
}

static int
call_qcsapi_wifi_set_rts_threshold(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int rts_threshold;

	if (strcmp("off", argv[0]) == 0) {
		rts_threshold = IEEE80211_RTS_THRESH_OFF;
	} else if (local_atou32_verify_numeric_range(argv[0], &rts_threshold, print,
			IEEE80211_RTS_MIN, IEEE80211_RTS_THRESH_OFF) < 0) {
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_rts_threshold(the_interface, rts_threshold);
	if (qcsapi_retval >= 0) {
		print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return qcsapi_retval;
}

static int
call_qcsapi_wifi_disable_wps(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		disable_wps = atoi(argv[0]);

	qcsapi_retval = qcsapi_wifi_disable_wps(the_interface, disable_wps);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_start_cca(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int channel;
	int duration;

	if (argc < 2) {
		print_err( print, "Format: start_cca <chan-num(36)> <msec-duration(40)> \n");
		return(1);
	}

	if (local_str_to_int32(argv[0], &channel, print, "channel number") < 0)
		return 1;

	if (local_str_to_int32(argv[1], &duration, print, "duration") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_start_cca(the_interface, channel, duration);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "Complete.\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_get_scan_chan_list(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		 statval = 0;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	struct qcsapi_data_256bytes chan_list;
	uint32_t count = 0;
	int i;

	memset(&chan_list, 0, sizeof(chan_list));
	qcsapi_retval = qcsapi_wifi_get_scan_chan_list(the_interface, &chan_list, &count);
	if (qcsapi_retval >= 0) {
		print_out(print, "%d channels in scan list: ", count);
		for (i = 0; i < count; i++)
			print_out(print, "%d%c", chan_list.data[i], (i < (count - 1)) ? ',' : '\n');
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scan_chan_list(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		 statval = 0;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	struct qcsapi_data_256bytes chan_list;
	struct qcsapi_data_256bytes *p_chan_list;
	uint32_t count = 0;

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle,
				"<WiFi interface> <default | channel list>\n");
		return 1;
	}

	if (strcmp(argv[0], "default") == 0) {
		p_chan_list = NULL;
		count = 0;
	} else {
		p_chan_list = &chan_list;
		memset(&chan_list, 0, sizeof(chan_list));
		statval = local_string_to_list(argv[0], chan_list.data, &count);
		if (statval < 0)
			return statval;
	}

	qcsapi_retval = qcsapi_wifi_set_scan_chan_list(the_interface, p_chan_list, count);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_start_scan(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		 statval = 0;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int pick_flags = 0;

	if (argc > 0) {
		while (argc > 0) {
			if (!strcasecmp("reentry", argv[0])) {
				pick_flags |= IEEE80211_PICK_REENTRY;
			} else if (!strcasecmp("clearest", argv[0])) {
				pick_flags |= IEEE80211_PICK_CLEAREST;
			} else if (!strcasecmp("no_pick", argv[0])) {
				pick_flags |= IEEE80211_PICK_NOPICK;
			} else if (!strcasecmp("background", argv[0])) {
				pick_flags |= IEEE80211_PICK_NOPICK_BG;
			} else if (!strcasecmp("dfs", argv[0])) {
				pick_flags |= IEEE80211_PICK_DFS;
			} else if (!strcasecmp("non_dfs", argv[0])) {
				pick_flags |= IEEE80211_PICK_NONDFS;
			} else if (!strcasecmp("all", argv[0])) {
				pick_flags |= IEEE80211_PICK_ALL;
			} else if (!strcasecmp("flush", argv[0])) {
				pick_flags |= IEEE80211_PICK_SCAN_FLUSH;
			} else if (!strcasecmp("active", argv[0])) {
				pick_flags |= IEEE80211_PICK_BG_ACTIVE;
			} else if (!strcasecmp("random", argv[0])) {
				pick_flags |= IEEE80211_SCAN_RANDOMIZE;
			} else if (!strcasecmp("fast", argv[0])) {
				pick_flags |= IEEE80211_PICK_BG_PASSIVE_FAST;
			} else if (!strcasecmp("normal", argv[0])) {
				pick_flags |= IEEE80211_PICK_BG_PASSIVE_NORMAL;
			} else if (!strcasecmp("slow", argv[0])) {
				pick_flags |= IEEE80211_PICK_BG_PASSIVE_SLOW;
			} else if (!strcasecmp("check", argv[0])) {
				pick_flags |= IEEE80211_PICK_BG_CHECK;
			} else {
				goto err_ret;
			}
			argc--;
			argv++;
		}

		if (pick_flags & IEEE80211_PICK_ALGORITHM_MASK) {
			uint32_t algorithm = pick_flags & IEEE80211_PICK_ALGORITHM_MASK;
			uint32_t chan_set = pick_flags & IEEE80211_PICK_DOMIAN_MASK;

			if (IS_MULTIPLE_BITS_SET(algorithm)) {
				print_out(print, "Only one pick algorithm can be specified\n");
				goto err_ret;
			}
			if (chan_set) {
				if (IS_MULTIPLE_BITS_SET(chan_set)) {
					print_out(print, "Only one channel set can be specified\n");
					goto err_ret;
				}
			} else {
				pick_flags |= IEEE80211_PICK_ALL;
			}
		} else {
			print_out(print, "pick algorithm was not specified\n");
			goto err_ret;
		}

		if (pick_flags & IEEE80211_PICK_NOPICK_BG) {
			uint32_t dfs_mode = pick_flags & IEEE80211_PICK_BG_MODE_MASK;

			if (IS_MULTIPLE_BITS_SET(dfs_mode)) {
				print_out(print, "Please specify only one DFS scan mode "
						"from active, (passive)fast, normal and slow\n");
				goto err_ret;
			}
		} else if (pick_flags & IEEE80211_PICK_BG_CHECK) {
			print_out(print, "check flag is only for QTN background scan\n");
			goto err_ret;
		}
	}

	qcsapi_retval = qcsapi_wifi_start_scan_ext(the_interface, pick_flags);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;

err_ret:
	print_start_scan_usage(print);
	return 1;
}

static int
call_qcsapi_wifi_cancel_scan(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int force = 0;
	int qcsapi_retval;

	if (argc == 1) {
		if (!strcasecmp("force", argv[0])) {
			force = 1;
		} else {
			print_out(print, "Unknown parameter: %s\n", argv[0]);
			print_cancel_scan_usage(print);
			return 1;
		}
	} else if (argc != 0) {
		print_cancel_scan_usage(print);
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_cancel_scan(the_interface, force);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_get_scan_status(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int scanstatus = -1;

	qcsapi_retval = qcsapi_wifi_get_scan_status(the_interface, &scanstatus);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%d\n", scanstatus);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_cac_status(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int cacstatus = -1;

	qcsapi_retval = qcsapi_wifi_get_cac_status(the_interface, &cacstatus);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%d\n", cacstatus);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_dfs_available_channel(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int dfs_available_channel_value;

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle,
				"Usage: call_qcsapi set_dfs_available_channel <WiFi interface> <DFS available channel>");
		return 1;
	}

	if (local_atou32_verify_numeric_range(argv[0], &dfs_available_channel_value, print, QCSAPI_MIN_CHANNEL, QCSAPI_MAX_CHANNEL) < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_dfs_available_channel(the_interface, dfs_available_channel_value);
	if (qcsapi_retval >= 0)	{
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_wait_scan_completes(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		 statval = 0;
	int		 qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	time_t		timeout;
	unsigned int	result;

	if (argc < 1) {
		print_err( print, "Wait Scan Completes requires a timeout\n" );
		return(1);
	}

	if (local_str_to_uint32(argv[0], &result, print, "timeout value") < 0)
		return 1;

	timeout = (time_t) result;

	qcsapi_retval = qcsapi_wifi_wait_scan_completes(the_interface, timeout);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_results_AP_scan( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int			 statval = 0;
	qcsapi_unsigned_int	 count_APs_scanned, *p_count_APs_scanned = NULL;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
		p_count_APs_scanned = &count_APs_scanned;
	qcsapi_retval = qcsapi_wifi_get_results_AP_scan(the_interface, p_count_APs_scanned);
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
		  /*
		   * Unlike most APIs that return a value by reference, this API permits
		   * that reference address to be 0.
		   *
		   * Primary purpose of this API is to get the results of the last AP scan.
		   */
			if (p_count_APs_scanned != NULL)
			  print_out( print, "%d\n", (int) count_APs_scanned );
			else
			  print_out( print, "complete\n" );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_count_APs_scanned( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_unsigned_int	 count_APs_scanned, *p_count_APs_scanned = NULL;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_count_APs_scanned = &count_APs_scanned;
	qcsapi_retval = qcsapi_wifi_get_count_APs_scanned( the_interface, p_count_APs_scanned );
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%d\n", (int) count_APs_scanned );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_properties_AP(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	qcsapi_ap_properties ap_properties;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int ap_index = p_calling_bundle->caller_generic_parameter.index;

	if (argc > 0) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <index>\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_get_properties_AP(the_interface, ap_index, &ap_properties);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			char mac_addr_string[ 24 ];

			snprintf(&mac_addr_string[ 0 ], sizeof(mac_addr_string), MACFILTERINGMACFMT,
				  ap_properties.ap_mac_addr[ 0 ],
				  ap_properties.ap_mac_addr[ 1 ],
				  ap_properties.ap_mac_addr[ 2 ],
				  ap_properties.ap_mac_addr[ 3 ],
				  ap_properties.ap_mac_addr[ 4 ],
				  ap_properties.ap_mac_addr[ 5 ]
			);

			print_out(print, "\"%s\" %s %d %d %x %d %d %d %d %d %d %u %u %s %s %d %d %u %d %d %d %s %s\n",
				 ap_properties.ap_name_SSID,
				 &mac_addr_string[ 0 ],
				 ap_properties.ap_channel,
				 ap_properties.ap_RSSI,
				 ap_properties.ap_flags,
				 ap_properties.ap_protocol,
				 ap_properties.ap_authentication_mode,
				 ap_properties.ap_encryption_modes,
				 ap_properties.ap_qhop_role,
				 ap_properties.ap_wps,
				 ap_properties.ap_bw,
				 ap_properties.ap_beacon_interval,
				 ap_properties.ap_dtim_interval,
				 ap_properties.ap_is_ess?"Infrastructure":"Ad-Hoc",
				 ap_properties.ap_ht_secoffset == IEEE80211_HTINFO_EXTOFFSET_ABOVE ?
					"Above" : ap_properties.ap_ht_secoffset == IEEE80211_HTINFO_EXTOFFSET_BELOW ?
					"Below" : "None",
				 ap_properties.ap_chan_center1,
				 ap_properties.ap_chan_center2,
				 ap_properties.ap_last_beacon,
				 ap_properties.ap_noise,
				 ap_properties.ap_11b_present,
				 ap_properties.ap_80211_proto,
				 ap_properties.ap_basic_rates,
				 ap_properties.ap_support_rates
			);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_wps_ie_scanned_AP(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int retval = 0;
	int qcsapi_retval;
	struct qcsapi_ie_data ie_data;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int ap_index = p_calling_bundle->caller_generic_parameter.index;

	qcsapi_retval = qcsapi_wifi_get_wps_ie_scanned_AP(the_interface, ap_index, &ie_data);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			char wps_ie_hex[QCSAPI_MAX_IE_INFOLEN * 2 + 1];
			int i;
			int pos;

			memset(wps_ie_hex, 0, sizeof(wps_ie_hex));
			pos = 0;
			for (i = 0; i < ie_data.ie_len; i++) {
				snprintf(&wps_ie_hex[pos], sizeof(wps_ie_hex) - pos,
					"%02X", ie_data.ie_buf[i]);
				pos += 2;
			}

			print_out(print, "%d %s\n",
				ie_data.ie_len,
				wps_ie_hex
			);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		retval = 1;
	}

	return retval;
}

static int
call_qcsapi_wifi_get_mcs_rate( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int statval = 0;
	char mcs_rate[16];
	char *p_mcs_rate = NULL;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	p_mcs_rate = &mcs_rate[0];
	qcsapi_retval = qcsapi_wifi_get_mcs_rate(the_interface, p_mcs_rate);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%s\n", &mcs_rate[0]);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_mcs_rate( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi WiFi set MCS rate, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		int		 qcsapi_retval;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*p_mcs_rate = argv[ 0 ];

	  /* MCS rate will not be NULL ... */

		if (strcmp( argv[ 0 ], "NULL" ) == 0)
		  p_mcs_rate = NULL;
		qcsapi_retval = qcsapi_wifi_set_mcs_rate( the_interface, p_mcs_rate );

		if (qcsapi_retval >= 0)
		{
			if (verbose_flag >= 0)
			{
				print_out( print, "complete\n" );
			}
		}
		else
		{
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

	return( statval );
}

/******************************************************************************
DESCRIPTION: This API returns the time that station has associated with AP.

*******************************************************************************/
static int
call_qcsapi_wifi_get_time_associated_per_association( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	int		 qcsapi_retval = 0;
	qcsapi_unsigned_int	time_associated = 0;
	qcsapi_unsigned_int	*p_time_associated = NULL;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	 association_index = p_calling_bundle->caller_generic_parameter.index;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0)
	  p_time_associated = &time_associated;

	qcsapi_retval = qcsapi_wifi_get_time_associated_per_association(the_interface, association_index, p_time_associated);

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "%d\n", time_associated);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_wds_add_peer(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	qcsapi_mac_addr  the_mac_addr;
	int ival = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int encryption = 0;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi WiFi wds add peer, count is %d\n", argc);
		statval = 1;
	} else {
		ival = parse_mac_addr(argv[ 0 ], the_mac_addr);
		if ((argc > 1) && (strcasecmp(argv[1], "encrypt") == 0))
			encryption = 1;

		if (ival >= 0) {
			qcsapi_retval = qcsapi_wds_add_peer_encrypt(the_interface, the_mac_addr, encryption);

			if (qcsapi_retval >= 0) {
				if (verbose_flag >= 0) {
					print_out( print, "complete\n");
				}
			} else {
				report_qcsapi_error(p_calling_bundle, qcsapi_retval);
				statval = 1;
			}

		} else {
			print_out( print, "Error parsing MAC address %s\n", argv[ 0 ]);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wifi_wds_remove_peer(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	qcsapi_mac_addr  the_mac_addr;
	int ival = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print,
	   "Not enough parameters in call qcsapi WiFi wds remove peer, count is %d\n", argc );
		statval = 1;
	} else {
		ival = parse_mac_addr(argv[ 0 ], the_mac_addr);

		if (ival >= 0) {
			qcsapi_retval = qcsapi_wds_remove_peer(the_interface, the_mac_addr);

			if (qcsapi_retval >= 0) {
				if (verbose_flag >= 0) {
					print_out( print, "complete\n");
				}
			} else {
				report_qcsapi_error(p_calling_bundle, qcsapi_retval);
				statval = 1;
			}

		} else {
			print_out( print, "Error parsing MAC address %s\n", argv[0]);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wifi_wds_get_peer_address(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	qcsapi_mac_addr peer_address;
	qcsapi_unsigned_int index = 0;
	char temp_peer_address_str[20];
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print,
	   "Not enough parameters in call qcsapi WiFi get peer address, count is %d\n", argc );
		statval = 1;
	} else {
		if (local_str_to_uint32(argv[0], &index, print, "index") < 0)
			return 1;

		qcsapi_retval = qcsapi_wds_get_peer_address(the_interface, index, peer_address);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				snprintf(&temp_peer_address_str[0], sizeof(temp_peer_address_str),
					  MACFILTERINGMACFMT,
					  peer_address[0],
					  peer_address[1],
					  peer_address[2],
					  peer_address[3],
					  peer_address[4],
					  peer_address[5]);
				print_out( print, "%s\n", temp_peer_address_str);
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wifi_wds_get_psk(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_mac_addr peer_address;
	int ival = 0;
	uint8_t pre_shared_key[IEEE80211_KEYBUF_SIZE + IEEE80211_MICBUF_SIZE];
	uint8_t key_len;

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <peer mac address>\n");
		return 1;
	}

	ival = parse_mac_addr(argv[0], peer_address);

	if (ival >= 0) {
		qcsapi_retval = qcsapi_wifi_wds_get_psk(the_interface,
							peer_address,
							pre_shared_key,
							&key_len);

		if (qcsapi_retval >= 0) {
			uint8_t i;

			for (i = 0; i < key_len; i++) {
				print_out(print, "%02x",
						pre_shared_key[i]);
			}
			print_out(print, "\n");
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	} else {
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_wds_set_psk(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	qcsapi_mac_addr peer_address;
	char *p_pre_shared_key = NULL;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int ival = 0;

	if (argc < 2) {
		print_err( print,
	   "Not enough parameters in call qcsapi WiFi wds set psk, count is %d\n", argc );
		statval = 1;
	} else {
		ival = parse_mac_addr(argv[0], peer_address);

		if (ival >= 0) {
			p_pre_shared_key = argv[1];
			if (strcmp(p_pre_shared_key, "NULL") == 0) {
				p_pre_shared_key = NULL;
			}
			qcsapi_retval = qcsapi_wifi_wds_set_psk(the_interface, peer_address, p_pre_shared_key);

			if (qcsapi_retval >= 0) {
				if (verbose_flag >= 0) {
					print_out( print, "complete\n");
				}
			} else {
				report_qcsapi_error(p_calling_bundle, qcsapi_retval);
				statval = 1;
			}
		} else {
			print_out( print, "Error parsing MAC address %s\n", argv[ 0 ]);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wifi_wds_set_mode(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	qcsapi_mac_addr peer_address;
	int rbs_mode;
	int rbs_mask;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int ival = 0;

	if (argc < 2) {
		print_err( print, "Not enough parameters in call qcsapi WiFi wds set "
				"mode, count is %d\n", argc );
		statval = 1;
	} else {
		ival = parse_mac_addr(argv[0], peer_address);

		if (ival >= 0) {
			if (strcasecmp(argv[1], "rbs") == 0) {
				rbs_mode = IEEE80211_QTN_WDS_RBS;
				rbs_mask = IEEE80211_QTN_WDS_MASK;
			} else if (strcasecmp(argv[1], "mbs") == 0) {
				rbs_mode = IEEE80211_QTN_WDS_MBS;
				rbs_mask = IEEE80211_QTN_WDS_MASK;
			} else if (strcasecmp(argv[1], "wds") == 0) {
				rbs_mode = IEEE80211_QTN_WDS_ONLY;
				rbs_mask = IEEE80211_QTN_WDS_MASK;
			} else if (strcasecmp(argv[1], "reset") == 0) {
				rbs_mode = 0;
				rbs_mask = IEEE80211_QTN_EXTDR_ALLMASK;
			} else {
				print_out(print, "Error parsing WDS mode %s\n", argv[1]);
				return 1;
			}

			qcsapi_retval = qcsapi_wds_set_mode(the_interface, peer_address,
					ieee80211_extdr_combinate(rbs_mode, rbs_mask));

			if (qcsapi_retval >= 0) {
				if (verbose_flag >= 0) {
					print_out( print, "complete\n");
				}
			} else {
				report_qcsapi_error(p_calling_bundle, qcsapi_retval);
				statval = 1;
			}
		} else {
			print_out( print, "Error parsing MAC address %s\n", argv[ 0 ]);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wifi_wds_get_mode(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	int rbs_mode;
	qcsapi_unsigned_int index = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *mode_str[] = {"mbs", "rbs", "none"};

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi WiFi get "
			"peer address, count is %d\n", argc );
		statval = 1;
	} else {
		if (local_str_to_uint32(argv[0], &index, print, "index") < 0)
			return 1;

		qcsapi_retval = qcsapi_wds_get_mode(the_interface, index, &rbs_mode);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "wds %s\n", mode_str[rbs_mode]);
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wifi_qos_get_param(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	int		qcsapi_retval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	int		the_queue = -1;
	int		the_param = -1;
	int		ap_bss_flag = 0;
	int		qos_param_value;
	int		i;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err(print, "Usage: call_qcsapi qos_get_param <WiFi interface> "
				"<QoS queue> <QoS param> [AP / BSS flag]\n");
		return 1;
	}

	if ((qcsapi_util_str_to_int32(argv[0], &the_queue) < 0)
			&& (name_to_qos_queue_type(argv[0], &the_queue) == 0)) {
		print_err(print, "Unrecognized QoS queue %s\n", argv[0]);
		if (verbose_flag >= 0) {
			print_out( print, "Supported QOS queue ID and name:\n" );
			for (i = 0; i < ARRAY_SIZE(qcsapi_qos_queue_table); i++)
				print_out( print, "%d: %s\n",
						qcsapi_qos_queue_table[i].qos_queue_type,
						qcsapi_qos_queue_table[i].qos_queue_name );
		}
		return 1;
	}

	if ((qcsapi_util_str_to_int32(argv[1], &the_param) < 0)
			&& (name_to_qos_param_type(argv[1], &the_param) == 0)) {
		print_err(print, "Unrecognized QoS param %s\n", argv[1]);
		if (verbose_flag >= 0) {
			print_out( print, "Supported QOS param ID and name:\n" );
			for (i = 0; i < ARRAY_SIZE(qcsapi_qos_param_table); i++)
				print_out( print, "%d: %s\n",
						qcsapi_qos_param_table[i].qos_param_type,
						qcsapi_qos_param_table[i].qos_param_name );
		}
		return 1;
	}

	if (argc > 2) {
		if (local_str_to_int32(argv[2], &ap_bss_flag, print, "AP/BSS flag") < 0)
			return 1;
	}

	qcsapi_retval = qcsapi_wifi_qos_get_param(the_interface,
						  the_queue,
						  the_param,
						  ap_bss_flag,
						  &qos_param_value);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%d\n", qos_param_value);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_qos_set_param(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	int		qcsapi_retval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	int		the_queue = -1;
	int		the_param = -1;
	int		ap_bss_flag = 0;
	int		param_value = -1;
	int		i;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 3) {
		print_err(print, "Usage: call_qcsapi qos_get_param <WiFi interface> "
				"<QoS queue> <QoS param> <value> [AP / BSS flag]\n");
		return 1;
	}

	if ((qcsapi_util_str_to_int32(argv[0], &the_queue) < 0)
			&& (name_to_qos_queue_type(argv[0], &the_queue) == 0)) {
		print_err(print, "Unrecognized QoS queue %s\n", argv[0]);
		if (verbose_flag >= 0) {
			print_out( print, "Supported QOS queue ID and name:\n" );
			for (i = 0; i < ARRAY_SIZE(qcsapi_qos_queue_table); i++)
				print_out( print, "%d: %s\n",
						qcsapi_qos_queue_table[i].qos_queue_type,
						qcsapi_qos_queue_table[i].qos_queue_name );
		}
		return 1;
	}

	if ((qcsapi_util_str_to_int32(argv[1], &the_param) < 0)
			&& (name_to_qos_param_type(argv[1], &the_param) == 0)) {
		print_err(print, "Unrecognized QoS param %s\n", argv[1]);
		if (verbose_flag >= 0) {
			print_out( print, "Supported QOS param ID and name:\n" );
			for (i = 0; i < ARRAY_SIZE(qcsapi_qos_param_table); i++)
				print_out( print, "%d: %s\n",
						qcsapi_qos_param_table[i].qos_param_type,
						qcsapi_qos_param_table[i].qos_param_name );
		}
		return 1;
	}

	if (local_str_to_int32(argv[2], &param_value, print, "QoS param value") < 0)
		return 1;

	if (argc > 3) {
		if (local_str_to_int32(argv[3], &ap_bss_flag, print, "AP/BSS flag") < 0)
			return 1;
	}

	qcsapi_retval = qcsapi_wifi_qos_set_param(the_interface,
						  the_queue,
						  the_param,
						  ap_bss_flag,
						  param_value);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_wmm_ac_map(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	string_64 ac_map; /* Must be a string for the RPC generation Perl script */
	qcsapi_output	*print = p_calling_bundle->caller_output;

	assert(sizeof(ac_map) >= QCSAPI_WIFI_AC_MAP_SIZE);

	memset(ac_map, 0, sizeof(ac_map));
	qcsapi_retval = qcsapi_wifi_get_wmm_ac_map(the_interface, ac_map);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%s\n", ac_map);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_wmm_ac_map(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	int		qcsapi_retval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	int		user_prio = -1;
	int		ac_index = -1;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err(print, "Usage: call_qcsapi set_wmm_ac_map <WiFi interface> "
				"<user priority> <AC index>\n");
		return 1;
	}

	if (local_str_to_int32(argv[0], &user_prio, print, "user priority") < 0)
		return 1;

	if (local_str_to_int32(argv[1], &ac_index, print, "AC index") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_wmm_ac_map(the_interface,
						  user_prio,
						  ac_index);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_dscp_8021p_map(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	i;
	int	statval = 0;
	int	qcsapi_retval = 0;
	string_64 dot1p_mapping; /* Must be a string for the RPC generation Perl script */
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	assert(sizeof(dot1p_mapping) >= IP_DSCP_NUM);

	memset(dot1p_mapping, 0, sizeof(dot1p_mapping));
	qcsapi_retval = qcsapi_wifi_get_dscp_8021p_map(the_interface, (char *)dot1p_mapping);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "IP DSCP/802.1p UP:\n");
			for (i = 0; i < IP_DSCP_NUM; i++) {
				print_out(print, "%2d/%d ", i, dot1p_mapping[i]);
				if ((i+1)%IEEE8021P_PRIORITY_NUM == 0)
					print_out(print, "\n");
			}
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_dscp_8021p_map(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval = 0;
	int	dot1p_up = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err(print, "Usage: call_qcsapi set_dscp_8021p_map <WiFi interface> "
				"<IP DSCP list> <802.1p UP>\n");
		return 1;
	}

	if (local_str_to_int32(argv[1], &dot1p_up, print, "802.1p UP value") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_dscp_8021p_map(the_interface, argv[0], dot1p_up);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_dscp_ac_map(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
#define QCSAPI_BINARY_CONVERT_MASK	0x20
	int	i;
	int	statval = 0;
	int	qcsapi_retval = 0;
	struct qcsapi_data_64bytes ac_mapping;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	const char *acstr[] = {"AC_BE", "AC_BK", "AC_VI", "AC_VO"};

	assert(sizeof(ac_mapping) >= IP_DSCP_NUM);

	memset(&ac_mapping, 0, sizeof(ac_mapping));
	qcsapi_retval = qcsapi_wifi_get_dscp_ac_map(the_interface, &ac_mapping);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "DSCP            AC\n");
			for (i = 0; i < IP_DSCP_NUM; i++) {
				uint8_t mask = QCSAPI_BINARY_CONVERT_MASK;
				/* Print DSCP in binary format */
				while (mask) {
					 print_out(print, "%d", i & mask ? 1 : 0);
					 mask >>= 1;
				}
				print_out(print, "(0x%02x)    %s\n", i, acstr[(uint8_t)ac_mapping.data[i]]);
			}
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

/*
 * Convert given formatted dscp string into digital value
 * Two types of formatted dscp string are acceptable
 * eg,
 * TYPE I  -- 3,4,5,25,38
 * TYPE II -- 3-25
*/
static int call_qcsapi_convert_ipdscp_digital(const char *dscpstr, uint8_t *array, uint8_t *number)
{
	uint8_t ip_dscp_number = 0;
	char *pcur;
	char *p;
	char buffer[256] = {0};

	if (dscpstr == NULL || array == NULL || number == NULL)
		return -EINVAL;

	strncpy(buffer, dscpstr, (sizeof(buffer) - 1));
	pcur = buffer;
	do {
		p = strchr(pcur,'-');
		if (p) {
			int dscpstart;
			int dscpend;
			int i;

			*p = '\0';
			p++;

			if (qcsapi_util_str_to_int32(pcur, &dscpstart) < 0)
				return -EINVAL;

			if (qcsapi_util_str_to_int32(p, &dscpend) < 0)
				return -EINVAL;

			if ((dscpstart > dscpend) || (dscpstart >= IP_DSCP_NUM)
				|| (dscpend >= IP_DSCP_NUM))
				return -EINVAL;
			ip_dscp_number = dscpend - dscpstart;
			for (i = 0; i <= ip_dscp_number; i++)
				array[i] =  dscpstart + i;
			break;
		} else {
			int value;

			if (ip_dscp_number > (IP_DSCP_NUM - 1))
				return -EINVAL;

			p = strchr(pcur,',');
			if (p) {
				*p = '\0';
				p++;

				if (qcsapi_util_str_to_int32(pcur, &value) < 0)
					return -EINVAL;

				array[ip_dscp_number] = value;

				if (array[ip_dscp_number] >= IP_DSCP_NUM)
					return -EINVAL;
				pcur = p;
				ip_dscp_number++;
			} else {
				if (qcsapi_util_str_to_int32(pcur, &value) < 0)
					return -EINVAL;

				array[ip_dscp_number] = value;

				if (array[ip_dscp_number] >= IP_DSCP_NUM)
					return -EINVAL;
			}
		}
	} while (p);
	*number = ip_dscp_number + 1;

	return 0;
}

static int
call_qcsapi_wifi_set_dscp_ac_map(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval = 0;
	uint8_t	listlen = 0;
	unsigned int ac = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	struct qcsapi_data_64bytes ip_dscp_value;

	if (argc != 2) {
		print_err(print,
			"Usage: call_qcsapi set_dscp_ac_map <WiFi interface> "
				"<IP DSCP list> <ac>\n");
		return 1;
	}

	if (local_str_to_uint32(argv[1], &ac, print, "access category value") < 0)
		return 1;

	memset(&ip_dscp_value, 0, sizeof(ip_dscp_value));
	statval = call_qcsapi_convert_ipdscp_digital(argv[0], ip_dscp_value.data, &listlen);
	if (statval < 0)
		return statval;

	qcsapi_retval = qcsapi_wifi_set_dscp_ac_map(the_interface, &ip_dscp_value, listlen, ac);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_ac_agg_hold_time(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int             statval = 0;
	int             qcsapi_retval = 0;
	uint32_t        ac = 0;
	uint32_t        agg_hold_time = 0;
	const char      *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output   *print = p_calling_bundle->caller_output;
	char            *usage = "<WiFi interface> <ac>\n";

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return 1;
	}

	if (local_str_to_uint32(argv[0], &ac, print, "access class") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_get_ac_agg_hold_time(the_interface, ac, &agg_hold_time);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%d\n", agg_hold_time);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_ac_agg_hold_time(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	int		qcsapi_retval = 0;
	uint32_t	ac = 0;
	uint32_t	agg_hold_time = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	char		*usage = "<WiFi interface> <ac> <agg_hold_time>\n";

	if (argc != 2) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return 1;
	}

	if (local_str_to_uint32(argv[0], &ac, print, "access class") < 0)
		return 1;

	if (local_str_to_uint32(argv[1], &agg_hold_time, print, "aggregation hold time") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_ac_agg_hold_time(the_interface, ac, agg_hold_time);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_qos_map(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	const char *ifname = p_calling_bundle->caller_interface;

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <QoS Map String>\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_qos_map(ifname, argv[0]);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_wifi_del_qos_map(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	const char *ifname = p_calling_bundle->caller_interface;

	qcsapi_retval = qcsapi_wifi_del_qos_map(ifname);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_wifi_get_qos_map(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	const char *ifname = p_calling_bundle->caller_interface;
	string_256 value_buf = {0};

	qcsapi_retval = qcsapi_wifi_get_qos_map(ifname, value_buf);

	return qcsapi_report_str_or_error(p_calling_bundle, qcsapi_retval, value_buf);
}

static int
call_qcsapi_wifi_send_qos_map_conf(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	const char *ifname = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_mac_addr sta_mac_addr = {0};

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <STA MAC address>\n");
		return 1;
	}

	if (parse_mac_addr(argv[0], sta_mac_addr)) {
		print_err(print, "\"%s\" is not a valid MAC address\n", argv[0]);
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_send_qos_map_conf(ifname, sta_mac_addr);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_wifi_get_dscp_tid_map(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	const char *ifname = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	struct qcsapi_data_64bytes dscp2tid = {{0}};
	int dscp;

	qcsapi_retval = qcsapi_wifi_get_dscp_tid_map(ifname, &dscp2tid);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	print_out(print, "DSCP: TID\n");
	for (dscp = 0; dscp < ARRAY_SIZE(dscp2tid.data); dscp++) {
		print_out(print, "%4d: %u\n", dscp, dscp2tid.data[dscp]);
	}

	return 0;
}

static int
call_qcsapi_wifi_get_priority(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval = 0;
	uint8_t	priority;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_priority(the_interface, &priority);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%u\n", priority);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static void
call_qcsapi_wifi_set_priority_usage(qcsapi_output *print)
{
	print_err(print, "Usage: call_qcsapi set_priority <WiFi interface> <priority>\n");
	print_err(print, "Priority is an integer from 0 to %u.\n", QTN_VAP_PRIORITY_NUM - 1);
}

static int
call_qcsapi_wifi_set_priority(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval = 0;
	int	priority = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc != 1) {
		call_qcsapi_wifi_set_priority_usage(print);
		return 1;
	}

	if (local_str_to_int32(argv[0], &priority, print, "interface priority value") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_priority(the_interface, priority);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_airfair(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval = 0;
	uint8_t	airfair;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_airfair(the_interface, &airfair);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%u\n", airfair);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static void
call_qcsapi_wifi_set_airfair_usage(qcsapi_output *print)
{
	print_err(print, "Usage: call_qcsapi set_airfair <WiFi interface> <status>\n");
	print_err(print, "Status is either 0(disabled) or 1(enabled).\n");
}

static int
call_qcsapi_wifi_set_airfair(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval = 0;
	uint8_t	airfair = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc != 1) {
		call_qcsapi_wifi_set_airfair_usage(print);
		return 1;
	}

	if (local_verify_enable_or_disable(argv[0], &airfair, print) < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_airfair(the_interface, airfair);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_config_get_parameter(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Usage: call_qcsapi get_persistent_param <WiFi interface> <parameter name>\n");
		statval = 1;
	} else {
		int		qcsapi_retval = 0;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*parameter_name = argv[ 0 ];
		char		parameter_value_buffer[QCSAPI_MAX_PARAMETER_VALUE_LEN] = "";
		char		*parameter_value = &parameter_value_buffer[0];
		size_t		parameter_value_size = QCSAPI_MAX_PARAMETER_VALUE_LEN;
		unsigned int	result;

		if (strcmp(parameter_name, "NULL") == 0) {
			parameter_name = NULL;
		}

		if (argc > 1) {
			if (strcmp(argv[1], "NULL") == 0) {
				parameter_value = NULL;
			} else {
				if (local_str_to_uint32(argv[1], &result, print, "size")
						< 0)
					return 1;

				parameter_value_size = (size_t) result;
			}
		}

		qcsapi_retval = qcsapi_config_get_parameter(the_interface,
							    parameter_name,
							    parameter_value,
							    parameter_value_size);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out(print, "%s\n", &parameter_value_buffer[0]);
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_config_update_parameter(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err( print,
	   "Not enough parameters in call qcsapi update persistent parameter, count is %d\n", argc);
		print_err( print, "Usage: call_qcsapi update_persistent_param <WiFi interface> <parameter name> <value>\n");
		statval = 1;
	} else {
		int		qcsapi_retval = 0;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*parameter_name = argv[ 0 ];
		char		*parameter_value = argv[ 1 ];

		if (strcmp(parameter_name, "NULL") == 0) {
			parameter_name = NULL;
		}

		if (strcmp(parameter_value, "NULL") == 0) {
			parameter_value = NULL;
		}

		qcsapi_retval = qcsapi_config_update_parameter(the_interface, parameter_name, parameter_value);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_config_get_ssid_parameter(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Usage: call_qcsapi get_persistent_ssid_param <WiFi interface> <parameter name>\n");
		statval = 1;
	} else {
		int		qcsapi_retval = 0;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*parameter_name = argv[ 0 ];
		char		parameter_value_buffer[QCSAPI_MAX_PARAMETER_VALUE_LEN] = "";
		char		*parameter_value = &parameter_value_buffer[0];
		size_t		parameter_value_size = QCSAPI_MAX_PARAMETER_VALUE_LEN;
		unsigned int	result;

		if (strcmp(parameter_name, "NULL") == 0) {
			parameter_name = NULL;
		}

		if (argc > 1) {
			if (strcmp(argv[1], "NULL") == 0) {
				parameter_value = NULL;
			} else {
				if (local_str_to_uint32(argv[1], &result, print, "size")
							< 0)
					return 1;

				parameter_value_size = (size_t) result;
			}
		}

		qcsapi_retval = qcsapi_config_get_ssid_parameter(the_interface,
							    parameter_name,
							    parameter_value,
							    parameter_value_size);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out(print, "%s\n", &parameter_value_buffer[0]);
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_config_update_ssid_parameter(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err( print,
				"Not enough parameters in call_qcsapi update_persistent_ssid_parameter\n");
		print_err( print,
				"Usage: call_qcsapi update_persistent_ssid_param <WiFi interface> <parameter name> <value>\n");
		statval = 1;
	} else {
		int		qcsapi_retval = 0;
		const char	*the_interface = p_calling_bundle->caller_interface;
		char		*parameter_name = argv[ 0 ];
		char		*parameter_value = argv[ 1 ];

		if (strcmp(parameter_name, "NULL") == 0) {
			parameter_name = NULL;
		}

		if (strcmp(parameter_value, "NULL") == 0) {
			parameter_value = NULL;
		}

		qcsapi_retval = qcsapi_config_update_ssid_parameter(the_interface, parameter_name, parameter_value);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_get_qfdr_parameter(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print,
			   "Not enough parameters in call qcsapi get qfdr parameter, count is %d\n", argc);
		print_err( print, "Usage: call_qcsapi get_qfdr_param <parameter name>\n");
		statval = 1;
	} else {
		int		qcsapi_retval = 0;
		char		*parameter_name = argv[ 0 ];
		char		parameter_value[QCSAPI_MAX_PARAMETER_VALUE_LEN + 1] = {'\0'};
		char		*param_value_addr = &parameter_value[0];
		size_t		parameter_len = QCSAPI_MAX_PARAMETER_VALUE_LEN + 1;
		unsigned int	result;

		if (strcmp(parameter_name, "NULL") == 0) {
			parameter_name = NULL;
		}

		if (argc > 1 && strcmp(argv[1], "NULL") == 0) {
			param_value_addr = NULL;
		}

		if (argc > 2) {
			if (local_str_to_uint32(argv[2], &result, print, "parameter") < 0)
				return 1;

			parameter_len = (size_t) result;
		}

		qcsapi_retval = qcsapi_get_qfdr_parameter(parameter_name,
							     param_value_addr,
							     parameter_len);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "%s\n", param_value_addr);
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_set_qfdr_parameter(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err( print,
			   "Not enough parameters in call qcsapi set qfdr parameter, count is %d\n", argc);
		print_err( print, "Usage: call_qcsapi set_qfdr_param <parameter name> <value>\n");
		statval = 1;
	} else {
		int		qcsapi_retval = 0;
		char		*parameter_name = argv[0];
		char		*param_value_addr = argv[1];

		if (strcmp(parameter_name, "NULL") == 0) {
			parameter_name = NULL;
		}

		if (strcmp(param_value_addr, "NULL") == 0) {
			param_value_addr = NULL;
		}

		qcsapi_retval = qcsapi_set_qfdr_parameter(parameter_name, param_value_addr);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_get_qfdr_state(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval;
	int	state;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	const char	*the_interface = p_calling_bundle->caller_interface;

	qcsapi_retval = qcsapi_get_qfdr_state(the_interface, &state);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%d\n", state);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return (statval);
}

static int
call_qcsapi_bootcfg_get_parameter(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print,
	   "Not enough parameters in call qcsapi get bootcfg parameter, count is %d\n", argc);
		print_err( print, "Usage: call_qcsapi get_bootcfg_param <parameter name>\n");
		statval = 1;
	} else {
		int		qcsapi_retval = 0;
		char		*parameter_name = argv[ 0 ];
		char		parameter_value[QCSAPI_MAX_PARAMETER_VALUE_LEN + 1] = {'\0'};
		char		*param_value_addr = &parameter_value[0];
		size_t		parameter_len = QCSAPI_MAX_PARAMETER_VALUE_LEN + 1;
		unsigned int	result;

		if (strcmp(parameter_name, "NULL") == 0) {
			parameter_name = NULL;
		}

		if (argc > 1 && strcmp(argv[1], "NULL") == 0) {
			param_value_addr = NULL;
		}

		if (argc > 2) {
			if (local_str_to_uint32(argv[2], &result, print, "parameter") < 0)
				return 1;

			parameter_len = (size_t) result;
		}

		qcsapi_retval = qcsapi_bootcfg_get_parameter(parameter_name,
							     param_value_addr,
							     parameter_len);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "%s\n", param_value_addr);
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_bootcfg_update_parameter(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err( print,
	   "Not enough parameters in call qcsapi update bootcfg parameter, count is %d\n", argc);
		print_err( print, "Usage: call_qcsapi update_bootcfg_param <parameter name> <value>\n");
		statval = 1;
	} else {
		int		qcsapi_retval = 0;
		char		*parameter_name = argv[0];
		char		*param_value_addr = argv[1];

		if (strcmp(parameter_name, "NULL") == 0) {
			parameter_name = NULL;
		}

		if (strcmp(param_value_addr, "NULL") == 0) {
			param_value_addr = NULL;
		}

		qcsapi_retval = qcsapi_bootcfg_update_parameter(parameter_name, param_value_addr);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_bootcfg_commit(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval = 0;

	qcsapi_retval = qcsapi_bootcfg_commit();

	if (qcsapi_retval >= 0) {
		print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_service_control(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int     statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err( print,
				"Not enough parameters in call qcsapi service_control, count is %d\n", argc);
		print_err( print, "Usage: call_qcsapi service_control <service name> <action>\n");
		statval = 1;
	} else {
		int     qcsapi_retval = 0;
		char *name = argv[0];
		char *action = argv[1];
		qcsapi_service_name serv_name;
		qcsapi_service_action serv_action;

		if (strcmp(argv[0], "NULL") == 0) {
			name = NULL;
		} else if (strcmp(argv[0], "telnet") == 0) {
			name = "inetd";
		}
		if (strcmp(argv[1], "NULL") == 0) {
			action = NULL;
		}

		qcsapi_retval = qcsapi_get_service_name_enum(name, &serv_name);
		if (qcsapi_retval  >= 0) {
			qcsapi_retval  = qcsapi_get_service_action_enum(action, &serv_action);
		}

		if (qcsapi_retval  >= 0) {
			qcsapi_retval = qcsapi_service_control(serv_name, serv_action);
		}

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}
	return statval;
}

static int
call_qcsapi_wfa_cert(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t enable = 1;

	if (argc > 0) {
		if (safe_atou16(argv[0], &enable, print, 0, 1) == 0)
			return 1;
	}

	qcsapi_retval = qcsapi_wfa_cert_mode_enable(!!enable);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_scs_enable(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t enable = 1;

	if (argc > 0) {
		if (0 == safe_atou16(argv[0], &enable, print, 0, 1))
			return 1;
	}

	qcsapi_retval = qcsapi_wifi_scs_enable(the_interface, enable);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static void
print_scs_switch_channel_usage(call_qcsapi_bundle *p_calling_bundle)
{
	qcsapi_report_usage(p_calling_bundle,
			"<interface name> <pick flags> [check margin]\n"
			"pick flags should be : dfs, non_dfs, all(default)\n"
			"check margin should be : 0 or 1 which means if we should check the margin");
}

static int
call_qcsapi_wifi_scs_switch_channel(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t pick_flags = 0;
	uint16_t check_margin = 0;

	if (argc >= 1 && argc <= 2) {
		if (!strcasecmp("dfs", argv[0])) {
			pick_flags |= IEEE80211_SCS_PICK_AVAILABLE_DFS_ONLY;
		} else if (!strcasecmp("non_dfs", argv[0])) {
			pick_flags |= IEEE80211_SCS_PICK_NON_DFS_ONLY;
		} else if (!strcasecmp("all", argv[0])) {
			pick_flags |= IEEE80211_SCS_PICK_AVAILABLE_ANY_CHANNEL;
		} else {
			print_scs_switch_channel_usage(p_calling_bundle);
			return 1;
		}

		if (argc == 2 && safe_atou16(argv[1], &check_margin, print, 0, 1) == 0)
			return 1;
		else if (check_margin == 0)
			pick_flags |= IEEE80211_SCS_PICK_ANYWAY;
	} else if (argc == 0) {
		pick_flags |= IEEE80211_SCS_PICK_AVAILABLE_ANY_CHANNEL;
	} else {
		print_scs_switch_channel_usage(p_calling_bundle);
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_scs_switch_channel(the_interface, pick_flags);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_scs_pick_best_channel(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t pick_flags = IEEE80211_SCS_NOPICK |
				IEEE80211_SCS_PICK_ANYWAY |
				IEEE80211_SCS_PICK_ALLOW_CURRENT;
	uint16_t check_margin = 0;
	int channel = -1;

	if (argc >= 1 && argc <= 2) {
		if (!strcasecmp("dfs", argv[0])) {
			pick_flags |= IEEE80211_SCS_PICK_AVAILABLE_DFS_ONLY;
		} else if (!strcasecmp("non_dfs", argv[0])) {
			pick_flags |= IEEE80211_SCS_PICK_NON_DFS_ONLY;
		} else if (!strcasecmp("all", argv[0])) {
			pick_flags |= IEEE80211_SCS_PICK_AVAILABLE_ANY_CHANNEL;
		} else {
			print_scs_switch_channel_usage(p_calling_bundle);
			return 1;
		}

		if (argc == 2 && safe_atou16(argv[1], &check_margin, print, 0, 1) == 0)
			return 1;
		else if (check_margin == 1)
			pick_flags &= ~(IEEE80211_SCS_PICK_ANYWAY | IEEE80211_SCS_PICK_ALLOW_CURRENT);
	} else if (argc == 0) {
		pick_flags |= IEEE80211_SCS_PICK_AVAILABLE_ANY_CHANNEL;
	} else {
		print_scs_switch_channel_usage(p_calling_bundle);
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_scs_pick_best_channel(the_interface, pick_flags, &channel);

	if (qcsapi_retval >= 0) {
		print_out(print, "%d\n", channel);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_set_scs_verbose(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t level;

	if (safe_atou16(argv[0], &level, print, SCSLOG_CRIT, SCSLOG_LEVEL_MAX) == 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_scs_verbose(the_interface, level);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_scs_status(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	qcsapi_unsigned_int status = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_scs_status(the_interface, &status);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			if (status == 1)
				print_out( print, "Enabled (%d)\n", status);
			else if (status == 0)
				print_out( print, "Disabled (%d)\n", status);
			else
				print_out( print, "Unknown (%d)\n", status);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scs_smpl_enable(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint8_t enable = 1;

	if (argc > 0) {
		if (local_verify_enable_or_disable(argv[0], &enable, print) < 0)
			return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_scs_smpl_enable(the_interface, enable);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static void call_qcsapi_wifi_set_scs_active_chan_list_help(call_qcsapi_bundle *p_calling_bundle)
{
	qcsapi_report_usage(p_calling_bundle, "<Wifi interface> <channel list> <enable_disable flag>\n");
}

static int
call_qcsapi_wifi_set_scs_active_chan_list(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 1;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	struct qcsapi_scs_chan_list scs_ch_list;
	uint32_t ch_count;
	uint32_t enable;

	if (argc < 2) {
		call_qcsapi_wifi_set_scs_active_chan_list_help(p_calling_bundle);
		return 1;
	}

	if (local_atou32_verify_numeric_range(argv[1], &enable, print, 0, 1) < 0) {
		call_qcsapi_wifi_set_scs_active_chan_list_help(p_calling_bundle);
		return 1;
	}

	memset(&scs_ch_list, 0, sizeof(scs_ch_list));
	statval = local_string_to_list(argv[0], scs_ch_list.chan, &ch_count);
	if (statval < 0) {
		call_qcsapi_wifi_set_scs_active_chan_list_help(p_calling_bundle);
		return statval;
	}
	scs_ch_list.num = ch_count;

	qcsapi_retval = qcsapi_wifi_set_scs_active_chan_list(the_interface, &scs_ch_list, enable);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
		statval = 0;
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
	}

	return statval;
}

static int
call_qcsapi_wifi_get_scs_active_chan_list(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	struct qcsapi_scs_chan_list scs_ch_list;
	int i;

	memset(&scs_ch_list, 0, sizeof(scs_ch_list));

	qcsapi_retval = qcsapi_wifi_get_scs_active_chan_list(the_interface, &scs_ch_list);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	} else {
		print_out(print, "Number of SCS enabled channels: %u\n", scs_ch_list.num);
		for (i = 0; i < scs_ch_list.num; i++)
			print_out(print, "%d ", scs_ch_list.chan[i]);
		print_out(print, "\n");
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scs_smpl_dwell_time(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	uint16_t sample_time = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_out( print, "%s: programming error, expected at least 1 additional parameter\n", __func__);
		return(1);
	}

	if (safe_atou16(argv[0], &sample_time, print,
			IEEE80211_SCS_SMPL_DWELL_TIME_MIN, IEEE80211_SCS_SMPL_DWELL_TIME_MAX) == 0) {
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_scs_smpl_dwell_time(the_interface, sample_time);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scs_sample_intv(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	uint16_t sample_intv = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (safe_atou16(argv[0], &sample_intv, print,
			IEEE80211_SCS_SMPL_INTV_MIN, IEEE80211_SCS_SMPL_INTV_MAX) == 0) {
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_scs_sample_intv(the_interface, sample_intv);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_scs_sample_intv(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	int		qcsapi_retval;
	qcsapi_unsigned_int scs_sample_intv = 0;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	const char	*the_interface = p_calling_bundle->caller_interface;

	qcsapi_retval = qcsapi_wifi_get_scs_sample_intv(the_interface, &scs_sample_intv);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%u\n", scs_sample_intv);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_scs_sample_type(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	uint16_t sample_type = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (safe_atou16(argv[0], &sample_type, print, 1, 0xFFFF))
		return 1;

	qcsapi_retval = qcsapi_wifi_set_scs_sample_type(the_interface, sample_type);

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_wifi_set_scs_intf_detect_intv(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	uint16_t intv = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (safe_atou16(argv[0], &intv, print,
			IEEE80211_SCS_CCA_DUR_MIN, IEEE80211_SCS_CCA_DUR_MAX) == 0) {
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_scs_intf_detect_intv(the_interface, intv);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scs_thrshld(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err( print,
		       "Not enough parameters in call_qcsapi set_scs_thrshld, count is %d\n",
			argc);
		print_err( print,
			"Usage: call_qcsapi set_scs_thrshld <Wifi interface> <threshold parameter> <threshold value>\n");
		statval = 1;
	} else {
		int qcsapi_retval = 0;
		const char *the_interface = p_calling_bundle->caller_interface;
		char *thrshld_param_name = argv[0];
		uint16_t thrshld_value;

		if (safe_atou16(argv[1], &thrshld_value, print,
				0, 0xFFFF) == 0) {
			return 1;
		}

		qcsapi_retval = qcsapi_wifi_set_scs_thrshld(the_interface, thrshld_param_name, thrshld_value);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scs_report_only(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{

	int statval = 0;
	int qcsapi_retval = 0;
	uint8_t report_value = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (local_verify_enable_or_disable(argv[0], &report_value, print) < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_scs_report_only(the_interface, report_value);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scs_override_mode(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	uint16_t override = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (safe_atou16(argv[0], &override, print, 0, 1) == 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_scs_override_mode(the_interface, override);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_scs_report(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int i;

	if (strcmp(argv[0], "current") == 0) {
		struct qcsapi_scs_currchan_rpt rpt;
		qcsapi_retval = qcsapi_wifi_get_scs_currchan_report(the_interface, &rpt);
		if (qcsapi_retval < 0) {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		} else {
			print_out(print, "SCS: current channel %d, cca_try=%u, cca_idle=%u cca_busy=%u cca_intf=%u"
					" cca_tx=%u tx_ms=%u rx_ms=%u pmbl_cnt=%u\n",
					rpt.chan,
					rpt.cca_try,
					rpt.cca_idle,
					rpt.cca_busy,
					rpt.cca_intf,
					rpt.cca_tx,
					rpt.tx_ms,
					rpt.rx_ms,
					rpt.pmbl);
		}
	} else if (strcmp(argv[0], "all") == 0) {
		struct qcsapi_scs_ranking_rpt rpt;
		const char  *str[] = QTN_CHAN_AVAIL_STATUS_TO_STR;

		qcsapi_retval = qcsapi_wifi_get_scs_stat_report(the_interface, &rpt);

		if (qcsapi_retval < 0) {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		} else {
			print_out(print, "SCS ranking report: chan number = %u\n", rpt.num);
			print_out(print, "chan dfs txpower  numbeacon cca_intf  weight    metric    pmbl_ap   pmbl_sta"
					 "   age duration times status\n");
			for (i = 0; i < rpt.num; i++) {
				print_out(print, "%4d %3d %7d %10u %8u %7d %9d %10d %10d %5u %8u %5u %s\n",
					rpt.chan[i],
					rpt.dfs[i],
					rpt.txpwr[i],
					rpt.numbeacons[i],
					rpt.cca_intf[i],
					rpt.weight[i],
					rpt.metric[i],
					rpt.pmbl_ap[i],
					rpt.pmbl_sta[i],
					rpt.metric_age[i],
					rpt.duration[i],
					rpt.times[i],
					str[rpt.chan_avail_status[i]]);
			}
		}
	} else if (strcmp(argv[0], "autochan") == 0) {
		struct qcsapi_autochan_rpt rpt;
		qcsapi_retval = qcsapi_wifi_get_autochan_report(the_interface, &rpt);
		if (qcsapi_retval < 0) {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		} else {
			print_out(print, "AP: initial auto channel ranking table: chan number = %u\n", rpt.num);
			print_out(print, "chan dfs txpower  numbeacon     cci     aci  weight         metric\n");
			for (i = 0; i < rpt.num; i++) {
				print_out(print, "%4d %3d %7d %10u %7d %7d %7d %14d\n",
					rpt.chan[i],
					rpt.dfs[i],
					rpt.txpwr[i],
					rpt.numbeacons[i],
					rpt.cci[i],
					rpt.aci[i],
					rpt.weight[i],
					rpt.metric[i]);
			}
		}
	} else if (strcmp(argv[0], "score") == 0) {
		struct qcsapi_scs_score_rpt rpt;
		qcsapi_retval = qcsapi_wifi_get_scs_score_report(the_interface, &rpt);
		if (qcsapi_retval < 0) {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		} else {
			print_out(print, "SCS score report: channel number = %u\n", rpt.num);
			print_out(print, "channel  score\n");
			for (i = 0; i < rpt.num; i++) {
				print_out(print, "%4d  %5d\n", rpt.chan[i], rpt.score[i]);
			}
		}
	} else if (strcmp(argv[0], "interference") == 0) {
#define INTF_NUM		6
#define SCS_CCA_INTF_INVALID	0xFFFF
		struct qcsapi_scs_interference_rpt rpt;
		char cca_intf20[INTF_NUM];
		char cca_intf40[INTF_NUM];
		char cca_intf80[INTF_NUM];

		qcsapi_retval = qcsapi_wifi_get_scs_interference_report(the_interface, &rpt);
		if (qcsapi_retval < 0) {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			return 1;
		}
		print_out(print, "SCS ranking report: chan number = %u\n", rpt.num);
		print_out(print, "chan cca_intf_20 cca_intf_40 cca_intf_80\n");
		for (i = 0; i < rpt.num; i++) {
			snprintf(cca_intf20, INTF_NUM, "%u", rpt.cca_intf_20[i]);
			snprintf(cca_intf40, INTF_NUM, "%u", rpt.cca_intf_40[i]);
			snprintf(cca_intf80, INTF_NUM, "%u", rpt.cca_intf_80[i]);
			print_out(print, "%4d %11s %11s %11s\n",
				rpt.chan[i],
				rpt.cca_intf_20[i] == SCS_CCA_INTF_INVALID ? "-" : cca_intf20,
				rpt.cca_intf_40[i] == SCS_CCA_INTF_INVALID ? "-" : cca_intf40,
				rpt.cca_intf_80[i] == SCS_CCA_INTF_INVALID ? "-" : cca_intf80);
		}
	} else {
		print_err(print, "Invalid parameter:%s\nOptional choice:current all autochan score\n", argv[0]);
		return 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scs_cca_intf_smth_fctr(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{

	int statval = 0;
	int qcsapi_retval = 0;
	int fctr_noxp = 0;
	int fctr_xped = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err(print,
			"Not enough parameters in call_qcsapi set_scs_cca_intf_smth_fctr, count is %d\n",
			argc);
		print_err(print,
			"Usage: call_qcsapi set_scs_cca_intf_smth_fctr <Wifi interface> "
			"<factor for never used channel> <factor for used channel>\n" );
		statval = 1;
	} else {
		if (local_str_to_int32(argv[0], &fctr_noxp, print, "smoothing factor") < 0)
			return 1;

		if (local_str_to_int32(argv[1], &fctr_xped, print, "smoothing factor") < 0)
                        return 1;

		qcsapi_retval = qcsapi_wifi_set_scs_cca_intf_smth_fctr(the_interface,
						fctr_noxp, fctr_xped);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scs_stats(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint8_t start = 1;

	if (argc > 0) {
		if (local_verify_enable_or_disable(argv[0], &start, print) < 0)
			return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_scs_stats(the_interface, start);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scs_burst_enable(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t enable_flag = 0;

	if (safe_atou16(argv[0], &enable_flag, print,
		IEEE80211_SCS_BURST_ENABLE_MIN, IEEE80211_SCS_BURST_ENABLE_MAX) == 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_scs_burst_enable(the_interface, enable_flag);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scs_burst_window(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t window = 0;

	if (safe_atou16(argv[0], &window, print,
			IEEE80211_SCS_BURST_WINDOW_MIN, IEEE80211_SCS_BURST_WINDOW_MAX) == 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_scs_burst_window(the_interface, window);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scs_burst_thresh(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t threshold = 0;

	if (safe_atou16(argv[0], &threshold, print,
			IEEE80211_SCS_BURST_THRESH_MIN, IEEE80211_SCS_BURST_THRESH_MAX) == 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_scs_burst_thresh(the_interface, threshold);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scs_burst_pause(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t pause_time = 0;

	if (safe_atou16(argv[0], &pause_time, print,
			IEEE80211_SCS_BURST_PAUSE_MIN, IEEE80211_SCS_BURST_PAUSE_MAX) == 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_scs_burst_pause(the_interface, pause_time);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scs_burst_switch(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t switch_flag = 0;

	if (safe_atou16(argv[0], &switch_flag, print,
		IEEE80211_SCS_BURST_SWITCH_MIN, IEEE80211_SCS_BURST_SWITCH_MAX) == 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_scs_burst_switch(the_interface, switch_flag);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scs_chan_weight(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint32_t temp_chan;
	uint8_t chan = 0;
	int32_t temp_weight;
	int8_t weight = 0;

	if (argc < 2) {
		print_err(print,
			"Not enough parameters in call_qcsapi set_scs_chan_weight, count is %d\n",
			argc);
		print_err(print,
			"Usage: call_qcsapi set_scs_chan_weight <Wifi interface> <Channel> <Weight>\n");
		return 1;
	}

	if (local_atou32_verify_numeric_range(argv[0], &temp_chan, print, 0, IEEE80211_CHAN_MAX) < 0)
		return 1;

	if (local_atoi32_verify_numeric_range(argv[1], &temp_weight, print,
				IEEE80211_CHAN_WEIGHT_MIN, IEEE80211_CHAN_WEIGHT_MAX) < 0) {
		return 1;
	}
	chan = temp_chan;
	weight = temp_weight;

	qcsapi_retval = qcsapi_wifi_set_scs_chan_weight(the_interface, chan, weight);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_scs_chan_weights(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	struct qcsapi_chan_weights chan_weights;
	int i;

	qcsapi_retval = qcsapi_wifi_get_scs_chan_weights(the_interface, &chan_weights);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "channel scs_weight\n");
			for (i = 0; i < chan_weights.num; i++) {
				print_out(print, "%4u %12d\n",
						chan_weights.chan[i], chan_weights.weight[i]);
			}
			print_out(print, "Total %d scs channels\n", i);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_autochan_weight(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint32_t temp_chan;
	uint8_t chan = 0;
	int32_t temp_weight;
	int8_t weight = 0;

	if (argc < 2) {
		print_err(print,
			"Not enough parameters, count is %d\n",
			argc);
		print_err(print,
			"Usage: call_qcsapi set_autochan_params <Wifi interface> <chan_weight> <Channel> <Weight>\n");
		return 1;
	}

	if (local_atou32_verify_numeric_range(argv[0], &temp_chan, print, 0, IEEE80211_CHAN_MAX) < 0)
		return 1;

	if (local_atoi32_verify_numeric_range(argv[1], &temp_weight, print,
				IEEE80211_CHAN_WEIGHT_MIN, IEEE80211_CHAN_WEIGHT_MAX) < 0) {
		return 1;
	}

	chan = temp_chan;
	weight = temp_weight;
	qcsapi_retval = qcsapi_wifi_set_autochan_weight(the_interface, chan, weight);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_autochan_weights(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	struct qcsapi_chan_weights chan_weights;
	int i;

	qcsapi_retval = qcsapi_wifi_get_autochan_weights(the_interface, &chan_weights);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "channel     ics_weight\n");
			for (i = 0; i < chan_weights.num; i++) {
				print_out(print, "%4u %10d\n",
						chan_weights.chan[i], chan_weights.weight[i]);
			}
			print_out(print, "Total %d channels\n", i);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_vendor_fix(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	int		qcsapi_retval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	int		fix_param = -1;
	int		param_value = -1;
	int		i;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err(print, "Usage: call_qcsapi set_vendor_fix <WiFi interface> "
				"<fix-param> <value>\n");
		return 1;
	}

	if (name_to_vendor_fix_idx(argv[0], &fix_param) == 0) {
		print_err(print, "Unrecognized vendor fix param %s\n", argv[0]);
		if (verbose_flag >= 0) {
			print_out( print, "Supported vendor fix param:\n" );
			for (i = 0; i < ARRAY_SIZE(qcsapi_vendor_fix_table); i++)
				print_out( print, "%s\n",
						qcsapi_vendor_fix_table[i].fix_name);
		}
		return 1;
	}

	if (local_str_to_int32(argv[1], &param_value, print, "flag") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_vendor_fix(the_interface,
						  fix_param,
						  param_value);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scs_chan_mtrc_mrgn(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	unsigned int value = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (local_str_to_uint32(argv[0], &value, print, "channel metric margin value") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_scs_chan_mtrc_mrgn(the_interface, value);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scs_inband_chan_mtrc_mrgn(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	unsigned int value = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (local_str_to_uint32(argv[0], &value, print, "channel metric margin value") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_scs_inband_chan_mtrc_mrgn(the_interface, value);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scs_nac_monitor_mode(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	uint32_t enable;
	uint32_t on_period = MONITOR_DEFAULT_ON_PERIOD * 100 / MONITOR_DEFAULT_CYCLE_PERIOD;
	uint32_t cycle_period = MONITOR_DEFAULT_CYCLE_PERIOD;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint8_t is_abs = 0;

	if (argc != 4 && argc != 3 && argc != 1) {
		qcsapi_report_usage(p_calling_bundle,
				"<WiFi interface> {1 | 0} [<on period> [abs] <cycle period>]");
		return 1;
	}

	if (local_atou32_verify_numeric_range(argv[0], &enable, print, 0, 1) < 0)
		return 1;

	if (argc == 3) {
		if (local_atou32_verify_numeric_range(argv[1], &on_period, print,
				MONITOR_MIN_ON_PERIOD, MONITOR_MAX_ON_PERIOD) < 0)
			return 1;

		if (local_atou32_verify_numeric_range(argv[2], &cycle_period, print,
				MONITOR_MIN_CYCLE_PERIOD, MONITOR_MAX_CYCLE_PERIOD) < 0)
			return 1;
	} else if (argc == 4) {
		if (local_atou32_verify_numeric_range(argv[3], &cycle_period, print,
				MONITOR_MIN_CYCLE_PERIOD, MONITOR_MAX_CYCLE_PERIOD) < 0)
			return 1;
		if (strcmp(argv[2], "abs") == 0) {
			is_abs = 1;
		} else {
			qcsapi_report_usage(p_calling_bundle,
				"<WiFi interface> {1 | 0} [<on period> [abs] <cycle period>]");
			return 1;
		}

		if (local_atou32_verify_numeric_range(argv[1], &on_period, print,
			1, cycle_period - 1) < 0)
			return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_scs_nac_monitor_mode_abs(the_interface, enable, on_period,
				cycle_period, is_abs);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scs_band_margin_check(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	uint16_t enable;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> {1 | 0}");
		return 1;
	}

	if (safe_atou16(argv[0], &enable, print, 0, 1) == 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_scs_band_margin_check(the_interface, enable);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scs_band_margin(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	uint16_t margin;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <margin>");
		return 1;
	}

	if (safe_atou16(argv[0], &margin, print, 0, IEEE80211_SCS_OUT_OF_BAND_MTRC_MRGN_MAX) == 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_scs_band_margin(the_interface, margin);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_scs_obss_check_enable(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t enable = 1;

	if (0 == safe_atou16(argv[0], &enable, print, 0, 1))
		return 1;

	qcsapi_retval = qcsapi_wifi_scs_obss_check_enable(the_interface, enable);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out( print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_scs_pmbl_smth_enable(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t enable = 1;
	uint16_t winsize = IEEE80211_SCS_PMBL_ERR_SMTH_WINSIZE_DFT;

	if (0 == safe_atou16(argv[0], &enable, print, 0, 1))
		return 1;

	if (argc == 2 && 0 == safe_atou16(argv[1], &winsize, print,
					IEEE80211_SCS_PMBL_ERR_SMTH_WINSIZE_MIN,
					IEEE80211_SCS_PMBL_ERR_SMTH_WINSIZE_MAX))
		return 1;

	qcsapi_retval = qcsapi_wifi_scs_pmbl_smth_enable(the_interface, enable, winsize);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out( print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_scs_dfs_reentry_request(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	qcsapi_unsigned_int status = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_scs_dfs_reentry_request(the_interface, &status);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%d\n", status);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_scs_cca_intf( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi to get scs cca interference\n" );
		print_err( print, "Usage: call_qcsapi get_scs_cca_intf <interface> <channel>\n" );
		statval = 1;
	}
	else {
		int			qcsapi_retval;
		const char		*the_interface = p_calling_bundle->caller_interface;
		qcsapi_unsigned_int	the_channel;
		int			cca_intf = 0;

		if (local_str_to_uint32(argv[0], &the_channel, print, "channel number") < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_get_scs_cca_intf( the_interface, the_channel, &cca_intf );
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "%d\n", cca_intf );
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_scs_param(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	int len = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_scs_param_rpt *p_rpt;

	len = sizeof(*p_rpt)*SCS_PARAM_MAX;
	p_rpt = (qcsapi_scs_param_rpt *)malloc(len);
	if (p_rpt == NULL) {
		print_err(print, "malloc failed - %s\n", __func__);
		return 1;
	}

	memset(p_rpt, 0, len);
	qcsapi_retval = qcsapi_wifi_get_scs_param_report(the_interface, p_rpt, SCS_PARAM_MAX);
	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	} else {
		dump_scs_param(print, p_rpt);
	}

	free(p_rpt);
	p_rpt = NULL;
	return statval;
}

static int
call_qcsapi_wifi_start_ocac(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t channel_value = 0;

	if (argc < 1) {
		print_out(print, "Usage:\n"
				"  call_qcsapi start_ocac wifi0 { auto | <DFS channel> }\n");
		return 1;
	}

	/* parameter parse */
	if (!strcasecmp("auto", argv[0])) {
		channel_value = 0;
	} else {
		if (safe_atou16(argv[0], &channel_value, print, 0, 0xFFFF) == 0) {
			return 1;
		}
	}

	qcsapi_retval = qcsapi_wifi_start_ocac(the_interface, channel_value);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_stop_ocac(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_stop_ocac(the_interface);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_ocac_status(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	qcsapi_unsigned_int status = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_ocac_status(the_interface, &status);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			if (status == 1)
				print_out( print, "Enabled\n");
			else if (status == 0)
				print_out( print, "Disabled\n");
			else
				print_out( print, "Unknown (%u)\n", status);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_ocac_dwell_time(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t dwell_time = 0;

	if (argc < 1) {
		print_out(print, "Usage:\n"
				"  call_qcsapi set_ocac_dwell_time wifi0 <msecs>\n");
		return 1;
	}

	if (safe_atou16(argv[0], &dwell_time, print, 0, 0xFFFF) == 0) {
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_ocac_dwell_time(the_interface, dwell_time);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_ocac_duration(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t duration = 0;

	if (argc < 1) {
		print_out(print, "Usage:\n"
				"  call_qcsapi set_ocac_duration wifi0 <seconds>\n");
		return 1;
	}

	if (safe_atou16(argv[0], &duration, print, 0, 0xFFFF) == 0) {
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_ocac_duration(the_interface, duration);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_ocac_cac_time(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t cac_time = 0;

	if (argc < 1) {
		print_out(print, "Usage:\n"
				"  call_qcsapi set_ocac_cac_time wifi0 <seconds>\n");
		return 1;
	}

	if (safe_atou16(argv[0], &cac_time, print, 0, 0xFFFF) == 0) {
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_ocac_cac_time(the_interface, cac_time);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_ocac_report_only(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t value = 0;

	if (argc < 1) {
		print_out(print, "Usage:\n"
				"  call_qcsapi set_ocac_report_only wifi0 { 1 | 0 }\n");
		return 1;
	}

	if (safe_atou16(argv[0], &value, print, 0, 0xFFFF) == 0) {
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_ocac_report_only(the_interface, value);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_ocac_threshold(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err( print,
			"Usage: call_qcsapi set_ocac_thrshld <WiFi interface> <threshold parameter> <threshold value>\n");
		statval = 1;
	} else {
		int qcsapi_retval = 0;
		const char *the_interface = p_calling_bundle->caller_interface;
		char *thrshld_param_name = argv[0];
		uint16_t thrshld_value;

		if (safe_atou16(argv[1], &thrshld_value, print,	0, 0xFFFF) == 0) {
			return 1;
		}

		qcsapi_retval = qcsapi_wifi_set_ocac_thrshld(the_interface, thrshld_param_name, thrshld_value);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wifi_xcac_set(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	struct qcsapi_xcac_op_req cac_req;
	qcsapi_unsigned_int status = 0;

	if (argc < 1)
		goto print_usage;

	memset(&cac_req, 0, sizeof(cac_req));

	if (strcasecmp(argv[0], "start") == 0)
		cac_req.command = QCSAPI_XCAC_CMD_START;
	else if (strcasecmp(argv[0], "stop") == 0)
		cac_req.command = QCSAPI_XCAC_CMD_STOP;
	else
		goto print_usage;

	if (cac_req.command == QCSAPI_XCAC_CMD_START) {
		if (argc != 5)
			goto print_usage;

		if (safe_atou16(argv[1], &cac_req.channel, print, QCSAPI_MIN_CHANNEL_5G,
				QCSAPI_MAX_CHANNEL) == 0)
			goto print_usage;

		if (safe_atou16(argv[2], &cac_req.bw, print, qcsapi_bw_20MHz,
				qcsapi_bw_160MHz) == 0)
			goto print_usage;

		if (safe_atou16(argv[3], &cac_req.method, print, QCSAPI_XCAC_METHOD_MIN,
				QCSAPI_XCAC_METHOD_MAX) == 0)
			goto print_usage;

		if (safe_atou16(argv[4], &cac_req.action, print, QCSAPI_XCAC_ACTION_MIN,
				QCSAPI_XCAC_ACTION_MAX) == 0)
			goto print_usage;
	}

	qcsapi_retval = qcsapi_wifi_xcac_set(the_interface, &cac_req, &status);
	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	} else {
		print_out(print, "Status: 0x%x\n", status);
		return 0;
	}

print_usage:
	qcsapi_report_usage(p_calling_bundle,
		"<WiFi interface> {start <channel> <bandwidth> <method> <action> | stop}\n");
	return 1;
}

static int
call_qcsapi_wifi_xcac_get(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	struct qcsapi_xcac_op_req cac_req;
	struct qcsapi_xcac_get_result cac_result;

	if (argc != 1)
		goto print_usage;

	memset(&cac_req, 0, sizeof(cac_req));
	memset(&cac_result, 0, sizeof(cac_result));

	if (strcasecmp(argv[0], "status") != 0)
		goto print_usage;
	cac_req.command = QCSAPI_XCAC_CMD_GET_STATUS;

	qcsapi_retval = qcsapi_wifi_xcac_get(the_interface, &cac_req, &cac_result);
	if (qcsapi_retval >= 0) {
		print_out(print, "status %d, channel %d, bw %d, channel status 0x%x\n",
				cac_result.status, cac_result.channel,
				cac_result.bw, cac_result.chan_status);
		statval = qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;

print_usage:
	qcsapi_report_usage(p_calling_bundle, "<WiFi interface> status\n");
	return 1;
}

static void call_qcsapi_wifi_start_dfs_s_radio_help(call_qcsapi_bundle *p_calling_bundle)
{
	qcsapi_report_usage(p_calling_bundle, "<Wifi interface> { auto | <test_DFS_channel> } | { auto <first_DFS_channel>}\n"
			"  1. Where auto indicates Quantenna Stack selects the best"
			"  DFS channel for which SDFS will be initiated\n"
			"  2. Where test_DFS_channel is a mandatory arguement for which SDFS will be initiated\n"
			"  3. Where \"auto <first_DFS_channel>\" indicates SDFS Auto DFS feature where\n"
			"  Quantenna Stack tries to initiate SDFS on <first_DFS_channel>\n"
			"  and later falls back to auto mode where change to a non_DFS_channel\n"
			"  always restarts SDFS\n");
}

static int
call_qcsapi_wifi_start_dfs_s_radio(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t channel_value = 0;
	uint16_t sdfs_auto_param = 0;
	int16_t channel_idx = -1;

	if ((argc < 1) || (argc > 2)) {
		statval = 1;
		goto usage;
	}

	if (!strcasecmp("auto", argv[0])) {
		sdfs_auto_param = 1;
	}

	channel_idx = (sdfs_auto_param && (argc == 2)) ? 1 : (((!sdfs_auto_param) && (argc == 1)) ? 0 : -1);

	if ((channel_idx >= 0) && (safe_atou16(argv[channel_idx], &channel_value, print, QCSAPI_ANY_CHANNEL, QCSAPI_MAX_CHANNEL) == 0)) {
		if (sdfs_auto_param == 0) {
			/** call_qcsapi start_dfs_s_radio wifi0 Junk */
			statval = 1;
			goto usage;
		} else if (argc == 2) {
			/** call_qcsapi start_dfs_s_radio wifi0 auto Junk */
			statval = 1;
			goto usage;
		}
		/** call_qcsapi start_dfs_s_radio wifi0 auto */
	}

	/** call_qcsapi start_dfs_s_radio <DFS channel> */
	if (argc == 2) {
		if (sdfs_auto_param) {
			/**  call_qcsapi start_dfs_s_radio auto <DFS channel> */
			channel_value |= IEEE80211_OCAC_AUTO_WITH_FIRST_DFS_CHAN;
		} else {
			/**  call_qcsapi start_dfs_s_radio Junk <DFS channel> */
			statval = 1;
			goto usage;
		}
	}

	qcsapi_retval = qcsapi_wifi_start_dfs_s_radio(the_interface, channel_value);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
		return 0;
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

usage:	call_qcsapi_wifi_start_dfs_s_radio_help(p_calling_bundle);
	return( statval );
}

static int
call_qcsapi_wifi_stop_dfs_s_radio(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_stop_dfs_s_radio(the_interface);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_dfs_s_radio_status(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	qcsapi_unsigned_int status = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_dfs_s_radio_status(the_interface, &status);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			if (status == 1)
				print_out( print, "Enabled\n");
			else if (status == 0)
				print_out( print, "Disabled\n");
			else
				print_out( print, "Unknown (%u)\n", status);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_dfs_s_radio_availability(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	int		qcsapi_retval;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	available = 0;

	qcsapi_retval = qcsapi_wifi_get_dfs_s_radio_availability(the_interface, &available);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			if (available == 1)
				print_out( print, "Available\n");
			else
				print_out( print, "Unavailable\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_dfs_s_radio_dwell_time(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t dwell_time = 0;

	if (argc < 1) {
		print_out(print, "Usage:\n"
				"  call_qcsapi set_dfs_s_radio_dwell_time wifi0 <msecs>\n");
		return 1;
	}

	if (safe_atou16(argv[0], &dwell_time, print, 0, 0xFFFF) == 0) {
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_dfs_s_radio_dwell_time(the_interface, dwell_time);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_dfs_s_radio_duration(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t duration = 0;

	if (argc < 1) {
		print_out(print, "Usage:\n"
				"  call_qcsapi set_dfs_s_radio_duration wifi0 <seconds>\n");
		return 1;
	}

	if (safe_atou16(argv[0], &duration, print, 0, 0xFFFF) == 0) {
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_dfs_s_radio_duration(the_interface, duration);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_dfs_s_radio_cac_time(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t cac_time = 0;

	if (argc < 1) {
		print_out(print, "Usage:\n"
				"  call_qcsapi set_dfs_s_radio_cac_time wifi0 <seconds>\n");
		return 1;
	}

	if (safe_atou16(argv[0], &cac_time, print, 0, 0xFFFF) == 0) {
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_dfs_s_radio_cac_time(the_interface, cac_time);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_dfs_s_radio_report_only(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t value = 0;

	if (argc < 1) {
		print_out(print, "Usage:\n"
				"  call_qcsapi set_dfs_s_radio_report_only wifi0 { 1 | 0 }\n");
		return 1;
	}

	if (safe_atou16(argv[0], &value, print, 0, 0xFFFF) == 0) {
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_dfs_s_radio_report_only(the_interface, value);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_dfs_s_radio_wea_duration(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint32_t duration = 0;

	if (argc < 1) {
		print_out(print, "Usage:\n"
				"  call_qcsapi set_dfs_s_radio_wea_duration wifi0 <seconds>\n");
		return 1;
	}

	if (local_atou32_verify_numeric_range(argv[0], &duration, print, 0, 0xFFFFFFFF) < 0) {
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_dfs_s_radio_wea_duration(the_interface, duration);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_dfs_s_radio_wea_cac_time(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint32_t cac_time = 0;

	if (argc < 1) {
		print_out(print, "Usage:\n"
				"  call_qcsapi set_dfs_s_radio_wea_cac_time wifi0 <seconds>\n");
		return 1;
	}

	if (local_atou32_verify_numeric_range(argv[0], &cac_time, print, 0, 0xFFFFFFFF) < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_dfs_s_radio_wea_cac_time(the_interface, cac_time);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_set_dfs_s_radio_wea_dwell_time(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t dwell_time = 0;

	if (argc < 1) {
		print_out(print, "Usage:\n"
				"  call_qcsapi set_dfs_s_radio_wea_dwell_time wifi0 <msecs>\n");
		return 1;
	}

	if (safe_atou16(argv[0], &dwell_time, print, 0, 0xFFFF) == 0) {
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_dfs_s_radio_wea_dwell_time(the_interface, dwell_time);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}


static int
call_qcsapi_wifi_set_dfs_s_radio_threshold(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err( print,
			"Usage: call_qcsapi set_dfs_s_radio_thrshld <WiFi interface> <threshold parameter> <threshold value>\n");
		statval = 1;
	} else {
		int qcsapi_retval = 0;
		const char *the_interface = p_calling_bundle->caller_interface;
		char *thrshld_param_name = argv[0];
		uint16_t thrshld_value;

		if (safe_atou16(argv[1], &thrshld_value, print,	0, 0xFFFF) == 0) {
			return 1;
		}

		qcsapi_retval = qcsapi_wifi_set_dfs_s_radio_thrshld(the_interface, thrshld_param_name, thrshld_value);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wifi_set_threshold_of_neighborhood_type(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc != 2) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <type> <threshold>");
		statval = 1;
	} else {
		int qcsapi_retval = 0;
		const char *the_interface = p_calling_bundle->caller_interface;
		uint32_t type;
		uint32_t threshold;

		if (local_atou32_verify_numeric_range(argv[0], &type, print, 0,
				IEEE80211_NEIGHBORHOOD_TYPE_MAX - 1) < 0)
			return 1;

		if (local_atou32_verify_numeric_range(argv[1], &threshold, print, 1, 255) < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_set_threshold_of_neighborhood_type(the_interface, type, threshold);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out(print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wifi_get_threshold_of_neighborhood_type(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <type>");
		statval = 1;
	} else {
		int qcsapi_retval = 0;
		const char *the_interface = p_calling_bundle->caller_interface;
		uint32_t type;
		uint32_t threshold;

		if (local_atou32_verify_numeric_range(argv[0], &type, print, 0,
				IEEE80211_NEIGHBORHOOD_TYPE_MAX - 1) < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_get_threshold_of_neighborhood_type(the_interface, type, &threshold);

		if (qcsapi_retval >= 0) {
			print_out(print, "%u\n", threshold);
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wifi_get_neighborhood_type(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc > 0) {
		print_err(print, "Usage: call_qcsapi get_neighborhood_type <WiFi interface>\n");
		statval = 1;
	} else {
		int qcsapi_retval = 0;
		const char *the_interface = p_calling_bundle->caller_interface;
		uint32_t type = IEEE80211_NEIGHBORHOOD_TYPE_SPARSE;
		uint32_t count = 0;

		qcsapi_retval = qcsapi_wifi_get_neighborhood_type(the_interface, &type, &count);

		if (qcsapi_retval >= 0) {
			if (type == IEEE80211_NEIGHBORHOOD_TYPE_SPARSE)
				print_out(print, "Sparse (%d neighbor APs)\n", count);
			else if (type == IEEE80211_NEIGHBORHOOD_TYPE_DENSE)
				print_out(print, "Dense (%d neighbor APs)\n", count);
			else if (type == IEEE80211_NEIGHBORHOOD_TYPE_VERY_DENSE)
				print_out(print, "Very dense (%d neighbor APs)\n", count);
			else
				print_out(print, "Unknown, may need a new scan\n");
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wifi_set_ap_isolate(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	uint8_t current_ap_isolate_status;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;

	if (argc < 1) {
		print_err( print,
				"Parameter count incorrect. Should be 3, is %d\n", argc
		);
		statval = 1;
	} else {
		if (local_verify_enable_or_disable(argv[0], &current_ap_isolate_status, print) < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_set_ap_isolate(the_interface, current_ap_isolate_status);
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out(print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_ap_isolate(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	int current_ap_isolate_status = (int)qcsapi_ap_isolate_disabled;
	int *p_current_ap_isolate_status = NULL;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1 || strcmp( argv[ 0 ], "NULL" ) != 0) {
		p_current_ap_isolate_status = &current_ap_isolate_status;
	}

	qcsapi_retval = qcsapi_wifi_get_ap_isolate(the_interface, p_current_ap_isolate_status);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%d\n", current_ap_isolate_status);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_get_interface_stats(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_interface_stats	stats;

	qcsapi_retval = qcsapi_get_interface_stats( the_interface, &stats );
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			if (sizeof(long) == 8) {
				print_out(print,	"tx_bytes:\t%llu\n"
						"tx_pkts:\t%u\n"
						"tx_wifi_sent_be:\t%u\n"
						"tx_wifi_sent_bk:\t%u\n"
						"tx_wifi_sent_vi:\t%u\n"
						"tx_wifi_sent_vo:\t%u\n"
						"tx_discard:\t%u\n"
						"tx_wifi_drop_be:\t%u\n"
						"tx_wifi_drop_bk:\t%u\n"
						"tx_wifi_drop_vi:\t%u\n"
						"tx_wifi_drop_vo:\t%u\n"
						"tx_err:\t\t%u\n"
						"tx_unicast:\t%u\n"
						"tx_multicast:\t%u\n"
						"tx_broadcast:\t%u\n"
						"rx_bytes:\t%llu\n"
						"rx_pkts:\t%u\n"
						"rx_discard:\t%u\n"
						"rx_err:\t\t%u\n"
						"rx_unicast:\t%u\n"
						"rx_multicast:\t%u\n"
						"rx_broadcast:\t%u\n"
						"rx_unknown:\t%u\n",
						stats.tx_bytes,
						stats.tx_pkts,
						stats.tx_wifi_sent[WMM_AC_BE],
						stats.tx_wifi_sent[WMM_AC_BK],
						stats.tx_wifi_sent[WMM_AC_VI],
						stats.tx_wifi_sent[WMM_AC_VO],
						stats.tx_discard,
						stats.tx_wifi_drop[WMM_AC_BE],
						stats.tx_wifi_drop[WMM_AC_BK],
						stats.tx_wifi_drop[WMM_AC_VI],
						stats.tx_wifi_drop[WMM_AC_VO],
						stats.tx_err,
						stats.tx_unicast,
						stats.tx_multicast,
						stats.tx_broadcast,
						stats.rx_bytes,
						stats.rx_pkts,
						stats.rx_discard,
						stats.rx_err,
						stats.rx_unicast,
						stats.rx_multicast,
						stats.rx_broadcast,
						stats.rx_unknown);
			} else {
				print_out(print,	"tx_bytes:\t%llu\n"
						"tx_pkts:\t%lu\n"
						"tx_wifi_sent_be:\t%u\n"
						"tx_wifi_sent_bk:\t%u\n"
						"tx_wifi_sent_vi:\t%u\n"
						"tx_wifi_sent_vo:\t%u\n"
						"tx_discard:\t%lu\n"
						"tx_wifi_drop_be:\t%u\n"
						"tx_wifi_drop_bk:\t%u\n"
						"tx_wifi_drop_vi:\t%u\n"
						"tx_wifi_drop_vo:\t%u\n"
						"tx_err:\t\t%lu\n"
						"tx_unicast:\t%lu\n"
						"tx_multicast:\t%lu\n"
						"tx_broadcast:\t%lu\n"
						"rx_bytes:\t%llu\n"
						"rx_pkts:\t%lu\n"
						"rx_discard:\t%lu\n"
						"rx_err:\t\t%lu\n"
						"rx_unicast:\t%lu\n"
						"rx_multicast:\t%lu\n"
						"rx_broadcast:\t%lu\n"
						"rx_unknown:\t%lu\n",
						stats.tx_bytes,
						stats.tx_pkts,
						stats.tx_wifi_sent[WMM_AC_BE],
						stats.tx_wifi_sent[WMM_AC_BK],
						stats.tx_wifi_sent[WMM_AC_VI],
						stats.tx_wifi_sent[WMM_AC_VO],
						stats.tx_discard,
						stats.tx_wifi_drop[WMM_AC_BE],
						stats.tx_wifi_drop[WMM_AC_BK],
						stats.tx_wifi_drop[WMM_AC_VI],
						stats.tx_wifi_drop[WMM_AC_VO],
						stats.tx_err,
						stats.tx_unicast,
						stats.tx_multicast,
						stats.tx_broadcast,
						stats.rx_bytes,
						stats.rx_pkts,
						stats.rx_discard,
						stats.rx_err,
						stats.rx_unicast,
						stats.rx_multicast,
						stats.rx_broadcast,
						stats.rx_unknown);

			}
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
local_if_infoset_print(call_qcsapi_bundle *p_calling_bundle, const uint16_t set_id,
				struct qtnis_if_set *infoset)
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	int i;

	COMPILE_TIME_ASSERT(ARRAY_SIZE(qtnis_if_label) < ARRAY_SIZE(infoset->val));

	for (i = 0; i < ARRAY_SIZE(infoset->val); i++) {
		if (QTNIS_IS_SET(infoset, i)) {
			print_out(print, "%-*s: %llu\n",
				QTNIS_IF_LABEL_LEN, qtnis_if_label[set_id][i], infoset->val[i]);
		}
	}

	return 0;
}

static int
call_qcsapi_wifi_get_if_infoset(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	struct qtnis_if_set infoset;
	const char *usage = "<WiFi interface> <set id>";
	uint16_t set_id;

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return 1;
	}
	if (!strcmp(argv[0], "scan_cap")) {
		set_id = QTNIS_SET_ID_SCAN_CAP;
	} else if (!strcmp(argv[0], "cac_cap")) {
		set_id = QTNIS_SET_ID_CAC_CAP;
	} else if (safe_atou16(argv[0], &set_id, print, 0, QTNIS_SET_ID_MAX - 1) <= 0) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return 1;
	}

	retval = qcsapi_wifi_get_if_infoset(the_interface, set_id, &infoset);
	if (retval < 0) {
		report_qcsapi_error(p_calling_bundle, retval);
		return 1;
	}

	local_if_infoset_print(p_calling_bundle, set_id, &infoset);

	return retval;
}

static int
call_qcsapi_get_phy_stats(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	iter;
	int			 qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_phy_stats	stats;

	qcsapi_retval = qcsapi_get_phy_stats( the_interface, &stats );
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "tstamp=\t\t%u\n"
					 "assoc=\t\t%u\n"
					 "channel=\t%u\n"
					 "attenuation=\t%u\n"
					 "cca_total=\t%u\n"
					 "cca_tx=\t\t%u\n"
					 "cca_rx=\t\t%u\n"
					 "cca_int=\t%u\n"
					 "cca_idle\t%u\n"
					 "rx_pkts=\t%u\n"
					 "last_rx_pkt_timestamp=\t%u\n"
					 "rx_gain=\t%u\n"
					 "rx_cnt_crc=\t%u\n"
					 "rx_noise=\t%5.1f\n"
					 "tx_pkts=\t%u\n"
					 "last_tx_pkt_timestamp=\t%u\n"
					 "tx_defers=\t%d\n"
					 "tx_touts=\t%u\n"
					 "tx_retries=\t%u\n"
					 "cnt_sp_fail=\t%u\n"
					 "cnt_lp_fail=\t%u\n"
					 "last_rx_mcs=\t%d\n"
					 "last_tx_mcs=\t%d\n",
				  stats.tstamp,
				  stats.assoc,
				  stats.channel,
				  stats.atten,
				  stats.cca_total,
				  stats.cca_tx,
				  stats.cca_rx,
				  stats.cca_int,
				  stats.cca_idle,
				  stats.rx_pkts,
				  stats.last_rx_pkt_timestamp,
				  stats.rx_gain,
				  stats.rx_cnt_crc,
				  stats.rx_noise,
				  stats.tx_pkts,
				  stats.last_tx_pkt_timestamp,
				  stats.tx_defers,
				  stats.tx_touts,
				  stats.tx_retries,
				  stats.cnt_sp_fail,
				  stats.cnt_lp_fail,
				  stats.last_rx_mcs,
				  stats.last_tx_mcs);
			print_out(print, "last_evm=\t%5.1f\n", stats.last_evm);
			for (iter = 0; iter < QCSAPI_QDRV_NUM_RF_STREAMS; iter++) {
				print_out(print, "last_evm_%d=\t%5.1f\n", iter, stats.last_evm_array[iter]);
			}

			print_out(print, "last_rcpi=\t%5.1f\n", stats.last_rcpi);

			print_out(print, "last_rssi=\t%5.1f\n", stats.last_rssi);
			for (iter = 0; iter < QCSAPI_QDRV_NUM_RF_STREAMS; iter++) {
				print_out(print, "last_rssi_%d=\t%5.1f\n", iter, stats.last_rssi_array[iter]);
			}
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_telnet_enable(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint8_t on_off;

	if (argc < 1) {
		print_err( print, "Usage: call_qcsapi enable_telnet <value>\n");
		print_err( print, "Usage: value: 0 - disable; 1 - enable\n");
		statval = 1;
	} else {
		int		qcsapi_retval = 0;

		if (local_verify_enable_or_disable(argv[0], &on_off, print) < 0)
			return 1;

		qcsapi_retval = qcsapi_telnet_enable(on_off);

		if (qcsapi_retval == 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wps_set_access_control(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		qcsapi_retval = 0;
	uint32_t	pp_enable;
	char		wps_state[32];

	if (argc < 1) {
		print_err( print, "Usage: call_qcsapi set_wps_access_control <value>\n" );
		print_err( print, "Usage: value: 0 - disable; 1 - enable\n" );
		statval = 1;
	} else {
		char	*parameter_value = argv[0];

		if (!strcmp(parameter_value, "1")) {
			pp_enable = 1;
		} else if (!strcmp(parameter_value, "0")) {
			pp_enable = 0;
		} else {
			print_err( print, "Usage: call_qcsapi set_wps_access_control <value>\n" );
			print_err( print, "Usage: value: 0 - disable; 1 - enable\n" );
			return 1;
		}

		qcsapi_retval = qcsapi_wps_get_configured_state(the_interface, wps_state, sizeof(wps_state));
		if (qcsapi_retval >= 0) {
			if (strncmp(wps_state, "configured", sizeof(wps_state)) != 0) {
				print_err(print, "enable WPS feature before setup WPS Access control\n");
				return 1;
			}
		}

		if (qcsapi_retval >= 0)
			qcsapi_retval = qcsapi_wps_set_access_control( the_interface, pp_enable );
	}

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n" );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wps_get_access_control(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		qcsapi_retval = 0;
	uint32_t	pp_enable;

	if (argc > 0) {
		print_err( print, "Usage: call_qcsapi get_wps_access\n" );
		print_err( print, "Usage: This command is used to get pair protection state \n" );
		statval = 1;
	} else {
		qcsapi_retval = qcsapi_wps_get_access_control( the_interface, &pp_enable );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "%s\n", (pp_enable ? "1":"0") );
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_non_wps_set_pp_enable(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		qcsapi_retval = 0;
	uint32_t	pp_enable;

	if (argc < 1) {
		print_err( print, "Usage: call_qcsapi set_non_wps_pp_enable <value>\n" );
		print_err( print, "Usage: value: 0 - disable; 1 - enable\n" );
		statval = 1;
	} else {
		char	*parameter_value = argv[0];

		if (!strcmp(parameter_value, "1")) {
			pp_enable = 1;
		} else if (!strcmp(parameter_value, "0")) {
			pp_enable = 0;
		} else {
			print_err( print, "Usage: call_qcsapi set_non_wps_pp_enable <value>\n" );
			print_err( print, "Usage: value: 0 - disable; 1 - enable\n" );
			return 1;
		}

		qcsapi_retval = qcsapi_non_wps_set_pp_enable( the_interface, pp_enable );
	}

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n" );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_non_wps_get_pp_enable(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		qcsapi_retval = 0;
	uint32_t	pp_enable;

	if (argc > 0) {
		print_err( print, "Usage: call_qcsapi get_non_wps_pp_enable\n" );
		print_err( print, "Usage: This command is used to get non_wps pair protection state \n" );
		statval = 1;
	} else {
		qcsapi_retval = qcsapi_non_wps_get_pp_enable( the_interface, &pp_enable );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "%s\n", (pp_enable ? "1":"0") );
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wps_cancel(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		qcsapi_retval = 0;

	if (argc > 0) {
		print_err( print, "Usage: call_qcsapi wps_cancel <WiFi interface>\n" );
		statval = 1;
	} else {
		qcsapi_retval = qcsapi_wps_cancel(the_interface);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wps_set_pbc_in_srcm(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int qcsapi_retval = 0;
	uint16_t enabled = 0;

	if (argv[0] != NULL && safe_atou16(argv[0], &enabled, print, 0, 1))
		qcsapi_retval = qcsapi_wps_set_pbc_in_srcm(the_interface, enabled);
	else
		return 1;

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wps_get_pbc_in_srcm(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int qcsapi_retval = 0;
	qcsapi_unsigned_int enabled = 0;

	qcsapi_retval = qcsapi_wps_get_pbc_in_srcm(the_interface, &enabled);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%d\n", enabled);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int call_qcsapi_wps_set_timeout(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		qcsapi_retval = 0;
	int		timeout_val = 0;

	if (argc < 0) {
		print_out(print, "Usage: call_qcsapi wps_timeout <WiFi Interface> <timeout value>\n");
		statval = 1;
	} else {
		if (local_atoi32_verify_numeric_range(argv[0], &timeout_val, print, 120, 600) < 0)
			return 1;

		qcsapi_retval = qcsapi_wps_set_timeout(the_interface, timeout_val);
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int call_qcsapi_wps_on_hidden_ssid(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		qcsapi_retval = 0;
	uint8_t		option;

	if (argc < 0) {
		print_out(print, "Usage: call_qcsapi wps_on_hidden_ssid <WiFi Interface> <0 | 1>\n");
		statval = 1;
	} else {
		if (local_verify_enable_or_disable(argv[0], &option, print) < 0)
			return 1;

		qcsapi_retval = qcsapi_wps_on_hidden_ssid(the_interface, option);
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int call_qcsapi_wps_on_hidden_ssid_status(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		qcsapi_retval = 0;
	char		state[64];

	if (argc > 0) {
		print_out(print, "Usage: call_qcsapi wps_on_hidden_ssid_status <WiFi Interface>\n");
		statval = 1;
	} else {
		qcsapi_retval = qcsapi_wps_on_hidden_ssid_status(the_interface, state, sizeof(state));

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "%s\n", state);
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int call_qcsapi_wps_upnp_enable(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		qcsapi_retval = 0;
	uint8_t		option = -1;

	if (argc < 0) {
		print_out(print, "Usage: call_qcsapi wps_upnp_enable <WiFi Interface> <0 | 1>\n");
		statval = 1;
	} else {
		if (local_verify_enable_or_disable(argv[0], &option, print) < 0)
			return 1;

		qcsapi_retval = qcsapi_wps_upnp_enable(the_interface, option);
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int call_qcsapi_wps_upnp_status(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		qcsapi_retval = 0;
	char		reply_buffer[16];

	if (argc > 0) {
		print_out(print, "Usage: call_qcsapi wps_upnp_status <WiFi Interface>\n");
		statval = 1;
	} else {
		memset(reply_buffer, 0, sizeof(reply_buffer));
		qcsapi_retval = qcsapi_wps_upnp_status(the_interface, reply_buffer, sizeof(reply_buffer));

		if (qcsapi_retval >= 0) {
			print_out(print, "%s\n", reply_buffer);
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int  call_qcsapi_wps_registrar_set_dfl_pbc_bss(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		qcsapi_retval = 0;

	if (argc > 0) {
		print_out(print, "Usage: call_qcsapi registrar_set_default_pbc_bss <WiFi Interface>\n");
		statval = 1;
	} else {
		qcsapi_retval = qcsapi_registrar_set_default_pbc_bss(the_interface);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int  call_qcsapi_wps_registrar_get_dfl_pbc_bss(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		qcsapi_retval = 0;
	char		reply_buffer[16];

	if (argc > 0) {
		print_out(print, "Usage: call_qcsapi registrar_get_default_pbc_bss\n");
		statval = 1;
	} else {
		memset(reply_buffer, 0, sizeof(reply_buffer));
		qcsapi_retval = qcsapi_registrar_get_default_pbc_bss(reply_buffer, sizeof(reply_buffer));

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out(print, "%s\n", reply_buffer);
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int  call_qcsapi_wps_set_dfl_pbc_bss(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		qcsapi_retval = 0;

	if (argc > 0) {
		print_out(print, "Usage: call_qcsapi wps_set_default_pbc_bss <WiFi Interface>\n");
		statval = 1;
	} else {
		qcsapi_retval = qcsapi_wps_set_default_pbc_bss(the_interface);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out(print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int call_qcsapi_wps_get_dfl_pbc_bss(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		qcsapi_retval = 0;
	char		reply_buffer[QCSAPI_CUSTOM_VALUE_MAX_LEN];

	if (argc > 0) {
		print_out(print, "Usage: call_qcsapi wps_get_default_pbc_bss\n");
		statval = 1;
	} else {
		memset(reply_buffer, 0, sizeof(reply_buffer));
		qcsapi_retval = qcsapi_wps_get_default_pbc_bss(reply_buffer,
				sizeof(reply_buffer));

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out(print, "%s\n", reply_buffer);
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_reset_all_counters(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int node_index = p_calling_bundle->caller_generic_parameter.index;
	int local_remote_flag = QCSAPI_LOCAL_NODE;
	int qcsapi_retval = 0;

	if (argc > 0) {
		if (parse_local_remote_flag(print, argv[0], &local_remote_flag) < 0) {
			return 1;
		}
	}

	qcsapi_retval = qcsapi_reset_all_counters(the_interface, node_index, local_remote_flag);

	if (qcsapi_retval == 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_test_traffic(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	int		qcsapi_retval = 0;
	uint32_t period = 0;

	if (argc < 1 || argc > 2) {
		statval = 1;
	} else {
		if ((argc == 2) && (!strcasecmp("start", argv[0]))) {
			sscanf(argv[1], "%u", &period);
			if (period < 10) {
				statval = 1;
				print_err( print, "<period> MUST >= 10 milliseconds for \"start\"\n");
				goto out;
			}
		} else if ((argc == 1) && (!strcasecmp("stop", argv[0]))) {
			period = 0;
		} else {
			statval = 1;
			goto out;
		}

		qcsapi_retval = qcsapi_wifi_test_traffic( the_interface, period );

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n" );
			}
		} else {
			report_qcsapi_error( p_calling_bundle, qcsapi_retval );
			statval = 1;
		}
	}

out:
	if (statval != 0 && qcsapi_retval >= 0) {
		print_err( print, "Usage: call_qcsapi test_traffic <WiFi interface> <start|stop> <period (unit:ms)>\n" );
		print_err( print, "Usage: This command is used to start or stop the test traffic\n" );
	}
	return statval;
}

static void call_qcsapi_pm_print_mode(qcsapi_output *print, const int level)
{
	switch (level) {
	case QCSAPI_PM_MODE_DISABLE:
		print_out(print, "off\n");
		break;
	case QCSAPI_PM_MODE_SUSPEND:
		print_out(print, "suspend\n");
		break;
	case QCSAPI_PM_MODE_IDLE:
		print_out(print, "idle\n");
		break;
	default:
		print_out(print, "auto\n");
		break;
	}
}

static int call_qcsapi_pm_str_to_level(qcsapi_output *print,
					const char *const level_str, int *level)
{
	if (strcmp(level_str, "off") == 0) {
		*level = QCSAPI_PM_MODE_DISABLE;
	} else if (strcmp(level_str, "on") == 0 || strcmp(level_str, "auto") == 0) {
		*level = QCSAPI_PM_MODE_AUTO;
	} else if (strcmp(level_str, "suspend") == 0) {
		*level = QCSAPI_PM_MODE_SUSPEND;
	} else if (strcmp(level_str, "idle") == 0) {
		*level = QCSAPI_PM_MODE_IDLE;
	} else {
		print_err(print, "%s: invalid parameter '%s'\n", __FUNCTION__, level_str);
		return -EINVAL;
	}

	return 0;
}

static int
call_qcsapi_pm_get_set_mode(call_qcsapi_bundle *call, int argc, char *argv[])
{
	qcsapi_output *print = call->caller_output;
	int level;
	int rc = 0;
	int demac = 0;

	if (argc > 0) {
		if (strcmp("dual_emac", argv[argc - 1]) == 0) {
			demac = 1;
			argc--;
		}
	}

	if (!argc) {
		if (demac) {
			rc = qcsapi_pm_dual_emac_get_mode(&level);
		} else {
			rc = qcsapi_pm_get_mode(&level);
		}
		if (rc >= 0 && verbose_flag >= 0) {
			call_qcsapi_pm_print_mode(print, level);
		}
	} else if (argc == 1) {
		rc = call_qcsapi_pm_str_to_level(print, argv[0], &level);
		if (rc >= 0) {
			if (demac) {
				rc = qcsapi_pm_dual_emac_set_mode(level);
			} else {
				rc = qcsapi_pm_set_mode(level);
			}
		}
	} else {
		rc = -EINVAL;
	}

	if (rc < 0) {
		report_qcsapi_error(call, rc);
	}

	return rc;
}

static int
call_qcsapi_qpm_get_level(call_qcsapi_bundle *call, int argc, char *argv[])
{
        qcsapi_output *print = call->caller_output;
        int qpm_level;
        int rc = 0;

        if (argc == 0) {
                rc = qcsapi_get_qpm_level(&qpm_level);
                if (rc < 0 || verbose_flag < 0) {
                        goto out;
                }
                print_out(print, "%d\n", qpm_level);

        } else {
                rc = -EINVAL;
        }

out:
        if (rc < 0) {
                report_qcsapi_error(call, rc);
        }

        return rc;
}

static int
call_qcsapi_restore_default_config(call_qcsapi_bundle *call, int argc, char *argv[])
{
	int flag = 0;
	char *argp;
	int rc = 0;

	while (argc > 0) {
		argp = argv[argc - 1];
		if (strcmp(argp, "1") == 0 || strcmp(argp, "ip") == 0) {
			flag |= QCSAPI_RESTORE_FG_IP;
		} else if (strcmp(argp, "noreboot") == 0) {
			flag |= QCSAPI_RESTORE_FG_NOREBOOT;
		} else if (strcmp(argp, "wconf_only") == 0) {
			flag |= QCSAPI_RESTORE_FG_WIRELESS_CONF;
		} else if (strcmp(argp, "ap") == 0) {
			flag |= QCSAPI_RESTORE_FG_AP;
		} else if (strcmp(argp, "sta") == 0) {
			flag |= QCSAPI_RESTORE_FG_STA;
		} else if (strcmp(argp, "security_daemon") == 0) {
			flag |= QCSAPI_RESTORE_FG_SEC_DAEMON;
		} else {
			rc = -EINVAL;
			break;
		}
		argc--;
	}

	if (rc == 0)
		rc = qcsapi_restore_default_config(flag);

	if (rc < 0)
		report_qcsapi_error(call, rc);

	return rc;
}

static int g_is_qtm = 0;

typedef int(*call_qcsapi_vsp_fn)(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[]);

struct call_qcsapi_fnmap {
	const char *name;
	call_qcsapi_vsp_fn func;
};

static call_qcsapi_vsp_fn call_qcsapi_fnmap_find(const char *name, const struct call_qcsapi_fnmap *map, size_t map_size)
{
	int i;
	for (i = 0; i < map_size; i++) {

		/* skip whitelist */
		if (g_is_qtm && strcmp(map[i].name, "wl") == 0)
			continue;

		if (strcmp(map[i].name, name) == 0) {
			return map[i].func;
		}
	}

	return NULL;
}

static const struct qvsp_cfg_param qvsp_cfg_params[] = QVSP_CFG_PARAMS;

static uint32_t
qvsp_cfg_param_get(const char *name)
{
	int i;

	for (i = 0; i < QVSP_CFG_MAX; i++) {
		if (strcmp(name, qvsp_cfg_params[i].name) == 0) {
			return i;
		}
	}
	return QVSP_CFG_MAX;
}

static uint32_t qvsp_cfg_name_len = 0;
static uint32_t qvsp_cfg_units_len = 0;
static uint32_t qvsp_rule_name_len = 0;
static uint32_t qvsp_rule_units_len = 0;
static int qvsp_show_cfg_initialised = 0;

static const char *qvsp_inactive_reason[] = QVSP_INACTIVE_REASON;

/*
 * Getting VSP version: whether it is VSP (v1 for Ruby) or QTM (Quantenna Traffic Management, v2 for Topaz)
 */
static int
qvsp_is_qtm()
{
	struct qcsapi_int_array128 *stats;
	struct qvsp_stats *p_stats;
	int rc;
	int is_qtm;

	stats = malloc(sizeof(*stats));
	if (stats == NULL)
		return -ENOMEM;
	p_stats = (struct qvsp_stats *)stats->val;
	rc = qcsapi_qtm_safe_get_stats("wifi0", stats);
	is_qtm = p_stats->is_qtm;
	free(stats);
	if (rc < 0) {
		return rc;
	}
	return is_qtm;
}

static int
call_qcsapi_vsp_is_active(call_qcsapi_bundle *call)
{
	qcsapi_output *print = call->caller_output;
	unsigned long inactive_flags = 0;
	int rc;
	int i;
	int first = 1;

	rc = qcsapi_qtm_get_inactive_flags(call->caller_interface, &inactive_flags);
	if (rc || inactive_flags) {
		if (rc == 0) {
			print_out(print, "QTM is inactive - reason:");

			for ( i = 0; i < ARRAY_SIZE(qvsp_inactive_reason); i++) {
				if ((inactive_flags & 0x1) && qvsp_inactive_reason[i]) {
					if (!first) {
						print_out(print, ", %s", qvsp_inactive_reason[i]);
					} else {
						print_out(print, " %s", qvsp_inactive_reason[i]);
						first = 0;
					}
				}
				inactive_flags >>= 1;
			}
			print_out(print, "\n");
		}
		return -EPERM;
	}

	return rc;
}

static int
call_qcsapi_vsp_is_enabled(call_qcsapi_bundle *call)
{
	qcsapi_output *print = call->caller_output;
	unsigned int enabled;
	int rc;

	rc = qcsapi_qtm_get_config(call->caller_interface, QVSP_CFG_ENABLED, &enabled);
	if (rc || (enabled == 0)) {
		print_out(print, "QTM is not enabled\n");
		return -EPERM;
	}

	return rc;
}

static void
call_qcsapi_vsp_cfg_paramlist(qcsapi_output *print)
{
	int i;
	const struct qvsp_cfg_param *param;
	int buflen = qvsp_cfg_name_len + qvsp_cfg_units_len + 5;
	char buf[buflen];

	print_out(print, "Parameters\n");


	for (i = 0; i < QVSP_CFG_MAX; i++) {
		param = &qvsp_cfg_params[i];
		snprintf(buf, buflen, "%s <%s>",
				param->name, param->units);
		print_out(print, "    %-*s   - %s [%u to %u]\n",
				buflen,
				buf,
				param->desc,
				param->min_val,
				param->max_val);
	}
}

static void
call_qcsapi_vsp_get_usage(qcsapi_output *print)
{
	print_out(print, "Usage\n"
			"    <qcsapi> qtm <if> get <param>\n\n");

	call_qcsapi_vsp_cfg_paramlist(print);
}

static void
call_qcsapi_vsp_set_usage(qcsapi_output *print)
{
	print_out(print, "Usage\n"
		"    <qcsapi> qtm <if> set <param> <val>\n\n");

	call_qcsapi_vsp_cfg_paramlist(print);
}

static int
call_qcsapi_vsp_get(call_qcsapi_bundle *call, int argc, char *argv[])
{
	qcsapi_output *print = call->caller_output;
	unsigned int index;
	unsigned int value;
	int ret;

	if (argc != 1) {
		call_qcsapi_vsp_get_usage(print);
		return -EINVAL;
	}

	index = qvsp_cfg_param_get(argv[0]);
	if (index >= QVSP_CFG_MAX) {
		call_qcsapi_vsp_get_usage(print);
		return -EINVAL;
	}

	ret = qcsapi_qtm_get_config(call->caller_interface, index, &value);
	if (ret) {
		if (ret == -EINVAL) {
			call_qcsapi_vsp_set_usage(print);
		} else if (ret == -qcsapi_not_supported) {
			print_err(print, "QTM is not supported\n");
		} else {
			print_err(print, "QTM get command failed\n");
		}
		return ret;
	}

	print_out(print, "%u\n", value);

	return 0;
}

static int
call_qcsapi_vsp_set(call_qcsapi_bundle *call, int argc, char *argv[])
{
	qcsapi_output *print = call->caller_output;
	unsigned int index;
	unsigned int value;
	int ret;

	if (argc != 2) {
		call_qcsapi_vsp_set_usage(print);
		return -EINVAL;
	}

	index = qvsp_cfg_param_get(argv[0]);
	ret = sscanf(argv[1], "%u", &value);

	if (index >= QVSP_CFG_MAX) {
		print_err(print, "Invalid argument: '%s'\n", argv[0]);
		call_qcsapi_vsp_set_usage(print);
		return -EINVAL;
	} else if (ret != 1) {
		print_err(print, "Error parsing argument '%s'\n", argv[1]);
		return -EINVAL;
	}

	ret = qcsapi_qtm_set_config(call->caller_interface, index, value);
	if (ret != 0) {
		if (ret == -EINVAL) {
			call_qcsapi_vsp_set_usage(print);
		} else if (ret == -qcsapi_not_supported) {
			print_err(print, "QTM is not supported\n");
		} else {
			print_err(print, "QTM set command failed\n");
		}
		return -EINVAL;
	}

	return 0;
}

const struct qvsp_rule_param qvsp_rule_params[] = QVSP_RULE_PARAMS;

static uint32_t
qvsp_rule_param_get(const char *name)
{
	int i;

	for (i = 0; i < QVSP_RULE_PARAM_MAX; i++) {
		if (strcmp(name, qvsp_rule_params[i].name) == 0) {
			return i;
		}
	}
	return QVSP_RULE_PARAM_MAX;
}

const static char *qvsp_rule_order_desc[] = QVSP_RULE_ORDER_DESCS;
const static char *qvsp_rule_order_desc_abbr[] = QVSP_RULE_ORDER_DESCS_ABBR;
const static char *qvsp_rule_dir_desc[] = QVSP_RULE_DIR_DESCS;
const static char *qvsp_if_desc[] = QVSP_IF_DESCS;
const static char *qvsp_strm_throt_desc_abbr[] = QVSP_STRM_THROT_DESCS_ABBR;

static void
call_qcsapi_vsp_rule_usage(qcsapi_output *print)
{
	const struct qvsp_rule_param *rule_param;
	int i;
	int j;
	int buflen = qvsp_rule_name_len + qvsp_rule_units_len + 6;
	char buf[buflen];

	print_out(print, "Usage\n"
			"    <qcsapi> qtm <if> rule add <param> <val> [<param> <val> ...]\n"
			"                                  - set a stream matching rule\n"
			"    <qcsapi> qtm <if> rule del    - delete all stream matching rules\n"
			"    <qcsapi> qtm <if> rule del [<rule_num>]\n"
			"                                  - delete a stream matching rule\n"
			"\n"
			"Parameters\n");

	for (i = 0; i < QVSP_RULE_PARAM_MAX; i++) {
		rule_param = &qvsp_rule_params[i];
		snprintf(buf, buflen, "    %s <%s>",
				rule_param->name, rule_param->units);
		print_out(print, "%-*s   - %s [%u to %u]\n",
				buflen,
				buf,
				rule_param->desc,
				rule_param->min_val,
				rule_param->max_val);
		switch (i) {
		case QVSP_RULE_PARAM_DIR:
			print_out(print, "%-*s       %u = Any\n", buflen, "", QVSP_RULE_DIR_ANY);
			print_out(print, "%-*s       %u = Tx\n", buflen, "", QVSP_RULE_DIR_TX);
			print_out(print, "%-*s       %u = Rx\n", buflen, "", QVSP_RULE_DIR_RX);
			break;
		case QVSP_RULE_PARAM_VAPPRI:
			print_out(print, "%-*s       0x01 = VAP Priority 0\n", buflen, "");
			print_out(print, "%-*s       0x02 = VAP Priority 1\n", buflen, "");
			print_out(print, "%-*s       0x04 = VAP Priority 2\n", buflen, "");
			print_out(print, "%-*s       0x08 = VAP Priority 3\n", buflen, "");
			break;
		case QVSP_RULE_PARAM_AC:
			print_out(print, "%-*s       0x01 = Best Effort (0)\n", buflen, "");
			print_out(print, "%-*s       0x02 = Background (1)\n", buflen, "");
			print_out(print, "%-*s       0x04 = Video (2)\n", buflen, "");
			print_out(print, "%-*s       0x08 = Voice (3)\n", buflen, "");
			break;
		case QVSP_RULE_PARAM_ORDER:
			for (j = 0; j < QVSP_RULE_ORDER_MAX; j++) {
				print_out(print, "%-*s       %u - %s\n",
						buflen,
						"",
						j,
						qvsp_rule_order_desc[j]);
			}
			break;
		default:
			break;
		}
	}
}

static int call_qcsapi_vsp_rule_parse(qcsapi_output *print,
		int argc, char **argv, struct qvsp_rule_flds *rule_fields)
{
	const struct qvsp_rule_param *rule_param;
	uint32_t rule_param_num;
	uint32_t val;
	int i;
	int ret;

	/* Must be field/value pairs */
	if (argc & 0x1) {
		call_qcsapi_vsp_rule_usage(print);
		return -EINVAL;
	}

	memset(rule_fields, 0, sizeof(*rule_fields));
	/* fields that are not 0 by default */
	rule_fields->param[QVSP_RULE_PARAM_THROT_POLICY] = QVSP_STRM_THROT_ADPT;
	if (!g_is_qtm)
		rule_fields->param[QVSP_RULE_PARAM_DEMOTE] = 1;

	for (i = 0; i < argc; i = i + 2) {
		ret = sscanf(argv[i + 1], "%u", &val);
		if (ret != 1) {
			print_err(print, "QTM: error parsing number: '%s'\n", argv[i + 1]);
			return -EINVAL;
		}

		rule_param_num = qvsp_rule_param_get(argv[i]);
		if (rule_param_num == QVSP_RULE_PARAM_MAX) {
			print_err(print, "QTM: invalid rule - %s\n", argv[i]);
			return -EINVAL;
		}

		rule_param = &qvsp_rule_params[rule_param_num];

		if ((val < rule_param->min_val) || (val > rule_param->max_val)) {
			print_err(print, "QTM: value for %s must be between %u and %u\n",
					argv[i], rule_param->min_val, rule_param->max_val);
			return -EINVAL;
		}

		if ((rule_param_num == QVSP_RULE_PARAM_PROTOCOL) &&
				(val != IPPROTO_UDP) && (val != IPPROTO_TCP)) {
			print_err(print, "QTM: protocol must be %u (TCP) or %u (UDP)\n",
					IPPROTO_TCP, IPPROTO_UDP);
			return -EINVAL;
		}

		rule_fields->param[rule_param_num] = val;
	}

	return 0;
}


static int
call_qcsapi_vsp_rule_add(call_qcsapi_bundle *call, int argc, char *argv[])
{
	qcsapi_output *print = call->caller_output;
	struct qvsp_rule_flds rule_fields;
	struct qcsapi_int_array32 rule_flds_buf;
	int rc;

	if (argc == 0) {
		call_qcsapi_vsp_rule_usage(print);
		return -EINVAL;
	}

	COMPILE_TIME_ASSERT(sizeof(rule_flds_buf.val) >= sizeof(rule_fields));

	rc = call_qcsapi_vsp_rule_parse(print, argc, argv, &rule_fields);
	if (rc) {
		return rc;
	}

	memset(rule_flds_buf.val, 0, sizeof(rule_flds_buf.val));
	memcpy(rule_flds_buf.val, &rule_fields, sizeof(rule_fields));

	return qcsapi_qtm_safe_add_rule(call->caller_interface, &rule_flds_buf);
}

static int
call_qcsapi_vsp_rule_del(call_qcsapi_bundle *call, int argc, char *argv[])
{
	qcsapi_output *print = call->caller_output;
	struct qvsp_rule_flds rule_fields;
	struct qcsapi_int_array32 rule_flds_buf;
	int rc;

	if (argc >= 2 && argc % 2 == 0) {
		COMPILE_TIME_ASSERT(sizeof(rule_flds_buf.val) >= sizeof(rule_fields));

		rc = call_qcsapi_vsp_rule_parse(print, argc, argv, &rule_fields);
		if (rc) {
			return rc;
		}

		memset(rule_flds_buf.val, 0, sizeof(rule_flds_buf.val));
		memcpy(rule_flds_buf.val, &rule_fields, sizeof(rule_fields));

		return qcsapi_qtm_safe_del_rule(call->caller_interface, &rule_flds_buf);
	} else if (argc == 1) {
		unsigned int index;
		rc = sscanf(argv[0], "%u", &index);
		if (rc != 1) {
			print_err(print, "Error parsing argument '%s'\n", argv[0]);
			return -EINVAL;
		}

		return qcsapi_qtm_del_rule_index(call->caller_interface, index);
	} else if (argc == 0) {
		return qcsapi_qtm_del_rule_index(call->caller_interface, ~0);
	} else {
		call_qcsapi_vsp_rule_usage(print);
		return -EINVAL;
	}
}

static const char *
call_qcsapi_vsp_dir_desc(enum qvsp_rule_dir_e dir)
{
	if (dir < ARRAY_SIZE(qvsp_rule_dir_desc)) {
		return qvsp_rule_dir_desc[dir];
	}
	return "invalid";
}

static int
call_qcsapi_vsp_rule_getlist(call_qcsapi_bundle *call, int argc, char *argv[])
{
	qcsapi_output *print = call->caller_output;
	const static unsigned int MAX_RULES = 64;
	const struct qvsp_rule_param *rule_param;
	struct qcsapi_int_array768 *rules_buf;
	struct qvsp_rule_flds *rules;
	struct qvsp_rule_flds default_rule;
	int n;
	int i;
	int j;
	int rc = 0;

	rules_buf = malloc(sizeof(struct qcsapi_int_array768));
	if (rules_buf == NULL)
		return -ENOMEM;
	rules = (struct qvsp_rule_flds *)rules_buf->val;

	memset(&default_rule, 0, sizeof(default_rule));
	n = qcsapi_qtm_safe_get_rule(call->caller_interface, rules_buf, MAX_RULES);
	if (n < 0) {
		rc = n;
		goto out;
	}

	print_out(print, "Rules\n");
	print_out(print, "    Rule ");
	for (i = 0; i < QVSP_RULE_PARAM_MAX; i++) {
		rule_param = &qvsp_rule_params[i];
		print_out(print, "%-8s ", rule_param->name);
	}
	print_out(print, "\n");

	if (n == 0) {
		print_out(print, "    no rules configured\n");
	}
	for (j = 0; j < n; j++) {
		const struct qvsp_rule_flds *rf = &rules[j];

		if (memcmp(&rules[j], &default_rule, sizeof(default_rule)) == 0) {
			print_out(print, "    dflt ");
		} else {
			print_out(print, "    %-4d ", j + 1);
		}
		for (i = 0; i < QVSP_RULE_PARAM_MAX; i++) {
			switch (i) {
			case QVSP_RULE_PARAM_DIR:
				print_out(print, "%-8s ",
					call_qcsapi_vsp_dir_desc(rf->param[i]));
				break;
			case QVSP_RULE_PARAM_VAPPRI:
			case QVSP_RULE_PARAM_AC:
				print_out(print, "0x%-6x ", rf->param[i]);
				break;
			case QVSP_RULE_PARAM_ORDER:
				print_out(print, "%u - %-4s ", rf->param[i],
						qvsp_rule_order_desc_abbr[rf->param[i]]);
				break;
			case QVSP_RULE_PARAM_THROT_POLICY:
				print_out(print, "%u - %-8s ", rf->param[i],
						qvsp_strm_throt_desc_abbr[rf->param[i]]);
				break;
			default:
				print_out(print, "%-8u ", rf->param[i]);
				break;
			}
		}
		print_out(print, "\n");
	}

out:
	if (rules_buf != NULL)
		free(rules_buf);
	return rc;
}

static int
call_qcsapi_vsp_rule(call_qcsapi_bundle *call, int argc, char *argv[])
{
	qcsapi_output *print = call->caller_output;
	call_qcsapi_vsp_fn func;

	static const struct call_qcsapi_fnmap mux[] = {
		{ "add",	call_qcsapi_vsp_rule_add },
		{ "del",	call_qcsapi_vsp_rule_del },
		{ "getlist",	call_qcsapi_vsp_rule_getlist },
	};

	if (argc < 1) {
		call_qcsapi_vsp_rule_usage(print);
		return -EINVAL;
	}

	func = call_qcsapi_fnmap_find(argv[0], mux, ARRAY_SIZE(mux));
	if (func == NULL) {
		call_qcsapi_vsp_rule_usage(print);
		return -EINVAL;
	} else {
		return func(call, argc - 1, argv + 1);
	}
}

#define QCSAPI_CIDR_STRLEN	(4)
#define QCSAPI_PORT_STRLEN	(6)

static void
call_qcsapi_vsp_wl_usage(qcsapi_output *print)
{
	print_out(print, "Usage\n"
			"    <qcsapi> qtm <if> wl add <saddr>[/<netmask>] <sport> <daddr>[/<netmask>] <dport>\n"
			"                               - add a whitelist entry\n"
			"    <qcsapi> qtm <if> wl del <saddr>[/<netmask>] <sport> <daddr>[/<netmask>] <dport>\n"
			"                               - delete a whitelist entry\n"
			"    <qcsapi> qtm <if> wl del\n"
			"                               - delete all whitelist entries\n"
			"\n"
			"Parameters\n"
			"  IPv4:\n"
			"    <saddr>                    - IP source address (0 for any)\n"
			"    <daddr>                    - IP destination address (0 for any)\n"
			"    <netmask>                  - IP netmask (1-32, default is 32)\n"
			"  IPv6:\n"
			"    <saddr>                    - IP source address (::0 for any)\n"
			"    <daddr>                    - IP destination address (::0 for any)\n"
			"    <netmask>                  - IP netmask (1-128, default is 128)\n"
			"  IPv4 or IPv6:\n"
			"    <sport>                    - IP source port (0 for any)\n"
			"    <dport>                    - IP destination port (0 for any)\n"
		 );
}

static int
call_qcsapi_parse_ip_cidr(call_qcsapi_bundle *call, const char *addr,
		__be32 *ipv4, struct in6_addr *ipv6, uint8_t *cidr)
{
	qcsapi_output *print = call->caller_output;
	int rc;
	int ipv;
	int max_cidr;
	char ipscan[128];

	rc = sscanf(addr, "%[^/]/%hhu", ipscan, cidr);

	if (strcmp(ipscan, "0") == 0) {
		*ipv4 = 0;
		ipv = 4;
	} else if (inet_pton(AF_INET, ipscan, ipv4) == 1) {
		ipv = 4;
	} else if (inet_pton(AF_INET6, ipscan, ipv6) == 1) {
		ipv = 6;
	} else {
		print_err(print, "Invalid value parsing ip[/mask] '%s'\n", addr);
		return -EINVAL;
	}

	if (ipv == 4) {
		max_cidr = sizeof(*ipv4) * NBBY;
	} else {
		max_cidr = sizeof(*ipv6) * NBBY;
	}

	if (rc == 2) {
		if (*cidr > max_cidr) {
			print_err(print, "Invalid CIDR (%u) for IPv%d address %s\n",
					*cidr, ipv, ipscan);
			return -EINVAL;
		}
	} else {
		*cidr = max_cidr;
	}

	return ipv;
}

static int
call_qcsapi_vsp_wl_parse_wlf(call_qcsapi_bundle *call, struct qvsp_wl_flds *wl_fields,
		const char *saddr, const char *daddr)
{
	qcsapi_output *print = call->caller_output;
	int rc;
	int ipv;

	rc = call_qcsapi_parse_ip_cidr(call, saddr,
			&wl_fields->hflds.ipv4.saddr,
			&wl_fields->hflds.ipv6.saddr,
			&wl_fields->s_cidr_bits);
	if (rc < 0) {
		return -EINVAL;
	}
	ipv = rc;

	rc = call_qcsapi_parse_ip_cidr(call, daddr,
			&wl_fields->hflds.ipv4.daddr,
			&wl_fields->hflds.ipv6.daddr,
			&wl_fields->d_cidr_bits);
	if (rc < 0) {
		return -EINVAL;
	} else if (rc != ipv) {
		print_err(print, "IP addresses are not both IPv4 or IPv6\n");
		return -EINVAL;
	}

	wl_fields->ip_version = ipv;

	return ipv;
}

static int
call_qcsapi_vsp_wl_parse(call_qcsapi_bundle *call, int argc, char *argv[], struct qvsp_wl_flds *wl_fields)
{
	qcsapi_output *print = call->caller_output;
	uint16_t sport;
	uint16_t dport;
	int ipv;

	if (argc != 4) {
		call_qcsapi_vsp_wl_usage(print);
		return -EINVAL;
	}

	ipv = call_qcsapi_vsp_wl_parse_wlf(call, wl_fields, argv[0], argv[2]);
	if (ipv < 0) {
		return -EINVAL;
	}

	if (sscanf(argv[1], "%hu", &sport) != 1) {
		print_err(print, "Error parsing source port '%s'\n", argv[1]);
		return -EINVAL;
	}
	if (sscanf(argv[3], "%hu", &dport) != 1) {
		print_err(print, "Error parsing destination port '%s'\n", argv[3]);
		return -EINVAL;
	}

	if (ipv == 4) {
		wl_fields->hflds.ipv4.sport = htons(sport);
		wl_fields->hflds.ipv4.dport = htons(dport);
	} else {
		wl_fields->hflds.ipv6.sport = htons(sport);
		wl_fields->hflds.ipv6.dport = htons(dport);
	}

	return 0;
}

static int
call_qcsapi_vsp_wl_add(call_qcsapi_bundle *call, int argc, char *argv[])
{
	struct qvsp_wl_flds wl;
	int rc;

	if (g_is_qtm)
		return 0;

	rc = call_qcsapi_vsp_wl_parse(call, argc, argv, &wl);
	if (rc) {
		return rc;
	}

#ifdef CALL_QCSAPI_QTM_UNSUPPORTED
	return qcsapi_vsp_add_wl(call->caller_interface, &wl);
#else
	return 0;
#endif
}

static int
call_qcsapi_vsp_wl_del(call_qcsapi_bundle *call, int argc, char *argv[])
{
	qcsapi_output *print = call->caller_output;
	struct qvsp_wl_flds wl;
	int rc;

	if (g_is_qtm)
		return 0;

	if (argc == 4) {
		rc = call_qcsapi_vsp_wl_parse(call, argc, argv, &wl);
		if (rc) {
			return rc;
		}

#ifdef CALL_QCSAPI_QTM_UNSUPPORTED
		return qcsapi_vsp_del_wl(call->caller_interface, &wl);
#else
		return 0;
#endif
	} else if (argc == 1) {
		unsigned int index;
		rc = sscanf(argv[0], "%u", &index);
		if (rc != 1) {
			print_err(print, "Error parsing argument '%s'\n", argv[0]);
			return -EINVAL;
		}

#ifdef CALL_QCSAPI_QTM_UNSUPPORTED
		return qcsapi_vsp_del_wl_index(call->caller_interface, index);
#else
		return 0;
#endif
	} else if (argc == 0) {
#ifdef CALL_QCSAPI_QTM_UNSUPPORTED
		return qcsapi_vsp_del_wl_index(call->caller_interface, ~0);
#else
		return 0;
#endif
	} else {
		call_qcsapi_vsp_wl_usage(print);
		return -EINVAL;
	}
}

#ifdef CALL_QCSAPI_QTM_UNSUPPORTED
static void call_qcsapi_vsp_wl_fmt(const struct qvsp_wl_flds *wlf, char *saddr, char *daddr, char *sport, char *dport)
{
	const struct in6_addr zero = IN6ADDR_ANY_INIT;

	strcpy(saddr, QVSP_CFG_SHOW_ANYSTR);
	strcpy(daddr, QVSP_CFG_SHOW_ANYSTR);
	strcpy(sport, QVSP_CFG_SHOW_ANYSTR);
	strcpy(dport, QVSP_CFG_SHOW_ANYSTR);

	if (wlf->ip_version == 4) {
		const struct qvsp_hash_flds_ipv4 *ip = &wlf->hflds.ipv4;

		if (ip->saddr) {
			sprintf(saddr, NIPQUAD_FMT "/%u",
					NIPQUAD(ip->saddr),
					wlf->s_cidr_bits);
		}
		if (ip->daddr) {
			sprintf(daddr, NIPQUAD_FMT "/%u",
					NIPQUAD(ip->daddr),
					wlf->d_cidr_bits);
		}
		if (ip->sport) {
			sprintf(sport, "%u", ntohs(ip->sport));
		}
		if (ip->dport) {
			sprintf(dport, "%u", ntohs(ip->dport));
		}
	} else {
		const struct qvsp_hash_flds_ipv6 *ip = &wlf->hflds.ipv6;
		char cidr[QCSAPI_CIDR_STRLEN];

		if (memcmp(&ip->saddr, &zero, sizeof(ip->saddr))) {
			inet_ntop(AF_INET6, &ip->saddr,
					saddr, INET6_ADDRSTRLEN);
			sprintf(cidr, "/%u", wlf->s_cidr_bits);
			strcat(saddr, cidr);
		}
		if (memcmp(&ip->daddr, &zero, sizeof(ip->daddr))) {
			inet_ntop(AF_INET6, &ip->daddr,
					daddr, INET6_ADDRSTRLEN);
			sprintf(cidr, "/%u", wlf->d_cidr_bits);
			strcat(daddr, cidr);
		}
		if (ip->sport) {
			sprintf(sport, "%u", ntohs(ip->sport));
		}
		if (ip->dport) {
			sprintf(dport, "%u", ntohs(ip->dport));
		}
	}
}
#endif

#define WL_FMT "    %-*s %-*s %-*s %-*s\n"

#define DISPLAY_WL(saddr_len, daddr_len, saddr, sport, daddr, dport) do {	\
	print_out(print, WL_FMT,						\
		saddr_len, saddr, QCSAPI_PORT_STRLEN, sport,			\
		daddr_len, daddr, QCSAPI_PORT_STRLEN, dport);			\
} while(0);

static int
call_qcsapi_vsp_wl_getlist(call_qcsapi_bundle *call, int argc, char *argv[])
{
#ifdef CALL_QCSAPI_QTM_UNSUPPORTED
	qcsapi_output *print = call->caller_output;
	const unsigned int MAX_WL = 64;
	char saddr[INET6_ADDRSTRLEN + 1];
	char daddr[INET6_ADDRSTRLEN + 1];
	char sport[QCSAPI_PORT_STRLEN + 1];
	char dport[QCSAPI_PORT_STRLEN + 1];
	int max_saddr_strlen = NIPQUAD_LEN;
	int max_daddr_strlen = NIPQUAD_LEN;
	struct qvsp_wl_flds *wl;
	int i;
	int rc = 0;

	if (g_is_qtm)
		return 0;

	wl = malloc(sizeof(*wl) * MAX_WL);
	if (!wl) {
		return -ENOMEM;
	}

	rc = qcsapi_vsp_get_wl(call->caller_interface, wl, MAX_WL);
	if (rc < 0) {
		free(wl);
		return rc;
	}
	print_out(print, "Whitelist\n");
	if (rc == 0) {
		DISPLAY_WL(max_saddr_strlen, max_daddr_strlen, "Source IP",
			"SPort", "Dest IP", "DPort");
		print_out(print, "    no whitelist entries\n");
	} else {
		int wl_num = rc;

		/* find max string length for ip addresses */
		for (i = 0; i < wl_num; i++) {
			int saddr_strlen;
			int daddr_strlen;
			call_qcsapi_vsp_wl_fmt(&wl[i], saddr, daddr, sport, dport);
			saddr_strlen = strlen(saddr);
			daddr_strlen = strlen(daddr);
			max_saddr_strlen = max(max_saddr_strlen, saddr_strlen);
			max_daddr_strlen = max(max_daddr_strlen, daddr_strlen);
		}

		DISPLAY_WL(max_saddr_strlen, max_daddr_strlen, "Source IP",
			"SPort", "Dest IP", "DPort");

		for (i = 0; i < wl_num; i++) {
			call_qcsapi_vsp_wl_fmt(&wl[i], saddr, daddr, sport, dport);
			DISPLAY_WL(max_saddr_strlen, max_daddr_strlen, saddr, sport, daddr, dport);
		}
	}

	free(wl);
#endif
	return 0;
}

static int
call_qcsapi_vsp_wl(call_qcsapi_bundle *call, int argc, char *argv[])
{
	qcsapi_output *print = call->caller_output;
	call_qcsapi_vsp_fn func;

	static const struct call_qcsapi_fnmap mux[] = {
		{ "add",	call_qcsapi_vsp_wl_add },
		{ "del",	call_qcsapi_vsp_wl_del },
		{ "getlist",	call_qcsapi_vsp_wl_getlist },
	};

	if (argc < 1) {
		call_qcsapi_vsp_wl_usage(print);
		return -EINVAL;
	}

	func = call_qcsapi_fnmap_find(argv[0], mux, ARRAY_SIZE(mux));
	if (func == NULL) {
		call_qcsapi_vsp_rule_usage(print);
		return -EINVAL;
	} else {
		return func(call, argc - 1, argv + 1);
	}
}

static void
call_qcsapi_vsp_show_usage(qcsapi_output *print)
{
	print_out(print, "Usage\n"
		"    <qcsapi> qtm <if> show          - show current state and high throughput streams\n"
		"    <qcsapi> qtm <if> show all      - show current state and all streams\n"
		"    <qcsapi> qtm <if> show stats    - show stream and packet statistics\n"
		"    <qcsapi> qtm <if> show config   - show config parameters, rules, and whitelist\n");
}

static int
call_qcsapi_vsp_show_config(call_qcsapi_bundle *call, int argc, char *argv[])
{
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	qcsapi_output *print = call->caller_output;
	struct qcsapi_int_array256 *cfg_buf;
	unsigned int *cfg;
	int rc;
	int i;

	cfg_buf = (struct qcsapi_int_array256 *)malloc(sizeof(struct qcsapi_int_array256));
	if (cfg_buf == NULL) {
		return -ENOMEM;
	}
	cfg = (unsigned int *)cfg_buf->val;

	rc = qcsapi_qtm_safe_get_config_all(call->caller_interface, cfg_buf, QVSP_CFG_MAX);
	if (rc) {
		free(cfg_buf);
		return rc;
	}

	print_out(print, "Parameters\n");
	for (i = 0; i < QVSP_CFG_MAX; i++) {
		if (cfg[i] == QCSAPI_QTM_CFG_INVALID)
			continue;
		print_out(print, "    %-*s  %-8u\n",
				qvsp_cfg_name_len,
				qvsp_cfg_params[i].name,
				cfg[i]);
	}
	free(cfg_buf);

	if (qcsapi_wifi_get_mode(call->caller_interface, &wifi_mode) < 0) {
		return -1;
	}

	if (wifi_mode == qcsapi_station) {
		return 0;
	}

	print_out(print, "\n");
	call_qcsapi_vsp_rule_getlist(call, 0, NULL);

	if (!g_is_qtm) {
		print_out(print, "\n");
		call_qcsapi_vsp_wl_getlist(call, 0, NULL);
	}
	return 0;
}

static const char *
call_qcsapi_qvsp_state_desc(enum qvsp_strm_state_e strm_state)
{
	switch (strm_state) {
	case QVSP_STRM_STATE_NONE:
		return "none";
	case QVSP_STRM_STATE_DISABLED:
		return "dis";
	case QVSP_STRM_STATE_LOW_TPUT:
		return "low";
	case QVSP_STRM_STATE_PRE_ENABLED:
		return "pre";
	case QVSP_STRM_STATE_ENABLED:
		return "ena";
	case QVSP_STRM_STATE_DELETED:
		return "del";
	case QVSP_STRM_STATE_MAX:
		break;
	}

	return "invalid";
}

static int
call_qcsapi_vsp_show_strms(call_qcsapi_bundle *call, int show_all)
{
	qcsapi_output *print = call->caller_output;
	unsigned int state[(sizeof(struct qcsapi_int_array32) / sizeof(unsigned int))];
	int rc;
	int i;
	struct qvsp_strms *strms_buf = NULL;
	struct qvsp_strm_info_safe *strms;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	char node_idx_buf[5];
	char *sta_str;
	uint32_t bytes;
	uint32_t pkts;

	strms_buf = malloc(sizeof(struct qvsp_strms));
	if (!strms_buf)
		return -ENOMEM;

	strms = strms_buf->strms;

	rc = qcsapi_wifi_get_mode(call->caller_interface, &wifi_mode);
	if (rc < 0) {
		goto out;
	}

	rc = qcsapi_qtm_safe_get_state_all(call->caller_interface, (void *)&state, QVSP_STATE_READ_MAX);
	if (rc < 0) {
		goto out;
	}

	rc = qcsapi_qtm_safe_get_strm(call->caller_interface, strms_buf, show_all);
	if (rc < 0) {
		goto out;
	}

	print_out(print, "Free airtime:        %u\n", state[QVSP_STATE_FAT]);
	print_out(print, "Interference:        %u\n", state[QVSP_STATE_FAT_INTF]);
	print_out(print, "Streams:\n");
	print_out(print, "    Total:           %u\n", state[QVSP_STATE_STRM_TOT]);
	print_out(print, "    QTM peers:       %u\n", state[QVSP_STATE_STRM_QTN]);
	print_out(print, "    Enabled:         %u\n", state[QVSP_STATE_STRM_ENA]);
	print_out(print, "    Disabled:        %u\n", state[QVSP_STATE_STRM_DIS]);
	print_out(print, "    Demoted:         %u\n", state[QVSP_STATE_STRM_DMT]);

	print_out(print, "Hash Dir Sta ");
	print_out(print, "%-17s ", "Station");
	print_out(print, "NdIdx TID VapPri AC ");
	print_out(print, "pps    TotPps Kbps    MaxKbps Rate NdCst Cost  Max   Age Status Dmt ThrKbps\n");

	for (i = 0; i < rc; i++) {
		const struct qvsp_strm_info_safe *strm = &strms[i];

		if (show_all == 0 && strm->strm_state == QVSP_STRM_STATE_LOW_TPUT) {
			continue;
		}

		if (wifi_mode == qcsapi_station) {
			sta_str = "-";
		} else {
			sta_str = strm->disable_remote ? "y" : "n";
		}

		/* pkts and bytes in the air */
		pkts = strm->prev_stats.pkts_sent;
		bytes = strm->prev_stats.bytes_sent;

		print_out(print, "%03u  %-3s %-3s ",
				strm->hash,
				call_qcsapi_vsp_dir_desc(strm->dir),
				sta_str);

		print_out(print, MACSTR" ", MAC2STR(strm->node_mac));

		switch (strm->hairpin_type) {
		case QVSP_HAIRPIN_NONE:
			snprintf(node_idx_buf, sizeof(node_idx_buf) - 1, "%u",
				strm->node_idx);
			break;
		case QVSP_HAIRPIN_UCAST:
			snprintf(node_idx_buf, sizeof(node_idx_buf) - 1, "%u-%u",
				strm->node_idx, strm->hairpin_id);
			break;
		case QVSP_HAIRPIN_MCAST:
			snprintf(node_idx_buf, sizeof(node_idx_buf) - 1, "%u-%u",
				strm->hairpin_id, strm->node_idx);
		}
		print_out(print, "%-5s ", node_idx_buf);

		print_out(print, "%-3u %-6u ", strm->tid, (uint32_t)strm->vap_pri);
		print_out(print,
				"%u  %-6u %-6u %-7u %-7u %-4u %-5u %-5u %-5u %-3u %-6s %u-%u [%s]%-7u\n",
				strm->ac_in,
				pkts, strm->prev_stats.pkts,
				qvsp_b2kbit(bytes),
				qvsp_b2kbit(strm->bytes_max),
				(strm->ni_inv_phy_rate == 0) ?
					0 : qvsp_inv2phy(strm->ni_inv_phy_rate),
				strm->ni_cost,
				strm->cost_current,
				strm->cost_max,
				strm->last_ref_secs,
				call_qcsapi_qvsp_state_desc(strm->strm_state),
				strm->demote_rule,
				strm->demote_state,
				qvsp_strm_throt_desc_abbr[strm->throt_policy],
				strm->throt_rate);
	}

	rc = 0;
out:
	if (strms_buf != NULL)
		free(strms_buf);
	return rc;
}

static int
call_qcsapi_vsp_show_all(call_qcsapi_bundle *call, int argc, char *argv[])
{
	return call_qcsapi_vsp_show_strms(call, 1);
}

static const char *
call_qcsapi_vsp_if_desc(enum qvsp_if_e vsp_if)
{
	if (vsp_if < ARRAY_SIZE(qvsp_if_desc)) {
		return qvsp_if_desc[vsp_if];
	}
	return "invalid";
}

static int
call_qcsapi_vsp_show_stats(call_qcsapi_bundle *call, int argc, char *argv[])
{
	qcsapi_output *print = call->caller_output;
	struct qvsp_stats stats;
	enum qvsp_if_e vsp_if;
	int rc;

	rc = qcsapi_qtm_safe_get_stats(call->caller_interface, (void *)&stats);
	if (rc < 0) {
		return rc;
	}

	print_out(print, "Free airtime\n");
	print_out(print, "  Oversubscription:         %u\n", stats.fat_over);
	print_out(print, "  Streams disabled:         %u\n", stats.fat_chk_disable);
	print_out(print, "  Undersubscription:        %u\n", stats.fat_under);
	print_out(print, "  Stream re-enabled:        %u\n", stats.fat_chk_reenable);
	print_out(print, "Streams\n");
	print_out(print, "  Enabled:                  %u\n", stats.strm_enable);
	print_out(print, "  Disabled:                 %u\n", stats.strm_disable);
	print_out(print, "  Re-enabled:               %u\n", stats.strm_reenable);
	print_out(print, "\n");
	print_out(print, "  Interface   Added  Not Fnd\n");
	for (vsp_if = 0; vsp_if < QVSP_IF_MAX; vsp_if++) {
		print_out(print, "  %-8s %8u %8u\n",
			call_qcsapi_vsp_if_desc(vsp_if),
			stats.stats_if[vsp_if].strm_add,
			stats.stats_if[vsp_if].strm_none);
	}
	print_out(print, "Packets\n");
	print_out(print, "  Interface   Checked        UDP        TCP      Other     "
			"Ignore       Sent  Throttled   Disabled Frag Found  Not Found    Demoted\n");
	for (vsp_if = 0; vsp_if < QVSP_IF_MAX; vsp_if++) {
		print_out(print,
			"  %-8s %10u %10u %10u %10u %10u %10u %10u %10u %10u %10u %10u\n",
			call_qcsapi_vsp_if_desc(vsp_if),
			stats.stats_if[vsp_if].pkt_chk,
			stats.stats_if[vsp_if].pkt_udp,
			stats.stats_if[vsp_if].pkt_tcp,
			stats.stats_if[vsp_if].pkt_other,
			stats.stats_if[vsp_if].pkt_ignore,
			stats.stats_if[vsp_if].pkt_sent,
			stats.stats_if[vsp_if].pkt_drop_throttle,
			stats.stats_if[vsp_if].pkt_drop_disabled,
			stats.stats_if[vsp_if].pkt_frag_found,
			stats.stats_if[vsp_if].pkt_frag_not_found,
			stats.stats_if[vsp_if].pkt_demoted);
	}

	return 0;
}

static int
call_qcsapi_vsp_show(call_qcsapi_bundle *call, int argc, char *argv[])
{
	qcsapi_output *print = call->caller_output;
	call_qcsapi_vsp_fn func;
	int rc;

	static const struct call_qcsapi_fnmap mux[] = {
		{ "all",	call_qcsapi_vsp_show_all },
		{ "config",	call_qcsapi_vsp_show_config },
		{ "stats",	call_qcsapi_vsp_show_stats },
	};

	rc = call_qcsapi_vsp_is_enabled(call);
	if (rc < 0) {
		return rc;
	}

	if ((argv[0] == NULL) || (strcmp(argv[0], "config") != 0)) {
		rc = call_qcsapi_vsp_is_active(call);
		if (rc < 0) {
			return rc;
		}
	}

	if (argc == 0) {
		return call_qcsapi_vsp_show_strms(call, 0);
	}

	func = call_qcsapi_fnmap_find(argv[0], mux, ARRAY_SIZE(mux));
	if (func == NULL) {
		call_qcsapi_vsp_show_usage(print);
		return -EINVAL;
	} else {
		return func(call, argc - 1, argv + 1);
	}
}

static void
call_qcsapi_vsp_test_usage(qcsapi_output *print)
{
	print_out(print, "Usage:\n"
			"    <qcsapi> qtm <if> test fat <fat>\n");
}


static int
call_qcsapi_vsp_reset(call_qcsapi_bundle *call, int argc, char *argv[])
{
	int rc;

	rc = call_qcsapi_vsp_is_enabled(call);
	if (rc < 0) {
		return rc;
	}

	return qcsapi_qtm_set_state(call->caller_interface, QVSP_STATE_RESET, 0);
}

static int
call_qcsapi_vsp_test_fat(call_qcsapi_bundle *call, int argc, char *argv[])
{
	qcsapi_output *print = call->caller_output;
	unsigned int val;
	int rc;

	if (argc != 1) {
		goto err;
	}

	rc = sscanf(argv[0], "%u", &val);
	if (rc != 1) {
		print_err(print, "QTM: error parsing '%s'\n", argv[0]);
		goto err;
	}

	rc = call_qcsapi_vsp_is_enabled(call);
	if (rc < 0) {
		return rc;
	}

	return qcsapi_qtm_set_state(call->caller_interface, QVSP_STATE_TEST_FAT, val);

err:
	call_qcsapi_vsp_test_usage(print);
	return -EINVAL;
}

static int
call_qcsapi_vsp_test(call_qcsapi_bundle *call, int argc, char *argv[])
{
	qcsapi_output *print = call->caller_output;
	call_qcsapi_vsp_fn func;
	int rc;

	static const struct call_qcsapi_fnmap mux[] = {
		{ "fat",	call_qcsapi_vsp_test_fat },
	};

	if (argc < 1) {
		call_qcsapi_vsp_test_usage(print);
		return -EINVAL;
	}

	rc = call_qcsapi_vsp_is_enabled(call);
	if (rc < 0) {
		return rc;
	}

	func = call_qcsapi_fnmap_find(argv[0], mux, ARRAY_SIZE(mux));
	if (func == NULL) {
		call_qcsapi_vsp_test_usage(print);
		return -EINVAL;
	} else {
		return func(call, argc - 1, argv + 1);
	}
}

static void call_qcsapi_vsp_init(void)
{
	int i;

	if (!qvsp_show_cfg_initialised) {
		qvsp_show_cfg_initialised = 1;

		for (i = 0; i < QVSP_CFG_MAX; i++) {
			if (strlen(qvsp_cfg_params[i].name) > qvsp_cfg_name_len) {
				qvsp_cfg_name_len = strlen(qvsp_cfg_params[i].name);
			}
			if (strlen(qvsp_cfg_params[i].units) > qvsp_cfg_units_len) {
				qvsp_cfg_units_len = strlen(qvsp_cfg_params[i].units);
			}
		}

		for (i = 0; i < QVSP_RULE_PARAM_MAX; i++) {
			if (strlen(qvsp_rule_params[i].name) > qvsp_rule_name_len) {
				qvsp_rule_name_len = strlen(qvsp_rule_params[i].name);
			}
			if (strlen(qvsp_rule_params[i].units) > qvsp_rule_units_len) {
				qvsp_rule_units_len = strlen(qvsp_rule_params[i].units);
			}
		}
	}
}

static void
call_qcsapi_vsp_usage(qcsapi_output *print)
{
	if (!g_is_qtm) {
		print_out(print, "Usage:\n"
			"    <qcsapi> qtm <if> show [config | all]\n"
			"    <qcsapi> qtm <if> reset\n"
			"    <qcsapi> qtm <if> set <param> <val>\n"
			"    <qcsapi> qtm <if> get <param>\n"
			"    <qcsapi> qtm <if> rule [add | del] <arg> [<arg> ...]\n"
			"    <qcsapi> qtm <if> wl [add | del] <saddr> <daddr> <sport> <dport>\n"
			"    <qcsapi> qtm <if> test <args>\n");
	} else {
		print_out(print, "Usage:\n"
			"    <qcsapi> qtm <if> show [config | all]\n"
			"    <qcsapi> qtm <if> reset\n"
			"    <qcsapi> qtm <if> set <param> <val>\n"
			"    <qcsapi> qtm <if> get <param>\n"
			"    <qcsapi> qtm <if> rule [add | del] <arg> [<arg> ...]\n"
			"    <qcsapi> qtm <if> test <args>\n");
	}
}

static int
call_qcsapi_vsp(call_qcsapi_bundle *call, int argc, char *argv[])
{
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	qcsapi_output *print = call->caller_output;
	call_qcsapi_vsp_fn func;
	int rc;
	int statval = 0;

	static const struct call_qcsapi_fnmap mux[] = {
		{ "set",	call_qcsapi_vsp_set },
		{ "get",	call_qcsapi_vsp_get },
		{ "rule",	call_qcsapi_vsp_rule },
		{ "wl",		call_qcsapi_vsp_wl },
		{ "show",	call_qcsapi_vsp_show },
		{ "reset",	call_qcsapi_vsp_reset },
		{ "test",	call_qcsapi_vsp_test },
	};

	call_qcsapi_vsp_init();

	if (argc < 1) {
		call_qcsapi_vsp_usage(print);
		return -EINVAL;
	}

	rc = qvsp_is_qtm();
	if (rc < 0)
		return rc;
	g_is_qtm = rc;

	func = call_qcsapi_fnmap_find(argv[0], mux, ARRAY_SIZE(mux));
	if (func == NULL) {
		call_qcsapi_vsp_usage(print);
		return -EINVAL;
	}

	rc = qcsapi_wifi_get_mode(call->caller_interface, &wifi_mode);
	if (rc >= 0) {
		if (wifi_mode == qcsapi_station) {
			if (func == call_qcsapi_vsp_set || func == call_qcsapi_vsp_rule
							|| func == call_qcsapi_vsp_wl) {
				print_err(print, "QTM: %s command cannot be used on stations\n",
					argv[0]);
				return -EINVAL;
			}
		}

		rc = func(call, argc - 1, argv + 1);
	}

	if (rc < 0) {
		report_qcsapi_error( call, rc );
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_run_script(call_qcsapi_bundle *call, int argc, char *argv[])
{
	int	statval = 0;
	int i = 0;
	char *scriptname = NULL;
	char param[QCSAPI_CMD_BUFSIZE], *param_p;
	int len = 0;
	int space = sizeof(param) - 1;
	int qcsapi_retval;
	qcsapi_output *print = call->caller_output;
	param_p = param;

	if (argc == 0) {
		print_err(print, "Not enough parameters\n");
		return 1;
	}

	scriptname = argv[0];

	for (i = 1; i < argc; i++) {
		if (strlen(argv[i]) + 1 < space) {
			len = sprintf(param_p , "%s ", argv[i]);
			param_p += len;
			space -= len;
		} else {
			print_err(print, "Parameter string is too long\n");
			return 1;
		}
	}

	*param_p = '\0';
	qcsapi_retval = qcsapi_wifi_run_script(scriptname, param);
	if (qcsapi_retval < 0) {
		report_qcsapi_error(call, qcsapi_retval);
		if (qcsapi_retval == -qcsapi_not_authorized)
			return 1;
		statval = 1;
	}

#ifdef BUILDIN_TARGET_BOARD
{
	char strbuf[QCSAPI_MSG_BUFSIZE] = {0};
	FILE *log_file;
	/* output the script message */
	log_file = fopen(QCSAPI_SCRIPT_LOG, "r");
	if (log_file != NULL) {
		while (fgets(strbuf, sizeof(strbuf), log_file))
			print_out(print, "%s", strbuf);
		fclose(log_file);
	} else {
		print_err(print, "Failed to open file %s\n", QCSAPI_SCRIPT_LOG);
		return 1;
	}
}
#endif

	return statval;
}

#define QCSAPI_TEMP_INVALID     (-274 * QDRV_TEMPSENS_COEFF10)

static int
call_qcsapi_get_temperature(call_qcsapi_bundle *call, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	int temp_rfic_external = QCSAPI_TEMP_INVALID;
	int temp_rfic_internal = QCSAPI_TEMP_INVALID;
	int temp_bbic_internal = QCSAPI_TEMP_INVALID;

	qcsapi_output *print = call->caller_output;

	qcsapi_retval = qcsapi_get_temperature_info(&temp_rfic_external, &temp_rfic_internal,
			&temp_bbic_internal);

	if (qcsapi_retval >= 0) {
		if (temp_rfic_external != QCSAPI_TEMP_INVALID) {
			print_out(print, "temperature_rfic_external = %3.1f\n",
				  (float)temp_rfic_external / QDRV_TEMPSENS_COEFF);
		}
		if (temp_rfic_internal != QCSAPI_TEMP_INVALID) {
			print_out(print, "temperature_rfic_internal = %3.1f\n",
				  (float)temp_rfic_internal / QDRV_TEMPSENS_COEFF10);
		}
		if (temp_bbic_internal != QCSAPI_TEMP_INVALID) {
			print_out(print, "temperature_bbic_internal = %3.1f\n",
				  (float)temp_bbic_internal / QDRV_TEMPSENS_COEFF10);
		}
	} else {
		report_qcsapi_error(call, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_set_accept_oui_filter(call_qcsapi_bundle *call, int argc, char *argv[])
{
	int	statval = 0;
	qcsapi_output *print = call->caller_output;

	if (argc < 2)
	{
		print_err(print, "Not enough parameters\n");
		statval = 1;
	}
	else
	{
		const char *the_interface = call->caller_interface;
		qcsapi_mac_addr the_mac_addr;
		qcsapi_mac_addr oui = {0};
		int qcsapi_retval;
		int ival = 0;
		int action;

		if (local_str_to_int32(argv[1], &action, print, "flag") < 0)
			return 1;

		ival = parse_mac_addr(argv[0], the_mac_addr);

		if (ival >= 0) {
			memcpy(oui, the_mac_addr, 3);
			qcsapi_retval = qcsapi_wifi_set_accept_oui_filter(the_interface, oui, action);
			if (qcsapi_retval >= 0) {
				if (verbose_flag >= 0)
					print_out(print, "complete\n");

			} else {
				report_qcsapi_error(call, qcsapi_retval);
				statval = 1;
			}

		} else {
			print_out(print, "Error parsing MAC address %s\n", argv[0]);
			statval = 1;
		}
	}

	return statval;
}

#define QCSAPI_OUI_LIST_SIZE 126
static int
call_qcsapi_get_accept_oui_filter(call_qcsapi_bundle *call, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = call->caller_interface;
	qcsapi_output *print = call->caller_output;
	char *oui_list = NULL;
	unsigned int sizeof_oui_list = QCSAPI_OUI_LIST_SIZE;

	if (argc > 0) {
		uint32_t usr_input = 0;

		if (local_str_to_uint32(argv[0], &usr_input, print, "size") < 0)
			return 1;

		sizeof_oui_list = (usr_input < QCSAPI_MSG_BUFSIZE) ? usr_input : QCSAPI_MSG_BUFSIZE;
	}

	oui_list = malloc(sizeof_oui_list);
	if (oui_list == NULL) {
		print_err( print, "Failed to allocate %u chars\n", sizeof_oui_list);
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_get_accept_oui_filter(the_interface, oui_list, sizeof_oui_list);

        if (qcsapi_report_str_or_error(call, qcsapi_retval, oui_list))
		statval = 1;

	free(oui_list);

	return statval;
}

static int
call_qcsapi_wifi_set_vht(call_qcsapi_bundle *call, int argc, char *argv[])
{
	int rc = 0;
	qcsapi_output *print = call->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi wifi set_vht, count is %d\n", argc );
		print_err( print, "Usage: call_qcsapi set_vht <WiFi interface> <0 | 1>\n" );
		rc = 1;
	} else {
		uint8_t vht_status;
		const char		*the_interface = call->caller_interface;
		int			qcsapi_retval;

		if (local_verify_enable_or_disable(argv[0], &vht_status, print) < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_set_vht( the_interface, vht_status );
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error( call, qcsapi_retval );
			rc = 1;
		}
	}
	return rc;
}

static int
call_qcsapi_get_swfeat_list(call_qcsapi_bundle *call, int argc, char *argv[])
{
	int qcsapi_retval;
	qcsapi_output *print = call->caller_output;
	string_4096 buf;

	qcsapi_retval = qcsapi_get_swfeat_list(buf);
	if (qcsapi_retval < 0) {
		report_qcsapi_error(call, qcsapi_retval);
		return 1;
	}

	print_out(print, "%s\n", buf);

	return 0;
}

/*
 * Pass-in epoch time (UTC secs) to convert to readable date string
 */
static void
local_qcsapi_timestr(char *const buf, const size_t bufsize, const uint32_t utc_time_secs)
{
	const time_t epoch_seconds = utc_time_secs;
	struct tm tm_parsed;

	gmtime_r(&epoch_seconds, &tm_parsed);

	strftime(buf, bufsize, "%d %B %Y %H:%M:%S", &tm_parsed);
}

static char *uboot_type_to_str(char type)
{
	char *ptr;

	switch (type - '0') {
	case UBOOT_INFO_LARGE:
		ptr = "Large";
		break;
	case UBOOT_INFO_MINI:
		ptr = "Mini";
		break;
	case UBOOT_INFO_TINY:
		ptr = "Tiny";
		break;
	default:
		ptr = "Unknown";
	}

	return ptr;
}

/*
 * Primary userspace call_qcsapi handler to get u-boot information
 */
static int
call_qcsapi_get_uboot_info(call_qcsapi_bundle *call, int argc, char *argv[])
{
	qcsapi_output *print = call->caller_output;
	struct early_flash_config ef_config;
	string_32 version_str;
	string_32 built_str = {0};
	uint32_t u_boot_time;
	int qcsapi_retval;
	int uboot_info;
	char *file;

	if (argc < 1) {
		print_err(print, "Not enough parameters in call_qcsapi get_uboot_info, "
					"count is %d\n", argc);
		print_err(print, "Usage: call_qcsapi get_uboot_info <info> : "
					"0 - ver, 1 - built, 2 - type, 3 - all\n");
		return -1;
	}

	file = (argc > 1) ? argv[1] : NULL;

	qcsapi_retval = qcsapi_get_uboot_img_info(version_str, &ef_config, file);
	if (qcsapi_retval) {
		print_err(print, "Call to qcsapi_get_uboot_info failed qcsapi_retval=%d\n",
				qcsapi_retval);
		return -1;
	}

	errno = 0;
	u_boot_time = strtol((char *)ef_config.built_time_utc_sec, NULL, 10);
	if (errno) {
		print_err(print, "strtol(%s) failed, errno=-%d\n",
				(char *)ef_config.built_time_utc_sec, errno);
		return -errno;
	}

	/* Convert UTC seconds to readable date string */
	local_qcsapi_timestr(built_str, sizeof(built_str) - 1, u_boot_time);

	if (local_str_to_int32(argv[0], &uboot_info, print, "uboot info value") < 0)
		return 1;

	switch (uboot_info) {
	case UBOOT_INFO_VER:
		print_out(print, "Version: %s\n", version_str);
		break;
	case UBOOT_INFO_BUILT:
		print_out(print, "Built: %s\n", built_str);
		break;
	default:
	case UBOOT_INFO_TYPE:
	case UBOOT_INFO_ALL:
		if (uboot_info == UBOOT_INFO_ALL) {
			print_out(print, "Version: %s\nBuilt  : %s\n", version_str, built_str);
		}
		print_out(print, "Type   : U-boot (%s)\n",
				uboot_type_to_str(ef_config.uboot_type));
		break;
	}

	return 0;
}

static int
call_qcsapi_wifi_get_vht(call_qcsapi_bundle *call, int argc, char *argv[])
{
	int rc = 0;
	int qcsapi_retval;

	qcsapi_unsigned_int	vht_status;
	qcsapi_output *print = call->caller_output;
	const char *the_interface = call->caller_interface;

	qcsapi_retval = qcsapi_wifi_get_vht( the_interface, &vht_status);
	if (qcsapi_retval >= 0) {
		print_out(print, "%d\n", vht_status);
	} else {
		report_qcsapi_error(call, qcsapi_retval);
		rc = 1;
	}

	return rc;
}

static int
call_qcsapi_calcmd_check_rfic_health(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	qcsapi_unsigned_int value;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_calcmd_check_rfic_health(&value);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
		    print_out(print, "%d\n", value);
			print_out(print, "Complete.\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_calcmd_set_test_mode(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int channel;
	int antenna ;
	int mcs;
	int bw;
	int pkt_size;
	int eleven_n;
	int primary_chan;
	if (argc < 7) {
		print_err( print, "Format: set_test_mode calcmd <channel> <antenna> <mcs> <bw> <packet size> <11n> <bf>\n");
		print_err( print, "Example: set_test_mode calcmd 36 127 7 40 40 1 1\n");
		return(1);
	}

	if (local_str_to_int32(argv[0], &channel, print, "channel number") < 0)
		return 1;

	if (local_str_to_int32(argv[1], &antenna, print, "antenna value") < 0)
		return 1;

	if (local_str_to_int32(argv[2], &mcs, print, "mcs value") < 0)
		return 1;

	if (local_str_to_int32(argv[3], &bw, print, "bandwidth value") < 0)
		return 1;

	if (local_str_to_int32(argv[4], &pkt_size, print, "packet size") < 0)
		return 1;

	if (local_str_to_int32(argv[5], &eleven_n, print, "11n enable/disable flag value") < 0)
		return 1;

	if (local_str_to_int32(argv[6], &primary_chan, print, "bf value") < 0)
		return 1;

	qcsapi_retval = qcsapi_calcmd_set_test_mode(channel, antenna, mcs, bw, pkt_size, eleven_n, primary_chan);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "Complete.\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}


static int
call_qcsapi_calcmd_show_test_packet(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	uint32_t txnum;
	uint32_t rxnum;
	uint32_t crc;

	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_calcmd_show_test_packet(&txnum, &rxnum, &crc);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "tx_pkts# = \t%d\nrx_pkts# = \t%d\nCRC_err# = \t%d\n", txnum, rxnum, crc);
			print_out(print, "Complete.\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}


static int
call_qcsapi_calcmd_send_test_packet(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	int packet_num;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Format: send_test_packet calcmd <pkt_num>\n");
		print_err( print, "Example: send_test_packet calcmd 0\n");
		return(1);
	}

	if (local_str_to_int32(argv[0], &packet_num, print, "packet number") < 0)
		return 1;

	qcsapi_retval = qcsapi_calcmd_send_test_packet(packet_num);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "Complete.\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return qcsapi_retval;
}

static int
call_qcsapi_calcmd_stop_test_packet(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_calcmd_stop_test_packet();
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "Complete.\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return qcsapi_retval;
}

static int
call_qcsapi_calcmd_send_dc_cw_signal(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	qcsapi_unsigned_int channel;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Format: send_dc_cw_signal calcmd <channel>\n");
		print_err( print, "Example: send_dc_cw_signal calcmd 36\n");
		return(1);
	}

	if (local_str_to_uint32(argv[0], &channel, print, "channel number") < 0)
		return 1;

	qcsapi_retval = qcsapi_calcmd_send_dc_cw_signal(channel);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "Complete.\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return qcsapi_retval;
}

static int
call_qcsapi_calcmd_stop_dc_cw_signal(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_calcmd_stop_dc_cw_signal();
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "Complete.\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return qcsapi_retval;
}

static int
call_qcsapi_calcmd_get_test_mode_antenna_sel(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	qcsapi_unsigned_int antenna;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_calcmd_get_test_mode_antenna_sel(&antenna);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%d\n", antenna);
			print_out(print, "Complete.\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return qcsapi_retval;
}

static int
call_qcsapi_calcmd_get_test_mode_mcs(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	qcsapi_unsigned_int mcs;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_calcmd_get_test_mode_mcs(&mcs);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%d\n", mcs);
			print_out(print, "Complete.\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return qcsapi_retval;
}

static int
call_qcsapi_calcmd_get_test_mode_bw(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	qcsapi_unsigned_int bw;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_calcmd_get_test_mode_bw(&bw);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%d\n", bw);
			print_out(print, "Complete.\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return qcsapi_retval;
}

static int
call_qcsapi_calcmd_get_tx_power(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	qcsapi_calcmd_tx_power_rsp tx_power;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_calcmd_get_tx_power(&tx_power);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%d.%ddBm %d.%ddBm %d.%ddBm %d.%ddBm\n",
				tx_power.value[0]>>2,(tx_power.value[0]&3)*25,
				tx_power.value[1]>>2,(tx_power.value[1]&3)*25,
				tx_power.value[2]>>2,(tx_power.value[2]&3)*25,
				tx_power.value[3]>>2,(tx_power.value[3]&3)*25);
			print_out(print, "Complete.\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return qcsapi_retval;
}

static int
call_qcsapi_calcmd_set_tx_power(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	qcsapi_unsigned_int tx_power;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err( print, "Format: set_test_mode_tx_power calcmd <tx_power>\n");
		print_err( print, "Example: set_test_mode_tx_power calcmd 19\n");
		return(1);
	}

	if (local_str_to_uint32(argv[0], &tx_power, print, "tx power value") < 0)
		return 1;

	qcsapi_retval = qcsapi_calcmd_set_tx_power(tx_power);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "Complete.\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return qcsapi_retval;
}


static int
call_qcsapi_calcmd_get_test_mode_rssi(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	qcsapi_calcmd_rssi_rsp rssi;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_calcmd_get_test_mode_rssi(&rssi);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%d.%d %d.%d %d.%d %d.%d\n",
				rssi.value[0]/10, rssi.value[0]%10,
				rssi.value[1]/10, rssi.value[1]%10,
				rssi.value[2]/10, rssi.value[2]%10,
				rssi.value[3]/10, rssi.value[3]%10);
			print_out(print, "Complete.\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return qcsapi_retval;
}

static int
call_qcsapi_calcmd_set_mac_filter(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	int sec_enable;
	int q_num;
	qcsapi_mac_addr mac_addr;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc != 3) {
		print_out(print, "Parameter input error! \n");
		print_out(print, "Format:\n");
		print_out(print, "call_qcsapi set_mac_filter wifi0 #q_num #sec_enable #mac_addr \n");
		print_out(print, "Example: call_qcsapi set_mac_filter wifi0 1 2 00:11:22:33:44:55\n");

		return qcsapi_retval;
	}

	if (local_str_to_int32(argv[0], &q_num, print, "queue number") < 0)
		return 1;

	if (local_str_to_int32(argv[1], &sec_enable, print, "flag") < 0)
		return 1;

	qcsapi_retval = parse_mac_addr(argv[2], mac_addr);
	if (qcsapi_retval >= 0) {
		qcsapi_retval = qcsapi_calcmd_set_mac_filter(q_num, sec_enable, mac_addr);
	}

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "Complete.\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		qcsapi_retval = 1;
	}

	return qcsapi_retval;
}

static int
call_qcsapi_calcmd_get_antenna_count(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	qcsapi_unsigned_int antenna_count;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_calcmd_get_antenna_count(&antenna_count);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%d\n", antenna_count);
			print_out(print, "Complete.\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return qcsapi_retval;
}

static int
call_qcsapi_calcmd_clear_counter(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_calcmd_clear_counter();
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "Complete.\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return qcsapi_retval;
}

static int
call_qcsapi_calcmd_get_info(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	qcsapi_output *print = p_calling_bundle->caller_output;
	string_1024 output_info = { 0 };

	qcsapi_retval = qcsapi_calcmd_get_info(output_info);
	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	print_out(print, "%s", output_info);

	return qcsapi_retval;
}

int
call_qcsapi_get_dfs_channels_status(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	qcsapi_unsigned_int	dfs_channels_status;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;

	qcsapi_retval = qcsapi_wifi_get_dfs_channels_status(the_interface, &dfs_channels_status);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%d\n", dfs_channels_status);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		qcsapi_retval = 1;
	}

	return qcsapi_retval;
}

int
call_qcsapi_disable_dfs_channels(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;
	int new_channel = 0;
	int scheme;

	if (argc < 1) {
		print_err(print, "usage:\ncall_qcsapi disable_dfs_channels <0|1> [new channel]\n");
		return 1;
	} else if (argc > 1) {
		if (local_str_to_int32(argv[1], &new_channel, print, "channel number") < 0)
			return 1;
	}

	if (local_str_to_int32(argv[0], &scheme, print, "value") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_disable_dfs_channels(the_interface, scheme, new_channel);
	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "complete\n" );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
	}

	return qcsapi_retval;
}

static int
call_qcsapi_wifi_set_soc_macaddr(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	qcsapi_mac_addr new_mac_addr;
	int		qcsapi_retval = 0;;
	int		ival = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char	*the_interface = p_calling_bundle->caller_interface;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi file path, count is %d\n", argc );
		statval = 1;
	}
	else
	{
		if (strcmp( "NULL", argv[ 0 ] ) == 0)
		{
			print_out( print, "Mac addr is NULL \n");
			statval = 1;
		}
		else
		{
			ival = parse_mac_addr( argv[ 0 ], new_mac_addr );
			if (ival >= 0)
			  qcsapi_retval = qcsapi_set_soc_mac_addr( the_interface, new_mac_addr );
			else
			{
				print_out( print, "Error parsing MAC address %s\n", argv[ 0 ] );
				statval = 1;
			}
		}

		if (ival >= 0)
		{
			if (qcsapi_retval >= 0)
			{
				if (verbose_flag >= 0)
				{
					print_out( print, "complete\n" );
				}
			}
			else
			{
				report_qcsapi_error( p_calling_bundle, qcsapi_retval );
				statval = 1;
			}
		}
	}

	return statval;

}

static int
call_qcsapi_wifi_enable_tdls(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint32_t enable_tdls = 1;

	if (argc > 0) {
		/*type conversion and parameter value check*/
		if (local_atou32_verify_numeric_range(argv[0], &enable_tdls, print, 0, 1) < 0)
			return 1;
	}

	qcsapi_retval = qcsapi_wifi_enable_tdls(the_interface, enable_tdls);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_enable_tdls_over_qhop(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint32_t tdls_over_qhop_en = 0;

	if (argc > 0) {
		/*type conversion and parameter value check*/
		if (local_atou32_verify_numeric_range(argv[0], &tdls_over_qhop_en, print, 0, 1) < 0)
			return 1;
	}

	qcsapi_retval = qcsapi_wifi_enable_tdls_over_qhop(the_interface, tdls_over_qhop_en);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int call_qcsapi_wifi_get_tdls_status(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	uint32_t tdls_status = 0;
	int32_t tdls_mode = 0;
	int32_t tdls_over_qhop_en = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_tdls_type type = qcsapi_tdls_nosuch_param;

	qcsapi_retval = qcsapi_wifi_get_tdls_status(the_interface, &tdls_status);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			if (tdls_status == 0)
				print_out(print, "tdls function: disabled\n");
			else
				print_out(print, "tdls function: enabled\n");
		}

		if(tdls_status != 0) {
			type = qcsapi_tdls_over_qhop_enabled;
			qcsapi_retval = qcsapi_wifi_get_tdls_params(the_interface, type, &tdls_over_qhop_en);

			if (qcsapi_retval >= 0) {
				if (verbose_flag >= 0)
					print_out(print, "tdls over qhop: %s\n", tdls_over_qhop_en ? "enabled" : "disabled");
			} else {
				report_qcsapi_error(p_calling_bundle, qcsapi_retval);
				statval = 1;
			}

			if (qcsapi_retval >= 0) {
				type = qcsapi_tdls_mode;
				qcsapi_retval = qcsapi_wifi_get_tdls_params(the_interface, type, &tdls_mode);

				if (qcsapi_retval >= 0) {
					if (verbose_flag >= 0)
						print_out(print, "tdls mode: %s\n", tdls_mode ? "forced" : "auto");
				} else {
					report_qcsapi_error(p_calling_bundle, qcsapi_retval);
					statval = 1;
				}
			}
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return (statval);
}

static int call_qcsapi_wifi_set_tdls_params(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_tdls_type type = p_calling_bundle->caller_generic_parameter.parameter_type.type_of_tdls;
	int value = 0;

	if (argc < 1) {
		print_err(print, "Not enough parameters, count is %d\n", argc);
		return 1;
	}

	if (local_str_to_int32(argv[0], &value, print, "parameter type") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_tdls_params(the_interface, type, value);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int call_qcsapi_wifi_get_tdls_params(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	uint32_t tdls_status = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_tdls_type type = 0;
	int value = 0;
	unsigned int iter;
	uint32_t param_num = 0;

	qcsapi_retval = qcsapi_wifi_get_tdls_status(the_interface, &tdls_status);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "tdls function: %s\n", tdls_status ? "enabled" : "disabled");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
		goto out;
	}

	param_num = TABLE_SIZE(qcsapi_tdls_param_table);
	for (iter = 0; iter < param_num; iter++) {
		type = qcsapi_tdls_param_table[iter].param_type;
		qcsapi_retval = qcsapi_wifi_get_tdls_params(the_interface, type, &value);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				if (type == qcsapi_tdls_over_qhop_enabled)
					print_out(print, "tdls over qhop: %s\n", value ? "enabled" : "disabled");
				else if (type == qcsapi_tdls_mode)
					print_out(print, "tdls mode: %s\n", value ? "forced" : "auto");
				else if((type >= qcsapi_tdls_min_rssi) && (type <= qcsapi_tdls_path_select_rate_thrshld))
					print_out(print, "\t%s: %d\n", qcsapi_tdls_param_table[iter].param_name, value);
				else
					print_out(print, "%s: %d\n", qcsapi_tdls_param_table[iter].param_name, value);
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
			goto out;
		}
	}
out:
	return (statval);
}

static int
call_qcsapi_get_carrier_id(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	qcsapi_unsigned_int carrier_id = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_get_carrier_id(&carrier_id);

	if (qcsapi_retval >= 0) {
		print_out( print, "%d\n", carrier_id);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_set_carrier_id(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint32_t carrier_id;
	uint32_t update_uboot = 0;

	if (argc < 1)
	{
		print_err( print, "Not enough parameters in call qcsapi set_carrier_id\n" );
		print_err( print, "Usage:  call_qcsapi set_carrier_id <carrier ID> <update uboot flag>\n");
		print_err( print, "        The second parameter is optional\n");
		print_err( print, "Example: call_qcsapi set_carrier_id 1\n");
		return 1;
	}

	if (local_str_to_uint32(argv[0], &carrier_id, print, "carrier id") < 0)
		return 1;

	/*
	 * The second parameter is optional and it indicates whether it is needed to update uboot.
	 * By default no update about uboot env. If the setting carrier ID is needed to write back into uboot
	 * this parameter is needed and should be set to 1.
	 */
	if ((argc > 1) && (local_str_to_uint32(argv[1], &update_uboot, print, "uboot update flag") < 0))
			return 1;

	qcsapi_retval = qcsapi_set_carrier_id(carrier_id, update_uboot);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out( print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_get_platform_id(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	qcsapi_unsigned_int platform_id = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_get_platform_id(&platform_id);

	if (qcsapi_retval >= 0) {
		print_out(print, "%d\n", platform_id);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_spinor_jedecid( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int statval = 0;
	unsigned int jedecid;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_spinor_jedecid( the_interface, &jedecid );

	if (qcsapi_retval >= 0)
	{
		if (verbose_flag >= 0)
		{
			print_out( print, "0x%08x\n", jedecid );
		}
	}
	else
	{
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_get_custom_value( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int statval = 0;
	int qcsapi_retval;
	qcsapi_output *print = p_calling_bundle->caller_output;
	char *key;
	char value[QCSAPI_CUSTOM_VALUE_MAX_LEN] = {'\0'};

	if (argc != 1) {
		print_err(print, "Usage: call_qcsapi get_custom_value <key>\n");
		return 1;
	}

	key = argv[0];
	qcsapi_retval = qcsapi_get_custom_value(key, value);

	if (qcsapi_retval >= 0) {
		print_out(print, "%s\n", value);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_custom_value( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int statval = 0;
	int qcsapi_retval;
	qcsapi_output *print = p_calling_bundle->caller_output;
	char *key;
	char *value;

	if (argc != 2) {
		print_err(print, "Usage: call_qcsapi set_custom_value <key> <value>\n");
		return 1;
	}

	key = argv[0];
	value = argv[1];
	qcsapi_retval = qcsapi_set_custom_value(key, value);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_vco_lock_detect_mode( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
        int statval = 0;
        int qcsapi_retval;
        qcsapi_output *print = p_calling_bundle->caller_output;
	const char              *the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int      vco_lock_detect_mode;

        if (argc != 1) {
                print_err(print, "Usage: call_qcsapi get_vco_lock_detect \n");
                return 1;
        }

        qcsapi_retval = qcsapi_wifi_get_vco_lock_detect_mode(the_interface, &vco_lock_detect_mode);

        if (qcsapi_retval >= 0) {
                print_out(print, "%d\n", vco_lock_detect_mode);
        } else {
                report_qcsapi_error(p_calling_bundle, qcsapi_retval);
                statval = 1;
        }

        return statval;
}

static int
call_qcsapi_wifi_set_vco_lock_detect_mode(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{

        int     statval = 0;
        qcsapi_output *print = p_calling_bundle->caller_output;

        if (argc < 1)
        {
                print_err( print, "Not enough parameters in call qcsapi WiFi set_vco_lock, count is %d\n", argc );
                statval = 1;
        }
        else
        {
                qcsapi_unsigned_int      vco_lock_detect_mode;
                int                      qcsapi_retval;
                const char              *the_interface = p_calling_bundle->caller_interface;

		if (local_str_to_uint32(argv[0], &vco_lock_detect_mode, print,
					"vco lock detect mode") < 0)
			return 1;

                qcsapi_retval = qcsapi_wifi_set_vco_lock_detect_mode(the_interface, &vco_lock_detect_mode );
                if (qcsapi_retval >= 0)
                {
                        if (verbose_flag >= 0)
                        {
                                print_out( print, "complete\n" );
                        }
                }
                else
                {
                        report_qcsapi_error( p_calling_bundle, qcsapi_retval );
                        statval = 1;
                }
        }

        return( statval );
}

static int
call_qcsapi_wifi_get_mlme_stats_per_mac(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	qcsapi_mac_addr the_mac_addr;
	qcsapi_mlme_stats stats;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc >= 1 && strcmp(argv[0], "NULL") != 0) {
		if (parse_mac_addr(argv[0], the_mac_addr) < 0) {
			print_out(print, "Error parsing MAC address %s\n", argv[0]);
			return 1;
		}
	} else {
		memset(the_mac_addr, 0x00, sizeof(the_mac_addr));
	}

	qcsapi_retval = qcsapi_wifi_get_mlme_stats_per_mac(the_mac_addr, &stats);

	if (qcsapi_retval >= 0) {
		print_out(print,
				  "auth:\t\t%u\n"
				  "auth_fails:\t%u\n"
				  "assoc:\t\t%u\n"
				  "assoc_fails:\t%u\n"
				  "deauth:\t\t%u\n"
				  "diassoc:\t%u\n",
				  stats.auth,
				  stats.auth_fails,
				  stats.assoc,
				  stats.assoc_fails,
				  stats.deauth,
				  stats.diassoc);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}
static int
call_qcsapi_wifi_get_mlme_stats_per_association(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	qcsapi_mlme_stats stats;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int association_index = p_calling_bundle->caller_generic_parameter.index;

	qcsapi_retval = qcsapi_wifi_get_mlme_stats_per_association(the_interface, association_index, &stats);

	if (qcsapi_retval >= 0) {
		print_out(print,
				  "auth:\t\t%u\n"
				  "auth_fails:\t%u\n"
				  "assoc:\t\t%u\n"
				  "assoc_fails:\t%u\n"
				  "deauth:\t\t%u\n"
				  "diassoc:\t%u\n",
				  stats.auth,
				  stats.auth_fails,
				  stats.assoc,
				  stats.assoc_fails,
				  stats.deauth,
				  stats.diassoc);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_mlme_stats_macs_list(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_mlme_stats_macs mac_list;
	qcsapi_mac_addr terminator_addr;
	int i;

	memset(&terminator_addr, 0xFF, sizeof(terminator_addr));

	qcsapi_retval = qcsapi_wifi_get_mlme_stats_macs_list(&mac_list);

	if (qcsapi_retval >= 0) {
		for (i = 0;i < QCSAPI_MLME_STATS_MAX_MACS; ++i) {
			if (memcmp(mac_list.addr[i], terminator_addr, sizeof(qcsapi_mac_addr)) == 0) {
				break;
			}
			dump_mac_addr(print, mac_list.addr[i]);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_nss_cap(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_mimo_type modulation;
	int qcsapi_retval;
	unsigned int nss;

	modulation = p_calling_bundle->caller_generic_parameter.parameter_type.modulation;
	qcsapi_retval = qcsapi_wifi_get_nss_cap(p_calling_bundle->caller_interface,
						modulation, &nss);

	if (qcsapi_retval >= 0) {
		print_out(print, "%u\n", nss);
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_set_nss_cap(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *const print = p_calling_bundle->caller_output;
	qcsapi_mimo_type modulation;
	int retval = 0;

	modulation = p_calling_bundle->caller_generic_parameter.parameter_type.modulation;

	if (argc != 1) {
		print_err(print, "Usage: call_qcsapi set_nss_cap "
					"<WiFi interface> {ht|vht} <nss>\n");
		retval = 1;
	} else {
		qcsapi_unsigned_int nss;
		int qcsapi_retval;

		if (local_str_to_uint32(argv[0], &nss, print, "nss value") < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_set_nss_cap(p_calling_bundle->caller_interface,
							modulation, nss);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out(print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			retval = 1;
		}
	}

	return retval;
}

static int
call_qcsapi_wifi_get_rx_nss_cap(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_mimo_type modulation;
	int qcsapi_retval;
	unsigned int nss;

	modulation = p_calling_bundle->caller_generic_parameter.parameter_type.modulation;
	qcsapi_retval = qcsapi_wifi_get_rx_nss_cap(p_calling_bundle->caller_interface,
						modulation, &nss);

	if (qcsapi_retval >= 0) {
		print_out(print, "%u\n", nss);
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_set_rx_nss_cap(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *const print = p_calling_bundle->caller_output;
	qcsapi_mimo_type modulation;
	int retval = 0;

	modulation = p_calling_bundle->caller_generic_parameter.parameter_type.modulation;

	if (argc != 1) {
		print_err(print, "Usage: call_qcsapi set_rx_nss_cap "
					"<WiFi interface> {ht|vht} <nss>\n");
		retval = 1;
	} else {
		qcsapi_unsigned_int nss;
		int qcsapi_retval;

		if (local_str_to_uint32(argv[0], &nss, print, "nss value") < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_set_rx_nss_cap(p_calling_bundle->caller_interface,
							modulation, nss);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out(print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			retval = 1;
		}
	}

	return retval;
}

static int
call_qcsapi_wifi_get_security_defer_mode(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval;
	int defer;

	qcsapi_retval = qcsapi_wifi_get_security_defer_mode(p_calling_bundle->caller_interface, &defer);

	if (qcsapi_retval >= 0) {
		print_out(print, "%d\n", defer);
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_set_security_defer_mode(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *const print = p_calling_bundle->caller_output;
	int retval = 0;

	if (argc != 1) {
		print_err(print, "Usage: call_qcsapi set_defer "
					"wifi0 {0|1}\n");
		retval = 1;
	} else {
		int defer;
		int qcsapi_retval;

		if (local_str_to_int32(argv[0], &defer, print, "defer mode value") < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_set_security_defer_mode(p_calling_bundle->caller_interface, defer);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out(print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			retval = 1;
		}
	}

	return retval;
}

static int
call_qcsapi_wifi_apply_security_config(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *const print = p_calling_bundle->caller_output;
	int retval = 0;

	if (argc != 0) {
		print_err(print, "Usage: call_qcsapi apply_security_config "
					"<WiFi interface>\n");
		retval = 1;
	} else {
		int qcsapi_retval = 0;

		qcsapi_retval = qcsapi_wifi_apply_security_config(p_calling_bundle->caller_interface);
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out(print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			retval = 1;
		}
	}

	return retval;
}

static int
call_qcsapi_wifi_reload_security_config(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *const print = p_calling_bundle->caller_output;
	int retval = 0;

	if (argc != 0) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface>\n");
		retval = 1;
	} else {
		int qcsapi_retval = 0;

		qcsapi_retval = qcsapi_wifi_reload_security_config(p_calling_bundle->caller_interface);
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out(print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			retval = 1;
		}
	}

	return retval;
}

static int
call_qcsapi_wifi_set_intra_bss_isolate(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint8_t enable;

	if (argc < 1) {
		print_err(print, "Not enough parameters, count is %d\n", argc);
		return 1;
	}

	if (local_verify_enable_or_disable(argv[0], &enable, print) < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_intra_bss_isolate(the_interface, enable);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_intra_bss_isolate(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int enable;

	qcsapi_retval = qcsapi_wifi_get_intra_bss_isolate(the_interface, &enable);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%u\n", enable);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_bss_isolate(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint8_t enable;

	if (argc < 1) {
		print_err(print, "Not enough parameters, count is %d\n", argc);
		return 1;
	}

	if (local_verify_enable_or_disable(argv[0], &enable, print) < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_bss_isolate(the_interface, enable);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_bss_isolate(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int enable;

	qcsapi_retval = qcsapi_wifi_get_bss_isolate(the_interface, &enable);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%u\n", enable);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_host_state_set(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	uint32_t host_state;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err(print, "not enough params\n");
		print_err(print, "Usage: call_qcsapi wowlan_host_state "
					"<WiFi interface> {0|1}\n");
		return 1;
	}

	if (local_str_to_uint32(argv[0], &host_state, print, "host state value") < 0)
		return 1;

	qcsapi_retval = qcsapi_set_host_state(the_interface, host_state);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_host_state_get(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t host_state;
	qcsapi_unsigned_int host_state_len = sizeof(host_state);

	qcsapi_retval = qcsapi_wifi_wowlan_get_host_state(the_interface, &host_state, &host_state_len);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%u\n", host_state);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_wowlan_match_type_set(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	uint32_t wowlan_match;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err(print, "not enough params\n");
		print_err(print, "Usage: call_qcsapi wowlan_match_type "
					"<WiFi interface> <protocol> "
					"protocol should be 0, 1(L2) or 2(L3) "
					"0 means match standard magic L2 type(0x0842) or L3 UDP destination port(7 or 9)\n");
		return 1;
	}

	if (local_str_to_uint32(argv[0], &wowlan_match, print, "protocol value") < 0)
		return 1;

	qcsapi_retval = qcsapi_wowlan_set_match_type(the_interface, wowlan_match);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_wowlan_match_type_get(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t match_type;
	qcsapi_unsigned_int len = sizeof(match_type);

	qcsapi_retval = qcsapi_wifi_wowlan_get_match_type(the_interface, &match_type, &len);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%u\n", match_type);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}
static int
call_qcsapi_wifi_wowlan_L2_type_set(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	uint32_t ether_type;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err(print, "not enough params\n");
		print_err(print, "Usage: call_qcsapi wowlan_L2_type "
					"<WiFi interface> <Ether type>\n");
		return 1;
	}

	if (local_str_to_uint32(argv[0], &ether_type, print, "ether type value") < 0)
		return 1;

	qcsapi_retval = qcsapi_wowlan_set_L2_type(the_interface, ether_type);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_wowlan_L2_type_get(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t l2_type;
	qcsapi_unsigned_int len = sizeof(l2_type);

	qcsapi_retval = qcsapi_wifi_wowlan_get_l2_type(the_interface, &l2_type, &len);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%u\n", l2_type);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}
static int
call_qcsapi_wifi_wowlan_udp_port_set(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	uint32_t udp_port;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err(print, "not enough params\n");
		print_err(print, "Usage: call_qcsapi wowlan_udp_port "
					"<WiFi interface> <udp port>\n");
		return 1;
	}

	if (local_str_to_uint32(argv[0], &udp_port, print, "udp port value") < 0)
		return 1;

	qcsapi_retval = qcsapi_wowlan_set_udp_port(the_interface, udp_port);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return( statval );
}

static int
call_qcsapi_wifi_wowlan_udp_port_get(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t udp_port;
	qcsapi_unsigned_int len = sizeof(udp_port);

	qcsapi_retval = qcsapi_wifi_wowlan_get_udp_port(the_interface, &udp_port, &len);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%u\n", udp_port);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}
#define MAX_USER_DEFINED_MAGIC	256
void str_to_hex(uint8_t *pbDest, const char *pbSrc, int nLen)
{
	char h1,h2;
	uint8_t s1,s2;
	int i;

	for (i = 0; i < nLen; i++)
	{
		h1 = pbSrc[2*i];
		h2 = pbSrc[2*i+1];

		s1 = toupper(h1) - 0x30;
		if (s1 > 9)
		s1 -= 7;

		s2 = toupper(h2) - 0x30;
		if (s2 > 9)
			s2 -= 7;

		pbDest[i] = s1*16 + s2;
	}
}

int get_pattern_string(const char *arg, uint8_t *pattern)
{
	int loop = 0;
	int num = 0;
	int pattern_len = strnlen(arg, MAX_USER_DEFINED_MAGIC<<1);

	while (loop < pattern_len) {
		if (isxdigit(arg[loop]) && isxdigit(arg[loop+1])) {
			str_to_hex(&pattern[num], &arg[loop], 1);
			num++;
			loop += 2;
		} else {
			loop++;
		}
	}
	return num;
}

static int
call_qcsapi_wifi_wowlan_pattern_set(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint8_t pattern[MAX_USER_DEFINED_MAGIC];
	struct qcsapi_data_256bytes pattern_data;
	uint32_t input_string_len;
	uint32_t actual_string_len;

	if (argc < 1) {
		print_err(print, "not enough params\n");
		print_err(print, "Usage: call_qcsapi wowlan_pattern "
					"<WiFi interface> <pattern> "
					"pattern should be aabb0a0b and 256 bytes in total length\n");
		return 1;
	}

	memset(pattern, 0, MAX_USER_DEFINED_MAGIC);
	if ((input_string_len = strnlen(argv[0], (MAX_USER_DEFINED_MAGIC<<1)+1)) > (MAX_USER_DEFINED_MAGIC<<1)) {
		print_err(print, "pattern should be 256 bytes in total length\n");
		return 1;
	}

	actual_string_len = get_pattern_string(argv[0], pattern);
	if (actual_string_len != (input_string_len>>1)) {
		print_err(print, "there are unrecognized chars\n");
		return 1;
	}

	memset(&pattern_data, 0, sizeof(pattern_data));
	memcpy(pattern_data.data, pattern, actual_string_len);
	qcsapi_retval = qcsapi_wowlan_set_magic_pattern(the_interface, &pattern_data, actual_string_len);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}
	return( statval );
}

static void
dump_magic_pattern(qcsapi_output *print, struct qcsapi_data_256bytes *magic_pattern, qcsapi_unsigned_int pattern_len)
{
	int i;

	for (i = 0; i < pattern_len; i++) {
		print_out(print, "%02X", magic_pattern->data[i]);
	}
	print_out(print, "\n");
}

static int
call_qcsapi_wifi_wowlan_pattern_get(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	struct qcsapi_data_256bytes magic_pattern;
	qcsapi_unsigned_int pattern_len = sizeof(magic_pattern);

	memset(&magic_pattern, 0, sizeof(magic_pattern));
	qcsapi_retval = qcsapi_wifi_wowlan_get_magic_pattern(the_interface, &magic_pattern, &pattern_len);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			dump_magic_pattern(print, &magic_pattern, pattern_len);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_tdls_operate(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_tdls_oper operate = p_calling_bundle->caller_generic_parameter.parameter_type.tdls_oper;
	int statval = 0;
	int qcsapi_retval = 0;
	int cs_interval = 0;

	if (operate == qcsapi_tdls_oper_switch_chan) {
		if (argc < 2) {
			print_err(print, "Not enough parameters, count is %d\n", argc);
			return 1;
		}

		if (local_str_to_int32(argv[1], &cs_interval, print, "cs interval value") < 0)
			return 1;
	} else {
		if (argc < 1) {
			print_err(print, "Not enough parameters, count is %d\n", argc);
			return 1;
		}
	}

	qcsapi_retval = qcsapi_wifi_tdls_operate(the_interface, operate, argv[0], cs_interval);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int call_qcsapi_wifi_set_extender_params(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_extender_type type = p_calling_bundle->caller_generic_parameter.parameter_type.type_of_extender;
	int value = 0;

	if (argc < 1) {
		print_err(print, "Not enough parameters\n");
		statval = 1;
		goto out;
	}

	switch (type) {
	case qcsapi_extender_role:
		if (strcasecmp(argv[0], "mbs") == 0) {
			value = IEEE80211_EXTENDER_ROLE_MBS;
		} else if (strcasecmp(argv[0], "rbs") == 0) {
			value = IEEE80211_EXTENDER_ROLE_RBS;
		} else if (strcasecmp(argv[0], "none") == 0) {
			value = IEEE80211_EXTENDER_ROLE_NONE;
		} else {
			print_err(print, "invalid role [%s]\n", argv[0]);
			statval = 1;
			goto out;
		}
		break;
	case qcsapi_extender_mbs_best_rssi:
	case qcsapi_extender_rbs_best_rssi:
	case qcsapi_extender_mbs_wgt:
	case qcsapi_extender_rbs_wgt:
	case qcsapi_extender_verbose:
	case qcsapi_extender_roaming:
	case qcsapi_extender_bgscan_interval:
	case qcsapi_extender_mbs_rssi_margin:
	case qcsapi_extender_short_retry_limit:
	case qcsapi_extender_long_retry_limit:
	case qcsapi_extender_scan_mbs_intvl:
	case qcsapi_extender_scan_mbs_expiry:
	case qcsapi_extender_scan_mbs_mode:
	case qcsapi_extender_fast_cac:
		if (sscanf(argv[0], "%d", &value) != 1) {
			print_err(print, "Error parsing '%s'\n", argv[0]);
			return 1;
		}
		break;
	default:
		statval = 1;
		goto out;
		break;
	}

	qcsapi_retval = qcsapi_wifi_set_extender_params(the_interface, type, value);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}
out:
	return statval;
}

static int
call_qcsapi_wifi_get_bgscan_status(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	int enable = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_bgscan_status(the_interface, &enable);

	if (qcsapi_retval >= 0) {
		print_out( print, "Bgscan enable: %d\n", enable);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_enable_bgscan(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint8_t enable = 0;

	if (argc < 1) {
		print_err(print, "Not enough parameters, count is %d\n", argc);
		return 1;
	}

	if (local_verify_enable_or_disable(argv[0], &enable, print) < 0)
                return 1;

	qcsapi_retval = qcsapi_wifi_enable_bgscan(the_interface, enable);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static void
print_extender_params(qcsapi_extender_type type, int value, qcsapi_output *print,
	int iter)
{
	char *role = NULL;
	if (type == qcsapi_extender_role) {
		switch(value) {
		case IEEE80211_EXTENDER_ROLE_NONE:
			role = "NONE";
			break;
		case IEEE80211_EXTENDER_ROLE_MBS:
			role = "MBS";
			break;
		case IEEE80211_EXTENDER_ROLE_RBS:
			role = "RBS";
			break;
		default:
			break;
		}
		print_out(print, "%s: %s\n",
			qcsapi_extender_param_table[iter].param_name, role);
	} else {
		print_out(print, "%s: %d\n",
			qcsapi_extender_param_table[iter].param_name, value);
	}
}

static void
print_eth_info(qcsapi_eth_info_type type, qcsapi_eth_info_result value, qcsapi_output *print)
{
	int iter;
	int mask = 0;

	for (iter = 0; iter < ARRAY_SIZE(qcsapi_eth_info_type_mask_table); iter++) {
		if (qcsapi_eth_info_type_mask_table[iter].type == type) {
			mask = qcsapi_eth_info_type_mask_table[iter].mask;
			break;
		}
	}

	for (iter = 0; iter < ARRAY_SIZE(qcsapi_eth_info_result_table); iter++) {
		if (!(mask & 1 << iter))
			continue;
		if (value & qcsapi_eth_info_result_table[iter].result_type) {
			if (qcsapi_eth_info_result_table[iter].result_bit_set) {
				print_out(print, "%s: %s\n",
					qcsapi_eth_info_result_table[iter].result_label,
					qcsapi_eth_info_result_table[iter].result_bit_set);
			}
		} else {
			if (qcsapi_eth_info_result_table[iter].result_bit_unset) {
				print_out(print, "%s: %s\n",
					qcsapi_eth_info_result_table[iter].result_label,
					qcsapi_eth_info_result_table[iter].result_bit_unset);
			}
		}
	}
}

static int
call_qcsapi_wifi_get_tx_amsdu(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int enable, qcsapi_retval;
	const char *wifi = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_tx_amsdu(wifi, &enable);

	if (qcsapi_retval >= 0) {
		print_out(print, "%d\n", enable);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_tx_amsdu(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	uint8_t enable;
	const char *wifi = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err(print, "Usage: call_qcsapi set_tx_amsdu "
				"<WiFi interface> { 0 | 1 }\n");
		return 1;
	}

	if (local_verify_enable_or_disable(argv[0], &enable, print) < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_tx_amsdu(wifi, enable);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_tx_max_amsdu(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	int max_len;
	const char *wifi = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_tx_max_amsdu(wifi, &max_len);

	if (qcsapi_retval >= 0) {
		print_out(print, "%d\n", max_len);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_tx_max_amsdu(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	int max_len;
	const char *wifi = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err(print, "Usage: call_qcsapi set_max_amsdu "
				"<WiFi interface> { 0 | 1 | 2 }\n");
		return 1;
	}

	if (local_str_to_int32(argv[0], &max_len, print, "max length value") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_tx_max_amsdu(wifi, max_len);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_beacon_power_backoff(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int power_backoff;

	qcsapi_retval = qcsapi_wifi_get_beacon_power_backoff(the_interface, &power_backoff);

	if (qcsapi_retval >= 0) {
		print_out(print, "%u\n", power_backoff);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_set_beacon_power_backoff(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int power_backoff;
	const char *usage = "<WiFi interface> <backoff in dB>";

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return 1;
	}

	power_backoff = (qcsapi_unsigned_int)atoi(argv[0]);
	qcsapi_retval = qcsapi_wifi_set_beacon_power_backoff(the_interface, power_backoff);
	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_get_mgmt_power_backoff(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int power_backoff;

	qcsapi_retval = qcsapi_wifi_get_mgmt_power_backoff(the_interface, &power_backoff);

	if (qcsapi_retval >= 0) {
		print_out(print, "%u\n", power_backoff);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_set_mgmt_power_backoff(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int power_backoff;

	if (argc != 1)
		goto usage;

	power_backoff = (qcsapi_unsigned_int)atoi(argv[0]);
	qcsapi_retval = qcsapi_wifi_set_mgmt_power_backoff(the_interface, power_backoff);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;

usage:
	qcsapi_report_usage(p_calling_bundle, "<interface> <backoff in dB>\n");
	return 1;
}

static int
call_qcsapi_wifi_get_extender_status(call_qcsapi_bundle *p_calling_bundle,
	int argc, char *argv[])
{
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_extender_type type = 0;
	int value = 0;
	unsigned int iter;

	for (iter = 0; iter < ARRAY_SIZE(qcsapi_extender_param_table); iter++) {
		type = qcsapi_extender_param_table[iter].param_type;
		if (type == qcsapi_extender_nosuch_param)
			continue;
		qcsapi_retval = qcsapi_wifi_get_extender_params(the_interface,
			type, &value);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_extender_params(type, value, print, iter);
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			return 1;
		}
	}

	return 0;
}

static int
call_qcsapi_wifi_set_extender_key(call_qcsapi_bundle *p_calling_bundle,
	int argc, char *argv[])
{
	int qcsapi_retval;
	qcsapi_mac_addr mac_addr = { 0 };
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc >= 1) {
		qcsapi_retval = parse_mac_addr(argv[0], mac_addr);
		if (qcsapi_retval < 0) {
			print_out(print, "Error parsing MAC address %s\n", argv[0]);
			return 1;
		}
	}

	qcsapi_retval = qcsapi_wifi_set_extender_key(the_interface, mac_addr);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
		      print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_get_autochan_input_format_ext(call_qcsapi_bundle *p_calling_bundle,
	qcsapi_autochan_type type, int *retval,
	int argc, char *argv[])
{
	if (type == qcsapi_autochan_chan_weights) {
		*retval = call_qcsapi_wifi_get_autochan_weights(p_calling_bundle, argc, argv);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_get_autochan_params(call_qcsapi_bundle *p_calling_bundle,
	int argc, char *argv[])
{
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_autochan_type type = 0;
	int value = 0;
	unsigned int i;

	for (i = 0; qcsapi_autochan_param_table[i].param_name != NULL; i++) {
		type = qcsapi_autochan_param_table[i].param_type;

		if (call_qcsapi_wifi_get_autochan_input_format_ext(p_calling_bundle,
					type, &qcsapi_retval, argc, argv)) {
			continue;
		}

		qcsapi_retval = qcsapi_wifi_get_autochan_params(the_interface,
			type, &value);

		if (qcsapi_retval >= 0) {
			print_out(print, "%s: %d\n",
				qcsapi_autochan_param_table[i].param_name, value);
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			return 1;
		}
	}

	return 0;
}

static int
call_qcsapi_wifi_set_autochan_exceptions(call_qcsapi_bundle *p_calling_bundle,
	qcsapi_autochan_type type, int *retval,
	int argc, char *argv[])
{
	if (type == qcsapi_autochan_chan_weights) {
		*retval = call_qcsapi_wifi_set_autochan_weight(p_calling_bundle, argc, argv);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_set_autochan_params(call_qcsapi_bundle *p_calling_bundle,
	int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_autochan_type type =
		p_calling_bundle->caller_generic_parameter.parameter_type.autochan_type;
	int value = 0;

	if (call_qcsapi_wifi_set_autochan_exceptions(p_calling_bundle,
				type, &qcsapi_retval, argc, argv)) {
		return qcsapi_retval;
	}

	if (sscanf(argv[0], "%d", &value) != 1) {
		print_err(print, "Error parsing '%s'\n", argv[0]);
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_autochan_params(the_interface, type, value);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_update_autochan_params(call_qcsapi_bundle *p_calling_bundle,
	int argc, char *argv[])
{
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	char *parameter_name = argv[0];
	char *parameter_value = argv[1];
	int qcsapi_retval = 0;
	int statval = 0;

	if (argc < 2) {
		print_err( print, "Not enough parameters in call_qcsapi"
			" update_autochan_params, count is %d\n", argc);
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface>"
			" <parameter name> <value>");
		return 1;
	}

	if (strcmp(parameter_name, "NULL") == 0) {
		parameter_name = NULL;
	}

	if (strcmp(parameter_value, "NULL") == 0) {
		parameter_value = NULL;
	}

	qcsapi_retval = qcsapi_wifi_update_autochan_params(the_interface,
				parameter_name, parameter_value);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_is_startprod_done(call_qcsapi_bundle *p_calling_bundle,
	int argc, char *argv[])
{
    int qcsapi_retval=0;
    int status=0;

    qcsapi_output *print = p_calling_bundle->caller_output;

    qcsapi_retval = qcsapi_is_startprod_done(&status);

    if (qcsapi_retval < 0) {
        report_qcsapi_error(p_calling_bundle, qcsapi_retval);
        return 1;
    }

    if (verbose_flag >= 0) {
        print_out(print, "%d\n",status);
    }

    return 0;
}

static int
call_qcsapi_wifi_get_disassoc_reason(call_qcsapi_bundle *call, int argc, char *argv[])
{
        int rc = 0;
        int qcsapi_retval;

        qcsapi_unsigned_int     disassoc_reason;
        qcsapi_output *print = call->caller_output;
        const char *the_interface = call->caller_interface;

        qcsapi_retval = qcsapi_wifi_get_disassoc_reason( the_interface, &disassoc_reason);
        if (qcsapi_retval >= 0) {
		if (disassoc_reason <= ARRAY_SIZE(qcsapi_disassoc_reason_list)) {
			print_out(print,"Disassoc Reason Code - %d: %s\n", disassoc_reason, qcsapi_disassoc_reason_list[disassoc_reason].reason_string);
		} else {
			print_out(print,"Reserved Code [%d]", disassoc_reason);
		}
        } else {
                report_qcsapi_error(call, qcsapi_retval);
                rc = 1;
        }

        return rc;
}

static int
call_qcsapi_wifi_get_bb_param( const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
        int statval = 0;
        int qcsapi_retval;
        qcsapi_output *print = p_calling_bundle->caller_output;
	const char              *the_interface = p_calling_bundle->caller_interface;
	qcsapi_unsigned_int      bb_param;

        qcsapi_retval = qcsapi_wifi_get_bb_param(the_interface, &bb_param);

        if (qcsapi_retval >= 0) {
                print_out(print, "%d\n", bb_param);
        } else {
                report_qcsapi_error(p_calling_bundle, qcsapi_retval);
                statval = 1;
        }

        return statval;
}

static int
call_qcsapi_wifi_set_bb_param(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{

        int     statval = 0;
        qcsapi_output *print = p_calling_bundle->caller_output;

        if (argc < 1)
        {
                print_err( print, "Not enough parameters in call qcsapi WiFi bb_param, count is %d\n", argc );
                statval = 1;
        }
        else
        {
                qcsapi_unsigned_int      bb_param;
                int                      qcsapi_retval;
                const char              *the_interface = p_calling_bundle->caller_interface;

		if (local_str_to_uint32(argv[0], &bb_param, print, "bb parameter value") < 0)
			return 1;

                qcsapi_retval = qcsapi_wifi_set_bb_param(the_interface, bb_param);
                if (qcsapi_retval >= 0)
                {
                        if (bb_param >= 0)
                        {
                                print_out( print, "complete\n" );
                        }
                }
                else
                {
                        report_qcsapi_error(p_calling_bundle, qcsapi_retval );
                        statval = 1;
                }
        }

        return( statval );
}

static int
call_qcsapi_wifi_set_scan_buf_max_size(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int max_buf_size;

	if (argc < 1) {
		print_err(print, "Not enough parameters, count is %d\n", argc);
		return 1;
	}

	if (local_str_to_uint32(argv[0], &max_buf_size, print, "buffer size") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_scan_buf_max_size(the_interface, max_buf_size);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_scan_buf_max_size(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int max_buf_size;

	qcsapi_retval = qcsapi_wifi_get_scan_buf_max_size(the_interface, &max_buf_size);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%u\n", max_buf_size);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_scan_table_max_len(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int max_table_len;

	if (argc < 1) {
		print_err(print, "Not enough parameters, count is %d\n", argc);
		return 1;
	}

	if (local_str_to_uint32(argv[0], &max_table_len, print, "max table length") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_scan_table_max_len(the_interface, max_table_len);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_scan_table_max_len(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int max_table_len;

	qcsapi_retval = qcsapi_wifi_get_scan_table_max_len(the_interface, &max_table_len);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%u\n", max_table_len);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_enable_mu(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint8_t mu_enable;

	if (argc < 1 || strcmp(argv[0], "NULL") == 0) {
		print_err(print, "Not enough parameters, count is %d\n", argc);
		return 1;
	}

	if (local_verify_enable_or_disable(argv[0], &mu_enable, print) < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_enable_mu(the_interface, mu_enable);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	} else if (verbose_flag >= 0) {
		qcsapi_retval = qcsapi_config_update_parameter(the_interface, "mu", argv[0]);
		print_out(print, "complete\n");
	}

	return statval;
}

static int
call_qcsapi_wifi_get_enable_mu(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int mu_enable;

	qcsapi_retval = qcsapi_wifi_get_enable_mu(the_interface, &mu_enable);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	} else if (verbose_flag >= 0) {
		print_out(print, "%u\n", mu_enable);
	}

	return statval;
}

static int
call_qcsapi_wifi_set_mu_use_precode(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int prec_enable;
	qcsapi_unsigned_int grp;

	if (argc < 2 || strcmp(argv[1], "NULL") == 0 || strcmp(argv[0], "NULL") == 0) {
		print_err(print, "Not enough parameters, count is %d\n", argc);
		return 1;
	}

	if (local_str_to_uint32(argv[0], &grp, print, "group number") < 0)
		return 1;

	if (local_str_to_uint32(argv[1], &prec_enable, print, "precode enable/disable value") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_mu_use_precode(the_interface, grp, prec_enable);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	} else if (verbose_flag >= 0) {
		print_out(print, "complete\n");
	}

	return statval;
}

static int
call_qcsapi_wifi_get_mu_use_precode(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int prec_enable;
	qcsapi_unsigned_int grp;

	if (argc < 1 || strcmp(argv[0], "NULL") == 0) {
		print_err(print, "Not enough parameters, count is %d\n", argc);
		return 1;
	}

	if (local_str_to_uint32(argv[0], &grp, print, "group number") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_get_mu_use_precode(the_interface, grp, &prec_enable);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	} else if (verbose_flag >= 0) {
		print_out(print, "%u\n", prec_enable);
	}

	return statval;
}

static int
call_qcsapi_wifi_set_mu_use_eq(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int eq_enable;

	if (argc < 1 || strcmp(argv[0], "NULL") == 0) {
		print_err(print, "Not enough parameters, count is %d\n", argc);
		return 1;
	}

	if (local_str_to_uint32(argv[0], &eq_enable, print, "eq enable/disable value") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_mu_use_eq(the_interface, eq_enable);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	} else if (verbose_flag >= 0) {
		print_out(print, "complete\n");
	}

	return statval;
}

static int
call_qcsapi_wifi_get_mu_use_eq(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int eq_enable;

	qcsapi_retval = qcsapi_wifi_get_mu_use_eq(the_interface, &eq_enable);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	} else if (verbose_flag >= 0) {
		print_out(print, "%u\n", eq_enable);
	}

	return statval;
}

static int
call_qcsapi_wifi_get_mu_groups(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	char buf[1024];

	qcsapi_retval = qcsapi_wifi_get_mu_groups(the_interface, &buf[0], sizeof(buf));

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	} else if (verbose_flag >= 0) {
		print_out(print, "%s", buf);
	}

	return statval;
}

static int
call_qcsapi_wifi_set_optim_stats(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
        int     statval = 0;
        qcsapi_output *print = p_calling_bundle->caller_output;

        if (argc < 1)
        {
                print_err( print, "Not enough parameters in call qcsapi WiFi set_optim_stats, count is %d\n", argc );
                statval = 1;
        }
        else
        {
                qcsapi_unsigned_int      rx_optim_stats;
                int                      qcsapi_retval;
                const char              *the_interface = p_calling_bundle->caller_interface;

		if (local_str_to_uint32(argv[0], &rx_optim_stats, print,
				"rx optim stats value") < 0)
			return 1;

                qcsapi_retval = qcsapi_wifi_set_optim_stats(the_interface, rx_optim_stats);
                if (qcsapi_retval >= 0)
                {
			print_out( print, "complete\n" );
                }
                else
                {
                        report_qcsapi_error(p_calling_bundle, qcsapi_retval );
                        statval = 1;
                }
        }

        return( statval );
}

static int call_qcsapi_send_file(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *image_file_path = NULL;
	int image_flags = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc != 1 && argc != 2) {
		print_err(print, "Usage: call_qcsapi send_file <image file path> <flags>\n");
		statval = 1;
	} else {
		if (strcmp(argv[0], "NULL") != 0) {
			image_file_path = argv[0];

			qcsapi_retval = qcsapi_send_file(image_file_path, image_flags);
			if (qcsapi_retval < 0) {
				report_qcsapi_error(p_calling_bundle, qcsapi_retval);
				statval = 1;
			}
		} else {
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_dscp_fill(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 3) {
		statval = 1;
		print_err(print, "Usage: call_qcsapi dscp <fill> <emac0|emac1> <value>\n");
	}
	else {
		int qcsapi_retval;
		const char *eth_type = argv[1];
		const char *value = argv[2];

		if (strcmp(eth_type, "NULL") == 0) {
			eth_type = NULL;
		}
		if (strcmp(value, "NULL") == 0) {
			value = NULL;
		}

		qcsapi_retval = qcsapi_eth_dscp_map(qcsapi_eth_dscp_fill,
							eth_type,
							NULL,
							value,
							NULL,
							0);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out(print, "complete\n" );
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_dscp_poke(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 4) {
		print_err(print, "Usage: call_qcsapi dscp <poke> <emac0|emac1> <level> <value>\n");
		statval = 1;
	}
	else {
		int qcsapi_retval;
		const char *eth_type = argv[1];
		const char *level = argv[2];
		const char *value = argv[3];

		if (strcmp(eth_type, "NULL") == 0) {
			eth_type = NULL;
		}
		if (strcmp(level, "NULL") == 0) {
			level = NULL;
		}
		if (strcmp(value, "NULL") == 0) {
			value = NULL;
		}

		qcsapi_retval = qcsapi_eth_dscp_map(qcsapi_eth_dscp_poke,
							eth_type,
							level,
							value,
							NULL,
							0);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out(print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_dscp_dump(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	char buf[2048] = {0};
	char *eth_type = argv[1];

	if (strcmp(eth_type, "NULL") == 0) {
		eth_type = NULL;
	}

	qcsapi_retval = qcsapi_eth_dscp_map(qcsapi_eth_dscp_dump,
						eth_type,
						NULL,
						NULL,
						&buf[0],
						sizeof(buf));

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	} else if (verbose_flag >= 0) {
		print_out(print, "%s", buf);
	}

	return statval;
}

static int
call_qcsapi_get_emac_switch(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval = 0;
	char buf[2048] = {0};

	qcsapi_retval = qcsapi_get_emac_switch(buf);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	} else if (verbose_flag >= 0) {
		print_out(print, "%s\n", buf);
	}

	return statval;
}

static int
call_qcsapi_set_emac_switch(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval = 0;
	uint8_t value;

	if (local_verify_enable_or_disable(argv[0], &value, print) < 0)
		return 1;

	if (value == 0) {
		qcsapi_retval = qcsapi_set_emac_switch(qcsapi_emac_switch_enable);
	} else {
		qcsapi_retval = qcsapi_set_emac_switch(qcsapi_emac_switch_disable);
	}

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_eth_dscp_map(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err(print, "Usage: call_qcsapi dscp <fill|poke|dump>"
					" <emac0|emac1> [level] [value]\n");
		statval = 1;
	} else {
		char *param = argv[0];


		if (strcmp(param, "fill") == 0) {
			statval = call_qcsapi_dscp_fill(p_calling_bundle, argc, argv);
		} else if (strcmp(param, "poke") == 0) {
			statval = call_qcsapi_dscp_poke(p_calling_bundle, argc, argv);
		} else if (strcmp(param, "dump") == 0) {
			statval = call_qcsapi_dscp_dump(p_calling_bundle, argc, argv);
		} else {
			print_err(print, "Usage: call_qcsapi dscp <fill|poke|dump>"
						" <emac0|emac1> [level] [value]\n");
			statval = 1;
		}
	}

	return statval;
}
static int
call_qcsapi_wifi_set_pref_band(call_qcsapi_bundle *call, int argc, char *argv[])
{
	int rc = 0;
	qcsapi_output *print = call->caller_output;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call qcsapi wifi set_pref_band, count is %d\n", argc );
		print_err( print, "Usage: call_qcsapi set_pref_band <WiFi interface> <2.4ghz | 5ghz>\n" );
		rc = 1;
	} else {
		qcsapi_pref_band pref_band;
		const char *the_interface = call->caller_interface;
		int qcsapi_retval = 0;
		qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
		string_64 p_buffer;
		qcsapi_rf_chip_id rf_chipid;

		qcsapi_get_board_parameter(qcsapi_rf_chipid, p_buffer);
		rf_chipid = string_to_rf_chipid(p_buffer);
		qcsapi_wifi_get_mode(the_interface, &wifi_mode);
		/* Check operating mode is station and dual band is supported */
		if ( (wifi_mode != qcsapi_station) && (rf_chipid != CHIPID_DUAL) ) {
			print_out(print,"!!ERROR Mode should be station and Band should be Dual Band  \n");
			qcsapi_retval = -EINVAL;
		}

		pref_band = string_to_wifi_band(argv[0]);

		if ( (pref_band != qcsapi_band_2_4ghz) && (pref_band != qcsapi_band_5ghz) ) {
			print_out(print,"Please enter preferred band as 2.4ghz|5ghz\n");
		}

		if (qcsapi_retval >= 0) {
			qcsapi_retval = qcsapi_wifi_set_pref_band( the_interface, pref_band );
		}
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error( call, qcsapi_retval );
			rc = 1;
		}
	}
	return rc;
}

static int
call_qcsapi_wifi_get_pref_band(call_qcsapi_bundle *call, int argc, char *argv[])
{
	int rc = 0;
	int qcsapi_retval = 0;
	qcsapi_unsigned_int pref_band;
	qcsapi_output *print = call->caller_output;
	const char *the_interface = call->caller_interface;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	string_64 p_buffer;
	qcsapi_rf_chip_id rf_chipid;

	qcsapi_get_board_parameter(qcsapi_rf_chipid, p_buffer);
	rf_chipid = string_to_rf_chipid(p_buffer);
	qcsapi_wifi_get_mode(the_interface, &wifi_mode);

	/* Check operating mode is station and dual band is supported */
	if ( (wifi_mode != qcsapi_station) && (rf_chipid != CHIPID_DUAL) ) {
		print_out(print,"!!ERROR Mode should be station and Band should be Dual Band  \n");
		qcsapi_retval = -EINVAL;
	}

	if (qcsapi_retval >= 0)
		qcsapi_retval = qcsapi_wifi_get_pref_band( the_interface, &pref_band);

	if (qcsapi_retval >= 0) {
		if (pref_band == qcsapi_band_2_4ghz) {
			print_out(print, "Preferred Band Set - 2.4Ghz\n");
		} else if (pref_band == qcsapi_band_5ghz) {
			print_out(print, "Preferred Band Set - 5Ghz\n");
		}
	} else {
		report_qcsapi_error(call, qcsapi_retval);
		rc = 1;
	}

        return rc;
}


static int
call_qcsapi_set_sys_time(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint32_t sec;

	if (argc != 1) {
		print_err(print, "Usage: call_qcsapi set_sys_time <seconds since epoch>\n");
		return 1;
	}

	if (local_atou32_verify_numeric_range(argv[0], &sec, print, 1, (UINT32_MAX - 1)) < 0)
		return 1;

	statval = qcsapi_wifi_set_sys_time(sec);
	if (statval >= 0 && verbose_flag >= 0)
		print_out(print, "complete\n");
	else
		report_qcsapi_error(p_calling_bundle, statval);

	return statval;
}

static int
call_qcsapi_get_sys_time(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint32_t sec;

	if (argc != 0) {
		print_err(print, "Usage: call_qcsapi get_sys_time\n");
		return 1;
	}

	statval = qcsapi_wifi_get_sys_time(&sec);
	if (statval == 0) {
		print_out(print, "%u\n", sec);
	} else {
		report_qcsapi_error(p_calling_bundle, statval);
	}

	return statval;
}

static int
call_qcsapi_get_eth_info(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_eth_info_type	eth_info_type = qcsapi_eth_nosuch_type;
	qcsapi_eth_info_result	eth_info_result = qcsapi_eth_info_unknown;
	int			qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;

	if (argc != 0 && argc != 1) {
		print_err(print, "Usage: call_qcsapi get_eth_info <ifname> "
					"{ link | speed | duplex | autoneg }\n");
		return 1;
	}

	if (argc == 0) {
		for (eth_info_type = qcsapi_eth_info_start;
				eth_info_type < qcsapi_eth_info_all;
				eth_info_type++) {
			qcsapi_retval = qcsapi_get_eth_info(the_interface, eth_info_type);
			if (qcsapi_retval >= 0) {
				eth_info_result |= (qcsapi_eth_info_result)qcsapi_retval;
			} else {
				report_qcsapi_error(p_calling_bundle, qcsapi_retval);
				return 1;
			}
		}
		print_eth_info(eth_info_type, eth_info_result, print);
		return 0;
	}

	if (!strcmp("link", argv[0])) {
		eth_info_type = qcsapi_eth_info_link;
	} else if (!strcmp("speed", argv[0])) {
		eth_info_type = qcsapi_eth_info_speed;
	} else if (!strcmp("duplex", argv[0])) {
		eth_info_type = qcsapi_eth_info_duplex;
	} else if (!strcmp("autoneg", argv[0])) {
		eth_info_type = qcsapi_eth_info_autoneg;
	} else {
		print_out(print, "Invalid option\n");
		return 1;
	}

	qcsapi_retval = qcsapi_get_eth_info(the_interface, eth_info_type);
	if (qcsapi_retval >= 0) {
		print_eth_info(eth_info_type, qcsapi_retval, print);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_set_repeater_ifreset(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint32_t ifreset;
	const char *usage = "<WiFi interface> { 0 | 1 }";

	if (argc != 2) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return -EINVAL;
	}

	qcsapi_retval = qcsapi_wifi_verify_repeater_mode();

	if (qcsapi_retval != 1) {
		print_out(print, "Repeater config rejected - not in Repeater mode\n");
		return 1;
	}

	if (local_str_to_uint32(argv[1], &ifreset, print, "ifreset value") < 0)
		return -EINVAL;

	statval = qcsapi_wifi_set_repeater_ifreset(ifreset);

	if (statval < 0)
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);

	return statval;
}

static int
call_qcsapi_wifi_get_repeater_ifreset(call_qcsapi_bundle *p_calling_bundle,
			int argc, char *argv[])
{
	int qcsapi_retval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int ifreset;

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface>");
		return -EINVAL;
	}

	qcsapi_retval = qcsapi_wifi_verify_repeater_mode();

	if (qcsapi_retval != 1) {
		print_out(print, "Dev not in repeater mode\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_get_repeater_ifreset(&ifreset);
	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	} else
		print_out(print, "%d\n", ifreset);

	return 0;
}

static int
call_qcsapi_wifi_set_ap_interface_name(call_qcsapi_bundle *p_calling_bundle,
			int argc, char *argv[])
{
	int qcsapi_retval;
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc != 1) {
		print_out(print, "Usage: call_qcsapi "
					"set_ap_interface_name <interface name>\n");
		return -EINVAL;
	}

	qcsapi_retval = qcsapi_wifi_set_ap_interface_name(argv[0]);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_ap_interface_name(call_qcsapi_bundle *p_calling_bundle,
			int argc, char *argv[])
{
	int qcsapi_retval = 0;
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	char ifname[IFNAMSIZ] = {0};

	if (argc > 0) {
		print_out(print, "Usage: call_qcsapi "
					"get_ap_interface_name\n");
		return -EINVAL;
	}

	qcsapi_retval = qcsapi_wifi_get_ap_interface_name(ifname);
	if(qcsapi_retval >= 0) {
                print_out(print, "%s\n", ifname);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_verify_repeater_mode(call_qcsapi_bundle *p_calling_bundle,
			int argc, char *argv[])
{
	int qcsapi_retval = 0;
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc > 0) {
		print_out(print, "Usage: call_qcsapi "
					"verify_repeater_mode\n");
		return -EINVAL;
	}

	qcsapi_retval = qcsapi_wifi_verify_repeater_mode();
	if(qcsapi_retval >= 0) {
                print_out(print, "%d\n", qcsapi_retval);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_block_bss(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint8_t flag;
	const char		*the_interface = p_calling_bundle->caller_interface;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call_qcsapi block_bss\n" );
		print_err( print, "Usage:  call_qcsapi block_bss <WiFi interface> { 0 | 1 }\n");
		return 1;
	}

	if (local_verify_enable_or_disable(argv[0], &flag, print) < 0)
                return 1;

	qcsapi_retval = qcsapi_wifi_block_bss(the_interface, flag);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n" );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return (statval);
}

static int
call_qcsapi_wifi_get_block_bss(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char		*the_interface = p_calling_bundle->caller_interface;
	unsigned int value;

	if (argc != 0) {
		print_err( print, "Usage:  call_qcsapi get_block_bss <WiFi interface>\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_get_block_bss(the_interface, &value);
	if (qcsapi_retval >= 0) {
		print_out( print, "%u\n", value);
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return (statval);
}

static int
call_qcsapi_wifi_set_txba_disable(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval = 0;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	const char	*the_interface = p_calling_bundle->caller_interface;
	uint8_t value;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call_qcsapi set_txba_disable\n" );
		print_err( print, "Usage:  call_qcsapi txba_disable <WiFi interface> { 0 | 1 } \n");
		return 1;
	}

	if (local_verify_enable_or_disable(argv[0], &value, print) < 0)
                return 1;

	qcsapi_retval = qcsapi_wifi_set_txba_disable(the_interface, value);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n" );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return (statval);
}

static int
call_qcsapi_wifi_get_txba_disable(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	txba_disable_status;
	const char		*the_interface = p_calling_bundle->caller_interface;

	qcsapi_retval = qcsapi_wifi_get_txba_disable(the_interface, &txba_disable_status);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%d\n", txba_disable_status);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return (statval);
}

static int
call_qcsapi_wifi_set_rxba_decline(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval = 0;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	const char	*the_interface = p_calling_bundle->caller_interface;
	uint8_t value;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call_qcsapi set_rxba_decline\n" );
		print_err( print, "Usage:  call_qcsapi rxba_decline <WiFi interface> { 0 | 1 } \n");
		return 1;
	}

	if (local_verify_enable_or_disable(argv[0], &value, print) < 0)
                return 1;

	qcsapi_retval = qcsapi_wifi_set_rxba_decline(the_interface, value);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n" );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return (statval);
}

static int
call_qcsapi_wifi_get_rxba_decline(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	rxba_decline_status;
	const char		*the_interface = p_calling_bundle->caller_interface;

	qcsapi_retval = qcsapi_wifi_get_rxba_decline(the_interface, &rxba_decline_status);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%d\n", rxba_decline_status);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return (statval);
}

static int
call_qcsapi_wifi_set_txburst(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char		*the_interface = p_calling_bundle->caller_interface;
	uint8_t value;

	if (argc < 1) {
		print_err( print, "Not enough parameters in call_qcsapi set_txburst\n" );
		print_err( print, "Usage:  call_qcsapi set_txburst <WiFi interface> { 0 | 1 } \n");
		return 1;
	}

	if (local_verify_enable_or_disable(argv[0], &value, print) < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_txburst(the_interface, value);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n" );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return (statval);
}

static int
call_qcsapi_wifi_get_txburst(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int	flag;
	const char		*the_interface = p_calling_bundle->caller_interface;

	qcsapi_retval = qcsapi_wifi_get_txburst(the_interface, &flag);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%d\n", flag);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return (statval);
}

static int
call_qcsapi_wifi_get_sec_chan(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int chan, sec_chan, qcsapi_retval;
	const char *wifi = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err(print, "Usage: call_qcsapi get_sec_chan_offset "
				"<WiFi interface> <chan>\n");
		return 1;
	}

	if (local_atoi32_verify_numeric_range(argv[0], &chan, print, QCSAPI_MIN_CHANNEL,
			QCSAPI_MAX_CHANNEL) < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_get_sec_chan(wifi, chan, &sec_chan);

	if (qcsapi_retval >= 0) {
		print_out(print, "%d\n", sec_chan);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_sec_chan(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int statval = 0;
	int chan, offset, qcsapi_retval;
	const char *wifi = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 2) {
		print_err(print, "Usage: call_qcsapi set_sec_chan "
				"<WiFi interface> <chan> <offset>\n");
		return 1;
	}

	if (local_atoi32_verify_numeric_range(argv[0], &chan, print, QCSAPI_MIN_CHANNEL,
			QCSAPI_MAX_CHANNEL) < 0)
		return 1;

	if (local_str_to_int32(argv[1], &offset, print, "offset value") < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_sec_chan(wifi, chan, offset);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_set_vap_default_state(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint8_t value;

	if (argc < 1) {
		print_err( print, "Not enough parameters\n" );
		print_err( print, "Usage:  call_qcsapi set_vap_default_state { 0 | 1 }\n");
		return 1;
	}

	if (local_verify_enable_or_disable(argv[0], &value, print) < 0)
                return 1;

	qcsapi_retval = qcsapi_wifi_set_vap_default_state(value);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n" );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return (statval);
}

static int
call_qcsapi_get_vap_default_state(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval;
	int	vap_default_state;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_vap_default_state(&vap_default_state);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%d\n", vap_default_state);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return (statval);
}

static int
call_qcsapi_set_vap_state(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	const char	*the_interface = p_calling_bundle->caller_interface;
	uint8_t value;

	if (argc < 1) {
		print_err( print, "Not enough parameters\n" );
		print_err( print, "Usage:  call_qcsapi set_vap_state <WiFi interface> { 0 | 1 }\n");
		return 1;
	}

	if (local_verify_enable_or_disable(argv[0], &value, print) < 0)
                return 1;

	qcsapi_retval = qcsapi_wifi_set_vap_state(the_interface, value);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "complete\n" );
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return (statval);
}

static int
call_qcsapi_get_vap_state(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval;
	int	vap_state;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	const char	*the_interface = p_calling_bundle->caller_interface;

	qcsapi_retval = qcsapi_wifi_get_vap_state(the_interface, &vap_state);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out( print, "%d\n", vap_state);
		}
	} else {
		report_qcsapi_error( p_calling_bundle, qcsapi_retval );
		statval = 1;
	}

	return (statval);
}

/* this API is deprecated and replaced by dump_txrx_airtime_per_node_new */
static void
dump_txrx_airtime_per_node(qcsapi_output *print, uint32_t idx, qcsapi_node_txrx_airtime *nta)
{
	print_out(print, "%-17s %8s %8s %20s %8s %20s \n", "MAC address", "Idx", "Tx airtime",
				"Tx airtime accum", "Rx airtime", "Rx airtime accum");
	print_out(print, MACSTR" %8d %8d %20d %8d %20d\n", MAC2STR(nta->addr), idx,
						  nta->tx_airtime,
						  nta->tx_airtime_accum,
						  nta->rx_airtime,
						  nta->rx_airtime_accum);
}

static void
dump_txrx_airtime_buffer(qcsapi_output *print, const string_4096 buffer)
{
	struct node_txrx_airtime *p_node;
	struct txrx_airtime *p_airtime;
	int      i;

	p_airtime = (struct txrx_airtime *)buffer;

	print_out(print, "Free airtime: %8u\n", p_airtime->free_airtime);
	print_out(print, "%-17s %8s %8s %20s %8s %20s \n", "MAC address", "Idx", "Tx airtime",
		"Tx airtime total", "Rx airtime", "Rx airtime total");

	p_node = p_airtime->nodes;

	for (i = 0; i < p_airtime->nr_nodes; i++) {
		print_out(print, MACSTR" %8u %8u %20u %8u %20u\n",
				MAC2STR(p_node->macaddr), i,
			p_node->tx_airtime, p_node->tx_airtime_accum,
			p_node->rx_airtime, p_node->rx_airtime_accum);
		p_node++;
	}

	print_out(print, "\n%18s %8u\n", "Total Clients Tx Airtime:",
			p_airtime->total_cli_tx_airtime);
	print_out(print, "%18s %8u\n", "Total Clients Rx Airtime:",
			p_airtime->total_cli_rx_airtime);
}

static void
dump_txrx_airtime_per_node_new(qcsapi_output *print, uint32_t idx,
		struct qtn_nis_info_list_entry *nis_entry)
{
	QTN_NIS_CHILD_INIT(nis_entry);
	print_out(print, "%-17s %8s %8s %20s %8s %20s \n", "MAC address", "Idx", "Tx airtime",
			"Tx airtime accum", "Rx airtime", "Rx airtime accum");
	print_out(print, MACSTR" %8d %8d %20d %8d %20d\n",
			MAC2STR(nis_entry->macaddr), nis_entry->idx,
			QTN_NIS_CHILD_GET(0, tx_airtime),
			QTN_NIS_CHILD_GET(0, tx_airtime_accum),
			QTN_NIS_CHILD_GET(0, rx_airtime),
			QTN_NIS_CHILD_GET(0, rx_airtime_accum));
}

static void
dump_txrx_airtime_per_radio(qcsapi_output *print,  struct qtn_nis_info_list *nis)
{
	struct qtn_nis_info_list_entry *nis_entry;
	int i;

	nis_entry = nis->nodes;
	QTN_NIS_ROOT_INIT(nis);
	QTN_NIS_CHILD_INIT(nis_entry);

	print_out(print, "Free airtime: %8u\n", QTN_NIS_ROOT_GET(0, free_airtime));
	print_out(print, "%-17s %8s %8s %20s %8s %20s \n", "MAC address", "Idx", "Tx airtime",
		"Tx airtime total", "Rx airtime", "Rx airtime total");

	for (i = 0; i < nis->cnt; i++) {
		print_out(print, MACSTR" %8u %8u %20u %8u %20u\n",
			MAC2STR(nis_entry->macaddr), nis_entry->idx,
			QTN_NIS_SET_CHILD_FROM_ROOT(0, tx_airtime, nis, i),
			QTN_NIS_SET_CHILD_FROM_ROOT(0, tx_airtime_accum, nis, i),
			QTN_NIS_SET_CHILD_FROM_ROOT(0, rx_airtime, nis, i),
			QTN_NIS_SET_CHILD_FROM_ROOT(0, rx_airtime_accum, nis, i));
		nis_entry++;
	}

	print_out(print, "\n%18s %8u\n", "Total Clients Tx Airtime:",
				QTN_NIS_ROOT_GET(0, total_cli_tx_airtime));
	print_out(print, "%18s %8u\n", "Total Clients Rx Airtime:",
				QTN_NIS_ROOT_GET(0, total_cli_rx_airtime));
}

static int
call_qcsapi_wifi_get_txrx_airtime(call_qcsapi_bundle *p_calling_bundle,
		                int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *intf = p_calling_bundle->caller_interface;
	qcsapi_node_txrx_airtime nta;
	string_4096 buffer = { 0 };
	int qcsapi_retval;
	uint32_t idx = 0;
	int statval = 0;
	int for_all = 0;
	int control = 0;

	if (argc < 1) {
		print_err(print, "Not enough parameters in call_qcsapi get_tx_airtime\n");
		statval = 1;
		goto out_usage;
	}

	if (!strcmp(argv[0], "all")) {
		for_all = 1;
	} else {
		if (local_str_to_uint32(argv[0], &idx, print, "index") < 0) {
			statval = 1;
			goto out_usage;
		}
	}

	if (argc == 2) {
		if (!strcmp(argv[1], "start")) {
			control = qcsapi_accum_airtime_start;
		} else if (!strcmp(argv[1], "stop")) {
			control = qcsapi_accum_airtime_stop;
		} else {
			print_err(print, "The argument \"%s\" is invalid\n", argv[1]);
			statval = 1;
			goto out_usage;
		}
	}

	if (control) {
		if (for_all)
			qcsapi_retval = qcsapi_wifi_tx_airtime_accum_control(intf, control);
		else
			qcsapi_retval = qcsapi_wifi_node_tx_airtime_accum_control(intf, idx, control);
	} else {
		if (for_all)
			qcsapi_retval = qcsapi_wifi_get_txrx_airtime(intf, buffer);
		else
			qcsapi_retval = qcsapi_wifi_node_get_txrx_airtime(intf, idx, &nta);
	}

	if (qcsapi_retval >= 0) {
		if (control) {
			print_out(print, "complete\n");
		} else {
			if (for_all)
				dump_txrx_airtime_buffer(print, buffer);
			else
				dump_txrx_airtime_per_node(print, idx, &nta);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;

out_usage:
	print_err(print, "\nUsage: call_qcsapi get_tx_airtime <interface> <node_idx | all> [start | stop]\n");
	return statval;
}

static void
dump_tx_retries_per_node(qcsapi_output *print, uint32_t idx,
			struct qtn_nis_info_list_entry *nis_entry)
{
	QTN_NIS_CHILD_INIT(nis_entry);
	print_out(print, "%-17s %8s %16s\n", "MAC address", "Idx", "Tx accum retries");
	print_out(print, MACSTR" %8u %16u\n",
		MAC2STR(nis_entry->macaddr), nis_entry->idx,
		QTN_NIS_CHILD_GET(1, tx_retries_accum));
}

static void
dump_tx_retries_per_radio(qcsapi_output *print, struct qtn_nis_info_list *nis)
{
	struct qtn_nis_info_list_entry *nis_entry;
	int i;

	nis_entry = nis->nodes;
	QTN_NIS_ROOT_INIT(nis);
	QTN_NIS_CHILD_INIT(nis_entry);

	print_out(print, "%-17s %8s %16s\n", "MAC address", "Idx", "Tx accum retries");

	for (i = 0; i < nis->cnt; i++) {
		print_out(print, MACSTR" %8u %16u\n", MAC2STR(nis_entry->macaddr),
			nis_entry->idx,
			QTN_NIS_SET_CHILD_FROM_ROOT(1, tx_retries_accum, nis, i));
		nis_entry++;
	}

	print_out(print, "\n%18s %8u\n", "Total retries for all stations:",
			QTN_NIS_ROOT_GET(1, total_cli_tx_retries));
}

static void
dump_ip_addr_per_node(qcsapi_output *print, uint32_t idx,
			struct qtn_nis_info_list_entry *nis_entry)
{
	char addr_buf[IP_ADDR_STR_LEN] = {0};
	int ipaddr;

	QTN_NIS_CHILD_INIT(nis_entry);
	ipaddr = QTN_NIS_CHILD_GET(2, ip_addr);
	print_out(print, "%-17s %8s %16s\n", "MAC address", "Idx", "IP address");
	if (inet_ntop(AF_INET, &ipaddr, addr_buf, IP_ADDR_STR_LEN) != NULL)
		print_out(print, MACSTR" %8u %16s\n",
			MAC2STR(nis_entry->macaddr), nis_entry->idx, addr_buf);
	else
		print_out(print, MACSTR" %8u     -\n",
			MAC2STR(nis_entry->macaddr), nis_entry->idx);
}

static void
dump_ip_addr_per_radio(qcsapi_output *print, struct qtn_nis_info_list *nis)
{
	struct qtn_nis_info_list_entry *nis_entry;
	int i;

	nis_entry = nis->nodes;
	QTN_NIS_CHILD_INIT(nis_entry);

	print_out(print, "%-17s %8s %16s\n", "MAC address", "Idx", "IP address");

	for (i = 0; i < nis->cnt; i++) {
		char addr_buf[IP_ADDR_STR_LEN] = {0};
		int ipaddr;

		ipaddr = QTN_NIS_SET_CHILD_FROM_ROOT(2, ip_addr, nis, i);
		if (inet_ntop(AF_INET, &ipaddr, addr_buf, IP_ADDR_STR_LEN) != NULL)
			print_out(print, MACSTR" %8u %16s\n",
					MAC2STR(nis_entry->macaddr), nis_entry->idx, addr_buf);
		else
			print_out(print, MACSTR" %8u     -\n",
				MAC2STR(nis_entry->macaddr), nis_entry->idx);
		nis_entry++;
	}
}

static void
dump_node_stat_per_node(qcsapi_output *print, uint32_t idx,
		struct qtn_nis_info_list_entry* nis_entry, qcsapi_node_stat_e qstat_index)
{
	switch (qstat_index) {
	case QCSAPI_NODE_STAT_TXRX_AIRTIME:
		dump_txrx_airtime_per_node_new(print, idx, nis_entry);
		break;
	case QCSAPI_NODE_STAT_TX_RETRIES:
		dump_tx_retries_per_node(print, idx, nis_entry);
		break;
	case QCSAPI_NODE_STAT_IP_ADDR:
		dump_ip_addr_per_node(print, idx, nis_entry);
		break;
	default:
		print_out(print, "%s\n", "Unknown statistics type");
	}
}

static void
dump_node_stat_per_radio(qcsapi_output *print, struct qtn_nis_info_list *nis,
				qcsapi_node_stat_e qstat_index)
{
	switch (qstat_index) {
	case QCSAPI_NODE_STAT_TXRX_AIRTIME:
		dump_txrx_airtime_per_radio(print, nis);
		break;
	case QCSAPI_NODE_STAT_TX_RETRIES:
		dump_tx_retries_per_radio(print, nis);
		break;
	case QCSAPI_NODE_STAT_IP_ADDR:
		dump_ip_addr_per_radio(print, nis);
		break;
	default:
		print_out(print, "%s\n", "Unknown statistics type");
	}
}

static int
qcsapi_node_stat_table_lookup(qcsapi_output *print, char* str,
				qcsapi_node_stat_e* qstat_index)
{
	int qcsapi_retval = -1;
	int i;

	for (i = 0; i < TABLE_SIZE(qcsapi_node_stat_names_table); i++) {
		if (strcmp(str, qcsapi_node_stat_names_table[i].name) == 0) {
			*qstat_index = qcsapi_node_stat_names_table[i].index;
			return 1;
		}
	}

	return qcsapi_retval;
}

static int
call_qcsapi_wifi_get_node_stat(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *intf = p_calling_bundle->caller_interface;
	struct qtn_nis_info_list node_list;
	struct qtn_nis_info_list_entry node_list_entry;
	int qcsapi_retval;
	uint32_t node_index = 0;
	qcsapi_mac_addr mac_addr = {0};
	qcsapi_node_stat_e qstat_index;
	int statval = 0;
	int for_all = 0;
	int control = 0;

	memset(&node_list, 0, sizeof(node_list));
	memset(&node_list_entry, 0, sizeof(node_list_entry));

	if (argc < 2) {
		statval = 1;
		goto out;
	}

	qcsapi_retval = qcsapi_node_stat_table_lookup(print, (char*)argv[0], &qstat_index);
	if (qcsapi_retval < 0) {
		goto out;
	}

	if (!strcmp(argv[1], "all")) {
		for_all = 1;
	} else {
		if (qcsapi_util_str_to_uint32(argv[1], &node_index) < 0 || node_index == 0) {
			statval = parse_mac_addr(argv[1], mac_addr);
			if (statval < 0) {
				statval = 1;
				goto out;
			}
		}
	}

	if (argc == 3) {
		if (!strcmp(argv[2], "start")) {
			control = qcsapi_accum_nodestat_start;
		} else if (!strcmp(argv[2], "stop")) {
			control = qcsapi_accum_nodestat_stop;
		} else {
			print_err(print, "The argument \"%s\" is invalid\n", argv[2]);
			statval = 1;
			goto out;
		}
	}

	if (control) {
		if (for_all)
			qcsapi_retval = qcsapi_wifi_nodestat_control_per_radio(intf,
						qstat_index, control);
		else
			qcsapi_retval = qcsapi_wifi_nodestat_control_per_node(intf,
						node_index, mac_addr, qstat_index, control);
	} else {
		if (for_all)
			qcsapi_retval = qcsapi_wifi_nodestat_per_radio(intf,
						&node_list, qstat_index);
		else
			qcsapi_retval = qcsapi_wifi_nodestat_per_node(intf, node_index,
						mac_addr, &node_list_entry, qstat_index);
	}

	if (qcsapi_retval >= 0) {
		if (control) {
			print_out(print, "complete\n");
		} else {
			if (for_all)
				dump_node_stat_per_radio(print,
					&node_list, qstat_index);
			else
				dump_node_stat_per_node(print, node_index,
					&node_list_entry, qstat_index);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;

out:
	print_err(print, "Usage: <WiFi interface> <stat> { <MAC addr> | <node_index> | all } ");
	print_err(print, "[ { start | stop } ]\n");
	return statval;
}

static int
call_qcsapi_qwe_command(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	int		qcsapi_retval;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	char		*command = argv[0];
	char		*param1 = (argc >= 2) ? argv[1] : NULL;
	char		*param2 = (argc >= 3) ? argv[2] : NULL;
	char		*param3 = (argc >= 4) ? argv[3] : NULL;
	char		output[1024];

	if (argc < 1 || argc > 4) {
		print_err(print, "Usage: call_qcsapi qwe <command> [<param1>] [<param2>] [<param3>]\n");
		return 1;
	}

	qcsapi_retval = qcsapi_qwe_command(command, param1, param2, param3, output, sizeof(output));
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%s\n", output);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_get_client_mac_list(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	int		qcsapi_retval;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	const char *intf = p_calling_bundle->caller_interface;
	int	index = (argc >= 1) ? atoi(argv[0]) : 0;
	struct qcsapi_mac_list *mlist = NULL;

	if (argc != 1) {
		print_err(print, "\nUsage: call_qcsapi get_client_mac_list <interface> <node_idx>\n");
		return statval;
	}
	//print_err(print, "argc %d %s %s index = %d, intf=%s\n", argc, argv[0], argv[1], index, intf);

	mlist = calloc(1, sizeof(struct qcsapi_mac_list));
	qcsapi_retval = qcsapi_get_client_mac_list(intf, index, mlist);
	if (qcsapi_retval >= 0) {
		if ((verbose_flag >= 0) && (mlist->num_entries)) {
			int i,k;
			if (mlist->flags & 0x2 ) {
				print_out(print, "Node supports 4 address\n");
			}
			if (mlist->flags & 0x1 ) {
				print_out(print, "Results are truncated to Max[%d]\n",
						QCSAPI_MAX_MACS_IN_LIST);
			}

			for (i=0,k=0; i < mlist->num_entries; i++, k += 6)
				print_out(print, "\t"MACSTR" \n", MAC2STR(&mlist->macaddr[k]));
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}
	free(mlist);
	return statval;
}

static int
call_qcsapi_get_core_dump2(call_qcsapi_bundle *p_calling_bundle,
		int argc, char *argv[])
{
	int retval = 0;
	int qcsapi_retval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	struct qcsapi_data_4Kbytes *buf = NULL;
	unsigned int bytes_copied;
	unsigned int bytes_written;
	unsigned int start_offset;

	buf = calloc(1, sizeof(*buf));
	if (!buf) {
		print_err(print, "Could not allocate %u bytes of memory\n", sizeof(*buf));
		retval = 1;
		goto out;
	}

	start_offset = 0;

	while (1) {
		qcsapi_retval = qcsapi_get_core_dump2(buf, sizeof(*buf), start_offset,
			&bytes_copied);
		if (qcsapi_retval < 0) {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			retval = 1;
			goto out;
		}

		if (!bytes_copied)
			break;

		bytes_written = write(STDOUT_FILENO, buf->data, bytes_copied);
		if ((bytes_written == -1) || (bytes_written != bytes_copied)) {
			retval = 1;
			goto out;
		}

		start_offset += bytes_copied;
	}

out:
	if (buf)
		free(buf);

	return retval;
}

static int
call_qcsapi_get_app_core_dump(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int retval = 0;
	int qcsapi_retval = 0;
	uint32_t bytes_copied;
	uint32_t bytes_remaining;
	uint32_t bytes_written = 0;
	uint32_t offset = 0;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	FILE *fp = NULL;
	string_4096 buff;

	if (argc != 2) {
		qcsapi_report_usage(p_calling_bundle, "<core dump file> <output file>\n");
		return 1;
	}

	fp = fopen(argv[1], "w+");
	if (!fp) {
		print_err(print, "Failed to open output file : %s\n", argv[1]);
		return 1;
	}

	while (1) {
		qcsapi_retval = qcsapi_get_app_core_dump_ext(argv[0], buff, sizeof(buff),
						offset, &bytes_copied, &bytes_remaining);
		if (qcsapi_retval < 0) {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			retval = 1;
			break;
		}

		bytes_written = fwrite(buff, 1, bytes_copied, fp);
		if (bytes_written != bytes_copied) {
			print_err(print, "Failed to write the content to output file : %s\n", argv[1]);
			retval = 1;
			break;
		}

		if (!bytes_remaining) {
			break;
		}

		offset += bytes_copied;
	}

	if (!retval)
		print_out(print, "Core file copied to %s\n", argv[1]);

	if (fp)
		fclose(fp);

	return retval;
}

static int
call_qcsapi_get_sys_log(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int retval = 0;
	int qcsapi_retval = 0;
	uint32_t bytes_copied;
	uint32_t bytes_remaining;
	uint32_t bytes_written = 0;
	uint32_t offset = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	FILE *fp = NULL;
	struct qcsapi_data_3Kbytes *buf = NULL;
	char *output_file = NULL;

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle, "<output file>\n");
		return 1;
	}

	output_file = argv[0];

	fp = fopen(output_file, "w+");
	if (!fp) {
		print_err(print, "Failed to open output file : %s\n", output_file);
		retval = 1;
		goto out;
	}

	buf = calloc(1, sizeof(*buf));
	if (!buf) {
		print_err(print, "Could not allocate %lu bytes of memory\n", sizeof(*buf));
		retval = 1;
		goto out;
	}

	while (1) {
		qcsapi_retval = qcsapi_get_sys_log(buf, offset, &bytes_copied, &bytes_remaining);
		if (qcsapi_retval < 0) {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			retval = 1;
			break;
		}

		bytes_written = fwrite(buf, 1, bytes_copied, fp);
		if (bytes_written != bytes_copied) {
			print_err(print, "Failed to write the content to output file : %s\n",
					output_file);
			retval = 1;
			break;
		}

		if (!bytes_remaining)
			break;

		offset += bytes_copied;
	}

	if (!retval)
		print_out(print, "System log copied to %s\n", output_file);

out:
	if (fp)
		fclose(fp);
	if (buf)
		free(buf);

	return retval;
}

static int
call_qcsapi_wifi_sample_all_clients(const call_qcsapi_bundle *p_calling_bundle,
								int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	uint8_t sta_count = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *intf = p_calling_bundle->caller_interface;

	qcsapi_retval = qcsapi_wifi_sample_all_clients(intf, &sta_count);
	if (qcsapi_retval >= 0) {
		print_out( print, "%u\n", sta_count);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

#define MAX_ASSOC_STA 2007
static int
call_qcsapi_wifi_get_per_assoc_data(const call_qcsapi_bundle *p_calling_bundle,
							int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	int num_entry;
	int offset;
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *intf = p_calling_bundle->caller_interface;
	struct qcsapi_sample_assoc_data *data;
	char ip_str[IP_ADDR_STR_LEN + 1];
	int i;
	int j;

	if (argc < 2) {
		qcsapi_report_usage(p_calling_bundle, "<interface> <num_entry> <offset>\n");
		return 1;
	}

	if (local_str_to_int32(argv[0], &num_entry, print, "value") < 0)
		return 1;

	if ((num_entry < 1) || (num_entry > MAX_ASSOC_STA))
		num_entry = MAX_ASSOC_STA;

	if (local_str_to_int32(argv[1], &offset, print, "offset value") < 0)
		return 1;

	data = calloc(num_entry, sizeof(struct qcsapi_sample_assoc_data));

	if (data == NULL)
		qcsapi_retval = -EFAULT;

	if (qcsapi_retval >= 0)
		qcsapi_retval = qcsapi_wifi_get_per_assoc_data(intf, data, num_entry, offset);

	if (qcsapi_retval >= 0) {
		for (i = 0; i < num_entry; i++) {
			print_out(print, "Assoc ID: %u\nMacaddr: "MACSTR"\nTx: %u\nRx: %u\n"
						"Tx_rate(Max): %u\nRx_rate(Max): %u\n"
						"Mode: %s\nBw: %u\nAssoc_time: %usec\n",
					data[i].assoc_id,
					MAC2STR(data[i].mac_addr),
					data[i].tx_stream,
					data[i].rx_stream,
					data[i].achievable_tx_phy_rate,
					data[i].achievable_rx_phy_rate,
					qcsapi_wifi_modes_strings[data[i].protocol],
					data[i].bw,
					data[i].time_associated);
			print_out(print, "Rx_bytes: %llu\nTx_bytes: %llu\nRx_pkts: %u\n"
					"Tx_pkts: %u\nRx_errors: %u\nTx_errors: %u\n"
					"Rx_dropped %u\nTx_dropped: %u\nRx_ucast: %u\n"
					"Tx_ucast: %u\nRx_mcast: %u\nTx_mcast: %u\n"
					"Rx_bcast: %u\nTx_bcast: %u\nLink_quality: %u\n",
						data[i].rx_bytes,
						data[i].tx_bytes,
						data[i].rx_packets,
						data[i].tx_packets,
						data[i].rx_errors,
						data[i].tx_errors,
						data[i].rx_dropped,
						data[i].tx_dropped,
						data[i].rx_ucast,
						data[i].tx_ucast,
						data[i].rx_mcast,
						data[i].tx_mcast,
						data[i].rx_bcast,
						data[i].tx_bcast,
						data[i].link_quality);
			print_out(print, "tx_wifi_drop: %u %u %u %u\n",
						data[i].tx_wifi_drop[WMM_AC_BE],
						data[i].tx_wifi_drop[WMM_AC_BK],
						data[i].tx_wifi_drop[WMM_AC_VI],
						data[i].tx_wifi_drop[WMM_AC_VO]);

			print_out(print, "\nRSSI\t RCPI\t EVM\t HW_NOISE\n");
			for (j = 0; j < QCSAPI_NUM_ANT; j++) {
				if (j == (QCSAPI_NUM_ANT - 1))
					print_out(print,"\n(AVG)\t(Max)\t(Sum)\t(Avg)\n");

				print_out(print, "%4d.%d\t",
						((int)(data[i].last_rssi_dbm[j])) / 10,
						abs((int)data[i].last_rssi_dbm[j]) % 10);

				print_out(print, "%4d.%d\t",
						((int)(data[i].last_rcpi_dbm[j])) / 10,
						abs((int)data[i].last_rcpi_dbm[j]) % 10);
				print_out(print, "%4d.%d\t",
						((int)(data[i].last_evm_dbm[j])) / 10,
						abs(((int)data[i].last_evm_dbm[j])) % 10);

				print_out(print, "%4d.%d\n",
						((int)(data[i].last_evm_dbm[j])) / 10,
						abs(((int)data[i].last_evm_dbm[j])) % 10);
			}

			switch (data[i].vendor) {
			case PEER_VENDOR_QTN:
				print_out(print, "vendor: quantenna\n");
				break;
			case PEER_VENDOR_BRCM:
				print_out(print, "vendor: broadcom\n");
				break;
			case PEER_VENDOR_ATH:
				print_out(print, "vendor: atheros\n");
				break;
			case PEER_VENDOR_RLNK:
				print_out(print, "vendor: ralink\n");
				break;
			case PEER_VENDOR_RTK:
				print_out(print, "vendor: realtek\n");
				break;
			case PEER_VENDOR_INTEL:
				print_out(print, "vendor: intel\n");
				break;
			default:
				print_out(print, "vendor: unknown\n");
			}

			inet_ntop(AF_INET, &data[i].ip_addr, ip_str, IP_ADDR_STR_LEN);
			print_out(print, "Ipaddr: %s\n\n", ip_str);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	if (data)
		free(data);

	return statval;
}

static int
call_qcsapi_wifi_set_tx_chains(call_qcsapi_bundle * p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err(print, "Not enough parameters in call qcsapi\n");
		print_err(print, "Usage: call_qcsapi set_tx_chains wifi0 <tx_chains>\n");
		statval = 1;
	} else {
		qcsapi_unsigned_int tx_chains;
		int qcsapi_retval;
		const char *interface = p_calling_bundle->caller_interface;

		if (local_str_to_uint32(argv[0], &tx_chains, print, "tx chains value") < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_set_tx_chains(interface, tx_chains);
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out(print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_wifi_get_tx_chains(call_qcsapi_bundle * p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	qcsapi_unsigned_int tx_chains;
	const char *interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_tx_chains(interface, &tx_chains);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "%d\n", tx_chains);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_get_wifi_ready(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	qcsapi_unsigned_int wifi_ready= 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_is_ready(&wifi_ready);

	if (qcsapi_retval >= 0) {
		print_out( print, "%d\n", wifi_ready );
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_get_cca_stats(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int			statval = 0;
	int			qcsapi_retval;
	const char		*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output		*print = p_calling_bundle->caller_output;
	qcsapi_cca_stats	stats;

	qcsapi_retval = qcsapi_get_cca_stats( the_interface, &stats );
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "cca_occupy=\t%u\n"
					 "cca_intf=\t%u\n"
					 "cca_trfc=\t%u\n"
					 "cca_tx=\t\t%u\n"
					 "cca_rx=\t\t%u\n",
				  stats.cca_occupy,
				  stats.cca_intf,
				  stats.cca_trfc,
				  stats.cca_tx,
				  stats.cca_rx);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_get_ep_status(call_qcsapi_bundle *call, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	qcsapi_output *print = call->caller_output;
	qcsapi_unsigned_int ep_status_val;
	const char *the_interface = call->caller_interface;

	qcsapi_retval = qcsapi_get_ep_status(the_interface, &ep_status_val);

	if (qcsapi_retval >= 0)	{
		print_out(print, "%u\n", ep_status_val);
	} else {
		report_qcsapi_error(call, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_get_igmp_snoop(call_qcsapi_bundle *call, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	uint32_t igmp_snooping_state = 0;
	qcsapi_output *print = call->caller_output;
	const char *the_interface = call->caller_interface;
	char *usage = "Usage: call_qcsapi get_igmp_snoop <bridge interface>\n";

	if (argc >= 1) {
		print_out(print, usage);
		statval = 1;
	} else {
		qcsapi_retval = qcsapi_get_igmp_snooping_state(the_interface,
								&igmp_snooping_state);

		if (qcsapi_retval >= 0) {
			print_out(print, "%u\n", igmp_snooping_state);
		} else {
			report_qcsapi_error(call, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_set_igmp_snoop(call_qcsapi_bundle *call, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	uint32_t igmp_snooping_state = 0;
	const char *the_interface = call->caller_interface;
	qcsapi_output *print = call->caller_output;
	uint8_t value;

	if (local_verify_enable_or_disable(argv[0], &value, print) < 0)
		return 1;

	switch (value) {
		case QCSAPI_IGMP_SNOOPING_ENABLE:
			igmp_snooping_state = QCSAPI_IGMP_SNOOPING_ENABLE;
			break;
		case QCSAPI_IGMP_SNOOPING_DISABLE:
			igmp_snooping_state = QCSAPI_IGMP_SNOOPING_DISABLE;
			break;
		default:
			qcsapi_retval = -EINVAL;
	}

	if (qcsapi_retval == 0) {
		qcsapi_retval = qcsapi_set_igmp_snooping_state(the_interface,
								igmp_snooping_state);
	}

	if (qcsapi_retval < 0) {
		report_qcsapi_error(call, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_set_max_bcast_pps(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	qcsapi_unsigned_int max_bcast_pps;

	if (argc < 1)
	{
		print_err(print, "Not enough parameters in call_qcsapi set_max_bcast_pps, count is %d\n", argc );
		print_err(print, "Usage: call_qcsapi set_max_bcast_pps <WiFi interface> <0 - %d>\n", MAX_BCAST_PPS_LIMIT);
		statval = 1;
	}
	else
	{
		if (local_atou32_verify_numeric_range(argv[0], &max_bcast_pps, print, 0, MAX_BCAST_PPS_LIMIT) < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_set_max_bcast_pps(the_interface, max_bcast_pps);
		if (qcsapi_retval >= 0) {
			print_out(print,"complete\n");
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}
	return (statval);
}

static int
call_qcsapi_wifi_set_scs_leavedfs_chan_mtrc_mrgn(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{

	int statval = 0;
	int qcsapi_retval = 0;
	uint32_t value = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		print_err(print,
			"Not enough parameters in call_qcsapi set_scs_leavedfs_chan_mtrc_mrgn, count is %d\n",
			argc);
		print_err(print,
			"Usage: call_qcsapi set_scs_leavedfs_chan_mtrc_mrgn <Wifi interface> "
			"<channel metric margin>\n" );
		statval = 1;
	} else {
		if (local_atou32_verify_numeric_range(argv[0], &value, print, 0,
				IEEE80211_SCS_CHAN_MTRC_MRGN_MAX) < 0) {
			return 1;
		}

		qcsapi_retval = qcsapi_wifi_set_scs_leavedfs_chan_mtrc_mrgn(the_interface, value);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0) {
				print_out( print, "complete\n");
			}
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return statval;
}

static int
call_qcsapi_set_max_boot_cac_duration(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int max_boot_cac_duration;

	if (argc < 1) {
		print_err(print, "Not enough parameters in call_qcsapi set_max_boot_cac_duration, count is %d\n", argc );
		print_err(print, "Usage: call_qcsapi set_max_boot_cac_duration <WiFi interface> -1(disabled)\n"
				"call_qcsapi set_max_boot_cac_duration <WiFi interface> 0\n"
				"call_qcsapi set_max_boot_cac_duration <WiFi interface> <seconds>\n");
		statval = 1;
	} else {
		if (local_atoi32_verify_numeric_range(argv[0], &max_boot_cac_duration, print, -1, MAX_BOOT_CAC_DURATION) < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_set_max_boot_cac_duration(the_interface, max_boot_cac_duration);
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0)
				print_out(print, "complete\n");
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}
	return (statval);
}

static int
call_qcsapi_get_icac_status(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	statval = 0;
	int	qcsapi_retval;
	int	status = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_icac_status(the_interface, &status);

	if (qcsapi_retval >= 0)
		print_out(print, "%s\n", status ? "Active" : "Inactive");
	else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int call_qcsapi_do_system_action(const call_qcsapi_bundle *p_calling_bundle,
								int argc, char *argv[])
{
        int		qcsapi_retval = 0;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	string_32	action;

	if (argc != 1) {
		print_err(print, "Not enough parameters in call qcsapi do_system_action, count is %d\n", argc);
		print_err(print, "Usage: call_qcsapi do_system_action <action>\n");
		return 1;
	}

	strncpy(action, argv[0], sizeof (action) - 1);

	qcsapi_retval = qcsapi_do_system_action(action);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int call_qcsapi_wifi_is_weather_channel(const call_qcsapi_bundle *p_calling_bundle,
			int argc, char *argv[])
{
	int		qcsapi_retval = 0;
	const char	*the_interface = p_calling_bundle->caller_interface;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	uint16_t	chan;

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle, "<ifname> <channel>");
		return 1;
	}

	if (safe_atou16(argv[0], &chan, print, 0, IEEE80211_CHAN_MAX) == 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_is_weather_channel(the_interface, chan);
	if (qcsapi_retval >= 0) {
		print_out(print, "%d\n", qcsapi_retval);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_set_nac_mon_mode(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval = 0;
	uint16_t period = MONITOR_DEFAULT_CYCLE_PERIOD;
	uint16_t percentage_on = MONITOR_DEFAULT_ON_PERIOD * 100 / MONITOR_DEFAULT_CYCLE_PERIOD;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint8_t enable = 2;
	uint8_t is_abs = 0;
	int show_usage = 0;
	const char *usage = "Usage:\n\tcall_qcsapi set_nac_mon_mode <Wifi interface>"
				" {enable | disable} [<cycle time> <percentage_on> [abs]]\n";

	if (argc != 4 && argc != 3 && argc != 1) {
		show_usage = 1;
		goto usage_out;
	} else {
		if (!strcmp(argv[0], "enable")) {
			enable = 1;
		} else if (!strcmp(argv[0], "disable")) {
			enable = 0;
		} else {
			show_usage = 1;
			goto usage_out;
		}
		if (enable == 1) {
			if (argc == 4) {
				if (strcmp(argv[3], "abs") == 0) {
					is_abs = 1;
				} else if (strcmp(argv[3], "abs") != 0) {
					show_usage = 1;
					goto usage_out;
				}
			}

			if (argc >= 3) {
				if (safe_atou16(argv[1], &period, print,
						MONITOR_MIN_CYCLE_PERIOD,
						MONITOR_MAX_CYCLE_PERIOD) == 0)
						return -EINVAL;

				if (is_abs) {
					if (safe_atou16(argv[2], &percentage_on,
						print, 1, period - 1) == 0)
						return -EINVAL;
				} else {
					if (safe_atou16(argv[2], &percentage_on,
						print, MONITOR_MIN_ON_PERIOD,
						MONITOR_MAX_ON_PERIOD) == 0)
						return -EINVAL;
				}
			}
		}

		qcsapi_retval = qcsapi_wifi_set_nac_mon_mode_abs2(the_interface, enable,
					period, percentage_on, is_abs);
		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0)
				print_out( print, "complete\n");
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

usage_out:
	if (show_usage) {
		print_out(print, usage);
		return 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_nac_mon_mode(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	int enable = 0;
	int is_abs = 0;
	int percentage_on = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int period = 0;

	qcsapi_retval = qcsapi_wifi_get_nac_mon_mode_abs(the_interface, &enable, &is_abs,
								&period, &percentage_on);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "status: %s\n Duty Cycle time: %d\n %s: %d\n",
				enable ? "enabled" : "disabled", period,
				is_abs ? "On period time" : "Percentage on", percentage_on);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
	}

	return qcsapi_retval;
}

static int
call_qcsapi_wifi_get_nac_stats(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int		statval = 0;
	qcsapi_output	*print = p_calling_bundle->caller_output;
	const char *intf = p_calling_bundle->caller_interface;
	int		qcsapi_retval;
	qcsapi_nac_stats_report *report = NULL;
	int i = 0;

	report = calloc(1, sizeof(qcsapi_nac_stats_report));
	if (!report)
		return -ENOMEM;
	qcsapi_retval = qcsapi_wifi_get_nac_stats(intf, report);

	if (qcsapi_retval >= 0) {
		if ((verbose_flag >= 0) && (report->num_valid_entries)) {
			print_out(print, "  Mac Address      Rssi(dB)  Timestamp  Channel  Packet Type\n");
			for (i=0; i < report->num_valid_entries; i++) {
				print_out(print, MACSTR" %9d %10llu %8d   %-10s\n",
					MAC2STR(&report->stats[i].txmac[0]),
					report->stats[i].average_rssi,
					report->stats[i].timestamp,
					report->stats[i].channel,
					(report->stats[i].packet_type == 1)?"Control":
						((report->stats[i].packet_type == 2)?"Data":"Management"));
			}
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}
	free(report);
	return statval;
}

static const struct {
	    qcsapi_log_module_name name_idx;
		const char *mod_name;
} module_name_tbl[] =
{
	{QCSAPI_WPA_SUPPLICANT, "wpa_supplicant"},
	{QCSAPI_HOSTAPD, "hostapd"},
	{QCSAPI_KERNEL, "kernel"},
	{QCSAPI_DRIVER, "driver"},
	{QCSAPI_QPROC_MON, "qproc_mon"},
};

int
local_get_log_module_name(const char * lookup_module, qcsapi_log_module_name *mod_name)
{
	unsigned int iter;

	if (lookup_module == NULL || mod_name == NULL)
		return -EFAULT;

	for (iter = 0; iter < ARRAY_SIZE(module_name_tbl); iter++)
		if (strcasecmp(module_name_tbl[iter].mod_name, lookup_module) == 0) {
				*mod_name = module_name_tbl[iter].name_idx;
				return 0;
		}

	return -EINVAL;
}

static int
call_qcsapi_set_log_level(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;
	int qcsapi_retval = 0;
	qcsapi_log_module_name mod_name;
	string_128 params;

	if (argc != 2) {
		print_err(print, "Usage:\n");
		print_err(print, "\tcall_qcsapi set_log_level <ifname> <module> <level>\n\n");
		print_err(print, "\tFor hostapd, you could also send the level for sub-modules as\n");
		print_err(print, "\tcall_qcsapi set_log_level <ifname> hostapd <sub-module> <level>\n");
		print_err(print, "\tcall_qcsapi set_log_level <ifname> hostapd <level> <sub-module> <level>\n");
		return 1;
	}

	if (local_get_log_module_name(argv[0], &mod_name) != 0) {
		print_err(print, "Invalid argument\n");
		return 1;
	}

	strncpy(params, argv[1], sizeof(params) - 1);
	params[sizeof(params) - 1] = '\0';

	qcsapi_retval = qcsapi_set_log_level(the_interface, mod_name, params);
	if (qcsapi_retval >= 0) {
	    if (verbose_flag >= 0) {
		print_out(print, "complete\n");
	    }
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_get_log_level(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;
	int qcsapi_retval = 0;
	qcsapi_log_module_name mod_name;
	string_128 level;

	if (argc != 1) {
		print_err(print, "Not enough parameters in call qcsapi get_log_level, count is %d\n", argc);
		print_err(print, "Usage: call_qcsapi get_log_level <ifname> <module>\n");
		return 1;
	}

	if (local_get_log_module_name(argv[0], &mod_name) != 0) {
		print_err(print, "Invalid argument\n");
		return 1;
	}

	qcsapi_retval = qcsapi_get_log_level(the_interface, mod_name, level);
	if (qcsapi_retval >= 0) {
	    if (verbose_flag >= 0)
		print_out(print, "%s\n", level);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static const struct {
	qcsapi_remote_log_action action_type;
	const char *action_name;
} remote_log_action_tbl[] =
{
	{QCSAPI_REMOTE_LOG_ENABLE, "enable"},
	{QCSAPI_REMOTE_LOG_DISABLE, "disable"}
};

static int
local_get_remote_logging_action(const char *action_name, qcsapi_remote_log_action *action_type)
{
	unsigned int iter;

	if (action_type == NULL || action_name == NULL)
		return -EFAULT;

	for (iter = 0; iter < ARRAY_SIZE(remote_log_action_tbl); iter++)
		if (strcasecmp(remote_log_action_tbl[iter].action_name, action_name) == 0) {
			*action_type = remote_log_action_tbl[iter].action_type;
			return 0;
		}

	return -EINVAL;
}

static int
call_qcsapi_set_remote_logging(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval = 0;
	qcsapi_remote_log_action action;
	qcsapi_unsigned_int ipaddr;

	if (argc < 1) {
		print_err(print, "Not enough parameters in call qcsapi set_remote_logging, count is %d\n", argc);
		print_err(print, "Usage: call_qcsapi set_remote_logging enable <NPU's ip address>\n");
		print_err(print, "Usage: call_qcsapi set_remote_logging disable\n");
		return 1;
	}

	if (local_get_remote_logging_action(argv[0], &action) != 0) {
		print_err(print, "Invalid argument\n");
		return 1;
	}

	if (action == QCSAPI_REMOTE_LOG_ENABLE) {
		if (argv[1] == NULL) {
			print_err(print, "IPv4 address not present\n");
			return 1;
		}

		if (inet_pton(AF_INET, argv[1], &ipaddr) != 1) {
			print_err(print, "Invalid IPv4 address %s\n", argv[1]);
			return 1;
		}

		if (ipaddr == 0) {
			print_err(print, "Invalid IPv4 address %s\n", argv[1]);
			return 1;
		}
	}

	qcsapi_retval = qcsapi_set_remote_logging(action, ipaddr);

	if (qcsapi_retval >= 0) {
	    if (verbose_flag >= 0)
		print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static const struct {
	qcsapi_console_action action_type;
	const char *action_name;
} console_action_tbl[] =
{
	{QCSAPI_CONSOLE_ENABLE, "enable"},
	{QCSAPI_CONSOLE_DISABLE, "disable"}
};

static int
local_get_console_action(const char *action_name, qcsapi_console_action *action_type)
{
	unsigned int iter;

	if (action_type == NULL || action_name == NULL)
		return -EFAULT;

	for (iter = 0; iter < ARRAY_SIZE(console_action_tbl); iter++)
		if (strcasecmp(console_action_tbl[iter].action_name, action_name) == 0) {
			*action_type = console_action_tbl[iter].action_type;
			return 0;
		}

	return -EINVAL;
}

static int
call_qcsapi_set_console(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval;
	qcsapi_console_action action;

	if (argc != 1) {
		print_err(print, "Not enough parameters in call_qcsapi set_console, count is %d\n", argc);
		print_err(print, "Usage: call_qcsapi set_console <enable/disable>\n");
		return 1;
	}

	if (local_get_console_action(argv[0], &action) != 0) {
		print_err(print, "Invalid argument\n");
		print_err(print, "Usage: call_qcsapi set_console <enable/disable>\n");
		return 1;
	}

	qcsapi_retval = qcsapi_set_console(action);

	if (qcsapi_retval >= 0) {
	    if (verbose_flag >= 0)
		print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
local_get_vopt_action_type(const char *action_name, qcsapi_vopt_action *action_type)
{
	unsigned int iter;

	if (action_type == NULL || action_name == NULL)
		return -EFAULT;

	for (iter = 0; iter < ARRAY_SIZE(vopt_action_tbl); iter++)
		if (strcasecmp(vopt_action_tbl[iter].action_name, action_name) == 0) {
			*action_type = vopt_action_tbl[iter].action_type;
			return 0;
		}

	return -EINVAL;
}

static const char*
local_get_vopt_action_name(const qcsapi_vopt_action action_type)
{
	unsigned int iter = 0;
	const char *ret_name = "No such vopt type";
	for (iter = 0; iter < ARRAY_SIZE(vopt_action_tbl); iter++)
		if (vopt_action_tbl[iter].action_type == action_type) {
			ret_name = vopt_action_tbl[iter].action_name;
			break;
		}

	return ret_name;
}

static int
call_qcsapi_set_vopt(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *wifi = p_calling_bundle->caller_interface;
	int qcsapi_retval;
	qcsapi_vopt_action action;

	if ((argc != 1) || (local_get_vopt_action_type(argv[0], &action) != 0)) {
		print_err(print, "Usage:\n");
		print_err(print, "\tcall_qcsapi set_vopt <ifname> <enable|disable>\n\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_vopt(wifi, action);
	if (qcsapi_retval >= 0) {
		print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_get_vopt(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int config;
	int qcsapi_retval;
	int status;
	const char *wifi = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_vopt(wifi, &status);

	if (qcsapi_retval >= 0) {
		config = (status >> VOPT_CONFIG_S);
		status = status & VOPT_STATUS_MASK;
		print_out(print, "Config:%s, Status:%s\n", local_get_vopt_action_name(config),
				local_get_vopt_action_name(status));
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}


static int
call_qcsapi_wifi_set_br_isolate(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = -1;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc != 2)
		goto usage_out;

	if (!strcmp(argv[0], "normal")) {
		uint8_t onoff;

		if (local_verify_enable_or_disable(argv[1], &onoff, print) < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_set_br_isolate(e_qcsapi_br_isolate_normal, onoff);
	} else if (!strcmp(argv[0], "vlan")) {
		uint32_t arg;

		if (!strcmp(argv[1], "all")) {
			arg = QVLAN_VID_ALL;
		} else if (!strcmp(argv[1], "none")) {
			arg = 0;
		} else {
			if (local_atou32_verify_numeric_range(argv[1], &arg, print, 0,
					(QVLAN_VID_MAX - 1)) < 0)
				return -EINVAL;
		}

		qcsapi_retval = qcsapi_wifi_set_br_isolate(e_qcsapi_br_isolate_vlan, arg);
	}

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
		return qcsapi_retval;
	}

usage_out:
	print_out(print, "Usage:\n");
	print_out(print, "	call_qcsapi set_br_isolate normal { 0 | 1 }\n");
	print_out(print, "	call_qcsapi set_br_isolate vlan { all | none | <VLAN ID> }\n");
	return -1;
}

static int
call_qcsapi_wifi_get_br_isolate(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval;
	uint32_t val;

	if (argc != 0) {
		qcsapi_report_usage(p_calling_bundle, "get_br_isolate\n");
		return -1;
	}

	qcsapi_retval = qcsapi_wifi_get_br_isolate(&val);
	if (qcsapi_retval >= 0) {
		if (val & BIT(0))
			print_out(print, "Normal bridge isolation enabled\n");
		else
			print_out(print, "Normal bridge isolation disabled\n");

		if (val & BIT(1)) {
			uint16_t vlanid = (val >> 16);

			if (vlanid == QVLAN_VID_ALL)
				print_out(print, "VLAN bridge isolation: All\n");
			else
				print_out(print, "VLAN bridge isolation: %u\n", vlanid);
		} else {
			print_out(print, "VLAN bridge isolation disabled\n");
		}
	}

	return qcsapi_retval;
}

static int
call_qcsapi_get_device_mode(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval;
	qcsapi_dev_mode dev_mode = qcsapi_dev_mode_unknown;

	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	statval = qcsapi_get_device_mode(the_interface, &dev_mode);
	if (statval >= 0) {
		if (dev_mode < ARRAY_SIZE(qcsapi_dev_modes)) {
			print_out(print, "%s\n", qcsapi_dev_modes[dev_mode]);
		} else {
			print_err(print, "Invalid mode %d\n", dev_mode);
			return 1;
		}
	} else {
		report_qcsapi_error(p_calling_bundle, statval);
		return 1;
	}

	return statval;
}

static int
call_qcsapi_set_report_flood_interval(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval;
	uint32_t interval;
	qcsapi_output *print = p_calling_bundle->caller_output;

	statval = local_atou32_verify_numeric_range(argv[1], &interval, print, 0, UINT32_MAX);
	if (statval < 0) {
		print_err(print, "Invalid value for report flood interval\n");
		return 1;
	}

	statval = qcsapi_set_report_flood_interval(argv[0], interval);
	if (statval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, statval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_get_report_flood_interval(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval;
	uint32_t interval;
	qcsapi_output *print = p_calling_bundle->caller_output;

	statval = qcsapi_get_report_flood_interval(argv[0], &interval);
	if (statval == 0) {
		print_out(print, "%u\n", interval);
	} else {
		report_qcsapi_error(p_calling_bundle, statval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_get_btm_cap(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int btm_cap = 0;

	if (argc >= 1) {
		print_err(print, "Incorrect parameters in call_qcsapi get_btm_cap, count is %d\n", argc);
		print_err(print, "Usage: call_qcsapi get_btm_cap <WiFi interface>\n");
		statval = 1;
	} else {
		qcsapi_retval = qcsapi_wifi_get_btm_cap(the_interface, &btm_cap);

		if (qcsapi_retval >= 0)
			print_out(print, "%s\n", ((btm_cap == 1) ? "enabled" : "disabled"));
		else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return (statval);
}

static int
call_qcsapi_wifi_set_btm_cap(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint8_t btm_cap;

	if (argc < 1) {
		print_err(print, "Not enough parameters in call_qcsapi set_btm_cap, count is %d\n", argc );
		print_err(print, "Usage: call_qcsapi set_btm_cap <WiFi interface> <0/1>\n");
		statval = 1;
	} else {
		if (local_verify_enable_or_disable(argv[0], &btm_cap, print) < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_set_btm_cap(the_interface, btm_cap);

		if (qcsapi_retval >= 0)	{
			if (verbose_flag >= 0)
				print_out( print, "complete\n");
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return (statval);
}

static int
call_qcsapi_wifi_get_rm_neigh_report(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int neigh_repo = 0;

	if (argc != 0) {
		print_err(print, "Incorrect parameters in call_qcsapi get_rm_neigh_report, count is %d\n", argc );
		print_err(print, "Usage: call_qcsapi get_rm_neigh_report <WiFi interface>\n");
		statval = 1;
	} else {
		qcsapi_retval = qcsapi_wifi_get_rm_neigh_report(the_interface, &neigh_repo);

		if (qcsapi_retval >= 0) {
			print_out(print, "%s\n", ((neigh_repo == 1) ? "enabled" : "disabled"));
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return (statval);
}

static int
call_qcsapi_wifi_set_rm_neigh_report(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint8_t neigh_repo;

	if (argc != 1) {
		print_err(print, "Not enough parameters in call_qcsapi set_rm_neigh_report, count is %d\n", argc );
		print_err(print, "Usage: call_qcsapi set_rm_neigh_report <WiFi interface> <0/1>\n");
		statval = 1;
	} else {
		if (local_verify_enable_or_disable(argv[0], &neigh_repo, print) < 0)
			return 1;

		qcsapi_retval = qcsapi_wifi_set_rm_neigh_report(the_interface, neigh_repo);

		if (qcsapi_retval >= 0) {
			if (verbose_flag >= 0)
				print_out(print, "complete\n");
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
			statval = 1;
		}
	}

	return (statval);
}

static int
call_qcsapi_wifi_add_11r_neighbour(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 4) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <MAC> "
				"<NAS Identifier> <128-bit key as hex string> <R1KH-ID(mac address)>\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_add_11r_neighbour_str(the_interface, argv[0], argv[1], argv[2], argv[3]);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		if (qcsapi_retval == -qcsapi_option_not_supported) {
			print_out(print, "Configuration only supported"
					" when ieee80211r is enabled\n");
		}
		return 1;
	}

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_wifi_del_11r_neighbour(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;

	if (argc < 1) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <MAC>\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_del_11r_neighbour_str(the_interface, argv[0]);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_wifi_get_11r_neighbour(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{

	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	string_4096	buf = {0};
	int		buflen = sizeof(string_4096);

	qcsapi_retval = qcsapi_wifi_get_11r_neighbour(the_interface, buf, buflen);

	return qcsapi_report_str_or_error(p_calling_bundle, qcsapi_retval, buf);
}

static const char	*protocol_name_table[] =
{
	"None",
	"WPA",
	"WPA2",
	"WPA WPA2",
	"WPA3",
};

static const char	*encryption_name_table[] =
{
	"None",
	"TKIP",
	"CCMP",
	"TKIP CCMP"
};

static const char	*authentication_name_table[] =
{
	"None",
	"PSK",
	"EAP",
	"SAE",
	"OWE",
	"DPP"
};

static const char *
get_name_by_value(const int qcsapi_value, const char **qcsapi_lookup_table, const size_t lookup_table_size)
{
	const char	*retaddr = NULL;

	if (qcsapi_value >= 0 && qcsapi_value < (int) lookup_table_size)
		retaddr = qcsapi_lookup_table[qcsapi_value];

	return retaddr;
}

static void
local_snprint_bitrate(char *buffer, int len, unsigned int bitrate)
{
	int i = 0;
	char ch[] = {' ','k','M','G'};
	int local_remainder = 0;
	int val;

	for (i = 0; i < 3 && bitrate >= 1000; i++)  {
		val = bitrate / 1000;
		local_remainder = (bitrate % 1000);
		bitrate = val;
	}
	if (local_remainder) {
		snprintf(buffer, len, "%d.%1.1d %cb/s", bitrate, local_remainder, ch[i]);
	} else {
		snprintf(buffer, len, "%d %cb/s", bitrate, ch[i]);
	}
}

static void
local_show_ap_properties(qcsapi_output *print, const qcsapi_unsigned_int index_ap, const qcsapi_ap_properties *p_ap_properties)
{
	char	mac_addr_string[24];
	char buffer[32];

	print_out(print, "AP %d:\n", index_ap);
	print_out(print, "\tSSID: %s\n", p_ap_properties->ap_name_SSID);
	sprintf(&mac_addr_string[ 0 ], MACFILTERINGMACFMT,
		p_ap_properties->ap_mac_addr[0],
		p_ap_properties->ap_mac_addr[1],
		p_ap_properties->ap_mac_addr[2],
		p_ap_properties->ap_mac_addr[3],
		p_ap_properties->ap_mac_addr[4],
		p_ap_properties->ap_mac_addr[5]
	);
	print_out(print, "\tMAC address: %s\n", &mac_addr_string[0]);
	print_out(print, "\tChannel: %d\n", p_ap_properties->ap_channel);
	print_out(print, "\tBandwidth: %d\n", p_ap_properties->ap_bw);
	print_out(print, "\tRSSI: %d\n", p_ap_properties->ap_RSSI);
	print_out(print, "\tBeacon Interval: %d\n", p_ap_properties->ap_beacon_interval);
	print_out(print, "\tDTIM period: %d\n", p_ap_properties->ap_dtim_interval);
	print_out(print, "\tOperating Mode: %s\n", p_ap_properties->ap_is_ess?"Infrastructure":"Ad-Hoc");
	print_out(print, "\tHT secondary offset: %s\n", p_ap_properties->ap_ht_secoffset == IEEE80211_HTINFO_EXTOFFSET_ABOVE ?
			"Above" : p_ap_properties->ap_ht_secoffset == IEEE80211_HTINFO_EXTOFFSET_BELOW ?
			"Below" : "None");
	print_out(print, "\tcenter channel 1: %d\n", p_ap_properties->ap_chan_center1);
	print_out(print, "\tcenter channel 2: %d\n", p_ap_properties->ap_chan_center2);
	print_out(print, "\tLast seen: %u\n", p_ap_properties->ap_last_beacon);
	local_snprint_bitrate(buffer, sizeof(buffer), p_ap_properties->ap_best_data_rate);
	print_out(print, "\tBest Data Rate: %s\n", buffer);

	print_out(print, "\tSGI capability:", buffer);
	if (p_ap_properties->ap_flags &
			((1 << QCSAPI_AP_FLAG_BIT_SGI_CAPS_IN_20MHZ) | (1 << QCSAPI_AP_FLAG_BIT_SGI_CAPS_IN_40MHZ) |
			 (1 << QCSAPI_AP_FLAG_BIT_SGI_CAPS_IN_80MHZ) | (1 << QCSAPI_AP_FLAG_BIT_SGI_CAPS_IN_160MHZ))) {
		if (p_ap_properties->ap_flags & (1 << QCSAPI_AP_FLAG_BIT_SGI_CAPS_IN_20MHZ))
			print_out(print, " 20MHz", buffer);
		if (p_ap_properties->ap_flags & (1 << QCSAPI_AP_FLAG_BIT_SGI_CAPS_IN_40MHZ))
			print_out(print, " 40MHz", buffer);
		if (p_ap_properties->ap_flags & (1 << QCSAPI_AP_FLAG_BIT_SGI_CAPS_IN_80MHZ))
			print_out(print, " 80MHz", buffer);
		if (p_ap_properties->ap_flags & (1 << QCSAPI_AP_FLAG_BIT_SGI_CAPS_IN_160MHZ))
			print_out(print, " 160MHz", buffer);
		print_out(print, "\n", buffer);
	} else
		print_out(print, " None\n", buffer);

	if ((p_ap_properties->ap_flags & (1 << QCSAPI_AP_FLAG_BIT_SEC_ENABLE)) != 0) {
		const char	*value_name = NULL;

		print_out(print, "\tsecurity enabled\n");

		value_name = get_name_by_value(
					p_ap_properties->ap_protocol,
					protocol_name_table,
					TABLE_SIZE(protocol_name_table));
		if (value_name == NULL)
			value_name = "(unknown)";
		print_out(print, "\tprotocol: %s\n", value_name);

		if (verbose_flag > 0) {
			value_name = get_name_by_value(
					p_ap_properties->ap_authentication_mode,
					authentication_name_table,
					TABLE_SIZE(authentication_name_table)
			);
			if (value_name == NULL)
				value_name = "(unknown)";
			print_out(print, "\tauthentication mode: %s\n", value_name);

			value_name = get_name_by_value(
					p_ap_properties->ap_encryption_modes,
					encryption_name_table,
					TABLE_SIZE(encryption_name_table)
			);
			if (value_name == NULL)
				value_name = "(unknown)";
			print_out(print, "\tencryption modes: %s\n", value_name);
		}
	} else {
		print_out(print, "\tsecurity disabled\n");
	}

	print_out(print, "\n");
}

static int
call_qcsapi_wifi_show_access_points(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint32_t count_APs;
	uint32_t offchan = 0;

	if ((argc >= 1) && (local_atou32_verify_numeric_range(argv[0], &offchan, print, 0, 1) < 0))
		return 1;

	if (offchan)
		statval = qcsapi_wifi_get_results_AP_scan_by_scs(the_interface, &count_APs);
	else
		statval = qcsapi_wifi_get_results_AP_scan(the_interface, &count_APs);
	if (statval >= 0) {
		qcsapi_unsigned_int	iter;
		qcsapi_ap_properties	ap_properties;

		for (iter = 0; iter < count_APs && statval >= 0; iter++) {
			statval = qcsapi_wifi_get_properties_AP(the_interface, iter, &ap_properties);
			if (statval >= 0)
				local_show_ap_properties(print, iter + 1, &ap_properties);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, statval);
		return 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_ieee80211r(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <0 | 1>\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_ieee80211r_str(the_interface, argv[0]);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		if (qcsapi_retval == -qcsapi_option_not_supported) {
			print_out(print, "Configuration only supported on"
					" WPA2-PSK and WPA2-EAP modes\n");
		}
		return 1;
	}

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_wifi_get_ieee80211r(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	string_16 value = {0};
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_ieee80211r(the_interface, &value[0]);

	if (qcsapi_retval >= 0) {
		print_out(print, "%s\n", ((atoi(value) == 1) ? "enabled" : "disabled"));
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_set_11r_mobility_domain(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <mobility_domain>\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_ieee80211r_mobility_domain_str(the_interface, argv[0]);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		if (qcsapi_retval == -qcsapi_option_not_supported) {
			print_out(print, "Configuration only supported"
					" when ieee80211r is enabled\n");
		}
		return 1;
	}

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_wifi_get_11r_mobility_domain(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	string_16 value = {0};
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_ieee80211r_mobility_domain(the_interface, &value[0]);

	if (qcsapi_retval >= 0)
		print_out(print, "%s\n", value);
	else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_set_11r_nas_id(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <nas_id>\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_ieee80211r_nas_id_str(the_interface, argv[0]);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		if (qcsapi_retval == -qcsapi_option_not_supported) {
			print_out(print, "Configuration only supported"
					" when ieee80211r is enabled\n");
		}
		return 1;
	}

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_wifi_get_11r_nas_id(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	string_64 value = {0};
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_ieee80211r_nas_id(the_interface, &value[0]);

	if (qcsapi_retval >= 0) {
		print_out(print,"%s\n", value);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_set_11r_ft_over_ds(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <0 | 1>\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_ieee80211r_ft_over_ds_str(the_interface, argv[0]);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		if (qcsapi_retval == -qcsapi_option_not_supported) {
			print_out(print, "Configuration only supported"
					" when ieee80211r is enabled\n");
		}
		return 1;
	}

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_wifi_get_11r_ft_over_ds(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	string_16 value = {0};
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	qcsapi_retval = qcsapi_wifi_get_ieee80211r_ft_over_ds(the_interface, &value[0]);

	if (qcsapi_retval >= 0) {
		print_out(print, "%s\n", ((atoi(value) == 1) ? "enabled" : "disabled"));
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_wifi_set_11r_r1_key_holder(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc < 1) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <r1_key_holder | 0 (delete)>\n");
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_11r_r1_key_holder_str(the_interface, argv[0]);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		if (qcsapi_retval == -qcsapi_option_not_supported) {
			print_out(print, "Configuration only supported"
					" when ieee80211r is enabled\n");
		}
		return 1;
	}

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_wifi_get_11r_r1_key_holder(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	string_16 value = {0};

	qcsapi_retval = qcsapi_wifi_get_11r_r1_key_holder(the_interface, &value[0]);

	if (qcsapi_retval >= 0) {
		print_out(print, "%s\n", value);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static int
call_qcsapi_get_pd_voltage_level(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval;
	int chains_count;
	struct qcsapi_int_array32 pd_values;
	qcsapi_output *print = p_calling_bundle->caller_output;
	int i;
	string_128 tmpbuf = {0};
	int total_chars = 0;
	int written_chars;

	qcsapi_retval = qcsapi_get_pd_voltage_level(&chains_count, &pd_values);

	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	for (i = 0; i < chains_count; i++) {
		written_chars = snprintf(tmpbuf + total_chars, sizeof(tmpbuf) - 1 - total_chars,
			"%d ", pd_values.val[i]);

		if (written_chars <= 0) {
			report_qcsapi_error(p_calling_bundle, -EPERM);
			return 1;
		}

		total_chars += written_chars;
	}

	if (total_chars == 0) {
		report_qcsapi_error(p_calling_bundle, -EPERM);
		return 1;
	}

	tmpbuf[total_chars] = 0;

	print_out(print, "%s\n", tmpbuf);

	return 0;
}

static int
call_qcsapi_enable_emac_sdp(const call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint32_t enable;

	if (argc < 1)
		statval = -qcsapi_parameter_not_found;
	else if (argc > 1)
		statval = -qcsapi_param_count_exceeded;

	if (statval >= 0) {
		if (local_atou32_verify_numeric_range(argv[0], &enable, print, 0, 1) < 0)
			statval = -qcsapi_param_value_invalid;
	}

	if (statval >= 0)
		statval = qcsapi_enable_emac_sdp(enable);

	if (statval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, statval);
	}

	return statval;
}

static int
call_qcsapi_wifi_set_bss_rxchan(call_qcsapi_bundle *p_calling_bundle,
	int argc, char *argv[])
{
	const char* the_interface = p_calling_bundle->caller_interface;
	qcsapi_output* print = p_calling_bundle->caller_output;
	int statval = 0;
	int qcsapi_retval;
	qcsapi_mac_addr bssid;
	uint32_t chan;

	if (argc < 2) {
		qcsapi_report_usage(p_calling_bundle, "<ifname> <bssid> <chan>");
		return 1;
	}

	if (parse_mac_addr(argv[0], bssid)) {
		print_out(print, "Error parsing MAC address %s\n", argv[0]);
		return 1;
	}

	if (local_atou32_verify_numeric_range(argv[1], &chan, print, 1, 255) < 0) {
		print_out(print, "Error channel index %s\n", argv[1]);
		return 1;
	}

	qcsapi_retval = qcsapi_wifi_set_bss_rxscan(the_interface, bssid, chan);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_set_unknown_dest_discover_intval(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint32_t intval;

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <intval in milliseconds>");
		return 1;
	}

	if ((local_atou32_verify_numeric_range(argv[0], &intval, print,
			MIN_UNKNOWN_DEST_DISCOVER_INTVAL, MAX_UNKNOWN_DEST_DISCOVER_INTVAL)) < 0)
		return 1;

	qcsapi_retval = qcsapi_set_unknown_dest_discover_intval(the_interface, intval);
	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static int
call_qcsapi_get_unknown_dest_discover_intval(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int	qcsapi_retval;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint32_t intval;

	if (argc != 0) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface>");
		return 1;
	}

	qcsapi_retval = qcsapi_get_unknown_dest_discover_intval(the_interface, &intval);
	if (qcsapi_retval < 0) {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	print_out(print, "%u\n", intval);

	return 0;
}

static int
call_qcsapi_set_3addr_br_config(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval = -1;
	int enabled;
	int radio;
	qcsapi_unsigned_int radio_id = 0;

	if (argc != 2 && argc != 3)
		goto usage_out;

	if (argc == 3) {
		radio = atoi(argv[0]);
		if (radio < 0)
			goto usage_out;
		radio_id = (unsigned int)radio;
		argv++;
	}

	if (strcmp(argv[0], "dhcp_chaddr") == 0) {
		if (strcmp(argv[1], "0") == 0)
			enabled = 0;
		else if (strcmp(argv[1], "1") == 0)
			enabled = 1;
		else
			goto usage_out;

		qcsapi_retval = qcsapi_radio_set_3addr_br_config(radio_id,
			e_qcsapi_3addr_br_dhcp_chaddr, enabled);
	} else {
		goto usage_out;
	}

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
	}

	return qcsapi_retval;

usage_out:
	print_out(print, "Usage: call_qcsapi set_3addr_br_config [ <radio_id> ] \
		dhcp_chaddr { 0 | 1 }\n");
	return -1;
}

static int
call_qcsapi_get_3addr_br_config(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	int qcsapi_retval = -1;
	uint32_t val;
	int radio;
	qcsapi_unsigned_int radio_id = 0;

	if (argc != 1 && argc != 2)
		goto usage_out;

	if (argc == 2) {
		radio = atoi(argv[0]);
		if (radio < 0)
			goto usage_out;
		radio_id = (unsigned int)radio;
		argv++;
	}

	if (strcmp(argv[0], "dhcp_chaddr") != 0)
		goto usage_out;

	qcsapi_retval = qcsapi_radio_get_3addr_br_config(radio_id,
		e_qcsapi_3addr_br_dhcp_chaddr, &val);
	if (qcsapi_retval >= 0) {
		if (val)
			print_out(print, "Enabled\n");
		else
			print_out(print, "Disabled\n");
	}

	return qcsapi_retval;
usage_out:
	print_out(print, "Usage: call_qcsapi get_3addr_br_config [ <radio_id> ] dhcp_chaddr\n");
	return -1;
}

static int
call_qcsapi_get_phy_param(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;
	int retval;
	const char *usage = "<ifname> { custom_mode | slottime | ack_to | difs }";
	char output[1024];

	if (argc < 1) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return 1;
	}

	retval = qcsapi_phy_get_parameter(the_interface, argv[0], output, sizeof(output));

	if (retval < 0) {
		report_qcsapi_error(p_calling_bundle, retval);
		return 1;
	}

	print_out(print, "%s\n", output);

	return 0;
}

static int
call_qcsapi_set_phy_param(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	const char *the_interface = p_calling_bundle->caller_interface;
	const char *usage = "<ifname> <parameter type> <value>";
	int retval;
	const char *param_value1;
	const char *param_value2;

	if ((argc < 2)) {
		qcsapi_report_usage(p_calling_bundle, usage);
		return 1;
	}

	param_value1 = argv[0];
	param_value2 = argv[1];
	retval = qcsapi_phy_set_parameter(the_interface, param_value1, param_value2);

	return	qcsapi_report_complete(p_calling_bundle, retval);
}

static void
call_qcsapi_display_get_pta_param_usage(qcsapi_output *print)
{
	print_out(print, "usage\n");
	print_out(print, "	call_qcsapi get_pta_param <ifname> mode\n");
	print_out(print, "	call_qcsapi get_pta_param <ifname> request_polarity\n");
	print_out(print, "	call_qcsapi get_pta_param <ifname> grant_polarity\n");
	print_out(print, "	call_qcsapi get_pta_param <ifname> request_timeout\n");
	print_out(print, "	call_qcsapi get_pta_param <ifname> grant_timeout\n");
	print_out(print, "	call_qcsapi get_pta_param <ifname> ifs_timeout\n");
}

static int
call_qcsapi_get_pta_param(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;
	const char *param_value1 = NULL;
	int qcsapi_retval = -1;
	char output[1024];

	if (argc < 1) {
		call_qcsapi_display_get_pta_param_usage(print);
		return 1;
	}

	param_value1 = argv[0];
	qcsapi_retval = qcsapi_pta_get_parameter(the_interface,	param_value1, output,
						sizeof(output));

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "%s\n", output);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		return 1;
	}

	return 0;
}

static void
call_qcsapi_display_set_pta_param_usage(qcsapi_output *print)
{
	print_out(print, "usage\n");
	print_out(print, "	call_qcsapi set_pta_param <ifname> mode { 0 | 1 | 2 | 4 }\n");
	print_out(print, "	Note: currently only 2-wire mode is supported\n");
	print_out(print, "	call_qcsapi set_pta_param <ifname> request_polarity { 0 | 1 }\n");
	print_out(print, "	call_qcsapi set_pta_param <ifname> grant_polarity { 0 | 1 }\n");
	print_out(print, "	call_qcsapi set_pta_param <ifname> request_timeout {%d - %d}\n",
			PTA_PARAM_REQ_TIMEOUT_MIN, PTA_PARAM_REQ_TIMEOUT_MAX);
	print_out(print, "	call_qcsapi set_pta_param <ifname> grant_timeout {%d - %d}\n",
			PTA_PARAM_GNT_TIMEOUT_MIN, PTA_PARAM_GNT_TIMEOUT_MAX);
	print_out(print, "	call_qcsapi set_pta_param <ifname> ifs_timeout {%d - %d}\n",
			PTA_PARAM_IFS_TIMEOUT_MIN, PTA_PARAM_IFS_TIMEOUT_MAX);
	print_out(print, "	Note: All timeout values are experimental and "
			"subjected to change in future\n");
}

static int
call_qcsapi_set_pta_param(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;
	int qcsapi_retval = -1;
	const char *param_value1;
	const char *param_value2;

	if ((argc < 2)) {
		call_qcsapi_display_set_pta_param_usage(print);
		return 1;
	}

	param_value1 = argv[0];
	param_value2 = argv[1];
	qcsapi_retval = qcsapi_pta_set_parameter(the_interface,
						param_value1, param_value2);

	return	qcsapi_report_complete(p_calling_bundle, qcsapi_retval);
}

static void
call_qcsapi_display_grab_config_usage(qcsapi_output *print)
{
	print_out(print, "usage\n");
	print_out(print, "	call_qcsapi grab_config <output file>\n");
}

static int
call_qcsapi_grab_config(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	int ret = 0;
	const char *output_path;
	FILE *output_stream = NULL;
	size_t bytes_written = 0;

	if ((argc < 1)) {
		call_qcsapi_display_grab_config_usage(print);
		return 1;
	}

	output_path = argv[0];
	output_stream = fopen(output_path, "w");
	if (output_stream == NULL) {
		print_err(print, "Failed to open %s: %s\n", output_path, strerror(errno));
		ret = -EFAULT;
		goto out;
	}

	print_err(print, "Grabbing config...\n");
	ret = qcsapi_grabber_write_config_blob(output_stream, QCSAPI_GRABBER_PARAM_ALL, &bytes_written);
	if (ret) {
		print_err(print, "Can not write blob to %s\n", output_path);
		goto out;
	}

out:
	if (output_stream)
		fclose(output_stream);

	return qcsapi_report_complete(p_calling_bundle, ret);
}

#define SCSON_SEC_CCA_MAX	-60
#define SCSON_SEC_CCA_MIN	-98
#define SCSOFF_SEC_CCA_MAX	-60
#define SCSOFF_SEC_CCA_MIN	-98

static void
call_qcsapi_display_get_sec_cca_param_usage(qcsapi_output *print)
{
	print_out(print, "usage\n");
	print_out(print, "	call_qcsapi get_sec_cca_param <ifname> <sec CCA bitmap>\n");
}

static int
call_qcsapi_get_sec_cca_param(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;
	int qcsapi_retval = -1;
	int sec_bitmap;
	int statval = 0;
	struct qcsapi_sec_cca_param *sec_cca_param;
	char output[1024];

	if (argc != 1) {
		call_qcsapi_display_get_sec_cca_param_usage(print);
		return 1;
	}

	if (sscanf(argv[0], "%d", &sec_bitmap) != 1)
		return 1;

	if (!(sec_bitmap & QCSAPI_BITMASK_CCA_THR) || (sec_bitmap & ~QCSAPI_BITMASK_CCA_THR)) {
		call_qcsapi_display_get_sec_cca_param_usage(print);
		return 1;
	}

	sec_cca_param = calloc(1, sizeof(struct qcsapi_sec_cca_param));
	if (!sec_cca_param)
		return -ENOMEM;

	qcsapi_retval = qcsapi_sec_cca_get_parameter(the_interface, sec_cca_param);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			if (sec_bitmap == (QCSAPI_BITMAP_CCA_THR_SEC | QCSAPI_BITMAP_CCA_THR_SEC40)) {
				snprintf(output, sizeof(output),
					"CCA thresholds for secondary channel: scs on %d dBm, scs off %d dBm \n"
					"CCA thresholds for secondary40 channel: scs on %d dBm, scs off %d dBm",
					sec_cca_param->scson_sec_thr, sec_cca_param->scsoff_sec_thr,
					sec_cca_param->scson_sec40_thr, sec_cca_param->scsoff_sec40_thr);
			} else if (sec_bitmap == QCSAPI_BITMAP_CCA_THR_SEC40) {
				snprintf(output, sizeof(output),
					"CCA thresholds for secondary40 channel: scs on %d dBm, scs off %d dBm",
					sec_cca_param->scson_sec40_thr, sec_cca_param->scsoff_sec40_thr);
			} else {
				snprintf(output, sizeof(output),
					"CCA thresholds for secondary channel: scs on %d dBm, scs off %d dBm",
					sec_cca_param->scson_sec_thr, sec_cca_param->scsoff_sec_thr);
			}
			print_out(print, "%s\n", output);
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	free(sec_cca_param);
	return statval;
}

static void
call_qcsapi_display_set_sec_cca_param_usage(qcsapi_output *print)
{
	print_out(print, "usage\n");
	print_out(print, "	call_qcsapi set_sec_cca_param <ifname> <sec CCA bitmap> scson <%d...%d> scsoff <%d...%d>\n",
			SCSON_SEC_CCA_MIN, SCSON_SEC_CCA_MAX,
			SCSOFF_SEC_CCA_MIN, SCSOFF_SEC_CCA_MAX);
}

static int
call_qcsapi_set_sec_cca_param(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	qcsapi_output *print = p_calling_bundle->caller_output;
	const char *the_interface = p_calling_bundle->caller_interface;
	int qcsapi_retval = -1;
	int scson_val = 0, scsoff_val = 0;
	int sec_bitmap;

	if ((argc != 5))
		goto usage_out;

	if (sscanf(argv[0], "%d", &sec_bitmap) != 1)
		return 1;

	if (!(sec_bitmap & QCSAPI_BITMASK_CCA_THR) || (sec_bitmap & ~QCSAPI_BITMASK_CCA_THR)) {
		call_qcsapi_display_set_sec_cca_param_usage(print);
		return 1;
	}

	if (strcmp(argv[1], "scson") == 0) {
		if (sscanf(argv[2], "%d", &scson_val) != 1)
			goto usage_out;
		if (scson_val > SCSON_SEC_CCA_MAX || scson_val < SCSON_SEC_CCA_MIN)
			goto usage_out;

	}
	if (strcmp(argv[3], "scsoff") == 0) {
		if (sscanf(argv[4], "%d", &scsoff_val) != 1)
			goto usage_out;
		if (scsoff_val > SCSOFF_SEC_CCA_MAX || scsoff_val < SCSOFF_SEC_CCA_MIN)
			goto usage_out;
	}

	if (!scson_val || !scsoff_val)
		goto usage_out;

	qcsapi_retval = qcsapi_sec_cca_set_parameter(the_interface, sec_bitmap, scson_val,
							scsoff_val);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0) {
			print_out(print, "complete\n");
		}
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
	}

	return qcsapi_retval;
usage_out:
	call_qcsapi_display_set_sec_cca_param_usage(print);
	return -1;
}

static int
call_qcsapi_repeater_mode_cfg(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = -1;
	qcsapi_output *print = p_calling_bundle->caller_output;
	unsigned int for_repeater;

	if (argc != 2)
		goto out;

	if (strcmp(argv[1], "0") == 0)
		for_repeater = 0;
	else if (strcmp(argv[1], "1") == 0)
		for_repeater = 1;
	else
		goto out;

	qcsapi_retval = qcsapi_wifi_repeater_mode_cfg(0, for_repeater);

	if (verbose_flag >= 0) {
		if (qcsapi_retval >= 0) {
			print_out(print, "complete\n");
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		}
	}

	return qcsapi_retval;

out:
	print_out(print, "Usage:\n");
	print_out(print, "      call_qcsapi repeater_mode_cfg <radio_id> { 0 | 1 }\n");
	return -1;
}

struct urepeater_params {
	const char *str;
	qcsapi_urepeater_type type;
	uint16_t is_get;
	uint16_t is_set;
};

static const struct urepeater_params urep_params[] = {
	{ "max_level", qcsapi_urepeater_max_level, 1, 1 },
	{ "curr_level", qcsapi_urepeater_curr_level, 1, 0 }
};

static int
call_qcsapi_set_urepeater_params(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = -1;
	qcsapi_urepeater_type type = qcsapi_urepeater_none;
	uint32_t value;
	int i;
	int ret;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc != 2) {
		qcsapi_report_usage(p_calling_bundle, "<parameter type> <value>\n");
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(urep_params); i++) {
		if (strcmp(argv[0], urep_params[i].str) == 0) {
			if (!urep_params[i].is_set)
				break;

			type = urep_params[i].type;
			break;
		}
	}

	if (type == qcsapi_urepeater_none) {
		print_out(print, "Invalid parameter type \"%s\"\n", argv[0]);
		return -EINVAL;
	}

	ret = local_atou32_verify_numeric_range(argv[1], &value, print, REPEATER_MIN_LEVEL, REPEATER_MAX_LEVEL);
	if (ret < 0) {
		print_out(print, "Invalid parameter value \"%s\"\n", argv[1]);
		return -EINVAL;
	}

	qcsapi_retval = qcsapi_wifi_set_urepeater_params(type, (int)value);

	if (verbose_flag >= 0) {
		if (qcsapi_retval >= 0) {
			print_out(print, "complete\n");
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		}
	}

	return qcsapi_retval;
}

static int
call_qcsapi_get_urepeater_params(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = -1;
	qcsapi_urepeater_type type = qcsapi_urepeater_none;
	int value;
	int i;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle, "<parameter type>\n");
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(urep_params); i++) {
		if (strcmp(argv[0], urep_params[i].str) == 0) {
			if (!urep_params[i].is_get)
				break;

			type = urep_params[i].type;
			break;
		}
	}

	if (type == qcsapi_urepeater_none) {
		print_out(print, "Invalid parameter type \"%s\"\n", argv[0]);
		return -EINVAL;
	}

	qcsapi_retval = qcsapi_wifi_get_urepeater_params(type, &value);

	if (verbose_flag >= 0) {
		if (qcsapi_retval >= 0) {
			print_out(print, "%d\n", value);
		} else {
			report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		}
	}

	return qcsapi_retval;
}

static int
call_qcsapi_set_ac_inheritance(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int retval;
	uint32_t ac_inheritance = 0;
	const char *the_interface = p_calling_bundle->caller_interface;

	retval = qcsapi_util_str_to_uint32(argv[0], &ac_inheritance);

	if (retval >= 0)
		retval = qcsapi_wifi_set_ac_inheritance(the_interface, ac_inheritance);

	return qcsapi_report_complete(p_calling_bundle, retval);
}

static int
call_qcsapi_set_dynamic_wmm(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int retval;
	uint32_t dyn_wmm = 0;
	const char *the_interface = p_calling_bundle->caller_interface;

	retval = qcsapi_util_str_to_uint32(argv[0], &dyn_wmm);

	if (retval >= 0)
		retval = qcsapi_wifi_set_dynamic_wmm(the_interface, dyn_wmm);

	return qcsapi_report_complete(p_calling_bundle, retval);
}

static int
call_qcsapi_wifi_get_restrict_wlan_ip(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	const char *the_interface = p_calling_bundle->caller_interface;

	qcsapi_unsigned_int enable = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	int qcsapi_retval;
	int statval = 0;

	qcsapi_retval = qcsapi_wifi_get_restrict_wlan_ip(the_interface, &enable);

	if (qcsapi_retval >= 0) {
		print_out(print, "%u\n", enable);
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_wifi_set_restrict_wlan_ip(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	const char *the_interface = p_calling_bundle->caller_interface;

	qcsapi_unsigned_int enable = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

	int qcsapi_retval;
	int statval = 0;

	if (local_atou32_verify_numeric_range(argv[0], &enable, print, 0, 1) < 0)
		return 1;

	qcsapi_retval = qcsapi_wifi_set_restrict_wlan_ip(the_interface, enable);

	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		report_qcsapi_error(p_calling_bundle, qcsapi_retval);
		statval = 1;
	}

	return statval;
}

static int
call_qcsapi_get_reboot_cause(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
        qcsapi_unsigned_int value = 0;
        int qcsapi_retval = 0;
        qcsapi_output *print = p_calling_bundle->caller_output;

        qcsapi_retval = qcsapi_system_get_debug_value(QCSAPI_REBOOT_CAUSE, &value);

        if (qcsapi_retval >= 0) {
                print_out(print,"Reboot Cause - %u\n", value);
        } else {
                report_qcsapi_error(p_calling_bundle, qcsapi_retval);
                return 1;
        }

        return 0;
}

static int call_qcsapi_add_wps_pbc_ssid_filter(call_qcsapi_bundle *p_calling_bundle,
						int argc, char *argv[])
{
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	char *wps_pbc_ssid;
	size_t filter_len;
	int retval;
	int i;

	if (argc < 1) {
		qcsapi_report_parameter_count(p_calling_bundle, argc);
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <SSID filter>...");
		return 1;
	}

	for (i = 0; i < argc; i++) {
		wps_pbc_ssid = argv[i];
		filter_len = strlen(wps_pbc_ssid);

		if (filter_len > QCSAPI_SSID_MAXLEN || filter_len < 1) {
			print_err(print, "Not supported filter length for %s\n", wps_pbc_ssid);
			return 1;
		}

		retval = qcsapi_add_wps_pbc_ssid_filter(the_interface, wps_pbc_ssid);
		if (retval < 0) {
			report_qcsapi_error(p_calling_bundle, retval);
			return 1;
		}
	}
	if (verbose_flag >= 0)
		print_out(print, "complete\n");

	return 0;
}

static int call_qcsapi_del_wps_pbc_ssid_filter(call_qcsapi_bundle *p_calling_bundle,
						int argc, char *argv[])
{
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	char *wps_pbc_ssid;
	size_t filter_len;
	int retval;
	int i;

	if (argc < 1) {
		qcsapi_report_parameter_count(p_calling_bundle, argc);
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <SSID filter>...");
		return 1;
	}

	for (i = 0; i < argc; i++) {
		wps_pbc_ssid = argv[i];
		filter_len = strlen(wps_pbc_ssid);

		if (filter_len > QCSAPI_SSID_MAXLEN) {
			print_err(print, "Not supported filter length for %s\n", wps_pbc_ssid);
			return 1;
		}

		retval = qcsapi_del_wps_pbc_ssid_filter(the_interface, wps_pbc_ssid);
		if (retval < 0) {
			report_qcsapi_error(p_calling_bundle, retval);
			return 1;
		}
	}
	if (verbose_flag >= 0)
		print_out(print, "complete\n");

	return 0;
}

static int call_qcsapi_show_wps_pbc_ssid_filters(call_qcsapi_bundle *p_calling_bundle,
						int argc, char *argv[])
{
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	string_512 filters;
	int retval;

	if (argc > 0) {
		qcsapi_report_parameter_count(p_calling_bundle, argc);
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface>");
		return 1;
	}

	memset(filters, 0, sizeof(filters));

	retval = qcsapi_show_wps_pbc_ssid_filters(the_interface, filters);
	if (retval < 0) {
		report_qcsapi_error(p_calling_bundle, retval);
		return 1;
	}
	if (verbose_flag >= 0)
		print_out(print,"WPS PBC SSID filters list: %s\n", filters);

	return 0;
}

static int call_qcsapi_wifi_enable_repeater_ap(call_qcsapi_bundle *p_calling_bundle,
						int argc, char *argv[])
{
	int retval;

	if (argc > 0) {
		qcsapi_report_parameter_count(p_calling_bundle, argc);
		qcsapi_report_usage(p_calling_bundle, "");
		return 1;
	}

	retval = qcsapi_wifi_enable_repeater_ap();
	if (retval < 0) {
		report_qcsapi_error(p_calling_bundle, retval);
		return 1;
	}

	return 0;
}

static int call_qcsapi_wifi_disable_repeater_ap(call_qcsapi_bundle *p_calling_bundle,
						int argc, char *argv[])
{
	int retval;

	if (argc > 0) {
		qcsapi_report_parameter_count(p_calling_bundle, argc);
		qcsapi_report_usage(p_calling_bundle, "");
		return 1;
	}

	retval = qcsapi_wifi_disable_repeater_ap();
	if (retval < 0) {
		report_qcsapi_error(p_calling_bundle, retval);
		return 1;
	}

	return 0;
}

static int call_qcsapi_wifi_multi_psk_info_append(call_qcsapi_bundle *p_calling_bundle,
						int argc, char *argv[])
{
	int retval;

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface> <string>");
		return 1;
	}

	const char *the_interface = p_calling_bundle->caller_interface;

	retval = qcsapi_wifi_multi_psk_info_append(the_interface, argv[0]);

	return qcsapi_report_complete(p_calling_bundle, retval);
}

static int call_qcsapi_wifi_multi_psk_info_read(call_qcsapi_bundle *p_calling_bundle,
						int argc, char *argv[])
{
	int retval;

	if (argc != 0) {
		qcsapi_report_usage(p_calling_bundle, "<WiFi interface>");
		return 1;
	}

	const char *the_interface = p_calling_bundle->caller_interface;
	string_4096 buf;

	retval = qcsapi_wifi_multi_psk_info_read(the_interface, buf);
	if (retval < 0) {
		report_qcsapi_error(p_calling_bundle, retval);
		return 1;
	}

	qcsapi_output *print = p_calling_bundle->caller_output;

	print_out(print, "%s\n", buf);

	return 0;
}

static int call_qcsapi_wifi_multi_psk_info_replace(call_qcsapi_bundle *p_calling_bundle,
						int argc, char *argv[])
{
	int retval;
	const char *buf = NULL;

	if (argc != 0) {
		if (argc == 1) {
			buf = argv[0];
		} else {
			qcsapi_report_usage(p_calling_bundle, "<WiFi interface> [<string>]");
			return 1;
		}
	}

	const char *the_interface = p_calling_bundle->caller_interface;

	retval = qcsapi_wifi_multi_psk_info_replace(the_interface, buf);

	return qcsapi_report_complete(p_calling_bundle, retval);
}

static int
call_qcsapi_wifi_start_phy_scan(call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[])
{
	int qcsapi_retval = 0;
	int statval = 0;
	int index = 0;
	char *tok = NULL;
	const char *the_interface = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;
	uint16_t bw = qcsapi_bw_20MHz;
	string_1024 tmp = {0};
	uint32_t freqs_num = 0;
	struct qcsapi_int_array64 freqs;
	uint32_t *p_freqs = (uint32_t *)freqs.val;
	const char usage[] = "<WiFi interface> [ bw <bw> ] [ freqs <freqs> ]\n";

	if (argc >= 1) {
		for (index = 0; index < (argc - 1); index++) {
			if ((strcmp(argv[index], "bw") == 0) && safe_atou16(argv[index + 1],
						&bw, print, 0, 0xFF))
				index++;
			else if (strcmp(argv[index], "freqs") == 0) {
				strncpy(tmp, argv[index + 1], sizeof(tmp)-1);
				if (!tmp[0])
					break;
				for (tok = strtok(tmp, ","); tok; tok = strtok(NULL, ",")) {
					if (freqs_num >= IEEE80211_MAX_DUAL_CHANNELS)
						break;
					if (qcsapi_util_str_to_uint32(tok, &p_freqs[freqs_num++])) {
						report_qcsapi_error(p_calling_bundle, -EINVAL);
						return 1;
					}
				}
				index++;
			} else
				break;
		}

		if (index < argc) {
			qcsapi_report_usage(p_calling_bundle, usage);
			return 1;
		}
	}

	qcsapi_retval = qcsapi_wifi_start_phy_scan(the_interface, bw, &freqs, freqs_num);
	if (qcsapi_retval >= 0) {
		if (verbose_flag >= 0)
			print_out(print, "complete\n");
	} else {
		qcsapi_report_usage(p_calling_bundle, usage);
		statval = 1;
	}

	return statval;
}

static int call_qcsapi_wifi_get_chan_phy_info(call_qcsapi_bundle *p_calling_bundle,
						int argc, char *argv[])
{
	int retval = 0;
	int i = 0;
	int count = 0;
	int getall = 0;
	int should_cont = 0;
	int len_left = 0;
	unsigned int total_no = 0;
	char *p_end;
	struct qcsapi_data_256bytes chan_list;
	struct qcsapi_chan_phy_info *phy_info;
	struct qcsapi_chan_phy_stats *phy_stats, *p_offset;
	const char *ifname = p_calling_bundle->caller_interface;
	qcsapi_output *print = p_calling_bundle->caller_output;

	if (argc != 1) {
		qcsapi_report_usage(p_calling_bundle,
				"<WiFi interface> <channel list | all>\n");
		return 1;
	}

	if (strcmp(argv[0], "all") == 0) {
		getall = 1;
	} else {
		memset(&chan_list, 0, sizeof(chan_list));
		retval = local_string_to_list(argv[0], chan_list.data, &total_no);
		if (retval < 0) {
			print_err(print, "Invalid channel list\n");
			return 1;
		}
	}

	phy_info = (struct qcsapi_chan_phy_info *)
			malloc(sizeof(struct qcsapi_data_1Kbytes));
	if (!phy_info) {
		print_err(print, "Not enough memory to execute the API\n");
		return 1;
	}

	do {
		memset(phy_info, 0, sizeof(struct qcsapi_data_1Kbytes));

		if (getall) {
			phy_info->flag |= QCSAPI_CHAN_PHY_STATS_GET_ALL;
		} else {
			p_end = (char *)phy_info + sizeof(struct qcsapi_data_1Kbytes);
			p_offset = phy_info->phy_stats + 1;

			i = 0;
			do {
				phy_info->phy_stats[i].chan_no = chan_list.data[count];
				i++;
				count++;
				p_offset++;
			} while ((char *)p_offset <= p_end && count < total_no);

			phy_info->num = i;
		}

		retval = qcsapi_wifi_get_chan_phy_info(ifname,
				(struct qcsapi_data_1Kbytes *)phy_info);

		if (retval >= 0) {
			if (verbose_flag >= 0) {
				len_left = sizeof(struct qcsapi_data_1Kbytes) -
						sizeof(struct qcsapi_chan_phy_info);
				for (i = 0; i < phy_info->num; i++) {
					if (len_left < sizeof(struct qcsapi_chan_phy_stats))
						break;
					phy_stats = &phy_info->phy_stats[i];

					if (phy_stats->flag & QCSAPI_CHAN_PHY_STATS_READY)
						print_out(print, "chan_no=%d, flag=%d, bw=%d, "
							"busy_20=%d, busy_40=%d, busy_80=%d, "
							"tx_20=%d, rx_20=%d, rx_others_20=%d, "
							"scan_typ=%s, scan_age=%d, noise_20=%d, "
							"aggr_scan_duration=%d\n",
							phy_stats->chan_no, phy_stats->flag,
							phy_stats->bandwidth, phy_stats->busy_20,
							phy_stats->busy_40, phy_stats->busy_80,
							phy_stats->tx_20, phy_stats->rx_20,
							phy_stats->rx_others_20,
							phy_stats->scan_type ==
								QCSAPI_PHY_STATS_SCAN_TYPE_ACTIVE ?
								"active" : "passive",
							phy_stats->scan_age, phy_stats->noise_20,
							phy_stats->aggr_scan_duration);
					else
						print_out(print, "Stats of chan %d is not ready\n",
								phy_stats->chan_no);

					len_left -= sizeof(struct qcsapi_chan_phy_stats);
				}
			}
		} else {
			report_qcsapi_error(p_calling_bundle, retval);
			free(phy_info);
			return 1;
		}

		if (getall)
			should_cont = phy_info->status & QCSAPI_CHAN_PHY_STATS_MORE;
		else
			should_cont = count < total_no;
	} while (should_cont);

	free(phy_info);
	return 0;
}
/* end of programs to call individual QCSAPIs */

static int
call_particular_qcsapi( call_qcsapi_bundle *p_calling_bundle, int argc, char *argv[] )
{
	int	statval = 0;
	qcsapi_output *print = p_calling_bundle->caller_output;

  /*
   * Interface programs that SET a parameter require the
   * current list of arguments to get additional parameters
   */
	switch (p_calling_bundle->caller_qcsapi)
	{
	  case e_qcsapi_errno_get_message:
		statval = call_qcsapi_errno_get_message( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_store_ipaddr:
		statval = call_qcsapi_store_ipaddr( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_set_ip_route:
		statval = call_qcsapi_set_ip_route( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_get_ip_route:
		statval = call_qcsapi_get_ip_route( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_set_ip_dns:
		statval = call_qcsapi_set_ip_dns( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_get_ip_dns:
		statval = call_qcsapi_get_ip_dns( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_get_stored_ipaddr:
		statval = call_qcsapi_get_stored_ipaddr( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_interface_enable:
		statval = call_qcsapi_interface_enable( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_interface_get_BSSID:
		statval = call_qcsapi_interface_get_BSSID( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_interface_get_mac_addr:
		statval = call_qcsapi_interface_get_mac_addr( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_interface_set_mac_addr:
		statval = call_qcsapi_interface_set_mac_addr( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_interface_get_counter:
		statval = call_qcsapi_interface_get_counter( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_interface_get_counter64:
		statval = call_qcsapi_interface_get_counter64( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_flash_image_update:
		statval = call_qcsapi_flash_image_update( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_firmware_get_version:
		statval = call_qcsapi_firmware_get_version( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_system_get_time_since_start:
		statval = call_qcsapi_system_get_time_since_start( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_get_system_status:
		statval = call_qcsapi_get_system_status( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_get_random_seed:
		statval = call_qcsapi_get_random_seed( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_set_random_seed:
		statval = call_qcsapi_set_random_seed( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_led_get:
		statval = call_qcsapi_led_get( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_led_set:
		statval = call_qcsapi_led_set( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_led_pwm_enable:
		statval = call_qcsapi_led_pwm_enable( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_led_brightness:
		statval = call_qcsapi_led_brightness( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_gpio_get_config:
		statval = call_qcsapi_gpio_get_config( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_gpio_set_config:
		statval = call_qcsapi_gpio_set_config( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_gpio_enable_wps_push_button:
		statval = call_qcsapi_gpio_enable_wps_push_button( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_file_path_get_config:
		statval = call_qcsapi_file_path_get_config( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_file_path_set_config:
		statval = call_qcsapi_file_path_set_config( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_wifi_macaddr:
		statval = call_qcsapi_wifi_set_wifi_macaddr( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_create_restricted_bss:
		statval = call_qcsapi_wifi_create_restricted_bss(p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_create_bss:
		statval = call_qcsapi_wifi_create_bss(p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_remove_bss:
		statval = call_qcsapi_wifi_remove_bss(p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_primary_interface:
		statval = call_qcsapi_wifi_get_primary_interface(p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_interface_by_index:
		statval = call_qcsapi_wifi_get_interface_by_index(p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_interface_by_index_all:
		statval = call_qcsapi_wifi_get_interface_by_index_all(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_mode:
		statval = call_qcsapi_wifi_get_mode( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_mode:
		statval = call_qcsapi_wifi_set_mode( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_phy_mode:
		statval = call_qcsapi_wifi_get_phy_mode( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_phy_mode:
		statval = call_qcsapi_wifi_set_phy_mode( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_reload_in_mode:
		statval = call_qcsapi_wifi_reload_in_mode( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_rfenable:
		statval = call_qcsapi_wifi_rfenable( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_rfstatus:
		statval = call_qcsapi_wifi_rfstatus( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_startprod:
		statval = call_qcsapi_wifi_startprod( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_bw:
		statval = call_qcsapi_wifi_get_bw( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_bw:
		statval = call_qcsapi_wifi_set_bw( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_24g_bw:
		statval = call_qcsapi_wifi_get_24g_bw( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_24g_bw:
		statval = call_qcsapi_wifi_set_24g_bw( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_freq_bands:
		statval = call_qcsapi_wifi_get_supported_freq_bands( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_noise:
		statval = call_qcsapi_wifi_get_noise( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_rssi_by_chain:
		statval = call_qcsapi_wifi_get_rssi_by_chain( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_avg_snr:
		statval = call_qcsapi_wifi_get_avg_snr( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_BSSID:
		statval = call_qcsapi_wifi_get_BSSID( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_config_BSSID:
		statval = call_qcsapi_wifi_get_config_BSSID( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_ssid_get_bssid:
		statval = call_qcsapi_wifi_ssid_get_bssid( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_ssid_set_bssid:
		statval = call_qcsapi_wifi_ssid_set_bssid( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_SSID:
		statval = call_qcsapi_wifi_get_SSID( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_SSID:
		statval = call_qcsapi_wifi_set_SSID( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_scan_SSID_cfg:
		statval = call_qcsapi_wifi_get_scan_SSID_cfg( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_scan_SSID_cfg:
		statval = call_qcsapi_wifi_set_scan_SSID_cfg( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_channel:
		statval = call_qcsapi_wifi_get_channel( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_channel:
		statval = call_qcsapi_wifi_set_channel( p_calling_bundle, argc, argv );
		break;

	case e_qcsapi_wifi_get_channel_and_bw:
		statval = call_qcsapi_wifi_get_channel_and_bw(p_calling_bundle, argc, argv);
		break;

	case e_qcsapi_wifi_set_channel_and_bw:
		statval = call_qcsapi_wifi_set_channel_and_bw(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_wea_cac_en:
		statval = call_qcsapi_wifi_set_wea_cac_en(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_auto_channel:
		statval = call_qcsapi_wifi_get_auto_channel( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_auto_channel:
		statval = call_qcsapi_wifi_set_auto_channel( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_standard:
		statval = call_qcsapi_wifi_get_standard( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_dtim:
		statval = call_qcsapi_wifi_get_dtim( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_dtim:
		statval = call_qcsapi_wifi_set_dtim( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_assoc_limit:
		statval = call_qcsapi_wifi_get_assoc_limit( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_assoc_limit:
		statval = call_qcsapi_wifi_set_assoc_limit( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_bss_assoc_limit:
		statval = call_qcsapi_wifi_get_bss_assoc_limit( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_bss_assoc_limit:
		statval = call_qcsapi_wifi_set_bss_assoc_limit( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_SSID_group_id:
		statval = call_qcsapi_wifi_set_SSID_group_id( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_SSID_group_id:
		statval = call_qcsapi_wifi_get_SSID_group_id( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_SSID_assoc_reserve:
		statval = call_qcsapi_wifi_set_SSID_assoc_reserve( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_SSID_assoc_reserve:
		statval = call_qcsapi_wifi_get_SSID_assoc_reserve( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_interface_get_status:
		statval = call_qcsapi_interface_get_status( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_pm_get_counter:
		statval = call_qcsapi_pm_get_counter( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_pm_get_elapsed_time:
		statval = call_qcsapi_pm_get_elapsed_time( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_interface_set_ip4:
		statval = call_qcsapi_interface_set_ip4( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_interface_get_ip4:
		statval = call_qcsapi_interface_get_ip4(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_interface_set_mtu:
		statval = call_qcsapi_interface_set_mtu(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_interface_get_mtu:
		statval = call_qcsapi_interface_get_mtu(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_list_channels:
		statval = call_qcsapi_wifi_get_list_channels( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_supp_chans:
		statval = call_qcsapi_wifi_get_supp_chans( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_mode_switch:
		statval = call_qcsapi_wifi_get_mode_switch( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_option:
		statval = call_qcsapi_wifi_get_option( p_calling_bundle, argc, argv );
		break;

	 case e_qcsapi_get_board_parameter:
		statval = call_qcsapi_get_board_parameter( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_option:
		statval = call_qcsapi_wifi_set_option( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_rates:
		statval = call_qcsapi_wifi_get_rates( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_rates:
		statval = call_qcsapi_wifi_set_rates( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_max_bitrate:
		statval = call_qcsapi_wifi_get_max_bitrate( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_max_bitrate:
		statval = call_qcsapi_wifi_set_max_bitrate( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_beacon_type:
		statval = call_qcsapi_wifi_get_beacon_type( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_beacon_type:
		statval = call_qcsapi_wifi_set_beacon_type( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_beacon_interval:
		statval = call_qcsapi_wifi_get_beacon_interval(  p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_beacon_interval:
		statval = call_qcsapi_wifi_set_beacon_interval(  p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_list_regulatory_regions:
		statval = call_qcsapi_wifi_get_list_regulatory_regions( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_regulatory_tx_power:
		statval = call_qcsapi_wifi_get_regulatory_tx_power( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_configured_tx_power:
		statval = call_qcsapi_wifi_get_configured_tx_power( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_regulatory_channel:
		statval = call_qcsapi_wifi_set_regulatory_channel( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_regulatory_region:
		statval = call_qcsapi_wifi_set_regulatory_region( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_restore_regulatory_tx_power:
		statval = call_qcsapi_wifi_restore_regulatory_tx_power( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_regulatory_region:
		statval = call_qcsapi_wifi_get_regulatory_region( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_overwrite_country_code:
		statval = call_qcsapi_wifi_overwrite_country_code( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_list_regulatory_channels:
		statval = call_qcsapi_wifi_get_list_regulatory_channels( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_list_regulatory_bands:
		statval = call_qcsapi_wifi_get_list_regulatory_bands( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_regulatory_db_version:
		statval = call_qcsapi_wifi_get_regulatory_db_version( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_regulatory_tx_power_cap:
		statval = call_qcsapi_wifi_set_regulatory_tx_power_cap( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_chan_pri_inactive:
		statval = call_qcsapi_wifi_set_chan_pri_inactive( p_calling_bundle, argc, argv );
		break;
	  case e_qcsapi_wifi_get_chan_pri_inactive:
		statval = call_qcsapi_wifi_get_chan_pri_inactive( p_calling_bundle, argc, argv );
		break;
	  case e_qcsapi_wifi_set_dfs_s_radio_chan_off:
		statval = call_qcsapi_wifi_set_dfs_s_radio_chan_off(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_dfs_s_radio_chan_off:
		statval = call_qcsapi_wifi_get_dfs_s_radio_chan_off(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_chan_disabled:
		statval = call_qcsapi_wifi_set_chan_disabled( p_calling_bundle, argc, argv );
		break;
	  case e_qcsapi_wifi_get_chan_disabled:
		statval = call_qcsapi_wifi_get_chan_disabled( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_tx_power:
		statval = call_qcsapi_wifi_get_tx_power( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_tx_power:
		statval = call_qcsapi_wifi_set_tx_power( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_tx_power_ext:
		statval = call_qcsapi_wifi_get_tx_power_ext( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_tx_power_ext:
		statval = call_qcsapi_wifi_set_tx_power_ext( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_reg_chan_txpower_set:
		statval = call_qcsapi_reg_chan_txpower_set( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_reg_chan_txpower_get:
		statval = call_qcsapi_reg_chan_txpower_get( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_chan_power_table:
		statval = call_qcsapi_wifi_set_chan_power_table( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_bw_power:
		statval = call_qcsapi_wifi_get_bw_power( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_bw_power:
		statval = call_qcsapi_wifi_set_bw_power( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_bf_power:
		statval = call_qcsapi_wifi_get_bf_power( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_bf_power:
		statval = call_qcsapi_wifi_set_bf_power( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_power_selection:
		statval = call_qcsapi_wifi_get_power_selection( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_power_selection:
		statval = call_qcsapi_wifi_set_power_selection( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_carrier_interference:
		statval = call_qcsapi_wifi_get_carrier_interference( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_congestion_idx:
		statval = call_qcsapi_wifi_get_congestion_idx( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_supported_tx_power_levels:
		statval = call_qcsapi_wifi_get_supported_tx_power_levels( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_current_tx_power_level:
		statval = call_qcsapi_wifi_get_current_tx_power_level( p_calling_bundle, argc, argv );
		break;
	  case e_qcsapi_wifi_set_current_tx_power_level:
		statval = call_qcsapi_wifi_set_current_tx_power_level( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_power_constraint:
		statval = call_qcsapi_wifi_set_power_constraint( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_power_constraint:
		statval = call_qcsapi_wifi_get_power_constraint( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_tpc_interval:
		statval = call_qcsapi_wifi_set_tpc_interval( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_tpc_interval:
		statval = call_qcsapi_wifi_get_tpc_interval( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_assoc_records:
		statval = call_qcsapi_wifi_get_assoc_records(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_disassoc_records:
		statval = call_qcsapi_wifi_get_disassoc_records(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_list_DFS_channels:
		statval = call_qcsapi_wifi_get_list_DFS_channels( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_is_channel_DFS:
		statval = call_qcsapi_wifi_is_channel_DFS( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_DFS_alt_channel:
		statval = call_qcsapi_wifi_get_DFS_alt_channel( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_DFS_alt_channel:
		statval = call_qcsapi_wifi_set_DFS_alt_channel( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_DFS_reentry:
		statval = call_qcsapi_wifi_set_dfs_reentry( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_scs_cce_channels:
		statval = call_qcsapi_wifi_get_scs_cce_channels( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_dfs_cce_channels:
		statval = call_qcsapi_wifi_get_dfs_cce_channels( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_csw_records:
		statval = call_qcsapi_wifi_get_csw_records( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_radar_status:
		statval = call_qcsapi_wifi_get_radar_status( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_WEP_encryption_level:
		statval = call_qcsapi_wifi_get_WEP_encryption_level( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_WPA_encryption_modes:
		statval = call_qcsapi_wifi_get_WPA_encryption_modes( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_WPA_encryption_modes:
		statval = call_qcsapi_wifi_set_WPA_encryption_modes( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_WPA_authentication_mode:
		statval = call_qcsapi_wifi_get_WPA_authentication_mode( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_WPA_authentication_mode:
		statval = call_qcsapi_wifi_set_WPA_authentication_mode( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_interworking:
		statval = call_qcsapi_wifi_get_interworking( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_interworking:
		statval = call_qcsapi_wifi_set_interworking( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_80211u_params:
		statval = call_qcsapi_wifi_get_80211u_params( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_80211u_params:
		statval = call_qcsapi_wifi_set_80211u_params( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_get_nai_realms:
		statval = call_qcsapi_security_get_nai_realms( p_calling_bundle, argc, argv );
		break;

	case e_qcsapi_wifi_get_params:
		statval = call_qcsapi_wifi_get_params(p_calling_bundle, argc, argv);
		break;

	case e_qcsapi_wifi_set_params:
		statval = call_qcsapi_wifi_set_params(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_security_add_nai_realm:
		statval = call_qcsapi_security_add_nai_realm( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_del_nai_realm:
		statval = call_qcsapi_security_del_nai_realm( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_add_roaming_consortium:
		statval = call_qcsapi_security_add_roaming_consortium( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_del_roaming_consortium:
		statval = call_qcsapi_security_del_roaming_consortium( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_get_roaming_consortium:
		statval = call_qcsapi_security_get_roaming_consortium( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_get_venue_name:
		statval = call_qcsapi_security_get_venue_name( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_add_venue_name:
		statval = call_qcsapi_security_add_venue_name( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_del_venue_name:
		statval = call_qcsapi_security_del_venue_name( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_get_oper_friendly_name:
		statval = call_qcsapi_security_get_oper_friendly_name( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_add_oper_friendly_name:
		statval = call_qcsapi_security_add_oper_friendly_name( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_del_oper_friendly_name:
		statval = call_qcsapi_security_del_oper_friendly_name( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_get_hs20_conn_capab:
		statval = call_qcsapi_security_get_hs20_conn_capab( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_add_hs20_conn_capab:
		statval = call_qcsapi_security_add_hs20_conn_capab( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_del_hs20_conn_capab:
		statval = call_qcsapi_security_del_hs20_conn_capab( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_add_hs20_icon:
		statval = call_qcsapi_security_add_hs20_icon( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_get_hs20_icon:
		statval = call_qcsapi_security_get_hs20_icon( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_del_hs20_icon:
		statval = call_qcsapi_security_del_hs20_icon( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_add_osu_server_uri:
		statval = call_qcsapi_security_add_osu_server_uri( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_get_osu_server_uri:
		statval = call_qcsapi_security_get_osu_server_uri( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_del_osu_server_uri:
		statval = call_qcsapi_security_del_osu_server_uri( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_add_osu_server_param:
		statval = call_qcsapi_security_add_osu_server_param( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_get_osu_server_param:
		statval = call_qcsapi_security_get_osu_server_param( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_security_del_osu_server_param:
		statval = call_qcsapi_security_del_osu_server_param( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_hs20_status:
		statval = call_qcsapi_wifi_get_hs20_status( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_hs20_status:
		statval = call_qcsapi_wifi_set_hs20_status( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_hs20_params:
		statval = call_qcsapi_wifi_get_hs20_params( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_hs20_params:
		statval = call_qcsapi_wifi_set_hs20_params( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_remove_11u_param:
		statval = call_qcsapi_remove_11u_param( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_remove_hs20_param:
		statval = call_qcsapi_remove_hs20_param( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_proxy_arp:
		statval = call_qcsapi_wifi_set_proxy_arp( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_proxy_arp:
		statval = call_qcsapi_wifi_get_proxy_arp( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_l2_ext_filter:
		statval = call_qcsapi_wifi_get_l2_ext_filter( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_l2_ext_filter:
		statval = call_qcsapi_wifi_set_l2_ext_filter( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_IEEE11i_encryption_modes:
		statval = call_qcsapi_wifi_get_IEEE11i_encryption_modes( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_IEEE11i_encryption_modes:
		statval = call_qcsapi_wifi_set_IEEE11i_encryption_modes( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_IEEE11i_authentication_mode:
		statval = call_qcsapi_wifi_get_IEEE11i_authentication_mode( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_IEEE11i_authentication_mode:
		statval = call_qcsapi_wifi_set_IEEE11i_authentication_mode( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_michael_errcnt:
		statval = call_qcsapi_wifi_get_michael_errcnt( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_pre_shared_key:
		statval = call_qcsapi_wifi_get_pre_shared_key( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_pre_shared_key:
		statval = call_qcsapi_wifi_set_pre_shared_key( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_psk_auth_failures:
		statval = call_qcsapi_wifi_get_psk_auth_failures( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_key_passphrase:
		statval = call_qcsapi_wifi_get_key_passphrase( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_key_passphrase:
		statval = call_qcsapi_wifi_set_key_passphrase( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_group_key_interval:
		statval = call_qcsapi_wifi_get_group_key_interval( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_group_key_interval:
		statval = call_qcsapi_wifi_set_group_key_interval( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_pairwise_key_interval:
		statval = call_qcsapi_wifi_get_pairwise_key_interval( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_pairwise_key_interval:
		statval = call_qcsapi_wifi_set_pairwise_key_interval( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_pmf:
		statval = call_qcsapi_wifi_get_pmf( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_pmf:
		statval = call_qcsapi_wifi_set_pmf( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_SSID_get_wps_SSID:
		statval = call_qcsapi_SSID_get_wps_SSID( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_vlan_config:
		statval = call_qcsapi_wifi_vlan_config( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_show_vlan_config:
		statval = call_qcsapi_wifi_show_vlan_config( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_br_vlan_promisc:
		statval = call_qcsapi_enable_vlan_promisc( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_add_multicast:
		statval = call_qcsapi_set_multicast(p_calling_bundle, 1, argc, argv);
		break;

	  case e_qcsapi_del_multicast:
		statval = call_qcsapi_set_multicast(p_calling_bundle, 0, argc, argv);
		break;

	  case e_qcsapi_get_multicast_list:
		statval = call_qcsapi_get_multicast_list(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_add_ipff:
		statval = call_qcsapi_set_ipff( p_calling_bundle, 1, argc, argv );
		break;

	  case e_qcsapi_del_ipff:
		statval = call_qcsapi_set_ipff( p_calling_bundle, 0, argc, argv );
		break;

	  case e_qcsapi_get_ipff:
		statval = call_qcsapi_get_ipff( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_rts_threshold:
		statval = call_qcsapi_wifi_get_rts_threshold( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_rts_threshold:
		statval = call_qcsapi_wifi_set_rts_threshold( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_mac_address_filtering:
		statval = call_qcsapi_wifi_get_mac_address_filtering( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_mac_address_filtering:
		statval = call_qcsapi_wifi_set_mac_address_filtering( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_is_mac_address_authorized:
		statval = call_qcsapi_wifi_is_mac_address_authorized( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_authorized_mac_addresses:
		statval = call_qcsapi_wifi_get_authorized_mac_addresses( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_denied_mac_addresses:
		statval = call_qcsapi_wifi_get_denied_mac_addresses( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_authorize_mac_address:
		statval = call_qcsapi_wifi_authorize_mac_address( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_authorize_mac_address_ext:
		statval = call_qcsapi_wifi_authorize_mac_address_ext( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_deny_mac_address:
		statval = call_qcsapi_wifi_deny_mac_address( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_deny_mac_address_ext:
		statval = call_qcsapi_wifi_deny_mac_address_ext( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_remove_mac_address:
		statval = call_qcsapi_wifi_remove_mac_address( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_remove_mac_address_ext:
		statval = call_qcsapi_wifi_remove_mac_address_ext( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_clear_mac_address_filters:
		statval = call_qcsapi_wifi_clear_mac_address_filters( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_add_temp_acl_macaddr:
		statval = call_qcsapi_wifi_add_temp_acl_macaddr( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_del_temp_acl_macaddr:
		statval = call_qcsapi_wifi_del_temp_acl_macaddr( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_mac_address_reserve:
		statval = call_qcsapi_wifi_set_mac_address_reserve( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_mac_address_reserve:
		statval = call_qcsapi_wifi_get_mac_address_reserve( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_clear_mac_address_reserve:
		statval = call_qcsapi_wifi_clear_mac_address_reserve( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_backoff_fail_max:
		statval = call_qcsapi_wifi_backoff_fail_max( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_backoff_timeout:
		statval = call_qcsapi_wifi_backoff_timeout( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_registrar_report_button_press:
		statval = call_qcsapi_wps_registrar_report_button_press( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_registrar_report_pin:
		statval = call_qcsapi_wps_registrar_report_pin( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_registrar_get_pp_devname:
		statval = call_qcsapi_wps_registrar_get_pp_devname( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_registrar_set_pp_devname:
		statval = call_qcsapi_wps_registrar_set_pp_devname( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_enrollee_report_button_press:
		statval = call_qcsapi_wps_enrollee_report_button_press( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_enrollee_report_pin:
		statval = call_qcsapi_wps_enrollee_report_pin( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_enrollee_generate_pin:
		statval = call_qcsapi_wps_enrollee_generate_pin( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_get_sta_pin:
		statval = call_qcsapi_wps_generate_random_pin( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_get_ap_pin:
		statval = call_qcsapi_wps_get_ap_pin( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_set_ap_pin:
		statval = call_qcsapi_wps_set_ap_pin( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_save_ap_pin:
		statval = call_qcsapi_wps_save_ap_pin( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_enable_ap_pin:
		statval = call_qcsapi_wps_enable_ap_pin( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_configure_ap:
		statval = call_qcsapi_wps_configure_ap( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_get_state:
		statval = call_qcsapi_wps_get_state( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_get_configured_state:
		statval = call_qcsapi_wps_get_configured_state( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_set_configured_state:
		statval = call_qcsapi_wps_set_configured_state( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_get_runtime_state:
		statval = call_qcsapi_wps_get_runtime_state( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_allow_pbc_overlap:
		statval = call_qcsapi_wps_allow_pbc_overlap( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_get_allow_pbc_overlap_status:
		statval = call_qcsapi_wps_get_allow_pbc_overlap_status( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_get_param:
		statval = call_qcsapi_wps_get_param( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_set_param:
		statval = call_qcsapi_wps_set_param( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_set_access_control:
		statval = call_qcsapi_wps_set_access_control( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_get_access_control:
		statval = call_qcsapi_wps_get_access_control( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_non_wps_set_pp_enable:
		statval = call_qcsapi_non_wps_set_pp_enable( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_non_wps_get_pp_enable:
		statval = call_qcsapi_non_wps_get_pp_enable( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_cancel:
		statval = call_qcsapi_wps_cancel(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wps_set_pbc_in_srcm:
		statval = call_qcsapi_wps_set_pbc_in_srcm(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wps_get_pbc_in_srcm:
		statval = call_qcsapi_wps_get_pbc_in_srcm(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wps_timeout:
		statval = call_qcsapi_wps_set_timeout(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wps_on_hidden_ssid:
		statval = call_qcsapi_wps_on_hidden_ssid(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wps_on_hidden_ssid_status:
		statval = call_qcsapi_wps_on_hidden_ssid_status(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wps_upnp_enable:
		statval = call_qcsapi_wps_upnp_enable(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wps_upnp_status:
		statval = call_qcsapi_wps_upnp_status(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wps_registrar_set_dfl_pbc_bss:
		statval = call_qcsapi_wps_registrar_set_dfl_pbc_bss( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_registrar_get_dfl_pbc_bss:
		statval = call_qcsapi_wps_registrar_get_dfl_pbc_bss( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wps_set_dfl_pbc_bss:
		statval = call_qcsapi_wps_set_dfl_pbc_bss(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wps_get_dfl_pbc_bss:
		statval = call_qcsapi_wps_get_dfl_pbc_bss(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_wpa_status:
		statval = call_qcsapi_wifi_get_wpa_status( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_auth_state:
		statval = call_qcsapi_wifi_get_auth_state( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_disconn_info:
		statval = call_qcsapi_wifi_get_disconn_info( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_reset_disconn_info:
		statval = call_qcsapi_wifi_reset_disconn_info( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_dwell_times:
		statval = call_qcsapi_wifi_set_dwell_times( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_dwell_times:
		statval = call_qcsapi_wifi_get_dwell_times( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_bgscan_dwell_times:
		statval = call_qcsapi_wifi_set_bgscan_dwell_times( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_bgscan_dwell_times:
		statval = call_qcsapi_wifi_get_bgscan_dwell_times( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_count_associations:
		statval = call_qcsapi_wifi_get_count_associations( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_associated_device_mac_addr:
		statval = call_qcsapi_wifi_get_associated_device_mac_addr( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_associated_device_ip_addr:
		statval = call_qcsapi_wifi_get_associated_device_ip_addr(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_link_quality:
		statval = call_qcsapi_wifi_get_link_quality( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_rssi_per_association:
		statval = call_qcsapi_wifi_get_rssi_per_association( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_rssi_in_dbm_per_association:
		statval = call_qcsapi_wifi_get_rssi_in_dbm_per_association( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_snr_per_association:
		statval = call_qcsapi_wifi_get_snr_per_association( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_hw_noise_per_association:
		statval = call_qcsapi_wifi_get_hw_noise_per_association( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_rx_bytes_per_association:
		statval = call_qcsapi_wifi_get_rx_bytes_per_association( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_tx_bytes_per_association:
		statval = call_qcsapi_wifi_get_tx_bytes_per_association( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_rx_packets_per_association:
		statval = call_qcsapi_wifi_get_rx_packets_per_association( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_tx_packets_per_association:
		statval = call_qcsapi_wifi_get_tx_packets_per_association( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_tx_err_packets_per_association:
		statval = call_qcsapi_wifi_get_tx_err_packets_per_association( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_bw_per_association:
		statval = call_qcsapi_wifi_get_bw_per_association( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_tx_phy_rate_per_association:
		call_qcsapi_wifi_get_tx_phy_rate_per_association(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_rx_phy_rate_per_association:
		call_qcsapi_wifi_get_rx_phy_rate_per_association(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_tx_mcs_per_association:
		call_qcsapi_wifi_get_tx_mcs_per_association(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_rx_mcs_per_association:
		call_qcsapi_wifi_get_rx_mcs_per_association(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_achievable_tx_phy_rate_per_association:
		call_qcsapi_wifi_get_achievable_tx_phy_rate_per_association( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_achievable_rx_phy_rate_per_association:
		call_qcsapi_wifi_get_achievable_rx_phy_rate_per_association( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_auth_enc_per_association:
		call_qcsapi_wifi_get_auth_enc_per_association( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_tput_caps:
		call_qcsapi_wifi_get_tput_caps(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_connection_mode:
		call_qcsapi_wifi_get_connection_mode(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_vendor_per_association:
		call_qcsapi_wifi_get_vendor_per_association( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_max_mimo:
		call_qcsapi_wifi_get_max_mimo( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_node_counter:
		statval = call_qcsapi_wifi_get_node_counter(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_node_param:
		statval = call_qcsapi_wifi_get_node_param(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_node_stats:
		statval = call_qcsapi_wifi_get_node_stats(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_node_infoset:
		statval = call_qcsapi_wifi_get_node_infoset(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_node_infoset_all:
		statval = call_qcsapi_wifi_get_node_infoset_all(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_max_queued:
		statval = call_qcsapi_wifi_get_max_queued(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_disassociate:
		statval = call_qcsapi_wifi_disassociate(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_disassociate_sta:
		statval = call_qcsapi_wifi_disassociate_sta(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_reassociate:
		statval = call_qcsapi_wifi_reassociate(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_associate:
		statval = call_qcsapi_wifi_associate(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_associate_noscan:
		statval = call_qcsapi_wifi_associate_noscan(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_update_bss_cfg:
		statval = call_qcsapi_wifi_update_bss_cfg(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_bss_cfg:
		statval = call_qcsapi_wifi_get_bss_cfg(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_SSID_create_SSID:
		statval = call_qcsapi_SSID_create_SSID( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_SSID_remove_SSID:
		statval = call_qcsapi_SSID_remove_SSID( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_SSID_verify_SSID:
		statval = call_qcsapi_SSID_verify_SSID( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_SSID_rename_SSID:
		statval = call_qcsapi_SSID_rename_SSID( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_SSID_get_SSID_list:
		statval = call_qcsapi_SSID_get_SSID_list( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_SSID_get_protocol:
		statval = call_qcsapi_SSID_get_protocol( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_SSID_get_encryption_modes:
		statval = call_qcsapi_SSID_get_encryption_modes( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_SSID_get_group_encryption:
		statval = call_qcsapi_SSID_get_group_encryption( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_SSID_get_authentication_mode:
		statval = call_qcsapi_SSID_get_authentication_mode( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_SSID_set_protocol:
		statval = call_qcsapi_SSID_set_protocol( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_SSID_set_encryption_modes:
		statval = call_qcsapi_SSID_set_encryption_modes( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_SSID_set_group_encryption:
		statval = call_qcsapi_SSID_set_group_encryption( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_SSID_set_authentication_mode:
		statval = call_qcsapi_SSID_set_authentication_mode( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_SSID_get_pre_shared_key:
		statval = call_qcsapi_SSID_get_pre_shared_key( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_SSID_set_pre_shared_key:
		statval = call_qcsapi_SSID_set_pre_shared_key( p_calling_bundle, argc, argv );
		break;

	case e_qcsapi_wifi_add_radius_auth_server_cfg:
		statval = call_qcsapi_wifi_add_radius_auth_server_cfg( p_calling_bundle, argc, argv );
		break;

	case e_qcsapi_wifi_del_radius_auth_server_cfg:
		statval = call_qcsapi_wifi_del_radius_auth_server_cfg( p_calling_bundle, argc, argv );
		break;

	case e_qcsapi_wifi_get_radius_auth_server_cfg:
		statval = call_qcsapi_wifi_get_radius_auth_server_cfg( p_calling_bundle, argc, argv );
		break;

	case e_qcsapi_wifi_add_radius_acct_server_cfg:
		statval = call_qcsapi_wifi_add_radius_acct_server_cfg( p_calling_bundle, argc, argv );
		break;

	case e_qcsapi_wifi_del_radius_acct_server_cfg:
		statval = call_qcsapi_wifi_del_radius_acct_server_cfg( p_calling_bundle, argc, argv );
		break;

	case e_qcsapi_wifi_get_radius_acct_server_cfg:
		statval = call_qcsapi_wifi_get_radius_acct_server_cfg( p_calling_bundle, argc, argv );
		break;

	case e_qcsapi_wifi_get_radius_acct_interim_interval:
		statval = call_qcsapi_wifi_get_radius_acct_interim_interval(p_calling_bundle, argc, argv);
		break;

	case e_qcsapi_wifi_set_radius_acct_interim_interval:
		statval = call_qcsapi_wifi_set_radius_acct_interim_interval(p_calling_bundle, argc, argv);
		break;

	case e_qcsapi_wifi_set_eap_own_ip_addr:
		statval = call_qcsapi_wifi_set_eap_own_ip_addr( p_calling_bundle, argc, argv );
		break;

	case e_qcsapi_wifi_get_eap_own_ip_addr:
		statval = call_qcsapi_wifi_get_eap_own_ip_addr( p_calling_bundle, argc, argv );
		break;

	case e_qcsapi_SSID_get_key_passphrase:
		statval = call_qcsapi_SSID_get_key_passphrase( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_SSID_set_key_passphrase:
		statval = call_qcsapi_SSID_set_key_passphrase( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_SSID_get_pmf:
		statval = call_qcsapi_SSID_get_pmf( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_SSID_set_pmf:
		statval = call_qcsapi_SSID_set_pmf( p_calling_bundle, argc, argv );
		break;

	case e_qcsapi_SSID_get_params:
		statval = call_qcsapi_SSID_get_params(p_calling_bundle, argc, argv);
		break;

	case e_qcsapi_SSID_set_params:
		statval = call_qcsapi_SSID_set_params(p_calling_bundle, argc, argv);
		break;

	case e_qcsapi_wifi_get_scan_chan_list:
		statval = call_qcsapi_wifi_get_scan_chan_list(p_calling_bundle, argc, argv);
		break;

	case e_qcsapi_wifi_set_scan_chan_list:
		statval = call_qcsapi_wifi_set_scan_chan_list(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_start_scan:
		statval = call_qcsapi_wifi_start_scan(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_cancel_scan:
		statval = call_qcsapi_wifi_cancel_scan(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_scan_status:
		statval = call_qcsapi_wifi_get_scan_status(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_cac_status:
		statval = call_qcsapi_wifi_get_cac_status(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_dfs_available_channel:
		statval = call_qcsapi_wifi_set_dfs_available_channel(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_wait_scan_completes:
		statval = call_qcsapi_wifi_wait_scan_completes(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scan_chk_inv:
		statval = call_qcsapi_wifi_set_scan_chk_inv(p_calling_bundle, argc, argv);

		break;

	  case e_qcsapi_wifi_get_scan_chk_inv:
		statval = call_qcsapi_wifi_get_scan_chk_inv(p_calling_bundle, argc, argv);

		break;

	  case e_qcsapi_wifi_start_cca:
		statval = call_qcsapi_wifi_start_cca(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_disable_wps:
		statval = call_qcsapi_wifi_disable_wps(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_results_AP_scan:
		statval = call_qcsapi_wifi_get_results_AP_scan( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_count_APs_scanned:
		statval = call_qcsapi_wifi_get_count_APs_scanned( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_properties_AP:
		statval = call_qcsapi_wifi_get_properties_AP( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_wps_ie_scanned_AP:
		statval = call_qcsapi_wifi_get_wps_ie_scanned_AP( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_mcs_rate:
		statval = call_qcsapi_wifi_get_mcs_rate( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_mcs_rate:
		statval = call_qcsapi_wifi_set_mcs_rate( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_time_associated_per_association:
		statval = call_qcsapi_wifi_get_time_associated_per_association( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_wds_add_peer:
		statval = call_qcsapi_wifi_wds_add_peer( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_wds_remove_peer:
		statval = call_qcsapi_wifi_wds_remove_peer( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_wds_get_peer_address:
		statval = call_qcsapi_wifi_wds_get_peer_address( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_wds_get_psk:
		statval = call_qcsapi_wifi_wds_get_psk( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_wds_set_psk:
		statval = call_qcsapi_wifi_wds_set_psk( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_wds_set_mode:
		statval = call_qcsapi_wifi_wds_set_mode( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_wds_get_mode:
		statval = call_qcsapi_wifi_wds_get_mode( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_qos_get_param:
		statval = call_qcsapi_wifi_qos_get_param( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_qos_set_param:
		statval = call_qcsapi_wifi_qos_set_param( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_wmm_ac_map:
		statval = call_qcsapi_wifi_get_wmm_ac_map( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_wmm_ac_map:
		statval = call_qcsapi_wifi_set_wmm_ac_map( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_dscp_8021p_map:
		statval = call_qcsapi_wifi_get_dscp_8021p_map( p_calling_bundle, argc, argv );
		break;
	  case e_qcsapi_wifi_set_dscp_8021p_map:
		statval = call_qcsapi_wifi_set_dscp_8021p_map( p_calling_bundle, argc, argv );
		break;
	  case e_qcsapi_wifi_get_dscp_ac_map:
		statval = call_qcsapi_wifi_get_dscp_ac_map( p_calling_bundle, argc, argv );
		break;
	  case e_qcsapi_wifi_set_dscp_ac_map:
		statval = call_qcsapi_wifi_set_dscp_ac_map( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_ac_agg_hold_time:
		statval = call_qcsapi_wifi_get_ac_agg_hold_time( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_ac_agg_hold_time:
		statval = call_qcsapi_wifi_set_ac_agg_hold_time( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_qos_map:
		statval = call_qcsapi_wifi_set_qos_map( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_del_qos_map:
		statval = call_qcsapi_wifi_del_qos_map( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_qos_map:
		statval = call_qcsapi_wifi_get_qos_map( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_send_qos_map_conf:
		statval = call_qcsapi_wifi_send_qos_map_conf( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_dscp_tid_map:
		statval = call_qcsapi_wifi_get_dscp_tid_map( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_priority:
		statval = call_qcsapi_wifi_get_priority( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_priority:
		statval = call_qcsapi_wifi_set_priority( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_airfair:
		statval = call_qcsapi_wifi_get_airfair( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_airfair:
		statval = call_qcsapi_wifi_set_airfair( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_config_get_parameter:
		statval = call_qcsapi_config_get_parameter( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_config_update_parameter:
		statval = call_qcsapi_config_update_parameter( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_config_get_ssid_parameter:
		statval = call_qcsapi_config_get_ssid_parameter( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_config_update_ssid_parameter:
		statval = call_qcsapi_config_update_ssid_parameter( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_service_control:
		statval = call_qcsapi_service_control(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wfa_cert:
		statval = call_qcsapi_wfa_cert(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_enable_scs:
		statval = call_qcsapi_wifi_scs_enable(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_scs_switch_channel:
		statval = call_qcsapi_wifi_scs_switch_channel(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_scs_pick_best_channel:
		statval = call_qcsapi_wifi_scs_pick_best_channel(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_verbose:
		statval = call_qcsapi_wifi_set_scs_verbose(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_scs_status:
		statval = call_qcsapi_wifi_get_scs_status(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_smpl_enable:
		statval = call_qcsapi_wifi_set_scs_smpl_enable(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_active_chan_list:
		statval = call_qcsapi_wifi_set_scs_active_chan_list(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_scs_active_chan_list:
		statval = call_qcsapi_wifi_get_scs_active_chan_list(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_smpl_dwell_time:
		statval = call_qcsapi_wifi_set_scs_smpl_dwell_time(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_smpl_intv:
		statval = call_qcsapi_wifi_set_scs_sample_intv(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_scs_smpl_intv:
		statval = call_qcsapi_wifi_get_scs_sample_intv(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_smpl_type:
		statval = call_qcsapi_wifi_set_scs_sample_type(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_intf_detect_intv:
		statval = call_qcsapi_wifi_set_scs_intf_detect_intv(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_thrshld:
		statval = call_qcsapi_wifi_set_scs_thrshld(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_report_only:
		statval = call_qcsapi_wifi_set_scs_report_only(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_override_mode:
		statval = call_qcsapi_wifi_set_scs_override_mode(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_scs_report_stat:
		statval = call_qcsapi_wifi_get_scs_report(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_cca_intf_smth_fctr:
		statval = call_qcsapi_wifi_set_scs_cca_intf_smth_fctr(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_chan_mtrc_mrgn:
		statval = call_qcsapi_wifi_set_scs_chan_mtrc_mrgn(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_inband_chan_mtrc_mrgn:
		statval = call_qcsapi_wifi_set_scs_inband_chan_mtrc_mrgn(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_nac_monitor_mode:
		statval = call_qcsapi_wifi_set_scs_nac_monitor_mode(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_obss_check_enable:
		statval = call_qcsapi_wifi_scs_obss_check_enable(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_pmbl_smth_enable:
		statval = call_qcsapi_wifi_scs_pmbl_smth_enable(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_scs_dfs_reentry_request:
		statval = call_qcsapi_wifi_get_scs_dfs_reentry_request(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_scs_cca_intf:
		statval = call_qcsapi_wifi_get_scs_cca_intf( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_scs_param:
		statval = call_qcsapi_wifi_get_scs_param(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_stats:
		statval = call_qcsapi_wifi_set_scs_stats(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_burst_enable:
		statval = call_qcsapi_wifi_set_scs_burst_enable(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_burst_window:
		statval = call_qcsapi_wifi_set_scs_burst_window(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_burst_thresh:
		statval = call_qcsapi_wifi_set_scs_burst_thresh(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_burst_pause:
		statval = call_qcsapi_wifi_set_scs_burst_pause(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_burst_switch:
		statval = call_qcsapi_wifi_set_scs_burst_switch(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_scs_chan_weight:
		statval = call_qcsapi_wifi_set_scs_chan_weight(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_scs_chan_weights:
		statval = call_qcsapi_wifi_get_scs_chan_weights(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_start_ocac:
		statval = call_qcsapi_wifi_start_ocac(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_stop_ocac:
		statval = call_qcsapi_wifi_stop_ocac(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_ocac_status:
		statval = call_qcsapi_wifi_get_ocac_status(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_ocac_threshold:
		statval = call_qcsapi_wifi_set_ocac_threshold(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_ocac_dwell_time:
		statval = call_qcsapi_wifi_set_ocac_dwell_time(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_ocac_duration:
		statval = call_qcsapi_wifi_set_ocac_duration(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_ocac_cac_time:
		statval = call_qcsapi_wifi_set_ocac_cac_time(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_ocac_report_only:
		statval = call_qcsapi_wifi_set_ocac_report_only(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_start_dfs_s_radio:
		statval = call_qcsapi_wifi_start_dfs_s_radio(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_stop_dfs_s_radio:
		statval = call_qcsapi_wifi_stop_dfs_s_radio(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_dfs_s_radio_status:
		statval = call_qcsapi_wifi_get_dfs_s_radio_status(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_dfs_s_radio_availability:
		statval = call_qcsapi_wifi_get_dfs_s_radio_availability(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_dfs_s_radio_threshold:
		statval = call_qcsapi_wifi_set_dfs_s_radio_threshold(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_dfs_s_radio_dwell_time:
		statval = call_qcsapi_wifi_set_dfs_s_radio_dwell_time(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_dfs_s_radio_duration:
		statval = call_qcsapi_wifi_set_dfs_s_radio_duration(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_dfs_s_radio_cac_time:
		statval = call_qcsapi_wifi_set_dfs_s_radio_cac_time(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_dfs_s_radio_report_only:
		statval = call_qcsapi_wifi_set_dfs_s_radio_report_only(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_dfs_s_radio_wea_duration:
		statval = call_qcsapi_wifi_set_dfs_s_radio_wea_duration(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_dfs_s_radio_wea_cac_time:
		statval = call_qcsapi_wifi_set_dfs_s_radio_wea_cac_time(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_dfs_s_radio_wea_dwell_time:
		statval = call_qcsapi_wifi_set_dfs_s_radio_wea_dwell_time(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_xcac_set:
		statval = call_qcsapi_wifi_xcac_set(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_xcac_get:
		statval = call_qcsapi_wifi_xcac_get(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_vendor_fix:
		statval = call_qcsapi_wifi_set_vendor_fix( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_ap_isolate:
		statval = call_qcsapi_wifi_set_ap_isolate(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_ap_isolate:
		statval = call_qcsapi_wifi_get_ap_isolate(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_power_save:
		statval = call_qcsapi_pm_get_set_mode(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_qpm_level:
		statval = call_qcsapi_qpm_get_level(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_get_interface_stats:
		statval = call_qcsapi_get_interface_stats( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_if_infoset:
		statval = call_qcsapi_wifi_get_if_infoset( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_get_phy_stats:
		statval = call_qcsapi_get_phy_stats( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_get_qfdr_parameter:
		statval = call_qcsapi_get_qfdr_parameter( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_set_qfdr_parameter:
		statval = call_qcsapi_set_qfdr_parameter( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_get_qfdr_state:
		statval = call_qcsapi_get_qfdr_state(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_bootcfg_get_parameter:
		statval = call_qcsapi_bootcfg_get_parameter( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_bootcfg_update_parameter:
		statval = call_qcsapi_bootcfg_update_parameter( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_bootcfg_commit:
		statval = call_qcsapi_bootcfg_commit( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_telnet_enable:
		statval = call_qcsapi_telnet_enable( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_restore_default_config:
		statval = call_qcsapi_restore_default_config( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_reset_all_stats:
		statval = call_qcsapi_reset_all_counters( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_run_script:
		statval = call_qcsapi_run_script( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_qtm:
		statval = call_qcsapi_vsp( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_pairing_id:
		statval = call_qcsapi_wifi_get_pairing_id( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_pairing_id:
		statval = call_qcsapi_wifi_set_pairing_id( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_pairing_enable:
		statval = call_qcsapi_wifi_get_pairing_enable( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_pairing_enable:
		statval = call_qcsapi_wifi_set_pairing_enable( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_set_txqos_sched_tbl:
		statval = call_qcsapi_wifi_set_txqos_sched_tbl( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_wifi_get_txqos_sched_tbl:
		statval = call_qcsapi_wifi_get_txqos_sched_tbl( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_eth_phy_power_off:
		statval = call_qcsapi_eth_phy_power_off( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_aspm_l1:
		statval = call_qcsapi_set_aspm_l1( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_l1:
		statval = call_qcsapi_set_l1( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_test_traffic:
		statval = call_qcsapi_test_traffic( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_get_temperature:
		statval = call_qcsapi_get_temperature( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_set_accept_oui_filter:
		statval = call_qcsapi_set_accept_oui_filter( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_get_accept_oui_filter:
		statval = call_qcsapi_get_accept_oui_filter( p_calling_bundle, argc, argv );
		break;

	  case e_qcsapi_get_swfeat_list:
		statval = call_qcsapi_get_swfeat_list( p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_set_vht:
		statval = call_qcsapi_wifi_set_vht( p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_get_vht:
		statval = call_qcsapi_wifi_get_vht( p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_calcmd_check_rfic_health:
		statval = call_qcsapi_calcmd_check_rfic_health(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_calcmd_set_test_mode:
		statval = call_qcsapi_calcmd_set_test_mode(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_calcmd_show_test_packet:
		statval = call_qcsapi_calcmd_show_test_packet(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_calcmd_send_test_packet:
		statval = call_qcsapi_calcmd_send_test_packet(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_calcmd_stop_test_packet:
		statval = call_qcsapi_calcmd_stop_test_packet(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_calcmd_send_dc_cw_signal:
		statval = call_qcsapi_calcmd_send_dc_cw_signal(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_calcmd_stop_dc_cw_signal:
		statval = call_qcsapi_calcmd_stop_dc_cw_signal(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_calcmd_get_test_mode_antenna_sel:
		statval = call_qcsapi_calcmd_get_test_mode_antenna_sel(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_calcmd_get_test_mode_mcs:
		statval = call_qcsapi_calcmd_get_test_mode_mcs(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_calcmd_get_test_mode_bw:
		statval = call_qcsapi_calcmd_get_test_mode_bw(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_calcmd_get_tx_power:
		statval = call_qcsapi_calcmd_get_tx_power(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_calcmd_set_tx_power:
		statval = call_qcsapi_calcmd_set_tx_power(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_calcmd_get_test_mode_rssi:
		statval = call_qcsapi_calcmd_get_test_mode_rssi(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_calcmd_set_mac_filter:
		statval = call_qcsapi_calcmd_set_mac_filter(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_calcmd_get_antenna_count:
		statval = call_qcsapi_calcmd_get_antenna_count(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_calcmd_clear_counter:
		statval = call_qcsapi_calcmd_clear_counter(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_calcmd_get_info:
		statval = call_qcsapi_calcmd_get_info(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_set_soc_macaddr:
		statval = call_qcsapi_wifi_set_soc_macaddr(p_calling_bundle, argc, argv);
		break;

	  case e_qcsapi_wifi_enable_tdls:
		statval = call_qcsapi_wifi_enable_tdls(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_enable_tdls_over_qhop:
		statval = call_qcsapi_wifi_enable_tdls_over_qhop(p_calling_bundle, argc, argv);
		break;
	case e_qcsapi_wifi_disable_dfs_channels:
		statval = call_qcsapi_disable_dfs_channels(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_dfs_channels_status:
		statval = call_qcsapi_get_dfs_channels_status(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_tdls_status:
		statval = call_qcsapi_wifi_get_tdls_status(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_tdls_params:
		statval = call_qcsapi_wifi_set_tdls_params(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_tdls_params:
		statval = call_qcsapi_wifi_get_tdls_params(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_carrier_id:
		  statval = call_qcsapi_get_carrier_id( p_calling_bundle, argc, argv );
		break;
	  case e_qcsapi_set_carrier_id:
		  statval = call_qcsapi_set_carrier_id( p_calling_bundle, argc, argv );
		break;
	case e_qcsapi_get_platform_id:
		statval = call_qcsapi_get_platform_id(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_spinor_jedecid:
		statval = call_qcsapi_wifi_get_spinor_jedecid(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_custom_value:
		statval = call_qcsapi_wifi_get_custom_value(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_custom_value:
		statval = call_qcsapi_wifi_set_custom_value(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_vco_lock_detect_mode:
		statval = call_qcsapi_wifi_get_vco_lock_detect_mode(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_vco_lock_detect_mode:
		statval = call_qcsapi_wifi_set_vco_lock_detect_mode(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_tdls_operate:
		statval = call_qcsapi_wifi_tdls_operate(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_mlme_stats_per_mac:
		statval = call_qcsapi_wifi_get_mlme_stats_per_mac(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_mlme_stats_per_association:
		statval = call_qcsapi_wifi_get_mlme_stats_per_association(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_mlme_stats_macs_list:
		statval = call_qcsapi_wifi_get_mlme_stats_macs_list(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_nss_cap:
		statval = call_qcsapi_wifi_get_nss_cap(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_nss_cap:
		statval = call_qcsapi_wifi_set_nss_cap(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_rx_nss_cap:
		statval = call_qcsapi_wifi_get_rx_nss_cap(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_rx_nss_cap:
		statval = call_qcsapi_wifi_set_rx_nss_cap(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_security_defer_mode:
		statval = call_qcsapi_wifi_get_security_defer_mode(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_security_defer_mode:
		statval = call_qcsapi_wifi_set_security_defer_mode(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_apply_security_config:
		statval = call_qcsapi_wifi_apply_security_config(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_intra_bss_isolate:
		statval = call_qcsapi_wifi_set_intra_bss_isolate(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_intra_bss_isolate:
		statval = call_qcsapi_wifi_get_intra_bss_isolate(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_bss_isolate:
		statval = call_qcsapi_wifi_set_bss_isolate(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_bss_isolate:
		statval = call_qcsapi_wifi_get_bss_isolate(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wowlan_host_state:
		statval = call_qcsapi_wifi_host_state_set(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wowlan_match_type:
		statval = call_qcsapi_wifi_wowlan_match_type_set(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wowlan_L2_type:
		statval = call_qcsapi_wifi_wowlan_L2_type_set(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wowlan_udp_port:
		statval = call_qcsapi_wifi_wowlan_udp_port_set(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wowlan_pattern:
		statval = call_qcsapi_wifi_wowlan_pattern_set(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wowlan_get_host_state:
		statval = call_qcsapi_wifi_host_state_get(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wowlan_get_match_type:
		statval = call_qcsapi_wifi_wowlan_match_type_get(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wowlan_get_L2_type:
		statval = call_qcsapi_wifi_wowlan_L2_type_get(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wowlan_get_udp_port:
		statval = call_qcsapi_wifi_wowlan_udp_port_get(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wowlan_get_pattern:
		statval = call_qcsapi_wifi_wowlan_pattern_get(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_extender_params:
		statval = call_qcsapi_wifi_set_extender_params(p_calling_bundle,
			argc, argv);
		break;
	  case e_qcsapi_wifi_get_extender_status:
		statval = call_qcsapi_wifi_get_extender_status(p_calling_bundle,
			argc, argv);
		break;
	  case e_qcsapi_wifi_set_extender_key:
		statval = call_qcsapi_wifi_set_extender_key(p_calling_bundle,
			argc, argv);
		break;
	  case e_qcsapi_wifi_update_autochan_params:
		statval = call_qcsapi_wifi_update_autochan_params(p_calling_bundle,
			argc, argv);
		break;
	  case e_qcsapi_wifi_set_autochan_params:
		statval = call_qcsapi_wifi_set_autochan_params(p_calling_bundle,
			argc, argv);
		break;
	  case e_qcsapi_wifi_get_autochan_params:
		statval = call_qcsapi_wifi_get_autochan_params(p_calling_bundle,
			argc, argv);
		break;
	  case e_qcsapi_wifi_enable_bgscan:
		statval = call_qcsapi_wifi_enable_bgscan(p_calling_bundle,
			argc, argv);
		break;
	  case e_qcsapi_wifi_get_bgscan_status:
		statval = call_qcsapi_wifi_get_bgscan_status(p_calling_bundle,
			argc, argv);
		break;
	  case e_qcsapi_get_uboot_info:
		statval = call_qcsapi_get_uboot_info(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_disassoc_reason:
		statval = call_qcsapi_wifi_get_disassoc_reason(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_is_startprod_done:
		statval = call_qcsapi_is_startprod_done(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_bb_param:
		statval = call_qcsapi_wifi_get_bb_param(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_bb_param:
		statval = call_qcsapi_wifi_set_bb_param(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_tx_amsdu:
		statval = call_qcsapi_wifi_get_tx_amsdu(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_tx_amsdu:
		statval = call_qcsapi_wifi_set_tx_amsdu(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_tx_max_amsdu:
		statval = call_qcsapi_wifi_get_tx_max_amsdu(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_tx_max_amsdu:
		statval = call_qcsapi_wifi_set_tx_max_amsdu(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_scan_buf_max_size:
		statval = call_qcsapi_wifi_set_scan_buf_max_size(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_scan_buf_max_size:
		statval = call_qcsapi_wifi_get_scan_buf_max_size(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_scan_table_max_len:
		statval = call_qcsapi_wifi_set_scan_table_max_len(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_scan_table_max_len:
		statval = call_qcsapi_wifi_get_scan_table_max_len(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_enable_mu:
		statval = call_qcsapi_wifi_set_enable_mu(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_enable_mu:
		statval = call_qcsapi_wifi_get_enable_mu(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_mu_use_precode:
		statval = call_qcsapi_wifi_set_mu_use_precode(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_mu_use_precode:
		statval = call_qcsapi_wifi_get_mu_use_precode(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_mu_use_eq:
		statval = call_qcsapi_wifi_set_mu_use_eq(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_mu_use_eq:
		statval = call_qcsapi_wifi_get_mu_use_eq(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_mu_groups:
		statval = call_qcsapi_wifi_get_mu_groups(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_send_file:
		statval = call_qcsapi_send_file(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_emac_switch:
		statval = call_qcsapi_get_emac_switch(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_emac_switch:
		statval = call_qcsapi_set_emac_switch(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_eth_dscp_map:
		statval = call_qcsapi_eth_dscp_map(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_optim_stats:
		statval = call_qcsapi_wifi_set_optim_stats(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_pref_band:
		statval = call_qcsapi_wifi_set_pref_band( p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_pref_band:
		statval = call_qcsapi_wifi_get_pref_band( p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_sys_time:
		statval = call_qcsapi_set_sys_time(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_sys_time:
		statval = call_qcsapi_get_sys_time(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_eth_info:
		statval = call_qcsapi_get_eth_info(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_verify_repeater_mode:
		statval = call_qcsapi_wifi_verify_repeater_mode(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_repeater_ifreset:
		statval = call_qcsapi_wifi_set_repeater_ifreset(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_repeater_ifreset:
		statval = call_qcsapi_wifi_get_repeater_ifreset(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_ap_interface_name:
		statval = call_qcsapi_wifi_set_ap_interface_name(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_ap_interface_name:
		statval = call_qcsapi_wifi_get_ap_interface_name(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_block_bss:
		statval = call_qcsapi_wifi_block_bss(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_block_bss:
		statval = call_qcsapi_wifi_get_block_bss(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_txba_disable:
		statval = call_qcsapi_wifi_set_txba_disable(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_txba_disable:
		statval = call_qcsapi_wifi_get_txba_disable(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_rxba_decline:
		statval = call_qcsapi_wifi_set_rxba_decline(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_rxba_decline:
		statval = call_qcsapi_wifi_get_rxba_decline(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_txburst:
		statval = call_qcsapi_wifi_set_txburst(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_txburst:
		statval = call_qcsapi_wifi_get_txburst(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_sec_chan:
		statval = call_qcsapi_wifi_get_sec_chan(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_sec_chan:
		statval = call_qcsapi_wifi_set_sec_chan(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_vap_default_state:
		statval = call_qcsapi_set_vap_default_state(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_vap_default_state:
		statval = call_qcsapi_get_vap_default_state(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_vap_state:
		statval = call_qcsapi_set_vap_state(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_vap_state:
		statval = call_qcsapi_get_vap_state(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_txrx_airtime:
		statval = call_qcsapi_wifi_get_txrx_airtime(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_node_stat:
		statval = call_qcsapi_wifi_get_node_stat(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_qwe_command:
		statval = call_qcsapi_qwe_command(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_client_mac_list:
		statval = call_qcsapi_get_client_mac_list(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_core_dump:
		statval = call_qcsapi_get_core_dump2(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_app_core_dump:
		statval = call_qcsapi_get_app_core_dump(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_sys_log:
		statval = call_qcsapi_get_sys_log(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_sample_all_clients:
		statval = call_qcsapi_wifi_sample_all_clients(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_per_assoc_data:
		statval = call_qcsapi_wifi_get_per_assoc_data(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_tx_chains:
		statval = call_qcsapi_wifi_set_tx_chains( p_calling_bundle, argc, argv );
		break;
	  case e_qcsapi_wifi_get_tx_chains:
		statval = call_qcsapi_wifi_get_tx_chains( p_calling_bundle, argc, argv );
		break;
	  case e_qcsapi_get_wifi_ready:
		 statval = call_qcsapi_get_wifi_ready( p_calling_bundle, argc, argv );
		 break;
	  case e_qcsapi_get_cca_stats:
		statval = call_qcsapi_get_cca_stats( p_calling_bundle, argc, argv );
		break;
	  case e_qcsapi_get_ep_status:
		statval = call_qcsapi_get_ep_status( p_calling_bundle, argc, argv );
		break;
	  case e_qcsapi_get_igmp_snooping_state:
		statval = call_qcsapi_get_igmp_snoop(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_igmp_snooping_state:
		statval = call_qcsapi_set_igmp_snoop(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_max_bcast_pps:
		statval = call_qcsapi_set_max_bcast_pps(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_scs_leavedfs_chan_mtrc_mrgn:
		statval = call_qcsapi_wifi_set_scs_leavedfs_chan_mtrc_mrgn(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_max_boot_cac_duration:
		statval = call_qcsapi_set_max_boot_cac_duration(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_log_level:
		statval = call_qcsapi_set_log_level(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_log_level:
		statval = call_qcsapi_get_log_level(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_remote_logging:
		statval = call_qcsapi_set_remote_logging(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_console:
		statval = call_qcsapi_set_console(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_vopt:
		statval = call_qcsapi_set_vopt(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_vopt:
		statval = call_qcsapi_get_vopt(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_neighborhood_type:
		statval = call_qcsapi_wifi_get_neighborhood_type(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_threshold_of_neighborhood_type:
		statval = call_qcsapi_wifi_set_threshold_of_neighborhood_type(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_parameter:
		statval = call_qcsapi_wifi_get_parameter(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_parameter:
		statval = call_qcsapi_wifi_set_parameter(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_dpp_parameter:
		statval = call_qcsapi_wifi_dpp_parameter(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_do_system_action:
		statval = call_qcsapi_do_system_action(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_threshold_of_neighborhood_type:
		statval = call_qcsapi_wifi_get_threshold_of_neighborhood_type(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_is_weather_channel:
		statval = call_qcsapi_wifi_is_weather_channel(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_br_isolate:
		statval = call_qcsapi_wifi_set_br_isolate(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_br_isolate:
		statval = call_qcsapi_wifi_get_br_isolate(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_show_access_points:
		statval = call_qcsapi_wifi_show_access_points(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_nac_mon_mode:
		statval = call_qcsapi_wifi_set_nac_mon_mode(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_nac_mon_mode:
		statval = call_qcsapi_wifi_get_nac_mon_mode(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_nac_stats:
		statval = call_qcsapi_wifi_get_nac_stats(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_ieee80211r:
		statval = call_qcsapi_wifi_set_ieee80211r(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_ieee80211r:
		statval = call_qcsapi_wifi_get_ieee80211r(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_11r_mobility_domain:
		statval = call_qcsapi_wifi_set_11r_mobility_domain(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_11r_mobility_domain:
		statval = call_qcsapi_wifi_get_11r_mobility_domain(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_11r_nas_id:
		statval = call_qcsapi_wifi_set_11r_nas_id(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_11r_nas_id:
		statval = call_qcsapi_wifi_get_11r_nas_id(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_11r_ft_over_ds:
		statval = call_qcsapi_wifi_set_11r_ft_over_ds(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_11r_ft_over_ds:
		statval = call_qcsapi_wifi_get_11r_ft_over_ds(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_chan_usable:
		statval = call_qcsapi_wifi_get_chan_usable(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_device_mode:
		statval = call_qcsapi_get_device_mode(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_report_flood_interval:
		statval = call_qcsapi_set_report_flood_interval(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_report_flood_interval:
		statval = call_qcsapi_get_report_flood_interval(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_btm_cap:
		statval = call_qcsapi_wifi_get_btm_cap(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_btm_cap:
		statval = call_qcsapi_wifi_set_btm_cap(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_rm_neigh_report:
		statval = call_qcsapi_wifi_get_rm_neigh_report(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_rm_neigh_report:
		statval = call_qcsapi_wifi_set_rm_neigh_report(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_add_11r_neighbour:
		statval = call_qcsapi_wifi_add_11r_neighbour(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_del_11r_neighbour:
		statval = call_qcsapi_wifi_del_11r_neighbour(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_11r_neighbour:
		statval = call_qcsapi_wifi_get_11r_neighbour(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_11r_r1_key_holder:
		statval = call_qcsapi_wifi_set_11r_r1_key_holder(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_11r_r1_key_holder:
		statval = call_qcsapi_wifi_get_11r_r1_key_holder(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_pd_voltage_level:
		statval = call_qcsapi_get_pd_voltage_level(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_reload_security_config:
		statval = call_qcsapi_wifi_reload_security_config(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_icac_status:
		statval = call_qcsapi_get_icac_status(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_enable_emac_sdp:
		statval = call_qcsapi_enable_emac_sdp(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_bss_rxchan:
		statval = call_qcsapi_wifi_set_bss_rxchan(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_scs_band_margin_check:
		statval = call_qcsapi_wifi_set_scs_band_margin_check(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_scs_band_margin:
		statval = call_qcsapi_wifi_set_scs_band_margin(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_unknown_dest_discover_intval:
		statval = call_qcsapi_set_unknown_dest_discover_intval(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_unknown_dest_discover_intval:
		statval = call_qcsapi_get_unknown_dest_discover_intval(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_3addr_br_config:
		statval = call_qcsapi_set_3addr_br_config(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_3addr_br_config:
		statval = call_qcsapi_get_3addr_br_config(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_pta_param:
		statval = call_qcsapi_get_pta_param(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_pta_param:
		statval = call_qcsapi_set_pta_param(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_phy_param:
		statval = call_qcsapi_get_phy_param(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_phy_param:
		statval = call_qcsapi_set_phy_param(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_reg_chan_txpower_path_get:
		statval = call_qcsapi_reg_chan_txpower_path_get( p_calling_bundle, argc, argv );
		break;
	  case e_qcsapi_wifi_get_sec_cca_param:
		statval = call_qcsapi_get_sec_cca_param(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_sec_cca_param:
		statval = call_qcsapi_set_sec_cca_param(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_repeater_mode_cfg:
		statval = call_qcsapi_repeater_mode_cfg(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_urepeater_params:
		statval = call_qcsapi_set_urepeater_params(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_urepeater_params:
		statval = call_qcsapi_get_urepeater_params(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_ac_inheritance:
		statval = call_qcsapi_set_ac_inheritance(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_set_dynamic_wmm:
		statval = call_qcsapi_set_dynamic_wmm(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_oper_bw:
		statval = call_qcsapi_wifi_set_oper_bw(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_grab_config:
		statval = call_qcsapi_grab_config(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_current_band:
		statval = call_qcsapi_wifi_get_current_band( p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_get_restrict_wlan_ip:
		statval = call_qcsapi_wifi_get_restrict_wlan_ip(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_set_restrict_wlan_ip:
		statval = call_qcsapi_wifi_set_restrict_wlan_ip(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_get_reboot_cause:
		statval = call_qcsapi_get_reboot_cause(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_add_wps_pbc_ssid_filter:
		statval = call_qcsapi_add_wps_pbc_ssid_filter(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_del_wps_pbc_ssid_filter:
		statval = call_qcsapi_del_wps_pbc_ssid_filter(p_calling_bundle, argc, argv);
		break;
	  case e_qcsapi_wifi_show_wps_pbc_ssid_filters:
		statval = call_qcsapi_show_wps_pbc_ssid_filters(p_calling_bundle, argc, argv);
		break;
	case e_qcsapi_wifi_enable_repeater_ap:
		statval = call_qcsapi_wifi_enable_repeater_ap(p_calling_bundle, argc, argv);
		break;
	case e_qcsapi_wifi_disable_repeater_ap:
		statval = call_qcsapi_wifi_disable_repeater_ap(p_calling_bundle, argc, argv);
		break;
	case e_qcsapi_wifi_get_beacon_power_backoff:
		statval = call_qcsapi_wifi_get_beacon_power_backoff(p_calling_bundle, argc, argv);
		break;
	case e_qcsapi_wifi_set_beacon_power_backoff:
		statval = call_qcsapi_wifi_set_beacon_power_backoff(p_calling_bundle, argc, argv);
		break;
	case e_qcsapi_wifi_get_mgmt_power_backoff:
		statval = call_qcsapi_wifi_get_mgmt_power_backoff(p_calling_bundle, argc, argv);
		break;
	case e_qcsapi_wifi_set_mgmt_power_backoff:
		statval = call_qcsapi_wifi_set_mgmt_power_backoff(p_calling_bundle, argc, argv);
		break;
	case e_qcsapi_wifi_multi_psk_info_append:
		statval = call_qcsapi_wifi_multi_psk_info_append(p_calling_bundle, argc, argv);
		break;
	case e_qcsapi_wifi_multi_psk_info_read:
		statval = call_qcsapi_wifi_multi_psk_info_read(p_calling_bundle, argc, argv);
		break;
	case e_qcsapi_wifi_multi_psk_info_replace:
		statval = call_qcsapi_wifi_multi_psk_info_replace(p_calling_bundle, argc, argv);
		break;
	case e_qcsapi_wifi_start_phy_scan:
		statval = call_qcsapi_wifi_start_phy_scan(p_calling_bundle, argc, argv);
		break;
	case e_qcsapi_wifi_get_chan_phy_info:
		statval = call_qcsapi_wifi_get_chan_phy_info(p_calling_bundle, argc, argv);
		break;
	default:
		print_out( print, "no interface program (yet) for QCS API enum %d\n", p_calling_bundle->caller_qcsapi );
	}

	return( statval );
}

static int
call_qcsapi(qcsapi_output *print, int argc, char *argv[] )
{
	qcsapi_entry_point		 e_the_entry_point = e_qcsapi_nosuch_api;
	int				 ok_to_continue = 1;
	int				 expected_argc = 1;
	call_qcsapi_bundle		 calling_bundle;
	const struct qcsapi_entry	*qcsapi_table_entry = NULL;
	int				 statval = 0;

	calling_bundle.caller_output = print;

  /*
   * Argument count (argc) required to be at least 1, the name of the QCS API to be called.
   */
	if (argc < 1)
	{
		print_out( print, "programming error in call_qcsapi, argc = %d\n", argc );
		ok_to_continue = 0;
	}

	if (ok_to_continue)
	{
		if (name_to_entry_point_enum( argv[ 0 ], &e_the_entry_point ) == 0)
		{
			print_out( print, "QCSAPI entry point %s not found\n", argv[ 0 ] );
			ok_to_continue = 0;
		}
	}
  /*
   * Selected QCSAPIs are NOT supported by call_qcsapi.
   */
	if (ok_to_continue)
	{
		if (e_the_entry_point == e_qcsapi_gpio_monitor_reset_device)
		{
			print_out( print, "GPIO monitor reset device cannot be accessed from call_qcsapi\n" );
			ok_to_continue = 0;
		}
	}

	if (ok_to_continue)
	{
		qcsapi_table_entry = entry_point_enum_to_table_entry( e_the_entry_point );

		if (qcsapi_table_entry == NULL)
		{
			print_out( print, "programming error in call_qcsapi, no entry for enum %d\n", (int) e_the_entry_point );
			ok_to_continue = 0;
		}
		else
		{
		  /*
		   * Originally all APIs expected an interface name.  Now a few APIs apply to the entire system,
		   * and thus do not require an interface name.  These new APIs are identified as get system value
		   * and set system value.  Older APIs are identified as get and set APIs.  They require an
		   * interface, which now needs to be accounted for here.  And set system value APIs will require
		   * an additional parameter, the new system-wide value.
		   *
		   * APIs that expect an additional parameter (counters, rates, etc.) require an additional parameter
		   * APIs that expect an SSID AND an index (SSID get passphrase) require yet another parameter
		   * APIs that SET a value require yet another parameter
		   *
		   * No interdependencies.
		   */
			if (qcsapi_table_entry->e_typeof_api == e_qcsapi_get_api ||
			    qcsapi_table_entry->e_typeof_api == e_qcsapi_set_api)
			  expected_argc++;						// account for the interface
			if (qcsapi_table_entry->e_generic_param_type != e_qcsapi_none)
			  expected_argc++;
			if (qcsapi_table_entry->e_generic_param_type == e_qcsapi_SSID_index)
			  expected_argc++;
			if (qcsapi_table_entry->e_typeof_api == e_qcsapi_set_api ||
			    qcsapi_table_entry->e_typeof_api == e_qcsapi_set_system_value)
			  expected_argc++;
			if (qcsapi_table_entry->e_typeof_api == e_qcsapi_set_api_without_parameter)
				expected_argc++;

			if (expected_argc > argc)
			{
				print_out( print,
			   "Too few command line parameters in call_qcsapi, expected %d, found %d\n", expected_argc, argc
				);
				ok_to_continue = 0;
			}
		}

		if (ok_to_continue)
		{
		  /* Eliminate the QCS API name from the argument list. */

			argc--;
			argv++;

		  /* Begin filling in the calling bundle ... */

			calling_bundle.caller_qcsapi = e_the_entry_point;

			if (qcsapi_table_entry->e_typeof_api == e_qcsapi_get_api ||
			    qcsapi_table_entry->e_typeof_api == e_qcsapi_set_api ||
				qcsapi_table_entry->e_typeof_api == e_qcsapi_set_api_without_parameter)
			{
				calling_bundle.caller_interface = argv[ 0 ];
				argc--;
				argv++;
			}
			else
			  calling_bundle.caller_interface = NULL;

			calling_bundle.caller_generic_parameter.generic_parameter_type = qcsapi_table_entry->e_generic_param_type;
		}
	}

	if (ok_to_continue)
	{
		if (calling_bundle.caller_generic_parameter.generic_parameter_type != e_qcsapi_none)
		{
		  /* Again we checked previously that enough arguments were present ... */

			if (parse_generic_parameter_name(print, argv[ 0 ], &(calling_bundle.caller_generic_parameter)) == 0)
			  ok_to_continue = 0;
			else
			{
			  /* And remove the parameter name from the argument list. */

			argc--;
			argv++;
			}
		}
	}

	if (ok_to_continue)
	{
		unsigned int	iter;

		if (verbose_flag > 0)
		{
			print_out( print, "call QCSAPI: %s", entry_point_enum_to_name( calling_bundle.caller_qcsapi ) );

			if (qcsapi_table_entry->e_typeof_api == e_qcsapi_get_api ||
			    qcsapi_table_entry->e_typeof_api == e_qcsapi_set_api ||
				qcsapi_table_entry->e_typeof_api == e_qcsapi_set_api_without_parameter)
			{
				print_out( print, " %s", calling_bundle.caller_interface );
			}

			if (calling_bundle.caller_generic_parameter.generic_parameter_type != e_qcsapi_none)
			{
				print_out( print, " " );
				dump_generic_parameter_name(print, &(calling_bundle.caller_generic_parameter) );
			}

			if (argc > 0)
			{
				for (iter = 0; iter < argc; iter++)
				  print_out( print, " %s", argv[ iter ] );
			}

			print_out( print, "\n" );
		}

		if (call_qcsapi_init_count > 0)
		{
			if (call_qcsapi_init_count == 1)
			  qcsapi_init();
			else
			{
				for (iter = 0; iter < call_qcsapi_init_count; iter++)
				  qcsapi_init();
			}
		}

		if (call_count < 2) {
			statval = call_particular_qcsapi( &calling_bundle, argc, argv );
		} else {
			for (iter = 0; iter < call_count - 1; iter++) {
				call_particular_qcsapi( &calling_bundle, argc, argv );
				if (delay_time > 0) {
					sleep( delay_time );
				}
			}

			call_particular_qcsapi( &calling_bundle, argc, argv );
		}
	}

	if (!ok_to_continue)
		return -EINVAL;

	return( statval );
}

static int
process_options(qcsapi_output *print, int argc, char **argv)
{
	int	local_index = 0;

	while (local_index < argc && *(argv[ local_index ]) == '-')
	{
		char		*option_arg = argv[ local_index ];
		unsigned int	 length_option = strlen( option_arg );

		if (length_option > 1)
		{
			char	option_letter = option_arg[ 1 ];

			if (option_letter == 'v')
			{
				unsigned int	index_2 = 1;

				while (option_arg[ index_2 ] == 'v')
				{
					verbose_flag++;
					index_2++;
				}
			}
			else if (option_letter == 'q')
			{
				unsigned int	index_2 = 1;

				while (option_arg[ index_2 ] == 'q')
				{
					verbose_flag--;
					index_2++;
				}
			}
		  /*
		   * Process all options that require a numeric (integer) value here.
		   */
			else if (option_letter == 'n' || option_letter == 'd' || option_letter == 'i')
			{
				char	*local_addr = NULL;

				if (length_option > 2)
				{
					local_addr = option_arg + 2;
				}
				else
				{
					if (local_index + 1 >= argc)
					{
						print_err( print, "Missing numeric value for %c option\n", option_letter );
					}
					else
					{
						local_index++;
						local_addr = argv[ local_index ];
					}

				}

				if (local_addr != NULL)
				{
					int	min_value = 1;
					int	local_value;

					if (local_str_to_int32(local_addr, &local_value, print,
							"value") < 0)
						return -EINVAL;
				  /*
				   * Most options require a numeric value to be greater than 0.  'i' is an exception.
				   */
					if (option_letter == 'i')
					  min_value = 0;

					if (local_value < min_value)
					{
						print_err( print,
							"Invalid numeric value %d for %c option\n",
							local_value, option_letter);
						return -EINVAL;
					}
					else
					{
						if (option_letter == 'n')
						  call_count = (unsigned int) local_value;
						else if (option_letter == 'i')
						  call_qcsapi_init_count = (unsigned int) local_value;
						else
						  delay_time = (unsigned int) local_value;
					}
				}
			  /*
			   * Error causing local_addr to be NULL has already been reported.
			   */
			}
			else if (option_letter == 'h')
			{
				if (local_index + 1 >= argc)
				{
					list_entry_point_names(print);
				}
				else
				{
					char	*local_addr = NULL;

					local_index++;
					local_addr = argv[ local_index ];

					if (strcasecmp( local_addr, "options" ) == 0)
					  list_option_names(print);
					else if (strcasecmp( local_addr, "entry_points" ) == 0)
					  list_entry_point_names(print);
					else if (strcasecmp( local_addr, "counters" ) == 0)
					  list_counter_names(print);
					else if (strcasecmp( local_addr, "per_node_params" ) == 0)
					  list_per_node_param_names(print);
					else if (strcasecmp( local_addr, "board_parameters" ) == 0)
					  list_board_parameter_names(print);
					else if (strcasecmp( local_addr, "wifi_parameters" ) == 0)
					  list_wifi_parameter_names(print);
					else {
						print_err(print, "Unrecognized help option %s\n", local_addr );
						print_err(print, "Choose from 'entry_points', 'counters', 'options',"
									"'per_node_params', 'board_parameters', or "
									"'wifi_parameters'\n");
					}
				}

				return -EINVAL;
			}
			else if (option_letter == 'g')
			{
				char *reg;

				if (local_index + 1 >= argc)
				{
					return -EINVAL;
				}

				reg = argv[ ++local_index ];

				grep_entry_point_names(print, reg);

				return -EINVAL;
			}
			else if (option_letter == 'f')
			{
				if (local_index + 1 >= argc)
				{
					print_err( print, "Missing numeric value for %c option\n", option_letter );
				}
				else
				{
					char	*local_addr = NULL;

					local_index++;
					local_addr = argv[ local_index ];

					if (!strcmp("force_NULL", local_addr))
						print_err(print, "Deprecated parameter %s ignored\n",
							local_addr);
					else
						print_err(print, "Unrecognized parameter %s for %c option\n",
								local_addr, option_letter);
				}
			}
			else if (option_letter == 'u')
			{
				qcsapi_sem_disable();
			}
			else
			{
				print_out( print, "unrecognized option '%c'\n", option_letter );
			}
		}
	  /*
	   * Control would take the non-existent else clause if the argument were just "-".
	   */
		local_index++;
	}

	if( verbose_flag > 1)
	{
		print_out( print, "Verbose flag: %d, call count: %u\n", verbose_flag, call_count );
	}

	return( local_index );
}

static void
call_qscapi_help(qcsapi_output *print)
{
	print_out( print, "Usage:\n" );
	print_out( print, "    To get a parameter value: call_qcsapi <QCS API> <interface>\n" );
	print_out( print, "                              call_qcsapi <QCS API> <interface> <type of parameter>\n" );
	print_out( print, "    To set a parameter: call_qcsapi <QCS API> <interface> <parameter value>\n" );
	print_out( print, "                        call_qcsapi <QCS API> <interface> <type of parameter> <parameter value>\n" );
}

int
qcsapi_main(qcsapi_output *print, int argc, char **argv)
{
	int ival;
	int exitval = 0;

	if (argc <= 1) {
		call_qscapi_help(print);
		return -EINVAL;
	}

	argc--;
	argv++;

	ival = process_options(print, argc, argv);
	if (ival < 0) {
		exitval = ival;
	} else {
		argc = argc - ival;
		argv += ival;

		exitval = call_qcsapi(print, argc, argv);
	}

	return exitval;
}
