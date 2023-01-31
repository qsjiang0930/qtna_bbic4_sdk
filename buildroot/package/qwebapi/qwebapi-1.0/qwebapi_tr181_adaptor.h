/*SH1
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications Inc                   **
**                                                                           **
**  File        : qwebapi_tr181_adaptor.h                                    **
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
EH1*/

#ifndef _QWEBAPI_TR181_ADAPTOR_H_
#define _QWEBAPI_TR181_ADAPTOR_H_

#include "qwebapi.h"
#include <sys/sysinfo.h>
#include <netinet/ether.h>
#include "qwebapi_core.h"
#include "qwebapi_util.h"
#include <pthread.h>
#include <errno.h>

#define QWEBAPI_TR181_STRING_MAX_LEN                            (1024)
#define QWEBAPI_TR181_VERSION_MAX_LEN                           (64)
#define QWEBAPI_TR181_STR_DELIM                                 (",")
#define QWEBAPI_TR181_IP_STR_MAX_LEN                            (45)
#define QWEBAPI_TR181_PASSPHRASE_MAX_LEN                        (64)
#define QWEBAPI_TR181_PORT_STR_MAX_LEN                          (8)
#define QWEBAPI_IFNAME_MAX_LEN                                  (32)
#define QWEBAPI_SSID_MAX_LEN                                    (32)
#define QWEBAPI_SSID_MIN_LEN                                    (1)
#define QWEBAPI_MAX_WDS_LINKS                                   (8)

#ifdef TOPAZ_DBDC
#define QWEBAPI_MAX_24G_BSSID                                   (5)
#define QWEBAPI_MAX_24G_VAP                                     (4)
#define QWEBAPI_CMD_MAX_LEN                                     (64)
#endif

#define QWEBAPI_MAX_BSSID                                       (8)
#define QWEBAPI_QTN_WDS_ONLY                                    (0x0000)	/* 0 = Plain WDS; No WDS Extender */
#define QWEBAPI_QTN_WDS_MBS                                     (0x0001)	/* 1 = MBS-Master Base Station */
#define QWEBAPI_QTN_WDS_RBS                                     (0x0002)	/* 2 = RBS-Repeater/Remote Base Station */
#define QWEBAPI_QTN_WDS_MASK                                    (0x0003)
#define QWEBAPI_QTN_EXTDR_ALLMASK                               (0xFFFF)
#define QWEBAPI_QTN_EXTDR_MASK_SHIFT                            (16)
#define QWEBAPI_MAX_BITRATE_STR_MIN_LEN                         (4)

/* Common */
#define ITEM_NAME_STATS                                         ("Stats")
#define ITEM_NAME_BYTES_SENT                                    ("BytesSent")
#define ITEM_NAME_BYTES_RECEIVED                                ("BytesReceived")
#define ITEM_NAME_PACKETS_SENT                                  ("PacketsSent")
#define ITEM_NAME_PACKETS_RECEIVED                              ("PacketsReceived")
#define ITEM_NAME_ERRORS_SENT                                   ("ErrorsSent")
#define ITEM_NAME_ERRORS_RECEIVED                               ("ErrorsReceived")
#define ITEM_NAME_DISCARD_PACKETS_SENT                          ("DiscardPacketsSent")
#define ITEM_NAME_DISCARD_PACKETS_RECEIVED                      ("DiscardPacketsReceived")
#define ITEM_NAME_UNICAST_PACKETS_SENT                          ("UnicastPacketsSent")
#define ITEM_NAME_UNICAST_PACKETS_RECEIVED                      ("UnicastPacketsReceived")
#define ITEM_NAME_MULTICAST_PACKETS_SENT                        ("MulticastPacketsSent")
#define ITEM_NAME_MULTICAST_PACKETS_RECEIVED                    ("MulticastPacketsReceived")
#define ITEM_NAME_BROADCAST_PACKETS_SENT                        ("BroadcastPacketsSent")
#define ITEM_NAME_BROADCAST_PACKETS_RECEIVED                    ("BroadcastPacketsReceived")
#define ITEM_NAME_UNKNOWN_PACKETS_RECEIVED                      ("UnknownProtoPacketsReceived")
#define ITEM_NAME_LOWER_LAYERS                                  ("LowerLayers")
#define ITEM_NAME_ALIAS                                         ("Alias")
#define ITEM_NAME_LAST_CHANGE                                   ("LastChange")
#define ITEM_NAME_UP_STREAM                                     ("Upstream")
#define ITEM_NAME_NAME                                          ("Name")
#define ITEM_NAME_RETRANSMISSIONS                               ("Retransmissions")
#define ITEM_NAME_ACTIVE                                        ("Active")
#define ITEM_NAME_AVAILABLE                                     ("Available")
#define ITEM_NAME_RETRY_LIMIT                                   ("RetryLimit")
#define ITEM_NAME_RESET                                         ("Reset")
#define ITEM_NAME_ENABLE                                        ("Enable")
#define ITEM_NAME_DISABLE                                       ("Disable")
#define ITEM_NAME_STATUS                                        ("Status")
#define ITEM_NAME_MAC_ADDR                                      ("MACAddress")
#define ITEM_NAME_SECURITY                                      ("Security")
#define ITEM_NAME_ACCOUNTING                                    ("Accounting")
#define ITEM_NAME_LAST_DATA_DOWNLINK_RATE                       ("LastDataDownlinkRate")
#define ITEM_NAME_LAST_DATA_UPLINK_RATE                         ("LastDataUplinkRate")
#define ITEM_NAME_MODE_SUPPORTED                                ("ModesSupported")
#define ITEM_NAME_MODE_NONE                                     ("None")
#define ITEM_NAME_MODE_WPA2_AES                                 ("WPA2-Personal")
#define ITEM_NAME_MODE_WPA2_WPA                                 ("WPA-WPA2-Personal")
#define ITEM_NAME_MODE_WPA2_AES_ENTERPRISE                      ("WPA2-Enterprise")
#define ITEM_NAME_MODE_WPA2_AES_SHA256                          ("WPA2-AES-SHA256")
#define ITEM_NAME_MODE_WPA2_WPA_ENTERPRISE                      ("WPA-WPA2-Enterprise")
#define ITEM_NAME_MODE_WPA_TKIP                                 ("WPA-TKIP")
#define ITEM_NAME_MODE_WPA_AES                                  ("WPA-Personal")
#define ITEM_NAME_MODE_WPA2_TKIP                                ("WPA2-TKIP")
#define ITEM_NAME_MODE_SAE				("SAE")
#define ITEM_NAME_MODE_SAE_WPA_PSK			("SAE-WPA-PSK")
#define ITEM_NAME_MODE_OWE				("OWE")

#ifdef TOPAZ_DBDC
#define ITEM_NAME_MODE_NONE_24G                                 ("open")
#define ITEM_NAME_MODE_WPA_AES_24G                              ("wpa_aes")
#define ITEM_NAME_MODE_WPA_TKIP_24G                             ("wpa_tkip")
#define ITEM_NAME_MODE_WPA2_AES_24G                             ("wpa2_aes")
#define ITEM_NAME_MODE_WPA2_TKIP_24G                            ("wpa2_tkip")
#define ITEM_NAME_MODE_WPA2_WPA_24G                             ("mixed")
#define ITEM_NAME_MODE_SAE_24G			("sae")
#define ITEM_NAME_MODE_SAE_WPA_PSK_24G		("sae-wpa-psk")
#define ITEM_NAME_MODE_OWE_24G			("owe")
#endif

#define ITEM_NAME_AUTH_PROTO_NONE                               ("NONE")
#define ITEM_NAME_AUTH_PROTO_BASIC                              ("Basic")
#define ITEM_NAME_AUTH_PROTO_WPA                                ("WPA")
#define ITEM_NAME_AUTH_PROTO_11I                                ("11i")
#define ITEM_NAME_AUTH_PROTO_WPA_AND_11I                        ("WPAand11i")
#define ITEM_NAME_AUTH_TYPE_PSK                                 ("PSKAuthentication")
#define ITEM_NAME_AUTH_TYPE_EAP                                 ("EAPAuthentication")
#define ITEM_NAME_AUTH_TYPE_SHA256PSK                           ("SHA256PSKAuthentication")
#define ITEM_NAME_AUTH_TYPE_SAE			("SAEAuthentication")
#define ITEM_NAME_AUTH_TYPE_SAE_WPA_PSK		("SAEandPSKAuthentication")
#define ITEM_NAME_AUTH_TYPE_OWE			("OPENandOWEAuthentication")
#define ITEM_NAME_ENCRY_TYPE_AES                                ("AESEncryption")
#define ITEM_NAME_ENCRY_TYPE_TKIP                               ("TKIPEncryption")
#define ITEM_NAME_ENCRY_TYPE_TKIP_AES                           ("TKIPandAESEncryption")
#define ITEM_NAME_REKEYING_INTERVAL                             ("RekeyingInterval")
#define ITEM_NAME_KEY_PASSPHRASE                                ("KeyPassphrase")
#define ITEM_NAME_PRE_SHARED_KEY                                ("PreSharedKey")
#define ITEM_NAME_MODE_ENABLED                                  ("ModeEnabled")
#define ITEM_NAME_PRIORITY                                      ("Priority")
#define ITEM_NAME_WPS                                           ("WPS")
#define ITEM_NAME_SSID_REFERENCE                                ("SSIDReference")

/* Device */
#define ITEM_NAME_DEVICE                                        ("Device")

/* Device.DeviceInfo */
#define ITEM_NAME_DEVICE_INFO                                   ("DeviceInfo")
#define ITEM_NAME_MODEL_NAME                                    ("ModelName")
#define ITEM_NAME_SOFTWARE_VERSION                              ("SoftwareVersion")
#define ITEM_NAME_UPTIME                                        ("UpTime")

/* Device.WiFi */
#define ITEM_NAME_RADIO_NUMBER                                  ("RadioNumberOfEntries")
#define ITEM_NAME_SSID_NUMBER                                   ("SSIDNumberOfEntries")
#define ITEM_NAME_AP_NUMBER                                     ("AccessPointNumberOfEntries")
#define ITEM_NAME_END_POINT_NUMBER                              ("EndPointNumberOfEntries")

/* Device.WiFi.Radio */
#define ITEM_NAME_RADIO                                         ("Radio")
#define ITEM_NAME_CHANNEL                                       ("Channel")
#define ITEM_NAME_POSSIBLE_CHANNEL                              ("PossibleChannels")
#define ITEM_NAME_CHANNELS_IN_USE                               ("ChannelsInUse")
#define ITEM_NAME_AUTO_CHANNEL_SUPPORTED                        ("AutoChannelSupported")
#define ITEM_NAME_AUTO_CHANNEL_ENABLE                           ("AutoChannelEnable")
#define ITEM_NAME_SUPPORTED_STANDARDS                           ("SupportedStandards")
#define ITEM_NAME_OPERATING_STANDARDS                           ("OperatingStandards")
#define ITEM_NAME_STANDARDS_A                                   ("a")
#define ITEM_NAME_STANDARDS_B                                   ("b")
#define ITEM_NAME_STANDARDS_G                                   ("g")
#define ITEM_NAME_STANDARDS_BG                                  ("bg")
#define ITEM_NAME_STANDARDS_NA                                  ("na")
#define ITEM_NAME_STANDARDS_NG                                  ("ng")
#define ITEM_NAME_STANDARDS_AC                                  ("ac")
#define ITEM_NAME_STANDARDS_80211_A                             ("11a")
#define ITEM_NAME_STANDARDS_80211_NA                            ("11na")
#define ITEM_NAME_STANDARDS_80211_B                             ("11b")
#define ITEM_NAME_STANDARDS_80211_G                             ("11g")
#define ITEM_NAME_STANDARDS_80211_NG                            ("11ng")
#define ITEM_NAME_STANDARDS_80211_AC                            ("11ac")
#define ITEM_NAME_X_QUANTENNA_COM_SUPPORTED_BW                  ("X_QUANTENNA_COM_SupportedBandwidth")
#define ITEM_NAME_BW                                            ("OperatingChannelBandwidth")
#define ITEM_NAME_BW_20M                                        ("20MHz")
#define ITEM_NAME_BW_40M                                        ("40MHz")
#define ITEM_NAME_BW_80M                                        ("80MHz")
#define ITEM_NAME_BW_160M                                       ("160MHz")
#define ITEM_NAME_80211H_SUPPORTED                              ("IEEE80211hSupported")
#define ITEM_NAME_80211H_ENABLED                                ("IEEE80211hEnabled")
#define ITEM_NAME_BI                                            ("BeaconPeriod")
#define ITEM_NAME_DTIM                                          ("DTIMPeriod")
#define ITEM_NAME_OPERATING_BAND                                ("OperatingFrequencyBand")
#define ITEM_NAME_SUPPORTED_FREQUENCY_BANDS                     ("SupportedFrequencyBands")
#define ITEM_NAME_OPERATING_BAND_24G                            ("2.4GHz")
#define ITEM_NAME_OPERATING_BAND_5G                             ("5GHz")
#define ITEM_NAME_X_QUANTENNA_COM_MODE                          ("X_QUANTENNA_COM_Mode")
#define ITEM_NAME_AP                                            ("ap")
#define ITEM_NAME_STA                                           ("sta")
#define ITEM_NAME_WDS                                           ("wds")
#define ITEM_NAME_REPEATER                                      ("repeater")
#define ITEM_NAME_X_QUANTENNA_COM_PMF                           ("X_QUANTENNA_COM_PMF")
#define ITEM_NAME_X_QUANTENNA_COM_NSS                           ("X_QUANTENNA_COM_NSS")
#define ITEM_NAME_HT                                            ("ht")
#define ITEM_NAME_VHT                                           ("vht")
#define ITEM_NAME_X_QUANTENNA_COM_PRIORITY                      ("X_QUANTENNA_COM_Priority")
#define ITEM_NAME_MCS                                           ("MCS")
#define ITEM_NAME_X_QUANTENNA_COM_AUTO_RATE                     ("X_QUANTENNA_COM_Auto_rate")
#define ITEM_NAME_MAX_BIT_RATE                                  ("MaxBitRate")
#define ITEM_NAME_GUARD_INTERVAL                                ("GuardInterval")
#define ITEM_NAME_REGULATORY_DOMAIN                             ("RegulatoryDomain")
#define ITEM_NAME_X_QUANTENNA_COM_REGULATORY_CHANNEL            ("X_QUANTENNA_COM_Regulatory_channel")
#define ITEM_NAME_PREAMBLE_TYPE                                 ("PreambleType")
#define ITEM_NAME_TRANSMIT_POWER_SUPPORTED                      ("TransmitPowerSupported")
#define ITEM_NAME_TRANSMIT_POWER                                ("TransmitPower")
#define ITEM_NAME_NOISE                                         ("Noise")
#define ITEM_NAME_AUTO_CHANNEL_REFRESH_PERIOD                   ("AutoChannelRefreshPeriod")
#define ITEM_NAME_EXTENSION_CHANNEL                             ("ExtensionChannel")
#define ITEM_NAME_WEP_KEY                                       ("WEPKey")

/* Device.WiFi.SSID */
#define ITEM_NAME_WIFI                                          ("WiFi")
#define ITEM_NAME_BSSID                                         ("BSSID")
#define ITEM_NAME_SSID                                          ("SSID")
#define ITEM_NAME_X_QUANTENNA_PRIMARY_INTERFACE                 ("X_QUANTENNA_COM_Primary_interface")

/* Device.WiFi.AccessPoint */
#define ITEM_NAME_ACCESSPOINT                                   ("AccessPoint")
#define ITEM_NAME_AP_ASSOC_COUNT                                ("AssociatedDeviceNumberOfEntries")
#define ITEM_NAME_ASSOCIATED_DEVICE                             ("AssociatedDevice")
#define ITEM_NAME_SIGNAL_STRENGTH                               ("SignalStrength")
#define ITEM_NAME_BROADCAST_SSID                                ("SSIDAdvertisementEnabled")
#define ITEM_NAME_MAC_ADDR_CONTROL_ENABLED                      ("MACAddressControlEnabled")
#define ITEM_NAME_ALLOWED_MAC_ADDR                              ("AllowedMACAddress")
#define ITEM_NAME_RADIUS_SERVER_IP_ADDR                         ("RadiusServerIPAddr")
#define ITEM_NAME_RADIUS_SERVER_PORT                            ("RadiusServerPort")
#define ITEM_NAME_RADIUS_SECRET                                 ("RadiusSecret")
#define ITEM_NAME_SECOND_RADIUS_SERVER_IP_ADDR                  ("SecondaryRadiusServerIPAddr")
#define ITEM_NAME_SECOND_RADIUS_SERVER_PORT                     ("SecondaryRadiusServerPort")
#define ITEM_NAME_SECOND_RADIUS_SECRET                          ("SecondaryRadiusSecret")
#define ITEM_NAME_X_QUANTENNA_COM_WPS_RUNTIME_STATE             ("X_QUANTENNA_COM_WPS_Runtime_State")
#define ITEM_NAME_DISABLED                                      ("disabled")
#define ITEM_NAME_CONFIGURED                                    ("configured")
#define ITEM_NAME_NOT_CONFIGURED                                ("not configured")
#define ITEM_NAME_CONFIG_METHODS_SUPPORTED                      ("ConfigMethodsSupported")
#define ITEM_NAME_CONFIG_METHODS_ENABLED                        ("ConfigMethodsEnabled")
#define ITEM_NAME_WPS_PBC                                       ("PushButton")
#define ITEM_NAME_WPS_PIN                                       ("PIN")
#define ITEM_NAME_WPS_CONFIG_VALUE_LABEL                        ("label")
#define ITEM_NAME_WPS_CONFIG_VALUE_DISPLAY                      ("display")
#define ITEM_NAME_WPS_CONFIG_VALUE_V_DISPLAY                    ("virtual_display")
#define ITEM_NAME_WPS_CONFIG_VALUE_PBC                          ("push_button")
#define ITEM_NAME_WPS_CONFIG_VALUE_V_PBC                        ("virtual_push_button")
#define ITEM_NAME_WPS_CONFIG_VALUE_P_PBC                        ("physical_push_button")
#define ITEM_NAME_WPS_CONFIG_VALUE_KEYPAD                       ("keypad")
#define ITEM_NAME_WPS_AP_PIN                                    ("X_QUANTENNA_COM_AP_PIN")
#define ITEM_NAME_WPS_STATION_PIN                               ("X_QUANTENNA_COM_STA_PIN")
#define ITEM_NAME_WPS_REGRENERATE_PIN                           ("X_QUANTENNA_COM_Regenerate_PIN")
#define ITEM_NAME_WPS_REG_REPORT_BUTTON_PRESS                   ("X_QUANTENNA_COM_REG_report_button_press")
#define ITEM_NAME_WPS_ENR_REPORT_BUTTON_PRESS                   ("X_QUANTENNA_COM_ENR_report_button_press")
#define ITEM_NAME_WPS_STATE                                     ("X_QUANTENNA_COM_State")
#define ITEM_NAME_WPS_CONFIGURED_STATE                          ("X_QUANTENNA_COM_Configured_State")
#define ITEM_NAME_WPS_REG_REPORT_PIN                            ("X_QUANTENNA_COM_REG_report_pin")
#define ITEM_NAME_WPS_ENR_REPORT_PIN                            ("X_QUANTENNA_COM_ENR_report_pin")
#define ITEM_NAME_WMM_ENABLE                                    ("WMMEnable")
#define ITEM_NAME_WMM_CAPABILITY                                ("WMMCapability")
#define ITEM_NAME_UAPSD_CAPABILITY                              ("UAPSDCapability")
#define ITEM_NAME_UAPSD_ENABLE                                  ("UAPSDEnable")
#define ITEM_NAME_MAX_ASSOC_DEVICES                             ("MaxAssociatedDevices")
#define ITEM_NAME_ISOLATION_ENABLE                              ("IsolationEnable")
#define ITEM_NAME_X_QUANTENNA_COM_VLAN_CONFIG                   ("X_QUANTENNA_COM_vlan_config")
#define ITEM_NAME_X_QUANTENNA_COM_VLAN_TAGRX_CONFIG             ("X_QUANTENNA_COM_vlan_tagrx_config")
#define ITEM_NAME_ACCESS                                        ("access")
#define ITEM_NAME_TRUNK                                         ("trunk")
#define ITEM_NAME_HYBRID                                        ("hybrid")
#define ITEM_NAME_DYNAMIC                                       ("dynamic")
#define ITEM_NAME_BIND                                          ("bind")
#define ITEM_NAME_UNBIND                                        ("unbind")
#define ITEM_NAME_DEFAULT                                       ("default")
#define ITEM_NAME_TAG                                           ("tag")
#define ITEM_NAME_UNTAG                                         ("untag")
#define ITEM_NAME_DELETE                                        ("delete")
#define ITEM_NAME_TAGRX                                         ("tagrx")
#define ITEM_NAME_X_QUANTENNA_COM_INTERWORKING                  ("X_QUANTENNA_COM_interworking")
#define ITEM_NAME_X_QUANTENNA_COM_80211U_INTERNET_ACCESS        ("X_QUANTENNA_COM_80211u_internet_access")
#define ITEM_NAME_X_QUANTENNA_COM_80211U_ACCESS_NETWORK_TYPE    ("X_QUANTENNA_COM_80211u_access_network_type")
#define ITEM_NAME_X_QUANTENNA_COM_80211U_NETWORK_AUTH_TYPE      ("X_QUANTENNA_COM_80211u_network_auth_type")
#define ITEM_NAME_X_QUANTENNA_COM_80211U_HESSID                 ("X_QUANTENNA_COM_80211u_hessid")
#define ITEM_NAME_X_QUANTENNA_COM_80211U_DOMAIN_NAME            ("X_QUANTENNA_COM_80211u_domain_name")
#define ITEM_NAME_X_QUANTENNA_COM_IPADDR_TYPE_AVAILABILITY      ("X_QUANTENNA_COM_80211u_ipaddr_type_availability")
#define ITEM_NAME_X_QUANTENNA_COM_ANQP_3GPP_CELL_NET            ("X_QUANTENNA_COM_80211u_anqp_3gpp_cell_net")
#define ITEM_NAME_X_QUANTENNA_COM_VENUE_GROUP                   ("X_QUANTENNA_COM_80211u_venue_group")
#define ITEM_NAME_X_QUANTENNA_COM_VENUE_TYPE                    ("X_QUANTENNA_COM_80211u_venue_type")
#define ITEM_NAME_X_QUANTENNA_COM_VENUE_NAME                    ("X_QUANTENNA_COM_80211u_venue_name")
#define ITEM_NAME_X_QUANTENNA_COM_GAS_COMEBACK_DELAY            ("X_QUANTENNA_COM_80211u_gas_comeback_delay")
#define ITEM_NAME_X_QUANTENNA_COM_NAI_REALM                     ("X_QUANTENNA_COM_nai_realm")
#define ITEM_NAME_X_QUANTENNA_COM_ROAMING_CONSORTIUM            ("X_QUANTENNA_COM_roaming_consortium")
#define ITEM_NAME_X_QUANTENNA_COM_HS20_STATUS                   ("X_QUANTENNA_COM_hs20_status")
#define ITEM_NAME_X_QUANTENNA_COM_HS20_WAN_METRICS              ("X_QUANTENNA_COM_hs20_wan_metrics")
#define ITEM_NAME_X_QUANTENNA_COM_HS20_DISABLE_DGAF             ("X_QUANTENNA_COM_hs20_disable_dgaf")
#define ITEM_NAME_X_QUANTENNA_COM_HS20_OSEN                     ("X_QUANTENNA_COM_hs20_osen")
#define ITEM_NAME_X_QUANTENNA_COM_HS20_DEAUTH_REQ_TIMEOUT       ("X_QUANTENNA_COM_hs20_deauth_req_timeout")
#define ITEM_NAME_X_QUANTENNA_COM_HS20_OPERATING_CLASS          ("X_QUANTENNA_COM_hs20_operating_class")
#define ITEM_NAME_X_QUANTENNA_COM_HS20_OSU_SSID                 ("X_QUANTENNA_COM_hs20_osu_ssid")
#define ITEM_NAME_X_QUANTENNA_COM_HS20_CONN_CAPAB               ("X_QUANTENNA_COM_hs20_conn_capab")
#define ITEM_NAME_X_QUANTENNA_COM_PROXY_ARP                     ("X_QUANTENNA_COM_proxy_arp")
#define ITEM_NAME_X_QUANTENNA_COM_OPER_FRIENDLY_NAME            ("X_QUANTENNA_COM_oper_friendly_name")
#define ITEM_NAME_X_QUANTENNA_COM_BEACON_TYPE                   ("X_QUANTENNA_COM_beacon_type")
#define ITEM_NAME_X_QUANTENNA_COM_WPA_ENCRY_MODES               ("X_QUANTENNA_COM_WPA_encryption_modes")
#define ITEM_NAME_X_QUANTENNA_COM_WPA_AUTH_MODE                 ("X_QUANTENNA_COM_WPA_authentication_mode")
#define ITEM_NAME_X_QUANTENNA_COM_OWN_IP_ADDR                   ("X_QUANTENNA_COM_own_ip_addr")
#define ITEM_NAME_X_QUANTENNA_COM_WDS_PEER                      ("X_QUANTENNA_COM_WDS_peer")
#define ITEM_NAME_X_QUANTENNA_COM_WDS_PSK                       ("X_QUANTENNA_COM_WDS_psk")
#define ITEM_NAME_X_QUANTENNA_COM_WDS_MODE                      ("X_QUANTENNA_COM_WDS_mode")
#define ITEM_NAME_X_QUANTENNA_COM_WDS_RSSI                      ("X_QUANTENNA_COM_WDS_rssi")
#define ITEM_NAME_X_QUANTENNA_COM_80211R_ENABLE			("X_QUANTENNA_COM_80211r_enable")
#define ITEM_NAME_X_QUANTENNA_COM_80211R_MDID			("X_QUANTENNA_COM_80211r_mdid")
#define ITEM_NAME_INTERNET                                      ("internet")
#define ITEM_NAME_ACCESS_NETWORK_TYPE                           ("access_network_type")
#define ITEM_NAME_NETWORK_AUTH_TYPE                             ("network_auth_type")
#define ITEM_NAME_HESSID                                        ("hessid")
#define ITEM_NAME_DOMAIN_NAME                                   ("domain_name")
#define ITEM_NAME_IPADDR_TYPE_AVAILABILITY                      ("ipaddr_type_availability")
#define ITEM_NAME_ANQP_3GPP_CELL_NET                            ("anqp_3gpp_cell_net")
#define ITEM_NAME_VENUE_GROUP                                   ("venue_group")
#define ITEM_NAME_VENUE_TYPE                                    ("venue_type")
#define ITEM_NAME_VENUE_NAME                                    ("venue_name")
#define ITEM_NAME_GAS_COMEBACK_DELAY                            ("gas_comeback_delay")
#define ITEM_NAME_HS20_WAN_METRICS                              ("hs20_wan_metrics")
#define ITEM_NAME_HS20_DISABLE_DGAF                             ("disable_dgaf")
#define ITEM_NAME_HS20_OSEN                                     ("osen")
#define ITEM_NAME_HS20_DEAUTH_REQ_TIMEOUT                       ("hs20_deauth_req_timeout")
#define ITEM_NAME_HS20_OPERATING_CLASS                          ("hs20_operating_class")
#define ITEM_NAME_HS20_OSU_SSID                                 ("osu_ssid")
#define ITEM_NAME_RBS                                           ("rbs")
#define ITEM_NAME_MBS                                           ("mbs")
#define ITEM_NAME_WDS                                           ("wds")
#define ITEM_NAME_ASSOC_DEVICE_AUTH_STATE                       ("AuthenticationState")
#define ITEM_NAME_OPERATING_STANDARD                            ("OperatingStandard")

/* Device.WiFi.AccessPoint.Accounting */
#define ITEM_NAME_ACCOUNTING_SERVER_IP_ADDR                     ("ServerIPAddr")
#define ITEM_NAME_ACCOUNTING_SECONDARY_SERVER_IP_ADDR           ("SecondaryServerIPAddr")
#define ITEM_NAME_ACCOUNTING_SERVER_PORT                        ("ServerPort")
#define ITEM_NAME_ACCOUNTING_SECONDARY_SERVER_PORT              ("SecondaryServerPort")
#define ITEM_NAME_ACCOUNTING_SERVER_SECRET                      ("Secret")
#define ITEM_NAME_ACCOUNTING_SERVER_SECONDARY_SECRET            ("SecondarySecret")
#define ITEM_NAME_ACCOUNTING_SERVER_INTERIM_INTERVAL            ("InterimInterval")

/* Device.WiFi.EndPoint */
#define ITEM_NAME_ENDPOINT                                      ("EndPoint")
#define ITEM_NAME_ENDPOINT_PROFILE_NUM                          ("ProfileNumberOfEntries")
#define ITEM_NAME_ENDPOINT_PROFILE                              ("Profile")
#define ITEM_NAME_ENDPOINT_PROFILE_REFERENCE                    ("ProfileReference")
#define ITEM_NAME_ENDPOINT_LOCATION                             ("Location")

/* Device.DHCPv4 */
#define ITEM_NAME_DHCPV4                                        ("DHCPv4")
#define ITEM_NAME_CLIENT                                        ("Client")
#define ITEM_NAME_IP_ADDRESS                                    ("IPAddress")
#define ITEM_NAME_SUB_NETMASK                                   ("SubnetMask")

/* Device.Ethernet */
#define ITEM_NAME_ETHERNET                                      ("Ethernet")
#define ITEM_NAME_INTERFACE                                     ("Interface")

/* Value */
#define ITEM_VALUE_BW_20M                                       (20)
#define ITEM_VALUE_BW_40M                                       (40)
#define ITEM_VALUE_BW_80M                                       (80)
#define ITEM_VALUE_BW_160M                                      (160)
#define ITEM_VALUE_GI_800                                       ("800nsec")
#define ITEM_VALUE_GI_400                                       ("400nsec")
#define ITEM_VALUE_GI_AUTO                                      ("Auto")
#define ITEM_VALUE_PREAMBLE_TYPE_SHORT                          ("short")
#define ITEM_VALUE_PREAMBLE_TYPE_LONG                           ("long")
#define ITEM_VALUE_PREAMBLE_TYPE_AUTO                           ("auto")
#define ITEM_VALUE_CHANNEL                                      ("channel")
#define ITEM_VALUE_MODE                                         ("mode")
#define ITEM_VALUE_ENABLED                                      ("Enabled")
#define ITEM_VALUE_DISABLED                                     ("Disabled")
#define ITEM_VALUE_UP                                           ("Up")
#define ITEM_VALUE_DOWN	                                        ("Down")
#define ITEM_VALUE_ERROR                                        ("Error")
#define ITEM_VALUE_UNKNOWN                                      ("Unknown")
#define ITEM_VALUE_NONE                                         ("none")
#define ITEM_VALUE_ACCT_SERVER_IP                               ("acct_server_addr")
#define ITEM_VALUE_ACCT_SERVER_PORT                             ("acct_server_port")
#define ITEM_VALUE_ACCT_SERVER_SECRET                           ("acct_server_shared_secret")
#define ITEM_VALUE_ACCT_SERVER_INTERIM_INTERVAL                 ("radius_acct_interim_interval")
#define ITEM_VALUE_IPADDR                                       ("ipaddr")
#define ITEM_VALUE_NETMASK                                      ("netmask")
#define ITEM_VALUE_STATIC_IP                                    ("staticip")

/***************************MACRO Definition**********************************/
#define DECLARE_QWEB_SET_OBJ_FUNC(func_name)  \
int qweb_set_##func_name(char *path, JSON *obj)

#define DECLARE_QWEB_GET_OBJ_FUNC(func_name)  \
JSON *qweb_get_##func_name(char *path, int *perr)

#define DECLARE_QWEB_SET_INT_FUNC(func_name)  \
int qweb_set_##func_name(char *path, int value)

#define DECLARE_QWEB_GET_INT_FUNC(func_name)  \
int qweb_get_##func_name(char *path, int *perr)

#define DECLARE_QWEB_SET_UINT8_FUNC(func_name)  \
int qweb_set_##func_name(char *path, uint8_t value)

#define DECLARE_QWEB_GET_UINT8_FUNC(func_name)  \
uint8_t qweb_get_##func_name(char *path, int *perr)

#define DECLARE_QWEB_SET_UINT_FUNC(func_name)  \
int qweb_set_##func_name(char *path, unsigned int value)

#define DECLARE_QWEB_GET_UINT_FUNC(func_name)  \
unsigned int qweb_get_##func_name(char *path, int *perr)

#define DECLARE_QWEB_GET_UINT64_FUNC(func_name)  \
uint64_t qweb_get_##func_name(char *path, int *perr)

#define DECLARE_QWEB_GET_STATS_FUNC(func_name)  \
uint64_t qweb_get_##func_name(char *path, int *perr)

#define DECLARE_QWEB_SET_STRING_FUNC(func_name)  \
int qweb_set_##func_name(char *path, char *value)

#define DECLARE_QWEB_GET_STRING_FUNC(func_name)  \
char *qweb_get_##func_name(char *path, int *perr)

#define DECLARE_QWEB_SET_BEFORE_FUNC(func_name)  \
int qweb_set_##func_name##_before(char *path);

#define DECLARE_QWEB_SET_AFTER_FUNC(func_name) \
int qweb_set_##func_name##_after(char *path);

#define DECLARE_QWEB_GET_BEFORE_FUNC(func_name)  \
int qweb_get_##func_name##_before(char *path);

#define DECLARE_QWEB_GET_AFTER_FUNC(func_name) \
int qweb_get_##func_name##_after(char *path);

#define DECLARE_QWEB_CHECK_FUNC(func_name) \
int qweb_check_##func_name(char *path, JSON *obj);

/***************************Function Declaration******************************/

/* Device.DeviceInfo */
/* Model Name */
DECLARE_QWEB_GET_STRING_FUNC(model_name);

/* Software Version */
DECLARE_QWEB_GET_STRING_FUNC(software_version);

/* UpTime */
DECLARE_QWEB_GET_INT_FUNC(uptime);

/* Device.WiFi.RadioNumberOfEntries */
DECLARE_QWEB_GET_UINT_FUNC(radio_number_of_entries);

/* Device.WiFi.SSIDNumberOfEntries */
DECLARE_QWEB_GET_UINT_FUNC(ssid_number_of_entries);

/* Device.WiFi.AccessPointNumberOfEntries */
DECLARE_QWEB_GET_UINT_FUNC(ap_number_of_entries);

/* Device.WiFi.EndPointNumberOfEntries */
DECLARE_QWEB_GET_UINT_FUNC(endpoint_number_of_entries);

/* Device.WiFi.Radio */
int qweb_get_radio_num(char *path);

/* Device.WiFi.Radio.{i}.Enable */
DECLARE_QWEB_SET_UINT_FUNC(radio_enable);
DECLARE_QWEB_GET_UINT_FUNC(radio_enable);

/* Device.WiFi.Radio.{i}.Status */
DECLARE_QWEB_GET_STRING_FUNC(radio_status);

/* Device.WiFi.Radio.{i}.Alias */
DECLARE_QWEB_SET_STRING_FUNC(radio_alias);
DECLARE_QWEB_GET_STRING_FUNC(radio_alias);

/* Device.WiFi.Radio.{i}.Name */
DECLARE_QWEB_GET_STRING_FUNC(radio_name);

/* Device.WiFi.Radio.{i}.LastChange */
DECLARE_QWEB_GET_UINT_FUNC(radio_last_change);

/* Device.WiFi.Radio.{i}.LowerLayers */
DECLARE_QWEB_GET_STRING_FUNC(radio_lower_layers);

/* Device.WiFi.Radio.{i}.Upstream */
DECLARE_QWEB_GET_UINT_FUNC(radio_up_stream);

/* Device.WiFi.Radio.{i}.MaxBitRate */
DECLARE_QWEB_GET_STRING_FUNC(max_bit_rate);

/* Device.WiFi.Radio.{i}.SupportedFrequencyBands */
DECLARE_QWEB_GET_STRING_FUNC(supported_frequency_bands);

/* Device.WiFi.Radio.{i}.OperatingBand */
DECLARE_QWEB_SET_STRING_FUNC(operating_band);
DECLARE_QWEB_GET_STRING_FUNC(operating_band);

/* Device.WiFi.Radio.{i}.SupportedStandards */
DECLARE_QWEB_GET_STRING_FUNC(supported_standards);

/* Device.WiFi.Radio.{i}.OperatingStandards */
DECLARE_QWEB_SET_STRING_FUNC(operating_standards);
DECLARE_QWEB_GET_STRING_FUNC(operating_standards);

/* Device.WiFi.Radio.{i}.ChannelsInUse */
DECLARE_QWEB_GET_STRING_FUNC(channels_in_use);

/* Device.WiFi.Radio.{i}.Channel */
DECLARE_QWEB_SET_UINT_FUNC(channel);
DECLARE_QWEB_GET_UINT_FUNC(channel);

/* Device.WiFi.Radio.{i}.AutoChannelSupported */
DECLARE_QWEB_GET_UINT_FUNC(auto_channel_supported);

/* Device.WiFi.Radio.{i}.AutoChannelEnable */
DECLARE_QWEB_SET_UINT_FUNC(auto_channel_enable);
DECLARE_QWEB_GET_UINT_FUNC(auto_channel_enable);

/* Device.WiFi.Radio.{i}.AutoChannelRefreshPeriod */
DECLARE_QWEB_SET_UINT_FUNC(auto_channel_refresh_period);
DECLARE_QWEB_GET_UINT_FUNC(auto_channel_refresh_period);

/* Device.WiFi.Radio.{i}.OperatingChannelBandwidth */
DECLARE_QWEB_SET_STRING_FUNC(bw);
DECLARE_QWEB_GET_STRING_FUNC(bw);

/* Device.WiFi.Radio.{i}.ExtensionChannel */
DECLARE_QWEB_SET_STRING_FUNC(extension_channel);
DECLARE_QWEB_GET_STRING_FUNC(extension_channel);

/* Device.WiFi.Radio.{i}.GuardInterval */
DECLARE_QWEB_SET_STRING_FUNC(gi);
DECLARE_QWEB_GET_STRING_FUNC(gi);

/* Device.WiFi.Radio.{i}.MCS */
DECLARE_QWEB_SET_INT_FUNC(mcs);
DECLARE_QWEB_GET_INT_FUNC(mcs);

/* Device.WiFi.Radio.{i}.TransmitPowerSupported */
DECLARE_QWEB_GET_STRING_FUNC(transmit_power_supported);

/* Device.WiFi.Radio.{i}.TransmitPower*/
DECLARE_QWEB_SET_UINT_FUNC(transmit_power);
DECLARE_QWEB_GET_UINT_FUNC(transmit_power);

/* Device.WiFi.Radio.{i}.IEEE80211hSupported */
DECLARE_QWEB_GET_UINT_FUNC(option_80211h_supported);

/* Device.WiFi.Radio.{i}.IEEE80211hEnabled */
DECLARE_QWEB_SET_UINT_FUNC(doth_enable);
DECLARE_QWEB_GET_UINT_FUNC(doth_enable);

/* Device.WiFi.Radio.{i}.BeaconInterval */
DECLARE_QWEB_SET_UINT_FUNC(beacon_interval);
DECLARE_QWEB_GET_UINT_FUNC(beacon_interval);

/* Device.WiFi.Radio.{i}.DTIM */
DECLARE_QWEB_SET_UINT_FUNC(dtim);
DECLARE_QWEB_GET_UINT_FUNC(dtim);

/* Device.WiFi.Radio.{i}.PreambleType */
DECLARE_QWEB_SET_STRING_FUNC(preamble_type);
DECLARE_QWEB_GET_STRING_FUNC(preamble_type);

/* Device.WiFi.Radio.{i}.X_QUANTENNA_COM_Mode */
DECLARE_QWEB_SET_STRING_FUNC(mode);
DECLARE_QWEB_GET_STRING_FUNC(mode);

/* Device.WiFi.Radio.{i}.X_QUANTENNA_COM_PMF */
DECLARE_QWEB_SET_INT_FUNC(pmf);
DECLARE_QWEB_GET_INT_FUNC(pmf);

/* Device.WiFi.Radio.{i}.X_QUANTENNA_COM_NSS */
DECLARE_QWEB_SET_STRING_FUNC(nss);
DECLARE_QWEB_GET_STRING_FUNC(nss);

/* Device.WiFi.Radio.{i}.X_QUANTENNA_COM_Auto_rate */
DECLARE_QWEB_SET_INT_FUNC(option_auto_rate);
DECLARE_QWEB_GET_INT_FUNC(option_auto_rate);

/* Device.WiFi.Radio.{i}.X_QUANTENNA_COM_SupportedBandwidth */
DECLARE_QWEB_GET_STRING_FUNC(supported_bw);

/* Device.WiFi.Radio.{i}.RegulatoryDomain */
DECLARE_QWEB_SET_STRING_FUNC(regulatory_region);
DECLARE_QWEB_GET_STRING_FUNC(regulatory_region);

/* Device.WiFi.Radio.{i}.X_QUANTENNA_COM_Regulatory_channel */
DECLARE_QWEB_SET_STRING_FUNC(regulatory_channel);
DECLARE_QWEB_GET_STRING_FUNC(regulatory_channel);

/* Device.WiFi.SSID */
int qweb_get_ssid_max_num(char *path);
int qweb_add_ssid_entry(char *path, char *value);
int qweb_del_ssid_entry(char *path);
int qweb_ssid_exist(char *path);

/* Device.WiFi.SSID.{i}.Enable */
DECLARE_QWEB_SET_UINT_FUNC(SSID_enable);
DECLARE_QWEB_GET_UINT_FUNC(SSID_enable);

/* Device.WiFi.SSID.{i}.Status */
DECLARE_QWEB_GET_STRING_FUNC(SSID_status);

/* Device.WiFi.SSID.{i}.Alias */
DECLARE_QWEB_GET_STRING_FUNC(SSID_alias);

/* Device.WiFi.SSID.{i}.Name */
DECLARE_QWEB_SET_STRING_FUNC(SSID_name);
DECLARE_QWEB_GET_STRING_FUNC(SSID_name);

/* Device.WiFi.SSID.{i}.LastChange */
DECLARE_QWEB_GET_UINT_FUNC(SSID_last_change);

/* Device.WiFi.SSID.{i}.LowerLayers */
DECLARE_QWEB_GET_STRING_FUNC(SSID_lower_layers);

/* Device.WiFi.SSID.{i}.BSSID */
DECLARE_QWEB_GET_STRING_FUNC(bssid);

/* Device.WiFi.SSID.{i}.MACAddress */
DECLARE_QWEB_GET_STRING_FUNC(mac_addr);

/* Device.WiFi.SSID.{i}.SSID */
DECLARE_QWEB_SET_STRING_FUNC(ssid);
DECLARE_QWEB_GET_STRING_FUNC(ssid);
DECLARE_QWEB_CHECK_FUNC(ssid);

/* Device.WiFi.SSID.{i}.X_QUANTENNA_COM_Priority */
DECLARE_QWEB_SET_UINT_FUNC(priority);
DECLARE_QWEB_GET_UINT_FUNC(priority);
DECLARE_QWEB_CHECK_FUNC(priority);

/* Device.WiFi.SSID.{i}.X_QUANTENNA_COM_Primary_interface */
DECLARE_QWEB_GET_STRING_FUNC(primary_interface);

/* Device.WiFi.AccessPoint */
int qweb_get_ap_max_num(char *path);
int qweb_add_accesspoint_entry(char *path, char *value);
int qweb_del_accesspoint_entry(char *path);
int qweb_accesspoint_exist(char *path);

/* Device.WiFi.AccessPoint.{i}.Enable */
DECLARE_QWEB_SET_UINT_FUNC(accesspoint_enable);
DECLARE_QWEB_GET_UINT_FUNC(accesspoint_enable);

/* Device.WiFi.AccessPoint.{i}.Status */
DECLARE_QWEB_SET_STRING_FUNC(accesspoint_status);
DECLARE_QWEB_GET_STRING_FUNC(accesspoint_status);

/* Device.WiFi.AccessPoint.{i}.Alias */
DECLARE_QWEB_GET_STRING_FUNC(accesspoint_alias);

/* Device.WiFi.AccessPoint.{i}.SSIDReference */
DECLARE_QWEB_GET_STRING_FUNC(ap_ssid_reference);

/* Device.WiFi.AccessPoint.{i}.SSIDAdvertisementEnabled */
DECLARE_QWEB_SET_INT_FUNC(option_broadcast_ssid);
DECLARE_QWEB_GET_INT_FUNC(option_broadcast_ssid);

/* Device.WiFi.AccessPoint.{i}.RetryLimit */
DECLARE_QWEB_SET_UINT_FUNC(accesspoint_retry_limit);
DECLARE_QWEB_GET_UINT_FUNC(accesspoint_retry_limit);

/* Device.WiFi.AccessPoint.{i}.WMMCapability */
DECLARE_QWEB_GET_UINT_FUNC(wmm_capability);

/* Device.WiFi.AccessPoint.{i}.UAPSDCapability */
DECLARE_QWEB_GET_UINT_FUNC(uapsd_capability);

/* Device.WiFi.AccessPoint.{i}.WMMEnable */
DECLARE_QWEB_SET_INT_FUNC(option_wmm_enable);
DECLARE_QWEB_GET_INT_FUNC(option_wmm_enable);

/* Device.WiFi.AccessPoint.{i}.UAPSDEnable */
DECLARE_QWEB_SET_INT_FUNC(option_uapsd_enable);
DECLARE_QWEB_GET_INT_FUNC(option_uapsd_enable);

/* Device.WiFi.AccessPoint.{i}.AssociatedDeviceNumberOfEntries */
DECLARE_QWEB_GET_UINT_FUNC(count_associations);

/* Device.WiFi.AccessPoint.{i}.MaxAssociatedDevices */
DECLARE_QWEB_SET_UINT_FUNC(max_assoc_devices);
DECLARE_QWEB_GET_UINT_FUNC(max_assoc_devices);

/* Device.WiFi.AccessPoint.{i}.IsolationEnable */
DECLARE_QWEB_SET_INT_FUNC(isolation_enable);
DECLARE_QWEB_GET_INT_FUNC(isolation_enable);

/* Device.WiFi.AccessPoint.{i}.MACAddressControlEnabled */
DECLARE_QWEB_SET_BEFORE_FUNC(macaddr_filter);
DECLARE_QWEB_GET_BEFORE_FUNC(macaddr_filter);

DECLARE_QWEB_SET_UINT_FUNC(macaddr_filter);
DECLARE_QWEB_GET_UINT_FUNC(macaddr_filter);

/* Device.WiFi.AccessPoint.{i}.AllowedMACAddress */
DECLARE_QWEB_SET_BEFORE_FUNC(allowed_macaddr);
DECLARE_QWEB_GET_BEFORE_FUNC(allowed_macaddr);

DECLARE_QWEB_SET_STRING_FUNC(allowed_macaddr);
DECLARE_QWEB_GET_STRING_FUNC(allowed_macaddr);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_vlan_config */
DECLARE_QWEB_SET_STRING_FUNC(vlan_config);
DECLARE_QWEB_GET_STRING_FUNC(vlan_config);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_vlan_tagrx_config */
DECLARE_QWEB_GET_STRING_FUNC(vlan_tagrx_config);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_interworking */
DECLARE_QWEB_SET_STRING_FUNC(interworking);
DECLARE_QWEB_GET_STRING_FUNC(interworking);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211u_internet_access */
DECLARE_QWEB_SET_STRING_FUNC(internet_access);
DECLARE_QWEB_GET_STRING_FUNC(internet_access);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211u_access_network_type */
DECLARE_QWEB_SET_STRING_FUNC(access_network_type);
DECLARE_QWEB_GET_STRING_FUNC(access_network_type);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211u_network_auth_type */
DECLARE_QWEB_SET_STRING_FUNC(network_auth_type);
DECLARE_QWEB_GET_STRING_FUNC(network_auth_type);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211u_hessid */
DECLARE_QWEB_CHECK_FUNC(hessid);
DECLARE_QWEB_SET_STRING_FUNC(hessid);
DECLARE_QWEB_GET_STRING_FUNC(hessid);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211u_domain_name */
DECLARE_QWEB_SET_STRING_FUNC(domain_name);
DECLARE_QWEB_GET_STRING_FUNC(domain_name);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211u_ipaddr_type_availability */
DECLARE_QWEB_SET_STRING_FUNC(ipaddr_type_availability);
DECLARE_QWEB_GET_STRING_FUNC(ipaddr_type_availability);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211u_anqp_3gpp_cell_net */
DECLARE_QWEB_SET_STRING_FUNC(anqp_3gpp_cell_net);
DECLARE_QWEB_GET_STRING_FUNC(anqp_3gpp_cell_net);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211u_venue_group */
DECLARE_QWEB_SET_STRING_FUNC(venue_group);
DECLARE_QWEB_GET_STRING_FUNC(venue_group);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211u_venue_type */
DECLARE_QWEB_SET_STRING_FUNC(venue_type);
DECLARE_QWEB_GET_STRING_FUNC(venue_type);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211u_venue_name */
DECLARE_QWEB_SET_STRING_FUNC(venue_name);
DECLARE_QWEB_GET_STRING_FUNC(venue_name);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211u_gas_comeback_delay */
DECLARE_QWEB_SET_STRING_FUNC(gas_comeback_delay);
DECLARE_QWEB_GET_STRING_FUNC(gas_comeback_delay);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_nai_realm */
DECLARE_QWEB_SET_STRING_FUNC(nai_realm);
DECLARE_QWEB_GET_STRING_FUNC(nai_realm);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_roaming_consortium */
DECLARE_QWEB_SET_STRING_FUNC(roaming_consortium);
DECLARE_QWEB_GET_STRING_FUNC(roaming_consortium);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_hs20_status */
DECLARE_QWEB_SET_STRING_FUNC(hs20_status);
DECLARE_QWEB_GET_STRING_FUNC(hs20_status);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_hs20_wan_metrics */
DECLARE_QWEB_SET_STRING_FUNC(hs20_wan_metrics);
DECLARE_QWEB_GET_STRING_FUNC(hs20_wan_metrics);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_hs20_disable_dgaf */
DECLARE_QWEB_SET_STRING_FUNC(hs20_disable_dgaf);
DECLARE_QWEB_GET_STRING_FUNC(hs20_disable_dgaf);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_hs20_osen */
DECLARE_QWEB_SET_STRING_FUNC(hs20_osen);
DECLARE_QWEB_GET_STRING_FUNC(hs20_osen);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_hs20_deauth_req_timeout */
DECLARE_QWEB_SET_STRING_FUNC(hs20_deauth_req_timeout);
DECLARE_QWEB_GET_STRING_FUNC(hs20_deauth_req_timeout);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_hs20_operating_class */
DECLARE_QWEB_SET_STRING_FUNC(hs20_operating_class);
DECLARE_QWEB_GET_STRING_FUNC(hs20_operating_class);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_hs20_osu_ssid */
DECLARE_QWEB_SET_STRING_FUNC(hs20_osu_ssid);
DECLARE_QWEB_GET_STRING_FUNC(hs20_osu_ssid);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_hs20_conn_capab */
DECLARE_QWEB_SET_STRING_FUNC(hs20_conn_capab);
DECLARE_QWEB_GET_STRING_FUNC(hs20_conn_capab);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_proxy_arp*/
DECLARE_QWEB_SET_STRING_FUNC(proxy_arp);
DECLARE_QWEB_GET_STRING_FUNC(proxy_arp);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_oper_friendly_name */
DECLARE_QWEB_SET_STRING_FUNC(oper_friendly_name);
DECLARE_QWEB_GET_STRING_FUNC(oper_friendly_name);

/* Device.WiFi.AccessPoint.{i}.Security.Reset */
DECLARE_QWEB_SET_UINT_FUNC(security_reset);
DECLARE_QWEB_GET_UINT_FUNC(security_reset);

/* Device.WiFi.AccessPoint.{i}.Security.ModesSupported */
DECLARE_QWEB_GET_STRING_FUNC(accesspoint_mode_supported);

/* Device.WiFi.AccessPoint.{i}.Security.ModeEnabled */
DECLARE_QWEB_SET_STRING_FUNC(mode_enabled);
DECLARE_QWEB_GET_STRING_FUNC(mode_enabled);

/* Device.WiFi.AccessPoint.{i}.Security.KeyPassphrase */
DECLARE_QWEB_SET_STRING_FUNC(key_passphrase);
DECLARE_QWEB_GET_STRING_FUNC(key_passphrase);

/* Device.WiFi.AccessPoint.{i}.Security.WEPKey */
DECLARE_QWEB_SET_STRING_FUNC(wep_key);
DECLARE_QWEB_GET_STRING_FUNC(wep_key);

/* Device.WiFi.AccessPoint.{i}.Security.PreSharedKey */
DECLARE_QWEB_SET_STRING_FUNC(pre_shared_key);
DECLARE_QWEB_GET_STRING_FUNC(pre_shared_key);

/* Device.WiFi.AccessPoint.{i}.Security.RekeyingInterval */
DECLARE_QWEB_SET_UINT_FUNC(rekeying_interval);
DECLARE_QWEB_GET_UINT_FUNC(rekeying_interval);

/* Device.WiFi.AccessPoint.{i}.Security.RadiusServerIPAddr */
DECLARE_QWEB_SET_STRING_FUNC(radius_auth_server_ip);
DECLARE_QWEB_GET_STRING_FUNC(radius_auth_server_ip);

/* Device.WiFi.AccessPoint.{i}.Security.RadiusServerPort */
DECLARE_QWEB_SET_UINT_FUNC(radius_auth_server_port);
DECLARE_QWEB_GET_UINT_FUNC(radius_auth_server_port);

/* Device.WiFi.AccessPoint.{i}.Security.RadiusSecret */
DECLARE_QWEB_SET_STRING_FUNC(radius_auth_server_secret);
DECLARE_QWEB_GET_STRING_FUNC(radius_auth_server_secret);

/* Device.WiFi.AccessPoint.{i}.Security.SecondaryRadiusServerIPAddr */
DECLARE_QWEB_SET_STRING_FUNC(secondary_radius_auth_server_ip);
DECLARE_QWEB_GET_STRING_FUNC(secondary_radius_auth_server_ip);

/* Device.WiFi.AccessPoint.{i}.Security.SecondaryRadiusServerPort */
DECLARE_QWEB_SET_UINT_FUNC(secondary_radius_auth_server_port);
DECLARE_QWEB_GET_UINT_FUNC(secondary_radius_auth_server_port);

/* Device.WiFi.AccessPoint.{i}.Security.SecondaryRadiusSecret */
DECLARE_QWEB_SET_STRING_FUNC(secondary_radius_auth_server_secret);
DECLARE_QWEB_GET_STRING_FUNC(secondary_radius_auth_server_secret);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_beacon_type */
DECLARE_QWEB_SET_STRING_FUNC(beacon_type);
DECLARE_QWEB_GET_STRING_FUNC(beacon_type);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_WPA_encryption_modes */
DECLARE_QWEB_SET_STRING_FUNC(WPA_encryption_modes);
DECLARE_QWEB_GET_STRING_FUNC(WPA_encryption_modes);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_WPA_authentication_mode */
DECLARE_QWEB_SET_STRING_FUNC(WPA_authentication_mode);
DECLARE_QWEB_GET_STRING_FUNC(WPA_authentication_mode);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_own_ip_addr */
DECLARE_QWEB_SET_STRING_FUNC(own_ip_addr);
DECLARE_QWEB_GET_STRING_FUNC(own_ip_addr);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_WDS_peer */
DECLARE_QWEB_SET_STRING_FUNC(wds_peer);
DECLARE_QWEB_GET_STRING_FUNC(wds_peer);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_WDS_psk */
DECLARE_QWEB_SET_STRING_FUNC(wds_psk);
DECLARE_QWEB_GET_STRING_FUNC(wds_psk);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_WDS_mode */
DECLARE_QWEB_SET_STRING_FUNC(wds_mode);
DECLARE_QWEB_GET_STRING_FUNC(wds_mode);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_WDS_rssi */
DECLARE_QWEB_GET_STRING_FUNC(wds_rssi);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211r_enable */
DECLARE_QWEB_SET_STRING_FUNC(80211r_enable);
DECLARE_QWEB_GET_STRING_FUNC(80211r_enable);

/* Device.WiFi.AccessPoint.{i}.X_QUANTENNA_COM_80211r_mdid */
DECLARE_QWEB_SET_STRING_FUNC(80211r_mdid);
DECLARE_QWEB_GET_STRING_FUNC(80211r_mdid);

/* Device.WiFi.AccessPoint.{i}.Accounting.Enable */
DECLARE_QWEB_SET_UINT_FUNC(acct_enable);
DECLARE_QWEB_GET_UINT_FUNC(acct_enable);

/* Device.WiFi.AccessPoint.{i}.Accounting.ServerIPAddr */
DECLARE_QWEB_SET_STRING_FUNC(radius_acct_server_ip);
DECLARE_QWEB_GET_STRING_FUNC(radius_acct_server_ip);

/* Device.WiFi.AccessPoint.{i}.Accounting.SecondaryServerIPAddr */
DECLARE_QWEB_SET_STRING_FUNC(secondary_radius_acct_server_ip);
DECLARE_QWEB_GET_STRING_FUNC(secondary_radius_acct_server_ip);

/* Device.WiFi.AccessPoint.{i}.Accounting.ServerPort */
DECLARE_QWEB_SET_UINT_FUNC(radius_acct_server_port);
DECLARE_QWEB_GET_UINT_FUNC(radius_acct_server_port);

/* Device.WiFi.AccessPoint.{i}.Accounting.SecondaryServerPort */
DECLARE_QWEB_SET_UINT_FUNC(secondary_radius_acct_server_port);
DECLARE_QWEB_GET_UINT_FUNC(secondary_radius_acct_server_port);

/* Device.WiFi.AccessPoint.{i}.Accounting.Secret */
DECLARE_QWEB_SET_STRING_FUNC(radius_acct_server_secret);
DECLARE_QWEB_GET_STRING_FUNC(radius_acct_server_secret);

/* Device.WiFi.AccessPoint.{i}.Accounting.SecondarySecret */
DECLARE_QWEB_SET_STRING_FUNC(secondary_radius_acct_server_secret);
DECLARE_QWEB_GET_STRING_FUNC(secondary_radius_acct_server_secret);

/* Device.WiFi.AccessPoint.{i}.Accounting.InterimInterval */
DECLARE_QWEB_SET_UINT_FUNC(acct_interim_interval);
DECLARE_QWEB_GET_UINT_FUNC(acct_interim_interval);

/* Device.WiFi.AccessPoint.{i}.WPS.Enable */
DECLARE_QWEB_SET_INT_FUNC(ap_wps_enable);
DECLARE_QWEB_GET_INT_FUNC(ap_wps_enable);

/* Device.WiFi.AccessPoint.{i}.WPS.ConfigMethodsSupported */
DECLARE_QWEB_GET_STRING_FUNC(ap_wps_config_methods_supported);

/* Device.WiFi.AccessPoint.{i}.WPS.ConfigMethodsEnabled */
DECLARE_QWEB_SET_STRING_FUNC(ap_wps_config_methods_enabled);
DECLARE_QWEB_GET_STRING_FUNC(ap_wps_config_methods_enabled);

/* Device.WiFi.AccessPoint.{i}.WPS.X_QUANTENNA_COM_WPS_Runtime_State */
DECLARE_QWEB_GET_STRING_FUNC(wps_runtime_state);

/* Device.WiFi.AccessPoint.{i}.WPS.X_QUANTENNA_COM_AP_PIN */
DECLARE_QWEB_SET_STRING_FUNC(wps_ap_pin);
DECLARE_QWEB_GET_STRING_FUNC(wps_ap_pin);

/* Device.WiFi.AccessPoint.{i}.WPS.X_QUANTENNA_COM_Regenerate_PIN */
DECLARE_QWEB_GET_STRING_FUNC(wps_regenerate_pin);

/* Device.WiFi.AccessPoint.{i}.WPS.X_QUANTENNA_COM_State */
DECLARE_QWEB_GET_STRING_FUNC(wps_state);

/* Device.WiFi.AccessPoint.{i}.WPS.X_QUANTENNA_COM_Configured_State */
DECLARE_QWEB_SET_STRING_FUNC(wps_configured_state);
DECLARE_QWEB_GET_STRING_FUNC(wps_configured_state);

/* Device.WiFi.AccessPoint.{i}.WPS.X_QUANTENNA_COM_REG_report_button_press */
DECLARE_QWEB_SET_STRING_FUNC(wps_registrar_report_button_press);
DECLARE_QWEB_GET_STRING_FUNC(wps_registrar_report_button_press);

/* Device.WiFi.AccessPoint.{i}.WPS.X_QUANTENNA_COM_REG_report_pin */
DECLARE_QWEB_SET_STRING_FUNC(wps_registrar_report_pin);
DECLARE_QWEB_GET_STRING_FUNC(wps_registrar_report_pin);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice */
int qweb_get_associated_device_num(char *path);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.OperatingStandard */
DECLARE_QWEB_GET_STRING_FUNC(assoc_device_operating_standard);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.MACAddress */
DECLARE_QWEB_GET_STRING_FUNC(assoc_device_mac_addr);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.AuthenticationState */
DECLARE_QWEB_GET_STRING_FUNC(assoc_device_auth_state);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.LastDataDownlinkRate */
DECLARE_QWEB_GET_UINT_FUNC(assoc_device_tx_phy_rate);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.LastDataUplinkRate */
DECLARE_QWEB_GET_UINT_FUNC(assoc_device_rx_phy_rate);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.SignalStrength */
DECLARE_QWEB_GET_INT_FUNC(rssi_in_dbm_per_association);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Retransmissions */
DECLARE_QWEB_GET_UINT_FUNC(assoc_device_retransmissions);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Active */
DECLARE_QWEB_GET_UINT_FUNC(assoc_device_active);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.BytesSent */
DECLARE_QWEB_GET_UINT64_FUNC(assoc_device_bytes_sent);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.BytesReceived */
DECLARE_QWEB_GET_UINT64_FUNC(assoc_device_bytes_received);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.PacketsSent */
DECLARE_QWEB_GET_UINT_FUNC(assoc_device_packets_sent);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.PacketsReceived */
DECLARE_QWEB_GET_UINT_FUNC(assoc_device_packets_received);

/* Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.ErrorsSent*/
DECLARE_QWEB_GET_UINT_FUNC(assoc_device_errors_sent);

/* Device.WiFi.Radio.{i}.Stats.BytesSent */
DECLARE_QWEB_GET_UINT64_FUNC(interface_bytes_sent);

/* Device.WiFi.Radio.{i}.Stats.BytesReceived */
DECLARE_QWEB_GET_UINT64_FUNC(interface_bytes_received);

/* Device.WiFi.Radio.{i}.Stats.PacketsSent */
DECLARE_QWEB_GET_UINT64_FUNC(interface_packets_sent);

/* Device.WiFi.Radio.{i}.Stats.PacketsReceived */
DECLARE_QWEB_GET_UINT64_FUNC(interface_packets_received);

/* Device.WiFi.Radio.{i}.Stats.ErrorsSent */
DECLARE_QWEB_GET_UINT64_FUNC(interface_errors_sent);

/* Device.WiFi.Radio.{i}.Stats.ErrorsReceived */
DECLARE_QWEB_GET_UINT64_FUNC(interface_errors_received);

/* Device.WiFi.Radio.{i}.Stats.DiscardPacketsSent */
DECLARE_QWEB_GET_UINT64_FUNC(interface_discard_packets_sent);

/* Device.WiFi.Radio.{i}.Stats.DiscardPacketsReceived */
DECLARE_QWEB_GET_UINT64_FUNC(interface_discard_packets_received);

/* Device.WiFi.Radio.{i}.Stats.Noise */
DECLARE_QWEB_GET_INT_FUNC(noise);

/* Device.WiFi.SSID.{i}.Stats.BytesSent */
DECLARE_QWEB_GET_STATS_FUNC(interface_stats_bytes_sent);

/* Device.WiFi.SSID.{i}.Stats.BytesReceived */
DECLARE_QWEB_GET_STATS_FUNC(interface_stats_bytes_received);

/* Device.WiFi.SSID.{i}.Stats.PacketsSent */
DECLARE_QWEB_GET_STATS_FUNC(interface_stats_packets_sent);

/* Device.WiFi.SSID.{i}.Stats.PacketsReceived */
DECLARE_QWEB_GET_STATS_FUNC(interface_stats_packets_received);

/* Device.WiFi.SSID.{i}.Stats.ErrorsSent */
DECLARE_QWEB_GET_STATS_FUNC(interface_stats_errors_sent);

/* Device.WiFi.SSID.{i}.Stats.ErrorsReceived */
DECLARE_QWEB_GET_STATS_FUNC(interface_stats_errors_received);

/* Device.WiFi.SSID.{i}.Stats.UnicastPacketsSent */
DECLARE_QWEB_GET_STATS_FUNC(interface_stats_unicast_pkts_tx);

/* Device.WiFi.SSID.{i}.Stats.UnicastPacketsReceived */
DECLARE_QWEB_GET_STATS_FUNC(interface_stats_unicast_pkts_rx);

/* Device.WiFi.SSID.{i}.Stats.DiscardPacketsSent */
DECLARE_QWEB_GET_STATS_FUNC(interface_stats_discard_pkts_tx);

/* Device.WiFi.SSID.{i}.Stats.DiscardPacketsReceived */
DECLARE_QWEB_GET_STATS_FUNC(interface_stats_discard_pkts_rx);

/* Device.WiFi.SSID.{i}.Stats.MulticastPacketsSent */
DECLARE_QWEB_GET_STATS_FUNC(interface_stats_multicast_pkts_tx);

/* Device.WiFi.SSID.{i}.Stats.MulticastPacketsReceived */
DECLARE_QWEB_GET_STATS_FUNC(interface_stats_multicast_pkts_rx);

/* Device.WiFi.SSID.{i}.Stats.BroadcastPacketsSent */
DECLARE_QWEB_GET_STATS_FUNC(interface_stats_broadcast_pkts_tx);

/* Device.WiFi.SSID.{i}.Stats.BroadcastPacketsReceived */
DECLARE_QWEB_GET_STATS_FUNC(interface_stats_broadcast_pkts_rx);

/* Device.WiFi.SSID.{i}.Stats.UnknownProtoPacketsReceived */
DECLARE_QWEB_GET_STATS_FUNC(interface_stats_unknown_pkts_rx);

/* Device.DHCPv4*/
int qweb_get_dhcpv4_client_num(char *path);

/* Device.DHCPv4..Client.{i}.Enable */
DECLARE_QWEB_SET_UINT_FUNC(dhcpv4_enable);
DECLARE_QWEB_GET_UINT_FUNC(dhcpv4_enable);

/* Device.DHCPv4.Client.{i}.IPAddress */
DECLARE_QWEB_GET_STRING_FUNC(dhcpv4_ip);

/* Device.DHCPv4.Client.{i}.SubnetMask */
DECLARE_QWEB_GET_STRING_FUNC(dhcpv4_netmask);

/* Device.Ethernet */
int qweb_get_interface_num(char *path);

/* Device.Ethernet.Interface.{i}.MACAddress */
DECLARE_QWEB_GET_STRING_FUNC(ethernet_mac);

/* Device.WiFi.EndPoint */
int qweb_get_sta_max_num(char *path);
int qweb_add_endpoint_profile_entry(char *path, char *value);
int qweb_del_endpoint_profile_entry(char *path);
int qweb_endpoint_exist(char *path);

/* Device.WiFi.EndPoint.{i}.Enable */
DECLARE_QWEB_SET_UINT_FUNC(endpoint_enable);
DECLARE_QWEB_GET_UINT_FUNC(endpoint_enable);

/* Device.WiFi.EndPoint.{i}.Status */
DECLARE_QWEB_GET_STRING_FUNC(endpoint_status);

/* Device.WiFi.EndPoint.{i}.Alias*/
DECLARE_QWEB_SET_STRING_FUNC(endpoint_alias);
DECLARE_QWEB_GET_STRING_FUNC(endpoint_alias);

/* Device.WiFi.Endpoint.{i}.ProfileReference */
DECLARE_QWEB_SET_STRING_FUNC(endpoint_profile_reference);
DECLARE_QWEB_GET_STRING_FUNC(endpoint_profile_reference);

/* Device.WiFi.Endpoint.{i}.SSIDReference */
DECLARE_QWEB_GET_STRING_FUNC(endpoint_ssid_reference);

/* Device.WiFi.EndPoint.{i}.ProfileNumberOfEntries */
DECLARE_QWEB_GET_UINT_FUNC(endpoint_profile_num);

/* Device.WiFi.EndPoint.{i}.Stats */
/* Device.WiFi.EndPoint.{i}.Stats.LastDataDownlinkRate */
DECLARE_QWEB_GET_UINT_FUNC(endpoint_rx_phy_rate);

/* Device.WiFi.EndPoint.{i}.Stats.LastDataUplinkRate */
DECLARE_QWEB_GET_UINT_FUNC(endpoint_tx_phy_rate);

/* Device.WiFi.EndPoint.{i}.Stats.SignalStrength */
DECLARE_QWEB_GET_INT_FUNC(endpoint_rssi);

/* Device.WiFi.EndPoint.{i}.Stats.Retransmissions */
DECLARE_QWEB_GET_UINT_FUNC(endpoint_retransmissions);

/* Device.WiFi.EndPoint.Security */
/* Device.WiFi.EndPoint.Security.ModesSupported */
DECLARE_QWEB_GET_STRING_FUNC(endpoint_mode_supported);

/* Device.WiFi.EndPoint.{i}.Profile.{i} */
int qweb_get_profile_num(char *path);

/* Device.WiFi.EndPoint.{i}.Profile.{i}.Enable */
DECLARE_QWEB_SET_UINT_FUNC(endpoint_profile_enable);
DECLARE_QWEB_GET_UINT_FUNC(endpoint_profile_enable);

/* Device.WiFi.EndPoint.{i}.Profile.{i}.Status */
DECLARE_QWEB_GET_STRING_FUNC(endpoint_profile_status);

/* Device.WiFi.EndPoint.{i}.Profile.{i}.Alias*/
DECLARE_QWEB_SET_STRING_FUNC(endpoint_profile_alias);
DECLARE_QWEB_GET_STRING_FUNC(endpoint_profile_alias);

/* Device.WiFi.EndPoint.{i}.Profile.{i}.SSID */
DECLARE_QWEB_SET_STRING_FUNC(endpoint_profile_ssid);
DECLARE_QWEB_GET_STRING_FUNC(endpoint_profile_ssid);

/* Device.WiFi.EndPoint.{i}.Profile.{i}.Location */
DECLARE_QWEB_SET_STRING_FUNC(endpoint_profile_location);
DECLARE_QWEB_GET_STRING_FUNC(endpoint_profile_location);

/* Device.WiFi.EndPoint.{i}.Profile.{i}.Priority */
DECLARE_QWEB_SET_UINT_FUNC(endpoint_priority);
DECLARE_QWEB_GET_UINT_FUNC(endpoint_priority);

/* Device.WiFi.EndPoint.{i}.Profile.{i}.Security */
/* Device.WiFi.EndPoint.{i}.Profile.{i}.Security.ModeEnabled */
DECLARE_QWEB_SET_STRING_FUNC(endpoint_mode_enabled);
DECLARE_QWEB_GET_STRING_FUNC(endpoint_mode_enabled);

/* Device.WiFi.EndPoint.{i}.Profile.{i}.Security.WEPKey */
DECLARE_QWEB_SET_STRING_FUNC(endpoint_wep_key);
DECLARE_QWEB_GET_STRING_FUNC(endpoint_wep_key);

/* Device.WiFi.EndPoint.{i}.Profile.{i}.Security.PreSharedKey */
DECLARE_QWEB_SET_STRING_FUNC(endpoint_pre_shared_key);
DECLARE_QWEB_GET_STRING_FUNC(endpoint_pre_shared_key);

/* Device.WiFi.EndPoint.{i}.Profile.{i}.Security.KeyPassphrase */
DECLARE_QWEB_SET_STRING_FUNC(endpoint_key_passphrase);
DECLARE_QWEB_GET_STRING_FUNC(endpoint_key_passphrase);

/* Device.WiFi.EndPoint.{i}.WPS */
/* Device.WiFi.EndPoint.{i}.WPS.Enable */
DECLARE_QWEB_SET_UINT_FUNC(endpoint_wps_enable);
DECLARE_QWEB_GET_UINT_FUNC(endpoint_wps_enable);

/* Device.WiFi.Endpoint.{i}.WPS.ConfigMethodsSupported */
DECLARE_QWEB_GET_STRING_FUNC(endpoint_wps_config_methods_supported);

/* Device.WiFi.Endpoint.{i}.WPS.ConfigMethodsEnabled */
DECLARE_QWEB_SET_STRING_FUNC(endpoint_wps_config_methods_enabled);
DECLARE_QWEB_GET_STRING_FUNC(endpoint_wps_config_methods_enabled);

/* Device.WiFi.EndPoint.{i}.WPS.X_QUANTENNA_COM_STA_PIN */
DECLARE_QWEB_GET_STRING_FUNC(wps_sta_pin);

/* Device.WiFi.EndPoint.{i}.WPS.X_QUANTENNA_COM_REG_report_button_press */
DECLARE_QWEB_SET_STRING_FUNC(wps_enrollee_report_button_press);
DECLARE_QWEB_GET_STRING_FUNC(wps_enrollee_report_button_press);

/* Device.WiFi.EndPoint.{i}.WPS.X_QUANTENNA_COM_ENR_report_pin */
DECLARE_QWEB_SET_STRING_FUNC(wps_enrollee_report_pin);
DECLARE_QWEB_GET_STRING_FUNC(wps_enrollee_report_pin);

#ifdef TOPAZ_DBDC
int qweb_apply_for_change(char *path);
#endif

#endif				/* _QWEBAPI_TR181_ADAPTOR_H_ */
