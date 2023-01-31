/*SH1
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications Inc                   **
**                                                                           **
**  File        : qwebapi_tr181.c                                            **
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

#include "qwebapi_tr181_adaptor.h"

#define ITEM_TERMINAL \
	{\
		.key=NULL,\
	}

/* DeviceInfo */
struct qwebitem qdevice_info_element[] = {
	{
	 .key = ITEM_NAME_MODEL_NAME,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_model_name,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_SOFTWARE_VERSION,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_software_version,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_UPTIME,
	 .type = QWEBAPI_TYPE_INT,
	 .get_func.get_int = qweb_get_uptime,
	 .child = NULL,
	 },
	ITEM_TERMINAL
};

/* Device.WiFi.Radio.Stats */
struct qwebitem radio_stats_element[] = {
	{
	 .key = ITEM_NAME_BYTES_SENT,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_bytes_sent,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_BYTES_RECEIVED,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_bytes_received,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_PACKETS_SENT,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_packets_sent,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_PACKETS_RECEIVED,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_packets_received,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ERRORS_SENT,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_errors_sent,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ERRORS_RECEIVED,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_errors_received,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_DISCARD_PACKETS_SENT,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_discard_packets_sent,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_DISCARD_PACKETS_RECEIVED,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_discard_packets_received,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_NOISE,
	 .type = QWEBAPI_TYPE_INT,
	 .get_func.get_int = qweb_get_noise,
	 .child = NULL,
	 },
	ITEM_TERMINAL
};

/* Device.WiFi.Radio */
struct qwebitem radio_element[] = {
	{
	 .key = ITEM_NAME_ENABLE,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_radio_enable,
	 .get_func.get_uint = qweb_get_radio_enable,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_STATUS,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_radio_status,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ALIAS,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_radio_alias,
	 .get_func.get_string = qweb_get_radio_alias,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_NAME,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_radio_name,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_LAST_CHANGE,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_radio_last_change,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_LOWER_LAYERS,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_radio_lower_layers,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_UP_STREAM,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_radio_up_stream,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_MAX_BIT_RATE,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_max_bit_rate,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_SUPPORTED_FREQUENCY_BANDS,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_supported_frequency_bands,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_OPERATING_BAND,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_operating_band,
	 .get_func.get_string = qweb_get_operating_band,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_SUPPORTED_STANDARDS,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_supported_standards,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_OPERATING_STANDARDS,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_operating_standards,
	 .get_func.get_string = qweb_get_operating_standards,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_POSSIBLE_CHANNEL,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_regulatory_channel,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_CHANNELS_IN_USE,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_channels_in_use,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_CHANNEL,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_channel,
	 .get_func.get_uint = qweb_get_channel,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_AUTO_CHANNEL_SUPPORTED,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_auto_channel_supported,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_AUTO_CHANNEL_ENABLE,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_auto_channel_enable,
	 .get_func.get_uint = qweb_get_auto_channel_enable,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_AUTO_CHANNEL_REFRESH_PERIOD,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_auto_channel_refresh_period,
	 .get_func.get_uint = qweb_get_auto_channel_refresh_period,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_BW,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_bw,
	 .get_func.get_string = qweb_get_bw,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_EXTENSION_CHANNEL,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_extension_channel,
	 .get_func.get_string = qweb_get_extension_channel,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_GUARD_INTERVAL,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_gi,
	 .get_func.get_string = qweb_get_gi,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_MCS,
	 .type = QWEBAPI_TYPE_INT,
	 .set_func.set_int = qweb_set_mcs,
	 .get_func.get_int = qweb_get_mcs,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_TRANSMIT_POWER_SUPPORTED,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_transmit_power_supported,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_TRANSMIT_POWER,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_transmit_power,
	 .get_func.get_uint = qweb_get_transmit_power,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_80211H_SUPPORTED,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_option_80211h_supported,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_80211H_ENABLED,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_doth_enable,
	 .get_func.get_uint = qweb_get_doth_enable,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_REGULATORY_DOMAIN,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_regulatory_region,
	 .get_func.get_string = qweb_get_regulatory_region,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_BI,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_beacon_interval,
	 .get_func.get_uint = qweb_get_beacon_interval,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_DTIM,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_dtim,
	 .get_func.get_uint = qweb_get_dtim,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_PREAMBLE_TYPE,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_preamble_type,
	 .get_func.get_string = qweb_get_preamble_type,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_MODE,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_mode,
	 .get_func.get_string = qweb_get_mode,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_PMF,
	 .type = QWEBAPI_TYPE_INT,
	 .set_func.set_int = qweb_set_pmf,
	 .get_func.get_int = qweb_get_pmf,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_NSS,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_nss,
	 .get_func.get_string = qweb_get_nss,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_AUTO_RATE,
	 .type = QWEBAPI_TYPE_INT,
	 .set_func.set_int = qweb_set_option_auto_rate,
	 .get_func.get_int = qweb_get_option_auto_rate,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_SUPPORTED_BW,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_supported_bw,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_REGULATORY_CHANNEL,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_regulatory_channel,
	 .get_func.get_string = qweb_get_regulatory_channel,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_STATS,
	 .child = radio_stats_element,
	 },
	ITEM_TERMINAL
};

/* Device.WiFi.SSID.{i}.Stats */
struct qwebitem ssid_stats_element[] = {
	{
	 .key = ITEM_NAME_BYTES_SENT,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_stats_bytes_sent,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_BYTES_RECEIVED,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_stats_bytes_received,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_PACKETS_SENT,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_stats_packets_sent,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_PACKETS_RECEIVED,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_stats_packets_received,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ERRORS_SENT,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_stats_errors_sent,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ERRORS_RECEIVED,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_stats_errors_received,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_UNICAST_PACKETS_SENT,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_stats_unicast_pkts_tx,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_UNICAST_PACKETS_RECEIVED,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_stats_unicast_pkts_rx,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_DISCARD_PACKETS_SENT,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_stats_discard_pkts_tx,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_DISCARD_PACKETS_RECEIVED,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_stats_discard_pkts_rx,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_MULTICAST_PACKETS_SENT,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_stats_multicast_pkts_tx,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_MULTICAST_PACKETS_RECEIVED,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_stats_multicast_pkts_rx,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_BROADCAST_PACKETS_SENT,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_stats_broadcast_pkts_tx,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_BROADCAST_PACKETS_RECEIVED,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_stats_broadcast_pkts_rx,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_UNKNOWN_PACKETS_RECEIVED,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_interface_stats_unknown_pkts_rx,
	 .child = NULL,
	 },
	ITEM_TERMINAL
};

/* Device.WiFi.SSID */
struct qwebitem ssid_element[] = {
	{
	 .key = ITEM_NAME_ENABLE,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_SSID_enable,
	 .get_func.get_uint = qweb_get_SSID_enable,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_STATUS,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_SSID_status,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ALIAS,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_SSID_alias,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_NAME,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_SSID_name,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_LAST_CHANGE,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_SSID_last_change,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_LOWER_LAYERS,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_SSID_lower_layers,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_BSSID,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_bssid,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_MAC_ADDR,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_mac_addr,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_SSID,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_ssid,
	 .get_func.get_string = qweb_get_ssid,
	 .check = qweb_check_ssid,
#ifdef TOPAZ_DBDC
	 .apply_for_change = qweb_apply_for_change,
#endif
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_PRIORITY,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_priority,
	 .get_func.get_uint = qweb_get_priority,
	 .check = qweb_check_priority,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_PRIMARY_INTERFACE,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_primary_interface,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_STATS,
	 .child = ssid_stats_element,
	 },
	ITEM_TERMINAL
};

/* Device.WiFi.AccessPoint.AssociatedDevice.Stats */
struct qwebitem assoc_device_stats_element[] = {
	{
	 .key = ITEM_NAME_BYTES_SENT,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_assoc_device_bytes_sent,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_BYTES_RECEIVED,
	 .type = QWEBAPI_TYPE_UINT64,
	 .get_func.get_uint64 = qweb_get_assoc_device_bytes_received,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_PACKETS_SENT,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_assoc_device_packets_sent,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_PACKETS_RECEIVED,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_assoc_device_packets_received,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ERRORS_SENT,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_assoc_device_errors_sent,
	 .child = NULL,
	 },
	ITEM_TERMINAL
};

/* Device.WiFi.AccessPoint.AssociatedDevice */
struct qwebitem associate_device_element[] = {
	{
	 .key = ITEM_NAME_OPERATING_STANDARD,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_assoc_device_operating_standard,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_MAC_ADDR,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_assoc_device_mac_addr,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ASSOC_DEVICE_AUTH_STATE,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_assoc_device_auth_state,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_LAST_DATA_DOWNLINK_RATE,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_assoc_device_tx_phy_rate,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_LAST_DATA_UPLINK_RATE,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_assoc_device_rx_phy_rate,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_SIGNAL_STRENGTH,
	 .type = QWEBAPI_TYPE_INT,
	 .get_func.get_int = qweb_get_rssi_in_dbm_per_association,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_RETRANSMISSIONS,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_assoc_device_retransmissions,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ACTIVE,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_assoc_device_active,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_STATS,
	 .child = assoc_device_stats_element,
	 },
	ITEM_TERMINAL
};

/* Device.WiFi.AccessPoint.Security */
struct qwebitem ap_security_element[] = {
	{
	 .key = ITEM_NAME_RESET,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_security_reset,
	 .get_func.get_uint = qweb_get_security_reset,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_MODE_SUPPORTED,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_accesspoint_mode_supported,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_MODE_ENABLED,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_mode_enabled,
	 .get_func.get_string = qweb_get_mode_enabled,
#ifdef TOPAZ_DBDC
	 .apply_for_change = qweb_apply_for_change,
#endif
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_WEP_KEY,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_wep_key,
	 .get_func.get_string = qweb_get_wep_key,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_PRE_SHARED_KEY,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_pre_shared_key,
	 .get_func.get_string = qweb_get_pre_shared_key,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_KEY_PASSPHRASE,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_key_passphrase,
	 .get_func.get_string = qweb_get_key_passphrase,
#ifdef TOPAZ_DBDC
	 .apply_for_change = qweb_apply_for_change,
#endif
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_REKEYING_INTERVAL,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_rekeying_interval,
	 .get_func.get_uint = qweb_get_rekeying_interval,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_RADIUS_SERVER_IP_ADDR,
	 .type = QWEBAPI_TYPE_STRING,
	 .not_directly_set = 1,
	 .set_func.set_string = qweb_set_radius_auth_server_ip,
	 .get_func.get_string = qweb_get_radius_auth_server_ip,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_RADIUS_SERVER_PORT,
	 .type = QWEBAPI_TYPE_UINT,
	 .not_directly_set = 1,
	 .set_func.set_uint = qweb_set_radius_auth_server_port,
	 .get_func.get_uint = qweb_get_radius_auth_server_port,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_RADIUS_SECRET,
	 .type = QWEBAPI_TYPE_STRING,
	 .not_directly_set = 1,
	 .set_func.set_string = qweb_set_radius_auth_server_secret,
	 .get_func.get_string = qweb_get_radius_auth_server_secret,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_SECOND_RADIUS_SERVER_IP_ADDR,
	 .type = QWEBAPI_TYPE_STRING,
	 .not_directly_set = 1,
	 .set_func.set_string = qweb_set_secondary_radius_auth_server_ip,
	 .get_func.get_string = qweb_get_secondary_radius_auth_server_ip,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_SECOND_RADIUS_SERVER_PORT,
	 .type = QWEBAPI_TYPE_UINT,
	 .not_directly_set = 1,
	 .set_func.set_uint = qweb_set_secondary_radius_auth_server_port,
	 .get_func.get_uint = qweb_get_secondary_radius_auth_server_port,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_SECOND_RADIUS_SECRET,
	 .type = QWEBAPI_TYPE_STRING,
	 .not_directly_set = 1,
	 .set_func.set_string = qweb_set_secondary_radius_auth_server_secret,
	 .get_func.get_string = qweb_get_secondary_radius_auth_server_secret,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_BEACON_TYPE,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_beacon_type,
	 .get_func.get_string = qweb_get_beacon_type,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_WPA_ENCRY_MODES,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_WPA_encryption_modes,
	 .get_func.get_string = qweb_get_WPA_encryption_modes,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_WPA_AUTH_MODE,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_WPA_authentication_mode,
	 .get_func.get_string = qweb_get_WPA_authentication_mode,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_OWN_IP_ADDR,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_own_ip_addr,
	 .get_func.get_string = qweb_get_own_ip_addr,
	 .child = NULL,
	 },
	ITEM_TERMINAL
};

/* Device.WiFi.AccessPoint.Accounting */
struct qwebitem ap_acct_element[] = {
	{
	 .key = ITEM_NAME_ENABLE,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_acct_enable,
	 .get_func.get_uint = qweb_get_acct_enable,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ACCOUNTING_SERVER_IP_ADDR,
	 .type = QWEBAPI_TYPE_STRING,
	 .not_directly_set = 1,
	 .set_func.set_string = qweb_set_radius_acct_server_ip,
	 .get_func.get_string = qweb_get_radius_acct_server_ip,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ACCOUNTING_SECONDARY_SERVER_IP_ADDR,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_secondary_radius_acct_server_ip,
	 .get_func.get_string = qweb_get_secondary_radius_acct_server_ip,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ACCOUNTING_SERVER_PORT,
	 .type = QWEBAPI_TYPE_UINT,
	 .not_directly_set = 1,
	 .set_func.set_uint = qweb_set_radius_acct_server_port,
	 .get_func.get_uint = qweb_get_radius_acct_server_port,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ACCOUNTING_SECONDARY_SERVER_PORT,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_secondary_radius_acct_server_port,
	 .get_func.get_uint = qweb_get_secondary_radius_acct_server_port,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ACCOUNTING_SERVER_SECRET,
	 .type = QWEBAPI_TYPE_STRING,
	 .not_directly_set = 1,
	 .set_func.set_string = qweb_set_radius_acct_server_secret,
	 .get_func.get_string = qweb_get_radius_acct_server_secret,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ACCOUNTING_SERVER_SECONDARY_SECRET,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_secondary_radius_acct_server_secret,
	 .get_func.get_string = qweb_get_secondary_radius_acct_server_secret,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ACCOUNTING_SERVER_INTERIM_INTERVAL,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_acct_interim_interval,
	 .get_func.get_uint = qweb_get_acct_interim_interval,
	 .child = NULL,
	 },
	ITEM_TERMINAL
};

/* Device.WiFi.AccessPoint.WPS */
struct qwebitem ap_wps_element[] = {
	{
	 .key = ITEM_NAME_ENABLE,
	 .type = QWEBAPI_TYPE_INT,
	 .set_func.set_int = qweb_set_ap_wps_enable,
	 .get_func.get_int = qweb_get_ap_wps_enable,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_CONFIG_METHODS_SUPPORTED,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_ap_wps_config_methods_supported,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_CONFIG_METHODS_ENABLED,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_ap_wps_config_methods_enabled,
	 .get_func.get_string = qweb_get_ap_wps_config_methods_enabled,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_WPS_RUNTIME_STATE,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_wps_runtime_state,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_WPS_AP_PIN,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_wps_ap_pin,
	 .get_func.get_string = qweb_get_wps_ap_pin,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_WPS_REGRENERATE_PIN,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_wps_regenerate_pin,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_WPS_STATE,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_wps_state,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_WPS_CONFIGURED_STATE,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_wps_configured_state,
	 .get_func.get_string = qweb_get_wps_configured_state,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_WPS_REG_REPORT_BUTTON_PRESS,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_wps_registrar_report_button_press,
	 .get_func.get_string = qweb_get_wps_registrar_report_button_press,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_WPS_REG_REPORT_PIN,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_wps_registrar_report_pin,
	 .get_func.get_string = qweb_get_wps_registrar_report_pin,
	 .child = NULL,
	 },
	ITEM_TERMINAL
};

/* Device.WiFi.AccessPoint */
struct qwebitem accesspoint_element[] = {
	{
	 .key = ITEM_NAME_ENABLE,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_accesspoint_enable,
	 .get_func.get_uint = qweb_get_accesspoint_enable,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_STATUS,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_accesspoint_status,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ALIAS,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_accesspoint_alias,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_SSID_REFERENCE,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_ap_ssid_reference,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_BROADCAST_SSID,
	 .type = QWEBAPI_TYPE_INT,
	 .set_func.set_int = qweb_set_option_broadcast_ssid,
	 .get_func.get_int = qweb_get_option_broadcast_ssid,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_RETRY_LIMIT,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_accesspoint_retry_limit,
	 .get_func.get_uint = qweb_get_accesspoint_retry_limit,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_WMM_CAPABILITY,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_wmm_capability,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_UAPSD_CAPABILITY,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_uapsd_capability,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_WMM_ENABLE,
	 .type = QWEBAPI_TYPE_INT,
	 .set_func.set_int = qweb_set_option_wmm_enable,
	 .get_func.get_int = qweb_get_option_wmm_enable,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_UAPSD_ENABLE,
	 .type = QWEBAPI_TYPE_INT,
	 .set_func.set_int = qweb_set_option_uapsd_enable,
	 .get_func.get_int = qweb_get_option_uapsd_enable,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_AP_ASSOC_COUNT,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_count_associations,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_MAX_ASSOC_DEVICES,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_max_assoc_devices,
	 .get_func.get_uint = qweb_get_max_assoc_devices,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ISOLATION_ENABLE,
	 .type = QWEBAPI_TYPE_INT,
	 .set_func.set_int = qweb_set_isolation_enable,
	 .get_func.get_int = qweb_get_isolation_enable,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_MAC_ADDR_CONTROL_ENABLED,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_before = qweb_set_macaddr_filter_before,
	 .set_func.set_uint = qweb_set_macaddr_filter,
	 .get_before = qweb_get_macaddr_filter_before,
	 .get_func.get_uint = qweb_get_macaddr_filter,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ALLOWED_MAC_ADDR,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_before = qweb_set_allowed_macaddr_before,
	 .set_func.set_string = qweb_set_allowed_macaddr,
	 .get_before = qweb_get_allowed_macaddr_before,
	 .get_func.get_string = qweb_get_allowed_macaddr,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_VLAN_CONFIG,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_vlan_config,
	 .get_func.get_string = qweb_get_vlan_config,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_VLAN_TAGRX_CONFIG,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_vlan_tagrx_config,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_INTERWORKING,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_interworking,
	 .get_func.get_string = qweb_get_interworking,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_80211U_INTERNET_ACCESS,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_internet_access,
	 .get_func.get_string = qweb_get_internet_access,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_80211U_ACCESS_NETWORK_TYPE,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_access_network_type,
	 .get_func.get_string = qweb_get_access_network_type,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_80211U_NETWORK_AUTH_TYPE,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_network_auth_type,
	 .get_func.get_string = qweb_get_network_auth_type,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_80211U_HESSID,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_hessid,
	 .get_func.get_string = qweb_get_hessid,
	 .check = qweb_check_hessid,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_80211U_DOMAIN_NAME,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_domain_name,
	 .get_func.get_string = qweb_get_domain_name,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_IPADDR_TYPE_AVAILABILITY,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_ipaddr_type_availability,
	 .get_func.get_string = qweb_get_ipaddr_type_availability,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_ANQP_3GPP_CELL_NET,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_anqp_3gpp_cell_net,
	 .get_func.get_string = qweb_get_anqp_3gpp_cell_net,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_VENUE_GROUP,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_venue_group,
	 .get_func.get_string = qweb_get_venue_group,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_VENUE_TYPE,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_venue_type,
	 .get_func.get_string = qweb_get_venue_type,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_VENUE_NAME,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_venue_name,
	 .get_func.get_string = qweb_get_venue_name,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_GAS_COMEBACK_DELAY,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_gas_comeback_delay,
	 .get_func.get_string = qweb_get_gas_comeback_delay,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_NAI_REALM,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_nai_realm,
	 .get_func.get_string = qweb_get_nai_realm,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_ROAMING_CONSORTIUM,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_roaming_consortium,
	 .get_func.get_string = qweb_get_roaming_consortium,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_HS20_STATUS,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_hs20_status,
	 .get_func.get_string = qweb_get_hs20_status,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_OPER_FRIENDLY_NAME,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_oper_friendly_name,
	 .get_func.get_string = qweb_get_oper_friendly_name,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_HS20_WAN_METRICS,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_hs20_wan_metrics,
	 .get_func.get_string = qweb_get_hs20_wan_metrics,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_HS20_DISABLE_DGAF,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_hs20_disable_dgaf,
	 .get_func.get_string = qweb_get_hs20_disable_dgaf,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_HS20_OSEN,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_hs20_osen,
	 .get_func.get_string = qweb_get_hs20_osen,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_HS20_DEAUTH_REQ_TIMEOUT,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_hs20_deauth_req_timeout,
	 .get_func.get_string = qweb_get_hs20_deauth_req_timeout,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_HS20_OPERATING_CLASS,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_hs20_operating_class,
	 .get_func.get_string = qweb_get_hs20_operating_class,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_HS20_OSU_SSID,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_hs20_osu_ssid,
	 .get_func.get_string = qweb_get_hs20_osu_ssid,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_HS20_CONN_CAPAB,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_hs20_conn_capab,
	 .get_func.get_string = qweb_get_hs20_conn_capab,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_PROXY_ARP,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_proxy_arp,
	 .get_func.get_string = qweb_get_proxy_arp,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_WDS_PEER,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_wds_peer,
	 .get_func.get_string = qweb_get_wds_peer,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_WDS_PSK,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_wds_psk,
	 .get_func.get_string = qweb_get_wds_psk,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_WDS_MODE,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_wds_mode,
	 .get_func.get_string = qweb_get_wds_mode,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_WDS_RSSI,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_wds_rssi,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_80211R_ENABLE,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_80211r_enable,
	 .get_func.get_string = qweb_get_80211r_enable,
#ifdef TOPAZ_DBDC
	 .apply_for_change = qweb_apply_for_change,
#endif
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_X_QUANTENNA_COM_80211R_MDID,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_80211r_mdid,
	 .get_func.get_string = qweb_get_80211r_mdid,
#ifdef TOPAZ_DBDC
	 .apply_for_change = qweb_apply_for_change,
#endif
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_SECURITY,
#ifdef TOPAZ_DBDC
	 .apply_for_change = qweb_apply_for_change,
#endif
	 .child = ap_security_element,
	 },
	{
	 .key = ITEM_NAME_ACCOUNTING,
	 .child = ap_acct_element,
	 },
	{
	 .key = ITEM_NAME_WPS,
	 .child = ap_wps_element,
	 },
	{
	 .key = ITEM_NAME_ASSOCIATED_DEVICE,
	 .get_size = qweb_get_associated_device_num,
	 .child = associate_device_element,
	 },
	ITEM_TERMINAL
};

/* Device.WiFi.EndPoint.{i}.Stats */
struct qwebitem endpoint_stats_element[] = {
	{
	 .key = ITEM_NAME_LAST_DATA_DOWNLINK_RATE,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_endpoint_rx_phy_rate,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_LAST_DATA_UPLINK_RATE,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_endpoint_tx_phy_rate,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_SIGNAL_STRENGTH,
	 .type = QWEBAPI_TYPE_INT,
	 .get_func.get_int = qweb_get_endpoint_rssi,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_RETRANSMISSIONS,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_endpoint_retransmissions,
	 .child = NULL,
	 },
	ITEM_TERMINAL
};

/* Device.WiFi.EndPoint.{i}.Security */
struct qwebitem endpoint_security_element[] = {
	{
	 .key = ITEM_NAME_MODE_SUPPORTED,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_endpoint_mode_supported,
	 .child = NULL,
	 },
	ITEM_TERMINAL
};

/* Device.WiFi.EndPoint.{i}.Profile.{i}.Security */
struct qwebitem endpoint_profile_security_element[] = {
	{
	 .key = ITEM_NAME_MODE_ENABLED,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_endpoint_mode_enabled,
	 .get_func.get_string = qweb_get_endpoint_mode_enabled,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_WEP_KEY,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_endpoint_wep_key,
	 .get_func.get_string = qweb_get_endpoint_wep_key,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_PRE_SHARED_KEY,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_endpoint_pre_shared_key,
	 .get_func.get_string = qweb_get_endpoint_pre_shared_key,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_KEY_PASSPHRASE,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_endpoint_key_passphrase,
	 .get_func.get_string = qweb_get_endpoint_key_passphrase,
	 .child = NULL,
	 },
	ITEM_TERMINAL
};

/* Device.WiFi.EndPoint.{i}.Profile.{i} */
struct qwebitem endpoint_profile_element[] = {
	{
	 .key = ITEM_NAME_ENABLE,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_endpoint_profile_enable,
	 .get_func.get_uint = qweb_get_endpoint_profile_enable,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_STATUS,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_endpoint_profile_status,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ALIAS,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_endpoint_profile_alias,
	 .get_func.get_string = qweb_get_endpoint_profile_alias,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_SSID,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_endpoint_profile_ssid,
	 .get_func.get_string = qweb_get_endpoint_profile_ssid,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ENDPOINT_LOCATION,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_endpoint_profile_location,
	 .get_func.get_string = qweb_get_endpoint_profile_location,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_PRIORITY,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_endpoint_priority,
	 .get_func.get_uint = qweb_get_endpoint_priority,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_SECURITY,
	 .child = endpoint_profile_security_element,
	 },
	ITEM_TERMINAL
};

/* Device.WiFi.EndPoint.{i}.WPS */
struct qwebitem endpoint_wps_element[] = {
	{
	 .key = ITEM_NAME_ENABLE,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_endpoint_wps_enable,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_CONFIG_METHODS_SUPPORTED,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_endpoint_wps_config_methods_supported,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_CONFIG_METHODS_ENABLED,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_endpoint_wps_config_methods_enabled,
	 .get_func.get_string = qweb_get_endpoint_wps_config_methods_enabled,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_WPS_STATION_PIN,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_wps_sta_pin,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_WPS_ENR_REPORT_BUTTON_PRESS,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_wps_enrollee_report_button_press,
	 .get_func.get_string = qweb_get_wps_enrollee_report_button_press,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_WPS_ENR_REPORT_PIN,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_wps_enrollee_report_pin,
	 .get_func.get_string = qweb_get_wps_enrollee_report_pin,
	 .child = NULL,
	 },
	ITEM_TERMINAL
};

/* Device.WiFi.EndPoint.{i} */
struct qwebitem endpoint_element[] = {
	{
	 .key = ITEM_NAME_ENABLE,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_endpoint_enable,
	 .get_func.get_uint = qweb_get_endpoint_enable,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_STATUS,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_endpoint_status,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ENDPOINT_PROFILE_REFERENCE,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_endpoint_profile_reference,
	 .get_func.get_string = qweb_get_endpoint_profile_reference,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_SSID_REFERENCE,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_endpoint_ssid_reference,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ALIAS,
	 .type = QWEBAPI_TYPE_STRING,
	 .set_func.set_string = qweb_set_endpoint_alias,
	 .get_func.get_string = qweb_get_endpoint_alias,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_ENDPOINT_PROFILE_NUM,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_endpoint_profile_num,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_STATS,
	 .child = endpoint_stats_element,
	 },
	{
	 .key = ITEM_NAME_SECURITY,
	 .child = endpoint_security_element,
	 },
	{
	 .key = ITEM_NAME_ENDPOINT_PROFILE,
	 .add_func = qweb_add_endpoint_profile_entry,
	 .del_func = qweb_del_endpoint_profile_entry,
	 .get_size = qweb_get_profile_num,
	 .child = endpoint_profile_element,
	 },
	{
	 .key = ITEM_NAME_WPS,
	 .child = endpoint_wps_element,
	 },
	ITEM_TERMINAL
};

/* Device.WiFi */
struct qwebitem qwifi_element[] = {
	{
	 .key = ITEM_NAME_RADIO_NUMBER,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_radio_number_of_entries,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_SSID_NUMBER,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_ssid_number_of_entries,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_AP_NUMBER,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_ap_number_of_entries,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_END_POINT_NUMBER,
	 .type = QWEBAPI_TYPE_UINT,
	 .get_func.get_uint = qweb_get_endpoint_number_of_entries,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_RADIO,
	 .get_size = qweb_get_radio_num,
	 .child = radio_element,
	 },
	{
	 .key = ITEM_NAME_SSID,
	 .add_func = qweb_add_ssid_entry,
	 .del_func = qweb_del_ssid_entry,
	 .get_size = qweb_get_ssid_max_num,
	 .entry_exist = qweb_ssid_exist,
#ifdef TOPAZ_DBDC
	 .apply_for_change = qweb_apply_for_change,
#endif
	 .child = ssid_element,
	 },
	{
	 .key = ITEM_NAME_ACCESSPOINT,
	 .add_func = qweb_add_accesspoint_entry,
	 .del_func = qweb_del_accesspoint_entry,
	 .get_size = qweb_get_ap_max_num,
	 .entry_exist = qweb_accesspoint_exist,
#ifdef TOPAZ_DBDC
	 .apply_for_change = qweb_apply_for_change,
#endif
	 .child = accesspoint_element,
	 },
	{
	 .key = ITEM_NAME_ENDPOINT,
	 .get_size = qweb_get_sta_max_num,
	 .entry_exist = qweb_endpoint_exist,
	 .child = endpoint_element,
	 },
	ITEM_TERMINAL
};

/* Device.DHCPv4.Client */
struct qwebitem qdhcpv4_client_element[] = {
	{
	 .key = ITEM_NAME_ENABLE,
	 .type = QWEBAPI_TYPE_UINT,
	 .set_func.set_uint = qweb_set_dhcpv4_enable,
	 .get_func.get_uint = qweb_get_dhcpv4_enable,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_IP_ADDRESS,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_dhcpv4_ip,
	 .child = NULL,
	 },
	{
	 .key = ITEM_NAME_SUB_NETMASK,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_dhcpv4_netmask,
	 .child = NULL,
	 },
	ITEM_TERMINAL
};

/* Device.DHCPv4 */
struct qwebitem qdhcpv4_element[] = {
	{
	 .key = ITEM_NAME_CLIENT,
	 .get_size = qweb_get_dhcpv4_client_num,
	 .child = qdhcpv4_client_element,
	 },
	ITEM_TERMINAL
};

/* Device.Ethernet.Interface */
struct qwebitem qeth_inferface_element[] = {
	{
	 .key = ITEM_NAME_MAC_ADDR,
	 .type = QWEBAPI_TYPE_STRING,
	 .get_func.get_string = qweb_get_ethernet_mac,
	 .child = NULL,
	 },
	ITEM_TERMINAL
};

/* Device.Ethernet */
struct qwebitem qeth_element[] = {
	{
	 .key = ITEM_NAME_INTERFACE,
	 .get_size = qweb_get_interface_num,
	 .child = qeth_inferface_element,
	 },
	ITEM_TERMINAL
};

/* Device */
struct qwebitem qdevice_element[] = {
	{
	 .key = ITEM_NAME_DEVICE_INFO,
	 .child = qdevice_info_element,
	 },
	{
	 .key = ITEM_NAME_ETHERNET,
	 .child = qeth_element,
	 },
	{
	 .key = ITEM_NAME_WIFI,
#ifdef TOPAZ_DBDC
	 .apply_for_change = qweb_apply_for_change,
#endif
	 .child = qwifi_element,
	 },
	{
	 .key = ITEM_NAME_DHCPV4,
	 .child = qdhcpv4_element,
	 },
	ITEM_TERMINAL
};

/* Root */
struct qwebitem qdevice[] = {
	{
	 .key = ITEM_NAME_DEVICE,
	 .child = qdevice_element,
	 },
	ITEM_TERMINAL
};

struct qwebitem *qweb_root = qdevice;
