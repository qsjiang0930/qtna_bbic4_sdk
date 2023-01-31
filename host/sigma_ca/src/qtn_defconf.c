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

#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>

#include "qcsapi.h"
#include <net80211/ieee80211.h>

#include "qtn_log.h"
#include "qtn_common.h"
#include "qtn_ca_config.h"
#include "qtn_defconf.h"

enum {
	DEFAULT_VHT_CHANNEL = 36
};


int qtn_defconf_vht_dut_sta(const char* ifname)
{
	int ret;
	qcsapi_unsigned_int tx_chains = 1;

	qtn_log("qtn_defconf_vht_dut_sta, ifname %s", ifname);

	/*  Table 142: STAUT Default Mode
	 * ---------------------------------------------------------
	 * #  | Mode name                   | Default | Notes
	 * ---------------------------------------------------------
	 * 1  | Spatial streams             | 1-4     |
	 * 2  | Bandwidth                   | 80 MHz  |
	 * 3  | VHT MCS Set                 | 0-9     |
	 * 4  | Short GI for 20 MHz         | On      | for both Tx/Rx
	 * 5  | Short GI for 40 MHz         | On      | for both Tx/Rx
	 * 6  | Short GI for 80 MHz         | On      | for both Tx/Rx
	 * 7  | SU Transmit Beamformer      | On      |
	 * 8  | SU Transmit Beamformee      | On      |
	 * 9  | MU Transmit Beamformer      | Off     |
	 * 10 | MU Transmit Beamformee      | Off     |
	 * 11 | Transmit A-MSDU             | On      |
	 * 12 | Receive A-MPDU with A-MSDU  | On      |
	 * 13 | Tx STBC 2x1                 | On      |
	 * 14 | Rx STBC 2x1                 | On      |
	 * 15 | Tx LDPC                     | On      |
	 * 16 | Rx LDPC                     | On      |
	 * 17 | Operating Mode Notification | On      | Transmit
	 * 18 | RTS with Bandwidth Signaling| On      |
	 * 19 | Two-character Country Code  | On      |
	 * 20 | Transmit Power Control      | On      |
	 * 21 | Channel Switching           | On      |
	 * ---------------------------------------------------------
	 */

	ret = qcsapi_wifi_cancel_scan(ifname, 0);
	if (ret < 0) {
		qtn_error("error: can't cancel scan, error %d", ret);
	}

	ret = qcsapi_wifi_set_phy_mode(ifname , "11ac");
	if (ret < 0) {
		qtn_error("error: cannot set 11ac, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_wifi_set_channel(ifname, DEFAULT_VHT_CHANNEL);
	if (ret < 0) {
		qtn_error("error: can't set channel, error %d", ret);
	}

	/* VHT mode */
	ret = qcsapi_wifi_set_vht(ifname, 1);
	if (ret < 0) {
		qtn_error("error: cannot enable vht, errcode %d", ret);
		return ret;
	}

	/* 1. Spatial streams, "Wi-Fi CERTIFIED ac Interoperability Test Plan v2.0", Table 169 STAUT Default Mode. */
	ret = qcsapi_wifi_get_tx_chains(ifname, &tx_chains);
	if (ret < 0) {
		qtn_error("error: cannot get tx chains number, errcode %d", ret);
		return ret;
	}
	if (tx_chains < 2 || tx_chains > 4)
		tx_chains = 1;
	ret = qcsapi_wifi_set_nss_cap(ifname, qcsapi_mimo_vht, tx_chains);

	if (ret < 0) {
		qtn_error("error: cannot set NSS capability, errcode %d", ret);
		return ret;
	}

	/* 2. Bandwidth, 80Mhz */
	qcsapi_wfa_cert_feature(ifname, "FIXED_BW", "auto");

	ret = qcsapi_wifi_set_bw(ifname, qcsapi_bw_80MHz);
	if (ret < 0) {
		qtn_error("error: cannot set bw capability %d, errcode %d", qcsapi_bw_80MHz, ret);
		return ret;
	}

	/* 3. VHT MCS Set, 0-9 */
	/* by default */

	/* 4. Short GI for 20 MHz, Off, for both Tx/Rx
	 * 5. Short GI for 40 MHz, Off, for both Tx/Rx
	 * 6. Short GI for 80 MHz, Off, for both Tx/Rx
	 */

	/* enable dynamic GI selection */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_GI_probing, 1);
	if (ret < 0) {
		/* not supported on RFIC6, ignore error for now. */
		qtn_error("error: enable dynamic GI selection, errcode %d", ret);
	}

	/* enable short GI */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_short_GI, 1);
	if (ret < 0) {
		qtn_error("error: enable short GI, errcode %d", ret);
		return ret;
	}

	/* 7. SU Transmit Beamformer, On */
	/* 8. SU Transmit Beamformee, On */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_beamforming, 1);
	if (ret < 0) {
		qtn_error("error: enable beamforming, errcode %d", ret);
		return ret;
	}

	/* 9. MU Transmit Beamformer, Off */
	/* 10. MU Transmit Beamformee, 0ff */


	/* 11. Transmit A-MSDU, On
	 * 12. Receive A-MPDU with A-MSDU, On
	 */
	ret = qcsapi_wifi_set_tx_amsdu(ifname, 1);
	if (ret < 0) {
		qtn_error("error: enable tx amsdu, errcode %d", ret);
		return ret;
	}

	/* 13. Tx STBC 2x1, On
	 * 14. Rx STBC 2x1, On
	 */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_stbc, 1);
	if (ret < 0) {
		qtn_error("error: cannot set stbc, errcode %d", ret);
		return ret;
	}

	/* 15. Tx LDPC, On
	 * 16. Rx LDPC, On
	 */
	/* by default */

	/* 17. Operating Mode Notification, On (if supported) */

	/* 18. RTS with Bandwidth Signaling, On (if supported) */
	ret = qcsapi_wfa_cert_feature(ifname, "BW_SGNL", "Reset");
	if (ret < 0) {
		qtn_error("error: cannot reset BW_SGNL, errcode %d", ret);
		return ret;
	}

	/* 19. Two-character Country Code, On (if supported) */
	/* 20. Transmit Power Control, On (if supported) */
	/* 21. Channel Switching, On (if supported) */

	return 0;
}

int qtn_defconf_vht_dut_ap(const char* ifname)
{
	qtn_log("qtn_defconf_vht_dut_ap");

	/*  Table 141: APUT Default Mode
	 * ---------------------------------------------------------
	 * #  | Mode name                   | Default | Notes
	 * ---------------------------------------------------------
	 * 1  | Spatial streams             | 1-4     |
	 * 2  | Bandwidth                   | 80 MHz  |
	 * 3  | VHT MCS Set                 | 0-9     |
	 * 4  | Short GI for 20 MHz         | On      | for both Tx/Rx
	 * 5  | Short GI for 40 MHz         | On      | for both Tx/Rx
	 * 6  | Short GI for 80 MHz         | On      | for both Tx/Rx
	 * 7  | SU Transmit Beamformer      | On      |
	 * 8  | SU Transmit Beamformee      | On      |
	 * 9  | MU Transmit Beamformer      | Off     |
	 * 10 | MU Transmit Beamformee      | Off     |
	 * 11 | Transmit A-MSDU             | On      |
	 * 12 | Receive A-MPDU with A-MSDU  | On      |
	 * 13 | Tx STBC 2x1                 | On      |
	 * 14 | Rx STBC 2x1                 | On      |
	 * 15 | Tx LDPC                     | On      |
	 * 16 | Rx LDPC                     | On      |
	 * 17 | Operating Mode Notification | On      | Transmit
	 * 18 | RTS with Bandwidth Signaling| On      |
	 * 19 | Two-character Country Code  | On      |
	 * 20 | Transmit Power Control      | On      |
	 * 21 | Channel Switching           | On      |
	 * ---------------------------------------------------------
	 */

	return qtn_defconf_vht_dut_sta(ifname);
}

int qtn_defconf_pmf_dut(const char* ifname)
{
	int ret;

	qtn_log("qtn_defconf_pmf_dut: ifname %s", ifname);

	ret = qcsapi_wifi_set_phy_mode(ifname , "11na");
	if (ret < 0) {
		qtn_error("error: cannot set 11na, errcode %d", ret);
		return ret;
	}


	/* 1. Spatial streams, 2 */
	ret = qcsapi_wifi_set_nss_cap(ifname, qcsapi_mimo_ht, 2);
	if (ret < 0) {
		qtn_error("error: cannot set NSS capability, errcode %d", ret);
		return ret;
	}

	/* 2. Bandwidth, 20Mhz */
	ret = qcsapi_wifi_set_bw(ifname, qcsapi_bw_20MHz);
	if (ret < 0) {
		qtn_error("error: cannot set bw capability %d, errcode %d", qcsapi_bw_20MHz, ret);
		return ret;
	}

	/* enable dynamic GI selection */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_GI_probing, 1);
	if (ret < 0) {
		/* not supported on RFIC6, ignore error for now. */
		qtn_error("error: enable dynamic GI selection, errcode %d", ret);
	}

	/* enable short GI */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_short_GI, 1);
	if (ret < 0) {
		qtn_error("error: enable short GI, errcode %d", ret);
		return ret;
	}

	return 0;
}

int qtn_defconf_hs2_dut(const char* ifname)
{
	int ret;

	qtn_log("qtn_defconf_hs2_dut, ifname %s", ifname);

	/* restore default hostapd config */
	ret = qtn_run_script("hostapd_restore_default_config.sh",
			qtn_config_get_option("conf_name"));
	if (ret < 0) {
		qtn_error("error: unable to restore default config, error %d", ret);
		return ret;
	}

	sleep(2);

	ret = qcsapi_wifi_scs_enable(ifname, 0);
	if (ret < 0) {
		qtn_error("error: cannot disable SCS, error %d", ret);
		return ret;
	}

	ret = qcsapi_wifi_set_phy_mode(ifname , "11na");
	if (ret < 0) {
		qtn_error("error: cannot set 11na, errcode %d", ret);
		return ret;
	}

	/* VHT mode */
	ret = qcsapi_wifi_set_vht(ifname, 0);
	if (ret < 0) {
		qtn_error("error: cannot enable vht, errcode %d", ret);
		return ret;
	}

	/* 1. Spatial streams, 2 */
	ret = qcsapi_wifi_set_nss_cap(ifname, qcsapi_mimo_ht, 2);

	if (ret < 0) {
		qtn_error("error: cannot set NSS capability, errcode %d", ret);
		return ret;
	}

	/* 2. Bandwidth, 20Mhz */
	ret = qcsapi_wifi_set_bw(ifname, qcsapi_bw_20MHz);
	if (ret < 0) {
		qtn_error("error: cannot set bw capability %d, errcode %d", qcsapi_bw_20MHz, ret);
		return ret;
	}

	/* 4. Short GI for 20 MHz, Off, for both Tx/Rx
	 * 5. Short GI for 40 MHz, Off, for both Tx/Rx
	 * 6. Short GI for 80 MHz, Off, for both Tx/Rx
	 */

	/* enable dynamic GI selection */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_GI_probing, 1);
	if (ret < 0) {
		/* not supported on RFIC6, ignore error for now. */
		qtn_error("error: enable dynamic GI selection, errcode %d", ret);
	}

	/* enable short GI */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_short_GI, 1);
	if (ret < 0) {
		qtn_error("error: enable short GI, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_wifi_set_interworking(ifname, "1");
	if (ret < 0) {
		qtn_error("error: enable interworking, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_wifi_set_80211u_params(ifname, "access_network_type", "2", NULL);
	if (ret < 0) {
		qtn_error("error: set 80211u access_network_type, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_wifi_set_80211u_params(ifname, "internet", "0", NULL);
	if (ret < 0) {
		qtn_error("error: set 80211u internet, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_wifi_set_80211u_params(ifname, "venue_group", "2", NULL);
	if (ret < 0) {
		qtn_error("error: set 80211u venue_group, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_wifi_set_80211u_params(ifname, "venue_type", "8", NULL);
	if (ret < 0) {
		qtn_error("error: set 80211u venue_type, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_wifi_set_80211u_params(ifname, "hessid", "50:6f:9a:00:11:22", NULL);
	if (ret < 0) {
		qtn_error("error: set 80211u hessid, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_wifi_set_80211u_params(ifname, "network_auth_type", "01", NULL);
	if (ret < 0) {
		qtn_error("error: set 80211u network_auth_type, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_wifi_set_80211u_params(ifname, "domain_name", "wi-fi.org", NULL);
	if (ret < 0) {
		qtn_error("error: set 80211u domain_name, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_wifi_set_hs20_status(ifname, "1");
	if (ret < 0) {
		qtn_error("error: enable hs20, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_security_add_oper_friendly_name(ifname, "eng", "Wi-Fi Alliance");
	if (ret < 0) {
		qtn_error("error: add_oper_friendly_name, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_security_add_oper_friendly_name(ifname, "chi", "Wi-Fi联盟");
	if (ret < 0) {
		qtn_error("error: add_oper_friendly_name, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_security_add_roaming_consortium(ifname, "506F9A");
	if (ret < 0) {
		qtn_error("error: add_roaming_consortium, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_security_add_roaming_consortium(ifname, "001BC504BD");
	if (ret < 0) {
		qtn_error("error: add_roaming_consortium, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_wifi_set_hs20_params(ifname, "disable_dgaf", "1",
			       NULL, NULL, NULL, NULL, NULL);
	if (ret < 0) {
		qtn_error("error: disable DGAF, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_wifi_set_hs20_params(ifname, "hs20_deauth_req_timeout", "20",
			       NULL, NULL, NULL, NULL, NULL);
	if (ret < 0) {
		qtn_error("error: hs20_deauth_req_timeout, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_wifi_set_pmf(ifname, 1);
	if (ret < 0) {
		qtn_error("error: set PMF, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_wifi_disable_wps(ifname, 1);
	if (ret < 0) {
		qtn_error("error: disable WPS, errcode %d", ret);
		return ret;
	}

	return 0;
}

int qtn_defconf_hs2_dut_all(void)
{
	int ret = 0;

	qcsapi_wifi_remove_bss("wifi1");

	ret = qtn_defconf_hs2_dut("wifi0");
	if (ret < 0)
		return ret;

	return 0;
}

int qtn_defconf_11n_dut(const char* ifname)
{
	int ret;

	qtn_log("qtn_defconf_11n_dut, ifname %s", ifname);

	ret = qcsapi_wifi_set_phy_mode(ifname , "11na");
	if (ret < 0) {
		qtn_error("error: cannot set 11na, errcode %d", ret);
		return ret;
	}

	/* Spatial streams, 4 */
	ret = qcsapi_wifi_set_nss_cap(ifname, qcsapi_mimo_ht, 4);
	if (ret < 0) {
		qtn_error("error: cannot set NSS capability, errcode %d", ret);
		return ret;
	}

	/* restore automatic bandwidth selection */
	qcsapi_wfa_cert_feature(ifname, "FIXED_BW", "auto");

	/* Bandwidth, 40Mhz */
	ret = qcsapi_wifi_set_bw(ifname, qcsapi_bw_40MHz);
	if (ret < 0) {
		qtn_error("error: cannot set bw capability %d, errcode %d", qcsapi_bw_40MHz, ret);
		return ret;
	}

	/* enable dynamic GI selection */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_GI_probing, 1);
	if (ret < 0) {
		/* not supported on RFIC6, ignore error for now. */
		qtn_error("error: enable dynamic GI selection, errcode %d", ret);
	}

	/* enable short GI */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_short_GI, 1);
	if (ret < 0) {
		qtn_error("error: enable short GI, errcode %d", ret);
		return ret;
	}

	/* SU Transmit Beamformer, Off */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_beamforming, 0);
	if (ret < 0) {
		qtn_error("error: enable beamforming, errcode %d", ret);
		return ret;
	}

	/* Transmit A-MSDU, On
	 * Receive A-MPDU with A-MSDU, On
	 */
	ret = qcsapi_wifi_set_tx_amsdu(ifname, 1);
	if (ret < 0) {
		qtn_error("error: enable tx amsdu, errcode %d", ret);
		return ret;
	}

	/* Tx/Rx STBC 2x1, On */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_stbc, 1);
	if (ret < 0) {
		qtn_error("error: cannot set stbc, errcode %d", ret);
		return ret;
	}

	return 0;
}

int qtn_defconf_tdls_dut(const char* ifname)
{
	int ret;

	qtn_log("qtn_defconf_tdls_dut, ifname %s", ifname);

	ret = qcsapi_wifi_set_phy_mode(ifname , "11na");
	if (ret < 0) {
		qtn_error("error: cannot set 11na, errcode %d", ret);
		return ret;
	}

	/* VHT mode */
	ret = qcsapi_wifi_set_vht(ifname, 0);
	if (ret < 0) {
		qtn_error("error: cannot enable vht, errcode %d", ret);
		return ret;
	}

	/* 1. Spatial streams, 2 */
	ret = qcsapi_wifi_set_nss_cap(ifname, qcsapi_mimo_ht, 2);

	if (ret < 0) {
		qtn_error("error: cannot set NSS capability, errcode %d", ret);
		return ret;
	}

	/* 2. Bandwidth, 20Mhz */
	ret = qcsapi_wifi_set_bw(ifname, qcsapi_bw_20MHz);
	if (ret < 0) {
		qtn_error("error: cannot set bw capability %d, errcode %d", qcsapi_bw_20MHz, ret);
		return ret;
	}

	/* 4. Short GI for 20 MHz, Off, for both Tx/Rx
	 * 5. Short GI for 40 MHz, Off, for both Tx/Rx
	 * 6. Short GI for 80 MHz, Off, for both Tx/Rx
	 */

	/* enable dynamic GI selection */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_GI_probing, 1);
	if (ret < 0) {
		/* not supported on RFIC6, ignore error for now. */
		qtn_error("error: enable dynamic GI selection, errcode %d", ret);
	}

	/* enable short GI */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_short_GI, 1);
	if (ret < 0) {
		qtn_error("error: enable short GI, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_wifi_enable_tdls(ifname, 1);
	if (ret < 0) {
		qtn_error("error: can't enable TDLS, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_wifi_set_tdls_params(ifname, qcsapi_tdls_discovery_interval, 0);
	if (ret < 0) {
		qtn_error("error: can't set discovery_interval, errcode %d", ret);
	}

	ret = qcsapi_wifi_set_tdls_params(ifname, qcsapi_tdls_mode, 1);
	if (ret < 0) {
		qtn_error("error: can't set tdls_mode, errcode %d", ret);
	}

	return 0;
}
