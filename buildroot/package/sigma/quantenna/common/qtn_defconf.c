#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "qtn/qdrv_bld.h"
#include "qtn/qcsapi.h"
#include <linux/wireless.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <sys/ioctl.h>

#include "qsigma_log.h"
#include "qtn_dut_common.h"
#include "qtn_defconf.h"

static void reset_rts_cts_settings(struct qtn_dut_config *conf, const char* ifname)
{
	char tmpbuf[64];
	conf->bws_enable = 0;
	conf->bws_dynamic = 0;
	conf->force_rts = 0;
	conf->update_settings = 0;

	/* disable CTS with fixed bw */
	snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s set_cts_bw 0", ifname);
	system(tmpbuf);

	qtn_set_rts_settings(ifname, conf);
}

static void enable_rx_bw_signaling_support(const char* ifname)
{
	char tmpbuf[64];
	snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s set_rx_bws_ndpa 1", ifname);
	system(tmpbuf);
}

static int qtn_defconf_check_txbf_support(const char* ifname)
{
	struct iwreq iwr;
	int ioctl_sock;
	unsigned int vhtcap_flags = 0;
	int ret;

	ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (ioctl_sock < 0)
		return -errno;

        memset(&iwr, 0, sizeof(iwr));
        strncpy(iwr.ifr_name, ifname, IFNAMSIZ - 1);
        iwr.u.data.flags = SIOCDEV_SUBIO_GET_VHT_CAP_FLAGS;
        iwr.u.data.pointer = &vhtcap_flags;
        iwr.u.data.length = sizeof(vhtcap_flags);

        ret = ioctl(ioctl_sock, IEEE80211_IOCTL_EXT, &iwr);
        close(ioctl_sock);

        if (ret < 0)
                return ret;

	if (vhtcap_flags & IEEE80211_VHTCAP_C_SU_BEAM_FORMER_CAP)
		return 1;
	else
		return 0;
}


int qtn_defconf_vht_testbed_sta(const char* ifname)
{
	int ret;
	struct qtn_dut_config *conf;
	char tmpbuf[64];

	qtn_log("START: qtn_defconf_vht_testbed_sta");

	/*  Table 138: Testbed Default Mode STA
	 * ---------------------------------------------------------
	 * #  | Mode name                   | Default | Notes
	 * ---------------------------------------------------------
	 * 1  | Spatial streams             | 1       |
	 * 2  | Bandwidth                   | 80 MHz  |
	 * 3  | VHT MCS Set                 | 0-7     | MCS 8-9 off
	 * 4  | Short GI for 20 MHz         | Off     | for both Tx/Rx
	 * 5  | Short GI for 40 MHz         | Off     | for both Tx/Rx
	 * 6  | Short GI for 80 MHz         | Off     | for both Tx/Rx
	 * 7  | SU Transmit Beamforming     | Off     |
	 * 8  | SU Transmit Beamformee      | Off     |
	 * 9  | MU Transmit Beamformer      | Off     |
	 * 10 | MU Transmit Beamformee      | Off     |
	 * 11 | Transmit A-MSDU             | Off     |
	 * 12 | Receive A-MPDU with A-MSDU  | Off     |
	 * 13 | STBC 2x1 Transmit           | Off     |
	 * 14 | STBC 2x1 Receive            | Off     |
	 * 15 | LDPC                        | Off     |
	 * 16 | Operating Mode Notification | Off     | Transmit
	 * 17 | RTS with Bandwidth Signaling| Off     |
	 * 18 | Two-character Country Code  | Off     |
	 * 19 | Transmit Power Control      | Off     |
	 * 20 | Channel Switching           | Off     |
	 * ---------------------------------------------------------
	 */

	ret = qcsapi_wifi_set_phy_mode(ifname , "11ac");
	if (ret < 0) {
		qtn_error("error: cannot set 11ac, errcode %d", ret);
		return ret;
	}

	/* VHT mode */
	ret = qcsapi_wifi_set_vht(ifname, 1);
	if (ret < 0) {
		qtn_error("error: cannot enable vht, errcode %d", ret);
		return ret;
	}

	/* 1. Spatial streams, 1 */
	ret = qcsapi_wifi_set_nss_cap(ifname, qcsapi_mimo_vht, 1);
	if (ret < 0) {
		qtn_error("error: cannot set NSS capability, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_wifi_set_rx_nss_cap(ifname, qcsapi_mimo_vht, 1);
	if (ret < 0) {
		qtn_error("error: cannot set NSS capability, errcode %d", ret);
		return ret;
	}

	/* 2. Bandwidth, 80Mhz */
	system("set_fixed_bw -b auto");
	ret = qcsapi_wifi_set_bw(ifname, qcsapi_bw_80MHz);
	if (ret < 0) {
		qtn_error("error: cannot set bw capability %d, errcode %d", qcsapi_bw_80MHz, ret);
		return ret;
	}

	/* 3. VHT MCS Set, 0-7 */
	snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s set_vht_mcs_cap %d",
			ifname,
			IEEE80211_VHT_MCS_0_7);
	system(tmpbuf);

	/* 4. Short GI for 20 MHz, Off, for both Tx/Rx
	 * 5. Short GI for 40 MHz, Off, for both Tx/Rx
	 * 6. Short GI for 80 MHz, Off, for both Tx/Rx
	 */

	/* disable dynamic GI selection */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_GI_probing, 0);
	if (ret < 0) {
		/* ignore error since qcsapi_GI_probing does not work for RFIC6 */
		qtn_error("error: disable dynamic GI selection, errcode %d", ret);
	}

	/* disable short GI */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_short_GI, 0);
	if (ret < 0) {
		qtn_error("error: disable short GI, errcode %d", ret);
		return ret;
	}

	/* 7. SU Transmit Beamforming, Off */
	/* 8. SU Transmit Beamformee, Off */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_beamforming, 0);
	if (ret < 0) {
		qtn_error("error: disable beamforming, errcode %d", ret);
		return ret;
	}

	/* 9. MU Transmit Beamformer, Off */
	/* 10. MU Transmit Beamformee, 0ff */
	enable_rx_bw_signaling_support(ifname);


	/* restore Ndpa_stainfo_mac to default */
	system("mu sta0 00:00:00:00:00:00");

	ret = qtn_set_mu_enable(0);
	if (ret < 0) {
		qtn_error("error: disable MU beamforming, errcode %d", ret);
		return ret;
	}

	/* 11. Transmit A-MSDU, Off
	 * 12. Receive A-MPDU with A-MSDU, Off
	 */
	ret = qcsapi_wifi_set_tx_amsdu(ifname, 0);
	if (ret < 0) {
		qtn_error("error: disable tx amsdu, errcode %d", ret);
		return ret;
	}

	/* 13. STBC 2x1 Transmit, Off
	 * 14. STBC 2x1 Receive, Off
	 */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_stbc, 0);
	if (ret < 0) {
		qtn_error("error: cannot set stbc, errcode %d", ret);
		return ret;
	}

	/* 15. LDPC, Off */
	snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s set_ldpc %d", ifname, 0);
	system(tmpbuf);

	/* 16. Operating Mode Notification, Off, Transmit */
	snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s set_vht_opmntf %d",
			ifname,
			0xFFFF);
	system(tmpbuf);

	/* 17. RTS with Bandwidth Signaling, Off */
	conf = qtn_dut_get_config(ifname);

	if (conf) {
		reset_rts_cts_settings(conf, ifname);

	} else {
		ret = -EFAULT;
		qtn_error("error: cannot get config, errcode %d", ret);
		return ret;
	}

	/* 18. Two-character Country Code, Off */
	/* 19. Transmit Power Control, Off */
	/* 20. Channel Switching, Off */

	qtn_log("END: qtn_defconf_vht_testbed_sta");

	return 0;
}


int qtn_defconf_vht_testbed_ap(const char* ifname)
{
	int ret;
	struct qtn_dut_config *conf;
	char tmpbuf[64];

	qtn_log("qtn_defconf_vht_testbed_ap");

	/*  Table 137: Testbed Default Mode AP
	 * ---------------------------------------------------------
	 * #  | Mode name                   | Default | Notes
	 * ---------------------------------------------------------
	 * 1  | Spatial streams             | 2       |
	 * 2  | Bandwidth                   | 80 MHz  |
	 * 3  | VHT MCS Set                 | 0-7     | MCS 8-9 off
	 * 4  | Short GI for 20 MHz         | Off     | for both Tx/Rx
	 * 5  | Short GI for 40 MHz         | Off     | for both Tx/Rx
	 * 6  | Short GI for 80 MHz         | Off     | for both Tx/Rx
	 * 7  | SU Transmit Beamforming     | Off     |
	 * 8  | SU Transmit Beamformee      | Off     |
	 * 9  | MU Transmit Beamformer      | Off     |
	 * 10 | MU Transmit Beamformee      | Off     |
	 * 11 | Transmit A-MSDU             | Off     |
	 * 12 | Receive A-MPDU with A-MSDU  | Off     |
	 * 13 | STBC 2x1 Transmit           | Off     |
	 * 14 | STBC 2x1 Receive            | Off     |
	 * 15 | LDPC                        | Off     |
	 * 16 | Operating Mode Notification | Off     | Transmit
	 * 17 | RTS with Bandwidth Signaling| Off     |
	 * 18 | Two-character Country Code  | Any     |
	 * 19 | Transmit Power Control      | Any     |
	 * 20 | Channel Switching           | Any     |
	 * ---------------------------------------------------------
	 */


	ret = qcsapi_wifi_scs_enable(ifname, 0);
	if (ret < 0) {
		qtn_error("error: cannot disable SCS, error %d", ret);
	}

	ret = qcsapi_wifi_set_phy_mode(ifname , "11ac");
	if (ret < 0) {
		qtn_error("error: cannot set 11ac, errcode %d", ret);
		return ret;
	}

	ret = qcsapi_wifi_set_channel(ifname, DEFAULT_VHT_CHANNEL);
	if (ret < 0) {
		qtn_error("error: cannot set channel to %d, errcode %d", DEFAULT_VHT_CHANNEL, ret);
		return ret;
	}

	/* VHT mode */
	ret = qcsapi_wifi_set_vht(ifname, 1);
	if (ret < 0) {
		qtn_error("error: cannot enable vht, errcode %d", ret);
		return ret;
	}

	/* 1. Spatial streams, 2 */
	ret = qcsapi_wifi_set_nss_cap(ifname, qcsapi_mimo_vht, 2);
	if (ret < 0) {
		qtn_error("error: cannot set NSS capability, errcode %d", ret);
		return ret;
	}
	ret = qcsapi_wifi_set_rx_nss_cap(ifname, qcsapi_mimo_vht, 2);
	if (ret < 0) {
		qtn_error("error: cannot set NSS capability, errcode %d", ret);
		return ret;
	}

	/* 2. Bandwidth, 80Mhz */
	system("set_fixed_bw -b auto");
	ret = qcsapi_wifi_set_bw(ifname, qcsapi_bw_80MHz);
	if (ret < 0) {
		qtn_error("error: cannot set bw capability %d, errcode %d", qcsapi_bw_80MHz, ret);
		return ret;
	}

	/* 3. VHT MCS Set, 0-7 */
	snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s set_vht_mcs_cap %d",
			ifname,
			IEEE80211_VHT_MCS_0_7);
	system(tmpbuf);

	/* 4. Short GI for 20 MHz, Off, for both Tx/Rx
	 * 5. Short GI for 40 MHz, Off, for both Tx/Rx
	 * 6. Short GI for 80 MHz, Off, for both Tx/Rx
	 */

	/* disable dynamic GI selection */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_GI_probing, 0);
	if (ret < 0) {
		/* ignore error since qcsapi_GI_probing does not work for RFIC6 */
		qtn_error("error: disable dynamic GI selection, errcode %d", ret);
	}

	/* disable short GI */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_short_GI, 0);
	if (ret < 0) {
		qtn_error("error: disable short GI, errcode %d", ret);
		return ret;
	}

	/* 7. SU Transmit Beamforming, Off */
	/* 8. SU Transmit Beamformee, Off */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_beamforming, 0);
	if (ret < 0) {
		qtn_error("error: disable beamforming, errcode %d", ret);
		return ret;
	}

	/* 9. MU Transmit Beamformer, Off */
	/* 10. MU Transmit Beamformee, 0ff */
	enable_rx_bw_signaling_support(ifname);

	/* restore Ndpa_stainfo_mac to default */
	system("mu sta0 00:00:00:00:00:00");

	ret = qtn_set_mu_enable(0);
	if (ret < 0) {
		qtn_error("error: disable MU beamforming, errcode %d", ret);
		return ret;
	}

	/* 11. Transmit A-MSDU, Off
	 * 12. Receive A-MPDU with A-MSDU, Off
	 */
	ret = qcsapi_wifi_set_tx_amsdu(ifname, 0);
	if (ret < 0) {
		qtn_error("error: disable tx amsdu, errcode %d", ret);
		return ret;
	}

	/* 13. STBC 2x1 Transmit, Off
	 * 14. STBC 2x1 Receive, Off
	 */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_stbc, 0);
	if (ret < 0) {
		qtn_error("error: cannot set stbc, errcode %d", ret);
		return ret;
	}

	/* 15. LDPC, Off */
	snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s set_ldpc %d", ifname, 0);
	system(tmpbuf);

	/* 16. Operating Mode Notification, Off, Transmit */
	snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s set_vht_opmntf %d",
			ifname,
			0xFFFF);
	system(tmpbuf);

	/* 17. RTS with Bandwidth Signaling, Off */
	conf = qtn_dut_get_config(ifname);

	if (conf) {
		reset_rts_cts_settings(conf, ifname);
	} else {
		ret = -EFAULT;
		qtn_error("error: cannot get config, errcode %d", ret);
		return ret;
	}

	/* 18. Two-character Country Code, Any */
	/* 19. Transmit Power Control, Any */
	/* 20. Channel Switching, Any */

	return 0;
}

int qtn_defconf_vht_dut_sta(const char* ifname)
{
	int ret;
	struct qtn_dut_config *conf;
	char tmpbuf[64];
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
	system("set_fixed_bw -b auto");
	ret = qcsapi_wifi_set_bw(ifname, qcsapi_bw_80MHz);
	if (ret < 0) {
		qtn_error("error: cannot set bw capability %d, errcode %d", qcsapi_bw_80MHz, ret);
		return ret;
	}

	/* 3. VHT MCS Set, 0-9 */
	snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s set_vht_mcs_cap %d",
			ifname,
			IEEE80211_VHT_MCS_0_9);
	system(tmpbuf);

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

	ret = qtn_defconf_check_txbf_support(ifname);
	if (ret == 1) {
		/* 7. SU Transmit Beamformer, On */
		/* 8. SU Transmit Beamformee, On */
		ret = qcsapi_wifi_set_option(ifname, qcsapi_beamforming, 1);
		if (ret < 0) {
			qtn_error("error: enable beamforming, errcode %d", ret);
			return ret;
		}
	}

	/* 9. MU Transmit Beamformer, Off */
	/* 10. MU Transmit Beamformee, 0ff */
	enable_rx_bw_signaling_support(ifname);

	/* restore Ndpa_stainfo_mac to default */
	system("mu sta0 00:00:00:00:00:00");

	ret = qtn_set_mu_enable(0);
	if (ret < 0) {
		qtn_error("error: disable MU beamforming, errcode %d", ret);
		return ret;
	}

	/* 11. Transmit A-MSDU, On
	 * 12. Receive A-MPDU with A-MSDU, On
	 */
	ret = qcsapi_wifi_set_tx_amsdu(ifname, 1);
	if (ret < 0) {
		qtn_error("error: disable tx amsdu, errcode %d", ret);
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
	snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s set_ldpc %d", ifname, 1);
	system(tmpbuf);

	/* 17. Operating Mode Notification, On (if supported) */
	snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s set_vht_opmntf %d",
			ifname,
			0xFFFF);
	system(tmpbuf);

	/* 18. RTS with Bandwidth Signaling, On (if supported) */
	conf = qtn_dut_get_config(ifname);

	if (conf) {
		reset_rts_cts_settings(conf, ifname);
	} else {
		ret = -EFAULT;
		qtn_error("error: cannot get config, errcode %d", ret);
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

/* restore default hostapd config */
static void qtn_defconf_hostapd_conf(int reconfigure)
{
	char cmdbuf[QTN_DEFCONF_CMDBUF_LEN] = {0};

	if (snprintf(cmdbuf, QTN_DEFCONF_CMDBUF_LEN,
			"/scripts/restore_default_config -nr -m ap -sd") <= 0) {
		qtn_error("error: cannot format cmd, errno = %d", errno);
		return;
	}

	system(cmdbuf);

	if (!reconfigure)
		return;

	if (snprintf(cmdbuf, QTN_DEFCONF_CMDBUF_LEN,
			"test -e /scripts/hostapd.conf && "
			"cat /scripts/hostapd.conf > /mnt/jffs2/hostapd.conf && "
			"hostapd_cli reconfigure") <= 0) {
		qtn_error("error: cannot format cmd, errno = %d", errno);
		return;
	}

	system(cmdbuf);
}


/* restore default wpa_supplicant config */
static void qtn_defconf_wpa_supplicant_conf(int reconfigure)
{
	char cmdbuf[QTN_DEFCONF_CMDBUF_LEN] = {0};

	if (snprintf(cmdbuf, QTN_DEFCONF_CMDBUF_LEN,
			"/scripts/restore_default_config -nr -m sta -sd") <= 0) {
		qtn_error("error: cannot format cmd, errno = %d", errno);
		return;
	}

	system(cmdbuf);

	if (!reconfigure)
		return;

	if (snprintf(cmdbuf, QTN_DEFCONF_CMDBUF_LEN,
			"test -e /scripts/wpa_supplicant.conf && "
			"cat /scripts/wpa_supplicant.conf > /mnt/jffs2/wpa_supplicant.conf && "
			"wpa_cli reconfigure") <= 0) {
		qtn_error("error: cannot format cmd, errno = %d", errno);
		return;
	}

	system(cmdbuf);
}

int qtn_defconf_hs2_dut(const char* ifname)
{
	int ret;

	qtn_log("qtn_defconf_hs2_dut, ifname %s", ifname);

	/* restore default hostapd config */
	system("test -e /scripts/hostapd.conf && "
		"cat /scripts/hostapd.conf > /mnt/jffs2/hostapd.conf && "
		"hostapd_cli reconfigure");

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
	system("set_fixed_bw -b auto");

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

int qtn_defconf_11n_testbed(const char* ifname)
{
	int ret;
	char tmpbuf[128];

	qtn_log("qtn_defconf_11n_testbed, ifname %s", ifname);

	ret = qcsapi_wifi_set_phy_mode(ifname , "11na");
	if (ret < 0) {
		qtn_error("error: cannot set 11na, errcode %d", ret);
		return ret;
	}

	/* Spatial streams, 2 */
	ret = qcsapi_wifi_set_nss_cap(ifname, qcsapi_mimo_ht, 2);
	if (ret < 0) {
		qtn_error("error: cannot set NSS capability, errcode %d", ret);
		return ret;
	}

	/* Bandwidth, 40Mhz */
	system("set_fixed_bw -b auto");
	ret = qcsapi_wifi_set_bw(ifname, qcsapi_bw_40MHz);
	if (ret < 0) {
		qtn_error("error: cannot set bw capability %d, errcode %d", qcsapi_bw_40MHz, ret);
		return ret;
	}

	/* disable dynamic GI selection */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_GI_probing, 0);
	if (ret < 0) {
		/* not supported on RFIC6, ignore error for now. */
		qtn_error("error: enable dynamic GI selection, errcode %d", ret);
	}

	/* disable short GI */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_short_GI, 0);
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

	/* Transmit A-MSDU, Off
	 * Receive A-MPDU with A-MSDU, Off
	 */
	ret = qcsapi_wifi_set_tx_amsdu(ifname, 0);
	if (ret < 0) {
		qtn_error("error: enable tx amsdu, errcode %d", ret);
		return ret;
	}

	/* Tx/Rx STBC 2x1, Off*/
	ret = qcsapi_wifi_set_option(ifname, qcsapi_stbc, 0);
	if (ret < 0) {
		qtn_error("error: cannot set stbc, errcode %d", ret);
		return ret;
	}

	/* 15. Tx LDPC, On
	 * 16. Rx LDPC, On
	 */
	snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s set_ldpc %d", ifname, 1);
	system(tmpbuf);

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


static void enable_bss_tm(const char* ifname)
{
	char tmpbuf[64];
	snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s bss_tm 1", ifname);
	system(tmpbuf);
}

/* default mode configuration for MBO */
int qtn_defconf_mbo_dut_ap(const char* ifname)
{
	int ret;
	char region_name[16];
	char macstr[64], cmd[64];
	unsigned char macaddr[IEEE80211_ADDR_LEN];

	qtn_log("%s, ifname %s", __FUNCTION__, ifname);

	ret = qcsapi_wifi_scs_enable(ifname, 0);
	if (ret < 0) {
		qtn_error("error: cannot disable SCS, error %d", ret);
		return ret;
	}

	/* spatial streams, 2 */
	ret = qcsapi_wifi_set_nss_cap(ifname, qcsapi_mimo_ht, 2);

	if (ret < 0) {
		qtn_error("error: cannot set NSS capability, errcode %d", ret);
		return ret;
	}

	/* bandwidth, 20Mhz */
	ret = qcsapi_wifi_set_bw(ifname, qcsapi_bw_20MHz);
	if (ret < 0) {
		qtn_error("error: cannot set bw capability %d, errcode %d", qcsapi_bw_20MHz, ret);
		return ret;
	}

	/* enable short GI */
	ret = qcsapi_wifi_set_option(ifname, qcsapi_short_GI, 1);
	if (ret < 0) {
		qtn_error("error: enable short GI, errcode %d", ret);
		return ret;
	}

	/* if region is none, reset to us as default */
	if ((ret = qcsapi_wifi_get_regulatory_region(ifname, region_name)) < 0) {
		qtn_error("error: cannot get regulatory region, errcode %d", ret);
		return ret;
	}
	if (0 == strcasecmp(region_name, "none")) {
		ret = qcsapi_regulatory_set_regulatory_region(ifname, "us");
		if (ret < 0) {
			qtn_error("error: cannot set regulatory region, errcode %d", ret);
			return ret;
		}
	}

	/* reset SSID to Wi-Fi */
	ret = qcsapi_wifi_set_SSID(ifname, "Wi-Fi");
	if (ret < 0) {
		qtn_error("error: cannot set SSID, errcode %d", ret);
		return ret;
	}

	/* reset passphrase to MBORocks */
	ret = qcsapi_wifi_set_key_passphrase(ifname, 0, "MBORocks");
	if (ret < 0) {
		qtn_error("error: cannot set passphrase, errcode %d", ret);
		return ret;
	}

	/* reset PMF MFPC to 1, MFPR to 0 */
	ret = qcsapi_wifi_set_pmf(ifname, 1);
	if (ret < 0) {
		qtn_error("error: cannot enable pmf, errcode %d", ret);
		return ret;
	}

	/* reset btm_delay to 255 */
	snprintf(cmd, sizeof(cmd), "iwpriv %s set_btm_delay 255", ifname);
	ret = system(cmd);
	if (ret != 0)
		qtn_error("error: cannot reset btm delay to default %d", ret);

	/* reset assoc disallow to 0 */
	ret = qcsapi_interface_get_mac_addr(ifname, macaddr);
	if (ret < 0) {
		qtn_error("error: set assoc disallow: get macaddr failed");
		return ret;
	}
	snprintf(macstr, sizeof(macstr), "%02x:%02x:%02x:%02x:%02x:%02x",
			macaddr[0], macaddr[1], macaddr[2],
			macaddr[3], macaddr[4], macaddr[5]);

	snprintf(cmd, sizeof(cmd), "%s test assoc_disallow %s 0",
			QTN_MBO_TEST_CLI, macstr);
	ret = system(cmd);
	if (ret != 0)
		qtn_error("error: failed to reset assoc disallow");

	/* reset uns_btm_disassoc_imminent to 0 */
	snprintf(cmd, sizeof(cmd), "%s set 0 uns_btm_disassoc_imminent 0",
		QTN_MBO_TEST_CLI);
	ret = system(cmd);
	if (ret != 0)
		qtn_error("error: failed to reset uns_btm_disassoc_imminent");

	/* enable bss tm */
	enable_bss_tm(ifname);

	return 0;
}

int qtn_defconf_mbo_dut_ap_all()
{
	int ret = -EINVAL;

	qtn_defconf_hostapd_conf(0);

	ret = qtn_defconf_mbo_dut_ap("wifi0");
	if (ret < 0)
		return ret;

	return 0;
}

int qtn_defconf_wpa3_dut_ap(const char *ifname)
{
	qtn_log("%s, ifname %s", __func__, ifname);

	qtn_defconf_hostapd_conf(1);

	return 0;
}

int qtn_defconf_wpa3_dut_sta(const char *ifname)
{
	qtn_log("%s, ifname %s", __func__, ifname);

	qtn_defconf_wpa_supplicant_conf(0);

	return 0;
}

static int qtn_alloc_dpp_config(const char *ifname, struct qtn_dut_config *conf)
{
	struct qtn_dut_dpp_config *dpp_config;
	qtn_log("%s, ifname %s, reset DPP config", __func__, ifname);

	if (conf->dpp_config)
		free(conf->dpp_config);

	dpp_config = calloc(1, sizeof(*dpp_config));
	if (!dpp_config) {
		qtn_error("ifname %s: failed to allocate memory for dpp_config", ifname);
		return -ENOMEM;
	}

	conf->dpp_config = dpp_config;
	return 0;
}

int qtn_defconf_dpp(const char *ifname)
{
	int ret;
	struct qtn_dut_config *conf;
	qcsapi_wifi_mode current_mode;

	qtn_log("%s, ifname %s", __func__, ifname);

	ret = qcsapi_wifi_get_mode(ifname, &current_mode);
	if (ret < 0) {
		qtn_error("can't get mode, error %d", ret);
		return ret;
	}

	if (current_mode == qcsapi_station)
		qtn_defconf_wpa_supplicant_conf(1);
	else
		qtn_defconf_hostapd_conf(1);

	conf = qtn_dut_get_config(ifname);
	if (!conf)
		goto fail;

	if (qtn_alloc_dpp_config(ifname, conf))
		goto fail;

	return 0;
fail:
	qtn_error("error: cannot get config");
	return -EFAULT;
}

static int qtn_easymesh_reset_supplicant_params(const char *ifname)
{
	char cmd[QTN_DEFCONF_CMDBUF_LEN];
	int ret;

	if (snprintf(cmd, QTN_DEFCONF_CMDBUF_LEN,
		"test -e /scripts/wpa_supplicant.conf && "
		"cat /scripts/wpa_supplicant.conf > /mnt/jffs2/wpa_supplicant.conf && "
		"sed -i \'s/ssid=\"Quantenna\"/ssid=\"MAP-STA\"/g' /mnt/jffs2/wpa_supplicant.conf && "
		"wpa_cli -i%s reconfigure", ifname) <= 0) {
		qtn_error("error: cannot format cmd, errno = %d", errno);
		return -1;
	}
	ret = system(cmd);
	if (ret < 0) {
		qtn_error("error: cannot restore supplicant params, errno = %d", errno);
		return -1;
	}

	ret = qcsapi_interface_enable(ifname, 1);
	if (ret < 0) {
		qtn_error("error: cannot enable interface %s", ifname);
		return -1;
	}

	return 0;
}

static int qtn_easymesh_reset_hostapd_params(int repeater)
{
	char cmd[QTN_DEFCONF_CMDBUF_LEN];
	char ifname[IFNAMSIZ];
	int ret;

	snprintf(ifname, sizeof(ifname), "wifi%d", repeater);

	if (snprintf(cmd, QTN_DEFCONF_CMDBUF_LEN,
		"test -e /scripts/hostapd.conf && "
		"cat /scripts/hostapd.conf > /mnt/jffs2/hostapd.conf && "
		"sed -i \'s/interface=wifi0/interface=%s/g' /mnt/jffs2/hostapd.conf && "
		"sed -i \'s/ssid=Quantenna/ssid=MAP-5G/g' /mnt/jffs2/hostapd.conf && "
		"hostapd_cli -i%s reconfigure", ifname, ifname) <= 0) {
		qtn_error("error: cannot format cmd, errno = %d", errno);
		return -1;
	}
	ret = system(cmd);
	if (ret < 0) {
		qtn_error("error: cannot restore hostapd params, errno = %d", errno);
		return -1;
	}

	ret = qcsapi_interface_enable(ifname, 1);
	if (ret < 0) {
		qtn_error("error: cannot enable interface %s", ifname);
		return -1;
	}

	return 0;
}

#define enable_restore_default 0
int qtn_defconf_easymesh(const char *ifname)
{
#if enable_restore_default
	char cmd[QTN_DEFCONF_CMDBUF_LEN];
#endif
	char mode[16];
	int repeater, ret;

	qtn_log("%s, ifname %s", __func__, ifname);

	repeater = qcsapi_wifi_verify_repeater_mode();
	snprintf(mode, sizeof(mode), "%s", repeater ? "repeater" : "ap");

#if enable_restore_default
	if (snprintf(cmd, QTN_DEFCONF_CMDBUF_LEN,
		"/scripts/restore_default_config -nr -m %s -sd", mode) <= 0) {
		qtn_error("error: cannot format cmd, errno = %d", errno);
		return -1;
	}
	ret = system(cmd);
	if (ret < 0) {
		qtn_error("error: cannot restore config, errno = %d", errno);
		return -1;
	}
#endif

	ret = qcsapi_wifi_set_channel(ifname, DEFAULT_MAP_VHT_CHANNEL);
	if (ret < 0) {
		qtn_error("error: cannot set channel to %d, errno = %d",
			DEFAULT_MAP_VHT_CHANNEL, errno);
		return -1;
	}

	if (repeater) {
		ret = qtn_easymesh_reset_supplicant_params(ifname);
		if (ret < 0) {
			qtn_error("error: cannot restore supplicant params");
			return -1;
		}
	}

	ret = qtn_easymesh_reset_hostapd_params(repeater);
	if (ret < 0) {
		qtn_error("error: cannot restore hostapd params");
		return -1;
	}

	return 0;
}
