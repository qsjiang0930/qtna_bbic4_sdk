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
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <net80211/ieee80211.h>
#include <sys/stat.h>
#include "qcsapi.h"
#include "qtn_common.h"
#include "qtn_log.h"
#include "qtn_ca_config.h"

int qtn_parse_mac(const char *mac_str, unsigned char *mac)
{
	unsigned int tmparray[IEEE80211_ADDR_LEN];

	if (mac_str == NULL)
		return -EINVAL;

	if (sscanf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
			&tmparray[0],
			&tmparray[1],
			&tmparray[2],
			&tmparray[3], &tmparray[4], &tmparray[5]) != IEEE80211_ADDR_LEN) {
		return -EINVAL;
	}

	mac[0] = tmparray[0];
	mac[1] = tmparray[1];
	mac[2] = tmparray[2];
	mac[3] = tmparray[3];
	mac[4] = tmparray[4];
	mac[5] = tmparray[5];

	return 0;
}

int qtn_set_tx_bandwidth(const char* ifname, unsigned bandwidth)
{
	qcsapi_unsigned_int current_bw;
	int ret;
	char val_buf[32];

	if (qcsapi_wifi_get_bw(ifname, &current_bw) < 0) {
		current_bw = 0;
		qtn_error("can't get current bw");
	}

	/* change bw only when current is not wide enough */
	if (bandwidth > current_bw
		&& (ret = qcsapi_wifi_set_bw(ifname, bandwidth)) < 0) {
		qtn_error("can't set bandwidth to %d, error %d", bandwidth, ret);
		return ret;
	}

	/* force RA to use only specified bandwidth */
	snprintf(val_buf, sizeof(val_buf), "%d", bandwidth);
	qcsapi_wfa_cert_feature(ifname, "FIXED_BW", val_buf);

	return 0;
}

const char* qtn_get_sigma_interface(void)
{
	static char ifname[128];

	if (ifname[0] == '\0') {
		qcsapi_get_primary_interface(ifname, sizeof(ifname));
	}

	return ifname;
}

const char* qtn_get_sigma_vap_interface(unsigned vap_index)
{
	static char qtn_dut_sigma_vap[IFNAMSIZ];

	if (vap_index == 0)
		return qtn_get_sigma_interface();

	sprintf(qtn_dut_sigma_vap, "wifi%u", vap_index);

	char status[32] = {0};
	if (qcsapi_interface_get_status(qtn_dut_sigma_vap, status) < 0) {
		qtn_error("failed to get vap interface if_index = %d", vap_index);
		return qtn_get_sigma_interface();
	}

	return qtn_dut_sigma_vap;
}

int qtn_set_rf_enable(int enable)
{
	int ret = qcsapi_wifi_rfenable(enable);

	/* WAR: let system to UP/DOWN completely */
	sleep(5);

	return ret;
}

#define QTN_DUT_RADIO_UP_TRY_COUNT	3

void qtn_bring_up_radio_if_needed(void)
{
	qcsapi_rf_status rf_status;

	/* Status of the radio could be one of the following:
	 *  QCSAPI_RFSTATUS_OFF
	 *  QCSAPI_RFSTATUS_ON
	 *  QCSAPI_RFSTATUS_TURNING_OFF
	 *  QCSAPI_RFSTATUS_TURNING_ON
	 */
	if ((qcsapi_wifi_rfstatus(&rf_status) == 0) && (rf_status != QCSAPI_RFSTATUS_ON)) {
		qtn_log("enable RF");

		int try_count;

		for (try_count = 1; try_count <= QTN_DUT_RADIO_UP_TRY_COUNT; try_count++) {
			/* enable radio */
			qtn_set_rf_enable(1);

			/* check status for another 5 seconds */
			int timeout = 5;
			while (timeout-- > 0) {
				if ((qcsapi_wifi_rfstatus(&rf_status) == 0) && (rf_status == QCSAPI_RFSTATUS_ON)) {
					/* radio is up */
					return;
				}

				qtn_log("wait RF, status %d", rf_status);

				sleep(1);
			}

			qtn_log("try to enable RF again");
		}

		qtn_log("unable to bring up RF after %d tries", try_count);
	}
}

/*
 * The function checks if "defer" mode for security configuration is "active".
 * Then it apply "deferred" security configuration for specified interface.
 * Usually "deferred" configuration is used for "stateless" mode.
 */
void qtn_check_defer_mode_apply_config(const char* ifname)
{
	int defer_mode;
	int ret = qcsapi_wifi_get_security_defer_mode(ifname, &defer_mode);

	if (ret < 0) {
		qtn_error("unable to obtain defer_mode, error %d", ret);
		return;
	}

	if (defer_mode) {
		ret = qcsapi_wifi_apply_security_config(ifname);
		if (ret < 0) {
			qtn_error("unable to apply deffered security config, error %d", ret);
			return;
		}
	}
}

int qtn_run_script(const char* script_name, const char* arg1)
{
	char tmpbuf[256];
	int ret;

	ret = snprintf(tmpbuf, sizeof(tmpbuf), "%s %s", script_name, arg1);

	if (ret < 0 || ret >= sizeof(tmpbuf)) {
		qtn_error("invalid command: %s %s", script_name, arg1);
		return -1;
	}

	ret = system(tmpbuf);

	return ret;
}
