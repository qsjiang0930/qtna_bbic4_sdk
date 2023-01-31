/**
  Copyright (c) 2020 Quantenna Communications Inc
  All Rights Reserved

  This software may be distributed under the terms of the BSD license.
  See README for more details.
 **/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include "map_util_test.h"
#include "map_scan_test.h"

#define IEEE80211_IOCTL_EXT			(SIOCDEVPRIVATE+0xF)
#define SIOCDEV_SUBIO_BASE			(0)
#define SIOCDEV_SUBIO_QRPE_TRIGGER_SCAN		(SIOCDEV_SUBIO_BASE + 88)

/**
 * @brief Data structure for SIOCDEV_SUBIO_QRPE_TRIGGER_SCAN QRPE IOCTL
 */
struct ieee80211_qrpe_scan_param {
	enum ieee80211_qrpe_scan_type  scan_type;
	uint8_t  scan_bw;
	/* scan_flags it is reserved for use */
	uint32_t scan_flags;
	uint32_t freqs_num;
	uint32_t freqs[IEEE80211_MAX_DUAL_CHANNELS];
};

int map_test_start_scan(const char *ifname, uint8_t scan_type, uint8_t bw,
		uint32_t *freqs, uint32_t freqs_num)
{
	struct ieee80211_qrpe_scan_param scan_param;
	struct iwreq iwr;
	int ret = 0;
	int skfd = -1;

	if (ifname == NULL || freqs == NULL) {
		return -1;
	}

	if (freqs_num >= IEEE80211_MAX_DUAL_CHANNELS) {
		return -1;
	}

	scan_param.scan_type = scan_type;
	scan_param.scan_bw = bw;
	scan_param.freqs_num = freqs_num;

	memcpy(&scan_param.freqs, &freqs[0], freqs_num * sizeof(uint32_t));

	skfd = socket(PF_INET, SOCK_DGRAM, 0);
	if (skfd < 0) {
		return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ - 1);
	iwr.u.data.flags = SIOCDEV_SUBIO_QRPE_TRIGGER_SCAN;
	iwr.u.data.pointer = &scan_param;
	iwr.u.data.length = sizeof(scan_param);

	if ((ret = ioctl(skfd, IEEE80211_IOCTL_EXT, &iwr)) < 0) {
		printf("%s: ret=%d\n",__func__,ret);
	}

	close(skfd);

	return ret;
}




