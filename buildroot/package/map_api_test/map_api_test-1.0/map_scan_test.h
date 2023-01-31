/**
  Copyright (c) 2020 Quantenna Communications Inc
  All Rights Reserved

  This software may be distributed under the terms of the BSD license.
  See README for more details.
 **/

#ifndef _MAP_SCAN_TEST_H
#define _MAP_SCAN_TEST_H

#include <stdint.h>

#define IEEE80211_MAX_2_4_GHZ_CHANNELS	14
#define IEEE80211_MAX_5_GHZ_CHANNELS	30
#define IEEE80211_MAX_DUAL_CHANNELS (IEEE80211_MAX_2_4_GHZ_CHANNELS + IEEE80211_MAX_5_GHZ_CHANNELS)

enum ieee80211_qrpe_scan_type {
	IEEE80211_BGSCAN_CHECK_TRAFFIC = 1,
	IEEE80211_SCAN_TYPE_MAX
};

int map_test_start_scan(const char *ifname, uint8_t scan_type, uint8_t bw,
		uint32_t *freqs, uint32_t freqs_num);

#endif
