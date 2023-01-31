/**
  Copyright (c) 2020 Quantenna Communications Inc
  All Rights Reserved

  This software may be distributed under the terms of the BSD license.
  See README for more details.
 **/

#include <stdint.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <getopt.h>
#include "map_scan_test.h"
#include "map_util_test.h"
#include "map_api_test.h"


int isDebug = 0;

static struct option opts[] = {
	{ "help", 0, NULL, 'h' },
	{ "debug", 0, NULL, 'd' },
	{ "triggerscan", 0, NULL, 't' },
	{ "ifname", 1, NULL, 'i' },
	{ "freqs", 1, NULL, 'f' },
	{ "bw", 1, NULL, 'b' },
};

static void usage()
{
	fprintf(stderr, "\t-h --help\t\tThis help message\n");
	fprintf(stderr, "\t-d --debug\t\tshow debug info\n");
	fprintf(stderr, "\t-t --triggerscan\ttrigger scan command\n");
	fprintf(stderr, "\t-f --freqs k,k,k,...\tset scan freqs\n");
	fprintf(stderr, "\t-i --ifname wlan ifname\n");
	fprintf(stderr, "\t-b --bw bandwidth\tchannel scan with bandwidth\n");
	fprintf(stderr, "\tcmd <erw> <params>: command for test\n");
	fprintf(stderr, "\t\tcmd erw <help>	: help for erw test command\n");
	fprintf(stderr, "\n");
}

static int map_handle_cmd(int argc, char *argv[])
{
	int retval = 0;

	if (memcmp(argv[0], "erw", 3) == 0) {
		argc -= 1;
		if (argc < 0) {
			usage();
			return -1;
		}

		retval = map_erw_test(argc, &argv[1]);
	} else {
		usage();
	}
	return retval;
}

int main(int argc, char *argv[])
{
	uint32_t freqs_num = 0;
	int cmd_type = 0;
	int bw = 0;
	int c = 0;
	int ret = 0;
	uint8_t scan_type = IEEE80211_BGSCAN_CHECK_TRAFFIC;
	char ifname[IFNAMSIZE] = {0};
	char tmp[BUF_SIZE] = {0};
	uint32_t freqs[IEEE80211_MAX_DUAL_CHANNELS] = {0};


	if (argc >= 3 && argv[1] && !memcmp(argv[1], "cmd", strlen("cmd"))) {
		argc -= 2;
		return map_handle_cmd(argc, &argv[2]);
	}

	while ((c = getopt_long(argc, argv,"b:tdhi:f:", opts, NULL)) != -1) {
		char *tok;

		switch (c) {
			case 't':
				cmd_type = MAP_TEST_TRIGGER_SCAN;
				scan_type = IEEE80211_BGSCAN_CHECK_TRAFFIC;
				break;
			case 'b':
				bw = strtoul(optarg, NULL, 0);
				break;
			case 'i':
				strncpy(ifname, optarg, sizeof(ifname)-1);
				break;
			case 'f':
				strncpy(tmp, optarg, sizeof(tmp)-1);
				if (!tmp[0])
					break;
				for (tok = strtok(tmp, ","); tok; tok = strtok(NULL, ",")) {
					if (freqs_num >= IEEE80211_MAX_DUAL_CHANNELS) {
						fprintf(stderr,
								"WARN: too many keys"
								" requested: (%d max)\n",
								IEEE80211_MAX_DUAL_CHANNELS);
						break;
					}
					freqs[freqs_num++] = strtoul(tok, NULL, 0);
				}
				break;
			case 'h':
				usage();
				break;
			case 'd':
				isDebug = 1;
				break;
			default:
				usage();
				break;
		}
	}

	switch (cmd_type) {
		case MAP_TEST_TRIGGER_SCAN:
			ret = map_test_start_scan(ifname, scan_type, bw, freqs, freqs_num);
			if (ret < 0)
				printf("map start scan failed, ret=%d\n",ret);
			break;
		default:
			break;
	}

	return 0;
}
