/**
 * Copyright (c) 2016 Quantenna Communications, Inc.
 * All rights reserved.
 **/

#include <errno.h>
#include <net/ethernet.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ql2t.h"

#define ql2t_test_err(format, ...)	do {							\
						ql2t_test_log("%s: ERR: " format "\n", __func__,	\
							##__VA_ARGS__);				\
					} while (0)

#define DEBUG
#ifdef DEBUG
#define ql2t_test_out(format, ...)	do {							\
						ql2t_test_log("%s: " format "\n", __func__,	\
							##__VA_ARGS__);				\
					} while (0)
#else
#define ql2t_test_out(format, ...)
#endif

#define QL2T_TIMEOUT		5

/* Check ql2t.h to be sure that EP's used here are not used by others */
#define QL2T_TEST_EP_SERVER	1000
#define QL2T_TEST_EP_CLIENT	2000

typedef enum {
	TYPE_INVALID	= -1,
	TYPE_CLIENT	= 0,
	TYPE_SERVER	= 1,
} ql2t_test_type;

struct ql2t_test_cfg {
	ql2t_test_type	type;
	char		local_if_name[IFNAMSIZ];
	unsigned char	remote_mac_addr[ETH_ALEN];
	unsigned int	test_no;
};

static struct ql2t_test_cfg cfg =	{
						.type = TYPE_INVALID,
					};

static void ql2t_test_log(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	/* TBD: Extend this to support log file, syslog, etc (if needed) */
	vfprintf(stdout, format, args);
	va_end(args);
}

static int ql2t_test_get_options(int argc, char *argv[])
{
	int ch;
	int mac_cfg = 0;
	int retval = -EINVAL;

	while ((ch = getopt(argc, argv, "ci:m:st:h")) != -1) {
		switch (ch) {
		case 'c':
			if (cfg.type != TYPE_INVALID) {
				ql2t_test_err("cfg.type = %u", cfg.type);
				goto exit;
			}
			cfg.type = TYPE_CLIENT;
			break;
		case 'i':
			if (strlen(optarg) > sizeof(cfg.local_if_name) - 1) {
				ql2t_test_err("Exceeds max allowed len (%u)", sizeof(cfg.local_if_name) - 1);
				goto exit;
			}

			strncpy(cfg.local_if_name, optarg, sizeof(cfg.local_if_name) - 1);
			break;
		case 'm':
			{
				int count;
				int mac_addr[sizeof(cfg.remote_mac_addr)];

				count = sscanf(optarg, "%02x:%02x:%02x:%02x:%02x:%02x",
							&mac_addr[0],
							&mac_addr[1],
							&mac_addr[2],
							&mac_addr[3],
							&mac_addr[4],
							&mac_addr[5]);
				if (count != sizeof(cfg.remote_mac_addr)) {
					ql2t_test_err("Incorrect MAC address format; expected xx:xx:xx:xx:xx:xx");
					goto exit;
				}

				while(count--)
					cfg.remote_mac_addr[count] = mac_addr[count];

				mac_cfg = 1;
			}
			break;
		case 's':
			if (cfg.type != TYPE_INVALID) {
				ql2t_test_err("cfg.type = %u", cfg.type);
				goto exit;
			}
			cfg.type = TYPE_SERVER;
			break;
		case 't':
			cfg.test_no = atoi(optarg);
			break;
		case 'h':
		default:
			ql2t_test_out("Option h: Help");
			goto exit;
		}
	}

	if (cfg.type == TYPE_INVALID) {
		ql2t_test_err("cfg.type is not set");
		goto exit;
	}

	if (!cfg.local_if_name[0]) {
		ql2t_test_err("cfg.local_if_name is not set");
		goto exit;
	}

	if (!mac_cfg) {
		ql2t_test_err("cfg.remote_mac_addr is not set");
		goto exit;
	}

	if (!cfg.test_no) {
		ql2t_test_err("cfg.test_no is not set or is set to 0");
		goto exit;
	}

	retval = 0;

exit:
	return retval;
}

static int ql2t_test_send(int fd, unsigned short remote_end_pt, char data[],
		unsigned int len)
{
	ql2t_send_cfg send_cfg;

	memcpy(send_cfg.remote_mac_addr, cfg.remote_mac_addr, ETH_ALEN);
	send_cfg.remote_end_pt = remote_end_pt;

	ql2t_test_out("Sending data...");

	ql2t_test_out("rem MAC: %02x:%02x:%02x:%02x:%02x:%02x, rem_ep: 0x%04x, data: %.25s",
		(unsigned char) send_cfg.remote_mac_addr[0],
		(unsigned char) send_cfg.remote_mac_addr[1],
		(unsigned char) send_cfg.remote_mac_addr[2],
		(unsigned char) send_cfg.remote_mac_addr[3],
		(unsigned char) send_cfg.remote_mac_addr[4],
		(unsigned char) send_cfg.remote_mac_addr[5],
		send_cfg.remote_end_pt,
		data);

	if (ql2t_send(fd, &send_cfg, data, len)) {
		ql2t_test_out("ql2t_send failed");
	}

	return 0;
}

static int ql2t_test_recv(int fd, char data[], unsigned int len)
{
	ql2t_recv_cfg recv_cfg;
	unsigned short bytes_copied;

	memset(data, 0, len);
	memset(&recv_cfg, 0, sizeof(recv_cfg));

	ql2t_test_out("Waiting to receive...");

	if (ql2t_recv(fd, &recv_cfg, data, len, &bytes_copied)) {
		ql2t_test_out("ql2t_recv failed");
	} else {
		ql2t_test_out("rem MAC: %02x:%02x:%02x:%02x:%02x:%02x, rem_ep: 0x%04x, data: %.25s",
			(unsigned char) recv_cfg.remote_mac_addr[0],
			(unsigned char) recv_cfg.remote_mac_addr[1],
			(unsigned char) recv_cfg.remote_mac_addr[2],
			(unsigned char) recv_cfg.remote_mac_addr[3],
			(unsigned char) recv_cfg.remote_mac_addr[4],
			(unsigned char) recv_cfg.remote_mac_addr[5],
			recv_cfg.remote_end_pt,
			data);
	}

	return 0;
}

/*
 * Data:
 * - Direction	: Server => Client
 * - Size	: 1 L2 frame
 *
 * Server EP	: Fixed
 * Client EP	: Fixed
 */
static int ql2t_tc_1()
{
	char data[25];
	int fd;
	unsigned int count;

	ql2t_test_out("===> Start test");

	if (cfg.type == TYPE_CLIENT) {
		fd = ql2t_open(cfg.local_if_name, QL2T_TEST_EP_CLIENT);

		for (count = 1; count <= 10; ++count) {
			ql2t_test_recv(fd, data, sizeof(data));
		}

		ql2t_close(fd);
	} else {
		fd = ql2t_open(cfg.local_if_name, QL2T_TEST_EP_SERVER);

		for (count = 1; count <= 10; ++count) {
			snprintf(data, sizeof(data), "### Server says %u", count);
			ql2t_test_send(fd, QL2T_TEST_EP_CLIENT, data, strlen(data) + 1);
		}

		ql2t_close(fd);
	}

	ql2t_test_out("===> End test");

	return 0;
}

/*
 * Data:
 * - Direction	: Server => Client
 * - Size	: 1 L2 frame
 *
 * Server EP	: Modified on each iteration
 * Client EP	: Fixed
 */
static int ql2t_tc_2()
{
	char data[25];
	int fd;
	unsigned int count;

	ql2t_test_out("===> Start test");

	if (cfg.type == TYPE_CLIENT) {
		fd = ql2t_open(cfg.local_if_name, QL2T_TEST_EP_CLIENT);

		for (count = 1; count <= 10; ++count) {
			ql2t_test_recv(fd, data, sizeof(data));
		}

		ql2t_close(fd);
	} else {
		for (count = 1; count <= 10; ++count) {
			fd = ql2t_open(cfg.local_if_name, QL2T_TEST_EP_SERVER + count);

			snprintf(data, sizeof(data), "### Server says %u", count);
			ql2t_test_send(fd, QL2T_TEST_EP_CLIENT, data, strlen(data) + 1);

			ql2t_close(fd);
		}
	}

	ql2t_test_out("===> End test");

	return 0;
}

/*
 * Data:
 * - Direction	: Server => Client and then Client => Server (alternately)
 * - Size	: 1 L2 frame
 *
 * Server EP	: Modified on each iteration
 * Client EP	: Fixed
 */
static int ql2t_tc_3()
{
	char data[25];
	int fd;
	unsigned int count;

	ql2t_test_out("===> Start test");

	if (cfg.type == TYPE_CLIENT) {
		fd = ql2t_open(cfg.local_if_name, QL2T_TEST_EP_CLIENT);

		for (count = 1; count <= 10; ++count) {
			if (count % 2) {
				ql2t_test_recv(fd, data, sizeof(data));
			} else {
				snprintf(data, sizeof(data), "*** Client says %u", count);
				ql2t_test_send(fd, QL2T_TEST_EP_SERVER, data, strlen(data) + 1);
			}
		}

		ql2t_close(fd);
	} else {
		fd = ql2t_open(cfg.local_if_name, QL2T_TEST_EP_SERVER);

		for (count = 1; count <= 10; ++count) {
			if (count % 2) {
				snprintf(data, sizeof(data), "### Server says %u", count);
				ql2t_test_send(fd, QL2T_TEST_EP_CLIENT, data, strlen(data) + 1);
			} else {
				ql2t_test_recv(fd, data, sizeof(data));
			}
		}

		ql2t_close(fd);
	}

	ql2t_test_out("===> End test");

	return 0;
}

/*
 * Data:
 * - Direction	: Server => Client
 * - Size	: > 1 L2 frame
 *
 * Server EP	: Fixed
 * Client EP	: Fixed
 */
static int ql2t_tc_4()
{
	char data[65535] = {0};
	int fd;
	unsigned int count = 1;

	ql2t_test_out("===> Start test");

	if (cfg.type == TYPE_CLIENT) {
		fd = ql2t_open(cfg.local_if_name, QL2T_TEST_EP_CLIENT);

		while (count--) {
			ql2t_test_recv(fd, data, sizeof(data));
		}

		ql2t_close(fd);
	} else {
		fd = ql2t_open(cfg.local_if_name, QL2T_TEST_EP_SERVER);

		while (count--) {
			ql2t_test_send(fd, QL2T_TEST_EP_CLIENT, data, sizeof(data));
		}

		ql2t_close(fd);
	}

	ql2t_test_out("===> End test");

	return 0;
}

int (*test_list[])() =	{
				ql2t_tc_1,
				ql2t_tc_2,
				ql2t_tc_3,
				ql2t_tc_4
			};

int main(int argc, char *argv[])
{
	int retval;
	unsigned int max_test_no;

	retval = ql2t_test_get_options(argc, argv);
	if (retval != 0)
		goto exit;

	ql2t_test_out("Max data len = %u", ql2t_get_max_data_len());

	max_test_no = sizeof(test_list) / sizeof(test_list[0]);
	if (cfg.test_no > max_test_no) {
		ql2t_test_err("Invalid test_no, valid: [1, %u]", max_test_no);
		retval = -EINVAL;
		goto exit;
	}

	(*test_list[cfg.test_no -1])();

	retval = 0;

exit:
	return retval;
}
