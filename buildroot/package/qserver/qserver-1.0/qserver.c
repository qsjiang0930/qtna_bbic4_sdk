/*
 *	   Quantenna private connections managment daemon
 *
 * Main code for "qserver". It's mainly used to receive the Quantenna private
 * events from driver and process these events. It also maintains the
 * Quantenna private connection state machine and control the automatic switch
 *  for Quantenna private connections.
 *
 * Copyright (c) 2016 Quantenna Communications, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */


#include "qhop.h"
#include "driver.h"
#include "eloop.h"
#include "wireless.h"

#include <net/ethernet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/rtnetlink.h>


static int debug_enable = 0;

static struct qserver_data qevt_data;

static const struct option long_opts_qserver[] = {
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{"background", no_argument, NULL, 'B'},
	{"debug", no_argument, NULL, 'd'},
	{"interface", required_argument, NULL, 'i'},
	{"driver", required_argument, NULL, 'D'},
	{"save", optional_argument, NULL, 's'},
	{NULL, 0, NULL, 0 }
};

extern struct qserver_driver_ops qserver_qtn_driver_ops;
struct qserver_driver_ops *global_driver_ops[] =
{
	&qserver_qtn_driver_ops,
};

void os_fprintf(FILE *stream, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if (debug_enable)
		vfprintf(stream, fmt, args);
	va_end(args);
}

int os_get_time(struct os_time *t)
{
	int res;
	struct timeval tv;
	res = gettimeofday(&tv, NULL);
	t->sec = tv.tv_sec;
	t->usec = tv.tv_usec;
	return res;
}

int os_hexstr2bin(const char *hex, uint8_t *buf, size_t len)
{
	size_t i;
	int a;
	const char *ipos = hex;
	uint8_t *opos = buf;

	for (i = 0; i < len; i++) {
		a = os_hex2byte(ipos);
		if (a < 0)
			return -1;
		*opos++ = a;
		ipos += 2;
	}
	return 0;
}

int os_snprintf_hex(char *buf, size_t buf_size,
	const uint8_t *data, size_t len)
{
	size_t i;
	char *pos = buf, *end = buf + buf_size;
	int ret;

	if (buf_size == 0)
		return 0;

	for (i = 0; i < len; i++) {
		ret = snprintf(pos, end - pos, "%02x", data[i]);
		if (ret < 0 || ret >= end - pos) {
			end[-1] = '\0';
			return pos - buf;
		}
		pos += ret;
	}
	end[-1] = '\0';
	return pos - buf;
}

int os_hwaddr_aton(const char *txt, uint8_t *addr)
{
	int i;

	for (i = 0; i < ETH_ALEN; i++) {
		int a, b;

		a = os_hex2num(*txt++);
		if (a < 0)
			return -1;
		b = os_hex2num(*txt++);
		if (b < 0)
			return -1;
		*addr++ = (a << 4) | b;
		if (i < 5 && *txt++ != ':')
			return -1;
	}

	return 0;
}

int os_random_array(unsigned char *data,
	int len, unsigned int ext_seed)
{
	int index;

	if (data == NULL || len <= 0)
		return -EFAULT;

	srand((unsigned int)time(NULL) + ext_seed);
	for (index = 0; index < len; index++) {
		data[index] = (unsigned char)rand();
	}

	return 0;
}

static void
qserver_handle_wireless_event_custom(const char *ifname, char *custom)
{
	if (strncmp(custom, "QTN-WDS-EXT", 11) == 0)
		qhop_handle_wds_ext_event(ifname, custom);
}

static void
qserver_handle_wireless_event(const char *ifname, char *data, int len)
{
	struct iw_event iwe_buf, *iwe = &iwe_buf;
	char *pos, *end, *custom, *buf;

	pos = data;
	end = data + len;

	while (pos + IW_EV_LCP_LEN <= end) {
		/* Event data may be unaligned, so make a local, aligned copy
		 * before processing. */
		memcpy(&iwe_buf, pos, IW_EV_LCP_LEN);
		if (iwe->len <= IW_EV_LCP_LEN)
			return;

		custom = pos + IW_EV_POINT_LEN;
		if (iwe->cmd == IWEVCUSTOM) {
			char *dpos = (char *) &iwe_buf.u.data.length;
			int dlen = dpos - (char *) &iwe_buf;
			memcpy(dpos, pos + IW_EV_LCP_LEN,
			       sizeof(struct iw_event) - dlen);
		} else {
			memcpy(&iwe_buf, pos, sizeof(struct iw_event));
			custom += IW_EV_POINT_OFF;
		}

		switch (iwe->cmd) {
		case IWEVCUSTOM:
			if (custom + iwe->u.data.length > end)
				return;
			buf = malloc(iwe->u.data.length + 1);
			if (buf == NULL)
				return;

			memcpy(buf, custom, iwe->u.data.length);
			buf[iwe->u.data.length] = '\0';
			qserver_handle_wireless_event_custom(ifname, buf);
			free(buf);
			break;
		}

		pos += iwe->len;
	}
}

static void
qserver_wireless_event_rtm_newlink(const char *ifname,
		struct ifinfomsg *ifi UNUSED_PARAM, uint8_t *buf, size_t len)
{
	int attrlen, rta_len;
	struct rtattr *attr;

	attrlen = len;
	attr = (struct rtattr *) buf;

	rta_len = RTA_ALIGN(sizeof(struct rtattr));
	while (RTA_OK(attr, attrlen)) {
		if (attr->rta_type == IFLA_WIRELESS) {
			qserver_handle_wireless_event(ifname,
				((char *) attr) + rta_len,
				attr->rta_len - rta_len);
		}
		attr = RTA_NEXT(attr, attrlen);
	}
}


static void
qserver_handle_netlink_events(int sock UNUSED_PARAM, void *eloop_ctx, void *sock_ctx UNUSED_PARAM)
{
	struct qserver_data *q_data = (struct qserver_data *)eloop_ctx;

	while (1) {
		struct sockaddr_nl sanl;
		socklen_t sanllen = sizeof(struct sockaddr_nl);
		char buf[QSERVER_MSG_BUF_LEN] = {0};
		struct nlmsghdr *h;
		int rest;

		rest = recvfrom(q_data->rth.fd, buf, sizeof(buf), MSG_DONTWAIT,
				(struct sockaddr*)&sanl, &sanllen);
		if (rest < 0) {
			if(errno != EINTR && errno != EAGAIN)
				os_fprintf(stderr, "%s: error reading netlink: %s.\n",
					__func__, strerror(errno));
				return;
		}

		if (rest == 0) {
			os_fprintf(stdout, "%s: EOF on netlink\n", __func__);
			return;
		}

		h = (struct nlmsghdr*)buf;
		while (rest >= (int)sizeof(*h)) {
			int len = h->nlmsg_len;
			int data_len = len - sizeof(*h);

			if (data_len < 0 || len > rest) {
				os_fprintf(stderr, "%s: malformed netlink message: len=%d\n",
					__func__, len);
				break;
			}

			switch (h->nlmsg_type) {
			case RTM_NEWLINK:
				qserver_wireless_event_rtm_newlink(q_data->ifname, NLMSG_DATA(h),
					(uint8_t *) NLMSG_DATA(h) + NLMSG_ALIGN(sizeof(struct ifinfomsg)),
					NLMSG_PAYLOAD(h, sizeof(struct ifinfomsg)));
				break;
			default:
				break;
			}

			len = NLMSG_ALIGN(len);
			rest -= len;
			h = (struct nlmsghdr*)((char*)h + len);
		}

		if (rest > 0)
			os_fprintf(stderr, "%s: redundant size %d on netlink\n", __func__, rest);
    }
}

static int
qserver_rtnl_open(struct rtnl_handle *rth, unsigned subscriptions)
{
	int addr_len;

	memset(rth, 0, sizeof(*rth));

	rth->fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (rth->fd < 0) {
		perror("Cannot open netlink socket");
		return -1;
	}

	rth->local.nl_family = AF_NETLINK;
	rth->local.nl_groups = subscriptions;

	if (bind(rth->fd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0) {
		perror("Cannot bind netlink socket");
		return -1;
	}
	addr_len = sizeof(rth->local);
	if (getsockname(rth->fd, (struct sockaddr*)&rth->local,
			(socklen_t *)&addr_len) < 0) {
		perror("Cannot getsockname");
		return -1;
	}
	if (addr_len != sizeof(rth->local)) {
		fprintf(stderr, "%s: Wrong address length %d\n", __func__, addr_len);
		return -1;
	}
	if (rth->local.nl_family != AF_NETLINK) {
		fprintf(stderr, "%s: Wrong address family %d\n",
				__func__, rth->local.nl_family);
		return -1;
	}
	rth->seq = time(NULL);

	eloop_register_read_sock(rth->fd,
			qserver_handle_netlink_events, &qevt_data, NULL);

	os_fprintf(stdout, "%s: open netlink socket to receive wireless events\n",
			__func__);

	return 0;
}

static void
qserver_rtnl_close(struct rtnl_handle *rth)
{
	os_fprintf(stdout, "%s: close netlink socket for wireless events\n",
			__func__);

	if (rth->fd >= 0) {
		eloop_unregister_read_sock(rth->fd);
		close(rth->fd);
	}
}

static int
qserver_init_driver_ops(struct qserver_data *data,
	const char *drv_name, const char *ifname)
{
	uint32_t i;

	for (i = 0; i < ARRAYSIZE(global_driver_ops); i++) {
		if (strcasecmp(global_driver_ops[i]->name, drv_name) == 0)
			break;
	}

	if (i >= ARRAYSIZE(global_driver_ops)) {
		os_fprintf(stderr, "%s: fail to find the assigned driver\n",
				__func__);
		return -1;
	}

	data->driver = global_driver_ops[i];

	data->driver_priv = qserver_drv_init(data, ifname);
	if (!data->driver_priv) {
		os_fprintf(stderr, "%s: fail to initialize driver interface\n",
				__func__);
		return -1;
	}

	return 0;
}

static void
qserver_deinit_driver_ops(struct qserver_data *data)
{
	qserver_drv_deinit(data);
}

static inline void
qserver_sigext(int sig UNUSED_PARAM, void *signal_ctx UNUSED_PARAM)
{
	fprintf(stdout, "%s: receive terminal signal and exit\n", __func__);

	eloop_terminate();
}

static inline void
qserver_usage(int status)
{
	fprintf(status ? stderr : stdout,
		"Usage: qserver [OPTIONS]\n"
		"   Receive Quantenna special wireless events and manage private connection\n"
		"   Options are:\n"
		"     -h,--help		Print this message.\n"
		"     -v,--version	Show version of this program.\n"
		"     -B,--background	Run this program as a daemon.\n"
		"     -d,--debug	Print debugging messages.\n"
		"     -i,--interface	assign interface name\n"
		"     -D,--driver	assign driver interface name\n"
		"     -s,--save		save synced params to a local file\n"
		);
	exit(status);
}

static inline void
qserver_version(int status)
{
	fprintf(stdout, "qserver: 1.0\n");
	exit(status);
}

void *qserver_get_context()
{
	return &qevt_data;
}

int
main(int argc, char * argv[])
{
	char *if_name = QSERVER_DEFAULT_IFACE;
	char *drv_name = QSERVER_DEFAULT_DRV_NAME;
	char *params_filename = NULL;
	int save_params = 0;
	int daemonize = 0;
	int ret = 0;
	int opt;

	/* Check command line options */
	while((opt = getopt_long(argc, argv, "hvBdi:D:s::",
			long_opts_qserver, NULL)) > 0) {
		switch(opt) {
		case 'h':
			qserver_usage(0);
			break;
		case 'v':
			qserver_version(0);
			break;
		case 'B':
			daemonize = 1;
			break;
		case 'd':
			debug_enable = 1;
			break;
		case 's':
			save_params = 1;
			if (optarg)
				params_filename = optarg;
			break;
		case 'i':
			if_name = optarg;
			break;
		case 'D':
			drv_name = optarg;
			break;
		default:
			qserver_usage(1);
			break;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "Too many arguments.\n");
		qserver_usage(1);
	}

	os_fprintf(stdout, "%s: start qserver daemon with interface"
		" %s and driver %s\n", __func__, if_name, drv_name);

	memset(&qevt_data, 0, sizeof(qevt_data));
	strncpy(qevt_data.ifname, if_name, IFNAMSIZ);
	qevt_data.save_params = save_params;
	if (params_filename)
		strncpy(qevt_data.params_filename, params_filename,
				QTN_FILENAME_LENGTH_MAX);

	/* Initialize eloop structure */
	eloop_init();

	/* Open sockets */
	if (qserver_rtnl_open(&qevt_data.rth, RTMGRP_LINK) < 0) {
		perror("Can't initialize rtnetlink socket");
		ret = -1;
		goto out;
	}
	if (qserver_raw_frame_init(&qevt_data.frm_data,
			if_name, &qevt_data) < 0) {
		perror("Can't initialize qserver frame raw socket");
		ret = -1;
		goto out_rtnl;
	}

	/* Initialize control interface */
	if (qserver_ctrl_iface_init(&qevt_data.ctrl_iface,
			if_name, &qevt_data) < 0) {
		perror("Can't initialize qserver control interface");
		ret = -1;
		goto out_raw_frame;
	}

	/* Initialize driver interfaces */
	if (qserver_init_driver_ops(&qevt_data,
			drv_name, if_name) < 0) {
		perror("Can't initialize assigned driver interface");
		ret = -1;
		goto out_ctrl_iface;
	}

	/* Initialize link switch state machine */
	if (link_switch_sm_init(&qevt_data.ls_data,
			if_name, &qevt_data)) {
		perror("Can't initialize link switch state machine");
		ret = -1;
		goto out_driver_ops;
	}

	qserver_drv_get_device_mode(&qevt_data, &qevt_data.dev_mode);
	qserver_drv_get_device_capas(&qevt_data, &qevt_data.dev_capas);

	/* Daemonize */
	if (daemonize && daemon(0, 0)) {
		perror("daemonize error");
		ret = -1;
		goto out_link_switch_sm;
	}

	/* Establish signal handler */
	eloop_register_signal_terminate(qserver_sigext, NULL);

	/* Main loop */
	eloop_run();

	/* Deinitialize eloop structure */
	eloop_destroy();

out_link_switch_sm:
	/* Deinitialize qserver related structures */
	link_switch_sm_deinit(&qevt_data.ls_data);

out_driver_ops:
	qserver_deinit_driver_ops(&qevt_data);

out_ctrl_iface:
	qserver_ctrl_iface_deinit(&qevt_data.ctrl_iface);

out_raw_frame:
	qserver_raw_frame_deinit(&qevt_data.frm_data);

out_rtnl:
	qserver_rtnl_close(&qevt_data.rth);

out:
	return ret;
}

