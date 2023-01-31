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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "qtn_log.h"
#include "qtn_common.h"
#include "qtn_ca_config.h"

#define QTN_CA_PORT_DEFAULT	9001

struct qtn_config g_qtn_config;

void qtn_config_init()
{
	struct qtn_config *cfg = &g_qtn_config;
	memset(cfg, 0, sizeof(*cfg));
	cfg->lsn_port = QTN_CA_PORT_DEFAULT;
}

int qtn_config_set_listener_options(const char *addr, const char *port)
{
	struct qtn_config *cfg = &g_qtn_config;

	/* port */
	if (port && *port) {
		char *endptr = NULL;
		unsigned val = strtoul(port, &endptr, 10);

		if ((val == 0) || (val > UINT16_MAX) || (endptr && (*endptr != 0))) {
			qtn_error("invalid port number: %s", port);
			return -1;
		}

		cfg->lsn_port = (uint16_t)val;
	}

	if (addr && *addr) {
		struct in_addr ipaddr;

		/* IPv4 address ? */
		if (inet_aton(addr, &ipaddr) != 0) {
			cfg->lsn_addr = ipaddr;
			cfg->lsn_iface[0] = 0;

		} else if (strlen(addr) < IFNAMSIZ) {
			/* interface name ? */
			int fd;
			struct ifreq ifr;
			int ret;

			/* get IPv4 address attached to interface */
			fd = socket(AF_INET, SOCK_DGRAM, 0);

			if (fd == -1) {
				qtn_error("unable to check interface, "
					  "socket creation error (%d)",
					  errno);
				return -1;
			}

			memset(&ifr, 0, sizeof(ifr));
			ifr.ifr_addr.sa_family = AF_INET;
			strncpy(ifr.ifr_name, addr, IFNAMSIZ - 1);

			ret = ioctl(fd, SIOCGIFADDR, &ifr);

			close(fd);

			if (ret == -1) {
				qtn_error("unable to get address "
					  "from \"%s\" interface, (%d)",
					  addr, errno);
				return -1;
			}

			cfg->lsn_addr = ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr;
			strncpy(cfg->lsn_iface, addr, IFNAMSIZ - 1);
		} else
			return -1;
	}

	return 0;
}

int qtn_config_set_dut_options(const char *str)
{
	struct qtn_config *cfg = &g_qtn_config;
	char proto[4] = {0};

	if (!str || *str == 0)
		return -1;

	const char* delim = strchr(str, ',');

	if (!delim)
		return -1;

	if ((delim - str) < sizeof(proto)) {
		int len = delim - str;
		strncpy(proto, str, len);
		proto[len] = 0;
	}

	if (strcasecmp(proto, "raw") == 0) {
		const char *iface = delim + 1;
		int iface_len;
		const char *macaddr;
		unsigned char mac[ETH_ALEN];

		delim = strchr(iface, ',');

		if (!delim)
			return -1;

		iface_len = delim - iface;

		if (iface_len >= IFNAMSIZ)
			return -1;

		macaddr = delim + 1;

		if (qtn_parse_mac(macaddr, mac) != 0)
			return -1;

		strncpy(cfg->dut_proto, proto, 3);
		cfg->dut_proto[3] = 0;
		strncpy(cfg->dut_iface, iface, iface_len);
		cfg->dut_iface[iface_len] = 0;
		memcpy(cfg->dut_mac, mac, sizeof(cfg->dut_mac));

	} else if (strcasecmp(proto, "tcp") == 0 || strcasecmp(proto, "udp") == 0) {
		const char *addr = delim + 1;
		int addr_len = strlen(addr);

		if (addr_len >= sizeof(cfg->dut_addr))
			return -1;

		strncpy(cfg->dut_proto, proto, 3);
		cfg->dut_proto[3] = 0;
		strncpy(cfg->dut_addr, addr, addr_len);
		cfg->dut_iface[0] = 0;
	} else {
		qtn_error("not supported protocol: %s", proto);
		return -1;
	}

	return 0;
}

int qtn_config_set_option(const char *name, const char *value)
{
	struct qtn_config *cfg = &g_qtn_config;

	if (!name || !name[0])
		return -1;

	if (strcasecmp(name, "icons_folder") == 0) {
		const char *folder = value;
		struct stat sbuf;

		if (stat(folder, &sbuf) == -1) {
			fprintf(stderr, "error: stat failed: error=%d\n", errno);
			return -1;
		}

		if (!S_ISDIR(sbuf.st_mode)) {
			fprintf(stderr, "error: the %s is not a directory\n", folder);
			return -1;
		}

		if (cfg->icons_folder)
			free(cfg->icons_folder);
		cfg->icons_folder = strdup(folder);

	} else if (strcasecmp(name, "conf_name") == 0) {
		if (cfg->conf_name) {
			free(cfg->conf_name);
			cfg->conf_name = NULL;
		}

		if (value && *value)
			cfg->conf_name = strdup(value);
	} else {
		qtn_error("unknown option: %s", name);
		return -1;
	}

	return 0;
}

const char *qtn_config_get_option(const char *name)
{
	const char *value = NULL;
	struct qtn_config *cfg = &g_qtn_config;

	if (!name || !name[0])
		return NULL;

	if (strcasecmp(name, "icons_folder") == 0)
		value = cfg->icons_folder;
	else if (strcasecmp(name, "conf_name") == 0)
		value = cfg->conf_name;
	else
		qtn_error("unknown option: %s", name);

	return value;
}

const struct qtn_config *qtn_config_get()
{
	struct qtn_config *cfg = &g_qtn_config;
	return cfg;
}

void qtn_config_print()
{
	struct qtn_config *cfg = &g_qtn_config;

	fprintf(stderr, "info: listener port: %d\n", cfg->lsn_port);

	fprintf(stderr, "info: listener address: %s\n", inet_ntoa(cfg->lsn_addr));

	if (cfg->lsn_iface[0]) {
		fprintf(stderr, "info: listener interface: %s\n", cfg->lsn_iface);
	}

	fprintf(stderr, "info: DUT protocol: %s\n", cfg->dut_proto);

	if (strcasecmp(cfg->dut_proto, "raw") == 0) {
		fprintf(stderr, "info: DUT interface: %s\n", cfg->dut_iface);
		fprintf(stderr, "info: DUT macaddr: %02x:%02x:%02x:%02x:%02x:%02x\n",
			cfg->dut_mac[0], cfg->dut_mac[1], cfg->dut_mac[2],
			cfg->dut_mac[3], cfg->dut_mac[4], cfg->dut_mac[5]);

	} else if (strcasecmp(cfg->dut_proto, "tcp") == 0
			|| strcasecmp(cfg->dut_proto, "udp") == 0) {

		fprintf(stderr, "info: DUT address: %s\n", cfg->dut_addr);
	}
}

int qtn_config_check()
{
	struct qtn_config *cfg = &g_qtn_config;

	if ((cfg->lsn_addr.s_addr == 0) && (*cfg->lsn_iface == 0)) {
		fprintf(stderr, "error: listener address is not set\n");
		return -1;
	}

	if (*cfg->dut_proto == 0) {
		fprintf(stderr, "error: DUT protocol is not set\n");
		return -1;
	}

	return 0;
}

void qtn_config_cleanup()
{
	struct qtn_config *cfg = &g_qtn_config;

	if (cfg->icons_folder) {
		free(cfg->icons_folder);
		cfg->icons_folder = NULL;
	}

	if (cfg->conf_name) {
		free(cfg->conf_name);
		cfg->conf_name = NULL;
	}

}
