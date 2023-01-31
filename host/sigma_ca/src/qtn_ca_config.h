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

#include <stdint.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_ether.h>

struct qtn_config {
	char lsn_iface[IFNAMSIZ];
	uint16_t lsn_port;
	struct in_addr lsn_addr;
	char dut_proto[4];
	char dut_iface[IFNAMSIZ];
	uint8_t dut_mac[ETH_ALEN];
	char dut_addr[32];
	char *conf_name;
	char *icons_folder;
};

void qtn_config_init();
int qtn_config_set_listener_options(const char *addr, const char *port);
int qtn_config_set_dut_options(const char *str);
int qtn_config_set_option(const char *name, const char *value);
void qtn_config_print();
int qtn_config_check();
void qtn_config_cleanup();

const struct qtn_config *qtn_config_get();
const char *qtn_config_get_option(const char *name);
