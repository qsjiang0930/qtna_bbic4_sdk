/**
 * Copyright (c) 2014 - 2017 Quantenna Communications Inc
 * All Rights Reserved
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
 **/

#ifndef __QTN_WOWLAN_H__
#define __QTN_WOWLAN_H__

#include <qtn/qtn_net_packet.h>
#define WOWLAN_MATCH_TYPE_DEFAULT	0
#define WOWLAN_MATCH_TYPE_L2		1
#define WOWLAN_MATCH_TYPE_UDP		2

#ifndef IEEE80211_ADDR_BCAST
#define	IEEE80211_ADDR_BCAST(a)	((a)[0] == 0xff && (a)[1] == 0xff && (a)[2] == 0xff && \
					(a)[3] == 0xff && (a)[4] == 0xff && (a)[5] == 0xff)
#endif
RUBY_INLINE uint16_t get_udp_dst_port(const void *iphdr)
{
	const struct qtn_ipv4 *ipv4 = (const struct qtn_ipv4 *)iphdr;
	const uint8_t proto = ipv4->proto;

	if (proto == QTN_IP_PROTO_UDP) {
		const struct qtn_udp *udp = (struct qtn_udp *)((uint8_t *)ipv4 + sizeof(struct qtn_ipv4));
		return udp->dst_port;
	}
	return 0;
}

RUBY_INLINE uint8_t wowlan_is_magic_packet(uint16_t ether_type, const void *eth_hdr, const void *iphdr,
		uint16_t wowlan_match_type, uint16_t config_ether_type, uint16_t config_udp_port)
{
	const struct ether_header *eh = (struct ether_header *)eth_hdr;

	if (wowlan_match_type == WOWLAN_MATCH_TYPE_DEFAULT) {
		if (IEEE80211_ADDR_BCAST(eh->ether_dhost))/*broadcast*/
			return 1;
		if (ether_type == htons(ETHERTYPE_WAKE_ON_LAN))/* ehter type is 0x0842*/
			return 1;
		if (ether_type == htons(ETHERTYPE_IP)) {
			uint16_t udp_dst = get_udp_dst_port(iphdr);
			if (udp_dst == htons(7) || udp_dst == htons(9))
				return 1;
		}
	} else if (wowlan_match_type == WOWLAN_MATCH_TYPE_L2) {
		if (ether_type == htons(config_ether_type))/* ehter type is 0x0842 or user defined*/
			return 1;
	} else if (wowlan_match_type == WOWLAN_MATCH_TYPE_UDP) {
		if (ether_type == htons(ETHERTYPE_IP)) {
			uint16_t udp_dst = get_udp_dst_port(iphdr);
			if (((config_udp_port == 0xffff) && (udp_dst == htons(7) || udp_dst == htons(9))) ||
						(udp_dst == htons(config_udp_port)))
				return 1;

		}
	}

	return 0;
}
#endif
