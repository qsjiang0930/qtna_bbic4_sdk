/*
 * WPA Supplicant - Layer2 packet interface definition
 * Copyright (c) 2003-2005, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 *
 */

#ifndef L2_PACKET_H
#define L2_PACKET_H

#include "commons.h"
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <netinet/if_ether.h>


/**
 * struct l2_packet_data - Internal l2_packet data structure
 *
 * This structure is used by the l2_packet implementation to store its private
 * data. Other files use a pointer to this data when calling the l2_packet
 * functions, but the contents of this structure should not be used directly
 * outside l2_packet implementation.
 */
struct l2_packet_data;

struct l2_ethhdr {
	uint8_t h_dest[ETH_ALEN];
	uint8_t h_source[ETH_ALEN];
	uint16_t h_proto;
} __attribute__ ((packed));


/**
 * l2_packet_init - Initialize l2_packet interface
 * @ifname: Interface name
 * @own_addr: Optional own MAC address if available from driver interface or
 *	%NULL if not available
 * @protocol: Ethernet protocol number in host byte order
 * @rx_callback: Callback function that will be called for each received packet
 * @rx_callback_ctx: Callback data (ctx) for calls to rx_callback()
 * @l2_hdr: 1 = include layer 2 header, 0 = do not include header
 * Returns: Pointer to internal data or %NULL on failure
 *
 * rx_callback function will be called with src_addr pointing to the source
 * address (MAC address) of the the packet. If l2_hdr is set to 0, buf
 * points to len bytes of the payload after the layer 2 header and similarly,
 * TX buffers start with payload. This behavior can be changed by setting
 * l2_hdr=1 to include the layer 2 header in the data buffer.
 */
struct l2_packet_data * l2_packet_init(
	const char *ifname, const uint8_t *own_addr, unsigned short protocol,
	void (*rx_callback)(void *ctx, const uint8_t *src_addr,
			    const uint8_t *buf, size_t len),
	void *rx_callback_ctx, int l2_hdr);

/**
 * l2_packet_deinit - Deinitialize l2_packet interface
 * @l2: Pointer to internal l2_packet data from l2_packet_init()
 */
void l2_packet_deinit(struct l2_packet_data *l2);

/**
 * l2_packet_get_own_addr - Get own layer 2 address
 * @l2: Pointer to internal l2_packet data from l2_packet_init()
 * @addr: Buffer for the own address (6 bytes)
 * Returns: 0 on success, -1 on failure
 */
int l2_packet_get_own_addr(struct l2_packet_data *l2, uint8_t *addr);

/**
 * l2_packet_send - Send a packet
 * @l2: Pointer to internal l2_packet data from l2_packet_init()
 * @dst_addr: Destination address for the packet (only used if l2_hdr == 0)
 * @proto: Protocol/ethertype for the packet in host byte order (only used if
 * l2_hdr == 0)
 * @buf: Packet contents to be sent; including layer 2 header if l2_hdr was
 * set to 1 in l2_packet_init() call. Otherwise, only the payload of the packet
 * is included.
 * @len: Length of the buffer (including l2 header only if l2_hdr == 1)
 * Returns: >=0 on success, <0 on failure
 */
int l2_packet_send(struct l2_packet_data *l2, const uint8_t *dst_addr, uint16_t proto,
		   const uint8_t *buf, size_t len);

/**
 * l2_packet_get_ip_addr - Get the current IP address from the interface
 * @l2: Pointer to internal l2_packet data from l2_packet_init()
 * @buf: Buffer for the IP address in text format
 * @len: Maximum buffer length
 * Returns: 0 on success, -1 on failure
 *
 * This function can be used to get the current IP address from the interface
 * bound to the l2_packet. This is mainly for status information and the IP
 * address will be stored as an ASCII string. This function is not essential
 * for %wpa_supplicant operation, so full implementation is not required.
 * l2_packet implementation will need to define the function, but it can return
 * -1 if the IP address information is not available.
 */
int l2_packet_get_ip_addr(struct l2_packet_data *l2, char *buf, size_t len);


#endif /* L2_PACKET_H */
