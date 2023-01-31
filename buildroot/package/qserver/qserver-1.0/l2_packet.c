/*
 * WPA Supplicant - Layer2 packet handling with Linux packet sockets
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
 */

#include "eloop.h"
#include "l2_packet.h"


struct l2_packet_data {
	int fd; /* packet socket for EAPOL frames */
	char ifname[IFNAMSIZ + 1];
	int ifindex;
	uint8_t own_addr[ETH_ALEN];
	void (*rx_callback)(void *ctx, const uint8_t *src_addr,
			    const uint8_t *buf, size_t len);
	void *rx_callback_ctx;
	int l2_hdr; /* whether to include layer 2 (Ethernet) header data
		     * buffers */
};


int l2_packet_get_own_addr(struct l2_packet_data *l2, uint8_t *addr)
{
	memcpy(addr, l2->own_addr, ETH_ALEN);
	return 0;
}


int l2_packet_send(struct l2_packet_data *l2, const uint8_t *dst_addr, uint16_t proto,
		   const uint8_t *buf, size_t len)
{
	int ret;
	if (l2 == NULL)
		return -1;
	if (l2->l2_hdr) {
		ret = send(l2->fd, buf, len, 0);
		if (ret < 0)
			os_fprintf(stderr, "l2_packet_send - send: %s\n",
				   strerror(errno));
	} else {
		struct sockaddr_ll ll;
		memset(&ll, 0, sizeof(ll));
		ll.sll_family = AF_PACKET;
		ll.sll_ifindex = l2->ifindex;
		ll.sll_protocol = htons(proto);
		ll.sll_halen = ETH_ALEN;
		memcpy(ll.sll_addr, dst_addr, ETH_ALEN);
		ret = sendto(l2->fd, buf, len, 0, (struct sockaddr *) &ll,
			     sizeof(ll));
		if (ret < 0) {
			os_fprintf(stderr, "l2_packet_send - sendto: %s\n",
				   strerror(errno));
		}
	}
	return ret;
}


static void l2_packet_receive(int sock, void *eloop_ctx, void *sock_ctx UNUSED_PARAM)
{
	struct l2_packet_data *l2 = eloop_ctx;
	uint8_t buf[2300];
	int res;
	struct sockaddr_ll ll;
	socklen_t fromlen;

	memset(&ll, 0, sizeof(ll));
	fromlen = sizeof(ll);
	res = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *) &ll,
		       &fromlen);
	if (res < 0) {
		os_fprintf(stderr, "l2_packet_receive - recvfrom: %s\n",
			   strerror(errno));
		return;
	}

	l2->rx_callback(l2->rx_callback_ctx, ll.sll_addr, buf, res);
}


struct l2_packet_data * l2_packet_init(
	const char *ifname, const uint8_t *own_addr UNUSED_PARAM, unsigned short protocol,
	void (*rx_callback)(void *ctx, const uint8_t *src_addr,
			    const uint8_t *buf, size_t len),
	void *rx_callback_ctx, int l2_hdr)
{
	struct l2_packet_data *l2;
	struct ifreq ifr;
	struct sockaddr_ll ll;

	l2 = os_zalloc(sizeof(struct l2_packet_data));
	if (l2 == NULL)
		return NULL;
	strlcpy(l2->ifname, ifname, sizeof(l2->ifname));
	l2->rx_callback = rx_callback;
	l2->rx_callback_ctx = rx_callback_ctx;
	l2->l2_hdr = l2_hdr;

	l2->fd = socket(PF_PACKET, l2_hdr ? SOCK_RAW : SOCK_DGRAM,
			htons(protocol));
	if (l2->fd < 0) {
		os_fprintf(stderr, "%s: socket(PF_PACKET): %s\n",
			   __func__, strerror(errno));
		free(l2);
		return NULL;
	}
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, l2->ifname, sizeof(ifr.ifr_name));
	if (ioctl(l2->fd, SIOCGIFINDEX, &ifr) < 0) {
		os_fprintf(stderr, "%s: ioctl[SIOCGIFINDEX]: %s\n",
			   __func__, strerror(errno));
		close(l2->fd);
		free(l2);
		return NULL;
	}
	l2->ifindex = ifr.ifr_ifindex;

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_ifindex = ifr.ifr_ifindex;
	ll.sll_protocol = htons(protocol);
	if (bind(l2->fd, (struct sockaddr *) &ll, sizeof(ll)) < 0) {
		os_fprintf(stderr, "%s: bind[PF_PACKET]: %s\n",
			   __func__, strerror(errno));
		close(l2->fd);
		free(l2);
		return NULL;
	}

	if (ioctl(l2->fd, SIOCGIFHWADDR, &ifr) < 0) {
		os_fprintf(stderr, "%s: ioctl[SIOCGIFHWADDR]: %s\n",
			   __func__, strerror(errno));
		close(l2->fd);
		free(l2);
		return NULL;
	}
	memcpy(l2->own_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	eloop_register_read_sock(l2->fd, l2_packet_receive, l2, NULL);

	return l2;
}


void l2_packet_deinit(struct l2_packet_data *l2)
{
	if (l2 == NULL)
		return;

	if (l2->fd >= 0) {
		eloop_unregister_read_sock(l2->fd);
		close(l2->fd);
	}

	free(l2);
}


int l2_packet_get_ip_addr(struct l2_packet_data *l2, char *buf, size_t len)
{
	int s;
	struct ifreq ifr;
	struct sockaddr_in *saddr;
	size_t res;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		os_fprintf(stderr, "%s: socket: %s\n",
			   __func__, strerror(errno));
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, l2->ifname, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		if (errno != EADDRNOTAVAIL)
			os_fprintf(stderr, "%s: ioctl[SIOCGIFADDR]: %s\n",
				   __func__, strerror(errno));
		close(s);
		return -1;
	}
	close(s);
	saddr = aliasing_hide_typecast(&ifr.ifr_addr, struct sockaddr_in);
	if (saddr->sin_family != AF_INET)
		return -1;
	res = strlcpy(buf, inet_ntoa(saddr->sin_addr), len);
	if (res >= len)
		return -1;
	return 0;
}


