/**
 * Copyright (c) 2016 Quantenna Communications, Inc.
 * All rights reserved.
 **/

#include <arpa/inet.h>
#include <errno.h>
#include <linux/filter.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ql2t.h"

#define ql2t_err(format, ...)	do {							\
					ql2t_p_log("%s: ERR: " format "\n", __func__,	\
						##__VA_ARGS__);				\
				} while (0)

#ifdef DEBUG
#define ql2t_out(format, ...)	do {							\
					ql2t_p_log("%s: " format "\n", __func__,	\
						##__VA_ARGS__);				\
				} while (0)
#else
#define ql2t_out(format, ...)
#endif

#define MIN(x, y)		(x) < (y) ? (x) : (y)

#define QL2T_RETRY_COUNT	5

typedef enum {
	QL2T_FRAG_STATE_FIRST	= 1,
	QL2T_FRAG_STATE_NEXT	= 2,
	QL2T_FRAG_STATE_IGNORE	= 3,
	QL2T_FRAG_STATE_DONE	= 4
} ql2t_frag_state;

/* TBD: RPC also uses the same; can we club? */
#if 1
#define ETH_P_OUI_EXT		0x88BF
#define QUANTENNA_OUI		0x002686
#define QL2T_RAW_SOCK_PROT	33

struct q_raw_ethoui_hdr {
	struct ethhdr	eth_hdr;
	uint8_t		prot_id[5];
	uint8_t		_pad1;
} __attribute__ ((packed));
#endif

typedef struct {
	struct q_raw_ethoui_hdr	eth_oui_hdr;
	__be16			src_end_pt;
	__be16			dst_end_pt;
	unsigned char		id;		/* Unique id to identify the client request the
						   fragment belongs to */
	unsigned char		tot_frag;	/* 1 less than the total fragments needed for a
						   client request */
	unsigned char		rem_frag;	/* 0 => only or last fragment */
	unsigned char		_pad1;
	unsigned short		len;		/* Length of the payload */
} __attribute__ ((packed)) ql2t_eth_hdr;

typedef struct {
	ql2t_eth_hdr		hdr;
	char			payload[ETH_FRAME_LEN - sizeof(ql2t_eth_hdr)];
} __attribute__ ((packed)) ql2t_eth_pkt;

typedef struct {
	char			local_if_name[IFNAMSIZ];	/* Local interface name; eg: host0,
								   pcie0 */
	unsigned short		local_end_pt;

	/* Internal variables */
	int			local_if_index;
	unsigned char		local_mac_addr[ETH_ALEN];
	int			fd_raw_sock;
	unsigned char		id;				/* Used to id the client request in
								   the packet */
	ql2t_eth_pkt		tx_pkt;
	ql2t_eth_pkt		rx_pkt;
#define QL2T_INVALID_ID		0xFF
	unsigned char		rx_last_id;
#define QL2T_INVALID_REM_FRAG	0xFF
	unsigned char		rx_last_rem_frag;
} ql2t_socket;

typedef struct {
#define lock(x)			pthread_mutex_lock(x)
#define unlock(x)		pthread_mutex_unlock(x)
	pthread_mutex_t		mutex;
#define QL2T_MAX_SOCKET		5 /* Should be atleast 1 */
	ql2t_socket		*list[QL2T_MAX_SOCKET];
} ql2t_state;

static ql2t_state state =	{
					.mutex = PTHREAD_MUTEX_INITIALIZER,
				};
/*
 * Internal functions
 */
static void ql2t_p_log(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	/* TBD: Extend this to support log file, syslog, etc (if needed) */
	vfprintf(stdout, format, args);
	va_end(args);
}

/* For debugging */
#ifdef DUMP_PKT
static void ql2t_p_dump_packet(ql2t_eth_pkt *pkt)
{
	ql2t_out("\n"
		"\th_dest    : %02x:%02x:%02x:%02x:%02x:%02x\n"
		"\th_source  : %02x:%02x:%02x:%02x:%02x:%02x\n"
		"\th_proto   : 0x%x\n"
		"\tprot_id   : 0x%02x 0x%02x 0x%02x 0x%02x %u\n"
		"\tsrc_end_pt: %02d\n"
		"\tdst_end_pt: %02d\n"
		"\tid        : %02d\n"
		"\ttot_frag  : %02d\n"
		"\trem_frag  : %02d\n"
		"\tlen       : %d\n"
		"\tpayload   : %c\n",
		pkt->hdr.eth_oui_hdr.eth_hdr.h_dest[0],
		pkt->hdr.eth_oui_hdr.eth_hdr.h_dest[1],
		pkt->hdr.eth_oui_hdr.eth_hdr.h_dest[2],
		pkt->hdr.eth_oui_hdr.eth_hdr.h_dest[3],
		pkt->hdr.eth_oui_hdr.eth_hdr.h_dest[4],
		pkt->hdr.eth_oui_hdr.eth_hdr.h_dest[5],
		pkt->hdr.eth_oui_hdr.eth_hdr.h_source[0],
		pkt->hdr.eth_oui_hdr.eth_hdr.h_source[1],
		pkt->hdr.eth_oui_hdr.eth_hdr.h_source[2],
		pkt->hdr.eth_oui_hdr.eth_hdr.h_source[3],
		pkt->hdr.eth_oui_hdr.eth_hdr.h_source[4],
		pkt->hdr.eth_oui_hdr.eth_hdr.h_source[5],
		ntohs(pkt->hdr.eth_oui_hdr.eth_hdr.h_proto),
		pkt->hdr.eth_oui_hdr.prot_id[0],
		pkt->hdr.eth_oui_hdr.prot_id[1],
		pkt->hdr.eth_oui_hdr.prot_id[2],
		pkt->hdr.eth_oui_hdr.prot_id[3],
		pkt->hdr.eth_oui_hdr.prot_id[4],
		ntohs(pkt->hdr.src_end_pt),
		ntohs(pkt->hdr.dst_end_pt),
		pkt->hdr.id,
		pkt->hdr.tot_frag,
		pkt->hdr.rem_frag,
		ntohs(pkt->hdr.len),
		pkt->payload[0]);
}
#endif

static int ql2t_p_recv_set_prot_filter(int fd_sock, unsigned short local_end_pt)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD + BPF_H + BPF_ABS, ETH_ALEN * 2),	/* Load h_proto (16-bits) */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
			ETH_P_OUI_EXT, 0, 7),				/* Check if ETH_P_OUT_EXT */

		BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ETH_HLEN),		/* If true, load prot_id[0] to
									   prot_id[3] (32-bits) */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
			QUANTENNA_OUI << 8, 0, 5),			/* Check if QUANTENNA_OUI */

		BPF_STMT(BPF_LD + BPF_B + BPF_ABS, ETH_HLEN + 4),	/* If true, load proto_id[4]
									   (8-bits) */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
			QL2T_RAW_SOCK_PROT, 0, 3),			/* Check if QL2T_RAW_SOCK_PROT */

		BPF_STMT(BPF_LD + BPF_H + BPF_ABS, ETH_HLEN + 8),	/* If true, load dst_end_pt
									   (16-bits) */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
			local_end_pt, 0, 1),				/* Check if 'local_end_pt' */

		BPF_STMT(BPF_RET + BPF_K, ETH_FRAME_LEN),		/* Accept the packet */
		BPF_STMT(BPF_RET + BPF_K, 0)				/* Ignore the packet */
	};
	struct sock_fprog fp;

	fp.filter = filter;
	fp.len = sizeof(filter) / sizeof(filter[0]);

	if (setsockopt(fd_sock, SOL_SOCKET, SO_ATTACH_FILTER, &fp, sizeof(fp)) == -1) {
		ql2t_err("setsockopt (SO_ATTACH_FILTER) failed, err = %d", -errno);
		return -errno;
	}

	return 0;

}

#define QL2T_ARRAY_SIZE(x)	(sizeof(x) / sizeof(x[0]))

static int ql2t_p_list_add_socket(ql2t_socket *sock)
{
	unsigned int count = QL2T_ARRAY_SIZE(state.list);

	while (count) {
		--count;
		if (!state.list[count]) {
			state.list[count] = sock;
			return 0;
		}
	}

	ql2t_err("No memory to add more sockets, err = %d", -ENOMEM);
	return -ENOMEM;
}

static int ql2t_p_list_del_socket(ql2t_socket *sock)
{
	unsigned int count = QL2T_ARRAY_SIZE(state.list);

	while (count) {
		--count;
		if (state.list[count] == sock) {
			state.list[count] = NULL;
			return 0;
		}
	}

	ql2t_err("Invalid socket, err = %d", -EINVAL);
	return -EINVAL;
}

static ql2t_socket *ql2t_p_list_find_socket(int fd_raw_sock)
{
	unsigned int count = QL2T_ARRAY_SIZE(state.list);

	while (count) {
		--count;
		if (state.list[count] && state.list[count]->fd_raw_sock == fd_raw_sock) {
			return state.list[count];
		}
	}

	ql2t_err("Invalid socket, returning NULL");
	return NULL;
}

static void ql2t_p_free_socket(ql2t_socket *sock)
{
	if (!sock)
		return;

	if (sock->fd_raw_sock != -1)
		close(sock->fd_raw_sock);

	free(sock);
}

int ql2t_p_recv(ql2t_socket *sock, char timeout)
{
	int retval, retry;

	if (timeout) {
		/* Wait until something happens or timeout */
		retry = QL2T_RETRY_COUNT;

		do {
			fd_set rfds;
			struct timeval tv;

			FD_ZERO(&rfds);
			FD_SET(sock->fd_raw_sock, &rfds);

			/*
			 * ql2t_send() breaks and sends one fragment after another for one request;
			 * adding a timeout here in case the next fragment does not arrive
			 */
			tv.tv_sec = 1;
			tv.tv_usec = 0;

			retval = select(sock->fd_raw_sock + 1, &rfds, NULL, NULL, &tv);

		} while ((retval == -1) && (errno == EINTR) && retry--);

		if (retry < 0) {
			ql2t_err("select() retry exceeded (%u), err = %d", QL2T_RETRY_COUNT,
				-EAGAIN);
			return -EAGAIN;
		}

		if (retval == -1) {
			ql2t_err("select() failed, err = %d", -errno);
			return -errno;
		}

		if (retval == 0) {
			ql2t_err("select() timedout, err = %d", -EAGAIN);
			return -EAGAIN;
		}
	}

	/* Receive the packet */
	retry = QL2T_RETRY_COUNT;

	do {
		retval = recvfrom(sock->fd_raw_sock, &sock->rx_pkt, sizeof(sock->rx_pkt), 0, NULL,
			NULL);

	} while ((retval == -1) && (errno == EINTR) && retry--);

	if (retry < 0) {
		ql2t_err("recvfrom() retry exceeded (%u), err = %d", QL2T_RETRY_COUNT, -EAGAIN);
		return -EAGAIN;
	}

	if (retval == -1) {
		ql2t_err("recv_from() failed, err = %d", -errno);
		return -errno;
	} else if (retval < sizeof(ql2t_eth_hdr)) {
		ql2t_err("Received less than ql2t packet header size (e = %ld, a = %d), err = %d",
			sizeof(ql2t_eth_hdr), retval, -EIO);
		return -EIO;
	/*
	 * To prevent runt frames, the L2 layer could send more data than what the user intended;
	 * in all cases sock->rx_pkt.hdr.len denotes the actual len of user data
	 */
	} else if (retval - sizeof(ql2t_eth_hdr) < ntohs(sock->rx_pkt.hdr.len)) {
		ql2t_err("Received less payload than expected (e = %ld, a = %d), err = %d",
			ntohs(sock->rx_pkt.hdr.len), retval - sizeof(ql2t_eth_hdr), -EIO);
		return -EIO;
	}

#ifdef DUMP_PKT
	ql2t_p_dump_packet(&sock->rx_pkt);
#endif

	return 0;
}

static int ql2t_p_copy_pkt(char dst_buf[], unsigned short dst_len, char src_buf[],
	unsigned short src_len)
{
	if (dst_len < src_len) {
		ql2t_err("Insufficient buffer provided... discarding data\n");
		return -EINVAL;
	}

	memcpy(dst_buf, src_buf, src_len);
	return 0;
}

int ql2t_p_frag_first(ql2t_socket *sock, char data[], unsigned short len,
	unsigned short *len_copied, ql2t_frag_state *frag_state)
{
	int retval = 0;
	ql2t_eth_pkt *pkt = &sock->rx_pkt;

	/* In case we have not received the first fragment */
	if (pkt->hdr.tot_frag != pkt->hdr.rem_frag) {
		ql2t_err("Not the first fragment... id = %d, total_frag = %d, rem_frag = %d\n",
			pkt->hdr.id, pkt->hdr.tot_frag, pkt->hdr.rem_frag);

		if (!pkt->hdr.rem_frag) {
			/* Error, terminate the state machine */
			*frag_state = QL2T_FRAG_STATE_DONE;
			return -EIO;
		}

		*frag_state = QL2T_FRAG_STATE_IGNORE;
		return 0;
	}

	/* Copy the fragment */
	retval = ql2t_p_copy_pkt(data, len, pkt->payload, ntohs(pkt->hdr.len));
	if (retval) {
		/* Error, terminate the state machine */
		*frag_state = QL2T_FRAG_STATE_DONE;
		return retval;
	}

	*len_copied = ntohs(pkt->hdr.len);

	/* In case there are no more fragments */
	if (!pkt->hdr.rem_frag) {
		/* Copied all the fragments, terminate the state machine */
		*frag_state = QL2T_FRAG_STATE_DONE;
		return 0;
	}

	sock->rx_last_id = pkt->hdr.id;
	sock->rx_last_rem_frag = pkt->hdr.rem_frag;

	*frag_state = QL2T_FRAG_STATE_NEXT;

	return 0;
}

int ql2t_p_frag_next(ql2t_socket *sock, char data[], unsigned short len,
	unsigned short *len_copied, ql2t_frag_state *frag_state)
{
	int retval;
	ql2t_eth_pkt *pkt = &sock->rx_pkt;

	retval = ql2t_p_recv(sock, 1);
	if (retval) {
		/* Error, terminate the state machine */
		*frag_state = QL2T_FRAG_STATE_DONE;
		return retval;
	}

	/* In case the current fragment is from another id */
	if (pkt->hdr.id != sock->rx_last_id) {
		*frag_state = QL2T_FRAG_STATE_FIRST;
		return 0;
	}

	/* In case we have missed one of more fragments */
	if (pkt->hdr.rem_frag != sock->rx_last_rem_frag - 1) {
		ql2t_err("Missed a fragment... id = %d, last_rem_frag = %d, rem_flag = %d\n",
			pkt->hdr.id, sock->rx_last_rem_frag, pkt->hdr.rem_frag);
		*frag_state = QL2T_FRAG_STATE_IGNORE;
		return 0;
	}

	/* Copy the fragment */
	retval = ql2t_p_copy_pkt(data + *len_copied, len - *len_copied, pkt->payload, ntohs(pkt->hdr.len));
	if (retval) {
		/* Error, terminate the state machine */
		*frag_state = QL2T_FRAG_STATE_DONE;
		return retval;
	}

	*len_copied += ntohs(pkt->hdr.len);

	/* In case there are no more fragments */
	if (!pkt->hdr.rem_frag) {
		/* Copied all the fragments, terminate the state machine */
		*frag_state = QL2T_FRAG_STATE_DONE;
		return retval;
	}

	--sock->rx_last_rem_frag;

	return 0;
}

int ql2t_p_frag_ignore(ql2t_socket *sock, ql2t_frag_state *frag_state)
{
	int retval;
	ql2t_eth_pkt *pkt = &sock->rx_pkt;

	retval = ql2t_p_recv(sock, 1);
	if (retval) {
		/* Error, terminate the state machine */
		*frag_state = QL2T_FRAG_STATE_DONE;
		return retval;
	}

	/* In case the fragment is from another id */
	if (pkt->hdr.id != sock->rx_last_id) {
		*frag_state = QL2T_FRAG_STATE_FIRST;
		return retval;
	}

	/* In case the fragment is the last one to ignore */
	if (!pkt->hdr.rem_frag) {
		/* Ignored all the fragments, terminate the state machine */
		*frag_state = QL2T_FRAG_STATE_DONE;
		return -EIO;
	}

	return retval;
}

/*
 * Exported functions
 */
int ql2t_open(const char local_if_name[], unsigned short local_end_pt)
{
	int retval = 0;
	ql2t_socket *sock;
	struct ifreq if_request;
	struct sockaddr_ll addr;

	sock = calloc(1, sizeof(*sock));
	if (!sock) {
		ql2t_err("calloc() failed to allocate %u bytes, err = %d", sizeof(*sock), -ENOMEM);
		retval = -ENOMEM;
		goto out;
	}

	sock->fd_raw_sock = -1;

	strncpy(sock->local_if_name, local_if_name, sizeof(sock->local_if_name) - 1);
	sock->local_end_pt = local_end_pt;

	sock->fd_raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_OUI_EXT));
	if (sock->fd_raw_sock == -1) {
		ql2t_err("socket() failed, err = %d", -errno);
		retval = -errno;
		goto out;
	}

	/* Get the index of the interface */
	memset(&if_request, 0, sizeof(if_request));
	strncpy(if_request.ifr_name, sock->local_if_name, sizeof(if_request.ifr_name) - 1);

	if (ioctl(sock->fd_raw_sock, SIOCGIFINDEX, &if_request) == -1) {
		ql2t_err("ioctl (SIOCGIFINDEX) failed; err = %d", -errno);
		retval = -errno;
		goto out;
	}

	sock->local_if_index = if_request.ifr_ifindex;

	/* Get the MAC address of the interface */
	if (ioctl(sock->fd_raw_sock, SIOCGIFHWADDR, &if_request) == -1) {
		ql2t_err("ioctl (SIOCGIFHWADDR) failed; err = %d", -errno);
		retval = -errno;
		goto out;
	}

	memcpy(sock->local_mac_addr, if_request.ifr_hwaddr.sa_data, ETH_ALEN);

	/*
	 * Size of payload is 1484 bytes
	 * So, for 65535 bytes (max data that QL2T is designed to handle), we would need 45
	 * fragments
	 *
	 * Size of each sbk is 4224 bytes (holds 1 fragment)
	 * So, at max, we would need 45 * 4224 = 190,080 bytes socket rx buffer; hence we are
	 * using QL2T_SOCK_RX_BUF_SIZE (kernel would allocate QL2T_SOCK_RX_BUF_SIZE * 2 bytes)
	 */
#define QL2T_SOCK_RX_BUF_SIZE	(100 * 1024)
	int rmem_max = QL2T_SOCK_RX_BUF_SIZE;
	if (setsockopt(sock->fd_raw_sock, SOL_SOCKET, SO_RCVBUFFORCE, &rmem_max,
		sizeof(rmem_max)) == -1) {
		ql2t_err("setsockopt (SO_RCVBUFFORCE) failed, err = %d", -errno);
		retval = -errno;
		goto out;
	}

	retval = ql2t_p_recv_set_prot_filter(sock->fd_raw_sock, sock->local_end_pt);
	if (retval != 0) {
		goto out;
	}

	/*
	 * Assign a name to the socket - to bind a socket to an interface (needed only to receive
	 * data)
	 */
	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_OUI_EXT);
	addr.sll_ifindex = sock->local_if_index;

	if (bind(sock->fd_raw_sock, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		ql2t_err("bind() failed, err = %d", -errno);
		retval = -errno;
		goto out;
	}

	lock(&state.mutex);
	retval = ql2t_p_list_add_socket(sock);
	unlock(&state.mutex);

	if (retval != 0)
		goto out;

	return sock->fd_raw_sock;

out:
	ql2t_p_free_socket(sock);

	return retval;
}

void ql2t_close(int fd_raw_sock)
{
	ql2t_socket *sock;

	lock(&state.mutex);

	sock = ql2t_p_list_find_socket(fd_raw_sock);
	if (!sock) {
		ql2t_err("Invalid socket, err = %d", -EINVAL);
		unlock(&state.mutex);
		return;
	}

	ql2t_p_list_del_socket(sock);

	unlock(&state.mutex);

	ql2t_p_free_socket(sock);
}

unsigned short ql2t_get_max_data_len()
{
	return (sizeof(ql2t_eth_pkt) - sizeof(ql2t_eth_hdr));
}

int ql2t_send(int fd_raw_sock, const ql2t_send_cfg *cfg, const char data[], unsigned short len)
{
	unsigned char rem_frag;
	unsigned short pkt_len;
	int bytes_sent, retval = 0, retry = QL2T_RETRY_COUNT;
	ql2t_eth_pkt *pkt;
	ql2t_socket *sock;
	struct sockaddr_ll addr;

	lock(&state.mutex);

	sock = ql2t_p_list_find_socket(fd_raw_sock);
	if (!sock) {
		ql2t_err("Invalid socket, err = %d", -EINVAL);
		retval = -EINVAL;
		goto out;
	}

	if (!cfg) {
		ql2t_err("cfg is NULL, err = %d", -EINVAL);
		retval = -EINVAL;
		goto out;
	}

	if (!data) {
		ql2t_err("data is NULL, err = %d", -EINVAL);
		retval = -EINVAL;
		goto out;
	}

	if (!len) {
		ql2t_err("len is 0, err = %d", -EINVAL);
		retval = -EINVAL;
		goto out;
	}

	pkt = &sock->tx_pkt;

	/* Setup addr to send the packet */
	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_OUI_EXT);
	addr.sll_ifindex = sock->local_if_index;
	addr.sll_halen = ETH_ALEN;
	memcpy(addr.sll_addr, cfg->remote_mac_addr, ETH_ALEN);

	/* Setup the Ethernet header */
	memcpy(pkt->hdr.eth_oui_hdr.eth_hdr.h_dest, cfg->remote_mac_addr, ETH_ALEN);
	memcpy(pkt->hdr.eth_oui_hdr.eth_hdr.h_source, sock->local_mac_addr, ETH_ALEN);
	pkt->hdr.eth_oui_hdr.eth_hdr.h_proto = htons(ETH_P_OUI_EXT);

	/* Setup the Ethernet OUI header */
	pkt->hdr.eth_oui_hdr.prot_id[0] = QUANTENNA_OUI >> 16;
	pkt->hdr.eth_oui_hdr.prot_id[1] = QUANTENNA_OUI >> 8;
	pkt->hdr.eth_oui_hdr.prot_id[2] = QUANTENNA_OUI & 0xFF;
	pkt->hdr.eth_oui_hdr.prot_id[3] = 0;
	pkt->hdr.eth_oui_hdr.prot_id[4] = QL2T_RAW_SOCK_PROT;

	/* Setup the QMA packet header and payload */
	pkt->hdr.src_end_pt = htons(sock->local_end_pt);
	pkt->hdr.dst_end_pt = htons(cfg->remote_end_pt);

	pkt->hdr.id = sock->id++;
	if (sock->id == QL2T_INVALID_ID)
		sock->id = 0;

	if (len <= sizeof(pkt->payload))
		rem_frag = 0;
	else
		rem_frag = len / sizeof(pkt->payload);

	ql2t_out("len to send = %d, max payload len = %ld, rem_frag = %d", len,
		sizeof(pkt->payload), rem_frag);

	pkt->hdr.tot_frag = rem_frag;

	do {
		pkt->hdr.rem_frag = rem_frag;

		pkt_len = MIN(len, sizeof(pkt->payload));
		memcpy(pkt->payload, data, pkt_len);
		pkt->hdr.len = htons(pkt_len);

		len -= pkt_len;
		data += pkt_len;

#ifdef DUMP_PKT
		ql2t_p_dump_packet(pkt);
#endif

		pkt_len += sizeof(ql2t_eth_hdr);

		ql2t_out("id (%02d), rem_frag (%02d)\n", pkt->hdr.id, pkt->hdr.rem_frag);

		/* Send the packet */
		do {
			bytes_sent = sendto(sock->fd_raw_sock, pkt, pkt_len, 0,
				(struct sockaddr *) &addr, sizeof(addr));
		} while ((bytes_sent == -1) && (errno == EINTR) && retry--);

		if (retry < 0) {
			ql2t_err("sendto() timedout (%u), err = %d", QL2T_RETRY_COUNT, -EAGAIN);
			retval = -EAGAIN;
			goto out;
		}

		if (bytes_sent == -1) {
			ql2t_err("sendto() failed, err = %d", -errno);
			retval = -errno;
			goto out;
		}

		/*
		 * "net rx softirq" reads packets and charges them against the receive socket (each
		 * socket can hold skb's upto a max limit. In case, this limit is reached, it
		 * starts to silently drops skb's until it has space to save them
		 *
		 * This delay is, hence, needed to let the receiver app (which is at a lower
		 * priority vis-a-vis the "net rx softirq") read packets off the socket before the
		 * socket receive buffer overflows
		 */
		usleep(1);

	} while (rem_frag--);

out:
	unlock(&state.mutex);

	return retval;
}

int ql2t_recv(int fd_raw_sock, ql2t_recv_cfg *cfg, char data[], unsigned short len,
		unsigned short *len_copied)
{
	int done = 0;
	int retval = 0;
	ql2t_eth_pkt *pkt;
	ql2t_frag_state frag_state = QL2T_FRAG_STATE_FIRST;
	ql2t_socket *sock;

	lock(&state.mutex);

	sock = ql2t_p_list_find_socket(fd_raw_sock);
	if (!sock) {
		ql2t_err("Invalid socket, err = %d", -EINVAL);
		retval = -EINVAL;
		goto out;
	}

	if (!cfg) {
		ql2t_err("cfg is NULL, err = %d", -EINVAL);
		retval = -EINVAL;
		goto out;
	}

	if (!data) {
		ql2t_err("data is NULL, err = %d", -EINVAL);
		retval = -EINVAL;
		goto out;
	}

	if (!len) {
		ql2t_err("len is 0, err = %d", -EINVAL);
		retval = -EINVAL;
		goto out;
	}

	if (!len_copied) {
		ql2t_err("len_copied is NULL, err = %d", -EINVAL);
		retval = -EINVAL;
		goto out;
	}

	sock->rx_last_id = QL2T_INVALID_ID;
	sock->rx_last_rem_frag = QL2T_INVALID_REM_FRAG;

	pkt = &sock->rx_pkt;

	/* Receive the first fragment */
	retval = ql2t_p_recv(sock, 0);
	if (retval) {
		goto out;
	}

	while (!done) {
		ql2t_out("state (%02d): id (%02d, %02d), rem_frag (%02d, %02d)", frag_state,
			sock->rx_last_id, pkt->hdr.id, sock->rx_last_rem_frag, pkt->hdr.rem_frag);

		switch (frag_state) {
		case QL2T_FRAG_STATE_FIRST:
			*len_copied = 0;
			retval = ql2t_p_frag_first(sock, data, len, len_copied, &frag_state);
			if (retval)
				break;

			/* Save the remote_mac_address and remote_end_pt */
			memcpy(cfg->remote_mac_addr, pkt->hdr.eth_oui_hdr.eth_hdr.h_source,
				ETH_ALEN);
			cfg->remote_end_pt = ntohs(pkt->hdr.src_end_pt);

			break;

		case QL2T_FRAG_STATE_NEXT:
			retval = ql2t_p_frag_next(sock, data, len, len_copied, &frag_state);
			break;

		case QL2T_FRAG_STATE_IGNORE:
			retval = ql2t_p_frag_ignore(sock, &frag_state);
			break;

		case QL2T_FRAG_STATE_DONE:
			done = 1;
			break;
		}
	}

	if (retval)
		*len_copied = 0;

out:
	unlock(&state.mutex);

	return retval;
}
