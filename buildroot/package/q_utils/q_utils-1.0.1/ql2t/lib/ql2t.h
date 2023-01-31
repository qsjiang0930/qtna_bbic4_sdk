/**
 * Copyright (c) 2016 Quantenna Communications, Inc.
 * All rights reserved.
 **/

#ifndef _QL2T_H_
#define _QL2T_H_

#include <net/if.h>
#include <net/ethernet.h>
#include <sys/time.h>

/* List of all local end points in use */
#define QL2T_EP_QEVT_SERVER	1
#define QL2T_EP_QEVT_CLIENT	2
#define QL2T_EP_PKTLOGGER	3

typedef struct {
	unsigned char	remote_mac_addr[ETH_ALEN];
	unsigned short	remote_end_pt;
} ql2t_send_cfg, ql2t_recv_cfg;

int ql2t_open(const char local_if_name[], unsigned short local_end_pt);
void ql2t_close(int fd_raw_sock);
unsigned short ql2t_get_max_data_len();
int ql2t_send(int fd_raw_sock, const ql2t_send_cfg *conf, const char data[], unsigned short len);
int ql2t_recv(int fd_raw_sock, ql2t_recv_cfg *conf, char data[], unsigned short len,
		unsigned short *len_copied);

#endif /* _QL2T_H_ */
