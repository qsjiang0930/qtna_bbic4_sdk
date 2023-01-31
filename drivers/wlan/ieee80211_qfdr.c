/*-
 * Copyright (c) 2015 Quantenna Communications, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: ieee80211_qfdr.c 2759 2015-12-20 10:48:20Z Jason $
 */
#ifndef EXPORT_SYMTAB
#define	EXPORT_SYMTAB
#endif

/*
 * IEEE 802.11 sync scan result for Quantenna QFDR.
 */
#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/version.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/in.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <net/sock.h>

#include "net80211/if_media.h"

#include "net80211/ieee80211_var.h"

#define QFDR_REP_TIMEOUT   (2 * HZ)
#define QFDR_REQ_MAX_SIZE  4096

static char *local_ip = "0.0.0.0";
module_param(local_ip, charp, S_IRUGO);
MODULE_PARM_DESC(local_ip, "qfdr local ip");

static char *remote_ip = "0.0.0.0";
module_param(remote_ip, charp, S_IRUGO);
MODULE_PARM_DESC(remote_ip, "qfdr remote ip");

static unsigned short req_port = 0;
module_param(req_port, ushort, S_IRUGO);
MODULE_PARM_DESC(req_port, "qfdr port to recv req");

static unsigned short rep_port = 0;
module_param(rep_port, ushort, S_IRUGO);
MODULE_PARM_DESC(rep_port, "qfdr port to recv rep");

static struct socket *sock_send;
static struct socket *sock_recv_req;
static struct socket *sock_recv_rep;
static struct sockaddr_in sin_req;
static struct sockaddr_in sin_rep;

static struct task_struct *thread_recv_req;
static struct completion comp_recv_req_thread;

static struct socket * qfdr_create_recv_socket(unsigned int addr, unsigned short port)
{
	struct sockaddr_in sin_bind;
	struct socket *socket = NULL;

	if (sock_create_kern(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &socket)) {
		printk(KERN_ERR "%s: Failed to create socket\n", __func__);
		return NULL;
	}

	sin_bind.sin_family = AF_INET;
	sin_bind.sin_addr.s_addr = addr;
	sin_bind.sin_port = htons(port);

	if (kernel_bind(socket, (struct sockaddr *)&sin_bind, sizeof(sin_bind))) {
		printk(KERN_ERR "%s: Failed to bind socket to port %pI4:%d\n", __func__, &addr, port);
		sock_release(socket);
		return NULL;
	}

	return socket;
}

static int qfdr_recv(struct socket *sock, char *buffer, size_t buflen)
{
	struct msghdr	msg = {NULL};
	struct kvec	iov;
	int		len;

	/* adjust the RCVBUF */
	if (buflen > sock->sk->sk_rcvbuf)
		sock->sk->sk_rcvbuf = buflen;

	iov.iov_base     = buffer;
	iov.iov_len      = buflen;

	len = kernel_recvmsg(sock, &msg, &iov, 1, buflen, 0);

	return len;
}

static int qfdr_send(struct socket *sock, char *buffer, size_t buflen, struct sockaddr_in *dest_addr)
{
	struct msghdr	msg = {.msg_flags = MSG_DONTWAIT|MSG_NOSIGNAL};
	struct kvec	iov;
	int		len;

	/* adjust the SNDBUF */
	if (buflen > sock->sk->sk_sndbuf)
		sock->sk->sk_sndbuf = buflen;

	msg.msg_name     = dest_addr;
	msg.msg_namelen  = sizeof(struct sockaddr_in);

	iov.iov_base     = buffer;
	iov.iov_len      = buflen;

	len = kernel_sendmsg(sock, &msg, &iov, 1, buflen);

	return len;
}

int qfdr_remote_giwscan(struct iwscanreq *req)
{
	struct qfdr_remote_aplist_req request;
	char *recvbuf;
	size_t recvbuf_size;
	int recvlen;
	struct qfdr_remote_aplist_rep *rep;
	int res;

	request.type = QFDR_GIWSCAN;
	memcpy(&request.info, req->info, sizeof(struct iw_request_info));
	request.extra_len = req->end_buf - req->current_ev;
	strcpy(request.dev_name, req->vap->iv_dev->name);
	qfdr_send(sock_send, (char *)&request, sizeof(request), &sin_req);

	recvbuf_size = request.extra_len + sizeof(struct qfdr_remote_aplist_rep);
	recvbuf = kmalloc(recvbuf_size, GFP_KERNEL);
	if (!recvbuf) {
		printk(KERN_ERR "%s: Failed to alloc recvbuf\n", __func__);
		return 0;
	}

	recvlen = qfdr_recv(sock_recv_rep, recvbuf, recvbuf_size);
	if (recvlen < sizeof(struct qfdr_remote_aplist_rep)) {
		kfree(recvbuf);
		if (recvlen < 0)
			printk(KERN_ERR "%s: Failed to recv rep with errno %d\n", __func__, recvlen);
		else
			printk(KERN_ERR "%s: recv invalid rep\n", __func__);
		return 0;
	}

	rep = (struct qfdr_remote_aplist_rep *)recvbuf;
	res = rep->res;
	if (rep->length > 0 && rep->type == QFDR_GIWSCAN) {
		memcpy(req->current_ev, rep->extra, rep->length);
		req->current_ev += rep->length;
	}
	kfree(recvbuf);

	/* Only pass E2BIG on to local */
	if (res != E2BIG)
		res = 0;

	return res;
}

int qfdr_remote_ap_scan_results(struct ap_scan_iter *iter)
{
	struct qfdr_remote_aplist_req request;
	char *recvbuf;
	size_t recvbuf_size;
	int recvlen;
	struct qfdr_remote_aplist_rep *rep;
	int res;

	request.type = QFDR_AP_SCAN_RESULT;
	request.extra_len = iter->end_buf - iter->current_env;
	strcpy(request.dev_name, iter->vap->iv_dev->name);
	qfdr_send(sock_send, (char *)&request, sizeof(request), &sin_req);

	recvbuf_size = request.extra_len + sizeof(struct qfdr_remote_aplist_rep);
	recvbuf = kmalloc(recvbuf_size, GFP_KERNEL);
	if (!recvbuf) {
		printk(KERN_ERR "%s: Failed to alloc recvbuf\n", __func__);
		return 0;
	}

	recvlen = qfdr_recv(sock_recv_rep, recvbuf, recvbuf_size);
	if (recvlen < sizeof(struct qfdr_remote_aplist_rep)) {
		kfree(recvbuf);
		if (recvlen < 0)
			printk(KERN_ERR "%s: Failed to recv rep with errno %d\n", __func__, recvlen);
		else
			printk(KERN_ERR "%s: recv invalid rep\n", __func__);
		return 0;
	}

	rep = (struct qfdr_remote_aplist_rep *)recvbuf;
	res = rep->res;
	if (rep->length > 0 && rep->type == QFDR_AP_SCAN_RESULT) {
		memcpy(iter->current_env, rep->extra, rep->length);
		iter->current_env += rep->length;
		iter->ap_counts += rep->ap_counts;
	}
	kfree(recvbuf);

	/* Only pass E2BIG on to local */
	if (res != E2BIG)
		res = 0;

	return res;
}

int qfdr_remote_siwscan(char *dev_name, struct iw_point *data)
{
	struct qfdr_remote_scan_req *request;
	int req_len = sizeof(struct qfdr_remote_scan_req);

	if (data)
		req_len += data->length;
	if (req_len > QFDR_REQ_MAX_SIZE) {
		printk(KERN_ERR "%s: qfdr peer canonly recv %d bytes req\n", __func__, QFDR_REQ_MAX_SIZE);
		return -EINVAL;
	}
	request = kmalloc(req_len, GFP_KERNEL);
	if (!request) {
		printk(KERN_ERR "%s: Failed to alloc buf\n", __func__);
		return -ENOMEM;
	}

	strcpy(request->dev_name, dev_name);
	if (data) {
		request->type = QFDR_SIWSCAN;
		request->flags = data->flags;
		request->length = data->length;
		memcpy(request->pointer, data->pointer, data->length);
	} else {
		request->type = QFDR_SIWSCAN_SIMPLE;
	}

	qfdr_send(sock_send, (char *)request, req_len, &sin_req);
	kfree(request);

	return 0;
}

int qfdr_send_bss_info(struct ieee80211vap *vap, uint8_t channel)
{
	struct ieee80211_node *ni = vap->iv_bss;
	struct qfdr_bss_info *info;
	int32_t info_len;

	if (!ni) {
		printk(KERN_ERR "%s: %s don't associate with any AP\n", __func__, vap->iv_dev->name);
		return -EINVAL;
	}

	if (!ni->ni_beacon_frame_len || !ni->ni_beacon_frame) {
		printk(KERN_ERR "%s: beacon from %pM was not backuped\n", __func__, ni->ni_bssid);
		return -EINVAL;
	}

	info_len = sizeof(struct qfdr_bss_info) + ni->ni_beacon_frame_len;
	if (info_len > QFDR_REQ_MAX_SIZE) {
		printk(KERN_ERR "%s: bss_info is too long %u\n", __func__, info_len);
		return -EINVAL;
	}

	info = kmalloc(info_len, GFP_KERNEL);
	if (!info) {
		printk(KERN_ERR "%s: Failed to alloc buf\n", __func__);
		return -ENOMEM;
	}
	info->type = QFDR_REMOTE_BSS_INFO;
	strcpy(info->dev_name, vap->iv_dev->name);
	info->rssi = ni->ni_rssi;
	info->channel = channel;
	info->ssid[0] = IEEE80211_ELEMID_SSID;
	info->ssid[1] = ni->ni_esslen;
	memcpy(&info->ssid[2], ni->ni_essid, ni->ni_esslen);
	info->beacon_len = ni->ni_beacon_frame_len;
	memcpy(info->beacon, ni->ni_beacon_frame, ni->ni_beacon_frame_len);

	qfdr_send(sock_send, (char *)info, info_len, &sin_req);
	kfree(info);

	return 0;
}

static void qfdr_process_req(char *recvbuf, int recvlen)
{
	int type = *((int *)recvbuf);
	struct qfdr_remote_aplist_rep rep_nomem = {ENOMEM, 0, 0, 0};
	struct qfdr_remote_aplist_rep *rep;

	if (type == QFDR_GIWSCAN) {
		rep = qfdr_giwscan_for_remote((struct qfdr_remote_aplist_req *)recvbuf);
		if (rep) {
			qfdr_send(sock_send, (char *)rep, sizeof(struct qfdr_remote_aplist_rep) + rep->length, &sin_rep);
			kfree(rep);
		} else {
			rep = &rep_nomem;
			rep->type = QFDR_GIWSCAN;
			qfdr_send(sock_send, (char *)rep, sizeof(struct qfdr_remote_aplist_rep) + rep->length, &sin_rep);
		}
	} else if (type == QFDR_AP_SCAN_RESULT) {
		rep = qfdr_ap_scan_results_for_remote((struct qfdr_remote_aplist_req *)recvbuf);
		if (rep) {
			qfdr_send(sock_send, (char *)rep, sizeof(struct qfdr_remote_aplist_rep) + rep->length, &sin_rep);
			kfree(rep);
		} else {
			rep = &rep_nomem;
			rep->type = QFDR_AP_SCAN_RESULT;
			qfdr_send(sock_send, (char *)rep, sizeof(struct qfdr_remote_aplist_rep) + rep->length, &sin_rep);
		}
	} else if (type == QFDR_SIWSCAN_SIMPLE || type == QFDR_SIWSCAN) {
		qfdr_siwscan_for_remote((struct qfdr_remote_scan_req *)recvbuf);
	} else if (type == QFDR_REMOTE_BSS_INFO) {
		qfdr_recv_bss_info((struct qfdr_bss_info *)recvbuf);
	}
}

static int qfdr_recv_req_thread(void *data)
{
	char *recvbuf;
	int recvlen;

	recvbuf = kmalloc(QFDR_REQ_MAX_SIZE, GFP_KERNEL);
	if (!recvbuf) {
		printk(KERN_ERR "%s: Failed to alloc recvbuf\n", __func__);
		return -ENOMEM;
	}

	allow_signal(SIGTERM);

	while (!signal_pending(current)) {
		recvlen = qfdr_recv(sock_recv_req, recvbuf, QFDR_REQ_MAX_SIZE);
		if (recvlen > 0) {
			qfdr_process_req(recvbuf, recvlen);
		} else {
			printk(KERN_WARNING "%s: broken pipe on socket\n", __func__);
		}
	}

	kfree(recvbuf);
	complete(&comp_recv_req_thread);
	thread_recv_req = NULL;

	return 0;
}

/*
 * Module glue.
 */
MODULE_AUTHOR("Quantenna, Jason.Wang");
MODULE_DESCRIPTION("802.11 wireless support: Quantenna QFDR sync scan result");
#ifdef MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif

static int __init init_wlan_qfdr(void)
{
	unsigned int local_addr, remote_addr;

	local_addr = in_aton(local_ip);
	if (local_addr == INADDR_ANY || local_addr == INADDR_NONE) {
		printk(KERN_ERR "%s: Invalid local IP %pI4\n", __func__, &local_addr);
		return -EINVAL;
	}

	remote_addr = in_aton(remote_ip);
	if (remote_addr == INADDR_ANY || remote_addr == INADDR_NONE) {
		printk(KERN_ERR "%s: Invalid remote IP %pI4\n", __func__, &remote_addr);
		return -EINVAL;
	}

	if (req_port == 0) {
		printk(KERN_ERR "%s: Invalid req port %u, must be greater than 0\n", __func__, req_port);
		return -EINVAL;
	}

	if (rep_port == 0 || rep_port == req_port) {
		printk(KERN_ERR "%s: Invalid rep port %u, must be greater than 0 and not same as req port\n", __func__, rep_port);
		return -EINVAL;
	}

	if (sock_create_kern(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock_send)) {
		printk(KERN_ERR "%s: Failed to create send socket\n", __func__);
		goto fail;
	}

	sock_recv_req = qfdr_create_recv_socket(local_addr, req_port);
	if (!sock_recv_req) {
		printk(KERN_ERR "%s: Failed to create req recv socket\n", __func__);
		goto fail;
	}

	sock_recv_rep = qfdr_create_recv_socket(local_addr, rep_port);
	if (!sock_recv_rep) {
		printk(KERN_ERR "%s: Failed to create rep recv socket\n", __func__);
		goto fail;
	}

	/* set the RCVTIMEO */
	sock_recv_rep->sk->sk_rcvtimeo = QFDR_REP_TIMEOUT;

	sin_req.sin_family = AF_INET;
	sin_req.sin_addr.s_addr = remote_addr;
	sin_req.sin_port = htons(req_port);

	sin_rep.sin_family = AF_INET;
	sin_rep.sin_addr.s_addr = remote_addr;
	sin_rep.sin_port = htons(rep_port);

	thread_recv_req = kthread_run(qfdr_recv_req_thread, NULL, "qfdr");
	if (IS_ERR(thread_recv_req)) {
		printk(KERN_ERR "%s: Failed to start qfdr_recv_req_thread\n", __func__);
		goto fail;
	}

	init_completion(&comp_recv_req_thread);
	ieee80211_register_qfdr_remote_siwscan_hook(qfdr_remote_siwscan);
	ieee80211_register_qfdr_remote_giwscan_hook(qfdr_remote_giwscan);
	ieee80211_register_qfdr_remote_ap_scan_results_hook(qfdr_remote_ap_scan_results);
	ieee80211_register_qfdr_send_bss_info_hook(qfdr_send_bss_info);

	printk(KERN_INFO "Load qfdr module successfully, local ip:%pI4, remote ip:%pI4, req_port:%u, rep_port:%u\n", &local_addr, &remote_addr, req_port, rep_port);
	return 0;
fail:
	if (sock_send)
		sock_release(sock_send);
	if (sock_recv_req)
		sock_release(sock_recv_req);
	if (sock_recv_rep)
		sock_release(sock_recv_rep);

	return -EAGAIN;
}
module_init(init_wlan_qfdr);

static void __exit exit_wlan_qfdr(void)
{
	ieee80211_register_qfdr_remote_siwscan_hook(NULL);
	ieee80211_register_qfdr_remote_giwscan_hook(NULL);
	ieee80211_register_qfdr_remote_ap_scan_results_hook(NULL);
	if (thread_recv_req) {
		send_sig(SIGTERM, thread_recv_req, 0);
		wait_for_completion(&comp_recv_req_thread);
	}

	if (sock_send)
		sock_release(sock_send);
	if (sock_recv_req)
		sock_release(sock_recv_req);
	if (sock_recv_rep)
		sock_release(sock_recv_rep);
}
module_exit(exit_wlan_qfdr);
