/****************************************************************************
 *
 * Copyright (c) 2004-2007, Jouni Malinen <j@w1.fi>
 * wpa_supplicant/hostapd control interface library
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 ****************************************************************************
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifdef __QNXNTO__
#include <sys/select.h>
#endif /* __QNXNTO__ */
#include <sys/stat.h>

#define CONFIG_CTRL_IFACE
#define CONFIG_CTRL_IFACE_UNIX
#define os_malloc malloc
#define os_free free
#define os_memset memset
#define os_memcmp memcmp
#define os_snprintf snprintf
#define os_strlen strlen
#define os_strncmp strncmp
#define os_strlcpy strlcpy

#ifdef CONFIG_CTRL_IFACE

#ifdef CONFIG_CTRL_IFACE_UNIX
#include <sys/un.h>
#endif /* CONFIG_CTRL_IFACE_UNIX */

#include "qtn_wpa_ctrl.h"
#include "common/qsigma_log.h"


#if defined(CONFIG_CTRL_IFACE_UNIX) || defined(CONFIG_CTRL_IFACE_UDP)
#define CTRL_IFACE_SOCKET
#endif /* CONFIG_CTRL_IFACE_UNIX || CONFIG_CTRL_IFACE_UDP */


#ifndef CONFIG_CTRL_IFACE_CLIENT_DIR
#define CONFIG_CTRL_IFACE_CLIENT_DIR "/tmp"
#endif /* CONFIG_CTRL_IFACE_CLIENT_DIR */
#ifndef CONFIG_CTRL_IFACE_CLIENT_PREFIX
#define CONFIG_CTRL_IFACE_CLIENT_PREFIX "wpa_ctrl_"
#endif /* CONFIG_CTRL_IFACE_CLIENT_PREFIX */

#ifdef CTRL_IFACE_SOCKET
int wpa_ctrl_recv(struct wpa_ctrl *ctrl, char *reply, size_t *reply_len)
{
	int res;

	res = recv(ctrl->s, reply, *reply_len, 0);
	if (res < 0)
		return res;
	*reply_len = res;
	return 0;
}


int wpa_ctrl_pending(struct wpa_ctrl *ctrl)
{
	struct timeval tv;
	fd_set rfds;

	tv.tv_sec = 0;
	tv.tv_usec = 0;
	FD_ZERO(&rfds);
	FD_SET(ctrl->s, &rfds);
	select(ctrl->s + 1, &rfds, NULL, NULL, &tv);
	return FD_ISSET(ctrl->s, &rfds);
}

int wpa_ctrl_get_fd(struct wpa_ctrl *ctrl)
{
	return ctrl->s;
}

int wpa_ctrl_request(struct wpa_ctrl *ctrl, const char *cmd, size_t cmd_len,
		     char *reply, size_t *reply_len,
		     void (*msg_cb)(char *msg, size_t len))
{
	struct timeval tv;
	int res;
	fd_set rfds;
	const char *_cmd;
	char *cmd_buf = NULL;
	size_t _cmd_len;

#ifdef CONFIG_CTRL_IFACE_UDP
	if (ctrl->cookie) {
		char *pos;

		_cmd_len = os_strlen(ctrl->cookie) + 1 + cmd_len;
		cmd_buf = os_malloc(_cmd_len);
		if (cmd_buf == NULL)
			return -1;
		_cmd = cmd_buf;
		pos = cmd_buf;
		os_strlcpy(pos, ctrl->cookie, _cmd_len);
		pos += os_strlen(ctrl->cookie);
		*pos++ = ' ';
		os_memcpy(pos, cmd, cmd_len);
	} else
#endif /* CONFIG_CTRL_IFACE_UDP */
	{
		_cmd = cmd;
		_cmd_len = cmd_len;
	}

	if (send(ctrl->s, _cmd, _cmd_len, 0) < 0) {
		os_free(cmd_buf);
		return -1;
	}
	os_free(cmd_buf);

	for (;;) {
		tv.tv_sec = 10;
		tv.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_SET(ctrl->s, &rfds);
		res = select(ctrl->s + 1, &rfds, NULL, NULL, &tv);
		if (res < 0)
			return res;
		if (FD_ISSET(ctrl->s, &rfds)) {
			res = recv(ctrl->s, reply, *reply_len, 0);
			if (res < 0)
				return res;
			if (res > 0 && reply[0] == '<') {
				/* This is an unsolicited message from
				 * wpa_supplicant, not the reply to the
				 * request. Use msg_cb to report this to the
				 * caller.
				 */
				if (msg_cb) {
					/* Make sure the message is nul
					 * terminated.
					 */
					if ((size_t) res == *reply_len)
						res = (*reply_len) - 1;
					reply[res] = '\0';
					msg_cb(reply, res);
				}
				continue;
			}
			*reply_len = res;
			break;
		}
		return -1;
	}
	return 0;
}
#endif /* CTRL_IFACE_SOCKET */

static int wpa_ctrl_attach_helper(struct wpa_ctrl *ctrl, int attach)
{
	char buf[10];
	int ret;
	size_t len = 10;

	ret = wpa_ctrl_request(ctrl, attach ? "ATTACH" : "DETACH", 6,
					buf, &len, NULL);
	if (ret < 0)
		return ret;
	if (len == 3 && os_memcmp(buf, "OK\n", 3) == 0)
		return 0;
	return -1;
}


int wpa_ctrl_attach(struct wpa_ctrl *ctrl)
{
	return wpa_ctrl_attach_helper(ctrl, 1);
}


int wpa_ctrl_detach(struct wpa_ctrl *ctrl)
{
	return wpa_ctrl_attach_helper(ctrl, 0);
}

struct wpa_ctrl *wpa_ctrl_open2(const char *ctrl_path, const char *cli_path)
{
	struct wpa_ctrl *ctrl;
	static int counter;
	int ret;
	size_t res;
	int tries = 0;

	if (ctrl_path == NULL)
		return NULL;

	ctrl = os_malloc(sizeof(*ctrl));
	if (ctrl == NULL)
		return NULL;
	os_memset(ctrl, 0, sizeof(*ctrl));

	ctrl->s = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (ctrl->s < 0) {
		os_free(ctrl);
		return NULL;
	}

	ctrl->local.sun_family = AF_UNIX;
	counter++;
try_again:
	if (cli_path && cli_path[0] == '/') {
		ret = os_snprintf(ctrl->local.sun_path,
				  sizeof(ctrl->local.sun_path),
				  "%s/" CONFIG_CTRL_IFACE_CLIENT_PREFIX "%d-%d",
				  cli_path, (int) getpid(), counter);
	} else {
		ret = os_snprintf(ctrl->local.sun_path,
				  sizeof(ctrl->local.sun_path),
				  CONFIG_CTRL_IFACE_CLIENT_DIR "/"
				  CONFIG_CTRL_IFACE_CLIENT_PREFIX "%d-%d",
				  (int) getpid(), counter);
	}

	if (ret < 0 || (size_t) ret >= sizeof(ctrl->local.sun_path)) {
		close(ctrl->s);
		os_free(ctrl);
		return NULL;
	}
	tries++;
	if (bind(ctrl->s, (struct sockaddr *) &ctrl->local,
		    sizeof(ctrl->local)) < 0) {
		if (errno == EADDRINUSE && tries < 2) {
			/*
			 * getpid() returns unique identifier for this instance
			 * of wpa_ctrl, so the existing socket file must have
			 * been left by unclean termination of an earlier run.
			 * Remove the file and try again.
			 */
			unlink(ctrl->local.sun_path);
			goto try_again;
		}
		close(ctrl->s);
		os_free(ctrl);
		return NULL;
	}

	ctrl->dest.sun_family = AF_UNIX;
	res = os_strlcpy(ctrl->dest.sun_path, ctrl_path,
			 sizeof(ctrl->dest.sun_path));
	if (res >= sizeof(ctrl->dest.sun_path)) {
		close(ctrl->s);
		os_free(ctrl);
		return NULL;
	}
	if (connect(ctrl->s, (struct sockaddr *) &ctrl->dest,
		    sizeof(ctrl->dest)) < 0) {
		close(ctrl->s);
		unlink(ctrl->local.sun_path);
		os_free(ctrl);
		return NULL;
	}

	return ctrl;
}

struct wpa_ctrl *wpa_ctrl_open(const char *ctrl_path)
{
	return wpa_ctrl_open2(ctrl_path, NULL);
}

void wpa_ctrl_close(struct wpa_ctrl *ctrl)
{
	if (ctrl == NULL)
		return;
	unlink(ctrl->local.sun_path);
	if (ctrl->s >= 0)
		close(ctrl->s);
	os_free(ctrl);
}

int get_wpa_cli_events(struct wpa_ctrl *mon, int timeout, const char **events, char *buf,
			size_t buf_size)
{
	int fd, ret;
	fd_set rfd;
	char *pos;
	struct timeval tv;
	time_t start, now;
	int i;

	if (!mon) {
		qtn_error("Invalid WPA ctrl monitor");
		return -1;
	}

	fd = wpa_ctrl_get_fd(mon);
	if (fd < 0) {
		qtn_error("get_wpa_cli: invalid fd monitor");
		return -1;
	}

	time(&start);
	while (1) {
		size_t len;

		FD_ZERO(&rfd);
		FD_SET(fd, &rfd);

		time(&now);
		if ((unsigned int) (now - start) >= timeout)
			tv.tv_sec = 1;
		else
			tv.tv_sec = timeout - (unsigned int) (now - start) + 1;
		tv.tv_usec = 0;
		ret = select(fd + 1, &rfd, NULL, NULL, &tv);
		if (ret == 0) {
			qtn_error("Timeout on waiting for events");
			return -1;
		}
		if (ret < 0) {
			qtn_error("select: %s", strerror(errno));
			return -1;
		}
		len = buf_size;
		if (wpa_ctrl_recv(mon, buf, &len) < 0) {
			qtn_error("Failure while waiting for events");
			return -1;
		}
		if (len == buf_size)
			len--;
		buf[len] = '\0';

		pos = strchr(buf, '>');
		if (pos) {
			for (i = 0; events[i]; i++) {
				if (strncmp(pos + 1, events[i],
					    strlen(events[i])) == 0)
					return 0; /* Event found */
			}
		}

		time(&now);
		if ((unsigned int) (now - start) > timeout) {
			qtn_error("Timeout on waiting for event");
			return -1;
		}
	}
}

#endif /* CONFIG_CTRL_IFACE */

static int qtn_parse_hex(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';

	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;

	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	return -1;
}

static int qtn_hex_byte(const char *str)
{
	int res1, res2;

	res1 = qtn_parse_hex(str[0]);
	if (res1 < 0)
		return -1;
	res2 = qtn_parse_hex(str[1]);
	if (res2 < 0)
		return -1;
	return (res1 << 4) | res2;
}


int qtn_hexstr_to_ascii(const char *hex, char *buf, size_t buflen)
{
	size_t i;
	const char *pos = hex;

	for (i = 0; i < buflen; i++) {
		int val;

		if (*pos == '\0')
			break;
		val = qtn_hex_byte(pos);
		if (val < 0)
			return -1;
		buf[i] = val;
		pos += 2;
	}

	return i;
}

void qtn_ascii_to_hexstr(const char *str, char *hex)
{
	int i, length;

	length = strlen(str);

	for (i = 0; i < length; i++)
		snprintf(hex + i * 2, 3, "%X", str[i]);

	hex[length * 2] = '\0';
}
