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

//#ifdef CONFIG_CTRL_IFACE_UNIX
#include <sys/un.h>
//#endif /* CONFIG_CTRL_IFACE_UNIX */

#ifndef WPA_CTRL_H
#define WPA_CTRL_H

#ifdef __cplusplus
extern "C" {
#endif

/* wpa_supplicant control interface - fixed message prefixes */

/**
 * struct wpa_ctrl - Internal structure for control interface library
 *
 * This structure is used by the wpa_supplicant/hostapd control interface
 * library to store internal data. Programs using the library should not touch
 * this data directly. They can only use the pointer to the data structure as
 * an identifier for the control interface connection and use this as one of
 * the arguments for most of the control interface library functions.
 */
struct wpa_ctrl {
//#ifdef CONFIG_CTRL_IFACE_UNIX
	int s;
	struct sockaddr_un local;
	struct sockaddr_un dest;
//#endif /* CONFIG_CTRL_IFACE_UNIX */
};

/* wpa_supplicant/hostapd control interface access */

/**
 * wpa_ctrl_open - Open a control interface to wpa_supplicant/hostapd
 * @ctrl_path: Path for UNIX domain sockets; ignored if UDP sockets are used.
 * Returns: Pointer to abstract control interface data or %NULL on failure
 *
 * This function is used to open a control interface to wpa_supplicant/hostapd.
 * ctrl_path is usually /var/run/wpa_supplicant or /var/run/hostapd. This path
 * is configured in wpa_supplicant/hostapd and other programs using the control
 * interface need to use matching path configuration.
 */
struct wpa_ctrl *wpa_ctrl_open(const char *ctrl_path);

/**
 * wpa_ctrl_open2 - Open a control interface to wpa_supplicant/hostapd
 * @ctrl_path: Path for UNIX domain sockets; ignored if UDP sockets are used.
 * @cli_path: Path for client UNIX domain sockets; ignored if UDP socket
 *            is used.
 * Returns: Pointer to abstract control interface data or %NULL on failure
 *
 * This function is used to open a control interface to wpa_supplicant/hostapd
 * when the socket path for client need to be specified explicitly. Default
 * ctrl_path is usually /var/run/wpa_supplicant or /var/run/hostapd and client
 * socket path is /tmp.
 */
struct wpa_ctrl *wpa_ctrl_open2(const char *ctrl_path, const char *cli_path);


/**
 * wpa_ctrl_close - Close a control interface to wpa_supplicant/hostapd
 * @ctrl: Control interface data from wpa_ctrl_open()
 *
 * This function is used to close a control interface.
 */
void wpa_ctrl_close(struct wpa_ctrl *ctrl);


/**
 * wpa_ctrl_get_fd - Get file descriptor used by the control interface
 * @ctrl: Control interface data from wpa_ctrl_open()
 * Returns: File descriptor used for the connection
 *
 * This function can be used to get the file descriptor that is used for the
 * control interface connection. The returned value can be used, e.g., with
 * select() while waiting for multiple events.
 *
 * The returned file descriptor must not be used directly for sending or
 * receiving packets; instead, the library functions wpa_ctrl_request() and
 * wpa_ctrl_recv() must be used for this.
 */
int wpa_ctrl_get_fd(struct wpa_ctrl *ctrl);

int wpa_ctrl_attach(struct wpa_ctrl *ctrl);

int wpa_ctrl_detach(struct wpa_ctrl *ctrl);

int get_wpa_cli_events(struct wpa_ctrl *mon, int timeout, const char **events,
			char *buf, size_t buf_size);

#ifdef CONFIG_CTRL_IFACE_UDP
#define WPA_CTRL_IFACE_PORT 9877
#define WPA_GLOBAL_CTRL_IFACE_PORT 9878
#endif /* CONFIG_CTRL_IFACE_UDP */


int qtn_hexstr_to_ascii(const char *hex, char *buf, size_t buflen);
void qtn_ascii_to_hexstr(const char *str, char *hex);

#ifdef __cplusplus
}
#endif

#endif /* WPA_CTRL_H */
