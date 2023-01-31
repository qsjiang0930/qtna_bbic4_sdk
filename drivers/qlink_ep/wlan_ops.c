/**
 * Copyright (c) 2015 - 2016 Quantenna Communications, Inc.
 * All rights reserved.
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

#define pr_fmt(fmt)	"%s: " fmt, __func__

#include <linux/netdevice.h>
#include <linux/file.h>
#include <linux/net.h>

#include <net/iw_handler.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_qrpe.h>

#include <qtn/shared_defs.h>

#include "wlan_ops.h"
#include "utils.h"

/* wext ioctl emulation */

int qlink_wext_ioctl(struct net_device *dev, unsigned int cmd, struct iwreq *iwr)
{
	mm_segment_t oldmm = get_fs();
	struct file *sock_filp;
	struct socket *sock;
	int sock_fd;
	int ret = 0;

	memcpy(iwr->ifr_ifrn.ifrn_name, dev->name, IFNAMSIZ);
	iwr->ifr_ifrn.ifrn_name[IFNAMSIZ - 1] = '\0';

	ret = sock_create(PF_INET, SOCK_STREAM, 0, &sock);
	if (ret != 0) {
		pr_err("can't create socket: %d\n", ret);
		goto out;
	}

	sock_fd = sock_alloc_file(sock, &sock_filp, 0);
	if (sock_fd < 0) {
		ret = sock_fd;
		pr_err("can't allocate socket file: %d\n", ret);
		sock_release(sock);
		goto out;
	}

	set_fs(KERNEL_DS);
	if (sock_filp->f_op->unlocked_ioctl)
		ret = sock_filp->f_op->unlocked_ioctl(sock_filp, cmd, (unsigned long)iwr);
	set_fs(oldmm);

	fput(sock_filp);
	put_unused_fd(sock_fd);
out:
	return ret;
}

/* kernel qcsapi port */

static int qlink_locate_iwpriv_cmd(const char *cmd, const struct iw_priv_args *priv,
	int priv_num, int *subcmd, int *offset)
{
	int i, j;

	for (i = 0; i < priv_num; i++)
		if (strcmp(priv[i].name, cmd) == 0)
			break;

	if (i == priv_num)
		return -EOPNOTSUPP;

	/* Special case - private ioctls, need to find the full ioctl number */
	if (priv[i].cmd < SIOCDEVPRIVATE) {
		for (j = 0; j < priv_num; j++)
			if ((priv[j].name[0] == '\0')
					&& (priv[j].set_args == priv[i].set_args)
					&& (priv[j].get_args == priv[i].get_args))
				break;

		if (j == priv_num)
			return -EOPNOTSUPP;

		*subcmd = priv[i].cmd;
		*offset = sizeof(__u32);
		i = j;
	}

	return i;
}

static int qlink_prepare_iwpriv_wrq(const struct iw_priv_args *priv,
		char *argv[], int argc, struct iwreq *wrq, u_char *buffer,
		int buffer_size)
{
	int temp;
	int i = -1;
	int args_size = priv->set_args & IW_PRIV_SIZE_MASK;

	if (argc > args_size)
		argc = args_size;

	if ((priv->set_args & IW_PRIV_TYPE_MASK) == IW_PRIV_TYPE_CHAR) {
		if (argc > 0) {
			wrq->u.data.length = strlen(argv[0]) + 1;
			if (wrq->u.data.length > args_size)
				wrq->u.data.length = args_size;
			if (wrq->u.data.length >= buffer_size - 1)
				wrq->u.data.length = buffer_size - 1;
		} else
			wrq->u.data.length = 1;
	} else {
		wrq->u.data.length = argc;
	}

	if ((priv->set_args & IW_PRIV_SIZE_FIXED)
			&& (wrq->u.data.length != args_size)) {
		pr_err("IOCTL needs exactly %d argument(s)\n",
		       priv->set_args & IW_PRIV_SIZE_MASK);
		return (-EOPNOTSUPP);
	}

	switch (priv->set_args & IW_PRIV_TYPE_MASK) {
	case IW_PRIV_TYPE_BYTE:
		while (++i < argc) {
			sscanf(argv[i], "%i", &temp);
			buffer[i] = (char)temp;
		}
		break;

	case IW_PRIV_TYPE_INT:
		while (++i < argc)
			sscanf(argv[i], "%i", (__s32 *)buffer + i);
		break;

	case IW_PRIV_TYPE_CHAR:
		if (argc > 0) {
			memcpy(buffer, argv[0], wrq->u.data.length);
			buffer[wrq->u.data.length] = '\0';
		} else {
			buffer[0] = '\0';
		}
		break;

	case IW_PRIV_TYPE_FLOAT:
		pr_err("IOCTL float type is not supported\n");
		return -EOPNOTSUPP;

	case IW_PRIV_TYPE_ADDR:
		while (++i < argc) {
			struct sockaddr *csa = ((struct sockaddr *)buffer) + i;

			csa->sa_family = AF_INET;
			memcpy(csa->sa_data, argv[i], 6);
		}
		break;

	default:
		pr_err("IOCTL args [0x%x] not implemented\n", priv->set_args);
		return -EOPNOTSUPP;
	}

	return 0;
}

static int qlink_get_priv_args_size(int args)
{
	int num = args & IW_PRIV_SIZE_MASK;

	switch (args & IW_PRIV_TYPE_MASK) {
	case IW_PRIV_TYPE_BYTE:
	case IW_PRIV_TYPE_CHAR:
		return num;
	case IW_PRIV_TYPE_INT:
		return num * sizeof(__u32);
	case IW_PRIV_TYPE_ADDR:
		return num * sizeof(struct sockaddr);
	case IW_PRIV_TYPE_FLOAT:
		return num * sizeof(struct iw_freq);
	default:
		return 0;
	}
}

static int qlink_parse_iwpriv_result(const struct iw_priv_args *priv,
		struct iwreq *wrq, u_char *data, void *result, __u32 size)
{
	int c = 0;

	/* get number of the returned data */
	if ((priv->get_args & IW_PRIV_SIZE_FIXED)
	    && (qlink_get_priv_args_size(priv->get_args) <= IFNAMSIZ)) {
		memcpy(data, wrq->u.name, IFNAMSIZ);
		c = priv->get_args & IW_PRIV_SIZE_MASK;
	} else {
		c = wrq->u.data.length;
	}

	switch (priv->get_args & IW_PRIV_TYPE_MASK) {
	case IW_PRIV_TYPE_CHAR:
		if (size > c) {
			data[c] = '\0';
			strcpy(result, (char *)data);
		} else {
			return (-ENOMEM);
		}
		break;

	case IW_PRIV_TYPE_INT:
		c *= sizeof(__s32);
		/* continue copying data */
	case IW_PRIV_TYPE_BYTE:
		if (size >= c)
			memcpy(result, (void *)data, c);
		else
			return -ENOMEM;
		break;

	default:
		pr_err("IOCTL result type not implemented\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

static int qlink_get_priv_ioctls(struct net_device *dev, int *p_num_priv_ioctls,
				 const struct iw_priv_args **pp_priv_ioctls)
{
	if (!dev->wireless_handlers)
		return -EOPNOTSUPP;

	*p_num_priv_ioctls = dev->wireless_handlers->num_private_args;
	*pp_priv_ioctls = dev->wireless_handlers->private_args;

	return 0;
}

static int qlink_call_private_ioctl(struct net_device *dev, char *argv[], int argc,
				    const char *cmd, void *result_addr,
				    unsigned int result_size)
{
	enum {
		iwpriv_buffer_size = 4096
	};
	struct iwreq wrq;
	u_char *buffer = NULL;
	int subcmd = 0; /* sub-ioctl index */
	int offset = 0; /* Space for sub-ioctl index */
	int ret = 0;
	const struct iw_priv_args *priv_args;
	const struct iw_priv_args *priv_table = NULL;
	int priv_num;
	int index;

	ret = qlink_get_priv_ioctls(dev, &priv_num, &priv_table);
	if (ret < 0)
		goto ready_to_return;

	if (priv_num <= 0 || priv_table == NULL) {
		ret = -EOPNOTSUPP;
		goto ready_to_return;
	}

	if ((argc >= 1) && (sscanf(argv[0], "[%i]", &subcmd) == 1)) {
		argv++;
		argc--;
	}

	index = qlink_locate_iwpriv_cmd(cmd, priv_table, priv_num, &subcmd, &offset);
	if (index < 0) {
		pr_err("IOCTL invalid command: %s\n", cmd);
		ret = -EOPNOTSUPP;
		goto ready_to_return;
	}
	priv_args = &priv_table[index];

	buffer = kmalloc(iwpriv_buffer_size, GFP_KERNEL);
	if (buffer == NULL) {
		ret = -ENOMEM;
		goto ready_to_return;
	}

	memset(buffer, 0, iwpriv_buffer_size);
	memset((u_char *)&wrq, 0, sizeof(wrq));

	if ((priv_args->set_args & IW_PRIV_TYPE_MASK)
			&& (priv_args->set_args & IW_PRIV_SIZE_MASK)) {
		if (qlink_prepare_iwpriv_wrq(priv_args, argv, argc, &wrq, buffer,
					     iwpriv_buffer_size) != 0) {
			ret = -EPERM;
			goto ready_to_return;
		}
	}

	strncpy(wrq.ifr_name, "wifi", IFNAMSIZ);

	if ((priv_args->set_args & IW_PRIV_SIZE_FIXED)
	    && ((qlink_get_priv_args_size(priv_args->set_args) + offset) <= IFNAMSIZ)) {
		/* all SET args fit within wrq */
		if (offset)
			wrq.u.mode = subcmd;
		memcpy(wrq.u.name + offset, buffer, IFNAMSIZ - offset);
	} else if ((priv_args->set_args == 0) && (priv_args->get_args & IW_PRIV_SIZE_FIXED)
		   && (qlink_get_priv_args_size(priv_args->get_args) <= IFNAMSIZ)) {
		/* no SET args, GET args fit within wrq */
		if (offset)
			wrq.u.mode = subcmd;
	} else {
		/* argv won't fit in wrq, or variable number of argv */
		wrq.u.data.pointer = (caddr_t)buffer;
		wrq.u.data.flags = subcmd;
	}

	/* Note: warn for another kernel code path,
	 * coverity referes to VLAN ioctls, not for WEXT private ioctls
	 */

	/* coverity[overrun-buffer-val] */
	if (qlink_wext_ioctl(dev, priv_args->cmd, &wrq) < 0) {
		pr_err("IOCTL interface doesn't accept private ioctl\n");
		pr_err("IOCTL %s (%X)\n", cmd, priv_args->cmd);
		ret = -EOPNOTSUPP;
		goto ready_to_return;
	}

	if ((priv_args->get_args & IW_PRIV_TYPE_MASK)
	    && (priv_args->get_args & IW_PRIV_SIZE_MASK)) {
		ret = qlink_parse_iwpriv_result(priv_args, &wrq, buffer,
						result_addr, result_size);
	}

ready_to_return:
	kfree(buffer);
	return ret;
}

/* private ioctl ops */

int qlink_wifi_getparam(struct net_device *dev, const int param, int *p_value)
{
	int retval = 0;
	struct iwreq iwr;
	s32 *buffer = (s32 *)iwr.u.name;

	buffer[0] = param;

	retval = qlink_wext_ioctl(dev, IEEE80211_IOCTL_GETPARAM, &iwr);

	*p_value = buffer[0];

	return retval;
}

int qlink_wifi_setparam(struct net_device *dev, const int param, const int value)
{
	struct iwreq iwr;
	s32 *buffer = (s32 *)iwr.u.name;

	buffer[0] = param;
	buffer[1] = value;

	return qlink_wext_ioctl(dev, IEEE80211_IOCTL_SETPARAM, &iwr);
}

int qlink_wifi_updparam(struct net_device *dev, const int param, const int value)
{
	int old_value;
	int ret;

	ret = qlink_wifi_getparam(dev, param, &old_value);
	if (!ret && (value != old_value))
		ret = qlink_wifi_setparam(dev, param, value);

	return ret;
}

int qlink_wifi_setpriv(struct net_device *dev, int op, const void *data, int len)
{
	struct iwreq iwr;
	int fits_in_name = len < IFNAMSIZ;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, "wifi", IFNAMSIZ);

	if ((op == IEEE80211_IOCTL_SET_APPIEBUF) ||
	    (op == IEEE80211_IOCTL_POSTEVENT) ||
	    (op == IEEE80211_IOCTL_TXEAPOL))
		fits_in_name = 0;
	if (fits_in_name) {
		memcpy(iwr.u.name, data, len);
	} else {
		iwr.u.data.pointer = (void *)data;
		iwr.u.data.length = len;
	}


	/* Note: warn for another kernel code path,
	 * coverity referes to VLAN ioctls, not for WEXT ioctls
	 */

	/* coverity[overrun-buffer-val] */
	return qlink_wext_ioctl(dev, op, &iwr);
}

int qlink_wifi_get_802_11_mode(struct net_device *dev, char *wifi_802_11_mode, int max_mode_len)
{
	const char * const argv[] = { NULL };
	int retval = 0;
	int argc = 0;

	retval = qlink_call_private_ioctl(dev, (char **)argv, argc, "get_mode",
					  (void *)wifi_802_11_mode, max_mode_len);

	return retval;
}

#define QLINK_MODE_MAX_LEN	20
int qlink_wifi_set_802_11_mode(struct net_device *dev, const char *wifi_802_11_mode)
{
	int retval = 0;
	char *argv[] = {(char *)wifi_802_11_mode};
	int argc = ARRAY_SIZE(argv);
	char cur_mode[QLINK_MODE_MAX_LEN];

	retval = qlink_wifi_get_802_11_mode(dev, cur_mode, sizeof(cur_mode) - 1);
	if (retval)
		return retval;

	if (!strcasecmp(wifi_802_11_mode, cur_mode))
		return 0;

	pr_info("%s: mode change \"%s\" -> \"%s\"\n",
		dev->name, cur_mode, wifi_802_11_mode);

	retval = qlink_call_private_ioctl(dev, argv, argc, "mode", NULL, 0);

	return retval;
}

int qlink_wifi_set_cclass(struct net_device *dev, u8 class)
{
	int retval = 0;
	char setparam_class[4];
	char *argv[] = {&setparam_class[0]};
	int argc = ARRAY_SIZE(argv);

	snprintf(setparam_class, sizeof(setparam_class), "%d", class);
	retval = qlink_call_private_ioctl(dev, argv, argc, "coverageclass", NULL, 0);

	return retval;
}

int qlink_wifi_set_sta_authorized(struct net_device *dev, u8 *sta_addr, u32 authorized)
{
	struct ieee80211req_mlme mlme;

	memset(&mlme, 0, sizeof(mlme));
	if (authorized)
		mlme.im_op = IEEE80211_MLME_AUTHORIZE;
	else
		mlme.im_op = IEEE80211_MLME_UNAUTHORIZE;
	mlme.im_reason = 0;
	memcpy(mlme.im_macaddr, sta_addr, IEEE80211_ADDR_LEN);
	return qlink_wifi_setpriv(dev, IEEE80211_IOCTL_SETMLME, &mlme, sizeof(mlme));
}

int qlink_wifi_sta_deauth(struct net_device *dev, u8 *sta_addr, u8 reason_code)
{
	struct ieee80211req_mlme mlme;

	memset(&mlme, 0, sizeof(mlme));
	mlme.im_op = IEEE80211_MLME_DEAUTH;
	mlme.im_reason = reason_code;
	memcpy(mlme.im_macaddr, sta_addr, IEEE80211_ADDR_LEN);
	return qlink_wifi_setpriv(dev, IEEE80211_IOCTL_SETMLME, &mlme, sizeof(mlme));
}

int qlink_wifi_sta_disassoc(struct net_device *dev, u8 *sta_addr, u8 reason_code)
{
	struct ieee80211req_mlme mlme;

	memset(&mlme, 0, sizeof(mlme));
	mlme.im_op = IEEE80211_MLME_DISASSOC;
	mlme.im_reason = reason_code;
	memcpy(mlme.im_macaddr, sta_addr, IEEE80211_ADDR_LEN);
	return qlink_wifi_setpriv(dev, IEEE80211_IOCTL_SETMLME, &mlme, sizeof(mlme));
}

/* wext ioctl ops */

int qlink_phy_apply_rts_thre(struct net_device *dev, u32 rts_thresh)
{
	struct iwreq iwr;

	pr_debug("setting RTS threshold %u\n", rts_thresh);

	memset(&iwr, 0, sizeof(iwr));

	if (rts_thresh == IEEE80211_RTS_THRESH_OFF) {
		iwr.u.rts.disabled = 1;
		iwr.u.rts.value = 0;
	} else {
		iwr.u.rts.disabled = 0;
		iwr.u.rts.value = rts_thresh;
	}

	if (qlink_wext_ioctl(dev, SIOCSIWRTS, &iwr))
		return -1;

	return 0;
}

int qlink_phy_apply_frag_thre(struct net_device *dev, u32 frag_thresh)
{
	struct iwreq iwr;

	pr_debug("setting frag threshold %u\n", frag_thresh);

	memset(&iwr, 0, sizeof(iwr));

	if (frag_thresh == (u32)-1)
		iwr.u.frag.disabled = 1;
	else
		iwr.u.frag.disabled = 0;

	iwr.u.frag.value = frag_thresh;

	if (qlink_wext_ioctl(dev, SIOCSIWFRAG, &iwr))
		return -1;

	return 0;
}

int qlink_phy_get_rts_thre(struct net_device *dev, int *rts_thresh)
{
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	iwr.u.rts.disabled = 0;
	iwr.u.rts.value = 0;

	if (qlink_wext_ioctl(dev, SIOCGIWRTS, &iwr))
		return -1;

	if (iwr.u.rts.disabled)
		*rts_thresh = -1;
	else
		*rts_thresh = iwr.u.rts.value;

	pr_debug("RTS threshold %u\n", *rts_thresh);
	return 0;
}

int qlink_phy_get_frag_thre(struct net_device *dev, int *frag_thresh)
{
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	iwr.u.frag.disabled = 0;
	iwr.u.frag.value = 0;

	if (qlink_wext_ioctl(dev, SIOCGIWFRAG, &iwr))
		return -1;

	if (iwr.u.frag.disabled)
		*frag_thresh = -1;
	else
		*frag_thresh = iwr.u.frag.value;
	pr_debug("frag threshold %u\n", *frag_thresh);

	return 0;
}

int qlink_phy_get_retry(struct net_device *dev, int *retry)
{
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	iwr.u.retry.disabled = 0;
	iwr.u.retry.value = *retry;
	iwr.u.retry.flags = IW_RETRY_LIMIT | IW_RETRY_MAX;

	if (qlink_wext_ioctl(dev, SIOCGIWRETRY, &iwr))
		return -1;

	*retry = iwr.u.retry.value;
	pr_debug("retry limit %d\n", *retry);

	return 0;
}

int qlink_wifi_set_ssid(struct net_device *dev, u8 *ssid, size_t len)
{
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	iwr.u.essid.flags = (len != 0);
	iwr.u.essid.pointer = ssid;
	iwr.u.essid.length = len;

	if (qlink_wext_ioctl(dev, SIOCSIWESSID, &iwr))
		return -1;

	return 0;
}

int qlink_wifi_set_rate(struct net_device *dev, s32 value, u8 fixed)
{
	struct iwreq iwr;

	pr_debug("setting rate: value[%d] fixed[%u]\n", value, fixed);

	memset(&iwr, 0, sizeof(iwr));
	iwr.u.bitrate.value = value;
	iwr.u.bitrate.fixed = fixed;

	if (qlink_wext_ioctl(dev, SIOCSIWRATE, &iwr))
		return -1;

	return 0;
}

int qlink_wifi_set_appie(struct net_device *dev, u32 frmtype, const u8 *buf, size_t buf_len)
{
	struct ieee80211req_getset_appiebuf *appie_req;
	const size_t req_buf_size = sizeof(*appie_req) + buf_len;
	int ret = 0;

	appie_req = kmalloc(req_buf_size, GFP_KERNEL);

	if (!appie_req)
		return -ENOMEM;

	appie_req->app_frmtype = frmtype;
	appie_req->flags = 0;
	appie_req->app_buflen = buf_len;

	if (buf_len > 0)
		memcpy(appie_req->app_buf, buf, buf_len);

	ret = qlink_wifi_setpriv(dev, IEEE80211_IOCTL_SET_APPIEBUF, appie_req,
		req_buf_size);

	kfree(appie_req);

	return ret;
}

int qlink_wifi_set_opt_ie(struct net_device *dev, const u8 *ies, size_t ies_len)
{
	return qlink_wifi_setpriv(dev, IEEE80211_IOCTL_SETOPTIE, ies, ies_len);
}

/* clear the SSIDs list */
int qlink_wifi_scan_ssid_clear(struct net_device *dev)
{
	struct iwreq iwr;
	char *tmpssid = "tmp";
	int ret;

	memset(&iwr, 0, sizeof(iwr));
	iwr.u.essid.pointer = tmpssid;
	iwr.u.essid.length = strlen(tmpssid);
	iwr.u.essid.flags = IEEE80211_SSID_OP_SCAN_CLEAR;

	ret = qlink_wext_ioctl(dev, SIOCSIWESSID, &iwr);
	if (ret < 0) {
		pr_err("SIOCSIWESSID::CLEAR ioctl failed: %d\n", ret);
		return ret;
	}

	return 0;
}

int qlink_wifi_scan_ssid_add(struct net_device *dev, u8 *ssid, u16 ssid_len)
{
	struct iwreq iwr;
	int ret;

	memset(&iwr, 0, sizeof(iwr));
	iwr.u.essid.pointer = ssid;
	iwr.u.essid.length = ssid_len;
	iwr.u.essid.flags = IEEE80211_SSID_OP_SCAN_ADD;

	ret = qlink_wext_ioctl(dev, SIOCSIWESSID, &iwr);
	if (ret < 0) {
		pr_err("SIOCSIWESSID::ADD ioctl failed: %d\n", ret);
		return ret;
	}

	return 0;
}

int qlink_wifi_scan_freq_set(struct net_device *dev,
			     struct ieee80211_scan_freqs *scan_freqs)
{
	struct iwreq iwr;
	int ret;

	if (!scan_freqs->num)
		return 0;

	memset(&iwr, 0, sizeof(iwr));
	iwr.u.data.flags = SIOCDEV_SUBIO_SET_SCAN_FREQS;
	iwr.u.data.pointer = scan_freqs;
	iwr.u.data.length = sizeof(*scan_freqs) +
		scan_freqs->num * sizeof(scan_freqs->freqs[0]);

	ret = qlink_wext_ioctl(dev, IEEE80211_IOCTL_EXT, &iwr);
	if (ret) {
		pr_err("SET_SCAN_FREQS ioctl failed: %d\n", ret);
		return ret;
	}

	return 0;
}

int qlink_wifi_associate(struct net_device *dev, u8 *bssid)
{
	struct ieee80211req_mlme mlme;

	memset(&mlme, 0, sizeof(mlme));
	mlme.im_op = IEEE80211_MLME_ASSOC;
	memcpy(mlme.im_macaddr, bssid, IEEE80211_ADDR_LEN);
	return qlink_wifi_setpriv(dev, IEEE80211_IOCTL_SETMLME, &mlme, sizeof(mlme));
}

int qlink_scs_ioctl(struct net_device *dev, uint32_t op, void *data, int len)
{
	struct ieee80211req_scs req;
	struct iwreq iwr;
	uint32_t reason;

	memset(&req, 0x0, sizeof(req));
	req.is_op = op;
	req.is_status = &reason;
	req.is_data = data;
	req.is_data_len = len;

	memset(&iwr, 0, sizeof(iwr));
	iwr.u.data.flags = SIOCDEV_SUBIO_SCS;
	iwr.u.data.pointer = &req;
	iwr.u.data.length = sizeof(req);

	if (qlink_wext_ioctl(dev, IEEE80211_IOCTL_EXT, &iwr)) {
		pr_err("SCS ioctl failed with reason=%d\n", reason);
		return -1;

	}

	return 0;
}

int qlink_wifi_scs_config(struct net_device *dev, unsigned int scs_cmd, int val)
{
	uint32_t cmd;
	int ret;

	cmd = (scs_cmd << IEEE80211_SCS_COMMAND_S) |
	      (val & IEEE80211_SCS_VALUE_M);

	ret = qlink_wifi_setparam(dev, IEEE80211_PARAM_SCS, cmd);
	if (ret)
		pr_warn("%s: SCS config failed: cmd=%u val=%d ret=%d\n",
			dev->name, scs_cmd, val, ret);

	return ret;
}

int qlink_phy_get_pta_param(struct net_device *dev, int param_id, int *param_val)
{
	struct iwreq iwr;
	uint32_t val = (param_id << PTA_CMD_PARAM_S) & PTA_CMD_PARAM_M;
	int ret;

	memset(&iwr, 0, sizeof(iwr));

	iwr.u.data.flags = SIOCDEV_SUBIO_GET_PTA_PARAM;
	iwr.u.data.pointer = &val;
	iwr.u.data.length = sizeof(val);

	ret = qlink_wext_ioctl(dev, IEEE80211_IOCTL_EXT, &iwr);
	if (ret < 0) {
		pr_err("IOCTL_EXT::GET_PTA_PARAM failed, ret=%d\n", ret);
		return ret;
	}

	/* exception for PTA mode, see qcsapi_pta_get_mode implementation */
	if (param_id == QTN_PTA_PARAM_MODE)
		*param_val = (val & PTA_CMD_PARAM_M) >> PTA_CMD_PARAM_S;
	else
		*param_val = val & PTA_CMD_VALUE_M;

	return 0;
}

int qlink_phy_set_pta_param(struct net_device *dev, int param_id, int param_val)
{
	struct iwreq iwr;
	uint32_t val;
	int mode;
	int ret;

	switch (param_id) {
	case QTN_PTA_PARAM_MODE:
		/* mode is already verified */
		break;

	case QTN_PTA_PARAM_REQ_POL:
	case QTN_PTA_PARAM_GNT_POL:
		/* verify polarity value */
		if (param_val != 0 && param_val != 1) {
			pr_err("invalid polarity\n");
			return -EINVAL;
		}

		/* polarity can be configured only when PTA is disabled */
		ret = qlink_phy_get_pta_param(dev, QTN_PTA_PARAM_MODE, &mode);
		if (ret)
			return ret;

		if (mode != PTA_MODE_DISABLED) {
			pr_err("PTA is enabled, cannot configure PTA polarity\n");
			return -EPERM;
		}
		break;

	case QTN_PTA_PARAM_REQ_TIMEOUT:
		if (param_val < PTA_PARAM_REQ_TIMEOUT_MIN ||
		    param_val > PTA_PARAM_REQ_TIMEOUT_MAX) {
			pr_err("invalid request timeout\n");
			return -EINVAL;
		}
		break;
	case QTN_PTA_PARAM_GNT_TIMEOUT:
		if (param_val < PTA_PARAM_GNT_TIMEOUT_MIN ||
		    param_val > PTA_PARAM_GNT_TIMEOUT_MAX) {
			pr_err("invalid grant timeout\n");
			return -EINVAL;
		}
		break;
	case QTN_PTA_PARAM_IFS_TIMEOUT:
		if (param_val < PTA_PARAM_IFS_TIMEOUT_MIN ||
		    param_val > PTA_PARAM_IFS_TIMEOUT_MAX) {
			pr_err("invalid IFS timeout\n");
			return -EINVAL;
		}
		break;
	default:
		pr_err("unknown parameter: %d\n", param_id);
		return -EOPNOTSUPP;
	}

	val = param_val & PTA_CMD_VALUE_M;
	val |= (param_id << PTA_CMD_PARAM_S) & PTA_CMD_PARAM_M;

	memset(&iwr, 0, sizeof(iwr));

	iwr.u.data.flags = SIOCDEV_SUBIO_SET_PTA_PARAM;
	iwr.u.data.pointer = &val;
	iwr.u.data.length = sizeof(val);

	ret = qlink_wext_ioctl(dev, IEEE80211_IOCTL_EXT, &iwr);
	if (ret < 0) {
		pr_err("IOCTL_EXT::SET_PTA_PARAM failed, ret=%d\n", ret);
		return ret;
	}

	return 0;
}

int qlink_wowlan_config(struct net_device *dev, u32 enable, const u8 *pkt, int len)
{
	struct ieee80211req_wowlan req;
	struct iwreq iwr;
	uint32_t value;
	int ret;
	u8 tmp;

#define WOWLAN_CMD_M	0xffff
#define WOWLAN_CMD_S	16

	/* enable/disable WoWLAN/BMPS */
	value = (IEEE80211_WOWLAN_HOST_POWER_SAVE << WOWLAN_CMD_S) |
		((enable ? 1 : 0) & WOWLAN_CMD_M);

	ret = qlink_wifi_setparam(dev, IEEE80211_PARAM_WOWLAN, value);
	if (ret < 0) {
		pr_err("WOWLAN PARAM ioctl failed: %d\n", ret);
		return ret;
	}

	/* set WoWLAN wakeup packet pattern */
	memset(&req, 0x0, sizeof(req));
	req.is_op = IEEE80211_WOWLAN_MAGIC_PATTERN;
	if (pkt) {
		req.is_data = (u8 *)pkt;
		req.is_data_len = len;
	} else {
		/* reset pattern: set length to 0 */
		req.is_data = &tmp;
		req.is_data_len = 0;
	}

	memset(&iwr, 0, sizeof(iwr));
	iwr.u.data.flags = SIOCDEV_SUBIO_WOWLAN;
	iwr.u.data.pointer = &req;
	iwr.u.data.length = sizeof(req);

	ret = qlink_wext_ioctl(dev, IEEE80211_IOCTL_EXT, &iwr);
	if (ret < 0) {
		pr_err("WOWLAN subioctl failed: %d\n", ret);
		return -1;

	}

	return 0;
}

int qlink_wifi_set_ampdu(struct net_device *dev, u8 ampdu)
{
	int ret;
	int val;

	/* AMPDU enabled => ADDBA request enabled */
	val = (ampdu) ? 0xFFFF : 0;

	ret = qlink_wifi_updparam(dev, IEEE80211_PARAM_GLOBAL_BA_CONTROL, val);
	if (ret)
		pr_warn("%s: AMPDU setup failed: val=%d ret=%d\n",
			dev->name, val, ret);

	return ret;
}

int qlink_wifi_set_amsdu(struct net_device *dev, u8 amsdu)
{
	int ret;

	ret = qlink_wifi_updparam(dev, IEEE80211_PARAM_TX_AMSDU, amsdu);
	if (ret)
		pr_warn("%s: AMSDU setup failed: val=%d ret=%d\n",
			dev->name, amsdu, ret);

	return ret;
}

int qlink_wifi_set_chan(struct net_device *dev, u16 ieee)
{
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	iwr.u.freq.m = ieee;
	iwr.u.freq.e = 0;

	if (qlink_wext_ioctl(dev, SIOCSIWFREQ, &iwr))
		return -1;

	return 0;
}

int qlink_wifi_init_txpwr_table(struct net_device *dev, unsigned int ieee, int pwr)
{
	int val = 0;

	val = ((ieee & 0xff) << 24) | ((ieee & 0xff) << 16) |
		((pwr & 0xff) << 8);

	return qlink_wifi_setparam(dev, IEEE80211_PARAM_INITIATE_TXPOWER_TABLE, val);
}

int qlink_wifi_set_reguatory_txpwr(struct net_device *dev, unsigned int ieee_start,
	unsigned int ieee_end, int pwr)
{
	int val;

	val = ((ieee_start & 0xff) << 16) | ((ieee_end & 0xff) << 8) | (pwr & 0xff);

	return qlink_wifi_setparam(dev, IEEE80211_PARAM_CONFIG_REGULATORY_TXPOWER, val);
}
