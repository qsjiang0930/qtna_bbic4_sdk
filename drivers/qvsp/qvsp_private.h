/* Copyright (c) 2011-2017 Quantenna Communications Inc.
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

#ifndef _QVSP_PRIVATE_H_
#define _QVSP_PRIVATE_H_

#include <net80211/if_media.h>
#include <net80211/ieee80211_var.h>

#include "qtn/qvsp.h"
#include <qtn/qvsp_common.h>
#include <qtn/qvsp_data.h>
#include <net/iw_handler.h>

#define QVSP_CFG(_qvsp, _name)	(_qvsp->cfg_param[QVSP_CFG_##_name])

/* QVSP client (kernel part of the service) */
struct qvsp_c {
	/* qvsp_ext must be first for external references from qvsp.h */
	struct qvsp_ext_s qvsp_ext;

	uint32_t is_active;
	uint32_t cfg_param[QVSP_CFG_MAX];
	struct net_device *dev;
	void *wme_token;

	struct qtm_tid_stats tid_stats[QTN_VSP_STATS_TID_NUM];
	struct sk_buff *stats_skb;
	void *stats_msg_hdr;	/* genl user-specific header of stats_skb */

	uint8_t stamode;
	void (*cb_cfg)(void *token, uint32_t index, uint32_t value);
	void (*cb_strm_ctrl)(void *token, struct ieee80211_node *node,
			uint8_t strm_state, struct ieee80211_qvsp_strm_id *strm_id,
			struct ieee80211_qvsp_strm_dis_attr *attr);
	void (*cb_logger)(void *token, void *vsp_data, uint32_t size);

	int (*cb_ba_throt)(struct ieee80211_node *ni, int32_t tid, int intv, int dur, int win_size);
	int (*cb_wme_throt)(void *token, uint32_t ac, uint32_t enable,
					uint32_t aifsn, uint32_t ecwmin, uint32_t ecwmax, uint32_t txoplimit,
					uint32_t add_qwme_ie);
	void (*cb_strm_ext_throttler)(void *token, struct ieee80211_node *node,
			uint8_t strm_state, const struct ieee80211_qvsp_strm_id *strm_id,
			struct ieee80211_qvsp_strm_dis_attr *attr, uint32_t throt_intvl);
	void					*ioctl_token;
	int (*ioctl)(void *ioctl_token, uint32_t ioctl_param, uint32_t ioctl_value);
	_fn_qvsp_find_node cb_find_node;
};

void qvsp_cfg_init(struct qvsp_c *qvsp);
int qvsp_enable(struct qvsp_c *qvsp);

#endif
