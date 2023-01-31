/**
 * Copyright (c) 2011-2017 Quantenna Communications Inc
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

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/moduleloader.h>
#include <linux/net/bridge/br_public.h>

#include <net80211/if_media.h>
#include <net80211/ieee80211_var.h>
#include <net80211/if_ethersubr.h>

#include <qtn/qtn_global.h>
#include "qtn/qvsp.h"
#include "qtn/qvsp_data.h"
#include "qvsp_private.h"
#include "qvsp_nl.h"
#include <qtn/iputil.h>

MODULE_DESCRIPTION("Video Stream Protection");
MODULE_AUTHOR("Quantenna Communications, Inc.");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

void
qvsp_reset(struct qvsp_c *qvsp)
{
	if (!qvsp || !qvsp_inactive_flag_cleared(qvsp)) {
		return;
	}

	qvsp_nl_strm_reset(qvsp);
}
EXPORT_SYMBOL(qvsp_reset);


#if TOPAZ_QTM

void qvsp_stats_node_update_begin(struct qvsp_c *qvsp, struct ieee80211_node *ni)
{
	qvsp_lock();
	if (qvsp)
		qvsp_nl_stats_node_update_begin(qvsp, ni);
}
EXPORT_SYMBOL(qvsp_stats_node_update_begin);

void qvsp_stats_node_update_end(struct qvsp_c *qvsp, struct ieee80211_node *ni)
{
	if (qvsp)
		qvsp_nl_stats_node_update_end(qvsp, ni);
	qvsp_unlock();
}
EXPORT_SYMBOL(qvsp_stats_node_update_end);

void qvsp_strm_tid_check_add(struct qvsp_c *qvsp, struct ieee80211_node *ni, uint8_t node, uint8_t tid,
		uint32_t pkts, uint32_t bytes, uint32_t sent_pkts, uint32_t sent_bytes)
{

	if (!qvsp || !qvsp_is_active(qvsp))
		return;

	qvsp_nl_stats_update_add(qvsp, ni, node, tid, pkts, bytes, sent_pkts, sent_bytes);

}
EXPORT_SYMBOL(qvsp_strm_tid_check_add);
#endif /* TOPAZ_QTM */

void qvsp_inactive_flag_update(struct qvsp_ext_s *qvsp_ext, uint32_t flag, int set)
{
	unsigned long irq_flags;
	unsigned long old_flags;
	unsigned long update = 0;

	if (qvsp_ext && flag) {
		local_irq_save(irq_flags);

		old_flags = qvsp_ext->inactive_flags;
		if (set) {
			qvsp_ext->inactive_flags |= flag;
		} else {
			qvsp_ext->inactive_flags &= ~flag;
		}

		local_irq_restore(irq_flags);

		update = ((old_flags == 0) != (qvsp_ext->inactive_flags == 0));
		if (update && qvsp_ext->flags_changed) {
			qvsp_ext->flags_changed(qvsp_ext);
		}
	}

	/* forward flag setting to server */
	if (qvsp_ext)
		qvsp_nl_inactive_flag_set((struct qvsp_c *)qvsp_ext, qvsp_ext->inactive_flags);
}
EXPORT_SYMBOL(qvsp_inactive_flag_update);

void qvsp_fat_set(struct qvsp_c *qvsp, uint32_t fat, uint32_t intf_ms, uint8_t chan)
{
	if (!qvsp || !qvsp_is_active(qvsp)) {
		return;
	}

	qvsp_lock();

	qvsp_nl_fat_set(qvsp, fat, intf_ms, chan);

	qvsp_unlock();

}
EXPORT_SYMBOL(qvsp_fat_set);

#ifdef TOPAZ_QTM_STA_CTRL
/*
 * Process a command on a STA from the AP to set stream state
 * The STA is to be supported in later versions of QTM
 */
void
qvsp_cmd_strm_state_set(struct qvsp_c *qvsp, uint8_t strm_state_char,
			const struct ieee80211_qvsp_strm_id *strm_id,
			struct ieee80211_qvsp_strm_dis_attr *attr)
{
}
EXPORT_SYMBOL(qvsp_cmd_strm_state_set);
#endif


void qvsp_inactive_flags_changed(struct qvsp_ext_s *qvsp_ext)
{
	struct qvsp_c *qvsp = (struct qvsp_c *)qvsp_ext;
	int new_active, active_changed;

	qvsp_lock();
	new_active = (qvsp_ext->inactive_flags == 0);
	active_changed = (new_active == !qvsp->is_active);
	qvsp->is_active = new_active;
	qvsp_unlock();

	if (active_changed)
		qvsp_nl_inactive_flag_set(qvsp, qvsp_ext->inactive_flags);
}

void qvsp_change_stamode(struct qvsp_c *qvsp, uint8_t stamode)
{
	int stamode_changed = 0;

	if (!qvsp)
		return;
	qvsp_lock();
	if (qvsp->stamode != stamode) {
		qvsp->stamode = stamode;
		stamode_changed = 1;
	}
	qvsp_unlock();
	if (stamode_changed)
		qvsp_nl_stamode_change(qvsp, stamode);
}
EXPORT_SYMBOL(qvsp_change_stamode);

void qvsp_node_init(struct ieee80211_node *ni)
{
	ni->ni_shared_stats->tx[STATS_SU].cost = QVSP_NODE_COST_DFLT;
	ni->ni_shared_stats->rx[STATS_SU].cost = QVSP_NODE_COST_DFLT;
	ni->ni_shared_stats->tx[STATS_MU].cost = QVSP_NODE_COST_DFLT;
	ni->ni_shared_stats->rx[STATS_MU].cost = QVSP_NODE_COST_DFLT;
	qvsp_nl_node_init(ni);
}
EXPORT_SYMBOL(qvsp_node_init);

/*
 * Remove all streams for a node
 */
void qvsp_node_del(struct qvsp_c *qvsp, struct ieee80211_node *ni)
{
	if (!qvsp || !qvsp_inactive_flag_cleared(qvsp)) {
		return;
	}

	qvsp_lock();
	qvsp_nl_node_del(qvsp, ni);
	qvsp_unlock();
}
EXPORT_SYMBOL(qvsp_node_del);

static struct qvsp_c *qvsp_alloc(void)
{
	struct qvsp_c *qvsp;

	qvsp = kmalloc(sizeof(*qvsp), GFP_KERNEL);

	if (qvsp) {
		memset(qvsp, 0, sizeof(*qvsp));
	}

	return qvsp;
}

static void qvsp_free(struct qvsp_c *qvsp)
{
	kfree(qvsp);
}

struct qvsp_c *
qvsp_init(int (*ioctl_fn)(void *ioctl_token, uint32_t ioctl_param, uint32_t ioctl_value),
		void *ioctl_fn_token, struct net_device *dev, uint8_t stamode,
		void (*cb_cfg)(void *token, uint32_t index, uint32_t value),
		void (*cb_strm_ctrl)(void *token, struct ieee80211_node *ni, uint8_t strm_state,
			struct ieee80211_qvsp_strm_id *strm_id,
			struct ieee80211_qvsp_strm_dis_attr *attr),
		void (*cb_strm_ext_throttler)(void *token, struct ieee80211_node *node,
			uint8_t strm_state, const struct ieee80211_qvsp_strm_id *strm_id,
			struct ieee80211_qvsp_strm_dis_attr *attr, uint32_t throt_intvl),
		_fn_qvsp_find_node cb_find_node,
		uint32_t ieee80211node_size, uint32_t ieee80211vap_size
		)
{
	struct qvsp_c *qvsp = NULL;
	struct qvsp_ext_s *qvsp_ext;

	BUILD_BUG_ON(offsetof(struct qvsp_c, qvsp_ext) != 0);

	/*
	 * Data structure sanity check to make sure what we see is same from other modules.
	 * This can be caused by different compile options in Makefile and is hard to debug.
	 */
	if ((sizeof(struct ieee80211_node) != ieee80211node_size) ||
		(sizeof(struct ieee80211vap) != ieee80211vap_size)) {
		printk("VSP Build error: different data structure size: node %u %u, vap %u %u\n",
				(unsigned int)sizeof(struct ieee80211_node), ieee80211node_size,
				(unsigned int)sizeof(struct ieee80211vap), ieee80211vap_size);
		return NULL;
	}

	qvsp = qvsp_alloc();
	if (!qvsp) {
		printk("%s: malloc failure\n", __FUNCTION__);
		return NULL;
	}

	qvsp->is_active = 0;

	qvsp->stamode = stamode;

	/* disable STA side control for QTM-Lite */
#ifdef TOPAZ_QTM_STA_CTRL
	qvsp->cb_cfg = cb_cfg;
	qvsp->cb_strm_ctrl = cb_strm_ctrl;
#endif

	qvsp->cb_strm_ext_throttler = cb_strm_ext_throttler;
	qvsp->cb_find_node = cb_find_node;

	qvsp_cfg_init(qvsp);

	dev_hold(dev);
	qvsp->dev = dev;

	qvsp->ioctl = ioctl_fn;
	qvsp->ioctl_token = ioctl_fn_token;

	qvsp_ext = (struct qvsp_ext_s *)qvsp;
	qvsp_ext->flags_changed  = qvsp_inactive_flags_changed;
	qvsp_ext->inactive_flags = (qvsp->cfg_param[0]) ? 0: QVSP_INACTIVE_CFG;

	qvsp_lock();
	qvsp_nl_service_init(qvsp);
	qvsp_unlock();

	return qvsp;
}
EXPORT_SYMBOL(qvsp_init);

void qvsp_exit(struct qvsp_c **qvspp, struct net_device *dev)
{
	struct qvsp_c *qvsp;

	if (!qvspp) {
		return;
	}

	qvsp = *qvspp;
	if (!(qvsp && qvsp->dev && qvsp->dev == dev)) {
		return;
	}

	qvsp_lock();

	qvsp_nl_service_exit(qvsp);

	qvsp_wrapper_exit();

	qvsp_disable(qvsp);

	dev_put(qvsp->dev);
	qvsp->dev = NULL;

	qvsp_free(qvsp);
	*qvspp = NULL;

	qvsp_unlock();
}
EXPORT_SYMBOL(qvsp_exit);

static int __init qvsp_mod_init(void)
{
	pr_info("QVSP module init\n");
	return qvsp_nl_bus_init();
}

static void __exit qvsp_mod_exit(void)
{
	pr_info("QVSP module exit\n");
	qvsp_nl_bus_exit();
}

module_init (qvsp_mod_init);
module_exit (qvsp_mod_exit);
