/**
 * Copyright (c) 2017 Quantenna Communications Inc
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

#include <net/genetlink.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/etherdevice.h>
#include <linux/spinlock.h>

#include "qtn/qvsp.h"
#include "qtn/qvsp_proto.h"
#include "qtn/qvsp_common.h"
#include "qvsp_private.h"
#include "qvsp_nl.h"
#include "qvsp_cfg.h"

static struct qtm_comm {
	uint32_t qvspd_pid;
	uint32_t qvspd_seq;
	struct net *qvspd_net;
	struct qvsp_c *qvsp;
	struct sk_buff_head qvsp_nl_queue;
	struct work_struct qvsp_nl_work;
	spinlock_t vsp_lock;
	uint32_t vsp_lock_taken;
} g_comm = {0};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,24)
#define GENL_SND_PORTID(x) (x)->snd_portid
#else
#define GENL_SND_PORTID(x) (x)->snd_pid
#endif

static struct nla_policy qvsp_genl_policy[QTM_ATTR_MAX + 1] = QTM_ATTR_POLICY;

static struct genl_family qvsp_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = QTM_GENL_FAMILY,
	.version = QTM_GENL_VERSION,
	.maxattr = QTM_ATTR_MAX, };

void qvsp_lock(void)
{
	if (!in_irq() && !in_softirq() && !irqs_disabled()) {
		spin_lock_bh(&g_comm.vsp_lock);
		g_comm.vsp_lock_taken++;
	}
}

void qvsp_unlock(void)
{
	if (g_comm.vsp_lock_taken) {
		g_comm.vsp_lock_taken--;
		spin_unlock_bh(&g_comm.vsp_lock);
	}
}

static void qvsp_nl_process(struct work_struct *work)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&g_comm.qvsp_nl_queue)))
		genlmsg_unicast(g_comm.qvspd_net, skb, skb->dest_port);
}

static DECLARE_WORK(qvsp_nl_work, qvsp_nl_process);

static void qvsp_nl_send(struct sk_buff *skb, void *hdr, uint32_t pid)
{
	genlmsg_end(skb, hdr);
	skb->dest_port = pid;
	skb_queue_tail(&g_comm.qvsp_nl_queue, skb);
	schedule_work(&qvsp_nl_work);
}

static void qvsp_nl_report_error(int rc, const char *funcname)
{
	pr_err("Error %d in %s\n", rc, funcname);
}

struct sk_buff *qvsp_nl_msg_new(u32 seq, int flags, u8 cmd, void **phdr)
{
	struct sk_buff *skb;
	void *msg_head;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL)
		return NULL;
	msg_head = genlmsg_put(skb, 0, seq, &qvsp_genl_family, flags, cmd);
	if (msg_head == NULL) {
		nlmsg_free(skb);
		return NULL;
	}
	*phdr = msg_head;
	return skb;
}

static int qvsp_nlcmd_register(struct sk_buff *recv_skb, struct genl_info *info)
{
	struct sk_buff *skb;
	int rc;
	void *msg_head;

	g_comm.qvspd_pid = GENL_SND_PORTID(info);
	g_comm.qvspd_seq = 0;
	g_comm.qvspd_net = genl_info_net(info);

	pr_info("QTM daemon registered\n");

	/* Send a confirmation message */
	skb = qvsp_nl_msg_new(info->snd_seq, NLM_F_REQUEST | NLM_F_ACK, QTM_CMD_REGISTER,
				 &msg_head);
	if (skb == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	qvsp_nl_send(skb, msg_head, GENL_SND_PORTID(info));

	qvsp_lock();
	/* If the daemon registers after VAP creation (e.g. when qtmd is restarted),
	 * start QTM service immediately, enabling kernel messages processing.
	 */
	if (g_comm.qvsp) {
		pr_info("Reenable QTM service\n");
		qvsp_nl_service_init(g_comm.qvsp);
	}
	qvsp_unlock();
	return 0;

out:	qvsp_nl_report_error(rc, __func__);
	return rc;
}

static int qvsp_nlcmd_unregister(struct sk_buff *recv_skb, struct genl_info *info)
{
	struct sk_buff *skb;
	int rc;
	void *msg_head;

	pr_info("QTM daemon unregistered\n");
	g_comm.qvspd_pid = 0;

	/* Send a confirmation message */
	skb = qvsp_nl_msg_new(info->snd_seq, NLM_F_REQUEST | NLM_F_ACK, QTM_CMD_UNREGISTER,
				 &msg_head);
	if (skb == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	qvsp_nl_send(skb, msg_head, GENL_SND_PORTID(info));
	return 0;

out:	qvsp_nl_report_error(rc, __func__);
	return rc;
}

static int qvsp_nlcmd_server_get(struct sk_buff *recv_skb, struct genl_info *info)
{
	struct sk_buff *skb;
	int rc;
	void *msg_head;

	skb = qvsp_nl_msg_new(info->snd_seq, NLM_F_REQUEST | NLM_F_ACK, QTM_CMD_SERVER_GET,
				 &msg_head);
	if (skb == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = nla_put_u32(skb, QTM_ATTR_PID, g_comm.qvspd_pid);
	if (rc != 0) {
		nlmsg_free(skb);
		goto out;
	}

	qvsp_nl_send(skb, msg_head, GENL_SND_PORTID(info));
	return 0;

out:	qvsp_nl_report_error(rc, __func__);
	return rc;
}

static int qvsp_nlcmd_cfg_cb(struct sk_buff *recv_skb, struct genl_info *info)
{

	struct nlattr *na;
	uint32_t index, value;

	/* Process the request */
	na = info->attrs[QTM_ATTR_CTL_INDEX];
	if (na) {
		index = *(uint32_t *)nla_data(na);
	} else {
		pr_err("%s: No attr QTM_ATTR_CTL_INDEX found\n", __func__);
		return -EINVAL;
	}

	na = info->attrs[QTM_ATTR_CTL_VALUE];
	if (na) {
		value = *(uint32_t *)nla_data(na);
	} else {
		pr_err("%s: No attr QTM_ATTR_CTL_VALUE found\n", __func__);
		return -EINVAL;
	}

	qvsp_lock();

	if (!g_comm.qvsp) {
		qvsp_unlock();
		return 0;
	}

	qvsp_invoke_cfg_cb(g_comm.qvsp, index, value);
	qvsp_unlock();

	return 0;
}

static int qvsp_nlcmd_throt_ext(struct sk_buff *recv_skb, struct genl_info *info)
{

	struct nlattr *na;
	struct qtm_throt_ext_params *throt;
	struct ieee80211_node *ni;
	struct ieee80211_qvsp_strm_id strm_id;
	struct ieee80211_qvsp_strm_dis_attr attr;

	na = info->attrs[QTM_ATTR_CTL_PARAM];
	if (na) {
		throt = nla_data(na);
	} else {
		pr_err("%s: No attr QTM_ATTR_CTL_PARAM found\n", __func__);
		return -EINVAL;
	}

	qvsp_lock();

	if (!g_comm.qvsp) {
		qvsp_unlock();
		return 0;
	}
	if (!g_comm.qvsp->cb_find_node) {
		qvsp_unlock();
		return 0;
	}

	ni = g_comm.qvsp->cb_find_node(g_comm.qvsp->ioctl_token, throt->macaddr);
	if (ni == NULL) {
		qvsp_unlock();
		/*
		 * When the node is not found, it is not necessary an error.
		 * The node might have been deleted while the message is delivered.
		 */
		return 0;
	}

	if (g_comm.qvsp->ioctl_token && g_comm.qvsp->cb_strm_ext_throttler) {
		memset(&strm_id, 0, sizeof(strm_id));
		strm_id.daddr.ipv4 = throt->ipv4_addr;
		memset(&attr, 0, sizeof(attr));
		attr.throt_rate = throt->throt_rate;

		g_comm.qvsp->cb_strm_ext_throttler(g_comm.qvsp->ioctl_token, ni,
				throt->strm_state, &strm_id, &attr,
				QVSP_CFG(g_comm.qvsp, STRM_TPUT_SMPL_MIN));

	}
	qvsp_unlock();

	return 0;
}

static void qvsp_netdbg_log(struct qvsp_c *qvsp, void *ndb, uint32_t ndb_size)
{
	if (qvsp->cb_logger) {
		qvsp->cb_logger(qvsp->ioctl_token, ndb, ndb_size);
	}
}

static int qvsp_nlcmd_netdbg_log(struct sk_buff *recv_skb, struct genl_info *info)
{

	struct nlattr *na;
	void *netdbg_info;
	uint32_t netdbg_info_len;

	na = info->attrs[QTM_ATTR_NETDBG_INFO];
	if (na) {
		netdbg_info = nla_data(na);
		netdbg_info_len = nla_len(na);
		qvsp_lock();
		if (!g_comm.qvsp) {
			qvsp_unlock();
			return 0;
		}
		qvsp_netdbg_log(g_comm.qvsp, netdbg_info, netdbg_info_len);
		qvsp_unlock();
	} else {
		pr_err("%s: No attr QTM_ATTR_NETDBG_INFO found\n", __func__);
		return -EINVAL;
	}

	return 0;
}

struct genl_ops qvsp_genl_ops[] = {
		{.cmd = QTM_CMD_REGISTER, .flags = 0, .policy = qvsp_genl_policy,
				.doit = qvsp_nlcmd_register, .dumpit = NULL,},
		{.cmd = QTM_CMD_UNREGISTER, .flags = 0, .policy = qvsp_genl_policy,
				.doit = qvsp_nlcmd_unregister, .dumpit = NULL,},
		{.cmd = QTM_CMD_CFG_CB, .flags = 0, .policy = qvsp_genl_policy,
				.doit = qvsp_nlcmd_cfg_cb, .dumpit = NULL,},
		{.cmd = QTM_CMD_THROT_EXT, .flags = 0, .policy = qvsp_genl_policy,
				.doit = qvsp_nlcmd_throt_ext, .dumpit = NULL,},
		{.cmd = QTM_CMD_SERVER_GET, .flags = 0, .policy = qvsp_genl_policy,
				.doit = qvsp_nlcmd_server_get, .dumpit = NULL,},
		{.cmd = QTM_CMD_NETDBG_LOG, .flags = 0, .policy = qvsp_genl_policy,
				.doit = qvsp_nlcmd_netdbg_log, .dumpit = NULL,},
};

int qvsp_nl_bus_init(void)
{
	int ret;

	memset(&g_comm, 0 , sizeof(g_comm));

	INIT_WORK(&g_comm.qvsp_nl_work, qvsp_nl_process);
	skb_queue_head_init(&g_comm.qvsp_nl_queue);
	g_comm.qvspd_net = &init_net;

	spin_lock_init(&g_comm.vsp_lock);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,24)
	ret = genl_register_family_with_ops(&qvsp_genl_family, qvsp_genl_ops);
#else
	ret = genl_register_family_with_ops(&qvsp_genl_family, qvsp_genl_ops,
					    ARRAY_SIZE(qvsp_genl_ops));
#endif
	if (ret != 0) {
		pr_err("Register QVSP NL family with ops: error %i\n", ret);
		return -1;
	}

	return 0;
}

void qvsp_nl_bus_exit(void)
{
	int ret;

	ret = genl_unregister_family(&qvsp_genl_family);
	cancel_work_sync(&g_comm.qvsp_nl_work);
	if (ret != 0) {
		pr_err("Unregister QVSP nl family: error %i\n", ret);
		return;
	}
}

int qvsp_nl_service_init(struct qvsp_c *qvsp)
{
	struct sk_buff *skb;
	int rc;
	void *msg_head;

	g_comm.qvsp = qvsp;

	if (g_comm.qvspd_pid == 0)
		return 0;

	skb = qvsp_nl_msg_new(g_comm.qvspd_seq++, 0, QTM_CMD_VAP_INIT,
				 &msg_head);
	if (skb == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = nla_put_u32(skb, QTM_ATTR_VAP_MODE, qvsp->stamode);
	if (rc != 0) {
		nlmsg_free(skb);
		goto out;
	}

	qvsp_nl_send(skb, msg_head, g_comm.qvspd_pid);

	/* Don't wait for reply here */
	/* Maybe create a flag and set it on receiving the status */
	return 0;

out:	qvsp_nl_report_error(rc, __func__);
	return rc;
}

void qvsp_nl_service_exit(struct qvsp_c *qvsp)
{
	struct sk_buff *skb;
	int rc;
	void *msg_head;

	if (g_comm.qvspd_pid == 0)
		return;

	skb = qvsp_nl_msg_new(g_comm.qvspd_seq++, 0, QTM_CMD_VAP_DEINIT,
				 &msg_head);
	if (skb == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	qvsp_nl_send(skb, msg_head, g_comm.qvspd_pid);
	/* Don't wait for reply here */

	g_comm.qvsp = NULL;

	return;

out:	qvsp_nl_report_error(rc, __func__);
}

static int qvsp_nl_msg_add_node_info(struct sk_buff *skb, struct ieee80211_node *ni)
{
	struct qtm_node_params node_info;

	node_info.node_idx = IEEE80211_NODE_IDX_UNMAP(ni->ni_node_idx);
	node_info.iv_pri = ni->ni_vap->iv_pri;
	node_info.vendor = ni->ni_vendor;
	node_info.vsp_version = ni->ni_vsp_version;
	node_info.has_qtn_assoc_ie = (ni->ni_qtn_assoc_ie != NULL);
	IEEE80211_ADDR_COPY(&node_info.macaddr, ni->ni_macaddr);
	node_info.tx_cost = ni->ni_shared_stats->tx[STATS_SU].cost;
	node_info.rx_cost = ni->ni_shared_stats->rx[STATS_SU].cost;
	node_info.ralg_inv_phy_rate = ni->ni_shared_stats->tx[STATS_SU].ralg_inv_phy_rate;
	node_info.inv_phy_rate_smoothed = ni->ni_shared_stats->rx[STATS_SU].inv_phy_rate_smoothed;
	return nla_put(skb, QTM_ATTR_NODE_INFO, sizeof(node_info), &node_info);
}

void qvsp_nl_stats_node_update_begin(struct qvsp_c *qvsp, struct ieee80211_node *ni)
{
	int rc;

	if (g_comm.qvspd_pid == 0)
		return;

	if (qvsp->stats_skb) {
		pr_err("%s: unsent stats skb dropped\n", __func__);
		nlmsg_free(qvsp->stats_skb);
	}

	qvsp->stats_skb = qvsp_nl_msg_new(g_comm.qvspd_seq++, 0, QTM_CMD_NODE_STATS,
				 &(qvsp->stats_msg_hdr));
	if (qvsp->stats_skb == NULL) {
		qvsp->stats_skb = NULL;
		rc = -ENOMEM;
		goto out;
	}

	memset(qvsp->tid_stats, 0, sizeof(qvsp->tid_stats));

	rc = qvsp_nl_msg_add_node_info(qvsp->stats_skb, ni);
	if (rc != 0) {
		nlmsg_free(qvsp->stats_skb);
		qvsp->stats_skb = NULL;
		rc = -ENOMEM;
		goto out;
	}

	return;

out:	qvsp_nl_report_error(rc, __func__);
}

void qvsp_nl_stats_update_add(struct qvsp_c *qvsp, struct ieee80211_node *ni, uint16_t node,
			      uint8_t tid, uint32_t pkts, uint32_t bytes, uint32_t sent_pkts,
			      uint32_t sent_bytes)
{
	const int tid2idx[] = QTN_VSP_STATS_TID2IDX;
	int idx = tid2idx[tid];

	if (g_comm.qvspd_pid == 0)
		return;

	qvsp->tid_stats[idx].tx_total_pkts = pkts;
	qvsp->tid_stats[idx].tx_total_bytes = bytes;
	qvsp->tid_stats[idx].tx_sent_pkts = sent_pkts;
	qvsp->tid_stats[idx].tx_sent_bytes = sent_bytes;
}

void qvsp_nl_stats_node_update_end(struct qvsp_c *qvsp, struct ieee80211_node *ni)
{
	if (g_comm.qvspd_pid == 0)
		return;
	if (qvsp->stats_skb == NULL) {
		pr_err("%s: stats skb not ready\n", __func__);
		return;
	}

	if (nla_put(qvsp->stats_skb, QTM_ATTR_TID_INFO,
			sizeof(qvsp->tid_stats), qvsp->tid_stats)) {
		nlmsg_free(qvsp->stats_skb);
		qvsp->stats_skb = NULL;
		pr_err("Error %d in %s\n", -ENOMEM, __func__);
		return;
	}

	qvsp_nl_send(qvsp->stats_skb, qvsp->stats_msg_hdr, g_comm.qvspd_pid);
	qvsp->stats_skb = NULL;
}

void qvsp_nl_fat_set(struct qvsp_c *qvsp, uint32_t fat, uint32_t intf_ms, uint8_t chan)
{
	int rc;
	void *msg_head;
	struct sk_buff *skb;
	struct qtm_fat_data fat_data;

	if (g_comm.qvspd_pid == 0)
		return;

	skb = qvsp_nl_msg_new(g_comm.qvspd_seq++, 0, QTM_CMD_FAT_SET,
				 &msg_head);
	if (skb == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	fat_data.fat = fat;
	fat_data.intf_ms = intf_ms;
	fat_data.chan = chan;

	rc = nla_put(skb, QTM_ATTR_FAT_INFO, sizeof(struct qtm_fat_data), &fat_data);
	if (rc != 0) {
		nlmsg_free(skb);
		goto out;
	}

	qvsp_nl_send(skb, msg_head, g_comm.qvspd_pid);

	return;

out:	qvsp_nl_report_error(rc, __func__);
}

void qvsp_nl_stats_node_del(struct qvsp_c *qvsp, struct ieee80211_node *ni)
{
	int rc;
	void *msg_head;
	struct sk_buff *skb;

	if (g_comm.qvspd_pid == 0)
		return;

	skb = qvsp_nl_msg_new(g_comm.qvspd_seq++, 0, QTM_CMD_STATS_NODE_DEL,
				 &msg_head);
	if (skb == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = qvsp_nl_msg_add_node_info(skb, ni);
	if (rc != 0) {
		nlmsg_free(skb);
		goto out;
	}

	qvsp_nl_send(skb, msg_head, g_comm.qvspd_pid);

	return;

out:	qvsp_nl_report_error(rc, __func__);
}

void qvsp_nl_cfg_set(struct qvsp_c *qvsp, uint32_t index, uint32_t value)
{
	int rc;
	void *msg_head;
	struct sk_buff *skb;

	if (g_comm.qvspd_pid == 0)
		return;

	skb = qvsp_nl_msg_new(g_comm.qvspd_seq++, 0, QTM_CMD_CFG_SET,
				 &msg_head);
	if (skb == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = nla_put_u32(skb, QTM_ATTR_CTL_INDEX, index);
	if (rc != 0) {
		nlmsg_free(skb);
		goto out;
	}

	rc = nla_put_u32(skb, QTM_ATTR_CTL_VALUE, value);
	if (rc != 0) {
		nlmsg_free(skb);
		goto out;
	}

	qvsp_nl_send(skb, msg_head, g_comm.qvspd_pid);

	return;

out:	qvsp_nl_report_error(rc, __func__);
}

void qvsp_nl_inactive_flag_set(struct qvsp_c *qvsp, uint32_t value)
{
	int rc;
	void *msg_head;
	struct sk_buff *skb;

	if (g_comm.qvspd_pid == 0)
		return;

	skb = qvsp_nl_msg_new(g_comm.qvspd_seq++, 0, QTM_CMD_INACTIVE_FLAGS_SET,
				 &msg_head);
	if (skb == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = nla_put_u32(skb, QTM_ATTR_CTL_VALUE, value);
	if (rc != 0) {
		nlmsg_free(skb);
		goto out;
	}

	qvsp_nl_send(skb, msg_head, g_comm.qvspd_pid);

	return;

out:	qvsp_nl_report_error(rc, __func__);
}

void qvsp_nl_stamode_change(struct qvsp_c *qvsp, uint8_t stamode)
{
	int rc;
	void *msg_head;
	struct sk_buff *skb;

	if (g_comm.qvspd_pid == 0)
		return;

	skb = qvsp_nl_msg_new(g_comm.qvspd_seq++, 0, QTM_CMD_STAMODE_SET,
				 &msg_head);
	if (skb == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = nla_put_u32(skb, QTM_ATTR_VAP_MODE, stamode);
	if (rc != 0) {
		nlmsg_free(skb);
		goto out;
	}

	qvsp_nl_send(skb, msg_head, g_comm.qvspd_pid);

	return;

out:	qvsp_nl_report_error(rc, __func__);
}

void qvsp_nl_node_init(struct ieee80211_node *ni)
{
	int rc;
	void *msg_head;
	struct sk_buff *skb;

	if (!g_comm.qvsp) {
		pr_info("%s: QVSP not initialized\n", __func__);
		return;
	}

	if (g_comm.qvspd_pid == 0)
		return;

	skb = qvsp_nl_msg_new(g_comm.qvspd_seq++, 0, QTM_CMD_NODE_INIT,
				 &msg_head);
	if (skb == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = qvsp_nl_msg_add_node_info(skb, ni);
	if (rc != 0) {
		nlmsg_free(skb);
		goto out;
	}

	qvsp_nl_send(skb, msg_head, g_comm.qvspd_pid);

	return;

out:	qvsp_nl_report_error(rc, __func__);
}

void qvsp_nl_node_del(struct qvsp_c *qvsp, struct ieee80211_node *ni)
{
	int rc;
	void *msg_head;
	struct sk_buff *skb;

	if (!g_comm.qvsp) {
		pr_info("%s: QVSP not initialized\n", __func__);
		return;
	}
	if (g_comm.qvspd_pid == 0)
		return;

	skb = qvsp_nl_msg_new(g_comm.qvspd_seq++, 0, QTM_CMD_NODE_DEL,
				 &msg_head);
	if (skb == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = qvsp_nl_msg_add_node_info(skb, ni);
	if (rc != 0) {
		nlmsg_free(skb);
		goto out;
	}

	qvsp_nl_send(skb, msg_head, g_comm.qvspd_pid);

	return;

out:	qvsp_nl_report_error(rc, __func__);
}

void qvsp_nl_strm_reset(struct qvsp_c *qvsp)
{
	int rc;
	void *msg_head;
	struct sk_buff *skb;

	if (g_comm.qvspd_pid == 0)
		return;

	skb = qvsp_nl_msg_new(g_comm.qvspd_seq++, 0, QTM_CMD_STRM_RESET,
				 &msg_head);
	if (skb == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	qvsp_nl_send(skb, msg_head, g_comm.qvspd_pid);

	return;

out:	qvsp_nl_report_error(rc, __func__);
}

void qvsp_nl_netdbg_init(struct qvsp_c *qvsp, uint32_t interval)
{
	int rc;
	void *msg_head;
	struct sk_buff *skb;

	if (g_comm.qvspd_pid == 0)
		return;

	skb = qvsp_nl_msg_new(g_comm.qvspd_seq++, 0, QTM_CMD_NETDBG_INIT,
				 &msg_head);
	if (skb == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = nla_put_u32(skb, QTM_ATTR_CTL_VALUE, interval);
	if (rc != 0) {
		nlmsg_free(skb);
		goto out;
	}

	qvsp_nl_send(skb, msg_head, g_comm.qvspd_pid);

	return;

out:	qvsp_nl_report_error(rc, __func__);
}

void qvsp_nl_netdbg_exit(struct qvsp_c *qvsp)
{
	int rc;
	void *msg_head;
	struct sk_buff *skb;

	if (g_comm.qvspd_pid == 0)
		return;

	skb = qvsp_nl_msg_new(g_comm.qvspd_seq++, 0, QTM_CMD_NETDBG_EXIT,
				 &msg_head);
	if (skb == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	qvsp_nl_send(skb, msg_head, g_comm.qvspd_pid);

	return;

out:	qvsp_nl_report_error(rc, __func__);
}
