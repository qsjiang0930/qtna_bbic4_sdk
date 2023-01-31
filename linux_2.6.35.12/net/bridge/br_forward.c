/*
 *	Forwarding decision
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/err.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netpoll.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <linux/netfilter_bridge.h>
#include "br_private.h"

static int br_ap_isolate_enabled = 0;
void br_set_ap_isolate(int enable) {
	br_ap_isolate_enabled = !!enable;
}
EXPORT_SYMBOL(br_set_ap_isolate);

int br_get_ap_isolate(void) {
	return br_ap_isolate_enabled;
}
EXPORT_SYMBOL(br_get_ap_isolate);

static inline int br_ap_isolate_should_forward(const struct net_bridge_port *p,
		const struct sk_buff *skb) {
	if (skb->dev == p->dev)
		return !br_ap_isolate_enabled && !QTN_FLAG_IS_INTRA_BSS(skb->dev->qtn_flags);

	if ((QTN_FLAG_IS_BSS_ISOLATE(skb->dev->qtn_flags) &&
		(p->dev->qtn_flags & QTN_FLAG_WIFI_DEVICE)) ||
		((skb->dev->qtn_flags & QTN_FLAG_WIFI_DEVICE)
		&& QTN_FLAG_IS_BSS_ISOLATE(p->dev->qtn_flags)))
		return 0;

	return 1;
}

static int deliver_clone(const struct net_bridge_port *prev,
			__u32 dest_port,
			struct sk_buff *skb,
			void (*__packet_hook)(const struct net_bridge_port *p,
				__u32 dest_port,
				struct sk_buff *skb));

static inline int br_src_port_filter_check(const struct net_bridge_port *p,
		 const struct sk_buff *skb, __u32 dest_port)
{
	return (p->flags & BR_HAIRPIN_MODE) || skb->dev != p->dev ||
			(dest_port && skb->src_port && skb->src_port != dest_port);
}

/* Don't forward packets to originating port or forwarding diasabled */
/* Unless the src_port and dest_port are different */
static inline int should_deliver(const struct net_bridge_port *p, __u32 dest_port,
				 const struct sk_buff *skb)
{
	return (p->state == BR_STATE_FORWARDING &&
			br_src_port_filter_check(p, skb, dest_port) &&
			br_ap_isolate_should_forward(p, skb));
}

static inline unsigned packet_length(const struct sk_buff *skb)
{
	return skb->len - (skb->protocol == htons(ETH_P_8021Q) ? VLAN_HLEN : 0);
}

int __sram_text br_dev_queue_push_xmit(struct sk_buff *skb)
{
	/* drop mtu oversized packets except gso */
	if (packet_length(skb) > skb->dev->mtu && !skb_is_gso(skb))
		kfree_skb(skb);
	else {
		/* ip_fragment doesn't copy the MAC header */
		if (nf_bridge_maybe_copy_header(skb))
			kfree_skb(skb);
		else {
			skb_push(skb, ETH_HLEN);
			dev_queue_xmit(skb);
		}
	}

	return 0;
}

int __sram_text br_forward_finish(struct sk_buff *skb)
{
	return NF_HOOK(NFPROTO_BRIDGE, NF_BR_POST_ROUTING, skb, NULL, skb->dev,
		       br_dev_queue_push_xmit);
}

static void __br_deliver(const struct net_bridge_port *to, __u32 dest_port, struct sk_buff *skb)
{
	skb->dev = to->dev;
	skb->dest_port = dest_port;

	if (unlikely(skb->ext_l2_filter && !br_is_wlan_dev(skb->dev))) {
		kfree_skb(skb);
		return;
	}

	NF_HOOK(NFPROTO_BRIDGE, NF_BR_LOCAL_OUT, skb, NULL, skb->dev,
		br_forward_finish);
}

static void __sram_text __br_forward(const struct net_bridge_port *to, __u32 dest_port, struct sk_buff *skb)
{
	struct net_device *indev;

	if (skb_warn_if_lro(skb)) {
		kfree_skb(skb);
		return;
	}

	indev = skb->dev;
	skb->dev = to->dev;
	skb->dest_port = dest_port;
	skb_forward_csum(skb);

	if (unlikely(skb->ext_l2_filter && !br_is_wlan_dev(skb->dev))) {
		kfree_skb(skb);
		return;
	}

	NF_HOOK(NFPROTO_BRIDGE, NF_BR_FORWARD, skb, indev, skb->dev,
		br_forward_finish);
}

/* called with rcu_read_lock */
void br_deliver(const struct net_bridge_port *to, __u32 dest_port, struct sk_buff *skb)
{
	if (should_deliver(to, dest_port, skb)) {
		__br_deliver(to, dest_port, skb);
		return;
	}

	kfree_skb(skb);
}

/* called with rcu_read_lock */
void br_forward(const struct net_bridge_port *to, __u32 dest_port,
	struct sk_buff *skb, struct sk_buff *skb0)
{
	if (should_deliver(to, dest_port, skb)) {
		if (skb0)
			deliver_clone(to, dest_port, skb, __br_forward);
		else
			__br_forward(to, dest_port, skb);
		return;
	}

	if (!skb0)
		kfree_skb(skb);
}

static int deliver_clone(const struct net_bridge_port *prev, __u32 dest_port,
			 struct sk_buff *skb,
			 void (*__packet_hook)(const struct net_bridge_port *p,
				__u32 dest_port,
				struct sk_buff *skb))
{
	struct net_device *dev = BR_INPUT_SKB_CB(skb)->brdev;

	skb = skb_clone(skb, GFP_ATOMIC);
	if (!skb) {
		dev->stats.tx_dropped++;
		return -ENOMEM;
	}

	__packet_hook(prev, dest_port, skb);
	return 0;
}

static struct net_bridge_port *maybe_deliver(
	struct net_bridge_port *prev, __u32 prev_subport,
	struct net_bridge_port *p, __u32 dest_port,
	struct sk_buff *skb,
	void (*__packet_hook)(const struct net_bridge_port *p,
			__u32 dest_port,
			struct sk_buff *skb))
{
	int err;

	if (!should_deliver(p, dest_port, skb))
		return prev;

	if (!prev)
		goto out;

	err = deliver_clone(prev, prev_subport, skb, __packet_hook);
	if (err)
		return ERR_PTR(err);

out:
	return p;
}

/* called under bridge lock */
static void br_flood(struct net_bridge *br, struct sk_buff *skb,
		     struct sk_buff *skb0,
		     void (*__packet_hook)(const struct net_bridge_port *p,
				__u32 dest_port,
				struct sk_buff *skb))
{
	struct net_bridge_port *p;
	struct net_bridge_port *prev;

	prev = NULL;

	list_for_each_entry_rcu(p, &br->port_list, list) {
		prev = maybe_deliver(prev, 0, p, 0, skb, __packet_hook);
		if (IS_ERR(prev)) {
			goto out;
		}
	}

	if (!prev)
		goto out;

	if (skb0)
		deliver_clone(prev, 0, skb, __packet_hook);
	else
		__packet_hook(prev, 0, skb);

	return;

out:
	if (!skb0)
		kfree_skb(skb);
}

#ifdef ARTSMNG_SUPPORT
/* called with rcu_read_lock */
void br_flood_deliver_to_one(struct net_bridge *br, struct sk_buff *skb)
{
	struct net_bridge_port *p;

	list_for_each_entry_rcu(p, &br->port_list, list) {
		if (should_deliver(p, skb->dest_port, skb)) {
			__br_deliver(p, skb->dest_port, skb);
			return;
		}
	}

	kfree_skb(skb);
}
#endif /* ARTSMNG_SUPPORT */

/* called with rcu_read_lock */
void br_flood_deliver(struct net_bridge *br, struct sk_buff *skb)
{
	br_flood(br, skb, NULL, __br_deliver);
}

/* called under bridge lock */
void br_flood_forward(struct net_bridge *br, struct sk_buff *skb,
		      struct sk_buff *skb2)
{
	br_flood(br, skb, skb2, __br_forward);
}

#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
static void br_multicast_bitmap_flood(struct net_bridge_port *port,
		uint32_t *port_bitmap, struct sk_buff *skb, void (*__packet_hook)(
				const struct net_bridge_port *p,
				__u32 subport,
				struct sk_buff *skb))
{
	int idx;
	int bit_idx;
	uint32_t sub_port_bitmap;

	for (idx = 0; idx < BR_SUB_PORT_BITMAP_SIZE; idx++) {
		bit_idx = 0;
		sub_port_bitmap = port_bitmap[idx];

		while (sub_port_bitmap) {
			if (sub_port_bitmap & 0x1) {
				__u32 subport = BR_SUBPORT_MAP(BR_SUBPORT(idx, bit_idx));
				maybe_deliver(port, subport, port, subport, skb, __packet_hook);
			}

			sub_port_bitmap >>= 1;
			bit_idx++;
		}
	}
}

static inline int br_get_sub_port(const struct net_bridge_port *port,
	       uint32_t *sub_port_bitmap, int size)
{
	int is_active;

	if (unlikely(!port || !port->dev))
		return 0;

	if (!br_is_wlan_dev(port->dev))
		return 0;

	if (!br_fdb_get_active_sub_port_hook)
		return 0;

	is_active = br_fdb_get_active_sub_port_hook(port, sub_port_bitmap, size);

	return is_active;
}

/* called with rcu_read_lock */
static void br_multicast_flood(struct net_bridge_mdb_entry *mdst,
			       struct sk_buff *skb, struct sk_buff *skb0,
			       void (*__packet_hook)(
					const struct net_bridge_port *p,
					__u32 dest_port,
					struct sk_buff *skb))
{
	struct net_device *dev = BR_INPUT_SKB_CB(skb)->brdev;
	struct net_bridge *br = netdev_priv(dev);
	struct net_bridge_port *prev = NULL;
	struct net_bridge_port_group *p;
	struct hlist_node *rp;
	__u32 prev_subport = 0;

	rp = rcu_dereference(br->router_list.first);
	p = mdst ? rcu_dereference(mdst->ports) : NULL;
	while (p || rp) {
		struct net_bridge_port *port, *lport, *rport;
		__u32 subport;

		lport = p ? p->port : NULL;
		rport = rp ? hlist_entry(rp, struct net_bridge_port, rlist) :
			     NULL;

		port = (unsigned long)lport > (unsigned long)rport ?
		       lport : rport;

		if (port == lport) {
			if (p)
				subport = p->sub_port;
			else
				subport = 0;

			prev = maybe_deliver(prev, prev_subport, port, subport, skb, __packet_hook);
			prev_subport = subport;
		} else if (BR_INPUT_SKB_CB_MROUTERS_ONLY(skb)) {
			if (port && br_is_wlan_dev(port->dev)) {
				br_multicast_bitmap_flood(port, port->router_port_bitmap,
						skb, __packet_hook);
			} else {
				prev = maybe_deliver(prev, prev_subport, port, 0, skb, __packet_hook);
				prev_subport = 0;
			}
		}

		if (IS_ERR(prev))
			goto out;

		if ((unsigned long)lport >= (unsigned long)port)
			p = rcu_dereference(p->next);
		if ((unsigned long)rport >= (unsigned long)port)
			rp = rcu_dereference(rp->next);
	}

	if (!prev)
		goto out;

	if (skb0)
		deliver_clone(prev, prev_subport, skb, __packet_hook);
	else
		__packet_hook(prev, prev_subport, skb);

	return;

out:
	if (!skb0)
		kfree_skb(skb);
}

/* called with rcu_read_lock */
void br_multicast_deliver(struct net_bridge_mdb_entry *mdst,
			  struct sk_buff *skb)
{
	br_multicast_flood(mdst, skb, NULL, __br_deliver);
}

/* called with rcu_read_lock */
void br_multicast_forward(struct net_bridge_mdb_entry *mdst,
			  struct sk_buff *skb, struct sk_buff *skb2)
{
	br_multicast_flood(mdst, skb, skb2, __br_forward);
}

static int br_should_exclude_mcast_member(struct net_bridge *br,
		struct net_bridge_mdb_entry *mp)
{
	if (!mp)
		return 0;

	if (br->report_flood_interval == BR_NEVER_FLOOD_REPORT)
		return 1;
	else if (br->report_flood_interval == BR_ALWAYS_FLOOD_REPORT)
		return 0;

	if (time_after(jiffies, mp->report_target_jiffies))
		return 0;

	if ((mp->report_flood_indicator >= br->report_flood_interval) && !mp->rx_specific_query)
		return 0;

	return 1;
}

static int br_exclude_mcast_member(struct net_bridge_mdb_entry *mp,
		struct net_bridge_port *port, uint32_t* sub_port_bitmap)
{
	struct net_bridge_port_group *p;
	struct net_bridge *br = port->br;
	int is_wlan_dev;
	int ret = 0;

	is_wlan_dev = br_is_wlan_dev(port->dev);

	spin_lock(&br->multicast_lock);
	for (p = mp->ports; p; p = p->next) {
		if (p->port == port) {
			if (!is_wlan_dev) {
				ret = 1;
				break;
			}
			br_reset_sub_port_bitmap(sub_port_bitmap, p->sub_port);
		}
	}
	spin_unlock(&br->multicast_lock);

	return ret;
}

void br_report_flood(struct net_bridge *br, struct net_bridge_mdb_entry *mp,
		struct sk_buff *skb)
{
	struct net_bridge_port *port;
	uint32_t sub_port_bitmap[BR_SUB_PORT_BITMAP_SIZE];
	int is_wlan_dev;
	int idx;

	list_for_each_entry_rcu(port, &br->port_list, list) {
		is_wlan_dev = br_is_wlan_dev(port->dev);
		if (!hlist_unhashed(&port->rlist) && !is_wlan_dev)
			continue;

		if (is_wlan_dev && !br_get_sub_port(port, sub_port_bitmap, sizeof(sub_port_bitmap)))
			continue;

		if (br_should_exclude_mcast_member(br, mp)) {
			if (br_exclude_mcast_member(mp, port, sub_port_bitmap))
				continue;
		}

		if (is_wlan_dev) {
			if (!hlist_unhashed(&port->rlist)) {
				for (idx = 0; idx < ARRAY_SIZE(sub_port_bitmap); idx++) {
					sub_port_bitmap[idx] |= port->router_port_bitmap[idx];
					sub_port_bitmap[idx] ^= port->router_port_bitmap[idx];
				}
			}
			br_multicast_bitmap_flood(port, sub_port_bitmap, skb, __br_forward);
		} else {
			maybe_deliver(port, 0, port, 0, skb, __br_forward);
		}
	}
}

void br_multicast_copy_to_sub_ports(struct net_bridge *br, struct net_bridge_mdb_entry *mdst,
		struct sk_buff *skb)
{
#if 0
	struct net_bridge_port *port;

	list_for_each_entry_rcu(port, &br->port_list, list) {
		if (!br_is_wlan_dev(port->dev)) {
			skb->dest_port = 0;
			maybe_deliver(port, port, skb, __br_forward);
		} else {
			struct net_bridge_port_group *p;
			uint32_t bmp[BR_SUB_PORT_BITMAP_SIZE];

			memset(bmp, 0, sizeof(bmp));

			for (p = mdst->ports; p != NULL; p = p->next) {
				if (p->port == port)
					br_set_sub_port_bitmap(bmp, p->sub_port);
			}

			br_multicast_bitmap_flood(port, bmp, skb, __br_forward);
		}
	}
#else
	struct net_bridge_port_group *pg;

	for (pg = mdst->ports; pg != NULL; pg = pg->next)
		maybe_deliver(pg->port, pg->sub_port, pg->port, pg->sub_port, skb, __br_forward);
#endif
}
#endif
