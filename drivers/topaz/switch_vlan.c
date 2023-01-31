/**
 * Copyright (c) 2015 Quantenna Communications, Inc.
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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/spinlock.h>
#include <linux/net/bridge/br_public.h>

#include <net80211/if_ethersubr.h>
#include <qtn/topaz_tqe_cpuif.h>
#include <qtn/qtn_skb_cb.h>
#include <qtn/qtn_vlan.h>
#include <qtn/lhost_muc_comm.h>
#include <drivers/ruby/emac_lib.h>

__attribute__((section(".sram.data"))) uint8_t vlan_enabled;
EXPORT_SYMBOL(vlan_enabled);

__attribute__((section(".sram.data"))) uint8_t vlan_drop_stag;
EXPORT_SYMBOL(vlan_drop_stag);

__sram_data struct qtn_vlan_dev *vdev_tbl_lhost[VLAN_INTERFACE_MAX];
EXPORT_SYMBOL(vdev_tbl_lhost);

__sram_data struct qtn_vlan_dev *vdev_tbl_bus[VLAN_INTERFACE_MAX];
EXPORT_SYMBOL(vdev_tbl_bus);

__sram_data struct qtn_vlan_dev *vport_tbl_lhost[TOPAZ_TQE_NUM_PORTS];
EXPORT_SYMBOL(vport_tbl_lhost);

__sram_data struct qtn_vlan_dev *vport_tbl_bus[TOPAZ_TQE_NUM_PORTS];
EXPORT_SYMBOL(vport_tbl_bus);

struct qtn_vlan_info qtn_vlan_info;
EXPORT_SYMBOL(qtn_vlan_info);

static __sram_data uint8_t node2vap_tbl[QTN_NCIDX_MAX];

static DEFINE_SPINLOCK(lock);

#define		SWITCH_VLAN_PROC	"topaz_vlan"
#define		INVALID_VAP_IDX		0xff

#ifdef CONFIG_TOPAZ_DBDC_HOST
static enum topaz_tqe_port g_topaz_tqe_pcie_rel_port = TOPAZ_TQE_DROP_PORT;

void tqe_register_pcie_rel_port(const enum topaz_tqe_port tqe_port)
{
	g_topaz_tqe_pcie_rel_port = tqe_port;
}
EXPORT_SYMBOL(tqe_register_pcie_rel_port);

static inline int tqe_port_is_pcie(const enum topaz_tqe_port tqe_port)
{
	return (tqe_port == g_topaz_tqe_pcie_rel_port);
}
#endif

static inline void __switch_vlan_add_member(struct qtn_vlan_dev *vdev, uint16_t vid)
{
	set_bit_a(vdev->u.member_bitmap, vid);
}

static inline void __switch_vlan_del_member(struct qtn_vlan_dev *vdev, uint16_t vid)
{
	clr_bit_a(vdev->u.member_bitmap, vid);
}

static inline void __switch_vlan_tag_member(struct qtn_vlan_dev *vdev, uint16_t vid)
{
	set_bit_a(vdev->tag_bitmap, vid);
}

static inline void __switch_vlan_untag_member(struct qtn_vlan_dev *vdev, uint16_t vid)
{
	clr_bit_a(vdev->tag_bitmap, vid);
}

static inline void
switch_vlan_set_tagrx(struct qtn_vlan_info *vlan_info, uint16_t vlanid, uint8_t tagrx)
{
	uint32_t *tagrx_bitmap = vlan_info->vlan_tagrx_bitmap;
	tagrx = tagrx & QVLAN_TAGRX_BITMASK;

	tagrx_bitmap[qvlan_tagrx_index(vlanid)] &=
		~(QVLAN_TAGRX_BITMASK << qvlan_tagrx_shift(vlanid));

	tagrx_bitmap[qvlan_tagrx_index(vlanid)] |=
		tagrx << (qvlan_tagrx_shift(vlanid));
}

static inline int switch_vlan_manage_tagrx(struct qtn_vlan_dev *vdev,
		uint16_t vlanid, uint8_t tag, uint32_t member_quit)
{
	struct qtn_vlan_dev *other_dev;

	if (vdev->port == TOPAZ_TQE_EMAC_0_PORT)
		other_dev = vport_tbl_lhost[TOPAZ_TQE_EMAC_1_PORT];
	else if (vdev->port == TOPAZ_TQE_EMAC_1_PORT)
		other_dev = vport_tbl_lhost[TOPAZ_TQE_EMAC_0_PORT];
#ifdef CONFIG_TOPAZ_DBDC_HOST
	else if (tqe_port_is_pcie(vdev->port))
		return qtn_vlan_get_tagrx(qtn_vlan_info.vlan_tagrx_bitmap, vlanid);
#endif
	else if (vdev->port == TOPAZ_TQE_PCIE_PORT || vdev->port == TOPAZ_TQE_DSP_PORT) {
		other_dev = NULL;
	} else {
		return qtn_vlan_get_tagrx(qtn_vlan_info.vlan_tagrx_bitmap, vlanid);
	}

	if (other_dev && !member_quit
			&& qtn_vlan_is_member(other_dev, vlanid)
			&& qtn_vlan_is_tagged_member(other_dev, vlanid) != !!tag) {
		/*
		 * NOTE: All ethernet ports should have the same tag/untag config
		 * for one VLAN ID. This is to avoid confusion for multicast packets
		 * destined for multiple ethernet ports.
		 */
		printk(KERN_INFO"Warning:port %u forced to %s VLAN %u packets\n",
			other_dev->port, tag ? "tag" : "untag", vlanid);

		if (tag)
			__switch_vlan_tag_member(other_dev, vlanid);
		else
			__switch_vlan_untag_member(other_dev, vlanid);
	} else if (member_quit) {
		if (!other_dev || !qtn_vlan_is_member(other_dev, vlanid))
			return QVLAN_TAGRX_UNTOUCH;
		else
			return qtn_vlan_get_tagrx(qtn_vlan_info.vlan_tagrx_bitmap, vlanid);
	}

	return (tag ? QVLAN_TAGRX_TAG : QVLAN_TAGRX_STRIP);
}

static void switch_vlan_add(struct qtn_vlan_dev *vdev, uint16_t vlanid, uint8_t tag)
{
	int tagrx;

	if (!qtn_vlan_is_member(vdev, vlanid)) {
		__switch_vlan_add_member(vdev, vlanid);
	}

	/* update tag bitmap */
	if (tag)
		__switch_vlan_tag_member(vdev, vlanid);
	else
		__switch_vlan_untag_member(vdev, vlanid);

	tagrx = switch_vlan_manage_tagrx(vdev, vlanid, tag, 0);
	switch_vlan_set_tagrx(&qtn_vlan_info, vlanid, tagrx);
}

static void switch_vlan_del(struct qtn_vlan_dev *vdev, uint16_t vlanid)
{
	int tagrx;
	if (!qtn_vlan_is_member(vdev, vlanid))
		return;

	tagrx = switch_vlan_manage_tagrx(vdev, vlanid, 0, 1);
	switch_vlan_set_tagrx(&qtn_vlan_info, vlanid, tagrx);

	__switch_vlan_del_member(vdev, vlanid);
	__switch_vlan_untag_member(vdev, vlanid);
}

#ifdef CONFIG_TOPAZ_DBDC_HOST
static inline void update_vlan_tbl_for_dbdc(uint8_t port, uint8_t idx, int ifindex,
			uint32_t vdev, uint32_t bus_addr)
{
	if (ifindex > 0) {
		arc_write_uncached_32((uint32_t *)&vdev_tbl_lhost[idx], vdev);
		arc_write_uncached_32((uint32_t *)&vdev_tbl_bus[idx], bus_addr);
	} else {
		arc_write_uncached_32((uint32_t *)&vport_tbl_lhost[port], vdev);
		arc_write_uncached_32((uint32_t *)&vport_tbl_bus[port], bus_addr);
	}
}
#endif

struct qtn_vlan_dev *switch_alloc_vlan_dev(uint8_t port, uint8_t idx, int ifindex)
{
	struct qtn_vlan_dev *vdev = NULL;
	struct qtn_vlan_user_interface *vintf = NULL;
	dma_addr_t bus_addr, bus_addr2;

	spin_lock_bh(&lock);

	if (vdev_tbl_lhost[idx] != NULL)
		goto out;

	vdev = (struct qtn_vlan_dev *)dma_alloc_coherent(NULL,
		sizeof(struct qtn_vlan_dev), &bus_addr, GFP_ATOMIC);
	if (!vdev)
		goto out;

	memset(vdev, 0, sizeof(*vdev));
	vdev->pvid = QVLAN_DEF_PVID;
	vdev->bus_addr = (unsigned long)bus_addr;
	vdev->port = port;
	vdev->idx = idx;
	vdev->ifindex = ifindex;

	vintf = (struct qtn_vlan_user_interface *)dma_alloc_coherent(NULL,
		sizeof(struct qtn_vlan_user_interface), &bus_addr2, GFP_ATOMIC);
	if (!vintf)
		goto out;

	memset(vintf, 0, sizeof(*vintf));
	vintf->bus_addr = bus_addr2;
	vintf->mode = QVLAN_MODE_ACCESS;
	vdev->user_data = (void *)vintf;

#ifdef CONFIG_TOPAZ_DBDC_HOST
	/*
	 * On DBDC platform, there are max to 8 third party 2.4G VAPs behind pcie port,
	 * when TQE/MuC forward packet to such VAP, it don't use correct vdev of such
	 * VAP but use vport_tbl_lhost[pcie_port] to do egress check and always fail.
	 * To resolve this problem, qfp allocates a virtual vdev with ifindex 0 and only
	 * save it in vport_tbl_lhost[pcie_port], and qfp fills the member_bitmap of this
	 * vdev with 0xff. In this way, TQE/MuC always can forward packet to pcie port,
	 * qfp will retrieve the correct vdev and do egress check itself before deliver
	 * packet to third party driver.
	 * Details please refer to topaz_qfp.c & topaz_pcie_tqe.c under drivers/pcie2/tqe/
	 */
	if (tqe_port_is_pcie(port))
		update_vlan_tbl_for_dbdc(port, idx, ifindex, (uint32_t)vdev, (uint32_t)bus_addr);
	else
#endif
	{
		arc_write_uncached_32((uint32_t *)&vdev_tbl_lhost[idx], (uint32_t)vdev);
		arc_write_uncached_32((uint32_t *)&vdev_tbl_bus[idx], (uint32_t)bus_addr);

		if (TOPAZ_TQE_PORT_IS_WIRED(port)) {
			arc_write_uncached_32((uint32_t *)&vport_tbl_lhost[port], (uint32_t)vdev);
			arc_write_uncached_32((uint32_t *)&vport_tbl_bus[port], (uint32_t)bus_addr);
		}
	}

	switch_vlan_add(vdev, QVLAN_PRIO_VID, 0);
	switch_vlan_add(vdev, vdev->pvid, 0);

	spin_unlock_bh(&lock);
	return vdev;

out:
	if (vdev)
		dma_free_coherent(NULL, sizeof(struct qtn_vlan_dev), vdev, (dma_addr_t)(vdev->bus_addr));
	spin_unlock_bh(&lock);

	return NULL;
}
EXPORT_SYMBOL(switch_alloc_vlan_dev);

void switch_free_vlan_dev(struct qtn_vlan_dev *vdev)
{
	struct qtn_vlan_user_interface *vintf = (struct qtn_vlan_user_interface *)vdev->user_data;

	spin_lock_bh(&lock);
#ifdef CONFIG_TOPAZ_DBDC_HOST
	if (tqe_port_is_pcie(vdev->port))
		update_vlan_tbl_for_dbdc(vdev->port, vdev->idx, vdev->ifindex, 0, 0);
	else
#endif
	{
		/* vlan_info_tbl[info->idx] = NULL; */
		arc_write_uncached_32((uint32_t *)&vdev_tbl_lhost[vdev->idx], (uint32_t)NULL);
		arc_write_uncached_32((uint32_t *)&vdev_tbl_bus[vdev->idx], (uint32_t)NULL);

		if (TOPAZ_TQE_PORT_IS_WIRED(vdev->port)) {
			arc_write_uncached_32((uint32_t *)&vport_tbl_lhost[vdev->port], (uint32_t)NULL);
			arc_write_uncached_32((uint32_t *)&vport_tbl_bus[vdev->port], (uint32_t)NULL);
		}
	}
	spin_unlock_bh(&lock);

	dma_free_coherent(NULL, sizeof(struct qtn_vlan_dev), vdev, (dma_addr_t)(vdev->bus_addr));
	dma_free_coherent(NULL, sizeof(struct qtn_vlan_user_interface), vintf, (dma_addr_t)(vintf->bus_addr));
}
EXPORT_SYMBOL(switch_free_vlan_dev);

void switch_free_vlan_dev_by_idx(uint8_t idx)
{
	BUG_ON(idx >= VLAN_INTERFACE_MAX);

	switch_free_vlan_dev(vdev_tbl_lhost[idx]);
}
EXPORT_SYMBOL(switch_free_vlan_dev_by_idx);

struct qtn_vlan_dev*
switch_vlan_dev_get_by_port(uint8_t port)
{
#ifdef CONFIG_TOPAZ_DBDC_HOST
	uint8_t dev_id = EXTRACT_DEV_ID_FROM_PORT_ID(port);

	port = EXTRACT_PORT_ID_FROM_PORT_ID(port);

	if (tqe_port_is_pcie(port))
		return vdev_tbl_lhost[QFP_VDEV_IDX(dev_id)];
#endif
	return vport_tbl_lhost[port];
}
EXPORT_SYMBOL(switch_vlan_dev_get_by_port);

struct qtn_vlan_dev*
switch_vlan_dev_get_by_idx(uint8_t idx)
{
	return vdev_tbl_lhost[idx];
}
EXPORT_SYMBOL(switch_vlan_dev_get_by_idx);

typedef void (*_fn_vlan_member)(struct qtn_vlan_dev *vdev,
			uint16_t vid, uint8_t tag);
static int switch_vlan_member_comm(struct qtn_vlan_dev *vdev, uint16_t vid,
		uint8_t tag, _fn_vlan_member handler)
{
	if (vid == QVLAN_VID_ALL) {
		for (vid = 0; vid < QVLAN_VID_MAX; vid++)
			handler(vdev, vid, tag);
	} else if (vid < QVLAN_VID_MAX) {
		handler(vdev, vid, tag);
	} else {
		return -EINVAL;
	}

	return 0;
}

static void _vlan_add_member(struct qtn_vlan_dev *vdev, uint16_t vid, uint8_t tag)
{
	spin_lock_bh(&lock);
	switch_vlan_add(vdev, vid, tag);
	spin_unlock_bh(&lock);
}

int switch_vlan_add_member(struct qtn_vlan_dev *vdev, uint16_t vid, uint8_t tag)
{
	return switch_vlan_member_comm(vdev, vid, tag, _vlan_add_member);
}
EXPORT_SYMBOL(switch_vlan_add_member);

static void _vlan_del_member(struct qtn_vlan_dev *vdev, uint16_t vid, uint8_t arg)
{
	spin_lock_bh(&lock);
	switch_vlan_del(vdev, vid);
	spin_unlock_bh(&lock);
}

int switch_vlan_del_member(struct qtn_vlan_dev *vdev, uint16_t vid)
{
	return switch_vlan_member_comm(vdev, vid, 0, _vlan_del_member);
}
EXPORT_SYMBOL(switch_vlan_del_member);

static void _vlan_tag_member(struct qtn_vlan_dev *vdev, uint16_t vid, uint8_t arg)
{
	int tagrx;
	spin_lock_bh(&lock);
	if (!qtn_vlan_is_member(vdev, vid))
		goto out;

	__switch_vlan_tag_member(vdev, vid);
	tagrx = switch_vlan_manage_tagrx(vdev, vid, 1, 0);
	switch_vlan_set_tagrx(&qtn_vlan_info, vid, tagrx);
out:
	spin_unlock_bh(&lock);
}

int switch_vlan_tag_member(struct qtn_vlan_dev *vdev, uint16_t vid)
{
	return switch_vlan_member_comm(vdev, vid, 0, _vlan_tag_member);
}
EXPORT_SYMBOL(switch_vlan_tag_member);

static void _vlan_untag_member(struct qtn_vlan_dev *vdev, uint16_t vid, uint8_t arg)
{
	int tagrx;
	spin_lock_bh(&lock);
	if (!qtn_vlan_is_member(vdev, vid))
		goto out;

	__switch_vlan_untag_member(vdev, vid);
	tagrx = switch_vlan_manage_tagrx(vdev, vid, 0, 0);
	switch_vlan_set_tagrx(&qtn_vlan_info, vid, tagrx);
out:
	spin_unlock_bh(&lock);
}

int switch_vlan_untag_member(struct qtn_vlan_dev *vdev, uint16_t vid)
{
	return switch_vlan_member_comm(vdev, vid, 0, _vlan_untag_member);
}
EXPORT_SYMBOL(switch_vlan_untag_member);

static void __switch_vlan_set_pvid(struct qtn_vlan_dev *vdev, uint16_t vid)
{
	switch_vlan_del(vdev, vdev->pvid);
	switch_vlan_add(vdev, vid, 0);

	vdev->pvid = vid;
}

int switch_vlan_set_pvid(struct qtn_vlan_dev *vdev, uint16_t vid)
{
	if (vid >= QVLAN_VID_MAX)
		return -EINVAL;

	spin_lock_bh(&lock);
	__switch_vlan_set_pvid(vdev, vid);
	spin_unlock_bh(&lock);

	return 0;
}
EXPORT_SYMBOL(switch_vlan_set_pvid);

int switch_vlan_set_priority(struct qtn_vlan_dev *vdev, uint8_t priority)
{
	if (priority > QVLAN_PRIO_MAX)
		return -EINVAL;

	spin_lock_bh(&lock);
	vdev->priority = priority;
	spin_unlock_bh(&lock);

	return 0;
}
EXPORT_SYMBOL(switch_vlan_set_priority);

static void __switch_vlan_set_mode(struct qtn_vlan_dev *vdev, uint8_t mode)
{
	if (qtn_vlan_is_mode(vdev, mode))
		return;

	((struct qtn_vlan_user_interface *)vdev->user_data)->mode = mode;
}

int switch_vlan_set_mode(struct qtn_vlan_dev *vdev, uint8_t mode)
{
	if (mode >= QVLAN_MODE_MAX)
		return -EINVAL;

	spin_lock_bh(&lock);
	__switch_vlan_set_mode(vdev, mode);
	spin_unlock_bh(&lock);

	return 0;
}
EXPORT_SYMBOL(switch_vlan_set_mode);

static inline void __switch_vlan_clear_dev(struct qtn_vlan_dev *vdev)
{
	memset(&vdev->u, 0, sizeof(vdev->u));
	memset(&vdev->tag_bitmap, 0, sizeof(vdev->tag_bitmap));
	memset(&vdev->ig_pass, 0, sizeof(vdev->ig_pass));
	memset(&vdev->ig_drop, 0, sizeof(vdev->ig_drop));
	memset(&vdev->eg_pass, 0, sizeof(vdev->eg_pass));
	memset(&vdev->eg_drop, 0, sizeof(vdev->eg_drop));
	memset(&vdev->stag_drop, 0, sizeof(vdev->stag_drop));
	vdev->pvid = QVLAN_DEF_PVID;
	vdev->flags = 0;
	vdev->priority = 0;
}

void switch_vlan_dyn_enable(struct qtn_vlan_dev *vdev)
{
	spin_lock_bh(&lock);

	__switch_vlan_clear_dev(vdev);
	vdev->flags |= QVLAN_DEV_F_DYNAMIC;

	spin_unlock_bh(&lock);
}
EXPORT_SYMBOL(switch_vlan_dyn_enable);

void switch_vlan_dyn_disable(struct qtn_vlan_dev *vdev)
{
	spin_lock_bh(&lock);

	__switch_vlan_clear_dev(vdev);
	vdev->pvid = QVLAN_DEF_PVID;
	switch_vlan_add(vdev, vdev->pvid, 0);

	spin_unlock_bh(&lock);
}
EXPORT_SYMBOL(switch_vlan_dyn_disable);

int switch_vlan_set_node(struct qtn_vlan_dev *vdev, uint16_t ncidx, uint16_t vlanid)
{
	int ret = 0;

	spin_lock_bh(&lock);

	if (!QVLAN_IS_DYNAMIC(vdev)
			|| ncidx >= QTN_NCIDX_MAX
			|| !qtn_vlan_is_valid(vlanid)
			|| vdev->port != TOPAZ_TQE_WMAC_PORT) {
		ret = -EINVAL;
		goto out;
	}

	vdev->u.node_vlan[ncidx] = vlanid;

out:
	spin_unlock_bh(&lock);
	return ret;
}
EXPORT_SYMBOL(switch_vlan_set_node);

int switch_vlan_clr_node(struct qtn_vlan_dev *vdev, uint16_t ncidx)
{
	int ret = 0;

	spin_lock_bh(&lock);

	if (!QVLAN_IS_DYNAMIC(vdev)
			|| ncidx >= QTN_NCIDX_MAX
			|| vdev->port != TOPAZ_TQE_WMAC_PORT) {
		ret = -EINVAL;
		goto out;
	}

	vdev->u.node_vlan[ncidx] = QVLAN_VID_ALL;

out:
	spin_unlock_bh(&lock);
	return ret;
}
EXPORT_SYMBOL(switch_vlan_clr_node);

static struct sk_buff *switch_vlan_tag_pkt(struct sk_buff *skb, uint16_t vlan_tci)
{
	struct vlan_ethhdr *veth;
	struct qtn_vlan_pkt old;
	struct qtn_vlan_pkt *new;

	memcpy(&old, qtn_vlan_get_info(skb->data), sizeof(old));

	if (skb_cow_head(skb, VLAN_HLEN) < 0) {
		kfree_skb(skb);
		return NULL;
	}
	veth = (struct vlan_ethhdr *)skb_push(skb, VLAN_HLEN);

	/* Move the mac addresses to the beginning of the new header. */
	memmove(skb->data, skb->data + VLAN_HLEN, 2 * VLAN_ETH_ALEN);
	veth->h_vlan_proto = __constant_htons(ETH_P_8021Q);
	veth->h_vlan_TCI = htons(vlan_tci);

	new = qtn_vlan_get_info(skb->data);
	memcpy(new, &old, sizeof(*new));
	new->flag |= ((vlan_tci & QVLAN_MASK_VID) != QVLAN_PRIO_VID
			? QVLAN_PKT_TAGGED : QVLAN_PKT_ZERO_TAGGED);

	return skb;
}

static void switch_vlan_untag_pkt(struct sk_buff *skb)
{
	struct vlan_ethhdr *veth;
	struct qtn_vlan_pkt *pktinfo;

	veth = (struct vlan_ethhdr *)(skb->data);
	memmove((uint8_t *)veth - QVLAN_PKTCTRL_LEN + VLAN_HLEN,
		(uint8_t *)veth - QVLAN_PKTCTRL_LEN,
		QVLAN_PKTCTRL_LEN + 2 * VLAN_ETH_ALEN);

	skb_pull(skb, VLAN_HLEN);

	pktinfo = qtn_vlan_get_info(skb->data);
	pktinfo->flag &= ~(QVLAN_PKT_TAGGED | QVLAN_PKT_ZERO_TAGGED);
}

static void switch_vlan_replace_tag(struct sk_buff *skb, uint16_t vlan_tci)
{
	struct vlan_ethhdr *veth;
	struct qtn_vlan_pkt *pktinfo;

	veth = (struct vlan_ethhdr *)(skb->data);
	KASSERT(veth->h_vlan_proto == __constant_htons(ETH_P_8021Q),
		("802.1Q VLAN header is missing\n"));

	veth->h_vlan_TCI = htons(vlan_tci);

	pktinfo = qtn_vlan_get_info(skb->data);
	pktinfo->flag &= ~QVLAN_PKT_ZERO_TAGGED;
	pktinfo->flag |= QVLAN_PKT_TAGGED;
}

struct net_device *switch_vlan_find_br(struct net_device *ndev)
{
	struct net_device *brdev = NULL;

	if ((ndev->flags & IFF_SLAVE) && ndev->master)
		ndev = ndev->master;

	rcu_read_lock();
	if (rcu_dereference(ndev->br_port) != NULL)
		brdev = ndev->br_port->br->dev;
	rcu_read_unlock();

	return brdev;
}

/*
 * supposed to be called after eth_type_trans and before netif_receive_skb
 * VLAN ingress handling should be done already
 */
struct sk_buff *switch_vlan_to_proto_stack(struct sk_buff *skb)
{
	struct qtn_vlan_pkt *pkt;
	uint16_t vlan_id;
	struct net_device *brdev;
	int tag_in_frame;
	int prio_tag_in_frame;
	int should_tag;

	BUG_ON(!skb_mac_header_was_set(skb));

	if (!vlan_enabled)
		return skb;

	if (skb->protocol == __constant_htons(ETH_P_PAE))
		return skb;

	M_FLAG_SET(skb, M_ORIG_OUTSIDE);

	pkt = qtn_vlan_get_info(skb_mac_header(skb));

	tag_in_frame = !!(pkt->flag & QVLAN_PKT_TAGGED);
	prio_tag_in_frame = !!(pkt->flag & QVLAN_PKT_ZERO_TAGGED);
	vlan_id = (pkt->vlan_info & QVLAN_MASK_VID);

	brdev = switch_vlan_find_br(skb->dev);
	if (likely(brdev)) {
		should_tag = !!vlan_check_vlan_exist(brdev, vlan_id);
	} else {
		return skb;
	}

	if (tag_in_frame != should_tag || prio_tag_in_frame != should_tag) {
		skb_push(skb, ETH_HLEN);
		if (should_tag) {
			if (prio_tag_in_frame) {
				switch_vlan_replace_tag(skb, pkt->vlan_info);
			} else if (!tag_in_frame) {
				skb = switch_vlan_tag_pkt(skb, pkt->vlan_info);
			}
		} else {
			switch_vlan_untag_pkt(skb);
		}

		if (skb)
			skb->protocol = eth_type_trans(skb, skb->dev);
	}

	return skb;
}
EXPORT_SYMBOL(switch_vlan_to_proto_stack);

static void switch_vlan_add_pktinfo(struct sk_buff *skb)
{
	struct qtn_vlan_pkt *pktinfo;

	KASSERT(skb_headroom(skb) >= QVLAN_PKTCTRL_LEN, ("Not enough head room"));

	pktinfo = qtn_vlan_get_info(skb->data);
	pktinfo->magic = QVLAN_PKT_MAGIC;
	pktinfo->flag = 0;

	M_FLAG_SET(skb, M_VLAN_TAGGED);
}

struct sk_buff *switch_vlan_from_proto_stack(struct sk_buff *skb, struct qtn_vlan_dev *outdev,
	uint16_t ncidx)
{
	struct qtn_vlan_pkt *pktinfo;
	struct vlan_ethhdr *veth;
	uint16_t vlan_tci;
	uint16_t vlan_miscuser;
	struct sk_buff *skb2;

	if (!vlan_enabled)
		return skb;

	skb2 = skb_copy_expand(skb, QVLAN_PKTCTRL_LEN * 2 + VLAN_HLEN,
		skb_tailroom(skb), GFP_ATOMIC);
	dev_kfree_skb(skb);
	skb = skb2;

	if (!skb)
		return NULL;

	if (!M_FLAG_ISSET(skb, M_ORIG_OUTSIDE)) {
		/*
		 * The packet is generated by the device.
		 * A qtn_vlan_pkt structure is needed.
		 */
		switch_vlan_add_pktinfo(skb);

		pktinfo = qtn_vlan_get_info(skb->data);

		if (M_FLAG_ISSET(skb, M_ORIG_BR)) {
			veth = (struct vlan_ethhdr *)(skb->data);

			if (veth->h_vlan_proto == __constant_htons(ETH_P_8021Q)) {
				vlan_tci = ntohs(veth->h_vlan_TCI);
				pktinfo->flag |= QVLAN_PKT_TAGGED;
				pktinfo->vlan_info = vlan_tci;
			} else {
				pktinfo->flag |= QVLAN_PKT_SKIP_CHECK;
			}
		} else {
			pktinfo->flag |= QVLAN_PKT_SKIP_CHECK;
		}
	}

	if (!qtn_vlan_egress(outdev, ncidx, skb->data, &vlan_miscuser, 0))
		goto drop_out;

	pktinfo = qtn_vlan_get_info(skb->data);
	vlan_tci = pktinfo->vlan_info;

	if (vlan_miscuser & TQE_MISCUSER_ANY2A_VLAN_UNTAG)
		switch_vlan_untag_pkt(skb);

	if (vlan_miscuser & TQE_MISCUSER_ANY2A_VLAN_TAG) {
		if (vlan_miscuser & TQE_MISCUSER_ANY2A_VLAN_TAG_VLAN0)
			vlan_tci = QVLAN_PRIO_VID | (vlan_tci & ~QVLAN_MASK_VID);

		skb = switch_vlan_tag_pkt(skb, vlan_tci);
	}

	if (!skb)
		return NULL;

	/* Mark the skb as SKIP_CHECK so AuC won't do repeated work */
	pktinfo = qtn_vlan_get_info(skb->data);
	pktinfo->flag |= QVLAN_PKT_SKIP_CHECK;

	return skb;
drop_out:
	kfree_skb(skb);
	return NULL;
}
EXPORT_SYMBOL(switch_vlan_from_proto_stack);

static int switch_vlan_stats_rd(char *page, char **start, off_t offset,
		int count, int *eof, void *data)
{
	char *p = page;
	struct qtn_vlan_dev *vdev;
	struct net_device *ndev;
	int i;

	spin_lock_bh(&lock);

	for (i = 0; i < VLAN_INTERFACE_MAX; i++) {
		vdev = vdev_tbl_lhost[i];
		if (!vdev)
			continue;

		ndev = dev_get_by_index(&init_net, vdev->ifindex);
		if (unlikely(!ndev))
			continue;

		p += sprintf(p, "%s\ti-pass\t\te-pass\t\ti-drop\t\te-drop\t\tstag-drop\t\t"
				"magic-invalid\n", ndev->name);
		p += sprintf(p, "Lhost\t%u\t\t%u\t\t%u\t\t%u\t\t%u\t\t%u\n",
				vdev->ig_pass.lhost, vdev->eg_pass.lhost,
				vdev->ig_drop.lhost, vdev->eg_drop.lhost,
				vdev->stag_drop.lhost, vdev->magic_invalid.lhost);
		p += sprintf(p, "MuC\t%u\t\t%u\t\t%u\t\t%u\t\t%u\t\t%u\n",
				vdev->ig_pass.muc, vdev->eg_pass.muc,
				vdev->ig_drop.muc, vdev->eg_drop.muc,
				vdev->stag_drop.muc, vdev->magic_invalid.muc);

		dev_put(ndev);
	}

	spin_unlock_bh(&lock);

	*eof = 1;
	return p - page;
}

void switch_vlan_dev_reset(struct qtn_vlan_dev *vdev, uint8_t mode)
{
	uint32_t i;

	spin_lock_bh(&lock);
	for (i = 0; i < QVLAN_VID_MAX; i++) {
		if (qtn_vlan_is_member(vdev, i))
			switch_vlan_del(vdev, i);
	}

	memset(vdev->u.member_bitmap, 0, sizeof(vdev->u.member_bitmap));
	memset(vdev->tag_bitmap, 0, sizeof(vdev->tag_bitmap));

	switch_vlan_add(vdev, QVLAN_PRIO_VID, 0);
	__switch_vlan_set_pvid(vdev, QVLAN_DEF_PVID);
	__switch_vlan_set_mode(vdev, mode);

	vdev->priority = 0;

	spin_unlock_bh(&lock);
}
EXPORT_SYMBOL(switch_vlan_dev_reset);

void switch_vlan_reset(void)
{
	uint32_t i;

	for (i = 0; i < VLAN_INTERFACE_MAX; i++) {
		if (vdev_tbl_lhost[i])
			switch_vlan_dev_reset(vdev_tbl_lhost[i], QVLAN_MODE_ACCESS);
	}
}
EXPORT_SYMBOL(switch_vlan_reset);

int switch_vlan_register_node(uint16_t ncidx, struct qtn_vlan_dev *vdev)
{
	if (unlikely(ncidx >= ARRAY_SIZE(node2vap_tbl)))
		return -EINVAL;

	node2vap_tbl[ncidx] = vdev->idx;

	return 0;
}
EXPORT_SYMBOL(switch_vlan_register_node);

void switch_vlan_unregister_node(uint16_t ncidx)
{
	node2vap_tbl[ncidx] = INVALID_VAP_IDX;
}
EXPORT_SYMBOL(switch_vlan_unregister_node);

struct qtn_vlan_dev *switch_vlan_dev_from_node(uint16_t ncidx)
{
	if (node2vap_tbl[ncidx] == INVALID_VAP_IDX)
		return NULL;

	return vdev_tbl_lhost[node2vap_tbl[ncidx]];
}
EXPORT_SYMBOL(switch_vlan_dev_from_node);

static int __init switch_vlan_module_init(void)
{
	if (!create_proc_read_entry(SWITCH_VLAN_PROC, 0,
			NULL, switch_vlan_stats_rd, 0))
		return -EEXIST;

	memset(node2vap_tbl, INVALID_VAP_IDX, sizeof(node2vap_tbl));

	return 0;
}

static void __exit switch_vlan_module_exit(void)
{
	remove_proc_entry(SWITCH_VLAN_PROC, 0);
}

module_init(switch_vlan_module_init);
module_exit(switch_vlan_module_exit);

MODULE_DESCRIPTION("VLAN control panel");
MODULE_AUTHOR("Quantenna");
MODULE_LICENSE("GPL");
