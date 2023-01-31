/**
 * Copyright (c) 2014 - 2017 Quantenna Communications Inc
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

#ifndef _QTN_VLAN_H_
#define _QTN_VLAN_H_

#include "../common/ruby_mem.h"
#include <qtn/qtn_debug.h>
#include <qtn/qtn_uc_comm.h>
#include <qtn/qtn_net_packet.h>
#if defined(__KERNEL__) || defined(MUC_BUILD) || defined(AUC_BUILD)
#include <qtn/topaz_tqe_cpuif.h>
#endif
#if defined(__KERNEL__)
#include <qtn/dmautil.h>
#endif

#define QVLAN_MODE_ACCESS		0
#define QVLAN_MODE_TRUNK		1
#define QVLAN_MODE_DYNAMIC		3
#define QVLAN_CMD_DEF_PRIORITY		4
#define QVLAN_MODE_MAX			QVLAN_CMD_DEF_PRIORITY
#define QVLAN_MODE_DISABLED		(QVLAN_MODE_MAX + 1)
#define QVLAN_SHIFT_MODE		16
#define QVLAN_MASK_MODE			0xffff0000
#define QVLAN_MASK_VID			0x00000fff

#define QVLAN_MODE(x)			(uint16_t)((x) >> QVLAN_SHIFT_MODE)
#define QVLAN_VID(x)			(uint16_t)((x) & QVLAN_MASK_VID)

#define QVLAN_MODE_STR_ACCESS	"Access mode"
#define QVLAN_MODE_STR_TRUNK	"Trunk mode"
#define QVLAN_MODE_STR_DYNAMIC	"Dynamic mode"

#define QVLAN_PRIO_VID			0
#define QVLAN_DEF_PVID			1

#define QVLAN_VID_MAX			4096
#define QVLAN_VID_MAX_S			12
#define QVLAN_VID_ALL			0xffff

#ifndef NBBY
#define NBBY		8
#endif

#ifndef NBDW
#define NBDW		32
#endif

#ifdef CONFIG_TOPAZ_DBDC_HOST
#define VLAN_INTERFACE_MAX	(QTN_MAX_VAPS + 2 + MAX_QFP_NETDEV)
#define QFP_VDEV_IDX(dev_id)	(QTN_MAX_VAPS + 2 + (dev_id))
#else
#define VLAN_INTERFACE_MAX	(QTN_MAX_VAPS + 2)
#endif
#define WMAC_VDEV_IDX_MAX	QTN_MAX_VAPS
#define EMAC_VDEV_IDX(port)	(QTN_MAX_VAPS + (port))
#define PCIE_VDEV_IDX		(QTN_MAX_VAPS + 0)

#ifndef howmany
#define howmany(x, y)			(((x) + ((y) - 1)) / (y))
#endif

#define bitsz_var(var)			(sizeof(var) * 8)
#define bitsz_ptr(ptr)			bitsz_var((ptr)[0])

#define set_bit_a(a, i)			((a)[(i) / bitsz_ptr(a)] |= 1 << ((i) % bitsz_ptr(a)))
#define clr_bit_a(a, i)			((a)[(i) / bitsz_ptr(a)] &= ~(1 << ((i) % bitsz_ptr(a))))
#define is_set_a(a, i)			((a)[(i) / bitsz_ptr(a)] & (1 << ((i) % bitsz_ptr(a))))
#define is_clr_a(a, i)			(is_set_a(a, i) == 0)

struct qtn_vlan_stats {
	uint32_t lhost;
	uint32_t muc;
};

struct qtn_vlan_user_interface {
	unsigned long bus_addr;
	uint8_t mode;
};

#define QVLAN_PRIO_MAX	7
struct qtn_vlan_dev {
	uint8_t		idx;
	uint8_t		port;
	uint16_t	pvid;
	uint16_t	priority;
#define QVLAN_DEV_F_DYNAMIC	BIT(0)
	uint16_t	flags;
	unsigned long	bus_addr;
	int		ifindex;
	union {
		uint32_t	member_bitmap[howmany(QVLAN_VID_MAX, NBDW)];
		uint16_t	node_vlan[QTN_NCIDX_MAX];
	}u;
	uint32_t	tag_bitmap[howmany(QVLAN_VID_MAX, NBDW)];
	struct qtn_vlan_stats ig_pass;
	struct qtn_vlan_stats ig_drop;
	struct qtn_vlan_stats eg_pass;
	struct qtn_vlan_stats eg_drop;
	struct qtn_vlan_stats stag_drop;
	struct qtn_vlan_stats magic_invalid;
	void		*user_data;
};
#define QVLAN_IS_DYNAMIC(vdev)		((vdev)->flags & QVLAN_DEV_F_DYNAMIC)

struct qtn_vlan_pkt {
#define QVLAN_PKT_MAGIC			0xf8
	uint8_t		magic;
#define QVLAN_PKT_TAGGED		BIT(0)
#define QVLAN_PKT_ZERO_TAGGED		BIT(1)
#define QVLAN_PKT_SKIP_CHECK		BIT(2)
	uint8_t	flag;
#define QVLAN_PKT_VID_MASK		0x0fff
#define QVLAN_PKT_PRIORITY_MASK		0xe000
#define QVLAN_PKT_PRIORITY_SHIFT	13
	uint16_t	vlan_info;
} __packed;

#define QVLAN_PKTCTRL_LEN	sizeof(struct qtn_vlan_pkt)

struct qtn_vlan_info {
#define QVLAN_TAGRX_UNTOUCH		0
#define QVLAN_TAGRX_STRIP		1
#define QVLAN_TAGRX_TAG			2
#define QVLAN_TAGRX_BITMASK		0x3
#define QVLAN_TAGRX_BITWIDTH		2
#define QVLAN_TAGRX_BITSHIFT		1
#define QVLAN_TAGRX_NUM_PER_DW		(32 / QVLAN_TAGRX_BITWIDTH)
#define QVLAN_TAGRX_NUM_PER_DW_S	4
	uint32_t vlan_tagrx_bitmap[howmany(QVLAN_VID_MAX * QVLAN_TAGRX_BITWIDTH, NBDW)];
};

RUBY_INLINE int qvlan_tagrx_index(int vid)
{
	return (vid >> QVLAN_TAGRX_NUM_PER_DW_S);
}

RUBY_INLINE int qvlan_tagrx_shift(int vid)
{
	int shift;

	shift = vid & (QVLAN_TAGRX_NUM_PER_DW - 1);
	return (shift << QVLAN_TAGRX_BITSHIFT);
}

/*
 * Must be in sync with qcsapi_vlan_config in qcsapi.h
 *  -- Whenever 'struct qtn_vlan_config' changes, qcsapi.h changes as well
 */
struct qtn_vlan_config {
	uint32_t	vlan_cfg;
	uint32_t	priority;
	uint32_t	drop_stag;
	union {
		struct vlan_dev_config {
			uint32_t	member_bitmap[howmany(QVLAN_VID_MAX, NBDW)];
			uint32_t	tag_bitmap[howmany(QVLAN_VID_MAX, NBDW)];
		} dev_config;
		uint32_t	tagrx_config[howmany(QVLAN_VID_MAX * QVLAN_TAGRX_BITWIDTH, NBDW)];
	} u;
};

RUBY_INLINE void qtn_vlan_config_htonl(struct qtn_vlan_config *vcfg, int tagrx)
{
	unsigned int i;

	vcfg->vlan_cfg = htonl(vcfg->vlan_cfg);
	vcfg->priority = htonl(vcfg->priority);

	if (tagrx) {
		for (i = 0; i < ARRAY_SIZE(vcfg->u.tagrx_config); i++)
			vcfg->u.tagrx_config[i] = htonl(vcfg->u.tagrx_config[i]);
	} else {
		for (i = 0; i < ARRAY_SIZE(vcfg->u.dev_config.member_bitmap); i++)
			vcfg->u.dev_config.member_bitmap[i] = htonl(vcfg->u.dev_config.member_bitmap[i]);

		for (i = 0; i < ARRAY_SIZE(vcfg->u.dev_config.tag_bitmap); i++)
			vcfg->u.dev_config.tag_bitmap[i] = htonl(vcfg->u.dev_config.tag_bitmap[i]);
	}
}

RUBY_INLINE void qtn_vlan_config_ntohl(struct qtn_vlan_config *vcfg, int tagrx)
{
	unsigned int i;

	vcfg->vlan_cfg = ntohl(vcfg->vlan_cfg);
	vcfg->priority = ntohl(vcfg->priority);

	if (tagrx) {
		for (i = 0; i < ARRAY_SIZE(vcfg->u.tagrx_config); i++)
			vcfg->u.tagrx_config[i] = ntohl(vcfg->u.tagrx_config[i]);
	} else {
		for (i = 0; i < ARRAY_SIZE(vcfg->u.dev_config.member_bitmap); i++)
			vcfg->u.dev_config.member_bitmap[i] = ntohl(vcfg->u.dev_config.member_bitmap[i]);

		for (i = 0; i < ARRAY_SIZE(vcfg->u.dev_config.tag_bitmap); i++)
			vcfg->u.dev_config.tag_bitmap[i] = ntohl(vcfg->u.dev_config.tag_bitmap[i]);
	}
}

/*
* VLAN forward/drop table
*|	traffic direction	|  frame	|  Access(MBSS/Dynamic mode)	  | Trunk(Passthrough mode)
*|--------------------------------------------------------------------------------------------------------------
*|	wifi tx			|  no vlan	|  drop				  | forward
*|--------------------------------------------------------------------------------------------------------------
*|				|  vlan tagged	| compare tag with PVID:	  | compare tag against VID list
*|				|		| 1.equal:untag and forward	  | 1.Found:forward
*|				|		| 2.not equal:drop		  | 2.Not found:drop
*|--------------------------------------------------------------------------------------------------------------
*|	wifi rx			|  no vlan	| Add PVID tag and forward	  | forward
*|--------------------------------------------------------------------------------------------------------------
*|				|  vlan tagged	| Compare tag with PVID:	  | compare tag against VID list
*|				|		| 1.equal:forward		  | 1. Found:forward
*|				|		| 2.not equal:drop		  | 2. Not found:drop
*|--------------------------------------------------------------------------------------------------------------
*/

#define QVLAN_BYTES_PER_VID		((QTN_MAX_BSS_VAPS + NBBY - 1) / NBBY)
#define QVLAN_BYTES_PER_VID_SHIFT	0

RUBY_INLINE int
qtn_vlan_is_valid(int vid)
{
	return (vid >= 0 && vid < QVLAN_VID_MAX);
}

RUBY_INLINE int
qtn_vlan_is_member(volatile struct qtn_vlan_dev *vdev, uint16_t vid)
{
	return !!is_set_a(vdev->u.member_bitmap, vid);
}

RUBY_INLINE int
qtn_vlan_is_tagged_member(volatile struct qtn_vlan_dev *vdev, uint16_t vid)
{
	return !!is_set_a(vdev->tag_bitmap, vid);
}

RUBY_INLINE int
qtn_vlan_is_pvid(volatile struct qtn_vlan_dev *vdev, uint16_t vid)
{
	return vdev->pvid == vid;
}

RUBY_INLINE int
qtn_vlan_is_mode(volatile struct qtn_vlan_dev *vdev, uint16_t mode)
{
	return ((struct qtn_vlan_user_interface *)vdev->user_data)->mode == mode;
}

RUBY_INLINE int
qtn_vlan_get_tagrx(uint32_t *tagrx_bitmap, uint16_t vlanid)
{
	return (tagrx_bitmap[vlanid >> QVLAN_TAGRX_NUM_PER_DW_S] >>
				((vlanid & (QVLAN_TAGRX_NUM_PER_DW - 1)) << QVLAN_TAGRX_BITSHIFT)) &
		QVLAN_TAGRX_BITMASK;
}

RUBY_INLINE void
qtn_vlan_gen_group_addr(uint8_t *mac, uint16_t vid, uint8_t vapid)
{
	uint16_t encode;

	mac[0] = 0xff;
	mac[1] = 0xff;
	mac[2] = 0xff;
	mac[3] = 0xff;

	encode = ((uint16_t)vapid << QVLAN_VID_MAX_S) | vid;
	mac[4] = encode >> 8;
	mac[5] = (uint8_t)(encode & 0xff);
}

RUBY_INLINE int
qtn_vlan_is_group_addr(const uint8_t *mac)
{
	return (mac[0] == 0xff && mac[1] == 0xff
		&& mac[2] == 0xff && mac[3] == 0xff
		&& mac[4] != 0xff);
}

#if defined(__KERNEL__) || defined(MUC_BUILD) || defined(AUC_BUILD)
RUBY_INLINE struct qtn_vlan_pkt*
qtn_vlan_get_info(const void *data)
{
	struct qtn_vlan_pkt *pkt;
#if defined(AUC_BUILD)
#pragma Off(Behaved)
#endif
	pkt = (struct qtn_vlan_pkt *)((const uint8_t *)data - QVLAN_PKTCTRL_LEN);
#if defined(AUC_BUILD)
#pragma On(Behaved)
#endif
	return pkt;
}

RUBY_INLINE void
qtn_vlan_inc_stats(struct qtn_vlan_stats *stats) {
#if defined(__KERNEL__)
	stats->lhost++;
#elif defined(MUC_BUILD)
	stats->muc++;
#endif
}

RUBY_INLINE int
qtn_vlan_magic_check(struct qtn_vlan_dev *outdev, struct qtn_vlan_pkt *pkt)
{
	if (unlikely(pkt->magic != QVLAN_PKT_MAGIC)) {
		qtn_vlan_inc_stats(&outdev->magic_invalid);
		return 0;
	}

	return 1;
}

RUBY_INLINE int
qtn_vlan_vlanid_check(struct qtn_vlan_dev *vdev, uint16_t ncidx, uint16_t vlanid)
{
	if (QVLAN_IS_DYNAMIC(vdev))
		return (vdev->u.node_vlan[ncidx] == vlanid);
	else
		return qtn_vlan_is_member(vdev, vlanid);
}

/*
 * VLAN encapsulation action table
 * | Frame Non-Zero tagged | Frame Zero tagged | Tx Tag | VLAN 0 Tx Tag | Action     |
 * | 0                     | 0                 | 0      | 0             | DONT_TOUCH |
 * | 0                     | 0                 | 0      | 1             | ADD_TAG_0  |
 * | 0                     | 0                 | 1      | 0             | ADD_TAG    |
 * | 0                     | 0                 | 1      | 1             | ADD_TAG    |
 * | 0                     | 1                 | 0      | 0             | STRIP      |
 * | 0                     | 1                 | 0      | 1             | DONT_TOUCH |
 * | 0                     | 1                 | 1      | 0             | REPLACE    |
 * | 0                     | 1                 | 1      | 1             | REPLACE    |
 * | 1                     | 0                 | 0      | 0             | STRIP      |
 * | 1                     | 0                 | 0      | 1             | REPLACE_0  |
 * | 1                     | 0                 | 1      | 0             | DONT_TOUCH |
 * | 1                     | 0                 | 1      | 1             | DONT_TOUCH |
 */
static const uint16_t qvlan_tx_actions[] = {
	TQE_MISCUSER_ANY2A_VLAN_UNTOUCH,
	TQE_MISCUSER_ANY2A_VLAN_TAG | TQE_MISCUSER_ANY2A_VLAN_TAG_VLAN0,
	TQE_MISCUSER_ANY2A_VLAN_TAG,
	TQE_MISCUSER_ANY2A_VLAN_TAG,

	TQE_MISCUSER_ANY2A_VLAN_UNTAG,
	TQE_MISCUSER_ANY2A_VLAN_UNTOUCH,
	TQE_MISCUSER_ANY2A_VLAN_REPLACE,
	TQE_MISCUSER_ANY2A_VLAN_REPLACE,

	TQE_MISCUSER_ANY2A_VLAN_UNTAG,
	TQE_MISCUSER_ANY2A_VLAN_REPLACE | TQE_MISCUSER_ANY2A_VLAN_TAG_VLAN0,
	TQE_MISCUSER_ANY2A_VLAN_UNTOUCH,
	TQE_MISCUSER_ANY2A_VLAN_UNTOUCH
};

RUBY_INLINE uint16_t
qtn_vlan_tx_action(struct qtn_vlan_dev *vdev, struct qtn_vlan_pkt *pkt)
{
	uint8_t index;
	uint16_t vlanid;

	if (unlikely(pkt->flag & QVLAN_PKT_SKIP_CHECK))
		return TQE_MISCUSER_ANY2A_VLAN_UNTOUCH;

	index = 0;
	vlanid = (pkt->vlan_info & QVLAN_PKT_VID_MASK);

	index |= (qtn_vlan_is_tagged_member(vdev, QVLAN_PRIO_VID) ? BIT(0): 0);
	index |= (qtn_vlan_is_tagged_member(vdev, vlanid) ? BIT(1) : 0);
	index |= ((pkt->flag & QVLAN_PKT_ZERO_TAGGED) ? BIT (2) : 0);
	index |= ((pkt->flag & QVLAN_PKT_TAGGED) ? BIT(3) : 0);

#if defined(AUC_BUILD)
	AUC_OS_ASSERT(index < ARRAY_SIZE(qvlan_tx_actions), "VLAN action invalid\n");
#elif defined(MUC_BUILD)
	OS_ASSERT(index < ARRAY_SIZE(qvlan_tx_actions), ("VLAN action invalid\n"));
#elif defined(__KERNEL__)
	KASSERT(index < ARRAY_SIZE(qvlan_tx_actions), ("VLAN action invalid\n"));
#endif

	return qvlan_tx_actions[index];
}

RUBY_INLINE int
qtn_vlan_egress(struct qtn_vlan_dev *outdev, uint16_t ncidx, void *data,
	uint16_t *vlan_miscuser, int cache_op)
{
	struct qtn_vlan_pkt *pkt = qtn_vlan_get_info(data);

	if (!qtn_vlan_magic_check(outdev, pkt)
			|| (pkt->flag & QVLAN_PKT_SKIP_CHECK)
			|| qtn_vlan_vlanid_check(outdev, ncidx, pkt->vlan_info & QVLAN_PKT_VID_MASK)) {
		qtn_vlan_inc_stats(&outdev->eg_pass);

		if (vlan_miscuser)
			*vlan_miscuser = qtn_vlan_tx_action(outdev, pkt);

		if (cache_op) {
#if defined(__KERNEL__)
			flush_and_inv_dcache_sizerange_safe(pkt, QVLAN_PKTCTRL_LEN);
#elif defined(MUC_BUILD)
			flush_and_inv_dcache_range_safe(pkt, QVLAN_PKTCTRL_LEN);
#endif
		}

		return 1;
	}

	qtn_vlan_inc_stats(&outdev->eg_drop);
	return 0;
}

#endif

#if defined(__KERNEL__) || defined(MUC_BUILD)
RUBY_INLINE int
qtn_vlan_should_drop_stag(struct qtn_vlan_dev *indev, void *data, uint8_t drop_stag)
{
	struct ether_header *eh = (struct ether_header *)data;

	if (unlikely(drop_stag && eh->ether_type == htons(ETHERTYPE_8021AD))) {
		qtn_vlan_inc_stats(&indev->stag_drop);
		return 1;
	}
	return 0;
}

RUBY_INLINE int
qtn_vlan_ingress(struct qtn_vlan_dev *indev, uint16_t ncidx, void *data,
		uint16_t known_vlan, uint16_t known_vlan_tci, uint8_t cache_op)
{
	struct ether_header *eh = (struct ether_header *)data;
	struct qtn_vlan_pkt *pkt;
	uint16_t vlan_tci = 0;
	uint16_t vlan_id = QVLAN_PRIO_VID;
	uint16_t flag = 0;

	if (eh->ether_type == htons(ETHERTYPE_8021Q)) {
		vlan_tci = ntohs(*(uint16_t *)(eh + 1));
		vlan_id = vlan_tci & QVLAN_PKT_VID_MASK;

		flag |= (vlan_id == QVLAN_PRIO_VID ? QVLAN_PKT_ZERO_TAGGED : QVLAN_PKT_TAGGED);

		if (vlan_id == QVLAN_PRIO_VID && known_vlan) {
			vlan_tci = known_vlan_tci;
			vlan_id = vlan_tci & QVLAN_PKT_VID_MASK;
		}
	} else if (known_vlan) {
		vlan_tci = known_vlan_tci;
		vlan_id = vlan_tci & QVLAN_PKT_VID_MASK;
	} else {
		vlan_tci = (indev->priority << QVLAN_PKT_PRIORITY_SHIFT);
	}

	if (vlan_id == QVLAN_PRIO_VID) {
		vlan_tci |= indev->pvid;
	} else if (!qtn_vlan_vlanid_check(indev, ncidx, vlan_id)) {
		qtn_vlan_inc_stats(&indev->ig_drop);
		return 0;
	}

	pkt = qtn_vlan_get_info(data);
	pkt->magic = QVLAN_PKT_MAGIC;
	pkt->flag = flag;
	pkt->vlan_info = vlan_tci;

	if (cache_op) {
#if defined(__KERNEL__)
		flush_and_inv_dcache_sizerange_safe(pkt, QVLAN_PKTCTRL_LEN);
#elif defined(MUC_BUILD)
		flush_and_inv_dcache_range_safe(pkt, QVLAN_PKTCTRL_LEN);
#endif
	}

	qtn_vlan_inc_stats(&indev->ig_pass);
	return 1;
}
#endif

#if defined(__KERNEL__)
extern uint8_t vlan_enabled;
extern uint8_t vlan_drop_stag;
extern struct qtn_vlan_dev *vdev_tbl_lhost[VLAN_INTERFACE_MAX];
extern struct qtn_vlan_dev *vdev_tbl_bus[VLAN_INTERFACE_MAX];
extern struct qtn_vlan_dev *vport_tbl_lhost[TOPAZ_TQE_NUM_PORTS];
extern struct qtn_vlan_dev *vport_tbl_bus[TOPAZ_TQE_NUM_PORTS];
extern struct qtn_vlan_info qtn_vlan_info;

extern struct qtn_vlan_dev *switch_alloc_vlan_dev(uint8_t port, uint8_t idx, int ifindex);
extern void switch_free_vlan_dev(struct qtn_vlan_dev *dev);
extern void switch_free_vlan_dev_by_idx(uint8_t idx);
extern struct qtn_vlan_dev *switch_vlan_dev_get_by_port(uint8_t port);
extern struct qtn_vlan_dev *switch_vlan_dev_get_by_idx(uint8_t idx);

extern int switch_vlan_add_member(struct qtn_vlan_dev *vdev, uint16_t vid, uint8_t tag);
extern int switch_vlan_del_member(struct qtn_vlan_dev *vdev, uint16_t vid);
extern int switch_vlan_tag_member(struct qtn_vlan_dev *vdev, uint16_t vid);
extern int switch_vlan_untag_member(struct qtn_vlan_dev *vdev, uint16_t vid);
extern int switch_vlan_set_pvid(struct qtn_vlan_dev *vdev, uint16_t vid);
extern int switch_vlan_set_priority(struct qtn_vlan_dev *vdev, uint8_t priority);

extern int switch_vlan_register_node(uint16_t ncidx, struct qtn_vlan_dev *vdev);
extern void switch_vlan_unregister_node(uint16_t ncidx);
extern struct qtn_vlan_dev *switch_vlan_dev_from_node(uint16_t ncidx);

/* dynamic VLAN support */
extern void switch_vlan_dyn_enable(struct qtn_vlan_dev *vdev);
extern void switch_vlan_dyn_disable(struct qtn_vlan_dev *vdev);
extern int switch_vlan_set_node(struct qtn_vlan_dev *vdev, uint16_t ncidx, uint16_t vlan);
extern int switch_vlan_clr_node(struct qtn_vlan_dev *vdev, uint16_t ncidx);

extern struct sk_buff *switch_vlan_to_proto_stack(struct sk_buff *);
extern struct sk_buff *switch_vlan_from_proto_stack(struct sk_buff *, struct qtn_vlan_dev *, uint16_t ncidx);
extern void switch_vlan_reset(void);
extern void switch_vlan_dev_reset(struct qtn_vlan_dev *vdev, uint8_t mode);
extern void switch_vlan_emac_to_lhost(uint32_t enable);
#endif

#endif
