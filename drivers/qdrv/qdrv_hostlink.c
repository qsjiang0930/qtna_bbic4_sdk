/**
  Copyright (c) 2008 - 2013 Quantenna Communications Inc
  All Rights Reserved

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

 **/

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/version.h>

#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include "qdrv_features.h"
#include "qdrv_debug.h"
#include "qdrv_mac.h"
#include "qdrv_soc.h"
#include "qdrv_comm.h"
#include "qdrv_wlan.h"
#include "qdrv_vap.h"
#include "qdrv_uc_print.h"
#include <qtn/qtn_global.h>

#ifdef MTEST
#include "../mtest/mtest.h"
#endif

#define QDRV_MAX_IOCTL_FAIL_DIE 5

static void dump_hring(struct qdrv_wlan *qw)
{
	int i = 0;
	struct host_ioctl *ioctl;
	struct host_ioctl *ioctl_phys;

	DBGPRINTF(DBG_LL_CRIT, QDRV_LF_HLINK,
			"HLINK State Write %d Tosend %d Read %d First %p Last %p Mbx %p\n",
			qw->tx_if.hl_write, qw->tx_if.hl_tosend, qw->tx_if.hl_read,
			qw->tx_if.hl_first, qw->tx_if.hl_last,&qw->tx_if.tx_mbox[0]);
	for (i = 0; i < QNET_HLRING_ENTRIES; i++) {
		ioctl = &qw->tx_if.hl_ring[i];
		ioctl_phys = &(((struct host_ioctl *) qw->tx_if.hl_ring_dma)[qw->tx_if.hl_tosend]);

		DBGPRINTF(DBG_LL_CRIT, QDRV_LF_HLINK,
				"I[%d] IO(V):%p IO(P):%p ARGP:%p COMM:%d STAT:%08X RC:%08X\n", i,
				ioctl, ioctl_phys,(void *)ioctl->ioctl_argp,
				ioctl->ioctl_command,
				ioctl->ioctl_status,
				ioctl->ioctl_rc);
	}
}

static struct host_ioctl *qdrv_alloc_ioctl(struct qdrv_wlan *qw)
{
	int indx;
	struct host_ioctl *ioctl;
	unsigned long flags;

#ifdef QDRV_FEATURE_KILL_MUC
	if (qw->flags_ext & QDRV_WLAN_MUC_KILLED) {
		return NULL;
	}
#endif
	spin_lock_irqsave(&qw->tx_if.hl_flowlock, flags);

	/* Search for an empty IOCTL */
	for (indx=0; indx < QNET_HLRING_ENTRIES; indx++) {
		ioctl = &qw->tx_if.hl_ring[indx];
		if (ioctl->ioctl_status == QTN_HLINK_STATUS_AVAIL)
			break;
	}

	if (indx == QNET_HLRING_ENTRIES) {
		DBGPRINTF_E("Hostlink buffer not available\n");

		if (DBG_LOG_FUNC_TEST(QDRV_LF_HLINK)) {
			dump_hring(qw);
		}

		spin_unlock_irqrestore(&qw->tx_if.hl_flowlock, flags);
		return (NULL);
	}

	ioctl->ioctl_status = 0;

	spin_unlock_irqrestore(&qw->tx_if.hl_flowlock, flags);

	memset(ioctl, 0, sizeof(*ioctl));
	ioctl->ioctl_dev = qw->unit;

	return (ioctl);
}

static void qdrv_free_ioctl(struct host_ioctl *ioctl)
{
	if (ioctl == NULL) {
		return;
	}

	ioctl->ioctl_status = QTN_HLINK_STATUS_AVAIL;
}

static int qdrv_ioctl_cond(volatile uint32_t *mbox, struct host_ioctl *ioctl)
{
	if (mbox)
		return *mbox;
	else
		return !(ioctl->ioctl_rc & (QTN_HLINK_RC_DONE | QTN_HLINK_RC_ERR));
}

/*
 * Notice: spinlock must be taken prior to call this function if the lock exist.
 */
static int qdrv_ioctl_event_timeout(struct qdrv_mac *mac, spinlock_t *lock,
	unsigned long *flags, volatile uint32_t *mbox, struct host_ioctl *ioctl,
	int wait_time, const char *msg)
{
	unsigned long start_time = jiffies;
	uint32_t timeout = 0;
	uint32_t dly_cnt = 0;
	uint32_t irq_to = wait_time * 100000 / HZ;
	unsigned long irq_trig_time = start_time;
	u32 irq_trig_intv = msecs_to_jiffies(1000);

	KASSERT(wait_time > 0, (DBGEFMT "Wait time must be positive.", DBGARG));

	while (!timeout && qdrv_ioctl_cond(mbox, ioctl)) {
		if (lock)
			spin_unlock_irqrestore(lock, *flags);

		if (irqs_disabled()) {
			udelay(10);
			timeout = (++dly_cnt) > irq_to;
			if ((dly_cnt % (irq_to >> 1)) == 0) {
				printk("HLINK MSG: %s over %u jiffies in irq context,"
					" re-trigger interrupt to muc\n", msg,
					wait_time >> 1);
				qdrv_mac_interrupt_muc(mac);
			}
		} else {
			if (!in_atomic())
				msleep(1);

			timeout = time_after(jiffies, start_time + wait_time);
			if (time_after(jiffies, irq_trig_time + irq_trig_intv)) {
				printk("HLINK MSG: %s over %lu jiffies, re-trigger "
					"interrupt to muc\n", msg,
					(jiffies - start_time));
				irq_trig_time = jiffies;
				irq_trig_intv <<= 1;
				qdrv_mac_interrupt_muc(mac);
			}
		}

		if (lock)
			spin_lock_irqsave(lock, *flags);
	}

	DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_HLINK,
		"HLINK MSG: %s %s after %lu jiffies\n",
		msg, timeout ? "timed out" : "accepted", jiffies - start_time);
	return timeout && qdrv_ioctl_cond(mbox, ioctl);
}

#define QDRV_IOCTL_RET_TIMEOUT			(-1)
#define QDRV_IOCTL_HARD_IRQ_PM_WAIT_TIME	30
#define QDRV_IOCTL_HARD_IRQ_WAIT_TIME		(HZ / 10)
#define QDRV_IOCTL_ISR_WAIT_TIME		(HZ * 5)
#define QDRV_IOCTL_PROC_WAIT_TIME		(HZ * 10)

static int qdrv_send_ioctl(struct qdrv_wlan *qw, struct host_ioctl *ioctl)
{
#ifdef MTEST
	return 0;
#else
	volatile u32 *mbox = &qw->tx_if.tx_mbox[0];
	struct qdrv_mac *mac = qw->mac;
	struct ieee80211com *ic = &qw->ic;
	int rc;
	int in_isr = 0;
	int wait_time;
	unsigned long flags;
	char *desc;

	/* This is a purely blocking IOCTL. No real ring. */

	KASSERT(ioctl, (DBGEFMT "PASSED NULL IOCTL IN HOSTLINK SEND", DBGARG));

	if (irqs_disabled()) {
		DBGPRINTF(DBG_LL_WARNING, QDRV_LF_HLINK,
			"HLINK MSG: called with IRQ disabled, cmd %u in_irq %lu\n",
			ioctl->ioctl_command, in_irq());
	}

	in_isr = in_interrupt();
	if (in_irq()) {
		wait_time = QDRV_IOCTL_HARD_IRQ_WAIT_TIME;
		if (ic->ic_pm_enabled)
			wait_time = QDRV_IOCTL_HARD_IRQ_PM_WAIT_TIME;
	} else if (in_isr) {
		wait_time = QDRV_IOCTL_ISR_WAIT_TIME;
	} else {
		wait_time = QDRV_IOCTL_PROC_WAIT_TIME;
	}

	DBGPRINTF(DBG_LL_NOTICE, QDRV_LF_HLINK,
		"HLINK MSG: %d Dev %d args %08X %08X called in %s context\n",
		ioctl->ioctl_command, ioctl->ioctl_dev, ioctl->ioctl_arg1,
		ioctl->ioctl_arg2, in_isr ? "interrupt" : "process");

	if (mac->dead) {
		static int count_msg = 0;
		#define QDRV_MAX_DEAD_MSG 25
		if ((count_msg++) <= QDRV_MAX_DEAD_MSG) {
			DBGPRINTF_E("(%d)Dropping IOCTL %p due to dead MAC: %d dev %d"
				" args %08X %08X called in %s context\n", count_msg, ioctl,
				ioctl->ioctl_command, ioctl->ioctl_dev, ioctl->ioctl_arg1,
				ioctl->ioctl_arg2, in_isr ? "interrupt" : "process");
			if (count_msg == QDRV_MAX_DEAD_MSG) {
				DBGPRINTF_E("Restricting dead IOCTL messages\n");
			}
		}
		rc = 1;
		qdrv_free_ioctl(ioctl);
		return (rc);
	}

	spin_lock_irqsave(&qw->flowlock, flags);

	/* IOCTLs can be sent from non-sleep context. So we are forced to busy
	 * wait. MuC treats IOCTL msgs as highest prio task
	 */
	desc = "waiting for empty mbox";
	rc = qdrv_ioctl_event_timeout(qw->mac, &qw->flowlock, &flags,
			mbox, ioctl, wait_time, desc);
	if (rc) {
		goto freelock;
	}

	/*
	 * Push msg into mbx
	 * - the current msg is offset into the dma region by ioctl index
	 */
	DBGPRINTF(DBG_LL_CRIT, QDRV_LF_TRACE | QDRV_LF_HLINK,
			"MBOX %p\n", mbox);
	qtn_mproc_sync_mem_write_wmb((u32)mbox,
		(u32)((ioctl - qw->tx_if.hl_ring) +
			(struct host_ioctl *)qw->tx_if.hl_ring_dma));
	DBGPRINTF(DBG_LL_CRIT, QDRV_LF_TRACE | QDRV_LF_HLINK,
			"set MBOX %p\n", mbox);

	/* Interrupt Muc */
	DBGPRINTF(DBG_LL_CRIT, QDRV_LF_TRACE | QDRV_LF_HLINK,
			"Interrupting MuC %p\n", qw->mac);
	qdrv_mac_interrupt_muc(qw->mac);
	DBGPRINTF(DBG_LL_CRIT, QDRV_LF_TRACE | QDRV_LF_HLINK,
			"Interrupted MuC %p\n", qw->mac);

	desc = "waiting for MuC dequeue";
	rc = qdrv_ioctl_event_timeout(qw->mac, &qw->flowlock, &flags,
			mbox, ioctl, wait_time, desc);
	if (rc) {
		goto freelock;
	}

	spin_unlock_irqrestore(&qw->flowlock, flags);

	desc = "waiting for ioctl completion";

	/* when in calibration mode, it takes long time. So, increase time-out period */
	if (soc_shared_params->calstate != QTN_CALSTATE_DEFAULT)
		wait_time *= 100;

	rc = qdrv_ioctl_event_timeout(qw->mac, NULL, &flags,
			NULL, ioctl, wait_time, desc);
	if (rc) {
		goto hlink_timeout;
	}

	rc = ioctl->ioctl_rc;

	qdrv_free_ioctl(ioctl);
	mac->ioctl_fail_count = 0;

	return rc;

freelock:
	spin_unlock_irqrestore(&qw->flowlock, flags);

hlink_timeout:
	DBGPRINTF_E("HLINK MSG timed out while %s: cmd=%d dev=%d args=%08x %08x"
		" status=%u rc=%u ctxt=%s\n", desc, ioctl->ioctl_command,
		ioctl->ioctl_dev, ioctl->ioctl_arg1, ioctl->ioctl_arg2,
		ioctl->ioctl_status, ioctl->ioctl_rc,
		in_isr ? "interrupt" : "process");
	rc = QDRV_IOCTL_RET_TIMEOUT;
	qdrv_free_ioctl(ioctl);

	/*
	 * If too many failed IOCTLs, perform some system action
	 * (eg, panic, gather logs, whatever).
	 */
	mac->ioctl_fail_count++;

	qdrv_mac_print_muc();
	/* Force dump MuC print buffer via schedule the print work queue */
	uc_print_schedule_work();
	if (mac->ioctl_fail_count > QDRV_MAX_IOCTL_FAIL_DIE) {
		DBGPRINTF_E("Too many failed IOCTLs (%d) - MAC is dead\n",
			mac->ioctl_fail_count);
		qdrv_mac_die_action(mac);
	}

	return rc;
#endif /* #ifdef MTEST */
}

void* qdrv_hostlink_alloc_coherent(struct device *dev, size_t size, dma_addr_t *dma_handle, gfp_t flag)
{
	void *ret = dma_alloc_coherent(dev, size, dma_handle, flag);
	if(dma_handle && *dma_handle) {
		*dma_handle = (dma_addr_t)muc_to_nocache((void*)(*dma_handle));
	}
	return ret;
}

void qdrv_hostlink_free_coherent(struct device *dev, size_t size, void *kvaddr, dma_addr_t dma_handle)
{
	dma_free_coherent(dev, size, kvaddr, (dma_addr_t)nocache_to_muc((void*)dma_handle));
}

/* THese are the Per vap IOCLTS that finally go over the DEV ioctl */
void vnet_free_ioctl(struct host_ioctl *ioctl)
{
	if (ioctl) {
		qdrv_free_ioctl(ioctl);
	}
}

struct host_ioctl *vnet_alloc_ioctl(struct qdrv_vap *qv)
{
	struct qdrv_wlan *qw = (struct qdrv_wlan*)qv->parent;
	struct host_ioctl *ioctl;

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl != NULL) {
		ioctl->ioctl_dev = qv->devid;
	}

	return (ioctl);
}

int vnet_send_ioctl(struct qdrv_vap *qv, struct host_ioctl *ioctl)
{
	struct qdrv_wlan *qw = (struct qdrv_wlan*)qv->parent;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");
	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}

static int qdrv_hostlink_call_ioctl_param(struct qdrv_wlan *qw, u32 cmd, u32 arg1, u32 arg2)
{
	struct host_ioctl *ioctl;

	ioctl = qdrv_alloc_ioctl(qw);
	if (!ioctl) {
		DBGPRINTF_E("ioctl NULL\n");
		return -1;
	}

	ioctl->ioctl_command = cmd;
	ioctl->ioctl_arg1 = arg1;
	ioctl->ioctl_arg2 = arg2;

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_msg_calcmd(struct qdrv_wlan *qw, int cmdlen, dma_addr_t cmd_dma)
{
	struct host_ioctl *ioctl;
	int unit;
	unit = qw->unit;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -ENOMEM;
	}

	ioctl->ioctl_command = IOCTL_DEV_CALCMD;
	ioctl->ioctl_arg1 = 0; /*sys_rev_num*/;
	ioctl->ioctl_arg2 = cmdlen;
	ioctl->ioctl_argp = cmd_dma;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_msg_cmd(struct qdrv_wlan *qw, u_int32_t cmd, u_int32_t arg)
{
	struct host_ioctl *ioctl;
	int unit;
	unit = qw->unit;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -ENOMEM;
	}

	ioctl->ioctl_command = IOCTL_DEV_CMD;
	ioctl->ioctl_arg1 = cmd;
	ioctl->ioctl_arg2 = arg;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}

static int qdrv_get_vap_id(const char *ifname, uint8_t *vap_id)
{
	if (vap_id == NULL || sscanf(ifname, "wifi%hhu", vap_id) != 1)
		return -EINVAL;
	if (*vap_id >= QDRV_MAX_BSS_VAPS)
		return -EINVAL;
	return 0;
}

int qdrv_hostlink_msg_create_vap(struct qdrv_wlan *qw,
	const char *name_lhost, const uint8_t *mac_addr, int devid, int opmode, int flags)
{
	struct host_ioctl *ioctl;
	struct qtn_vap_args *vap_args = NULL;
	dma_addr_t args_dma;
	int alloc_len;
	int unit;
	int ret;
	uint8_t vap_id = QTN_MAX_BSS_VAPS;

	unit = qw->unit;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		ret = -ENOMEM;
		goto out_no_free;
	}

	if (opmode == IEEE80211_M_WDS)
		vap_id = 0;
	else {
		ret = qdrv_get_vap_id(name_lhost, &vap_id);
		if (ret != 0)
			goto out_free_ioctl;
	}

	alloc_len = sizeof(*vap_args) + 1;
	vap_args = qdrv_hostlink_alloc_coherent(NULL, alloc_len,
			&args_dma, GFP_ATOMIC);
	if (vap_args == NULL) {
		DBGPRINTF_E("Failed allocate %d bytes for name\n", alloc_len);
		ret = -ENOMEM;
		goto out_free_ioctl;
	}

	ioctl->ioctl_command = IOCTL_DEV_VAPCREATE;
	ioctl->ioctl_arg1 = unit | (flags << 8) | (opmode << 16);
	ioctl->ioctl_arg2 = devid;
	ioctl->ioctl_argp = args_dma;

	memset(vap_args, 0, sizeof(*vap_args));
	strncpy(vap_args->vap_name, name_lhost, sizeof(vap_args->vap_name)-1);
	vap_args->vap_name[sizeof(vap_args->vap_name)-1] = '\0';
	memcpy(vap_args->vap_macaddr, mac_addr, IEEE80211_ADDR_LEN);
	vap_args->vap_id = vap_id;

	ret = qdrv_send_ioctl(qw, ioctl);
	qdrv_hostlink_free_coherent(NULL, alloc_len, vap_args, args_dma);

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return ret;

out_free_ioctl:
	qdrv_free_ioctl(ioctl);
out_no_free:
	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
	return ret;
}

int qdrv_hostlink_msg_delete_vap(struct qdrv_wlan *qw, struct net_device *vdev)
{
	struct host_ioctl *ioctl;
	int unit;
	int devid;
	struct qdrv_vap *qv = netdev_priv(vdev);

	unit = qw->unit;
	devid = qv->devid;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -ENOMEM;
	}

	ioctl->ioctl_command = IOCTL_DEV_VAPDELETE;
	ioctl->ioctl_arg1 = unit;
	ioctl->ioctl_arg2 = devid;
	ioctl->ioctl_argp = 0;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_sample_chan_cancel(struct qdrv_wlan *qw, struct qtn_samp_chan_info *samp_chan_bus)
{
	struct host_ioctl *ioctl;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -1;
	}

	ioctl->ioctl_command = IOCTL_DEV_SAMPLE_CHANNEL_CANCEL;
	ioctl->ioctl_arg1 = (u32)samp_chan_bus;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_sample_chan(struct qdrv_wlan *qw, struct qtn_samp_chan_info *samp_chan_bus)
{
	struct host_ioctl *ioctl;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -1;
	}

	ioctl->ioctl_command = IOCTL_DEV_SAMPLE_CHANNEL;
	ioctl->ioctl_arg1 = (u32)samp_chan_bus;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_remain_chan(struct qdrv_wlan *qw, struct qtn_remain_chan_info *remain_chan_bus)
{
	struct host_ioctl *ioctl;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -1;
	}

	ioctl->ioctl_command = IOCTL_DEV_REMAIN_CHANNEL;
	ioctl->ioctl_arg1 = (uint32_t)remain_chan_bus;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_suspend_off_chan(struct qdrv_wlan *qw, uint32_t suspend)
{
	struct host_ioctl *ioctl;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -1;
	}

	ioctl->ioctl_command = IOCTL_DEV_SUSPEND_OFF_CHANNEL;
	ioctl->ioctl_arg1 = suspend;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_set_ocac(struct qdrv_wlan *qw, struct qtn_ocac_info *ocac_bus)
{
	struct host_ioctl *ioctl;

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		return -1;
	}

	ioctl->ioctl_command = IOCTL_DEV_SET_OCAC;
	ioctl->ioctl_arg1 = (u32)ocac_bus;

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_meas_chan(struct qdrv_wlan *qw, struct qtn_meas_chan_info *meas_chan_bus)
{
	struct host_ioctl *ioctl;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -1;
	}

	ioctl->ioctl_command = IOCTL_DEV_MEAS_CHANNEL;
	ioctl->ioctl_arg1 = (u32)meas_chan_bus;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_rxgain_params(struct qdrv_wlan *qw, uint32_t index, struct qtn_rf_rxgain_params *rx_gain_params)
{
	struct host_ioctl *ioctl;
	dma_addr_t args_dma = 0;
	struct qtn_rf_rxgain_params *sp_rxgain_params=NULL;
	int alloc_len = sizeof(*sp_rxgain_params) + 1;
	int ret = 0;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -ENOMEM;
	}

	if (rx_gain_params != NULL) {
		sp_rxgain_params = qdrv_hostlink_alloc_coherent(NULL, alloc_len,
				&args_dma, GFP_ATOMIC);

		if (sp_rxgain_params == NULL) {
			qdrv_free_ioctl(ioctl);
			DBGPRINTF_E("Failed allocate %d bytes for name\n", alloc_len);
			DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
			return -ENOMEM;
		}

		*sp_rxgain_params = *rx_gain_params;
	}

	ioctl->ioctl_command = IOCTL_DEV_SET_RX_GAIN_PARAMS;
	ioctl->ioctl_arg1 = index;
	ioctl->ioctl_arg2 = args_dma;

	ret = qdrv_send_ioctl(qw, ioctl);

	if (sp_rxgain_params != NULL) {
		qdrv_hostlink_free_coherent(NULL, alloc_len, sp_rxgain_params, args_dma);
	}

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return ret;
}

#ifdef QTN_BG_SCAN
int qdrv_hostlink_bgscan_chan(struct qdrv_wlan *qw, struct qtn_scan_chan_info *scan_chan_bus)
{
	struct host_ioctl *ioctl;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -1;
	}

	ioctl->ioctl_command = IOCTL_DEV_BGSCAN_CHANNEL;
	ioctl->ioctl_arg1 = (u32)scan_chan_bus;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_bgscan_end(struct qdrv_wlan *qw, struct qtn_scan_chan_info *scan_chan_bus)
{
	struct host_ioctl *ioctl;

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E("ioctl NULL\n");
		return -1;
	}

	ioctl->ioctl_command = IOCTL_DEV_BGSCAN_END;
	ioctl->ioctl_arg1 = (uint32_t)scan_chan_bus;

	return qdrv_send_ioctl(qw, ioctl);
}
#endif /* QTN_BG_SCAN */

int qdrv_hostlink_store_txpow(struct qdrv_wlan *qw, u_int32_t txpow)
{
	struct host_ioctl *ioctl;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
#if 0
		DPRINTF(LL_1, LF_ERROR, (DBGEFMT "ioctl NULL\n", DBGARG));
		DPRINTF(LL_1, LF_TRACE, (DBGFMT "<--Exit\n", DBGARG));
#endif
		return -ENOMEM;
	}

	ioctl->ioctl_command = IOCTL_DEV_STORE_TXPOW;
	ioctl->ioctl_arg1 = qw->rf_chipid;
	ioctl->ioctl_arg2 = txpow;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_setchan(struct qdrv_wlan *qw, uint32_t freq_band, uint32_t qtn_chan)
{
	struct host_ioctl *ioctl;
	int unit;
	unit = qw->unit;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -ENOMEM;
	}

	ioctl->ioctl_command = IOCTL_DEV_CHANGE_CHANNEL;
	ioctl->ioctl_arg1 = freq_band;
	ioctl->ioctl_arg2 = qtn_chan;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_setchan_deferred(struct qdrv_wlan *qw, struct qtn_csa_info *csa_phyaddr_info)
{
	struct host_ioctl *ioctl;
	int unit;
	unit = qw->unit;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -ENOMEM;
	}

	ioctl->ioctl_command = IOCTL_DEV_CHANGE_CHAN_DEFERRED;
	ioctl->ioctl_arg1 = (u32)csa_phyaddr_info;
	DBGPRINTF(DBG_LL_CRIT, QDRV_LF_HLINK,
			"sending to %p muc\n", csa_phyaddr_info);
	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_xmitctl(struct qdrv_wlan *qw, bool enable_xmit)
{
	struct host_ioctl *ioctl;
	int unit;
	unit = qw->unit;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -ENOMEM;
	}

	ioctl->ioctl_command = IOCTL_DEV_XMITCTL;
	ioctl->ioctl_arg1 = (enable_xmit)? 1 : 0;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_use_rtscts(struct qdrv_wlan *qw, int rtscts_required)
{
	struct host_ioctl *ioctl;
	int unit;
	unit = qw->unit;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -ENOMEM;
	}

	ioctl->ioctl_command = IOCTL_DEV_USE_RTS_CTS;
	ioctl->ioctl_arg1 = (rtscts_required)? 1 : 0;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}

#ifdef QDRV_FEATURE_KILL_MUC
int qdrv_hostlink_killmuc(struct qdrv_wlan *qw)
{
	struct host_ioctl *ioctl;
	int unit;
	unit = qw->unit;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -ENOMEM;;
	}

	ioctl->ioctl_command = IOCTL_DEV_KILL_MUC;
	ioctl->ioctl_arg1 = unit;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}
#endif

#ifdef CONFIG_QVSP
int qdrv_hostlink_qvsp(struct qdrv_wlan *qw, uint32_t param, uint32_t value)
{
	struct host_ioctl *ioctl;
	int rc;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -ENOMEM;;
	}

	ioctl->ioctl_command = IOCTL_DEV_VSP;
	ioctl->ioctl_arg1 = param;
	ioctl->ioctl_arg2 = value;

	rc = qdrv_send_ioctl(qw, ioctl);

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return rc;
}
#endif

int qdrv_dump_log(struct qdrv_wlan *qw)
{
	struct host_ioctl *ioctl;
	int unit;
	unit = qw->unit;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -ENOMEM;;
	}

	ioctl->ioctl_command = IOCTL_DEV_DUMP_LOG;
	ioctl->ioctl_arg1 = unit;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}
int qdrv_hostlink_msg_set_wifi_macaddr( struct qdrv_wlan *qw, u8 *new_macaddr )
{
	struct host_ioctl *ioctl;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -ENOMEM;;
	}

	ioctl->ioctl_command = IOCTL_DEV_SET_MACADDR;
	ioctl->ioctl_arg1 = ((new_macaddr[ 0 ] << 24) | (new_macaddr[ 1 ] << 16) | (new_macaddr[ 2 ] << 8) | new_macaddr[ 3 ]);
	ioctl->ioctl_arg2 = ((new_macaddr[ 4 ] << 8) | new_macaddr[ 5 ]);

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_setscanmode(struct qdrv_wlan *qw, bool scan_mode_en,
			      const uint8_t *scan_addr)
{
	struct host_ioctl *ioctl;

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		return -ENOMEM;;
	}

	ioctl->ioctl_command = IOCTL_DEV_SET_SCANMODE_STA;
	ioctl->ioctl_arg1 = (scan_mode_en ? 1 : 0) & 0xff;

	if (scan_addr) {
		ioctl->ioctl_arg1 |= (scan_addr[4] << 16) | (scan_addr[5] << 8);
		ioctl->ioctl_arg2 = (scan_addr[0] << 24) | (scan_addr[1] << 16) |
				    (scan_addr[2] << 8) | scan_addr[3];
	}

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_set_hrflags(struct qdrv_wlan *qw, u_int32_t hrflags)
{
	struct host_ioctl *ioctl;
	int unit;
	unit = qw->unit;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -ENOMEM;;
	}

	ioctl->ioctl_command = IOCTL_DEV_SET_HRFLAGS;
	ioctl->ioctl_arg1 = hrflags;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_power_save(struct qdrv_wlan *qw, int param, int val)
{
	struct host_ioctl *ioctl;
	int unit;
	unit = qw->unit;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E( "ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -ENOMEM;;
	}

	ioctl->ioctl_command = IOCTL_DEV_SET_POWER_SAVE;
	ioctl->ioctl_arg1 = param;
	ioctl->ioctl_arg2 = val;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_tx_airtime_control(struct qdrv_wlan *qw, uint32_t value)
{
	struct host_ioctl *ioctl;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (!ioctl) {
		DBGPRINTF_E("ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -ENOMEM;
	}

	ioctl->ioctl_command = IOCTL_DEV_AIRTIME_CONTROL;
	ioctl->ioctl_arg1 = value;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_mu_group_update(struct qdrv_wlan *qw, struct qtn_mu_group_update_args *args)
{
	struct host_ioctl *ioctl;
	struct qtn_mu_group_update_args *sp_args = NULL;
	dma_addr_t args_dma = 0;
	int alloc_len = sizeof(struct qtn_mu_group_update_args);
	int ret = 0;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (!ioctl) {
		DBGPRINTF_E("ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -ENOMEM;
	}

	sp_args = qdrv_hostlink_alloc_coherent(NULL, alloc_len,
		&args_dma, GFP_ATOMIC);
	if (sp_args == NULL) {
		qdrv_free_ioctl(ioctl);
		DBGPRINTF_E("Failed to allocate %d bytes for name\n", alloc_len);
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -ENOMEM;
	}
	*sp_args = *args;

	ioctl->ioctl_command = IOCTL_DEV_MU_GROUP_UPDATE;
	ioctl->ioctl_arg1 = 0;
	ioctl->ioctl_arg2 = 0;
	ioctl->ioctl_argp = args_dma;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	ret = qdrv_send_ioctl(qw, ioctl);

	qdrv_hostlink_free_coherent(NULL, alloc_len, sp_args, args_dma);
	return ret;
}

int qdrv_hostlink_send_ioctl_args(struct qdrv_wlan *qw, uint32_t command,
		uint32_t arg1, uint32_t arg2)
{
	struct host_ioctl *ioctl;
	int unit;
	unit = qw->unit;

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E("ioctl %u qdrv_alloc_ioctl return NULL\n", command);
		return -ENOMEM;
	}

	ioctl->ioctl_command = command;
	ioctl->ioctl_arg1 = arg1;
	ioctl->ioctl_arg2 = arg2;

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_start(struct qdrv_mac *mac)
{
	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");
	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return(0);
}

int qdrv_hostlink_stop(struct qdrv_mac *mac)
{
	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");
	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return(0);
}

int qdrv_hostlink_init(struct qdrv_wlan *qw, struct host_ioctl_hifinfo *hifinfo)
{
	int indx;
	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	/* Allocate the Hostlink circular buffer */
	qw->tx_if.hl_ring = qdrv_hostlink_alloc_coherent(NULL, QNET_HLRING_SIZE,
		(dma_addr_t *) &qw->tx_if.hl_ring_dma, GFP_ATOMIC);

	if(!qw->tx_if.hl_ring)
	{
		DBGPRINTF_E("Failed to allocate DMA memory\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return(-ENOMEM);
	}

	memset(qw->tx_if.hl_ring, 0, QNET_HLRING_SIZE);
	for(indx=0;indx<QNET_HLRING_ENTRIES;indx++){
		qw->tx_if.hl_ring[indx].ioctl_status = QTN_HLINK_STATUS_AVAIL;
	}
	qw->tx_if.hl_read = qw->tx_if.hl_write = qw->tx_if.hl_tosend = 0;
	qw->tx_if.hl_first = qw->tx_if.hl_last = NULL;

	spin_lock_init(&qw->tx_if.hl_flowlock);

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return(0);
}

int qdrv_hostlink_exit(struct qdrv_wlan *qw)
{
	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	/* Make sure work queues are done */
	flush_scheduled_work();

	dma_free_coherent(NULL, QNET_HLRING_SIZE, qw->tx_if.hl_ring,
		qw->tx_if.hl_ring_dma);

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return(0);
}

int qdrv_hostlink_config_hbm_meta(struct qdrv_wlan *qw, unsigned int need_append_meta)
{
	struct host_ioctl *ioctl;

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E("ioctl NULL\n");
		return -ENOMEM;
	}

	ioctl->ioctl_command = IOCTL_DEV_FRAME_META_INFO;
	ioctl->ioctl_arg1 = need_append_meta;

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_vlan_enable(struct qdrv_wlan *qw, int enable)
{
	struct host_ioctl *ioctl;
	int ret = 0;

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E("ioctl cmd [%d] NULL\n", IOCTL_DEV_ENABLE_VLAN);
		return -ENOMEM;
	}

	ioctl->ioctl_command = IOCTL_DEV_ENABLE_VLAN;
	ioctl->ioctl_arg1 = enable;
	ioctl->ioctl_arg2 = 0;
	ioctl->ioctl_argp = 0;

	ret = qdrv_send_ioctl(qw, ioctl);
	return ret;
}

int qdrv_hostlink_vlan_drop_stag(struct qdrv_wlan *qw, int drop_stag)
{
	struct host_ioctl *ioctl;
	int ret = 0;

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E("ioctl cmd [%d] NULL\n", IOCTL_DEV_VLAN_DROP_STAG);
		return -ENOMEM;
	}

	ioctl->ioctl_command = IOCTL_DEV_VLAN_DROP_STAG;
	ioctl->ioctl_arg1 = drop_stag;
	ioctl->ioctl_arg2 = 0;
	ioctl->ioctl_argp = 0;

	ret = qdrv_send_ioctl(qw, ioctl);
	return ret;
}

int qdrv_hostlink_enable_flush_data(struct qdrv_wlan *qw, int enable)
{
        struct host_ioctl *ioctl;
        int ret = 0;

        ioctl = qdrv_alloc_ioctl(qw);
        if (ioctl == NULL) {
                DBGPRINTF_E("ioctl cmd[%d] NULL\n", IOCTL_DEV_FLUSH_DATA);
                return -ENOMEM;
        }

        if (enable) {

		ioctl->ioctl_command = IOCTL_DEV_FLUSH_DATA;
		ioctl->ioctl_arg1 = enable;
		ioctl->ioctl_arg2 = 0;
		ioctl->ioctl_argp = 0;

		ret = qdrv_send_ioctl(qw, ioctl);
        }
        return ret;
}

int qdrv_hostlink_update_ocac_state_ie(struct qdrv_wlan *qw, uint8_t state, uint8_t param)
{
	struct host_ioctl *ioctl;

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E("%s: ioctl NULL\n", __func__);
		return -1;
	}

	ioctl->ioctl_command = IOCTL_DEV_UPDATE_OCAC_STATE_IE;
	ioctl->ioctl_arg1 = state;
	ioctl->ioctl_arg2 = param;

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_change_bcn_scheme(struct qdrv_vap *qv, int param, int value)
{
	struct host_ioctl *ioctl;
	struct qtn_setparams_args *args = NULL;
	dma_addr_t args_dma = 0;
	int ret = 0;
	struct qdrv_wlan *qw = (struct qdrv_wlan*)qv->parent;

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E("ioctl cmd[%d] NULL\n", IOCTL_DEV_SETPARAMS);
		return -1;
	}

	args = qdrv_hostlink_alloc_coherent(NULL, sizeof(*args),
			&args_dma, GFP_DMA | GFP_ATOMIC);
	if (args == NULL) {
		qdrv_free_ioctl(ioctl);
		DBGPRINTF_E("Failed allocate memory for bytes for args\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -1;
	}

	args->ni_param = param;
	args->ni_value = value;
	args->ni_len = 0;

	ioctl->ioctl_command = IOCTL_DEV_SETPARAMS;
	ioctl->ioctl_dev = qv->devid;
	ioctl->ioctl_argp = args_dma;

	ret = qdrv_send_ioctl(qw, ioctl);

	qdrv_hostlink_free_coherent(NULL, sizeof(*args), args, args_dma);
	return ret;
}

int qdrv_hostlink_set_txctl(struct qdrv_wlan *qw, uint32_t txctl)
{
	struct host_ioctl *ioctl;

	ioctl = qdrv_alloc_ioctl(qw);
	if (!ioctl) {
		DBGPRINTF_E("ioctl NULL\n");
		return -1;
	}

	ioctl->ioctl_command = IOCTL_DEV_SET_TXCTL;
	ioctl->ioctl_arg1 = txctl;

	return qdrv_send_ioctl(qw, ioctl);
}


int qdrv_hostlink_robust_csa_send_frame(struct qdrv_wlan *qw,
		struct qtn_robust_csa_info *robust_csa_bus)
{
	struct host_ioctl *ioctl;

	ioctl = qdrv_alloc_ioctl(qw);
	if (!ioctl) {
		DBGPRINTF_E("ioctl NULL\n");
		return -1;
	}

	ioctl->ioctl_command = IOCTL_DEV_ROBUST_CSA_SEND;
	ioctl->ioctl_arg1 = (u32)robust_csa_bus;

	return qdrv_send_ioctl(qw, ioctl);

}

int qdrv_hostlink_radar_start(struct qdrv_wlan *qw, enum radar_dfs_rqmt region, u8 scancnt)
{
	return qdrv_hostlink_call_ioctl_param(qw, IOCTL_DEV_RADAR_START, (u32)region, scancnt);
}

int qdrv_hostlink_radar_enable(struct qdrv_wlan *qw)
{
	return qdrv_hostlink_call_ioctl_param(qw, IOCTL_DEV_RADAR_ENABLE, 0, 0);
}

int qdrv_hostlink_radar_disable(struct qdrv_wlan *qw)
{
	return qdrv_hostlink_call_ioctl_param(qw, IOCTL_DEV_RADAR_DISABLE, 0, 0);
}

int qdrv_hostlink_radar_clear(struct qdrv_wlan *qw)
{
	return qdrv_hostlink_call_ioctl_param(qw, IOCTL_DEV_RADAR_CLEAR, 0, 0);
}

void qdrv_hostlink_ocac_dump_tsf_log(struct ieee80211com *ic)
{
	struct qdrv_wlan *qw = container_of(ic, struct qdrv_wlan, ic);

	qdrv_hostlink_call_ioctl_param(qw, IOCTL_DEV_OCAC_DUMP_TSF_LOG, 0, 0);
}

int qdrv_hostlink_radar_ocac_start(struct qdrv_wlan *qw, const struct qtn_ocac_params *params)
{
	u32 arg = 0;

	memcpy(&arg, params, sizeof(*params));

	return qdrv_hostlink_call_ioctl_param(qw, IOCTL_DEV_RADAR_OCAC_START, arg, 0);
}

int qdrv_hostlink_radar_set_param(struct qdrv_wlan *qw, enum qtn_radar_param param, u32 value)
{
	return qdrv_hostlink_call_ioctl_param(qw, IOCTL_DEV_RADAR_PARAM_SET, (u32) param, value);
}

int qdrv_hostlink_radar_get_param(struct qdrv_wlan *qw, enum qtn_radar_param param, u32 *value)
{
	struct host_ioctl *ioctl;
	int ret;

	ioctl = qdrv_alloc_ioctl(qw);
	if (!ioctl) {
		DBGPRINTF_E("ioctl NULL\n");
		return -1;
	}

	ioctl->ioctl_command = IOCTL_DEV_RADAR_PARAM_GET;
	ioctl->ioctl_arg1 = (u32)param;

	ret = qdrv_send_ioctl(qw, ioctl);

	*value = (u32)ioctl->ioctl_arg2;

	return ret;
}

int qdrv_hostlink_radar_get_str(struct qdrv_wlan *qw, char *buf, enum qtn_radar_string type,
				size_t *len, size_t max_len)
{
	struct host_ioctl *ioctl;
	dma_addr_t buf_dma = 0;
	char *summary_buf;
	int res;

	*len = 0;

	ioctl = qdrv_alloc_ioctl(qw);
	if (!ioctl) {
		DBGPRINTF_E("ioctl NULL\n");
		return -1;
	}

	summary_buf = qdrv_hostlink_alloc_coherent(NULL, max_len, &buf_dma, GFP_ATOMIC);
	if (summary_buf == NULL) {
		qdrv_free_ioctl(ioctl);
		DBGPRINTF_E("Failed allocate memory for bytes for string buf\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -1;
	}

	ioctl->ioctl_command = IOCTL_DEV_RADAR_GET_STRING;
	ioctl->ioctl_arg1 = type;
	ioctl->ioctl_arg2 = max_len;
	ioctl->ioctl_argp = buf_dma;

	res = qdrv_send_ioctl(qw, ioctl);

	*len = strlcpy(buf, summary_buf, max_len);

	qdrv_hostlink_free_coherent(NULL, max_len, summary_buf, buf_dma);
	return res;
}

int qdrv_hostlink_spdia_set_dsp_buf(struct qdrv_wlan *qw, uint32_t qspdia_buf_dma,
					uint32_t qspdia_buf_len)
{
	struct host_ioctl *ioctl;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (ioctl == NULL) {
		DBGPRINTF_E("ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return QTN_HLINK_RC_ERR;
	}

	ioctl->ioctl_command = IOCTL_DEV_SPDIA_SET_DSP_BUF;
	ioctl->ioctl_arg1 = qspdia_buf_len;
	ioctl->ioctl_arg2 = 0;
	ioctl->ioctl_argp = qspdia_buf_dma;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return qdrv_send_ioctl(qw, ioctl);
}

int qdrv_hostlink_spdia_set_conf(struct qdrv_wlan *qw, struct qspdia_conf *qspdia_conf,
					uint32_t conf_num)
{
	struct host_ioctl *ioctl;
	struct qspdia_conf *conf_buf;
	dma_addr_t conf_buf_dma = 0;
	int ret;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	ioctl = qdrv_alloc_ioctl(qw);
	if (!ioctl) {
		DBGPRINTF_E("ioctl NULL\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return QTN_HLINK_RC_ERR;
	}

	conf_buf = qdrv_hostlink_alloc_coherent(NULL, sizeof(*conf_buf), &conf_buf_dma, GFP_ATOMIC);
	if (conf_buf == NULL) {
		qdrv_free_ioctl(ioctl);
		DBGPRINTF_E("Failed allocate memory for bytes for string buf\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return QTN_HLINK_RC_ERR;
	}

	ioctl->ioctl_command = IOCTL_DEV_SPDIA_SET_CONF;
	ioctl->ioctl_arg1 = conf_num;
	ioctl->ioctl_arg2 = 0;
	ioctl->ioctl_argp = conf_buf_dma;

	memcpy(conf_buf, qspdia_conf, sizeof(*conf_buf));

	ret = qdrv_send_ioctl(qw, ioctl);

	qdrv_hostlink_free_coherent(NULL, sizeof(*conf_buf), conf_buf, conf_buf_dma);

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return ret;
}
