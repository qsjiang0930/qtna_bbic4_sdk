/**
 * Copyright (c) 2015-2016 Quantenna Communications, Inc.
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
 **/

#define pr_fmt(fmt)	"%s: " fmt, __func__

#include <linux/module.h>
#include <linux/types.h>

#include <qtn/dmautil.h>

#include "shm_ipc.h"

static bool qlink_shm_ipc_has_new_data(struct qlink_shm_ipc *ipc)
{
	const u32 flags = le32_to_cpu(arc_read_uncached_32(&ipc->shm_region->headroom.hdr.flags));

	return (flags & QLINK_SHM_IPC_NEW_DATA);
}

static void qlink_shm_handle_new_data(struct qlink_shm_ipc *ipc)
{
	size_t size;
	bool rx_buff_ok = true;
	volatile struct qtn_pcie_shm_region_header *shm_reg_hdr = &ipc->shm_region->headroom.hdr;

	size = le16_to_cpu(arc_read_uncached_16(&shm_reg_hdr->data_len));

	if (unlikely(size == 0 || size > QTN_SHM_MAX_DATA_SZ)) {
		pr_err("wrong rx packet size: %u\n", size);
		rx_buff_ok = false;
	} else {
		inv_dcache_sizerange_safe(
			(void *)((struct qtn_pcie_shm_region *)ipc->shm_region)->data, size);

		memcpy(ipc->rx_data, (void *)ipc->shm_region->data, size);
	}

	arc_write_uncached_32(&shm_reg_hdr->flags, cpu_to_le32(QLINK_SHM_IPC_ACK));

	wmb(); /* sync up all memory writes before generating interrupt */

	ipc->interrupt.fn(ipc->interrupt.arg);

	if (likely(rx_buff_ok)) {
		ipc->rx_packet_count++;
		ipc->rx_callback.fn(ipc->rx_callback.arg, ipc->rx_data, size);
	}
}

static void qlink_shm_ipc_irq_work(struct work_struct *work)
{
	struct qlink_shm_ipc *ipc = container_of(work, struct qlink_shm_ipc, irq_work);

	while (qlink_shm_ipc_has_new_data(ipc))
		qlink_shm_handle_new_data(ipc);
}

static void qlink_shm_ipc_irq_inbound_handler(struct qlink_shm_ipc *ipc)
{
	u32 flags;

	flags = le32_to_cpu(arc_read_uncached_32(&ipc->shm_region->headroom.hdr.flags));

	if (flags & QLINK_SHM_IPC_NEW_DATA)
		queue_work(ipc->workqueue, &ipc->irq_work);
}

static void qlink_shm_ipc_irq_outbound_handler(struct qlink_shm_ipc *ipc)
{
	u32 flags;

	if (!ipc->waiting_for_ack)
		return;

	flags = le32_to_cpu(arc_read_uncached_32(&ipc->shm_region->headroom.hdr.flags));

	if (flags & QLINK_SHM_IPC_ACK) {
		ipc->waiting_for_ack = false;
		complete(&ipc->tx_completion);
	}
}

int qlink_shm_ipc_init(struct qlink_shm_ipc *ipc,
		       enum qlink_shm_ipc_direction direction,
		       volatile struct qtn_pcie_shm_region *shm_region,
		       struct workqueue_struct *workqueue,
		       const struct qlink_shm_ipc_int *interrupt,
		       const struct qlink_shm_ipc_rx_callback *rx_callback)
{
	if (!ipc || !shm_region || !workqueue || !interrupt || !rx_callback) {
		pr_err("some of input parameters are NULL\n");
		return -EINVAL;
	}

	ipc->shm_region = shm_region;
	ipc->direction = direction;
	ipc->interrupt = *interrupt;
	ipc->rx_callback = *rx_callback;
	ipc->tx_packet_count = 0;
	ipc->rx_packet_count = 0;
	ipc->workqueue = workqueue;
	ipc->waiting_for_ack = false;
	ipc->tx_timeout_count = 0;

	switch (direction) {
	case QLINK_SHM_IPC_OUTBOUND:
		ipc->irq_handler = qlink_shm_ipc_irq_outbound_handler;
		break;
	case QLINK_SHM_IPC_INBOUND:
		ipc->irq_handler = qlink_shm_ipc_irq_inbound_handler;
		break;
	default:
		return -EINVAL;
	}

	INIT_WORK(&ipc->irq_work, qlink_shm_ipc_irq_work);
	init_completion(&ipc->tx_completion);
	mutex_init(&ipc->tx_lock);

	return 0;
}

void qlink_shm_ipc_free(struct qlink_shm_ipc *ipc)
{
	complete_all(&ipc->tx_completion);
}

int qlink_shm_ipc_send(struct qlink_shm_ipc *ipc, const u8 *buf, size_t size)
{
	int ret = 0;
	volatile struct qtn_pcie_shm_region_header *shm_reg_hdr = &ipc->shm_region->headroom.hdr;

	if (unlikely(size > QTN_SHM_MAX_DATA_SZ))
		return -E2BIG;

	mutex_lock(&ipc->tx_lock);

	arc_write_uncached_32(&shm_reg_hdr->flags, 0);
	arc_write_uncached_16(&shm_reg_hdr->data_len, cpu_to_le16(size));

	/* Use cached access to SHM region, then just flush cache */
	memcpy((void *)ipc->shm_region->data, buf, size);
	flush_dcache_sizerange_safe((void *)((struct qtn_pcie_shm_region *)ipc->shm_region)->data,
				    size);

	ipc->waiting_for_ack = true;

	wmb(); /* sync up all memory writes before generating interrupt */

	/* Set NEW_DATA flag only after SHM region flush is complete, since
	 * we have shared IRQ on the host side and hdr.flags can be read before we
	 * generate an interrupt.
	 */
	arc_write_uncached_32(&shm_reg_hdr->flags, cpu_to_le32(QLINK_SHM_IPC_NEW_DATA));

	ipc->interrupt.fn(ipc->interrupt.arg);

	ipc->tx_packet_count++;

	if (!wait_for_completion_timeout(&ipc->tx_completion,
					 QTN_SHM_IPC_ACK_TIMEOUT)) {
		ret = -ETIMEDOUT;
		ipc->tx_timeout_count++;
		pr_err("TX ACK timeout\n");
	}

	ipc->waiting_for_ack = false;

	mutex_unlock(&ipc->tx_lock);

	return ret;
}
