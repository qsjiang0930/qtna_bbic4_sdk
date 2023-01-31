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

#ifndef _QTN_FMAC_SHM_IPC_H_
#define _QTN_FMAC_SHM_IPC_H_

#include <linux/workqueue.h>
#include <linux/completion.h>
#include <linux/mutex.h>

#include <shm_ipc_defs.h>

#define QTN_SHM_IPC_MAX_RETRY_COUNT	5
#define QTN_SHM_IPC_ACK_TIMEOUT		(2 * HZ)

struct qlink_shm_ipc_int {
	void (*fn)(void *arg);
	void *arg;
};

struct qlink_shm_ipc_rx_callback {
	void (*fn)(void *arg, const u8 *buf, size_t len);
	void *arg;
};

enum qlink_shm_ipc_direction {
	QLINK_SHM_IPC_OUTBOUND		= BIT(0),
	QLINK_SHM_IPC_INBOUND		= BIT(1),
};

enum qlink_shm_ipc_region_flags {
	QLINK_SHM_IPC_NEW_DATA		= BIT(0),
	QLINK_SHM_IPC_ACK		= BIT(1),
	QLINK_SHM_IPC_RETRY		= BIT(2),
};

struct qlink_shm_ipc {
	volatile struct qtn_pcie_shm_region *shm_region;
	enum qlink_shm_ipc_direction direction;
	size_t tx_packet_count;
	size_t rx_packet_count;

	size_t tx_timeout_count;

	volatile bool waiting_for_ack;

	u8 rx_data[QTN_SHM_MAX_DATA_SZ] __aligned(sizeof(u32));

	struct qlink_shm_ipc_int interrupt;
	struct qlink_shm_ipc_rx_callback rx_callback;

	void (*irq_handler)(struct qlink_shm_ipc *ipc);

	struct workqueue_struct *workqueue;
	struct work_struct irq_work;
	struct completion tx_completion;
	struct mutex tx_lock;
};

/* shm_region should be cache-line aligned */
int qlink_shm_ipc_init(struct qlink_shm_ipc *ipc,
		       enum qlink_shm_ipc_direction direction,
		       volatile struct qtn_pcie_shm_region *shm_region,
		       struct workqueue_struct *workqueue,
		       const struct qlink_shm_ipc_int *interrupt,
		       const struct qlink_shm_ipc_rx_callback *rx_callback);
void qlink_shm_ipc_free(struct qlink_shm_ipc *ipc);
int qlink_shm_ipc_send(struct qlink_shm_ipc *ipc, const u8 *buf, size_t size);

static inline void qlink_shm_ipc_irq_handler(struct qlink_shm_ipc *ipc)
{
	ipc->irq_handler(ipc);
}

#endif /* _QTN_FMAC_SHM_IPC_H_ */
