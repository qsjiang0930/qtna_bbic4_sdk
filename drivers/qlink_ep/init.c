/**
 * Copyright (c) 2015-2016 Quantenna Communications, Inc.
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
#include <linux/device.h>
#include <linux/workqueue.h>

#include <qtn/topaz_hbm_cpuif.h>

#include <ruby_pcie_bda.h>
#include <ruby_platform.h>

#include <qdrv/qdrv_control.h>
#include <qdrv/qdrv_soc.h>

#include "qlink_priv.h"
#include "command.h"
#include "events.h"

static struct qlink_server qlink_server;

ssize_t qlink_xmit(void *buf, size_t size)
{
	int ret;

	ret = qlink_shm_ipc_send(&qlink_server.shm_ipc_ep_out, buf, size);

	kfree(buf);

	return (ret == 0) ? size : 0;
}

int qlink_server_init(struct qlink_server *qs)
{
	int ret;

	qs->br_dev = dev_get_by_name(&init_net, QTNF_QBR_IFNAME);
	if (!qs->br_dev) {
		pr_err("couldn't find bridge device %s\n", QTNF_QBR_IFNAME);
		return -ENODEV;
	}

	ret = qlink_events_init(qs);
	if (ret)
		goto err_events;

	ret = qlink_events_mgmt_init(qs);
	if (ret)
		goto err_events;

	pm_qos_update_requirement(PM_QOS_POWER_SAVE, BOARD_PM_GOVERNOR_QCSAPI,
				  BOARD_PM_LEVEL_NO);
	qs->pwr_save = BMPS_MODE_OFF;
	qs->qdrv_dev = qdrv_soc_get_addr_dev();
	qs->qs_status |= QLINK_STATUS_FW_INIT_DONE;

	return 0;

err_events:
	qlink_events_mgmt_deinit(qs);
	qlink_events_deinit(qs);
	dev_put(qs->br_dev);
	qs->br_dev = NULL;

	return ret;
}

void qlink_server_deinit(struct qlink_server *qs)
{
	struct qlink_bss *bss;
	unsigned int macidx;
	unsigned int ifidx;

	for (macidx = 0; macidx < QTNF_MAC_NUM; ++macidx) {
		for (ifidx = 0; ifidx < QTNF_MAX_BSS_NUM; ++ifidx) {
			bss = &qs->maclist[macidx].bss[ifidx];

			if (!bss_has_status(bss, QLINK_BSS_ADDED))
				continue;

			qlink_events_mgmt_bss_deinit(bss);
		}
	}

	qlink_events_mgmt_deinit(qs);
	qlink_events_deinit(qs);

	qs->qs_status &= ~QLINK_STATUS_FW_INIT_DONE;
	dev_put(qs->br_dev);
	qs->br_dev = NULL;
}

static void uboot_pcie_set_bootstate(volatile uint32_t *reg, uint32_t state)
{
	arc_write_uncached_32(reg, state);
}

static void qlink_ep_module_release(struct device *dev)
{
	pr_debug("release\n");
}

static void qlink_pci_shm_ipc_rx_callback(void *arg, const u8 *buf, size_t len)
{
	const struct qlink_cmd *cmd = (void *)buf;

	if (unlikely(len < sizeof(*cmd))) {
		pr_warn("received control packet is too short: %u\n", len);
		return;
	}

	if (unlikely(len != le16_to_cpu(cmd->mhdr.len))) {
		pr_warn("control packet len not match: %u != %u\n",
			len, le16_to_cpu(cmd->mhdr.len));
		return;
	}

	qlink_process_command(&qlink_server, cmd);
}

static void gen_rc_int(void *arg)
{
#define	TOPAZ_ASSERT_INTX	BIT(9)

	volatile qdpc_pcie_bda_t *bda = (qdpc_pcie_bda_t *)(RUBY_PCIE_BDA_ADDR);
	unsigned long reg;

	if (bda->bda_rc_msi_enabled) {
		writew(qlink_server.msi_data, bda->bda_msi_addr);
	} else {
		reg = readl(RUBY_SYS_CTL_PCIE_CFG0);
		writel(reg | TOPAZ_ASSERT_INTX, RUBY_SYS_CTL_PCIE_CFG0);
	}
}

static void qlink_shm_ipc_int_handler(void *arg1, void *arg2)
{
	qlink_shm_ipc_irq_handler(&qlink_server.shm_ipc_ep_in);
	qlink_shm_ipc_irq_handler(&qlink_server.shm_ipc_ep_out);
}

static void qlink_control_path_init(void)
{
	volatile struct qtn_pcie_shm_region *ipc_in_reg;
	volatile struct qtn_pcie_shm_region *ipc_out_reg;
	const struct qlink_shm_ipc_int ipc_int = {gen_rc_int, NULL};
	const struct qlink_shm_ipc_rx_callback rx_callback = {qlink_pci_shm_ipc_rx_callback, NULL};

	ipc_in_reg = &qlink_server.bda->bda_shm_reg1;
	ipc_out_reg = &qlink_server.bda->bda_shm_reg2;

	qlink_shm_ipc_init(&qlink_server.shm_ipc_ep_in, QLINK_SHM_IPC_INBOUND,
			   ipc_in_reg, qlink_server.workqueue, &ipc_int, &rx_callback);
	qlink_shm_ipc_init(&qlink_server.shm_ipc_ep_out, QLINK_SHM_IPC_OUTBOUND,
			   ipc_out_reg, qlink_server.workqueue, &ipc_int, &rx_callback);

	/* Setup IRQ RC -> EP */
	qdrv_set_ipc_irq_handler(qlink_shm_ipc_int_handler);
	qdrv_enable_ipc_irq();
}

static void qlink_control_path_free(void)
{
	qdrv_disable_ipc_irq();
	qdrv_clear_ipc_irq_handler();
	qlink_shm_ipc_free(&qlink_server.shm_ipc_ep_in);
	qlink_shm_ipc_free(&qlink_server.shm_ipc_ep_out);
}

static struct device qlink_ep_device = {
	.platform_data	= (void *)&qlink_server,
	.release	= qlink_ep_module_release,
};

static int __init qlink_module_init(void)
{
#define PCIE_MSI_DATA		(RUBY_PCIE_REG_BASE + 0x5c)
#define MSI_DATA_MASK		0x0000ffff
	volatile qdpc_pcie_bda_t *bda = (qdpc_pcie_bda_t *)(RUBY_PCIE_BDA_ADDR);
	struct shared_params *sp;
	u16 msi_data;
	int ret;

	memset(&qlink_server, 0, sizeof(qlink_server));

	skb_queue_head_init(&qlink_server.cmd_list);

	msi_data = readl(PCIE_MSI_DATA) & MSI_DATA_MASK;
	qlink_server.msi_data = msi_data;
	qlink_server.bda = bda;

	sp = qtn_mproc_sync_shared_params_get();
	qlink_server.sp = sp;
	if (!qlink_server.sp) {
		pr_err("failed to get access to LHost shared data\n");
		return -EFAULT;
	}

	qlink_server.workqueue = create_workqueue("QLINK");
	if (!qlink_server.workqueue) {
		pr_err("failed to alloc cmd workqueue\n");
		return -ENOMEM;
	}

	qlink_control_path_init();
	mutex_init(&qlink_server.mlock);
	dev_set_name(&qlink_ep_device, "qlink_ep");

	ret = device_register(&qlink_ep_device);
	if (ret) {
		pr_err("failed to register \"qlink_ep\"\n");
		goto device_reg_fail;
	}

	ret = qlink_cmd_sysfs_register(&qlink_ep_device);
	if (ret) {
		pr_err("failed to create command sysfs file \"qlink_ep\"\n");
		goto control_sysfs_fail;
	}

	ret = qlink_event_sysfs_register(&qlink_ep_device);
	if (ret) {
		pr_err("failed to create event sysfs file \"qlink_ep\"\n");
		goto control_sysfs_event_fail;
	}

	if (qlink_server.sp->calstate == QTN_CALSTATE_PROD) {
		ret = qdrv_set_hbm_buf_append_meta(1);
		if (ret) {
			pr_err("failed to enable frames meta info\n");
			goto control_sysfs_event_fail;
		}
	}

	uboot_pcie_set_bootstate(&bda->bda_bootstate, QDPC_BDA_FW_QLINK_DONE);
	pr_info("qlink server module initialized\n");

	return 0;

control_sysfs_event_fail:
	qlink_cmd_sysfs_unregister(&qlink_ep_device);
control_sysfs_fail:
	device_unregister(&qlink_ep_device);
device_reg_fail:
	flush_workqueue(qlink_server.workqueue);
	destroy_workqueue(qlink_server.workqueue);

	return ret;
}

static void __exit qlink_module_exit(void)
{
	int ret;

	if (qlink_server.sp->calstate == QTN_CALSTATE_PROD) {
		ret = qdrv_set_hbm_buf_append_meta(0);
		if (ret)
			pr_err("failed to disable frames meta info\n");
	}

	if (qlink_server.qs_status & QLINK_STATUS_FW_INIT_DONE)
		qlink_server_deinit(&qlink_server);

	flush_workqueue(qlink_server.workqueue);
	destroy_workqueue(qlink_server.workqueue);

	qlink_cmd_sysfs_unregister(&qlink_ep_device);
	qlink_event_sysfs_unregister(&qlink_ep_device);
	device_unregister(&qlink_ep_device);

	qlink_control_path_free();

	pr_info("qlink server module exited\n");
}

module_init(qlink_module_init);
module_exit(qlink_module_exit);

MODULE_AUTHOR("Quantenna Communications");
MODULE_DESCRIPTION("Server implementation of Qlink protocol");
MODULE_LICENSE("GPL");
