/**
  Copyright (c) 2018 Quantenna Communications Inc
  All Rights Reserved

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

 **/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/sched.h>

#include "qdrv_mac.h"
#include "qdrv_wlan.h"
#include "qtn/qtn_global.h"
#include "qtn/dmautil.h"
#include "qtn/txbf_common.h"
#include "qtn/txbf_mbox.h"

#include "net80211/ieee80211_var.h"

#include "common/queue.h"

#include "qdrv_spdia.h"
#include "net80211/ieee80211_qrpe.h"
#if defined(CONFIG_QTN_BSA_SUPPORT)
#include "net80211/ieee80211_bsa.h"
#endif

struct qspdia_ctx {
	struct qdrv_wlan *qw;
	int running;

	/* Buffers for IPC with DSP */
	struct qspdia_buf *qspdia_buf;
	uint32_t qspdia_buf_dma;
	uint32_t qspdia_buf_len;

	/* Last r_bucket reported by DSP */
	uint32_t cur_bucket;
	/* Bucket num from latest iwevent sent to QDock */
	uint16_t ioctl_last_bucket;
	uint16_t ioctl_circle_num;
};

#define QSPDIA_LAST_BUCKET_MAX (65535)

struct ieee80211_qrpe_spdia_event_with_hdr {
	struct ieee80211_qrpe_event_data hdr;
	struct ieee80211_qrpe_event_spdia event;
} __packed;

static struct qspdia_ctx *qspdia_ctx;

uint32_t qdrv_spdia_get_buf(void **buf, uint16_t ioctl_bucket)
{
	struct qspdia_csi_report *report;
	uint32_t bucket = ioctl_bucket % QSPDIA_BUCKETS_NUM;

	if (!qspdia_ctx || !qspdia_ctx->running || !qspdia_ctx->qspdia_buf)
		return 0;

	/*
	 * Check if this buffer is already overwritten by DSP.
	 * Check if buffer number valid and not equal to current write buffer.
	 */
	if (ioctl_bucket > qspdia_ctx->ioctl_last_bucket ||
		qspdia_ctx->ioctl_last_bucket - ioctl_bucket >= QSPDIA_BUCKETS_NUM ||
		bucket == (qspdia_ctx->cur_bucket + 1) % QSPDIA_BUCKETS_NUM ||
		bucket == (qspdia_ctx->cur_bucket + 2) % QSPDIA_BUCKETS_NUM) {
			return 0;
	}

	*buf = (void *) qspdia_ctx->qspdia_buf->buf[bucket];
	report = *buf;

	return report->hdr.size;
}

static int qdrv_spdia_send_qrpe(uint32_t bucket)
{
	struct ieee80211com *ic;
	struct ieee80211vap *iv;
	struct ieee80211_qrpe_spdia_event_with_hdr spdia_event;

	if (!qspdia_ctx || !qspdia_ctx->running) {
		DBGPRINTF_E("%s: qspdia module not inited\n", __func__);
		return -EFAULT;
	}

	ic = &qspdia_ctx->qw->ic;
	iv = TAILQ_FIRST(&ic->ic_vaps);

	if (iv == NULL) {
		DBGPRINTF_E("%s: cannot obtain vap\n", __func__);
		return -EFAULT;
	}
#if defined(CONFIG_QTN_BSA_SUPPORT)
	if (iv->bsa_status != IEEE80211_QRPE_STATUS_ACTIVE)
		return -EPERM;
#endif

	if (bucket < (qspdia_ctx->ioctl_last_bucket % QSPDIA_BUCKETS_NUM))
		qspdia_ctx->ioctl_circle_num++;

	qspdia_ctx->ioctl_last_bucket = bucket + qspdia_ctx->ioctl_circle_num * QSPDIA_BUCKETS_NUM;

	spdia_event.event.bucket_num = qspdia_ctx->ioctl_last_bucket;

#if defined(CONFIG_QTN_BSA_SUPPORT)
	ieee80211_build_qrpe_event_head(iv, &spdia_event.hdr,
			IEEE80211_QRPE_EVENT_SPDIA_STATS, sizeof(spdia_event.event));

	return ieee80211_send_qrpe_event(BSA_MCGRP_DRV_EVENT, (uint8_t *)&spdia_event,
			sizeof(spdia_event));
#else
	return -EPERM;
#endif
}

int qdrv_spdia_setup(void)
{
	struct ieee80211com *ic;
	struct ieee80211vap *iv;
	dma_addr_t qspdia_buf_dmaaddr;
	int hlink_rc;

	if (!qspdia_ctx || !qspdia_ctx->running) {
		DBGPRINTF_E("%s: qspdia module not inited\n", __func__);
		return -EFAULT;
	}

	/* Already initialized */
	if (qspdia_ctx->qspdia_buf)
		return 0;

	ic = &qspdia_ctx->qw->ic;
	iv = TAILQ_FIRST(&ic->ic_vaps);

	if (iv == NULL) {
		DBGPRINTF_E("%s: cannot obtain vap\n", __func__);
		return -EFAULT;
	}

	qspdia_ctx->qspdia_buf = dma_alloc_coherent(NULL,
					sizeof(struct qspdia_buf),
					&qspdia_buf_dmaaddr, GFP_KERNEL);

	if (!qspdia_ctx->qspdia_buf) {
		DBGPRINTF_E("%s: failed to alloc qspdia buffer\n", __func__);
		return -EFAULT;
	}

	memset(qspdia_ctx->qspdia_buf, 0, sizeof(struct qspdia_buf));
	flush_and_inv_dcache_sizerange_safe((void *) qspdia_ctx->qspdia_buf,
						sizeof(struct qspdia_buf));

	qspdia_ctx->qspdia_buf_dma = qspdia_buf_dmaaddr;
	qspdia_ctx->qspdia_buf_len = sizeof(struct qspdia_buf);

	hlink_rc = qdrv_hostlink_spdia_set_dsp_buf(qspdia_ctx->qw, qspdia_ctx->qspdia_buf_dma,
							qspdia_ctx->qspdia_buf_len);
	if (hlink_rc & QTN_HLINK_RC_ERR) {
		dma_free_coherent(NULL, qspdia_ctx->qspdia_buf_len,
					qspdia_ctx->qspdia_buf, qspdia_ctx->qspdia_buf_dma);
		qspdia_ctx->qspdia_buf = NULL;
		qspdia_ctx->qspdia_buf_dma = 0;
		qspdia_ctx->qspdia_buf_len = 0;

		DBGPRINTF_E("%s: failed to send qspdia buffer\n", __func__);
		return -EFAULT;
	}

	return 0;
}

void qdrv_spdia_dsp_finished(void)
{
	int ret;

	if (!qspdia_ctx || !qspdia_ctx->running || !qspdia_ctx->qspdia_buf)
		return;

	qspdia_ctx->cur_bucket = qspdia_ctx->qspdia_buf->cur_bucket;

	ret = qdrv_spdia_send_qrpe(qspdia_ctx->cur_bucket);
	if (ret != 0)
		DBGPRINTF_E("%s: failed send QRPE, error = %d\n", __func__, ret);
}

int qdrv_spdia_init(struct qdrv_wlan *qw)
{
	if (qspdia_ctx != NULL) {
		DBGPRINTF_E("%s: double run\n", __func__);
		return 0;
	}

	qspdia_ctx = kmalloc(sizeof(struct qspdia_ctx), GFP_KERNEL);
	if (qspdia_ctx == NULL) {
		DBGPRINTF_E("%s: kmalloc fail\n", __func__);
		return -1;
	}

	memset(qspdia_ctx, 0, sizeof(struct qspdia_ctx));

	qspdia_ctx->qw = qw;

	/* set this variable to big value to test ioctl_last_bucket wrap-around */
	qspdia_ctx->ioctl_circle_num = QSPDIA_LAST_BUCKET_MAX / QSPDIA_BUCKETS_NUM - 10;

	qspdia_ctx->running = 1;

	return 0;
}

int qdrv_spdia_exit(struct qdrv_wlan *qw)
{
	if (qspdia_ctx == NULL)
		return 0;

	qspdia_ctx->running = 0;
	if (qspdia_ctx->qspdia_buf) {
		dma_free_coherent(NULL, qspdia_ctx->qspdia_buf_len,
					qspdia_ctx->qspdia_buf, qspdia_ctx->qspdia_buf_dma);
	}

	kfree(qspdia_ctx);
	qspdia_ctx = NULL;

	return 0;
}
