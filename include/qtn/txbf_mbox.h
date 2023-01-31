/*
 * (C) Copyright 2011 Quantenna Communications Inc.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#ifndef __QTN_TXBF_MBOX_H
#define __QTN_TXBF_MBOX_H

#include "mproc_sync.h"
#include "txbf_common.h"
#include "dsp_stats.h"

#define QTN_TXBF_MBOX_BAD_IDX			((u_int32_t)-1)

#define QTN_TXBF_MUC_TO_DSP_MBOX_INT		(0)
#define QTN_TXBF_DSP_TO_HOST_MBOX_INT		(0)
#define QTN_TXBF_DSP_TO_MUC_MBOX_INT		(0)

#define QTN_RATE_MUC_DSP_MSG_RING_SIZE		(32)

/*
 * QTN_MAX_MU_SND_NODES nodes (6) + QTN_MAX_SND_NODES (10) + 3 for IPC cmd 19.
 * This value still causes buffer allocation failure, which is probably due to bad DSP performance.
 * With 3 more there is no allocation failure for 4 STAs case.
 */
#define QTN_TXBF_MUC_DSP_MSG_RING_SIZE		(6 + 10 + 3 + 3)

#define QTN_TXBF_NDP_DATA_BUFS			(1)

/* MU group install/delete IPC from DSP to LHost */
#define QTN_TXBF_DSP_TO_HOST_INST_MU_GRP        1
#define QTN_TXBF_DSP_TO_HOST_DELE_MU_GRP        2
#define QTN_TXBF_DSP_TO_HOST_QSPDIA_FINISHED    3

#ifndef __ASSEMBLY__

#if DSP_ENABLE_STATS && !defined(QTN_RC_ENABLE_HDP)
#define DSP_UPDATE_STATS(_a, _b)	(qtn_txbf_mbox_get()->dsp_stats._a += (_b))
#define DSP_SETSTAT(_a, _b)		(qtn_txbf_mbox_get()->dsp_stats._a =  (_b))
#else
#define DSP_UPDATE_STATS(_a, _b)
#define DSP_SETSTAT(_a, _b)
#endif

/* Structure be used for txbf message box */
struct qtn_txbf_mbox
{
	/* Write index in txbf_msg_bufs array. Updated only by a sender */
	volatile u_int32_t wr;

	#define MUC_TO_DSP_ACT_MBOX_SIZE	12
	volatile u_int32_t muc_to_dsp_action_frame_mbox[MUC_TO_DSP_ACT_MBOX_SIZE];
	volatile u_int32_t muc_to_dsp_ndp_mbox;
	volatile u_int32_t muc_to_dsp_del_grp_node_mbox;
	volatile u_int32_t muc_to_dsp_gr_upd_done_mbox;
	volatile u_int32_t muc_to_trig_mu_grp_sel_mbox;
	volatile u_int32_t dsp_to_host_mbox;

	volatile struct txbf_pkts txbf_msg_bufs[QTN_TXBF_MUC_DSP_MSG_RING_SIZE];

	volatile struct txbf_ctrl bfctrl_params;

	/* Debug verbosity level */
#define DEBUG_LVL_NO	0
#define DEBUG_LVL_ALL	1
	volatile uint32_t debug_level;

#define MU_QMAT_FREEZE				0x00000001
#define MU_MANUAL_RANK				0x00000002
#define MU_FREEZE_RANK				0x00000004
#define MU_V_GROUPING				0x00000008
#define MU_QMAT_ZERO_STA0			0x00000010
#define MU_QMAT_ZERO_STA1			0x00000020
#define MU_QMAT_PRINT_CHMAT			0x00000100
#define MU_QMAT_PRINT_PRECMAT			0x00000200
#define MU_QMAT_PRINT_SNR			0x00000400
#define MU_QMAT_PRINT_RANK			0x00000800
#define MU_QMAT_PRINT_STUFFMEM			0x00001000
#define MU_QMAT_PRINT_ACTFRM			0x00002000
#define MU_MATLAB_PROCESS			0x00004000
#define MU_V_ANGLE				0x00008000
#define MU_PROJ_PREC_MUEQ_NEED_MASK		0x000F0000
#define MU_PROJ_PREC_MUEQ_NEED_NC0_MASK		0x00030000
#define MU_PROJ_PREC_MUEQ_NEED_NC0_SHIFT	16
#define MU_PROJ_PREC_MUEQ_NEED_NC1_MASK		0x000C0000
#define MU_PROJ_PREC_MUEQ_NEED_NC1_SHIFT	18
#define MU_PRINT_RANK_INFO			0x00100000
#define MU_LIMIT_GRP_ENTRY			0x00300000
#define MU_NEW_GRP_SORT_ALG			0x01000000
#define MU_NEW_GRP_SORT_ALG_S			24
#define MU_NEW_GRP_SORT_ALG_WAR			0x02000000
#define MU_NEW_GRP_SORT_ALG_WAR_S		25
	volatile uint32_t debug_flag;
	volatile struct qtn_sram_qmat mu_grp_qmat[QTN_MU_QMAT_MAX_SLOTS];
	/* Used for testing to set rank for STA pairs manually */
	volatile struct qtn_grp_rank mu_grp_man_rank[QTN_MU_QMAT_MAX_SLOTS];
#if DSP_ENABLE_STATS
	volatile struct qtn_dsp_stats dsp_stats;
#endif

#define MU_ALGORITHM_AUTO		0x00000000
#define MU_ALGORITHM_PROJECTION		0x00000001
#define MU_ALGORITHM_ITERATION		0x00000002
#define MU_PRECODING_ALGORITHM_DEFAULT	MU_ALGORITHM_PROJECTION
#define MU_RANKING_ALGORITHM_DEFAULT	MU_ALGORITHM_AUTO
/* in case of adding algorithms above please update below equation accordingly */
#define MU_ALLOWED_ALG(x) ((x)<=MU_ALGORITHM_ITERATION)
	volatile uint32_t ranking_algorithm_to_use;
	volatile uint32_t precoding_algorithm_to_use;
#define RANK_CRIT_ONE_AND_ONE	0x00000000
#define RANK_CRIT_TWO_AND_ONE	0x00000001
#define RANK_CRIT_THREE_AND_ONE	0x00000002
#define RANK_CRIT_ONE_AND_TWO	0x00000003
#define RANK_CRIT_ONE_AND_THREE	0x00000004
#define RANK_CRIT_TWO_AND_TWO	0x00000005
#define RANK_CRIT_MAX_MU_SUB_MAX_SU	0x00000006
#define RANK_CRIT_DEFAULT	RANK_CRIT_TWO_AND_TWO
#define RANK_CRIT_NO_USER_CONF	0x0000000f
	volatile uint32_t rank_criteria_to_use;

	volatile uint32_t mu_prec_cache_max_time;
	volatile int32_t mu_rank_tolerance;
	volatile uint32_t qtest_data_pointer;
};

#define QTN_MUC_DSP_OPTI_MSG_INDEX 0xFF
struct qtn_muc_dsp_mbox
{
	volatile u_int32_t muc_to_dsp_mbox;
	volatile u_int32_t dsp_to_muc_mbox;
	volatile struct qtn_rate_train_info muc_dsp_msg_bufs[QTN_RATE_MUC_DSP_MSG_RING_SIZE]
				__attribute__ ((aligned (ARC_DCACHE_LINE_LENGTH) ));
	volatile struct qtn_rate_train_info muc_dsp_opti_msg
				__attribute__ ((aligned (ARC_DCACHE_LINE_LENGTH) ));
};

#define QTN_TXBF_MBOX_PROCESSED 1
#define QTN_TXBF_MBOX_NOT_PROCESSED 0

#if !defined(MUC_BUILD) && !defined(DSP_BUILD) && !defined(AUC_BUILD)

#if CONFIG_USE_SPI1_FOR_IPC
	#define QTN_TXBF_D2L_IRQ	RUBY_IRQ_SPI
	#define QTN_TXBF_D2L_IRQ_NAME	"DSP(spi)"
#else
	#define QTN_TXBF_D2L_IRQ	RUBY_IRQ_DSP
	#define QTN_TXBF_D2L_IRQ_NAME	"DSP(d2l)"
#endif

RUBY_INLINE void
qtn_txbf_lhost_init(void)
{
#if CONFIG_USE_SPI1_FOR_IPC
	/* Initialize SPI controller, keep IRQ disabled */
	qtn_mproc_sync_mem_write(RUBY_SPI1_SPCR,
		RUBY_SPI1_SPCR_SPE | RUBY_SPI1_SPCR_MSTR |
		RUBY_SPI1_SPCR_SPR(0));
	qtn_mproc_sync_mem_write(RUBY_SPI1_SPER,
		RUBY_SPI1_SPER_ESPR(0));
#else
	/* Ack, and keep IRQ disabled */
	qtn_mproc_sync_mem_write(RUBY_SYS_CTL_D2L_INT,
		qtn_mproc_sync_mem_read(RUBY_SYS_CTL_D2L_INT));
	qtn_mproc_sync_mem_write(RUBY_SYS_CTL_D2L_INT_MASK,
		~(1 << QTN_TXBF_DSP_TO_HOST_MBOX_INT));
#endif
}

RUBY_INLINE u_int32_t
qtn_txbf_lhost_irq_ack(struct qdrv_mac *mac)
{
#if CONFIG_USE_SPI1_FOR_IPC
	/*
	 * Only single interrupt is supported now.
	 * If need to support more interrupts then something like
	 * 'status' in RAM, guarded by semaphores has to be implemented.
	 * This should be avoided, as it is performance penalty.
	 */
	qtn_mproc_sync_mem_write(RUBY_SPI1_SPSR,
		qtn_mproc_sync_mem_read(RUBY_SPI1_SPSR));
	return (1 << QTN_TXBF_DSP_TO_HOST_MBOX_INT);
#else
	return qtn_mproc_sync_irq_ack_all((u_int32_t)mac->mac_host_dsp_int_status);
#endif
}

RUBY_INLINE void
qtn_txbf_lhost_irq_enable(struct qdrv_mac *mac)
{
#if CONFIG_USE_SPI1_FOR_IPC
	set_bit(RUBY_SPI1_SPCR_SPIE_BIT, (void*)RUBY_SPI1_SPCR);
#else
	set_bit(QTN_TXBF_DSP_TO_HOST_MBOX_INT, (void*)mac->mac_host_dsp_int_mask);
#endif
}

RUBY_INLINE void
qtn_txbf_lhost_irq_disable(struct qdrv_mac *mac)
{
#if CONFIG_USE_SPI1_FOR_IPC
	clear_bit(RUBY_SPI1_SPCR_SPIE_BIT, (void*)RUBY_SPI1_SPCR);
#else
	clear_bit(QTN_TXBF_DSP_TO_HOST_MBOX_INT, (void*)mac->mac_host_dsp_int_mask);
#endif
}

#endif // #if !defined(MUC_BUILD) && !defined(DSP_BUILD) && !defined(AUC_BUILD)

RUBY_INLINE volatile struct txbf_pkts *
qtn_txbf_mbox_alloc_msg_buf(volatile struct qtn_txbf_mbox* mbox) {
	int i;

	for (i = 0; i < ARRAY_SIZE(mbox->txbf_msg_bufs); i++) {
		int j = (i + mbox->wr) % ARRAY_SIZE(mbox->txbf_msg_bufs);
		if (mbox->txbf_msg_bufs[j].state == TXBF_BUFF_FREE) {
			mbox->wr = j;
			mbox->txbf_msg_bufs[j].state = TXBF_BUFF_IN_USE;
			return &mbox->txbf_msg_bufs[j];
		}
	}

	return NULL;
}

RUBY_INLINE void
qtn_txbf_mbox_free_msg_buf(volatile struct txbf_pkts *msg) {
	msg->state = TXBF_BUFF_FREE;
}

RUBY_INLINE u_int32_t
qtn_txbf_mbox_get_index(volatile struct qtn_txbf_mbox* mbox) {
	return mbox->wr;
}

RUBY_INLINE volatile struct qtn_txbf_mbox*
qtn_txbf_mbox_get(void)
{
#if defined(MUC_BUILD) || defined(DSP_BUILD) || defined(AUC_BUILD)
	return qtn_mproc_sync_nocache
		(qtn_mproc_sync_shared_params_get()->txbf_mbox_bus);
#else
	/* Linux target */
	return qtn_mproc_sync_shared_params_get()->txbf_mbox_lhost;
#endif
}

RUBY_INLINE volatile struct qtn_muc_dsp_mbox*
qtn_muc_dsp_mbox_get(void)
{
#if defined(MUC_BUILD) || defined(DSP_BUILD) || defined(AUC_BUILD)
	return qtn_mproc_sync_nocache
		(qtn_mproc_sync_shared_params_get()->muc_dsp_mbox_bus);
#else
	/* Linux target */
	return qtn_mproc_sync_shared_params_get()->muc_dsp_mbox_lhost;
#endif
}

#if defined(MUC_BUILD) || defined(DSP_BUILD) || defined(AUC_BUILD)
RUBY_INLINE int
qtn_muc_dsp_mbox_send(u_int32_t mbox, u_int32_t idx)
{
	int ret = 0;

	if (qtn_mproc_sync_mem_read(mbox) == QTN_TXBF_MBOX_BAD_IDX) {
		qtn_mproc_sync_mem_write_wmb(mbox, idx);
#if defined(MUC_BUILD)
		qtn_mproc_sync_irq_trigger(RUBY_SYS_CTL_M2D_INT,
			QTN_TXBF_MUC_TO_DSP_MBOX_INT);
#else
		qtn_mproc_sync_irq_trigger(RUBY_SYS_CTL_D2M_INT,
			QTN_TXBF_DSP_TO_MUC_MBOX_INT);
#endif
		ret = 1;
	}

	return ret;
}
#endif

#if defined(MUC_BUILD) || defined(DSP_BUILD) || defined(AUC_BUILD)
RUBY_INLINE int
qtn_txbf_mbox_send(u_int32_t mbox, u_int32_t idx)
{
	int ret = 0;

	if (qtn_mproc_sync_mem_read(mbox) == QTN_TXBF_MBOX_BAD_IDX) {
		qtn_mproc_sync_mem_write_wmb(mbox, idx);
#if defined(MUC_BUILD)
		qtn_mproc_sync_irq_trigger(RUBY_SYS_CTL_M2D_INT,
			QTN_TXBF_MUC_TO_DSP_MBOX_INT);
#else
	#if CONFIG_USE_SPI1_FOR_IPC
		qtn_mproc_sync_mem_write(RUBY_SPI1_SPDR, 0x1/*value is not important*/);
	#else
		qtn_mproc_sync_irq_trigger(RUBY_SYS_CTL_D2L_INT,
			QTN_TXBF_DSP_TO_HOST_MBOX_INT);
	#endif
#endif
		ret = 1;
	}

	return ret;
}
#endif

RUBY_INLINE u_int32_t
qtn_txbf_mbox_recv(u_int32_t mbox)
{
	u_int32_t ret = qtn_mproc_sync_mem_read(mbox);
	if (ret != QTN_TXBF_MBOX_BAD_IDX) {
		qtn_mproc_sync_mem_write_wmb(mbox, QTN_TXBF_MBOX_BAD_IDX);
	}

	return ret;
}

RUBY_INLINE void
qtn_txbf_fft_dump_default(void)
{
	qtn_mproc_sync_mem_write(RUBY_QT3_BB_MIMO_BF_RX, QT4_BB_MIMO_BF_RX_INIT_VAL);
	qtn_mproc_sync_mem_write_wmb(RUBY_QT3_BB_GLBL_PREG_INTR_STATUS, RUBY_QT3_BB_FFT_INTR);
}

RUBY_INLINE void
qtn_txbf_fft_dump_any(void)
{
	qtn_mproc_sync_mem_write(RUBY_QT3_BB_MIMO_BF_RX, QT4_BB_MIMO_BF_RX_DUMP_FFT_ANY);
}

RUBY_INLINE int
qtn_txbf_fft_is_any_mode(void)
{
	return qtn_mproc_sync_mem_read(RUBY_QT3_BB_MIMO_BF_RX) & RUBY_QT3_BB_MIMO_BF_RX_DUMP_ANY;
}

RUBY_INLINE void
qtn_txbf_fft_lock(void)
{
	uint32_t bf_rx = qtn_mproc_sync_mem_read(RUBY_QT3_BB_MIMO_BF_RX);

	/* Manual, sw-centric locking. */
	if (bf_rx & RUBY_QT3_BB_MIMO_BF_RX_DUMP_ANY) {
		qtn_mproc_sync_mem_write_wmb(RUBY_QT3_BB_MIMO_BF_RX,
					bf_rx | RUBY_QT3_BB_MIMO_BF_RX_SW_LOCK);
	} else {
		qtn_mproc_sync_mem_write_wmb(RUBY_QT3_BB_MIMO_BF_RX,
					bf_rx & ~RUBY_QT3_BB_MIMO_BF_RX_DUMP_ENABLE);
	}
}

RUBY_INLINE void
qtn_txbf_fft_unlock(void)
{
	uint32_t bf_rx = qtn_mproc_sync_mem_read(RUBY_QT3_BB_MIMO_BF_RX);

	/* Manual, sw-centric locking. */
	if (bf_rx & RUBY_QT3_BB_MIMO_BF_RX_DUMP_ANY) {
		qtn_mproc_sync_mem_write_wmb(RUBY_QT3_BB_MIMO_BF_RX,
					bf_rx & ~RUBY_QT3_BB_MIMO_BF_RX_SW_LOCK);
	} else {
		qtn_mproc_sync_mem_write_wmb(RUBY_QT3_BB_MIMO_BF_RX,
					bf_rx | RUBY_QT3_BB_MIMO_BF_RX_DUMP_ENABLE);
	}
	/* Always do hw-unlocking, it will not affect sw-centric locks. */
	qtn_mproc_sync_mem_write_wmb(RUBY_QT3_BB_GLBL_PREG_INTR_STATUS, RUBY_QT3_BB_FFT_INTR);
}

RUBY_INLINE void
qtn_txbf_fft_unlock_no_wmb(void)
{
	uint32_t bf_rx = qtn_mproc_sync_mem_read(RUBY_QT3_BB_MIMO_BF_RX);

	/* Manual, sw-centric locking. */
	if (bf_rx & RUBY_QT3_BB_MIMO_BF_RX_DUMP_ANY) {
		qtn_mproc_sync_mem_write(RUBY_QT3_BB_MIMO_BF_RX,
					bf_rx & ~RUBY_QT3_BB_MIMO_BF_RX_SW_LOCK);
	} else {
		qtn_mproc_sync_mem_write(RUBY_QT3_BB_MIMO_BF_RX,
					bf_rx | RUBY_QT3_BB_MIMO_BF_RX_DUMP_ENABLE);
	}
	/* Always do hw-unlocking, it will not affect sw-centric locks. */
	qtn_mproc_sync_mem_write(RUBY_QT3_BB_GLBL_PREG_INTR_STATUS, RUBY_QT3_BB_FFT_INTR);
}

RUBY_INLINE int
qtn_txbf_fft_is_sw_locked(void)
{
	uint32_t status = qtn_mproc_sync_mem_read(RUBY_QT3_BB_MIMO_BF_RX);

	return (status & RUBY_QT3_BB_MIMO_BF_RX_SW_LOCK) ||
			!(status & RUBY_QT3_BB_MIMO_BF_RX_DUMP_ENABLE);
}

/*
* qtn_txbf_mbox can be used to set parameters for DSP core from other cores.
* Ideally this way should be reworked but until it happens lets use dedicated macros to access such parameters
* to distibuish this qtn_txbf_mbox usage purpose from others (IPC, BF feedbacks exchange)
*/
#define DSP_PARAM_GET(param) (qtn_txbf_mbox_get()->param)
#define DSP_PARAM_SET(param, value) qtn_txbf_mbox_get()->param = (value)

#endif // #ifndef __ASSEMBLY__

#endif // #ifndef __QTN_TXBF_MBOX_H


