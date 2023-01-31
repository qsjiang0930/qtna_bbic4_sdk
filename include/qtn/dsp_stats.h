/**
 * Copyright (c) 2016 - 2017 Quantenna Communications Inc
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

#ifndef _DSP_STATS_H_
#define _DSP_STATS_H_

#include "qtn/txbf_common.h"

#define DSP_ACT_RX_DBG_SIZE	10

#if DSP_ENABLE_STATS
struct qtn_dsp_stats {
	uint32_t dsp_ndp_rx;

	/* Per-node DSP stats */

	/* Total number of feedbacks received */
	uint32_t dsp_act_rx[DSP_ACT_RX_DBG_SIZE];

	/* Number of SU feedbacks */
	uint32_t dsp_act_rx_su[DSP_ACT_RX_DBG_SIZE];

	/* Number of MU group selection feedbacks */
	uint32_t dsp_act_rx_mu_grp_sel[DSP_ACT_RX_DBG_SIZE];

	/* Number of MU precoding feedbacks */
	uint32_t dsp_act_rx_mu_prec[DSP_ACT_RX_DBG_SIZE];

	/* Number of bad feedbacks, i.e. those that are not met SU nor MU criteria */
	uint32_t dsp_act_rx_bad[DSP_ACT_RX_DBG_SIZE];

	/*
	 * Number of feedbacks that were not places into the cache due to any reason. Counters for two reasons
	 * are just below
	 */
	uint32_t dsp_act_rx_mu_drop[DSP_ACT_RX_DBG_SIZE];

	/* The number of MU feedback not placed into the cache as the previous one has not been exprired */
	uint32_t dsp_act_rx_mu_nexp[DSP_ACT_RX_DBG_SIZE];

	/* The number of MU feedback not placed into the cache due to cache is locked */
	uint32_t dsp_act_rx_mu_lock_cache[DSP_ACT_RX_DBG_SIZE];

	/*
	 * The number of precoding feedback was released unused, i.e. not participated in QMat calculation.
	 * It means the buddy feedback either have not been received or received after cache expiration time
	 */
	uint32_t dsp_act_rx_mu_rel_nuse[DSP_ACT_RX_DBG_SIZE];

	/* The number of MU feedback for which dsp_qmat_check_act_len is failed */
	uint32_t dsp_act_rx_inval_len[DSP_ACT_RX_DBG_SIZE];

	uint32_t dsp_del_mu_node_rx;
	uint32_t dsp_ipc_in;
	uint32_t dsp_ipc_out;
	uint32_t dsp_sleep_in;
	uint32_t dsp_sleep_out;
	uint32_t dsp_act_tx;
	uint32_t dsp_ndp_discarded;
	uint32_t dsp_ndp_inv_len;
	uint32_t dsp_ndp_max_len;
	uint32_t dsp_ndp_inv_bw;
	uint32_t dsp_act_free_tx;
	uint32_t dsp_inst_mu_grp_tx;
	uint32_t dsp_qmat_invalid;
	uint32_t dsp_su_feedback_proc_time;
/* Number of QMat currently installed */
	int32_t dsp_sram_qmat_num;
/*
 * Number of times dsp_sram_qmat_num becomes negative. Non zero value signals that the number
 * of QMat de-installation is more than the number of installations. This is an error condition but not a critical one
 */
	uint32_t dsp_err_neg_qmat_num;
	uint32_t dsp_flag;
	/* Interrupts */
	uint32_t dsp_ipc_int;
	uint32_t dsp_timer_int;
	uint32_t dsp_timer1_int;
	uint32_t dsp_last_int;

	uint32_t dsp_exc;
	/* registers */
	uint32_t dsp_status32;
	uint32_t dsp_status32_l1;
	uint32_t dsp_status32_l2;
	uint32_t dsp_ilink1;
	uint32_t dsp_ilink2;
	uint32_t dsp_blink;
	uint32_t dsp_sp;
	uint32_t dsp_time;

	uint32_t dsp_point;
	uint32_t dsp_stat_bad_stack;

	int16_t dspmu_D_user1[4];
	int16_t dspmu_D_user2[4];
	int16_t dspmu_max_intf_user1;
	int16_t dspmu_max_intf_user2;
	int16_t rank_criteria;
	int16_t pad;
	uint32_t dsp_trig_mu_grp_sel;
	uint32_t dsp_mu_rank_success;
	uint32_t dsp_mu_rank_fail;

	/* The number of failed group installations */
	uint32_t dsp_mu_grp_inst_fail;

	/* Per-MU group DSP stats */
	/* The number of successful group installations */
	uint32_t dsp_mu_grp_inst_success[QTN_MU_QMAT_MAX_SLOTS];
	/* The number of successful QMat installations */
	uint32_t dsp_mu_grp_update_success[QTN_MU_QMAT_MAX_SLOTS];
	/* The number of failed QMat installations */
	uint32_t dsp_mu_grp_update_fail[QTN_MU_QMAT_MAX_SLOTS];
	/* Group's AID 0 */
	uint32_t dsp_mu_grp_aid0[QTN_MU_QMAT_MAX_SLOTS];
	/* Group's AID 1 */
	uint32_t dsp_mu_grp_aid1[QTN_MU_QMAT_MAX_SLOTS];
	/* Group's rank */
	int32_t dsp_mu_grp_rank[QTN_MU_QMAT_MAX_SLOTS];

	/* Group candidates stats */
	/* MU_GRP_CAND_NUM_MAX */
	uint32_t dsp_mu_grcand_valid[MU_GRP_CAND_NUM_MAX];
	uint32_t dsp_mu_grcand_aid0[MU_GRP_CAND_NUM_MAX];
	uint32_t dsp_mu_grcand_aid1[MU_GRP_CAND_NUM_MAX];
	uint32_t dsp_mu_grcand_rank[MU_GRP_CAND_NUM_MAX];
	uint32_t dsp_mu_grcand_last_upd_time[MU_GRP_CAND_NUM_MAX];

	/*
	 * Distribution (histogram) of MU QMat copying time
	 0:  0- 3us
	 1:  4- 7us
	 ...............
	 3: 12+ us
	 */
#define DSP_MU_QMAT_COPY_TIME_HIST_WIDTH_US	4
	uint32_t dsp_mu_qmat_qmem_copy_time_hist[4];
	uint32_t dsp_mu_qmat_qmem_copy_time_max;

	/*
	 * Distribution (histogram) of MU QMat calculation and installation time
	 0:  0- 3ms
	 1:  4- 7ms
	 ...............
	 3: 12+ ms
	 */
#define DSP_MU_QMAT_INST_TIME_HIST_WIDTH_MS	6
	uint32_t dsp_mu_qmat_inst_time_hist[8];
	uint32_t dsp_mu_qmat_inst_time_max;

	uint32_t dsp_mu_grp_inv_act;
	uint32_t dsp_act_cache_expired[2];
	uint32_t dsp_mu_grp_upd_done;
	uint32_t dsp_mu_node_del;

	uint32_t dsp_mimo_ctrl_fail;
	uint32_t dsp_mu_fb_80mhz;
	uint32_t dsp_mu_fb_40mhz;
	uint32_t dsp_mu_fb_20mhz;
	uint32_t dsp_mu_drop_20mhz;
};
#endif


#endif	/* _DSP_STATS_H_ */
