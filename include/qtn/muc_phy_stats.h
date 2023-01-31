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

#ifndef  _MUC_PHY_STATS_H
#define _MUC_PHY_STATS_H

#include "../common/ruby_mem.h"
#include "../common/queue.h"
#include "qtn/qtn_wmm_ac.h"

#define NUM_ANT 4
#define NUM_LOG_BUFFS 0x8

#define MUC_PHY_STATS_ALTERNATE		0
#define MUC_PHY_STATS_RSSI_RCPI_ONLY	1
#define MUC_PHY_STATS_ERROR_SUM_ONLY	2

#define MUC_PHY_ERR_SUM_NOT_AVAIL	0xffffffff

#define MUC_PHY_RSSI_NOT_AVAIL		(-1000)

#include <qtn/muc_txrx_stats.h>

/**
 * \defgroup PHYSTATS PHY generated statistics
 */
/** @{ */

#define QTN_STATS_MCS_SGI	0x40000000
#define QTN_STATS_MCS_BW40	0x80000000

#define QTN_PHY_STATS_MCS_PHYRATE	0xFFFF0000
#define QTN_PHY_STATS_MCS_PHYRATE_S	16
#define QTN_PHY_STATS_MCS_NSS	0xf000
#define QTN_PHY_STATS_MCS_NSS_S	12
#define QTN_PHY_STATS_MCS_BW		0xC00
#define QTN_PHY_STATS_MCS_BW_S	10
#define QTN_PHY_STATS_MCS_MODE		0x380
#define QTN_PHY_STATS_MCS_MODE_S	7
#define QTN_STATS_MCS_RATE_MASK	0x7f
#define QTN_STATS_MCS_RATE_MASK_S 0

#define QTN_NODE_STATS_RSSI_PER_CHAN	NUM_ANT
#define QTN_NODE_STATS_RSSI_AVE		(QTN_NODE_STATS_RSSI_PER_CHAN)
#define QTN_NODE_STATS_RSSI_TOT		(QTN_NODE_STATS_RSSI_AVE + 1)
#define QTN_NODE_STATS_RSSI_MAX		(QTN_NODE_STATS_RSSI_TOT + 1)

enum qtn_stats_mcs_mode{
	QTN_PHY_STATS_MODE_UNKNOWN = 0,
	QTN_PHY_STATS_MODE_11N = 1,
	QTN_PHY_STATS_MODE_11AC = 2,
};

#define QTN_PER_NODE_STATS_POOL_SIZE	QTN_NODE_TBL_SIZE_LHOST

#define EVM_TIME_MEAN_SHIFT	4
#define EVM_TIME_MEAN_COUNT	(1 << EVM_TIME_MEAN_SHIFT)
#define RSSI_TIME_MEAN_SHIFT	4
#define RSSI_TIME_MEAN_COUNT	(1 << RSSI_TIME_MEAN_SHIFT)
#define PHY_RATE_MEAN_SHIFT	4
#define PHY_RATE_MEAN_COUNT	(1 << PHY_RATE_MEAN_SHIFT)

struct qtn_node_shared_stats_tx {
	uint32_t max_queue;
	/*
	 * last_mcs are used as bitmask value
	 * bit[31:16]		rate		(Mbps)
	 * bit[15:12]		nss		(1~4)
	 * bit[11:10]		bw		(0 - 20; 1-40; 2-80; 3-unknow)
	 * bit[9:7]		mode		(1-11n, 2-11ac others-unknow)
	 * bit[6:0]		mcs		([0,76] for 11n, [0,9] [33,76] for 11ac)
	 */
	uint32_t last_mcs;
	uint32_t last_tx_scale;
	uint32_t ralg_inv_phy_rate;
	int32_t avg_rssi_dbm;
	uint32_t cost;
	uint32_t pkts;
	uint32_t txdone_failed_cum;
	uint32_t avg_per;
	uint32_t pkts_per_sec;
	uint32_t avg_tx_phy_rate;
	uint32_t acks;
	uint32_t data_acks;
	uint32_t tx_airtime;
	uint32_t tx_accum_airtime;
	uint32_t tx_accum_retries;

	/**
	 * The total transmit airtime across all TIDs for this client, in microseconds.
	 *
	 * The airtime includes any control frames transmitted prior to the actual packet, for example, RTS or
	 * CTS-to-self.
	 *
	 * Used by BSA to maintain a longer term average of transmit airtime across all TIDs to this client to
	 * make bandsteering decisions.
	 */
	uint32_t time_avg_tx_airtime;

	/*
	 * The number of data packets transmitted through
	 * wireless media for each traffic category(TC).
	 */
	uint32_t tx_sent_data_msdu[WMM_AC_NUM];

	/**
	 * The number of MPDUs transmitted to the station.
	 */
	uint32_t tx_mpdus;
	uint32_t tx_mpdus_cum;

	uint32_t last_sgi;
	uint32_t last_pkt_timestamp;
	uint32_t rts_fails;
};

struct qtn_node_shared_stats_rx {
	int32_t last_rssi_dbm[NUM_ANT + 1];
	int32_t rssi_dbm_smoothed[NUM_ANT + 1];
	int32_t last_rcpi_dbm[NUM_ANT + 1];
	int32_t rcpi_dbm_smoothed[NUM_ANT + 1];
	int32_t last_evm_dbm[NUM_ANT + 1];
	int32_t evm_dbm_smoothed[NUM_ANT + 1];
	int32_t last_hw_noise[NUM_ANT + 1];
	uint32_t last_rxsym;
	/*
	 * last_mcs are used as bitmask value
	 * bit[31:16]		rate		(Mbps)
	 * bit[15:12]		nss		(1~4)
	 * bit[11:10]		bw		(0 - 20; 1-40; 2-80; 3-unknow)
	 * bit[9:7]		mode		(1-11n, 2-11ac others-unknow)
	 * bit[6:0]		mcs		([0,76] for 11n, [0,9] [33,76] for 11ac)
	 */
	uint32_t last_mcs;
	uint32_t pkts;
	uint32_t avg_rx_phy_rate;
	uint32_t data_pkts;
	uint32_t pkts_cum;
	uint32_t data_pkts_cum;
	uint32_t inv_phy_rate_smoothed;
	uint32_t cost;
	uint32_t rx_airtime;
	uint32_t rx_accum_airtime;
	uint32_t last_sgi;
	uint32_t last_pkt_timestamp;
	uint32_t bar_pkts[WME_NUM_TID];
	uint32_t rts_pkts;
};

/**
 * Per node values and statistics; updated periodically
 * with each invocation of qtn_stats_sample, based on
 * MuC per node stats
 */
struct qtn_node_shared_stats {
	/* 0 for SU, 1 for MU */
#define STATS_MIN	0
#define STATS_SU	STATS_MIN
#define STATS_MU	1
#define STATS_MAX	2
	struct qtn_node_shared_stats_tx tx[STATS_MAX];
	struct qtn_node_shared_stats_rx rx[STATS_MAX];
	uint64_t beacon_tbtt;
	uint64_t beacon_tbtt_jiffies;
	uint64_t last_rx_jiffies;
	uint64_t dtim_tbtt;
	uint64_t qtn_tx_bytes;
	uint64_t qtn_rx_bytes;
	uint32_t tim_set;
	uint32_t dtim_set;
	uint16_t beacon_interval;
	uint8_t cfg_4addr;
	uint8_t pad;
};

/**
 * \brief PHY receive statistics
 *
 * These statistics are either read directly from the PHY or are generated
 * based on PHY inputs (eg, RX vector or other structures).
 */
struct qtn_rx_stats {
	/**
	 * The count of the number of packets the PHY has received and passed
	 * up. This is the total of the number of singleton packets (MPDU, MMPDU, control frames),
	 * plus the total of subframes within AMPDUs, plus the number of AMSDUs which have been
	 * passed up from the PHY.
	 *
	 * \note On BBIC4, it just counts single AMPDU rather than the subframes in AMPDU.
	 */
	u_int32_t num_pkts;

	/**
	 * count of packets with A-MSDU flag set
	 */
	u_int32_t num_amsdu;
	/**
	 * count of data packets only. It includes AMPDU subframe count.
	 */
	u_int32_t num_data_pkts;

	/**
	 * The average RX gain used on the previously received packet
	 * (MMPDU, MPDU, AMPDU or singleton AMSDU).
	 */
	u_int32_t avg_rxgain;

	/**
	 * The number of packets received by the PHY with invalid CRC.
	 */
	u_int32_t cnt_mac_crc;

	/**
	 * The number of short preamble failures reported by the PHY.
	 */
	u_int32_t cnt_sp_fail;

	/**
	 * The number of long preamble failures reported by the PHY.
	 */
	u_int32_t cnt_lp_fail;

	int32_t hw_noise;

	u_int32_t max_init_gain;

	/**
	 * The current temperature of the system.
	 */
	u_int32_t sys_temp;

	/**
	 * The mode of the last received packet.
	 * 1 - 11n
	 * 2 - 11ac
	 * others - unknow
	 */
	u_int32_t last_rx_mode;

	/**
	 * The bandwidth of the last received packet.
	 * 0 - 20MHZ
	 * 1 - 40MHZ
	 * 2 - 80MHZ
	 * others - unknow
	 */
	u_int32_t last_rx_bw;

	/**
	 * The MCS index of the last received packet.
	 */
	u_int32_t last_rx_mcs;

	/**
	 * Debug information.
	 */
	u_int32_t rx_gain_fields;

	/**
	 * RSSI / RCPI / EVM for frames
	 */
	int32_t last_rssi_evm[NUM_ANT];

	int32_t last_rssi_all;

	u_int32_t last_rxsym;
	u_int32_t cts_pkts;

	u_int32_t plcperrs;
};

/**
 * \brief PHY transmit statistics
 *
 * These statistics are either read directly from the PHY or are generated
 * based on PHY values.
 */
struct qtn_tx_stats {
	/**
	 * The count of the number of packets (MMPDU, MPDU, AMSDU, and one for each
	 * subframe in an AMPDU) sent to the PHY.
	 *
	 * \note On BBIC4, it just counts single AMPDU rather than the subframes in AMPDU.
	 */
	u_int32_t num_pkts;

	/**
	 * The number of times transmitted packets were deferred due to CCA.
	 */
	u_int32_t num_defers;

	/**
	 * The number of times packets were timed out - spent too long inside the MAC.
	 */
	u_int32_t num_timeouts;

	/**
	 * The number of SW retries - singleton retransmissions, full AMPDU retransmissions,
	 * or partial AMPDU retransmissions.
	 */
	u_int32_t num_swretries;

	/**
	 * The number of MPDUs in HW retries - singleton / AMPDU retransmissions,
	 */
	u_int32_t num_hwretries;

	/**
	 * The transmit power scale index used for the last packet
	 *
	 * \note On BBIC4, This variable is not available.
	 */
	u_int32_t last_tx_scale;

	/**
	 * The mode of the last transmit packet.
	 * 1 - 11n
	 * 2 - 11ac
	 * others - unknow
	 */
	u_int32_t last_tx_mode;

	/**
	 * The bandwidth of the last transmit packet.
	 * 0 - 20MHZ
	 * 1 - 40MHZ
	 * 2 - 80MHZ
	 */
	u_int32_t last_tx_bw;

	/**
	 * The MCS index of the last acknowledged transmit packet.
	 */
	u_int32_t last_tx_mcs;

	/**
	 * Rate adaptations current best throughput rate
	 */
	u_int32_t rate;		/* this field must be last for stat_parser.pl */

	/**
	 * The number of packets per AC.
	 */
	u_int32_t num_msdu_ac[WMM_AC_NUM];
};

/** @} */

struct qtn_stats {
	u_int32_t tstamp;
	struct qtn_rx_stats rx_phy_stats;
	struct qtn_rx_stats mu_rx_phy_stats;
	struct qtn_tx_stats tx_phy_stats;
	struct qtn_tx_stats mu_tx_phy_stats;
};

struct qtn_phy_stats {
	int curr_buff; /* Indx of the buffer with latest data */
	struct qtn_stats stat_buffs[NUM_LOG_BUFFS];
};

struct qtn_stats_log {
	struct qtn_phy_stats *phy_stats;
	struct muc_rx_stats *rx_muc_stats;
	struct muc_stat_rates *rx_muc_rates;
	struct muc_rx_bf_stats *rx_muc_bf_stats;
	struct muc_tx_stats *tx_muc_stats;
	struct qtn_rate_tx_stats_per_sec *tx_muc_rates;
	uint32_t *muc_su_rate_stats_read;
	uint32_t *muc_mu_rate_stats_read;
	uint32_t *scs_cnt;
	struct muc_pta_stats *pta_muc_stats;
	struct qtn_node_rate_stats *rates_per_node;
	uint32_t pad[5]; /* Ensure the pad makes this structure a multiple of ARC cache line size */
};

/*
 * Micro stats: provide stats in micro view along the time axis
 * Can be used for off-channel and other debug purpose.
 */
#define QTN_MICRO_STATS_GRANULARITY	1	/* ms, for trace burst in traffic */
#define QTN_MICRO_STATS_NUM		32	/* enough for max off-channel duration */
struct qtn_micro_stats {
	/*
	 * tx msdu: collected in tx done. With average 1.5ms aggregation timeout, this is accurate
	 * enough for off-channel use.
	 */
	uint32_t tx_msdu;
	/*
	 * rx msdu: collected after rx reorder and mpdu decap, and amsdu decap if existing.
	 * - Delay in rx reorder lead to different instantaneous pkt rate from what is in the
	 *   air in ms level granularity.
	 * - If amsdu decap is done in lhost, bbic3 or bbic4 sdp, this value is not correct.
	 */
	uint32_t rx_msdu;
};

struct qtn_micro_stats_log {
	struct qtn_micro_stats latest_stats;
	/* snapshot */
	uint32_t curr_idx;
	struct qtn_micro_stats micro_stats[QTN_MICRO_STATS_NUM];
};

RUBY_INLINE int qtn_select_rssi_over_error_sums(u_int32_t timestamp, int muc_phy_stats_mode)
{
	int	retval = 0;

	switch (muc_phy_stats_mode) {
	case MUC_PHY_STATS_RSSI_RCPI_ONLY:
		retval = 1;
		break;
	case MUC_PHY_STATS_ERROR_SUM_ONLY:
		retval = 0;
		break;
	case MUC_PHY_STATS_ALTERNATE:
	default:
		retval = (timestamp & 0x01);
		break;
	}

	return( retval );
}

#endif
