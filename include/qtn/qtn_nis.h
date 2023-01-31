/**
  Copyright (c) 2017 Quantenna Communications Inc
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

/*
 * Node Information Sets
 */
#ifndef _QTN_NIS_H_
#define _QTN_NIS_H_

#define QTN_NIS_SET_NOT_ENABLED(_nis, _set_id, _name, _val)

#ifdef __KERNEL__
#define QTN_NIS_SET(_nis, _set_id, _name, _val)	\
	do {	\
		KASSERT(_set_id == _nis->set_id, ("must use initial set"));	\
		_nis->val[QTN_NIS_S ## _set_id ## _ ## _name] = (_val);		\
		_nis->bitmap |= (1ULL << QTN_NIS_S ## _set_id ## _ ## _name);	\
	} while (0)
#else
#define QTN_NIS_SET(_nis, _set_id, _name, _val)	\
	do {	\
		_nis->val[QTN_NIS_S ## _set_id ## _ ## _name] = (_val);		\
		_nis->bitmap |= (1ULL << QTN_NIS_S ## _set_id ## _ ## _name);	\
	} while (0)
#endif

#define QTN_NIS_ALL_SET(_nis, _set_id, _idx, _name, _val)	\
	do {	\
		KASSERT(_set_id == _nis->set_id, ("must use initial set"));			\
		_nis->node[_idx].val[QTN_NIS_ALL_S ## _set_id ## _ ## _name] = (_val);		\
		_nis->node[_idx].bitmap |= (1ULL << QTN_NIS_ALL_S ## _set_id ## _ ## _name);	\
	} while (0)

#define QTN_NIS_IS_SET(_nis, _i)	(!!(_nis->bitmap & (1ULL << _i)))

#define QTN_NIS_INIT(_nis)		uint64_t *__val = (_nis)->val
#define QTN_NIS_GET(_set_id, _name)				\
	__val[QTN_NIS_S ## _set_id ## _ ## _name]

#define QTN_NIS_ROOT_INIT(_nis)		uint32_t *__root_val = (_nis)->root_val
#define QTN_NIS_ROOT_SET(_set_id, _name, _root_val)		\
	__root_val[QTN_NIS_ROOT_S ## _set_id ## _ ## _name] = (_root_val)
#define QTN_NIS_ROOT_GET(_set_id, _name)				\
	__root_val[QTN_NIS_ROOT_S ## _set_id ## _ ## _name]

#define QTN_NIS_CHILD_INIT(_nis)		uint32_t *__child_val = (_nis)->child_val
#define QTN_NIS_CHILD_SET(_set_id, _name, _child_val)	\
	__child_val[QTN_NIS_CHILD_S ## _set_id ## _ ## _name] = (_child_val)
#define QTN_NIS_CHILD_GET(_set_id, _name)				\
	__child_val[QTN_NIS_CHILD_S ## _set_id ## _ ## _name]

#define QTN_NIS_SET_CHILD_FROM_ROOT(_set_id, _name, _root_val, index)		\
	__child_val[QTN_NIS_CHILD_S ## _set_id ## _ ## _name] =					\
	(_root_val->nodes[index].child_val[QTN_NIS_CHILD_S ## _set_id ## _ ## _name])

/**@addtogroup PerNodeAPIs
 *@{*/

/** Number of elements in an Node Information Set */
#define QTN_NIS_VAL_MAX		64

/** Number of defined Node Information Sets */
#define QTN_NIS_SET_ID_MAX	15
#define QTN_NIS_SET_ID_INVALID		QTN_NIS_SET_ID_MAX

/** Max number of nodes in Node Info List */
#define QTN_NIS_INFO_LIST_SIZE	128

/** Number of root elements in an Node Info List Set */
#define QTN_NIS_ROOT_VAL_MAX		10

/** Number of child elements in an Node Info List Entry Set */
#define QTN_NIS_CHILD_VAL_MAX		100

/**
 * Node information set labels
 */
#define QTN_NIS_LABEL_LEN	35

/**
 * Root node Info list set 0
 */
enum qtn_nis_root_s0_e {
	QTN_NIS_ROOT_S0_free_airtime,
	QTN_NIS_ROOT_S0_total_cli_tx_airtime,
	QTN_NIS_ROOT_S0_total_cli_rx_airtime,
	QTN_NIS_ROOT_S0_MAX
};

/**
 * Root node info list set 1
 */
enum qtn_nis_root_s1_e {
	QTN_NIS_ROOT_S1_total_cli_tx_retries,
	QTN_NIS_ROOT_S1_MAX
};

/**
 * Root node info list set 2
 */
enum qtn_nis_root_s2_e {
	QTN_NIS_ROOT_S2_MAX
};

/**
 * Child node info list entry set 0
 */
enum qtn_nis_child_s0_e {
	QTN_NIS_CHILD_S0_tx_airtime,
	QTN_NIS_CHILD_S0_tx_airtime_accum,
	QTN_NIS_CHILD_S0_rx_airtime,
	QTN_NIS_CHILD_S0_rx_airtime_accum,
	QTN_NIS_CHILD_S0_MAX
};

/**
 * Child node info list entry set 1
 */
enum qtn_nis_child_s1_e {
	QTN_NIS_CHILD_S1_tx_retries_accum,
	QTN_NIS_CHILD_S1_MAX
};

/**
 * Child node info list entry set 2
 */
enum qtn_nis_child_s2_e {
	QTN_NIS_CHILD_S2_ip_addr,
	QTN_NIS_CHILD_S2_MAX
};

/**
 * Identifying information for an node info list entry.
 */
struct qtn_nis_info_list_entry {
	/**
	 * Node index
	 */
	uint16_t	idx;

	/**
	 * MAC address
	 */
	uint8_t  macaddr[MAC_ADDR_LEN];

	/**
	 * Returned data
	 */
	uint32_t	child_val[QTN_NIS_CHILD_VAL_MAX];
};

/**
 * Identifying information for an node info list.
 */
struct qtn_nis_info_list {
	/**
	 * Total number of entries in the list.
	 */
	uint32_t cnt;

	/**
	 * Returned data
	 */
	uint32_t	root_val[QTN_NIS_ROOT_VAL_MAX];

	/**
	 * Node information
	 */
	struct qtn_nis_info_list_entry nodes[QTN_NIS_INFO_LIST_SIZE];
};

/**
 * Generic structure to hold an array of integer values for a node.
 */
struct qtn_nis_set {
	/**
	 * Node information set ID
	 */
	uint16_t set_id;

	/**
	 * MAC address
	 */
	uint8_t mac_addr[MAC_ADDR_LEN];

	/**
	 * Node index
	 */
	uint16_t node_index;

	/**
	 * Miscellaneous flags
	 */
	uint32_t flags;

	/**
	 * Bitmap of fields that have been set
	 */
	uint64_t bitmap;

	/**
	 * Returned data
	 */
	uint64_t val[QTN_NIS_VAL_MAX];
};

#define QTN_NIS_FLAG_MEAS_TYPE			0x00000001
#define QTN_NIS_FLAG_MEAS_TYPE_S		0
#define QTN_NIS_FLAG_MEAS_TYPE_LOCAL		0x00000000
#define QTN_NIS_FLAG_MEAS_TYPE_REMOTE		0x00000001

#define QTN_NIS_FLAG_MEAS_STATUS		0x0000000e
#define QTN_NIS_FLAG_MEAS_STATUS_S		1
#define QTN_NIS_FLAG_MEAS_STATUS_SUCC		0
#define QTN_NIS_FLAG_MEAS_STATUS_TIMEOUT	0x00000001
#define QTN_NIS_FLAG_MEAS_STATUS_NODELEAVE	0x00000002
#define QTN_NIS_FLAG_MEAS_STATUS_STOP		0x00000003

#define QTN_NIS_FLAG_MEAS_REP			0x00000070
#define QTN_NIS_FLAG_MEAS_REP_S			4
#define QTN_NIS_FLAG_MEAS_REP_OK		0x00000000
#define QTN_NIS_FLAG_MEAS_REP_LATE		0x00000001
#define QTN_NIS_FLAG_MEAS_REP_INCAP		0x00000002
#define QTN_NIS_FLAG_MEAS_REP_REFUSE		0x00000003

#define QTN_NIS_FLAG_MEAS_PARAM_TYPE		0xFF000000
#define QTN_NIS_FLAG_MEAS_PARAM_TYPE_S		24

enum qtn_nis_val_type_s {
	QTN_NIS_VAL_UNSIGNED = 0,
	QTN_NIS_VAL_SIGNED,
	QTN_NIS_VAL_FLAG,
	QTN_NIS_VAL_MACADDR,
	QTN_NIS_VAL_INDEX,
	QTN_NIS_VAL_RSN_CAPS,
};

struct qtn_nis_meta_data {
	enum qtn_nis_val_type_s type;
	char *label;
};

/*
 * NOTE: For backwards compatibility, the contents of these sets should not be changed.
 * Keep sets in sync with qtn_nis_meta.
 * New fields *MUST* only be added to the end.
 */

/**
 * Node information name mapping
 */
enum qtn_nis_name_set_mapping_e {
	QTN_NIS_11H_11K_BASIC = 2,
	QTN_NIS_11H_11K_FIRST = QTN_NIS_11H_11K_BASIC,
	QTN_NIS_11H_11K_CCA,
	QTN_NIS_11H_11K_RPI,
	QTN_NIS_11H_11K_CHAN_LOAD,
	QTN_NIS_11H_11K_NOISE_HIS,
	QTN_NIS_11H_11K_BEACON,
	QTN_NIS_11H_11K_FRAME,
	QTN_NIS_11H_11K_TRANS_STREAM_CAT,
	QTN_NIS_11H_11K_MULTICAST_DIAG,
	QTN_NIS_11H_11K_LINK,
	QTN_NIS_11H_11K_NEIGHBOR,
	QTN_NIS_11H_11K_TPC,
	QTN_NIS_11H_11K_COMMON,
	QTN_NIS_11H_11K_LAST = QTN_NIS_11H_11K_COMMON

	/* add new set name here. */
};

/**
 * Node information set 0
 */
enum qtn_nis_s0_e {
	QTN_NIS_S0_assoc_id,
	QTN_NIS_S0_bw,
	QTN_NIS_S0_tx_bytes,
	QTN_NIS_S0_tx_packets,
	QTN_NIS_S0_tx_amsdu_msdus,
	QTN_NIS_S0_tx_mpdus,
	QTN_NIS_S0_tx_ppdus,
	QTN_NIS_S0_tx_dropped,
	QTN_NIS_S0_tx_wifi_drop1,
	QTN_NIS_S0_tx_wifi_drop2,
	QTN_NIS_S0_tx_wifi_drop3,
	QTN_NIS_S0_tx_wifi_drop4,
	QTN_NIS_S0_tx_errors,
	QTN_NIS_S0_tx_ucast,
	QTN_NIS_S0_tx_mcast,
	QTN_NIS_S0_tx_bcast,
	QTN_NIS_S0_tx_max_phy_rate,
	QTN_NIS_S0_tx_max_nss,
	QTN_NIS_S0_tx_max_mcs,
	QTN_NIS_S0_tx_last_phy_rate,
	QTN_NIS_S0_tx_last_nss,
	QTN_NIS_S0_tx_last_mcs,
	QTN_NIS_S0_tx_flags,
	QTN_NIS_S0_tx_retries,
	QTN_NIS_S0_rx_bytes,
	QTN_NIS_S0_rx_packets,
	QTN_NIS_S0_rx_amsdu_msdus,
	QTN_NIS_S0_rx_mpdus,
	QTN_NIS_S0_rx_ppdus,
	QTN_NIS_S0_rx_dropped,
	QTN_NIS_S0_rx_errors,
	QTN_NIS_S0_rx_ucast,
	QTN_NIS_S0_rx_mcast,
	QTN_NIS_S0_rx_bcast,
	QTN_NIS_S0_rx_unknown,
	QTN_NIS_S0_rx_max_phy_rate,
	QTN_NIS_S0_rx_max_nss,
	QTN_NIS_S0_rx_max_mcs,
	QTN_NIS_S0_rx_last_phy_rate,
	QTN_NIS_S0_rx_last_nss,
	QTN_NIS_S0_rx_last_mcs,
	QTN_NIS_S0_rx_smthd_rssi,
	QTN_NIS_S0_rx_flags,
	QTN_NIS_S0_rx_retries,
	QTN_NIS_S0_tx_bw,
	QTN_NIS_S0_rx_bw,
	QTN_NIS_S0_rx_last_rssi,
	QTN_NIS_S0_rx_last_rssi_tot,
	QTN_NIS_S0_rx_smthd_rssi_tot,
	QTN_NIS_S0_timestamp_last_rx,
	QTN_NIS_S0_timestamp_last_tx,
	QTN_NIS_S0_average_tx_phyrate,
	QTN_NIS_S0_average_rx_phyrate,
	QTN_NIS_S0_average_rssi,
	QTN_NIS_S0_pkts_per_sec,
	QTN_NIS_S0_tx_pkt_errors,
	QTN_NIS_S0_tx_airtime,
	QTN_NIS_S0_rx_airtime,
	QTN_NIS_S0_tx_last_rate,
	QTN_NIS_S0_rx_last_rate,
	QTN_NIS_S0_tx_retry_cnt,
	/* Only add new fields here. */
	QTN_NIS_S0_MAX
};

/**
 * Node information set 1
 *
 * Per-TID counters
 */
enum qtn_nis_s1_e {
	QTN_NIS_S1_tx_tid0_bytes,
	QTN_NIS_S1_tx_tid1_bytes,
	QTN_NIS_S1_tx_tid2_bytes,
	QTN_NIS_S1_tx_tid3_bytes,
	QTN_NIS_S1_tx_tid4_bytes,
	QTN_NIS_S1_tx_tid5_bytes,
	QTN_NIS_S1_tx_tid6_bytes,
	QTN_NIS_S1_tx_tid7_bytes,
	QTN_NIS_S1_rx_tid0_bytes,
	QTN_NIS_S1_rx_tid1_bytes,
	QTN_NIS_S1_rx_tid2_bytes,
	QTN_NIS_S1_rx_tid3_bytes,
	QTN_NIS_S1_rx_tid4_bytes,
	QTN_NIS_S1_rx_tid5_bytes,
	QTN_NIS_S1_rx_tid6_bytes,
	QTN_NIS_S1_rx_tid7_bytes,
	QTN_NIS_S1_MAX
};

/**
 * Node information set 2
 */
enum qtn_nis_11h_11k_basic_e {
	/**
	 * basic request set
	 */
	QTN_NIS_S2_offset,
	QTN_NIS_S2_duration,
	QTN_NIS_S2_channel,

	/**
	 * basic result set
	 */
	QTN_NIS_S2_basic,

	/* Only add new fields here. */
	QTN_NIS_S2_MAX
};

/**
 * Node information set 3
 */
enum qtn_nis_11h_11k_cca_e {
	/**
	 * cca request set
	 */
	QTN_NIS_S3_offset,
	QTN_NIS_S3_duration,
	QTN_NIS_S3_channel,

	/**
	 * cca result set
	 */
	QTN_NIS_S3_cca,

	/* Only add new fields here. */
	QTN_NIS_S3_MAX
};

/**
 * Node information set 4
 */
enum qtn_nis_11h_11k_rpi_e {
	/**
	 * rpi request set
	 */
	QTN_NIS_S4_offset,
	QTN_NIS_S4_duration,
	QTN_NIS_S4_channel,

	/**
	 * rpi result set
	 */
	QTN_NIS_S4_rpi_size,
	QTN_NIS_S4_rpi_1,
	QTN_NIS_S4_rpi_2,
	QTN_NIS_S4_rpi_3,
	QTN_NIS_S4_rpi_4,
	QTN_NIS_S4_rpi_5,
	QTN_NIS_S4_rpi_6,
	QTN_NIS_S4_rpi_7,
	QTN_NIS_S4_rpi_8,

	/* Only add new fields here. */
	QTN_NIS_S4_MAX
};

/**
 * Node information set 5
 */
enum qtn_nis_11h_11k_chan_load_e {
	/**
	 * channel load request set
	 */
	QTN_NIS_S5_op_class,
	QTN_NIS_S5_channel,
	QTN_NIS_S5_duration,

	/**
	 * channel load result set
	 */
	QTN_NIS_S5_chan_load,

	/* Only add new fields here. */
	QTN_NIS_S5_MAX
};

/**
 * Node information set 6
 */
enum qtn_nis_11h_11k_noise_his_e {
	/**
	 * noise_his request set
	 */
	QTN_NIS_S6_op_class,
	QTN_NIS_S6_channel,
	QTN_NIS_S6_duration,

	/**
	 * noise_his result set
	 */
	QTN_NIS_S6_antenna_id,
	QTN_NIS_S6_anpi,
	QTN_NIS_S6_ipi_size,
	QTN_NIS_S6_ipi_1,
	QTN_NIS_S6_ipi_2,
	QTN_NIS_S6_ipi_3,
	QTN_NIS_S6_ipi_4,
	QTN_NIS_S6_ipi_5,
	QTN_NIS_S6_ipi_6,
	QTN_NIS_S6_ipi_7,
	QTN_NIS_S6_ipi_8,
	QTN_NIS_S6_ipi_9,
	QTN_NIS_S6_ipi_10,
	QTN_NIS_S6_ipi_11,

	/* Only add new fields here. */
	QTN_NIS_S6_MAX
};

/**
 * Node information set 7
 */
#define  QTN_NIS_NODE_BCN_RPT_FLAG 0xFF
#define  QTN_NIS_NODE_BCN_RPT_ENTRY_MAX 9
enum qtn_nis_11h_11k_beacon_e {
	/**
	 * beacon request set
	 */
	QTN_NIS_S7_op_class,
	QTN_NIS_S7_channel,
	QTN_NIS_S7_duration,
	QTN_NIS_S7_mode,
	QTN_NIS_S7_bssid,

	/**
	 * beacon result set
	 */
	QTN_NIS_S7_item_num,
	QTN_NIS_S7_total_reports,
	QTN_NIS_S7_report_num,
	QTN_NIS_S7_rep_frame_info_1,
	QTN_NIS_S7_rcpi_1,
	QTN_NIS_S7_rsni_1,
	QTN_NIS_S7_bssid_result_1,
	QTN_NIS_S7_antenna_id_1,
	QTN_NIS_S7_parent_tsf_1,
	QTN_NIS_S7_rep_frame_info_2,
	QTN_NIS_S7_rcpi_2,
	QTN_NIS_S7_rsni_2,
	QTN_NIS_S7_bssid_result_2,
	QTN_NIS_S7_antenna_id_2,
	QTN_NIS_S7_parent_tsf_2,
	QTN_NIS_S7_rep_frame_info_3,
	QTN_NIS_S7_rcpi_3,
	QTN_NIS_S7_rsni_3,
	QTN_NIS_S7_bssid_result_3,
	QTN_NIS_S7_antenna_id_3,
	QTN_NIS_S7_parent_tsf_3,
	QTN_NIS_S7_rep_frame_info_4,
	QTN_NIS_S7_rcpi_4,
	QTN_NIS_S7_rsni_4,
	QTN_NIS_S7_bssid_result_4,
	QTN_NIS_S7_antenna_id_4,
	QTN_NIS_S7_parent_tsf_4,
	QTN_NIS_S7_rep_frame_info_5,
	QTN_NIS_S7_rcpi_5,
	QTN_NIS_S7_rsni_5,
	QTN_NIS_S7_bssid_result_5,
	QTN_NIS_S7_antenna_id_5,
	QTN_NIS_S7_parent_tsf_5,
	QTN_NIS_S7_rep_frame_info_6,
	QTN_NIS_S7_rcpi_6,
	QTN_NIS_S7_rsni_6,
	QTN_NIS_S7_bssid_result_6,
	QTN_NIS_S7_antenna_id_6,
	QTN_NIS_S7_parent_tsf_6,
	QTN_NIS_S7_rep_frame_info_7,
	QTN_NIS_S7_rcpi_7,
	QTN_NIS_S7_rsni_7,
	QTN_NIS_S7_bssid_result_7,
	QTN_NIS_S7_antenna_id_7,
	QTN_NIS_S7_parent_tsf_7,
	QTN_NIS_S7_rep_frame_info_8,
	QTN_NIS_S7_rcpi_8,
	QTN_NIS_S7_rsni_8,
	QTN_NIS_S7_bssid_result_8,
	QTN_NIS_S7_antenna_id_8,
	QTN_NIS_S7_parent_tsf_8,
	QTN_NIS_S7_rep_frame_info_9,
	QTN_NIS_S7_rcpi_9,
	QTN_NIS_S7_rsni_9,
	QTN_NIS_S7_bssid_result_9,
	QTN_NIS_S7_antenna_id_9,
	QTN_NIS_S7_parent_tsf_9,

	/* Only add new fields here. */
	QTN_NIS_S7_MAX
};

/**
 * Node information set 8
 */
enum qtn_nis_11h_11k_frame_e {
	/**
	 * frame request set
	 */
	QTN_NIS_S8_op_class,
	QTN_NIS_S8_channel,
	QTN_NIS_S8_duration,
	QTN_NIS_S8_type,
	QTN_NIS_S8_mac_addr,

	/**
	 * frame result set
	 */
	QTN_NIS_S8_sub_ele_report,
	QTN_NIS_S8_ta,
	QTN_NIS_S8_bssid,
	QTN_NIS_S8_phy_type,
	QTN_NIS_S8_avg_rcpi,
	QTN_NIS_S8_last_rcpi,
	QTN_NIS_S8_last_rsni,
	QTN_NIS_S8_antenna_id,
	QTN_NIS_S8_frame_count,

	/* Only add new fields here. */
	QTN_NIS_S8_MAX
};

/**
 * Node information set 9
 */
enum qtn_nis_11h_11k_tran_stream_e {
	/**
	 * tran_stream request set
	 */
	QTN_NIS_S9_duration,
	QTN_NIS_S9_peer_sta,
	QTN_NIS_S9_tid,
	QTN_NIS_S9_bin0,

	/**
	 * tran_stream result set
	 */
	QTN_NIS_S9_reason,
	QTN_NIS_S9_tran_msdu_cnt,
	QTN_NIS_S9_msdu_discard_cnt,
	QTN_NIS_S9_msdu_fail_cnt,
	QTN_NIS_S9_msdu_mul_retry_cnt,
	QTN_NIS_S9_qos_lost_cnt,
	QTN_NIS_S9_avg_queue_delay,
	QTN_NIS_S9_avg_tran_delay,
	QTN_NIS_S9_bin0_range,
	QTN_NIS_S9_bin_1,
	QTN_NIS_S9_bin_2,
	QTN_NIS_S9_bin_3,
	QTN_NIS_S9_bin_4,
	QTN_NIS_S9_bin_5,
	QTN_NIS_S9_bin_6,

	/* Only add new fields here. */
	QTN_NIS_S9_MAX
};

/**
 * Node information set 10
 */
enum qtn_nis_11h_11k_multicast_diag_e {
	/**
	 * multicast_diag request set
	 */
	QTN_NIS_S10_duration,
	QTN_NIS_S10_group_mac,

	/**
	 * multicast_diag result set
	 */
	QTN_NIS_S10_reason,
	QTN_NIS_S10_mul_rec_msdu_cnt,
	QTN_NIS_S10_first_seq_num,
	QTN_NIS_S10_last_seq_num,
	QTN_NIS_S10_mul_rate,

	/* Only add new fields here. */
	QTN_NIS_S10_MAX
};

/**
 * Node information set 11
 */
enum qtn_nis_11h_11k_link_e {
	QTN_NIS_S11_tx_power,
	QTN_NIS_S11_link_margin,
	QTN_NIS_S11_recv_antenna_id,
	QTN_NIS_S11_tran_antenna_id,
	QTN_NIS_S11_rcpi,
	QTN_NIS_S11_rsni,

	/* Only add new fields here. */
	QTN_NIS_S11_MAX
};

/**
 * Node information set 12
 */
enum qtn_nis_11h_11k_neighbor_e {
	QTN_NIS_S12_item_num,
	QTN_NIS_S12_bssid,
	QTN_NIS_S12_bssid_info,
	QTN_NIS_S12_operating_class,
	QTN_NIS_S12_channel,
	QTN_NIS_S12_phy_type,

	/* Only add new fields here. */
	QTN_NIS_S12_MAX
};

/**
 * Node information set 13
 */
enum qtn_nis_11h_11k_tpc_e {
	QTN_NIS_S13_status,
	QTN_NIS_S13_tx_power,
	QTN_NIS_S13_link_margin,

	/* Only add new fields here. */
	QTN_NIS_S13_MAX
};

/**
 * Node information set 14
 */
enum qtn_nis_11h_11k_common_e {
	QTN_NIS_S14_common_b1,
	QTN_NIS_S14_common_b2,
	QTN_NIS_S14_common_b3,

	/* Only add new fields here. */
	QTN_NIS_S14_MAX
};

/** Number of node entries in an All-node Information Set */
#define QTN_NIS_ALL_ENTRY_MAX	64

/** Number of fields in an All-node Information Set */
#define QTN_NIS_ALL_FIELD_MAX	4

/** Number of defined All-node Information Sets */
#define QTN_NIS_ALL_SET_ID_MAX	1

/**
 * Generic structure to hold up to four integer values for a node.
 */
struct qtn_nis_all_node {
	/**
	 * MAC address
	 */
	uint8_t		mac_addr[MAC_ADDR_LEN];

	/**
	 * Node index
	 */
	uint16_t	node_index;

	/**
	 * Bitmap of fields that have been set
	 */
	uint16_t	bitmap;

	/**
	 * Unused
	 */
	uint16_t	flags;

	/**
	 * Returned data
	 */
	uint32_t	val[QTN_NIS_ALL_FIELD_MAX];
};

/**
 * All-node Information Set entry.
 */
struct qtn_nis_all_set {
	/**
	 * Node information set ID
	 */
	uint16_t	set_id;

	/**
	 * Node index to start retrieving from
	 */
	uint16_t	first_node_index;

	/**
	 * Miscellaneous flags
	 */
	uint32_t	flags;

	/**
	 * Number of nodes in report
	 */
	uint16_t	node_cnt;

	/**
	 * Node information
	 */
	struct qtn_nis_all_node node[QTN_NIS_ALL_ENTRY_MAX];
};

/*
 * NOTE: For backwards compatibility, the contents of these sets should not be changed.
 * Keep sets in sync with qtn_nis_all_meta.
 * New fields *MUST* only be added to the end.
 */

/**
 * All-node information set 0
 *
 * RSN Capabilities
 */
enum qtn_nis_all_s0_e {
	QTN_NIS_ALL_S0_rsn_caps,
	/* Only add new fields here. */
	QTN_NIS_ALL_S0_MAX
};

/**@}*/

#endif	// _QTN_NIS_H_

