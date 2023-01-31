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

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 **/

/*
 * Quantenna Information Sets
 */
#ifndef _QTNIS_H_
#define _QTNIS_H_

#ifndef IFNAMSIZ
#define IFNAMSIZ	16
#endif /* IFNAMSIZ */

#define QTNIS_SET_NOT_ENABLED(_qtnis, _set_id, _name, _val)
#ifdef __KERNEL__
#define QTNIS_SET(_qtnis, _set_id, _name, _val)	\
	do {	\
		KASSERT(_set_id == _qtnis->set_id, ("must use initial set"));	\
		_qtnis->val[QTNIS_S ## _set_id ## _ ## _name] = (_val);		\
		_qtnis->bitmap |= (1ULL << QTNIS_S ## _set_id ## _ ## _name);	\
	} while (0)
#else
#define QTNIS_SET(_qtnis, _set_id, _name, _val)	\
	do {	\
		_qtnis->val[QTNIS_S ## _set_id ## _ ## _name] = (_val);		\
		_qtnis->bitmap |= (1ULL << QTNIS_S ## _set_id ## _ ## _name);	\
	} while (0)
#endif
#define QTNIS_IS_SET(_qtnis, _i)	(!!(_qtnis->bitmap & (1ULL << _i)))

/**@addtogroup InfosetAPIs
 *@{*/

/**
 * Infoset field types.
 */
enum qtnis_val_type_s {
	/**
	 * Unsigned integer
	 */
	QTNIS_VAL_UNSIGNED = 0,

	/**
	 * Signed integer
	 */
	QTNIS_VAL_SIGNED,

	/**
	 * Miscellaneous flags
	 */
	QTNIS_VAL_FLAG,

	/**
	 * MAC address
	 */
	QTNIS_VAL_MACADDR,

	/**
	 * Index
	 */
	QTNIS_VAL_INDEX
};

/**
 * Infoset metadata
 */
struct qtnis_meta_data {
	enum qtnis_val_type_s type;
	char *label;
};

/** Number of elements in an Interface Information Set */
#define QTNIS_IF_VAL_MAX		64

/** CAP scan+auto scan set ID */
#define QTNIS_SET_ID_SCAN_CAP		3

/** CAP cac set ID */
#define QTNIS_SET_ID_CAC_CAP		4

/** Number of defined Interface Information Sets */
#define QTNIS_SET_ID_MAX		5

/**
 * Generic structure to hold an array of integer values for an interface.
 */
struct qtnis_if_set {
	/**
	 * Interface information set ID
	 */
	uint16_t	set_id;

	/**
	 * Interface name
	 */
	int8_t		ifname[IFNAMSIZ];

	/**
	 * Interface MAC address
	 */
	uint8_t		mac_addr[MAC_ADDR_LEN];

	/**
	 * Miscellaneous flags
	 */
	uint64_t	flags;

	/**
	 * Bitmap of fields that have been set
	 */
	uint64_t	bitmap;

	/**
	 * Returned data
	 */
	uint64_t	val[QTNIS_IF_VAL_MAX];
};

/*
 * NOTE: For backwards compatibility, the contents of these sets should not be changed.
 * Keep sets in sync with qcsapi_qtnis_if_label.
 * New fields *MUST* only be added to the end.
 */

/**
 * Interface information set 0
 */

enum qtnis_if_s0_e {
	QTNIS_S0_assoc_id,
	QTNIS_S0_bw,

	QTNIS_S0_tx_bytes,
	QTNIS_S0_tx_packets,
	QTNIS_S0_tx_amsdu_msdus,
	QTNIS_S0_tx_mpdus,
	QTNIS_S0_tx_ppdus,
	QTNIS_S0_tx_wifi_sent_be,
	QTNIS_S0_tx_wifi_sent_bk,
	QTNIS_S0_tx_wifi_sent_vi,
	QTNIS_S0_tx_wifi_sent_vo,
	QTNIS_S0_tx_dropped,
	QTNIS_S0_tx_wifi_drop_be,
	QTNIS_S0_tx_wifi_drop_bk,
	QTNIS_S0_tx_wifi_drop_vi,
	QTNIS_S0_tx_wifi_drop_vo,
	QTNIS_S0_tx_errors,
	QTNIS_S0_tx_ucast,
	QTNIS_S0_tx_mcast,
	QTNIS_S0_tx_bcast,
	QTNIS_S0_tx_ucast_bytes,
	QTNIS_S0_tx_mcast_bytes,
	QTNIS_S0_tx_bcast_bytes,
	QTNIS_S0_tx_max_phy_rate,
	QTNIS_S0_tx_max_nss,
	QTNIS_S0_tx_max_mcs,
	QTNIS_S0_tx_last_phy_rate,
	QTNIS_S0_tx_last_nss,
	QTNIS_S0_tx_last_mcs,
	QTNIS_S0_tx_flags,
	QTNIS_S0_tx_retries,
	QTNIS_S0_tx_bw,

	QTNIS_S0_rx_bytes,
	QTNIS_S0_rx_packets,
	QTNIS_S0_rx_amsdu_msdus,
	QTNIS_S0_rx_mpdus,
	QTNIS_S0_rx_ppdus,
	QTNIS_S0_rx_dropped,
	QTNIS_S0_rx_errors,
	QTNIS_S0_rx_ucast,
	QTNIS_S0_rx_mcast,
	QTNIS_S0_rx_bcast,
	QTNIS_S0_rx_ucast_bytes,
	QTNIS_S0_rx_mcast_bytes,
	QTNIS_S0_rx_bcast_bytes,
	QTNIS_S0_rx_unknown,
	QTNIS_S0_rx_max_phy_rate,
	QTNIS_S0_rx_max_nss,
	QTNIS_S0_rx_max_mcs,
	QTNIS_S0_rx_last_phy_rate,
	QTNIS_S0_rx_last_nss,
	QTNIS_S0_rx_last_mcs,
	QTNIS_S0_rx_smthd_rssi,
	QTNIS_S0_rx_flags,
	QTNIS_S0_rx_retries,
	QTNIS_S0_rx_bw,
	QTNIS_S0_rx_last_rssi,
	QTNIS_S0_rx_last_rssi_tot,
	QTNIS_S0_rx_smthd_rssi_tot,

	/* Only add new fields here. */
	QTNIS_S0_MAX
};

/**
 * Interface information set 1
 */
enum qtnis_11h_11k_basic_e {
	/**
	 * basic request set
	 */
	QTNIS_S1_offset,
	QTNIS_S1_duration,
	QTNIS_S1_channel,

	/**
	 * basic result set
	 */
	QTNIS_S1_basic,

	/* Only add new fields here. */
	QTNIS_S1_MAX
};

/**
 * Interface information set 2
 *
 * \note If MBSS is enabled, these values are totals for all VAPs.
 */
enum qtnis_if_infoset_e {
	/**
	 * The number of expected ACKs that were never received.
	 */
	QTNIS_S2_tx_ack_failures,
	/**
	 * The number of received packets with an invalid mac header.
	 */
	QTNIS_S2_rx_invalid_mac_header,
	/**
	 * The number of received packets from non-associated stations.
	 */
	QTNIS_S2_rx_non_assoc_packets,
	/**
	 * The number of frames for which the parity check of the PLCP header failed.
	 */
	QTNIS_S2_rx_plcp_errors,
	/**
	 * The number of frames for which the Frame Check Sequence (FCS) was in error.
	 */
	QTNIS_S2_rx_fcs_errors,

	/* Only add new fields here. */
	QTNIS_S2_MAX
};

/**
 * Interface information set for scan capability reporting
 */
enum qtnis_if_infoset_cap_scan {
	/**
	 * current auto scan state
	 */
	QTNIS_S3_cap_scan_auto_scan,

	/**
	 * Capability 0: scan only at boot
	 */
	QTNIS_S3_cap0_scan_boot,

	/**
	 * Capability 0: type of scan impact
	 */
	QTNIS_S3_cap0_scan_impact,

	/**
	 * Capability 0: minimum scan interval
	 */
	QTNIS_S3_cap0_scan_min_scan_intv,

	/**
	 * Capability 0: reserved 0
	 */
	QTNIS_S3_cap0_reserved_0,

	/**
	 * Capability 0: reserved 1
	 */
	QTNIS_S3_cap0_reserved_1,

	/**
	 * Capability 0: reserved 2
	 */
	QTNIS_S3_cap0_reserved_2,

	/**
	 * Capability 1: scan only at boot
	 */
	QTNIS_S3_cap1_scan_boot,

	/**
	 * Capability 1: type of scan impact
	 */
	QTNIS_S3_cap1_scan_impact,

	/**
	 * Capability 1: minimum scan interval
	 */
	QTNIS_S3_cap1_scan_min_scan_intv,

	/**
	 * Capability 1: reserved 0
	 */
	QTNIS_S3_cap1_reserved_0,

	/**
	 * Capability 1: reserved 1
	 */
	QTNIS_S3_cap1_reserved_1,

	/**
	 * Capability 1: reserved 2
	 */
	QTNIS_S3_cap1_reserved_2,

	/**
	 * Capability 2: scan only at boot
	 */
	QTNIS_S3_cap2_scan_boot,

	/**
	 * Capability 2: type of scan impact
	 */
	QTNIS_S3_cap2_scan_impact,

	/**
	 * Capability 2: minimum scan interval
	 */
	QTNIS_S3_cap2_scan_min_scan_intv,

	/**
	 * Capability 2: reserved 0
	 */
	QTNIS_S3_cap2_reserved_0,

	/**
	 * Capability 2: reserved 1
	 */
	QTNIS_S3_cap2_reserved_1,

	/**
	 * Capability 2: reserved 2
	 */
	QTNIS_S3_cap2_reserved_2,

	/**
	 * Capability 3: scan only at boot
	 */
	QTNIS_S3_cap3_scan_boot,

	/**
	 * Capability 3: type of scan impact
	 */
	QTNIS_S3_cap3_scan_impact,

	/**
	 * Capability 3: minimum scan interval
	 */
	QTNIS_S3_cap3_scan_min_scan_intv,

	/**
	 * Capability 3: reserved 0
	 */
	QTNIS_S3_cap3_reserved_0,

	/**
	 * Capability 3: reserved 1
	 */
	QTNIS_S3_cap3_reserved_1,

	/**
	 * Capability 3: reserved 2
	 */
	QTNIS_S3_cap3_reserved_2,

	/* Only add new fields here. */
	QTNIS_S3_MAX
};

/**
 * Interface information set for CAC capability reporting
 */
enum qtnis_if_infoset_cap_cac {
	/**
	 * Capability 0: CAC type
	 */
	QTNIS_S4_cap0_cac_type,

	/**
	 * Capability 0: CAC duration in normal channel
	 */
	QTNIS_S4_cap0_cac_dur,

	/**
	 * Capability 0: CAC duration in weather channel
	 */
	QTNIS_S4_cap0_cac_dur_wea,

	/**
	 * Capability 0: non-occupancy duration in normal channel
	 */
	QTNIS_S4_cap0_cac_nop_dur,

	/**
	 * Capability 0: non-occupancy duration in weather channel
	 */
	QTNIS_S4_cap0_cac_nop_dur_wea,

	/**
	 * Capability 0: reserved 0
	 */
	QTNIS_S4_cap0_reserved_0,

	/**
	 * Capability 0: reserved 1
	 */
	QTNIS_S4_cap0_reserved_1,

	/**
	 * Capability 1: CAC type
	 */
	QTNIS_S4_cap1_cac_type,

	/**
	 * Capability 1: CAC duration in normal channel
	 */
	QTNIS_S4_cap1_cac_dur,

	/**
	 * Capability 1: CAC duration in weather channel
	 */
	QTNIS_S4_cap1_cac_dur_wea,

	/**
	 * Capability 1: non-occupancy duration in normal channel
	 */
	QTNIS_S4_cap1_cac_nop_dur,

	/**
	 * Capability 1: non-occupancy duration in weather channel
	 */
	QTNIS_S4_cap1_cac_nop_dur_wea,

	/**
	 * Capability 1: reserved 0
	 */
	QTNIS_S4_cap1_reserved_0,

	/**
	 * Capability 1: reserved 1
	 */
	QTNIS_S4_cap1_reserved_1,

	/**
	 * Capability 2: CAC type
	 */
	QTNIS_S4_cap2_cac_type,

	/**
	 * Capability 2: CAC duration in normal channel
	 */
	QTNIS_S4_cap2_cac_dur,

	/**
	 * Capability 2: CAC duration in weather channel
	 */
	QTNIS_S4_cap2_cac_dur_wea,

	/**
	 * Capability 2: non-occupancy duration in normal channel
	 */
	QTNIS_S4_cap2_cac_nop_dur,

	/**
	 * Capability 2: non-occupancy duration in weather channel
	 */
	QTNIS_S4_cap2_cac_nop_dur_wea,

	/**
	 * Capability 2: reserved 0
	 */
	QTNIS_S4_cap2_reserved_0,

	/**
	 * Capability 2: reserved 1
	 */
	QTNIS_S4_cap2_reserved_1,

	/**
	 * Capability 3: CAC type
	 */
	QTNIS_S4_cap3_cac_type,

	/**
	 * Capability 3: CAC duration in normal channel
	 */
	QTNIS_S4_cap3_cac_dur,

	/**
	 * Capability 3: CAC duration in weather channel
	 */
	QTNIS_S4_cap3_cac_dur_wea,

	/**
	 * Capability 3: non-occupancy duration in normal channel
	 */
	QTNIS_S4_cap3_cac_nop_dur,

	/**
	 * Capability 3: non-occupancy duration in weather channel
	 */
	QTNIS_S4_cap3_cac_nop_dur_wea,

	/**
	 * Capability 3: reserved 0
	 */
	QTNIS_S4_cap3_reserved_0,

	/**
	 * Capability 3: reserved 1
	 */
	QTNIS_S4_cap3_reserved_1,

	/* Only add new fields here. */
	QTNIS_S4_MAX
};

/**@}*/

#endif /* _QTNIS_H_ */
