/**
 * Copyright (c) 2012 - 2017 Quantenna Communications Inc
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

#ifndef _QVSP_COMMON_H_
#define _QVSP_COMMON_H_

/*
 * Default stream airtime cost in msec per sec to send or receive at 8 Mbps.
 * Constants are binary for efficiency and do not need to be accurate.  They only need to
 * scale so that stream cost roughly equates to used airtime, in order to estimate the
 * affect of disabling or re-enabling a stream.
 */
#define BYTES_PER_KIB			(1024)		/* Kibibytes */
#define BYTES_PER_MIB			(1024 * 1024)	/* Mebibytes */
#define QVSP_STRM_COST_UNIT_MIB		(8)		/* arbitrary (optimised) cost unit */
#define QVSP_STRM_COST_UNIT_BYTES	(QVSP_STRM_COST_UNIT_MIB * BYTES_PER_MIB)
#define QVSP_NODE_COST_DFLT		(1000)

struct qtn_per_tid_stats {
	uint32_t tx_throt_pkts;
	uint32_t tx_throt_bytes;
	uint32_t tx_sent_pkts;
	uint32_t tx_sent_bytes;
};

struct qtm_fat_data {
	uint32_t fat;
	uint32_t intf_ms;
	uint8_t chan;
};

struct qtm_node_params {
	uint32_t tx_cost;
	uint32_t rx_cost;
	uint32_t ralg_inv_phy_rate;
	uint32_t inv_phy_rate_smoothed;
	uint32_t tx_last_mcs;
	uint32_t tx_avg_per;
	uint16_t node_idx;
	uint8_t macaddr[6];
	uint8_t iv_pri;
	uint8_t vendor;
	uint8_t has_qtn_assoc_ie;
	uint8_t vsp_version;
};

struct qtm_tid_stats {
	uint32_t tx_total_pkts;
	uint32_t tx_total_bytes;
	uint32_t tx_sent_pkts;
	uint32_t tx_sent_bytes;
};

struct qtm_throt_ext_params {
	uint8_t node_idx;
	uint8_t macaddr[6];
	uint32_t ipv4_addr; /* fake ipv4 address used for nodetid calculation */
	uint32_t throt_rate;
	uint32_t throt_intv;
	uint8_t strm_state;
};

#endif
