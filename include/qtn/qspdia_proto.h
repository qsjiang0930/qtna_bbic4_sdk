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

#ifndef _QSPDIA_PROTO_H_
#define _QSPDIA_PROTO_H_

#define QSPDIA_NDP	0x00000001
#define QSPDIA_DATA	0x00000002

#define QSPDIA_MIN_INTERVAL	10
#define QSPDIA_NUM_ANT		4

enum {
	QSPDIA_SMOOTH_NONE = 0,
	QSPDIA_SMOOTH_RAMP_ONLY = 1,
	QSPDIA_SMOOTH_EN = 2
};

struct qspdia_conf {
	uint32_t flags;
	uint32_t interval;
	uint8_t ng;
	uint8_t tone_reorder;
	uint8_t smooth;
	uint8_t mac_addr[6];
} __packed;

#define QSPDIA_CONF_INIT { 0, 0, 1, 1, QSPDIA_SMOOTH_NONE, {0} }

struct qspdia_conf_node {
	struct qspdia_conf conf;
	uint32_t tim;
	uint32_t can_spdia;
	uint8_t last_raw_rssi[QSPDIA_NUM_ANT];
};

#define QSPDIA_CONF_NODE_INIT {QSPDIA_CONF_INIT, 0, 0, {0} }

#define QSPDIA_NODES_NUM	3

#define H_TABLE_NTONES_MAX 256

enum {
	QSPDIA_TYPE_ACTION_FRAME = 0,
	QSPDIA_TYPE_CSI_REPORT = 1,
	QSPDIA_TYPE_MAX = 2
};

#define MAGIC_SIZE 8
#define MAGIC_WORD "QCETAPI0"

struct qspdia_hdr {
	uint8_t magic[MAGIC_SIZE];
	int32_t type;
	uint32_t size;
} __packed;

struct qspdia_csi_report {
	struct qspdia_hdr hdr;
	uint64_t timestamp;
	uint8_t macaddr[6];
	int32_t rssi[QSPDIA_NUM_ANT];
	int32_t hw_noise;
	uint8_t bf_mode;
	uint8_t nc;
	uint8_t nr;
	uint8_t bw;
	uint8_t ng;
	uint8_t chan;
	uint8_t mcs;
	uint8_t nss;
	uint32_t ntones;
	uint8_t h_mat[0];
} __packed;

/* Circle buffer for SPDIA reports */
#define QSPDIA_BUCKET_SIZE	20000
#define QSPDIA_BUCKETS_NUM	8

struct qspdia_buf {
	uint32_t cur_bucket;
	uint8_t  buf[QSPDIA_BUCKETS_NUM][QSPDIA_BUCKET_SIZE];
} __packed;

#endif /* _QSPDIA_PROTO_H_ */
