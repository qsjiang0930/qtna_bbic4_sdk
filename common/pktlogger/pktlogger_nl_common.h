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

/* Common structures for netdebug - userspace/kernelspace interface */
#ifndef __PKTLOGGER_NL_COMMON_H__
#define __PKTLOGGER_NL_COMMON_H__


#define PKTLOGGER_MSG_MAGIC 0x79FFA904

/* Magic, version, type, length then variable value. */
struct pktlogger_nl_hdr_t
{
	uint32_t magic;
	uint32_t mver;
	uint32_t mtype;
	uint32_t mlen;
	uint32_t mseq;
	uint8_t  msg[0];
};

enum pktlogger_nl_msg
{
	PKTLOGGER_NETLINK_MTYPE_QUERY        = 1,
	PKTLOGGER_NETLINK_MTYPE_CONFIG       = 2,
	PKTLOGGER_NETLINK_MTYPE_CONFIG_ONE   = 3,
	PKTLOGGER_NETLINK_MTYPE_PTYPE_CONFIG = 4
};

struct pktlogger_nl_query_t
{
	struct pktlogger_nl_hdr_t hdr;
	uint32_t query_num;
	uint32_t arg1;
	uint32_t arg2;
	uint8_t data[0];
};

struct pktlogger_nl_pktlog_config_t
{
	uint16_t type;
	uint16_t flags;
	char     name[16];
	uint32_t rate;
	uint32_t history;
	uint16_t struct_bsize;
	uint16_t struct_vsize;
};

struct pktlogger_nl_radio_config_t
{
	uint32_t destip;	/* Network endian destination IP address for pktlogger data.       */
	uint32_t srcip;
	uint8_t  destmac[6];	/* Destination MAC address.                                        */
	uint8_t  srcmac[6];	/* Source MAC address.                                             */
	uint16_t destport;	/* UDP dest port for this radio.                                   */
	uint16_t srcport;	/* UDP src port for this radio.                                    */
	uint32_t pktlog_ver_cnt;/*  0x000000FF: Number of entries in the pktlog_configs array,
				0x00FFFF00: reserved
				0xFF000000: Version of pktlog_types.                               */
	char     radioname[16];	/* Radio name (eg, wifi0, wifi1, wifi2).
				Filled out on query, ignored on configuration.                     */
	struct   pktlogger_nl_pktlog_config_t pktlog_configs[16];	/* Per-pktlogger config.
									Pointer to the first element. */
};

struct pktlogger_nl_config_t
{
	uint32_t rev;
	uint32_t rcontrol;
	struct pktlogger_nl_radio_config_t per_radio[3];
};

struct pktlogger_nl_config_one_t
{
	uint32_t radio_index;
	struct pktlogger_nl_pktlog_config_t config;
};

struct pktlogger_nl_config_set_t
{
	struct pktlogger_nl_hdr_t hdr;
	struct pktlogger_nl_config_t config;
};

struct pktlogger_nl_config_oneset_t
{
	struct pktlogger_nl_hdr_t hdr;
	struct pktlogger_nl_config_one_t config;
};

enum pktlogger_nl_query
{
	PKTLOGGER_QUERY_STRUCT       = 0,
	PKTLOGGER_QUERY_CONFIG       = 1,
	PKTLOGGER_QUERY_CONFIG_ONE   = 2,
	PKTLOGGER_QUERY_PTYPE_CONFIG = 3
};

/* pktlogger header - for all incoming data frames */
struct pktlogger_nl_pktlogger_hdr
{
	struct udphdr hdr;
	uint8_t type;
	uint8_t opmode;
	/**
	 * The source address (the bridge MAC address).
	 */
	unsigned char src[6];
	u_int32_t version;
	u_int32_t builddate;
	/**
	 * Identifying string to easily see in packet dumps that this is a packetlogger packet.
	 */
	char buildstring[32];
#define	QDRV_NETDEBUG_FLAGS_NO_STATS		0x1
#define	QDRV_NETDEBUG_FLAGS_TRUNCATED		0x2
/* Header version: Starts from 0 (for backward-compatibility) */
#define	QDRV_NETDEBUG_FLAGS_MASK_HDR_VERSION	0xFF000000
#define	QDRV_NETDEBUG_FLAGS_MASK_HDR_VERSION_S	24
	u_int32_t flags;

	/**
	 * Timestamp (in 5ms resolution for backward compatibility).
	 */
	u_int32_t timestamp;
	/**
	 * TSF timestamp low bytes.
	 */
	u_int32_t tsf_lo;
	/**
	 * TSF timestamp high bytes.
	 */
	u_int32_t tsf_hi;

	u_int32_t platform;
	u_int32_t stats_len;
	char padding[3];     /* Word align data start */
} __attribute__((__packed__));

#endif
