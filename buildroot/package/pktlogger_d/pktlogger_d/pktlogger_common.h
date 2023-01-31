/*
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 - 2019 Quantenna Communications Inc            **
**                                                                           **
**  File        : pktlogger_common.h                                         **
**  Description : pktlogger data structures and definitions                  **
**                                                                           **
*******************************************************************************
*/

#ifndef __PKTLOGGER_COMMON_H__
#define __PKTLOGGER_COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif

#define PKTLOGGER_NET_MAGIC	0x706b746c
#define PKTLOGGER_NET_VERSION	0
#define PKTLOGGER_MAX_RADIOS	3
#define PKTLOGGER_D_NET_PORT	9041

#define PKTLOGGER_CONFIG_FLAGS_ENABLED		0x0001
#define PKTLOGGER_CONFIG_FLAGS_VARIABLE_ARRAY	0x0002
#define PKTLOGGER_CONFIG_FLAGS_VARIABLE_STRING	0x0004

#define PKTLOGGER_RADIO_MASK_NUMBER		0x000000FF
#define PKTLOGGER_RADIO_MASK_TYPES_VER		0xFF000000

#define PKTLOGGER_REQ_COUNT_WHOLE_HISTORY_AND_REAL_TIME_DATA    0xFFFF
#define PKTLOGGER_REQ_COUNT_STOP_STREAMING                      0x0000

enum pktlogger_net_msg
{
	PKTLOGGER_MSG_INVALID              = 0,
	PKTLOGGER_MSG_STRUCT_REQUEST       = 1,	/* Query the pktlogger structs configured on the device.
						The return value will be in the form of ‘struct pktlogger_msg_query_t’
						with the compressed (LZMA) structure definitions directly following
						the structure. The mtype of the return structure will be
						‘PKTLOGGER_MSG_STRUCT_RESPONSE’. */
	PKTLOGGER_MSG_STRUCT_RESPONSE      = 2,	/* The response frame for the PKTLOGGER_MSG_STRUCT_REQUEST
						sent previously. Match up the requests/responses using the ‘mseq’
						field in the struct pktlogger_net_hdr_t. */
	PKTLOGGER_MSG_CONFIG_SET           = 3,	/* Configure the pklogger instance in some way.
						Packet contents is of type struct ‘pktlogger_msg_config_t’. */
	PKTLOGGER_MSG_CONFIG_REQUEST       = 4,	/* Request to obtain the pktlogger configuration.
						Match up the requests/responses using the ‘mseq’ field in
						the struct pktlogger_net_hdr_t. */
	PKTLOGGER_MSG_CONFIG_RESPONSE      = 5,	/* Response frame for the PKTLOGGER_MSG_CONFIG_REQUEST
						sent previously. Match up the requests/responses using the ‘mseq’
						field in the struct pktlogger_net_hdr_t. */
	PKTLOGGER_MSG_PTYPE_SET            = 6,
	PKTLOGGER_MSG_PTYPE_REQUEST        = 7,
	PKTLOGGER_MSG_PTYPE_RESPONSE       = 8,
	PKTLOGGER_MSG_PTYPE_DATA_READ      = 9,	/* Read in the stored ptype data. */
	PKTLOGGER_MSG_CONFIG_ONESET        = 10,/* Set a single pktlogger information. Type is ‘pktlogger_net_config_one_t’ */
	PKTLOGGER_MSG_CONFIG_ONEREQUEST    = 11,/* Get a single pktlogger type information. Type is ‘pktlogger_net_query_one_t’ */
	PKTLOGGER_MSG_CONFIG_ONERESPONSE   = 12,/* Response to a ‘PKTLOGGER_MSG_CONFIG_ONE_REQUEST’. Type is ‘pktlogger_net_config_one_t’ */
	PKTLOGGER_MSG_DATA_STREAM_REQUEST  = 13,
	PKTLOGGER_MSG_DATA_STREAM          = 14,
	PKTLOGGER_MSG_MAX_TYPE
};

enum pktlogger_stat_types
{
	PKTLOGGER_TYPE_UNUSED_0            = 0, /* --- !!! Never change this id                  */
	PKTLOGGER_TYPE_QDRV_NETDEBUG_STATS = 1,	/* The main statistics array, containing stats
						 * from various CPUs and subsystems within the
						 * QTN chipset.
						 */
	PKTLOGGER_TYPE_UNUSED_2            = 2, /* can be utilized later on                      */
	PKTLOGGER_TYPE_QDRV_RADAR_STATS    = 3,	/* Radar memory output.                          */
	PKTLOGGER_TYPE_NETDEBUG_TXBF       = 4,	/* TXBF steering vector output.                  */
	PKTLOGGER_TYPE_NETDEBUG_IWEVENT    = 5,	/* iwevent variable length string output.        */
	PKTLOGGER_TYPE_NETDEBUG_SYSMSG     = 6,	/* syslog message variable length string output. */
	PKTLOGGER_TYPE_NETDEBUG_MEM        = 7,	/* Memory monitor/dump output.                   */
	PKTLOGGER_TYPE_NETDEBUG_RATE       = 8,	/* Rate logger output.                           */
	PKTLOGGER_TYPE_NETDEBUG_VSP        = 9, /* VSP.                                          */
	PKTLOGGER_TYPE_NETDEBUG_PHY_STATS  = 10,/* Variable array length phy stats per client.   */
	PKTLOGGER_TYPE_NETDEBUG_DSP_STATS  = 11,/* DSP statistics.                               */
	PKTLOGGER_TYPE_NETDEBUG_CORE_DUMP  = 12,/* core dump.                                    */
	PKTLOGGER_TYPE_NODE_RATE_STATS     = 13,/* Per-node MCS statistics                       */
	PKTLOGGER_TYPE_VISION              = 14,/* Vision reporter statistic                     */
	PKTLOGGER_TYPE_UNUSED_15           = 15,/* can be utilized later on                      */
	PKTLOGGER_TYPE_MAX
};

/* Incoming from network header */
struct pktlogger_net_hdr_t
{
	uint32_t magic;
	uint32_t version;
	uint32_t mtype;
	uint32_t mlen; /* Of the data field only */
	uint32_t mseq;
};

struct pktlogger_net_query_one_t
{
	struct pktlogger_net_hdr_t hdr;
	uint32_t radio_index;
	uint32_t type;
};

struct pktlogger_pktlog_config_t
{
	uint16_t type;		/* Pktlogger type (enum pktlogger_stat_types)                      */
	uint16_t flags;		/* Flags for this pktlogger type:
				 * 0x1 - pktlogger type is enabled
				 * 0x2 - variable array structure
				 * 0x4 - variable string based structure
				 */
	uint8_t  name[16];	/* Pktlogger structure name (as contained in the results from the
				 * LZMA compressed structure array). Filled in on query,
				 * ignored on config.
				 */
	uint32_t rate;		/* Period for this pktlogger output in units of s (>= 1)           */
	uint32_t history;	/* Amount of history of this data to retain - number of entries.
				 * 0 - to store no history.
				 */
	uint16_t struct_bsize;  /* Size of the structure returned by this pktlogger type, the base
				 * size excluding any variable component. Valid for all pktlogger
				 * types. Filled in on query, ignored on set.
				 */
	uint16_t struct_vsize;  /* Size of the variable part of the structure. This field is only
				 * valid if the flags have bit 0x2 set. Filled in on query, ignored
				 * on set.
				 */
};

struct pktlogger_radio_config_t
{
	uint32_t destip;	/* Network endian destination IP address for pktlogger data.       */
	uint32_t srcip;		/* Network endian source IP address for pktlogger data.            */
	uint8_t  destmac[6];	/* Destination MAC address.                                        */
	uint8_t  srcmac[6];	/* Source MAC address.                                             */
	uint16_t destport;	/* UDP dest port for this radio.                                   */
	uint16_t srcport;	/* UDP src port for this radio.                                    */
	uint32_t pktlog_ver_cnt;/* 0x000000FF: Number of entries in the pktlog_configs array,
					0x00FFFF00: reserved
					0xFF000000: Version of pktlog_types.                       */
	uint8_t  radioname[16];	/* Radio name (eg, wifi0, wifi1, wifi2).
				   Filled out on query, ignored on configuration.                  */
	struct pktlogger_pktlog_config_t pktlog_configs[PKTLOGGER_TYPE_MAX]; /* Per pktlogger cfg */
};

struct pktlogger_config_t
{
	uint32_t rev;		/* Configuration revision */
	uint32_t radio_mask;	/* Flag field indicating which radio configurations are present:
				0x00000001 – radio index 0 config present
				0x00000002 – radio index 1 config present
				0x00000004 – radio index 2 config present */
	struct pktlogger_radio_config_t per_radio[PKTLOGGER_MAX_RADIOS];/* Per radio configuration*/
};

struct pktlogger_ptype_config_t
{
	int32_t ptype;		/* Packetlogger type, see enum pktlogger_stat_types.               */
	int32_t offset_sz;	/* upper 16-bits: offset into the structure referenced by ‘ptype’,
				lower 16-bits: width of data type.                                 */
	int32_t th_lo;		/* Low threshold for enabling gathering of data.                   */
	int32_t th_hi;		/* High threshold for triggering gathering of data.                */
};

struct pktlogger_net_query_t
{
	struct pktlogger_net_hdr_t hdr;
};

struct pktlogger_net_config_t
{
	struct pktlogger_net_hdr_t hdr;
	struct pktlogger_config_t config;
};

struct pktlogger_config_one_t
{
	uint32_t radio_index;
	struct pktlogger_pktlog_config_t config;
};

struct pktlogger_net_config_one_t
{
	struct pktlogger_net_hdr_t hdr;
	struct pktlogger_config_one_t config;
};

struct pktlogger_net_ptype_config_t
{
	struct pktlogger_net_hdr_t hdr;
	struct pktlogger_ptype_config_t config;
};

struct pktlogger_history_stream_request_t
{
	uint32_t radio_index;
	uint16_t type;
	uint16_t requestedcount;
#define PKL_STREAM_REQ_FLAG_RESET_STREAM 0x1
	uint32_t flags;
};

struct pktlogger_net_history_stream_request_t
{
	struct pktlogger_net_hdr_t hdr;
	struct pktlogger_history_stream_request_t request;
};

struct pktlogger_history_stream_t
{
	uint32_t radio_index;
	uint16_t type;
	uint16_t totalcount;
	uint16_t samplenum;
	uint16_t requestedcount;
	uint8_t  data[0];
};

struct pktlogger_net_history_stream_t
{
	struct pktlogger_net_hdr_t hdr;
	struct pktlogger_history_stream_t stream;
};

#ifdef __cplusplus
}
#endif

#endif
