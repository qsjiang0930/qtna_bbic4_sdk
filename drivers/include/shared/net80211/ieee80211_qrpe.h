
#ifndef __IEEE80211_QRPE_H__
#define __IEEE80211_QRPE_H__

#define IEEE80211_QRPE_H_VERSION	0x0001

#define IEEE80211_QRPE_MAX_LEN	1024

#ifndef IEEE80211_ADDR_LEN
#define IEEE80211_ADDR_LEN	6
#endif

#ifndef IEEE80211_NWID_LEN
#define IEEE80211_NWID_LEN	32
#endif

#ifndef IEEE80211_AID_DEF
#define IEEE80211_AID_DEF	128
#endif

#ifndef IEEE80211_MAX_NEIGH_BSS
#define IEEE80211_MAX_NEIGH_BSS		32
#endif

#ifndef IEEE80211_CHAN_MAX
#define IEEE80211_CHAN_MAX	255
#endif
/**
 * @brief Driver Event for QRPE
 */
enum ieee80211_qrpe_event {
	IEEE80211_QRPE_EVENT_PROBE_REQ = 0,
	IEEE80211_QRPE_EVENT_AUTH,
	IEEE80211_QRPE_EVENT_ASSOC_REQ_OR_RESP,
	IEEE80211_QRPE_EVENT_CONNECT_COMPL,
	IEEE80211_QRPE_EVENT_DEAUTH,
	IEEE80211_QRPE_EVENT_DISASSOC = 5,
	IEEE80211_QRPE_EVENT_BTM_STATUS,
	IEEE80211_QRPE_EVENT_STA_STATS,
	IEEE80211_QRPE_EVENT_INTF_UPDATE_NOTIFY,
	IEEE80211_QRPE_EVENT_RECV_MGMT_FRAME,
	IEEE80211_QRPE_EVENT_SPDIA_STATS = 10,
	IEEE80211_QRPE_EVENT_INTF_POWERSAVE_STATE,
	IEEE80211_QRPE_EVENT_SCAN_RESULT,
	IEEE80211_QRPE_EVENT_UPDATE_CHAN_STATE,
	IEEE80211_QRPE_EVENT_PHY_INFO_UPDATE,
	IEEE80211_QRPE_EVENT_UPDATE_SCAN_CAP = 15,
	IEEE80211_QRPE_EVENT_UPDATE_CAC_CAP,
	IEEE80211_QRPE_EVENT_XCAC_STATUS_UPDATE,
};
/**
 *For STA receiving ASSOC RESP frame to indenty association completed,
 * use IEEE80211_QRPE_EVENT_ASSOC_REQ_OR_RESP to replace IEEE80211_EVENT_ASSOC_REQ,
 * for compatiable with the privious versions.
 */
#define IEEE80211_QRPE_EVENT_ASSOC_REQ IEEE80211_QRPE_EVENT_ASSOC_REQ_OR_RESP

/**
 * @brief Band Type for QRPE
 */
enum ieee80211_qrpe_band {
	IEEE80211_QRPE_BAND_2G = 0,
	IEEE80211_QRPE_BAND_5G = 1,
	IEEE80211_QRPE_BAND_MAX
};

/**
 * @brief Phy Type
 */
enum ieee80211_qrpe_phytype {
	IEEE80211_QRPE_PHYTYPE_FHSS	= 1,
	IEEE80211_QRPE_PHYTYPE_DSSS	= 2,
	IEEE80211_QRPE_PHYTYPE_IRBB	= 3,
	IEEE80211_QRPE_PHYTYPE_OFDM	= 4,
	IEEE80211_QRPE_PHYTYPE_HRDSSS	= 5,
	IEEE80211_QRPE_PHYTYPE_ERP	= 6,
	IEEE80211_QRPE_PHYTYPE_HT	= 7,
	IEEE80211_QRPE_PHYTYPE_DMG	= 8,
	IEEE80211_QRPE_PHYTYPE_VHT	= 9,
};

/**
 * @brief Sta Filter Action
 */
enum ieee80211_qrpe_filter_action {
	IEEE80211_QRPE_FILTER_ACTION_NONE	= 0,
	IEEE80211_QRPE_FILTER_ACTION_DENY	= 1,
	IEEE80211_QRPE_FILTER_ACTION_ALLOW	= 2,
};

/*
** Data structure for QRPE IOCTL
*/

/**
 * @brief Data structure for SIOCDEV_SUBIO_SET_BSA_STATUS QRPE IOCTL
 */
enum ieee80211_qrpe_status {
	IEEE80211_QRPE_STATUS_INACTIVE	= 0,
	IEEE80211_QRPE_STATUS_ACTIVE	= 1,
};

/**
 * @brief Data structure for SIOCDEV_SUBIO_GET_CHAN_PHY_INFO QRPE IOCTL
 */
enum ieee80211_qrpe_phy_stats_scan_type {
	IEEE80211_QRPE_SCAN_TYPE_ACTIVE = 0,
	IEEE80211_QRPE_SCAN_TYPE_PASSIVE = 1,
};

#define IEEE80211_QRPE_MAX_CONFIG_IE_NUM	32
#define IEEE80211_QRPE_MAX_CONFIG_FRM_NUM	16
#define IEEE80211_QRPE_MAX_CONFIG_ACT_NUM	16

/**
 * @brief Data structure for SIOCDEV_SUBIO_GET_BSA_INTF_INFO QRPE IOCTL
 */
struct ieee80211_qrpe_intf_info {
	uint8_t bssid[IEEE80211_ADDR_LEN];
	uint16_t mdid;
	uint8_t channel;
	uint8_t band;			/*!< See enum ieee80211_qrpe_band */
	uint8_t opclass;
	uint8_t ssid[IEEE80211_NWID_LEN];
	uint8_t ssid_len;
	uint8_t phytype;		/*!< See enum ieee80211_qrpe_phytype */
	uint16_t capinfo;		/*!< Capabilities Information Field from probe resp */
	struct ieee80211_ie_htcap htcap;
	struct ieee80211_ie_htinfo htop;
	struct ieee80211_ie_vhtcap vhtcap;
	struct ieee80211_ie_vhtop vhtop;
	uint16_t bintval;
	uint8_t support_btm:1;
	uint8_t support_ht:1;
	uint8_t support_vht:1;
	uint8_t support_monitor:1;
	uint8_t pmfc:1;
	uint8_t pmfr:1;
	uint8_t support_erw:1;
	uint8_t support_spdia:1;
#define IEEE80211_QRPE_SPDIA_REORDER	(1<<0)
#define IEEE80211_QRPE_SPDIA_MODE_DATA	(1<<1)
#define IEEE80211_QRPE_SPDIA_MODE_NDP	(1<<2)
	uint8_t spdia_feature_support;
	uint8_t spdia_support_sta_num;	
#define IEEE80211_QRPE_CAP_COUNTRY_ENV	0x00000001 /* driver can change country code IE 3rd byte */
#define IEEE80211_QRPE_CAP_BTM_REQ	0x00000002 /* driver can send BTM REQ when brought down */
#define IEEE80211_QRPE_CAP_TX_OC_MGMT	0x00000004 /* off-chan Tx frames - not supported. */
	uint32_t driver_capab_mask;
	uint32_t ie_add_support_len;
	uint8_t ie_add_support[IEEE80211_QRPE_MAX_CONFIG_IE_NUM];
	uint8_t ext_cap_support[IEEE80211_EXTCAP_IE_LEN];
	uint32_t tx_frame_support_len;
	uint8_t tx_frame_support[IEEE80211_QRPE_MAX_CONFIG_FRM_NUM];
	uint32_t rx_frame_support_len;
	uint8_t rx_frame_support[IEEE80211_QRPE_MAX_CONFIG_FRM_NUM];
	uint32_t tx_action_frame_support_len;
	uint8_t tx_action_frame_support[IEEE80211_QRPE_MAX_CONFIG_ACT_NUM];
	uint32_t rx_action_frame_support_len;
	uint8_t rx_action_frame_support[IEEE80211_QRPE_MAX_CONFIG_ACT_NUM];
	uint8_t vap_mode;
};

/**
 * @brief Data structure for SIOCDEV_SUBIO_GET_BSA_FAT_INFO QRPE IOCTL
 */
struct ieee80211_qrpe_intf_fat {
	uint8_t channel;
	uint8_t band;			/*!< See enum ieee80211_qrpe_band */
	uint16_t avg_fat;
};

/**
 * @brief Data structure for SIOCDEV_SUBIO_UPDATE_MACFILTER_LIST QRPE IOCTL
 */
struct ieee80211_qrpe_mac_filter {
	uint8_t mac[IEEE80211_ADDR_LEN];
	uint8_t action;			/*!< See enum ieee80211_qrpe_filter_action */
};

/**
 * @brief Data structure for SIOCDEV_SUBIO_BSA_START_FAT_MON QRPE IOCTL
 */
struct ieee80211_qrpe_fat_mon {
	uint32_t period;
};

/**
 * @brief Scan Type for QRPE
 */
enum ieee80211_qrpe_scan_type {
	IEEE80211_BGSCAN_CHECK_TRAFFIC = 1,
	IEEE80211_QRPE_SCAN_TYPE_MAX,
};

/**
 * @brief Data structure for SIOCDEV_SUBIO_QRPE_TRIGGER_SCAN QRPE IOCTL
 */
struct ieee80211_qrpe_scan_param {
	enum ieee80211_qrpe_scan_type  scan_type;
	uint8_t  scan_bw;
	/* scan_flags it is reserved for use */
	uint32_t scan_flags;
	uint32_t freqs_num;
	uint32_t freqs[IEEE80211_MAX_DUAL_CHANNELS];
};

/**
 * @brief Data structure for params in SIOCDEV_SUBIO_GET_BSA_STA_STATS QRPE IOCTL, and event IEEE80211_QRPE_EVENT_STA_STATS
 */
struct ieee80211_qrpe_sta_stats_entry {
	uint8_t mac[IEEE80211_ADDR_LEN];
	uint32_t age_last_rx_pkt;
	uint32_t age_last_tx_pkt;
	uint32_t rx_phy_rate;
	uint32_t tx_phy_rate;
	int32_t  rssi;
	uint32_t pkts_per_sec;
	uint32_t avg_airtime;
	uint8_t tx_bw;
	uint8_t rx_bw;
};

/**
 * @brief Data structure for SIOCDEV_SUBIO_GET_BSA_STA_STATS QRPE IOCTL
 */
struct ieee80211_qrpe_sta_stats {
	uint16_t num;
	struct ieee80211_qrpe_sta_stats_entry entries[IEEE80211_AID_DEF];
};

/**
 * @brief Data structure for SIOCDEV_SUBIO_GET_BSA_ASSOC_STA_STATS QRPE IOCTL
 */
/* None data */

/**
 * @brief Data structure for SIOCDEV_SUBIO_SEND_BTM_REQ_FRM QRPE IOCTL
 */
struct ieee80211_qrpe_btm_req {
	uint8_t mac[IEEE80211_ADDR_LEN];
	uint16_t disassoc_timer;
	uint8_t req_mode;
	uint8_t val_intvl;
	uint8_t bssid[IEEE80211_ADDR_LEN];
	uint32_t bssid_info;
	uint8_t opclass;
	uint8_t channel;
	uint8_t phytype;
	uint8_t subel_len;
	uint8_t subels[0];
};

/* for gennetlink */
#define QRPE_FAMILY_NAME	"qrpe_family"
#define QRPE_DRIVER_EVENT	"qrpe_drv_event"
#define QRPE_APP_COMMAND	"qrpe_app_cmd"
#define QRPE_APP_EVENT		"qrpe_app_event"
#define QRPE_DRIVER_PROBE_EVENT	"qrpe_drv_probe"

enum {
	QRPE_GENL_DRV_EVENT		= 0x11,
	QRPE_GENL_APP_CMD		= 0x12,
	QRPE_GENL_DRV_APP_CMD		= 0x13,
	QRPE_GENL_PEER_EVENT		= 0x14,
	QRPE_GENL_DRV_PEER_EVENT	= 0x15,
};

enum qrpe_nl80211_attrs {
	QRPE_ATTR_UNSPEC,
	QRPE_ATTR_MSG_TYPE,
	QRPE_ATTR_EVENT_DATA,
	QRPE_ATTR_TX_APP_COMMAND,
	QRPE_ATTR_RX_APP_COMMAND,
	QRPE_ATTR_TX_APP_EVENT,
	QRPE_ATTR_RX_APP_EVENT,

	__QRPE_ATTR_AFTER_LAST,
	NUM_QRPE_ATTR = __QRPE_ATTR_AFTER_LAST,
};

#define IEEE80211_QRPE_EVENT_GROUP_NAME	"BSA-PEER-EVENT"

/**
 * @brief Driver event head structure
 */
struct ieee80211_qrpe_event_data {
#define IEEE80211_QRPE_EVENT_GROUP_NAME_MAXLEN	18
	char name[IEEE80211_QRPE_EVENT_GROUP_NAME_MAXLEN];
	uint8_t bssid[IEEE80211_ADDR_LEN];
	uint16_t event_id;
	uint16_t len;	/* the length of event */
	/* ensure the event is aligned with uint32_t */
	uint8_t event[0];
};

/**
 * For cookie in IEEE80211_QRPE_EVENT_PROBE_REQ
 *		 IEEE80211_QRPE_EVENT_PROBE_AUTH
 *		 IEEE80211_QRPE_EVENT_PROBE_ASSOC
 */
struct ieee80211_qrpe_frame_cookie {
#define IEEE80211_QRPE_COOKIE_WITHHELD		(1 << 0)
#define IEEE80211_QRPE_COOKIE_PROBE_WILD_SSID	(1 << 1)
#define IEEE80211_QRPE_COOKIE_NO_PAYLOAD	(1 << 7)
	/* Filter flags for Enhanced Response Witholding */
	uint8_t flags;
	uint8_t frm[0];
};

/**
 * @brief Data structure for IEEE80211_QRPE_EVENT_PROBE_REQ
 */
struct ieee80211_qrpe_event_probe_req {
	uint8_t	mac[IEEE80211_ADDR_LEN];
	uint8_t band;
	uint8_t channel;
	uint8_t nss;
	uint8_t band_width;
	uint8_t support_11v:1;
	uint8_t support_vht:1;
	uint8_t support_ht:1;
	uint8_t mumimo_capab:2;
	uint8_t reserve1;
	int32_t	rssi;
	uint16_t max_phy_rate;
	uint16_t cookie_len;
	uint8_t cookie[0];
};

/**
 * @brief Data structure for IEEE80211_QRPE_EVENT_AUTH
 */
struct ieee80211_qrpe_event_auth {
	uint8_t	mac[IEEE80211_ADDR_LEN];
	uint8_t band;
	uint8_t channel;
	int32_t	rssi;
	uint16_t reserve1;
	uint16_t cookie_len;
	uint8_t cookie[0];
};

/**
 * @brief Data structure for IEEE80211_QRPE_EVENT_ASSOC_REQ
 */
typedef struct ieee80211_qrpe_event_probe_req ieee80211_qrpe_event_assoc_req;

/**
 * @brief Data structure for IEEE80211_QRPE_EVENT_CONNECT_COMPL
 */
struct ieee80211_qrpe_event_connect_compl {
	uint8_t	mac[IEEE80211_ADDR_LEN];
	uint8_t	band;
	uint8_t channel;
	uint8_t nss;
	uint8_t band_width;
#define	IEEE80211_QRPE_NODETYPE_UNKNOWN		0
#define	IEEE80211_QRPE_NODETYPE_VAP		1
#define	IEEE80211_QRPE_NODETYPE_STA		2
#define	IEEE80211_QRPE_NODETYPE_WDS		3
#define	IEEE80211_QRPE_NODETYPE_TDLS		4
#define	IEEE80211_QRPE_NODETYPE_REPEATER	5
#define	IEEE80211_QRPE_NODETYPE_NOTWIFI		6
	uint8_t node_type;
	uint8_t support_11v:1;
	uint8_t support_vht:1;
	uint8_t support_ht:1;
	uint8_t mumimo_capab:2;
	int32_t	rssi;
	uint16_t max_phy_rate;
	uint16_t cookie_len;
	uint8_t cookie[0];
};

/**
 * @brief Data structure for IEEE80211_QRPE_EVENT_DEAUTH/IEEE80211_QRPE_EVENT_DISASSOC
 */
struct ieee80211_qrpe_event_disconn {
	uint8_t mac[IEEE80211_ADDR_LEN];
	uint16_t reason;
#define IEEE80211_QRPE_SELF_GENERATED	0
#define IEEE80211_QRPE_PEER_GENERATED	1
	uint8_t direction;
};

/**
 * @brief Data structure for IEEE80211_QRPE_EVENT_BTM_STATUS
 */
struct ieee80211_qrpe_event_btm_status {
	uint8_t mac[IEEE80211_ADDR_LEN];
	uint8_t status;
};

/**
 * @brief Data structure for IEEE80211_QRPE_EVENT_INTF_UPDATE_NOTIFY
 */
/* None data */

struct ieee80211_qrpe_event_recv_frame {
	int32_t rssi;
	uint32_t data_len; /* skb->len */
	uint8_t chan;
	uint8_t driver_process;
	uint8_t pad[2];
	uint8_t data[0]; /* skb->data including 802.11 mac hdr */
} __packed;

struct ieee80211_extcap_ie_buf {
	uint8_t extcap_len;	/* length of extcap_info */
	uint8_t extcap_info[0]; /* mask and ie */
}__packed;

/**
 * @brief Data structure for SIOCDEV_SUBIO_ERW_ENTRY IOCTL command
 */
struct ieee80211_qrpe_req_erw {
#define IEEE80211_ERW_REQ_SET		1
#define IEEE80211_ERW_REQ_GET		2
#define IEEE80211_ERW_REQ_CLEAR		3
#define IEEE80211_ERW_NR_REQ_SET	4
#define IEEE80211_ERW_NR_REQ_GET	5
#define IEEE80211_ERW_NR_REQ_CLEAR	6
#define IEEE80211_ERW_CONTENT_REQ_SET		7
#define IEEE80211_ERW_CONTENT_REQ_GET		8
#define IEEE80211_ERW_CONTENT_REQ_REMOVE	9
#define IEEE80211_ERW_CONTENT_REQ_CLEAR		10

	int32_t req;
	uint32_t data_len; /* the data len */
	uint8_t data[0];   /* point to the struct erw_entry_list */
};

struct ieee80211_req_erw_entry {
#define IEEE80211_ERW_ENTRY_OP_ADD	1
#define IEEE80211_ERW_ENTRY_OP_DEL	2
	uint8_t op;

	/* station MAC address, generic MAC address: ff:ff:ff:ff:ff:ff */
	//char mac_addr[IEEE80211_ADDR_LEN];
	uint8_t mac_addr[IEEE80211_ADDR_LEN];

#define IEEE80211_ERW_RSSI_MODE_NONE	0        /* don't care RSSI */
#define IEEE80211_ERW_RSSI_MODE_MAX	(1 << 0) /* above RSSI threshold */
#define IEEE80211_ERW_RSSI_MODE_MIN	(1 << 1) /* below RSSI threshold */
#define IEEE80211_ERW_CONTENT_BASE	(1 << 2)
	uint8_t rssi_mode;

#define IEEE80211_ERW_PROBE_RESP	(1 << 0)
#define IEEE80211_ERW_AUTH_RESP		(1 << 1)
#define IEEE80211_ERW_ASSOC_RESP	(1 << 2)
#define IEEE80211_ERW_REASSOC_RESP	(1 << 3)
#define IEEE80211_ERW_SELECT_ALL	(IEEE80211_ERW_PROBE_RESP |\
					IEEE80211_ERW_AUTH_RESP |\
					IEEE80211_ERW_ASSOC_RESP |\
					IEEE80211_ERW_REASSOC_RESP)
	uint16_t frame_select;
	uint16_t reject_mode; /* reject mode: 0 = withhold, > 0 = status code of reject */

	int32_t rssi_thrd_max;
	int32_t rssi_thrd_min;

	uint32_t idx_mask; /* the ID mask of neigh report IE table */
};

#define IEEE80211_BSA_REQ_IE_LEN	sizeof(struct ieee80211_req_erw_content_ie)
#define IEEE80211_BSA_REQ_SUBIE_LEN	sizeof(struct ieee80211_req_erw_content_subie)
#define IEEE80211_BSA_MAX_CONTENT_LEN	16

struct ieee80211_req_erw_content_subie {
	uint8_t subie_id;
	uint8_t reject_mode;
#define IEEE80211_ERW_SUBIE_MISSING		0
#define IEEE80211_ERW_SUBIE_PRESENT		1
	uint8_t subie_present;
#define IEEE80211_ERW_SUBIE_EQUAL		0
#define IEEE80211_ERW_SUBIE_NONEQUAL		1
#define IEEE80211_ERW_SUBIE_SMALLER_THAN	2
#define IEEE80211_ERW_SUBIE_BIGGER_THAN		3
	uint8_t match_type;
	uint16_t match_offset;
	uint16_t match_len;
	uint32_t idx_mask; /* the ID mask of neigh report IE table */
	uint8_t match[IEEE80211_BSA_MAX_CONTENT_LEN];
	uint8_t match_mask[IEEE80211_BSA_MAX_CONTENT_LEN];
};

struct ieee80211_req_erw_content_ie {
	uint8_t ie_id;
	uint8_t reject_mode;
#define IEEE80211_ERW_IE_MISSING	0
#define IEEE80211_ERW_IE_PRESENT	1
	uint8_t ie_present;
	uint8_t num_subie;
	uint32_t idx_mask; /* the ID mask of neigh report IE table */
	uint16_t match_offset;
	uint16_t match_len;
	uint16_t subel_offset;
	uint8_t match[IEEE80211_BSA_MAX_CONTENT_LEN];
	uint8_t match_mask[IEEE80211_BSA_MAX_CONTENT_LEN];
	struct ieee80211_req_erw_content_subie req_subie[0];
};

struct ieee80211_req_erw_content {
	uint8_t mac_addr[IEEE80211_ADDR_LEN];
	struct ieee80211_req_erw_content_ie req_ie;
};

struct ieee80211_req_erw_content_result {
	uint8_t mac_addr[IEEE80211_ADDR_LEN];
	uint8_t ie[0];	/* Data format: <IE + N * subIE> <IE + N * subIE> ... <IE + N * subIE> */
};
struct ieee80211_req_erw_entry_list {
	uint32_t num;
	struct ieee80211_req_erw_entry erw_entry[0];
};

struct ieee80211_req_erw_nr_entry {
#define IEEE80211_ERW_NR_ENTRY_OP_ADD	1
#define IEEE80211_ERW_NR_ENTRY_OP_DEL	2
	uint8_t op;
	uint8_t id;
	uint16_t nr_ie_len;
	uint8_t nr_ie[0]; /* The end address should be 4 bytes aligned with pad 1 ~ 3 */
};

struct ieee80211_req_erw_nr_entry_list {
	uint32_t num;
	struct ieee80211_req_erw_nr_entry erw_nr_entry[0];
};

/*
 * @brief Data structure for IEEE80211_QRPE_EVENT_SPDIA_STATS
 */
struct ieee80211_qrpe_event_spdia {
	uint16_t bucket_num;
};
#define IEEE80211_QRPE_CHAN_STATUS_INACTIVE			(1<<0)
#define IEEE80211_QRPE_CHAN_STATUS_DFS				(1<<1)
#define IEEE80211_QRPE_CHAN_STATUS_WEATHER			(1<<2)
#define IEEE80211_QRPE_CHAN_STATUS_NOT_AVAILABLE_CAC_REQUIRED	(1<<3)
#define IEEE80211_QRPE_CHAN_STATUS_NOT_AVAILABLE_RADAR_DETECTED	(1<<4)
#define IEEE80211_QRPE_CHAN_STATUS_AVAILABLE			(1<<5)
#define IEEE80211_QRPE_CHAN_STATUS_NOT_AVAILABLE			\
		(IEEE80211_QRPE_CHAN_STATUS_INACTIVE |			\
		IEEE80211_QRPE_CHAN_STATUS_NOT_AVAILABLE_CAC_REQUIRED |	\
		IEEE80211_QRPE_CHAN_STATUS_NOT_AVAILABLE_RADAR_DETECTED)
struct ieee80211_qrpe_opclass_chan_info {
	uint8_t chan_no;

	uint8_t chan_status;

#define IEEE80211_CAP_SCAN_STAT_IMPACT_NONE		BIT(IEEE80211_CAP_SCAN_IMPACT_NO_IMPACT)
#define IEEE80211_CAP_SCAN_STAT_IMPACT_RD_MIMO		BIT(IEEE80211_CAP_SCAN_IMPACT_REDUCED_MIMO)
#define IEEE80211_CAP_SCAN_STAT_IMPACT_TM_SLICED	BIT(IEEE80211_CAP_SCAN_IMPACT_TIME_SLICED)
#define IEEE80211_CAP_SCAN_STAT_IMPACT_UNAVAILABLE	BIT(IEEE80211_CAP_SCAN_IMPACT_UNAVAIL)
	uint8_t scan_support;

#define IEEE80211_CAP_CAC_CONT			BIT(IEEE80211_CAP_CAC_TYPE_CONTINUOUS)
#define IEEE80211_CAP_CAC_CONT_W_OTHER_RADIO	BIT(IEEE80211_CAP_CAC_TYPE_CONT_WITH_OTHER_RADIO)
#define IEEE80211_CAP_CAC_RD_MIMO		BIT(IEEE80211_CAP_CAC_TYPE_MIMO_DIM_REDUCED)
#define IEEE80211_CAP_CAC_TIME_SLICED		BIT(IEEE80211_CAP_CAC_TYPE_TIME_SLICED)
	uint8_t cac_support;

};

struct ieee80211_qrpe_opclass_info {
	uint8_t index;
	uint8_t global_index;
	uint8_t bandwidth;
	uint8_t reg_max_tx_power;
	struct ieee80211_qrpe_opclass_chan_info chaninfo_set[IEEE80211_MAX_DUAL_CHANNELS];
};

/*
 * @brief Data structure for IEEE80211_QRPE_EVENT_SCAN_RESULT
 */
struct ieee80211_qrpe_event_scan_result {
	uint8_t found;
	uint8_t se_ch;
	uint8_t se_bssid[IEEE80211_ADDR_LEN];
};

/*
 * @brief Data structure for IEEE80211_QRPE_EVENT_UPDATE_CHAN_STATE
 */
struct ieee80211_qrpe_update_chan_state {
	struct ieee80211_qrpe_opclass_chan_info chaninfo_set[IEEE80211_CHAN_MAX];
};

/**
 * @brief Data structure for SIOCDEV_SUBIO_GET_OPCLASS_INFO
 */
#define REGION_NAME_LEN			2
struct ieee80211_qrpe_region_opclass {
	char region_name[REGION_NAME_LEN];
	uint8_t radio_id;
	uint8_t opclass_num;
	struct ieee80211_qrpe_opclass_info opclass_set[IEEE80211_OPER_CLASS_BYTES
							+ IEEE80211_OPER_CLASS_BYTES_24G];
};

/**
 * @brief Data structure for SIOCDEV_SUBIO_GET_SCAN_CAP
 */
enum ieee80211_cap_scan_runtime_impact {
	IEEE80211_CAP_SCAN_IMPACT_NO_IMPACT = 0,
	IEEE80211_CAP_SCAN_IMPACT_REDUCED_MIMO,
	IEEE80211_CAP_SCAN_IMPACT_TIME_SLICED,
	IEEE80211_CAP_SCAN_IMPACT_UNAVAIL,
	IEEE80211_CAP_SCAN_IMPACT_MAX
};

/**
 * @brief Data structure for SIOCDEV_SUBIO_GET_CAC_CAP
 */
enum ieee80211_cap_cac_type_t {
	IEEE80211_CAP_CAC_TYPE_CONTINUOUS = 0,
	IEEE80211_CAP_CAC_TYPE_CONT_WITH_OTHER_RADIO,
	IEEE80211_CAP_CAC_TYPE_MIMO_DIM_REDUCED,
	IEEE80211_CAP_CAC_TYPE_TIME_SLICED,
	IEEE80211_CAP_CAC_TYPE_MAX,
};

/* minimum interval, in msec, between successive scan requests */
#define IEEE80211_CAP_MIN_SCAN_INTV 5000
#define IEEE80211_CAP_MAX_SCAN_INTV 0xFFFFFFFF

/* Pre-initialized capability table within driver */
struct ieee80211_cap_scan_ctx {
	int boot;
	enum ieee80211_cap_scan_runtime_impact impact;
	uint32_t min_scan_intv;
};

enum ieee80211_qrpe_cac_param {
	IEEE80211_QRPE_CAC_PARAM_CAC_DUR,
	IEEE80211_QRPE_CAC_PARAM_CAC_DUR_WEA,
	IEEE80211_QRPE_CAC_PARAM_NOP_DUR,
};

struct ieee80211_cap_cac_ctx {
	enum ieee80211_cap_cac_type_t cac_type;
	uint32_t cac_dur;
	uint32_t cac_dur_wea;
	uint32_t nop_dur;
	uint32_t nop_dur_wea;
};

struct ieee80211_cap_ctx {
	struct ieee80211_cap_scan_ctx scan_ctx[IEEE80211_CAP_SCAN_IMPACT_MAX];
	struct ieee80211_cap_cac_ctx cac_ctx[IEEE80211_CAP_CAC_TYPE_MAX];
};


#define PM_MAX_NAME_LEN			64
#define PM_PS_ON			1
#define PM_PS_OFF			0
struct ieee80211_qrpe_event_ps_state {
	int pm_qos_class;		/* Identifies which qos target changes it belongs. */
	char pm_name[PM_MAX_NAME_LEN];	/* Name of qos pm object */
	uint8_t pm_state;		/* State of PM, PM_PS_ENABLED or PM_PS_DISABLED */
};

struct ieee80211_qrpe_chan_phy_stats {
	uint8_t chan_no;
#define IEEE80211_QRPE_CHAN_PHY_STATS_READY			(1<<0)
#define IEEE80211_QRPE_CHAN_PHY_STATS_BSSCHAN			(1<<1)
#define IEEE80211_QRPE_CHAN_PHY_STATS_SUBBAND			(1<<2)
	uint8_t flag;
	uint8_t bandwidth;
	enum ieee80211_qrpe_phy_stats_scan_type scan_type;
	uint32_t busy_20;
	uint32_t busy_40;
	uint32_t busy_80;
	uint32_t busy_160;
	uint32_t tx_20;
	uint32_t rx_20;
	uint32_t rx_others_20;
	uint32_t tx_40;
	uint32_t rx_40;
	uint32_t rx_others_40;
	uint32_t tx_80;
	uint32_t rx_80;
	uint32_t rx_others_80;
	uint32_t tx_160;
	uint32_t rx_160;
	uint32_t rx_others_160;
	uint32_t aggr_scan_duration;
	uint32_t scan_age;
	int32_t noise_20;
};

struct ieee80211_qrpe_chan_phy_info {
#define IEEE80211_QRPE_CHAN_PHY_STATS_GET_ALL			(1<<0)
	uint8_t flag;
#define IEEE80211_QRPE_CHAN_PHY_STATS_MORE			(1<<0)
	uint8_t status;
	uint8_t num;			/*length of phy_stats*/
	struct ieee80211_qrpe_chan_phy_stats phy_stats[0];
};

struct ieee80211_qrpe_event_phy_info_chanlist {
	uint8_t num;			/* length of avail_chan */
	uint8_t avail_chan[0];		/* available channel number list */
};

/**
 * @brief Data structure for IEEE80211_QRPE_EVENT_XCAC_STATUS_UPDATE
 */
struct ieee80211_qrpe_event_xcac_status {
	uint16_t pri_chan;
	uint16_t bandwidth;

#define IEEE80211_QRPE_XCAC_COMPLETED		1
#define IEEE80211_QRPE_XCAC_CANCELLED		2
	uint8_t perform_status;
	uint8_t chan_status;
	uint16_t reserved;
};

/**
 * @brief Data structure for SIOCDEV_SUBIO_QRPE_REQ_XCAC
 */
enum ieee80211_qrpe_xcac_forbidden_reason {
	QRPE_XCAC_REASON_REGION = 1,
	QRPE_XCAC_REASON_NON_DFS_CHAN,
	QRPE_XCAC_REASON_RADAR_DETECTED,
};

enum ieee80211_qrpe_xcac_other_reason {
	QRPE_XCAC_REASON_IS_RUNNING = 1,
	QRPE_XCAC_REASON_NO_DFS_CHAN,
	QRPE_XCAC_REASON_NO_NON_DFS_CHAN,
	QRPE_XCAC_REASON_BSS_DFS_CHAN,
	QRPE_XCAC_REASON_CHAN_AVAILABLE,
	QRPE_XCAC_REASON_CHAN_DISABLED,
	QRPE_XCAC_REASON_CHAN_IS_BSS,
	QRPE_XCAC_REASON_WDS,
	QRPE_XCAC_REASON_MBSSID,
	QRPE_XCAC_REASON_AP_MODE,
};

enum ieee80211_qrpe_xcac_cmd {
	QRPE_XCAC_CMD_START = 1,
	QRPE_XCAC_CMD_MIN = QRPE_XCAC_CMD_START,
	QRPE_XCAC_CMD_STOP,
	QRPE_XCAC_CMD_GET,
	QRPE_XCAC_CMD_MAX = QRPE_XCAC_CMD_GET,
};

enum ieee80211_qrpe_xcac_action {
	QRPE_XCAC_ACTION_CONT = 1, /* Continue to run CAC on the specified channel */
	QRPE_XCAC_ACTION_RETURN, /* Return to most latest operational channel */
};

struct ieee80211_qrpe_xcac_req {
	/* input field */
	uint8_t command; /* enum ieee80211_qrpe_xcac_cmd */
	uint8_t method;
	uint16_t pri_chan;
	uint16_t bw;
	uint8_t action; /* enum ieee80211_qrpe_xcac_action */
	uint8_t reserved;

	/* output field */
#define	IEEE80211_QRPE_CAC_TYPE_NON_CONFORMANT		0x04
#define IEEE80211_QRPE_CAC_TYPE_OTHER_ERROR		0x05
#define IEEE80211_QRPE_CAC_ERROR_NON_CONFORMANT(reason_id)	\
		(IEEE80211_QRPE_CAC_TYPE_NON_CONFORMANT << 16 | reason_id)
#define IEEE80211_QRPE_CAC_ERROR_OTHER(reason_id)		\
		(IEEE80211_QRPE_CAC_TYPE_OTHER_ERROR << 16 | reason_id)
	union {
		uint32_t failure_code;
		struct ieee80211_qrpe_event_xcac_status xcac_status;
	} status;
};


#endif

