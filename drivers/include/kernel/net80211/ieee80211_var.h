/*-
 * Copyright (c) 2001 Atsushi Onoe
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: ieee80211_var.h 2607 2007-07-25 15:20:59Z mrenzmann $
 */
#ifndef _NET80211_IEEE80211_VAR_H_
#define _NET80211_IEEE80211_VAR_H_

/*
 * Definitions for IEEE 802.11 drivers.
 */
#define IEEE80211_DEBUG

#include <compat.h>
#include "qtn/qtn_global.h"
#include "qtn/lhost_muc_comm.h"
#ifdef CONFIG_QVSP
#include "qtn/qvsp_data.h"
#endif

#include "net80211/ieee80211_linux.h"

#include <common/queue.h>
#include <common/ruby_pm.h>
#include <common/qtn_bits.h>

#include "net80211/_ieee80211.h"
#include "net80211/ieee80211.h"
#include "net80211/ieee80211_crypto.h"
#include "net80211/ieee80211_ioctl.h"		/* for ieee80211_stats */
#include "net80211/ieee80211_node.h"
#include "net80211/ieee80211_power.h"
#include "net80211/ieee80211_proto.h"
#include "net80211/ieee80211_scan.h"
#include "net80211/ieee80211_tpc.h"
#include "net80211/ieee80211_tdls.h"
#include "net80211/ieee80211_chan_select.h"
#include "net80211/ieee80211_mfr.h"

#include "net80211/ieee80211_qrpe.h"
#if defined(CONFIG_BRIDGE) || defined(CONFIG_BRIDGE_MODULE)
#include <linux/if_bridge.h>
#include <linux/net/bridge/br_public.h>
#endif

#define IEEE80211_DEV_IS_UP(_dev) \
	((_dev->flags & (IFF_RUNNING|IFF_UP)) == (IFF_RUNNING|IFF_UP))

#define	IEEE80211_BGSCAN_INTVAL_MIN	15	/* min bg scan intvl (secs) */
#define	IEEE80211_BGSCAN_INTVAL_DEFAULT	(5*60)	/* default bg scan intvl */

#define	IEEE80211_BGSCAN_IDLE_MIN	100	/* min idle time (ms) */
#define	IEEE80211_BGSCAN_IDLE_DEFAULT	250	/* default idle time (ms) */

#define IEEE80211_USE_QTN_BGSCAN(vap)	\
	(((vap->iv_ic)->ic_flags_ext & IEEE80211_FEXT_REPEATER) &&	\
	((vap)->iv_opmode == IEEE80211_M_STA) &&	\
	(ieee80211_get_active_ap_vap(vap->iv_ic)) &&	\
	((vap)->iv_ic->ic_bsschan != IEEE80211_CHAN_ANYC))

#define IEEE80211_COVERAGE_CLASS_MAX	31	/* max coverage class */
#define IEEE80211_REGCLASSIDS_MAX	10	/* max regclass id list */

#define	IEEE80211_PS_SLEEP		0x1	/* STA is in power saving mode */
#define	IEEE80211_PS_MAX_QUEUE		50	/* maximum saved packets */

#define	IEEE80211_XR_BEACON_FACTOR	3	/* factor between xr Beacon interval and normal beacon interval */
#define	IEEE80211_XR_DEFAULT_RATE_INDEX	0
#define	IEEE80211_XR_FRAG_THRESHOLD	540
#define	IEEE80211_BLACKLIST_TIMEOUT	90	/* Default blacklist timeout (secs) */

#define	IEEE80211_FIXED_RATE_NONE	-1

#define IEEE80211_MIN_NON_OCCUPANCY_PERIOD	5
#define IEEE80211_MAX_NON_OCCUPANCY_PERIOD	1800

#define IEEE80211_NUM_BEACONS_TO_MISS	100 /* beacons allowed to miss before rescan */

#define	IEEE80211_MS_TO_TU(x)		(((x) * 1000) / 1024)
#define	IEEE80211_TU_TO_MS(x)		(IEEE80211_TU_TO_USEC(x) / 1000)
#define	IEEE80211_TU_TO_USEC(x)		((x) * 1024)
#define	IEEE80211_TU_TO_JIFFIES(x)	((IEEE80211_TU_TO_MS(x) * HZ) / 1000)
#define	IEEE80211_JIFFIES_TO_TU(x)	IEEE80211_MS_TO_TU((x) * 1000 / HZ)
#define IEEE80211_SEC_TO_USEC(x)	((x) * 1000 * 1000)
#define IEEE80211_MS_TO_USEC(x)		((x) * 1000)
#define IEEE80211_USEC_TO_MS(x)		((x) / 1000)
#define IEEE80211_MS_TO_JIFFIES(x)	((x) * HZ / 1000)


#define IEEE80211_MAX_AMPDU_SUBFRAMES			(64)
#define IEEE80211_TX_BA_REQUEST_RETRY_TIMEOUT		(5 * HZ)
#define IEEE80211_TX_BA_REQUEST_NEW_ATTEMPT_TIMEOUT	(15 * HZ)
#define IEEE80211_TX_BA_REQUEST_RELAX_TIMEOUT		(75/*ms*/ * HZ / 1000)
#define IEEE80211_TX_BA_REQUEST_LONG_RELAX_TIMEOUT	(1 * HZ)
#define IEEE80211_TX_ADDBA_REQUEST_NO_RESPONSE_TIMEOUT	(HZ / 2)
#define IEEE80211_TX_ADDBA_REQUEST_FAIL_BLOCK_THRESH	(3)
#define IEEE80211_TX_BA_REQUEST_BLOCK_PERIOD		(10 * 60 * HZ)

#define	IEEE80211_APPIE_MAX	1024

#define IEEE80211_QTN_NUM_RF_STREAMS	4

#define IEEE80211K_RM_MEASURE_STA_TIMEOUT	(HZ / 10)
#define IEEE80211_MEASUREMENT_REQ_TIMEOUT(offset, du)	(((offset + du) * HZ / 1000) + HZ)

#define IEEE80211_RSSI_FACTOR	10

#define IEEE80211_PWRCONSTRAINT_VAL(ic) \
	(((ic)->ic_bsschan->ic_maxregpower - (ic)->ic_pwr_constraint) > 0 ? \
	    (ic)->ic_pwr_constraint : 0)

#define IEEE80211_DIVIDE_N_CEIL(x, y)	(roundup((x), (y)) / (y))

#define	MIN(_a, _b)	((_a)<(_b)?(_a):(_b))
#define	MAX(_a, _b)	((_a)>(_b)?(_a):(_b))
#define ABS(_x)		(((_x) > 0) ? (_x) : (0 - (_x)))

#define IS_MULTIPLE_BITS_SET(_x)	(((unsigned)(_x)) & (((unsigned)(_x)) - 1))

/* For Little-endian */
#define ntohll(x)  be64_to_cpu(x)
#define htonll(x)  cpu_to_be64(x)

/* Power constraing override */

#define PWR_CONSTRAINT_SAVE_INIT	0xff
#define PWR_CONSTRAINT_PC_DEF		19
#define PWR_CONSTRAINT_RSSI_DEF		42
#define PWR_CONSTRAINT_OFFSET		4

struct ieee80211_pc_over {
	uint8_t					pco_set;
	struct timer_list		pco_timer;
	uint16_t				pco_pwr_constraint;
	uint8_t					pco_rssi_threshold;
	uint8_t					pco_sec_offset;
	uint8_t					pco_pwr_constraint_save;
};

#define	IEEE80211_EXTENDER_DEFAULT_MBS_WGT		10
#define	IEEE80211_EXTENDER_DEFAULT_RBS_WGT		6
#define IEEE80211_EXTENDER_DEFAULT_MBS_BEST_RSSI	20
#define	IEEE80211_EXTENDER_DEFAULT_RBS_BEST_RSSI	20
#define IEEE80211_EXTENDER_DEFAULT_MBS_RSSI_MARGIN	6
#define IEEE80211_EXTENDER_DEFAULT_ROLE_LOSS_THRES	10

#define IEEE80211_EXTWDS_MAX_PSEUDO_RSSI		70
#define IEEE80211_EXTWDS_MIN_PSEUDO_RSSI		0
#define IEEE80211_EXTWDS_MBS_BEST_RATE_RSSI		75
#define IEEE80211_EXTWDS_BEST_RATE_BDRY_RSSI		30

#define IEEE80211_PSEUDO_RSSI_TRANSITON_FACTOR		90

#define IEEE80211_EXTENDER_SCAN_MBS_INTERVAL		60	/* seconds */
#define IEEE80211_EXTENDER_MBS_INVALID_TIMEOUT		5	/* seconds */

#define STA_DFS_STRICT_TX_CHAN_CLOSE_TIME_MAX		1000	/* ms */
#define STA_DFS_STRICT_TX_CHAN_CLOSE_TIME_MIN		1	/* ms */
#define STA_DFS_STRICT_TX_CHAN_CLOSE_TIME_DEFAULT	1000	/* ms */

#ifdef CONFIG_QHOP
#define RBS_DFS_TX_CHAN_CLOSE_TIME_MAX           1000    /* ms */
#define RBS_DFS_TX_CHAN_CLOSE_TIME_MIN           1       /* ms */
#define RBS_DFS_TX_CHAN_CLOSE_TIME_DEFAULT       500    /* ms */
#endif

#define IEEE80211_IS_ENABLE_11R(_rsn_akm) \
	(((_rsn_akm) == (RSN_ASE_8021X_PSK | WPA_KEY_MGMT_FT_PSK)) || \
	((_rsn_akm) == (RSN_ASE_8021X_UNSPEC | WPA_KEY_MGMT_FT_IEEE8021X)) || \
	((_rsn_akm) == (WPA_KEY_MGMT_SAE | WPA_KEY_MGMT_FT_SAE)) || \
	((_rsn_akm) == (WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_FT_PSK | \
			 WPA_KEY_MGMT_SAE | WPA_KEY_MGMT_FT_SAE)))
/*
 * All Non-DFS channels are AVAILABLE by default
 * [AP] Any DFS channel is set to AVAILABLE:
 *	(i) only after CAC_DONE,
 *	(ii) and no radar was found
 * [STA] All DFS channels are NON_AVAILABLE by default.
 *
 */
#define IEEE80211_CHANNEL_STATUS_NON_AVAILABLE			(0x1)
#define IEEE80211_CHANNEL_STATUS_AVAILABLE			(0x2)
/* A DFS channel will stay in the NOT_AVAILABLE_RADAR_DETECTED state during the non-occupancy period */
#define IEEE80211_CHANNEL_STATUS_NOT_AVAILABLE_RADAR_DETECTED	(0x4)
/* All DFS channels are marked as NOT_AVAILABLE_CAC_REQUIRED by default */
#define IEEE80211_CHANNEL_STATUS_NOT_AVAILABLE_CAC_REQUIRED	(0x8)

#define ieee80211_is_chan_available(channel_to_check) \
	(IEEE80211_CHANNEL_STATUS_AVAILABLE == ic->ic_get_chan_availability_status_by_chan_num(ic, (channel_to_check)))
#define ieee80211_is_chan_not_available(channel_to_check) \
	(IEEE80211_CHANNEL_STATUS_NON_AVAILABLE == ic->ic_get_chan_availability_status_by_chan_num(ic, (channel_to_check)))
#define ieee80211_is_chan_radar_detected(channel_to_check) \
	(IEEE80211_CHANNEL_STATUS_NOT_AVAILABLE_RADAR_DETECTED == ic->ic_get_chan_availability_status_by_chan_num(ic, (channel_to_check)))
#define ieee80211_is_chan_cac_required(channel_to_check) \
	(IEEE80211_CHANNEL_STATUS_NOT_AVAILABLE_CAC_REQUIRED == ic->ic_get_chan_availability_status_by_chan_num(ic, (channel_to_check)))


#define IEEE80211_COC_REASON_SUCCESS				(0)
#define IEEE80211_COC_REASON_REGION_IS_US			(-1)
#define IEEE80211_COC_REASON_CSA_NOT_TRIGGERED			(-2)
#define IEEE80211_COC_BEST_NON_DFS_CHANNEL_NOT_FOUND		(-3)
#define IEEE80211_COC_BEST_AVAILABLE_DFS_CHANNEL_NOT_FOUND	(-4)
#define IEEE80211_COC_BEST_CHANNEL_NOT_FOUND			(-5)
#define IEEE80211_COC_REASON_ANY				(-6)

#define MSEC_TO_USEC(_x)			((_x) * (1000))
#define DEFAULT_MACFW_CS_TIME			3000
#define DEFAULT_CHSW_PROC_TIME			3000
#define DEFAULT_CHSW_TIMEOUT			10000

#define IEEE80211_MAX_CHANNELS_IN_BW(bw)	((bw)/BW_HT20)
#ifndef SYSTEM_BUILD
#define ic2dev(ic)      ((struct ieee80211vap *)(TAILQ_FIRST(&(ic)->ic_vaps)) ? \
                        ((struct ieee80211vap *)(TAILQ_FIRST(&(ic)->ic_vaps)))->iv_dev : NULL)
#else
#define ic2dev(ic)      NULL
#endif

#define COC_DBG_QEVT(qevtdev, ...)    do {\
                                                printk(__VA_ARGS__);\
                                                ieee80211_eventf(qevtdev, __VA_ARGS__);\
                                        } while (0)

/**
 * PM LEVEL trigger reasons from WLAN module only.
 */
enum IEEE80211_PM_LEVEL_CHANGE_TRIGGER_REASON {
	IEEE80211_PM_LEVEL_REMAIN_CHANNEL_WORK = 1,
	IEEE80211_PM_LEVEL_CCA_WORK,
	IEEE80211_PM_LEVEL_TPUT_ABOVE_UPPER_THRSH,
	IEEE80211_PM_LEVEL_TPUT_BELOW_LOWER_THRSH,
	IEEE80211_PM_LEVEL_VAP_ATTACH,
	IEEE80211_PM_LEVEL_VAP_DETACH,
	IEEE80211_PM_LEVEL_RCVD_ADDBA_REQ,
	IEEE80211_PM_LEVEL_RCVD_ADDBA_RESP,
	IEEE80211_PM_LEVEL_SWBCN_MISS,
	IEEE80211_PM_LEVEL_JOIN_BSS,
	IEEE80211_PM_LEVEL_LEAVE_BSS,
	IEEE80211_PM_LEVEL_INACTIVITY_IN_WDS,
	IEEE80211_PM_LEVEL_NODE_JOIN,
	IEEE80211_PM_LEVEL_NODE_LEFT,
	IEEE80211_PM_LEVEL_DEVICE_INIT,
	IEEE80211_PM_LEVEL_SWBCN_MISS_2,
	IEEE80211_PM_LEVEL_NEW_STATE_IEEE80211_S_RUN,
	IEEE80211_PM_LEVEL_SCAN_START,
	IEEE80211_PM_LEVEL_SCAN_STOP,
	IEEE80211_PM_LEVEL_SIWFREQ,
	IEEE80211_PM_LEVEL_SIWSCAN,
	IEEE80211_PM_LEVEL_STOP_OCAC_SDFS,
	IEEE80211_PM_LEVEL_BCN_SCHEME_CHANGED_FOR_2VAPS,
	IEEE80211_PM_LEVEL_OCAC_SDFS_TIMER,
	IEEE80211_PM_LEVEL_BCN_SCHEME_CHANGED,
	IEEE80211_PM_LEVEL_CAC_COMPLETED,
	IEEE80211_PM_LEVEL_CSA_DFS_ACTION,
	IEEE80211_PM_LEVEL_ICAC_COMPLETE_ACTION,
	IEEE80211_PM_LEVEL_RESET_CHANNEL_STATE,
	IEEE80211_PM_LEVEL_REASON_MAX,
};

/*
 * 802.11 control state is split into a common portion that maps
 * 1-1 to a physical device and one or more "Virtual AP's" (VAP)
 * that are bound to an ieee80211com instance and share a single
 * underlying device.  Each VAP has a corresponding OS device
 * entity through which traffic flows and that applications use
 * for issuing ioctls, etc.
 */

/*
 * Data common to one or more virtual AP's.  State shared by
 * the underlying device and the net80211 layer is exposed here;
 * e.g. device-specific callbacks.
 */
struct ieee80211vap;

enum ieee80211_shortrange_flags {
	IEEE80211_BKUP_TXPOWER_NORMAL = 0,
	IEEE80211_APPLY_LOWGAIN_TXPOWER = 1,
	IEEE80211_APPLY_TXPOWER_NORMAL = 2,
	IEEE80211_INIT_TXPOWER_TABLE = 3
};

enum ieee8211_scs_cnt {
	IEEE80211_SCS_CNT_TRIGGER = 0,
	IEEE80211_SCS_CNT_QOSNULL_NOTREADY,
	IEEE80211_SCS_CNT_IN_SCAN,
	IEEE80211_SCS_CNT_RADAR,
	IEEE80211_SCS_CNT_TRAFFIC_HEAVY,
	IEEE80211_SCS_CNT_IOCTL,
	IEEE80211_SCS_CNT_COMPLETE,
	IEEE80211_SCS_CNT_MAX,
};

enum ieee80211_phy_mode{
        IEEE80211_11AC_ONLY = 0x1,
        IEEE80211_11N_ONLY = 0x2
};

#define	IEEE80211_MAX_TDLS_NODES	16

struct ieee80211_tdls_scs_stats {
	uint8_t s_addr[IEEE80211_ADDR_LEN];	/* Sender address */
	uint8_t r_addr[IEEE80211_ADDR_LEN];	/* Receiver address */
	uint16_t tx_time;	/* Tx time - us */
	uint16_t is_latest;	/* latest statistics data flag */
} __packed;

struct ieee80211_tdls_scs_entry {
	LIST_ENTRY(ieee80211_tdls_scs_entry) entry;
	struct ieee80211_tdls_scs_stats stats;
};

struct ieee80211_scs {
	uint32_t		scs_smpl_dwell_time;
	uint32_t		scs_sample_intv;
	uint32_t		scs_thrshld_smpl_pktnum;
	uint32_t		scs_thrshld_smpl_airtime;
	uint32_t		scs_thrshld_atten_inc;
	uint32_t		scs_thrshld_dfs_reentry;
	uint32_t		scs_thrshld_dfs_reentry_minrate;
	uint32_t		scs_thrshld_dfs_reentry_intf;
	uint32_t		scs_thrshld_loaded;               /* unit: thousandth of air time */
	uint32_t		scs_thrshld_aging_nor;            /* unit: minute */
	uint32_t		scs_thrshld_aging_dfsreent;       /* unit: minute */
	uint16_t		scs_enable_manual;	/* SCS enabled/disabled manually */
	uint16_t		scs_enable;	/* 1 - channel switching can be triggered; 0 - don't change channel */
	int16_t			scs_debug_enable;
	uint16_t		scs_smpl_enable;
	uint8_t			scs_stats_on;	/* 1 - scs stats on; 0 - scs stats off */
	uint8_t			scs_report_only;
	struct timer_list	scs_compare_timer;
	uint32_t		scs_cca_idle_thrshld;
	uint32_t		scs_cca_intf_abs_thrshld;
	uint32_t		scs_cca_intf_hi_thrshld;
	uint32_t		scs_cca_intf_lo_thrshld;
	uint32_t		scs_cca_intf_ratio;
	uint32_t		scs_cca_intf_dfs_margin;
	uint32_t		scs_pmbl_err_thrshld;
	uint32_t		scs_cca_sample_dur;
#define SCS_CCA_INTF_SMTH_FCTR_NOXP		0
#define SCS_CCA_INTF_SMTH_FCTR_XPED		1
#define SCS_CCA_INTF_SMTH_FCTR_NUM		2
	uint8_t			scs_cca_intf_smth_fctr[SCS_CCA_INTF_SMTH_FCTR_NUM];
#define SCS_RSSI_SMTH_FCTR_UP			0
#define SCS_RSSI_SMTH_FCTR_DOWN			1
#define SCS_RSSI_SMTH_FCTR_NUM			2
	uint8_t			scs_rssi_smth_fctr[SCS_RSSI_SMTH_FCTR_NUM];
	uint8_t			scs_chan_mtrc_mrgn;
	uint8_t			scs_inband_chan_mtrc_mrgn;
	uint8_t			scs_leavedfs_chan_mtrc_mrgn;/* DFS-to-Non-DFS channel switch margin */
	uint8_t			scs_check_band_mrgn;	/* Enable/Disable band switch margin check */
	uint8_t			scs_out_of_band_mrgn; /* Band switch margin */
	int8_t			scs_atten_adjust;
	uint32_t		scs_cnt[IEEE80211_SCS_CNT_MAX];
	uint16_t		scs_atten_sw_enable;
	int16_t			scs_last_smpl_chan;	/* index into the channel array */
	struct brcm_rxglitch_thrshld_pair *scs_brcm_rxglitch_thrshlds;
	uint32_t		scs_brcm_rxglitch_thrshlds_scale;
	uint32_t		scs_pmbl_err_smth_fctr;
	uint32_t		scs_pmbl_err_smth_winsize;
	uint32_t		scs_pmbl_err_range;
	uint32_t		scs_pmbl_err_mapped_intf_range;    /* pmbl err range mapped to percent of cca intf */
	uint32_t		scs_sp_wf;              /* short preamble weight factor */
	uint32_t		scs_lp_wf;              /* long preamble weight factor */
	uint32_t		scs_sp_err_smthed;                 /* 1s based */
	uint32_t		scs_lp_err_smthed;                 /* 1s based */
	uint32_t		scs_cca_intf_smthed;
	uint32_t		scs_cca_intf_smthed_jiffies;
	uint16_t		scs_pmp_rpt_cca_smth_fctr;
	uint16_t		scs_pmp_rx_time_smth_fctr;
	uint16_t		scs_pmp_tx_time_smth_fctr;
	uint16_t		scs_pmp_stats_stable_percent;
	uint16_t		scs_pmp_stats_stable_range;
	uint16_t		scs_pmp_stats_clear_interval;
	uint16_t		scs_as_rx_time_smth_fctr;
	uint16_t		scs_as_tx_time_smth_fctr;
	uint16_t		scs_cca_idle_smthed;
	uint16_t		scs_cca_idle_smth_fctr;
	uint16_t		scs_cca_threshold_type;		/* 0:normal, 1:less sensitive, 2:more sensitive */
	uint16_t		scs_sample_type;
	uint16_t		scs_des_smpl_chan;	/* desired OC sampling channel, index into the channel array */
	uint16_t		scs_smpl_chan_offset;	/* the offset of a sampling channel within a channel set,
							   e.g. for 80MHz channel set, it's one of 0, 1, 2, 3 */
	uint16_t		scs_monitor_mode;
	uint16_t		scs_override_mode;
	uint16_t		scs_obss_check_enable;

	uint16_t		scs_burst_enable; /* flag of enable/disable burst channel switching */
	uint16_t		scs_burst_window; /* sliding window of time of checking burst */
	uint16_t		scs_burst_thresh; /* burst threshold */
	uint16_t		scs_burst_pause_time; /* pause time after burst happens */
	uint16_t		scs_burst_force_switch; /* enable/disable to switch channel */
	uint16_t		scs_burst_is_paused;
	unsigned long		scs_burst_pause_jiffies;
	uint32_t		scs_burst_queue[IEEE80211_SCS_BURST_THRESH_MAX]; /* queue for SCS event whose life time is valid */

	int32_t			scs_best_chan; /* to hold the best channel for upper layers to make further decision */
#if defined(CONFIG_QTN_BSA_SUPPORT)
	uint8_t			scs_qrpe_report_intvl;
#endif

	ATH_LIST_HEAD(, ieee80211_tdls_scs_entry) scs_tdls_list[IEEE80211_NODE_HASHSIZE];
	spinlock_t		scs_tdls_lock;
	atomic_t		scs_pause_cnt;
};

#define IEEE80211_SCS_CNT_INC(_scs, _id)	((_scs)->scs_cnt[_id]++)
#define IEEE80211_IS_SCS_OFF_CHAN_SAMPLING(_ic)	((_ic)->ic_flags_qtn & IEEE80211_QTN_SAMP_CHAN)

#define SCS_BEST_CHAN_INVALID		0

#define IEEE80211_SCS_MEASURE_INIT_TIMER	3
#define IEEE80211_SCS_MEASURE_TIMER_INTVAL	5
#define IEEE80211_MAX_STA_CCA_ENABLED		2
#define IEEE80211_CCA_IDLE_THRSHLD		40
#define IEEE80211_CCA_INTFR_ABSOLUTE_THRSHLD	950
#define IEEE80211_CCA_INTFR_HIGH_THRSHLD	50
#define IEEE80211_CCA_INTFR_LOW_THRSHLD		30
#define IEEE80211_CCA_INTFR_RATIO		20
#define IEEE80211_CCA_INTFR_DFS_MARGIN		0
#define IEEE80211_PMBL_ERR_THRSHLD		300

#define SCS_NODE_TRAFFIC_IDLE        0
#define SCS_NODE_TRAFFIC_LOADED      1
#define SCS_NODE_TRAFFIC_TYPE_NUM    2
#define SCS_NODE_NOTINTFED           0
#define SCS_NODE_INTFED              1
#define SCS_NODE_INTF_TYPE_NUM       2

struct ieee80211_ocac_counts {
	uint32_t		ap_not_running;
	uint32_t		chan_scanning;
	uint32_t		curchan_dfs;
	uint32_t		init_offchan;
	uint32_t		no_offchan;
	uint32_t		pick_offchan;
	uint32_t		invalid_offchan;
	uint32_t		set_bcn_intval;
	uint32_t		restore_bcn_intval;
	uint32_t		pm_update;
	uint32_t		unsupported_mbssid;
	uint32_t		beacon_scheme0;
	uint32_t		wds_exist;
	uint32_t		set_run;
	uint32_t		set_pend;
	uint32_t		skip_set_run;
	uint32_t		skip_set_pend;
	uint32_t		alloc_skb_error;
	uint32_t		set_frame_error;
	uint32_t		hostlink_err;
	uint32_t		hostlink_ok;
	uint32_t		cac_failed;
	uint32_t		cac_success;
	uint32_t		radar_detected;
	uint32_t		csw_rpt_only;
	uint32_t		csw_fail_intf;
	uint32_t		csw_fail_radar;
	uint32_t		csw_fail_csa;
	uint32_t		csw_success;
	uint32_t		clean_stats_reset;
	uint32_t		clean_stats_start;
	uint32_t		clean_stats_stop;
	uint32_t		tasklet_off_chan;
	uint32_t		tasklet_data_chan;
	uint32_t		intr_off_chan;
	uint32_t		intr_data_chan;
	uint32_t		cac_in_neighbourhood;
	uint32_t		no_channel_change_eu;
};

struct ieee80211_ocac_params {
	uint16_t		traffic_ctrl;	/* use qosnull frame to control the traffic */
	uint16_t		secure_dwell_ms;	/* milliseconds, the time on off channel
								within one off-channel action, using qosnull
								with large NAV to protect the traffic */
	uint16_t		dwell_time_ms;	/* milliseconds, the time on off channel
							within 1 beacon interval */
	uint16_t		duration_secs;	/* seconds, the total time for one channel */
	uint16_t		cac_time_secs;	/* seconds, the total time on off channel
							for one channel */
	uint16_t		wea_dwell_time_ms;	/* milliseconds, the time on weather channel
							within 1 beacon interval */
	uint32_t		wea_duration_secs;	/* seconds, the total time for weather channel */
	uint32_t		wea_cac_time_secs;	/* seconds, the total time on off channel
							for weather channel */
	uint16_t		thresh_fat;	/* percent, the threshold of FAT used to decide
							to run off-channel CAC */
	uint16_t		thresh_traffic;	/* percent, the threshold of traffic used to
							decide to run ocac */
	uint16_t		thresh_fat_dec;	/* percent, the threshold of consecutive FAT decrease,
							used to monitor the traffic variation */
	uint16_t		thresh_cca_intf;	/* percent, the threshold of cca interference to
							decide to jump to off channel */
	uint16_t		offset_txhalt;	/* milliseconds, the offset after sending
							beacon to halt tx in MuC */
	uint16_t		offset_offchan;	/* milliseconds, the offset after halt tx to
							switch to off channel in MuC*/
	uint16_t		timer_interval;	/* the ocac_timer interval */
	uint16_t		beacon_interval;	/* TUs, the beacon interval for OCAC */
	uint16_t		auto_first_dfs_channel; /* Auto SDFS channel supplied */
	uint16_t		suspend_time; /* OCAC suspend time interval for which the OCAC is suspended */
	uint16_t		thresh_video_frames;	/* threshold of video frames counted
							   every 2s for WLAN transmission */
};

struct ieee80211_ocac_cfg {
	uint8_t			ocac_enable;
	uint8_t			ocac_debug_level;
	uint8_t			ocac_report_only;	/* report mode, don't switch channel */
	uint16_t		ocac_chan_ieee;		/* ieee channel number, "0" means auto */
	uint16_t		ocac_timer_expire_init;	/* the ocac_timer expire when starting ocac */
	char			ocac_region[4];		/* the radar mode indicated by region */
	struct ieee80211_ocac_params	ocac_params;
};

struct ieee80211_ocac_rx_state {
	uint64_t		timestamp;		/* jiffies, when this beacon was received */
	uint8_t			ta[IEEE80211_ADDR_LEN];	/* Transmitter Address: sender of this beacon */
	uint8_t			state;			/* NONE, BACKOFF or ONGOING */
	uint8_t			param;
};

struct ieee80211_ocac {
#define OCAC_UNAVAILABLE	0x0
#define OCAC_AVAILABLE		0x1				/* No neighbouring AP doing OCAC */
	uint8_t			ocac_available;
	uint8_t			ocac_backoff_in_progress;	/* 1 => if BACKOFF sequence is in progress */
	uint8_t			ocac_backoff_count;		/* [8, 64]; random backoff */
	struct completion	ocac_backoff_completion;	/* Signalled when random backoff is done */

	uint8_t			ocac_running;
	uint8_t			ocac_bcn_intval_set;
	uint8_t			ocac_repick_dfs_chan;
	uint32_t		ocac_accum_duration_secs;	/* seconds, the accumulated off-channel
									CAC time for one channel*/
	uint32_t		ocac_accum_cac_time_ms;		/* milliseconds, the accumulated time on
									off channel for one channel*/
	struct timer_list		ocac_timer;
	struct ieee80211_channel	*ocac_chan;		/* current off channel for CAC */
	struct ieee80211_ocac_cfg	ocac_cfg;
	struct ieee80211_ocac_counts	ocac_counts;

	spinlock_t			ocac_lock;		/* Lock for ocac_rx_state */
	struct ieee80211_ocac_rx_state	ocac_rx_state;
};

#define IEEE80211_SET_CHANNEL_DEFERRED_CANCEL	0x80000000
#define IEEE80211_SET_CHANNEL_TSF_OFFSET	0x40000000

enum ieee80211_scan_frame_flags {
	IEEE80211_SCAN_FRAME_START = 0,
	IEEE80211_SCAN_FRAME_PRBREQ = 1,
	IEEE80211_SCAN_FRAME_SPEC_PRBREQ = 2,
	IEEE80211_SCAN_FRAME_FINISH = 3,
	IEEE80211_SCAN_FRAME_ALL = 4
};

struct qtn_bgscan_param	{
	u_int16_t	dwell_msecs_active;
	u_int16_t	dwell_msecs_passive;
	u_int16_t	duration_msecs_obss;
	u_int16_t	duration_msecs_active;
	u_int16_t	duration_msecs_passive_fast;
	u_int16_t	duration_msecs_passive_normal;
	u_int16_t	duration_msecs_passive_slow;
	u_int16_t	thrshld_fat_passive_fast;
	u_int16_t	thrshld_fat_passive_normal;
	u_int16_t	debug_flags;
	u_int16_t	check_beacon_conflict;
};

struct channel_change_event {
	u_int8_t	cce_previous;
	u_int8_t	cce_current;
};

struct ieee80211_phy_stats {
	u_int32_t	tstamp;

	u_int32_t	assoc;

	u_int32_t	atten;
	u_int32_t	cca_total;
	u_int32_t	cca_tx;
	u_int32_t	cca_rx;
	u_int32_t	cca_int;
	u_int32_t	cca_idle;

	u_int32_t	rx_pkts;
	u_int32_t	rx_gain;
	u_int32_t	rx_cnt_crc;
	u_int32_t	rx_noise;

	u_int32_t	tx_pkts;
	u_int32_t	tx_defers;
	u_int32_t	tx_touts;
	u_int32_t	tx_retries;

	u_int32_t	cnt_sp_fail;
	u_int32_t	cnt_lp_fail;
	u_int32_t	last_tx_scale;
	u_int32_t	last_rx_mcs;
	u_int32_t	last_tx_mcs;

	u_int32_t	last_rssi;
	u_int32_t	last_rssi_array[IEEE80211_QTN_NUM_RF_STREAMS];

	u_int32_t	last_rcpi;

	u_int32_t	last_evm;
	u_int32_t	last_evm_array[IEEE80211_QTN_NUM_RF_STREAMS];

	u_int32_t	last_tx_pkt_timestamp;
	u_int32_t	last_rx_pkt_timestamp;
};

#define BRCM_RXGLITCH_INVALID          0xFFFFFFFF
#define BRCM_RXGLITCH_TOP              0xFFFFFF
#define BRCM_RXGLITCH_THRSHLD_SCALE_MAX        0xFF
#define BRCM_RXGLITCH_MAX_PER_INTVL            300000
#define BRCM_RXGLITCH_NEXT_TRIG_THRSHLD        20      /* percent */
#define BRCM_RSSI_MIN                  -120
#define BRCM_RXGLITH_THRSHLD_HIPWR     0
#define BRCM_RXGLITH_THRSHLD_LOWPWR    1
#define BRCM_RXGLITH_THRSHLD_PWR_NUM   2
#define BRCM_RXGLITH_THRSHLD_STEP      5
struct brcm_rxglitch_thrshld_pair {
	int rssi;
	uint32_t rxglitch;
};

struct ip_mac_mapping {
	struct		ip_mac_mapping *next;
	__be32		ip_addr;
	u_int8_t	mac[ETH_ALEN];
};

#define MAX_USER_DEFINED_MAGIC_LEN	256
struct ieee80211_wowlan_pattern {
	uint32_t	len;
	uint8_t		magic_pattern[MAX_USER_DEFINED_MAGIC_LEN];
};

#define WOWLAN_TRIG_ALL	(~0U)

#define WOWLAN_TRIG_MAGIC	BIT(0)
#define WOWLAN_TRIG_PATTERN	BIT(1)
#define WOWLAN_TRIG_DISCONNECT	BIT(2)

enum wowlan_wakeup_type {
	WOWLAN_GPIO_PIN_HOST_WAKEUP	= 0,
	WOWLAN_PCIE_PME_HOST_WAKEUP	= 1,
};

struct ieee80211_wowlan {
	uint16_t	host_state;
	uint16_t	wowlan_match;
	uint16_t	L2_ether_type;
	uint16_t	L3_udp_port;
	uint32_t	mask;
	uint32_t	wakeup_type;
	struct ieee80211_wowlan_pattern	pattern;
};

/*
 * Channel occupancy record
 */
struct ieee80211_chan_occupy_record {
	uint32_t occupy_start;			/* time in seconds when channel was selected */
	uint8_t cur_chan;			/* channel for which time is recorded */
	uint8_t prev_chan;			/* previous channel */
	uint32_t duration[IEEE80211_CHAN_MAX];	/* time spent on a channel in seconds */
	uint32_t times[IEEE80211_CHAN_MAX];	/* number of times channel was used */
};

/* Some custom knobs for out ap scan alg */
#define	ICS_METRIC_CHECK_MARGIN	(10)

#define DM_TXPOWER_FACTOR_MAX	8
#define DM_TXPOWER_FACTOR_MIN	0
#define DM_ACI_FACTOR_MAX	0
#define DM_ACI_FACTOR_MIN	-4
#define DM_CCI_FACTOR_MAX	0
#define DM_CCI_FACTOR_MIN	-4
#define DM_DFS_FACTOR_MAX	32
#define DM_DFS_FACTOR_MIN	0
#define DM_BEACON_FACTOR_MAX	0
#define DM_BEACON_FACTOR_MIN	-4

#define DM_FLAG_TXPOWER_FACTOR_PRESENT	0x1
#define DM_FLAG_ACI_FACTOR_PRESENT	0x2
#define DM_FLAG_CCI_FACTOR_PRESENT	0x4
#define DM_FLAG_DFS_FACTOR_PRESENT	0x8
#define DM_FLAG_BEACON_FACTOR_PRESENT	0x10

struct ieee80211_dm_factor {
	uint32_t flags;
	int txpower_factor;
	int aci_factor;
	int cci_factor;
	int dfs_factor;
	int beacon_factor;
};

#if defined(QBMPS_ENABLE)

#define BMPS_MODE_OFF		0
#define BMPS_MODE_MANUAL	1
#define BMPS_MODE_AUTO		2

#define	BMPS_TPUT_THRESHOLD_UPPER	8000	/* 8 mbps */
#define	BMPS_TPUT_THRESHOLD_LOWER	4000	/* 4 mbps */
#define BMPS_TPUT_MEASURE_PERIOD_MS	5000	/* 5 seconds */

struct bmps_tput_measure {
	struct timer_list tput_timer;		/* STA BMPS timer for TX/RX */
						/* tput measurement */
	uint32_t prev_tx_bytes;			/* # of TX bytes in previous measurement */
	uint32_t prev_rx_bytes;			/* # of RX bytes in previous measurement */
	uint32_t tput_kbps;			/* TX & RX overall throughput in kbps */
};
#endif

/*
 * Operating class table for regulatory region to operating class conversion.
 */
struct operating_class_table {
	uint8_t index;
	uint8_t global_index;
	uint8_t bandwidth;
	uint8_t chan_set[IEEE80211_CHAN_BYTES];
	uint16_t behavior;
};

struct region_to_oper_class {
	const char *region_name;
	uint8_t class_num_5g;
	uint8_t classes_5g[IEEE80211_OPER_CLASS_BYTES];
	uint8_t class_num_24g;
	uint8_t classes_24g[IEEE80211_OPER_CLASS_BYTES_24G];
	const struct operating_class_table * const class_table;
};

/*
 * Logical SSID group used for defining association limits per group of VAPs.
 */
struct ssid_logical_group {
	u_int16_t limit;
	u_int16_t reserve;
	u_int16_t assocs;
};

struct offchan_protect {
	struct timer_list offchan_stop_expire;	/* off channel suspend/resume expiration timer */
	uint32_t offchan_suspend_cnt;	/* off channel suspending counter */
	unsigned long offchan_timeout;	/* off channel suspending timeout, in jiffies */
};

struct sta_dfs_info {
	struct timer_list sta_radar_timer;
	struct timer_list sta_silence_timer;
	bool	sta_dfs_radar_detected_timer;
	int	sta_dfs_radar_detected_channel;
	unsigned long	sta_dfs_tx_chan_close_time;
	uint8_t	sta_dfs_strict_mode;
	bool	sta_dfs_strict_msr_cac;
	bool	allow_measurement_report;
};

#ifdef CONFIG_QHOP
struct rbs_mbs_dfs_info {
        bool    rbs_mbs_allow_tx_frms_in_cac;
        bool    rbs_allow_qhop_report;
        bool    mbs_allow_csa;
        struct timer_list rbs_dfs_radar_timer;
	unsigned long rbs_dfs_tx_chan_close_time;
};
#endif

struct ieee80211_vopt_info {
	uint8_t state;
	uint8_t	cur_state;
	uint8_t	bf;
	uint8_t	bbf;
	uint8_t	pppc;
	uint8_t airfair;
	uint32_t scs;
	uint32_t ocac;
	uint32_t qtm;
	uint32_t slow_mask;
	int32_t rx_reset_wait;
	int32_t tx_bcn_hang;
};

enum qtn_rssi_dbm_endian {
	DBM_ENDIAN_AUTO = 0,	/* RSSI DBM auto check adaption */
	DBM_ENDIAN_BIG,		/* RSSI DBM adapt to old big endian */
	DBM_ENDIAN_LITTLE,	/* RSSI DBM adapt to new little endian */
};

struct qtn_rp_info {
	uint8_t flags;
	uint8_t type;
	uint32_t throughput;
};

struct ieee80211com {
	/* MATS FIX The member ic_dev is not used in QDRV and should be removed */
	struct net_device *ic_dev;		/* associated device */
	struct ieee80211_channel * (*ic_findchannel)(struct ieee80211com *ic, int ieee, int mode);
	ieee80211com_lock_t ic_comlock;		/* state update lock */
	ieee80211com_lock_t ic_vapslock;	/* vap state machine lock */
	TAILQ_HEAD(, ieee80211vap) ic_vaps;	/* list of vap instances */
	enum ieee80211_phytype ic_phytype;	/* XXX wrong for multi-mode */
	enum ieee80211_phymode ic_phymode;	/* Phy Mode */
	enum ieee80211_phymode ic_phymode_save;	/* Phy Mode save */
	int fixed_legacy_rate_mode;		/* Legacy rate mode */
	int ic_radar_bw;			/* Radar mode */
	enum ieee80211_opmode ic_opmode;	/* operation mode */
	struct ifmedia ic_media;		/* interface media config */
	u_int8_t ic_myaddr[IEEE80211_ADDR_LEN];
	struct timer_list ic_inact;		/* mgmt/inactivity timer */
	struct offchan_protect ic_offchan_protect;

	uint32_t ic_ver_sw;
	uint16_t ic_ver_hw;
	uint16_t ic_ver_platform_id;
	uint32_t ic_ver_timestamp;
	uint32_t ic_ver_flags;
	uint8_t ic_unit;

	u_int32_t ic_flags;			/* state flags */
	u_int32_t ic_flags_ext;			/* extension of state flags */
	u_int32_t ic_flags_ext2;		/* extension 2 of state flags */
	u_int32_t ic_flags_qtn;			/* Quantenna specific flags */
	u_int32_t ic_caps;			/* capabilities */
	enum ieee80211_vht_mcs_supported ic_vht_mcs_cap;	/* VHT MCS capability */
	enum ieee80211_ht_nss ic_ht_nss_cap;	/* Current HT Max spatial streams */
	enum ieee80211_ht_nss ic_ht_rx_nss_cap;	/* Current HT Max rx spatial streams */
	enum ieee80211_vht_nss ic_vht_nss_cap;		/* Current VHT Max spatial streams */
	enum ieee80211_vht_nss ic_vht_nss_cap_24g;	/* Current 2.4G VHT Max spatial streams*/
	enum ieee80211_vht_nss ic_vht_rx_nss_cap;	/* Current VHT Max rx spatial streams */
	enum ieee80211_vht_nss ic_vht_rx_nss_cap_24g;	/* Current 2.4G VHT rx Max spatial streams*/
	u_int8_t ic_ath_cap;			/* Atheros adv. capabilities */
	u_int8_t ic_promisc;			/* vap's needing promisc mode */
	u_int8_t ic_allmulti;			/* vap's needing all multicast*/
	u_int8_t ic_nopened;			/* vap's been opened */
	struct ieee80211_rateset ic_sup_rates[IEEE80211_MODE_MAX];
	struct ieee80211_rateset ic_sup_xr_rates;
	struct ieee80211_rateset ic_sup_half_rates;
	struct ieee80211_rateset ic_sup_quarter_rates;
	struct ieee80211_rateset ic_sup_ht_rates[IEEE80211_MODE_MAX];
	u_int16_t		ic_modecaps;	/* set of mode capabilities */
	u_int16_t		ic_curmode;	/* current mode */
	u_int16_t		ic_lintval;	/* beacon interval */
	u_int16_t		ic_lintval_backup;	/* beacon interval for backup */
	u_int16_t		ic_holdover;	/* PM hold over duration */
	u_int16_t		ic_bmisstimeout;/* beacon miss threshold (ms) */
	u_int16_t		ic_txpowlimit;	/* global tx power limit */
	u_int32_t		ic_sample_rate;	/* sampling rate in seconds */

	u_int16_t		ic_newtxpowlimit; /* tx power limit to change to (in 0.5 dBm) */
	u_int16_t		ic_uapsdmaxtriggers; /* max triggers that could arrive */
	u_int8_t		ic_coverageclass; /* coverage class */
	int8_t			ic_pwr_adjust_scancnt; /* Num of scans after which gain settings toggle */
	uint32_t		ic_bcn_hang_timeout; /* Beacon hang timeout */

	int rts_cts_prot; /* RTS-CTS protection support */

	/* 11n Capabilities */
	struct ieee80211_htcap ic_htcap; /* HT capabilities */
	int ldpc_enabled; /* LDPC support */
	int stbc_enabled; /* STBC support */

	/* 11n info */
	struct ieee80211_htinfo ic_htinfo; /* HT information */

	/* 11n beamforming */
	u_int16_t ic_bfgrouping;
	u_int16_t ic_bfcoeffsize;

	int ic_txbf_period;

	/* 2.4G band vht capabilities */
	struct ieee80211_vhtcap ic_vhtcap_24g;
	struct ieee80211_vhtop  ic_vhtop_24g;

	/* 5G band capabilities */
	struct ieee80211_vhtcap ic_vhtcap;
	struct ieee80211_vhtop	ic_vhtop;

	struct ieee80211_scs ic_scs; /* SCS related information */
	struct delayed_work ic_scs_sample_work;	/* SCS (ACI/CCI Detection and Mitigation) workqueue */
	struct ieee80211_ocac ic_ocac; /* OCAC related information*/
	struct ieee80211_cap_ctx ic_cap_ctx; /* MAP capabilities table */
	uint32_t ic_11n_40_only_mode;
	uint16_t ic_vht_opmode_notif;	/* Override OpMode Notification IE, for WFA Testbed */
	uint8_t ic_non_ht_sta;
	uint8_t ic_ht_20mhz_only_sta;
	uint8_t ic_non_ht_non_member;
	uint8_t ic_pppc_select_enable;
	uint8_t ic_pppc_select_enable_backup;
	uint8_t ic_pppc_step_db;
	uint8_t	ic_gi_fixed;		/* Enable fixed GI setting */
	uint8_t	ic_gi_select_enable;	/* Enable dynamic GI selection */
	uint8_t ic_bw_fixed;		/* Fixed bw setting */
	uint8_t ic_def_matrix;		/* Default expansion matrices */
	uint8_t ic_sta_cc;		/* Channel change due to noise at STA */
	uint8_t ic_sta_cc_brcm;		/* Channel change due to noise at brcm STA */
	uint8_t ic_tx_qos_sched;        /* tx qos sched index for hold-time table */
	uint8_t ic_local_rts;		/* Use RTS on local node */
	uint8_t ic_peer_rts_mode;	/* Config for informing peer nodes to use RTS */
	uint8_t ic_dyn_peer_rts;	/* Dynamic peer RTS current status */
	uint8_t ic_peer_rts;		/* Inform peer nodes to use RTS */
	uint8_t ic_dyn_wmm;		/* Dynamic WMM enabled */
	uint8_t ic_emi_power_switch_enable;
	uint8_t ic_dfs_channels_deactive; /* Deactive all DFS channels */
	uint8_t ic_beaconing_scheme;
	uint8_t ic_dfs_csa_cnt;
	uint8_t ic_weachan_cac_allowed;

	/*
	 * Channel state:
	 *
	 * ic_channels is the set of available channels for the device;
	 *    it is setup by the driver
	 * ic_nchans is the number of valid entries in ic_channels
	 * ic_chan_avail is a bit vector of these channels used to check
	 *    whether a channel is available w/o searching the channel table.
	 * ic_chan_active is a (potentially) constrained subset of
	 *    ic_chan_avail that reflects any mode setting or user-specified
	 *    limit on the set of channels to use/scan
	 * ic_curchan is the current channel the device is set to; it may
	 *    be different from ic_bsschan when we are off-channel scanning
	 *    or otherwise doing background work
	 * ic_bsschan is the channel selected for operation; it may
	 *    be undefined (IEEE80211_CHAN_ANYC)
	 * ic_prevchan is a cached ``previous channel'' used to optimize
	 *    lookups when switching back+forth between two channels
	 *    (e.g. for dynamic turbo)
	 */
	uint8_t ic_rf_chipid;                   /* RFIC chip ID */
	unsigned ic_nchans;				/* # entries in ic_channels */
	struct ieee80211_channel *ic_channels;
	struct ieee80211req_csw_record	ic_csw_record;	/* channel switch record */
	struct ieee80211_chan_occupy_record ic_chan_occupy_record;
	uint32_t ic_csw_reason;				/* reason for the last channel switch */
	u_int8_t ic_csw_mac[IEEE80211_ADDR_LEN];	/* client mac addr when SCS channel switch */
	struct ieee80211_assoc_history ic_assoc_history;
	struct ieee80211_disassoc_records ic_disassoc_records;
	u_int8_t ic_chan_avail[IEEE80211_CHAN_BYTES];
	u_int8_t ic_chan_active[IEEE80211_CHAN_BYTES];
	u_int8_t ic_chan_ocac_off[IEEE80211_CHAN_BYTES];	/* channels that have OCAC disabled */

	u_int8_t ic_chan_availability_status[IEEE80211_CHAN_MAX+1];

	uint8_t ic_autochan_obss_check;
	uint8_t ic_obss_flag;

	uint16_t ic_ics_check_margin;

	int8_t ic_chan_ics_weights[IEEE80211_CHAN_MAX];
	int8_t ic_chan_scs_weights[IEEE80211_CHAN_MAX];

	u_int8_t ic_chan_pri_inactive[IEEE80211_CHAN_BYTES];	/* channel not used as primary */
	u_int8_t ic_is_inactive_usercfg[IEEE80211_CHAN_BYTES];  /* 0x1-regulatory 0x2-user override */
	u_int8_t ic_is_inactive_autochan_only[IEEE80211_CHAN_BYTES];
	u_int8_t ic_is_scs_active[IEEE80211_CHAN_BYTES];	/* whether SCS is enabled or not */
	u_int8_t ic_chan_dfs_required[IEEE80211_CHAN_BYTES];	/* channel is DFS required */
	u_int8_t ic_chan_weather_radar[IEEE80211_CHAN_BYTES];	/* weather radar channel */
	u_int8_t ic_chan_disabled[IEEE80211_CHAN_BYTES];	/* channels are disabled */
	u_int8_t ic_chan_scs[IEEE80211_CHAN_BYTES];             /* scs channel */

	u_int8_t ic_chan_active_20[IEEE80211_CHAN_BYTES];
	u_int8_t ic_chan_active_40[IEEE80211_CHAN_BYTES];
	u_int8_t ic_chan_active_80[IEEE80211_CHAN_BYTES];
	u_int8_t ic_chan_intole_40[IEEE80211_CHAN_BYTES];
	u_int8_t ic_bw_auto_select;
	u_int8_t ic_max_system_bw;
	u_int8_t ic_bss_bw;			/* BSS channel width */
	u_int8_t ic_node_bw_cfg_pending;
	struct ieee80211_vopt_info ic_vopt;

	struct ieee80211_channel *ic_curchan;	/* current channel */
	struct ieee80211_channel *ic_bsschan;	/* bss channel */
	struct ieee80211_channel *ic_prevchan;	/* previous channel */
	struct ieee80211_channel *ic_coc_prevchan;	/* coc channel record */
	struct ieee80211_channel *ic_scanchan;	/* scanning channel */
	int16_t ic_channoise;			/* current channel noise in dBm */
	struct ieee80211_channel *ic_des_chan;	/* desired channel */
	int ic_des_chan_after_init_cac;	/* Saved desired chan to switch after Initial CAC */
	int ic_des_chan_after_init_scan;/* Saved desired chan to switch after Initial Scan */
	int ic_ignore_init_scan_icac;/* Ignore init cac in case of set channel for wireless_conf arguement fails */

	int ic_chan_is_set;
	u_int16_t ic_des_mode;			/* desired mode */
	/* regulatory class ids */
	u_int ic_nregclass;			/* # entries in ic_regclassids */
	u_int8_t ic_regclassids[IEEE80211_REGCLASSIDS_MAX];
	u_int8_t ic_user_set_chan;			/* used "set_channel" command to set channel */
	struct ieee80211_channel *ic_fast_reass_chan;	/* fast reassociate channel */
#define IEEE80211_FAST_REASS_SCAN_MAX 3
	u_int8_t ic_fast_reass_scan_cnt;	/* Number of times tried to do fast reassoc */

	/* scan-related state */
	struct ieee80211_scan_state *ic_scan;	/* scan state */
	uint8_t ic_scan_chan_list[IEEE80211_CHAN_BYTES];
	enum ieee80211_roamingmode ic_roaming;	/* roaming mode */
	unsigned long ic_lastdata;		/* time of last data frame */
	unsigned long ic_lastscan;		/* time last scan completed or cancelled */

	/* NB: this is the union of all vap stations/neighbors */
	struct ieee80211_node_table ic_sta;	/* stations/neighbors */

	/* XXX multi-bss: split out common/vap parts? */
	struct ieee80211_wme_state ic_wme;	/* WME/WMM state */
	uint8_t ic_vap_pri_wme;			/* enable automatic adjusting wme bss param based on vap priority */
	uint8_t ic_airfair;			/* airtime fairness */

	/* XXX multi-bss: can per-vap be done/make sense? */
	enum ieee80211_protmode	ic_protmode;	/* 802.11g protection mode */
	u_int16_t ic_nonerpsta;			/* # non-ERP stations */
	u_int16_t ic_longslotsta;		/* # long slot time stations */
	u_int16_t ic_sta_assoc_limit;		/* total assoc limit per interface */
	u_int16_t ic_sta_assoc;			/* stations associated(including WDS node) */
	u_int16_t ic_wds_links;			/* WDS links created */
	u_int16_t ic_dt_sta_assoc;		/* dturbo capable stations */
	u_int16_t ic_xr_sta_assoc;		/* XR stations associated */
	u_int16_t ic_nonqtn_sta;		/* Non-Quantenna peers */

	struct ssid_logical_group ic_ssid_grp[IEEE80211_MAX_BSS_GROUP]; /* VAPs logical group assocication limits */

	/* dwell times for channel scanning */
	u_int16_t ic_mindwell_active;
	u_int16_t ic_mindwell_passive;
	u_int16_t ic_maxdwell_active;
	u_int16_t ic_maxdwell_passive;
	struct qtn_bgscan_param	ic_qtn_bgscan;

	/* Adding Wireless stats per MAC. Per Vap is maintained in vap structure */
	struct iw_statistics ic_iwstats;
	/*
	 * Spectrum Management.
	 */
	u_int16_t ic_country_code;
	u_int16_t ic_country_code_for_update;   /* new country code for update after association */
	uint16_t ic_spec_country_code;	/* specific country code for EU region */
	uint8_t ic_country_env; /* the 3rd byte of country ie string */
	struct ieee80211_ie_country ic_country_ie; /* country info element */
	struct workqueue_struct *wlan_workqueue;  /* A generic work queue for wlan driver */
	struct work_struct region_work;

	uint8_t ic_oper_class[IEEE80211_OPER_CLASS_BYTES];	/* Supported operating class */
	const struct region_to_oper_class *ic_oper_class_table;
	/*
	 *  current channel power constraint for Power Constraint IE.
	 *
	 *  NB: local power constraint depends on the channel, but assuming it must
	 *     be detected dynamically, we cannot maintain a table (i.e., will not
	 *     know value until change to channel and detect).
	 */
	u_int8_t ic_pwr_constraint;
	struct ieee80211_pc_over ic_pco; /* Power constraint override related information*/
	u_int8_t ic_chanchange_tbtt;
	u_int8_t ic_chanchange_chan;

	u_int8_t ic_csa_count;			/* last csa count */
	u_int8_t ic_csa_mode;			/* last csa mode */
	u_int8_t ic_csa_bw;			/* New BW derived from CSA */
	u_int8_t ic_csa_bw_change_pending;
	int32_t ic_csa_reason;
#define IEEE80211_CSA_F_BEACON     0x1
#define IEEE80211_CSA_F_ACTION     0x2
	uint32_t ic_csa_flag;
#define IEEE80211_CSA_FRM_BEACON   0
#define IEEE80211_CSA_FRM_ACTION   1
#define IEEE80211_CSA_FRM_MAX      2
	int32_t ic_csa_frame[IEEE80211_CSA_FRM_MAX];
	struct ieee80211_channel *ic_csa_chan;	/* csa channel */
	struct ieee80211_channel *ic_pending_csa_chan;	/* pending csa channel */
	u_int8_t ic_pending_csa_mode;		/* pending csa mode */
	struct completion csa_completion;	/* complete event of csa counter, wake up MuC command */
	struct workqueue_struct *csa_work_queue;
	struct work_struct csa_work;		/* work queue to perform csa action */
	void (*finish_csa)(unsigned long);
	u_int8_t ic_cca_token;			/* last cca token */

	/* upcoming cca measurement */
	u_int64_t ic_cca_start_tsf;		/* tsf at which cca measurement will occur */
	u_int16_t ic_cca_duration_tu;		/* duration of cca measurement in TU */
	u_int8_t ic_cca_chan;			/* channel of cca measurement */

	u_int8_t ic_ieee_alt_chan;		/* if not zero jump to this channel if radar is detected */
	u_int8_t ic_ieee_best_alt_chan;		/* tracks best alternate chan to fast-switch into if radar is detected */
	u_int32_t ic_non_occupancy_period;	/* radar non-occupancy period. */

	/* boot time CAC*/
	int32_t ic_max_boot_cac_duration;
	unsigned long ic_boot_cac_end_jiffy;
        struct timer_list icac_timer;

	u_int8_t ic_mode_get_phy_stats;

	u_int8_t ic_legacy_retry_limit;
	u_int8_t ic_retry_count;

	u_int32_t ic_ndpa_dur;
	u_int32_t ic_su_txbf_pkt_cnt;
	u_int32_t ic_mu_txbf_pkt_cnt;
	u_int32_t ic_tx_max_ampdu_size;

	u_int16_t ic_mu_debug_level;
        u_int16_t ic_rts_bw_dyn;
	u_int8_t  ic_mu_enable;
	u_int8_t  ic_mu_qmat_bypass_mode_enable;

	u_int8_t ic_dup_rts;
	u_int8_t ic_cts_bw;
	u_int8_t use_non_ht_duplicate_for_mu;
	u_int8_t rx_bws_support_for_mu_ndpa;

	u_int8_t cca_fix_disable;
	u_int8_t auto_cca_enable;
	u_int8_t ic_opmode_bw_switch_en;
	u_int8_t ic_des_bw;

	struct muc_tx_stats *ic_muc_tx_stats;


	/* virtual ap create/delete */
	struct ieee80211vap *(*ic_vap_create)(struct ieee80211com *,
		const char *, int, int, int, struct net_device *);
	void (*ic_vap_delete)(struct ieee80211vap *);
	uint8_t (*ic_get_vap_idx)(struct ieee80211vap *);
	/* send/recv 802.11 management frame */
	int (*ic_send_mgmt)(struct ieee80211_node *, int, int);
	void (*ic_recv_mgmt)(struct ieee80211_node *, struct sk_buff *, int,
		int, u_int32_t);
	/* send an 802.11 encapsulated frame to the driver */
	int (*ic_send_80211)(struct ieee80211com *, struct ieee80211_node *ni,
				struct sk_buff *skb, uint32_t priority, uint8_t is_mgmt);
	/* reset device state after 802.11 parameter/state change */
	int (*ic_init)(struct ieee80211com *);
	int (*ic_reset)(struct ieee80211com *);
	void (*ic_queue_reset)(struct ieee80211_node *);
	/* update device state for 802.11 slot time change */
	void (*ic_updateslot)(struct ieee80211com *);
	/* new station association callback/notification */
	void (*ic_newassoc)(struct ieee80211_node *, int);
	void (*ic_disassoc)(struct ieee80211_node *);
	void (*ic_node_update)(struct ieee80211_node *);
	/* node state management */
	struct ieee80211_node *(*ic_node_alloc)(struct ieee80211_node_table *,
		struct ieee80211vap *, const uint8_t *, uint8_t tmp_node);
	void (*ic_node_free)(struct ieee80211_node *);
	void (*ic_qdrv_node_free)(struct ieee80211_node *);
	void (*ic_node_cleanup)(struct ieee80211_node *);
	u_int8_t (*ic_node_getrssi)(const struct ieee80211_node *);
	u_int8_t (*ic_node_move_data)(const struct ieee80211_node *);

	void (*ic_iterate_nodes)(struct ieee80211_node_table *, ieee80211_iter_func *,
		void *, int ignore_blacklist);
	void (*ic_iterate_dev_nodes)(struct net_device *,
				     struct ieee80211_node_table *,
				     ieee80211_iter_func *, void *, int);

	/* scanning support */
	void (*ic_initiate_scan)(struct ieee80211vap *vap);
	void (*ic_scan_start)(struct ieee80211com *com, const uint8_t *scan_addr);
	void (*ic_scan_end)(struct ieee80211com *);
#define IEEE80211_CHANNEL_CHECK_FASTSWITCH		0x00000001
#define IEEE80211_CHANNEL_CHECK_ALLOW_CURRENT		0x00000002
#define IEEE80211_CHANNEL_CHECK_BW_SWITCH		0x00000004
	int (*ic_check_channel)(struct ieee80211com *ic, struct ieee80211_channel *chan,
				uint32_t flags);
	void (*ic_set_channel)(struct ieee80211com *);
	void (*ic_bridge_set_dest_addr)(struct sk_buff *skb, void *eh1);
	void (*ic_get_tsf)(uint64_t *tsf);
	int (*ic_bmps_set_frame)(struct ieee80211com *ic, struct ieee80211_node *ni,
				struct sk_buff *skb);
	int (*ic_bmps_release_frame)(struct ieee80211com *ic);
	void (*ic_scs_update_scan_stats)(struct ieee80211com *ic);
	void (*ic_scs_override_mode)(struct ieee80211com *ic);
	int (*ic_sample_channel)(struct ieee80211vap *vap, struct ieee80211_channel *chan);
	int (*ic_sample_channel_cancel)(struct ieee80211vap *vap);
	int (*ic_bgscan_start)(struct ieee80211com *ic);
	int (*ic_bgscan_channel)(struct ieee80211vap *vap, struct ieee80211_channel *chan,
			int bgscan_flags, int dwelltime, int dwell_total, int scan_bw,
			int max_duration, uint8_t *bssid);
	int (*ic_bgscan_end)(struct ieee80211com *ic);
	void (*ic_set_channel_deferred)(struct ieee80211com *, u_int64_t tsf, int flags);
	int  (*ic_set_start_cca_measurement)(struct ieee80211com *ic,
					     const struct ieee80211_channel *cca_channel,
					     uint64_t start_tsf, u_int32_t duration);
	int (*ic_do_measurement)(struct ieee80211com *ic);
	void (*ic_finish_measurement)(struct ieee80211com *ic, u_int8_t result);
	void (*ic_send_csa_frame)(struct ieee80211vap *vap, uint8_t csa_mode,
				  uint8_t csa_chan, uint8_t csa_count, uint64_t tsf);
	int (*ic_set_ocac)(struct ieee80211vap *vap, struct ieee80211_channel *chan);
	int (*ic_ocac_release_frame)(struct ieee80211com *ic, int force);

	int (*ic_set_beaconing_scheme)(struct ieee80211vap *vap, int param, int value);

	int (*ic_set_txctl)(struct ieee80211com *ic, uint32_t txctl);
	int (*ic_robust_csa_release_frame)(struct ieee80211com *ic);
	int (*ic_robust_csa_send_frame)(struct ieee80211vap *vap,
			u_int8_t csa_mode, u_int8_t csa_chan,
			u_int8_t csa_count, u_int64_t tsf);

	/* u-apsd support */
	void (*ic_uapsd_flush)(struct ieee80211_node *);

	/* set coverage class */
	void (*ic_set_coverageclass)(struct ieee80211com *);

	/* mhz to ieee conversion */
	u_int (*ic_mhz2ieee)(struct ieee80211com *, u_int, u_int);
	void (*ic_setparam)(struct ieee80211_node *, int, int, unsigned char *, int);
	int (*ic_getparam)(struct ieee80211_node *, int, int *, unsigned char *, int *);
	void (*ic_register_node)(struct ieee80211_node *ni);
	void (*ic_unregister_node)(struct ieee80211_node *ni);
	int (*ic_get_phy_stats)(struct net_device *dev, struct ieee80211com *ic,
				struct ieee80211_phy_stats *ps, uint8_t all_stats);
	int (*ic_ncbeamforming)(struct ieee80211_node *, struct sk_buff *act_frame);
	void (*ic_htaddba)(struct ieee80211_node *, int, int);
	void (*ic_htdelba)(struct ieee80211_node *, int, int);

	void (*ic_join_bss)(struct ieee80211vap *vap);
	void (*ic_beacon_update)(struct ieee80211vap *vap);
	void (*ic_beacon_stop)(struct ieee80211vap *vap);
	void (*ic_set_vap_macaddr)(struct ieee80211vap *vap, int enable);
	void (*ic_setkey)(struct ieee80211vap *vap, const struct ieee80211_key *k,
		const u_int8_t mac[IEEE80211_ADDR_LEN]);
	void (*ic_delkey)(struct ieee80211vap *vap, const struct ieee80211_key *k,
		const u_int8_t mac[IEEE80211_ADDR_LEN]);

	/* L2 external filter */
	int (*ic_set_l2_ext_filter)(struct ieee80211vap *, int);
	int (*ic_set_l2_ext_filter_port)(struct ieee80211vap *, int);
	int (*ic_get_l2_ext_filter_port)(void);
	void (*ic_send_to_l2_ext_filter)(struct ieee80211vap *, struct sk_buff *);

	int (*ic_mac_reserved)(const uint8_t *addr);

	/* Stats support */
	void (*ic_get_wlanstats)(struct ieee80211com *, struct iw_statistics *);
	/* Change of the MIMO power save mode for the STA */
	void (*ic_smps)(struct ieee80211_node *, int);
	/* TKIP MIC failure report */
	void (*ic_tkip_mic_failure)(struct ieee80211vap *, int count);
	/* DFS radar is enabled */
	int (*ic_radar_is_enabled)(void);
	/* DFS radar detection handling */
	void (*ic_radar_detected)(struct ieee80211com* ic, u_int8_t new_ieee);
	/* DFS radar selection function */
	struct ieee80211_channel *(*ic_select_channel)(u_int8_t new_ieee);
	/* DFS action when channel scan is done*/
	void (*ic_dfs_action_scan_done)(void);
	/* Check if current region belongs to EU region */
	bool (*ic_dfs_is_eu_region)(void);
	/* Check if current region belongs to US region */
	int (*ic_dfs_is_us_region)(void);
	/* Check if STA need to keep slient upon entering a DFS channel */
	int (*ic_require_sta_slient)(struct ieee80211com* ic);
	/* Check if current region is a channel status saving region */
	int (*ic_dfs_is_status_save_region)(void);
	/* Check if current region is a ICAC supporting region */
	int (*ic_dfs_is_icac_supp_region)(void);


	void (*ic_mark_channel_availability_status)(struct ieee80211com *ic, struct ieee80211_channel *chan, uint8_t usable);

	int (*ic_get_chan_availability_status_by_chan_num)(struct ieee80211com *ic, struct ieee80211_channel *chan);

	void (*ic_mark_channel_dfs_cac_status)(struct ieee80211com *ic, struct ieee80211_channel *chan, u_int32_t cac_flag, bool set);
	void (*ic_dump_chan_availability_status)(struct ieee80211com *ic);
	void (*ic_report_chan_availability_status)(struct ieee80211com *ic, uint8_t usable);
	void (*ic_dump_ocac_tsf_log)(struct ieee80211com *ic);

	int (*ic_ap_next_cac)(struct ieee80211com *ic, struct ieee80211vap *vap,
			unsigned long cac_period,
			struct ieee80211_channel **qdrv_radar_cb_cac_chan,
			u_int32_t flags);

	bool (*ic_dfs_chans_available_for_cac)(struct ieee80211com *ic, struct ieee80211_channel *ch, int cac_type);
	int (*ic_is_dfs_chans_available_for_dfs_reentry)(struct ieee80211com *ic, struct ieee80211vap *);
	int  (*ic_get_init_cac_duration)(struct ieee80211com *ic);
	void (*ic_set_init_cac_duration)(struct ieee80211com *ic, int val);
	void (*ic_start_icac_procedure)(struct ieee80211com *ic);
	void (*ic_stop_icac_procedure)(struct ieee80211com *ic);
	bool (*ic_chan_compare_equality)(struct ieee80211com *ic,
					struct ieee80211_channel *curr_chan,
					struct ieee80211_channel *new_chan);

	bool (*ic_checkset_dfs_channel_availability_status)(struct ieee80211com *ic, int cur_bw, struct ieee80211_channel *chan);
	void (*ic_get_full_bss_chan)(struct ieee80211com *ic, struct ieee80211_channel *chan, struct ieee80211_channel *chan_list[], int cur_bw);

	/* DFS select channel */
	void (*ic_dfs_select_channel)(int channel);
	void (*ic_wmm_params_update)(struct ieee80211vap *);
	void (*ic_power_table_update)(struct ieee80211vap *vap,
			struct ieee80211_channel *chan);
	/* tdls parameters configuration */
	void (*ic_set_tdls_param)(struct ieee80211_node *ni, int cmd, int value);
	uint32_t (*ic_get_tdls_param)(struct ieee80211_node *ni, int cmd);
	int (*ic_rxtx_phy_rate)(const struct ieee80211_node *, const int is_rx,
			uint8_t *nss, uint8_t *mcs, uint8_t *mcs_mode, uint8_t *bw, uint8_t * sgi, uint32_t * phy_rate);
	int (*ic_rssi)(const struct ieee80211_node *);
	int (*ic_smoothed_rssi)(const struct ieee80211_node *);
	int (*ic_rssi_get)(const struct ieee80211_node *ni, int smoothed, int type);
	int (*ic_snr)(const struct ieee80211_node *);
	int (*ic_hw_noise)(const struct ieee80211_node *);
	int (*ic_max_queue)(const struct ieee80211_node *);
	u_int32_t (*ic_tx_failed)(const struct ieee80211_node *);
	/* Convert mcs to phy rate in Kbps */
	u_int32_t (*ic_mcs_to_phyrate)(u_int8_t bw, u_int8_t sgi, u_int8_t mcs,
			u_int8_t nss, u_int8_t vht);
	void (*ic_chan_switch_record)(struct ieee80211com *ic, struct ieee80211_channel *new_chan,
			uint32_t reason);
	void (*ic_chan_switch_reason_record)(struct ieee80211com *ic, int reason);
	void (*ic_disassoc_reason_record)(struct ieee80211com *ic, const char *macaddr, uint32_t reason);
	void (*ic_dfs_chan_switch_notify)(struct net_device *dev, struct ieee80211_channel *new_chan);
	int (*ic_radar_test_mode_enabled)(void);
	/* Count of the number of nodes allocated - for debug */
	int ic_node_count;

	void (*ic_node_auth_state_change)(struct ieee80211_node *ni, int deauth_auth);
	void (*ic_new_assoc)(struct ieee80211_node *ni);

	void (*ic_power_save)(struct ieee80211_node *ni, int enable);
	int (*ic_remain_on_channel)(struct ieee80211com *ic, struct ieee80211_node *ni,
			struct ieee80211_channel *off_chan, int bandwidth, uint64_t start_tsf,
			uint32_t timeout, uint32_t duration, int flags);

	int (*ic_mark_dfs_channels)(struct ieee80211com *ic);
	int (*ic_mark_weather_radar_chans)(struct ieee80211com *ic);
	void (*ic_use_rtscts)(struct ieee80211com *ic);
	void (*ic_send_notify_chan_width_action)(struct ieee80211vap *vap, struct ieee80211_node *ni, u_int32_t width);

	void (*ic_sta_set_xmit)(int enable);
	void (*ic_set_radar)(int enable);
	void (*ic_enable_sta_dfs)(int enable);
	int (*ic_radar_detections_num)(uint32_t chan);
	void (*ic_run_dfs_action)(struct ieee80211com *ic);
	void (*ic_complete_cac)(void);
	unsigned long (*ic_get_cac_duration_jiffies)(struct ieee80211com *ic,
		struct ieee80211_channel *channel);
	int (*ic_config_channel_list)(struct ieee80211com *ic, int ic_nchans);
	void (*ic_set_11g_erp)(struct ieee80211vap *vap, int on);
	void (*ic_enable_xmit)(struct ieee80211com *ic, const char *msg);
	void (*ic_disable_xmit)(struct ieee80211com *ic, const char *msg);
	void (*ic_set_pta)(struct ieee80211vap *vap, uint32_t value);
	void (*ic_get_pta)(struct ieee80211vap *vap, uint32_t cmd, unsigned char *data);
	void (*ic_set_wlan_phy_param)(struct ieee80211vap *vap, uint32_t value);
	void (*ic_get_wlan_phy_param)(struct ieee80211vap *vap, uint32_t cmd, unsigned char *data);
	int (*ic_set_sec_cca_thr)(struct ieee80211vap *vap, unsigned char *data);
	int (*ic_get_sec_cca_thr)(struct ieee80211vap *vap, unsigned char *data);

#ifdef CONFIG_QVSP
	/* Functions at sta to apply commands from AP */
	void (*ic_vsp_strm_state_set)(struct ieee80211com *ic, uint8_t strm_state,
			const struct ieee80211_qvsp_strm_id *strm_id, struct ieee80211_qvsp_strm_dis_attr *attr);
	void (*ic_vsp_change_stamode)(struct ieee80211com *ic, uint8_t stamode);
	void (*ic_vsp_configure)(struct ieee80211com *ic, uint32_t index, uint32_t value);
	void (*ic_vsp_set)(struct ieee80211com *ic, uint32_t index, uint32_t value);
	int (*ic_vsp_get)(struct ieee80211com *ic, uint32_t index, uint32_t *value);

	/* Callbacks at AP to send commands to sta */
	void (*ic_vsp_cb_strm_ctrl)(void *token, struct ieee80211_node *node, uint8_t strm_state,
			struct ieee80211_qvsp_strm_id *strm_id, struct ieee80211_qvsp_strm_dis_attr *attr);
	void (*ic_vsp_cb_cfg)(void *token, uint32_t index, uint32_t value);

	/* Callback to stream throttler external to vsp module */
	void (*ic_vsp_cb_strm_ext_throttler)(void *token, struct ieee80211_node *node,
			uint8_t strm_state, const struct ieee80211_qvsp_strm_id *strm_id,
			struct ieee80211_qvsp_strm_dis_attr *attr, uint32_t throt_intvl);

	void (*ic_vsp_cb_logger)(void *token, uint32_t index, uint32_t value);
	void (*ic_vsp_reset)(struct ieee80211com *ic);

	struct {
		uint8_t		set;
		uint32_t	value;
	} vsp_cfg[QVSP_CFG_MAX];

	/* BA throttling for 3rd party client control */
	uint32_t ic_vsp_ba_throt_num;
#endif
	struct channel_change_event	ic_dfs_cce;
	struct channel_change_event	ic_aci_cci_cce;

	/* association ID bitmap */
	u_int32_t ic_aid_bitmap[howmany(QTN_NODE_TBL_SIZE_LHOST, 32)];

#ifdef DOT11K_PM_INTERVAL
	/* Number of pm intervals(interface with pm_interval module) */
	u_int8_t ic_pm_intervals;
#endif
	/* Compatibility fix with other vendor chipset */
	uint32_t ic_vendor_fix;
	struct ip_mac_mapping *ic_ip_mac_mapping;

	/* power management */
	uint8_t ic_pm_enabled;
	struct delayed_work pm_work;
	int ic_pm_state[QTN_PM_IOCTL_MAX];
	struct timer_list ic_pm_period_change;	/* CoC period change timer */

#if defined(QBMPS_ENABLE)
	struct bmps_tput_measure ic_bmps_tput_check;	/* for BMPS tput measurement */
#endif
	/* hold the calling task until the scan completes */
	wait_queue_head_t	ic_scan_comp;

	struct ieee80211_node *ic_node_idx_ni[QTN_NCIDX_MAX];

	/* Soc mac addr of the STB*/
#if defined(CONFIG_QTN_80211K_SUPPORT)
	u_int8_t soc_addr[IEEE80211_ADDR_LEN];
	/* Soc IP addr of the STB*/
	u_int32_t ic_soc_ipaddr;
#endif
	/* tpc query info */
	struct ieee80211_tpc_query_info ic_tpc_query_info;
	int8_t (*ic_get_local_txpow)(struct ieee80211com *ic);
	int (*ic_get_local_link_margin)(struct ieee80211_node *ni, int8_t *result);
	/* measurement request */
	struct ieee80211_global_measure_info ic_measure_info;

	int (*ic_get_shared_vap_stats)(struct ieee80211vap *vap);
	int (*ic_reset_shared_vap_stats)(struct ieee80211vap *vap);
	int (*ic_get_shared_node_stats)(struct ieee80211_node *ni);
	int (*ic_reset_shared_node_stats)(struct ieee80211_node *ni);
	void (*ic_get_dscp2ac_map)(const uint8_t vapid, uint8_t *dscp2ac);
	void (*ic_set_dscp2ac_map)(const uint8_t vapid, uint8_t *ip_dscp, uint8_t listlen, uint8_t ac);
	void (*ic_set_dscp2tid_map)(const uint8_t vapid, const uint8_t *dscp2tid);
	void (*ic_get_dscp2tid_map)(const uint8_t vapid, uint8_t *dscp2tid);

	struct timer_list	ic_ba_setup_detect;	/*timer for detecting whether it is suitable to enable/disable AMPDU*/

	int (*ic_get_cca_adjusting_status)(void);

	struct ieee80211_wowlan ic_wowlan; /* WOWLAN related information */
	uint8_t ic_extender_role;		/* Extender role */
	uint8_t ic_extender_mbs_wgt;		/* MBS RSSI weight */
	uint8_t ic_extender_rbs_wgt;		/* RBS RSSI weight */
	uint8_t ic_extender_mbs_best_rssi;	/* MBS best RSSI threshold */
	uint8_t ic_extender_rbs_best_rssi;	/* MBS best RSSI threshold */
	uint8_t ic_extender_verbose;		/* EXTENDER Debug Level */
	uint8_t ic_extender_scan_mbs_expiry;	/* Expiry of MBS scanned by RBS(AP) */
	uint8_t ic_extender_scan_mbs_mode;	/* Mode of RBS(AP) scans for MBS: normal or background scan */
	uint8_t ic_extender_mbs_rssi_margin;	/* MBS RSSI margin, used in link down detection only */
	uint8_t ic_extender_mbs_bssid[IEEE80211_ADDR_LEN];
	uint8_t ic_extender_mbs_ocac;
	uint8_t ic_extender_rbs_num;
#define QTN_EXTENDER_RSSI_MAX_COUNT	10
	uint8_t ic_extender_rssi_continue;		/* record continuous RSSI event times */
	uint8_t ic_extender_rbs_bw;		/* recorded bandwidth of RBS */
	uint8_t ic_extender_rbs_bssid[QTN_MAX_RBS_NUM][IEEE80211_ADDR_LEN];
	uint8_t ic_extender_role_loss_thres;	/* threshold of peer Extender Role IE miss */
	uint8_t	ic_extender_fast_cac;		/* Instantly complete the CAC when beacon frame received */
	uint32_t ic_extender_bgscanintvl;
	uint32_t ic_extender_scan_mbs_intvl;	/* Interval of RBS(AP) scanning for MBS. Unit: second */
	unsigned long ic_extender_mbs_detected_jiffies;

	struct timer_list ic_extender_scan_timer;	/* timer used by RBS to search MBS */
	uint32_t ic_scan_opchan_enable;

	uint32_t ic_scan_tbl_len_max;
	uint32_t ic_scan_tbl_len_srt;

	int ic_scan_results_check;
	struct timer_list ic_scan_results_expire; /* scan results expire timer */
	int hostap_wpa_state;

	/* VHT related callbacks */
	void (*ic_send_vht_grp_id_act)(struct ieee80211vap *vap, struct ieee80211_node *ni);
	struct timer_list ic_obss_timer;
	uint8_t ic_obss_scan_enable;
	uint8_t ic_obss_scan_count;
	struct ieee80211_obss_scan_ie ic_obss_ie;
	void (*ic_coex_stats_update)(struct ieee80211com *ic, uint32_t value);
	struct ieee80211_dm_factor ic_dm_factor;
	uint32_t ic_vap_default_state;	/* 1 - enabled, 0 - disabled*/
	int32_t ic_neighbor_count;	/* Neighbor APs' count */
	uint8_t ic_neighbor_cnt_sparse; /* Threshold of neighbor AP count when it's sparse */
	uint8_t ic_neighbor_cnt_dense;	/* Threshold of neighbor AP count when it's dense */

	/* tx airtime callbacks */
	uint32_t (*ic_tx_airtime)(const struct ieee80211_node *ni);
	uint32_t (*ic_tx_accum_airtime)(const struct ieee80211_node *ni);
	void     (*ic_tx_airtime_control)(struct ieee80211vap *vap, uint32_t value);
	uint32_t (*ic_rx_airtime) (const struct ieee80211_node *ni);
	uint32_t (*ic_rx_accum_airtime) (const struct ieee80211_node *ni);

	/* tx retries callbacks */
	uint32_t (*ic_tx_accum_retries)(const struct ieee80211_node *ni);

	/* mu group update callback */
	void	(*ic_mu_group_update)(struct ieee80211com *ic, struct qtn_mu_group_update_args *state);
	int (*ic_get_cca_stats)(struct net_device *dev, struct ieee80211com *ic,
				struct qtn_exp_cca_stats *cs);
	int (*ic_get_cca_trfc)(struct ieee80211com *ic);
	uint32_t (*ic_get_spdia_buf)(void **buf, uint16_t bucket);

	/* sync rx reorder window on receiving BAR
	 * 0 - disabled
	 * 1 - enabled for QTN devices only
	 * 2 - enabled for all devices
	 */
	uint8_t ic_rx_bar_sync;
	uint8_t bb_deafness_war_disable;
	struct sta_dfs_info sta_dfs_info;
#ifdef CONFIG_QHOP
	struct rbs_mbs_dfs_info rbs_mbs_dfs_info;
#endif
	uint8_t ic_20_40_coex_enable;
	/* U-Repeater params */
	uint8_t rep_max_level;
	uint8_t rep_curr_level;
	uint8_t rep_max_level_cfg;
	uint8_t rep_tweaks;

	void (*ic_update_ocac_state_ie)(struct ieee80211com *ic, uint8_t state, uint8_t param);
	uint32_t ic_allow_11b;

	/* Initial channel selection */
	struct autochan_ranking_params ic_autochan_ranking_params;
	struct ieee80211_chanset_table ic_autochan_table;
	int ic_autochan_scan_type[CHAN_SELECT_SCAN_MAX];
	int ic_autochan_last_scan_bw;
	int ic_autochan_scan_flags;
	int ic_autochan_dbg_level;
	uint32_t ic_pm_reason;
	uint32_t ic_coc_cc_reason;
	uint32_t ic_coc_move_to_ndfs;
	uint32_t ic_flags_11k;
	uint32_t ic_flags_11v;

#if defined(PLATFORM_QFDR)
	uint8_t ic_start_ap_without_scan;
	/* flags to control rejection of authentication requests */
#define QFDR_F_REJECT_AUTH	0x1
#define QFDR_F_IGNORE_PROBE_REQ	0x2
	uint8_t ic_reject_auth;
#endif

	/* DOS attack Param(To avoid unknown station deauth and disassoc frame) */
#define IEEE80211_DEFAULT_DOS_INTERVAL	1
#define IEEE80211_DEFAULT_DOS_PKT_CNT	5
	unsigned long ic_last_upkt_seen;
	uint8_t ic_dos_pkt_cnt;
	uint8_t ic_dos_max_pkt_cnt;
	uint16_t ic_dos_interval;
	uint8_t ic_cot_tweaks;
	int ic_ifreset;

#ifdef ARTSMNG_SUPPORT
	u_int8_t ic_bsstrans_token;	/* BSS Transition Request token */
#endif /* ARTSMNG_SUPPORT */

	struct timer_list ic_bsa_stats_timer; /* bsa stats timer */
	uint32_t bsa_fat_mon_started;
	/* flag to indicate if bsa module enabled airtime calc */
	uint8_t ic_bsa_en_airtime;

	/* flag to indicate if user(ioctl) enabled airtime calc */
	uint8_t ic_user_en_airtime;

#define FW_PRINT_MAX_DEFAULT_LINES 300
#define FW_PRINT_MAX_MIN_LINES 200
	uint16_t ic_fw_print_max_lines; /* Max AuC and/or MuC debug lines to print in one go */
	struct work_struct ic_scs_monitor_work;
	uint32_t roc_frequency;
	uint32_t roc_duration;
	int rssi_dbm_endian;	/* a WAR for backward compatibility */
	struct qtn_rp_info ic_rp_info;

	int (*ic_tag_default_vlan)(struct ieee80211vap *vap, uint16_t *vlanid);
#define IEEE80211_XCAC_FLAG_QRPE	(1 << 0) /* CAC requested from QRPE */
#define IEEE80211_XCAC_FLAG_EVENT_EN	(1 << 1) /* Event report at end of CAC duration */
#define IEEE80211_XCAC_FLAG_ACT_RETURN	(1 << 2) /* Return to most latest operational channel */
#define IEEE80211_XCAC_FLAG_ACT_CONT	(1 << 3) /* Continue to run CAC on the specified channel */
#define IEEE80211_XCAC_FLAG_TYPE_OCAC	(1 << 4) /* Off-channel CAC */
#define IEEE80211_XCAC_FLAG_TYPE_CAC		(1 << 5) /* Normal CAC */
#define IEEE80211_XCAC_CAC_EVENT_EN(ic) \
		((ic->ic_xcac_req_flags & IEEE80211_XCAC_FLAG_EVENT_EN) && \
		(ic->ic_xcac_req_flags & IEEE80211_XCAC_FLAG_TYPE_CAC))
#define IEEE80211_XCAC_OCAC_EVENT_EN(ic) \
		((ic->ic_xcac_req_flags & IEEE80211_XCAC_FLAG_EVENT_EN) && \
		(ic->ic_xcac_req_flags & IEEE80211_XCAC_FLAG_TYPE_OCAC))
	uint32_t ic_xcac_req_flags;
#if defined(CONFIG_QTN_BSA_SUPPORT)
	struct ieee80211_channel *ic_xcac_return_chan;
	struct ieee80211_qrpe_event_xcac_status ic_xcac_status;
#endif
	uint32_t scan_buf_max_size;
};

static __inline__ uint32_t ieee80211_pm_period_tu(const struct ieee80211com *ic)
{
	return IEEE80211_MS_TO_TU(ic->ic_pm_state[QTN_PM_PDUTY_PERIOD_MS]);
}

struct vlan_group;
struct eapolcom;
struct ieee80211_aclator;

struct ieee80211_nsparams {
	enum ieee80211_state newstate;
	int arg;
	int result;
};

#define IW_MAX_SPY 8
struct ieee80211_spy {
        u_int8_t mac[IW_MAX_SPY * IEEE80211_ADDR_LEN];
        u_int32_t ts_rssi[IW_MAX_SPY];   /* ts of rssi value from last read */
        u_int8_t thr_low;	/* 1 byte rssi value, 0 = threshold is off */
        u_int8_t thr_high;	/* 1 byte rssi value */
        u_int8_t num;
};

#define MAX_PROC_IEEE80211_SIZE 16383
#define PROC_IEEE80211_PERM 0644

struct proc_ieee80211_priv {
     int rlen;
     int max_rlen;
     char *rbuf;

     int wlen;
     int max_wlen;
     char *wbuf;
};

struct ieee80211_proc_entry {
	char *name;
	struct file_operations *fileops;
	struct proc_dir_entry *entry;
	struct ieee80211_proc_entry *next;
};

struct ieee80211_app_ie {
	u_int32_t		length;		/* buffer length */
	struct ieee80211_ie    *ie;		/* buffer containing one or more IEs */
};

#define IEEE80211_PPQ_DEF_MAX_RETRY	1
#define REPLACE_PPQ_ENTRY_HEAD(x, e) do {\
	if ((x) == NULL) {\
		(x) = (e);\
	} else {\
		(e)->next = (x);\
		(x) = (e);\
	}\
} while (0)
#define IEEE80211_PPQ_QUERY_PERIOD	10 /* unit: msec */

enum ppq_fail_reason {
	PPQ_FAIL_TIMEOUT = 1,
	PPQ_FAIL_NODELEAVE,
	PPQ_FAIL_STOP,
	PPQ_FAIL_MAX,
};

enum coex_bw_switch{
	WLAN_COEX_STATS_BW_ACTION,
	WLAN_COEX_STATS_BW_ASSOC,
	WLAN_COEX_STATS_BW_SCAN,
};
struct ieee80211_pairing_pending_entry {
	struct ieee80211_pairing_pending_entry *next;

	struct sk_buff *skb;
	struct ieee80211_node *ni;

	/* response parameters you expect */
	u_int8_t expected_category;
	u_int8_t expected_action;
	u_int8_t expected_token;

	unsigned long expire;
	unsigned long next_expire_jiffies;
	u_int32_t max_retry;
	u_int32_t retry_cnt;

	ppq_callback_success fn_success;
	ppq_callback_fail fn_fail;
};

struct ieee80211_pairing_pending_queue {
	struct ieee80211_pairing_pending_entry *next;
	spinlock_t lock;
	struct timer_list timer;
	unsigned long next_expire_jiffies;
};

void ieee80211_ppqueue_remove_with_response(struct ieee80211_pairing_pending_queue *queue,
					struct ieee80211_node *ni,
					u_int8_t category,
					u_int8_t action,
					u_int8_t token);
void ieee80211_ppqueue_remove_node_leave(struct ieee80211_pairing_pending_queue *queue,
				struct ieee80211_node *ni);
void ieee80211_ppqueue_remove_with_cat_action(struct ieee80211_pairing_pending_queue *queue,
				u_int8_t category,
				u_int8_t action);
void ieee80211_ppqueue_init(struct ieee80211vap *vap);
void ieee80211_ppqueue_deinit(struct ieee80211vap *vap);
struct sk_buff *ieee80211_ppqueue_pre_tx(struct ieee80211_node *ni,
				struct sk_buff *skb,
				u_int8_t category,
				u_int8_t action,
				u_int8_t token,
				unsigned long expire,
				ppq_callback_success fn_success,
				ppq_callback_fail fn_fail);

typedef struct _ieee80211_11k_sub_element {
	SLIST_ENTRY(_ieee80211_11k_sub_element) next;
	uint8_t sub_id;
	uint8_t data[0]; /* append differenet sub element data*/
} ieee80211_11k_sub_element ;

typedef SLIST_HEAD(,_ieee80211_11k_sub_element) ieee80211_11k_sub_element_head;

struct tdls_peer_ps_info {
	LIST_ENTRY(tdls_peer_ps_info) peer_hash;
	uint8_t peer_addr[IEEE80211_ADDR_LEN];
	uint32_t tdls_path_down_cnt;		/* Teardown counter of this TDLS link */
	uint32_t tdls_link_disabled_ints;	/* Intervals that disable TDLS link */
};

struct ieee80211_extender_wds_info {
	LIST_ENTRY(ieee80211_extender_wds_info) peer_wds_hash;
	uint8_t peer_addr[IEEE80211_ADDR_LEN];
	uint8_t role_loss;
	struct ieee80211_qtn_ext_role extender_ie;

	struct ieee80211_ie_qtn    ie_qtn_assoc;

	struct ieee80211_ie_htcap  ie_htcap;
	struct ieee80211_ie_htinfo ie_htinfo;

	struct ieee80211_ie_vhtcap ie_vhtcap;
	struct ieee80211_ie_vhtop  ie_vhtop;
};
/**
 * Interworking Information
 */
struct interworking_info {
	uint8_t an_type;                        /* access network type */
	uint8_t hessid[IEEE80211_ADDR_LEN];     /* homogeneous essid */
};

/*
 * Station profile specific to dual band mode.
 * Each band will maintain profile to be referred while band change.
 * Station profile is initialized while bootup from user configurations.
 */
struct ieee80211_sta_profile {
        int phy_mode;
        int vht;
        int bw;
        int vsp;
        int scs;
        int pmf;
};

struct bcast_pps_info {
	u_int16_t	max_bcast_pps;		/* Max broadcast packets allowed per second */
	u_int16_t	rx_bcast_counter;	/* Counter to record no. of broadcast packets processed in wireless ingress path */
	unsigned long	rx_bcast_pps_start_time;/* Timestamp in jiffies referred to, to reset the rx_bcast_counter */
	u_int16_t	tx_bcast_counter;	/* Counter to record no. of broadcast packets processed in EMAC/PCIe ingress path */
	unsigned long	tx_bcast_pps_start_time;/* Timestamp in jiffies referred to, to reset the tx_bcast_counter */
};

struct ieee80211_wps_appextinfo {
	uint8_t oui[IEEE80211_OUI_LEN];
	uint16_t len;
	uint8_t *payload;
};

#ifdef ARTSMNG_SUPPORT
struct artsmng_sta {
	uint8_t mac[IEEE80211_ADDR_LEN];
	TAILQ_ENTRY(artsmng_sta) next;	/* neighbour sta instances */
};

struct artsmng_maclist {
	uint32_t count;				/* lenght of list */
	TAILQ_HEAD(, artsmng_sta) head;	/* tail queue head of mac list */
};

struct artsmng_client {
	uint8_t	enabled;
	struct artsmng_maclist blacklist;
	spinlock_t maclist_spinlock;
	uint32_t drop_counter;
	uint8_t hide_beacon_ssid;
};
#endif /* ARTSMNG_SUPPORT */

#define IEEE80211_RX_AMSDU_THRESHOLD_CCA	500
#define IEEE80211_RX_AMSDU_THRESHOLD_PMBL	1000
#define IEEE80211_RX_AMSDU_PMBL_WF_SP		10
#define IEEE80211_RX_AMSDU_PMBL_WF_LP		100

/**
 * @extcap: extended capabilities supported by the driver,
 *      additional capabilities might be supported by userspace; these are the
 *      802.11 extended capabilities ("Extended Capabilities element") and are
 *      in the same format as in the information element. See IEEE Std
 *      802.11-2012 8.4.2.29 for the defined fields.
 * @extcap_mask: mask of the valid values
 * @extcap_len: length of the extended capabilities
 */
struct ieee80211_config_extcap {
	uint8_t extcap_len;
	uint8_t *extcap_mask;
	uint8_t *extcap;
} __packed;

#define IEEE80211_BSS_BTM_DEF_DUR		2	/* Min */
#define IEEE80211_BSS_BTM_INVALID_TERM_DELAY	0xff	/* Sec */
#define IEEE80211_BTM_DELAY_MIN			1000	/* ms */
#define IEEE80211_SEND_DISASSOC_BEFORE_DOWN	500	/* ms */
struct ieee80211_btm_term {
#define IEEE80211_VAP_BTM_IN_EXTCAP		0x01
#define IEEE80211_VAP_BTM_REQ_SEND		0x02
	uint8_t flags;
	uint8_t delay;
	uint32_t bss_dur;
	struct timer_list timer;	/* timer to terminate bss when BTM enabled */
};

struct wps_assoc_war {
	uint8_t mac[IEEE80211_ADDR_LEN];
	uint8_t active;
};

struct ieee80211vap {
	struct net_device *iv_dev;		/* associated device */
	struct net_device_stats	iv_devstats;	/* interface statistics */
	struct ifmedia iv_media;			/* interface media config */
	struct iw_statistics iv_iwstats;		/* wireless statistics block */
	struct ctl_table_header	*iv_sysctl_header;
	struct ctl_table *iv_sysctls;
	struct proc_dir_entry *iv_proc;
	struct ieee80211_proc_entry *iv_proc_entries;
	struct vlan_group *iv_vlgrp;		/* vlan group state */
        struct ieee80211_sta_profile    iv_2_4ghz_prof;	/* 2.4ghz station profile */
        struct ieee80211_sta_profile    iv_5ghz_prof;	/* 5ghz station profile */
	enum ieee80211_phy_band        iv_pref_band;   /* preferred band in dual band mode */

	TAILQ_ENTRY(ieee80211vap) iv_next;	/* list of vap instances */
	u_int iv_unit;				/* virtual AP unit */
	struct ieee80211com *iv_ic;		/* back ptr to common state */
	u_int32_t iv_debug;			/* debug msg flags */
	u_int32_t iv_debug_ext;			/* extended debug msg flags */

#define QTN_RX_AMSDU_DISABLE	0
#define QTN_RX_AMSDU_ENABLE	1
#define QTN_RX_AMSDU_DYNAMIC	2
	u_int32_t iv_rx_amsdu_enable;		/* RX AMSDU mode: 0-disable, 1-enable, 2-dynamic */
	u_int32_t iv_rx_amsdu_threshold_cca;	/* the threshold of cca intf for dynamic RX AMSDU */
	u_int32_t iv_rx_amsdu_threshold_pmbl;	/* the threshold of preamble error for dynamic RX AMSDU */
	u_int32_t iv_rx_amsdu_pmbl_wf_lp;	/* the weight factor of long preamble for calculating pmbl error */
	u_int32_t iv_rx_amsdu_pmbl_wf_sp;	/* the weight factor of short preamble for calculating pmbl error */

	struct ieee80211_stats iv_stats;	/* statistics */

	uint32_t tdls_discovery_interval;
	uint32_t tdls_node_life_cycle;
	uint8_t tdls_uapsd_indicat_wnd;		/* dot11TDLSPeerUAPSDIndicationWindow */
	uint8_t tdls_path_sel_weight;			/* Weight of path selection algorithm */
	struct timer_list tdls_rate_detect_timer;	/* TDLS rate detection timer */
	struct delayed_work tdls_rate_detect_work;	/* TDLS rate detetion work */
	struct delayed_work tdls_link_switch_work;	/* TDLS link switch queue work */
	struct timer_list tdls_node_expire_timer;	/* TDLS node expire timer */
	ATH_LIST_HEAD(, tdls_peer_ps_info) tdls_ps_hash[IEEE80211_NODE_HASHSIZE];
	spinlock_t tdls_ps_lock;
	uint8_t tdls_path_sel_prohibited;
	uint32_t tdls_over_qhop_en;
	uint32_t tdls_timeout_time;
	uint32_t tdls_training_pkt_cnt;		/* TDLS training packet count */
	uint32_t tdls_path_sel_pps_thrshld;	/* TDLS path select packet per second threshold */
	uint32_t tdls_path_sel_rate_thrshld;	/* TDLS path select minium rate threshold */
	uint32_t tdls_verbose;			/* TDLS debug info level */
	int32_t tdls_min_valid_rssi;		/* The mininum RSSI value to allow to setup TDLS link*/
	int32_t tdls_switch_ints;		/* The path switch intervals */
	uint32_t tdls_phy_rate_wgt;		/* The weight of accumulated phy rate */
	struct timer_list tdls_disassoc_timer;	/* TDLS disassoication timer */
	enum ieee80211_state tdls_pending_state;	/* VAP pending state */
	uint8_t tdls_fixed_off_chan;		/* TDLS fixed off channel */
	uint8_t tdls_fixed_off_chan_bw;		/* TDLS fixed off channel bandwidth */
	int tdls_pending_arg;			/* VAP pending argument */
	uint8_t tdls_target_chan;		/* TDLS target off channel */
	uint8_t tdls_off_chan_bw;		/* TDLS off channel bandwidth */
	uint32_t tdls_cs_time;			/* TDLS channel switch time */
	uint32_t tdls_cs_timeout;		/* TDLS channel switch timeout */
	uint32_t tdls_cs_duration;		/* TDLS off channel duration in us */
	uint8_t tdls_chan_switching;		/* TDLS channel switch in progress */
	uint8_t tdls_cs_disassoc_pending;	/* Disassociation pending to wait channel switch finish */
	struct ieee80211_node *chanswitch_node;	/* The peer node channel switch is in progress */

	int iv_monitor_nods_only;		/* in monitor mode only nods traffic */
	int iv_monitor_txf_len;			/* in monitor mode, truncate tx packets */
	int iv_monitor_phy_errors;		/* in monitor mode, accept phy errors */
	int iv_monitor_crc_errors;		/* in monitor mode, accept crc errors */

	int (*iv_newstate)(struct ieee80211vap *, enum ieee80211_state, int);
	u_int8_t iv_myaddr[IEEE80211_ADDR_LEN];
	u_int8_t iv_ds_pc_addr[IEEE80211_ADDR_LEN]; /* In STA mode, sta is connected to this PC */
	u_int32_t iv_flags;			/* state flags */
	u_int32_t iv_flags_ext;			/* extension of state flags */
	u_int32_t iv_caps;			/* capabilities */
	u_int8_t iv_ath_cap;			/* Atheros adv. capabilities */
	enum ieee80211_opmode iv_opmode;	/* operation mode */
	enum ieee80211_state iv_state;		/* state machine state */

#define IEEE80211_VAP_STATE_F_EXT_AUTH_FRAME_SENT	0x00000001
	u_int32_t iv_state_flags;		/* state machine flags */

	struct delayed_work iv_mgmt_retry_work;
	struct spinlock iv_mgmt_retry_lock;
	struct ieee80211_node *iv_mgmt_retry_ni;	/* mgmt frame retry parameter - ni */
	int iv_mgmt_retry_type;		/* mgmt frame retry parameter - type */
	int iv_mgmt_retry_arg;			/* mgmt frame retry parameter - arg */
#define IEEE80211_MAX_MGMT_RETRY		3
	u_int32_t iv_mgmt_retry_cnt;		/* mgmt frame retry count */

						/* inactivity timer settings */
	int iv_inact_init;			/* setting for new station */
	int iv_inact_auth;			/* auth but not assoc setting */
	int iv_inact_run;			/* authorized setting */
	int iv_inact_probe;			/* inactive probe time */

	int iv_des_nssid;			/* # desired ssids */
	struct ieee80211_scan_ssid iv_des_ssid[1];/* desired ssid table */
	struct ieee80211_scan_ssid_list *iv_scan_ssid; /* scan ssid list for active scan */
	u_int8_t iv_des_bssid[IEEE80211_ADDR_LEN];
	int iv_nicknamelen;			/* XXX junk */
	u_int8_t	 iv_nickname[IEEE80211_NWID_LEN];
	u_int iv_bgscanidle;			/* bg scan idle threshold */
	u_int iv_bgscanintvl;			/* bg scan min interval */
	u_int iv_scanvalid;			/* scan cache valid threshold */
	struct ieee80211_roam iv_roam;		/* sta-mode roaming state */

	u_int16_t iv_max_aid;
	u_int16_t iv_sta_assoc;			/* stations associated */
	u_int16_t iv_non_qtn_sta_assoc;		/* non-qtn stations associated */
	u_int16_t iv_sta_assoc_limit;	/* max associated stations number */
	u_int16_t iv_ps_sta;			/* stations in power save */
	u_int16_t iv_ps_pending;		/* ps sta's w/ pending frames */
	u_int16_t iv_ap_buffered;		/* data buffered on AP */
	u_int8_t *iv_tim_bitmap;		/* power-save stations w/ data*/
	u_int16_t iv_tim_len;			/* ic_tim_bitmap size (bytes) */
	u_int8_t iv_dtim_period;		/* DTIM period */
	u_int8_t iv_dtim_count;			/* DTIM count from last bcn */
						/* set/unset aid pwrsav state */
	void (*iv_set_tim)(struct ieee80211_node *, int);
	u_int8_t iv_uapsdinfo;			/* sta mode QoS Info flags */
	struct ieee80211_node *iv_bss;		/* information for this node */
	int   iv_fixed_rate;  /* 802.11 rate or -1 */
	u_int32_t iv_rtsthreshold;
	u_int16_t iv_fragthreshold;
	u_int16_t iv_txmin;			/* min tx retry count */
	u_int16_t iv_txmax;			/* max tx retry count */
	u_int16_t iv_txlifetime;		/* tx lifetime */
	int iv_inact_timer;			/* inactivity timer wait */
	void *iv_opt_ie;			/* user-specified IE's */
	u_int16_t iv_opt_ie_len;		/* length of ni_opt_ie */
	u_int8_t iv_def_txkey;			/* default/group tx key index */
	struct ieee80211_key iv_nw_keys[IEEE80211_WEP_NKID];
	int (*iv_key_alloc)(struct ieee80211vap *, const struct ieee80211_key *);
	int (*iv_key_delete)(struct ieee80211vap *, const struct ieee80211_key *,
		const u_int8_t mac[IEEE80211_ADDR_LEN]);
	int (*iv_key_set)(struct ieee80211vap *, const struct ieee80211_key *,
		const u_int8_t mac[IEEE80211_ADDR_LEN]);
	void (*iv_key_update_begin)(struct ieee80211vap *);
	void (*iv_key_update_end)(struct ieee80211vap *);

	const struct ieee80211_authenticator *iv_auth;/* authenticator glue */
	void *iv_ec;				/* private auth state */
	struct ieee80211vap *iv_xrvap;		/* pointer to XR VAP , if XR is enabled */
	u_int16_t iv_xrbcnwait;			/* SWBA count incremented until it reaches XR_BECON_FACTOR */
	struct timer_list iv_xrvapstart;	/* timer to start xr */
	u_int8_t iv_chanchange_count; 		/* 11h counter for channel change */
	int iv_mcast_rate; 			/* Multicast rate (Kbps) */

	const struct ieee80211_aclator *iv_acl;	/* aclator glue */
	void *iv_as;				/* private aclator state */

	struct ieee80211_beacon_param_t *param;		/* beacon ie arguments list */
	struct timer_list iv_swbmiss;		/* software beacon miss timer */
	u_int16_t iv_swbmiss_period;		/* software beacon miss timer period */
	struct timer_list iv_swberp;		/* software obss erp protection check timer */
	u_int16_t iv_swberp_period;             /* software obss erp protection check period */
#define IEEE80211_SWBMISS_WARNINGS 10	/* # of warnings before taking action on swbmiss */
	u_int16_t iv_swbmiss_warnings;
	int		  iv_bcn_miss_thr;			/* Beacon miss threshold */
	u_int8_t  iv_link_loss_enabled;		/* Link loss - Controlled by user. By default is on */
#if defined(QBMPS_ENABLE)
	u_int8_t  iv_swbmiss_bmps_warning;	/* swbmiss warning for STA power-saving */
	int8_t  iv_bmps_tput_high;		/* tput indication for STA power-saving */
#endif

	u_int8_t  iv_qtn_ap_cap;			    /* Quantenna flags from bcn/probe resp (station only) */
	u_int8_t  iv_qtn_flags;					/* Quantenna capability flags */
	u_int8_t  iv_is_qtn_dev;		/* 1 - is QTN dev, 0 - is not QTN dev */
#define IEEE80211_QTN_BRIDGEMODE_DISABLED	0x01
	u_int8_t  iv_qtn_options;
#define IEEE80211_QTN_NO_SSID_ASSOC_DISABLED	0x01

	struct ieee80211_nsparams iv_nsparams;	/* new state parameters for tasklet for stajoin1 */
	struct IEEE80211_TQ_STRUCT iv_stajoin1tq; /* tasklet for newstate action called from stajoin1tq */
	uint16_t iv_vapnode_idx;		/* node_idx to use for tx of non specifically targetted frames */
	uint8_t iv_ssid_group;			/* Logical group assigned for SSID, used for BSS association limits */
	struct timer_list iv_sta_fast_rejoin;
	uint8_t iv_sta_fast_rejoin_bssid[IEEE80211_ADDR_LEN];
	uint8_t wds_mac[IEEE80211_ADDR_LEN];
	struct ieee80211_key iv_wds_peer_key;

	uint16_t		iv_extdr_flags;

	struct ieee80211_spy iv_spy;            /* IWSPY support */
	unsigned int		iv_nsdone;	/* Done with scheduled newstate tasklet */
	struct ieee80211_app_ie app_ie[IEEE80211_APPIE_FRAME_TOT];
	u_int32_t		app_filter;
	enum ieee80211_11n_htmode iv_htmode;	/* state machine state */
	int32_t			iv_mcs_config;	/* MCS configuration for 11N and 11AC or -1 for autorate */
#define IEEE80211_MCS_AUTO_RATE_ENABLE		-1

	u_int32_t		iv_ht_flags;	/* HT mode mandatory flags */
	u_int32_t		iv_vht_flags;	/* VHT mode htcap flags */
	u_int8_t		iv_dsss_40MHz_ok;	/* is dsss/cck OKAY in 40MHz? */
	u_int8_t		iv_non_gf_sta_present;	/* is non GF STA present? (always 1 for 88K) */
	u_int8_t		iv_ht_anomaly_40MHz_present;	/* atleast one 20 MHz STA in 20/40 MHz BSS found */
	u_int8_t		iv_ht_mixedmode_present; /* HT Non-HT mixed mode is desired */
	u_int8_t		iv_dual_cts_required;	/* HT dual CTS protection is required */
	u_int8_t		iv_lsig_txop_ok;	/* is lsig in TXOP ok */
	u_int8_t		iv_stbc_beacon;		/* is current beacon a stbc beacon */
	u_int16_t		iv_smps_force;		/* The overridden value for SMPS for the STA. */
	u_int8_t		iv_implicit_ba;		/* Implicit block ack flags for the VAP. */
	u_int16_t		iv_ba_control;		/* Block ack control - zero indicates accept no BAs,
							   bit in position 'n' indicates accept and send BA for the given TID */
	u_int16_t		iv_ba_old_control;	/* Old block ack control */
	unsigned long		iv_blacklist_timeout;	/* MAC Filtering */
	u_int16_t		iv_max_ba_win_size;	/* Maximum window size allowable */
	u_int32_t		iv_rate_training_count; /* Rate training to new STAs - number of bursts */
	u_int32_t		iv_rate_training_burst_count; /* Rate training to new STAs - packets per burst */
	u_int8_t		iv_mc_legacy_rate;	/* Multicast legacy rates */
	u_int8_t		iv_forward_unknown_mc;	/* Forward packets even if we have no bridge entry for them */
	u_int8_t		iv_mc_to_uc;		/* Forward mcast/bcast as unicast */
#define	IEEE80211_QTN_MC_TO_UC_LEGACY	0
#define	IEEE80211_QTN_MC_TO_UC_NEVER	1
#define	IEEE80211_QTN_MC_TO_UC_ALWAYS	2		/* For WFA testing only */
	u_int8_t		iv_reliable_bcst;
	u_int8_t		iv_ap_fwd_lncb;
#if defined(CONFIG_QTN_80211K_SUPPORT)
	struct ieee80211_pairing_pending_queue	iv_ppqueue;		/* pairing pending queue */
#endif
	struct ieee80211_app_ie	qtn_pairing_ie;
	u_int32_t iv_disconn_cnt;		/* count of disconnection event */
	u_int32_t iv_disconn_seq;		/* sequence to query disconnection count */

	struct timer_list	iv_test_traffic;	/* timer to start xr */
	u_int32_t		iv_test_traffic_period;		/* Interval of periodically sending NULL packet to all associated STAs. 0 means disable */
	uint32_t iv_11ac_enabled;	/* Enable/disable 11AC feature on Topaz */
	uint8_t	iv_pri;			/* vap priority, used to calculate priority for per node per tid queue */
	uint8_t iv_pmf;                 /* VAP PMF/802.11w capability options */
	u_int8_t		iv_local_max_txpow;	/* local max transmit power, equal to regulatory max power minus power constraint */
	u_int16_t iv_disassoc_reason;
	struct ieee80211_wme_state iv_wme;	/* Per-VAP WME/WMM state for AP mode */
	spinlock_t iv_extender_wds_lock;
	ATH_LIST_HEAD(, ieee80211_extender_wds_info) iv_extender_wds_hash[IEEE80211_NODE_HASHSIZE];

	uint8_t                 iv_tx_amsdu;            /* Enable/disable A-MSDU  */
	uint8_t			iv_tx_amsdu_11n;	/* Enable/disable A-MSDU for 11n nodes */
	uint8_t			iv_tx_max_amsdu;	/* Max TX A-MSDU */

	/* 802.11u related */
	uint8_t			interworking;           /* 1 - Enabled, 0 - Disabled */
	struct interworking_info interw_info;		/* Interworking information */

	uint8_t			hs20_enable;		/* Enable/Disable HS2.0 */
	uint8_t			disable_dgaf;		/* Disable Downstream Group-Addressed Forwarding - used by HS2.0 */
	uint8_t			proxy_arp;		/* 1 - Enabled,  0- Disabled */
	uint8_t			iv_coex;
	uint8_t			allow_tkip_for_vht;	/* 1 - TKIP is allowed, 0 - TKIP is not allowed */
	uint8_t			is_block_all_assoc;	/* 1 - block, 0 - unblock */
	uint8_t			tx_ba_disable;		/* 1 - TXBA disable, 0 - TXBA permitted */
	uint8_t			rx_ba_decline;		/* 1 - RXBA decline, 0 - RXBA permitted */
	uint8_t			iv_vap_state;		/* 1 - enabled, 0 - disabled */
	uint8_t			iv_osen;		/* 1/0 - OSEN enabled/disabled */
	uint8_t			iv_block_bss;
	uint8_t			sample_sta_count;
	spinlock_t		sample_sta_lock;
	struct list_head	sample_sta_list;
	struct bcast_pps_info	bcast_pps;
	uint8_t			iv_11ac_and_11n_flag;	/* 1 - IEEE80211_AC_ONLY, 2 - IEEE80211_N_ONLY */
	uint32_t		iv_flags_ext2;
	uint16_t		iv_mdid;		/* Mobility domain id */
	uint8_t			iv_ft_over_ds;		/* ft over ds */
	uint8_t			iv_pn_validate;		/* 1 - enable PN validation, 0 - disable PN validation*/
	uint8_t			enable_iot_sts_war;
#if defined(PLATFORM_QFDR)
	struct work_struct	deactivate_work;	/* work queue to deactivate vap */
	uint16_t		iv_scan_only_freq;	/* WAR: trigger several following scans */
#define QFDR_SCAN_ONLY_FREQ_ATTEMPTS	3
	uint16_t		iv_scan_only_cnt;	/* only for specific frequency   */
#endif
#if defined(CONFIG_QTN_BSA_SUPPORT)
	uint8_t			bsa_status;		/* bsa flag 1 - BSA is enabled, 0 - BSA is disabled */
	void			*bsa_erw_sta_tbl; /* point to struct ieee80211_bsa_erw_table */
	void			*bsa_erw_nr_tbl[IEEE80211_MAX_NEIGH_BSS]; /* point to struct ieee80211_bsa_erw_nr_ie */
	uint8_t			bsa_erw_sta_tbl_inited;
	spinlock_t		bsa_erw_sta_tbl_lock;
#endif

	struct ieee80211_scan_freqs *iv_scan_freqs;	/* specific scan frequencies */
	struct ieee80211_wps_appextinfo iv_wpsappext;	/* to override app. ext. attribute of WPS IE */
#ifdef ARTSMNG_SUPPORT
	struct artsmng_client	iv_artsmng;
#endif /* ARTSMNG_SUPPORT */
	void *iv_mfr_list;

	uint32_t iv_flags_11k;
	struct ieee80211_config_extcap iv_extcap_ie;
	struct ieee80211_btm_term iv_btm_term;
	uint32_t max_idle_period_ms;
	struct ieee80211_app_ie rpe_appie[IEEE80211_APPIE_FRAME_TOT];
	uint8_t	iv_beacon_power_backoff;	/* in dB */
	uint8_t	iv_mgmt_power_backoff;		/* in dB */

	/* 0.1 sec found experimentally + 0.1 sec safe delta = 0.2 sec = 200 TU */
#define MAX_CHAN_SWITCH_DEFAULT_TIME_TU		200
#define MAX_CHAN_SWITCH_MIN_TIME_TU		100
#define MAX_CHAN_SWITCH_MAX_TIME_TU		500
#define MAX_CHAN_SWITCH_DFS_SAFE_DELTA_TU	1000
	uint32_t max_chan_switch_time;			/* Max Channel Switch Time IE value */
	struct ieee80211_scan_ssid iv_nbr_req_ssid[1];	/* neigbor report req ssid */

	struct wps_assoc_war wps_intel_war;
	uint8_t iv_3addr_mc_msdu_da_rep;
};
MALLOC_DECLARE(M_80211_VAP);

#define IEEE80211_BAND_IDX_MAX	7
struct ieee80211_band_info {
	uint8_t		band_chan_step;			/* step to next channel */
	uint8_t		band_first_chan;		/* first channel in the band */
	int16_t		band_chan_cnt;			/* channels in the band */
};

/*
 * Note: A node table lock must be acquired or IRQ disabled to maintain atomic
 * when calling this function, and must not be released until a node ref is taken
 * or the returned pointer is discarded.
 */
static inline struct ieee80211_node *ieee80211_get_wds_peer_node_noref(struct ieee80211vap *iv)
{
	struct ieee80211com *ic = iv->iv_ic;

	if (IEEE80211_NODE_IDX_VALID(iv->iv_vapnode_idx)) {
		return ic->ic_node_idx_ni[IEEE80211_NODE_IDX_UNMAP(iv->iv_vapnode_idx)];
	}
	return NULL;
}

static inline struct ieee80211_node *ieee80211_get_wds_peer_node_ref(struct ieee80211vap *iv)
{
	struct ieee80211com *ic = iv->iv_ic;
	struct ieee80211_node *ni = NULL;

	IEEE80211_NODE_LOCK_IRQ(&ic->ic_sta);
	ni = ieee80211_get_wds_peer_node_noref(iv);
	if (ni)
		ieee80211_ref_node(ni);
	IEEE80211_NODE_UNLOCK_IRQ(&ic->ic_sta);

	return ni;
}

#define IEEE80211_WILDCARD_BSSID	"\xff\xff\xff\xff\xff\xff"
#define	IEEE80211_ADDR_NULL(a1)		(memcmp(a1, "\x00\x00\x00\x00\x00\x00", \
						IEEE80211_ADDR_LEN) == 0)
#define	IEEE80211_ADDR_BCAST(a1)	(memcmp(a1, "\xff\xff\xff\xff\xff\xff", \
						IEEE80211_ADDR_LEN) == 0)
#define	IEEE80211_ADDR_EQ(a1, a2)	(memcmp(a1, a2, IEEE80211_ADDR_LEN) == 0)
#define	IEEE80211_ADDR_COPY(dst, src)	memcpy(dst, src, IEEE80211_ADDR_LEN)
#define	IEEE80211_ADDR_SET_NULL(dst)	memset(dst, 0, IEEE80211_ADDR_LEN)

/* ic_flags, iv_flags */
#define	IEEE80211_F_FF		0x00000001	/* CONF: ATH FF enabled */
#define	IEEE80211_F_TURBOP	0x00000002	/* CONF: ATH Turbo enabled*/
#define	IEEE80211_F_PROMISC	0x00000004	/* STATUS: promiscuous mode */
#define	IEEE80211_F_ALLMULTI	0x00000008	/* STATUS: all multicast mode */
/* NB: this is intentionally setup to be IEEE80211_CAPINFO_PRIVACY */
#define	IEEE80211_F_PRIVACY	0x00000010	/* CONF: privacy enabled */
#define	IEEE80211_F_PUREG	0x00000020	/* CONF: 11g w/o 11b sta's */
#define	IEEE80211_F_XRUPDATE	0x00000040	/* CONF: update beacon XR element*/
#define	IEEE80211_F_SCAN	0x00000080	/* STATUS: scanning */
#define	IEEE80211_F_CCA		0x00000100	/* CONF: beacon cca info */
#define	IEEE80211_F_SIBSS	0x00000200	/* STATUS: start IBSS */
/* NB: this is intentionally setup to be IEEE80211_CAPINFO_SHORT_SLOTTIME */
#define	IEEE80211_F_SHSLOT	0x00000400	/* STATUS: use short slot time*/
#define	IEEE80211_F_PMGTON	0x00000800	/* CONF: Power mgmt enable */
#define	IEEE80211_F_DESBSSID	0x00001000	/* CONF: des_bssid is set */
#define	IEEE80211_F_WME		0x00002000	/* CONF: enable WME use */
#define	IEEE80211_F_BGSCAN	0x00004000	/* CONF: bg scan enabled */
#define	IEEE80211_F_SWRETRY	0x00008000	/* CONF: sw tx retry enabled */
#define IEEE80211_F_TXPOW_FIXED	0x00010000	/* TX Power: fixed rate */
#define	IEEE80211_F_IBSSON	0x00020000	/* CONF: IBSS creation enable */
#define	IEEE80211_F_SHPREAMBLE	0x00040000	/* STATUS: use short preamble */
#define	IEEE80211_F_DATAPAD	0x00080000	/* CONF: do alignment pad */
#define	IEEE80211_F_USEPROT	0x00100000	/* STATUS: protection enabled */
#define	IEEE80211_F_USEBARKER	0x00200000	/* STATUS: use barker preamble*/
#define	IEEE80211_F_TIMUPDATE	0x00400000	/* STATUS: update beacon tim */
#define	IEEE80211_F_WPA1	0x00800000	/* CONF: WPA enabled */
#define	IEEE80211_F_WPA2	0x01000000	/* CONF: WPA2 enabled */
#define	IEEE80211_F_WPA		0x01800000	/* CONF: WPA/WPA2 enabled */
#define	IEEE80211_F_DROPUNENC	0x02000000	/* CONF: drop unencrypted */
#define	IEEE80211_F_COUNTERM	0x04000000	/* CONF: TKIP countermeasures */
#define	IEEE80211_F_HIDESSID	0x08000000	/* CONF: hide SSID in beacon */
#define IEEE80211_F_NOBRIDGE    0x10000000	/* CONF: disable internal bridge */

#define	IEEE80211_F_WMEUPDATE	0x20000000	/* STATUS: update beacon wme */
#define IEEE80211_F_DOTH	0x40000000	/* enable 11.h */
#define IEEE80211_F_CHANSWITCH	0x80000000	/* force chanswitch */

/* ic_flags_ext, iv_flags_ext */
#define	IEEE80211_FEXT_WDS	0x00000001	/* CONF: 4 addr allowed */
#define IEEE80211_FEXT_COUNTRYIE 0x00000002	/* CONF: enable country IE */
#define IEEE80211_FEXT_SCAN_PENDING 0x00000004	/* STATE: scan pending */
#define	IEEE80211_FEXT_BGSCAN	0x00000008	/* STATE: enable full bgscan completion */
#define IEEE80211_FEXT_UAPSD	0x00000010	/* CONF: enable U-APSD */
#define IEEE80211_FEXT_SLEEP	0x00000020	/* STATUS: sleeping */
#define IEEE80211_FEXT_EOSPDROP	0x00000040	/* drop uapsd EOSP frames for test */
#define	IEEE80211_FEXT_MARKDFS	0x00000080	/* Enable marking of dfs interference */
#define IEEE80211_FEXT_REGCLASS	0x00000100	/* CONF: send regclassids in country ie */
#define IEEE80211_FEXT_ERPUPDATE 0x00000200	/* STATUS: update ERP element */
#define IEEE80211_FEXT_SWBMISS 0x00000400	/* CONF: use software beacon timer */
#define IEEE80211_FEXT_DROPUNENC_EAPOL 0x00000800      /* CONF: drop unencrypted eapol frames */
#define IEEE80211_FEXT_APPIE_UPDATE 0x00001000	/* STATE: beacon APP IE updated */
#define IEEE80211_FEXT_11N_PROTECT	0x00002000	/* Enable 11n protection */
#define IEEE80211_FEXT_AMPDU		0x00004000	/* CONF: A-MPDU supported */
#define IEEE80211_FEXT_AMSDU		0x00008000	/* CONF: A-MSDU supported */
#define IEEE80211_FEXT_USEHT20		0x00010000	/* use HT20 channel in 20/40 mode*/
#define	IEEE80211_FEXT_PURE11N		0x00020000	/* CONF: 11n w/o non ht sta's */
#define	IEEE80211_FEXT_REPEATER		0x00040000	/* CONF: Work as a repeater */
#define IEEE80211_FEXT_SCAN_20		0x00080000	/* Temporarily use 20MHz channel when changing channel */
#define IEEE80211_FEXT_DFS_FAST_SWITCH	0x00100000	/* on detection of radar, select a non-DFS channel and switch immediately */
#define IEEE80211_FEXT_SCAN_NO_DFS	0x00200000	/* on detection of radar, only scan non-DFS channels */
#define IEEE80211_FEXT_SCAN_FAST_REASS	0x00400000	/* Fast reassociation after power up
							   (remember the previous channel) */
#define IEEE80211_FEXT_TPC		0x00800000	/* TPC feature enable or disable bit */
#define IEEE80211_FEXT_TDLS_PROHIB	0x01000000	/* STATION prohibit TDLS function */
#define IEEE80211_FEXT_TDLS_CS_PROHIB	0x02000000	/* TDLS channel switch is prohibited */
#define IEEE80211_FEXT_TDLS_CS_PASSIVE	0x04000000	/* Passive TDLS channel switch */
#define	IEEE80211_FEXT_AP_TDLS_PROHIB	0x08000000	/* AP prohibit TDLS function */
#define IEEE80211_FEXT_SPECIFIC_SCAN	0x10000000	/* Just perform specific SSID scan */
#define IEEE80211_FEXT_SCAN_40		0x20000000	/* Temporarily use 40MHz channel when changing channel */
#define IEEE80211_FEXT_24GVHT		0x40000000	/* VHT support(256-QAM) on 2.4G band  */
#define IEEE80211_FEXT_BG_PROTECT	0x80000000	/* 802.11bg protect */
#define IEEE80211_FEXT_TDLS_DISABLED	(IEEE80211_FEXT_AP_TDLS_PROHIB | IEEE80211_FEXT_TDLS_PROHIB)

/* ic_flags_ext2, iv_flags_ext2 */
#define	IEEE80211_FEXT2_DYNAMIC_REGION_UPDATE	0x00000001	/* CONF: For dynamic update of region/country code */
#define IEEE80211_FEXT2_TXBF_SUPPORT_IN_5G	0x00000002
#define IEEE80211_FEXT2_BGSCAN_TURNOFF_RF	0x00000004
#define IEEE80211_FEXT2_SYNC_CONFIG		0x00000008
#define IEEE80211_FEXT2_CFG_4ADDR		0x00000010	/* use 4-addr headers */
#define IEEE80211_FEXT2_CFG_4ADDR_AMSDU		0x00000020	/* use 4-addr headers for A-MSDUs */
#define IEEE80211_FEXT2_WPS_ACTIVE		0x00000040	/* WPS active state */
#define IEEE80211_FEXT2_TAG_EAPOL		0x00000080	/* Add VLAN tags to EAP if needed */
/*
 * 802.11 state machine is controlled externally, drivers should not do
 * any state transitions
 */
#define IEEE80211_FEXT2_NO_80211_SM		0x00000100
#define IEEE80211_FEXT2_BW_CHANGING		0x00000200      /* BW change is ongoing */
#define IEEE80211_FEXT2_SCH_BSS_SUPPRESS	0x00000400	/* BSS priority based tx SP sch */
#define IEEE80211_FEXT2_SCH_TID_SUPPRESS	0x00000800	/* TID priority based tx SP sch */

#define IEEE80211_CFG_4ADDR_ENABLED(_vap) \
	(!!((_vap)->iv_flags_ext2 & (IEEE80211_FEXT2_CFG_4ADDR | IEEE80211_FEXT2_CFG_4ADDR_AMSDU)))
#define IEEE80211_CFG_4ADDR_AMSDU_ENABLED(_vap) \
	(!!((_vap)->iv_flags_ext2 & IEEE80211_FEXT2_CFG_4ADDR_AMSDU))

#define IEEE80211_11K_NEIGHREPORT	0x00000001	/* Neighbor Report - 802.11k */
#define IEEE80211_11K_APP_NEIGHREPORT	0x00000002      /* APPs Neighbor Report Config */

#define IEEE80211_COM_NEIGHREPORT_ENABLE(_vap)	((_vap)->iv_flags_11k |= IEEE80211_11K_NEIGHREPORT)
#define IEEE80211_COM_NEIGHREPORT_DISABLE(_vap)	((_vap)->iv_flags_11k &= ~IEEE80211_11K_NEIGHREPORT)
#define IEEE80211_COM_NEIGHREPORT_ENABLED(_vap)	((_vap)->iv_flags_11k & IEEE80211_11K_NEIGHREPORT)

/* ic 11v flags */
#define IEEE80211_11V_BTM		0x00000001	/* BSS transition management - 802.11v - WNM */

#define IEEE80211_COM_BTM_ENABLE(_ic)		((_ic)->ic_flags_11v |= IEEE80211_11V_BTM)
#define IEEE80211_COM_BTM_DISABLE(_ic)		((_ic)->ic_flags_11v &= ~IEEE80211_11V_BTM)
#define IEEE80211_COM_BTM_ENABLED(_ic)		((_ic)->ic_flags_11v & IEEE80211_11V_BTM)

/* ic_flags_qtn */
/* ic_flags_qtn */
#define IEEE80211_QTN_BCM_WAR		0x00000001	/* Workaround: rx odd length last aggregate */
#define IEEE80211_QTN_RADAR_SCAN_START	0x00000002	/* Radar: Start scan after non-occupancy timer expiry */
#define IEEE80211_QTN_PRINT_CH_INUSE	0x00000004	/* Enable printing of channels in Use. */
#define IEEE80211_QTN_BGSCAN		0x00000008	/* Quantenna background scanning */
#define IEEE80211_QTN_MONITOR		0x00000010	/* Quantenna sniffer mode */
#define IEEE80211_QTN_BMPS		0x00000020	/* Quantenna STA BMPS (power-saving) mode */
#define IEEE80211_QTN_SAMP_CHAN		0x00000040	/* Quantenna SCS sample channel */
#define IEEE80211_QTN_TXCTL		0x00000080	/* Quantenna robust_csa txctl indication */
#define IEEE80211_QTN_OCS_NAC_MON	0x00000100	/* Quantenna off-chan sample for NAC MON */

static inline int
ieee80211_is_dev_running(struct net_device *dev)
{
	if ((dev->flags & (IFF_RUNNING | IFF_UP)) == (IFF_RUNNING | IFF_UP))
		return 1;
	return 0;
}

static inline int
ieee80211_is_repeater(struct ieee80211com *ic)
{
	if (!(ic->ic_flags_ext & IEEE80211_FEXT_REPEATER))
		return 0;

	return 1;
}

static inline int
ieee80211_is_repeater_feature_enabled(struct ieee80211com *ic, uint8_t rep_feature)
{
	if (!ieee80211_is_repeater(ic))
		return 0;

	return !!(ic->rep_tweaks & rep_feature);
}

static inline int
ieee80211_is_repeater_ap(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	if (ieee80211_is_repeater(ic) && (vap->iv_opmode == IEEE80211_M_HOSTAP))
		return 1;

	return 0;
}

static inline int
ieee80211_is_repeater_ap_up(struct ieee80211com *ic)
{
	struct ieee80211vap *tmp_vap;

	if (!ieee80211_is_repeater(ic))
		return 0;

	TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
		if (tmp_vap->iv_opmode == IEEE80211_M_HOSTAP &&
			ieee80211_is_dev_running(tmp_vap->iv_dev))
			return 1;
	}

	return 0;
}

static inline int
ieee80211_is_repeater_sta(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	if (ieee80211_is_repeater(ic) && (vap->iv_opmode == IEEE80211_M_STA))
		return 1;

	return 0;
}

static inline int
ieee80211_is_repeater_associated(struct ieee80211com *ic)
{
	struct ieee80211vap *vap;

	if (!ieee80211_is_repeater(ic))
		return 0;

	/* 1st VAP is for STA interface */
	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap && vap->iv_state == IEEE80211_S_RUN)
		return 1;

	return 0;
}

static inline int
ieee80211_is_scanning(struct ieee80211com *ic)
{
	return ((ic->ic_flags & IEEE80211_F_SCAN) ||
		(ic->ic_flags_qtn & IEEE80211_QTN_BGSCAN));
}

#define IEEE80211_COM_UAPSD_ENABLE(_ic)		((_ic)->ic_flags_ext |= IEEE80211_FEXT_UAPSD)
#define IEEE80211_COM_UAPSD_DISABLE(_ic)	((_ic)->ic_flags_ext &= ~IEEE80211_FEXT_UAPSD)
#define IEEE80211_COM_UAPSD_ENABLED(_ic)	((_ic)->ic_flags_ext & IEEE80211_FEXT_UAPSD)
#define IEEE80211_COM_GOTOSLEEP(_ic)		((_ic)->ic_flags_ext |= IEEE80211_FEXT_GOTOSLEEP)
#define IEEE80211_COM_WAKEUP(_ic)		((_ic)->ic_flags_ext &= ~IEEE80211_FEXT_SLEEP)
#define IEEE80211_COM_IS_SLEEPING(_ic)		((_ic)->ic_flags_ext & IEEE80211_FEXT_SLEEP)

#define IEEE80211_COM_WDS_IS_NONE(_ic)		((_ic)->ic_extender_role == IEEE80211_EXTENDER_ROLE_NONE)
#define IEEE80211_COM_WDS_IS_RBS(_ic)		((_ic)->ic_extender_role == IEEE80211_EXTENDER_ROLE_RBS)
#define IEEE80211_COM_WDS_IS_MBS(_ic)		((_ic)->ic_extender_role == IEEE80211_EXTENDER_ROLE_MBS)

#define IEEE80211_BG_PROTECT_ENABLED(_ic)	((_ic)->ic_flags_ext & IEEE80211_FEXT_BG_PROTECT)
#define IEEE80211_11N_PROTECT_ENABLED(_ic)	((_ic)->ic_flags_ext & IEEE80211_FEXT_11N_PROTECT)

#define IEEE80211_IS_TKIP_ALLOWED(_ic)          (WPA_TKIP_SUPPORT || ((_ic)->ic_country_code != CTRY_UNITED_STATES))

#define IEEE80211_VAP_UAPSD_ENABLE(_v)	((_v)->iv_flags_ext |= IEEE80211_FEXT_UAPSD)
#define IEEE80211_VAP_UAPSD_DISABLE(_v)	((_v)->iv_flags_ext &= ~IEEE80211_FEXT_UAPSD)
#define IEEE80211_VAP_UAPSD_ENABLED(_v)	((_v)->iv_flags_ext & IEEE80211_FEXT_UAPSD)
#define IEEE80211_VAP_GOTOSLEEP(_v)	((_v)->iv_flags_ext |= IEEE80211_FEXT_SLEEP)
#define IEEE80211_VAP_WAKEUP(_v)	((_v)->iv_flags_ext &= ~IEEE80211_FEXT_SLEEP)
#define IEEE80211_VAP_IS_SLEEPING(_v)	((_v)->iv_flags_ext & IEEE80211_FEXT_SLEEP)
#define IEEE80211_VAP_EOSPDROP_ENABLE(_v)  ((_v)->iv_flags_ext |= IEEE80211_FEXT_EOSPDROP)
#define IEEE80211_VAP_EOSPDROP_DISABLE(_v) ((_v)->iv_flags_ext &= ~IEEE80211_FEXT_EOSPDROP)
#define IEEE80211_VAP_EOSPDROP_ENABLED(_v) ((_v)->iv_flags_ext & IEEE80211_FEXT_EOSPDROP)
#define IEEE80211_VAP_DROPUNENC_EAPOL_ENABLE(_v)  ((_v)->iv_flags_ext |= IEEE80211_FEXT_DROPUNENC_EAPOL)
#define IEEE80211_VAP_DROPUNENC_EAPOL_DISABLE(_v) ((_v)->iv_flags_ext &= ~IEEE80211_FEXT_DROPUNENC_EAPOL)
#define IEEE80211_VAP_DROPUNENC_EAPOL(_v) ((_v)->iv_flags_ext & IEEE80211_FEXT_DROPUNENC_EAPOL)

#define IEEE80211_VAP_WDS_ANY(_v)	((_v)->iv_opmode == IEEE80211_M_WDS)
#define IEEE80211_VAP_WDS_IS_RBS(_v)	(((_v)->iv_opmode == IEEE80211_M_WDS) && \
					(((_v)->iv_extdr_flags & IEEE80211_QTN_WDS_MASK) == IEEE80211_QTN_WDS_RBS))
#define IEEE80211_VAP_WDS_IS_MBS(_v)	(((_v)->iv_opmode == IEEE80211_M_WDS) && \
					(((_v)->iv_extdr_flags & IEEE80211_QTN_WDS_MASK) == IEEE80211_QTN_WDS_MBS))
#define IEEE80211_VAP_WDS_BASIC(_v)   (((_v)->iv_opmode == IEEE80211_M_WDS) && \
					(((_v)->iv_extdr_flags & IEEE80211_QTN_WDS_MASK) == IEEE80211_QTN_WDS_ONLY))

static __inline__ uint16_t ieee80211_extdr_get_flags(uint32_t comb)
{
	return (comb & IEEE80211_QTN_EXTDR_ALLMASK);
}

static __inline__ uint16_t ieee80211_extdr_get_mask(uint32_t comb)
{
	return ((comb >> IEEE80211_QTN_EXTDR_MASK_SHIFT) & IEEE80211_QTN_EXTDR_ALLMASK);
}

static inline void
ieee80211_vap_set_extdr_flags(struct ieee80211vap *vap, uint32_t etdr_comb)
{
	int flags;
	int mask;

	flags = ieee80211_extdr_get_flags(etdr_comb);
	mask = ieee80211_extdr_get_mask(etdr_comb);

	vap->iv_extdr_flags &= ~mask;
	vap->iv_extdr_flags |= flags;
}

#define	IEEE80211_VAP_WDS_SET_RBS(_v)	do {(_v)->iv_extdr_flags &= ~IEEE80211_QTN_WDS_MASK; \
					     (_v)->iv_extdr_flags |= IEEE80211_QTN_WDS_RBS ;} while(0)
#define	IEEE80211_VAP_WDS_SET_MBS(_v)	do {(_v)->iv_extdr_flags &= ~IEEE80211_QTN_WDS_MASK; \
					     (_v)->iv_extdr_flags |= IEEE80211_QTN_WDS_MBS;} while(0)
#define IEEE80211_VAP_WDS_SET_NONE(_v)	do {(_v)->iv_extdr_flags &= ~IEEE80211_QTN_WDS_MASK; \
					     (_v)->iv_extdr_flags |= IEEE80211_QTN_WDS_ONLY;} while(0)

/* ic_caps */
#define	IEEE80211_C_WEP		0x00000001	/* CAPABILITY: WEP available */
#define	IEEE80211_C_TKIP	0x00000002	/* CAPABILITY: TKIP available */
#define	IEEE80211_C_AES		0x00000004	/* CAPABILITY: AES OCB avail */
#define	IEEE80211_C_AES_CCM	0x00000008	/* CAPABILITY: AES CCM avail */
#define	IEEE80211_C_11N		0x00000010	/* CAPABILITY: 11n HT available */
#define	IEEE80211_C_CKIP	0x00000020	/* CAPABILITY: CKIP available */
#define	IEEE80211_C_FF		0x00000040	/* CAPABILITY: ATH FF avail */
#define	IEEE80211_C_TURBOP	0x00000080	/* CAPABILITY: ATH Turbo avail*/
#define	IEEE80211_C_IBSS	0x00000100	/* CAPABILITY: IBSS available */
#define	IEEE80211_C_PMGT	0x00000200	/* CAPABILITY: Power mgmt */
#define	IEEE80211_C_HOSTAP	0x00000400	/* CAPABILITY: HOSTAP avail */
#define	IEEE80211_C_AHDEMO	0x00000800	/* CAPABILITY: Old Adhoc Demo */
#define	IEEE80211_C_SWRETRY	0x00001000	/* CAPABILITY: sw tx retry */
#define	IEEE80211_C_TXPMGT	0x00002000	/* CAPABILITY: tx power mgmt */
#define	IEEE80211_C_SHSLOT	0x00004000	/* CAPABILITY: short slottime */
#define	IEEE80211_C_SHPREAMBLE	0x00008000	/* CAPABILITY: short preamble */
#define	IEEE80211_C_MONITOR	0x00010000	/* CAPABILITY: monitor mode */
#define	IEEE80211_C_TKIPMIC	0x00020000	/* CAPABILITY: TKIP MIC avail */
#define	IEEE80211_C_WPA1	0x00800000	/* CAPABILITY: WPA1 avail */
#define	IEEE80211_C_WPA2	0x01000000	/* CAPABILITY: WPA2 avail */
#define	IEEE80211_C_WPA		0x01800000	/* CAPABILITY: WPA1+WPA2 avail*/
#define	IEEE80211_C_BURST	0x02000000	/* CAPABILITY: frame bursting */
#define	IEEE80211_C_WME		0x04000000	/* CAPABILITY: WME avail */
#define	IEEE80211_C_WDS		0x08000000	/* CAPABILITY: 4-addr support */
#define IEEE80211_C_WME_TKIPMIC	0x10000000	/* CAPABILITY: TKIP MIC for QoS frame */
#define	IEEE80211_C_BGSCAN	0x20000000	/* CAPABILITY: bg scanning */
#define	IEEE80211_C_UAPSD	0x40000000	/* CAPABILITY: UAPSD */
#define	IEEE80211_C_UEQM	0x80000000	/* CAPABILITY: Unequal Modulation */
/* XXX protection/barker? */

#define	IEEE80211_C_CRYPTO	0x0000002f	/* CAPABILITY: crypto alg's */

/* HT flags */
#define IEEE80211_HTF_CBW_40MHZ_ONLY	0x00000001
#define IEEE80211_HTF_SHORTGI20_ONLY	0x00000002
#define IEEE80211_HTF_SHORTGI40_ONLY	0x00000004
#define IEEE80211_HTF_GF_MODE_ONLY		0x00000008
#define IEEE80211_HTF_NSS_2_ONLY		0x00000010
#define IEEE80211_HTF_TXSTBC_ONLY		0x00000020
#define IEEE80211_HTF_RXSTBC_ONLY		0x00000040
#define IEEE80211_HTF_DSSS_40MHZ_ONLY	0x00000080
#define IEEE80211_HTF_PSMP_SUPPORT_ONLY	0x00000100
#define IEEE80211_HTF_LSIG_TXOP_ONLY	0x00000200
#define IEEE80211_HTF_HTINFOUPDATE		0x00000400
#define IEEE80211_HTF_SHORTGI_ENABLED	0x00000800
#define IEEE80211_HTF_LDPC_ENABLED	0x00001000
#define IEEE80211_HTF_LDPC_ALLOW_NON_QTN	0x00002000
#define IEEE80211_HTF_STBC_ENABLED	0x00004000

/* Key management Capabilities */
#define WPA_KEY_MGMT_IEEE8021X BIT(0)
#define WPA_KEY_MGMT_PSK BIT(1)
#define WPA_KEY_MGMT_NONE BIT(2)
#define WPA_KEY_MGMT_IEEE8021X_NO_WPA BIT(3)
#define WPA_KEY_MGMT_WPA_NONE BIT(4)
#define WPA_KEY_MGMT_FT_IEEE8021X BIT(5)
#define WPA_KEY_MGMT_FT_PSK BIT(6)
#define WPA_KEY_MGMT_IEEE8021X_SHA256 BIT(7)
#define WPA_KEY_MGMT_PSK_SHA256 BIT(8)
#define WPA_KEY_MGMT_WPS BIT(9)
#define WPA_KEY_MGMT_SAE BIT(10)
#define WPA_KEY_MGMT_FT_SAE BIT(11)
#define WPA_KEY_MGMT_OWE BIT(22)
#define WPA_KEY_MGMT_DPP BIT(23)

/* Atheros ABOLT definitions */
#define IEEE80211_ABOLT_TURBO_G		0x01	/* Legacy Turbo G */
#define IEEE80211_ABOLT_TURBO_PRIME	0x02	/* Turbo Prime */
#define IEEE80211_ABOLT_COMPRESSION	0x04	/* Compression */
#define IEEE80211_ABOLT_FAST_FRAME	0x08	/* Fast Frames */
#define IEEE80211_ABOLT_BURST		0x10	/* Bursting */
#define IEEE80211_ABOLT_WME_ELE		0x20	/* WME based cwmin/max/burst tuning */
#define IEEE80211_ABOLT_XR		0x40	/* XR */
#define IEEE80211_ABOLT_AR		0x80	/* AR switches out based on adjaced non-turbo traffic */

/* Atheros Advanced Capabilities ABOLT definition */
#define IEEE80211_ABOLT_ADVCAP	(IEEE80211_ABOLT_TURBO_PRIME | \
				 IEEE80211_ABOLT_COMPRESSION | \
				 IEEE80211_ABOLT_FAST_FRAME | \
				 IEEE80211_ABOLT_XR | \
				 IEEE80211_ABOLT_AR | \
				 IEEE80211_ABOLT_BURST | \
				 IEEE80211_ABOLT_WME_ELE)

/* check if a capability was negotiated for use */
#define	IEEE80211_ATH_CAP(vap, ni, bit) \
	((ni)->ni_ath_flags & (vap)->iv_ath_cap & (bit))

/* flags to VAP create function */
#define IEEE80211_VAP_XR		0x10000	/* create a XR VAP without registering net device with OS */

int ieee80211_ifattach(struct ieee80211com *);
void ieee80211_ifdetach(struct ieee80211com *);
int ieee80211_vap_setup(struct ieee80211com *, struct net_device *,
	const char *, int, int, int);
int ieee80211_vap_attach(struct ieee80211vap *, ifm_change_cb_t, ifm_stat_cb_t);
void ieee80211_vap_detach(struct ieee80211vap *);
void ieee80211_vap_detach_late(struct ieee80211vap *);
void ieee80211_announce(struct ieee80211com *);
void ieee80211_announce_channels(struct ieee80211com *);
int ieee80211_media_change(void *);
void ieee80211_media_status(void *, struct ifmediareq *);
int ieee80211_rate2media(struct ieee80211com*, int, enum ieee80211_phymode);
int ieee80211_media2rate(int);
int ieee80211_mcs2media(struct ieee80211com*, int, enum ieee80211_phymode);
int ieee80211_media2mcs(int);
int ieee80211_mcs2rate(int mcs, int mode, int sgi, int vht);
int ieee80211_rate2mcs(int rate, int mode, int sgi);
u_int ieee80211_get_chanflags(enum ieee80211_phymode mode);
u_int ieee80211_mhz2ieee(u_int, u_int);
u_int ieee80211_chan2ieee(struct ieee80211com *,	const struct ieee80211_channel *);
u_int ieee80211_ieee2mhz(u_int, u_int);
u_int ieee80211_get_center_chan(const struct ieee80211_channel *chan, int bw);
struct ieee80211_channel *ieee80211_find_channel(struct ieee80211com *, int, int);
int ieee80211_setmode(struct ieee80211com *, enum ieee80211_phymode);
void ieee80211_reset_erp(struct ieee80211com *, enum ieee80211_phymode);
enum ieee80211_phymode ieee80211_chan2mode(const struct ieee80211_channel *);
int ieee80211_country_string_to_countryid( const char *input_str, u_int16_t *p_iso_code );
int ieee80211_countryid_to_country_string( const u_int16_t iso_code, char *output_str );
int ieee80211_region_to_operating_class(struct ieee80211com *ic, char *region_str);
void ieee80211_get_prichan_list_by_operating_class(struct ieee80211com *ic, int bw,
			uint8_t *chan_list, uint32_t flag);
int ieee80211_get_current_operating_class(uint16_t iso_code, int chan, int bw);
int ieee80211_build_country_string_env(struct ieee80211vap *vap, const uint8_t value);
void ieee80211_build_countryie(struct ieee80211com *);
int ieee80211_media_setup(struct ieee80211com *, struct ifmedia *, u_int32_t,
	ifm_change_cb_t, ifm_stat_cb_t);
void ieee80211_param_to_qdrv(struct ieee80211vap *vap,
	int param, int value, unsigned char *data, int len);
void ieee80211_param_from_qdrv(struct ieee80211vap *vap,
	int param, int *value, unsigned char *data, int *len);
int ieee80211_pause_scs_comparison_timer(struct ieee80211com *ic, int interval);
int ieee80211_enable_scs(struct ieee80211vap *vap, uint32_t arg);
int ieee80211_param_scs_set(struct net_device *dev, struct ieee80211vap *vap, u_int32_t value);
int ieee80211_param_ocac_set(struct net_device *dev, struct ieee80211vap *vap, u_int32_t value);
void get_node_info(void *s, struct ieee80211_node *ni);
void get_node_assoc_state(void *s, struct ieee80211_node *ni);
void get_node_ver(void *s, struct ieee80211_node *ni);
void get_node_capabilities(void *s, struct ieee80211_node *ni);
void get_node_tx_stats(void *s, struct ieee80211_node *ni);
void get_node_rx_stats(void *s, struct ieee80211_node *ni);
void ieee80211_update_node_assoc_qual(struct ieee80211_node *ni);
u_int8_t ieee80211_bridgemode_set(struct ieee80211vap *vap, u_int8_t config_change);
void ieee80211_channel_switch_post(struct ieee80211com *ic);
void ieee80211_eap_output(struct net_device *dev, const void *eap_msg, int eap_msg_len);
int ieee80211_blacklist_check(struct ieee80211_node *ni);
void ieee80211_remove_node_blacklist_timeout(struct ieee80211_node *ni);
int ieee80211_pwr_adjust(struct ieee80211vap *vap, int rxgain_state);
void ieee80211_pm_queue_work_custom(struct ieee80211com *ic, unsigned long delay);
void ieee80211_pm_queue_work(struct ieee80211com *ic);
void ieee80211_beacon_interval_set(struct ieee80211com *ic, int value);
void ieee80211_ocac_update_params(struct ieee80211com *ic, const char *region);

void
ieee80211_set_recv_ctrlpkts(struct ieee80211vap *vap);
struct ieee80211_channel * findchannel(struct ieee80211com *ic, int ieee, int mode);
struct ieee80211_channel * findchannel_any(struct ieee80211com *ic, int ieee, int prefer_mode);
struct ieee80211_channel* ieee80211_chk_update_pri_chan(struct ieee80211com *ic, struct ieee80211vap *vap,
		struct ieee80211_channel *chan, uint32_t rank_by_pwr, const char* caller, int print_warning);
void ieee80211_scs_metric_update_timestamps(struct ap_state *as);
void ieee80211_scs_update_tdls_stats(struct ieee80211com *ic, struct ieee80211_tdls_scs_stats *scs_stats);
void ieee80211_scs_free_node_tdls_stats(struct ieee80211com *ic, struct ieee80211_node *ni);
void ieee80211_scs_free_tdls_stats_list(struct ieee80211com *ic);
int ieee80211_scs_clean_stats(struct ieee80211com *ic, uint32_t level, int clear_dfs_reentry);
void ieee80211_scs_node_clean_stats(void *s, struct ieee80211_node *ni);
void ieee80211_scs_show_ranking_stats(struct ieee80211com *ic, int show_input, int show_result);
void ieee80211_show_initial_ranking_stats(struct ieee80211com *ic);
void ieee80211_scs_update_ranking_table_by_scan(struct ieee80211com *ic);
void ieee80211_scs_adjust_cca_threshold(struct ieee80211com *ic);
int ieee80211_scs_get_scaled_scan_info(struct ieee80211com *ic, int chan_ieee,
		struct qtn_scs_scan_info *p_scan_info);
void ieee80211_scs_scale_offchan_data(struct ieee80211com *ic, struct qtn_scs_oc_info *scs_oc_info);
int ieee80211_dual_sec_chan_supported(struct ieee80211com *ic, struct ieee80211_channel *chan);
void ieee80211_update_sec_chan_offset(struct ieee80211_channel *chan, int offset);
int ieee80211_get_ap_sec_chan_offset(const struct ieee80211_scan_entry *se);
int ieee80211_get_bw(struct ieee80211com *ic);
int ieee80211_get_csa_bw(struct ieee80211com *ic);
int ieee80211_get_cap_bw(struct ieee80211com *ic);
int ieee80211_get_max_ap_bw(const struct ieee80211_scan_entry *se);
int ieee80211_get_max_node_bw(struct ieee80211_node *ni);
int ieee80211_get_max_system_bw(struct ieee80211com *ic);
int ieee80211_get_max_channel_bw(struct ieee80211com *ic, int channel);
int ieee80211_get_max_bw(struct ieee80211vap *vap, struct ieee80211_node *ni, uint32_t chan);
void ieee80211_update_bw_capa(struct ieee80211vap *vap, int bw);
void ieee80211_wireless_update_all_nodes_bw(struct ieee80211com *ic);
void ieee80211_change_bw(struct ieee80211vap *vap, int bw, int delay_chan_switch);
void ieee80211_change_oper_bw(struct ieee80211vap *vap, int bw);
void ieee80211_indicate_bw_change(struct ieee80211com *ic, int bw);
void ieee80211_update_nodes_bw(struct ieee80211com *ic, int bw);
int ieee80211_get_mu_grp(struct ieee80211com *ic, struct qtn_mu_grp_args *mu_grp_tbl);
int ieee80211_find_sec_chan(struct ieee80211_channel *chan);
int ieee80211_find_sec40_chan(struct ieee80211_channel *chani, int sec40_index);
int ieee80211_find_sec40u_chan(struct ieee80211_channel *chan);
int ieee80211_find_sec40l_chan(struct ieee80211_channel *chan);
int ieee80211_find_sec_chan_by_operating_class(struct ieee80211com *ic, int chan, uint32_t preference);
int ieee80211_is_channel_disabled(struct ieee80211com *ic, int channel, int bw);
int ieee80211_chan_get_maxpwr(struct ieee80211_channel *ch, unsigned bw);
void ieee80211_enable_rxpn_check(struct ieee80211vap *vap, int enable);

int ieee80211_rst_dev_stats(struct ieee80211vap *vap);

int ieee80211_swfeat_is_supported(uint16_t feat, uint8_t print_msg);

void ieee80211_csa_finish(struct work_struct *work);
void ieee80211_finish_csa(unsigned long arg);
void ieee80211_finish_bw_switch_csa(unsigned long arg);
int ieee80211_enter_csa(struct ieee80211com *ic, struct ieee80211_channel *chan,
		void (*finish_csa)(unsigned long arg), uint32_t reason,
		uint8_t csa_count, uint8_t csa_mode, uint32_t flag);
void ieee80211_obss_scan_timer(unsigned long arg);
void ieee80211_start_obss_scan_timer(struct ieee80211vap *vap);
int ieee80211_scs_pick_channel(struct ieee80211com *ic, int pick_flags, uint32_t cc_flag);
void ieee80211_parse_cipher_key(struct ieee80211vap *vap, void *ie, uint16_t len);
void ieee80211_ap_pick_alternate_channel(struct ieee80211com *ic,
			struct ieee80211_channel *bestchan,
			struct ieee80211_channel *fs1_bestchan,
			struct ieee80211_channel *fs1_secbestchan,
			struct ieee80211_channel *fs2_bestchan,
			struct ieee80211_channel *fs2_secbestchan);
void ieee80211_update_alternate_channels(struct ieee80211com *ic,
			struct ieee80211_channel *bestchan,
			struct ieee80211_channel **fs_bestchan,
			struct ieee80211_channel **fs_secbestchan,
			int (*compare_fn)(struct ieee80211com *, int, int));

int ieee80211_vap_wds_mode_change(struct ieee80211vap *vap);
char *ieee80211_wireless_get_hw_desc(void);
struct ieee80211_channel *ieee80211_find_channel_by_ieee(struct ieee80211com *ic, int chan_ieee);
void ieee80211_add_sec_chan_off(u_int8_t **frm, struct ieee80211com *ic, u_int8_t csa_chan);
uint8_t ieee80211_wband_chanswitch_ie_len(uint32_t bw);
uint8_t ieee80211_sec_chan_off_ie_len(void);

void ieee80211_find_ht_pri_sec_chan(struct ieee80211vap *vap,
		const struct ieee80211_scan_entry *se, uint8_t *pri_chan, uint8_t *sec_chan);
uint8_t ieee80211_find_ht_center_chan(struct ieee80211vap *vap,
		const struct ieee80211_scan_entry *se);
int ieee80211_ap_chan_40_bw_permitted(struct ieee80211vap *vap, struct ieee80211_channel *chan);
void ieee80211_sta_chan_40_bw_permitted(struct ieee80211vap *vap, struct ieee80211_channel *chan,
					uint16_t *ch_list);
void ieee80211_off_channel_timeout(unsigned long arg);
void ieee80211_off_channel_resume(struct ieee80211vap *vap);
void ieee80211_off_channel_suspend(struct ieee80211vap *vap, uint32_t timeout);
u_int8_t *ieee80211_add_qtn_pairing_ie(u_int8_t *frm, struct ieee80211_app_ie *pairing_ie);

int ieee80211_wireless_get_max_supported_chwidth(struct ieee80211_node *ni);
uint8_t ieee80211_wireless_recalc_opmode(struct ieee80211_node *ni, uint8_t opmode);
void ieee80211_mark_all_channel_status(struct ieee80211com *ic, int cur_bw);
void ieee80211_switch_bss_bw(struct ieee80211vap *vap, int bw);
void ieee80211_clean_extcap_ie(struct ieee80211vap *vap);
int ieee80211_rpe_app_ie_set(struct ieee80211vap *vap, uint32_t type,
		struct ieee80211req_getset_appiebuf *iebuf);
void ieee80211_chan_phy_stats_update(struct ieee80211_scan_state *ss,
		struct ieee80211_chan_phy_stats *new_stats, uint8_t chan);
#if defined(CONFIG_QTN_BSA_SUPPORT)
int ieee80211_qrpe_phy_info_update_event_send(struct ieee80211_scan_state *ss,
		struct ieee80211vap *vap);
int ieee80211_qrpe_dispatch_event_capability(struct ieee80211vap *vap,
		enum ieee80211_qrpe_event event_id);
int
ieee80211_qrpe_send_event_xcac_status_update(struct ieee80211vap *vap, int status, int chan_no,
		int chan_status);
#endif
uint8_t ieee80211_vap_get_macid(struct ieee80211vap *vap);
uint8_t ieee80211_vap_get_vapidx(struct ieee80211vap *vap);

/*
 * Key update synchronization methods.  XXX should not be visible.
 */
static __inline void
ieee80211_key_update_begin(struct ieee80211vap *vap)
{
	vap->iv_key_update_begin(vap);
}
static __inline void
ieee80211_key_update_end(struct ieee80211vap *vap)
{
	vap->iv_key_update_end(vap);
}
/* Check if the channel is valid */
static __inline int
is_channel_valid(int chan)
{
	if ((chan >= IEEE80211_CHAN_MAX) || chan <= 0)
		return 0;

	return 1;
}

static __inline int
is_ieee80211_chan_valid(struct ieee80211_channel *chan)
{
	if (!chan || (chan == IEEE80211_CHAN_ANYC))
		return 0;

	return 1;
}

static inline int
ieee80211_keymgmt_req_app_processing(struct ieee80211_rsnparms *vap_rsn)
{
	return (vap_rsn->rsn_keymgmtset & (WPA_KEY_MGMT_SAE | WPA_KEY_MGMT_OWE | WPA_KEY_MGMT_DPP));
}

/*
 * XXX these need to be here for IEEE80211_F_DATAPAD
 */

/*
 * Return the space occupied by the 802.11 header and any
 * padding required by the driver.  This works for a
 * management or data frame.
 */
static __inline int
ieee80211_hdrspace(struct ieee80211com *ic, const void *data)
{
	int size;
	if((ic->ic_caps & IEEE80211_C_11N) == IEEE80211_C_11N)
		size = ieee80211_hdrsize(IEEE80211_HT_CAPABLE, data);
	else
		size = ieee80211_hdrsize(IEEE80211_NON_HT_CAPABLE, data);

	if (ic->ic_flags & IEEE80211_F_DATAPAD)
		size = roundup(size, sizeof(u_int32_t));
	return size;
}

/*
 * Like ieee80211_hdrspace, but handles any type of frame.
 */
static __inline int
ieee80211_anyhdrspace(struct ieee80211com *ic, const void *data)
{
	int size;
	if((ic->ic_caps & IEEE80211_C_11N) == IEEE80211_C_11N)
		size =  ieee80211_anyhdrsize(IEEE80211_HT_CAPABLE, data);
	else
		size =  ieee80211_anyhdrsize(IEEE80211_NON_HT_CAPABLE, data);

	if (ic->ic_flags & IEEE80211_F_DATAPAD)
		size = roundup(size, sizeof(u_int32_t));
	return size;
}

static __inline char *
ieee80211_bw2str(int bw)
{
	char *bwstr = "invalid";

	switch (bw) {
	case BW_HT20:
		bwstr = IEEE80211_BWSTR_20;
		break;
	case BW_HT40:
		bwstr = IEEE80211_BWSTR_40;
		break;
	case BW_HT80:
		bwstr = IEEE80211_BWSTR_80;
		break;
	case BW_HT160:
		bwstr = IEEE80211_BWSTR_160;
		break;
	default:
		break;
	}

	return bwstr;
}

static __inline int
ieee80211_tx_amsdu_disabled(struct ieee80211_node *ni)
{
	struct ieee80211vap *vap = ni->ni_vap;

	if (!vap->iv_tx_amsdu)
		return 1;

	if (!IEEE80211_NODE_IS_VHT(ni) &&
			IEEE80211_NODE_IS_HT(ni) &&
			!vap->iv_tx_amsdu_11n)
		return 1;

	return 0;
}

static __inline int
ieee80211_is_chan40d(const struct ieee80211_channel *chan)
{
	if (chan->ic_ieee > chan->cchan_40)
		return 1;

	return 0;
}

static __inline int
ieee80211_is_chan40u(const struct ieee80211_channel *chan)
{
	if (chan->ic_ieee < chan->cchan_40)
		return 1;

	return 0;
}

/* BITs of iv_debug definition */
#define IEEE80211_MSG_11N	0x80000000	/* 11n mode debug */
#define	IEEE80211_MSG_DEBUG	0x40000000	/* IFF_DEBUG equivalent */
#define	IEEE80211_MSG_DUMPPKTS	0x20000000	/* IFF_LINK2 equivalent */
#define	IEEE80211_MSG_CRYPTO	0x10000000	/* crypto work */
#define	IEEE80211_MSG_INPUT	0x08000000	/* input handling */
#define	IEEE80211_MSG_XRATE	0x04000000	/* rate set handling */
#define	IEEE80211_MSG_ELEMID	0x02000000	/* element id parsing */
#define	IEEE80211_MSG_NODE	0x01000000	/* node handling */
#define	IEEE80211_MSG_ASSOC	0x00800000	/* association handling */
#define	IEEE80211_MSG_AUTH	0x00400000	/* authentication handling */
#define	IEEE80211_MSG_SCAN	0x00200000	/* scanning */
#define	IEEE80211_MSG_OUTPUT	0x00100000	/* output handling */
#define	IEEE80211_MSG_STATE	0x00080000	/* state machine */
#define	IEEE80211_MSG_POWER	0x00040000	/* power save handling */
#define	IEEE80211_MSG_DOT1X	0x00020000	/* 802.1X authenticator */
#define	IEEE80211_MSG_NODEBSS	0x00010000	/* BSS node handling */
#define	IEEE80211_MSG_RADIUS	0x00008000	/* 802.1X radius client */
#define	IEEE80211_MSG_RADDUMP	0x00004000	/* dump 802.1X radius packets */
#define	IEEE80211_MSG_RADKEYS	0x00002000	/* dump 802.1X keys */
#define	IEEE80211_MSG_WPA	0x00001000	/* WPA/RSN protocol */
#define	IEEE80211_MSG_ACL	0x00000800	/* ACL handling */
#define	IEEE80211_MSG_WME	0x00000400	/* WME protocol */
#define	IEEE80211_MSG_SUPG	0x00000200	/* SUPERG */
#define	IEEE80211_MSG_DOTH	0x00000100	/* 11.h */
#define	IEEE80211_MSG_INACT	0x00000080	/* inactivity handling */
#define	IEEE80211_MSG_ROAM	0x00000040	/* sta-mode roaming */
#define IEEE80211_MSG_ACTION	0x00000020	/* action management frames */
#define IEEE80211_MSG_TPC	0x00000010	/* transmit power control */
#define	IEEE80211_MSG_VSP	0x00000008	/* VSP */
#define IEEE80211_MSG_VHT	0x00000004	/* 11ac mode debug-VHT*/
#define	IEEE80211_MSG_TDLS	0x00000002	/* TDLS */
#define	IEEE80211_MSG_EXTDR	0x00000001	/* Extender: QHOP or Repeater */

/* BITs of iv_debug_ext definition */
#define	IEEE80211_MSG_ANY	0xffffffff	/* anything */
#define IEEE80211_MSG_ERW	0x00000001	/* ERW */
#define IEEE80211_MSG_MFR	0x00000002	/* Manage Frame Registration */
#define IEEE80211_MSG_EXTCAP	0x00000004	/* Extended Capabilities */
#define IEEE80211_MSG_BTMREQ	0x00000008	/* BTM request */
#define IEEE80211_MSG_MAP	0x00000010	/* MultiAP */

#define IEEE80211_TDLS_MSG_WARN	1
#define IEEE80211_TDLS_MSG_DBG	2

#define IEEE80211_EXTENDER_MSG_DISABLE	0
#define IEEE80211_EXTENDER_MSG_WARN	1
#define IEEE80211_EXTENDER_MSG_DBG	2

#ifdef IEEE80211_DEBUG

#define	ieee80211_msg(_vap, _m)	((_vap)->iv_debug & (_m))

#define	ieee80211_msg_ext(_vap, _m)	((_vap)->iv_debug_ext & (_m))

#define	ieee80211_tdls_msg(_vap, _n)	((_n) <= (_vap)->tdls_verbose)

#define	ieee80211_extender_msg(_vap, _n)	((_n) <= (_vap)->iv_ic->ic_extender_verbose)

#define	IEEE80211_DPRINTF(_vap, _m, _fmt, ...) do {			\
	if (unlikely(ieee80211_msg(_vap, _m)))				\
		ieee80211_note(_vap, _fmt, __VA_ARGS__);		\
} while (0)

#define	IEEE80211_DPRINTF_EXT(_vap, _m, _fmt, ...) do {				\
		if (unlikely(ieee80211_msg_ext(_vap, _m)))			\
			ieee80211_note(_vap, _fmt, __VA_ARGS__);		\
} while (0)

#define	IEEE80211_TDLS_DPRINTF(_vap, _m, _n, _fmt, ...) do {	\
	if (unlikely(ieee80211_msg(_vap, _m) && ieee80211_tdls_msg(_vap, _n)))	\
		ieee80211_note(_vap, _fmt, __VA_ARGS__);		\
} while (0)

#define	IEEE80211_EXTENDER_DPRINTF(_vap, _n, _fmt, ...) do {	\
	if (unlikely(ieee80211_extender_msg(_vap, _n))) \
		ieee80211_note(_vap, _fmt, __VA_ARGS__);		\
} while (0)

#define	IEEE80211_NOTE(_vap, _m, _ni, _fmt, ...) do {			\
	if (unlikely(ieee80211_msg(_vap, _m)))				\
		ieee80211_note_mac(_vap, (_ni)->ni_macaddr, _fmt, __VA_ARGS__);\
} while (0)

#define	IEEE80211_NOTE_MAC(_vap, _m, _mac, _fmt, ...) do {		\
	if (unlikely(ieee80211_msg(_vap, _m)))				\
		ieee80211_note_mac(_vap, _mac, _fmt, __VA_ARGS__);	\
} while (0)

#define	IEEE80211_NOTE_FRAME(_vap, _m, _wh, _fmt, ...) do {		\
	if (unlikely(ieee80211_msg(_vap, _m)))				\
		ieee80211_note_frame(_vap, _wh, _fmt, __VA_ARGS__);	\
} while (0)

#define	IEEE80211_DPRINTF_NODEREF(_ni, _func, _line) do {				\
	if (unlikely(!_ni || !_ni->ni_vap)) {						\
		printk("%s:%u epic fail ni=%p\n", _func, _line, _ni);			\
		break;									\
	} else if (unlikely(ieee80211_msg(_ni->ni_vap, (_ni == _ni->ni_vap->iv_bss) ?	\
				IEEE80211_MSG_NODEBSS : IEEE80211_MSG_NODE))) {		\
		ieee80211_note(_ni->ni_vap,						\
			"[%s]%s:%u: nodecnt=%u ni=%p tbl=%u refcnt=%d\n",		\
			ether_sprintf(_ni->ni_macaddr),					\
			_func, _line,							\
			_ni->ni_ic ? _ni->ni_ic->ic_node_count : 0,			\
			_ni, (_ni->ni_table != NULL),					\
			ieee80211_node_refcnt(_ni));					\
	}										\
} while (0)

void ieee80211_note(struct ieee80211vap *, const char *, ...);
void ieee80211_note_mac(struct ieee80211vap *,
	const u_int8_t mac[IEEE80211_ADDR_LEN], const char *, ...);
void ieee80211_note_frame(struct ieee80211vap *,
	const struct ieee80211_frame *, const char *, ...);

#define	ieee80211_msg_debug(_vap) \
	ieee80211_msg(_vap, IEEE80211_MSG_DEBUG)
#define	ieee80211_msg_dumppkts(_vap) \
	ieee80211_msg(_vap, IEEE80211_MSG_DUMPPKTS)
#define	ieee80211_msg_input(_vap) \
	ieee80211_msg(_vap, IEEE80211_MSG_INPUT)
#define	ieee80211_msg_radius(_vap) \
	ieee80211_msg(_vap, IEEE80211_MSG_RADIUS)
#define	ieee80211_msg_dumpradius(_vap) \
	ieee80211_msg(_vap, IEEE80211_MSG_RADDUMP)
#define	ieee80211_msg_dumpradkeys(_vap) \
	ieee80211_msg(_vap, IEEE80211_MSG_RADKEYS)
#define	ieee80211_msg_scan(_vap) \
	ieee80211_msg(_vap, IEEE80211_MSG_SCAN)
#define	ieee80211_msg_assoc(_vap) \
	ieee80211_msg(_vap, IEEE80211_MSG_ASSOC)
#else /* IEEE80211_DEBUG */
#define	IEEE80211_DPRINTF(_vap, _m, _fmt, ...)
#define	IEEE80211_DPRINTF_EXT(_vap, _m, _fmt, ...)
#define	IEEE80211_NOTE(_vap, _m, _wh, _fmt, ...)
#define	IEEE80211_NOTE_FRAME(_vap, _m, _wh, _fmt, ...)
#define	IEEE80211_NOTE_MAC(_vap, _m, _mac, _fmt, ...)
#define	IEEE80211_DPRINTF_NODEREF(_ni, _func, _line)
#endif /* IEEE80211_DEBUG */

#ifdef CONFIG_QHOP
/* Some prototypes QHOP implementation */
extern int  ieee80211_scs_is_wds_rbs_node(struct ieee80211com *ic);
extern void ieee80211_dfs_send_csa(struct ieee80211vap *vap, uint8_t new_chan);
#endif

extern void ieee80211_wireless_reassoc(struct ieee80211vap *vap, int debug, int rescan);
struct ieee80211_band_info *ieee80211_get_band_info(int band_idx);

#if defined(QBMPS_ENABLE)
extern int ieee80211_wireless_set_sta_bmps(struct ieee80211vap *vap, struct ieee80211com *ic, int value);
extern int ieee80211_sta_bmps_update(struct ieee80211vap *vap);
#endif

extern int ieee80211_is_idle_state(struct ieee80211com *ic);
extern int ieee80211_is_on_weather_channel_bw(struct ieee80211com *ic,
				struct ieee80211_channel *chan, int bw);
extern int ieee80211_is_on_weather_channel(struct ieee80211com *ic, struct ieee80211_channel *chan);
void ieee80211_beacon_destroy_param(struct ieee80211vap *vap);

extern void ieee80211_reset_nop_timers(struct ieee80211com *ic, struct ieee80211_channel * chan,
					struct ieee80211_channel *chan_list[], int cur_bw);

extern int ieee80211_is_active_channel_per_bw(struct ieee80211com *ic,
				struct ieee80211_channel *chan, int bw);
extern int ieee80211_is_radar_detected_channel_per_bw(struct ieee80211com *ic,
				struct ieee80211_channel *chan, int bw);

extern uint8_t g_l2_ext_filter;
extern uint8_t g_l2_ext_filter_port;

#define QTN_IS_WDS_NI(_ni) ((_ni) && (_ni)->ni_vap && (_ni)->ni_vap->iv_opmode == IEEE80211_M_WDS)

struct ieee80211vap *ieee80211_get_first_vap(struct ieee80211com *, int, const char *);

#define ieee80211_get_primary_vap(_ic, _warn) ieee80211_get_first_vap(_ic, _warn, __func__)

static inline struct net_device *
ieee80211_ic2dev(struct ieee80211com *ic)
{
#ifndef SYSTEM_BUILD
	struct ieee80211vap *vap = ieee80211_get_first_vap(ic, 0, NULL);

	if (vap)
		return vap->iv_dev;
#endif
	return NULL;
}

struct ieee80211com *ieee80211_get_ic_from_vap(struct ieee80211vap *, const char *);

#define ieee80211_get_ic_from_vap_wrap(_vap)    ieee80211_get_ic_from_vap(_vap, __func__)

extern void ieee80211_vap_remove_scan_ssid(struct ieee80211_scan_ssid_list **scan_ssid);

int ieee80211_bw_to_cwm(int bw);
int ieee80211_cwm_to_bw(int cwm);

void ieee80211_update_node_bw(struct ieee80211_node *ni, int bw);
int ieee80211_send_mgmt_payload(struct ieee80211_node *ni, uint8_t subtype,
				const uint8_t *data, uint32_t len);
const struct region_to_oper_class *
ieee80211_get_region_opclass(struct ieee80211com *ic, const char *region_str, int *is_cur);
int ieee80211_send_app_frame_auth(struct ieee80211_node *ni, uint8_t *data, uint32_t len);
extern void ieee80211_scs_repeater_monitor(struct work_struct *work);
extern int ieee80211_remain_on_chan_prepare_send_event(struct ieee80211vap *vap,
							unsigned int frequency,
							unsigned int duration,
							unsigned int cancel_flag);
int ieee80211_wlan_cancel_remain_on_chan(struct ieee80211vap *vap);
#endif /* _NET80211_IEEE80211_VAR_H_ */
int ieee80211_is_repeater_sta_up(struct ieee80211com *ic);
int ieee80211_is_repeater_sta_down(struct ieee80211com *ic);
int ieee80211_are_scs_ap_only_funcs_allowed(struct ieee80211com *ic);
int ieee80211_set_basic_rate(struct ieee80211com *ic, int rate, int is_basic);
