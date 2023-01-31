/**
  Copyright (c) 2008 - 2019 Quantenna Communications Inc
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
#include <linux/version.h>
#ifndef AUTOCONF_INCLUDED
# include <linux/config.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
# include <linux/kconfig.h>
#else
# include <generated/autoconf.h>
#endif
#include <linux/version.h>
#include <linux/device.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/dma-mapping.h>
#include <linux/stddef.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/sch_generic.h>
#include <linux/netlink.h>
#include <trace/ippkt.h>

#include "qdrv_pktlogger.h"
#include "qdrv_control.h"
#include "qdrv_radar.h"
#include "qdrv_debug.h"
#include "qtn/qdrv_bld.h"
#include "qdrv_netdebug_checksum.h"
#include "qdrv_netdebug_binary.h"
#include "qdrv_muc_stats.h"
#include "qdrv_vap.h"
#include <qtn/qtn_math.h>

#include <asm/board/soc.h>
#include <qtn/mproc_sync_base.h>
#include <common/ruby_mem.h>
#include <common/pktlogger/pktlogger_nl_common.h>
#include <qtn/qtn_bb_mutex.h>
#include <qtn/hardware_revision.h>
#include <qtn/emac_debug.h>
#include <qtn/ruby_cpumon.h>
#include <qtn/qtn_muc_stats_print.h>
#include <qtn/txbf_mbox.h>

struct qdrv_pktlogger *g_pktlogger_p = NULL;

void *qdrv_pktlogger_alloc_buffer(char *description, int data_len)
{
	void *data_p;

	data_p = kzalloc(data_len, GFP_ATOMIC);
	if (data_p == NULL) {
		DBGPRINTF_LIMIT_E("%s():Failed for %s", __FUNCTION__, description);
		return NULL;
	}

	return data_p;
}

void qdrv_pktlogger_free_buffer(void *data_buffer)
{
	kfree(data_buffer);
}

void qdrv_pktlogger_hdr_init(struct qdrv_wlan *qw,
		struct qdrv_pktlogger_hdr *hdr,
		int rec_type,
		int stats_len)
{
	uint64_t tsf;

	hdr->udpheader.dest = qw->pktlogger.dst_port;
	hdr->udpheader.source = qw->pktlogger.src_port;
	hdr->udpheader.len = htons(stats_len);
	hdr->udpheader.check = 0;

	hdr->type = rec_type;

	IEEE80211_ADDR_COPY(hdr->src, qw->mac->mac_addr);
	hdr->version = QDRV_NETDEBUG_CHECKSUM;
	hdr->builddate = QDRV_BUILDDATE;
	strncpy(hdr->buildstring, QDRV_BLD_NAME, QDRV_NETDEBUG_BUILDSTRING_SIZE - 1);
	hdr->buildstring[QDRV_NETDEBUG_BUILDSTRING_SIZE - 1] = '\0';
	hdr->timestamp = jiffies_to_msecs(jiffies - INITIAL_JIFFIES) / 5;
	hdr->flags = SM(0, QDRV_NETDEBUG_FLAGS_MASK_HDR_VERSION);
	qw->ic.ic_get_tsf(&tsf);
	hdr->tsf_lo = U64_LOW32(tsf);
	hdr->tsf_hi = U64_HIGH32(tsf);
	hdr->stats_len = stats_len - sizeof(*hdr);
	hdr->opmode = (u_int8_t)qw->ic.ic_opmode;
	hdr->platform = get_hardware_revision();
	memset(hdr->padding, 0, sizeof(hdr->padding));
}

/*
 * Remap the statistics structures if not already done.
 * These are used by netdebug and ratedebug, and are never unmapped.
 */
int qdrv_pktlogger_map(struct qdrv_wlan *qw)
{
	struct qtn_stats_log *iw_stats_log;
	iw_stats_log = (struct qtn_stats_log *)qw->mac->mac_sys_stats;
	if (iw_stats_log == NULL) {
		return -1;
	}

	if (qw->pktlogger.stats_uc_phy_stats_ptr == NULL) {
		qw->pktlogger.stats_uc_phy_stats_ptr =
			ioremap_nocache(muc_to_lhost((u32)iw_stats_log->phy_stats),
					sizeof(struct qtn_phy_stats));
	}

	if (qw->pktlogger.stats_uc_rx_ptr == NULL) {
		qw->pktlogger.stats_uc_rx_ptr =
			ioremap_nocache(muc_to_lhost((u32)iw_stats_log->rx_muc_stats),
					sizeof(struct muc_rx_stats));
	}

	if (qw->pktlogger.stats_uc_rx_bf_ptr == NULL) {
		qw->pktlogger.stats_uc_rx_bf_ptr =
			ioremap_nocache(muc_to_lhost((u32)iw_stats_log->rx_muc_bf_stats),
					sizeof(struct muc_rx_bf_stats));
	}

	if (qw->pktlogger.stats_uc_rx_rate_ptr == NULL) {
		qw->pktlogger.stats_uc_rx_rate_ptr =
			ioremap_nocache(muc_to_lhost((u32)iw_stats_log->rx_muc_rates),
					sizeof(struct muc_stat_rates));
	}

	if (qw->pktlogger.stats_uc_tx_ptr == NULL) {
		qw->pktlogger.stats_uc_tx_ptr =
			ioremap_nocache(muc_to_lhost((u32)iw_stats_log->tx_muc_stats),
					sizeof(struct muc_tx_stats));
	}

	if (qw->pktlogger.stats_uc_tx_rate_ptr == NULL) {
		qw->pktlogger.stats_uc_tx_rate_ptr =
			ioremap_nocache(muc_to_lhost((u32)iw_stats_log->tx_muc_rates),
					sizeof(struct qtn_rate_tx_stats_per_sec));
	}

	if (qw->pktlogger.stats_uc_su_rates_read_ptr == NULL) {
		qw->pktlogger.stats_uc_su_rates_read_ptr =
			ioremap_nocache(muc_to_lhost((u32)iw_stats_log->muc_su_rate_stats_read),
					sizeof(uint32_t));
	}

	if (qw->pktlogger.stats_uc_mu_rates_read_ptr == NULL) {
		qw->pktlogger.stats_uc_mu_rates_read_ptr =
			ioremap_nocache(muc_to_lhost((u32)iw_stats_log->muc_mu_rate_stats_read),
					sizeof(uint32_t));
	}

	if (qw->pktlogger.stats_uc_scs_cnt == NULL) {
		qw->pktlogger.stats_uc_scs_cnt =
			ioremap_nocache(muc_to_lhost((u32)iw_stats_log->scs_cnt),
					sizeof(struct qdrv_scs_cnt));
	}

	if (qw->stats_uc_rates_per_node == NULL) {
		qw->stats_uc_rates_per_node =
			ioremap_nocache(muc_to_lhost((u32)iw_stats_log->rates_per_node),
					sizeof(struct qtn_node_rate_stats) *
					QTN_NODE_STAT_RATE_SLOTS);
	}

	if (qw->pktlogger.netdev_q_ptr_w == NULL) {
		struct ieee80211vap *vap = TAILQ_FIRST(&qw->ic.ic_vaps);
		if (vap) {
			if (vap->iv_dev != NULL) {
				struct netdev_queue *ndq = netdev_get_tx_queue(vap->iv_dev, 0);
				if (ndq != NULL) {
					qw->pktlogger.netdev_q_ptr_w = ndq;
				}
			}
		}
	}
	if (qw->pktlogger.netdev_q_ptr_e == NULL) {
		if (qw->pktlogger.dev != NULL) {
			struct netdev_queue *ndq = netdev_get_tx_queue(qw->pktlogger.dev, 0);
			if (ndq != NULL) {
				qw->pktlogger.netdev_q_ptr_e = ndq;
			}
		}
	}

	return 0;
}

/* record Auc status pointer */
void qdrv_pktlogger_set_auc_status_ptr(struct qdrv_wlan *qw)
{
#if !defined(CONFIG_TOPAZ_PCIE_HOST)
	const bool fw_no_mu = qw->sp->fw_no_mu;
	const struct qtn_auc_stat_field auc_field_default[] = {
	#include <qtn/qtn_auc_stats_fields.default.h>
	};
	const struct qtn_auc_stat_field auc_field_nomu[] = {
	#include <qtn/qtn_auc_stats_fields.nomu.h>
	};
	const struct qtn_auc_stat_field *auc_field = fw_no_mu ? auc_field_nomu : auc_field_default;
	const size_t nstats = fw_no_mu ? ARRAY_SIZE(auc_field_nomu) : ARRAY_SIZE(auc_field_default);
	unsigned int i;

	for (i = 0; i < nstats; i++) {
		const uintptr_t addr = auc_field[i].addr;
		const char *const name = auc_field[i].name;
		if (__in_mem_range(addr, TOPAZ_AUC_DMEM_ADDR, TOPAZ_AUC_DMEM_SIZE)) {
			if (strcmp(name, "sleep") == 0) {
				if (qw->pktlogger.stats_auc_sleep_p == NULL)
					qw->pktlogger.stats_auc_sleep_p = (uint32_t *)addr;
			} else if (strcmp(name, "jiffies") == 0) {
				if (qw->pktlogger.stats_auc_jiffies_p == NULL)
					qw->pktlogger.stats_auc_jiffies_p = (uint32_t *)addr;
			} else if (strcmp(name, "IRQ_0") == 0) {
				if (qw->pktlogger.stats_auc_intr_p == NULL)
					qw->pktlogger.stats_auc_intr_p = (uint32_t *)addr;
			} else if (strcmp(name, "task_alive_counters[0]") == 0) {
				if (qw->pktlogger.stats_auc_dbg_p == NULL)
					qw->pktlogger.stats_auc_dbg_p = (struct auc_dbg_counters *)addr;
			}
		}
	}
#endif
}

int qdrv_pktlogger_set(struct qdrv_wlan *qw, const char *param, const char *value)
{
	int ret = 0;
	struct net_device *ndev;

	if (strcmp(param, "dstmac") == 0) {
		ret = qdrv_parse_mac(value, qw->pktlogger.dst_addr);
	} else if (strcmp(param, "dstip") == 0) {
		ret = iputil_v4_pton(value, &qw->pktlogger.dst_ip);
	} else if (strcmp(param, "srcip") == 0) {
		ret = iputil_v4_pton(value, &qw->pktlogger.src_ip);
	} else if (strcmp(param, "dstport") == 0) {
		unsigned portnum;
		if ((sscanf(value, "%u", &portnum) != 1)) {
			printk("invalid portnum %s\n", value);
			ret = -1;
		} else {
			qw->pktlogger.dst_port = htons(portnum);
		}
	} else if (strcmp(param, "wifimac") == 0) {
		ret = qdrv_parse_mac(value, qw->pktlogger.recv_addr);
	} else if (strcmp(param, "interface") == 0) {
		ndev = dev_get_by_name(&init_net, value);
		if (ndev) {
			qw->pktlogger.dev = ndev;
			dev_put(ndev);
		}
	} else {
		printk("%s is not a valid parameter\n", param);
		return -1;
	}

	return ret;
}

void qdrv_pktlogger_show(struct qdrv_wlan *qw)
{
	uint8_t *addr_p;
	struct qdrv_pktlogger_types_tbl *tbl = NULL;
	int i;

	addr_p = (uint8_t*)&qw->pktlogger.dst_ip;
	printk("Dst IP:          %pI4:%u\n", addr_p, ntohs(qw->pktlogger.dst_port));

	addr_p = (uint8_t*)&qw->pktlogger.src_ip;
	printk("Src IP:          %pI4:%u\n", addr_p, ntohs(qw->pktlogger.src_port));

	addr_p = (uint8_t*)qw->pktlogger.dst_addr;
	printk("Dst MAC:         %pM\n", addr_p);
	addr_p = (uint8_t*)qw->pktlogger.src_addr;
	printk("Src MAC:         %pM\n", addr_p);
	addr_p = (uint8_t*)qw->pktlogger.recv_addr;

	printk("Wifi MAC:        %pM\n", addr_p);
	printk("Max IP frag len: %u\n", qw->pktlogger.maxfraglen);
	printk("Device name:     %s\n", qw->pktlogger.dev->name);
	printk("Packet id:       %u\n", qw->pktlogger.ip_id);
	printk("Queue len:       %u\n", qw->pktlogger.queue_len);
	printk("Queued:          %u\n", qw->pktlogger.stats.pkt_queued);
	printk("Requeued:        %u\n", qw->pktlogger.stats.pkt_requeued);
	printk("Dropped:         %u\n", qw->pktlogger.stats.pkt_dropped);
	printk("Failed:          %u\n", qw->pktlogger.stats.pkt_failed);
	printk("Queue send:      %u\n", qw->pktlogger.stats.queue_send);

	printk("\nType      Enabled    Interval\n");
	for (i = 0; i < QDRV_NETDEBUG_TYPE_MAX; i++) {
		tbl = qdrv_pktlogger_get_tbls_by_id(i);
		if (tbl) {
			printk("%-10s%5d%9d\n", tbl->name,
					!!(qw->pktlogger.flag & BIT(i)), tbl->interval);
		}
	}
}

/* RSSI monitor and MuC kill signal gen */
static void qdrv_pktlogger_gen_muc_kill(struct qdrv_wlan *qw,
			struct qtn_rx_stats *rx_stats)
{
#ifdef QDRV_FEATURE_KILL_MUC
	int ant;
	static int rssi_zero_cnt[4] = {0, 0, 0, 0};

	if ( qw->flags_ext & QDRV_WLAN_MUC_KILLED) {
		return;
	}

	for (ant=0; ant < 4; ant++) {

		if (rx_stats->num_pkts >= 0 &&
				rx_stats->avg_rssi[ant] == 0) {
			rssi_zero_cnt[ant]++;
		} else {
			rssi_zero_cnt[ant] = 0;
		}

	    if (rssi_zero_cnt[ant] >= 30) {
			printk("Killing MuC based on low RSSI\n");
			qdrv_hostlink_killmuc(qw);
			qw->flags_ext |= QDRV_WLAN_MUC_KILLED;
		}
	}

#if 0
	/* Test feature */
	if (rx_stats->sys_temp > 6000000) {
			qdrv_hostlink_killmuc(qw);
			qw->flags_ext |= QDRV_WLAN_MUC_KILLED;
	}
#endif

	return;

#endif
}

static void
qdrv_pktlogger_slab_prepare(struct qdrv_wlan *qw, struct qdrv_slab_watch *p_out)
{
	struct qdrv_pktlogger *p_pktlogger = &qw->pktlogger;
	struct kmem_cache *p_cache = NULL;

#define CACHE(x)\
	p_cache = p_pktlogger->qmeminfo.caches[QDRV_SLAB_IDX_SIZE_##x]; \
	if (p_cache) { \
		kmem_cache_calc_usage(p_cache, &p_out->stat_size_tot_alloc_##x, \
				&p_out->stat_size_cur_alloc_##x, &p_out->stat_size_act_alloc_##x, \
				&p_out->stat_size_hwm_alloc_##x); \
	}
#define ZACHE(y)\
	p_cache = p_pktlogger->qmeminfo.caches[QDRV_SLAB_IDX_##y]; \
	if (p_cache) { \
		kmem_cache_calc_usage(p_cache, &p_out->stat_tot_alloc_##y, \
				&p_out->stat_cur_alloc_##y, &p_out->stat_act_alloc_##y, \
				&p_out->stat_hwm_alloc_##y); \
	}
#include "qdrv_slab_watch.h"
#undef CACHE
#undef ZACHE
}

/*
 * Fill memory stats structure
 */
static void
qdrv_pktlogger_netdebug_mem_stats_prepare(struct qdrv_mem_stats *stats)
{
	struct sysinfo si;
	si_meminfo(&si);

	memset(stats, 0, sizeof(*stats));
	stats->mem_free = si.freeram;
	stats->mem_slab_reclaimable = global_page_state(NR_SLAB_RECLAIMABLE);
	stats->mem_slab_unreclaimable = global_page_state(NR_SLAB_UNRECLAIMABLE);
	stats->mem_anon = global_page_state(NR_ANON_PAGES);
	stats->mem_mapped = global_page_state(NR_FILE_MAPPED);
	stats->mem_cached = global_page_state(NR_FILE_PAGES);
}

/*
 * Usual Evm value range is from -5.x to -28.x
 * Need to decode it into signed integer in pktlogger
 */
static void
qdrv_pktlogger_insert_evms( struct qdrv_netdebug_stats *stats )
{
	int iter;

	for (iter = 0; iter < QDRV_NUM_RF_STREAMS; iter++) {
		if (stats->stats_phy_rx.last_rssi_evm[iter] != MUC_PHY_ERR_SUM_NOT_AVAIL) {
			stats->stats_evm.rx_evm_val[iter] = stats->stats_phy_rx.last_rssi_evm[iter];
		} else {
			stats->stats_evm.rx_evm_val[iter] = 0;
		}
	}
}

static void
qdrv_pktlogger_insert_pd_vol(struct qdrv_wlan *qw, struct qdrv_netdebug_stats *stats)
{
	char *cmd = NULL;
	dma_addr_t cmd_dma;
	char calcmd[4] = {51, 0, 4, 0};

	cmd = qdrv_hostlink_alloc_coherent(NULL, QDRV_CMD_LENGTH, &cmd_dma, GFP_ATOMIC);
	if (cmd == NULL) {
		DBGPRINTF_E("Failed allocate %d bytes for cmd\n", QDRV_CMD_LENGTH);
		return;
	}

	memcpy(cmd, calcmd, sizeof(calcmd));

	qdrv_hostlink_msg_calcmd(qw, sizeof(calcmd), cmd_dma);

	stats->stats_pd_vol.tx_pd_vol[0] = cmd[6] << 8 | cmd[5];
	stats->stats_pd_vol.tx_pd_vol[1] = cmd[9] << 8 | cmd[8];
	stats->stats_pd_vol.tx_pd_vol[2] = cmd[12] << 8 | cmd[11];
	stats->stats_pd_vol.tx_pd_vol[3] = cmd[15] << 8 | cmd[14];

	qdrv_hostlink_free_coherent(NULL, QDRV_CMD_LENGTH, cmd, cmd_dma);
}

static void qdrv_pktlogger_netdebug_misc_stats_prepare(struct qdrv_wlan *qw, struct qdrv_misc_stats *stats)
{
	static uint64_t last_awake;
	uint64_t this_awake;
	uint32_t diff_awake;

	ruby_cpumon_get_cycles(NULL, &this_awake);
	diff_awake = this_awake - last_awake;
	last_awake = this_awake;

	stats->cpuawake = diff_awake;
}

static void qdrv_pktlogger_get_tqe_stats(struct qdrv_tqe_stats *tqe_stats)
{
	tqe_stats->emac0_outc = readl(TOPAZ_TQE_OUTPORT_EMAC0_CNT);
	tqe_stats->emac1_outc = readl(TOPAZ_TQE_OUTPORT_EMAC1_CNT);
	tqe_stats->wmac_outc = readl(TOPAZ_TQE_OUTPORT_WMAC_CNT);
	tqe_stats->lhost_outc = readl(TOPAZ_TQE_OUTPORT_LHOST_CNT);
	tqe_stats->muc_outc = readl(TOPAZ_TQE_OUTPORT_MUC_CNT);
	tqe_stats->dsp_outc = readl(TOPAZ_TQE_OUTPORT_DSP_CNT);
	tqe_stats->auc_outc = readl(TOPAZ_TQE_OUTPORT_AUC_CNT);
	tqe_stats->pcie_outc = readl(TOPAZ_TQE_OUTPORT_PCIE_CNT);

	tqe_stats->drop = readl(TOPAZ_TQE_DROP_CNT);
	tqe_stats->emac0_drop= readl(TOPAZ_TQE_DROP_EMAC0_CNT);
	tqe_stats->emac1_drop = readl(TOPAZ_TQE_DROP_EMAC1_CNT);
	tqe_stats->wmac_drop = readl(TOPAZ_TQE_DROP_WMAC_CNT);
	tqe_stats->lhost_drop = readl(TOPAZ_TQE_DROP_LHOST_CNT);
	tqe_stats->muc_drop = readl(TOPAZ_TQE_DROP_MUC_CNT);
	tqe_stats->dsp_drop = readl(TOPAZ_TQE_DROP_DSP_CNT);
	tqe_stats->auc_drop = readl(TOPAZ_TQE_DROP_AUC_CNT);
	tqe_stats->pcie_drop = readl(TOPAZ_TQE_DROP_PCIE_CNT);
}

static void qdrv_pktlogger_get_hbm_stats(struct qdrv_hbm_stats *hbm_stats,
						struct qdrv_hbm_stats_oth *hbm_stats_oth)
{
	int pool;
	int master;
	uint32_t *statp = (uint32_t *)hbm_stats;
	int req = TOPAZ_HBM_BUF_EMAC_RX_COUNT + TOPAZ_HBM_BUF_WMAC_RX_COUNT;
	int rel = 0;

	COMPILE_TIME_ASSERT(sizeof(*hbm_stats) ==
			TOPAZ_HBM_POOL_COUNT * TOPAZ_HBM_MASTER_COUNT * 2 * sizeof(uint32_t));

	for (master = 0; master < TOPAZ_HBM_MASTER_COUNT; ++master) {
		for (pool = 0; pool < TOPAZ_HBM_POOL_COUNT; ++pool) {
			*statp = readl(TOPAZ_HBM_POOL_REQUEST_CNT(master, pool));
			req += *statp;
			statp++;
		}
	}
	for (master = 0; master < TOPAZ_HBM_MASTER_COUNT; ++master) {
		for (pool = 0; pool < TOPAZ_HBM_POOL_COUNT; ++pool) {
			*statp = readl(TOPAZ_HBM_POOL_RELEASE_CNT(master, pool));
			rel += *statp;
			statp++;
		}
	}

	hbm_stats_oth->hbm_req = req;
	hbm_stats_oth->hbm_rel = rel;
	hbm_stats_oth->hbm_diff = req - rel;
	hbm_stats_oth->hbm_overflow = readl(TOPAZ_HBM_OVERFLOW_CNT);
	hbm_stats_oth->hbm_underflow = readl(TOPAZ_HBM_UNDERFLOW_CNT);
}


static void qdrv_pktlogger_netdebug_dsp_mu_stats_prepare(
	struct dsp_mu_stats* stats_dsp_mu)
{
	volatile struct qtn_txbf_mbox* txbf_mbox = qtn_txbf_mbox_get();
	int i;

	memset(stats_dsp_mu, 0, sizeof(*stats_dsp_mu));

	for (i = 0; i < ARRAY_SIZE(txbf_mbox->mu_grp_qmat); i++) {
		if (txbf_mbox->mu_grp_qmat[i].grp_id != 0) {
			stats_dsp_mu->mu_u0_aid[i] = txbf_mbox->mu_grp_qmat[i].u0_aid;
			stats_dsp_mu->mu_u1_aid[i] = txbf_mbox->mu_grp_qmat[i].u1_aid;
			stats_dsp_mu->mu_rank[i]   = txbf_mbox->mu_grp_qmat[i].rank;
		}
	}
}

static inline void qdrv_pktlogger_prepare_11n_rates(struct qdrv_muc_rates *rates,
						const struct muc_stat_rates *curr,
						const struct muc_stat_rates *prev)
{
	int i;

	COMPILE_TIME_ASSERT(ARRAY_SIZE(rates->mcs) == ARRAY_SIZE(curr->mcs_11n));

	for (i = 0; i < ARRAY_SIZE(curr->mcs_11n); i++)
		rates->mcs[i] = (uint16_t) (curr->mcs_11n[i] - prev->mcs_11n[i]);
}

static inline void qdrv_pktlogger_prepare_11ac_rates(struct qdrv_muc_11acrates *rates,
						const struct muc_stat_rates *curr,
						const struct muc_stat_rates *prev)
{
	int nss, i;
	int nss_max;
	int mcs_max;

	COMPILE_TIME_ASSERT(ARRAY_SIZE(rates->mcs_11ac_su) ==
						ARRAY_SIZE(curr->mcs_11ac_su) *
						ARRAY_SIZE(curr->mcs_11ac_su[0]));

	nss_max = ARRAY_SIZE(curr->mcs_11ac_su);
	mcs_max = ARRAY_SIZE(curr->mcs_11ac_su[0]);

	for (nss = 0; nss < nss_max; nss++) {
		for (i = 0; i < mcs_max; i++) {
			int mcs_index = nss * mcs_max + i;

			rates->mcs_11ac_su[mcs_index] = (uint16_t) (curr->mcs_11ac_su[nss][i] -
									prev->mcs_11ac_su[nss][i]);
		}
	}

	COMPILE_TIME_ASSERT(ARRAY_SIZE(rates->mcs_11ac_mu) ==
						ARRAY_SIZE(curr->mcs_11ac_mu) *
						ARRAY_SIZE(curr->mcs_11ac_mu[0]));

	nss_max = ARRAY_SIZE(curr->mcs_11ac_mu);
	mcs_max = ARRAY_SIZE(curr->mcs_11ac_mu[0]);

	for (nss = 0; nss < nss_max; nss++) {
		for (i = 0; i < mcs_max; i++) {
			int mcs_index = nss * mcs_max + i;

			rates->mcs_11ac_mu[mcs_index] = (uint16_t) (curr->mcs_11ac_mu[nss][i] -
									prev->mcs_11ac_mu[nss][i]);
		}
	}
}

/*
 * Gather statistics and send to the configured target
 */
void qdrv_pktlogger_netdebug_stats_send(unsigned long data)
{
	struct qdrv_wlan *qw = (struct qdrv_wlan *)data;
	struct qtn_phy_stats *phy_stats;
	struct qdrv_netdebug_stats *stats;
	struct muc_stat_rates *muc_rx_rates_p;
	struct qdrv_mem_stats mem_stats;
	struct qdrv_misc_stats misc_stats;
	int curr_index;
	void *data_buff;
	struct qdrv_pktlogger_types_tbl *tbl = NULL;
	struct muc_stat_rates *rx_rates_prev;
	struct muc_stat_rates *rx_rates_curr;

	tbl = qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_STATS);
	if (!tbl) {
		return;
	}
#if QDRV_NETDEBUG_ETH_DEV_STATS_ENABLED
	struct net_device_stats *dev_stats;
#endif
        if (!qw) {
                DBGPRINTF_E("%s:qw is NULL\n", __func__);
                return;
        }

        rx_rates_prev = qw->pktlogger.rx_rate_pre;
        rx_rates_curr = qw->pktlogger.rx_rate_cur;

        if (rx_rates_prev == NULL || rx_rates_curr == NULL) {
                DBGPRINTF_E("%s:rx_rates_prev or rx_rates_curr is NULL\n", __func__);
                return;
        }

	qdrv_pktlogger_flush_data(qw);

	muc_rx_rates_p = (struct muc_stat_rates *)qw->pktlogger.stats_uc_rx_rate_ptr;
        if (muc_rx_rates_p == NULL) {
                DBGPRINTF_E("%s:muc_rx_rates_p is NULL\n", __func__);
                return;
        }

	phy_stats = (struct qtn_phy_stats *)qw->pktlogger.stats_uc_phy_stats_ptr;
        if (!phy_stats) {
                DBGPRINTF_E("%s:phy_stats is NULL\n", __func__);
                return;
        }

	data_buff = qdrv_pktlogger_alloc_buffer("net", sizeof(*stats));
	if (data_buff == NULL) {
		return;
	}
	stats = (struct qdrv_netdebug_stats *)data_buff;
	qdrv_pktlogger_hdr_init(qw, &stats->ndb_hdr, QDRV_NETDEBUG_TYPE_STATS,
			sizeof(*stats));

	/* Gather statistics */
	memcpy(&stats->stats_wlan_rx, &qw->rx_stats, sizeof(stats->stats_wlan_rx));
	memcpy(&stats->stats_wlan_tx, &qw->tx_stats, sizeof(stats->stats_wlan_tx));
	memcpy(&stats->stats_wlan_sm, &qw->sm_stats, sizeof(stats->stats_wlan_sm));
	memcpy(&stats->stats_scs_cnt, qw->pktlogger.stats_uc_scs_cnt, sizeof(stats->stats_scs_cnt));

	/* Use the current entry en to the log, making sure it has not already been sent */
	curr_index = (phy_stats->curr_buff - 1 + NUM_LOG_BUFFS) % NUM_LOG_BUFFS;

	memcpy(&stats->stats_phy_rx, &phy_stats->stat_buffs[curr_index].rx_phy_stats,
			sizeof(stats->stats_phy_rx));
	memcpy(&stats->stats_phy_tx, &phy_stats->stat_buffs[curr_index].tx_phy_stats,
			sizeof(stats->stats_phy_tx));

	/*
	 * Show the nss and mcs in a field with using XYY format.
	 * X means nss (1 ~ 4)
	 * YY means mcs (0~ 76)
	 */
	stats->stats_phy_rx.last_rx_mcs =
		(stats->stats_phy_rx.last_rx_mcs & QTN_STATS_MCS_RATE_MASK) +
		MS(stats->stats_phy_rx.last_rx_mcs, QTN_PHY_STATS_MCS_NSS) * 100;
	stats->stats_phy_tx.last_tx_mcs =
		(stats->stats_phy_tx.last_tx_mcs & QTN_STATS_MCS_RATE_MASK) +
		MS(stats->stats_phy_tx.last_tx_mcs, QTN_PHY_STATS_MCS_NSS) * 100;

	if (qw->pktlogger.stats_auc_sleep_p)
		stats->stats_auc_intr_count.sleep = *qw->pktlogger.stats_auc_sleep_p;
	if (qw->pktlogger.stats_auc_jiffies_p)
		stats->stats_auc_intr_count.jiffies = *qw->pktlogger.stats_auc_jiffies_p;

	if (qw->pktlogger.stats_auc_intr_p)
		memcpy(stats->stats_auc_intr_count.aucirq, qw->pktlogger.stats_auc_intr_p,
			sizeof(stats->stats_auc_intr_count.aucirq));
	if (qw->pktlogger.stats_auc_dbg_p)
		memcpy(&stats->stats_auc_debug_counts, qw->pktlogger.stats_auc_dbg_p,
			sizeof(stats->stats_auc_debug_counts));

	qdrv_pktlogger_get_tqe_stats(&stats->stats_tqe);
	memcpy(&stats->stats_cgq, &qw->cgq_stats, sizeof(stats->stats_cgq));
	qdrv_pktlogger_get_hbm_stats(&stats->stats_hbm, &stats->stats_hbm_oth);

	if (qdrv_muc_stats_get_display_choice(&phy_stats->stat_buffs[curr_index],
			&qw->ic) == QDRV_MUC_STATS_SHOW_EVM) {
		qdrv_pktlogger_insert_evms(stats);
	} else {
		memset(stats->stats_evm.rx_evm_val, 0, sizeof(stats->stats_evm.rx_evm_val));
	}

	qdrv_pktlogger_insert_pd_vol(qw, stats);

	/* uc_rx_stats are in DMEM, IO doesnt work */
	if(qw->pktlogger.stats_uc_rx_ptr)
                memcpy(&stats->stats_muc_rx, qw->pktlogger.stats_uc_rx_ptr, sizeof(stats->stats_muc_rx));
        else
                DBGPRINTF_E("%s:qw->pktlogger.stats_uc_rx_ptr is NULL\n", __func__);

	if(qw->pktlogger.stats_uc_rx_bf_ptr)
                memcpy(&stats->stats_muc_rx_bf, qw->pktlogger.stats_uc_rx_bf_ptr, sizeof(stats->stats_muc_rx_bf));
        else
                DBGPRINTF_E("%s:qw->pktlogger.stats_uc_rx_bf_ptr is NULL\n", __func__);

	if(qw->pktlogger.stats_uc_tx_ptr)
                memcpy(&stats->stats_muc_tx, qw->pktlogger.stats_uc_tx_ptr, sizeof(stats->stats_muc_tx));
        else
                DBGPRINTF_E("%s:qw->pktlogger.stats_uc_tx_ptr is NULL\n", __func__);

	trace_ippkt_dropped(TRACE_IPPKT_DROP_RSN_MUC_RX_AGG_TIMEOUT,
				stats->stats_muc_rx.agg_timeout, 1);
	trace_ippkt_dropped(TRACE_IPPKT_DROP_RSN_MUC_RX_AGG_EMPTY,
				stats->stats_muc_rx.agg_evict_empty, 1);

	/* Queueing stats on the LHost - within QDisc struct (one per tx queue). */
	if (qw->pktlogger.netdev_q_ptr_e != NULL) {
		struct Qdisc *qd = qw->pktlogger.netdev_q_ptr_e->qdisc;
		if (qd != NULL) {
			stats->stats_qdisc.eth_sent = qd->bstats.packets;
			stats->stats_qdisc.eth_dropped = qd->qstats.drops;
		}
	}

	if (qw->pktlogger.netdev_q_ptr_w != NULL) {
		struct Qdisc *qd = qw->pktlogger.netdev_q_ptr_w->qdisc;
		if (qd != NULL) {
			stats->stats_qdisc.wifi_sent = qd->bstats.packets;
			stats->stats_qdisc.wifi_dropped = qd->qstats.drops;
		}
	}

	if (qw->pktlogger.dev && (strncmp(qw->pktlogger.dev->name, "eth", 3) == 0)) {
		if (qw->pktlogger.dev_emac0)
			stats->stats_emac.rx_emac0_dma_missed =
				qtn_eth_rx_lost_get(qw->pktlogger.dev_emac0);
		if (qw->pktlogger.dev_emac1)
			stats->stats_emac.rx_emac1_dma_missed =
				qtn_eth_rx_lost_get(qw->pktlogger.dev_emac1);
	}

	/*
	 * There are too many 32 bit rate fields to fit in the debug packet so use 16 bit
	 * fields and take the difference from the previous value (otherwise it could wrap
	 * every few seconds).
	 */
	memcpy(rx_rates_curr, muc_rx_rates_p, sizeof(*rx_rates_curr));

	COMPILE_TIME_ASSERT(sizeof(stats->rates_muc_rx) == sizeof(struct qdrv_muc_rates));
	COMPILE_TIME_ASSERT(offsetof(struct qdrv_muc_rx_rates, rx_mcs_pad) ==
			    offsetof(struct qdrv_muc_rates, mcs_pad));
	qdrv_pktlogger_prepare_11n_rates((struct qdrv_muc_rates *)&stats->rates_muc_rx,
					 rx_rates_curr, rx_rates_prev);

	COMPILE_TIME_ASSERT(sizeof(stats->rates_muc_rx_11ac) == sizeof(struct qdrv_muc_11acrates));
	qdrv_pktlogger_prepare_11ac_rates((struct qdrv_muc_11acrates *)&stats->rates_muc_rx_11ac,
					  rx_rates_curr, rx_rates_prev);

	qw->pktlogger.rx_rate_pre = rx_rates_curr;
	qw->pktlogger.rx_rate_cur = rx_rates_prev;

#if QDRV_NETDEBUG_ETH_DEV_STATS_ENABLED
	if (qw->pktlogger.dev &&
		qw->pktlogger.dev->netdev_ops->ndo_get_stats) {

		dev_stats = qw->pktlogger.dev->netdev_ops->ndo_get_stats(qw->pktlogger.dev);
		memcpy(&stats->stats_eth, dev_stats, sizeof(stats->stats_eth));
	}
#endif

	/* Prepare memory statistics */
	qdrv_pktlogger_netdebug_mem_stats_prepare(&mem_stats);
	memcpy(&stats->stats_mem, &mem_stats, sizeof(stats->stats_mem));

	qdrv_pktlogger_slab_prepare(qw, &stats->stats_slab);

	qdrv_pktlogger_netdebug_misc_stats_prepare(qw, &misc_stats);
	memcpy(&stats->stats_misc, &misc_stats, sizeof(stats->stats_misc));

	memcpy(&stats->stats_csw, &qw->csw_stats, sizeof(stats->stats_csw));

	qdrv_pktlogger_netdebug_dsp_mu_stats_prepare(&stats->stats_dsp_mu);

	/* Invoke stat monitor to kill MuC possibly */
	qdrv_pktlogger_gen_muc_kill(qw, &stats->stats_phy_rx);

	qdrv_pktlogger_send(stats, sizeof(*stats));

	/* refresh timer */
	mod_timer(&qw->pktlogger.stats_timer, jiffies + (tbl->interval * HZ));
}

static void
qdrv_pktlogger_slab_init(struct qdrv_wlan *qw)
{
	struct qdrv_pktlogger *p_pktlogger = &qw->pktlogger;
#define CACHE(x)	p_pktlogger->qmeminfo.caches[QDRV_SLAB_IDX_SIZE_##x] = kmem_cache_find("size-"#x);
#define ZACHE(y)	p_pktlogger->qmeminfo.caches[QDRV_SLAB_IDX_##y] = kmem_cache_find(#y);
#include "qdrv_slab_watch.h"
#undef CACHE
#undef ZACHE
}

static int qdrv_pktlogger_start_stats(struct qdrv_wlan *qw)
{
	struct qdrv_pktlogger_types_tbl *tbl = NULL;

	tbl = qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_STATS);

	if (!tbl) {
		return -1;
	}
	if (qdrv_pktlogger_map(qw) < 0) {
		return -1;
	}

	qdrv_pktlogger_set_auc_status_ptr(qw);
	qdrv_pktlogger_slab_init(qw);
	del_timer(&qw->pktlogger.stats_timer);
	init_timer(&qw->pktlogger.stats_timer);
	qw->pktlogger.stats_timer.function = qdrv_pktlogger_netdebug_stats_send;
	qw->pktlogger.stats_timer.data = (unsigned long)qw;
	qw->pktlogger.stats_timer.expires = jiffies + (tbl->interval * HZ);
	add_timer(&qw->pktlogger.stats_timer);

	qw->pktlogger.flag |= BIT(QDRV_NETDEBUG_TYPE_STATS);
	printk("Netdebug is enabled\n");

	return 0;
}

static void qdrv_pktlogger_stop_stats(struct qdrv_wlan *qw)
{
	/*
	 * Clear the netdev queue pointers so we can uninstall the qdisc and
	 * resinstall a new one without crashing.
	 */
	qw->pktlogger.netdev_q_ptr_w = NULL;
	qw->pktlogger.netdev_q_ptr_e = NULL;

	del_timer(&qw->pktlogger.stats_timer);
	qw->pktlogger.flag &= (~BIT(QDRV_NETDEBUG_TYPE_STATS));
	printk("Netdebug is disabled\n");
}

static void qdrv_pktlogger_prepare_vis_vap(struct qdrv_mac *mac,
							struct qdrv_netdebug_vision *p_vision)
{
	struct qdrv_vap *qv = NULL;
	unsigned int vap_count = p_vision->vap_count;
	int i;

	for (i = 0; (i < QDRV_MAX_VAPS) && (vap_count < ARRAY_SIZE(p_vision->vap_data)); i++) {
		/* vnet[i] might be deleted or disabled */
		if (mac->vnet[i] == NULL || !IEEE80211_DEV_IS_UP(mac->vnet[i]))
			continue;

		qv = netdev_priv(mac->vnet[i]);
		p_vision->vap_data[vap_count].index = qv->devid;
		vap_count++;
	}

	p_vision->vap_count = vap_count;
}

static struct ieee80211_node_table *qdrv_pktlogger_nt_get(struct qdrv_mac *mac)
{
	struct qdrv_wlan *qw;
	struct ieee80211_node_table *nt;

	qw = (struct qdrv_wlan *)mac->data;
	if (!qw)
		return NULL;
	nt = &qw->ic.ic_sta;
	return nt;
}

static inline int qdrv_is_vap_node(const struct ieee80211_node *ni)
{
	if (!ni || !(ni->ni_vap))
		return 0;
	if (ieee80211_node_is_authorized(ni) && IEEE80211_AID(ni->ni_associd) != 0)
		return 0;
	if (ni != ni->ni_vap->iv_bss)
		return 0;

	return 1;
}

static void qdrv_pktlogger_prepare_vis_node(struct ieee80211_node_table *nt,
							struct qdrv_netdebug_vision *p_vision)
{
	struct ieee80211_node *ni = NULL;
	struct qdrv_vap *qv = NULL;
	unsigned int node_count = p_vision->node_count;
	struct qdrv_vision_node_stats *node_stats;
	struct qtn_node_shared_stats  *rxss;

	IEEE80211_NODE_LOCK_IRQ(nt);
	TAILQ_FOREACH(ni, &nt->nt_node, ni_list) {
		if (qdrv_is_vap_node(ni))
			continue;
		if (node_count >= QTN_ASSOC_LIMIT)
			break;
		node_stats = &p_vision->node_data[node_count];

		qv = container_of(ni->ni_vap, struct qdrv_vap, iv);
		node_stats->vap_index = qv->devid;

		memcpy(node_stats->macaddr, ni->ni_macaddr, sizeof(node_stats->macaddr));
		if (!ni->ni_shared_stats)
			continue;
		rxss = ni->ni_shared_stats;
		node_stats->tx_bytes = rxss->qtn_tx_bytes;
		node_stats->rx_bytes = rxss->qtn_rx_bytes;
		node_stats->rssi_dbm =
			rxss->rx[STATS_SU].rssi_dbm_smoothed[QTN_NODE_STATS_RSSI_AVE];

		node_count++;
	}
	IEEE80211_NODE_UNLOCK_IRQ(nt);

	p_vision->node_count = node_count;
}

static void qdrv_pktlogger_vision_send(unsigned long data)
{
	struct qdrv_wlan *qw = (struct qdrv_wlan *) data;
	struct qdrv_pktlogger_types_tbl *tbl = NULL;
	struct qdrv_netdebug_vision *p_vision = NULL;
	struct qdrv_mac *mac = NULL;
	struct ieee80211_node_table *nt = NULL;
	size_t pkt_size;
	const size_t pkt_size_max = sizeof(*p_vision) + QTN_ASSOC_LIMIT *
					sizeof(struct qdrv_vision_node_stats);


	tbl = qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_VISION);
	if (!tbl || !(qw->pktlogger.flag & BIT(QDRV_NETDEBUG_TYPE_VISION)))
		return;
	if (tbl->interval)
		mod_timer(&qw->pktlogger.vision_timer, jiffies + (tbl->interval * HZ));

	p_vision = qdrv_pktlogger_alloc_buffer(tbl->name, pkt_size_max);
	if (!p_vision)
		return;

	mac = qw->mac;
	qdrv_pktlogger_prepare_vis_vap(mac, p_vision);
	nt = qdrv_pktlogger_nt_get(mac);
	qdrv_pktlogger_prepare_vis_node(nt, p_vision);


	pkt_size = sizeof(*p_vision) + p_vision->node_count * sizeof(struct qdrv_vision_node_stats);
	qdrv_pktlogger_hdr_init(qw, &p_vision->ndb_hdr, QDRV_NETDEBUG_TYPE_VISION, pkt_size);
	qdrv_pktlogger_send(p_vision, pkt_size);
}

static int qdrv_pktlogger_start_vision(struct qdrv_wlan *qw)
{
	struct qdrv_pktlogger_types_tbl *tbl;

	tbl = qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_VISION);
	if (!tbl)
		return -1;

	if (qw->pktlogger.flag & BIT(QDRV_NETDEBUG_TYPE_VISION))
		return 0;

	init_timer(&qw->pktlogger.vision_timer);
	qw->pktlogger.vision_timer.function = qdrv_pktlogger_vision_send;
	qw->pktlogger.vision_timer.data = (unsigned long)qw;
	qw->pktlogger.vision_timer.expires = jiffies + (tbl->interval * HZ);
	add_timer(&qw->pktlogger.vision_timer);

	qw->pktlogger.flag |= BIT(QDRV_NETDEBUG_TYPE_VISION);
	pr_info("Vision stats is enabled\n");

	return 0;
}

static void qdrv_pktlogger_stop_vision(struct qdrv_wlan *qw)
{
	struct qdrv_pktlogger_types_tbl *tbl;

	tbl = qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_VISION);
	if (!tbl || !(qw->pktlogger.flag & BIT(QDRV_NETDEBUG_TYPE_VISION)))
		return;

	del_timer(&qw->pktlogger.stats_timer);
	qw->pktlogger.flag &= (~BIT(QDRV_NETDEBUG_TYPE_VISION));
	pr_info("Vision stats is disabled\n");
}

static void qdrv_pktlogger_send_iwevent(void *data, int len)
{
	struct qdrv_wlan *qw;
	struct qdrv_netdebug_iwevent* hdr;
	int payloadlen;

	if (g_pktlogger_p) {
		qw = g_pktlogger_p->qw;
	} else {
		printk("Pktlogger is not ready\n");
		return;
	}

	hdr = qdrv_pktlogger_alloc_buffer("iwevent", sizeof(*hdr));
	if (hdr == NULL) {
		return;
	}

	if (len > sizeof(hdr->iwevent_data))
		len = sizeof(hdr->iwevent_data);

	payloadlen = sizeof(struct qdrv_pktlogger_hdr) + len;

	qdrv_pktlogger_hdr_init(qw, &hdr->ndb_hdr, QDRV_NETDEBUG_TYPE_IWEVENT, payloadlen);
	memcpy(hdr->iwevent_data, data, len);
	qdrv_pktlogger_send(hdr, payloadlen);
}

/* Netlink query for the pktlogger compressed structures. */
static int
qdrv_pktlogger_create_pktlogger_data(struct qdrv_wlan *qw, char *p_buf, int buf_len)
{
	struct sk_buff *skb_out;
	struct nlmsghdr *nlho;
	void *p_pkt;
	int res = -1;
	skb_out = nlmsg_new(buf_len, GFP_KERNEL);
	if (skb_out) {
		nlho = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, buf_len, 0);
		NETLINK_CB(skb_out).dst_group = 0;
		p_pkt = nlmsg_data(nlho);
		memcpy(p_pkt, p_buf, buf_len);
		res = nlmsg_unicast(g_pktlogger_p->netlink_socket, skb_out, 12345);
	}
	return res;
}

static int
qdrv_pktlogger_max_radio_supported(void)
{
	return 1;
}

static int
qdrv_pktlogger_config_flag_enabled(struct pktlogger_nl_pktlog_config_t *p_cur_pktconfig)
{
	return p_cur_pktconfig->flags & 0x1;
}

static void
qdrv_pktlogger_config_flag_enable(struct pktlogger_nl_pktlog_config_t *p_cur_pktconfig)
{
	p_cur_pktconfig->flags |= 0x1;
}

static int
qdrv_pktlogger_runtime_flag_enabled(struct qdrv_wlan *qw, int type)
{
	return qw->pktlogger.flag & BIT(type);
}

static int
qdrv_pktlogger_config_interval_sanitise(struct pktlogger_nl_pktlog_config_t *p_cur_pktconfig)
{
	if (p_cur_pktconfig->rate > 180) {
		return 180;
	}
	if (p_cur_pktconfig->rate < 1) {
		return 1;
	}
	return p_cur_pktconfig->rate;
}

static void
qdrv_pktlogger_set_single(struct qdrv_wlan *qw, uint32_t radio_index, struct pktlogger_nl_pktlog_config_t *p_cur_pktconfig)
{
	struct qdrv_pktlogger_types_tbl *tbl = NULL;
	uint32_t this_type = p_cur_pktconfig->type;
	tbl = qdrv_pktlogger_get_tbls_by_id(this_type);
	if (tbl) {
		int to_enable = qdrv_pktlogger_config_flag_enabled(p_cur_pktconfig);
		int is_enabled = qdrv_pktlogger_runtime_flag_enabled(qw, this_type);
		tbl->interval = qdrv_pktlogger_config_interval_sanitise(p_cur_pktconfig);
		tbl->history = p_cur_pktconfig->history;
		if (to_enable && !is_enabled) {
			/* Enable - currently disabled */
			if (tbl->start) {
				printk("Enabling %s logger, period %d\n", tbl->name, tbl->interval);
				tbl->start(qw);
			}
		} else if (!to_enable && is_enabled) {
			/* Disable - currently enabled */
			if (tbl->stop) {
				printk("Disabling %s logger\n", tbl->name);
				tbl->stop(qw);
			}
		}
	}
}

static void
qdrv_pktlogger_set_config(struct qdrv_wlan *qw, struct pktlogger_nl_config_set_t *p_s_conf)
{
	int this_radio_idx = 0;
	struct pktlogger_nl_config_t *p_conf = &p_s_conf->config;
	uint32_t rcontrol = p_conf->rcontrol;

	while (rcontrol) {
		if (rcontrol & 0x1) {
			uint32_t radio_config_count;
			struct pktlogger_nl_radio_config_t *p_cur_radio = &p_conf->per_radio[this_radio_idx];
			int i = 0;
			radio_config_count = p_cur_radio->pktlog_ver_cnt & 0xFF;
			/* Configure the radio appropriately */
			for (i = 0; i < radio_config_count && i < ARRAY_SIZE(p_cur_radio->pktlog_configs); i++) {
				struct pktlogger_nl_pktlog_config_t *p_cur_pktconfig = &p_cur_radio->pktlog_configs[i];
				qdrv_pktlogger_set_single(qw, this_radio_idx, p_cur_pktconfig);
			}
		}
		/* Next radio */
		rcontrol >>= 1;
		this_radio_idx++;
		if (this_radio_idx >= qdrv_pktlogger_max_radio_supported()) {
			break;
		}
	}
}

static void
qdrv_pktlogger_get_one_config(struct qdrv_wlan *qw, struct pktlogger_nl_pktlog_config_t *p_cur_pktconfig, struct qdrv_pktlogger_types_tbl *tbl)
{
	p_cur_pktconfig->type = tbl->id;

	if (qw->pktlogger.flag & BIT(tbl->id)) {
		qdrv_pktlogger_config_flag_enable(p_cur_pktconfig);
	}
	if (tbl->struct_vsize) {
		if (tbl->struct_vsize == 0xFFFF) {
			p_cur_pktconfig->flags |= 0x4;
		} else {
			p_cur_pktconfig->flags |= 0x2;
			p_cur_pktconfig->struct_vsize = tbl->struct_vsize;
		}
	}
	p_cur_pktconfig->struct_bsize = tbl->struct_bsize;
	p_cur_pktconfig->history = tbl->history;
	strncpy(&p_cur_pktconfig->name[0], &tbl->name[0], sizeof(p_cur_pktconfig->name));
	p_cur_pktconfig->name[sizeof(p_cur_pktconfig->name) - 1] = '\0';
	p_cur_pktconfig->rate = tbl->interval;
}

static void
qdrv_pktlogger_get_config_one(struct qdrv_wlan *qw, struct pktlogger_nl_config_one_t *p_conf, uint32_t radio_index, uint32_t ptype)
{
	struct pktlogger_nl_pktlog_config_t *p_cur_pktconfig = &p_conf->config;
	struct qdrv_pktlogger_types_tbl *tbl = NULL;

	memset(p_conf, 0, sizeof(*p_conf));
	p_conf->radio_index = radio_index;
	tbl = qdrv_pktlogger_get_tbls_by_id(ptype);

	if (tbl) {
		qdrv_pktlogger_get_one_config(qw, p_cur_pktconfig, tbl);
	} else {
		p_cur_pktconfig->flags = 0x8000;
	}
}

static void
qdrv_pktlogger_get_config(struct qdrv_wlan *qw, struct pktlogger_nl_config_t *p_conf)
{
	struct qdrv_pktlogger *p_pktlogger = &qw->pktlogger;
	struct pktlogger_nl_radio_config_t *p_cur_radio;
	struct pktlogger_nl_pktlog_config_t *p_cur_pktconfig;
	int i = 0;
	int pktcount = 0;

	memset(p_conf, 0, sizeof(*p_conf));

	p_conf->rev = 0;
	if (!qw->mac->vnet[0]) {
		p_conf->rcontrol = 0; /* Interface not enabled */
		return;
	}
	p_conf->rcontrol = 0x1;
	p_cur_radio = &p_conf->per_radio[0];
	p_cur_radio->destip = p_pktlogger->dst_ip;
	p_cur_radio->srcip = p_pktlogger->src_ip;
	p_cur_radio->destport = p_pktlogger->dst_port;
	p_cur_radio->srcport = p_pktlogger->src_port;
	memcpy(&p_cur_radio->destmac[0], &p_pktlogger->dst_addr[0], sizeof(p_cur_radio->destmac));
	memcpy(&p_cur_radio->srcmac[0], &p_pktlogger->src_addr[0], sizeof(p_cur_radio->srcmac));
	strncpy(&p_cur_radio->radioname[0], qw->mac->vnet[0]->name, sizeof(p_cur_radio->radioname));
	p_cur_radio->radioname[sizeof(p_cur_radio->radioname) - 1] = '\0';
	p_cur_pktconfig = &p_cur_radio->pktlog_configs[0];
	for (i = 0; i < ARRAY_SIZE(p_cur_radio->pktlog_configs); i++) {
		struct qdrv_pktlogger_types_tbl *tbl = NULL;
		tbl = qdrv_pktlogger_get_tbls_by_id(i);
		if (tbl) {
			qdrv_pktlogger_get_one_config(qw, p_cur_pktconfig, tbl);
			p_cur_pktconfig++;
			pktcount++;
		}
	}
	p_cur_radio->pktlog_ver_cnt = pktcount;
}

/* Netlink query for a single pktlogger configuration structure */
static struct sk_buff *
qdrv_pktlogger_create_config_query_one(struct qdrv_wlan *qw, struct pktlogger_nl_query_t *p_query)
{
	struct sk_buff *skb_out;
	struct nlmsghdr *nlho;
	struct pktlogger_nl_query_t *p_outq;
	struct pktlogger_nl_config_one_t *p_outconf;
	int msg_size = sizeof(*p_outq) + sizeof(*p_outconf);

	/* Ensure sanity of input */
	if (p_query->arg1 >= qdrv_pktlogger_max_radio_supported()) {
		return NULL;
	}
	//printk("Create config\n");
	skb_out = nlmsg_new(msg_size, GFP_KERNEL);
	if (skb_out) {
		nlho = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
		NETLINK_CB(skb_out).dst_group = 0;
		p_outq = nlmsg_data(nlho);
		p_outconf = (struct pktlogger_nl_config_one_t *)&p_outq->data[0];
		memcpy(p_outq, p_query, sizeof(*p_outq));
		p_outq->hdr.mlen = sizeof(*p_outconf);
		qdrv_pktlogger_get_config_one(qw, p_outconf, p_query->arg1, p_query->arg2);
	}
	return skb_out;
}

/* Netlink query for the pktlogger config for all radios */
static struct sk_buff *
qdrv_pktlogger_create_config_query(struct qdrv_wlan *qw, struct pktlogger_nl_query_t *p_query)
{
	struct sk_buff *skb_out;
	struct nlmsghdr *nlho;
	struct pktlogger_nl_query_t *p_outq;
	struct pktlogger_nl_config_t *p_outconf;
	int msg_size = sizeof(*p_outq) + sizeof(*p_outconf);
	skb_out = nlmsg_new(msg_size, GFP_KERNEL);
	if (skb_out) {
		nlho = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
		NETLINK_CB(skb_out).dst_group = 0;
		p_outq = nlmsg_data(nlho);
		p_outconf = (struct pktlogger_nl_config_t *)&p_outq->data[0];
		memcpy(p_outq, p_query, sizeof(*p_outq));
		p_outq->hdr.mlen = sizeof(*p_outconf);
		qdrv_pktlogger_get_config(qw, p_outconf);
	}
	return skb_out;
}

/* Netlink query for the pktlogger compressed structures. */
static struct sk_buff *
qdrv_pktlogger_create_struct_query(struct qdrv_wlan *qw, struct pktlogger_nl_query_t *p_query)
{
	struct sk_buff *skb_out;
	struct nlmsghdr *nlho;
	int msg_size = sizeof(pktlogger_structs) + sizeof(*p_query);
	struct pktlogger_nl_query_t *p_outq;
	void *p_structstart;
	skb_out = nlmsg_new(msg_size, GFP_KERNEL);
	if (skb_out) {
		nlho = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
		NETLINK_CB(skb_out).dst_group = 0;
		p_outq = nlmsg_data(nlho);
		p_structstart = &p_outq->data[0];
		memcpy(p_outq, p_query, sizeof(*p_outq));
		p_outq->hdr.mlen = sizeof(pktlogger_structs);
		memcpy(p_structstart, pktlogger_structs, sizeof(pktlogger_structs));
	}
	return skb_out;
}

/* Generic query handler */
static void qdrv_pktlogger_netlink_query(struct qdrv_wlan *qw, struct nlmsghdr *nlh)
{
	int pid;
	int res = 0;
	struct sk_buff *skb_out = NULL;
	struct pktlogger_nl_query_t *p_query = (struct pktlogger_nl_query_t *)nlmsg_data(nlh);
	pid = nlh->nlmsg_pid;

	switch (p_query->query_num) {

	case PKTLOGGER_QUERY_STRUCT:
		skb_out = qdrv_pktlogger_create_struct_query(qw, p_query);
		break;
	case PKTLOGGER_QUERY_CONFIG:
		skb_out = qdrv_pktlogger_create_config_query(qw, p_query);
		break;
	case PKTLOGGER_QUERY_CONFIG_ONE:
		skb_out = qdrv_pktlogger_create_config_query_one(qw, p_query);
		break;
	default:
		printk("Unknown query (%d)\n", p_query->query_num);
		break;
	}

	if (skb_out) {
		res = nlmsg_unicast(g_pktlogger_p->netlink_socket, skb_out, pid);
	}
	if (res < 0)
		printk("Error sending msg to uspace\n");
}

static void
qdrv_pktlogger_netlink_config_one(struct qdrv_wlan *qw, struct nlmsghdr *nlh)
{
	struct pktlogger_nl_config_oneset_t *p_oconfig = (struct pktlogger_nl_config_oneset_t *)nlmsg_data(nlh);
	struct pktlogger_nl_pktlog_config_t *p_config = &p_oconfig->config.config;

	qdrv_pktlogger_set_single(qw, p_oconfig->config.radio_index, p_config);
}

static void
qdrv_pktlogger_netlink_config(struct qdrv_wlan *qw, struct nlmsghdr *nlh)
{
	struct pktlogger_nl_config_set_t *p_config = (struct pktlogger_nl_config_set_t *)nlmsg_data(nlh);

	qdrv_pktlogger_set_config(qw, p_config);
}

/* Pktlogger netlink message incoming */
static void qdrv_pktlogger_netlink_msg(struct qdrv_wlan *qw, struct nlmsghdr *nlh)
{
	struct pktlogger_nl_hdr_t *p_hdr = (struct pktlogger_nl_hdr_t *)nlmsg_data(nlh);

	if (p_hdr->magic != PKTLOGGER_MSG_MAGIC) {
		printk("Invalid magic in pktlogger netlink msg\n");
		return;
	}
	switch(p_hdr->mtype) {

	case PKTLOGGER_NETLINK_MTYPE_QUERY:
		qdrv_pktlogger_netlink_query(qw, nlh);
		break;
	case PKTLOGGER_NETLINK_MTYPE_CONFIG:
		qdrv_pktlogger_netlink_config(qw, nlh);
		break;
	case PKTLOGGER_NETLINK_MTYPE_CONFIG_ONE:
		qdrv_pktlogger_netlink_config_one(qw, nlh);
		break;
	default:
		printk("Unknown msg type %d\n", p_hdr->mtype);
		break;
	}
}

static void qdrv_pktlogger_recv_msg(struct sk_buff *skb)
{
	struct nlmsghdr *nlh  = (struct nlmsghdr*)skb->data;

	DBGPRINTF(DBG_LL_DEBUG, QDRV_LF_PKTLOGGER,
			"%s line %d Netlink received pid:%d, size:%d, type:%d\n",
			__FUNCTION__, __LINE__, nlh->nlmsg_pid, nlh->nlmsg_len, nlh->nlmsg_type);

	switch (nlh->nlmsg_type) {
		case QDRV_NETDEBUG_TYPE_IWEVENT:
			if (g_pktlogger_p->flag & BIT(QDRV_NETDEBUG_TYPE_IWEVENT)) {
				qdrv_pktlogger_send_iwevent(skb->data + sizeof(struct nlmsghdr),
					nlh->nlmsg_len);
			}
			break;

		case QDRV_NETDEBUG_TYPE_SYSMSG:
			qdrv_control_sysmsg_send(g_pktlogger_p->qw,
				(char *)(skb->data + sizeof(struct nlmsghdr)),
				nlh->nlmsg_len, 0);
			break;
		case QDRV_NETDEBUG_TYPE_PKTLOGGER:
			qdrv_pktlogger_netlink_msg(g_pktlogger_p->qw, nlh);
			break;

		default:
			printk("%s line %d Netlink Invalid type %d\n",
				__FUNCTION__, __LINE__, nlh->nlmsg_type);
			break;
	}
}

static int qdrv_pktlogger_start_netlink(struct qdrv_wlan *qw)
{
	qw->pktlogger.netlink_ref++;
	if (qw->pktlogger.netlink_socket == NULL) {
		qw->pktlogger.netlink_socket = netlink_kernel_create(&init_net,
				QDRV_NETLINK_PKTLOGGER, 0, qdrv_pktlogger_recv_msg, NULL, THIS_MODULE);
		if (qw->pktlogger.netlink_socket == NULL) {
			DBGPRINTF_E("Error creating netlink socket.\n");
			return -1;
		}
	}
	return 0;
}

static void qdrv_pktlogger_stop_netlink(struct qdrv_wlan *qw)
{
	qw->pktlogger.netlink_ref--;
	if ((qw->pktlogger.netlink_ref == 0) && qw->pktlogger.netlink_socket) {
			netlink_kernel_release(qw->pktlogger.netlink_socket);
			qw->pktlogger.netlink_socket = NULL;
	}
}

static int qdrv_pktlogger_start_iwevent(struct qdrv_wlan *qw)
{
	struct qdrv_pktlogger_types_tbl *tbl = NULL;

	if ((qw->pktlogger.flag & BIT(QDRV_NETDEBUG_TYPE_IWEVENT)) == 0) {
		tbl = qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_IWEVENT);
		if (!tbl) {
			return -1;
		}
		qw->pktlogger.flag |= BIT(QDRV_NETDEBUG_TYPE_IWEVENT);
		return qdrv_pktlogger_start_netlink(qw);
	} else {
		return 0;
	}
}

static void qdrv_pktlogger_stop_iwevent(struct qdrv_wlan *qw)
{
	if ((qw->pktlogger.flag & BIT(QDRV_NETDEBUG_TYPE_IWEVENT))) {
		qw->pktlogger.flag &= (~BIT(QDRV_NETDEBUG_TYPE_IWEVENT));
		qdrv_pktlogger_stop_netlink(qw);
	}
}

static void qdrv_pktlogger_sysmsg_work(struct work_struct *work)
{
	struct qdrv_pktlogger *pktlogger = container_of(to_delayed_work(work),
						struct qdrv_pktlogger, sysmsg_work);
	struct qdrv_pktlogger_types_tbl *tbl =
			qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_SYSMSG);

	if (!tbl)
		return;

	qdrv_control_sysmsg_send(g_pktlogger_p->qw, NULL, 0, 1);
	if (tbl->interval)
		schedule_delayed_work(&pktlogger->sysmsg_work, tbl->interval * HZ);
}

static int qdrv_pktlogger_start_sysmsg(struct qdrv_wlan *qw)
{
	struct qdrv_pktlogger_types_tbl *tbl = NULL;

	spin_lock(&qw->pktlogger.sysmsg_lock);
	if (qw->pktlogger.flag & BIT(QDRV_NETDEBUG_TYPE_SYSMSG)) {
		spin_unlock(&qw->pktlogger.sysmsg_lock);
		return 0;
	}

	tbl = qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_SYSMSG);
	if (!tbl) {
		spin_unlock(&qw->pktlogger.sysmsg_lock);
		return -1;
	}

	qw->pktlogger.flag |= BIT(QDRV_NETDEBUG_TYPE_SYSMSG);
	schedule_delayed_work(&qw->pktlogger.sysmsg_work, tbl->interval * HZ);
	spin_unlock(&qw->pktlogger.sysmsg_lock);

	return qdrv_pktlogger_start_netlink(qw);
}

static void qdrv_pktlogger_stop_sysmsg(struct qdrv_wlan *qw)
{
	spin_lock(&qw->pktlogger.sysmsg_lock);
	if (!(qw->pktlogger.flag & BIT(QDRV_NETDEBUG_TYPE_SYSMSG))) {
		spin_unlock(&qw->pktlogger.sysmsg_lock);
		return;
	}

	qdrv_control_sysmsg_send(qw, NULL, 0, 1);

	qw->pktlogger.flag &= (~BIT(QDRV_NETDEBUG_TYPE_SYSMSG));
	cancel_delayed_work_sync(&qw->pktlogger.sysmsg_work);
	spin_unlock(&qw->pktlogger.sysmsg_lock);

	qdrv_pktlogger_stop_netlink(qw);
}

static void qdrv_pktlogger_ratedebug_send(unsigned long data)
{
	struct qdrv_wlan *qw = (struct qdrv_wlan *)data;
	void *databuf;
	struct qdrv_netdebug_rate *rate_stats;
	struct qtn_phy_stats *phy_stats =
			(struct qtn_phy_stats *)qw->pktlogger.stats_uc_phy_stats_ptr;
	struct muc_stat_rates *muc_rx_rates_p =
			(struct muc_stat_rates *)qw->pktlogger.stats_uc_rx_rate_ptr;
	struct qtn_rate_tx_stats_per_sec *tx_rate_stats =
			(struct qtn_rate_tx_stats_per_sec *)qw->pktlogger.stats_uc_tx_rate_ptr;
	uint32_t *su_rates_read_ptr = qw->pktlogger.stats_uc_su_rates_read_ptr;
	uint32_t *mu_rates_read_ptr = qw->pktlogger.stats_uc_mu_rates_read_ptr;
	struct muc_stat_rates *rx_rates_prev = qw->pktlogger.rx_ratelog_pre;
	struct muc_stat_rates *rx_rates_curr = qw->pktlogger.rx_ratelog_cur;
	uint32_t curr_index;
	int i;
	int rate_entry = 0;
	struct qdrv_pktlogger_types_tbl *tbl =
			qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_RATE);

	if (!tbl) {
		return;
	}

	databuf = qdrv_pktlogger_alloc_buffer("rate", sizeof(*rate_stats));
	if (databuf == NULL) {
		return;
	}
	rate_stats = (struct qdrv_netdebug_rate *) databuf;
	qdrv_pktlogger_hdr_init(qw, &rate_stats->ndb_hdr, QDRV_NETDEBUG_TYPE_RATE,
			sizeof(*rate_stats));

	qdrv_pktlogger_flush_data(qw);

	/*
	 * Copy assuming all rate adaptions for this second collected. The
	 * parser will need to check the sequence numbers to detect missed data.
	 */
	memcpy(&rate_stats->rate_su_tx_stats, tx_rate_stats->stats_su,
		sizeof(rate_stats->rate_su_tx_stats));
	memcpy(&rate_stats->rate_mu_tx_stats, tx_rate_stats->stats_mu,
		sizeof(rate_stats->rate_mu_tx_stats));
	/* Tell MUC the rate tx stats can be re-written */
	*su_rates_read_ptr = 1;
	*mu_rates_read_ptr = 1;

	/*
	 * Get rates from the MuC and diff from previous values. Copy as many rates as
	 * possible, starting from the last rate to prefer higher rates.
	 */
	memcpy(rx_rates_curr, muc_rx_rates_p, sizeof(*rx_rates_curr));

	for (i = ARRAY_SIZE(rx_rates_curr->mcs_11ac_su) - 1; i >= 0; i--) {
		if (rate_entry >= (ARRAY_SIZE(rate_stats->rate_gen_stats.rx_mcs)))
			break;

		if (rx_rates_curr->mcs_11ac_su[i] == rx_rates_prev->mcs_11ac_su[i])
			continue;

		rate_stats->rate_gen_stats.rx_mcs_rates[rate_entry] =
			(uint16_t)((QTN_PHY_STATS_MODE_11AC << 8) | i);

		rate_stats->rate_gen_stats.rx_mcs[rate_entry] =
			rx_rates_curr->mcs_11ac_su[i] - rx_rates_prev->mcs_11ac_su[i];
		rate_entry++;
	}

	for (i = ARRAY_SIZE(rx_rates_curr->mcs_11n) - 1; i >= 0; i--) {
		if (rate_entry >= (ARRAY_SIZE(rate_stats->rate_gen_stats.rx_mcs)))
			break;

		if (rx_rates_curr->mcs_11n[i] == rx_rates_prev->mcs_11n[i])
			continue;

		rate_stats->rate_gen_stats.rx_mcs_rates[rate_entry] = i;

		rate_stats->rate_gen_stats.rx_mcs[rate_entry] =
			rx_rates_curr->mcs_11n[i] - rx_rates_prev->mcs_11n[i];
		rate_entry++;
	}
	qw->pktlogger.rx_ratelog_pre = rx_rates_curr;
	qw->pktlogger.rx_ratelog_cur = rx_rates_prev;

	/* Find the current index into the phy stats */
	curr_index = (phy_stats->curr_buff - 1 + NUM_LOG_BUFFS) % NUM_LOG_BUFFS;
	if ((phy_stats->stat_buffs[curr_index].tstamp & 0x01) == 0) {
		u_int32_t *p_evms = &rate_stats->rate_gen_stats.rx_evm[0];
		int32_t evm_int, evm_frac;

		for (i = 0; i < QDRV_NUM_RF_STREAMS; i++) {
			convert_evm_db(phy_stats->stat_buffs[curr_index].rx_phy_stats.last_rssi_evm[i],
				       phy_stats->stat_buffs[curr_index].rx_phy_stats.last_rxsym,
				       &evm_int,
				       &evm_frac);

			*p_evms++ = (evm_frac & 0xffff) | (evm_int << 16);
		}
	} else {
		memset(rate_stats->rate_gen_stats.rx_evm, 0,
			sizeof(rate_stats->rate_gen_stats.rx_evm));
	}

	rate_stats->rate_gen_stats.rx_crc =
			phy_stats->stat_buffs[curr_index].rx_phy_stats.cnt_mac_crc;
	rate_stats->rate_gen_stats.rx_sp_errors =
			phy_stats->stat_buffs[curr_index].rx_phy_stats.cnt_sp_fail;
	rate_stats->rate_gen_stats.rx_lp_errors =
			phy_stats->stat_buffs[curr_index].rx_phy_stats.cnt_lp_fail;

	qdrv_pktlogger_send(rate_stats, sizeof(*rate_stats));

	/* refresh timer */
	mod_timer(&qw->pktlogger.rate_timer, jiffies + (tbl->interval * HZ));
}

static int qdrv_pktlogger_start_rate(struct qdrv_wlan *qw)
{
	struct timer_list *timer = &qw->pktlogger.rate_timer;
	struct qdrv_pktlogger_types_tbl *tbl =
				qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_RATE);
	del_timer(&qw->pktlogger.rate_timer);

	if (!tbl) {
		return -1;
	}
	if (qdrv_pktlogger_map(qw) < 0) {
		return -1;
	}

	init_timer(timer);
	timer->function = qdrv_pktlogger_ratedebug_send;
	timer->data = (unsigned long)qw;
	timer->expires = jiffies + (tbl->interval * HZ);
	add_timer(timer);

	/* Set the flag to clear old stats */
	*qw->pktlogger.stats_uc_su_rates_read_ptr = 1;
	*qw->pktlogger.stats_uc_mu_rates_read_ptr = 1;
	qw->pktlogger.flag |= BIT(QDRV_NETDEBUG_TYPE_RATE);
	printk("Ratedebug is enabled\n");
	return 0;
}

static void qdrv_pktlogger_stop_rate(struct qdrv_wlan *qw)
{
	del_timer(&qw->pktlogger.rate_timer);
	qw->pktlogger.flag &= (~BIT(QDRV_NETDEBUG_TYPE_RATE));
	printk("Ratedebug is disabled\n");
}

static void qdrv_pktlogger_mem_send(unsigned long data)
{
	struct qdrv_wlan *qw = (struct qdrv_wlan *)data;
	struct qdrv_netdebug_mem *stats;
	struct qdrv_pktlogger_types_tbl *tbl = NULL;
	u8 *p;
	int i;
	int j;
	u32 *remap_addr;
	void *data_buf;
	u32 *local_buf;

	tbl = qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_MEM);
	if (!tbl) {
		return;
	}
	if (qw->pktlogger.mem_wps_read_buf == NULL)
		return;
	data_buf = qdrv_pktlogger_alloc_buffer("mem", sizeof(*stats));
	if (data_buf == NULL) {
		return;
	}
	stats = (struct qdrv_netdebug_mem *) data_buf;
	qdrv_pktlogger_hdr_init(qw, &stats->ndb_hdr, QDRV_NETDEBUG_TYPE_MEM,
			sizeof(*stats));

	/* copy from each location into the packet */
	p = &stats->stvec_data[0];

	/* BB registers can be registered into memdebug */

	for (i = 0; i < qw->pktlogger.mem_wp_index; i++) {
		memcpy(p, &qw->pktlogger.mem_wps[i].addr, sizeof(qw->pktlogger.mem_wps[i].addr));
		p += sizeof(qw->pktlogger.mem_wps[i].addr);

		memcpy(p, &qw->pktlogger.mem_wps[i].size, sizeof(qw->pktlogger.mem_wps[i].size));
		p += sizeof(qw->pktlogger.mem_wps[i].size);

		remap_addr = qw->pktlogger.mem_wps[i].remap_addr;
		local_buf = qw->pktlogger.mem_wps_read_buf;
		qtn_bb_mutex_enter(QTN_LHOST_SOC_CPU);
		for (j = 0; j < qw->pktlogger.mem_wps[i].size; j++) {
			local_buf[j] = *remap_addr;
			remap_addr++;
		}
		qtn_bb_mutex_leave(QTN_LHOST_SOC_CPU);
		memcpy(p, local_buf, j * sizeof(u32));
	}


	/* send completed packet */
	qdrv_pktlogger_send(stats, sizeof(*stats));

	/* refresh timer */
	mod_timer(&qw->pktlogger.mem_timer, jiffies + (tbl->interval * HZ));
}

static int qdrv_pktlogger_start_mem(struct qdrv_wlan *qw) {
	struct timer_list *timer = &qw->pktlogger.mem_timer;
	struct qdrv_pktlogger_types_tbl *tbl = NULL;

	if (!qw->pktlogger.mem_wp_index) {
		DBGPRINTF_E("no watchpoints defined! not starting\n");
		return -1;
	}

	tbl = qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_MEM);
	if (!tbl) {
		return -1;
	}
	del_timer(timer);
	init_timer(timer);
	timer->function = qdrv_pktlogger_mem_send;
	timer->data = (unsigned long) qw;
	timer->expires = jiffies + (tbl->interval * HZ);

	add_timer(timer);
	qw->pktlogger.flag |= BIT(QDRV_NETDEBUG_TYPE_MEM);
	return 0;
}

static void qdrv_pktlogger_stop_mem(struct qdrv_wlan *qw) {
	int i;

	del_timer(&qw->pktlogger.mem_timer);
	for (i = 0; i < qw->pktlogger.mem_wp_index; i++) {
		iounmap(qw->pktlogger.mem_wps[i].remap_addr);
	}
	qw->pktlogger.mem_wp_index = 0;
	qw->pktlogger.flag &= (~BIT(QDRV_NETDEBUG_TYPE_MEM));
}

#ifdef CONFIG_QVSP
/*
 * Forward VSP stats to the netdebug target
 */
static void qdrv_pktlogger_vspdebug_send(void *data, void *vsp_data, uint32_t size)
{
	struct qdrv_wlan *qw = (struct qdrv_wlan *)data;
	void *databuf;
	struct qdrv_pktlogger_hdr *ndb_hdr;
	databuf = qdrv_pktlogger_alloc_buffer("vsp", sizeof(struct qdrv_pktlogger_hdr) + size);
	if (databuf == NULL) {
		return;
	}
	ndb_hdr = (struct qdrv_pktlogger_hdr *)databuf;
	qdrv_pktlogger_hdr_init(qw, ndb_hdr,
			QDRV_NETDEBUG_TYPE_VSP, size + sizeof(struct qdrv_pktlogger_hdr));
	memcpy(ndb_hdr + 1, vsp_data, size);

	qdrv_pktlogger_send(databuf, size + sizeof(struct qdrv_pktlogger_hdr));
}

static int qdrv_pktlogger_start_vsp(struct qdrv_wlan *qw)
{
	struct qdrv_pktlogger_types_tbl *tbl = NULL;
	if (qw->qvsp == NULL) {
		DBGPRINTF_E("VSP is not not initialised\n");
		return -1;
	}
	tbl = qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_VSP);
	if (!tbl) {
		return -1;
	}
	qvsp_netdbg_init(qw->qvsp, &qdrv_pktlogger_vspdebug_send, tbl->interval);
	qw->pktlogger.flag |= BIT(QDRV_NETDEBUG_TYPE_VSP);
	printk("VSP netdebug is enabled\n");
	return 0;
}

static void qdrv_pktlogger_stop_vsp(struct qdrv_wlan *qw)
{
	if (qw->qvsp == NULL) {
		DBGPRINTF_E("VSP is not not initialised\n");
		return;
	}
	qvsp_netdbg_exit(qw->qvsp);
	qw->pktlogger.flag &= (~BIT(QDRV_NETDEBUG_TYPE_VSP));
	printk("VSP netdebug is disabled\n");
}
#endif

/*
 * Push radar statistics out on every call
 */
static void qdrv_control_radar_stats_send(void *arg, struct qtn_radar_sample *samples, size_t size)
{
	struct qdrv_wlan *qw = (struct qdrv_wlan *)arg;
	struct qdrv_radar_stats *stats;
	int num_bytes = 0;

	stats = qdrv_pktlogger_alloc_buffer("radar", sizeof(*stats));
	if (stats == NULL) {
		qdrv_radar_register_statcb(NULL, NULL);
		return;
	}

	qdrv_pktlogger_hdr_init(qw, &stats->ndb_hdr, QDRV_NETDEBUG_TYPE_RADAR,
			sizeof(*stats));

	/* Max num of pulses is 116 based on 12 bytes per pulse */
	if (size > QDRV_NETDEBUG_RADAR_MAXPULSE) {
		stats->ndb_hdr.flags |= QDRV_NETDEBUG_FLAGS_TRUNCATED;
		size = QDRV_NETDEBUG_RADAR_MAXPULSE;
	}

	stats->numpulses = size;

	memcpy(stats->pulseinfo, samples, sizeof(*samples) * size);

	int trimlen = QDRV_NETDEBUG_RADAR_PULSESIZE * QDRV_NETDEBUG_RADAR_MAXPULSE - num_bytes;

	qdrv_pktlogger_send(stats, sizeof(*stats) - trimlen);
}

static int qdrv_pktlogger_start_radar(struct qdrv_wlan *qw)
{
	qdrv_radar_register_statcb(qdrv_control_radar_stats_send, (void*)qw);
	qw->pktlogger.flag |= BIT(QDRV_NETDEBUG_TYPE_RADAR);
	return 0;
}

static void qdrv_pktlogger_stop_radar(struct qdrv_wlan *qw)
{
	qdrv_radar_register_statcb(NULL, NULL);
	qw->pktlogger.flag &= (~BIT(QDRV_NETDEBUG_TYPE_RADAR));
}

void add_per_node_phystat(struct qdrv_netdebug_phystats* stats,
	int index, struct ieee80211_node *ni)
{
	struct qdrv_netdebug_per_node_phystats* item =
		&stats->per_node_stats[index];
	memcpy(&item->node_macaddr, &ni->ni_macaddr, sizeof(item->node_macaddr));
	memcpy(&item->per_node_phystats, ni->ni_shared_stats, sizeof(item->per_node_phystats));
}

void qdrv_pktlogger_phystats_send(unsigned long data)
{
	static struct qtn_phy_stats phy_stats;
	static int last_tstamp = 0;
	struct qdrv_wlan* qw = (struct qdrv_wlan *)data;
	struct ieee80211_node_table* nt  = qw ? &qw->ic.ic_sta : NULL;
	struct ieee80211_node* ni;

	struct qdrv_pktlogger_types_tbl *tbl = NULL;
	int i;

	tbl = qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_PHY_STATS);

	if (!(tbl && qw && qw->pktlogger.stats_uc_phy_stats_ptr && nt)) {
		return;
	}

	memcpy(&phy_stats, qw->pktlogger.stats_uc_phy_stats_ptr, sizeof(phy_stats));
	/* Gather statistics */
	/* Why +2:
	 * the "current" stat is the most recently _complete_ stat written
	 * item at current+1 is being written right now and probably not safe to read
	 * item at +2 is the oldest available stat in this circular buffer
	*/
	for ( i = (phy_stats.curr_buff + 2) % NUM_LOG_BUFFS;
		i != phy_stats.curr_buff;
		i = (i+1) % NUM_LOG_BUFFS) {

		struct qtn_stats* curr_log_ptr = &phy_stats.stat_buffs[i];
		if(curr_log_ptr->tstamp > last_tstamp) {
			struct qdrv_netdebug_phystats* phystats;
			/*
			 * we do not know how much nodes will be acquired so
			 * allocate room enough for the worst case
			 */
			int phystats_len = sizeof(*phystats) +
				(QTN_NCIDX_MAX-1) * sizeof(phystats->per_node_stats[0]);

			phystats = qdrv_pktlogger_alloc_buffer("phystats", phystats_len);

			if (phystats != NULL) {
				int node_index = 0;
				IEEE80211_NODE_LOCK_IRQ(nt);
				TAILQ_FOREACH(ni, &nt->nt_node, ni_list) {
					add_per_node_phystat(phystats, node_index, ni);
					node_index++;
				}
				IEEE80211_NODE_UNLOCK_IRQ(nt);

				phystats->per_node_stats_count = node_index;

				/* redefine phystats_len as now we know how much nodes do we have*/
				phystats_len = sizeof(*phystats) +
					(node_index-1) * sizeof(phystats->per_node_stats[0]);

				qdrv_pktlogger_hdr_init(qw, &phystats->ndb_hdr,
					QDRV_NETDEBUG_TYPE_PHY_STATS, phystats_len);

				memcpy(&phystats->stats, curr_log_ptr, sizeof(phystats->stats));

				qdrv_pktlogger_send(phystats, phystats_len);
			}

			last_tstamp = curr_log_ptr->tstamp;
		}
	}

	/* refresh timer */
	mod_timer(&qw->pktlogger.phy_stats_timer, jiffies + (tbl->interval * HZ));
}

static int qdrv_pktlogger_start_phy_stats(struct qdrv_wlan *qw)
{
	struct timer_list *timer = &qw->pktlogger.phy_stats_timer;
	struct qdrv_pktlogger_types_tbl *tbl =
				qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_PHY_STATS);
	del_timer(&qw->pktlogger.phy_stats_timer);

	if (!tbl) {
		printk("unable to find item at QDRV_NETDEBUG_TYPE_PHY_STATS\n");
		return -1;
	}

	if (qdrv_pktlogger_map(qw) < 0)
		return -1;

	init_timer(timer);
	timer->function = qdrv_pktlogger_phystats_send;
	timer->data = (unsigned long)qw;
	timer->expires = jiffies + (tbl->interval * HZ);
	add_timer(timer);

	/* Set the flag to clear old stats */
	qw->pktlogger.flag |= BIT(QDRV_NETDEBUG_TYPE_PHY_STATS);
	printk("phy_stats sending enabled\n");
	return 0;
}

static void qdrv_pktlogger_stop_phy_stats(struct qdrv_wlan *qw)
{
	del_timer(&qw->pktlogger.phy_stats_timer);
	qw->pktlogger.flag &= (~BIT(QDRV_NETDEBUG_TYPE_PHY_STATS));
	printk("phy_stats sending disabled\n");
}

void qdrv_pktlogger_dspstats_send(unsigned long data)
{
	struct qdrv_wlan* qw = (struct qdrv_wlan *)data;
	struct qdrv_mac* mac             = qw ? qw->mac : NULL;

	struct qdrv_pktlogger_types_tbl *tbl = NULL;
	volatile struct qtn_txbf_mbox *txbf_mbox = qtn_txbf_mbox_get();
	struct qdrv_netdebug_dspstats* dspstats;

	tbl = qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_DSP_STATS);

	if (!(tbl && mac)) {
		return;
	}

	dspstats = qdrv_pktlogger_alloc_buffer("dspstats", sizeof(*dspstats));

	if (dspstats != NULL) {
		qdrv_pktlogger_hdr_init(qw, &dspstats->ndb_hdr,
			QDRV_NETDEBUG_TYPE_DSP_STATS, sizeof(*dspstats));
		memcpy(&dspstats->stats, (void *)&txbf_mbox->dsp_stats, sizeof(dspstats->stats));
		qdrv_pktlogger_send(dspstats, sizeof(*dspstats));
	}

	/* refresh timer */
	mod_timer(&qw->pktlogger.dsp_stats_timer, jiffies + (tbl->interval * HZ));
}

static int qdrv_pktlogger_start_dsp_stats(struct qdrv_wlan *qw)
{
	struct timer_list *timer = &qw->pktlogger.dsp_stats_timer;
	struct qdrv_pktlogger_types_tbl *tbl =
				qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_DSP_STATS);
	del_timer(&qw->pktlogger.dsp_stats_timer);

	if (!tbl) {
		printk("unable to find item at QDRV_NETDEBUG_TYPE_DSP_STATS\n");
		return -1;
	}

	init_timer(timer);
	timer->function = qdrv_pktlogger_dspstats_send;
	timer->data = (unsigned long)qw;
	timer->expires = jiffies + (tbl->interval * HZ);
	add_timer(timer);

	/* Set the flag to clear old stats */
	qw->pktlogger.flag |= BIT(QDRV_NETDEBUG_TYPE_DSP_STATS);
	printk("dsp_stats sending enabled\n");
	return 0;
}

static void qdrv_pktlogger_stop_dsp_stats(struct qdrv_wlan *qw)
{
	del_timer(&qw->pktlogger.dsp_stats_timer);
	qw->pktlogger.flag &= (~BIT(QDRV_NETDEBUG_TYPE_DSP_STATS));
	printk("dsp_stats sending disabled\n");
}

void qdrv_pktlogger_core_dump_send(unsigned long data)
{
	struct qdrv_wlan* qw = (struct qdrv_wlan *)data;
	struct qdrv_mac* mac = qw ? qw->mac : NULL;
	struct qdrv_pktlogger_types_tbl *tbl = NULL;
	struct qdrv_netdebug_core_dump *core_dump;
	uint32_t len_copied = 0;

	tbl = qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_CORE_DUMP);
	if (!(tbl && mac)) {
		return;
	}

	core_dump = qdrv_pktlogger_alloc_buffer(tbl->name, tbl->struct_bsize + tbl->struct_vsize);
	if (core_dump) {
		qdrv_copy_core_dump(core_dump->data, sizeof(core_dump->data), &len_copied);
		if (!len_copied) {
			qdrv_pktlogger_free_buffer(core_dump);
			return;
		}

		qdrv_pktlogger_hdr_init(qw, &core_dump->ndb_hdr,
			QDRV_NETDEBUG_TYPE_CORE_DUMP, sizeof(core_dump->ndb_hdr) + len_copied);

		qdrv_pktlogger_send(core_dump, sizeof(*core_dump));
	}
}

static int qdrv_pktlogger_start_core_dump(struct qdrv_wlan *qw)
{
	struct qdrv_pktlogger_types_tbl *tbl =
				qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_CORE_DUMP);

	if (!tbl) {
		printk("Unable to find item at QDRV_NETDEBUG_TYPE_CORE_DUMP\n");
		return -1;
	}

	/* Set the flag to clear old stats */
	qw->pktlogger.flag |= BIT(QDRV_NETDEBUG_TYPE_CORE_DUMP);
	printk("core_dump sending enabled\n");

	/*
	 * Send the core dump, if it exists; it would be sent only once when this type is enabled
	 * ('interval' is ignored)
	 */
	qdrv_pktlogger_core_dump_send((unsigned long) qw);

	return 0;
}

static void qdrv_pktlogger_stop_core_dump(struct qdrv_wlan *qw)
{
	qw->pktlogger.flag &= (~BIT(QDRV_NETDEBUG_TYPE_CORE_DUMP));
	printk("core_dump sending disabled\n");
}

void qdrv_pktlogger_flush_data(struct qdrv_wlan *qw)
{
        int enable = 1;

        qdrv_hostlink_enable_flush_data(qw, enable);

}

static void qdrv_pktlogger_send_node_rate_stats(unsigned long data)
{
	struct qdrv_wlan *qw = (struct qdrv_wlan *) data;
	struct qdrv_pktlogger *pktlogger = &qw->pktlogger;
	struct qdrv_pktlogger_types_tbl *tbl = NULL;
	struct qtn_node_rate_stats *uc_rates_per_node =
			(struct qtn_node_rate_stats *) qw->stats_uc_rates_per_node;
	struct qdrv_netdebug_node_rate_stats *p_node_rate_stats;
	int i;
	int cur;
	int node_count = 0;
	const size_t pkt_size_max = sizeof(*p_node_rate_stats) +
					(QTN_NODE_STAT_RATE_SLOTS) *
					sizeof(struct qdrv_muc_per_node_rates);
	size_t pkt_size;

	tbl = qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_NODE_RATE_STATS);
	if (!tbl)
		return;

	if (tbl->interval)
		mod_timer(&pktlogger->node_rate_stats_timer, jiffies + (tbl->interval * HZ));

	p_node_rate_stats = qdrv_pktlogger_alloc_buffer("node_rate_stats", pkt_size_max);
	if (!p_node_rate_stats)
		return;

	cur = pktlogger->node_ratelog_cur;
	for (i = 0; i < QTN_NODE_STAT_RATE_SLOTS; i++) {
		struct qdrv_muc_per_node_rates *node_stats =
						&p_node_rate_stats->rates_per_node[node_count];
		struct qtn_node_rate_stats *p_ratelog_cur = &pktlogger->node_ratelog[cur][i];
		struct qtn_node_rate_stats *p_ratelog_pre = &pktlogger->node_ratelog[!cur][i];
		struct qtn_node_rate_stats *muc_ratelog = &uc_rates_per_node[i];
		int ratelog_is_tx_pre;
		int ratelog_is_tx_cur;
		int ratelog_mac_changed;

		memcpy(p_ratelog_cur, muc_ratelog, sizeof(*p_ratelog_cur));

		ratelog_is_tx_pre = p_ratelog_pre->slot_flags & QTN_NODE_STAT_SLOT_IS_TX;
		ratelog_is_tx_cur = p_ratelog_cur->slot_flags & QTN_NODE_STAT_SLOT_IS_TX;
		ratelog_mac_changed = !IEEE80211_ADDR_EQ(p_ratelog_pre->macaddr,
								p_ratelog_cur->macaddr);

		/* Clear previous stats if it is not empty and mac or direction changed. */
		if (!IEEE80211_ADDR_NULL(p_ratelog_pre->macaddr) &&
				(ratelog_mac_changed || (ratelog_is_tx_pre != ratelog_is_tx_cur))) {
			memset(p_ratelog_pre, 0, sizeof(*p_ratelog_pre));
		}

		if (p_ratelog_cur->slot_flags & QTN_NODE_STAT_SLOT_ALLOCATED) {
			node_stats->flags = p_ratelog_cur->slot_flags;
			memcpy(node_stats->macaddr, p_ratelog_cur->macaddr,
				sizeof(node_stats->macaddr));
			node_stats->flags = p_ratelog_cur->slot_flags;
			qdrv_pktlogger_prepare_11n_rates(&node_stats->rates,
							 &p_ratelog_cur->rates,
							 &p_ratelog_pre->rates);
			qdrv_pktlogger_prepare_11ac_rates(&node_stats->rates_11ac,
							  &p_ratelog_cur->rates,
							  &p_ratelog_pre->rates);
			node_count++;
		}
	}
	pktlogger->node_ratelog_cur = !cur;

	pkt_size = sizeof(*p_node_rate_stats) + node_count *
		   sizeof(struct qdrv_muc_per_node_rates);
	p_node_rate_stats->node_count = node_count;

	qdrv_pktlogger_hdr_init(qw, &p_node_rate_stats->ndb_hdr,
				QDRV_NETDEBUG_TYPE_NODE_RATE_STATS,
				pkt_size);

	qdrv_pktlogger_send(p_node_rate_stats, pkt_size);
}

static int qdrv_pktlogger_start_node_rate_stats(struct qdrv_wlan *qw)
{
	struct qdrv_pktlogger *pktlogger = &qw->pktlogger;
	struct qdrv_pktlogger_types_tbl *tbl;

	tbl = qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_NODE_RATE_STATS);
	if (!tbl)
		return -1;

	if (qdrv_pktlogger_map(qw) < 0 || !qw->stats_uc_rates_per_node)
		return -1;

	del_timer(&pktlogger->node_rate_stats_timer);
	init_timer(&pktlogger->node_rate_stats_timer);
	pktlogger->node_rate_stats_timer.function = qdrv_pktlogger_send_node_rate_stats;
	pktlogger->node_rate_stats_timer.data = (unsigned long) qw;
	pktlogger->node_rate_stats_timer.expires = jiffies + (tbl->interval * HZ);
	add_timer(&pktlogger->node_rate_stats_timer);

	pktlogger->flag |= BIT(QDRV_NETDEBUG_TYPE_NODE_RATE_STATS);
	pr_info("Enabled node rate stats\n");

	return 0;
}

static void qdrv_pktlogger_stop_node_rate_stats(struct qdrv_wlan *qw)
{
	struct qdrv_pktlogger *pktlogger = &qw->pktlogger;
	struct qdrv_pktlogger_types_tbl *tbl;

	tbl = qdrv_pktlogger_get_tbls_by_id(QDRV_NETDEBUG_TYPE_NODE_RATE_STATS);
	if (!tbl)
		return;

	del_timer(&pktlogger->node_rate_stats_timer);

	pktlogger->flag &= (~BIT(QDRV_NETDEBUG_TYPE_NODE_RATE_STATS));
	pr_info("Disabled node rate stats\n");
}

struct qdrv_pktlogger_types_tbl qdrv_pktlogger_types_tbl_ent[] =
{
		{QDRV_NETDEBUG_TYPE_STATS, "stats",
				qdrv_pktlogger_start_stats, qdrv_pktlogger_stop_stats,
				QDRV_PKTLOGGER_INTERVAL_DFLT_STATS,
				sizeof(struct qdrv_netdebug_stats), 0, 0},
		{QDRV_NETDEBUG_TYPE_RADAR, "radar",
				qdrv_pktlogger_start_radar, qdrv_pktlogger_stop_radar,
				QDRV_PKTLOGGER_INTERVAL_DFLT_NONE,
				sizeof(struct qdrv_radar_stats), 0, 0},
		{QDRV_NETDEBUG_TYPE_TXBF, "txbf", NULL, NULL,
				QDRV_PKTLOGGER_INTERVAL_DFLT_NONE,
				sizeof(struct qdrv_netdebug_txbf), 0, 0},
		{QDRV_NETDEBUG_TYPE_IWEVENT, "iwevent",
				qdrv_pktlogger_start_iwevent, qdrv_pktlogger_stop_iwevent,
				QDRV_PKTLOGGER_INTERVAL_DFLT_NONE,
				sizeof(struct qdrv_netdebug_iwevent), 0xFFFF, 0},
		{QDRV_NETDEBUG_TYPE_SYSMSG, "sysmsg",
				qdrv_pktlogger_start_sysmsg, qdrv_pktlogger_stop_sysmsg,
				QDRV_PKTLOGGER_INTERVAL_DFLT_SYSMSG,
				sizeof(struct qdrv_netdebug_sysmsg), 0xFFFF, 0},
		{QDRV_NETDEBUG_TYPE_MEM, "mem",
				qdrv_pktlogger_start_mem, qdrv_pktlogger_stop_mem,
				QDRV_PKTLOGGER_INTERVAL_DFLT_MEM,
				sizeof(struct qdrv_netdebug_mem), 0, 0},
		{QDRV_NETDEBUG_TYPE_RATE, "rate",
				qdrv_pktlogger_start_rate, qdrv_pktlogger_stop_rate,
				QDRV_PKTLOGGER_INTERVAL_DFLT_RATE,
				sizeof(struct qdrv_netdebug_rate), 0, 0},
#ifdef CONFIG_QVSP
		{QDRV_NETDEBUG_TYPE_VSP, "vsp",
				qdrv_pktlogger_start_vsp, qdrv_pktlogger_stop_vsp,
				QDRV_PKTLOGGER_INTERVAL_DFLT_VSP,
				0, 0, 0},
#endif
		{QDRV_NETDEBUG_TYPE_PHY_STATS, "phy_stats",
				qdrv_pktlogger_start_phy_stats, qdrv_pktlogger_stop_phy_stats,
				QDRV_PKTLOGGER_INTERVAL_DFLT_PHY_STATS,
				sizeof(struct qdrv_netdebug_phystats),
				sizeof(struct qdrv_netdebug_per_node_phystats), 0},
		{QDRV_NETDEBUG_TYPE_DSP_STATS, "dsp_stats",
				qdrv_pktlogger_start_dsp_stats, qdrv_pktlogger_stop_dsp_stats,
				QDRV_PKTLOGGER_INTERVAL_DFLT_DSP_STATS,
				sizeof(struct qdrv_netdebug_dspstats), 0, 0},
		{QDRV_NETDEBUG_TYPE_CORE_DUMP, "core_dump",
				qdrv_pktlogger_start_core_dump, qdrv_pktlogger_stop_core_dump,
				QDRV_PKTLOGGER_INTERVAL_DFLT_NONE,
				sizeof(struct qdrv_netdebug_core_dump), 0, 0},
		{QDRV_NETDEBUG_TYPE_NODE_RATE_STATS, "node_rate_stats",
				qdrv_pktlogger_start_node_rate_stats,
				qdrv_pktlogger_stop_node_rate_stats,
				QDRV_PKTLOGGER_INTERVAL_DFLT_NONE,
				sizeof(struct qdrv_netdebug_node_rate_stats),
				sizeof(struct qdrv_muc_per_node_rates), 0},
		{QDRV_NETDEBUG_TYPE_VISION, "vision",
				qdrv_pktlogger_start_vision,
				qdrv_pktlogger_stop_vision,
				QDRV_PKTLOGGER_INTERVAL_DFLT_NONE,
				sizeof(struct qdrv_netdebug_vision),
				sizeof(struct qdrv_vision_node_stats), 0},
		{-1, NULL, NULL, NULL, QDRV_PKTLOGGER_INTERVAL_DFLT_NONE, 0, 0}
};

struct qdrv_pktlogger_types_tbl *qdrv_pktlogger_get_tbls_by_id(int id)
{
	struct qdrv_pktlogger_types_tbl * tbl_p = NULL;
	int i;

	for (i = 0; qdrv_pktlogger_types_tbl_ent[i].id > 0; i++) {
		if (qdrv_pktlogger_types_tbl_ent[i].id == id) {
			tbl_p = &qdrv_pktlogger_types_tbl_ent[i];
			break;
		}
	}

	return tbl_p;
}

static void qdrv_pktlogger_stop_all(struct qdrv_wlan *qw)
{
	int index;

	for (index = 0; qdrv_pktlogger_types_tbl_ent[index].name != NULL; index++) {
		if (qdrv_pktlogger_types_tbl_ent[index].stop != NULL) {
			qdrv_pktlogger_types_tbl_ent[index].stop(qw);
		}
	}
}

int qdrv_pktlogger_start_or_stop(struct qdrv_wlan *qw, const char *type,
		int start, uint32_t interval)
{
	int ret = 0;
	int index;

	if (!start && (strncmp(type, "all", strlen(type)) == 0)) {
		qdrv_pktlogger_stop_all(qw);
		return 0;
	}

	for (index = 0; qdrv_pktlogger_types_tbl_ent[index].name != NULL; index++) {
		if (strncmp(type, qdrv_pktlogger_types_tbl_ent[index].name, strlen(type)) == 0) {
			if (start) {
				if (qdrv_pktlogger_types_tbl_ent[index].start != NULL) {
					if (interval > 0) {
						qdrv_pktlogger_types_tbl_ent[index].interval = interval;
					}
					ret = qdrv_pktlogger_types_tbl_ent[index].start(qw);
				} else {
					printk("No start command for log type %s\n", type);
					ret = -1;
				}
			} else {
				if (qdrv_pktlogger_types_tbl_ent[index].stop != NULL) {
					qdrv_pktlogger_types_tbl_ent[index].stop(qw);
					ret = 0;
				} else {
					printk("No stop command for log type %s\n", type);
					ret = -1;
				}
			}

			break;
		}
	}

	if (qdrv_pktlogger_types_tbl_ent[index].name == NULL) {
		printk("Log type %s is invalid\n", type);
		ret = -1;
	}

	return ret;
}

static inline void qdrv_pktlogger_set_iphdr(struct iphdr *iphdr, u_int16_t id,
		u_int16_t frag_off, int len)
{
	iphdr->version = 4;
	iphdr->ihl = 5;
	iphdr->tos = 0;
	iphdr->tot_len = htons(PKTLOGGER_IP_HEADER_LEN + len);
	iphdr->id = htons(id);
	iphdr->frag_off = htons(frag_off);
	iphdr->ttl = PKTLOGGER_IP_TTL;
	iphdr->protocol = IPPROTO_UDP;
	iphdr->saddr = g_pktlogger_p->src_ip;
	iphdr->daddr = g_pktlogger_p->dst_ip;
	iphdr->check = ip_fast_csum((unsigned char *)iphdr, iphdr->ihl);
}

static inline void qdrv_pktlogger_set_etherhdr(struct ether_header *hdr)
{
	IEEE80211_ADDR_COPY(hdr->ether_shost, g_pktlogger_p->src_addr);
	IEEE80211_ADDR_COPY(hdr->ether_dhost, g_pktlogger_p->dst_addr);
	hdr->ether_type = htons(ETH_P_IP);
}

static struct sk_buff *qdrv_pktlogger_alloc_skb(int len)
{
	struct sk_buff *skb;
	int cache_alignment = dma_get_cache_alignment();
	int alignment;

	skb = dev_alloc_skb(qtn_rx_buf_size());
	if (skb == NULL) {
		DBGPRINTF_E("Stopping pktlogger debug - no buffers available\n");
		return NULL;
	}
	alignment = (unsigned int)(skb->data) & (cache_alignment - 1);
	if (alignment) {
		skb_reserve(skb, cache_alignment - alignment);
	}

	skb_put(skb, len);
	memset(skb->data, 0, len);

	return skb;
}

static int
qdrv_pktlogger_ip_send(void *data, int len, u_int16_t flag_off)
{
	int length = 0;
	struct ether_header *etherhdr_p;
	struct iphdr *iphdr_p = NULL;
	void *ippayload_p = NULL;
	struct sk_buff *skb;
	struct qdrv_wlan *qw = g_pktlogger_p->qw;

	length = len + sizeof(struct iphdr) + sizeof(struct ether_header);
	skb = qdrv_pktlogger_alloc_skb(length);
	if (skb == NULL) {
		DBGPRINTF_LIMIT_E("Failed to allocate SKB\n");
		return -1;
	}

	etherhdr_p = (struct ether_header *)skb->data;
	iphdr_p = (struct iphdr *)((char *)etherhdr_p + sizeof(struct ether_header));
	ippayload_p = (void *)((char *)iphdr_p + sizeof(struct iphdr));

	memcpy(ippayload_p, data, len);
	qdrv_pktlogger_set_iphdr(iphdr_p, g_pktlogger_p->ip_id, flag_off, len);
	qdrv_pktlogger_set_etherhdr(etherhdr_p);

	if ((strncmp(g_pktlogger_p->dev->name, "wifi", 4) == 0) &&
			(!IEEE80211_IS_MULTICAST(g_pktlogger_p->dst_addr)) &&
			(!IEEE80211_IS_MULTICAST(g_pktlogger_p->recv_addr))) {
		skb->dest_port = IEEE80211_AID(ieee80211_find_aid_by_mac_addr(&qw->ic.ic_sta,
				g_pktlogger_p->recv_addr));
		if (skb->dest_port == 0) {
			DBGPRINTF_LIMIT_E("Could not send netdebug packet - wifi peer not found\n");
			dev_kfree_skb(skb);
			return -1;
		}
	}

	if ((g_pktlogger_p->dev == NULL) ||
	    (g_pktlogger_p->dev->netdev_ops->ndo_start_xmit == NULL)) {
		DBGPRINTF_LIMIT_E("Ethernet interface not found\n");
		dev_kfree_skb(skb);
		return -1;
	}

	local_bh_disable();

	if (netif_queue_stopped(g_pktlogger_p->dev))
		goto qdrv_pktlogger_ip_send_error;

	if (unlikely(strncmp(g_pktlogger_p->dev->name, "wifi", 4) == 0)) {
		skb->dev = g_pktlogger_p->dev;
		dev_queue_xmit(skb);
	} else if (unlikely(g_pktlogger_p->dev->netdev_ops->ndo_start_xmit(skb,
			g_pktlogger_p->dev) == NETDEV_TX_BUSY)) {
		goto qdrv_pktlogger_ip_send_error;
	}

	local_bh_enable();
	return 0;

qdrv_pktlogger_ip_send_error:
	local_bh_enable();
	dev_kfree_skb(skb);
	return -1;
}

static int
qdrv_pktlogger_udp_send(void *data, uint32_t len)
{
	int ret = 0;
	uint16_t flag_off = 0;
	char *data_s = (char *)data;
	int len_s = 0;

	if (g_pktlogger_p == NULL) {
		DBGPRINTF_LIMIT_E("Pktlogger is not initialised\n");
		return -EINVAL;
	}

	if (len == 0) {
		return -EINVAL;
	}

	while ((len - len_s) > g_pktlogger_p->maxfraglen) {
		flag_off |= BIT(PKTLOGGER_IP_MORE_FRAG_BIT);
		ret = qdrv_pktlogger_ip_send(data_s, g_pktlogger_p->maxfraglen, flag_off);
		if (ret < 0) {
			/* Do not send rest of fragments. */
			return -ret;
		}
		len_s += g_pktlogger_p->maxfraglen;
		flag_off = (len_s >> 3);
		data_s += g_pktlogger_p->maxfraglen;
	}

	/* Send one IP packet or the last one */
	flag_off &= (~BIT(PKTLOGGER_IP_MORE_FRAG_BIT));
	ret = qdrv_pktlogger_ip_send(data_s, len - len_s, flag_off);
	if (ret >= 0) {
		g_pktlogger_p->ip_id++;
		return ret;
	}

	return ret;
}

void
qdrv_pktlogger_sendq_work(struct work_struct *work)
{
	struct qdrv_pktlogger_data *first;
	int rc;

	g_pktlogger_p->stats.queue_send++;

	spin_lock_bh(&g_pktlogger_p->sendq_lock);

	while ((first = STAILQ_FIRST(&g_pktlogger_p->sendq_head))) {
		STAILQ_REMOVE_HEAD(&g_pktlogger_p->sendq_head, entries);

		spin_unlock_bh(&g_pktlogger_p->sendq_lock);

		/* Send data on the network */
		rc = qdrv_pktlogger_udp_send(first->data, first->len);

		/* Send the data to pktlogger_d too */
		qdrv_pktlogger_create_pktlogger_data(g_pktlogger_p->qw, first->data, first->len);

		spin_lock_bh(&g_pktlogger_p->sendq_lock);

		if (rc < 0) {
			STAILQ_INSERT_HEAD(&g_pktlogger_p->sendq_head, first, entries);
			g_pktlogger_p->stats.pkt_requeued++;
			break;
		}

		qdrv_pktlogger_free_buffer(first->data);
		kfree(first);
		g_pktlogger_p->queue_len--;
	}

	g_pktlogger_p->sendq_scheduled = 0;

	spin_unlock_bh(&g_pktlogger_p->sendq_lock);
}

void
qdrv_pktlogger_send(void *data, uint32_t len)
{
	struct qdrv_pktlogger_data *tmp;
	struct qdrv_pktlogger_data *first;

	tmp = kmalloc(sizeof(*tmp), GFP_ATOMIC);
	if (!tmp) {
		g_pktlogger_p->stats.pkt_failed++;
		qdrv_pktlogger_free_buffer(data);
		return;
	}

	tmp->data = data;
	tmp->len = len;

	spin_lock_bh(&g_pktlogger_p->sendq_lock);

	if (g_pktlogger_p->queue_len >= QDRV_PKTLOGGER_QUEUE_LEN_MAX) {
		first = STAILQ_FIRST(&g_pktlogger_p->sendq_head);
		STAILQ_REMOVE_HEAD(&g_pktlogger_p->sendq_head, entries);
		qdrv_pktlogger_free_buffer(first->data);
		kfree(first);
		g_pktlogger_p->queue_len--;
		g_pktlogger_p->stats.pkt_dropped++;
	}

	STAILQ_INSERT_TAIL(&g_pktlogger_p->sendq_head, tmp, entries);
	g_pktlogger_p->queue_len++;
	g_pktlogger_p->stats.pkt_queued++;

	if (!g_pktlogger_p->sendq_scheduled) {
		g_pktlogger_p->sendq_scheduled = 1;
		schedule_work(&g_pktlogger_p->sendq_work);
	}

	spin_unlock_bh(&g_pktlogger_p->sendq_lock);
}

static int qdrv_pktlogger_ip_event(struct notifier_block *this,
			    unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	struct net_device *dev = (struct net_device *)ifa->ifa_dev->dev;
	struct qdrv_wlan *qw = g_pktlogger_p->qw;
	struct net_device *br_dev = qw->br_dev;

	switch (event) {
	case NETDEV_UP:
		if (dev == br_dev) {
			uint8_t *addr_p;

			g_pktlogger_p->src_ip = ifa->ifa_address;
			addr_p = (uint8_t *)&g_pktlogger_p->src_ip;
			printk("QDRV: src ip addr %pI4\n", addr_p);
			return NOTIFY_OK;
		}
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block qdrv_pktlogger_ip_notifier = {
	.notifier_call = qdrv_pktlogger_ip_event,
};

int
qdrv_pktlogger_init(struct qdrv_wlan *qw)
{
	int i = 0;
	unsigned int maxfraglen;
	unsigned int fragheaderlen;
	uint8_t default_dst_addr[IEEE80211_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	__be32 srcip = 0;

	g_pktlogger_p = &qw->pktlogger;
	memset(g_pktlogger_p, 0, sizeof(struct qdrv_pktlogger));

	g_pktlogger_p->rx_rate_cur = &g_pktlogger_p->rx_rates[0];
	g_pktlogger_p->rx_rate_pre = &g_pktlogger_p->rx_rates[1];
	g_pktlogger_p->rx_ratelog_cur = &g_pktlogger_p->rx_ratelog[0];
	g_pktlogger_p->rx_ratelog_pre = &g_pktlogger_p->rx_ratelog[1];

	for (i = 1; ; i++) {
		g_pktlogger_p->dev = dev_get_by_index(&init_net, i);
		if (g_pktlogger_p->dev == NULL) {
			DBGPRINTF_E("Ethernet interface not found\n");
			qdrv_pktlogger_exit(qw);
			return -1;
		}

		if ((strncmp(g_pktlogger_p->dev->name, "eth", 3) == 0) ||
				(strncmp(g_pktlogger_p->dev->name, "pcie", 4) == 0)) {
			break;
		}
		dev_put(g_pktlogger_p->dev);
	}

	if (strncmp(g_pktlogger_p->dev->name, "eth", 3) == 0) {
		g_pktlogger_p->dev_emac0 = dev_get_by_name(&init_net, "eth1_0");
		g_pktlogger_p->dev_emac1 = dev_get_by_name(&init_net, "eth1_1");
	}

	if (g_pktlogger_p->dev->netdev_ops->ndo_start_xmit == NULL) {
		DBGPRINTF_E("Ethernet transmit function not found\n");
		dev_put(g_pktlogger_p->dev);
		g_pktlogger_p->dev = NULL;
		return -1;
	}

	if (qw->br_dev) {
		srcip = qdrv_dev_ipaddr_get(qw->br_dev);
	}

	if (!srcip) {
		srcip = PKTLOGGER_DEFAULT_SRC_IP;
	}

	g_pktlogger_p->dst_ip = PKTLOGGER_DEFAULT_DST_IP;
	g_pktlogger_p->src_ip = srcip;
	g_pktlogger_p->dst_port = htons(PKTLOGGER_UDP_DST_PORT);
	g_pktlogger_p->src_port = htons(PKTLOGGER_UDP_SRC_PORT);

	IEEE80211_ADDR_COPY(g_pktlogger_p->dst_addr, default_dst_addr);
	IEEE80211_ADDR_COPY(g_pktlogger_p->recv_addr, default_dst_addr);
	IEEE80211_ADDR_COPY(g_pktlogger_p->src_addr, qw->mac->mac_addr);

	fragheaderlen = sizeof(struct iphdr);
	maxfraglen = ETHERMTU - fragheaderlen;
	maxfraglen -= (maxfraglen % 8);
	g_pktlogger_p->maxfraglen = maxfraglen;

	g_pktlogger_p->qw = qw;
	g_pktlogger_p->queue_len = 0;

	spin_lock_init(&g_pktlogger_p->sendq_lock);
	INIT_WORK(&g_pktlogger_p->sendq_work, qdrv_pktlogger_sendq_work);
	STAILQ_INIT(&g_pktlogger_p->sendq_head);

	spin_lock_init(&g_pktlogger_p->sysmsg_lock);
	INIT_DELAYED_WORK(&g_pktlogger_p->sysmsg_work, qdrv_pktlogger_sysmsg_work);

	qdrv_pktlogger_start_netlink(qw);

	return register_inetaddr_notifier(&qdrv_pktlogger_ip_notifier);
}

void qdrv_pktlogger_exit(struct qdrv_wlan *qw)
{
	struct qdrv_pktlogger_data *first;

	unregister_inetaddr_notifier(&qdrv_pktlogger_ip_notifier);

	/* Stop all debug packets */
	if (qw->pktlogger.flag) {
		qdrv_pktlogger_stop_all(qw);
	}

	spin_lock_bh(&g_pktlogger_p->sendq_lock);

	cancel_work_sync(&g_pktlogger_p->sendq_work);
	g_pktlogger_p->sendq_scheduled = 0;
	while (!STAILQ_EMPTY(&g_pktlogger_p->sendq_head)) {
		first = STAILQ_FIRST(&g_pktlogger_p->sendq_head);
		STAILQ_REMOVE_HEAD(&g_pktlogger_p->sendq_head, entries);
		qdrv_pktlogger_free_buffer(first->data);
		kfree(first);
	}

	spin_unlock_bh(&g_pktlogger_p->sendq_lock);

	g_pktlogger_p->queue_len = 0;
	g_pktlogger_p = NULL;

	if (qw->pktlogger.dev == NULL) {
			return;
	}

	dev_put(qw->pktlogger.dev);

	if (g_pktlogger_p->dev_emac0)
		dev_put(g_pktlogger_p->dev_emac0);
	if (g_pktlogger_p->dev_emac1)
		dev_put(g_pktlogger_p->dev_emac1);

	qw->pktlogger.dev = NULL;
}
