/**
  Copyright (c) 2008 - 2013 Quantenna Communications Inc
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

#ifndef _QDRV_RADAR_H_
#define _QDRV_RADAR_H_

#include <qtn/lhost_muc_comm.h>

#define QDRV_RADAR_DFLT_CHANSW_MS 50 /* msecs */
#define QDRV_RADAR_DFLT_NONOCCUPY_PERIOD	1800 /* secs */

#define CAC_PERIOD		(70 * HZ)
#define CAC_WEATHER_PERIOD_EU	(600 * HZ)
#define CAC_PERIOD_QUICK	(30 * HZ)
#define NONOCCUPY_PERIOD_QUICK	(60 * HZ)
#define STA_SILENCE_PERIOD	(CAC_PERIOD + 10 * HZ)
#define STA_WEATHER_CHAN_SILENCE_PERIOD	(CAC_WEATHER_PERIOD_EU + 10 * HZ)

struct qdrv_mac;

typedef void (*radar_stats_handler_t)(void *arg, struct qtn_radar_sample *samples, size_t size);

int qdrv_radar_init(struct qdrv_mac* mac);
int qdrv_radar_exit(struct qdrv_mac* mac);
int qdrv_radar_unload(struct qdrv_mac *mac);

void qdrv_radar_enable(const char* region);
void qdrv_radar_disable(void);
int qdrv_radar_is_enabled(void);
void qdrv_sta_set_xmit(int enable);
void qdrv_set_radar(int enable);

void qdrv_radar_mark_radar(void);
void qdrv_radar_handle_samples(size_t size);
void qdrv_radar_register_statcb(radar_stats_handler_t handler, void *arg);
void qdrv_radar_detected(struct ieee80211com* ic, u_int8_t new_ieee);
int qdrv_radar_require_sta_slient(struct ieee80211com *ic);
int qdrv_radar_can_sample_chan(void);
int qdrv_radar_test_mode_enabled(void);
void qdrv_radar_before_newchan(void);
void qdrv_radar_on_newchan(void);
void qdrv_radar_stop_active_cac(void);
void sta_dfs_cac_action(struct ieee80211_channel *chan);
void qdrv_cac_instant_completed(void);
unsigned long qdrv_get_cac_duration_jiffies(struct ieee80211com *ic,
	struct ieee80211_channel *channel);
void qdrv_sta_dfs_enable(int sta_dfs_enable);
int qdrv_radar_detections_num(uint32_t chan);
void qdrv_radar_run_dfs_action(struct ieee80211com *ic);
void qdrv_set_dfs_available_channel(uint32_t chan);

bool qdrv_radar_is_rdetection_required(const struct ieee80211_channel *chan);
bool qdrv_dfs_is_eu_region(void);
int qdrv_dfs_is_us_region(void);
int qdrv_dfs_is_jp_region(void);
int qdrv_dfs_is_cl_region(void);
int qdrv_dfs_is_br_region(void);
int qdrv_dfs_is_status_save_region(void);
int qdrv_dfs_is_icac_supp_region(void);
int qdrv_dfs_is_region_set(void);

void qdrv_dfs_action_scan_done(void);

struct ieee80211_channel * qdrv_radar_get_current_cac_chan(void);
void qdrv_radar_enable_radar_detection(void);

void sys_enable_xmit(const char *msg);
void sys_disable_xmit(const char *msg);

int qdrv_set_txctl(struct ieee80211com *ic, uint32_t txctl);
int qdrv_robust_csa_send_frame(struct ieee80211vap *vap,
		u_int8_t csa_mode, u_int8_t csa_chan,
		u_int8_t csa_count, u_int64_t tsf);
int qdrv_radar_set_bw(uint32_t bw);
#endif
