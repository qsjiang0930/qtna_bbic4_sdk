/*-
 * Copyright (c) 2016 Quantenna
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
 */


#ifndef IEEE80211_CHAN_SELECT_H
#define IEEE80211_CHAN_SELECT_H


#define CHAN_CCA_SIZE		4
#define CHAN_NUMACIBINS		2
#define	CHAN_MAX_NUM_PER_BAND	32


enum chan_selection_scan_type {
	CHAN_SELECT_SCAN_INVALID = 0,
	CHAN_SELECT_SCAN_BW20 = 1,
	CHAN_SELECT_SCAN_BW40 = 2,
	CHAN_SELECT_SCAN_BW40_ABOVE = 3,
	CHAN_SELECT_SCAN_BW40_BELOW = 4,
	CHAN_SELECT_SCAN_BW80 = 5,
	CHAN_SELECT_SCAN_BW160 = 6,
	CHAN_SELECT_SCAN_MAX = 7,
};

struct autochan_ranking_params
{
	int cci_instnt_factor;
	int aci_instnt_factor;
	int cci_longterm_factor;
	int aci_longterm_factor;
	int range_factor;
	int dfs_factor;
	int min_cochan_rssi;
	int maxbw_minbenefit;
	int dense_cci_span;
};

struct chan_aci_params
{
	int rssi;
	int bw;
	int weight;
};

struct ieee80211_chanset
{
	int pri_chan;
	int sec20_offset;
	int bw;
	int center_chan;
	int invalid;
	int inactive;
	int cca_array[CHAN_CCA_SIZE];
	int cca_pri[CHAN_NUMACIBINS];	/* Store CCA value on different RSSI strenth */
	int cca_intf;
	int cci_instnt;
	int aci_instnt;
	int cci_longterm;
	int aci_longterm;
	int range_cost;
	int is_dfs;
	int cost;
};

struct ieee80211_chanset_table
{
	struct ieee80211_chanset *chanset;
	int num;
};


#define CHAN_SEL_LOG_ERR			0
#define CHAN_SEL_LOG_WARN			1
#define CHAN_SEL_LOG_INFO			2
#define CHAN_SEL_LOG_MAX                        3

#define IEEE80211_CSDBG(_level, _fmt, ...)	do {	\
	if (ic->ic_autochan_dbg_level >= (_level)) {		\
			printk(_fmt, ##__VA_ARGS__);	\
		}					\
	} while (0)

void ieee80211_init_chanset_ranking_params(struct ieee80211com *ic);
int ieee80211_chan_selection_allowed(struct ieee80211com *ic);
int ieee80211_chanset_scan_finished(struct ieee80211com *ic);
int ieee80211_start_chanset_scan(struct ieee80211vap *vap, int scan_flags);
int ieee80211_start_chanset_selection(struct ieee80211vap *vap, int scan_flags);
struct ieee80211_channel * ieee80211_chanset_pick_channel(struct ieee80211vap *vap);
void ieee80211_clean_chanset_values(struct ieee80211com *ic);


#endif /* IEEE80211_CHAN_SELECT_H */

