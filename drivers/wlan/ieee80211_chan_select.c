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


#include <linux/version.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/random.h>

#include "net80211/ieee80211_var.h"
#include "net80211/ieee80211_chan_select.h"


static const struct autochan_ranking_params g_ranking_params_2g_scsoff = {
	0, 0, 100, 0, 10, 0, -80, 2, 5,
};

static const struct autochan_ranking_params g_ranking_params_5g_scsoff = {
	10, 5, 100, 20, 10, -30, -80, 2, 5,
};

static const struct autochan_ranking_params g_ranking_params_5g_scson = {
	100, 20, 10, 5, 10, -30, -80, 2, 5,
};

static const struct chan_aci_params g_aci_params[CHAN_NUMACIBINS] = {
	{-30, 80, 5},
	{-62, 20, 1},
};

static struct ieee80211_chanset g_chansets_2g_bw20[] = {
	{ 1, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20,  1, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 2, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20,  2, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 3, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20,  3, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 4, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20,  4, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 5, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20,  5, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 6, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20,  6, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 7, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20,  7, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 8, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20,  8, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 9, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20,  9, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{10, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 10, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{11, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 11, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{12, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 12, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{13, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 13, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{14, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 14, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
};

static struct ieee80211_chanset g_chansets_2g_bw40[] = {
	{ 1, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40,  3, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 2, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40,  4, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 3, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40,  5, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 4, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40,  6, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 5, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40,  7, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 6, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40,  8, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 7, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40,  9, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 8, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40, 10, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 9, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40, 11, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 5, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40,  3, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 6, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40,  4, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 7, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40,  5, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 8, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40,  6, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 9, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40,  7, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{10, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40,  8, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{11, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40,  9, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{12, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40, 10, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{13, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40, 11, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
};

static struct ieee80211_chanset g_chansets_5g_bw20[] = {
	{ 36, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20,  36, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 40, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20,  40, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 44, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20,  44, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 48, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20,  48, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 52, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20,  52, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 56, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20,  56, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 60, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20,  60, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 64, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20,  64, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{100, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 100, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{104, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 104, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{108, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 108, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{112, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 112, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{116, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 116, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{120, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 120, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{124, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 124, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{128, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 128, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{132, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 132, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{136, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 136, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{140, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 140, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{144, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 144, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{149, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 149, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{153, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 153, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{157, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 157, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{161, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 161, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{165, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 165, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{169, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 169, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{184, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 184, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{188, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 188, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{192, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 192, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{196, IEEE80211_HTINFO_CHOFF_SCN, BW_HT20, 196, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
};

static struct ieee80211_chanset g_chansets_5g_bw40[] = {
	{ 36, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40,  38, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 40, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40,  38, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 44, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40,  46, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 48, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40,  46, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 52, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40,  54, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 56, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40,  54, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 60, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40,  62, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 64, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40,  62, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{100, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40, 102, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{104, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40, 102, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{108, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40, 110, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{112, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40, 110, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{116, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40, 118, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{120, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40, 118, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{124, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40, 126, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{128, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40, 126, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{132, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40, 134, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{136, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40, 134, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{140, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40, 142, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{144, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40, 142, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{149, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40, 151, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{153, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40, 151, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{157, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40, 159, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{161, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40, 159, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{184, IEEE80211_HTINFO_CHOFF_SCA, BW_HT40, 186, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{188, IEEE80211_HTINFO_CHOFF_SCB, BW_HT40, 186, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{192, IEEE80211_HTINFO_CHOFF_SCA, BW_HT20, 194, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{196, IEEE80211_HTINFO_CHOFF_SCB, BW_HT20, 194, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
};

static struct ieee80211_chanset g_chansets_5g_bw80[] = {
	{ 36, IEEE80211_HTINFO_CHOFF_SCA, BW_HT80,  42, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 40, IEEE80211_HTINFO_CHOFF_SCB, BW_HT80,  42, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 44, IEEE80211_HTINFO_CHOFF_SCA, BW_HT80,  42, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 48, IEEE80211_HTINFO_CHOFF_SCB, BW_HT80,  42, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 52, IEEE80211_HTINFO_CHOFF_SCA, BW_HT80,  58, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 56, IEEE80211_HTINFO_CHOFF_SCB, BW_HT80,  58, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 60, IEEE80211_HTINFO_CHOFF_SCA, BW_HT80,  58, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 64, IEEE80211_HTINFO_CHOFF_SCB, BW_HT80,  58, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{100, IEEE80211_HTINFO_CHOFF_SCA, BW_HT80, 106, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{104, IEEE80211_HTINFO_CHOFF_SCB, BW_HT80, 106, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{108, IEEE80211_HTINFO_CHOFF_SCA, BW_HT80, 106, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{112, IEEE80211_HTINFO_CHOFF_SCB, BW_HT80, 106, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{116, IEEE80211_HTINFO_CHOFF_SCA, BW_HT80, 122, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{120, IEEE80211_HTINFO_CHOFF_SCB, BW_HT80, 122, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{124, IEEE80211_HTINFO_CHOFF_SCA, BW_HT80, 122, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{128, IEEE80211_HTINFO_CHOFF_SCB, BW_HT80, 122, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{132, IEEE80211_HTINFO_CHOFF_SCA, BW_HT80, 138, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{136, IEEE80211_HTINFO_CHOFF_SCB, BW_HT80, 138, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{140, IEEE80211_HTINFO_CHOFF_SCA, BW_HT80, 138, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{144, IEEE80211_HTINFO_CHOFF_SCB, BW_HT80, 138, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{149, IEEE80211_HTINFO_CHOFF_SCA, BW_HT80, 155, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{153, IEEE80211_HTINFO_CHOFF_SCB, BW_HT80, 155, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{157, IEEE80211_HTINFO_CHOFF_SCA, BW_HT80, 155, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{161, IEEE80211_HTINFO_CHOFF_SCB, BW_HT80, 155, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
};

static struct ieee80211_chanset g_chansets_5g_bw160[] = {
	{ 36, IEEE80211_HTINFO_CHOFF_SCA, BW_HT160,  50, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 40, IEEE80211_HTINFO_CHOFF_SCB, BW_HT160,  50, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 44, IEEE80211_HTINFO_CHOFF_SCA, BW_HT160,  50, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 48, IEEE80211_HTINFO_CHOFF_SCB, BW_HT160,  50, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 52, IEEE80211_HTINFO_CHOFF_SCA, BW_HT160,  50, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 56, IEEE80211_HTINFO_CHOFF_SCB, BW_HT160,  50, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 60, IEEE80211_HTINFO_CHOFF_SCA, BW_HT160,  50, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{ 64, IEEE80211_HTINFO_CHOFF_SCB, BW_HT160,  50, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{100, IEEE80211_HTINFO_CHOFF_SCA, BW_HT160, 114, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{104, IEEE80211_HTINFO_CHOFF_SCB, BW_HT160, 114, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{108, IEEE80211_HTINFO_CHOFF_SCA, BW_HT160, 114, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{112, IEEE80211_HTINFO_CHOFF_SCB, BW_HT160, 114, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{116, IEEE80211_HTINFO_CHOFF_SCA, BW_HT160, 114, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{120, IEEE80211_HTINFO_CHOFF_SCB, BW_HT160, 114, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{124, IEEE80211_HTINFO_CHOFF_SCA, BW_HT160, 114, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
	{128, IEEE80211_HTINFO_CHOFF_SCB, BW_HT160, 114, 0, 0, {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0},
};


__inline int
ieee80211_chan_selection_allowed(struct ieee80211com *ic)
{
	if ((ic->ic_opmode == IEEE80211_M_HOSTAP) &&
		IS_IEEE80211_24G_BAND(ic))
		return 1;
	else
		return 0;
}

static struct ieee80211_chanset *
ieee80211_find_chan_table(int band, int bw, int *table_size)
{
	struct ieee80211_chanset *table = NULL;
	*table_size = 0;

	if (band == IEEE80211_2_4Ghz) {
		switch (bw) {
		case BW_HT20:
			table = g_chansets_2g_bw20;
			*table_size = ARRAY_SIZE(g_chansets_2g_bw20);
			break;
		case BW_HT40:
			table = g_chansets_2g_bw40;
			*table_size = ARRAY_SIZE(g_chansets_2g_bw40);
			break;
		default:
			break;
		}
	} else {
		switch (bw) {
		case BW_HT20:
			table = g_chansets_5g_bw20;
			*table_size = ARRAY_SIZE(g_chansets_5g_bw20);
			break;
		case BW_HT40:
			table = g_chansets_5g_bw40;
			*table_size = ARRAY_SIZE(g_chansets_5g_bw40);
			break;
		case BW_HT80:
			table = g_chansets_5g_bw80;
			*table_size = ARRAY_SIZE(g_chansets_5g_bw80);
			break;
		case BW_HT160:
			table = g_chansets_5g_bw160;
			*table_size = ARRAY_SIZE(g_chansets_5g_bw160);
			break;
		default:
			break;
		}
	}

	return table;
}

static struct ieee80211_chanset *
ieee80211_find_chanset(struct ieee80211_chanset_table *table,
	int chan, int bw, int sec_chan)
{
	struct ieee80211_chanset *chanset = NULL;
	int i;

	if (!table)
		return NULL;

	for (i = 0; i < table->num; i++) {
		if ((chan == table->chanset[i].pri_chan) &&
			(bw == table->chanset[i].bw) &&
			(sec_chan == table->chanset[i].sec20_offset)) {
			chanset = &table->chanset[i];
			break;
		}
	}

	return chanset;
}

static struct ieee80211_chanset *
ieee80211_get_beacon_chanset(int chan, int bw, int sec_off)
{
	struct ieee80211_chanset_table chanset_table;
	struct ieee80211_chanset *chanset = NULL;
	int table_size;
	int band;

	if (chan <= QTN_2G_LAST_OPERATING_CHAN)
		band = IEEE80211_2_4Ghz;
	else
		band = IEEE80211_5Ghz;

	chanset = ieee80211_find_chan_table(band, bw, &table_size);
	if (!chanset)
		return NULL;

	chanset_table.chanset = chanset;
	chanset_table.num = table_size;

	return ieee80211_find_chanset(&chanset_table, chan, bw, sec_off);
}


static int
ieee80211_get_chanset_cci_high_edge(struct ieee80211com *ic,
	struct ieee80211_chanset *chanset)
{
	int start_freq;
	int neighbor_type;
	int cci_span = chanset->bw / 2;

	if (IS_IEEE80211_24G_BAND(ic)) {
		neighbor_type = ieee80211_get_type_of_neighborhood(ic);
		if (neighbor_type == IEEE80211_NEIGHBORHOOD_TYPE_VERY_DENSE)
			cci_span = ic->ic_autochan_ranking_params.dense_cci_span;
	}

	if (chanset->pri_chan < QTN_5G_FIRST_OPERATING_CHAN)
		start_freq = IEEE80211_2GBAND_START_FREQ;
	else if (chanset->pri_chan >= QTN_4G_FIRST_OPERATING_CHAN)
		start_freq = IEEE80211_4GBAND_START_FREQ;
	else
		start_freq = IEEE80211_5GBAND_START_FREQ;

	return start_freq + chanset->center_chan *
			IEEE80211_CHAN_SPACE + cci_span;
}

static int
ieee80211_get_chanset_cci_low_edge(struct ieee80211com *ic,
	struct ieee80211_chanset *chanset)
{
	int start_freq;
	int neighbor_type;
	int cci_span = chanset->bw / 2;

	if (IS_IEEE80211_24G_BAND(ic)) {
		neighbor_type = ieee80211_get_type_of_neighborhood(ic);
		if (neighbor_type == IEEE80211_NEIGHBORHOOD_TYPE_VERY_DENSE)
			cci_span = ic->ic_autochan_ranking_params.dense_cci_span;
	}

	if (chanset->pri_chan < QTN_5G_FIRST_OPERATING_CHAN)
		start_freq = IEEE80211_2GBAND_START_FREQ;
	else if (chanset->pri_chan >= QTN_4G_FIRST_OPERATING_CHAN)
		start_freq = IEEE80211_4GBAND_START_FREQ;
	else
		start_freq = IEEE80211_5GBAND_START_FREQ;

	return start_freq + chanset->center_chan *
			IEEE80211_CHAN_SPACE - cci_span;
}

static void
ieee80211_reset_chan_table_values(struct ieee80211com *ic,
	struct ieee80211_chanset_table *table)
{
	struct ieee80211_chanset *chanset;
	int i;

	for (i = 0; i < table->num; i++) {
		chanset = &table->chanset[i];
		chanset->invalid = 0;
		chanset->inactive = 0;
		memset(chanset->cca_array, 0, sizeof(chanset->cca_array));
		memset(chanset->cca_pri, 0, sizeof(chanset->cca_pri));
		chanset->cca_intf = 0;
		chanset->cci_instnt = 0;
		chanset->aci_instnt = 0;
		chanset->cci_longterm = 0;
		chanset->aci_longterm = 0;
		chanset->range_cost = 0;
		chanset->is_dfs = 0;
		chanset->cost = 0;
	}
}

static int
ieee80211_udpate_chan_table_invalid_flag(struct ieee80211com *ic,
	struct ieee80211_chanset *table, int chanset_size)
{
	struct ieee80211_chanset *chan;
	struct ieee80211_channel *ch;
	uint8_t *active_list = ic->ic_chan_active;
	int sec20;
	int sec40u;
	int sec40l;
	int i;

	for (i = 0; i < chanset_size; i++) {
		chan = &table[i];

		switch (chan->bw) {
		case BW_HT160:
			/* TODO: 160Mhz support here */
			break;
		case BW_HT80:
			active_list = ic->ic_chan_active_80;
			break;
		case BW_HT40:
			active_list = ic->ic_chan_active_40;
			break;
		case BW_HT20:
			active_list = ic->ic_chan_active_20;
			break;
		default:
			active_list = ic->ic_chan_active;
			break;
		}

		if (isclr(active_list, chan->pri_chan)) {
			chan->invalid = 1;
			continue;
		}

		if (isset(ic->ic_chan_pri_inactive, chan->pri_chan)) {
			chan->invalid = 1;
			continue;
		}

		if (ieee80211_is_channel_disabled(ic, chan->pri_chan, chan->bw)) {
			chan->invalid = 1;
			continue;
		}

		if (chan->bw > BW_HT20) {
			if (chan->sec20_offset == IEEE80211_HTINFO_CHOFF_SCA)
				sec20 = chan->pri_chan + IEEE80211_CHAN_SEC_SHIFT;
			else if (chan->sec20_offset == IEEE80211_HTINFO_CHOFF_SCB)
				sec20 = chan->pri_chan - IEEE80211_CHAN_SEC_SHIFT;
			else
				sec20 = chan->pri_chan;

			if (isclr(active_list, sec20)) {
				chan->invalid = 1;
				continue;
			}

			if (chan->bw > BW_HT40) {
				ch = findchannel_any(ic, chan->pri_chan, ic->ic_des_mode);
				if (!is_ieee80211_chan_valid(ch)) {
					IEEE80211_CSDBG(CHAN_SEL_LOG_ERR,
						"%s: fail to find channel %d\n",
						__func__, chan->pri_chan);
					continue;
				}

				sec40u = ieee80211_find_sec40u_chan(ch);
				sec40l = ieee80211_find_sec40l_chan(ch);

				if (isclr(active_list, sec40u) ||
						isclr(active_list, sec40l)) {
					chan->invalid = 1;
					continue;
				}
			}
		}
	}

	return 0;
}

static int
ieee80211_update_scan_cca_info(struct ieee80211com *ic)
{
	struct qtn_scs_scan_info scan_info;
	struct ieee80211_chanset *chanset;
	struct ieee80211_channel *chan;
	int sec20_offset;
	int ret;
	int i;

	if (!ieee80211_chan_selection_allowed(ic))
		return -1;

	for (i = 0; i < IEEE80211_CHAN_MAX; i++) {
		chan = findchannel(ic, i, ic->ic_des_mode);
		if (!is_ieee80211_chan_valid(chan))
			continue;

		ret = ieee80211_scs_get_scaled_scan_info(ic, i, &scan_info);
		if (ret != 0)
			continue;

		if (scan_info.bw_sel == BW_HT20) {
			sec20_offset = IEEE80211_HTINFO_CHOFF_SCN;
		} else {
			if (ieee80211_is_chan40u(chan))
				sec20_offset = IEEE80211_HTINFO_CHOFF_SCA;
			else if (ieee80211_is_chan40d(chan))
				sec20_offset = IEEE80211_HTINFO_CHOFF_SCB;
			else
				sec20_offset = IEEE80211_HTINFO_CHOFF_SCN;
		}

		chanset = ieee80211_find_chanset(&ic->ic_autochan_table,
				i, scan_info.bw_sel, sec20_offset);
		if (!chanset) {
			IEEE80211_CSDBG(CHAN_SEL_LOG_WARN,
				"%s: don't find chanset for channel %d"
				" bw %d and sec_chan_offset %d\n", __func__,
				i, scan_info.bw_sel, sec20_offset);
			continue;
		}

		chanset->cca_intf = scan_info.cca_intf;
		chanset->cca_array[0] = scan_info.cca_pri;
		chanset->cca_array[1] = scan_info.cca_sec20;
		chanset->cca_array[2] = scan_info.cca_sec40;

		/*
		 * variables cca_pri are designed to store CCA levels in different
		 * RSSI strength, while currently hardware doesn't support this.
		 * So only store the total CCA level in the last entry.
		 */
		chanset->cca_pri[0] = 0;
		chanset->cca_pri[1] = scan_info.cca_pri;
	}

	return 0;
}

static int
ieee80211_update_chan_table_cci_instnt(struct ieee80211com *ic,
	struct ieee80211_chanset *chanset, int chanset_size)
{
	int i;

	for (i = 0; i < chanset_size; i++)
		chanset[i].cci_instnt = chanset[i].cca_intf;

	return 0;
}

static int
ieee80211_udpate_chan_table_aci_instnt(struct ieee80211com *ic,
	struct ieee80211_chanset *chanset, int chanset_size)
{
	struct ieee80211_chanset *c1;
	struct ieee80211_chanset *c2;
	int c1_upperedge;
	int c1_loweredge;
	int c2_upperedge;
	int c2_loweredge;
	int i, j, k;

	for (i = 0; i < chanset_size; i++) {
		c1 = &chanset[i];
		c1_upperedge = ieee80211_get_chanset_cci_high_edge(ic, c1);
		c1_loweredge = ieee80211_get_chanset_cci_low_edge(ic, c1);

		for (j = 0; j < chanset_size; j++) {
			c2 = &chanset[j];
			c2_upperedge = ieee80211_get_chanset_cci_high_edge(ic, c2);
			c2_loweredge = ieee80211_get_chanset_cci_low_edge(ic, c2);

			for (k = 0; k < CHAN_NUMACIBINS; k++) {
				if ((c2_upperedge > (c1_loweredge - g_aci_params[k].bw)) &&
					(c2_upperedge <= c1_loweredge))
					c1->aci_instnt += c2->cca_pri[k];

				if ((c2_loweredge < (c1_upperedge + g_aci_params[k].bw)) &&
					(c2_loweredge >= c1_upperedge))
					c1->aci_instnt += c2->cca_pri[k];
			}
		}
	}

	return 0;
}

static int
ieee80211_udpate_chan_table_cci_aci_longterm(struct ieee80211com *ic,
	struct ieee80211_chanset *chanset, int chanset_size)
{
	struct ap_state *as = ic->ic_scan->ss_priv;
	struct ap_scan_entry *se, *next;
	struct ieee80211_scan_entry *ise;
	struct ieee80211_chanset *chan;
	char ssid[IEEE80211_NWID_LEN + 1];
	int aci = CHAN_NUMACIBINS - 1;
	int b_sec_offset;
	int b_bw;
	int rssi;
	int b_upperedge;
	int b_loweredge;
	int c_upperedge;
	int c_loweredge;
	int i, j;

	if (ic->ic_opmode != IEEE80211_M_HOSTAP)
		return -1;

	for (i = 0; i < IEEE80211_CHAN_MAX; i++) {
		TAILQ_FOREACH_SAFE(se, &as->as_scan_list[i].asl_head, ase_list, next) {
			ise = &se->base;

			b_bw = ieee80211_get_max_ap_bw(ise);
			b_sec_offset = ieee80211_get_ap_sec_chan_offset(ise);
			chan = ieee80211_get_beacon_chanset(i, b_bw, b_sec_offset);
			if (!chan) {
				memset(ssid, 0, sizeof(ssid));
				memcpy(ssid, &ise->se_ssid[2],
					MIN(IEEE80211_NWID_LEN, ise->se_ssid[1]));

				IEEE80211_CSDBG(CHAN_SEL_LOG_ERR,
					"%s: fail to find chanset for beacon %s "
					"(channel %d bw %d sec20_offset %d)\n", __func__,
					ssid, i, b_bw, b_sec_offset);
				continue;
			}
			b_upperedge = ieee80211_get_chanset_cci_high_edge(ic, chan);
			b_loweredge = ieee80211_get_chanset_cci_low_edge(ic, chan);

			rssi = ise->se_rssi - IEEE80211_PSEUDO_RSSI_TRANSITON_FACTOR;

			for (j = 0; j < CHAN_NUMACIBINS; j++) {
				if (rssi >= g_aci_params[j].rssi) {
					aci = j;
					break;
				}
			}

			for (j = 0; j < chanset_size; j++) {
				chan = &chanset[j];
				c_upperedge = ieee80211_get_chanset_cci_high_edge(ic, chan);
				c_loweredge = ieee80211_get_chanset_cci_low_edge(ic, chan);

				if ((rssi > ic->ic_autochan_ranking_params.min_cochan_rssi) &&
						(b_upperedge > c_loweredge) &&
						(b_loweredge < c_upperedge))
					chan->cci_longterm++;
				if (((b_upperedge > (c_loweredge - g_aci_params[aci].bw)) &&
						(b_upperedge <= c_loweredge)) ||
					((b_loweredge < (c_upperedge + g_aci_params[aci].bw)) &&
						(b_loweredge >= c_upperedge)))
					chan->aci_longterm += g_aci_params[aci].weight;
			}
		}
	}

	return 0;
}

static int
ieee80211_update_chan_table_range_cost(struct ieee80211com *ic,
	struct ieee80211_chanset *chanset, int chanset_size)
{
	struct ieee80211_channel *chan;
	int maxpower_chan;
	int maxpower_reg;
	int i;
	int bw_idx = 0;

	for (i = 0; i < chanset_size; i++) {
		chan = findchannel_any(ic, chanset[i].pri_chan, ic->ic_des_mode);
		if (!is_ieee80211_chan_valid(chan)) {
			IEEE80211_CSDBG(CHAN_SEL_LOG_WARN,
				"%s: fail to find channel %d\n", __func__,
				chanset[i].pri_chan);
			continue;
		}

		bw_idx = BW_TO_PWR_BW_IDX(chanset[i].bw);
		maxpower_chan = ieee80211_chan_get_maxpwr(chan, bw_idx);
		maxpower_reg = chan->ic_maxregpower;

		chanset[i].range_cost =	maxpower_reg - maxpower_chan;
	}

	return 0;
}

static int
ieee80211_update_chan_table_dfs_flag(struct ieee80211com *ic,
	struct ieee80211_chanset *chanset, int chanset_size)
{
	struct ieee80211_channel *chan;
	int i;

	for (i = 0; i < chanset_size; i++) {
		chan = findchannel_any(ic, chanset[i].pri_chan, ic->ic_des_mode);
		if (!is_ieee80211_chan_valid(chan)) {
			IEEE80211_CSDBG(CHAN_SEL_LOG_WARN,
				"%s: fail to find channel %d\n", __func__,
				chanset[i].pri_chan);
			continue;
		}

		if (chan->ic_flags & IEEE80211_CHAN_DFS)
			chanset[i].is_dfs = 1;
		else
			chanset[i].is_dfs = 0;
	}

	return 0;
}

static int
ieee80211_udpate_chan_table_inactive_flag(struct ieee80211com *ic,
	struct ieee80211_chanset *table, int chanset_size)
{
	struct ieee80211vap *vap = ieee80211_get_primary_vap(ic, 1);
	struct ieee80211_chanset *chanset;
	struct ieee80211_channel chan;
	struct ieee80211_channel *ch;
	int j;

	if (!vap)
		return -1;

	if (ic->ic_opmode != IEEE80211_M_HOSTAP)
		return -1;

	if (!IS_IEEE80211_24G_40(ic) || !ic->ic_20_40_coex_enable)
		return -1;

	for (j = 0; j < chanset_size; j++) {
		chanset = &table[j];

		if (chanset->bw == BW_HT20)
			continue;

		ch = findchannel_any(ic, chanset->pri_chan, ic->ic_des_mode);
		if (!is_ieee80211_chan_valid(ch)) {
			IEEE80211_CSDBG(CHAN_SEL_LOG_ERR,
				"%s: fail to find channel %d\n",
				__func__, chanset->pri_chan);
			continue;
		}

		memcpy(&chan, ch, sizeof(chan));
		if (ieee80211_dual_sec_chan_supported(ic, &chan))
			ieee80211_update_sec_chan_offset(&chan, chanset->sec20_offset);

		chanset->inactive = !ieee80211_ap_chan_40_bw_permitted(vap, &chan);
	}


	return 0;
}

static int
ieee80211_udpate_chan_table_cost(struct ieee80211com *ic,
	struct ieee80211_chanset *chanset, int chanset_size)
{
	int i;
	struct autochan_ranking_params *rank_params = &ic->ic_autochan_ranking_params;

	for (i = 0; i < chanset_size; i++) {
		chanset[i].cost =
			rank_params->cci_instnt_factor * chanset[i].cci_instnt +
			rank_params->aci_instnt_factor * chanset[i].aci_instnt +
			rank_params->cci_longterm_factor * chanset[i].cci_longterm +
			rank_params->aci_longterm_factor * chanset[i].aci_longterm +
			rank_params->range_factor * chanset[i].range_cost +
			rank_params->dfs_factor * chanset[i].is_dfs -
			rank_params->dfs_factor;
	}

	return 0;
}

static int
ieee80211_udpate_chan_table_values(struct ieee80211com *ic,
	struct ieee80211_chanset *chanset, int chanset_size)
{
	if (!ieee80211_chan_selection_allowed(ic))
		return -1;

	ieee80211_udpate_chan_table_invalid_flag(ic, chanset, chanset_size);
	ieee80211_update_chan_table_cci_instnt(ic, chanset, chanset_size);
	ieee80211_udpate_chan_table_aci_instnt(ic, chanset, chanset_size);
	ieee80211_udpate_chan_table_cci_aci_longterm(ic, chanset, chanset_size);
	ieee80211_update_chan_table_range_cost(ic, chanset, chanset_size);
	ieee80211_update_chan_table_dfs_flag(ic, chanset, chanset_size);
	ieee80211_udpate_chan_table_inactive_flag(ic, chanset, chanset_size);
	ieee80211_udpate_chan_table_cost(ic, chanset, chanset_size);

	return 0;
}

static void
ieee80211_dump_neighbor_beacon_info(struct ieee80211com *ic)
{
	struct ap_state *as = ic->ic_scan->ss_priv;
	struct ap_scan_entry *se, *next;
	struct ieee80211_scan_entry *ise;
	struct ieee80211_chanset *chan;
	char ssid[IEEE80211_NWID_LEN + 1];
	int aci = CHAN_NUMACIBINS - 1;
	int b_sec_offset;
	int b_bw;
	int rssi;
	int b_upperedge;
	int b_loweredge;
	int neighbor_type;
	int i, j;

	neighbor_type = ieee80211_get_type_of_neighborhood(ic);
	IEEE80211_CSDBG(CHAN_SEL_LOG_INFO, "%d BSSes are found and the environment is %s\n",
		ic->ic_neighbor_count, ieee80211_neighborhood_type2str(neighbor_type));

	if (ic->ic_neighbor_count > 0) {
		IEEE80211_CSDBG(CHAN_SEL_LOG_INFO, "%-32s %-7s %-9s %-9s %-9s"
			" %-9s %-4s %-8s\n", "Beacon", "Channel", "Bandwidth",
			"Sec20_off", "CCI_edge-", "CCI_edge+", "RSSI", "ACI_span");
	}

	for (i = 0; i < IEEE80211_CHAN_MAX; i++) {
		TAILQ_FOREACH_SAFE(se, &as->as_scan_list[i].asl_head, ase_list, next) {
			ise = &se->base;

			memset(ssid, 0, sizeof(ssid));
			memcpy(ssid, &ise->se_ssid[2], MIN(IEEE80211_NWID_LEN, ise->se_ssid[1]));

			b_bw = ieee80211_get_max_ap_bw(ise);
			b_sec_offset = ieee80211_get_ap_sec_chan_offset(ise);
			chan = ieee80211_get_beacon_chanset(i, b_bw, b_sec_offset);
			if (!chan) {
				IEEE80211_CSDBG(CHAN_SEL_LOG_ERR,
					"%s: fail to find chanset for beacon %s "
					"(channel %d bw %d sec20_offset %d)\n", __func__,
					ssid, i, b_bw, b_sec_offset);
				continue;
			}
			b_upperedge = ieee80211_get_chanset_cci_high_edge(ic, chan);
			b_loweredge = ieee80211_get_chanset_cci_low_edge(ic, chan);

			rssi = ise->se_rssi - IEEE80211_PSEUDO_RSSI_TRANSITON_FACTOR;

			for (j = 0; j < CHAN_NUMACIBINS; j++) {
				if (rssi >= g_aci_params[j].rssi) {
					aci = j;
					break;
				}
			}

			IEEE80211_CSDBG(CHAN_SEL_LOG_INFO,
				"%-32s %-7d %-9s %-9d %-9d %-9d %-4d %-8s\n",
				ssid, i, ieee80211_bw2str(b_bw), b_sec_offset,
				b_loweredge, b_upperedge, rssi,
				ieee80211_bw2str(g_aci_params[aci].bw));
		}
	}
}

static void
ieee80211_dump_chan_table_values(struct ieee80211com *ic,
	struct ieee80211_chanset *chanset, int chanset_size)
{
	struct ieee80211_chanset *chan;
	int c_upperedge;
	int c_loweredge;
	int i, j;

	IEEE80211_CSDBG(CHAN_SEL_LOG_INFO, "Dump Chanset table info:\n");
	IEEE80211_CSDBG(CHAN_SEL_LOG_INFO, "%-7s %-8s %-9s %-11s %-9s %-9s %-7s"
			" %-8s %-19s %-13s %-10s %-10s %-12s %-12s %-10s %-6s %-5s\n",
			"Chanset", "Pri_chan", "Bandwidth", "Center_chan", "CCI_edge-",
			"CCI_edge+", "Invalid", "Inactive", "CCA_Array[0~3]", "CCA_Pri[0~1]",
			"CCI_instnt", "ACI_instnt", "CCI_longterm", "ACI_longterm",
			"Range_cost", "Is_dfs", "Cost");

	for (i = 0; i < chanset_size; i++) {
		chan = &chanset[i];

		c_upperedge = ieee80211_get_chanset_cci_high_edge(ic, chan);
		c_loweredge = ieee80211_get_chanset_cci_low_edge(ic, chan);

		IEEE80211_CSDBG(CHAN_SEL_LOG_INFO,  "%-7d %-8d %-9s %-11d %-9d %-9d"
			" %-7d %-8d ", i, chan->pri_chan, ieee80211_bw2str(chan->bw),
			chan->center_chan, c_loweredge, c_upperedge, chan->invalid,
			chan->inactive);

		for (j = 0; j < ARRAY_SIZE(chan->cca_array); j++)
			IEEE80211_CSDBG(CHAN_SEL_LOG_INFO,
					"%-4d ", chan->cca_array[j]);
		for (j = 0; j < ARRAY_SIZE(chan->cca_pri); j++)
			IEEE80211_CSDBG(CHAN_SEL_LOG_INFO, "%-6d ", chan->cca_pri[j]);

		IEEE80211_CSDBG(CHAN_SEL_LOG_INFO, "%-10d %-10d %-12d %-12d %-10d %-6d"
			" %-5d\n", chan->cci_instnt, chan->aci_instnt, chan->cci_longterm,
			chan->aci_longterm, chan->range_cost, chan->is_dfs, chan->cost);
	}
}

static struct ieee80211_chanset *
ieee80211_get_random_best_chanset_for_bw(struct ieee80211com *ic,
	struct ieee80211_chanset *chanset, int chanset_size, int bw)
{
	struct ieee80211_chanset *best_equal[CHAN_MAX_NUM_PER_BAND] = {NULL};
	struct ieee80211_chanset *best = NULL;
	uint8_t best_cnt = 0;
	uint8_t seed;
	int i;

	for (i = 0; i < chanset_size; i++) {
		if ((chanset[i].bw == bw) &&
				(ic->ic_max_system_bw >= bw) &&
				(ic->ic_autochan_last_scan_bw <= bw) &&
				(chanset[i].invalid == 0) &&
				(chanset[i].inactive == 0)) {
			if (!best || (chanset[i].cost < best->cost)) {
				best = &chanset[i];
				best_cnt = 0;
			}

			if (best && (best_cnt < CHAN_MAX_NUM_PER_BAND) &&
					(chanset[i].cost == best->cost))
				best_equal[best_cnt++] = &chanset[i];
		}
	}

	if (best_cnt > 1) {
		get_random_bytes(&seed, sizeof(seed));
		best = best_equal[(seed % best_cnt)];
		if (best) {
			IEEE80211_CSDBG(CHAN_SEL_LOG_INFO, "Select channel %u"
				" randomly for bandwidth %u as multiple channels"
				" have same metric\n", best->pri_chan, bw);
		}
	}

	return best;
}

static struct ieee80211_chanset *
ieee80211_get_best_chanset(struct ieee80211com *ic,
	struct ieee80211_chanset *chanset, int chanset_size)
{
	struct ieee80211_chanset *best_160 = NULL;
	struct ieee80211_chanset *best_80 = NULL;
	struct ieee80211_chanset *best_40 = NULL;
	struct ieee80211_chanset *best_20 = NULL;
	struct ieee80211_chanset *best = NULL;

	best_160 = ieee80211_get_random_best_chanset_for_bw(ic,
			chanset, chanset_size, BW_HT160);
	best_80 = ieee80211_get_random_best_chanset_for_bw(ic,
			chanset, chanset_size, BW_HT80);
	best_40 = ieee80211_get_random_best_chanset_for_bw(ic,
			chanset, chanset_size, BW_HT40);
	best_20 = ieee80211_get_random_best_chanset_for_bw(ic,
			chanset, chanset_size, BW_HT20);
	best = best_160 ? best_160 : (best_80 ? best_80 : (best_40 ? best_40 : best_20));

	if (ic->ic_bw_auto_select) {
		if (IS_IEEE80211_24G_BAND(ic)) {
			if (best_40 && best_20 && (best_40->cost >
					ic->ic_autochan_ranking_params.maxbw_minbenefit
						* best_20->cost))
				best = best_20;
		} else {
			if (best_160 && best_80 && (best_160->cost >
					ic->ic_autochan_ranking_params.maxbw_minbenefit
						* best_80->cost))
				best = best_80;
		}
	}

	return best;
}

void
ieee80211_init_chanset_ranking_params(struct ieee80211com *ic)
{
	if (IS_IEEE80211_24G_BAND(ic)) {
		ic->ic_autochan_ranking_params = g_ranking_params_2g_scsoff;
	} else {
		if (!ic->ic_scs.scs_enable)
			ic->ic_autochan_ranking_params = g_ranking_params_5g_scsoff;
		else
			ic->ic_autochan_ranking_params = g_ranking_params_5g_scson;
	}

	IEEE80211_CSDBG(CHAN_SEL_LOG_INFO,
			"Chanset ranking params:\n"
			"cci_instnt_factor\t%d\n"
			"aci_instnt_factor\t%d\n"
			"cci_longterm_factor\t%d\n"
			"aci_longterm_factor\t%d\n"
			"range_factor\t\t%d\n"
			"dfs_factor\t\t%d\n"
			"min_cochan_rssi\t\t%d\n"
			"maxbw_minbenefit\t\t%d\n"
			"dense_cci_span\t\t%dMHz\n",
			ic->ic_autochan_ranking_params.cci_instnt_factor,
			ic->ic_autochan_ranking_params.aci_instnt_factor,
			ic->ic_autochan_ranking_params.cci_longterm_factor,
			ic->ic_autochan_ranking_params.aci_longterm_factor,
			ic->ic_autochan_ranking_params.range_factor,
			ic->ic_autochan_ranking_params.dfs_factor,
			ic->ic_autochan_ranking_params.min_cochan_rssi,
			ic->ic_autochan_ranking_params.maxbw_minbenefit,
			ic->ic_autochan_ranking_params.dense_cci_span);
}

static void
ieee80211_check_chanset_table(struct ieee80211com *ic)
{
	int found;
	int i, j;

	for (i = 0; i < IEEE80211_CHAN_MAX; i++) {
		if (isclr(ic->ic_chan_avail, i))
			continue;

		found = 0;
		for (j = 0; j < ARRAY_SIZE(g_chansets_2g_bw20); j++) {
			if (g_chansets_2g_bw20[j].pri_chan == i) {
				found = 1;
				break;
			}
		}

		if (found)
			continue;

		for (j = 0; j < ARRAY_SIZE(g_chansets_5g_bw20); j++) {
			if (g_chansets_5g_bw20[j].pri_chan == i) {
				found = 1;
				break;
			}
		}

		if (!found)
			IEEE80211_CSDBG(CHAN_SEL_LOG_ERR,
				"%s: fail to find channel %d in chanset table,"
				" please update chanset table\n", __func__, i);
	}
}

static int
ieee80211_init_chanset_table(struct ieee80211com *ic)
{
	struct ieee80211_chanset *chanset = NULL;
	int bw = ieee80211_get_bw(ic);
	int total_size = 0;
	int table_size = 0;
	int offset = 0;
	int band;

	ieee80211_check_chanset_table(ic);

	if (ic->ic_autochan_table.num) {
		ieee80211_free(ic->ic_autochan_table.chanset);
		ic->ic_autochan_table.chanset = NULL;
		ic->ic_autochan_table.num = 0;
	}

	if (IS_IEEE80211_24G_BAND(ic)) {
		band = IEEE80211_2_4Ghz;

		total_size = ARRAY_SIZE(g_chansets_2g_bw20);
		if (bw >= BW_HT40)
			total_size += ARRAY_SIZE(g_chansets_2g_bw40);
	} else {
		band = IEEE80211_5Ghz;

		total_size = ARRAY_SIZE(g_chansets_5g_bw20);
		if (bw >= BW_HT40)
			total_size += ARRAY_SIZE(g_chansets_5g_bw40);
		if (bw >= BW_HT80)
			total_size += ARRAY_SIZE(g_chansets_5g_bw80);
		if (bw >= BW_HT160)
			total_size += ARRAY_SIZE(g_chansets_5g_bw160);
	}

	ic->ic_autochan_table.chanset =
		ieee80211_malloc(total_size * sizeof(*chanset), GFP_KERNEL);
	if (!ic->ic_autochan_table.chanset) {
		IEEE80211_CSDBG(CHAN_SEL_LOG_ERR,
			"%s: fail to allocate channel table\n", __func__);
		return -1;
	}
	ic->ic_autochan_table.num = total_size;

	while (bw >= BW_HT20) {
		chanset = ieee80211_find_chan_table(band, bw, &table_size);
		if (!chanset) {
			IEEE80211_CSDBG(CHAN_SEL_LOG_ERR,
				"%s: fail to find channel table for band %s"
				" and bandwidth %d\n", __func__,
				IS_IEEE80211_24G_BAND(ic) ? "2.4G" : "5G", bw);
			goto fail;
		}

		if ((offset + table_size) > total_size) {
			IEEE80211_CSDBG(CHAN_SEL_LOG_INFO,
				"%s: channel set table overflow for %s %s\n",
				__func__, IS_IEEE80211_24G_BAND(ic) ? "2.4G" : "5G",
				ieee80211_bw2str(bw));
			goto fail;
		}

		memcpy(&ic->ic_autochan_table.chanset[offset],
				chanset, table_size * sizeof(*chanset));

		IEEE80211_CSDBG(CHAN_SEL_LOG_INFO,
			"%s: initialize chanset table for band %s bandwith %s\n",
			__func__, IS_IEEE80211_24G_BAND(ic) ? "2.4G" : "5G",
			ieee80211_bw2str(bw));

		offset += table_size;
		bw = bw >> 1;
	}

	ieee80211_reset_chan_table_values(ic, &ic->ic_autochan_table);

	return 0;

fail:
	ieee80211_free(ic->ic_autochan_table.chanset);
	ic->ic_autochan_table.chanset = NULL;
	ic->ic_autochan_table.num = 0;

	return -1;
}

static int
ieee80211_add_chanset_scan_type(struct ieee80211com *ic, int bw)
{
	char *type_str;
	int index = 0;
	int i;

	for (i = 0; i < CHAN_SELECT_SCAN_MAX; i++) {
		if (ic->ic_autochan_scan_type[i] == CHAN_SELECT_SCAN_INVALID) {
			index = i;
			break;
		}
	}

	ic->ic_autochan_last_scan_bw = bw;

	switch (bw) {
	case BW_HT20:
		ic->ic_autochan_scan_type[index] = CHAN_SELECT_SCAN_BW20;
		type_str = "BW20";
		break;
	case BW_HT40:
		if (IS_IEEE80211_24G_BAND(ic)) {
			if (index > CHAN_SELECT_SCAN_MAX - 2) {
				IEEE80211_CSDBG(CHAN_SEL_LOG_ERR,
					"%s: incorrect scan type index %d\n",
					__func__, index);
				return -1;
			}

			ic->ic_autochan_scan_type[index] = CHAN_SELECT_SCAN_BW40_ABOVE;
			ic->ic_autochan_scan_type[index+1] = CHAN_SELECT_SCAN_BW40_BELOW;
			type_str = "BW40_ABOVE BW40_BELOW";
		} else {
			ic->ic_autochan_scan_type[index] = CHAN_SELECT_SCAN_BW40;
			type_str = "BW40";
		}
		break;
	case BW_HT80:
		ic->ic_autochan_scan_type[index] = CHAN_SELECT_SCAN_BW80;
		type_str = "BW80";
		break;
	case BW_HT160:
		ic->ic_autochan_scan_type[index] = CHAN_SELECT_SCAN_BW160;
		type_str = "BW160";
		break;
	default:
		type_str = "INVALID";
		break;
	}

	IEEE80211_CSDBG(CHAN_SEL_LOG_INFO,
		"%s: add chanset scan type %s\n", __func__, type_str);

	return 0;
}

static void
ieee80211_set_chanset_sec_chan(struct ieee80211com *ic, int sec_offset)
{
	struct ieee80211_channel *chan;
	int i;

	for (i = 1; i <= QTN_2G_LAST_OPERATING_CHAN; i++) {
		chan = findchannel_any(ic, i, ic->ic_des_mode);
		if (!is_ieee80211_chan_valid(chan)) {
			IEEE80211_CSDBG(CHAN_SEL_LOG_ERR,
				"%s: fail to find channel %d\n",
				__func__, i);
			continue;
		}

		if (!ieee80211_dual_sec_chan_supported(ic, chan))
			continue;

		IEEE80211_CSDBG(CHAN_SEL_LOG_INFO,
			"%s: set sec_chan_offset to %d for channel %d\n",
			__func__, sec_offset, i);

		ieee80211_update_sec_chan_offset(chan, sec_offset);
	}
}

__inline int
ieee80211_chanset_scan_finished(struct ieee80211com *ic)
{
	if ((IS_IEEE80211_5G_BAND(ic)) ||
		(ic->ic_autochan_scan_type[0] == CHAN_SELECT_SCAN_INVALID))
		return 1;
	else
		return 0;
}
EXPORT_SYMBOL(ieee80211_chanset_scan_finished);

int
ieee80211_start_chanset_scan(struct ieee80211vap *vap, int scan_flags)
{
	struct ieee80211com *ic = vap->iv_ic;
	char *bw_str = IEEE80211_BWSTR_20;

	if ((ic->ic_autochan_scan_type[0] == CHAN_SELECT_SCAN_BW40) ||
		(ic->ic_autochan_scan_type[0] == CHAN_SELECT_SCAN_BW40_ABOVE) ||
		(ic->ic_autochan_scan_type[0] == CHAN_SELECT_SCAN_BW40_BELOW)) {
		scan_flags |= IEEE80211_SCAN_BW40;
		bw_str = IEEE80211_BWSTR_40;
	} else if (ic->ic_autochan_scan_type[0] == CHAN_SELECT_SCAN_BW80) {
		scan_flags |= IEEE80211_SCAN_BW80;
		bw_str = IEEE80211_BWSTR_80;
	}

	if (ic->ic_autochan_scan_type[0] == CHAN_SELECT_SCAN_BW40_ABOVE)
		ieee80211_set_chanset_sec_chan(ic, IEEE80211_HTINFO_CHOFF_SCA);
	else if (ic->ic_autochan_scan_type[0] == CHAN_SELECT_SCAN_BW40_BELOW)
		ieee80211_set_chanset_sec_chan(ic, IEEE80211_HTINFO_CHOFF_SCB);

	IEEE80211_CSDBG(CHAN_SEL_LOG_INFO, "%s: Start scan with bandwidth %s\n",
		__func__, bw_str);

	return ieee80211_check_scan(vap, scan_flags, IEEE80211_SCAN_FOREVER,
			vap->iv_des_nssid, vap->iv_des_ssid, NULL);
}
EXPORT_SYMBOL(ieee80211_start_chanset_scan);

int
ieee80211_start_chanset_selection(struct ieee80211vap *vap, int scan_flags)
{
	struct ieee80211com *ic = vap->iv_ic;
	int bw = ieee80211_get_bw(ic);
	int ret;

	ic->ic_autochan_scan_flags = scan_flags;
	memset(ic->ic_autochan_scan_type, CHAN_SELECT_SCAN_INVALID,
		sizeof(ic->ic_autochan_scan_type));

	ret = ieee80211_init_chanset_table(ic);
	if (ret < 0) {
		IEEE80211_CSDBG(CHAN_SEL_LOG_ERR,
			"%s: fail to initilize channel table\n", __func__);
		return ret;
	}

	/*
	 * Only once scan with 20M bandwidth can gather enough information
	 * if instantaneous factors are all 0
	 */
	if ((ic->ic_autochan_ranking_params.cci_instnt_factor == 0) &&
			(ic->ic_autochan_ranking_params.aci_instnt_factor == 0))
		bw = BW_HT20;

	ret = ieee80211_add_chanset_scan_type(ic, bw);
	if (ret < 0) {
		IEEE80211_CSDBG(CHAN_SEL_LOG_ERR,
			"%s: fail to add scan bandwidth %s\n",
			__func__, ieee80211_bw2str(bw));
		return ret;
	}

	if ((ic->ic_bw_auto_select) && (bw > BW_HT20)) {
		ret = ieee80211_add_chanset_scan_type(ic, bw/2);
		if (ret < 0) {
			IEEE80211_CSDBG(CHAN_SEL_LOG_ERR,
				"%s: fail to add scan bandwidth %s\n",
				__func__, ieee80211_bw2str(bw/2));
			return ret;
		}
	}

	return ieee80211_start_chanset_scan(vap, scan_flags);
}

__inline void
ieee80211_chanset_shift_scan_type(struct ieee80211com *ic)
{
	int i;

	for (i = 0; i < CHAN_SELECT_SCAN_MAX - 1; i++)
		ic->ic_autochan_scan_type[i] = ic->ic_autochan_scan_type[i + 1];
	ic->ic_autochan_scan_type[CHAN_SELECT_SCAN_MAX - 1] = CHAN_SELECT_SCAN_INVALID;
}

struct ieee80211_channel *
ieee80211_chanset_pick_channel(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_chanset *best = NULL;
	struct ieee80211_channel *chan = NULL;
	int cur_bw = ieee80211_get_bw(ic);
	int bw;
	int ret;

	ieee80211_update_scan_cca_info(ic);
	ieee80211_chanset_shift_scan_type(ic);

	if (is_ieee80211_chan_valid(ic->ic_des_chan)) {
		IEEE80211_CSDBG(CHAN_SEL_LOG_WARN,
			"%s: BSS channel is already configured"
			" and bypass channel selection\n", __func__);
		return ic->ic_des_chan;
	}

	if (!ieee80211_chanset_scan_finished(ic)) {
		IEEE80211_CSDBG(CHAN_SEL_LOG_INFO,
			"%s: Channel selection not finished,"
			" start next scan\n", __func__);
		return NULL;
	}

	ieee80211_udpate_chan_table_values(ic,
		ic->ic_autochan_table.chanset, ic->ic_autochan_table.num);

	ieee80211_dump_neighbor_beacon_info(ic);

	ieee80211_dump_chan_table_values(ic,
		ic->ic_autochan_table.chanset, ic->ic_autochan_table.num);

	best = ieee80211_get_best_chanset(ic,
		ic->ic_autochan_table.chanset, ic->ic_autochan_table.num);

	if (!best) {
		if (ic->ic_autochan_last_scan_bw > BW_HT20) {
			IEEE80211_CSDBG(CHAN_SEL_LOG_INFO,
				"%s: all candidate channels are inactive,"
				"try to halve bandwidth and rescan\n", __func__);

			bw = ic->ic_autochan_last_scan_bw >> 1;
			ret = ieee80211_add_chanset_scan_type(ic, bw);
			if (ret < 0) {
				IEEE80211_CSDBG(CHAN_SEL_LOG_INFO,
					"%s: failed to add new scan tyep for "
					"bandwidth %s\n", __func__,
					ieee80211_bw2str(bw));
				return NULL;
			}
		}
	} else {
		IEEE80211_CSDBG(CHAN_SEL_LOG_INFO,
			"%s: candidate channel %d bandwidth %s sec20_offsest %d\n",
			__func__, best->pri_chan, ieee80211_bw2str(best->bw),
			best->sec20_offset);

		chan = findchannel_any(ic, best->pri_chan, ic->ic_des_mode);
		if (!is_ieee80211_chan_valid(chan)) {
			IEEE80211_CSDBG(CHAN_SEL_LOG_ERR,
				"%s: fail to find candidate channel %d\n",
				__func__, best->pri_chan);
			return NULL;
		}

		if (ieee80211_dual_sec_chan_supported(ic, chan))
			ieee80211_update_sec_chan_offset(chan, best->sec20_offset);

		if (cur_bw != best->bw) {
			IEEE80211_CSDBG(CHAN_SEL_LOG_INFO, "%s: change bandwidth to %s\n",
				__func__, ieee80211_bw2str(best->bw));
			ieee80211_change_bw(vap, best->bw, 0);
		}
	}

	return chan;
}
EXPORT_SYMBOL(ieee80211_chanset_pick_channel);

void
ieee80211_clean_chanset_values(struct ieee80211com *ic)
{
	ieee80211_free(ic->ic_autochan_table.chanset);
	ic->ic_autochan_table.chanset = NULL;
	ic->ic_autochan_table.num = 0;

	memset(ic->ic_autochan_scan_type, CHAN_SELECT_SCAN_INVALID,
			sizeof(ic->ic_autochan_scan_type));
	ic->ic_autochan_scan_flags = 0;
}

