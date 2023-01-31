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

#include "qtn/qdrv_sch.h"
#include "qtn/bootcfg_hw_board_config.h"
#include "qdrv_sch_wmm.h"


const int qdrv_sch_band_prio[] = {
	QDRV_BAND_CTRL,
	QDRV_BAND_AC_VO,
	QDRV_BAND_AC_VI,
	QDRV_BAND_AC_BE,
	QDRV_BAND_AC_BK
};

static const char *ac_name[] = {"BE", "BK", "VI", "VO"};

struct qdrv_sch_band_aifsn qdrv_sch_band_chg_prio[] = {
	{QDRV_BAND_CTRL, 1},
	{QDRV_BAND_AC_VO, 1},
	{QDRV_BAND_AC_VI, 1},
	{QDRV_BAND_AC_BE, 3},
	{QDRV_BAND_AC_BK, 7}
};

const char *qdrv_sch_tos2ac_str(int tos)
{
	if ((tos < 0) || (tos >= IEEE8021P_PRIORITY_NUM))
		return NULL;

	return ac_name[qdrv_sch_tos2ac[tos]];
}

void qdrv_sch_set_ac_map(int tos, int aid)
{
	if ((tos >= 0) && (tos < IEEE8021P_PRIORITY_NUM) &&
			(aid >= 0) && (aid < QDRV_SCH_PRIORITIES)) {
		qdrv_sch_tos2ac[tos] = aid;
	}
}

uint32_t qdrv_sch_get_emac_in_use(void)
{
	uint32_t emac_in_use = 0;
	int emac_cfg = 0;

	if (bootcfg_get_hw_board_config(BOARD_CFG_EMAC0, NULL, &emac_cfg) == 0) {
		if (emac_cfg & EMAC_IN_USE) {
			emac_in_use |= QDRV_SCH_EMAC0_IN_USE;
		}
	}
	if (bootcfg_get_hw_board_config(BOARD_CFG_EMAC1, NULL, &emac_cfg) == 0) {
		if (emac_cfg & EMAC_IN_USE) {
			emac_in_use |= QDRV_SCH_EMAC1_IN_USE;
		}
	}

	return emac_in_use;
}

int qdrv_sch_set_dscp2ac_map(const uint8_t vapid, uint8_t *ip_dscp, uint8_t listlen, uint8_t ac)
{
	uint8_t i;
	const uint32_t emac_in_use = qdrv_sch_get_emac_in_use();

	for (i = 0; i < listlen; i++) {
		qdrv_sch_mask_settid(vapid, ip_dscp[i], WME_AC_TO_TID(ac), emac_in_use);
	}

	return 0;
}

void qdrv_sch_set_dscp2tid_map(const uint8_t vapid, const uint8_t *dscp2tid)
{
	uint8_t dscp;
	uint8_t tid;
	const uint32_t emac_in_use = qdrv_sch_get_emac_in_use();

	for (dscp = 0; dscp < IP_DSCP_NUM; dscp++) {
		tid = dscp2tid[dscp];
		if (tid >= IEEE8021P_PRIORITY_NUM)
			tid = qdrv_dscp2tid_default(dscp);
		tid = QTN_TID_MAP_UNUSED(tid);
		qdrv_sch_mask_settid(vapid, dscp, tid, emac_in_use);
	}
}

void qdrv_sch_get_dscp2tid_map(const uint8_t vapid, uint8_t *dscp2tid)
{
	uint8_t dscp;

	for (dscp = 0; dscp < IP_DSCP_NUM; dscp++) {
		dscp2tid[dscp] = qdrv_sch_mask_gettid(vapid, dscp);
	}
}

int qdrv_sch_get_dscp2ac_map(const uint8_t vapid, uint8_t *dscp2ac)
{
	uint8_t i;

	if (!dscp2ac)
		return -1;

	for (i = 0; i < IP_DSCP_NUM; i++){
		dscp2ac[i] = TID_TO_WME_AC(qdrv_sch_mask_gettid(vapid, i));
	}

	return 0;
}
