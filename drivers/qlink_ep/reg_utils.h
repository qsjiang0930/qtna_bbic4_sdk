/**
 * Copyright (c) 2018 Quantenna Communications, Inc.
 * All rights reserved.
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
 **/

#ifndef _QLINK_EP_REG_UTILS_H_
#define _QLINK_EP_REG_UTILS_H_

#include "qlink_priv.h"

int qlink_reg_region_update(struct qlink_mac *mac, char *alpha2, int slave_radar,
	enum qlink_dfs_regions new_dfs_region);
size_t qlink_reg_mac_info_fill(struct ieee80211com *ic,
	struct qlink_resp_get_mac_info *info, unsigned int offset);
void qlink_reg_update_tx_power(struct qlink_mac *mac);
void qlink_reg_regulatory_reset(struct qlink_mac *mac);
void qlink_reg_chan_update(struct qlink_mac *mac, const struct qlink_channel *qch);
int qlink_reg_eirp_from_pchain_dbm(unsigned int macid, int max_pwr);

#endif /* _QLINK_EP_REG_UTILS_H_ */
