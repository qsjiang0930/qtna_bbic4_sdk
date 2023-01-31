/*SH1
*******************************************************************************
**                                                                           **
**         Copyright (c) 2009 - 2018 Quantenna Communications, Inc.          **
**                                                                           **
**  File        : qtn_hapd_bss.h                                             **
**  Description :                                                            **
**                                                                           **
*******************************************************************************
**  Copyright 1992-2014 The FreeBSD Project. All rights reserved.            **
**  Redistribution and use in source and binary forms, with or without       **
**  modification, are permitted provided that the following conditions       **
**  are met:                                                                 **
**  1. Redistributions of source code must retain the above copyright        **
**     notice, this list of conditions and the following disclaimer.         **
**  2. Redistributions in binary form must reproduce the above copyright     **
**     notice, this list of conditions and the following disclaimer in the   **
**     documentation and/or other materials provided with the distribution.  **
**  3. The name of the author may not be used to endorse or promote products **
**     derived from this software without specific prior written permission. **
**                                                                           **
**  Alternatively, this software may also be distributed under the terms of  **
**  the GNU General Public License ("GPL") version 2, or (at your option)    **
**  any later version as published by the Free Software Foundation.          **
**                                                                           **
*******************************************************************************
EH1*/

#ifndef QTN_HAPD_BSS
#define QTN_HAPD_BSS

#ifdef CONFIG_QTNA_WIFI

#ifdef CONFIG_DPP
#include "common/dpp.h"
#endif /* CONFIG_DPP */

#ifdef CONFIG_WPS
#include "ap/wps_hostapd.h"
#endif /* CONFIG_WPS */

#define WLAN_REASON_DENIED 100

int hostapd_set_bss_params(struct hostapd_data *hapd);
int hostapd_set_total_assoc_limit(struct hostapd_data *hapd, int limit);
int hostapd_set_bss_assoc_limit(struct hostapd_data *hapd, int limit);
int qtn_hapd_acl_reject(struct hostapd_data *hapd, const u8 *own_addr);
void hostapd_send_wlan_msg(struct hostapd_data *hapd, const char *msg);
int hostapd_set_broadcast_ssid(struct hostapd_data *hapd, int value);

#ifdef CONFIG_DPP
void hapd_dpp_write_new_config(FILE *file, const void *cred);
#endif /* CONFIG_DPP */

#ifdef CONFIG_WPS
void hapd_wps_write_new_config(FILE *file, const void *cred);
#endif /* CONFIG_WPS */

#if defined(CONFIG_WPS) || defined(CONFIG_DPP)
enum {
	HAPD_CFG_TYPE_WPS,
	HAPD_CFG_TYPE_DPP,
};

struct hostapd_cfg_ctx {
	int config_type;
	char *ifname;
};

void hostapd_update_config(void *eloop_data, void *user_ctx);
void hapd_parse_and_write_new_config(struct hostapd_data *hapd, FILE *oconf, FILE *nconf,
					const void *cred, int conf_type);
#endif /* CONFIG_WPS || CONFIG_DPP */

#endif /* CONFIG_QTNA_WIFI */
#endif /* QTN_HAPD_BSS */

