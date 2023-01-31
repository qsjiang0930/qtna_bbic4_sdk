/*-
 * Copyright (c) 2017 Quantenna Communications Inc.
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
 * $Id: _ieee80211.h 2749 2007-10-16 08:58:14Z kelmo $
 */

#ifndef _NET80211__IEEE80211_QVSP_H_
#define _NET80211__IEEE80211_QVSP_H_

/**
 * The following structure definitions are for passing in data to the
 * management send function to generate action frames for VSP.
 */
struct ieee80211_qvsp_act {
	uint8_t oui[3];
	uint8_t type;
};

struct ieee80211_qvsp_strm_id {
	union {
		struct in6_addr	ipv6;
		__be32		ipv4;
	} saddr;
	union {
		struct in6_addr ipv6;
		__be32		ipv4;
	} daddr;
	__be16 sport;
	__be16 dport;
	uint8_t ip_version;
	uint8_t ip_proto;
	uint8_t ac;
} __packed;

#define IEEE8021_QVSP_MAX_ACT_ITEMS 32

struct ieee80211_qvsp_strm_dis_attr {
	uint32_t throt_policy;
	uint32_t throt_rate;
	uint32_t demote_rule;
	uint32_t demote_state;
};

struct ieee80211_qvsp_act_strm_ctrl {
	struct ieee80211_qvsp_act header;
	uint8_t strm_state;
	uint8_t count;
	struct ieee80211_qvsp_strm_dis_attr dis_attr;
	struct ieee80211_qvsp_strm_id strm_items[IEEE8021_QVSP_MAX_ACT_ITEMS];
};

struct ieee80211_qvsp_act_cfg_item {
	uint32_t index;
	uint32_t value;
};

struct ieee80211_qvsp_act_cfg {
	struct ieee80211_qvsp_act header;
	uint8_t count;
	struct ieee80211_qvsp_act_cfg_item cfg_items[IEEE8021_QVSP_MAX_ACT_ITEMS];
};
#endif
