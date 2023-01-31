/**
 * Copyright (c) 2012 - 2017 Quantenna Communications Inc
 * All Rights Reserved
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 **/

#ifndef _IEEE80211_DFS_REENTRY_H
#define _IEEE80211_DFS_REENTRY_H

/*
 *  DFS-reentry
 */
#define IEEE80211_PICK_DOMIAN_MASK	0x0007
#define IEEE80211_PICK_ALL		0x0001		/* pick channel from all available channels */
#define IEEE80211_PICK_DFS		0x0002		/* pick channel from available DFS channel */
#define IEEE80211_PICK_NONDFS		0x0004		/* pick channel from available non-DFS channel */

#define IEEE80211_PICK_CONTROL_MASK		0x00F8
#define IEEE80211_PICK_SCAN_FLUSH		0x0008
/*
 *  IEEE80211_PICK_BG_* and IEEE80211_SCAN_* flags share the same bits and can not be used together.
 *  IEEE80211_PICK_BG_* flags can only be used if IEEE80211_PICK_NOPICK_BG is set.
 */
#define IEEE80211_SCAN_RANDOMIZE		0x0010

enum ieee80211_bgscan_mode {
	IEEE80211_BGSCAN_MODE_ACTIVE = 0x01,
	IEEE80211_BGSCAN_MODE_PASSIVE_FAST = 0x02,
	IEEE80211_BGSCAN_MODE_FAKE_PS = 0x03,
	IEEE80211_BGSCAN_MODE_PASSIVE_NORMAL = 0x04,
	IEEE80211_BGSCAN_MODE_PASSIVE_SLOW = 0x08,
};
#define IEEE80211_PICK_BG_MODE_MASK		0x00F0
#define IEEE80211_PICK_BG_MODE_SHIFT		4

#define IEEE80211_PICK_BG_ACTIVE		\
	(IEEE80211_BGSCAN_MODE_ACTIVE << IEEE80211_PICK_BG_MODE_SHIFT)
#define IEEE80211_PICK_BG_PASSIVE_FAST		\
	(IEEE80211_BGSCAN_MODE_PASSIVE_FAST << IEEE80211_PICK_BG_MODE_SHIFT)
#define IEEE80211_PICK_BG_PASSIVE_NORMAL		\
	(IEEE80211_BGSCAN_MODE_PASSIVE_NORMAL << IEEE80211_PICK_BG_MODE_SHIFT)
#define IEEE80211_PICK_BG_PASSIVE_SLOW		\
	(IEEE80211_BGSCAN_MODE_PASSIVE_SLOW << IEEE80211_PICK_BG_MODE_SHIFT)

#define IEEE80211_PICK_BG_CHECK			0x8000	/* scan background with the check of beacon conflicts */

#define IEEE80211_PICK_ALGORITHM_MASK	0x7F00
#define IEEE80211_PICK_CLEAREST		0x0100		/* pick clearest channel */
#define IEEE80211_PICK_REENTRY		0x0200		/* pick channel again after DFS process */
#define IEEE80211_PICK_NOPICK		0x0400		/* do not pick channel */
#define IEEE80211_PICK_NOPICK_BG	0x0800		/* scan background and do not pick channel */

#define IEEE80211_PICK_DEFAULT		(IEEE80211_PICK_ALL | IEEE80211_PICK_CLEAREST)

#define IEEE80211_SCS_PICK_DFS_ONLY			0x0001	/* Pick channels from DFS set only*/
#define IEEE80211_SCS_PICK_NON_DFS_ONLY			0x0002	/* Pick channels from Non-DFS set only*/
#define IEEE80211_SCS_PICK_AVAILABLE_DFS_ONLY		0x0004	/* Pick channels from available DFS set*/
#define IEEE80211_SCS_PICK_AVAILABLE_ANY_CHANNEL	0x0008	/* Pick channels from available DFS and Non-DFS sets*/
#define IEEE80211_SCS_PICK_ANYWAY			0x0010	/* Omit channel margins during channel pick*/
#define IEEE80211_SCS_PICK_NOT_AVAILABLE_DFS_ONLY	0x0020	/* Pick channels from unavailable DFS set*/
#define IEEE80211_SCS_PICK_ALLOW_CURRENT		0x0040	/* Allow for picking the current channels */
#define IEEE80211_SCS_PICK_OCAC_CHANNEL			0x0080	/* Pick OCAC available channel from DFS channels */
#define IEEE80211_SCS_NOPICK				0x8000	/* Don't switch channel after picking up the best channel */

/* Prefer selecting DFS only channels for bootup CAC;
 * Below flag must be used only while calling below APIs
 * ieee80211_scan_pickchannel, scan_pickchan, ap_pick_channel
 */
#define IEEE80211_SCAN_PICK_NOT_AVAILABLE_DFS_ONLY		0x00110000

/* Select channel from DFS and non-DFS sets which are available only*/
/* All Non-DFS channels are available by default,
 * DFS channels are available only after CAC-Completion events;
 * Below flag must be used only while calling below APIs
 * ieee80211_scan_pickchannel, scan_pickchan, ap_pick_channel
 */
#define IEEE80211_SCAN_PICK_AVAILABLE_ANY_CHANNEL		0x00120000

/*
 * Select any valid DFS channel from {CAC_REQUIRED, AVAILABLE} set;
 * Below flag must be used only while calling below APIs
 * ieee80211_scan_pickchannel, scan_pickchan, ap_pick_channel
 */
#define IEEE80211_SCAN_PICK_ANY_DFS				0x00130000

#endif
