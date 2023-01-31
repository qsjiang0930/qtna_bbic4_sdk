/**
 * Copyright (c) 2015 - 2017 Quantenna Communications Inc
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

#ifndef __BEACON_IOCTL_H__
#define __BEACON_IOCTL_H__
/*
#define LHOST_DEBUG_BEACON
#define MUC_DEBUG_BEACON
*/

#define BEACON_PARAM_SIZE		1000
/*
 * A general ie descriptor shared between sender (LHOST) and receiver (MuC).
 * To avoid issues of alignment compatibility between different hosts, all fields has 32bits
 * aligned.
 */
struct beacon_shared_ie_t
{
	dma_addr_t	buf;			/* MuC reference to the ie buffer */
	uint8_t *	lhost_buf;		/* LHOST reference to the ie buffer */
	uint32_t	size;			/* total length of ie including id + len */
	uint32_t	next_muc_addr;		/* next ie descriptor address presented in MuC addr mapping */
	struct		beacon_shared_ie_t *next;	/* next ie descriptor */
};
#endif /* __BEACON_IOCTL_H__ */
