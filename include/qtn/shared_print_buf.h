/**
 * Copyright (c) 2010 - 2017 Quantenna Communications Inc
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

#ifndef __SHARED_PRINT_BUF
#define __SHARED_PRINT_BUF

struct shared_print_producer {
	u32	produced;
	u32	bufsize;
	char*	buf;		/* producer address space ptr */
};

struct shared_print_consumer {
	const volatile struct shared_print_producer * producer;
	u32 consumed;
	char* buf;		/* consumer address space ptr */
};

#endif // __SHARED_PRINT_BUF
