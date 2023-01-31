/*
 * (C) Copyright 2017 Quantenna Communications Inc.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#ifndef __QTN_BITS_H
#define __QTN_BITS_H

#if !defined(__KERNEL__) && !defined(BIT)
#define BIT(x)		(1 << (x))
#endif

#define MS(_v, _f)	(((_v) >> _f##_S) & (_f >> _f##_S))
#define SM(_v, _f)	(((_v) & (_f >> _f##_S)) << _f##_S)

/* Variants of the SM and MS macros that don't require a shift position macro */
#define MS_OP(_v, _f)			(((_v) & (_f)) >> __builtin_ctz(_f))
#define SM_OP(_v, _f)			(((_v) << __builtin_ctz(_f)) & (_f))

/*
 * The following macro couldn't be defined via SM because of issues with nesting ##
 * i.e. the following define does not work
 * do{ where = (where) & (~(bitmask)) | SM(new_value, bitmask); }while(0)
 */
#define UPDATE_BITSET(where, bitmask, new_value) \
	do{ where = ((where) & (~(bitmask))) | (((new_value) << bitmask##_S) & bitmask); }while(0)

#endif	// __QTN_BITS_H

