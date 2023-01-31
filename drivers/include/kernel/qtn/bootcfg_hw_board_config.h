/*
 * Copyright (c) 2016 Quantenna Communications, Inc.
 * All rights reserved.
 *
 * Create a wrapper around other bootcfg datastores which compresses on write
 * and decompresses on read.
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

#ifndef _BOOTCFG_HW_BOARD_CONFIG_H
#define _BOOTCFG_HW_BOARD_CONFIG_H

#include <common/ruby_board_cfg.h>

extern int bootcfg_get_hw_board_config(uint16_t type, char* text, int* data);

#endif
