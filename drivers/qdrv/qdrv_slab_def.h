/**
  Copyright (c) 2019 Quantenna Communications Inc
  All Rights Reserved

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
 **/

#ifndef _QDRV_SLAB_DEF_H
#define _QDRV_SLAB_DEF_H

struct qdrv_slab_watch {
	unsigned int stat_size_tot_alloc_64;
	unsigned int stat_size_cur_alloc_64;
	unsigned int stat_size_act_alloc_64;
	unsigned int stat_size_hwm_alloc_64;
	unsigned int stat_size_tot_alloc_96;
	unsigned int stat_size_cur_alloc_96;
	unsigned int stat_size_act_alloc_96;
	unsigned int stat_size_hwm_alloc_96;
	unsigned int stat_size_tot_alloc_128;
	unsigned int stat_size_cur_alloc_128;
	unsigned int stat_size_act_alloc_128;
	unsigned int stat_size_hwm_alloc_128;
	unsigned int stat_size_tot_alloc_192;
	unsigned int stat_size_cur_alloc_192;
	unsigned int stat_size_act_alloc_192;
	unsigned int stat_size_hwm_alloc_192;
	unsigned int stat_size_tot_alloc_256;
	unsigned int stat_size_cur_alloc_256;
	unsigned int stat_size_act_alloc_256;
	unsigned int stat_size_hwm_alloc_256;
	unsigned int stat_size_tot_alloc_512;
	unsigned int stat_size_cur_alloc_512;
	unsigned int stat_size_act_alloc_512;
	unsigned int stat_size_hwm_alloc_512;
	unsigned int stat_size_tot_alloc_1024;
	unsigned int stat_size_cur_alloc_1024;
	unsigned int stat_size_act_alloc_1024;
	unsigned int stat_size_hwm_alloc_1024;
	unsigned int stat_size_tot_alloc_2048;
	unsigned int stat_size_cur_alloc_2048;
	unsigned int stat_size_act_alloc_2048;
	unsigned int stat_size_hwm_alloc_2048;
	unsigned int stat_size_tot_alloc_4096;
	unsigned int stat_size_cur_alloc_4096;
	unsigned int stat_size_act_alloc_4096;
	unsigned int stat_size_hwm_alloc_4096;
	unsigned int stat_size_tot_alloc_RX_BUF_SIZE_KMALLOC;
	unsigned int stat_size_cur_alloc_RX_BUF_SIZE_KMALLOC;
	unsigned int stat_size_act_alloc_RX_BUF_SIZE_KMALLOC;
	unsigned int stat_size_hwm_alloc_RX_BUF_SIZE_KMALLOC;
	unsigned int stat_tot_alloc_skbuff_head_cache;
	unsigned int stat_cur_alloc_skbuff_head_cache;
	unsigned int stat_act_alloc_skbuff_head_cache;
	unsigned int stat_hwm_alloc_skbuff_head_cache;
} __packed;

enum qdrv_slab_index {
	QDRV_SLAB_IDX_SIZE_64,
	QDRV_SLAB_IDX_SIZE_96,
	QDRV_SLAB_IDX_SIZE_128,
	QDRV_SLAB_IDX_SIZE_192,
	QDRV_SLAB_IDX_SIZE_256,
	QDRV_SLAB_IDX_SIZE_512,
	QDRV_SLAB_IDX_SIZE_1024,
	QDRV_SLAB_IDX_SIZE_2048,
	QDRV_SLAB_IDX_SIZE_4096,
	QDRV_SLAB_IDX_SIZE_RX_BUF_SIZE_KMALLOC,
	QDRV_SLAB_IDX_skbuff_head_cache,
	QDRV_SLAB_IDX_MAX
};

#endif
