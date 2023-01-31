#ifndef __FILE__H__
#define __FILE__H__
/*
 * (C) Copyright 2010
 *
 *  Quantenna Communications Inc.
 *
 *  SPDX-License-Identifier:     GPL-2.0+
 *
 *  Board configuration definitions that only apply to the boot loader.
 *
 *  Most definitions have been moved to common/ruby_config.h
 *
 */

int board_config(int board_id, int parameter);
int board_parse_custom_cfg(void);
#ifndef TOPAZ_EP_MINI_UBOOT
void board_setup_bda(void *addr, int board_id);
#endif
int board_parse_tag(const char *bc_param, const char *valstr, int *val);

#endif // __BOARD_CFG_H__

