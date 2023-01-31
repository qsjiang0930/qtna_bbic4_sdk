/**
  Copyright (c) 2020 Quantenna Communications Inc
  All Rights Reserved

  This software may be distributed under the terms of the BSD license.
  See README for more details.
 **/

#ifndef _MAP_ERW_TEST_H
#define _MAP_ERW_TEST_H

#define SIOCDEV_SUBIO_SET_BSA_STATUS		(SIOCDEV_SUBIO_BASE + 50)

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define REQ_MACSTR_INPUT_FMT	"%02x:%02x:%02x:%02x:%02x:%02x"
#define ETH_ALEN 6

#define BE_READ_2(p)					\
	((u_int16_t)					\
	((((const u_int8_t *)(p))[1]) |			\
	(((const u_int8_t *)(p))[0] <<  8)))
#define BE_READ_4(p)					\
	((u_int32_t)					\
	((((const u_int8_t *)(p))[3]) |			\
	(((const u_int8_t *)(p))[2] <<  8) |		\
	(((const u_int8_t *)(p))[1] << 16) |		\
	(((const u_int8_t *)(p))[0] << 24)))


#endif

