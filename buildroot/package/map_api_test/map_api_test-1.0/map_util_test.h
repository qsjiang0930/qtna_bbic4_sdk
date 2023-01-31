/**
  Copyright (c) 2020 Quantenna Communications Inc
  All Rights Reserved

  This software may be distributed under the terms of the BSD license.
  See README for more details.
 **/

#ifndef _MAP_UTIL_TEST_H
#define _MAP_UTIL_TEST_H

#include <stdio.h>
#include <stdlib.h>

extern int isDebug;
#define DebugPrintf(format, arg...)               \
	do {                                      \
		if (isDebug)                      \
		printf(format , ## arg);          \
	} while (0)

int map_erw_test(int argc, char *argv[]);
#endif

