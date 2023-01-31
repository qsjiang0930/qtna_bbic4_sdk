/*
 * Copyright (c) 2017 Quantenna Communications, Inc.
 * All rights reserved.
 *
 */
#include <assert.h>

#include "qtn_grpcand_sort_algorithms.h"

void qtn_grpcand_sort_bubble(grp_map_type map[], uint32_t len, qtn_grpcand_sort_eq_function_p eq,
			     qtn_grpcand_sort_swap_function_p swap, void *data1, void *data2, void *data3)
{
	uint32_t i, j;

	for (i = 0; i != len - 1; ++i) {
		for (j = i + 1; j != len; ++j) {
			if ( eq(map[i], map[j], data1, data2, data3) )
				swap(&map[i], &map[j]);
		}
	}
}

void qtn_grpcand_sort_insertion(grp_map_type map[], uint32_t len, qtn_grpcand_sort_eq_function_p eq,
				qtn_grpcand_sort_swap_function_p swap, void *data1, void *data2, void *data3)
{
	uint32_t i, j;
	grp_map_type tmp;

	for (i = 1u; i < len; ++i) {
		tmp = map[i];
		j = i;

		while(j > 0 && eq(map[j - 1], tmp, data1, data2, data3)) {
			swap(&map[j], &map[j - 1]);
			j--;
		}
		map[j] = tmp;
	}
}
