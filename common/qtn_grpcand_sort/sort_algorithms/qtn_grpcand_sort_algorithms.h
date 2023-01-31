/*
 * Copyright (c) 2017 Quantenna Communications, Inc.
 * All rights reserved.
 *
 */

#ifndef SORT_ALGORITHMS_H
#define SORT_ALGORITHMS_H
#if defined __GNUC__
#include <stdint.h>
#else
#include "types.h"
#endif
#include "qtn_grpcand_sort_utils.h"


typedef void (*qtn_grpcand_sort_function_p)(grp_map_type *, uint32_t len,
					    qtn_grpcand_sort_eq_function_p,
					    qtn_grpcand_sort_swap_function_p, void *,void *,
					    void *);

void qtn_grpcand_sort_bubble(grp_map_type map[], uint32_t len, qtn_grpcand_sort_eq_function_p eq,
			     qtn_grpcand_sort_swap_function_p swap, void *data1, void *data2,
			     void *data3);
void qtn_grpcand_sort_insertion(grp_map_type map[], uint32_t len, qtn_grpcand_sort_eq_function_p eq,
				qtn_grpcand_sort_swap_function_p swap, void *data1, void *data2,
				void *data3);
#endif /* SORT_ALGORITHMS_H */
