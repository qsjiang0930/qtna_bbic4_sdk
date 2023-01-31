/*
 * Copyright (c) 2017 Quantenna Communications, Inc.
 * All rights reserved.
 *
 */

#ifndef SORT_UTILS_H
#define SORT_UTILS_H

#if defined __GNUC__
#include <stdint.h>
#else
#include "types.h"
#endif
typedef uint8_t grp_map_type;

typedef int32_t (*qtn_grpcand_sort_eq_function_p)(int, int, void *, void *, void *);
typedef void (*qtn_grpcand_sort_swap_function_p)(grp_map_type *, grp_map_type *);

void qtn_grpcand_sort_swap_xor(grp_map_type *a, grp_map_type *b);
void qtn_grpcand_sort_swap_simple(grp_map_type *a, grp_map_type *b);
int32_t qtn_grpcand_sort_simple_greater(int a, int b, void *data1, void *data2, void *data3);
int32_t qtn_grpcand_sort_simple_less(int a, int b, void *data1, void *data2, void *data3);
int32_t qtn_grpcand_sort_simple_greater_by_arr(int a, int b, void *data1, void *data2, void *data3);
int32_t qtn_grpcand_sort_simple_less_by_arr(int a, int b, void *data1, void *data2, void *data3);

#endif /* SORT_UTILS_H */

