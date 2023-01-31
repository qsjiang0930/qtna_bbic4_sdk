/*
 * Copyright (c) 2017 Quantenna Communications, Inc.
 * All rights reserved.
 *
 */
#include"qtn_grpcand_sort_utils.h"

void qtn_grpcand_sort_swap_xor(grp_map_type *a, grp_map_type *b)
{
	if (a == b)
		return;
	*a ^= *b;
	*b ^= *a;
	*a ^= *b;
}

void qtn_grpcand_sort_swap_simple(grp_map_type *a, grp_map_type *b)
{
	grp_map_type buff;
	buff = *b;
	*b = *a;
	*a = buff;
}

int32_t qtn_grpcand_sort_simple_greater(int a, int b, void *data1, void *data2, void *data3)
{
	if (a > b)
		return 1;
	return 0;
}

int32_t qtn_grpcand_sort_simple_less(int a, int b, void *data1, void *data2, void *data3)
{
	if (a < b)
		return 1;
	return 0;
}

int32_t qtn_grpcand_sort_simple_greater_by_arr(int a, int b, void *data1, void *data2, void *data3)
{
	grp_map_type *arr = (grp_map_type *) data1;
	if (arr[a] > arr[b])
		return 1;
	return 0;
}

int32_t qtn_grpcand_sort_simple_less_by_arr(int a, int b, void *data1, void *data2, void *data3)
{
	grp_map_type *arr = (grp_map_type *) data1;
	if (arr[a] < arr[b])
		return 1;
	return 0;
}
