/*
 * Copyright (c) 2017 Quantenna Communications, Inc.
 * All rights reserved.
 *
 */

#ifndef QTN_GROUPCANDSORT_H
#define QTN_GROUPCANDSORT_H
#include "sort_algorithms/qtn_grpcand_sort_algorithms.h"
#include "hashtable/qtn_grpcand_hashtable.h"

#if defined __GNUC__
#include "groupcandsort_test_data.h"
#include <assert.h>
#define sort_dbg_printf(fmt ...) printf(fmt)
#define QTN_GRPCAND_ASSERT(x, a...) assert((x))
#else
#include "../rdspfw/include/dsp_compat.h"
#include "../rdspfw/os/dsp_grcand.h"
#include "types.h"
#define sort_dbg_printf(fmt ...) dsp_printf(fmt)
#define QTN_GRPCAND_ASSERT(x, a...) DSP_ASSERT((x), (a));
#endif

typedef uint8_t grp_map_type ;
typedef uint32_t (*qtn_grpcand_sort_get_score_by_len_p)(uint32_t len);

struct qtn_grpcand_sort_mu_grp_cand {
	uint16_t* (*get_aids)(int32_t n);
	uint32_t  (*get_max_num_aids)(void);
	int32_t   (*is_valid)(int32_t n);
	int32_t   (*get_rank)(int32_t n);
	qtn_grpcand_sort_get_score_by_len_p get_score_by_len;
	int       (*get_war)(void);
};

void qtn_grpcand_sort(grp_map_type mu_grp_map[],
		      struct qtn_grpcand_sort_mu_grp_cand *mu_grp_cand_it,
		      uint32_t valid_len, qtn_grpcand_sort_function_p sort,
		      qtn_grpcand_sort_eq_function_p score_func);

int32_t qtn_grpcand_sort_eq_score_less(int a, int b, void *data1, void *data2, void *data3);

#endif /* QTN_GROUPCANDSORT_H */

