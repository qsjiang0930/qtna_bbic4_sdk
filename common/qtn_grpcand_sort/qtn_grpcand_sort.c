/*
 * Copyright (c) 2017 Quantenna Communications, Inc.
 * All rights reserved.
 *
 */
#include "qtn_grpcand_sort.h"

#define QTN_GRCAND_SORT_HASH_LOAD_FACTOR 2

int32_t qtn_grpcand_sort_get_score_by_aids(uint16_t *aids, uint32_t len,
					   qtn_grpcand_hash_table *hash);
int32_t qtn_grpcand_sort_eq_aids_valid_less(int a, int b, void *data1, void *data2, void *data3);



int32_t qtn_grpcand_sort_get_score_by_aids(uint16_t *aids, uint32_t len,
					   qtn_grpcand_hash_table *hash)
{
#define SCORE_INIT 1000000L;
	const int score_init = SCORE_INIT;
	uint32_t i = 0;
	int32_t score = 1;
	uint32_t val;
	enum qtn_grcand_hash_error ret;

	while (i != len && aids[i] != 0) {
		ret = qtn_grpcand_hashtable_get(hash, aids[i], &val);
		QTN_GRPCAND_ASSERT(ret == QTN_GRPCAND_HASH_OK,
				   "score_by_aids_and_len: Node not found\n");
		score += val;
		i++;
	}
	return score_init - score;
}

int32_t qtn_grpcand_sort_eq_aids_valid_less(int a, int b, void *data1, void *data2, void *data3)
{
	struct qtn_grpcand_sort_mu_grp_cand *mu_grp_cand_it =
			(struct qtn_grpcand_sort_mu_grp_cand *)data1;

	return mu_grp_cand_it->is_valid(a) < mu_grp_cand_it->is_valid(b);
}

int32_t qtn_grpcand_sort_eq_score_less(int a, int b, void *data1, void *data2, void *data3)
{
	struct qtn_grpcand_sort_mu_grp_cand *mu_grp_cand_it =
			(struct qtn_grpcand_sort_mu_grp_cand *)data1;
	qtn_grpcand_hash_table *hash = (qtn_grpcand_hash_table *) data2;

	int32_t score1 = 0;
	int32_t score2 = 0;

	score1 = qtn_grpcand_sort_get_score_by_aids(mu_grp_cand_it->get_aids(a),
						    mu_grp_cand_it->get_max_num_aids(), hash);
	score2 = qtn_grpcand_sort_get_score_by_aids(mu_grp_cand_it->get_aids(b),
						    mu_grp_cand_it->get_max_num_aids(), hash);
	return score1 < score2;
}

static void qtn_grpcand_sort_incr_score_with_penalty(uint16_t *aids, uint32_t len,
					      qtn_grpcand_hash_table *hash, int32_t *penalty)
{
	uint32_t i = 0;

	while (i != len && aids[i] != 0) {
		QTN_GRPCAND_ASSERT(qtn_grpcand_hashtable_incr_by_n(hash, aids[i], (*penalty))
				   == QTN_GRPCAND_HASH_OK,
				   "incr_score_w_penalty: Node not found\n");
		i++;
	}
	(*penalty) += 1;
}

static void qtn_grpcand_sort_create_freq_hash(grp_map_type mu_grp_map[],
					      struct qtn_grpcand_sort_mu_grp_cand *mu_grp_cand_it,
					      uint32_t len,
					      qtn_grpcand_hash_table *hash)
{
	uint32_t i,j;
	uint16_t *aids;

	for (i = 0; i != len; ++i) {
		if (!mu_grp_cand_it->is_valid(mu_grp_map[i]))
			continue;

		aids = mu_grp_cand_it->get_aids(mu_grp_map[i]);

		for (j = 0; j != mu_grp_cand_it->get_max_num_aids(); ++j) {
			if (aids[j] == 0)
				break;
			QTN_GRPCAND_ASSERT( qtn_grpcand_hashtable_incr(hash, aids[j])
					    == QTN_GRPCAND_HASH_OK, "create_freq_hash: hash err\n");
		}
	}
}

static uint32_t qtn_grpcand_sort_by_valid(grp_map_type mu_grp_map[],
					  struct qtn_grpcand_sort_mu_grp_cand *mu_grp_cand_it,
					  uint32_t valid_len, qtn_grpcand_sort_function_p sort)
{
	uint32_t i;
	sort(mu_grp_map, valid_len, qtn_grpcand_sort_eq_aids_valid_less,
	     qtn_grpcand_sort_swap_xor, (void *)mu_grp_cand_it, NULL, NULL);

	for (i = valid_len - 1; i != 0; --i) {
		if (mu_grp_cand_it->is_valid(mu_grp_map[i]))
			return (i + 1);
	}

	return 0;
}

static int qtn_grpcand_sort_main(grp_map_type mu_grp_map[],
				 struct qtn_grpcand_sort_mu_grp_cand *mu_grp_cand_it,
				 uint32_t valid_len, qtn_grpcand_sort_function_p sort,
				 uint32_t range_start, uint32_t range_end,
				 qtn_grpcand_hash_table *hash, int32_t penalty,
				 qtn_grpcand_sort_eq_function_p score_func)
{
	uint32_t start = range_start;
	uint32_t length = range_end - range_start;
	int32_t score_penalty = penalty;

	QTN_GRPCAND_ASSERT(range_end >= range_start, "sort_main: range error\n");
	QTN_GRPCAND_ASSERT(range_end <= valid_len, "sort_main: range error\n");

	while(start != range_end) {
		sort(&mu_grp_map[start], length, score_func, qtn_grpcand_sort_swap_xor,
		     (void *)mu_grp_cand_it, (void *)hash, NULL);

		qtn_grpcand_sort_incr_score_with_penalty(
					mu_grp_cand_it->get_aids(mu_grp_map[start]),
					mu_grp_cand_it->get_max_num_aids(), hash, &score_penalty);

		start++;
		length = range_end - start;
	}
	return score_penalty;
}

void qtn_grpcand_sort(grp_map_type mu_grp_map[],
		      struct qtn_grpcand_sort_mu_grp_cand *mu_grp_cand_it,
		      uint32_t valid_len, qtn_grpcand_sort_function_p sort,
		      qtn_grpcand_sort_eq_function_p score_func)
{
	static uint32_t skip_allow = 0, prev_len = 0;
	qtn_grpcand_hash_table table;
	qtn_grpcand_hash_node nodes[MU_GRP_CAND_NUM_MAX * QTN_GRCAND_SORT_HASH_LOAD_FACTOR];

	qtn_grpcand_hashtable_init(&table, nodes, MU_GRP_CAND_NUM_MAX *
				   QTN_GRCAND_SORT_HASH_LOAD_FACTOR);

	valid_len = qtn_grpcand_sort_by_valid(mu_grp_map, mu_grp_cand_it, valid_len, sort);

	if (mu_grp_cand_it->get_war()) {
		/*
		 * WAR: Sometimes when number of groupcandidates significantly more when number of
		 * groups, any accidental groupcandidate invalidation cause significantly resorting.
		 * It can have long term issue due to when groupcandidate leave the group
		 * he will be invalidated.
		 * So one invalidation can cause another invalidation and so on, so on.
		 * To prevent it let's skip sorting once
		 * when number of invalid groupcandidates were changed.
		 */
		if (skip_allow && valid_len != prev_len) {
			prev_len = valid_len;
			skip_allow = 0;
			return;
		} else {
			prev_len = valid_len;
			skip_allow = 1;
		}
	}

	qtn_grpcand_sort_create_freq_hash(mu_grp_map, mu_grp_cand_it, valid_len, &table);

#define PENALTY 15
	int penalty = PENALTY;

	qtn_grpcand_sort_main(mu_grp_map, mu_grp_cand_it, valid_len, sort, 0, valid_len, &table,
			       penalty, score_func);
}
