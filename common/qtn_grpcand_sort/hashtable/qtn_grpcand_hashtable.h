/*
 * Copyright (c) 2017 Quantenna Communications, Inc.
 * All rights reserved.
 *
 */

#ifndef HASHTABLE_H
#define HASHTABLE_H

#if defined __GNUC__
#include <stdio.h>
#include <stdint.h>
#define hash_dbg_printf(fmt ...) printf(fmt)
#else
#include "types.h"
#include "../rdspfw/os/dsp_os.h"
#define hash_dbg_printf(fmt ...) dsp_printf(fmt)
#endif

typedef struct qtn_grpcand_hash_node_s {
	uint32_t node;
	uint32_t value;
} qtn_grpcand_hash_node;

typedef struct qtn_grpcand_hash_table_s {
	qtn_grpcand_hash_node *nodes;
	uint32_t len;
} qtn_grpcand_hash_table;

enum qtn_grcand_hash_error {
	QTN_GRPCAND_HASH_FAIL = 0,
	QTN_GRPCAND_HASH_OK = 1
};

void qtn_grpcand_hashtable_init(qtn_grpcand_hash_table *hash, qtn_grpcand_hash_node *nodes,
				uint32_t nodes_len);
void qtn_grpcand_hashtable_clear(qtn_grpcand_hash_table *hash);
enum qtn_grcand_hash_error qtn_grpcand_hashtable_get(qtn_grpcand_hash_table *hash, uint32_t node,
						     uint32_t *value);
enum qtn_grcand_hash_error qtn_grpcand_hashtable_set(qtn_grpcand_hash_table *hash, uint32_t node,
						     uint32_t value);
enum qtn_grcand_hash_error qtn_grpcand_hashtable_incr(qtn_grpcand_hash_table *hash, uint32_t node);
enum qtn_grcand_hash_error qtn_grpcand_hashtable_incr_by_n(qtn_grpcand_hash_table *hash,
							   uint32_t node, int32_t n);
enum qtn_grcand_hash_error qtn_grpcand_hashtable_decr(qtn_grpcand_hash_table *hash, uint32_t node);

void qtn_grpcand_hashtable_print_nodes(qtn_grpcand_hash_table *hash);
void qtn_grpcand_hashtable_graph_nodes(qtn_grpcand_hash_table *hash);

#endif /* HASHTABLE_H */
