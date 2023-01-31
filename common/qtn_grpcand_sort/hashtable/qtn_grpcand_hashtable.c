/*
 * Copyright (c) 2017 Quantenna Communications, Inc.
 * All rights reserved.
 *
 */
#include <string.h>
#include <stdlib.h>
#include "qtn_grpcand_hashtable.h"

static void qtn_grpcand_hashtable_debug_out(qtn_grpcand_hash_table *hash, uint32_t node)
{
	hash_dbg_printf("\nCan't find node: %u\n", node);
	qtn_grpcand_hashtable_print_nodes(hash);
}

void qtn_grpcand_hashtable_init(qtn_grpcand_hash_table *hash, qtn_grpcand_hash_node *nodes,
				uint32_t nodes_len)
{
	hash->nodes = nodes;
	hash->len = nodes_len;

	qtn_grpcand_hashtable_clear(hash);
}

void qtn_grpcand_hashtable_clear(qtn_grpcand_hash_table *hash)
{
	memset(hash->nodes, 0, sizeof(qtn_grpcand_hash_node) * hash->len);
}

enum qtn_grcand_hash_error qtn_grpcand_hashtable_get(qtn_grpcand_hash_table *hash, uint32_t node, uint32_t *value)
{
	uint32_t i = (node * node) % hash->len;

	while(i < hash->len) {
		if (hash->nodes[i].node == 0)
			break;
		else if (hash->nodes[i].node == node) {
			*value = hash->nodes[i].value;
			return QTN_GRPCAND_HASH_OK;
		} else
			i++;
	}
	qtn_grpcand_hashtable_debug_out(hash, node);
	return QTN_GRPCAND_HASH_FAIL;
}

enum qtn_grcand_hash_error qtn_grpcand_hashtable_set(qtn_grpcand_hash_table *hash, uint32_t node, uint32_t value)
{
	uint32_t i = (node * node) % hash->len;

	while(i < hash->len) {
		if (hash->nodes[i].node == 0 || hash->nodes[i].node == node) {
			hash->nodes[i].node = node;
			hash->nodes[i].value = value;
			return QTN_GRPCAND_HASH_OK;
		}
		i++;
	}

	qtn_grpcand_hashtable_debug_out(hash, node);
	return QTN_GRPCAND_HASH_FAIL;
}

enum qtn_grcand_hash_error qtn_grpcand_hashtable_incr(qtn_grpcand_hash_table *hash, uint32_t node)
{
	uint32_t i = (node * node) % hash->len;

	while(i < hash->len) {
		if (hash->nodes[i].node == 0 || hash->nodes[i].node == node) {
			hash->nodes[i].node = node;
			hash->nodes[i].value++;
			return QTN_GRPCAND_HASH_OK;
		}
		i++;
	}

	qtn_grpcand_hashtable_debug_out(hash, node);
	return QTN_GRPCAND_HASH_FAIL;
}

enum qtn_grcand_hash_error qtn_grpcand_hashtable_incr_by_n(qtn_grpcand_hash_table *hash,
							   uint32_t node, int32_t n)
{
	uint32_t i = (node * node) % hash->len;

	while(i < hash->len) {
		if (hash->nodes[i].node == 0 || hash->nodes[i].node == node) {
			hash->nodes[i].node = node;
			if (n > 0)
				hash->nodes[i].value += (uint32_t)abs(n);
			else
				hash->nodes[i].value -= (uint32_t)abs(n);
			return QTN_GRPCAND_HASH_OK;
		}
		i++;
	}

	qtn_grpcand_hashtable_debug_out(hash, node);
	return QTN_GRPCAND_HASH_FAIL;
}

enum qtn_grcand_hash_error qtn_grpcand_hashtable_decr(qtn_grpcand_hash_table *hash, uint32_t node)
{
	uint32_t i = (node * node) % hash->len;

	while (i < hash->len) {
		if (hash->nodes[i].node == 0 || hash->nodes[i].node == node) {
			hash->nodes[i].node = node;
			hash->nodes[i].value--;
			return QTN_GRPCAND_HASH_OK;
		}
		i++;
	}

	qtn_grpcand_hashtable_debug_out(hash, node);
	return QTN_GRPCAND_HASH_FAIL;
}

void qtn_grpcand_hashtable_print_nodes(qtn_grpcand_hash_table *hash)
{
	uint32_t i;
	hash_dbg_printf("N:     ");
	for (i = 0; i != hash->len; ++i) {
		hash_dbg_printf("%4d ", i);
	}
	hash_dbg_printf("\n");

	hash_dbg_printf("node:  ");
	for (i = 0; i != hash->len; ++i) {
		hash_dbg_printf("%4d ", hash->nodes[i].node);
	}
	hash_dbg_printf("\n");

	hash_dbg_printf("value: ");
	for (i = 0; i != hash->len; ++i) {
		hash_dbg_printf("%4d ", hash->nodes[i].value);
	}
	hash_dbg_printf("\n");
}

void qtn_grpcand_hashtable_graph_nodes(qtn_grpcand_hash_table *hash)
{
	for (uint32_t i = 0; i != hash->len; ++i) {
		if (hash->nodes[i].node != 0) {
			hash_dbg_printf("%4d: ", hash->nodes[i].node);
			for (uint32_t j = 0; j != hash->nodes[i].value; ++j)
				hash_dbg_printf("* ");
			hash_dbg_printf("\n");
		}
	}
	hash_dbg_printf("\n");
}
