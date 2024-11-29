/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __FLOW_EM_PRIV_H__
#define __FLOW_EM_PRIV_H__

#include <stddef.h>

#include <rte_hash.h>
#include <rte_ether.h>

#include <dao_flow.h>

#include "dao_log.h"

#include "flow_parser_priv.h"

#define EM_DEFAULT_MAX_CATEGORIES 1
#define EM_MAX_RULES_PER_PORT     (5 * 1024 * 1024)

#define EM_X4_RULE_DEF_SIZE 15

enum em_rule_error {
	EM_RULE_HASH_INVALID = -3001,
	EM_RULE_OBJ_INVALID = -3002,
	EM_RULE_TBL_INVALID = -3003,
	EM_RULE_EMPTY	     = -3004,
};

struct flow_global_cfg;

struct em_parse_info {
	const struct rte_flow_item *pattern;
};

struct em_rule_data {
	TAILQ_ENTRY(em_rule_data) next;
	bool is_hw_offloaded;
	uint16_t port_id;
	/* Contiguous match string */
	uint64_t parsed_flow_data[FLOW_PARSER_MAX_MCAM_WIDTH_DWORDS];
	uint32_t rule_idx;
	uint32_t rule_hits;
};

struct em_actions {
	bool in_use;
	bool is_hw_offloaded;
	bool counter_enable;
#define EM_ACTION_MARK  DAO_BIT_ULL(0)
#define EM_ACTION_COUNT DAO_BIT_ULL(1)
	uint64_t act_map;
	uint32_t index;
	union {
		uint64_t rx_action;
		uint64_t tx_action;
	} u;
	uint64_t vtag_action;
	struct em_rule_data *rule_data;
};

/* Single ACL table instance for a port */
struct em_per_port {
	uint16_t port_id;
	bool em_val;
	uint32_t num_rules;
	struct rte_hash *hash;
	struct em_actions *action;
	uint32_t size;
	struct parse_profile_ops *prfl_ops;
	uint32_t num_rules_per_prt;
	/* Spinlock */
	rte_spinlock_t hash_lock;

	TAILQ_HEAD(hash_rule_list, em_rule_data) flow_list;
};

/* Global EM confiuration - across all ports */
struct em_global_config {
	struct em_per_port em_cfg_prt[RTE_MAX_ETHPORTS];
};

int em_global_config_init(uint16_t port_id, void **gbl_cfg);
int em_global_config_fini(uint16_t port_id, void *gbl_cfg);

void *em_create_rule(void *em_cfg, const struct rte_flow_attr *attr,
		     const struct rte_flow_item pattern[],
		     const struct rte_flow_action actions[],
		     uint16_t port_id, uint32_t *rule_idx,
		     struct rte_flow_error *error);

int em_delete_rule(void *em_cfg, uint16_t port_id, uint32_t tbl_id, void *rule);
int em_flow_lookup(void *em_cfg, uint16_t port_id, struct rte_mbuf **objs, uint16_t nb_objs,
		   uint32_t *result);
int em_rule_info(void *em_cfg, FILE *file, bool is_hw_offloaded);
int em_rule_flush(void *em_cfg, uint16_t port_id);
int em_rule_dump(void *em_cfg, uint16_t port_id, uint32_t tbl_id, void *rule_data,
		 FILE *file);
int em_rule_query(void *em_cfg, uint16_t port_id, uint32_t tbl_id, void *rule_data,
		  struct dao_flow_query_count *query);
int em_port_rule_count(void *em_gbl, uint16_t port_id);
#endif /* __FLOW_EM_PRIV_H__ */
