/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __FLOW_ACL_PRIV_H__
#define __FLOW_ACL_PRIV_H__

#include <stddef.h>

#include <rte_acl.h>
#include <rte_ether.h>

#include <dao_flow.h>

#include "dao_log.h"

#include "flow_parser_priv.h"

#define ACL_DEFAULT_MAX_CATEGORIES 1
#define ACL_MAX_RULES_PER_CTX      (4 * 1024)
#define ACL_MAX_PORT_TABLES        10
#define ACL_MAX_NUM_CTX            1

#define ACL_X4_RULE_DEF_SIZE 15

enum acl_rule_error {
	ACL_RULE_CTX_INVALID = -3001,
	ACL_RULE_OBJ_INVALID = -3002,
	ACL_RULE_TBL_INVALID = -3003,
	ACL_RULE_EMPTY	     = -3004,
};

static struct rte_acl_field_def ovs_kex_acl_defs[ACL_X4_RULE_DEF_SIZE] = {
	{
		// Padding. Ignore
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 1,
		.field_index = 0,
		.input_index = 0,
		.offset = 0,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 4,
		.field_index = 1,
		.input_index = 1,
		.offset = 4,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 4,
		.field_index = 2,
		.input_index = 2,
		.offset = 8,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 4,
		.field_index = 3,
		.input_index = 3,
		.offset = 12,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 4,
		.field_index = 4,
		.input_index = 4,
		.offset = 16,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 4,
		.field_index = 5,
		.input_index = 5,
		.offset = 20,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 4,
		.field_index = 6,
		.input_index = 6,
		.offset = 24,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 4,
		.field_index = 7,
		.input_index = 7,
		.offset = 28,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 4,
		.field_index = 8,
		.input_index = 8,
		.offset = 32,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 4,
		.field_index = 9,
		.input_index = 9,
		.offset = 36,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 4,
		.field_index = 10,
		.input_index = 10,
		.offset = 40,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 4,
		.field_index = 11,
		.input_index = 11,
		.offset = 44,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 4,
		.field_index = 12,
		.input_index = 12,
		.offset = 48,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 4,
		.field_index = 13,
		.input_index = 13,
		.offset = 52,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 4,
		.field_index = 14,
		.input_index = 14,
		.offset = 56,
	},
};

RTE_ACL_RULE_DEF(acl_rule, RTE_DIM(ovs_kex_acl_defs));
/* Forward declaration */
struct flow_global_cfg;
struct acl_rule;

struct acl_parse_info {
	const struct rte_flow_item *pattern;
};

struct acl_rule_data {
	TAILQ_ENTRY(acl_rule_data) next;
	bool is_hw_offloaded;
	uint16_t port_id;
	uint16_t tbl_id;
	struct acl_rule *rule;
	/* Contiguous match string */
	uint64_t parsed_flow_data[FLOW_PARSER_MAX_MCAM_WIDTH_DWORDS];
	uint64_t parsed_flow_data_mask[FLOW_PARSER_MAX_MCAM_WIDTH_DWORDS];
	uint32_t rule_idx;
	uint32_t rule_hits;
};

struct acl_actions {
	bool in_use;
	bool is_hw_offloaded;
	bool counter_enable;
#define ACL_ACTION_MARK  RTE_BIT64(0)
#define ACL_ACTION_COUNT RTE_BIT64(1)
	uint64_t act_map;
	uint32_t index;
	union {
		uint64_t rx_action;
		uint64_t tx_action;
	} u;
	uint64_t vtag_action;
	struct acl_rule_data *rule_data;
};

/* Single ACL table instance for a port */
struct acl_table {
	uint16_t port_id;
	uint16_t tbl_id;
	bool tbl_val;
	uint32_t num_rules;
	struct rte_acl_ctx *ctx;
	struct acl_actions *action;
	uint32_t size;
	struct parse_profile_ops *prfl_ops;
	/* Spinlock */
	rte_spinlock_t ctx_lock;

	TAILQ_HEAD(ctx_rule_list, acl_rule_data) flow_list;
};

/* Per port ACL tables */
struct acl_config_per_port {
	struct acl_table acl_tbl[ACL_MAX_PORT_TABLES];
	uint32_t num_rules_per_prt;
	uint32_t flow_aging;
};

/* Global ACL confiuration - across all ports */
struct acl_global_config {
	struct acl_config_per_port acl_cfg_prt[RTE_MAX_ETHPORTS];
};

int acl_global_config_init(struct flow_global_cfg *gbl_cfg);
int acl_global_config_fini(struct flow_global_cfg *gbl_cfg);

struct acl_rule_data *acl_create_rule(struct acl_table *acl_tbl, const struct rte_flow_attr *attr,
				      const struct rte_flow_item pattern[],
				      const struct rte_flow_action actions[],
				      struct rte_flow_error *error);

uint32_t acl_delete_rule(struct acl_table *acl_tbl, struct acl_rule_data *rule);
int acl_flow_lookup(struct acl_table *acl_tbl, struct rte_mbuf **objs, uint16_t nb_objs,
		    uint32_t *result);
int acl_rule_info(struct acl_rule_data *arule, FILE *file);
int acl_rule_flush(struct acl_config_per_port *acl_cfg_prt);
int acl_rule_dump(struct acl_table *acl_tbl, struct acl_rule_data *rule_data, FILE *file);
int acl_rule_query(struct acl_table *acl_tbl, struct acl_rule_data *rule_data,
		   struct dao_flow_query_count *query);
#endif /* __FLOW_ACL_PRIV_H__ */
