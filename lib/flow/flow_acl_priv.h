/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __FLOW_ACL_PRIV_H__
#define __FLOW_ACL_PRIV_H__

#define ACL_DEFAULT_MAX_CATEGORIES 1
#define ACL_MAX_RULES_PER_CTX      (4 * 1024)
#define ACL_MAX_PORT_TABLES        10
#define ACL_MAX_NUM_CTX            1

#include <stddef.h>

#include <rte_acl.h>
#include <rte_ether.h>

#include <dao_flow.h>

#include "dao_log.h"

/* Forward declaration */
struct flow_global_cfg;
struct acl_rule;

struct acl_parse_info {
	const struct rte_flow_item *pattern;
};

struct acl_rule_data {
	TAILQ_ENTRY(acl_rule_data) next;
	struct acl_rule *rule;
	uint32_t rule_idx;
};

struct acl_actions {
	bool in_use;
	bool is_hw_offloaded;
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
	/* Spinlock */
	rte_spinlock_t ctx_lock;

	TAILQ_HEAD(ctx_rule_list, acl_rule_data) flow_list;
};

/* Per port ACL tables */
struct acl_config_per_port {
	struct acl_table acl_tbl[ACL_MAX_PORT_TABLES];
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
int acl_flow_lookup(struct acl_table *acl_tbl, struct rte_mbuf **objs, uint16_t nb_objs);

#endif /* __FLOW_ACL_PRIV_H__ */
