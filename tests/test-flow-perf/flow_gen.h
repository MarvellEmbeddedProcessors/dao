/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 *
 * This file contains the items, actions and attributes
 * definition. And the methods to prepare and fill items,
 * actions and attributes to generate rte_flow rule.
 */

#ifndef FLOW_PERF_FLOW_GEN
#define FLOW_PERF_FLOW_GEN

#include <rte_flow.h>
#include <stdint.h>

#include "config.h"

#include <dao_flow.h>

/* Actions */
#define HAIRPIN_QUEUE_ACTION FLOW_ACTION_MASK(0)
#define HAIRPIN_RSS_ACTION   FLOW_ACTION_MASK(1)

/* Attributes */
#define INGRESS  FLOW_ATTR_MASK(0)
#define EGRESS   FLOW_ATTR_MASK(1)
#define TRANSFER FLOW_ATTR_MASK(2)

struct test_ipaddr_port {
	struct rte_flow_item_ipv4 ipv4;
	struct rte_flow_item_ipv6 ipv6;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t core_idx;
};

struct flow_gen_params {
	uint16_t port_id;
	uint16_t group;
	uint64_t *flow_attrs;
	uint64_t *flow_items;
	uint64_t *flow_actions;
	uint16_t next_table;
	uint32_t outer_ip_src;
	uint16_t hairpinq;
	uint64_t encap_data;
	uint64_t decap_data;
	uint16_t dst_port;
	uint8_t core_idx;
	uint8_t rx_queues_count;
	bool unique_data;
	uint8_t max_priority;
};

struct dao_flow *generate_flow(struct flow_gen_params *params, struct test_ipaddr_port *test_vals,
			       struct rte_flow_error *error);

#endif /* FLOW_PERF_FLOW_GEN */
