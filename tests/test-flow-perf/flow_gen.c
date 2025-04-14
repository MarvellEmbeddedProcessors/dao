/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 *
 * The file contains the implementations of the method to
 * fill items, actions & attributes in their corresponding
 * arrays, and then generate rte_flow rule.
 *
 * After the generation. The rule goes to validation then
 * creation state and then return the results.
 */

#include <stdint.h>

#include "actions_gen.h"
#include "config.h"
#include "flow_gen.h"
#include "items_gen.h"

static void
fill_attributes(struct rte_flow_attr *attr, uint64_t *flow_attrs, uint16_t group,
		uint8_t max_priority)
{
	uint8_t i;

	for (i = 0; i < MAX_ATTRS_NUM; i++) {
		if (flow_attrs[i] == 0)
			break;
		if (flow_attrs[i] & INGRESS)
			attr->ingress = 1;
		else if (flow_attrs[i] & EGRESS)
			attr->egress = 1;
		else if (flow_attrs[i] & TRANSFER)
			attr->transfer = 1;
	}
	attr->group = group;
	attr->priority = rte_rand_max(max_priority);
}

struct dao_flow *
generate_flow(struct flow_gen_params *params, struct test_ipaddr_port *test_vals,
	      struct rte_flow_error *error)
{
	struct rte_flow_attr attr;
	struct rte_flow_item items[MAX_ITEMS_NUM];
	struct rte_flow_action actions[MAX_ACTIONS_NUM];
	struct dao_flow *flow = NULL;

	memset(items, 0, sizeof(items));
	memset(actions, 0, sizeof(actions));
	memset(&attr, 0, sizeof(struct rte_flow_attr));

	fill_attributes(&attr, params->flow_attrs, params->group, params->max_priority);

	fill_actions(actions, params->flow_actions, params->outer_ip_src, params->next_table,
		     params->hairpinq, params->encap_data, params->decap_data, params->core_idx,
		     params->unique_data, params->rx_queues_count, params->dst_port);

	fill_items(items, params->flow_items, params->core_idx, test_vals);

	flow = (struct dao_flow *)dao_flow_create(params->port_id, &attr, items, actions, error);
	return flow;
}
