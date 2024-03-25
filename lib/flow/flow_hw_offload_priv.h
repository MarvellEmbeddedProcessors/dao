/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __FLOW_HW_OFFLOAD_PRIV_H__
#define __FLOW_HW_OFFLOAD_PRIV_H__

#include <stddef.h>

#include <rte_flow.h>
#include <rte_malloc.h>
#include <rte_thread.h>

#include <dao_flow.h>

#include "dao_log.h"

/* Forward declaration */
struct flow_global_cfg;

struct hw_offload_flow {
	struct rte_flow_action *actions;
	struct rte_flow_item *pattern;
	struct rte_flow_attr *attr;
	struct rte_flow *flow;
	uint16_t id;
	bool offloaded;
};

/* Managing flow rules per port */
struct hw_offload_config_per_port {
	uint16_t port_id;
	uint16_t num_rules;
	/* Aging timeout */
	uint32_t aging_tmo;
};

/* Global hw_offload confiuration - across all ports */
struct hw_offload_global_config {
	/* Aging thread */
	rte_thread_t aging_thrd;
	bool aging_thrd_quit;
	struct hw_offload_config_per_port hw_off_cfg[RTE_MAX_ETHPORTS];
};

int hw_offload_global_config_init(struct flow_global_cfg *gbl_cfg);
int hw_offload_global_config_fini(struct flow_global_cfg *gbl_cfg);

struct hw_offload_flow *hw_offload_flow_reserve(struct hw_offload_config_per_port *hw_off_cfg,
						const struct rte_flow_attr *attr,
						const struct rte_flow_item pattern[],
						const struct rte_flow_action actions[],
						struct rte_flow_error *error);

int hw_offload_flow_create(struct hw_offload_config_per_port *hw_off_cfg,
			   struct hw_offload_flow *rule);
int hw_offload_flow_destroy(struct hw_offload_config_per_port *hw_off_cfg,
			    struct hw_offload_flow *rule);
#endif /* __FLOW_HW_OFFLOAD_PRIV_H__ */
