/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __FLOW_CTRL_H__
#define __FLOW_CTRL_H__

#include <rte_flow.h>

#include <ood_msg_ctrl.h>

struct flows {
	STAILQ_ENTRY(flows) next;
	struct rte_flow *host_flow;
	struct rte_flow *mac_flow;
	uint16_t act_cfg_idx;
};

typedef struct representor_mapping {
	uint16_t host_port;
	uint16_t mac_port;
	bool mark_offload_enable;

	STAILQ_HEAD(flow_head, flows) flow_list;
} representor_mapping_t;

struct rte_flow *ood_flow_create(uint16_t portid, struct rte_flow_attr *attr,
				 struct rte_flow_item *pattern, struct rte_flow_action *action,
				 struct rte_flow_error *err);
int ood_flow_destroy(uint16_t portid, struct rte_flow *flow, struct rte_flow_error *err);

int ood_flow_validate(uint16_t repr_qid, struct rte_flow_attr *attr, struct rte_flow_item *pattern,
		      struct rte_flow_action *action, struct rte_flow_error *err);
int ood_flow_flush(uint16_t portid, struct rte_flow_error *err);
int ood_flow_dump(uint16_t portid, struct rte_flow *flow, uint8_t is_stdout,
		  struct rte_flow_error *err);
int ood_flow_query(uint16_t repr_qid, struct rte_flow *flow, uint8_t reset,
		   struct rte_flow_action *action, struct rte_flow_error *err,
		   ood_msg_ack_data_t *adata);
#endif /* __FLOW_CTRL_H__ */
