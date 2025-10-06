/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __RDMA_GRAPH_H__
#define __RDMA_GRAPH_H__

#include "rdma_node_ctrl.h"

#include <rte_graph.h>
#include <rte_graph_worker_common.h>

extern rte_node_t rdma_pts_deq_nodes[];
extern rte_node_t rdma_pts_enq_nodes[];

/* Forward declaration */
struct rdma_main_cfg_data;

typedef struct rdma_graph_param {
	uint16_t nb_graphs;
	uint16_t nb_conf;
	rdma_node_eth_ctrl_conf_t eth_ctrl_cfg[RTE_MAX_ETHPORTS];
	rdma_node_rdma_ctrl_conf_t fm_ctrl_cfg;
	rte_thread_t graph_stats_thread;
} rdma_graph_param_t;

int rdma_graph_init(struct rdma_main_cfg_data *rdma_main_cfg);
void rdma_eth_node_config(struct rdma_main_cfg_data *rdma_main_cfg, uint16_t port_id, uint8_t rxq,
			  uint8_t txq);
int rdma_graph_print_stats(struct rdma_main_cfg_data *rdma_main_cfg);

#endif /* __RDMA_GRAPH_H__ */
