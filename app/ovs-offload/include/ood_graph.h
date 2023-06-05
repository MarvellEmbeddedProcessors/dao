/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __OOD_GRAPH_H__
#define __OOD_GRAPH_H__

#include <ood_node_ctrl.h>

/* Forward declaration */
struct ood_main_cfg_data;

typedef struct ood_graph_param {
	uint16_t nb_graphs;
	uint16_t nb_conf;
	ood_node_eth_ctrl_conf_t eth_ctrl_cfg[RTE_MAX_ETHPORTS];
	ood_node_flow_mapper_ctrl_conf_t fm_ctrl_cfg;
	ood_node_repr_ctrl_conf_t repr_ctrl_cfg;
	rte_thread_t graph_stats_thread;
} ood_graph_param_t;

int ood_graph_init(struct ood_main_cfg_data *ood_main_cfg);
void ood_eth_node_config(struct ood_main_cfg_data *ood_main_cfg, uint16_t port_id, uint8_t rxq,
			 uint8_t txq);
int ood_graph_print_stats(struct ood_main_cfg_data *ood_main_cfg);

#endif /* __OOD_GRAPH_H__ */
