/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __SMC_GRAPH_H__
#define __SMC_GRAPH_H__

/* Forward declaration */
struct smc_main_cfg_data;

struct eth_node_s {
	char node_name[RTE_NODE_NAMESIZE];
	uint16_t portid;
};

typedef struct smc_graph_param {
	struct eth_node_s eth_rx_node[RTE_MAX_ETHPORTS];
	struct eth_node_s eth_tx_node[RTE_MAX_ETHPORTS];
	uint16_t nb_eth_rx_node;
	uint16_t nb_eth_tx_node;
	rte_thread_t graph_stats_thread;
} smc_graph_param_t;

int smc_graph_init(struct smc_main_cfg_data *smc_main_cfg);
int smc_graph_print_stats(struct smc_main_cfg_data *smc_main_cfg);
int smc_graph_rx_to_tx_node_link(uint16_t portid1, uint16_t portid2);
#endif /* __SMC_GRAPH_H__ */
