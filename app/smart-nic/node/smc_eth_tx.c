/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#include <dao_log.h>

#include "smc_eth_tx_priv.h"

static struct smc_eth_tx_node_main smc_eth_tx_main;

static uint16_t
smc_eth_tx_node_process(struct rte_graph *graph, struct rte_node *node, void **objs,
			uint16_t nb_objs)
{
	smc_eth_tx_node_ctx_t *ctx = (smc_eth_tx_node_ctx_t *)node->ctx;
	uint16_t port, queue;
	uint16_t count;

	/* Get Tx port id */
	port = ctx->port;
	/* TODO: use ctx->queue*/
	queue = 0;

	dao_dbg("		lcore %d name %s port %d queue %d\n\n", rte_lcore_id(), node->name,
		port, queue);
	count = rte_eth_tx_burst(port, queue, (struct rte_mbuf **)objs, nb_objs);

	/* Redirect unsent pkts to drop node */
	if (count != nb_objs)
		rte_node_enqueue(graph, node, SMC_ETH_TX_NEXT_PKT_DROP, &objs[count],
				 nb_objs - count);

	return count;
}

static int
smc_eth_tx_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	smc_eth_tx_node_ctx_t *ctx = (smc_eth_tx_node_ctx_t *)node->ctx;
	uint64_t port_id = RTE_MAX_ETHPORTS;
	int i;

	RTE_SET_USED(graph);
	/* Find our port id */
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (smc_eth_tx_main.nodes[i] == node->id) {
			port_id = i;
			break;
		}
	}
	RTE_VERIFY(port_id < RTE_MAX_ETHPORTS);

	/* Update port and queue */
	ctx->port = port_id;
	ctx->queue = graph->id;

	return 0;
}

struct smc_eth_tx_node_main *
smc_eth_tx_node_data_get(void)
{
	return &smc_eth_tx_main;
}

static struct rte_node_register smc_eth_tx_node_base = {
	.process = smc_eth_tx_node_process,
	.name = "smc_eth_tx",
	.init = smc_eth_tx_node_init,

	.nb_edges = SMC_ETH_TX_NEXT_MAX,
	.next_nodes = {
		[SMC_ETH_TX_NEXT_PKT_DROP] = "pkt_drop",
	},
};

struct rte_node_register *
smc_eth_tx_node_get(void)
{
	return &smc_eth_tx_node_base;
}

RTE_NODE_REGISTER(smc_eth_tx_node_base);
