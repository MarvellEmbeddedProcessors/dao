/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#include <dao_log.h>

#include "ood_eth_tx_priv.h"

static struct ood_eth_tx_node_main ood_eth_tx_main;

static uint16_t
ood_eth_tx_node_process(struct rte_graph *graph, struct rte_node *node, void **objs,
			uint16_t nb_objs)
{
	ood_eth_tx_node_ctx_t *ctx = (ood_eth_tx_node_ctx_t *)node->ctx;
	uint16_t port, queue;
	uint16_t count;

	/* Get Tx port id */
	port = ctx->port;
	queue = ctx->queue;

	dao_dbg("		lcore %d name %s port %d queue %d\n\n", rte_lcore_id(), node->name,
		port, queue);
	count = rte_eth_tx_burst(port, queue, (struct rte_mbuf **)objs, nb_objs);

	/* Redirect unsent pkts to drop node */
	if (count != nb_objs)
		rte_node_enqueue(graph, node, EP_ETH_TX_NEXT_PKT_DROP, &objs[count],
				 nb_objs - count);

	return count;
}

static int
ood_eth_tx_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	ood_eth_tx_node_ctx_t *ctx = (ood_eth_tx_node_ctx_t *)node->ctx;
	uint64_t port_id = RTE_MAX_ETHPORTS;
	int i;

	RTE_SET_USED(graph);
	/* Find our port id */
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (ood_eth_tx_main.nodes[i] == node->id) {
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

struct ood_eth_tx_node_main *
ood_eth_tx_node_data_get(void)
{
	return &ood_eth_tx_main;
}

static struct rte_node_register ood_eth_tx_node_base = {
	.process = ood_eth_tx_node_process,
	.name = "ood_eth_tx",
	.init = ood_eth_tx_node_init,

	.nb_edges = EP_ETH_TX_NEXT_MAX,
	.next_nodes = {
			[EP_ETH_TX_NEXT_PKT_DROP] = "pkt_drop",
	},
};

struct rte_node_register *
ood_eth_tx_node_get(void)
{
	return &ood_eth_tx_node_base;
}

RTE_NODE_REGISTER(ood_eth_tx_node_base);
