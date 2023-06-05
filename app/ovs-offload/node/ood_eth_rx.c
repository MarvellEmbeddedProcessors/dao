/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#include <dao_log.h>

#include "ood_eth_rx_priv.h"

static struct ood_eth_rx_node_main ood_eth_rx_main;

static __rte_always_inline uint16_t
ood_eth_rx_node_process_inline(struct rte_graph *graph, struct rte_node *node,
			       ood_eth_rx_node_ctx_t *ctx)
{
	uint16_t count, next_index;
	uint16_t port, queue;

	port = ctx->port_id;
	queue = ctx->queue_id;
	next_index = ctx->cls_next;

	/* Get pkts from port */
	count = rte_eth_rx_burst(port, queue, (struct rte_mbuf **)node->objs, RTE_GRAPH_BURST_SIZE);

	if (!count)
		return 0;
	dao_dbg("lcore %d name %s port %d queue %d", rte_lcore_id(), node->name, port, queue);
	node->idx = count;
	/* Enqueue to next node */
	rte_node_next_stream_move(graph, node, next_index);

	return count;
}

static __rte_always_inline uint16_t
ood_eth_rx_node_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t cnt)
{
	ood_eth_rx_node_ctx_t *ctx = (ood_eth_rx_node_ctx_t *)node->ctx;
	uint16_t n_pkts = 0;

	RTE_SET_USED(objs);
	RTE_SET_USED(cnt);

	n_pkts = ood_eth_rx_node_process_inline(graph, node, ctx);
	return n_pkts;
}

static int
ood_eth_rx_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	ood_eth_rx_node_ctx_t *ctx = (ood_eth_rx_node_ctx_t *)node->ctx;
	ood_eth_rx_node_elem_t *elem = ood_eth_rx_main.head;

	RTE_SET_USED(graph);

	while (elem) {
		if (elem->nid == node->id) {
			/* Update node specific context */
			memcpy(ctx, &elem->ctx, sizeof(ood_eth_rx_node_ctx_t));
			break;
		}
		elem = elem->next;
	}

	RTE_VERIFY(elem != NULL);

	/* Check and setup ptype */
	return 0;
}

struct ood_eth_rx_node_main *
ood_eth_rx_get_node_data_get(void)
{
	return &ood_eth_rx_main;
}

static struct rte_node_register ood_eth_rx_node_base = {
	.process = ood_eth_rx_node_process,
	.flags = RTE_NODE_SOURCE_F,
	.name = "ood_eth_rx",

	.init = ood_eth_rx_node_init,

	.nb_edges = EP_ETH_RX_NEXT_MAX,
	.next_nodes = {
			/* Default pkt lookup node */
			[EP_ETH_RX_NEXT_FLOW_MAPPER] = "flow_mapper",
		},
};

struct rte_node_register *
ood_eth_rx_node_get(void)
{
	return &ood_eth_rx_node_base;
}

RTE_NODE_REGISTER(ood_eth_rx_node_base);
