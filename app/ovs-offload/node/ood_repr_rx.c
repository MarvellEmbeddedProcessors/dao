/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_malloc.h>

#include <dao_log.h>

#include <ood_msg_ctrl.h>
#include <ood_node_ctrl.h>

#include "ood_repr_rx_priv.h"

#define REPR_RX_NODE_PRIV1_OFF(ctx) (((struct repr_rx_node_ctx *)ctx)->mbuf_priv1_off)

#define MAX_PKT_BURST 32
static struct repr_rx_node_main repr_rx_main;
int node_mbuf_priv1_dynfield_queue = -1;

static __rte_always_inline uint16_t
repr_rx_node_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs)
{
	repr_rx_node_ctx_t *ctx = (repr_rx_node_ctx_t *)node->ctx;
	const int dyn = REPR_RX_NODE_PRIV1_OFF(node->ctx);
	uint16_t n_pkts = 0, nb_repr, port, j;
	struct rte_mbuf *mbuf;
	uint16_t next_index;

	RTE_SET_USED(nb_objs);
	port = ctx->port_id;
	nb_repr = ctx->nb_repr;
	next_index = REPR_RX_NEXT_FLOW_MAPPER;

	/* Get pkts from port */
	n_pkts = rte_eth_rx_burst(port, OOD_ESWITCH_DEFAULT_QUEUE, (struct rte_mbuf **)node->objs,
				  MAX_PKT_BURST);
	if (!n_pkts)
		return 0;

	node->idx = n_pkts;

	for (j = 0; j < n_pkts; j++) {
		mbuf = (struct rte_mbuf *)objs[j];
		dao_dbg("lcore %d name %s port %d vlan_tci %d nb_repr %d", rte_lcore_id(),
			node->name, port, mbuf->vlan_tci, nb_repr);

		/* Next hop is the port no which corresponds to queue ID
		 * if the representor.
		 */
		node_mbuf_priv1(mbuf, dyn)->nh = mbuf->vlan_tci;
		next_index = REPR_RX_NEXT_FLOW_MAPPER;
	}

	/* Enqueue to next node */
	rte_node_enqueue(graph, node, next_index, objs, n_pkts);

	return n_pkts;
}

static int
repr_rx_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	repr_rx_node_ctx_t *ctx = (repr_rx_node_ctx_t *)node->ctx;
	static bool init_once;

	RTE_SET_USED(graph);

	ctx->port_id = repr_rx_main.repr_portid;
	ctx->nb_repr = repr_rx_main.nb_repr;

	/* Registering mbuf field for storing queue from which packet is
	 * received. Same will be used by subsequent nodes to determine the
	 * host port based on it.
	 */
	if (!init_once) {
		node_mbuf_priv1_dynfield_queue =
			rte_mbuf_dynfield_register(&node_mbuf_priv1_dynfield_desc);
		if (node_mbuf_priv1_dynfield_queue < 0)
			return -rte_errno;

		init_once = 1;
	}

	REPR_RX_NODE_PRIV1_OFF(node->ctx) = node_mbuf_priv1_dynfield_queue;
	dao_dbg("node_mbuf_priv1_dynfield_queue %d", node_mbuf_priv1_dynfield_queue);

	return 0;
}

struct repr_rx_node_main *
repr_rx_get_node_data_get(void)
{
	return &repr_rx_main;
}

static struct rte_node_register repr_rx_node_base = {
	.process = repr_rx_node_process,
	.flags = RTE_NODE_SOURCE_F,
	.name = "repr_rx",

	.init = repr_rx_node_init,

	.nb_edges = REPR_RX_NEXT_MAX,
	.next_nodes = {
			[REPR_RX_NEXT_PKT_DROP] = "pkt_drop",
			/* Default pkt lookup node */
			[REPR_RX_NEXT_FLOW_MAPPER] = "flow_mapper",
		},
};

struct rte_node_register *
repr_rx_node_get(void)
{
	return &repr_rx_node_base;
}

RTE_NODE_REGISTER(repr_rx_node_base);
