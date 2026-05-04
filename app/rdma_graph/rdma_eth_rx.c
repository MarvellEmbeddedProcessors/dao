/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <dao_log.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_hexdump.h>
#include <rte_mbuf_core.h>

#include "rdma_counter.h"
#include "rdma_eth_rx_priv.h"
#include "rdma_node_ctrl.h"

int node_mbuf_priv1_dynfield_queue = -1;
static struct rdma_eth_rx_node_main rdma_eth_rx_main;

#define RDMA_ETH_RX_NODE_PRIV1_OFF(ctx) (((struct rdma_eth_rx_node_ctx *)ctx)->mbuf_priv1_off)

static __rte_always_inline uint16_t
rdma_eth_rx_node_process_inline(struct rte_graph *graph, struct rte_node *node,
				rdma_eth_rx_node_ctx_t *ctx)
{
	const int dyn = RDMA_ETH_RX_NODE_PRIV1_OFF(node->ctx);
	uint16_t count, next_index;
	uint16_t port, queue;
	struct rte_mbuf *mbuf;
	int i;

	port = ctx->port_id;
	queue = ctx->queue_id;
	next_index = EP_ETH_RX_NEXT_RDMA;

	/* Get pkts from port */
	count = rte_eth_rx_burst(port, queue, (struct rte_mbuf **)node->objs,
				 APP_RDMA_ETH_DEQ_BURST_MAX);

	if (!count)
		return 0;
	RDMA_DBG_ADD_PORT_COUNTER(rte_lcore_id(), port, RDMA_RX_PORT_ETH_RX_RECVD, count);

	/* Burst of packets received will be from same port and queue-id */
	for (i = 0; i < count; i++) {
		mbuf = node->objs[i];
		node_mbuf_priv1(mbuf, dyn)->queue = queue;
		node_mbuf_priv1(mbuf, dyn)->port = port;
	}
#ifdef DAO_RDMA_DEBUG
	dao_dbg("lcore %d name %s port %d queue %d count %u", rte_lcore_id(), node->name, port,
		queue, count);
#endif
	node->idx = count;
	/* Enqueue to next node */
	rte_node_next_stream_move(graph, node, next_index);

	return count;
}

static __rte_always_inline uint16_t
rdma_eth_rx_node_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t cnt)
{
	rdma_eth_rx_node_ctx_t *ctx = (rdma_eth_rx_node_ctx_t *)node->ctx;
	uint16_t n_pkts = 0;

	RTE_SET_USED(objs);
	RTE_SET_USED(cnt);

	n_pkts = rdma_eth_rx_node_process_inline(graph, node, ctx);
	return n_pkts;
}

static int
rdma_eth_rx_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	static bool init_once;

	rdma_eth_rx_node_ctx_t *ctx = (rdma_eth_rx_node_ctx_t *)node->ctx;
	rdma_eth_rx_node_elem_t *elem = rdma_eth_rx_main.head;

	RTE_SET_USED(graph);

	while (elem) {
		if (elem->nid == node->id) {
			/* Update node specific context */
			memcpy(ctx, &elem->ctx, sizeof(rdma_eth_rx_node_ctx_t));
			break;
		}
		elem = elem->next;
	}

	RTE_VERIFY(elem != NULL);

	if (!init_once) {
		node_mbuf_priv1_dynfield_queue =
			rte_mbuf_dynfield_register(&node_mbuf_priv1_dynfield_desc);
		if (node_mbuf_priv1_dynfield_queue < 0)
			return -rte_errno;
		init_once = true;
	}

	RDMA_ETH_RX_NODE_PRIV1_OFF(node->ctx) = node_mbuf_priv1_dynfield_queue;

	/* Check and setup ptype */
	return 0;
}

struct rdma_eth_rx_node_main *
rdma_eth_rx_get_node_data_get(void)
{
	return &rdma_eth_rx_main;
}

static struct rte_node_register rdma_eth_rx_node_base = {
	.process = rdma_eth_rx_node_process,
	.flags = RTE_NODE_SOURCE_F,
	.name = "rdma_eth_rx",
	.init = rdma_eth_rx_node_init,
	.nb_edges = EP_ETH_RX_NEXT_MAX,
	.next_nodes = {
		/* Default rdma node */
		[EP_ETH_RX_NEXT_RDMA] = "rdma_rx_process",
	},
};

struct rte_node_register *
rdma_eth_rx_node_get(void)
{
	return &rdma_eth_rx_node_base;
}

RTE_NODE_REGISTER(rdma_eth_rx_node_base);
