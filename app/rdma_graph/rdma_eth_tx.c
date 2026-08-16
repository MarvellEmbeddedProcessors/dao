/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_hexdump.h>
#include <rte_lcore.h>
#include <rte_mbuf_core.h>
#include <rte_pause.h>

#include <dao_log.h>

#include "rdma_counter.h"
#include "rdma_eth_tx_priv.h"
#include "rdma_node_ctrl.h"

extern int node_mbuf_priv1_dynfield_queue;
static struct rdma_eth_tx_node_main rdma_eth_tx_main;

#define RDMA_ETH_TX_NODE_PRIV1_OFF(ctx) (((struct rdma_eth_tx_node_ctx *)ctx)->mbuf_priv1_off)

static uint16_t
rdma_eth_tx_node_process(struct rte_graph *graph, struct rte_node *node, void **objs,
			 uint16_t nb_objs)
{
	rdma_eth_tx_node_ctx_t *ctx = (rdma_eth_tx_node_ctx_t *)node->ctx;
	const int dyn = RDMA_ETH_TX_NODE_PRIV1_OFF(node->ctx);
	struct rte_mbuf *mbuf;
	uint16_t port, queue;
	uint16_t count = 0, sent = 0;
	/* Send in up to 512-packet windows; retry for a bounded time before dropping. */
	const uint16_t max_burst = 512;
	/* RDMA wire packets should not be dropped; retry until sent or hard stall. */
	const uint32_t max_stall = 1000000;
	uint32_t stall = 0;

	if (unlikely(nb_objs == 0))
		return 0;

	/* Get Tx port id */
	port = ctx->port;

	/* Get the queue from the first packet */
	mbuf = (struct rte_mbuf *)objs[0];
	queue = node_mbuf_priv1(mbuf, dyn)->queue;

	while (sent < nb_objs) {
		uint16_t batch = RTE_MIN((uint16_t)(nb_objs - sent), max_burst);
		uint16_t n = rte_eth_tx_burst(port, queue, (struct rte_mbuf **)&objs[sent], batch);

		if (likely(n > 0)) {
			sent += n;
			stall = 0;
			continue;
		}

		(void)rte_eth_tx_done_cleanup(port, queue, 0);
		stall++;
		rte_pause();
		if ((stall & 0x7) == 0)
			rte_delay_us_block(1);
		if (unlikely(stall >= max_stall)) {
			dao_dbg("RDMA ETH TX: stall limit on port %u queue %u; unsent=%u", port,
				queue, (uint16_t)(nb_objs - sent));
			break;
		}
	}
	count = sent;

	RDMA_DBG_ADD_PORT_COUNTER(rte_lcore_id(), port, RDMA_TX_PORT_ETH_TX_SENT, count);

	/* Redirect unsent pkts to drop node */
	if (count != nb_objs) {
		uint16_t dropped = nb_objs - count;

		RDMA_ADD_PORT_COUNTER(rte_lcore_id(), port, RDMA_PORT_ETH_TX_DROP, dropped);
		rte_node_enqueue(graph, node, EP_ETH_TX_NEXT_PKT_DROP, &objs[count], dropped);
	}
	return count;
}

static int
rdma_eth_tx_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	rdma_eth_tx_node_ctx_t *ctx = (rdma_eth_tx_node_ctx_t *)node->ctx;
	uint64_t port_id = RTE_MAX_ETHPORTS;
	static bool init_once;
	int i;

	RTE_SET_USED(graph);
	/* Find our port id */
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (rdma_eth_tx_main.nodes[i] == node->id) {
			port_id = i;
			break;
		}
	}
	RTE_VERIFY(port_id < RTE_MAX_ETHPORTS);

	/* Update port and queue */
	ctx->port = port_id;
	ctx->queue = graph->id;

	if (!init_once) {
		node_mbuf_priv1_dynfield_queue =
			rte_mbuf_dynfield_register(&node_mbuf_priv1_dynfield_desc);
		if (node_mbuf_priv1_dynfield_queue < 0)
			return -rte_errno;
		init_once = true;
	}

	RDMA_ETH_TX_NODE_PRIV1_OFF(node->ctx) = node_mbuf_priv1_dynfield_queue;

	return 0;
}

struct rdma_eth_tx_node_main *
rdma_eth_tx_node_data_get(void)
{
	return &rdma_eth_tx_main;
}

static struct rte_node_register rdma_eth_tx_node_base = {
	.process = rdma_eth_tx_node_process,
	.name = "rdma_eth_tx",
	.init = rdma_eth_tx_node_init,
	.nb_edges = EP_ETH_TX_NEXT_MAX,
	.next_nodes = {
		[EP_ETH_TX_NEXT_PKT_DROP] = "pkt_drop",
	},
};

struct rte_node_register *
rdma_eth_tx_node_get(void)
{
	return &rdma_eth_tx_node_base;
}

RTE_NODE_REGISTER(rdma_eth_tx_node_base);
