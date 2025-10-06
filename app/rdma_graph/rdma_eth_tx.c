/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_hexdump.h>
#include <rte_mbuf_core.h>
#include <rte_pause.h>

#include <dao_log.h>

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
	/* throttle huge bursts to avoid NIC backpressure */
	const uint16_t max_burst = 256;
	/* retry knobs: aggressive but bounded to preserve graph liveness */
	const uint16_t max_retries_per_chunk = 64;

	if (unlikely(nb_objs == 0))
		return 0;

	/* Get Tx port id */
	port = ctx->port;

	/* Get the queue from the first packet */
	mbuf = (struct rte_mbuf *)objs[0];
	queue = node_mbuf_priv1(mbuf, dyn)->queue;

	/* Send in chunks to improve fairness and reduce 0-sent on huge bursts */
	while (sent < nb_objs) {
		uint16_t todo = RTE_MIN((uint16_t)(nb_objs - sent), max_burst);
		uint16_t retries = 0;

		/* Keep submitting the same contiguous window until all are enqueued or retries
		 * exhausted. */
		while (todo > 0 && retries <= max_retries_per_chunk) {
			uint16_t n = rte_eth_tx_burst(port, queue, (struct rte_mbuf **)&objs[sent],
						      todo);
			if (likely(n > 0)) {
				sent += n;
				todo -= n;
				/* If not all sent, try again for remainder without advancing
				 * pointer beyond 'sent' */
				continue;
			}

			/* No immediate progress; try to free done mbufs and backoff briefly */
			(void)rte_eth_tx_done_cleanup(port, queue, 0);
			retries++;
			rte_pause();
			/* Optional tiny sleep every few retries to give HW room without stalling
			 * the graph */
			if ((retries & 0x7) == 0)
				rte_delay_us_block(1);
		}

		/* If still have unsent items in this chunk after retries, stop and drop the rest */
		if (todo > 0) {
			dao_err("RDMA ETH TX: enqueue partial on port %u queue %u; failed within chunk: %u (retries=%u)",
				port, queue, todo, retries);
			break;
		}
	}
	count = sent;

	/* Redirect unsent pkts to drop node */
	if (count != nb_objs)
		rte_node_enqueue(graph, node, EP_ETH_TX_NEXT_PKT_DROP, &objs[count],
				 nb_objs - count);
#ifdef RDMA_DEBUG
	dao_dbg("RDMA ETH TX: port %u queue %u sent %u packets, unsent %u packets", port, queue,
		count, nb_objs - count);
#endif
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
