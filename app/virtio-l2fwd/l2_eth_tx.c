/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2024 Marvell.
 */

#include "l2_node.h"

/* Maximum retry attempts before dropping packets */
#define L2_ETHDEV_TX_MAX_RETRIES 2048

static uint16_t
l2_ethdev_tx_node_process(struct rte_graph *graph, struct rte_node *node, void **objs,
			  uint16_t nb_objs)
{
	l2_ethdev_tx_node_ctx_t *ctx = (l2_ethdev_tx_node_ctx_t *)node->ctx;
	uint16_t count, nb_pkts, sent, i;
	struct rte_mbuf *mbuf;
	uint32_t retry_count;
	uint16_t port, queue;

	/* Get Tx port id */
	port = ctx->eth_port;

	i = 0;
	while (i < nb_objs) {
		mbuf = (struct rte_mbuf *)objs[i];
		queue = l2_mbuf_tx_priv1(mbuf)->tx_queue;
		nb_pkts = l2_mbuf_tx_priv1(mbuf)->nb_pkts;

		sent = 0;
		retry_count = 0;
		while (sent < nb_pkts) {
			count = rte_eth_tx_burst(port, queue, (struct rte_mbuf **)&objs[i + sent],
						 nb_pkts - sent);
			sent += count;
			if (sent < nb_pkts) {
				if (unlikely(retry_count >= L2_ETHDEV_TX_MAX_RETRIES)) {
					rte_node_enqueue(graph, node, 0, &objs[i + sent],
							 nb_pkts - sent);
					break;
				}
				retry_count++;
			}
		}
		i += nb_pkts;
	}

	return nb_objs;
}

static struct rte_node_register l2_ethdev_tx_node_base = {
	.process = l2_ethdev_tx_node_process,
	.name = "l2_ethdev_tx",

	.nb_edges = 1,
	.next_nodes = {
		[0] = "pkt_drop",
	},
};

struct rte_node_register *
l2_ethdev_tx_node_get(void)
{
	return &l2_ethdev_tx_node_base;
}

RTE_NODE_REGISTER(l2_ethdev_tx_node_base);
