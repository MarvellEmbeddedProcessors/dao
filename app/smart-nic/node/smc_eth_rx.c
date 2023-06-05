/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <stdlib.h>

#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#include <dao_log.h>

#include "smc_eth_rx_priv.h"

#define SMC_ETHDEV_RX_BURST_PER_Q 64
#define SMC_ETHDEV_RX_BURST_MAX   128
static struct smc_eth_rx_node_main smc_eth_rx_main;

static __rte_always_inline uint16_t
smc_eth_rx_node_process_inline(struct rte_graph *graph, struct rte_node *node,
			       smc_eth_rx_node_ctx_t *ctx)
{
	uint16_t nb_pkts = 0, next_index, count;
	uint16_t port, queue = 0;
	uint64_t rx_q_map;
	uint16_t q_count;

	rx_q_map = ctx->rx_q_map;
	port = ctx->port;
	next_index = ctx->next;

	q_count = __builtin_popcountl(rx_q_map);
	while (q_count) {
		if (!(rx_q_map & RTE_BIT64(queue))) {
			queue = queue >= 63 ? 0 : queue + 1;
			continue;
		}

		next_index = ctx->next;
		count = rte_eth_rx_burst(port, queue, (struct rte_mbuf **)node->objs,
					 RTE_GRAPH_BURST_SIZE);
		if (count)
			dao_dbg("name %s port %d queue %d nb_pkts %d next %d", node->name, port,
				queue, count, next_index);

		nb_pkts += count;
		queue = queue >= 63 ? 0 : queue + 1;
		q_count--;
	}

	if (!nb_pkts)
		return 0;

	node->idx = nb_pkts;
	/* Enqueue to next node */
	rte_node_next_stream_move(graph, node, next_index);

	return nb_pkts;
}

static __rte_always_inline uint16_t
smc_eth_rx_node_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t cnt)
{
	smc_eth_rx_node_ctx_t *ctx = (smc_eth_rx_node_ctx_t *)node->ctx;
	uint16_t n_pkts = 0;

	RTE_SET_USED(objs);
	RTE_SET_USED(cnt);

	n_pkts = smc_eth_rx_node_process_inline(graph, node, ctx);
	return n_pkts;
}

static int
smc_eth_rx_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	smc_eth_rx_node_ctx_t *ctx = (smc_eth_rx_node_ctx_t *)node->ctx;
	smc_eth_rx_node_elem_t *elem = smc_eth_rx_main.head;

	RTE_SET_USED(graph);

	while (elem) {
		if (elem->nid == node->id) {
			/* Update node specific context */
			memcpy(ctx, &elem->ctx, sizeof(smc_eth_rx_node_ctx_t));
			break;
		}
		elem = elem->next;
	}
	RTE_VERIFY(elem != NULL);

	/* Check and setup ptype */
	return 0;
}

int
smc_eth_rx_q_map_update(struct rte_node *node, uint64_t q_map, bool enable)
{
	smc_eth_rx_node_ctx_t *ctx = (smc_eth_rx_node_ctx_t *)node->ctx;

	smc_eth_rx_node_elem_t *elem = smc_eth_rx_main.head;

	while (elem) {
		if (elem->nid == node->id) {
			/* Update node specific context */
			memcpy(&elem->ctx, ctx, sizeof(smc_eth_rx_node_ctx_t));
			if (enable)
				elem->ctx.rx_q_map |= q_map;
			else
				elem->ctx.rx_q_map &= q_map;
			memcpy(ctx, &elem->ctx, sizeof(smc_eth_rx_node_ctx_t));
			break;
		}
		elem = elem->next;
	}

	return 0;
}

int
smc_eth_rx_next_update(struct rte_node *node, const char *edge_name, bool link)
{
	smc_eth_rx_node_ctx_t *ctx = (smc_eth_rx_node_ctx_t *)node->ctx;
	smc_eth_rx_node_elem_t *elem = smc_eth_rx_main.head;
	char **next_nodes;
	rte_node_t rx_id;
	uint16_t i = 0;
	uint32_t size;
	bool found = false;

	if (edge_name == NULL)
		goto fail;

	rx_id = rte_node_from_name(node->name);
	if (rte_node_is_invalid(rx_id))
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid node id for %s", node->name);

	size = rte_node_edge_get(rx_id, NULL);
	if (size == RTE_NODE_ID_INVALID)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid next node size %s", node->name);

	next_nodes = calloc((size / sizeof(char *)) + 1, sizeof(*next_nodes));
	if (next_nodes == NULL)
		DAO_ERR_GOTO(-ENOMEM, fail, "Invalid next node size %s", node->name);

	size = rte_node_edge_get(rx_id, next_nodes);
	while (next_nodes[i] != NULL) {
		if (strcmp(edge_name, next_nodes[i]) == 0) {
			while (elem) {
				if (elem->nid == rx_id) {
					memcpy(&elem->ctx, ctx, sizeof(struct smc_eth_rx_node_ctx));
					elem->ctx.next = link ? i : SMC_ETH_RX_NEXT_PKT_DROP;
					memcpy(ctx, &elem->ctx, sizeof(struct smc_eth_rx_node_ctx));
					found = true;
					break;
				}
				elem = elem->next;
			}
		}
		if (found)
			break;
		i++;
	}

	free(next_nodes);
	return 0;
fail:
	return -errno;
}

struct smc_eth_rx_node_main *
smc_eth_rx_node_data_get(void)
{
	return &smc_eth_rx_main;
}

static struct rte_node_register smc_eth_rx_node_base = {
	.process = smc_eth_rx_node_process,
	.flags = RTE_NODE_SOURCE_F,
	.name = "smc_eth_rx",

	.init = smc_eth_rx_node_init,

	.nb_edges = SMC_ETH_RX_NEXT_MAX,
	.next_nodes = {
		/* Default pkt lookup node */
		[SMC_ETH_RX_NEXT_PKT_DROP] = "pkt_drop",
	},
};

struct rte_node_register *
smc_eth_rx_node_get(void)
{
	return &smc_eth_rx_node_base;
}

RTE_NODE_REGISTER(smc_eth_rx_node_base);
