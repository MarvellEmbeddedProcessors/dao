/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <dao_virtio_cryptodev.h>

#include "vc_node.h"
#include "vc_offload.h"

static __rte_always_inline uint16_t
vc_virtio_rx_node_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t cnt)
{
	vc_virtio_rx_node_ctx_t *ctx = (vc_virtio_rx_node_ctx_t *)node->ctx;
	uint16_t nb_cops = 0, next_index, count;
	struct rte_crypto_op **cops;
	uint16_t queue, virt_q;
	uint16_t virtio_devid;
	uint64_t virt_q_map;
	uint16_t max_cops;
	uint16_t q_count;

	RTE_SET_USED(objs);
	RTE_SET_USED(cnt);

	if (ctx->virt_q_map == 0) {
		rte_pause();
		return 0;
	}

	next_index = ctx->next_devid;
	virt_q_map = ctx->virt_q_map;
	virtio_devid = ctx->virtio_devid;
	max_cops = VC_VIRTIO_RX_BURST_MAX;

	/*
	 * Application registers vc_cryptodev_enq node as next node 1. If there are more cryptodev
	 * and nodes, this need to be revisited.
	 */
	next_index = 1;

	/* Get stream for cops */
	cops = (struct rte_crypto_op **)rte_node_next_stream_get(graph, node, next_index, max_cops);

	q_count = __builtin_popcountl(virt_q_map);
	queue = ctx->next_q;
	while (q_count && nb_cops < max_cops) {
		if (!(virt_q_map & RTE_BIT64(queue))) {
			queue = queue >= 63 ? 0 : queue + 1;
			continue;
		}

		virt_q = (queue << 1);
		count = RTE_MIN(VC_VIRTIO_RX_BURST_PER_Q, max_cops - nb_cops);
		count = dao_virtio_crypto_host_rx(virtio_devid, virt_q, &cops[nb_cops], count);

		nb_cops += count;
		queue = queue >= 63 ? 0 : queue + 1;
		rte_prefetch0(dao_virtio_cryptodevs[virtio_devid].qs[queue]);
		q_count--;
	}
	ctx->next_q = queue;

	if (!nb_cops)
		return 0;

	/* Put cops to next node */
	rte_node_next_stream_put(graph, node, next_index, nb_cops);

	return nb_cops;
}

static int
vc_virtio_rx_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);

	return 0;
}

static struct rte_node_register vc_virtio_rx_node_base = {
	.process = vc_virtio_rx_node_process,
	.flags = RTE_NODE_SOURCE_F,
	.name = "vc_virtio_rx",

	.init = vc_virtio_rx_node_init,

	.nb_edges = 1,
	.next_nodes = {
		[0] = "cop_drop",
	},
};

struct rte_node_register *
vc_virtio_rx_node_get(void)
{
	return &vc_virtio_rx_node_base;
}

RTE_NODE_REGISTER(vc_virtio_rx_node_base);
