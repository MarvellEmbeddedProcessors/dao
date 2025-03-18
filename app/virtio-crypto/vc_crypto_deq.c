/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <stdio.h>
#include <stdlib.h>

#include <rte_cryptodev.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_mbuf.h>

#include <dao_virtio_cryptodev.h>

#include "vc_node.h"
#include "vc_offload.h"

static __rte_always_inline uint16_t
vc_cryptodev_deq_node_process(struct rte_graph *graph, struct rte_node *node, void **objs,
			      uint16_t cnt)
{
	vc_cryptodev_deq_node_ctx_t *ctx = (vc_cryptodev_deq_node_ctx_t *)node->ctx;
	uint16_t devid, queue, q_count, nb_cops = 0, max_cops, count;
	struct dao_virtio_crypto_buffer *buf;
	struct rte_crypto_op **cops;
	uint64_t crypto_q_map;

	RTE_SET_USED(objs);
	RTE_SET_USED(cnt);

	if (ctx->crypto_q_map == 0) {
		rte_pause();
		return 0;
	}

	devid = ctx->devid;
	queue = ctx->next_q;
	crypto_q_map = ctx->crypto_q_map;
	max_cops = VC_VIRTIO_RX_BURST_MAX;
	q_count = __builtin_popcountl(crypto_q_map);

	/* Get stream for cops */
	cops = (struct rte_crypto_op **)rte_node_next_stream_get(graph, node, 1, max_cops);

	while (q_count && nb_cops < max_cops) {
		if (!(crypto_q_map & RTE_BIT64(queue))) {
			queue = queue >= 63 ? 0 : queue + 1;
			continue;
		}
		count = RTE_MIN(VC_VIRTIO_RX_BURST_PER_Q, max_cops - nb_cops);

		count = rte_cryptodev_dequeue_burst(devid, queue, cops, count);

		if (count == 0) {
			queue = queue >= 63 ? 0 : queue + 1;
			q_count--;
			continue;
		}

		/* Set metadata in first packet to save cryptodev ID & queue */
		buf = RTE_PTR_SUB(cops[0], offsetof(struct dao_virtio_crypto_buffer, cop));
		buf->metadata.cdev.qp_id = queue;
		buf->metadata.cnt = count;

		nb_cops += count;
		queue = queue >= 63 ? 0 : queue + 1;
		q_count--;
	}
	ctx->next_q = queue;

	if (!nb_cops)
		return 0;

	/* Put cops to next node */
	rte_node_next_stream_put(graph, node, 1, nb_cops);

	return nb_cops;
}

static int
vc_cryptodev_deq_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);

	return 0;
}

static struct rte_node_register vc_cryptodev_deq_node_base = {
	.process = vc_cryptodev_deq_node_process,
	.flags = RTE_NODE_SOURCE_F,
	.name = "vc_cryptodev_deq",

	.init = vc_cryptodev_deq_node_init,

	.nb_edges = 1,
	.next_nodes = {
		[0] = "cop_drop",
	},
};

struct rte_node_register *
vc_cryptodev_deq_node_get(void)
{
	return &vc_cryptodev_deq_node_base;
}

RTE_NODE_REGISTER(vc_cryptodev_deq_node_base);
