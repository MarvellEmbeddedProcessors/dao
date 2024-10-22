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
	struct dao_virtio_crypto_buffer *buf;
	uint16_t devid, queue, nb_cops;
	struct rte_crypto_op **cops;
	uint64_t crypto_q_map;

	RTE_SET_USED(objs);
	RTE_SET_USED(cnt);

	devid = ctx->devid;
	crypto_q_map = ctx->crypto_q_map;
	queue = ctx->next_q;

	if (crypto_q_map == 0) {
		rte_pause();
		return 0;
	}

	if (!(crypto_q_map & RTE_BIT64(queue))) {
		ctx->next_q = queue >= 63 ? 0 : queue + 1;
		return 0;
	}

	/* Get stream for cops */
	cops = (struct rte_crypto_op **)rte_node_next_stream_get(graph, node, 1,
								 VC_CRYPTODEV_DEQ_BURST_MAX);

	nb_cops = rte_cryptodev_dequeue_burst(devid, queue, cops, VC_CRYPTODEV_DEQ_BURST_MAX);

	ctx->next_q = queue >= 63 ? 0 : queue + 1;

	/* For the rte_node_next_stream_put() to work, nb_cops should be non zero.
	 * Since packets are posted in virtio tx for DMA,
	 * we need to check for DMA completion even if no new packets are there.
	 * So nb_cops is set to 0xFFFF to check for DMA completion of previous packets.
	 */
	if (nb_cops == 0) {
		nb_cops = 0xFFFF;
	} else {
		/* Set metadata in first packet to save cryptodev ID & queue */
		buf = RTE_PTR_SUB(cops[0], offsetof(struct dao_virtio_crypto_buffer, cop));
		buf->metadata.cdev.qp_id = queue;
		buf->metadata.cnt = nb_cops;
	}

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
