/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_graph.h>

#include <dao_virtio_cryptodev.h>

#include "vc_node.h"
#include "vc_offload.h"

static uint16_t
vc_virtio_tx_node_process(struct rte_graph *graph, struct rte_node *node, void **objs,
			  uint16_t nb_objs)
{
	uint16_t nb_tx_total, nb_tx_iter, cdev_qp_id, virt_dev_id, virt_q_id, i = 0;
	vc_virtio_tx_node_ctx_t *ctx = (vc_virtio_tx_node_ctx_t *)node->ctx;
	struct dao_virtio_crypto_buffer *buf;

	if (ctx->cdev_vdev_map == NULL)
		return 0;

	nb_tx_total = 0;

again:

	/* Retrieve metadata from first packet */
	buf = RTE_PTR_SUB(objs[0], offsetof(struct dao_virtio_crypto_buffer, cop));
	cdev_qp_id = buf->metadata.cdev.qp_id;
	nb_tx_iter = buf->metadata.cnt;

	virt_dev_id = ctx->cdev_vdev_map[cdev_qp_id].virtio_dev_id;
	virt_q_id = ctx->cdev_vdev_map[cdev_qp_id].virtio_queue_id;

	dao_virtio_crypto_host_tx(virt_dev_id, virt_q_id, (struct rte_crypto_op **)&objs[i],
				  nb_tx_iter);

	nb_tx_total += nb_tx_iter;

	if (nb_tx_total < nb_objs) {
		objs += nb_tx_iter;
		goto again;
	}

	RTE_SET_USED(graph);
	return nb_tx_total;
}

static uint16_t
vc_virtio_tx_dma_completion_node_process(struct rte_graph *graph, struct rte_node *node,
					 void **objs, uint16_t nb_objs)
{
	vc_virtio_tx_dma_node_ctx_t *ctx = (vc_virtio_tx_dma_node_ctx_t *)node->ctx;
	uint16_t queue, virtio_devid;
	uint64_t virt_q_map;
	uint16_t q_count;

	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);

	virt_q_map = ctx->virt_q_map;
	virtio_devid = ctx->virtio_devid;
	q_count = __builtin_popcountl(virt_q_map);

	if (virt_q_map == 0) {
		rte_pause();
		return 0;
	}

	queue = ctx->next_q;

	while (q_count) {
		if (!(virt_q_map & RTE_BIT64(queue))) {
			queue = queue >= 63 ? 0 : queue + 1;
			continue;
		}

		dao_virtio_crypto_tx_desc_dma_completion(virtio_devid, queue);

		queue = queue >= 63 ? 0 : queue + 1;
		rte_prefetch0(dao_virtio_cryptodevs[virtio_devid].qs[queue]);
		q_count--;
	}

	ctx->next_q = queue;

	RTE_SET_USED(graph);
	RTE_SET_USED(node);

	return 0;
}

static struct rte_node_register vc_virtio_tx_dma_completion_node_base = {
	.process = vc_virtio_tx_dma_completion_node_process,
	.flags = RTE_NODE_SOURCE_F,
	.name = "vc_virtio_tx_dma",

	.nb_edges = 1,
	.next_nodes = {
		[0] = "cop_drop",
	},
};

struct rte_node_register *
vc_virtio_tx_dma_completion_node_get(void)
{
	return &vc_virtio_tx_dma_completion_node_base;
}

RTE_NODE_REGISTER(vc_virtio_tx_dma_completion_node_base);

static struct rte_node_register vc_virtio_tx_node_base = {
	.process = vc_virtio_tx_node_process,
	.name = "vc_virtio_tx",

	.nb_edges = 1,
	.next_nodes = {
		[0] = "cop_drop",
	},
};

struct rte_node_register *
vc_virtio_tx_node_get(void)
{
	return &vc_virtio_tx_node_base;
}

RTE_NODE_REGISTER(vc_virtio_tx_node_base);
