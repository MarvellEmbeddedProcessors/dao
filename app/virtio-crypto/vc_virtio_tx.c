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
	if (nb_objs == 0xFFFF) {
		nb_objs = 0;

		/* Empty poll on first queue. This empty poll need to be moved as separate node. */
		cdev_qp_id = 0;
		nb_tx_iter = 0;
	} else {
		/* Retrieve metadata from first packet */
		buf = RTE_PTR_SUB(objs[0], offsetof(struct dao_virtio_crypto_buffer, cop));
		cdev_qp_id = buf->metadata.cdev.qp_id;
		nb_tx_iter = buf->metadata.cnt;
	}

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
