/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <stdio.h>
#include <stdlib.h>

#include <rte_cryptodev.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_malloc.h>

#include <dao_virtio_cryptodev.h>

#include "vc_node.h"
#include "vc_offload.h"

static uint16_t
vc_cryptodev_enq_node_process(struct rte_graph *graph, struct rte_node *node, void **objs,
			      uint16_t cnt)
{
	uint16_t queue, devid, nq_total, nq_iter, ret;
	struct dao_virtio_crypto_buffer *buf;

#ifdef VIRTIO_CRYPTO_DEBUG
	if (unlikely(cnt == 0)) {
		APP_ERR("Invalid count\n");
		return 0;
	}
#endif

	nq_total = 0;

again:
	/* Get metadata from first object */
	buf = RTE_PTR_SUB((struct rte_crypto_op *)objs[0],
			  offsetof(struct dao_virtio_crypto_buffer, cop));
	devid = buf->metadata.cdev.id;
	queue = buf->metadata.cdev.qp_id;
	nq_iter = buf->metadata.cnt;

#ifdef VIRTIO_CRYPTO_DEBUG
	if (unlikely(nq_total + nq_iter > cnt)) {
		APP_ERR("CRITICAL_ERR: Invalid count\n");
		return nq_total;
	}
#endif

	ret = rte_cryptodev_enqueue_burst(devid, queue, (struct rte_crypto_op **)objs, nq_iter);
	if (unlikely(ret < nq_iter)) {
		APP_ERR("CRITICAL_ERR: Could not enqueue %u crypto ops\n", nq_iter - ret);
		return nq_total + ret;
	}

	nq_total += nq_iter;

	if (nq_total < cnt) {
		objs += nq_total;
		goto again;
	}

	RTE_SET_USED(graph);
	RTE_SET_USED(node);

	return nq_total;
}

static int
vc_cryptodev_enq_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);

	return 0;
}

static struct rte_node_register vc_cryptodev_enq_node_base = {
	.process = vc_cryptodev_enq_node_process,
	.name = "vc_cryptodev_enq",

	.init = vc_cryptodev_enq_node_init,

	.nb_edges = 1,
	.next_nodes = {
		[0] = "cop_drop",
	},
};

struct rte_node_register *
vc_cryptodev_enq_node_get(void)
{
	return &vc_cryptodev_enq_node_base;
}

RTE_NODE_REGISTER(vc_cryptodev_enq_node_base);
