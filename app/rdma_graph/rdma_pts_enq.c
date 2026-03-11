/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Marvell.
 */

#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_hexdump.h>
#include <rte_mbuf_core.h>

#include <dao_log.h>
#include <dao_pts_rdma_dev.h>

#include "rdma_node_ctrl.h"
#include "rdma_pts_enq_priv.h"

extern int node_mbuf_priv1_dynfield_queue;
static struct rdma_pts_enq_node_main rdma_pts_enq_main;

#define RDMA_PTS_ENQ_NODE_PRIV1_OFF(ctx) (((struct rdma_pts_enq_node_ctx *)ctx)->mbuf_priv1_off)

static uint16_t
rdma_pts_enq_node_process(struct rte_graph *graph, struct rte_node *node, void **objs,
			  uint16_t nb_objs)
{
	rdma_pts_enq_node_ctx_t *ctx = (rdma_pts_enq_node_ctx_t *)node->ctx;
	const int dyn = node_mbuf_priv1_dynfield_queue;
	uint16_t count, nb_pkts, i;
	struct rte_mbuf *mbuf;
	uint16_t devid;
	uint16_t qp_id;

	/* Get Tx port id */
	devid = ctx->devid;

	i = 0;
	while (i < nb_objs) {
		mbuf = (struct rte_mbuf *)objs[i];
		qp_id = node_mbuf_priv1(mbuf, dyn)->qp_id;
		nb_pkts = node_mbuf_priv1(mbuf, dyn)->nb_pkts;
		/* Enqueue to host */
		count = dao_pts_rdma_enqueue_burst(devid, qp_id, (struct rte_mbuf **)&objs[i],
						   nb_pkts);
		/* Redirect unsent pkts to drop node */
		if (count != nb_pkts) {
			mbuf->ol_flags = 0;
			rte_node_enqueue(graph, node, 0, &objs[i + count], nb_pkts - count);
		}
		i += nb_pkts;
	}

	return nb_objs;
}

struct rdma_pts_enq_node_main *
rdma_pts_enq_node_data_get(void)
{
	return &rdma_pts_enq_main;
}

static struct rte_node_register rdma_pts_enq_node_base = {
	.process = rdma_pts_enq_node_process,
	.name = "rdma_pts_enq",
	.nb_edges = 1,
	.next_nodes = {
		[0] = "pkt_drop",
	},
};

struct rte_node_register *
rdma_pts_enq_node_get(void)
{
	return &rdma_pts_enq_node_base;
}

RTE_NODE_REGISTER(rdma_pts_enq_node_base);
