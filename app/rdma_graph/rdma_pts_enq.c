/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
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
	uint16_t nb_pkts, i, sent, todo;
	/* retry knobs: aggressive but bounded to preserve graph liveness */
	const uint16_t max_retries_per_chunk = 64;
	struct rte_mbuf *mbuf;
	uint16_t retries;
	uint16_t devid;
	uint16_t qp_id;
	uint16_t n;

	/* Get Tx port id */
	devid = ctx->devid;

	i = 0;
	while (i < nb_objs) {
		mbuf = (struct rte_mbuf *)objs[i];
		qp_id = node_mbuf_priv1(mbuf, dyn)->qp_id;
		nb_pkts = node_mbuf_priv1(mbuf, dyn)->nb_pkts;

		sent = 0;
		todo = nb_pkts;
		retries = 0;

		/* Keep submitting until all are enqueued or retries exhausted */
		while (todo > 0 && retries <= max_retries_per_chunk) {
			n = dao_pts_rdma_enqueue_burst(devid, qp_id,
						       (struct rte_mbuf **)&objs[i + sent], todo);
			if (likely(n > 0)) {
				sent += n;
				todo -= n;
				/* If not all sent, try again for remainder */
				continue;
			}

			/* No immediate progress; backoff briefly */
			retries++;
			rte_pause();
			/* Optional tiny sleep every few retries to give HW room without stalling
			 * the graph */
			if ((retries & 0x7) == 0)
				rte_delay_us_block(1);
		}

		/* Redirect unsent pkts to drop node */
		if (todo > 0) {
			mbuf->ol_flags = 0;
			rte_node_enqueue(graph, node, 0, &objs[i + sent], todo);
			dao_dbg("RDMA PTS Enqueue failed on dev %u qp %u, sent %u/%u pkts "
				"(retries=%u)",
				devid, qp_id, sent, nb_pkts, retries);
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
