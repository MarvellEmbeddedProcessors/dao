/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */

#include <stdlib.h>

#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_hexdump.h>
#include <rte_malloc.h>
#include <rte_mbuf_core.h>
#include <rte_timer.h>

#include <dao_log.h>

#include <dao_pts_rdma_dev.h>

#include "dao_rdma_fp.h"
#include "rdma_node_ctrl.h"
#include "rdma_pts_deq_priv.h"

#define APP_RDMA_PTS_DEQ_RTR_MAX   64
#define APP_RDMA_PTS_DEQ_BURST_MAX 32

extern int node_mbuf_priv1_dynfield_queue;

#define RDMA_PTS_DEQ_NODE_PRIV1_OFF(ctx) (((struct rdma_pts_deq_node_ctx *)ctx)->mbuf_priv1_off)

static __rte_always_inline uint16_t
rdma_pts_deq_node_process_inline(struct rte_graph *graph, struct rte_node *node,
				 rdma_pts_deq_node_ctx_t *ctx)
{
	struct rte_mbuf *retr_mbufs[APP_RDMA_PTS_DEQ_RTR_MAX] = {NULL};
	struct rte_mbuf *mbufs[APP_RDMA_PTS_DEQ_BURST_MAX] = {NULL};
	const int dyn = node_mbuf_priv1_dynfield_queue;
	uint16_t nb_pkts = 0, next_index, count;
	rte_edge_t tx_edge = ctx->tx_node_idx;
	uint16_t retr_nb_pkts = 0, nb = 0;
	uint16_t qp_count = 0, can_fetch;
	uint32_t max_qp = 0, min_qp = 0;
	uint16_t max_pkts, drained;
	rdma_pts_bitmap_t *qp_map;
	struct rte_mbuf *mbuf;
	uint32_t qp_id;
	uint16_t devid;
	int i, j;

	next_index = ctx->next_node;
	devid = ctx->devid;
	max_pkts = APP_RDMA_PTS_DEQ_BURST_MAX;
	qp_map = ctx->qp_map;
	if (unlikely(!qp_map))
		return 0;

	for (i = RDMA_PTS_BITMAP_WORDS - 1; i >= 0; --i) {
		qp_count += __builtin_popcountl(qp_map->bits[i]);
		if (qp_map->bits[i] && !max_qp) {
			int bit_pos = 63 - rte_clz64(qp_map->bits[i]);

			max_qp = i * 64 + bit_pos;
		}

		j = RDMA_PTS_BITMAP_WORDS - 1 - i;
		if (qp_map->bits[j] && !min_qp)
			min_qp = j * 64 + rte_ctz64(qp_map->bits[j]);
	}

	qp_id = ctx->next_qp;
	if (qp_id < min_qp)
		qp_id = min_qp;

	while (qp_count && nb_pkts < max_pkts && retr_nb_pkts < APP_RDMA_PTS_DEQ_RTR_MAX) {
		if (!(qp_map->bits[qp_id / 64] & RTE_BIT64(qp_id % 64))) {
			qp_id = qp_id > max_qp ? min_qp : qp_id + 1;
			continue;
		}

		nb = dao_rdma_get_retransmition_pkts(
			qp_id, devid, APP_RDMA_PTS_DEQ_RTR_MAX - retr_nb_pkts, retr_mbufs);
		if (nb) {
			rte_prefetch0(retr_mbufs[0]);
			node_mbuf_priv1(retr_mbufs[0], dyn)->queue = ctx->queue_id;
			rte_node_enqueue(graph, node, tx_edge, (void **)retr_mbufs, nb);
			retr_nb_pkts += nb;
			goto next_qp;
		}

		can_fetch = APP_RDMA_PTS_DEQ_RTR_MAX - retr_nb_pkts;
		drained = dao_rdma_ack_dequeue_until_read(qp_id, devid, retr_mbufs, can_fetch);
		if (drained) {
			mbuf = retr_mbufs[0];
			if (unlikely(!mbuf))
				break;
			rte_prefetch0(mbuf);
			node_mbuf_priv1(mbuf, dyn)->queue = ctx->queue_id;
			rte_node_enqueue(graph, node, tx_edge, (void **)retr_mbufs, drained);
			retr_nb_pkts += drained;
			goto next_qp;
		}

		count = dao_is_qp_stalled(qp_id, devid);
		if (!count)
			goto next_qp;

		count = RTE_MIN(APP_RDMA_PTS_DEQ_BURST_PER_QP, count);
		count = RTE_MIN(count, max_pkts - nb_pkts);
		count = dao_pts_rdma_dequeue_burst(devid, qp_id, &mbufs[nb_pkts], count);
		if (likely(count)) {
			/* Only annotate first mbuf of this QP run; downstream will read nb_pkts */
			mbuf = mbufs[nb_pkts];
			if (likely(mbuf)) {
				node_mbuf_priv1(mbuf, dyn)->qp_id = qp_id;
				node_mbuf_priv1(mbuf, dyn)->port = mbuf->port;
				node_mbuf_priv1(mbuf, dyn)->queue = ctx->queue_id;
				node_mbuf_priv1(mbuf, dyn)->devid = devid;
				node_mbuf_priv1(mbuf, dyn)->nb_pkts = count;
				/* Prefetch a couple of mbufs in this run to help the next node */
				if (count > 1) {
					rte_prefetch0(mbufs[nb_pkts + 1]);
					if (count > 2)
						rte_prefetch0(mbufs[nb_pkts + 2]);
				}
			} else {
				dao_err("Got NULL mbuf for qp %d devid %d\n", qp_id, devid);
			}

			nb_pkts += count;
		}
	next_qp:
		qp_id = qp_id > max_qp ? min_qp : qp_id + 1;
		qp_count--;
	}
	ctx->next_qp = qp_id;

	if (!nb_pkts)
		return retr_nb_pkts;

	rte_node_enqueue(graph, node, next_index, (void **)mbufs, nb_pkts);

	return nb_pkts + retr_nb_pkts;
}

static __rte_always_inline uint16_t
rdma_pts_deq_node_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t cnt)
{
	rdma_pts_deq_node_ctx_t *ctx = (rdma_pts_deq_node_ctx_t *)node->ctx_ptr;
	uint16_t n_pkts = 0;
	static uint64_t last_tsc;

	RTE_SET_USED(objs);
	RTE_SET_USED(cnt);

	const uint64_t now = rte_get_tsc_cycles();
	const uint64_t interval = (rte_get_tsc_hz() << 12) / 1000000; // every ~4.096 μs

	if (now - last_tsc > interval) {
		rte_timer_manage();
		last_tsc = now;
	}

	n_pkts = rdma_pts_deq_node_process_inline(graph, node, ctx);
	return n_pkts;
}

static int
rdma_pts_deq_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	rdma_pts_deq_node_ctx_t *ctx;

	RTE_SET_USED(graph);

	ctx = (rdma_pts_deq_node_ctx_t *)rte_malloc("rdma_pts_deq_node_ctx",
						    sizeof(rdma_pts_deq_node_ctx_t), 0);
	if (ctx == NULL) {
		dao_err("Failed to allocate dqueue context");
		return -1;
	}

	memset(ctx, 0, sizeof(rdma_pts_deq_node_ctx_t));
	ctx->next_node = EP_PTS_DEQ_NEXT_RDMA;

	ctx->qp_map =
		(rdma_pts_bitmap_t *)rte_zmalloc("rdma_pts_bitmap", sizeof(rdma_pts_bitmap_t), 0);
	if (ctx->qp_map == NULL) {
		dao_err("Failed to allocate dqueue qp_map");
		rte_free(ctx);
		return -1;
	}
	node->ctx_ptr = (void *)ctx;
	return 0;
}

static void
rdma_pts_deq_node_fini(const struct rte_graph *graph, struct rte_node *node)
{
	RTE_SET_USED(graph);

	if (node->ctx_ptr) {
		rdma_pts_deq_node_ctx_t *ctx = (rdma_pts_deq_node_ctx_t *)node->ctx_ptr;

		if (ctx->qp_map)
			rte_free(ctx->qp_map);
		rte_free(node->ctx_ptr);
	}
}

static struct rte_node_register rdma_pts_deq_node_base = {
	.process = rdma_pts_deq_node_process,
	.flags = RTE_NODE_SOURCE_F,
	.name = "rdma_pts_deq",
	.init = rdma_pts_deq_node_init,
	.fini = rdma_pts_deq_node_fini,
	.nb_edges = EP_PTS_DEQ_NEXT_MAX,
	.next_nodes = {
		/* Default rdma node */
		[EP_PTS_DEQ_NEXT_RDMA] = "rdma_pts_process",
	},
};

struct rte_node_register *
rdma_pts_deq_node_get(void)
{
	return &rdma_pts_deq_node_base;
}

RTE_NODE_REGISTER(rdma_pts_deq_node_base);
