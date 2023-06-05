/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <nodes/node_priv.h>

typedef struct {
	dao_worker_t *worker;
	secgw_mbuf_devindex_dynfield_t offset;
} secgw_tap_tx_node_ctx_t;

static __rte_always_inline uint16_t
secgw_taptx_node_process_func(struct rte_graph *graph, struct rte_node *node,
			      void **objs, uint16_t nb_objs)
{
	secgw_tap_tx_node_ctx_t *ctx = (secgw_tap_tx_node_ctx_t *)node->ctx;
	secgw_mbuf_devindex_dynfield_t *dyn = NULL;
	secgw_device_t *sdev = NULL;
	struct rte_mbuf **bufs;
	uint16_t n_tx;

	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	bufs = (struct rte_mbuf **)objs;

	dyn = secgw_mbuf_devindex_dynfield(bufs[0], ctx->offset);
	sdev = secgw_get_device(*dyn);

	n_tx = rte_eth_tx_burst(sdev->dp_port_id, 0 /* queue-0 */, bufs, nb_objs);

	if (unlikely(n_tx != nb_objs)) {
		rte_node_enqueue(graph, node, 0 /*error-drop node */, &objs[n_tx],
				 nb_objs - n_tx);
		rte_node_next_stream_put(graph, node, 0, nb_objs - n_tx);
		dao_err("%u pkts are NOT transmitted to %s", nb_objs - n_tx, sdev->dev_name);
	} else {
		dao_dbg("%u pkts transmitted to %s", n_tx, sdev->dev_name);
	}
	return n_tx;
}

static int
secgw_taptx_node_init_func(const struct rte_graph *graph, struct rte_node *node)
{
	secgw_tap_tx_node_ctx_t *ctx = (secgw_tap_tx_node_ctx_t *)node->ctx;

	RTE_SET_USED(graph);
	RTE_SET_USED(node);

	ctx->worker = dao_workers_self_worker_get();

	if (!ctx->worker) {
		dao_err("lcore-%d: dao_workers_self_worker_get() failed", rte_lcore_id());
		return -1;
	}
	ctx->offset = secgw_mbuf_devindex_dynfield_offset;

	return 0;
}

static struct rte_node_register secgw_taptx_node = {
	.process = secgw_taptx_node_process_func,
	.flags = 0,
	.name = "tap-tx",
	.init = secgw_taptx_node_init_func,
	.nb_edges = 1,
	.next_nodes = {
		[0] = "secgw_error-drop",
	}
};

struct rte_node_register *
secgw_taptx_node_get(void)
{
	return &secgw_taptx_node;
}

RTE_NODE_REGISTER(secgw_taptx_node);
