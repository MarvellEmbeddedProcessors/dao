/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <nodes/rxtx/rxtx_node_priv.h>

typedef struct {
	dao_worker_t *worker;
} secgw_ethdev_tx_node_ctx_t;

static __rte_always_inline uint16_t
secgw_ethdevtx_node_process_func(struct rte_graph *graph, struct rte_node *node,
				 void **objs, uint16_t nb_objs)
{
	secgw_ethdev_tx_node_ctx_t *ctx = (secgw_ethdev_tx_node_ctx_t *)node->ctx;
	secgw_mbuf_dynfield_t *dyn = NULL;
	struct rte_mbuf **bufs;
	uint32_t tx_port;
	uint16_t n_tx;

	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	bufs = (struct rte_mbuf **)objs;

	dyn = secgw_mbuf_dynfield(bufs[0]);
	tx_port = SECGW_EGRESS_PORT(dyn);

	n_tx = rte_eth_tx_burst(tx_port, ctx->worker->worker_index, bufs, nb_objs);

	if (unlikely(n_tx != nb_objs)) {
		rte_node_enqueue(graph, node, 0 /*error-drop node */, &objs[n_tx],
				 nb_objs - n_tx);
		rte_node_next_stream_put(graph, node, 0, nb_objs - n_tx);
		dao_err("ethdev-tx: Failure %u pkts NOT transmitted to %s", nb_objs - n_tx,
			secgw_get_device(tx_port)->dev_name);
	} else {
		node_debug("ethdev-tx: %u pkts transmitted to %s", n_tx,
			   (secgw_get_device(tx_port))->dev_name);
	}
	return n_tx;
}

static int
secgw_ethdevtx_node_init_func(const struct rte_graph *graph, struct rte_node *node)
{
	secgw_ethdev_tx_node_ctx_t *ctx = (secgw_ethdev_tx_node_ctx_t *)node->ctx;

	RTE_SET_USED(graph);
	RTE_SET_USED(node);

	ctx->worker = dao_workers_self_worker_get();

	if (!ctx->worker) {
		dao_err("lcore-%d: dao_workers_self_worker_get()", rte_lcore_id());
		return -1;
	}

	return 0;
}

static struct rte_node_register secgw_ethdevtx_node = {
	.process = secgw_ethdevtx_node_process_func,
	.flags = 0,
	.name = "ethdev-tx",
	.init = secgw_ethdevtx_node_init_func,
	.nb_edges = 1,
	.next_nodes = {
		[0] = "secgw_error-drop",
	},
};

struct rte_node_register *
secgw_ethdevtx_node_get(void)
{
	return &secgw_ethdevtx_node;
}

RTE_NODE_REGISTER(secgw_ethdevtx_node);
