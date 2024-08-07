/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <nodes/rxtx/rxtx_node_priv.h>

typedef struct {
	dao_worker_t *worker;
	dao_portq_group_t portq_group;
} secgw_taprx_node_ctx_t;

static __rte_always_inline uint16_t
secgw_taprx_node_process_func(struct rte_graph *graph, struct rte_node *node, void **objs,
			      uint16_t nb_objs)
{
	secgw_taprx_node_ctx_t *senc = (secgw_taprx_node_ctx_t *)node->ctx;
	uint16_t n_pkts, total_pkts = 0, n;
	dao_portq_t *portq = NULL;
	struct rte_mbuf **bufs;
	int32_t iter = -1;
	void **to_next;

	RTE_SET_USED(nb_objs);

	/* validate */
	DAO_PORTQ_GROUP_FOREACH_CORE(senc->portq_group, senc->worker->worker_index, portq, iter)
	{
		n_pkts = rte_eth_rx_burst(portq->port_id, portq->rq_id,
					  (struct rte_mbuf **)node->objs, RTE_GRAPH_BURST_SIZE);

		if (!n_pkts)
			continue;

		to_next = rte_node_next_stream_get(graph, node,
						   SECGW_SOURCE_NODE_NEXT_INDEX_PORTMAPPER, n_pkts);

		bufs = (struct rte_mbuf **)node->objs;
		n = n_pkts;

		while (n > 0) {
			if (n > 2)
				rte_prefetch0(bufs[2]);

			SECGW_MBUF_INGRESS_PORT(bufs[0]) = portq->port_id;
			SECGW_MBUF_FEATURE(bufs[0]) = DAO_GRAPH_FEATURE_INVALID_VALUE;
			n--;
			bufs++;
		}
		total_pkts += n_pkts;

		rte_memcpy(to_next, node->objs, n_pkts * sizeof(objs[0]));

		rte_node_next_stream_put(graph, node, SECGW_SOURCE_NODE_NEXT_INDEX_PORTMAPPER,
					 n_pkts);
		node_debug("tap-rx: %s received %u pkts",
			   (secgw_get_device(portq->port_id))->dev_name, n_pkts);
	}

	return total_pkts;
}

static int
secgw_taprx_node_init_func(const struct rte_graph *graph, struct rte_node *node)
{
	secgw_taprx_node_ctx_t *senc = (secgw_taprx_node_ctx_t *)node->ctx;
	struct dao_ds pv_str = DS_EMPTY_INITIALIZER;
	dao_portq_t *portq = NULL;
	uint32_t worker_index;
	int32_t iter = -1;

	RTE_SET_USED(graph);
	RTE_SET_USED(node);

	RTE_BUILD_BUG_ON(sizeof(secgw_taprx_node_ctx_t) > RTE_NODE_CTX_SZ);

	senc->worker = dao_workers_self_worker_get();
	if (!senc->worker) {
		dao_err("lcore-%d: secgw_get_worker_on_wrkr failed", rte_lcore_id());
		return -1;
	}
	if (dao_portq_group_get_by_name(SECGW_TAP_PORT_GROUP_NAME, &senc->portq_group) < 0) {
		dao_err("Error from dao_portq_group_get_by_name(%s)", SECGW_TAP_PORT_GROUP_NAME);
		return -1;
	}
	/* validate */
	worker_index = dao_workers_worker_index_get(senc->worker);
	dao_ds_put_format(&pv_str, "W%u: Tap-rx-node Polling Vector: ", worker_index);

	DAO_PORTQ_GROUP_FOREACH_CORE(senc->portq_group, worker_index, portq, iter)
	dao_ds_put_format(&pv_str, "[P%d, Q%d], ", portq->port_id, portq->rq_id);

	dao_info("%s", dao_ds_cstr(&pv_str));
	dao_ds_destroy(&pv_str);

	return 0;
}

static struct rte_node_register secgw_taprx_node = {
	.process = secgw_taprx_node_process_func,
	.flags = RTE_NODE_SOURCE_F,
	.name = "secgw_taprx-rx",
	.init = secgw_taprx_node_init_func,
	.nb_edges = SECGW_SOURCE_NODE_MAX_NEXT_INDEX,
	.next_nodes = {
			[SECGW_SOURCE_NODE_NEXT_INDEX_PKT_CLS] = "secgw_pkt-cls",
			[SECGW_SOURCE_NODE_NEXT_INDEX_PORTMAPPER] = "secgw_port-mapper",
		},
};

struct rte_node_register *
secgw_taprx_node_get(void)
{
	return &secgw_taprx_node;
}

RTE_NODE_REGISTER(secgw_taprx_node);
