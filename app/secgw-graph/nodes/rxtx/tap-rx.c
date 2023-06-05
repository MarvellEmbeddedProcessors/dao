/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <nodes/node_priv.h>

typedef struct {
	dao_worker_t *worker;
	dao_portq_group_t portq_group;
	secgw_mbuf_devindex_dynfield_t offset;
} secgw_taprx_node_ctx_t;

static __rte_always_inline uint16_t
secgw_taprx_node_process_func(struct rte_graph *graph, struct rte_node *node,
			      void **objs, uint16_t nb_objs)
{
	secgw_taprx_node_ctx_t *senc = (secgw_taprx_node_ctx_t *)node->ctx;
	secgw_mbuf_devindex_dynfield_t *dynfield = NULL;
	uint16_t n_pkts, total_pkts = 0, n;
	secgw_device_t *sdev = NULL;
	dao_portq_t *portq = NULL;
	struct rte_eth_link link;
	struct rte_mbuf **bufs;
	int32_t iter = -1;
	void **to_next;

	RTE_SET_USED(nb_objs);

	/* validate */
	DAO_PORTQ_GROUP_FOREACH_CORE(senc->portq_group, senc->worker->worker_index, portq, iter) {
		if (unlikely(rte_eth_link_get(portq->port_id, &link)))
			continue;

		if (unlikely(link.link_status != RTE_ETH_LINK_UP))
			continue;

		sdev = secgw_get_device(portq->port_id);
		n_pkts = rte_eth_rx_burst(sdev->dp_port_id, portq->rq_id,
					  (struct rte_mbuf **)node->objs,
					  RTE_GRAPH_BURST_SIZE);

		if (!n_pkts)
			continue;

		to_next = rte_node_next_stream_get(graph, node,
						   SECGW_SOURCE_NODE_NEXT_INDEX_PORTMAPPER,
						   n_pkts);

		bufs = (struct rte_mbuf **)node->objs;
		n = n_pkts;

		while (n > 0) {
			if (n > 2)
				rte_prefetch0(bufs[2]);

			/* fill sdev device_index in dynamic field */
			dynfield = secgw_mbuf_devindex_dynfield(bufs[0], senc->offset);
			*dynfield = (secgw_mbuf_devindex_dynfield_t)sdev->device_index;

			n--;
			bufs++;
		}
		total_pkts += n_pkts;
		rte_memcpy(to_next, node->objs, n_pkts * sizeof(objs[0]));

		rte_node_next_stream_put(graph, node,
					 SECGW_SOURCE_NODE_NEXT_INDEX_PORTMAPPER,
					 n_pkts);
		dao_dbg("received %u pkts from %s", n_pkts, sdev->dev_name);
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
	senc->offset = secgw_mbuf_devindex_dynfield_offset;
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
	DAO_PORTQ_GROUP_FOREACH_CORE(senc->portq_group, worker_index, portq, iter) {
		dao_ds_put_format(&pv_str, "[P%d, Q%d], ", portq->port_id, portq->rq_id);
	}
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
		[SECGW_SOURCE_NODE_NEXT_INDEX_ERROR_DROP] = "secgw_error-drop",
		[SECGW_SOURCE_NODE_NEXT_INDEX_PORTMAPPER] = "secgw_portmapper",
		[SECGW_SOURCE_NODE_NEXT_INDEX_IFACE_OUT] = "secgw_interface-output",
	},
};

struct rte_node_register *
secgw_taprx_node_get(void)
{
	return &secgw_taprx_node;
}

RTE_NODE_REGISTER(secgw_taprx_node);
