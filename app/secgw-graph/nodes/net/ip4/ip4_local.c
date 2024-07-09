/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <arpa/inet.h>
#include <sys/socket.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_fbk_hash.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_jhash.h>
#include <rte_lpm.h>

#include <nodes/net/ip_node_priv.h>

#include <nodes/node_api.h>

typedef struct {
	uint16_t last_next_index;
	dao_graph_feature_arc_t dfl;
} secgw_ip4_local_node_ctx_t;

static int
secgw_ip4_local_node_init_func(const struct rte_graph *graph, struct rte_node *node)
{
	secgw_ip4_local_node_ctx_t *ctx = (secgw_ip4_local_node_ctx_t *)node->ctx;

	RTE_SET_USED(graph);
	RTE_SET_USED(node);

	ctx->last_next_index = 0;
	ctx->dfl = DAO_GRAPH_FEATURE_ARC_INITIALIZER;
	dao_graph_feature_arc_lookup_by_name(IP4_LOCAL_FEATURE_ARC_NAME, &ctx->dfl);
	return 0;
}

static uint16_t
secgw_ip4_local_node_process_scalar(struct rte_graph *graph, struct rte_node *node, void **objs,
				    uint16_t nb_objs)
{
	uint16_t next0, n_left, last_next_index, last_spec = 0, held = 0;
	secgw_ip4_local_node_ctx_t *ctx = (secgw_ip4_local_node_ctx_t *)node->ctx;
	dao_graph_feature_t feature = DAO_GRAPH_FEATURE_INVALID_VALUE;
	rte_edge_t edge = SECGW_NODE_IP4_LOCAL_NEXT_PKT_DROP;
	struct dao_graph_feature_arc *arc = NULL;
	secgw_mbuf_dynfield_t *dyn = NULL;
	struct rte_mbuf **bufs, *mbuf0;
	void **from, **to_next;
	uint32_t rx_port;
	int64_t data;

	last_next_index = ctx->last_next_index;
	bufs = (struct rte_mbuf **)objs;
	from = objs;
	n_left = nb_objs;
	arc = dao_graph_feature_arc_get(ctx->dfl);

	to_next = rte_node_next_stream_get(graph, node, last_next_index, n_left);

	while (n_left > 0) {
		if (n_left > 2)
			rte_prefetch0(bufs[0]);

		mbuf0 = bufs[0];
		dyn = secgw_mbuf_dynfield(mbuf0);
		rx_port = SECGW_INGRESS_PORT(dyn);

		next0 = SECGW_NODE_IP4_LOCAL_NEXT_PKT_DROP;

		if (dao_graph_feature_arc_has_feature(arc, rx_port, &feature)) {
			dao_graph_feature_arc_first_feature_data_get(arc, feature, rx_port, &edge,
								     &data);
			node_debug("ip_local: itf: %u, feature slot : %d enabled at edge: %u",
				   rx_port, feature, edge);
			next0 = edge;
		}

		if (unlikely(next0 != last_next_index)) {
			rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;

			node_debug("ip4-local: sending a pkt to node: %u", next0);
			rte_node_enqueue_x1(graph, node, next0, from[0]);
			from += 1;
		} else {
			last_spec++;
		}
		n_left--;
		bufs++;
	}

	if (likely(last_spec == nb_objs)) {
		if (edge != SECGW_NODE_IP4_LOCAL_NEXT_PKT_DROP)
			last_next_index = edge;

		rte_node_next_stream_move(graph, node, last_next_index);
		node_debug("ip4-local: sending %u pkts to node: %u", nb_objs, last_next_index);
		return nb_objs;
	}
	held += last_spec;
	rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
	rte_node_next_stream_put(graph, node, last_next_index, held);

	/* save last_next_index for next iteration */
	ctx->last_next_index = last_next_index;

	return nb_objs;
}

static struct rte_node_register secgw_ip4_local_node = {
	.process = secgw_ip4_local_node_process_scalar,
	.init = secgw_ip4_local_node_init_func,
	.name = "secgw_ip4-local",

	.nb_edges = SECGW_NODE_IP4_LOCAL_NEXT_PKT_DROP + 1,
	.next_nodes = {
			[SECGW_NODE_IP4_LOCAL_NEXT_PKT_DROP] = "secgw_error-drop",
		},
};

struct rte_node_register *
secgw_ip4_local_node_get(void)
{
	return &secgw_ip4_local_node;
}

RTE_NODE_REGISTER(secgw_ip4_local_node);
