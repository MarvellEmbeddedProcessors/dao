/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <rte_graph.h>
#include <rte_graph_worker.h>

#include <secgw_worker.h>

#include <nodes/net/classifier/pkt_cls_priv.h>
#include <nodes/net/ip_node_priv.h>
#include <nodes/node_api.h>

/* Next node for each ptype, default is '0' is "pkt_drop" */
static const uint8_t p_nxt[4096] __rte_cache_aligned = {
	[RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_UDP] = PKT_CLS_NEXT_IP4_LOOKUP,

	[RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_ICMP] = PKT_CLS_NEXT_IP4_LOOKUP,

	[RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP] = PKT_CLS_NEXT_IP4_LOOKUP,
};

struct rte_node_register *pkt_classifier_node_get(void);

static uint16_t
pkt_cls_node_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs)
{
	uint16_t next_index, n_left_from, next;
	uint16_t held = 0, last_spec = 0;
	struct rte_mbuf *mbuf0, **pkts;
	struct pkt_cls_node_ctx *ctx;
	void **to_next, **from;
	uint16_t l0, last_type;
	uint32_t i;

	pkts = (struct rte_mbuf **)objs;
	from = objs;
	n_left_from = nb_objs;

	for (i = SECGW_OBJS_PER_CLINE; i < RTE_GRAPH_BURST_SIZE; i += SECGW_OBJS_PER_CLINE)
		rte_prefetch0(&objs[i]);

#if RTE_GRAPH_BURST_SIZE > 64
	for (i = 0; i < 4 && i < n_left_from; i++)
		rte_prefetch0(pkts[i]);
#endif

	ctx = (struct pkt_cls_node_ctx *)node->ctx;
	last_type = ctx->l2l3_type;
	next_index = p_nxt[last_type];

	/* Get stream for the speculated next node */
	to_next = rte_node_next_stream_get(graph, node, next_index, nb_objs);

	while (n_left_from > 0) {
		mbuf0 = pkts[0];

		pkts += 1;
		n_left_from -= 1;

		l0 = mbuf0->packet_type &
		     (RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK | RTE_PTYPE_L4_MASK);
		next = p_nxt[l0];
		if (unlikely((l0 != last_type) && (next != next_index))) {
			/* Copy things successfully speculated till now */
			rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;
			node_debug("classified pkt_type: 0x%x to %s", l0,
				   pkt_classifier_node_get()->next_nodes[next]);

			rte_node_enqueue_x1(graph, node, next, from[0]);
			from += 1;
		} else {
			node_debug("classified pkt_type: 0x%x to %s", l0,
				   pkt_classifier_node_get()->next_nodes[next_index]);
			last_spec += 1;
		}
	}

	/* !!! Home run !!! */
	if (likely(last_spec == nb_objs)) {
		rte_node_next_stream_move(graph, node, next_index);
		return nb_objs;
	}

	held += last_spec;
	/* Copy things successfully speculated till now */
	rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
	rte_node_next_stream_put(graph, node, next_index, held);

	ctx->l2l3_type = last_type;
	return nb_objs;
}

/* Packet Classification Node */
struct rte_node_register pkt_cls_node = {
	.process = pkt_cls_node_process,
	.name = "secgw_pkt-cls",
	.nb_edges = PKT_CLS_NEXT_MAX,
	.next_nodes = {
			/* Port-mapper node starts at '0' */
			[PKT_CLS_NEXT_PKT_DROP] = "secgw_port-mapper",
			[PKT_CLS_NEXT_IP4_LOOKUP] = "secgw_ip4-lookup",
			/* TODO: IPv6 not yet supported */
			[PKT_CLS_NEXT_IP6_LOOKUP] = "secgw_error-drop",
		},
};

struct rte_node_register *
pkt_classifier_node_get(void)
{
	return &pkt_cls_node;
}

RTE_NODE_REGISTER(pkt_cls_node);
