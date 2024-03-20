/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <nodes/node_api.h>

typedef struct {
	uint16_t last_next_index;
} secgw_interface_out_node_ctx_t;

static __rte_always_inline uint16_t
secgw_interface_out_node_process_func(struct rte_graph *graph, struct rte_node *node, void **objs,
				      uint16_t nb_objs)
{
	secgw_interface_out_node_ctx_t *ctx = (secgw_interface_out_node_ctx_t *)node->ctx;
	uint16_t next0, n_left, last_next_index, last_spec = 0, held = 0;
	secgw_mbuf_dynfield_t *dyn = NULL;
	struct rte_mbuf **bufs, *mbuf;
	void **from, **to_next;

	last_next_index = ctx->last_next_index;
	bufs = (struct rte_mbuf **)objs;
	from = objs;
	n_left = nb_objs;

	to_next = rte_node_next_stream_get(graph, node, last_next_index, n_left);

	while (n_left > 0) {
		if (n_left > 2)
			rte_prefetch0(bufs[0]);

		mbuf = bufs[0];
		dyn = secgw_mbuf_dynfield(mbuf);

		next0 = (uint16_t)SECGW_EGRESS_PORT(dyn);
		secgw_print_mbuf(graph, node, mbuf, -1, NULL, 1, 1);
		if (unlikely(next0 != last_next_index)) {
			rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;
			node_debug("interface-out: sending 1 pkt to %s",
				   secgw_get_device(next0)->dev_name);
			rte_node_enqueue_x1(graph, node, next0, from[0]);
			from += 1;
		} else {
			last_spec++;
		}
		n_left--;
		bufs++;
	}

	if (likely(last_spec == nb_objs)) {
		rte_node_next_stream_move(graph, node, last_next_index);
		node_debug("interface-out: sending %u pkts to %s", nb_objs,
			   secgw_get_device(last_next_index)->dev_name);
		return nb_objs;
	}
	held += last_spec;
	rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
	rte_node_next_stream_put(graph, node, last_next_index, held);

	/* save last_next_index for next iteration */
	ctx->last_next_index = last_next_index;
	node_debug("sending nb_objs: %u", nb_objs);

	return nb_objs;
}

static int
secgw_interface_out_node_init_func(const struct rte_graph *graph, struct rte_node *node)
{
	secgw_interface_out_node_ctx_t *sdnc = (secgw_interface_out_node_ctx_t *)node->ctx;

	RTE_SET_USED(graph);
	RTE_SET_USED(node);

	RTE_BUILD_BUG_ON(sizeof(secgw_interface_out_node_ctx_t) > RTE_NODE_CTX_SZ);

	sdnc->last_next_index = 0;

	return 0;
}

static struct rte_node_register secgw_interface_out_node = {
	.process = secgw_interface_out_node_process_func,
	.flags = 0,
	.name = "secgw_interface-output",
	.init = secgw_interface_out_node_init_func,
	.nb_edges = 0,
};

struct rte_node_register *
secgw_interface_out_node_get(void)
{
	return &secgw_interface_out_node;
}

RTE_NODE_REGISTER(secgw_interface_out_node);
