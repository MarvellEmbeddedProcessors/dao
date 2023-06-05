/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <nodes/node_priv.h>

typedef struct {
	secgw_mbuf_devindex_dynfield_t offset;
	uint16_t last_next_index;
} secgw_interface_out_node_ctx_t;

static __rte_always_inline uint16_t
secgw_interface_out_node_process_func(struct rte_graph *graph, struct rte_node *node,
				      void **objs, uint16_t nb_objs)
{
	secgw_interface_out_node_ctx_t *ctx = (secgw_interface_out_node_ctx_t *)node->ctx;
	uint16_t next0, n_left, last_next_index, last_spec = 0, held = 0;
	secgw_mbuf_devindex_dynfield_t *dyn = NULL;
	struct rte_mbuf **bufs, *mbuf0;
	void **from, **to_next;

	last_next_index = ctx->last_next_index;
	bufs = (struct rte_mbuf **)objs;
	from = objs;
	n_left = nb_objs;

	to_next = rte_node_next_stream_get(graph, node, last_next_index, n_left);

	while (n_left > 0) {
		if (n_left > 2)
			rte_prefetch0(bufs[0]);

		mbuf0 = bufs[0];
		dyn = secgw_mbuf_devindex_dynfield(mbuf0, ctx->offset);

		next0 = (uint16_t)*dyn;

		if (unlikely(next0 != last_next_index)) {
			rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;
			dao_dbg("sending %u pkts to node: %u", last_spec + 1, next0);
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
		dao_dbg("sending nb_objs: %u to %d", nb_objs, last_next_index);
		return nb_objs;
	}
	held += last_spec;
	rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
	rte_node_next_stream_put(graph, node, last_next_index, held);

	/* save last_next_index for next iteration */
	ctx->last_next_index = last_next_index;
	dao_dbg("sending nb_objs: %u", nb_objs);

	return nb_objs;
}

static int
secgw_interface_out_node_init_func(const struct rte_graph *graph, struct rte_node *node)
{
	secgw_interface_out_node_ctx_t *sdnc = (secgw_interface_out_node_ctx_t *)node->ctx;

	RTE_SET_USED(graph);
	RTE_SET_USED(node);

	RTE_BUILD_BUG_ON(sizeof(secgw_interface_out_node_ctx_t) > RTE_NODE_CTX_SZ);

	sdnc->offset = secgw_mbuf_devindex_dynfield_offset;
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
