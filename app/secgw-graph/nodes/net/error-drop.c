/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <secgw.h>

struct rte_node_register *secgw_errordrop_node_get(void);

static __rte_always_inline uint16_t
secgw_errordrop_node_process_func(struct rte_graph *graph, struct rte_node *node,
				  void **objs, uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);

	rte_pktmbuf_free_bulk((struct rte_mbuf **)objs, nb_objs);
	dao_dbg("freed %u nb_objs", nb_objs);
	return nb_objs;
}

static int
secgw_errordrop_node_init_func(const struct rte_graph *graph, struct rte_node *node)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);

	return 0;
}

static struct rte_node_register secgw_errordrop_node = {
	.process = secgw_errordrop_node_process_func,
	.flags = 0,
	.name = "secgw_error-drop",
	.init = secgw_errordrop_node_init_func,
	.nb_edges = 0,
};

struct rte_node_register *
secgw_errordrop_node_get(void)
{
	return &secgw_errordrop_node;
}

RTE_NODE_REGISTER(secgw_errordrop_node);
