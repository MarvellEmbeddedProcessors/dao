/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_graph.h>

#include "vc_node.h"
#include "vc_offload.h"

static __rte_always_inline uint16_t
vc_node_drop_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t cnt)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(objs);
	return cnt;
}

static struct rte_node_register vc_drop_node_base = {
	.process = vc_node_drop_process,
	.name = "cop_drop",

	.init = NULL,
	.fini = NULL,

	.nb_edges = 0,
};

struct rte_node_register *
vc_drop_node_get(void)
{
	return &vc_drop_node_base;
}

RTE_NODE_REGISTER(vc_drop_node_base);
