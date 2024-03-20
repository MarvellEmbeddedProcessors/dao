/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <nodes/node_api.h>

struct rte_node_register *secgw_errordrop_node_get(void);

static __rte_always_inline uint16_t
secgw_errordrop_node_process_func(struct rte_graph *graph, struct rte_node *node, void **objs,
				  uint16_t nb_objs)
{
#ifdef SECGW_DEBUG_PKT_TRACE
	struct rte_mbuf *mbuf = NULL;
	uint16_t n_left = 0;
#endif
	uint32_t rx_port;

	RTE_SET_USED(graph);
	RTE_SET_USED(node);
#ifdef SECGW_DEBUG_PKT_TRACE
	while (n_left < nb_objs) {
		mbuf = (struct rte_mbuf *)objs[n_left++];
		secgw_print_mbuf(graph, node, mbuf, -1, NULL, 0, 1);
	}
#endif

	rx_port = SECGW_INGRESS_PORT(secgw_mbuf_dynfield((struct rte_mbuf *)objs[0]));
	rte_pktmbuf_free_bulk((struct rte_mbuf **)objs, nb_objs);
	node_debug("%s: freed %u nb_objs", secgw_get_device(rx_port)->dev_name, nb_objs);
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
