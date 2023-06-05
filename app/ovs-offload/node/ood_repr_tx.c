/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#include <dao_log.h>

#include <ood_node_ctrl.h>

#include "ood_repr_tx_priv.h"

static struct repr_tx_node_main repr_tx_main;

static uint16_t
repr_tx_node_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs)
{
	repr_tx_node_ctx_t *ctx = (repr_tx_node_ctx_t *)node->ctx;
	struct rte_mbuf *mbuf;
	uint16_t port, rep_id;
	uint16_t count, i;

	/* Get Tx port id */
	port = ctx->port_id;
	rep_id = ctx->rep_id;

	dao_dbg("		lcore %d name %s port %d rep_id %d\n\n", rte_lcore_id(), node->name,
		port, rep_id);

	for (i = 0; i < nb_objs; i++) {
		mbuf = (struct rte_mbuf *)objs[i];
		mbuf->ol_flags |= RTE_MBUF_F_TX_VLAN;
		mbuf->vlan_tci = (1 << OOD_ESWITCH_VFPF_SHIFT) | rep_id;
	}

	count = rte_eth_tx_burst(port, OOD_ESWITCH_DEFAULT_QUEUE, (struct rte_mbuf **)objs,
				 nb_objs);

	/* Redirect unsent pkts to drop node */
	if (count != nb_objs) {
		dao_warn("Dropping %d unsent packets out of total %d", count,
			 nb_objs);
		rte_node_enqueue(graph, node, REPR_TX_NEXT_PKT_DROP, &objs[count], nb_objs - count);
	}

	return count;
}

static int
repr_tx_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	repr_tx_node_ctx_t *ctx = (repr_tx_node_ctx_t *)node->ctx;
	ood_repr_tx_node_elem_t *elem = repr_tx_main.head;

	RTE_SET_USED(graph);
	while (elem) {
		if (elem->nid == node->id) {
			/* Update node specific context */
			memcpy(ctx, &elem->ctx, sizeof(repr_tx_node_ctx_t));
			break;
		}
		elem = elem->next;
	}

	RTE_VERIFY(elem != NULL);

	dao_dbg("Representor TX node ID %d port id %d rep id %d", node->id, ctx->port_id,
		ctx->rep_id);

	return 0;
}

struct repr_tx_node_main *
repr_tx_node_data_get(void)
{
	return &repr_tx_main;
}

static struct rte_node_register repr_tx_node_base = {
	.process = repr_tx_node_process,
	.name = "repr_tx",

	.init = repr_tx_node_init,
	.nb_edges = REPR_TX_NEXT_MAX,
	.next_nodes = {
			[REPR_TX_NEXT_PKT_DROP] = "pkt_drop",
	},
};

struct rte_node_register *
repr_tx_node_get(void)
{
	return &repr_tx_node_base;
}

RTE_NODE_REGISTER(repr_tx_node_base);
