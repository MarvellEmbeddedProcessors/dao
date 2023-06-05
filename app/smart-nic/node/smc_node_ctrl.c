/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <stdlib.h>

#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker_common.h>
#include <rte_malloc.h>

#include <smc_init.h>
#include <smc_node_ctrl.h>

#include "smc_eth_rx_priv.h"
#include "smc_eth_tx_priv.h"

#define MAX_ETHDEV_RX_PER_LCORE 128

struct eth_rx_node {
	uint16_t portid;
	uint16_t queueid;
	char node_name[RTE_NODE_NAMESIZE];
	struct rte_node *node;
};

struct smc_graph_conf {
	uint16_t nb_eth_rx_node;
	struct eth_rx_node rx_node[MAX_ETHDEV_RX_PER_LCORE];
	bool valid;
	struct lcore_conf *qconf;
};

typedef struct smc_node_ctrl {
	struct smc_graph_conf graph_conf[RTE_MAX_LCORE];
	uint16_t nb_graphs;
} smc_node_ctrl_t;

smc_node_ctrl_t *node_ctrl_cmn;

static int
eth_rx_tx_edge(smc_graph_param_t *graph_prm)
{
	const char *next_nodes;
	rte_node_t rx_id;
	int i, j;

	for (i = 0; i < graph_prm->nb_eth_rx_node; i++) {
		for (j = 0; j < graph_prm->nb_eth_tx_node; j++) {
			rx_id = rte_node_from_name(graph_prm->eth_rx_node[i].node_name);
			if (rte_node_is_invalid(rx_id)) {
				DAO_ERR_GOTO(-EINVAL, fail, "Invalid node id retrieved %s",
					     graph_prm->eth_rx_node[i].node_name);
			}

			next_nodes = graph_prm->eth_tx_node[j].node_name;
			rte_node_edge_update(rx_id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
		}
	}
	return 0;
fail:
	return errno;
}

int
smc_node_eth_ctrl(smc_graph_param_t *graph_prm)
{
	struct smc_eth_tx_node_main *tx_node_data;
	struct smc_eth_rx_node_main *rx_node_data;
	struct rte_node_register *tx_node;
	struct rte_node_register *rx_node;
	smc_eth_rx_node_elem_t *elem;
	char name[RTE_NODE_NAMESIZE];
	uint16_t portid;
	uint32_t id;

	tx_node_data = smc_eth_tx_node_data_get();
	rx_node_data = smc_eth_rx_node_data_get();
	tx_node = smc_eth_tx_node_get();
	rx_node = smc_eth_rx_node_get();

	RTE_ETH_FOREACH_DEV(portid) {
		if ((enabled_port_mask & (1 << portid)) == 0)
			continue;

		/* Create a per port tx node from base node */
		snprintf(name, sizeof(name), "%u", portid);
		/* Clone a new node with same edges as parent */
		id = rte_node_clone(rx_node->id, name);
		if (id == RTE_NODE_ID_INVALID)
			return -EIO;

		/* Add it to list of nic rx nodes for lookup */
		elem = malloc(sizeof(smc_eth_rx_node_elem_t));
		if (elem == NULL)
			return -ENOMEM;

		memset(elem, 0, sizeof(smc_eth_rx_node_elem_t));
		memset(&elem->ctx, 0, sizeof(struct smc_eth_rx_node_ctx));
		elem->ctx.port = portid;
		elem->nid = id;
		elem->next = rx_node_data->head;
		rx_node_data->head = elem;

		dao_info("Rx node %s-%s: is at %u", rx_node->name, name, id);

		/* Prepare the actual name of the cloned node */
		snprintf(name, sizeof(name), "smc_eth_rx-%u", portid);

		strncpy(graph_prm->eth_rx_node[graph_prm->nb_eth_rx_node].node_name, name,
			sizeof(name));
		graph_prm->eth_rx_node[graph_prm->nb_eth_rx_node].portid = portid;
		graph_prm->nb_eth_rx_node++;

		/* Create a per port tx node from base node */
		snprintf(name, sizeof(name), "%u", portid);
		/* Clone a new node with same edges as parent */
		id = rte_node_clone(tx_node->id, name);
		tx_node_data->nodes[portid] = id;

		dao_info("Tx node %s-%s: is at %u", tx_node->name, name, id);

		/* Prepare the actual name of the cloned node */
		snprintf(name, sizeof(name), "smc_eth_tx-%u", portid);

		strncpy(graph_prm->eth_tx_node[graph_prm->nb_eth_tx_node].node_name, name,
			sizeof(name));
		graph_prm->eth_tx_node[graph_prm->nb_eth_tx_node].portid = portid;
		graph_prm->nb_eth_tx_node++;
	}

	/* Make every TX node edge to RX node */
	return eth_rx_tx_edge(graph_prm);
}

int
smc_node_ctrl_init(void)
{
	node_ctrl_cmn = rte_zmalloc("node ctrl cmn", sizeof(smc_node_ctrl_t), RTE_CACHE_LINE_SIZE);
	if (!node_ctrl_cmn)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory for node_ctrl_cmn");
	return 0;
fail:
	return errno;
}

int
smc_node_context_save(struct lcore_conf *qconf)
{
	uint16_t graph = node_ctrl_cmn->nb_graphs;
	struct rte_node *node = NULL;
	int i;

	for (i = 0; i < qconf->n_rx_queue; i++) {
		node = rte_graph_node_get_by_name(qconf->name, qconf->rx_queue_list[i].node_name);
		if (rte_node_is_invalid(rte_node_from_name(node->name)))
			DAO_ERR_GOTO(-EINVAL, fail, "Failed to get valid node for %s in graph %s",
				     qconf->rx_queue_list[i].node_name, qconf->name);
		node_ctrl_cmn->graph_conf[graph].rx_node[i].node = node;
		node_ctrl_cmn->graph_conf[graph].rx_node[i].portid =
			qconf->rx_queue_list[i].port_id;
		node_ctrl_cmn->graph_conf[graph].rx_node[i].queueid =
			qconf->rx_queue_list[i].queue_id;
		strncpy(node_ctrl_cmn->graph_conf[graph].rx_node[i].node_name,
			qconf->rx_queue_list[i].node_name, RTE_NODE_NAMESIZE);
		node_ctrl_cmn->graph_conf[graph].nb_eth_rx_node++;
	}
	node_ctrl_cmn->graph_conf[graph].qconf = qconf;
	node_ctrl_cmn->graph_conf[graph].valid = true;
	node_ctrl_cmn->nb_graphs++;

	return 0;
fail:
	return errno;
}

int
smc_node_link_unlink_ports(uint16_t rx_port, uint16_t tx_port, bool link)
{
	struct eth_rx_node *rx_node = NULL;
	char tx_name[RTE_NODE_NAMESIZE];
	int i, j, rc = -EINVAL;

	for (i = 0; i < node_ctrl_cmn->nb_graphs; i++) {
		for (j = 0; j < node_ctrl_cmn->graph_conf[i].nb_eth_rx_node; j++) {
			if (node_ctrl_cmn->graph_conf[i].rx_node[j].portid == rx_port) {
				rx_node = &node_ctrl_cmn->graph_conf[i].rx_node[j];
				break;
			}
		}
		if (rx_node)
			break;
	}

	if (rx_node) {
		snprintf(tx_name, sizeof(tx_name), "smc_eth_tx-%u", tx_port);
		rc = smc_eth_rx_next_update(rx_node->node, tx_name, link);
		if (rc)
			DAO_ERR_GOTO(rc, fail, "Failed to update link between %s <--> %s",
				     rx_node->node_name, tx_name);
	}

fail:
	return rc;
}

int
smc_node_add_del_port(uint16_t portid, bool enable)
{
	struct eth_rx_node *rx_node = NULL;
	char tx_name[RTE_NODE_NAMESIZE];
	int i, j, rc = -EINVAL;
	uint64_t q_map;

	q_map = enable ? 0 : UINT64_MAX;
	for (i = 0; i < node_ctrl_cmn->nb_graphs; i++) {
		for (j = 0; j < node_ctrl_cmn->graph_conf[i].nb_eth_rx_node; j++) {
			if (node_ctrl_cmn->graph_conf[i].rx_node[j].portid == portid) {
				rx_node = &node_ctrl_cmn->graph_conf[i].rx_node[j];
				if (enable)
					q_map |= RTE_BIT64(rx_node->queueid);
				else
					q_map &= ~RTE_BIT64(rx_node->queueid);
			}
		}
		if (!rx_node)
			continue;

		rc = smc_eth_rx_q_map_update(rx_node->node, q_map, enable);
		if (rc)
			DAO_ERR_GOTO(rc, fail, "Failed to update link between %s <--> %s",
				     rx_node->node_name, tx_name);
		rx_node = NULL;
	}

fail:
	return rc;
}
