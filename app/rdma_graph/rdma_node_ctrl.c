/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <stdlib.h>

#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_malloc.h>

#include <dao_log.h>
#include <dao_util.h>

#include "rdma_eth_rx_priv.h"
#include "rdma_eth_tx_priv.h"
#include "rdma_lcore.h"
#include "rdma_node_ctrl.h"
#include "rdma_priv.h"

int
rdma_node_rdma_ctrl(rdma_node_rdma_ctrl_conf_t *conf)
{
	/* Setting up normal forwarding table */
	if (rdma_setup_nrml_fwd_table(conf->host_mac_map, conf->nb_ports) < 0)
		DAO_ERR_GOTO(errno, fail, "Failed to setup normal fwd table");

	/* Setting up RDMA forwarding table */
	if (rdma_setup_rdma_fwd_table(conf->rdma_port_map, conf->nb_ports) < 0)
		DAO_ERR_GOTO(errno, fail, "Failed to setup RDMA fwd table");

	return 0;
fail:
	return errno;
}

int
rdma_node_eth_ctrl(rdma_node_eth_ctrl_conf_t *conf, uint16_t nb_confs, uint16_t nb_graphs)
{
	struct rdma_eth_tx_node_main *tx_node_data;
	uint16_t rx_q_used, port_id, tx_q_used;
	struct rte_node_register *rdma_node;
	struct rte_node_register *rdma_pts_node;
	struct rte_node_register *tx_node;
	char name[RTE_NODE_NAMESIZE];
	struct rte_mempool *mp;
	const char *next_nodes;
	int i, j, rc;
	uint32_t id;

	next_nodes = name;
	rdma_node = rdma_node_get();
	rdma_pts_node = rdma_pts_node_get();
	tx_node_data = rdma_eth_tx_node_data_get();
	tx_node = rdma_eth_tx_node_get();
	for (i = 0; i < nb_confs; i++) {
		port_id = conf[i].port_id;

		if (!rte_eth_dev_is_valid_port(port_id))
			return -EINVAL;

		/* Check for mbuf minimum private size requirement */
		for (j = 0; j < conf[i].mp_count; j++) {
			mp = conf[i].mp[j];
			if (!mp)
				continue;
			/* Check for minimum private space */
			if (rte_pktmbuf_priv_size(mp) < NODE_MBUF_PRIV2_SIZE) {
				dao_err("Minimum mbuf priv size requirement not met by mp %s",
					mp->name);
				return -EINVAL;
			}
		}

		rx_q_used = conf[i].num_rx_queues;
		tx_q_used = conf[i].num_tx_queues;
		/* Check if we have a txq for each worker */
		if (tx_q_used < nb_graphs)
			return -EINVAL;

		/* Create node for each rx port queue pair */
		for (j = 0; j < rx_q_used; j++) {
			struct rdma_eth_rx_node_main *rx_node_data;
			struct rte_node_register *rx_node;
			rdma_eth_rx_node_elem_t *elem;

			rx_node_data = rdma_eth_rx_get_node_data_get();
			rx_node = rdma_eth_rx_node_get();
			snprintf(name, sizeof(name), "%u-%u", port_id, j);
			/* Clone a new rx node with same edges as parent */
			id = rte_node_clone(rx_node->id, name);

			if (id == RTE_NODE_ID_INVALID)
				return -EIO;

			/* Add it to list of nic rx nodes for lookup */
			elem = malloc(sizeof(rdma_eth_rx_node_elem_t));
			if (elem == NULL)
				return -ENOMEM;
			memset(elem, 0, sizeof(rdma_eth_rx_node_elem_t));
			elem->ctx.port_id = port_id;
			elem->ctx.queue_id = j;
			elem->nid = id;
			elem->next = rx_node_data->head;
			rx_node_data->head = elem;

			dao_dbg("Rx node %s-%s: is at %u", rx_node->name, name, id);
		}

		/* Create a per port tx node from base node */
		snprintf(name, sizeof(name), "%u", port_id);
		/* Clone a new node with same edges as parent */
		id = rte_node_clone(tx_node->id, name);
		tx_node_data->nodes[port_id] = id;

		dao_dbg("Tx node %s-%s: is at %u", tx_node->name, name, id);

		/* Prepare the actual name of the cloned node */
		snprintf(name, sizeof(name), "rdma_eth_tx-%u", port_id);

		/* Add this tx port node as next to both rdma nodes to keep edge order identical */
		rte_node_edge_update(rdma_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
		rte_node_edge_update(rdma_pts_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
		/* Use the PTS-process node edge index to program mapping used by PTS path */
		rc = rdma_set_eth_tx_edge_idx(port_id, rte_node_edge_count(rdma_pts_node->id) - 1);
		dao_dbg("Setting eth_tx_edge[%d] = %d (from PTS node) for %s", port_id,
			rte_node_edge_count(rdma_pts_node->id) - 1, name);
		if (rc < 0)
			return rc;
	}

	return 0;
}
