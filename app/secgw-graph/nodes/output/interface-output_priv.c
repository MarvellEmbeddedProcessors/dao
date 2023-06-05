/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <nodes/node_priv.h>

int
secgw_node_interface_out_attach_tx_node(secgw_device_t *sdev, struct rte_node_register *tx_node)
{
	struct rte_node_register *io_node = secgw_interface_out_node_get();
	char node_name[256];
	const char *name = NULL;
	rte_edge_t edge = -1;
	uint32_t node_id;

	if (!tx_node)
		return -1;

	RTE_SET_USED(edge);

	name = node_name;

	snprintf(node_name, sizeof(node_name), "%u", sdev->port_index);

	node_id = rte_node_clone(tx_node->id, node_name);

	if (node_id == RTE_NODE_ID_INVALID) {
		dao_err("Error in cloning tx_node: %s", tx_node->name);
		return -1;
	}
	snprintf(node_name, sizeof(node_name), "%s-%u", tx_node->name, sdev->port_index);

	edge = rte_node_edge_update(io_node->id, RTE_EDGE_ID_INVALID, &name, 1);
	edge = rte_node_edge_count(io_node->id) - 1;

	dao_info("Attaching %s(id:%u) at edge: %u(di: %u) to %s(id: %u)",
		 node_name, node_id, edge, sdev->device_index, io_node->name, io_node->id);

	return 0;
}
