/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_GRAPH_NODES_OUTPUT_INTERFACE_OUTPUT_PRIV_H_
#define _APP_SECGW_GRAPH_NODES_OUTPUT_INTERFACE_OUTPUT_PRIV_H_

struct rte_node_register *secgw_interface_out_node_get(void);
int secgw_node_interface_out_attach_tx_node(secgw_device_t *sdev,
					    struct rte_node_register *tx_node);
#endif
