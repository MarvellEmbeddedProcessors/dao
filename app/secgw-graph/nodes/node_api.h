/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_GRAPH_NODES_NODE_PRIV_H_
#define _APP_SECGW_GRAPH_NODES_NODE_PRIV_H_

#include <secgw_worker.h>
#include <nodes/net/ip_api.h>
#include <nodes/output/interface-output_priv.h>
#include <nodes/rxtx/rxtx_node_priv.h>

struct rte_node_register *secgw_portmapper_node_get(void);
struct rte_node_register *secgw_errordrop_node_get(void);
struct rte_node_register *secgw_interface_out_node_get(void);
#endif
