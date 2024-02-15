/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_GRAPH_NODES_NET_IP4_IP4_LOOKUP_PRIV_H_
#define _APP_SECGW_GRAPH_NODES_NET_IP4_IP4_LOOKUP_PRIV_H_

/**
 * @internal
 *
 * Get the ipv4 lookup node.
 *
 * @return
 *   Pointer to the ipv4 lookup node.
 */
struct rte_node_register *ip4_lookup_node_get(void);

#endif /* __INCLUDE_DOS_IP4_LOOKUP_PRIV_H__ */
