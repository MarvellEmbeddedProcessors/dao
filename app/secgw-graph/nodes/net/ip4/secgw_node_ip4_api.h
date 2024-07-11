/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_GRAPH_NODES_NET_IP4_RTE_NODE_IP4_API_H_
#define _APP_SECGW_GRAPH_NODES_NET_IP4_RTE_NODE_IP4_API_H_

/**
 * @file rte_node_ip4_api.h
 *
 * @warning
 * @b EXPERIMENTAL:
 * All functions in this file may be changed or removed without prior notice.
 *
 * This API allows to do control path functions of ip4_* nodes
 * like ip4_lookup, ip4_rewrite.
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>
#include <rte_compat.h>

#include <rte_graph.h>

/**
 * IP4 lookup next nodes.
 */
enum secgw_node_ip4_lookup_next {
	SECGW_NODE_IP4_LOOKUP_NEXT_REWRITE,
	/**< Rewrite node. */
	SECGW_NODE_IP4_LOOKUP_NEXT_IP4_LOCAL,
	/** IP Local node. */
	SECGW_NODE_IP4_LOOKUP_NEXT_PKT_DROP,
	/**< Number of next nodes of lookup node. */
};

/**
 * IP4 Local next nodes.
 */
enum secgw_node_ip4_local_next {
	/* SECGW_NODE_IP4_LOCAL_NEXT_UDP4_INPUT, */
	/**< ip4 Local node. */
	SECGW_NODE_IP4_LOCAL_NEXT_PKT_DROP,
	/**< Packet drop node. */
};

/**
 * IP4 reassembly next nodes.
 */
enum secgw_node_ip4_reassembly_next {
	SECGW_NODE_IP4_REASSEMBLY_NEXT_PKT_DROP,
	/**< Packet drop node. */
};

/**
 * Reassembly configure structure.
 * @see secgw_node_ip4_reassembly_configure
 */
struct secgw_node_ip4_reassembly_cfg {
	struct rte_ip_frag_tbl *tbl;
	/**< Reassembly fragmentation table. */
	struct rte_ip_frag_death_row *dr;
	/**< Reassembly deathrow table. */
	rte_node_t node_id;
	/**< Node identifier to configure. */
};

/**
 * Add ipv4 route to lookup table.
 *
 * @param ip
 *   IP address of route to be added.
 * @param depth
 *   Depth of the rule to be added.
 * @param next_hop
 *   Next hop id of the rule result to be added.
 * @param next_node
 *   Next node to redirect traffic to.
 *
 * @return
 *   0 on success, negative otherwise.
 */
int secgw_ip4_route_add(uint32_t ip, uint8_t depth, uint16_t next_hop,
			enum secgw_node_ip4_lookup_next next_node);

/**
 * Add a next hop's rewrite data.
 *
 * @param next_hop
 *   Next hop id to add rewrite data to.
 * @param rewrite_data
 *   Rewrite data.
 * @param rewrite_len
 *   Length of rewrite data.
 * @param dst_port
 *   Destination port to redirect traffic to.
 *
 * @return
 *   0 on success, negative otherwise.
 */
int secgw_ip4_rewrite_add(uint16_t next_hop, uint8_t *rewrite_data, uint8_t rewrite_len,
			  uint16_t dst_port);

#ifdef __cplusplus
}
#endif

#endif
