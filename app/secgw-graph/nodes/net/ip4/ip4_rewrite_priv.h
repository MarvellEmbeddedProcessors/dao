/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_GRAPH_NODES_NET_IP4_IP4_REWRITE_PRIV_H_
#define _APP_SECGW_GRAPH_NODES_NET_IP4_IP4_REWRITE_PRIV_H_

#include <rte_common.h>

#define SECGW_GRAPH_IP4_REWRITE_MAX_NH  64
#define SECGW_GRAPH_IP4_REWRITE_MAX_LEN 56

/**
 * @internal
 *
 * Ipv4 rewrite next hop header data structure. Used to store port specific
 * rewrite data.
 */
struct secgw_ip4_rewrite_nh_header {
	uint16_t rewrite_len; /**< Header rewrite length. */
	uint16_t tx_node;     /**< Tx node next index identifier. */
	uint16_t enabled;     /**< NH enable flag */
	uint16_t rsvd;
	union {
		struct {
			struct rte_ether_addr dst;
			/**< Destination mac address. */
			struct rte_ether_addr src;
			/**< Source mac address. */
		};
		uint8_t rewrite_data[SECGW_GRAPH_IP4_REWRITE_MAX_LEN];
		/**< Generic rewrite data */
	};
};

/**
 * @internal
 *
 * Ipv4 node main data structure.
 */
struct secgw_ip4_rewrite_node_main {
	struct secgw_ip4_rewrite_nh_header nh[SECGW_GRAPH_IP4_REWRITE_MAX_NH];
	/**< Array of next hop header data */
	uint16_t next_index[RTE_MAX_ETHPORTS];
	/**< Next index of each configured port. */
};

/**
 * @internal
 *
 * Get the ipv4 rewrite node.
 *
 * @return
 *   Pointer to the ipv4 rewrite node.
 */
struct rte_node_register *secgw_ip4_rewrite_node_get(void);

/**
 * @internal
 *
 * Set the Edge index of a given port_id.
 *
 * @param port_id
 *   Ethernet port identifier.
 * @param next_index
 *   Edge index of the Given Tx node.
 */
int secgw_ip4_rewrite_set_next(uint16_t port_id, uint16_t next_index);

#endif
