/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __RDMA_ETH_RX_PRIV_H__
#define __RDMA_ETH_RX_PRIV_H__

#include <rte_common.h>
#include <rte_graph.h>

struct rdma_eth_rx_node_elem;
struct rdma_eth_rx_node_ctx;
typedef struct rdma_eth_rx_node_elem rdma_eth_rx_node_elem_t;
typedef struct rdma_eth_rx_node_ctx rdma_eth_rx_node_ctx_t;

/**
 * @internal
 *
 * Ethernet device Rx node context structure.
 */
struct rdma_eth_rx_node_ctx {
	uint16_t port_id;  /**< Port identifier of the Rx node. */
	uint16_t queue_id; /**< Queue identifier of the Rx node. */
	int mbuf_priv1_off;
};

/**
 * @internal
 *
 * Ethernet device Rx node list element structure.
 */
struct rdma_eth_rx_node_elem {
	struct rdma_eth_rx_node_elem *next;
	/**< Pointer to the next Rx node element. */
	struct rdma_eth_rx_node_ctx ctx;
	/**< Rx node context. */
	rte_node_t nid;
	/**< Node identifier of the Rx node. */
};

enum rdma_eth_rx_next_nodes {
	EP_ETH_RX_NEXT_RDMA,
	EP_ETH_RX_NEXT_MAX,
};

/**
 * @internal
 *
 * Ethernet Rx node main structure.
 */
struct rdma_eth_rx_node_main {
	rdma_eth_rx_node_elem_t *head;
	/**< Pointer to the head Rx node element. */
};

/**
 * @internal
 *
 * Get the Ethernet Rx node data.
 *
 * @return
 *   Pointer to Ethernet Rx node data.
 */
struct rdma_eth_rx_node_main *rdma_eth_rx_get_node_data_get(void);

/**
 * @internal
 *
 * Get the Ethernet Rx node.
 *
 * @return
 *   Pointer to the Ethernet Rx node.
 */
struct rte_node_register *rdma_eth_rx_node_get(void);

#endif /* __RDMA_ETH_RX_PRIV_H__ */
