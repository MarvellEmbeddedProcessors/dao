/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __INCLUDE_EP_ETH_RX_PRIV_H__
#define __INCLUDE_EP_ETH_RX_PRIV_H__

#include <rte_common.h>

struct ood_eth_rx_node_elem;
struct ood_eth_rx_node_ctx;
typedef struct ood_eth_rx_node_elem ood_eth_rx_node_elem_t;
typedef struct ood_eth_rx_node_ctx ood_eth_rx_node_ctx_t;

/**
 * @internal
 *
 * Ethernet device Rx node context structure.
 */
struct ood_eth_rx_node_ctx {
	uint16_t port_id;  /**< Port identifier of the Rx node. */
	uint16_t queue_id; /**< Queue identifier of the Rx node. */
	uint16_t cls_next;
};

/**
 * @internal
 *
 * Ethernet device Rx node list element structure.
 */
struct ood_eth_rx_node_elem {
	struct ood_eth_rx_node_elem *next;
	/**< Pointer to the next Rx node element. */
	struct ood_eth_rx_node_ctx ctx;
	/**< Rx node context. */
	rte_node_t nid;
	/**< Node identifier of the Rx node. */
};

enum ood_eth_rx_next_nodes {
	EP_ETH_RX_NEXT_FLOW_MAPPER,
	EP_ETH_RX_NEXT_MAX,
};

/**
 * @internal
 *
 * Ethernet Rx node main structure.
 */
struct ood_eth_rx_node_main {
	ood_eth_rx_node_elem_t *head;
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
struct ood_eth_rx_node_main *ood_eth_rx_get_node_data_get(void);

/**
 * @internal
 *
 * Get the Ethernet Rx node.
 *
 * @return
 *   Pointer to the Ethernet Rx node.
 */
struct rte_node_register *ood_eth_rx_node_get(void);

#endif /* __INCLUDE_EP_ETH_RX_PRIV_H__ */
