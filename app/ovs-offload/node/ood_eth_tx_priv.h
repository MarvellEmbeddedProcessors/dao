/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __INCLUDE_EP_ETH_TX_PRIV_H__
#define __INCLUDE_EP_ETH_TX_PRIV_H__

struct ood_eth_tx_node_ctx;
typedef struct ood_eth_tx_node_ctx ood_eth_tx_node_ctx_t;

enum ood_eth_tx_next_nodes {
	EP_ETH_TX_NEXT_PKT_DROP,
	EP_ETH_TX_NEXT_MAX,
};

/**
 * @internal
 *
 * Ethernet Tx node context structure.
 */
struct ood_eth_tx_node_ctx {
	uint16_t port;  /**< Port identifier of the Ethernet Tx node. */
	uint16_t queue; /**< Queue identifier of the Ethernet Tx node. */
};

/**
 * @internal
 *
 * Ethernet Tx node main structure.
 */
struct ood_eth_tx_node_main {
	uint32_t nodes[RTE_MAX_ETHPORTS]; /**< Tx nodes for each nic port. */
};

/**
 * @internal
 *
 * Get the Ethernet Tx node data.
 *
 * @return
 *   Pointer to Ethernet Tx node data.
 */
struct ood_eth_tx_node_main *ood_eth_tx_node_data_get(void);

/**
 * @internal
 *
 * Get the Ethernet Tx node.
 *
 * @return
 *   Pointer to the Ethernet Tx node.
 */
struct rte_node_register *ood_eth_tx_node_get(void);

#endif /* __INCLUDE_EP_ETH_TX_PRIV_H__ */
