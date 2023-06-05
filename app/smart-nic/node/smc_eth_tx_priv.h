/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __SMC_ETHDEV_TX_PRIV_H__
#define __SMC_ETHDEV_TX_PRIV_H__

struct smc_eth_tx_node_ctx;
typedef struct smc_eth_tx_node_ctx smc_eth_tx_node_ctx_t;

enum smc_eth_tx_next_nodes {
	SMC_ETH_TX_NEXT_PKT_DROP,
	SMC_ETH_TX_NEXT_MAX,
};

/**
 * @internal
 *
 * Ethernet Tx node context structure.
 */
struct smc_eth_tx_node_ctx {
	uint16_t port;  /**< Port identifier of the Ethernet Tx node. */
	uint16_t queue; /**< Queue identifier of the Ethernet Tx node. */
};

/**
 * @internal
 *
 * Ethernet Tx node main structure.
 */
struct smc_eth_tx_node_main {
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
struct smc_eth_tx_node_main *smc_eth_tx_node_data_get(void);

/**
 * @internal
 *
 * Get the Ethernet Tx node.
 *
 * @return
 *   Pointer to the Ethernet Tx node.
 */
struct rte_node_register *smc_eth_tx_node_get(void);
#endif /* __SMC_ETHDEV_TX_PRIV_H__ */
