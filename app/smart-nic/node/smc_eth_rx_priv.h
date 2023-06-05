/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __SMC_ETH_RX_PRIV_H__
#define __SMC_ETH_RX_PRIV_H__

struct smc_eth_rx_node_ctx;
typedef struct smc_eth_rx_node_ctx smc_eth_rx_node_ctx_t;

enum smc_eth_rx_next_nodes {
	SMC_ETH_RX_NEXT_PKT_DROP,
	SMC_ETH_RX_NEXT_MAX,
};

/**
 * @internal
 *
 * Ethernet Tx node context structure.
 */
struct smc_eth_rx_node_ctx {
	uint16_t port; /**< Port identifier of the Ethernet Rx node. */
	uint16_t next;
	uint16_t rx_q_count;
	uint16_t next_q;
	uint64_t rx_q_map;
};

/**
 * @internal
 *
 * Ethernet device Rx node list element structure.
 */
typedef struct smc_eth_rx_node_elem {
	struct smc_eth_rx_node_elem *next;
	/**< Pointer to the next Rx node element. */
	struct smc_eth_rx_node_ctx ctx;
	/**< Rx node context. */
	rte_node_t nid;
	/**< Node identifier of the Rx node. */
} smc_eth_rx_node_elem_t;

/**
 * @internal
 *
 * Ethernet Rx node main structure.
 */
struct smc_eth_rx_node_main {
	smc_eth_rx_node_elem_t *head;
	/**< Pointer to the head Rx node element. */
};

/**
 * @internal
 *
 * Get the Ethernet Tx node data.
 *
 * @return
 *   Pointer to Ethernet Tx node data.
 */
struct smc_eth_rx_node_main *smc_eth_rx_node_data_get(void);

/**
 * @internal
 *
 * Get the Ethernet Tx node.
 *
 * @return
 *   Pointer to the Ethernet Tx node.
 */
struct rte_node_register *smc_eth_rx_node_get(void);
int smc_eth_rx_next_update(struct rte_node *node, const char *edge_name, bool link);
int smc_eth_rx_q_map_update(struct rte_node *node, uint64_t q_map, bool enable);
#endif /* __SMC_ETH_RX_PRIV_H__ */
