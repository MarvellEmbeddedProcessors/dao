/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __OOD_REPR_TX_PRIV_H__
#define __OOD_REPR_TX_PRIV_H__

struct repr_tx_node_ctx;
typedef struct repr_tx_node_ctx repr_tx_node_ctx_t;

enum repr_tx_next_nodes {
	REPR_TX_NEXT_PKT_DROP,
	REPR_TX_NEXT_MAX,
};

/**
 * @internal
 *
 * Ethernet Tx node context structure.
 */
struct repr_tx_node_ctx {
	/* Port identifier of the Ethernet Tx node. */
	uint16_t port_id;
	/* Representor identifier of the Ethernet Tx node. */
	uint16_t rep_id;
};

/**
 * @internal
 *
 * Representor device Tx node list element structure.
 */
typedef struct ood_repr_tx_node_elem {
	struct ood_repr_tx_node_elem *next;
	/**< Pointer to the next Rx node element. */
	struct repr_tx_node_ctx ctx;
	/**< Rx node context. */
	rte_node_t nid;
	/**< Node identifier of the Rx node. */
} ood_repr_tx_node_elem_t;
/**
 * @internal
 *
 * Ethernet Tx node main structure.
 */
struct repr_tx_node_main {
	/**< Pointer to the head Rx node element. */
	ood_repr_tx_node_elem_t *head;
	uint32_t nodes[RTE_MAX_ETHPORTS];
	/* repr port ID */
	uint16_t repr_portid;
};

/**
 * @internal
 *
 * Get the Ethernet Tx node data.
 *
 * @return
 *   Pointer to Ethernet Tx node data.
 */
struct repr_tx_node_main *repr_tx_node_data_get(void);

/**
 * @internal
 *
 * Get the Ethernet Tx node.
 *
 * @return
 *   Pointer to the Ethernet Tx node.
 */
struct rte_node_register *repr_tx_node_get(void);

#endif /* __OOD_REPR_TX_PRIV_H__ */
