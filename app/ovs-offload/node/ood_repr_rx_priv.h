/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __OOD_REPR_RX_PRIV_H__
#define __OOD_REPR_RX_PRIV_H__

#include <rte_common.h>

/**
 * @internal
 *
 * Ethernet device Rx node context structure.
 */
typedef struct repr_rx_node_ctx {
	/* Port identifier of the Rx node. */
	uint16_t port_id;
	/* No of Representors */
	uint16_t nb_repr;
	/* Dynamic offset to mbuf priv1 */
	int mbuf_priv1_off;
} repr_rx_node_ctx_t;

enum repr_rx_next_nodes {
	REPR_RX_NEXT_PKT_DROP,
	REPR_RX_NEXT_FLOW_MAPPER,
	REPR_RX_NEXT_MAX,
};

/**
 * @internal
 *
 * Ethernet Rx node main structure.
 */
struct repr_rx_node_main {
	/* Node identifier of the Rx node. */
	rte_node_t nid;
	/* Port identifier of the repr port. */
	uint16_t repr_portid;
	/* No of Representors */
	uint16_t nb_repr;
};

/**
 * @internal
 *
 * Get the Ethernet Rx node data.
 *
 * @return
 *   Pointer to Ethernet Rx node data.
 */
struct repr_rx_node_main *repr_rx_get_node_data_get(void);

/**
 * @internal
 *
 * Get the Ethernet Rx node.
 *
 * @return
 *   Pointer to the Ethernet Rx node.
 */
struct rte_node_register *repr_rx_node_get(void);

#endif /* __OOD_REPR_RX_PRIV_H__ */
