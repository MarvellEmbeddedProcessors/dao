/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __RDMA_PRIV_H__
#define __RDMA_PRIV_H__

#define RDMA_FWD_TBL_MAX_IDX 256

/**
 * @internal
 *
 * RDMA node main data structure.
 */
struct rdma_node_main {
	/* Port mapping between host port and mac ports */
	uint32_t nrml_fwd_tbl[RTE_MAX_ETHPORTS * 2];
	uint32_t rdma_fwd_tbl[RTE_MAX_ETHPORTS * 2];
	/* Next eth tx edge */
	uint16_t eth_tx_edge[RTE_MAX_ETHPORTS * 2];
};

typedef struct rdma_node_ctx {
	uint16_t port_id;  /**< Port identifier of the Rx node. */
	uint16_t queue_id; /**< Queue identifier of the Rx node. */
	/* Dynamic offset to mbuf priv1 */
	int mbuf_priv1_off;
} rdma_node_ctx_t;

enum rdma_next_nodes {
	RDMA_NEXT_PKT_DROP,
	RDMA_NEXT_MAX,
};

/**
 * @internal
 *
 * Get the rdma node.
 *
 * @return
 *   Pointer to the rdma node.
 */
struct rte_node_register *rdma_node_get(void);
struct rte_node_register *rdma_pts_node_get(void);

/**
 * @internal
 *
 * Set the Edge index of a given port_id.
 *
 * @param port_id
 *   port identifier.
 * @param next_index
 *   Edge index of the Given Tx node.
 */
int rdma_set_eth_tx_edge_idx(uint16_t port_id, uint16_t next_index);

/**
 * @internal
 *
 * Setting up the normal forwarding table which can be looked up for packet
 * flow between host and mac ports.
 *
 * @param port_arr
 *   Array of ports
 * @param nb_ports
 *   No of ports
 */
int rdma_setup_nrml_fwd_table(uint16_t *host_mac_map, uint16_t nb_ports);

int rdma_setup_rdma_fwd_table(uint16_t *rdma_port_map, uint16_t nb_ports);

uint16_t rdma_get_mac_port_from_rdevid(uint16_t rdevid);
#endif /* __RDMA_PRIV_H__ */
