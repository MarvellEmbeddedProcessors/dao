/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Marvell.
 */
#ifndef __INCLUDE_RDMA_PTS_ENQ_PRIV_H__
#define __INCLUDE_RDMA_PTS_ENQ_PRIV_H__

struct rdma_pts_enq_node_ctx;
typedef struct rdma_pts_enq_node_ctx rdma_pts_enq_node_ctx_t;

/**
 * @internal
 *
 * Ethernet Tx node context structure.
 */
struct rdma_pts_enq_node_ctx {
	uint16_t devid;
	int mbuf_priv1_off;
};

/**
 * @internal
 *
 * Ethernet Tx node main structure.
 */
struct rdma_pts_enq_node_main {
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
struct rdma_pts_enq_node_main *rdma_pts_enq_node_data_get(void);

/**
 * @internal
 *
 * Get the Ethernet Tx node.
 *
 * @return
 *   Pointer to the Ethernet Tx node.
 */
struct rte_node_register *rdma_pts_enq_node_get(void);

#endif /* __INCLUDE_RDMA_PTS_ENQ_PRIV_H__ */
