/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Marvell.
 */
#ifndef __INCLUDE_RDMA_PTS_DEQ_PRIV_H__
#define __INCLUDE_RDMA_PTS_DEQ_PRIV_H__

#include <rte_common.h>

struct rdma_pts_deq_node_elem;
struct rdma_pts_deq_node_ctx;
typedef struct rdma_pts_deq_node_elem rdma_pts_deq_node_elem_t;
typedef struct rdma_pts_deq_node_ctx rdma_pts_deq_node_ctx_t;

#define RDMA_PTS_BITMAP_WORDS 16

typedef struct {
	uint64_t bits[RDMA_PTS_BITMAP_WORDS];
} rdma_pts_bitmap_t;

/**
 * @internal
 *
 * Ethernet device Rx node context structure.
 */
struct rdma_pts_deq_node_ctx {
	rdma_pts_bitmap_t *qp_map;
	uint8_t devid;
	uint8_t next_qp;
	uint8_t qp_count;
	uint8_t next_node;
	uint16_t tx_node_idx;
	uint32_t queue_id;
	int mbuf_priv1_off;
};

enum rdma_pts_deq_next_nodes {
	EP_PTS_DEQ_NEXT_RDMA,
	EP_PTS_DEQ_NEXT_MAX,
};

/**
 * @internal
 *
 * Get the Ethernet Rx node.
 *
 * @return
 *   Pointer to the Ethernet Rx node.
 */
struct rte_node_register *rdma_pts_deq_node_get(void);

#endif /* __INCLUDE_RDMA_PTS_DEQ_PRIV_H__ */
