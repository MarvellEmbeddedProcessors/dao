/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */
#ifndef __VC_NODE_H__
#define __VC_NODE_H__

#include <rte_graph.h>
#include <rte_graph_worker.h>

#include <dao_util.h>

typedef struct vc_cryptodev_enq_node_ctx {
	uint16_t devid;
} vc_cryptodev_enq_node_ctx_t;

typedef struct vc_cryptodev_deq_node_ctx {
	uint16_t devid;
	uint16_t next_q;
	uint64_t crypto_q_map;
} vc_cryptodev_deq_node_ctx_t;

typedef struct vc_virtio_rx_node_ctx {
	uint64_t virt_q_map;
	uint16_t virt_q_count;
	uint16_t virtio_devid;
	uint16_t next_devid;
	uint16_t next_q;
} vc_virtio_rx_node_ctx_t;

typedef struct vc_virtio_tx_node_ctx {
	uint16_t virtio_devid;
} vc_virtio_tx_node_ctx_t;

DAO_STATIC_ASSERT(sizeof(vc_virtio_rx_node_ctx_t) <= RTE_NODE_CTX_SZ);
DAO_STATIC_ASSERT(sizeof(vc_virtio_tx_node_ctx_t) <= RTE_NODE_CTX_SZ);
DAO_STATIC_ASSERT(sizeof(vc_cryptodev_enq_node_ctx_t) <= RTE_NODE_CTX_SZ);
DAO_STATIC_ASSERT(sizeof(vc_cryptodev_deq_node_ctx_t) <= RTE_NODE_CTX_SZ);

#define VC_CRYPTODEV_MAX           16
#define VC_CRYPTODEV_DEQ_BURST_MAX 64

#define VC_VIRTIO_RX_BURST_PER_Q 64
#define VC_VIRTIO_RX_Q_MAX       64
#define VC_VIRTIO_RX_BURST_MAX   128

struct rte_node_register *vc_drop_node_get(void);
struct rte_node_register *vc_virtio_rx_node_get(void);
struct rte_node_register *vc_virtio_tx_node_get(void);
struct rte_node_register *vc_cryptodev_enq_node_get(void);
struct rte_node_register *vc_cryptodev_deq_node_get(void);

#endif /* __VC_NODE_H__ */
