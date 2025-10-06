/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __RDMA_NODE_CTRL_H__
#define __RDMA_NODE_CTRL_H__

/**
 * @file rte_node_eth_api.h
 *
 * @warning
 * @b EXPERIMENTAL:
 * All functions in this file may be changed or removed without prior notice.
 *
 * This API allows to setup rdma_eth_rx and rdma_eth_tx nodes
 * and its queue associations.
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_bitmap.h>
#include <rte_common.h>
#include <rte_compat.h>
#include <rte_graph.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <rte_mempool.h>

#define RDMA_MAX_RX_QUEUE_PER_PORT 128
#define APP_RDMA_ETH_DEQ_BURST_MAX 16

/**
 * Node mbuf private area 2.
 */
struct node_mbuf_priv2 {
	uint64_t priv_data;
} __rte_cache_aligned;

#define NODE_MBUF_PRIV2_SIZE sizeof(struct node_mbuf_priv2)

/**
 * Node mbuf private metadata carried across RDMA graph nodes.
 *
 */
struct node_mbuf_priv1 {
	/* Target Tx queue for NIC transmission */
	uint16_t queue;
	/* Ingress/egress ethernet port (optional; for diagnostics or mapping) */
	uint16_t port;
	/* RDMA device identifier (port on RDMA device array) */
	uint16_t devid;
	/* Number of packets in a grouped operation (e.g., segmentation or ACK batch) */
	uint16_t nb_pkts;
	/* RDMA Queue Pair identifier */
	uint32_t qp_id;
};

static const struct rte_mbuf_dynfield node_mbuf_priv1_dynfield_desc = {
	.name = "rte_node_dynfield_priv1",
	.size = sizeof(struct node_mbuf_priv1),
	.align = __alignof__(struct node_mbuf_priv1),
};

extern int node_mbuf_priv1_dynfield_queue;

/**
 * Get mbuf_priv1 pointer from rte_mbuf.
 *
 * @param
 *   Pointer to the rte_mbuf.
 *
 * @return
 *   Pointer to the mbuf_priv1.
 */
static __rte_always_inline struct node_mbuf_priv1 *
node_mbuf_priv1(struct rte_mbuf *m, const int offset)
{
	return RTE_MBUF_DYNFIELD(m, offset, struct node_mbuf_priv1 *);
}

/*
 * Node configuration for flow_mapper node
 */
typedef struct rdma_node_rdma_ctrl_conf {
	/* Host to Mac port mapping array */
	uint16_t host_mac_map[RTE_MAX_ETHPORTS * 2];
	/* Mac port to RDMA mapping array */
	uint16_t rdma_port_map[RTE_MAX_ETHPORTS * 2];
	/* Total no of ports */
	uint16_t nb_ports;
	/* No of active host ports */
	uint16_t active_host_ports;
	/* Array of active host ports */
	uint16_t host_ports[RTE_MAX_ETHPORTS];

} rdma_node_rdma_ctrl_conf_t;

/**
 * Port config for rdma_eth_rx and rdma_eth_tx node.
 */
typedef struct rdma_node_eth_ctrl_conf {
	/* Port identifier */
	uint16_t port_id;
	/* Number of Rx queues. */
	uint16_t num_rx_queues;
	/* Number of Tx queues. */
	uint16_t num_tx_queues;
	/* Array of mempools associated to Rx queue. */
	struct rte_mempool **mp;
	/* Size of mp array. */
	uint16_t mp_count;
} rdma_node_eth_ctrl_conf_t;

extern uint8_t port_type[RTE_MAX_ETHPORTS * 2];

/**
 * Control API for configuring Eth nodes
 *
 * @param conf
 *   Array of eth config that identifies which port's rdma_eth_rx and rdma_eth_tx
 *   nodes need to be created and queue association.
 * @param cnt
 *   Size of cfg array.
 * @param nb_graphs
 *   Number of graphs that will be used.
 *
 * @return
 *   0 on successful initialization, negative otherwise.
 */
int rdma_node_eth_ctrl(rdma_node_eth_ctrl_conf_t *conf, uint16_t nb_conf, uint16_t nb_graphs);

/**
 * Control API for configuring RDMA node
 *
 * @param conf
 *   RDMA configuration that identifies which port mappings and port to
 *   node edge mappings.
 *
 * @return
 *   0 on successful initialization, negative otherwise.
 */
int rdma_node_rdma_ctrl(rdma_node_rdma_ctrl_conf_t *conf);

#ifdef __cplusplus
}
#endif

#endif /* __RDMA_NODE_CTRL_H__ */
