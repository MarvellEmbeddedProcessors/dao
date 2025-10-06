/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __RDMA_LCORE_H__
#define __RDMA_LCORE_H__

#define RDMA_MAX_RX_QUEUE_PER_PORT  128
#define RDMA_MAX_RX_QUEUE_PER_LCORE 128
#define RDMA_MAX_TX_QUEUE_PER_PORT  RTE_MAX_ETHPORTS
#define RDMA_MAX_LCORE_PARAMS       128

struct lcore_rx_queue {
	uint16_t port_id;
	uint8_t queue_id;
	char node_name[RTE_NODE_NAMESIZE];
};

struct lcore_pts_rdma_deq {
	char node_name[RTE_NODE_NAMESIZE];
	uint16_t devid;
	struct rdma_pts_deq_node_ctx *node_ctx;
};

struct lcore_pts_rdma_enq {
	char node_name[RTE_NODE_NAMESIZE];
	uint16_t devid;
	struct rdma_pts_enq_node_ctx *node_ctx;
};

/* Lcore conf */
struct lcore_conf {
	uint16_t n_rx_queue;
	uint16_t total_rx_queue;
	struct lcore_rx_queue rx_queue_list[RDMA_MAX_RX_QUEUE_PER_LCORE];

	struct lcore_pts_rdma_deq pts_rdma_deq_list[RDMA_MAX_RX_QUEUE_PER_LCORE];
	uint16_t nb_pts_rdma_deq;

	struct lcore_pts_rdma_enq pts_rdma_enq_list[RDMA_MAX_RX_QUEUE_PER_LCORE];
	uint16_t nb_pts_rdma_enq;

	/* Graph attributes */
	char node_name[RTE_NODE_NAMESIZE];
	struct rte_graph *graph;
	char name[RTE_GRAPH_NAMESIZE];
	rte_graph_t graph_id;

	bool service_lcore;
	int dev2mem_id;
	int mem2dev_id;
	int nb_vchans;

	uint32_t weight;
};

struct lcore_params {
	uint16_t port_id;
	uint8_t queue_id;
	uint8_t lcore_id;
};

typedef struct rdma_lcore_param {
	uint16_t nb_lcore_params;
	struct lcore_params lcore_params_array[RDMA_MAX_LCORE_PARAMS];
	struct lcore_conf lcore_conf[RTE_MAX_LCORE];
} rdma_lcore_param_t;

extern uint16_t lcore_list_wt_sorted[RTE_MAX_LCORE];

#endif /* __RDMA_LCORE_H__ */
