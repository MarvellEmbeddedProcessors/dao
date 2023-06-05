/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __OOD_LCORE_H__
#define __OOD_LCORE_H__

#include "ood_repr.h"

#define OOD_MAX_RX_QUEUE_PER_PORT  128
#define OOD_MAX_RX_QUEUE_PER_LCORE OOD_MAX_REPR_RX_QUEUE_PER_LCORE
#define OOD_MAX_TX_QUEUE_PER_PORT  RTE_MAX_ETHPORTS
#define OOD_MAX_LCORE_PARAMS       128

struct lcore_rx_queue {
	uint16_t port_id;
	uint8_t queue_id;
	char node_name[RTE_NODE_NAMESIZE];
};

/* Lcore conf */
struct lcore_conf {
	uint16_t n_rx_queue;
	struct lcore_rx_queue rx_queue_list[OOD_MAX_RX_QUEUE_PER_LCORE];

	/* Graph attributes */
	char node_name[RTE_NODE_NAMESIZE];
	struct rte_graph *graph;
	char name[RTE_GRAPH_NAMESIZE];
	rte_graph_t graph_id;
};

struct lcore_params {
	uint16_t port_id;
	uint8_t queue_id;
	uint8_t lcore_id;
};

typedef struct ood_lcore_param {
	uint16_t nb_lcore_params;
	struct lcore_params lcore_params_array[OOD_MAX_LCORE_PARAMS];
	struct lcore_conf lcore_conf[RTE_MAX_LCORE];
} ood_lcore_param_t;

#endif /* __OOD_LCORE_H__ */
