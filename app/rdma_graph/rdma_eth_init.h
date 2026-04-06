/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __RDMA_ETH_INIT_H__
#define __RDMA_ETH_INIT_H__

#include <rte_ethdev.h>
#include <rte_mempool.h>

#include "rdma_config.h"

#define RDMA_MAX_JUMBO_PKT_LEN 9600

#define RDMA_MAX_PKT_BURST      32
#define RDMA_BURST_TX_DRAIN_US  100 /* TX drain every ~100us */
#define RDMA_MEMPOOL_CACHE_SIZE 64

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RDMA_RX_DESC_DEFAULT 1024
#define RDMA_TX_DESC_DEFAULT 16384

#define RDMA_NB_SOCKETS 1
/*
 * To support 8MB RDMA message size with 1024 MTU, and 16 burst size, we need minimum
 * 8MB*16/1KB = 128K mbufs. So we set default to 128K.
 */
#define RDMA_DEFAULT_NB_MBUF 131072

/* Forward declaration */
struct rdma_main_cfg_data;

struct rdma_ethdev_port_info {
	uint16_t nb_rxq;
	uint16_t port_id;
};

typedef struct rdma_ethdev_host_mac_map {
	struct rdma_ethdev_port_info mac_port;
	struct rdma_ethdev_port_info host_port;
} rdma_ethdev_host_mac_map_t;

typedef struct rdma_ethdev_param {
	int numa_on; /**< NUMA is enabled by default. */
	struct rte_mempool *pktmbuf_pool[RTE_MAX_ETHPORTS][RDMA_NB_SOCKETS];
	/* list of enabled ports */
	rdma_ethdev_host_mac_map_t host_mac_map[RTE_MAX_ETHPORTS / 2];
	uint16_t nb_ports;
} rdma_ethdev_param_t;

int rdma_ethdev_init(struct rdma_main_cfg_data *rdma_main_cfg);
int rdma_config_port_max_pkt_len(rdma_config_param_t *cfg_prm, struct rte_eth_conf *conf,
				 struct rte_eth_dev_info *dev_info);
uint16_t rdma_ethdev_port_pair_get(rdma_ethdev_host_mac_map_t *host_mac_map, uint16_t portid);
struct rdma_ethdev_port_info *rdma_ethdev_port_info_get(uint16_t portid);

#endif /* __RDMA_ETH_INIT_H__ */
