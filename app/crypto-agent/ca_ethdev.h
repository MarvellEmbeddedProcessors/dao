/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __CA_ETHDEV_H__
#define __CA_ETHDEV_H__

#include <stdlib.h>

#include "crypto_agent.h"
#include <dao_card_grpc_server.h>

#define ETH_DEV_PMD_NAME_CN9K  "net_cn9k"
#define ETH_DEV_PMD_NAME_CN10K "net_cn10k"

struct ca_eth_dev_queue_lcore_link {
	uint8_t port_id;
	uint16_t queue_id;
	struct pending_queue *pq;
};

struct ca_eth_dev_queue_lcore_map {
	uint16_t nb_links;
	struct ca_eth_dev_queue_lcore_link link[CA_MAX_QUEUE_PER_CORE];
};

int ca_eth_lcore_map_init(void);
void ca_eth_lcore_map_fini(void);
struct ca_eth_dev_queue_lcore_map *ca_eth_lcore_map_get(uint8_t lcore_id);
int ca_eth_dev_init(uint32_t port_id, uint32_t nb_queue);
int ca_eth_dev_close(uint32_t port_id);
int ca_eth_dev_q_configure(struct dao_lc_eth_qconf *conf);
int ca_eth_dev_q_destroy(uint32_t dev_id, uint32_t qp_id);
int ca_eth_dev_start(uint32_t port_id);
int ca_eth_dev_stop(uint32_t dev_id);

#endif /* __CA_ETHDEV_H__ */
