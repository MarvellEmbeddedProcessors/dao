/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __CA_ETHDEV_H__
#define __CA_ETHDEV_H__

#include <stdlib.h>

#include "crypto_agent.h"

#define ETH_DEV_PMD_NAME_CN9K  "net_cn9k"
#define ETH_DEV_PMD_NAME_CN10K "net_cn10k"

int ca_eth_dev_init(uint8_t port_id, struct ca_dev_config *dev_config, struct rte_mempool *mp);
void ca_eth_dev_fini(struct ca_ethdev_ctx *eth_ctx);

int ca_eth_flow_create(uint8_t port_id);
void ca_eth_flow_clear(uint8_t port_id);

#endif /* __CA_ETHDEV_H__ */
