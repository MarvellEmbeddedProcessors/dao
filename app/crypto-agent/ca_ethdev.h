/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __CA_ETHDEV_H__
#define __CA_ETHDEV_H__

#include "crypto_agent.h"

int ca_eth_dev_init(uint8_t port_id, struct ca_dev_config *dev_config, struct rte_mempool *mp);
void ca_eth_dev_fini(struct ca_ethdev_ctx *eth_ctx);

#endif /* __CA_ETHDEV_H__ */
