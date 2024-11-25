/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __CRYPTO_AGENT_H__
#define __CRYPTO_AGENT_H__

#include <rte_log.h>
#include <rte_mempool.h>

#include "ca_admin.h"

/* Log type */
#define RTE_LOGTYPE_AGENT        RTE_LOGTYPE_USER1
#define CA_INFO(fmt, args...)    RTE_LOG(INFO, AGENT, fmt "\n", ##args)
#define CA_INFO_NH(fmt, args...) rte_log(RTE_LOG_INFO, RTE_LOGTYPE_AGENT, fmt "\n", ##args)
#define CA_ERR(fmt, args...)     RTE_LOG(ERR, AGENT, fmt "\n", ##args)

struct ca_ethdev_ctx {
	uint16_t port_id;
	struct rte_mempool *mempool;
};

struct ca_global_ctx {
	uint8_t cryptodev_ids[RTE_CRYPTO_MAX_DEVS];
	uint8_t nb_valid_ethdevs;
	struct ca_ethdev_ctx eth_ctx[RTE_MAX_ETHPORTS];
};

#endif /* __CRYPTO_AGENT_H__ */
