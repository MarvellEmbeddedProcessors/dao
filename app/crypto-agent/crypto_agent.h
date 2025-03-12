/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __CRYPTO_AGENT_H__
#define __CRYPTO_AGENT_H__

#include <rte_cryptodev.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_pmd_cnxk_crypto.h>
#include <rte_security.h>

#include "ca_admin.h"
#include "ca_crypto_queue.h"

/* Default command timeout in seconds */
#define DEFAULT_COMMAND_TIMEOUT 4

#define ETH_DEV_MIN_BUF_LEN 44ul
#define ETH_DEV_MAX_BUF_LEN 65531ul

#define CA_MAX_ETH_DEV        8
#define CA_MAX_ETH_QUEUE      8
#define CA_ETH_RETA_SIZE      64
#define CA_MAX_QUEUE_PER_CORE 64
#define CA_MAX_LCORE          24
#define CA_MAX_PAYLOAD_SIZE   5120

DAO_STATIC_ASSERT(CA_MAX_ETH_DEV <= RTE_MAX_ETHPORTS);
DAO_STATIC_ASSERT(CA_MAX_ETH_QUEUE <= RTE_MAX_QUEUES_PER_PORT);

/* Log type */
#define RTE_LOGTYPE_AGENT        RTE_LOGTYPE_USER1
#define CA_INFO(fmt, args...)    RTE_LOG(INFO, AGENT, fmt "\n", ##args)
#define CA_INFO_NH(fmt, args...) rte_log(RTE_LOG_INFO, RTE_LOGTYPE_AGENT, fmt "\n", ##args)
#define CA_WARN(fmt, args...)    RTE_LOG(WARNING, AGENT, fmt "\n", ##args)
#define CA_ERR(fmt, args...)     RTE_LOG(ERR, AGENT, fmt "\n", ##args)

struct ca_eth_dev_ctx {
	bool is_configured;
	bool is_started;
	uint16_t port_id;
	uint16_t nb_queue;
	uint16_t nb_queue_avail;
	uint64_t init_q_mask;
	struct pending_queue cpt_pq[CA_MAX_ETH_QUEUE];
};

DAO_STATIC_ASSERT(CA_MAX_ETH_QUEUE <= 64);

struct ca_global_ctx {
	uint8_t cryptodev_ids[RTE_CRYPTO_MAX_DEVS];
	uint8_t nb_valid_ethdevs;
	struct ca_eth_dev_ctx eth_ctx[RTE_MAX_ETHPORTS];
	uint16_t nb_cpt_qp;
	struct rte_pmd_cnxk_crypto_qptr *cpt_qptr[CA_MAX_LCORE];
};

struct lcore_conf {
	struct rte_pmd_cnxk_crypto_qptr *cpt_qptr;
	uint16_t nb_pq;
	struct pending_queue *pq[CA_MAX_QUEUE_PER_CORE];
} __rte_cache_aligned;

struct ca_eth_dev_ctx *ca_eth_dev_ctx_get(uint16_t port_id);

#endif /* __CRYPTO_AGENT_H__ */
