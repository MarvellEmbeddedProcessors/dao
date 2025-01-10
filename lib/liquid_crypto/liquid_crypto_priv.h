/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __LIQUID_CRYPTO_PRIV_H__
#define __LIQUID_CRYPTO_PRIV_H__

#include <rte_common.h>
#include <rte_mempool.h>

#define LIQUID_CRYPTO_BUF_SZ_MIN 64ull

#define LIQUID_CRYPTO_MAX_NB_QP 64

/** Liquid crypto device */
struct liquid_crypto_dev {
	/** Is created */
	bool is_created;
	/** Number of queue pairs */
	uint16_t nb_qp;
	/** Queue pair pointers */
	void *qp[LIQUID_CRYPTO_MAX_NB_QP];
} __rte_cache_aligned;

/** Liquid crypto queue pair */
struct liquid_crypto_qp {
	/** Ethernet port ID */
	uint16_t port_id;
	/** Ethernet queue ID */
	uint16_t queue_id;
	/** RX mempool */
	struct rte_mempool *rx_mp;
	/** TX mempool */
	struct rte_mempool *tx_mp;
} __rte_cache_aligned;

#endif /* __LIQUID_CRYPTO_PRIV_H__ */
