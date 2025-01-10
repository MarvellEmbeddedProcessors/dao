/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __LIQUID_CRYPTO_PRIV_H__
#define __LIQUID_CRYPTO_PRIV_H__

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

#endif /* __LIQUID_CRYPTO_PRIV_H__ */
