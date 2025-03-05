/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __LIQUID_CRYPTO_PRIV_H__
#define __LIQUID_CRYPTO_PRIV_H__

#include <rte_bitmap.h>
#include <rte_bitops.h>
#include <rte_common.h>
#include <rte_mempool.h>

#define LIQUID_CRYPTO_BUF_SZ_MIN 64ull

#define LIQUID_CRYPTO_MAX_BURST 32
#define LIQUID_CRYPTO_MAX_NB_QP 64

#define LIQUID_CRYPTO_RSA_MOD_LEN_MIN     17
#define LIQUID_CRYPTO_RSA_MOD_LEN_MAX     1024
#define LIQUID_CRYPTO_RSA_MSG_LEN_PADDING 11

/** Liquid crypto device */
struct liquid_crypto_dev {
	/** Is created */
	bool is_created;
	/** Is started */
	bool is_started;
	/** Number of queue pairs */
	uint16_t nb_qp;
	/** Index of command queue pair */
	uint16_t cmd_qp_idx;
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
	/** Inflight request queue */
	struct liquid_crypto_inflight_req *req_queue;
	/** Inflight request bitmap */
	struct rte_bitmap *req_bm;
	/** Inflight request bitmap memory */
	uint8_t *req_bm_mem;
} __rte_cache_aligned;

struct liquid_crypto_inflight_req {
	/** Field provided by application during request submission */
	uint64_t op_cookie;
	/** Output buffer given for a crypto operation. */
	void *data_out;
};

static inline uint32_t
liquid_crypto_qp_req_idx_get(struct liquid_crypto_qp *qp)
{
	uint32_t req_idx = 0;
	uint64_t slab = 0;
	int rc;

	rc = rte_bitmap_scan(qp->req_bm, &req_idx, &slab);
	if (rc == 0)
		return UINT32_MAX;

	req_idx += rte_ctz64(slab);
	rte_bitmap_clear(qp->req_bm, req_idx);

	return req_idx;
}

static inline void
liquid_crypto_qp_req_idx_put(struct liquid_crypto_qp *qp, uint32_t req_idx)
{
	rte_bitmap_set(qp->req_bm, req_idx);
}

#endif /* __LIQUID_CRYPTO_PRIV_H__ */
