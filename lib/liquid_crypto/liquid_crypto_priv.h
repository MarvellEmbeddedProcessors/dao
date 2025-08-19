/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __LIQUID_CRYPTO_PRIV_H__
#define __LIQUID_CRYPTO_PRIV_H__

#include <rte_bitmap.h>
#include <rte_bitops.h>
#include <rte_common.h>
#include <rte_mempool.h>

#include <liquid_crypto_sym.h>

#define LIQUID_CRYPTO_BUF_SZ_MIN          64ull
#define LIQUID_CRYPTO_BUF_SZ_MAX          32768ull
#define LIQUID_CRYPTO_BUF_SDP_DATA_LEN_SZ 8ull

#define LIQUID_CRYPTO_MAX_BURST 128

/* TODO: With lower values observed event corruption.
 * Lower values can be configured, once the issue is resolved.
 */
#define LIQUID_CRYPTO_SEG_SZ_MIN 512ull

#define LIQUID_CRYPTO_MAX_NB_QP 64

#define LIQUID_CRYPTO_RSA_MOD_LEN_MIN     17
#define LIQUID_CRYPTO_RSA_MOD_LEN_MAX     1024
#define LIQUID_CRYPTO_RSA_MSG_LEN_PADDING 11

#define LIQUID_CRYPTO_RNG_MAX_LEN 32767

/** Liquid crypto device */
struct liquid_crypto_dev {
	/** Is created */
	bool is_created;
	/** Is started */
	bool is_started;
	/** Is destroyed */
	bool is_destroyed;
	/** Number of queue pairs */
	uint16_t nb_qp;
	/** Index of command queue pair */
	uint16_t cmd_qp_idx;
	/** Queue pair pointers */
	void *qp[LIQUID_CRYPTO_MAX_NB_QP];
	/** Number of eth ports */
	uint8_t nb_ports;
	/** Port info of each eth port */
	struct dao_eth_trs_port_info port_info;
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
	/**
	 * Command queue inflight request bitmap.
	 * Only applicable for queue pair designated as cmd_qp_idx
	 */
	struct rte_bitmap *cmd_req_bm;
	/**
	 * Command queue inflight request bitmap memory.
	 * Only applicable for queue pair designated as cmd_qp_idx
	 */
	uint8_t *cmd_req_bm_mem;
} __rte_cache_aligned;

struct liquid_crypto_inflight_req {
	/** Field provided by application during request submission */
	uint64_t op_cookie;
	/** Output buffer given for a crypto operation. */
	void *data_out;
	/**< ECC operation type */
	enum dao_lc_ecdsa_sign_type ecc_op;
	/** Digest location */
	void *digest;

	/** Digest length */
	uint16_t digest_len;

	/** Liquid Crypto Buffer Offset */
	uint32_t lc_buf_offset;

	/** Cipher length */
	uint16_t cipher_len;

	/** Result offset */
	uint16_t result_offset;

	/* Operation type */
	enum lc_crypto_op_type op_type;

	union {
		/** Pointer to metadata for the symmetric session creation request */
		struct dao_lc_sym_sess_meta *sess_meta;
	};

	/* Is auth generate operation */
	bool is_auth_gen;
};

static inline uint32_t
liquid_crypto_qp_req_idx_get(struct liquid_crypto_qp *qp, const bool is_cmd_qp)
{
	struct rte_bitmap *req_bm;
	uint32_t req_idx = 0;
	uint64_t slab = 0;
	int rc;

	if (is_cmd_qp)
		req_bm = qp->cmd_req_bm;
	else
		req_bm = qp->req_bm;

	rc = rte_bitmap_scan(req_bm, &req_idx, &slab);
	if (rc == 0)
		return UINT32_MAX;

	req_idx += rte_ctz64(slab);
	rte_bitmap_clear(req_bm, req_idx);

	return req_idx;
}

static inline void
liquid_crypto_qp_req_idx_put(struct liquid_crypto_qp *qp, uint32_t req_idx, const bool is_cmd_qp)
{
	if (is_cmd_qp)
		rte_bitmap_set(qp->cmd_req_bm, req_idx);
	else
		rte_bitmap_set(qp->req_bm, req_idx);
}

#endif /* __LIQUID_CRYPTO_PRIV_H__ */
