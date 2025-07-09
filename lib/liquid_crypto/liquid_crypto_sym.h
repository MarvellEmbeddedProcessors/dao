/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __LIQUID_CRYPTO_SYM_H__
#define __LIQUID_CRYPTO_SYM_H__

#include <rte_tailq.h>

#include <dao_liquid_crypto.h>

#define DAO_LC_SYM_META_GET_PTR(sess_opaque)                                                       \
	((struct dao_lc_sym_sess_meta *)((uintptr_t)(sess_opaque)))

enum lc_sym_op_type {
	LC_SYM_OP_CIPHER_ONLY = 1,
	LC_SYM_OP_AUTH_ONLY,
	LC_SYM_OP_CIPHER_AUTH,
	LC_SYM_OP_AEAD,
};

/**
 * The liquid crypto symmetric context.
 */
struct dao_lc_sym_sess_meta {
	TAILQ_ENTRY(dao_lc_sym_sess_meta) next;

	/** CPT Instruction W4 */
	uint64_t w4;

	/** CPT Instruction W7 */
	uint64_t w7;

	/**
	 * Algorithm IV length provided by user.
	 * For AES-GCM, NIST SP 800-38D allows variable IV lengths, but hardware
	 * implementations may have specific requirements.
	 */
	uint16_t alg_iv_len;

	/**
	 * Packet IV length after adjusting for hardware processing.
	 * For AES-GCM with 12-byte IV, this is set to 16 bytes to accommodate
	 * J0 block formation (IV||0^31||1).
	 * For other IV lengths, may be adjusted based on hardware requirements.
	 */
	uint16_t pkt_iv_len;

	/** Digest length */
	uint16_t digest_len;

	/** Cipher type */
	enum dao_lc_fc_enc_cipher cipher_type;

	/** Hash type */
	enum dao_lc_fc_hash_type hash_type;

	/* Operation type */
	enum lc_sym_op_type op_type;
};

int liquid_crypto_sym_sess_verify(const struct dao_lc_sym_ctx *ctx);

struct dao_lc_sym_sess_meta *liquid_crypto_sym_sess_meta_alloc(const struct dao_lc_sym_ctx *ctx);

void liquid_crypto_sym_sess_meta_insert(struct dao_lc_sym_sess_meta *sess_meta, uint64_t sess_id);

int liquid_crypto_sym_sess_meta_remove(uint64_t sess_id, uint64_t *sess_opaque);

int liquid_crypto_sym_sess_meta_lookup(uint64_t sess_opaque);

void liquid_crypto_sym_sess_meta_free(struct dao_lc_sym_sess_meta *sess_meta);

#endif /* __LIQUID_CRYPTO_SYM_H__ */
