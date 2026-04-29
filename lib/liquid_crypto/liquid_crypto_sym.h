/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __LIQUID_CRYPTO_SYM_H__
#define __LIQUID_CRYPTO_SYM_H__

#include <rte_tailq.h>

#include "liquid_crypto_op_defines.h"
#include <dao_liquid_crypto.h>

#define DAO_LC_SYM_META_GET_PTR(sess_opaque)                                                       \
	((struct dao_lc_sym_sess_meta *)((uintptr_t)(sess_opaque)))

/**
 * Kind subfield of dao_lc_sym_sess_meta::flags:
 * low bits = dao_lc_sym_sess_kind; high bits reserved
 */
#define DAO_LC_SYM_SESS_F_KIND_SHIFT 0u
#define DAO_LC_SYM_SESS_F_KIND_MASK  0xFFu

enum dao_lc_sym_sess_kind {
	DAO_LC_SYM_SESS_KIND_HW = 0,
	DAO_LC_SYM_SESS_KIND_HASH = 1,
	DAO_LC_SYM_SESS_KIND_AES_KEY_WRAP = 2,
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
	 * Session kind and future attributes. Kind (see dao_lc_sym_sess_kind) selects the wire
	 * session id used for SYM_SESSION_DESTROY; remaining bits are reserved.
	 */
	uint16_t flags;

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
	enum dao_lc_hash_type hash_type;

	/* Operation type */
	enum lc_crypto_op_type op_type;

	/* HMAC authentication key length*/
	uint16_t auth_key_len;

	/* HMAC authentication key */
	uint8_t auth_key[DAO_LC_MAX_AUTH_KEY_LEN];

	/* Key encryption key length */
	uint16_t kek_len;

	/* Key encryption key for AES Key wrap */
	uint8_t kek[DAO_LC_AES_MAX_KEY_ENC_KEY_LEN];
};

static inline enum dao_lc_sym_sess_kind
dao_lc_sym_sess_meta_get_kind(const struct dao_lc_sym_sess_meta *sess_meta)
{
	return (enum dao_lc_sym_sess_kind)((sess_meta->flags >> DAO_LC_SYM_SESS_F_KIND_SHIFT) &
					   DAO_LC_SYM_SESS_F_KIND_MASK);
}

static inline void
dao_lc_sym_sess_meta_set_kind(struct dao_lc_sym_sess_meta *sess_meta,
			      enum dao_lc_sym_sess_kind kind)
{
	uint16_t k = (uint16_t)kind & (uint16_t)DAO_LC_SYM_SESS_F_KIND_MASK;
	uint16_t kind_bits =
		(uint16_t)(DAO_LC_SYM_SESS_F_KIND_MASK << DAO_LC_SYM_SESS_F_KIND_SHIFT);

	sess_meta->flags &= (uint16_t)~kind_bits;
	sess_meta->flags |= (uint16_t)(k << DAO_LC_SYM_SESS_F_KIND_SHIFT);
}

static inline uint64_t
dao_lc_sym_sess_meta_wire_destroy_id(const struct dao_lc_sym_sess_meta *sess_meta)
{
	switch (dao_lc_sym_sess_meta_get_kind(sess_meta)) {
	case DAO_LC_SYM_SESS_KIND_HASH:
		return DAO_LC_SESS_ID_HASH;
	case DAO_LC_SYM_SESS_KIND_AES_KEY_WRAP:
		return DAO_LC_SESS_ID_AES_KEY_WRAP;
	default:
		return sess_meta->w7;
	}
}

int liquid_crypto_sym_sess_verify(const struct dao_lc_sym_ctx *ctx);

struct dao_lc_sym_sess_meta *liquid_crypto_sym_sess_meta_alloc(const struct dao_lc_sym_ctx *ctx);

void liquid_crypto_sym_sess_meta_insert(struct dao_lc_sym_sess_meta *sess_meta, uint64_t sess_id);

int liquid_crypto_sym_sess_meta_remove(uint64_t sess_id, uint64_t *sess_opaque);

int liquid_crypto_sym_sess_meta_lookup(uint64_t sess_opaque);

void liquid_crypto_sym_sess_meta_free(struct dao_lc_sym_sess_meta *sess_meta);

int lc_sym_op_validate(struct dao_lc_sym_op *op);

int lc_sym_aes_key_wrap_param_validate(const struct dao_lc_sym_op *op,
				       const struct dao_lc_sym_sess_meta *sess_meta);

int sym_sess_get_aes_kek_len(enum dao_lc_fc_aes_key_len kek_type);

#endif /* __LIQUID_CRYPTO_SYM_H__ */
