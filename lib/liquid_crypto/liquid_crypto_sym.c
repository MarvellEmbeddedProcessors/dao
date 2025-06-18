/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>
#include <stddef.h>

#include <rte_malloc.h>

#include <dao_liquid_crypto.h>
#include <dao_log.h>

#include "liquid_crypto_sym.h"

#include "hw/cpt.h"
#include "mc/se.h"

static TAILQ_HEAD(dao_lc_sym_sess_meta_list, dao_lc_sym_sess_meta)
	sym_sess_list_head = TAILQ_HEAD_INITIALIZER(sym_sess_list_head);

static int
sym_sess_fc_iv_len_validate(const struct dao_lc_sym_ctx *ctx)
{
	uint16_t iv_len = 0;

	switch (ctx->fc.enc_cipher) {
	case DAO_LC_FC_ENC_CIPHER_AES_CBC:
	case DAO_LC_FC_ENC_CIPHER_AES_GCM:
		iv_len = 16;
		break;
	default:
		dao_err("Unsupported encryption cipher.");
		return -ENOTSUP;
	}

	if (ctx->iv_len != iv_len) {
		dao_err("Invalid IV length for encryption cipher.");
		return -EINVAL;
	}

	return 0;
}

static int
sym_sess_fc_digest_len_validate(const struct dao_lc_sym_ctx *ctx)
{
	switch (ctx->fc.enc_cipher) {
	case DAO_LC_FC_ENC_CIPHER_AES_CBC:
		return 0;
	case DAO_LC_FC_ENC_CIPHER_AES_GCM:
		if (ctx->fc.mac_len == 16)
			return 0;
		break;
	default:
		dao_err("Unsupported encryption cipher.");
		return -ENOTSUP;
	}

	dao_err("Invalid digest length for encryption cipher.");
	return -EINVAL;
}

static int
sym_sess_hash_digest_len_validate(const struct dao_lc_sym_ctx *ctx)
{
	switch (ctx->fc.hash_type) {
	case DAO_LC_FC_HASH_TYPE_SHA1:
		if (ctx->fc.mac_len == 20)
			return 0;
		break;
	default:
		dao_err("Unsupported hash type.");
		return -ENOTSUP;
	}

	dao_err("Invalid digest length for hash type.");
	return -EINVAL;
}

struct dao_lc_sym_sess_meta *
liquid_crypto_sym_sess_meta_alloc(const struct dao_lc_sym_ctx *ctx)
{
	struct dao_lc_sym_sess_meta *sess_meta;
	union cpt_inst_w4 w4 = {0};

	sess_meta =
		rte_zmalloc("liquid_crypto_sym_sess_meta", sizeof(*sess_meta), RTE_CACHE_LINE_SIZE);
	if (sess_meta == NULL) {
		dao_err("Could not allocate memory for session metadata.");
		return NULL;
	}

	if (ctx->opcode == DAO_LC_SYM_OPCODE_FC) {
		if (sym_sess_fc_iv_len_validate(ctx))
			goto sess_meta_free;

		if (sym_sess_fc_digest_len_validate(ctx))
			goto sess_meta_free;

		if (ctx->fc.enc_cipher == DAO_LC_FC_ENC_CIPHER_AES_GCM)
			w4.s.opcode_minor |= (1 << 5);

		sess_meta->cipher_type = ctx->fc.enc_cipher;
		sess_meta->iv_len = ctx->iv_len;
		w4.s.opcode_major = ROC_SE_MAJOR_OP_FC;
	} else if (ctx->opcode == DAO_LC_SYM_OPCODE_HASH) {
		if (sym_sess_hash_digest_len_validate(ctx))
			goto sess_meta_free;

		sess_meta->hash_type = ctx->fc.hash_type;
		sess_meta->is_auth_only = true;
		w4.s.opcode_major = ROC_SE_MAJOR_OP_HASH;
		w4.s.opcode_minor = 0x0;
		w4.s.param1 = 0;
		w4.s.param2 = ((uint16_t)ctx->fc.hash_type << 8) | (uint16_t)ctx->fc.mac_len;
	} else {
		dao_err("Unsupported opcode.");
		goto sess_meta_free;
	}

	sess_meta->w4 = w4.u64;
	sess_meta->digest_len = ctx->fc.mac_len;

	return sess_meta;

sess_meta_free:
	rte_free(sess_meta);
	return NULL;
}

void
liquid_crypto_sym_sess_meta_insert(struct dao_lc_sym_sess_meta *sess_meta, uint64_t sess_id)
{
	sess_meta->w7 = sess_id;
	TAILQ_INSERT_TAIL(&sym_sess_list_head, sess_meta, next);
}

int
liquid_crypto_sym_sess_meta_remove(uint64_t sess_id, uint64_t *sess_opaque)
{
	struct dao_lc_sym_sess_meta *sess_meta;

	TAILQ_FOREACH(sess_meta, &sym_sess_list_head, next) {
		if (sess_meta->w7 == sess_id) {
			*sess_opaque = (uint64_t)sess_meta;
			TAILQ_REMOVE(&sym_sess_list_head, sess_meta, next);
			rte_free(sess_meta);
			return 0;
		}
	}

	return -ENOENT;
}

int
liquid_crypto_sym_sess_meta_lookup(uint64_t sess_opaque)
{
	struct dao_lc_sym_sess_meta *sess_meta = DAO_LC_SYM_META_GET_PTR(sess_opaque);
	struct dao_lc_sym_sess_meta *sess_meta_found;

	TAILQ_FOREACH(sess_meta_found, &sym_sess_list_head, next) {
		if (sess_meta_found == sess_meta)
			return 0;
	}

	return -ENOENT;
}

void
liquid_crypto_sym_sess_meta_free(struct dao_lc_sym_sess_meta *sess_meta)
{
	rte_free(sess_meta);
}

static int
sym_sess_fc_aes_key_len_verify(const struct dao_lc_sym_fc_ctx *fc_ctx)
{
	switch (fc_ctx->aes_key_len) {
	case DAO_LC_FC_AES_KEY_LEN_128:
	case DAO_LC_FC_AES_KEY_LEN_192:
	case DAO_LC_FC_AES_KEY_LEN_256:
		break;
	default:
		dao_err("Invalid AES key length.");
		return -EINVAL;
	}

	return 0;
}

static int
sym_sess_fc_verify(const struct dao_lc_sym_ctx *ctx)
{
	const struct dao_lc_sym_fc_ctx *fc_ctx;
	bool is_aes;
	int ret;

	fc_ctx = &ctx->fc;

	if (fc_ctx->iv_source == DAO_LC_FC_IV_SRC_CTX) {
		dao_err("Invalid IV source.");
		return -EINVAL;
	}

	is_aes = false;

	switch (fc_ctx->enc_cipher) {
	case DAO_LC_FC_ENC_CIPHER_AES_CBC:
	case DAO_LC_FC_ENC_CIPHER_AES_GCM:
		is_aes = true;
		break;
	default:
		dao_err("Unsupported encryption cipher.");
		return -EINVAL;
	}

	if (is_aes) {
		ret = sym_sess_fc_aes_key_len_verify(fc_ctx);
		if (ret)
			return ret;
	}

	if (fc_ctx->auth_input_type != DAO_LC_FC_AUTH_INPUT_OPAD_IPAD) {
		dao_err("Invalid authentication input type. Must be set to OPAD-IPAD.");
		return -EINVAL;
	}

	if (fc_ctx->auth_key_src != DAO_LC_FC_AUTH_KEY_SRC_CTX) {
		dao_err("Invalid authentication key source. Must be set to CTX.");
		return -EINVAL;
	}

	switch (fc_ctx->hash_type) {
	case DAO_LC_FC_HASH_TYPE_NULL:
		break;
	default:
		dao_err("Unsupported hash type.");
		return -EINVAL;
	}

	return 0;
}

static int
sym_sess_hash_verify(const struct dao_lc_sym_ctx *ctx)
{
	const struct dao_lc_sym_fc_ctx *fc_ctx;

	fc_ctx = &ctx->fc;

	switch (fc_ctx->hash_type) {
	case DAO_LC_FC_HASH_TYPE_SHA1:
		break;
	default:
		dao_err("Unsupported hash type.");
		return -EINVAL;
	}

	return 0;
}

int
liquid_crypto_sym_sess_verify(const struct dao_lc_sym_ctx *ctx)
{
	if (ctx == NULL) {
		dao_err("Invalid argument.");
		return -EINVAL;
	}

	switch (ctx->opcode) {
	case DAO_LC_SYM_OPCODE_FC:
		return sym_sess_fc_verify(ctx);
	case DAO_LC_SYM_OPCODE_HASH:
		return sym_sess_hash_verify(ctx);
	default:
		dao_err("Unsupported opcode.");
		return -EINVAL;
	}

	return 0;
}
