/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>
#include <stddef.h>

#include <rte_malloc.h>

#include <dao_liquid_crypto.h>
#include <dao_log.h>

#include "liquid_crypto_sym.h"

static TAILQ_HEAD(dao_lc_sym_sess_meta_list, dao_lc_sym_sess_meta)
	sym_sess_list_head = TAILQ_HEAD_INITIALIZER(sym_sess_list_head);

struct dao_lc_sym_sess_meta *
liquid_crypto_sym_sess_meta_alloc(const struct dao_lc_sym_ctx *ctx)
{
	struct dao_lc_sym_sess_meta *sess_meta;
	uint16_t iv_len = 0;

	sess_meta =
		rte_zmalloc("liquid_crypto_sym_sess_meta", sizeof(*sess_meta), RTE_CACHE_LINE_SIZE);
	if (sess_meta == NULL)
		dao_err("Could not allocate memory for session metadata.");

	if (ctx->opcode == DAO_LC_SYM_OPCODE_FC) {
		switch (ctx->fc.enc_cipher) {
		case DAO_LC_FC_ENC_CIPHER_AES_CBC:
			iv_len = 16;
			break;
		default:
			dao_err("Unsupported encryption cipher.");
			rte_free(sess_meta);
			return NULL;
		}
		sess_meta->iv_len = iv_len;
	} else {
		dao_err("Unsupported opcode.");
		rte_free(sess_meta);
		return NULL;
	}

	return sess_meta;
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
		break;
	case DAO_LC_FC_AES_KEY_LEN_192:
	case DAO_LC_FC_AES_KEY_LEN_256:
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
	default:
		dao_err("Unsupported opcode.");
		return -EINVAL;
	}

	return 0;
}
