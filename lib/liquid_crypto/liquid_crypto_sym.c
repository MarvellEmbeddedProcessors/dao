/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>
#include <stddef.h>

#include <dao_liquid_crypto.h>
#include <dao_log.h>

#include "liquid_crypto_sym.h"

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
