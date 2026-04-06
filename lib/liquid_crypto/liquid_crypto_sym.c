/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>
#include <stddef.h>

#include <rte_malloc.h>

#include <dao_liquid_crypto.h>
#include <dao_log.h>

#include "liquid_crypto_debug.h"
#include "liquid_crypto_op_defines.h"
#include "liquid_crypto_sym.h"

#include "hw/cpt.h"
#include "mc/se.h"

#define DAO_LC_OPCODE_IV_LENGTH_MASK (1 << 5)
#define DAO_LC_PARAM_MASK 0x3
#define DAO_LC_HASH_MASK  0xF
#define DAO_LC_KMAC_PARAM2 (2 & DAO_LC_PARAM_MASK)
#define DAO_LC_CSHAKE_PARAM2 (1 & DAO_LC_PARAM_MASK)

static TAILQ_HEAD(dao_lc_sym_sess_meta_list, dao_lc_sym_sess_meta)
	sym_sess_list_head = TAILQ_HEAD_INITIALIZER(sym_sess_list_head);

static int
sym_sess_fc_iv_len_validate(const struct dao_lc_sym_ctx *ctx)
{
	const uint8_t iv_len = ctx->iv_len;

	switch (ctx->fc.enc_cipher) {
	case DAO_LC_FC_ENC_CIPHER_AES_CBC:
		if (iv_len == 16)
			return 0;
		break;
	case DAO_LC_FC_ENC_CIPHER_AES_GCM:
		if (iv_len == 12)
			return 0;
		break;
	case DAO_LC_FC_ENC_CIPHER_AES_CCM:
		if (iv_len >= 7 && iv_len <= 13)
			return 0;
		break;
	case DAO_LC_FC_ENC_CIPHER_CHACHA:
		if (ctx->fc.hash_type != DAO_LC_HASH_TYPE_POLY1305) {
			dao_err("Unsupported hash type for ChaCha cipher.");
			return -ENOTSUP;
		}
		if (iv_len == 12)
			return 0;
		break;
	case DAO_LC_FC_ENC_CIPHER_NULL:
		if (ctx->fc.hash_type != DAO_LC_HASH_TYPE_GMAC) {
			dao_err("Unsupported hash type for NULL cipher.");
			return -ENOTSUP;
		}
		if (iv_len == 12)
			return 0;
		break;
	default:
		dao_err("Unsupported encryption cipher.");
		return -ENOTSUP;
	}

	dao_err("Invalid IV length for encryption cipher.");
	return -EINVAL;
}

static int
sym_sess_fc_digest_len_validate(const struct dao_lc_sym_ctx *ctx)
{
	const uint16_t mac_len = (uint16_t)ctx->fc.mac_len;

	switch (ctx->fc.enc_cipher) {
	case DAO_LC_FC_ENC_CIPHER_AES_CBC:
		return 0;
	case DAO_LC_FC_ENC_CIPHER_AES_GCM:
		if (mac_len == 16)
			return 0;
		break;
	case DAO_LC_FC_ENC_CIPHER_AES_CCM:
		if (mac_len == 8)
			return 0;
		break;
	case DAO_LC_FC_ENC_CIPHER_CHACHA:
		if (ctx->fc.hash_type != DAO_LC_HASH_TYPE_POLY1305) {
			dao_err("Unsupported hash type for ChaCha cipher.");
			return -ENOTSUP;
		}
		if (mac_len == 16)
			return 0;
		break;
	case DAO_LC_FC_ENC_CIPHER_NULL:
		if (ctx->fc.hash_type != DAO_LC_HASH_TYPE_GMAC) {
			dao_err("Unsupported hash type for NULL cipher.");
			return -ENOTSUP;
		}
		if (mac_len == 16)
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
	const uint16_t mac_len = (uint16_t)ctx->hash.digest_len;

	switch (ctx->hash.hmac_hash_type) {
	case DAO_LC_HASH_TYPE_SHA1:
		if (mac_len == 20)
			return 0;
		break;
	case DAO_LC_HASH_TYPE_SHA2_SHA224:
	case DAO_LC_HASH_TYPE_SHA3_SHA224:
		if (mac_len == 28)
			return 0;
		break;
	case DAO_LC_HASH_TYPE_SHA2_SHA256:
	case DAO_LC_HASH_TYPE_SHA3_SHA256:
		if (mac_len == 32)
			return 0;
		break;
	case DAO_LC_HASH_TYPE_SHA2_SHA384:
	case DAO_LC_HASH_TYPE_SHA3_SHA384:
		if (mac_len == 48)
			return 0;
		break;
	case DAO_LC_HASH_TYPE_SHA2_SHA512:
	case DAO_LC_HASH_TYPE_SHA3_SHA512:
		if (mac_len == 64)
			return 0;
		break;
		/*
		 * KMAC and cSHAKE use output length instead of digest length,
		 * so session-level digest-len validation is skipped.
		 */
	case DAO_LC_HASH_TYPE_SHA3_KMAC128:
	case DAO_LC_HASH_TYPE_SHA3_KMAC256:
	case DAO_LC_HASH_TYPE_SHA3_CSHAKE128:
	case DAO_LC_HASH_TYPE_SHA3_CSHAKE256:
		return 0;
	case DAO_LC_HASH_TYPE_SHA3_SHAKE128:
	case DAO_LC_HASH_TYPE_SHA3_SHAKE256:
		if ((mac_len >= 1) && (mac_len <= DAO_LC_MAX_DIGEST_LEN))
			return 0;
		break;
	case DAO_LC_HASH_TYPE_CMAC:
		if ((ctx->hash.hmac_key_len != 16) && (ctx->hash.hmac_key_len != 24) &&
		    (ctx->hash.hmac_key_len != 32)) {
			dao_err("Invalid AES-CMAC key length.");
			return -EINVAL;
		}
		if (mac_len >= 1 && mac_len <= 16)
			return 0;
		break;
	default:
		dao_err("Unsupported hash type.");
		return -ENOTSUP;
	}

	dao_err("Invalid digest length for hash type.");
	return -EINVAL;
}

static int
sym_sess_cipher_auth_digest_len_validate(const struct dao_lc_sym_ctx *ctx)
{
	const uint16_t mac_len = (uint16_t)ctx->fc.mac_len;

	switch (ctx->fc.hash_type) {
	case DAO_LC_HASH_TYPE_SHA1:
		if (mac_len == 20)
			return 0;
		break;
	default:
		dao_err("Unsupported hash type.");
		return -ENOTSUP;
	}

	dao_err("Invalid digest length for cipher-auth operation.");
	return -EINVAL;
}

int
sym_sess_get_aes_kek_len(enum dao_lc_fc_aes_key_len aes_kek_type)
{
	switch (aes_kek_type) {
	case DAO_LC_FC_AES_KEY_LEN_128:
		return DAO_LC_AES_KEY_LEN_16_BYTES;
	case DAO_LC_FC_AES_KEY_LEN_192:
		return DAO_LC_AES_KEY_LEN_24_BYTES;
	case DAO_LC_FC_AES_KEY_LEN_256:
		return DAO_LC_AES_KEY_LEN_32_BYTES;
	}

	return -EINVAL;
}

struct dao_lc_sym_sess_meta *
liquid_crypto_sym_sess_meta_alloc(const struct dao_lc_sym_ctx *ctx)
{
	struct dao_lc_sym_sess_meta *sess_meta;
	union cpt_inst_w4 w4 = {0};
	uint16_t hash_field = 0;
	int kek_len;

	sess_meta =
		rte_zmalloc("liquid_crypto_sym_sess_meta", sizeof(*sess_meta), RTE_CACHE_LINE_SIZE);
	if (sess_meta == NULL) {
		dao_err("Could not allocate memory for session metadata.");
		return NULL;
	}

	sess_meta->op_type = LC_SYM_OP_CIPHER_ONLY;

	if (ctx->opcode == DAO_LC_SYM_OPCODE_FC) {
		if (sym_sess_fc_iv_len_validate(ctx))
			goto sess_meta_free;

		if (sym_sess_fc_digest_len_validate(ctx))
			goto sess_meta_free;

		sess_meta->alg_iv_len = ctx->iv_len;
		sess_meta->pkt_iv_len = ctx->iv_len;
		sess_meta->cipher_type = ctx->fc.enc_cipher;
		w4.s.opcode_major = ROC_SE_MAJOR_OP_FC;

		if (ctx->is_chained_cipher) {
			if (sym_sess_cipher_auth_digest_len_validate(ctx))
				goto sess_meta_free;

			w4.s.opcode_minor |= (ctx->chain_order << 4);
			sess_meta->hash_type = ctx->fc.hash_type;
			sess_meta->op_type = LC_SYM_OP_CIPHER_AUTH;
		}

		if (ctx->fc.enc_cipher == DAO_LC_FC_ENC_CIPHER_AES_GCM) {
			w4.s.opcode_minor |= DAO_LC_OPCODE_IV_LENGTH_MASK;
			sess_meta->op_type = LC_SYM_OP_AEAD;
			/* When IV len is 12, 4B would be added by LC layer and submitted. */
			if (sess_meta->alg_iv_len == 12)
				sess_meta->pkt_iv_len = 16;
		}

		if (ctx->fc.hash_type == DAO_LC_HASH_TYPE_GMAC) {
			sess_meta->hash_type = ctx->fc.hash_type;
			w4.s.opcode_minor |= DAO_LC_OPCODE_IV_LENGTH_MASK;
			sess_meta->op_type = LC_SYM_OP_AUTH_ONLY;
			if (sess_meta->alg_iv_len == 12)
				sess_meta->pkt_iv_len = 16;
		}

		if (ctx->fc.enc_cipher == DAO_LC_FC_ENC_CIPHER_CHACHA) {
			sess_meta->hash_type = ctx->fc.hash_type;
			w4.s.opcode_minor |= DAO_LC_OPCODE_IV_LENGTH_MASK;
			sess_meta->op_type = LC_SYM_OP_AEAD;
			if (sess_meta->alg_iv_len == 12)
				sess_meta->pkt_iv_len = 16;
		}

		if (ctx->fc.enc_cipher == DAO_LC_FC_ENC_CIPHER_AES_CCM) {
			sess_meta->pkt_iv_len = 16;
			sess_meta->op_type = LC_SYM_OP_AEAD;
		}

		sess_meta->digest_len = ctx->fc.mac_len;
	} else if (ctx->opcode == DAO_LC_SYM_OPCODE_HASH) {
		if (sym_sess_hash_digest_len_validate(ctx))
			goto sess_meta_free;

		sess_meta->hash_type = ctx->hash.hmac_hash_type;
		sess_meta->op_type = LC_SYM_OP_AUTH_ONLY;
		w4.s.opcode_major = ROC_SE_MAJOR_OP_HASH;
		w4.s.opcode_minor = 0x0;
		w4.s.param1 = 0;
		w4.s.param2 =
			((uint16_t)ctx->hash.hmac_hash_type << 8) | (uint16_t)ctx->hash.digest_len;
		sess_meta->digest_len = ctx->hash.digest_len;
	} else if (ctx->opcode == DAO_LC_SYM_OPCODE_HMAC) {
		if (sym_sess_hash_digest_len_validate(ctx))
			goto sess_meta_free;

		sess_meta->hash_type = ctx->hash.hmac_hash_type;
		sess_meta->op_type = LC_SYM_OP_HMAC_AUTH_ONLY;
		sess_meta->auth_key_len = ctx->hash.hmac_key_len;
		switch (sess_meta->hash_type) {
		case DAO_LC_HASH_TYPE_SHA3_SHAKE128:
		case DAO_LC_HASH_TYPE_SHA3_SHAKE256:
		case DAO_LC_HASH_TYPE_SHA3_CSHAKE128:
		case DAO_LC_HASH_TYPE_SHA3_CSHAKE256:
			if (sess_meta->auth_key_len != 0) {
				dao_err("Unsupported auth-key-len for SHAKE and cSHAKE operations.");
				goto sess_meta_free;
			}
			break;
		default:
			break;
		}
		memcpy(sess_meta->auth_key, ctx->hash.hmac_auth_key, ctx->hash.hmac_key_len);

		w4.s.opcode_major = ROC_SE_MAJOR_OP_HMAC;
		w4.s.opcode_minor = 0x0;
		if (ctx->hash.hmac_hash_type == DAO_LC_HASH_TYPE_CMAC)
			w4.s.opcode_minor |= (0x1 << 4);
		w4.s.param1 = ctx->hash.hmac_key_len;
		switch (ctx->hash.hmac_hash_type) {
		case DAO_LC_HASH_TYPE_SHA3_KMAC128:
			w4.s.param2 = (uint16_t)(DAO_LC_KMAC_PARAM2 << 12) |
			((DAO_LC_HASH_MASK & DAO_LC_HASH_TYPE_SHA3_SHAKE128) << 8) |
			ctx->hash.digest_len;
			break;
		case DAO_LC_HASH_TYPE_SHA3_KMAC256:
			w4.s.param2 = (uint16_t)(DAO_LC_KMAC_PARAM2 << 12) |
			((DAO_LC_HASH_MASK & DAO_LC_HASH_TYPE_SHA3_SHAKE256) << 8) |
			ctx->hash.digest_len;
			break;
		case DAO_LC_HASH_TYPE_SHA3_CSHAKE128:
			hash_field = ((DAO_LC_HASH_MASK & DAO_LC_HASH_TYPE_SHA3_SHAKE128) << 8);
			w4.s.param2 = (uint16_t)(DAO_LC_CSHAKE_PARAM2 << 12) | (hash_field) |
									ctx->hash.digest_len;
			break;
		case DAO_LC_HASH_TYPE_SHA3_CSHAKE256:
			hash_field = ((DAO_LC_HASH_MASK & DAO_LC_HASH_TYPE_SHA3_SHAKE256) << 8);
			w4.s.param2 = (uint16_t)(DAO_LC_CSHAKE_PARAM2 << 12) | (hash_field) |
									ctx->hash.digest_len;
			break;
		default:
			w4.s.param2 = (sess_meta->hash_type << 8) | ctx->hash.digest_len;
		}
		sess_meta->digest_len = ctx->hash.digest_len;
	} else if (ctx->opcode == DAO_LC_SYM_OPCODE_AES_KEY_WRAP) {
		kek_len = sym_sess_get_aes_kek_len(ctx->aes_key_wrap.aes_kek_type);
		if (kek_len < 0) {
			dao_err("Failed to get KEK length.");
			goto sess_meta_free;
		}

		sess_meta->op_type = LC_SYM_OP_KEY_WRAP_UNWRAP;
		sess_meta->kek_len = kek_len;
		memcpy(sess_meta->kek, ctx->aes_key_wrap.kek, kek_len);
		w4.s.opcode_major = DAO_LC_SYM_OPCODE_AES_KEY_WRAP;
		w4.s.opcode_minor = ((ctx->aes_key_wrap.aes_kek_type & 0x03) << 2);
		w4.s.param2 = 0;
	} else {
		dao_err("Unsupported opcode.");
		goto sess_meta_free;
	}

	sess_meta->w4 = w4.u64;

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
sym_cipher_auth_fc_verify(const struct dao_lc_sym_ctx *ctx)
{
	const struct dao_lc_sym_fc_ctx *fc_ctx;
	int ret;

	fc_ctx = &ctx->fc;

	if (ctx->chain_order != DAO_LC_FC_CIPHER_THEN_AUTH) {
		dao_err("Invalid chained cipher order.");
		return -EINVAL;
	}

	switch (fc_ctx->enc_cipher) {
	case DAO_LC_FC_ENC_CIPHER_AES_CBC:
		break;
	default:
		dao_err("Unsupported chained cipher type.");
		return -EINVAL;
	}

	ret = sym_sess_fc_aes_key_len_verify(fc_ctx);
	if (ret)
		return ret;

	/* For now, auth input type must be Key */
	if (fc_ctx->auth_input_type != DAO_LC_FC_AUTH_INPUT_KEY) {
		dao_err("Invalid authentication input type. Must be set to KEY.");
		return -EINVAL;
	}

	switch (fc_ctx->hash_type) {
	case DAO_LC_HASH_TYPE_SHA1:
		break;
	default:
		dao_err("Unsupported hash type for chained cipher.");
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

	if (fc_ctx->auth_key_src != DAO_LC_FC_AUTH_KEY_SRC_CTX) {
		dao_err("Invalid authentication key source. Must be set to CTX.");
		return -EINVAL;
	}

	if (ctx->is_chained_cipher)
		return sym_cipher_auth_fc_verify(ctx);

	is_aes = false;

	switch (fc_ctx->enc_cipher) {
	case DAO_LC_FC_ENC_CIPHER_AES_CBC:
	case DAO_LC_FC_ENC_CIPHER_AES_GCM:
	case DAO_LC_FC_ENC_CIPHER_AES_CCM:
		is_aes = true;
		break;
	case DAO_LC_FC_ENC_CIPHER_CHACHA:
		if (fc_ctx->hash_type != DAO_LC_HASH_TYPE_POLY1305) {
			dao_err("Unsupported hash type for ChaCha cipher.");
			return -ENOTSUP;
		}
		break;
	case DAO_LC_FC_ENC_CIPHER_NULL:
		if (fc_ctx->hash_type != DAO_LC_HASH_TYPE_GMAC) {
			dao_err("Unsupported hash type for NULL cipher.");
			return -ENOTSUP;
		}
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

	switch (fc_ctx->hash_type) {
	case DAO_LC_HASH_TYPE_NULL:
		break;
	case DAO_LC_HASH_TYPE_GMAC:
		if (fc_ctx->enc_cipher != DAO_LC_FC_ENC_CIPHER_NULL) {
			dao_err("Unsupported cipher type for GMAC.");
			return -ENOTSUP;
		}
		break;
	case DAO_LC_HASH_TYPE_POLY1305:
		if (fc_ctx->enc_cipher != DAO_LC_FC_ENC_CIPHER_CHACHA) {
			dao_err("Unsupported cipher type for Poly1305.");
			return -ENOTSUP;
		}
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
	const struct dao_lc_hmac_hash_ctx *hash_ctx;
	uint16_t digest_len = 0;

	hash_ctx = &ctx->hash;

	switch (hash_ctx->hmac_hash_type) {
	case DAO_LC_HASH_TYPE_SHA1:
	case DAO_LC_HASH_TYPE_SHA2_SHA224:
	case DAO_LC_HASH_TYPE_SHA2_SHA256:
	case DAO_LC_HASH_TYPE_SHA2_SHA384:
	case DAO_LC_HASH_TYPE_SHA2_SHA512:
	case DAO_LC_HASH_TYPE_SHA3_SHA224:
	case DAO_LC_HASH_TYPE_SHA3_SHA256:
	case DAO_LC_HASH_TYPE_SHA3_SHA384:
	case DAO_LC_HASH_TYPE_SHA3_SHA512:
	case DAO_LC_HASH_TYPE_CMAC:
	case DAO_LC_HASH_TYPE_SHA3_SHAKE128:
	case DAO_LC_HASH_TYPE_SHA3_SHAKE256:
	case DAO_LC_HASH_TYPE_SHA3_KMAC128:
	case DAO_LC_HASH_TYPE_SHA3_KMAC256:
	case DAO_LC_HASH_TYPE_SHA3_CSHAKE128:
	case DAO_LC_HASH_TYPE_SHA3_CSHAKE256:
		break;
	default:
		dao_err("Unsupported HMAC/hash type.");
		return -EINVAL;
	}

	if (ctx->opcode == DAO_LC_SYM_OPCODE_HMAC) {
		switch (hash_ctx->hmac_hash_type) {
		case DAO_LC_HASH_TYPE_SHA3_SHAKE128:
		case DAO_LC_HASH_TYPE_SHA3_SHAKE256:
			dao_err("Unsupported HMAC/hash type for HMAC operation.");
			return -ENOTSUP;
		default:
			break;
		}
	} else if (ctx->opcode == DAO_LC_SYM_OPCODE_HASH) {
		switch (hash_ctx->hmac_hash_type) {
		case DAO_LC_HASH_TYPE_SHA3_CSHAKE128:
		case DAO_LC_HASH_TYPE_SHA3_CSHAKE256:
		case DAO_LC_HASH_TYPE_SHA3_KMAC128:
		case DAO_LC_HASH_TYPE_SHA3_KMAC256:
			dao_err("Unsupported HMAC/hash type for HASH operation.");
			return -ENOTSUP;
		default:
			break;
		}
	}

	digest_len = hash_ctx->digest_len;
	switch (hash_ctx->hmac_hash_type) {
	case DAO_LC_HASH_TYPE_SHA3_KMAC128:
	case DAO_LC_HASH_TYPE_SHA3_KMAC256:
	case DAO_LC_HASH_TYPE_SHA3_CSHAKE128:
	case DAO_LC_HASH_TYPE_SHA3_CSHAKE256:
		/* Skip digest length validation for KMAC and cSHAKE */
		break;
	default:
		if ((digest_len == 0) || (digest_len > DAO_LC_MAX_DIGEST_LEN)) {
			dao_err("Invalid digest length for HMAC.");
			return -EINVAL;
		}
		break;
	}

	/*
	 * SHAKE and cSHAKE do not use keys, so skip key-length validation.
	 * KMAC uses its own key length constraints, so validate against KMAC-specific limits.
	 * All other HMAC algorithms validate key length against DAO_LC_MAX_AUTH_KEY_LEN.
	 */
	if (ctx->opcode == DAO_LC_SYM_OPCODE_HMAC) {
		switch (hash_ctx->hmac_hash_type) {
		case DAO_LC_HASH_TYPE_SHA3_SHAKE128:
		case DAO_LC_HASH_TYPE_SHA3_SHAKE256:
		case DAO_LC_HASH_TYPE_SHA3_CSHAKE128:
		case DAO_LC_HASH_TYPE_SHA3_CSHAKE256:
			break;
		case DAO_LC_HASH_TYPE_SHA3_KMAC128:
		case DAO_LC_HASH_TYPE_SHA3_KMAC256:
			if ((hash_ctx->hmac_key_len == 0) ||
			    (hash_ctx->hmac_key_len > DAO_LC_KMAC_MAX_AUTH_KEY_LEN)) {
				dao_err("Invalid key length for KMAC operation.");
				return -EINVAL;
			}
			break;
		default:
			if ((hash_ctx->hmac_key_len == 0) ||
			    (hash_ctx->hmac_key_len > DAO_LC_MAX_AUTH_KEY_LEN)) {
				dao_err("Invalid HMAC key length.");
				return -EINVAL;
			}
			break;
		}
	}

	return 0;
}

static int
sym_sess_kek_type_verify(enum dao_lc_fc_aes_key_len aes_kek_type)
{
	switch (aes_kek_type) {
	case DAO_LC_FC_AES_KEY_LEN_128:
	case DAO_LC_FC_AES_KEY_LEN_192:
	case DAO_LC_FC_AES_KEY_LEN_256:
		return 0;
	}

	return -EINVAL;
}

static int
sym_sess_kek_verify(const struct dao_lc_sym_ctx *ctx)
{
	const struct dao_lc_aes_key_wrap_ctx *kek_ctx;
	int rc;

	kek_ctx = &ctx->aes_key_wrap;

	rc = sym_sess_kek_type_verify(kek_ctx->aes_kek_type);
	if (rc < 0) {
		dao_err("Invalid KEK type. Valid types are DAO_LC_FC_AES_KEY_LEN_128, DAO_LC_FC_AES_KEY_LEN_192, DAO_LC_FC_AES_KEY_LEN_256.");
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
	case DAO_LC_SYM_OPCODE_HMAC:
		return sym_sess_hash_verify(ctx);
	case DAO_LC_SYM_OPCODE_AES_KEY_WRAP:
		return sym_sess_kek_verify(ctx);
	default:
		dao_err("Unsupported opcode.");
		return -EINVAL;
	}

	return 0;
}

static int
lc_sym_op_cipher_only_validate(const struct dao_lc_sym_op *op,
			       const struct dao_lc_sym_sess_meta *sess_meta)
{
	if (sess_meta->alg_iv_len && op->cipher_iv == NULL) {
		dao_err("Invalid cipher IV pointer for cipher only operation.");
		return -EINVAL;
	}

	if (op->cipher_len == 0) {
		dao_err("Invalid cipher length for cipher only operation.");
		return -EINVAL;
	}

	if (op->cipher_offset + op->cipher_len > op->in_buffer->total_len) {
		dao_err("Cipher offset and length exceed input buffer total length.");
		return -EINVAL;
	}

	if (op->cipher_len & 0xf) {
		if (sess_meta->cipher_type == DAO_LC_FC_ENC_CIPHER_AES_CBC) {
			dao_err("Invalid cipher length. cipher_len = %u", op->cipher_len);
			return -EINVAL;
		}
	}

	if (op->out_buffer != NULL) {
		if (op->out_buffer->total_len < op->cipher_len + op->cipher_offset) {
			dao_err("Output buffer total length is less than cipher length.");
			return -EINVAL;
		}
	}

	return 0;
}

static int
lc_sym_op_auth_only_validate(const struct dao_lc_sym_op *op,
			     const struct dao_lc_sym_sess_meta *sess_meta)
{
	if (op->auth_offset + op->auth_len > op->in_buffer->total_len) {
		dao_err("Auth offset and length exceed input buffer total length.");
		return -EINVAL;
	}

	if (op->digest == NULL) {
		dao_err("Invalid digest pointer for auth only operation.");
		return -EINVAL;
	}

	if (sess_meta->digest_len == 0 || sess_meta->digest_len > DAO_LC_MAX_DIGEST_LEN) {
		dao_err("Invalid digest length. digest_len: %d.", sess_meta->digest_len);
		return -EINVAL;
	}

	if (sess_meta->hash_type == DAO_LC_HASH_TYPE_GMAC) {
		if (sess_meta->alg_iv_len != 12 || op->auth_iv == NULL) {
			dao_err("Invalid auth IV pointer for GMAC operation.");
			return -EINVAL;
		}
	}

	if ((sess_meta->hash_type == DAO_LC_HASH_TYPE_SHA3_KMAC128) ||
	    (sess_meta->hash_type == DAO_LC_HASH_TYPE_SHA3_KMAC256)) {
		if (op->kmac_params.custom_string == NULL) {
			dao_err("Invalid custom-string pointer for KMAC operation.");
			return -EINVAL;
		}
		if ((op->kmac_params.output_len == 0) ||
		    (op->kmac_params.output_len > DAO_LC_MAX_DIGEST_LEN)) {
			dao_err("Invalid output length for KMAC operation. output_len: %d.",
				op->kmac_params.output_len);
			return -EINVAL;
		}
		if (op->kmac_params.custom_string_len > DAO_LC_SHA3_MAX_CUSTOM_STRING_LEN) {
			dao_err("Invalid custom-string length for KMAC operation. custom_string_len:%d.",
				op->kmac_params.custom_string_len);
			return -EINVAL;
		}
	}

	if ((sess_meta->hash_type == DAO_LC_HASH_TYPE_SHA3_CSHAKE128) ||
	    (sess_meta->hash_type == DAO_LC_HASH_TYPE_SHA3_CSHAKE256)) {
		if (op->cshake_params.custom_string == NULL) {
			dao_err("Invalid custom-string pointer for cSHAKE operation.");
			return -EINVAL;
		}
		if ((op->cshake_params.output_len == 0) ||
		    (op->cshake_params.output_len > DAO_LC_MAX_DIGEST_LEN)) {
			dao_err("Invalid output length for cSHAKE operation. output_len: %d.",
				op->cshake_params.output_len);
			return -EINVAL;
		}
		if (op->cshake_params.custom_string_len > DAO_LC_SHA3_MAX_CUSTOM_STRING_LEN) {
			dao_err("Invalid custom-string length for cSHAKE operation. custom_string_len: %d.",
				op->cshake_params.custom_string_len);
			return -EINVAL;
		}
		if (op->cshake_params.function_name_len > DAO_LC_SHA3_MAX_FUNCTION_NAME_LEN) {
			dao_err("Invalid function-name length for cSHAKE operation. function_name_len: %d.",
				op->cshake_params.function_name_len);
			return -EINVAL;
		}
	}

	return 0;
}

static int
lc_sym_op_cipher_auth_validate(const struct dao_lc_sym_op *op,
			       const struct dao_lc_sym_sess_meta *sess_meta)
{
	uint16_t cipher_offset = op->cipher_offset, auth_offset = op->auth_offset;
	uint16_t cipher_len = op->cipher_len, auth_len = op->auth_len;
	uint16_t digest_len_in_pkt = 0, total_len_reqd = 0;

	if (sess_meta->alg_iv_len && op->cipher_iv == NULL) {
		dao_err("Invalid cipher IV pointer for cipher auth operation.");
		return -EINVAL;
	}

	if (cipher_len & 0xf) {
		if (sess_meta->cipher_type == DAO_LC_FC_ENC_CIPHER_AES_CBC) {
			dao_err("Invalid cipher length. cipher_len = %u", cipher_len);
			return -EINVAL;
		}
	}

	if (cipher_offset < auth_offset) {
		dao_err("Cipher offset is less than auth offset.");
		return -EINVAL;
	}

	if ((cipher_offset - auth_offset) > 1024) {
		dao_err("Cipher and auth offsets difference exceed 1024 bytes.");
		return -EINVAL;
	}

	if ((cipher_offset - auth_offset) & 0x7) {
		dao_err("Cipher and auth offsets difference is not multiple of 8 bytes.");
		return -EINVAL;
	}

	if ((auth_offset + auth_len) < (cipher_offset + cipher_len)) {
		dao_err("Cipher end offset is more than auth end offset.");
		return -EINVAL;
	}

	if ((auth_offset + auth_len) - (cipher_offset + cipher_len) > 56) {
		dao_err("Auth end offset is more than 56 bytes after cipher end offset.");
		return -EINVAL;
	}

	if (auth_offset + auth_len > op->in_buffer->total_len) {
		dao_err("Auth offset and length exceed input buffer total length.");
		return -EINVAL;
	}

	if (op->aad_len != 0) {
		dao_err("AAD length must be zero for cipher auth operation.");
		return -EINVAL;
	}

	if ((sess_meta->digest_len != 0) && (op->digest == NULL))
		digest_len_in_pkt = sess_meta->digest_len;

	total_len_reqd = auth_offset + auth_len + digest_len_in_pkt;

	if (op->out_buffer != NULL) {
		if (op->encrypt) {
			if (op->in_buffer->total_len != auth_offset + auth_len) {
				dao_err("Auth region and input region (without digest) must end at the same point.");
				return -EINVAL;
			}
		} else {
			if (op->in_buffer->total_len < total_len_reqd) {
				dao_err("Input buffer total length is less than required length.");
				return -EINVAL;
			}
		}

		if (op->out_buffer->total_len < auth_offset + auth_len) {
			dao_err("Output buffer total length is less than required length.");
			return -EINVAL;
		}
	} else {
		if (op->in_buffer->total_len != total_len_reqd) {
			dao_err("Auth region and input region (without digest) must end at the same point.");
			return -EINVAL;
		}
	}

	return 0;
}

static int
lc_sym_op_aead_validate(const struct dao_lc_sym_op *op,
			const struct dao_lc_sym_sess_meta *sess_meta)
{
	uint16_t digest_len_in_pkt = 0, total_len_reqd = 0;

	if (sess_meta->alg_iv_len && op->cipher_iv == NULL) {
		dao_err("Invalid cipher IV pointer for AEAD operation.");
		return -EINVAL;
	}

	if (op->cipher_offset + op->cipher_len > op->in_buffer->total_len) {
		dao_err("Cipher offset and length exceed input buffer total length.");
		return -EINVAL;
	}

	if (op->aad == NULL && op->aad_len != 0) {
		dao_err("Invalid AAD.");
		return -EINVAL;
	}

	if (op->aad_len > 1024) {
		dao_err("AAD too long. aad_len = %u", op->aad_len);
		return -ENOTSUP;
	}

	if ((sess_meta->digest_len != 0) && (op->digest == NULL))
		digest_len_in_pkt = sess_meta->digest_len;

	total_len_reqd = op->cipher_offset + op->cipher_len + digest_len_in_pkt;

	if (op->out_buffer != NULL) {
		if (op->encrypt) {
			if (op->out_buffer->total_len < total_len_reqd) {
				dao_err("Output buffer total length is less than required length.");
				return -EINVAL;
			}
		} else {
			if (op->out_buffer->total_len < op->cipher_offset + op->cipher_len) {
				dao_err("Output buffer total length is less than required length.");
				return -EINVAL;
			}
		}
	} else {
		if (op->in_buffer->total_len < total_len_reqd) {
			dao_err("Input buffer total length is less than required length.");
			return -EINVAL;
		}
	}

	return 0;
}

static inline bool
lc_sym_op_is_empty_buf_allowed(enum lc_crypto_op_type op_type)
{
	if ((op_type == LC_SYM_OP_AUTH_ONLY) || (op_type == LC_SYM_OP_HMAC_AUTH_ONLY) ||
	    (op_type == LC_SYM_OP_AEAD) || (op_type == LC_SYM_OP_CIPHER_AUTH))
		return true;

	return false;
}

int
lc_sym_aes_key_wrap_param_validate(const struct dao_lc_sym_op *op,
				   const struct dao_lc_sym_sess_meta *sess_meta)
{
	uint32_t output_len_required = 0;
	uint16_t key_len, kek_len;

	key_len = op->wrap_unwrap_key_len;
	kek_len = sess_meta->kek_len;

	if (key_len == 0) {
		dao_err("Key length cannot be zero.");
		return -EINVAL;
	}

	if (kek_len == 0) {
		dao_err("KEK length cannot be zero.");
		return -EINVAL;
	}

	if (kek_len != DAO_LC_AES_KEY_LEN_16_BYTES && kek_len != DAO_LC_AES_KEY_LEN_24_BYTES &&
	    kek_len != DAO_LC_AES_KEY_LEN_32_BYTES) {
		dao_err("Invalid KEK length (%u). KEK length must be 16, 24, or 32 bytes", kek_len);
		return -EINVAL;
	}

	if (!op->is_wrap_pad) {
		if (key_len < 16) {
			dao_err("Invalid key length (%u). Key length is too small for AES-KW and minimum key length must be 16 bytes.",
				key_len);
			return -EINVAL;
		}

		if (key_len % 8 != 0) {
			dao_err("Invalid key length (%u). Key length must be a multiple of 8 bytes.",
				key_len);
			return -EINVAL;
		}
	}

	if (key_len > DAO_LC_AES_KEY_WRAP_MAX_KEY_DATA_LEN) {
		dao_err("Invalid key length (%u). Key length exceeds maximum limit (%u bytes).",
			key_len, DAO_LC_AES_KEY_WRAP_MAX_KEY_DATA_LEN);
		return -EINVAL;
	}

	/* For wrap operations, check output buffer size */
	if (op->is_wrap) {
		/* AES Key Wrap adds 8 bytes of authentication data */
		output_len_required = key_len + 8;

		if (op->out_buffer != NULL) {
			if (op->out_buffer->total_len < output_len_required) {
				dao_err("Output buffer too small for wrapped key. Needs %u bytes.",
					output_len_required);
				return -EINVAL;
			}
		} else {
			/* For in-place operation */
			if (op->in_buffer->total_len < output_len_required) {
				dao_err("In-place buffer too small for wrapped key. Needs %u bytes.",
					output_len_required);
				return -EINVAL;
			}
		}
	}

	return 0;
}

int
lc_sym_op_validate(struct dao_lc_sym_op *op)
{
	struct dao_lc_sym_sess_meta *sess_meta;
	enum lc_crypto_op_type op_type;
	int ret;

	if (op == NULL) {
		dao_err("Invalid operation pointer.");
		return -EINVAL;
	}

	if (liquid_crypto_sym_sess_meta_lookup(op->sess_id) != 0) {
		dao_err("Invalid session id. sess_id = %lu", op->sess_id);
		return -EINVAL;
	}

	sess_meta = DAO_LC_SYM_META_GET_PTR(op->sess_id);
	op_type = sess_meta->op_type;

	ret = lc_buf_validate(op->in_buffer, lc_sym_op_is_empty_buf_allowed(op_type));
	if (ret != 0) {
		dao_err("Invalid input buffer.");
		return ret;
	}

	if (!lc_sym_op_is_empty_buf_allowed(op_type) && op->out_buffer != NULL) {
		ret = lc_buf_validate(op->out_buffer, false);
		if (ret != 0) {
			dao_err("Invalid output buffer.");
			return ret;
		}
	}

	switch (op_type) {
	case LC_SYM_OP_CIPHER_ONLY:
		ret = lc_sym_op_cipher_only_validate(op, sess_meta);
		if (ret)
			return ret;
		break;
	case LC_SYM_OP_AUTH_ONLY:
	case LC_SYM_OP_HMAC_AUTH_ONLY:
		ret = lc_sym_op_auth_only_validate(op, sess_meta);
		if (ret)
			return ret;
		break;
	case LC_SYM_OP_CIPHER_AUTH:
		ret = lc_sym_op_cipher_auth_validate(op, sess_meta);
		if (ret)
			return ret;
		break;
	case LC_SYM_OP_AEAD:
		ret = lc_sym_op_aead_validate(op, sess_meta);
		if (ret)
			return ret;
		break;
	case LC_SYM_OP_KEY_WRAP_UNWRAP:
		ret = lc_sym_aes_key_wrap_param_validate(op, sess_meta);
		if (ret)
			return ret;
		break;
	default:
		dao_err("Invalid operation type: %d", op_type);
		return -EINVAL;
	}

	if (sess_meta->alg_iv_len != sess_meta->pkt_iv_len) {
		switch (sess_meta->cipher_type) {
		case DAO_LC_FC_ENC_CIPHER_AES_GCM:
		case DAO_LC_FC_ENC_CIPHER_AES_CCM:
			break;
		case DAO_LC_FC_ENC_CIPHER_NULL:
			if (sess_meta->hash_type != DAO_LC_HASH_TYPE_GMAC) {
				dao_err("Unsupported hash type for NULL cipher.");
				return -ENOTSUP;
			}
			break;
		case DAO_LC_FC_ENC_CIPHER_CHACHA:
			if (sess_meta->hash_type != DAO_LC_HASH_TYPE_POLY1305) {
				dao_err("Unsupported hash type for ChaCha cipher.");
				return -ENOTSUP;
			}
			break;
		default:
			dao_err("Invalid IV length for cipher type: %d", sess_meta->cipher_type);
			return -EINVAL;
		}
	}

	return 0;
}
