/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>
#include <stddef.h>

#include <rte_malloc.h>

#include <dao_liquid_crypto.h>
#include <dao_log.h>

#include "liquid_crypto_op_defines.h"
#include "liquid_crypto_sym.h"

#include "hw/cpt.h"
#include "mc/se.h"

#define DAO_LC_OPCODE_IV_LENGTH_MASK (1 << 5)

static TAILQ_HEAD(dao_lc_sym_sess_meta_list, dao_lc_sym_sess_meta)
	sym_sess_list_head = TAILQ_HEAD_INITIALIZER(sym_sess_list_head);

static int
sym_sess_fc_iv_len_validate(const struct dao_lc_sym_ctx *ctx)
{
	switch (ctx->fc.enc_cipher) {
	case DAO_LC_FC_ENC_CIPHER_AES_CBC:
		if (ctx->iv_len == 16)
			return 0;
		break;
	case DAO_LC_FC_ENC_CIPHER_AES_GCM:
		if (ctx->iv_len == 12)
			return 0;
		break;
	case DAO_LC_FC_ENC_CIPHER_AES_CCM:
		if (ctx->iv_len >= 7 && ctx->iv_len <= 13)
			return 0;
		break;
	case DAO_LC_FC_ENC_CIPHER_NULL:
		if (ctx->fc.hash_type != DAO_LC_FC_HASH_TYPE_GMAC) {
			dao_err("Unsupported hash type for NULL cipher.");
			return -ENOTSUP;
		}
		if (ctx->iv_len == 12)
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
	switch (ctx->fc.enc_cipher) {
	case DAO_LC_FC_ENC_CIPHER_AES_CBC:
		return 0;
	case DAO_LC_FC_ENC_CIPHER_AES_GCM:
		if (ctx->fc.mac_len == 16)
			return 0;
		break;
	case DAO_LC_FC_ENC_CIPHER_AES_CCM:
		if (ctx->fc.mac_len == 8)
			return 0;
		break;
	case DAO_LC_FC_ENC_CIPHER_NULL:
		if (ctx->fc.hash_type != DAO_LC_FC_HASH_TYPE_GMAC) {
			dao_err("Unsupported hash type for NULL cipher.");
			return -ENOTSUP;
		}
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
	case DAO_LC_FC_HASH_TYPE_SHA2_SHA224:
		if (ctx->fc.mac_len == 28)
			return 0;
		break;
	case DAO_LC_FC_HASH_TYPE_SHA2_SHA256:
		if (ctx->fc.mac_len == 32)
			return 0;
		break;
	case DAO_LC_FC_HASH_TYPE_SHA2_SHA384:
		if (ctx->fc.mac_len == 48)
			return 0;
		break;
	case DAO_LC_FC_HASH_TYPE_SHA2_SHA512:
		if (ctx->fc.mac_len == 64)
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
sym_sess_hmac_hash_digest_len_validate(const struct dao_lc_sym_ctx *ctx)
{
	switch (ctx->hash.hmac_hash_type) {
	case DAO_LC_FC_HMAC_TYPE_SHA1:
		if (ctx->hash.digest_len == 20)
			return 0;
		break;
	default:
		dao_err("Unsupported HMAC hash type.");
		return -ENOTSUP;
	}
	dao_err("Invalid digest length for HMAC hash type.");
	return -EINVAL;
}

struct dao_lc_sym_sess_meta *
liquid_crypto_sym_sess_meta_alloc(const struct dao_lc_sym_ctx *ctx)
{
	struct dao_lc_sym_sess_meta *sess_meta;
	union cpt_inst_w4 w4 = {0};
	uint8_t hash_type;

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

		if (ctx->fc.enc_cipher == DAO_LC_FC_ENC_CIPHER_AES_GCM) {
			w4.s.opcode_minor |= DAO_LC_OPCODE_IV_LENGTH_MASK;
			sess_meta->op_type = LC_SYM_OP_AEAD;
			/* When IV len is 12, 4B would be added by LC layer and submitted. */
			if (sess_meta->alg_iv_len == 12)
				sess_meta->pkt_iv_len = 16;
		}

		if (ctx->fc.hash_type == DAO_LC_FC_HASH_TYPE_GMAC) {
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

		sess_meta->hash_type = ctx->fc.hash_type;
		sess_meta->op_type = LC_SYM_OP_AUTH_ONLY;
		w4.s.opcode_major = ROC_SE_MAJOR_OP_HASH;
		w4.s.opcode_minor = 0x0;
		w4.s.param1 = 0;
		w4.s.param2 = ((uint16_t)ctx->fc.hash_type << 8) | (uint16_t)ctx->fc.mac_len;
		sess_meta->digest_len = ctx->fc.mac_len;
	} else if (ctx->opcode == DAO_LC_SYM_OPCODE_HMAC) {
		if (sym_sess_hmac_hash_digest_len_validate(ctx))
			goto sess_meta_free;
		switch (ctx->hash.hmac_hash_type) {
		case DAO_LC_FC_HMAC_TYPE_SHA1:
			hash_type = DAO_LC_FC_HASH_TYPE_SHA1;
			break;
		default:
			hash_type = DAO_LC_FC_HASH_TYPE_NULL;
			break;
		}

		sess_meta->hash_type = ctx->hash.hmac_hash_type;
		sess_meta->op_type = LC_SYM_OP_HMAC_AUTH_ONLY;
		sess_meta->auth_key_len = ctx->hash.hmac_key_len;
		memcpy(sess_meta->auth_key, ctx->hash.hmac_auth_key, ctx->hash.hmac_key_len);

		w4.s.opcode_major = ROC_SE_MAJOR_OP_HMAC;
		w4.s.opcode_minor = 0x0;
		w4.s.param1 = ctx->hash.hmac_key_len;
		w4.s.param2 = (hash_type << 8) | ctx->hash.digest_len;
		sess_meta->digest_len = ctx->hash.digest_len;
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
	case DAO_LC_FC_ENC_CIPHER_AES_CCM:
		is_aes = true;
		break;
	case DAO_LC_FC_ENC_CIPHER_NULL:
		if (fc_ctx->hash_type != DAO_LC_FC_HASH_TYPE_GMAC) {
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

	if (fc_ctx->auth_key_src != DAO_LC_FC_AUTH_KEY_SRC_CTX) {
		dao_err("Invalid authentication key source. Must be set to CTX.");
		return -EINVAL;
	}

	switch (fc_ctx->hash_type) {
	case DAO_LC_FC_HASH_TYPE_NULL:
	case DAO_LC_FC_HASH_TYPE_GMAC:
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
	const struct dao_lc_hmac_hash_ctx *hash_ctx;

	fc_ctx = &ctx->fc;
	hash_ctx = &ctx->hash;

	if (ctx->opcode == DAO_LC_SYM_OPCODE_HASH) {
		switch (fc_ctx->hash_type) {
		case DAO_LC_FC_HASH_TYPE_SHA1:
		case DAO_LC_FC_HASH_TYPE_SHA2_SHA224:
		case DAO_LC_FC_HASH_TYPE_SHA2_SHA256:
		case DAO_LC_FC_HASH_TYPE_SHA2_SHA384:
		case DAO_LC_FC_HASH_TYPE_SHA2_SHA512:
			break;
		default:
			dao_err("Unsupported hash type.");
			return -EINVAL;
		}
	} else if (ctx->opcode == DAO_LC_SYM_OPCODE_HMAC) {
		switch (hash_ctx->hmac_hash_type) {
		case DAO_LC_FC_HMAC_TYPE_SHA1:
			break;
		default:
			dao_err("Unsupported HMAC hash type.");
			return -EINVAL;
		}

		if (hash_ctx->digest_len == 0 || hash_ctx->digest_len > DAO_LC_MAX_DIGEST_LEN) {
			dao_err("Invalid digest length for HMAC.");
			return -EINVAL;
		}

		if (hash_ctx->hmac_key_len == 0 ||
		    hash_ctx->hmac_key_len > DAO_LC_MAX_AUTH_KEY_LEN) {
			dao_err("Invalid HMAC key length.");
			return -EINVAL;
		}
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

	if (op->cipher_len == 0 && sess_meta->hash_type != DAO_LC_FC_HASH_TYPE_GMAC) {
		dao_err("Invalid cipher length for AEAD operation.");
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
		if (op->out_buffer->total_len < total_len_reqd) {
			dao_err("Output buffer total length is less than cipher length.");
			return -EINVAL;
		}
	} else {
		if (op->in_buffer->total_len < total_len_reqd) {
			dao_err("Input buffer total length is less than cipher length.");
			return -EINVAL;
		}
	}

	return 0;
}

int
lc_sym_op_validate(struct dao_lc_sym_op *op)
{
	struct dao_lc_sym_sess_meta *sess_meta;
	uint32_t pkt_len, out_pkt_len;
	enum lc_crypto_op_type op_type;
	struct dao_lc_buf *buf;
	int ret;

	if (op == NULL) {
		dao_err("Invalid operation pointer.");
		return -EINVAL;
	}

	if (op->in_buffer == NULL) {
		dao_err("Invalid input buffer pointer.");
		return -EINVAL;
	}

	if (liquid_crypto_sym_sess_meta_lookup(op->sess_id) != 0) {
		dao_err("Invalid session id. sess_id = %lu", op->sess_id);
		return -EINVAL;
	}

	if (op->in_buffer->total_len == 0) {
		dao_err("Invalid input buffer total length.");
		return -EINVAL;
	}

	pkt_len = 0;
	buf = op->in_buffer;
	do {
		if (buf->data == NULL) {
			dao_err("Invalid input buffer fragment data pointer.");
			return -EINVAL;
		}
		if (buf->frag_len == 0) {
			dao_err("Invalid input buffer fragment length.");
			return -EINVAL;
		}
		pkt_len += buf->frag_len;
		buf = buf->next;
	} while (buf != NULL);

	if (pkt_len != op->in_buffer->total_len) {
		dao_err("Input buffer total length does not match fragment lengths.");
		return -EINVAL;
	}

	if (op->out_buffer != NULL) {
		out_pkt_len = 0;
		buf = op->out_buffer;
		do {
			if (buf->data == NULL) {
				dao_err("Invalid output buffer fragment data pointer.");
				return -EINVAL;
			}
			if (buf->frag_len == 0) {
				dao_err("Invalid output buffer fragment length.");
				return -EINVAL;
			}
			out_pkt_len += buf->frag_len;
			buf = buf->next;
		} while (buf != NULL);

		if (out_pkt_len != op->out_buffer->total_len) {
			dao_err("Output buffer total length does not match fragment lengths.");
			return -EINVAL;
		}
	}

	sess_meta = DAO_LC_SYM_META_GET_PTR(op->sess_id);
	op_type = sess_meta->op_type;

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
		break;
	case LC_SYM_OP_AEAD:
		ret = lc_sym_op_aead_validate(op, sess_meta);
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
			if (sess_meta->hash_type != DAO_LC_FC_HASH_TYPE_GMAC) {
				dao_err("Unsupported hash type for NULL cipher.");
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
