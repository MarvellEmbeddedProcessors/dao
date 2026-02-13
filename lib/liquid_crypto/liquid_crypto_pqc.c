/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2026 Marvell.
 */

#include <errno.h>

#include <dao_liquid_crypto.h>
#include <dao_log.h>

#include "liquid_crypto_pqc.h"

static inline bool
lc_pqc_alg_is_kem(enum dao_lc_pqc_alg alg)
{
	return ((alg >= DAO_LC_ML_KEM_512) && (alg <= DAO_LC_ML_KEM_1024));
}

static inline bool
lc_pqc_alg_is_dsa(enum dao_lc_pqc_alg alg)
{
	return ((alg >= DAO_LC_ML_DSA_44) && (alg <= DAO_LC_ML_DSA_87));
}

static int
lc_pqc_op_kem_keygen_validate(struct dao_lc_pqc_op *op)
{
	if (!lc_pqc_alg_is_kem(op->alg)) {
		dao_err("Invalid algorithm for KEM keygen operation %d.", op->alg);
		return -EINVAL;
	}
	if (op->keygen.pub_key == NULL || op->keygen.priv_key == NULL) {
		dao_err("Invalid key generation parameters.");
		return -EINVAL;
	}
	return 0;
}

static int
lc_pqc_op_kem_encap_validate(struct dao_lc_pqc_op *op)
{
	if (!lc_pqc_alg_is_kem(op->alg)) {
		dao_err("Invalid algorithm for KEM encap operation %d.", op->alg);
		return -EINVAL;
	}
	if (op->encap.enc_key == NULL || op->encap.shared_secret == NULL ||
	    op->encap.ciphertext == NULL) {
		dao_err("Invalid encap parameters.");
		return -EINVAL;
	}
	return 0;
}

static int
lc_pqc_op_kem_decap_validate(struct dao_lc_pqc_op *op)
{
	if (!lc_pqc_alg_is_kem(op->alg)) {
		dao_err("Invalid algorithm for KEM decap operation %d.", op->alg);
		return -EINVAL;
	}
	if (op->decap.dec_key == NULL || op->decap.ciphertext == NULL ||
	    op->decap.shared_secret == NULL) {
		dao_err("Invalid decap parameters.");
		return -EINVAL;
	}
	return 0;
}

static int
lc_pqc_op_dsa_keygen_validate(struct dao_lc_pqc_op *op)
{
	if (!lc_pqc_alg_is_dsa(op->alg)) {
		dao_err("Invalid algorithm for DSA keygen operation %d.", op->alg);
		return -EINVAL;
	}
	if (op->keygen.pub_key == NULL || op->keygen.priv_key == NULL) {
		dao_err("Invalid key generation parameters.");
		return -EINVAL;
	}
	return 0;
}

static int
lc_pqc_op_dsa_sign_validate(struct dao_lc_pqc_op *op)
{
	if (!lc_pqc_alg_is_dsa(op->alg)) {
		dao_err("Invalid algorithm for DSA sign operation %d.", op->alg);
		return -EINVAL;
	}
	if (op->sign.priv_key == NULL || op->sign.signature == NULL) {
		dao_err("Invalid sign parameters.");
		return -EINVAL;
	}
	if (op->sign.msg_len > 0 && op->sign.msg == NULL) {
		dao_err("Invalid sign parameters.");
		return -EINVAL;
	}
	if (op->sign.ctx_len > 0 && op->sign.ctx == NULL) {
		dao_err("Invalid sign parameters.");
		return -EINVAL;
	}
	if (op->sign.ctx_len > DAO_LC_ML_DSA_CTX_LEN_MAX) {
		dao_err("ctx_len %u exceeds max %u.", op->sign.ctx_len, DAO_LC_ML_DSA_CTX_LEN_MAX);
		return -EINVAL;
	}
	return 0;
}

static int
lc_pqc_op_dsa_verify_validate(struct dao_lc_pqc_op *op)
{
	if (!lc_pqc_alg_is_dsa(op->alg)) {
		dao_err("Invalid algorithm for DSA verify operation %d.", op->alg);
		return -EINVAL;
	}
	if (op->verify.pub_key == NULL || op->verify.signature == NULL) {
		dao_err("Invalid verify parameters.");
		return -EINVAL;
	}
	if (op->verify.msg_len > 0 && op->verify.msg == NULL) {
		dao_err("Invalid verify parameters.");
		return -EINVAL;
	}
	if (op->verify.ctx_len > 0 && op->verify.ctx == NULL) {
		dao_err("Invalid verify parameters.");
		return -EINVAL;
	}
	if (op->verify.ctx_len > DAO_LC_ML_DSA_CTX_LEN_MAX) {
		dao_err("ctx_len %u exceeds max %u.", op->verify.ctx_len,
			DAO_LC_ML_DSA_CTX_LEN_MAX);
		return -EINVAL;
	}
	return 0;
}

int
lc_pqc_op_validate(struct dao_lc_pqc_op *op)
{
	enum dao_lc_pqc_op_type op_type;
	enum dao_lc_pqc_alg alg;
	int ret;

	if (op == NULL) {
		dao_err("Invalid operation pointer.");
		return -EINVAL;
	}

	op_type = op->op_type;
	alg = op->alg;

	if (alg >= DAO_LC_ML_PQC_ALG_END || alg <= 0) {
		dao_err("Unsupported PQC algorithm: %d", alg);
		return -EINVAL;
	}

	switch (op_type) {
	case DAO_LC_ML_KEM_OP_KEYGEN:
		ret = lc_pqc_op_kem_keygen_validate(op);
		if (ret)
			return ret;
		break;
	case DAO_LC_ML_KEM_OP_ENCAP:
		ret = lc_pqc_op_kem_encap_validate(op);
		if (ret)
			return ret;
		break;
	case DAO_LC_ML_KEM_OP_DECAP:
		ret = lc_pqc_op_kem_decap_validate(op);
		if (ret)
			return ret;
		break;
	case DAO_LC_ML_DSA_OP_KEYGEN:
		ret = lc_pqc_op_dsa_keygen_validate(op);
		if (ret)
			return ret;
		break;
	case DAO_LC_ML_DSA_OP_SIGN:
		ret = lc_pqc_op_dsa_sign_validate(op);
		if (ret)
			return ret;
		break;
	case DAO_LC_ML_DSA_OP_VERIFY:
		ret = lc_pqc_op_dsa_verify_validate(op);
		if (ret)
			return ret;
		break;
	default:
		dao_err("Invalid operation type: %d", op_type);
		return -EINVAL;
	}
	return 0;
}
