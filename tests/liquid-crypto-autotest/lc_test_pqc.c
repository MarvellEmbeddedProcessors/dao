/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2026 Marvell.
 */

#include <errno.h>

#include <rte_cycles.h>
#include <rte_hexdump.h>
#include <rte_malloc.h>
#include <rte_random.h>

#include <dao_liquid_crypto.h>
#include <hw/cpt.h>

#include "lc_autotest.h"
#include "lc_test_generic.h"
#include "lc_test_pqc.h"
#include "test.h"

static struct test_pqc_params ml_kem_512_params = {
	.alg = DAO_LC_ML_KEM_512,
};

static struct test_pqc_params ml_kem_768_params = {
	.alg = DAO_LC_ML_KEM_768,
};

static struct test_pqc_params ml_kem_1024_params = {
	.alg = DAO_LC_ML_KEM_1024,
};

static struct test_pqc_params ml_dsa_44_params = {
	.alg = DAO_LC_ML_DSA_44,
};

static struct test_pqc_params ml_dsa_65_params = {
	.alg = DAO_LC_ML_DSA_65,
};

static struct test_pqc_params ml_dsa_87_params = {
	.alg = DAO_LC_ML_DSA_87,
};

int
pqc_testsuite_setup(void)
{
	uint8_t dev_id = glb_params.dev_id;
	struct dao_lc_dev_caps caps = {0};
	int ret;

	ret = dao_liquid_crypto_dev_caps_get(&caps);
	if (ret < 0) {
		TEST_LC_ERR("Could not get liquid crypto device %d capabilities", dev_id);
		return TEST_SKIPPED;
	}

	if (caps.pqc_en)
		return 0;

	return TEST_SKIPPED;
}

static int
test_ml_kem(const void *data)
{
	const struct test_pqc_params *params = data;
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	uint8_t *shared_secret_e = NULL;
	uint8_t *shared_secret_d = NULL;
	struct dao_lc_pqc_op op = {0};
	struct dao_lc_res res = {0};
	uint8_t *ciphertext = NULL;
	uint8_t *priv_key = NULL;
	uint8_t *pub_key = NULL;
	int ret = 0;

	pub_key = rte_zmalloc("ml_kem_pub_key", pqc_ml_pub_key_len[params->alg], 0);
	if (pub_key == NULL)
		return TEST_FAILED;
	priv_key = rte_zmalloc("ml_kem_priv_key", pqc_ml_priv_key_len[params->alg], 0);
	if (priv_key == NULL) {
		ret = TEST_FAILED;
		goto pub_key_free;
	}
	shared_secret_e = rte_zmalloc("ml_kem_shared_secret_e", DAO_LC_ML_KEM_SHARED_SECRET_LEN, 0);
	if (shared_secret_e == NULL) {
		ret = TEST_FAILED;
		goto priv_key_free;
	}
	shared_secret_d = rte_zmalloc("ml_kem_shared_secret_d", DAO_LC_ML_KEM_SHARED_SECRET_LEN, 0);
	if (shared_secret_d == NULL) {
		ret = TEST_FAILED;
		goto shared_sec_e_free;
	}
	ciphertext = rte_zmalloc("ml_kem_ciphertext", pqc_ml_ciphertext_len[params->alg], 0);
	if (ciphertext == NULL) {
		ret = TEST_FAILED;
		goto shared_sec_d_free;
	}

	/* Generate keys */
	op.alg = params->alg;
	op.op_type = DAO_LC_ML_KEM_OP_KEYGEN;
	op.keygen.pub_key = pub_key;
	op.keygen.priv_key = priv_key;
	op.keygen.seed = NULL; /* No seed for key generation */

	ret = dao_liquid_crypto_pqc_enqueue(dev_id, qp_id, &op, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue PQC ML KEM operation. Error: %d", ret);
		ret = TEST_FAILED;
		goto exit;
	}
	/* Dequeue the operation */
	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue PQC ML KEM operation. Error: %d", ret);
		ret = TEST_FAILED;
		goto exit;
	}
	if (res.res.pqc.compcode != DAO_PQC_COMP_GOOD) {
		TEST_LC_ERR("PQC ML KEM operation failed with ret_code: %d", res.res.pqc.compcode);
		ret = TEST_FAILED;
		goto exit;
	}
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	rte_hexdump(stdout, "Public Key", pub_key, pqc_ml_pub_key_len[params->alg]);
	rte_hexdump(stdout, "Private Key", priv_key, pqc_ml_priv_key_len[params->alg]);
#endif
	memset(&op, 0, sizeof(struct dao_lc_pqc_op));
	memset(&res, 0, sizeof(struct dao_lc_res));
	/* Perform Encryption */
	op.alg = params->alg;
	op.op_type = DAO_LC_ML_KEM_OP_ENCAP;
	op.encap.enc_key = pub_key;
	op.encap.shared_secret = shared_secret_e;
	op.encap.ciphertext = ciphertext;

	ret = dao_liquid_crypto_pqc_enqueue(dev_id, qp_id, &op, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue PQC ML KEM encapsulation operation. Error: %d", ret);
		ret = TEST_FAILED;
		goto exit;
	}
	/* Dequeue the encapsulation operation */
	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue PQC ML KEM encapsulation operation. Error: %d", ret);
		ret = TEST_FAILED;
		goto exit;
	}
	if (res.res.pqc.compcode != DAO_PQC_COMP_GOOD) {
		TEST_LC_ERR("PQC ML KEM encapsulation operation failed with ret_code: %d",
			    res.res.pqc.compcode);
		ret = TEST_FAILED;
		goto exit;
	}
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	rte_hexdump(stdout, "Ciphertext", ciphertext, pqc_ml_ciphertext_len[params->alg]);
	rte_hexdump(stdout, "Shared Secret (Encap)", shared_secret_e,
		    DAO_LC_ML_KEM_SHARED_SECRET_LEN);
#endif
	memset(&op, 0, sizeof(struct dao_lc_pqc_op));
	memset(&res, 0, sizeof(struct dao_lc_res));
	/* Perform Decapsulation */
	op.alg = params->alg;
	op.op_type = DAO_LC_ML_KEM_OP_DECAP;
	op.decap.dec_key = priv_key;
	op.decap.ciphertext = ciphertext;
	op.decap.shared_secret = shared_secret_d;
	ret = dao_liquid_crypto_pqc_enqueue(dev_id, qp_id, &op, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue PQC ML KEM decapsulation operation. Error: %d", ret);
		ret = TEST_FAILED;
		goto exit;
	}
	/* Dequeue the decapsulation operation */
	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue PQC ML KEM decapsulation operation. Error: %d", ret);
		ret = TEST_FAILED;
		goto exit;
	}
	if (res.res.pqc.compcode != DAO_PQC_COMP_GOOD) {
		TEST_LC_ERR("PQC ML KEM decapsulation operation failed with ret_code: %d",
			    res.res.pqc.compcode);
		ret = TEST_FAILED;
		goto exit;
	}
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	rte_hexdump(stdout, "Shared Secret (Decap)", shared_secret_d,
		    DAO_LC_ML_KEM_SHARED_SECRET_LEN);
#endif
	TEST_ASSERT(memcmp(shared_secret_d, shared_secret_e, DAO_LC_ML_KEM_SHARED_SECRET_LEN) == 0,
		    "Shared secrets do not match");

	ret = TEST_SUCCESS;

exit:
	rte_free(ciphertext);
shared_sec_d_free:
	rte_free(shared_secret_d);
shared_sec_e_free:
	rte_free(shared_secret_e);
priv_key_free:
	rte_free(priv_key);
pub_key_free:
	rte_free(pub_key);

	return ret;
}

static int
test_ml_dsa(const void *data)
{
	const struct test_pqc_params *params = data;
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	struct dao_lc_pqc_op op = {0};
	struct dao_lc_res res = {0};
	uint8_t *signature = NULL;
	uint8_t *priv_key = NULL;
	uint8_t *pub_key = NULL;
	uint16_t msg_len = 32; /* Example message length */
	uint16_t ctx_len = 16; /* Example context length */
	uint8_t *msg = NULL;
	uint8_t *ctx = NULL;
	int ret = 0;

	pub_key = rte_zmalloc("ml_dsa_pub_key", pqc_ml_pub_key_len[params->alg], 0);
	if (pub_key == NULL)
		return TEST_FAILED;
	priv_key = rte_zmalloc("ml_dsa_priv_key", pqc_ml_priv_key_len[params->alg], 0);
	if (priv_key == NULL) {
		ret = TEST_FAILED;
		goto pub_key_free;
	}
	signature = rte_zmalloc("ml_dsa_signature", pqc_ml_signature_len[params->alg], 0);
	if (signature == NULL) {
		ret = TEST_FAILED;
		goto priv_key_free;
	}
	msg = rte_zmalloc("ml_dsa_msg", msg_len, 0);
	if (msg == NULL) {
		ret = TEST_FAILED;
		goto signature_free;
	}
	ctx = rte_zmalloc("ml_dsa_ctx", ctx_len, 0);
	if (ctx == NULL) {
		ret = TEST_FAILED;
		goto msg_free;
	}
	/* Generate keys */
	op.alg = params->alg;
	op.op_type = DAO_LC_ML_DSA_OP_KEYGEN;
	op.keygen.pub_key = pub_key;
	op.keygen.priv_key = priv_key;
	ret = dao_liquid_crypto_pqc_enqueue(dev_id, qp_id, &op, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue PQC ML DSA key generation operation. Error: %d",
			    ret);
		ret = TEST_FAILED;
		goto exit;
	}
	/* Dequeue the key generation operation */
	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue PQC ML DSA key generation operation. Error: %d",
			    ret);
		ret = TEST_FAILED;
		goto exit;
	}
	if (res.res.pqc.compcode != DAO_PQC_COMP_GOOD) {
		TEST_LC_ERR("PQC ML DSA key generation operation failed with ret_code: %d",
			    res.res.pqc.compcode);
		ret = TEST_FAILED;
		goto exit;
	}
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	rte_hexdump(stdout, "Public Key", pub_key, pqc_ml_pub_key_len[params->alg]);
	rte_hexdump(stdout, "Private Key", priv_key, pqc_ml_priv_key_len[params->alg]);
#endif
	memset(&op, 0, sizeof(struct dao_lc_pqc_op));
	memset(&res, 0, sizeof(struct dao_lc_res));
	/* Perform Signature Generation */
	op.alg = params->alg;
	op.op_type = DAO_LC_ML_DSA_OP_SIGN;
	op.sign.msg = msg;
	op.sign.msg_len = msg_len;
	op.sign.ctx = ctx;
	op.sign.ctx_len = ctx_len;
	op.sign.priv_key = priv_key;
	op.sign.signature = signature;
	ret = dao_liquid_crypto_pqc_enqueue(dev_id, qp_id, &op, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR(
			"Could not enqueue PQC ML DSA signature generation operation. Error: %d",
			ret);
		ret = TEST_FAILED;
		goto exit;
	}
	/* Dequeue the signature generation operation */
	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR(
			"Could not dequeue PQC ML DSA signature generation operation. Error: %d",
			ret);
		ret = TEST_FAILED;
		goto exit;
	}
	if (res.res.pqc.compcode != DAO_PQC_COMP_GOOD) {
		TEST_LC_ERR("PQC ML DSA signature generation operation failed with ret_code: %d",
			    res.res.pqc.compcode);
		ret = TEST_FAILED;
		goto exit;
	}
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	rte_hexdump(stdout, "Signature", signature, pqc_ml_signature_len[params->alg]);
#endif
	memset(&op, 0, sizeof(struct dao_lc_pqc_op));
	memset(&res, 0, sizeof(struct dao_lc_res));
	/* Perform Signature Verification */
	op.alg = params->alg;
	op.op_type = DAO_LC_ML_DSA_OP_VERIFY;
	op.verify.msg = msg;
	op.verify.msg_len = msg_len;
	op.verify.ctx = ctx;
	op.verify.ctx_len = ctx_len;
	op.verify.signature = signature;
	op.verify.pub_key = pub_key;
	ret = dao_liquid_crypto_pqc_enqueue(dev_id, qp_id, &op, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR(
			"Could not enqueue PQC ML DSA signature verification operation. Error: %d",
			ret);
		ret = TEST_FAILED;
		goto exit;
	}
	/* Dequeue the signature verification operation */
	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR(
			"Could not dequeue PQC ML DSA signature verification operation. Error: %d",
			ret);
		ret = TEST_FAILED;
		goto exit;
	}
	if (res.res.pqc.compcode != DAO_PQC_COMP_GOOD) {
		TEST_LC_ERR("PQC ML DSA signature verification operation failed with ret_code: %d",
			    res.res.pqc.compcode);
		ret = TEST_FAILED;
		goto exit;
	}

	ret = TEST_SUCCESS;

exit:
	rte_free(ctx);
msg_free:
	rte_free(msg);
signature_free:
	rte_free(signature);
priv_key_free:
	rte_free(priv_key);
pub_key_free:
	rte_free(pub_key);

	return ret;
}

struct unit_test_suite lc_testsuite_pqc = {
	.suite_name = "Liquid Crypto PQC Test Suite",
	.setup = pqc_testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		TEST_CASE_NAMED_WITH_DATA("PQC ML KEM 512", ut_setup, ut_teardown, test_ml_kem,
					  &ml_kem_512_params),

		TEST_CASE_NAMED_WITH_DATA("PQC ML KEM 768", ut_setup, ut_teardown, test_ml_kem,
					  &ml_kem_768_params),

		TEST_CASE_NAMED_WITH_DATA("PQC ML KEM 1024", ut_setup, ut_teardown, test_ml_kem,
					  &ml_kem_1024_params),

		TEST_CASE_NAMED_WITH_DATA("PQC ML DSA 44", ut_setup, ut_teardown, test_ml_dsa,
					  &ml_dsa_44_params),

		TEST_CASE_NAMED_WITH_DATA("PQC ML DSA 65", ut_setup, ut_teardown, test_ml_dsa,
					  &ml_dsa_65_params),

		TEST_CASE_NAMED_WITH_DATA("PQC ML DSA 87", ut_setup, ut_teardown, test_ml_dsa,
					  &ml_dsa_87_params),

		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};
