/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>

#include <rte_cycles.h>
#include <rte_random.h>

#include <hw/cpt.h>

#include "lc_autotest.h"
#include "lc_test_asym_ecdsa.h"
#include "lc_test_asym_rsa.h"
#include "lc_test_generic.h"
#include "test.h"

static int
test_rsa_sign(const void *data)
{
	const struct test_rsa_params *params = data;
	uint8_t output[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	struct dao_lc_res res;
	int ret;

	memset(&res, 0, sizeof(res));
	memset(output, 0, sizeof(output));

	/* RSA SIGN */
	ret = dao_liquid_crypto_enq_op_pkcs1v15enc_crt(
		dev_id, qp_id, params->n.len, params->plaintext.len, params->q.data,
		params->dQ.data, params->p.data, params->dP.data, params->qInv.data,
		params->plaintext.data, output, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue RSA sign operation");
		return TEST_FAILED;
	}

	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue RSA sign operation");
		return TEST_FAILED;
	}

	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD, "Crypto operation failed");
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_SUCCESS, "RSA operation failed");
	TEST_ASSERT(memcmp(output, params->sign.data, params->n.len) == 0, "Invalid result");

	return TEST_SUCCESS;
}

static int
test_rsa_verify(const void *data)
{
	const struct test_rsa_params *params = data;
	uint8_t message[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	struct dao_lc_res res;
	int ret;

	memset(&res, 0, sizeof(res));
	memset(message, 0, sizeof(message));

	/* RSA VERIFY */
	ret = dao_liquid_crypto_enq_op_pkcs1v15dec(
		dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PUBLIC, params->n.len, params->e.len,
		params->n.data, params->e.data, params->sign.data, message, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue RSA verify operation");
		return TEST_FAILED;
	}

	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue RSA verify operation");
		return TEST_FAILED;
	}

	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD, "Crypto operation failed");
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_SUCCESS, "RSA operation failed");
	TEST_ASSERT(res.rsa.data_out_len == params->plaintext.len, "Invalid result length");
	TEST_ASSERT(memcmp(message, params->plaintext.data, params->plaintext.len) == 0,
		    "Invalid result");

	return TEST_SUCCESS;
}

static int
test_rsa_sign_unsupported_mod(const void *data)
{
	const struct test_rsa_params *params = data;
	uint8_t output[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	int ret;

#ifndef TEST_LC_DEBUG_BUILD
	return TEST_SKIPPED;
#endif

	memset(output, 0, sizeof(output));

	/* RSA SIGN */
	ret = dao_liquid_crypto_enq_op_pkcs1v15enc_crt(
		dev_id, qp_id, params->n.len, params->plaintext.len, params->q.data,
		params->dQ.data, params->p.data, params->dP.data, params->qInv.data,
		params->plaintext.data, output, op_cookie);

	TEST_ASSERT(ret == -EINVAL, "RSA CRT encrypt should fail");

	return TEST_SUCCESS;
}

static int
test_rsa_invalid_verify(const void *data)
{
	uint8_t invalid_sign[TEST_LC_MAX_OUTPUT_LEN];
	const struct test_rsa_params *params = data;
	uint8_t message[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	struct dao_lc_res res;
	int ret;

	memset(&res, 0, sizeof(res));
	memset(message, 0, sizeof(message));

	memcpy(invalid_sign, params->sign.data, params->sign.len);
	invalid_sign[params->sign.len / 2] ^= 0x01;

	/* RSA VERIFY */
	ret = dao_liquid_crypto_enq_op_pkcs1v15dec(
		dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PUBLIC, params->n.len, params->e.len,
		params->n.data, params->e.data, invalid_sign, message, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue RSA verify operation");
		return TEST_FAILED;
	}

	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue RSA verify operation");
		return TEST_FAILED;
	}

	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD, "Crypto operation failed");
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_RSA_PKCS_DEC_INCORRECT,
		    "RSA operation failed");
	TEST_ASSERT(res.rsa.data_out_len == 0, "Invalid result length");

	return TEST_SUCCESS;
}

static int
test_rsa_enc_pub_exp(const void *data)
{
	const struct test_rsa_params *params = data;
	uint8_t decrypt[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t output[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	struct dao_lc_res res;
	int ret;

	memset(&res, 0, sizeof(res));
	memset(output, 0, sizeof(output));
	memset(decrypt, 0, sizeof(decrypt));

	/* RSA ENCRYPT */
	ret = dao_liquid_crypto_enq_op_pkcs1v15enc(
		dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PUBLIC, params->n.len, params->e.len,
		params->plaintext.len, params->n.data, params->e.data, params->plaintext.data,
		output, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue RSA encrypt operation");
		return TEST_FAILED;
	}

	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue RSA encrypt operation");
		return TEST_FAILED;
	}

	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD, "Crypto operation failed");
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_SUCCESS, "RSA operation failed");

	/* Validate encryption */
	ret = dao_liquid_crypto_enq_op_pkcs1v15dec_crt(
		dev_id, qp_id, params->n.len, params->q.data, params->dQ.data, params->p.data,
		params->dP.data, params->qInv.data, output, decrypt, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue RSA decrypt operation");
		return TEST_FAILED;
	}

	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue RSA decrypt operation");
		return TEST_FAILED;
	}

	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD, "Crypto operation failed");
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_SUCCESS, "RSA operation failed");
	TEST_ASSERT(res.rsa.data_out_len == params->plaintext.len, "Invalid result length");
	TEST_ASSERT(memcmp(decrypt, params->plaintext.data, params->plaintext.len) == 0,
		    "Invalid result");

	return TEST_SUCCESS;
}

static int
test_rsa_enc_unsupported_mod(const void *data)
{
	const struct test_rsa_params *params = data;
	uint8_t output[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	int ret;

#ifndef TEST_LC_DEBUG_BUILD
	return TEST_SKIPPED;
#endif

	memset(output, 0, sizeof(output));

	/* RSA ENCRYPT */
	ret = dao_liquid_crypto_enq_op_pkcs1v15enc(
		dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PUBLIC, 16, params->e.len, params->plaintext.len,
		params->n.data, params->e.data, params->plaintext.data, output, op_cookie);

	TEST_ASSERT(ret == -EINVAL, "RSA Public encrypt should fail");

	return TEST_SUCCESS;
}

static int
test_rsa_enc_unsupported_msw(const void *data)
{
	const struct test_rsa_params *params = data;
	uint8_t output[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t mod[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	int ret;

#ifndef TEST_LC_DEBUG_BUILD
	return TEST_SKIPPED;
#endif

	memset(output, 0, sizeof(output));
	memcpy(mod, params->n.data, params->n.len);
	*(uint64_t *)mod = 0;

	/* RSA ENCRYPT */
	ret = dao_liquid_crypto_enq_op_pkcs1v15enc(dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PUBLIC,
						   params->n.len, params->e.len,
						   params->plaintext.len, mod, params->e.data,
						   params->plaintext.data, output, op_cookie);

	TEST_ASSERT(ret == -EINVAL, "RSA Public encrypt should fail");

	return TEST_SUCCESS;
}

static int
test_rsa_dec_prv_crt(const void *data)
{
	const struct test_rsa_params *params = data;
	uint8_t message[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	struct dao_lc_res res;
	int ret;

	memset(&res, 0, sizeof(res));
	memset(message, 0, sizeof(message));

	/* RSA DECRYPT */
	ret = dao_liquid_crypto_enq_op_pkcs1v15dec_crt(
		dev_id, qp_id, params->n.len, params->q.data, params->dQ.data, params->p.data,
		params->dP.data, params->qInv.data, params->cipher.data, message, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue RSA decrypt operation");
		return TEST_FAILED;
	}

	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue RSA decrypt operation");
		return TEST_FAILED;
	}

	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD, "Crypto operation failed");
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_SUCCESS, "RSA operation failed");
	TEST_ASSERT(res.rsa.data_out_len == params->plaintext.len, "Invalid result length");
	TEST_ASSERT(memcmp(message, params->plaintext.data, params->plaintext.len) == 0,
		    "Invalid result");

	return TEST_SUCCESS;
}

static int
test_rsa_dec_crt_unsupported_mod(const void *data)
{
	const struct test_rsa_params *params = data;
	uint8_t message[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	int ret;

#ifndef TEST_LC_DEBUG_BUILD
	return TEST_SKIPPED;
#endif

	memset(message, 0, sizeof(message));

	/* RSA DECRYPT */
	ret = dao_liquid_crypto_enq_op_pkcs1v15dec_crt(
		dev_id, qp_id, params->n.len, params->q.data, params->dQ.data, params->p.data,
		params->dP.data, params->qInv.data, params->cipher.data, message, op_cookie);

	TEST_ASSERT(ret == -EINVAL, "RSA CRT decrypt should fail");

	return TEST_SUCCESS;
}

static int
test_rsa_dec_invalid_prv_crt(const void *data)
{
	uint8_t invalid_cipher[TEST_LC_MAX_OUTPUT_LEN];
	const struct test_rsa_params *params = data;
	uint8_t message[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	struct dao_lc_res res;
	int ret;

	memset(&res, 0, sizeof(res));
	memset(message, 0, sizeof(message));

	memcpy(invalid_cipher, params->cipher.data, params->cipher.len);
	invalid_cipher[params->cipher.len / 2] ^= 0x01;

	/* RSA DECRYPT */
	ret = dao_liquid_crypto_enq_op_pkcs1v15dec_crt(
		dev_id, qp_id, params->n.len, params->q.data, params->dQ.data, params->p.data,
		params->dP.data, params->qInv.data, invalid_cipher, message, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue RSA decrypt operation");
		return TEST_FAILED;
	}

	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue RSA decrypt operation");
		return TEST_FAILED;
	}

	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD, "Crypto operation failed");
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_RSA_PKCS_DEC_INCORRECT,
		    "RSA operation failed");
	TEST_ASSERT(res.rsa.data_out_len == 0, "Invalid result length");

	return TEST_SUCCESS;
}

static int
test_rsa_enc_prv_exp(const void *data)
{
	const struct test_rsa_params *params = data;
	uint8_t decrypt[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t output[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	struct dao_lc_res res;
	int ret;

	memset(&res, 0, sizeof(res));
	memset(output, 0, sizeof(output));
	memset(decrypt, 0, sizeof(decrypt));

	/* RSA ENCRYPT */
	ret = dao_liquid_crypto_enq_op_pkcs1v15enc(
		dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PRIVATE, params->n.len, params->d.len,
		params->plaintext.len, params->n.data, params->d.data, params->plaintext.data,
		output, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue RSA encrypt operation");
		return TEST_FAILED;
	}

	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue RSA encrypt operation");
		return TEST_FAILED;
	}

	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD, "Crypto operation failed");
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_SUCCESS, "RSA operation failed");

	/* Validate encryption */
	ret = dao_liquid_crypto_enq_op_pkcs1v15dec(dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PUBLIC,
						   params->n.len, params->e.len, params->n.data,
						   params->e.data, output, decrypt, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue RSA decrypt operation");
		return TEST_FAILED;
	}

	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue RSA decrypt operation");
		return TEST_FAILED;
	}

	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD, "Crypto operation failed");
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_SUCCESS, "RSA operation failed");
	TEST_ASSERT(res.rsa.data_out_len == params->plaintext.len, "Invalid result length");
	TEST_ASSERT(memcmp(decrypt, params->plaintext.data, params->plaintext.len) == 0,
		    "Invalid result");

	return TEST_SUCCESS;
}

static int
test_rsa_dec_prv_exp(const void *data)
{
	const struct test_rsa_params *params = data;
	uint8_t message[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	struct dao_lc_res res;
	int ret;

	memset(&res, 0, sizeof(res));
	memset(message, 0, sizeof(message));

	/* RSA DECRYPT */
	ret = dao_liquid_crypto_enq_op_pkcs1v15dec(
		dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PRIVATE, params->n.len, params->d.len,
		params->n.data, params->d.data, params->cipher.data, message, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue RSA decrypt operation");
		return TEST_FAILED;
	}

	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue RSA decrypt operation");
		return TEST_FAILED;
	}

	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD, "Crypto operation failed");
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_SUCCESS, "RSA operation failed");
	TEST_ASSERT(res.rsa.data_out_len == params->plaintext.len, "Invalid result length");
	TEST_ASSERT(memcmp(message, params->plaintext.data, params->plaintext.len) == 0,
		    "Invalid result");

	return TEST_SUCCESS;
}

static int
test_rsa_seg_size(void)
{
	struct dao_lc_feature_params params;
	int ret;

	memset(&params, 0, sizeof(params));

	/* Test exponent type */
	params.rsa.mod_len = TEST_LC_MAX_RSA_MOD_LEN;
	params.rsa.exp_len = 4;
	ret = dao_liquid_crypto_seg_size_calc(&params);
	if (ret == 0) {
		TEST_LC_ERR("Segment size calculation failed");
		return TEST_FAILED;
	}

	TEST_ASSERT(ret == 2074, "Incorrect segment size");

	/* Test CRT type */
	params.rsa.mod_len = TEST_LC_MAX_RSA_MOD_LEN;
	params.rsa.exp_len = 0;
	ret = dao_liquid_crypto_seg_size_calc(&params);
	if (ret == 0) {
		TEST_LC_ERR("Segment size calculation failed");
		return TEST_FAILED;
	}

	TEST_ASSERT(ret == 3606, "Incorrect segment size");

	/* Test unsupported parameters */
	params.rsa.mod_len = TEST_LC_MAX_RSA_MOD_LEN + 1;
	params.rsa.exp_len = 0;
	ret = dao_liquid_crypto_seg_size_calc(&params);
	TEST_ASSERT(ret == 0, "Segment size calculation should fail");

	params.rsa.mod_len = 8;
	params.rsa.exp_len = 0;
	ret = dao_liquid_crypto_seg_size_calc(&params);
	TEST_ASSERT(ret == 0, "Segment size calculation should fail");

	params.rsa.mod_len = TEST_LC_MAX_RSA_MOD_LEN + 1;
	params.rsa.exp_len = 1;
	ret = dao_liquid_crypto_seg_size_calc(&params);
	TEST_ASSERT(ret == 0, "Segment size calculation should fail");

	params.rsa.mod_len = 8;
	params.rsa.exp_len = 1;
	ret = dao_liquid_crypto_seg_size_calc(&params);
	TEST_ASSERT(ret == 0, "Segment size calculation should fail");

	return TEST_SUCCESS;
}

static int
test_ecdsa_sign_verify(const void *data)
{
	const struct test_ecdsa_params *params = data;
	uint8_t rs_output[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	uint16_t prime_length = 0;
	struct dao_lc_res res;
	int ret, j;

	for (j = 1; j <= params->digest.length; j++) {
		memset(&res, 0, sizeof(res));
		memset(rs_output, 0, sizeof(rs_output));

		/* ECDSA SIGN */
		ret = dao_liquid_crypto_enq_op_ecdsa_sign(
			dev_id, qp_id, params->curve, params->scalar.length, params->pkey.length, j,
			params->scalar.data, params->pkey.data, params->digest.data, rs_output,
			op_cookie);
		if (ret < 0) {
			TEST_LC_ERR("Could not enqueue ECDSA sign operation");
			return TEST_FAILED;
		}

		ret = op_dequeue(dev_id, qp_id, &res);
		if (ret < 0) {
			TEST_LC_ERR("Could not dequeue ECDSA sign operation");
			return TEST_FAILED;
		}

		TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
		TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD, "Crypto operation failed");
		TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_SUCCESS,
			    "ECDSA Sign operation failed");

		prime_length = res.ecdsa.ecc_rs_out_len / 2;
		TEST_ASSERT(prime_length != 0, "Invalid prime length");

		/* ECDSA Verify */
		memset(&res, 0, sizeof(res));
		ret = dao_liquid_crypto_enq_op_ecdsa_verify(
			dev_id, qp_id, params->curve, params->sign_r.length, params->sign_s.length,
			j, params->pubkey_qx.length, params->pubkey_qy.length, rs_output,
			rs_output + prime_length, params->digest.data, params->pubkey_qx.data,
			params->pubkey_qy.data, op_cookie);
		if (ret < 0) {
			TEST_LC_ERR("Could not enqueue ECDSA verify operation");
			return TEST_FAILED;
		}

		ret = op_dequeue(dev_id, qp_id, &res);
		if (ret < 0) {
			TEST_LC_ERR("Could not dequeue ECDSA verify operation");
			return TEST_FAILED;
		}

		TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
		TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD, "Crypto operation failed");
		TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_SUCCESS,
			    "ECDSA verify operation failed");
	}

	return TEST_SUCCESS;
}

static int
test_ecdsa_sign(const void *data)
{
	const struct test_ecdsa_params *params = data;
	uint8_t rs_output[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	uint16_t prime_length = 0;
	struct dao_lc_res res;
	int ret;

	memset(&res, 0, sizeof(res));
	memset(rs_output, 0, sizeof(rs_output));

	/* ECDSA SIGN */
	ret = dao_liquid_crypto_enq_op_ecdsa_sign(
		dev_id, qp_id, params->curve, params->scalar.length, params->pkey.length,
		params->digest.length, params->scalar.data, params->pkey.data, params->digest.data,
		rs_output, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue ECDSA sign operation");
		return TEST_FAILED;
	}

	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue ECDSA sign operation");
		return TEST_FAILED;
	}

	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD, "Crypto operation failed");
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_SUCCESS, "ECDSA Sign operation failed");

	prime_length = res.ecdsa.ecc_rs_out_len / 2;

	TEST_ASSERT(prime_length != 0, "Invalid prime length");
	TEST_ASSERT(memcmp(rs_output, params->sign_r.data, prime_length) == 0, "Invalid r result");
	TEST_ASSERT(memcmp(rs_output + prime_length, params->sign_s.data, prime_length) == 0,
		    "Invalid s result");

	return TEST_SUCCESS;
}

static int
test_ecdsa_verify(const void *data)
{
	const struct test_ecdsa_params *params = data;
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	struct dao_lc_res res;
	int ret;

	memset(&res, 0, sizeof(res));

	/* ECDSA Verify */
	ret = dao_liquid_crypto_enq_op_ecdsa_verify(
		dev_id, qp_id, params->curve, params->sign_r.length, params->sign_s.length,
		params->digest.length, params->pubkey_qx.length, params->pubkey_qy.length,
		params->sign_r.data, params->sign_s.data, params->digest.data,
		params->pubkey_qx.data, params->pubkey_qy.data, op_cookie);

	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue ECDSA verify operation");
		return TEST_FAILED;
	}

	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue ECDSA verify operation");
		return TEST_FAILED;
	}

	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD, "Crypto operation failed");
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_SUCCESS, "ECDSA verify operation failed");

	return TEST_SUCCESS;
}

static int
test_rsa_oaep_enc_dec_exp(const void *data)
{
	const struct test_rsa_oaep_params *params = data;
	uint8_t decrypt[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t output[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	struct dao_lc_res res;
	int ret;

	memset(&res, 0, sizeof(res));
	memset(output, 0, sizeof(output));
	memset(decrypt, 0, sizeof(decrypt));

	/* RSA ENCRYPT */
	ret = dao_liquid_crypto_enq_op_rsa_oaep_enc(
		dev_id, qp_id, params->label.data, params->label.len, params->hash_type,
		params->n.len, params->e.len, params->plaintext.len, params->n.data, params->e.data,
		params->plaintext.data, output, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue RSA encrypt operation");
		return TEST_FAILED;
	}

	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue RSA encrypt operation");
		return TEST_FAILED;
	}

	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD, "Crypto operation failed");
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_SUCCESS, "RSA operation failed");

	/* Validate encryption */
	ret = dao_liquid_crypto_enq_op_rsa_oaep_pvt_exp_dec(
		dev_id, qp_id, params->label.len, params->label.data, params->hash_type,
		params->n.len, params->n.data, params->d.len, params->d.data, output, decrypt,
		op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue RSA decrypt operation");
		return TEST_FAILED;
	}

	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue RSA decrypt operation");
		return TEST_FAILED;
	}

	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD, "Crypto operation failed");
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_SUCCESS, "RSA operation failed");
	TEST_ASSERT(res.rsa.data_out_len == params->plaintext.len, "Invalid result length");
	TEST_ASSERT(memcmp(decrypt, params->plaintext.data, params->plaintext.len) == 0,
		    "Invalid result");

	return TEST_SUCCESS;
}

static int
test_rsa_oaep_enc_dec_crt(const void *data)
{
	const struct test_rsa_oaep_params *params = data;
	uint8_t decrypt[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t output[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	struct dao_lc_res res;
	int ret;

	memset(&res, 0, sizeof(res));
	memset(output, 0, sizeof(output));
	memset(decrypt, 0, sizeof(decrypt));
	/* RSA ENCRYPT */
	ret = dao_liquid_crypto_enq_op_rsa_oaep_enc(
		dev_id, qp_id, params->label.data, params->label.len, params->hash_type,
		params->n.len, params->e.len, params->plaintext.len, params->n.data, params->e.data,
		params->plaintext.data, output, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue RSA encrypt operation");
		return TEST_FAILED;
	}

	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue RSA encrypt operation");
		return TEST_FAILED;
	}
	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD, "Crypto operation failed");
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_SUCCESS, "RSA operation failed");

	/* RSA CRT Decrypt */
	ret = dao_liquid_crypto_enq_op_rsa_oaep_pvt_crt_dec(
		dev_id, qp_id, params->label.data, params->label.len, params->hash_type,
		params->n.len, params->p.data, params->dP.data, params->q.data, params->dQ.data,
		params->qInv.data, output, decrypt, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue RSA decrypt operation");
		return TEST_FAILED;
	}

	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue RSA decrypt operation");
		return TEST_FAILED;
	}

	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD, "Crypto operation failed");
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_SUCCESS, "RSA operation failed");
	TEST_ASSERT(res.rsa.data_out_len == params->plaintext.len, "Invalid result length");
	TEST_ASSERT(memcmp(decrypt, params->plaintext.data, params->plaintext.len) == 0,
		    "Invalid result");

	return TEST_SUCCESS;
}

static int
test_rsa_modex_enc_dec_exp(const void *data)
{
	const struct test_modex_params *params = data;
	uint8_t decrypt[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t output[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	struct dao_lc_res res;
	int ret;

	memset(&res, 0, sizeof(res));
	memset(output, 0, sizeof(output));
	memset(decrypt, 0, sizeof(decrypt));

	/* Modex EXP Encrypt */
	ret = dao_liquid_crypto_enq_op_modex_exp(
		dev_id, qp_id, params->n.len, params->e.len, params->plaintext.len, params->n.data,
		params->e.data, params->plaintext.data, output, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue Modex EXP encrypt operation");
		return TEST_FAILED;
	}
	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue Modex EXP encrypt operation");
		return TEST_FAILED;
	}
	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD,
		    "Modex EXP crypto operation failed");
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_SUCCESS, "Modex EXP operation failed");

	if (memcmp(output, params->result.data, params->result.len) != 0) {
		TEST_LC_ERR("Modex EXP encryption result mismatch");
		return TEST_FAILED;
	}

	/* Modex EXP Decrypt */
	ret = dao_liquid_crypto_enq_op_modex_exp(dev_id, qp_id, params->n.len, params->d.len,
						 params->result.len, params->n.data, params->d.data,
						 output, decrypt, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue Modex EXP decrypt operation");
		return TEST_FAILED;
	}
	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue Modex EXP decrypt operation");
		return TEST_FAILED;
	}

	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD,
		    "Modex EXP crypto operation failed");
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_SUCCESS, "Modex EXP operation failed");

	if (memcmp(decrypt + (params->n.len - params->plaintext.len), params->plaintext.data,
		   params->plaintext.len) != 0) {
		TEST_LC_ERR("Modex EXP decryption result mismatch");
		return TEST_FAILED;
	}

	return TEST_SUCCESS;
}

static int
test_rsa_modex_enc_exp_dec_crt(const void *data)
{
	const struct test_modex_params *params = data;
	uint8_t decrypt[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t output[TEST_LC_MAX_OUTPUT_LEN];
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	struct dao_lc_res res;
	int ret;

	memset(&res, 0, sizeof(res));
	memset(output, 0, sizeof(output));
	memset(decrypt, 0, sizeof(decrypt));

	/* Modex EXP Encrypt */
	ret = dao_liquid_crypto_enq_op_modex_exp(
		dev_id, qp_id, params->n.len, params->e.len, params->plaintext.len, params->n.data,
		params->e.data, params->plaintext.data, output, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue Modex EXP encrypt operation");
		return TEST_FAILED;
	}
	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue Modex EXP encrypt operation");
		return TEST_FAILED;
	}
	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD,
		    "Modex EXP crypto operation failed");
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_SUCCESS, "Modex EXP operation failed");

	if (memcmp(output, params->result.data, params->result.len) != 0) {
		TEST_LC_ERR("Modex EXP encryption result mismatch");
		return TEST_FAILED;
	}

	/* Modex CRT Decrypt */
	ret = dao_liquid_crypto_enq_op_modex_crt(dev_id, qp_id, params->n.len,
						 params->n.len, params->q.data,
						 params->dQ.data, params->p.data, params->dP.data,
						 params->qInv.data, output, decrypt, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue Modex CRT decrypt operation");
		return TEST_FAILED;
	}
	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue Modex CRT decrypt operation");
		return TEST_FAILED;
	}

	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res.res.cn9k.compcode == DAO_CPT_COMP_GOOD,
		    "Modex CRT crypto operation failed");
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_SUCCESS, "Modex CRT operation failed");

	if (memcmp(decrypt + (params->n.len - params->plaintext.len), params->plaintext.data,
		   params->plaintext.len) != 0) {
		TEST_LC_ERR("Modex CRT decryption result mismatch");
		return TEST_FAILED;
	}

	return TEST_SUCCESS;
}

struct unit_test_suite lc_testsuite_asym = {
	.suite_name = "Liquid Crypto Asymmetric Test Suite",
	.setup = testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		TEST_CASE_NAMED_WITH_DATA("RSA Sign", ut_setup, ut_teardown, test_rsa_sign,
					  &rsa_params),
		TEST_CASE_NAMED_WITH_DATA("RSA Verify", ut_setup, ut_teardown, test_rsa_verify,
					  &rsa_params),
		TEST_CASE_NAMED_WITH_DATA("RSA Verify Invalid Sign", ut_setup, ut_teardown,
					  test_rsa_invalid_verify, &rsa_params),
		TEST_CASE_NAMED_WITH_DATA("RSA Public Encrypt", ut_setup, ut_teardown,
					  test_rsa_enc_pub_exp, &rsa_params),
		TEST_CASE_NAMED_WITH_DATA("RSA Public Encrypt (8192 bits)", ut_setup, ut_teardown,
					  test_rsa_enc_pub_exp, &rsa_8192_params),
		TEST_CASE_NAMED_WITH_DATA("RSA Private Decrypt (CRT type)", ut_setup, ut_teardown,
					  test_rsa_dec_prv_crt, &rsa_params),
		TEST_CASE_NAMED_WITH_DATA("RSA Private Decrypt Invalid Cipher", ut_setup,
					  ut_teardown, test_rsa_dec_invalid_prv_crt, &rsa_params),
		TEST_CASE_NAMED_WITH_DATA("RSA Private Encrypt (Exponent type)", ut_setup,
					  ut_teardown, test_rsa_enc_prv_exp, &rsa_params),
		TEST_CASE_NAMED_WITH_DATA("RSA Private Decrypt (Exponent type)", ut_setup,
					  ut_teardown, test_rsa_dec_prv_exp, &rsa_params),
		TEST_CASE_NAMED_WITH_DATA("RSA Sign (2048 bits)", ut_setup, ut_teardown,
					  test_rsa_sign, &rsa_2048_params),
		TEST_CASE_NAMED_WITH_DATA("RSA Verify (2048 bits)", ut_setup, ut_teardown,
					  test_rsa_verify, &rsa_2048_params),
		TEST_CASE_NAMED_WITH_DATA("RSA Sign (4096 bits)", ut_setup, ut_teardown,
					  test_rsa_sign, &rsa_4096_params),
		TEST_CASE_NAMED_WITH_DATA("RSA Verify (4096 bits)", ut_setup, ut_teardown,
					  test_rsa_verify, &rsa_4096_params),
		TEST_CASE_NAMED_WITH_DATA("RSA Sign (8192 bits)", ut_setup, ut_teardown,
					  test_rsa_sign, &rsa_8192_params),
		TEST_CASE_NAMED_WITH_DATA("RSA Verify (8192 bits)", ut_setup, ut_teardown,
					  test_rsa_verify, &rsa_8192_params),
		TEST_CASE_NAMED_WITH_DATA("RSA Verify (256 bits)", ut_setup, ut_teardown,
					  test_rsa_verify, &rsa_256_params),
		TEST_CASE_NAMED_WITH_DATA("RSA Private Encrypt (256 bits)", ut_setup, ut_teardown,
					  test_rsa_enc_prv_exp, &rsa_256_params),
		TEST_CASE_NAMED_WITH_DATA("RSA Private Decrypt (256 bits)", ut_setup, ut_teardown,
					  test_rsa_dec_prv_exp, &rsa_256_params),
		TEST_CASE_NAMED_WITH_DATA("RSA Sign Unsupported Mod", ut_setup, ut_teardown,
					  test_rsa_sign_unsupported_mod, &rsa_256_params),
		TEST_CASE_NAMED_WITH_DATA("RSA CRT Decrypt Unsupported Mod", ut_setup, ut_teardown,
					  test_rsa_dec_crt_unsupported_mod, &rsa_256_params),
		TEST_CASE_NAMED_WITH_DATA("RSA Public Encrypt Unsupported Mod", ut_setup,
					  ut_teardown, test_rsa_enc_unsupported_mod, &rsa_params),
		TEST_CASE_NAMED_WITH_DATA("RSA Public Encrypt Unsupported MSW", ut_setup,
					  ut_teardown, test_rsa_enc_unsupported_msw, &rsa_params),
		TEST_CASE_NAMED_ST("RSA segment size calculation", ut_setup, ut_teardown,
				   test_rsa_seg_size),
		TEST_CASE_NAMED_WITH_DATA("ECDSA secp192r1 Verify (r signature length 23B bytes)",
					  ut_setup, ut_teardown, test_ecdsa_verify,
					  &ecdsa_param_secp192r1_verify),
		TEST_CASE_NAMED_WITH_DATA("ECDSA secp521r1 Verify( r signature length 65B bytes)",
					  ut_setup, ut_teardown, test_ecdsa_verify,
					  &ecdsa_param_secp521r1_verify),
		TEST_CASE_NAMED_WITH_DATA("ECDSA secp521r1 sign with 64B prv key", ut_setup,
					  ut_teardown, test_ecdsa_sign,
					  &ecdsa_param_secp521r1_verify_2),
		TEST_CASE_NAMED_WITH_DATA("ECDSA secp521r1 verify with 64B prv key", ut_setup,
					  ut_teardown, test_ecdsa_verify,
					  &ecdsa_param_secp521r1_verify_2),
		TEST_CASE_NAMED_WITH_DATA("ECDSA secp192r1 Sign", ut_setup, ut_teardown,
					  test_ecdsa_sign, &ecdsa_param_secp192r1),
		TEST_CASE_NAMED_WITH_DATA("ECDSA secp192r1 Verify", ut_setup, ut_teardown,
					  test_ecdsa_verify, &ecdsa_param_secp192r1),
		TEST_CASE_NAMED_WITH_DATA("ECDSA secp224r1 Sign", ut_setup, ut_teardown,
					  test_ecdsa_sign, &ecdsa_param_secp224r1),
		TEST_CASE_NAMED_WITH_DATA("ECDSA secp224r1 Verify", ut_setup, ut_teardown,
					  test_ecdsa_verify, &ecdsa_param_secp224r1),
		TEST_CASE_NAMED_WITH_DATA("ECDSA secp256r1 Sign", ut_setup, ut_teardown,
					  test_ecdsa_sign, &ecdsa_param_secp256r1),
		TEST_CASE_NAMED_WITH_DATA("ECDSA secp256r1 Verify", ut_setup, ut_teardown,
					  test_ecdsa_verify, &ecdsa_param_secp256r1),
		TEST_CASE_NAMED_WITH_DATA("ECDSA secp384r1 Sign", ut_setup, ut_teardown,
					  test_ecdsa_sign, &ecdsa_param_secp384r1),
		TEST_CASE_NAMED_WITH_DATA("ECDSA secp384r1 Verify", ut_setup, ut_teardown,
					  test_ecdsa_verify, &ecdsa_param_secp384r1),
		TEST_CASE_NAMED_WITH_DATA("ECDSA secp521r1 Sign", ut_setup, ut_teardown,
					  test_ecdsa_sign, &ecdsa_param_secp521r1),
		TEST_CASE_NAMED_WITH_DATA("ECDSA secp521r1 Verify", ut_setup, ut_teardown,
					  test_ecdsa_verify, &ecdsa_param_secp521r1),
		TEST_CASE_NAMED_WITH_DATA(
			"ECDSA secp192r1 sign and verify with varying digest lengths", ut_setup,
			ut_teardown, test_ecdsa_sign_verify, &ecdsa_param_secp192r1),
		TEST_CASE_NAMED_WITH_DATA(
			"ECDSA secp224r1 sign and verify with varying digest lengths", ut_setup,
			ut_teardown, test_ecdsa_sign_verify, &ecdsa_param_secp224r1),
		TEST_CASE_NAMED_WITH_DATA(
			"ECDSA secp256r1 sign and verify with varying digest lengths", ut_setup,
			ut_teardown, test_ecdsa_sign_verify, &ecdsa_param_secp256r1),
		TEST_CASE_NAMED_WITH_DATA(
			"ECDSA secp384r1 sign and verify with varying digest lengths", ut_setup,
			ut_teardown, test_ecdsa_sign_verify, &ecdsa_param_secp384r1),
		TEST_CASE_NAMED_WITH_DATA(
			"ECDSA secp521r1 sign and verify with varying digest lengths", ut_setup,
			ut_teardown, test_ecdsa_sign_verify, &ecdsa_param_secp521r1),
		TEST_CASE_NAMED_WITH_DATA("RSA OAEP Encrypt/Decrypt with pvt exp (1024 bits)",
					  ut_setup, ut_teardown, test_rsa_oaep_enc_dec_exp,
					  &rsa_oaep_params),
		TEST_CASE_NAMED_WITH_DATA(
			"RSA OAEP Encrypt/Decrypt with pvt exp with label (1024 bits)", ut_setup,
			ut_teardown, test_rsa_oaep_enc_dec_exp, &rsa_oaep_params_5B_label),
		TEST_CASE_NAMED_WITH_DATA(
			"RSA OAEP Encrypt/Decrypt with pvt CRT with label (1024 bits)", ut_setup,
			ut_teardown, test_rsa_oaep_enc_dec_crt, &rsa_oaep_params_5B_label),
		TEST_CASE_NAMED_WITH_DATA(
			"RSA OAEP Encrypt/Decrypt with pvt exp with label (2048 bits)", ut_setup,
			ut_teardown, test_rsa_oaep_enc_dec_exp, &rsa_oaep_params_1K_label_2k_mod),
		TEST_CASE_NAMED_WITH_DATA(
			"RSA OAEP Encrypt/Decrypt with pvt CRT with label (2048 bits)", ut_setup,
			ut_teardown, test_rsa_oaep_enc_dec_crt, &rsa_oaep_params_1K_label_2k_mod),
		TEST_CASE_NAMED_WITH_DATA("RSA OAEP Encrypt/Decrypt with pvt exp (7904 bits)",
					  ut_setup, ut_teardown, test_rsa_oaep_enc_dec_exp,
					  &rsa_7904_oaep_params),
		TEST_CASE_NAMED_WITH_DATA("RSA OAEP Encrypt/Decrypt with pvt CRT (7904 bits)",
					  ut_setup, ut_teardown, test_rsa_oaep_enc_dec_crt,
					  &rsa_7904_oaep_params),
		TEST_CASE_NAMED_WITH_DATA(
			"RSA OAEP Encrypt/Decrypt with pvt exp and label, zero message length (2048 bits)",
			ut_setup, ut_teardown, test_rsa_oaep_enc_dec_exp,
			&rsa_oaep_params_1K_label_2k_mod_empty_string),
		TEST_CASE_NAMED_WITH_DATA(
			"RSA OAEP Encrypt/Decrypt with pvt CRT and label, zero message length (2048 bits)",
			ut_setup, ut_teardown, test_rsa_oaep_enc_dec_crt,
			&rsa_oaep_params_1K_label_2k_mod_empty_string),
		TEST_CASE_NAMED_WITH_DATA("Modex encrypt/decrypt with exponent(1024 bits)",
					  ut_setup, ut_teardown, test_rsa_modex_enc_dec_exp,
					  &rsa_modex_params),
		TEST_CASE_NAMED_WITH_DATA(
			"Modex encrypt with public exponent and decrypt with prv CRT params (1024 bits)",
			ut_setup, ut_teardown, test_rsa_modex_enc_exp_dec_crt,
			&rsa_modex_params),
		TEST_CASE_NAMED_WITH_DATA(
			"Modex encrypt with public exponent and decrypt with prv CRT params (2048 bits)",
			ut_setup, ut_teardown, test_rsa_modex_enc_exp_dec_crt,
			&rsa_modex_2048_params),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};
