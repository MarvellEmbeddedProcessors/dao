/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>

#include <rte_cycles.h>
#include <rte_random.h>

#include <dao_liquid_crypto.h>
#include <hw/cpt.h>

#include "lc_autotest.h"
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
	ret = dao_crypto_enqueue_op_pkcs1v15enc_crt(
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
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_RSA_SUCCESS, "RSA operation failed");
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
	ret = dao_crypto_enqueue_op_pkcs1v15dec(
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
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_RSA_SUCCESS, "RSA operation failed");
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
	ret = dao_crypto_enqueue_op_pkcs1v15enc_crt(
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
	ret = dao_crypto_enqueue_op_pkcs1v15dec(dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PUBLIC,
						params->n.len, params->e.len, params->n.data,
						params->e.data, invalid_sign, message, op_cookie);
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
	ret = dao_crypto_enqueue_op_pkcs1v15enc(dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PUBLIC,
						params->n.len, params->e.len, params->plaintext.len,
						params->n.data, params->e.data,
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
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_RSA_SUCCESS, "RSA operation failed");

	/* Validate encryption */
	ret = dao_crypto_enqueue_op_pkcs1v15dec_crt(
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
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_RSA_SUCCESS, "RSA operation failed");
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
	ret = dao_crypto_enqueue_op_pkcs1v15enc(
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
	ret = dao_crypto_enqueue_op_pkcs1v15enc(dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PUBLIC,
						params->n.len, params->e.len, params->plaintext.len,
						mod, params->e.data, params->plaintext.data, output,
						op_cookie);

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
	ret = dao_crypto_enqueue_op_pkcs1v15dec_crt(
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
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_RSA_SUCCESS, "RSA operation failed");
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
	ret = dao_crypto_enqueue_op_pkcs1v15dec_crt(
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
	ret = dao_crypto_enqueue_op_pkcs1v15dec_crt(
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
	ret = dao_crypto_enqueue_op_pkcs1v15enc(dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PRIVATE,
						params->n.len, params->d.len, params->plaintext.len,
						params->n.data, params->d.data,
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
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_RSA_SUCCESS, "RSA operation failed");

	/* Validate encryption */
	ret = dao_crypto_enqueue_op_pkcs1v15dec(dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PUBLIC,
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
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_RSA_SUCCESS, "RSA operation failed");
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
	ret = dao_crypto_enqueue_op_pkcs1v15dec(
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
	TEST_ASSERT(res.res.cn9k.uc_compcode == DAO_UC_RSA_SUCCESS, "RSA operation failed");
	TEST_ASSERT(res.rsa.data_out_len == params->plaintext.len, "Invalid result length");
	TEST_ASSERT(memcmp(message, params->plaintext.data, params->plaintext.len) == 0,
		    "Invalid result");

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
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};
