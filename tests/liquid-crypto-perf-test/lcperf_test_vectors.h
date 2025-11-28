/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef _LCPERF_TEST_VECTORS_H_
#define _LCPERF_TEST_VECTORS_H_

#include <dao_liquid_crypto.h>

#include "lcperf_options.h"

/* Maximum length of IV */
#define TEST_LC_MAX_IV_LEN 16
/* Maximum length of plaintext */
#define TEST_LC_MAX_PLAINTEXT_LEN 32256
/* Maximum length of output buffer */
#define TEST_LC_MAX_OUTPUT_LEN 32256
/* Maximum burst size */
#define TEST_LC_MAX_BURST_SIZE 8192
/* Maximum length of RSA modulus */
#define TEST_LC_MAX_RSA_MOD_LEN 1024
/* Maximum length of RSA message */
#define TEST_LC_MAX_RSA_MSG_LEN 1013
/* Maximum length of ECC private/public key */
#define TEST_LC_MAX_ECC_PKEY_LEN 66
/* Maximum length of ECC signature */
#define TEST_LC_MAX_ECC_SIGN_LEN 66
/* Maximum length of ECC digest */
#define TEST_LC_MAX_ECC_DIGEST_LEN 66
/* Maximum nonce length */
#define TEST_LC_MAX_NONCE_LEN 66

struct lcperf_test_sym_params {
	struct dao_lc_sym_ctx ctx;
	struct {
		uint8_t data[TEST_LC_MAX_IV_LEN];
		uint8_t len;
	} iv;
	struct {
		const uint8_t *data;
		uint16_t len;
	} plaintext;
	struct {
		const uint8_t *data;
		uint16_t len;
	} ciphertext;
	struct {
		const uint8_t *data;
		uint16_t len;
	} digest;
};

struct lcperf_test_buf_mem {
	struct dao_lc_buf in_buffer;
	uint8_t in_buf_data[TEST_LC_MAX_PLAINTEXT_LEN];
	uint8_t digest[DAO_LC_MAX_DIGEST_LEN];
};

struct lcperf_test_data {
	uint64_t op_cookie;
	uint16_t nb_ops;
	uint16_t ops_unused;
	uint16_t ops_enqd;
	struct dao_lc_sym_op ops[TEST_LC_MAX_BURST_SIZE];
	struct lcperf_test_sym_params sym_params;
	struct rte_mempool *buf_pool;
	enum lcperf_crypto_sym_cipher_op_type cipher_op;
	enum lcperf_crypto_sym_auth_op_type auth_op;
	struct {
		uint8_t data[TEST_LC_MAX_PLAINTEXT_LEN];
		uint16_t len;
	} plaintext;
	struct {
		uint8_t data[TEST_LC_MAX_PLAINTEXT_LEN];
		uint16_t len;
	} ciphertext;
	struct {
		uint8_t data[DAO_LC_MAX_DIGEST_LEN];
		uint16_t len;
	} digest;
};

struct lcperf_rsa_test_data {
	struct {
		uint8_t *data;
		uint16_t len;
	} plaintext;
	struct {
		uint8_t *data;
		uint16_t len;
	} sign;
	struct {
		uint8_t *data;
		uint16_t len;
	} cipher;
	struct {
		uint8_t *data;
		uint16_t len;
	} n;
	struct {
		uint8_t *data;
		uint16_t len;
	} e;
	struct {
		uint8_t *data;
		uint16_t len;
	} d;
	struct {
		uint8_t *data;
		uint16_t len;
	} p;
	struct {
		uint8_t *data;
		uint16_t len;
	} q;
	struct {
		uint8_t *data;
		uint16_t len;
	} dP;
	struct {
		uint8_t *data;
		uint16_t len;
	} dQ;
	struct {
		uint8_t *data;
		uint16_t len;
	} qInv;
};

struct lcperf_ecdsa_test_data {
	struct {
		uint8_t *data;
		uint16_t length;
	} pubkey_qx;
	struct {
		uint8_t *data;
		uint16_t length;
	} pubkey_qy;
	struct {
		uint8_t *data;
		uint16_t length;
	} scalar;
	struct {
		uint8_t *data;
		uint16_t length;
	} digest;
	struct {
		uint8_t *data;
		uint16_t length;
	} sign_r;
	struct {
		uint8_t *data;
		uint16_t length;
	} sign_s;
	struct {
		uint8_t *data;
		uint16_t length;
	} pkey;
	uint8_t curve;
};

extern struct lcperf_rsa_test_data rsa_1024_params;
extern struct lcperf_rsa_test_data rsa_256_params;
extern struct lcperf_rsa_test_data rsa_2048_params;
extern struct lcperf_rsa_test_data rsa_4096_params;
extern struct lcperf_rsa_test_data rsa_8192_params;

extern struct lcperf_ecdsa_test_data secp192r1_test_vector;
extern struct lcperf_ecdsa_test_data secp224r1_test_vector;
extern struct lcperf_ecdsa_test_data secp256r1_test_vector;
extern struct lcperf_ecdsa_test_data secp384r1_test_vector;
extern struct lcperf_ecdsa_test_data secp521r1_test_vector;
struct lcperf_test_data *lcperf_test_vector_get_dummy(const struct lcperf_options *options);

void lcperf_test_vector_free(struct lcperf_test_data *vector);

#endif /* _LCPERF_TEST_VECTORS_H_ */
