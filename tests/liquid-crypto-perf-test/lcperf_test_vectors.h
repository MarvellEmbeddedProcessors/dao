/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef _LCPERF_TEST_VECTORS_H_
#define _LCPERF_TEST_VECTORS_H_

#include <dao_liquid_crypto.h>

#include "lcperf_options.h"

#define LC_PERF_MAX_OUTPUT_LEN 5120

/* Maximum length of IV */
#define TEST_LC_MAX_IV_LEN 16
/* Maximum length of plaintext */
#define TEST_LC_MAX_PLAINTEXT_LEN 1024
/* Maximum burst size */
#define TEST_LC_MAX_BURST_SIZE 128

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
};

struct lcperf_test_data {
	uint64_t op_cookie;
	uint16_t nb_ops;
	struct dao_lc_sym_op ops[TEST_LC_MAX_BURST_SIZE];
	struct lcperf_test_sym_params sym_params;
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

extern struct lcperf_rsa_test_data rsa_1024_params;
extern struct lcperf_rsa_test_data rsa_256_params;
extern struct lcperf_rsa_test_data rsa_2048_params;
extern struct lcperf_rsa_test_data rsa_4096_params;
extern struct lcperf_rsa_test_data rsa_8192_params;

struct lcperf_test_data *lcperf_test_vector_get_dummy(const struct lcperf_options *options);

void lcperf_test_vector_free(struct lcperf_test_data *vector);

#endif /* _LCPERF_TEST_VECTORS_H_ */
