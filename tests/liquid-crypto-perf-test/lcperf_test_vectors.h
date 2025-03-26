/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef _LCPERF_TEST_VECTORS_H_
#define _LCPERF_TEST_VECTORS_H_

#include "lcperf_options.h"

#define LC_PERF_MAX_OUTPUT_LEN 5120

struct lcperf_test_data {
	uint64_t op_cookie;
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

#endif /* _LCPERF_TEST_VECTORS_H_ */
