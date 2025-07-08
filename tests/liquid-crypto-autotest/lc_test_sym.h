/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __LC_TEST_SYM_H__
#define __LC_TEST_SYM_H__

#include <dao_liquid_crypto.h>

#include "test.h"

extern struct unit_test_suite lc_testsuite_sym;

struct test_sym_params {
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
	} aad;
	struct {
		const uint8_t *data;
		uint16_t len;
	} digest;
	uint16_t cipher_offset;
	uint16_t auth_offset;
};

#endif /* __LC_TEST_SYM_H__ */
