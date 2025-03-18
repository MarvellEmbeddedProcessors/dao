/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __LC_TEST_SYM_H__
#define __LC_TEST_SYM_H__

#include <dao_liquid_crypto.h>

#include "test.h"

extern struct unit_test_suite lc_testsuite_sym;

#define MAX_IV_LEN 32
#define MAX_PLAINTEXT_LEN 1024
#define MAX_CIPHERTEXT_LEN 1024

struct test_sym_params {
	struct dao_lc_sym_ctx ctx;
	struct {
		uint8_t data[MAX_IV_LEN];
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

#endif /* __LC_TEST_SYM_H__ */
