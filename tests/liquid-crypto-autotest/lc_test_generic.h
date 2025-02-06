/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __LC_TEST_GENERIC__
#define __LC_TEST_GENERIC__

#include <stdint.h>

#include <dao_liquid_crypto.h>

struct global_params {
	uint8_t dev_id;
	uint16_t qp_id;
	struct dao_lc_info info;
};

int testsuite_setup(void);
void testsuite_teardown(void);
int ut_setup(void);
void ut_teardown(void);

extern struct unit_test_suite lc_testsuite_generic;
extern struct global_params glb_params;

int op_dequeue(uint8_t dev_id, uint16_t qp_id, struct dao_lc_res *res);

#endif /* __LC_TEST_GENERIC__ */
