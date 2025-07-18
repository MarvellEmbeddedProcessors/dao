/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __LC_TEST_PQC_H__
#define __LC_TEST_PQC_H__

#include "test.h"

extern struct unit_test_suite lc_testsuite_pqc;

struct test_pqc_params {
	enum dao_lc_pqc_alg alg; /**< The PQC algorithm */
};

int pqc_testsuite_setup(void);

#endif /* __LC_TEST_PQC_H__ */
