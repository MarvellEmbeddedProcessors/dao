/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <stdlib.h>

#include <dao_liquid_crypto.h>

#include <rte_cycles.h>

#include "lc_autotest.h"
#include "lc_test_generic.h"
#include "test.h"

struct global_params glb_params;

int
testsuite_setup(void)
{
	return 0;
}

void
testsuite_teardown(void)
{
}

int
ut_setup(void)
{
	return 0;
}

void
ut_teardown(void)
{
}

int
op_dequeue(uint8_t dev_id, uint16_t qp_id, struct dao_lc_res *res)
{
	uint64_t timeout;
	int ret;

	/* Set a timeout of TEST_LC_TIMEOUT second. */
	timeout = rte_get_timer_cycles() + rte_get_timer_hz() * TEST_LC_TIMEOUT;

	do {
		ret = dao_liquid_crypto_dequeue_burst(dev_id, qp_id, res, 1);
		if (ret == 1)
			break;

		if (rte_get_timer_cycles() > timeout) {
			TEST_LC_ERR("Operation timed out");
			break;
		}
	} while (ret == 0);

	if (ret != 1) {
		TEST_LC_ERR("Could not dequeue operation");
		return -1;
	}

	return 0;
}

static int
ut_passthrough(void)
{
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = 0xdeadbeef;
	struct dao_lc_res res;
	int ret;

	ret = dao_liquid_crypto_enqueue_op_passthrough(dev_id, qp_id, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue passthrough operation");
		return TEST_FAILED;
	}

	ret = op_dequeue(dev_id, qp_id, &res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue passthrough operation");
		return TEST_FAILED;
	}

	TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");

	return TEST_SUCCESS;
}

struct unit_test_suite lc_testsuite_generic = {
	.suite_name = "Liquid Crypto Generic Test Suite",
	.setup = testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		TEST_CASE_NAMED_ST("Passthrough Operation", ut_setup, ut_teardown, ut_passthrough),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};
