/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <stdlib.h>

#include <dao_liquid_crypto.h>

#include <rte_cycles.h>
#include <rte_random.h>

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
	uint8_t dev_id = glb_params.dev_id;
	int ret;

	ret = dao_liquid_crypto_dev_start(dev_id);
	if (ret < 0) {
		TEST_LC_ERR("Could not start liquid crypto device %d with error %d", dev_id, ret);
		return TEST_FAILED;
	}

	return TEST_SUCCESS;
}

void
ut_teardown(void)
{
	uint8_t dev_id = glb_params.dev_id;
	int ret;

	ret = dao_liquid_crypto_dev_stop(dev_id);
	if (ret != 0) {
		TEST_LC_ERR("Could not stop liquid crypto device %d: %d. "
			    "Device may have inflight operations.",
			    dev_id, ret);
	}
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

uint16_t
op_dequeue_multi(uint8_t dev_id, uint16_t qp_id, struct dao_lc_res *res, uint16_t nb_res)
{
	uint16_t ret, remaining;
	uint16_t dequeued = 0;
	uint64_t timeout;

	if (!res || nb_res == 0)
		return 0;

	timeout = rte_get_timer_cycles() + rte_get_timer_hz() * TEST_LC_TIMEOUT;

	do {
		remaining = nb_res - dequeued;
		ret = dao_liquid_crypto_dequeue_burst(dev_id, qp_id, res + dequeued, remaining);

		if (ret > 0)
			dequeued += ret;

		if (rte_get_timer_cycles() > timeout)
			break;

	} while (dequeued < nb_res);

	return dequeued;
}

static int
ut_passthrough(uint8_t dev_id, uint16_t qp_id)
{
	uint64_t op_cookie = rte_rand();
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

static int
ut_passthrough_single_queue(void)
{
	return ut_passthrough(glb_params.dev_id, glb_params.qp_id);
}

static int
ut_passthrough_multi_queue(void)
{
	uint8_t dev_id;
	uint16_t qp_id;

	for (dev_id = 0; dev_id < glb_params.info.nb_dev; dev_id++) {
		for (qp_id = 1; qp_id < glb_params.info.nb_qp[dev_id]; qp_id++) {
#ifdef UT_VERBOSE
			printf("\t\tDev_id: %u, qp_id: %u\n", dev_id, qp_id);
#endif
			if (ut_passthrough(dev_id, qp_id) != TEST_SUCCESS)
				return TEST_FAILED;
		}
	}

	return TEST_SUCCESS;
}

struct unit_test_suite lc_testsuite_generic = {
	.suite_name = "Liquid Crypto Generic Test Suite",
	.setup = testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		TEST_CASE_NAMED_ST("Passthrough Operation (Single Queue)", ut_setup, ut_teardown,
				   ut_passthrough_single_queue),
		TEST_CASE_NAMED_ST("Passthrough Operation (Multi Queue)", ut_setup, ut_teardown,
				   ut_passthrough_multi_queue),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};
