/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_random.h>

#include <dao_liquid_crypto.h>

#include "lc_autotest.h"
#include "lc_test_generic.h"
#include "test.h"

static uint8_t rng_prev_buf_data[TEST_LC_MAX_RANDOM_ITER][TEST_LC_MAX_RANDOM_LEN];

static int
test_rng_verify_with_prev_data(struct rte_hash *rng_hash_tbl, const uint8_t *out_buf_data, int iter)
{
	void *lookup_buf = NULL;
	uint32_t out_buf_hash;
	int ret;

	out_buf_hash = rte_jhash(out_buf_data, TEST_LC_MAX_RANDOM_LEN, 0);

	ret = rte_hash_lookup_data(rng_hash_tbl, &out_buf_hash, &lookup_buf);
	if (ret >= 0 && lookup_buf != NULL) {
		ret = memcmp(lookup_buf, out_buf_data, TEST_LC_MAX_RANDOM_LEN);
		if (ret == 0) {
			TEST_LC_ERR("Duplicate random data found in iteration %d", iter);
			return TEST_FAILED;
		}
	}

	memcpy(rng_prev_buf_data[iter], out_buf_data, TEST_LC_MAX_RANDOM_LEN);
	ret = rte_hash_add_key_data(rng_hash_tbl, &out_buf_hash, rng_prev_buf_data[iter]);
	if (ret < 0) {
		TEST_LC_ERR("Could not add data to hash table: rc: %d, iter: %d", ret, iter);
		return TEST_FAILED;
	}

	return TEST_SUCCESS;
}

static int
test_rng_hw_random(void)
{
	uint8_t out_buf_data[TEST_LC_MAX_RANDOM_LEN] = {0};
	int ret, diff_found, test_ret = TEST_FAILED;
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	struct rte_hash *rng_hash_tbl;
	struct dao_lc_res res;
	uint64_t op_cookie;
	int i, j;

	struct dao_lc_buf out_buf = {
		.data = out_buf_data,
		.frag_len = TEST_LC_MAX_RANDOM_LEN,
		.total_len = TEST_LC_MAX_RANDOM_LEN
	};

	struct dao_lc_random_op op = {
		.type = DAO_LC_RANDOM_TYPE_HW,
		.out_buf = &out_buf,
		.rand_len = TEST_LC_MAX_RANDOM_LEN,
	};

	struct rte_hash_parameters rng_hash_params = {
		.name = "rng_hash_table",
		.entries = TEST_LC_MAX_RANDOM_ITER * 2,
		.key_len = sizeof(uint32_t),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};

	rng_hash_tbl = rte_hash_create(&rng_hash_params);
	if (rng_hash_tbl == NULL) {
		TEST_LC_ERR("Could not create hash table\n");
		return TEST_FAILED;
	}

	memset(rng_prev_buf_data, 0, sizeof(rng_prev_buf_data));

	for (i = 0; i < TEST_LC_MAX_RANDOM_ITER; i++) {
		memset(out_buf_data, 0, TEST_LC_MAX_RANDOM_LEN);

		op_cookie = rte_rand();
		op.op_cookie = op_cookie;

		ret = dao_liquid_crypto_enq_op_random(dev_id, qp_id, &op);
		if (ret < 0) {
			TEST_LC_ERR("Could not enqueue random operation");
			test_ret = TEST_FAILED;
			goto hash_tbl_free;
		}

		ret = op_dequeue(dev_id, qp_id, &res);
		if (ret < 0) {
			TEST_LC_ERR("Could not dequeue random operation");
			test_ret = TEST_FAILED;
			goto hash_tbl_free;
		}

		TEST_ASSERT(res.op_cookie == op_cookie, "Invalid operation cookie");

		diff_found = 0;
		for (j = 0; j < TEST_LC_MAX_RANDOM_LEN; j++) {
			if (out_buf_data[j] != 0) {
				diff_found = 1;
				break;
			}
		}
		TEST_ASSERT(diff_found, "Random output is all zeros");

		test_ret = test_rng_verify_with_prev_data(rng_hash_tbl, out_buf_data, i);
		TEST_ASSERT(test_ret == TEST_SUCCESS, "Random data verification failed");
	}

hash_tbl_free:
	rte_hash_free(rng_hash_tbl);
	return test_ret;
}

struct unit_test_suite lc_testsuite_rng = {
	.suite_name = "Liquid Crypto RNG Test Suite",
	.setup = testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		TEST_CASE_NAMED_ST("RNG HW Random", ut_setup, ut_teardown, test_rng_hw_random),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};
