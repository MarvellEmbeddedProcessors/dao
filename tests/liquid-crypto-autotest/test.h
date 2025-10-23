/* SPDX-License-Identifier: Marvell-MIT
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 * Copyright(c) 2025 Marvell
 */

/* File based on https://github.com/DPDK/dpdk/blob/main/app/test/test.h */

#ifndef __TEST_H__
#define __TEST_H__

#include <stdlib.h>

#include <rte_eal.h>

#define TEST_SUCCESS EXIT_SUCCESS
#define TEST_FAILED  -1
#define TEST_SKIPPED 77

#define TEST_ASSERT(cond, msg, ...)                                                                \
	do {                                                                                       \
		if (!(cond)) {                                                                     \
			RTE_LOG(ERR, EAL, "Test assert %s line %d failed: " msg "\n", __func__,    \
				__LINE__, ##__VA_ARGS__);                                          \
			return -1;                                                                 \
		}                                                                                  \
	} while (0)

#define TEST_ASSERT_EQUAL(a, b, msg, ...) TEST_ASSERT((a) == (b), msg, ##__VA_ARGS__)

#define TEST_ASSERT_NOT_EQUAL(a, b, msg, ...) TEST_ASSERT((a) != (b), msg, ##__VA_ARGS__)

#define TEST_ASSERT_SUCCESS(val, msg, ...) TEST_ASSERT((val) == 0, msg, ##__VA_ARGS__)

#define TEST_ASSERT_FAIL(val, msg, ...) TEST_ASSERT((val) != 0, msg, ##__VA_ARGS__)

#define TEST_ASSERT_NULL(val, msg, ...) TEST_ASSERT((val) == NULL, msg, ##__VA_ARGS__)

#define TEST_ASSERT_NOT_NULL(val, msg, ...) TEST_ASSERT((val) != NULL, msg, ##__VA_ARGS__)

struct unit_test_case {
	int (*setup)(void);
	void (*teardown)(void);
	int (*testcase)(void);
	int (*testcase_with_data)(const void *data);
	const char *name;
	unsigned int enabled;
	const void *data;
};

struct unit_test_suite {
	const char *suite_name;
	int (*setup)(void);
	void (*teardown)(void);
	unsigned int total;
	unsigned int executed;
	unsigned int succeeded;
	unsigned int skipped;
	unsigned int failed;
	unsigned int unsupported;
	struct unit_test_suite **unit_test_suites;
	struct unit_test_case unit_test_cases[];
};

#define TEST_CASE(fn) { NULL, NULL, fn, NULL, #fn, 1, NULL }

#define TEST_CASE_NAMED(name, fn) { NULL, NULL, fn, NULL, name, 1, NULL }

#define TEST_CASE_ST(setup, teardown, testcase) \
		{ setup, teardown, testcase, NULL, #testcase, 1, NULL }

#define TEST_CASE_WITH_DATA(setup, teardown, testcase, data) \
		{ setup, teardown, NULL, testcase, #testcase, 1, data }

#define TEST_CASE_NAMED_ST(name, setup, teardown, testcase) \
		{ setup, teardown, testcase, NULL, name, 1, NULL }

#define TEST_CASE_NAMED_WITH_DATA(name, setup, teardown, testcase, data) \
		{ setup, teardown, NULL, testcase, name, 1, data }

#define TEST_CASE_DISABLED(fn) { NULL, NULL, fn, NULL, #fn, 0, NULL }

#define TEST_CASE_ST_DISABLED(setup, teardown, testcase) \
		{ setup, teardown, testcase, NULL, #testcase, 0, NULL }

#define TEST_CASES_END() { NULL, NULL, NULL, NULL, NULL, 0, NULL }

int unit_test_suite_runner(struct unit_test_suite *suite);

/* Signal handling support for graceful test termination */
extern volatile int force_quit;

#endif /* __TEST_H__ */
