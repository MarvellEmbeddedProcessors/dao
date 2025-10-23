/* SPDX-License-Identifier: Marvell-MIT
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 * Copyright(c) 2025 Marvell
 */

/* File based on https://github.com/DPDK/dpdk/blob/main/app/test/test.c */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "test.h"

extern volatile int force_quit;

#define FOR_EACH_SUITE_TESTCASE(iter, suite, case)                                                 \
	for (iter = 0, case = (suite)->unit_test_cases[0];                                         \
	     (suite)->unit_test_cases[iter].testcase ||                                            \
	     (suite)->unit_test_cases[iter].testcase_with_data;                                    \
	     iter++, case = (suite)->unit_test_cases[iter])

#define FOR_EACH_SUITE_TESTSUITE(iter, suite, sub_ts)                                              \
	for (iter = 0, sub_ts = (suite)->unit_test_suites ? (suite)->unit_test_suites[0] : NULL;   \
	     sub_ts && (suite)->unit_test_suites[iter]->suite_name != NULL;                        \
	     iter++, sub_ts = (suite)->unit_test_suites[iter])

static void
unit_test_suite_count_tcs_on_setup_fail(struct unit_test_suite *suite, int test_success,
					unsigned int *sub_ts_failed, unsigned int *sub_ts_skipped,
					unsigned int *sub_ts_total)
{
	struct unit_test_case tc;
	struct unit_test_suite *ts;
	int i;

	FOR_EACH_SUITE_TESTSUITE(i, suite, ts) {
		unit_test_suite_count_tcs_on_setup_fail(ts, test_success, sub_ts_failed,
							sub_ts_skipped, sub_ts_total);
		suite->total += ts->total;
		suite->failed += ts->failed;
		suite->skipped += ts->skipped;
		if (ts->failed)
			(*sub_ts_failed)++;
		else
			(*sub_ts_skipped)++;
		(*sub_ts_total)++;
	}

	FOR_EACH_SUITE_TESTCASE(i, suite, tc) {
		suite->total++;
		if (!tc.enabled || test_success == TEST_SKIPPED)
			suite->skipped++;
		else
			suite->failed++;
	}
}

static void
unit_test_suite_reset_counts(struct unit_test_suite *suite)
{
	struct unit_test_suite *ts;
	int i;

	FOR_EACH_SUITE_TESTSUITE(i, suite, ts)
		unit_test_suite_reset_counts(ts);
	suite->total = 0;
	suite->executed = 0;
	suite->succeeded = 0;
	suite->skipped = 0;
	suite->failed = 0;
	suite->unsupported = 0;
}

int
unit_test_suite_runner(struct unit_test_suite *suite)
{
	int test_success, i, ret;
	const char *status;
	struct unit_test_case tc;
	struct unit_test_suite *ts;
	unsigned int sub_ts_succeeded = 0, sub_ts_failed = 0;
	unsigned int sub_ts_skipped = 0, sub_ts_total = 0;

	unit_test_suite_reset_counts(suite);

	if (suite->suite_name) {
		printf(" + ------------------------------------------------------- +\n");
		printf(" + Test Suite : %s\n", suite->suite_name);
	}

	if (suite->setup) {
		test_success = suite->setup();
		if (test_success != 0) {
			/*
			 * setup did not pass, so count all enabled tests and
			 * mark them as failed/skipped
			 */
			unit_test_suite_count_tcs_on_setup_fail(suite, test_success, &sub_ts_failed,
								&sub_ts_skipped, &sub_ts_total);
			goto suite_summary;
		}
	}

	printf(" + ------------------------------------------------------- +\n");

	FOR_EACH_SUITE_TESTCASE(suite->total, suite, tc) {
		/* Check for signal interruption */
		if (force_quit) {
			printf("Test execution interrupted by signal\n");
			suite->failed++;
			break;
		}

		if (!tc.enabled) {
			suite->skipped++;
			continue;
		} else {
			suite->executed++;
		}

		/* run test case setup */
		if (tc.setup)
			test_success = tc.setup();
		else
			test_success = TEST_SUCCESS;

		if (test_success == TEST_SUCCESS) {
			/* run the test case */
			if (tc.testcase)
				test_success = tc.testcase();
			else if (tc.testcase_with_data)
				test_success = tc.testcase_with_data(tc.data);
			else
				test_success = -ENOTSUP;

			if (test_success == TEST_SUCCESS) {
				suite->succeeded++;
			} else if (test_success == TEST_SKIPPED) {
				suite->skipped++;
				suite->executed--;
			} else if (test_success == -ENOTSUP) {
				suite->unsupported++;
				suite->executed--;
			} else {
				suite->failed++;
			}
		} else if (test_success == -ENOTSUP) {
			suite->unsupported++;
		} else if (test_success == TEST_SKIPPED) {
			suite->skipped++;
		} else {
			suite->failed++;
		}

		/* run the test case teardown */
		if (tc.teardown)
			tc.teardown();

		if (test_success == TEST_SUCCESS)
			status = "succeeded";
		else if (test_success == TEST_SKIPPED)
			status = "skipped";
		else if (test_success == -ENOTSUP)
			status = "unsupported";
		else
			status = "failed";

		printf(" + TestCase [%2d] : %s %s\n", suite->total, tc.name, status);
	}

	FOR_EACH_SUITE_TESTSUITE(i, suite, ts) {
		/* Check for signal interruption before running sub-suites */
		if (force_quit) {
			printf("Sub-suite execution interrupted by signal\n");
			sub_ts_failed++;
			sub_ts_total++;
			continue;
		}

		ret = unit_test_suite_runner(ts);
		if (ret == TEST_SUCCESS)
			sub_ts_succeeded++;
		else if (ret == TEST_SKIPPED)
			sub_ts_skipped++;
		else
			sub_ts_failed++;
		sub_ts_total++;

		suite->total += ts->total;
		suite->succeeded += ts->succeeded;
		suite->failed += ts->failed;
		suite->skipped += ts->skipped;
		suite->unsupported += ts->unsupported;
		suite->executed += ts->executed;
	}

	/* Run test suite teardown */
	if (suite->teardown)
		suite->teardown();

	goto suite_summary;

suite_summary:
	printf(" + ------------------------------------------------------- +\n");
	printf(" + Test Suite Summary : %s\n", suite->suite_name);
	printf(" + ------------------------------------------------------- +\n");

	FOR_EACH_SUITE_TESTSUITE(i, suite, ts)
	printf(" + %s : %d/%d passed, %d/%d skipped, "
	       "%d/%d failed, %d/%d unsupported\n",
	       ts->suite_name, ts->succeeded, ts->total, ts->skipped, ts->total, ts->failed,
	       ts->total, ts->unsupported, ts->total);

	if (suite->unit_test_suites) {
		printf(" + ------------------------------------------------------- +\n");
		printf(" + Sub Testsuites Total :     %2d\n", sub_ts_total);
		printf(" + Sub Testsuites Skipped :   %2d\n", sub_ts_skipped);
		printf(" + Sub Testsuites Passed :    %2d\n", sub_ts_succeeded);
		printf(" + Sub Testsuites Failed :    %2d\n", sub_ts_failed);
		printf(" + ------------------------------------------------------- +\n");
	}

	printf(" + Tests Total :       %2d\n", suite->total);
	printf(" + Tests Skipped :     %2d\n", suite->skipped);
	printf(" + Tests Executed :    %2d\n", suite->executed);
	printf(" + Tests Unsupported:  %2d\n", suite->unsupported);
	printf(" + Tests Passed :      %2d\n", suite->succeeded);
	printf(" + Tests Failed :      %2d\n", suite->failed);
	printf(" + ------------------------------------------------------- +\n");

	if (suite->failed)
		return TEST_FAILED;
	if (suite->total == suite->skipped)
		return TEST_SKIPPED;
	return TEST_SUCCESS;
}
