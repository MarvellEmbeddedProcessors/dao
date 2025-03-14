/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef _LCPERF_OPTIONS_
#define _LCPERF_OPTIONS_

#include <stdio.h>

#include <rte_common.h>
#include <rte_memory.h>

#define LCPERF_PTEST_TYPE ("ptest")
#define LCPERF_TOTAL_OPS  ("total-ops")
#define LCPERF_DESC_NB    ("desc-nb")
#define LCPERF_OPTYPE     ("optype")

#define MAX_LIST 1

enum lcperf_perf_test_type { LCPERF_TEST_TYPE_THROUGHPUT };

extern const char *lcperf_test_type_strs[];

enum lcperf_op_type { LCPERF_OP_PASSTHROUGH = 1 };

extern const char *lcperf_op_type_strs[];

struct lcperf_options {
	enum lcperf_perf_test_type test;

	uint32_t total_ops;
	uint32_t test_buffer_size;
	uint32_t nb_descriptors;
	uint16_t nb_qps;

	enum lcperf_op_type op_type;

	uint32_t buffer_size_list[MAX_LIST];
	uint8_t buffer_size_count;

	uint32_t burst_size_list[MAX_LIST];
	uint8_t burst_size_count;
};

void lcperf_options_default(struct lcperf_options *options);

int lcperf_options_parse(struct lcperf_options *options, int argc, char **argv);

int lcperf_options_check(struct lcperf_options *options);

void lcperf_options_dump(struct lcperf_options *options);

#endif /* _LCPERF_OPTIONS_ */
