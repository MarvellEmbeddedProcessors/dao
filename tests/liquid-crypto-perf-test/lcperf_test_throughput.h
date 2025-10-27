/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef _LCPERF_THROUGHPUT_
#define _LCPERF_THROUGHPUT_

#include <stdint.h>

#include "lcperf_ops.h"
#include "lcperf_options.h"

struct lcperf_throughput_worker_result {
	uint8_t lcore_id;
	uint64_t ops_enqueued;
	uint64_t ops_dequeued;
	uint64_t ops_enq_retries;
	uint64_t ops_deq_retries;
	double mops;
	double gbps;
	double cycles_per_buf;
};

void *lcperf_throughput_test_constructor(uint8_t dev_id, uint16_t qp_id,
					 const struct lcperf_options *options,
					 const struct lcperf_op_fns *ops_fn);

int lcperf_throughput_test_runner(void *test_ctx);

void lcperf_throughput_test_destructor(void *test_ctx);

void lcperf_print_throughput_summary(uint32_t buffer_size);

#endif /* _LCPERF_THROUGHPUT_ */
