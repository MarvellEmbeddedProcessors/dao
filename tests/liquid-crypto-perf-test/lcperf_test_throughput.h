/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef _LCPERF_THROUGHPUT_
#define _LCPERF_THROUGHPUT_

#include <stdint.h>

#include "lcperf_ops.h"
#include "lcperf_options.h"

void *lcperf_throughput_test_constructor(uint8_t dev_id, uint16_t qp_id,
					 const struct lcperf_options *options,
					 const struct lcperf_op_fns *ops_fn);

int lcperf_throughput_test_runner(void *test_ctx);

void lcperf_throughput_test_destructor(void *test_ctx);

#endif /* _LCPERF_THROUGHPUT_ */
