/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef _LCPERF_
#define _LCPERF_

#include "lcperf_ops.h"

struct lcperf_options;
struct lcperf_op_fns;

typedef void *(*lcperf_constructor_t)(uint8_t dev_id, uint16_t qp_id,
				      const struct lcperf_options *options,
				      const struct lcperf_op_fns *op_fns);
typedef int (*lcperf_runner_t)(void *test_ctx);
typedef void (*lcperf_destructor_t)(void *test_ctx);

struct lcperf_test {
	lcperf_constructor_t constructor;
	lcperf_runner_t runner;
	lcperf_destructor_t destructor;
};

#endif /* _LCPERF_ */
