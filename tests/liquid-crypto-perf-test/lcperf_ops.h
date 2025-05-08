/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef _LCPERF_OPS_
#define _LCPERF_OPS_

#include "lcperf_options.h"
#include "lcperf_test_vectors.h"

#define ENQ_TIMEOUT 12

typedef int (*lcperf_enqueue_ops_t)(uint8_t dev_id, uint16_t qp_id,
				    const struct lcperf_test_data *tdata);

struct lcperf_op_fns {
	lcperf_enqueue_ops_t enqueue_ops;
};

int lcperf_get_op_functions(const struct lcperf_options *options, struct lcperf_op_fns *op_fns);

#endif /* _LCPERF_OPS_ */
