/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef _LCPERF_OPS_
#define _LCPERF_OPS_

#include "lcperf_options.h"
#include "lcperf_test_vectors.h"

#define ENQ_TIMEOUT 12

typedef int (*lcperf_enqueue_ops_t)(uint8_t dev_id, uint16_t qp_id, struct lcperf_test_data *tdata,
				    const struct lcperf_options *options);
typedef uint64_t (*lcperf_sess_create_t)(uint8_t dev_id,
					 const struct lcperf_test_sym_params *sym_params);
typedef int (*lcperf_sess_destroy_t)(uint8_t dev_id, uint64_t sess_id);
typedef int (*lcperf_populate_ops_t)(uint64_t sess_id, const struct lcperf_options *options,
				     struct lcperf_test_data *test_data);

struct lcperf_op_fns {
	lcperf_enqueue_ops_t enqueue_ops;
	lcperf_populate_ops_t populate_ops;
	lcperf_sess_create_t sess_create;
	lcperf_sess_destroy_t sess_destroy;
};

int lcperf_get_op_functions(const struct lcperf_options *options, struct lcperf_op_fns *op_fns);

#endif /* _LCPERF_OPS_ */
