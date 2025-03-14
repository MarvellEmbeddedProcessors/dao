/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <dao_liquid_crypto.h>

#include "lcperf_ops.h"
#include "lcperf_test_vectors.h"

static int
lcperf_set_op_passthrough(uint8_t dev_id, uint16_t qp_id, const struct lcperf_test_data *tdata)
{
	return dao_liquid_crypto_enqueue_op_passthrough(dev_id, qp_id, tdata->op_cookie);
}

int
lcperf_get_op_functions(const struct lcperf_options *options, struct lcperf_op_fns *op_fns)
{
	memset(op_fns, 0, sizeof(struct lcperf_op_fns));

	switch (options->op_type) {
	case LCPERF_OP_PASSTHROUGH:
		op_fns->enqueue_ops = lcperf_set_op_passthrough;
		break;
	default:
		return -1;
	}

	return 0;
}
