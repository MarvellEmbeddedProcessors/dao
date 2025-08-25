/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <inttypes.h>
#include <stdlib.h>

#include <dao_liquid_crypto.h>

#include <rte_crypto.h>
#include <rte_cryptodev.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_random.h>

#include "lcperf_ops.h"
#include "lcperf_test_latency.h"
#include "lcperf_test_vectors.h"

extern volatile int force_quit;

struct lcperf_op_result {
	uint64_t tsc_start;
	uint64_t tsc_end;
};

struct lcperf_latency_ctx {
	uint8_t dev_id;
	uint16_t qp_id;
	uint8_t lcore_id;

	lcperf_populate_ops_t populate_ops;
	lcperf_enqueue_ops_t enqueue_ops;
	uint64_t sess_id;

	const struct lcperf_options *options;
	const struct lcperf_op_fns *op_fns;
	struct lcperf_op_result *result;
};

static void
lcperf_latency_test_free(struct lcperf_latency_ctx *ctx)
{
	if (ctx == NULL)
		return;

	if (ctx->result != NULL)
		rte_free(ctx->result);

	rte_free(ctx);
}

void *
lcperf_latency_test_constructor(uint8_t dev_id, uint16_t qp_id,
				const struct lcperf_options *options,
				const struct lcperf_op_fns *op_fns)
{
	struct lcperf_latency_ctx *ctx = NULL;

	ctx = rte_zmalloc(NULL, sizeof(struct lcperf_latency_ctx), 0);
	if (ctx == NULL)
		return NULL;

	ctx->dev_id = dev_id;
	ctx->qp_id = qp_id;

	ctx->enqueue_ops = op_fns->enqueue_ops;
	ctx->populate_ops = op_fns->populate_ops;
	ctx->options = options;
	ctx->op_fns = op_fns;

	ctx->result =
		rte_malloc(NULL, sizeof(struct lcperf_op_result) * ctx->options->total_ops, 0);
	if (ctx->result == NULL)
		goto ctx_free;

	return ctx;
ctx_free:
	rte_free(ctx);
	return NULL;
}

static int
lcperf_check_single_op(struct lcperf_latency_ctx *ctx, struct lcperf_test_data *tdata)
{
	uint64_t tsc_start = 0;
	struct dao_lc_res res;
	int ret = 0;

	tdata->nb_ops = 1;
	ret = ctx->populate_ops(ctx->sess_id, ctx->options, tdata);
	if (ret < 0) {
		RTE_LOG(ERR, USER1, "Could not populate operation\n");
		return -1;
	}

	ret = ctx->enqueue_ops(ctx->dev_id, ctx->qp_id, tdata, ctx->options);
	if (ret < 0) {
		RTE_LOG(ERR, USER1, "Could not enqueue operation\n");
		return ret;
	}

	/* Wait for one minute to complete the operation*/
	tsc_start = rte_rdtsc_precise();
	while (1) {
		ret = dao_liquid_crypto_dequeue_burst(ctx->dev_id, ctx->qp_id, &res, 1);

		if (ret == 1) {
			if (res.op_cookie != tdata->op_cookie) {
				RTE_LOG(ERR, USER1, "Invalid operation cookie\n");
				return -1;
			}
			return 1;
		}

		/* Check if 1 minute timeout has been reached */
		if ((rte_rdtsc_precise() - tsc_start) > rte_get_tsc_hz()) {
			RTE_LOG(ERR, USER1, "Dequeue operation timed out.\n");
			return -1;
		}
	}
}

int
lcperf_latency_test_runner(void *test_ctx)
{
	uint64_t ops_deqd = 0, ops_deqd_total = 0, ops_deqd_failed = 0;
	uint64_t tsc_max = 0, tsc_min = ~0UL, tsc_tot = 0;
	uint64_t ops_enqd = 0, ops_enqd_total = 0;
	uint64_t tsc_enq_idx = 0, tsc_deq_idx = 0;
	struct lcperf_latency_ctx *ctx = test_ctx;
	uint64_t enqd_max = 0, enqd_min = ~0UL;
	uint64_t deqd_max = 0, deqd_min = ~0UL;
	uint64_t tsc_val, tsc_end, tsc_start;
	uint32_t burst_size, curr_burst_sz;
	uint32_t lcore = rte_lcore_id();
	uint64_t op_cookie = rte_rand();
	struct lcperf_test_data tdata;
	uint64_t remaining_ops;
	uint64_t total_ops, j;
	struct dao_lc_res res;
	uint64_t b_idx = 0;
	uint8_t dev_id;
	uint16_t qp_id;
	int ret;

	ctx->lcore_id = lcore;
	tdata.op_cookie = op_cookie;

	if (lcperf_check_single_op(ctx, &tdata) < 0) {
		RTE_LOG(ERR, USER1, "Single operation check failed\n");
		goto ctx_cleanup;
	}

	burst_size = ctx->options->burst_size;
	total_ops = ctx->options->total_ops;
	dev_id = ctx->dev_id;
	qp_id = ctx->qp_id;

	while (!force_quit && (ops_enqd_total < total_ops)) {
		remaining_ops = total_ops - ops_enqd_total;
		curr_burst_sz = RTE_MIN(remaining_ops, burst_size);

		ops_enqd = 0;
		ops_deqd = 0;

		tsc_start = rte_rdtsc_precise();
		tdata.op_cookie = tsc_start;
		tdata.nb_ops = curr_burst_sz;

		ret = ctx->populate_ops(ctx->sess_id, ctx->options, &tdata);
		if (ret == 0) {
			ret = ctx->enqueue_ops(dev_id, qp_id, &tdata, ctx->options);
			ops_enqd += ret;
		}

		for (j = 0; j < curr_burst_sz; j++) {
			ret = dao_liquid_crypto_dequeue_burst(dev_id, qp_id, &res, 1);
			if (ret == 1) {
				ops_deqd++;
				ctx->result[tsc_enq_idx].tsc_start = res.op_cookie;
				tsc_enq_idx++;
			} else {
				ops_deqd_failed++;
			}
		}

		tsc_end = rte_rdtsc_precise();

		for (j = 0; j < ops_deqd; j++) {
			ctx->result[tsc_deq_idx].tsc_end = tsc_end;
			tsc_deq_idx++;
		}

		ops_enqd_total += ops_enqd;
		ops_deqd_total += ops_deqd;

		enqd_max = RTE_MAX(ops_enqd, enqd_max);
		enqd_min = RTE_MIN(ops_enqd, enqd_min);

		deqd_max = RTE_MAX(ops_deqd, deqd_max);
		deqd_min = RTE_MIN(ops_deqd, deqd_min);
		b_idx++;
	}

	ops_deqd = ops_deqd_total;
	/* Dequeue any remaining operations */
	for (j = 0; ops_deqd_total < ops_enqd_total; j++) {
		ret = dao_liquid_crypto_dequeue_burst(dev_id, qp_id, &res, 1);
		if (ret == 1) {
			ops_deqd_total++;
			ctx->result[tsc_enq_idx].tsc_start = res.op_cookie;
			tsc_enq_idx++;
		} else {
			ops_deqd_failed++;
		}
	}

	tsc_end = rte_rdtsc_precise();

	ops_deqd = ops_deqd_total - ops_deqd;
	if (ops_deqd != 0) {
		deqd_max = RTE_MAX(ops_deqd, deqd_max);
		deqd_min = RTE_MIN(ops_deqd, deqd_min);
	}

	for (j = 0; j < ops_deqd; j++) {
		ctx->result[tsc_deq_idx].tsc_end = tsc_end;
		tsc_deq_idx++;
	}

	for (j = 0; j < tsc_enq_idx; j++) {
		tsc_val = ctx->result[j].tsc_end - ctx->result[j].tsc_start;
		tsc_max = RTE_MAX(tsc_val, tsc_max);
		tsc_min = RTE_MIN(tsc_val, tsc_min);
		tsc_tot += tsc_val;
	}

	double time_tot, time_avg, time_max, time_min;

	const uint64_t tunit = 1000000; /* us */
	const uint64_t tsc_hz = rte_get_tsc_hz();

	uint64_t enqd_avg = ops_enqd_total / b_idx;
	uint64_t deqd_avg = ops_deqd_total / b_idx;
	uint64_t tsc_avg = tsc_tot / tsc_enq_idx;

	time_tot = tunit * (double)(tsc_tot) / tsc_hz;
	time_avg = tunit * (double)(tsc_avg) / tsc_hz;
	time_max = tunit * (double)(tsc_max) / tsc_hz;
	time_min = tunit * (double)(tsc_min) / tsc_hz;

	printf("\n# Device %d on lcore %u\n", ctx->dev_id, ctx->lcore_id);
	printf("\n# total operations: %u", ctx->options->total_ops);
	printf("\n# Buffer size: %u", ctx->options->test_buffer_size);

	printf("\n#");
	printf("\n#          \t       Total\t   Average\t   "
	       "Maximum\t   Minimum");
	printf("\n#  enqueued\t%12" PRIu64 "\t%10" PRIu64 "\t"
	       "%10" PRIu64 "\t%10" PRIu64,
	       ops_enqd_total, enqd_avg, enqd_max, enqd_min);
	printf("\n#  dequeued\t%12" PRIu64 "\t%10" PRIu64 "\t"
	       "%10" PRIu64 "\t%10" PRIu64,
	       ops_deqd_total, deqd_avg, deqd_max, deqd_min);
	printf("\n#    cycles\t%12" PRIu64 "\t%10" PRIu64 "\t"
	       "%10" PRIu64 "\t%10" PRIu64,
	       tsc_tot, tsc_avg, tsc_max, tsc_min);
	printf("\n# time [us]\t%12.0f\t%10.3f\t%10.3f\t%10.3f", time_tot, time_avg, time_max,
	       time_min);
	printf("\n\n");

	return 0;

ctx_cleanup:
	lcperf_latency_test_destructor(test_ctx);
	return -1;
}

void
lcperf_latency_test_destructor(void *arg)
{
	struct lcperf_latency_ctx *ctx = arg;

	if (ctx == NULL)
		return;

	lcperf_latency_test_free(ctx);
}
