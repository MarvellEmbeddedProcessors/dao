/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <inttypes.h>
#include <stdlib.h>

#include <dao_liquid_crypto.h>

#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_random.h>

#include "lcperf_ops.h"
#include "lcperf_test_throughput.h"
#include "lcperf_test_vectors.h"

struct lcperf_throughput_ctx {
	uint8_t dev_id;
	uint16_t qp_id;
	uint8_t lcore_id;

	lcperf_enqueue_ops_t enqueue_ops;

	const struct lcperf_options *options;
};

static void
lcperf_throughput_test_free(struct lcperf_throughput_ctx *ctx)
{
	if (ctx == NULL)
		return;

	rte_free(ctx);
}

void *
lcperf_throughput_test_constructor(uint8_t dev_id, uint16_t qp_id,
				   const struct lcperf_options *options,
				   const struct lcperf_op_fns *op_fns)
{
	struct lcperf_throughput_ctx *ctx = NULL;

	ctx = rte_zmalloc(NULL, sizeof(struct lcperf_throughput_ctx), 0);
	if (ctx == NULL)
		return NULL;

	ctx->dev_id = dev_id;
	ctx->qp_id = qp_id;

	ctx->enqueue_ops = op_fns->enqueue_ops;
	ctx->options = options;

	return ctx;
}

static int
lcperf_check_single_op(struct lcperf_throughput_ctx *ctx, struct lcperf_test_data *tdata)
{
	struct dao_lc_res res;
	uint64_t tsc_start = 0;
	int ret = 0;

	ret = ctx->enqueue_ops(ctx->dev_id, ctx->qp_id, tdata);
	if (ret < 0) {
		RTE_LOG(ERR, USER1, "Could not enqueue operation\n");
		return -1;
	}

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

		/* Check if 1 second timeout has been reached */
		if ((rte_rdtsc_precise() - tsc_start) > rte_get_tsc_hz()) {
			RTE_LOG(ERR, USER1, "Dequeue operation timed out.\n");
			return -1;
		}
	}
}

int
lcperf_throughput_test_runner(void *test_ctx)
{
	uint64_t ops_enqd = 0, ops_enqd_total = 0, ops_enqd_failed = 0;
	uint64_t ops_deqd = 0, ops_deqd_total = 0, ops_deqd_failed = 0;
	struct lcperf_throughput_ctx *ctx = test_ctx;
	uint64_t tsc_start, tsc_end, tsc_duration;
	uint32_t lcore = rte_lcore_id();
	uint64_t op_cookie = rte_rand();
	struct lcperf_test_data tdata;
	uint16_t burst_size, qp_id;
	uint64_t total_ops, i, j;
	struct dao_lc_res res;
	uint32_t nb_desc;
	uint8_t dev_id;
	int ret;

	ctx->lcore_id = lcore;
	tdata.op_cookie = op_cookie;

	if (lcperf_check_single_op(ctx, &tdata) < 0) {
		RTE_LOG(ERR, USER1, "Single operation check failed\n");
		return -1;
	}

	nb_desc = ctx->options->nb_descriptors;
	total_ops = ctx->options->total_ops;
	dev_id = ctx->dev_id;
	qp_id = ctx->qp_id;

	tsc_start = rte_rdtsc_precise();

	for (i = 0; i < total_ops; i += burst_size) {
		if ((ops_enqd_total + nb_desc) > total_ops)
			burst_size = total_ops - ops_enqd_total;
		else
			burst_size = nb_desc;

		for (j = 0; j < burst_size; j++) {
			ret = ctx->enqueue_ops(dev_id, qp_id, &tdata);
			if (ret == 0)
				ops_enqd++;
			else
				ops_enqd_failed++;
			ops_enqd_total++;
		}

		for (j = 0; j < burst_size; j++) {
			ret = dao_liquid_crypto_dequeue_burst(dev_id, qp_id, &res, 1);
			if (ret == 0)
				ops_deqd++;
			else
				ops_deqd_failed++;
			ops_deqd_total++;
		}
	}

	tsc_end = rte_rdtsc_precise();
	tsc_duration = (tsc_end - tsc_start);

	/* Calculate average operations processed per second */
	double ops_per_second = ((double)ctx->options->total_ops / tsc_duration) * rte_get_tsc_hz();

	/* Calculate average throughput (Gbps) in bits per second */
	double throughput_gbps =
		((ops_per_second * ctx->options->test_buffer_size * 8) / 1000000000);

	/* Calculate average cycles per packet */
	double cycles_per_packet = ((double)tsc_duration / ctx->options->total_ops);

	static RTE_ATOMIC(uint16_t)display_once;
	uint16_t exp = 0;

	if (rte_atomic_compare_exchange_strong_explicit(
		    &display_once, &exp, 1, rte_memory_order_relaxed, rte_memory_order_relaxed))
		printf("%12s%12s%12s%12s%12s%12s%12s%12s%12s\n\n", "lcore id", "Buf Size",
		       "Enqueued", "Dequeued", "Failed Enq", "Failed Deq", "MOps", "Gbps",
		       "Cycles/Buf");

	printf("%12u%12u%12" PRIu64 "%12" PRIu64 "%12" PRIu64 "%12" PRIu64 "%12.4f%12.4f%12.2f\n",
	       ctx->lcore_id, ctx->options->test_buffer_size, ops_enqd_total, ops_deqd_total,
	       ops_enqd_failed, ops_deqd_failed, ops_per_second / 1000000, throughput_gbps,
	       cycles_per_packet);

	return 0;
}

void
lcperf_throughput_test_destructor(void *arg)
{
	struct lcperf_throughput_ctx *ctx = arg;

	if (ctx == NULL)
		return;

	lcperf_throughput_test_free(ctx);
}
