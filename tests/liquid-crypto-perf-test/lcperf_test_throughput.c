/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <inttypes.h>
#include <stdlib.h>

#include <dao_liquid_crypto.h>

#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_mempool.h>

#include "lcperf_ops.h"
#include "lcperf_test_throughput.h"
#include "lcperf_test_vectors.h"

extern volatile int force_quit;

/* Worker results storage for summary calculation */
struct lcperf_throughput_worker_result worker_results[RTE_MAX_LCORE];
uint8_t volatile worker_count;

struct lcperf_throughput_ctx {
	uint8_t dev_id;
	uint16_t qp_id;
	uint8_t lcore_id;

	lcperf_enqueue_ops_t enqueue_ops;
	lcperf_populate_ops_t populate_ops;
	uint64_t sess_id;

	const struct lcperf_options *options;
	const struct lcperf_op_fns *op_fns;
	struct lcperf_test_data *tdata;
	struct rte_mempool *buf_pool;
};

void *
lcperf_throughput_test_constructor(uint8_t dev_id, uint16_t qp_id,
				   const struct lcperf_options *options,
				   const struct lcperf_op_fns *op_fns)
{
	struct lcperf_throughput_ctx *ctx = NULL;
	struct lcperf_test_data *tdata = NULL;
	struct rte_mempool *data_buf_pool = NULL;
	char pool_name[32] = "";

	ctx = rte_zmalloc(NULL, sizeof(struct lcperf_throughput_ctx), 0);
	if (ctx == NULL)
		return NULL;

	ctx->dev_id = dev_id;
	ctx->qp_id = qp_id;

	ctx->enqueue_ops = op_fns->enqueue_ops;
	ctx->populate_ops = op_fns->populate_ops;
	ctx->options = options;
	ctx->op_fns = op_fns;

	tdata = lcperf_test_vector_get_dummy(options);
	if (tdata == NULL) {
		RTE_LOG(ERR, USER1, "Failed to get test data\n");
		goto ctx_free;
	}
	ctx->tdata = tdata;

	if (options->op_type == LCPERF_OP_SYM) {
		snprintf(pool_name, sizeof(pool_name), "buf_pool_cdev_%u_qp_%u", dev_id, qp_id);
		data_buf_pool = rte_mempool_create(pool_name, options->nb_descriptors * 2,
						   sizeof(struct lcperf_test_buf_mem), 512, 0, NULL,
						   NULL, NULL, NULL, SOCKET_ID_ANY, 0);

		if (data_buf_pool == NULL) {
			RTE_LOG(ERR, USER1, "Failed to create operation pool\n");
			goto test_vector_free;
		}
		ctx->buf_pool = data_buf_pool;
		RTE_LOG(INFO, USER1, "Buffer pool %s created for device %u, queue %u\n", pool_name,
			dev_id, qp_id);

		if (op_fns->sess_create == NULL) {
			RTE_LOG(ERR, USER1, "Session creation function is NULL\n");
			goto mempool_free;
		}
		ctx->sess_id = op_fns->sess_create(dev_id, &tdata->sym_params);
		if (ctx->sess_id == DAO_LC_SESS_ID_INVALID) {
			RTE_LOG(ERR, USER1, "Could not create session\n");
			goto mempool_free;
		}
	}

	return ctx;

mempool_free:
	if (ctx->buf_pool != NULL) {
		rte_mempool_free(ctx->buf_pool);
		ctx->buf_pool = NULL;
	}
test_vector_free:
	lcperf_test_vector_free(ctx->tdata);
	ctx->tdata = NULL;

ctx_free:
	rte_free(ctx);
	return NULL;
}

static int
lcperf_validate_single_op(struct lcperf_throughput_ctx *ctx, struct dao_lc_res *res,
			  struct lcperf_test_data *tdata, bool update_test_vect)
{
	if (ctx->options->op_type == LCPERF_OP_COMPRESS ||
	    ctx->options->op_type == LCPERF_OP_DECOMPRESS) {
		if (res->compdev_res.status != DAO_LC_COMP_OP_STATUS_SUCCESS) {
			RTE_LOG(ERR, USER1, "Compdev op failed with status: %d\n",
				res->compdev_res.status);
			return -1;
		}
		return 0;
	}

	if (ctx->options->op_type == LCPERF_OP_SYM) {
		struct lcperf_test_buf_mem *buf_mem = NULL;
		int diff = 0;

		if (res->op_cookie == 0) {
			RTE_LOG(ERR, USER1, "Operation cookie is NULL\n");
			return -1;
		}

		if (res->res.cn9k.compcode != DAO_CPT_COMP_GOOD) {
			RTE_LOG(ERR, USER1, "Operation failed with compcode: %u\n",
				res->res.cn9k.compcode);
			return -1;
		}

		if (res->op_cookie != tdata->ops[0].op_cookie) {
			RTE_LOG(ERR, USER1, "Operation cookie mismatch: expected %lu, got %lu\n",
				tdata->ops[0].op_cookie, res->op_cookie);
			return -1;
		}

		buf_mem = (struct lcperf_test_buf_mem *)(uintptr_t)res->op_cookie;

		if (ctx->options->sym_op == LCPERF_CRYPTO_SYM_OP_CIPHER_ONLY) {
			if (update_test_vect) {
				memcpy(tdata->ciphertext.data, buf_mem->in_buf_data,
				       tdata->ciphertext.len);
				return 0;
			}

			if (ctx->options->cipher_op == LCPERF_CRYPTO_SYM_CIPHER_OP_ENCRYPT) {
				diff = memcmp(buf_mem->in_buf_data, tdata->ciphertext.data,
					      tdata->ciphertext.len);
				if (diff != 0) {
					RTE_LOG(ERR, USER1, "Ciphertext mismatch\n");
					return -1;
				}
			} else {
				diff = memcmp(buf_mem->in_buf_data, tdata->plaintext.data,
					      tdata->plaintext.len);
				if (diff != 0) {
					RTE_LOG(ERR, USER1, "Plaintext mismatch\n");
					return -1;
				}
			}
		} else if (ctx->options->sym_op == LCPERF_CRYPTO_SYM_OP_AUTH_ONLY) {
			if (update_test_vect) {
				memcpy(tdata->digest.data, buf_mem->digest, tdata->digest.len);
				return 0;
			}

			if (ctx->options->auth_op == LCPERF_CRYPTO_SYM_AUTH_OP_GENERATE) {
				diff = memcmp(buf_mem->digest, tdata->digest.data,
					      tdata->digest.len);
				if (diff != 0) {
					RTE_LOG(ERR, USER1, "Digest mismatch\n");
					return -1;
				}
			} else if (ctx->options->auth_op == LCPERF_CRYPTO_SYM_AUTH_OP_VERIFY) {
				if (res->res.cn9k.uc_compcode == DAO_UC_ERR_GC_ICV_MISCOMPARE) {
					RTE_LOG(ERR, USER1, "Digest verification failed\n");
					return -1;
				}
			}
		} else {
			RTE_LOG(ERR, USER1, "Unsupported sym operation type: %d\n",
				ctx->options->sym_op);
			return -1;
		}
	}

	return 0;
}

static int
lcperf_check_single_op(struct lcperf_throughput_ctx *ctx, struct lcperf_test_data *tdata,
		       bool update_test_vect)
{
	uint64_t tsc_start = 0;
	struct dao_lc_res res;
	int ret = 0, rc = 0;

	tdata->nb_ops = 1;
	ret = ctx->populate_ops(ctx->sess_id, ctx->options, tdata);
	if (ret < 0) {
		RTE_LOG(ERR, USER1, "Could not populate operation\n");
		return -1;
	}

	ret = ctx->enqueue_ops(ctx->dev_id, ctx->qp_id, tdata, ctx->options);
	if (ret != 1) {
		RTE_LOG(ERR, USER1, "Could not enqueue operation\n");
		rc = -1;
		goto op_buf_free;
	}

	tsc_start = rte_rdtsc_precise();
	while (1) {
		ret = dao_liquid_crypto_dequeue_burst(ctx->dev_id, ctx->qp_id, &res, 1);

		if (ret == 1) {
			rc = lcperf_validate_single_op(ctx, &res, tdata, update_test_vect);
			break;
		}

		/* Check if 1 second timeout has been reached */
		if ((rte_rdtsc_precise() - tsc_start) > rte_get_tsc_hz()) {
			RTE_LOG(ERR, USER1, "Dequeue operation timed out.\n");
			rc = -1;
			break;
		}
	}

op_buf_free:
	if (ctx->buf_pool != NULL && tdata->ops[0].op_cookie != 0) {
		/* Free op buf memory. */
		rte_mempool_put(ctx->buf_pool, (void *)(tdata->ops[0].op_cookie));
		tdata->ops[0].op_cookie = 0;
	}

	return rc;
}

static int
lcperf_check_update_test_vec_single_op(struct lcperf_throughput_ctx *ctx,
				       struct lcperf_test_data *tdata)
{
	int rc = 0;

	if (ctx->options->op_type == LCPERF_OP_COMPRESS ||
	    ctx->options->op_type == LCPERF_OP_DECOMPRESS)
		goto check_single_op;

	if (tdata->sym_params.plaintext.len != ctx->options->test_buffer_size) {
		tdata->plaintext.len = ctx->options->test_buffer_size;
		tdata->ciphertext.len = ctx->options->test_buffer_size;

		/* For test vector generation perform encrypt / auth generation. */
		if (ctx->options->sym_op == LCPERF_CRYPTO_SYM_OP_CIPHER_ONLY)
			tdata->cipher_op = LCPERF_CRYPTO_SYM_CIPHER_OP_ENCRYPT;
		else if (ctx->options->sym_op == LCPERF_CRYPTO_SYM_OP_AUTH_ONLY)
			tdata->auth_op = LCPERF_CRYPTO_SYM_AUTH_OP_GENERATE;

		rc = lcperf_check_single_op(ctx, tdata, true);
		if (rc < 0) {
			RTE_LOG(ERR, USER1, "Single operation test vector update failed\n");
			return rc;
		}

		/* Restore original cipher and auth operations */
		tdata->auth_op = ctx->options->auth_op;
		tdata->cipher_op = ctx->options->cipher_op;
	}

check_single_op:
	rc = lcperf_check_single_op(ctx, tdata, false);

	return rc;
}

int
lcperf_throughput_test_runner(void *test_ctx)
{
	uint64_t ops_enqd = 0, ops_enqd_total = 0, ops_enqd_failed = 0, total_ops_enqd_failed = 0;
	uint64_t ops_deqd = 0, ops_deqd_total = 0, ops_deqd_failed = 0;
	uint64_t tsc_start, tsc_end, tsc_duration, drain_tsc_start;
	uint64_t time_limit_tsc, drain_time_limit_tsc;
	struct lcperf_throughput_ctx *ctx = test_ctx;
	uint32_t burst_size, curr_burst_sz;
	uint32_t lcore = rte_lcore_id();
	struct lcperf_test_data *tdata;
	bool timeout_occurred = false;
	double tsc_per_op = 0.0;
	bool rate_limit_enabled;
	uint64_t remaining_ops;
	uint64_t total_ops, j;
	struct dao_lc_res res;
	uint8_t dev_id, idx;
	uint16_t qp_id;
	int ret;

	ctx->lcore_id = lcore;

	tdata = ctx->tdata;
	if (tdata == NULL) {
		RTE_LOG(ERR, USER1, "Test data is NULL\n");
		return -1;
	}

	tdata->op_cookie = 0;
	tdata->buf_pool = ctx->buf_pool;
	tdata->ops_unused = 0;
	tdata->ops_enqd = 0;
	tdata->cipher_op = ctx->options->cipher_op;
	tdata->auth_op = ctx->options->auth_op;

	if (lcperf_check_update_test_vec_single_op(ctx, tdata) < 0) {
		RTE_LOG(ERR, USER1, "Single operation check failed\n");
		return -1;
	}

	burst_size = ctx->options->burst_size;
	total_ops = ctx->options->total_ops;
	dev_id = ctx->dev_id;
	qp_id = ctx->qp_id;

	/* Calculate rate limiting parameters if enabled */
	rate_limit_enabled = (ctx->options->throughput_limit_gbps > 0);
	if (rate_limit_enabled) {
		/*
		 * Calculate per-worker throughput limit from total limit:
		 * per_worker_gbps = total_limit_gbps / num_workers
		 *
		 * Calculate target ops per second from per-worker Gbps limit:
		 * target_ops_per_sec = (per_worker_gbps * 1e9) / (buffer_size_bytes * 8)
		 *
		 * Then calculate TSC cycles per operation:
		 * tsc_per_op = tsc_hz / target_ops_per_sec
		 */
		double per_worker_gbps, target_ops_per_sec;
		uint16_t num_workers;

		num_workers = rte_lcore_count() - 1; /* Exclude main lcore */
		if (num_workers == 0) {
			RTE_LOG(WARNING, USER1,
				"Throughput limit specified but no worker lcores detected.\n");
			return -1;
		}

		per_worker_gbps = ctx->options->throughput_limit_gbps / num_workers;
		target_ops_per_sec = (per_worker_gbps * 1e9) / (ctx->options->test_buffer_size * 8);
		tsc_per_op = (double)rte_get_tsc_hz() / target_ops_per_sec;
	}

	time_limit_tsc = rte_get_tsc_hz() * ctx->options->enq_timeout * 60;
	tsc_start = rte_rdtsc_precise();

	while (!force_quit && (ops_enqd_total < total_ops)) {
		remaining_ops = total_ops - ops_enqd_total;
		curr_burst_sz = RTE_MIN(remaining_ops, burst_size);

		ops_enqd = 0;
		ops_deqd = 0;
		ops_enqd_failed = 0;

		tdata->nb_ops = curr_burst_sz;

		ret = ctx->populate_ops(ctx->sess_id, ctx->options, tdata);
		if (ret == 0) {
			ret = ctx->enqueue_ops(dev_id, qp_id, tdata, ctx->options);
			ops_enqd += ret;
			ops_enqd_failed += curr_burst_sz - ret;
		} else {
			ops_enqd_failed += curr_burst_sz;
		}

		ops_enqd_total += ops_enqd;
		total_ops_enqd_failed += ops_enqd_failed;

		/* Rate limiting: wait if we're ahead of schedule */
		if (rate_limit_enabled) {
			uint64_t target_tsc = tsc_start + (uint64_t)(ops_enqd_total * tsc_per_op);

			while (rte_rdtsc_precise() < target_tsc)
				rte_pause();
		}

		/* Check if time limit has been reached */
		if ((ops_enqd_failed > 0) && ((rte_rdtsc_precise() - tsc_start) > time_limit_tsc)) {
			RTE_LOG(ERR, USER1,
				"Time limit reached due to enqueue failures. Breaking loop.\n");
			break;
		}

		for (j = 0; j < burst_size; j++) {
			ret = dao_liquid_crypto_dequeue_burst(dev_id, qp_id, &res, 1);
			if (ret == 1) {
				ops_deqd++;
				if (res.op_cookie != 0) {
					rte_mempool_put(ctx->buf_pool,
							(void *)(uintptr_t)res.op_cookie);
					res.op_cookie = 0;
				}
			} else {
				ops_deqd_failed++;
				break;
			}
		}

		ops_deqd_total += ops_deqd;
	}

	drain_time_limit_tsc = rte_get_tsc_hz() * ctx->options->drain_timeout * 60;
	drain_tsc_start = rte_rdtsc_precise();
	/* Dequeue any remaining operations */
	for (j = 0; ops_deqd_total < ops_enqd_total; j++) {
		ret = dao_liquid_crypto_dequeue_burst(dev_id, qp_id, &res, 1);
		if (ret == 1) {
			ops_deqd_total++;
			if (res.op_cookie != 0) {
				rte_mempool_put(ctx->buf_pool, (void *)(uintptr_t)res.op_cookie);
				res.op_cookie = 0;
			}
		} else {
			ops_deqd_failed++;
			if (drain_tsc_start + drain_time_limit_tsc < rte_rdtsc_precise()) {
				RTE_LOG(ERR, USER1,
					"Time limit reached during drain. Breaking loop.\n");
				timeout_occurred = true;
				break;
			}
		}
	}

	tsc_end = rte_rdtsc_precise();
	tsc_duration = (tsc_end - tsc_start);

	/* Skip performance reporting if timeout occurred */
	if (timeout_occurred) {
		RTE_LOG(ERR, USER1, "Lcore %u: Skipping performance report due to timeout\n",
			ctx->lcore_id);
		return -1;
	}

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
		printf("%14s%14s%14s%14s%14s%14s%14s%14s%14s\n\n", "lcore id", "Buf Size",
		       "Enqueued", "Dequeued", "Failed Enq", "Failed Deq", "MOps", "Gbps",
		       "Cycles/Buf");

	printf("%14u%14u%14" PRIu64 "%14" PRIu64 "%14" PRIu64 "%14" PRIu64 "%14.5f%14.5f%14.2f\n",
	       ctx->lcore_id, ctx->options->test_buffer_size, ops_enqd_total, ops_deqd_total,
	       total_ops_enqd_failed, ops_deqd_failed, ops_per_second / 1000000, throughput_gbps,
	       cycles_per_packet);

	/* Store results for summary calculation */
	idx = __sync_fetch_and_add(&worker_count, 1);
	if (idx < RTE_MAX_LCORE) {
		worker_results[idx].lcore_id = ctx->lcore_id;
		worker_results[idx].ops_enqueued = ops_enqd_total;
		worker_results[idx].ops_dequeued = ops_deqd_total;
		worker_results[idx].ops_enq_retries = total_ops_enqd_failed;
		worker_results[idx].ops_deq_retries = ops_deqd_failed;
		worker_results[idx].mops = ops_per_second / 1000000;
		worker_results[idx].gbps = throughput_gbps;
		worker_results[idx].cycles_per_buf = cycles_per_packet;
	}

	return 0;
}

void
lcperf_throughput_test_destructor(void *arg)
{
	struct lcperf_throughput_ctx *ctx = arg;

	if (ctx == NULL)
		return;

	if (ctx->options->op_type == LCPERF_OP_SYM) {
		if (ctx->sess_id != DAO_LC_SESS_ID_INVALID && ctx->op_fns != NULL &&
		    ctx->op_fns->sess_destroy != NULL) {
			ctx->op_fns->sess_destroy(ctx->dev_id, ctx->sess_id);
			ctx->sess_id = DAO_LC_SESS_ID_INVALID;
		}

		if (ctx->buf_pool != NULL) {
			rte_mempool_free(ctx->buf_pool);
			ctx->buf_pool = NULL;
		}
	}

	if (ctx->tdata != NULL) {
		lcperf_test_vector_free(ctx->tdata);
		ctx->tdata = NULL;
	}

	rte_free(ctx);
}

void
lcperf_print_throughput_summary(uint32_t buffer_size)
{
	double total_mops = 0.0;
	double total_gbps = 0.0;
	uint64_t total_ops_enqueued = 0;
	uint64_t total_ops_dequeued = 0;
	uint64_t total_enq_retries = 0;
	uint64_t total_deq_retries = 0;
	double avg_cycles_per_buf = 0.0;
	uint8_t i;

	if (worker_count == 0)
		return;

	printf("\n");
	printf("# Performance Summary\n");
	printf("#\n");
	printf("# Buffer size: %u bytes\n", buffer_size);
	printf("# Total worker threads: %u\n", worker_count);
	printf("#\n");

	for (i = 0; i < worker_count; i++) {
		total_mops += worker_results[i].mops;
		total_gbps += worker_results[i].gbps;
		total_ops_enqueued += worker_results[i].ops_enqueued;
		total_ops_dequeued += worker_results[i].ops_dequeued;
		total_enq_retries += worker_results[i].ops_enq_retries;
		total_deq_retries += worker_results[i].ops_deq_retries;
		avg_cycles_per_buf += worker_results[i].cycles_per_buf;
	}

	avg_cycles_per_buf /= worker_count;

	printf("# Total Operations Enqueued: %12" PRIu64 "\n", total_ops_enqueued);
	printf("# Total Operations Dequeued: %12" PRIu64 "\n", total_ops_dequeued);
	printf("# Total Enqueue Retries:     %12" PRIu64 "\n", total_enq_retries);
	printf("# Total Dequeue Retries:     %12" PRIu64 "\n", total_deq_retries);
	printf("#\n");
	printf("# TOTAL THROUGHPUT:\n");
	printf("#   Total MOps:      %12.5f\n", total_mops);
	printf("#   Total Gbps:      %12.5f\n", total_gbps);
	printf("#   Avg Cycles/Buf:  %12.2f\n", avg_cycles_per_buf);
	printf("#\n");
	printf("# PER-WORKER AVERAGE:\n");
	printf("#   Avg MOps/worker: %12.5f\n", total_mops / worker_count);
	printf("#   Avg Gbps/worker: %12.5f\n", total_gbps / worker_count);
	printf("#\n");
}
