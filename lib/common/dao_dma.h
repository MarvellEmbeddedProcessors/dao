/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

/**
 * @file
 *
 * DAO DMA helper
 */

#ifndef __INCLUDE_DAO_DMA_H__
#define __INCLUDE_DAO_DMA_H__

#include <rte_eal.h>

#include <rte_dmadev.h>
#include <rte_lcore.h>
#include <rte_mempool.h>
#include <rte_prefetch.h>
#include <rte_vect.h>

#include <dao_config.h>

#include "dao_log.h"

/** DMA MAX pointer */
#define DAO_DMA_MAX_POINTER 15u

/** DMA MAX META pointer MAX DMA POINTER  */
#define DAO_DMA_MAX_META_POINTER 48

/** DMA Max VCHAN per lcore */
#define DAO_DMA_MAX_VCHAN_PER_LCORE 64

/** DMA inflight event meta data */
#define DAO_DMA_MAX_INFLIGHT_MDATA 4096

/** DMA doorbell threshold */
#define DAO_DMA_DOORBELL_THRESHOLD 1024

/** DMA inflight event completion meta data */
struct dao_dma_cmpl_mdata {
	/** Pending counter address */
	uint16_t *pend_ptr[DAO_DMA_MAX_META_POINTER];
	/** Pending value */
	uint16_t pend_val[DAO_DMA_MAX_META_POINTER];
	/** Completion val to write */
	union {
		uint16_t val[DAO_DMA_MAX_META_POINTER];
		uint32_t val32[DAO_DMA_MAX_META_POINTER];
	};
	/** Completion address to write */
	uint16_t *ptr[DAO_DMA_MAX_META_POINTER];
	/** Count */
	uint16_t cnt;
};

/** DMA per vchan state */
struct dao_dma_vchan_state {
	/** Tail index */
	uint16_t tail;
	/** Head index */
	uint16_t head;
	/** DMA device ID */
	int16_t devid;
	/** DMA device vchan */
	uint8_t vchan;
	uint8_t rsvd;
	/** Source pointer index */
	uint16_t src_i;
	/** Destination pointer index */
	uint16_t dst_i;
	/** DMA flush threshold */
	uint8_t flush_thr;
	/** DMA auto free enabled */
	uint8_t auto_free : 1;
	uint8_t rsvd2 : 7;
	/** DMA pending ops */
	uint16_t pend_ops;
	/** DMA source SGE's */
	struct rte_dma_sge src[DAO_DMA_MAX_POINTER];
	/** DMA destination SGE's */
	struct rte_dma_sge dst[DAO_DMA_MAX_POINTER];
	/** DMA pointers count */
	uint64_t ptrs;
	/** DMA ops count */
	uint64_t ops;
	/** DMA doorbells count */
	uint64_t dbells;
	/** DMA enqueue errors */
	uint64_t dma_enq_errs;
	/** DMA completion errors */
	uint64_t dma_compl_errs;
	/** Ops memory buffer base */
	void *ops_mem;
	/** Precomputed ops pointer array */
	struct rte_dma_op **dma_ops;
	/** Ops ring head (consumer/free index) */
	uint16_t ops_head;
	/** Ops ring tail (producer/alloc index) */
	uint16_t ops_tail;
	/** Ops ring mask (size - 1, must be power of 2) */
	uint16_t ops_mask;
	/** DMA events meta data */
	struct dao_dma_cmpl_mdata mdata[DAO_DMA_MAX_INFLIGHT_MDATA];
} __rte_cache_aligned;

/** DMA per lcore vchan info */
struct dao_dma_vchan_info {
	/** Number of dev2mem vchans */
	uint16_t nb_dev2mem;
	/** Number of mem2dev vchans */
	uint16_t nb_mem2dev;
	/** Dev2mem vchan state */
	struct dao_dma_vchan_state dev2mem[DAO_DMA_MAX_VCHAN_PER_LCORE];
	/** Mem2dev vchan state */
	struct dao_dma_vchan_state mem2dev[DAO_DMA_MAX_VCHAN_PER_LCORE];
} __rte_cache_aligned;

/** DMA per vchan stats */
struct dao_dma_vchan_stats {
	/** DMA pointers count */
	uint64_t ptrs;
	/** DMA operations count */
	uint64_t ops;
	/** DMA doorbells count */
	uint64_t dbells;
	/** DMA enqueue errors */
	uint64_t enq_errs;
};

/** DMA stats */
struct dao_dma_stats {
	/** Number of dev2mem vchans */
	uint16_t nb_dev2mem;
	/** Number of mem2dev vchans */
	uint16_t nb_mem2dev;
	/** dev2mem vchan stats */
	struct dao_dma_vchan_stats dev2mem[DAO_DMA_MAX_VCHAN_PER_LCORE];
	/** mem2dev vchan stats */
	struct dao_dma_vchan_stats mem2dev[DAO_DMA_MAX_VCHAN_PER_LCORE];
};

/** DMA per lcore vchan info */
RTE_DECLARE_PER_LCORE(struct dao_dma_vchan_info *, dao_dma_vchan_info);

/**
 * Flush DMA requests and submit ops
 *
 * @return
 *   Zero on success.
 */
int dao_dma_flush_submit(void);

/**
 * Flush DMA requests and submit ops version 2
 *
 * @return
 *   Zero on success.
 */
int dao_dma_flush_submit_v2(void);

/**
 * Flush DMA requests and submit ops
 *
 * @return
 *   Zero on success.
 */
int dao_dma_flush_submit_ops(void);

/**
 * Get DMA stats from DAO library
 *
 * @param lcore_id
 *   Lcore to get stats from.
 * @param stats
 *   Address to store stats.
 * @return
 *   Zero on success.
 */
int dao_dma_stats_get(uint16_t lcore_id, struct dao_dma_stats *stats);

/**
 * Assign dev2mem dma device to an lcore.
 *
 * @param dma_devid
 *   DMA device id to assign to lcore.
 * @param nb_vchans
 *   Number of vchans available in DMA device
 * @param flush_thr
 *   Flush threshold.
 * @return
 *   Zero on success.
 */
int dao_dma_lcore_dev2mem_set(int16_t dma_devid, uint16_t nb_vchans, uint16_t flush_thr);

/**
 * Assign dev2mem dma device to an lcore with ops support.
 *
 * @param dma_devid
 *   DMA device id to assign to lcore.
 * @param nb_vchans
 *   Number of vchans available in DMA device
 * @param flush_thr
 *   Flush threshold.
 * @param nb_ops
 *   Number of DMA operations per vchan.
 * @return
 *   Zero on success.
 */
int dao_dma_lcore_dev2mem_set_ops(int16_t dma_devid, uint16_t nb_vchans, uint16_t flush_thr,
				  uint16_t nb_ops);

/**
 * Assign mem2dev dma device to an lcore.
 *
 * @param dma_devid
 *   DMA device id to assign to lcore.
 * @param nb_vchans
 *   Number of vchans available in DMA device
 * @param flush_thr
 *   Flush threshold.
 * @return
 *   Zero on success.
 */
int dao_dma_lcore_mem2dev_set(int16_t dma_devid, uint16_t nb_vchans, uint16_t flush_thr);

/**
 * Assign mem2dev dma device to an lcore.
 *
 * @param dma_devid
 *   DMA device id to assign to lcore.
 * @param nb_vchans
 *   Number of vchans available in DMA device
 * @param flush_thr
 *   Flush threshold.
 * @param nb_ops
 *   Number of DMA operations per vchan.
 * @return
 *   Zero on success.
 */
int dao_dma_lcore_mem2dev_set_ops(int16_t dma_devid, uint16_t nb_vchans, uint16_t flush_thr,
				  uint16_t nb_ops);

/**
 * Enable or Disable auto free on a mem2dev dma device's vchan of a given lcore.
 *
 * @param dma_devid
 *   DMA device id to assigned to the lcore.
 * @param vchan
 *   mem2dev vchan of the dma device.
 * @param enable
 *   Flag
 * @return
 *   Zero on success.
 */
int dao_dma_lcore_mem2dev_autofree_set(int16_t dma_devid, uint16_t vchan, bool enable);

/**
 * Assign a global DMA device id for control path.
 *
 * @param dev2mem_id
 *    dev2mem dma device id.
 * @param mem2dev_id
 *    mem2dev dma device id.
 * @return
 *    Zero on success.
 */
int dao_dma_ctrl_dev_set(int16_t dev2mem_id, int16_t mem2dev_id);

/**
 * Get global DMA dev2mem device id.
 *
 * @return
 *    dma device id.
 */
int16_t dao_dma_ctrl_dev2mem(void);

/**
 * Get global DMA mem2dev device id.
 *
 * @return
 *    dma device id.
 */
int16_t dao_dma_ctrl_mem2dev(void);

/**
 * Check and wait for all DMA requests that are enqueued to current tail index
 *
 * @param vchan
 *    Vchan ID
 */
void dao_dma_compl_wait_inflight(uint16_t vchan);

/**
 * Tests DMA stats support
 *
 * @return
 *    1 if DMA stats is supported, 0 otherwise.
 */
static __rte_always_inline int
dao_dma_has_stats_feature(void)
{
#if DAO_DMA_STATS
	return 1;
#else
	return 0;
#endif
}

/**
 * Query DMA descriptor capacity for a vchan.
 *
 * @param vchan
 *    Vchan state pointer
 * @return
 *    Number of DMA instructions that can be submitted.
 */
static __rte_always_inline uint16_t
dao_dma_burst_capacity(struct dao_dma_vchan_state *vchan)
{
	return rte_dma_burst_capacity(vchan->devid, vchan->vchan);
}

/**
 * Check if the DMA vchan has enough descriptor capacity for a multi segment enqueue
 *
 * @param vchan
 *    Vchan state pointer
 * @param nb_src
 *    Total source segments to enqueue.
 * @param nb_dst
 *    Total destination segments to enqueue.
 * @return
 *    True if space is available, false otherwise.
 */
static __rte_always_inline bool
dao_dma_desc_avail_get(struct dao_dma_vchan_state *vchan, uint32_t nb_src, uint32_t nb_dst)
{
	int src_avail = vchan->flush_thr - vchan->src_i;
	int dst_avail = vchan->flush_thr - vchan->dst_i;
	uint16_t inflight = vchan->tail - vchan->head;
	uint32_t n_src, n_dst, nb_desc;
	uint8_t flush_thr;

	if (likely((src_avail >= (int)nb_src || !vchan->src_i) &&
		   (dst_avail >= (int)nb_dst || !vchan->dst_i)))
		return true;

	flush_thr = vchan->flush_thr;
	n_src = (nb_src + flush_thr - 1) / flush_thr;
	n_dst = (nb_dst + flush_thr - 1) / flush_thr;
	nb_desc = RTE_MAX(n_src, n_dst);

	/* increment by 1 to consider current enqueued pointers
	 */
	nb_desc++;
	if (inflight + nb_desc > DAO_DMA_MAX_INFLIGHT_MDATA)
		return false;

	return dao_dma_burst_capacity(vchan) >= nb_desc;
}

/**
 * Get DMA operation status
 *
 * @param vchan
 *    Vchan associated with DMA operation.
 * @param op_idx
 *    DMA operation index
 * @return
 *    True  - DMA op complete.
 *    False - DMA op not complete.
 */
static __rte_always_inline bool
dao_dma_op_status(struct dao_dma_vchan_state *vchan, uint16_t op_idx)
{
	uint16_t head = vchan->head;
	uint16_t tail = vchan->tail;

	if (vchan->src_i && (tail == op_idx))
		return false;

	return head <= tail ? (op_idx < head || op_idx >= tail) : (op_idx < head && op_idx >= tail);
}

/**
 * Flush DMA operation
 *
 * @param vchan
 *    Vchan state pointer
 * @param avail
 *    Avail needed post flush
 * @return
 *    True on success.
 */
static __rte_always_inline bool
dao_dma_flush(struct dao_dma_vchan_state *vchan, const uint8_t avail)
{
	int src_avail = vchan->flush_thr - vchan->src_i;
	int dst_avail = vchan->flush_thr - vchan->dst_i;
	uint64_t flags = (uint64_t)vchan->auto_free << 3;
	int rc;

	if (likely((src_avail >= (int)avail || !vchan->src_i) &&
		   (dst_avail >= (int)avail || !vchan->dst_i)))
		goto exit;

	if (vchan->pend_ops >= DAO_DMA_DOORBELL_THRESHOLD)
		flags |= RTE_DMA_OP_FLAG_SUBMIT;

	rc = rte_dma_copy_sg(vchan->devid, vchan->vchan, vchan->src, vchan->dst, vchan->src_i,
			     vchan->dst_i, flags);
	if (unlikely(rc < 0)) {
		if (dao_dma_has_stats_feature())
			vchan->dma_enq_errs++;
		return false;
	}
	vchan->tail++;
	vchan->pend_ops++;

	if (flags & RTE_DMA_OP_FLAG_SUBMIT)
		vchan->pend_ops = 0;

	if (dao_dma_has_stats_feature()) {
		vchan->ptrs += vchan->src_i;
		vchan->ops++;
	}
	vchan->src_i = 0;
	vchan->dst_i = 0;
exit:
	return true;
}

/**
 * Get available space in DMA src vchan state
 *
 * @param vchan
 *    Vchan state pointer
 * @return
 *    Returns space in number of src pointers.
 */
static __rte_always_inline uint16_t
dao_dma_src_avail(struct dao_dma_vchan_state *vchan)
{
	int src_avail = vchan->flush_thr - vchan->src_i;

	return src_avail;
}

/**
 * Get available space in DMA dst vchan state
 *
 * @param vchan
 *    Vchan state pointer
 * @return
 *    Returns space in number of dst pointers.
 */
static __rte_always_inline uint16_t
dao_dma_dst_avail(struct dao_dma_vchan_state *vchan)
{
	int dst_avail = vchan->flush_thr - vchan->dst_i;

	return dst_avail;
}

/**
 * Get DMA src pointer base
 *
 * @param vchan
 *    Vchan state pointer
 * @return
 *    Returns pointer base
 */
static __rte_always_inline struct rte_dma_sge *
dao_dma_sge_src(struct dao_dma_vchan_state *vchan)
{
	return &vchan->src[vchan->src_i];
}

/**
 * Get DMA dst pointer base
 *
 * @param vchan
 *    Vchan state pointer
 * @return
 *    Returns pointer base
 */
static __rte_always_inline struct rte_dma_sge *
dao_dma_sge_dst(struct dao_dma_vchan_state *vchan)
{
	return &vchan->dst[vchan->dst_i];
}

/**
 * Enqueue one DMA pointer pair.
 *
 * Space is vchan state is checked by caller before calling this
 * API
 *
 * @param vchan
 *    Vchan state pointer
 * @param src
 *    source data IOVA
 * @param src_len
 *    source data length
 * @param dst
 *    Destination data IOVA
 * @param dst_len
 *    Destination data len
 */
static __rte_always_inline void
dao_dma_enq_x1(struct dao_dma_vchan_state *vchan, rte_iova_t src, uint32_t src_len, rte_iova_t dst,
	       uint32_t dst_len)
{
	uint16_t src_i = vchan->src_i;
	uint16_t dst_i = vchan->dst_i;

	vchan->dst[dst_i].addr = dst;
	vchan->dst[dst_i].length = dst_len;
	vchan->src[src_i].addr = src;
	vchan->src[src_i].length = src_len;

	vchan->src_i = src_i + 1;
	vchan->dst_i = dst_i + 1;
}

/**
 * Enqueue one DMA pointer for destination address.
 *
 * Space in vchan state is checked by caller before calling this
 * API
 *
 * @param vchan
 *    Vchan state pointer
 * @param dst
 *    Destination data IOVA
 * @param dst_len
 *    Destination data len
 */
static __rte_always_inline void
dao_dma_enq_dst_x1(struct dao_dma_vchan_state *vchan, rte_iova_t dst, uint32_t dst_len)
{
	uint16_t dst_i = vchan->dst_i;

	vchan->dst[dst_i].addr = dst;
	vchan->dst[dst_i].length = dst_len;

	vchan->dst_i = dst_i + 1;
}

/**
 * Enqueue one DMA pointer for source address.
 *
 * Space in vchan state is checked by caller before calling this
 * API
 *
 * @param vchan
 *    Vchan state pointer
 * @param src
 *    source data IOVA
 * @param src_len
 *    source data length
 */
static __rte_always_inline void
dao_dma_enq_src_x1(struct dao_dma_vchan_state *vchan, rte_iova_t src, uint32_t src_len)
{
	uint16_t src_i = vchan->src_i;

	vchan->src[src_i].addr = src;
	vchan->src[src_i].length = src_len;

	vchan->src_i = src_i + 1;
}

/**
 * Enqueue four DMA pointer pairs.
 *
 * @param vchan
 *    Vchan state pointer
 * @param vsrc
 *    source vector in format of ``struct rte_dma_sge``.
 * @param vdst
 *    destination vector in format of ``struct rte_dma_sge``.
 * @return
 *    Number of pointers enqueued.
 */
static __rte_always_inline uint16_t
dao_dma_enq_x4(struct dao_dma_vchan_state *vchan, uint64x2_t *vsrc, uint64x2_t *vdst)
{
	struct rte_dma_sge *src, *dst;
	uint16_t src_i = vchan->src_i;
	uint16_t dst_i = vchan->dst_i;
	int src_avail = vchan->flush_thr - src_i;
	int i;

	src = vchan->src + src_i;
	dst = vchan->dst + dst_i;
	if (src_avail >= 4) {
		vst1q_u64((uint64_t *)&src[0], vsrc[0]);
		vst1q_u64((uint64_t *)&src[1], vsrc[1]);
		vst1q_u64((uint64_t *)&src[2], vsrc[2]);
		vst1q_u64((uint64_t *)&src[3], vsrc[3]);

		vst1q_u64((uint64_t *)&dst[0], vdst[0]);
		vst1q_u64((uint64_t *)&dst[1], vdst[1]);
		vst1q_u64((uint64_t *)&dst[2], vdst[2]);
		vst1q_u64((uint64_t *)&dst[3], vdst[3]);

		vchan->src_i = src_i + 4;
		vchan->dst_i = dst_i + 4;
		return 4;
	}

	i = 0;
	while (i < 4 && src_avail > 0) {
		vst1q_u64((uint64_t *)src, vsrc[i]);
		vst1q_u64((uint64_t *)dst, vdst[i]);
		src++;
		dst++;
		i++;
		src_avail--;
	};
	vchan->src_i = src_i + i;
	vchan->dst_i = dst_i + i;

	/* Flush enqueued pointers */
	dao_dma_flush(vchan, 4);

	src_i = vchan->src_i;
	dst_i = vchan->dst_i;
	src = vchan->src + src_i;
	dst = vchan->dst + dst_i;
	src_avail = vchan->flush_thr - src_i;

	while (i < 4 && src_avail > 0) {
		vst1q_u64((uint64_t *)src, vsrc[i]);
		vst1q_u64((uint64_t *)dst, vdst[i]);
		i++;
		src++;
		dst++;
		src_avail--;
		vchan->src_i++;
		vchan->dst_i++;
	};
	return i;
}

/**
 * Check and update DMA completions.
 *
 * @param vchan
 *    Vchan state pointer
 */
static __rte_always_inline void
dao_dma_check_compl(struct dao_dma_vchan_state *vchan)
{
	uint16_t cmpl;
	bool has_err = 0;

	/* Fetch all DMA completed status */
	cmpl = rte_dma_completed(vchan->devid, vchan->vchan, 128, NULL, &has_err);
	if (unlikely(has_err)) {
		vchan->dma_compl_errs++;
		cmpl += 1;
	}
	vchan->head += cmpl;
}

/**
 * Get available ops count from ring buffer.
 *
 * @param vchan
 *    Vchan state pointer
 * @return
 *    Number of available ops in the ring.
 */
static __rte_always_inline uint16_t
dao_dma_ops_avail(struct dao_dma_vchan_state *vchan)
{
	return vchan->ops_head - vchan->ops_tail;
}

/**
 * Get ops pointers from ring buffer.
 *
 * @param vchan
 *    Vchan state pointer
 * @param n
 *    Number of ops requested
 * @return
 *    Pointer to contiguous ops array (2x ring avoids wrap handling).
 */
static __rte_always_inline struct rte_dma_op **
dao_dma_ops_get(struct dao_dma_vchan_state *vchan, uint16_t n)
{
	uint16_t tail = vchan->ops_tail;

	vchan->ops_tail = tail + n;
	return &vchan->dma_ops[tail & vchan->ops_mask];
}

/**
 * Return ops to ring buffer (bulk) - advances head.
 *
 * @param vchan
 *    Vchan state pointer
 * @param n
 *    Number of ops to return (must match dequeue order)
 */
static __rte_always_inline void
dao_dma_ops_put(struct dao_dma_vchan_state *vchan, uint16_t n)
{
	vchan->ops_head += n;
}

/**
 * Reset ops tail to release unsubmitted ops.
 *
 * @param vchan
 *    Vchan state pointer
 * @param n
 *    Number of ops to release from tail
 */
static __rte_always_inline void
dao_dma_ops_release(struct dao_dma_vchan_state *vchan, uint16_t n)
{
	vchan->ops_tail -= n;
}

/**
 * Store completion metadata directly in rte_dma_op header fields.
 *
 * Layout:
 *   op->user_meta  = ptr       (descriptor offset pointer)
 *   op->event_meta = pend_ptr  (pending counter pointer)
 *   op->rsvd       = val << 16 | pend_val  (non-zero == valid)
 */
static __rte_always_inline void
dao_dma_op_set_cmpl(struct rte_dma_op *op, uint16_t *ptr, uint16_t val, uint16_t *pend_ptr,
		    uint16_t pend_val)
{
	op->user_meta = (uint64_t)(uintptr_t)ptr;
	op->event_meta = (uint64_t)(uintptr_t)pend_ptr;
	op->rsvd = ((uint32_t)val << 16) | pend_val;
}

/**
 * Check and update DMA completions with metadata.
 *
 * @param vchan
 *    Vchan state pointer
 * @param mem_order
 *    Memory order to update address
 */

static __rte_always_inline void
dao_dma_check_meta_compl(struct dao_dma_vchan_state *vchan, const int mem_order)
{
	uint32_t cmpl, i, j, idx = 0;
	bool has_err = 0;

	/* Fetch all DMA completed status */
	cmpl = rte_dma_completed(vchan->devid, vchan->vchan, 128, NULL, &has_err);
	if (unlikely(has_err)) {
		vchan->dma_compl_errs++;
		cmpl += 1;
	}
	for (i = vchan->head; i < vchan->head + cmpl; i++) {
		idx = i % DAO_DMA_MAX_INFLIGHT_MDATA;
		for (j = 0; j < vchan->mdata[idx].cnt; j++) {
			if (mem_order)
				__atomic_store_n(vchan->mdata[idx].ptr[j], vchan->mdata[idx].val[j],
						 __ATOMIC_RELEASE);
			else
				*vchan->mdata[idx].ptr[j] = vchan->mdata[idx].val[j];
			*vchan->mdata[idx].pend_ptr[j] -= vchan->mdata[idx].pend_val[j];
		}
		vchan->mdata[idx].cnt = 0;
	}
	vchan->head += cmpl;
}

/**
 * Check and update DMA completions with metadata version2.
 *
 * @param vchan
 *    Vchan state pointer
 * @param mem_order
 *    Memory order to update address
 */

static __rte_always_inline void
dao_dma_check_meta_compl_ops(struct dao_dma_vchan_state *vchan, const int mem_order)
{
#define DEQ_SZ 128
	uint32_t cmpl, i;
	struct rte_dma_op *deq_ops[DEQ_SZ];

	/* Skip costly dequeue call when no ops are inflight */
	if (vchan->head == vchan->tail)
		return;

	cmpl = rte_dma_dequeue_ops(vchan->devid, vchan->vchan, deq_ops, DEQ_SZ);
	if (!cmpl)
		return;

	for (i = 0; i < cmpl; i++) {
		struct rte_dma_op *op = deq_ops[i];

		if (unlikely(op->status != RTE_DMA_STATUS_SUCCESSFUL))
			vchan->dma_compl_errs++;

		if (op->rsvd) {
			uint16_t *ptr = (uint16_t *)(uintptr_t)op->user_meta;
			uint16_t *pend_ptr = (uint16_t *)(uintptr_t)op->event_meta;
			uint16_t val = op->rsvd >> 16;
			uint16_t pend_val = op->rsvd & 0xFFFF;

			if (mem_order)
				__atomic_store_n(ptr, val, __ATOMIC_RELEASE);
			else
				*ptr = val;
			*pend_ptr -= pend_val;
			op->rsvd = 0;
		}
	}

	/* Return ops to ring buffer */
	dao_dma_ops_put(vchan, cmpl);
	vchan->head += cmpl;
}

/**
 * Update DMA op index metadata.
 *
 * @param vchan
 *    Vchan state pointer
 * @param ptr
 *    desc location to write
 * @param val
 *    Value to store in descriptor location
 * @param pend_ptr
 *    Pending count location to write
 * @param pend_val
 *    Pending Value to store
 * @param tail
 *    Meta data index to store
 */
static __rte_always_inline void
dao_dma_update_cmpl_meta(struct dao_dma_vchan_state *vchan, uint16_t *ptr, uint16_t val,
			 uint16_t *pend_ptr, uint16_t pend_val, uint16_t tail)
{
	uint16_t idx = tail % DAO_DMA_MAX_INFLIGHT_MDATA;
	uint16_t j = vchan->mdata[idx].cnt;

	vchan->mdata[idx].ptr[j] = ptr;
	vchan->mdata[idx].val[j] = val;
	vchan->mdata[idx].pend_ptr[j] = pend_ptr;
	vchan->mdata[idx].pend_val[j] = pend_val;
	vchan->mdata[idx].cnt = j + 1;
}

/**
 * Check and update DMA completions with metadata version2.
 *
 * @param vchan
 *    Vchan state pointer
 * @param mem_order
 *    Memory order to update address
 */

static __rte_always_inline void
dao_dma_check_meta_compl_v2(struct dao_dma_vchan_state *vchan, const int mem_order)
{
	uint32_t cmpl, i, j, idx = 0;
	bool has_err = 0;
	uint32_t *ptr;

	/* Fetch all DMA completed status */
	cmpl = rte_dma_completed(vchan->devid, vchan->vchan, 128, NULL, &has_err);
	if (unlikely(has_err)) {
		vchan->dma_compl_errs++;
		cmpl += 1;
	}
	for (i = vchan->head; i < vchan->head + cmpl; i++) {
		idx = i % DAO_DMA_MAX_INFLIGHT_MDATA;
		for (j = 0; j < vchan->mdata[idx].cnt; j++) {
			ptr = (uint32_t *)vchan->mdata[idx].ptr[j];
			if (mem_order)
				__atomic_store_n(ptr, vchan->mdata[idx].val32[j], __ATOMIC_RELEASE);
			else
				*ptr = vchan->mdata[idx].val32[j];
		}
		vchan->mdata[idx].cnt = 0;
	}
	vchan->head += cmpl;
}

/**
 * Update DMA op index metadata version2.
 *
 * @param vchan
 *    Vchan state pointer
 * @param ptr
 *    desc location to write
 * @param val
 *    Value to store in descriptor location
 * @param tail
 *    Meta data index to store
 */
static __rte_always_inline void
dao_dma_update_cmpl_meta_v2(struct dao_dma_vchan_state *vchan, uint32_t *ptr, uint32_t val,
			    uint16_t tail)
{
	uint16_t idx = tail % DAO_DMA_MAX_INFLIGHT_MDATA;
	uint16_t j = vchan->mdata[idx].cnt;

	vchan->mdata[idx].ptr[j] = (uint16_t *)ptr;
	vchan->mdata[idx].val32[j] = val;
	vchan->mdata[idx].cnt = j + 1;
}

#endif /* __INCLUDE_DAO_DMA_H__ */
