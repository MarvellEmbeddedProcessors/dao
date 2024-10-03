/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */
#ifndef __INCLUDE_VIRTIO_CRYPTO_PRIV_H__
#define __INCLUDE_VIRTIO_CRYPTO_PRIV_H__

#include <rte_common.h>

#include <spec/virtio.h>

#include <dao_virtio_cryptodev.h>
#include <virtio_dev_priv.h>

struct virtio_crypto_queue {
	/* Fast path */
	/* Read only, shared by both service and worker */
	uintptr_t desc_base __rte_cache_aligned;
	uint32_t *notify_addr;
	uint16_t q_sz;
	uint16_t dma_vchan;

	/* Slow path */
	struct dao_virtio_cryptodev *dao_cryptodev __rte_cache_aligned;
	uint16_t qid;

	/* Read-Write worker. */

	/*
	 * Shadow queue tail - increment when worker core finishes descriptor processing.
	 * Updated by worker core, read by service core.
	 *
	 * Must be updated atomically.
	 *
	 */
	uint16_t shadow_q_tail;

	/* Read-Write service. */

	/*
	 * DMA shadow queue head - incremented by service core after DMA of descriptors on shadow
	 * queue is done. Updated by service core, read by worker core.
	 *
	 * Must be updated atomically.
	 */
	uint16_t dma_shadow_q_head __rte_cache_aligned;

	/*
	 * Shadow queue head - increment when service core pushes to shadow queue.
	 * Accessed only by service core.
	 */
	uint16_t shadow_q_head;

	/*
	 * DMA shadow queue tail - increment after service core initiates DMA from shadow queue tail
	 * to host memory. Updated only by service core. Follows shadow_q_tail.
	 */
	uint16_t dma_shadow_q_tail;

	/*
	 * Index ID of the DMA transaction initiated from host memory to local memory. Updated only
	 * by service core.
	 */
	uint16_t dev2mem_desc_dma_idx;

	/*
	 * Set when DMA is initiated from local memory to host memory. Updated only by service core.
	 */
	uint16_t mem2dev_desc_dma_pending;

	/*
	 * Index ID of the DMA transaction initiated from local memory to host memory to update
	 * descriptors. Updated only by service core.
	 */
	uint16_t mem2dev_desc_dma_idx;

	RTE_CACHE_GUARD;

	uint32_t *cb_notify_addr;
	uint64_t *cb_intr_addr;

	/* Shadow Ring space */
	uint64_t sd_desc_base[] __rte_cache_aligned;
} __rte_cache_aligned;

struct virtio_cryptodev {
	struct virtio_dev dev;
	/* config flags */
	uint16_t flags;
	/* Cryptodev ID */
	uint16_t cdev_id;
	/** Default dequeue mempool */
	struct rte_mempool *pool;
	/* Host interrupt for callback */
	bool cb_enabled;

	/* Fast path */
	struct virtio_crypto_queue *qs[DAO_VIRTIO_MAX_QUEUES];
};

void virtio_crypto_desc_validate(struct virtio_crypto_queue *q, uint16_t start, uint16_t count,
				 bool avail, bool used);

#ifdef DAO_VIRTIO_DEBUG
#define VIRTIO_CRYPTO_DESC_CHECK(q, start, count, avail, used)                                     \
	virtio_crypto_desc_validate(q, start, count, avail, used)
#else
#define VIRTIO_CRYPTO_DESC_CHECK(...)
#endif

static inline struct virtio_cryptodev *
virtio_cryptodev_priv(struct dao_virtio_cryptodev *cryptodev)
{
	return (struct virtio_cryptodev *)cryptodev->reserved;
}

static inline struct virtio_cryptodev *
virtio_dev_to_cryptodev(struct virtio_dev *dev)
{
	return (struct virtio_cryptodev *)dev;
}

static inline struct dao_virtio_cryptodev *
virtio_cryptodev_to_dao(struct virtio_cryptodev *cryptodev)
{
	return (struct dao_virtio_cryptodev *)((uintptr_t)cryptodev -
					       offsetof(struct dao_virtio_cryptodev, reserved));
}

/*
 * Virtio crypto descriptor management ops
 */
#define VIRTIO_CRYPTO_DESC_MANAGE_DEF       (0)
#define VIRTIO_CRYPTO_DESC_MANAGE_NOINORDER RTE_BIT64(0)
#define VIRTIO_CRYPTO_DESC_MANAGE_LAST      RTE_BIT64(0)

#define M_NOORDER_F VIRTIO_CRYPTO_DESC_MANAGE_NOINORDER

#define VIRTIO_CRYPTO_DESC_MANAGE_MODES                                                            \
	M(def, VIRTIO_CRYPTO_DESC_MANAGE_DEF)                                                      \
	M(noinorder, M_NOORDER_F)

#define M(name, flags) int virtio_crypto_desc_manage_##name(uint16_t devid, uint16_t qp_count);

VIRTIO_CRYPTO_DESC_MANAGE_MODES
#undef M

static __rte_always_inline void
host_to_local_desc_copy(struct virtio_crypto_queue *q, struct dao_dma_vchan_state *dev2mem,
			uint16_t start, uint16_t end)
{
	uintptr_t sd_desc_base = (uintptr_t)q->sd_desc_base;
	uintptr_t desc_base = q->desc_base;
	uint16_t cnt, q_sz = q->q_sz;
	rte_iova_t src, dst;
	uint32_t copy_len;

	/* Calculate the number of descriptors to copy. Copy till wrap. */
	cnt = desc_off_diff_no_wrap(end, start, q_sz);

	/* Calculate the bytes to be copied. */
	copy_len = cnt * sizeof(struct vring_packed_desc);

	src = (rte_iova_t)DESC_PTR_OFF(desc_base, DESC_OFF(start), 0);
	dst = (rte_iova_t)DESC_PTR_OFF(sd_desc_base, DESC_OFF(start), 0);

	/* Issue descriptor data DMA */
	dao_dma_enq_x1(dev2mem, src, copy_len, dst, copy_len);

	/* Update starting point to copy remaining descriptors. */
	start = desc_off_add(start, cnt, q_sz);

	/* Copy remaining. */

	cnt = desc_off_diff(end, start, q_sz);
	if (cnt) {
		copy_len = cnt * sizeof(struct vring_packed_desc);

		src = (rte_iova_t)DESC_PTR_OFF(desc_base, DESC_OFF(start), 0);
		dst = (rte_iova_t)DESC_PTR_OFF(sd_desc_base, DESC_OFF(start), 0);

		dao_dma_enq_x1(dev2mem, src, copy_len, dst, copy_len);
	}

	/**
	 * Store idx (tail) to monitor descriptor DMA completion. This represents the next free slot
	 * in the vchan state ring and will be used during a flush operation. Either a subsequent
	 * flush ('dao_dma_flush()') or 'dao_dma_flush_submit()' will finalize the entry and
	 * increment the tail.
	 */
	q->dev2mem_desc_dma_idx = dev2mem->tail;

	q->shadow_q_head = start;
}

static __rte_always_inline void
local_to_host_desc_copy(struct virtio_crypto_queue *q, struct dao_dma_vchan_state *mem2dev,
			uint16_t start, uint16_t end)
{
	uintptr_t sd_desc_base = (uintptr_t)q->sd_desc_base;
	uintptr_t desc_base = q->desc_base;
	uint16_t cnt, q_sz = q->q_sz;
	rte_iova_t src, dst;
	uint32_t copy_len;

	/*
	 * The shadow queue descriptors are updated after processing. Copy the descriptors to host
	 * to mark the operation as complete.
	 */

	/* Validate descriptor */
	/* TODO - implement validate descriptor */
	VIRTIO_CRYPTO_DESC_CHECK(q, start, desc_off_diff(end, start, q_sz), true, true);

	/* Calculate the number of descriptors to copy. Copy till wrap. */
	cnt = desc_off_diff_no_wrap(end, start, q_sz);

	/* Calculate the bytes to be copied. */
	copy_len = cnt * sizeof(struct vring_packed_desc);

	src = (rte_iova_t)DESC_PTR_OFF(sd_desc_base, DESC_OFF(start), 0);
	dst = (rte_iova_t)DESC_PTR_OFF(desc_base, DESC_OFF(start), 0);

	/* Issue descriptor data DMA */
	dao_dma_enq_x1(mem2dev, src, copy_len, dst, copy_len);

	/* Update starting point to copy remaining descriptors. */
	start = desc_off_add(start, cnt, q_sz);

	/* Copy remaining. */

	cnt = desc_off_diff(end, start, q_sz);
	if (cnt) {
		copy_len = cnt * sizeof(struct vring_packed_desc);

		src = (rte_iova_t)DESC_PTR_OFF(sd_desc_base, DESC_OFF(start), 0);
		dst = (rte_iova_t)DESC_PTR_OFF(desc_base, DESC_OFF(start), 0);

		dao_dma_enq_x1(mem2dev, src, copy_len, dst, copy_len);
	}

	/**
	 * Store idx (tail) to monitor descriptor DMA completion. This represents the next free slot
	 * in the vchan state ring and will be used during a flush operation. Either a subsequent
	 * flush ('dao_dma_flush()') or 'dao_dma_flush_submit()' will finalize the entry and
	 * increment the tail.
	 */
	q->mem2dev_desc_dma_idx = mem2dev->tail;
	q->mem2dev_desc_dma_pending = 1;

	q->dma_shadow_q_tail = end;
}

#endif /* __INCLUDE_VIRTIO_CRYPTO_PRIV_H__ */
