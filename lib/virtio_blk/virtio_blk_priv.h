/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell.
 */
#ifndef __INCLUDE_VIRTIO_BLK_PRIV_H__
#define __INCLUDE_VIRTIO_BLK_PRIV_H__

/*
 * Virtio blk descriptor management ops
 */
#define VIRTIO_BLK_DESC_MANAGE_DEF       (0)
#define VIRTIO_BLK_DESC_MANAGE_NOINORDER RTE_BIT64(0)
#define VIRTIO_BLK_DESC_MANAGE_MSEG      RTE_BIT64(1)
#define VIRTIO_BLK_DESC_MANAGE_EXTBUF    RTE_BIT64(2)
#define VIRTIO_BLK_DESC_MANAGE_LAST      RTE_BIT64(2)

#define M_NOORDER_F VIRTIO_BLK_DESC_MANAGE_NOINORDER
#define M_MSEG_F    VIRTIO_BLK_DESC_MANAGE_MSEG
#define M_EBUF_F    VIRTIO_BLK_DESC_MANAGE_EXTBUF

#define VIRTIO_BLK_DESC_MANAGE_MODES                                                               \
	M(def, VIRTIO_BLK_DESC_MANAGE_DEF)                                                         \
	M(noinorder, M_NOORDER_F)                                                                  \
	M(mseg, M_MSEG_F)                                                                          \
	M(extbuf, M_EBUF_F)                                                                        \
	M(noinorder_mseg, M_MSEG_F | M_NOORDER_F)                                                  \
	M(noinorder_extbuf, M_NOORDER_F | M_EBUF_F)                                                \
	M(mseg_extbuf, M_MSEG_F | M_EBUF_F)                                                        \
	M(noinorder_mseg_extbuf, M_MSEG_F | M_NOORDER_F | M_EBUF_F)

#define M(name, flags) int virtio_blk_desc_manage_##name(uint16_t devid, uint16_t qp_count);

VIRTIO_BLK_DESC_MANAGE_MODES
#undef M

/**
 Flags to control dequeue function pointers
*/
#define VIRTIO_BLK_DEQ_DEFAULT		(0)
#define VIRTIO_BLK_DEQ_NOINOR		RTE_BIT64(0)
#define VIRTIO_BLK_DEQ_LAST		RTE_BIT64(1)

#define D_NOORDER_F VIRTIO_BLK_DEQ_NOINOR

#define VIRTIO_BLK_DEQ_FASTPATH_MODES				\
	R(deflt, VIRTIO_BLK_DEQ_DEFAULT)			\
	R(noinorder, D_NOORDER_F)

#define R(name, flags)										\
	uint16_t virtio_blk_deq_##name(void *q, void **pkts, uint16_t nb_pkts);			\
	uint16_t virtio_blk_deq_ext_##name(void *q, void **pkts, uint16_t nb_pkts);

VIRTIO_BLK_DEQ_FASTPATH_MODES
#undef R

#define VIRTIO_BLK_COMPL_DEF		(0)
#define VIRTIO_BLK_COMPL_LAST		(1)

#define VIRTIO_BLK_COMPL_EXTBUF		RTE_BIT64(15)

#define VIRTIO_BLK_COMPL_FASTPATH_MODES			\
	T(def, VIRTIO_BLK_COMPL_DEF)

#define T(name, flags)										\
	uint16_t virtio_blk_process_compl_##name(void *q, void **pkts, uint16_t nb_pkts);	\
	uint16_t virtio_blk_process_compl_ext_##name(void *q, void **pkts, uint16_t nb_pkts);

VIRTIO_BLK_COMPL_FASTPATH_MODES
#undef T

struct virtio_blk_queue {
	/* Fast path */
	/* Read only, shared by both service and worker */
	uintptr_t desc_base __rte_cache_aligned;
	uint32_t *notify_addr;
	uint16_t data_off;
	uint16_t buf_len;
	uint16_t q_sz;
	uint16_t dma_vchan;
	uint16_t blkdev_id;
	uint8_t virtio_hdr_sz;
	uint8_t auto_free;

	/* Slow path */
	struct dao_virtio_blkdev *dao_blkdev __rte_cache_aligned;
	uint16_t qid;

	/* Read-Write worker. */
	uint16_t pend_sd_mbuf __rte_cache_aligned;
	uint16_t pend_sd_mbuf_idx;
	uint16_t pend_compl_off;
	uint16_t m2d_pend_sd_mbuf;
	uint16_t m2d_pend_sd_mbuf_idx;

	RTE_CACHE_GUARD;

	/* Read-Write service. */
	uint16_t pend_sd_desc __rte_cache_aligned;
	uint16_t pend_sd_desc_idx;
	uint16_t pend_compl_idx;
	uint16_t pend_compl;
	uint16_t compl_off;

	RTE_CACHE_GUARD;

	uint16_t last_off __rte_cache_aligned;
	uint16_t sd_desc_off;
	uint16_t sd_mbuf_off;
	uint32_t *cb_notify_addr;
	uint64_t *cb_intr_addr;

	/* Mempool to use for DMA inbound */
	struct rte_mempool *mp;
	union {
		void **mbuf_arr;
		void **extbuf_arr;
	};
	uintptr_t driver_area;
	uintptr_t sd_driver_area;
	/* Shadow Ring space */
	uint64_t sd_desc_base[] __rte_cache_aligned;
} __rte_cache_aligned;

struct virtio_blkdev {
	struct virtio_dev dev;
	bool auto_free_en;
	/* config flags */
	uint16_t flags;
	union {
		/** Default dequeue mempool */
		struct rte_mempool *pool;
		/** Valid when DOS_VIRTIO_BLKDEV_EXTBUF is set */
		uint16_t dataroom_size;
	};
	/* Number of virt queues */
	uint16_t num_queues;

	/* Fast path data */
	struct virtio_blk_queue *qs[DAO_VIRTIO_MAX_QUEUES] __rte_cache_aligned;
};

extern struct dao_virtio_blkdev_cbs blkdev_user_cbs;
uint8_t virtio_blkdev_hdr_size(struct virtio_blkdev *blkdev);
void virtio_blk_flush_deq(struct virtio_blk_queue *q);
void virtio_blk_flush_deq_ext(struct virtio_blk_queue *q);
void virtio_blk_desc_validate(struct virtio_blk_queue *q, uint16_t start,
			      uint16_t count, bool avail, bool used);

#ifdef DAO_VIRTIO_DEBUG
#define VIRTIO_BLK_DESC_CHECK(q, start, count, avail, used)                                        \
	virtio_blk_desc_validate(q, start, count, avail, used)
#else
#define VIRTIO_BLK_DESC_CHECK(...)
#endif

static inline struct virtio_blkdev *
virtio_blkdev_priv(struct dao_virtio_blkdev *blkdev)
{
	return (struct virtio_blkdev *)blkdev->reserved;
}

static inline struct virtio_blkdev *
virtio_dev_to_blkdev(struct virtio_dev *dev)
{
	return (struct virtio_blkdev *)dev;
}

static inline struct dao_virtio_blkdev *
virtio_blkdev_to_dao(struct virtio_blkdev *blkdev)
{
	return (struct dao_virtio_blkdev *)((uintptr_t)blkdev -
					    offsetof(struct dao_virtio_blkdev, reserved));
}

static __rte_always_inline void
free_extbufs(struct virtio_blk_queue *q, uint16_t off, uint16_t q_sz, uint16_t num, uint16_t flags)
{
	uint8_t blkdev_id = q->blkdev_id;
	void **extbuf = q->extbuf_arr;
	uint16_t cnt;

	RTE_SET_USED(flags);

	cnt = (off + num) > q_sz ? q_sz - off : num;
	blkdev_user_cbs.extbuf_put(blkdev_id, extbuf + off, cnt);
	off = (off + cnt) & (q_sz - 1);
	cnt = num - cnt;
	if (cnt)
		blkdev_user_cbs.extbuf_put(blkdev_id, extbuf + off, cnt);
}

static __rte_always_inline uint16_t
alloc_extbufs(struct virtio_blk_queue *q, uint16_t off, uint16_t q_sz, uint16_t num)
{
	uint8_t blkdev_id = q->blkdev_id;
	void **extbuf = q->extbuf_arr;
	uint16_t cnt;

	cnt = (off + num) > q_sz ? q_sz - off : num;
	if (blkdev_user_cbs.extbuf_get(blkdev_id, extbuf + off, cnt) < 0)
		return 0;

	off = (off + cnt) & (q_sz - 1);
	cnt = num - cnt;
	if (cnt && blkdev_user_cbs.extbuf_get(blkdev_id, extbuf + off, cnt) < 0)
		num -= cnt;

	return num;
}

static __rte_always_inline uint16_t
alloc_mbufs(void **mbuf_arr, struct rte_mempool *mp, uint16_t off, uint16_t q_sz,
	    uint16_t nb_mbufs)
{
	uint16_t cnt;

	cnt = (off + nb_mbufs) > q_sz ? q_sz - off : nb_mbufs;
	if (rte_mempool_get_bulk(mp, (void **)(mbuf_arr + off), cnt))
		return 0;
	off = (off + cnt) & (q_sz - 1);
	cnt = nb_mbufs - cnt;
	if (cnt && rte_mempool_get_bulk(mp, (void **)(mbuf_arr + off), cnt))
		nb_mbufs -= cnt;
	return nb_mbufs;
}

static __rte_always_inline void
free_mseg_mbufs(struct virtio_blk_queue *q, void **mbuf_arr, uint16_t off,
		uint16_t q_sz, uint16_t nb_mbufs)
{
	struct rte_mempool *mp;
	uint16_t cnt, i, count;

	/* Assuming all segments pkts are coming from same pool in this Tx queue and
	 * all mbuf's ref_cnt is 1 without ext buf.
	 */
	/* Get mempool from first mbuf */
	mp = q->mp;
	cnt = (off + nb_mbufs) > q_sz ? q_sz - off : nb_mbufs;
	count = cnt & ~(0x3u);
	for (i = 0; i < count; i += 4) {
		if (unlikely(mbuf_arr[off] == NULL || mbuf_arr[off + 1] == NULL ||
			     mbuf_arr[off + 2] == NULL || mbuf_arr[off + 3] == NULL))
			break;
		rte_mempool_put_bulk(mp, (void **)&mbuf_arr[off], 4);
		off += 4;
	}

	rte_mempool_put_bulk(mp, &mbuf_arr[off], cnt - i);

	off = (off + cnt - i) & (q_sz - 1);
	cnt = nb_mbufs - cnt;
	if (!cnt)
		return;

	count = cnt & ~(0x3u);
	for (i = 0; i < count; i += 4) {
		if (unlikely(mbuf_arr[off] == NULL || mbuf_arr[off + 1] == NULL ||
			     mbuf_arr[off + 2] == NULL || mbuf_arr[off + 3] == NULL))
			break;
		rte_mempool_put_bulk(mp, (void **)&mbuf_arr[off], 4);
		off += 4;
	}
	rte_mempool_put_bulk(mp, &mbuf_arr[off], cnt - i);
}

static __rte_always_inline void
free_mbufs(struct virtio_blk_queue *q, void **mbuf_arr, uint16_t off, uint16_t q_sz,
	 uint16_t nb_mbufs, const uint16_t flags)
{
	struct rte_mempool *mp;
	uint16_t cnt;

	if (flags & VIRTIO_BLK_DESC_MANAGE_MSEG)
		return free_mseg_mbufs(q, mbuf_arr, off, q_sz, nb_mbufs);

	/* Assuming all segments pkts are coming from same pool in this Tx queue and
	 * all mbuf's ref_cnt is 1 without ext buf.
	 */
	/* Get mempool from first mbuf */
	mp = q->mp;
	cnt = (off + nb_mbufs) > q_sz ? q_sz - off : nb_mbufs;
	rte_mempool_put_bulk(mp, (void **)&mbuf_arr[off], cnt);
	off = (off + cnt) & (q_sz - 1);
	cnt = nb_mbufs - cnt;
	if (cnt)
		rte_mempool_put_bulk(mp, (void **)&mbuf_arr[off], cnt);
}

static __rte_always_inline uint16_t
fetch_io_desc_prep(struct virtio_blk_queue *q, struct dao_dma_vchan_state *dev2mem,
		    struct rte_dma_sge *src, struct rte_dma_sge *dst, const uint16_t flags)
{
	uintptr_t sd_desc_base = (uintptr_t)q->sd_desc_base;
	uint16_t sd_desc_off, pend_sd_desc;
	uintptr_t desc_base = q->desc_base;
	void **mbuf_arr;
	uint16_t q_sz = q->q_sz;
	uint32_t notify_data;
	uint16_t next_off, off;
	int i, j = 0;
	int nb_desc;
	int desc_count = 0;
	uint16_t sd_desc_val = 0;

	pend_sd_desc = q->pend_sd_desc;
	sd_desc_off = q->sd_desc_off;

	/* Include the wrap bit to check if there are descriptors */
	notify_data = __atomic_load_n(q->notify_addr, __ATOMIC_RELAXED);
	next_off = (notify_data >> 16) & 0xFFFF;
	if (unlikely(next_off == sd_desc_off))
		return 0;

	/* Limit the fetch to end of the queue */
	nb_desc = desc_off_diff(next_off, sd_desc_off, q_sz) - pend_sd_desc;
	if (unlikely(!nb_desc))
		return 0;

	/* Allocate required mbufs */
	off = desc_off_add(sd_desc_off, pend_sd_desc, q_sz);
	off = DESC_OFF(off);
	mbuf_arr = q->mbuf_arr;

	if (flags & VIRTIO_BLK_DESC_MANAGE_EXTBUF)
		nb_desc = alloc_extbufs(q, off, q_sz, nb_desc);
	else
		nb_desc = alloc_mbufs(mbuf_arr, q->mp, off, q_sz, nb_desc);

	if (unlikely(!nb_desc))
		return 0;

	/* Assume nothing else is pending now */
	/* Start DMA of descriptors */
	i = 0;
	do {
		i = (off + nb_desc) > q_sz ? (q_sz - off) : nb_desc;
		src[j].addr = (rte_iova_t)DESC_PTR_OFF(desc_base, off, 0);
		dst[j].addr = (rte_iova_t)DESC_PTR_OFF(sd_desc_base, off, 0);
		src[j].length = i << 4;
		dst[j].length = i << 4;
		desc_count += i;
		off = (off + i) & (q_sz - 1);
		nb_desc -= i;
		j++;
	} while (nb_desc);

	sd_desc_val = desc_off_add(q->sd_desc_off, desc_count + q->pend_sd_desc, q->q_sz);
	q->pend_sd_desc += desc_count;
	dao_dma_update_cmpl_meta(dev2mem, &q->sd_desc_off, sd_desc_val, &q->pend_sd_desc,
				 desc_count, dev2mem->tail);
	return j;
}

static __rte_always_inline void
mark_deq_compl_no_inorder(struct virtio_blk_queue *q, struct dao_dma_vchan_state *mem2dev,
			  uint16_t start, uint16_t nb_desc)
{
	uintptr_t sd_desc_base = (uintptr_t)q->sd_desc_base;
	uintptr_t desc_base = q->desc_base;
	uint16_t q_sz = q->q_sz;
	uint16_t end, pend;

	end = desc_off_add(start, nb_desc, q_sz);
	pend = desc_off_diff_no_wrap(end, start, q_sz);

	/* Issue descriptor data DMA */
	dao_dma_enq_x1(mem2dev, (rte_iova_t)DESC_PTR_OFF(sd_desc_base, DESC_OFF(start), 0),
		       DESC_ENTRY_SZ * pend,
		       (rte_iova_t)DESC_PTR_OFF(desc_base, DESC_OFF(start), 0),
		       DESC_ENTRY_SZ * pend);

	start = desc_off_add(start, pend, q_sz);
	pend = end - start;

	if (pend) {
		dao_dma_enq_x1(mem2dev, (rte_iova_t)DESC_PTR_OFF(sd_desc_base, DESC_OFF(start), 0),
			       DESC_ENTRY_SZ * pend,
			       (rte_iova_t)DESC_PTR_OFF(desc_base, DESC_OFF(start), 0),
			       DESC_ENTRY_SZ * pend);
	}
}

static __rte_always_inline void
mark_io_desc_compl(struct virtio_blk_queue *q, struct dao_dma_vchan_state *mem2dev, uint16_t start,
		   uint16_t nb_desc, const uint16_t flags)
{
	uintptr_t sd_desc_base = (uintptr_t)q->sd_desc_base;
	uintptr_t desc_base = q->desc_base;
	uint16_t q_sz = q->q_sz;
	rte_iova_t src, dst;
	uint64_t last_id;
	uint64_t first;
	uint64_t used;
	uint16_t end;

	RTE_SET_USED(flags);
	if (unlikely(!q->auto_free)) {
		if (flags & VIRTIO_BLK_DESC_MANAGE_EXTBUF)
			free_extbufs(q, DESC_OFF(start), q_sz, nb_desc,
				     flags);
		else
			free_mbufs(q, q->mbuf_arr, DESC_OFF(start), q_sz,
				   nb_desc, flags);
	}

	end = desc_off_add(start, nb_desc - 1, q_sz);
	/* Overwrite buffer id in first descriptor second word */
	last_id = (*DESC_PTR_OFF(sd_desc_base, end, 8) >> 32) & 0xFFFF;
	first = *DESC_PTR_OFF(sd_desc_base, start, 8) & ~0xFFFF00000000UL;
	/* Mark the same value for free as used */
	used = (first >> 55) & 0x1;
	first = first & ~RTE_BIT64(63);
	*DESC_PTR_OFF(sd_desc_base, start, 8) = first | (used << 63) | last_id << 32;

	src = (rte_iova_t)DESC_PTR_OFF(sd_desc_base, start, 8);
	dst = (rte_iova_t)DESC_PTR_OFF(desc_base, start, 8);

	/* Enqueue DMA op assuming space is available */
	dao_dma_enq_x1(mem2dev, src, 8, dst, 8);
}

#endif /* __INCLUDE_VIRTIO_BLK_PRIV_H__ */
