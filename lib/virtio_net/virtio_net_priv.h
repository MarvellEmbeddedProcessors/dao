/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2024 Marvell.
 */
#ifndef __INCLUDE_VIRTIO_NET_PRIV_H__
#define __INCLUDE_VIRTIO_NET_PRIV_H__

struct virtio_net_queue {
	/* Fast path */
	/* Read only, shared by both service and worker */
	uintptr_t desc_base __rte_cache_aligned;
	uint32_t *notify_addr;
	uint16_t data_off;
	uint16_t buf_len;
	uint16_t q_sz;
	uint16_t dma_vchan;
	uint8_t auto_free;

	/* Slow path */
	struct dao_virtio_netdev *dao_netdev __rte_cache_aligned;
	uint16_t qid;

	/* Read-Write worker. */
	uint16_t pend_sd_mbuf __rte_cache_aligned;
	uint16_t pend_sd_mbuf_idx;

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
	/* TODO avoid indirection */
	struct rte_mbuf **mbuf_arr;
	uintptr_t driver_area;
	uintptr_t sd_driver_area;
	/* Shadow Ring space */
	uint64_t sd_desc_base[] __rte_cache_aligned;
} __rte_cache_aligned;

struct virtio_netdev {
	struct virtio_dev dev;
	uint16_t vq_pairs_set; /* CTRL_MQ_VQ_PAIRS_SET */
	struct rte_mempool *pool;
	bool auto_free_en;
	uint16_t reta_size;
	uint16_t hash_key_size;

	/* Fast path data */
	struct virtio_net_queue *qs[DAO_VIRTIO_MAX_QUEUES] __rte_cache_aligned;
};

void virtio_net_flush_enq(struct virtio_net_queue *q);
void virtio_net_flush_deq(struct virtio_net_queue *q);
void virtio_net_desc_validate(struct virtio_net_queue *q, uint16_t start, uint16_t count,
			      bool avail, bool used);

#ifdef DAO_VIRTIO_DEBUG
#define VIRTIO_NET_DESC_CHECK(q, start, count, avail, used)                                        \
	virtio_net_desc_validate(q, start, count, avail, used)
#else
#define VIRTIO_NET_DESC_CHECK(...)
#endif

static inline struct virtio_netdev *
virtio_netdev_priv(struct dao_virtio_netdev *netdev)
{
	return (struct virtio_netdev *)netdev->reserved;
}

static inline struct virtio_netdev *
virtio_dev_to_netdev(struct virtio_dev *dev)
{
	return (struct virtio_netdev *)dev;
}

static inline struct dao_virtio_netdev *
virtio_netdev_to_dao(struct virtio_netdev *netdev)
{
	return (struct dao_virtio_netdev *)((uintptr_t)netdev -
					    offsetof(struct dao_virtio_netdev, reserved));
}

/*
 * Virtio Net Rx Offloads
 */
#define VIRTIO_NET_DEQ_OFFLOAD_NONE     (0)
#define VIRTIO_NET_DEQ_OFFLOAD_CHECKSUM RTE_BIT64(0)
#define VIRTIO_NET_DEQ_OFFLOAD_NOINOR   RTE_BIT64(1)
#define VIRTIO_NET_DEQ_OFFLOAD_LAST     RTE_BIT64(1)

#define VIRTIO_NET_DEQ_FASTPATH_MODES                                                              \
	R(no_offload, VIRTIO_NET_DEQ_OFFLOAD_NONE)                                                 \
	R(cksum, VIRTIO_NET_DEQ_OFFLOAD_CHECKSUM)                                                  \
	R(noinorder, VIRTIO_NET_DEQ_OFFLOAD_NOINOR)                                                \
	R(noinorder_csum, VIRTIO_NET_DEQ_OFFLOAD_NOINOR | VIRTIO_NET_DEQ_OFFLOAD_CHECKSUM)

#define R(name, flags)                                                                             \
	uint16_t virtio_net_deq_##name(void *q, struct rte_mbuf **pkts, uint16_t nb_pkts);

VIRTIO_NET_DEQ_FASTPATH_MODES
#undef R

/*
 * Virtio Net Tx Offloads
 */
#define VIRTIO_NET_ENQ_OFFLOAD_NONE (0)
#define VIRTIO_NET_ENQ_OFFLOAD_NOFF RTE_BIT64(0)
#define VIRTIO_NET_ENQ_OFFLOAD_CHECKSUM RTE_BIT64(1)
#define VIRTIO_NET_ENQ_OFFLOAD_MSEG RTE_BIT64(2)
#define VIRTIO_NET_ENQ_OFFLOAD_LAST RTE_BIT64(2)

#define VIRTIO_NET_ENQ_FASTPATH_MODES                                                              \
	T(no_offload, VIRTIO_NET_ENQ_OFFLOAD_NONE)                                                 \
	T(no_ff, VIRTIO_NET_ENQ_OFFLOAD_NOFF)                                                      \
	T(cksum, VIRTIO_NET_ENQ_OFFLOAD_CHECKSUM)                                                  \
	T(mseg, VIRTIO_NET_ENQ_OFFLOAD_MSEG)                                                       \
	T(no_ff_cksum, VIRTIO_NET_ENQ_OFFLOAD_NOFF | VIRTIO_NET_ENQ_OFFLOAD_CHECKSUM)              \
	T(no_ff_mseg, VIRTIO_NET_ENQ_OFFLOAD_NOFF | VIRTIO_NET_ENQ_OFFLOAD_MSEG)                   \
	T(cksum_mseg, VIRTIO_NET_ENQ_OFFLOAD_CHECKSUM | VIRTIO_NET_ENQ_OFFLOAD_MSEG)               \
	T(no_ff_cksum_mseg, VIRTIO_NET_ENQ_OFFLOAD_NOFF | VIRTIO_NET_ENQ_OFFLOAD_CHECKSUM |        \
	  VIRTIO_NET_ENQ_OFFLOAD_MSEG)

#define T(name, flags)                                                                             \
	uint16_t virtio_net_enq_##name(void *q, struct rte_mbuf **pkts, uint16_t nb_pkts);

VIRTIO_NET_ENQ_FASTPATH_MODES
#undef T

/*
 * Virtio net descriptor management ops
 */
#define VIRTIO_NET_DESC_MANAGE_DEF		(0)
#define VIRTIO_NET_DESC_MANAGE_NOINORDER	RTE_BIT64(0)
#define VIRTIO_NET_DESC_MANAGE_MSEG		RTE_BIT64(1)
#define VIRTIO_NET_DESC_MANAGE_LAST		RTE_BIT64(1)

#define VIRTIO_NET_DESC_MANAGE_MODES                                                               \
	M(def, VIRTIO_NET_DESC_MANAGE_DEF)                                                         \
	M(noinorder, VIRTIO_NET_DESC_MANAGE_NOINORDER)                                             \
	M(mseg, VIRTIO_NET_DESC_MANAGE_MSEG)                                                       \
	M(noinorder_mseg, VIRTIO_NET_DESC_MANAGE_MSEG | VIRTIO_NET_DESC_MANAGE_NOINORDER)

#define M(name, flags)                                                                             \
	int virtio_net_desc_manage_##name(uint16_t devid, uint16_t qp_count);

VIRTIO_NET_DESC_MANAGE_MODES
#undef M

static __rte_always_inline uint16_t
alloc_mbufs(struct rte_mbuf **mbuf_arr, struct rte_mempool *mp, uint16_t off, uint16_t q_sz,
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
free_mseg_mbufs(struct rte_mbuf **mbuf_arr, uint16_t off, uint16_t q_sz, uint16_t nb_mbufs)
{
	struct rte_mempool *mp;
	uint16_t cnt, i, count;

	/* Assuming all segments pkts are coming from same pool in this Tx queue and
	 * all mbuf's ref_cnt is 1 without ext buf.
	 */
	/* Get mempool from first mbuf */
	mp = mbuf_arr[off]->pool;
	cnt = (off + nb_mbufs) > q_sz ? q_sz - off : nb_mbufs;
	count = cnt & ~(0x3u);
	for (i = 0; i < count; i += 4) {
		if (unlikely(mbuf_arr[off] == NULL || mbuf_arr[off + 1] == NULL ||
			     mbuf_arr[off + 2] == NULL || mbuf_arr[off + 3] == NULL))
			break;
		rte_mempool_put_bulk(mp, (void **)&mbuf_arr[off], 4);
		off += 4;
	}

	rte_pktmbuf_free_bulk(&mbuf_arr[off], cnt - i);

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
	rte_pktmbuf_free_bulk(&mbuf_arr[off], cnt - i);
}

static __rte_always_inline void
free_mbufs(struct rte_mbuf **mbuf_arr, uint16_t off, uint16_t q_sz, uint16_t nb_mbufs,
	   const uint16_t flags)
{
	struct rte_mempool *mp;
	uint16_t cnt;

	if (flags & VIRTIO_NET_DESC_MANAGE_MSEG)
		return free_mseg_mbufs(mbuf_arr, off, q_sz, nb_mbufs);

	/* Assuming all segments pkts are coming from same pool in this Tx queue and
	 * all mbuf's ref_cnt is 1 without ext buf.
	 */
	/* Get mempool from first mbuf */
	mp = mbuf_arr[off]->pool;
	cnt = (off + nb_mbufs) > q_sz ? q_sz - off : nb_mbufs;
	rte_mempool_put_bulk(mp, (void **)&mbuf_arr[off], cnt);
	off = (off + cnt) & (q_sz - 1);
	cnt = nb_mbufs - cnt;
	if (cnt)
		rte_mempool_put_bulk(mp, (void **)&mbuf_arr[off], cnt);
}

static __rte_always_inline uint16_t
fetch_deq_desc_prep(struct virtio_net_queue *q, struct dao_dma_vchan_state *dev2mem,
		    struct rte_dma_sge *src, struct rte_dma_sge *dst, const uint16_t flags)
{
	uintptr_t sd_desc_base = (uintptr_t)q->sd_desc_base;
	uint16_t sd_desc_off, pend_sd_desc;
	uintptr_t desc_base = q->desc_base;
	struct rte_mbuf **mbuf_arr;
	uint16_t q_sz = q->q_sz;
	uint32_t notify_data;
	uint16_t next_off, off;
	int i, j = 0;
	int nb_desc;

	RTE_SET_USED(flags);
	pend_sd_desc = q->pend_sd_desc;
	sd_desc_off = q->sd_desc_off;

	/* Check if pending DMA's for shadow op are done */
	/* TODO Does this detect dma completion in all corner cases */
	if (pend_sd_desc &&dao_dma_op_status(dev2mem, q->pend_sd_desc_idx)) {
		/* Validate descriptor */
		VIRTIO_NET_DESC_CHECK(q, sd_desc_off, pend_sd_desc, true, false);

		sd_desc_off = desc_off_add(sd_desc_off, pend_sd_desc, q_sz);
		__atomic_store_n(&q->sd_desc_off, sd_desc_off, __ATOMIC_RELEASE);
		pend_sd_desc = 0;
		q->pend_sd_desc = 0;
	}

	/* Include the wrap bit to check if there are descriptors */
	notify_data = __atomic_load_n(q->notify_addr, __ATOMIC_RELAXED);
	next_off = (notify_data >> 16) & 0xFFFF;
	if (unlikely(pend_sd_desc || next_off == sd_desc_off))
		return 0;

	/* Limit the fetch to end of the queue */
	nb_desc = desc_off_diff(next_off, sd_desc_off, q_sz);

	/* Allocate required mbufs */
	off = DESC_OFF(sd_desc_off);
	mbuf_arr = q->mbuf_arr;
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

		/* Mark descriptor as invalid */
		VIRTIO_NET_DESC_CHECK(q, off, i, false, false);

		off = (off + i) & (q_sz - 1);
		nb_desc -= i;
		q->pend_sd_desc += i;
		j++;
	} while (nb_desc);

	q->pend_sd_desc_idx = dev2mem->tail;
	return j;
}

static __rte_always_inline uint16_t
fetch_enq_desc_prep(struct virtio_net_queue *q, struct dao_dma_vchan_state *dev2mem,
		    struct rte_dma_sge *src, struct rte_dma_sge *dst)
{
	uintptr_t sd_desc_base = (uintptr_t)q->sd_desc_base;
	uint16_t sd_desc_off, pend_sd_desc;
	uintptr_t desc_base = q->desc_base;
	uint16_t q_sz = q->q_sz;
	uint32_t notify_data;
	uint16_t next_off, off;
	int i, j = 0;
	int nb_desc;

	pend_sd_desc = q->pend_sd_desc;
	sd_desc_off = q->sd_desc_off;

	/* Check if pending DMA's for shadow op are done */
	/* TODO Does this detect dma completion in all corner cases */
	if (pend_sd_desc &&dao_dma_op_status(dev2mem, q->pend_sd_desc_idx)) {
		/* Validate descriptor */
		VIRTIO_NET_DESC_CHECK(q, sd_desc_off, pend_sd_desc, true, false);

		sd_desc_off = desc_off_add(sd_desc_off, pend_sd_desc, q_sz);
		__atomic_store_n(&q->sd_desc_off, sd_desc_off, __ATOMIC_RELEASE);
		pend_sd_desc = 0;
		q->pend_sd_desc = 0;
	}

	/* Include the wrap bit to check if there are descriptors */
	notify_data = __atomic_load_n(q->notify_addr, __ATOMIC_RELAXED);
	next_off = (notify_data >> 16) & 0xFFFF;
	if (unlikely(pend_sd_desc || next_off == sd_desc_off))
		return 0;

	/* Limit the fetch to end of the queue */
	nb_desc = desc_off_diff(next_off, sd_desc_off, q_sz);

	/* Assume nothing else is pending now */
	/* Start DMA of descriptors */
	i = 0;
	off = DESC_OFF(sd_desc_off);
	do {
		i = (off + nb_desc) > q_sz ? (q_sz - off) : nb_desc;

		src[j].addr = (rte_iova_t)DESC_PTR_OFF(desc_base, off, 0);
		dst[j].addr = (rte_iova_t)DESC_PTR_OFF(sd_desc_base, off, 0);
		src[j].length = i << 4;
		dst[j].length = i << 4;

		/* Mark descriptor as invalid */
		VIRTIO_NET_DESC_CHECK(q, off, i, false, false);

		off = (off + i) & (q_sz - 1);
		nb_desc -= i;
		q->pend_sd_desc += i;
		j++;
	} while (nb_desc);

	q->pend_sd_desc_idx = dev2mem->tail;
	return j;
}

static __rte_always_inline void
mark_deq_compl_no_inorder(struct virtio_net_queue *q, struct dao_dma_vchan_state *mem2dev,
			  uint16_t start, uint16_t nb_desc)
{
	uintptr_t sd_desc_base = (uintptr_t)q->sd_desc_base;
	uintptr_t desc_base = q->desc_base;
	uint16_t q_sz = q->q_sz;
	uint16_t end, pend;

	/* Validate descriptor */
	VIRTIO_NET_DESC_CHECK(q, start, desc_off_diff(end, start, q_sz), true, true);

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
mark_deq_compl(struct virtio_net_queue *q, struct dao_dma_vchan_state *mem2dev, uint16_t start,
	       uint16_t nb_desc, const uint16_t flags)
{
	uintptr_t sd_desc_base = (uintptr_t)q->sd_desc_base;
	uintptr_t desc_base = q->desc_base;
	rte_iova_t src, dst;
	uint64_t last_id;
	uint64_t first;
	uint64_t used;
	uint16_t end;

	if (flags & VIRTIO_NET_DESC_MANAGE_NOINORDER)
		return mark_deq_compl_no_inorder(q, mem2dev, start, nb_desc);

	end = desc_off_add(start, nb_desc - 1, q->q_sz);
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

static __rte_always_inline void
mark_enq_compl(struct virtio_net_queue *q, struct dao_dma_vchan_state *mem2dev, uint16_t start,
	       uint16_t end, const uint16_t flags)
{
	uintptr_t sd_desc_base = (uintptr_t)q->sd_desc_base;
	uintptr_t desc_base = q->desc_base;
	uint16_t q_sz = q->q_sz;
	uint16_t pend;

	/* Validate descriptor */
	VIRTIO_NET_DESC_CHECK(q, start, desc_off_diff(end, start, q_sz), true, true);

	if (unlikely(!q->auto_free))
		free_mbufs(q->mbuf_arr, DESC_OFF(start), q_sz, desc_off_diff(end, start, q_sz),
			   flags);

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

#endif /* __INCLUDE_VIRTIO_NET_PRIV_H__ */
