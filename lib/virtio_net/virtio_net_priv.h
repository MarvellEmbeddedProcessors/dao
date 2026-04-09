/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2024 Marvell.
 */
#ifndef __INCLUDE_VIRTIO_NET_PRIV_H__
#define __INCLUDE_VIRTIO_NET_PRIV_H__

#include <rte_ip.h>

struct virtio_net_queue {
	/* Fast path */
	/* Read only, shared by both service and worker */
	uintptr_t desc_base __rte_cache_aligned;
	uint32_t *notify_addr;
	uint16_t data_off;
	uint16_t buf_len;
	uint16_t q_sz;
	uint16_t dma_vchan;
	uint16_t netdev_id;
	uint8_t virtio_hdr_sz;
	uint8_t auto_free;
	uint8_t *hash_report;

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
	uint16_t sd_desc_off;

	RTE_CACHE_GUARD;

	/* Written by worker, read by service */
	uint16_t last_off __rte_cache_aligned;
	uint16_t sd_mbuf_off;

	/* Read-mostly after init (service reads, worker reads) */
	uint32_t *cb_notify_addr __rte_cache_aligned;
	uint64_t *cb_intr_addr;
	uint64_t cb_intr_val;
	uint64_t *cb_ack_addr;

	/* Mempool to use for DMA inbound */
	struct rte_mempool *mp;
	/* TODO avoid indirection */
	union {
		struct rte_mbuf **mbuf_arr;
		void **extbuf_arr;
	};
	uintptr_t driver_area;
	uintptr_t sd_driver_area;
	/* Shadow Ring space */
	uint64_t sd_desc_base[] __rte_cache_aligned;
} __rte_cache_aligned;

struct virtio_netdev {
	struct virtio_dev dev;
	uint16_t vq_pairs_set; /* CTRL_MQ_VQ_PAIRS_SET */
	/* config flags */
	uint16_t flags;
	union {
		/** Default dequeue mempool */
		struct rte_mempool *pool;
		/** Valid when DOS_VIRTIO_NETDEV_EXTBUF is set */
		uint16_t dataroom_size;
	};
	bool auto_free_en;
	uint16_t reta_size;
	uint16_t hash_key_size;
#define DAO_HASH_REPORT_INDEX_MAX 256
	uint8_t *hash_report;

	/* Fast path data */
	struct virtio_net_queue *qs[DAO_VIRTIO_MAX_QUEUES] __rte_cache_aligned;
};

extern struct dao_virtio_netdev_cbs user_cbs;

void virtio_net_flush_enq(struct virtio_net_queue *q);
void virtio_net_flush_deq(struct virtio_net_queue *q);
void virtio_net_flush_enq_ext(struct virtio_net_queue *q);
void virtio_net_flush_deq_ext(struct virtio_net_queue *q);
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

static __rte_always_inline void
virtio_net_intr_trigger(uint64_t *cb_intr_addr, uint64_t *cb_ack_addr, uint64_t cb_intr_val)
{
	__atomic_store_n(cb_intr_addr, cb_intr_val, __ATOMIC_RELAXED);
	if (cb_ack_addr) {
		rte_io_wmb();
		__atomic_store_n(cb_ack_addr, cb_intr_val, __ATOMIC_RELAXED);
	}
}

/*
 * Virtio Net Rx Offloads
 */
#define VIRTIO_NET_DEQ_OFFLOAD_NONE     (0)
#define VIRTIO_NET_DEQ_OFFLOAD_CHECKSUM RTE_BIT64(0)
#define VIRTIO_NET_DEQ_OFFLOAD_NOINOR   RTE_BIT64(1)
#define VIRTIO_NET_DEQ_OFFLOAD_GSO      RTE_BIT64(2)
#define VIRTIO_NET_DEQ_OFFLOAD_LAST     RTE_BIT64(2)

/* Flags to control dequeue function.
 * Defining it from backwards to denote its been
 * not used as offload flags to pick function
 */
#define VIRTIO_NET_DEQ_EXTBUF RTE_BIT64(15)

#define D_CSUM_F    VIRTIO_NET_DEQ_OFFLOAD_CHECKSUM
#define D_NOORDER_F VIRTIO_NET_DEQ_OFFLOAD_NOINOR
#define D_GSO_F     VIRTIO_NET_DEQ_OFFLOAD_GSO

#define VIRTIO_NET_DEQ_FASTPATH_MODES                                                              \
	R(no_offload, VIRTIO_NET_DEQ_OFFLOAD_NONE)                                                 \
	R(cksum, D_CSUM_F)                                                                         \
	R(noinorder, D_NOORDER_F)                                                                  \
	R(gso, D_GSO_F)                                                                            \
	R(noinorder_csum, D_NOORDER_F | D_CSUM_F)                                                  \
	R(cksum_gso, D_CSUM_F | D_GSO_F)                                                           \
	R(noinorder_gso, D_NOORDER_F | D_GSO_F)                                                    \
	R(noinorder_csum_gso, D_NOORDER_F | D_CSUM_F | D_GSO_F)

#define R(name, flags)                                                                             \
	uint16_t virtio_net_deq_##name(void *q, struct rte_mbuf **pkts, uint16_t nb_pkts);         \
	uint16_t virtio_net_deq_ext_##name(void *q, void **pkts, uint16_t nb_pkts);                \
	uint16_t virtio_net_deq_ops_##name(void *q, struct rte_mbuf **pkts, uint16_t nb_pkts);

VIRTIO_NET_DEQ_FASTPATH_MODES
#undef R

/*
 * Virtio Net Tx Offloads
 */
#define VIRTIO_NET_ENQ_OFFLOAD_NONE     (0)
#define VIRTIO_NET_ENQ_OFFLOAD_NOFF     RTE_BIT64(0)
#define VIRTIO_NET_ENQ_OFFLOAD_CHECKSUM RTE_BIT64(1)
#define VIRTIO_NET_ENQ_OFFLOAD_MSEG     RTE_BIT64(2)
#define VIRTIO_NET_ENQ_OFFLOAD_HASH_REPORT RTE_BIT64(3)
#define VIRTIO_NET_ENQ_OFFLOAD_LAST     RTE_BIT64(3)

/* Flags to control enqueue function.
 * Defining it from backwards to denote its been
 * not used as offload flags to pick function
 */
#define VIRTIO_NET_ENQ_EXTBUF RTE_BIT64(15)

#define NOFF_F VIRTIO_NET_ENQ_OFFLOAD_NOFF
#define CSUM_F VIRTIO_NET_ENQ_OFFLOAD_CHECKSUM
#define MSEG_F VIRTIO_NET_ENQ_OFFLOAD_MSEG
#define HRP_F VIRTIO_NET_ENQ_OFFLOAD_HASH_REPORT

#define VIRTIO_NET_ENQ_FASTPATH_MODES                                                              \
	T(no_offload, VIRTIO_NET_ENQ_OFFLOAD_NONE)                                                 \
	T(no_ff, NOFF_F)                                                                           \
	T(cksum, CSUM_F)                                                                           \
	T(mseg, MSEG_F)                                                                            \
	T(hash_report, HRP_F)                                                                      \
	T(no_ff_cksum, NOFF_F | CSUM_F)                                                            \
	T(no_ff_mseg, NOFF_F | MSEG_F)                                                             \
	T(no_ff_hash_report, NOFF_F | HRP_F)                                                       \
	T(cksum_mseg, CSUM_F | MSEG_F)                                                             \
	T(cksum_hash_report, CSUM_F | HRP_F)                                                       \
	T(mseg_hash_report, MSEG_F | HRP_F)                                                        \
	T(no_ff_cksum_mseg, NOFF_F | CSUM_F | MSEG_F)                                              \
	T(no_ff_cksum_hash_report, NOFF_F | CSUM_F | HRP_F)                                        \
	T(no_ff_mseg_hash_report, NOFF_F | MSEG_F | HRP_F)                                         \
	T(cksum_mseg_hash_report, CSUM_F | MSEG_F | HRP_F)                                         \
	T(no_ff_cksum_mseg_hash_report, NOFF_F | CSUM_F | MSEG_F | HRP_F)

#define T(name, flags)                                                                             \
	uint16_t virtio_net_enq_##name(void *q, struct rte_mbuf **pkts, uint16_t nb_pkts);         \
	uint16_t virtio_net_enq_ext_##name(void *q, void **pkts, uint16_t nb_pkts);                \
	uint16_t virtio_net_enq_ops_##name(void *q, struct rte_mbuf **pkts, uint16_t nb_pkts);

VIRTIO_NET_ENQ_FASTPATH_MODES
#undef T

/*
 * Virtio net descriptor management ops
 */
#define VIRTIO_NET_DESC_MANAGE_DEF       (0)
#define VIRTIO_NET_DESC_MANAGE_NOINORDER RTE_BIT64(0)
#define VIRTIO_NET_DESC_MANAGE_MSEG      RTE_BIT64(1)
#define VIRTIO_NET_DESC_MANAGE_EXTBUF    RTE_BIT64(2)
#define VIRTIO_NET_DESC_MANAGE_LAST      RTE_BIT64(2)

#define M_NOORDER_F VIRTIO_NET_DESC_MANAGE_NOINORDER
#define M_MSEG_F    VIRTIO_NET_DESC_MANAGE_MSEG
#define M_EBUF_F    VIRTIO_NET_DESC_MANAGE_EXTBUF

#define VIRTIO_NET_DESC_MANAGE_MODES                                                               \
	M(def, VIRTIO_NET_DESC_MANAGE_DEF)                                                         \
	M(noinorder, M_NOORDER_F)                                                                  \
	M(mseg, M_MSEG_F)                                                                          \
	M(extbuf, M_EBUF_F)                                                                        \
	M(noinorder_mseg, M_MSEG_F | M_NOORDER_F)                                                  \
	M(noinorder_extbuf, M_NOORDER_F | M_EBUF_F)                                                \
	M(mseg_extbuf, M_MSEG_F | M_EBUF_F)                                                        \
	M(noinorder_mseg_extbuf, M_MSEG_F | M_NOORDER_F | M_EBUF_F)

#define M(name, flags)                                                                             \
	int virtio_net_desc_manage_##name(uint16_t devid, uint16_t qp_count);                      \
	int virtio_net_desc_manage_ops_##name(uint16_t devid, uint16_t qp_count);

VIRTIO_NET_DESC_MANAGE_MODES
#undef M

static __rte_always_inline void
free_extbufs(struct virtio_net_queue *q, uint16_t off, uint16_t q_sz, uint16_t num, uint16_t flags)
{
	uint8_t netdev_id = q->netdev_id;
	void **extbuf = q->extbuf_arr;
	uint16_t cnt;

	RTE_SET_USED(flags);

	cnt = (off + num) > q_sz ? q_sz - off : num;
	user_cbs.extbuf_put(netdev_id, extbuf + off, cnt);
	off = (off + cnt) & (q_sz - 1);
	cnt = num - cnt;
	if (cnt)
		user_cbs.extbuf_put(netdev_id, extbuf + off, cnt);
}

static __rte_always_inline uint16_t
alloc_extbufs(struct virtio_net_queue *q, uint16_t off, uint16_t q_sz, uint16_t num)
{
	uint8_t netdev_id = q->netdev_id;
	void **extbuf = q->extbuf_arr;
	uint16_t cnt;

	cnt = (off + num) > q_sz ? q_sz - off : num;
	if (user_cbs.extbuf_get(netdev_id, extbuf + off, cnt) < 0)
		return 0;

	off = (off + cnt) & (q_sz - 1);
	cnt = num - cnt;
	if (cnt && user_cbs.extbuf_get(netdev_id, extbuf + off, cnt) < 0)
		num -= cnt;

	return num;
}

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

	if (flags & VIRTIO_NET_DESC_MANAGE_EXTBUF)
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

		/* Mark descriptor as invalid */
		VIRTIO_NET_DESC_CHECK(q, off, i, false, false);

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
	int sd_desc_val = 0;
	int desc_count = 0;

	pend_sd_desc = q->pend_sd_desc;
	sd_desc_off = q->sd_desc_off;

	/* Include the wrap bit to check if there are descriptors */
	notify_data = __atomic_load_n(q->notify_addr, __ATOMIC_RELAXED);
	next_off = (notify_data >> 16) & 0xFFFF;
	if (unlikely(next_off == sd_desc_off))
		return 0;

	/* Limit the fetch to end of the queue */
	nb_desc = desc_off_diff(next_off, sd_desc_off, q_sz) - q->pend_sd_desc;
	if (unlikely(!nb_desc))
		return 0;

	/* Assume nothing else is pending now */
	/* Start DMA of descriptors */
	i = 0;
	off = desc_off_add(sd_desc_off, pend_sd_desc, q_sz);
	off = DESC_OFF(off);
	do {
		i = (off + nb_desc) > q_sz ? (q_sz - off) : nb_desc;
		src[j].addr = (rte_iova_t)DESC_PTR_OFF(desc_base, off, 0);
		dst[j].addr = (rte_iova_t)DESC_PTR_OFF(sd_desc_base, off, 0);
		src[j].length = i << 4;
		dst[j].length = i << 4;

		/* Mark descriptor as invalid */
		VIRTIO_NET_DESC_CHECK(q, off, i, false, false);

		desc_count += i;
		off = (off + i) & (q_sz - 1);
		nb_desc -= i;
		j++;
	} while (nb_desc);

	q->pend_sd_desc_idx = dev2mem->tail;
	sd_desc_val = desc_off_add(q->sd_desc_off, desc_count + q->pend_sd_desc, q->q_sz);
	q->pend_sd_desc += desc_count;
	dao_dma_update_cmpl_meta(dev2mem, &q->sd_desc_off, sd_desc_val, &q->pend_sd_desc,
				 desc_count, dev2mem->tail);
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

	end = desc_off_add(start, nb_desc, q_sz);
	pend = desc_off_diff_no_wrap(end, start, q_sz);

	/* Validate descriptor */
	VIRTIO_NET_DESC_CHECK(q, start, desc_off_diff(end, start, q_sz), true, true);

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

	if (unlikely(!q->auto_free)) {
		if (flags & VIRTIO_NET_DESC_MANAGE_EXTBUF)
			free_extbufs(q, DESC_OFF(start), q_sz, desc_off_diff(end, start, q_sz),
				     flags);
		else
			free_mbufs(q->mbuf_arr, DESC_OFF(start), q_sz,
				   desc_off_diff(end, start, q_sz), flags);
	}

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

/**
 * Free an mbuf segment chain.
 *
 * @param mbuf
 *   Head of the mbuf chain to free.
 */
static __rte_always_inline void
free_mbuf_seg_chain(struct rte_mbuf *mbuf)
{
	struct rte_mbuf *mb = mbuf, *mb_next;

	while (mb) {
		mb_next = mb->next;
		rte_pktmbuf_free_seg(mb);
		mb = mb_next;
	}
}

/*
 * Common macros for dequeue post-processing
 */
#define TX_OFFLOAD_SHIFT 52

#define TX_IPV4_UDP_OFFLOAD (RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_UDP_CKSUM)
#define TX_IPV4_TCP_OFFLOAD (RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_TCP_CKSUM)

#define TX_IPV4_TCP_GSO_OFFLOAD                                                                    \
	(RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_TCP_CKSUM |                   \
	 RTE_MBUF_F_TX_TCP_SEG)

#define TX_IPV6_TCP_GSO_OFFLOAD                                                                    \
	(RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV6 | RTE_MBUF_F_TX_TCP_CKSUM |                   \
	 RTE_MBUF_F_TX_TCP_SEG)

/**
 * Post-process dequeued packets from virtio net queue.
 * Common function used by both standard dequeue and ops-based dequeue paths.
 *
 * @param q
 *   Pointer to virtio net queue.
 * @param d_mbufs
 *   Output array of mbuf pointers.
 * @param nb_mbufs
 *   Pointer to number of mbufs (input/output).
 * @param flags
 *   Dequeue offload flags.
 * @return
 *   Number of mbufs processed.
 */
static __rte_always_inline uint16_t
post_process_pkts(struct virtio_net_queue *q, struct rte_mbuf **d_mbufs, uint16_t *nb_mbufs,
		  const uint16_t flags)
{
	const uint64_t rearm_data = 0x100010000ULL | RTE_PKTMBUF_HEADROOM;
	struct rte_mbuf **mbuf_arr, *mbuf0, *mbuf1, *mbuf2, *mbuf3;
	uintptr_t desc_base = (uintptr_t)q->sd_desc_base;
	uint16_t last_off = DESC_OFF(q->last_off), off;
	uint64x2_t desc0, desc1, desc2, desc3, doff;
	const uint16_t vhdr_sz = q->virtio_hdr_sz;
	uint64x2_t mbuf01, mbuf23, hdr01, hdr23;
	uint32x4_t csum_off, tx_offload, olflags;
	uint32x4_t hdr0, hdr1, hdr2, hdr3;
	uint16_t total_mbufs = *nb_mbufs;
	uint16_t data_off = q->data_off;
	uint16_t q_sz = q->q_sz, segs;
	uint64x2_t flags01, flags23;
	uint32x4_t d0, d1, len_mask;
	struct virtio_net_hdr *hdr;
	uint64_t ol_flags, dflags;
	int count, i, num = 0;
	uint16_t l3_len = 0;

	doff = vdupq_n_u64(data_off);
	mbuf_arr = q->mbuf_arr;
	rte_prefetch0(&mbuf_arr[last_off]);
	count = total_mbufs & ~(0x3u);

	if (likely(count)) {
		rte_prefetch0(DESC_PTR_OFF(desc_base, last_off, 0));
		rte_prefetch0(DESC_PTR_OFF(desc_base, last_off + 4, 0));
		rte_prefetch0(DESC_PTR_OFF(desc_base, last_off + 8, 0));
		rte_prefetch0(DESC_PTR_OFF(desc_base, last_off + 12, 0));
		/* Prefetch mbuf headers for NIX TX path (reads at offset 0 and +24) */
		rte_prefetch0(mbuf_arr[last_off]);
		if (likely(last_off + 3 < q_sz)) {
			rte_prefetch0(mbuf_arr[last_off + 1]);
			rte_prefetch0(mbuf_arr[last_off + 2]);
			rte_prefetch0(mbuf_arr[last_off + 3]);
		}
	}

	for (i = 0; i < count; i += 4) {
		const uint8x16_t tbl = {
			0, 0, 0, 0, 0, TX_IPV4_UDP_OFFLOAD >> TX_OFFLOAD_SHIFT, 0, 0, 0, 0,
			0, 0, 0, 0, 0, TX_IPV4_TCP_OFFLOAD >> TX_OFFLOAD_SHIFT,
		};

		if (unlikely(last_off + 3 >= q_sz))
			break;

		desc0 = vld1q_u64(DESC_PTR_OFF(desc_base, last_off, 0));
		desc1 = vld1q_u64(DESC_PTR_OFF(desc_base, last_off + 1, 0));
		desc2 = vld1q_u64(DESC_PTR_OFF(desc_base, last_off + 2, 0));
		desc3 = vld1q_u64(DESC_PTR_OFF(desc_base, last_off + 3, 0));

		flags01 = vzip2q_u64(desc0, desc1);
		flags23 = vzip2q_u64(desc2, desc3);

		flags01 = vtrn2q_u32(flags01, flags23);
		const uint64x2_t xflags = {
			0x0001000000010000,
			0x0001000000010000,
		};
		flags01 = vandq_u64(flags01, xflags);
		flags01 = vceqzq_u64(flags01);
		/* If VRING_DESC_F_NEXT is set in any then process remaining mbufs in scalar way */
		if (unlikely(!vgetq_lane_u64(flags01, 0) || !vgetq_lane_u64(flags01, 1)))
			break;

		/* Prefetch descriptors and mbuf pointer array ahead */
		rte_prefetch0(DESC_PTR_OFF(desc_base, last_off + 16, 0));
		rte_prefetch0(mbuf_arr + ((last_off + 12) & (q_sz - 1)));

		/* Prefetch mbuf data (for virtio header parsing) */
		rte_prefetch0((uint8_t *)mbuf_arr[(last_off + 8) & (q_sz - 1)] + data_off);
		rte_prefetch0((uint8_t *)mbuf_arr[(last_off + 9) & (q_sz - 1)] + data_off);
		rte_prefetch0((uint8_t *)mbuf_arr[(last_off + 10) & (q_sz - 1)] + data_off);
		rte_prefetch0((uint8_t *)mbuf_arr[(last_off + 11) & (q_sz - 1)] + data_off);

		/* Prefetch mbuf headers for downstream NIX TX (reads offset 0 and +24) */
		rte_prefetch0(mbuf_arr[(last_off + 4) & (q_sz - 1)]);
		rte_prefetch0(mbuf_arr[(last_off + 5) & (q_sz - 1)]);
		rte_prefetch0(mbuf_arr[(last_off + 6) & (q_sz - 1)]);
		rte_prefetch0(mbuf_arr[(last_off + 7) & (q_sz - 1)]);

		/* Load mbuf pointers early for both csum and non-csum paths */
		mbuf01 = vld1q_u64((uint64_t *)&mbuf_arr[last_off]);
		mbuf23 = vld1q_u64((uint64_t *)&mbuf_arr[last_off + 2]);

		if (!(flags & VIRTIO_NET_DEQ_OFFLOAD_CHECKSUM))
			goto skip_csum;

		/* Move mbuf to data offset */
		hdr01 = vaddq_u64(mbuf01, doff);
		hdr23 = vaddq_u64(mbuf23, doff);

		/* Load virtio Net headers */
		hdr0 = vld1q_u32((void *)vgetq_lane_u64(hdr01, 0));
		hdr1 = vld1q_u32((void *)vgetq_lane_u64(hdr01, 1));
		hdr2 = vld1q_u32((void *)vgetq_lane_u64(hdr23, 0));
		hdr3 = vld1q_u32((void *)vgetq_lane_u64(hdr23, 1));

		/* If at least one buffer has gso type set, go to scalar processing */
		if (flags & VIRTIO_NET_DEQ_OFFLOAD_GSO) {
			if ((hdr0[0] & 0XFF00) || (hdr1[0] & 0XFF00) || (hdr2[0] & 0XFF00) ||
			    (hdr3[0] & 0XFF00))
				break;
		}
		/* Combine 4 packet headers into single 128 bit */
		d0 = vtrn1q_u32(hdr0, hdr1);
		d1 = vtrn1q_u32(hdr2, hdr3);

		/* Retrieve csum_offset values and get ol_flags based on csum offset
		 * For UDP, csum offset will be 6, and for TCP, it will be 0x10.
		 * Subtract csum offset with -1 for table lookup
		 */
		csum_off = vzip2q_u32(d0, d1);
		csum_off = vandq_u32(csum_off, vdupq_n_u32(0x0000FFFF));
		csum_off = vsubq_u32(csum_off, vdupq_n_u32(0x00000001));
		olflags = vqtbl1q_u8(tbl, csum_off);

		/* Extract csum start info from packets */
		d0 = vtrn2q_u32(hdr0, hdr1);
		d1 = vtrn2q_u32(hdr2, hdr3);
		tx_offload = vzip1q_u32(d0, d1);
		tx_offload = vshrq_n_u32(tx_offload, 16);

		/* l2_len = csum_start - 20. Update BIT0_BIT6 */
		tx_offload = vsubq_u32(tx_offload, vdupq_n_u32(20));
		len_mask = vcltq_u32(tx_offload, vdupq_n_u32(0x0000003F));
		tx_offload = vandq_u32(tx_offload, len_mask);

		/* Assuming IPv4 packets with 20 bytes header length.
		 * Update len value from BIT_7 to BIT_15
		 */
		tx_offload = vorrq_u32(tx_offload, vdupq_n_u32(0x00000A00));

		mbuf0 = (struct rte_mbuf *)vgetq_lane_u64(mbuf01, 0);
		mbuf1 = (struct rte_mbuf *)vgetq_lane_u64(mbuf01, 1);
		mbuf2 = (struct rte_mbuf *)vgetq_lane_u64(mbuf23, 0);
		mbuf3 = (struct rte_mbuf *)vgetq_lane_u64(mbuf23, 1);

		mbuf0->ol_flags = ((uint64_t)vgetq_lane_u32(olflags, 0)) << TX_OFFLOAD_SHIFT;
		mbuf1->ol_flags = ((uint64_t)vgetq_lane_u32(olflags, 1)) << TX_OFFLOAD_SHIFT;
		mbuf2->ol_flags = ((uint64_t)vgetq_lane_u32(olflags, 2)) << TX_OFFLOAD_SHIFT;
		mbuf3->ol_flags = ((uint64_t)vgetq_lane_u32(olflags, 3)) << TX_OFFLOAD_SHIFT;

		mbuf0->tx_offload = vgetq_lane_u32(tx_offload, 0);
		mbuf1->tx_offload = vgetq_lane_u32(tx_offload, 1);
		mbuf2->tx_offload = vgetq_lane_u32(tx_offload, 2);
		mbuf3->tx_offload = vgetq_lane_u32(tx_offload, 3);

	skip_csum:
		/* Store mbuf pointers to output array using NEON (already in regs) */
		vst1q_u64((uint64_t *)(d_mbufs + num), mbuf01);
		vst1q_u64((uint64_t *)(d_mbufs + num + 2), mbuf23);
		num += 4;
		last_off = (last_off + 4) & (q_sz - 1);
	}

	count = i;
	segs = 0;
	while (i < total_mbufs) {
		rte_prefetch0((uint8_t *)mbuf_arr[(last_off + 1) & (q_sz - 1)] + data_off);
		mbuf0 = mbuf_arr[last_off];

		dflags = (*DESC_PTR_OFF(desc_base, last_off, 8) >> 48) & VRING_DESC_F_NEXT;

		mbuf1 = mbuf0;
		off = last_off;

		/* Calculate additional segments required for mbuf-chain */
		while (unlikely(dflags)) {
			off = (off + 1) & (q_sz - 1);
			dflags = (*DESC_PTR_OFF(desc_base, off, 8) >> 48) & VRING_DESC_F_NEXT;
			segs++;
		}

		if (unlikely((i + segs >= total_mbufs)))
			break;

		/* Create mbuf chain from descriptors */
		while (unlikely(segs)) {
			/* Internal mbufs can also have chain based on descriptor length vs
			 * mbuf length variation.
			 */
			while (mbuf1->next)
				mbuf1 = mbuf1->next;

			last_off = (last_off + 1) & (q_sz - 1);
			mbuf2 = mbuf_arr[last_off];
			mbuf1->next = mbuf2;
			mbuf2->data_len += vhdr_sz;
			mbuf2->pkt_len += vhdr_sz;
			mbuf0->nb_segs += mbuf2->nb_segs;
			mbuf0->pkt_len += mbuf2->pkt_len;
			*((uint64_t *)&mbuf2->rearm_data) = rearm_data;
			mbuf1 = mbuf2;
			i++;
			segs--;
		}

		d_mbufs[num++] = mbuf0;

		if (flags & VIRTIO_NET_DEQ_OFFLOAD_CHECKSUM) {
			hdr = (struct virtio_net_hdr *)((uintptr_t)mbuf0 + data_off);
			ol_flags = 0;
			if (hdr->csum_start && hdr->csum_offset) {
				ol_flags = (hdr->csum_offset == 6) ? TX_IPV4_UDP_OFFLOAD :
								     TX_IPV4_TCP_OFFLOAD;
				l3_len = sizeof(struct rte_ipv4_hdr);
				if (flags & VIRTIO_NET_DEQ_OFFLOAD_GSO) {
					if (hdr->gso_type != VIRTIO_NET_HDR_GSO_NONE) {
						mbuf0->tso_segsz = hdr->gso_size;
						mbuf0->l4_len = hdr->hdr_len - hdr->csum_start;

						if (hdr->gso_type == VIRTIO_NET_HDR_GSO_TCPV4) {
							ol_flags = TX_IPV4_TCP_GSO_OFFLOAD;
						} else if (hdr->gso_type ==
							   VIRTIO_NET_HDR_GSO_TCPV6) {
							l3_len = sizeof(struct rte_ipv6_hdr);
							ol_flags = TX_IPV6_TCP_GSO_OFFLOAD;
						}
					}
				}
				mbuf0->l3_len = l3_len;
				mbuf0->l2_len = hdr->csum_start - l3_len;
				mbuf0->ol_flags |= ol_flags;
			}
		}
		last_off = (last_off + 1) & (q_sz - 1);
		i++;
		count = i;
	}
	/* Return consumed descriptor mbufs to update last_off,
	   And num will hold number of copied mbufs.
	 */
	*nb_mbufs = count;
	return num;
}

#endif /* __INCLUDE_VIRTIO_NET_PRIV_H__ */
