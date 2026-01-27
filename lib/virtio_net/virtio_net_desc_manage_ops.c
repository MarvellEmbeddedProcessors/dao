/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2026 Marvell.
 */
#include "dao_virtio_netdev.h"
#include "virtio_dev_priv.h"
#include "virtio_net_priv.h"

dao_net_desc_manage_fn_t dao_net_desc_manage_ops_fns[VIRTIO_NET_DESC_MANAGE_LAST << 1] = {
#define M(name, flags) [flags] = virtio_net_desc_manage_ops_##name,
	VIRTIO_NET_DESC_MANAGE_MODES
#undef M
};

static __rte_always_inline uint16_t
fetch_enq_desc_prep_ops(struct virtio_net_queue *q, struct dao_dma_vchan_state *dev2mem,
			struct rte_dma_op *op, uint16_t op_idx)
{
	uintptr_t sd_desc_base = (uintptr_t)q->sd_desc_base;
	uintptr_t desc_base = q->desc_base;
	uint16_t pend_sd_desc = q->pend_sd_desc;
	uint16_t sd_desc_off = q->sd_desc_off;
	uint16_t q_sz = q->q_sz;
	uint32_t notify_data;
	uint16_t next_off, off;
	uint16_t first_seg, second_seg;
	int nb_desc;

	/* Include the wrap bit to check if there are descriptors */
	notify_data = __atomic_load_n(q->notify_addr, __ATOMIC_RELAXED);
	next_off = (notify_data >> 16) & 0xFFFF;
	if (unlikely(next_off == sd_desc_off))
		return 0;

	/* Limit the fetch to end of the queue */
	nb_desc = desc_off_diff(next_off, sd_desc_off, q_sz) - pend_sd_desc;
	if (unlikely(nb_desc <= 0))
		return 0;

	off = DESC_OFF(desc_off_add(sd_desc_off, pend_sd_desc, q_sz));

	/* Calculate segment sizes - check for wrap-around */
	first_seg = (off + nb_desc) > q_sz ? (q_sz - off) : nb_desc;
	second_seg = nb_desc - first_seg;

	/* Mark descriptor as invalid */
	VIRTIO_NET_DESC_CHECK(q, off, first_seg, false, false);
	VIRTIO_NET_DESC_CHECK(q, 0, second_seg, false, false);

	/* Branchless: fill all 4 segments, nb_src/nb_dst controls what's used */
	op->nb_src = 1 + !!second_seg;
	op->nb_dst = op->nb_src;
	op->src_dst_seg[0].addr = (rte_iova_t)DESC_PTR_OFF(desc_base, off, 0);
	op->src_dst_seg[0].length = first_seg << 4;
	op->src_dst_seg[1].addr = (rte_iova_t)DESC_PTR_OFF(desc_base, 0, 0);
	op->src_dst_seg[1].length = second_seg << 4;
	op->src_dst_seg[op->nb_src].addr = (rte_iova_t)DESC_PTR_OFF(sd_desc_base, off, 0);
	op->src_dst_seg[op->nb_src].length = first_seg << 4;
	op->src_dst_seg[op->nb_src + 1].addr = (rte_iova_t)DESC_PTR_OFF(sd_desc_base, 0, 0);
	op->src_dst_seg[op->nb_src + 1].length = second_seg << 4;
	op->flags = 0;

	q->pend_sd_desc_idx = dev2mem->tail + op_idx;
	q->pend_sd_desc += nb_desc;
	dao_dma_op_set_cmpl(op, &q->sd_desc_off,
			    desc_off_add(sd_desc_off, nb_desc + pend_sd_desc, q_sz),
			    &q->pend_sd_desc, nb_desc);
	return 1;
}

static __rte_always_inline uint16_t
fetch_deq_desc_prep_ops(struct virtio_net_queue *q, struct rte_dma_op *op, const uint16_t flags)
{
	uintptr_t sd_desc_base = (uintptr_t)q->sd_desc_base;
	uintptr_t desc_base = q->desc_base;
	uint16_t pend_sd_desc = q->pend_sd_desc;
	uint16_t sd_desc_off = q->sd_desc_off;
	uint16_t q_sz = q->q_sz;
	uint32_t notify_data;
	uint16_t next_off, off;
	uint16_t first_seg, second_seg;
	int nb_desc;

	/* Include the wrap bit to check if there are descriptors */
	notify_data = __atomic_load_n(q->notify_addr, __ATOMIC_RELAXED);
	next_off = (notify_data >> 16) & 0xFFFF;
	if (unlikely(next_off == sd_desc_off))
		return 0;

	/* Limit the fetch to end of the queue */
	nb_desc = desc_off_diff(next_off, sd_desc_off, q_sz) - pend_sd_desc;
	if (unlikely(nb_desc <= 0))
		return 0;

	/* Allocate required mbufs */
	off = DESC_OFF(desc_off_add(sd_desc_off, pend_sd_desc, q_sz));

	if (flags & VIRTIO_NET_DESC_MANAGE_EXTBUF)
		nb_desc = alloc_extbufs(q, off, q_sz, nb_desc);
	else
		nb_desc = alloc_mbufs(q->mbuf_arr, q->mp, off, q_sz, nb_desc);

	if (unlikely(!nb_desc))
		return 0;

	/* Calculate segment sizes - check for wrap-around */
	first_seg = (off + nb_desc) > q_sz ? (q_sz - off) : nb_desc;
	second_seg = nb_desc - first_seg;

	/* Mark descriptor as invalid */
	VIRTIO_NET_DESC_CHECK(q, off, first_seg, false, false);
	VIRTIO_NET_DESC_CHECK(q, 0, second_seg, false, false);

	/* Branchless: fill all 4 segments, nb_src/nb_dst controls what's used */
	op->nb_src = 1 + !!second_seg;
	op->nb_dst = op->nb_src;
	op->src_dst_seg[0].addr = (rte_iova_t)DESC_PTR_OFF(desc_base, off, 0);
	op->src_dst_seg[0].length = first_seg << 4;
	op->src_dst_seg[1].addr = (rte_iova_t)DESC_PTR_OFF(desc_base, 0, 0);
	op->src_dst_seg[1].length = second_seg << 4;
	op->src_dst_seg[op->nb_src].addr = (rte_iova_t)DESC_PTR_OFF(sd_desc_base, off, 0);
	op->src_dst_seg[op->nb_src].length = first_seg << 4;
	op->src_dst_seg[op->nb_src + 1].addr = (rte_iova_t)DESC_PTR_OFF(sd_desc_base, 0, 0);
	op->src_dst_seg[op->nb_src + 1].length = second_seg << 4;
	op->flags = 0;

	q->pend_sd_desc += nb_desc;
	dao_dma_op_set_cmpl(op, &q->sd_desc_off,
			    desc_off_add(sd_desc_off, nb_desc + pend_sd_desc, q_sz),
			    &q->pend_sd_desc, nb_desc);
	return 1;
}

static __rte_always_inline void
mark_deq_compl_ops_noinorder(struct virtio_net_queue *q, struct rte_dma_op *op, uint16_t start,
			     uint16_t nb_desc)
{
	uintptr_t sd_desc_base = (uintptr_t)q->sd_desc_base;
	uintptr_t desc_base = q->desc_base;
	uint16_t q_sz = q->q_sz;
	uint16_t off = DESC_OFF(start);
	uint16_t first_seg, second_seg;

	/* Validate descriptor */
	VIRTIO_NET_DESC_CHECK(q, start, nb_desc, true, true);

	/* Calculate segment sizes */
	first_seg = desc_off_diff_no_wrap(desc_off_add(start, nb_desc, q_sz), start, q_sz);
	second_seg = nb_desc - first_seg;

	/* Branchless: fill all 4 segments, nb_src/nb_dst controls what's used */
	op->nb_src = 1 + !!second_seg;
	op->nb_dst = op->nb_src;
	op->src_dst_seg[0].addr = (rte_iova_t)DESC_PTR_OFF(sd_desc_base, off, 0);
	op->src_dst_seg[0].length = DESC_ENTRY_SZ * first_seg;
	op->src_dst_seg[1].addr = (rte_iova_t)DESC_PTR_OFF(sd_desc_base, 0, 0);
	op->src_dst_seg[1].length = DESC_ENTRY_SZ * second_seg;
	op->src_dst_seg[op->nb_src].addr = (rte_iova_t)DESC_PTR_OFF(desc_base, off, 0);
	op->src_dst_seg[op->nb_src].length = DESC_ENTRY_SZ * first_seg;
	op->src_dst_seg[op->nb_src + 1].addr = (rte_iova_t)DESC_PTR_OFF(desc_base, 0, 0);
	op->src_dst_seg[op->nb_src + 1].length = DESC_ENTRY_SZ * second_seg;
	op->flags = 0;
}

static __rte_always_inline void
mark_deq_compl_ops(struct virtio_net_queue *q, struct rte_dma_op *op, uint16_t start,
		   uint16_t nb_desc, const uint16_t flags)
{
	uintptr_t sd_desc_base = (uintptr_t)q->sd_desc_base;
	uintptr_t desc_base = q->desc_base;
	uint64_t last_id;
	uint64_t first;
	uint64_t used;
	uint16_t end;

	if (flags & M_NOORDER_F)
		return mark_deq_compl_ops_noinorder(q, op, start, nb_desc);

	end = desc_off_add(start, nb_desc - 1, q->q_sz);
	/* Overwrite buffer id in first descriptor second word */
	last_id = (*DESC_PTR_OFF(sd_desc_base, end, 8) >> 32) & 0xFFFF;
	first = *DESC_PTR_OFF(sd_desc_base, start, 8) & ~0xFFFF00000000UL;
	/* Mark the same value for free as used */
	used = (first >> 55) & 0x1;
	first = first & ~RTE_BIT64(63);
	*DESC_PTR_OFF(sd_desc_base, start, 8) = first | (used << 63) | last_id << 32;

	/* Validate descriptor */
	VIRTIO_NET_DESC_CHECK(q, start, desc_off_diff(end, start, q->q_sz), false, true);

	/* Issue 8-byte DMA for in-order completion */
	op->nb_src = 1;
	op->nb_dst = 1;
	op->src_dst_seg[0].addr = (rte_iova_t)DESC_PTR_OFF(sd_desc_base, start, 8);
	op->src_dst_seg[0].length = 8;
	op->src_dst_seg[1].addr = (rte_iova_t)DESC_PTR_OFF(desc_base, start, 8);
	op->src_dst_seg[1].length = 8;
	op->flags = 0;
}

static __rte_always_inline void
mark_enq_compl_ops(struct virtio_net_queue *q, struct rte_dma_op *op, uint16_t start, uint16_t end,
		   const uint16_t flags)
{
	uintptr_t sd_desc_base = (uintptr_t)q->sd_desc_base;
	uintptr_t desc_base = q->desc_base;
	uint16_t q_sz = q->q_sz;
	uint16_t off = DESC_OFF(start);
	uint16_t nb_desc, first_seg, second_seg;

	nb_desc = desc_off_diff(end, start, q_sz);

	/* Validate descriptor */
	VIRTIO_NET_DESC_CHECK(q, start, nb_desc, true, true);

	if (unlikely(!q->auto_free)) {
		if (flags & VIRTIO_NET_DESC_MANAGE_EXTBUF)
			free_extbufs(q, off, q_sz, nb_desc, flags);
		else
			free_mbufs(q->mbuf_arr, off, q_sz, nb_desc, flags);
	}

	/* Calculate segment sizes */
	first_seg = desc_off_diff_no_wrap(end, start, q_sz);
	second_seg = nb_desc - first_seg;

	/* Branchless: fill all 4 segments, nb_src/nb_dst controls what's used */
	op->nb_src = 1 + !!second_seg;
	op->nb_dst = op->nb_src;
	op->src_dst_seg[0].addr = (rte_iova_t)DESC_PTR_OFF(sd_desc_base, off, 0);
	op->src_dst_seg[0].length = DESC_ENTRY_SZ * first_seg;
	op->src_dst_seg[1].addr = (rte_iova_t)DESC_PTR_OFF(sd_desc_base, 0, 0);
	op->src_dst_seg[1].length = DESC_ENTRY_SZ * second_seg;
	op->src_dst_seg[op->nb_src].addr = (rte_iova_t)DESC_PTR_OFF(desc_base, off, 0);
	op->src_dst_seg[op->nb_src].length = DESC_ENTRY_SZ * first_seg;
	op->src_dst_seg[op->nb_src + 1].addr = (rte_iova_t)DESC_PTR_OFF(desc_base, 0, 0);
	op->src_dst_seg[op->nb_src + 1].length = DESC_ENTRY_SZ * second_seg;
	op->flags = 0;
}

static __rte_always_inline int
virtio_net_desc_manage_ops(uint16_t devid, uint16_t qp_count, const uint16_t flags)
{
	struct dao_virtio_netdev *virtio_netdev = &dao_virtio_netdevs[devid];
	struct virtio_netdev *netdev = virtio_netdev_priv(virtio_netdev);
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	struct dao_dma_vchan_state *dev2mem, *mem2dev;
	struct rte_dma_op **dev2mem_ops, **mem2dev_ops;
	uint16_t d2m_ops_tail, d2m_ops_mask;
	uint16_t m2d_ops_tail, m2d_ops_mask;
	struct virtio_net_queue *rxq, *txq;
	uint16_t compl_off, q_sz;
	uint16_t dma_vchan;
	uint16_t nb_desc;
	uint16_t dev2mem_op_cnt = 0;
	uint16_t mem2dev_op_cnt = 0;
	uint16_t total_ops;
	uint16_t off;
	int i, nb_enq;

	if (unlikely(!netdev->qs[qp_count * 2 - 1]))
		return 0;

	dma_vchan = netdev->qs[0]->dma_vchan;
	dev2mem = &vchan_info->dev2mem[dma_vchan];
	mem2dev = &vchan_info->mem2dev[dma_vchan];

	/* Fetch all DMA completed status */
	dao_dma_check_meta_compl_ops(dev2mem, 1 /* ATOMIC update */);
	dao_dma_check_meta_compl_ops(mem2dev, 1 /* ATOMIC update */);

	total_ops = qp_count * 2;

	/* Check ops ring availability for both directions */
	if (unlikely(dao_dma_ops_avail(dev2mem) < total_ops) ||
	    unlikely(dao_dma_ops_avail(mem2dev) < total_ops))
		return 0;

	/* Get precomputed ops arrays and save starting positions */
	d2m_ops_tail = dev2mem->ops_tail;
	d2m_ops_mask = dev2mem->ops_mask;
	dev2mem_ops = dev2mem->dma_ops;
	dev2mem->ops_tail = d2m_ops_tail + total_ops;

	m2d_ops_tail = mem2dev->ops_tail;
	m2d_ops_mask = mem2dev->ops_mask;
	mem2dev_ops = mem2dev->dma_ops;
	mem2dev->ops_tail = m2d_ops_tail + total_ops;

	/* Process all queue pairs */
	for (i = 0; i < qp_count; i++) {
		struct rte_dma_op *op;

		rxq = netdev->qs[(i * 2)];
		txq = netdev->qs[(i * 2) + 1];

		/* Prefetch next queue pair structures into L1 */
		if (likely(i + 1 < qp_count)) {
			rte_prefetch0(netdev->qs[((i + 1) * 2)]);
			rte_prefetch0(netdev->qs[((i + 1) * 2) + 1]);
		}

		/* === Host Rx queue (enqueue path) === */
		/* Fetch descriptors */
		op = dev2mem_ops[(d2m_ops_tail + dev2mem_op_cnt) & d2m_ops_mask];
		dev2mem_op_cnt += fetch_enq_desc_prep_ops(rxq, dev2mem, op, dev2mem_op_cnt);

		/* Check completion and trigger host interrupt */
		if (rxq->cb_intr_addr && rxq->pend_compl &&
		    dao_dma_op_status(mem2dev, rxq->pend_compl_idx)) {
			__atomic_store_n(rxq->cb_notify_addr, 1, __ATOMIC_RELAXED);
			virtio_net_intr_trigger(rxq->cb_intr_addr, rxq->cb_ack_addr,
						rxq->cb_intr_val);
			rxq->pend_compl = 0;
		}

		/* Mark enqueue completion */
		off = __atomic_load_n(&rxq->sd_mbuf_off, __ATOMIC_ACQUIRE);
		compl_off = rxq->compl_off;
		if (compl_off != off) {
			op = mem2dev_ops[(m2d_ops_tail + mem2dev_op_cnt) & m2d_ops_mask];
			mark_enq_compl_ops(rxq, op, compl_off, off, flags);
			op->user_meta = (uint64_t)(uintptr_t)rxq;
			op->event_meta = (uint64_t)compl_off |
				((uint64_t)rxq->pend_compl_idx << 16) |
				((uint64_t)rxq->pend_compl << 32);
			rxq->compl_off = off;
			rxq->pend_compl_idx = mem2dev->tail + mem2dev_op_cnt;
			rxq->pend_compl = 1;
			mem2dev_op_cnt++;
		}

		/* === Host Tx queue (dequeue path) === */
		/* Fetch descriptors */
		op = dev2mem_ops[(d2m_ops_tail + dev2mem_op_cnt) & d2m_ops_mask];
		dev2mem_op_cnt += fetch_deq_desc_prep_ops(txq, op, flags);

		/* Check completion and trigger host interrupt */
		if (txq->cb_intr_addr && txq->pend_compl &&
		    dao_dma_op_status(mem2dev, txq->pend_compl_idx)) {
			__atomic_store_n(txq->cb_notify_addr, 1, __ATOMIC_RELAXED);
			virtio_net_intr_trigger(txq->cb_intr_addr, txq->cb_ack_addr,
						txq->cb_intr_val);
			txq->pend_compl = 0;
		}

		/* Mark dequeue completion */
		off = __atomic_load_n(&txq->last_off, __ATOMIC_ACQUIRE);
		compl_off = txq->compl_off;
		q_sz = txq->q_sz;
		if (compl_off != off) {
			nb_desc = desc_off_diff(off, compl_off, q_sz);
			op = mem2dev_ops[(m2d_ops_tail + mem2dev_op_cnt) & m2d_ops_mask];
			mark_deq_compl_ops(txq, op, compl_off, nb_desc, flags);
			op->user_meta = (uint64_t)(uintptr_t)txq;
			op->event_meta = (uint64_t)compl_off |
				((uint64_t)txq->pend_compl_idx << 16) |
				((uint64_t)txq->pend_compl << 32);
			txq->compl_off = off;
			txq->pend_compl_idx = mem2dev->tail + mem2dev_op_cnt;
			txq->pend_compl = 1;
			mem2dev_op_cnt++;
		}
	}

	/* Enqueue descriptor fetch ops and release unused/failed */
	nb_enq = 0;
	if (dev2mem_op_cnt) {
		nb_enq = rte_dma_enqueue_ops(dev2mem->devid, dev2mem->vchan,
					     &dev2mem_ops[d2m_ops_tail & d2m_ops_mask],
					     dev2mem_op_cnt);
		if (unlikely(nb_enq < dev2mem_op_cnt)) {
			for (i = nb_enq; i < dev2mem_op_cnt; i++) {
				struct rte_dma_op *fail_op =
					dev2mem_ops[(d2m_ops_tail + i) & d2m_ops_mask];

				if (fail_op->rsvd) {
					uint16_t *pend_ptr =
						(uint16_t *)(uintptr_t)fail_op->event_meta;

					*pend_ptr -= fail_op->rsvd & 0xFFFF;
					fail_op->rsvd = 0;
				}
			}
		}
		dev2mem->tail += nb_enq;
	}
	/* Release all dev2mem ops that were not enqueued (unused + failed) */
	dao_dma_ops_release(dev2mem, total_ops - nb_enq);

	/* Enqueue completion marking ops and release unused/failed */
	nb_enq = 0;
	if (mem2dev_op_cnt) {
		nb_enq = rte_dma_enqueue_ops(mem2dev->devid, mem2dev->vchan,
					     &mem2dev_ops[m2d_ops_tail & m2d_ops_mask],
					     mem2dev_op_cnt);
		if (unlikely(nb_enq < mem2dev_op_cnt)) {
			for (i = nb_enq; i < mem2dev_op_cnt; i++) {
				struct rte_dma_op *fail_op =
					mem2dev_ops[(m2d_ops_tail + i) & m2d_ops_mask];
				struct virtio_net_queue *q =
					(struct virtio_net_queue *)(uintptr_t)
						fail_op->user_meta;

				q->compl_off = (uint16_t)fail_op->event_meta;
				q->pend_compl_idx =
					(uint16_t)(fail_op->event_meta >> 16);
				q->pend_compl =
					(uint16_t)(fail_op->event_meta >> 32);
				fail_op->rsvd = 0;
			}
		}
		mem2dev->tail += nb_enq;
	}
	/* Release all mem2dev ops that were not enqueued (unused + failed) */
	dao_dma_ops_release(mem2dev, total_ops - nb_enq);

	return 0;
}

#define M(name, flags)                                                                             \
	int virtio_net_desc_manage_ops_##name(uint16_t devid, uint16_t qp_count)                   \
	{                                                                                          \
		return virtio_net_desc_manage_ops(devid, qp_count, (flags));                       \
	}

VIRTIO_NET_DESC_MANAGE_MODES
#undef M
