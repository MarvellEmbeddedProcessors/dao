/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2026 Marvell.
 */

#include <rte_ip.h>
#include <rte_vect.h>

#include "dao_virtio_netdev.h"
#include "virtio_dev_priv.h"

#include "spec/virtio_net.h"
#include "virtio_net_priv.h"

/* Maximum burst size for DMA ops array allocation */
#define VIRTIO_NET_DMA_MAX_BURST 128

dao_virtio_net_deq_fn_t dao_virtio_net_deq_ops_fns[VIRTIO_NET_DEQ_OFFLOAD_LAST << 1] = {
#define R(name, flags) [flags] = virtio_net_deq_ops_##name,
	VIRTIO_NET_DEQ_FASTPATH_MODES
#undef R
};

static __rte_always_inline uint16_t
fetch_host_data_ops(struct virtio_net_queue *q, struct dao_dma_vchan_state *dev2mem, uint16_t hint,
		    const uint16_t flags)
{
	const uint64_t rearm_data = 0x100010000ULL | RTE_PKTMBUF_HEADROOM;
	uintptr_t desc_base = (uintptr_t)q->sd_desc_base;
	struct rte_mbuf *mbuf0, *mbuf1, *mbuf2, *mbuf3;
	const uint8_t flush_thr = dev2mem->flush_thr;
	const uint16_t vhdr_sz = q->virtio_hdr_sz;
	uint64x2_t len01, len23, buf01, buf23;
	uint64x2_t desc0, desc1, desc2, desc3;
	uint8_t curr_op = 0, src_off, dst_off;
	uint16_t sd_desc_off, sd_mbuf_off;
	uint32_t nb_mbufs, count, nb_enq;
	uint32_t i = 0, slen, dlen;
	uint16_t data_off = q->data_off;
	uint16_t buf_len = q->buf_len;
	uint64x2_t flags01, flags23;
	uint16_t ops_tail, ops_mask;
	struct rte_dma_op **dma_ops;
	struct rte_dma_op *op;
	uint64_t *op_src, *op_dst;
	struct rte_mbuf **mbuf_arr;
	uint64x2_t mbuf01, mbuf23;
	uint64x2_t xtmp0, xtmp1;
	uint64_t d_flags, avail;
	uint16_t q_sz = q->q_sz;
	struct rte_mbuf *mbuf;
	uint32x4_t xlen, ylen;
	uint16_t used = 0;
	int j;
	uint16_t off, mbuf_off;

	sd_mbuf_off = q->sd_mbuf_off;

	sd_desc_off = __atomic_load_n(&q->sd_desc_off, __ATOMIC_ACQUIRE);
	/* Return if already something is pending DMA or there are no descriptors to process */
	if (unlikely(sd_desc_off == sd_mbuf_off))
		return sd_mbuf_off;

	/* Start DMAs of mbuf's assuming other pending mbuf's are done */
	nb_mbufs = desc_off_diff(sd_desc_off, sd_mbuf_off, q_sz) - q->pend_sd_mbuf;
	if (!nb_mbufs)
		return sd_mbuf_off;

	nb_mbufs = RTE_MIN(nb_mbufs, hint);
	if (nb_mbufs > VIRTIO_NET_DMA_MAX_BURST)
		nb_mbufs = VIRTIO_NET_DMA_MAX_BURST;

	/* Clamp to available ops, allow partial burst instead of all-or-nothing */
	{
		uint16_t ops_free = dao_dma_ops_avail(dev2mem);

		if (unlikely(ops_free < nb_mbufs)) {
			nb_mbufs = ops_free;
			if (!nb_mbufs)
				return sd_mbuf_off;
		}
	}

	/* Get precomputed ops array and save starting position */
	ops_tail = dev2mem->ops_tail;
	ops_mask = dev2mem->ops_mask;
	dma_ops = dev2mem->dma_ops;
	dev2mem->ops_tail = ops_tail + nb_mbufs;

	off = desc_off_add(sd_mbuf_off, q->pend_sd_mbuf, q_sz);
	off = DESC_OFF(off);

	rte_prefetch0(DESC_PTR_OFF(desc_base, off, 0));
	rte_prefetch0(DESC_PTR_OFF(desc_base, off + 4, 0));
	mbuf_arr = q->mbuf_arr;
	rte_prefetch0(&mbuf_arr[off]);

	uint16_t pack_filled_len = 0, pack_sz = 0;

	/* Start DMA of mbuf data */
	count = nb_mbufs & ~(0x3u);
	for (i = 0; i < count;) {
		if (pack_filled_len == 0) {
			op = dma_ops[(ops_tail + curr_op) & ops_mask];
			op->flags = 0;
			/* Calculate the pack size based on remaining mbufs */
			pack_sz = count - i;
			if (pack_sz > flush_thr)
				pack_sz = flush_thr;
			op->nb_src = pack_sz;
			op->nb_dst = pack_sz;
		}

		src_off = pack_filled_len;
		dst_off = src_off + pack_sz;

		op_src = (uint64_t *)&op->src_dst_seg[src_off];
		op_dst = (uint64_t *)&op->src_dst_seg[dst_off];

		const uint64x2_t hoff = {0, vhdr_sz};
		uint64x2_t doff_vec = vdupq_n_u64(data_off);
		uint64x2_t f0, f1, f2, f3;
		const uint64x2_t rearm = {rearm_data + vhdr_sz, 0};
		const uint8x16_t shuf_msk = {
			0xFF, 0xFF, 0xFF, 0xFF, 8,    9,    0xFF, 0xFF,
			8,    9,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		};
		const uint32x4_t vbuf_len = {buf_len, 0, buf_len, 0};
		const uint64x2_t xflags_mask = {
			~(VIRT_PACKED_RING_DESC_F_USED),
			~(VIRT_PACKED_RING_DESC_F_USED),
		};
		const uint64x2_t xflags2 = {
			VIRT_PACKED_RING_DESC_F_AVAIL,
			VIRT_PACKED_RING_DESC_F_AVAIL,
		};

		if (unlikely(off + 3 >= q_sz)) {
			if (pack_filled_len > 0) {
				memcpy(&op->src_dst_seg[pack_filled_len], &op->src_dst_seg[pack_sz],
				       pack_filled_len * sizeof(struct rte_dma_sge));
				op->nb_src = pack_filled_len;
				op->nb_dst = pack_filled_len;
				curr_op++;
			}
			break;
		}

		desc0 = vld1q_u64(DESC_PTR_OFF(desc_base, off, 0));
		desc1 = vld1q_u64(DESC_PTR_OFF(desc_base, off + 1, 0));
		desc2 = vld1q_u64(DESC_PTR_OFF(desc_base, off + 2, 0));
		desc3 = vld1q_u64(DESC_PTR_OFF(desc_base, off + 3, 0));

		buf01 = vzip1q_u64(desc0, desc1);
		buf23 = vzip1q_u64(desc2, desc3);

		mbuf01 = vld1q_u64((uint64_t *)&mbuf_arr[off]);
		mbuf23 = vld1q_u64((uint64_t *)&mbuf_arr[off + 2]);

		/* Prefetch descriptors far ahead to hide memory latency */
		rte_prefetch0(DESC_PTR_OFF(desc_base, off + 16, 0));
		rte_prefetch0(DESC_PTR_OFF(desc_base, off + 32, 0));
		rte_prefetch0(mbuf_arr + ((off + 24) & (q_sz - 1)));
		if (likely(off + 7 < q_sz)) {
			rte_prefetch0_write(mbuf_arr[off + 4]);
			rte_prefetch0_write(mbuf_arr[off + 5]);
			rte_prefetch0_write(mbuf_arr[off + 6]);
			rte_prefetch0_write(mbuf_arr[off + 7]);
		}

		/* Extract lengths */
		len01 = vzip2q_u64(desc0, desc1);
		len23 = vzip2q_u64(desc2, desc3);

		xlen = vcgtq_u32(len01, vbuf_len);
		ylen = vcgtq_u32(len23, vbuf_len);
		xlen = vuzp1q_u32(xlen, ylen);
		if (vmaxvq_u32(xlen)) {
			if (pack_filled_len > 0) {
				memcpy(&op->src_dst_seg[pack_filled_len], &op->src_dst_seg[pack_sz],
				       pack_filled_len * sizeof(struct rte_dma_sge));
				op->nb_src = pack_filled_len;
				op->nb_dst = pack_filled_len;
				curr_op++;
			}
			break;
		}

		if (flags & VIRTIO_NET_DEQ_OFFLOAD_NOINOR) {
			flags01 = vzip2q_u64(desc0, desc1);
			flags23 = vzip2q_u64(desc2, desc3);

			/* Prepare descriptor flags */
			flags01 = flags01 & xflags_mask;
			flags23 = flags23 & xflags_mask;

			/* Extract AVAIL bits and move to USED */
			xtmp0 = flags01 & xflags2;
			xtmp1 = flags23 & xflags2;
			xtmp0 = xtmp0 << 8;
			xtmp1 = xtmp1 << 8;
			/* Set USED field in flags */
			flags01 |= xtmp0;
			flags23 |= xtmp1;

			desc0 = vzip1q_u64(buf01, flags01);
			desc1 = vzip2q_u64(buf01, flags01);
			desc2 = vzip1q_u64(buf23, flags23);
			desc3 = vzip2q_u64(buf23, flags23);

			/* Write back descriptor and its flags */
			vst1q_u64(DESC_PTR_OFF(desc_base, off, 0), desc0);
			vst1q_u64(DESC_PTR_OFF(desc_base, off + 1, 0), desc1);
			vst1q_u64(DESC_PTR_OFF(desc_base, off + 2, 0), desc2);
			vst1q_u64(DESC_PTR_OFF(desc_base, off + 3, 0), desc3);
		}

		/* Take minimum of pktbuf and desc buf len */
		len01 = vminq_u32(len01, vbuf_len);
		len23 = vminq_u32(len23, vbuf_len);

		/* Store source pointers in op */
		vst1q_u64(&op_src[0], vzip1q_u64(buf01, len01));
		vst1q_u64(&op_src[2], vzip2q_u64(buf01, len01));
		vst1q_u64(&op_src[4], vzip1q_u64(buf23, len23));
		vst1q_u64(&op_src[6], vzip2q_u64(buf23, len23));

		mbuf0 = (struct rte_mbuf *)vgetq_lane_u64(mbuf01, 0);
		mbuf1 = (struct rte_mbuf *)vgetq_lane_u64(mbuf01, 1);
		mbuf2 = (struct rte_mbuf *)vgetq_lane_u64(mbuf23, 0);
		mbuf3 = (struct rte_mbuf *)vgetq_lane_u64(mbuf23, 1);

		/* Move mbuf to data offset */
		mbuf01 = vaddq_u64(mbuf01, doff_vec);
		mbuf23 = vaddq_u64(mbuf23, doff_vec);

		/* Store destination pointers in op */
		vst1q_u64(&op_dst[0], vzip1q_u64(mbuf01, len01));
		vst1q_u64(&op_dst[2], vzip2q_u64(mbuf01, len01));
		vst1q_u64(&op_dst[4], vzip1q_u64(mbuf23, len23));
		vst1q_u64(&op_dst[6], vzip2q_u64(mbuf23, len23));

		desc0 = vsubq_u64(desc0, hoff);
		desc1 = vsubq_u64(desc1, hoff);
		desc2 = vsubq_u64(desc2, hoff);
		desc3 = vsubq_u64(desc3, hoff);

		/* Prepare rx_descriptor_fields1 with pkt_len and data_len */
		f0 = vqtbl1q_u8(desc0, shuf_msk);
		f1 = vqtbl1q_u8(desc1, shuf_msk);
		f2 = vqtbl1q_u8(desc2, shuf_msk);
		f3 = vqtbl1q_u8(desc3, shuf_msk);

		vst1q_u64((uint64_t *)&mbuf0->rx_descriptor_fields1, f0);
		vst1q_u64((uint64_t *)&mbuf1->rx_descriptor_fields1, f1);
		vst1q_u64((uint64_t *)&mbuf2->rx_descriptor_fields1, f2);
		vst1q_u64((uint64_t *)&mbuf3->rx_descriptor_fields1, f3);

		/* Store rearm data */
		vst1q_u64((uint64_t *)&mbuf0->rearm_data, rearm);
		vst1q_u64((uint64_t *)&mbuf1->rearm_data, rearm);
		vst1q_u64((uint64_t *)&mbuf2->rearm_data, rearm);
		vst1q_u64((uint64_t *)&mbuf3->rearm_data, rearm);

		/* Reset mbuf next pointer (ol_flags already zeroed by 16B rearm store) */
		mbuf0->next = NULL;
		mbuf1->next = NULL;
		mbuf2->next = NULL;
		mbuf3->next = NULL;

		pack_filled_len += 4;
		i += 4;
		used = i;

		if (pack_filled_len == pack_sz) {
			curr_op++;
			pack_filled_len = 0;
			rte_prefetch0_write(dma_ops[(ops_tail + curr_op) & ops_mask]);
		}
		off = (off + 4) & (q_sz - 1);
	}

	/* Reset packing state for scalar loop */
	pack_filled_len = 0;

	while (i < nb_mbufs) {
		struct rte_mbuf *mbuf1;
		uint32_t pend = 0;

		mbuf = mbuf_arr[off];
		mbuf0 = mbuf;

		d_flags = *DESC_PTR_OFF(desc_base, off, 8);
		slen = d_flags & (RTE_BIT64(32) - 1);
		dlen = slen;

		if (flags & VIRTIO_NET_DEQ_OFFLOAD_NOINOR) {
			avail = !!(d_flags & VIRT_PACKED_RING_DESC_F_AVAIL);
			d_flags &= ~VIRT_PACKED_RING_DESC_F_AVAIL_USED;

			/* Set both AVAIL and USED bit same */
			*DESC_PTR_OFF(desc_base, off, 8) = avail << 55 | avail << 63 | d_flags;
		}

		/* Limit data to buffer length */
		if (unlikely(slen > buf_len)) {
			pend = slen - buf_len;
			dlen = buf_len;
		}

		/* Multi-segment case: handle separately */
		if (unlikely(pend)) {
			uint8_t nb_dst_segs = 1;

			/* Finalize any pending pack before handling mseg */
			if (pack_filled_len > 0) {
				rte_memcpy(&op->src_dst_seg[pack_filled_len],
					   &op->src_dst_seg[pack_sz],
					   pack_filled_len * sizeof(struct rte_dma_sge));
				op->nb_src = pack_filled_len;
				op->nb_dst = pack_filled_len;
				curr_op++;
				pack_filled_len = 0;
			}

			/* Use a dedicated op for this multi-segment packet */
			op = dma_ops[(ops_tail + curr_op) & ops_mask];
			op->flags = 0;

			/* Source: single large buffer from host */
			op->src_dst_seg[0].addr = *DESC_PTR_OFF(desc_base, off, 0);
			op->src_dst_seg[0].length = slen;

			/* First destination segment */
			op->src_dst_seg[1].addr = (((uintptr_t)mbuf) + data_off);
			op->src_dst_seg[1].length = dlen;

			/* Update first mbuf */
			*((uint64_t *)&mbuf->rearm_data) = rearm_data + vhdr_sz;
			mbuf->pkt_len = slen - vhdr_sz;
			mbuf->data_len = dlen - vhdr_sz;
			mbuf->next = NULL;
			mbuf->ol_flags = 0;

			/* Allocate additional mbufs for remaining data */
			while (pend) {
				if (rte_mempool_get(q->mp, (void **)&mbuf1)) {
					/* Failed to allocate, cleanup and exit */
					free_mbuf_seg_chain(mbuf0->next);
					mbuf0->next = NULL;
					mbuf0->nb_segs = 1;
					goto exit;
				}

				*((uint64_t *)&mbuf1->rearm_data) = rearm_data;
				dlen = pend;
				if (dlen > buf_len)
					dlen = buf_len;

				mbuf->next = mbuf1;
				mbuf = mbuf1;
				mbuf->data_len = dlen;
				mbuf->next = NULL;
				mbuf->ol_flags = 0;
				mbuf0->nb_segs++;

				/* Add destination segment */
				nb_dst_segs++;
				op->src_dst_seg[nb_dst_segs].addr = (((uintptr_t)mbuf) + data_off);
				op->src_dst_seg[nb_dst_segs].length = dlen;
				pend -= dlen;
			}

			op->nb_src = 1;
			op->nb_dst = nb_dst_segs;
			curr_op++;

			i++;
			off = (off + 1) & (q_sz - 1);
			used = i;
			continue;
		}

		/* Initialize new pack if needed */
		if (pack_filled_len == 0) {
			op = dma_ops[(ops_tail + curr_op) & ops_mask];
			op->flags = 0;
			/* Calculate the pack size based on remaining mbufs */
			pack_sz = nb_mbufs - i;
			if (pack_sz > flush_thr)
				pack_sz = flush_thr;
		}

		src_off = pack_filled_len;
		dst_off = src_off + pack_sz;

		op->src_dst_seg[src_off].addr = *DESC_PTR_OFF(desc_base, off, 0);
		op->src_dst_seg[src_off].length = slen;
		op->src_dst_seg[dst_off].addr = (((uintptr_t)mbuf) + data_off);
		op->src_dst_seg[dst_off].length = dlen;

		/* Update mbuf length */
		*((uint64_t *)&mbuf->rearm_data) = rearm_data + vhdr_sz;
		mbuf->pkt_len = slen - vhdr_sz;
		mbuf->data_len = dlen - vhdr_sz;
		mbuf->next = NULL;
		mbuf->ol_flags = 0;

		pack_filled_len++;
		if (pack_filled_len == pack_sz) {
			op->nb_src = pack_sz;
			op->nb_dst = pack_sz;
			curr_op++;
			pack_filled_len = 0;
		}

		i++;
		off = (off + 1) & (q_sz - 1);
		used = i;
	}

exit:
	/* Finalize any remaining pack from scalar loop */
	if (pack_filled_len > 0) {
		rte_memcpy(&op->src_dst_seg[pack_filled_len], &op->src_dst_seg[pack_sz],
			   pack_filled_len * sizeof(struct rte_dma_sge));
		op->nb_src = pack_filled_len;
		op->nb_dst = pack_filled_len;
		curr_op++;
	}

	/* ops array is 2x size with duplicated pointers - no wrap handling needed */
	nb_enq = rte_dma_enqueue_ops(dev2mem->devid, dev2mem->vchan, &dma_ops[ops_tail & ops_mask],
				     curr_op);
	if (nb_enq < curr_op) {
		uint16_t fail_off, total_failed = 0;

		/* Compute start offset of failed ops region */
		for (j = nb_enq; j < curr_op; j++)
			total_failed += dma_ops[(ops_tail + j) & ops_mask]->nb_src;
		fail_off = (off - total_failed) & (q_sz - 1);

		for (j = nb_enq; j < curr_op; j++) {
			op = dma_ops[(ops_tail + j) & ops_mask];

			/* For MSEG ops (nb_src != nb_dst), free the
			 * allocated mbuf chain segments to avoid leaks.
			 */
			if (op->nb_src != op->nb_dst) {
				struct rte_mbuf *head = mbuf_arr[fail_off];

				if (head->next) {
					free_mbuf_seg_chain(head->next);
					head->next = NULL;
					head->nb_segs = 1;
				}
			}

			fail_off = (fail_off + op->nb_src) & (q_sz - 1);
			used -= op->nb_src;
			i -= op->nb_src;
		}
	}
	dev2mem->tail += nb_enq;

	/* Release all ops that were not successfully enqueued */
	if (nb_enq < nb_mbufs)
		dao_dma_ops_release(dev2mem, nb_mbufs - nb_enq);

	if (likely(used)) {
		mbuf_off = desc_off_add(q->sd_mbuf_off, used + q->pend_sd_mbuf, q->q_sz);
		q->pend_sd_mbuf += used;
		dao_dma_op_set_cmpl(dma_ops[(ops_tail + nb_enq - 1) & ops_mask], &q->sd_mbuf_off,
				    mbuf_off, &q->pend_sd_mbuf, used);
	}

	return sd_mbuf_off;
}

static __rte_always_inline int
virtio_net_deq_ops(struct virtio_net_queue *q, struct rte_mbuf **mbufs, uint16_t nb_mbufs,
		   const uint16_t flags)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	uint16_t dma_vchan = q->dma_vchan;
	struct dao_dma_vchan_state *dev2mem;
	uint16_t nb_avail, last_off;
	uint16_t sd_mbuf_off;
	uint16_t q_sz;
	int rc = 0;

	dev2mem = &vchan_info->dev2mem[dma_vchan];

	rte_prefetch0(&q->last_off);
	/* Update completed DMA ops */
	dao_dma_check_meta_compl_ops(dev2mem, 0 /* No ATOMIC update */);

	/* Check shadow mbuf status and issue new DMA's for mbuf's */
	sd_mbuf_off = fetch_host_data_ops(q, dev2mem, 128, flags);
	last_off = q->last_off;

	q_sz = q->q_sz;
	/* Check for available mbufs */
	nb_avail = desc_off_diff(sd_mbuf_off, last_off, q_sz);

	/* Return if no mbuf's available */
	if (unlikely(!nb_avail))
		goto exit;

	nb_mbufs = RTE_MIN(nb_mbufs, nb_avail);

	/* Post process packets and fill buffers */
	rc = post_process_pkts(q, mbufs, &nb_mbufs, flags);

	last_off = desc_off_add(last_off, nb_mbufs, q_sz);
	__atomic_store_n(&q->last_off, last_off, __ATOMIC_RELEASE);
exit:
	return rc;
}

#define R(name, flags)                                                                             \
	uint16_t virtio_net_deq_ops_##name(void *q, struct rte_mbuf **mbufs, uint16_t nb_mbufs)    \
	{                                                                                          \
		return virtio_net_deq_ops(q, mbufs, nb_mbufs, (flags));                            \
	}

VIRTIO_NET_DEQ_FASTPATH_MODES
#undef R
