/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell.
 */

#include "dao_virtio_blkdev.h"
#include "virtio_dev_priv.h"

#include "spec/virtio_blk.h"
#include "virtio_blk_priv.h"

dao_virtio_blk_deq_fn_t dao_virtio_blk_deq_fns[VIRTIO_BLK_DEQ_LAST << 1] = {
#define R(name, flags)[flags] = virtio_blk_deq_##name,
	VIRTIO_BLK_DEQ_FASTPATH_MODES
#undef R
};

void
virtio_blk_flush_deq(struct virtio_blk_queue *q)
{
	uint16_t pend_sd_mbuf = q->pend_sd_mbuf, sd_desc_off, sd_mbuf_off = q->sd_mbuf_off;
	uint16_t last_off = q->last_off, q_sz = q->q_sz;
	struct rte_mempool *mp;
	uint32_t nb_avail;

	sd_desc_off = __atomic_load_n(&q->sd_desc_off, __ATOMIC_ACQUIRE);
	/* Return if no pending mbufs */
	if (unlikely(!pend_sd_mbuf || sd_desc_off == sd_mbuf_off))
		return;

	/* We are sure all DMAs are completed before reaching here */
	if (pend_sd_mbuf) {
		sd_mbuf_off = desc_off_add(q->sd_mbuf_off, pend_sd_mbuf, q_sz);
		pend_sd_mbuf = 0;
		q->sd_mbuf_off = sd_mbuf_off;
		q->pend_sd_mbuf = 0;
	}
	/* Check for available mbufs */
	nb_avail = desc_off_diff_no_wrap(sd_mbuf_off, last_off, q_sz);
	/* Return if no mbuf's available */
	if (unlikely(!nb_avail))
		return;

	mp = q->mp;
	rte_mempool_put_bulk(mp, &q->mbuf_arr[DESC_OFF(last_off)], nb_avail);
	last_off = desc_off_add(last_off, nb_avail, q_sz);
	nb_avail = sd_mbuf_off - last_off;
	if (nb_avail)
		rte_mempool_put_bulk(mp, &q->mbuf_arr[DESC_OFF(last_off)], nb_avail);
}

static __rte_always_inline uint16_t
fetch_host_data(struct virtio_blk_queue *q, struct dao_dma_vchan_state *dev2mem, uint16_t hint,
		const uint16_t flags)
{
	uintptr_t desc_base = (uintptr_t)q->sd_desc_base;
	struct rte_dma_sge *src = NULL, *dst = NULL;
	struct dao_virtio_blk_hdr *buf, *n_buf, *buf0;
	uint16_t pend_sd_mbuf = q->pend_sd_mbuf;
	uint32_t i = 0, slen, dlen, pend = 0;
	uint64_t d_flags, avail, is_rd = 0;
	uint16_t sd_desc_off, sd_mbuf_off;
	uint16_t buf_len = q->buf_len;
	uint16_t q_sz = q->q_sz;
	uint16_t used = 0, off;
	void **extbuf_arr;
	uint32_t nb_bufs;
	int last_idx = 0;

	RTE_SET_USED(flags);
	RTE_SET_USED(avail);
	RTE_SET_USED(hint);
	sd_mbuf_off = q->sd_mbuf_off;
	/* Check if pending DMA's for rx data are done */
	if (pend_sd_mbuf && dao_dma_op_status(dev2mem, q->pend_sd_mbuf_idx)) {
		sd_mbuf_off = desc_off_add(q->sd_mbuf_off, pend_sd_mbuf, q_sz);
		pend_sd_mbuf = 0;
		q->sd_mbuf_off = sd_mbuf_off;
		q->pend_sd_mbuf = 0;
	}

	sd_desc_off = __atomic_load_n(&q->sd_desc_off, __ATOMIC_ACQUIRE);
	/* Return if already something is pending DMA or there are no descriptors to process */
	if (unlikely(pend_sd_mbuf || sd_desc_off == sd_mbuf_off))
		return sd_mbuf_off;

	nb_bufs = desc_off_diff(sd_desc_off, sd_mbuf_off, q_sz);
	/* This is leading to issues due to broken chain of descriptors when
	   nb_bufs > hint. There is no guarantee that hint will always limit
	   the nb_bufs to exact boundary of descriptor chain. No need to
	   limit here. Revist if necessary. */
	// nb_bufs = RTE_MIN(nb_bufs, hint);

	off = DESC_OFF(sd_mbuf_off);
	rte_prefetch0(DESC_PTR_OFF(desc_base, off, 0));
	extbuf_arr = q->extbuf_arr;

	/* Flush to get minimum space */
	if (!dao_dma_flush(dev2mem, 1))
		return sd_mbuf_off;

	/* Start DMA of buf data */
	while (i < nb_bufs) {
		buf = (struct dao_virtio_blk_hdr *)extbuf_arr[off];

		d_flags = *DESC_PTR_OFF(desc_base, off, 8);
		slen = d_flags & (RTE_BIT64(32) - 1);
		dlen = slen;
		/* read-only buffer(blk write reqs) for device */
		is_rd = !(d_flags & ((unsigned long)VRING_DESC_F_WRITE << 48));

		/* Limit data to buffer length */
		if (unlikely(slen > buf_len)) {
			pend = slen - buf_len;
			dlen = buf_len;
			/* NOTE: This would break the statement "each segment
			   is one desc in vring". i.e buf0->total_segs == num
			   of desc making the IO. As long as buf_len >=
			   size_max (i.e max segment size) in block dev config,
			   it's unlikely that segment has to be fragmented to
			   fit into local bufs. Currently buf_len value is
			   coming from app, so outside the library scope.
			   Library cannot assume that this statement will
			   always hold good, can potentially lead to completion
			   issues. Logging this as a warning for now. */
			dao_warn("[dev %u] [qid %u] Fragmented segment "
				 "detected at %s:%d. slen %u > buf_len "
				 "%u, off %u",
				 q->blkdev_id, q->qid, __func__, __LINE__, slen, buf_len, off);
		}

		if (is_rd) {
			src = dao_dma_sge_src(dev2mem);
			dst = dao_dma_sge_dst(dev2mem);
			src[0].addr = *DESC_PTR_OFF(desc_base, off, 0);
			src[0].length = slen;
			dst[0].addr = (uintptr_t)(buf->hdr_data);
			dst[0].length = dlen;
			dev2mem->src_i++;
			dev2mem->dst_i++;
		}

		/* update buffer length */
		buf->desc_data[0] = 0x0;
		buf->desc_data[1] = dlen | (d_flags & 0xFFFF000000000000);
		buf0 = buf;
		buf0->tot_len = slen;
		buf0->tot_segs = 1;
		buf0->tot_bufs = 1;

		while (unlikely(pend)) {
			blkdev_user_cbs.extbuf_get(q->blkdev_id, (void **)&n_buf, 1);
			dlen = pend;
			if (unlikely(dlen > buf_len))
				dlen = buf_len;
			n_buf->desc_data[0] = 0x0;
			n_buf->desc_data[1] = dlen;
			buf->desc_data[0] = (uintptr_t)n_buf;

			/* Enqueue only destination pointers as source length is big */
			if (is_rd)
				dao_dma_enq_dst_x1(dev2mem, (uintptr_t)(n_buf->hdr_data), dlen);
			pend -= dlen;
			buf = n_buf;
			buf0->tot_bufs++;
		}

		i++;
		off = (off + 1) & (q_sz - 1);
		used = i;
		last_idx = dev2mem->tail;

		if (is_rd) {
			/* Flush on reaching max SG limit */
			if (!dao_dma_flush(dev2mem, 1))
				goto exit;
		}
	}

exit:
	if (likely(used)) {
		/* If we are here, it means there are no pending mbufs */
		q->pend_sd_mbuf = used;
		q->pend_sd_mbuf_idx = last_idx;
	}

	return sd_mbuf_off;
}

static __rte_always_inline uint16_t
post_process_bufs(struct virtio_blk_queue *q, void **d_bufs, uint16_t nb_bufs, uint16_t *nb_desc,
		  const uint16_t flags)
{
	uintptr_t desc_base = (uintptr_t)q->sd_desc_base;
	uint16_t pend_compl_off = DESC_OFF(q->pend_compl_off), off;
	struct dao_virtio_blk_hdr *buf0, *buf1, *buf2;
	uint16_t q_sz = q->q_sz, segs = 0;
	uint16_t total_desc = *nb_desc;
	int i = 0, num_io_reqs = 0;
	uint64_t dflags;
	void **buf_arr;

	RTE_SET_USED(flags);

	buf_arr = q->extbuf_arr;

	while ((i < total_desc) && (num_io_reqs < nb_bufs)) {
		rte_prefetch0((uint8_t *)buf_arr[pend_compl_off + 1]);
		buf0 = (struct dao_virtio_blk_hdr *)buf_arr[pend_compl_off];

		dflags = (*DESC_PTR_OFF(desc_base, pend_compl_off, 8) >> 48) & VRING_DESC_F_NEXT;

		buf2 = buf1 = buf0;
		off = pend_compl_off;

		/* Calculate additional segments required for buf-chain */
		while (unlikely(dflags)) {
			off = (off + 1) & (q_sz - 1);
			dflags = (*DESC_PTR_OFF(desc_base, off, 8) >> 48) & VRING_DESC_F_NEXT;
			segs++;
		}

		buf0->tot_segs += segs;
		/* Create buf chain from descriptors */
		while (unlikely(segs)) {
			/* Internal bufs can also have chain based on descriptor length vs
			 * buf length variation.
			 */

			while (buf1->desc_data[0])
				buf1 = (struct dao_virtio_blk_hdr *)buf1->desc_data[0];

			pend_compl_off = (pend_compl_off + 1) & (q_sz - 1);
			buf2 = buf_arr[pend_compl_off];
			buf1->desc_data[0] = (uint64_t)buf2;
			buf1 = buf2;
			i++;
			segs--;
			buf0->tot_bufs += buf2->tot_bufs;
		}

		d_bufs[num_io_reqs++] = buf0;
		/** Store/cache the address corresponding to status buffer in
		    first buffer */
		buf0->status = buf2->hdr_data;

		pend_compl_off = (pend_compl_off + 1) & (q_sz - 1);
		i++;
	}
	/* Return consumed descriptor mbufs to update pend_compl_off,
	   And num will hold number of copied mbufs.
	 */
	*nb_desc = i;
	return num_io_reqs;
}

static __rte_always_inline int
virtio_blk_deq(struct virtio_blk_queue *q, void **mbufs, uint16_t nb_bufs,
			const uint16_t flags)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	struct dao_dma_vchan_state *dev2mem, *mem2dev;
	uint16_t dma_vchan = q->dma_vchan;
	uint16_t nb_desc, pend_compl_off;
	uint16_t sd_mbuf_off;
	uint16_t q_sz;
	int rc = 0;

	dev2mem = &vchan_info->dev2mem[dma_vchan];
	mem2dev = &vchan_info->mem2dev[dma_vchan];

	rte_prefetch0(&q->pend_compl_off);
	/* Update completed DMA ops */
	dao_dma_check_meta_compl(dev2mem, 0);
	dao_dma_check_meta_compl(mem2dev, 0);

	/**
	 * Process io completion marking here. This is done here instead of
	 * completion marking API sequence because completion marking APIs
	 * are not called all the time from application. Hence, this is the
	 * right place to implement this.
	 */
	if (q->m2d_pend_sd_mbuf && dao_dma_op_status(mem2dev, q->m2d_pend_sd_mbuf_idx)) {
		uint16_t off = desc_off_add(q->last_off, q->m2d_pend_sd_mbuf, q->q_sz);

		__atomic_store_n(&q->last_off, off, __ATOMIC_RELEASE);
		q->m2d_pend_sd_mbuf = 0;
	}

	/* Check shadow buf status and issue new DMA's for buf's */
	sd_mbuf_off = fetch_host_data(q, dev2mem, 256, flags);
	pend_compl_off = q->pend_compl_off;

	q_sz = q->q_sz;
	/* Check for available mbufs */
	nb_desc = desc_off_diff_no_wrap(sd_mbuf_off, pend_compl_off, q_sz);

	/* Return if no buf's available */
	if (unlikely(!nb_desc || !nb_bufs))
		goto exit;

	rc = post_process_bufs(q, mbufs, nb_bufs, &nb_desc, flags);

	pend_compl_off = desc_off_add(pend_compl_off, nb_desc, q_sz);
	q->pend_compl_off = pend_compl_off;

exit:
	return rc;
}

#define R(name, flags)										\
	uint16_t virtio_blk_deq_##name(void *q, void **mbufs, uint16_t nb_mbufs)	\
	{											\
		return virtio_blk_deq(q, mbufs, nb_mbufs, (flags));				\
	}

VIRTIO_BLK_DEQ_FASTPATH_MODES
#undef R

