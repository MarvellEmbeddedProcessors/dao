/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell.
 */

#include <dao_assert.h>

#include "dao_virtio_blkdev.h"
#include "virtio_dev_priv.h"
#include "spec/virtio_blk.h"
#include "virtio_blk_priv.h"
#include "virtio_blk_trace.h"

dao_virtio_blk_process_compl_fn_t dao_virtio_blk_process_compl_fns[VIRTIO_BLK_COMPL_LAST << 1] = {
#define T(name, flags)[flags] = virtio_blk_process_compl_##name,
	VIRTIO_BLK_COMPL_FASTPATH_MODES
#undef T
};

static __rte_always_inline int
push_compl_data(struct virtio_blk_queue *q, struct dao_dma_vchan_state *mem2dev, void **vbufs,
		uint16_t nb_bufs, const uint16_t flags)
{
	struct dao_virtio_blk_hdr *hdr, *next_hdr;
	uint64_t *sd_desc_base = q->sd_desc_base;
	uint16_t off = DESC_OFF(q->last_off);
	uint16_t off_mask = q->q_sz - 1;
	uint16_t used = 0, i = 0;
	uint16_t used_wrap_bit;
	uint16_t last_idx = 0;
	uint32_t n_segs;
	uint64_t is_wr;

	RTE_SET_USED(flags);
	used_wrap_bit = (q->last_off >> 15) & 0x1;

	while (i < nb_bufs) {
		hdr = (struct dao_virtio_blk_hdr *)vbufs[i];
		n_segs = hdr->tot_segs;

#ifdef VIRTIO_BLK_DEBUG
		/* Block request header should be the first in the chain. */
		DAO_ASSERT_FATAL(hdr->cur_len == q->virtio_hdr_sz,
				 "Invalid header length %u at %s:%d", hdr->cur_len, __func__,
				 __LINE__);

		/* assert for inorder case */
		if (!(flags & VIRTIO_BLK_COMPL_NOINOR))
			DAO_ASSERT_FATAL(vbufs[i] == q->mbuf_arr[off],
					 "detected out-of-order completion processing at %s:%d",
					 __func__, __LINE__);

		virtio_blk_trace_io_req_compl(q->blkdev_id, q->qid, off | (used_wrap_bit << 15),
					      hdr->vio_desc.id, ((uint32_t *)hdr->hdr_data)[0],
					      *hdr->status);
#endif
		/* Make room to enqueue in worst possible case. */
		if (unlikely(!dao_dma_flush(mem2dev, n_segs - 1)))
			goto exit;

		/* Prepare the used descriptor */
		hdr->vio_desc.flags = used_wrap_bit << 15 | used_wrap_bit << 7;
		hdr->vio_desc.len = hdr->write_buf_len;
		rte_compiler_barrier();
		*DESC_PTR_OFF(sd_desc_base, off, 8) = hdr->desc_data[1];
		used_wrap_bit ^= (off + n_segs >= q->q_sz);

		while (n_segs-- > 0) {
			next_hdr = hdr->next;
			is_wr = !!(hdr->vio_desc.flags & VRING_DESC_F_WRITE);
			if (is_wr) {
#ifdef VIRTIO_BLK_DEBUG
				DAO_ASSERT_FATAL(hdr->cur_len <= hdr->vio_desc.len,
						 "DMA slen > dlen");
#endif
				dao_dma_enq_x1(mem2dev, (uintptr_t)&(hdr->hdr_data), hdr->cur_len,
					       hdr->desc_data[0], hdr->cur_len);
			} else {
				/* auto free applies only to DPI HW submissions. */
				if (likely(q->auto_free))
					rte_mempool_put(q->mp, hdr);
			}
			off = (off + 1) & off_mask;
			used++;
			hdr = next_hdr;
		}
		i++;
		last_idx = mem2dev->tail;
	}

exit:
	if (used) {
		q->m2d_pend_sd_mbuf = used;
		q->m2d_pend_sd_mbuf_idx = last_idx;
	}
	return i;
}

static __rte_always_inline int
virtio_blk_process_compl(struct virtio_blk_queue *q, void **vbufs, uint16_t nb_bufs,
			 const uint16_t flags)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	uint16_t dma_vchan = q->dma_vchan;
	struct dao_dma_vchan_state *mem2dev;
	uint16_t nb_compl;

	mem2dev = &vchan_info->mem2dev[dma_vchan];

	/* Fetch mem2dev DMA completed status */
	dao_dma_check_meta_compl(mem2dev, 0);
	if (q->m2d_pend_sd_mbuf && dao_dma_op_status(mem2dev, q->m2d_pend_sd_mbuf_idx)) {
		uint16_t off = desc_off_add(q->last_off, q->m2d_pend_sd_mbuf, q->q_sz);

		__atomic_store_n(&q->last_off, off, __ATOMIC_RELEASE);
		q->m2d_pend_sd_mbuf = 0;
	}

	/* If there are any pending mbufs, return */
	if (q->m2d_pend_sd_mbuf || !nb_bufs)
		return 0;

	/* Process mbuf transfer using DMA */
	nb_compl = push_compl_data(q, mem2dev, vbufs, nb_bufs, flags);

	return nb_compl;
}

#define T(name, flags)										\
	uint16_t virtio_blk_process_compl_##name(void *q, void **mbufs, uint16_t nb_compl)	\
	{                                                                                       \
		return virtio_blk_process_compl(q, mbufs, nb_compl, (flags));			\
	}

VIRTIO_BLK_COMPL_FASTPATH_MODES
#undef T
