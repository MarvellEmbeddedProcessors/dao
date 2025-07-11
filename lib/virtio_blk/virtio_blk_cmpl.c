/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell.
 */

#include <dao_assert.h>
#include "dao_virtio_blkdev.h"
#include "virtio_dev_priv.h"
#include "spec/virtio_blk.h"
#include "virtio_blk_priv.h"

dao_virtio_blk_process_compl_fn_t dao_virtio_blk_process_compl_fns[VIRTIO_BLK_COMPL_LAST << 1] = {
#define T(name, flags)[flags] = virtio_blk_process_compl_##name,
	VIRTIO_BLK_COMPL_FASTPATH_MODES
#undef T
};

static __rte_always_inline int
push_compl_data(struct virtio_blk_queue *q, struct dao_dma_vchan_state *mem2dev,
		void **vbufs, uint16_t nb_bufs, const uint16_t flags)
{
	uint64_t *sd_desc_base = q->sd_desc_base;
	uint16_t off = DESC_OFF(q->last_off);
	uint32_t buf_len, cur_len, n_segs;
	void **mbuf_arr = q->mbuf_arr;
	struct dao_virtio_blk_hdr *hdr;
	uint16_t used = 0, i = 0;
	uint16_t q_sz = q->q_sz;
	uint16_t last_idx = 0;
	uint64_t d_flags, avail;
	uint64_t is_wr = 0;

	RTE_SET_USED(flags);

	while (i < nb_bufs) {
		hdr = (struct dao_virtio_blk_hdr *)vbufs[i];

		n_segs = hdr->tot_segs;
		/* Make room to enqueue in worst possible case. Block request
		   header is always read-only, so worst case would be a read
		   request with n_segs-1 descriptors following the block
		   header. */
		if (!dao_dma_flush(mem2dev, n_segs - 1))
			goto exit;

		while (n_segs-- > 0) {
			cur_len = (hdr->desc_data[1] & 0xFFFFFFFF);

			d_flags = *DESC_PTR_OFF(sd_desc_base, off, 8);
			buf_len = d_flags & (RTE_BIT64(32) - 1);
			d_flags = d_flags & 0xFFFFFFFF00000000UL;

			/* The configuration should support each VIO BLock
			   segment fits in single DMA buffer */
			DAO_ASSERT_FATAL(cur_len == buf_len, "desc seg len must be equal to local dma seg buflen");

			avail = !!(d_flags & VIRT_PACKED_RING_DESC_F_AVAIL);
			d_flags &= ~VIRT_PACKED_RING_DESC_F_AVAIL_USED;
			/* write-only(blk read reqs) buffer. hence can be written by the device */
			is_wr = !!(d_flags & ((unsigned long)VRING_DESC_F_WRITE << 48));

			/* Set both AVAIL and USED bit same and fillup length in Tx desc */
			*DESC_PTR_OFF(sd_desc_base, off, 8) = (avail << 55 | avail << 63 | d_flags
							      | (cur_len & (RTE_BIT64(32) - 1)));

			mbuf_arr[off] = (void *)((uintptr_t)hdr);

			/* Prepare DMA src/dst of mbuf transfer */
			if (is_wr) {
				dao_dma_enq_x1(mem2dev, (uintptr_t)&(hdr->hdr_data), cur_len,
					       *DESC_PTR_OFF(sd_desc_base, off, 0), cur_len);
			} else {
				/*
				 * Auto free happens only for buffers submitted
				 * to DPI HW, so do explicit SW free.
				 */
				if (likely(q->auto_free))
					rte_mempool_put(q->mp, mbuf_arr[off]);
			}

			off = (off + 1) & (q_sz - 1);
			used++;
			hdr = (struct dao_virtio_blk_hdr *)hdr->desc_data[0];
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
