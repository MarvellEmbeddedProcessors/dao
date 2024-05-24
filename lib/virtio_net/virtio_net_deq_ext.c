/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2024 Marvell.
 */

#include <rte_vect.h>

#include "dao_virtio_netdev.h"
#include "spec/virtio_net.h"
#include "virtio_dev_priv.h"
#include "virtio_net_priv.h"

dao_virtio_net_deq_ext_fn_t dao_virtio_net_deq_ext_fns[VIRTIO_NET_DEQ_OFFLOAD_LAST << 1] = {
#define R(name, flags)[flags] = virtio_net_deq_ext_##name,
	VIRTIO_NET_DEQ_FASTPATH_MODES
#undef R
};

void
virtio_net_flush_deq_ext(struct virtio_net_queue *q)
{
	uint16_t pend_sd_mbuf = q->pend_sd_mbuf, sd_desc_off, sd_mbuf_off = q->sd_mbuf_off;
	uint16_t last_off = q->last_off, q_sz = q->q_sz;
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
	/* Return if no buf's available */
	if (unlikely(!nb_avail))
		return;

	user_cbs.extbuf_put(q->netdev_id, &q->extbuf_arr[DESC_OFF(last_off)], nb_avail);
	last_off = desc_off_add(last_off, nb_avail, q_sz);
	nb_avail = sd_mbuf_off - last_off;
	if (nb_avail)
		user_cbs.extbuf_put(q->netdev_id, &q->extbuf_arr[DESC_OFF(last_off)], nb_avail);
}

static __rte_always_inline uint16_t
fetch_host_data(struct virtio_net_queue *q, struct dao_dma_vchan_state *dev2mem, uint16_t hint,
		const uint16_t flags)
{
	uintptr_t desc_base = (uintptr_t)q->sd_desc_base;
	struct rte_dma_sge *src = NULL, *dst = NULL;
	uint16_t pend_sd_mbuf = q->pend_sd_mbuf;
	struct dao_virtio_net_hdr *buf, *n_buf;
	uint32_t i = 0, slen, dlen, pend = 0;
	uint16_t sd_desc_off, sd_mbuf_off;
	uint16_t buf_len = q->buf_len;
	uint64_t d_flags, avail;
	uint16_t q_sz = q->q_sz;
	uint16_t used = 0, off;
	void **extbuf_arr;
	uint32_t nb_bufs;
	int last_idx = 0;

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
	nb_bufs = RTE_MIN(nb_bufs, hint);

	off = DESC_OFF(sd_mbuf_off);
	rte_prefetch0(DESC_PTR_OFF(desc_base, off, 0));
	extbuf_arr = q->extbuf_arr;

	/* Flush to get minimum space */
	if (!dao_dma_flush(dev2mem, 1))
		return sd_mbuf_off;

	/* Start DMA of buf data */
	while (i < nb_bufs) {
		buf = (struct dao_virtio_net_hdr *)extbuf_arr[off];

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

		src = dao_dma_sge_src(dev2mem);
		dst = dao_dma_sge_dst(dev2mem);
		src[0].addr = *DESC_PTR_OFF(desc_base, off, 0);
		src[0].length = slen;
		dst[0].addr = (uintptr_t)&(buf->hdr);
		dst[0].length = dlen;

		/* update buffer length */
		buf->desc_data[0] = 0x0;
		buf->desc_data[1] = dlen | (d_flags & 0xFFFF000000000000);

		while (unlikely(pend)) {
			user_cbs.extbuf_get(q->netdev_id, (void **)&n_buf, 1);
			dlen = pend;
			if (unlikely(dlen > buf_len))
				dlen = buf_len;
			n_buf->desc_data[0] = 0x0;
			n_buf->desc_data[1] = dlen;
			buf->desc_data[0] = (uintptr_t)n_buf;
			/* Enqueue only destination pointers as source length is big */
			dao_dma_enq_dst_x1(dev2mem, (uintptr_t)&(n_buf->hdr), dlen);
			pend -= dlen;
			buf = n_buf;
		}

		dev2mem->src_i++;
		dev2mem->dst_i++;
		i++;
		off = (off + 1) & (q_sz - 1);
		used = i;
		last_idx = dev2mem->tail;
		/* Flush on reaching max SG limit */
		if (!dao_dma_flush(dev2mem, 1))
			goto exit;
	}

exit:
	if (likely(used)) {
		/* If we are here, it means there are no pending mbufs */
		q->pend_sd_mbuf = used;
		q->pend_sd_mbuf_idx = last_idx;
	}

	return sd_mbuf_off;
}

static __rte_always_inline int
virtio_net_deq_ext(struct virtio_net_queue *q, void **vbufs, uint16_t nb_bufs, const uint16_t flags)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	struct dao_dma_vchan_state *dev2mem;
	uint16_t dma_vchan = q->dma_vchan;
	uint16_t nb_avail, last_off;
	uint16_t sd_mbuf_off;
	uint16_t q_sz;
	int rc = 0;

	dev2mem = &vchan_info->dev2mem[dma_vchan];

	rte_prefetch0(&q->last_off);
	/* Update completed DMA ops */
	dao_dma_check_compl(dev2mem);

	/* Check shadow buf status and issue new DMA's for buf's */
	sd_mbuf_off = fetch_host_data(q, dev2mem, 128, flags);
	last_off = q->last_off;

	q_sz = q->q_sz;
	/* Check for available mbufs */
	nb_avail = desc_off_diff_no_wrap(sd_mbuf_off, last_off, q_sz);

	/* Return if no buf's available */
	if (unlikely(!nb_avail))
		goto exit;

	nb_bufs = RTE_MIN(nb_bufs, nb_avail);

	/* Memcpy DMA'ed buf pointers */
	memcpy(vbufs, &q->extbuf_arr[DESC_OFF(last_off)], nb_bufs << 3);

	last_off = desc_off_add(last_off, nb_bufs, q_sz);
	__atomic_store_n(&q->last_off, last_off, __ATOMIC_RELEASE);

	rc = nb_bufs;
exit:
	return rc;
}

#define R(name, flags)                                                                             \
	uint16_t virtio_net_deq_ext_##name(void *q, void **vbufs, uint16_t nb_bufs)                \
	{                                                                                          \
		return virtio_net_deq_ext(q, vbufs, nb_bufs, (flags));                             \
	}

VIRTIO_NET_DEQ_FASTPATH_MODES
#undef R
