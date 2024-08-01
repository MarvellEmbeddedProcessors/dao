/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2024 Marvell.
 */

#include "dao_virtio_netdev.h"
#include "spec/virtio_net.h"
#include "virtio_dev_priv.h"
#include "virtio_net_priv.h"

dao_virtio_net_enq_ext_fn_t dao_virtio_net_enq_ext_fns[VIRTIO_NET_ENQ_OFFLOAD_LAST << 1] = {
#define T(name, flags)[flags] = virtio_net_enq_ext_##name,
	VIRTIO_NET_ENQ_FASTPATH_MODES
#undef T
};

void
virtio_net_flush_enq_ext(struct virtio_net_queue *q)
{
	uint16_t sd_mbuf_off = q->sd_mbuf_off;
	uint16_t last_off = q->last_off;
	uint16_t q_sz = q->q_sz;
	uint16_t pend;

	if (likely(q->auto_free))
		return;

	if (sd_mbuf_off != last_off) {
		pend = desc_off_diff_no_wrap(last_off, sd_mbuf_off, q_sz);
		user_cbs.extbuf_put(q->netdev_id, &q->extbuf_arr[DESC_OFF(sd_mbuf_off)], pend);
		sd_mbuf_off = desc_off_add(sd_mbuf_off, pend, q_sz);
		pend = last_off - sd_mbuf_off;
		if (pend) {
			user_cbs.extbuf_put(q->netdev_id, &q->extbuf_arr[DESC_OFF(sd_mbuf_off)],
					    pend);
			sd_mbuf_off = desc_off_add(sd_mbuf_off, pend, q_sz);
		}
		q->sd_mbuf_off = sd_mbuf_off;
		q->pend_sd_mbuf = 0;
	}
}

static __rte_always_inline void
process_enq_compl(struct virtio_net_queue *q, struct dao_dma_vchan_state *mem2dev,
		  const uint16_t flags)
{
	uint16_t sd_mbuf_off = q->sd_mbuf_off;
	uint16_t last_off = q->last_off;

	RTE_SET_USED(flags);

	/* Check if mbuf DMA is complete */
	if (sd_mbuf_off != last_off && dao_dma_op_status(mem2dev, q->pend_sd_mbuf_idx)) {
		__atomic_store_n(&q->sd_mbuf_off, last_off, __ATOMIC_RELEASE);
		q->pend_sd_mbuf = 0;
	}
}

static __rte_always_inline int
push_enq_ext_data(struct virtio_net_queue *q, struct dao_dma_vchan_state *mem2dev, void **vbufs,
		  uint16_t nb_bufs, const uint16_t flags)
{
	uint64_t *sd_desc_base = q->sd_desc_base;
	uint16_t off = DESC_OFF(q->last_off);
	void **extbuf_arr = q->extbuf_arr;
	struct dao_virtio_net_hdr *dhdr;
	uint16_t used = 0, i = 0;
	uint16_t q_sz = q->q_sz;
	uint64_t d_flags, avail;
	uint32_t len, buf_len;
	uint16_t last_idx = 0;
	int16_t data_off;

	RTE_SET_USED(flags);

	/* Check for minimum space */
	if (!dao_dma_flush(mem2dev, 1))
		goto exit;

	while (i < nb_bufs) {
		dhdr = (struct dao_virtio_net_hdr *)vbufs[i];
		data_off = dhdr->desc_data[0] & 0xFFFF;

		d_flags = *DESC_PTR_OFF(sd_desc_base, off, 8);
		buf_len = d_flags & (RTE_BIT64(32) - 1);

		d_flags = d_flags & 0xFFFFFFFF00000000UL;

		len = (dhdr->desc_data[1] & 0xFFFFFFFF);
		/* Limit length to buf len */
		len = len > buf_len ? buf_len : len;

		avail = !!(d_flags & VIRT_PACKED_RING_DESC_F_AVAIL);
		d_flags &= ~VIRT_PACKED_RING_DESC_F_AVAIL_USED;

		/* Set both AVAIL and USED bit same and fillup length in Tx desc */
		*DESC_PTR_OFF(sd_desc_base, off, 8) =
			avail << 55 | avail << 63 | d_flags | (len & (RTE_BIT64(32) - 1));

		extbuf_arr[off] = (void *)((uintptr_t)dhdr + data_off);

		/* Prepare DMA src/dst of mbuf transfer */
		dao_dma_enq_x1(mem2dev, (uintptr_t)&(dhdr->hdr), len,
			       *DESC_PTR_OFF(sd_desc_base, off, 0), len);
		off = (off + 1) & (q_sz - 1);
		i++;
		used += dhdr->hdr.num_buffers;
		last_idx = mem2dev->tail;
		/* Flush on reaching max SG limit */
		if (!dao_dma_flush(mem2dev, 1))
			goto exit;
	}

exit:
	if (used) {
		/* Update last offset index as per used mbufs */
		off = desc_off_add(q->last_off, used, q_sz);
		q->last_off = off;
		q->pend_sd_mbuf += used;
		q->pend_sd_mbuf_idx = last_idx;
	}
	return i;
}

static __rte_always_inline int
virtio_net_enq_ext(struct virtio_net_queue *q, void **vbufs, uint16_t nb_bufs, const uint16_t flags)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	uint16_t dma_vchan = q->dma_vchan;
	struct dao_dma_vchan_state *mem2dev;
	uint16_t nb_used, sd_desc_off;
	uint16_t count;

	mem2dev = &vchan_info->mem2dev[dma_vchan];

	/* Fetch mem2dev DMA completed status */
	dao_dma_check_compl(mem2dev);

	/* Process enqueue completions */
	process_enq_compl(q, mem2dev, flags);

	/* Send only mbufs as per available descriptors */
	sd_desc_off = __atomic_load_n(&q->sd_desc_off, __ATOMIC_ACQUIRE);
	count = desc_off_diff(sd_desc_off, q->last_off, q->q_sz);
	count = RTE_MIN(count, nb_bufs);
	count = RTE_MIN(count, q->q_sz - q->pend_sd_mbuf);

	/* Return if no Tx descriptors are available */
	if (unlikely(!count))
		return 0;

	/* Validate descriptors */
	VIRTIO_NET_DESC_CHECK(q, q->last_off, count, true, false);

	/* Process mbuf transfer using DMA */
	nb_used = push_enq_ext_data(q, mem2dev, vbufs, count, flags);

	return nb_used;
}

#define T(name, flags)                                                                             \
	uint16_t virtio_net_enq_ext_##name(void *q, void **vbufs, uint16_t nb_bufs)                \
	{                                                                                          \
		return virtio_net_enq_ext(q, vbufs, nb_bufs, (flags));                             \
	}

VIRTIO_NET_ENQ_FASTPATH_MODES
#undef T
