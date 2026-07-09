/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright(C) 2025 Marvell.
 */

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "pts_rdma_dev_priv.h"

#define PTS_RDMA_D2M_MASK                                                                          \
	(1 << DAO_PTS_RDMA_WRITE | 1 << DAO_PTS_RDMA_WRITE_WITH_IMM | 1 << DAO_PTS_RDMA_SEND |     \
	 1 << DAO_PTS_RDMA_SEND_WITH_IMM)

#define PTS_RDMA_M2D_MASK (1 << DAO_PTS_RDMA_READ)

#define PTS_RDMA_SQE_HDR_SZ offsetof(union dao_pts_rdma_sqe, sges0)
#define PTS_RDMA_DATA_OFF   (RTE_PKTMBUF_HEADROOM)

/* Up to 512 batch is supported */
#define DEQ_BULK_MBUF_ALLOC 512U

static __rte_always_inline uint16_t
post_process_data(uint16_t devid, struct pts_rdma_qp_sq *sq, struct rte_mbuf **d_mbufs,
		  uint16_t nb_mbufs, const uint16_t flags)
{
	const uint64_t rearm_data =
		(0x100010000ULL | PTS_RDMA_DATA_OFF | ((uint64_t)(devid + RTE_MAX_ETHPORTS) << 48));
	uintptr_t desc_base = (uintptr_t)sq->sd_desc_base;
	uint32_t sd_mbuf_dma_off = sq->sd_mbuf_dma_off;
	uint32_t q_sz = sq->q_sz;
	struct rte_mbuf **mbuf_arr;
	uint8_t opcode, next_desc;
	uint32_t off, num_sges;
	struct rte_mbuf *mbuf;
	uint64_t d_flags, len;
	void *mbuf_priv;
	int i = 0;

	RTE_SET_USED(flags);
	off = sq->last_off;
	mbuf_arr = sq->mbuf_arr;

	while (i < nb_mbufs) {
		d_flags = *SQ_DESC_PTR_OFF(desc_base, off, 0);
		opcode = d_flags & 0xFF;
		num_sges = (d_flags >> 24) & 0xFF;
		next_desc = num_sges > 2 ? RTE_ALIGN_CEIL(num_sges - 2, 4) / 4 : 0;
		if (unlikely(next_desc)) {
			/* Find the available slots first and check for next desc availability in
			 * the slots */
			if (unlikely(desc_off_diff32(sd_mbuf_dma_off, off, q_sz) <
				     (uint32_t)(next_desc + 1)))
				break;
		}
		mbuf = mbuf_arr[off];
		/* Copy SQE descriptor without SGEs to mbuf */
		mbuf_priv = rte_mbuf_to_priv(mbuf);
		rte_memcpy(mbuf_priv, SQ_DESC_PTR_OFF(desc_base, off, 0), PTS_RDMA_SQE_HDR_SZ);

		if (DAO_BIT(opcode) & PTS_RDMA_M2D_MASK) {
			/* Copy SGEs to mbuf */
			len = sizeof(struct dao_pts_rdma_sge) * num_sges;
			rte_memcpy((uint8_t *)((uintptr_t)mbuf_priv + PTS_RDMA_SQE_HDR_SZ),
				   SQ_DESC_PTR_OFF(desc_base, off, PTS_RDMA_SQE_HDR_SZ), len);
			/* Update mbuf length */
			*((uint64_t *)&mbuf->rearm_data) = rearm_data;
		}

		d_mbufs[i] = mbuf;
		i++;
		off = desc_off_add32(off, next_desc + 1, q_sz);
		if (off == sd_mbuf_dma_off)
			break;
	}

	__atomic_store_n(&sq->last_off, off, __ATOMIC_RELEASE);
	__atomic_store_n(sq->ci_addr, off, __ATOMIC_RELEASE);

	/* Return actual packets processed */
	return i;
}

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

static __rte_always_inline uint32_t
cal_num_dst_mbufs(uint32_t slen, uint32_t buf_len, uint32_t mtu)
{
	uint32_t n_mbufs = 0, mbuf_off = 0;
	uint32_t len = 0, mbuf_space_left = 0;
	uint32_t mtu_limit = mtu;

	while (slen > 0) {
		if (mbuf_off == 0)
			n_mbufs++;
		mbuf_space_left = buf_len - mbuf_off;
		len = RTE_MIN(RTE_MIN(mbuf_space_left, mtu_limit), slen);
		mbuf_off += len;
		mtu_limit -= len;
		slen -= len;
		/* Move to next mbuf if buf_len or MTU boundary is reached */
		if (mbuf_off == buf_len || mtu_limit == 0) {
			mbuf_off = 0;
			if (mtu_limit == 0)
				mtu_limit = mtu;
		}
	}
	return n_mbufs;
}

static __rte_always_inline int16_t
alloc_and_chain_mbufs(struct pts_rdma_qp_sq *sq, struct rte_mbuf *mb, uint32_t n_mbufs,
		      uint64_t rearm_data)
{
	struct rte_mbuf *mbufs[DEQ_BULK_MBUF_ALLOC];
	struct rte_mbuf *last_mbuf = mb;
	uint32_t n_left = n_mbufs - 1;
	uint32_t n_alloc, i;

	while (n_left > 0) {
		n_alloc = RTE_MIN(n_left, DEQ_BULK_MBUF_ALLOC);
		if (unlikely(rte_mempool_get_bulk(sq->mp, (void **)mbufs, n_alloc))) {
			free_mbuf_seg_chain(mb->next);
			mb->next = NULL;
			mb->nb_segs = 1;
			return -1;
		}

		for (i = 0; i < n_alloc; i++) {
			*((uint64_t *)&mbufs[i]->rearm_data) = rearm_data;
			mbufs[i]->ol_flags = 0;
			mbufs[i]->next = NULL;
			mbufs[i]->pkt_len = 0;
			mbufs[i]->data_len = 0;
			last_mbuf->next = mbufs[i];
			last_mbuf = mbufs[i];
		}
		n_left -= n_alloc;
	}
	return 0;
}

static __rte_always_inline int16_t
process_multi_mbuf(uint16_t devid, struct dao_dma_vchan_state *dev2mem, struct pts_rdma_qp_sq *sq,
		   struct rte_mbuf *mbuf, uint16_t off, uint32_t nb_src_segs, uint32_t slen)
{
	const uint64_t rearm_data =
		(0x100010000ULL | PTS_RDMA_DATA_OFF | ((uint64_t)(devid + RTE_MAX_ETHPORTS) << 48));
	uintptr_t desc_base = (uintptr_t)sq->sd_desc_base;
	uint8_t flush_thr = dev2mem->flush_thr;
	uint16_t buf_len, mtu;
	uint32_t max_src_len, max_dst_len, n_sge_idx, n_mbuf_idx;
	uint32_t mtu_limit, to_copy, len;
	uint32_t n_dst_mbufs = 0;
	uint32_t dst_ops = 0;
	uint32_t mbuf_off = 0, mbuf_len_left;
	uint32_t dlen = 0, next_sge = 0;
	struct rte_mbuf *mb = mbuf;
	uint32_t sge_len, sge_offset = 0;
	uint64_t sge_addr;
	uint32_t sge_len_left;

	max_src_len = slen;
	buf_len = sq->buf_len;
	mtu = sq->mtu ? sq->mtu : buf_len;
	mtu_limit = mtu;

	/* Calculate total required mbufs based on MTU requirement */
	n_dst_mbufs = cal_num_dst_mbufs(slen, buf_len, mtu);

	if (alloc_and_chain_mbufs(sq, mbuf, n_dst_mbufs, rearm_data) < 0)
		return -1;

	mbuf->nb_segs = n_dst_mbufs;
	n_sge_idx = 0;
	n_mbuf_idx = 0;

	if (unlikely(!dao_dma_desc_avail_get(dev2mem, nb_src_segs, n_dst_mbufs))) {
		free_mbuf_seg_chain(mbuf->next);
		mbuf->next = NULL;
		mbuf->nb_segs = 1;
		return -1;
	}

	while (n_sge_idx < nb_src_segs && max_src_len > 0) {
		if (unlikely(!dao_dma_flush(dev2mem, flush_thr))) {
			free_mbuf_seg_chain(mbuf->next);
			mbuf->next = NULL;
			mbuf->nb_segs = 1;
			return -1;
		}

		dst_ops = 0;
		max_dst_len = 0;
		while (n_mbuf_idx < n_dst_mbufs && max_src_len > 0 && dst_ops < flush_thr) {
			mbuf_len_left = buf_len - mbuf_off;
			dlen = RTE_MIN(mbuf_len_left, mtu_limit);
			len = RTE_MIN(dlen, max_src_len);

			if (len == 0) {
				if (mbuf_off > 0)
					mb->data_len = mbuf_off;
				n_mbuf_idx++;
				if (n_mbuf_idx < n_dst_mbufs)
					mb = mb->next;
				mbuf_off = 0;
				if (mtu_limit == 0)
					mtu_limit = mtu;
				continue;
			}

			dao_dma_enq_dst_x1(dev2mem, (uintptr_t)mb + sq->data_off + mbuf_off, len);
			mbuf_off += len;
			mtu_limit -= len;
			max_dst_len += len;
			max_src_len -= len;
			dst_ops++;

			if (mbuf_off == buf_len || mtu_limit == 0) {
				mb->data_len = mbuf_off;
				n_mbuf_idx++;
				if (n_mbuf_idx < n_dst_mbufs)
					mb = mb->next;
				mbuf_off = 0;
				if (mtu_limit == 0)
					mtu_limit = mtu;
			}
		}
		if (mbuf_off > 0 && n_mbuf_idx < n_dst_mbufs)
			mb->data_len = mbuf_off;

		to_copy = max_dst_len;
		while (to_copy > 0 && n_sge_idx < nb_src_segs) {
			if (!next_sge) {
				sge_len = *(uint32_t *)SQ_DESC_PTR_OFF(desc_base, off,
								       40 + 16 * n_sge_idx);
				sge_addr = *SQ_DESC_PTR_OFF(desc_base, off, 32 + 16 * n_sge_idx) &
					   PTS_RDMA_DEV_IOVA_MASK;
				next_sge = true;
			}
			sge_len_left = sge_len - sge_offset;
			len = RTE_MIN(sge_len_left, to_copy);
			if (len == 0) {
				n_sge_idx++;
				sge_offset = 0;
				next_sge = 0;
				continue;
			}
			dao_dma_enq_src_x1(dev2mem, sge_addr + sge_offset, len);
			sge_offset += len;
			to_copy -= len;
			if (sge_offset == sge_len) {
				n_sge_idx++;
				sge_offset = 0;
				next_sge = 0;
			}
		}
	}
	return 0;
}

static __rte_always_inline uint16_t
fetch_host_data(uint16_t devid, struct pts_rdma_qp_sq *sq, struct dao_dma_vchan_state *vchan,
		uint16_t hint, const uint16_t flags)
{
	const uint64_t rearm_data =
		(0x100010000ULL | PTS_RDMA_DATA_OFF | ((uint64_t)(devid + RTE_MAX_ETHPORTS) << 48));
	uintptr_t desc_base = (uintptr_t)sq->sd_desc_base;
	struct rte_dma_sge *src = NULL, *dst = NULL;
	uint32_t sd_desc_dma_off, sd_mbuf_off, q_sz;
	uint16_t data_off = sq->data_off;
	uint16_t buf_len = sq->buf_len;
	uint16_t mtu = sq->mtu;
	struct rte_mbuf *mbuf;
	uint32_t used = 0, read_used = 0, num_sges;
	uint32_t nb_mbufs, nb_desc;
	uint32_t i = 0, slen, dlen, len;
	struct rte_mbuf **mbuf_arr;
	uint32_t unused_mbuf_off;
	uint8_t opcode, next_desc;
	uint32_t off, mbuf_off;
	int last_idx = 0;
	uint32_t j;
	uint64_t d_flags;

	RTE_SET_USED(flags);

	q_sz = sq->q_sz;
	sd_mbuf_off = sq->sd_mbuf_off;
	sd_desc_dma_off = __atomic_load_n(&sq->sd_desc_dma_off, __ATOMIC_ACQUIRE);
	nb_mbufs = desc_off_diff32(sd_desc_dma_off, sd_mbuf_off, q_sz);

	/* Return if already something is pending DMA or there are no descriptors to process */
	if (unlikely(!nb_mbufs))
		return 0;

	nb_desc = RTE_MIN(nb_mbufs, hint);
	off = sd_mbuf_off;

	rte_prefetch0(SQ_DESC_PTR_OFF(desc_base, off, 0));
	mbuf_arr = sq->mbuf_arr;

	/* Flush to get minimum space */
	if (!dao_dma_flush(vchan, 1))
		return 0;

	if (!mtu)
		mtu = buf_len;
	i = 0;
	while (i < nb_desc) {
		d_flags = *SQ_DESC_PTR_OFF(desc_base, off, 0);
		opcode = d_flags & 0xFF;
		num_sges = (d_flags >> 24) & 0xFF;
		next_desc = num_sges > 2 ? RTE_ALIGN_CEIL(num_sges - 2, 4) / 4 : 0;
		if (unlikely(next_desc)) {
			/* Find the available slots first and check for next desc availability in
			 * the slots */
			if (unlikely(desc_off_diff32(sd_desc_dma_off, off, q_sz) <
				     (uint32_t)(next_desc + 1)))
				break;
		}
		/* Skip DMA if xfer is from device to host */
		if (DAO_BIT(opcode) & PTS_RDMA_M2D_MASK) {
			i += (next_desc + 1);
			off = (off + next_desc + 1) & (q_sz - 1);
			read_used = i;
			continue;
		}

		src = dao_dma_sge_src(vchan);
		dst = dao_dma_sge_dst(vchan);

		/* Copy source sgs */
		slen = *(uint32_t *)SQ_DESC_PTR_OFF(desc_base, off, 40);
		dlen = slen;
		mbuf = mbuf_arr[off];

		/* Update mbuf length */
		*((uint64_t *)&mbuf->rearm_data) = rearm_data;
		mbuf->pkt_len = slen;
		mbuf->ol_flags = 0;

		if (likely(num_sges == 1 && dlen <= buf_len && dlen <= mtu)) {
			src[0].addr = *SQ_DESC_PTR_OFF(desc_base, off, 32) & PTS_RDMA_DEV_IOVA_MASK;
			src[0].length = slen;
			dst[0].addr = (((uintptr_t)mbuf) + data_off);
			dst[0].length = dlen;

			mbuf->data_len = dlen;
			vchan->src_i++;
			vchan->dst_i++;
		} else {
			for (j = 1; j < num_sges; j++) {
				len = *SQ_DESC_PTR_OFF(desc_base, off, 40 + 16 * j);
				slen += len;
			}
			/* Free the mbuf which was allocated for next_desc > 2 */
			if (next_desc) {
				unused_mbuf_off = (off + 1) & (q_sz - 1);
				rte_pktmbuf_free(mbuf_arr[unused_mbuf_off]);
			}
			mbuf->pkt_len = slen;
			if (process_multi_mbuf(devid, vchan, sq, mbuf, off, num_sges, slen) < 0)
				goto exit;
		}
		i += (next_desc + 1);
		off = (off + next_desc + 1) & (q_sz - 1);
		used = i;
		last_idx = vchan->tail;
		if (!dao_dma_flush(vchan, 1))
			break;
	}

exit:
	if (used) {
		mbuf_off = desc_off_add32(sq->sd_mbuf_off, used, sq->q_sz);
		sq->sd_mbuf_off = mbuf_off;
		dao_dma_update_cmpl_meta_v2(vchan, &sq->sd_mbuf_dma_off, mbuf_off, last_idx);
	}
	if (read_used) {
		mbuf_off = desc_off_add32(sq->sd_mbuf_off, read_used, sq->q_sz);
		sq->sd_mbuf_off = mbuf_off;
		sq->sd_mbuf_dma_off = mbuf_off;
	}
	return 0;
}

static __rte_always_inline uint16_t
fetch_pending_read(struct pts_rdma_qp *qp, uint16_t hint, struct rte_mbuf **mbufs,
		   const uint16_t flags)
{
	uint32_t nb_mbufs_avail, nb_desc, i = 0;
	uint32_t q_sz, mbuf_off, last_off, index = 0;
	struct rte_mbuf **mbuf_arr;

	RTE_SET_USED(flags);
	q_sz = qp->r_q_sz;
	last_off = qp->r_last_off;
	mbuf_off = __atomic_load_n(&qp->r_mbuf_off, __ATOMIC_ACQUIRE);
	nb_mbufs_avail = desc_off_diff32(mbuf_off, last_off, q_sz);

	if (unlikely(!nb_mbufs_avail))
		return 0;

	nb_desc = RTE_MIN(nb_mbufs_avail, hint);
	if (unlikely(!nb_desc))
		return 0;

	mbuf_arr = qp->r_mbuf_arr;

	for (i = 0; i < nb_desc; i++) {
		index = desc_off_add32(last_off, i, q_sz);
		mbufs[i] = mbuf_arr[index];
	}

	last_off = desc_off_add32(last_off, nb_desc, q_sz);
	__atomic_store_n(&qp->r_last_off, last_off, __ATOMIC_RELEASE);

	return nb_desc;
}

static __rte_always_inline int
pts_rdma_dequeue_burst(uint16_t devid, struct pts_rdma_qp *qp, struct rte_mbuf **mbufs,
		       uint16_t nb_mbufs, const uint16_t flags)
{
	uint32_t q_sz, nb_read = 0, nb_deq_pkts = 0, nb_to_process = 0, nb_deq_hint = 0;
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	struct pts_rdma_qp_sq *sq = &qp->sq;
	uint8_t nb_host_pkts, nb_read_pkts;
	uint16_t dma_vchan = sq->dma_vchan;
	struct dao_dma_vchan_state *vchan;
	uint32_t nb_avail, last_off;
	uint32_t sd_mbuf_dma_off;
	uint16_t nb_read_hint;

	vchan = &vchan_info->dev2mem[dma_vchan];

	rte_prefetch0(&sq->last_off);
	/* Update completed DMA ops */
	dao_dma_check_meta_compl_v2(vchan, 0 /* No ATOMIC update */);

	nb_host_pkts = nb_mbufs & 0xFF;
	nb_read_pkts = (nb_mbufs >> 8) & 0xFF;

	nb_read_hint = nb_read_pkts;
	nb_read = fetch_pending_read(qp, nb_read_hint, mbufs, flags);

	nb_deq_hint = nb_host_pkts;
	fetch_host_data(devid, sq, vchan, nb_deq_hint, flags);
	sd_mbuf_dma_off = sq->sd_mbuf_dma_off;
	last_off = sq->last_off;

	q_sz = sq->q_sz;
	nb_avail = desc_off_diff32(sd_mbuf_dma_off, last_off, q_sz);
	nb_to_process = RTE_MIN(nb_deq_hint, nb_avail);

	if (unlikely(nb_to_process == 0))
		goto exit;

	nb_deq_pkts = post_process_data(devid, sq, mbufs + nb_read, nb_to_process, flags);
exit:
	return nb_read + nb_deq_pkts;
}

uint16_t
dao_pts_rdma_dequeue_burst(uint16_t devid, uint16_t qp_id, struct rte_mbuf **mbufs,
			   uint16_t nb_mbufs)
{
	struct pts_rdma_qp *qp = dao_pts_rdma_devs[devid].qps[qp_id];

	if (unlikely(!qp)) {
		dao_err("Invalid QP %u", qp_id);
		return 0;
	}

	return pts_rdma_dequeue_burst(devid, qp, mbufs, nb_mbufs, 0);
}
