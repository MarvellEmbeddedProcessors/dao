/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright(C) 2025 Marvell.
 */
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "pts_rdma_dev_priv.h"

static inline int
pts_rdma_enqueue_cqe(struct pts_rdma_cq_data *cq_data, struct dao_pts_rdma_cqe *cqe,
		     uint16_t nb_cqes, const bool skip_compl)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	uint16_t dma_vchan = cq_data->dma_vchan;
	struct dao_dma_vchan_state *vchan = &vchan_info->mem2dev[dma_vchan];
	void *ring_base = cq_data->ring_base;
	uint16_t q_sz = cq_data->q_sz;
	uint16_t i = 0, avail, tail;
	uint16_t pi_data, ci;
	uint16_t meta_index;

	ci = __atomic_load_n(&cq_data->ci, __ATOMIC_ACQUIRE);
	pi_data = __atomic_load_n(&cq_data->pi_data, __ATOMIC_RELAXED);
	avail = q_sz - desc_off_diff(pi_data, ci, q_sz) - 1;

	nb_cqes = RTE_MIN(nb_cqes, avail);
	if (unlikely(!nb_cqes))
		return 0;

	tail = vchan->tail;
	if (!skip_compl && tail != vchan->head) {
		meta_index = vchan->mdata[(tail - 1) % DAO_DMA_MAX_INFLIGHT_MDATA].cnt;
		if ((unlikely(meta_index >= 1024)))
			return 0;
	}

	for (i = 0; i < nb_cqes; i++) {
		rte_memcpy(CQ_DESC_PTR_OFF(ring_base, pi_data, 0), &cqe[i],
			   sizeof(struct dao_pts_rdma_cqe));
		pi_data = (pi_data + 1) & (q_sz - 1);
	}

	cq_data->pi_data = pi_data;
	if (skip_compl)
		return nb_cqes;

	/* Post completion in order after existing DMA's from this vchan */
	if (tail != vchan->head)
		dao_dma_update_cmpl_meta_v2(vchan, &cq_data->pi, pi_data, tail - 1);
	else
		__atomic_store_n(&cq_data->pi, pi_data, __ATOMIC_RELEASE);

	return nb_cqes;
}

int
dao_pts_rdma_enqueue_cqe(uint16_t devid, uint16_t qp_id, bool recv, struct dao_pts_rdma_cqe *cqe,
			 uint16_t nb_cqes)
{
	struct pts_rdma_qp *qp = dao_pts_rdma_devs[devid].qps[qp_id];
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	struct pts_rdma_cq_data *cq_data;
	struct dao_dma_vchan_state *vchan;

	if (unlikely(!qp))
		return -EINVAL;

	cq_data = recv ? &qp->rq.cq_data : &qp->sq.cq_data;
	vchan = &vchan_info->mem2dev[cq_data->dma_vchan];

	/* Poll for completions to make space since there are independent CQE's */
	dao_dma_check_meta_compl_v2(vchan, 1 /* ATOMIC update */);

	return pts_rdma_enqueue_cqe(cq_data, cqe, nb_cqes, false);
}

static __rte_always_inline uint32_t
calcualte_nb_enq_sges(uintptr_t desc_base, uint16_t ci, uint32_t dlen)
{
	uint16_t nb_sges, i;
	uint64_t w0, sge_len;
	uint32_t slen = 0;

	w0 = *RQ_DESC_PTR_OFF(desc_base, ci, 0);
	nb_sges = (w0 >> 48) & 0xFFFF;
	nb_sges = RTE_MIN(nb_sges, DAO_PTS_RDMA_MAX_SGES);

	for (i = 0; i < nb_sges; i++) {
		sge_len = *RQ_DESC_PTR_OFF(desc_base, ci, 24 + 16 * i) & 0xFFFFFFFF;
		slen += sge_len;

		if (slen >= dlen)
			return i + 1;
	}
	return UINT16_MAX;
}

static __rte_always_inline int
process_and_enq_mbuf_desc(struct dao_dma_vchan_state *mem2dev, uintptr_t desc_base, uint16_t ci,
			  struct rte_mbuf *mbuf)
{
	uint64_t slen, dst_ptr, dst_len;
	uint32_t nb_enq_sges, dlen;

	slen = mbuf->pkt_len;
	nb_enq_sges = calcualte_nb_enq_sges(desc_base, ci, slen);
	if (nb_enq_sges == UINT16_MAX)
		return -1;

	if (likely(nb_enq_sges == 1 && mbuf->nb_segs == 1)) {
		dst_ptr = *RQ_DESC_PTR_OFF(desc_base, ci, 16);
		dst_len = *RQ_DESC_PTR_OFF(desc_base, ci, 24) & 0xFFFFFFFF;
		dlen = slen > dst_len ? dst_len : slen;
		dao_dma_enq_dst_x1(mem2dev, dst_ptr & PTS_RDMA_DEV_IOVA_MASK, dlen);
		dao_dma_enq_src_x1(mem2dev, (uintptr_t)rte_pktmbuf_mtod(mbuf, uint64_t *), dlen);
		mbuf->next = NULL;
		mbuf->nb_segs = 1;
		return 0;
	}
	return -1;
}

static __rte_always_inline int
process_m2d_rqe_with_cqe(struct pts_rdma_qp *qp, struct dao_dma_vchan_state *mem2dev,
			 struct rte_mbuf *mbuf)
{
	struct pts_rdma_qp_rq *rq = &qp->rq;
	uintptr_t desc_base = (uintptr_t)rq->sd_desc_base;
	struct pts_rdma_cq_data *cq_data;
	struct dao_pts_rdma_cqe *cqe;
	uint16_t ci, pi, q_sz;

	cq_data = &qp->rq.cq_data;
	ci = rq->sd_mbuf_off;
	pi = __atomic_load_n(&rq->sd_desc_dma_off, __ATOMIC_ACQUIRE);
	q_sz = rq->q_sz;

	/* Check for space in RQ */
	if (unlikely(desc_off_diff(pi, ci, q_sz) < 1))
		return -1;

	/* Check for space in CQ */
	if (unlikely(is_queue_full(cq_data->pi_data, cq_data->ci)))
		return -1;

	if (unlikely(process_and_enq_mbuf_desc(mem2dev, desc_base, ci, mbuf)))
		return -1;

#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
	/* All the buffers would be freed to NPA by DPI.
	 * Mark them as put since SW did not free them
	 */
	RTE_MEMPOOL_CHECK_COOKIES(mbuf->pool, (void **)&mbuf, 1, 0);
#endif
	ci = (ci + 1) & (q_sz - 1);
	/* Get CQE and update wr_id */
	cqe = DAO_PTS_RDMA_MBUF_TO_CQE(mbuf);
	cqe->wr_id = *RQ_DESC_PTR_OFF(desc_base, ci, 8);

	/* Push CQE at last */
	pts_rdma_enqueue_cqe(&qp->rq.cq_data, cqe, 1, true);
	rq->sd_mbuf_off = ci;

	return 0;
}

static __rte_always_inline int
push_enq_buffers(uint16_t devid, struct pts_rdma_qp *qp, struct rte_mbuf **mbufs, uint16_t nb_mbufs,
		 const uint16_t flags)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	uint16_t i = 0, nb_cqe = 0;
	struct pts_rdma_qp_rq *rq = &qp->rq;
	struct dao_dma_vchan_state *mem2dev;
	struct dao_dma_vchan_state *dev2mem;
	uint16_t dma_vchan = rq->dma_vchan;
	uint16_t last_idx = 0;
	struct rte_mbuf *mbuf = NULL;
	uint64_t ol_flags = 0;
	uint8_t type;
	int ret = 0;

	RTE_SET_USED(devid);
	RTE_SET_USED(flags);

	dev2mem = &vchan_info->dev2mem[dma_vchan];
	mem2dev = &vchan_info->mem2dev[dma_vchan];
	/* Check for minimum space */
	if (!dao_dma_flush(mem2dev, 1) || !dao_dma_flush(dev2mem, 1))
		goto exit;

	while (i < nb_mbufs) {
		mbuf = mbufs[i];
		ol_flags = mbuf->ol_flags;
		type = ol_flags >> 60;
		mbuf->ol_flags &= ~(0xFULL << 60);
		if (type == DAO_PTS_RDMA_ENQ_M2D_RQE_WITH_CQE) {
			ret = process_m2d_rqe_with_cqe(qp, mem2dev, mbuf);
			if (ret)
				goto exit;
			nb_cqe++;
		}
		i++;
		last_idx = mem2dev->tail;
		/* Flush on reaching max SG limit */
		if (!dao_dma_flush(mem2dev, 1) || !dao_dma_flush(dev2mem, 1))
			goto exit;
	}
exit:
	/* Update consumer index for RQ */
	__atomic_store_n(rq->ci_addr, rq->sd_mbuf_off, __ATOMIC_RELAXED);

	/* Update producer index for CQ data as a completion */
	if (nb_cqe)
		dao_dma_update_cmpl_meta_v2(mem2dev, &qp->rq.cq_data.pi, qp->rq.cq_data.pi_data,
					    last_idx);

	return i;
}

static __rte_always_inline int
pts_rdma_enq_burst(uint16_t devid, struct pts_rdma_qp *qp, struct rte_mbuf **mbufs,
		   uint16_t nb_mbufs)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	struct pts_rdma_qp_rq *rq = &qp->rq;
	uint16_t dma_vchan = rq->dma_vchan;
	struct dao_dma_vchan_state *vchan;
	uint16_t nb_used = 0, count;
	const uint16_t flags = 0;

	RTE_SET_USED(devid);

	/* Fetch mem2dev DMA completed status */
	vchan = &vchan_info->mem2dev[dma_vchan];
	dao_dma_check_meta_compl_v2(vchan, 1 /* ATOMIC update */);

	/* Fetch dev2mem DMA completed status */
	vchan = &vchan_info->dev2mem[dma_vchan];
	dao_dma_check_meta_compl_v2(vchan, 1 /* ATOMIC update */);

	/* Copy receive entries based on available space
	 * including in-flight dma ops.
	 * TODO: Cannot check the RQ space since we get mixed requests?
	 */
	count = nb_mbufs;

	if (unlikely(!count))
		return 0;

	nb_used = push_enq_buffers(devid, qp, mbufs, count, flags);

	return nb_used;
}

int
dao_pts_rdma_enqueue_burst(uint16_t devid, uint16_t qp_id, struct rte_mbuf **mbufs,
			   uint16_t nb_mbufs)
{
	struct pts_rdma_qp *qp = dao_pts_rdma_devs[devid].qps[qp_id];

	if (unlikely(!qp))
		return -EINVAL;

	return pts_rdma_enq_burst(devid, qp, mbufs, nb_mbufs);
}
