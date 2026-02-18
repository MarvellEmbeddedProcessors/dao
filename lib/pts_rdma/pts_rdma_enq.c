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
		if ((unlikely(meta_index >= DAO_DMA_MAX_META_POINTER)))
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

	cqe->ibqp = qp->ibqp;
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

static __rte_always_inline bool
validate_sge_len(const struct dao_pts_rdma_sge *sges, uint16_t nb_sge, uint32_t pkt_len)
{
	uint32_t sge_sum = 0;
	uint16_t i;

	for (i = 0; i < nb_sge; i++) {
		sge_sum += sges[i].length;
		if (sge_sum >= pkt_len)
			return true;
	}
	return false;
}

static __rte_always_inline int
read_response_process_multi_mbuf(struct dao_dma_vchan_state *mem2dev, struct rte_mbuf *mbuf,
				 uint32_t nb_enq_sges, uint32_t nb_mbuf_segs)
{
	uint32_t n_mbufs_left = nb_mbuf_segs, sge_idx = 0, n_src_mbufs, n_dst_sges;
	uint64_t max_dst_len, max_src_len, dst_ptr, dst_len, avail, len;
	uint64_t src_offset = 0, dst_offset = 0, sge_total, i;
	uint8_t flush_thr = mem2dev->flush_thr;
	struct rte_mbuf *m = mbuf, *mbuf_next;
	struct dao_pts_rdma_sge *sges;

	sges = DAO_PTS_RDMA_MBUF_TO_SGES(mbuf);
	while (n_mbufs_left > 0 && sge_idx < nb_enq_sges) {
		if (unlikely(!m || !dao_dma_flush(mem2dev, flush_thr)))
			return -1;

		/* max enqueue length can be copied in this DMA instruction */
		max_dst_len = 0;
		for (i = 0; i < flush_thr && sge_idx + i < nb_enq_sges; i++) {
			sge_total = (i == 0) ? (sges[sge_idx + i].length - dst_offset) :
					       sges[sge_idx + i].length;
			max_dst_len += sge_total;
		}

		max_src_len = 0;
		n_src_mbufs = 0;
		while (n_src_mbufs < flush_thr && max_src_len < max_dst_len) {
			if (n_mbufs_left == 0 || !m)
				break;
			avail = m->data_len - src_offset;
			len = RTE_MIN(avail, max_dst_len - max_src_len);
			/* Single MBUF might split across DMA instructions based on src_offset  */
			dao_dma_enq_src_x1(mem2dev,
					   (uintptr_t)rte_pktmbuf_mtod(m, uint64_t *) + src_offset,
					   len);
			src_offset += len;
			max_src_len += len;
			n_src_mbufs++;
			/* Move to next mbuf */
			if (src_offset >= m->data_len) {
				mbuf_next = m->next;
				m->next = NULL;
				m->nb_segs = 1;
				m = mbuf_next;
				src_offset = 0;
				n_mbufs_left--;
			}
		}
		n_dst_sges = 0;
		while (max_src_len > 0 && n_dst_sges < flush_thr) {
			if (sge_idx >= nb_enq_sges)
				break;
			dst_ptr = sges[sge_idx].addr;
			dst_len = sges[sge_idx].length;
			avail = dst_len - dst_offset;
			len = RTE_MIN(max_src_len, avail);
			/* Single sge split across DMA instructions based on dst_offset  */
			dao_dma_enq_dst_x1(mem2dev, (dst_ptr + dst_offset) & PTS_RDMA_DEV_IOVA_MASK,
					   len);
			dst_offset += len;
			max_src_len -= len;
			n_dst_sges++;
			if (dst_offset >= dst_len) {
				sge_idx++;
				dst_offset = 0;
			}
		}
	}
	return 0;
}

static __rte_always_inline int
read_response_process_multi_sge(struct dao_dma_vchan_state *mem2dev, struct rte_mbuf *mbuf,
				uint32_t nb_dst_sges, uint32_t nb_mbuf_segs)
{
	uint64_t max_src_len, max_dst_len, off, avail, dst_len, dst_addr;
	uint32_t dst_sge_index = 0, n_src_mbufs, n_dst_sges;
	uint64_t src_offset = 0, dst_offset = 0, tot_len = mbuf->pkt_len;
	struct rte_mbuf *m = mbuf, *mbuf_next, *mbuf2;
	uint8_t flush_thr = mem2dev->flush_thr;
	struct dao_pts_rdma_sge *sges;

	RTE_SET_USED(nb_mbuf_segs);
	sges = DAO_PTS_RDMA_MBUF_TO_SGES(mbuf);
	while (likely(dst_sge_index < nb_dst_sges && tot_len > 0)) {
		if (unlikely(!m || !dao_dma_flush(mem2dev, flush_thr)))
			return -1;

		max_src_len = 0;
		n_src_mbufs = 0;
		mbuf2 = m;
		off = src_offset;
		while (n_src_mbufs < flush_thr && max_src_len < tot_len) {
			if (!mbuf2)
				break;
			avail = mbuf2->data_len - off;
			dst_len = RTE_MIN(tot_len - max_src_len, avail);
			max_src_len += dst_len;
			n_src_mbufs++;
			/* mbuf split b/w DMA instrctions */
			if (off + dst_len >= mbuf2->data_len) {
				mbuf2 = mbuf2->next;
				off = 0;
			} else {
				off += dst_len;
			}
		}
		max_dst_len = 0;
		n_dst_sges = 0;
		while (n_dst_sges < flush_thr && max_dst_len < max_src_len) {
			if (dst_sge_index >= nb_dst_sges)
				break;
			dst_addr = sges[dst_sge_index].addr;
			dst_len = sges[dst_sge_index].length;
			avail = dst_len - dst_offset;
			if (max_dst_len + avail > max_src_len) {
				dst_len = max_src_len - max_dst_len;
				dao_dma_enq_dst_x1(mem2dev,
						   (dst_addr + dst_offset) & PTS_RDMA_DEV_IOVA_MASK,
						   dst_len);
				dst_offset += dst_len;
				max_dst_len += dst_len;
				break;
			}
			dao_dma_enq_dst_x1(mem2dev,
					   (dst_addr + dst_offset) & PTS_RDMA_DEV_IOVA_MASK, avail);
			max_dst_len += avail;
			n_dst_sges++;
			dst_sge_index++;
			dst_offset = 0;
		}
		n_src_mbufs = 0;
		while (max_dst_len > 0 && n_src_mbufs < flush_thr) {
			if (!m)
				break;
			avail = m->data_len - src_offset;
			dst_len = RTE_MIN(max_dst_len, avail);
			dao_dma_enq_src_x1(mem2dev,
					   (uintptr_t)rte_pktmbuf_mtod(m, uint64_t *) + src_offset,
					   dst_len);
			src_offset += dst_len;
			max_dst_len -= dst_len;
			tot_len -= dst_len;
			n_src_mbufs++;
			/* Move to next mbuf */
			if (src_offset >= m->data_len) {
				mbuf_next = m->next;
				m->next = NULL;
				m->nb_segs = 1;
				m = mbuf_next;
				src_offset = 0;
			}
		}
	}
	return 0;
}

static __rte_always_inline int32_t
read_resp_enqueue(struct dao_dma_vchan_state *mem2dev, struct rte_mbuf *mbuf,
		  struct dao_pts_rdma_sge *sges)
{
	uint32_t nb_mbuf_segs = mbuf->nb_segs;
	uint32_t nb_dst_segs = mbuf->l2_len;
	uint64_t len;
	int ret;

	if (likely(nb_mbuf_segs == 1) && (nb_dst_segs == 1)) {
		len = RTE_MIN(mbuf->pkt_len, sges[0].length);
		dao_dma_enq_dst_x1(mem2dev, sges[0].addr & PTS_RDMA_DEV_IOVA_MASK, len);
		dao_dma_enq_src_x1(mem2dev, (uintptr_t)rte_pktmbuf_mtod(mbuf, uint64_t *), len);
		mbuf->next = NULL;
		mbuf->nb_segs = 1;
		return 0;
	}

	/* more sges and less mbufs */
	if (nb_dst_segs > nb_mbuf_segs)
		ret = read_response_process_multi_sge(mem2dev, mbuf, nb_dst_segs, nb_mbuf_segs);
	/* more mbufs and less sges */
	else
		ret = read_response_process_multi_mbuf(mem2dev, mbuf, nb_dst_segs, nb_mbuf_segs);

#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
	/* All the buffers would be freed to NPA by DPI.
	 * Mark them as put since SW did not free them
	 */
	RTE_MEMPOOL_CHECK_COOKIES(mbuf->pool, (void **)&mbuf, 1, 0);
#endif
	return ret;
}

static inline int
process_rdma_read_resp(struct pts_rdma_qp *qp, struct dao_dma_vchan_state *mem2dev,
		       struct rte_mbuf *mbuf)
{
	struct pts_rdma_cq_data *cq_data = &qp->sq.cq_data;
	struct dao_pts_rdma_cqe *cqe;
	struct dao_pts_rdma_sge *sges;
	uint32_t pkt_len;
	uint16_t nb_sge;

	if (unlikely(is_queue_full(cq_data->pi_data, cq_data->ci)))
		return -1;

	nb_sge = mbuf->l2_len;
	pkt_len = mbuf->pkt_len;
	sges = DAO_PTS_RDMA_MBUF_TO_SGES(mbuf);
	cqe = DAO_PTS_RDMA_MBUF_TO_CQE(mbuf);

	if (unlikely(!validate_sge_len(sges, nb_sge, pkt_len)))
		return -1;

	if (unlikely(read_resp_enqueue(mem2dev, mbuf, sges)))
		return -1;

	pts_rdma_enqueue_cqe(&qp->sq.cq_data, cqe, 1, true);

	return 0;
}

static inline int
process_rdma_read_resp_no_cqe(struct dao_dma_vchan_state *mem2dev, struct rte_mbuf *mbuf)
{
	struct dao_pts_rdma_sge *sges;
	uint32_t pkt_len;
	uint16_t nb_sge;

	nb_sge = mbuf->l2_len;
	pkt_len = mbuf->pkt_len;
	sges = DAO_PTS_RDMA_MBUF_TO_SGES(mbuf);

	if (unlikely(!validate_sge_len(sges, nb_sge, pkt_len)))
		return -1;

	if (unlikely(read_resp_enqueue(mem2dev, mbuf, sges)))
		return -1;

	return 0;
}

static inline int
process_rdma_write(struct dao_dma_vchan_state *mem2dev, struct rte_mbuf *mbuf)
{
	uint8_t flush_thr = mem2dev->flush_thr;
	struct dao_pts_rdma_sge *sges;
	struct rte_mbuf *m = NULL, *m_next;
	uint32_t nb_segs = mbuf->nb_segs, i;
	uint64_t sge_off, tot_len = 0;
	uint32_t n_segs_left = 0;

	sges = DAO_PTS_RDMA_MBUF_TO_SGES(mbuf);
	if (unlikely(mbuf->pkt_len != sges[0].length))
		return -1;

	if (likely(nb_segs == 1)) {
		dao_dma_enq_dst_x1(mem2dev, sges[0].addr & PTS_RDMA_DEV_IOVA_MASK, sges[0].length);
		dao_dma_enq_src_x1(mem2dev, (uintptr_t)rte_pktmbuf_mtod(mbuf, uint64_t *),
				   mbuf->data_len);
		mbuf->next = NULL;
		mbuf->nb_segs = 1;
		return 0;
	}
	n_segs_left = nb_segs;
	sge_off = sges[0].addr;
	m = mbuf;

	while (n_segs_left > 0) {
		if (unlikely(!dao_dma_flush(mem2dev, flush_thr)))
			return -1;
		for (i = 0; i < flush_thr && n_segs_left; i++) {
			dao_dma_enq_src_x1(mem2dev, (uintptr_t)rte_pktmbuf_mtod(m, uint64_t *),
					   m->data_len);

			tot_len += m->data_len;
			m_next = m->next;
			m->next = NULL;
			m->nb_segs = 1;
			m = m_next;
			n_segs_left--;
		}
		dao_dma_enq_dst_x1(mem2dev, sge_off & PTS_RDMA_DEV_IOVA_MASK, tot_len);
		sge_off += tot_len;
		tot_len = 0;
	}
#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
	/* All the buffers would be freed to NPA by DPI.
	 * Mark them as put since SW did not free them
	 */
	RTE_MEMPOOL_CHECK_COOKIES(mbuf->pool, (void **)&mbuf, 1, 0);
#endif
	return 0;
}

static inline int
process_rdma_write_imm(struct dao_dma_vchan_state *mem2dev, struct pts_rdma_qp *qp,
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

	if (process_rdma_write(mem2dev, mbuf))
		return -1;

	/* Get CQE and update wr_id */
	cqe = DAO_PTS_RDMA_MBUF_TO_CQE(mbuf);
	cqe->wr_id = *RQ_DESC_PTR_OFF(desc_base, ci, 8);

	/* Push CQE at last */
	pts_rdma_enqueue_cqe(&qp->rq.cq_data, cqe, 1, true);
	ci = (ci + 1) & (q_sz - 1);
	rq->sd_mbuf_off = ci;

	return 0;
}

static __rte_always_inline int
process_rdma_read_req(uint16_t dev_id, struct pts_rdma_qp *qp, struct dao_dma_vchan_state *dev2mem,
		      struct rte_mbuf *mbuf, uint16_t *r_off)
{
	uint8_t flush_thr = dev2mem->flush_thr;
	uint16_t r_last_off, q_sz;
	struct rte_mbuf *m = NULL;
	struct dao_pts_rdma_sge *sges;
	uint16_t roff = *r_off, nb_segs = 0, n_segs_left = 0;
	uint64_t sge_off = 0, tot_len = 0;
	uint32_t i;

	q_sz = qp->r_q_sz;
	r_last_off = __atomic_load_n(&qp->r_last_off, __ATOMIC_ACQUIRE);
	/* Check for space */
	if (((roff + 1) & (q_sz - 1)) == r_last_off)
		return -1;

	sges = DAO_PTS_RDMA_MBUF_TO_SGES(mbuf);
	if (unlikely(mbuf->pkt_len != sges[0].length))
		return -1;

	mbuf->packet_type = DAO_PTS_RDMA_D2M_COMPL;
	mbuf->port = dev_id + RTE_MAX_ETHPORTS;
	nb_segs = mbuf->nb_segs;
	if (likely(nb_segs == 1)) {
		dao_dma_enq_src_x1(dev2mem, sges[0].addr & PTS_RDMA_DEV_IOVA_MASK, sges[0].length);
		dao_dma_enq_dst_x1(dev2mem, (uintptr_t)rte_pktmbuf_mtod(mbuf, uint64_t *),
				   mbuf->data_len);
		qp->r_mbuf_arr[roff] = mbuf;
		roff = (roff + 1) & (q_sz - 1);
		*r_off = roff;
		return 0;
	}

	/* Read request has single remote address */
	n_segs_left = nb_segs;
	sge_off = sges[0].addr;
	m = mbuf;
	while (n_segs_left > 0) {
		if (unlikely(!dao_dma_flush(dev2mem, flush_thr)))
			return -1;
		for (i = 0; i < flush_thr && n_segs_left; i++) {
			dao_dma_enq_dst_x1(dev2mem, (uintptr_t)rte_pktmbuf_mtod(m, uint64_t *),
					   m->data_len);
			tot_len += m->data_len;
			m = m->next;
			n_segs_left--;
		}
		dao_dma_enq_src_x1(dev2mem, sge_off & PTS_RDMA_DEV_IOVA_MASK, tot_len);
		sge_off += tot_len;
		tot_len = 0;
	}
	qp->r_mbuf_arr[roff] = mbuf;
	roff = (roff + 1) & (q_sz - 1);
	*r_off = roff;
	return 0;
}

static __rte_always_inline uint64_t
calculate_max_dlen(uintptr_t desc_base, uint16_t ci, uint32_t sge_idx, uint32_t nb_enq_sges,
		   uint64_t sge_offset, uint8_t flush_thr)
{
	uint64_t max_dlen = 0, sge_len, len = 0;
	uint32_t i = 0;

	for (i = 0; i < flush_thr && sge_idx + i < nb_enq_sges; i++) {
		sge_len = *RQ_DESC_PTR_OFF(desc_base, ci, 24 + 16 * (sge_idx + i)) & 0xFFFFFFFF;
		/* If any sge bytes left from previous DMA */
		len = (i == 0) ? (sge_len - sge_offset) : sge_len;
		max_dlen += len;
	}
	return max_dlen;
}

static __rte_always_inline int
process_multi_mbuf(struct dao_dma_vchan_state *mem2dev, uintptr_t desc_base, uint16_t ci,
		   struct rte_mbuf *mbuf, uint32_t nb_enq_sges)
{
	uint32_t n_mbufs_left = mbuf->nb_segs, sge_idx = 0, n_src_mbufs, n_dst_sges;
	uint64_t max_dst_len, max_src_len, dst_ptr, dst_len, avail, len;
	uint64_t src_offset = 0, dst_offset = 0;
	uint8_t flush_thr = mem2dev->flush_thr;
	struct rte_mbuf *m = mbuf, *mbuf_next;

	while (n_mbufs_left > 0 && sge_idx < nb_enq_sges) {
		if (unlikely(!m || !dao_dma_flush(mem2dev, flush_thr)))
			return -1;
		/* max enqueue length can be copied in this DMA instruction */
		max_dst_len = calculate_max_dlen(desc_base, ci, sge_idx, nb_enq_sges, dst_offset,
						 flush_thr);
		max_src_len = 0;
		n_src_mbufs = 0;
		while (n_src_mbufs < flush_thr && max_src_len < max_dst_len) {
			if (n_mbufs_left == 0 || !m)
				break;
			avail = m->data_len - src_offset;
			len = RTE_MIN(avail, max_dst_len - max_src_len);
			/* Single MBUF might split across DMA instructions based on src_offset  */
			dao_dma_enq_src_x1(mem2dev,
					   (uintptr_t)rte_pktmbuf_mtod(m, uint64_t *) + src_offset,
					   len);
			src_offset += len;
			max_src_len += len;
			n_src_mbufs++;
			/* Move to next mbuf */
			if (src_offset >= m->data_len) {
				mbuf_next = m->next;
				m->next = NULL;
				m->nb_segs = 1;
				m = mbuf_next;
				src_offset = 0;
				n_mbufs_left--;
			}
		}
		n_dst_sges = 0;
		while (max_src_len > 0 && n_dst_sges < flush_thr) {
			if (sge_idx >= nb_enq_sges)
				break;
			dst_ptr = *RQ_DESC_PTR_OFF(desc_base, ci, 16 + 16 * sge_idx);
			dst_len = *RQ_DESC_PTR_OFF(desc_base, ci, 24 + 16 * sge_idx) & 0xFFFFFFFF;
			avail = dst_len - dst_offset;
			len = RTE_MIN(max_src_len, avail);
			/* Single sge split across DMA instructions based on dst_offset  */
			dao_dma_enq_dst_x1(mem2dev, (dst_ptr + dst_offset) & PTS_RDMA_DEV_IOVA_MASK,
					   len);
			dst_offset += len;
			max_src_len -= len;
			n_dst_sges++;
			if (dst_offset >= dst_len) {
				sge_idx++;
				dst_offset = 0;
			}
		}
	}
	return 0;
}

static __rte_always_inline int
process_multi_sge(struct dao_dma_vchan_state *mem2dev, uintptr_t desc_base, uint16_t ci,
		  struct rte_mbuf *mbuf, uint32_t nb_dst_sges)
{
	uint64_t max_src_len, max_dst_len, off, avail, dst_len, dst_addr;
	uint32_t dst_sge_index = 0, n_src_mbufs, n_dst_sges;
	uint64_t src_offset = 0, dst_offset = 0, tot_len = mbuf->pkt_len;
	struct rte_mbuf *m = mbuf, *mbuf_next, *mbuf2;
	uint8_t flush_thr = mem2dev->flush_thr;

	while (likely(dst_sge_index < nb_dst_sges && tot_len > 0)) {
		if (unlikely(!m || !dao_dma_flush(mem2dev, flush_thr)))
			return -1;

		max_src_len = 0;
		n_src_mbufs = 0;
		mbuf2 = m;
		off = src_offset;
		while (n_src_mbufs < flush_thr && max_src_len < tot_len) {
			if (!mbuf2)
				break;
			avail = mbuf2->data_len - off;
			dst_len = RTE_MIN(tot_len - max_src_len, avail);
			max_src_len += dst_len;
			n_src_mbufs++;
			/* mbuf split b/w DMA instrctions */
			if (off + dst_len >= mbuf2->data_len) {
				mbuf2 = mbuf2->next;
				off = 0;
			} else {
				off += dst_len;
			}
		}
		max_dst_len = 0;
		n_dst_sges = 0;
		while (n_dst_sges < flush_thr && max_dst_len < max_src_len) {
			if (dst_sge_index >= nb_dst_sges)
				break;
			dst_addr = *RQ_DESC_PTR_OFF(desc_base, ci, 16 + 16 * dst_sge_index);
			dst_len = *RQ_DESC_PTR_OFF(desc_base, ci, 24 + 16 * dst_sge_index) &
				  0xFFFFFFFF;
			avail = dst_len - dst_offset;
			if (max_dst_len + avail > max_src_len) {
				dst_len = max_src_len - max_dst_len;
				dao_dma_enq_dst_x1(mem2dev,
						   (dst_addr + dst_offset) & PTS_RDMA_DEV_IOVA_MASK,
						   dst_len);
				dst_offset += dst_len;
				max_dst_len += dst_len;
				break;
			}
			dao_dma_enq_dst_x1(mem2dev,
					   (dst_addr + dst_offset) & PTS_RDMA_DEV_IOVA_MASK, avail);
			max_dst_len += avail;
			n_dst_sges++;
			dst_sge_index++;
			dst_offset = 0;
		}
		n_src_mbufs = 0;
		while (max_dst_len > 0 && n_src_mbufs < flush_thr) {
			if (!m)
				break;
			avail = m->data_len - src_offset;
			dst_len = RTE_MIN(max_dst_len, avail);
			dao_dma_enq_src_x1(mem2dev,
					   (uintptr_t)rte_pktmbuf_mtod(m, uint64_t *) + src_offset,
					   dst_len);
			src_offset += dst_len;
			max_dst_len -= dst_len;
			tot_len -= dst_len;
			n_src_mbufs++;
			/* Move to next mbuf */
			if (src_offset >= m->data_len) {
				mbuf_next = m->next;
				m->next = NULL;
				m->nb_segs = 1;
				m = mbuf_next;
				src_offset = 0;
			}
		}
	}
	return 0;
}

static __rte_always_inline int
process_and_enq_mbuf_desc(struct dao_dma_vchan_state *mem2dev, uintptr_t desc_base, uint16_t ci,
			  struct rte_mbuf *mbuf, uint16_t qp_id, uint32_t *len)
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

		/* QP ID 1 corresponds to a QPT_GSI (General Service Interface) queue pair,
		 * which is kernel-managed. The DMA addresses for kernel QPs are already
		 * properly aligned within the 39-bit address boundary, so IOVA masking
		 * is not required.
		 *
		 * TODO: Implement a mechanism to identify all kernel ULP (Upper Layer Protocol)
		 * queue pairs and bypass IOVA masking for improved performance.
		 */
		if (unlikely(qp_id == 1))
			dao_dma_enq_dst_x1(mem2dev, dst_ptr, dlen);
		else
			dao_dma_enq_dst_x1(mem2dev, dst_ptr & PTS_RDMA_DEV_IOVA_MASK, dlen);

		dao_dma_enq_src_x1(mem2dev, (uintptr_t)rte_pktmbuf_mtod(mbuf, uint64_t *), dlen);
		mbuf->next = NULL;
		mbuf->nb_segs = 1;
		*len = dlen;
		return 0;
	}
	if (mbuf->nb_segs > nb_enq_sges)
		return process_multi_mbuf(mem2dev, desc_base, ci, mbuf, nb_enq_sges);
	else
		return process_multi_sge(mem2dev, desc_base, ci, mbuf, nb_enq_sges);
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
	uint32_t len = 0;

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

	if (unlikely(process_and_enq_mbuf_desc(mem2dev, desc_base, ci, mbuf, qp->qp_id, &len)))
		return -1;

#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
	/* All the buffers would be freed to NPA by DPI.
	 * Mark them as put since SW did not free them
	 */
	RTE_MEMPOOL_CHECK_COOKIES(mbuf->pool, (void **)&mbuf, 1, 0);
#endif
	/* Get CQE and update wr_id */
	cqe = DAO_PTS_RDMA_MBUF_TO_CQE(mbuf);
	cqe->wr_id = *RQ_DESC_PTR_OFF(desc_base, ci, 8);
	if (unlikely(qp->qp_id == 1))
		cqe->opcode = *RQ_DESC_PTR_OFF(desc_base, ci, 4);
	cqe->byte_len = len;
	cqe->ibqp = qp->ibqp;

	/* Push CQE at last */
	pts_rdma_enqueue_cqe(&qp->rq.cq_data, cqe, 1, true);
	ci = (ci + 1) & (q_sz - 1);
	rq->sd_mbuf_off = ci;

	return 0;
}

static __rte_always_inline int
push_enq_buffers(uint16_t devid, struct pts_rdma_qp *qp, struct rte_mbuf **mbufs, uint16_t nb_mbufs,
		 const uint16_t flags)
{
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	uint16_t roff, r_mbuf_dma_off = 0, nb_read_enq = 0;
	uint16_t i = 0, nb_cqe = 0, nb_read_cqe = 0;
	struct pts_rdma_qp_rq *rq = &qp->rq;
	struct dao_dma_vchan_state *mem2dev;
	struct dao_dma_vchan_state *dev2mem;
	uint16_t dma_vchan = rq->dma_vchan;
	uint16_t last_idx = 0, last_read_idx = 0;
	struct rte_mbuf *mbuf = NULL;
	uint64_t ol_flags = 0;
	uint8_t type;
	int ret = 0;

	RTE_SET_USED(flags);

	dev2mem = &vchan_info->dev2mem[dma_vchan];
	mem2dev = &vchan_info->mem2dev[dma_vchan];
	roff = qp->r_mbuf_dma_off;
	/* Check for minimum space */
	if (!dao_dma_flush(mem2dev, 1) || !dao_dma_flush(dev2mem, 1))
		goto exit;

	while (i < nb_mbufs) {
		mbuf = mbufs[i];
		ol_flags = mbuf->ol_flags;
		type = ol_flags >> 60;
		mbuf->ol_flags &= ~(0xFULL << 60);
		if (type == DAO_PTS_RDMA_ENQ_M2D_SQE_WITH_CQE) {
			ret = process_rdma_read_resp(qp, mem2dev, mbuf);
			if (ret)
				goto exit;
			nb_read_cqe++;
		} else if (type == DAO_PTS_RDMA_ENQ_M2D_SQE) {
			ret = process_rdma_read_resp_no_cqe(mem2dev, mbuf);
			if (ret)
				goto exit;
		} else if (type == DAO_PTS_RDMA_ENQ_D2M) {
			ret = process_rdma_read_req(devid, qp, dev2mem, mbuf, &roff);
			if (ret)
				goto exit;
			nb_read_enq++;
		} else if (type == DAO_PTS_RDMA_ENQ_M2D) {
			ret = process_rdma_write(mem2dev, mbuf);
			if (ret)
				goto exit;
		} else if (type == DAO_PTS_RDMA_ENQ_M2D_WITH_CQE) {
			ret = process_rdma_write_imm(mem2dev, qp, mbuf);
			if (ret)
				goto exit;
		} else if (type == DAO_PTS_RDMA_ENQ_M2D_RQE_WITH_CQE) {
			ret = process_m2d_rqe_with_cqe(qp, mem2dev, mbuf);
			if (ret)
				goto exit;
			nb_cqe++;
		}
		i++;
		last_read_idx = dev2mem->tail;
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
	if (nb_read_cqe)
		dao_dma_update_cmpl_meta_v2(mem2dev, &qp->sq.cq_data.pi, qp->sq.cq_data.pi_data,
					    last_idx);

	/* Update mbuf_off index with mbuf_dma_off as completion */
	if (nb_read_enq) {
		r_mbuf_dma_off = desc_off_add(qp->r_mbuf_dma_off, nb_read_enq, qp->r_q_sz);
		qp->r_mbuf_dma_off = r_mbuf_dma_off;
		dao_dma_update_cmpl_meta_v2(dev2mem, &qp->r_mbuf_off, qp->r_mbuf_dma_off,
					    last_read_idx);
	}

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
