/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell.
 */
#include "pts_rdma_mbox.h"
#include "dao_dma.h"
#include "pts_rdma_dev_priv.h"

extern struct dao_pts_rdma_dev_cbs pts_rdma_dev_cbs;

static inline void
pts_rdma_dev_mbox_cpy(volatile char *dst, const char *src, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		dst[i] = src[i];
}

static inline void
pts_rdma_qp_mem_free(struct pts_rdma_dev *dev, struct pts_rdma_qp *qp)
{
	if (!qp)
		return;

	if (qp->is_mgmt && dev->mgmt_qp_id == qp->qp_id)
		dev->mgmt_qp_id = -1;

	rte_bitmap_clear(dev->qp_bmap, qp->qp_id);
	rte_free(qp->rq.cq_data.ring_base);
	rte_free(qp->rq.sd_desc_base);
	rte_free(qp->r_mbuf_arr);
	rte_free(qp->sq.cq_data.ring_base);
	rte_free(qp->sq.mbuf_arr);
	rte_free(qp->sq.sd_desc_base);
	rte_free(qp);
}

static void
pts_rdma_qp_sq_flush(struct pts_rdma_qp *qp)
{
	struct pts_rdma_qp_sq *sq = &qp->sq;
	uint32_t sd_mbuf_dma_off, last_off = sq->last_off, q_sz = sq->q_sz;
	uint32_t off;
	uint32_t nb_avail, end;

	if (!qp)
		return;
	/* No pending DMAs at this stage */
	sd_mbuf_dma_off = __atomic_load_n(&sq->sd_mbuf_dma_off, __ATOMIC_ACQUIRE);
	nb_avail = desc_off_diff32(sd_mbuf_dma_off, last_off, q_sz);
	if (unlikely(!nb_avail))
		return;
	off = last_off;
	do {
		end = (off + nb_avail > q_sz) ? (uint32_t)(q_sz - off) : nb_avail;
		rte_pktmbuf_free_bulk(&sq->mbuf_arr[off], end);
		off = (off + end) & (q_sz - 1);
		nb_avail -= end;
	} while (nb_avail);
}

static void
pts_rdma_qp_read_ring_flush(struct pts_rdma_qp *qp)
{
	uint32_t mbuf_dma_off, last_off, q_sz, off, end;
	struct rte_mbuf *seg;
	uint32_t nb_avail, k;

	if (!qp)
		return;

	mbuf_dma_off = qp->r_mbuf_dma_off;
	last_off = qp->r_last_off;
	q_sz = qp->r_q_sz;

	nb_avail = desc_off_diff32(mbuf_dma_off, last_off, q_sz);
	if (unlikely(!nb_avail))
		return;

	off = last_off;
	do {
		end = (off + nb_avail > q_sz) ? (uint32_t)(q_sz - off) : nb_avail;
		/* Release extra refcnt taken by rdma_read_prep_for_pts()
		 * so the subsequent free brings each segment to zero.
		 */
		for (k = 0; k < end; k++) {
			for (seg = qp->r_mbuf_arr[off + k]; seg; seg = seg->next) {
				if (rte_mbuf_refcnt_read(seg) > 1)
					rte_mbuf_refcnt_update(seg, -1);
			}
		}
		rte_pktmbuf_free_bulk(&qp->r_mbuf_arr[off], end);
		off = (off + end) & (q_sz - 1);
		nb_avail -= end;
	} while (nb_avail);
}

static void
pts_rdma_qp_rq_flush(struct pts_rdma_qp *qp)
{
	/* Post DMA completion, all buffers are freed by DPI */
	RTE_SET_USED(qp);
}

static void
pts_rdma_qp_buf_free(struct pts_rdma_dev *dev, struct pts_rdma_qp *qp)
{
	RTE_SET_USED(dev);

	if (!qp)
		return;
	pts_rdma_qp_sq_flush(qp);
	pts_rdma_qp_rq_flush(qp);
	pts_rdma_qp_read_ring_flush(qp);
}

static void
pts_rdma_qp_dma_finish(struct pts_rdma_dev *dev, struct pts_rdma_qp *qp)
{
	struct pts_rdma_qp_rq *rq;
	uint16_t dma_vchan;

	RTE_SET_USED(dev);
	if (!qp)
		return;

	rq = &qp->rq;
	/* All the QPs (in turn CQ/RQ/SQ) of a RDMA device  belong to the same DMA vchan */
	dma_vchan = rq->dma_vchan;
	dao_dma_compl_wait_inflight(dma_vchan);
}

void
pts_rdma_clear_qp_info(struct pts_rdma_dev *dev)
{
	struct dao_pts_rdma_dev *dao_dev = pts_rdma_ptsdev_to_dao(dev);
	struct pts_rdma_qp *qp;
	uint32_t i;

	for (i = 0; i < dev->max_qps; i++) {
		qp = dao_dev->qps[i];
		if (!qp)
			continue;
		pts_rdma_qp_dma_finish(dev, qp);
		pts_rdma_qp_buf_free(dev, qp);
		pts_rdma_qp_mem_free(dev, qp);
		dao_dev->qps[i] = NULL;
	}

	for (i = 0; i < dev->max_cqs; i++) {
		if (dev->cqs[i]) {
			rte_free(dev->cqs[i]);
			dev->cqs[i] = NULL;
		}
	}
}

static inline int
pts_rdma_populate_qp_info(struct pts_rdma_dev *dev,
			  volatile struct pts_rdma_dev_set_qp_config_req *req)
{
	struct dao_pts_rdma_dev *dao_dev = pts_rdma_ptsdev_to_dao(dev);
	struct pts_rdma_cq *send_cq, *recv_cq;
	struct pts_rdma_qp_sq *sq;
	struct pts_rdma_qp_rq *rq;
	uint16_t qp_id = req->qp_id;
	struct pts_rdma_qp *qp;
	uint16_t buf_len;
	int rc = 0;

	if (qp_id >= dev->max_qps) {
		dao_err("Invalid QP %d, Supported range is 0-%d ", qp_id, dev->max_qps - 1);
		return -EINVAL;
	}

	if (dao_dev->qps[qp_id] != NULL) {
		dao_err("QP %d is already initialized", qp_id);
		return -EINVAL;
	}

	qp = rte_zmalloc("pts_rdma_sq", sizeof(*qp), RTE_CACHE_LINE_SIZE);
	if (!qp) {
		dao_err("[dev %u] Failed to allocate memory for RDMA queue pair", dev->dev_id);
		return -ENOMEM;
	}

	qp->qp_id = qp_id;
	qp->is_mgmt = (req->type == PTS_RDMA_QP_TYPE_MGMT) ? 1 : 0;
	if (qp->is_mgmt)
		dao_info("[dev %u] QP %u configured as management QP", dev->dev_id, qp_id);
	sq = &qp->sq;
	rq = &qp->rq;

	if (!(req->sq_size)) {
		dao_err("[QP-%d] Invalid SQ size-(%d)", qp_id, req->sq_size);
		return -EINVAL;
	}

	if (!(req->rq_size)) {
		dao_err("[QP-%d] Invalid RQ size-(%d)", qp_id, req->rq_size);
		return -EINVAL;
	}

	/* Populate Send Queue and associate with its CQ */
	sq->sd_desc_base = (uint64_t *)rte_zmalloc(
		"pts_rdma_sq_sd_desc", req->sq_size * PTS_RDMA_DEV_SQE_SIZE, RTE_CACHE_LINE_SIZE);
	if (!sq->sd_desc_base) {
		dao_err("[dev %u] Failed to allocate memory for RDMA sq sd descriptors",
			dev->dev_id);
		rc = -ENOMEM;
		goto qp_free;
	}
	sq->mbuf_arr = (struct rte_mbuf **)rte_zmalloc("pts_rdma_sq_mub_arr",
						       req->sq_size * sizeof(struct rte_mbuf *),
						       RTE_CACHE_LINE_SIZE);
	if (!sq->mbuf_arr) {
		dao_err("[dev %u] Failed to allocate memory for RDMA sq mbuf_arr", dev->dev_id);
		rc = -ENOMEM;
		goto sq_free;
	}

	sq->desc_base = req->sq_base;
	sq->q_sz = req->sq_size;
	sq->pi_addr = (uint32_t *)(dev->notify_base +
				   ((qp_id * dev->notify_qs_mltpr) * dev->notify_off_mltpr));
	sq->ci_addr = sq->pi_addr + 1;
	*(sq->pi_addr) = 0;
	*(sq->ci_addr) = 0;
	sq->dma_vchan = dev->dma_vchan;
	sq->mp = dev->pool;
	buf_len = dev->pool->elt_size;
	buf_len -= sizeof(struct rte_mbuf);
	buf_len -= RTE_PKTMBUF_HEADROOM;
	buf_len -= rte_pktmbuf_priv_size(dev->pool);
	sq->buf_len = buf_len;
	sq->data_off = (sizeof(struct rte_mbuf));
	sq->data_off += RTE_PKTMBUF_HEADROOM;
	sq->data_off += rte_pktmbuf_priv_size(dev->pool);

	send_cq = dev->cqs[req->send_cq_id];
	if (!send_cq) {
		dao_err("[dev %u] Invalid associated Send CQ %u in the QP %u", dev->dev_id,
			req->send_cq_id, qp_id);
		rc = -EINVAL;
		goto sq_free;
	}
	if (!send_cq->enable) {
		dao_err("[dev %u] Invalid associated Send CQ %u in the QP %u", dev->dev_id,
			req->send_cq_id, qp_id);
		rc = -EINVAL;
		goto sq_free;
	}
	sq->cq_id = req->send_cq_id;
	sq->cq_data.cq = send_cq;
	sq->cq_data.q_sz = sq->q_sz;
	sq->cq_data.qmask = sq->cq_data.q_sz - 1;
	sq->cq_data.dma_vchan = send_cq->dma_vchan;
	sq->cq_data.pi_data = 0;
	sq->cq_data.ci = 0;
	sq->cq_data.ring_base = (uint64_t *)rte_zmalloc(
		"pts_rdma_sq_cq_sd_desc", sq->q_sz * PTS_RDMA_DEV_CQE_SIZE, RTE_CACHE_LINE_SIZE);
	if (!sq->cq_data.ring_base) {
		dao_err("[dev %u] Failed to allocate memory for RDMA sq cq descriptors",
			dev->dev_id);
		rc = -ENOMEM;
		goto sq_free;
	}
	qp->r_mbuf_arr = (struct rte_mbuf **)rte_zmalloc(
		"pts_rdma_qp_read_ring", sizeof(struct rte_mbuf *) * PTS_RDMA_MAX_READ_REQ,
		RTE_CACHE_LINE_SIZE);
	if (!qp->r_mbuf_arr) {
		dao_err("[dev %u] Failed to allocate read mbuf ring", dev->dev_id);
		goto sq_free;
	}
	qp->r_q_sz = PTS_RDMA_MAX_READ_REQ;
	/* Populate Recv Queue and associate with its CQ */
	rq->sd_desc_base = (uint32_t *)rte_zmalloc(
		"pts_rdma_rq_sd_desc", req->rq_size * PTS_RDMA_DEV_RQE_SIZE, RTE_CACHE_LINE_SIZE);
	if (!rq->sd_desc_base) {
		dao_err("[dev %u] Failed to allocate memory for RDMA sq cq descriptors",
			dev->dev_id);
		rc = -ENOMEM;
		goto mbuf_free;
	}
	rq->desc_base = req->rq_base;
	rq->q_sz = req->rq_size;
	rq->pi_addr = (uint32_t *)(dev->notify_base +
				   (((qp_id * dev->notify_qs_mltpr) + 1) * dev->notify_off_mltpr));
	rq->ci_addr = rq->pi_addr + 1;
	*(rq->pi_addr) = 0;
	*(rq->ci_addr) = 0;
	rq->dma_vchan = dev->dma_vchan;

	recv_cq = dev->cqs[req->recv_cq_id];
	if (!recv_cq) {
		dao_err("[dev %u] Invalid associated Recv CQ %u in the QP %u", dev->dev_id,
			req->recv_cq_id, qp_id);
		rc = -EINVAL;
		goto rq_free;
	}
	if (!recv_cq->enable) {
		dao_err("[dev %u] Invalid associated Recv CQ %u in the QP %u", dev->dev_id,
			req->recv_cq_id, qp_id);
		rc = -EINVAL;
		goto rq_free;
	}
	rq->cq_id = req->recv_cq_id;
	rq->cq_data.cq = recv_cq;
	rq->cq_data.q_sz = rq->q_sz;
	rq->cq_data.qmask = rq->cq_data.q_sz - 1;
	rq->cq_data.dma_vchan = recv_cq->dma_vchan;
	rq->cq_data.pi_data = 0;
	rq->cq_data.ci = 0;
	rq->cq_data.ring_base = (uint64_t *)rte_zmalloc(
		"pts_rdma_rq_cq_sd_desc", rq->q_sz * PTS_RDMA_DEV_CQE_SIZE, RTE_CACHE_LINE_SIZE);
	if (!rq->cq_data.ring_base) {
		dao_err("[dev %u] Failed to allocate memory for RDMA rq cq descriptors",
			dev->dev_id);
		rc = -ENOMEM;
		goto rq_free;
	}

	qp->ibqp = req->ibqp;

	dao_dev->qps[qp_id] = qp;

	if (qp->is_mgmt)
		dev->mgmt_qp_id = qp_id;

	dao_dbg("[dev %u] Adding qp%d: sq_desc_base %p sq_sz %u rq_desc_base %p rq_sz %u",
		dev->dev_id, qp_id, (void *)sq->desc_base, sq->q_sz, (void *)rq->desc_base,
		rq->q_sz);
	dao_dbg("[dev %u] Adding qp[%d]: send cq_id: %u notify_addr %p val %08x", dev->dev_id,
		qp_id, req->send_cq_id, sq->pi_addr, *(sq->pi_addr));

	dao_dbg("[dev %u] Adding qp[%d]: recv cq_id: %u notify_addr %p val %08x", dev->dev_id,
		qp_id, req->recv_cq_id, rq->pi_addr, *(rq->pi_addr));

	return 0;

rq_free:
	rte_free(rq->sd_desc_base);
	rte_free(rq->cq_data.ring_base);
mbuf_free:
	rte_free(qp->r_mbuf_arr);
sq_free:
	rte_free(sq->mbuf_arr);
	rte_free(sq->cq_data.ring_base);
	rte_free(sq->sd_desc_base);
qp_free:
	rte_free(qp);

	return rc;
}

static inline int
pts_rdma_populate_cq_info(struct pts_rdma_dev *dev,
			  volatile struct pts_rdma_dev_set_cq_config_req *req)
{
	uint16_t cq_id = req->cq_id;
	struct pts_rdma_cq *cq;

	if (cq_id >= dev->max_cqs) {
		dao_err("Invalid CQ %d, Supported range is 0-%d ", cq_id, dev->max_cqs - 1);
		return -EINVAL;
	}

	if (dev->cqs[cq_id] != NULL) {
		dao_err("CQ %d is already initialized", cq_id);
		return -EINVAL;
	}

	if (!(req->size)) {
		dao_err("Invalid CQ(%d) size-(%d)", cq_id, req->size);
		return -EINVAL;
	}

	cq = rte_zmalloc("pts_rdma_cq", sizeof(*cq), RTE_CACHE_LINE_SIZE);
	if (!cq) {
		dao_err("[dev %u] Failed to allocate memory for RDMA control queue %u", dev->dev_id,
			cq_id);
		return -ENOMEM;
	}
	cq->desc_base = req->cq_base;
	cq->q_sz = req->size;
	cq->cq_id = cq_id;
	cq->pi_addr = (uint32_t *)(dev->notify_base +
				   (((cq_id * dev->notify_qs_mltpr) + 2) * dev->notify_off_mltpr));
	cq->ci_addr = cq->pi_addr + 1;
	cq->dma_vchan = dev->dma_vchan;
	cq->pend_dma = 0;

	cq->cb_intr_addr = dev->nb_cb_intrs ? dev->cb_intr_addr[cq_id % dev->nb_cb_intrs] : NULL;

	cq->cb_notify_addr = cq->pi_addr + 4;
	__atomic_store_n(cq->cb_notify_addr, 1, __ATOMIC_RELAXED);

	cq->cb_cq_req_notify_addr = cq->pi_addr + 3;
	__atomic_store_n(cq->cb_cq_req_notify_addr, 1, __ATOMIC_RELAXED);

	dev->cqs[cq_id] = cq;

	dao_dbg("[dev %u] Adding CQ%d: desc_base %p cq_sz %u", dev->dev_id, cq_id,
		(void *)cq->desc_base, cq->q_sz);

	return 0;
}

static inline int
mbox_msg_set_qp_config_handle(struct pts_rdma_dev *dev, volatile void *data)
{
	volatile struct pts_rdma_dev_set_qp_config_req *req =
		(volatile struct pts_rdma_dev_set_qp_config_req *)data;

	dao_dbg("[dev %u] Config QP%d", dev->dev_id, req->qp_id);

	return pts_rdma_populate_qp_info(dev, req);
}

static inline int
mbox_msg_set_qp_state_handle(struct pts_rdma_dev *dev, volatile void *data)
{
	volatile struct pts_rdma_dev_set_qp_state_req *req =
		(volatile struct pts_rdma_dev_set_qp_state_req *)data;
	struct dao_pts_rdma_dev *dao_dev = pts_rdma_ptsdev_to_dao(dev);
	uint16_t qp_id = req->qp_id;
	struct pts_rdma_qp *qp = dao_dev->qps[qp_id];
	int rc = 0;

	if (!qp)
		return -EINVAL;

	dao_dbg("[dev %u] %s QP%d", dev->dev_id, req->enable ? "Enabling" : "Disabling", qp_id);

	if (req->enable) {
		rte_bitmap_set(dev->qp_bmap, req->qp_id);
		/* Notify the app about QP state change */
		if (pts_rdma_dev_cbs.qp_status_cb)
			rc = pts_rdma_dev_cbs.qp_status_cb(dev->dev_id, req->qp_id, req->enable);
	} else {
		rte_bitmap_clear(dev->qp_bmap, req->qp_id);
		/* Notify the app about QP state change */
		if (pts_rdma_dev_cbs.qp_status_cb)
			rc = pts_rdma_dev_cbs.qp_status_cb(dev->dev_id, req->qp_id, req->enable);
		pts_rdma_qp_dma_finish(dev, qp);
		pts_rdma_qp_buf_free(dev, qp);
		*(qp->sq.pi_addr) = 0;
		*(qp->sq.ci_addr) = 0;
		*(qp->rq.pi_addr) = 0;
		*(qp->rq.ci_addr) = 0;
		pts_rdma_qp_mem_free(dev, qp);
		dao_dev->qps[qp_id] = NULL;
		rte_io_wmb();
	}

	return rc;
}

static inline int
mbox_msg_set_cq_config_handle(struct pts_rdma_dev *dev, volatile void *data)
{
	volatile struct pts_rdma_dev_set_cq_config_req *req =
		(volatile struct pts_rdma_dev_set_cq_config_req *)data;

	dao_dbg("[dev %u] Config CQ%d", dev->dev_id, req->cq_id);

	return pts_rdma_populate_cq_info(dev, req);
}

static inline int
mbox_msg_set_cq_state_handle(struct pts_rdma_dev *dev, volatile void *data)
{
	volatile struct pts_rdma_dev_set_cq_state_req *req =
		(volatile struct pts_rdma_dev_set_cq_state_req *)data;
	uint16_t cq_id = req->cq_id;
	struct pts_rdma_cq *cq = dev->cqs[cq_id];

	if (!cq) {
		dao_err("Invalid CQ");
		return -EINVAL;
	}

	dao_dbg("[dev %u] %s CQ%d", dev->dev_id, req->enable ? "Enabling" : "Disabling", cq_id);

	cq->enable = req->enable;
	if (!req->enable) {
		rte_free(cq);
		dev->cqs[cq_id] = NULL;
	}

	return 0;
}

static void
pts_rdma_dev_mbox_process(struct pts_rdma_dev *dev)
{
	volatile struct dao_pts_rdma_mbox *mbox = (struct dao_pts_rdma_mbox *)dev->mbox_mem;
	void *rsp = dev->mbox_usr_rsp_mem;
	uint16_t rc = 0, rsp_len = 0;

	rte_delay_us(100);
	if (mbox->hdr.sig != MBOX_REQ_SIG) {
		rc = EINVAL;
		goto exit;
	}
	if (mbox->hdr.id >= MBOX_MSG_USER_DEFINED) {
		rc = pts_rdma_dev_cbs.user_mbox_cb(dev->dev_id, mbox, rsp, &rsp_len);
		if (!rc && rsp_len)
			pts_rdma_dev_mbox_cpy((volatile char *)mbox->data, (const char *)rsp,
					      rsp_len);
		goto exit;
	}

	switch (mbox->hdr.id) {
	case MBOX_MSG_SET_QP_CONFIG:
		rc = mbox_msg_set_qp_config_handle(dev, mbox->data);
		break;
	case MBOX_MSG_SET_QP_STATE:
		rc = mbox_msg_set_qp_state_handle(dev, mbox->data);
		break;
	case MBOX_MSG_SET_CQ_CONFIG:
		rc = mbox_msg_set_cq_config_handle(dev, mbox->data);
		break;
	case MBOX_MSG_SET_CQ_STATE:
		rc = mbox_msg_set_cq_state_handle(dev, mbox->data);
		break;
	default:
		rc = EINVAL;
		break;
	}

	if (rc)
		dao_err("[dev %u] Failed to process mailbox message %u, rc=%d", dev->dev_id,
			mbox->hdr.id, rc);
exit:
	mbox->sts.rc = rc;
	mbox->sts.rsp = 1;
	mbox->hdr.sig = MBOX_RSP_SIG;
	mbox->hdr.id = 0;
	rte_wmb();
}

static int
pts_rdma_dev_mbox_process_cb(void *ctx, uintptr_t shadow, uint32_t offset, uint64_t val,
			     uint64_t shadow_val)
{
	struct pts_rdma_dev *dev = ctx;

	RTE_SET_USED(offset);
	RTE_SET_USED(shadow_val);

	*((uint64_t *)shadow) = val;
	pts_rdma_dev_mbox_process(dev);
	memcpy((void *)shadow, (void *)dev->mbox_mem, 8);

	return 0;
}

int
pts_rdma_dev_mbox_init(struct pts_rdma_dev *dev)
{
	uintptr_t mbox_mem = dev->mbox_mem;
	int rc;

	memset((void *)mbox_mem, 0, 8);
	dev->mbox_h2d = (volatile struct dao_pts_rdma_mbox *)mbox_mem;
	dev->mbox_d2h =
		(volatile struct dao_pts_rdma_mbox *)(mbox_mem + PTS_RDMA_DEV_MBOX_H2D_SIZE);

	/* Register MBOX H2D header region */
	rc = dao_pem_ctrl_region_register(dev->pem_devid, (uintptr_t)dev->mbox_h2d, 8,
					  pts_rdma_dev_mbox_process_cb, dev, false);
	if (rc)
		dao_err("[dev %u] Failed to register mbox region, rc=%d", dev->dev_id, rc);

	return rc;
}

void
pts_rdma_dev_mbox_fini(struct pts_rdma_dev *dev)
{
	dao_pem_ctrl_region_unregister(dev->pem_devid, (uintptr_t)dev->mbox_mem, 8,
				       pts_rdma_dev_mbox_process_cb, dev);
}
