/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Marvell.
 */
#include <linux/dma-mapping.h>
#include <rdma/uverbs_ioctl.h>

#include "octep_verbs.h"

#define OCTEP_RDMA_MODIFY_QP_SUPP_MASK                                                             \
	(IB_QP_STATE | IB_QP_CUR_STATE | IB_QP_EN_SQD_ASYNC_NOTIFY | IB_QP_PKEY_INDEX |            \
	 IB_QP_PORT | IB_QP_QKEY | IB_QP_SQ_PSN | IB_QP_RNR_RETRY)

static void
octep_rdma_qp_safe_free(struct kref *ref)
{
	struct octep_rdma_qp *qp = container_of(ref, struct octep_rdma_qp, ref);

	complete(&qp->safe_free);
}

void
octep_rdma_qp_put(struct octep_rdma_qp *qp)
{
	WARN_ON(kref_read(&qp->ref) < 1);
	kref_put(&qp->ref, octep_rdma_qp_safe_free);
}

void
octep_rdma_qp_get(struct octep_rdma_qp *qp)
{
	kref_get(&qp->ref);
}

int
octep_rdma_qp_validate_cap(struct octep_rdma_dev *rdma_dev, struct ib_qp_init_attr *attrs)
{
	if ((attrs->cap.max_send_sge > rdma_dev->attr.max_send_sge) ||
	    (attrs->cap.max_recv_sge > rdma_dev->attr.max_recv_sge) ||
	    (attrs->cap.max_inline_data > OCTEP_RDMA_MAX_INLINE)) {
		return -EINVAL;
	}

	return 0;
}

int
octep_rdma_qp_validate_attr(struct octep_rdma_dev *rdma_dev, struct ib_qp_init_attr *attrs)
{
	if (attrs->qp_type != IB_QPT_RC && attrs->qp_type != IB_QPT_UD) {
		ibdev_err(&rdma_dev->ibdev,
			  "QP type %d [IB_QPT_RC %d IB_QPT_UD %d] not supported\n", attrs->qp_type,
			  IB_QPT_RC, IB_QPT_UD);
		return -EOPNOTSUPP;
	}

	if (attrs->srq) {
		ibdev_err(&rdma_dev->ibdev, "SRQ not supported\n");
		return -EOPNOTSUPP;
	}

	if (!attrs->send_cq || !attrs->recv_cq) {
		ibdev_err(&rdma_dev->ibdev, "CQ not provided\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

void
free_kernel_qp(struct octep_rdma_qp *qp)
{
	struct octep_rdma_dev *rdma_dev = qp->rdma_dev;

	vfree(qp->kern_qp.swr_tbl);
	vfree(qp->kern_qp.rwr_tbl);

	if (qp->kern_qp.sq_buf)
		dma_free_coherent(&rdma_dev->pdev->dev,
				  WARPPED_BUFSIZE(qp->attrs.sq_size << SQEBB_SHIFT),
				  qp->kern_qp.sq_buf, qp->kern_qp.sq_buf_dma_addr);

	if (qp->kern_qp.rq_buf)
		dma_free_coherent(&rdma_dev->pdev->dev,
				  WARPPED_BUFSIZE(qp->attrs.rq_size << RQE_SHIFT),
				  qp->kern_qp.rq_buf, qp->kern_qp.rq_buf_dma_addr);
}

static void *
register_kern_va(struct ib_qp *ibqp, struct octep_rdma_mem *mem)
{
	u32 nr_pages;
	struct page **pages;
	void *vaddr;
	u64 va;
	long pinned_pages;
	int i;

	nr_pages = mem->page_cnt;
	va = mem->va;

	/* Allocate memory for the page array */
	pages = kcalloc(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return ERR_PTR(-ENOMEM);

	/* Pin the user pages */
	pinned_pages = get_user_pages_fast(va, nr_pages, FOLL_WRITE, pages);
	if (pinned_pages <= 0) {
		ibdev_err(ibqp->device, "Failed to pin any user pages (ret=%ld)\n", pinned_pages);
		kfree(pages);
		return ERR_PTR(pinned_pages ? pinned_pages : -EFAULT);
	}

	if (pinned_pages != nr_pages) {
		ibdev_err(ibqp->device, "Partial page pinning: %ld/%u pages\n", pinned_pages,
			  nr_pages);
		/* Release the partially pinned pages */
		for (i = 0; i < pinned_pages; i++)
			put_page(pages[i]);
		kfree(pages);
		return ERR_PTR(-EFAULT);
	}

	/* Map the pages into a contiguous virtual address space */
	vaddr = vmap(pages, nr_pages, VM_MAP, PAGE_KERNEL);
	if (!vaddr) {
		ibdev_err(ibqp->device, "Failed to map %u pages\n", nr_pages);
		/* Release all pinned pages */
		for (i = 0; i < nr_pages; i++)
			put_page(pages[i]);
		kfree(pages);
		return ERR_PTR(-ENOMEM);
	}

	/* Release page references (vmap holds its own references) */
	for (i = 0; i < nr_pages; i++)
		put_page(pages[i]);
	kfree(pages);

	ibdev_dbg(ibqp->device, "Mapped %u pages to vaddr %p\n", nr_pages, vaddr);
	return vaddr;
}

static int
map_user_qp(struct octep_rdma_qp *qp, u64 va, u32 len)
{
	struct ib_qp *ibqp = &qp->ibqp;
	u32 rq_offset, length, calc_len;
	void *vaddr;
	u64 *pa;
	int ret;

	calc_len =
		(ALIGN(qp->attrs.sq_size * sizeof(union octep_rdma_sqe), OCTEP_RDMA_HW_PAGE_SIZE)) +
		(ALIGN(qp->attrs.rq_size * sizeof(union octep_rdma_rqe), OCTEP_RDMA_HW_PAGE_SIZE));
	if (len < calc_len) {
		ibdev_err(ibqp->device, "Invalid length received: %d calculated: %d\n", len,
			  calc_len);
		return -EINVAL;
	}

	length = ALIGN(qp->attrs.sq_size * sizeof(union octep_rdma_sqe), OCTEP_RDMA_HW_PAGE_SIZE);
	ibdev_dbg(ibqp->device, "sq_size %d size of sqe %ld length %x\n", qp->attrs.sq_size,
		  sizeof(union octep_rdma_sqe), length);
	ret = setup_mem_trans_tbl(qp->rdma_dev, &qp->user_qp.sq_mtt, va, length, 0, va, PAGE_SIZE,
				  1);
	if (ret)
		return ret;

	vaddr = register_kern_va(ibqp, &qp->user_qp.sq_mtt);
	if (IS_ERR(vaddr)) {
		ret = PTR_ERR(vaddr);
		ibdev_err(ibqp->device, "Failed to map SQ space, ret=%d\n", ret);
		goto put_sq_mtt;
	}

	qp->user_qp.sq_vaddr = vaddr;

	pa = qp->user_qp.sq_mtt.mtt_buf;
	ibdev_dbg(ibqp->device, "[%s] SQ: user va: 0x%llx kern va: 0x%llx pa %llx\n", __func__,
		  qp->user_qp.sq_mtt.va, (u64)vaddr, *pa);

	rq_offset = ALIGN(length, OCTEP_RDMA_HW_PAGE_SIZE);
	qp->user_qp.rq_offset = rq_offset;

	length = ALIGN(qp->attrs.rq_size * sizeof(union octep_rdma_rqe), OCTEP_RDMA_HW_PAGE_SIZE);
	ibdev_dbg(ibqp->device, "rq_offset %d length %x\n", rq_offset, length);
	ret = setup_mem_trans_tbl(qp->rdma_dev, &qp->user_qp.rq_mtt, va + rq_offset, length, 0,
				  va + rq_offset, PAGE_SIZE, 1);
	if (ret) {
		ibdev_err(ibqp->device, "Failed to get MTT entries for RQ\n");
		goto free_sq_vaddr;
	}

	vaddr = register_kern_va(ibqp, &qp->user_qp.rq_mtt);
	if (IS_ERR(vaddr)) {
		ret = PTR_ERR(vaddr);
		ibdev_err(ibqp->device, "Failed to map RQ space, ret=%d\n", ret);
		goto put_rq_mtt;
	}

	qp->user_qp.rq_vaddr = vaddr;
	pa = qp->user_qp.rq_mtt.mtt_buf;
	ibdev_dbg(ibqp->device, "[%s] RQ: user va: 0x%llx kern va: 0x%llx pa %llx\n", __func__,
		  qp->user_qp.rq_mtt.va, (u64)vaddr, *pa);

	return 0;

put_rq_mtt:
	release_mem_trans_tbl(qp->rdma_dev, &qp->user_qp.rq_mtt);
free_sq_vaddr:
	vunmap(qp->user_qp.sq_vaddr);
put_sq_mtt:
	release_mem_trans_tbl(qp->rdma_dev, &qp->user_qp.sq_mtt);
	return ret;
}

int
init_user_qp(struct octep_rdma_dev *rdma_dev, struct octep_rdma_qp *qp, struct ib_udata *udata)
{
	struct octep_rdma_uresp_create_qp uresp;
	struct octep_rdma_ureq_create_qp ureq;
	struct ib_qp *ibqp = &qp->ibqp;
	int ret;

	ret = ib_copy_from_udata(&ureq, udata, min(sizeof(ureq), udata->inlen));
	if (ret) {
		ibdev_err(ibqp->device, "ib_copy_from_udata failed\n");
		goto err;
	}

	qp->attrs.sq_size = roundup_pow_of_two(ureq.num_sqe);
	if (qp->attrs.sq_size < OCTEP_RDMA_MIN_SEND_WR)
		qp->attrs.sq_size = OCTEP_RDMA_MIN_SEND_WR;
	else if (qp->attrs.sq_size > OCTEP_RDMA_MAX_SEND_WR)
		qp->attrs.sq_size = OCTEP_RDMA_MAX_SEND_WR;

	qp->attrs.rq_size = roundup_pow_of_two(ureq.num_rqe);
	if (qp->attrs.rq_size < OCTEP_RDMA_MIN_RECV_WR)
		qp->attrs.rq_size = OCTEP_RDMA_MIN_RECV_WR;
	else if (qp->attrs.rq_size > OCTEP_RDMA_MAX_RECV_WR)
		qp->attrs.rq_size = OCTEP_RDMA_MAX_RECV_WR;

	ret = map_user_qp(qp, ureq.qbuf_va, ureq.qbuf_len);
	if (ret) {
		ibdev_err(ibqp->device, "Failed to map user QP\n");
		goto err;
	}

	memset(&uresp, 0, sizeof(uresp));
	uresp.qp_id = QP_ID(qp);
	uresp.rq_offset = qp->user_qp.rq_offset;

	ret = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
	if (ret) {
		ibdev_err(ibqp->device, "ib_copy_to_udata failed\n");
		goto free_qp_map;
	}
	ibdev_dbg(ibqp->device, "[%s] uresp.qp_id %d uresp.rq_offset %d qp->sendq 0x%llx\n",
		  __func__, uresp.qp_id, uresp.rq_offset, (uint64_t)qp->sendq);
	return 0;
free_qp_map:
	release_mem_trans_tbl(qp->rdma_dev, &qp->user_qp.rq_mtt);
	release_mem_trans_tbl(qp->rdma_dev, &qp->user_qp.sq_mtt);
	vunmap(qp->user_qp.sq_vaddr);
	vunmap(qp->user_qp.rq_vaddr);
err:
	return ret;
}

int
init_kernel_qp(struct octep_rdma_dev *rdma_dev, struct octep_rdma_qp *qp,
	       struct ib_qp_init_attr *attrs)
{
	struct octep_rdma_kqp *kqp = &qp->kern_qp;
	int size;

	if (attrs->sq_sig_type == IB_SIGNAL_ALL_WR)
		kqp->sig_all = 1;

	kqp->sq_pi = 0;
	kqp->sq_ci = 0;
	kqp->rq_pi = 0;
	kqp->rq_ci = 0;

	kqp->swr_tbl = vmalloc(qp->attrs.sq_size * sizeof(u64));
	kqp->rwr_tbl = vmalloc(qp->attrs.rq_size * sizeof(u64));
	if (!kqp->swr_tbl || !kqp->rwr_tbl)
		goto err_out;

	size = (qp->attrs.sq_size << SQEBB_SHIFT) + OCTEP_RDMA_EXTRA_BUFFER_SIZE;
	kqp->sq_buf =
		dma_alloc_coherent(&rdma_dev->pdev->dev, size, &kqp->sq_buf_dma_addr, GFP_KERNEL);
	if (!kqp->sq_buf)
		goto err_out;

	size = (qp->attrs.rq_size << RQE_SHIFT) + OCTEP_RDMA_EXTRA_BUFFER_SIZE;
	kqp->rq_buf =
		dma_alloc_coherent(&rdma_dev->pdev->dev, size, &kqp->rq_buf_dma_addr, GFP_KERNEL);
	if (!kqp->rq_buf)
		goto err_out;

	kqp->sq_db_info = kqp->sq_buf + (qp->attrs.sq_size << SQEBB_SHIFT);
	kqp->rq_db_info = kqp->rq_buf + (qp->attrs.rq_size << RQE_SHIFT);

	return 0;

err_out:
	free_kernel_qp(qp);
	return -ENOMEM;
}

int
octep_rdma_prepare_qp_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_qp *qp, u32 pdn)
{
	struct octep_rdma_qp_create_req *qp_req;
	int ret = 0;

	qp_req = kzalloc(sizeof(*qp_req), GFP_KERNEL);
	if (!qp_req)
		return -ENOMEM;

	qp_req->port_num = rdma_dev->port.port_num;
	qp_req->pd_id = pdn;
	qp_req->qp_id = QP_ID(qp);
	qp_req->sq_size = qp->attrs.sq_size;
	qp_req->rq_size = qp->attrs.rq_size;
	qp_req->send_cq_id = qp->scq->cqn;
	qp_req->recv_cq_id = qp->rcq->cqn;
	qp_req->sq_base = qp->user_qp.sq_mtt.iova[0];
	qp_req->rq_base = qp->user_qp.rq_mtt.iova[0];
	qp_req->type = qp->attrs.qp_type;
	qp_req->sq_sig_type = qp->attrs.sq_sig_type;

	ret = octep_rdma_mbox_qp_create(rdma_dev->caps_rgn, qp_req);
	if (ret)
		ibdev_err(&rdma_dev->ibdev, "octep_rdma_mbox_qp_create failed\n");

	kfree(qp_req);
	return ret;
}

int
octep_rdma_prepare_qp_state_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_qp *qp,
				bool enable)
{
	struct octep_rdma_qp_state_req *qp_state;
	int ret = 0;

	qp_state = kzalloc(sizeof(*qp_state), GFP_KERNEL);
	if (!qp_state)
		return -ENOMEM;

	qp_state->port_num = rdma_dev->port.port_num;
	qp_state->qp_id = QP_ID(qp);
	qp_state->enable = enable;

	ret = octep_rdma_mbox_qp_state(rdma_dev->caps_rgn, qp_state);
	if (ret)
		ibdev_err(&rdma_dev->ibdev, "octep_rdma_mbox_qp_state failed, err %d\n", ret);

	ibdev_info(&rdma_dev->ibdev, "[%s] qp_state->qp_id %d qp_state->enable %d\n", __func__,
		   qp_state->qp_id, qp_state->enable);
	kfree(qp_state);

	return ret;
}

int
octep_rdma_prepare_user_qp_destroy_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_qp *qp)
{
	struct octep_rdma_qp_destroy_req *qp_destroy;
	int ret = 0;

	qp_destroy = kzalloc(sizeof(*qp_destroy), GFP_KERNEL);
	if (!qp_destroy)
		return -ENOMEM;

	qp_destroy->qp_id = QP_ID(qp);
	qp_destroy->port_num = rdma_dev->port.port_num;

	ret = octep_rdma_mbox_qp_destroy(rdma_dev->caps_rgn, qp_destroy);
	if (ret)
		ibdev_err(&rdma_dev->ibdev, "octep_rdma_mbox_qp_state failed, err %d\n", ret);

	ibdev_info(&rdma_dev->ibdev, "QP destroy port_num %d qp_destroy->qp_id %d\n",
		   qp_destroy->port_num, qp_destroy->qp_id);
	kfree(qp_destroy);

	return ret;
}

int
octep_rdma_prepare_user_qp_modify_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_qp *qp)
{
	struct octep_rdma_user_qp_modify_req *qp_mod;
	int ret = 0;

	qp_mod = kzalloc(sizeof(*qp_mod), GFP_KERNEL);
	if (!qp_mod)
		return -ENOMEM;

	qp_mod->port_num = rdma_dev->port.port_num;
	qp_mod->modify_mask = qp->attrs.qp_mod_attr->modify_mask;
	qp_mod->new_qp_state = qp->attrs.qp_mod_attr->new_qp_state;
	qp_mod->cur_qp_state = qp->attrs.qp_mod_attr->cur_qp_state;
	qp_mod->qp_access_flags = qp->attrs.qp_mod_attr->qp_access_flags;
	qp_mod->path_mtu = qp->attrs.qp_mod_attr->path_mtu;
	qp_mod->qkey = qp->attrs.qp_mod_attr->qkey;
	qp_mod->pkey_index = qp->attrs.qp_mod_attr->pkey_index;
	qp_mod->sq_drained_async_notify = qp->attrs.qp_mod_attr->sq_drained_async_notify;
	qp_mod->max_dest_rd_atomic = qp->attrs.qp_mod_attr->max_dest_rd_atomic;
	qp_mod->max_rd_atomic = qp->attrs.qp_mod_attr->max_rd_atomic;
	qp_mod->min_rnr_timer = qp->attrs.qp_mod_attr->min_rnr_timer;
	qp_mod->rnr_retry_cnt = qp->attrs.qp_mod_attr->rnr_retry_cnt;
	qp_mod->retry_cnt = qp->attrs.qp_mod_attr->retry_cnt;
	qp_mod->timeout = qp->attrs.qp_mod_attr->timeout;
	qp_mod->qp_id = QP_ID(qp);
	qp_mod->src_udp_port = qp->attrs.qp_mod_attr->src_udp_port;
	qp_mod->rq_psn = qp->attrs.qp_mod_attr->rq_psn;
	qp_mod->sq_psn = qp->attrs.qp_mod_attr->sq_psn;
	qp_mod->dest_qpn = qp->attrs.qp_mod_attr->dest_qpn;
	/* HP - Check this */
	qp_mod->network_type = qp->attrs.qp_mod_attr->mod_av.network_type;
	qp_mod->s_addr = qp->attrs.qp_mod_attr->mod_av.sgid_addr._sockaddr_in.sin_addr.s_addr;
	qp_mod->d_addr = qp->attrs.qp_mod_attr->mod_av.dgid_addr._sockaddr_in.sin_addr.s_addr;
	memcpy(qp_mod->dmac, qp->attrs.qp_mod_attr->mod_av.dmac, ETH_ALEN);
	memcpy(qp_mod->smac, rdma_dev->netdev->dev_addr, ETH_ALEN);

	ret = octep_rdma_mbox_user_qp_modify(rdma_dev->caps_rgn, qp_mod);
	if (ret)
		ibdev_err(&rdma_dev->ibdev, "octep_rdma_mbox_user_qp_modify failed, err %d\n", ret);

	kfree(qp_mod);

	return ret;
}

static enum ib_qp_state
octep_rdma_get_ibqp_state(enum octep_rdma_qp_state qp_state)
{
	switch (qp_state) {
	case OCTEP_RDMA_QP_STATE_RESET:
		return IB_QPS_RESET;
	case OCTEP_RDMA_QP_STATE_INIT:
		return IB_QPS_INIT;
	case OCTEP_RDMA_QP_STATE_RTR:
		return IB_QPS_RTR;
	case OCTEP_RDMA_QP_STATE_RTS:
		return IB_QPS_RTS;
	case OCTEP_RDMA_QP_STATE_SQD:
		return IB_QPS_SQD;
	case OCTEP_RDMA_QP_STATE_ERR:
		return IB_QPS_ERR;
	case OCTEP_RDMA_QP_STATE_SQE:
		return IB_QPS_SQE;
	}
	return IB_QPS_ERR;
}

static enum octep_rdma_qp_state
octep_rdma_get_state_from_ibqp(enum ib_qp_state qp_state)
{
	switch (qp_state) {
	case IB_QPS_RESET:
		return OCTEP_RDMA_QP_STATE_RESET;
	case IB_QPS_INIT:
		return OCTEP_RDMA_QP_STATE_INIT;
	case IB_QPS_RTR:
		return OCTEP_RDMA_QP_STATE_RTR;
	case IB_QPS_RTS:
		return OCTEP_RDMA_QP_STATE_RTS;
	case IB_QPS_SQD:
		return OCTEP_RDMA_QP_STATE_SQD;
	case IB_QPS_ERR:
		return OCTEP_RDMA_QP_STATE_ERR;
	default:
		return OCTEP_RDMA_QP_STATE_ERR;
	}
}

int
octep_rdma_modify_qp_validate(struct octep_rdma_qp *qp, struct ib_qp_attr *qp_attr,
			      int qp_attr_mask)
{
	struct octep_rdma_dev *rdma_dev = qp->rdma_dev;
	enum ib_qp_state cur_state;
	enum ib_qp_state new_state;
	int err;

	cur_state = (qp_attr_mask & IB_QP_CUR_STATE) ? qp_attr->cur_qp_state :
						       octep_rdma_get_ibqp_state(qp->attrs.state);
	new_state = (qp_attr_mask & IB_QP_STATE) ? qp_attr->qp_state : cur_state;
	err = !ib_modify_qp_is_ok(cur_state, new_state, qp->attrs.qp_type, qp_attr_mask);

	if (err) {
		ibdev_err(&rdma_dev->ibdev,
			  "Invalid modify QP state for type %d - cur_state %d -> new state %d\n",
			  qp->attrs.qp_type, cur_state, new_state);
		return -EINVAL;
	}

	if ((qp_attr_mask & IB_QP_PORT) && qp_attr->port_num != 1) {
		ibdev_err(&rdma_dev->ibdev, "Can't change port num: %d\n", qp_attr->port_num);
		return -EOPNOTSUPP;
	}

	if ((qp_attr_mask & IB_QP_PKEY_INDEX) && qp_attr->pkey_index) {
		ibdev_err(&rdma_dev->ibdev, "Can't change pkey index %d\n", qp_attr->pkey_index);
		return -EOPNOTSUPP;
	}

	return 0;
}

static int
octep_rdma_update_qp_state(struct octep_rdma_qp *qp, enum octep_rdma_qp_state cur_state,
			   enum octep_rdma_qp_state new_state)
{
	int status = 0;

	if (new_state == cur_state)
		return 0;

	switch (cur_state) {
	case OCTEP_RDMA_QP_STATE_RESET:
		switch (new_state) {
		case OCTEP_RDMA_QP_STATE_INIT:
			ibdev_info(qp->ibqp.device, "QP state change from RESET to INIT\n");
			break;
		default:
			/* Invalid state change. */
			ibdev_err(qp->ibqp.device, "Invalid state change from RESET to %d\n",
				  new_state);
			status = -EINVAL;
			break;
		}
		break;
	case OCTEP_RDMA_QP_STATE_INIT:
		switch (new_state) {
		case OCTEP_RDMA_QP_STATE_RTR:
			ibdev_info(qp->ibqp.device, "QP state change from INIT to RTR\n");
			break;
		case OCTEP_RDMA_QP_STATE_ERR:
			ibdev_info(qp->ibqp.device, "QP state change from INIT to ERR\n");
			break;
		default:
			/* Invalid state change. */
			ibdev_err(qp->ibqp.device, "Invalid state change from INIT to %d\n",
				  new_state);
			status = -EINVAL;
			break;
		}
		break;
	case OCTEP_RDMA_QP_STATE_RTR:
		/* RTR->XXX */
		switch (new_state) {
		case OCTEP_RDMA_QP_STATE_RTS:
			ibdev_info(qp->ibqp.device, "QP state change from RTR to RTS\n");
			break;
		case OCTEP_RDMA_QP_STATE_ERR:
			ibdev_info(qp->ibqp.device, "QP state change from RTR to ERR\n");
			break;
		default:
			/* Invalid state change. */
			ibdev_err(qp->ibqp.device, "Invalid state change from RTR to %d\n",
				  new_state);
			status = -EINVAL;
			break;
		}
		break;
	case OCTEP_RDMA_QP_STATE_RTS:
		/* RTS->XXX */
		switch (new_state) {
		case OCTEP_RDMA_QP_STATE_SQD:
			ibdev_info(qp->ibqp.device, "QP state change from RTS to SQD\n");
			break;
		case OCTEP_RDMA_QP_STATE_ERR:
			ibdev_info(qp->ibqp.device, "QP state change from RTS to ERR\n");
			break;
		default:
			/* Invalid state change. */
			ibdev_err(qp->ibqp.device, "Invalid state change from RTS to %d\n",
				  new_state);
			status = -EINVAL;
			break;
		}
		break;
	case OCTEP_RDMA_QP_STATE_SQD:
		/* SQD->XXX */
		switch (new_state) {
		case OCTEP_RDMA_QP_STATE_RTS:
			ibdev_info(qp->ibqp.device, "QP state change from SQD to RTS\n");
			break;
		case OCTEP_RDMA_QP_STATE_ERR:
			ibdev_info(qp->ibqp.device, "QP state change from SQD to ERR\n");
			break;
		default:
			/* Invalid state change. */
			ibdev_err(qp->ibqp.device, "Invalid state change from SQD to %d\n",
				  new_state);
			status = -EINVAL;
			break;
		}
		break;
	case OCTEP_RDMA_QP_STATE_ERR:
		/* ERR->XXX */
		switch (new_state) {
		case OCTEP_RDMA_QP_STATE_RESET:
			ibdev_info(qp->ibqp.device, "QP state change from ERR to RESET\n");
			break;
		default:
			status = -EINVAL;
			ibdev_err(qp->ibqp.device, "Invalid state change from ERR to %d\n",
				  new_state);
			break;
		}
		break;
	default:
		status = -EINVAL;
		break;
	}

	return status;
}

int
octep_rdma_modify_qp_attr_populate(struct octep_rdma_qp *qp, struct ib_qp_attr *qp_attr,
				   int qp_attr_mask, struct octep_rdma_qp_mod_attrs *qp_mod_attr)
{
	struct octep_rdma_dev *rdma_dev = qp->rdma_dev;
	struct ib_qp *ibqp = &qp->ibqp;
	enum ib_qp_state cur_state;
	enum ib_qp_state new_state;
	int ret = 0;

	cur_state = (qp_attr_mask & IB_QP_CUR_STATE) ? qp_attr->cur_qp_state :
						       octep_rdma_get_ibqp_state(qp->attrs.state);
	new_state = (qp_attr_mask & IB_QP_STATE) ? qp_attr->qp_state : cur_state;

	if (qp_attr_mask & IB_QP_STATE) {
		OCTEP_RDMA_SET_FIELD(&qp_mod_attr->modify_mask, OCTEP_RDMA_QP_MOD_QP_STATE, 1);
		qp_mod_attr->new_qp_state = octep_rdma_get_state_from_ibqp(new_state);
	}
	if (qp_attr_mask & IB_QP_CUR_STATE) {
		OCTEP_RDMA_SET_FIELD(&qp_mod_attr->modify_mask, OCTEP_RDMA_QP_MOD_CUR_QP_STATE, 1);
		qp_mod_attr->cur_qp_state = octep_rdma_get_state_from_ibqp(cur_state);
	}

	if (qp_attr_mask & IB_QP_EN_SQD_ASYNC_NOTIFY) {
		OCTEP_RDMA_SET_FIELD(&qp_mod_attr->modify_mask, OCTEP_RDMA_QP_MOD_SQD_ASYNC_NOTIFY,
				     1);
		qp_mod_attr->sq_drained_async_notify = qp_attr->en_sqd_async_notify;
	}

	if (qp_attr_mask & IB_QP_QKEY) {
		OCTEP_RDMA_SET_FIELD(&qp_mod_attr->modify_mask, OCTEP_RDMA_QP_MOD_QKEY, 1);
		qp_mod_attr->qkey = qp_attr->qkey;
	}

	if (qp_attr_mask & IB_QP_SQ_PSN) {
		OCTEP_RDMA_SET_FIELD(&qp_mod_attr->modify_mask, OCTEP_RDMA_QP_MOD_SQ_PSN, 1);
		qp_mod_attr->sq_psn = qp_attr->sq_psn;
	}

	if ((qp_attr_mask & IB_QP_PKEY_INDEX) && qp_attr->pkey_index) {
		OCTEP_RDMA_SET_FIELD(&qp_mod_attr->modify_mask, OCTEP_RDMA_QP_MOD_PKEY_INDEX, 1);
		qp_mod_attr->pkey_index = qp_attr->pkey_index;
	}

	if (qp_attr_mask & IB_QP_RETRY_CNT) {
		OCTEP_RDMA_SET_FIELD(&qp_mod_attr->modify_mask, OCTEP_RDMA_QP_MOD_RETRY_CNT, 1);
		qp_mod_attr->retry_cnt = qp_attr->retry_cnt;
	}

	if (qp_attr_mask & IB_QP_TIMEOUT) {
		if (qp_attr->timeout > 31) {
			ibdev_err(ibqp->device, "unsupported timeout=%d, supported<=31\n",
				  qp_attr->timeout);
			ret = -EINVAL;
			goto err;
		}
		OCTEP_RDMA_SET_FIELD(&qp_mod_attr->modify_mask, OCTEP_RDMA_QP_MOD_TIMEOUT, 1);
		qp_mod_attr->timeout = qp_attr->timeout;
	}

	if (qp_attr_mask & IB_QP_RNR_RETRY) {
		OCTEP_RDMA_SET_FIELD(&qp_mod_attr->modify_mask, OCTEP_RDMA_QP_MOD_RNR_RETRY, 1);
		qp_mod_attr->rnr_retry_cnt = qp_attr->rnr_retry;
	}

	if (qp_attr_mask & IB_QP_RQ_PSN) {
		OCTEP_RDMA_SET_FIELD(&qp_mod_attr->modify_mask, OCTEP_RDMA_QP_MOD_RQ_PSN, 1);
		qp_mod_attr->rq_psn = qp_attr->rq_psn;
	}

	if (qp_attr_mask & IB_QP_MAX_QP_RD_ATOMIC) {
		if (qp_attr->max_rd_atomic > rdma_dev->attr.max_qp_rd_atom) {
			ret = -EINVAL;
			ibdev_err(ibqp->device, "unsupported max_rd_atomic=%d, supported=%d\n",
				  qp_attr->max_rd_atomic, rdma_dev->attr.max_qp_rd_atom);
			goto err;
		}

		OCTEP_RDMA_SET_FIELD(&qp_mod_attr->modify_mask, OCTEP_RDMA_QP_MOD_MAX_QP_RD_ATOMIC,
				     1);
		qp_mod_attr->max_rd_atomic = qp_attr->max_rd_atomic;
	}

	if (qp_attr_mask & IB_QP_MIN_RNR_TIMER) {
		OCTEP_RDMA_SET_FIELD(&qp_mod_attr->modify_mask, OCTEP_RDMA_QP_MOD_MIN_RNR_TIMER, 1);
		qp_mod_attr->min_rnr_timer = qp_attr->min_rnr_timer;
	}

	if (qp_attr_mask & IB_QP_MAX_DEST_RD_ATOMIC) {
		if (qp_attr->max_dest_rd_atomic > rdma_dev->attr.max_res_rd_atom) {
			ibdev_err(ibqp->device, "unsupported max_dest_rd_atomic=%d, supported=%d\n",
				  qp_attr->max_dest_rd_atomic, rdma_dev->attr.max_res_rd_atom);

			ret = -EINVAL;
			goto err;
		}

		OCTEP_RDMA_SET_FIELD(&qp_mod_attr->modify_mask,
				     OCTEP_RDMA_QP_MOD_MAX_DEST_RD_ATOMIC, 1);
		qp_mod_attr->max_dest_rd_atomic = qp_attr->max_dest_rd_atomic;
	}

	if (qp_attr_mask & IB_QP_DEST_QPN) {
		OCTEP_RDMA_SET_FIELD(&qp_mod_attr->modify_mask, OCTEP_RDMA_QP_MOD_DEST_QPN, 1);
		qp_mod_attr->dest_qpn = qp_attr->dest_qp_num;
		qp->attrs.dest_qpn = qp_attr->dest_qp_num;
	}

	if (qp_attr_mask & IB_QP_ACCESS_FLAGS) {
		OCTEP_RDMA_SET_FIELD(&qp_mod_attr->modify_mask, OCTEP_RDMA_QP_MOD_ACCESS_FLAGS, 1);
		qp_mod_attr->qp_access_flags = qp_attr->qp_access_flags;
	}

	if (qp_attr_mask & IB_QP_PATH_MTU) {
		OCTEP_RDMA_SET_FIELD(&qp_mod_attr->modify_mask, OCTEP_RDMA_QP_MOD_PATH_MTU, 1);
		qp_mod_attr->path_mtu = qp_attr->path_mtu;
		qp->attrs.mtu = ib_mtu_enum_to_int(qp_attr->path_mtu);
		ibdev_info(ibqp->device, "path_mtu %d mtu %d\n", qp_mod_attr->path_mtu,
			   qp->attrs.mtu);
	}

	if ((qp_attr_mask & IB_QP_STATE) && qp->attrs.qp_type != IB_QPT_GSI &&
	    qp_mod_attr->new_qp_state == OCTEP_RDMA_QP_STATE_ERR) {
		ibdev_err(ibqp->device, "QP state change to error\n");
		qp->attrs.state = OCTEP_RDMA_QP_STATE_ERR;
	}

	if (qp_attr_mask & IB_QP_AV) {
		octep_rdma_init_av(&qp_attr->ah_attr, &qp->attrs.cur_av);
		OCTEP_RDMA_SET_FIELD(&qp_mod_attr->modify_mask, OCTEP_RDMA_QP_MOD_AV, 1);
		memcpy(&qp_mod_attr->mod_av, &qp->attrs.cur_av, sizeof(struct octep_rdma_av));
	}

	if ((qp_attr_mask & IB_QP_AV) && (qp_attr->ah_attr.ah_flags & IB_AH_GRH)) {
		OCTEP_RDMA_SET_FIELD(&qp_mod_attr->modify_mask, OCTEP_RDMA_QP_MOD_AV, 1);
		qp_mod_attr->src_udp_port = rdma_get_udp_sport(qp_attr->ah_attr.grh.flow_label,
							       qp->ibqp.qp_num, qp->attrs.dest_qpn);
	}

	/* Note: Not in spec, but need source port in octeon FW. */
	if (qp->ibqp.qp_type == IB_QPT_UD) {
		OCTEP_RDMA_SET_FIELD(&qp_mod_attr->modify_mask, OCTEP_RDMA_QP_MOD_SRC_PORT, 1);
		/* In case of UD, destination QP will be part of send WR. Hence taking a constant
		 * value here to get a unique UDP source port number.
		 */
		qp_mod_attr->src_udp_port = rdma_get_udp_sport(qp_attr->ah_attr.grh.flow_label,
							       qp->ibqp.qp_num, 0xDEADFACE);
	}

	if (qp_attr_mask & IB_QP_STATE) {
		if (qp->attrs.qp_type != IB_QPT_GSI)
			ret = octep_rdma_update_qp_state(qp,
							 octep_rdma_get_state_from_ibqp(cur_state),
							 octep_rdma_get_state_from_ibqp(new_state));
		qp->attrs.state = qp_mod_attr->new_qp_state;
	}

	ibdev_info(ibqp->device,
		   "[%s] qp_id %d modify_mask 0x%x new_state %d cur state %d qp_access_flags %x "
		   "path_mtu %d qkey %x pkey_index %d sq_drained_async_notify %d "
		   "max_dest_rd_atomic  %d max_rd_atomic %d min_rnr_timer %d rnr_retry_cnt %d "
		   "timeout %d port_num %d src_udp_port %d rq_psn %x sq_psn %x dst_qpn %d\n",
		   __func__, qp->ibqp.qp_num, qp_mod_attr->modify_mask, cur_state, new_state,
		   qp_mod_attr->qp_access_flags, qp_mod_attr->path_mtu, qp_mod_attr->qkey,
		   qp_mod_attr->pkey_index, qp_mod_attr->sq_drained_async_notify,
		   qp_mod_attr->max_dest_rd_atomic, qp_mod_attr->max_rd_atomic,
		   qp_mod_attr->min_rnr_timer, qp_mod_attr->rnr_retry_cnt, qp_mod_attr->timeout,
		   qp_mod_attr->port_num, qp_mod_attr->src_udp_port, qp_mod_attr->rq_psn,
		   qp_mod_attr->sq_psn, qp_mod_attr->dest_qpn);
err:
	return ret;
}
