/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Marvell.
 */

#include "octep_verbs.h"

static struct octep_rdma_cqe *
get_next_valid_cqe(struct octep_rdma_cq *cq)
{
	struct octep_rdma_cqe *cqe;

	if (!cq) {
		pr_err("%s: cq is NULL\n", __func__);
		return NULL;
	}

	cqe = get_queue_entry(cq->kern_cq.qbuf, cq->kern_cq.ci, cq->depth, CQE_SHIFT);
	if (!cqe) {
		pr_err("%s: Failed to get queue entry\n", __func__);
		return NULL;
	}

	return !!(cq->kern_cq.ci & cq->depth) ? cqe : NULL;
}

int
octep_rdma_poll_one_cqe(struct octep_rdma_cq *cq, struct ib_wc *wc)
{
	struct octep_rdma_cqe *cqe;

	cqe = get_next_valid_cqe(cq);
	if (!cqe) {
		ibdev_err(cq->ibcq.device, "No CQE\n");
		return -EAGAIN;
	}
	cq->kern_cq.ci++;

	/* cqbuf should be ready when we poll */
	dma_rmb();

	wc->wc_flags = 0;
	wc->wr_id = cqe->wr_id;
	wc->byte_len = be32_to_cpu(cqe->byte_len);
	wc->opcode = cqe->opcode;
	wc->status = cqe->status;
	if (wc->opcode == IB_WC_RECV_RDMA_WITH_IMM) {
		wc->ex.imm_data = cpu_to_be32(le32_to_cpu(cqe->imm_data));
		wc->wc_flags |= IB_WC_WITH_IMM;
	}

	ibdev_dbg(cq->ibcq.device, "opcode %x status %d wr_id %lld imm_data %x\n", cqe->opcode,
		  cqe->status, cqe->wr_id, cqe->imm_data);

	return 0;
}

int
octep_rdma_init_kernel_cq(struct octep_rdma_cq *cq)
{
	return 0;
}

int
octep_rdma_init_user_cq(struct octep_rdma_cq *cq, struct octep_rdma_ureq_create_cq *ureq)
{
	struct octep_rdma_dev *rdma_dev = to_octep_rdma_dev(cq->ibcq.device);
	uint64_t *pa;
	int ret;

	ret = setup_mem_trans_tbl(rdma_dev, &cq->user_cq.qbuf_mtt, ureq->qbuf_va, ureq->qbuf_len, 0,
				  ureq->qbuf_va, PAGE_SIZE, 1);
	if (ret)
		return ret;

	pa = cq->user_cq.qbuf_mtt.mtt_buf;

	ibdev_info(cq->ibcq.device, "[%s] cq->user_cq.qbuf_mtt.va: 0x%llx pa %llx\n", __func__,
		   cq->user_cq.qbuf_mtt.va, *pa);

	return ret;
}

int
octep_rdma_prepare_cq_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_cq *cq)
{
	struct octep_rdma_cq_create_req *cq_req;
	struct octep_rdma_cq_state_req *cq_state_req;
	int ret = 0;

	cq_req = kzalloc(sizeof(*cq_req), GFP_KERNEL);
	if (!cq_req)
		return -ENOMEM;

	cq_req->port_num = rdma_dev->port.port_num;
	cq_req->cq_id = cq->cqn;
	cq_req->size = cq->depth;
	cq_req->cq_base = cq->user_cq.qbuf_mtt.iova[0];

	ibdev_info(cq->ibcq.device, "[%s] ID %d size %d cq->user_cq_base: 0x%llx\n", __func__,
		   cq_req->cq_id, cq_req->size, cq_req->cq_base);

	ret = octep_rdma_mbox_cq_create(rdma_dev->caps_rgn, cq_req);
	if (ret) {
		ibdev_err(cq->ibcq.device, "octep_rdma_mbox_cq_create failed\n");
		goto err;
	}

	cq_state_req = kzalloc(sizeof(*cq_state_req), GFP_KERNEL);
	if (!cq_state_req) {
		ret = -ENOMEM;
		goto err;
	}

	cq_state_req->port_num = rdma_dev->port.port_num;
	cq_state_req->cq_id = cq->cqn;
	cq_state_req->enable = true;

	ret = octep_rdma_mbox_cq_state(rdma_dev->caps_rgn, cq_state_req);
	if (ret)
		ibdev_err(cq->ibcq.device, "octep_rdma_mbox_cq_state failed\n");

	kfree(cq_state_req);
err:
	kfree(cq_req);
	return ret;
}

int
octep_rdma_prepare_cq_destroy_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_cq *cq)
{
	struct octep_rdma_cq_state_req *cq_state_req;
	struct octep_rdma_cq_destroy_req *cq_dest;
	int ret = 0;

	cq_dest = kzalloc(sizeof(*cq_dest), GFP_KERNEL);
	if (!cq_dest)
		return -ENOMEM;

	cq_dest->cq_id = cq->cqn;
	cq_dest->port_num = rdma_dev->port.port_num;

	ret = octep_rdma_mbox_cq_destroy(rdma_dev->caps_rgn, cq_dest);
	if (ret) {
		ibdev_err(cq->ibcq.device, "octep_rdma_mbox_cq_destroy failed\n");
		goto err;
	}

	cq_state_req = kzalloc(sizeof(*cq_state_req), GFP_KERNEL);
	if (!cq_state_req) {
		ret = -ENOMEM;
		goto err;
	}

	cq_state_req->cq_id = cq->cqn;
	cq_state_req->enable = false;

	ret = octep_rdma_mbox_cq_state(rdma_dev->caps_rgn, cq_state_req);
	if (ret)
		ibdev_err(cq->ibcq.device, "octep_rdma_mbox_cq_state failed\n");

	kfree(cq_state_req);
err:
	kfree(cq_dest);
	return ret;
}
