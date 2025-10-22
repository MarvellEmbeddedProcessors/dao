/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Marvell.
 */

#include <rdma/uverbs_ioctl.h>

#include "octep_sdp.h"
#include "octep_verbs.h"

static int
octep_rdma_alloc_idx(struct octep_rdma_resource_cb *res_cb)
{
	int idx;
	unsigned long flags;

	spin_lock_irqsave(&res_cb->lock, flags);
	idx = find_next_zero_bit(res_cb->bitmap, res_cb->max_cap, res_cb->next_alloc_idx);
	if (idx == res_cb->max_cap) {
		/* Wrap around case.
		 *
		 * First zero will get position of the first 0th bit starting
		 * from LSB.
		 */
		idx = find_first_zero_bit(res_cb->bitmap, res_cb->max_cap);
		if (!idx || idx == res_cb->max_cap) {
			res_cb->next_alloc_idx = res_cb->start_idx;
			idx = find_next_zero_bit(res_cb->bitmap, res_cb->max_cap,
						 res_cb->next_alloc_idx);
			if (idx == res_cb->max_cap) {
				spin_unlock_irqrestore(&res_cb->lock, flags);
				return -ENOSPC;
			}
		}
	}

	set_bit(idx, res_cb->bitmap);
	res_cb->next_alloc_idx = idx + 1;
	spin_unlock_irqrestore(&res_cb->lock, flags);

	return idx;
}

static inline void
octep_rdma_free_idx(struct octep_rdma_resource_cb *res_cb, u32 idx)
{
	unsigned long flags;
	u32 used;

	spin_lock_irqsave(&res_cb->lock, flags);
	used = __test_and_clear_bit(idx, res_cb->bitmap);
	spin_unlock_irqrestore(&res_cb->lock, flags);
	WARN_ON(!used);
}

void
octep_rdma_disassociate_ucontext(struct ib_ucontext *ibcontext)
{
	ibdev_info(ibcontext->device, "%s: Disassociating RDMA ucontext\n", __func__);
}

int
octep_rdma_mmap(struct ib_ucontext *ibucontext, struct vm_area_struct *vma)
{
	struct octep_rdma_ucontext *uctx;
	struct rdma_user_mmap_entry *rdma_entry;
	size_t size;
	struct octep_rdma_user_mmap_entry *entry;
	u64 pfn;
	int err;

	if (!ibucontext || !vma) {
		pr_err("%s: NULL pointer parameter\n", __func__);
		return -EINVAL;
	}

	uctx = to_octep_rdma_ctx(ibucontext);
	size = vma->vm_end - vma->vm_start;

	if (vma->vm_start & (PAGE_SIZE - 1)) {
		ibdev_err(ibucontext->device, "mmap not page aligned\n");
		return -EINVAL;
	}

	rdma_entry = rdma_user_mmap_entry_get(&uctx->ibucontext, vma);
	if (!rdma_entry) {
		ibdev_err(ibucontext->device, "mmap lookup failed pgoff %lx size %ld\n",
			  vma->vm_pgoff, size);
		return -EINVAL;
	}

	entry = to_octep_rdma_mmap(rdma_entry);
	ibdev_dbg(ibucontext->device,
		  "Mapping address 0x%llx, npages %ld, mmap_flag %d at va 0x%lx\n", entry->address,
		  rdma_entry->npages, entry->mmap_flag, vma->vm_start);

	pfn = entry->address >> PAGE_SHIFT;
	switch (entry->mmap_flag) {
	case OCTEP_RDMA_MMAP_IO_NC:
		/* map doorbell. */
		err = rdma_user_mmap_io(&uctx->ibucontext, vma, pfn, rdma_entry->npages * PAGE_SIZE,
					pgprot_noncached(vma->vm_page_prot), rdma_entry);
		if (err) {
			ibdev_err(ibucontext->device, "rdma_user_mmap_io failed\n");
			goto put_entry;
		}

		break;
	default:
		err = -EINVAL;
		goto put_entry;
	}

	ibdev_dbg(ibucontext->device, "mmap success: entry %p vm_start 0x%lx, size %zu\n", entry,
		  vma->vm_start, size);

put_entry:
	rdma_user_mmap_entry_put(rdma_entry);
	return err;
}

void
octep_rdma_mmap_free(struct rdma_user_mmap_entry *rdma_entry)
{
	struct octep_rdma_user_mmap_entry *entry = to_octep_rdma_mmap(rdma_entry);

	kfree(entry);
}

static int
setup_db_region(struct octep_rdma_dev *rdma_dev, struct octep_rdma_ucontext *ctx,
		struct octep_rdma_uresp_alloc_ctx *uresp)
{
	int ret;

	if (!rdma_dev || !ctx || !uresp) {
		pr_err("%s: NULL parameters - rdma_dev=%p ctx=%p uresp=%p\n", __func__, rdma_dev,
		       ctx, uresp);
		return -EINVAL;
	}

	if (!rdma_dev->caps_rgn) {
		ibdev_err(&rdma_dev->ibdev, "caps_rgn is NULL\n");
		return -EINVAL;
	}

	ctx->db_region = rdma_dev->caps_rgn->notify_base_pa;
	if (!ctx->db_region) {
		ibdev_err(&rdma_dev->ibdev, "DB region not available\n");
		ret = -ENOMEM;
		goto fail;
	}

	uresp->db_region_sz = rdma_dev->caps_rgn->notify_sz;

	ctx->db_mmap_entry = octep_rdma_mmap_entry_insert(ctx, ctx->db_region, uresp->db_region_sz,
							  OCTEP_RDMA_MMAP_IO_NC, &uresp->db_region);
	if (!ctx->db_mmap_entry) {
		ibdev_err(&rdma_dev->ibdev, "DB mmap entry insert failed\n");
		ret = -ENOMEM;
		goto fail;
	}

	uresp->notify_off_multiplier = rdma_dev->caps_rgn->notify_off_multiplier;
	ibdev_dbg(&rdma_dev->ibdev, "DB region 0x%llx entry %p size %lld resp->db 0x%llx\n",
		  ctx->db_region, ctx->db_mmap_entry, uresp->db_region_sz, uresp->db_region);

	return 0;
fail:
	return ret;
}

int
octep_rdma_alloc_ucontext(struct ib_ucontext *ibucontext, struct ib_udata *udata)
{
	struct octep_rdma_ucontext *ctx = to_octep_rdma_ctx(ibucontext);
	struct octep_rdma_dev *rdma_dev = to_octep_rdma_dev(ibucontext->device);
	int ret;
	struct octep_rdma_uresp_alloc_ctx uresp = {};

	ibdev_info(ibucontext->device, "%s: Allocating RDMA ucontext\n", __func__);
	if (atomic_inc_return(&rdma_dev->num_ctx) > OCTEP_RDMA_MAX_CONTEXT)
		return -ENOMEM;

	uresp.dev_id = rdma_dev->pdev->device;
	ctx->rdma_dev = rdma_dev;

	ret = setup_db_region(rdma_dev, ctx, &uresp);
	if (ret) {
		ibdev_err(ibucontext->device, "setup_db_region failed\n");
		goto err_out;
	}
	ret = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
	if (ret)
		goto err_out;

	ibdev_info(ibucontext->device, "%s: success\n", __func__);
	return 0;
err_out:
	ibdev_info(ibucontext->device, "%s: failed\n", __func__);
	atomic_dec(&rdma_dev->num_ctx);
	return ret;
}

void
octep_rdma_dealloc_ucontext(struct ib_ucontext *ibucontext)
{
	struct octep_rdma_dev *rdma_dev = to_octep_rdma_dev(ibucontext->device);
	struct octep_rdma_ucontext *ctx = to_octep_rdma_ctx(ibucontext);

	atomic_dec(&rdma_dev->num_ctx);
	rdma_user_mmap_entry_remove(ctx->db_mmap_entry);
}

int
octep_rdma_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct octep_rdma_dev *rdma_dev = to_octep_rdma_dev(ibpd->device);
	struct octep_rdma_pd *pd = to_octep_rdma_pd(ibpd);
	int pdn, ret;

	pdn = octep_rdma_alloc_idx(&rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_PD]);
	if (pdn < 0)
		return pdn;

	pd->pdn = pdn;
	ibdev_info(ibpd->device, "Allocated PD %d\n", pd->pdn);

	pd->mr_res_cb.start_idx = 1;
	pd->mr_res_cb.next_alloc_idx = 1;
	pd->mr_res_cb.max_cap = rdma_dev->attr.max_mr;
	spin_lock_init(&pd->mr_res_cb.lock);
	pd->mr_res_cb.bitmap = bitmap_zalloc(pd->mr_res_cb.max_cap, GFP_KERNEL);
	if (!pd->mr_res_cb.bitmap) {
		ret = -ENOMEM;
		goto error;
	}

	ret = octep_rdma_prepare_pd_add_cmd(rdma_dev, pd->pdn);
	if (ret) {
		ibdev_err(ibpd->device, "octep_rdma_prepare_pd_add_cmd failed\n");
		goto error_bitmap;
	}

	if (udata) {
		struct octep_rdma_uresp_alloc_pd resp = {.pdn = pd->pdn};

		ret = ib_copy_to_udata(udata, &resp, min(udata->outlen, sizeof(resp)));
		if (ret) {
			ibdev_err(ibpd->device, "PD -- failed to copy to udata, ret = %d\n", ret);
			octep_rdma_prepare_pd_del_cmd(rdma_dev, pd->pdn);
			goto error_bitmap;
		}
	}

	return 0;

error_bitmap:
	bitmap_free(pd->mr_res_cb.bitmap);
error:
	octep_rdma_free_idx(&rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_PD], pd->pdn);
	return ret;
}

int
octep_rdma_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct octep_rdma_dev *rdma_dev = to_octep_rdma_dev(ibpd->device);
	struct octep_rdma_pd *pd = to_octep_rdma_pd(ibpd);
	int ret;

	ret = octep_rdma_prepare_pd_del_cmd(rdma_dev, pd->pdn);
	if (ret) {
		ibdev_err(ibpd->device, "octep_rdma_prepare_pd_del_cmd failed\n");
		return ret;
	}

	ibdev_info(ibpd->device, "Deallocating PD %d\n", pd->pdn);
	octep_rdma_free_idx(&rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_PD], pd->pdn);

	return 0;
}

int
octep_rdma_add_gid(const struct ib_gid_attr *attr, void **context)
{
	int ret = 0;

	ibdev_info(attr->device, "[%s:%d] GID index %d type %d raw bytes %pI6\n", __func__,
		   __LINE__, attr->index, attr->gid_type, attr->gid.raw);

	/* FIXME - ADD GID command to octeon */

	return ret;
}

int
octep_rdma_del_gid(const struct ib_gid_attr *attr, void **context)
{
	ibdev_info(attr->device, "[%s:%d] GID index %d type %d raw bytes %pI6\n", __func__,
		   __LINE__, attr->index, attr->gid_type, attr->gid.raw);

	/* FIXME - Delete GID command to octeon */

	return 0;
}

int
octep_rdma_query_device(struct ib_device *ibdev, struct ib_device_attr *attr,
			struct ib_udata *udata)
{
	struct octep_rdma_dev *rdma_dev = to_octep_rdma_dev(ibdev);
	int err;

	if (udata->inlen || udata->outlen) {
		dev_err(&rdma_dev->pdev->dev, "Invalid udata\n");
		err = -EINVAL;
		goto err_out;
	}

	memcpy(attr, &rdma_dev->attr, sizeof(*attr));

	attr->vendor_id = PCI_VENDOR_ID_CAVIUM;
	attr->vendor_part_id = rdma_dev->pdev->device;
	attr->hw_ver = rdma_dev->pdev->revision;

	return 0;

err_out:
	dev_err(&rdma_dev->pdev->dev, "returned err = %d\n", err);
	return err;
}

int
octep_rdma_query_port(struct ib_device *ibdev, u32 port, struct ib_port_attr *attr)
{
	struct octep_rdma_dev *rdma_dev = to_octep_rdma_dev(ibdev);
	struct net_device *ndev = rdma_dev->netdev;
	int ret;

	if (port != 1) {
		ret = -EINVAL;
		dev_err(&rdma_dev->pdev->dev, "Invalid port number %d\n", port);
		goto err_out;
	}

	memset(attr, 0, sizeof(*attr));
	/* FIXME - Get from device */
	memcpy(attr, &rdma_dev->port.attr, sizeof(*attr));

	attr->port_cap_flags = IB_PORT_CM_SUP | IB_PORT_DEVICE_MGMT_SUP;
	attr->max_msg_sz = -1;

	if (!ndev)
		goto out;

	ib_get_eth_speed(ibdev, port, &attr->active_speed, &attr->active_width);
	attr->max_mtu = ib_mtu_int_to_enum(ndev->mtu);
	attr->active_mtu = ib_mtu_int_to_enum(ndev->mtu);
	if (netif_running(ndev) && netif_carrier_ok(ndev))
		rdma_dev->port.state = IB_PORT_ACTIVE;
	else
		rdma_dev->port.state = IB_PORT_DOWN;
	attr->state = rdma_dev->port.state;

out:
	if (rdma_dev->port.state == IB_PORT_ACTIVE)
		attr->phys_state = IB_PORT_PHYS_STATE_LINK_UP;
	else
		attr->phys_state = IB_PORT_PHYS_STATE_DISABLED;
	return 0;
err_out:
	dev_err(&rdma_dev->pdev->dev, "returned err = %d\n", ret);
	return ret;
}

int
octep_rdma_get_port_immutable(struct ib_device *ibdev, u32 port_num,
			      struct ib_port_immutable *immutable)
{
	struct ib_port_attr attr = {};
	int err;

	if (port_num != 1) {
		err = -EINVAL;
		ibdev_err(ibdev, "bad port_num = %d", port_num);
		goto err_out;
	}

	err = ib_query_port(ibdev, port_num, &attr);
	if (err)
		goto err_out;

	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len = attr.gid_tbl_len;
	immutable->core_cap_flags = RDMA_CORE_CAP_PROT_ROCE_UDP_ENCAP;

	return 0;
err_out:
	return err;
}

enum rdma_link_layer
octep_rdma_get_link_layer(struct ib_device *ibdev, u32 port_num)
{
	return IB_LINK_LAYER_ETHERNET;
}

int
octep_rdma_query_pkey(struct ib_device *ibdev, u32 port, u16 index, u16 *pkey)
{
	/* FIXME - Proper way */
	*pkey = 0xffff;

	return 0;
}

struct ib_mr *
octep_rdma_get_dma_mr(struct ib_pd *ibpd, int access)
{
	/* FIXME: TBD */
	return NULL;
}

struct ib_mr *
octep_rdma_reg_user_mr(struct ib_pd *ibpd, u64 start, u64 length, u64 iova, int access,
		       struct ib_udata *udata)
{
	struct octep_rdma_dev *rdma_dev = to_octep_rdma_dev(ibpd->device);
	struct octep_rdma_pd *pd = to_octep_rdma_pd(ibpd);
	struct octep_rdma_mr *mr;
	uint64_t *pa;
	int ret, mrn;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	mrn = octep_rdma_alloc_idx(&pd->mr_res_cb);
	if (mrn < 0) {
		kfree(mr);
		return ERR_PTR(mrn);
	}

	mr->ibmr.pd = ibpd;
	mr->ibmr.device = ibpd->device;
	mr->mrn = (u32)mrn;
	octep_rdma_mr_init(access, mr, mr->mrn);

	ret = setup_mem_trans_tbl(rdma_dev, &mr->mrbuf_mtt, start, length, access, iova, PAGE_SIZE,
				  0);
	if (ret) {
		ibdev_err(ibpd->device, "memory translation table for MR failed.\n");
		goto error;
	}

	ret = octep_rdma_prepare_mr_register_cmd(rdma_dev, mr, pd->pdn);
	if (ret) {
		ibdev_err(ibpd->device, "octep_rdma_prepare_mr_reg_cmd failed\n");
		release_mem_trans_tbl(rdma_dev, &mr->mrbuf_mtt);
		goto error;
	}

	pa = mr->mrbuf_mtt.mtt_entry;
	ibdev_info(ibpd->device, "mrmbuf_mtt.va %llx mrbuff_mtt.pa %llx\n", mr->mrbuf_mtt.va, *pa);

	return &mr->ibmr;
error:
	octep_rdma_free_idx(&pd->mr_res_cb, mr->mrn);
	kfree(mr);
	return ERR_PTR(ret);
}

int
octep_rdma_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata)
{
	struct octep_rdma_dev *rdma_dev = to_octep_rdma_dev(ibmr->device);
	struct octep_rdma_mr *mr = to_octep_rdma_mr(ibmr);
	struct octep_rdma_pd *pd = to_octep_rdma_pd(mr->ibmr.pd);
	int ret = 0;

	ret = octep_rdma_prepare_mr_deregister_cmd(rdma_dev, mr, pd->pdn);
	if (ret) {
		ibdev_err(ibmr->device, "octep_rdma_prepare_mr_deregister_cmd failed\n");
		return ret;
	}

	if (!rdma_is_kernel_res(&ibmr->res))
		release_mem_trans_tbl(rdma_dev, &mr->mrbuf_mtt);

	if (atomic_read(&mr->num_mw) > 0) {
		ibdev_err(ibmr->device, "mr has mw's bound");
		ret = -EINVAL;
	}

	octep_rdma_free_idx(&pd->mr_res_cb, mr->mrn);
	kfree_rcu_mightsleep(mr);

	return ret;
}

int
octep_rdma_create_cq(struct ib_cq *ibcq, const struct ib_cq_init_attr *init_attr,
		     struct ib_udata *udata)
{
	struct octep_rdma_cq *cq;
	struct octep_rdma_dev *rdma_dev;
	unsigned int depth = init_attr->cqe;
	int ret, cqn;

	cq = to_octep_rdma_cq(ibcq);
	if (!cq) {
		ibdev_info(ibcq->device, "cq is NULL\n");
		return -EINVAL;
	}

	rdma_dev = to_octep_rdma_dev(ibcq->device);
	if (!rdma_dev) {
		ibdev_info(ibcq->device, "rdma_dev is NULL\n");
		return -EINVAL;
	}
	if (depth > rdma_dev->attr.max_cqe)
		return -EINVAL;

	depth = roundup_pow_of_two(depth + 1);
	cq->ibcq.cqe = depth;
	cq->depth = depth;
	cq->assoc_eqn = init_attr->comp_vector + 1;

	cqn = octep_rdma_alloc_idx(&rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_CQ]);
	if (cqn < 0)
		return cqn;

	cq->cqn = cqn;
	ibdev_info(ibcq->device, "[%s:%d] max_cq %d cqn %d next_alloc_cqn %d\n", __func__, __LINE__,
		   rdma_dev->attr.max_cq, cq->cqn,
		   rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_CQ].next_alloc_idx);

	if (!rdma_is_kernel_res(&ibcq->res)) {
		struct octep_rdma_ureq_create_cq ureq;
		struct octep_rdma_uresp_create_cq uresp;

		ret = ib_copy_from_udata(&ureq, udata, min(udata->inlen, sizeof(ureq)));
		if (ret)
			goto err_out_xa;

		ibdev_info(ibcq->device, "[%s %d] qbuf_va 0x%llx size %x\n", __func__, __LINE__,
			   ureq.qbuf_va, ureq.qbuf_len);
		ret = octep_rdma_init_user_cq(cq, &ureq);
		if (ret)
			goto err_out_xa;

		uresp.cq_id = cq->cqn;
		uresp.num_cqe = depth;

		ret = ib_copy_to_udata(udata, &uresp, min(sizeof(uresp), udata->outlen));
		if (ret)
			goto err_free_res;

		ibdev_info(ibcq->device, "[%s:%d] User cq->cqn %d depth %d\n", __func__, __LINE__,
			   cq->cqn, depth);
	} else {
		ret = octep_rdma_init_kernel_cq(cq);
		if (ret)
			goto err_out_xa;
		ibdev_info(ibcq->device, "[%s:%d] Kernel cq->cqn %d\n", __func__, __LINE__,
			   cq->cqn);
	}

	ret = octep_rdma_prepare_cq_cmd(rdma_dev, cq);
	if (ret) {
		ibdev_err(ibcq->device, "octep_rdma_prepare_cq_cmd failed\n");
		goto err_free_res;
	}

	return 0;

err_free_res:
	if (!rdma_is_kernel_res(&ibcq->res)) {
		release_mem_trans_tbl(rdma_dev, &cq->user_cq.qbuf_mtt);
	} else {
		dma_free_coherent(&rdma_dev->pdev->dev, WARPPED_BUFSIZE(depth << CQE_SHIFT),
				  cq->kern_cq.qbuf, cq->kern_cq.qbuf_dma_addr);
	}

err_out_xa:
	octep_rdma_free_idx(&rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_CQ], cq->cqn);

	return ret;
}

int
octep_rdma_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc)
{
	struct octep_rdma_cq *cq = to_octep_rdma_cq(ibcq);
	unsigned long flags;
	int npolled, ret;

	spin_lock_irqsave(&cq->kern_cq.lock, flags);
	for (npolled = 0; npolled < num_entries;) {
		ret = octep_rdma_poll_one_cqe(cq, wc + npolled);

		if (ret == -EAGAIN) /* no received new CQEs. */
			break;
		else if (ret) /* ignore invalid CQEs. */
			continue;

		npolled++;
	}
	spin_unlock_irqrestore(&cq->kern_cq.lock, flags);
	ibdev_info(ibcq->device, "[%s:%d] num_entries %d completed\n", __func__, __LINE__, npolled);

	return npolled;
}

int
octep_rdma_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags)
{
	return 0;
}

int
octep_rdma_destroy_cq(struct ib_cq *ibcq, struct ib_udata *udata)
{
	struct octep_rdma_cq *cq = to_octep_rdma_cq(ibcq);
	struct octep_rdma_dev *rdma_dev = to_octep_rdma_dev(ibcq->device);
	struct octep_rdma_cmdq_destroy_cq_req req = {};
	int ret = 0;

	req.cqn = cq->cqn;

	ret = octep_rdma_prepare_cq_destroy_cmd(rdma_dev, cq);
	if (ret) {
		ibdev_err(ibcq->device, "octep_rdma_prepare_cq_cmd failed, ret %d\n", ret);
		return ret;
	}

	ibdev_info(ibcq->device, "[%s:%d] cq->cqn %d\n", __func__, __LINE__, cq->cqn);
	if (rdma_is_kernel_res(&cq->ibcq.res)) {
		dma_free_coherent(&rdma_dev->pdev->dev, WARPPED_BUFSIZE(cq->depth << CQE_SHIFT),
				  cq->kern_cq.qbuf, cq->kern_cq.qbuf_dma_addr);
	} else {
		release_mem_trans_tbl(rdma_dev, &cq->user_cq.qbuf_mtt);
	}

	octep_rdma_free_idx(&rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_CQ], cq->cqn);

	return 0;
}

int
octep_rdma_create_qp(struct ib_qp *ibqp, struct ib_qp_init_attr *attrs, struct ib_udata *udata)
{
	struct octep_rdma_qp *qp = to_octep_rdma_qp(ibqp);
	struct octep_rdma_dev *rdma_dev;
	struct octep_rdma_ucontext *uctx;
	struct octep_rdma_pd *pd;
	int ret, qpn;

	if (!qp) {
		pr_err("%s: Failed to convert ibqp to octep_rdma_qp\n", __func__);
		return -EINVAL;
	}

	rdma_dev = to_octep_rdma_dev(ibqp->device);
	if (!rdma_dev) {
		pr_err("%s: Failed to get rdma_dev from ibqp->device\n", __func__);
		return -EINVAL;
	}

	uctx = rdma_udata_to_drv_context(udata, struct octep_rdma_ucontext, ibucontext);
	pd = to_octep_rdma_pd(qp->ibqp.pd);
	if (!pd) {
		ibdev_err(&rdma_dev->ibdev, "Failed to get PD from qp\n");
		return -EINVAL;
	}

	ret = octep_rdma_qp_validate_cap(rdma_dev, attrs);
	if (ret) {
		ibdev_err(ibqp->device, "QP cap validation failed\n");
		goto err_out;
	}

	ret = octep_rdma_qp_validate_attr(rdma_dev, attrs);
	if (ret) {
		ibdev_err(ibqp->device, "QP attr validation failed\n");
		goto err_out;
	}

	qp->scq = to_octep_rdma_cq(attrs->send_cq);
	qp->rcq = to_octep_rdma_cq(attrs->recv_cq);
	qp->rdma_dev = rdma_dev;

	init_rwsem(&qp->state_lock);
	kref_init(&qp->ref);
	init_completion(&qp->safe_free);

	qpn = octep_rdma_alloc_idx(&rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_QP]);
	if (qpn < 0) {
		ret = qpn;
		ibdev_err(ibqp->device, "Failed to allocate QP index, ret %d\n", ret);
		goto err_out;
	}

	qp->ibqp.qp_num = qpn;
	ibdev_info(ibqp->device, "[%s] max_qp %d qp_num %d next_alloc_qpn %d\n", __func__,
		   rdma_dev->attr.max_qp, qp->ibqp.qp_num,
		   rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_QP].next_alloc_idx);

	if (uctx) {
		ret = init_user_qp(rdma_dev, qp, udata);
		if (ret) {
			ibdev_err(ibqp->device, "init_user_qp failed\n");
			goto err_out_xa;
		}
	} else {
		ret = init_kernel_qp(rdma_dev, qp, attrs);
		if (ret) {
			ibdev_err(ibqp->device, "init_kernel_qp failed\n");
			goto err_out_xa;
		}
	}

	qp->attrs.max_send_sge = attrs->cap.max_send_sge;
	qp->attrs.max_recv_sge = attrs->cap.max_recv_sge;
	qp->attrs.state = OCTEP_RDMA_QP_STATE_RESET;
	qp->attrs.qp_type = attrs->qp_type;
	qp->attrs.sq_sig_type = attrs->sq_sig_type;

	ret = octep_rdma_prepare_qp_cmd(rdma_dev, qp, pd->pdn);
	if (ret) {
		ibdev_err(ibqp->device, "octep_rdma_prepare_qp_cmd failed\n");
		goto err_out_cmd;
	}

	spin_lock_init(&qp->lock);

	return 0;
err_out_cmd:
	if (uctx) {
		release_mem_trans_tbl(qp->rdma_dev, &qp->user_qp.rq_mtt);
		release_mem_trans_tbl(qp->rdma_dev, &qp->user_qp.sq_mtt);
		vunmap(qp->user_qp.sq_vaddr);
		vunmap(qp->user_qp.rq_vaddr);
	} else {
		free_kernel_qp(qp);
	}

err_out_xa:
	octep_rdma_free_idx(&rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_QP], qp->ibqp.qp_num);
err_out:
	ibdev_err(ibqp->device, "[%s] returned err = %d\n", __func__, ret);
	return ret;
}

int
octep_rdma_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr, int qp_attr_mask,
		     struct ib_udata *udata)
{
	struct octep_rdma_qp *qp = to_octep_rdma_qp(ibqp);
	struct octep_rdma_qp_mod_attrs qp_mod_attr;
	int ret = 0;

	if (!qp) {
		pr_err("%s: Failed to convert ibqp to octep_rdma_qp\n", __func__);
		return -EINVAL;
	}

	if (qp_attr_mask & ~IB_QP_ATTR_STANDARD_BITS)
		return -EOPNOTSUPP;

	if (udata->inlen && !ib_is_udata_cleared(udata, 0, udata->inlen)) {
		ibdev_err(ibqp->device, "Incompatible ABI params, udata not cleared\n");
		return -EINVAL;
	}

	if (!qp->attrs.qp_mod_attr) {
		qp->attrs.qp_mod_attr = kzalloc(sizeof(*qp->attrs.qp_mod_attr), GFP_KERNEL);
		if (!qp->attrs.qp_mod_attr)
			return -ENOMEM;
	}

	ret = octep_rdma_modify_qp_validate(qp, qp_attr, qp_attr_mask);
	if (ret) {
		ibdev_err(ibqp->device, "Invalid modify QP parameters\n");
		return -EINVAL;
	}

	memset(&qp_mod_attr, 0, sizeof(struct octep_rdma_qp_mod_attrs));
	down_write(&qp->state_lock);

	ret = octep_rdma_modify_qp_attr_populate(qp, qp_attr, qp_attr_mask, &qp_mod_attr);

	memcpy(qp->attrs.qp_mod_attr, &qp_mod_attr, sizeof(struct octep_rdma_qp_mod_attrs));
	up_write(&qp->state_lock);

	if (qp->attrs.state == OCTEP_RDMA_QP_STATE_RTR ||
	    qp->attrs.state == OCTEP_RDMA_QP_STATE_RTS) {
		ret = octep_rdma_prepare_qp_state_cmd(qp->rdma_dev, qp, true);
		if (ret) {
			ibdev_err(ibqp->device, "octep_rdma_prepare_qp_state_cmd failed\n");
			return ret;
		}
	}

	ret = octep_rdma_prepare_user_qp_modify_cmd(qp->rdma_dev, qp);
	if (ret) {
		ibdev_err(ibqp->device, "octep_rdma_user_qp_modify_cmd failed\n");
		return ret;
	}

	return ret;
}

int
octep_rdma_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr, int qp_attr_mask,
		    struct ib_qp_init_attr *qp_init_attr)
{
	struct octep_rdma_qp *qp;
	struct octep_rdma_dev *dev;

	if (ibqp && qp_attr && qp_init_attr) {
		qp = to_octep_rdma_qp(ibqp);
		dev = to_octep_rdma_dev(ibqp->device);
	} else {
		return -EINVAL;
	}

	qp_attr->cap.max_inline_data = OCTEP_RDMA_MAX_INLINE;
	qp_init_attr->cap.max_inline_data = OCTEP_RDMA_MAX_INLINE;

	qp_attr->cap.max_send_wr = qp->attrs.sq_size;
	qp_attr->cap.max_recv_wr = qp->attrs.rq_size;
	qp_attr->cap.max_send_sge = qp->attrs.max_send_sge;
	qp_attr->cap.max_recv_sge = qp->attrs.max_recv_sge;

	qp_attr->path_mtu = ib_mtu_int_to_enum(dev->netdev->mtu);
	qp_attr->max_rd_atomic = qp->attrs.irq_size;
	qp_attr->max_dest_rd_atomic = qp->attrs.orq_size;

	qp_attr->qp_access_flags =
		IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ;

	qp_init_attr->cap = qp_attr->cap;

	return 0;
}

int
octep_rdma_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata)
{
	struct octep_rdma_qp *qp = to_octep_rdma_qp(ibqp);
	struct octep_rdma_dev *rdma_dev = to_octep_rdma_dev(ibqp->device);
	struct octep_rdma_ucontext *ctx =
		rdma_udata_to_drv_context(udata, struct octep_rdma_ucontext, ibucontext);
	int ret = 0;

	ibdev_info(ibqp->device, "Destroying qp->ibqp.qp_num %d\n", qp->ibqp.qp_num);

	ret = octep_rdma_prepare_user_qp_destroy_cmd(qp->rdma_dev, qp);
	if (ret) {
		ibdev_err(ibqp->device, "octep_rdma_user_qp_destroy_cmd failed: ret %d\n", ret);
		return ret;
	}

	ret = octep_rdma_prepare_qp_state_cmd(qp->rdma_dev, qp, false);
	if (ret) {
		ibdev_err(ibqp->device, "octep_rdma_prepare_qp_state_cmd failed, ret %d\n", ret);
		return ret;
	}

	if (rdma_is_kernel_res(&qp->ibqp.res)) {
		vfree(qp->kern_qp.swr_tbl);
		vfree(qp->kern_qp.rwr_tbl);
		dma_free_coherent(&rdma_dev->pdev->dev,
				  WARPPED_BUFSIZE(qp->attrs.rq_size << RQE_SHIFT),
				  qp->kern_qp.rq_buf, qp->kern_qp.rq_buf_dma_addr);
		dma_free_coherent(&rdma_dev->pdev->dev,
				  WARPPED_BUFSIZE(qp->attrs.sq_size << SQEBB_SHIFT),
				  qp->kern_qp.sq_buf, qp->kern_qp.sq_buf_dma_addr);
	} else {
		if (ctx) {
			release_mem_trans_tbl(qp->rdma_dev, &qp->user_qp.rq_mtt);
			release_mem_trans_tbl(qp->rdma_dev, &qp->user_qp.sq_mtt);
			vunmap(qp->user_qp.sq_vaddr);
			vunmap(qp->user_qp.rq_vaddr);
		}
	}

	octep_rdma_free_idx(&rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_QP], qp->ibqp.qp_num);
	kfree(qp->attrs.qp_mod_attr);

	return 0;
}

int
octep_rdma_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
		     const struct ib_send_wr **bad_wr)
{
	struct octep_rdma_qp *qp = to_octep_rdma_qp(ibqp);
	union octep_rdma_sqe *sqe;
	int ret;
	u32 idx;

	if (wr && !rdma_is_kernel_res(&qp->ibqp.res)) {
		ibdev_err(ibqp->device, "wr must be empty for user mapped sq\n");
		*bad_wr = wr;
		return -EINVAL;
	}

	dma_wmb();
	idx = qp->sq_get % qp->attrs.sq_size;
	sqe = (union octep_rdma_sqe *)(qp->user_qp.sq_vaddr) + idx;

	if (!sqe) {
		ibdev_err(ibqp->device, "sqe is NULL: idx %d\n", idx);
		return -EINVAL;
	}

	if (!sqe->flags) {
		ibdev_err(ibqp->device, "SQE empty: idx %d flags %x\n", idx, sqe->flags);
		print_hex_dump(KERN_ERR, "SQE: ", DUMP_PREFIX_OFFSET, 16, 1, sqe, sizeof(*sqe),
			       true);
		return -EINVAL;
	}

	ibdev_dbg(ibqp->device,
		  "[%s] wr_id %lld num_sges %d ci %d flags %x opcode %d ah_num %d "
		  "remote_qpn %d qkey %x sge[0].addr %llx sge[0].len %d\n",
		  __func__, sqe->wr_id, sqe->num_sges, qp->sq_get, sqe->flags, sqe->opcode,
		  sqe->ud.ah, sqe->ud.remote_qpn, sqe->ud.qkey, sqe->sges0[0].addr,
		  sqe->sges0[0].length);

	/* Send the SQE to the device */
	ret = octep_tx(qp->rdma_dev->octep_dev, 1, sqe);
	if (ret) {
		ibdev_err(ibqp->device, "octep_tx failed: err %d\n", ret);
		if (ret == -EFAULT) {
			ibdev_err(ibqp->device, "idx %d ci %d sq_size %d\n", idx, qp->sq_get,
				  qp->attrs.sq_size);
		}
	}

	/* Clear SQE flags */
	smp_store_mb(sqe->flags, 0);
	qp->sq_get++;
	return 0;
}

int
octep_rdma_post_recv(struct ib_qp *ibqp, const struct ib_recv_wr *recv_wr,
		     const struct ib_recv_wr **bad_wr)
{
	struct octep_rdma_qp *qp = to_octep_rdma_qp(ibqp);
	union octep_rdma_rqe *rqe;
	u32 idx;

	if (recv_wr && !rdma_is_kernel_res(&qp->ibqp.res)) {
		ibdev_err(ibqp->device, "wr must be empty for user mapped sq\n");
		*bad_wr = recv_wr;
		return -EINVAL;
	}

	/* Send the SQE to the device */
	idx = qp->rq_get % qp->attrs.rq_size;
	rqe = (union octep_rdma_rqe *)(qp->user_qp.rq_vaddr) + idx;

	ibdev_dbg(ibqp->device,
		  "[%s] idx %d rq_get %d  rqe %p wr_id %lld "
		  "rq_get %d flags %xsge[0].addr %llx sge[0].len %d\n",
		  __func__, idx, qp->rq_get, rqe, rqe->wr_id, qp->rq_get, rqe->flags,
		  rqe->sges0[0].addr, rqe->sges0[0].length);
	if (octep_oq_fill_ring_buffers_custom(qp->rdma_dev->octep_dev, 1, rqe, idx)) {
		ibdev_err(ibqp->device, "ring buffer fill failed\n");
		return -EFAULT;
	}
	qp->rq_get++;

	/* Memory barrier */
	smp_store_mb(rqe->flags, 0);

	/* Clear SQE flags */
	return 0;
}

/* ah */
int
octep_rdma_create_ah(struct ib_ah *ibah, struct rdma_ah_init_attr *init_attr,
		     struct ib_udata *udata)
{
	struct octep_rdma_dev *rdma_dev = to_octep_rdma_dev(ibah->device);
	struct octep_rdma_ah *ah = to_octep_rdma_ah(ibah);
	struct octep_rdma_create_ah_resp __user *uresp = NULL;
	u32 ah_num;
	int err;

	if (udata) {
		/* test if new user provider */
		if (udata->outlen >= sizeof(*uresp))
			uresp = udata->outbuf;
		ah->is_user = true;
	} else {
		ah->is_user = false;
	}

	ah_num = octep_rdma_alloc_idx(&rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_AH]);
	if (ah_num < 0)
		return ah_num;

	ah->ah_num = ah_num;
	ibdev_info(ibah->device, "[%s:%d] ah_num %d\n", __func__, __LINE__, ah->ah_num);
	err = octep_rdma_ah_chk_attr(ah, init_attr->ah_attr);
	if (err) {
		ibdev_err(ibah->device, "Failed to check attribute, err = %d\n", err);
		goto err_cleanup;
	}

	if (uresp) {
		/* only if new user provider */
		err = copy_to_user(&uresp->ah_num, &ah->ah_num, sizeof(uresp->ah_num));
		if (err) {
			err = -EFAULT;
			ibdev_err(ibah->device, "failed to copy to udata, err = %d\n", err);
			goto err_cleanup;
		}
	} else if (ah->is_user) {
		/* only if old user provider */
		ah->ah_num = 0;
	}

	octep_rdma_init_av(init_attr->ah_attr, &ah->av);

	if (octep_rdma_prepare_ah_cmd(rdma_dev, ah, &ah->av, AH_CREATE)) {
		err = -ENOMEM;
		ibdev_err(ibah->device, "Failed to prepare AH command, err = %d\n", err);
		goto err_cleanup;
	}

	return 0;

err_cleanup:
	octep_rdma_free_idx(&rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_AH], ah->ah_num);
	ibdev_err(&rdma_dev->ibdev, "returned err = %d", err);
	return err;
}

int
octep_rdma_modify_ah(struct ib_ah *ibah, struct rdma_ah_attr *attr)
{
	struct octep_rdma_dev *rdma_dev = to_octep_rdma_dev(ibah->device);
	struct octep_rdma_ah *ah = to_octep_rdma_ah(ibah);
	int err;

	err = octep_rdma_ah_chk_attr(ah, attr);
	if (err) {
		ibdev_err(ibah->device, "bad attr");
		goto err_out;
	}

	octep_rdma_init_av(attr, &ah->av);
	if (octep_rdma_prepare_ah_cmd(rdma_dev, ah, &ah->av, AH_MODIFY)) {
		err = -ENOMEM;
		ibdev_err(ibah->device, "Failed to prepare AH modify command, err = %d\n", err);
		goto err_out;
	}

	return 0;

err_out:
	return err;
}

int
octep_rdma_query_ah(struct ib_ah *ibah, struct rdma_ah_attr *attr)
{
	struct octep_rdma_ah *ah = to_octep_rdma_ah(ibah);

	memset(attr, 0, sizeof(*attr));
	attr->type = ibah->type;
	octep_rdma_av_to_attr(&ah->av, attr);

	return 0;
}

int
octep_rdma_destroy_ah(struct ib_ah *ibah, u32 flags)
{
	struct octep_rdma_dev *rdma_dev = to_octep_rdma_dev(ibah->device);
	struct octep_rdma_ah *ah = to_octep_rdma_ah(ibah);
	int ret;

	if (!ah) {
		ibdev_err(ibah->device, "ah is NULL\n");
		return -EINVAL;
	}

	ret = octep_rdma_prepare_ah_destroy_cmd(rdma_dev, ah);
	if (ret)
		ibdev_err(ibah->device, "Failed to prepare AH destroy command, ret = %d\n", ret);

	ibdev_info(ibah->device, "[%s:%d] ah->ah_num %d\n", __func__, __LINE__, ah->ah_num);
	octep_rdma_free_idx(&rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_AH], ah->ah_num);

	return 0;
}
