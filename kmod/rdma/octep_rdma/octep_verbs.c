/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Marvell.
 */

#include <rdma/uverbs_ioctl.h>

#include "octep_verbs.h"

/* Helper function to check if device is ready for mailbox communication */
static inline bool
octep_rdma_device_ready(struct octep_rdma_dev *rdma_dev)
{
	int status = atomic_read(&rdma_dev->status);

	return ((status >= OCTEP_RDMA_DEV_STATUS_INIT &&
		 status <= OCTEP_RDMA_DEV_STATUS_NETDEV_REG) ||
		status == OCTEP_RDMA_DEV_STATUS_UNINIT);
}

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
		err = rdma_user_mmap_io(&uctx->ibucontext, vma, pfn, rdma_entry->npages * PAGE_SIZE,
					pgprot_noncached(vma->vm_page_prot), rdma_entry);
		if (err) {
			ibdev_err(ibucontext->device, "rdma_user_mmap_io failed\n");
			goto put_entry;
		}
		err = 0;
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
	if (atomic_inc_return(&rdma_dev->num_ctx) > OCTEP_RDMA_MAX_CONTEXT) {
		atomic_dec(&rdma_dev->num_ctx);
		return -ENOMEM;
	}

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
	bool device_active;
	int ret;

	device_active = octep_rdma_device_ready(rdma_dev);

	if (device_active) {
		ret = octep_rdma_prepare_pd_del_cmd(rdma_dev, pd->pdn);
		if (ret) {
			ibdev_warn(
				ibpd->device,
				"PD delete command failed: ret %d (continuing with local cleanup)\n",
				ret);
		}
	} else {
		ibdev_info(ibpd->device, "Device inactive, skipping remote PD cleanup\n");
	}

	/*
	 * Always free the bitmap index and return success, even if the
	 * firmware-side pd_delete mbox failed.  This function is called
	 * from the IB core's cleanup path (process exit / ib_dealloc_pd);
	 * returning an error would leak the kernel ib_pd structure.
	 *
	 * If the mbox did fail, the firmware still holds a stale PD entry.
	 * The freed bitmap index may be reused by a subsequent
	 * octep_rdma_alloc_pd, which sends a pd_add mbox with the same ID.
	 * The firmware's pd_add handler is designed to detect and replace
	 * such stale entries, so the inconsistency is self-healing.
	 */
	ibdev_info(ibpd->device, "Deallocating PD %d\n", pd->pdn);
	bitmap_free(pd->mr_res_cb.bitmap);
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

	if (udata && (udata->inlen || udata->outlen)) {
		dev_err(&rdma_dev->pdev->dev, "Invalid udata\n");
		err = -EINVAL;
		goto err_out;
	}

	memcpy(attr, &rdma_dev->attr, sizeof(*attr));

	attr->vendor_id = PCI_VENDOR_ID_CAVIUM;
	attr->vendor_part_id = rdma_dev->pdev->device;
	attr->hw_ver = rdma_dev->pdev->revision;
	attr->kernel_cap_flags = IBK_LOCAL_DMA_LKEY;

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
	immutable->core_cap_flags = RDMA_CORE_CAP_PROT_ROCE_UDP_ENCAP | RDMA_CORE_CAP_IB_MAD |
				    RDMA_CORE_CAP_IB_CM | RDMA_CORE_CAP_ETH_AH;
	immutable->max_mad_size = IB_MGMT_MAD_SIZE;

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
	struct octep_rdma_pd *pd = to_octep_rdma_pd(ibpd);
	struct octep_rdma_mr *mr;
	int mrn;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	mrn = octep_rdma_alloc_idx(&pd->mr_res_cb);
	if (mrn < 0) {
		kfree(mr);
		return ERR_PTR(mrn);
	}

	mr->mrn = (u32)mrn;
	mr->ibmr.pd = ibpd;
	mr->ibmr.device = ibpd->device;

	octep_rdma_mr_init(access, mr, mr->mrn);
	mr->state = OCTEP_RDMA_MR_STATE_VALID;
	mr->ibmr.type = IB_MR_TYPE_DMA;

	return &mr->ibmr;
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
	bool device_active;
	int ret = 0;

	/* Check if device is still active for communication */
	device_active = octep_rdma_device_ready(rdma_dev);

	/* Try to deregister on device side, but continue cleanup even if it fails */
	if (device_active) {
		ret = octep_rdma_prepare_mr_deregister_cmd(rdma_dev, mr, pd->pdn);
		if (ret)
			ibdev_warn(
				ibmr->device,
				"MR deregister command failed: ret %d (continuing with local cleanup)\n",
				ret);
	} else {
		ibdev_info(ibmr->device, "Device inactive, skipping remote MR cleanup\n");
	}

	/* Always continue with local cleanup */
	if (!rdma_is_kernel_res(&ibmr->res))
		release_mem_trans_tbl(rdma_dev, &mr->mrbuf_mtt);

	if (atomic_read(&mr->num_mw) > 0) {
		ibdev_warn(ibmr->device, "MR has MWs bound during cleanup\n");
		/* Don't fail cleanup - just warn */
	}

	octep_rdma_free_idx(&pd->mr_res_cb, mr->mrn);
	kfree_rcu_mightsleep(mr);

	/* Always return success for cleanup operations to avoid resource leaks */
	return 0;
}

int
octep_rdma_create_cq(struct ib_cq *ibcq, const struct ib_cq_init_attr *init_attr,
		     struct ib_udata *udata)
{
	bool is_user = false;
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

	if (!rdma_is_kernel_res(&ibcq->res))
		depth = roundup_pow_of_two(depth + 1);
	else
		depth = roundup_pow_of_two(depth);
	cq->ibcq.cqe = depth;
	cq->depth = depth;

	cqn = octep_rdma_alloc_idx(&rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_CQ]);
	if (cqn < 0)
		return cqn;

	cq->cqn = cqn;
	ibdev_info(ibcq->device, "[%s:%d] max_cq %d cqn %d next_alloc_idx %d\n", __func__, __LINE__,
		   rdma_dev->attr.max_cq, cq->cqn,
		   rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_CQ].next_alloc_idx);

	if (!rdma_is_kernel_res(&ibcq->res)) {
		struct octep_rdma_ureq_create_cq ureq;
		struct octep_rdma_uresp_create_cq uresp;
		is_user = true;

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
		is_user = false;
		ret = octep_rdma_init_kernel_cq(cq);
		if (ret)
			goto err_out_xa;
		ibdev_info(ibcq->device, "[%s:%d] Kernel cq->cqn %d\n", __func__, __LINE__,
			   cq->cqn);
	}

	ret = octep_rdma_prepare_cq_cmd(rdma_dev, cq, is_user);
	if (ret) {
		ibdev_err(ibcq->device, "octep_rdma_prepare_cq_cmd failed\n");
		goto err_free_res;
	}

	if (is_user == false) {
		ret = octep_rdma_kern_cq_poll_insert(cq);
		if (ret < 0) {
			ibdev_err(ibcq->device, "Failed to insert CQ for poll\n");
			goto err_free_res;
		}
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
		ret = octep_rdma_poll_one_cqe(cq, wc + npolled, num_entries - npolled);

		if (ret == -EAGAIN) /* no received new CQEs. */
			break;

		if (!ret)
			break;

		npolled += ret;
	}
	spin_unlock_irqrestore(&cq->kern_cq.lock, flags);

	return npolled;
}

int
octep_rdma_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags)
{
	struct octep_rdma_cq *cq = to_octep_rdma_cq(ibcq);
	int ret = 0;

	if (cq->notify != IB_CQ_NEXT_COMP)
		cq->notify = flags & IB_CQ_SOLICITED_MASK;

	return ret;
}

int
octep_rdma_destroy_cq(struct ib_cq *ibcq, struct ib_udata *udata)
{
	struct octep_rdma_cq *cq = to_octep_rdma_cq(ibcq);
	struct octep_rdma_dev *rdma_dev = to_octep_rdma_dev(ibcq->device);
	bool device_active;
	int ret = 0;

	/* Check if device is still active for communication */
	device_active = octep_rdma_device_ready(rdma_dev);

	/* Try to destroy on device side, but continue cleanup even if it fails */
	if (device_active) {
		ret = octep_rdma_prepare_cq_destroy_cmd(rdma_dev, cq);
		if (ret)
			ibdev_warn(
				ibcq->device,
				"CQ destroy command failed: ret %d (continuing with local cleanup)\n",
				ret);
	} else {
		ibdev_info(ibcq->device, "Device inactive, skipping remote CQ cleanup\n");
	}

	/* Always continue with local cleanup */
	ibdev_info(ibcq->device, "[%s:%d] cq->cqn %d\n", __func__, __LINE__, cq->cqn);

	if (rdma_is_kernel_res(&cq->ibcq.res)) {
		/* Remove from polling list before freeing */
		octep_rdma_kern_cq_poll_remove(cq);
		octep_rdma_free_kernel_cq(rdma_dev, cq);
	} else {
		release_mem_trans_tbl(rdma_dev, &cq->user_cq.qbuf_mtt);
	}

	octep_rdma_free_idx(&rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_CQ], cq->cqn);

	/* Always return success for cleanup operations to avoid resource leaks */
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
	bool is_user = false;

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

	if (attrs->qp_type != IB_QPT_GSI) {
		qpn = octep_rdma_alloc_idx(&rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_QP]);
		if (qpn < 0) {
			ret = qpn;
			ibdev_err(ibqp->device, "Failed to allocate QP index, ret %d\n", ret);
			goto err_out;
		}

		qp->ibqp.qp_num = qpn;
	} else {
		qp->ibqp.qp_num = 1;
	}

	ibdev_info(ibqp->device, "[%s] max_qp %d qp_num %d next_alloc_idx %d\n", __func__,
		   rdma_dev->attr.max_qp, qp->ibqp.qp_num,
		   rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_QP].next_alloc_idx);

	if (uctx) {
		is_user = true;
		ret = init_user_qp(rdma_dev, qp, udata);
		if (ret) {
			ibdev_err(ibqp->device, "init_user_qp failed\n");
			goto err_out_xa;
		}
	} else {
		is_user = false;
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

	ret = octep_rdma_prepare_qp_cmd(rdma_dev, qp, pd->pdn, is_user);
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
		free_kernel_qp(rdma_dev, qp);
	}

err_out_xa:
	if (attrs->qp_type != IB_QPT_GSI)
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

	if (udata && udata->inlen && !ib_is_udata_cleared(udata, 0, udata->inlen)) {
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
	struct octep_rdma_qp_mod_attrs *mod;

	if (ibqp && qp_attr && qp_init_attr) {
		qp = to_octep_rdma_qp(ibqp);
		dev = to_octep_rdma_dev(ibqp->device);
	} else {
		return -EINVAL;
	}

	down_read(&qp->state_lock);

	mod = qp->attrs.qp_mod_attr;

	/* QP state */
	qp_attr->qp_state = octep_rdma_get_ibqp_state(qp->attrs.state);
	qp_attr->cur_qp_state = qp_attr->qp_state;

	/* Capabilities */
	qp_attr->cap.max_inline_data = OCTEP_RDMA_MAX_INLINE;
	qp_attr->qkey = qp->attrs.qkey;
	qp_init_attr->cap.max_inline_data = OCTEP_RDMA_MAX_INLINE;

	qp_attr->cap.max_send_wr = qp->attrs.sq_size;
	qp_attr->cap.max_recv_wr = qp->attrs.rq_size;
	qp_attr->cap.max_send_sge = qp->attrs.max_send_sge;
	qp_attr->cap.max_recv_sge = qp->attrs.max_recv_sge;

	qp_attr->path_mtu = ib_mtu_int_to_enum(dev->netdev->mtu);
	qp_attr->max_rd_atomic = qp->attrs.irq_size;
	qp_attr->max_dest_rd_atomic = qp->attrs.orq_size;

	qp_attr->qp_access_flags = IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE |
				   IB_ACCESS_REMOTE_READ;

	/* Connection parameters from last modify_qp */
	qp_attr->dest_qp_num = qp->attrs.dest_qpn;
	if (mod) {
		qp_attr->sq_psn = mod->sq_psn;
		qp_attr->rq_psn = mod->rq_psn;
		qp_attr->timeout = mod->timeout;
		qp_attr->retry_cnt = mod->retry_cnt;
		qp_attr->rnr_retry = mod->rnr_retry_cnt;
		qp_attr->min_rnr_timer = mod->min_rnr_timer;
		qp_attr->pkey_index = mod->pkey_index;
		qp_attr->port_num = mod->port_num;
		if (qp_attr->max_rd_atomic == 0)
			qp_attr->max_rd_atomic = mod->max_rd_atomic;
		if (qp_attr->max_dest_rd_atomic == 0)
			qp_attr->max_dest_rd_atomic = mod->max_dest_rd_atomic;
	}
	qp_init_attr->sq_sig_type = qp->attrs.sq_sig_type;

	up_read(&qp->state_lock);
	/*
	 * Ensure non-zero defaults for RDMA READ atomic counts.
	 * ucma_modify_qp_rtr() queries these BEFORE the first modify_qp(RTR),
	 * so both irq_size/orq_size and mod values are still 0.
	 * A zero max_dest_rd_atomic causes firmware to reject inbound READs.
	 */
	if (qp_attr->max_rd_atomic == 0)
		qp_attr->max_rd_atomic = 1;
	if (qp_attr->max_dest_rd_atomic == 0)
		qp_attr->max_dest_rd_atomic = 1;

	/* Fallback port_num from device if not set via modify */
	if (!qp_attr->port_num)
		qp_attr->port_num = 1;

	qp_init_attr->cap = qp_attr->cap;
	qp_init_attr->qp_type = ibqp->qp_type;

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
	bool device_active;

	ibdev_info(ibqp->device, "Destroying qp->ibqp.qp_num %d\n", qp->ibqp.qp_num);

	/* Check if device is still active for communication */
	device_active = octep_rdma_device_ready(rdma_dev);

	/* Try to destroy on device side, but continue cleanup even if it fails */
	if (device_active) {
		ret = octep_rdma_prepare_user_qp_destroy_cmd(qp->rdma_dev, qp);
		if (ret)
			ibdev_warn(
				ibqp->device,
				"QP destroy command failed: ret %d (continuing with local cleanup)\n",
				ret);

		ret = octep_rdma_prepare_qp_state_cmd(qp->rdma_dev, qp, false);
		if (ret)
			ibdev_warn(
				ibqp->device,
				"QP state command failed: ret %d (continuing with local cleanup)\n",
				ret);
	} else {
		ibdev_info(ibqp->device, "Device inactive, skipping remote QP cleanup\n");
	}

	/* Always continue with local cleanup regardless of remote cleanup status */
	if (rdma_is_kernel_res(&qp->ibqp.res)) {
		free_kernel_qp(rdma_dev, qp);
	} else {
		if (ctx) {
			release_mem_trans_tbl(qp->rdma_dev, &qp->user_qp.rq_mtt);
			release_mem_trans_tbl(qp->rdma_dev, &qp->user_qp.sq_mtt);
			vunmap(qp->user_qp.sq_vaddr);
			vunmap(qp->user_qp.rq_vaddr);
		}
	}

	if (qp->ibqp.qp_num != 1)
		octep_rdma_free_idx(&rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_QP], qp->ibqp.qp_num);

	kfree(qp->attrs.qp_mod_attr);

	/* Always return success for cleanup operations to avoid resource leaks */
	return 0;
}

static inline int
octep_rdma_post_one_send(struct octep_rdma_qp *qp, struct octep_rdma_queue *sq,
			 const struct ib_send_wr *wr_list)
{
	union octep_rdma_sqe *sqe;
	struct ib_sge *sg_list;
	u16 qmask, prod_index, cons_index;
	int num_sge;
	void *qbuf;

	/* Cache frequently accessed values for better performance */
	qmask = sq->qmask;
	qbuf = sq->qbuf;
	prod_index = sq->pi;
	cons_index = (u16)atomic_read(sq->ci_dbl);

	/* Fast path: check queue full condition early */
	if (unlikely(octep_rdma_is_queue_full(prod_index, cons_index, qmask)))
		return -ENOMEM;

	sg_list = wr_list->sg_list;
	num_sge = wr_list->num_sge;

	/* Get initial SQE and prefetch next potential SQE */
	sqe = (union octep_rdma_sqe *)qbuf + prod_index;
	if (likely(num_sge > 1))
		prefetch((union octep_rdma_sqe *)qbuf + ((prod_index + 1) & qmask));

	/* Optimized SQE field assignment - group related fields together */
	sqe->wr_id = wr_list->wr_id;
	sqe->opcode = wr_list->opcode;
	sqe->num_sges = num_sge;
	sqe->send_flags = wr_list->send_flags;
	sqe->imm_data = wr_list->ex.imm_data;

	if (qp->ibqp.qp_type == IB_QPT_UD || qp->ibqp.qp_type == IB_QPT_GSI) {
		const struct ib_ud_wr *ud_wr_ptr = ud_wr(wr_list);
		struct ib_ah *ibah = ud_wr_ptr->ah;

		sqe->ud.ah = to_octep_rdma_ah(ibah)->ah_num;
		sqe->ud.remote_qpn = ud_wr_ptr->remote_qpn;
		sqe->ud.qkey = ud_wr_ptr->remote_qkey;
	}

	/* Optimized SGE copying with reduced branching */
	if (likely(num_sge > 0)) {
		/* First SGE - always present */
		sqe->sges0[0] = *(struct octep_rdma_sge *)sg_list;
		sg_list++;
		num_sge--;

		if (likely(num_sge > 0)) {
			/* Second SGE in same SQE */
			sqe->sges0[1] = *(struct octep_rdma_sge *)sg_list;
			sg_list++;
			num_sge--;
			prod_index = (prod_index + 1) & qmask;

			/* Handle remaining SGEs efficiently */
			while (num_sge > 0) {
				sqe = (union octep_rdma_sqe *)qbuf + prod_index;

				/* Optimized batch copy - handle up to 4 SGEs per SQE */
				if (likely(num_sge >= 4)) {
					/* Fast path: copy 4 SGEs at once */
					memcpy(sqe->sges1, sg_list, sizeof(struct ib_sge) * 4);
					sg_list += 4;
					num_sge -= 4;
				} else {
					/* Handle remaining SGEs (1-3) */
					memcpy(sqe->sges1, sg_list,
					       sizeof(struct ib_sge) * num_sge);
					num_sge = 0;
				}
				prod_index = (prod_index + 1) & qmask;
			}
		} else {
			prod_index = (prod_index + 1) & qmask;
		}
	} else {
		prod_index = (prod_index + 1) & qmask;
	}

	/* Update producer index */
	sq->pi = prod_index;
	return 0;
}

int
octep_rdma_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr_list,
		     const struct ib_send_wr **bad_wr)
{
	struct octep_rdma_qp *qp;
	struct octep_rdma_queue *sq;
	const struct ib_send_wr *wr;
	int ret = 0;
	u32 wr_count = 0;

	/* Fast path validation - group all checks together */
	if (unlikely(!ibqp || !bad_wr || !wr_list))
		return -EINVAL;

	*bad_wr = NULL;
	qp = to_octep_rdma_qp(ibqp);
	sq = &qp->kern_qp.sq;

	if (unlikely(!sq || !sq->qbuf))
		return -EINVAL;

	/* Prefetch first WR data for better cache performance */
	prefetch(wr_list);
	prefetch(wr_list->sg_list);

	/* Optimized posting loop with reduced overhead */
	for (wr = wr_list; wr; wr = wr->next) {
		/* Prefetch next WR while processing current one */
		if (likely(wr->next)) {
			prefetch(wr->next);
			prefetch(wr->next->sg_list);
		}

		/* Fast path validation - check SGE list */
		if (unlikely(!wr->sg_list)) {
			ret = -EINVAL;
			*bad_wr = wr;
			break;
		}

		ret = octep_rdma_post_one_send(qp, sq, wr);
		if (unlikely(ret)) {
			*bad_wr = wr;
			break;
		}

		wr_count++;

		/* Batch doorbell updates for better performance when posting many WRs */
		if (unlikely(wr_count >= 16 && wr->next)) {
			/* Memory barrier before doorbell update */
			wmb();
			atomic_set(sq->pi_dbl, sq->pi);
			wr_count = 0;
		}
	}

	/* Final doorbell update with memory barrier */
	wmb();
	atomic_set(sq->pi_dbl, sq->pi);

	return ret;
}

int
octep_rdma_post_recv(struct ib_qp *ibqp, const struct ib_recv_wr *recv_wr,
		     const struct ib_recv_wr **bad_wr)
{
	struct octep_rdma_qp *qp;
	struct octep_rdma_queue *rq;
	const struct ib_recv_wr *wr;
	union octep_rdma_rqe *rqe;
	struct ib_sge *sg_list;
	u16 qmask, pi, ci;
	void *qbuf;
	u16 num_sge, cnt;
	u32 wr_count = 0;
	int rv = 0;

	/* Fast path validation - group all checks together */
	if (unlikely(!ibqp || !bad_wr || !recv_wr))
		return -EINVAL;

	*bad_wr = NULL;
	qp = to_octep_rdma_qp(ibqp);
	rq = &qp->kern_qp.rq;

	if (unlikely(!rq || !rq->qbuf))
		return -EINVAL;

	/* Cache frequently accessed values */
	qmask = rq->qmask;
	qbuf = rq->qbuf;
	pi = rq->pi;
	ci = (u16)atomic_read(rq->ci_dbl);

	/* Prefetch first WR data for better cache performance */
	prefetch(recv_wr);
	prefetch(recv_wr->sg_list);

	/* Optimized posting loop */
	for (wr = recv_wr; wr; wr = wr->next) {
		/* Prefetch next WR while processing current one */
		if (likely(wr->next)) {
			prefetch(wr->next);
			prefetch(wr->next->sg_list);
		}

		/* Fast path: check queue full condition */
		if (unlikely(octep_rdma_is_queue_full(pi, ci, qmask))) {
			rv = -ENOMEM;
			*bad_wr = wr;
			break;
		}

		/* Get RQE and prefetch next potential RQE */
		rqe = (union octep_rdma_rqe *)qbuf + pi;
		if (likely(wr->num_sge > 1))
			prefetch((union octep_rdma_rqe *)qbuf + ((pi + 1) & qmask));

		/* Cache SGE information */
		num_sge = wr->num_sge;
		sg_list = wr->sg_list;

		/* Fill RQE header - grouped for cache efficiency */
		rqe->wr_id = wr->wr_id;
		rqe->num_sge = num_sge;
		rqe->opcode = IB_WC_RECV;

		/* Optimized SGE copying */
		if (likely(num_sge > 0)) {
			/* First SGE - direct assignment */
			rqe->sges0[0] = *(struct octep_rdma_sge *)sg_list;

			sg_list++;
			num_sge--;
			pi = (pi + 1) & qmask;

			/* Handle remaining SGEs efficiently */
			while (num_sge > 0) {
				rqe = (union octep_rdma_rqe *)qbuf + pi;

				/* Optimized batch copy - handle up to 2 SGEs per RQE */
				cnt = (num_sge >= 2) ? 2 : num_sge;

				if (likely(cnt == 2)) {
					/* Fast path: copy 2 SGEs */
					rqe->sges1[0] = *(struct octep_rdma_sge *)&sg_list[0];
					rqe->sges1[1] = *(struct octep_rdma_sge *)&sg_list[1];
				} else {
					/* Single SGE remaining */
					rqe->sges1[0] = *(struct octep_rdma_sge *)&sg_list[0];
				}

				sg_list += cnt;
				num_sge -= cnt;
				pi = (pi + 1) & qmask;
			}
		} else {
			pi = (pi + 1) & qmask;
		}

		wr_count++;

		/* Batch doorbell updates for better performance when posting many WRs */
		if (unlikely(wr_count >= 16 && wr->next)) {
			/* Update queue state and ring doorbell */
			rq->pi = pi;
			wmb(); /* Memory barrier before doorbell */
			atomic_set(rq->pi_dbl, pi);
			wr_count = 0;
		}
	}

	/* Final update - always update queue state and ring doorbell */
	rq->pi = pi;
	wmb(); /* Memory barrier before doorbell */
	atomic_set(rq->pi_dbl, pi);

	return rv;
}

/* ah */
int
octep_rdma_create_ah(struct ib_ah *ibah, struct rdma_ah_init_attr *init_attr,
		     struct ib_udata *udata)
{
	struct octep_rdma_dev *rdma_dev = to_octep_rdma_dev(ibah->device);
	struct octep_rdma_ah *ah = to_octep_rdma_ah(ibah);
	bool sleepable = !!(init_attr->flags & RDMA_CREATE_AH_SLEEPABLE);
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
	ibdev_info(ibah->device, "[%s:%d] ah_num %d sleepable %d\n", __func__, __LINE__, ah->ah_num,
		   sleepable);
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

	err = octep_rdma_prepare_ah_cmd(rdma_dev, ah, &ah->av, AH_CREATE, sleepable);
	if (err) {
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
	err = octep_rdma_prepare_ah_cmd(rdma_dev, ah, &ah->av, AH_MODIFY, true);
	if (err) {
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
	bool sleepable = !!(flags & RDMA_DESTROY_AH_SLEEPABLE);
	int ret;

	if (!ah) {
		ibdev_err(ibah->device, "ah is NULL\n");
		return -EINVAL;
	}

	ret = octep_rdma_prepare_ah_destroy_cmd(rdma_dev, ah, sleepable);
	if (ret)
		ibdev_err(ibah->device, "Failed to prepare AH destroy command, ret = %d\n", ret);

	ibdev_info(ibah->device, "[%s:%d] ah->ah_num %d sleepable %d\n", __func__, __LINE__,
		   ah->ah_num, sleepable);
	octep_rdma_free_idx(&rdma_dev->res_cb[OCTEP_RDMA_RES_TYPE_AH], ah->ah_num);

	return 0;
}
