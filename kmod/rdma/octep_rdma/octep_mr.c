/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Marvell.
 */

#include <linux/iommu.h>

#include "octep_verbs.h"

#define OCTEP_RDMA_IOVA_AS_VA_MASK 39

struct rdma_user_mmap_entry *
octep_rdma_mmap_entry_insert(struct octep_rdma_ucontext *uctx, u64 address, size_t length,
			     u8 mmap_flag, u64 *offset)
{
	struct octep_rdma_user_mmap_entry *entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	int rv;

	*offset = OCTEP_RDMA_INVAL_UOBJ_KEY;
	if (!entry)
		return NULL;

	entry->address = address;
	entry->mmap_flag = mmap_flag;

	length = PAGE_ALIGN(length);
	rv = rdma_user_mmap_entry_insert(&uctx->ibucontext, &entry->rdma_entry, length);
	if (rv) {
		kfree(entry);
		return NULL;
	}

	*offset = rdma_user_mmap_get_offset(&entry->rdma_entry);

	return &entry->rdma_entry;
}

static void
octep_iommu_unmapping(struct octep_rdma_dev *rdma_dev, struct octep_rdma_mem *mem)
{
	struct device *dev = &rdma_dev->octep_dev->pdev->dev;
	struct iommu_domain *domain;
	size_t page_size = mem->page_size;
	size_t size = 0, unmap_len;
	int i;

	if (!mem->iova || !mem->size)
		return;

	domain = iommu_get_domain_for_dev(dev);
	if (!domain) {
		ibdev_err(&rdma_dev->ibdev, "no IOMMU domain found\n");
		return;
	}

	for (i = 0; i < mem->iommu_mapped_cnt; i++) {
		if (mem->iova[i]) {
			phys_addr_t existing_phys = iommu_iova_to_phys(domain, mem->iova[i]);

			if (existing_phys) {
				unmap_len = iommu_unmap(domain, mem->iova[i], page_size);
				if (unmap_len != page_size) {
					dev_warn(dev,
						 "Invalid unmapped bytes 0x%lx, expected 0x%lx\n",
						 unmap_len, page_size);
				}
				ibdev_dbg(&rdma_dev->ibdev,
					  "iommu_unmapping iova[%d] 0x%llx size 0x%lx\n", i,
					  mem->iova[i], page_size);
				size += page_size;
			} else {
				ibdev_dbg(&rdma_dev->ibdev, "Skipping unmapped iova[%d] 0x%llx\n",
					  i, mem->iova[i]);
			}
		}
	}

	if (mem->size != size)
		ibdev_err(&rdma_dev->ibdev, "iommu_unmapping size mismatch %lx != %llx\n", size,
			  mem->size);

	kfree(mem->iova);
	mem->iova = NULL;
	mem->size = 0;
}

static int
octep_iommu_mapping(struct octep_rdma_dev *rdma_dev, struct octep_rdma_mem *mem)
{
	struct device *dev = &rdma_dev->octep_dev->pdev->dev;
	struct sg_page_iter sg_iter;
	struct sg_table *sgt = &mem->umem->sgt_append.sgt;
	struct iommu_domain *domain;
	phys_addr_t phys;
	size_t page_size = mem->page_size;
	struct page *page;
	int ret;
	u64 mask = (1ull << OCTEP_RDMA_IOVA_AS_VA_MASK) - 1;
	u64 iova = ALIGN_DOWN(mem->va, page_size) & mask;
	size_t offset = mem->va & (page_size - 1);
	size_t expected_size = PAGE_ALIGN(mem->len + offset);
	size_t size = 0;
	int mapped_cnt = 0;
	int j;

	__sg_page_iter_start(&sg_iter, sgt->sgl, sgt->orig_nents, 0);
	if (!__sg_page_iter_next(&sg_iter)) {
		ibdev_err(&rdma_dev->ibdev, "no sg page found\n");
		return -EINVAL;
	}

	domain = iommu_get_domain_for_dev(dev);
	if (!domain) {
		ibdev_err(&rdma_dev->ibdev, "no IOMMU domain found\n");
		return -EINVAL;
	}

	ibdev_dbg(&rdma_dev->ibdev, "Mapping IOMMU for device %s\n", dev_name(dev));

	mem->iova = kcalloc(mem->page_cnt, sizeof(u64), GFP_KERNEL);
	if (!mem->iova)
		return -ENOMEM;

	do {
		page = sg_page_iter_page(&sg_iter);
		phys = page_to_phys(page);

		/* Check if IOVA is already mapped */
		phys_addr_t existing_phys = iommu_iova_to_phys(domain, iova);

		if (existing_phys) {
			ibdev_warn(&rdma_dev->ibdev,
				   "IOVA 0x%llx already mapped to phys 0x%llx, skipping\n", iova,
				   existing_phys);
			iova += page_size;
			size += page_size;
			continue;
		}

		ret = iommu_map(domain, iova, phys, page_size, IOMMU_READ | IOMMU_WRITE,
				GFP_KERNEL);
		if (ret) {
			ibdev_err(&rdma_dev->ibdev,
				  "iommu_map failed at iova 0x%llx, phys 0x%llx, ret %d\n", iova,
				  phys, ret);

			/* Only unmap valid (non-zero) IOVA addresses that we successfully mapped */
			for (j = 0; j < mapped_cnt; j++) {
				if (mem->iova[j])
					iommu_unmap(domain, mem->iova[j], page_size);
			}

			kfree(mem->iova);
			mem->iova = NULL;
			return ret;
		}

		mem->iova[mapped_cnt] = iova;
		ibdev_dbg(&rdma_dev->ibdev, "iommu_map iova[%d] 0x%llx phys 0x%llx size 0x%lx\n",
			  mapped_cnt, iova, phys, page_size);

		iova += page_size;
		size += page_size;
		mapped_cnt++;
	} while (__sg_page_iter_next(&sg_iter));

	if (expected_size != size) {
		ibdev_err(&rdma_dev->ibdev, "iommu_map size mismatch %lx != %lx\n", size,
			  expected_size);
		octep_iommu_unmapping(rdma_dev, mem);
		return -EINVAL;
	}

	mem->size = size;
	mem->iommu_mapped_cnt = mapped_cnt;

	return 0;
}

int
setup_mem_trans_tbl(struct octep_rdma_dev *rdma_dev, struct octep_rdma_mem *mem, u64 start, u64 len,
		    int access, u64 virt, unsigned long req_page_size, u8 force_indirect_mtt)
{
	struct ib_block_iter biter;
	uint64_t *phy_addr = NULL;
	int ret = 0;

	mem->umem = ib_umem_get(&rdma_dev->ibdev, virt, len, access);
	if (IS_ERR(mem->umem)) {
		ibdev_dbg(&rdma_dev->ibdev, "ib_umem_get failed\n");
		ret = PTR_ERR(mem->umem);
		mem->umem = NULL;
		return ret;
	}

	mem->va = virt;
	mem->len = len;
	mem->page_size = ib_umem_find_best_pgsz(mem->umem, req_page_size, virt);
	mem->page_offset = virt & (mem->page_size - 1);
	mem->mtt_nents = ib_umem_num_dma_blocks(mem->umem, mem->page_size);
	mem->page_cnt = mem->mtt_nents;

	ibdev_info(&rdma_dev->ibdev,
		   "[%s:%d] start 0x%llx va %llx len %llx page_size %x"
		   " page_offset %x mtt_nents %d page_cnt %d\n",
		   __func__, __LINE__, start, mem->va, mem->len, mem->page_size, mem->page_offset,
		   mem->mtt_nents, mem->page_cnt);

	if (mem->page_cnt > OCTEP_RDMA_MAX_INLINE_MTT_ENTRIES || force_indirect_mtt) {
		mem->mtt_type = OCTEP_RDMA_MR_INDIRECT_MTT;
		mem->mtt_buf = alloc_pages_exact(MTT_SIZE(mem->page_cnt), GFP_KERNEL);
		if (!mem->mtt_buf) {
			ret = -ENOMEM;
			goto error_ret;
		}
		phy_addr = mem->mtt_buf;
	} else {
		mem->mtt_type = OCTEP_RDMA_MR_INLINE_MTT;
		phy_addr = mem->mtt_entry;
	}

	rdma_umem_for_each_dma_block(mem->umem, &biter, mem->page_size)	{
		*phy_addr = rdma_block_iter_dma_address(&biter);
		ibdev_dbg(&rdma_dev->ibdev, "*phy_addr %llx\n", *phy_addr);
		phy_addr++;
	}

	if (mem->mtt_type == OCTEP_RDMA_MR_INDIRECT_MTT) {
		mem->mtt_entry[0] = dma_map_single(&rdma_dev->pdev->dev, mem->mtt_buf,
						   MTT_SIZE(mem->page_cnt), DMA_TO_DEVICE);
		if (dma_mapping_error(&rdma_dev->pdev->dev, mem->mtt_entry[0])) {
			free_pages_exact(mem->mtt_buf, MTT_SIZE(mem->page_cnt));
			mem->mtt_buf = NULL;
			ret = -ENOMEM;
			goto error_ret;
		}
	}

	ibdev_dbg(&rdma_dev->ibdev,
		  "MTT_SIZE(mem->page_cnt) %x umem %p mem->mtt_buf[0] 0x%llx mtt_entry[0] %llx\n",
		  MTT_SIZE(mem->page_cnt), mem->umem, mem->mtt_buf ? *((u64 *)mem->mtt_buf) : 0,
		  mem->mtt_entry[0]);

	ret = octep_iommu_mapping(rdma_dev, mem);
	if (ret) {
		ibdev_err(&rdma_dev->ibdev, "octep_iommu_mapping failed\n");
		goto error_iommu_mapping;
	}

	return 0;

error_iommu_mapping:
	/* Clean up DMA mapping if it was created */
	if (mem->mtt_type == OCTEP_RDMA_MR_INDIRECT_MTT && mem->mtt_entry[0]) {
		if (!dma_mapping_error(&rdma_dev->pdev->dev, mem->mtt_entry[0])) {
			dma_unmap_single(&rdma_dev->pdev->dev, mem->mtt_entry[0],
					 MTT_SIZE(mem->page_cnt), DMA_TO_DEVICE);
		}
		mem->mtt_entry[0] = 0;
	}

	/* Clean up allocated buffer */
	if (mem->mtt_buf) {
		free_pages_exact(mem->mtt_buf, MTT_SIZE(mem->page_cnt));
		mem->mtt_buf = NULL;
	}

error_ret:
	if (mem->umem) {
		ib_umem_release(mem->umem);
		mem->umem = NULL;
	}

	return ret;
}

void
release_mem_trans_tbl(struct octep_rdma_dev *rdma_dev, struct octep_rdma_mem *mem)
{
	octep_iommu_unmapping(rdma_dev, mem);
	if (mem->mtt_buf) {
		dma_unmap_single(&rdma_dev->pdev->dev, mem->mtt_entry[0], MTT_SIZE(mem->page_cnt),
				 DMA_TO_DEVICE);
		free_pages_exact(mem->mtt_buf, MTT_SIZE(mem->page_cnt));
	}

	if (mem->umem) {
		ib_umem_release(mem->umem);
		mem->umem = NULL;
	}
}

static u16
octep_rdma_get_next_key(u32 last_key)
{
	u16 key;

	do {
		get_random_bytes(&key, 2);
	} while (key == last_key);

	return key;
}

#define IB_ACCESS_REMOTE (IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_ATOMIC)

void
octep_rdma_mr_init(int access, struct octep_rdma_mr *mr, int mrn)
{
	u32 lkey = mrn << 20 | octep_rdma_get_next_key(-1);
	u32 rkey = (access & IB_ACCESS_REMOTE) ? lkey : 0;

	/* set ibmr->l/rkey and also copy into private l/rkey
	 * for user MRs these will always be the same
	 * for cases where caller 'owns' the key portion
	 * they may be different until REG_MR WQE is executed.
	 */
	mr->ibmr.lkey = lkey;
	mr->lkey = mr->ibmr.lkey;
	mr->ibmr.rkey = rkey;
	mr->rkey = mr->ibmr.rkey;

	mr->access = access;
	mr->ibmr.page_size = PAGE_SIZE;
	mr->page_mask = PAGE_MASK;
	mr->page_shift = PAGE_SHIFT;
	mr->state = OCTEP_RDMA_MR_STATE_INVALID;

	ibdev_info(mr->ibmr.device, " mr %p lkey 0x%x rkey 0x%x access 0x%x state %d\n", mr,
		   mr->lkey, mr->rkey, mr->access, mr->state);
}

int
octep_rdma_prepare_mr_register_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_mr *mr,
				   u32 pdn)
{
	struct octep_rdma_mr_register_req *mr_req;
	int ret = 0;

	mr_req = kzalloc(sizeof(*mr_req), GFP_KERNEL);
	if (!mr_req)
		return -ENOMEM;

	mr_req->port_num = rdma_dev->port.port_num;
	mr_req->pd_id = pdn;
	mr_req->mr.va = mr->mrbuf_mtt.va;
	mr_req->mr.length = mr->mrbuf_mtt.len;
	mr_req->mr.key = mr->lkey;
	mr_req->mr.access_flags = mr->access;

	ret = octep_rdma_mbox_mr_register(rdma_dev->caps_rgn, mr_req);
	if (ret) {
		ibdev_err(&rdma_dev->ibdev, "octep_rdma_mbox_mr_add failed, err %d\n", ret);
		goto done;
	}

	ibdev_info(&rdma_dev->ibdev, "[%s] mbox pd: %d mr 0x%llx success\n", __func__,
		   mr_req->pd_id, mr_req->mr.va);

done:
	kfree(mr_req);
	return ret;
}

int
octep_rdma_prepare_mr_deregister_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_mr *mr,
				     u32 pdn)
{
	struct octep_rdma_mr_deregister_req *mr_req;
	int ret = 0;

	mr_req = kzalloc(sizeof(*mr_req), GFP_KERNEL);
	if (!mr_req)
		return -ENOMEM;

	mr_req->port_num = rdma_dev->port.port_num;
	mr_req->pd_id = pdn;
	mr_req->key = mr->lkey;

	ret = octep_rdma_mbox_mr_deregister(rdma_dev->caps_rgn, mr_req);
	if (ret) {
		ibdev_err(&rdma_dev->ibdev, "octep_rdma_mbox_mr_delete failed, err %d\n", ret);
		goto done;
	}

	ibdev_info(&rdma_dev->ibdev, "[%s] mbox pd: %d mr %u success\n", __func__, mr_req->pd_id,
		   mr_req->key);

done:
	kfree(mr_req);
	return ret;
}
