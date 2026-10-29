/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Marvell.
 */

#include <linux/iommu.h>

#include "octep_verbs.h"
#include "octep_plat.h"
#include "octterm_cdev.h"

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
	struct device *dev = &rdma_dev->pdev->dev;
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

	kvfree(mem->iova);
	mem->iova = NULL;
	mem->size = 0;
}

static int
octep_iommu_mapping(struct octep_rdma_dev *rdma_dev, struct octep_rdma_mem *mem)
{
	struct device *dev = &rdma_dev->pdev->dev;
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
	size_t total_size = 0;
	size_t mapped_size = 0;
	int mapped_cnt = 0;
#ifdef CONFIG_OCTEP_RDMA_OCTTERM
	u32 pg_idx = 0;
#endif
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

	mem->iova = kvmalloc_array(mem->page_cnt, sizeof(u64), GFP_KERNEL | __GFP_ZERO);
	if (!mem->iova)
		return -ENOMEM;

	do {
		page = sg_page_iter_page(&sg_iter);
		phys = page_to_phys(page);

#ifdef CONFIG_OCTEP_RDMA_OCTTERM
		/* Remember the real PA of every page (also already-mapped ones) */
		if (mem->pa && pg_idx < mem->page_cnt)
			mem->pa[pg_idx] = phys;
		pg_idx++;
#endif

		/* Check if IOVA is already mapped */
		phys_addr_t existing_phys = iommu_iova_to_phys(domain, iova);

		if (existing_phys) {
			ibdev_dbg(&rdma_dev->ibdev,
				  "IOVA 0x%llx already mapped to phys 0x%llx, skipping iommu_map\n",
				  iova, existing_phys);
			iova += page_size;
			total_size += page_size;
			continue;
		}

		ret = iommu_map(domain, iova, phys, page_size, IOMMU_READ | IOMMU_WRITE,
				GFP_KERNEL);
		if (ret) {
			ibdev_err(&rdma_dev->ibdev,
				  "iommu_map failed at iova 0x%llx, phys 0x%llx, ret %d\n", iova,
				  phys, ret);

			for (j = 0; j < mapped_cnt; j++) {
				if (mem->iova[j])
					iommu_unmap(domain, mem->iova[j], page_size);
			}

			kvfree(mem->iova);
			mem->iova = NULL;
			return ret;
		}

		mem->iova[mapped_cnt] = iova;
		ibdev_dbg(&rdma_dev->ibdev, "iommu_map iova[%d] 0x%llx phys 0x%llx size 0x%lx\n",
			  mapped_cnt, iova, phys, page_size);

		iova += page_size;
		total_size += page_size;
		mapped_size += page_size;
		mapped_cnt++;
	} while (__sg_page_iter_next(&sg_iter));

	if (expected_size != total_size) {
		ibdev_err(&rdma_dev->ibdev, "iommu_map size mismatch %lx != %lx\n", total_size,
			  expected_size);
		octep_iommu_unmapping(rdma_dev, mem);
		return -EINVAL;
	}

	mem->size = mapped_size;
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
		mem->mtt_buf = kvmalloc(MTT_SIZE(mem->page_cnt), GFP_KERNEL);
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

	ibdev_dbg(&rdma_dev->ibdev,
		  "MTT_SIZE(mem->page_cnt) %x umem %p mem->mtt_buf[0] 0x%llx mtt_entry[0] %llx\n",
		  MTT_SIZE(mem->page_cnt), mem->umem, mem->mtt_buf ? *((u64 *)mem->mtt_buf) : 0,
		  mem->mtt_entry[0]);

#ifdef CONFIG_OCTEP_RDMA_OCTTERM
	/* Real PAs are only needed for MRs that can be the target of atomics */
	if (access & IB_ACCESS_REMOTE_ATOMIC) {
		mem->pa = kvmalloc_array(mem->page_cnt, sizeof(u64), GFP_KERNEL | __GFP_ZERO);
		if (!mem->pa) {
			ret = -ENOMEM;
			goto error_iommu_mapping;
		}
	}
#endif

	ret = octep_iommu_mapping(rdma_dev, mem);
	if (ret) {
		ibdev_err(&rdma_dev->ibdev, "octep_iommu_mapping failed\n");
		goto error_iommu_mapping;
	}

	return 0;

error_iommu_mapping:
#ifdef CONFIG_OCTEP_RDMA_OCTTERM
	kvfree(mem->pa);
	mem->pa = NULL;
#endif
	if (mem->mtt_buf) {
		kvfree(mem->mtt_buf);
		mem->mtt_buf = NULL;
	}

error_ret:
	if (mem->umem) {
		ib_umem_release(mem->umem);
		mem->umem = NULL;
	}

	return ret;
}

void release_mem_trans_tbl(struct octep_rdma_dev *rdma_dev, struct octep_rdma_mem *mem)
{
	octep_iommu_unmapping(rdma_dev, mem);
#ifdef CONFIG_OCTEP_RDMA_OCTTERM
	kvfree(mem->pa);
	mem->pa = NULL;
#endif
	if (mem->mtt_buf) {
		kvfree(mem->mtt_buf);
		mem->mtt_buf = NULL;
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

#ifdef CONFIG_OCTEP_RDMA_OCTTERM

/*
 * Make an MR mmappable through the octterm cdev.  Called before the MR
 * register mbox is sent, because the FW maps the MR while it handles that
 * mbox.  If the mbox fails the caller removes the entry again with
 * octep_rdma_mr_map_remove().  mr_map_lock is not held across the mbox.
 */
int octep_rdma_mr_map_add(struct octep_rdma_dev *rdma_dev, struct octep_rdma_mr *mr, u32 pdn)
{
	unsigned long key = mr->lkey;
	void *old;
	int ret = 0;

	/* lkey 0 would collide with the DDR region offset */
	if (!key)
		return -EINVAL;

	mr->pdn = pdn;

	mutex_lock(&rdma_dev->mr_map_lock);
	if (xa_load(&rdma_dev->mr_map_xa, key)) {
		ret = -EBUSY;
	} else {
		old = xa_store(&rdma_dev->mr_map_xa, key, mr, GFP_KERNEL);
		if (xa_is_err(old))
			ret = xa_err(old);
		else
			mr->mmap_added = true;
	}
	mutex_unlock(&rdma_dev->mr_map_lock);

	return ret;
}

/*
 * Drop the MR from the lookup table and zap every user mapping of its pages.
 * Must run before the pages are unpinned (release_mem_trans_tbl()).
 * Safe for MRs that were never added.
 */
void octep_rdma_mr_map_remove(struct octep_rdma_dev *rdma_dev, struct octep_rdma_mr *mr)
{
	struct octterm_cdev *odev = rdma_dev->octterm;
	unsigned long key = mr->lkey;
	struct address_space *mapping;

	if (!mr->mmap_added)
		return;

	mutex_lock(&rdma_dev->mr_map_lock);
	xa_erase(&rdma_dev->mr_map_xa, key);

	/* pairs with smp_store_release() in octterm_dev_open() */
	mapping = odev ? smp_load_acquire(&odev->mapping) : NULL;
	if (mapping) {
		if (mr->mrbuf_mtt.page_cnt)
			unmap_mapping_range(mapping, (loff_t)key << PAGE_SHIFT,
					    (loff_t)mr->mrbuf_mtt.page_cnt << PAGE_SHIFT, 1);
	}
	mutex_unlock(&rdma_dev->mr_map_lock);

	mr->mmap_added = false;
}

/*
 * A VMA without vm_ops is treated as anonymous memory by the core MM, so after
 * the dereg-time zap a stale access would silently get a zero page.  Install a
 * fault handler that always fails so a stale mapping raises SIGBUS instead.
 */
static vm_fault_t octep_mr_vm_fault(struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}

static const struct vm_operations_struct octep_mr_vm_ops = {
	.fault = octep_mr_vm_fault,
};

/*
 * mmap() of a registered MR.  vm_pgoff is the MR lkey, the length is the
 * number of MR pages to map (1 .. page_cnt) starting at the first MR page.
 */
int octep_rdma_mr_mmap(struct octep_rdma_dev *rdma_dev, struct vm_area_struct *vma)
{
	unsigned long lkey = vma->vm_pgoff;
	unsigned long npages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
	struct octep_rdma_mr *mr;
	unsigned long i;
	int ret;

	/* Must be a shared mapping (no COW) */
	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	mutex_lock(&rdma_dev->mr_map_lock);
	mr = xa_load(&rdma_dev->mr_map_xa, lkey);
	if (!mr) {
		/* Not registered (yet), or already deregistered */
		ret = -ENOENT;
		goto out;
	}

	if (!(mr->access & IB_ACCESS_REMOTE_ATOMIC)) {
		ret = -EACCES;
		goto out;
	}

	if (!mr->mrbuf_mtt.pa || !npages || npages > mr->mrbuf_mtt.page_cnt) {
		ret = -EINVAL;
		goto out;
	}

	for (i = 0; i < npages; i++) {
		if (!mr->mrbuf_mtt.pa[i]) {
			ret = -EFAULT;
			goto out;
		}
	}

	/*
	 * The pages are pinned user memory (anonymous), which vm_insert_page()
	 * refuses.  Map the PFNs directly; the umem pin keeps the pages alive
	 * and the dereg path zaps the mapping before unpinning.  The pages are
	 * physically scattered but end up virtually contiguous.
	 */
	vma->vm_ops = &octep_mr_vm_ops;
	vm_flags_set(vma, VM_DONTCOPY);
	for (i = 0; i < npages; i++) {
		ret = remap_pfn_range(vma, vma->vm_start + (i << PAGE_SHIFT),
				      PHYS_PFN(mr->mrbuf_mtt.pa[i]), PAGE_SIZE, vma->vm_page_prot);
		if (ret) {
			ibdev_err(&rdma_dev->ibdev, "MR mmap lkey 0x%lx page %lu failed %d\n", lkey,
				  i, ret);
			goto out;
		}
	}

	ibdev_dbg(&rdma_dev->ibdev, "MR mmap lkey 0x%lx pages %lu\n", lkey, npages);
out:
	mutex_unlock(&rdma_dev->mr_map_lock);
	return ret;
}

#endif /* CONFIG_OCTEP_RDMA_OCTTERM */
