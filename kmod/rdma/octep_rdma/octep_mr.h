/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Marvell.
 */

#ifndef __OCTEP_MR_H__
#define __OCTEP_MR_H__

#include "octep_rdma.h"
/*
 * MemoryRegion definition.
 */
#define OCTEP_RDMA_MAX_INLINE_MTT_ENTRIES 4
#define MTT_SIZE(mtt_cnt)                 ((mtt_cnt) << 3) /* per mtt takes 8 Bytes. */
#define OCTEP_RDMA_MR_MAX_MTT_CNT         524288
#define OCTEP_RDMA_MTT_ENTRY_SIZE         8

#define OCTEP_RDMA_MR_TYPE_NORMAL 0
#define OCTEP_RDMA_MR_TYPE_FRMR   1
#define OCTEP_RDMA_MR_TYPE_DMA    2

#define OCTEP_RDMA_MR_INLINE_MTT   0
#define OCTEP_RDMA_MR_INDIRECT_MTT 1

#define OCTEP_RDMA_MR_ACC_RA BIT(0)
#define OCTEP_RDMA_MR_ACC_LR BIT(1)
#define OCTEP_RDMA_MR_ACC_LW BIT(2)
#define OCTEP_RDMA_MR_ACC_RR BIT(3)
#define OCTEP_RDMA_MR_ACC_RW BIT(4)

/* REG MR attrs */
#define OCTEP_RDMA_SQE_MR_ACCESS_MASK   GENMASK(5, 1)
#define OCTEP_RDMA_SQE_MR_MTT_TYPE_MASK GENMASK(7, 6)
#define OCTEP_RDMA_SQE_MR_MTT_CNT_MASK  GENMASK(31, 12)

struct octep_rdma_ucontext;
struct octep_rdma_reg_mr_sqe {
	__le64 hdr;
	__le64 addr;
	__le32 length;
	__le32 stag;
	__le32 attrs;
	__le32 rsvd;
};

struct octep_rdma_mem {
	struct ib_umem *umem;
	void *mtt_buf;
	u32 mtt_type;
	u32 page_size;
	u32 page_offset;
	u32 page_cnt;
	u32 mtt_nents;

	u64 va;
	u64 len;

	u64 *iova;
	u64 size;

	u64 mtt_entry[OCTEP_RDMA_MAX_INLINE_MTT_ENTRIES];
};

enum octep_rdma_mr_state {
	OCTEP_RDMA_MR_STATE_INVALID,
	OCTEP_RDMA_MR_STATE_FREE,
	OCTEP_RDMA_MR_STATE_VALID,
};

struct octep_rdma_mr {
	struct ib_mr ibmr;

	struct ib_umem *umem;

	u32 lkey;
	u32 rkey;
	enum octep_rdma_mr_state state;
	int access;
	atomic_t num_mw;

	unsigned int page_offset;
	unsigned int page_shift;
	u64 page_mask;

	u32 num_buf;
	u32 nbuf;
	u32 mrn;

	struct octep_rdma_mem mrbuf_mtt;

	struct xarray page_list;
};

struct octep_rdma_user_mmap_entry {
	struct rdma_user_mmap_entry rdma_entry;
	u64 address;
	u8 mmap_flag;
};

static inline struct octep_rdma_user_mmap_entry *
to_octep_rdma_mmap(struct rdma_user_mmap_entry *ibmmap)
{
	return container_of(ibmmap, struct octep_rdma_user_mmap_entry, rdma_entry);
}

static inline struct octep_rdma_mr *
to_octep_rdma_mr(struct ib_mr *ibmr)
{
	return ibmr ? container_of(ibmr, struct octep_rdma_mr, ibmr) : NULL;
}

void octep_rdma_mr_init(int access, struct octep_rdma_mr *mr, int mrn);
struct rdma_user_mmap_entry *octep_rdma_mmap_entry_insert(struct octep_rdma_ucontext *uctx,
							  u64 address, size_t length, u8 mmap_flag,
							  u64 *offset);
int setup_mem_trans_tbl(struct octep_rdma_dev *rdma_dev, struct octep_rdma_mem *mem, u64 start,
			u64 len, int access, u64 virt, unsigned long req_page_size,
			u8 force_indirect_mtt);
void release_mem_trans_tbl(struct octep_rdma_dev *rdma_dev, struct octep_rdma_mem *mem);
int octep_rdma_prepare_mr_register_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_mr *mr,
				       u32 pdn);
int octep_rdma_prepare_mr_deregister_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_mr *mr,
					 u32 pdn);
#endif /* __OCTEP_MR_H__ */
