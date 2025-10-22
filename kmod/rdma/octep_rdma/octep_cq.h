/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Marvell.
 */

#ifndef __OCTEP_CQ_H__
#define __OCTEP_CQ_H__

#include "octep_mr.h"

struct octep_rdma_cmdq_destroy_cq_req {
	u64 hdr;
	u32 cqn;
};

struct octep_rdma_kcq_info {
	void *qbuf;
	dma_addr_t qbuf_dma_addr;
	u32 ci;
	u32 cmdsn;
	u32 notify_cnt;

	spinlock_t lock; /* Lock for synchronization */
	u8 __iomem *db;
	u64 *db_record;
};

struct octep_rdma_ucq_info {
	struct octep_rdma_mem qbuf_mtt;
	struct octep_rdma_user_dbrecords_page *user_dbr_page;
	dma_addr_t db_info_dma_addr;
};

struct octep_rdma_cq {
	struct ib_cq ibcq;
	u32 cqn;

	u32 depth;
	u32 assoc_eqn;

	union {
		struct octep_rdma_kcq_info kern_cq;
		struct octep_rdma_ucq_info user_cq;
	};
};

int octep_rdma_poll_one_cqe(struct octep_rdma_cq *cq, struct ib_wc *wc);
int octep_rdma_init_kernel_cq(struct octep_rdma_cq *cq);
int octep_rdma_init_user_cq(struct octep_rdma_cq *cq, struct octep_rdma_ureq_create_cq *ureq);
int octep_rdma_prepare_cq_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_cq *cq);
int octep_rdma_prepare_cq_destroy_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_cq *cq);
#endif /* __OCTEP_CQ_H__ */
