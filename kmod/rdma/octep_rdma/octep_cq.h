/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Marvell.
 */

#ifndef __OCTEP_CQ_H__
#define __OCTEP_CQ_H__

#include "octep_mr.h"

struct octep_rdma_kcq_info {
	/* Hot data - frequently accessed fields (first cache line) */
	void *qbuf;       /* Buffer pointer - hot */
	atomic_t *pi_dbl; /* Producer index - hot */
	atomic_t *ci_dbl; /* Consumer index - hot */
	u8 __iomem *db;   /* Doorbell pointer - hot */

	/* Medium frequency access - control fields */
	spinlock_t lock;           /* Lock for synchronization */
	u32 ci;                    /* Consumer index value */
	u32 size;                  /* Buffer size */
	u32 notify_off_multiplier; /* Notification offset multiplier */

	/* Cold data - rarely accessed after initialization */
	dma_addr_t qbuf_dma_addr; /* DMA address - cold */
	u64 db_region;            /* Doorbell region - cold */
	u64 *iova;                /* IOVA pointer - cold */
} ____cacheline_aligned;

struct octep_rdma_ucq_info {
	struct octep_rdma_mem qbuf_mtt;
	struct octep_rdma_user_dbrecords_page *user_dbr_page;
	dma_addr_t db_info_dma_addr;
};

struct octep_rdma_cq {
	/* First cache line: Hot data - frequently accessed in polling path */
	struct ib_cq ibcq; /* IB CQ structure - hot */
	u32 depth;         /* Queue depth - hot */
	u32 qmask;         /* Queue mask - hot */
	u32 cqn;           /* CQ number - medium frequency */
	u8 notify;         /* Notification flags - hot */
	u8 __pad[3];       /* Padding for alignment */

	/* Second cache line onwards: Cold data - rarely accessed after init */
	union {
		struct octep_rdma_kcq_info kern_cq;
		struct octep_rdma_ucq_info user_cq;
	};
} ____cacheline_aligned;

struct octep_kern_cq_entry {
	struct octep_rdma_cq *cq;
	struct list_head list;
};

int octep_rdma_poll_one_cqe(struct octep_rdma_cq *cq, struct ib_wc *wc, int num_entries);
int octep_rdma_init_kernel_cq(struct octep_rdma_cq *cq);
void octep_rdma_free_kernel_cq(struct octep_rdma_dev *rdma_dev, struct octep_rdma_cq *cq);
int octep_rdma_init_user_cq(struct octep_rdma_cq *cq, struct octep_rdma_ureq_create_cq *ureq);
int octep_rdma_prepare_cq_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_cq *cq,
			      bool is_user);
int octep_rdma_prepare_cq_destroy_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_cq *cq);
int octep_rdma_kern_cq_poll_insert(struct octep_rdma_cq *cq);
int octep_rdma_kern_cq_poll_remove(struct octep_rdma_cq *cq);
int octep_rdma_kern_cq_poll_thread(void);
void octep_rdma_kern_cq_poll_thread_cleanup(void);
void octep_rdma_kern_cq_poll_thread_force_cleanup(void);
#endif /* __OCTEP_CQ_H__ */
