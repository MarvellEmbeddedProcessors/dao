/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Marvell.
 */

#ifndef __OCTEP_QP_H__
#define __OCTEP_QP_H__

#include "octep_mr.h"
#include "octep_rdma.h"

#define QP_ID(qp) ((qp)->ibqp.qp_num)

struct octep_rdma_uqp {
	struct octep_rdma_mem sq_mtt;
	struct octep_rdma_mem rq_mtt;

	dma_addr_t sq_db_info_dma_addr;
	dma_addr_t rq_db_info_dma_addr;

	struct octep_rdma_user_dbrecords_page *user_dbr_page;
	void *sq_vaddr;
	void *rq_vaddr;

	u32 rq_offset;
};

struct octep_rdma_queue {
	/* Hot path data - first cache line (64 bytes) */
	void *qbuf;       /* Queue buffer - frequently accessed */
	void __iomem *db; /* Doorbell register - hot path */
	atomic_t *pi_dbl; /* Producer index - hot path */
	atomic_t *ci_dbl; /* Consumer index - hot path */

	u16 pi;     /* Producer index - hot path */
	u16 depth;  /* Queue depth - hot path */
	u16 qmask;  /* Queue mask - hot path */
	u8 sig_all; /* Signal all flag - moderate usage */
	u8 pad1;    /* Padding for alignment */

	/* Cold path data - second cache line */
	dma_addr_t qbuf_dma_addr; /* DMA address - setup only */
	u32 size;                 /* Buffer size - setup only */
	u32 pad2;                 /* Padding for alignment */
} ____cacheline_aligned;

struct octep_rdma_kqp {
	/* Queue structures - cache-line aligned for performance */
	struct octep_rdma_queue sq ____cacheline_aligned;
	struct octep_rdma_queue rq ____cacheline_aligned;

	/* Setup-time configuration - cold data */
	u64 db_region;             /* Doorbell region base */
	u32 notify_off_multiplier; /* Notification offset multiplier */
	u32 pad;                   /* Padding for alignment */
} ____cacheline_aligned;

enum octep_rdma_qp_state {
	OCTEP_RDMA_QP_STATE_RESET = 0,
	OCTEP_RDMA_QP_STATE_INIT = 1,
	OCTEP_RDMA_QP_STATE_RTR = 2,
	OCTEP_RDMA_QP_STATE_RTS = 3,
	OCTEP_RDMA_QP_STATE_SQD = 4,
	OCTEP_RDMA_QP_STATE_SQE = 5,
	OCTEP_RDMA_QP_STATE_ERR = 6,
};

#define OCTEP_RDMA_QP_MOD_QP_STATE           BIT(0)
#define OCTEP_RDMA_QP_MOD_CUR_QP_STATE       BIT(1)
#define OCTEP_RDMA_QP_MOD_SQD_ASYNC_NOTIFY   BIT(2)
#define OCTEP_RDMA_QP_MOD_ACCESS_FLAGS       BIT(3)
#define OCTEP_RDMA_QP_MOD_PKEY_INDEX         BIT(4)
#define OCTEP_RDMA_QP_MOD_PORT               BIT(5)
#define OCTEP_RDMA_QP_MOD_QKEY               BIT(6)
#define OCTEP_RDMA_QP_MOD_AV                 BIT(7)
#define OCTEP_RDMA_QP_MOD_PATH_MTU           BIT(8)
#define OCTEP_RDMA_QP_MOD_TIMEOUT            BIT(9)
#define OCTEP_RDMA_QP_MOD_RETRY_CNT          BIT(10)
#define OCTEP_RDMA_QP_MOD_RNR_RETRY          BIT(11)
#define OCTEP_RDMA_QP_MOD_RQ_PSN             BIT(12)
#define OCTEP_RDMA_QP_MOD_MAX_QP_RD_ATOMIC   BIT(13)
#define OCTEP_RDMA_QP_MOD_ALT_PATH           BIT(14)
#define OCTEP_RDMA_QP_MOD_MIN_RNR_TIMER      BIT(15)
#define OCTEP_RDMA_QP_MOD_SQ_PSN             BIT(16)
#define OCTEP_RDMA_QP_MOD_MAX_DEST_RD_ATOMIC BIT(17)
#define OCTEP_RDMA_QP_MOD_PATH_MIG_STATE     BIT(18)
#define OCTEP_RDMA_QP_MOD_CAP                BIT(19)
#define OCTEP_RDMA_QP_MOD_DEST_QPN           BIT(20)
#define OCTEP_RDMA_QP_MOD_SRC_PORT           BIT(21)

struct octep_rdma_qp_mod_attrs {
	u32 modify_mask;
	enum octep_rdma_qp_state new_qp_state;
	enum octep_rdma_qp_state cur_qp_state;
	int qp_access_flags;
	int path_mtu;
	u32 qkey;
	u16 pkey_index;
	u8 sq_drained_async_notify;
	int max_dest_rd_atomic;
	int max_rd_atomic;
	int min_rnr_timer;
	u8 rnr_retry_cnt;
	u8 retry_cnt;
	u8 timeout;
	u8 port_num;
	u16 qp_id;
	u16 src_udp_port;
	u32 rq_psn;
	u32 sq_psn;
	u32 dest_qpn;
	struct octep_rdma_av mod_av;
};

enum octep_rdma_qp_mod_flags {
	OCTEP_RDMA_QP_IN_FLUSHING = (1 << 0),
};

struct octep_rdma_qp_attrs {
	enum octep_rdma_qp_state state;
	u32 sq_size;
	u32 rq_size;
	u32 orq_size;
	u32 irq_size;
	u32 max_send_sge;
	u32 max_recv_sge;
	u32 cookie;
	u8 qp_type;
	u8 pd_len;
	u8 sq_sig_type;
	u32 dest_qpn;
	u32 qkey;
	int mtu;
	struct octep_rdma_av cur_av;
	struct octep_rdma_qp_mod_attrs *qp_mod_attr;
};

struct octep_rdma_qp {
	struct ib_qp ibqp;
	struct kref ref;
	struct completion safe_free;
	struct octep_rdma_dev *rdma_dev;
	struct rw_semaphore state_lock;

	unsigned long flags;

	union {
		struct octep_rdma_kqp kern_qp;
		struct octep_rdma_uqp user_qp;
	};
	union octep_rdma_sqe *sendq; /* send queue element array */

	struct octep_rdma_cq *scq;
	struct octep_rdma_cq *rcq;

	struct octep_rdma_qp_attrs attrs;
	int sq_get;
	spinlock_t lock;             /* lock for synchronization */
	union octep_rdma_rqe *recvq; /* recv queue element array */
	u32 rq_get;                  /* consumer index into rq array */
	u32 rq_put;                  /* kernel prod. index into rq array */
	spinlock_t rq_lock;
};

static inline struct octep_rdma_qp *
to_octep_rdma_qp(struct ib_qp *ibqp)
{
	struct octep_rdma_qp *qp;

	if (!ibqp)
		return NULL;

	qp = container_of(ibqp, struct octep_rdma_qp, ibqp);

	/* Basic sanity check - verify qp points back to the same ibqp */
	if (unlikely(&qp->ibqp != ibqp)) {
		pr_err("%s: Invalid QP conversion, corrupted structure\n", __func__);
		return NULL;
	}

	return qp;
}

static inline void *
get_queue_entry(void *qbuf, u32 idx, u32 depth, u32 shift)
{
	/* Validate parameters */
	if (!qbuf) {
		pr_err("%s: qbuf is NULL\n", __func__);
		return NULL;
	}

	if (!depth || (depth & (depth - 1))) {
		pr_err("%s: depth %u is not power of 2\n", __func__, depth);
		return NULL;
	}

	/* Sanity check shift to prevent integer overflow */
	if (shift > 31) {
		pr_err("%s: shift %u too large\n", __func__, shift);
		return NULL;
	}

	/* Mask index to queue depth (efficient modulo for power of 2) */
	idx &= (depth - 1);

	return qbuf + (idx << shift);
}

int octep_rdma_modify_qp_attr_populate(struct octep_rdma_qp *qp, struct ib_qp_attr *qp_attr,
				       int qp_attr_mask,
				       struct octep_rdma_qp_mod_attrs *qp_mod_attr);
int octep_rdma_modify_qp_validate(struct octep_rdma_qp *qp, struct ib_qp_attr *qp_attr,
				  int qp_attr_mask);
int octep_rdma_prepare_qp_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_qp *qp, u32 pdn,
			      bool is_user);
int octep_rdma_prepare_qp_state_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_qp *qp,
				    bool enable);
int octep_rdma_prepare_user_qp_modify_cmd(struct octep_rdma_dev *rdma_dev,
					  struct octep_rdma_qp *qp);
int octep_rdma_prepare_user_qp_destroy_cmd(struct octep_rdma_dev *rdma_dev,
					   struct octep_rdma_qp *qp);
int init_kernel_qp(struct octep_rdma_dev *rdma_dev, struct octep_rdma_qp *qp,
		   struct ib_qp_init_attr *attrs);
void free_kernel_qp(struct octep_rdma_dev *rdma_dev, struct octep_rdma_qp *qp);
int init_user_qp(struct octep_rdma_dev *rdma_dev, struct octep_rdma_qp *qp, struct ib_udata *udata);
int user_define_qp(struct octep_rdma_dev *rdma_dev, struct octep_rdma_qp *qp,
		   struct ib_udata *udata);
int octep_rdma_qp_validate_attr(struct octep_rdma_dev *dev, struct ib_qp_init_attr *attrs);
int octep_rdma_qp_validate_cap(struct octep_rdma_dev *rdma_dev, struct ib_qp_init_attr *attrs);
void octep_rdma_qp_get(struct octep_rdma_qp *qp);
void octep_rdma_qp_put(struct octep_rdma_qp *qp);
#endif /* __OCTEP_QP_H__ */
