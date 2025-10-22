/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 Marvell.
 */

#ifndef __OCTEP_VERBS_H__
#define __OCTEP_VERBS_H__

#include <rdma/ib_verbs.h>
#include <rdma/octep_rdma-abi.h>

#include "octep_ah.h"
#include "octep_cq.h"
#include "octep_mr.h"
#include "octep_pd.h"
#include "octep_qp.h"
#include "octep_rdma.h"

/* WQE related. */
#define EQE_SIZE          16
#define EQE_SHIFT         4
#define RQE_SIZE          32
#define RQE_SHIFT         5
#define CQE_SIZE          32
#define CQE_SHIFT         5
#define SQEBB_SIZE        32
#define SQEBB_SHIFT       5
#define SQEBB_MASK        (~(SQEBB_SIZE - 1))
#define SQEBB_ALIGN(size) (((size) + SQEBB_SIZE - 1) & SQEBB_MASK)
#define SQEBB_COUNT(size) (SQEBB_ALIGN(size) >> SQEBB_SHIFT)

#define OCTEP_RDMA_MAX_SQE_SIZE      128
#define OCTEP_RDMA_MAX_WQEBB_PER_SQE 64

/* hardware page size definition */
#define OCTEP_RDMA_HW_PAGE_SHIFT 12
#define OCTEP_RDMA_HW_PAGE_SIZE  4096

/* FIXME: eRDMA PCIe DBs definition. */
#define OCTEP_RDMA_BAR_DB_SPACE_BASE 4096

#define OCTEP_RDMA_BAR_SQDB_SPACE_OFFSET OCTEP_RDMA_BAR_DB_SPACE_BASE
#define OCTEP_RDMA_BAR_SQDB_SPACE_SIZE   (384 * 1024)

#define OCTEP_RDMA_BAR_RQDB_SPACE_OFFSET                                                           \
	(OCTEP_RDMA_BAR_SQDB_SPACE_OFFSET + OCTEP_RDMA_BAR_SQDB_SPACE_SIZE)
#define OCTEP_RDMA_BAR_RQDB_SPACE_SIZE (96 * 1024)

#define OCTEP_RDMA_BAR_CQDB_SPACE_OFFSET                                                           \
	(OCTEP_RDMA_BAR_RQDB_SPACE_OFFSET + OCTEP_RDMA_BAR_RQDB_SPACE_SIZE)

#define OCTEP_RDMA_SGE_PER_WQE 4
#define OCTEP_RDMA_MAX_IOVLEN  1024

#define OCTEP_RDMA_MSG_MAX      20
#define OCTEP_RDMA_MSG_SIZE_MAX (OCTEP_RDMA_MAX_IOVLEN * PAGE_SIZE)

static inline u8
to_octep_rdma_access_flags(int access)
{
	return (access & IB_ACCESS_REMOTE_READ ? OCTEP_RDMA_MR_ACC_RR : 0) |
	       (access & IB_ACCESS_LOCAL_WRITE ? OCTEP_RDMA_MR_ACC_LW : 0) |
	       (access & IB_ACCESS_REMOTE_WRITE ? OCTEP_RDMA_MR_ACC_RW : 0) |
	       (access & IB_ACCESS_REMOTE_ATOMIC ? OCTEP_RDMA_MR_ACC_RA : 0);
}

enum octep_rdma_wq_flag {
	OCTEP_RDMA_WQ_EMPTY,
	OCTEP_RDMA_WQ_POST,
};

enum octep_rdma_wq_status {
	OCTEP_RDMA_WQ_UNINITIALIZED,
	OCTEP_RDMA_WQ_INITIALIZED,
	OCTEP_RDMA_WQ_RUNNING,
	OCTEP_RDMA_WQ_EXITED,
};

enum octep_rdma_wq_type {
	OCTEP_RDMA_SQ,
	OCTEP_RDMA_RQ,
};

/* SQE */
#define OCTEP_RDMA_SQE_HDR_SGL_LEN_MASK     GENMASK_ULL(63, 56)
#define OCTEP_RDMA_SQE_HDR_WQEBB_CNT_MASK   GENMASK_ULL(54, 52)
#define OCTEP_RDMA_SQE_HDR_QPN_MASK         GENMASK_ULL(51, 32)
#define OCTEP_RDMA_SQE_HDR_OPCODE_MASK      GENMASK_ULL(31, 27)
#define OCTEP_RDMA_SQE_HDR_DWQE_MASK        BIT_ULL(26)
#define OCTEP_RDMA_SQE_HDR_INLINE_MASK      BIT_ULL(25)
#define OCTEP_RDMA_SQE_HDR_FENCE_MASK       BIT_ULL(24)
#define OCTEP_RDMA_SQE_HDR_SE_MASK          BIT_ULL(23)
#define OCTEP_RDMA_SQE_HDR_CE_MASK          BIT_ULL(22)
#define OCTEP_RDMA_SQE_HDR_WQEBB_INDEX_MASK GENMASK_ULL(15, 0)

struct octep_rdma_write_sqe {
	__le64 hdr;
	__be32 imm_data;
	__le32 length;

	__le32 sink_stag;
	__le32 sink_to_l;
	__le32 sink_to_h;

	__le32 rsvd;

	struct octep_rdma_sge sgl[];
};

struct octep_rdma_send_sqe {
	__le64 hdr;
	union {
		__be32 imm_data;
		__le32 invalid_stag;
	};

	__le32 length;
	struct octep_rdma_sge sgl[];
};

struct octep_rdma_readreq_sqe {
	__le64 hdr;
	__le32 invalid_stag;
	__le32 length;
	__le32 sink_stag;
	__le32 sink_to_l;
	__le32 sink_to_h;
	__le32 rsvd;
};

struct octep_rdma_atomic_sqe {
	__le64 hdr;
	__le64 rsvd;
	__le64 fetchadd_swap_data;
	__le64 cmp_data;

	struct octep_rdma_sge remote;
	struct octep_rdma_sge sgl;
};

struct octep_rdma_sge_map {
	struct iovec *mr_pages;
	u64 base_offset;
	u64 page_offset;
	u64 page_count;
	u64 sge_len;
	u8 is_dma;
};

struct octep_rdma_wqe {
	struct ib_qp *ibqp;
	struct iovec *page_map_dynamic;
	struct iovec page_map_static[OCTEP_RDMA_SGE_PER_WQE];
	u32 wr_id;
	u32 l_qpn;
	u32 byte_len;
	u8 opcode;
};

struct octep_rdma_pd {
	struct ib_pd ibpd;
	u32 pdn;
	struct octep_rdma_resource_cb mr_res_cb;
};

struct octep_rdma_ucontext {
	struct ib_ucontext ibucontext;
	struct octep_rdma_dev *rdma_dev;
	u64 db_region;
	struct rdma_user_mmap_entry *db_mmap_entry;
};

enum {
	OCTEP_RDMA_MMAP_IO_NC = 0, /* no cache */
};

static inline struct octep_rdma_ucontext *
to_octep_rdma_ctx(struct ib_ucontext *ibucontext)
{
	return ibucontext ? container_of(ibucontext, struct octep_rdma_ucontext, ibucontext) : NULL;
}

static inline struct octep_rdma_dev *
to_octep_rdma_dev(struct ib_device *ibdev)
{
	return ibdev ? container_of(ibdev, struct octep_rdma_dev, ibdev) : NULL;
}

static inline struct octep_rdma_pd *
to_octep_rdma_pd(struct ib_pd *ibpd)
{
	return ibpd ? container_of(ibpd, struct octep_rdma_pd, ibpd) : NULL;
}

static inline struct octep_rdma_ah *
to_octep_rdma_ah(struct ib_ah *ibah)
{
	return ibah ? container_of(ibah, struct octep_rdma_ah, ibah) : NULL;
}

static inline struct octep_rdma_cq *
to_octep_rdma_cq(struct ib_cq *ibcq)
{
	return ibcq ? container_of(ibcq, struct octep_rdma_cq, ibcq) : NULL;
}

// Ucontext verbs.
int octep_rdma_alloc_ucontext(struct ib_ucontext *ibucontext, struct ib_udata *udata);
void octep_rdma_dealloc_ucontext(struct ib_ucontext *ibucontext);

// Protection Domain verbs.
int octep_rdma_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata);
int octep_rdma_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata);

// Device verbs.
int octep_rdma_query_device(struct ib_device *ibdev, struct ib_device_attr *dev_attr,
			    struct ib_udata *udata);
int octep_rdma_query_port(struct ib_device *ibdev, u32 port, struct ib_port_attr *port_attr);
int octep_rdma_get_port_immutable(struct ib_device *ibdev, u32 port_num,
				  struct ib_port_immutable *immutable);
// Memory Region verbs.
struct ib_mr *octep_rdma_reg_user_mr(struct ib_pd *ibpd, u64 start, u64 length, u64 va, int access,
				     struct ib_udata *udata);
struct ib_mr *octep_rdma_get_dma_mr(struct ib_pd *ibpd, int access);
int octep_rdma_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata);

// Completion Queue verbs.
int octep_rdma_create_cq(struct ib_cq *ibcq, const struct ib_cq_init_attr *init_attr,
			 struct ib_udata *udata);

int octep_rdma_poll_cq(struct ib_cq *ibcq, int num_wc, struct ib_wc *ibwc);
int octep_rdma_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags);
int octep_rdma_destroy_cq(struct ib_cq *ibcq, struct ib_udata *udata);

// Queue pair verbs.
int octep_rdma_create_qp(struct ib_qp *ibqp, struct ib_qp_init_attr *init_attr,
			 struct ib_udata *udata);
int octep_rdma_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask,
			struct ib_qp_init_attr *init_attr);
int octep_rdma_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask,
			 struct ib_udata *udata);
int octep_rdma_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata);
int octep_rdma_post_send(struct ib_qp *ibqp, const struct ib_send_wr *send_wr,
			 const struct ib_send_wr **bad_wr);
int octep_rdma_post_recv(struct ib_qp *ibqp, const struct ib_recv_wr *recv_wr,
			 const struct ib_recv_wr **bad_wr);
int octep_rdma_query_pkey(struct ib_device *ibdev, u32 port, u16 index, u16 *pkey);

enum rdma_link_layer octep_rdma_get_link_layer(struct ib_device *ibdev, u32 port_num);
int octep_rdma_create_ah(struct ib_ah *ibah, struct rdma_ah_init_attr *init_attr,
			 struct ib_udata *udata);
int octep_rdma_query_ah(struct ib_ah *ibah, struct rdma_ah_attr *attr);
int octep_rdma_destroy_ah(struct ib_ah *ibah, u32 flags);
int octep_rdma_modify_ah(struct ib_ah *ibah, struct rdma_ah_attr *attr);
int octep_rdma_mmap(struct ib_ucontext *ctx, struct vm_area_struct *vma);
void octep_rdma_mmap_free(struct rdma_user_mmap_entry *rdma_entry);
int octep_rdma_add_gid(const struct ib_gid_attr *attr, void **context);
int octep_rdma_del_gid(const struct ib_gid_attr *attr, void **context);
void octep_rdma_disassociate_ucontext(struct ib_ucontext *ibcontext);
#endif /* __OCTEP_VERBS_H__ */
