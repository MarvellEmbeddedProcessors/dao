/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 Marvell.
 * Shared file with host and FW
 */
#ifndef __OCTEP_MBOX_H__
#define __OCTEP_MBOX_H__

#include "octep_dev_cap.h"

enum octep_mbox_ids {
	OCTEP_RDMA_MBOX_MSG_SET_QP_CONFIG = 1,
	OCTEP_RDMA_MBOX_MSG_SET_QP_STATE,
	OCTEP_RDMA_MBOX_MSG_SET_CQ_CONFIG,
	OCTEP_RDMA_MBOX_MSG_SET_CQ_STATE,
	OCTEP_RDMA_MBOX_MSG_USER_DEFINED = 0x200,
};

enum octep_mbox_user_ids {
	OCTEP_RDMA_MBOX_MSG_USER_QP_CREATE = OCTEP_RDMA_MBOX_MSG_USER_DEFINED + 1,
	OCTEP_RDMA_MBOX_MSG_USER_QP_MODIFY,
	OCTEP_RDMA_MBOX_MSG_USER_QP_DESTROY,
	OCTEP_RDMA_MBOX_MSG_USER_CQ_CREATE,
	OCTEP_RDMA_MBOX_MSG_USER_CQ_DESTROY,
	OCTEP_RDMA_MBOX_MSG_USER_AH_CREATE,
	OCTEP_RDMA_MBOX_MSG_USER_AH_MODIFY,
	OCTEP_RDMA_MBOX_MSG_USER_AH_DESTROY,
	OCTEP_RDMA_MBOX_MSG_USER_PORT_STATE,
	OCTEP_RDMA_MBOX_MSG_USER_QUERY_DEVICE_CAP,
	OCTEP_RDMA_MBOX_MSG_USER_QUERY_PORT_ATTR,
	OCTEP_RDMA_MBOX_MSG_USER_PD_ADD,
	OCTEP_RDMA_MBOX_MSG_USER_PD_DELETE,
	OCTEP_RDMA_MBOX_MSG_USER_MR_REGISTER,
	OCTEP_RDMA_MBOX_MSG_USER_MR_DEREGISTER,
};

struct octep_rdma_ah_create_req {
	u16 index;
	u16 port_num;
	u8 network_type;
	u8 dmac[6];
	u8 smac[6];
	u8 rsvd; /* Padding for __be32 alignment */
	__be32 s_addr;
	__be32 d_addr;
};

struct octep_rdma_ah_destroy_req {
	u16 index;
	u16 port_num;
};

struct octep_rdma_cq_create_req {
	u16 port_num;
	u16 cq_id;
	u32 size;
	u64 cq_base;
};

/* MBOX_MSG_SET_CQ_STATE */
struct octep_rdma_cq_state_req {
	u16 port_num;
	u16 cq_id;
	u16 enable;
	u16 rsvd;
};

struct octep_rdma_cq_destroy_req {
	u16 port_num;
	u16 cq_id;
};

/*
 * OCTEP_RDMA_MBOX_MSG_SET_QP_CONFIG
 * Note: Field order matters for cross-architecture alignment (x86 <-> ARM).
 * u8 fields placed before u64 to ensure natural 8-byte alignment.
 */
/* Management QP type — firmware uses this to route raw Ethernet traffic */
#define OCTEP_RDMA_QP_TYPE_MGMT  0xFF

struct octep_rdma_qp_create_req {
	u16 port_num;
	u16 qp_id;
	u16 pd_id;
	u16 sq_size;
	u16 rq_size;
	u16 send_cq_id;
	u16 recv_cq_id;
	u8 type;
	u8 sq_sig_type;
	u64 sq_base;
	u64 rq_base;
	u64 ibqp;
};

/* OCTEP_RDMA_MSG_SET_QP_STATE */
struct octep_rdma_qp_state_req {
	u16 port_num;
	u16 qp_id;
	u16 enable;
	u16 rsvd;
};

struct octep_rdma_qp_destroy_req {
	u16 port_num;
	u16 qp_id;
};

/*
 * Note: Explicit padding for cross-architecture alignment (x86 <-> ARM).
 */
struct octep_rdma_user_qp_modify_req {
	u32 modify_mask;
	u8 new_qp_state;
	u8 cur_qp_state;
	u8 rsvd0[2]; /* Padding for u32 alignment */
	u32 qp_access_flags;
	u32 path_mtu;
	u32 qkey;
	u16 pkey_index;
	u8 sq_drained_async_notify;
	u8 rsvd1; /* Padding for u32 alignment */
	u32 max_dest_rd_atomic;
	u32 max_rd_atomic;
	u32 min_rnr_timer;
	u8 rnr_retry_cnt;
	u8 retry_cnt;
	u8 timeout;
	u8 rsvd2; /* Padding for u16 alignment */
	u16 port_num;
	u16 qp_id;
	u16 src_udp_port;
	u16 rsvd3; /* Padding for u32 alignment */
	u32 rq_psn;
	u32 sq_psn;
	u32 dest_qpn;

	/* Updated AV attributes */
	u8 network_type;
	u8 dmac[6];
	u8 smac[6];
	u8 rsvd4; /* Padding for __be32 alignment */
	__be32 s_addr;
	__be32 d_addr;
};

struct octep_rdma_evt_data {
	u16 link_state;
	u16 mtu;
	u32 rsvd;
};

struct octep_rdma_port_state_req {
	u16 port_num;
#define OCTEP_RDMA_USER_PORT_LINK_STATE BIT_ULL(0)
#define OCTEP_RDMA_USER_PORT_MTU_CHANGE BIT_ULL(1)
	u16 event;
	struct octep_rdma_evt_data evt_data;
};

struct octep_rdma_get_device_cap_msg {
	u16 port_num;
	u16 rsvd;
	struct octep_rdma_device_cap dev_cap;
};

struct octep_rdma_get_port_attr_msg {
	u16 port_num;
	u16 rsvd;
	struct octep_rdma_port_attr port_attr;
};

struct octep_rdma_pd_add_req {
	u32 pd_id;
	u32 port_num;
};

struct octep_rdma_pd_delete_req {
	u32 pd_id;
	u32 port_num;
};

struct octep_rdma_mr_data {
	u64 va;
	u32 length;
	u32 key;
	u32 access_flags;
};

struct octep_rdma_mr_register_req {
	u32 pd_id;
	u32 port_num;
	struct octep_rdma_mr_data mr;
};

struct octep_rdma_mr_deregister_req {
	u32 key;
	u32 pd_id;
	u32 port_num;
};

#endif /* __OCTEP_MBOX_H__ */
