/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell.
 */
#ifndef __INCLUDE_PTS_RDMA_MBOX_H__
#define __INCLUDE_PTS_RDMA_MBOX_H__

#include <pts_rdma_dev_priv.h>

#define PTS_RDMA_DEV_MBOX_H2D_SIZE 8192
#define PTS_RDMA_DEV_MBOX_D2H_SIZE 8192

#define PTS_RDMA_DEV_MBOX_SIZE (PTS_RDMA_DEV_MBOX_H2D_SIZE + PTS_RDMA_DEV_MBOX_D2H_SIZE)

enum pts_rdma_dev_mbox_ids {
	MBOX_MSG_SET_QP_CONFIG = 1,
	MBOX_MSG_SET_QP_STATE,
	MBOX_MSG_SET_CQ_CONFIG,
	MBOX_MSG_SET_CQ_STATE,
	MBOX_MSG_USER_DEFINED = 0x200,
};

/* Mbox data structures */

/* Management QP type — raw Ethernet traffic routed through this QP */
#define PTS_RDMA_QP_TYPE_MGMT 0xFF

/* MBOX_MSG_SET_QP_CONFIG */
struct pts_rdma_dev_set_qp_config_req {
	uint16_t port_id;
	uint16_t qp_id;
	uint16_t pd_id;
	uint16_t sq_size;
	uint16_t rq_size;
	uint16_t send_cq_id;
	uint16_t recv_cq_id;
	uint8_t type;
	uint8_t sq_sig_type;
	uint64_t sq_base;
	uint64_t rq_base;
	uint64_t ibqp;
};

/* MBOX_MSG_SET_QP_STATE */
struct pts_rdma_dev_set_qp_state_req {
	uint16_t port_id;
	uint16_t qp_id;
	uint16_t enable;
};

/* MBOX_MSG_SET_CQ_CONFIG */
struct pts_rdma_dev_set_cq_config_req {
	uint16_t port_id;
	uint16_t cq_id;
	uint16_t size;
	uint64_t cq_base;
};

/* MBOX_MSG_SET_CQ_STATE */
struct pts_rdma_dev_set_cq_state_req {
	uint16_t port_id;
	uint16_t cq_id;
	uint16_t enable;
};

int pts_rdma_dev_mbox_init(struct pts_rdma_dev *dev);
void pts_rdma_dev_mbox_fini(struct pts_rdma_dev *dev);

#endif /* __INCLUDE_PTS_RDMA_MBOX_H__ */
