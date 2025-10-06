/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __RDMA_MBOX_PRIV_H__
#define __RDMA_MBOX_PRIV_H__

#include "rdma_qp.h"
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

typedef enum rdma_qp_attr_mask {
	RDMA_QP_STATE = 1,
	RDMA_QP_CUR_STATE = (1 << 1),
	RDMA_QP_EN_SQD_ASYNC_NOTIFY = (1 << 2),
	RDMA_QP_ACCESS_FLAGS = (1 << 3),
	RDMA_QP_PKEY_INDEX = (1 << 4),
	RDMA_QP_PORT = (1 << 5),
	RDMA_QP_QKEY = (1 << 6),
	RDMA_QP_AV = (1 << 7),
	RDMA_QP_PATH_MTU = (1 << 8),
	RDMA_QP_TIMEOUT = (1 << 9),
	RDMA_QP_RETRY_CNT = (1 << 10),
	RDMA_QP_RNR_RETRY = (1 << 11),
	RDMA_QP_RQ_PSN = (1 << 12),
	RDMA_QP_MAX_QP_RD_ATOMIC = (1 << 13),
	RDMA_QP_ALT_PATH = (1 << 14),
	RDMA_QP_MIN_RNR_TIMER = (1 << 15),
	RDMA_QP_SQ_PSN = (1 << 16),
	RDMA_QP_MAX_DEST_RD_ATOMIC = (1 << 17),
	RDMA_QP_PATH_MIG_STATE = (1 << 18),
	RDMA_QP_CAP = (1 << 19),
	RDMA_QP_DEST_QPN = (1 << 20),
	RDMA_QP_SRC_PORT = (1 << 21),
} rdma_qp_attr_mask_e;

#endif /* __RDMA_MBOX_PRIV_H__ */
