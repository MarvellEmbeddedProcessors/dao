/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */
#ifndef __RDMA_RETRANSMIT_H__
#define __RDMA_RETRANSMIT_H__

#include "rdma_qp.h"
#include <rte_mbuf.h>

void rdma_setup_retransmission(rdma_qp_t *qp);
void rdma_timeout_handler_cb(struct rte_timer *tim, void *arg);
int rdma_check_retransmission_limit(rdma_qp_t *qp);
#endif //__RDMA_RETRANSMIT_H__
