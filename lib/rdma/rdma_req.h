/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */
#ifndef RDMA_REQ_H
#define RDMA_REQ_H
#include "rdma_hdr.h"

int rdma_requester(struct rdma_qp *qp, struct rdma_send_wqe *wqe, struct rte_mbuf *mbuf,
		   bool more_segs, int num_pkt);
int dao_send_cqe(struct rdma_qp *qp, bool host_recv, struct rdma_send_wqe *wqe);
#endif /* RDMA_REQ_H */
