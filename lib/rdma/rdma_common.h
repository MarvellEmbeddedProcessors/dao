/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */
#ifndef __RDMA_COMMON_H__
#define __RDMA_COMMON_H__
#include "rdma_qp.h"

#define OFFLD_UPPER_BITS 60
#ifndef STAILQ_FOREACH_SAFE
#define STAILQ_FOREACH_SAFE(var, head, field, tvar)                                                \
	for ((var) = STAILQ_FIRST((head)); (var) && ((tvar) = STAILQ_NEXT((var), field), 1);       \
	     (var) = (tvar))
#endif

static inline void
rdma_free_mbuf_list(struct rdma_mbufs *rmbuf)
{
	rmbuf->mbuf->ol_flags &= ~(0x7ULL << OFFLD_UPPER_BITS);
	rte_pktmbuf_free(rmbuf->mbuf);
}

static inline void
rdma_delete_all_wqe(struct rdma_qp *qp)
{
	struct rdma_send_wqe *wqe_next, *tmp;
	struct rdma_mbufs *rmbuf = NULL, *tmp_rmbuf = NULL;
	struct rdma_ack *ack_next, *tmp_ack;

	STAILQ_FOREACH_SAFE(wqe_next, &qp->req.wqe_head, next, tmp)
	{
		STAILQ_FOREACH_SAFE(rmbuf, &wqe_next->mbuf_list, next, tmp_rmbuf)
		{
			rdma_free_mbuf_list(rmbuf);
			STAILQ_REMOVE(&wqe_next->mbuf_list, rmbuf, rdma_mbufs, next);
			/* rmbuf embedded; no free */
		}
		STAILQ_REMOVE(&qp->req.wqe_head, wqe_next, rdma_send_wqe, next);
		/* wqe embedded; no free */
	}
	/* Free up ack_pending_list */
	STAILQ_FOREACH_SAFE(ack_next, &qp->resp.ack_pending_list, next, tmp_ack)
	{
		STAILQ_REMOVE(&qp->resp.ack_pending_list, ack_next, rdma_ack, next);
		/* ack embedded; no free */
	}
}

int rdma_process_read_reply(struct rdma_qp *qp, struct rte_mbuf *mbuf, struct rte_mbuf **mbufs,
			    uint16_t *n_mbufs);
int dao_send_cqe(struct rdma_qp *qp, bool host_recv, struct rdma_send_wqe *wqe);
#endif
