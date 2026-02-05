/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include "rdma_retransmit.h"
#include "dao_rdma_fp.h"
#include "rdma_common.h"
#include "rdma_opcode.h"
#include "rdma_qp.h"
#include <assert.h>
#include <dao_log.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>

void
rdma_setup_retransmission(rdma_qp_t *qp)
{
	uint32_t first_psn;
	struct rdma_mbufs *rmbuf;
	rdma_send_wqe_t *wqe;

	if (qp->req.in_retransmission) {
		return;
	}

	wqe = STAILQ_FIRST(&qp->req.wqe_head);
	qp->req.retransmit.curr_wqe = wqe;
	if (!wqe) {
		rte_timer_stop(&qp->timer_data->retrans_timer);
		qp->req.in_retransmission = 0;
		return;
	}

	rmbuf = STAILQ_FIRST(&wqe->mbuf_list);
	first_psn = wqe->first_psn;

	if (wqe->mask & WR_READ_MASK) {
		/* READ: always retransmit from the first mbuf */
		qp->req.retransmit.curr_mbuf = rmbuf;
		qp->req.in_retransmission = 1;
		return;
	}

	while (rmbuf && psn_compare(first_psn, qp->comp.psn) < 0) {
		rmbuf = STAILQ_NEXT(rmbuf, next);
		first_psn++;
	}
	qp->req.retransmit.curr_mbuf = rmbuf;
	qp->req.in_retransmission = 1;
}

static inline void
rdma_reset_and_send_cqe(rdma_qp_t *qp, int status)
{
	struct rdma_send_wqe *wqe_next, *tmp;

	qp->req.cur_wqe = NULL;
	qp->state = QP_STATE_ERROR;
	qp->comp.retry_cnt = qp->attr.max_retry_cnt;
	qp->comp.rnr_retry = qp->attr.max_rnr_retry;
	rte_timer_stop(&qp->timer_data->retrans_timer);

	STAILQ_FOREACH_SAFE(wqe_next, &qp->req.wqe_head, next, tmp)
	{
		wqe_next->status = status;
		dao_send_cqe(qp, false, wqe_next);
	}

	rdma_delete_all_wqe(qp);
}

int
rdma_check_retransmission_limit(rdma_qp_t *qp)
{
	if (qp->comp.retry_cnt == 0) {
		rdma_reset_and_send_cqe(qp, RDMA_WC_RETRY_EXC_ERR);
		return -1;
	}
	if (qp->comp.retry_cnt != 7)
		qp->comp.retry_cnt--;
	return 0;
}

/**
 * @function - rdma_timeout_handler_cb
 * @tim: Timer structure pointer
 * @arg: Argument to the timer
 * @brief: On timeout, all WQE's in the WQE list will be marked as fresh start and
 * retransmist flag will be set.
 */
void
rdma_timeout_handler_cb(struct rte_timer *tim, void *arg)
{
	RTE_SET_USED(tim);
	struct rdma_timer_data *data = (struct rdma_timer_data *)arg;
	rdma_qp_t *qp = NULL;

	qp = rdma_qp_query_fast(data->qp_id, data->dev_id);
	if (!qp || !qp->valid) {
		rte_free(data);
		return;
	}

	if (data->timer_type & RDMA_RNR_TIMER) {
		qp->req.wait_rnr_exp = 0;

		if (qp->comp.rnr_retry == 0) {
			dao_info("No RNR retries left, marking WQE as failed\n");
			rdma_reset_and_send_cqe(qp, RDMA_WC_RNR_RETRY_EXC_ERR);
			return;
		}

		if (qp->comp.rnr_retry != 7)
			qp->comp.rnr_retry--;
	} else {
		rdma_check_retransmission_limit(qp);
	}

	rdma_setup_retransmission(qp);
}

/**
 * @function - dao_rdma_get_retransmition_pkts
 * @qpi_id: RDMA Queue Pair ID
 * @dev_id: RDMA Device ID
 * @num_pkts: Number of packets
 * @mbufs: Array of mbufs
 * @brief: This function forms the retranmission packets from WQE list.
 * It returns the number of packets formed.
 */

uint16_t
dao_rdma_get_retransmition_pkts(int qp_id, int dev_id, int num_pkts, struct rte_mbuf **mbufs)
{
	int produced = 0;
	rdma_qp_t *qp;
	rdma_send_wqe_t *wqe;
	struct rdma_mbufs *rmbuf;

	qp = rdma_qp_query_fast(qp_id, dev_id);
	if (!qp || !qp->req.in_retransmission)
		return 0;

	wqe = qp->req.retransmit.curr_wqe;
	rmbuf = qp->req.retransmit.curr_mbuf;
	if (!wqe) {
		qp->req.in_retransmission = 0;
		return 0;
	}

	/* Pack up to num_pkts across pending WQEs, persisting progress. */
	while (produced < num_pkts && wqe) {
		/* Do not retransmit past the current front WQE; only within it. */
		if (wqe == qp->req.cur_wqe && rmbuf == qp->req.cur_mbuf)
			break;

		/* Skip non-pending WQEs and advance. */
		if (wqe->state != wqe_state_pending) {
			if (wqe == qp->req.cur_wqe)
				break;
			wqe = STAILQ_NEXT(wqe, next);
			rmbuf = wqe ? STAILQ_FIRST(&wqe->mbuf_list) : NULL;
			continue;
		}

		/* If rmbuf is NULL for this WQE, move to next WQE (unless at boundary). */
		if (rmbuf == NULL) {
			if (wqe == qp->req.cur_wqe)
				break; /* boundary */
			wqe = STAILQ_NEXT(wqe, next);
			rmbuf = wqe ? STAILQ_FIRST(&wqe->mbuf_list) : NULL;
			continue;
		}

		/* Copy mbufs from this WQE. */
		while (produced < num_pkts && rmbuf) {
			mbufs[produced] = rmbuf->mbuf;
			rte_mbuf_refcnt_update(mbufs[produced], 1);
			produced++;
			rmbuf = STAILQ_NEXT(rmbuf, next);
		}

		/* If exhausted this WQE, advance to next (respect boundary). */
		if (rmbuf == NULL) {
			if (wqe == qp->req.cur_wqe)
				break; /* do not go beyond current front */
			wqe = STAILQ_NEXT(wqe, next);
			rmbuf = wqe ? STAILQ_FIRST(&wqe->mbuf_list) : NULL;
		}
	}

	/* Persist progress for next call. */
	qp->req.retransmit.curr_wqe = wqe;
	qp->req.retransmit.curr_mbuf = rmbuf;

	if (produced == 0) {
		/* No packets produced: mark retransmission done and (re)arm timer. */
		qp->req.in_retransmission = 0;
		qp->req.retransmit.curr_wqe = STAILQ_FIRST(&qp->req.wqe_head);
		qp->req.retransmit.curr_mbuf = NULL;
		if (rte_timer_pending(&qp->timer_data->retrans_timer))
			rte_timer_stop(&qp->timer_data->retrans_timer);
		rte_timer_reset(&qp->timer_data->retrans_timer, qp->req.timeout_cycles, SINGLE,
				rte_lcore_id(), rdma_timeout_handler_cb, qp->timer_data);
		dao_dbg("Retransmission completed for QP %d qp->comp.retry_cnt %d\n", qp_id,
			qp->comp.retry_cnt);
	}
#ifdef RDMA_DEBUG
	/* clang-format off */
	dao_dbg("[%s] Retrans QP %d produced %u (limit %d) curr_wqe %p cur_wqe %p state %d\n",
		__func__, qp_id, produced, num_pkts, wqe, qp->req.cur_wqe,
		wqe ? wqe->state : (enum rdma_wqe_state)-1);
	/* clang-format on */
#endif
	return produced;
}
