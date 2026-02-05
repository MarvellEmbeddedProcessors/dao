/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */
#include "dao_rdma_fp.h"
#include "rdma_common.h"
#include "rdma_comp.h"
#include "rdma_hdr.h"
#include "rdma_opcode.h"
#include "rdma_qp.h"
#include "rdma_req.h"
#include "rdma_resp.h"
#include "rdma_retransmit.h"
#include "rdma_utils.h"
#include <arpa/inet.h>
#include <dao_log.h>
#include <stdio.h>
#include <sys/socket.h>

typedef enum comp_state {
	RDMA_COMPST_COMP_WQE,
	RDMA_COMPST_GET_WQE,
	RDMA_COMPST_COMP_ACK,
	RDMA_COMPST_CHECK_PSN,
	RDMA_COMPST_CHECK_ACK,
	RDMA_COMPST_READ,
	RDMA_COMPST_ATOMIC,
	RDMA_COMPST_WRITE_SEND,
	RDMA_COMPST_UPDATE_COMP,
	RDMA_COMPST_ERROR_RETRY,
	RDMA_COMPST_RNR_RETRY,
	RDMA_COMPST_ERROR,
	RDMA_COMPST_EXIT,
	RDMA_COMPST_DONE,
} comp_state_t;

static uint64_t rnrnak_usec[32] = {
	[RDMA_RNR_TIMER_655_36] = 655360, [RDMA_RNR_TIMER_000_01] = 10,
	[RDMA_RNR_TIMER_000_02] = 20,     [RDMA_RNR_TIMER_000_03] = 30,
	[RDMA_RNR_TIMER_000_04] = 40,     [RDMA_RNR_TIMER_000_06] = 60,
	[RDMA_RNR_TIMER_000_08] = 80,     [RDMA_RNR_TIMER_000_12] = 120,
	[RDMA_RNR_TIMER_000_16] = 160,    [RDMA_RNR_TIMER_000_24] = 240,
	[RDMA_RNR_TIMER_000_32] = 320,    [RDMA_RNR_TIMER_000_48] = 480,
	[RDMA_RNR_TIMER_000_64] = 640,    [RDMA_RNR_TIMER_000_96] = 960,
	[RDMA_RNR_TIMER_001_28] = 1280,   [RDMA_RNR_TIMER_001_92] = 1920,
	[RDMA_RNR_TIMER_002_56] = 2560,   [RDMA_RNR_TIMER_003_84] = 3840,
	[RDMA_RNR_TIMER_005_12] = 5120,   [RDMA_RNR_TIMER_007_68] = 7680,
	[RDMA_RNR_TIMER_010_24] = 10240,  [RDMA_RNR_TIMER_015_36] = 15360,
	[RDMA_RNR_TIMER_020_48] = 20480,  [RDMA_RNR_TIMER_030_72] = 30720,
	[RDMA_RNR_TIMER_040_96] = 40960,  [RDMA_RNR_TIMER_061_44] = 61410,
	[RDMA_RNR_TIMER_081_92] = 81920,  [RDMA_RNR_TIMER_122_88] = 122880,
	[RDMA_RNR_TIMER_163_84] = 163840, [RDMA_RNR_TIMER_245_76] = 245760,
	[RDMA_RNR_TIMER_327_68] = 327680, [RDMA_RNR_TIMER_491_52] = 491520,
};

typedef comp_state_t (*state_func_t)(struct rdma_qp *qp, struct pkt_info *pkt,
				     struct rdma_send_wqe *wqe);

static inline void
reset_retry_counters(struct rdma_qp *qp)
{
	qp->comp.retry_cnt = qp->attr.max_retry_cnt;
	qp->comp.rnr_retry = qp->attr.max_rnr_retry;
	// qp->comp.started_retry = 0; compare with in_retransmission
}

static inline comp_state_t
rdma_check_psn(struct rdma_qp *qp, struct pkt_info *pkt, struct rdma_send_wqe *wqe)
{
	int diff;

	/* check to see if response is past the oldest WQE. if it is, complete
	 * send/write or error read
	 */
	diff = psn_compare(pkt->rinfo.psn, wqe->last_psn);
	if (diff > 0) {
		if (wqe->state == wqe_state_pending) {
			if (wqe->mask & WR_READ_MASK)
				return RDMA_COMPST_ERROR_RETRY;

			reset_retry_counters(qp);
			return RDMA_COMPST_COMP_WQE;
		} else {
			return RDMA_COMPST_DONE;
		}
	}

	/* compare response packet to expected response */
	diff = psn_compare(pkt->rinfo.psn, qp->comp.psn);
	if (diff < 0) {
		if (pkt->rinfo.psn == wqe->last_psn)
			return RDMA_COMPST_COMP_ACK;
		else if (pkt->rinfo.opcode == RDMA_OPCODE_RC_ACKNOWLEDGE &&
			 (qp->comp.opcode == RDMA_OPCODE_RC_RDMA_READ_RESPONSE_FIRST ||
			  qp->comp.opcode == RDMA_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE))
			return RDMA_COMPST_CHECK_ACK;
		else
			return RDMA_COMPST_DONE;
	} else if ((diff > 0) && (wqe->mask & WR_READ_MASK)) {
		return RDMA_COMPST_DONE;
	} else {
		return RDMA_COMPST_CHECK_ACK;
	}
}

static inline comp_state_t
rdma_check_ack(struct rdma_qp *qp, struct pkt_info *pkt, struct rdma_send_wqe *wqe)
{
	unsigned int mask = pkt->rinfo.mask;
	uint8_t syn;

#ifdef RDMA_DEBUG
	dao_dbg("ACK psn %d expected psn %d opcode %d mask %x\n", pkt->rinfo.psn, qp->comp.psn,
		pkt->rinfo.opcode, mask);
#endif
	/* Check the sequence only */
	switch (qp->comp.opcode) {
	case -1:
		/* Will catch all *_ONLY cases. */
		if (!(mask & RDMA_START_MASK))
			return RDMA_COMPST_ERROR;

		break;

	case RDMA_OPCODE_RC_RDMA_READ_RESPONSE_FIRST:
	case RDMA_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE:
		/* Check NAK code to handle a remote error */
		if (pkt->rinfo.opcode == RDMA_OPCODE_RC_ACKNOWLEDGE)
			break;

		if (pkt->rinfo.opcode != RDMA_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE &&
		    pkt->rinfo.opcode != RDMA_OPCODE_RC_RDMA_READ_RESPONSE_LAST) {
			/* read retries of partial data may restart from
			 * read response first or response only.
			 */
			if ((pkt->rinfo.psn == wqe->first_psn &&
			     pkt->rinfo.opcode == RDMA_OPCODE_RC_RDMA_READ_RESPONSE_FIRST) ||
			    (wqe->first_psn == wqe->last_psn &&
			     pkt->rinfo.opcode == RDMA_OPCODE_RC_RDMA_READ_RESPONSE_ONLY))
				break;

			return RDMA_COMPST_ERROR;
		}
		break;
	default:
		dao_err("unexpected opcode %d\n", qp->comp.opcode);
	}

	/* Check operation validity. */
	switch (pkt->rinfo.opcode) {
	case RDMA_OPCODE_RC_RDMA_READ_RESPONSE_FIRST:
	case RDMA_OPCODE_RC_RDMA_READ_RESPONSE_LAST:
	case RDMA_OPCODE_RC_RDMA_READ_RESPONSE_ONLY:
		syn = aeth_syn(&pkt->rinfo);

		if ((syn & AETH_TYPE_MASK) != AETH_ACK)
			return RDMA_COMPST_ERROR;

		__attribute__((fallthrough));
		/* (RDMA_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE doesn't have an AETH)
		 */
	case RDMA_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE:
		if (wqe->wr->opcode != RDMA_WR_RDMA_READ &&
		    wqe->wr->opcode != RDMA_WR_RDMA_READ_WITH_INV &&
		    wqe->wr->opcode != RDMA_WR_FLUSH) {
			wqe->status = RDMA_WC_FATAL_ERR;
			return RDMA_COMPST_ERROR;
		}
		reset_retry_counters(qp);
		return RDMA_COMPST_READ;

	case RDMA_OPCODE_RC_ACKNOWLEDGE:
		syn = aeth_syn(&pkt->rinfo);
		switch (syn & AETH_TYPE_MASK) {
		case AETH_ACK:
			reset_retry_counters(qp);
			return RDMA_COMPST_WRITE_SEND;

		case AETH_RNR_NAK:
			dao_info("RNR NAK\n");
			return RDMA_COMPST_RNR_RETRY;

		case AETH_NAK:
			switch (syn) {
			case AETH_NAK_PSN_SEQ_ERROR:
				if (psn_compare(pkt->rinfo.psn, qp->comp.psn) > 0) {
					dao_err("[COMP] QP_ID %d remote SEQ Number ERR remote psn %d"
						" qp->comp.psn %d\n",
						qp->qid, pkt->rinfo.psn, qp->comp.psn);
					qp->comp.psn = pkt->rinfo.psn;
					if (qp->req.stop_psn)
						qp->req.stop_psn = 0;
				}
				return RDMA_COMPST_ERROR_RETRY;

			case AETH_NAK_INVALID_REQ:
				wqe->status = RDMA_WC_REM_INV_REQ_ERR;
				return RDMA_COMPST_ERROR;

			case AETH_NAK_REM_ACC_ERR:
				wqe->status = RDMA_WC_REM_ACCESS_ERR;
				return RDMA_COMPST_ERROR;

			case AETH_NAK_REM_OP_ERR:
				wqe->status = RDMA_WC_REM_OP_ERR;
				return RDMA_COMPST_ERROR;

			default:
				dao_err("unexpected nak %x\n", syn);
				wqe->status = RDMA_WC_REM_OP_ERR;
				return RDMA_COMPST_ERROR;
			}

		default:
			return RDMA_COMPST_ERROR;
		}
		break;

	default:
		dao_err("unexpected opcode\n");
	}

	return RDMA_COMPST_ERROR;
}

static inline void
populate_cqe(struct dao_pts_rdma_cqe *cqe, struct rdma_qp *qp, rdma_send_wr_t *wr)
{
	memset(cqe, 0, sizeof(*cqe));
	cqe->opcode = wr->opcode;
	cqe->status = RDMA_WC_SUCCESS;
	cqe->wr_id = wr->wr_id;
	cqe->qp_id = qp->qid;
}

static inline void
rdma_populate_wr(struct pkt_info *pkt, struct rdma_send_wqe *wqe)
{
	struct rdma_qp *qp = pkt->rinfo.qp;
	struct rte_mbuf *mbuf = wqe->read_mbuf;
	struct dao_pts_rdma_cqe *cqe = rdma_rx_priv_cqe(mbuf);
	uint8_t *sges = (uint8_t *)rdma_rx_priv_sge_base(mbuf);
	bool need_cqe;
	uint64_t enq_flag;

	memcpy(sges, &wqe->wr->sges0[0], sizeof(struct octep_rdma_sge) * wqe->wr->num_sges);
	pkt->mbuf = mbuf;
	mbuf->l2_len = wqe->wr->num_sges;
	pkt->mbuf_flags = RDMA_RESPONDER_MBUF_UPDATED;

	need_cqe = ((qp->sq_sig_type == RDMA_SIGNAL_ALL_WR) ||
		    (wqe->wr->send_flags & RDMA_SEND_SIGNALED));
	if (need_cqe) {
		populate_cqe(cqe, qp, wqe->wr);
		enq_flag = DAO_PTS_RDMA_ENQ_M2D_SQE_WITH_CQE;
	} else {
		enq_flag = DAO_PTS_RDMA_ENQ_M2D_SQE;
	}
	mbuf->ol_flags |= enq_flag << OFFLD_UPPER_BITS;

	wqe->read_mbuf = NULL;
	wqe->read_tail = NULL;
}

static inline comp_state_t
rdma_do_read(struct rdma_qp *qp, struct pkt_info *pkt, struct rdma_send_wqe *wqe)
{
	struct rte_mbuf *mbuf = pkt->mbuf;

	RTE_SET_USED(qp);

	if (!mbuf) {
		dao_err("Invalid mbuf\n");
		return RDMA_COMPST_ERROR;
	}

	wqe->dma_length -= rte_pktmbuf_pkt_len(mbuf);
	pkt->mbuf_flags = RDMA_RESPONDER_MBUF_CONSUMED;
	if (!wqe->read_mbuf) {
		/* Initialize chain */
		wqe->read_mbuf = mbuf;
		wqe->read_tail = rte_pktmbuf_lastseg(mbuf);
	} else {
		/* Append in O(1) using maintained tail pointer */
		if (likely(wqe->read_tail)) {
			wqe->read_tail->next = mbuf;
			wqe->read_tail = rte_pktmbuf_lastseg(mbuf);
		} else {
			/* Fallback: tail missing, rebuild quickly */
			wqe->read_tail = rte_pktmbuf_lastseg(wqe->read_mbuf);
			wqe->read_tail->next = mbuf;
			wqe->read_tail = rte_pktmbuf_lastseg(mbuf);
		}
		/* Update aggregate lengths on head */
		wqe->read_mbuf->nb_segs = (uint16_t)(wqe->read_mbuf->nb_segs + mbuf->nb_segs);
		wqe->read_mbuf->pkt_len = (uint32_t)(wqe->read_mbuf->pkt_len + mbuf->pkt_len);
	}
	pkt->mbuf = NULL;
	if (wqe->dma_length == 0 && (pkt->rinfo.mask & RDMA_END_MASK)) {
		rdma_populate_wr(pkt, wqe);
		return RDMA_COMPST_COMP_ACK;
	}

	return RDMA_COMPST_UPDATE_COMP;
}

static inline comp_state_t
rdma_write_send(struct rdma_qp *qp, struct pkt_info *pkt, struct rdma_send_wqe *wqe)
{
	comp_state_t state;

	RTE_SET_USED(pkt);
	RTE_SET_USED(qp);

	if (wqe->state == wqe_state_pending && wqe->last_psn == pkt->rinfo.psn)
		state = RDMA_COMPST_COMP_ACK;
	else
		state = RDMA_COMPST_UPDATE_COMP;

	return state;
}

static inline void
rdma_delete_wqe(struct rdma_qp *qp, struct rdma_send_wqe *wqe)
{
	struct rdma_send_wqe *wqe_next, *tmp;
	struct rdma_mbufs *rmbuf = NULL, *temp_rmbuf = NULL;

	STAILQ_FOREACH_SAFE(wqe_next, &qp->req.wqe_head, next, tmp)
	{
		STAILQ_REMOVE(&qp->req.wqe_head, wqe_next, rdma_send_wqe, next);
		STAILQ_FOREACH_SAFE(rmbuf, &wqe_next->mbuf_list, next, temp_rmbuf)
		{
			STAILQ_REMOVE(&wqe_next->mbuf_list, rmbuf, rdma_mbufs, next);
			rdma_free_mbuf_list(rmbuf);
		}

		if (qp->req.cur_wqe == wqe_next)
			qp->req.cur_wqe = NULL;

		if (wqe_next == wqe)
			break;
	}
}

static void
reset_retry_timer(struct rdma_qp *qp)
{
	if (qp->type == RDMA_QPT_RC && qp->req.timeout_cycles) {
		if (qp->state >= QP_STATE_RTS && psn_compare(qp->req.psn, qp->comp.psn) > 0)
			qp->timer_data->timer_type |= RDMA_RETRNS_TIMER;
		rte_timer_stop(&qp->timer_data->retrans_timer);
		if (!STAILQ_EMPTY(&qp->req.wqe_head)) {
			rte_timer_reset(&qp->timer_data->retrans_timer, qp->req.timeout_cycles,
					SINGLE, rte_lcore_id(), rdma_timeout_handler_cb,
					qp->timer_data);
		}
	}
}

static void
do_complete(struct rdma_qp *qp, struct rdma_send_wqe *wqe)
{
	if (wqe->status != RDMA_WC_SUCCESS || wqe->wr->opcode != RDMA_WR_RDMA_READ)
		dao_send_cqe(qp, false, wqe);

	wqe->state = wqe_state_done;

	if (qp->req.wait_fence)
		qp->req.wait_fence = 0;

	if (qp->req.in_retransmission && qp->req.retransmit.curr_wqe == wqe) {
		qp->req.in_retransmission = 0;
		qp->req.retransmit.curr_wqe = NULL;
	}
#ifdef RDMA_DEBUG
	dao_dbg("[COMP] WQE completed qp id %d psn %u wqe->status %u\n", qp->qid, qp->comp.psn,
		wqe->status);
#endif
	rdma_delete_wqe(qp, wqe);
	reset_retry_timer(qp);
}

static inline void
rdma_check_sq_drain_done(struct rdma_qp *qp)
{
	if (unlikely(qp->state == QP_STATE_SQ_DRAIN)) {
		if (qp->attr.sq_draining && qp->comp.psn == qp->req.psn) {
			qp->attr.sq_draining = 0;
			// TODO implement event notify to host
		}
	}
}

static inline comp_state_t
rdma_complete_ack(struct rdma_qp *qp, struct pkt_info *pkt, struct rdma_send_wqe *wqe)
{
	if (wqe->has_read_req) {
		wqe->has_read_req = 0;
		qp->req.read_rq_bal++;
		qp->req.need_rd_credit = 0;
	}

	rdma_check_sq_drain_done(qp);

	do_complete(qp, wqe);

	if (psn_compare(pkt->rinfo.psn, qp->comp.psn) >= 0)
		return RDMA_COMPST_UPDATE_COMP;
	else
		return RDMA_COMPST_DONE;
}

static inline comp_state_t
rdma_update_comp(struct rdma_qp *qp, struct pkt_info *pkt, __rte_unused struct rdma_send_wqe *wqe)
{
	if (pkt->rinfo.mask & RDMA_END_MASK)
		qp->comp.opcode = -1;
	else
		qp->comp.opcode = pkt->rinfo.opcode;

	if (psn_compare(pkt->rinfo.psn, qp->comp.psn) >= 0) {
		qp->comp.psn = (pkt->rinfo.psn + 1) & BTH_PSN_MASK;
		qp->req.unacked_window =
			RDMA_MAX_UNACKED_PSNS - (int32_t)(qp->req.psn - qp->comp.psn);

		/*
		 * Reset retransmission timer on forward progress.
		 * This is critical for large READ operations where many
		 * response packets arrive over time. Without this, the timer
		 * may expire before all responses arrive.
		 */
		if (qp->type == RDMA_QPT_RC && qp->req.timeout_cycles &&
		    !STAILQ_EMPTY(&qp->req.wqe_head)) {
			rte_timer_stop(&qp->timer_data->retrans_timer);
			rte_timer_reset(&qp->timer_data->retrans_timer, qp->req.timeout_cycles,
					SINGLE, rte_lcore_id(), rdma_timeout_handler_cb,
					qp->timer_data);
		}
	}

	if (qp->req.stop_psn)
		qp->req.stop_psn = 0;

	return RDMA_COMPST_DONE;
}

static inline comp_state_t
rdma_complete_wqe(struct rdma_qp *qp, struct pkt_info *pkt, struct rdma_send_wqe *wqe)
{
	RTE_SET_USED(pkt);

	/* Only complete WQEs that are pending - skip if already done */
	if (wqe->state != wqe_state_pending)
		return RDMA_COMPST_GET_WQE;

	if (psn_compare(wqe->last_psn, qp->comp.psn) >= 0) {
		qp->comp.psn = (wqe->last_psn + 1) & BTH_PSN_MASK;
		qp->req.unacked_window =
			RDMA_MAX_UNACKED_PSNS - (int32_t)(qp->req.psn - qp->comp.psn);
		qp->comp.opcode = -1;
	}

	if (qp->req.stop_psn)
		qp->req.stop_psn = 0;

	do_complete(qp, wqe);

	return RDMA_COMPST_GET_WQE;
}

static inline comp_state_t
rdma_error_retry(struct rdma_qp *qp, struct pkt_info *pkt, struct rdma_send_wqe *wqe)
{
	RTE_SET_USED(pkt);
	RTE_SET_USED(wqe);
	/**
	 * 2 cases
	 * 1. if current is read but we received ACK for later packet
	 * 2. if we received NAK with PSN SEQ ERROR
	 * Note check any other cases
	 */

	if (qp->req.in_retransmission) {
		return RDMA_COMPST_DONE;
	} else if (rdma_check_retransmission_limit(qp) < 0) {
		dao_err("Max retry reached qp id %d qp state %d\n", qp->qid, qp->state);
		return RDMA_COMPST_DONE;
	}
	rdma_setup_retransmission(qp);

	return RDMA_COMPST_DONE;
}

static inline uint64_t
calculate_rnrnak_timeout(struct pkt_info *pkt)
{
	uint8_t syn = aeth_syn(&pkt->rinfo);
	uint8_t rnrnak = syn & ~AETH_TYPE_MASK;
	uint64_t usec = rnrnak_usec[rnrnak];
	uint64_t cycles = usec * rte_get_timer_hz() / 1000000;

	dao_info("RNR timeout %lu\n", cycles);

	return cycles;
}

static inline comp_state_t
rdma_rnr_retry(struct rdma_qp *qp, struct pkt_info *pkt, struct rdma_send_wqe *wqe)
{
	RTE_SET_USED(pkt);
	comp_state_t state;
	uint64_t cycles;

	if (qp->comp.rnr_retry > 0) {
		if (qp->comp.rnr_retry != 7)
			qp->comp.rnr_retry--;

		qp->req.wait_rnr_exp = 1;
		qp->timer_data->timer_type |= RDMA_RNR_TIMER;
		dao_info("set rnr nak timer\n");

		cycles = calculate_rnrnak_timeout(pkt);

		rte_timer_reset(&qp->timer_data->rnr_timer, cycles, SINGLE, rte_lcore_id(),
				rdma_timeout_handler_cb, qp->timer_data);
		state = RDMA_COMPST_DONE;
	} else {
		wqe->status = RDMA_WC_RNR_RETRY_EXC_ERR;
		state = RDMA_COMPST_ERROR;
	}

	return state;
}

static inline comp_state_t
rdma_error(struct rdma_qp *qp, struct pkt_info *pkt, struct rdma_send_wqe *wqe)
{
	RTE_SET_USED(pkt);

	do_complete(qp, wqe);
	return RDMA_COMPST_DONE;
}

state_func_t comp_state_funcs[] = {
	[RDMA_COMPST_GET_WQE] = NULL,
	[RDMA_COMPST_CHECK_PSN] = rdma_check_psn,
	[RDMA_COMPST_CHECK_ACK] = rdma_check_ack,
	[RDMA_COMPST_READ] = rdma_do_read,
	[RDMA_COMPST_ATOMIC] = NULL, /* Dont support */
	[RDMA_COMPST_WRITE_SEND] = rdma_write_send,
	[RDMA_COMPST_COMP_ACK] = rdma_complete_ack,
	[RDMA_COMPST_COMP_WQE] = rdma_complete_wqe,
	[RDMA_COMPST_UPDATE_COMP] = rdma_update_comp,
	[RDMA_COMPST_ERROR_RETRY] = rdma_error_retry,
	[RDMA_COMPST_RNR_RETRY] = rdma_rnr_retry,
	[RDMA_COMPST_ERROR] = rdma_error,
	[RDMA_COMPST_EXIT] = NULL,
	[RDMA_COMPST_DONE] = NULL,
};

static comp_state_t
rdma_get_wqe(struct rdma_qp *qp, struct pkt_info *pkt, struct rdma_send_wqe **wq)
{
	RTE_SET_USED(pkt);
	rdma_send_wqe_t *wqe = NULL;

	wqe = STAILQ_FIRST(&qp->req.wqe_head);

	/* No WQE or requester has not started it yet */
	if (!wqe || wqe->state == wqe_state_posted)
		return RDMA_COMPST_DONE;

	if (wqe->state == wqe_state_done) {
		dao_err("WQE already completed\n");
		return RDMA_COMPST_COMP_WQE;
	}

	/* WQE caused an error */
	if (wqe->state == wqe_state_error) {
		dao_err("WQE in error state\n");
		return RDMA_COMPST_ERROR;
	}

	*wq = wqe;

	return RDMA_COMPST_CHECK_PSN;
}

int
rdma_process_ack(struct pkt_info *pinfo)
{
	struct rdma_qp *qp = (struct rdma_qp *)pinfo->rinfo.qp;
	struct rdma_send_wqe *wqe = NULL;
	comp_state_t state;

	if (!qp->valid || qp->state == QP_STATE_ERROR || qp->state == QP_STATE_RESET) {
		dao_err("[%s::%d] qp error\n", __func__, __LINE__);
		// rdma_flush_sqe(qp); TODO
		return -1;
	}

	state = RDMA_COMPST_GET_WQE;

	while (state != RDMA_COMPST_DONE && state != RDMA_COMPST_EXIT) {
		if (state == RDMA_COMPST_GET_WQE)
			state = rdma_get_wqe(qp, pinfo, &wqe);

		if (comp_state_funcs[state])
			state = comp_state_funcs[state](qp, pinfo, wqe);
	}

	return 0;
}
