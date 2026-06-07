/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_ethdev.h>

#include <dao_log.h>

#include "dao_rdma_fp.h"
#include "rdma_common.h"
#include "rdma_counter.h"
#include "rdma_net.h"
#include "rdma_opcode.h"
#include "rdma_qp.h"
#include "rdma_resp.h"
#include "rdma_utils.h"

#define RDMA_ACK_MAX 32

typedef enum resp_states {
	RDMA_RESPST_NONE,
	RDMA_RESPST_GET_REQ,
	RDMA_RESPST_CHK_PSN,
	RDMA_RESPST_CHK_OP_SEQ,
	RDMA_RESPST_CHK_OP_VALID,
	RDMA_RESPST_CHK_RESOURCE,
	RDMA_RESPST_CHK_LENGTH,
	RDMA_RESPST_CHK_RKEY,
	RDMA_RESPST_EXECUTE,
	RDMA_RESPST_ATOMIC_REPLY,
	RDMA_RESPST_COMPLETE,
	RDMA_RESPST_ACKNOWLEDGE,
	RDMA_RESPST_CLEANUP,
	RDMA_RESPST_DUPLICATE_REQUEST,
	RDMA_RESPST_ERR_MALFORMED_WQE,
	RDMA_RESPST_ERR_UNSUPPORTED_OPCODE,
	RDMA_RESPST_ERR_MISALIGNED_ATOMIC,
	RDMA_RESPST_ERR_PSN_OUT_OF_SEQ,
	RDMA_RESPST_ERR_MISSING_OPCODE_FIRST,
	RDMA_RESPST_ERR_MISSING_OPCODE_LAST_C,
	RDMA_RESPST_ERR_MISSING_OPCODE_LAST_D1E,
	RDMA_RESPST_ERR_TOO_MANY_RDMA_ATM_REQ,
	RDMA_RESPST_ERR_RNR,
	RDMA_RESPST_ERR_RKEY_VIOLATION,
	RDMA_RESPST_ERR_INVALIDATE_RKEY,
	RDMA_RESPST_ERR_LENGTH,
	RDMA_RESPST_ERR_CQ_OVERFLOW,
	RDMA_RESPST_ERROR,
	RDMA_RESPST_RESET,
	RDMA_RESPST_DONE,
	RDMA_RESPST_EXIT,
} resp_states_t;

/* This forms struct rdma_ack and adds to the ack_pending_list */
static inline int
rdma_update_ack_pending_list(struct rdma_qp *qp, struct rte_mbuf *mbuf, uint32_t psn,
			     uint8_t syndrome, bool is_read)
{
	struct rdma_ack *ack;

	/* Embed ACK node into the mbuf private area to avoid allocation */
	ack = rdma_rx_priv_ack(mbuf);
	ack->psn = psn;
	ack->opcode = qp->resp.opcode;
	ack->msn = qp->resp.msn;
	ack->aeth_syndrome = syndrome;
	ack->is_read = is_read;
	ack->last_psn = qp->resp.ack_psn;
	ack->mbuf = mbuf;
	STAILQ_INSERT_TAIL(&qp->resp.ack_pending_list, ack, next);

	return 0;
}

static inline enum resp_states
queue_check(struct rdma_qp *qp)
{
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id = qp->qid;

	if (qp->state == QP_STATE_ERROR) {
		/* Go drain recv wr queue */
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_QUEUE_CHK_QP_STATE_ERR);
		return RDMA_RESPST_CHK_RESOURCE;
	}

	return RDMA_RESPST_CHK_PSN;
}

static resp_states_t
check_psn(struct rdma_qp *qp, struct pkt_info *pinfo)
{
	struct rdma_pkt_info *pkt = &pinfo->rinfo;
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id = qp->qid;

	/* PSN is 24 bit number. */
	int diff = psn_compare(pkt->psn, qp->resp.psn);

	switch (qp->type) {
	case RDMA_QPT_RC:
		if (diff > 0) {
			if (qp->resp.sent_psn_nak)
				return RDMA_RESPST_CLEANUP;

			qp->resp.sent_psn_nak = 1;
			pkt->psn = qp->resp.psn;
			pinfo->mbuf_flags = RDMA_RESPONDER_MBUF_DROP;
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
					    RDMA_RX_QP_CHK_PSN_PKT_OUT_OF_SEQ_ERR);
			return RDMA_RESPST_ERR_PSN_OUT_OF_SEQ;
		} else if (diff < 0) {
			return RDMA_RESPST_DUPLICATE_REQUEST;
		}

		if (qp->resp.sent_psn_nak)
			qp->resp.sent_psn_nak = 0;
		break;

	default:
		/* QPT other than RC and UC, PSN check is not required. */
		break;
	}

	return RDMA_RESPST_CHK_OP_SEQ;
}

static resp_states_t
check_op_seq(struct rdma_qp *qp, struct rdma_pkt_info *pkt)
{
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id = qp->qid;

	switch (qp->type) {
	case RDMA_QPT_RC:
		switch (qp->resp.opcode) {
		case RDMA_OPCODE_RC_SEND_FIRST:
		case RDMA_OPCODE_RC_SEND_MIDDLE:
			switch (pkt->opcode) {
			case RDMA_OPCODE_RC_SEND_MIDDLE:
			case RDMA_OPCODE_RC_SEND_LAST:
			case RDMA_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE:
			case RDMA_OPCODE_RC_SEND_LAST_WITH_INVALIDATE:
				return RDMA_RESPST_CHK_OP_VALID;
			default:
				RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
						    RDMA_RX_QP_CHK_OP_SEQ_MISS_OP_LAST_C_ERR);
				return RDMA_RESPST_ERR_MISSING_OPCODE_LAST_C;
			}

		case RDMA_OPCODE_RC_RDMA_WRITE_FIRST:
		case RDMA_OPCODE_RC_RDMA_WRITE_MIDDLE:
			switch (pkt->opcode) {
			case RDMA_OPCODE_RC_RDMA_WRITE_MIDDLE:
			case RDMA_OPCODE_RC_RDMA_WRITE_LAST:
			case RDMA_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
				return RDMA_RESPST_CHK_OP_VALID;
			default:
				RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
						    RDMA_RX_QP_CHK_OP_SEQ_MISS_OP_LAST_C_ERR);
				return RDMA_RESPST_ERR_MISSING_OPCODE_LAST_C;
			}

		default:
			switch (pkt->opcode) {
			case RDMA_OPCODE_RC_SEND_MIDDLE:
			case RDMA_OPCODE_RC_SEND_LAST:
			case RDMA_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE:
			case RDMA_OPCODE_RC_SEND_LAST_WITH_INVALIDATE:
			case RDMA_OPCODE_RC_RDMA_WRITE_MIDDLE:
			case RDMA_OPCODE_RC_RDMA_WRITE_LAST:
			case RDMA_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
				RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
						    RDMA_RX_QP_CHK_OP_SEQ_MISS_OP_FIRST_ERR);
				return RDMA_RESPST_ERR_MISSING_OPCODE_FIRST;
			default:
				return RDMA_RESPST_CHK_OP_VALID;
			}
		}

		break;

	case RDMA_QPT_UC:
		/* TODO: Mx */
		break;

	default:
		return RDMA_RESPST_CHK_OP_VALID;
	}

	return RDMA_RESPST_CHK_OP_VALID;
}

static resp_states_t
check_op_valid(struct rdma_qp *qp, struct rdma_pkt_info *pkt)
{
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id = qp->qid;

	switch (qp->type) {
	case RDMA_QPT_RC:
		if (((pkt->mask & RDMA_READ_MASK) &&
		     !(qp->attr.qp_access_flags & RDMA_ACCESS_REMOTE_READ)) ||
		    ((pkt->mask & RDMA_WRITE_MASK) &&
		     !(qp->attr.qp_access_flags & RDMA_ACCESS_REMOTE_WRITE))) {
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
					    RDMA_RX_QP_CHK_OP_VALID_UNSUPP_OP_ERR);
			return RDMA_RESPST_ERR_UNSUPPORTED_OPCODE;
		}

		break;

	case RDMA_QPT_UC:
		/* TODO: M3 */
		break;

	case RDMA_QPT_UD:
	case RDMA_QPT_GSI:
		break;

	default:
		break;
	}

	return RDMA_RESPST_CHK_RESOURCE;
}

static inline bool
check_rq_resource(struct rdma_qp *qp)
{
	RTE_SET_USED(qp);
	/* TODO: check RQ status from PTS */
	// dao_pts_rdma_rq_avail_get(qp);
	return 1;
}

static resp_states_t
check_resource(struct rdma_qp *qp, struct rdma_pkt_info *pkt)
{
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id = qp->qid;

	if (pkt->mask & RDMA_READ_MASK) {
		if (likely(qp->resp.resp_read_rq_bal > 0))
			return RDMA_RESPST_CHK_LENGTH;

		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_CHK_RES_NO_READ_REQ_RES);
		return RDMA_RESPST_ERR_TOO_MANY_RDMA_ATM_REQ;
	}

	if (pkt->mask & RDMA_RWR_MASK) {
		if (likely(check_rq_resource(qp)))
			return RDMA_RESPST_CHK_LENGTH;
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_CHK_RES_RNR_ERR);
		return RDMA_RESPST_ERR_RNR;
	}

	return RDMA_RESPST_CHK_LENGTH;
}

static resp_states_t
check_length(struct rdma_qp *qp, struct rdma_pkt_info *pkt)
{
	RTE_SET_USED(pkt);

	switch (qp->type) {
	case RDMA_QPT_RC:
		return RDMA_RESPST_CHK_RKEY;

	case RDMA_QPT_UC:
		return RDMA_RESPST_CHK_RKEY;

	default:
		return RDMA_RESPST_CHK_RKEY;
	}

	return RDMA_RESPST_CHK_RKEY;
}

static inline int
validate_rkey(struct pkt_info *pinfo)
{
	struct pd_entry *pd;
	struct rdma_pkt_info *pkt = &pinfo->rinfo;
	struct rdma_qp *qp = pkt->qp;
	struct octep_rdma_mr_data *mr;
	uint32_t rkey = rte_be_to_cpu_32(pkt->reth->rkey);
	uint32_t index = rkey >> RDMA_MR_KEY_SHIFT;
	uint32_t length = rte_be_to_cpu_32(pkt->reth->len);
	uint64_t va = rte_be_to_cpu_64(pkt->reth->va);
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id = qp->qid;

	if (index >= RDMA_MAX_MR) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_VAL_RKEY_INV_RKEY_INDEX);
		return -1;
	}

	pd = pd_find_by_id(qp->pd_id, pinfo->port_num);
	if (!pd) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_VAL_RKEY_PD_NOT_FOUND);
		return -1;
	}

	mr = pd->mr_pool[index];
	if (!mr) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_VAL_RKEY_MR_NOT_FOUND);
		return -1;
	}

	if ((pkt->mask & RDMA_READ_MASK && !(mr->access_flags & RDMA_ACCESS_REMOTE_READ)) ||
	    (pkt->mask & RDMA_WRITE_MASK && !(mr->access_flags & RDMA_ACCESS_REMOTE_WRITE))) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_VAL_RKEY_ACC_VIOL);
		return -1;
	}

	if (length > mr->length || (va < mr->va) || (va + length > mr->va + mr->length)) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_VAL_RKEY_LEN_VIOL);
		return -1;
	}

	return 0;
}

static resp_states_t
check_rkey(struct rdma_qp *qp, struct pkt_info *pkt)
{
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id = qp->qid;

	RTE_SET_USED(qp);

	if ((pkt->rinfo.mask & RDMA_READ_OR_WRITE_MASK) && (pkt->rinfo.mask & RDMA_START_MASK)) {
		if (validate_rkey(pkt) < 0) {
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_CHK_RKEY_INV_RKEY);
			return RDMA_RESPST_ERR_RKEY_VIOLATION;
		}
	}

	return RDMA_RESPST_EXECUTE;
}

static inline int
prepare_ack_packet_with_mbuf(struct rdma_qp *qp, int opcode, int payload, uint32_t psn,
			     uint8_t syndrome, struct rte_mbuf *mbuf, uint32_t msn, bool is_read)
{
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id = qp->qid;
	struct rdma_pkt_info ainfo;
	int padlen;
	int paylen;

	padlen = (-payload) & 0x3;
	paylen = rdma_opcode[opcode].length + payload + padlen + RDMA_ICRC_SIZE;

	rdma_mbuf_init(mbuf);

	ainfo.qp = qp;
	ainfo.opcode = opcode;
	ainfo.mask = rdma_opcode[opcode].mask;
	ainfo.paylen = paylen;
	ainfo.psn = psn;
	ainfo.hdr = is_read ? (void *)rte_pktmbuf_prepend(mbuf, rdma_opcode[opcode].length) :
			      (void *)rte_pktmbuf_append(mbuf, rdma_opcode[opcode].length);

	bth_init(&ainfo, 0, 0, padlen, BTH_DEF_PKEY, qp->dest_qp_num, 0, psn);

	if (is_read && bth_pad(&ainfo)) {
		uint8_t *pad = (void *)rte_pktmbuf_append(mbuf, padlen);

		memset(pad, 0, bth_pad(&ainfo));
	}

	if (ainfo.mask & RDMA_AETH_MASK) {
		aeth_set_syn(&ainfo, syndrome);
		aeth_set_msn(&ainfo, msn);
	}

	if (rdma_net_hdr_insert(mbuf, &qp->av, qp->sport) < 0) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_QP_NET_HDR_INSERT_FAIL);
		return -1;
	}
	/* Packet formation is done. Time to calculate icrc. */
	rdma_icrc_generate(mbuf, &ainfo);

	return 0;
}

static inline struct rte_mbuf *
prepare_ack_packet(struct rdma_qp *qp, int opcode, int payload, uint32_t psn, uint8_t syndrome,
		   struct rte_mempool *pool)
{
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id = qp->qid;
	struct rte_mbuf *mbuf;

	mbuf = rte_pktmbuf_alloc(pool);
	if (mbuf == NULL) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
				    RDMA_RX_QP_PREP_ACK_PKT_MBUF_ALLOC_FAIL);
		return NULL;
	}

	if (prepare_ack_packet_with_mbuf(qp, opcode, payload, psn, syndrome, mbuf, qp->resp.msn,
					 false) < 0) {
		rte_pktmbuf_free(mbuf);
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_PREP_ACK_PKT_FAIL);
		return NULL;
	}

	return mbuf;
}

static inline int
read_next_opcode(uint32_t opcode, bool m_segs)
{
	switch (opcode) {
	case RDMA_OPCODE_RC_RDMA_READ_RESPONSE_FIRST:
	case RDMA_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE:
		if (m_segs)
			return RDMA_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE;
		else
			return RDMA_OPCODE_RC_RDMA_READ_RESPONSE_LAST;
	default:
		if (m_segs)
			return RDMA_OPCODE_RC_RDMA_READ_RESPONSE_FIRST;
		else
			return RDMA_OPCODE_RC_RDMA_READ_RESPONSE_ONLY;
	}
	return -1;
}

static inline int
rdma_prep_read_ack(struct rdma_qp *qp, struct rte_mbuf *mbuf, struct rdma_ack *ack, bool m_segs,
		   int opcode, uint32_t *psn)
{
	opcode = read_next_opcode(opcode, m_segs);
	prepare_ack_packet_with_mbuf(qp, opcode, mbuf->data_len, *psn, ack->aeth_syndrome, mbuf,
				     ack->msn, true);
	(*psn)++;

	return opcode;
}

/* Free all mbufs in wqe->mbuf_list except the first (owned by the caller). */
static inline void
rdma_read_reply_cleanup(struct rdma_send_wqe *wqe)
{
	struct rdma_mbufs *rmbuf, *next_rmbuf;
	struct rte_mbuf *seg;
	bool first = true;

	rmbuf = STAILQ_FIRST(&wqe->mbuf_list);
	while (rmbuf) {
		next_rmbuf = STAILQ_NEXT(rmbuf, next);

		/* Release extra refcnt taken in rdma_read_prep_for_pts() */
		for (seg = rmbuf->mbuf; seg; seg = seg->next)
			rte_mbuf_refcnt_update(seg, -1);

		if (!first && rmbuf->mbuf)
			rte_pktmbuf_free(rmbuf->mbuf);
		first = false;
		rmbuf = next_rmbuf;
	}
	memset(wqe, 0, sizeof(*wqe));
}

/*
 * Complete an in-progress READ reply: drop the READ ack, drain non-READ acks
 * queued behind it, release the head, and restore the responder credit.
 */
static inline void
rdma_read_reply_finish(struct rdma_qp *qp)
{
	struct rdma_ack *ack;
	struct rte_mbuf *head = qp->resp.read_reply.read_mbuf;

	ack = STAILQ_FIRST(&qp->resp.ack_pending_list);
	if (likely(ack))
		STAILQ_REMOVE(&qp->resp.ack_pending_list, ack, rdma_ack, next);

	/* Drop the emit pin and free the last ref so the head (and any chained
	 * ICRC tail) returns to the pool; refcnt_update alone never frees it.
	 */
	if (likely(head)) {
		rte_mbuf_refcnt_update(head, -1);
		rte_pktmbuf_free(head);
	}

	qp->resp.resp_cur_rmbuf = NULL;
	memset(&qp->resp.read_reply, 0, sizeof(qp->resp.read_reply));
	STAILQ_INIT(&qp->resp.read_reply.mbuf_list);
	qp->resp.resp_read_rq_bal++;
	RDMA_DBG_INC_QP_COUNTER(qp->lcore, qp->port_id, qp->qid, RDMA_TX_QP_READ_RSP_COMPLETE);
}

/*
 * Emit READ reply segments from @rmbuf. With @burst_limited, stop after
 * @burst_limit packets and save the resume cursor/opcode/psn; otherwise emit
 * all. Finishes the reply once its last segment is emitted.
 */
static inline void
rdma_read_reply_emit(struct rdma_qp *qp, struct rdma_mbufs *rmbuf, struct rte_mbuf **mbufs,
		     uint16_t *n_mbufs, bool burst_limited, uint16_t burst_limit)
{
	struct rdma_send_wqe *wqe = &qp->resp.read_reply;
	struct rdma_ack *ack = STAILQ_FIRST(&qp->resp.ack_pending_list);
	int opcode = qp->resp.read_reply_opcode;
	uint32_t psn = qp->resp.read_reply_psn;
	uint16_t read_pkt_start = *n_mbufs;
	bool m_segs;

	while (rmbuf) {
		struct rdma_mbufs *next_rmbuf = STAILQ_NEXT(rmbuf, next);

		if (burst_limited && burst_limit <= (*n_mbufs - read_pkt_start)) {
			qp->resp.resp_cur_rmbuf = rmbuf;
			qp->resp.read_reply_opcode = opcode;
			qp->resp.read_reply_psn = psn;
			RDMA_DBG_ADD_QP_COUNTER(qp->lcore, qp->port_id, qp->qid,
						RDMA_TX_QP_READ_RSP_PKT_SENT,
						*n_mbufs - read_pkt_start);
			return;
		}

		/* DCQCN RP pacing for READ replies; flush_all bypasses so the
		 * read_reply WQE slot can always free. On postpone, park the cursor
		 * and let the dummy reschedule resume once the TSC gate opens.
		 */
		if (burst_limited && qp->cc.enabled &&
		    dcqcn_rp_pacing_check(&qp->cc,
					  rmbuf->mbuf->pkt_len + DCQCN_ROCEV2_HDR_OVERHEAD)) {
			qp->resp.resp_cur_rmbuf = rmbuf;
			qp->resp.read_reply_opcode = opcode;
			qp->resp.read_reply_psn = psn;
			RDMA_DBG_ADD_QP_COUNTER(qp->lcore, qp->port_id, qp->qid,
						RDMA_TX_QP_READ_RSP_PKT_SENT,
						*n_mbufs - read_pkt_start);
			return;
		}

		m_segs = wqe->n_rdma_segs > 1 ? true : false;
		opcode = rdma_prep_read_ack(qp, rmbuf->mbuf, ack, m_segs, opcode, &psn);
		wqe->n_rdma_segs--;

		if (rmbuf->mbuf == ack->mbuf) {
			/* Head: pin to refcnt >= 2 so duplicate_request() sees
			 * "DMA in flight"; released in finish.
			 */
			rte_mbuf_refcnt_update(rmbuf->mbuf, 1);
			wqe->read_mbuf = rmbuf->mbuf;
		} else {
			/* Drop the prep ref so the NIC frees the segment on TX. */
			struct rte_mbuf *seg = rmbuf->mbuf;

			while (seg) {
				struct rte_mbuf *next_seg = seg->next;

				rte_mbuf_refcnt_update(seg, -1);
				seg = next_seg;
			}
		}

		mbufs[*n_mbufs] = rmbuf->mbuf;
		(*n_mbufs)++;
		rmbuf = next_rmbuf;
	}

	RDMA_DBG_ADD_QP_COUNTER(qp->lcore, qp->port_id, qp->qid, RDMA_TX_QP_READ_RSP_PKT_SENT,
				*n_mbufs - read_pkt_start);
	rdma_read_reply_finish(qp);
}

int
rdma_process_read_reply(struct rdma_qp *qp, struct rte_mbuf *mbuf, struct rte_mbuf **mbufs,
			uint16_t *n_mbufs, uint16_t burst_limit)
{
	struct rdma_ack *ack;
	struct rdma_send_wqe *wqe = &qp->resp.read_reply;
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id = qp->qid;

	/* ACK list is in receive order; replies must be sent in order. */
	ack = STAILQ_FIRST(&qp->resp.ack_pending_list);
	if (!ack || !ack->is_read) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
				    RDMA_TX_QP_PROC_READ_REPLY_ACK_MISMATCH);
		rdma_read_reply_cleanup(wqe);
		return -1;
	}

	mbuf->ol_flags &= ~(DAO_PTS_RDMA_ENQ_D2M << OFFLD_UPPER_BITS);

	/* Fresh reply: first response packet carries the request's first PSN */
	qp->resp.read_reply_opcode = -1;
	qp->resp.read_reply_psn = ack->psn;
	rdma_read_reply_emit(qp, STAILQ_FIRST(&wqe->mbuf_list), mbufs, n_mbufs, true, burst_limit);

	return 0;
}

/* Resume a burst-limited READ reply from the saved cursor (dummy trigger). */
int
rdma_process_read_reply_remaining(struct rdma_qp *qp, struct rte_mbuf **mbufs, uint16_t *n_mbufs,
				  uint16_t burst_limit)
{
	struct rdma_mbufs *rmbuf = qp->resp.resp_cur_rmbuf;

	if (unlikely(!rmbuf)) {
		rdma_read_reply_finish(qp);
		return 0;
	}

	rdma_read_reply_emit(qp, rmbuf, mbufs, n_mbufs, true, burst_limit);

	return 0;
}

/*
 * Flush all remaining segments of the in-progress reply without a burst limit,
 * to free the single read_reply WQE slot before a new D2M completion fetched in
 * the same dequeue run can be processed.
 */
void
rdma_read_reply_flush_all(struct rdma_qp *qp, struct rte_mbuf **mbufs, uint16_t *n_mbufs)
{
	struct rdma_mbufs *rmbuf = qp->resp.resp_cur_rmbuf;

	if (unlikely(!rmbuf)) {
		rdma_read_reply_finish(qp);
		return;
	}

	rdma_read_reply_emit(qp, rmbuf, mbufs, n_mbufs, false, 0);
}

static inline void
populate_sge(struct dao_pts_rdma_sge *sge, struct rdma_pkt_info *rinfo)
{
	sge->addr = rte_be_to_cpu_64(rinfo->reth->va);
	sge->length = rte_be_to_cpu_32(rinfo->reth->len);
	sge->lkey = rte_be_to_cpu_32(rinfo->reth->rkey);
}

static inline void
populate_cqe(struct dao_pts_rdma_cqe *cqe, struct rdma_qp *qp, struct rdma_pkt_info *rinfo)
{
	memset(cqe, 0, sizeof(*cqe));
	cqe->opcode = rinfo->opcode;
	cqe->status = RDMA_WC_SUCCESS;
	cqe->imm_data = rinfo->imm_data;
	cqe->qp_id = qp->qid;
}

static inline void
rdma_populate_dma_info(struct pkt_info *pinfo, uint64_t flag)
{
	struct dao_pts_rdma_sge *sge =
		(struct dao_pts_rdma_sge *)rdma_rx_priv_sge_base(pinfo->mbuf);

	populate_sge(sge, &pinfo->rinfo);

	pinfo->mbuf->ol_flags |= flag << OFFLD_UPPER_BITS;
}

static inline void
rdma_populate_cqe(struct rdma_qp *qp, struct pkt_info *pinfo)
{
	struct dao_pts_rdma_cqe *cqe = rdma_rx_priv_cqe(pinfo->mbuf);

	populate_cqe(cqe, qp, &pinfo->rinfo);

	pinfo->mbuf->ol_flags |= DAO_PTS_RDMA_ENQ_M2D_RQE_WITH_CQE << OFFLD_UPPER_BITS;
}

static inline void
rdma_populate_dma_and_cqe(struct rdma_qp *qp, struct pkt_info *pinfo)
{
	struct dao_pts_rdma_sge *sge = rdma_rx_priv_sge_base(pinfo->mbuf);
	struct dao_pts_rdma_cqe *cqe = rdma_rx_priv_cqe(pinfo->mbuf);

	populate_sge(sge, &pinfo->rinfo);
	populate_cqe(cqe, qp, &pinfo->rinfo);

	pinfo->mbuf->ol_flags |= DAO_PTS_RDMA_ENQ_M2D_WITH_CQE << OFFLD_UPPER_BITS;
}

static inline void
rdma_save_mbuf(struct rdma_qp *qp, struct pkt_info *pinfo)
{
	struct rdma_recv_wqe *wqe = &qp->resp.wqe;

	if (wqe->mbuf == NULL) {
		wqe->mbuf = pinfo->mbuf;
		wqe->tail = rte_pktmbuf_lastseg(pinfo->mbuf);
		wqe->opcode = pinfo->rinfo.opcode;
		wqe->reth = *pinfo->rinfo.reth;
	} else {
		struct rte_mbuf *last = rte_pktmbuf_lastseg(pinfo->mbuf);

		wqe->tail->next = pinfo->mbuf;
		wqe->tail = last;
		wqe->mbuf->nb_segs = (uint16_t)(wqe->mbuf->nb_segs + pinfo->mbuf->nb_segs);
		wqe->mbuf->pkt_len = (uint32_t)(wqe->mbuf->pkt_len + pinfo->mbuf->pkt_len);
	}

	pinfo->mbuf_flags = RDMA_RESPONDER_MBUF_CONSUMED;
}

static inline void
rdma_update_final_mbuf(struct rdma_qp *qp, struct pkt_info *pinfo)
{
	struct rdma_recv_wqe *wqe = &qp->resp.wqe;

	rdma_save_mbuf(qp, pinfo);
	pinfo->mbuf = wqe->mbuf;
	pinfo->mbuf->l2_len = 1;
	wqe->mbuf = NULL;
	wqe->tail->next = NULL;
	wqe->tail = NULL;
	pinfo->mbuf_flags = RDMA_RESPONDER_MBUF_UPDATED;
	pinfo->rinfo.opcode = wqe->opcode;
	rdma_populate_cqe(qp, pinfo);
	RDMA_DBG_INC_QP_COUNTER(qp->lcore, qp->port_id, qp->qid, RDMA_RX_QP_SEND_REQ_RECVD);
}

static inline void
rdma_update_write_final_mbuf(struct rdma_qp *qp, struct pkt_info *pinfo)
{
	struct rdma_recv_wqe *wqe = &qp->resp.wqe;

	rdma_save_mbuf(qp, pinfo);
	pinfo->mbuf = wqe->mbuf;
	pinfo->mbuf->l2_len = 1;
	wqe->mbuf = NULL;
	wqe->tail->next = NULL;
	wqe->tail = NULL;

	if (qp->type == RDMA_QPT_RC)
		pinfo->mbuf_flags = RDMA_RESPONDER_MBUF_UPDATED;

	pinfo->rinfo.opcode = wqe->opcode;
	pinfo->rinfo.reth = &wqe->reth;
	if (pinfo->rinfo.mask & RDMA_IMMDT_MASK)
		rdma_populate_dma_and_cqe(qp, pinfo);
	else
		rdma_populate_dma_info(pinfo, DAO_PTS_RDMA_ENQ_M2D);
	RDMA_DBG_INC_QP_COUNTER(qp->lcore, qp->port_id, qp->qid, RDMA_RX_QP_WRITE_REQ_RECVD);
}

static inline void
rdma_update_mbuf(struct rte_mbuf *mbuf, uint32_t dma_len, uint32_t *mtu, uint32_t *offset)
{
	uint32_t minimum;

	minimum = RTE_MIN(RTE_MIN(*mtu, dma_len - *offset), rte_pktmbuf_tailroom(mbuf));
	rte_pktmbuf_append(mbuf, minimum);
	*offset += minimum;
	*mtu -= minimum;
}

static inline int
rdma_read_prep_for_pts(struct rdma_qp *qp, struct pkt_info *pinfo, uint32_t *npkts)
{
	uint32_t offset = 0;
	uint16_t port = 0;
	struct rte_mbuf *mbuf;
	uint32_t mtu = qp->mtu;
	struct rdma_pkt_info *rinfo = &pinfo->rinfo;
	uint32_t dma_len = rte_be_to_cpu_32(rinfo->reth->len);
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id = qp->qid;

	port = pinfo->mbuf->port;
	rte_pktmbuf_reset(pinfo->mbuf);
	pinfo->mbuf->l2_len = 1;
	rdma_update_mbuf(pinfo->mbuf, dma_len, &mtu, &offset);

	/* Bump refcnt: the chain is also referenced via ack_pending_list;
	 * the extra reference prevents use-after-free when PTS enqueue
	 * fails and the drop path frees the chain.
	 */
	rte_mbuf_refcnt_update(pinfo->mbuf, 1);

	/* Build chain with a local tail pointer to avoid repeated scans */
	struct rte_mbuf *tail = pinfo->mbuf;

	while (offset < dma_len) {
		if (!mtu) {
			mtu = qp->mtu;
			*npkts += 1;
		}
		mbuf = rte_pktmbuf_alloc(pinfo->mbuf->pool);
		if (!mbuf) {
			struct rte_mbuf *m = pinfo->mbuf;

			/* Undo refcnt bumps on the partial chain so the
			 * caller's free brings each segment back to 0.
			 */
			while (m) {
				rte_mbuf_refcnt_update(m, -1);
				m = m->next;
			}
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
					    RDMA_RX_QP_READ_PREP_PTS_ALLOC_MBUF_ERR);
			return -1;
		}
		rte_pktmbuf_reset_headroom(mbuf);
		rdma_update_mbuf(mbuf, dma_len, &mtu, &offset);
		rte_mbuf_refcnt_update(mbuf, 1);
		tail->next = mbuf;
		tail = mbuf;
		tail->next = NULL;
		pinfo->mbuf->nb_segs = (uint16_t)(pinfo->mbuf->nb_segs + mbuf->nb_segs);
		pinfo->mbuf->pkt_len = (uint32_t)(pinfo->mbuf->pkt_len + mbuf->pkt_len);
	}

	rdma_populate_dma_info(pinfo, DAO_PTS_RDMA_ENQ_D2M);
	pinfo->mbuf->port = port;
	qp->resp.resp_read_rq_bal--;
	pinfo->mbuf_flags = RDMA_RESPONDER_MBUF_UPDATED;

	return 0;
}

static inline resp_states_t
rdma_handle_read_request(struct rdma_qp *qp, struct pkt_info *pinfo)
{
	uint32_t npkts = 1;
	uint32_t dma_len = rte_be_to_cpu_32(pinfo->rinfo.reth->len);
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id = qp->qid;

	if (dma_len > RDMA_PORT_MAX_MSG_SZ) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
				    RDMA_RX_QP_HANDLE_READ_REQ_DMA_LEN_EXC);
		return RDMA_RESPST_ERR_LENGTH;
	}

	if (rdma_read_prep_for_pts(qp, pinfo, &npkts) < 0) {
		qp->resp.wqe.mbuf = NULL;
		qp->resp.wqe.tail = NULL;
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
				    RDMA_RX_QP_HANDLE_READ_REQ_READ_PREP_PTS_FAIL);
		return RDMA_RESPST_ERR_RNR;
	}

	qp->resp.msn++;
	qp->resp.opcode = -1;
	qp->resp.status = RDMA_WC_SUCCESS;

	qp->resp.psn = (pinfo->rinfo.psn + npkts) & BTH_PSN_MASK;
	qp->resp.ack_psn = qp->resp.psn;

	rdma_update_ack_pending_list(qp, pinfo->mbuf, pinfo->rinfo.psn, AETH_ACK_UNLIMITED, true);
	RDMA_DBG_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_READ_REQ_RCVD);

	return RDMA_RESPST_DONE;
}

static resp_states_t
execute(struct rdma_qp *qp, struct pkt_info *pinfo)
{
	struct rdma_pkt_info *rinfo = &pinfo->rinfo;

	if (rinfo->mask & RDMA_SEND_MASK) {
		/* For UD and GSI queue pairs, preserve the network header for user-space
		 * processing. UD packets require the Global Routing Header (GRH) to be
		 * passed to the application as part of the receive completion, so we
		 * prepend it to the mbuf data.
		 */
		if (qp->type == RDMA_QPT_GSI || qp->type == RDMA_QPT_UD) {
			struct rdma_network_hdr *nhdr =
				(struct rdma_network_hdr *)rte_pktmbuf_prepend(
					pinfo->mbuf, sizeof(struct rdma_network_hdr));
			if (nhdr == NULL)
				return RDMA_RESPST_CLEANUP;

			/* Copy the IPv4/IPv6 header as RoCE GRH and clear reserved field */
			memmove(&nhdr->roce4grh, pinfo->iph, sizeof(nhdr->roce4grh));
			memset(&nhdr->reserved, 0, sizeof(nhdr->reserved));
		}

		if (!(rinfo->mask & RDMA_END_MASK))
			rdma_save_mbuf(qp, pinfo);
		else
			rdma_update_final_mbuf(qp, pinfo);
	} else if (rinfo->mask & RDMA_WRITE_MASK) {
		if (!(rinfo->mask & RDMA_END_MASK)) {
			rdma_save_mbuf(qp, pinfo);
		} else {
			rdma_update_write_final_mbuf(qp, pinfo);
			RDMA_DBG_INC_QP_COUNTER(qp->lcore, qp->port_id, qp->qid,
						RDMA_RX_QP_WRITE_MSG_COMPLETE);
		}
	} else if (rinfo->mask & RDMA_READ_MASK) {
		return rdma_handle_read_request(qp, pinfo);
	} else {
		return RDMA_RESPST_CLEANUP;
	}

	if (rinfo->mask & RDMA_END_MASK)
		/* We successfully processed this new request. */
		qp->resp.msn++;
	qp->resp.opcode = rinfo->opcode;
	qp->resp.status = RDMA_WC_SUCCESS;

	/* next expected psn, read handles this separately */
	qp->resp.psn = (rinfo->psn + 1) & BTH_PSN_MASK;
	qp->resp.ack_psn = qp->resp.psn;

	if (rinfo->mask & (RDMA_COMP_MASK | RDMA_END_MASK))
		return RDMA_RESPST_COMPLETE;
	else if (qp->type == RDMA_QPT_RC)
		return RDMA_RESPST_ACKNOWLEDGE;

	return RDMA_RESPST_CLEANUP;
}

static resp_states_t
do_complete(struct rdma_qp *qp, struct rdma_pkt_info *pkt)
{
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id = qp->qid;

	RTE_SET_USED(pkt);

	qp->resp.wqe.mbuf = NULL;
	qp->resp.wqe.tail = NULL;
	qp->resp.opcode = -1;

	if (unlikely(qp->state == QP_STATE_ERROR)) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_DO_COMP_QP_STATE_ERR);
		return RDMA_RESPST_EXIT;
	}
	if (qp->type == RDMA_QPT_RC)
		return RDMA_RESPST_ACKNOWLEDGE;

	return RDMA_RESPST_CLEANUP;
}

static resp_states_t
cleanup(struct rdma_qp *qp, struct rdma_pkt_info *pkt)
{
	RTE_SET_USED(qp);
	RTE_SET_USED(pkt);

	return RDMA_RESPST_DONE;
}

static int
send_ack(struct rdma_qp *qp, uint8_t syndrome, struct pkt_info *pinfo, int opcode, const char *msg)
{
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id = qp->qid;
	struct rte_mbuf *mbuf;

	RTE_SET_USED(msg);

	mbuf = prepare_ack_packet(qp, opcode, 0, pinfo->rinfo.psn, syndrome, pinfo->mbuf->pool);
	if (!mbuf)
		return -ENOMEM;

	mbuf->port = pinfo->mbuf->port;
	mbuf->hash.fdir.hi = pinfo->rx_queue;

	if (rdma_update_ack_pending_list(qp, mbuf, pinfo->rinfo.psn, syndrome, false) < 0) {
		rte_pktmbuf_free(mbuf);
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
				    RDMA_RX_QP_SEND_ACK_UPDATE_ACK_PENDING_LIST_ERR);
		return -ENOMEM;
	}

	RDMA_DBG_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_ACK_QUEUED);
	return 0;
}

static resp_states_t
acknowledge(struct rdma_qp *qp, struct pkt_info *pinfo)
{
	if (qp->type != RDMA_QPT_RC)
		return RDMA_RESPST_CLEANUP;

	if (qp->resp.aeth_syndrome != AETH_ACK_UNLIMITED) {
		send_ack(qp, qp->resp.aeth_syndrome, pinfo, RDMA_OPCODE_RC_ACKNOWLEDGE, "ACK");
		RDMA_DBG_INC_QP_COUNTER(qp->lcore, qp->port_id, qp->qid, RDMA_RX_QP_ACK_GENERATED);
	} else if (bth_ack(&pinfo->rinfo)) {
		send_ack(qp, AETH_ACK_UNLIMITED, pinfo, RDMA_OPCODE_RC_ACKNOWLEDGE, "ACK");
		RDMA_DBG_INC_QP_COUNTER(qp->lcore, qp->port_id, qp->qid, RDMA_RX_QP_ACK_GENERATED);
	}

	return RDMA_RESPST_CLEANUP;
}

static inline int
rdma_ack_pending_list_find(struct rdma_qp *qp, uint32_t psn)
{
	struct rdma_ack *ack;

	STAILQ_FOREACH(ack, &qp->resp.ack_pending_list, next) {
		if (ack->psn == psn)
			return 1;
	}

	return 0;
}

static inline struct rte_mbuf *
rdma_ack_pending_list_find_mbuf_by_psn(struct rdma_qp *qp, uint32_t psn)
{
	struct rdma_ack *ack;

	/* clang-format off */
	STAILQ_FOREACH(ack, &qp->resp.ack_pending_list, next) {
		/* clang-format on */
		if (ack->psn == psn)
			return ack->mbuf;
	}

	return NULL;
}

/*
 * Find and remove an ack entry by PSN from ack_pending_list.
 * Returns the mbuf that was associated with this ack, or NULL if not found.
 */
static inline struct rte_mbuf *
rdma_ack_pending_list_remove_by_psn(struct rdma_qp *qp, uint32_t psn)
{
	struct rdma_ack *ack, *tmp_ack;
	struct rte_mbuf *old_mbuf = NULL;

	STAILQ_FOREACH_SAFE(ack, &qp->resp.ack_pending_list, next, tmp_ack)
	{
		if (ack->psn == psn) {
			old_mbuf = ack->mbuf;
			STAILQ_REMOVE(&qp->resp.ack_pending_list, ack, rdma_ack, next);
			break;
		}
	}

	return old_mbuf;
}

static inline int
rdma_is_last_acked_request(struct rdma_qp *qp, uint32_t psn, struct pkt_info *pkt)
{
	uint32_t npkts = 0;
	uint32_t dma_len = rte_be_to_cpu_32(pkt->rinfo.reth->len);

	npkts = dma_len / qp->mtu + ((dma_len % qp->mtu) ? 1 : 0);

	/* Check if this is the last request that was acked. */
	if (((psn + npkts - 1) & BTH_PSN_MASK) == ((qp->resp.ack_psn - 1) & BTH_PSN_MASK))
		return 1;

	return 0;
}

static inline int
rdma_read_rkey_validate(struct rdma_qp *qp, struct pkt_info *pkt)
{
	RTE_SET_USED(qp);
	RTE_SET_USED(pkt);

	return 1;
}

static int
send_dup_ack(struct rdma_qp *qp, uint8_t syndrome, struct pkt_info *pinfo, uint32_t psn, int opcode)
{
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id = qp->qid;
	struct rte_mbuf *mbuf;

	mbuf = prepare_ack_packet(qp, opcode, 0, psn, syndrome, pinfo->mbuf->pool);
	if (!mbuf || pinfo->mbuf->port >= RTE_MAX_ETHPORTS)
		return -ENOMEM;

	if (rte_eth_tx_burst(pinfo->mbuf->port, pinfo->rx_queue, &mbuf, 1) != 1) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
				    RDMA_RX_QP_SEND_DUP_ACK_TX_BURST_FAIL);
		rte_pktmbuf_free(mbuf);
	}

	return 0;
}

static resp_states_t
duplicate_request(struct rdma_qp *qp, struct pkt_info *pkt)
{
	uint32_t npkts = 1;
	uint32_t prev_psn = (qp->resp.ack_psn - 1) & BTH_PSN_MASK;

	if (pkt->rinfo.mask & RDMA_SEND_MASK || pkt->rinfo.mask & RDMA_WRITE_MASK) {
		/* SEND. Ack again and cleanup. C9-105. */
		send_dup_ack(qp, AETH_ACK_UNLIMITED, pkt, prev_psn, RDMA_OPCODE_RC_ACKNOWLEDGE);
		return RDMA_RESPST_CLEANUP;

	} else if (pkt->rinfo.mask & RDMA_READ_MASK) {
		struct rte_mbuf *old_mbuf;
		bool requeue_dma = false;
		bool enq_requeue = false;

		/* Check if request is in ack pending list */
		old_mbuf = rdma_ack_pending_list_find_mbuf_by_psn(qp, pkt->rinfo.psn);
		if (old_mbuf) {
			/* refcnt == 1: enqueue failed, chain parked intact by the
			 * prep ref - the only state safe to resubmit. refcnt 0
			 * (freed) or >= 2 (DMA in flight) must not be resubmitted.
			 */
			if (rte_mbuf_refcnt_read(old_mbuf) == 1) {
				struct rte_mbuf *m;
				uint16_t linked = 0;

				/* Resubmit only if still fully linked; the enqueuer
				 * walks exactly nb_segs via ->next.
				 */
				for (m = old_mbuf; m; m = m->next)
					linked++;

				/* A chain already DMA-completed (packet_type set by
				 * process_rdma_read_req) must never be resubmitted:
				 * its segments are owned by the reply path and may be
				 * freed/recycled, so re-enqueuing corrupts the chain.
				 */
				if (likely(linked == old_mbuf->nb_segs &&
					   old_mbuf->packet_type != DAO_PTS_RDMA_D2M_COMPL)) {
					for (m = old_mbuf; m; m = m->next)
						rte_mbuf_refcnt_update(m, 1);
					old_mbuf->ol_flags |= DAO_PTS_RDMA_ENQ_D2M
							      << OFFLD_UPPER_BITS;

					rte_pktmbuf_free(pkt->mbuf);
					pkt->mbuf = old_mbuf;
					pkt->mbuf_flags = RDMA_RESPONDER_MBUF_UPDATED;
					enq_requeue = true;
				}
			}
			/* else: DMA in-flight or unsafe - remote retransmits. */
		} else if (rdma_is_last_acked_request(qp, pkt->rinfo.psn, pkt) &&
			   rdma_read_rkey_validate(qp, pkt)) {
			/* Last read reply lost - reread and retransmit */
			requeue_dma = true;
		}

		/* A previously enqueued chain was lost; re-enqueued to PTS. */
		if (enq_requeue)
			RDMA_INC_QP_COUNTER(qp->lcore, qp->port_id, qp->qid,
					    RDMA_RX_QP_READ_DUP_ENQ_PKT_LOST_PTS_REQUEUE);

		if (requeue_dma) {
			rdma_read_prep_for_pts(qp, pkt, &npkts);
			rdma_update_ack_pending_list(qp, pkt->mbuf, pkt->rinfo.psn,
						     AETH_ACK_UNLIMITED, true);
			/* Last read reply lost on the wire; re-read and re-enqueue. */
			RDMA_INC_QP_COUNTER(qp->lcore, qp->port_id, qp->qid,
					    RDMA_RX_QP_READ_DUP_WIRE_PKT_LOST_PTS_REQUEUE);
			RDMA_DBG_INC_QP_COUNTER(qp->lcore, qp->port_id, qp->qid,
						RDMA_RX_QP_READ_DUP_REQ);
		}
	}
	return RDMA_RESPST_CLEANUP;
}

/* Process a class A or C. Both are treated the same in this implementation. */
static void
do_class_ac_error(struct rdma_qp *qp, uint8_t syndrome, enum rdma_wc_status status)
{
	qp->resp.aeth_syndrome = syndrome;
	qp->resp.status = status;

	/* indicate that we should go through the ERROR state */
	qp->resp.goto_error = 1;
}

int
rdma_responder(struct pkt_info *pinfo)
{
	struct rdma_qp *qp = (struct rdma_qp *)pinfo->rinfo.qp;
	unsigned int lcore_id = rte_lcore_id();
	uint32_t port_id = pinfo->port_num;
	resp_states_t state;
	uint32_t qp_id;

	if (!qp->valid) {
		RDMA_INC_PORT_COUNTER(lcore_id, port_id, RDMA_RX_PORT_RSP_QP_INV);
		goto exit;
	}

	qp->resp.aeth_syndrome = AETH_ACK_UNLIMITED;
	qp_id = qp->qid;
	lcore_id = qp->lcore;

	switch (qp->state) {
	case QP_STATE_RESET:
		state = RDMA_RESPST_RESET;
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_RSP_QP_STATE_RESET);
		break;

	default:
		state = RDMA_RESPST_GET_REQ;
		break;
	}

	while (1) {
		switch (state) {
		case RDMA_RESPST_GET_REQ:
			state = queue_check(qp);
			break;
		case RDMA_RESPST_CHK_PSN:
			state = check_psn(qp, pinfo);
			break;
		case RDMA_RESPST_CHK_OP_SEQ:
			state = check_op_seq(qp, &pinfo->rinfo);
			break;
		case RDMA_RESPST_CHK_OP_VALID:
			state = check_op_valid(qp, &pinfo->rinfo);
			break;
		case RDMA_RESPST_CHK_RESOURCE:
			state = check_resource(qp, &pinfo->rinfo);
			break;
		case RDMA_RESPST_CHK_LENGTH:
			state = check_length(qp, &pinfo->rinfo);
			break;
		case RDMA_RESPST_CHK_RKEY:
			state = check_rkey(qp, pinfo);
			break;
		case RDMA_RESPST_EXECUTE:
			state = execute(qp, pinfo);
			break;
		case RDMA_RESPST_COMPLETE:
			state = do_complete(qp, &pinfo->rinfo);
			break;
		case RDMA_RESPST_ACKNOWLEDGE:
			state = acknowledge(qp, pinfo);
			break;
		case RDMA_RESPST_CLEANUP:
			state = cleanup(qp, &pinfo->rinfo);
			break;
		case RDMA_RESPST_DUPLICATE_REQUEST:
			state = duplicate_request(qp, pinfo);
			break;
		case RDMA_RESPST_ERR_PSN_OUT_OF_SEQ:
			/* RC only - Class B. Drop packet. */
			send_ack(qp, AETH_NAK_PSN_SEQ_ERROR, pinfo, RDMA_OPCODE_RC_ACKNOWLEDGE,
				 NULL);
			state = RDMA_RESPST_CLEANUP;
			break;
		case RDMA_RESPST_ERR_TOO_MANY_RDMA_ATM_REQ:
		case RDMA_RESPST_ERR_MISSING_OPCODE_FIRST:
		case RDMA_RESPST_ERR_MISSING_OPCODE_LAST_C:
		case RDMA_RESPST_ERR_UNSUPPORTED_OPCODE:
		case RDMA_RESPST_ERR_LENGTH:
			/* RC Only - Class C. */
			do_class_ac_error(qp, AETH_NAK_INVALID_REQ, RDMA_WC_REM_INV_REQ_ERR);
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_RSP_CLASS_C_ERR);
			state = RDMA_RESPST_COMPLETE;
			break;
		case RDMA_RESPST_ERR_RNR:
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
					    RDMA_RX_QP_RSP_CLASS_C_RNR_ERR);
			if (qp->type == RDMA_QPT_RC) {
				send_ack(qp,
					 AETH_RNR_NAK | (~AETH_TYPE_MASK & qp->attr.min_rnr_timer),
					 pinfo, RDMA_OPCODE_RC_ACKNOWLEDGE, NULL);
			}
			return -1;
		case RDMA_RESPST_ERR_RKEY_VIOLATION:
			do_class_ac_error(qp, AETH_NAK_REM_ACC_ERR, RDMA_WC_REM_ACCESS_ERR);
			state = RDMA_RESPST_COMPLETE;
			break;
		case RDMA_RESPST_ERR_CQ_OVERFLOW:
			/* All - Class G */
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
					    RDMA_RX_QP_RSP_CQ_OVERFLOW_ERR);
			state = RDMA_RESPST_ERROR;
			break;
		case RDMA_RESPST_DONE:
			if (qp->resp.goto_error) {
				state = RDMA_RESPST_ERROR;
				break;
			}
			goto done;
		case RDMA_RESPST_EXIT:
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_RSP_RESPST_EXIT);
			goto exit;
		case RDMA_RESPST_RESET:
			qp->resp.wqe.mbuf = NULL;
			qp->resp.wqe.tail = NULL;
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_RSP_RESPST_RESET);
			goto exit;
		case RDMA_RESPST_ERROR:
			qp->resp.goto_error = 0;
			qp->state = QP_STATE_ERROR;
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_RSP_RESPST_ERR);
			goto exit;

		default:
		}
	}

done:
	return 0;
exit:
	return -1;
}

/**
 * Dequeue pending ACK mbufs (non-READ) from ack_pending_list until a READ entry is hit.
 * Returns number of ACK mbufs copied to out array.
 */
uint16_t
dao_rdma_ack_dequeue_until_read(uint32_t qp_id, int devid, struct rte_mbuf **mbufs,
				uint16_t max_pkts)
{
	struct rdma_qp *qp = rdma_qp_query_fast(qp_id, devid);
	struct rdma_ack *ack;
	uint16_t n = 0;

	if (!qp || !mbufs || !max_pkts || STAILQ_EMPTY(&qp->resp.ack_pending_list))
		return 0;

	while (n < max_pkts) {
		ack = STAILQ_FIRST(&qp->resp.ack_pending_list);
		if (!ack || ack->is_read)
			break;
		STAILQ_REMOVE_HEAD(&qp->resp.ack_pending_list, next);
		mbufs[n++] = ack->mbuf;
		RDMA_DBG_INC_QP_COUNTER(qp->lcore, qp->port_id, qp_id, RDMA_RX_QP_ACK_SENT);
	}

	return n;
}
