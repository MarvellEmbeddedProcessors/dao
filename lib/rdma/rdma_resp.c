/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_ethdev.h>

#include <dao_log.h>

#include "dao_rdma_fp.h"
#include "rdma_common.h"
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
	if (qp->state == QP_STATE_ERROR)
		/* Go drain recv wr queue */
		return RDMA_RESPST_CHK_RESOURCE;

	return RDMA_RESPST_CHK_PSN;
}

static resp_states_t
check_psn(struct rdma_qp *qp, struct pkt_info *pinfo)
{
	struct rdma_pkt_info *pkt = &pinfo->rinfo;

	/* PSN is 24 bit number. */
	int diff = psn_compare(pkt->psn, qp->resp.psn);

	switch (qp->type) {
	case RDMA_QPT_RC:
		if (diff > 0) {
			if (qp->resp.sent_psn_nak)
				return RDMA_RESPST_CLEANUP;

			qp->resp.sent_psn_nak = 1;
#ifdef RDMA_DEBUG
			dao_dbg("PSN out of sequence. Expected %u, received %u on QP %d mbufs avail %u",
				qp->resp.psn, pkt->psn, qp->qid,
				rte_mempool_avail_count(pinfo->mbuf->pool));
#endif
			pkt->psn = qp->resp.psn;
			pinfo->mbuf_flags = RDMA_RESPONDER_MBUF_DROP;
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
	switch (qp->type) {
	case RDMA_QPT_RC:
		if (((pkt->mask & RDMA_READ_MASK) &&
		     !(qp->attr.qp_access_flags & RDMA_ACCESS_REMOTE_READ)) ||
		    ((pkt->mask & RDMA_WRITE_MASK) &&
		     !(qp->attr.qp_access_flags & RDMA_ACCESS_REMOTE_WRITE)))
			return RDMA_RESPST_ERR_UNSUPPORTED_OPCODE;

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
	if (pkt->mask & RDMA_READ_MASK) {
		if (likely(qp->resp.resp_read_rq_bal > 0))
			return RDMA_RESPST_CHK_LENGTH;

		dao_err("No read request resources available for QP %d, port %u", qp->qid,
			pkt->port_num);
		return RDMA_RESPST_ERR_TOO_MANY_RDMA_ATM_REQ;
	}

	if (pkt->mask & RDMA_RWR_MASK) {
		if (likely(check_rq_resource(qp)))
			return RDMA_RESPST_CHK_LENGTH;
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

	if (index >= RDMA_MAX_MR) {
		dao_err("Invalid RKEY %x in packet PSN %u", rkey, pkt->psn);
		return -1;
	}

	pd = pd_find_by_id(qp->pd_id, pinfo->port_num);
	if (!pd) {
		dao_err("PD not found for PD ID %u qp id %d port %u", qp->pd_id, qp->qid,
			pinfo->port_num);
		return -1;
	}

	mr = pd->mr_pool[index];
	if (!mr) {
		dao_err("MR not found for index %u key %x, pdn %u qpid %d", index, rkey, qp->pd_id,
			qp->qid);
		return -1;
	}

	if ((pkt->mask & RDMA_READ_MASK && !(mr->access_flags & RDMA_ACCESS_REMOTE_READ)) ||
	    (pkt->mask & RDMA_WRITE_MASK && !(mr->access_flags & RDMA_ACCESS_REMOTE_WRITE))) {
		dao_err("Access violation for RKEY %u in packet PSN %u", rkey, pkt->psn);
		return -1;
	}

	if (length > mr->length || (va < mr->va) || (va + length > mr->va + mr->length)) {
		dao_err("Length violation failed for RKEY %u in packet PSN %u reth len %u mr len %u",
			rkey, pkt->psn, length, mr->length);
		return -1;
	}

	return 0;
}

static resp_states_t
check_rkey(struct rdma_qp *qp, struct pkt_info *pkt)
{
	RTE_SET_USED(qp);

	if ((pkt->rinfo.mask & RDMA_READ_OR_WRITE_MASK) && (pkt->rinfo.mask & RDMA_START_MASK)) {
		if (validate_rkey(pkt) < 0) {
			dao_err("Invalid RKEY %u in packet PSN %u", pkt->rinfo.reth->rkey,
				pkt->rinfo.psn);
			return RDMA_RESPST_ERR_RKEY_VIOLATION;
		}
	}

	return RDMA_RESPST_EXECUTE;
}

static inline int
prepare_ack_packet_with_mbuf(struct rdma_qp *qp, int opcode, int payload, uint32_t psn,
			     uint8_t syndrome, struct rte_mbuf *mbuf, uint32_t msn, bool is_read)
{
	struct rdma_pkt_info ainfo;
	int padlen;
	int paylen;

	padlen = (-payload) & 0x3;
	paylen = rdma_opcode[opcode].length + payload + padlen + RDMA_ICRC_SIZE;
#ifdef RDMA_DEBUG
	dao_dbg("paylen %d padlen %d opcode %d psn %u msn %u syn %d pay %d hdrlen %d", paylen,
		padlen, opcode, psn, msn, syndrome, payload, rdma_opcode[opcode].length);
#endif

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
		dao_err("Failed to insert network header into mbuf.");
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
	struct rte_mbuf *mbuf;

	mbuf = rte_pktmbuf_alloc(pool);
	if (mbuf == NULL) {
		dao_err("Failed to allocate mbuf for ACK packet.");
		return NULL;
	}

	if (prepare_ack_packet_with_mbuf(qp, opcode, payload, psn, syndrome, mbuf, qp->resp.msn,
					 false) < 0) {
		rte_pktmbuf_free(mbuf);
		return NULL;
	}

	return mbuf;
}

/* Removed obsolete #if 0 rdma_recheck_mr block per style warning */
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
		   int opcode)
{
	opcode = read_next_opcode(opcode, m_segs);
	prepare_ack_packet_with_mbuf(qp, opcode, mbuf->data_len, ack->psn, ack->aeth_syndrome, mbuf,
				     ack->msn, true);
	ack->psn++;

	return opcode;
}

/*
 * Free all mbufs in wqe->mbuf_list EXCEPT the first one (which is owned by caller).
 * This handles cleanup when dropping a read reply to prevent memory leaks.
 */
static inline void
rdma_read_reply_cleanup(struct rdma_send_wqe *wqe)
{
	struct rdma_mbufs *rmbuf, *next_rmbuf;

	/* Skip the first mbuf - it is owned by the caller who will free it */
	rmbuf = STAILQ_FIRST(&wqe->mbuf_list);
	if (rmbuf)
		rmbuf = STAILQ_NEXT(rmbuf, next);

	while (rmbuf) {
		next_rmbuf = STAILQ_NEXT(rmbuf, next);
		if (rmbuf->mbuf)
			rte_pktmbuf_free(rmbuf->mbuf);
		rmbuf = next_rmbuf;
	}
	/* memset zeros everything including mbuf_list head pointers */
	memset(wqe, 0, sizeof(*wqe));
}

int
rdma_process_read_reply(struct rdma_qp *qp, struct rte_mbuf *mbuf, struct rte_mbuf **mbufs,
			uint16_t *n_mbufs)
{
	bool m_segs;
	int opcode = -1;
	struct rdma_ack *ack = NULL, *tmp_ack = NULL;
	struct rdma_mbufs *rmbuf = NULL, *next_rmbuf = NULL;
	struct rdma_send_wqe *wqe = &qp->resp.read_reply;

	/*
	 * Get the first ACK entry.
	 * ACK list is maintained in receive order, and replies MUST
	 * be sent in order.
	 */
	ack = STAILQ_FIRST(&qp->resp.ack_pending_list);
	if (!ack || !ack->is_read) {
#ifdef RDMA_DEBUG
		dao_dbg("[RESP-READ] QP %d: no ack entry or not READ, dropping", qp->qid);
#endif
		rdma_read_reply_cleanup(wqe);
		return -1;
	}

	/*
	 * If mbuf doesn't match but this is a valid READ ack entry,
	 * check if PSN matches. This handles the case where a duplicate
	 * READ replaced the original entry, and the old DMA completes.
	 * The old mbuf has valid DMA data, so we can process it.
	 */
	if (ack->mbuf != mbuf) {
		/* Get PSN from incoming mbuf's private data */
		uint32_t mbuf_psn = rdma_rx_priv_ack(mbuf)->psn;

		if (ack->psn == mbuf_psn) {
#ifdef RDMA_DEBUG
			dao_dbg("[RESP-READ] QP %d PSN %u: mbuf mismatch but PSN matches, "
				"processing (ack_mbuf=%p mbuf=%p)",
				qp->qid, ack->psn, ack->mbuf, mbuf);
#endif
			/* Update ack entry to use current mbuf */
			ack->mbuf = mbuf;
		} else {
#ifdef RDMA_DEBUG
			dao_dbg("[RESP-READ] QP %d: mbuf and PSN mismatch, dropping "
				"(ack_psn=%u mbuf_psn=%u ack_mbuf=%p mbuf=%p)",
				qp->qid, ack->psn, mbuf_psn, ack->mbuf, mbuf);
#endif
			rdma_read_reply_cleanup(wqe);
			return -1;
		}
	}

#ifdef RDMA_DEBUG
	dao_dbg("[RESP-READ] QP %d READ PSN %u: processing reply, n_segs %u", qp->qid, ack->psn,
		wqe->n_rdma_segs);
#endif
	mbuf->ol_flags &= ~(DAO_PTS_RDMA_ENQ_D2M << OFFLD_UPPER_BITS);

	/* Process all packets */
	rmbuf = STAILQ_FIRST(&wqe->mbuf_list);
	while (rmbuf) {
		m_segs = wqe->n_rdma_segs > 1 ? true : false;
		next_rmbuf = STAILQ_NEXT(rmbuf, next);
		opcode = rdma_prep_read_ack(qp, rmbuf->mbuf, ack, m_segs, opcode);
		wqe->n_rdma_segs--;
		mbufs[*n_mbufs] = rmbuf->mbuf;
		(*n_mbufs)++;
		rmbuf = next_rmbuf;
	}

	/* All packets processed, cleanup */
#ifdef RDMA_DEBUG
	dao_dbg("[RESP-READ] QP %d READ PSN %u: reply COMPLETE, sent %u pkts, removing ack",
		qp->qid, ack->psn, *n_mbufs);
#endif
	STAILQ_REMOVE(&qp->resp.ack_pending_list, ack, rdma_ack, next);

	/* Drain any non-READ acks that were waiting behind this one */
	ack = NULL;
	STAILQ_FOREACH_SAFE(ack, &qp->resp.ack_pending_list, next, tmp_ack)
	{
		if (ack->is_read)
			break;

		mbufs[*n_mbufs] = ack->mbuf;
		(*n_mbufs)++;
		STAILQ_REMOVE(&qp->resp.ack_pending_list, ack, rdma_ack, next);
	}

	memset(&qp->resp.read_reply, 0, sizeof(qp->resp.read_reply));
	STAILQ_INIT(&qp->resp.read_reply.mbuf_list);
	qp->resp.resp_read_rq_bal++;

	return 0;
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
#ifdef RDMA_DEBUG
	dao_dbg("%s: addr %lx, length %u, rkey %u\n", __func__, sge->addr, sge->length, sge->lkey);
#endif
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
#ifdef RDMA_DEBUG
	dao_dbg("RDMA final mbuf updated for QP %d, mbuf %p nb_segs %u pkt_len %u", qp->qid,
		pinfo->mbuf, pinfo->mbuf->nb_segs, pinfo->mbuf->pkt_len);
#endif
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
#ifdef RDMA_DEBUG
	dao_dbg("RDMA write final mbuf updated for QP %d, mbuf %p nb_segs %u pkt_len %u", qp->qid,
		pinfo->mbuf, pinfo->mbuf->nb_segs, pinfo->mbuf->pkt_len);
#endif
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
rdma_mbuf_print(struct rte_mbuf *mbuf)
{
	struct rte_mbuf *m = mbuf;

	dao_dbg("mbuf chain:\n");
	while (m) {
		dao_dbg("mbuf %p, data_len %u, next %p", m, m->data_len, m->next);
		m = m->next;
	}
	return 0;
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

	port = pinfo->mbuf->port;
	rte_pktmbuf_reset(pinfo->mbuf);
	pinfo->mbuf->l2_len = 1;
	rdma_update_mbuf(pinfo->mbuf, dma_len, &mtu, &offset);

	/* Build chain with a local tail pointer to avoid repeated scans */
	struct rte_mbuf *tail = pinfo->mbuf;

	while (offset < dma_len) {
		if (!mtu) {
			mtu = qp->mtu;
			*npkts += 1;
		}
		mbuf = rte_pktmbuf_alloc(pinfo->mbuf->pool);
		if (!mbuf) {
			dao_err("Failed to allocate mbuf for RDMA read.");
			return -1;
		}
		rte_pktmbuf_reset_headroom(mbuf);
		rdma_update_mbuf(mbuf, dma_len, &mtu, &offset);
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
#ifdef RDMA_DEBUG
	dao_dbg("RDMA read prepared for PTS: port %u, npkts %u, dma_len %u mbuf %p nb_segs %u %d qp state %u qp->req.read_rq_bal %u",
		port, *npkts, dma_len, pinfo->mbuf, pinfo->mbuf->nb_segs,
		rdma_mbuf_print(pinfo->mbuf), qp->state, qp->req.read_rq_bal);
#endif
	return 0;
}

static inline resp_states_t
rdma_handle_read_request(struct rdma_qp *qp, struct pkt_info *pinfo)
{
	uint32_t npkts = 1;
	uint32_t dma_len = rte_be_to_cpu_32(pinfo->rinfo.reth->len);

#ifdef RDMA_DEBUG
	dao_dbg("[RESP-READ] QP %d received READ req PSN %u len %u", qp->qid, pinfo->rinfo.psn,
		dma_len);
#endif

	if (dma_len > RDMA_PORT_MAX_MSG_SZ) {
		dao_err("RDMA read request length %u exceeds maximum allowed %u.", dma_len,
			(uint32_t)RDMA_PORT_MAX_MSG_SZ);
		return RDMA_RESPST_ERR_LENGTH;
	}

	if (rdma_read_prep_for_pts(qp, pinfo, &npkts) < 0) {
		dao_err("Failed to prepare RDMA read for PTS.");
		qp->resp.wqe.mbuf = NULL;
		qp->resp.wqe.tail = NULL;
		return RDMA_RESPST_ERR_RNR;
	}

#ifdef RDMA_DEBUG
	dao_dbg("[RESP-READ] QP %d READ PSN %u: DMA queued, npkts %u", qp->qid, pinfo->rinfo.psn,
		npkts);
#endif

	qp->resp.msn++;
	qp->resp.opcode = -1;
	qp->resp.status = RDMA_WC_SUCCESS;

	qp->resp.psn = (pinfo->rinfo.psn + npkts) & BTH_PSN_MASK;
	qp->resp.ack_psn = qp->resp.psn;

	rdma_update_ack_pending_list(qp, pinfo->mbuf, pinfo->rinfo.psn, AETH_ACK_UNLIMITED, true);

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
		if (!(rinfo->mask & RDMA_END_MASK))
			rdma_save_mbuf(qp, pinfo);
		else
			rdma_update_write_final_mbuf(qp, pinfo);
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
	RTE_SET_USED(pkt);

	qp->resp.wqe.mbuf = NULL;
	qp->resp.wqe.tail = NULL;
	qp->resp.opcode = -1;

	if (unlikely(qp->state == QP_STATE_ERROR)) {
		dao_err("QP %d is in error state, cannot complete request.", qp->qid);
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
	struct rte_mbuf *mbuf;

	RTE_SET_USED(msg);

	mbuf = prepare_ack_packet(qp, opcode, 0, pinfo->rinfo.psn, syndrome, pinfo->mbuf->pool);
	if (!mbuf)
		return -ENOMEM;

	mbuf->port = pinfo->mbuf->port;
	mbuf->hash.fdir.hi = pinfo->rx_queue;

	if (rdma_update_ack_pending_list(qp, mbuf, pinfo->rinfo.psn, syndrome, false) < 0) {
		dao_err("Failed to update ACK pending list.");
		rte_pktmbuf_free(mbuf);
		return -ENOMEM;
	}

	return 0;
}

static resp_states_t
acknowledge(struct rdma_qp *qp, struct pkt_info *pinfo)
{
	if (qp->type != RDMA_QPT_RC)
		return RDMA_RESPST_CLEANUP;

	if (qp->resp.aeth_syndrome != AETH_ACK_UNLIMITED)
		send_ack(qp, qp->resp.aeth_syndrome, pinfo, RDMA_OPCODE_RC_ACKNOWLEDGE, "ACK");
	else if (bth_ack(&pinfo->rinfo))
		send_ack(qp, AETH_ACK_UNLIMITED, pinfo, RDMA_OPCODE_RC_ACKNOWLEDGE, "ACK");

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

#ifdef RDMA_DEBUG
	dao_dbg("[RESP] expected PSN %u and acked psn %u, npkts %u",
		((psn + npkts - 1) & BTH_PSN_MASK), ((qp->resp.ack_psn - 1) & BTH_PSN_MASK), npkts);
#endif
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
	struct rte_mbuf *mbuf;

	mbuf = prepare_ack_packet(qp, opcode, 0, psn, syndrome, pinfo->mbuf->pool);
	if (!mbuf || pinfo->mbuf->port >= RTE_MAX_ETHPORTS)
		return -ENOMEM;

	if (rte_eth_tx_burst(pinfo->mbuf->port, pinfo->rx_queue, &mbuf, 1) != 1) {
		dao_info("Failed to transmit ACK packet.");
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

		/* Check if request is in ack pending list */
		old_mbuf = rdma_ack_pending_list_remove_by_psn(qp, pkt->rinfo.psn);
		if (old_mbuf) {
			qp->resp.resp_read_rq_bal++;
#ifdef RDMA_DEBUG
			dao_dbg("Duplicate READ PSN %u: replacing old mbuf %p with new %p",
				pkt->rinfo.psn, old_mbuf, pkt->mbuf);
#endif
			requeue_dma = true;
		} else if (rdma_is_last_acked_request(qp, pkt->rinfo.psn, pkt) &&
			   rdma_read_rkey_validate(qp, pkt)) {
			/* Last read reply lost - reread and retransmit */
			requeue_dma = true;
		}

		if (requeue_dma) {
			rdma_read_prep_for_pts(qp, pkt, &npkts);
			rdma_update_ack_pending_list(qp, pkt->mbuf, pkt->rinfo.psn,
						     AETH_ACK_UNLIMITED, true);
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
	resp_states_t state;

#ifdef RDMA_DEBUG
	dao_dbg("[RESP] RESP QP ID %d PSN %u\n", qp->qid, pinfo->rinfo.psn);
#endif

	if (!qp->valid)
		goto exit;

	qp->resp.aeth_syndrome = AETH_ACK_UNLIMITED;

	switch (qp->state) {
	case QP_STATE_RESET:
		state = RDMA_RESPST_RESET;
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
			dao_err("Class C error: opcode %d, syndrome %d qp->resp.opcode %d pkt ocode %d",
				state, qp->resp.aeth_syndrome, qp->resp.opcode,
				pinfo->rinfo.opcode);
			state = RDMA_RESPST_COMPLETE;
			break;
		case RDMA_RESPST_ERR_RNR:
			dao_err("Class C error: opcode %d, syndrome %d qp->resp.opcode %d pkt ocode %d",
				state, qp->resp.aeth_syndrome, qp->resp.opcode,
				pinfo->rinfo.opcode);
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
			state = RDMA_RESPST_ERROR;
			break;
		case RDMA_RESPST_DONE:
			if (qp->resp.goto_error) {
				state = RDMA_RESPST_ERROR;
				break;
			}
			goto done;
		case RDMA_RESPST_EXIT:
			goto exit;
		case RDMA_RESPST_RESET:
			qp->resp.wqe.mbuf = NULL;
			qp->resp.wqe.tail = NULL;
			goto exit;
		case RDMA_RESPST_ERROR:
			qp->resp.goto_error = 0;
			dao_err("QP %d: setting state to ERROR (responder)", qp->qid);
			qp->state = QP_STATE_ERROR;
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
	}

	return n;
}
