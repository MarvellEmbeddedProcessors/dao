/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <dao_log.h>
#include <rte_ethdev.h>

#include "rdma_net.h"
#include "rdma_priv.h"
#include "rdma_qp.h"
#include "rdma_req.h"
#include "rdma_retransmit.h"
#include "rdma_utils.h"

static int
next_opcode_rc(struct rdma_qp *qp, uint32_t opcode, bool no_segs)
{
	switch (opcode) {
	case RDMA_WR_RDMA_WRITE:
		if (qp->req.opcode == RDMA_OPCODE_RC_RDMA_WRITE_FIRST ||
		    qp->req.opcode == RDMA_OPCODE_RC_RDMA_WRITE_MIDDLE)
			return no_segs ? RDMA_OPCODE_RC_RDMA_WRITE_LAST :
					 RDMA_OPCODE_RC_RDMA_WRITE_MIDDLE;
		else
			return no_segs ? RDMA_OPCODE_RC_RDMA_WRITE_ONLY :
					 RDMA_OPCODE_RC_RDMA_WRITE_FIRST;

	case RDMA_WR_WRITE_WITH_IMM:
		if (qp->req.opcode == RDMA_OPCODE_RC_RDMA_WRITE_FIRST ||
		    qp->req.opcode == RDMA_OPCODE_RC_RDMA_WRITE_MIDDLE)
			return no_segs ? RDMA_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE :
					 RDMA_OPCODE_RC_RDMA_WRITE_MIDDLE;
		else
			return no_segs ? RDMA_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE :
					 RDMA_OPCODE_RC_RDMA_WRITE_FIRST;

	case RDMA_WR_SEND:
		if (qp->req.opcode == RDMA_OPCODE_RC_SEND_FIRST ||
		    qp->req.opcode == RDMA_OPCODE_RC_SEND_MIDDLE)
			return no_segs ? RDMA_OPCODE_RC_SEND_LAST : RDMA_OPCODE_RC_SEND_MIDDLE;
		else
			return no_segs ? RDMA_OPCODE_RC_SEND_ONLY : RDMA_OPCODE_RC_SEND_FIRST;

	case RDMA_WR_SEND_WITH_IMM:
		if (qp->req.opcode == RDMA_OPCODE_RC_SEND_FIRST ||
		    qp->req.opcode == RDMA_OPCODE_RC_SEND_MIDDLE)
			return no_segs ? RDMA_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE :
					 RDMA_OPCODE_RC_SEND_MIDDLE;
		else
			return no_segs ? RDMA_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE :
					 RDMA_OPCODE_RC_SEND_FIRST;

	case RDMA_WR_RDMA_READ:
		return RDMA_OPCODE_RC_RDMA_READ_REQUEST;

	case RDMA_WR_ATOMIC_CMP_AND_SWP:
		return RDMA_OPCODE_RC_COMPARE_SWAP;

	case RDMA_WR_ATOMIC_FETCH_AND_ADD:
		return RDMA_OPCODE_RC_FETCH_ADD;

	case RDMA_WR_SEND_WITH_INV:
		if (qp->req.opcode == RDMA_OPCODE_RC_SEND_FIRST ||
		    qp->req.opcode == RDMA_OPCODE_RC_SEND_MIDDLE)
			return no_segs ? RDMA_OPCODE_RC_SEND_LAST_WITH_INVALIDATE :
					 RDMA_OPCODE_RC_SEND_MIDDLE;
		else
			return no_segs ? RDMA_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE :
					 RDMA_OPCODE_RC_SEND_FIRST;

	case RDMA_WR_REG_MR:
	case RDMA_WR_LOCAL_INV:
		return opcode;
	}

	return -EINVAL;
}

static int
next_opcode(struct rdma_qp *qp, uint32_t opcode, bool more_segs)
{
	switch (qp->type) {
	case RDMA_QPT_RC:
		return next_opcode_rc(qp, opcode, !more_segs);

	case RDMA_QPT_UD:
	case RDMA_QPT_GSI:
		switch (opcode) {
		case 2:
			return RDMA_OPCODE_UD_SEND_ONLY;

		case 3:
			return RDMA_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE;
		}
		break;

	default:
		break;
	}

	return -EINVAL;
}

static inline int
get_mtu(struct rdma_qp *qp, uint16_t eth_port)
{
	uint16_t mtu;

	if ((qp->type == RDMA_QPT_RC) || (qp->type == RDMA_QPT_UC))
		return qp->mtu;

	rte_eth_dev_get_mtu(eth_port, &mtu);
	return mtu;
}

static struct rdma_av *
rdma_get_av(struct rdma_pkt_info *pinfo)
{
	struct rdma_send_wqe *wqe = (struct rdma_send_wqe *)pinfo->wqe;
	struct rdma_qp *qp = (struct rdma_qp *)pinfo->qp;

	if (!pinfo || !pinfo->qp)
		return NULL;

	if (qp->type == RDMA_QPT_RC)
		return &qp->av;

	if (!pinfo->wqe)
		return NULL;
#ifdef RDMA_DEBUG
	dao_info("wqe->wr->ud.ah: %u\n", wqe->wr->ud.ah);
#endif
	return (struct rdma_av *)rdma_av_get(pinfo->port_num, wqe->wr->ud.ah);
}

static int
rdma_proto_hdr_insert(struct rte_mbuf *pkt, struct rdma_pkt_info *pinfo, uint32_t payload)
{
	struct rdma_send_wqe *wqe = pinfo->wqe;
	struct rdma_send_wr *wr = wqe->wr;
	int pad_len = (-pkt->pkt_len) & 0x3;
	struct rdma_qp *qp;
	uint32_t dqp_num;
	int ack_req = 0;
	int solicited;

	qp = pinfo->qp;
	/* length from start of bth to end of icrc */
	pinfo->paylen = rdma_opcode[pinfo->opcode].length + payload + pad_len + RDMA_ICRC_SIZE;
	pinfo->port_num = qp->port_id;
	pinfo->mask |= RDMA_GRH_MASK;

	solicited = (wr->send_flags & RDMA_SEND_SOLICITED) && (pinfo->mask & RDMA_END_MASK) &&
		    ((pinfo->mask & (RDMA_SEND_MASK)) ||
		     (pinfo->mask & (RDMA_WRITE_MASK | RDMA_IMMDT_MASK)) ==
			     (RDMA_WRITE_MASK | RDMA_IMMDT_MASK));

	dqp_num = (pinfo->mask & RDMA_DETH_MASK) ? wr->ud.remote_qpn : qp->dest_qp_num;
	pinfo->hdr = (void *)rte_pktmbuf_prepend(pkt, rdma_opcode[pinfo->opcode].length);
	if (pinfo->hdr == NULL)
		return -1;

	if (qp->type != RDMA_QPT_UD && qp->type != RDMA_QPT_UC)
		ack_req = ((pinfo->mask & RDMA_END_MASK) ||
			   (qp->req.no_ack_pkts++ > RDMA_MAX_PKT_PER_ACK));
	if (ack_req)
		qp->req.no_ack_pkts = 0;

	/* XXX: Migration bit is set to 0. In-future we will have to take from the wqe. */
	bth_init(pinfo, solicited, 0, pad_len, BTH_DEF_PKEY, dqp_num, ack_req, pinfo->psn);
	if (bth_pad(pinfo)) {
		uint8_t *pad = (void *)rte_pktmbuf_append(pkt, pad_len);

		memset(pad, 0, pad_len);
	}

	if (pinfo->mask & RDMA_DETH_MASK) {
		if (qp->type == RDMA_QPT_GSI)
			deth_set_qkey(pinfo, GSI_QKEY);
		else
			deth_set_qkey(pinfo, wr->ud.qkey);
		deth_set_sqp(pinfo, qp->qid);
	}

	if (pinfo->mask & RDMA_RETH_MASK) {
		reth_set_rkey(pinfo, wr->rdma.rkey);
		reth_set_va(pinfo, wr->rdma.remote_addr);
		reth_set_len(pinfo, wqe->dma_length);
	}

	if (pinfo->mask & RDMA_IMMDT_MASK)
		immdt_set_imm(pinfo, wr->imm_data);

	return 0;
}

static int
rdma_hdr_insert(struct rte_mbuf *pkt, struct rdma_av *av, uint32_t payload,
		struct rdma_pkt_info *pinfo)
{
	struct rdma_qp *qp;
	int ret = -1;

	RTE_SET_USED(payload);

	rdma_mbuf_init(pkt);

	/* RDMA specific headers and payload */
	ret = rdma_proto_hdr_insert(pkt, pinfo, payload);
	if (ret < 0) {
		dao_err("ERROR: RDMA proto header error\n");
		return ret;
	}

	qp = pinfo->qp;

	ret = rdma_net_hdr_insert(pkt, av, qp->sport);
	if (ret < 0) {
		dao_err("ERROR: offset error\n");
		return ret;
	}

	/* Packet formation is done. Time to calculate icrc. */
	if (rdma_icrc_generate(pkt, pinfo))
		return -1;

	return ret;
}

static void
update_wqe_state(struct rdma_qp *qp, struct rdma_send_wqe *wqe, struct rdma_pkt_info *pinfo)
{
	if (pinfo->mask & RDMA_END_MASK) {
		if (qp->type == RDMA_QPT_RC)
			wqe->state = wqe_state_pending;
		else
			wqe->state = wqe_state_done;
	} else {
		wqe->state = wqe_state_processing;
	}
}

static void
update_wqe_psn(struct rdma_qp *qp, struct rdma_send_wqe *wqe, struct rdma_pkt_info *pinfo,
	       uint32_t num_pkt)
{
	if (pinfo->mask & RDMA_START_MASK) {
		wqe->first_psn = qp->req.psn;
		wqe->last_psn = (qp->req.psn + num_pkt - 1) & BTH_PSN_MASK;
#ifdef RDMA_DEBUG
		dao_dbg("[SEND] wqe->first_psn %u wqe->last_psn %u\n", wqe->first_psn,
			wqe->last_psn);
#endif
	}

	if (pinfo->mask & RDMA_READ_MASK)
		qp->req.psn = (wqe->first_psn + num_pkt) & BTH_PSN_MASK;
	else
		qp->req.psn = (qp->req.psn + 1) & BTH_PSN_MASK;
	qp->req.unacked_window = RDMA_MAX_UNACKED_PSNS - (int32_t)(qp->req.psn - qp->comp.psn);
}

static void
update_state(struct rdma_qp *qp)
{
	if (!rte_timer_pending(&qp->timer_data->retrans_timer) && qp->req.timeout_cycles) {
		qp->timer_data->timer_type |= RDMA_RETRNS_TIMER;
		rte_timer_reset(&qp->timer_data->retrans_timer, qp->req.timeout_cycles, SINGLE,
				rte_lcore_id(), rdma_timeout_handler_cb, qp->timer_data);
	}
}

static inline int
rdma_wqe_is_fenced(struct rdma_qp *qp, struct rdma_send_wqe *wqe)
{
	/* IBA 10.6.5.1 Requires ALL previous operations on the send queue are
	 * complete.
	 */
	if (wqe->wr->opcode == RDMA_WR_LOCAL_INV)
		return qp->req.cur_wqe != STAILQ_FIRST(&qp->req.wqe_head);

	/* Fence see IBA 10.8.3.3 Requires that all previous read
	 * operations are complete.
	 */
	return (wqe->wr->send_flags & RDMA_SEND_FENCE) &&
	       qp->req.read_rq_bal != qp->attr.max_read_rq_cnt;

	return 0;
}

static int
rdma_do_local_ops(struct rdma_qp *qp, struct rdma_send_wqe *wqe)
{
	struct rdma_send_wr *wr = wqe->wr;
	int ret = 0;

	switch (wr->opcode) {
	case RDMA_WR_LOCAL_INV:
		/* XXX: Need to implement */
		break;

	case RDMA_WR_REG_MR:
		/* XXX: Need to implement */
		break;

	case RDMA_WR_BIND_MW:
		/* XXX: Need to implement */
		break;

	default:
		ret = -EINVAL;
		break;
	}

	wqe->state = wqe_state_done;
	wqe->status = RDMA_WC_SUCCESS;
	qp->req.cur_wqe = wqe;

	return ret;
}

static inline int
check_init_depth(struct rdma_qp *qp, struct rdma_send_wqe *wqe)
{
	int depth;

	if (wqe->has_read_req)
		return 0;

	qp->req.need_rd_credit = 1;
	depth = qp->req.read_rq_bal - 1;

	if (depth >= 0) {
		qp->req.need_rd_credit = 0;
		wqe->has_read_req = 1;
		qp->req.read_rq_bal = depth;
		return 0;
	}

	return -EAGAIN;
}

int
rdma_requester(struct rdma_qp *qp, struct rdma_send_wqe *wqe, struct rte_mbuf *mbuf, bool more_segs,
	       int num_pkt)
{
	struct rdma_pkt_info pinfo;
	enum rdma_hdr_mask mask;
	struct rdma_av *av;
	uint32_t payload;
	uint32_t mtu;
	int opcode;
	int ret = -1;

	if (unlikely(!qp->valid)) {
		dao_err("[%s::%d] QP not valid\n", __func__, __LINE__);
		goto exit;
	}

	if (unlikely(qp->state == QP_STATE_ERROR)) {
		wqe->status = RDMA_WC_WR_FLUSH_ERR;
		dao_err("[%s::%d] QP in error state\n", __func__, __LINE__);
		goto err;
	}

	if (unlikely(qp->state == QP_STATE_RESET)) {
		dao_err("[%s::%d] QP in RESET state\n", __func__, __LINE__);
		qp->req.opcode = -1;
		qp->req.stop_psn = 0;
		qp->req.wait_rnr_exp = 0;
		goto exit;
	}

	if (rdma_wqe_is_fenced(qp, wqe)) {
		dao_err("[%s::%d] WQE is fenced\n", __func__, __LINE__);
		qp->req.wait_fence = 1;
		goto exit;
	}

	if (wqe->mask & WR_LOCAL_OP_MASK) {
		ret = rdma_do_local_ops(qp, wqe);
		if (unlikely(ret))
			goto err;
		else
			goto done;
	}

	opcode = next_opcode(qp, wqe->wr->opcode, more_segs);
	if (unlikely(opcode < 0)) {
		dao_err("[%s::%d] opcode error %d vs wqe->wr->opcode %d QP type %d\n", __func__,
			__LINE__, opcode, wqe->wr->opcode, qp->type);
		wqe->status = RDMA_WC_LOC_QP_OP_ERR;
		goto err;
	}

	mtu = get_mtu(qp, mbuf->port);
	mask = rdma_opcode[opcode].mask;
	if (unlikely(mask & (RDMA_READ_MASK))) {
		if (check_init_depth(qp, wqe)) {
			dao_err("[%s::%d] read rq depth error\n", __func__, __LINE__);
			goto exit;
		}
	}

	payload = (mask & RDMA_WRITE_OR_SEND_MASK) ? mbuf->pkt_len : 0;
	if (payload > mtu) {
		if (qp->type == RDMA_QPT_UD) {
			/* C10-93.1.1: If the total sum of all the buffer lengths specified for a
			 * UD message exceeds the MTU of the port as returned by QueryHCA, the CI
			 * shall not emit any packets for this message. Further, the CI shall not
			 * generate an error due to this condition.
			 */

			/* fake a successful UD send */
			struct dao_pts_rdma_cqe cqe = {0};

			wqe->first_psn = qp->req.psn;
			wqe->last_psn = qp->req.psn;
			qp->req.psn = (qp->req.psn + 1) & BTH_PSN_MASK;
			qp->req.opcode = RDMA_OPCODE_UD_SEND_ONLY;
			wqe->state = wqe_state_done;
			wqe->status = RDMA_WC_SUCCESS;
			qp->req.cur_wqe = wqe;
			rdma_make_send_cqe(qp, wqe, &cqe);
			dao_pts_rdma_enqueue_cqe(qp->port_id, qp->qid, false, &cqe, 1);
			dao_err("[%s::%d] payload error\n", __func__, __LINE__);
			goto done;
		} else {
			dao_err("[%s::%d] pkt_len %d data_len %u exceeds mtu %d nb_segs %u qp id %d mbuf refcnt %u"
				" nb_pkts %u\n",
				__func__, __LINE__, mbuf->pkt_len, mbuf->data_len, mtu,
				mbuf->nb_segs, qp->qid, mbuf->refcnt, num_pkt);
			goto exit;
		}
	}

	pinfo.opcode = opcode;
	qp->req.opcode = opcode;
	pinfo.qp = qp;
	pinfo.psn = qp->req.psn;
	pinfo.mask = mask;
	pinfo.wqe = wqe;
	pinfo.port_num = qp->port_id;

	av = rdma_get_av(&pinfo);
	if (unlikely(av == NULL)) {
		dao_err("[%s::%d] av error\n", __func__, __LINE__);
		wqe->status = RDMA_WC_LOC_QP_OP_ERR;
		goto err;
	}

	ret = rdma_hdr_insert(mbuf, av, payload, &pinfo);
	if (unlikely(ret)) {
		dao_err("[%s::%d] hdr insert error\n", __func__, __LINE__);
		wqe->status = RDMA_WC_LOC_QP_OP_ERR;
		goto exit;
	}

	/* update wqe state as though we had sent it */
	update_wqe_state(qp, wqe, &pinfo);
	update_wqe_psn(qp, wqe, &pinfo, num_pkt);
	update_state(qp);

done:
	ret = 0;
	goto out;
err:
	/* update wqe_index for each wqe completion */
	wqe->state = wqe_state_error;
	qp->state = QP_STATE_ERROR;
exit:
	ret = -EAGAIN;
out:
	return ret;
}
