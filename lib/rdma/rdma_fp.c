/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <arpa/inet.h>
#include <rte_dmadev.h>
#include <stdio.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <dao_dma.h>
#include <dao_log.h>

#include "dao_pts_rdma_dev.h"
#include "dao_rdma_fp.h"
#include "rdma_common.h"
#include "rdma_comp.h"
#include "rdma_cq.h"
#include "rdma_hdr.h"
#include "rdma_opcode.h"
#include "rdma_qp.h"
#include "rdma_req.h"
#include "rdma_resp.h"
#include "rdma_retransmit.h"
#include "rdma_utils.h"

rcu_cb_t rcu_cb;
struct rdma_wr_opcode_info rdma_wr_opcode_info[] = {
	[RDMA_WR_RDMA_WRITE] = {
		.name = "RDMA_WR_RDMA_WRITE",
		.mask = {
			[RDMA_QPT_RC] = WR_WRITE_MASK,
			[RDMA_QPT_UC] = WR_WRITE_MASK,
		},
	},
	[RDMA_WR_WRITE_WITH_IMM] = {
		.name = "RDMA_WR_WRITE_WITH_IMM",
		.mask = {
			[RDMA_QPT_RC] = WR_WRITE_MASK,
			[RDMA_QPT_UC] = WR_WRITE_MASK,
		},
	},
	[RDMA_WR_SEND] = {
		.name = "RDMA_WR_SEND",
		.mask = {
			[RDMA_QPT_GSI] = WR_SEND_MASK,
			[RDMA_QPT_RC] = WR_SEND_MASK,
			[RDMA_QPT_UC] = WR_SEND_MASK,
			[RDMA_QPT_UD] = WR_SEND_MASK,
		},
	},
	[RDMA_WR_SEND_WITH_IMM] = {
		.name = "RDMA_WR_SEND_WITH_IMM",
		.mask = {
			[RDMA_QPT_GSI] = WR_SEND_MASK,
			[RDMA_QPT_RC] = WR_SEND_MASK,
			[RDMA_QPT_UC] = WR_SEND_MASK,
			[RDMA_QPT_UD] = WR_SEND_MASK,
		},
	},
	[RDMA_WR_RDMA_READ] = {
		.name = "RDMA_WR_RDMA_READ",
		.mask = {
			[RDMA_QPT_RC] = WR_READ_MASK,
		},
	},
	[RDMA_WR_SEND_WITH_INV] = {
		.name = "RDMA_WR_SEND_WITH_INV",
		.mask = {
			[RDMA_QPT_RC] = WR_SEND_MASK,
			[RDMA_QPT_UC] = WR_SEND_MASK,
			[RDMA_QPT_UD] = WR_SEND_MASK,
		},
	},
	[RDMA_WR_RDMA_READ_WITH_INV] = {
		.name = "RDMA_WR_RDMA_READ_WITH_INV",
		.mask = {
			[RDMA_QPT_RC] = WR_READ_MASK,
		},
	},
	[RDMA_WR_LOCAL_INV] = {
		.name = "RDMA_WR_LOCAL_INV",
		.mask = {
			[RDMA_QPT_RC] = WR_LOCAL_OP_MASK,
		},
	},
	[RDMA_WR_REG_MR] = {
		.name = "RDMA_WR_REG_MR",
		.mask = {
			[RDMA_QPT_RC] = WR_LOCAL_OP_MASK,
		},
	},
	[RDMA_WR_BIND_MW] = {
		.name = "RDMA_WR_BIND_MW",
		.mask = {
			[RDMA_QPT_RC] = WR_LOCAL_OP_MASK,
			[RDMA_QPT_UC] = WR_LOCAL_OP_MASK,
		},
	},
	[RDMA_WR_FLUSH] = {
		.name = "RDMA_WR_FLUSH",
		.mask = {
			[RDMA_QPT_RC] = WR_FLUSH_MASK,
		},
	},
};

int
dao_rdma_rx_process(struct rte_mbuf **mbuf_p, uint16_t rx_queue, uint32_t *qpn, int devid)
{
	struct pkt_info pinfo = {0};
	struct rte_mbuf *mbuf = *mbuf_p;

	rdma_pkt_extract(mbuf, &pinfo, rx_queue, devid);
	*qpn = bth_qpn(&pinfo.rinfo);

	if (rdma_hdr_check(&pinfo)) {
		dao_err("RX: header check failed\n");
		return -1;
	}

	if (rdma_icrc_check(mbuf, &pinfo)) {
		dao_err("RX: icrc check failed\n");
		return -1;
	}

	/* Simple CC: detect CNP opcode early and apply backoff, then drop */
	if (pinfo.rinfo.opcode == RDMA_OPCODE_CNP) {
		struct rdma_qp *qp = (struct rdma_qp *)pinfo.rinfo.qp; /* set in hdr_check */

		if (qp && qp->cc.cc_enabled) {
			uint64_t now = rte_get_tsc_cycles();

			qp->cc.cnp_rx_cnt++;
			qp->cc.last_cnp_rx_cycles = now;
			/* Exponential backoff of pacing interval within bounds */
			if (qp->cc.pacing_interval_cycles == 0)
				qp->cc.pacing_interval_cycles = qp->cc.min_pacing_cycles;
			else
				qp->cc.pacing_interval_cycles =
					RTE_MIN(qp->cc.pacing_interval_cycles * 2,
						qp->cc.max_pacing_cycles);
		}
		/* CNP carries no further processing */
		return RDMA_COMPLETION_DONE;
	}

	/* ECN CE detection (IPv4 only for now): increment counter & possibly send CNP */
	if ((pinfo.ptype & RTE_PTYPE_L3_IPV4) && (pinfo.rinfo.mask & RDMA_REQ_MASK)) {
		struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr *)pinfo.iph;

		if ((iph->type_of_service & 0x03) == 0x03) { /* CE */
			struct rdma_qp *qp =
				(struct rdma_qp *)pinfo.rinfo.qp; /* Valid after hdr_check */
			if (qp && qp->cc.cc_enabled) {
				qp->cc.ecn_ce_marks++;
				/* Generate CNP if allowed */
				rdma_send_cnp(qp, mbuf);
			}
		}
	}

	int result = 0;

	if (pinfo.rinfo.mask & RDMA_REQ_MASK) {
		if (rdma_responder(&pinfo)) {
			dao_err("RX: responder failed\n");
			return -1;
		}
		result = RDMA_RESPONDER_DONE;
	} else {
		if (rdma_process_ack(&pinfo)) {
			dao_err("RX: process ack failed\n");
			return -1;
		}
		result = RDMA_COMPLETION_DONE;
	}

	if (pinfo.mbuf_flags == RDMA_RESPONDER_MBUF_UPDATED)
		*mbuf_p = pinfo.mbuf;

	return pinfo.mbuf_flags ? pinfo.mbuf_flags : result;
}

static inline int
rdma_requester_error(struct rdma_qp *qp, struct rdma_send_wqe *wqe)
{
	/* Free'd in main loop */
	int first_skip = 1;
	struct rdma_mbufs *rmbuf = NULL, *rmbuf_next = NULL;

	wqe->status = RDMA_WC_LOC_QP_OP_ERR;
	dao_send_cqe(qp, false, wqe);
	STAILQ_REMOVE(&qp->req.wqe_head, wqe, rdma_send_wqe, next);
	STAILQ_FOREACH_SAFE(rmbuf, &wqe->mbuf_list, next, rmbuf_next)
	{
		if (!first_skip)
			rte_pktmbuf_free(rmbuf->mbuf);
		rte_pktmbuf_free(rmbuf->mbuf);
		STAILQ_REMOVE(&wqe->mbuf_list, rmbuf, rdma_mbufs, next);
		first_skip = 0;
	}
	return 0;
}

static inline int
rdma_requester_error2(struct rdma_qp *qp, struct rdma_send_wqe *wqe)
{
	int first_skip = 1;
	struct rdma_mbufs *rmbuf = NULL, *rmbuf_next = NULL;

	wqe->status = RDMA_WC_LOC_QP_OP_ERR;
	dao_send_cqe(qp, false, wqe);
	STAILQ_REMOVE(&qp->req.wqe_head, wqe, rdma_send_wqe, next);
	STAILQ_FOREACH_SAFE(rmbuf, &wqe->mbuf_list, next, rmbuf_next)
	{
		if (!first_skip)
			rte_pktmbuf_free(rmbuf->mbuf);
		rte_pktmbuf_free(rmbuf->mbuf);
		STAILQ_REMOVE(&wqe->mbuf_list, rmbuf, rdma_mbufs, next);
		first_skip = 0;
	}
	return 0;
}

static inline int
dao_rdma_process_remaining_segs(struct rdma_qp *qp, struct rte_mbuf **mbufs, uint16_t *n_mbufs)
{
	int ret;
	bool m_segs;
	struct rdma_mbufs *next_r = NULL;
	struct rdma_mbufs *rmbuf = NULL;
	struct rdma_send_wqe *wqe = qp->req.cur_wqe;

	if (wqe == NULL) {
		dao_err("[%s::%d] WQE list is empty\n", __func__, __LINE__);
		return -1;
	}
	rmbuf = qp->req.cur_mbuf;
	while (rmbuf) {
		m_segs = wqe->n_rdma_segs > 1 ? true : false;
		next_r = STAILQ_NEXT(rmbuf, next);
		if (next_r)
			rte_prefetch0(rte_pktmbuf_mtod(next_r->mbuf, void *));
		ret = rdma_requester(qp, wqe, rmbuf->mbuf, m_segs, 0);
		if (ret < 0) {
			rdma_requester_error2(qp, wqe);
			*n_mbufs = 0;
			dao_err("[%s::%d] rdma RC requester error\n", __func__, __LINE__);
			rte_mbuf_refcnt_update(qp->req.dummy_mbuf, 1);
			return -1;
		} else if (ret == RDMA_REQUESTER_POSTPONED_RC) {
			qp->req.cur_mbuf = rmbuf;
			break;
		}
		wqe->n_rdma_segs--;
		mbufs[*n_mbufs] = rmbuf->mbuf;
		rmbuf = next_r;
		qp->req.cur_mbuf = rmbuf;
		(*n_mbufs)++;
		if (RDMA_MAX_ENQ_BURST <= *n_mbufs)
			break;
	}

#ifdef RDMA_DEBUG
	dao_dbg("[%s::%d] qp id %d Processed remaining segs, n_mbufs %u wqe->state %d "
		"wqe->n_rdma_segs %d qp->req.unacked_window %d cur psn %d\n",
		__func__, __LINE__, qp->qid, *n_mbufs, wqe->state, wqe->n_rdma_segs,
		qp->req.unacked_window, qp->req.psn);
#endif

	return 0;
}

static inline int
rdma_process_rc_packets(struct rdma_qp *qp, struct rte_mbuf *mbuf, struct rte_mbuf **mbufs,
			uint16_t *n_mbufs)
{
	int ret;
	int nb = 1;
	bool m_segs;
	struct rdma_mbufs *next_r = NULL;
	struct rdma_mbufs *rmbuf = NULL;
	struct rdma_send_wqe *wqe = qp->req.cur_wqe;

	if (wqe && wqe->state == wqe_state_processing)
		return dao_rdma_process_remaining_segs(qp, mbufs, n_mbufs);

	/* Handle scheduled trigger for remaining requester segments */
	if (mbuf == qp->req.dummy_mbuf)
		return 0;

	qp->req.opcode = -1;
	ret = dao_rdma_preprocess_dequeued_pkts(qp, mbuf);
	if (ret < 0) {
		dao_err("[%s::%d] rdma preprocess error\n", __func__, __LINE__);
		return -1;
	}
	if (qp->resp.read_reply.n_rdma_segs) {
		ret = rdma_process_read_reply(qp, mbuf, mbufs, n_mbufs);
		if (ret < 0) {
			dao_err("[%s::%d] rdma process read reply error\n", __func__, __LINE__);
			return -1;
		}
		return 0;
	}

	wqe = qp->req.cur_wqe ? STAILQ_NEXT(qp->req.cur_wqe, next) :
				STAILQ_FIRST(&qp->req.wqe_head);
	if (wqe == NULL) {
		dao_err("[%s::%d] WQE list is empty\n", __func__, __LINE__);
		return -1;
	}

	nb = wqe->dma_length / qp->mtu + ((wqe->dma_length % qp->mtu) ? 1 : 0);

	rmbuf = STAILQ_FIRST(&wqe->mbuf_list);
	while (rmbuf) {
		m_segs = wqe->n_rdma_segs > 1 ? true : false;
		next_r = STAILQ_NEXT(rmbuf, next);
		if (next_r)
			rte_prefetch0(rte_pktmbuf_mtod(next_r->mbuf, void *));
		ret = rdma_requester(qp, wqe, rmbuf->mbuf, m_segs, nb);
		if (ret < 0) {
			rdma_requester_error(qp, wqe);
			*n_mbufs = 0;
			dao_err("[%s::%d] rdma RC requester error\n", __func__, __LINE__);
			return -1;
		} else if (ret == RDMA_REQUESTER_POSTPONED_RC) {
			qp->req.cur_mbuf = next_r;
			break;
		}
		wqe->n_rdma_segs--;
		mbufs[*n_mbufs] = rmbuf->mbuf;
		(*n_mbufs)++;
		qp->req.cur_mbuf = next_r;
		if (RDMA_MAX_ENQ_BURST <= *n_mbufs)
			break;
		rmbuf = next_r;
	}

#ifdef RDMA_DEBUG
	dao_dbg("[REQ] qp_id %d, dma_len %u, current nb_segs %d, total segs %d, "
		"start psn %u end psn %u current qp psn %u qp->req.unacked_window %d\n",
		qp->qid, wqe->dma_length, *n_mbufs, wqe->n_rdma_segs + *n_mbufs, wqe->first_psn,
		wqe->last_psn, qp->req.psn, qp->req.unacked_window);
#endif
	qp->req.cur_wqe = wqe;

	return 0;
}

int
dao_rdma_tx_process(struct rte_mbuf *mbuf, uint32_t qp_id, int devid, struct rte_mbuf **mbufs,
		    uint16_t *n_mbufs)
{
	int ret;
	bool flag = false;
	uint32_t nb = 1;
	struct rdma_qp *qp = NULL;
	struct rdma_send_wqe wqe = {0};

	qp = rdma_qp_query_fast(qp_id, devid);
	if (qp == NULL || qp->state == QP_STATE_ERROR) {
		dao_err("qp error: qp_id %d qp %p state %d", qp_id, qp, qp ? (int)qp->state : -1);
		return -1;
	}

	if (qp->lcore != rte_lcore_id()) {
		dao_err("QP %d on port %d is not owned by lcore %d", qp_id, devid, rte_lcore_id());
		return -1;
	}

	if (qp->type == RDMA_QPT_RC) {
		if (!qp->req.dummy_mbuf)
			qp->req.dummy_mbuf = rte_pktmbuf_alloc(mbuf->pool);
		ret = rdma_process_rc_packets(qp, mbuf, mbufs, n_mbufs);
		if (ret < 0) {
			dao_err("[%s::%d] rdma RC process error\n", __func__, __LINE__);
			goto error;
		}
		qp->req.dummy_mbuf->port = RTE_MAX_ETHPORTS + devid;
	} else {
		qp->req.opcode = -1;
		wqe.wr = rdma_tx_priv_wr(mbuf);
		ret = rdma_requester(qp, &wqe, mbuf, flag, nb);
		if (ret < 0) {
			dao_err("[%s::%d] rdma UD requester error\n", __func__, __LINE__);
			goto error;
		}
#ifdef RDMA_DEBUG
		dao_dbg("[REQ] qp_id %d, pktlen %u, qp->req.psn %u\n", qp->qid, mbuf->pkt_len,
			qp->req.psn);
#endif
		dao_send_cqe(qp, false, &wqe);
	}
	return 0;

error:
	mbuf->ol_flags &= ~(0x7ULL << OFFLD_UPPER_BITS);
	return -1;
}

int
dao_send_cqe(struct rdma_qp *qp, bool host_recv, struct rdma_send_wqe *wqe)
{
	struct dao_pts_rdma_cqe cqe = {0};
	bool post = false;
	int rc;

	if (unlikely(!qp || !wqe))
		return -1;
	post = ((qp->sq_sig_type == RDMA_SIGNAL_ALL_WR) ||
		(wqe->wr->send_flags & RDMA_SEND_SIGNALED) || wqe->status != RDMA_WC_SUCCESS);

	if (post) {
		rdma_make_send_cqe(qp, wqe, &cqe);
		rc = dao_pts_rdma_enqueue_cqe(qp->port_id, qp->qid, host_recv, &cqe, 1);
		if (unlikely(rc < 1))
			dao_err("enqueue_cqe failed, ret=%d\n", rc);
	}

	/* Always log errors */
	if (wqe->status != RDMA_WC_SUCCESS)
		dao_err("QP %d: CQE generated for wr_id %lu, status %d, opcode %d, byte_len %u\n",
			qp->qid, wqe->wr->wr_id, wqe->status, wqe->wr->opcode, wqe->dma_length);
#ifdef RDMA_DEBUG
	dao_dbg("QP %d: CQE generated for wr_id %lu, status %d, opcode %d, byte_len %u\n", qp->qid,
		wqe->wr->wr_id, wqe->status, wqe->wr->opcode, wqe->dma_length);
#endif
	return 0;
}

int
rdma_opcode_rdma_hdr_len(uint32_t opcode)
{
	RTE_SET_USED(opcode);
	switch (opcode) {
	case RDMA_WR_SEND_WITH_IMM:
	case RDMA_WR_SEND_WITH_INV:
		return sizeof(struct rdma_bth);
	case RDMA_WR_RDMA_WRITE:
	case RDMA_WR_WRITE_WITH_IMM:
		return sizeof(struct rdma_bth); // FIXME
	case RDMA_WR_RDMA_READ:
	case RDMA_WR_RDMA_READ_WITH_INV:
		return sizeof(struct rdma_bth); // FIXME
	default:
		return 0;
	}
	return 0;
}

/**
 * @function - rdma_free_mbuf_generate_cqe
 * @qp: RDMA QP structure pointer
 * @status: Status of the operation
 * @brief: This function generates the CQE and frees the mbuf.
 */

static int
rdma_free_mbuf_generate_cqe(struct rdma_qp *qp, struct rdma_send_wr *wr, uint32_t status)
{
	struct dao_pts_rdma_cqe cqe = {0};

	cqe.wr_id = wr->wr_id;
	cqe.status = status;
	cqe.opcode = wr->opcode;
	cqe.byte_len = 0;
	cqe.qp_id = qp->dest_qp_num;

	dao_pts_rdma_enqueue_cqe(qp->dev_id, qp->qid, false, &cqe, 1);

	return 0;
}

static inline uint32_t
rdma_get_sge_length(struct rdma_send_wr *wr)
{
	uint32_t length = 0;
	int i;

	for (i = 0; i < wr->num_sges; i++)
		length += wr->sges0[i].length;

	return length;
}

/**
 * @function - dao_rdma_preprocess_dequeued_pkts
 * @qp: RDMA QP structure pointer
 * @mbuf: Mbuf structure pointer
 * @brief: This function forms the work queue elements for the dequeued packets.
 */
int
dao_rdma_preprocess_dequeued_pkts(rdma_qp_t *qp, struct rte_mbuf *mbuf)
{
	uint8_t n_segs = 0;
	uint16_t mtu_accum = 0;
	rdma_send_wr_t *wr;
	rdma_send_wqe_t *wqe;
	struct rte_mbuf *next;
	struct rdma_mbufs *rdma_mbuf;
	uint32_t packet_type = mbuf->packet_type;
	struct rte_mbuf *mtu_head = NULL, *mtu_tail = NULL;

	/* On TX, private area holds wr, wqe, and rdma_mbuf nodes */
	wr = rdma_tx_priv_wr(mbuf);

	if (packet_type == DAO_PTS_RDMA_D2M_COMPL)
		wqe = &qp->resp.read_reply;
	else
		wqe = rdma_tx_priv_wqe(mbuf);

	if (unlikely(!wqe)) {
		dao_err("Failed to get WQE space in mbuf priv\n");
		rdma_free_mbuf_generate_cqe(qp, wr, RDMA_WC_LOC_QP_OP_ERR);
		return -1;
	}
	memset(wqe, 0, sizeof(*wqe));
	STAILQ_INIT(&wqe->mbuf_list);
	wqe->wr = wr;
	wqe->dma_length = wr->opcode == RDMA_WR_RDMA_READ ? rdma_get_sge_length(wr) : mbuf->pkt_len;
	if (wr->opcode == RDMA_WR_RDMA_READ)
		rte_pktmbuf_reset(mbuf);

	if (!wqe->dma_length || wqe->dma_length > RDMA_PORT_MAX_MSG_SZ) {
		dao_err("Invalid dma_length %u for wr_id %lu max supported %u received req %u\n",
			wqe->dma_length, wr->wr_id, (uint32_t)RDMA_PORT_MAX_MSG_SZ,
			wqe->dma_length);
		wqe->status = RDMA_WC_LOC_QP_OP_ERR;
		dao_send_cqe(qp, false, wqe);
		return -1;
	}

	while (mbuf) {
		n_segs++;
		next = mbuf->next;
		mbuf->next = NULL;
		if (mtu_head == NULL) {
			mtu_head = mbuf;
			mtu_tail = mbuf;
		} else {
			mtu_tail->next = mbuf;
			mtu_tail = mbuf;
		}
		mtu_accum += mbuf->data_len;
		if (packet_type != DAO_PTS_RDMA_D2M_COMPL)
			rte_mbuf_refcnt_update(mbuf, 1);
		if (mtu_accum >= qp->mtu || next == NULL) {
			rdma_mbuf = (packet_type == DAO_PTS_RDMA_D2M_COMPL) ?
					    rdma_tx_priv_rmbuf_head(mtu_head) :
					    rdma_tx_priv_rmbuf(mbuf);
			rdma_mbuf->mbuf = mtu_head;
			STAILQ_INSERT_TAIL(&wqe->mbuf_list, rdma_mbuf, next);
			mtu_head->pkt_len = mtu_accum;
			mtu_head->nb_segs = n_segs;
			mtu_head = NULL;
			mtu_tail = NULL;
			mtu_accum = 0;
			n_segs = 0;
			wqe->n_rdma_segs++;
		}
		mbuf = next;
	}

	if (packet_type != DAO_PTS_RDMA_D2M_COMPL) {
		wqe->mask = rdma_wr_opcode_info[wr->opcode].mask[qp->type];
		STAILQ_INSERT_TAIL(&qp->req.wqe_head, wqe, next);
	}

	return 0;
}

int
dao_rdma_get_pvt_len(void)
{
	/*
	 * Reserve the maximum of TX and RX layouts.
	 * TX: wr + wqe + rdma_mbufs[N] + 32
	 * RX: 32 + sge[RDMA_MAX_SGES] + cqe + ack
	 */
	size_t tx_size =
		RDMA_TX_PRIV_OFF_RDMABUF + sizeof(struct rdma_mbufs) + RDMA_RX_PRIV_OFF_BASE;
	size_t rx_size = RDMA_RX_PRIV_OFF_ACK_MAX + sizeof(struct rdma_ack) + RDMA_RX_PRIV_OFF_BASE;

	return (tx_size > rx_size) ? tx_size : rx_size;
}

/**
 * @function - dao_rdma_lib_init
 * @brief: This function initializes the RDMA library.
 */
int
dao_rdma_lib_init(rdma_cb_t *cb, int disable_cc)
{
	int ret = 0;
	/* Initialize the timer subsystem */
	ret = rte_timer_subsystem_init();
	if (ret < 0) {
		dao_err("Failed to initialize timer subsystem\n");
		return ret;
	}
	ret = rdma_cb_register(cb);
	rcu_cb = cb->rcu_cb;

	/* Register RDMA map callback if provided */
	if (cb->rdma_map_cb)
		dao_rdma_register_rdma_map_cb(cb->rdma_map_cb);

	/* Apply global CC disable before any QP creation */
	rdma_global_cc_disable_set(disable_cc);
	if (disable_cc)
		dao_info("RDMA CC globally disabled via init param");

	return ret;
}

void
dao_rdma_lib_close(void)
{
	/* Close the timer subsystem */
	rte_timer_subsystem_finalize();
}

uint16_t
dao_is_qp_stalled(uint32_t qp_id, int devid)
{
	struct rdma_qp *qp = rdma_qp_query_fast(qp_id, devid);

	if (qp && (qp->req.cur_wqe == STAILQ_FIRST(&qp->req.wqe_head)))
		qp->attr.sq_draining = 0;

	if (unlikely(!qp || qp->attr.sq_draining || !qp->req.read_rq_bal ||
		     qp->req.in_retransmission || (qp->req.unacked_window <= 0)))
		return 0;

	return qp->req.read_rq_bal;
}

struct rte_mbuf *
dao_rdma_need_qp_schedule(uint32_t qp_id, int devid)
{
	struct rdma_qp *qp = rdma_qp_query_fast(qp_id, devid);

	if (unlikely(!qp || qp->state == QP_STATE_ERROR))
		return NULL;

	if (qp->type != RDMA_QPT_RC)
		return NULL;

	/* Check if we have pending segments to send */
	if (qp->req.cur_wqe && qp->req.cur_wqe->n_rdma_segs && qp->req.cur_mbuf)
		return qp->req.dummy_mbuf;

	return NULL;
}
