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
#include "dao_rdma_sp.h"
#include "rdma_common.h"
#include "rdma_comp.h"
#include "rdma_counter.h"
#include "rdma_cq.h"
#include "rdma_hdr.h"
#include "rdma_opcode.h"
#include "rdma_qp.h"
#include "rdma_req.h"
#include "rdma_resp.h"
#include "rdma_retransmit.h"
#include "rdma_utils.h"

rcu_cb_t rcu_cb;
/* clang-format off */
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

/* clang-format on */

static RTE_DEFINE_PER_LCORE(uint8_t, qp_resource_check_status[RDMA_QP_MAX]);
static RTE_DEFINE_PER_LCORE(bool, dma_resource_fetched);
RTE_DEFINE_PER_LCORE(uint32_t, rdma_dma_m2d_budget);
RTE_DEFINE_PER_LCORE(uint32_t, rdma_dma_d2m_budget);

int
dao_rdma_rx_process(struct rte_mbuf **mbuf_p, uint16_t rx_queue, uint32_t *qpn, int devid,
		    bool burst_start)
{
	uint8_t *qp_res_status = RTE_PER_LCORE(qp_resource_check_status);
	struct pkt_info pinfo = {0};
	struct rte_mbuf *mbuf = *mbuf_p;
	unsigned int lcore_id = rte_lcore_id();
	uint32_t port_id;
	uint32_t qp_id;

	if (burst_start) {
		memset(qp_res_status, 0, sizeof(RTE_PER_LCORE(qp_resource_check_status)));
		RTE_PER_LCORE(dma_resource_fetched) = false;
	}

	rdma_pkt_extract(mbuf, &pinfo, rx_queue, devid);
	*qpn = bth_qpn(&pinfo.rinfo);
	port_id = pinfo.port_num;

	if (rdma_hdr_check(&pinfo)) {
		RDMA_INC_PORT_COUNTER(lcore_id, port_id, RDMA_RX_PORT_RX_PROC_HDR_CHK_FAIL);
		return -1;
	}

	qp_id = ((struct rdma_qp *)pinfo.rinfo.qp)->qid;

	/* Fetch PTS resource budget once per QP per graph iteration */
	if (!qp_res_status[qp_id]) {
		struct rdma_qp *qp = (struct rdma_qp *)pinfo.rinfo.qp;
		uint64_t avail = 0;

		if (dao_pts_rdma_res_avail_get(devid, qp_id, &avail) == 0) {
			qp->pts_resource.rqe_avail = (uint16_t)(avail & DAO_PTS_RDMA_RES_RQ_MASK);

			/* DMA resources are per-lcore; fetch once per iteration */
			if (!RTE_PER_LCORE(dma_resource_fetched)) {
				RTE_PER_LCORE(rdma_dma_m2d_budget) =
					(uint32_t)((avail >> DAO_PTS_RDMA_RES_NON_READ_SHIFT) &
						   DAO_PTS_RDMA_RES_NON_READ_MASK);
				RTE_PER_LCORE(rdma_dma_d2m_budget) =
					(uint32_t)((avail >> DAO_PTS_RDMA_RES_READ_SHIFT) &
						   DAO_PTS_RDMA_RES_READ_MASK);
				RTE_PER_LCORE(dma_resource_fetched) = true;
			}
		} else {
			qp->pts_resource.rqe_avail = 0;
		}
		qp_res_status[qp_id] = 1;
	}
	if (rdma_icrc_check(mbuf, &pinfo)) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_RX_PROC_ICRC_CHK_FAIL);
		return -1;
	}

	RDMA_DBG_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_PKT_RECV);

	/* DCQCN RP: detect CNP opcode and apply rate reduction, then drop. */
	if (pinfo.rinfo.opcode == RDMA_OPCODE_CNP) {
		struct rdma_qp *qp = (struct rdma_qp *)pinfo.rinfo.qp;

		if (qp && qp->cc.enabled) {
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp->qid,
					    RDMA_RX_QP_DCQCN_CNP_RECEIVED);
			dcqcn_rp_cnp_received(&qp->cc);
		}
		return RDMA_COMPLETION_DONE;
	}

	/* DCQCN NP: ECN CE detection (IPv4, RC only) — generate CNP back to
	 * requester.  UD QPs have no fixed dest_qp_num so CNPs would carry a
	 * stale/zero QPN and be dropped or misdelivered by the peer.
	 */
	if ((pinfo.ptype & RTE_PTYPE_L3_IPV4) && (pinfo.rinfo.mask & RDMA_REQ_MASK)) {
		struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr *)pinfo.iph;

		if ((iph->type_of_service & 0x03) == 0x03) {
			struct rdma_qp *qp = (struct rdma_qp *)pinfo.rinfo.qp;

			if (qp && qp->cc.enabled && qp->type == RDMA_QPT_RC)
				dcqcn_np_ecn_detected(qp, mbuf, rx_queue);
		}
	}

	int result = 0;

	if (pinfo.rinfo.mask & RDMA_REQ_MASK) {
		if (rdma_responder(&pinfo)) {
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
					    RDMA_RX_QP_RX_PROC_RESPONDER_FAIL);
			return -1;
		}
		result = RDMA_RESPONDER_DONE;
	} else {
		RDMA_DBG_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_ACK_RECVD);
		if (rdma_process_ack(&pinfo)) {
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
					    RDMA_RX_QP_RX_PROC_PROCESS_ACK_FAIL);
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
	/* All mbufs are fresh (preprocess bumped refcnt to 2, never TX'd).
	 * First mbuf also freed by graph node drop path → 1 free here.
	 * Non-first need 2 frees (undo preprocess + base).
	 */
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
	/* Segments before cur_mbuf were sent to NIC in a prior burst — NIC TX
	 * owns their preprocess ref, so free once (base only).  Segments from
	 * cur_mbuf onward are fresh (never TX'd) — free twice (preprocess + base).
	 */
	struct rdma_mbufs *fresh_start = qp->req.cur_mbuf;
	bool is_fresh = false;
	struct rdma_mbufs *rmbuf = NULL, *rmbuf_next = NULL;

	RDMA_INC_QP_COUNTER(qp->lcore, qp->port_id, qp->qid,
			    RDMA_TX_QP_PROC_REMAINING_SEGS_REQUESTER_FAIL);
	wqe->status = RDMA_WC_LOC_QP_OP_ERR;
	dao_send_cqe(qp, false, wqe);
	qp->req.cur_wqe = NULL;
	qp->req.cur_mbuf = NULL;
	STAILQ_REMOVE(&qp->req.wqe_head, wqe, rdma_send_wqe, next);
	STAILQ_FOREACH_SAFE(rmbuf, &wqe->mbuf_list, next, rmbuf_next)
	{
		if (rmbuf == fresh_start)
			is_fresh = true;
		if (is_fresh)
			rte_pktmbuf_free(rmbuf->mbuf);
		rte_pktmbuf_free(rmbuf->mbuf);
		STAILQ_REMOVE(&wqe->mbuf_list, rmbuf, rdma_mbufs, next);
	}
	return 0;
}

static inline int
dao_rdma_process_remaining_segs(struct rdma_qp *qp, struct rte_mbuf **mbufs, uint16_t *n_mbufs,
				uint16_t burst_limit)
{
	int ret;
	bool m_segs;
	struct rdma_mbufs *next_r = NULL;
	struct rdma_mbufs *rmbuf = NULL;
	struct rdma_send_wqe *wqe = qp->req.cur_wqe;
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id = qp->qid;
	int nb;

	if (wqe == NULL) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
				    RDMA_TX_QP_PROC_REMAINING_SEGS_WQE_EMPTY);
		return -1;
	}
	nb = wqe->dma_length / qp->mtu + ((wqe->dma_length % qp->mtu) ? 1 : 0);
	rmbuf = qp->req.cur_mbuf;
	while (rmbuf) {
		m_segs = wqe->n_rdma_segs > 1 ? true : false;
		next_r = STAILQ_NEXT(rmbuf, next);
		if (next_r)
			rte_prefetch0(rte_pktmbuf_mtod(next_r->mbuf, void *));
		ret = rdma_requester(qp, wqe, rmbuf->mbuf, m_segs, nb);
		if (ret < 0) {
			rdma_requester_error2(qp, wqe);
			*n_mbufs = 0;
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
		if (burst_limit <= *n_mbufs)
			break;
	}

	/* Current WQE fully drained — advance to next in chain if available */
	if (wqe->n_rdma_segs == 0 && qp->req.cur_mbuf == NULL) {
		struct rdma_send_wqe *next_wqe = STAILQ_NEXT(wqe, next);

		if (next_wqe) {
			qp->req.cur_wqe = next_wqe;
			qp->req.cur_mbuf = STAILQ_FIRST(&next_wqe->mbuf_list);
			qp->req.opcode = -1;
		}
	}

	return 0;
}

static inline int
rdma_process_rc_packets(struct rdma_qp *qp, struct rte_mbuf *mbuf, struct rte_mbuf **mbufs,
			uint16_t *n_mbufs, uint16_t burst_limit)
{
	int ret;
	int nb = 1;
	bool m_segs;
	struct rdma_mbufs *next_r = NULL;
	struct rdma_mbufs *rmbuf = NULL;
	struct rdma_send_wqe *wqe = qp->req.cur_wqe;
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id = qp->qid;
	uint16_t flushed_mbufs = 0;

	/*
	 * A burst-limited READ reply in progress takes priority. Resume on its
	 * dummy trigger; on a new D2M completion in the same run, flush it first
	 * since the preprocess below memsets the read_reply WQE.
	 */
	if (qp->resp.read_chunk.needs_pts_enqueue) {
		dao_rdma_read_chunk_flush_pending(qp->qid, qp->dev_id);
		if (mbuf == qp->resp.resp_dummy_mbuf && !qp->resp.resp_cur_rmbuf)
			return 0;
	}

	if (qp->resp.resp_cur_rmbuf) {
		if (mbuf == qp->resp.resp_dummy_mbuf)
			return rdma_process_read_reply_remaining(qp, mbufs, n_mbufs, burst_limit);
		rdma_read_reply_flush_all(qp, mbufs, n_mbufs);
	}

	flushed_mbufs = *n_mbufs;

	if (wqe && (wqe->state == wqe_state_processing || qp->req.cur_mbuf)) {
		if (mbuf != qp->req.dummy_mbuf) {
			ret = dao_rdma_preprocess_dequeued_pkts(qp, mbuf);
			if (ret < 0) {
				RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
						    RDMA_TX_QP_PROC_RC_PKTS_PREPROC_DEQ_PKTS_FAIL);
				if (flushed_mbufs) {
					rte_pktmbuf_free(mbuf);
					return 0;
				}
				return -1;
			}
			if (qp->resp.read_reply.n_rdma_segs) {
				ret = rdma_process_read_reply(qp, mbuf, mbufs, n_mbufs,
							      burst_limit);
				if (ret < 0) {
					RDMA_INC_QP_COUNTER(
						lcore_id, port_id, qp_id,
						RDMA_TX_QP_PROC_RC_PKTS_READ_REPLY_FAIL);
					return flushed_mbufs ? 0 : -1;
				}
				return 0;
			}
		}
		return dao_rdma_process_remaining_segs(qp, mbufs, n_mbufs, burst_limit);
	}

	/* Handle scheduled trigger for remaining requester segments */
	if (mbuf == qp->req.dummy_mbuf)
		return 0;

	qp->req.opcode = -1;
	ret = dao_rdma_preprocess_dequeued_pkts(qp, mbuf);
	if (ret < 0) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
				    RDMA_TX_QP_PROC_RC_PKTS_PREPROC_DEQ_PKTS_FAIL);
		if (flushed_mbufs) {
			rte_pktmbuf_free(mbuf);
			return 0;
		}
		return -1;
	}
	if (qp->resp.read_reply.n_rdma_segs) {
		ret = rdma_process_read_reply(qp, mbuf, mbufs, n_mbufs, burst_limit);
		if (ret < 0) {
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
					    RDMA_TX_QP_PROC_RC_PKTS_READ_REPLY_FAIL);
			return flushed_mbufs ? 0 : -1;
		}
		return 0;
	}

	wqe = qp->req.cur_wqe ? STAILQ_NEXT(qp->req.cur_wqe, next) :
				STAILQ_FIRST(&qp->req.wqe_head);
	if (wqe == NULL) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_TX_QP_PROC_RC_PKTS_WQE_EMPTY);
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
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
					    RDMA_TX_QP_PROC_RC_REQUESTER_FAIL);
			return -1;
		} else if (ret == RDMA_REQUESTER_POSTPONED_RC) {
			qp->req.cur_mbuf = rmbuf;
			wqe->state = wqe_state_processing;
			break;
		}
		wqe->n_rdma_segs--;
		mbufs[*n_mbufs] = rmbuf->mbuf;
		(*n_mbufs)++;
		qp->req.cur_mbuf = next_r;
		if (burst_limit <= *n_mbufs)
			break;
		rmbuf = next_r;
	}
	qp->req.cur_wqe = wqe;

	return 0;
}

int
dao_rdma_tx_process(struct rte_mbuf *mbuf, uint32_t qp_id, int devid, struct rte_mbuf **mbufs,
		    uint16_t *n_mbufs, uint16_t burst_limit)
{
	int ret;
	bool flag = false;
	uint32_t nb = 1;
	struct rdma_qp *qp = NULL;
	struct rdma_send_wqe wqe = {0};
	unsigned int lcore_id = rte_lcore_id();

	qp = rdma_qp_query_fast(qp_id, devid);
	if (qp == NULL || qp->state == QP_STATE_ERROR) {
		RDMA_INC_PORT_COUNTER(lcore_id, devid, RDMA_TX_PORT_TX_PROC_QP_INV);
		return -1;
	}

	if (qp->lcore != rte_lcore_id()) {
		RDMA_INC_QP_COUNTER(lcore_id, devid, qp_id,
				    RDMA_TX_QP_TX_PROC_ACC_QP_BY_NON_OWNER_LCORE);
		return -1;
	}

	if (qp->type == RDMA_QPT_RC) {
		if (!qp->req.dummy_mbuf)
			qp->req.dummy_mbuf = rte_pktmbuf_alloc(mbuf->pool);
		if (!qp->resp.resp_dummy_mbuf)
			qp->resp.resp_dummy_mbuf = rte_pktmbuf_alloc(mbuf->pool);
		if (unlikely(!qp->req.dummy_mbuf || !qp->resp.resp_dummy_mbuf))
			goto error;
		ret = rdma_process_rc_packets(qp, mbuf, mbufs, n_mbufs, burst_limit);
		if (ret < 0) {
			RDMA_INC_QP_COUNTER(lcore_id, devid, qp_id,
					    RDMA_TX_QP_TX_PROC_RC_PKT_PROCESS_FAIL);
			goto error;
		}
		qp->req.dummy_mbuf->port = RTE_MAX_ETHPORTS + devid;
		qp->resp.resp_dummy_mbuf->port = RTE_MAX_ETHPORTS + devid;
		if (*n_mbufs == 0)
			return RDMA_TX_PROC_CONSUMED;
	} else if (unlikely(qp->type == RDMA_QPT_MGMT)) {
		wqe.wr = rdma_tx_priv_wr(mbuf);
		wqe.status = RDMA_WC_SUCCESS;
		dao_send_cqe(qp, false, &wqe);
	} else {
		qp->req.opcode = -1;
		wqe.wr = rdma_tx_priv_wr(mbuf);
		ret = rdma_requester(qp, &wqe, mbuf, flag, nb);
		if (ret < 0) {
			RDMA_INC_QP_COUNTER(lcore_id, devid, qp_id,
					    RDMA_TX_QP_TX_PROC_UD_REQUESTER_FAIL);
			goto error;
		}
		dao_send_cqe(qp, false, &wqe);
	}
	return 0;

error:
	mbuf->ol_flags &= ~(0x7ULL << OFFLD_UPPER_BITS);
	RDMA_INC_QP_COUNTER(lcore_id, devid, qp_id, RDMA_TX_QP_TX_PROC_REQUESTER_FAIL);
	return -1;
}

int
dao_send_cqe(struct rdma_qp *qp, bool host_recv, struct rdma_send_wqe *wqe)
{
	struct dao_pts_rdma_cqe cqe = {0};
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id = qp->qid;
	bool post = false;
	int rc;

	if (unlikely(!qp || !wqe))
		return -1;
	post = ((qp->sq_sig_type == RDMA_SIGNAL_ALL_WR) ||
		(wqe->wr->send_flags & RDMA_SEND_SIGNALED) || wqe->status != RDMA_WC_SUCCESS);

	if (post) {
		rdma_make_send_cqe(qp, wqe, &cqe);
		rc = dao_pts_rdma_enqueue_cqe(qp->port_id, qp->qid, host_recv, &cqe, 1);
		if (unlikely(rc < 1)) {
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
					    RDMA_TX_QP_SEND_CQE_ENQ_CQE_FAIL);
		}
	}

	if (wqe->status != RDMA_WC_SUCCESS)
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_TX_QP_SEND_CQE_FAIL);

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
	cqe.opcode = rdma_wr_to_wc_opcode(wr->opcode);
	cqe.byte_len = 0;
	cqe.qp_id = qp->dest_qp_num;

	dao_pts_rdma_enqueue_cqe(qp->dev_id, qp->qid, false, &cqe, 1);

	return 0;
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
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id = qp->qid;

	if (packet_type == DAO_PTS_RDMA_D2M_COMPL) {
		struct rdma_ack *read_ack = NULL;
		struct rdma_ack *ack;

		/* clang-format off */
		STAILQ_FOREACH(ack, &qp->resp.ack_pending_list, next) {
			/* clang-format on */
			if (ack->is_read && ack->mbuf == mbuf) {
				read_ack = ack;
				break;
			}
		}
		if (!read_ack) {
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
					    RDMA_TX_QP_PREPROC_DEQ_D2M_ACK_HEAD_MISMATCH);
			mbuf->packet_type = 0;
			return -1;
		}
		wqe = &qp->resp.read_reply;
		wr = NULL;
	} else {
		/* On TX, private area holds wr, wqe, and rdma_mbuf nodes */
		wr = rdma_tx_priv_wr(mbuf);
		wqe = rdma_tx_priv_wqe(mbuf);
	}

	if (unlikely(!wqe)) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
				    RDMA_TX_QP_PREPROC_DEQ_PKTS_EXTRACT_WQE_FAIL);
		rdma_free_mbuf_generate_cqe(qp, wr, RDMA_WC_LOC_QP_OP_ERR);
		return -1;
	}
	memset(wqe, 0, sizeof(*wqe));
	STAILQ_INIT(&wqe->mbuf_list);
	wqe->wr = wr;
	if (packet_type == DAO_PTS_RDMA_D2M_COMPL) {
		wqe->dma_length = mbuf->pkt_len;
	} else {
		if (wr->opcode == RDMA_WR_RDMA_READ) {
			wqe->dma_length = rdma_get_sge_length(wr);
			rte_pktmbuf_reset(mbuf);
		} else {
			wqe->dma_length = mbuf->pkt_len;
		}
	}

	if (!wqe->dma_length || wqe->dma_length > RDMA_PORT_MAX_MSG_SZ) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
				    RDMA_TX_QP_PREPROC_DEQ_PKTS_DMA_LEN_INV);
		if (packet_type != DAO_PTS_RDMA_D2M_COMPL) {
			wqe->status = RDMA_WC_LOC_QP_OP_ERR;
			dao_send_cqe(qp, false, wqe);
		}
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

#ifdef DAO_RDMA_DEBUG
		if (wr->opcode == RDMA_WR_SEND || wr->opcode == RDMA_WR_SEND_WITH_IMM)
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
					    RDMA_TX_QP_SEND_WQE_PROCESSED);
		else if (wr->opcode == RDMA_WR_RDMA_WRITE || wr->opcode == RDMA_WR_WRITE_WITH_IMM)
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
					    RDMA_TX_QP_WRITE_WQE_PROCESSED);
		else if (wr->opcode == RDMA_WR_RDMA_READ)
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
					    RDMA_TX_QP_READ_WQE_PROCESSED);
#endif
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
dao_rdma_lib_init(rdma_cb_t *cb, int disable_cc, uint8_t nport)
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

	ret = rdma_counter_init(nport);
	if (ret < 0) {
		dao_err("Failed to allocate memory for RDMA counters\n");
		return ret;
	}

	/* Register RDMA map callback if provided */
	if (cb->rdma_map_cb)
		dao_rdma_register_rdma_map_cb(cb->rdma_map_cb);

	/* Apply global DCQCN disable before any QP creation */
	dcqcn_global_disable_set(disable_cc);
	if (disable_cc)
		dao_info("RDMA DCQCN globally disabled via init param");

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
	uint8_t req_bal, resp_bal;

	if (qp && (qp->req.cur_wqe == STAILQ_FIRST(&qp->req.wqe_head)))
		qp->attr.sq_draining = 0;

	/* Always let an in-progress READ reply drain to free its WQE/DMA credit. */
	if (qp && (qp->resp.resp_cur_rmbuf || qp->resp.read_chunk.in_progress ||
		   qp->resp.read_chunk.needs_pts_enqueue || qp->resp.read_chunk.needs_chunk_retry))
		return (uint16_t)1 << 8;

	if (unlikely(!qp || qp->attr.sq_draining))
		return 0;

	resp_bal = (uint8_t)((qp->attr.max_dest_rd_atomic - qp->resp.resp_read_rq_bal) +
			     qp->resp.resp_read_requeue_inflight);

	if (unlikely(!qp->req.read_rq_bal || qp->req.in_retransmission ||
		     (qp->req.unacked_window <= 0)))
		return (uint16_t)resp_bal << 8;

	req_bal = (uint8_t)qp->req.read_rq_bal;

	return ((uint16_t)resp_bal << 8) | req_bal;
}

struct rte_mbuf *
dao_rdma_need_qp_schedule(uint32_t qp_id, int devid)
{
	struct rdma_qp *qp = rdma_qp_query_fast(qp_id, devid);

	if (unlikely(!qp || qp->state == QP_STATE_ERROR))
		return NULL;

	if (qp->type != RDMA_QPT_RC)
		return NULL;

	/* Responder READ reply has priority; finish it before the requester. */
	if (qp->resp.resp_cur_rmbuf || qp->resp.read_chunk.needs_pts_enqueue ||
	    qp->resp.read_chunk.needs_chunk_retry)
		return qp->resp.resp_dummy_mbuf;

	/* Check if we have pending requester segments to send */
	if (qp->req.cur_wqe && qp->req.cur_wqe->n_rdma_segs && qp->req.cur_mbuf)
		return qp->req.dummy_mbuf;

	return NULL;
}
