/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <dao_log.h>

#include <rte_ethdev.h>

#include "dao_pts_rdma_dev.h"
#include "rdma_common.h"
#include "rdma_counter.h"
#include "rdma_kernel_abi.h"
#include "rdma_mbox_priv.h"
#include "rdma_port_priv.h"
#include "rdma_qp.h"

#define MAX_NUM_MPOOL_MBUF 1024
#define MEMPOOL_CACHE_SIZE 256

/* Max default QP's supported. (Zero-initialized) */
static rdma_qp_status_cb_t qp_status_cb;

int
rdma_qp_create(void *data)
{
	struct rdma_qp *rqp = (struct rdma_qp *)data;
	struct rdma_port *port;
	struct rdma_qp *qp;

	port = rdma_port_lookup(rqp->port_id);
	if (port == NULL) {
		dao_err("Invalid RDMA portid for QP create");
		return -1;
	}

	qp = port->qp[rqp->qid];
	if (qp) {
		dao_err("QPid: %u already exist", rqp->qid);
		return -1;
	}

	qp = (struct rdma_qp *)rte_zmalloc("rdma_qp", sizeof(struct rdma_qp), 0);
	if (qp == NULL) {
		dao_err("Failed to allocate rdma_qp for qid %d\n", rqp->qid);
		return -1;
	}

	*qp = *rqp;

	qp->timer_data = rte_zmalloc("rdma_qp_timer_data", sizeof(struct rdma_timer_data), 0);
	if (qp->timer_data == NULL) {
		dao_err("Failed to allocate memory for QP timer data");
		rte_free(qp);
		return -1;
	}

	qp->timer_data->dev_id = rqp->port_id;
	qp->timer_data->qp_id = rqp->qid;
	qp->attr.max_read_rq_cnt = RDMA_MAX_QP_RD_ATOM;
	qp->req.read_rq_bal = RDMA_MAX_QP_RD_ATOM;
	/* Brand new QP has no outstanding sends; full unacked window available */
	qp->req.unacked_window = RDMA_MAX_UNACKED_PSNS;
	STAILQ_INIT(&qp->req.wqe_head);
	STAILQ_INIT(&qp->resp.ack_pending_list);
	rte_timer_init(&qp->timer_data->retrans_timer);
	rte_timer_init(&qp->timer_data->rnr_timer);
	qp->req.cur_wqe = 0;
	qp->resp.opcode = -1;
	qp->resp.msn = 0;
	/* Ensure READ reply tracking fields are clean */
	memset(&qp->resp.read_reply, 0, sizeof(qp->resp.read_reply));
	qp->resp.resp_cur_rmbuf = NULL;
	qp->resp.resp_dummy_mbuf = NULL;
	qp->resp.read_reply_opcode = -1;
	qp->resp.read_reply_psn = 0;
	qp->state = QP_STATE_RESET;
	qp->valid = 1;
	qp->lcore = 0;

	/* Initialize DCQCN congestion control state. Query the port link
	 * speed so the algorithm knows the line rate ceiling.
	 */
	{
		struct rte_eth_link link;
		uint64_t link_speed_bps = 0;

		if (rte_eth_link_get_nowait(qp->port_id, &link) == 0 &&
		    link.link_speed != RTE_ETH_SPEED_NUM_NONE)
			link_speed_bps = (uint64_t)link.link_speed * 1000000ULL;

		dcqcn_init_qp(&qp->cc, link_speed_bps);
	}

	port->num_active_qp++;

	port->qp[qp->qid] = qp;

	dao_dbg("qpd[port].num_active_qp = %d, port %d, qid %d pdn = %d", port->num_active_qp,
		qp->port_id, qp->qid, qp->pd_id);

	return 0;
}

int
rdma_qp_destroy(uint8_t portid, uint32_t qid)
{
	struct rdma_port *port;
	rdma_qp_t *qp;

	if (qid >= RDMA_QP_MAX)
		return -1;

	port = rdma_port_lookup(portid);
	if (port == NULL) {
		dao_err("Invalid RDMA portid for QP destroy");
		return -1;
	}

	qp = port->qp[qid];
	if (qp == NULL) {
		dao_err("QP %d does not exist", qid);
		return -1;
	}

	RDMA_INC_PORT_COUNTER(rdma_counter_update_lcore(), portid, RDMA_PORT_QP_DESTROY);
	if (!STAILQ_EMPTY(&qp->resp.ack_pending_list))
		RDMA_INC_PORT_COUNTER(rdma_counter_update_lcore(), portid,
				      RDMA_PORT_QP_DESTROY_ACK_PENDING);

	qp->valid = 0;
	port->qp[qid] = NULL;

	if (qp_status_cb(portid, qid, false) < 0) {
		dao_err("qp_status_cb failed for port %d, qid %d", portid, qid);
		qp->valid = 1;
		return -1;
	}

	rdma_delete_all_wqe(qp);

	/* Free the RC fast-path sentinel mbuf allocated during QP creation.
	 * Without this, each RC QP destroy leaks one mbuf from the pool,
	 * eventually exhausting it and crashing rdma_fp.c when
	 * dummy_mbuf is dereferenced as NULL.
	 */
	if (qp->req.dummy_mbuf) {
		rte_pktmbuf_free(qp->req.dummy_mbuf);
		qp->req.dummy_mbuf = NULL;
	}
	if (qp->resp.resp_dummy_mbuf) {
		rte_pktmbuf_free(qp->resp.resp_dummy_mbuf);
		qp->resp.resp_dummy_mbuf = NULL;
	}

	rte_free(qp);
	port->num_active_qp--;

	dao_dbg("qpd[port].num_active_qp = %d, port %d , qid %d", port->num_active_qp, portid, qid);
	return 0;
}

static inline int
rdma_qp_reset(struct rdma_qp *qp, int port)
{
	qp->valid = 0;
	qp->state = QP_STATE_RESET;
	qp->attr.sq_draining = 0;
	qp->ssn = 0;
	qp->req.opcode = -1;
	qp->req.wait_rnr_exp = 0;
	qp->req.no_ack_pkts = 0;
	qp->resp.msn = 0;
	qp->resp.opcode = -1;
	qp->valid = 0;
	qp_status_cb(port, qp->qid, false);
	rdma_delete_all_wqe(qp);
	/* Release the old sentinel mbuf before the QP is re-enabled;
	 * a fresh one will be allocated on the next RC SEND.
	 */
	if (qp->req.dummy_mbuf) {
		rte_pktmbuf_free(qp->req.dummy_mbuf);
		qp->req.dummy_mbuf = NULL;
	}
	if (qp->resp.resp_dummy_mbuf) {
		rte_pktmbuf_free(qp->resp.resp_dummy_mbuf);
		qp->resp.resp_dummy_mbuf = NULL;
	}
	qp->resp.resp_cur_rmbuf = NULL;
	qp->resp.read_reply_opcode = -1;
	qp->resp.read_reply_psn = 0;

	/* Reinitialize DCQCN state so stale rate/alpha/timers from the
	 * previous flow do not carry over into the next use of this QP.
	 */
	{
		struct rte_eth_link link;
		uint64_t link_speed_bps = 0;

		if (rte_eth_link_get_nowait(qp->port_id, &link) == 0 &&
		    link.link_speed != RTE_ETH_SPEED_NUM_NONE)
			link_speed_bps = (uint64_t)link.link_speed * 1000000ULL;

		dcqcn_init_qp(&qp->cc, link_speed_bps);
	}

	qp->valid = 1;
	qp_status_cb(port, qp->qid, true);

	return 0;
}

/*
 * Convert timeout value to nsecs 4.096 μsec 2^timeout
 * then use DPDK API to convert nano seconds to CPU cycles
 */

static inline void
rdma_convert_timeout_cycles(uint8_t timeout, uint64_t *timeout_cycles)
{
	/* 4.096 μsec 2^timeout */
	*timeout_cycles = 4096ULL << timeout;
	*timeout_cycles = rte_get_tsc_hz() * (*timeout_cycles) / 1000000;
}

static inline int
rdma_update_av(struct rdma_av *av, struct octep_rdma_user_qp_modify_req *req)
{
	av->network_type = req->network_type;
	av->port_num = req->port_num;
	av->iph.hop_limit = 64;
	av->iph.traffic_class = 0;
	av->iph.ip_id = rte_rand() % 0xffff;

	if (req->network_type == RDMA_NETWORK_TYPE_IPV4) {
		av->sgid_addr.ip4 = req->s_addr;
		av->dgid_addr.ip4 = req->d_addr;
	} else {
		memcpy(av->sgid_addr.ip6, &req->s_addr, sizeof(req->s_addr));
		memcpy(av->dgid_addr.ip6, &req->d_addr, sizeof(req->d_addr));
	}

	memcpy(av->dmac.addr_bytes, req->dmac, sizeof(req->dmac));
	memcpy(av->smac.addr_bytes, req->smac, sizeof(req->smac));
	av->iph.hop_limit = 64;

	return 0;
}

static inline int
mtu_enum_to_int(int mtu)
{
	switch (mtu) {
	case RDMA_MTU_256:
		return 256;
	case RDMA_MTU_512:
		return 512;
	case RDMA_MTU_1024:
		return 1024;
	case RDMA_MTU_2048:
		return 2048;
	case RDMA_MTU_4096:
		return 4096;
	default:
		return 0;
	}

	return 0;
}

static inline int
rdma_qp_update_from_attr(struct rdma_qp *qp, struct octep_rdma_user_qp_modify_req *req,
			 uint32_t mask, int port)
{
	if (mask & RDMA_QP_PATH_MTU) {
		if (req->path_mtu < RDMA_MTU_256 || req->path_mtu > RDMA_MTU_4096) {
			dao_err("Invalid MTU value %d", req->path_mtu);
			return -1;
		}
		qp->mtu = mtu_enum_to_int(req->path_mtu);
		dao_dbg("RDMA_QP_PATH_MTU %d", qp->mtu);
		if (dao_pts_rdma_qp_mtu_set(port, qp->qid, qp->mtu) < 0) {
			dao_err("dao_pts_rdma_qp_mtu_set failed for port %d, qid %d", port,
				qp->qid);
			return -1;
		}
	}

	if (mask & RDMA_QP_MAX_DEST_RD_ATOMIC) {
		qp->attr.max_dest_rd_atomic = req->max_dest_rd_atomic;
		qp->resp.resp_read_rq_bal = req->max_dest_rd_atomic;
		dao_dbg("RDMA_QP_MAX_DEST_RD_ATOMIC %d", qp->attr.max_dest_rd_atomic);
	}

	if (mask & RDMA_QP_MAX_QP_RD_ATOMIC) {
		qp->attr.max_read_rq_cnt = req->max_rd_atomic;
		qp->req.read_rq_bal = req->max_rd_atomic;
		dao_dbg("RDMA_QP_MAX_QP_RD_ATOMIC %d", qp->attr.max_read_rq_cnt);
	}

	if (mask & RDMA_QP_MIN_RNR_TIMER)
		qp->attr.min_rnr_timer = req->min_rnr_timer;

	if (mask & RDMA_QP_RETRY_CNT)
		qp->attr.max_retry_cnt = req->retry_cnt;

	if (mask & RDMA_QP_RNR_RETRY)
		qp->attr.max_rnr_retry = req->rnr_retry_cnt;

	if (mask & RDMA_QP_TIMEOUT) {
		qp->attr.timeout = req->timeout;
		rdma_convert_timeout_cycles(qp->attr.timeout, &qp->req.timeout_cycles);
	}

	if (mask & RDMA_QP_PORT)
		qp->port_id = req->port_num;

	if (mask & RDMA_QP_PKEY_INDEX) {
		// qp->pkey_index = req->pkey_index;
		qp->pkey = 0xffff; // Default PKEY is 0xffff
	}

	if (mask & RDMA_QP_DEST_QPN)
		qp->dest_qp_num = req->dest_qpn;

	if (mask & RDMA_QP_SQ_PSN) {
		qp->attr.sq_psn = req->sq_psn;
		qp->req.psn = req->sq_psn;
		qp->comp.psn = req->sq_psn;
		qp->comp.opcode = -1;
	}

	if (mask & RDMA_QP_RQ_PSN) {
		qp->attr.rq_psn = req->rq_psn;
		qp->resp.psn = req->rq_psn;
	}

	if (mask & RDMA_QP_QKEY)
		qp->qkey = req->qkey;

	if (mask & RDMA_QP_AV) {
		rdma_update_av(&qp->av, req);
		qp->sport = req->src_udp_port;
	}

	/* Note: This comes only for QP type as UD. This is not part of spec. */
	if (mask & RDMA_QP_SRC_PORT)
		qp->sport = req->src_udp_port;

	if (RDMA_QP_ACCESS_FLAGS & mask) {
		qp->attr.qp_access_flags = req->qp_access_flags;
		qp->req.is_read_qp = !!(req->qp_access_flags & RDMA_ACCESS_REMOTE_READ);
	}

	if (mask & RDMA_QP_CUR_STATE)
		qp->state = req->cur_qp_state;

	if (mask & RDMA_QP_STATE) {
		qp->state = req->new_qp_state;
		if (qp->state == QP_STATE_SQ_DRAIN)
			qp->attr.sq_draining = 1;
		if (qp->state == QP_STATE_RESET)
			rdma_qp_reset(qp, port);
	}

	return 0;
}

int
rdma_qp_modify(void *data)
{
	struct octep_rdma_user_qp_modify_req *req = (struct octep_rdma_user_qp_modify_req *)data;
	uint32_t mask = req->modify_mask;
	uint32_t qid = req->qp_id;
	struct rdma_port *port;
	struct rdma_qp *qp;
	int lcore;

	if (mask & RDMA_QP_PORT && req->port_num >= RDMA_PORT_MAX)
		return -1;

	port = rdma_port_lookup(req->port_num);
	if (port == NULL) {
		dao_err("Invalid RDMA portid for QP modify");
		return -1;
	}

	if (qid >= RDMA_QP_MAX)
		return -1;

	qp = (struct rdma_qp *)port->qp[qid];
	RDMA_INC_PORT_COUNTER(rdma_counter_update_lcore(), req->port_num, RDMA_PORT_QP_MODIFY);

	if (rdma_qp_update_from_attr(qp, req, mask, req->port_num) < 0)
		return -1;

	if (qp->state >= QP_STATE_RTR && !qp->lcore) {
		lcore = qp_status_cb(qp->port_id, qp->qid, true);
		if (lcore < 0) {
			dao_err("qp_status_cb failed for port %d, qid %d", qp->port_id, qp->qid);
			return -1;
		}
		qp->lcore = lcore;
		dao_dbg("QP %d on port %d is now owned by lcore %d", qid, qp->port_id, qp->lcore);
	}

	return 0;
}

inline struct rdma_qp *
rdma_qp_query(uint32_t qid, int portid)
{
	struct rdma_port *port;
	rdma_qp_t *qp;

	if (qid >= RDMA_QP_MAX)
		return NULL;

	port = rdma_port_lookup(portid);
	if (port == NULL) {
		dao_err("Invalid RDMA portid for QP query %d", portid);
		return NULL;
	}

	qp = (struct rdma_qp *)port->qp[qid];
	if (qp == NULL || !qp->valid) {
		return NULL;
	}

	return qp;
}

int
rdma_qp_init(uint64_t **qp, uint32_t num_qp)
{
	uint32_t qp_count = num_qp;
	uint32_t i;

	if (qp_count == 0)
		qp_count = RDMA_QP_MAX;

	for (i = 0; i < qp_count; i++) {
		qp[i] = rte_zmalloc("rdma_qp", sizeof(rdma_qp_t), 0);
		if (qp[i] == NULL) {
			dao_err("Failed to allocate memory for QP");
			return -1;
		}
		memset(qp[i], 0, sizeof(struct rdma_qp));
	}

	return 0;
}

int
rdma_qp_free(struct rdma_qp **qp)
{
	uint32_t i;

	if (qp == NULL)
		return 0;

	for (i = 0; i < RDMA_QP_MAX; i++) {
		if (qp[i]) {
			rte_free(qp[i]);
			qp[i] = NULL;
		}
	}

	return 0;
}

int
rdma_qp_state_check(struct rdma_pkt_info *pinfo, struct rdma_qp *qp)
{
	unsigned int pkt_type;

	if (unlikely(!qp->valid)) {
		dao_err("QP %d: invalid (valid=0)", qp->qid);
		return -1;
	}

	pkt_type = pinfo->opcode & 0xe0;
	switch (qp->type) {
	case RDMA_QPT_RC:
		if (unlikely(pkt_type != RDMA_OPCODE_RC)) {
			dao_err("QP %d: type mismatch, qp_type=RC pkt_type=0x%x opcode=0x%x",
				qp->qid, pkt_type, pinfo->opcode);
			return -EINVAL;
		}
		break;
	case RDMA_QPT_UC:
		if (unlikely(pkt_type != RDMA_OPCODE_UC)) {
			dao_err("QP %d: type mismatch, qp_type=UC pkt_type=0x%x opcode=0x%x",
				qp->qid, pkt_type, pinfo->opcode);
			return -EINVAL;
		}
		break;
	case RDMA_QPT_GSI:
	case RDMA_QPT_UD:
		if (unlikely(pkt_type != RDMA_OPCODE_UD)) {
			dao_err("QP %d: type mismatch, qp_type=UD pkt_type=0x%x opcode=0x%x",
				qp->qid, pkt_type, pinfo->opcode);
			return -EINVAL;
		}
		break;
	default:
		dao_err("QP %d: unknown qp_type=%d", qp->qid, qp->type);
		return -EINVAL;
	}

	if (pinfo->mask & RDMA_REQ_MASK) {
		if (unlikely(qp->state < QP_STATE_RTR)) {
			dao_err("QP %d: state %d < RTR for REQ pkt (opcode=0x%x)", qp->qid,
				qp->state, pinfo->opcode);
			return -EINVAL;
		}
	} else if (unlikely(qp->state < QP_STATE_RTS)) {
		dao_err("QP %d: state %d < RTS for non-REQ pkt (opcode=0x%x mask=0x%x)", qp->qid,
			qp->state, pinfo->opcode, pinfo->mask);
		return -EINVAL;
	}

	return 0;
}

int
rdma_check_keys(struct rdma_pkt_info *pinfo, uint32_t qpn, struct rdma_qp *qp)
{
	uint16_t pkey = bth_pkey(pinfo);

	pinfo->pkey_index = 0;

	/* XXX: Supporting default partition key. */
	if (!pkey_match(pkey, BTH_DEF_PKEY))
		return -1;

	if (qp->type == RDMA_QPT_UD || qp->type == RDMA_QPT_GSI) {
		uint32_t pkt_qkey = deth_qkey(pinfo);
		uint32_t qkey = (qpn == 1) ? GSI_QKEY : qp->qkey;

		if (unlikely(pkt_qkey != qkey))
			return -1;
	}

	return 0;
}

int
rdma_cb_register(rdma_cb_t *cb)
{
	if (cb == NULL) {
		dao_err("%s: callback is NULL", __func__);
		return -1;
	}
	qp_status_cb = cb->qp_status_cb;
	return 0;
}
