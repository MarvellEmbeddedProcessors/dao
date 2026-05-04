/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __RDMA_QP_H__
#define __RDMA_QP_H__

#include <rte_spinlock.h>
#include <rte_timer.h>
#include <stdlib.h>
#include <string.h>

#include "dao_rdma_fp.h"
#include "rdma_av.h"
#include "rdma_dcqcn.h"
#include "rdma_dev_cap_priv.h"
#include "rdma_hdr.h"
#include "rdma_pd_mr.h"
#include "rdma_priv.h"
#include <dao_pts_rdma_dev.h>
#include <rte_mbuf.h>

#ifndef RDMA_QP_MAX
#define RDMA_QP_MAX 1024
#endif

#define RDMA_QPN_MASK      0xFFFFFF
#define RDMA_MULTICAST_QPN 0xFFFFFF

#define MAX_RESP_BUCKET 32

enum rdma_wr_opcode {
	RDMA_WR_RDMA_WRITE = 0,
	RDMA_WR_WRITE_WITH_IMM = 1,
	RDMA_WR_SEND = 2,
	RDMA_WR_SEND_WITH_IMM = 3,
	RDMA_WR_RDMA_READ = 4,
	RDMA_WR_ATOMIC_CMP_AND_SWP = 5,
	RDMA_WR_ATOMIC_FETCH_AND_ADD = 6,
	RDMA_WR_LOCAL_INV = 7,
	RDMA_WR_BIND_MW = 8,
	RDMA_WR_SEND_WITH_INV = 9,
	RDMA_WR_TSO = 10,
	RDMA_WR_RDMA_READ_WITH_INV = 11,
	RDMA_WR_MASKED_ATOMIC_CMP_AND_SWP = 12,
	RDMA_WR_MASKED_ATOMIC_FETCH_AND_ADD = 13,
	RDMA_WR_FLUSH = 14,
	RDMA_WR_ATOMIC_WRITE = 15,
	RDMA_WR_REG_MR = 16,
};

enum rdma_wc_status {
	RDMA_WC_SUCCESS,
	RDMA_WC_LOC_LEN_ERR,
	RDMA_WC_LOC_QP_OP_ERR,
	RDMA_WC_LOC_EEC_OP_ERR,
	RDMA_WC_LOC_PROT_ERR,
	RDMA_WC_WR_FLUSH_ERR,
	RDMA_WC_MW_BIND_ERR,
	RDMA_WC_BAD_RESP_ERR,
	RDMA_WC_LOC_ACCESS_ERR,
	RDMA_WC_REM_INV_REQ_ERR,
	RDMA_WC_REM_ACCESS_ERR,
	RDMA_WC_REM_OP_ERR,
	RDMA_WC_RETRY_EXC_ERR,
	RDMA_WC_RNR_RETRY_EXC_ERR,
	RDMA_WC_LOC_RDD_VIOL_ERR,
	RDMA_WC_REM_INV_RD_REQ_ERR,
	RDMA_WC_REM_ABORT_ERR,
	RDMA_WC_INV_EECN_ERR,
	RDMA_WC_INV_EEC_STATE_ERR,
	RDMA_WC_FATAL_ERR,
	RDMA_WC_RESP_TIMEOUT_ERR,
	RDMA_WC_GENERAL_ERR
};

enum rdma_wc_opcode {
	RDMA_WC_SEND = 0,
	RDMA_WC_RDMA_WRITE = 1,
	RDMA_WC_RDMA_READ = 2,
	/*
	 * Set value of RDMA_WC_RECV so consumers can test if a completion is a
	 * receive by testing (opcode & RDMA_WC_RECV).
	 */
	RDMA_WC_RECV = 1 << 7,
};

typedef enum rdma_qp_type {
	RDMA_QPT_SMI,
	RDMA_QPT_GSI,
	RDMA_QPT_RC = 2,
	RDMA_QPT_UC,
	RDMA_QPT_UD,
	RDMA_QPT_RAW_IPV6,
	RDMA_QPT_RAW_ETHERTYPE,
	RDMA_QPT_RAW_PACKET = 8,
	RDMA_QPT_XRC_INI,
	RDMA_QPT_XRC_TGT,
	RDMA_QPT_MAX,
	RDMA_QPT_MGMT = 0xFF,
} rdma_qp_type_e;

typedef enum rdma_qp_state {
	QP_STATE_RESET,
	QP_STATE_INIT,
	QP_STATE_RTR,
	QP_STATE_RTS,      /* req only */
	QP_STATE_SQ_DRAIN, /* req only */
	QP_STATE_SQ_ERROR,
	QP_STATE_ERROR,
} rdma_qp_state_e;

enum rdma_wqe_state {
	wqe_state_posted,
	wqe_state_processing,
	wqe_state_pending,
	wqe_state_done,
	wqe_state_error,
};

#define RDMA_UVERBS_ACCESS_OPTIONAL_FIRST (1 << 20)
#define RDMA_UVERBS_ACCESS_OPTIONAL_LAST  (1 << 29)

enum rdma_access_flags {
	RDMA_ACCESS_LOCAL_WRITE = 1 << 0,
	RDMA_ACCESS_REMOTE_WRITE = 1 << 1,
	RDMA_ACCESS_REMOTE_READ = 1 << 2,
	RDMA_ACCESS_REMOTE_ATOMIC = 1 << 3,
	RDMA_ACCESS_MW_BIND = 1 << 4,
	RDMA_ZERO_BASED = 1 << 5,
	RDMA_ACCESS_ON_DEMAND = 1 << 6,
	RDMA_ACCESS_HUGETLB = 1 << 7,
	RDMA_ACCESS_RELAXED_ORDERING = 1 << 20,

	RDMA_ACCESS_OPTIONAL = ((RDMA_UVERBS_ACCESS_OPTIONAL_LAST << 1) - 1) &
			       ~(RDMA_UVERBS_ACCESS_OPTIONAL_FIRST - 1),
	RDMA_ACCESS_SUPPORTED = ((RDMA_ACCESS_HUGETLB << 1) - 1) | RDMA_ACCESS_OPTIONAL,
};

struct rdma_cqe {
	uint64_t wr_id;
	uint32_t status;
	uint32_t opcode;
	uint32_t byte_len;
	uint32_t qp_num;
	uint32_t src_qp;
	uint32_t wc_flags;
	uint8_t port_num;
};

struct rdma_recv_wqe {
	struct rte_mbuf *mbuf;
	struct rte_mbuf *tail;
	struct rdma_reth reth;
	uint8_t opcode;
};

/* Structure for PTS RDMA device basic SGE element */
struct __rte_packed_begin octep_rdma_sge {
	uint64_t addr;
	uint32_t length;
	uint32_t lkey;
} __rte_packed_end;

typedef struct rdma_send_wr {
	struct {
		/* WORD 0 */
		uint8_t opcode;
		uint8_t send_flags;
		uint8_t flags;
		uint8_t num_sges;
		uint32_t imm_data;
		/* WORD 1 */
		uint64_t wr_id;
		/* WORD 2-3 */
		union {
			struct {
				uint64_t remote_addr;
				uint32_t rkey;
				uint32_t reserved;
			} rdma;
			struct {
				uint32_t ah;
				uint32_t remote_qpn;
				uint32_t qkey;
			} ud;
		};
		/* WORD 4-7 */
		struct octep_rdma_sge sges0[2];
	};
	/* WORD 0-7 */
	struct octep_rdma_sge sges1[4];
} rdma_send_wr_t;

struct rdma_mbufs {
	struct rte_mbuf *mbuf;

	STAILQ_ENTRY(rdma_mbufs) next;
};

typedef struct rdma_send_wqe {
	rdma_send_wr_t *wr;
	struct rte_mbuf *read_mbuf;
	struct rte_mbuf *read_tail;

	STAILQ_HEAD(mbuf_list, rdma_mbufs) mbuf_list;
	STAILQ_ENTRY(rdma_send_wqe) next;
	uint32_t status;
	uint32_t mask;
	uint32_t first_psn;
	uint32_t last_psn;
	uint32_t ack_length;
	uint32_t dma_length;
	uint32_t n_rdma_segs;
	enum rdma_wqe_state state;
	uint8_t has_read_req;
} rdma_send_wqe_t;

struct retransmit {
	rdma_send_wqe_t *curr_wqe;
	struct rdma_mbufs *curr_mbuf;
};

struct rdma_req_info {
	/* Retransmission timeout in cycles */
	uint64_t timeout_cycles;
	rdma_send_wqe_t *cur_wqe;
	struct rdma_mbufs *cur_mbuf;
	struct rte_mbuf *dummy_mbuf;
	struct retransmit retransmit;

	STAILQ_HEAD(wqe_list, rdma_send_wqe) wqe_head;
	uint32_t psn;
	/* Unacknowledged packets count */
	uint32_t no_ack_pkts;
	int opcode;
	/* Flag to indicate RNR timer expired */
	int no_ack_cnt;
	uint8_t wait_fence;
	/* Outstanding unacknowledged packets count */
	uint8_t wait_rnr_exp;
	int read_rq_bal;
	uint8_t need_rd_credit;
	bool stop_psn;
	bool in_retransmission;
	bool is_read_qp;
	int32_t unacked_window; /* Cached: RDMA_MAX_UNACKED_PSNS - (req.psn - comp.psn) */
};

struct rdma_comp_info {
	uint32_t psn;
	int opcode;
	uint32_t retry_cnt;
	uint32_t rnr_retry;
};

enum rdatm_res_state {
	rdatm_res_state_next,
	rdatm_res_state_new,
	rdatm_res_state_replay,
};

struct resp_res {
	int type;
	int replay;
	uint32_t first_psn;
	uint32_t last_psn;
	uint32_t cur_psn;
	enum rdatm_res_state state;

	/* Read params. */
	uint64_t va_org;
	uint32_t rkey;
	uint32_t length;
	uint64_t va;
	uint32_t resid;
	/* Read params - End */
};

struct rdma_ack {
	uint32_t psn;
	uint32_t last_psn;
	uint32_t msn;
	uint8_t aeth_syndrome;
	uint32_t ack_psn;
	int opcode;
	struct rte_mbuf *mbuf;
	bool is_read;

	STAILQ_ENTRY(rdma_ack) next;
};

struct rdma_resp_info {
	enum rdma_wc_status status;
	struct rdma_recv_wqe wqe;
	rdma_send_wqe_t read_reply;
	uint32_t psn;
	uint32_t ack_psn;
	uint32_t msn;
	int sent_psn_nak;
	int opcode;
	int goto_error;
	int resp_read_rq_bal;
	uint8_t aeth_syndrome;

	STAILQ_HEAD(ack_list, rdma_ack) ack_pending_list;
};

struct rdma_qp_attr {
	uint32_t qkey;
	uint32_t sq_psn;
	uint32_t rq_psn;
	uint32_t pkey_index;
	uint16_t path_mtu;
	uint16_t dest_qp_num;
	uint8_t timeout;
	uint8_t min_rnr_timer;
	uint8_t max_retry_cnt;
	uint8_t max_rnr_retry;
	int max_read_rq_cnt;
	int max_dest_rd_atomic;
	uint8_t sq_draining;
	int qp_access_flags;
};

enum rdma_sig_type { RDMA_SIGNAL_ALL_WR, RDMA_SIGNAL_REQ_WR };

#define RDMA_RETRNS_TIMER 1 << 0
#define RDMA_RNR_TIMER    1 << 1

struct rdma_timer_data {
	uint32_t qp_id;
	uint32_t dev_id;
	uint32_t timer_type;
	struct rte_timer retrans_timer;
	struct rte_timer rnr_timer;
};

typedef struct rdma_qp {
	uint64_t sq_base;
	uint64_t rq_base;
	uint64_t scq_base;
	uint64_t rcq_base;
	uint64_t srq_base;
	struct rdma_resp_info resp;
	struct rdma_req_info req;
	struct rdma_comp_info comp;
	struct rdma_av av;
	struct rdma_qp_attr attr;
	struct rdma_timer_data *timer_data;
	enum rdma_qp_type type;
	enum rdma_qp_state state;
	enum rdma_sig_type sq_sig_type;
	uint32_t qid;
	uint32_t pd_id;
	uint32_t dev_id;
	uint32_t port_id;
	uint32_t dest_qp_num;
	uint32_t qkey;
	uint32_t ssn;
	uint16_t sq_size;
	uint16_t rq_size;
	uint16_t scq_size;
	uint16_t srq_size;
	uint16_t sport;
	uint16_t pkey;
	uint32_t mtu;
	uint32_t lcore;
	uint8_t valid;
	/* DCQCN congestion control state (NP + RP) */
	struct dcqcn_state cc;
} rdma_qp_t;

/* ---- MBUF private-area helpers (embed small objects) ---- */
/* TX layout: [ rdma_send_wr_t | rdma_send_wqe | rdma_mbufs[N] ] */
#define RDMA_TX_PRIV_OFF_WR      0
#define RDMA_TX_PRIV_OFF_WQE     (RDMA_TX_PRIV_OFF_WR + sizeof(rdma_send_wr_t))
#define RDMA_TX_PRIV_OFF_RDMABUF (RDMA_TX_PRIV_OFF_WQE + sizeof(struct rdma_send_wqe))

/* RX layout: [ 32 | sge[mbuf->l2_len] | cqe | ack ]
 * Note: mbuf->l2_len carries the number of SGEs for RX mbufs.
 * For mempool sizing we also provide MAX-based constants.
 */
#define RDMA_RX_PRIV_OFF_BASE 32
#define RDMA_MAX_SGES         DAO_PTS_RDMA_MAX_SGES
#define RDMA_RX_PRIV_OFF_SGE  (RDMA_RX_PRIV_OFF_BASE)
/* Max layout offsets for pool sizing */
#define RDMA_RX_PRIV_OFF_AFTER_SGE_MAX                                                             \
	(RDMA_RX_PRIV_OFF_SGE + RDMA_MAX_SGES * sizeof(struct dao_pts_rdma_sge))
#define RDMA_RX_PRIV_OFF_CQE_MAX (RDMA_RX_PRIV_OFF_AFTER_SGE_MAX)
#define RDMA_RX_PRIV_OFF_ACK_MAX (RDMA_RX_PRIV_OFF_CQE_MAX + sizeof(struct dao_pts_rdma_cqe))

/* Capacity assumptions for inline lists; tune with mbuf priv_size */
#define RDMA_MAX_INLINE_RDMAMB_NODES 32

static inline uint8_t *
rdma_priv_base(struct rte_mbuf *mbuf)
{
	return (uint8_t *)rte_mbuf_to_priv(mbuf);
}

/* TX helpers */
static inline rdma_send_wr_t *
rdma_tx_priv_wr(struct rte_mbuf *owner)
{
	return (rdma_send_wr_t *)(rdma_priv_base(owner) + RDMA_TX_PRIV_OFF_WR);
}

static inline struct rdma_send_wqe *
rdma_tx_priv_wqe(struct rte_mbuf *owner)
{
	return (struct rdma_send_wqe *)(rdma_priv_base(owner) + RDMA_TX_PRIV_OFF_WQE);
}

static inline struct rdma_mbufs *
rdma_tx_priv_rmbuf(struct rte_mbuf *owner)
{
	return (struct rdma_mbufs *)(rdma_priv_base(owner) + RDMA_TX_PRIV_OFF_RDMABUF);
}

/* In READ reply case, avoid overlapping RX private layout by using the
 * beginning of the mbuf private area for the rdma_mbuf node.
 */
static inline struct rdma_mbufs *
rdma_tx_priv_rmbuf_head(struct rte_mbuf *owner)
{
	return (struct rdma_mbufs *)(rdma_priv_base(owner) + RDMA_TX_PRIV_OFF_WR);
}

/* RX helpers — CQE sits after l2_len SGEs, matching PTS DAO_PTS_RDMA_MBUF_TO_CQE */
static inline struct dao_pts_rdma_cqe *
rdma_rx_priv_cqe(struct rte_mbuf *mbuf)
{
	size_t off = RDMA_RX_PRIV_OFF_SGE +
		     mbuf->l2_len * sizeof(struct dao_pts_rdma_sge);

	return (struct dao_pts_rdma_cqe *)(rdma_priv_base(mbuf) + off);
}

static inline struct dao_pts_rdma_sge *
rdma_rx_priv_sge_base(struct rte_mbuf *mbuf)
{
	return (struct dao_pts_rdma_sge *)(rdma_priv_base(mbuf) + RDMA_RX_PRIV_OFF_SGE);
}

static inline struct rdma_ack *
rdma_rx_priv_ack(struct rte_mbuf *mbuf)
{
	size_t off = RDMA_RX_PRIV_OFF_SGE +
		     DAO_PTS_RDMA_MAX_SGES * sizeof(struct dao_pts_rdma_sge) +
		     sizeof(struct dao_pts_rdma_cqe);

	return (struct rdma_ack *)(rdma_priv_base(mbuf) + off);
}

static __rte_always_inline int
is_multicast_qpn(uint32_t qpn)
{
	if (qpn == RDMA_MULTICAST_QPN)
		return 1;

	return 0;
}

static __rte_always_inline int
pkey_match(uint16_t key1, uint16_t key2)
{
	return (((key1 & 0x7fff) != 0) && ((key1 & 0x7fff) == (key2 & 0x7fff)) &&
		((key1 & 0x8000) || (key2 & 0x8000))) ?
		       1 :
		       0;
}

static inline int
psn_compare(uint32_t psn_a, uint32_t psn_b)
{
	int32_t diff;

	diff = (psn_a - psn_b) << 8;
	return diff;
}

/* Slow-path call's */
int rdma_qp_create(void *data);
int rdma_qp_destroy(uint8_t port, uint32_t qid);
int rdma_qp_modify(void *data);
int rdma_qp_init(uint64_t **qp, uint32_t num_qp);
int rdma_qp_free(struct rdma_qp **qp);

/* Fastpath call's */
struct rdma_qp *rdma_qp_query(uint32_t qid, int port);

/*
 * Per-lcore 1-entry cache wrapper for QP lookup.
 * Assumptions:
 * - Packets in a burst often target the same QP, so a tiny cache
 *   eliminates repeated lookups and cache-misses.
 * - Validity is checked on each hit to avoid using a stale QP.
 * - Thread-local storage maps to DPDK lcores.
 */
static __rte_always_inline struct rdma_qp *
rdma_qp_query_fast(uint32_t qid, int portid)
{
	/* 64-entry per-lcore direct-mapped cache to handle many active QPs */
	enum { RDMA_QP_FASTCACHE_SZ = 64 };
	typedef struct {
		uint32_t qid;
		int16_t port;
		int16_t pad;
		struct rdma_qp *qp;
	} ent_t;
	static __thread ent_t cache[RDMA_QP_FASTCACHE_SZ];
	static __thread uint8_t inited;

	if (!inited) {
		for (int i = 0; i < RDMA_QP_FASTCACHE_SZ; i++) {
			cache[i].qid = UINT32_MAX;
			cache[i].port = -1;
			cache[i].qp = NULL;
		}
		inited = 1;
	}

	uint32_t idx = (qid ^ (uint32_t)portid) & (RDMA_QP_FASTCACHE_SZ - 1);
	ent_t *e = &cache[idx];

	if (likely(e->qp && e->qid == qid && e->port == portid && e->qp->valid &&
		   e->qp->qid == qid && (int)e->qp->port_id == portid)) {
		return e->qp;
	}

	struct rdma_qp *qp = rdma_qp_query(qid, portid);

	e->qid = qid;
	e->port = portid;
	e->qp = qp;
	return qp;
}

int rdma_check_keys(struct rdma_pkt_info *pinfo, uint32_t qpn, struct rdma_qp *qp);
int rdma_qp_state_check(struct rdma_pkt_info *pinfo, struct rdma_qp *qp);
int dao_rdma_preprocess_dequeued_pkts(rdma_qp_t *qp, struct rte_mbuf *mbuf);
int rdma_cb_register(rdma_cb_t *cb);

#endif /* __RDMA_QP_H__ */
