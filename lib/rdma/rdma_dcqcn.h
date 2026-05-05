/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2026 Marvell.
 */

#ifndef __RDMA_DCQCN_H__
#define __RDMA_DCQCN_H__

#include <rte_cycles.h>
#include <stdint.h>

/*
 * DCQCN (Data Center Quantized Congestion Notification) — SIGCOMM 2015.
 *
 * Three logical entities:
 *   CP  – Congestion Point (switch, ECN marking) — out of scope here.
 *   NP  – Notification Point (receiver): detects ECN CE, generates CNPs.
 *   RP  – Reaction Point (sender): adjusts rate on CNP, recovers when idle.
 *
 * Rate control is expressed in bytes-per-microsecond to avoid floating-point.
 * The pacing gate in the requester converts the current rate to an
 * inter-packet interval in TSC cycles.
 */

/* ------------------------------------------------------------------ */
/*  Tunable defaults (compile-time; overridable per-QP after create)  */
/* ------------------------------------------------------------------ */

/* NP: minimum interval between CNP packets for the same flow (us). */
#define DCQCN_NP_CNP_INTERVAL_US 50

/* RP: alpha EWMA weight g = 1/DCQCN_RP_G_DIV.  alpha' = (1-g)*alpha + g */
#define DCQCN_RP_G_DIV 256

/* RP: rate-increase timer period (us). Must be > NP CNP interval. */
#define DCQCN_RP_TIMER_PERIOD_US 55

/* RP: byte-counter threshold for rate increase trigger. */
#define DCQCN_RP_BYTE_THRESHOLD (150 * 1024)

/* RP: fast-recovery round count (F in the paper). */
#define DCQCN_RP_FAST_RECOVERY_F 5

/* RP: additive increase step (bytes/us ≈ MB/s).  50 ≈ ~400 Mbps */
#define DCQCN_RP_RAI_BYTES_PER_US 50

/* RP: hyper-additive increase step (bytes/us). */
#define DCQCN_RP_RHAI_BYTES_PER_US 100

/* RP: alpha timer period for EWMA update (us). */
#define DCQCN_RP_ALPHA_TIMER_US 55

/* Minimum rate floor (bytes/us). ~8 Mbps — never rate-limit below this. */
#define DCQCN_RP_RATE_MIN_BYTES_PER_US 1

/*
 * Maximum iterations when catching up missed timer periods after an idle gap.
 * Alpha decays to 0 (from G_DIV=256) after ~1413 iterations via integer
 * truncation, so any count beyond this is a no-op.  Round up to a safe value.
 */
#define DCQCN_RP_ALPHA_CATCHUP_MAX 1536

/* Cap for rate-increase timer catch-up iterations.  Once cur_rate reaches
 * line_rate the loop breaks early, so this just bounds the worst case.
 */
#define DCQCN_RP_RATE_INC_CATCHUP_MAX 512

/*
 * Minimum RoCEv2 frame overhead added to payload when estimating wire size
 * for pacing: Eth(14) + IPv4(20) + UDP(8) + BTH(12) + ICRC(4) = 58 bytes.
 */
#define DCQCN_ROCEV2_HDR_OVERHEAD 58

/* ------------------------------------------------------------------ */
/*  Per-QP DCQCN state (embedded in struct rdma_qp)                   */
/* ------------------------------------------------------------------ */

struct dcqcn_np_state {
	uint64_t last_cnp_tx_cycles;
	uint64_t cnp_min_interval_cycles;
	uint32_t cnp_tx_cnt;
	uint32_t ecn_ce_marks;
};

struct dcqcn_rp_state {
	/*
	 * Rates are in bytes-per-microsecond.  With 64-bit arithmetic this
	 * gives ~18 EB/s headroom, well above 400 GbE line rate (~50000 B/us).
	 */
	uint64_t cur_rate;    /* RC — current sending rate */
	uint64_t target_rate; /* RT — target rate after cut */
	uint64_t line_rate;   /* Max rate (link speed in B/us) */

	/* Alpha: stored scaled by DCQCN_RP_G_DIV to avoid floating-point.
	 * Real alpha = alpha_scaled / DCQCN_RP_G_DIV.
	 * Initial: DCQCN_RP_G_DIV  (i.e. alpha = 1.0).
	 */
	uint32_t alpha_scaled;

	/* Rate-increase counters (T = timer-based, BC = byte-based). */
	uint32_t timer_count;
	uint32_t byte_count;
	uint64_t bytes_since_last_inc;

	/* Timestamps (TSC cycles). */
	uint64_t last_cnp_rx_cycles;
	uint64_t rate_inc_timer_cycles;
	uint64_t alpha_timer_cycles;
	uint64_t last_send_cycles;
	uint64_t next_send_cycles;

	/* Configurable intervals in cycles (set at QP create). */
	uint64_t rate_inc_period_cycles;
	uint64_t alpha_period_cycles;
	uint64_t byte_threshold;

	/* Rate-increase steps (bytes/us). */
	uint64_t rai;
	uint64_t rhai;
	uint32_t fast_recovery_f;

	uint64_t rate_min;

	uint64_t tsc_hz; /* Cached rte_get_tsc_hz() — avoids per-packet call */

	uint32_t cnp_rx_cnt;
};

struct dcqcn_state {
	struct dcqcn_np_state np;
	struct dcqcn_rp_state rp;
	uint8_t enabled;
};

/* ------------------------------------------------------------------ */
/*  API                                                                */
/* ------------------------------------------------------------------ */

struct rdma_qp;
struct rte_mbuf;

/* Initialization & teardown. */
void dcqcn_init_qp(struct dcqcn_state *cc, uint64_t link_speed_bps);
void dcqcn_global_disable_set(int disable);
int dcqcn_is_globally_disabled(void);

/* NP path: called on receiver when ECN CE detected on incoming request. */
int dcqcn_np_ecn_detected(struct rdma_qp *qp, struct rte_mbuf *rx_mbuf, uint16_t rx_queue);

/* RP path: called on sender when CNP received. */
void dcqcn_rp_cnp_received(struct dcqcn_state *cc);

/*
 * RP pacing gate: called before each packet send.
 * Returns 0 if send is allowed (and updates next_send_cycles).
 * Returns 1 if the packet must be postponed (pacing backpressure).
 *
 * Also drives the timer-based rate increase + alpha decay when timers fire.
 * pkt_len is the wire size of the packet about to be sent.
 */
int dcqcn_rp_pacing_check(struct dcqcn_state *cc, uint32_t pkt_len);

/* CNP packet construction. */
int dcqcn_send_cnp(struct rdma_qp *qp, struct rte_mbuf *rx_mbuf, uint16_t tx_queue);

#endif /* __RDMA_DCQCN_H__ */
