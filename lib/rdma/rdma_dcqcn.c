/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2026 Marvell.
 */

/*
 * Full DCQCN (Data Center Quantized Congestion Notification) implementation.
 *
 * Reference: "Congestion Control for Large-Scale RDMA Deployments",
 *            Y. Zhu et al., SIGCOMM 2015.
 *
 * This file implements the end-device roles:
 *   NP (Notification Point) — receiver-side ECN detection & CNP generation.
 *   RP (Reaction Point)     — sender-side rate control on CNP feedback.
 *
 * The CP (Congestion Point / switch ECN marking) is handled by the network
 * fabric and is out of scope for this implementation.
 */

#include <string.h>

#include <dao_log.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "rdma_counter.h"
#include "rdma_dcqcn.h"
#include "rdma_hdr.h"
#include "rdma_net.h"
#include "rdma_opcode.h"
#include "rdma_qp.h"
#include "rdma_utils.h"

/* ------------------------------------------------------------------ */
/*  Global CC toggle                                                   */
/* ------------------------------------------------------------------ */

static uint8_t g_dcqcn_disabled;

void
dcqcn_global_disable_set(int disable)
{
	g_dcqcn_disabled = !!disable;
}

int
dcqcn_is_globally_disabled(void)
{
	return g_dcqcn_disabled;
}

/* ------------------------------------------------------------------ */
/*  Helper: convert link speed in bps to bytes-per-microsecond         */
/* ------------------------------------------------------------------ */

static inline uint64_t
bps_to_bytes_per_us(uint64_t link_speed_bps)
{
	return link_speed_bps / (8ULL * 1000000ULL);
}

/* ------------------------------------------------------------------ */
/*  Helper: convert rate (bytes/us) to inter-packet interval (cycles)  */
/* ------------------------------------------------------------------ */

static inline uint64_t
rate_to_ipg_cycles(uint64_t tsc_hz, uint64_t rate_bytes_per_us, uint32_t pkt_len)
{
	if (rate_bytes_per_us == 0)
		return 0;

	/*
	 * interval_us = pkt_len / rate_bytes_per_us
	 * interval_cycles = interval_us * (hz / 1e6)
	 * Combined: (pkt_len * hz) / (rate_bytes_per_us * 1e6)
	 */
	return (uint64_t)pkt_len * tsc_hz / (rate_bytes_per_us * 1000000ULL);
}

/* ------------------------------------------------------------------ */
/*  QP initialization                                                  */
/* ------------------------------------------------------------------ */

void
dcqcn_init_qp(struct dcqcn_state *cc, uint64_t link_speed_bps)
{
	uint64_t hz = rte_get_tsc_hz();
	struct dcqcn_rp_state *rp;
	uint64_t line_rate;

	memset(cc, 0, sizeof(*cc));

	cc->enabled = g_dcqcn_disabled ? 0 : 1;
	if (!cc->enabled)
		return;

	line_rate = bps_to_bytes_per_us(link_speed_bps);
	if (line_rate == 0)
		line_rate = bps_to_bytes_per_us(100ULL * 1000000000ULL); /* default 100 GbE */

	/* ---- NP defaults ---- */
	cc->np.cnp_min_interval_cycles = hz * DCQCN_NP_CNP_INTERVAL_US / 1000000ULL;
	cc->np.last_cnp_tx_cycles = 0;
	cc->np.cnp_tx_cnt = 0;
	cc->np.ecn_ce_marks = 0;

	/* ---- RP defaults ---- */
	rp = &cc->rp;

	rp->line_rate = line_rate;
	rp->cur_rate = line_rate;
	rp->target_rate = line_rate;

	rp->alpha_scaled = DCQCN_RP_G_DIV; /* alpha = 1.0 initially */

	rp->timer_count = 0;
	rp->byte_count = 0;
	rp->bytes_since_last_inc = 0;

	rp->last_cnp_rx_cycles = 0;
	rp->rate_inc_timer_cycles = 0;
	rp->alpha_timer_cycles = 0;
	rp->last_send_cycles = 0;
	rp->next_send_cycles = 0;

	rp->rate_inc_period_cycles = hz * DCQCN_RP_TIMER_PERIOD_US / 1000000ULL;
	rp->alpha_period_cycles = hz * DCQCN_RP_ALPHA_TIMER_US / 1000000ULL;
	rp->byte_threshold = DCQCN_RP_BYTE_THRESHOLD;

	rp->rai = DCQCN_RP_RAI_BYTES_PER_US;
	rp->rhai = DCQCN_RP_RHAI_BYTES_PER_US;
	rp->fast_recovery_f = DCQCN_RP_FAST_RECOVERY_F;

	rp->rate_min = DCQCN_RP_RATE_MIN_BYTES_PER_US;

	rp->tsc_hz = hz;

	rp->cnp_rx_cnt = 0;
}

/* ================================================================== */
/*  NP  —  Notification Point (receiver side)                          */
/* ================================================================== */

/*
 * Build and send a minimal CNP packet for a given QP.
 * Rate-limited to one CNP per cnp_min_interval_cycles.
 */
int
dcqcn_send_cnp(struct rdma_qp *qp, struct rte_mbuf *rx_mbuf, uint16_t tx_queue)
{
	struct dcqcn_np_state *np;
	uint32_t port_id, lcore_id, qp_id;
	struct rdma_pkt_info pinfo = {0};
	struct rte_mbuf *mbuf;
	uint64_t now;
	uint16_t sent;

	if (unlikely(!qp || !rx_mbuf))
		return -1;

	np = &qp->cc.np;
	port_id = qp->port_id;
	lcore_id = qp->lcore;
	qp_id = qp->qid;

	if (!qp->cc.enabled)
		return 0;

	now = rte_get_tsc_cycles();

	if (now - np->last_cnp_tx_cycles < np->cnp_min_interval_cycles) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_CNP_THROTTLED);
		return 0;
	}

	mbuf = rte_pktmbuf_alloc(rx_mbuf->pool);
	if (unlikely(!mbuf)) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_SEND_CNP_MBUF_ALLOC_FAIL);
		return -1;
	}

	pinfo.qp = qp;
	pinfo.opcode = RDMA_OPCODE_CNP;
	pinfo.mask = 0;
	pinfo.psn = 0;
	pinfo.paylen = RDMA_BTH_BYTES + RDMA_ICRC_SIZE;
	pinfo.hdr = (uint8_t *)rte_pktmbuf_prepend(mbuf, RDMA_BTH_BYTES);
	if (unlikely(!pinfo.hdr)) {
		rte_pktmbuf_free(mbuf);
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
				    RDMA_RX_QP_SEND_CNP_MBUF_PREPEND_FAIL);
		return -1;
	}

	bth_init(&pinfo, 0, 0, 0, BTH_DEF_PKEY, qp->dest_qp_num, 0, 0);

	rdma_mbuf_init(mbuf);

	if (rdma_net_hdr_insert(mbuf, &qp->av, qp->sport) < 0) {
		rte_pktmbuf_free(mbuf);
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_SEND_CNP_NET_HDR_INS_FAIL);
		return -1;
	}

	if (rdma_icrc_generate(mbuf, &pinfo) < 0) {
		rte_pktmbuf_free(mbuf);
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_SEND_CNP_ICRC_GEN_FAIL);
		return -1;
	}

	sent = rte_eth_tx_burst(qp->port_id, tx_queue, &mbuf, 1);
	if (sent != 1) {
		rte_pktmbuf_free(mbuf);
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_SEND_CNP_TX_BURST_FAIL);
		return -1;
	}

	np->cnp_tx_cnt++;
	np->last_cnp_tx_cycles = now;
	RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_CNP_SENT);
	return 0;
}

/*
 * NP entry point: receiver detected ECN CE on an incoming request packet.
 * Bumps counters and (rate-limited) sends a CNP back to the requester.
 */
int
dcqcn_np_ecn_detected(struct rdma_qp *qp, struct rte_mbuf *rx_mbuf, uint16_t rx_queue)
{
	if (!qp || !qp->cc.enabled)
		return 0;

	RDMA_INC_QP_COUNTER(qp->lcore, qp->port_id, qp->qid, RDMA_RX_QP_ECN_CE_DETECTED);
	qp->cc.np.ecn_ce_marks++;
	return dcqcn_send_cnp(qp, rx_mbuf, rx_queue);
}

/* ================================================================== */
/*  RP  —  Reaction Point (sender side)                                */
/* ================================================================== */

/*
 * RP: called when a CNP is received for this QP.
 *
 * Equations from SIGCOMM'15 §3.1:
 *   RT = RC
 *   RC = RC * (1 - alpha/2)
 *   alpha = (1 - g) * alpha + g
 *   Reset(Timer, ByteCounter, T, BC)
 */
void
dcqcn_rp_cnp_received(struct dcqcn_state *cc)
{
	struct dcqcn_rp_state *rp = &cc->rp;
	uint64_t two_g = 2ULL * DCQCN_RP_G_DIV;
	uint64_t now = rte_get_tsc_cycles();

	rp->cnp_rx_cnt++;
	rp->last_cnp_rx_cycles = now;

	/* RT = RC */
	rp->target_rate = rp->cur_rate;

	/*
	 * RC = RC * (1 - alpha/2)
	 * With alpha_scaled = alpha * G_DIV:
	 *   RC = RC * (2*G_DIV - alpha_scaled) / (2*G_DIV)
	 */

	rp->cur_rate = rp->cur_rate * (two_g - rp->alpha_scaled) / two_g;
	if (rp->cur_rate < rp->rate_min)
		rp->cur_rate = rp->rate_min;

	/*
	 * alpha = (1 - g) * alpha + g
	 * alpha_scaled' = alpha_scaled * (G_DIV - 1) / G_DIV + 1
	 */
	rp->alpha_scaled = rp->alpha_scaled * (DCQCN_RP_G_DIV - 1) / DCQCN_RP_G_DIV + 1;
	if (rp->alpha_scaled > DCQCN_RP_G_DIV)
		rp->alpha_scaled = DCQCN_RP_G_DIV;

	/* Reset timer, byte counter, T, BC */
	rp->rate_inc_timer_cycles = now;
	rp->alpha_timer_cycles = now;
	rp->timer_count = 0;
	rp->byte_count = 0;
	rp->bytes_since_last_inc = 0;
}

/*
 * RP rate increase logic (internal).  Called from pacing_check when the
 * rate-increase timer or byte counter fires.
 *
 * From the paper §3.1, Figure 7:
 *   if max(T, BC) < F          → Fast Recovery:  RC = (RT + RC)/2
 *   else if min(T, BC) > F     → Hyper Increase: RT += R_HAI; RC = (RT + RC)/2
 *   else                       → Additive Increase: RT += R_AI; RC = (RT + RC)/2
 */
static inline void
dcqcn_rp_rate_increase(struct dcqcn_rp_state *rp)
{
	uint32_t f = rp->fast_recovery_f;
	uint32_t t_max = RTE_MAX(rp->timer_count, rp->byte_count);
	uint32_t t_min = RTE_MIN(rp->timer_count, rp->byte_count);

	if (t_max < f) {
		/* Fast Recovery: RC = (RT + RC) / 2 */
		rp->cur_rate = (rp->target_rate + rp->cur_rate) / 2;
	} else if (t_min > f) {
		/* Hyper Increase */
		rp->target_rate += rp->rhai;
		rp->cur_rate = (rp->target_rate + rp->cur_rate) / 2;
	} else {
		/* Additive Increase */
		rp->target_rate += rp->rai;
		rp->cur_rate = (rp->target_rate + rp->cur_rate) / 2;
	}

	/* Clamp to line rate. */
	if (rp->cur_rate > rp->line_rate)
		rp->cur_rate = rp->line_rate;
	if (rp->target_rate > rp->line_rate)
		rp->target_rate = rp->line_rate;
}

/*
 * RP alpha decay: when the alpha timer fires without a CNP arriving.
 *
 * From §3.1, Equation (2):
 *   alpha = (1 - g) * alpha
 *   alpha_scaled' = alpha_scaled * (G_DIV - 1) / G_DIV
 */
static inline void
dcqcn_rp_alpha_decay(struct dcqcn_rp_state *rp)
{
	rp->alpha_scaled = rp->alpha_scaled * (DCQCN_RP_G_DIV - 1) / DCQCN_RP_G_DIV;
}

/*
 * RP pacing gate — called before every packet send.
 *
 * Drives timers inline (polled model, no async timer threads):
 *   1. Alpha timer → decay alpha if no CNP.
 *   2. Rate-increase timer → bump T, call rate_increase().
 *   3. Byte counter → bump BC, call rate_increase().
 *   4. Check inter-packet gap.
 *
 * Returns 0 if send is allowed; 1 if send must be postponed.
 */
int
dcqcn_rp_pacing_check(struct dcqcn_state *cc, uint32_t pkt_len)
{
	struct dcqcn_rp_state *rp = &cc->rp;
	uint64_t now = rte_get_tsc_cycles();
	int rate_changed = 0;

	if (!cc->enabled)
		return 0;

	/*
	 * No CNP ever received — congestion control is not active.
	 * Avoids spurious timer firing (timestamps are 0 at init) and
	 * unnecessary IPG enforcement at line rate before any congestion.
	 */
	if (rp->last_cnp_rx_cycles == 0)
		return 0;

	/* Fully recovered: at line rate with alpha decayed to zero. */
	if (rp->cur_rate >= rp->line_rate && rp->alpha_scaled == 0)
		return 0;

	/* --- Alpha timer (catch up missed periods after idle gaps) --- */
	if (rp->alpha_period_cycles) {
		uint64_t a_elapsed = now - rp->alpha_timer_cycles;

		if (a_elapsed >= rp->alpha_period_cycles) {
			uint64_t n = a_elapsed / rp->alpha_period_cycles;

			if (n > DCQCN_RP_ALPHA_CATCHUP_MAX) {
				rp->alpha_scaled = 0;
			} else {
				for (uint64_t i = 0; i < n; i++)
					dcqcn_rp_alpha_decay(rp);
			}
			rp->alpha_timer_cycles += n * rp->alpha_period_cycles;
		}
	}

	/* --- Rate-increase timer (catch up missed periods) --- */
	if (rp->rate_inc_period_cycles) {
		uint64_t r_elapsed = now - rp->rate_inc_timer_cycles;

		if (r_elapsed >= rp->rate_inc_period_cycles) {
			uint64_t n = r_elapsed / rp->rate_inc_period_cycles;
			uint64_t cap = (n > DCQCN_RP_RATE_INC_CATCHUP_MAX) ?
					       DCQCN_RP_RATE_INC_CATCHUP_MAX :
					       n;
			uint64_t processed = 0;

			for (uint64_t i = 0; i < cap; i++) {
				rp->timer_count++;
				dcqcn_rp_rate_increase(rp);
				processed++;
				if (rp->cur_rate >= rp->line_rate)
					break;
			}
			/*
			 * Fully recovered → skip all remaining events.
			 * Otherwise advance only by what was processed so
			 * the remaining missed events are preserved.
			 */
			if (rp->cur_rate >= rp->line_rate)
				rp->rate_inc_timer_cycles += n * rp->rate_inc_period_cycles;
			else
				rp->rate_inc_timer_cycles += processed * rp->rate_inc_period_cycles;
			rate_changed = 1;
		}
	}

	/* --- Byte counter (BC counter) --- */
	if (rp->byte_threshold && rp->bytes_since_last_inc >= rp->byte_threshold) {
		rp->byte_count++;
		dcqcn_rp_rate_increase(rp);
		rp->bytes_since_last_inc = 0;
		rate_changed = 1;
	}

	/*
	 * If rate has recovered to line rate and alpha has fully decayed,
	 * stop enforcing pacing.
	 */
	if (rate_changed && rp->cur_rate >= rp->line_rate) {
		rp->cur_rate = rp->line_rate;
		rp->target_rate = rp->line_rate;
		rp->last_send_cycles = 0;
		rp->next_send_cycles = 0;
		return 0;
	}

	/* IPG enforcement only when rate is actually below line rate. */
	if (rp->cur_rate < rp->line_rate) {
		uint64_t ipg = rate_to_ipg_cycles(rp->tsc_hz, rp->cur_rate, pkt_len);
		uint64_t deadline = rp->last_send_cycles + ipg;

		if (ipg && now < deadline)
			return 1; /* postpone */

		rp->last_send_cycles = now;
		rp->next_send_cycles = now + ipg;
	}

	rp->bytes_since_last_inc += pkt_len;
	return 0;
}
