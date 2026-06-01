/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __CA_ETH_RX_H__
#define __CA_ETH_RX_H__

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ring.h>

#include <rte_mbuf.h>

#include <dao_eth_trs.h>
#include <dao_liquid_crypto.h>
#include <mc/ae.h>
#include <mc/se.h>

#include "ca_asym.h"
#include "ca_compress_dev.h"
#include "ca_crypto_queue.h"
#ifdef DAO_LIBOQS_DEP
#include "ca_pqc.h"
#endif
#include "ca_sess_mgr.h"
#include "cpt_debug.h"
#include "crypto_agent.h"

extern struct ca_global_ctx ca_glb_ctx;

static inline void
cpt_infl_req_init(struct cpt_inflight_req *infl_req, struct rte_mbuf *rx_pkt)
{
	infl_req->res.cn9k.compcode = DAO_CPT_COMP_NOT_DONE;
	infl_req->ooo_done = 0;
	infl_req->mbuf = rx_pkt;
}

static inline void
cpt_inst_init(struct cpt_inflight_req *infl_req, struct cpt_inst_s *inst)
{
	inst->w0.u64 = 0;
	inst->res_addr = (uint64_t)&infl_req->res;
	inst->w2.u64 = 0;
	inst->w3.u64 = 0;
}

static inline void
process_pkts(struct rte_mbuf **rx_pkts, uint16_t nb_pkts, struct pending_queue *pq,
	     struct rte_pmd_cnxk_crypto_qptr *cpt_qptr, struct dev_desc_cnt *desc_cnt,
	     const bool compdev_enabled)
{
	struct cpt_inst_s inst[CA_ETHDEV_RX_BURST];
	struct cpt_inflight_req *infl_req = NULL;
	struct __dao_lc_resp_asym *asym_resp;
	uint16_t pkt_id, nb_cpt_bypass = 0;
	struct __dao_lc_req_asym *asym;
	struct __dao_lc_req_sym *sym;
	struct dao_eth_trs_pkt *req;
	uint16_t cpt_inst_cnt = 0;
	uint64_t ctrl_word_be;
	union cpt_inst_w4 w4;
	uint64_t ctrl_word;
	uint16_t label_len;
	uint8_t lcore_id;
	uint64_t head;
	int rc = 0;

	const uint64_t pq_mask = pq->pq_mask;

	head = pq->head;

	for (pkt_id = 0; pkt_id < nb_pkts; pkt_id++) {
		req = rte_pktmbuf_mtod(rx_pkts[pkt_id], struct dao_eth_trs_pkt *);
		switch (req->hdr.op_type) {
		case DAO_ETH_TRS_OP_TYPE_REFLECT:
			infl_req = &pq->cpt_req_queue[head];
			infl_req->res.cn9k.compcode = DAO_CPT_COMP_GOOD;
			infl_req->ooo_done = 0;
			/* Save handle of the packet */
			infl_req->mbuf = rx_pkts[pkt_id];
			pending_queue_advance(&head, pq_mask);
			nb_cpt_bypass++;
			break;
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_MISC:
			infl_req = &pq->cpt_req_queue[head];
			cpt_infl_req_init(infl_req, rx_pkts[pkt_id]);
			cpt_inst_init(infl_req, &inst[cpt_inst_cnt]);

			sym = (struct __dao_lc_req_sym *)req;
			inst[cpt_inst_cnt].w4.s.opcode_major = ROC_SE_MAJOR_OP_MISC;
			inst[cpt_inst_cnt].w4.s.opcode_minor = ROC_SE_MISC_MINOR_OP_PASSTHROUGH;
			inst[cpt_inst_cnt].w4.s.param1 = 1;
			inst[cpt_inst_cnt].w4.s.param2 = 1;
			inst[cpt_inst_cnt].w4.s.dlen = 0;
			inst[cpt_inst_cnt].w5.u64 = (uint64_t)sym->dptr;
			inst[cpt_inst_cnt].w7.u64 = 0;
			inst[cpt_inst_cnt].w7.s.egrp = ROC_LEGACY_CPT_DFLT_ENG_GRP_SE;

			pending_queue_advance(&head, pq_mask);
			cpt_inst_cnt++;
			break;
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_SYM:
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_RNG:
			infl_req = &pq->cpt_req_queue[head];
			cpt_infl_req_init(infl_req, rx_pkts[pkt_id]);
			cpt_inst_init(infl_req, &inst[cpt_inst_cnt]);

			sym = (struct __dao_lc_req_sym *)req;
			infl_req->op_type = sym->op_type;
			infl_req->is_gmac = sym->is_gmac;
			inst[cpt_inst_cnt].w4.u64 = sym->w4;
			inst[cpt_inst_cnt].w5.u64 = (uint64_t)sym->dptr;
			inst[cpt_inst_cnt].w6.u64 = (uint64_t)sym->dptr; /* INPLACE*/
			inst[cpt_inst_cnt].w7.u64 = sym->w7;
			infl_req->sym_param2 = inst[cpt_inst_cnt].w4.s.param2;
			infl_req->stage = 0;
			infl_req->max_stage = 1;

			pending_queue_advance(&head, pq_mask);
			cpt_inst_cnt++;
			break;
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_ASYM:
			infl_req = &pq->cpt_req_queue[head];
			cpt_infl_req_init(infl_req, rx_pkts[pkt_id]);
			cpt_inst_init(infl_req, &inst[cpt_inst_cnt]);

			asym = (struct __dao_lc_req_asym *)req;
			asym_resp = (struct __dao_lc_resp_asym *)req;
			w4.u64 = asym->w4;
			inst[cpt_inst_cnt].w4.u64 = w4.u64;
			inst[cpt_inst_cnt].w5.u64 = (uint64_t)asym->dptr;
			inst[cpt_inst_cnt].w6.u64 = (uint64_t)asym_resp->rptr;
			inst[cpt_inst_cnt].w7.u64 = 0;
			inst[cpt_inst_cnt].w7.s.egrp = ROC_LEGACY_CPT_DFLT_ENG_GRP_AE;
			infl_req->op_type = asym->op_type;
			ca_handle_asym_op(&inst[cpt_inst_cnt], infl_req, asym, asym_resp, w4);
			infl_req->stage = 0;
			infl_req->max_stage = 1;
			pending_queue_advance(&head, pq_mask);
			cpt_inst_cnt++;
			break;
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_OAEP_ENC:
			infl_req = &pq->cpt_req_queue[head];
			cpt_infl_req_init(infl_req, rx_pkts[pkt_id]);
			cpt_inst_init(infl_req, &inst[cpt_inst_cnt]);
			/* stage-0 will be OAEP Encode
			 * stage-1 will be RSA Encrypt
			 */
			asym = (struct __dao_lc_req_asym *)req;
			asym_resp = (struct __dao_lc_resp_asym *)req;
			w4.u64 = asym->w4;
			/* stage-0 will be OAEP */
			infl_req->stage = 0;
			infl_req->max_stage = 2;
			infl_req->rsa_oaep.rsa_exp_len = asym->exp_len;
			infl_req->rsa_mod_len = w4.s.param1;
			inst[cpt_inst_cnt].w4.u64 = asym->w4;
			inst[cpt_inst_cnt].w5.u64 =
				(uint64_t)(asym->dptr + asym->exp_len + infl_req->rsa_mod_len);
			inst[cpt_inst_cnt].w6.u64 =
				(uint64_t)(asym_resp->rptr + asym->exp_len + infl_req->rsa_mod_len);
			inst[cpt_inst_cnt].w7.u64 = 0;
			inst[cpt_inst_cnt].w7.s.egrp = ROC_LEGACY_CPT_DFLT_ENG_GRP_SE;
			infl_req->op_type = asym->op_type;
			pending_queue_advance(&head, pq_mask);
			cpt_inst_cnt++;
			break;
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_OAEP_DEC:
			infl_req = &pq->cpt_req_queue[head];
			cpt_infl_req_init(infl_req, rx_pkts[pkt_id]);
			cpt_inst_init(infl_req, &inst[cpt_inst_cnt]);
			/* stage-0 will be RSA Decrypt
			 * stage-1 will be OAEP Decode
			 */
			asym = (struct __dao_lc_req_asym *)req;
			asym_resp = (struct __dao_lc_resp_asym *)req;
			w4.u64 = asym->w4;
			/* Extract label length from control word (bits 31:15 of dptr) */
			ctrl_word = *(uint64_t *)(asym->dptr);
			ctrl_word_be = rte_be_to_cpu_64(ctrl_word);
			label_len = (ctrl_word_be >> 16) & 0xFFFF;
			infl_req->oaep_label_len = label_len;

			infl_req->rsa_oaep.hash_type = asym->hash_type;
			infl_req->rsa_mod_len = w4.s.param1;
			inst[cpt_inst_cnt].w4.u64 = asym->w4;
			inst[cpt_inst_cnt].w5.u64 =
				(uint64_t)(asym->dptr + CPT_AE_RSA_OAEP_CONTROL_WORD_SIZE +
					   label_len);
			inst[cpt_inst_cnt].w6.u64 =
				(uint64_t)((uint8_t *)asym_resp->rptr +
					   CPT_AE_RSA_OAEP_CONTROL_WORD_SIZE + label_len);
			inst[cpt_inst_cnt].w7.u64 = 0;
			inst[cpt_inst_cnt].w7.s.egrp = ROC_LEGACY_CPT_DFLT_ENG_GRP_AE;
			infl_req->op_type = asym->op_type;
			infl_req->stage = 0;
			infl_req->max_stage = 2;
			pending_queue_advance(&head, pq_mask);
			cpt_inst_cnt++;
			break;
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_PQC:
			infl_req = &pq->cpt_req_queue[head];
			cpt_infl_req_init(infl_req, rx_pkts[pkt_id]);
#ifdef DAO_LIBOQS_DEP
			rc = ca_pqc_process(rx_pkts[pkt_id], &infl_req->res);
			if (rc != 0) {
				CA_INFO("Could not process PQC operation");
				infl_req->res.pqc.compcode = DAO_PQC_COMP_ERROR;
			} else {
				infl_req->res.pqc.compcode = DAO_PQC_COMP_GOOD;
			}
#else
			CA_INFO("PQC support not available - liboqs not found");
			infl_req->res.pqc.compcode = DAO_PQC_COMP_LIB_ERROR_LIBOQS;
#endif
			infl_req->stage = 0;
			infl_req->max_stage = 1;

			pending_queue_advance(&head, pq_mask);
			nb_cpt_bypass++;
			break;
		case DAO_ETH_TRS_OP_TYPE_SYM_SESSION_CREATE:
			infl_req = &pq->cpt_req_queue[head];
			cpt_infl_req_init(infl_req, rx_pkts[pkt_id]);

			rc = ca_sess_handle_create(rx_pkts[pkt_id]);
			infl_req->res.cn9k.compcode = DAO_CPT_COMP_GOOD;
			if (rc != 0)
				CA_INFO("Could not create session: rc: %d", rc);
			pending_queue_advance(&head, pq_mask);
			nb_cpt_bypass++;
			break;
		case DAO_ETH_TRS_OP_TYPE_SYM_SESSION_DESTROY:
			infl_req = &pq->cpt_req_queue[head];
			cpt_infl_req_init(infl_req, rx_pkts[pkt_id]);

			rc = ca_sess_handle_destroy(rx_pkts[pkt_id]);
			infl_req->res.cn9k.compcode = DAO_CPT_COMP_GOOD;
			if (rc != 0)
				CA_INFO("Could not destroy session: rc: %d", rc);
			pending_queue_advance(&head, pq_mask);
			nb_cpt_bypass++;
			break;
		case DAO_ETH_TRS_OP_TYPE_COMPRESS:
		case DAO_ETH_TRS_OP_TYPE_DECOMPRESS:
			if (compdev_enabled) {
				lcore_id = rte_lcore_id();
				rte_ring_enqueue(
					ca_glb_ctx.compdev_ctx[lcore_id].comp_req_ring[lcore_id],
					rx_pkts[pkt_id]);
				desc_cnt->comp_req_ring_enq_cnt++;
			} else {
				infl_req = &pq->cpt_req_queue[head];
				cpt_infl_req_init(infl_req, rx_pkts[pkt_id]);
				infl_req->res.cn9k.compcode = DAO_CPT_COMP_GOOD;
				nb_cpt_bypass++;
				CA_INFO("Invalid DAO ETH opcode %d", req->hdr.op_type);
				req->hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_END;
				pending_queue_advance(&head, pq_mask);
			}
			break;
		default:
			infl_req = &pq->cpt_req_queue[head];
			cpt_infl_req_init(infl_req, rx_pkts[pkt_id]);
			infl_req->res.cn9k.compcode = DAO_CPT_COMP_GOOD;
			nb_cpt_bypass++;
			CA_INFO("Invalid DAO ETH opcode %d", req->hdr.op_type);
			req->hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_END;
			pending_queue_advance(&head, pq_mask);
		}
#ifdef CA_DEBUG_ENABLE
		if (req->hdr.op_type == DAO_ETH_TRS_OP_TYPE_CRYPTO_ASYM ||
		    req->hdr.op_type == DAO_ETH_TRS_OP_TYPE_CRYPTO_SYM ||
		    req->hdr.op_type == DAO_ETH_TRS_OP_TYPE_CRYPTO_MISC ||
		    req->hdr.op_type == DAO_ETH_TRS_OP_TYPE_CRYPTO_RNG)
			cpt_debug_inst_print(&inst[cpt_inst_cnt - 1]);
#endif
	}

	if (likely(cpt_inst_cnt > 0)) {
		rte_pmd_cnxk_crypto_submit(cpt_qptr, inst, cpt_inst_cnt);
		desc_cnt->cpt -= cpt_inst_cnt;
	}

	pq->time_out = rte_get_timer_cycles() + DEFAULT_COMMAND_TIMEOUT * rte_get_timer_hz();
	pq->head = head;
}

#ifdef CA_DEBUG_ENABLE_CPT_BYPASS_REFLECT
static void
process_pkts_reflect(struct rte_mbuf **rx_pkts, uint16_t *nb_pkts, uint8_t port_id,
		     uint8_t queue_id)
{
	struct rte_mbuf *mb_cpt[CA_ETHDEV_RX_BURST], *mb_tx[CA_ETHDEV_RX_BURST];
	uint16_t i, nb_cpt, nb_tx;
	struct __dao_lc_hdr *hdr;

	nb_cpt = 0;
	nb_tx = 0;

	for (i = 0; i < *nb_pkts; i++) {
		hdr = rte_pktmbuf_mtod(rx_pkts[i], struct __dao_lc_hdr *);

		if (hdr->trs_hdr.op_type == DAO_ETH_TRS_OP_TYPE_REFLECT)
			mb_tx[nb_tx++] = rx_pkts[i];
		else
			mb_cpt[nb_cpt++] = rx_pkts[i];
	}

	if (nb_tx) {
		rte_eth_tx_burst(port_id, queue_id, mb_tx, nb_tx);

		*nb_pkts = nb_cpt;
		if (nb_cpt)
			memcpy(rx_pkts, mb_cpt, nb_cpt * sizeof(struct rte_mbuf *));
	}
}
#endif /* CA_DEBUG_ENABLE_CPT_BYPASS_REFLECT */

#ifdef CA_DEBUG_ENABLE_PERIODIC_PRINT
static inline void
periodic_print(void)
{
	static uint64_t last_time;
	uint64_t cur_time;

	cur_time = rte_get_timer_cycles();

	/* Print every minute */
	if (cur_time - last_time > 60 * rte_get_timer_hz()) {
		CA_INFO("Waiting for packets on ethdevs");
		last_time = cur_time;
	}
}
#endif /* CA_DEBUG_ENABLE_PERIODIC_PRINT */

/*
 * Process a single COMPRESS or DECOMPRESS packet when compress device is enabled.
 * Caller must ensure compdev is enabled before calling.
 * Returns 1 on success (caller should increment nb_comp_req), 0 on failure (caller may continue).
 */
static inline int
process_compdev_pkt(struct dao_eth_trs_pkt *req, struct rte_mbuf *mbuf,
		    struct comp_dev_inflight_req *infl_req, struct rte_comp_op *comp_op)
{
	return prepare_comp_op(req, infl_req, comp_op, mbuf);
}

static inline int
process_compdev_pkt_noop(struct dao_eth_trs_pkt *req, struct rte_mbuf *mbuf,
			 struct comp_dev_inflight_req *infl_req, struct rte_comp_op *comp_op)
{
	RTE_SET_USED(req);
	RTE_SET_USED(infl_req);
	rte_comp_op_free(comp_op);
	rte_pktmbuf_free(mbuf);
	return 0;
}
static inline uint16_t
ca_eth_rx(struct lcore_conf *lconf, int pq_id, struct rte_pmd_cnxk_crypto_qptr *cpt_qptr,
	  struct dev_desc_cnt *desc_cnt, const bool compdev_enabled)
{
	uint16_t nb_cpt_pq_avail, nb_compdev_pq_avail;
	struct pending_queue *cpt_pq, *compdev_pq;
	struct rte_mbuf *mb[CA_ETHDEV_RX_BURST];
	uint16_t nb_rx, port_id, queue_id;

#ifdef CA_DEBUG_ENABLE_PERIODIC_PRINT
	periodic_print();
#endif
	cpt_pq = lconf->pq[pq_id];

	port_id = cpt_pq->eth_port_id;
	queue_id = cpt_pq->eth_queue_id;

	nb_cpt_pq_avail = pending_queue_free_cnt(cpt_pq->head, cpt_pq->tail, cpt_pq->pq_mask);
	nb_rx = RTE_MIN(nb_cpt_pq_avail, desc_cnt->cpt);
	nb_rx = RTE_MIN(nb_rx, CA_ETHDEV_RX_BURST);

	if (compdev_enabled) {
		compdev_pq = lconf->compdev_pq[pq_id];
		nb_compdev_pq_avail = pending_queue_free_cnt(compdev_pq->head, compdev_pq->tail,
							     compdev_pq->pq_mask);
		nb_rx = RTE_MIN(nb_rx, nb_compdev_pq_avail);
		nb_rx = RTE_MIN(nb_rx, desc_cnt->compdev);
	}

	if (unlikely(nb_rx == 0))
		return 0;

	nb_rx = rte_eth_rx_burst(port_id, queue_id, mb, nb_rx);
	if (nb_rx) {
#ifdef CA_DEBUG_ENABLE_CPT_BYPASS_REFLECT
		process_pkts_reflect(mb, &nb_rx, port_id, 0);
		if (nb_rx == 0)
			return 0;
#endif /* CA_DEBUG_ENABLE_CPT_BYPASS_REFLECT */
		process_pkts(mb, nb_rx, cpt_pq, cpt_qptr, desc_cnt, compdev_enabled);
	}

	return nb_rx;
}

#endif /* __CA_ETH_RX_H__ */
