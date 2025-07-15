/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __CA_CPT_DEQ_H__
#define __CA_CPT_DEQ_H__

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <dao_eth_trs.h>
#include <dao_liquid_crypto.h>
#include <liquid_crypto_trs.h>
#include <mc/ae.h>
#include <mc/se.h>

#include "ca_asym.h"
#include "ca_crypto_queue.h"
#include "cpt_debug.h"
#include "crypto_agent.h"

#define CA_ETHDEV_TX_BURST 64
#define CA_GMAC_IV_LEN     16
#define CA_GMAC_DIGEST_LEN 16

#define CA_ETHDEV_RX_BURST 32
#define CA_CPT_OOO_WINDOW  64

static inline void
ca_cpt_post_process_asym(struct cpt_inflight_req *infl_req, union dao_cpt_res_s *res)
{
	struct __dao_lc_resp_asym *resp;
	uint16_t rlen = 0, pkt_len;
	struct rte_mbuf *mb;
	uint8_t *rptr;

	mb = infl_req->mbuf;
	resp = rte_pktmbuf_mtod(mb, struct __dao_lc_resp_asym *);

	if (unlikely(infl_req->res.cn9k.uc_compcode != DAO_UC_SUCCESS)) {
		rlen = 0;
		pkt_len = sizeof(struct __dao_lc_resp_asym);
		goto rlen_set;
	}

	rptr = resp->rptr;
	switch (infl_req->op_type) {
	case LC_ASYM_RSA_ENCRYPT:
		/* For RSA operations, the length of the modulus is used as the length of
		 * the output data.
		 */
		rlen = infl_req->rsa_mod_len;
		/* Set the length of the response buffer */
		pkt_len = sizeof(struct __dao_lc_resp_asym) + rlen;
		break;
	case LC_ASYM_RSA_DECRYPT:
		/* For decryption operations, the dequeue API in the host library needs the
		 * length of the decrypted data to copy the data from the inflight request to the
		 * response buffer.
		 */
		rlen = rte_cpu_to_be_16(*((uint16_t *)RTE_PTR_SUB(rptr, 2)));
		/* Set the length of the response buffer */
		pkt_len = sizeof(struct __dao_lc_resp_asym) + rlen;
		break;
	case LC_ASYM_ECDSA_SIGN:
		/* For ECDSA sign, the lengths of r and s components are equal to the
		 * prime length.
		 */
		rlen = infl_req->ec_prime_len;
		/* Set the length of the response buffer */
		pkt_len = sizeof(struct __dao_lc_resp_asym) + (rlen + RTE_ALIGN_CEIL(rlen, 8));
		break;
	default:
		rlen = 0;
		/* Set the length of the response buffer */
		pkt_len = sizeof(struct __dao_lc_resp_asym) + rlen;
		break;
	}

rlen_set:
	/* Copy the response in reserved field of response buffer */
	res->cn9k.reserved_17_63 = rlen;

	memcpy(&resp->res, res, sizeof(union dao_cpt_res_s));

	pkt_len = RTE_MAX(pkt_len, ETH_DEV_MIN_BUF_LEN);
	resp->hdr.trs_hdr.op_len = pkt_len;

#ifdef CA_DEBUG_ENABLE
	if (unlikely(pkt_len > mb->buf_len)) {
		CA_ERR("Response buffer too small. Trimming buffer.");
		pkt_len = mb->buf_len;
	}
#endif /* CA_DEBUG_ENABLE */

	/* Set the length of the packet */
	mb->pkt_len = pkt_len;
	mb->data_len = pkt_len;
}

static inline void
ca_cpt_post_process_sym(struct cpt_inflight_req *infl_req, union dao_cpt_res_s *res)
{
	struct __dao_lc_resp_sym *resp;
	struct rte_mbuf *mb;
	uint16_t pkt_len;

	mb = infl_req->mbuf;
	resp = rte_pktmbuf_mtod(mb, struct __dao_lc_resp_sym *);

	/* Host to trim the packet start to get the final result of crypto operation */
	memcpy(&resp->res, res, sizeof(union dao_cpt_res_s));

	switch (infl_req->op_type) {
	case LC_SYM_OP_AUTH_ONLY:
	case LC_SYM_OP_HMAC_AUTH_ONLY:
		if (infl_req->is_gmac) {
			/* inflq_req->sym_param2 = GMAC input data length */
			uint8_t *gmac_digest_ptr =
				(uint8_t *)resp->rptr + infl_req->sym_param2 + CA_GMAC_IV_LEN;

			if (gmac_digest_ptr + CA_GMAC_DIGEST_LEN > (uint8_t *)resp + mb->buf_len) {
				CA_ERR("GMAC buffer overflow detected");
				rte_errno = EINVAL;
				return;
			}
			memcpy(resp->rptr, gmac_digest_ptr, CA_GMAC_DIGEST_LEN);
			pkt_len = sizeof(struct __dao_lc_resp_sym) + CA_GMAC_DIGEST_LEN;
		} else {
			pkt_len = sizeof(struct __dao_lc_resp_sym) + (infl_req->sym_param2 & 0xFF);
		}

		pkt_len = RTE_MAX(pkt_len, ETH_DEV_MIN_BUF_LEN);
		mb->pkt_len = pkt_len;
		mb->data_len = pkt_len;
		break;
	default:
		break;
	}

#ifdef CA_DEBUG_ENABLE
	rte_pktmbuf_dump(stdout, mb, rte_pktmbuf_pkt_len(mb));
#endif
}

static inline void
ca_cpt_post_process_random(struct cpt_inflight_req *infl_req, union dao_cpt_res_s *res)
{
	struct __dao_lc_resp_sym *resp;
	struct rte_mbuf *mb;

	mb = infl_req->mbuf;
	resp = rte_pktmbuf_mtod(mb, struct __dao_lc_resp_sym *);

	memcpy(&resp->res, res, sizeof(union dao_cpt_res_s));
}

static inline void
ca_cpt_post_process_oaep_enc(struct cpt_inflight_req *infl_req, union dao_cpt_res_s *res)
{
	struct __dao_lc_resp_asym *resp;
	uint16_t rlen = 0, pkt_len = 0;
	struct rte_mbuf *mb;

	mb = infl_req->mbuf;
	resp = rte_pktmbuf_mtod(mb, struct __dao_lc_resp_asym *);

	if (unlikely(infl_req->res.cn9k.uc_compcode != DAO_UC_SUCCESS)) {
		rlen = 0;
		pkt_len = sizeof(struct __dao_lc_resp_asym);

		/* Error case marking current stage to max stage */
		infl_req->stage = infl_req->max_stage;
		goto rlen_set;
	}

	switch (infl_req->op_type) {
	case LC_ASYM_RSA_OAEP_ENCODE:
		/* No error detected; proceed to RSA encryption in the next stage */
		return;
	case LC_ASYM_RSA_OAEP_ENCRYPT:
		/* Final stage. No further processing */
		/* For RSA operations, the length of the modulus is used as the length of
		 * the output data.
		 */
		rlen = infl_req->rsa_mod_len;
		/* Set the length of the response buffer */
		pkt_len = sizeof(struct __dao_lc_resp_asym) + rlen;
		break;
	default:
		break;
	}

rlen_set:
	/* Copy the response in reserved field of response buffer */
	res->cn9k.reserved_17_63 = rlen;

	memcpy(&resp->res, res, sizeof(union dao_cpt_res_s));

	pkt_len = RTE_MAX(pkt_len, ETH_DEV_MIN_BUF_LEN);
	resp->hdr.trs_hdr.op_len = pkt_len;

#ifdef CA_DEBUG_ENABLE
	if (unlikely(pkt_len > mb->buf_len)) {
		CA_ERR("Response buffer too small. Trimming buffer.");
		pkt_len = mb->buf_len;
	}
#endif /* CA_DEBUG_ENABLE */

	/* Set the length of the packet */
	mb->pkt_len = pkt_len;
	mb->data_len = pkt_len;
}

static inline void
ca_cpt_post_process_oaep_dec(struct cpt_inflight_req *infl_req, union dao_cpt_res_s *res)
{
	struct __dao_lc_resp_asym *resp;
	uint16_t rlen = 0, pkt_len = 0;
	struct rte_mbuf *mb;

	mb = infl_req->mbuf;
	resp = rte_pktmbuf_mtod(mb, struct __dao_lc_resp_asym *);

	if (unlikely(infl_req->res.cn9k.uc_compcode != DAO_UC_SUCCESS)) {
		pkt_len = sizeof(struct __dao_lc_resp_asym);
		rlen = 0;

		/* Error Case marking current stage to max stage */
		infl_req->stage = infl_req->max_stage;
		goto rlen_set;
	}

	switch (infl_req->op_type) {
	case LC_ASYM_RSA_OAEP_DECRYPT:
		/* Moving to next stage which is OAEP decode */
		return;
	case LC_ASYM_RSA_OAEP_DECODE:
		/* Final stage. No further processing */
		rlen = rte_cpu_to_be_16(*((uint16_t *)RTE_PTR_SUB(resp->rptr, 2)));
		/* Set the length of the response buffer */
		pkt_len = sizeof(struct __dao_lc_resp_asym) + rlen;
		break;
	default:
		break;
	}

rlen_set:
	/* Copy the response in reserved field of response buffer */
	res->cn9k.reserved_17_63 = rlen;
	memcpy(&resp->res, res, sizeof(union dao_cpt_res_s));

	pkt_len = RTE_MAX(pkt_len, ETH_DEV_MIN_BUF_LEN);
	resp->hdr.trs_hdr.op_len = pkt_len;
#ifdef CA_DEBUG_ENABLE
	if (unlikely(pkt_len > mb->buf_len)) {
		CA_ERR("Response buffer too small. Trimming buffer.");
		pkt_len = mb->buf_len;
	}
#endif /* CA_DEBUG_ENABLE */
	/* Set the length of the packet */
	mb->pkt_len = pkt_len;
	mb->data_len = pkt_len;
}

static inline void
ca_cpt_post_process_pqc(struct cpt_inflight_req *infl_req, union dao_cpt_res_s *res)
{
	struct __dao_lc_resp_pqc *resp;
	struct rte_mbuf *mb;
	uint16_t pkt_len;

	mb = infl_req->mbuf;
	resp = rte_pktmbuf_mtod(mb, struct __dao_lc_resp_pqc *);

	memcpy(&resp->res, res, sizeof(union dao_cpt_res_s));
	/* Set the length of the response buffer */
	pkt_len = sizeof(struct __dao_lc_resp_pqc) + res->pqc.data_out_len;
	pkt_len = RTE_MAX(pkt_len, ETH_DEV_MIN_BUF_LEN);
	mb->pkt_len = pkt_len;
	mb->data_len = pkt_len;
}

/* Common post-processing function based on operation type */
static inline void
ca_cpt_post_process(struct cpt_inflight_req *req, union dao_cpt_res_s *res)
{
	struct dao_eth_trs_pkt *trs = rte_pktmbuf_mtod(req->mbuf, struct dao_eth_trs_pkt *);

	/* Increment the stage */
	req->stage++;
	switch (trs->hdr.op_type) {
	case DAO_ETH_TRS_OP_TYPE_CRYPTO_ASYM:
		ca_cpt_post_process_asym(req, res);
		break;
	case DAO_ETH_TRS_OP_TYPE_CRYPTO_SYM:
		ca_cpt_post_process_sym(req, res);
		break;
	case DAO_ETH_TRS_OP_TYPE_CRYPTO_RNG:
		ca_cpt_post_process_random(req, res);
		break;
	case DAO_ETH_TRS_OP_TYPE_CRYPTO_OAEP_ENC:
		ca_cpt_post_process_oaep_enc(req, res);
		break;
	case DAO_ETH_TRS_OP_TYPE_CRYPTO_OAEP_DEC:
		ca_cpt_post_process_oaep_dec(req, res);
		break;
	case DAO_ETH_TRS_OP_TYPE_CRYPTO_PQC:
		ca_cpt_post_process_pqc(req, res);
		break;
	default:
		break;
	}
}

/* Determine whether a completed request requires an additional CPT processing stage. */
static inline int
ca_cpt_need_resubmit(struct cpt_inflight_req *infl_req)
{
	if (infl_req->stage < infl_req->max_stage)
		return 1;
	return 0;
}

/* Build new instruction for next stage */
static inline void
ca_cpt_build_next_stage(struct cpt_inflight_req *infl_req, struct cpt_inst_s *inst)
{
	struct dao_eth_trs_pkt *req = rte_pktmbuf_mtod(infl_req->mbuf, struct dao_eth_trs_pkt *);
	struct __dao_lc_resp_asym *asym_resp = (struct __dao_lc_resp_asym *)req;
	struct __dao_lc_req_asym *asym = (struct __dao_lc_req_asym *)req;
	uint16_t mod_len, exp_len, hash_type;
	uint8_t *rptr;

	memset(inst, 0, sizeof(*inst));
	inst->res_addr = (uint64_t)&infl_req->res;

	switch (req->hdr.op_type) {
	case DAO_ETH_TRS_OP_TYPE_CRYPTO_OAEP_ENC:
		/* Stage-1 will be RSA encrypt */
		/* Populate and submit for RSA pubkey encryption operation */
		inst->w4.s.opcode_major = ROC_AE_MAJOR_OP_MODEX;
		inst->w4.s.opcode_minor = ROC_AE_MINOR_OP_MODEX_EXP;
		mod_len = infl_req->rsa_mod_len;
		exp_len = infl_req->rsa_oaep.rsa_exp_len;
		inst->w4.s.param1 = mod_len;
		inst->w4.s.param2 = exp_len;
		/* Copy encoded message from asym_resp->rptr + exp_len + mod_len
		 * up to mod_len bytes, copied after in asym->dptr + mod_len + exp_len
		 */
		memcpy((uint8_t *)asym->dptr + mod_len + exp_len,
		       (uint8_t *)asym_resp->rptr + exp_len + mod_len, mod_len);
		inst->w4.s.dlen = (mod_len * 2) + exp_len;
		inst->w5.s.dptr = (uint64_t)asym->dptr;
		inst->w6.s.rptr = (uint64_t)asym_resp->rptr;
		inst->w7.u64 = 0;
		inst->w7.s.egrp = ROC_LEGACY_CPT_DFLT_ENG_GRP_AE;
		infl_req->op_type = LC_ASYM_RSA_OAEP_ENCRYPT;
		break;
	case DAO_ETH_TRS_OP_TYPE_CRYPTO_OAEP_DEC:
		/* Populate and submit for OAEP Decode operation */
		uint64_t ctrl_word = *(uint64_t *)(asym->dptr);
		uint64_t ctrl_word_be = rte_be_to_cpu_64(ctrl_word);
		uint16_t label_len = (ctrl_word_be >> 16) & 0xFFFF;
		uint8_t *dptr;

		hash_type = infl_req->rsa_oaep.hash_type;
		mod_len = infl_req->rsa_mod_len;

		inst->w4.s.opcode_major = ROC_SE_MAJOR_OP_OAEP_ENCODE_DECODE;
		inst->w4.s.opcode_minor = ROC_SE_MINOR_OP_OAEP_DECODE;
		inst->w4.s.param1 = mod_len;
		inst->w4.s.param2 = (hash_type & 0xF) << 8;
		inst->w4.s.dlen = mod_len + CPT_AE_RSA_OAEP_CONTROL_WORD_SIZE + label_len;
		rptr = asym_resp->rptr + CPT_AE_RSA_OAEP_CONTROL_WORD_SIZE + label_len;

		/* Copy the decrypted message to the dptr to decode using OAEP */
		memcpy((uint8_t *)asym->dptr + CPT_AE_RSA_OAEP_CONTROL_WORD_SIZE + label_len, rptr,
		       infl_req->rsa_mod_len);

		dptr = (uint8_t *)asym->dptr;
		*(uint64_t *)dptr = rte_cpu_to_be_64(((uint64_t)label_len << 16) |
						     ((uint64_t)infl_req->rsa_mod_len));
		inst->w5.s.dptr = (uint64_t)asym->dptr;
		inst->w6.s.rptr = (uint64_t)RTE_PTR_SUB(asym_resp->rptr, 2);
		inst->w7.u64 = 0;
		inst->w7.s.egrp = ROC_LEGACY_CPT_DFLT_ENG_GRP_SE;
		infl_req->op_type = LC_ASYM_RSA_OAEP_DECODE;
		break;
	default:
		break;
	}
	infl_req->res.cn9k.compcode = DAO_CPT_COMP_NOT_DONE;
}

static inline int
ca_cpt_process_multistage(struct cpt_inflight_req *req, struct cpt_inst_s *inst_resub,
			  bool *is_resub)
{
	/* Decide if more stages required */
	if (ca_cpt_need_resubmit(req)) {
		ca_cpt_build_next_stage(req, inst_resub);
		*is_resub = true;
		return 0; /* keep slot, not final yet */
	}
	/* resubmit array full: force finalize */
	req->stage = req->max_stage; /* treat as final */
	return 1;                    /* final stage, ready for post-processing */
}

uint16_t
ca_cpt_deq(struct pending_queue *pq, struct rte_pmd_cnxk_crypto_qptr *cpt_qptr)
{
	struct rte_mbuf *mb_tx[CA_ETHDEV_TX_BURST];
	struct cpt_inflight_req *infl_req;
	const uint64_t mask = pq->pq_mask;
	uint16_t nb_pending, i, nb_tx;
	struct cpt_inst_s inst_resub;
	uint64_t head, tail, pq_tail;
	union dao_cpt_res_s res;
	bool is_resub = false;
	head = pq->head;
	tail = pq->tail;
	pq_tail = tail;

	nb_pending = pending_queue_infl_cnt(head, tail, mask);
	if (nb_pending == 0)
		return 0;

	nb_pending = RTE_MIN(nb_pending, CA_ETHDEV_TX_BURST);

	for (i = 0; i < nb_pending; i++) {
		infl_req = &pq->req_queue[(pq_tail + i) & mask];
		res.u64[0] = __atomic_load_n(&infl_req->res.u64[0], __ATOMIC_RELAXED);
		if (unlikely(res.cn9k.compcode == DAO_CPT_COMP_NOT_DONE)) {
			if (unlikely(rte_get_timer_cycles() > pq->time_out)) {
				CA_ERR("Request timed out");
				pq->time_out = rte_get_timer_cycles() +
					       DEFAULT_COMMAND_TIMEOUT * rte_get_timer_hz();
			}
			break;
		}

		ca_cpt_post_process(infl_req, &res);
		if (!ca_cpt_process_multistage(infl_req, &inst_resub, &is_resub)) {
		} else {
			/* Final stage, prepare for TX */
			mb_tx[i] = infl_req->mbuf;
			pending_queue_advance(&tail, mask);
		}

		if (is_resub)
			break;
	}

	if (is_resub) {
		rte_pmd_cnxk_crypto_submit(cpt_qptr, &inst_resub, is_resub);
		is_resub = false;
	}

	nb_tx = rte_eth_tx_burst(pq->eth_port_id, pq->eth_queue_id, mb_tx, i);
#ifdef CA_DEBUG_ENABLE
	if (unlikely(nb_tx < i))
		CA_ERR("Could not transmit all packets");
#endif /* CA_DEBUG_ENABLE */

	pq->tail = tail;

	return nb_tx;
}

/* Common multi-stage processing function (OOO variant)
 * Returns: 0 = needs resubmit (keep slot), 1 = final stage ready for post-processing
 */
static inline int
ca_cpt_process_multistage_ooo(struct cpt_inflight_req *req, struct cpt_inst_s *inst_resub,
			      uint16_t *n_resub, uint16_t max_resub)
{
	/* Decide if more stages required */
	if (ca_cpt_need_resubmit(req)) {
		if (*n_resub < max_resub) {
			ca_cpt_build_next_stage(req, &inst_resub[*n_resub]);
			(*n_resub)++;
			return 0; /* keep slot, not final yet */
		}
		/* resubmit array full: force finalize */
		req->stage = req->max_stage; /* treat as final */
	}

	return 1; /* final stage, ready for post-processing */
}

uint16_t
ca_cpt_deq_ooo(struct pending_queue *pq, struct rte_pmd_cnxk_crypto_qptr *cpt_qptr)
{
	const uint64_t mask = pq->pq_mask;
	uint64_t head = pq->head;
	uint64_t tail = pq->tail;
	uint64_t infl;

	infl = pending_queue_infl_cnt(head, tail, mask);
	if (!infl)
		return 0;

	uint16_t scan = RTE_MIN((uint16_t)infl, (uint16_t)CA_CPT_OOO_WINDOW);
	struct cpt_inst_s inst_resub[CA_ETHDEV_RX_BURST];
	struct rte_mbuf *tx_batch[CA_ETHDEV_TX_BURST];
	uint16_t batch_cnt = 0;
	uint16_t n_resub = 0;
	uint16_t sent = 0;
	uint64_t now = 0; /* Cache timer for lazy timeout check */

	/* First pass: scan window, post-process completions, collect TX */
	for (uint16_t off = 0; off < scan; off++) {
		struct cpt_inflight_req *req = &pq->req_queue[(tail + off) & mask];
		union dao_cpt_res_s res;

		/* Prefetch next request to reduce cache misses */
		if (likely(off + 1 < scan))
			rte_prefetch0(&pq->req_queue[(tail + off + 1) & mask]);

		/* If already marked done (final stage processed earlier) skip processing */
		if (req->ooo_done)
			continue;

		res.u64[0] = __atomic_load_n(&req->res.u64[0], __ATOMIC_ACQUIRE);

		if (res.cn9k.compcode == DAO_CPT_COMP_NOT_DONE) {
			/* Lazy timeout check: only call timer once */
			if (unlikely(now == 0))
				now = rte_get_timer_cycles();
			if (unlikely(now > pq->time_out)) {
				CA_ERR("Request timed out");
				pq->time_out = now + DEFAULT_COMMAND_TIMEOUT * rte_get_timer_hz();
			}
			continue;
		}

		ca_cpt_post_process(req, &res);

		/* Process multi-stage logic */
		if (!ca_cpt_process_multistage_ooo(req, inst_resub, &n_resub, CA_ETHDEV_RX_BURST))
			continue; /* needs resubmit, keep slot */

		/* Final stage: mark done and collect for TX */
		req->ooo_done = 1;
		tx_batch[batch_cnt] = req->mbuf;
		batch_cnt++;
	}

	if (batch_cnt)
		sent = rte_eth_tx_burst(pq->eth_port_id, pq->eth_queue_id, tx_batch, batch_cnt);

	/* Submit any collected resubmits after TX to minimize latency */
	if (n_resub)
		rte_pmd_cnxk_crypto_submit(cpt_qptr, inst_resub, n_resub);

	/* Tail reclamation: advance tail past completed packets */
	while (infl) {
		struct cpt_inflight_req *req = &pq->req_queue[tail & mask];

		/* Can only reclaim if processing is done */
		if (!req->ooo_done)
			break;

		/* Packet successfully processed and transmitted - reclaim the slot */
		req->ooo_done = 0;
		pending_queue_advance(&tail, mask);
		infl--;
	}
	pq->tail = tail;
	return sent;
}

#endif /* __CA_CPT_DEQ_H__ */
