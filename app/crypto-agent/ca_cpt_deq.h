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
	default:
		break;
	}
}

/* Decide if a completed request needs another CPT stage. */
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

	memset(inst, 0, sizeof(*inst));
	inst->res_addr = (uint64_t)&infl_req->res;

	switch (req->hdr.op_type) {
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

static inline uint16_t
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

#endif /* __CA_CPT_DEQ_H__ */
