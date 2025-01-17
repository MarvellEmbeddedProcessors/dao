/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __CA_CPT_DEQ_H__
#define __CA_CPT_DEQ_H__

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_mbuf.h>

#include <dao_eth_trs.h>
#include <dao_liquid_crypto.h>
#include <liquid_crypto_trs.h>
#include <mc/ae.h>

#include "ca_crypto_queue.h"
#include "ca_dp.h"
#include "crypto_agent.h"

static inline void
ca_cpt_post_process_asym(struct cpt_inflight_req *infl_req, union dao_cpt_res_s *res)
{
	struct __dao_lc_resp_asym *resp;
	uint8_t *rptr;

	resp = rte_pktmbuf_mtod(infl_req->mbuf, struct __dao_lc_resp_asym *);
	rptr = resp->rptr;
	if (infl_req->rsa_is_decrypt) {
		/* For PKCS decryption operations, the decrypted message length is stored in the
		 * reserved field of the response buffer.
		 */
		res->cn9k.reserved_17_63 = rte_cpu_to_be_16(*((uint16_t *)RTE_PTR_SUB(rptr, 2)));
	} else {
		/* For encryption operations, the dequeue API in the host library needs the
		 * modulus length to copy the data from the inflight request to the response buffer.
		 */
		res->cn9k.reserved_17_63 = infl_req->rsa_mod_len;
	}
	memcpy(&resp->res, res, sizeof(union dao_cpt_res_s));
}

static inline void
ca_cpt_deq(struct pending_queue *pq)
{
	struct cpt_inflight_req *infl_req;
	struct dao_eth_trs_pkt *req;
	union dao_cpt_res_s res;
	uint16_t nb_pending, i;
	uint64_t head, tail;
	int nb_tx;

	const uint64_t pq_mask = pq->pq_mask;

	head = pq->head;
	tail = pq->tail;

	nb_pending = pending_queue_infl_cnt(head, tail, pq_mask);
	if (nb_pending == 0)
		return;

	for (i = 0; i < nb_pending; i++) {
		infl_req = &pq->req_queue[tail];

		res.u64[0] = __atomic_load_n(&infl_req->res.u64[0], __ATOMIC_RELAXED);

		if (unlikely(res.cn9k.compcode == DAO_CPT_COMP_NOT_DONE)) {
			if (unlikely(rte_get_timer_cycles() > pq->time_out)) {
				CA_ERR("Request timed out");
				pq->time_out = rte_get_timer_cycles() +
					       DEFAULT_COMMAND_TIMEOUT * rte_get_timer_hz();
			}
			break;
		}

		pending_queue_advance(&tail, pq_mask);

		/* Process the packet */
		req = rte_pktmbuf_mtod(infl_req->mbuf, struct dao_eth_trs_pkt *);
		switch (req->hdr.op_type) {
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_ASYM:
			ca_cpt_post_process_asym(infl_req, &res);
			break;
		default:
			break;
		}

		nb_tx = rte_eth_tx_burst(0, 0, &infl_req->mbuf, 1);
		CA_ERR("%d packets sent to host", nb_tx);
	}

	pq->tail = tail;
}

#endif /* __CA_CPT_DEQ_H__ */
