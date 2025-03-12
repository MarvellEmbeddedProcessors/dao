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
#include "cpt_debug.h"
#include "crypto_agent.h"

#define CA_ETHDEV_TX_BURST 64

static inline void
ca_cpt_post_process_asym(struct cpt_inflight_req *infl_req, union dao_cpt_res_s *res)
{
	struct __dao_lc_resp_asym *resp;
	uint16_t rlen, pkt_len;
	struct rte_mbuf *mb;
	uint8_t *rptr;

	mb = infl_req->mbuf;
	resp = rte_pktmbuf_mtod(mb, struct __dao_lc_resp_asym *);

	if (unlikely(infl_req->res.cn9k.uc_compcode != DAO_UC_RSA_SUCCESS)) {
		rlen = 0;
		goto rlen_set;
	}

	rptr = resp->rptr;
	if (infl_req->rsa_is_decrypt) {
		/* For decryption operations, the dequeue API in the host library needs the
		 * length of the decrypted data to copy the data from the inflight request to the
		 * response buffer.
		 */
		rlen = rte_cpu_to_be_16(*((uint16_t *)RTE_PTR_SUB(rptr, 2)));
	} else {
		/* For encryption operations, the length of the encrypted data is already
		 * present in the response buffer.
		 */
		rlen = infl_req->rsa_mod_len;
	}

rlen_set:
	/* Copy the response in reserved field of response buffer */
	res->cn9k.reserved_17_63 = rlen;

	memcpy(&resp->res, res, sizeof(union dao_cpt_res_s));

	/* Set the length of the response buffer */
	pkt_len = sizeof(struct __dao_lc_resp_asym) + rlen;
	resp->hdr.trs_hdr.op_len = pkt_len;

	pkt_len = RTE_MAX(pkt_len, ETH_DEV_MIN_BUF_LEN);

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
ca_cpt_deq(struct pending_queue *pq)
{
	struct rte_mbuf *mb[CA_ETHDEV_TX_BURST];
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

	nb_pending = RTE_MIN(nb_pending, CA_ETHDEV_TX_BURST);

	for (i = 0; i < nb_pending; i++) {
		infl_req = &pq->req_queue[tail];

		res.u64[0] = __atomic_load_n(&infl_req->res.u64[0], __ATOMIC_RELAXED);

		if (unlikely(res.cn9k.compcode == DAO_CPT_COMP_NOT_DONE)) {
			if (unlikely(rte_get_timer_cycles() > pq->time_out)) {
				CA_ERR("Request timed out");
				pq->time_out = rte_get_timer_cycles() +
					       DEFAULT_COMMAND_TIMEOUT * rte_get_timer_hz();
			}

			if (unlikely(i == 0))
				return;
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

#ifdef CPT_DEBUG_ENABLE
		cpt_debug_res_print(infl_req);
#endif
		mb[i] = infl_req->mbuf;
	}

	nb_tx = rte_eth_tx_burst(pq->eth_port_id, pq->eth_queue_id, mb, i);

#ifdef CA_DEBUG_ENABLE
	if (unlikely(nb_tx < i))
		CA_ERR("Could not transmit all packets");
#endif /* CA_DEBUG_ENABLE */

	RTE_SET_USED(nb_tx);

	pq->tail = tail;
}

#endif /* __CA_CPT_DEQ_H__ */
