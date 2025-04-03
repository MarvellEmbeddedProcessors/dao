/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __CA_ETH_RX_H__
#define __CA_ETH_RX_H__

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_mbuf.h>

#include <dao_eth_trs.h>
#include <dao_liquid_crypto.h>
#include <mc/ae.h>
#include <mc/se.h>

#include "ca_crypto_queue.h"
#include "ca_sess_mgr.h"
#include "cpt_debug.h"
#include "crypto_agent.h"

#define CA_ETHDEV_RX_BURST 32

static inline void
process_pkts(struct rte_mbuf **rx_pkts, uint16_t nb_pkts, struct pending_queue *pq,
	     struct rte_pmd_cnxk_crypto_qptr *cpt_qptr)
{
	struct cpt_inst_s inst[CA_ETHDEV_RX_BURST];
	struct __dao_lc_resp_asym *asym_resp;
	struct cpt_inflight_req *infl_req;
	struct __dao_lc_req_asym *asym;
	uint16_t pkt_id, nb_cpt_bypass;
	struct __dao_lc_req_sym *sym;
	struct dao_eth_trs_pkt *req;
	union cpt_inst_w4 w4;
	uint64_t head;
	uint16_t i;
	int rc = 0;

	const uint64_t pq_mask = pq->pq_mask;

	head = pq->head;

	nb_cpt_bypass = 0;
	for (pkt_id = 0; pkt_id < nb_pkts; pkt_id++) {
		infl_req = &pq->req_queue[head];

		req = rte_pktmbuf_mtod(rx_pkts[pkt_id], struct dao_eth_trs_pkt *);

		infl_req->res.cn9k.compcode = DAO_CPT_COMP_NOT_DONE;

		i = pkt_id - nb_cpt_bypass;
		inst[i].w0.u64 = 0;
		inst[i].res_addr = (uint64_t)&infl_req->res;
		inst[i].w2.u64 = 0;
		inst[i].w3.u64 = 0;

		switch (req->hdr.op_type) {
		case DAO_ETH_TRS_OP_TYPE_REFLECT:
			infl_req->res.cn9k.compcode = DAO_CPT_COMP_GOOD;
			nb_cpt_bypass++;
			break;
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_MISC:
			sym = (struct __dao_lc_req_sym *)req;
			inst[i].w4.s.opcode_major = ROC_SE_MAJOR_OP_MISC;
			inst[i].w4.s.opcode_minor = ROC_SE_MISC_MINOR_OP_PASSTHROUGH;
			inst[i].w4.s.param1 = 1;
			inst[i].w4.s.param2 = 1;
			inst[i].w4.s.dlen = 0;
			inst[i].w5.u64 = (uint64_t)sym->dptr;
			inst[i].w7.u64 = 0;
			inst[i].w7.s.egrp = ROC_LEGACY_CPT_DFLT_ENG_GRP_SE;
			break;
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_SYM:
			sym = (struct __dao_lc_req_sym *)req;
			inst[i].w4.u64 = sym->w4;
			inst[i].w5.u64 = (uint64_t)sym->dptr;
			inst[i].w6.u64 = (uint64_t)sym->dptr; /* INPLACE*/
			inst[i].w7.u64 = sym->w7;
			break;
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_ASYM:
			asym = (struct __dao_lc_req_asym *)req;
			asym_resp = (struct __dao_lc_resp_asym *)req;
			w4.u64 = asym->w4;
			inst[i].w4.u64 = w4.u64;
			inst[i].w5.u64 = (uint64_t)asym->dptr;
			inst[i].w6.u64 = (uint64_t)asym_resp->rptr;
			inst[i].w7.u64 = 0;
			inst[i].w7.s.egrp = ROC_LEGACY_CPT_DFLT_ENG_GRP_AE;

			if (w4.s.opcode_major == ROC_AE_MAJOR_OP_MODEX) {
				infl_req->rsa_mod_len = w4.s.param1;
				infl_req->rsa_is_decrypt = 0;

				if (w4.s.opcode_minor == ROC_AE_MINOR_OP_PKCS_DEC_CRT ||
				    w4.s.opcode_minor == ROC_AE_MINOR_OP_PKCS_DEC) {
					infl_req->rsa_is_decrypt = 1;
					/* Reserve two bytes for output length */
					inst->rptr = (uint64_t)RTE_PTR_SUB(asym_resp->rptr, 2);
				}
			}
			break;
		case DAO_ETH_TRS_OP_TYPE_SYM_SESSION_CREATE:
			rc = ca_sess_handle_create(rx_pkts[pkt_id]);
			infl_req->res.cn9k.compcode = DAO_CPT_COMP_GOOD;
			if (rc != 0)
				CA_INFO("Could not create session: rc: %d", rc);
			nb_cpt_bypass++;
			break;
		case DAO_ETH_TRS_OP_TYPE_SYM_SESSION_DESTROY:
			rc = ca_sess_handle_destroy(rx_pkts[pkt_id]);
			infl_req->res.cn9k.compcode = DAO_CPT_COMP_GOOD;
			if (rc != 0)
				CA_INFO("Could not destroy session: rc: %d", rc);
			nb_cpt_bypass++;
			break;
		default:
			infl_req->res.cn9k.compcode = DAO_CPT_COMP_GOOD;
			nb_cpt_bypass++;
			CA_INFO("Invalid DAO ETH opcode %d", req->hdr.op_type);
			req->hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_END;
		}

		/* Save handle of the packet */
		infl_req->mbuf = rx_pkts[pkt_id];

		pending_queue_advance(&head, pq_mask);
	}

	if ((nb_pkts - nb_cpt_bypass) > 0)
		rte_pmd_cnxk_crypto_submit(cpt_qptr, inst, nb_pkts - nb_cpt_bypass);

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

static inline uint16_t
ca_eth_rx(struct pending_queue *pq, struct rte_pmd_cnxk_crypto_qptr *cpt_qptr,
	  uint16_t nb_cpt_avail)
{
	uint16_t nb_rx, port_id, queue_id, nb_pq_avail;
	struct rte_mbuf *mb[CA_ETHDEV_RX_BURST];

#ifdef CA_DEBUG_ENABLE_PERIODIC_PRINT
	periodic_print();
#endif

	port_id = pq->eth_port_id;
	queue_id = pq->eth_queue_id;

	nb_pq_avail = pending_queue_free_cnt(pq->head, pq->tail, pq->pq_mask);

	nb_rx = RTE_MIN(nb_pq_avail, nb_cpt_avail);
	nb_rx = RTE_MIN(nb_rx, CA_ETHDEV_RX_BURST);
	if (unlikely(nb_rx == 0))
		return 0;

	nb_rx = rte_eth_rx_burst(port_id, queue_id, mb, nb_rx);
	if (nb_rx) {
#ifdef CA_DEBUG_ENABLE_CPT_BYPASS_REFLECT
		process_pkts_reflect(mb, &nb_rx, port_id, 0);
		if (nb_rx == 0)
			continue;
#endif /* CA_DEBUG_ENABLE_CPT_BYPASS_REFLECT */
		process_pkts(mb, nb_rx, pq, cpt_qptr);
	}

	return nb_rx;
}

#endif /* __CA_ETH_RX_H__ */
