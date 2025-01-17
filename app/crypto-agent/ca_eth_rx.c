/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_mbuf.h>

#include "hw/cpt.h"
#include "mc/se.h"

#include "ca_crypto_queue.h"
#include "ca_dp.h"
#include "crypto_agent.h"
#include "dao_eth_trs.h"
#include "liquid_crypto_trs.h"

#define CA_ETHDEV_RX_BURST 32

static void
process_pkts(struct rte_mbuf **rx_pkts, uint16_t nb_pkts, struct pending_queue *pq)
{
	struct cpt_inst_s inst[CA_ETHDEV_RX_BURST];
	struct __dao_lc_resp_asym *asym_resp;
	struct cpt_inflight_req *infl_req;
	struct __dao_lc_req_asym *asym;
	struct __dao_lc_req_sym *sym;
	struct dao_eth_trs_pkt *req;
	uint64_t head, tail;
	uint16_t i;

	const uint64_t pq_mask = pq->pq_mask;

	head = pq->head;
	tail = pq->tail;

	RTE_SET_USED(tail);

	for (i = 0; i < nb_pkts; i++) {
		infl_req = &pq->req_queue[head];

		req = rte_pktmbuf_mtod(rx_pkts[i], struct dao_eth_trs_pkt *);

		infl_req->res.cn10k.compcode = CPT_COMP_NOT_DONE;

		inst[i].w0.u64 = 0;
		inst[i].res_addr = (uint64_t)&infl_req->res;
		inst[i].w2.u64 = 0;
		inst[i].w3.u64 = 0;

		switch (req->hdr.op_type) {
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
			inst[i].w6.u64 = 0;
			inst[i].w7.u64 = sym->w7;
			break;
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_ASYM:
			asym = (struct __dao_lc_req_asym *)req;
			asym_resp = (struct __dao_lc_resp_asym *)req;
			inst[i].w4.u64 = asym->w4;
			inst[i].w5.u64 = (uint64_t)asym->dptr;
			inst[i].w6.u64 = (uint64_t)asym_resp->rptr;
			inst[i].w7.u64 = 0;
			inst[i].w7.s.egrp = ROC_LEGACY_CPT_DFLT_ENG_GRP_AE;
			break;
		default:
			CA_INFO("Invalid DAO ETH opcode %d", req->hdr.op_type);
		}

		/* Save handle of the packet */
		infl_req->mbuf = rx_pkts[i];

		pending_queue_advance(&head, pq_mask);
	}

	rte_pmd_cnxk_crypto_submit(pq->cpt_qptr, inst, nb_pkts);

	pq->time_out = rte_get_timer_cycles() + DEFAULT_COMMAND_TIMEOUT * rte_get_timer_hz();
	pq->head = head;
}

void
ca_eth_rx(uint16_t nb_valid_ethdevs, struct pending_queue *pq)
{
	struct rte_mbuf *mb[CA_ETHDEV_RX_BURST];
	uint16_t nb_rx, port_id;
	static int count;

	if (count % 10 == 0)
		CA_INFO("Waiting for packets on ethdevs");

	count++;
	rte_delay_ms(100);

	for (port_id = 0; port_id < nb_valid_ethdevs; port_id++) {
		nb_rx = rte_eth_rx_burst(port_id, 0, mb, CA_ETHDEV_RX_BURST);
		if (nb_rx) {
			CA_INFO("Received %u packets on port %u", nb_rx, port_id);
			process_pkts(mb, nb_rx, pq);
		}
	}
}
