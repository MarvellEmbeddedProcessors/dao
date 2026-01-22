/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2026 Marvell.
 */

#include <dao_log.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "rdma_hdr.h"
#include "rdma_net.h"
#include "rdma_opcode.h"
#include "rdma_qp.h"
#include "rdma_utils.h"

/* Build and send a minimal CNP packet immediately (out-of-band). */
int
rdma_send_cnp(struct rdma_qp *qp, struct rte_mbuf *rx_mbuf)
{
	if (unlikely(!qp || !rx_mbuf))
		return -1;
	if (!qp->cc.cc_enabled)
		return 0;

	uint64_t now = rte_get_tsc_cycles();

	if (now - qp->cc.last_cnp_tx_cycles < qp->cc.cnp_min_interval_cycles)
		return 0; /* throttled */

	/* Allocate new mbuf from same pool as triggering packet */
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(rx_mbuf->pool);

	if (unlikely(!mbuf))
		return -1;

	struct rdma_pkt_info pinfo = {0};

	pinfo.qp = qp;
	pinfo.opcode = RDMA_OPCODE_CNP;
	pinfo.mask = 0;                                 /* No payload */
	pinfo.psn = 0;                                  /* Not used by CNP */
	pinfo.paylen = RDMA_BTH_BYTES + RDMA_ICRC_SIZE; /* BTH + ICRC */
	pinfo.hdr = (uint8_t *)rte_pktmbuf_prepend(mbuf, RDMA_BTH_BYTES);
	if (unlikely(!pinfo.hdr)) {
		rte_pktmbuf_free(mbuf);
		return -1;
	}

	/* Initialize BTH (no ACK req, psn=0) */
	bth_init(&pinfo, 0, 0, 0, BTH_DEF_PKEY, qp->dest_qp_num, 0, 0);

	/* Insert L2/L3/L4 headers */
	if (rdma_net_hdr_insert(mbuf, &qp->av, qp->sport) < 0) {
		rte_pktmbuf_free(mbuf);
		return -1;
	}

	/* Compute ICRC */
	if (rdma_icrc_generate(mbuf, &pinfo) < 0) {
		rte_pktmbuf_free(mbuf);
		return -1;
	}

	/* Transmit immediately on port 'qp->port_id', queue 0. */
	uint16_t sent = rte_eth_tx_burst(qp->port_id, 0, &mbuf, 1);

	if (sent != 1) {
		rte_pktmbuf_free(mbuf);
		return -1;
	}

	qp->cc.cnp_tx_cnt++;
	qp->cc.last_cnp_tx_cycles = now;
	return 0;
}
