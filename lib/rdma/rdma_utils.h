/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */
#include "rdma_hdr.h"
#include <dao_log.h>
#include <dao_pts_rdma_dev.h>

#include <rte_hexdump.h>
#include <rte_mbuf.h>

int dao_send_cqe(struct rdma_qp *qp, bool host_recv, struct rdma_send_wqe *wqe);
int rdma_icrc_check(struct rte_mbuf *mbuf, struct pkt_info *pinfo);
int rdma_icrc_generate(struct rte_mbuf *mbuf, struct rdma_pkt_info *pinfo);
void rdma_pkt_extract(struct rte_mbuf *mbuf, struct pkt_info *pinfo, uint16_t rx_queue, int devid);
int rdma_hdr_check(struct pkt_info *pinfo);
int rdma_opcode_rdma_hdr_len(uint32_t opcode);
extern int rdma_max_segments;

/* Debugging */
static inline void
rdma_dump_data(const unsigned char *packet, size_t length)
{
	for (size_t i = 0; i < length; i++) {
		printf("%02X ", packet[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
	printf("\n");
}

static inline void
rdma_print_mbuf(struct rte_mbuf *mbuf)
{
	printf("MBUF INFO:\n");
	printf("  buf_addr: %p\n", mbuf->buf_addr);
	printf("  data_off: %u\n", mbuf->data_off);
	printf("  data_len: %u\n", mbuf->data_len);
	printf("  pkt_len : %u\n", mbuf->pkt_len);
	printf("  nb_segs : %u\n", mbuf->nb_segs);
	printf("  port    : %u\n", mbuf->port);
	printf("  ol_flags: 0x%" PRIx64 "\n", mbuf->ol_flags);

	// Dump packet data (hex + ASCII)
	rte_pktmbuf_dump(stdout, mbuf, mbuf->pkt_len);
}

static inline void
rdma_make_send_cqe(struct rdma_qp *qp, struct rdma_send_wqe *wqe, struct dao_pts_rdma_cqe *cqe)
{
	cqe->wr_id = wqe->wr->wr_id;
	cqe->status = wqe->status;
	cqe->opcode = wqe->wr->opcode;
	cqe->byte_len = 0;
	cqe->qp_id = qp->qid;
}
