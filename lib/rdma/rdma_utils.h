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

/* WR-opcode to WC-opcode lookup: nibble N of RDMA_WR_WC_MAP holds the
 * WC completion opcode for WR opcode N (opcodes 0-15).
 *   WR 0/1 (RDMA_WRITE, WRITE_WITH_IMM) -> WC 1 (RDMA_WRITE)
 *   WR 2/3 (SEND, SEND_WITH_IMM)        -> WC 0 (SEND)
 *   WR 4   (RDMA_READ)                  -> WC 2 (RDMA_READ)
 *   WR 5-15 pass through unchanged.
 * Opcodes > 15 are returned as-is.
 */
#define RDMA_WR_WC_MAP UINT64_C(0xfedcba9876520011)

static inline uint8_t
rdma_wr_to_wc_opcode(uint8_t wr_opcode)
{
	if (unlikely(wr_opcode > 15))
		return wr_opcode;
	return (RDMA_WR_WC_MAP >> ((uint32_t)wr_opcode << 2)) & 0xFU;
}

static inline void
rdma_make_send_cqe(struct rdma_qp *qp, struct rdma_send_wqe *wqe, struct dao_pts_rdma_cqe *cqe)
{
	cqe->wr_id = wqe->wr->wr_id;
	cqe->status = wqe->status;
	cqe->opcode = rdma_wr_to_wc_opcode(wqe->wr->opcode);
	cqe->byte_len = 0;
	cqe->qp_id = qp->qid;
}
