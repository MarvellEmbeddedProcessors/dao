/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */
#include <rte_net_crc.h>
#include <rte_prefetch.h>
#include <string.h>

#include "rdma_qp.h"
#include "rdma_utils.h"
#include "rdma_counter.h"

#if defined(__aarch64__)
#include <arm_acle.h>
#endif

void
rdma_pkt_extract(struct rte_mbuf *mbuf, struct pkt_info *pinfo, uint16_t rx_queue, int devid)
{
	pinfo->ptype = mbuf->packet_type & RTE_PTYPE_L3_MASK;
	pinfo->mbuf = mbuf;
	pinfo->rx_queue = rx_queue;

	pinfo->port_num = devid;
	pinfo->hdr_len = 0;

	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

	pinfo->hdr_len += sizeof(struct rte_ether_hdr);

	uint8_t *l3_hdr = (uint8_t *)(eth_hdr + 1);

	pinfo->iph = l3_hdr;

	if (pinfo->ptype & RTE_PTYPE_L3_IPV4) {
		pinfo->udph = l3_hdr + sizeof(struct rte_ipv4_hdr);
		pinfo->hdr_len += sizeof(struct rte_ipv4_hdr);
	} else {
		pinfo->udph = l3_hdr + sizeof(struct rte_ipv6_hdr);
		pinfo->hdr_len += sizeof(struct rte_ipv6_hdr);
	}

	struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)pinfo->udph;

	pinfo->rinfo.hdr = (uint8_t *)(udp_hdr + 1);
	pinfo->hdr_len += sizeof(struct rte_udp_hdr);

	pinfo->rinfo.opcode = bth_opcode(&pinfo->rinfo);
	pinfo->rinfo.psn = bth_psn(&pinfo->rinfo);
	pinfo->rinfo.pkey_index = 0;
	pinfo->rinfo.mask = RDMA_GRH_MASK | rdma_opcode[pinfo->rinfo.opcode].mask;
	pinfo->rinfo.paylen = rte_be_to_cpu_16(udp_hdr->dgram_len) - sizeof(struct rte_udp_hdr);
	pinfo->hdr_len += rdma_opcode[pinfo->rinfo.opcode].length;

	pinfo->rinfo.reth =
		(struct rdma_reth *)(pinfo->rinfo.hdr +
				     rdma_opcode[pinfo->rinfo.opcode].offset[RDMA_RETH]);

	switch (pinfo->rinfo.opcode) {
	case RDMA_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE:
	case RDMA_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE:
	case RDMA_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
	case RDMA_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE:
	case RDMA_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE:
		pinfo->rinfo.imm_data =
			*((uint32_t *)(pinfo->rinfo.hdr +
				       rdma_opcode[pinfo->rinfo.opcode].offset[RDMA_IMMDT]));
		break;
	default:
		break;
	}
}

/* XXX: Shift this function to rdma_av.c */
static int
rdma_check_addr(struct pkt_info *pinfo, struct rdma_qp *qp)
{
	if (qp->type != RDMA_QPT_RC && qp->type != RDMA_QPT_UC)
		return 0;

	if (unlikely(pinfo->port_num != qp->port_id))
		return -EINVAL;

	if (pinfo->ptype & RTE_PTYPE_L3_IPV4) {
		/* Compare src,dst ip-address in packet with that present in AV */
		/* TODO */

	} else if (pinfo->ptype & RTE_PTYPE_L3_IPV6) {
		/* Compare src,dst ip-address in packet with that present in AV */
		/* TODO */
	}

	return 0;
}

int
rdma_hdr_check(struct pkt_info *pinfo)
{
	unsigned int lcore_id = rte_lcore_id();
	uint32_t qpn = bth_qpn(&pinfo->rinfo);
	uint32_t port_id = pinfo->port_num;
	struct rdma_qp *qp;
	int err;

	if (unlikely(bth_tver(&pinfo->rinfo) != BTH_TVER)) {
		RDMA_INC_PORT_COUNTER(lcore_id, port_id, RDMA_RX_PORT_HDR_CHK_BTH_TVER_FAIL);
		return -1;
	}

	/* XXX: Multicast QP is not supported in initial version. */
	if (unlikely(is_multicast_qpn(qpn))) {
		RDMA_INC_PORT_COUNTER(lcore_id, port_id, RDMA_RX_PORT_HDR_CHK_MULTICAST_QP_FAIL);
		return -1;
	}

	qp = rdma_qp_query_fast(qpn, pinfo->port_num);
	if (unlikely(qp == NULL)) {
		RDMA_INC_PORT_COUNTER(lcore_id, port_id, RDMA_RX_PORT_HDR_CHK_QP_INV);
		return -1;
	}

	if (qp->lcore != rte_lcore_id()) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qpn,
				    RDMA_RX_QP_HDR_CHK_ACCESS_QP_BY_NON_OWNER_LCORE);
		return -1;
	}

	err = rdma_qp_state_check(&pinfo->rinfo, qp);
	if (unlikely(err)) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qpn, RDMA_RX_QP_HDR_CHK_QP_STATE_INV);
		return -1;
	}

	err = rdma_check_addr(pinfo, qp);
	if (unlikely(err)) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qpn, RDMA_RX_QP_HDR_CHK_ADDR_INV);
		return -1;
	}

	err = rdma_check_keys(&pinfo->rinfo, qpn, qp);
	if (unlikely(err)) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qpn, RDMA_RX_QP_HDR_CHK_KEYS_INV);
		return -1;
	}

	pinfo->rinfo.qp = qp;
	return 0;
}

/* CRC32 table for portable fallback (IEEE 802.3 polynomial) */
static const uint32_t rdma_crc32_table[256] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535,
	0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd,
	0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d,
	0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
	0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4,
	0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59, 0x26d930ac,
	0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
	0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab,
	0xb6662d3d, 0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f,
	0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb,
	0x086d3d2d, 0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea,
	0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65, 0x4db26158, 0x3ab551ce,
	0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a,
	0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
	0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409,
	0xce61e49f, 0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739,
	0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
	0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 0xf00f9344, 0x8708a3d2, 0x1e01f268,
	0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0,
	0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8,
	0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef,
	0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703,
	0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7,
	0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
	0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae,
	0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777, 0x88085ae6,
	0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
	0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d,
	0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5,
	0x47b2cf7f, 0x30b5ffe9, 0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605,
	0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d};

static inline uint32_t
rdma_crc32_sw_update(uint32_t crc, const uint8_t *input, size_t length)
{
	for (size_t i = 0; i < length; i++)
		crc = (crc >> 8) ^ rdma_crc32_table[(crc ^ input[i]) & 0xff];
	return crc;
}

static inline uint32_t
rdma_crc32_update(uint32_t crc, const uint8_t *data, size_t len)
{
	while (len >= 32) {
		uint64_t v0, v1, v2, v3;

		memcpy(&v0, data + 0, 8);
		memcpy(&v1, data + 8, 8);
		memcpy(&v2, data + 16, 8);
		memcpy(&v3, data + 24, 8);
		crc = __crc32d(crc, v0);
		crc = __crc32d(crc, v1);
		crc = __crc32d(crc, v2);
		crc = __crc32d(crc, v3);
		data += 32;
		len -= 32;
	}
	while (len >= 16) {
		uint64_t v0, v1;

		memcpy(&v0, data + 0, 8);
		memcpy(&v1, data + 8, 8);
		crc = __crc32d(crc, v0);
		crc = __crc32d(crc, v1);
		data += 16;
		len -= 16;
	}
	if (len >= 8) {
		uint64_t v;

		memcpy(&v, data, 8);
		crc = __crc32d(crc, v);
		data += 8;
		len -= 8;
	}
	if (len >= 4) {
		uint32_t v;

		memcpy(&v, data, 4);
		crc = __crc32w(crc, v);
		data += 4;
		len -= 4;
	}
	if (len >= 2) {
		uint16_t v;

		memcpy(&v, data, 2);
		crc = __crc32h(crc, v);
		data += 2;
		len -= 2;
	}
	if (len)
		crc = __crc32b(crc, *data);
	return crc;
}

static rte_be32_t
rdma_icrc_calculate(struct rte_mbuf *mbuf, struct rdma_pkt_info *pinfo)
{
	struct rte_ipv4_hdr *iph;
	struct rte_udp_hdr *udph;
	struct rdma_bth *bth;
	uint16_t dgram_cksum;
	uint16_t hdr_cksum;
	rte_be32_t crc;
	uint8_t tos;
	uint8_t ttl;
	int offset = sizeof(struct rte_ether_hdr);
	struct rte_mbuf *seg;
	int remaining;
	uint8_t *data;

	RTE_SET_USED(pinfo);

	crc = (rte_be32_t)0xdebb20e3;

	// Access headers in the first segment
	iph = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, offset);
	udph = (struct rte_udp_hdr *)(iph + 1);
	bth = (struct rdma_bth *)(udph + 1);

	// Save and mask variable fields
	ttl = iph->time_to_live;
	tos = iph->type_of_service;
	hdr_cksum = iph->hdr_checksum;
	dgram_cksum = udph->dgram_cksum;

	iph->time_to_live = 0xff;
	iph->type_of_service = 0xff;
	iph->hdr_checksum = 0xffff;
	udph->dgram_cksum = 0xffff;
	bth->qpn |= rte_cpu_to_be_32(~BTH_QPN_MASK);

	// Skip Ethernet header
	seg = mbuf;
	offset = sizeof(struct rte_ether_hdr);
	remaining = mbuf->pkt_len - offset;

	while (seg && remaining > 0) {
		int seg_data_len = seg->data_len;

		if (offset >= seg_data_len) {
			offset -= seg_data_len;
			seg = seg->next;
			continue;
		}

		if (likely(seg->next))
			rte_prefetch0(rte_pktmbuf_mtod(seg->next, void *));

		data = rte_pktmbuf_mtod(seg, uint8_t *) + offset;
		int len = seg_data_len - offset;

		if (len > remaining)
			len = remaining;

		crc = rdma_crc32_update(crc, data, len);

		remaining -= len;
		offset = 0;
		seg = seg->next;
	}

	// Restore original values
	iph->time_to_live = ttl;
	iph->type_of_service = tos;
	iph->hdr_checksum = hdr_cksum;
	udph->dgram_cksum = dgram_cksum;
	bth->qpn &= rte_cpu_to_be_32(BTH_QPN_MASK);

	return crc;
}

static inline int
get_last_n_bytes_from_mbuf(struct rte_mbuf *mbuf, uint8_t *out, uint32_t len)
{
	uint32_t total_len = rte_pktmbuf_pkt_len(mbuf);
	uint32_t offset = total_len - len;

	struct rte_mbuf *seg = mbuf;

	while (seg && offset >= seg->data_len) {
		offset -= seg->data_len;
		seg = seg->next;
	}

	if (unlikely(seg == NULL))
		return -EFAULT;

	uint8_t *src = rte_pktmbuf_mtod(seg, uint8_t *) + offset;
	uint32_t first_copy_len = seg->data_len - offset;

	if (first_copy_len >= len) {
		memcpy(out, src, len);
	} else {
		memcpy(out, src, first_copy_len);
		seg = seg->next;
		memcpy(out + first_copy_len, rte_pktmbuf_mtod(seg, uint8_t *),
		       len - first_copy_len);
	}
	return 0;
}

int
rdma_icrc_check(struct rte_mbuf *mbuf, struct pkt_info *info)
{
	struct rdma_pkt_info *pinfo = &info->rinfo;
	struct rdma_bth *bth = (struct rdma_bth *)(pinfo->hdr);
	struct rdma_qp *qp = pinfo->qp;
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id  = qp->qid;
	rte_be32_t pkt_icrc;
	rte_be32_t icrc;
	int pad_len;

	if (get_last_n_bytes_from_mbuf(mbuf, (uint8_t *)&pkt_icrc, RDMA_ICRC_SIZE) < 0) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
				    RDMA_RX_QP_ICRC_CHK_PKT_ICRC_EXTRACT_FAIL);
		return -1;
	}

	rte_pktmbuf_trim(mbuf, RDMA_ICRC_SIZE);
	icrc = rdma_icrc_calculate(mbuf, pinfo);
	icrc = ~icrc;
	if (unlikely(icrc != pkt_icrc)) {
		RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id, RDMA_RX_QP_ICRC_CHECK_ICRC_MISMATCH);
		return -1;
	}

	pad_len = (bth->flags & BTH_PAD_MASK) >> 4;
	if (pad_len > 0)
		rte_pktmbuf_trim(mbuf, pad_len);

	/* Time to remove all the network headers */
	rte_pktmbuf_adj(mbuf, info->hdr_len);

	return 0;
}

static inline rte_be32_t *
rdma_mbuf_tail_extend(struct rte_mbuf *mbuf, size_t size, struct rdma_pkt_info *pinfo)
{
	rte_be32_t *new_data = NULL;
	struct rdma_qp *qp = pinfo->qp;
	struct rte_mbuf *new_seg = rte_pktmbuf_alloc(mbuf->pool);

	if (new_seg != NULL) {
		rte_pktmbuf_chain(mbuf, new_seg);
		new_data = (rte_be32_t *)rte_pktmbuf_append(mbuf, size);
		if (qp->type == RDMA_QPT_RC)
			rte_mbuf_refcnt_update(new_seg, 1);
	}

	return new_data;
}

int
rdma_icrc_refresh(struct rte_mbuf *mbuf)
{
	rte_be32_t *icrcp;
	rte_be32_t icrc;

	if (rte_pktmbuf_trim(mbuf, RDMA_ICRC_SIZE) < 0)
		return -1;

	icrc = rdma_icrc_calculate(mbuf, NULL);

	icrcp = (rte_be32_t *)rte_pktmbuf_append(mbuf, RDMA_ICRC_SIZE);
	if (!icrcp)
		return -1;
	*icrcp = ~icrc;
	return 0;
}

int
rdma_icrc_generate(struct rte_mbuf *mbuf, struct rdma_pkt_info *pinfo)
{
	rdma_qp_t *qp = (rdma_qp_t *)pinfo->qp;
	uint32_t port_id = qp->port_id;
	uint32_t lcore_id = qp->lcore;
	uint32_t qp_id  = qp->qid;
	rte_be32_t *icrcp;
	rte_be32_t icrc;

	icrc = rdma_icrc_calculate(mbuf, pinfo);
	icrcp = (rte_be32_t *)rte_pktmbuf_append(mbuf, RDMA_ICRC_SIZE);
	if (!icrcp) {
		icrcp = rdma_mbuf_tail_extend(mbuf, RDMA_ICRC_SIZE, pinfo);
		if (!icrcp) {
			RDMA_INC_QP_COUNTER(lcore_id, port_id, qp_id,
					    RDMA_QP_ICRC_GEN_APPEND_ICRC_FAIL);
			return -1;
		}
	}
	*icrcp = ~icrc;

	return 0;
}
