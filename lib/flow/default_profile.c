/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <rte_acl.h>
#include <rte_ethdev.h>
#include <rte_vect.h>

#include "dao_flow.h"
#include "flow_acl_priv.h"
#include "flow_gbl_priv.h"
#include "profile_priv.h"

#define L2L3_BCAST_NIB	0

struct flow_parser_tcam_kex default_kex_profile = {
	.mkex_sign = MKEX_SIGN,
	.name = "default",
	.prfl_version = FLOW_PARSER_PROFILE_VER,
	.keyx_cfg = {
		/* nibble: LA..LE (ltype only) + Error code + Channel */
		[NIX_INTF_RX] = ((uint64_t)PROFILE_TCAM_KEY_X2 << 32) | PARSE_NIBBLE_INTF_RX |
				(uint64_t)PROFILE_EXACT_NIBBLE_HIT,
		/* nibble: LA..LE (ltype only) */
		[NIX_INTF_TX] = ((uint64_t)PROFILE_TCAM_KEY_X2 << 32) | PARSE_NIBBLE_INTF_TX,
	},
	.intf_lid_lt_ld = {
		/* Default RX MCAM KEX profile */
		[NIX_INTF_RX] = {
			[PROFILE_LID_LA] = {
				/* Layer A: Ethernet: */
				[PROFILE_LT_LA_ETHER] = {
					/* DMAC: 6 bytes, KW1[55:8], PROFILE_KEXOF_DMAC:9*/
					KEX_LD_CFG(0x05, 0x0, 0x1, 0x0, PROFILE_KEXOF_DMAC),
					/* Ethertype: 2 bytes, KW0[55:40] */
					KEX_LD_CFG(0x01, 0xc, 0x1, 0x0, 0x5),
				},
				[PROFILE_LT_LA_CPT_HDR] = {
					/* DMAC: 6 bytes, KW1[55:8] */
					KEX_LD_CFG(0x05, 0x0, 0x1, 0x0, PROFILE_KEXOF_DMAC),
					/* Ethertype: 2 bytes, KW0[55:40] */
					KEX_LD_CFG(0x01, 0xc, 0x1, 0x0, 0x5),
				},
				/* Layer A: HiGig2: */
				[PROFILE_LT_LA_HIGIG2_ETHER] = {
					/* Classification: 2 bytes, KW1[23:8] */
					KEX_LD_CFG(0x01, 0x8, 0x1, 0x0, PROFILE_KEXOF_DMAC),
					/* VID: 2 bytes, KW1[39:24] */
					KEX_LD_CFG(0x01, 0xc, 0x1, 0x0,
						   PROFILE_KEXOF_DMAC + 2),
				},
			},
			[PROFILE_LID_LB] = {
				/* Layer B: Single VLAN (CTAG) */
				[PROFILE_LT_LB_CTAG] = {
					/* CTAG VLAN: 2 bytes, KW1[7:0], KW0[63:56] */
					KEX_LD_CFG(0x01, 0x2, 0x1, 0x0, 0x7),
					/* Ethertype: 2 bytes, KW0[55:40] */
					KEX_LD_CFG(0x01, 0x4, 0x1, 0x0, 0x5),
				},
				/* Layer B: Stacked VLAN (STAG|QinQ) */
				[PROFILE_LT_LB_STAG_QINQ] = {
					/* Outer VLAN: 2 bytes, KW1[7:0], KW0[63:56] */
					KEX_LD_CFG(0x01, 0x2, 0x1, 0x0, 0x7),
					/* Ethertype: 2 bytes, KW0[55:40] */
					KEX_LD_CFG(0x01, 0x8, 0x1, 0x0, 0x5),
				},
				[PROFILE_LT_LB_FDSA] = {
					/* SWITCH PORT: 1 byte, KW0[63:56] */
					KEX_LD_CFG(0x0, 0x1, 0x1, 0x0, 0x7),
					/* Ethertype: 2 bytes, KW0[55:40] */
					KEX_LD_CFG(0x01, 0x4, 0x1, 0x0, 0x5),
				},
			},
			[PROFILE_LID_LC] = {
				/* Layer C: IPv4 */
				[PROFILE_LT_LC_IP] = {
					/* SIP+DIP: 8 bytes, KW2[63:0] */
					KEX_LD_CFG(0x07, 0xc, 0x1, 0x0, 0x10),
					/* TOS: 1 byte, KW1[63:56] */
					KEX_LD_CFG(0x0, 0x1, 0x1, 0x0, 0xf),
				},
				/* Layer C: IPv6 */
				[PROFILE_LT_LC_IP6] = {
					/* Everything up to SADDR: 8 bytes, KW2[63:0] */
					KEX_LD_CFG(0x07, 0x0, 0x1, 0x0, 0x10),
				},
			},
			[PROFILE_LID_LD] = {
				/* Layer D:UDP */
				[PROFILE_LT_LD_UDP] = {
					/* SPORT+DPORT: 4 bytes, KW3[31:0] */
					KEX_LD_CFG(0x3, 0x0, 0x1, 0x0, 0x18),
				},
				/* Layer D:TCP */
				[PROFILE_LT_LD_TCP] = {
					/* SPORT+DPORT: 4 bytes, KW3[31:0] */
					KEX_LD_CFG(0x3, 0x0, 0x1, 0x0, 0x18),
				},
			},
		},

		/* Default TX MCAM KEX profile */
		[NIX_INTF_TX] = {
			[PROFILE_LID_LA] = {
				/* Layer A: NIX_INST_HDR_S + Ethernet */
				/* NIX appends 8 bytes of NIX_INST_HDR_S at the
				 * start of each TX packet supplied to profile.
				 */
				[PROFILE_LT_LA_IH_NIX_ETHER] = {
					/* PF_FUNC: 2B , KW0 [47:32] */
					KEX_LD_CFG(0x01, 0x0, 0x1, 0x0, 0x4),
					/* DMAC: 6 bytes, KW1[63:16] */
					KEX_LD_CFG(0x05, 0x8, 0x1, 0x0, 0xa),
				},
				/* Layer A: HiGig2: */
				[PROFILE_LT_LA_IH_NIX_HIGIG2_ETHER] = {
					/* PF_FUNC: 2B , KW0 [47:32] */
					KEX_LD_CFG(0x01, 0x0, 0x1, 0x0, 0x4),
					/* VID: 2 bytes, KW1[31:16] */
					KEX_LD_CFG(0x01, 0x10, 0x1, 0x0, 0xa),
				},
			},
			[PROFILE_LID_LB] = {
				/* Layer B: Single VLAN (CTAG) */
				[PROFILE_LT_LB_CTAG] = {
					/* CTAG VLAN[2..3] KW0[63:48] */
					KEX_LD_CFG(0x01, 0x2, 0x1, 0x0, 0x6),
					/* CTAG VLAN[2..3] KW1[15:0] */
					KEX_LD_CFG(0x01, 0x4, 0x1, 0x0, 0x8),
				},
				/* Layer B: Stacked VLAN (STAG|QinQ) */
				[PROFILE_LT_LB_STAG_QINQ] = {
					/* Outer VLAN: 2 bytes, KW0[63:48] */
					KEX_LD_CFG(0x01, 0x2, 0x1, 0x0, 0x6),
					/* Outer VLAN: 2 Bytes, KW1[15:0] */
					KEX_LD_CFG(0x01, 0x8, 0x1, 0x0, 0x8),
				},
			},
			[PROFILE_LID_LC] = {
				/* Layer C: IPv4 */
				[PROFILE_LT_LC_IP] = {
					/* SIP+DIP: 8 bytes, KW2[63:0] */
					KEX_LD_CFG(0x07, 0xc, 0x1, 0x0, 0x10),
				},
				/* Layer C: IPv6 */
				[PROFILE_LT_LC_IP6] = {
					/* Everything up to SADDR: 8 bytes, KW2[63:0] */
					KEX_LD_CFG(0x07, 0x0, 0x1, 0x0, 0x10),
				},
			},
			[PROFILE_LID_LD] = {
				/* Layer D:UDP */
				[PROFILE_LT_LD_UDP] = {
					/* SPORT+DPORT: 4 bytes, KW3[31:0] */
					KEX_LD_CFG(0x3, 0x0, 0x1, 0x0, 0x18),
				},
				/* Layer D:TCP */
				[PROFILE_LT_LD_TCP] = {
					/* SPORT+DPORT: 4 bytes, KW3[31:0] */
					KEX_LD_CFG(0x3, 0x0, 0x1, 0x0, 0x18),
				},
			},
		},
	},
};

static int
default_profile_key_generation(struct rte_mbuf *pkt, uint16_t channel, uint8_t *key_buf)
{
	struct rte_vlan_hdr *outer_vlan_hdr, *inner_vlan_hdr;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	uint32_t next_proto = 0;
	uint16_t offset = 0;
	uint16_t eth_type;

	RTE_ASSERT(pkt != NULL);

	key_buf[0] = channel & 0xFF;
	key_buf[1] = (channel & 0xF00) >> 8;
	key_buf[1] = key_buf[1] | (L2L3_BCAST_NIB << 4);

	key_buf[2] = PROFILE_LT_LA_ETHER;

	/* ETH */
	eth_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ether_hdr *, 0);

	eth_type = rte_be_to_cpu_16(eth_hdr->ether_type);

	*(uint16_t *)&key_buf[6] = eth_hdr->ether_type;
	reverse_memcpy(&key_buf[9], (uint8_t *)eth_hdr->dst_addr.addr_bytes, 6);

	offset += sizeof(struct rte_ether_hdr);

	/* VLAN */
	if (eth_type == RTE_ETHER_TYPE_VLAN) {
		outer_vlan_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_vlan_hdr *, offset);
		next_proto = rte_be_to_cpu_16(outer_vlan_hdr->eth_proto);

		*(uint16_t *)&key_buf[5] = next_proto;
		*(uint16_t *)&key_buf[7] = rte_be_to_cpu_16(outer_vlan_hdr->vlan_tci);

		key_buf[2] = key_buf[2] | (PROFILE_LT_LB_CTAG << 4);
		offset += sizeof(struct rte_vlan_hdr);
	} else if (eth_type == RTE_ETHER_TYPE_QINQ) {
		inner_vlan_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_vlan_hdr *,
							 offset + sizeof(struct rte_vlan_hdr));

		next_proto = rte_be_to_cpu_16(inner_vlan_hdr->eth_proto);
		*(uint16_t *)&key_buf[5] = next_proto;
		*(uint16_t *)&key_buf[7] = rte_be_to_cpu_16(inner_vlan_hdr->vlan_tci);

		key_buf[2] = key_buf[2] | (PROFILE_LT_LB_STAG_QINQ << 4);
		offset += sizeof(struct rte_vlan_hdr) * 2;
	}

	/* IPV4, IPV6*/
	if (next_proto == RTE_ETHER_TYPE_IPV4) {
		ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, offset);

		*(uint32_t *)&key_buf[15] = ipv4_hdr->type_of_service;
		*(uint32_t *)&key_buf[16] = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
		*(uint32_t *)&key_buf[20] = rte_be_to_cpu_32(ipv4_hdr->src_addr);

		key_buf[3] = PROFILE_LT_LC_IP;

		next_proto = ipv4_hdr->next_proto_id;

		offset += sizeof(struct rte_ipv4_hdr);
	} else if (next_proto == RTE_ETHER_TYPE_IPV6) {
		ipv6_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv6_hdr *, offset);

		*(uint32_t *)&key_buf[15] = *(uint32_t *)ipv6_hdr;
		*(uint32_t *)&key_buf[19] = *(((uint32_t *)ipv6_hdr) + 1);

		key_buf[3] = PROFILE_LT_LC_IP6;
		next_proto = ipv6_hdr->proto;
		offset += sizeof(struct rte_ipv6_hdr);
	}

	/* UDP */
	if (next_proto == IPPROTO_UDP) {
		udp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_udp_hdr *, offset);

		*(uint32_t *)&key_buf[24] = rte_be_to_cpu_32(*(uint32_t *)udp_hdr);

		key_buf[3] = key_buf[3] | (PROFILE_LT_LD_UDP << 4);
		next_proto = udp_hdr->dst_port;
		offset += sizeof(struct rte_udp_hdr);
	} else if (next_proto == IPPROTO_TCP) {
		tcp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_tcp_hdr *, offset);

		*(uint32_t *)&key_buf[24] = rte_be_to_cpu_32(*(uint32_t *)tcp_hdr);

		key_buf[3] = key_buf[3] | (PROFILE_LT_LD_TCP << 4);
		next_proto = tcp_hdr->dst_port;
	}
	return 0;
}

struct parse_profile_ops default_prfl_ops = {
	.key_generation = default_profile_key_generation,
};
