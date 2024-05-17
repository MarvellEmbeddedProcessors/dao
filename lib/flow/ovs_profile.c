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

#define UDP_PORT_VXLAN 4789
#define VXLAN_I        0x0800
#define L2L3_BCAST_NIB 0

struct flow_parser_tcam_kex ovs_kex_profile = {
	.mkex_sign = MKEX_SIGN,
	.name = "ovs",
	.prfl_version = FLOW_PARSER_PROFILE_VER,
	.keyx_cfg = {
		/* nibble: LA..LE (ltype only) + Error code + Channel */
		[NIX_INTF_RX] = ((uint64_t)PROFILE_TCAM_KEY_X2 << 32) | PARSE_NIBBLE_INTF_RX |
				(uint64_t)PROFILE_EXACT_NIBBLE_HIT,
		/* nibble: LA..LE (ltype only) */
		[NIX_INTF_TX] = ((uint64_t)PROFILE_TCAM_KEY_X2 << 32) | PARSE_NIBBLE_INTF_TX,
	},
	.kex_ld_flags[NIX_INTF_RX] = PROFILE_LID_LC,
	.intf_ld_flags = {
		[NIX_INTF_RX] = {
			[0] = {
				/* TOS: 1 byte */
				KEX_LD_CFG(0, 0x1, 1, 0, 0x36),
			},
		},
	},
	.intf_lid_lt_ld = {
		/* OVS RX MCAM KEX profile */
		[NIX_INTF_RX] = {
			[PROFILE_LID_LA] = {
				/* Layer A: Ethernet: */
				[PROFILE_LT_LA_ETHER] = {
					/* DMAC + SMAC : 12 bytes */
					KEX_LD_CFG(0x0B, 0x0, 0x1, 0x0, 0x8),
					/* Ethertype: 2 bytes, KW0[55:40] */
					KEX_LD_CFG(0x01, 0xc, 0x1, 0x0, 0x14),
				},
			},
			[PROFILE_LID_LB] = {
				/* Layer B: Single VLAN (CTAG) */
				[PROFILE_LT_LB_CTAG] = {
					/* CTAG VLAN: 2 bytes, KW1[7:0], KW0[63:56] */
					KEX_LD_CFG(0x01, 0x2, 0x1, 0x0, 0x16),
					/* Ethertype: 2 bytes, KW0[55:40] */
					KEX_LD_CFG(0x01, 0x4, 0x1, 0x0, 0x14),
				},
				/* Layer B: Stacked VLAN (STAG|QinQ) */
				[PROFILE_LT_LB_STAG_QINQ] = {
					/* Outer VLAN: 2 bytes, KW1[7:0], KW0[63:56] */
					KEX_LD_CFG(0x01, 0x6, 0x1, 0x0, 0x16),
					/* Ethertype: 2 bytes, KW0[55:40] */
					KEX_LD_CFG(0x01, 0x8, 0x1, 0x0, 0x14),
				},
			},
			[PROFILE_LID_LC] = {
				/* Layer C: IPv4 */
				[PROFILE_LT_LC_IP] = {
					/* FRAG OFFSET: 2 bytes */
					KEX_LD_CFG(0x01, 0x6, 0x1, 0x1, 0x18),
					/* SIP + DIP: 8 byte */
					KEX_LD_CFG(0x07, 0xC, 0x1, 0x0, 0x1A),
				},
				/* Layer C: IPv6 */
				[PROFILE_LT_LC_IP6] = {
					/* First 8 bytes */
					KEX_LD_CFG(0x07, 0x0, 0x1, 0x0, 0x18),
				},
			},
			[PROFILE_LID_LD] = {
				/* Layer D:UDP */
				[PROFILE_LT_LD_UDP] = {
					/* SPORT+DPORT: 4 bytes, KW3[31:0] */
					KEX_LD_CFG(0x3, 0x0, 0x1, 0x0, 0x22),
				},
			},
			[PROFILE_LID_LE] = {
				/* Layer E:VXLAN */
				[PROFILE_LT_LE_VXLAN] = {
					/* VNI */
					KEX_LD_CFG(0x3, 0x4, 0x1, 0x0, 0x22),
				},
			},
			[PROFILE_LID_LF] = {
				[PROFILE_LT_LF_TU_ETHER] = {
					/* INNER ETH DMAC */
					KEX_LD_CFG(0xB, 0x0, 0x1, 0x0, 0x26),
					/* Ethertype */
					KEX_LD_CFG(0x1, 0xC, 0x1, 0x0, 0x32),
				},
			},
			[PROFILE_LID_LG] = {
				[PROFILE_LT_LG_TU_IP] = {
					/* INNER IP FRAG OFFSET */
					KEX_LD_CFG(0x1, 0x06, 0x1, 0x0, 0x34),
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
					KEX_LD_CFG(0x0D, 0x8, 0x1, 0x0, 0x6),
				},
			},
			[PROFILE_LID_LB] = {
				/* Layer B: Single VLAN (CTAG) */
				[PROFILE_LT_LB_CTAG] = {
					/* CTAG VLAN: 2 bytes, KW1[7:0], KW0[63:56] */
					KEX_LD_CFG(0x01, 0x2, 0x1, 0x0, 0x14),
					/* Ethertype: 2 bytes, KW0[55:40] */
					KEX_LD_CFG(0x01, 0x4, 0x1, 0x0, 0x12),
				},
				/* Layer B: Stacked VLAN (STAG|QinQ) */
				[PROFILE_LT_LB_STAG_QINQ] = {
					/* Outer VLAN: 2 bytes, KW1[7:0], KW0[63:56] */
					KEX_LD_CFG(0x01, 0x2, 0x1, 0x0, 0x14),
					/* Ethertype: 2 bytes, KW0[55:40] */
					KEX_LD_CFG(0x01, 0x8, 0x1, 0x0, 0x12),
				},
			},
			[PROFILE_LID_LC] = {
				/* Layer C: IPv4 */
				[PROFILE_LT_LC_IP] = {
					/* SIP+DIP: 8 bytes, KW2[63:0] */
					KEX_LD_CFG(0x01, 0x6, 0x1, 0x0, 0x16),
				},
			},
		},
	},
};

static int
ovs_profile_key_generation(struct rte_mbuf *pkt, uint16_t channel, uint8_t *key_buf)
{
	struct rte_vlan_hdr *outer_vlan_hdr, *inner_vlan_hdr;
	struct rte_ether_hdr *inner_eth_hdr;
	struct rte_ipv4_hdr *inner_ipv4_hdr;
	struct rte_vxlan_hdr *vxlan_hdr;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_udp_hdr *udp_hdr;
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

	reverse_memcpy(&key_buf[8], (uint8_t *)eth_hdr->dst_addr.addr_bytes, 12);

	eth_type = rte_be_to_cpu_16(eth_hdr->ether_type);
	offset += sizeof(struct rte_ether_hdr);
	*(uint16_t *)&key_buf[20] = eth_type;

	/* VLAN */
	if (eth_type == RTE_ETHER_TYPE_VLAN) {
		outer_vlan_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_vlan_hdr *, offset);
		next_proto = rte_be_to_cpu_16(outer_vlan_hdr->eth_proto);

		*(uint16_t *)&key_buf[20] = next_proto;
		*(uint16_t *)&key_buf[22] = rte_be_to_cpu_16(outer_vlan_hdr->vlan_tci);

		key_buf[2] = key_buf[2] | (PROFILE_LT_LB_CTAG << 4);
		offset += sizeof(struct rte_vlan_hdr);
	} else if (eth_type == RTE_ETHER_TYPE_QINQ) {
		inner_vlan_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_vlan_hdr *,
							 offset + sizeof(struct rte_vlan_hdr));

		next_proto = rte_be_to_cpu_16(inner_vlan_hdr->eth_proto);
		*(uint16_t *)&key_buf[20] = next_proto;
		*(uint16_t *)&key_buf[22] = rte_be_to_cpu_16(inner_vlan_hdr->vlan_tci);

		key_buf[2] = key_buf[2] | (PROFILE_LT_LB_STAG_QINQ << 4);
		offset += sizeof(struct rte_vlan_hdr) * 2;
	}

	/* IPV4, IPV6*/
	if (next_proto == RTE_ETHER_TYPE_IPV4 || eth_type == RTE_ETHER_TYPE_IPV4) {
		ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, offset);

		*(uint16_t *)&key_buf[24] = rte_be_to_cpu_16(ipv4_hdr->fragment_offset);
		*(uint32_t *)&key_buf[26] = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
		*(uint32_t *)&key_buf[30] = rte_be_to_cpu_32(ipv4_hdr->src_addr);
		*(uint8_t *)&key_buf[54] = ipv4_hdr->type_of_service;

		key_buf[3] = PROFILE_LT_LC_IP;
		next_proto = ipv4_hdr->next_proto_id;

		offset += sizeof(struct rte_ipv4_hdr);
	} else if (next_proto == RTE_ETHER_TYPE_IPV6 || eth_type == RTE_ETHER_TYPE_IPV6) {
		ipv6_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv6_hdr *, offset);

		*(uint32_t *)&key_buf[24] = *(uint32_t *)ipv6_hdr;
		*(uint32_t *)&key_buf[28] = *(((uint32_t *)ipv6_hdr) + 1);

		key_buf[3] = PROFILE_LT_LC_IP6;
		next_proto = ipv6_hdr->proto;
		offset += sizeof(struct rte_ipv6_hdr);
	}

	/* UDP */
	if (next_proto == IPPROTO_UDP) {
		udp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_udp_hdr *, offset);

		*(uint32_t *)&key_buf[34] = rte_be_to_cpu_32(*(uint32_t *)udp_hdr);

		key_buf[3] = key_buf[3] | (PROFILE_LT_LD_UDP << 4);
		next_proto = rte_be_to_cpu_16(udp_hdr->dst_port);
		offset += sizeof(struct rte_udp_hdr);
	}

	/* VXLAN */
	if (next_proto == UDP_PORT_VXLAN) {
		vxlan_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_vxlan_hdr *, offset);

		*(uint32_t *)&key_buf[34] = rte_be_to_cpu_32(vxlan_hdr->vx_vni);
		key_buf[4] = PROFILE_LT_LE_VXLAN;

		offset += sizeof(struct rte_vxlan_hdr);
		inner_eth_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ether_hdr *, offset);

		reverse_memcpy(&key_buf[38], (uint8_t *)inner_eth_hdr->dst_addr.addr_bytes, 12);

		offset += sizeof(struct rte_ether_hdr);
		next_proto = rte_be_to_cpu_16(inner_eth_hdr->ether_type);
		*(uint32_t *)&key_buf[50] = next_proto;
	}
	/* INNER IPV4 */
	if (next_proto == RTE_ETHER_TYPE_IPV4) {
		inner_ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, offset);

		*(uint16_t *)&key_buf[52] = rte_be_to_cpu_16(inner_ipv4_hdr->fragment_offset);
	}

	return 0;
}

struct parse_profile_ops ovs_prfl_ops = {
	.key_generation = ovs_profile_key_generation,
};
