/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_acl.h>
#include <rte_ethdev.h>
#include <rte_vect.h>

#include "dao_flow.h"
#include "flow_acl_priv.h"
#include "flow_gbl_priv.h"
#include "key.h"
#include "profile_priv.h"

#define L2L3_BCAST_NIB 0

#define MAX_CPT_KCFG_FIELDS 32

struct key_config cpt_em_kcfg[] = {
	/*LTYPE, LID, offset_in_ltype, offset_in_key, size*/
	/* VLAN -> DMAC 6 bytes */
	{RTE_PTYPE_L2_ETHER_VLAN, 0, 0, 0, 6},
	/* IPV4 -> SIP 8 bytes */
	{(RTE_PTYPE_L3_IPV4 >> 4), 1, 12, 6, 8},
	/* UDP -> SPORT 4 bytes */
	{(RTE_PTYPE_L4_UDP >> 8), 2, 0, 14, 2},
};

struct flow_parser_tcam_kex cpt_em_kex_profile = {
	.mkex_sign = MKEX_SIGN,
	.name = "cpt-em",
	.prfl_version = FLOW_PARSER_PROFILE_VER,
	.keyx_cfg = {
			/* nibble: LA..LE (ltype only) + Error code + Channel */
			[NIX_INTF_RX] = ((uint64_t)PROFILE_TCAM_KEY_X2 << 32) |
					PARSE_NIBBLE_INTF_RX | (uint64_t)PROFILE_EXACT_NIBBLE_HIT,
			/* nibble: LA..LE (ltype only) */
			[NIX_INTF_TX] =
				((uint64_t)PROFILE_TCAM_KEY_X2 << 32) | PARSE_NIBBLE_INTF_TX,
		},
	.intf_lid_lt_ld = {
			/* Default RX MCAM KEX profile */
			[NIX_INTF_RX] = {
					[PROFILE_LID_LA] = {
							/* Layer A: Ethernet: */
							[PROFILE_LT_LA_ETHER] = {
									/* DMAC: 6 bytes */
									/* (bytesm1, hdr_ofs, ena,
									   flags_ena, key_ofs) */
									KEX_LD_CFG(0x05, 0x0, 0x1,
										   0x0, 0x5),
								},
						},
					[PROFILE_LID_LC] = {
							/* Layer C: IPv4 */
							[PROFILE_LT_LC_IP] = {
									/* SIP+DIP: 8 bytes */
									KEX_LD_CFG(0x07, 0xc, 0x1,
										   0x0, 0xB),
								},
						},
					[PROFILE_LID_LD] = {
							/* Layer D:UDP */
							[PROFILE_LT_LD_UDP] = {
									/* SPORT+DPORT: 4 bytes */
									KEX_LD_CFG(0x3, 0x0, 0x1,
										   0x0, 0x13),
								},
						},
				},

			/* Default TX MCAM KEX profile */
			[NIX_INTF_TX] = {
					[PROFILE_LID_LA] = {
							/* Layer A: NIX_INST_HDR_S + Ethernet */
							/* NIX appends 8 bytes of NIX_INST_HDR_S at
							 * the start of each TX packet supplied to
							 * profile.
							 */
							[PROFILE_LT_LA_IH_NIX_ETHER] = {
									/* PF_FUNC: 2B , KW0 [47:32]
									 */
									KEX_LD_CFG(0x01, 0x0, 0x1,
										   0x0, 0x4),
									/* DMAC: 6 bytes, KW1[63:16]
									 */
									KEX_LD_CFG(0x05, 0x8, 0x1,
										   0x0, 0xa),
								},
							/* Layer A: HiGig2: */
							[PROFILE_LT_LA_IH_NIX_HIGIG2_ETHER] = {
									/* PF_FUNC: 2B , KW0 [47:32]
									 */
									KEX_LD_CFG(0x01, 0x0, 0x1,
										   0x0, 0x4),
									/* VID: 2 bytes, KW1[31:16]
									 */
									KEX_LD_CFG(0x01, 0x10,
										   0x1, 0x0, 0xa),
								},
						},
					[PROFILE_LID_LB] = {
							/* Layer B: Single VLAN (CTAG) */
							[PROFILE_LT_LB_CTAG] = {
									/* CTAG VLAN[2..3]
									   KW0[63:48] */
									KEX_LD_CFG(0x01, 0x2, 0x1,
										   0x0, 0x6),
									/* CTAG VLAN[2..3] KW1[15:0]
									 */
									KEX_LD_CFG(0x01, 0x4, 0x1,
										   0x0, 0x8),
								},
							/* Layer B: Stacked VLAN (STAG|QinQ) */
							[PROFILE_LT_LB_STAG_QINQ] = {
									/* Outer VLAN: 2 bytes,
									   KW0[63:48] */
									KEX_LD_CFG(0x01, 0x2, 0x1,
										   0x0, 0x6),
									/* Outer VLAN: 2 Bytes,
									   KW1[15:0] */
									KEX_LD_CFG(0x01, 0x8, 0x1,
										   0x0, 0x8),
								},
						},
					[PROFILE_LID_LC] = {
							/* Layer C: IPv4 */
							[PROFILE_LT_LC_IP] = {
									/* SIP+DIP: 8 bytes,
									   KW2[63:0] */
									KEX_LD_CFG(0x07, 0xc, 0x1,
										   0x0, 0x10),
								},
							/* Layer C: IPv6 */
							[PROFILE_LT_LC_IP6] = {
									/* Everything up to SADDR: 8
									   bytes, KW2[63:0] */
									KEX_LD_CFG(0x07, 0x0, 0x1,
										   0x0, 0x10),
								},
						},
					[PROFILE_LID_LD] = {
							/* Layer D:UDP */
							[PROFILE_LT_LD_UDP] = {
									/* SPORT+DPORT: 4 bytes,
									   KW3[31:0] */
									KEX_LD_CFG(0x3, 0x0, 0x1,
										   0x0, 0x18),
								},
							/* Layer D:TCP */
							[PROFILE_LT_LD_TCP] = {
									/* SPORT+DPORT: 4 bytes,
									   KW3[31:0] */
									KEX_LD_CFG(0x3, 0x0, 0x1,
										   0x0, 0x18),
								},
						},
				},
		},
};
