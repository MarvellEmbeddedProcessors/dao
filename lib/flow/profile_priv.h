/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _PROFILE_PRIV_H_
#define _PROFILE_PRIV_H_

/* Register offsets */

#define PROFILE_MAX_INTF 2
#define PROFILE_MAX_LID  8
#define PROFILE_MAX_LT   16
#define PROFILE_MAX_LD   2
#define PROFILE_MAX_LFL  16

#define PROFILE_TCAM_KEY_X1 (0x0ull)
#define PROFILE_TCAM_KEY_X2 (0x1ull)
#define PROFILE_TCAM_KEY_X4 (0x2ull)

#define PROFILE_F_STAG_STAG_CTAG     15
#define PROFILE_F_ETAG_CTAG          25
#define PROFILE_F_MPLS_4_LABELS      36
#define PROFILE_F_MPLS_3_LABELS      37
#define PROFILE_F_MPLS_2_LABELS      38
#define PROFILE_F_GRE_NVGRE          79
#define PROFILE_F_UDP_VXLAN          60
#define PROFILE_F_UDP_GTP_GTPC       71
#define PROFILE_F_UDP_GTP_GTPU_G_PDU 72
#define PROFILE_F_UDP_GENEVE         75
#define PROFILE_F_UDP_VXLANGPE       63
#define PROFILE_F_TU_ETHER_CTAG      96
#define PROFILE_F_TU_ETHER_STAG_CTAG 98

enum PROFILE_LID_E {
	PROFILE_LID_LA = 0,
	PROFILE_LID_LB,
	PROFILE_LID_LC,
	PROFILE_LID_LD,
	PROFILE_LID_LE,
	PROFILE_LID_LF,
	PROFILE_LID_LG,
	PROFILE_LID_LH,
};

#ifndef __PROFILE_LT_TYPES__
#define __PROFILE_LT_TYPES__
#define PROFILE_LT_NA 0

enum profile_la_ltype {
	PROFILE_LT_LA_8023 = 1,
	PROFILE_LT_LA_ETHER,
	PROFILE_LT_LA_IH_NIX_ETHER,
	PROFILE_LT_LA_HIGIG2_ETHER = 7,
	PROFILE_LT_LA_IH_NIX_HIGIG2_ETHER,
	PROFILE_LT_LA_CUSTOM_L2_90B_ETHER,
	PROFILE_LT_LA_CPT_HDR,
	PROFILE_LT_LA_CUSTOM_L2_24B_ETHER,
	PROFILE_LT_LA_CUSTOM_PRE_L2_ETHER,
	PROFILE_LT_LA_CUSTOM0 = 0xE,
	PROFILE_LT_LA_CUSTOM1 = 0xF,
};

enum profile_lb_ltype {
	PROFILE_LT_LB_ETAG = 1,
	PROFILE_LT_LB_CTAG,
	PROFILE_LT_LB_STAG_QINQ,
	PROFILE_LT_LB_BTAG,
	PROFILE_LT_LB_PPPOE,
	PROFILE_LT_LB_DSA,
	PROFILE_LT_LB_DSA_VLAN,
	PROFILE_LT_LB_EDSA,
	PROFILE_LT_LB_EDSA_VLAN,
	PROFILE_LT_LB_EXDSA,
	PROFILE_LT_LB_EXDSA_VLAN,
	PROFILE_LT_LB_FDSA,
	PROFILE_LT_LB_VLAN_EXDSA,
	PROFILE_LT_LB_CUSTOM0 = 0xE,
	PROFILE_LT_LB_CUSTOM1 = 0xF,
};

enum profile_lc_ltype {
	PROFILE_LT_LC_PTP = 1,
	PROFILE_LT_LC_IP,
	PROFILE_LT_LC_IP_OPT,
	PROFILE_LT_LC_IP6,
	PROFILE_LT_LC_IP6_EXT,
	PROFILE_LT_LC_ARP,
	PROFILE_LT_LC_RARP,
	PROFILE_LT_LC_MPLS,
	PROFILE_LT_LC_NSH,
	PROFILE_LT_LC_FCOE,
	PROFILE_LT_LC_NGIO,
	PROFILE_LT_LC_CUSTOM0 = 0xE,
	PROFILE_LT_LC_CUSTOM1 = 0xF,
};

/* Don't modify Ltypes up to SCTP, otherwise it will
 * effect flow tag calculation and thus RSS.
 */
enum profile_ld_ltype {
	PROFILE_LT_LD_TCP = 1,
	PROFILE_LT_LD_UDP,
	PROFILE_LT_LD_SCTP = 4,
	PROFILE_LT_LD_ICMP6,
	PROFILE_LT_LD_CUSTOM0,
	PROFILE_LT_LD_CUSTOM1,
	PROFILE_LT_LD_IGMP = 8,
	PROFILE_LT_LD_AH,
	PROFILE_LT_LD_GRE,
	PROFILE_LT_LD_NVGRE,
	PROFILE_LT_LD_NSH,
	PROFILE_LT_LD_TU_MPLS_IN_NSH,
	PROFILE_LT_LD_TU_MPLS_IN_IP,
	PROFILE_LT_LD_ICMP,
};

enum profile_le_ltype {
	PROFILE_LT_LE_VXLAN = 1,
	PROFILE_LT_LE_GENEVE,
	PROFILE_LT_LE_ESP,
	PROFILE_LT_LE_GTPU = 4,
	PROFILE_LT_LE_VXLANGPE,
	PROFILE_LT_LE_GTPC,
	PROFILE_LT_LE_NSH,
	PROFILE_LT_LE_TU_MPLS_IN_GRE,
	PROFILE_LT_LE_TU_NSH_IN_GRE,
	PROFILE_LT_LE_TU_MPLS_IN_UDP,
	PROFILE_LT_LE_CUSTOM0 = 0xE,
	PROFILE_LT_LE_CUSTOM1 = 0xF,
};

#endif

enum profile_lf_ltype {
	PROFILE_LT_LF_TU_ETHER = 1,
	PROFILE_LT_LF_TU_PPP,
	PROFILE_LT_LF_TU_MPLS_IN_VXLANGPE,
	PROFILE_LT_LF_TU_NSH_IN_VXLANGPE,
	PROFILE_LT_LF_TU_MPLS_IN_NSH,
	PROFILE_LT_LF_TU_3RD_NSH,
	PROFILE_LT_LF_CUSTOM0 = 0xE,
	PROFILE_LT_LF_CUSTOM1 = 0xF,
};

enum profile_lg_ltype {
	PROFILE_LT_LG_TU_IP = 1,
	PROFILE_LT_LG_TU_IP6,
	PROFILE_LT_LG_TU_ARP,
	PROFILE_LT_LG_TU_ETHER_IN_NSH,
	PROFILE_LT_LG_CUSTOM0 = 0xE,
	PROFILE_LT_LG_CUSTOM1 = 0xF,
};

/* Don't modify Ltypes up to SCTP, otherwise it will
 * effect flow tag calculation and thus RSS.
 */
enum profile_lh_ltype {
	PROFILE_LT_LH_TU_TCP = 1,
	PROFILE_LT_LH_TU_UDP,
	PROFILE_LT_LH_TU_SCTP = 4,
	PROFILE_LT_LH_TU_ICMP6,
	PROFILE_LT_LH_CUSTOM0,
	PROFILE_LT_LH_CUSTOM1,
	PROFILE_LT_LH_TU_IGMP = 8,
	PROFILE_LT_LH_TU_ESP,
	PROFILE_LT_LH_TU_AH,
	PROFILE_LT_LH_TU_ICMP = 0xF,
};

enum profile_lb_uflag {
	PROFILE_F_LB_U_UNK_ETYPE = 0x80,
	PROFILE_F_LB_U_MORE_TAG = 0x40,
};

enum profile_lb_lflag {
	PROFILE_F_LB_L_WITH_CTAG = 1,
	PROFILE_F_LB_L_WITH_CTAG_UNK,
	PROFILE_F_LB_L_WITH_STAG_CTAG,
	PROFILE_F_LB_L_WITH_STAG_STAG,
	PROFILE_F_LB_L_WITH_QINQ_CTAG,
	PROFILE_F_LB_L_WITH_QINQ_QINQ,
	PROFILE_F_LB_L_WITH_ITAG,
	PROFILE_F_LB_L_WITH_ITAG_STAG,
	PROFILE_F_LB_L_WITH_ITAG_CTAG,
	PROFILE_F_LB_L_WITH_ITAG_UNK,
	PROFILE_F_LB_L_WITH_BTAG_ITAG,
	PROFILE_F_LB_L_WITH_STAG,
	PROFILE_F_LB_L_WITH_QINQ,
	PROFILE_F_LB_L_DSA,
	PROFILE_F_LB_L_DSA_VLAN,
	PROFILE_F_LB_L_EDSA,
	PROFILE_F_LB_L_EDSA_VLAN,
	PROFILE_F_LB_L_EXDSA,
	PROFILE_F_LB_L_EXDSA_VLAN,
	PROFILE_F_LB_L_FDSA,
};

enum profile_lc_uflag {
	PROFILE_F_LC_U_UNK_PROTO = 0x10,
	PROFILE_F_LC_U_IP_FRAG = 0x20,
	PROFILE_F_LC_U_IP6_FRAG = 0x40,
};

enum profile_lc_lflag {
	PROFILE_F_LC_L_IP_IN_IP = 1,
	PROFILE_F_LC_L_6TO4,
	PROFILE_F_LC_L_MPLS_IN_IP,
	PROFILE_F_LC_L_IP6_TUN_IP6,
	PROFILE_F_LC_L_IP6_MPLS_IN_IP,
	PROFILE_F_LC_L_MPLS_4_LABELS,
	PROFILE_F_LC_L_MPLS_3_LABELS,
	PROFILE_F_LC_L_MPLS_2_LABELS,
	PROFILE_F_LC_L_EXT_HOP,
	PROFILE_F_LC_L_EXT_DEST,
	PROFILE_F_LC_L_EXT_ROUT,
	PROFILE_F_LC_L_EXT_MOBILITY,
	PROFILE_F_LC_L_EXT_HOSTID,
	PROFILE_F_LC_L_EXT_SHIM6,
};

struct profile_cfg_rsp {
	uint64_t rx_keyx_cfg; /* PROFILE_INTF(0)_KEX_CFG */
	uint64_t tx_keyx_cfg; /* PROFILE_INTF(1)_KEX_CFG */
	/* PROFILE_KEX_LDATA(0..1)_FLAGS_CFG */
	uint64_t kex_ld_flags[PROFILE_MAX_LD];
	/* PROFILE_INTF(0..1)_LID(0..7)_LT(0..15)_LD(0..1)_CFG */
	uint64_t intf_lid_lt_ld[PROFILE_MAX_INTF][PROFILE_MAX_LID][PROFILE_MAX_LT][PROFILE_MAX_LD];
	/* PROFILE_INTF(0..1)_LDATA(0..1)_FLAGS(0..15)_CFG */
	uint64_t intf_ld_flags[PROFILE_MAX_INTF][PROFILE_MAX_LD][PROFILE_MAX_LFL];
#define MKEX_NAME_LEN 128
	uint8_t mkex_pfl_name[MKEX_NAME_LEN];
};

#ifndef BIT_ULL
#define BIT_ULL(nr) (1ULL << (nr))
#endif

#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif

#ifndef BITS_PER_LONG
#define BITS_PER_LONG (__SIZEOF_LONG__ * 8)
#endif
#ifndef BITS_PER_LONG_LONG
#define BITS_PER_LONG_LONG (__SIZEOF_LONG_LONG__ * 8)
#endif

#ifndef GENMASK
#define GENMASK(h, l) (((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#endif
#ifndef GENMASK_ULL
#define GENMASK_ULL(h, l)                                                                          \
	(((~0ULL) - (1ULL << (l)) + 1) & (~0ULL >> (BITS_PER_LONG_LONG - 1 - (h))))
#endif

#define NIX_INTFX_RX(a) (0x0ull | (a) << 1)
#define NIX_INTFX_TX(a) (0x1ull | (a) << 1)

/* Default interfaces are NIX0_RX and NIX0_TX */
#define NIX_INTF_RX NIX_INTFX_RX(0)
#define NIX_INTF_TX NIX_INTFX_TX(0)

#define MKEX_NAME_LEN    128
#define PROFILE_MAX_INTF 2
#define PROFILE_MAX_LID  8
#define PROFILE_MAX_LT   16
#define PROFILE_MAX_LD   2
#define PROFILE_MAX_LFL  16

#define PROFILE_KEXOF_DMAC 9
#define MKEX_SIGN          0x19bbfdbd15f
#define KEX_LD_CFG(bytesm1, hdr_ofs, ena, flags_ena, key_ofs)                                      \
	(((bytesm1) << 16) | ((hdr_ofs) << 8) | ((ena) << 7) | ((flags_ena) << 6) |                \
	 ((key_ofs) & 0x3F))

/* PROFILE_EXACT_KEX_S nibble definitions for each field */
#define PROFILE_EXACT_NIBBLE_HIT   BIT_ULL(40)
#define PROFILE_EXACT_NIBBLE_OPC   BIT_ULL(40)
#define PROFILE_EXACT_NIBBLE_WAY   BIT_ULL(40)
#define PROFILE_EXACT_NIBBLE_INDEX GENMASK_ULL(43, 41)

/* PROFILE_KEX_S nibble definitions for each field */
#define PARSE_NIBBLE_CHAN       GENMASK_ULL(2, 0)
#define PARSE_NIBBLE_ERRLEV     BIT_ULL(3)
#define PARSE_NIBBLE_ERRCODE    GENMASK_ULL(5, 4)
#define PARSE_NIBBLE_L2L3_BCAST BIT_ULL(6)
#define PARSE_NIBBLE_LA_FLAGS   GENMASK_ULL(8, 7)
#define PARSE_NIBBLE_LA_LTYPE   BIT_ULL(9)
#define PARSE_NIBBLE_LB_FLAGS   GENMASK_ULL(11, 10)
#define PARSE_NIBBLE_LB_LTYPE   BIT_ULL(12)
#define PARSE_NIBBLE_LC_FLAGS   GENMASK_ULL(14, 13)
#define PARSE_NIBBLE_LC_LTYPE   BIT_ULL(15)
#define PARSE_NIBBLE_LD_FLAGS   GENMASK_ULL(17, 16)
#define PARSE_NIBBLE_LD_LTYPE   BIT_ULL(18)
#define PARSE_NIBBLE_LE_FLAGS   GENMASK_ULL(20, 19)
#define PARSE_NIBBLE_LE_LTYPE   BIT_ULL(21)
#define PARSE_NIBBLE_LF_FLAGS   GENMASK_ULL(23, 22)
#define PARSE_NIBBLE_LF_LTYPE   BIT_ULL(24)
#define PARSE_NIBBLE_LG_FLAGS   GENMASK_ULL(26, 25)
#define PARSE_NIBBLE_LG_LTYPE   BIT_ULL(27)
#define PARSE_NIBBLE_LH_FLAGS   GENMASK_ULL(29, 28)
#define PARSE_NIBBLE_LH_LTYPE   BIT_ULL(30)

/* Rx parse key extract nibble enable */
#define PARSE_NIBBLE_INTF_RX                                                                       \
	(PARSE_NIBBLE_CHAN | PARSE_NIBBLE_L2L3_BCAST | PARSE_NIBBLE_LA_LTYPE |                     \
	 PARSE_NIBBLE_LB_LTYPE | PARSE_NIBBLE_LC_LTYPE | PARSE_NIBBLE_LD_LTYPE |                   \
	 PARSE_NIBBLE_LE_LTYPE)
/* Tx parse key extract nibble enable */
#define PARSE_NIBBLE_INTF_TX                                                                       \
	(PARSE_NIBBLE_LA_LTYPE | PARSE_NIBBLE_LB_LTYPE | PARSE_NIBBLE_LC_LTYPE |                   \
	 PARSE_NIBBLE_LD_LTYPE | PARSE_NIBBLE_LE_LTYPE)

#define FLOW_PARSER_PROFILE_VER 1
struct flow_parser_tcam_kex {
	/* MKEX Profle Header */
	uint64_t mkex_sign;          /* "mcam-kex-profile" (8 bytes/ASCII characters) */
	uint8_t name[MKEX_NAME_LEN]; /* MKEX Profile name */
	uint64_t cpu_model;          /* Format as profiled by CPU hardware */
	uint64_t prfl_version;        /* KPU firmware/profile version */
	uint64_t reserved;           /* Reserved for extension */

	/* MKEX Profle Data */
	uint64_t keyx_cfg[PROFILE_MAX_INTF]; /* PROFILE_INTF(0..1)_KEX_CFG */
	/* PROFILE_KEX_LDATA(0..1)_FLAGS_CFG */
	uint64_t kex_ld_flags[PROFILE_MAX_LD];
	/* PROFILE_INTF(0..1)_LID(0..7)_LT(0..15)_LD(0..1)_CFG */
	uint64_t intf_lid_lt_ld[PROFILE_MAX_INTF][PROFILE_MAX_LID][PROFILE_MAX_LT][PROFILE_MAX_LD];
	/* PROFILE_INTF(0..1)_LDATA(0..1)_FLAGS(0..15)_CFG */
	uint64_t intf_ld_flags[PROFILE_MAX_INTF][PROFILE_MAX_LD][PROFILE_MAX_LFL];
} __rte_packed;

#endif /* _PROFILE_PRIV_H_ */