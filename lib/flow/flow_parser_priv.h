/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _FLOW_PARSER_PRIV_H_
#define _FLOW_PARSER_PRIV_H_

#include <rte_atomic.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_flow.h>
#include <sys/queue.h>

#include "profile_priv.h"

#define IH_LENGTH               8
#define TPID_LENGTH             2
#define HIGIG2_LENGTH           16
#define PARSER_MAX_RAW_ITEM_LEN 16
#define COUNTER_NONE            (-1)

/* 32 bytes from LDATA_CFG & 32 bytes from FLAGS_CFG */
#define PROFILE_MAX_EXTRACT_DATA_LEN (64)
#define PROFILE_MAX_EXTRACT_HW_LEN   (4 * PROFILE_MAX_EXTRACT_DATA_LEN)
#define PROFILE_LDATA_LFLAG_LEN      (16)
#define PROFILE_MAX_KEY_NIBBLES      (31)

/* Nibble offsets */
#define PROFILE_LAYER_KEYX_SZ   (3)
#define PROFILE_KEX_S_LA_OFFSET (7)
#define PROFILE_KEX_S_LID_OFFSET(lid)                                                              \
	((((lid) - (PROFILE_LID_LA)) * PROFILE_LAYER_KEYX_SZ) + PROFILE_KEX_S_LA_OFFSET)

#define PROFILE_LTYPE_OFFSET_START 7
/* LB OFFSET : START + LA (2b flags + 1b ltype) + LB (2b flags) */
#define PROFILE_LTYPE_LB_OFFSET (PROFILE_LTYPE_OFFSET_START + 5)
#define PROFILE_LFLAG_LB_OFFSET (PROFILE_LTYPE_OFFSET_START + 3)
/* LC OFFSET : START + LA (2b flags + 1b ltype) + LB (2b flags + 1b ltype) + LC
 * (2b flags)
 */
#define PROFILE_LFLAG_LC_OFFSET (PROFILE_LTYPE_OFFSET_START + 6)
#define PROFILE_LTYPE_LC_OFFSET (PROFILE_LTYPE_OFFSET_START + 8)

#define PARSER_ETHER_TYPE_VLAN 0x8100 /**< IEEE 802.1Q VLAN tagging. */
#define PARSER_ETHER_TYPE_QINQ 0x88A8 /**< IEEE 802.1ad QinQ tagging. */

enum parse_err_status {
	PARSE_ERR_PARAM = -1024,
	PARSE_ERR_NO_MEM,
	PARSE_ERR_INVALID_SPEC,
	PARSE_ERR_INVALID_MASK,
	PARSE_ERR_INVALID_RANGE,
	PARSE_ERR_INVALID_KEX,
	PARSE_ERR_INVALID_SIZE,
	PARSE_ERR_INTERNAL,
	PARSE_ERR_MCAM_ALLOC,
	PARSE_ERR_ACTION_NOTSUP,
	PARSE_ERR_PATTERN_NOTSUP,
};

enum profile_cam_intf { PROFILE_CAM_RX, PROFILE_CAM_TX };

struct parse_item_info {
	const void *def_mask; /* default mask */
	void *hw_mask;        /* hardware supported mask */
	int len;              /* length of item */
	const void *spec;     /* spec to use, NULL implies match any */
	const void *mask;     /* mask to use */
	uint8_t hw_hdr_len;   /* Extra data len at each layer*/
};

struct parse_state {
	struct flow_parser *parser;
	const struct rte_flow_item *pattern;
	const struct rte_flow_item *last_pattern;
	struct parsed_flow *flow;
	uint8_t nix_intf;
	uint8_t tunnel;
	uint8_t terminate;
	uint8_t layer_mask;
	uint8_t lt[PROFILE_MAX_LID];
	uint8_t flags[PROFILE_MAX_LID];
	uint8_t *parsed_data;      /* point to flow->parsed_data + key_len */
	uint8_t *parsed_data_mask; /* point to flow->parsed_data_mask + key_len */
	bool is_vf;
	/* adjust ltype in MCAM to match at least one vlan */
	bool set_vlan_ltype_mask;
	bool set_ipv6ext_ltype_mask;
	bool is_second_pass_rule;
	bool has_eth_type;
	uint16_t nb_tx_queues;
	uint16_t dst_pf_func;
};

struct profile_xtract_info {
	/* Length in bytes of pkt data extracted. len = 0
	 * indicates that extraction is disabled.
	 */
	uint8_t len;
	uint8_t hdr_off;      /* Byte offset of proto hdr: extract_src */
	uint8_t key_off;      /* Byte offset in MCAM key where data is placed */
	uint8_t enable;       /* Extraction enabled or disabled */
	uint8_t flags_enable; /* Flags extraction enabled */
	uint8_t use_hash;     /* Use field hash */
};

/* Information for a given {LAYER, LTYPE} */
struct profile_lid_lt_xtract_info {
	/* Info derived from parser configuration */
	uint16_t proto;             /* Network protocol identified */
	uint8_t valid_flags_mask;   /* Flags applicable */
	uint8_t is_terminating : 1; /* No more parsing */
	struct profile_xtract_info xtract[PROFILE_MAX_LD];
};

union profile_kex_ldata_flags_cfg {
	struct {
		uint64_t lid : 3;
		uint64_t rvsd_62_1 : 61;
	} s;

	uint64_t i;
};

typedef struct profile_lid_lt_xtract_info profile_dxcfg_t[PROFILE_MAX_INTF][PROFILE_MAX_LID]
							 [PROFILE_MAX_LT];
typedef struct profile_lid_lt_xtract_info profile_fxcfg_t[PROFILE_MAX_INTF][PROFILE_MAX_LD]
							 [PROFILE_MAX_LFL];
typedef union profile_kex_ldata_flags_cfg profile_ld_flags_t[PROFILE_MAX_LD];

struct flow_parser {
	uint32_t keyx_supp_nmask[PROFILE_MAX_INTF]; /* nibble mask */
	uint32_t keyx_len[PROFILE_MAX_INTF];        /* per intf key len in bits */
	uint32_t keyw[PROFILE_MAX_INTF];            /* max key + data len bits */
	uint16_t channel;                           /* RX Channel number */
	uint16_t switch_header_type;                /* Supported switch header type */
	uint16_t pf_func;                           /* pf_func of device */
	profile_dxcfg_t prx_dxcfg;                  /* intf, lid, lt, extract */
	profile_fxcfg_t prx_fxcfg;                  /* Flag extract */
	profile_ld_flags_t prx_lfcfg;               /* KEX LD_Flags CFG */
	uint64_t rx_parse_nibble;
#define FLOW_PARSER_MIRROR_LIST_SIZE 2
	uint16_t mcast_pf_funcs[FLOW_PARSER_MIRROR_LIST_SIZE];
	uint16_t mcast_channels[FLOW_PARSER_MIRROR_LIST_SIZE];
};

struct parsed_flow_dump_data {
	uint8_t lid;
	uint16_t ltype;
};

struct parsed_flow {
	uint8_t nix_intf;
	uint8_t enable;
	uint32_t cam_idx;
	uint8_t use_ctr;
	int32_t ctr_idx;
	uint32_t priority;
#define FLOW_PARSER_MAX_MCAM_WIDTH_DWORDS 7
	/* Contiguous match string */
	uint64_t parsed_data[FLOW_PARSER_MAX_MCAM_WIDTH_DWORDS];
	uint64_t parsed_data_mask[FLOW_PARSER_MAX_MCAM_WIDTH_DWORDS];
#define FLOW_PARSER_MAX_FLOW_PATTERNS 32
	struct parsed_flow_dump_data dump_data[FLOW_PARSER_MAX_FLOW_PATTERNS];
	uint16_t num_patterns;
};

enum flow_parser_intf {
	FLOW_PARSER_INTF_RX = 0,
	FLOW_PARSER_INTF_TX = 1,
	FLOW_PARSER_INTF_MAX = 2,
};

enum flow_vtag_cfg_dir { VTAG_TX, VTAG_RX };

#define FLOW_PARSER_AGE_POLL_FREQ_MIN 10

int flow_parser_init(struct flow_parser *parser, struct flow_parser_tcam_kex *parse_prfl);
struct parsed_flow *flow_parse(struct flow_parser *parser, const struct rte_flow_attr *attr,
			       const struct rte_flow_item pattern[],
			       const struct rte_flow_action actions[]);

#endif /* _FLOW_PARSER_PRIV_H_ */
