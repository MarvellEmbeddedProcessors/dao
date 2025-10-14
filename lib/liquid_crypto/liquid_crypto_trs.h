/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell
 */

#ifndef __LIQUID_CRYPTO_TRS_H__
#define __LIQUID_CRYPTO_TRS_H__

#include <rte_common.h>

#include <dao_eth_trs.h>
#include <dao_liquid_crypto.h>
#include <dao_util.h>

#include <liquid_crypto_op_defines.h>

struct __rte_packed __dao_lc_hdr {
	struct dao_eth_trs_hdr trs_hdr;
	uint32_t req_idx;
};

DAO_STATIC_ASSERT(sizeof(struct __dao_lc_hdr) == 8);

struct __rte_packed __dao_lc_req_sym {
	struct __dao_lc_hdr hdr;
	uint64_t w4;
	uint64_t w7;
	enum lc_crypto_op_type op_type;
	uint64_t is_gmac : 1;
	uint64_t rsvd_align : 31;
	uint8_t dptr[];
};

struct __rte_packed __dao_lc_resp_sym {
	struct __dao_lc_hdr hdr;
	union dao_cpt_res_s res;
	uint64_t rsvd_align;
	uint8_t rptr[];
};

DAO_STATIC_ASSERT(sizeof(struct __dao_lc_req_sym) == sizeof(struct __dao_lc_resp_sym));

struct __rte_packed __dao_lc_req_asym {
	struct __dao_lc_hdr hdr;
	enum lc_crypto_op_type op_type;
	uint64_t w4;
	union {
		/* Used for OAEP Encode */
		uint16_t exp_len;
		/* Used for OAEP Decode */
		uint16_t hash_type;
	};
	uint8_t dptr[];
};

struct __rte_packed __dao_lc_resp_asym {
	struct __dao_lc_hdr hdr;
	union dao_cpt_res_s res;
	uint8_t rptr[];
};

struct __rte_packed __dao_lc_req_sess_create {
	struct __dao_lc_hdr hdr;
	uint64_t opcode : 16;
	uint64_t rsvd_align : 48;
	uint8_t cptr[];
};

struct __rte_packed __dao_lc_resp_sess_create {
	struct __dao_lc_hdr hdr;
	uint64_t sess_id;
};

struct __rte_packed __dao_lc_req_resp_sess_destroy {
	struct __dao_lc_hdr hdr;
	uint64_t sess_id;
};

#endif /*  __LIQUID_CRYPTO_TRS_H__ */
