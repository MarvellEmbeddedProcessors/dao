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

struct __rte_packed_begin __dao_lc_hdr {
	struct dao_eth_trs_hdr trs_hdr;
	uint32_t req_idx;
} __rte_packed_end;

DAO_STATIC_ASSERT(sizeof(struct __dao_lc_hdr) == 8);

struct __rte_packed_begin __dao_lc_req_sym {
	struct __dao_lc_hdr hdr;
	uint64_t w4;
	uint64_t w7;
	enum lc_crypto_op_type op_type;
	uint64_t is_gmac : 1;
	uint64_t rsvd_align : 31;
	uint8_t dptr[];
} __rte_packed_end;

struct __rte_packed_begin __dao_lc_resp_sym {
	struct __dao_lc_hdr hdr;
	union dao_cpt_res_s res;
	uint64_t rsvd_align;
	uint8_t rptr[];
} __rte_packed_end;

DAO_STATIC_ASSERT(sizeof(struct __dao_lc_req_sym) == sizeof(struct __dao_lc_resp_sym));

struct __rte_packed_begin __dao_lc_req_asym {
	struct __dao_lc_hdr hdr;
	enum lc_crypto_op_type op_type;
	uint64_t w4;
	union {
		/* Used for RSA PAD SCHEME Encode */
		uint16_t exp_len;
		/* Used for RSA PAD SCHEME Decode */
		uint16_t hash_type;
	};
	uint8_t dptr[];
} __rte_packed_end;

struct __rte_packed_begin __dao_lc_resp_asym {
	struct __dao_lc_hdr hdr;
	union dao_cpt_res_s res;
	uint8_t status_flags;
	uint8_t rptr[];
} __rte_packed_end;

struct __rte_packed_begin __dao_lc_req_pqc {
	struct __dao_lc_hdr hdr;
	uint64_t rsvd_align;
	uint64_t w4;
	uint8_t dptr[];
} __rte_packed_end;

struct __rte_packed_begin __dao_lc_resp_pqc {
	struct __dao_lc_hdr hdr;
	union dao_cpt_res_s res;
	uint8_t rptr[];
} __rte_packed_end;

struct __rte_packed_begin __dao_lc_req_sess_create {
	struct __dao_lc_hdr hdr;
	uint64_t opcode : 16;
	uint64_t rsvd_align : 48;
	uint8_t cptr[];
} __rte_packed_end;

struct __rte_packed_begin __dao_lc_resp_sess_create {
	struct __dao_lc_hdr hdr;
	uint64_t sess_id;
} __rte_packed_end;

struct __rte_packed_begin __dao_lc_req_resp_sess_destroy {
	struct __dao_lc_hdr hdr;
	uint64_t sess_id;
} __rte_packed_end;

struct __rte_packed_begin __dao_lc_req_comp_op {
	struct __dao_lc_hdr hdr;
	/** Source data length */
	uint32_t src_len;
	/** Output buffer length */
	uint32_t op_buf_len;
	/**
	 * Minimum compression level = 1
	 * Maximum compression level = 9
	 */
	uint32_t level : 4;
	/**  Compression algorithm */
	uint32_t comp_algo : 2;
	/**  Compression huffman encoding type */
	uint32_t huff_enc_type : 2;
	/** Padding */
	uint32_t rsvd_align : 24;
	/** Plain text to be compressed */
	uint8_t input[];
} __rte_packed_end;

struct __rte_packed_begin __dao_lc_resp_compdev_op {
	struct __dao_lc_hdr hdr;
	/** Compress device result for compress op */
	struct dao_compdev_res res;
	/** Output data length */
	uint32_t op_len;
	/** Buffer to store compress device output */
	uint8_t output[];
} __rte_packed_end;

struct __rte_packed_begin __dao_lc_req_decomp_op {
	struct __dao_lc_hdr hdr;
	/** Source data length */
	uint32_t src_len;
	/** Output buffer length */
	uint32_t op_buf_len;
	/**  Compression algorithm */
	enum dao_lc_comp_algo comp_algo;
	/** Compressed text to be decompressed */
	uint8_t input[];
} __rte_packed_end;
#endif /*  __LIQUID_CRYPTO_TRS_H__ */
