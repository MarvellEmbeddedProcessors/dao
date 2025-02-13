/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell
 */

#ifndef __HW_CPT_H__
#define __HW_CPT_H__

#include <rte_byteorder.h>

#define ROC_ALIGN 128

/* CPT instruction words */
union cpt_inst_w4 {
	uint64_t u64;
	struct {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
		uint64_t dlen : 16;
		uint64_t param2 : 16;
		uint64_t param1 : 16;
		uint64_t opcode_major : 8;
		uint64_t opcode_minor : 8;
#else
		uint64_t opcode_minor : 8;
		uint64_t opcode_major : 8;
		uint64_t param1 : 16;
		uint64_t param2 : 16;
		uint64_t dlen : 16;
#endif
	} s;
};

union cpt_inst_w5 {
	uint64_t u64;
	struct {
		uint64_t dptr : 60;
		uint64_t gather_sz : 4;
	} s;
};

union cpt_inst_w6 {
	uint64_t u64;
	struct {
		uint64_t rptr : 60;
		uint64_t scatter_sz : 4;
	} s;
};

union cpt_inst_w7 {
	uint64_t u64;
	struct {
		uint64_t cptr : 60;
		uint64_t ctx_val : 1;
		uint64_t egrp : 3;
	} s;
};

struct cpt_inst_s {
	union cpt_inst_w0 {
		struct {
			uint64_t nixtxl : 3;
			uint64_t doneint : 1;
			uint64_t nixtx_addr : 60;
		} s;
		uint64_t u64;
	} w0;

	uint64_t res_addr;

	union cpt_inst_w2 {
		struct {
			uint64_t tag : 32;
			uint64_t tt : 2;
			uint64_t grp : 10;
			uint64_t reserved_172_175 : 4;
			uint64_t rvu_pf_func : 16;
		} s;
		uint64_t u64;
	} w2;

	union cpt_inst_w3 {
		struct {
			uint64_t qord : 1;
			uint64_t reserved_194_193 : 2;
			uint64_t wqe_ptr : 61;
		} s;
		uint64_t u64;
	} w3;

	union cpt_inst_w4 w4;

	union {
		union cpt_inst_w5 w5;
		uint64_t dptr;
	};

	union {
		union cpt_inst_w6 w6;
		uint64_t rptr;
	};

	union cpt_inst_w7 w7;
};

/* Default engine groups */
#define ROC_LEGACY_CPT_DFLT_ENG_GRP_SE    0UL
#define ROC_LEGACY_CPT_DFLT_ENG_GRP_SE_IE 1UL
#define ROC_LEGACY_CPT_DFLT_ENG_GRP_AE    2UL

#endif /*  __HW_CPT_H__ */
