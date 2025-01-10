/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell
 */

#ifndef __HW_CPT_H__
#define __HW_CPT_H__

/* Completion codes */
#define CPT_COMP_NOT_DONE (0x0ull)
#define CPT_COMP_GOOD     (0x1ull)
#define CPT_COMP_FAULT    (0x2ull)
#define CPT_COMP_SWERR    (0x3ull)
#define CPT_COMP_HWERR    (0x4ull)
#define CPT_COMP_INSTERR  (0x5ull)
#define CPT_COMP_WARN     (0x6ull)

/* CPT instruction words */
union cpt_inst_w4 {
	uint64_t u64;
	struct {
		uint64_t dlen : 16;
		uint64_t param2 : 16;
		uint64_t param1 : 16;
		uint64_t opcode_major : 8;
		uint64_t opcode_minor : 8;
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

/* Default engine groups */
#define ROC_LEGACY_CPT_DFLT_ENG_GRP_SE    0UL
#define ROC_LEGACY_CPT_DFLT_ENG_GRP_SE_IE 1UL
#define ROC_LEGACY_CPT_DFLT_ENG_GRP_AE    2UL

#endif /*  __HW_CPT_H__ */
