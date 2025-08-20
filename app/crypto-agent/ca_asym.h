/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __CA_ASYM_H__
#define __CA_ASYM_H__

#include <dao_eth_trs.h>
#include <dao_liquid_crypto.h>
#include <mc/ae.h>

#include "crypto_agent.h"

int ca_ae_fpm_get(uint8_t dev_id);

int ca_ae_ec_grp_get(uint8_t dev_id);

static inline void
ca_handle_ec_sign_verify_op(union cpt_inst_w4 w4, struct cpt_inflight_req *infl_req,
			    struct rte_pmd_cnxk_crypto_ae_ec_group_params *ec_grp, uint8_t *dptr)
{
	uint16_t o_offset = ec_grp->prime.length - ec_grp->order.length;
	uint16_t p_align = RTE_ALIGN_CEIL(ec_grp->prime.length, 8);
	uint16_t digest_len = (w4.s.param1 >> 8) & 0xFF;
	uint16_t m_align = RTE_ALIGN_CEIL(digest_len, 8);
	uint8_t opcode_minor = w4.s.opcode_minor;

	if ((opcode_minor == ROC_AE_MINOR_OP_EC_SIGN)) {
		uint16_t nonce_len = w4.s.param2 & 0xFF;
		uint16_t nonce_align = RTE_ALIGN_CEIL(nonce_len, 8);

		/* Store prime length in inflight request to copy r and s
		 * components of sign data from response buffer
		 */
		infl_req->ec_prime_len = ec_grp->prime.length;

		dptr += nonce_align;
		/* Store prime length */
		memcpy(dptr, ec_grp->prime.data, ec_grp->prime.length);
		dptr += p_align;

		/* Store order length */
		memcpy(dptr + o_offset, ec_grp->order.data, ec_grp->order.length);
		dptr += p_align;

		/* Skip private key component */
		dptr += p_align;
		/* Skip digest data */
		dptr += m_align;
	} else if (opcode_minor == ROC_AE_MINOR_OP_EC_VERIFY) {
		/* Skip r component */
		dptr += p_align;
		/* Skip s component */
		dptr += p_align;
		/* Skip digest data */
		dptr += m_align;
		/* Store order at offset */
		memcpy(dptr + o_offset, ec_grp->order.data, ec_grp->order.length);
		dptr += p_align;
		/* Store prime */
		memcpy(dptr, ec_grp->prime.data, ec_grp->prime.length);
		dptr += p_align;

		/* Skip public key x and y components */
		dptr += p_align;
		dptr += p_align;
	}

	/* Store consta and constb components*/
	memcpy(dptr, ec_grp->consta.data, ec_grp->consta.length);
	dptr += p_align;
	memcpy(dptr, ec_grp->constb.data, ec_grp->constb.length);
	dptr += p_align;
}

static inline void
ca_handle_asym_op(struct cpt_inst_s *inst, struct cpt_inflight_req *infl_req,
		  struct __dao_lc_req_asym *asym, struct __dao_lc_resp_asym *asym_resp,
		  union cpt_inst_w4 w4)
{
	uint8_t opcode_major = w4.s.opcode_major;
	uint8_t opcode_minor = w4.s.opcode_minor;
	uint64_t curve_id;

	if (opcode_major == ROC_AE_MAJOR_OP_MODEX) {
		infl_req->rsa_mod_len = w4.s.param1;

		if (opcode_minor == ROC_AE_MINOR_OP_PKCS_DEC_CRT ||
		    opcode_minor == ROC_AE_MINOR_OP_PKCS_DEC) {
			/* Reserve two bytes for output length */
			inst->rptr = (uint64_t)RTE_PTR_SUB(asym_resp->rptr, 2);
		}
	} else if (opcode_major == ROC_AE_MAJOR_OP_EC) {
		/* Store first 8 bytes from inst[i].dptr in curve_id */
		curve_id = *(uint64_t *)inst->w5.u64;

		if (curve_id > ca_glb_ctx.nb_ae_ec_max_entries) {
			CA_ERR("Invalid curve_id: %lu", curve_id);
			infl_req->res.cn9k.compcode = DAO_CPT_COMP_NOT_DONE;
			return;
		}

		struct rte_pmd_cnxk_crypto_ae_ec_group_params *ec_grp =
			ca_glb_ctx.ca_ec_grp[curve_id];
		if (ec_grp == NULL) {
			CA_ERR("ec_grp[%lu] is NULL", curve_id);
			infl_req->res.cn9k.compcode = DAO_CPT_COMP_NOT_DONE;
			return;
		}

		uint8_t *dptr = asym->dptr;

		/* Store Host address of FPM table in first 8 bytes of dptr
		 * based on curve_id.
		 */
		*(uint64_t *)dptr = ca_glb_ctx.ca_ae_fpm_iova[curve_id];
		dptr += sizeof(uint64_t);

		ca_handle_ec_sign_verify_op(w4, infl_req, ec_grp, dptr);
	}
}

#endif /* __CA_ASYM_H__ */
