/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __CA_PQC_H__
#define __CA_PQC_H__

#include <rte_common.h>
#include <rte_hexdump.h>

#include <dao_liquid_crypto.h>
#include <dao_log.h>

#include <oqs/oqs.h>

#include "hw/cpt.h"

static const char *const pqc_ml_kem_alg_names[] = {
	[DAO_LC_ML_KEM_512] = "ML-KEM-512",
	[DAO_LC_ML_KEM_768] = "ML-KEM-768",
	[DAO_LC_ML_KEM_1024] = "ML-KEM-1024",
};

static const char *const pqc_ml_dsa_alg_names[] = {
	[DAO_LC_ML_DSA_44] = "ML-DSA-44",
	[DAO_LC_ML_DSA_65] = "ML-DSA-65",
	[DAO_LC_ML_DSA_87] = "ML-DSA-87",
};

static int
ca_pqc_process(struct rte_mbuf *mb, union dao_cpt_res_s *res)
{
	struct __dao_lc_req_pqc *req;
	struct __dao_lc_resp_pqc *resp;
	union cpt_inst_w4 w4;
	size_t sig_len = 0;
	OQS_KEM *kem = NULL;
	OQS_SIG *dsa = NULL;
	uint8_t alg = 0;

	req = rte_pktmbuf_mtod(mb, struct __dao_lc_req_pqc *);
	w4.u64 = req->w4;
	switch (w4.s.opcode_major) {
	case ROC_AE_MAJOR_OP_ML_KEM:
		kem = OQS_KEM_new(pqc_ml_kem_alg_names[w4.s.param2]);
		if (kem == NULL) {
			dao_err("Failed to create KEM instance for algorithm: %d", w4.s.param2);
			rte_errno = ENOMEM;
			return -ENOMEM;
		}

		switch (w4.s.opcode_minor) {
		case ROC_AE_MINOR_OP_ML_KEM_KEYGEN:
			resp = (struct __dao_lc_resp_pqc *)req;
			res->pqc.op_type = DAO_LC_ML_KEM_OP_KEYGEN;
			res->pqc.alg = w4.s.param2;
			res->pqc.compcode = OQS_KEM_keypair(
				kem, resp->rptr /*public key */,
				resp->rptr + pqc_ml_pub_key_len[w4.s.param2] /* private key */);
			res->pqc.data_out_len =
				pqc_ml_pub_key_len[w4.s.param2] + pqc_ml_priv_key_len[w4.s.param2];
#ifdef DAO_LIQUID_CRYPTO_DEBUG
			rte_hexdump(stdout, "Public Key", resp->rptr,
				    pqc_ml_pub_key_len[w4.s.param2]);
			rte_hexdump(stdout, "Private Key",
				    resp->rptr + pqc_ml_pub_key_len[w4.s.param2],
				    pqc_ml_priv_key_len[w4.s.param2]);
#endif
			OQS_KEM_free(kem);
			return res->pqc.compcode;
		case ROC_AE_MINOR_OP_ML_KEM_ENCAP:
			resp = (struct __dao_lc_resp_pqc *)rte_pktmbuf_adj(
				mb,
				sizeof(struct __dao_lc_req_pqc) + pqc_ml_pub_key_len[w4.s.param2]);
			resp->hdr.req_idx = req->hdr.req_idx;
			resp->hdr.trs_hdr.op_len = req->hdr.trs_hdr.op_len;
			resp->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_PQC;
			res->pqc.op_type = DAO_LC_ML_KEM_OP_ENCAP;
			res->pqc.alg = w4.s.param2;
			res->pqc.compcode = OQS_KEM_encaps(
				kem, resp->rptr + DAO_LC_ML_KEM_SHARED_SECRET_LEN /* cipher text */,
				resp->rptr /* shared secret */, req->dptr /* public key */);
			res->pqc.data_out_len = pqc_ml_ciphertext_len[w4.s.param2] +
						DAO_LC_ML_KEM_SHARED_SECRET_LEN;
#ifdef DAO_LIQUID_CRYPTO_DEBUG
			rte_hexdump(stdout, "Shared Secret (Encap)", resp->rptr,
				    DAO_LC_ML_KEM_SHARED_SECRET_LEN);
			rte_hexdump(stdout, "Cipher text",
				    resp->rptr + DAO_LC_ML_KEM_SHARED_SECRET_LEN,
				    pqc_ml_ciphertext_len[w4.s.param2]);
#endif
			OQS_KEM_free(kem);
			return res->pqc.compcode;
		case ROC_AE_MINOR_OP_ML_KEM_DECAP:
			resp = (struct __dao_lc_resp_pqc *)rte_pktmbuf_adj(
				mb, sizeof(struct __dao_lc_req_pqc) +
					    pqc_ml_priv_key_len[w4.s.param2] +
					    pqc_ml_ciphertext_len[w4.s.param2]);
			resp->hdr.req_idx = req->hdr.req_idx;
			resp->hdr.trs_hdr.op_len = req->hdr.trs_hdr.op_len;
			resp->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_PQC;
			res->pqc.op_type = DAO_LC_ML_KEM_OP_DECAP;
			res->pqc.alg = w4.s.param2;
			res->pqc.compcode = OQS_KEM_decaps(
				kem, resp->rptr,                              /* shared secret */
				req->dptr + pqc_ml_priv_key_len[w4.s.param2], /* cipher text*/
				req->dptr /* Private key */);
			res->pqc.data_out_len = DAO_LC_ML_KEM_SHARED_SECRET_LEN;
#ifdef DAO_LIQUID_CRYPTO_DEBUG
			rte_hexdump(stdout, "Shared Secret (Decap)",
				    resp->rptr + pqc_ml_priv_key_len[w4.s.param2] +
					    pqc_ml_ciphertext_len[w4.s.param2],
				    DAO_LC_ML_KEM_SHARED_SECRET_LEN);
#endif
			OQS_KEM_free(kem);
			return res->pqc.compcode;
		default:
			dao_err("Unsupported PQC ML KEM operation: %d", w4.s.opcode_minor);
			rte_errno = EINVAL;
			OQS_KEM_free(kem);
			return -EINVAL;
		}
	case ROC_AE_MAJOR_OP_ML_DSA:
		dsa = OQS_SIG_new(pqc_ml_dsa_alg_names[(w4.s.param2 & 0x3) + 3]);
		if (dsa == NULL) {
			dao_err("Failed to create DSA instance for algorithm: %d",
				w4.s.param2 & 0x3);
			rte_errno = ENOMEM;
			return -ENOMEM;
		}

		alg = (w4.s.param2 & 0x3) + 3; /* Extract algorithm from param2 */
		switch (w4.s.opcode_minor) {
		case ROC_AE_MINOR_OP_ML_DSA_KEYGEN:
			resp = (struct __dao_lc_resp_pqc *)req;
			res->pqc.op_type = DAO_LC_ML_DSA_OP_KEYGEN;
			res->pqc.alg = alg;
			res->pqc.compcode = OQS_SIG_keypair(
				dsa, resp->rptr, /*public key */
				resp->rptr + pqc_ml_pub_key_len[alg] /* private key */);
			res->pqc.data_out_len = pqc_ml_pub_key_len[alg] + pqc_ml_priv_key_len[alg];
#ifdef DAO_LIQUID_CRYPTO_DEBUG
			rte_hexdump(stdout, "DSA Public Key", resp->rptr, pqc_ml_pub_key_len[alg]);
			rte_hexdump(stdout, "DSA Private Key", resp->rptr + pqc_ml_pub_key_len[alg],
				    pqc_ml_priv_key_len[alg]);
#endif
			OQS_SIG_free(dsa);
			return res->pqc.compcode;
		case ROC_AE_MINOR_OP_ML_DSA_SIGN:
			resp = (struct __dao_lc_resp_pqc *)rte_pktmbuf_adj(
				mb, sizeof(struct __dao_lc_req_pqc) + pqc_ml_priv_key_len[alg] +
					    (w4.s.param2 >> 2) + w4.s.param1);
			resp->hdr.req_idx = req->hdr.req_idx;
			resp->hdr.trs_hdr.op_len = req->hdr.trs_hdr.op_len;
			resp->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_PQC;
			res->pqc.op_type = DAO_LC_ML_DSA_OP_SIGN;
			res->pqc.alg = alg;
			res->pqc.compcode = OQS_SIG_sign_with_ctx_str(
				dsa, resp->rptr, /* signature */
				&sig_len,        /* signature length */
				req->dptr + pqc_ml_priv_key_len[alg] +
					(w4.s.param2 >> 2),           /* message */
				w4.s.param1,                          /* message length */
				req->dptr + pqc_ml_priv_key_len[alg], /* context */
				(w4.s.param2 >> 2),                   /* context length */
				req->dptr /*private key*/);
#ifdef DAO_LIQUID_CRYPTO_DEBUG
			rte_hexdump(stdout, "DSA Signature", resp->rptr, sig_len);
#endif
			res->pqc.data_out_len = sig_len;
			OQS_SIG_free(dsa);
			return res->pqc.compcode;
		case ROC_AE_MINOR_OP_ML_DSA_VERIFY:
			res->pqc.op_type = DAO_LC_ML_DSA_OP_VERIFY;
			res->pqc.alg = alg;
			res->pqc.compcode = OQS_SIG_verify_with_ctx_str(
				dsa,
				req->dptr + pqc_ml_pub_key_len[alg] +
					(w4.s.param2 >> 2) /* message */,
				w4.s.param1 /* message length */,
				req->dptr + pqc_ml_pub_key_len[alg] + (w4.s.param2 >> 2) +
					w4.s.param1 /* signature */,
				pqc_ml_signature_len[alg] /* signature length */,
				req->dptr + pqc_ml_pub_key_len[alg] /* context */,
				(w4.s.param2 >> 2) /* context length */, req->dptr /*public key*/);
			res->pqc.data_out_len = 0;
			OQS_SIG_free(dsa);
			return res->pqc.compcode;
		default:
			dao_err("Unsupported PQC ML DSA operation: %d", w4.s.opcode_minor);
			rte_errno = EINVAL;
			OQS_SIG_free(dsa);
			return -EINVAL;
		}
	}
	return 0;
}

#endif /* __CA_PQC_H__ */
