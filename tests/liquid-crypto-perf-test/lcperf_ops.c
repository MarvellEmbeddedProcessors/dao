/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <dao_liquid_crypto.h>

#include "lcperf_ops.h"
#include "lcperf_test_vectors.h"

static int
lcperf_set_op_passthrough(uint8_t dev_id, uint16_t qp_id, const struct lcperf_test_data *tdata,
			  const struct lcperf_options *options __rte_unused)
{
	return dao_liquid_crypto_enqueue_op_passthrough(dev_id, qp_id, tdata->op_cookie);
}

static int
lcperf_set_ops_asym_rsa(uint8_t dev_id, uint16_t qp_id, const struct lcperf_test_data *tdata,
			const struct lcperf_options *options)
{
	const struct lcperf_rsa_test_data *params = options->rsa_data;
	uint8_t message[LC_PERF_MAX_OUTPUT_LEN];
	uint8_t output[LC_PERF_MAX_OUTPUT_LEN];

	if (options->asym_op_type == LCPERF_CRYPTO_ASYM_OP_PUB_ENCRYPT) {
		return dao_liquid_crypto_enq_op_pkcs1v15enc(
			dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PUBLIC, params->n.len, params->e.len,
			params->plaintext.len, params->n.data, params->e.data,
			params->plaintext.data, output, tdata->op_cookie);
	} else if (options->asym_op_type == LCPERF_CRYPTO_ASYM_OP_PRV_ENCRYPT) {
		if (options->rsa_priv_keytype == LCPERF_RSA_KEY_TYPE_QT) {
			return dao_liquid_crypto_enq_op_pkcs1v15enc_crt(
				dev_id, qp_id, params->n.len, params->plaintext.len, params->q.data,
				params->dQ.data, params->p.data, params->dP.data, params->qInv.data,
				params->plaintext.data, output, tdata->op_cookie);
		} else {
			return dao_liquid_crypto_enq_op_pkcs1v15enc(
				dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PRIVATE, params->n.len,
				params->d.len, params->plaintext.len, params->n.data,
				params->d.data, params->plaintext.data, output, tdata->op_cookie);
		}
	} else if (options->asym_op_type == LCPERF_CRYPTO_ASYM_OP_PRV_DECRYPT) {
		if (options->rsa_priv_keytype == LCPERF_RSA_KEY_TYPE_QT) {
			return dao_liquid_crypto_enq_op_pkcs1v15dec_crt(
				dev_id, qp_id, params->n.len, params->q.data, params->dQ.data,
				params->p.data, params->dP.data, params->qInv.data,
				params->cipher.data, message, tdata->op_cookie);
		} else {
			return dao_liquid_crypto_enq_op_pkcs1v15dec(
				dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PRIVATE, params->n.len,
				params->d.len, params->n.data, params->d.data, params->cipher.data,
				message, tdata->op_cookie);
		}
	} else if (options->asym_op_type == LCPERF_CRYPTO_ASYM_OP_PUB_DECRYPT) {
		return dao_liquid_crypto_enq_op_pkcs1v15dec(
			dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PUBLIC, params->n.len, params->e.len,
			params->n.data, params->e.data, params->sign.data, message,
			tdata->op_cookie);
	}
	return -ENOTSUP;
}

int
lcperf_get_op_functions(const struct lcperf_options *options, struct lcperf_op_fns *op_fns)
{
	memset(op_fns, 0, sizeof(struct lcperf_op_fns));

	switch (options->op_type) {
	case LCPERF_OP_PASSTHROUGH:
		op_fns->enqueue_ops = lcperf_set_op_passthrough;
		break;
	case LCPERF_OP_ASYM_RSA:
		op_fns->enqueue_ops = lcperf_set_ops_asym_rsa;
		break;
	default:
		return -1;
	}

	return 0;
}
