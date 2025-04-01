/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_cycles.h>
#include <rte_random.h>

#include <dao_liquid_crypto.h>

#include "lcperf_ops.h"
#include "lcperf_test_vectors.h"

static uint8_t inbuf_data[TEST_LC_MAX_PLAINTEXT_LEN] = {0};
struct dao_lc_buf in_buf[1];

static int
lcperf_set_op_passthrough(uint8_t dev_id, uint16_t qp_id, struct lcperf_test_data *tdata,
			  const struct lcperf_options *options __rte_unused)
{
	uint64_t ops_enqd = 0;
	int ret, i;

	for (i = 0; i < tdata->nb_ops; i++) {
		ret = dao_liquid_crypto_enqueue_op_passthrough(dev_id, qp_id, tdata->op_cookie);
		if (ret == 0)
			ops_enqd++;
	}

	return ops_enqd;
}

static int
lcperf_populate_ops_passthrough(uint64_t sess_id, const struct lcperf_options *options,
				struct lcperf_test_data *test_data)
{
	(void)sess_id;
	(void)options;
	(void)test_data;
	return 0;
}

static int
lcperf_enqueue_ops_asym_rsa(uint8_t dev_id, uint16_t qp_id, struct lcperf_test_data *tdata,
			    const struct lcperf_options *options)
{
	const struct lcperf_rsa_test_data *params = options->rsa_data;
	uint8_t message[LC_PERF_MAX_OUTPUT_LEN];
	uint8_t output[LC_PERF_MAX_OUTPUT_LEN];
	int ops_enqd = 0;
	int ret = -1;

	if (options->asym_op_type == LCPERF_CRYPTO_ASYM_OP_PUB_ENCRYPT) {
		ret = dao_liquid_crypto_enq_op_pkcs1v15enc(
			dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PUBLIC, params->n.len, params->e.len,
			params->plaintext.len, params->n.data, params->e.data,
			params->plaintext.data, output, tdata->op_cookie);
	} else if (options->asym_op_type == LCPERF_CRYPTO_ASYM_OP_PRV_ENCRYPT) {
		if (options->rsa_priv_keytype == LCPERF_RSA_KEY_TYPE_QT) {
			ret = dao_liquid_crypto_enq_op_pkcs1v15enc_crt(
				dev_id, qp_id, params->n.len, params->plaintext.len, params->q.data,
				params->dQ.data, params->p.data, params->dP.data, params->qInv.data,
				params->plaintext.data, output, tdata->op_cookie);
		} else {
			ret = dao_liquid_crypto_enq_op_pkcs1v15enc(
				dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PRIVATE, params->n.len,
				params->d.len, params->plaintext.len, params->n.data,
				params->d.data, params->plaintext.data, output, tdata->op_cookie);
		}
	} else if (options->asym_op_type == LCPERF_CRYPTO_ASYM_OP_PRV_DECRYPT) {
		if (options->rsa_priv_keytype == LCPERF_RSA_KEY_TYPE_QT) {
			ret = dao_liquid_crypto_enq_op_pkcs1v15dec_crt(
				dev_id, qp_id, params->n.len, params->q.data, params->dQ.data,
				params->p.data, params->dP.data, params->qInv.data,
				params->cipher.data, message, tdata->op_cookie);
		} else {
			ret = dao_liquid_crypto_enq_op_pkcs1v15dec(
				dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PRIVATE, params->n.len,
				params->d.len, params->n.data, params->d.data, params->cipher.data,
				message, tdata->op_cookie);
		}
	} else if (options->asym_op_type == LCPERF_CRYPTO_ASYM_OP_PUB_DECRYPT) {
		ret = dao_liquid_crypto_enq_op_pkcs1v15dec(
			dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PUBLIC, params->n.len, params->e.len,
			params->n.data, params->e.data, params->sign.data, message,
			tdata->op_cookie);
	}

	if (ret == 0)
		ops_enqd = 1;

	return ops_enqd;
}

static int
lcperf_set_ops_asym_rsa(uint8_t dev_id, uint16_t qp_id, struct lcperf_test_data *tdata,
			const struct lcperf_options *options)
{
	uint64_t ops_enqd = 0;
	int ret, i;

	for (i = 0; i < tdata->nb_ops; i++) {
		ret = lcperf_enqueue_ops_asym_rsa(dev_id, qp_id, tdata, options);
		if (ret == 1)
			ops_enqd++;
		else
			break;
	}

	return ops_enqd;
}

static int
lcperf_populate_ops_asym(uint64_t sess_id, const struct lcperf_options *options,
			 struct lcperf_test_data *test_data)
{
	(void)sess_id;
	(void)options;
	(void)test_data;
	return 0;
}

static int
lcperf_enqueue_ops_sym(uint8_t dev_id, uint16_t qp_id, struct lcperf_test_data *tdata,
		       const struct lcperf_options *options __rte_unused)
{
	return dao_liquid_crypto_sym_enqueue_burst(dev_id, qp_id, &tdata->ops[0], tdata->nb_ops);
}

static int
lcperf_populate_ops_sym(uint64_t sess_id, const struct lcperf_options *options,
			struct lcperf_test_data *test_data)
{
	struct dao_lc_sym_op *op = test_data->ops;
	bool is_encrypt = false;
	uint8_t *in_buf_data;
	int i;

	in_buf_data = inbuf_data;
	if (in_buf_data == NULL) {
		RTE_LOG(ERR, USER1, "Could not allocate input buffer\n");
		return -1;
	}

	/* Allocate inbuffers separately for each op as the result will be written in the same
	 * location. */
	if (options->sym_op == LCPERF_CRYPTO_SYM_OP_CIPHER_ONLY) {
		if (options->cipher_op == LCPERF_CRYPTO_SYM_CIPHER_OP_ENCRYPT) {
			memcpy(in_buf_data, test_data->sym_params.plaintext.data,
			       test_data->sym_params.plaintext.len);
			in_buf[0].frag_len = test_data->sym_params.plaintext.len;
			in_buf[0].total_len = test_data->sym_params.plaintext.len;
			is_encrypt = true;
		} else {
			memcpy(in_buf_data, test_data->sym_params.ciphertext.data,
			       test_data->sym_params.ciphertext.len);
			in_buf[0].frag_len = test_data->sym_params.ciphertext.len;
			in_buf[0].total_len = test_data->sym_params.ciphertext.len;
		}

		in_buf[0].data = in_buf_data;

		for (i = 0; i < test_data->nb_ops; i++) {
			op[i].encrypt = is_encrypt;
			op[i].in_buffer = in_buf;
			op[i].cipher_offset = 0;
			op[i].cipher_len = test_data->sym_params.ciphertext.len;
			op[i].cipher_iv = test_data->sym_params.iv.data;
			op[i].sess_id = sess_id;
			op[i].op_cookie = test_data->op_cookie;
		}
	}

	return 0;
}

static int
sess_event_dequeue(uint8_t dev_id, struct dao_lc_cmd_event *ev)
{
	uint64_t timeout;
	int ret;

	/* Set a timeout of 1 second. */
	timeout = rte_get_timer_cycles() + rte_get_timer_hz();

	do {
		ret = dao_liquid_crypto_cmd_event_dequeue(dev_id, ev, 1);
		if (ret == 1)
			break;

		if (rte_get_timer_cycles() > timeout) {
			RTE_LOG(ERR, USER1, "Operation timed out");
			break;
		}
	} while (ret == 0);

	if (ret != 1) {
		RTE_LOG(ERR, USER1, "Could not dequeue operation");
		return -1;
	}

	return 0;
}

static uint64_t
lcperf_sym_sess_create(uint8_t dev_id, const struct lcperf_test_sym_params *sym_params)
{
	uint64_t sess_cookie = rte_rand();
	struct dao_lc_cmd_event ev;
	int ret;

	ret = dao_liquid_crypto_sym_sess_create(dev_id, &sym_params->ctx, sess_cookie);
	if (ret < 0) {
		RTE_LOG(ERR, USER1, "Could not create session\n");
		return DAO_LC_SESS_ID_INVALID;
	}

	ret = sess_event_dequeue(dev_id, &ev);
	if (ret < 0) {
		RTE_LOG(ERR, USER1, "Could not dequeue session event\n");
		return DAO_LC_SESS_ID_INVALID;
	}

	if (ev.event_type != DAO_LC_CMD_EVENT_SESS_CREATE) {
		RTE_LOG(ERR, USER1, "Invalid event type: %d\n", ev.event_type);
		return DAO_LC_SESS_ID_INVALID;
	}

	if (ev.sess_event.sess_id == DAO_LC_SESS_ID_INVALID) {
		RTE_LOG(ERR, USER1, "Invalid session ID\n");
		return DAO_LC_SESS_ID_INVALID;
	}

	if (ev.sess_event.sess_cookie != sess_cookie) {
		RTE_LOG(ERR, USER1, "Invalid session cookie\n");
		return DAO_LC_SESS_ID_INVALID;
	}

	return ev.sess_event.sess_id;
}

static int
lcperf_sym_sess_destroy(uint8_t dev_id, uint64_t sess_id)
{
	uint64_t sess_cookie = rte_rand();
	struct dao_lc_cmd_event ev;
	int ret;

	ret = dao_liquid_crypto_sym_sess_destroy(dev_id, sess_id, sess_cookie);
	if (ret < 0) {
		RTE_LOG(ERR, USER1, "Could not destroy session");
		return -1;
	}

	ret = sess_event_dequeue(dev_id, &ev);
	if (ret < 0) {
		RTE_LOG(ERR, USER1, "Could not dequeue session destroy event\n");
		return -1;
	}

	if (ev.event_type != DAO_LC_CMD_EVENT_SESS_DESTROY) {
		RTE_LOG(ERR, USER1, "Invalid event type: %d\n", ev.event_type);
		return -1;
	}

	if (ev.sess_event.sess_cookie != sess_cookie) {
		RTE_LOG(ERR, USER1, "Invalid session cookie: %016lx\n", ev.sess_event.sess_cookie);
		return -1;
	}

	return 0;
}

int
lcperf_get_op_functions(const struct lcperf_options *options, struct lcperf_op_fns *op_fns)
{
	memset(op_fns, 0, sizeof(struct lcperf_op_fns));

	switch (options->op_type) {
	case LCPERF_OP_PASSTHROUGH:
		op_fns->enqueue_ops = lcperf_set_op_passthrough;
		op_fns->populate_ops = lcperf_populate_ops_passthrough;
		op_fns->sess_create = NULL;
		op_fns->sess_destroy = NULL;
		break;
	case LCPERF_OP_SYM:
		op_fns->enqueue_ops = lcperf_enqueue_ops_sym;
		op_fns->populate_ops = lcperf_populate_ops_sym;
		op_fns->sess_create = lcperf_sym_sess_create;
		op_fns->sess_destroy = lcperf_sym_sess_destroy;
		break;
	case LCPERF_OP_ASYM_RSA:
		op_fns->enqueue_ops = lcperf_set_ops_asym_rsa;
		op_fns->populate_ops = lcperf_populate_ops_asym;
		op_fns->sess_create = NULL;
		op_fns->sess_destroy = NULL;
		break;
	default:
		return -1;
	}

	return 0;
}
