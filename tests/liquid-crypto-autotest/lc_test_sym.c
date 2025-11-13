/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_cycles.h>
#include <rte_hexdump.h>
#include <rte_random.h>

#include <dao_liquid_crypto.h>

#include "lc_autotest.h"
#include "lc_test_generic.h"
#include "lc_test_sym_aes.h"
#include "lc_test_sym_aes_keywrap.h"
#include "lc_test_sym_hash.h"
#include "test.h"

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
			TEST_LC_ERR("Operation timed out");
			break;
		}
	} while (ret == 0);

	if (ret != 1) {
		TEST_LC_ERR("Could not dequeue operation");
		return -1;
	}

	return 0;
}

static int
test_hash_only(const void *data, const bool is_auth_gen)
{
	uint8_t in_buf_data[TEST_LC_MAX_PLAINTEXT_LEN] = {0};
	uint8_t digest[TEST_LC_MAX_DIGEST_LEN] = {0};
	int ret, i, max_offset = TEST_LC_MAX_OFFSET;
	const struct test_sym_params *params = data;
	struct dao_lc_sym_ctx ctx = params->ctx;
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t sess_cookie = rte_rand();
	struct dao_lc_buf in_buf[1] = {0};
	struct dao_lc_sym_op op[1] = {0};
	struct dao_lc_cmd_event ev;
	struct dao_lc_res res[1];
	uint16_t digest_len = 0;
	uint64_t op_cookie;

	ctx.iv_len = params->iv.len;
	ret = dao_liquid_crypto_sym_sess_create(dev_id, &ctx, sess_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not create session");
		return -1;
	}

	ret = sess_event_dequeue(dev_id, &ev);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue session event");
		return -1;
	}

	TEST_ASSERT(ev.event_type == DAO_LC_CMD_EVENT_SESS_CREATE, "Invalid event type");
	TEST_ASSERT(ev.sess_event.sess_id != DAO_LC_SESS_ID_INVALID, "Invalid session ID");
	TEST_ASSERT(ev.sess_event.sess_cookie == sess_cookie, "Invalid operation cookie");

	/* Perform crypto operation */
	op_cookie = rte_rand();
	op[0].op_cookie = op_cookie;
	op[0].sess_id = ev.sess_event.sess_id;
	op[0].digest = digest;
	op[0].auth_gen = is_auth_gen;

	if (params->ctx.opcode == DAO_LC_SYM_OPCODE_HMAC ||
	    params->ctx.opcode == DAO_LC_SYM_OPCODE_HASH)
		digest_len = params->ctx.hash.digest_len;
	else
		digest_len = params->ctx.fc.mac_len;

	for (i = 0; i < max_offset; i++) {
		if (is_auth_gen)
			memset(digest, 0, sizeof(digest));
		else
			memcpy(op[0].digest, params->digest_data, digest_len);

		memset(in_buf_data, 0, i);
		memcpy(in_buf_data + i, params->plaintext.data, params->plaintext.len);
		in_buf[0].frag_len = params->plaintext.len + i;
		in_buf[0].total_len = params->plaintext.len + i;

		in_buf[0].data = in_buf_data;
		op[0].in_buffer = in_buf;
		op[0].auth_offset = params->auth_offset + i;
		op[0].auth_len = params->plaintext.len;

		if ((ctx.hash.hmac_hash_type == DAO_LC_HASH_TYPE_SHA3_KMAC128) ||
		    (ctx.hash.hmac_hash_type == DAO_LC_HASH_TYPE_SHA3_KMAC256)) {
			op[0].params.output_len = params->output_len;
			op[0].params.custom_string = (uint8_t *)params->custom_string.data;
			op[0].params.custom_string_len = params->custom_string.len;
		}

		if (params->ctx.fc.hash_type == DAO_LC_HASH_TYPE_GMAC) {
			if (params->iv.len == 0) {
				TEST_LC_ERR("Invalid IV data or length");
				return -1;
			}
			op[0].auth_iv = (uint8_t *)params->iv.data;
		}

		ret = dao_liquid_crypto_sym_enqueue_burst(dev_id, qp_id, op, 1);
		if (ret != 1) {
			TEST_LC_ERR("Could not enqueue symmetric crypto operation");
			return -1;
		}

		ret = op_dequeue(dev_id, qp_id, res);
		if (ret < 0) {
			TEST_LC_ERR("Could not dequeue symmetric crypto operation");
			return -1;
		}

		TEST_ASSERT(res[0].op_cookie == op_cookie, "Invalid operation cookie");
		TEST_ASSERT(res[0].res.cn9k.compcode == DAO_CPT_COMP_GOOD,
			    "Crypto operation failed");

		if (is_auth_gen) {
			if (res[0].res.cn9k.uc_compcode != DAO_UC_SUCCESS) {
				TEST_LC_ERR("Auth gen failed with uc_compcode %u for offset %d",
					    res[0].res.cn9k.uc_compcode, i);
				return -1;
			}
			ret = memcmp(op[0].digest, params->digest_data, digest_len);
			if (ret != 0) {
				TEST_LC_ERR("Digest Gen failed for offset %d", i);
				rte_hexdump(stdout, "RESULT digest: ", op[0].digest, digest_len);
				rte_hexdump(stdout, "EXPECTED digest: ", params->digest_data,
					    digest_len);
				return -1;
			}
		} else {
			if (res[0].res.cn9k.uc_compcode == DAO_UC_ERR_GC_ICV_MISCOMPARE) {
				TEST_LC_ERR("Expected digest verification to succeed for offset %d",
					    i);
				rte_hexdump(stdout, "PROVIDED digest: ", op[0].digest, digest_len);
				return -1;
			} else if (res[0].res.cn9k.uc_compcode != DAO_UC_SUCCESS) {
				TEST_LC_ERR("Auth verify failed with uc_compcode %u for offset %d",
					    res[0].res.cn9k.uc_compcode, i);
				return -1;
			}
		}
	}

	sess_cookie = rte_rand();
	ret = dao_liquid_crypto_sym_sess_destroy(glb_params.dev_id, ev.sess_event.sess_id,
						 sess_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not destroy session");
		return -1;
	}

	ret = sess_event_dequeue(dev_id, &ev);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue session event");
		return -1;
	}

	TEST_ASSERT(ev.event_type == DAO_LC_CMD_EVENT_SESS_DESTROY, "Invalid event type");
	TEST_ASSERT(ev.sess_event.sess_cookie == sess_cookie, "Invalid operation cookie");

	return 0;
}

static int
test_hash_gen(const void *data)
{
	return test_hash_only(data, true);
}

static int
test_hash_verify(const void *data)
{
	return test_hash_only(data, false);
}

static bool
is_aead_algo(const struct test_sym_params *params)
{
	return ((params->ctx.fc.enc_cipher == DAO_LC_FC_ENC_CIPHER_AES_GCM) ||
		(params->ctx.fc.enc_cipher == DAO_LC_FC_ENC_CIPHER_AES_CCM) ||
		((params->ctx.fc.enc_cipher == DAO_LC_FC_ENC_CIPHER_CHACHA) &&
		 (params->ctx.fc.hash_type == DAO_LC_HASH_TYPE_POLY1305)));
}

static int
test_aes_key_wrap_unwrap(const void *data, const bool is_wrap, const bool is_oop,
			 const bool is_invalid_keydata, const bool is_iv_error, const bool is_pad)
{
	uint8_t key_data[TEST_LC_MAX_KEY_DATA_LEN + TEST_LC_MAX_OFFSET +
			 TEST_LC_AES_KEY_WRAP_IV_LEN + TEST_LC_AES_KEY_WRAP_IV_LEN] = {0};
	uint8_t wrap_key_data[TEST_LC_MAX_KEY_DATA_LEN + TEST_LC_MAX_OFFSET +
			      TEST_LC_AES_KEY_WRAP_IV_LEN + TEST_LC_AES_KEY_WRAP_IV_LEN] = {0};
	uint32_t key_data_len, wrap_key_len, pad_len = 0;
	const struct test_sym_params *params = data;
	struct dao_lc_sym_ctx ctx = params->ctx;
	int max_offset = TEST_LC_MAX_OFFSET;
	uint8_t dev_id = glb_params.dev_id;
	struct dao_lc_buf out_buf[1] = {0};
	uint16_t qp_id = glb_params.qp_id;
	uint64_t sess_cookie = rte_rand();
	struct dao_lc_buf in_buf[1] = {0};
	struct dao_lc_sym_op op[1] = {0};
	struct dao_lc_res res[1] = {0};
	struct dao_lc_buf iv_buf = {0};
	uint8_t *result_buffer = NULL;
	uint32_t expected_err_code;
	struct dao_lc_buf *dst_buf;
	struct dao_lc_cmd_event ev;
	uint64_t op_cookie;
	int ret, i;

#ifdef TEST_LC_DEBUG_BUILD
	if (is_invalid_keydata)
		return TEST_SKIPPED;
#endif

	/* Create session */
	ret = dao_liquid_crypto_sym_sess_create(dev_id, &ctx, sess_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not create session");
		return -1;
	}

	ret = sess_event_dequeue(dev_id, &ev);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue session event");
		return -1;
	}

	TEST_ASSERT(ev.event_type == DAO_LC_CMD_EVENT_SESS_CREATE, "Invalid event type");
	TEST_ASSERT(ev.sess_event.sess_id != DAO_LC_SESS_ID_INVALID, "Invalid session ID");
	TEST_ASSERT(ev.sess_event.sess_cookie == sess_cookie, "Invalid operation cookie");

	/* Perform crypto operation */
	op[0].sess_id = ev.sess_event.sess_id;
	op[0].is_wrap = is_wrap;
	op[0].is_wrap_pad = is_pad;

	for (i = 0; i < max_offset; i++) {
		/* Clearing buffers for each iteration */
		memset(key_data, 0, sizeof(key_data));

		if (is_wrap) {
			key_data_len = params->plaintext.len;
			memcpy(key_data + i, params->plaintext.data, params->plaintext.len);
		} else {
			key_data_len = params->wrap_key.len;
			memcpy(key_data + i, params->wrap_key.data, params->wrap_key.len);
		}

		if (key_data_len + i > TEST_LC_MAX_KEY_DATA_LEN + TEST_LC_MAX_OFFSET) {
			TEST_LC_ERR("Key data length is exceeded for offset %d", i);
			goto exit;
		}
		in_buf[0].data = key_data;
		in_buf[0].frag_len = key_data_len + i;
		in_buf[0].total_len = in_buf[0].frag_len;

		op[0].cipher_offset = params->cipher_offset + i;

		if (is_wrap) {
			wrap_key_len = params->wrap_key.len;
			op[0].wrap_unwrap_key_len = params->plaintext.len;
		} else {
			wrap_key_len = params->plaintext.len;
			op[0].wrap_unwrap_key_len = params->wrap_key.len;
		}

		if (is_oop) {
			dst_buf = out_buf;
			dst_buf[0].data = wrap_key_data;
			dst_buf[0].frag_len = wrap_key_len + i;
			dst_buf[0].total_len = dst_buf[0].frag_len;
			op[0].out_buffer = out_buf;
		} else {
			/* In in-place operation, output is written back to input buffer */
			op[0].out_buffer = NULL;
			if (is_wrap) {
				/* Append space for IV at the end of input buffer */
				if (op[0].is_wrap_pad)
					pad_len = RTE_ALIGN_CEIL(key_data_len, 8) - key_data_len;
				iv_buf.data = key_data + key_data_len + i;
				iv_buf.frag_len = TEST_LC_AES_KEY_WRAP_IV_LEN + pad_len;
				iv_buf.total_len = iv_buf.frag_len;
				in_buf[0].next = &iv_buf;
			}
			in_buf[0].total_len = in_buf[0].frag_len + iv_buf.frag_len;
			dst_buf = in_buf;
		}

		op[0].in_buffer = in_buf;

		op_cookie = rte_rand();
		op[0].op_cookie = op_cookie;

		ret = dao_liquid_crypto_sym_enqueue_burst(dev_id, qp_id, op, 1);
		if (ret != 1) {
			TEST_LC_ERR("Could not enqueue symmetric crypto operation");
			return -1;
		}

		ret = op_dequeue(dev_id, qp_id, res);
		if (ret < 0) {
			TEST_LC_ERR("Could not dequeue symmetric crypto operation");
			return -1;
		}

		TEST_ASSERT(res[0].op_cookie == op_cookie, "Invalid operation cookie");
		TEST_ASSERT(res[0].res.cn9k.compcode == DAO_CPT_COMP_GOOD,
			    "Crypto operation failed");

		result_buffer = (uint8_t *)dst_buf[0].data + i;
		if (is_wrap) {
			if (res[0].res.cn9k.uc_compcode != DAO_UC_SUCCESS) {
				if (is_invalid_keydata || is_iv_error) {
					expected_err_code =
						is_invalid_keydata ?
							DAO_UC_ERR_GC_KEY_DATA_LEN_INVALID :
							DAO_UC_ERR_GC_ICV_MISCOMPARE;

					TEST_LC_INFO(
						"Key wrap verification is expected to fail with uc_compcode %u",
						res[0].res.cn9k.uc_compcode);
					TEST_ASSERT(res[0].res.cn9k.uc_compcode ==
							    expected_err_code,
						    "Expected error code %d but got %d (%s)",
						    expected_err_code, res[0].res.cn9k.uc_compcode,
						    is_invalid_keydata ? "Invalid keydata" :
									 "Default IV invalid");
					goto exit_success;
				}
				TEST_LC_ERR("Key wrap failed with uc_compcode %u",
					    res[0].res.cn9k.uc_compcode);
				goto exit;
			}

			if (res[0].key_wrap.wrap_unwrap_key_len != params->wrap_key.len) {
				TEST_LC_ERR("Wrapped key length mismatch. Expected: %u, Got: %u",
					    params->wrap_key.len,
					    res[0].key_wrap.wrap_unwrap_key_len);
				goto exit;
			}

			if (memcmp(result_buffer, params->wrap_key.data, params->wrap_key.len) !=
			    0) {
				TEST_LC_ERR(
					"Key wrap failed. Expected key does not match wrapped key");
				rte_hexdump(stdout, "WRAPPED KEY: ", result_buffer,
					    params->wrap_key.len);
				rte_hexdump(stdout, "EXPECTED WRAPPED KEY: ", params->wrap_key.data,
					    params->wrap_key.len);
				goto exit;
			}
		} else {
			if (res[0].res.cn9k.uc_compcode != DAO_UC_SUCCESS) {
				if (is_invalid_keydata || is_iv_error) {
					expected_err_code =
						is_invalid_keydata ?
							DAO_UC_ERR_GC_KEY_DATA_LEN_INVALID :
							DAO_UC_ERR_GC_ICV_MISCOMPARE;
					TEST_LC_INFO(
						"Key unwrap verification is expected to fail with uc_compcode %u",
						res[0].res.cn9k.uc_compcode);
					TEST_ASSERT(res[0].res.cn9k.uc_compcode ==
							    expected_err_code,
						    "Expected error code %d but got %d (%s)",
						    expected_err_code, res[0].res.cn9k.uc_compcode,
						    is_invalid_keydata ? "Invalid keydata" :
									 "Default IV invalid");
					goto exit_success;
				}

				TEST_LC_ERR("Key unwrap verification is failed with uc_compcode %u",
					    res[0].res.cn9k.uc_compcode);
				goto exit;
			}

			if (res[0].key_wrap.wrap_unwrap_key_len != params->plaintext.len) {
				TEST_LC_ERR("Unwrapped key length meismatch. Expected: %u, Got: %u",
					    params->plaintext.len,
					    res[0].key_wrap.wrap_unwrap_key_len);
				goto exit;
			}

			if (memcmp(result_buffer, params->plaintext.data, params->plaintext.len) !=
			    0) {
				TEST_LC_ERR(
					"Key unwrap failed. Expected unwrap key does not match unwrapped key");
				rte_hexdump(stdout, "UNWRAPPED KEY: ", result_buffer,
					    params->plaintext.len);
				rte_hexdump(stdout,
					    "EXPECTED UNWRAPPED KEY: ", params->plaintext.data,
					    params->plaintext.len);
				goto exit;
			}
		}
	}

exit_success:
	sess_cookie = rte_rand();
	ret = dao_liquid_crypto_sym_sess_destroy(glb_params.dev_id, ev.sess_event.sess_id,
						 sess_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not destroy session");
		return -1;
	}

	ret = sess_event_dequeue(dev_id, &ev);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue session event");
		return -1;
	}

	TEST_ASSERT(ev.event_type == DAO_LC_CMD_EVENT_SESS_DESTROY, "Invalid event type");
	TEST_ASSERT(ev.sess_event.sess_cookie == sess_cookie, "Invalid operation cookie");

	return 0;

exit:
	/* clean-up path in case of early error */
	dao_liquid_crypto_sym_sess_destroy(glb_params.dev_id, ev.sess_event.sess_id, sess_cookie);
	sess_event_dequeue(dev_id, &ev);
	return -1;
}

static int
test_aes_key_wrap(const void *data)
{
	return test_aes_key_wrap_unwrap(data, true, false, false, false, false);
}

static int
test_aes_key_unwrap(const void *data)
{
	return test_aes_key_wrap_unwrap(data, false, false, false, false, false);
}

static int
test_aes_key_wrap_oop(const void *data)
{
	return test_aes_key_wrap_unwrap(data, true, true, false, false, false);
}

static int
test_aes_key_unwrap_oop(const void *data)
{
	return test_aes_key_wrap_unwrap(data, false, true, false, false, false);
}

static int
test_aes_key_unwrap_invalid_keydata(const void *data)
{
	return test_aes_key_wrap_unwrap(data, false, false, true, false, false);
}

static int
test_aes_key_wrap_invalid_keydata(const void *data)
{
	return test_aes_key_wrap_unwrap(data, true, false, true, false, false);
}

static int
test_aes_key_unwrap_invalid_iv_case(const void *data)
{
	return test_aes_key_wrap_unwrap(data, false, false, false, true, true);
}

static int
test_aes_key_wrap_pad(const void *data)
{
	return test_aes_key_wrap_unwrap(data, true, false, false, false, true);
}

static int
test_aes_key_unwrap_pad(const void *data)
{
	return test_aes_key_wrap_unwrap(data, false, false, false, false, true);
}

static int
test_aes_key_wrap_pad_oop(const void *data)
{
	return test_aes_key_wrap_unwrap(data, true, true, false, false, true);
}

static int
test_aes_key_unwrap_pad_oop(const void *data)
{
	return test_aes_key_wrap_unwrap(data, false, true, false, false, true);
}

static int
test_block_cipher_only(const void *data, bool is_encrypt, bool is_oop, bool is_digest_separate)
{
	uint8_t out_buf_data[TEST_LC_MAX_CIPHERTEXT_LEN + TEST_LC_MAX_DIGEST_LEN +
			     TEST_LC_MAX_OFFSET] = {0};
	uint8_t in_buf_data[TEST_LC_MAX_PLAINTEXT_LEN + TEST_LC_MAX_DIGEST_LEN +
			    TEST_LC_MAX_OFFSET] = {0};
	uint8_t digest_buf[TEST_LC_MAX_DIGEST_LEN] = {0};
	int ret, i, max_offset = TEST_LC_MAX_OFFSET;
	const struct test_sym_params *params = data;
	struct dao_lc_sym_ctx ctx = params->ctx;
	uint8_t dev_id = glb_params.dev_id;
	struct dao_lc_buf out_buf[1] = {0};
	uint32_t in_data_len, out_data_len;
	uint16_t qp_id = glb_params.qp_id;
	struct dao_lc_buf in_buf[1] = {0};
	struct dao_lc_sym_op op[1] = {0};
	uint64_t sess_cookie, op_cookie;
	uint8_t *result_buffer = NULL;
	uint8_t *digest_result = NULL;
	struct dao_lc_cmd_event ev;
	struct dao_lc_buf *dst_buf;
	size_t max_len, total_len;
	struct dao_lc_res res[1];
	uint16_t digest_len = 0;

	ctx.iv_len = params->iv.len;
	sess_cookie = rte_rand();
	ret = dao_liquid_crypto_sym_sess_create(dev_id, &ctx, sess_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not create session");
		return -1;
	}

	ret = sess_event_dequeue(dev_id, &ev);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue session event");
		return -1;
	}

	TEST_ASSERT(ev.event_type == DAO_LC_CMD_EVENT_SESS_CREATE, "Invalid event type");
	TEST_ASSERT(ev.sess_event.sess_id != DAO_LC_SESS_ID_INVALID, "Invalid session ID");
	TEST_ASSERT(ev.sess_event.sess_cookie == sess_cookie, "Invalid operation cookie");

	/* Perform crypto operation */
	op[0].sess_id = ev.sess_event.sess_id;

	if (params->ctx.opcode == DAO_LC_SYM_OPCODE_HMAC)
		digest_len = params->ctx.hash.digest_len;
	else
		digest_len = params->ctx.fc.mac_len;

	for (i = 0; i < max_offset; i++) {
		/* Clearing buffers for each iteration */
		memset(in_buf_data, 0, sizeof(in_buf_data));
		memset(out_buf_data, 0, sizeof(out_buf_data));
		if (is_encrypt)
			in_data_len = params->plaintext.len;
		else
			in_data_len = params->ciphertext.len;

		if (in_data_len + i > TEST_LC_MAX_PLAINTEXT_LEN + TEST_LC_MAX_OFFSET) {
			TEST_LC_ERR("Input buffer size exceeded for offset %d", i);
			goto exit;
		}

		in_buf[0].data = in_buf_data;
		in_buf[0].frag_len = in_data_len + i;
		total_len = in_data_len + digest_len + i;

		if (is_oop) {
			/*
			 * As, in-place digest is stored in in_buf_data[] and in OOP
			 * it is stored in out_buf_data[] and each buffer has
			 * different capacity different limit checks are used.
			 */
			max_len = TEST_LC_MAX_CIPHERTEXT_LEN + TEST_LC_MAX_DIGEST_LEN +
				  TEST_LC_MAX_OFFSET;

			dst_buf = out_buf;
			if (is_encrypt)
				out_data_len = params->ciphertext.len;
			else
				out_data_len = params->plaintext.len;
			dst_buf[0].data = out_buf_data;
			dst_buf[0].frag_len = out_data_len + i;
			op[0].out_buffer = out_buf;
		} else {
			max_len = TEST_LC_MAX_PLAINTEXT_LEN + TEST_LC_MAX_DIGEST_LEN +
				  TEST_LC_MAX_OFFSET;

			dst_buf = in_buf;
			op[0].out_buffer = NULL;
		}

		op[0].in_buffer = in_buf;

		if (is_aead_algo(params)) {
			if (params->aad.len > TEST_LC_MAX_AAD_LEN) {
				TEST_LC_ERR("AAD length (%u) out of bounds [0, %u]",
					    params->aad.len, TEST_LC_MAX_AAD_LEN);
				return -1;
			}
			if (params->aad.data == NULL) {
				TEST_LC_ERR("Invalid AAD data");
				return -1;
			}
			op[0].aad = (uint8_t *)params->aad.data;
			op[0].aad_len = params->aad.len;

			if (is_encrypt) {
				memcpy(in_buf_data + i, params->plaintext.data,
				       params->plaintext.len);
				op[0].encrypt = true;
				if (is_digest_separate) {
					memset(digest_buf, 0, TEST_LC_MAX_DIGEST_LEN);
					op[0].digest = digest_buf;
				} else {
					if (total_len > max_len) {
						TEST_LC_ERR("Digest buffer too small for offset %d",
							    i);
						goto exit;
					}
					if (is_oop)
						dst_buf[0].frag_len += digest_len;
					else
						in_buf[0].frag_len += digest_len;
				}
			} else {
				memcpy(in_buf_data + i, params->ciphertext.data,
				       params->ciphertext.len);
				op[0].encrypt = false;
				if (is_digest_separate) {
					memcpy(digest_buf, params->digest_data, digest_len);
					op[0].digest = digest_buf;
				} else {
					if (total_len > max_len) {
						TEST_LC_ERR("Digest buffer too small for offset %d",
							    i);
						goto exit;
					}

					memcpy(in_buf_data + params->ciphertext.len + i,
					       params->digest_data, digest_len);
					in_buf[0].frag_len += digest_len;
				}
			}
		} else {
			/* For non-GCM/CCM modes */
			if (is_encrypt) {
				memcpy(in_buf_data + i, params->plaintext.data,
				       params->plaintext.len);
				op[0].encrypt = true;
			} else {
				memcpy(in_buf_data + i, params->ciphertext.data,
				       params->ciphertext.len);
				op[0].encrypt = false;
			}
		}

		in_buf[0].total_len = in_buf[0].frag_len;
		dst_buf[0].total_len = dst_buf[0].frag_len;

		op[0].cipher_offset = params->cipher_offset + i;
		op[0].cipher_len = params->ciphertext.len;
		op[0].auth_offset = params->auth_offset + i;
		op[0].auth_len = params->ciphertext.len;

		if (params->iv.len == 0) {
			TEST_LC_ERR("Invalid IV data or length");
			return -1;
		}

		op[0].cipher_iv = (uint8_t *)params->iv.data;

		op_cookie = rte_rand();
		op[0].op_cookie = op_cookie;

		ret = dao_liquid_crypto_sym_enqueue_burst(dev_id, qp_id, op, 1);
		if (ret != 1) {
			TEST_LC_ERR("Could not enqueue symmetric crypto operation");
			return -1;
		}

		ret = op_dequeue(dev_id, qp_id, res);
		if (ret < 0) {
			TEST_LC_ERR("Could not dequeue symmetric crypto operation");
			return -1;
		}

		TEST_ASSERT(res[0].op_cookie == op_cookie, "Invalid operation cookie");
		TEST_ASSERT(res[0].res.cn9k.compcode == DAO_CPT_COMP_GOOD,
			    "Crypto operation failed");
		TEST_ASSERT(res[0].res.cn9k.uc_compcode == DAO_UC_SUCCESS,
			    "Symmetric operation failed");

		result_buffer = (uint8_t *)dst_buf[0].data + i;
		if (is_encrypt) {
			ret = memcmp(result_buffer, params->ciphertext.data,
				     params->ciphertext.len);
			if (ret != 0) {
				TEST_LC_ERR("Invalid result for offset %d", i);
				rte_hexdump(stdout, "RESULT: ", result_buffer,
					    params->ciphertext.len);
				rte_hexdump(stdout, "EXPECTED: ", params->ciphertext.data,
					    params->ciphertext.len);
				return -1;
			}

			if (is_digest_separate)
				digest_result = op[0].digest;
			else
				digest_result = result_buffer + params->ciphertext.len;

			ret = memcmp(digest_result, params->digest_data, digest_len);
			if (ret != 0) {
				TEST_LC_ERR("Invalid digest for offset %d", i);
				rte_hexdump(stdout, "RESULT digest: ", digest_result, digest_len);
				rte_hexdump(stdout, "EXPECTED digest: ", params->digest_data,
					    digest_len);
				return -1;
			}
		} else {
			ret = memcmp(result_buffer, params->plaintext.data, params->plaintext.len);
			if (ret != 0) {
				TEST_LC_ERR("Invalid result for offset %d", i);
				rte_hexdump(stdout, "RESULT: ", result_buffer,
					    params->plaintext.len);
				rte_hexdump(stdout, "EXPECTED: ", params->plaintext.data,
					    params->plaintext.len);
				return -1;
			}
		}
	}

	sess_cookie = rte_rand();
	ret = dao_liquid_crypto_sym_sess_destroy(glb_params.dev_id, ev.sess_event.sess_id,
						 sess_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not destroy session");
		return -1;
	}

	ret = sess_event_dequeue(dev_id, &ev);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue session event");
		return -1;
	}

	TEST_ASSERT(ev.event_type == DAO_LC_CMD_EVENT_SESS_DESTROY, "Invalid event type");
	TEST_ASSERT(ev.sess_event.sess_cookie == sess_cookie, "Invalid operation cookie");

	return 0;

exit:
	/* clean-up path in case of early error */
	dao_liquid_crypto_sym_sess_destroy(glb_params.dev_id, ev.sess_event.sess_id, sess_cookie);
	sess_event_dequeue(dev_id, &ev);
	return -1;
}

static int
test_block_cipher_only_encrypt(const void *data)
{
	const struct test_sym_params *params = data;
	int ret = 0;

	if (is_aead_algo(params)) {
		/**
		 * AEAD supports two modes of digest handling.
		 * 1. Digest can be placed explicitly in a separate buffer.
		 * 2. Digest data can located after the ciphertext in the buffer.
		 *
		 * Test here case 1.
		 */

		ret = test_block_cipher_only(data, true, false, true);

		if (ret < 0) {
			TEST_LC_ERR("AEAD test failed for separate digest mode");
			return ret;
		}
	}

	return test_block_cipher_only(data, true, false, false);
}

static int
test_block_cipher_only_decrypt(const void *data)
{
	const struct test_sym_params *params = data;
	int ret = 0;

	if (is_aead_algo(params)) {
		/**
		 * AEAD supports two modes of digest handling.
		 * 1. Digest can be placed explicitly in a separate buffer.
		 * 2. Digest data can located after the ciphertext in the buffer.
		 *
		 * Test here case 1.
		 */

		ret = test_block_cipher_only(data, false, false, true);
		if (ret < 0) {
			TEST_LC_ERR("AEAD test failed for separate digest mode");
			return ret;
		}
	}

	return test_block_cipher_only(data, false, false, false);
}

static int
test_block_cipher_only_encrypt_oop(const void *data)
{
	const struct test_sym_params *params = data;
	int ret = 0;

	if (is_aead_algo(params)) {
		/**
		 * AEAD supports two modes of digest handling.
		 * 1. Digest can be placed explicitly in a separate buffer.
		 * 2. Digest data can located after the ciphertext in the buffer.
		 *
		 * Test here case 1.
		 */

		ret = test_block_cipher_only(data, true, true, true);
		if (ret < 0) {
			TEST_LC_ERR("AEAD test failed for separate digest mode");
			return ret;
		}
	}

	return test_block_cipher_only(data, true, true, false);
}

static int
test_block_cipher_only_decrypt_oop(const void *data)
{
	const struct test_sym_params *params = data;
	int ret = 0;

	if (is_aead_algo(params)) {
		/**
		 * AEAD supports two modes of digest handling.
		 * 1. Digest can be placed explicitly in a separate buffer.
		 * 2. Digest data can located after the ciphertext in the buffer.
		 *
		 * Test here case 1.
		 */

		ret = test_block_cipher_only(data, false, true, true);
		if (ret < 0) {
			TEST_LC_ERR("AEAD test failed for separate digest mode");
			return ret;
		}
	}

	return test_block_cipher_only(data, false, true, false);
}

static int
test_block_cipher_auth(const void *data, bool is_encrypt, bool is_oop, bool is_digest_separate)
{
	uint8_t out_buf_data[TEST_LC_MAX_CIPHERTEXT_LEN + TEST_LC_MAX_DIGEST_LEN +
			     TEST_LC_MAX_OFFSET] = {0};
	uint8_t in_buf_data[TEST_LC_MAX_PLAINTEXT_LEN + TEST_LC_MAX_DIGEST_LEN +
			    TEST_LC_MAX_OFFSET] = {0};
	uint32_t in_data_len, out_data_len, decrypt_result_len;
	uint8_t digest_buf[TEST_LC_MAX_DIGEST_LEN] = {0};
	int ret, i, max_offset = TEST_LC_MAX_OFFSET;
	const struct test_sym_params *params = data;
	struct dao_lc_sym_ctx ctx = params->ctx;
	uint8_t dev_id = glb_params.dev_id;
	struct dao_lc_buf out_buf[1] = {0};
	uint16_t qp_id = glb_params.qp_id;
	struct dao_lc_buf in_buf[1] = {0};
	struct dao_lc_sym_op op[1] = {0};
	uint64_t sess_cookie, op_cookie;
	uint8_t *result_buffer = NULL;
	uint8_t *digest_result = NULL;
	struct dao_lc_cmd_event ev;
	struct dao_lc_buf *dst_buf;
	size_t max_len, total_len;
	struct dao_lc_res res[1];
	uint16_t digest_len = 0;

	ctx.is_chained_cipher = true;
	ctx.iv_len = params->iv.len;
	sess_cookie = rte_rand();
	ret = dao_liquid_crypto_sym_sess_create(dev_id, &ctx, sess_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not create session");
		return -1;
	}

	ret = sess_event_dequeue(dev_id, &ev);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue session event");
		return -1;
	}

	TEST_ASSERT(ev.event_type == DAO_LC_CMD_EVENT_SESS_CREATE, "Invalid event type");
	TEST_ASSERT(ev.sess_event.sess_id != DAO_LC_SESS_ID_INVALID, "Invalid session ID");
	TEST_ASSERT(ev.sess_event.sess_cookie == sess_cookie, "Invalid operation cookie");

	/* Perform crypto operation */
	op[0].sess_id = ev.sess_event.sess_id;
	digest_len = params->ctx.fc.mac_len;

	for (i = 0; i < max_offset; i++) {
		/* Clearing buffers for each iteration */
		memset(in_buf_data, 0, sizeof(in_buf_data));
		memset(out_buf_data, 0, sizeof(out_buf_data));

		if (is_encrypt)
			in_data_len = i + params->plaintext.len;
		else
			in_data_len = i + params->cipher_offset + params->ciphertext.len;

		if (in_data_len > TEST_LC_MAX_PLAINTEXT_LEN + TEST_LC_MAX_OFFSET) {
			TEST_LC_ERR("Input buffer size exceeded for offset %d", i);
			goto exit;
		}

		in_buf[0].data = in_buf_data;
		in_buf[0].frag_len = in_data_len;
		op[0].in_buffer = in_buf;
		total_len = in_data_len + digest_len;

		if (is_oop) {
			if (is_encrypt)
				out_data_len = i + params->cipher_offset + params->ciphertext.len;
			else
				out_data_len = i + params->plaintext.len;

			dst_buf = out_buf;
			dst_buf[0].data = out_buf_data;
			dst_buf[0].frag_len = out_data_len;
			op[0].out_buffer = out_buf;

			/*
			 * As, in-place digest is stored in in_buf_data[] and in OOP
			 * it is stored in out_buf_data[] and each buffer has
			 * different capacity different limit checks are used.
			 */
			max_len = TEST_LC_MAX_CIPHERTEXT_LEN + TEST_LC_MAX_DIGEST_LEN +
				  TEST_LC_MAX_OFFSET;
		} else {
			dst_buf = in_buf;
			op[0].out_buffer = NULL;
			max_len = TEST_LC_MAX_PLAINTEXT_LEN + TEST_LC_MAX_DIGEST_LEN +
				  TEST_LC_MAX_OFFSET;
		}

		if (is_encrypt) {
			op[0].encrypt = true;
			memcpy(in_buf_data + i, params->plaintext.data, params->plaintext.len);

			if (is_digest_separate) {
				memset(digest_buf, 0, TEST_LC_MAX_DIGEST_LEN);
				op[0].digest = digest_buf;
			} else {
				if (total_len > max_len) {
					TEST_LC_ERR("Digest buffer too small for offset %d", i);
					goto exit;
				}
				if (is_oop)
					dst_buf[0].frag_len += digest_len;
				else
					in_buf[0].frag_len += digest_len;
			}
		} else {
			op[0].encrypt = false;
			/*
			 * Copy plaintext from auth offset to cipher offset - Needed for
			 * authentication
			 */
			memcpy(in_buf_data + i + params->auth_offset,
			       params->plaintext.data + params->auth_offset,
			       params->cipher_offset - params->auth_offset);
			/* Copy ciphertext */
			memcpy(in_buf_data + i + params->cipher_offset, params->ciphertext.data,
			       params->ciphertext.len);

			if (is_digest_separate) {
				memcpy(digest_buf, params->digest_data, digest_len);
				op[0].digest = digest_buf;
			} else {
				if (total_len > max_len) {
					TEST_LC_ERR("Digest buffer too small for offset %d", i);
					goto exit;
				}

				memcpy(in_buf_data + i + params->cipher_offset +
					       params->ciphertext.len,
				       params->digest_data, digest_len);
				in_buf[0].frag_len += digest_len;
			}
		}

		in_buf[0].total_len = in_buf[0].frag_len;
		dst_buf[0].total_len = dst_buf[0].frag_len;

		op[0].cipher_offset = params->cipher_offset + i;
		op[0].cipher_len = params->cipher_len ? params->cipher_len : params->ciphertext.len;
		op[0].auth_offset = params->auth_offset + i;
		op[0].auth_len = params->auth_len ? params->auth_len : params->ciphertext.len;

		if (params->iv.len == 0) {
			TEST_LC_ERR("Invalid IV data or length");
			return -1;
		}
		op[0].cipher_iv = (uint8_t *)params->iv.data;

		op_cookie = rte_rand();
		op[0].op_cookie = op_cookie;

		ret = dao_liquid_crypto_sym_enqueue_burst(dev_id, qp_id, op, 1);
		if (ret != 1) {
			TEST_LC_ERR("Could not enqueue symmetric crypto operation");
			return -1;
		}

		ret = op_dequeue(dev_id, qp_id, res);
		if (ret < 0) {
			TEST_LC_ERR("Could not dequeue symmetric crypto operation");
			return -1;
		}

		TEST_ASSERT(res[0].op_cookie == op_cookie, "Invalid operation cookie");
		TEST_ASSERT(res[0].res.cn9k.compcode == DAO_CPT_COMP_GOOD,
			    "Crypto operation failed");
		TEST_ASSERT(res[0].res.cn9k.uc_compcode == DAO_UC_SUCCESS,
			    "Symmetric operation failed");

		result_buffer = (uint8_t *)dst_buf[0].data + i + params->cipher_offset;
		if (is_encrypt) {
			ret = memcmp(result_buffer, params->ciphertext.data,
				     params->ciphertext.len);
			if (ret != 0) {
				TEST_LC_ERR("Invalid result for offset %d", i);
				rte_hexdump(stdout, "RESULT: ", result_buffer,
					    params->ciphertext.len);
				rte_hexdump(stdout, "EXPECTED: ", params->ciphertext.data,
					    params->ciphertext.len);
				return -1;
			}

			if (is_digest_separate)
				digest_result = op[0].digest;
			else
				digest_result = result_buffer + params->ciphertext.len;

			ret = memcmp(digest_result, params->digest_data, digest_len);
			if (ret != 0) {
				TEST_LC_ERR("Invalid digest for offset %d", i);
				rte_hexdump(stdout, "RESULT digest: ", digest_result, digest_len);
				rte_hexdump(stdout, "EXPECTED digest: ", params->digest_data,
					    digest_len);
				return -1;
			}
		} else {
			if (params->cipher_len > 0)
				decrypt_result_len = params->cipher_len;
			else
				decrypt_result_len = params->plaintext.len - params->cipher_offset;

			ret = memcmp(result_buffer, params->plaintext.data + params->cipher_offset,
				     decrypt_result_len);
			if (ret != 0) {
				TEST_LC_ERR("Invalid result for offset %d", i);
				rte_hexdump(stdout, "RESULT: ", result_buffer, decrypt_result_len);
				rte_hexdump(stdout, "EXPECTED: ",
					    params->plaintext.data + params->cipher_offset,
					    decrypt_result_len);
				return -1;
			}
		}
	}

	sess_cookie = rte_rand();
	ret = dao_liquid_crypto_sym_sess_destroy(glb_params.dev_id, ev.sess_event.sess_id,
						 sess_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not destroy session");
		return -1;
	}

	ret = sess_event_dequeue(dev_id, &ev);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue session event");
		return -1;
	}

	TEST_ASSERT(ev.event_type == DAO_LC_CMD_EVENT_SESS_DESTROY, "Invalid event type");
	TEST_ASSERT(ev.sess_event.sess_cookie == sess_cookie, "Invalid operation cookie");

	return 0;

exit:
	/* clean-up path in case of early error */
	dao_liquid_crypto_sym_sess_destroy(glb_params.dev_id, ev.sess_event.sess_id, sess_cookie);
	sess_event_dequeue(dev_id, &ev);
	return -1;
}

static int
test_block_cipher_auth_encrypt(const void *data)
{
	int ret = 0;

	ret = test_block_cipher_auth(data, true, false, true);

	if (ret < 0) {
		TEST_LC_ERR("Chained Cipher test failed for separate digest mode");
		return ret;
	}

	return test_block_cipher_auth(data, true, false, false);
}

static int
test_block_cipher_auth_decrypt(const void *data)
{
	int ret = 0;

	ret = test_block_cipher_auth(data, false, false, true);
	if (ret < 0) {
		TEST_LC_ERR("Chained Cipher test failed for separate digest mode");
		return ret;
	}

	return test_block_cipher_auth(data, false, false, false);
}

static int
test_block_cipher_auth_encrypt_oop(const void *data)
{
	int ret = 0;

	ret = test_block_cipher_auth(data, true, true, true);
	if (ret < 0) {
		TEST_LC_ERR("Chained Cipher test failed for separate digest mode");
		return ret;
	}

	return test_block_cipher_auth(data, true, true, false);
}

static int
test_block_cipher_auth_decrypt_oop(const void *data)
{
	int ret = 0;

	ret = test_block_cipher_auth(data, false, true, true);
	if (ret < 0) {
		TEST_LC_ERR("Chained Cipher test failed for separate digest mode");
		return ret;
	}

	return test_block_cipher_auth(data, false, true, false);
}

struct unit_test_suite lc_testsuite_sym = {
	.suite_name = "Liquid Crypto Symmetric Test Suite",
	.setup = testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		TEST_CASE_NAMED_WITH_DATA("AES-128-CBC Encrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt, &aes_cbc_128_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-CBC Decrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt, &aes_cbc_128_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-CBC Encrypt OOP", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt_oop,
					  &aes_cbc_128_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-CBC Decrypt OOP", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt_oop,
					  &aes_cbc_128_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-CBC Encrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt, &aes_cbc_192_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-CBC Decrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt, &aes_cbc_192_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-CBC Encrypt OOP", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt_oop,
					  &aes_cbc_192_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-CBC Decrypt OOP", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt_oop,
					  &aes_cbc_192_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-CBC Encrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt, &aes_cbc_256_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-CBC Decrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt, &aes_cbc_256_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-CBC Encrypt OOP", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt_oop,
					  &aes_cbc_256_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-CBC Decrypt OOP", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt_oop,
					  &aes_cbc_256_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-GCM Encrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt, &aes_gcm_128_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-GCM Decrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt, &aes_gcm_128_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-GCM Encrypt OOP", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt_oop,
					  &aes_gcm_128_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-GCM Decrypt OOP", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt_oop,
					  &aes_gcm_128_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-GCM Zero Length Encrypt", ut_setup,
					  ut_teardown, test_block_cipher_only_encrypt,
					  &aes_gcm_128_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-GCM Zero Length Decrypt", ut_setup,
					  ut_teardown, test_block_cipher_only_decrypt,
					  &aes_gcm_128_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-GCM Zero Length Encrypt OOP", ut_setup,
					  ut_teardown, test_block_cipher_only_encrypt_oop,
					  &aes_gcm_128_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-GCM Zero Length Decrypt OOP", ut_setup,
					  ut_teardown, test_block_cipher_only_decrypt_oop,
					  &aes_gcm_128_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-GCM Encrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt, &aes_gcm_192_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-GCM Decrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt, &aes_gcm_192_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-GCM Encrypt OOP", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt_oop,
					  &aes_gcm_192_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-GCM Decrypt OOP", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt_oop,
					  &aes_gcm_192_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-GCM Zero Length Encrypt", ut_setup,
					  ut_teardown, test_block_cipher_only_encrypt,
					  &aes_gcm_192_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-GCM Zero Length Decrypt", ut_setup,
					  ut_teardown, test_block_cipher_only_decrypt,
					  &aes_gcm_192_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-GCM Zero Length Encrypt OOP", ut_setup,
					  ut_teardown, test_block_cipher_only_encrypt_oop,
					  &aes_gcm_192_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-GCM Zero Length Decrypt OOP", ut_setup,
					  ut_teardown, test_block_cipher_only_decrypt_oop,
					  &aes_gcm_192_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-GCM Encrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt, &aes_gcm_256_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-GCM Decrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt, &aes_gcm_256_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-GCM Encrypt OOP", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt_oop,
					  &aes_gcm_256_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-GCM Decrypt OOP", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt_oop,
					  &aes_gcm_256_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-GCM Zero Length Encrypt", ut_setup,
					  ut_teardown, test_block_cipher_only_encrypt,
					  &aes_gcm_256_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-GCM Zero Length Decrypt", ut_setup,
					  ut_teardown, test_block_cipher_only_decrypt,
					  &aes_gcm_256_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-GCM Zero Length Encrypt OOP", ut_setup,
					  ut_teardown, test_block_cipher_only_encrypt_oop,
					  &aes_gcm_256_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-GCM Zero Length Decrypt OOP", ut_setup,
					  ut_teardown, test_block_cipher_only_decrypt_oop,
					  &aes_gcm_256_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-GMAC Digest Gen", ut_setup, ut_teardown,
					  test_hash_gen, &aes_gmac_128_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-GMAC Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &aes_gmac_128_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-GMAC Digest Gen", ut_setup, ut_teardown,
					  test_hash_gen, &aes_gmac_192_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-GMAC Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &aes_gmac_192_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-GMAC Digest Gen", ut_setup, ut_teardown,
					  test_hash_gen, &aes_gmac_256_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-GMAC Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &aes_gmac_256_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-CCM Encrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt, &aes_ccm_128_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-CCM Decrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt, &aes_ccm_128_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-CCM Zero Length Encrypt", ut_setup,
					  ut_teardown, test_block_cipher_only_encrypt,
					  &aes_ccm_128_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-CCM Zero Length Decrypt", ut_setup,
					  ut_teardown, test_block_cipher_only_decrypt,
					  &aes_ccm_128_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-CCM Long AAD Encrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt,
					  &aes_ccm_128_long_aad_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-CCM Long AAD Decrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt,
					  &aes_ccm_128_long_aad_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-CCM Encrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt, &aes_ccm_192_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-CCM Decrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt, &aes_ccm_192_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-CCM Zero Length Encrypt", ut_setup,
					  ut_teardown, test_block_cipher_only_encrypt,
					  &aes_ccm_192_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-CCM Zero Length Decrypt", ut_setup,
					  ut_teardown, test_block_cipher_only_decrypt,
					  &aes_ccm_192_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-CCM Encrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt, &aes_ccm_256_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-CCM Decrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt, &aes_ccm_256_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-CCM Zero Length Encrypt", ut_setup,
					  ut_teardown, test_block_cipher_only_encrypt,
					  &aes_ccm_256_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-CCM Zero Length Decrypt", ut_setup,
					  ut_teardown, test_block_cipher_only_decrypt,
					  &aes_ccm_256_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("ChaCha-Poly Encrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt, &chacha_poly_test_data),
		TEST_CASE_NAMED_WITH_DATA("ChaCha-Poly Decrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt, &chacha_poly_test_data),
		TEST_CASE_NAMED_WITH_DATA("ChaCha-Poly Zero Length Encrypt", ut_setup,
					  ut_teardown, test_block_cipher_only_encrypt,
					  &chacha_poly_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("ChaCha-Poly Zero Length Decrypt", ut_setup,
					  ut_teardown, test_block_cipher_only_decrypt,
					  &chacha_poly_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-12B-CMAC Digest Gen", ut_setup, ut_teardown,
					  test_hash_gen, &aes_cmac_128_12B_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-12B-CMAC Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &aes_cmac_128_12B_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-16B-CMAC Digest Gen", ut_setup, ut_teardown,
					  test_hash_gen, &aes_cmac_128_16B_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-16B-CMAC Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &aes_cmac_128_16B_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-12B-CMAC Digest Gen", ut_setup, ut_teardown,
					  test_hash_gen, &aes_cmac_192_12B_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-12B-CMAC Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &aes_cmac_192_12B_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-16B-CMAC Digest Gen", ut_setup, ut_teardown,
					  test_hash_gen, &aes_cmac_192_16B_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-16B-CMAC Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &aes_cmac_192_16B_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-12B-CMAC Digest Gen", ut_setup, ut_teardown,
					  test_hash_gen, &aes_cmac_256_12B_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-12B-CMAC Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &aes_cmac_256_12B_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-16B-CMAC Digest Gen", ut_setup, ut_teardown,
					  test_hash_gen, &aes_cmac_256_16B_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-16B-CMAC Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &aes_cmac_256_16B_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHA1 Digest Gen", ut_setup, ut_teardown, test_hash_gen,
					  &sha1_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHA1 Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &sha1_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHA224 Digest Gen", ut_setup, ut_teardown, test_hash_gen,
					  &sha224_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHA224 Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &sha224_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHA256 Digest Gen", ut_setup, ut_teardown, test_hash_gen,
					  &sha256_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHA256 Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &sha256_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHA384 Digest Gen", ut_setup, ut_teardown, test_hash_gen,
					  &sha384_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHA384 Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &sha384_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHA512 Digest Gen", ut_setup, ut_teardown, test_hash_gen,
					  &sha512_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHA512 Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &sha512_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHA3-224 Digest Gen", ut_setup, ut_teardown,
					  test_hash_gen, &sha3_224_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHA3-224 Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &sha3_224_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHA3-256 Digest Gen", ut_setup, ut_teardown,
					  test_hash_gen, &sha3_256_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHA3-256 Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &sha3_256_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHA3-384 Digest Gen", ut_setup, ut_teardown,
					  test_hash_gen, &sha3_384_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHA3-384 Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &sha3_384_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHA3-512 Digest Gen", ut_setup, ut_teardown,
					  test_hash_gen, &sha3_512_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHA3-512 Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &sha3_512_test_data),
		TEST_CASE_NAMED_WITH_DATA("HMAC-SHA1 Digest Gen with 20 byte key data", ut_setup,
					  ut_teardown, test_hash_gen, &hmac_sha1_20B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC-SHA1 Digest Verify with 20 byte key data", ut_setup,
					  ut_teardown, test_hash_verify, &hmac_sha1_20B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC SHA1 Digest Gen with 1024 byte key data", ut_setup,
					  ut_teardown, test_hash_gen, &hmac_sha1_1024B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC SHA1 Digest Verify with 1024 byte key data",
					  ut_setup, ut_teardown, test_hash_verify,
					  &hmac_sha1_1024B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC-SHA224 Digest Gen with 28 byte key data", ut_setup,
					  ut_teardown, test_hash_gen, &hmac_sha224_28B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC-SHA224 Digest Verify with 28 byte key data",
					  ut_setup, ut_teardown, test_hash_verify,
					  &hmac_sha224_28B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC-SHA256 Digest Gen with 32 byte key data", ut_setup,
					  ut_teardown, test_hash_gen, &hmac_sha256_32B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC-SHA256 Digest Verify with 32 byte key data",
					  ut_setup, ut_teardown, test_hash_verify,
					  &hmac_sha256_32B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC SHA256 Digest Gen with 1024 byte key data",
					  ut_setup, ut_teardown, test_hash_gen,
					  &hmac_sha256_1024B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC SHA256 Digest Verify with 1024 byte key data",
					  ut_setup, ut_teardown, test_hash_verify,
					  &hmac_sha256_1024B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC-SHA384 Digest Gen with 48 byte key data", ut_setup,
					  ut_teardown, test_hash_gen, &hmac_sha384_48B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC-SHA384 Digest Verify with 48 byte key data",
					  ut_setup, ut_teardown, test_hash_verify,
					  &hmac_sha384_48B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC-SHA512 Digest Gen with 64 byte key data", ut_setup,
					  ut_teardown, test_hash_gen, &hmac_sha512_64B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC-SHA512 Digest Verify 64 byte key data", ut_setup,
					  ut_teardown, test_hash_verify, &hmac_sha512_64B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC-SHA3-224 Digest Gen with 28 byte key data",
					  ut_setup, ut_teardown, test_hash_gen,
					  &hmac_sha3_224_28B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC-SHA3-224 Digest Verify with 28 byte key data",
					  ut_setup, ut_teardown, test_hash_verify,
					  &hmac_sha3_224_28B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC-SHA3-256 Digest Gen with 32 byte key data",
					  ut_setup, ut_teardown, test_hash_gen,
					  &hmac_sha3_256_32B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC-SHA3-256 Digest Verify with 32 byte key data",
					  ut_setup, ut_teardown, test_hash_verify,
					  &hmac_sha3_256_32B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC-SHA3-384 Digest Gen with 48 byte key data",
					  ut_setup, ut_teardown, test_hash_gen,
					  &hmac_sha3_384_48B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC-SHA3-384 Digest Verify with 48 byte key data",
					  ut_setup, ut_teardown, test_hash_verify,
					  &hmac_sha3_384_48B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC-SHA3-512 Digest Gen with 64 byte key data",
					  ut_setup, ut_teardown, test_hash_gen,
					  &hmac_sha3_512_64B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC-SHA3-512 Digest Verify with 64 byte key data",
					  ut_setup, ut_teardown, test_hash_verify,
					  &hmac_sha3_512_64B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC_SHA3-224 Digest Gen with 128 byte key data",
					  ut_setup, ut_teardown, test_hash_gen,
					  &hmac_sha3_224_128B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC_SHA3-224 Digest Verify with 128 byte key data",
					  ut_setup, ut_teardown, test_hash_verify,
					  &hmac_sha3_224_128B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC_SHA3-256 Digest Gen with 128 byte key data",
					  ut_setup, ut_teardown, test_hash_gen,
					  &hmac_sha3_256_128B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC_SHA3-256 Digest Verify with 128 byte key data",
					  ut_setup, ut_teardown, test_hash_verify,
					  &hmac_sha3_256_128B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC_SHA3-384 Digest Gen with 128 byte key data",
					  ut_setup, ut_teardown, test_hash_gen,
					  &hmac_sha3_384_128B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC_SHA3-384 Digest Verify with 128 byte key data",
					  ut_setup, ut_teardown, test_hash_verify,
					  &hmac_sha3_384_128B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC_SHA3-512 Digest Gen with 128 byte key data",
					  ut_setup, ut_teardown, test_hash_gen,
					  &hmac_sha3_512_128B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC_SHA3-512 Digest Verify with 128 byte key data",
					  ut_setup, ut_teardown, test_hash_verify,
					  &hmac_sha3_512_128B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC_SHA3-224 Digest Gen with 358 byte key data",
					  ut_setup, ut_teardown, test_hash_gen,
					  &hmac_sha3_224_358B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC_SHA3-224 Digest Verify with 358 byte key data",
					  ut_setup, ut_teardown, test_hash_verify,
					  &hmac_sha3_224_358B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC_SHA3-224 Digest Gen with 360 byte key data",
					  ut_setup, ut_teardown, test_hash_gen,
					  &hmac_sha3_224_360B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC_SHA3-224 Digest Verify with 360 byte key data",
					  ut_setup, ut_teardown, test_hash_verify,
					  &hmac_sha3_224_360B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC_SHA3-224 Digest Gen with 1024 byte key data",
					  ut_setup, ut_teardown, test_hash_gen,
					  &hmac_sha3_224_1024B_key),
		TEST_CASE_NAMED_WITH_DATA("HMAC_SHA3-224 Digest Verify with 1024 byte key data",
					  ut_setup, ut_teardown, test_hash_verify,
					  &hmac_sha3_224_1024B_key),
		TEST_CASE_NAMED_WITH_DATA("SHAKE128 Digest Gen", ut_setup, ut_teardown,
					  test_hash_gen, &shake128_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHAKE128 Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &shake128_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHAKE256 Digest Gen", ut_setup, ut_teardown,
					  test_hash_gen, &shake256_test_data),
		TEST_CASE_NAMED_WITH_DATA("SHAKE256 Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &shake256_test_data),
		TEST_CASE_NAMED_WITH_DATA("KMAC128 Digest Gen", ut_setup, ut_teardown,
					  test_hash_gen, &kmac128_test_data),
		TEST_CASE_NAMED_WITH_DATA("KMAC128 Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &kmac128_test_data),
		TEST_CASE_NAMED_WITH_DATA("KMAC256 Digest Gen", ut_setup, ut_teardown,
					  test_hash_gen, &kmac256_test_data),
		TEST_CASE_NAMED_WITH_DATA("KMAC256 Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &kmac256_test_data),
		TEST_CASE_NAMED_WITH_DATA("Wrap 128 bit key data with 128 bit KEK", ut_setup,
					  ut_teardown, test_aes_key_wrap,
					  &aes_keywrap_128B_kek_128B_key),
		TEST_CASE_NAMED_WITH_DATA("Unwrap 136 bit key data and 128 bit KEK", ut_setup,
					  ut_teardown, test_aes_key_unwrap,
					  &aes_keywrap_128B_kek_128B_key),
		TEST_CASE_NAMED_WITH_DATA("Wrap 128 bit key data with 192 bit KEK", ut_setup,
					  ut_teardown, test_aes_key_wrap,
					  &aes_keywrap_192B_kek_128B_key),
		TEST_CASE_NAMED_WITH_DATA("Unwrap 128 bit key data and 192 bit KEK", ut_setup,
					  ut_teardown, test_aes_key_unwrap,
					  &aes_keywrap_192B_kek_128B_key),
		TEST_CASE_NAMED_WITH_DATA("Wrap 128 bit key data with 256 bit KEK", ut_setup,
					  ut_teardown, test_aes_key_wrap,
					  &aes_keywrap_256B_kek_128B_key),
		TEST_CASE_NAMED_WITH_DATA("Unwrap 128 bit key data and 256 bit KEK", ut_setup,
					  ut_teardown, test_aes_key_unwrap,
					  &aes_keywrap_256B_kek_128B_key),
		TEST_CASE_NAMED_WITH_DATA("Wrap 192 bit key data with 192 bit KEK", ut_setup,
					  ut_teardown, test_aes_key_wrap,
					  &aes_keywrap_192B_kek_192B_key),
		TEST_CASE_NAMED_WITH_DATA("Unwrap 192 bit key data and 192 bit KEK", ut_setup,
					  ut_teardown, test_aes_key_unwrap,
					  &aes_keywrap_192B_kek_192B_key),
		TEST_CASE_NAMED_WITH_DATA("Wrap 192 bit key data with 256 bit KEK", ut_setup,
					  ut_teardown, test_aes_key_wrap,
					  &aes_keywrap_256B_kek_192B_key),
		TEST_CASE_NAMED_WITH_DATA("Unwrap 192 bit key data and 256 bit KEK", ut_setup,
					  ut_teardown, test_aes_key_unwrap,
					  &aes_keywrap_256B_kek_192B_key),
		TEST_CASE_NAMED_WITH_DATA("Wrap 256 bit key data with 256 bit KEK", ut_setup,
					  ut_teardown, test_aes_key_wrap,
					  &aes_keywrap_256B_kek_256B_key),
		TEST_CASE_NAMED_WITH_DATA("Unwrap 256 bit key data and 256 bit KEK", ut_setup,
					  ut_teardown, test_aes_key_unwrap,
					  &aes_keywrap_256B_kek_256B_key),
		TEST_CASE_NAMED_WITH_DATA("Wrap 3072 bytes key data with 256 bit KEK", ut_setup,
					  ut_teardown, test_aes_key_wrap,
					  &aes_keywrap_256B_kek_3072B_key),
		TEST_CASE_NAMED_WITH_DATA("Unwrap 3072 bytes invalid key data with 256 bit KEK",
					  ut_setup, ut_teardown,
					  test_aes_key_unwrap_invalid_keydata,
					  &aes_keywrap_256B_kek_3072B_key),
		TEST_CASE_NAMED_WITH_DATA("Wrap 3080 bytes invalid key data with 256 bit KEK",
					  ut_setup, ut_teardown, test_aes_key_wrap_invalid_keydata,
					  &aes_keywrap_256B_kek_3080B_key),
		TEST_CASE_NAMED_WITH_DATA("Wrap 3064 bytes key data with 256 bit KEK", ut_setup,
					  ut_teardown, test_aes_key_wrap,
					  &aes_keywrap_256B_kek_3064B_key),
		TEST_CASE_NAMED_WITH_DATA("Unwrap 3064 bytes key data with 256 bit KEK", ut_setup,
					  ut_teardown, test_aes_key_unwrap,
					  &aes_keywrap_256B_kek_3064B_key),
		TEST_CASE_NAMED_WITH_DATA("Wrap 128 bit key data with 128 bit KEK OOP", ut_setup,
					  ut_teardown, test_aes_key_wrap_oop,
					  &aes_keywrap_128B_kek_128B_key),
		TEST_CASE_NAMED_WITH_DATA("Unwrap 128 bit key data and 128 bit KEK OOP", ut_setup,
					  ut_teardown, test_aes_key_unwrap_oop,
					  &aes_keywrap_128B_kek_128B_key),
		TEST_CASE_NAMED_WITH_DATA("Wrap 128 bit key data with 192 bit KEK OOP", ut_setup,
					  ut_teardown, test_aes_key_wrap_oop,
					  &aes_keywrap_192B_kek_128B_key),
		TEST_CASE_NAMED_WITH_DATA("Unwrap 128 bit key data and 192 bit KEK OOP", ut_setup,
					  ut_teardown, test_aes_key_unwrap_oop,
					  &aes_keywrap_192B_kek_128B_key),
		TEST_CASE_NAMED_WITH_DATA("Wrap 128 bit key data with 256 bit KEK OOP", ut_setup,
					  ut_teardown, test_aes_key_wrap_oop,
					  &aes_keywrap_256B_kek_128B_key),
		TEST_CASE_NAMED_WITH_DATA("Unwrap 128 bit key data and 256 bit KEK OOP", ut_setup,
					  ut_teardown, test_aes_key_unwrap_oop,
					  &aes_keywrap_256B_kek_128B_key),
		TEST_CASE_NAMED_WITH_DATA("Wrap 192 bit key data with 192 bit KEK OOP", ut_setup,
					  ut_teardown, test_aes_key_wrap_oop,
					  &aes_keywrap_192B_kek_192B_key),
		TEST_CASE_NAMED_WITH_DATA("Unwrap 192 bit key data and 192 bit KEK OOP", ut_setup,
					  ut_teardown, test_aes_key_unwrap_oop,
					  &aes_keywrap_192B_kek_192B_key),
		TEST_CASE_NAMED_WITH_DATA("Wrap 192 bit key data with 256 bit KEK OOP", ut_setup,
					  ut_teardown, test_aes_key_wrap_oop,
					  &aes_keywrap_256B_kek_192B_key),
		TEST_CASE_NAMED_WITH_DATA("Unwrap 192 bit key data and 256 bit KEK OOP", ut_setup,
					  ut_teardown, test_aes_key_unwrap_oop,
					  &aes_keywrap_256B_kek_192B_key),
		TEST_CASE_NAMED_WITH_DATA("Wrap 256 bit key data with 256 bit KEK OOP", ut_setup,
					  ut_teardown, test_aes_key_wrap_oop,
					  &aes_keywrap_256B_kek_256B_key),
		TEST_CASE_NAMED_WITH_DATA("Unwrap 256 bit key data and 256 bit KEK OOP", ut_setup,
					  ut_teardown, test_aes_key_unwrap_oop,
					  &aes_keywrap_256B_kek_256B_key),
		TEST_CASE_NAMED_WITH_DATA("Wrap 3072 bytes key data with 256 bit KEK OOP", ut_setup,
					  ut_teardown, test_aes_key_wrap_oop,
					  &aes_keywrap_256B_kek_3072B_key),
		TEST_CASE_NAMED_WITH_DATA("Wrap 3064 bytes key data with 256 bit KEK OOP", ut_setup,
					  ut_teardown, test_aes_key_wrap_oop,
					  &aes_keywrap_256B_kek_3064B_key),
		TEST_CASE_NAMED_WITH_DATA("Unwrap 3064 bytes key data with 256 bit KEK OOP",
					  ut_setup, ut_teardown, test_aes_key_unwrap_oop,
					  &aes_keywrap_256B_kek_3064B_key),
		TEST_CASE_NAMED_WITH_DATA("Wrap 20 bytes key data with 192 bit KEK", ut_setup,
					  ut_teardown, test_aes_key_wrap_pad,
					  &aes_keywrap_192B_kek_20B_key),
		TEST_CASE_NAMED_WITH_DATA("Unwrap 20 bytes key data and 192 bit KEK", ut_setup,
					  ut_teardown, test_aes_key_unwrap_pad,
					  &aes_keywrap_192B_kek_20B_key),
		TEST_CASE_NAMED_WITH_DATA("Wrap 20 bytes key data with 192 bit KEK OOP", ut_setup,
					  ut_teardown, test_aes_key_wrap_pad_oop,
					  &aes_keywrap_192B_kek_20B_key),
		TEST_CASE_NAMED_WITH_DATA("Unwrap 20 bytes key data and 192 bit KEK OOP", ut_setup,
					  ut_teardown, test_aes_key_unwrap_pad_oop,
					  &aes_keywrap_192B_kek_20B_key),
		TEST_CASE_NAMED_WITH_DATA("Wrap 7 bytes key data with 192 bit KEK", ut_setup,
					  ut_teardown, test_aes_key_wrap_pad,
					  &aes_keywrap_192B_kek_7B_key),
		TEST_CASE_NAMED_WITH_DATA("Unwrap 7 bytes key data and 192 bit KEK", ut_setup,
					  ut_teardown, test_aes_key_unwrap_pad,
					  &aes_keywrap_192B_kek_7B_key),
		TEST_CASE_NAMED_WITH_DATA("Wrap 7 bytes key data with 192 bit KEK OOP", ut_setup,
					  ut_teardown, test_aes_key_wrap_pad_oop,
					  &aes_keywrap_192B_kek_7B_key),
		TEST_CASE_NAMED_WITH_DATA("Unwrap 7 bytes key data and 192 bit KEK OOP", ut_setup,
					  ut_teardown, test_aes_key_unwrap_pad_oop,
					  &aes_keywrap_192B_kek_7B_key),
		TEST_CASE_NAMED_WITH_DATA(
			"Unwrap 16 bytes(0xA6) key data and 192 bit KEK with padding bit enabled",
			ut_setup, ut_teardown, test_aes_key_unwrap_invalid_iv_case,
			&aes_keywrap_192_kek_16B_wrapkey_with_A6),
		TEST_CASE_NAMED_WITH_DATA(
			"Unwrap 32 bytes(0xA6) key data and 192 bit KEK with padding bit enabled",
			ut_setup, ut_teardown, test_aes_key_unwrap_invalid_iv_case,
			&aes_keywrap_192_kek_32B_wrapkey_with_A6),
		TEST_CASE_NAMED_WITH_DATA(
			"Unwrap 2408 bytes(0xA6) key data and 192 bit KEK with padding bit enabled",
			ut_setup, ut_teardown, test_aes_key_unwrap_invalid_iv_case,
			&aes_keywrap_192_kek_2408B_wrapkey_with_A6),
		TEST_CASE_NAMED_WITH_DATA(
			"Wrap 16 bytes(0XA6) key data and 192 bit KEK with padding bit enabled",
			ut_setup, ut_teardown, test_aes_key_wrap_pad,
			&aes_keywrap_192_kek_16B_key_with_A6),
		TEST_CASE_NAMED_WITH_DATA(
			"Unwrap 16 bytes(0xA6 original) key data and 192 bit KEK with padding bit enabled",
			ut_setup, ut_teardown, test_aes_key_unwrap_pad,
			&aes_keywrap_192_kek_16B_key_with_A6),
		TEST_CASE_NAMED_WITH_DATA(
			"Wrap 1KB bytes(0XA6) key data and 192 bit KEK with padding bit enabled",
			ut_setup, ut_teardown, test_aes_key_wrap_pad,
			&aes_keywrap_192_kek_1KB_key_with_A6),
		TEST_CASE_NAMED_WITH_DATA(
			"Unwrap 1KB bytes(0xA6 original) key data and 192 bit KEK with padding bit enabled",
			ut_setup, ut_teardown, test_aes_key_unwrap_pad,
			&aes_keywrap_192_kek_1KB_key_with_A6),
		TEST_CASE_NAMED_WITH_DATA(
			"Wrap 2400 bytes(0XA6) key data and 192 bit KEK with padding bit enabled",
			ut_setup, ut_teardown, test_aes_key_wrap_pad,
			&aes_keywrap_192_kek_2400B_key_with_A6),
		TEST_CASE_NAMED_WITH_DATA(
			"Unwrap 2400 bytes(0xA6) key data and 192 bit KEK with padding bit enabled",
			ut_setup, ut_teardown, test_aes_key_unwrap_pad,
			&aes_keywrap_192_kek_2400B_key_with_A6),
		TEST_CASE_NAMED_WITH_DATA("AES-CBC-128_HMAC-SHA1 Encrypt", ut_setup, ut_teardown,
					  test_block_cipher_auth_encrypt,
					  &aes_cbc_128_sha1_hmac_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-CBC-128_HMAC-SHA1 Decrypt", ut_setup, ut_teardown,
					  test_block_cipher_auth_decrypt,
					  &aes_cbc_128_sha1_hmac_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-CBC-128_HMAC-SHA1 Encrypt OOP", ut_setup,
					  ut_teardown, test_block_cipher_auth_encrypt_oop,
					  &aes_cbc_128_sha1_hmac_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-CBC-128_HMAC-SHA1 Decrypt OOP", ut_setup,
					  ut_teardown, test_block_cipher_auth_decrypt_oop,
					  &aes_cbc_128_sha1_hmac_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-CBC-128_HMAC-SHA1 Zero Length Encrypt", ut_setup,
					  ut_teardown, test_block_cipher_auth_encrypt,
					  &aes_cbc_128_sha1_hmac_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-CBC-128_HMAC-SHA1 Zero Length Decrypt", ut_setup,
					  ut_teardown, test_block_cipher_auth_decrypt,
					  &aes_cbc_128_sha1_hmac_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-CBC-128_HMAC-SHA1 Zero Length Encrypt OOP", ut_setup,
					  ut_teardown, test_block_cipher_auth_encrypt_oop,
					  &aes_cbc_128_sha1_hmac_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-CBC-128_HMAC-SHA1 Zero Length Decrypt OOP", ut_setup,
					  ut_teardown, test_block_cipher_auth_decrypt_oop,
					  &aes_cbc_128_sha1_hmac_empty_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-CBC-128_HMAC-SHA1 Encrypt Offset", ut_setup,
					  ut_teardown, test_block_cipher_auth_encrypt,
					  &aes_cbc_128_sha1_hmac_offsets_test_data_1),
		TEST_CASE_NAMED_WITH_DATA("AES-CBC-128_HMAC-SHA1 Decrypt Offset", ut_setup,
					  ut_teardown, test_block_cipher_auth_decrypt,
					  &aes_cbc_128_sha1_hmac_offsets_test_data_1),
		TEST_CASE_NAMED_WITH_DATA("AES-CBC-128_HMAC-SHA1 Encrypt OOP Offset", ut_setup,
					  ut_teardown, test_block_cipher_auth_encrypt_oop,
					  &aes_cbc_128_sha1_hmac_offsets_test_data_1),
		TEST_CASE_NAMED_WITH_DATA("AES-CBC-128_HMAC-SHA1 Decrypt OOP Offset", ut_setup,
					  ut_teardown, test_block_cipher_auth_decrypt_oop,
					  &aes_cbc_128_sha1_hmac_offsets_test_data_1),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};
