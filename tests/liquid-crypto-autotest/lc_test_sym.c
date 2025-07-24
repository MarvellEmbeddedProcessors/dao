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
	const struct test_sym_params *params = data;
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t sess_cookie = rte_rand();
	struct dao_lc_buf in_buf[1] = {0};
	struct dao_lc_sym_op op[1] = {0};
	int ret, i, max_offset = 32;
	struct dao_lc_cmd_event ev;
	struct dao_lc_res res[1];
	uint64_t op_cookie;

	ret = dao_liquid_crypto_sym_sess_create(dev_id, &params->ctx, sess_cookie);
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

	for (i = 0; i < max_offset; i++) {
		if (is_auth_gen)
			memset(digest, 0, sizeof(digest));
		else
			memcpy(op[0].digest, params->digest.data, params->digest.len);

		memset(in_buf_data, 0, i);
		memcpy(in_buf_data + i, params->plaintext.data, params->plaintext.len);
		in_buf[0].frag_len = params->plaintext.len + i;
		in_buf[0].total_len = params->plaintext.len + i;

		in_buf[0].data = in_buf_data;
		op[0].in_buffer = in_buf;
		op[0].auth_offset = params->auth_offset + i;
		op[0].auth_len = params->plaintext.len;

		if (is_auth_gen)
			memset(op[0].digest, 0, params->digest.len);
		else
			memcpy(op[0].digest, params->digest.data, params->digest.len);

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

			ret = memcmp(op[0].digest, params->digest.data, params->digest.len);
			if (ret != 0) {
				TEST_LC_ERR("Digest Gen failed for offset %d", i);
				rte_hexdump(stdout, "RESULT digest: ", op[0].digest,
					    params->digest.len);
				rte_hexdump(stdout, "EXPECTED digest: ", params->digest.data,
					    params->digest.len);
				return -1;
			}
		} else {
			if (res[0].res.cn9k.uc_compcode == DAO_UC_ERR_GC_ICV_MISCOMPARE) {
				TEST_LC_ERR("Expected digest verification to succeed for offset %d",
					    i);
				rte_hexdump(stdout, "PROVIDED digest: ", op[0].digest,
					    params->digest.len);
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

static int
test_block_cipher_only(const void *data, bool is_encrypt, bool is_oop)
{
	uint8_t out_buf_data[TEST_LC_MAX_CIPHERTEXT_LEN + TEST_LC_MAX_DIGEST_LEN +
			     TEST_LC_MAX_OFFSET] = {0};
	uint8_t in_buf_data[TEST_LC_MAX_PLAINTEXT_LEN + TEST_LC_MAX_DIGEST_LEN +
			    TEST_LC_MAX_OFFSET] = {0};
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
	struct dao_lc_cmd_event ev;
	struct dao_lc_buf *dst_buf;
	size_t max_len, total_len;
	struct dao_lc_res res[1];

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
		in_buf[0].total_len = in_buf[0].frag_len;

		if (is_oop) {
			dst_buf = out_buf;
			if (is_encrypt)
				out_data_len = params->ciphertext.len;
			else
				out_data_len = params->plaintext.len;
			dst_buf[0].data = out_buf_data;
			dst_buf[0].frag_len = out_data_len + i;
			dst_buf[0].total_len = dst_buf[0].frag_len;
			op[0].out_buffer = out_buf;
		} else {
			dst_buf = in_buf;
			op[0].out_buffer = NULL;
		}

		op[0].in_buffer = in_buf;

		if ((params->ctx.fc.enc_cipher == DAO_LC_FC_ENC_CIPHER_AES_GCM) ||
		    (params->ctx.fc.enc_cipher == DAO_LC_FC_ENC_CIPHER_AES_CCM)) {
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
				/*
				 * As, in-place digest is stored in in_buf_data[] and in OOP it is
				 * stored in out_buf_data[] and each buffer has different capacity
				 * different limit checks are used.
				 */
				if (is_oop)
					max_len = TEST_LC_MAX_CIPHERTEXT_LEN +
						  TEST_LC_MAX_DIGEST_LEN + TEST_LC_MAX_OFFSET;
				else
					max_len = TEST_LC_MAX_PLAINTEXT_LEN +
						  TEST_LC_MAX_DIGEST_LEN + TEST_LC_MAX_OFFSET;

				total_len = params->plaintext.len + params->digest.len + i;
				if (total_len <= max_len) {
					op[0].digest = (uint8_t *)dst_buf[0].data +
						       params->plaintext.len + i;
				} else {
					TEST_LC_ERR("Digest buffer too small for offset %d", i);
					goto exit;
				}
			} else {
				memcpy(in_buf_data + i, params->ciphertext.data,
				       params->ciphertext.len);
				op[0].encrypt = false;
				if (params->ciphertext.len + params->digest.len + i <=
				    TEST_LC_MAX_PLAINTEXT_LEN + TEST_LC_MAX_DIGEST_LEN +
					    TEST_LC_MAX_OFFSET) {
					memcpy(in_buf_data + params->ciphertext.len + i,
					       params->digest.data, params->digest.len);
					op[0].digest = &(in_buf_data[params->ciphertext.len + i]);
					/*
					 * During decryption digest should be present in input
					 * buffer for  both in-place and out-of-place operations,
					 * as APIs require digest to be present in the input
					 * buffer for decryption.
					 * TODO: Address this limitation in the LC API.
					 */
				} else {
					TEST_LC_ERR("Buffer too small for digest for offset %d", i);
					goto exit;
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

		op[0].cipher_offset = params->cipher_offset + i;
		op[0].cipher_len = params->ciphertext.len;

		if (params->iv.data == NULL || params->iv.len == 0) {
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

			ret = memcmp(op[0].digest, params->digest.data, params->digest.len);
			if (ret != 0) {
				TEST_LC_ERR("Invalid digest for offset %d", i);
				rte_hexdump(stdout, "RESULT digest: ", op[0].digest,
					    params->digest.len);
				rte_hexdump(stdout, "EXPECTED digest: ", params->digest.data,
					    params->digest.len);
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
	return test_block_cipher_only(data, true, false);
}

static int
test_block_cipher_only_decrypt(const void *data)
{
	return test_block_cipher_only(data, false, false);
}

static int
test_block_cipher_only_encrypt_oop(const void *data)
{
	return test_block_cipher_only(data, true, true);
}

static int
test_block_cipher_only_decrypt_oop(const void *data)
{
	return test_block_cipher_only(data, false, true);
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
		TEST_CASE_NAMED_WITH_DATA("AES-128-CCM Encrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt, &aes_ccm_128_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-128-CCM Decrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt, &aes_ccm_128_test_data),
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
		TEST_CASE_NAMED_WITH_DATA("AES-256-CCM Encrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt, &aes_ccm_256_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-CCM Decrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt, &aes_ccm_256_test_data),
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
		TEST_CASE_NAMED_WITH_DATA("HMAC-SHA1 Digest Gen", ut_setup, ut_teardown,
					  test_hash_gen, &hmac_sha1_test_data),
		TEST_CASE_NAMED_WITH_DATA("HMAC-SHA1 Digest Verify", ut_setup, ut_teardown,
					  test_hash_verify, &hmac_sha1_test_data),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};
