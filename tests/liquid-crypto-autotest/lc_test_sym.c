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
test_block_cipher_only(const void *data, bool is_encrypt)
{
	uint8_t in_buf_data[TEST_LC_MAX_PLAINTEXT_LEN] = {0};
	const struct test_sym_params *params = data;
	uint8_t cipher_iv[TEST_LC_MAX_IV_LEN] = {0};
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t sess_cookie = rte_rand();
	struct dao_lc_buf in_buf[1] = {0};
	struct dao_lc_sym_op op[1] = {0};
	struct dao_lc_cmd_event ev;
	struct dao_lc_res res[1];
	int ret;

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
	op[0].op_cookie = sess_cookie;
	op[0].sess_id = ev.sess_event.sess_id;

	if (is_encrypt) {
		memcpy(in_buf_data, params->plaintext.data, params->plaintext.len);
		in_buf[0].seg_len = params->plaintext.len;
		in_buf[0].total_len = params->plaintext.len;
		op[0].encrypt = 1;
	} else {
		memcpy(in_buf_data, params->ciphertext.data, params->ciphertext.len);
		in_buf[0].seg_len = params->ciphertext.len;
		in_buf[0].total_len = params->ciphertext.len;
		op[0].encrypt = 0;
	}

	in_buf[0].data = in_buf_data;
	op[0].in_buffer = in_buf;
	op[0].cipher_offset = 0;
	op[0].cipher_len = params->ciphertext.len;

	memcpy(cipher_iv, params->iv.data, params->iv.len);
	op[0].cipher_iv = cipher_iv;

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

	TEST_ASSERT(res[0].op_cookie == sess_cookie, "Invalid operation cookie");
	TEST_ASSERT(res[0].res.cn9k.compcode == DAO_CPT_COMP_GOOD, "Crypto operation failed");
	TEST_ASSERT(res[0].res.cn9k.uc_compcode == DAO_UC_SUCCESS, "Symmetric operation failed");

	if (is_encrypt) {
		ret = memcmp(in_buf_data, params->ciphertext.data, params->ciphertext.len);
		if (ret != 0) {
			rte_hexdump(stdout, "RESULT: ", in_buf_data, params->ciphertext.len);
			rte_hexdump(stdout, "EXPECTED: ", params->ciphertext.data,
				    params->ciphertext.len);
		}
	} else {
		ret = memcmp(in_buf_data, params->plaintext.data, params->plaintext.len);
		if (ret != 0) {
			rte_hexdump(stdout, "RESULT: ", in_buf_data, params->plaintext.len);
			rte_hexdump(stdout, "EXPECTED: ", params->plaintext.data,
				    params->plaintext.len);
		}
	}
	TEST_ASSERT(ret == 0, "Invalid result");

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
test_block_cipher_only_encrypt(const void *data)
{
	return test_block_cipher_only(data, true);
}

static int
test_block_cipher_only_decrypt(const void *data)
{
	return test_block_cipher_only(data, false);
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
		TEST_CASE_NAMED_WITH_DATA("AES-192-CBC Encrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt, &aes_cbc_192_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-192-CBC Decrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt, &aes_cbc_192_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-CBC Encrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_encrypt, &aes_cbc_256_test_data),
		TEST_CASE_NAMED_WITH_DATA("AES-256-CBC Decrypt", ut_setup, ut_teardown,
					  test_block_cipher_only_decrypt, &aes_cbc_256_test_data),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}};
