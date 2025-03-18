/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <rte_cycles.h>
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
test_block_cipher_only(const void *data)
{
	const struct test_sym_params *params = data;
	uint64_t sess_cookie = rte_rand();
	struct dao_lc_cmd_event ev;
	int ret;

	ret = dao_liquid_crypto_sym_sess_create(glb_params.dev_id, &params->ctx, sess_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not create session");
		return -1;
	}

	ret = sess_event_dequeue(glb_params.dev_id, &ev);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue session event");
		return -1;
	}

	TEST_ASSERT(ev.event_type == DAO_LC_CMD_EVENT_SESS_CREATE, "Invalid event type");
	TEST_ASSERT(ev.sess_event.sess_id != DAO_LC_SESS_ID_INVALID, "Invalid session ID");
	TEST_ASSERT(ev.sess_event.sess_cookie == sess_cookie, "Invalid operation cookie");

	ret = dao_liquid_crypto_sym_sess_destroy(glb_params.dev_id, ev.sess_event.sess_id,
						 sess_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not destroy session");
		return -1;
	}

	ret = sess_event_dequeue(glb_params.dev_id, &ev);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue session event");
		return -1;
	}

	TEST_ASSERT(ev.event_type == DAO_LC_CMD_EVENT_SESS_DESTROY, "Invalid event type");
	TEST_ASSERT(ev.sess_event.sess_cookie == sess_cookie, "Invalid operation cookie");

	return 0;
}

struct unit_test_suite lc_testsuite_sym = {
	.suite_name = "Liquid Crypto Symmetric Test Suite",
	.setup = testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		TEST_CASE_NAMED_WITH_DATA("AES-128-CBC Encrypt",
					  ut_setup, ut_teardown, test_block_cipher_only,
					  &aes_test_data_1),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};
