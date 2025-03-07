/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>
#include <inttypes.h>
#include <string.h>

#include <rte_eal.h>

#include <dao_liquid_crypto.h>

#include "lc_autotest.h"
#include "lc_test_asym.h"
#include "lc_test_generic.h"
#include "test.h"

struct unit_test_suite *test_suites[] = {
	&lc_testsuite_generic,
	&lc_testsuite_asym,
	NULL
};

static struct unit_test_suite ts = {
	.suite_name = "Liquid Crypto Unit Test Suite",
	.setup = testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {TEST_CASES_END()},
	.unit_test_suites = test_suites
};

int
main(int argc, char **argv)
{
	struct dao_lc_dev_conf dev_conf;
	struct dao_lc_qp_conf qp_conf;
	struct dao_lc_info *info;
	uint16_t qp_id;
	uint8_t dev_id;
	int ret, i;

	TEST_LC_INFO("Starting liquid crypto autotest");

	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		TEST_LC_ERR("Could not initialize EAL");
		return ret;
	}

	argc += ret;
	argv += ret;

	ret = dao_liquid_crypto_init();
	if (ret < 0) {
		TEST_LC_ERR("Could not initialize liquid crypto");
		goto eal_cleanup;
	}

	info = &glb_params.info;

	memset(info, 0, sizeof(*info));

	ret = dao_liquid_crypto_info_get(info);
	if (ret < 0) {
		TEST_LC_ERR("Could not get liquid crypto information");
		goto fini;
	}

	if (info->nb_dev == 0) {
		TEST_LC_ERR("No liquid crypto devices found");
		ret = -1;
		goto fini;
	}

	for (i = 0; i < info->nb_dev; i++) {
		if (info->nb_qp[i] != 0)
			break;
	}

	if (i == info->nb_dev) {
		TEST_LC_ERR("No queue pairs found for any device");
		ret = -ENODEV;
		goto fini;
	}

	glb_params.dev_id = i;
	glb_params.qp_id = 1;

	TEST_LC_INFO("Liquid crypto version: %s", info->version);
	TEST_LC_INFO("Number of liquid crypto devices: %u", info->nb_dev);
	for (dev_id = 0; dev_id < info->nb_dev; dev_id++) {
		TEST_LC_INFO("Number of queue pairs for device %u: %u", dev_id, info->nb_qp[i]);

		if (info->nb_qp[dev_id] == 0)
			continue;

		memset(&dev_conf, 0, sizeof(dev_conf));
		dev_conf.dev_id = dev_id;
		dev_conf.nb_qp = info->nb_qp[dev_id];
		dev_conf.cmd_qp_idx = 0;

		ret = dao_liquid_crypto_dev_create(&dev_conf);
		if (ret < 0) {
			TEST_LC_ERR("Could not create liquid crypto device");
			goto fini;
		}

		memset(&qp_conf, 0, sizeof(qp_conf));

		qp_conf.nb_desc = 2048;
		qp_conf.out_of_order_delivery_en = false;
		qp_conf.max_seg_size = TEST_LC_MAX_OUTPUT_LEN;

		for (qp_id = 0; qp_id < info->nb_qp[dev_id]; qp_id++) {
			ret = dao_liquid_crypto_qp_configure(dev_id, qp_id, &qp_conf);
			if (ret < 0) {
				TEST_LC_ERR("Could not configure liquid crypto queue pair");
				info->nb_qp[dev_id] = dev_id;
				goto dev_destroy;
			}
		}

		ret = dao_liquid_crypto_dev_start(dev_id);
		if (ret < 0) {
			TEST_LC_ERR("Could not start liquid crypto device");
			info->nb_qp[dev_id] = dev_id;
			goto dev_destroy;
		}
	}

	ret = unit_test_suite_runner(&ts);

	for (dev_id = 0; dev_id < info->nb_dev; dev_id++) {
		if (info->nb_qp[dev_id] == 0)
			continue;
		dao_liquid_crypto_dev_stop(dev_id);
	}

dev_destroy:
	for (dev_id = 0; dev_id < info->nb_dev; dev_id++) {
		if (info->nb_qp[dev_id] == 0)
			continue;
		dao_liquid_crypto_dev_destroy(dev_id);
	}
fini:
	dao_liquid_crypto_fini();

eal_cleanup:
	rte_eal_cleanup();

	return ret;
}
