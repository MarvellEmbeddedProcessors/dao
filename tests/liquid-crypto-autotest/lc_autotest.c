/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>
#include <inttypes.h>
#include <string.h>

#include <rte_eal.h>

#include <dao_liquid_crypto.h>

#include "lc_autotest.h"
#include "lc_test_generic.h"
#include "test.h"

int
main(int argc, char **argv)
{
	struct dao_lc_qp_conf conf;
	struct dao_lc_info info;
	uint16_t qp_id;
	uint8_t dev_id;
	int ret;

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

	memset(&info, 0, sizeof(info));

	ret = dao_liquid_crypto_info_get(&info);
	if (ret < 0) {
		TEST_LC_ERR("Could not get liquid crypto information");
		goto fini;
	}

	if (info.nb_dev == 0) {
		TEST_LC_ERR("No liquid crypto devices found");
		ret = -1;
		goto fini;
	}

	if (info.nb_qp[0] == 0) {
		TEST_LC_ERR("No queue pairs found for device 0");
		ret = -1;
		goto fini;
	}

	TEST_LC_INFO("Liquid crypto version: %s", info.version);
	TEST_LC_INFO("Number of liquid crypto devices: %u", info.nb_dev);

	/* Use dev_id = 0 & qp_id = 0 for tests. */
	dev_id = 0;
	qp_id = 0;

	glb_params.dev_id = dev_id;
	glb_params.qp_id = qp_id;

	ret = dao_liquid_crypto_dev_create(dev_id, 1);
	if (ret < 0) {
		TEST_LC_ERR("Could not create liquid crypto device");
		goto fini;
	}

	memset(&conf, 0, sizeof(conf));

	conf.nb_desc = 2048;
	conf.out_of_order_delivery_en = false;
	conf.max_seg_size = 2048;

	ret = dao_liquid_crypto_qp_configure(dev_id, qp_id, &conf);
	if (ret < 0) {
		TEST_LC_ERR("Could not configure liquid crypto queue pair");
		goto dev_destroy;
	}

	ret = dao_liquid_crypto_dev_start(dev_id);
	if (ret < 0) {
		TEST_LC_ERR("Could not start liquid crypto device");
		goto dev_destroy;
	}

	unit_test_suite_runner(&lc_testsuite_generic);

	dao_liquid_crypto_dev_stop(dev_id);

dev_destroy:
	dao_liquid_crypto_dev_destroy(dev_id);
fini:
	dao_liquid_crypto_fini();

eal_cleanup:
	rte_eal_cleanup();

	return ret;
}
