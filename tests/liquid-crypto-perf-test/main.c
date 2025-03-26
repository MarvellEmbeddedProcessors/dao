/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <dao_liquid_crypto.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_log.h>

#include "lcperf.h"
#include "lcperf_options.h"
#include "lcperf_test_throughput.h"

/* Maximum length of output buffer */
#define LCPERF_MAX_OUTPUT_LEN 5120

#define LCPERF_MAX_DEVS 1

const char *lcperf_test_type_strs[] = {
	[LCPERF_TEST_TYPE_THROUGHPUT] = "throughput",
};

const char *lcperf_op_type_strs[] = {
	[LCPERF_OP_PASSTHROUGH] = "passthrough",
	[LCPERF_OP_ASYM_RSA] = "rsa",
};

const char *lcperf_crypto_asym_op_type_strs[] = {
	[LCPERF_CRYPTO_ASYM_OP_PUB_ENCRYPT] = "pub-encrypt",
	[LCPERF_CRYPTO_ASYM_OP_PUB_DECRYPT] = "pub-decrypt",
	[LCPERF_CRYPTO_ASYM_OP_PRV_ENCRYPT] = "prv-encrypt",
	[LCPERF_CRYPTO_ASYM_OP_PRV_DECRYPT] = "prv-decrypt",
};

const char *lcperf_rsa_priv_keytype_strs[] = {
	[LCPERF_RSA_KEY_TYPE_EXP] = "exp",
	[LCPERF_RSA_KEY_TYPE_QT] = "crt",
};

const struct lcperf_test lcperf_testmap[] = {
	[LCPERF_TEST_TYPE_THROUGHPUT] = {lcperf_throughput_test_constructor,
					 lcperf_throughput_test_runner,
					 lcperf_throughput_test_destructor},
};

static int
lcperf_initialize_liquid_crypto(struct lcperf_options *opts, uint8_t *enabled_cdevs)
{
	uint8_t enabled_cdev_count = 0, nb_lcores, cdev_id;
	struct dao_lc_qp_conf qp_conf;
	struct dao_lc_dev_conf dev_conf;
	struct dao_lc_info info;
	unsigned int i, j;
	int ret;

	ret = dao_liquid_crypto_init();
	if (ret < 0) {
		RTE_LOG(ERR, USER1, "Could not initialize liquid crypto\n");
		return -EINVAL;
	}

	memset(&info, 0, sizeof(info));

	ret = dao_liquid_crypto_info_get(&info);
	if (ret < 0) {
		RTE_LOG(ERR, USER1, "Could not get liquid crypto information\n");
		goto fini;
	}

	if (info.nb_dev == 0) {
		RTE_LOG(ERR, USER1, "No liquid crypto devices found\n");
		return -EINVAL;
	}

	enabled_cdev_count = info.nb_dev;

	nb_lcores = rte_lcore_count() - 1;

	if (nb_lcores < 1) {
		RTE_LOG(ERR, USER1, "Number of enabled cores need to be higher than 1\n");
		return -EINVAL;
	}

	/*
	 * Use less number of devices,
	 * if there are more available than cores.
	 */
	if (enabled_cdev_count > nb_lcores)
		enabled_cdev_count = nb_lcores;

	/*
	 * Calculate number of needed queue pairs, based on the amount
	 * of available number of logical cores and liquid crypto devices.
	 * For instance, if there are 4 cores and 2 devices,
	 * 2 queue pairs will be set up per device.
	 */
	opts->nb_qps = (nb_lcores % enabled_cdev_count) ? (nb_lcores / enabled_cdev_count) + 1 :
							  nb_lcores / enabled_cdev_count;

	/* Add one more queue pair for the command queue */
	opts->nb_qps += 1;

	for (i = 0; i < enabled_cdev_count && i < LCPERF_MAX_DEVS; i++) {
		cdev_id = enabled_cdevs[i];

		if (opts->nb_qps > info.nb_qp[cdev_id]) {
			printf("Number of needed queue pairs is higher "
			       "than the maximum number of queue pairs "
			       "per device.\n");
			printf("Lower the number of cores or increase "
			       "the number of liquid crypto devices\n");
			return -EINVAL;
		}

		memset(&dev_conf, 0, sizeof(dev_conf));
		dev_conf.dev_id = cdev_id;
		dev_conf.nb_qp = opts->nb_qps;
		dev_conf.cmd_qp_idx = opts->nb_qps - 1;

		ret = dao_liquid_crypto_dev_create(&dev_conf);
		if (ret < 0) {
			printf("Failed to create liquid crypto device %u", cdev_id);
			goto fini;
		}

		memset(&qp_conf, 0, sizeof(qp_conf));

		qp_conf.nb_desc = opts->nb_descriptors;
		qp_conf.out_of_order_delivery_en = false;
		qp_conf.max_seg_size = LCPERF_MAX_OUTPUT_LEN;

		for (j = 0; j < opts->nb_qps; j++) {
			ret = dao_liquid_crypto_qp_configure(cdev_id, j, &qp_conf);
			if (ret < 0) {
				printf("Failed to setup queue pair %u on "
				       "liquid crypto device %u",
				       j, cdev_id);
				goto dev_destroy;
			}
		}

		ret = dao_liquid_crypto_dev_start(cdev_id);
		if (ret < 0) {
			printf("Failed to start device %u: error %d\n", cdev_id, ret);
			goto dev_destroy;
		}
	}

	return enabled_cdev_count;
dev_destroy:
	for (i = 0; i < enabled_cdev_count && i < LCPERF_MAX_DEVS; i++) {
		cdev_id = enabled_cdevs[i];
		dao_liquid_crypto_dev_destroy(i);
	}
fini:
	dao_liquid_crypto_fini();
	return -EINVAL;
}

int
main(int argc, char **argv)
{
	uint8_t enabled_cdevs[LCPERF_MAX_DEVS] = {0};
	uint8_t qp_id = 0, cdev_index = 0;
	struct lcperf_options opts = {0};
	void *ctx[RTE_MAX_LCORE] = {};
	struct lcperf_op_fns op_fns;
	uint16_t total_nb_qps = 0;
	uint8_t cdev_id, i;
	int nb_lcdevs = 0;
	uint32_t lcore_id;
	int ret;

	/* Initialise DPDK EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments!\n");
	argc -= ret;
	argv += ret;

	lcperf_options_default(&opts);

	ret = lcperf_options_parse(&opts, argc, argv);
	if (ret) {
		RTE_LOG(ERR, USER1, "Parsing one or more user options failed\n");
		goto err;
	}
	ret = lcperf_options_check(&opts);
	if (ret) {
		RTE_LOG(ERR, USER1, "Checking one or more user options failed\n");
		goto err;
	}

	nb_lcdevs = lcperf_initialize_liquid_crypto(&opts, enabled_cdevs);

	if (nb_lcdevs < 1) {
		RTE_LOG(ERR, USER1,
			"Failed to initialise requested crypto "
			"device type\n");
		nb_lcdevs = 0;
		goto err;
	}

	lcperf_options_dump(&opts);

	ret = lcperf_get_op_functions(&opts, &op_fns);
	if (ret) {
		RTE_LOG(ERR, USER1,
			"Failed to find function ops set for "
			"specified algorithms combination\n");
		goto err;
	}

	total_nb_qps = nb_lcdevs * opts.nb_qps;

	i = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (i == total_nb_qps)
			break;

		cdev_id = enabled_cdevs[cdev_index];

		ctx[i] = lcperf_testmap[opts.test].constructor(cdev_id, qp_id, &opts, &op_fns);
		if (ctx[i] == NULL) {
			RTE_LOG(ERR, USER1, "Test run constructor failed\n");
			goto err;
		}

		qp_id = (qp_id + 1) % opts.nb_qps;
		if (qp_id == 0)
			cdev_index++;
		i++;
	}

	opts.test_buffer_size = opts.buffer_size_list[0];

	i = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (i == total_nb_qps)
			break;

		rte_eal_remote_launch(lcperf_testmap[opts.test].runner, ctx[i], lcore_id);
		i++;
	}
	i = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (i == total_nb_qps)
			break;
		ret |= rte_eal_wait_lcore(lcore_id);
		i++;
	}

	i = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (i == total_nb_qps)
			break;

		lcperf_testmap[opts.test].destructor(ctx[i]);
		i++;
	}

	for (i = 0; i < nb_lcdevs && i < LCPERF_MAX_DEVS; i++) {
		dao_liquid_crypto_dev_stop(i);
		dao_liquid_crypto_dev_destroy(i);
	}

	dao_liquid_crypto_fini();
	printf("\n");

	return EXIT_SUCCESS;

err:
	i = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (i == total_nb_qps)
			break;

		if (ctx[i] && lcperf_testmap[opts.test].destructor)
			lcperf_testmap[opts.test].destructor(ctx[i]);
		i++;
	}

	for (i = 0; i < nb_lcdevs && i < LCPERF_MAX_DEVS; i++) {
		dao_liquid_crypto_dev_stop(i);
		dao_liquid_crypto_dev_destroy(i);
	}

	dao_liquid_crypto_fini();
	printf("\n");

	return EXIT_FAILURE;
}
