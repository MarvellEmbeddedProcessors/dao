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

struct lcore_qp_mapping {
	uint8_t cdev_id;
	uint16_t qp_id;
};

static struct lcore_qp_mapping lcore_qp_map[RTE_MAX_LCORE];

static int
lcperf_initialize_liquid_crypto(struct lcperf_options *opts)
{
	uint8_t enabled_cdev_count, nb_lcores, cdev_id, required_cdev_cnt, lcore_id;
	uint16_t qp_id, required_qp_cnt;
	struct dao_lc_dev_conf dev_conf;
	struct dao_lc_qp_conf qp_conf;
	bool is_cmd_qp_reqd = false;
	struct dao_lc_info info;
	unsigned int j;
	int ret;

	ret = dao_liquid_crypto_init();
	if (ret < 0) {
		RTE_LOG(ERR, USER1, "Could not initialize liquid crypto\n");
		return 0;
	}

	memset(&info, 0, sizeof(info));

	ret = dao_liquid_crypto_info_get(&info);
	if (ret < 0) {
		RTE_LOG(ERR, USER1, "Could not get liquid crypto information\n");
		goto fini;
	}

	if (info.nb_dev == 0) {
		RTE_LOG(ERR, USER1, "No liquid crypto devices found\n");
		goto fini;
	}

	enabled_cdev_count = info.nb_dev;

	nb_lcores = rte_lcore_count() - 1;
	if (nb_lcores < 1) {
		RTE_LOG(ERR, USER1, "Number of enabled cores need to be higher than 1\n");
		goto fini;
	}

	required_qp_cnt = nb_lcores;

	required_cdev_cnt = 0;

	if (opts->op_type == LCPERF_OP_SYM)
		is_cmd_qp_reqd = true;

	/* Determine the number of 'qp's required per device */
	while (required_qp_cnt > 0 && required_cdev_cnt <= info.nb_dev) {
		/* If required, consider one queue per device for command queue */
		if (is_cmd_qp_reqd)
			required_qp_cnt++;

		/* Check if the device has more queues than required */
		if (required_qp_cnt < info.nb_qp[required_cdev_cnt]) {
			info.nb_qp[required_cdev_cnt] = required_qp_cnt;
			required_qp_cnt = 0;
			required_cdev_cnt++;
			break;
		}

		required_qp_cnt -= info.nb_qp[required_cdev_cnt];
		required_cdev_cnt++;
	}

	if (required_qp_cnt > 0) {
		RTE_LOG(ERR, USER1, "Not enough queue pairs available for the number of cores\n");
		RTE_LOG(ERR, USER1,
			"Increase the number of liquid crypto devices or decrease"
			" the number of cores\n");
		goto fini;
	}

	if (required_cdev_cnt > LCPERF_MAX_DEVS) {
		RTE_LOG(ERR, USER1,
			"Number of required devices is higher than the maximum "
			"number of devices supported by this test\n");
		goto fini;
	}

	if (required_cdev_cnt == 0) {
		RTE_LOG(ERR, USER1, "No liquid crypto devices available for the test\n");
		goto fini;
	}

	/* Populate lcore-qp mapping */

	cdev_id = 0;
	qp_id = 0;

	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		lcore_qp_map[lcore_id].cdev_id = cdev_id;
		lcore_qp_map[lcore_id].qp_id = qp_id;

		qp_id++;

		/* If command queue is required, do not use up all queues */
		if (is_cmd_qp_reqd && qp_id >= info.nb_qp[cdev_id] - 1) {
			cdev_id++;
			qp_id = 0;
		} else if (qp_id >= info.nb_qp[cdev_id]) {
			cdev_id++;
			qp_id = 0;
		}
	}

	/* Create and start liquid crypto devices */
	for (cdev_id = 0; cdev_id < required_cdev_cnt; cdev_id++) {
		memset(&dev_conf, 0, sizeof(dev_conf));
		dev_conf.dev_id = cdev_id;
		dev_conf.nb_qp = info.nb_qp[cdev_id];
		if (is_cmd_qp_reqd)
			dev_conf.cmd_qp_idx = info.nb_qp[cdev_id] - 1;
		else
			dev_conf.cmd_qp_idx = DAO_CMD_QP_IDX_INVALID;

		ret = dao_liquid_crypto_dev_create(&dev_conf);
		if (ret < 0) {
			printf("Failed to create liquid crypto device %u", cdev_id);
			goto dev_destroy;
		}

		memset(&qp_conf, 0, sizeof(qp_conf));

		qp_conf.nb_desc = opts->nb_descriptors;
		qp_conf.out_of_order_delivery_en = false;
		qp_conf.max_seg_size = LCPERF_MAX_OUTPUT_LEN;

		for (j = 0; j < info.nb_qp[cdev_id]; j++) {
			ret = dao_liquid_crypto_qp_configure(cdev_id, j, &qp_conf);
			if (ret < 0) {
				printf("Failed to setup queue pair %u on liquid crypto device %u",
				       j, cdev_id);
				dao_liquid_crypto_dev_destroy(cdev_id);
				goto dev_destroy;
			}
		}

		ret = dao_liquid_crypto_dev_start(cdev_id);
		if (ret < 0) {
			printf("Failed to start device %u: error %d\n", cdev_id, ret);
			dao_liquid_crypto_dev_destroy(cdev_id);
			goto dev_destroy;
		}
	}

	return enabled_cdev_count;

dev_destroy:
	while (cdev_id > 0) {
		cdev_id--;
		dao_liquid_crypto_dev_stop(cdev_id);
		dao_liquid_crypto_dev_destroy(cdev_id);
	}

fini:
	dao_liquid_crypto_fini();
	return 0;
}

int
main(int argc, char **argv)
{
	struct lcperf_options opts = {0};
	void *ctx[RTE_MAX_LCORE] = {};
	struct lcperf_op_fns op_fns;
	uint8_t cdev_id, i;
	int nb_lcdevs = 0;
	uint32_t lcore_id;
	uint16_t qp_id;
	int ret = 0;

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
		goto eal_cleanup;
	}

	ret = lcperf_options_check(&opts);
	if (ret) {
		RTE_LOG(ERR, USER1, "Checking one or more user options failed\n");
		goto eal_cleanup;
	}

	nb_lcdevs = lcperf_initialize_liquid_crypto(&opts);
	if (nb_lcdevs == 0) {
		RTE_LOG(ERR, USER1, "Failed to initialise liquid crypto device\n");
		nb_lcdevs = 0;
		goto eal_cleanup;
	}

	lcperf_options_dump(&opts);

	ret = lcperf_get_op_functions(&opts, &op_fns);
	if (ret) {
		RTE_LOG(ERR, USER1,
			"Failed to find function ops set for "
			"specified algorithms combination\n");
		goto dev_stop_destroy;
	}

	i = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		cdev_id = lcore_qp_map[lcore_id].cdev_id;
		qp_id = lcore_qp_map[lcore_id].qp_id;

		ctx[i] = lcperf_testmap[opts.test].constructor(cdev_id, qp_id, &opts, &op_fns);
		if (ctx[i] == NULL) {
			RTE_LOG(ERR, USER1, "Test run constructor failed\n");
			goto ctx_destructor;
		}
		i++;
	}

	opts.test_buffer_size = opts.buffer_size_list[0];

	i = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		rte_eal_remote_launch(lcperf_testmap[opts.test].runner, ctx[i], lcore_id);
		i++;
	}

	i = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		ret |= rte_eal_wait_lcore(lcore_id);
		i++;
	}

ctx_destructor:

	i = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (ctx[i] == NULL || lcperf_testmap[opts.test].destructor == NULL) {
			i++;
			continue;
		}

		lcperf_testmap[opts.test].destructor(ctx[i]);
		i++;
	}

dev_stop_destroy:
	for (i = 0; i < nb_lcdevs; i++) {
		dao_liquid_crypto_dev_stop(i);
		dao_liquid_crypto_dev_destroy(i);
	}

	dao_liquid_crypto_fini();
	printf("\n");

eal_cleanup:
	rte_eal_cleanup();

	if (ret)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
