/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <string.h>

#include <rte_eal.h>

#include <dao_eth_trs.h>
#include <dao_liquid_crypto.h>
#include <dao_log.h>

#include "liquid_crypto_priv.h"

static struct dao_liquid_crypto_info liquid_crypto_info;

static struct liquid_crypto_dev liquid_crypto_devs[DAO_CRYPTO_MAX_NB_DEV];

int
dao_liquid_crypto_init(void)
{
	struct dao_eth_trs_info trs_info;
	int rc, i;

	memset(&liquid_crypto_info, 0, sizeof(liquid_crypto_info));
	memset(liquid_crypto_devs, 0, sizeof(liquid_crypto_devs));

	rc = dao_eth_trs_init();
	if (rc != 0) {
		dao_err("Could not initialize ethernet transport.");
		return rc;
	}

	rc = dao_eth_trs_info(&trs_info);
	if (rc != 0) {
		dao_err("Could not get ethernet transport information.");
		goto trs_fini;
	}

	if (trs_info.nb_devs > DAO_CRYPTO_MAX_NB_DEV) {
		dao_err("[Internal error] Number of devices exceeds the maximum supported.");
		rc = -EINVAL;
		goto trs_fini;
	}

	if (trs_info.nb_queues > LIQUID_CRYPTO_MAX_NB_QP) {
		dao_err("[Internal error] Number of queues exceeds the maximum supported.");
		rc = -EINVAL;
		goto trs_fini;
	}

	liquid_crypto_info.nb_dev = trs_info.nb_devs;

	for (i = 0; i < trs_info.nb_devs; i++)
		liquid_crypto_info.nb_qp[i] = trs_info.nb_queues;

	return 0;

trs_fini:
	dao_eth_trs_fini();
	return rc;
}

int
dao_liquid_crypto_fini(void)
{
	int i, rc;

	for (i = 0; i < liquid_crypto_info.nb_dev; i++) {
		if (liquid_crypto_devs[i].is_created)
			dao_liquid_crypto_dev_destroy(i);
	}

	rc = dao_eth_trs_fini();
	if (rc != 0) {
		dao_err("Could not finalize ethernet transport.");
		return rc;
	}

	memset(liquid_crypto_devs, 0, sizeof(liquid_crypto_devs));
	memset(&liquid_crypto_info, 0, sizeof(liquid_crypto_info));

	return 0;
}

int
dao_liquid_crypto_info_get(struct dao_liquid_crypto_info *info)
{
	if (info == NULL) {
		dao_err("Invalid argument.");
		return -EINVAL;
	}

	memcpy(info, &liquid_crypto_info, sizeof(liquid_crypto_info));

	return 0;
}

int
dao_liquid_crypto_dev_create(uint8_t dev_id, uint16_t nb_qp)
{
	struct dao_eth_trs_dev_config trs_conf;
	struct liquid_crypto_dev *dev;
	int rc;

	if (dev_id >= liquid_crypto_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.",
			liquid_crypto_info.nb_dev - 1);
		return -EINVAL;
	}

	if (nb_qp == 0 || nb_qp > liquid_crypto_info.nb_qp[dev_id]) {
		dao_err("Invalid argument. nb_qp must be between 1 and %u.",
			liquid_crypto_info.nb_qp[dev_id]);
		return -EINVAL;
	}

	dev = &liquid_crypto_devs[dev_id];

	if (dev->is_created) {
		dao_err("Device already created.");
		return -EEXIST;
	}

	dev->nb_qp = nb_qp;

	trs_conf.nb_queues = nb_qp;
	trs_conf.promiscuous = 1;

	rc = dao_eth_trs_dev_alloc(dev_id, &trs_conf);
	if (rc != 0) {
		dao_err("Could not allocate ethernet transport device.");
		return rc;
	}

	dev->is_created = true;

	return 0;
}

int
dao_liquid_crypto_dev_destroy(uint8_t dev_id)
{
	struct liquid_crypto_dev *dev;
	int rc;

	if (dev_id >= liquid_crypto_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.",
			liquid_crypto_info.nb_dev - 1);
		return -EINVAL;
	}

	rc = dao_eth_trs_dev_free(dev_id);
	if (rc != 0) {
		dao_err("Could not free ethernet transport device.");
		return rc;
	}

	dev = &liquid_crypto_devs[dev_id];

	memset(dev, 0, sizeof(*dev));

	return 0;
}

int
dao_liquid_crypto_qp_configure(uint8_t dev_id, uint16_t qp_id,
			       struct dao_liquid_crypto_qp_conf *conf)

{
	/* Create mempool etc */

	/* Call eth TRS API
	 * - Configure the eth queue pair
	 * rte_eth_rx_queue_setup()
	 * rte_eth_tx_queue_setup()
	 */

	RTE_SET_USED(dev_id);
	RTE_SET_USED(qp_id);
	RTE_SET_USED(conf);

	return -ENOTSUP;
}

int
dao_liquid_crypto_dev_start(uint8_t dev_id)
{
	/* Call eth TRS API
	 * - Start the eth device
	 * rte_eth_promiscuous_enable()
	 * rte_eth_dev_start()
	 * rte_eth_link_get()
	 */

	RTE_SET_USED(dev_id);

	return -ENOTSUP;
}

int
dao_liquid_crypto_dev_stop(uint8_t dev_id)
{
	/* Call eth TRS API
	 * - Stop the eth device
	 * rte_eth_dev_stop()
	 */

	RTE_SET_USED(dev_id);

	return -ENOTSUP;
}

int
dao_liquid_crypto_enqueue_op_passthrough(uint8_t dev_id, uint16_t qp_id, uint64_t op_cookie)
{
	/* Call eth TRS API
	 * - Enqueue the operation
	 * rte_eth_tx_burst()
	 */

	RTE_SET_USED(dev_id);
	RTE_SET_USED(qp_id);
	RTE_SET_USED(op_cookie);

	return -ENOTSUP;
}

uint16_t
dao_liquid_crypto_dequeue_burst(uint8_t dev_id, uint16_t qp_id, struct dao_crypto_res *res,
				uint16_t nb_res)
{
	/* Call eth TRS API
	 * - Dequeue the operation
	 * rte_eth_rx_burst()
	 */

	RTE_SET_USED(dev_id);
	RTE_SET_USED(qp_id);
	RTE_SET_USED(res);
	RTE_SET_USED(nb_res);

	return 0;
}
