/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <string.h>

#include <rte_eal.h>

#include <dao_liquid_crypto.h>
#include <dao_log.h>

static struct dao_liquid_crypto_info liquid_crypto_info;

int
dao_liquid_crypto_init(void)
{
	memset(&liquid_crypto_info, 0, sizeof(liquid_crypto_info));

	/* Call eth TRS API
	 * - Get the count of eth devices
	 */

	/* Save the info here. */

	return 0;
}

int
dao_liquid_crypto_fini(void)
{
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
	/* Call eth TRS API
	 * - Create the eth device
	 * rte_eth_dev_configure()
	 * rte_eth_dev_adjust_nb_rx_tx_desc()
	 */

	RTE_SET_USED(dev_id);
	RTE_SET_USED(nb_qp);

	return -ENOTSUP;
}

int
dao_liquid_crypto_dev_destroy(uint8_t dev_id)
{
	/* Call eth TRS API
	 * - Destroy the eth device
	 * rte_eth_dev_close()
	 */

	RTE_SET_USED(dev_id);

	return -ENOTSUP;
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
