/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <stdint.h>

#include <rte_common.h>

#include <dao_virtio_cryptodev.h>

int
dao_virtio_cryptodev_init(uint16_t devid, struct dao_virtio_cryptodev_conf *conf)
{
	RTE_SET_USED(devid);
	RTE_SET_USED(conf);

	return 0;
}

int
dao_virtio_cryptodev_fini(uint16_t devid)
{
	RTE_SET_USED(devid);
	return 0;
}
