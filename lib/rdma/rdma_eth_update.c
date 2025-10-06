/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */
#include "dao_rdma_fp.h"
#include <dao_log.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <stdio.h>

/* Callback for rdma_map access (zero-initialized by default) */
rdma_map_cb_t g_rdma_map_cb;
void
dao_rdma_register_rdma_map_cb(rdma_map_cb_t cb)
{
	g_rdma_map_cb = cb;
}

int
dao_rdma_update_mtu(uint16_t port_id, uint16_t mtu)
{
	struct rte_eth_dev_info dev_info;
	int ret = 0;

	/* Validate port_id */
	if (port_id >= RTE_MAX_ETHPORTS) {
		dao_err("Invalid port_id %u\n", port_id);
		return -EINVAL;
	}

	/* Get the device info */
	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret != 0) {
		dao_err("Error getting device info: %s\n", strerror(-ret));
		return ret;
	}

	/* Check if the MTU is supported */
	if (mtu < dev_info.min_mtu || mtu > dev_info.max_mtu) {
		dao_err("MTU %u is not supported. Supported range: [%u, %u]\n", mtu,
			dev_info.min_mtu, dev_info.max_mtu);
		return -EINVAL;
	}

	dao_dbg("Updating MTU for port %u to %u", port_id, mtu);

	/* Stop the ethernet device before MTU update */
	ret = rte_eth_dev_stop(port_id);
	if (ret != 0) {
		dao_err("Error stopping device: %s\n", strerror(-ret));
		return ret;
	}

	/* Set the MTU */
	ret = rte_eth_dev_set_mtu(port_id, mtu);
	if (ret != 0) {
		dao_err("Error setting MTU: %s\n", strerror(-ret));
		/* Try to restart the device even if MTU setting failed */
		rte_eth_dev_start(port_id);
		return ret;
	}

	/* Start the ethernet device after MTU update */
	ret = rte_eth_dev_start(port_id);
	if (ret != 0) {
		dao_err("Error starting device: %s\n", strerror(-ret));
		return ret;
	}

	dao_info("Successfully updated MTU for port %u to %u", port_id, mtu);

	return 0;
}
