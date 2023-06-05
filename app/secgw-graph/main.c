/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <nodes/node_priv.h>

#define SECGW_MEMPOOL_CACHE_SIZE        256

#define SECGW_RXQ_NUM_DESC              2048
#define SECGW_TXQ_NUM_DESC              2048

/* To support at least 8 ports */
#define SECGW_MEMPOOL_NUM_MBUFS         (SECGW_RXQ_NUM_DESC * 8)

static int
start_devices(void)
{
	struct dao_ds dev_str = DS_EMPTY_INITIALIZER;
	char link_status[RTE_ETH_LINK_MAX_STR_LEN];
	secgw_device_t *sdev = NULL;
	dao_portq_group_t edpg;
	struct rte_eth_link link;
	dao_port_t port;
	int iter;

	if (dao_port_group_get_by_name(SECGW_ETHDEV_PORT_GROUP_NAME, &edpg) < 0)
		return -1;

	DAO_PORT_GROUP_FOREACH_PORT(edpg, port, iter) {
		sdev = secgw_get_device(port);

		rte_eth_dev_start(sdev->dp_port_id);
		rte_eth_promiscuous_enable(sdev->dp_port_id);
		rte_eth_dev_set_link_up(sdev->dp_port_id);
		dao_info("started device: %s", sdev->dev_name);
	}

	if (dao_port_group_get_by_name(SECGW_TAP_PORT_GROUP_NAME, &edpg) < 0)
		return -1;

	DAO_PORT_GROUP_FOREACH_PORT(edpg, port, iter) {
		sdev = secgw_get_device(port);

		rte_eth_dev_start(sdev->dp_port_id);
		rte_eth_promiscuous_enable(sdev->dp_port_id);
		rte_eth_dev_set_link_up(sdev->dp_port_id);
		dao_info("started device: %s", sdev->dev_name);
	}
	for (iter = 0; iter < secgw_num_devices_get(); iter++) {
		sdev = secgw_get_device(iter);
		dao_ds_put_cstr(&dev_str, sdev->dev_name);
		rte_eth_link_get(sdev->dp_port_id, &link);
		dao_ds_put_cstr(&dev_str, " LINK: ");
		rte_eth_link_to_str(link_status, sizeof(link_status), &link);
		dao_ds_put_cstr(&dev_str, link_status);
		if (rte_eth_promiscuous_get(sdev->dp_port_id))
			dao_ds_put_cstr(&dev_str, ", Promisc: ON ");
		else
			dao_ds_put_cstr(&dev_str, ", Promisc: OFF ");

		dao_info("%s", dao_ds_cstr(&dev_str));
		dao_ds_clear(&dev_str);
	}
	dao_ds_destroy(&dev_str);

	return 0;
}

static int
connect_interface_output_next_nodes(void)
{
	secgw_device_t *sdev = NULL;
	int iter;

	for (iter = 0; iter < secgw_num_devices_get(); iter++) {
		sdev = secgw_get_device(iter);
		/* Add only that device tx node which has valid tx_node set
		 */
		if (sdev->tx_node)
			secgw_node_interface_out_attach_tx_node(sdev, sdev->tx_node);
	}

	return 0;
}

/* Register all devices aka ethdevs, taps, virtio, etc */
static int
register_devices(void)
{
	secgw_device_main_t *sdm = secgw_get_device_main();
	secgw_device_register_conf_t dev_reg_conf = {0};
	uint16_t iter = 0, total_devices;
	struct rte_eth_dev_info devinfo;
	secgw_device_t *sdev = NULL;

	total_devices = rte_eth_dev_count_avail();
	dao_dbg("Total available devices: %d detected", total_devices);

	if (total_devices < 1) {
		dao_err("No valid ethdev detected");
		return -1;
	}

	dev_reg_conf.num_rx_desc = SECGW_RXQ_NUM_DESC;
	dev_reg_conf.num_tx_desc = SECGW_TXQ_NUM_DESC;
	dev_reg_conf.total_devices = total_devices;
	dev_reg_conf.num_workers = dao_workers_num_workers_get();

	/** Check how many physical and tap devices present */
	RTE_ETH_FOREACH_DEV(iter) {
		if (!rte_eth_dev_is_valid_port(iter))
			continue;

		memset(&devinfo, 0, sizeof(struct rte_eth_dev_info));

		rte_eth_dev_info_get(iter, &devinfo);

		/* See if room present to new device */
		if (secgw_num_devices_get() >= (sdm->max_num_devices_allocated - 1)) {
			sdm->devices = realloc(sdm->devices, (sizeof(secgw_device_t) *
							      (sdm->max_num_devices_allocated +
							       SECGW_REALLOC_NUM)));
			if (!sdm->devices) {
				dao_err("realloc fails");
				return -1;
			}
			sdm->max_num_devices_allocated += SECGW_REALLOC_NUM;
		}
		dev_reg_conf.dp_port_id = iter;
		dev_reg_conf.device_index = secgw_num_devices_get();

		if (strstr(devinfo.driver_name, "tap")) {
			dev_reg_conf.name = (const char *)SECGW_TAP_PORT_GROUP_NAME;
			/*
			 * tap driver insist to have equal number of rxqs and txqs
			 * So no tap queue for Main-core for now
			 */
			dev_reg_conf.num_rx_queues = dao_workers_num_workers_get();
			dev_reg_conf.num_tx_queues = dao_workers_num_workers_get();
			if (secgw_register_tap(&sdm->devices[secgw_num_devices_get()],
					       &dev_reg_conf) < 0) {
				dao_err("secgw_register_tap failed");
				continue;
			}
		} else {
			dev_reg_conf.name = (const char *)SECGW_ETHDEV_PORT_GROUP_NAME;
			dev_reg_conf.num_rx_queues = dao_workers_num_workers_get();
			dev_reg_conf.num_tx_queues = dao_workers_num_workers_get();
			if (secgw_register_ethdev(&sdm->devices[sdm->n_devices],
						  &dev_reg_conf) < 0) {
				dao_err("secgw_register_ethdev failed");
				continue;
			}
		}
		sdm->n_devices++;
		sdev = secgw_get_device(dev_reg_conf.device_index);
		dao_info("Added device: %s at index: %u, port_index: %d, port_id: %u",
			 sdev->dev_name, sdev->device_index, sdev->port_index,
			 sdev->dp_port_id);
	}

	return (secgw_num_devices_get());
}

static int
pair_tap_to_ethdev(void)
{
	dao_portq_group_t edpg, tdpg;
	secgw_device_t *sdev = NULL;
	uint32_t n_ethdev, n_tapdev;
	uint32_t n_common;
	dao_port_t port;
	int32_t iter, i;

	if (dao_port_group_get_by_name(SECGW_ETHDEV_PORT_GROUP_NAME, &edpg) < 0)
		return -1;

	if (dao_port_group_get_by_name(SECGW_TAP_PORT_GROUP_NAME, &tdpg) < 0)
		return -1;

	RTE_VERIFY(!dao_port_group_port_get_num(edpg, &n_ethdev));
	RTE_VERIFY(!dao_port_group_port_get_num(tdpg, &n_tapdev));

	n_common = RTE_MIN(n_ethdev, n_tapdev);

	if (!n_common) {
		dao_err("No pairing possible [n_tapdev: %u, n_ethdev: %u]", n_tapdev, n_ethdev);
		return -1;
	}

	/* Pair ethdevs to tap */
	if (n_ethdev >= n_tapdev) {
		int32_t ports[n_ethdev];

		i = 0;
		DAO_PORT_GROUP_FOREACH_PORT(edpg, port, iter) {
			ports[i++] = port;
		}
		i = 0;
		DAO_PORT_GROUP_FOREACH_PORT(tdpg, port, iter) {
			sdev = secgw_get_device(port);
			sdev->paired_device_index = ports[i];
			dao_info("%s paired with %s", sdev->dev_name,
				 (secgw_get_device(sdev->paired_device_index))->dev_name);

			/* Add tap to portq for node polling */
			secgw_register_active_tap(sdev, dao_workers_num_workers_get());

			sdev = secgw_get_device(ports[i]);
			sdev->paired_device_index = port;
			dao_info("%s paired with %s", sdev->dev_name,
				 (secgw_get_device(sdev->paired_device_index))->dev_name);
			i++;
		}
	} else {
		int32_t ports[n_tapdev];

		i = 0;
		DAO_PORT_GROUP_FOREACH_PORT(tdpg, port, iter) {
			ports[i++] = port;
		}
		i = 0;
		DAO_PORT_GROUP_FOREACH_PORT(edpg, port, iter) {
			sdev = secgw_get_device(port);
			sdev->paired_device_index = ports[i];
			dao_info("%s paired with %s", sdev->dev_name,
				 (secgw_get_device(sdev->paired_device_index))->dev_name);

			sdev = secgw_get_device(ports[i]);
			sdev->paired_device_index = port;
			dao_info("%s paired with %s", sdev->dev_name,
				 (secgw_get_device(sdev->paired_device_index))->dev_name);
			/* Add tap to portq for node polling */
			secgw_register_active_tap(sdev, dao_workers_num_workers_get());
			i++;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	secgw_numa_id_t *numa = NULL;
	secgw_main_t *sm = NULL;
	char name[256];
	int rc;

	rc = secgw_main_init(argc, argv, sizeof(secgw_worker_t));
	if (rc < 0)
		DAO_ERR_GOTO(rc, error, "rte_eal_init_failed: %s", argv[0]);

	if (dao_workers_num_workers_get() < 1) {
		dao_err("Launch app on more cores, found %d workers",
			dao_workers_num_workers_get());
		return -1;
	}

	sm = secgw_get_main();

	/* Create Mempool for each socket/numa id */
	STAILQ_FOREACH(numa, &sm->secgw_main_numa_list, next_numa_id) {
		snprintf(name, sizeof(name), "%s-%s-%d", "mempool", "numa", numa->numa_id);

		numa->user_arg = NULL;
		numa->user_arg = (void *)rte_pktmbuf_pool_create(name, SECGW_MEMPOOL_NUM_MBUFS,
								 SECGW_MEMPOOL_CACHE_SIZE,
								 RTE_CACHE_LINE_SIZE,
								 RTE_MBUF_DEFAULT_BUF_SIZE,
								 numa->numa_id);

		if (!numa->user_arg)
			DAO_ERR_GOTO(ENOMEM, error, "rte_mempool fails for %s", name);

		dao_info("Created packet mempool: %s", name);
	}

	if (register_devices() <= 0)
		DAO_ERR_GOTO(EINVAL, error, "No device found in secgw_register_ethdevs()");

	pair_tap_to_ethdev();

	/* Connect next node edges from interface-outout node to all active tx-nodes */
	connect_interface_output_next_nodes();

	start_devices();

	if (dao_netlink_xfrm_notifier_register(&secgw_xfrm_ops, NULL) < 0)
		DAO_ERR_GOTO(EINVAL, error, "dao xfrm netlink register failed");

	if (dao_netlink_route_notifier_register(&secgw_route_ops, SECGW_TAP_PORT_GROUP_NAME) < 0)
		DAO_ERR_GOTO(EINVAL, error, "dao route table notifier failed");

	dao_dbg("Launching threads");
	sm = secgw_get_main();

	rte_eal_mp_remote_launch(secgw_thread_cb, sm, CALL_MAIN);

	return 0;

error:
	secgw_main_exit();
	return rc;
}
