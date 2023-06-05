/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <secgw.h>

secgw_main_t *__secgw_main;

static void
secgw_signal_handler(int signum)
{
	secgw_main_t *em = secgw_get_main();

	if (!em)
		return;

	switch (signum) {
	case SIGINT:
		dao_err("\n\nSIGINT received. Exiting...");
	break;

	case SIGTERM:
		dao_err("\n\nSIGTERM received. Exiting...");
	break;

	default:
		dao_err("\n\nReceived signal: %d", signum);
	}

	em->datapath_exit_requested = 1;
}

int secgw_main_init(int argc, char **argv, size_t user_per_core_size)
{
	secgw_main_t *secgw_main  = NULL;
	secgw_numa_id_t *numa = NULL;
	uint64_t core_mask = 0;
	unsigned int i;
	int rc = -1;

	if (!__secgw_main) {
		rc = rte_eal_init(argc, argv);
		if (rc < 0)
			DAO_ERR_GOTO(rc, error, "rte_eal_init failed: %s", argv[9]);

		secgw_main = malloc(sizeof(secgw_main_t));
		if (!secgw_main)
			DAO_ERR_GOTO(ENOMEM, error, "secgw_main mem alloc failed");

		memset(secgw_main, 0, sizeof(secgw_main_t));

		/* Initialize NUMA list for socket-0 so that app can create memory
		 * Currently socket-id-0 is added, later it can be made generic
		 */
		STAILQ_INIT(&secgw_main->secgw_main_numa_list);
		numa = malloc(sizeof(*numa));
		if (!numa)
			DAO_ERR_GOTO(ENOMEM, freem, "secgw_socket_list mem alloc failed");

		memset(numa, 0, sizeof(*numa));
		numa->numa_id = 0; /* duplicate to memset */
		STAILQ_INSERT_TAIL(&secgw_main->secgw_main_numa_list, numa, next_numa_id);
		__secgw_main = secgw_main;
	} else {
		DAO_ERR_GOTO(EBUSY, error, "secgw_init() already done");
	}
	secgw_main = __secgw_main;

	if (secgw_main) {
		for (i = 0; i < RTE_MAX_LCORE; i++) {
			if (!rte_lcore_is_enabled(i))
				continue;
			core_mask |= RTE_BIT64(i);
		}
		if (dao_workers_init(core_mask, rte_get_main_lcore(), user_per_core_size) < 0) {
			dao_err("workers_main_init failed:  core_mask: 0x%lx, main: %u, app_sz: %lu",
				core_mask, rte_get_main_lcore(), user_per_core_size);
			return -1;
		}
		dao_dbg("Core_mask: 0x%lx, main_lcore: %u, app_sz: %lu",
			core_mask, rte_get_main_lcore(), user_per_core_size);
	}
	dao_dbg("secgw_init() successful");
	signal(SIGINT, secgw_signal_handler);
	signal(SIGTERM, secgw_signal_handler);

	return 0;
freem:
	if (numa)
		free(numa);

	if (secgw_main) {
		free(secgw_main);
		__secgw_main = NULL;
	}
error:
	return -1;
}

int secgw_main_exit(void)
{
	secgw_main_t *secgw_main = __secgw_main;
	secgw_device_main_t *sdm = NULL;
	secgw_numa_id_t *numa = NULL;
	secgw_device_t *sdev = NULL;
	int i;

	rte_eal_mp_wait_lcore();
	sdm = secgw_get_device_main();

	for (i = 0; sdm && i < sdm->n_devices; i++) {
		sdev = secgw_get_device(i);
		rte_eth_dev_set_link_down(sdev->dp_port_id);
		rte_eth_dev_stop(sdev->dp_port_id);
		rte_eth_dev_close(sdev->dp_port_id);
	}

	if (secgw_main) {
		while (!STAILQ_EMPTY(&secgw_main->secgw_main_numa_list)) {
			numa = STAILQ_FIRST(&secgw_main->secgw_main_numa_list);
			STAILQ_REMOVE_HEAD(&secgw_main->secgw_main_numa_list, next_numa_id);
			dao_dbg("numa: %d, user_arg: %p", numa->numa_id, numa->user_arg);
			free(numa);
		}

		dao_workers_fini();
		dao_netlink_cleanup();
		rte_eal_cleanup();
		dao_info("secgw_exit() successful");

		free(secgw_main);
		__secgw_main = NULL;

		return 0;
	}
	dao_err("Invalid secgw_exit() call");
	return -1;
}
