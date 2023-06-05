/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <errno.h>
#include <inttypes.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_graph_worker.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>

#include <dao_log.h>
#include <dao_util.h>
#include <dao_version.h>

#include <ood_graph.h>
#include <ood_init.h>
#include <ood_lcore.h>

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		dao_info("\n\nSignal %d received, preparing to exit...\n", signum);
		/* Intimating other party about the exit */
		ood_send_exit_message();
	}
}

static void
ood_cleanup(struct ood_main_cfg_data *ood_main_cfg, const struct rte_memzone *mz)
{
	DAO_FREE(ood_main_cfg->ctrl_chan_prm);
	DAO_FREE(ood_main_cfg->repr_prm);
	DAO_FREE(ood_main_cfg->graph_prm);
	DAO_FREE(ood_main_cfg->eth_prm);
	DAO_FREE(ood_main_cfg->cfg_prm);
	DAO_FREE(ood_main_cfg->lcore_prm);
	rte_memzone_free(mz);
}

static int
ood_mem_allocate(struct ood_main_cfg_data *ood_main_cfg)
{
	/* Allocate memory for lcore params */
	ood_main_cfg->lcore_prm = calloc(1, sizeof(ood_lcore_param_t));
	if (!ood_main_cfg->lcore_prm)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to alloc mem for lcore params");

	/* Allocate memory for config params */
	ood_main_cfg->cfg_prm = calloc(1, sizeof(ood_config_param_t));
	if (!ood_main_cfg->cfg_prm)
		DAO_ERR_GOTO(-ENOMEM, free_lcore, "Failed to alloc mem for config params");

	/* Allocate memory for ethdev params */
	ood_main_cfg->eth_prm = calloc(1, sizeof(ood_ethdev_param_t));
	if (!ood_main_cfg->eth_prm)
		DAO_ERR_GOTO(-ENOMEM, free_cfg, "Failed to alloc mem for ethdev params");

	/* Allocate memory for graph params */
	ood_main_cfg->graph_prm = calloc(1, sizeof(ood_graph_param_t));
	if (!ood_main_cfg->graph_prm)
		DAO_ERR_GOTO(-ENOMEM, free_eth, "Failed to alloc mem for graph params");

	/* Allocate memory for repr params */
	ood_main_cfg->repr_prm = calloc(1, sizeof(ood_repr_param_t));
	if (!ood_main_cfg->repr_prm)
		DAO_ERR_GOTO(-ENOMEM, free_gph, "Failed to alloc mem for repr params");

	/* Allocate memory for control channel params */
	ood_main_cfg->ctrl_chan_prm = calloc(1, sizeof(ood_ctrl_chan_param_t));
	if (!ood_main_cfg->ctrl_chan_prm)
		DAO_ERR_GOTO(-ENOMEM, free_repr, "Failed to alloc mem for repr params");

	return 0;
free_repr:
	DAO_FREE(ood_main_cfg->repr_prm);
free_gph:
	DAO_FREE(ood_main_cfg->graph_prm);
free_eth:
	DAO_FREE(ood_main_cfg->eth_prm);
free_cfg:
	DAO_FREE(ood_main_cfg->cfg_prm);
free_lcore:
	DAO_FREE(ood_main_cfg->lcore_prm);
fail:
	return errno;
}

static int
ood_main_loop(void *config)
{
	struct ood_main_cfg_data *ood_main_cfg = (struct ood_main_cfg_data *)config;
	uint16_t port_id, queue_id;
	struct lcore_conf *qconf;
	struct rte_graph *graph;
	uint32_t lcore_id;
	int queue = 0;

	RTE_SET_USED(config);
	lcore_id = rte_lcore_id();
	qconf = &ood_main_cfg->lcore_prm->lcore_conf[lcore_id];
	graph = qconf->graph;
	if (!graph) {
		dao_info("Lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	dao_dbg("Entering main loop on lcore %u, graph %s(%p)\n", lcore_id, qconf->name, graph);

	for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
		port_id = qconf->rx_queue_list[queue].port_id;
		queue_id = qconf->rx_queue_list[queue].queue_id;

		dao_info("Lcore %d port %d queue %d dest port %d", lcore_id, port_id, queue_id,
			 ood_ethdev_port_pair_get(ood_main_cfg->eth_prm->host_mac_map, port_id));
	}

	while (likely(!ood_main_cfg->force_quit))
		rte_graph_walk(graph);

	return 0;
}

static int
ovs_offload_launch_one_lcore(void *config)
{
	ood_main_loop(config);
	return 0;
}

/*
 * The main function, which does initialization and cleanup
 */
int
main(int argc, char *argv[])
{
	struct ood_main_cfg_data *ood_main_cfg;
	const struct rte_memzone *mz;
	uint16_t lcore_id, portid;
	struct lcore_conf *qconf;
	int rc;

	dao_info("ovs-offload application version %s", dao_version());

	/* Init EAL. */
	rc = rte_eal_init(argc, argv);
	if (rc < 0)
		DAO_ERR_GOTO(rc, error, "Invalid EAL arguments\n");

	argc -= rc;
	argv += rc;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Allocate global memory for storing all configurations and parameters */
	mz = rte_memzone_reserve_aligned(OOD_MAIN_CFG_MZ_NAME, sizeof(struct ood_main_cfg_data),
					 0, 0, RTE_CACHE_LINE_SIZE);
	if (!mz)
		DAO_ERR_GOTO(-ENOMEM, error, "Failed to reserve mem for main_cfg");

	ood_main_cfg = mz->addr;

	rc = ood_mem_allocate(ood_main_cfg);
	if (rc)
		goto fail;

	ood_main_cfg->force_quit = false;

	/* parse application arguments (after the EAL ones) */
	rc = ood_parse_args(argc, argv, ood_main_cfg);
	if (rc < 0)
		DAO_ERR_GOTO(rc, fail, "Invalid ovs-offload arguments\n");

	dao_dbg("MAC updating %s", ood_main_cfg->cfg_prm->mac_updating ? "enabled" : "disabled");

	/* Setting up the repr port and queues */
	rc = ood_representor_eswitch_dev_init(ood_main_cfg);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to initialize repr client");

	/* Setting up the ethdev ports and queues */
	rc = ood_ethdev_init(ood_main_cfg);
	if (rc)
		DAO_ERR_GOTO(rc, close_repr, "Failed to initialize ethernet ports");

	/* Initialize control channel */
	ood_control_channel_init(ood_main_cfg);

	/* Setting up the ethdev ports and queues */
	rc = ood_graph_init(ood_main_cfg);
	if (rc)
		DAO_ERR_GOTO(rc, close_eth, "Failed to setup graphs");

	/* Accumulate and print stats on main until exit */
	if (ood_main_cfg->cfg_prm->enable_graph_stats && rte_graph_has_stats_feature())
		ood_graph_print_stats(ood_main_cfg);

	rc = 0;
	dao_info("\nLaunching worker loops....\n");
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(ovs_offload_launch_one_lcore, ood_main_cfg, CALL_MAIN);

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		rc = rte_eal_wait_lcore(lcore_id);
		/* Destroy graph */
		qconf = &ood_main_cfg->lcore_prm->lcore_conf[lcore_id];
		if (rc < 0 || rte_graph_destroy(rte_graph_from_name(qconf[lcore_id].name))) {
			rc = -1;
			break;
		}
	}

	/* Wait for the graph stats thread completion */
	if (ood_main_cfg->cfg_prm->enable_graph_stats && rte_graph_has_stats_feature())
		rte_thread_join(ood_main_cfg->graph_prm->graph_stats_thread, NULL);

	/* Wait for control channel thread to complete */
	rte_thread_join(ood_main_cfg->ctrl_chan_prm->ctrl_chan_thrd, NULL);
close_eth:
	RTE_ETH_FOREACH_DEV(portid) {
		if (portid == ood_main_cfg->repr_prm->portid)
			continue;
		dao_info("Closing port %d...", portid);
		rc = rte_eth_dev_stop(portid);
		if (rc != 0)
			dao_info("rte_eth_dev_stop: err=%d, port=%d\n", rc, portid);
		dao_info(" Done\n");
	}

close_repr:
	portid = ood_main_cfg->repr_prm->portid;
	rc = rte_eth_dev_stop(portid);
	if (rc != 0)
		dao_info("rte_eth_dev_stop: err=%d, port=%d\n", rc, portid);
fail:
	ood_cleanup(ood_main_cfg, mz);

	/* clean up the EAL */
	rte_eal_cleanup();

error:
	return rc;
}
