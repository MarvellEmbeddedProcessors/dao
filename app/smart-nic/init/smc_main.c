/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_graph_worker.h>
#include <rte_launch.h>

#include <dao_log.h>
#include <dao_util.h>
#include <dao_version.h>

#include <smc_config.h>
#include <smc_init.h>

static void
signal_handler(int signum)
{
	struct smc_main_cfg_data *cfg_data;
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		cfg_data = smc_main_cfg_handle();
		if (cfg_data)
			cfg_data->force_quit = true;
	}
}

bool
app_graph_stats_enabled(void)
{
	struct smc_main_cfg_data *cfg_data;

	cfg_data = smc_main_cfg_handle();
	return !!(cfg_data && cfg_data->cfg_prm && cfg_data->cfg_prm->enable_graph_stats);
}

bool
app_graph_exit(void)
{
	struct timeval tv;
	fd_set fds;
	int ret;
	char c;

	FD_ZERO(&fds);
	FD_SET(0, &fds);
	tv.tv_sec = 0;
	tv.tv_usec = 100;
	ret = select(1, &fds, NULL, NULL, &tv);
	if ((ret < 0 && errno == EINTR) || (ret == 1 && read(0, &c, 1) > 0))
		return true;
	else
		return false;
}

static void
smc_cleanup(struct smc_main_cfg_data *smc_main_cfg, const struct rte_memzone *mz)
{
	DAO_FREE(smc_main_cfg->cli_cfg.lcore_conf);
	DAO_FREE(smc_main_cfg->graph_prm);
	DAO_FREE(smc_main_cfg->cfg_prm);
	rte_memzone_free(mz);
}

static int
smc_mem_allocate(struct smc_main_cfg_data *smc_main_cfg)
{
	/* Allocate memory for config params */
	smc_main_cfg->cfg_prm = calloc(1, sizeof(smc_config_param_t));
	if (!smc_main_cfg->cfg_prm)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to alloc mem for config params");

	/* Allocate memory for lcore params */
	smc_main_cfg->cli_cfg.lcore_conf = calloc(1, RTE_MAX_LCORE * sizeof(struct lcore_conf));
	if (!smc_main_cfg->cli_cfg.lcore_conf)
		DAO_ERR_GOTO(-ENOMEM, free_cfg, "Failed to alloc mem for lcore params");

	/* Allocate memory for graph params */
	smc_main_cfg->graph_prm = calloc(1, sizeof(smc_graph_param_t));
	if (!smc_main_cfg->graph_prm)
		DAO_ERR_GOTO(-ENOMEM, free_cli_cfg, "Failed to alloc mem for graph params");

	return 0;
free_cli_cfg:
	DAO_FREE(smc_main_cfg->cli_cfg.lcore_conf);
free_cfg:
	DAO_FREE(smc_main_cfg->cfg_prm);
fail:
	return errno;
}

int
main(int argc, char **argv)
{
	struct smc_main_cfg_data *smc_main_cfg;
	struct smc_config_param *cfg_prm;
	const struct rte_memzone *mz;
	int rc;

	dao_info("smart-nic application version %s", dao_version());

	/* Init EAL. */
	rc = rte_eal_init(argc, argv);
	if (rc < 0)
		DAO_ERR_GOTO(rc, error, "Invalid EAL arguments\n");

	argc -= rc;
	argv += rc;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Allocate global memory for storing all configurations and parameters */
	mz = rte_memzone_reserve_aligned(SMC_MAIN_CFG_MZ_NAME, sizeof(struct smc_main_cfg_data), 0,
					 0, RTE_CACHE_LINE_SIZE);
	if (!mz)
		DAO_ERR_GOTO(-ENOMEM, error, "Failed to reserve mem for main_cfg");

	smc_main_cfg = mz->addr;

	rc = smc_mem_allocate(smc_main_cfg);
	if (rc)
		goto fail;

	smc_main_cfg->force_quit = false;

	cfg_prm = smc_main_cfg->cfg_prm;
	/* Populate default configurations */
	rc = smc_default_config(cfg_prm);
	if (rc < 0)
		DAO_ERR_GOTO(rc, fail, "Failed to populate default configurations");

	/* Parse application arguments (after the EAL ones) */
	rc = smc_parse_args(argc, argv, cfg_prm);
	if (rc < 0)
		DAO_ERR_GOTO(rc, fail, "Invalid smart-nic app arguments\n");

	/* Initialize the CLI */
	cli_init();

	/* Connectivity */
	cfg_prm->conn.msg_handle_arg = NULL;
	smc_main_cfg->cli_cfg.conn = conn_init(&cfg_prm->conn);
	if (!smc_main_cfg->cli_cfg.conn) {
		printf("Error: Connectivity initialization failed\n");
		goto fail;
	};

	/* Script */
	if (cfg_prm->script_name) {
		cli_script_process(cfg_prm->script_name, cfg_prm->conn.msg_in_len_max,
				   cfg_prm->conn.msg_out_len_max, NULL);
	}

	/* Dispatch loop */
	while (!smc_main_cfg->force_quit) {
		conn_req_poll(smc_main_cfg->cli_cfg.conn);

		conn_msg_poll(smc_main_cfg->cli_cfg.conn);
		if (app_graph_exit())
			smc_main_cfg->force_quit = true;
	}

	if (rte_graph_has_stats_feature() && app_graph_stats_enabled())
		rte_thread_join(smc_main_cfg->graph_prm->graph_stats_thread, NULL);
fail:
	smc_cleanup(smc_main_cfg, mz);

	conn_free(smc_main_cfg->cli_cfg.conn);
	ethdev_stop_all();
	cli_exit();
	/* clean up the EAL */
	rte_eal_cleanup();

error:
	return rc;
}
