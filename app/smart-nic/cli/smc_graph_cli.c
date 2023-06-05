/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_socket.h>
#include <rte_ethdev.h>
#include <rte_graph_worker.h>
#include <rte_log.h>

#include <smc_cli_api.h>
#include <smc_init.h>

#include "smc_graph_cli_priv.h"

#define RTE_LOGTYPE_APP_GRAPH RTE_LOGTYPE_USER1

static const char cmd_graph_help[] =
	"graph config coremask <bitmask> bsz <size> tmo <ns> "
	"model <rtc | mcd | default> pcap_enable <0 | 1> num_pcap_pkts <num>"
	"pcap_file <output_capture_file>";

static const char cmd_graph_dump_help[] = "graph dump";
struct graph_config graph_config;
bool graph_started;

static int
graph_stats_print_to_file(void)
{
	struct rte_graph_cluster_stats_param s_param;
	struct rte_graph_cluster_stats *stats;
	const char *pattern = "worker_*";
	struct conn *conn = NULL;
	FILE *fp = NULL;
	size_t sz, len;

	CONN_CONF_HANDLE(conn, -EINVAL);

	/* Prepare stats object */
	fp = fopen("/tmp/graph_stats.txt", "w+");
	if (fp == NULL)
		rte_exit(EXIT_FAILURE, "Error in opening stats file\n");

	memset(&s_param, 0, sizeof(s_param));
	s_param.f = fp;
	s_param.socket_id = SOCKET_ID_ANY;
	s_param.graph_patterns = &pattern;
	s_param.nb_graph_patterns = 1;

	stats = rte_graph_cluster_stats_create(&s_param);
	if (stats == NULL)
		rte_exit(EXIT_FAILURE, "Unable to create stats object\n");

	/* Clear screen and move to top left */
	rte_graph_cluster_stats_get(stats, 0);
	rte_delay_ms(1E3);

	fseek(fp, 0L, SEEK_END);
	sz = ftell(fp);
	fseek(fp, 0L, SEEK_SET);

	len = strlen(conn->msg_out);
	if (len > conn->msg_out_len_max)
		rte_exit(EXIT_FAILURE, "Invalid msg len\n");
	conn->msg_out += len;

	sz = fread(conn->msg_out, sizeof(char), sz, fp);
	conn->msg_out[sz + 1] = '\0';
	len = strlen(conn->msg_out);
	conn->msg_out_len_max -= len;
	rte_graph_cluster_stats_destroy(stats);

	fclose(fp);

	return 0;
}

void
cmd_graph_stats_show_parsed(__rte_unused void *parsed_result, __rte_unused struct cmdline *cl,
			    __rte_unused void *data)
{
	graph_stats_print_to_file();
}

bool
graph_status_get(void)
{
	return graph_started;
}

static int
smc_main_loop(void *config)
{
	struct smc_main_cfg_data *smc_main_cfg = (struct smc_main_cfg_data *)config;
	uint16_t port_id, queue_id;
	struct lcore_conf *qconf;
	struct rte_graph *graph;
	uint32_t lcore_id;
	int queue = 0;

	RTE_SET_USED(config);
	lcore_id = rte_lcore_id();
	qconf = &smc_main_cfg->cli_cfg.lcore_conf[lcore_id];
	graph = qconf->graph;
	if (!graph) {
		dao_info("Lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	dao_dbg("Entering main loop on lcore %u, graph %s(%p)\n", lcore_id, qconf->name, graph);

	for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
		port_id = qconf->rx_queue_list[queue].port_id;
		queue_id = qconf->rx_queue_list[queue].queue_id;

		dao_info("Lcore %d port %d queue %d", lcore_id, port_id, queue_id);
	}

	while (likely(!smc_main_cfg->force_quit))
		rte_graph_walk(graph);

	return 0;
}

static int
smc_launch_one_lcore(void *config)
{
	smc_main_loop(config);
	return 0;
}

static int
graph_start(void)
{
	struct smc_main_cfg_data *smc_main_cfg = NULL;
	int rc = -EINVAL;

	smc_main_cfg = smc_main_cfg_handle();
	if (!smc_main_cfg)
		DAO_ERR_GOTO(rc, fail, "Failed to get global config");

	rc = smc_graph_init(smc_main_cfg);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to setup graphs");

	/* Accumulate and print stats on main until exit */
	if (rte_graph_has_stats_feature() && app_graph_stats_enabled())
		smc_graph_print_stats(smc_main_cfg);

	rc = 0;
	dao_info("\nLaunching worker loops....\n");
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(smc_launch_one_lcore, smc_main_cfg, SKIP_MAIN);
fail:
	return rc;
}

void
cmd_graph_start_parsed(__rte_unused void *parsed_result, __rte_unused struct cmdline *cl,
		       __rte_unused void *data)
{
	graph_start();
}

static int
graph_config_add(struct graph_config *config)
{
	uint64_t lcore_id, core_num;
	uint64_t eal_coremask = 0;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id))
			eal_coremask |= RTE_BIT64(lcore_id);
	}

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		core_num = 1 << lcore_id;
		if (config->params.coremask & core_num) {
			if (eal_coremask & core_num)
				continue;
			else
				DAO_ERR_GOTO(-EINVAL, fail,
					     "User coremask 0x%lx not part of eal coremask 0x%lx",
					     config->params.coremask, eal_coremask);
		}
	}

	graph_config.params.bsz = config->params.bsz;
	graph_config.params.tmo = config->params.tmo;
	graph_config.params.coremask = config->params.coremask;
	graph_config.model = config->model;
	graph_config.pcap_ena = config->pcap_ena;
	graph_config.num_pcap_pkts = config->num_pcap_pkts;
	graph_config.pcap_file = strdup(config->pcap_file);

	return 0;
fail:
	return errno;
}

void
graph_pcap_config_get(uint8_t *pcap_ena, uint64_t *num_pkts, char **file)
{
	*pcap_ena = graph_config.pcap_ena;
	*num_pkts = graph_config.num_pcap_pkts;
	*file = graph_config.pcap_file;
}

int
graph_walk_start(void *conf)
{
	struct lcore_conf *qconf, *lcore_conf = NULL;
	struct smc_main_cfg_data *cfg_data;
	struct rte_graph *graph;
	uint32_t lcore_id;

	RTE_SET_USED(conf);

	LCORE_CONF_HANDLE(lcore_conf, -EINVAL);

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];
	graph = qconf->graph;

	if (!graph) {
		RTE_LOG(INFO, APP_GRAPH, "Lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, APP_GRAPH, "Entering main loop on lcore %u, graph %s(%p)\n", lcore_id,
		qconf->name, graph);

	cfg_data = smc_main_cfg_handle();
	while (likely(cfg_data && !cfg_data->force_quit)) {
		rte_graph_walk(graph);
		cfg_data = smc_main_cfg_handle();
	}

	return 0;
}

void
graph_stats_print(void)
{
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
	const char clr[] = {27, '[', '2', 'J', '\0'};
	struct rte_graph_cluster_stats_param s_param;
	struct rte_graph_cluster_stats *stats;
	const char *pattern = "worker_*";
	struct smc_main_cfg_data *cfg_handle;

	/* Prepare stats object */
	memset(&s_param, 0, sizeof(s_param));
	s_param.f = stdout;
	s_param.socket_id = SOCKET_ID_ANY;
	s_param.graph_patterns = &pattern;
	s_param.nb_graph_patterns = 1;

	stats = rte_graph_cluster_stats_create(&s_param);
	if (stats == NULL)
		rte_exit(EXIT_FAILURE, "Unable to create stats object\n");

	cfg_handle = smc_main_cfg_handle();
	if (!cfg_handle)
		rte_exit(EXIT_FAILURE, "Fail to get cfg handle\n");

	while (!cfg_handle->force_quit) {
		/* Clear screen and move to top left */
		printf("%s%s", clr, topLeft);
		rte_graph_cluster_stats_get(stats, 0);
		rte_delay_ms(1E3);
		if (app_graph_exit())
			cfg_handle->force_quit = true;
	}

	rte_graph_cluster_stats_destroy(stats);
}

uint64_t
graph_coremask_get(void)
{
	return graph_config.params.coremask;
}

void
cmd_graph_config_coremask_parsed(void *parsed_result, __rte_unused struct cmdline *cl,
				 __rte_unused void *data)
{
	struct cmd_graph_config_coremask_result *res = parsed_result;
	struct graph_config config;
	char *model_name;
	uint8_t model;
	int rc;

	model_name = res->model_name;
	if (strcmp(model_name, "default") == 0) {
		model = GRAPH_MODEL_RTC;
	} else if (strcmp(model_name, "rtc") == 0) {
		model = GRAPH_MODEL_RTC;
	} else if (strcmp(model_name, "mcd") == 0) {
		model = GRAPH_MODEL_MCD;
	} else {
		printf(MSG_ARG_NOT_FOUND, "model arguments");
		return;
	}

	config.params.bsz = res->size;
	config.params.tmo = res->ns;
	config.params.coremask = res->mask;
	config.model = model;
	config.pcap_ena = res->pcap_ena;
	config.num_pcap_pkts = res->num_pcap_pkts;
	config.pcap_file = res->pcap_file;
	rc = graph_config_add(&config);
	if (rc < 0) {
		cli_exit();
		printf(MSG_CMD_FAIL, res->graph);
		rte_exit(EXIT_FAILURE, "coremask is Invalid\n");
	}
}

static int
print_graph_help(void)
{
	struct conn *conn = NULL;
	size_t len;

	CONN_CONF_HANDLE(conn, -EINVAL);

	len = strlen(conn->msg_out);
	conn->msg_out += len;
	snprintf(conn->msg_out, conn->msg_out_len_max, "\n%s\n%s\n%s\n%s\n%s\n",
		 "----------------------------- graph command help -----------------------------",
		 cmd_graph_help, "graph start", "graph stats show", cmd_graph_dump_help);

	len = strlen(conn->msg_out);
	conn->msg_out_len_max -= len;

	return 0;
}

void
cmd_help_graph_parsed(__rte_unused void *parsed_result, __rte_unused struct cmdline *cl,
		      __rte_unused void *data)
{
	print_graph_help();
}

static int
graph_dump(void)
{
	struct lcore_conf *qconf, *lcore_conf = NULL;
	char filename[BUFSIZ];
	uint16_t lcore_id;
	FILE *f;

	LCORE_CONF_HANDLE(lcore_conf, -EINVAL);

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		qconf = &lcore_conf[lcore_id];

		if (!qconf->graph)
			continue;

		rte_graph_dump(stdout, qconf->graph_id);
		rte_graph_obj_dump(stdout, qconf->graph, 1);

		snprintf(filename, BUFSIZ, "/tmp/%s", qconf->name);
		f = fopen(filename, "w+");
		if (f == NULL)
			DAO_ERR_GOTO(-ENOENT, fail, "fail to open file %s", filename);
		rte_graph_export(qconf->name, f);
		fclose(f);
	}

	return 0;
fail:
	return errno;
}

void
cmd_graph_dump_parsed(__rte_unused void *parsed_result, __rte_unused struct cmdline *cl,
		      __rte_unused void *data)
{
	graph_dump();
}
