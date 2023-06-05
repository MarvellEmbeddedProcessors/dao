/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_graph.h>

#include <smc_cli_api.h>
#include <smc_init.h>
#include <smc_node_ctrl.h>

static uint32_t
graph_print_stats(void *arg)
{
	struct smc_main_cfg_data *smc_main_cfg = (struct smc_main_cfg_data *)arg;
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
	const char clr[] = {27, '[', '2', 'J', '\0'};
	struct rte_graph_cluster_stats_param s_param;
	struct rte_graph_cluster_stats *stats;
	const char **s_patterns;
	uint16_t nb_patterns;
	static const char *const patterns[] = {
		"worker_*",
	};

	RTE_SET_USED(arg);
	/* Get the patterns */
	nb_patterns = RTE_DIM(patterns);
	s_patterns = malloc((ETHDEV_RX_QUEUE_PER_LCORE_MAX + nb_patterns) * sizeof(*s_patterns));
	if (!s_patterns)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory for stats patterns");

	memcpy(s_patterns, patterns, nb_patterns * sizeof(*s_patterns));

	/* Prepare stats object */
	memset(&s_param, 0, sizeof(s_param));
	s_param.f = stdout;
	s_param.socket_id = SOCKET_ID_ANY;
	s_param.graph_patterns = s_patterns;
	s_param.nb_graph_patterns = nb_patterns;

	stats = rte_graph_cluster_stats_create(&s_param);
	if (stats == NULL)
		DAO_ERR_GOTO(-EINVAL, fail, "Unable to create stats object");

	while (!smc_main_cfg->force_quit) {
		/* Clear screen and move to top left */
		printf("%s%s", clr, topLeft);
		rte_graph_cluster_stats_get(stats, 0);
		rte_delay_ms(1E3);
	}

	rte_graph_cluster_stats_destroy(stats);
	free(s_patterns);

fail:
	return 0;
}

int
smc_graph_print_stats(struct smc_main_cfg_data *smc_main_cfg)
{
	rte_thread_t thread;
	int rc;

	/* Create a thread for capturing graph statistics */
	rc = rte_thread_create_control(&thread, "grph-stats-thrd", graph_print_stats, smc_main_cfg);
	if (rc != 0)
		DAO_ERR_GOTO(rc, fail, "Failed to create thread for VF mbox handling");

	/* Save the thread handle to join later */
	smc_main_cfg->graph_prm->graph_stats_thread = thread;

	return 0;
fail:
	return errno;
}

int
smc_graph_rx_to_tx_node_link(uint16_t portid1, uint16_t portid2)
{
	char name[RTE_NODE_NAMESIZE];
	const char *next_node = name;
	struct smc_main_cfg_data *cfg_data;
	smc_graph_param_t *graph_prm;
	rte_node_t rx_id;
	uint16_t tx_port;

	cfg_data = smc_main_cfg_handle();
	if (cfg_data && cfg_data->graph_prm)
		graph_prm = cfg_data->graph_prm;
	else
		return -EINVAL;

	tx_port = smc_pipeline_tx_link_for_rx_port(portid1);
	if (tx_port != UINT16_MAX) {
		rx_id = rte_node_from_name(graph_prm->eth_rx_node[portid1].node_name);
		snprintf(name, sizeof(name), "ethdev_tx-%u", tx_port);
		rte_node_edge_update(rx_id, RTE_EDGE_ID_INVALID, &next_node, 1);
	} else {
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to find tx link for rx port %d", portid1);
	}

	tx_port = smc_pipeline_tx_link_for_rx_port(portid2);
	if (tx_port != UINT16_MAX) {
		rx_id = rte_node_from_name(graph_prm->eth_rx_node[portid2].node_name);
		snprintf(name, sizeof(name), "ethdev_tx-%u", tx_port);
		rte_node_edge_update(rx_id, RTE_EDGE_ID_INVALID, &next_node, 1);
	} else {
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to find tx link for rx port %d", portid2);
	}

	return 0;
fail:
	return errno;
}

int
smc_graph_init(struct smc_main_cfg_data *smc_main_cfg)
{
	smc_graph_param_t *graph_prm = smc_main_cfg->graph_prm;
	struct rte_graph_param graph_conf;
	uint16_t lcore_id, nb_patterns;
	const char **node_patterns = NULL;
	struct lcore_conf *qconf;
	uint64_t pcap_pkts_count;
	uint8_t pcap_ena;
	char *pcap_file;
	int rc;
	/* Graph initialization. */
	static const char *const default_patterns[] = {
		"smc_eth_tx-*",
	};

	rc = smc_node_ctrl_init();
	if (rc)
		DAO_ERR_GOTO(errno, fail, "Failed to allocate memory for node ctrl");

	rc = smc_node_eth_ctrl(graph_prm);
	if (rc)
		DAO_ERR_GOTO(errno, fail, "Failed to configure eth nodes");

	/* Graph Initialization */
	nb_patterns = RTE_DIM(default_patterns);
	node_patterns =
		malloc((ETHDEV_RX_QUEUE_PER_LCORE_MAX + nb_patterns) * sizeof(*node_patterns));
	if (!node_patterns)
		return -ENOMEM;
	memcpy(node_patterns, default_patterns, nb_patterns * sizeof(*node_patterns));

	memset(&graph_conf, 0, sizeof(graph_conf));
	graph_conf.node_patterns = node_patterns;

	/* Pcap config */
	graph_pcap_config_get(&pcap_ena, &pcap_pkts_count, &pcap_file);
	graph_conf.pcap_enable = pcap_ena;
	graph_conf.num_pkt_to_capture = pcap_pkts_count;
	graph_conf.pcap_filename = strdup(pcap_file);

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		rte_graph_t graph_id;
		rte_edge_t i;

		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		qconf = &smc_main_cfg->cli_cfg.lcore_conf[lcore_id];

		/* Skip graph creation if no source exists */
		if (!qconf->n_rx_queue)
			continue;

		/* Add rx node patterns of this lcore */
		for (i = 0; i < qconf->n_rx_queue; i++) {
			graph_conf.node_patterns[nb_patterns + i] =
				qconf->rx_queue_list[i].node_name;
		}

		graph_conf.nb_node_patterns = nb_patterns + i;
		graph_conf.socket_id = rte_lcore_to_socket_id(lcore_id);

		snprintf(qconf->name, sizeof(qconf->name), "worker_%u", lcore_id);

		graph_id = rte_graph_create(qconf->name, &graph_conf);
		if (graph_id == RTE_GRAPH_ID_INVALID)
			DAO_ERR_GOTO(-EINVAL, fail,
				     "rte_graph_create(): graph_id invalid"
				     " for lcore %u\n",
				     lcore_id);

		qconf->graph_id = graph_id;
		qconf->graph = rte_graph_lookup(qconf->name);
		/* >8 End of graph initialization. */
		if (!qconf->graph)
			DAO_ERR_GOTO(-EFAULT, fail, "rte_graph_lookup(): graph %s not found\n",
				     qconf->name);

		/* Update context data of ethdev rx and virtio tx nodes of this graph */
		rc = smc_node_context_save(qconf);
		if (rc)
			DAO_ERR_GOTO(errno, fail, "Failed to save the node context");

		if (smc_main_cfg->cfg_prm->enable_debug) {
			rte_graph_dump(stdout, graph_id);
			rte_graph_obj_dump(stdout, qconf->graph, 1);
			char filename[BUFSIZ];
			FILE *f;

			snprintf(filename, BUFSIZ, "/tmp/%s", qconf->name);
			f = fopen(filename, "w+");
			if (f == NULL)
				DAO_ERR_GOTO(-ENOENT, fail, "fail to open file %s", filename);
			rte_graph_export(qconf->name, f);
			fclose(f);
		}
	}

	free(node_patterns);
	return 0;
fail:
	if (node_patterns)
		free(node_patterns);
	return errno;
}
