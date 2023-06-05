/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <stdlib.h>

#include <ood_graph.h>
#include <ood_init.h>
#include <ood_node_ctrl.h>

#include <dao_log.h>

static uint32_t
graph_print_stats(void *arg)
{
	struct ood_main_cfg_data *ood_main_cfg = (struct ood_main_cfg_data *)arg;
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
	const char clr[] = {27, '[', '2', 'J', '\0'};
	struct rte_graph_cluster_stats_param s_param;
	struct rte_graph_cluster_stats *stats;
	const char **s_patterns;
	uint16_t nb_patterns;
	static const char *const patterns[] = {
		"worker_*",
		"control_*",
	};

	RTE_SET_USED(arg);
	/* Get the patterns */
	nb_patterns = RTE_DIM(patterns);
	s_patterns = malloc((OOD_MAX_RX_QUEUE_PER_LCORE + nb_patterns) * sizeof(*s_patterns));
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

	while (!ood_main_cfg->force_quit) {
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
ood_graph_print_stats(struct ood_main_cfg_data *ood_main_cfg)
{
	rte_thread_t thread;
	int rc;

	/* Create a thread for capturing graph statistics */
	rc = rte_thread_create_control(&thread, "grph-stats-thrd", graph_print_stats,
				       ood_main_cfg);
	if (rc != 0)
		DAO_ERR_GOTO(rc, fail, "Failed to create thread for VF mbox handling");

	/* Save the thread handle to join later */
	ood_main_cfg->graph_prm->graph_stats_thread = thread;

	return 0;
fail:
	return errno;
}

void
ood_eth_node_config(struct ood_main_cfg_data *ood_main_cfg, uint16_t portid, uint8_t nb_rxq,
		    uint8_t nb_txq)
{
	ood_graph_param_t *graph_prm = ood_main_cfg->graph_prm;
	ood_ethdev_param_t *eth_prm = ood_main_cfg->eth_prm;
	uint16_t nb_conf = graph_prm->nb_conf;

	/* Setup ethdev node config */
	graph_prm->eth_ctrl_cfg[nb_conf].port_id = portid;
	graph_prm->eth_ctrl_cfg[nb_conf].num_rx_queues = nb_rxq;
	graph_prm->eth_ctrl_cfg[nb_conf].num_tx_queues = nb_txq;
	if (!ood_main_cfg->cfg_prm->per_port_pool)
		graph_prm->eth_ctrl_cfg[nb_conf].mp = eth_prm->pktmbuf_pool[0];

	else
		graph_prm->eth_ctrl_cfg[nb_conf].mp = eth_prm->pktmbuf_pool[portid];
	graph_prm->eth_ctrl_cfg[nb_conf].mp_count = OOD_NB_SOCKETS;

	graph_prm->nb_conf++;
	printf("\n");
}

int
ood_graph_init(struct ood_main_cfg_data *ood_main_cfg)
{
	ood_graph_param_t *graph_prm = ood_main_cfg->graph_prm;
	ood_config_param_t *cfg_prm = ood_main_cfg->cfg_prm;
	struct rte_graph_param graph_conf;
	uint16_t lcore_id, nb_patterns;
	const char **node_patterns = NULL;
	struct lcore_conf *qconf;
	int rc;
	/* Graph initialization. */
	static const char *const default_patterns[] = {
		"flow_mapper",
		"ood_eth_tx-*",
	};

	rc = ood_node_ctrl_init();
	if (rc)
		DAO_ERR_GOTO(errno, fail, "Fail to initialize node control layer");

	/* Ethdev node config, skip rx queue mapping */
	rc = ood_node_eth_ctrl(graph_prm->eth_ctrl_cfg, graph_prm->nb_conf, graph_prm->nb_graphs);
	if (rc)
		DAO_ERR_GOTO(errno, fail, "Failed to configure eth nodes");

	/* Populate representor config required for respective nodes */
	rc = ood_repr_populate_node_config(ood_main_cfg,
					   &ood_main_cfg->graph_prm->repr_ctrl_cfg);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to populate repr node config, err=%d", rc);

	/* Flow mapper node config */
	rc = ood_node_flow_mapper_ctrl(&graph_prm->fm_ctrl_cfg,
				       &ood_main_cfg->graph_prm->repr_ctrl_cfg);
	if (rc)
		DAO_ERR_GOTO(errno, fail, "Failed to configure eth nodes");

	/* repr node config */
	rc = ood_node_repr_ctrl(&ood_main_cfg->graph_prm->repr_ctrl_cfg);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "ood_node_repr_ctrl: err=%d\n", rc);

	/* Graph Initialization */
	nb_patterns = RTE_DIM(default_patterns);
	node_patterns = malloc((OOD_MAX_RX_QUEUE_PER_LCORE + nb_patterns) * sizeof(*node_patterns));
	if (!node_patterns)
		return -ENOMEM;
	memcpy(node_patterns, default_patterns, nb_patterns * sizeof(*node_patterns));

	memset(&graph_conf, 0, sizeof(graph_conf));
	graph_conf.node_patterns = node_patterns;

	/* Pcap config */
	graph_conf.pcap_enable = cfg_prm->pcap_trace_enable;
	graph_conf.num_pkt_to_capture = cfg_prm->packet_to_capture;
	graph_conf.pcap_filename = cfg_prm->pcap_filename;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		rte_graph_t graph_id;
		rte_edge_t i;

		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		qconf = &ood_main_cfg->lcore_prm->lcore_conf[lcore_id];

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

		if (lcore_id == rte_get_main_lcore())
			snprintf(qconf->name, sizeof(qconf->name), "control_%u", lcore_id);
		else
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

		if (cfg_prm->enable_debug) {
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
