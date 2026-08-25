/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "rdma_dma_init.h"
#include "rdma_eth_rx_priv.h"
#include "rdma_graph.h"
#include "rdma_init.h"
#include "rdma_node_ctrl.h"
#include "rdma_priv.h"
#include "rdma_pts_deq_priv.h"
#include "rdma_pts_enq_priv.h"

#include <dao_log.h>
#include <rte_graph.h>
#include <rte_graph_worker_common.h>

rte_node_t rdma_pts_deq_nodes[DAO_PTS_RDMA_MAX_DEVS];
rte_node_t rdma_pts_enq_nodes[DAO_PTS_RDMA_MAX_DEVS];

/* Cache edge index from PTS-DEQ node (per RDMA device) to its rdma_eth_tx-<port> */
static uint16_t pts_deq_tx_edge_idx[DAO_PTS_RDMA_MAX_DEVS];
static bool pts_deq_tx_edge_idx_init;

static uint32_t
graph_print_stats(void *arg)
{
	struct rdma_main_cfg_data *rdma_main_cfg = (struct rdma_main_cfg_data *)arg;
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
	const char clr[] = {27, '[', '2', 'J', '\0'};
	struct rte_graph_cluster_stats_param s_param;
	struct rte_graph_cluster_stats *stats;
	const char **s_patterns;
	uint16_t nb_patterns;
	char *buf = NULL;
	size_t buf_sz = 0;
	FILE *memfp;
	static const char *const patterns[] = {
		"worker_*",
	};

	RTE_SET_USED(arg);
	/* Get the patterns */
	nb_patterns = RTE_DIM(patterns);
	s_patterns = malloc((RDMA_MAX_RX_QUEUE_PER_LCORE + nb_patterns) * sizeof(*s_patterns));
	if (!s_patterns)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory for stats patterns");

	memcpy(s_patterns, patterns, nb_patterns * sizeof(*s_patterns));

	/* Prepare stats object */
	memfp = open_memstream(&buf, &buf_sz);
	if (!memfp)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to open memstream for stats");

	memset(&s_param, 0, sizeof(s_param));
	s_param.f = memfp;
	s_param.socket_id = SOCKET_ID_ANY;
	s_param.graph_patterns = s_patterns;
	s_param.nb_graph_patterns = nb_patterns;

	stats = rte_graph_cluster_stats_create(&s_param);
	if (stats == NULL) {
		fclose(memfp);
		free(buf);
		DAO_ERR_GOTO(-EINVAL, fail, "Unable to create stats object");
	}

	while (!rdma_main_cfg->force_quit) {
		rewind(memfp);
		rte_graph_cluster_stats_get(stats, 0);
		fflush(memfp);

		flockfile(stdout);
		fputs(clr, stdout);
		fputs(topLeft, stdout);
		fwrite(buf, 1, buf_sz, stdout);
		fflush(stdout);
		funlockfile(stdout);
		rte_delay_ms(1E3);
	}

	rte_graph_cluster_stats_destroy(stats);
	fclose(memfp);
	free(buf);
	free(s_patterns);

fail:
	return 0;
}

int
rdma_graph_print_stats(struct rdma_main_cfg_data *rdma_main_cfg)
{
	rte_thread_t thread;
	int rc;

	/* Create a thread for capturing graph statistics */
	rc = rte_thread_create_control(&thread, "grph-stats-thrd", graph_print_stats,
				       rdma_main_cfg);
	if (rc != 0)
		DAO_ERR_GOTO(rc, fail, "Failed to create thread for stats printing");

	/* Save the thread handle to join later */
	rdma_main_cfg->graph_prm->graph_stats_thread = thread;

	return 0;
fail:
	return errno;
}

void
rdma_eth_node_config(struct rdma_main_cfg_data *rdma_main_cfg, uint16_t portid, uint8_t nb_rxq,
		     uint8_t nb_txq)
{
	rdma_graph_param_t *graph_prm = rdma_main_cfg->graph_prm;
	rdma_ethdev_param_t *eth_prm = rdma_main_cfg->eth_prm;
	uint16_t nb_conf = graph_prm->nb_conf;

	/* Setup ethdev node config */
	graph_prm->eth_ctrl_cfg[nb_conf].port_id = portid;
	graph_prm->eth_ctrl_cfg[nb_conf].num_rx_queues = nb_rxq;
	graph_prm->eth_ctrl_cfg[nb_conf].num_tx_queues = nb_txq;
	if (!rdma_main_cfg->cfg_prm->per_port_pool)
		graph_prm->eth_ctrl_cfg[nb_conf].mp = eth_prm->pktmbuf_pool[0];

	else
		graph_prm->eth_ctrl_cfg[nb_conf].mp = eth_prm->pktmbuf_pool[portid];
	graph_prm->eth_ctrl_cfg[nb_conf].mp_count = RDMA_NB_SOCKETS;

	graph_prm->nb_conf++;
	printf("\n");
}

int
rdma_graph_init(struct rdma_main_cfg_data *rdma_main_cfg)
{
	rdma_graph_param_t *graph_prm = rdma_main_cfg->graph_prm;
	rdma_config_param_t *cfg_prm = rdma_main_cfg->cfg_prm;
	struct rte_graph_param graph_conf;
	uint16_t lcore_id, nb_patterns;
	const char **node_patterns = NULL;
	struct lcore_conf *qconf;
	bool service_lcore = false;
	struct rte_node *node;
	uint16_t devid;
	int rc;
	/* Graph initialization. */
	static const char *const default_patterns[] = {
		"rdma_eth_tx-*",
		"rdma_rx_process",
		"rdma_pts_process",
	};

	/* Ethdev node config, skip rx queue mapping */
	rc = rdma_node_eth_ctrl(graph_prm->eth_ctrl_cfg, graph_prm->nb_conf, graph_prm->nb_graphs);
	if (rc)
		DAO_ERR_GOTO(errno, fail, "Failed to configure eth nodes");

	/* RDMA node config */
	rc = rdma_node_rdma_ctrl(&graph_prm->fm_ctrl_cfg);
	if (rc)
		DAO_ERR_GOTO(errno, fail, "Failed to configure eth nodes");

	/* Initialize PTS-DEQ -> rdma_eth_tx-<port> edges once, prior to graph creation */
	if (!pts_deq_tx_edge_idx_init) {
		for (uint16_t d = 0; d < DAO_PTS_RDMA_MAX_DEVS; d++)
			pts_deq_tx_edge_idx[d] = RTE_EDGE_ID_INVALID;
		uint32_t dev_mask = cfg_prm->enabled_dev_mask;

		while (dev_mask) {
			uint16_t devid = __builtin_ctz(dev_mask);

			dev_mask &= ~(1u << devid);
			uint16_t mac_port = rdma_get_mac_port_from_rdevid(devid);

			if (mac_port >= RTE_MAX_ETHPORTS) {
				DAO_ERR_GOTO(-EINVAL, fail, "Invalid MAC port for RDMA devid %u",
					     devid);
			}
			char tx_name[RTE_NODE_NAMESIZE];
			const char *next_nodes;

			snprintf(tx_name, sizeof(tx_name), "rdma_eth_tx-%u", mac_port);
			next_nodes = tx_name;
			/* Append edge to the correct TX node for this RDMA device */
			rte_node_edge_update(rdma_pts_deq_nodes[devid], RTE_EDGE_ID_INVALID,
					     &next_nodes, 1);
			pts_deq_tx_edge_idx[devid] =
				rte_node_edge_count(rdma_pts_deq_nodes[devid]) - 1;
			dao_info("PTS-DEQ devid %u mapped to %s (edge idx %u)", devid, tx_name,
				 pts_deq_tx_edge_idx[devid]);
		}
		pts_deq_tx_edge_idx_init = true;
	}

	/* Graph Initialization */
	nb_patterns = RTE_DIM(default_patterns);
	node_patterns =
		malloc((RDMA_MAX_RX_QUEUE_PER_LCORE * 2 + nb_patterns) * sizeof(*node_patterns));
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

		nb_patterns = RTE_DIM(default_patterns);

		qconf = &rdma_main_cfg->lcore_prm->lcore_conf[lcore_id];

		/* Skip graph creation if no source exists */
		if (!qconf->n_rx_queue && !qconf->nb_pts_rdma_deq) {
			/* If this lcore is pre-marked as service, honor it and assign DMA */
			if (qconf->service_lcore) {
				if (!service_lcore) {
					service_lcore = true;
					if (rdma_dma_dev_assign(rdma_main_cfg, lcore_id))
						return -1;
				}
				continue;
			}
			/* Otherwise pick a non-main unused lcore as service if none chosen yet */
			if (!service_lcore && lcore_id != rte_get_main_lcore()) {
				qconf->service_lcore = true;
				service_lcore = true;
				if (rdma_dma_dev_assign(rdma_main_cfg, lcore_id))
					return -1;
				continue;
			}
			/* If main lcore has no sources and service already chosen, just skip */
			continue;
		}

		/* Assign DMA device id */
		if (rdma_dma_dev_assign(rdma_main_cfg, lcore_id))
			return -1;

		/* Add rx node patterns of this lcore */
		for (i = 0; i < qconf->n_rx_queue; i++) {
			graph_conf.node_patterns[nb_patterns + i] =
				qconf->rx_queue_list[i].node_name;

			dao_info("graph node: %s", graph_conf.node_patterns[nb_patterns + i]);
		}
		nb_patterns += i;

		/* Add pts_rdma_deq node patterns of this lcore */
		for (i = 0; i < qconf->nb_pts_rdma_deq; i++) {
			graph_conf.node_patterns[nb_patterns + i] =
				qconf->pts_rdma_deq_list[i].node_name;

			dao_info("graph node: %s", graph_conf.node_patterns[nb_patterns + i]);
		}
		nb_patterns += i;
		/* Add pts_rdma_enq node patterns of this lcore */
		for (i = 0; i < qconf->nb_pts_rdma_enq; i++) {
			graph_conf.node_patterns[nb_patterns + i] =
				qconf->pts_rdma_enq_list[i].node_name;

			dao_info("graph node: %s", graph_conf.node_patterns[nb_patterns + i]);
		}
		nb_patterns += i;

		graph_conf.nb_node_patterns = nb_patterns;
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

		/* Lookup node contexts of the nodes */
		for (i = 0; i < qconf->nb_pts_rdma_deq; i++) {
			devid = qconf->pts_rdma_deq_list[i].devid;
			node = rte_graph_node_get(graph_id, rdma_pts_deq_nodes[devid]);
			qconf->pts_rdma_deq_list[i].node_ctx =
				(struct rdma_pts_deq_node_ctx *)node->ctx_ptr;
			if (!node || !qconf->pts_rdma_deq_list[i].node_ctx)
				DAO_ERR_GOTO(-EFAULT, fail, "node %s not found in graph %s\n",
					     qconf->pts_rdma_deq_list[i].node_name, qconf->name);
			/* Bind PTS-DEQ queue to this lcore's RX queue on the device's MAC port */
			{
				uint16_t mac_port = rdma_get_mac_port_from_rdevid(devid);

				bool found_q = false;

				for (rte_edge_t r = 0; r < qconf->n_rx_queue; r++) {
					if (qconf->rx_queue_list[r].port_id == mac_port) {
						qconf->pts_rdma_deq_list[i].node_ctx->queue_id =
							qconf->rx_queue_list[r].queue_id;
						found_q = true;
						break;
					}
				}
				if (!found_q)
					DAO_ERR_GOTO(
						-EINVAL, fail,
						"PTS-DEQ devid %u: no RX queue on lcore %u for MAC port %u",
						devid, lcore_id, mac_port);
			}
			qconf->pts_rdma_deq_list[i].node_ctx->tx_node_idx =
				pts_deq_tx_edge_idx[devid];
			qconf->pts_rdma_deq_list[i].node_ctx->devid = devid;
			/* Validate tx edge index is within bounds for this node instance */
			if (qconf->pts_rdma_deq_list[i].node_ctx->tx_node_idx >= node->nb_edges) {
				DAO_ERR_GOTO(
					-EINVAL, fail,
					"PTS-DEQ devid %u: invalid tx edge %u (nb_edges %u) on graph %s",
					devid, qconf->pts_rdma_deq_list[i].node_ctx->tx_node_idx,
					node->nb_edges, qconf->name);
			} else {
				dao_info(
					"PTS-DEQ devid %u: tx edge idx %u valid (nb_edges %u) on graph %s",
					devid, qconf->pts_rdma_deq_list[i].node_ctx->tx_node_idx,
					node->nb_edges, qconf->name);
			}
		}

		for (i = 0; i < qconf->nb_pts_rdma_enq; i++) {
			devid = qconf->pts_rdma_enq_list[i].devid;
			node = rte_graph_node_get(graph_id, rdma_pts_enq_nodes[devid]);
			qconf->pts_rdma_enq_list[i].node_ctx =
				(struct rdma_pts_enq_node_ctx *)node->ctx;
			qconf->pts_rdma_enq_list[i].node_ctx->devid = devid;
			if (!node || !qconf->pts_rdma_enq_list[i].node_ctx)
				DAO_ERR_GOTO(-EFAULT, fail, "node %s not found in graph %s\n",
					     qconf->pts_rdma_enq_list[i].node_name, qconf->name);
		}

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

	if (!service_lcore)
		DAO_ERR_GOTO(-EINVAL, fail, "No service lcore found\n");

	free(node_patterns);
	return 0;
fail:
	if (node_patterns)
		free(node_patterns);
	return errno;
}
