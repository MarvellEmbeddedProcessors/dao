/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
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

#include <rte_atomic.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_graph_worker.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>

#include <dao_dma.h>
#include <dao_log.h>
#include <dao_pem.h>
#include <dao_util.h>
#include <dao_version.h>

#include "rdma_dma_init.h"
#include "rdma_graph.h"
#include "rdma_heartbeat.h"
#include "rdma_init.h"
#include "rdma_lcore.h"
#include "rdma_pem_init.h"

#include "rdma_pts_deq_priv.h"
#include "rdma_pts_enq_priv.h"

#include "dao_rdma_fp.h"
#include "dao_rdma_sp.h"
#include "rdma_priv.h"
#include "rdma_rss.h"

/* Global pause flag for graph walking */
volatile uint8_t g_rdma_graph_pause;

struct rdma_main_cfg_data *rdma_main_cfg;
const struct rte_memzone *mz;

/* RCU QSBR variable */
static struct rte_rcu_qsbr *qs_v;

/* Callback to return DPDK MAC port for a given RDMA port_num */
static uint16_t
app_rdma_map_cb(uint16_t port_num, uint8_t *pause_flag)
{
	if (pause_flag) {
		g_rdma_graph_pause = *pause_flag;
		rte_mb(); /* Memory barrier to ensure visibility across cores */
	}
	return rdma_get_mac_port_from_rdevid(port_num);
}

static uint16_t dma_flush_thr;

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		dao_info("\n\nSignal %d received, preparing to exit...\n", signum);
		rdma_main_cfg->force_quit = true;
	}
}

static void
rdma_cleanup(void)
{
	rte_free(rdma_main_cfg->graph_prm);
	rte_free(rdma_main_cfg->eth_prm);
	rte_free(rdma_main_cfg->cfg_prm);
	rte_free(rdma_main_cfg->lcore_prm);
	rte_free(rdma_main_cfg->pem_prm);

	rte_memzone_free(mz);
}

static int
rdma_mem_allocate(void)
{
	/* Allocate memory for lcore params */
	rdma_main_cfg->lcore_prm =
		rte_zmalloc("config", sizeof(rdma_lcore_param_t), RTE_CACHE_LINE_SIZE);
	if (!rdma_main_cfg->lcore_prm)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to alloc mem for lcore params");

	/* Allocate memory for config params */
	rdma_main_cfg->cfg_prm =
		rte_zmalloc("config", sizeof(rdma_config_param_t), RTE_CACHE_LINE_SIZE);
	if (!rdma_main_cfg->cfg_prm)
		DAO_ERR_GOTO(-ENOMEM, free_lcore, "Failed to alloc mem for config params");

	/* Allocate memory for ethdev params */
	rdma_main_cfg->eth_prm =
		rte_zmalloc("config", sizeof(rdma_ethdev_param_t), RTE_CACHE_LINE_SIZE);
	if (!rdma_main_cfg->eth_prm)
		DAO_ERR_GOTO(-ENOMEM, free_cfg, "Failed to alloc mem for ethdev params");

	/* Allocate memory for graph params */
	rdma_main_cfg->graph_prm =
		rte_zmalloc("config", sizeof(rdma_graph_param_t), RTE_CACHE_LINE_SIZE);
	if (!rdma_main_cfg->graph_prm)
		DAO_ERR_GOTO(-ENOMEM, free_eth, "Failed to alloc mem for graph params");

	/* Allocate memory for graph params */
	rdma_main_cfg->pem_prm =
		rte_zmalloc("config", sizeof(rdma_pemdev_param_t), RTE_CACHE_LINE_SIZE);
	if (!rdma_main_cfg->pem_prm)
		DAO_ERR_GOTO(-ENOMEM, free_graph, "Failed to alloc mem for pem params");

	return 0;
free_graph:
	rte_free(rdma_main_cfg->graph_prm);
free_eth:
	rte_free(rdma_main_cfg->eth_prm);
free_cfg:
	rte_free(rdma_main_cfg->cfg_prm);
free_lcore:
	rte_free(rdma_main_cfg->lcore_prm);
fail:
	return errno;
}

void
rdma_rcu_qsbr_synchronize(void)
{
	/* Synchronize RCU QSBR */
	rte_rcu_qsbr_synchronize(qs_v, RTE_QSBR_THRID_INVALID);
}

int
rdma_qp_status_cb(uint16_t devid, uint16_t qp_id, bool enable)
{
	struct lcore_conf *qconf = NULL, *found = NULL;
	struct rdma_pts_deq_node_ctx *ctx = NULL;
	rdma_pts_bitmap_t *qp_map;
	uint32_t lcore_id;
	bool q_exists = false;
	uint16_t queue = 0, port_id = 0;
	int i;

	port_id = rdma_get_mac_port_from_rdevid(devid);
	if (port_id >= RTE_MAX_ETHPORTS) {
		dao_err("Invalid port id %d for device id %d\n", port_id, devid);
		return -1;
	}

	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		qconf = &rdma_main_cfg->lcore_prm->lcore_conf[lcore_id];
		queue = rdma_get_queue_id(qp_id, qconf->total_rx_queue, port_id);
		for (i = 0; i < qconf->nb_pts_rdma_deq; i++) {
			if ((qconf->pts_rdma_deq_list[i].devid != devid))
				continue;
			for (int j = 0; j < qconf->n_rx_queue; j++) {
				if (qconf->rx_queue_list[j].port_id == port_id &&
				    qconf->rx_queue_list[j].queue_id == queue) {
					ctx = qconf->pts_rdma_deq_list[i].node_ctx;
					if (ctx->qp_map->bits[qp_id / 64] & RTE_BIT64(qp_id % 64)) {
						found = qconf;
						q_exists = true;
					} else {
						found = qconf;
					}
					break;
				}
			}
		}
		if (found)
			break;
	}

	if (enable && q_exists) {
		dao_dbg("QP %d on lcore %u is already enabled\n", qp_id, lcore_id);
		return lcore_id;
	}

	if (!enable && !q_exists) {
		dao_dbg("QP %d on lcore %u is already disabled\n", qp_id, lcore_id);
		return lcore_id;
	}

	dao_dbg("[QP-MAP] QP %d on lcore %u queue id %d\n", qp_id, lcore_id, queue);
	qp_map = ctx->qp_map;
	ctx->qp_map = NULL;
	/* Synchronize RCU */
	rte_rcu_qsbr_synchronize(qs_v, RTE_QSBR_THRID_INVALID);

	if (enable) {
		if (!found) {
			dao_err("No lcore found for dev_id %d\n", devid);
			return -1;
		}

		dao_dbg("Enabling QP %d on lcore %u\n", qp_id, lcore_id);
		qp_map->bits[qp_id / 64] |= RTE_BIT64(qp_id % 64);
		ctx->qp_count++;
	} else {
		dao_dbg("Disabling QP %d on lcore %u\n", qp_id, lcore_id);
		qp_map->bits[qp_id / 64] &= ~RTE_BIT64(qp_id % 64);
		ctx->qp_count--;
	}
	ctx->qp_map = qp_map;

	return lcore_id;
}

static int
service_main_loop(void *conf)
{
	uint32_t dev_mask = rdma_main_cfg->cfg_prm->enabled_dev_mask;
	struct lcore_conf *qconf;
	uint32_t lcore_id;
	int devid;
	int rc;

	RTE_SET_USED(conf);

	lcore_id = rte_lcore_id();
	qconf = &rdma_main_cfg->lcore_prm->lcore_conf[lcore_id];

	/* Set per lcore DMA device id */
	rc = dao_dma_lcore_dev2mem_set(qconf->dev2mem_id, qconf->nb_vchans, dma_flush_thr);
	rc |= dao_dma_lcore_mem2dev_set(qconf->mem2dev_id, qconf->nb_vchans, dma_flush_thr);
	if (rc) {
		dao_err("Error in setting DMA device on lcore\n");
		return -1;
	}

	/* Register this thread to rdaort quiescent state */
	rte_rcu_qsbr_thread_register(qs_v, lcore_id);
	rte_rcu_qsbr_thread_online(qs_v, lcore_id);

	dao_info("Entering service main loop on lcore %u", lcore_id);

	while (likely(!rdma_main_cfg->force_quit)) {
		for (devid = 0; devid < RDMA_MAX_DEVS; devid++) {
			if (!(dev_mask & (1 << devid)))
				continue;
			/* Process RDMA descriptors */
			dao_pts_rdma_desc_manage(devid);

			/* Flush and submit DMA ops */
			dao_dma_flush_submit_v2();

			/* Update quiescent state */
			rte_rcu_qsbr_quiescent(qs_v, lcore_id);
		}
	}

	rte_rcu_qsbr_thread_offline(qs_v, lcore_id);
	rte_rcu_qsbr_thread_unregister(qs_v, lcore_id);
	return 0;
}

static int
rdma_main_loop(void *config)
{
	//	struct lcore_params *lparams;
	uint16_t port_id, queue_id;
	struct lcore_conf *qconf;
	struct rte_graph *graph;
	uint32_t lcore_id;
	int queue = 0;
	int rc, i;

	RTE_SET_USED(config);

	lcore_id = rte_lcore_id();
	//	lparams = &rdma_main_cfg->lcore_prm->lcore_params_array[lcore_id];
	qconf = &rdma_main_cfg->lcore_prm->lcore_conf[lcore_id];
	graph = qconf->graph;
	if (!graph) {
		dao_info("Lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	/* Set per lcore DMA device id */
	rc = dao_dma_lcore_dev2mem_set(qconf->dev2mem_id, qconf->nb_vchans, dma_flush_thr);
	rc |= dao_dma_lcore_mem2dev_set(qconf->mem2dev_id, qconf->nb_vchans, dma_flush_thr);
	for (i = 0; i < qconf->nb_vchans; i++)
		rc |= dao_dma_lcore_mem2dev_autofree_set(qconf->mem2dev_id, i, true);

	if (rc) {
		dao_err("Error in setting DMA device on lcore\n");
		return -1;
	}

	/* Set up DMA per lcore.
	 * XXX: Hardcoded the threshold to 8.
	 * XXX - DAO-DMA
	 */
	//	rc = dao_dma_lcore_dev2mem_set(lparams->dev2mem_id, lparams->nb_vchans, 8);
	//	rc |= dao_dma_lcore_mem2dev_set(lparams->mem2dev_id, lparams->nb_vchans, 8);
	//	if (rc) {
	//		dao_err("Error in setting DMA device on lcore\n");
	//		return -1;
	//	}

	/* Register this thread to rdaort quiescent state */
	rte_rcu_qsbr_thread_register(qs_v, lcore_id);
	rte_rcu_qsbr_thread_online(qs_v, lcore_id);

	dao_dbg("Entering main loop on lcore %u, graph %s(%p)\n", lcore_id, qconf->name, graph);

	for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
		port_id = qconf->rx_queue_list[queue].port_id;
		queue_id = qconf->rx_queue_list[queue].queue_id;

		dao_info("Lcore %d port %d queue %d dest port %d", lcore_id, port_id, queue_id,
			 rdma_ethdev_port_pair_get(rdma_main_cfg->eth_prm->host_mac_map, port_id));
	}

	while (likely(!rdma_main_cfg->force_quit)) {
		/* Check if graph walk is paused with memory barrier */
		if (likely(!g_rdma_graph_pause))
			rte_graph_walk(graph);

		/* Flush and submit DMA ops */
		dao_dma_flush_submit_v2();

		/* Update quiescent state */
		rte_rcu_qsbr_quiescent(qs_v, lcore_id);
	}

	rte_rcu_qsbr_thread_offline(qs_v, lcore_id);
	rte_rcu_qsbr_thread_unregister(qs_v, lcore_id);

	return 0;
}

static int
rdma_launch_one_lcore(void *config)
{
	rdma_main_loop(config);
	return 0;
}

static void
release_dma_devices(void)
{
	int16_t dma_devid;
	int rc;

	/* stop DMA devices */
	RTE_DMA_FOREACH_DEV(dma_devid)
	{
		rc = rte_dma_stop(dma_devid);
		if (rc)
			dao_err("Failed to stop dma dev %u: %s\n", dma_devid, rte_strerror(-rc));

		rc = rte_dma_close(dma_devid);
		if (rc)
			dao_err("Failed to close dma dev %u: %s\n", dma_devid, rte_strerror(-rc));
	}
}

static void
release_eth_devices(void)
{
	uint16_t portid;
	int rc;

	/* Stop ports */
	RTE_ETH_FOREACH_DEV(portid) {
		dao_info("Closing port %d...", portid);
		rc = rte_eth_dev_stop(portid);
		if (rc != 0)
			dao_err("Failed to stop port %u: %s\n", portid, rte_strerror(-rc));
		rte_eth_dev_close(portid);
		dao_info(" Done\n");
	}
}

static void
release_pem_device(void)
{
	/* Close PEM */
	dao_pem_dev_fini(rdma_main_cfg->pem_prm->pem_id);
}

/*
 * The main function, which does initialization and cleanup
 */
int
main(int argc, char *argv[])
{
	struct lcore_conf *qconf;
	rdma_cb_t cb = {
		.qp_status_cb = rdma_qp_status_cb,
		.rcu_cb = rdma_rcu_qsbr_synchronize,
		.rdma_map_cb = app_rdma_map_cb,
	};
	uint16_t lcore_id;
	size_t sz;
	int rc;

	dao_info("RDMA application version %s", dao_version());

	/* Init EAL. */
	rc = rte_eal_init(argc, argv);
	if (rc < 0)
		DAO_ERR_GOTO(rc, error, "Invalid EAL arguments\n");

	argc -= rc;
	argv += rc;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Allocate global memory for storing all configurations and parameters */
	mz = rte_memzone_reserve_aligned(RDMA_MAIN_CFG_MZ_NAME, sizeof(struct rdma_main_cfg_data),
					 0, 0, RTE_CACHE_LINE_SIZE);
	if (!mz)
		DAO_ERR_GOTO(-ENOMEM, error, "Failed to reserve mem for main_cfg");

	rdma_main_cfg = mz->addr;

	rc = rdma_mem_allocate();
	if (rc)
		goto fail;

	rdma_main_cfg->force_quit = false;

	/* parse application arguments (after the EAL ones) */
	rc = rdma_parse_args(argc, argv, rdma_main_cfg);
	if (rc < 0)
		DAO_ERR_GOTO(rc, fail, "Invalid RDMA arguments\n");

	/* Configure global DMA flush threshold if provided by CLI */
	dma_flush_thr = rdma_main_cfg->cfg_prm->dma_flush_thr;

	/* Setting up the ethdev ports and queues */
	rc = rdma_ethdev_init(rdma_main_cfg);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to initialize ethernet ports");

	/* Initialize link status monitoring */
	rc = rdma_link_status_init();
	if (rc < 0)
		dao_warn("Failed to initialize link status monitoring: %d", rc);

	/* Setting up DMA devices */
	if (rdma_main_cfg->cfg_prm->termination_enabled) {
		rc = dao_pem_get_sec_strm_id(&rdma_main_cfg->cfg_prm->sec_strm_id);
		if (rc != 0)
			DAO_ERR_GOTO(rc, close_eth, "Failed to get secondary stream id");
	}
	dao_dbg("Sec stream id %u", rdma_main_cfg->cfg_prm->sec_strm_id);
	rc = rdma_dma_init(rdma_main_cfg);
	if (rc)
		DAO_ERR_GOTO(rc, close_eth, "Failed to initialize DMA devices");

	/* PEM init.
	 * ** NOTE ** : Init pem device after ethdev. Mempool allocated in ethdev init are used.
	 */
	rdma_pem_init(rdma_main_cfg);

	dao_rdma_port_alloc(rdma_main_cfg->cfg_prm->num_rport);
	if (dao_rdma_lib_init(&cb, rdma_main_cfg->cfg_prm->disable_cc,
			      rdma_main_cfg->cfg_prm->num_rport) < 0) {
		dao_err("Failed to initialize RDMA library\n");
		goto close_pem;
	}

	/* Initialize heartbeat system after PEM and RDMA library are ready */
	rc = rdma_heartbeat_init();
	if (rc < 0) {
		dao_err("Failed to initialize heartbeat system\n");
		goto close_pem;
	}

	/* Setup RCU QSBR variable */
	sz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
	qs_v = (struct rte_rcu_qsbr *)rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
							 SOCKET_ID_ANY);
	if (!qs_v)
		rte_exit(EXIT_FAILURE, "Failed to alloc rcu_qsbr variable\n");

	rc = rte_rcu_qsbr_init(qs_v, RTE_MAX_LCORE);
	if (rc)
		rte_exit(EXIT_FAILURE, "rte_rcu_qsbr_init(): failed to init, rc=%d\n", rc);

	/* Setting up the ethdev ports and queues */
	rc = rdma_graph_init(rdma_main_cfg);
	if (rc)
		DAO_ERR_GOTO(rc, close_pem, "Failed to setup graphs");

	/* Accumulate and print stats on main until exit */
	if (rdma_main_cfg->cfg_prm->enable_graph_stats && rte_graph_has_stats_feature())
		rdma_graph_print_stats(rdma_main_cfg);

	rc = 0;
	dao_info("Launching worker loops....");
	/* launch per-lcore init on every lcore */
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		qconf = &rdma_main_cfg->lcore_prm->lcore_conf[lcore_id];
		if (qconf->service_lcore)
			rte_eal_remote_launch(service_main_loop, NULL, lcore_id);
		else if (qconf->graph)
			rte_eal_remote_launch(rdma_launch_one_lcore, NULL, lcore_id);
	}

	/* Launch on main lcore if needed */
	qconf = &rdma_main_cfg->lcore_prm->lcore_conf[rte_get_main_lcore()];
	if (qconf->service_lcore)
		service_main_loop(NULL);
	else if (qconf->graph)
		rdma_launch_one_lcore(NULL);

	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		rc = rte_eal_wait_lcore(lcore_id);
		/* Destroy graph */
		qconf = &rdma_main_cfg->lcore_prm->lcore_conf[lcore_id];
		if (rc < 0 || rte_graph_destroy(rte_graph_from_name(qconf[lcore_id].name))) {
			rc = -1;
			break;
		}
	}

	/* Wait for the graph stats thread completion */
	if (rdma_main_cfg->cfg_prm->enable_graph_stats && rte_graph_has_stats_feature())
		rte_thread_join(rdma_main_cfg->graph_prm->graph_stats_thread, NULL);

close_pem:
	rdma_heartbeat_cleanup();
	rdma_link_status_cleanup();
	dao_rdma_lib_close();
	dao_rdma_port_free();
	release_pem_device();
	release_dma_devices();

close_eth:
	release_eth_devices();

fail:
	rdma_cleanup();

	/* clean up the EAL */
	rte_eal_cleanup();

error:
	return rc;
}
