/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include "rdma_init.h"

#include <rte_mbuf.h>

#include "dao_pem.h"
#include "dao_rdma_fp.h"
#include "dao_rdma_mbox.h"
#include "pts_rdma_dev_priv.h"
#include "rdma_priv.h"
#include "rdma_pts_deq_priv.h"
#include "rdma_pts_enq_priv.h"

#define RDMA_PER_LCORE_NB_MBUFS RDMA_DEFAULT_NB_MBUF

extern struct rdma_graph_map rdma_map[RDMA_MAX_DEVS];
extern uint8_t rdma_dma_vchans[RDMA_MAX_DEVS];

static struct rte_mempool *tx_lcore_pools[RTE_MAX_LCORE];

struct rte_mempool *
rdma_tx_lcore_pool_get(uint32_t lcore_id)
{
	if (lcore_id < RTE_MAX_LCORE)
		return tx_lcore_pools[lcore_id];
	return NULL;
}

static struct rte_mempool *
rdma_tx_lcore_pool_create(rdma_ethdev_param_t *eth_prm, rdma_config_param_t *cfg_prm,
			  rdma_lcore_param_t *lcore_prm)
{
	struct rte_mempool *rx_pool = eth_prm->pktmbuf_pool[0][0];
	struct rte_mempool *pool = NULL;
	uint16_t pvt_size, data_room;
	uint32_t per_lcore_mbufs;
	uint16_t nb_workers = 0;
	uint32_t lcore_id;
	char name[64];

	if (!rx_pool)
		rte_exit(EXIT_FAILURE, "NIC RX mbuf pool not created before PEM init\n");

	pvt_size = rte_pktmbuf_priv_size(rx_pool);
	data_room = rx_pool->elt_size - sizeof(struct rte_mbuf) - pvt_size;

	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (!lcore_prm->lcore_conf[lcore_id].service_lcore)
			nb_workers++;
	}

	if (!nb_workers)
		rte_exit(EXIT_FAILURE, "Invalid worker count");

	per_lcore_mbufs = cfg_prm->num_mbufs ? cfg_prm->num_mbufs : RDMA_PER_LCORE_NB_MBUFS;
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (lcore_prm->lcore_conf[lcore_id].service_lcore)
			continue;
		snprintf(name, sizeof(name), "tx_mbuf_pool_lc%u", lcore_id);
		tx_lcore_pools[lcore_id] = rte_pktmbuf_pool_create(
			name, per_lcore_mbufs, RDMA_MEMPOOL_CACHE_SIZE, pvt_size, data_room, 0);
		if (!tx_lcore_pools[lcore_id])
			rte_exit(EXIT_FAILURE, "Can not create per lcore tx mbuf pool");

		if (!pool)
			pool = tx_lcore_pools[lcore_id];
		dao_info("Created tx mbuf pool lcore %u: %u mbufs, priv %u, data_room %u", lcore_id,
			 per_lcore_mbufs, pvt_size, data_room);
	}
	return pool;
}

static inline int
rdma_update_tx_nodes_to_pts_deq(uint16_t devid, rte_node_t id, uint64_t port_mask)
{
	const char *next_nodes;
	char name[32] = {0};
	uint16_t i;
	int rc;

	snprintf(name, sizeof(name), "rdma_pts_deq-%u", devid);

	for (i = 0; port_mask; i++) {
		if (!(port_mask & (1ULL << i)))
			continue;
		port_mask &= ~(1ULL << i);

		sprintf(name, "rdma_eth_tx-%u", i);
		next_nodes = name;

		rc = rte_node_edge_update(id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
		if (rc < 0) {
			printf("Error updating edge for rdma_pts_deq node %u, rc=%d\n", id, rc);
			return rc;
		}
	}

	return 0;
}

int
rdma_pem_init(struct rdma_main_cfg_data *rdma_main_cfg)
{
	struct dao_pts_rdma_dev_conf pts_rdma_conf;
	struct rte_node_register *rdma_node;
	struct rte_node_register *rdma_pts_node;
	struct rte_node_register *node_reg;
	struct dao_pem_dev_conf pem_dev_conf;
	struct dao_pts_rdma_dev_cbs cbs;
	rdma_ethdev_param_t *eth_prm;
	rdma_pemdev_param_t *pem_prm;
	rdma_config_param_t *cfg_prm;
	const char *next_nodes;
	uint8_t pem_devices = 1; /* Default to single PEM device */
	uint8_t num_rport;
	uint32_t dev_mask;
	uint16_t max_vfs;
	uint16_t portid;
	uint16_t devid;

	char name[32];
	int rc;

	eth_prm = rdma_main_cfg->eth_prm;
	pem_prm = rdma_main_cfg->pem_prm;
	cfg_prm = rdma_main_cfg->cfg_prm;

	num_rport = cfg_prm->num_rport;
	dev_mask = cfg_prm->enabled_dev_mask;
	if (!num_rport)
		num_rport = RDMA_MAX_DEVS; /* XXX: Shall get mac rdma port from rdma lib. */

	/* Setup pem0 */
	memset(&pem_dev_conf, 0, sizeof(pem_dev_conf));
	if (cfg_prm->termination_enabled)
		pem_dev_conf.cdev_inuse = 1;
	pem_dev_conf.sdp_inuse = false;
	/* Get Max number of VFs per PEM*/
	pem_prm->pem_id = 0;
	max_vfs = dao_pem_max_vfs_get(pem_prm->pem_id);

	printf("PEM max_vfs %d\n", max_vfs);

	if (num_rport > max_vfs)
		pem_devices = 2;

	for (int i = 0; i < pem_devices; i++) {
		rc = dao_pem_dev_init(i, &pem_dev_conf);
		if (rc) {
			rte_exit(EXIT_FAILURE, "Error with pem init, rc=%d\n", rc);
			return rc;
		}
	}

	memset(&pts_rdma_conf, 0, sizeof(pts_rdma_conf));

	pts_rdma_conf.max_qps_limit = 1024;
	pts_rdma_conf.max_cqs_limit = 1024;

	pts_rdma_conf.data_pool =
		rdma_tx_lcore_pool_create(eth_prm, cfg_prm, rdma_main_cfg->lcore_prm);
	memset(dao_pts_rdma_devs, 0, sizeof(dao_pts_rdma_devs));

	for (devid = 0; devid < RDMA_MAX_DEVS; devid++) {
		if (!(dev_mask & (1 << devid))) {
			printf("Skipping disabled RDMA dev %d\n", devid);
			continue;
		}
		/* Get PEM ID for this device */
		pts_rdma_conf.pem_devid = devid / max_vfs;
		pts_rdma_conf.dma_vchan = rdma_dma_vchans[devid];

		/* Get the mac port id from rdma map */
		portid = rdma_map[devid].id;
		pts_rdma_conf.mac_port_id = eth_prm->host_mac_map[portid].mac_port.port_id;
		printf("RDMA dev %d mac from mapping %d mac port id = %d\n", devid, portid,
		       pts_rdma_conf.mac_port_id);

		if (pts_rdma_conf.mac_port_id == RTE_MAX_ETHPORTS) {
			rte_exit(EXIT_FAILURE, "Invalid RDMA dev %d mac port id\n", devid);
			return -EINVAL;
		}
		rc = dao_pts_rdma_dev_init(devid, &pts_rdma_conf);
		if (rc) {
			rte_exit(EXIT_FAILURE, "Error with rdma dev init, rc=%d\n", rc);
			return rc;
		}

		/* Clone enq/deq nodes for pts rdma dev */
		snprintf(name, sizeof(name), "%u", devid);
		node_reg = rdma_pts_deq_node_get();
		rdma_update_tx_nodes_to_pts_deq(devid, node_reg->id,
						rdma_main_cfg->cfg_prm->enabled_port_mask);
		rdma_pts_deq_nodes[devid] = rte_node_clone(node_reg->id, name);

		node_reg = rdma_pts_enq_node_get();
		rdma_pts_enq_nodes[devid] = rte_node_clone(node_reg->id, name);

		/* Add enq node to rdma process node(s) */
		snprintf(name, sizeof(name), "rdma_pts_enq-%u", devid);
		rdma_node = rdma_node_get();
		rdma_pts_node = rdma_pts_node_get();

		/* Add this enq node as next to both rdma nodes to keep edge order identical */
		next_nodes = name;
		rte_node_edge_update(rdma_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
		rte_node_edge_update(rdma_pts_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
		rc = rdma_set_eth_tx_edge_idx(RTE_MAX_ETHPORTS + devid,
					      rte_node_edge_count(rdma_node->id) - 1);
		printf("Setting eth_tx_edge[%d] = %d for node %s\n", RTE_MAX_ETHPORTS + devid,
		       rte_node_edge_count(rdma_node->id) - 1, name);
		if (rc < 0)
			return rc;
	}

	cbs.user_mbox_cb = dao_rdma_mbox_process;
	cbs.qp_status_cb = NULL;

	dao_pts_rdma_dev_cb_register(&cbs);

	return 0;
}
