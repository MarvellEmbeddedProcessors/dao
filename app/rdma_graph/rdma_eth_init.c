/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <stdlib.h>

#include <rte_branch_prediction.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_flow.h>
#include <rte_interrupts.h>
#include <rte_mbuf.h>
#include <rte_random.h>
#include <rte_string_fns.h>

#include <dao_log.h>
#include <dao_rdma_sp.h>
#include <dao_util.h>

#include "dao_rdma_fp.h"
#include "rdma_eth_rx_priv.h"
#include "rdma_graph.h"
#include "rdma_init.h"
#include "rdma_priv.h"
#include "rdma_pts_deq_priv.h"
#include "rdma_pts_enq_priv.h"
#include "rdma_rss.h"

#define MAX_RTE_FLOW_PATTERN       10
#define MAX_RTE_FLOW_ACTIONS       10
#define RDMA_MBUF_DEFAULT_BUF_SIZE 4228

uint8_t rss_key[48] = {0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d,
		       0x2d, 0x8a, 0x60, 0x6d, 0x1e, 0x9f, 0x5e, 0x4f, 0x3b, 0x7d, 0x4b, 0x3c,
		       0x36, 0x9b, 0x1e, 0x69, 0x7f, 0x6a, 0x0c, 0x2e, 0x2f, 0x5c, 0x28, 0xf3,
		       0x4e, 0x2f, 0x2e, 0x66, 0x1a, 0x3b, 0x9c, 0x7e, 0x4d, 0x2a, 0x5f, 0x11};

struct rdma_graph_map rdma_map[RDMA_MAX_DEVS];
struct rdma_graph_map eth_map[RDMA_MAX_DEVS];

static uint8_t nb_rx_queue;
uint16_t nb_rxd = RDMA_RX_DESC_DEFAULT;
uint16_t nb_txd = RDMA_TX_DESC_DEFAULT;
static struct rte_eth_conf port_conf = {
	.rxmode =
		{
			.mq_mode = RTE_ETH_MQ_RX_RSS,
			//		.offloads = 0x00080000,
			.offloads = RTE_ETH_RX_OFFLOAD_RSS_HASH | RTE_ETH_RX_OFFLOAD_SCATTER,
		},
	.rx_adv_conf =
		{
			.rss_conf =
				{
					.rss_key = rss_key,
					.rss_key_len = sizeof(rss_key),
					.rss_hf =
						RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
				},
		},
};

static void
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];

	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	dao_info("%s%s", name, buf);
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(struct rdma_main_cfg_data *rdma_main_cfg)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	uint16_t portid;
	int rc;
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

	dao_info("Checking link status ...");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (rdma_main_cfg->force_quit)
			return;
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if (rdma_main_cfg->force_quit)
				return;
			memset(&link, 0, sizeof(link));
			rc = rte_eth_link_get_nowait(portid, &link);
			if (rc < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					dao_err("Port %u link get failed: %s", portid,
						rte_strerror(-rc));
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1) {
				rte_eth_link_to_str(link_status_text, sizeof(link_status_text),
						    &link);
				dao_info("Port %d %s", portid, link_status_text);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == RTE_ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			dao_info("done");
		}
	}
}

static int
init_lcore_rx_queues(struct rdma_main_cfg_data *rdma_main_cfg)
{
	rdma_lcore_param_t *lcore_prm = rdma_main_cfg->lcore_prm;
	uint16_t i, rx_queues;
	uint8_t lcore;
	uint8_t port_id;
	uint32_t port_mask = rdma_main_cfg->cfg_prm->enabled_port_mask;

	while (port_mask) {
		port_id = __builtin_ctz(port_mask);
		port_mask &= ~(1 << port_id);
		i = 0;
		RTE_LCORE_FOREACH(lcore) {
			/* Skip main lcore and any lcore pre-marked as service */
			if (lcore == rte_get_main_lcore() ||
			    lcore_prm->lcore_conf[lcore].service_lcore)
				continue;
			rx_queues = lcore_prm->lcore_conf[lcore].n_rx_queue;
			if (rx_queues >= RDMA_MAX_RX_QUEUE_PER_LCORE) {
				dao_err("Error: too many queues (%u) for lcore: %u",
					(uint32_t)rx_queues + 1, (uint32_t)lcore);
				return -1;
			}

			lcore_prm->lcore_conf[lcore].rx_queue_list[rx_queues].port_id = port_id;
			lcore_prm->lcore_conf[lcore].rx_queue_list[rx_queues].queue_id = i;

			dao_dbg("Lcore ID %d port_id %d queueid %d n_rx_queue %d", lcore,
				lcore_prm->lcore_conf[lcore].rx_queue_list[rx_queues].port_id,
				lcore_prm->lcore_conf[lcore].rx_queue_list[rx_queues].queue_id,
				rx_queues);
			lcore_prm->lcore_conf[lcore].n_rx_queue++;
			i++;
		}
	}

	return 0;
}

static int
init_lcore_pts_devs(struct rdma_main_cfg_data *rdma_main_cfg)
{
	uint32_t dev_mask = rdma_main_cfg->cfg_prm->enabled_dev_mask;
	rdma_lcore_param_t *lcore_prm = rdma_main_cfg->lcore_prm;
	uint16_t nb_pts_rdma;
	uint16_t dev_id;
	uint8_t lcore;

	while (dev_mask) {
		dev_id = __builtin_ctz(dev_mask);
		dev_mask &= ~(1 << dev_id);
		RTE_LCORE_FOREACH(lcore) {
			/* Skip main lcore and service lcore */
			if (lcore == rte_get_main_lcore() ||
			    lcore_prm->lcore_conf[lcore].service_lcore)
				continue;
			nb_pts_rdma = lcore_prm->lcore_conf[lcore].nb_pts_rdma_deq;
			dao_dbg("dev id %d\n", dev_id);
			lcore_prm->lcore_conf[lcore].pts_rdma_deq_list[nb_pts_rdma].devid = dev_id;
			lcore_prm->lcore_conf[lcore].pts_rdma_deq_list[nb_pts_rdma].node_ctx = NULL;

			lcore_prm->lcore_conf[lcore].nb_pts_rdma_deq++;
			snprintf(lcore_prm->lcore_conf[lcore]
					 .pts_rdma_deq_list[nb_pts_rdma]
					 .node_name,
				 RTE_NODE_NAMESIZE, "rdma_pts_deq-%u",
				 lcore_prm->lcore_conf[lcore].pts_rdma_deq_list[nb_pts_rdma].devid);

			nb_pts_rdma = lcore_prm->lcore_conf[lcore].nb_pts_rdma_enq;
			lcore_prm->lcore_conf[lcore].pts_rdma_enq_list[nb_pts_rdma].devid = dev_id;
			lcore_prm->lcore_conf[lcore].pts_rdma_enq_list[nb_pts_rdma].node_ctx = NULL;
			lcore_prm->lcore_conf[lcore].nb_pts_rdma_enq++;

			snprintf(lcore_prm->lcore_conf[lcore]
					 .pts_rdma_enq_list[nb_pts_rdma]
					 .node_name,
				 RTE_NODE_NAMESIZE, "rdma_pts_enq-%u",
				 lcore_prm->lcore_conf[lcore].pts_rdma_enq_list[nb_pts_rdma].devid);
		}
	}

	return 0;
}

static uint32_t
eth_dev_get_overhead_len(uint32_t max_rx_pktlen, uint16_t max_mtu)
{
	uint32_t overhead_len;

	if (max_mtu != UINT16_MAX && max_rx_pktlen > max_mtu)
		overhead_len = max_rx_pktlen - max_mtu;
	else
		overhead_len = RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN;

	return overhead_len;
}

int
rdma_config_port_max_pkt_len(rdma_config_param_t *cfg_prm, struct rte_eth_conf *conf,
			     struct rte_eth_dev_info *dev_info)
{
	uint32_t overhead_len;

	if (cfg_prm->max_pkt_len == 0)
		return 0;

	if (cfg_prm->max_pkt_len < RTE_ETHER_MIN_LEN ||
	    cfg_prm->max_pkt_len > RDMA_MAX_JUMBO_PKT_LEN)
		return -1;

	overhead_len = eth_dev_get_overhead_len(dev_info->max_rx_pktlen, dev_info->max_mtu);
	conf->rxmode.mtu = cfg_prm->max_pkt_len - overhead_len;

	if (conf->rxmode.mtu > RTE_ETHER_MTU)
		conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

	return 0;
}

static int
init_mem(struct rdma_main_cfg_data *rdma_main_cfg, uint16_t portid, uint32_t nb_mbuf)
{
	rdma_ethdev_param_t *eth_prm;
	uint32_t lcore_id;
	int socketid;
	char s[64];

	eth_prm = rdma_main_cfg->eth_prm;
	rdma_config_param_t *cfg_prm = rdma_main_cfg->cfg_prm;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		if (eth_prm->numa_on)
			socketid = rte_lcore_to_socket_id(lcore_id);
		else
			socketid = 0;

		if (socketid >= RDMA_NB_SOCKETS) {
			DAO_ERR_GOTO(-EINVAL, fail, "Socket %d of lcore %u is out of range %d",
				     socketid, lcore_id, RDMA_NB_SOCKETS);
		}
		uint32_t pvt_size = dao_rdma_get_pvt_len();

		pvt_size = RTE_CACHE_LINE_ROUNDUP(pvt_size);
		dao_info("PVT AREA SIZE: %u", pvt_size);

		if (eth_prm->pktmbuf_pool[portid][socketid] == NULL) {
			snprintf(s, sizeof(s), "mbuf_pool_%d:%d", portid, socketid);
			/* Create a pool with priv size of a cacheline */
			uint32_t data_room = cfg_prm->mbuf_data_size ? cfg_prm->mbuf_data_size :
								       RDMA_MBUF_DEFAULT_BUF_SIZE;
			/* num mbufs: use override if provided, else nb_mbuf passed by caller */
			uint32_t pool_mbufs = cfg_prm->num_mbufs ? cfg_prm->num_mbufs : nb_mbuf;

			dao_info("Creating mbuf pool %s on socket %d with %u mbufs, "
				 "data room size %u, pvt size %u",
				 s, socketid, pool_mbufs, data_room, pvt_size);
			eth_prm->pktmbuf_pool[portid][socketid] =
				rte_pktmbuf_pool_create(s, pool_mbufs, RDMA_MEMPOOL_CACHE_SIZE,
							pvt_size, data_room, socketid);
			if (eth_prm->pktmbuf_pool[portid][socketid] == NULL)
				DAO_ERR_GOTO(-EINVAL, fail, "Cannot init mbuf pool on socket %d",
					     socketid);
		}
	}

	return 0;
fail:
	return errno;
}

static int
port_init(struct rdma_main_cfg_data *rdma_main_cfg, uint16_t portid, uint16_t nb_lcores)
{
	struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
	struct rte_ether_addr dest_eth_addr[RTE_MAX_ETHPORTS];
	uint32_t n_tx_queue, queueid, lcore_id;
	struct rte_eth_conf local_port_conf = port_conf;
	struct rte_eth_dev_info dev_info;
	uint8_t socketid;
	struct rte_eth_txconf *txconf;
	rdma_config_param_t *cfg_prm;
	int rc;

	RTE_SET_USED(nb_lcores);
	cfg_prm = rdma_main_cfg->cfg_prm;

	/* Init port */
	dao_dbg("Initializing port %d ... ", portid);
	/* Use number of worker lcores for TX queues to keep 1:1 mapping with RX queues */
	n_tx_queue = nb_rx_queue;
	if (n_tx_queue > RDMA_MAX_TX_QUEUE_PER_PORT)
		n_tx_queue = RDMA_MAX_TX_QUEUE_PER_PORT;
	dao_dbg("Creating queues: nb_rxq=%d nb_txq=%u... ", nb_rx_queue, n_tx_queue);

	rc = rte_eth_dev_info_get(portid, &dev_info);

	rc = rdma_config_port_max_pkt_len(rdma_main_cfg->cfg_prm, &local_port_conf, &dev_info);
	if (rc != 0)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid max packet length: %u (port %u)",
			     cfg_prm->max_pkt_len, portid);

	local_port_conf.txmode.offloads |=
		RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM;

	local_port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
	if (local_port_conf.rx_adv_conf.rss_conf.rss_hf != port_conf.rx_adv_conf.rss_conf.rss_hf) {
		dao_info("Port %u modified RSS hash function based on "
			 "hardware support,"
			 "requested:%#" PRIx64 " configured:%#" PRIx64 "",
			 portid, port_conf.rx_adv_conf.rss_conf.rss_hf,
			 local_port_conf.rx_adv_conf.rss_conf.rss_hf);
	}

	rc = rte_eth_dev_configure(portid, nb_rx_queue, n_tx_queue, &local_port_conf);
	if (rc < 0)
		DAO_ERR_GOTO(-EINVAL, fail, "Cannot configure device: err=%d, port=%d", rc, portid);

	rc = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
	if (rc < 0)
		DAO_ERR_GOTO(-EINVAL, fail,
			     "Cannot adjust number of descriptors: err=%d, "
			     "port=%d",
			     rc, portid);

	rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
	print_ethaddr(" MAC Addresses - Source:", &ports_eth_addr[portid]);
	rte_eth_macaddr_get(rdma_ethdev_port_pair_get(rdma_main_cfg->eth_prm->host_mac_map, portid),
			    &dest_eth_addr[portid]);
	print_ethaddr(" Destination:", (const struct rte_ether_addr *)&dest_eth_addr[portid]);

	uint32_t eff_nb_mbuf = cfg_prm->num_mbufs ? cfg_prm->num_mbufs : RDMA_DEFAULT_NB_MBUF;
	/* Init memory */
	if (!cfg_prm->per_port_pool) {
		/* portid = 0; this is *not* signifying the first port,
		 * rather, it signifies that portid is ignored.
		 */
		rc = init_mem(rdma_main_cfg, 0, eff_nb_mbuf);
	} else {
		rc = init_mem(rdma_main_cfg, portid, eff_nb_mbuf);
	}
	if (rc < 0)
		DAO_ERR_GOTO(-EINVAL, fail, "init_mem() failed");

	/* Init one TX queue per worker (skip main and service lcores) */
	queueid = 0;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		/* Skip main and service lcores: TX queues are dedicated to workers */
		if (lcore_id == rte_get_main_lcore() ||
		    rdma_main_cfg->lcore_prm->lcore_conf[lcore_id].service_lcore)
			continue;

		if (rdma_main_cfg->eth_prm->numa_on)
			socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);
		else
			socketid = 0;

		dao_dbg("worker lcore=%u, portid=%d txq=%d, sockid=%d ", lcore_id, portid, queueid,
			socketid);

		txconf = &dev_info.default_txconf;
		txconf->offloads = local_port_conf.txmode.offloads;
		rc = rte_eth_tx_queue_setup(portid, queueid, nb_txd, socketid, txconf);
		if (rc < 0)
			DAO_ERR_GOTO(-EINVAL, fail,
				     "rte_eth_tx_queue_setup: err=%d, "
				     "port=%d",
				     rc, portid);
		queueid++;
		/* Set total_rx_queue for this worker */
		rdma_main_cfg->lcore_prm->lcore_conf[lcore_id].total_rx_queue = nb_rx_queue;
		if (queueid >= n_tx_queue)
			break;
	}

	/* Setup ethdev node config */
	rdma_eth_node_config(rdma_main_cfg, portid, nb_rx_queue, n_tx_queue);

	return 0;
fail:
	return errno;
}

static int
eth_rx_queue_setup(struct rdma_main_cfg_data *rdma_main_cfg, uint16_t lcore_id)
{
	struct rte_eth_dev_info dev_info;
	rdma_ethdev_param_t *eth_prm;
	uint16_t queueid, portid;
	uint8_t queue, socketid;
	struct lcore_conf *qconf;
	int rc;

	qconf = &rdma_main_cfg->lcore_prm->lcore_conf[lcore_id];
	eth_prm = rdma_main_cfg->eth_prm;
	/* Init RX queues */

	for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
		struct rte_eth_rxconf rxq_conf;

		portid = qconf->rx_queue_list[queue].port_id;
		queueid = qconf->rx_queue_list[queue].queue_id;

		if (eth_prm->numa_on)
			socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);
		else
			socketid = 0;

		dao_dbg("    portid=%d, rxq=%d, sockid=%d", portid, queueid, socketid);
		fflush(stdout);

		rc = rte_eth_dev_info_get(portid, &dev_info);
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = port_conf.rxmode.offloads;
		if (!rdma_main_cfg->cfg_prm->per_port_pool)
			rc = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, socketid, &rxq_conf,
						    eth_prm->pktmbuf_pool[0][socketid]);
		else
			rc = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, socketid, &rxq_conf,
						    eth_prm->pktmbuf_pool[portid][socketid]);
		if (rc < 0)
			DAO_ERR_GOTO(-EINVAL, fail,
				     "rte_eth_rx_queue_setup: err=%d, "
				     "port=%d",
				     rc, portid);

		/* Add this queue node to its graph */
		snprintf(qconf->rx_queue_list[queue].node_name, RTE_NODE_NAMESIZE,
			 "rdma_eth_rx-%u-%u", portid, queueid);
	}
	/* Alloc a graph to this lcore only if source exists  */
	if (qconf->n_rx_queue)
		rdma_main_cfg->graph_prm->nb_graphs++;

	return 0;
fail:
	return errno;
}

struct rdma_ethdev_port_info *
rdma_ethdev_port_info_get(uint16_t portid)
{
	struct rdma_main_cfg_data *rdma_main_cfg;
	struct rdma_ethdev_param *eth_prm;
	const struct rte_memzone *mz;
	uint16_t i;

	mz = rte_memzone_lookup(RDMA_MAIN_CFG_MZ_NAME);
	if (!mz) {
		dao_err("Failed to lookup for main_cfg, err %d", rte_errno);
		return NULL;
	}
	rdma_main_cfg = mz->addr;
	eth_prm = rdma_main_cfg->eth_prm;

	for (i = 0; i < (RTE_MAX_ETHPORTS / 2); i++) {
		if (eth_prm->host_mac_map[i].mac_port.port_id == portid)
			return &eth_prm->host_mac_map[i].mac_port;
	}

	return NULL;
}

uint16_t
rdma_ethdev_port_pair_get(rdma_ethdev_host_mac_map_t *host_mac_map, uint16_t portid)
{
	RTE_SET_USED(host_mac_map);
	return portid;
}

static struct rte_flow *
port_rss_flow_create(uint16_t portid)
{
	struct rte_flow_item pattern[MAX_RTE_FLOW_PATTERN] = {};
	struct rte_flow_action action[MAX_RTE_FLOW_ACTIONS] = {};
	struct rte_flow_action_rss *rss_conf;
	int pattern_idx = 0, act_idx = 0;
	struct rte_flow_attr attr = {};
	struct rte_flow_error err = {};
	uint16_t *queue_arr = NULL;
	uint32_t i;

	/* Define attributes */
	attr.egress = 0;
	attr.ingress = 1;

	/* Define patterns */
	pattern[pattern_idx].type = RTE_FLOW_ITEM_TYPE_IB_BTH;
	pattern[pattern_idx].spec = NULL;
	pattern[pattern_idx].mask = NULL;
	pattern[pattern_idx].last = NULL;
	pattern_idx++;
	pattern[pattern_idx].type = RTE_FLOW_ITEM_TYPE_END;

	rss_conf = calloc(1, sizeof(struct rte_flow_action_rss));
	if (!rss_conf)
		rte_exit(EXIT_FAILURE, "Failed to allocate memory for rss conf");

	/* Define Action */
	/* Add RSS action */
	action[act_idx].type = RTE_FLOW_ACTION_TYPE_RSS;
	rss_conf->queue_num = nb_rx_queue;
	queue_arr = calloc(1, rss_conf->queue_num * sizeof(uint16_t));
	if (!queue_arr)
		rte_exit(EXIT_FAILURE, "Failed to allocate memory for rss queue");

	dao_info("port: %u, rss_conf->queue_num: %u", portid, rss_conf->queue_num);

	for (i = 0; i < rss_conf->queue_num; i++)
		queue_arr[i] = i;

	rss_conf->queue = queue_arr;
	rss_conf->key = rss_key;
	rss_conf->key_len = sizeof(rss_key);
	rss_conf->types = RTE_ETH_RSS_IB_BTH;

	action[act_idx].conf = (struct rte_flow_action_rss *)rss_conf;
	action[act_idx].type = RTE_FLOW_ACTION_TYPE_RSS;

	/* End action */
	act_idx++;
	action[act_idx].type = RTE_FLOW_ACTION_TYPE_END;
	action[act_idx].conf = NULL;

	return rte_flow_create(portid, &attr, pattern, action, &err);
}

static inline int
rdma_create_ethdev_port_map(rdma_ethdev_host_mac_map_t *host_mac_map, uint32_t port_mask,
			    uint16_t *nb_ports, uint32_t dev_mask, int rdma_map_config_enable)
{
	uint16_t mac_ports[RTE_MAX_ETHPORTS];
	uint16_t portid, j = 0;

	RTE_ETH_FOREACH_DEV(portid) {
		if (port_mask & (1 << portid)) {
			dao_dbg("Mac port %d\n", portid);
			mac_ports[j++] = portid;
		}
	}

	if (j == 0) {
		dao_err("Error: no mac ports found");
		return -1;
	}

	*nb_ports = j;

	if (rdma_map_config_enable) {
		for (portid = 0; portid < *nb_ports; portid++) {
			uint16_t rdma_devid = eth_map[portid].id;

			host_mac_map[portid].mac_port.port_id = mac_ports[portid];
			if (!(dev_mask & (1 << rdma_devid))) {
				dao_err("Error: RDMA device %d not enabled in config", rdma_devid);
				return -1;
			}
		}
	} else {
		for (portid = 0; portid < *nb_ports; portid++)
			host_mac_map[portid].mac_port.port_id = mac_ports[portid];
	}

	for (int i = 0; i < *nb_ports; i++)
		dao_dbg("Mac port %d\n", host_mac_map[i].mac_port.port_id);

	return 0;
}

int
rdma_ethdev_init(struct rdma_main_cfg_data *rdma_main_cfg)
{
	uint16_t nb_ports, lcore_id, nb_lcores = 0;
	uint16_t nb_ports_available = 0;
	uint16_t mac_port;
	rdma_ethdev_param_t *eth_prm;
	rdma_config_param_t *cfg_prm;
	uint16_t rdma_devid = 0;
	uint32_t dev_mask;
	uint16_t portid;
	int rc, idx;

	eth_prm = rdma_main_cfg->eth_prm;
	cfg_prm = rdma_main_cfg->cfg_prm;

	dev_mask = cfg_prm->enabled_dev_mask;

	eth_prm->numa_on = 1;

	/* Determine total enabled lcores and pre-select one service lcore (not main). */
	nb_lcores = rte_lcore_count();
	uint16_t main_lcore = rte_get_main_lcore();
	uint16_t service_lcore_id = RTE_MAX_LCORE;

	RTE_LCORE_FOREACH(lcore_id) {
		if (lcore_id == main_lcore)
			continue;
		service_lcore_id = lcore_id;
		break;
	}
	if (service_lcore_id == RTE_MAX_LCORE)
		DAO_ERR_GOTO(-EINVAL, fail, "No available lcore for service thread");
	rdma_main_cfg->lcore_prm->lcore_conf[service_lcore_id].service_lcore = true;

	/* With 1 main + 1 service, remaining are RX workers. */
	uint16_t nb_workers = (nb_lcores >= 2) ? (nb_lcores - 2) : 0;

	nb_rx_queue = nb_workers;

	rc = init_lcore_rx_queues(rdma_main_cfg);
	if (rc < 0)
		DAO_ERR_GOTO(-EINVAL, fail, "init_lcore_rx_queues() failed");

	rc = init_lcore_pts_devs(rdma_main_cfg);
	if (rc < 0)
		DAO_ERR_GOTO(-EINVAL, fail, "init_lcore_pts_devs() failed");

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		DAO_ERR_GOTO(-EINVAL, fail, "No Ethernet ports - bye");

	/* reset host_mac_map */
	memset(eth_prm->host_mac_map, 0, sizeof(eth_prm->host_mac_map));
	if (rdma_create_ethdev_port_map(
		    rdma_main_cfg->eth_prm->host_mac_map, rdma_main_cfg->cfg_prm->enabled_port_mask,
		    &eth_prm->nb_ports, dev_mask, cfg_prm->rdma_map_config_enable))
		return -1;

	rdma_main_cfg->graph_prm->fm_ctrl_cfg.nb_ports = eth_prm->nb_ports;
	for (portid = 0; portid < eth_prm->nb_ports; portid++) {
		mac_port = eth_prm->host_mac_map[portid].mac_port.port_id;
		rdma_main_cfg->graph_prm->fm_ctrl_cfg.host_mac_map[portid] = mac_port;
	}

	rdma_main_cfg->graph_prm->fm_ctrl_cfg.active_host_ports = eth_prm->nb_ports;

	/* Initialize all ports */
	RTE_ETH_FOREACH_DEV(portid) {
		dao_info("port ID %d", portid);
		rc = port_init(rdma_main_cfg, portid, nb_lcores);
		if (rc)
			DAO_ERR_GOTO(rc, fail, "Failed to init port %d", portid);
		for (idx = 0; idx < eth_prm->nb_ports; idx++) {
			if (eth_prm->host_mac_map[idx].mac_port.port_id == portid)
				eth_prm->host_mac_map[idx].mac_port.nb_rxq = nb_rx_queue;
		}
		nb_ports_available++;
	}

	/* RDMA forwarding table */
	for (portid = 0; portid < eth_prm->nb_ports; portid++) {
		mac_port = eth_prm->host_mac_map[portid].mac_port.port_id;
		rdma_devid = eth_map[portid].id;

		rdma_main_cfg->graph_prm->fm_ctrl_cfg.rdma_port_map[mac_port] =
			RTE_MAX_ETHPORTS + rdma_devid;
		rdma_main_cfg->graph_prm->fm_ctrl_cfg.rdma_port_map[RTE_MAX_ETHPORTS + rdma_devid] =
			mac_port;
		dao_dbg("Port %d, mac_port %d, rdma_port %d", portid, mac_port, rdma_devid);
	}

	if (!nb_ports_available) {
		DAO_ERR_GOTO(-EINVAL, fail,
			     "All available ports are disabled. Please set portmask.");
	}

	/* Setting up the RX queue */
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0 || lcore_id == rte_get_main_lcore())
			continue;
		dao_dbg("\nInitializing rx queues on lcore %u ...", lcore_id);

		rc = eth_rx_queue_setup(rdma_main_cfg, lcore_id);
		if (rc)
			DAO_ERR_GOTO(rc, fail, "Failed to setup RX queue for lcore %d", lcore_id);
	}

	if (cfg_prm->pfc_tc >= 0) {
		RTE_ETH_FOREACH_DEV(portid) {
			struct rte_eth_pfc_queue_conf pfc_conf;
			struct rte_eth_dev_info pfc_dev_info;
			struct rte_eth_fc_conf fc_off;
			uint16_t queue;

			memset(&fc_off, 0, sizeof(fc_off));
			fc_off.mode = RTE_ETH_FC_NONE;
			rc = rte_eth_dev_flow_ctrl_set(portid, &fc_off);
			if (rc < 0)
				rte_exit(EXIT_FAILURE,
					 "Port %u: failed to disable flow control (%d): %s\n",
					 portid, rc, rte_strerror(-rc));

			rc = rte_eth_dev_info_get(portid, &pfc_dev_info);
			if (rc < 0)
				rte_exit(EXIT_FAILURE, "Port %u: dev_info_get failed (%d)\n",
					 portid, rc);

			for (queue = 0; queue < pfc_dev_info.nb_rx_queues; queue++) {
				memset(&pfc_conf, 0, sizeof(pfc_conf));
				pfc_conf.mode = RTE_ETH_FC_TX_PAUSE;
				pfc_conf.tx_pause.rx_qid = queue;
				pfc_conf.tx_pause.tc = cfg_prm->pfc_tc;
				pfc_conf.tx_pause.pause_time = cfg_prm->pfc_pause_time;

				rc = rte_eth_dev_priority_flow_ctrl_queue_configure(portid,
										    &pfc_conf);
				if (rc < 0)
					rte_exit(EXIT_FAILURE,
						 "Port %u queue%u: PFC config failed (%d): %s\n",
						 portid, queue, rc, rte_strerror(-rc));
			}
			dao_info("Port %u: PFC enabled on TC %d for %u RX queues", portid,
				 cfg_prm->pfc_tc, pfc_dev_info.nb_rx_queues);
		}
	}

	/* Start ports */
	RTE_ETH_FOREACH_DEV(portid) {
		/* Start device */
		rc = rte_eth_dev_start(portid);
		if (rc < 0)
			DAO_ERR_GOTO(-EINVAL, fail, "rte_eth_dev_start: err=%d, port=%d", rc,
				     portid);

		/* Display the port MAC address. */
		struct rte_ether_addr addr;

		rc = rte_eth_macaddr_get(portid, &addr);
		if (rc != 0)
			return rc;

		dao_info("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			 " %02" PRIx8 " %02" PRIx8,
			 portid, RTE_ETHER_ADDR_BYTES(&addr));

		/*
		 * If enabled, put device in promiscuous mode.
		 * This allows IO forwarding mode to forward packets
		 * to itself through 2 cross-connected  ports of the
		 * target machine.
		 */
		if (cfg_prm->promiscuous_on)
			rte_eth_promiscuous_enable(portid);

		/* Flow for port based RSS */
		if (!port_rss_flow_create(portid))
			rte_exit(EXIT_FAILURE, "Cannot create RSS flow: err=%d, port=%d\n", errno,
				 portid);

		rc = rdma_rss_cache_port(portid);
		if (rc)
			dao_warn("Failed to cache RETA for port %u: %s", portid, rte_strerror(-rc));
	}

	check_all_ports_link_status(rdma_main_cfg);

	return 0;
fail:
	return errno;
}
