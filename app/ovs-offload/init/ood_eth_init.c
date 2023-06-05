/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <rte_branch_prediction.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_interrupts.h>
#include <rte_mbuf.h>
#include <rte_random.h>
#include <rte_string_fns.h>

#include <dao_log.h>
#include <dao_util.h>

#include <ood_graph.h>
#include <ood_init.h>

static struct lcore_params lcore_params_array_default[] = {
	{0, 0, 2}, {0, 1, 2}, {0, 2, 2}, {1, 0, 2}, {1, 1, 2},
	{1, 2, 2}, {2, 0, 2}, {3, 0, 3}, {3, 1, 3},
};

static uint16_t nb_lcore_params;
static struct lcore_params *lcore_params;

uint16_t nb_rxd = OOD_RX_DESC_DEFAULT;
uint16_t nb_txd = OOD_TX_DESC_DEFAULT;
static struct rte_eth_conf port_conf = {
	.rxmode = {
			.mq_mode = RTE_ETH_MQ_RX_RSS,
		},
	.rx_adv_conf = {
			.rss_conf = {
					.rss_key = NULL,
					.rss_hf = RTE_ETH_RSS_IP,
				},
		},
	.txmode = {
			.mq_mode = RTE_ETH_MQ_TX_NONE,
		},
};

/*
 * Check port pair config with enabled port mask,
 * and for valid port pair combinations.
 */
static int
check_port_pair_config(ood_config_param_t *cfg_prm)
{
	uint32_t port_pair_config_mask = 0;
	uint32_t port_pair_mask = 0;
	uint16_t index, i, portid;

	for (index = 0; index < cfg_prm->nb_port_pair_params; index++) {
		port_pair_mask = 0;

		for (i = 0; i < NUM_PORTS; i++) {
			portid = cfg_prm->port_pair_param[index].port[i];
			if ((cfg_prm->enabled_port_mask & (1 << portid)) == 0) {
				dao_err("port %u is not enabled in port mask", portid);
				return -1;
			}

			if (!rte_eth_dev_is_valid_port(portid)) {
				dao_err("port %u is not present on the board", portid);
				return -1;
			}

			port_pair_mask |= 1 << portid;
		}

		if (port_pair_config_mask & port_pair_mask) {
			dao_err("port %u is used in other port pairs", portid);
			return -1;
		}
		port_pair_config_mask |= port_pair_mask;
	}

	cfg_prm->enabled_port_mask &= port_pair_config_mask;

	return 0;
}

static void
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];

	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(struct ood_main_cfg_data *ood_main_cfg)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	uint16_t portid;
	int rc;
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

	printf("\nChecking link status\n");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (ood_main_cfg->force_quit)
			return;
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if (ood_main_cfg->force_quit)
				return;
			if (portid == ood_repr_get_eswitch_portid(ood_main_cfg))
				continue;
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
				printf("Port %d %s\n", portid, link_status_text);
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
			printf("done\n");
		}
	}
}

static int
check_lcore_params(struct ood_main_cfg_data *ood_main_cfg)
{
	uint8_t queue, lcore;
	int socketid;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		queue = lcore_params[i].queue_id;
		if (queue >= OOD_MAX_RX_QUEUE_PER_PORT) {
			dao_err("Invalid queue number: %u", queue);
			return -1;
		}
		lcore = lcore_params[i].lcore_id;
		if (!rte_lcore_is_enabled(lcore)) {
			dao_err("Error: lcore %u is not enabled in lcore mask", lcore);
			return -1;
		}

		if (lcore == rte_get_main_lcore()) {
			dao_err("Error: lcore %u is main lcore", lcore);
			return -1;
		}
		socketid = rte_lcore_to_socket_id(lcore);
		if ((socketid != 0) && (ood_main_cfg->eth_prm->numa_on == 0)) {
			dao_warn("Warning: lcore %u is on socket %d with numa off", lcore,
				 socketid);
		}
	}

	return 0;
}

static int
check_port_config(ood_config_param_t *cfg_prm)
{
	uint16_t portid;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		portid = lcore_params[i].port_id;
		if ((cfg_prm->enabled_port_mask & (1 << portid)) == 0) {
			dao_err("Port %u is not enabled in port mask", portid);
			return -1;
		}
		if (!rte_eth_dev_is_valid_port(portid)) {
			dao_err("Port %u is not present on the board", portid);
			return -1;
		}
	}

	return 0;
}

static uint8_t
get_port_n_rx_queues(const uint16_t port)
{
	int queue = -1;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		if (lcore_params[i].port_id == port) {
			if (lcore_params[i].queue_id == queue + 1)
				queue = lcore_params[i].queue_id;
			else
				DAO_ERR_GOTO(-EINVAL, fail,
					     "Queue ids of the port %d must be"
					     " in sequence and must start with 0",
					     lcore_params[i].port_id);
		}
	}

	return (uint8_t)(++queue);
fail:
	return errno;
}

static int
init_lcore_rx_queues(ood_lcore_param_t *lcore_prm)
{
	uint16_t i, nb_rx_queue;
	uint8_t lcore;

	for (i = 0; i < nb_lcore_params; ++i) {
		lcore = lcore_params[i].lcore_id;
		nb_rx_queue = lcore_prm->lcore_conf[lcore].n_rx_queue;
		if (nb_rx_queue >= OOD_MAX_RX_QUEUE_PER_LCORE) {
			dao_err("Error: too many queues (%u) for lcore: %u",
				(uint32_t)nb_rx_queue + 1, (uint32_t)lcore);
			return -1;
		}

		lcore_prm->lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id =
			lcore_params[i].port_id;
		lcore_prm->lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id =
			lcore_params[i].queue_id;
		dao_dbg("Lcore ID %d port_id %d queueid %d n_rx_queue %d", lcore,
			lcore_prm->lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id,
			lcore_prm->lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id,
			nb_rx_queue);
		lcore_prm->lcore_conf[lcore].n_rx_queue++;
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
ood_config_port_max_pkt_len(ood_config_param_t *cfg_prm, struct rte_eth_conf *conf,
			    struct rte_eth_dev_info *dev_info)
{
	uint32_t overhead_len;

	if (cfg_prm->max_pkt_len == 0)
		return 0;

	if (cfg_prm->max_pkt_len < RTE_ETHER_MIN_LEN ||
	    cfg_prm->max_pkt_len > OOD_MAX_JUMBO_PKT_LEN)
		return -1;

	overhead_len = eth_dev_get_overhead_len(dev_info->max_rx_pktlen, dev_info->max_mtu);
	conf->rxmode.mtu = cfg_prm->max_pkt_len - overhead_len;

	if (conf->rxmode.mtu > RTE_ETHER_MTU)
		conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

	return 0;
}

static int
init_mem(struct ood_main_cfg_data *ood_main_cfg, uint16_t portid, uint32_t nb_mbuf)
{
	ood_ethdev_param_t *eth_prm;
	uint32_t lcore_id;
	int socketid;
	char s[64];

	eth_prm = ood_main_cfg->eth_prm;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		if (eth_prm->numa_on)
			socketid = rte_lcore_to_socket_id(lcore_id);
		else
			socketid = 0;

		if (socketid >= OOD_NB_SOCKETS) {
			DAO_ERR_GOTO(-EINVAL, fail, "Socket %d of lcore %u is out of range %d",
				     socketid, lcore_id, OOD_NB_SOCKETS);
		}

		if (eth_prm->pktmbuf_pool[portid][socketid] == NULL) {
			snprintf(s, sizeof(s), "mbuf_pool_%d:%d", portid, socketid);
			/* Create a pool with priv size of a cacheline */
			eth_prm->pktmbuf_pool[portid][socketid] = rte_pktmbuf_pool_create(
				s, nb_mbuf, OOD_MEMPOOL_CACHE_SIZE, RTE_CACHE_LINE_SIZE,
				RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
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
port_init(struct ood_main_cfg_data *ood_main_cfg, uint16_t portid, uint16_t nb_lcores)
{
	struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
	struct rte_ether_addr dest_eth_addr[RTE_MAX_ETHPORTS];
	uint32_t n_tx_queue, nb_ports, queueid, lcore_id;
	struct rte_eth_conf local_port_conf = port_conf;
	struct rte_eth_dev_info dev_info;
	uint8_t nb_rx_queue, socketid;
	struct rte_eth_txconf *txconf;
	ood_config_param_t *cfg_prm;
	int rc;

	cfg_prm = ood_main_cfg->cfg_prm;

	/* Init port */
	dao_dbg("Initializing port %d ... ", portid);
	nb_rx_queue = get_port_n_rx_queues(portid);
	n_tx_queue = nb_lcores;
	if (n_tx_queue > OOD_MAX_TX_QUEUE_PER_PORT)
		n_tx_queue = OOD_MAX_TX_QUEUE_PER_PORT;
	dao_dbg("Creating queues: nb_rxq=%d nb_txq=%u... ", nb_rx_queue, n_tx_queue);

	rte_eth_dev_info_get(portid, &dev_info);

	rc = ood_config_port_max_pkt_len(ood_main_cfg->cfg_prm, &local_port_conf, &dev_info);
	if (rc != 0)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid max packet length: %u (port %u)",
			     cfg_prm->max_pkt_len, portid);

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

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
		DAO_ERR_GOTO(-EINVAL, fail, "Cannot configure device: err=%d, port=%d", rc,
			     portid);

	rc = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
	if (rc < 0)
		DAO_ERR_GOTO(-EINVAL, fail,
			     "Cannot adjust number of descriptors: err=%d, "
			     "port=%d",
			     rc, portid);

	rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
	print_ethaddr(" MAC Addresses - Source:", &ports_eth_addr[portid]);
	printf(", ");
	rte_eth_macaddr_get(ood_ethdev_port_pair_get(ood_main_cfg->eth_prm->host_mac_map, portid),
			    &dest_eth_addr[portid]);
	print_ethaddr(" Destination:", (const struct rte_ether_addr *)&dest_eth_addr[portid]);

	nb_ports = rte_eth_dev_count_avail();
	/* Init memory */
	if (!cfg_prm->per_port_pool) {
		/* portid = 0; this is *not* signifying the first port,
		 * rather, it signifies that portid is ignored.
		 */
		rc = init_mem(ood_main_cfg, 0, OOD_NB_MBUF(nb_ports));
	} else {
		rc = init_mem(ood_main_cfg, portid, OOD_NB_MBUF(1));
	}
	if (rc < 0)
		DAO_ERR_GOTO(-EINVAL, fail, "init_mem() failed");

	/* Init one TX queue per couple (lcore,port) */
	queueid = 0;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		if (ood_main_cfg->eth_prm->numa_on)
			socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);
		else
			socketid = 0;

		dao_dbg("lcore=%u, portid=%d txq=%d, sockid=%d ", lcore_id, portid, queueid,
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
	}

	/* Setup ethdev node config */
	ood_eth_node_config(ood_main_cfg, portid, nb_rx_queue, n_tx_queue);

	return 0;
fail:
	return errno;
}

static int
eth_rx_queue_setup(struct ood_main_cfg_data *ood_main_cfg, uint16_t lcore_id)
{
	struct rte_eth_dev_info dev_info;
	ood_ethdev_param_t *eth_prm;
	uint16_t queueid, portid;
	uint8_t queue, socketid;
	struct lcore_conf *qconf;
	int rc;

	qconf = &ood_main_cfg->lcore_prm->lcore_conf[lcore_id];
	eth_prm = ood_main_cfg->eth_prm;
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

		rte_eth_dev_info_get(portid, &dev_info);
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = port_conf.rxmode.offloads;
		if (!ood_main_cfg->cfg_prm->per_port_pool)
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
			 "ood_eth_rx-%u-%u", portid, queueid);
	}
	/* Alloc a graph to this lcore only if source exists  */
	if (qconf->n_rx_queue)
		ood_main_cfg->graph_prm->nb_graphs++;

	return 0;
fail:
	return errno;
}

static uint8_t
is_host_port(uint16_t portid)
{
	struct rte_eth_dev_info dev_info;
	const char *info;

	rte_eth_dev_info_get(portid, &dev_info);

	info = rte_dev_bus_info(dev_info.device);
	return (strstr(info, "a0f7") != NULL);
}

uint16_t
ood_ethdev_port_pair_get(struct ood_ethdev_host_mac_map *host_mac_map, uint16_t portid)
{
	uint16_t i;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (host_mac_map[i].host_port == portid)
			return host_mac_map[i].mac_port;
		if (host_mac_map[i].mac_port == portid)
			return host_mac_map[i].host_port;
	}

	return i;
}

int
ood_ethdev_init(struct ood_main_cfg_data *ood_main_cfg)
{
	uint16_t portid, last_port, nb_ports_in_mask = 0;
	uint16_t nb_ports, lcore_id, nb_lcores = 0;
	char if_name[RTE_ETH_NAME_MAX_LEN];
	uint16_t nb_ports_available = 0;
	uint16_t host_port, mac_port;
	ood_lcore_param_t *lcore_prm;
	ood_ethdev_param_t *eth_prm;
	ood_config_param_t *cfg_prm;
	int rc, i = 0;

	eth_prm = ood_main_cfg->eth_prm;
	cfg_prm = ood_main_cfg->cfg_prm;
	lcore_prm = ood_main_cfg->lcore_prm;

	if (lcore_prm->nb_lcore_params) {
		/* User configured lcore params */
		lcore_params = lcore_prm->lcore_params_array;
		nb_lcore_params = lcore_prm->nb_lcore_params;
	} else {
		/* Default lcore params */
		nb_lcore_params = RTE_DIM(lcore_params_array_default);
		lcore_params = lcore_params_array_default;
	}

	eth_prm->numa_on = 1;
	if (check_lcore_params(ood_main_cfg) < 0)
		DAO_ERR_GOTO(-EFAULT, fail, "check_lcore_params() failed");

	rc = init_lcore_rx_queues(ood_main_cfg->lcore_prm);
	if (rc < 0)
		DAO_ERR_GOTO(-EINVAL, fail, "init_lcore_rx_queues() failed");

	if (check_port_config(ood_main_cfg->cfg_prm) < 0)
		DAO_ERR_GOTO(-EINVAL, fail, "check_port_config() failed");

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		DAO_ERR_GOTO(-EINVAL, fail, "No Ethernet ports - bye");

	if (cfg_prm->nb_port_pair_params) {
		if (check_port_pair_config(ood_main_cfg->cfg_prm) < 0)
			DAO_ERR_GOTO(-EINVAL, fail, "Invalid port pair config");
	}

	nb_lcores = rte_lcore_count();

	/* reset host_mac_map */
	memset(eth_prm->host_mac_map, 0, sizeof(eth_prm->host_mac_map));
	last_port = 0;

	/* populate destination port details */
	if (cfg_prm->nb_port_pair_params) {
		uint16_t idx, p, portid2;

		for (idx = i = 0; idx < (cfg_prm->nb_port_pair_params << 1); (idx = idx + 2), i++) {
			p = idx & 1;
			portid = cfg_prm->port_pair_param[idx >> 1].port[p];
			portid2 = cfg_prm->port_pair_param[idx >> 1].port[p ^ 1];

			eth_prm->host_mac_map[i].host_port =
				is_host_port(portid) ? portid : portid2;
			eth_prm->host_mac_map[i].mac_port = is_host_port(portid) ? portid2 : portid;
		}
	} else {
		/* TODO revisit, should be removed */
		uint16_t idx = 0;
		RTE_ETH_FOREACH_DEV(portid) {
			if (portid == ood_repr_get_eswitch_portid(ood_main_cfg))
				continue;

			if (nb_ports_in_mask % 2) {
				eth_prm->host_mac_map[idx].host_port =
					is_host_port(portid) ? portid : last_port;
				eth_prm->host_mac_map[idx].mac_port =
					is_host_port(portid) ? last_port : portid;
			} else {
				last_port = portid;
			}

			nb_ports_in_mask++;
			idx++;
		}
		if (nb_ports_in_mask % 2) {
			dao_warn("Notice: odd number of ports in portmask.");
			if (is_host_port(last_port))
				eth_prm->host_mac_map[idx].host_port = last_port;
			else
				eth_prm->host_mac_map[idx].mac_port = last_port;
		}
		cfg_prm->nb_port_pair_params = nb_ports_in_mask / 2;
	}

	/* Port pairs together represents VF representor ports */
	ood_repr_set_nb_representors(ood_main_cfg, cfg_prm->nb_port_pair_params);

	RTE_ETH_FOREACH_DEV(portid) {
		if (portid == ood_repr_get_eswitch_portid(ood_main_cfg))
			continue;
		rte_eth_dev_get_name_by_port(portid, if_name);
		eth_prm->hw_func[i++] = dao_pci_bdf_to_hw_func(if_name);
		dao_info("MAC Port ID %d (%s) -> Host Port ID %d",
			 eth_prm->host_mac_map[portid].mac_port, if_name,
			 eth_prm->host_mac_map[portid].host_port);
	}
	eth_prm->nb_ports = i;

	/* Normal forwarding table setup */
	ood_main_cfg->graph_prm->fm_ctrl_cfg.nb_ports = nb_ports;
	for (portid = 0; portid < cfg_prm->nb_port_pair_params; portid++) {
		host_port = eth_prm->host_mac_map[portid].host_port;
		mac_port = eth_prm->host_mac_map[portid].mac_port;

		ood_main_cfg->graph_prm->fm_ctrl_cfg.host_mac_map[host_port] = mac_port;
		ood_main_cfg->graph_prm->fm_ctrl_cfg.host_mac_map[mac_port] = host_port;

		ood_main_cfg->graph_prm->fm_ctrl_cfg.host_ports[portid] = host_port;
	}

	ood_main_cfg->graph_prm->fm_ctrl_cfg.active_host_ports =
		ood_main_cfg->cfg_prm->nb_port_pair_params;

	/* Initialize all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid) {
		if (portid == ood_repr_get_eswitch_portid(ood_main_cfg))
			continue;
		rc = port_init(ood_main_cfg, portid, nb_lcores);
		if (rc)
			DAO_ERR_GOTO(rc, fail, "Failed to init port %d", portid);
		nb_ports_available++;
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

		rc = eth_rx_queue_setup(ood_main_cfg, lcore_id);
		if (rc)
			DAO_ERR_GOTO(rc, fail, "Failed to setup RX queue for lcore %d", lcore_id);
	}

	/* Start ports */
	RTE_ETH_FOREACH_DEV(portid) {
		if (portid == ood_repr_get_eswitch_portid(ood_main_cfg))
			continue;

		/* Start device */
		rc = rte_eth_dev_start(portid);
		if (rc < 0)
			DAO_ERR_GOTO(-EINVAL, fail, "rte_eth_dev_start: err=%d, port=%d", rc,
				     portid);

		/*
		 * If enabled, put device in promiscuous mode.
		 * This allows IO forwarding mode to forward packets
		 * to itself through 2 cross-connected  ports of the
		 * target machine.
		 */
		if (cfg_prm->promiscuous_on)
			rte_eth_promiscuous_enable(portid);
	}

	check_all_ports_link_status(ood_main_cfg);

	return 0;
fail:
	return errno;
}
