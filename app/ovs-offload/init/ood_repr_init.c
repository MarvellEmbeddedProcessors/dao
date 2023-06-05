/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <stddef.h>
#include <stdint.h>

#include <rte_ethdev.h>

#include <dao_log.h>

#include <ood_init.h>
#include <ood_repr.h>

#define MAX_RTE_FLOW_ACTIONS 5
#define MAX_RTE_FLOW_PATTERN 5

/* Representor port configured with default settings. 8< */
static struct rte_eth_conf port_conf = {
	.txmode = {
		.offloads = RTE_ETH_TX_OFFLOAD_VLAN_INSERT,
	},
};

int
ood_repr_set_nb_representors(struct ood_main_cfg_data *ood_main_cfg, uint16_t count)
{
	ood_repr_param_t *repr_prm = NULL;

	if (!ood_main_cfg)
		DAO_ERR_GOTO(-EINVAL, fail, "ood_main_cfg invalid");

	repr_prm = ood_main_cfg->repr_prm;
	if (!repr_prm)
		DAO_ERR_GOTO(-EINVAL, fail, "Representor parameters not populated");

	repr_prm = ood_main_cfg->repr_prm;
	repr_prm->nb_repr = count;

	return 0;
fail:
	return errno;
}

int
ood_repr_populate_node_config(struct ood_main_cfg_data *ood_main_cfg,
			      ood_node_repr_ctrl_conf_t *repr_cfg)
{
	ood_repr_param_t *repr_prm = NULL;

	if (!ood_main_cfg)
		DAO_ERR_GOTO(-EINVAL, fail, "ood_main_cfg invalid");

	repr_prm = ood_main_cfg->repr_prm;
	if (!repr_prm)
		DAO_ERR_GOTO(-EINVAL, fail, "Representor parameters not populated");

	repr_cfg->nb_repr = repr_prm->nb_repr;
	repr_cfg->port_id = repr_prm->portid;
	rte_memcpy(repr_cfg->repr_map, repr_prm->repr_map, repr_prm->nb_repr * sizeof(uint16_t));

	return 0;
fail:
	return errno;
}

uint16_t
ood_repr_get_eswitch_portid(struct ood_main_cfg_data *ood_main_cfg)
{
	ood_repr_param_t *repr_prm = NULL;

	if (!ood_main_cfg)
		DAO_ERR_GOTO(-EINVAL, fail, "ood_main_cfg invalid");

	repr_prm = ood_main_cfg->repr_prm;
	if (!repr_prm)
		DAO_ERR_GOTO(-EINVAL, fail, "Representor parameters not populated");

	return repr_prm->portid;
fail:
	return UINT16_MAX;
}

/* repr graph to run on main control core */
static int
repr_lcore_rx_queues_setup(struct ood_main_cfg_data *ood_main_cfg)
{
	ood_lcore_param_t *lcore_prm;
	ood_repr_param_t *repr_prm;
	uint16_t i, portid;
	uint8_t lcore;

	lcore_prm = ood_main_cfg->lcore_prm;
	repr_prm = ood_main_cfg->repr_prm;
	lcore = rte_get_main_lcore();
	if (repr_prm->nb_repr >= OOD_MAX_REPR_RX_QUEUE_PER_LCORE) {
		dao_err("Error: too many queues (%u) for lcore: %u\n",
			(uint32_t)repr_prm->nb_repr + 1, (uint32_t)lcore);
		return -1;
	}

	lcore_prm->lcore_conf[lcore].n_rx_queue = repr_prm->nb_repr + 1;
	portid = repr_prm->portid;
	for (i = 0; i < repr_prm->nb_repr + 1; i++) {
		lcore_prm->lcore_conf[lcore].rx_queue_list[i].port_id = portid;
		lcore_prm->lcore_conf[lcore].rx_queue_list[i].queue_id = i;
		dao_dbg("repr Lcore ID %d port_id %d queueid %d n_rx_queue %d\n", lcore,
			lcore_prm->lcore_conf[lcore].rx_queue_list[i].port_id,
			lcore_prm->lcore_conf[lcore].rx_queue_list[i].queue_id,
			lcore_prm->lcore_conf[lcore].n_rx_queue);

		/* Add this queue node to its graph */
		snprintf(lcore_prm->lcore_conf[lcore].rx_queue_list[i].node_name, RTE_NODE_NAMESIZE,
			 "repr_rx");
	}

	return 0;
}

static struct rte_flow *
create_vlan_strip_flow(uint16_t portid)
{
	struct rte_flow_action action[MAX_RTE_FLOW_ACTIONS] = {};
	struct rte_flow_item pattern[MAX_RTE_FLOW_PATTERN] = {};
	struct rte_flow_attr attr = {};
	struct rte_flow_error err = {};
	int pattern_idx = 0, act_idx = 0;
	struct rte_flow *flow = NULL;
	int rc;

	/* Define attributes */
	attr.egress = 0;
	attr.ingress = 1;

	/* Define actions */
	action[act_idx].type = RTE_FLOW_ACTION_TYPE_OF_POP_VLAN;
	act_idx++;
	action[act_idx].type = RTE_FLOW_ACTION_TYPE_END;
	action[act_idx].conf = NULL;

	/* Define patterns */
	pattern[pattern_idx].type = RTE_FLOW_ITEM_TYPE_VLAN;
	pattern[pattern_idx].spec = NULL;
	pattern[pattern_idx].mask = NULL;
	pattern[pattern_idx].last = NULL;
	pattern_idx++;
	pattern[pattern_idx].type = RTE_FLOW_ITEM_TYPE_END;

	/* Validate the flow */
	rc = rte_flow_validate(portid, &attr, pattern, action, &err);
	if (rc)
		DAO_ERR_GOTO(rc, error, "Flow validation failed");

	/* Flow create */
	flow = rte_flow_create(portid, &attr, pattern, action, &err);
	if (flow == NULL)
		DAO_ERR_GOTO(rc, error, "Flow creation failed");

	return flow;
error:
	return NULL;
}

static inline int
configure_eswitch_dev(ood_repr_param_t *repr_prm, uint16_t port_id,
		      struct rte_eth_conf *local_port_conf)
{
	struct rte_mempool *repr_pktmbuf_pool = NULL;
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	struct rte_ether_addr addr;
	uint16_t q, nb_txq, nb_rxq;
	int rc;
	if (!rte_eth_dev_is_valid_port(port_id))
		return -1;

	/* No of repr queues is no of representors + 1 queue for control channel */
	nb_rxq = 1;
	nb_txq = 1;
	rc = rte_eth_dev_configure(port_id, nb_rxq, nb_txq, local_port_conf);
	if (rc != 0)
		DAO_ERR_GOTO(-EINVAL, fail, "dev config failed\n");

	for (q = 0; q < nb_txq; q++) {
		rc = rte_eth_tx_queue_setup(port_id, q, OOD_TX_DESC_PER_QUEUE,
					    rte_eth_dev_socket_id(port_id), NULL);
		if (rc < 0)
			DAO_ERR_GOTO(-EINVAL, fail, "queue setup failed\n");
	}

	/* Create the mbuf pool. */
	repr_pktmbuf_pool = rte_pktmbuf_pool_create("repr_mbuf_pool", OOD_NB_REPR_MBUF,
						    OOD_MEMPOOL_CACHE_SIZE, RTE_CACHE_LINE_SIZE,
						    RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (repr_pktmbuf_pool == NULL)
		DAO_ERR_GOTO(-ENOMEM, fail, "Cannot init mbuf pool\n");

	/* RX queue setup. */
	for (q = 0; q < nb_rxq; q++) {
		rc = rte_eth_rx_queue_setup(port_id, q, OOD_RX_DESC_PER_QUEUE,
					    rte_eth_dev_socket_id(port_id), NULL,
					    repr_pktmbuf_pool);
		if (rc < 0)
			DAO_ERR_GOTO(-EINVAL, fail, "rte_eth_rx_queue_setup:err=%d, port=%u\n", rc,
				     port_id);
	}

	repr_prm->repr_pool = repr_pktmbuf_pool;
	rc = rte_eth_dev_start(port_id);
	if (rc < 0)
		DAO_ERR_GOTO(-EINVAL, fail, "dev start failed\n");

	rc = rte_eth_macaddr_get(port_id, &addr);
	if (rc != 0)
		DAO_ERR_GOTO(-EINVAL, fail, "macaddr get failed\n");

	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, &addr);
	printf("\n");
	dao_info("repr port ID %u MAC: %s", port_id, buf);

	rc = rte_eth_promiscuous_enable(port_id);
	if (rc != 0)
		DAO_ERR_GOTO(-rc, fail, "promiscuous mode enable failed: %s\n", rte_strerror(-rc));

	return 0;
fail:
	return errno;
}

int
ood_representor_eswitch_dev_init(struct ood_main_cfg_data *ood_main_cfg)
{
	ood_repr_param_t *repr_prm = ood_main_cfg->repr_prm;
	struct rte_eth_conf local_port_conf = port_conf;
	struct rte_eth_dev_info ethdev_info;
	char name[RTE_ETH_NAME_MAX_LEN];
	int portid;

	if (!ood_main_cfg->repr_prm)
		DAO_ERR_GOTO(-EFAULT, fail, "repr params not allocated");

	portid = rte_eth_find_next(0);
	while (portid < RTE_MAX_ETHPORTS) {
		rte_eth_dev_info_get(portid, &ethdev_info);
		if (ethdev_info.switch_info.domain_id !=
			RTE_ETH_DEV_SWITCH_DOMAIN_ID_INVALID)
			break;
		portid = rte_eth_find_next(portid + 1);
	}

	if (!rte_eth_dev_is_valid_port(portid))
		DAO_ERR_GOTO(-EFAULT, fail, "Representor eswitch device not probed");

	ood_main_cfg->repr_prm->portid = portid;
	rte_eth_dev_get_name_by_port(portid, name);
	dao_info("Representor eswitch device port ID %d, name %s", portid, name);

	if (ood_config_port_max_pkt_len(ood_main_cfg->cfg_prm, &local_port_conf, &ethdev_info))
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid max packet length: %u (port %u)",
			     ood_main_cfg->cfg_prm->max_pkt_len, portid);

	/* configure eswitch_dev */
	if (configure_eswitch_dev(repr_prm, portid, &local_port_conf))
		DAO_ERR_GOTO(errno, fail, "Failed to configure repr eswitch_dev");

	/* Create flow rule to strip VLAN */
	if (!create_vlan_strip_flow(portid))
		DAO_ERR_GOTO(errno, fail, "Failed to create vlan strip flow rule");

	if (repr_lcore_rx_queues_setup(ood_main_cfg))
		DAO_ERR_GOTO(-EINVAL, fail, "repr Lcore rx queue setup failed");

	/* Populating active host ports */
	ood_main_cfg->graph_prm->fm_ctrl_cfg.repr_portid = repr_prm->portid;

	return 0;
fail:
	return errno;
}
