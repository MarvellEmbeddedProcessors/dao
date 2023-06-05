/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <stdlib.h>

#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_malloc.h>

#include <dao_log.h>
#include <dao_util.h>

#include <ood_node_ctrl.h>

#include "ood_eth_rx_priv.h"
#include "ood_eth_tx_priv.h"
#include "ood_flow_mapper_priv.h"
#include "ood_repr_rx_priv.h"
#include "ood_repr_tx_priv.h"
#include "ood_tnl_decap_priv.h"
#include "ood_vxlan_encap_priv.h"

ood_node_ctrl_t *node_ctrl_cmn;
int
ood_node_ctrl_init(void)
{
	node_ctrl_cmn = rte_zmalloc("node ctrl cmn", sizeof(ood_node_ctrl_t), RTE_CACHE_LINE_SIZE);
	if (!node_ctrl_cmn)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory for node_ctrl_cmn");

	node_ctrl_cmn->act_cfg_arr =
		rte_zmalloc("Action cfg arr", ACT_CFG_MAX_IDX * sizeof(ood_node_action_config_t),
			    RTE_CACHE_LINE_SIZE);
	if (!node_ctrl_cmn->act_cfg_arr)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory for act cfg arr");

	node_ctrl_cmn->act_cfg_bmp = ood_node_config_index_map_setup(ACT_CFG_MAX_IDX);
	if (!node_ctrl_cmn->act_cfg_bmp)
		DAO_ERR_GOTO(-EFAULT, fail, "Failed to setup act cfg bmp");

	return 0;
fail:
	return errno;
}

static int
convert_encap_pattern_to_raw(const struct rte_flow_item *items,
			     struct vxlan_encap_node_tunnel_config *tnl_cfg,
			     struct rte_flow_error *error)
{
	if (!items)
		return rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					  "invalid empty data");
	for (; items->type != RTE_FLOW_ITEM_TYPE_END; items++) {
		switch (items->type) {
		case RTE_FLOW_ITEM_TYPE_ETH:
			rte_memcpy(&tnl_cfg->eth, items->spec, sizeof(struct rte_ether_hdr));
			break;
		case RTE_FLOW_ITEM_TYPE_VLAN:
			rte_memcpy(&tnl_cfg->vlan, items->spec, sizeof(struct rte_vlan_hdr));
			break;
		case RTE_FLOW_ITEM_TYPE_IPV4:
			rte_memcpy(&tnl_cfg->ipv4, items->spec, sizeof(struct rte_ipv4_hdr));
			break;
		case RTE_FLOW_ITEM_TYPE_IPV6:
			rte_memcpy(&tnl_cfg->ipv6, items->spec, sizeof(struct rte_ipv6_hdr));
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			rte_memcpy(&tnl_cfg->udp, items->spec, sizeof(struct rte_udp_hdr));
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN:
			rte_memcpy(&tnl_cfg->vxlan, items->spec, sizeof(struct rte_vxlan_hdr));
			break;
		case RTE_FLOW_ITEM_TYPE_VOID:
			break;
		default:
			return rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
						  (void *)items->type, "unsupported item type");
			break;
		};
	}

	return 0;
}

int
ood_node_vxlan_encap_tunnel_config_ctrl(const void *patterns, void *error)
{
	struct vxlan_encap_node_tunnel_config *tnl_cfg;
	int tnl_cfg_idx;

	tnl_cfg = calloc(1, sizeof(struct vxlan_encap_node_tunnel_config));
	if (!tnl_cfg)
		DAO_ERR_GOTO(-ENOMEM, fail, "tunnel cfg memory allocation failed");

	convert_encap_pattern_to_raw(patterns, tnl_cfg, error);

	tnl_cfg_idx = vxlan_encap_node_tunnel_config_setup(tnl_cfg);
	if (tnl_cfg_idx <= 0)
		dao_err("Invalid tnl cfg received, err %d", tnl_cfg_idx);

	free(tnl_cfg);
	return tnl_cfg_idx;
fail:
	return errno;
}

int
ood_node_host_to_host_config_ctrl(uint16_t src_host_port, uint16_t dst_host_port)
{
	struct flow_mapper_host_to_host_fwd_cfg *hst_cfg;
	int hst_cfg_idx;

	hst_cfg = calloc(1, sizeof(struct flow_mapper_host_to_host_fwd_cfg));
	if (!hst_cfg)
		DAO_ERR_GOTO(-ENOMEM, fail, "host cfg memory allocation failed");

	hst_cfg->src_host_port = src_host_port;
	hst_cfg->dst_host_port = dst_host_port;
	hst_cfg_idx = flow_mapper_setup_host_to_host_fwd_table(hst_cfg);
	if (hst_cfg_idx <= 0)
		dao_err("Invalid tnl cfg received, err %d", hst_cfg_idx);

	free(hst_cfg);
	return hst_cfg_idx;
fail:
	return errno;
}

int
ood_node_flow_mapper_ctrl(ood_node_flow_mapper_ctrl_conf_t *conf,
			  ood_node_repr_ctrl_conf_t *repr_ctrl_cfg)
{
	int i;

	/* Setting up normal forwarding table */
	if (flow_mapper_setup_nrml_fwd_table(conf->host_mac_map, conf->nb_ports))
		DAO_ERR_GOTO(errno, fail, "Failed to setup normal fwd table");

	/* Set the repr port for flow mapper to match and read private
	 * area of only those mbufs
	 */
	if (flow_mapper_set_repr_portid(conf->repr_portid))
		DAO_ERR_GOTO(errno, fail, "Failed to set repr port");

	/* Host ports are the ones through which to/from representor traffic
	 * will flow. Setting up a lookup table of host ports to representor
	 * mapping.
	 */
	for (i = 0; i < conf->active_host_ports; i++)
		flow_mapper_set_host_port_mapping(conf->host_ports[i],
						  repr_ctrl_cfg->repr_map[i]);

	return 0;
fail:
	return errno;
}

int
ood_node_eth_ctrl(ood_node_eth_ctrl_conf_t *conf, uint16_t nb_confs, uint16_t nb_graphs)
{
	struct rte_node_register *flow_mapper_node;
	uint16_t rx_q_used, port_id, tx_q_used;
	struct ood_eth_tx_node_main *tx_node_data;
	struct rte_node_register *tx_node;
	char name[RTE_NODE_NAMESIZE];
	struct rte_mempool *mp;
	const char *next_nodes;
	int i, j, rc;
	uint32_t id;

	next_nodes = name;
	flow_mapper_node = flow_mapper_node_get();
	tx_node_data = ood_eth_tx_node_data_get();
	tx_node = ood_eth_tx_node_get();
	for (i = 0; i < nb_confs; i++) {
		port_id = conf[i].port_id;

		if (!rte_eth_dev_is_valid_port(port_id))
			return -EINVAL;

		/* Check for mbuf minimum private size requirement */
		for (j = 0; j < conf[i].mp_count; j++) {
			mp = conf[i].mp[j];
			if (!mp)
				continue;
			/* Check for minimum private space */
			if (rte_pktmbuf_priv_size(mp) < NODE_MBUF_PRIV2_SIZE) {
				dao_err("Minimum mbuf priv size requirement not met by mp %s",
					mp->name);
				return -EINVAL;
			}
		}

		rx_q_used = conf[i].num_rx_queues;
		tx_q_used = conf[i].num_tx_queues;
		/* Check if we have a txq for each worker */
		if (tx_q_used < nb_graphs)
			return -EINVAL;

		/* Create node for each rx port queue pair */
		for (j = 0; j < rx_q_used; j++) {
			struct ood_eth_rx_node_main *rx_node_data;
			struct rte_node_register *rx_node;
			ood_eth_rx_node_elem_t *elem;

			rx_node_data = ood_eth_rx_get_node_data_get();
			rx_node = ood_eth_rx_node_get();
			snprintf(name, sizeof(name), "%u-%u", port_id, j);
			/* Clone a new rx node with same edges as parent */
			id = rte_node_clone(rx_node->id, name);
			if (id == RTE_NODE_ID_INVALID)
				return -EIO;

			/* Add it to list of nic rx nodes for lookup */
			elem = malloc(sizeof(ood_eth_rx_node_elem_t));
			if (elem == NULL)
				return -ENOMEM;
			memset(elem, 0, sizeof(ood_eth_rx_node_elem_t));
			elem->ctx.port_id = port_id;
			elem->ctx.queue_id = j;
			elem->nid = id;
			elem->next = rx_node_data->head;
			rx_node_data->head = elem;

			dao_dbg("Rx node %s-%s: is at %u", rx_node->name, name, id);
		}

		/* Create a per port tx node from base node */
		snprintf(name, sizeof(name), "%u", port_id);
		/* Clone a new node with same edges as parent */
		id = rte_node_clone(tx_node->id, name);
		tx_node_data->nodes[port_id] = id;

		dao_dbg("Tx node %s-%s: is at %u", tx_node->name, name, id);

		/* Prepare the actual name of the cloned node */
		snprintf(name, sizeof(name), "ood_eth_tx-%u", port_id);

		/* Add this tx port node as next to flow_mapper_node */
		rte_node_edge_update(flow_mapper_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
		/* Assuming edge id is the last one alloc'ed */
		rc = flow_mapper_set_eth_tx_edge_idx(port_id,
						     rte_node_edge_count(flow_mapper_node->id) - 1);
		if (rc < 0)
			return rc;
	}

	return 0;
}

int
ood_node_repr_ctrl(ood_node_repr_ctrl_conf_t *conf)
{
	struct rte_node_register *flow_mapper_node;
	struct repr_tx_node_main *tx_node_data;
	struct repr_rx_node_main *rx_node_data;
	struct ood_repr_tx_node_elem *tx_elem;
	struct rte_node_register *tx_node;
	struct rte_node_register *rx_node;
	uint16_t nb_repr, port_id;
	char name[RTE_NODE_NAMESIZE];
	const char *next_nodes;
	uint32_t id, i;

	port_id = conf->port_id;
	if (!rte_eth_dev_is_valid_port(port_id))
		DAO_ERR_GOTO(-EINVAL, fail, "Port %d not a valid port", port_id);

	/* repr RX node configuration */
	rx_node_data = repr_rx_get_node_data_get();
	rx_node = repr_rx_node_get();

	/* Each representor port is represented by a repr queue */
	nb_repr = conf->nb_repr;

	/* Populate the rx node data to be configured */
	rx_node_data->repr_portid = port_id;
	rx_node_data->nb_repr = nb_repr;
	rx_node_data->nid = rx_node->id;

	dao_dbg("Rx node %s: is at %u", rx_node->name, rx_node->id);

	/* repr TX node configuration */
	next_nodes = name;
	flow_mapper_node = flow_mapper_node_get();
	tx_node_data = repr_tx_node_data_get();
	tx_node = repr_tx_node_get();

	/* Create a clone for each txq which will represent representor port to
	 * which packets can be transmitted by host ports.
	 */
	for (i = 0; i < nb_repr; i++) {
		/* Create a per port tx node from base node */
		snprintf(name, sizeof(name), "%u", i);
		/* Clone a new node with same edges as parent */
		id = rte_node_clone(tx_node->id, name);
		if (id == RTE_NODE_ID_INVALID)
			return -EIO;

		/* Add it to list of nic rx nodes for lookup */
		tx_elem = malloc(sizeof(ood_repr_tx_node_elem_t));
		if (tx_elem == NULL)
			return -ENOMEM;
		memset(tx_elem, 0, sizeof(ood_repr_tx_node_elem_t));
		tx_elem->ctx.port_id = port_id;
		tx_elem->ctx.rep_id = conf->repr_map[i];
		tx_elem->nid = id;
		tx_elem->next = tx_node_data->head;
		tx_node_data->head = tx_elem;

		dao_info("Tx node %s-%s: rep id %d is at %u", tx_node->name, name,
			 tx_elem->ctx.rep_id, id);

		/* Prepare the actual name of the cloned node */
		snprintf(name, sizeof(name), "repr_tx-%u", i);

		/* Add this tx port node as next to flow_mapper_node */
		rte_node_edge_update(flow_mapper_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);

		/* Assuming edge id is the last one alloc'ed */
		if (flow_mapper_set_repr_tx_edge_idx(conf->repr_map[i],
						     rte_node_edge_count(flow_mapper_node->id) - 1))
			DAO_ERR_GOTO(errno, fail, "Failed to set repr tx edge %d", i);
	}

	return 0;
fail:
	return errno;
}

static inline int
bitmap_ctzll(uint64_t slab)
{
	if (slab == 0)
		return 0;

	return __builtin_ctzll(slab);
}

int
ood_node_config_index_free(struct rte_bitmap *bmp, uint16_t index)
{
	if (!bmp)
		DAO_ERR_GOTO(-EINVAL, fail, "Bitmap is not setup properly");

	if (rte_bitmap_get(bmp, index))
		DAO_ERR_GOTO(-EINVAL, fail, "Index %d was not allocated", index);

	rte_bitmap_set(bmp, index);

	return 0;
fail:
	return errno;
}

int
ood_node_config_index_alloc(struct rte_bitmap *bmp)
{
	uint16_t idx, rc;
	uint64_t slab;
	uint32_t pos;

	if (!bmp)
		DAO_ERR_GOTO(-EINVAL, fail, "Bitmap is not setup properly");

	pos = 0;
	slab = 0;
	/* Scan from the beginning */
	__rte_bitmap_scan_init(bmp);
	/* Scan bitmap to get the free pool */
	rc = rte_bitmap_scan(bmp, &pos, &slab);
	/* Empty bitmap */
	if (rc == 0)
		DAO_ERR_GOTO(-EINVAL, fail, "Empty bitmap");

	idx = pos + bitmap_ctzll(slab);
	rte_bitmap_clear(bmp, idx);

	return idx;
fail:
	return errno;
}

struct rte_bitmap *
ood_node_config_index_map_setup(uint32_t bmap_max_sz)
{
	struct rte_bitmap *bmp;
	uint32_t bmap_sz, id;
	void *bmap_mem;

	if (!bmap_max_sz)
		DAO_ERR_GOTO(-EINVAL, fail, "Bitmap size cannot be zero");

	bmap_sz = rte_bitmap_get_memory_footprint(bmap_max_sz);

	/* Allocate memory for rep_xport queue bitmap */
	bmap_mem = rte_zmalloc("bmap_mem", bmap_sz, RTE_CACHE_LINE_SIZE);
	if (bmap_mem == NULL)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory for worker lmt bmap");

	/* Initialize worker lmt bitmap */
	bmp = rte_bitmap_init(bmap_max_sz, bmap_mem, bmap_sz);
	if (!bmp)
		DAO_ERR_GOTO(-EIO, fail, "Failed to initialize rep_xport queue bitmap");

	/* Set all the queue initially */
	for (id = 1; id < bmap_max_sz; id++)
		rte_bitmap_set(bmp, id);

	return bmp;
fail:
	return NULL;
}

int
ood_node_action_config_release(uint16_t act_cfg_idx)
{
	ood_node_action_config_t *act_cfg;
	int rc;

	act_cfg = &node_ctrl_cmn->act_cfg_arr[act_cfg_idx];

	/* Release vxlan tunnel config */
	if (dao_check_bit_is_set(act_cfg->act_cfg_map, VXLAN_ENCAP_ACTION_CONFIG + 1))
		rc = vxlan_encap_node_tunnel_config_index_free(act_cfg->tnl_cfg_idx);

	/* Release port id config */
	if (dao_check_bit_is_set(act_cfg->act_cfg_map, PORT_ID_ACTION_CONFIG + 1))
		rc = flow_mapper_host_to_host_fwd_tbl_index_free(act_cfg->hst_cfg_idx);

	/* Release action config index */
	if (!node_ctrl_cmn->act_cfg_arr[act_cfg_idx].in_use) {
		rc = -EINVAL;
		DAO_ERR_GOTO(rc, exit, "Action config index %d not in use", act_cfg_idx);
	}

	dao_dbg("Releasing action config index %d tnl cfg idx %d", act_cfg_idx,
		node_ctrl_cmn->act_cfg_arr[act_cfg_idx].tnl_cfg_idx);
	memset(&node_ctrl_cmn->act_cfg_arr[act_cfg_idx], 0, sizeof(ood_node_action_config_t));
	rc = ood_node_config_index_free(node_ctrl_cmn->act_cfg_bmp, act_cfg_idx);

exit:
	return rc;
}

int
ood_node_action_config_alloc(ood_node_action_config_t *act_cfg)
{
	int act_cfg_idx;

	if (!act_cfg)
		DAO_ERR_GOTO(-EINVAL, fail, "Received empty encap action cfg");

	act_cfg_idx = ood_node_config_index_alloc(node_ctrl_cmn->act_cfg_bmp);
	if (act_cfg_idx <= 0)
		DAO_ERR_GOTO(errno, fail, "Invalid tnl index received %d", act_cfg_idx);

	dao_dbg("Act cfg index %d allocated tnl idx %d", act_cfg_idx, act_cfg->tnl_cfg_idx);
	rte_memcpy(&node_ctrl_cmn->act_cfg_arr[act_cfg_idx], act_cfg,
		   sizeof(ood_node_action_config_t));
	node_ctrl_cmn->act_cfg_arr[act_cfg_idx].in_use = true;

	return act_cfg_idx;
fail:
	return errno;
}

ood_node_action_config_t *
ood_node_action_config_get(uint16_t act_cfg_idx)
{
	if (act_cfg_idx <= 0) {
		dao_err("Invalid act cfg index %d", act_cfg_idx);
		return NULL;
	}

	return &node_ctrl_cmn->act_cfg_arr[act_cfg_idx];
}
