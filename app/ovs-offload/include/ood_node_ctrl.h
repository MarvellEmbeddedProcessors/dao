/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __OOD_NODE_CTRL_H__
#define __OOD_NODE_CTRL_H__

/**
 * @file rte_node_eth_api.h
 *
 * @warning
 * @b EXPERIMENTAL:
 * All functions in this file may be changed or removed without prior notice.
 *
 * This API allows to setup ood_eth_rx and ood_eth_tx nodes
 * and its queue associations.
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_bitmap.h>
#include <rte_common.h>
#include <rte_compat.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <rte_mempool.h>

/* Packet from Eswitch VF to PF has 8th bit set */
#define OOD_ESWITCH_VFPF_SHIFT    8
#define OOD_ESWITCH_CTRL_VLAN_TCI 0
#define OOD_ESWITCH_DEFAULT_QUEUE 0

#define OOD_MARK_ID_SHIFT 6
#define ACT_CFG_MAX_IDX   256

/* Mark IDs */
#define DEFAULT_MARK_ID          0
#define NRML_FWD_MARK_ID         1
#define HOST_TO_HOST_FWD_MARK_ID 2
#define VXLAN_ENCAP_MARK_ID      4
#define TUNNEL_DECAP_MARK_ID     5

typedef enum ood_node_config_type {
	VXLAN_ENCAP_ACTION_CONFIG = 0,
	PORT_ID_ACTION_CONFIG,
	VLAN_INSERT_ACTION_CONFIG,
	ACTION_CONFIG_MAX,
} ood_node_config_type_t;

/**
 * Node mbuf private area 2.
 */
struct node_mbuf_priv2 {
	uint64_t priv_data;
} __rte_cache_aligned;

#define NODE_MBUF_PRIV2_SIZE sizeof(struct node_mbuf_priv2)

/**
 * Node mbuf private data to store next hop, ttl and checksum.
 */
struct node_mbuf_priv1 {
	union {
		/* repr port */
		struct {
			uint64_t nh;
		};
		/* repr port */
		struct {
			uint64_t tnl_cfg_idx;
		};
		/* repr port */
		struct {
			uint64_t tnl_type;
		};

		uint64_t u;
	};
};

static const struct rte_mbuf_dynfield node_mbuf_priv1_dynfield_desc = {
	.name = "rte_node_dynfield_priv1",
	.size = sizeof(struct node_mbuf_priv1),
	.align = __alignof__(struct node_mbuf_priv1),
};

extern int node_mbuf_priv1_dynfield_queue;

/**
 * Get mbuf_priv1 pointer from rte_mbuf.
 *
 * @param
 *   Pointer to the rte_mbuf.
 *
 * @return
 *   Pointer to the mbuf_priv1.
 */
static __rte_always_inline struct node_mbuf_priv1 *
node_mbuf_priv1(struct rte_mbuf *m, const int offset)
{
	return RTE_MBUF_DYNFIELD(m, offset, struct node_mbuf_priv1 *);
}

/*
 * Node configuration for flow_mapper node
 */
typedef struct ood_node_flow_mapper_ctrl_conf {
	/* Host to Mac port mapping array */
	uint16_t host_mac_map[RTE_MAX_ETHPORTS];
	/* Total no of ports */
	uint16_t nb_ports;
	/* No of active host ports */
	uint16_t active_host_ports;
	/* Array of active host ports */
	uint16_t host_ports[RTE_MAX_ETHPORTS];
	/* repr port id */
	uint16_t repr_portid;
} ood_node_flow_mapper_ctrl_conf_t;

/**
 * Port config for ood_eth_rx and ood_eth_tx node.
 */
typedef struct ood_node_eth_ctrl_conf {
	/* Port identifier */
	uint16_t port_id;
	/* Number of Rx queues. */
	uint16_t num_rx_queues;
	/* Number of Tx queues. */
	uint16_t num_tx_queues;
	/* Array of mempools associated to Rx queue. */
	struct rte_mempool **mp;
	/* Size of mp array. */
	uint16_t mp_count;
} ood_node_eth_ctrl_conf_t;

/**
 * Port config for repr_rx and repr_tx node.
 */
typedef struct ood_node_repr_ctrl_conf {
	/**< Port identifier */
	uint16_t port_id;
	/* No of representor ports */
	uint16_t nb_repr;
	/* Representer IDs map */
	uint16_t repr_map[RTE_MAX_ETHPORTS];
} ood_node_repr_ctrl_conf_t;

typedef struct ood_node_action_config {
	uint8_t act_cfg_map;
	uint8_t tnl_cfg_idx;
	uint8_t hst_cfg_idx;
	bool in_use;
} ood_node_action_config_t;

typedef struct ood_node_ctrl {
	/* Action config array */
	ood_node_action_config_t *act_cfg_arr;
	/* Action config index bitmap */
	struct rte_bitmap *act_cfg_bmp;
} ood_node_ctrl_t;

/**
 * Control API for configuring Eth nodes
 *
 * @param conf
 *   Array of eth config that identifies which port's ood_eth_rx and ood_eth_tx
 *   nodes need to be created and queue association.
 * @param cnt
 *   Size of cfg array.
 * @param nb_graphs
 *   Number of graphs that will be used.
 *
 * @return
 *   0 on successful initialization, negative otherwise.
 */
int ood_node_eth_ctrl(ood_node_eth_ctrl_conf_t *conf, uint16_t nb_conf, uint16_t nb_graphs);

/**
 * Control API for configuring flow mapper node
 *
 * @param conf
 *   Flow mapper configuration that identifies which port mappings and port to
 *   node edge mappings.
 *
 * @return
 *   0 on successful initialization, negative otherwise.
 */
int ood_node_flow_mapper_ctrl(ood_node_flow_mapper_ctrl_conf_t *conf,
			      ood_node_repr_ctrl_conf_t *repr_ctrl_cfg);

/**
 * Initializes repr nodes.
 *
 * @param conf
 *   Array of repr config that identifies which port's repr_rx and repr_tx
 *   nodes need to be created and queue association.
 *
 * @return
 *   0 on successful initialization, negative otherwise.
 */
int ood_node_repr_ctrl(ood_node_repr_ctrl_conf_t *conf);

int ood_node_ctrl_init(void);
int ood_node_vxlan_encap_tunnel_config_ctrl(const void *patterns, void *error);

struct rte_bitmap *ood_node_config_index_map_setup(uint32_t bmap_max_sz);
int ood_node_config_index_free(struct rte_bitmap *bmp, uint16_t index);
int ood_node_config_index_alloc(struct rte_bitmap *bmp);
int ood_node_action_config_release(uint16_t index);
int ood_node_action_config_alloc(ood_node_action_config_t *act_cfg);
ood_node_action_config_t *ood_node_action_config_get(uint16_t act_cfg_idx);

int ood_node_host_to_host_config_ctrl(uint16_t src_host_port, uint16_t dst_host_port);
#ifdef __cplusplus
}
#endif

#endif /* __OOD_NODE_CTRL_H__ */
