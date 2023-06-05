/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __FLOW_MAPPER_PRIV_H__
#define __FLOW_MAPPER_PRIV_H__

#define FLOW_MAPPER_FWD_TBL_MAX_IDX 256

struct flow_mapper_host_to_host_fwd_cfg {
	uint8_t src_host_port;
	uint8_t dst_host_port;
	bool in_use;
};

/**
 * @internal
 *
 * Flow mapper node main data structure.
 */
struct flow_mapper_node_main {
	/* Port mapping between host port and mac ports */
	uint32_t nrml_fwd_tbl[RTE_MAX_ETHPORTS];
	/* Next eth tx edge */
	uint16_t eth_tx_edge[RTE_MAX_ETHPORTS];
	/* Mapping between host port to repr TX node */
	uint32_t repr_tx_edge[RTE_MAX_ETHPORTS];
	/* Mapping between host port to representor ports */
	uint32_t host_port_tbl[RTE_MAX_ETHPORTS];
	/* Mapping between host to host forwarding */
	struct flow_mapper_host_to_host_fwd_cfg *host_to_host_fwd_tbl;
	/* Host to host fwd bitmap */
	struct rte_bitmap *hst_cfg_bmp;
	/* repr port ID */
	int repr_portid;
};

typedef struct flow_mapper_node_ctx {
	/* Dynamic offset to mbuf priv1 */
	int mbuf_priv1_off;
} flow_mapper_node_ctx_t;

enum flow_mapper_next_nodes {
	FLOW_MAPPER_NEXT_PKT_DROP,
	VXLAN_ENCAP_NEXT_PKT,
	TUNNEL_DECAP_NEXT_PKT,
	FLOW_MAPPER_NEXT_MAX,
};

/**
 * @internal
 *
 * Get the flow mapper node.
 *
 * @return
 *   Pointer to the flow mapper node.
 */
struct rte_node_register *flow_mapper_node_get(void);

/**
 * @internal
 *
 * Set the Edge index of a given port_id.
 *
 * @param port_id
 *   port identifier.
 * @param next_index
 *   Edge index of the Given Tx node.
 */
int flow_mapper_set_eth_tx_edge_idx(uint16_t port_id, uint16_t next_index);

/**
 * @internal
 *
 * Setting up the normal forwarding table which can be looked up for packet
 * flow between host and mac ports.
 *
 * @param port_arr
 *   Array of ports
 * @param nb_ports
 *   No of ports
 */
int flow_mapper_setup_nrml_fwd_table(uint16_t *port_arr, uint16_t nb_ports);

/**
 * @internal
 *
 * Set the Edge index to repr tx node.
 *
 * @param port_id
 *   port identifier.
 * @param next_index
 *   Edge index of the Given Tx node.
 */
int flow_mapper_set_repr_tx_edge_idx(uint16_t port_id, uint16_t next_index);

/**
 * @internal
 *
 * Setting up the mapping between host ports and representor ports which are
 * represented by a unique repr queue.
 *
 * @param queue_id
 *   repr queue id
 * @param index
 *   Index of host port
 */
int flow_mapper_set_host_port_mapping(uint16_t queue_id, uint16_t host_port_idx);

/**
 * @internal
 *
 * Setting up the repr port ID which will be used for determining if packet
 * dequeued is from representor or normal port.
 *
 * @param port_id
 *   repr port ID
 */
int flow_mapper_set_repr_portid(uint16_t port_id);

int flow_mapper_setup_host_to_host_fwd_table(struct flow_mapper_host_to_host_fwd_cfg *hst_cfg);
int flow_mapper_host_to_host_fwd_tbl_index_free(uint16_t hst_cfg_idx);

#endif /* __FLOW_MAPPER_PRIV_H__ */
