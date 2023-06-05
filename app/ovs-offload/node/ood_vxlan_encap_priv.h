/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __OOD_VXLAN_ENCAP_PRIV_H__
#define __OOD_VXLAN_ENCAP_PRIV_H__

#define VXLAN_ENCAP_TNL_CFG_MAX_IDX 256

struct vxlan_encap_node_tunnel_config {
	struct rte_ether_hdr eth;
	struct rte_vlan_hdr vlan;
	struct rte_ipv4_hdr ipv4;
	struct rte_ipv6_hdr ipv6;
	struct rte_udp_hdr udp;
	struct rte_vxlan_hdr vxlan;
	bool in_use;
};

/**
 * @internal
 *
 * VxLAN encap node main data structure.
 */
struct vxlan_encap_node_main {
	/* VXLAN encap fields */
	struct vxlan_encap_node_tunnel_config *tnl_cfg_arr;
	/* Port mapping between host port and mac ports */
	uint32_t nrml_fwd_tbl[RTE_MAX_ETHPORTS];
	/* Next eth tx edge */
	uint16_t eth_tx_edge[RTE_MAX_ETHPORTS];
	/* Tunnel config index bitmap */
	struct rte_bitmap *tnl_cfg_bmp;
};

enum vxlan_encap_next_nodes {
	VXLAN_ENCAP_NEXT_PKT_DROP,
	VXLAN_ENCAP_NEXT_FLOW_MAPPER,
	VXLAN_ENCAP_NEXT_MAX,
};

struct vxlan_encap_node_ctx {
	/* Dynamic offset to mbuf priv1 */
	int mbuf_priv1_off;
};

/**
 * @internal
 *
 * Get the flow mapper node.
 *
 * @return
 *   Pointer to the flow mapper node.
 */
struct rte_node_register *vxlan_encap_node_get(void);

int vxlan_encap_node_tunnel_config_setup(struct vxlan_encap_node_tunnel_config *tnl_cfg);
int vxlan_encap_node_tunnel_config_index_free(uint16_t tnl_cfg_idx);

#endif /* __OOD_VXLAN_ENCAP_PRIV_H__ */
