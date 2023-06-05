/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __OOD_TNL_DECAP_PRIV_H__
#define __OOD_TNL_DECAP_PRIV_H__

/**
 * @internal
 *
 * VxLAN encap node main data structure.
 */
struct tnl_decap_node_main {
	/* Port mapping between host port and mac ports */
	uint32_t nrml_fwd_tbl[RTE_MAX_ETHPORTS];
	/* Next eth tx edge */
	uint16_t eth_tx_edge[RTE_MAX_ETHPORTS];
};

enum tnl_decap_next_nodes {
	TNL_DECAP_NEXT_PKT_DROP,
	TNL_DECAP_NEXT_FLOW_MAPPER,
	TNL_DECAP_NEXT_MAX,
};

struct tnl_decap_node_ctx {
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
struct rte_node_register *tnl_decap_node_get(void);

#endif /* __OOD_TNL_DECAP_PRIV_H__ */
