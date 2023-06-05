/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_GRAPH_NODES_RXTX_NODE_PRIV_H_
#define _APP_SECGW_GRAPH_NODES_RXTX_NODE_PRIV_H_

#define SECGW_MBUF_DEVINDEX_DYNFIELD_NAME "secgw_mbuf_devindex"

#define foreach_secgw_source_node_next_index		\
	_(ERROR_DROP, "secgw_error-drop")		\
	_(PORTMAPPER, "secgw_portmapper")		\
	_(IFACE_OUT, "secgw_interface-output")		\

typedef enum {
#define _(idx, nodename) SECGW_SOURCE_NODE_NEXT_INDEX_##idx,
	foreach_secgw_source_node_next_index
#undef _
	SECGW_SOURCE_NODE_MAX_NEXT_INDEX,
} secgw_source_node_next_index_t;

typedef uint16_t secgw_mbuf_devindex_dynfield_t;
extern int secgw_mbuf_devindex_dynfield_offset;

static inline secgw_mbuf_devindex_dynfield_t *
secgw_mbuf_devindex_dynfield(struct rte_mbuf *mbuf, secgw_mbuf_devindex_dynfield_t off)
{
	return RTE_MBUF_DYNFIELD(mbuf, off, secgw_mbuf_devindex_dynfield_t *);
}

struct rte_node_register *secgw_ethdevrx_node_get(void);
struct rte_node_register *secgw_ethdevtx_node_get(void);
struct rte_node_register *secgw_taprx_node_get(void);
struct rte_node_register *secgw_taptx_node_get(void);
#endif
