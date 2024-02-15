/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_GRAPH_NODES_RXTX_NODE_PRIV_H_
#define _APP_SECGW_GRAPH_NODES_RXTX_NODE_PRIV_H_

#include <secgw_worker.h>

#define SECGW_MBUF_DEVINDEX_DYNFIELD_NAME "secgw_mbuf_devindex"
#define node_debug			dao_dbg
#define ip_debug			dao_dbg
#define _dmac(p, off)	(p)->dst_addr.addr_bytes[off]
#define _smac(p, off)	(p)->src_addr.addr_bytes[off]

typedef enum {
	SECGW_SOURCE_NODE_NEXT_INDEX_PKT_CLS,
	SECGW_SOURCE_NODE_NEXT_INDEX_PORTMAPPER,
	SECGW_SOURCE_NODE_MAX_NEXT_INDEX,
} secgw_source_node_next_index_t;

typedef struct {
	uint32_t ingress_port;
	uint32_t egress_port;
} secgw_mbuf_dynfield_t;

extern int secgw_mbuf_dynfield_offset;

static inline secgw_mbuf_dynfield_t *
secgw_mbuf_dynfield(struct rte_mbuf *mbuf)
{
	return RTE_MBUF_DYNFIELD(mbuf, secgw_mbuf_dynfield_offset, secgw_mbuf_dynfield_t *);
}

#define SECGW_INGRESS_PORT(dyn)		(dyn)->ingress_port
#define SECGW_EGRESS_PORT(dyn)		(dyn)->egress_port

#define SECGW_MBUF_EGRESS_PORT(mbuf)		(secgw_mbuf_dynfield(mbuf))->egress_port
#define SECGW_MBUF_INGRESS_PORT(mbuf)		(secgw_mbuf_dynfield(mbuf))->ingress_port

struct rte_node_register *secgw_ethdevrx_node_get(void);
struct rte_node_register *secgw_ethdevtx_node_get(void);
struct rte_node_register *secgw_taprx_node_get(void);
struct rte_node_register *secgw_taptx_node_get(void);
#endif
