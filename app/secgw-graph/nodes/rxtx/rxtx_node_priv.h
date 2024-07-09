/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_GRAPH_NODES_RXTX_NODE_PRIV_H_
#define _APP_SECGW_GRAPH_NODES_RXTX_NODE_PRIV_H_

#include <secgw_worker.h>

#define SECGW_MBUF_DEVINDEX_DYNFIELD_NAME "secgw_mbuf_devindex"

#define _dmac(p, off)	(p)->dst_addr.addr_bytes[off]
#define _smac(p, off)	(p)->src_addr.addr_bytes[off]

/* For fast path node logs */
#define node_debug			dao_dbg
#define ip_debug			dao_dbg

/* For control path node logs */
extern int rte_dao_logtype;
#define SECGW_NODE_LOG(level, node_name, ...)					\
	rte_log(RTE_LOG_##level, rte_dao_logtype,				\
		RTE_FMT("NODE %s: %s():%u " RTE_FMT_HEAD(__VA_ARGS__ ,) "\n",	\
			node_name, __func__, __LINE__,				\
			RTE_FMT_TAIL(__VA_ARGS__ ,)))

#define secgw_node_err(node_name, ...)		SECGW_NODE_LOG(ERR, node_name, __VA_ARGS__)
#define secgw_node_info(node_name, ...)		SECGW_NODE_LOG(INFO, node_name, __VA_ARGS__)
#define secgw_node_dbg(node_name, ...)		SECGW_NODE_LOG(DEBUG, node_name, __VA_ARGS__)

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
