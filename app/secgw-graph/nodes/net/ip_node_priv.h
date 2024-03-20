/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __APP_SECGW_GRAPH_NODES_NET_NODE_PRIV_H__
#define __APP_SECGW_GRAPH_NODES_NET_NODE_PRIV_H__

#include <rte_bitmap.h>
#include <rte_bitops.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_crypto_sym.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_security.h>
#include <rte_spinlock.h>

#include <dao_log.h>
#include <dao_util.h>

#include <dao_dynamic_string.h>
#include <dao_graph_feature_arc.h>
#include <dao_graph_feature_arc_worker.h>
#include <dao_netlink.h>
#include <dao_port_group.h>
#include <dao_portq_group_worker.h>
#include <dao_workers.h>

#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>

/**
 * @internal
 *
 * Get the ipv4 local node.
 *
 * @return
 *   Pointer to the ipv4 local node.
 */

struct rte_node_register *secgw_ip4_local_node_get(void);

/**
 * Node mbuf private data to store next hop, ttl and checksum.
 */
struct secgw_mbuf_priv1 {
	union {
		/* IP4/IP6 rewrite */
		struct {
			uint16_t nh;
			uint16_t ttl;
			uint32_t cksum;
		};

		uint64_t u;
	};
};

static const struct rte_mbuf_dynfield secgw_mbuf_priv1_dynfield_desc = {
	.name = "rte_node_dynfield_priv1",
	.size = sizeof(struct secgw_mbuf_priv1),
	.align = __alignof__(struct secgw_mbuf_priv1),
};

extern int secgw_mbuf_priv1_dynfield_offset;

/**
 * Node mbuf private area 2.
 */
struct secgw_mbuf_priv2 {
	uint64_t priv_data;
} __rte_cache_aligned;

#define SECGW_OBJS_PER_CLINE (RTE_CACHE_LINE_SIZE / sizeof(void *))

/**
 * Get mbuf_priv1 pointer from rte_mbuf.
 *
 * @param
 *   Pointer to the rte_mbuf.
 *
 * @return
 *   Pointer to the mbuf_priv1.
 */
static __rte_always_inline struct secgw_mbuf_priv1 *
secgw_mbuf_priv1(struct rte_mbuf *m, const int offset)
{
	return RTE_MBUF_DYNFIELD(m, offset, struct secgw_mbuf_priv1 *);
}

/**
 * Get mbuf_priv2 pointer from rte_mbuf.
 *
 * @param
 *   Pointer to the rte_mbuf.
 *
 * @return
 *   Pointer to the mbuf_priv2.
 */
static __rte_always_inline struct secgw_mbuf_priv2 *
secgw_mbuf_priv2(struct rte_mbuf *m)
{
	return (struct secgw_mbuf_priv2 *)rte_mbuf_to_priv(m);
}

#endif
