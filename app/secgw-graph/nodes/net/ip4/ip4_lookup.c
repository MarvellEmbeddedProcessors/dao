/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <arpa/inet.h>
#include <sys/socket.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_lpm.h>

#include <nodes/net/ip4/ip4_lookup_priv.h>
#include <nodes/net/ip_node_priv.h>

#include <nodes/node_api.h>

#define IPV4_L3FWD_LPM_MAX_RULES    1024
#define IPV4_L3FWD_LPM_NUMBER_TBL8S (1 << 8)

/* IP4 Lookup global data struct */
struct secgw_ip4_lookup_node_main {
	struct rte_lpm *lpm_tbl[RTE_MAX_NUMA_NODES];
};

struct secgw_ip4_lookup_node_ctx {
	/* Socket's LPM table */
	struct rte_lpm *lpm;
	/* Dynamic offset to mbuf priv1 */
	int mbuf_priv1_off;
};

int secgw_mbuf_priv1_dynfield_offset = -1;

static struct secgw_ip4_lookup_node_main secgw_ip4_lookup_nm;

#define SECGW_IP4_LOOKUP_NODE_LPM(ctx) (((struct secgw_ip4_lookup_node_ctx *)ctx)->lpm)

#define SECGW_IP4_LOOKUP_NODE_PRIV1_OFF(ctx)                                                       \
	(((struct secgw_ip4_lookup_node_ctx *)ctx)->mbuf_priv1_off)

static uint16_t
secgw_ip4_lookup_node_process_scalar(struct rte_graph *graph, struct rte_node *node, void **objs,
				     uint16_t nb_objs)
{
	struct rte_lpm *lpm = SECGW_IP4_LOOKUP_NODE_LPM(node->ctx);
	const int dyn = SECGW_IP4_LOOKUP_NODE_PRIV1_OFF(node->ctx);
#ifdef SECGW_DEBUG_PKT_TRACE
	char __pkt_trace[256], *pkt_trace = NULL;
#endif
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_mbuf *mbuf = NULL;
	void **to_next, **from;
	uint16_t last_spec = 0;
	rte_edge_t next_index;
	uint16_t held = 0, ri;
	uint32_t drop_nh;
	int i, rc;

	RTE_SET_USED(ri);
#ifdef SECGW_DEBUG_PKT_TRACE
	pkt_trace = (char *)__pkt_trace;
#endif

	/* Speculative next */
	next_index = SECGW_NODE_IP4_LOOKUP_NEXT_REWRITE;
	/* Drop node */
	drop_nh = ((uint32_t)SECGW_NODE_IP4_LOOKUP_NEXT_PKT_DROP) << 16;
	from = objs;

	/* Get stream for the speculated next node */
	to_next = rte_node_next_stream_get(graph, node, next_index, nb_objs);
	for (i = 0; i < nb_objs; i++) {
		uint32_t next_hop;
		uint16_t next;

		mbuf = (struct rte_mbuf *)objs[i];

		/* Extract DIP of mbuf0 */
		ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *,
						   sizeof(struct rte_ether_hdr));
		/* Extract cksum, ttl as ipv4 hdr is in cache */
		secgw_mbuf_priv1(mbuf, dyn)->cksum = ipv4_hdr->hdr_checksum;
		secgw_mbuf_priv1(mbuf, dyn)->ttl = ipv4_hdr->time_to_live;
		rc = rte_lpm_lookup(lpm, rte_be_to_cpu_32(ipv4_hdr->dst_addr), &next_hop);
		next_hop = (rc == 0) ? next_hop : drop_nh;
		secgw_mbuf_priv1(mbuf, dyn)->nh = (uint16_t)next_hop;
		next = (uint16_t)(next_hop >> 16);
		ri = (uint16_t)(next_hop & 0xFFFF);

		if (unlikely(next_index != next)) {
			/* Copy things successfully speculated till now */
			rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;
#ifdef SECGW_DEBUG_PKT_TRACE
			sprintf(pkt_trace, "ri:%u, next-%u", ri, next);
			secgw_print_mbuf(graph, node, mbuf, next, pkt_trace, 0, 0);
#endif
			rte_node_enqueue_x1(graph, node, next, from[0]);
			from += 1;
		} else {
#ifdef SECGW_DEBUG_PKT_TRACE
			sprintf(pkt_trace, "ri:%u, next-%u", ri, next_index);
			secgw_print_mbuf(graph, node, mbuf, next_index, pkt_trace, 0, 0);
#endif
			last_spec += 1;
		}
	}

	/* !!! Home run !!! */
	if (likely(last_spec == nb_objs)) {
		rte_node_next_stream_move(graph, node, next_index);
		return nb_objs;
	}
	held += last_spec;
	rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
	rte_node_next_stream_put(graph, node, next_index, held);

	return nb_objs;
}

int
secgw_ip4_route_add(uint32_t ip, uint8_t depth, uint16_t next_hop,
		    enum secgw_node_ip4_lookup_next next_node)
{
	char abuf[INET6_ADDRSTRLEN];
	struct in_addr in;
	uint8_t socket;
	uint32_t val;
	int ret;

	in.s_addr = htonl(ip);
	inet_ntop(AF_INET, &in, abuf, sizeof(abuf));
	/* Embedded next node id into 24 bit next hop */
	val = ((next_node << 16) | next_hop) & ((1ull << 24) - 1);
	secgw_node_dbg("ip4_lookup", "LPM: Adding route %s / %d nh (0x%x)", abuf, depth, val);

	for (socket = 0; socket < RTE_MAX_NUMA_NODES; socket++) {
		if (!secgw_ip4_lookup_nm.lpm_tbl[socket])
			continue;

		ret = rte_lpm_add(secgw_ip4_lookup_nm.lpm_tbl[socket], ip, depth, val);
		if (ret < 0) {
			secgw_node_err(
				"ip4_lookup",
				"Unable to add entry %s / %d nh (%x) to LPM table on sock %d, rc=%d\n",
				abuf, depth, val, socket, ret);
			return ret;
		}
	}

	return 0;
}

static int
setup_lpm(struct secgw_ip4_lookup_node_main *nm, int socket)
{
	struct rte_lpm_config config_ipv4;
	char s[RTE_LPM_NAMESIZE];

	/* One LPM table per socket */
	if (nm->lpm_tbl[socket])
		return 0;

	/* create the LPM table */
	config_ipv4.max_rules = IPV4_L3FWD_LPM_MAX_RULES;
	config_ipv4.number_tbl8s = IPV4_L3FWD_LPM_NUMBER_TBL8S;
	config_ipv4.flags = 0;
	snprintf(s, sizeof(s), "IPV4_L3FWD_LPM_%d", socket);
	nm->lpm_tbl[socket] = rte_lpm_create(s, socket, &config_ipv4);
	if (nm->lpm_tbl[socket] == NULL)
		return -rte_errno;

	return 0;
}

static int
secgw_ip4_lookup_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	uint16_t socket, lcore_id;
	static uint8_t init_once;
	int rc;

	RTE_SET_USED(graph);
	RTE_BUILD_BUG_ON(sizeof(struct secgw_ip4_lookup_node_ctx) > RTE_NODE_CTX_SZ);

	if (!init_once) {
		secgw_mbuf_priv1_dynfield_offset =
			rte_mbuf_dynfield_register(&secgw_mbuf_priv1_dynfield_desc);
		if (secgw_mbuf_priv1_dynfield_offset < 0)
			return -rte_errno;

		/* Setup LPM tables for all sockets */
		RTE_LCORE_FOREACH(lcore_id) {
			socket = rte_lcore_to_socket_id(lcore_id);
			rc = setup_lpm(&secgw_ip4_lookup_nm, socket);
			if (rc) {
				secgw_node_err("ip4_lookup",
					       "Failed to setup lpm tbl for sock %u, rc=%d", socket,
					       rc);
				return rc;
			}
		}
		init_once = 1;
	}

	/* Update socket's LPM and mbuf dyn priv1 offset in node ctx */
	SECGW_IP4_LOOKUP_NODE_LPM(node->ctx) = secgw_ip4_lookup_nm.lpm_tbl[graph->socket];
	SECGW_IP4_LOOKUP_NODE_PRIV1_OFF(node->ctx) = secgw_mbuf_priv1_dynfield_offset;
	secgw_node_dbg("ip4_lookup", "Initialized ip4_lookup node");

	return 0;
}

static struct rte_node_register secgw_ip4_lookup_node = {
	.process = secgw_ip4_lookup_node_process_scalar,
	.name = "secgw_ip4-lookup",

	.init = secgw_ip4_lookup_node_init,

	.nb_edges = SECGW_NODE_IP4_LOOKUP_NEXT_PKT_DROP + 1,
	.next_nodes = {
			[SECGW_NODE_IP4_LOOKUP_NEXT_IP4_LOCAL] = "secgw_ip4-local",
			[SECGW_NODE_IP4_LOOKUP_NEXT_REWRITE] = "secgw_ip4-rewrite",
			[SECGW_NODE_IP4_LOOKUP_NEXT_PKT_DROP] = "secgw_port-mapper",
		},
};

struct rte_node_register *
secgw_ip4_lookup_node_get(void)
{
	return &secgw_ip4_lookup_node;
}

RTE_NODE_REGISTER(secgw_ip4_lookup_node);
