/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_flow.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_hash_crc.h>
#include <rte_malloc.h>

#include <dao_log.h>

#include <ood_node_ctrl.h>

#include "ood_tnl_decap_priv.h"

struct tnl_decap_node_main *tnl_decap_nm;
#define TNL_DECAP_NODE_PRIV1_OFF(ctx) (((struct tnl_decap_node_ctx *)ctx)->mbuf_priv1_off)

#define DEFAULT_VXLAN_PORT 4789
/* structure that caches offload info for the current packet */
union tunnel_offload_info {
	uint64_t data;
	struct {
		uint64_t l2_len : 7;        /**< L2 (MAC) Header Length. */
		uint64_t l3_len : 9;        /**< L3 (IP) Header Length. */
		uint64_t l4_len : 8;        /**< L4 Header Length. */
		uint64_t tso_segsz : 16;    /**< TCP TSO segment size */
		uint64_t outer_l2_len : 7;  /**< outer L2 Header Length */
		uint64_t outer_l3_len : 16; /**< outer L3 Header Length */
	};
};

static void
parse_ethernet(struct rte_ether_hdr *eth_hdr, union tunnel_offload_info *info, uint8_t *l4_proto)
{
	struct rte_vlan_hdr *vlan_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	uint16_t ethertype;

	info->outer_l2_len = sizeof(struct rte_ether_hdr);
	ethertype = rte_be_to_cpu_16(eth_hdr->ether_type);

	if (ethertype == RTE_ETHER_TYPE_VLAN) {
		vlan_hdr = (struct rte_vlan_hdr *)(eth_hdr + 1);
		info->outer_l2_len += sizeof(struct rte_vlan_hdr);
		ethertype = rte_be_to_cpu_16(vlan_hdr->eth_proto);
	}

	switch (ethertype) {
	case RTE_ETHER_TYPE_IPV4:
		ipv4_hdr = (struct rte_ipv4_hdr *)((char *)eth_hdr + info->outer_l2_len);
		info->outer_l3_len = sizeof(struct rte_ipv4_hdr);
		*l4_proto = ipv4_hdr->next_proto_id;
		break;
	case RTE_ETHER_TYPE_IPV6:
		ipv6_hdr = (struct rte_ipv6_hdr *)((char *)eth_hdr + info->outer_l2_len);
		info->outer_l3_len = sizeof(struct rte_ipv6_hdr);
		*l4_proto = ipv6_hdr->proto;
		break;
	default:
		info->outer_l3_len = 0;
		*l4_proto = 0;
		break;
	}
}

static int
vxlan_decapsulation(struct rte_mbuf *pkt)
{
	uint8_t l4_proto = 0;
	uint16_t outer_header_len;
	struct rte_udp_hdr *udp_hdr;
	union tunnel_offload_info info = {.data = 0};
	struct rte_ether_hdr *phdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);

	parse_ethernet(phdr, &info, &l4_proto);

	if (l4_proto != IPPROTO_UDP)
		return -1;

	udp_hdr = (struct rte_udp_hdr *)((char *)phdr + info.outer_l2_len + info.outer_l3_len);

	if (udp_hdr->dst_port != rte_cpu_to_be_16(DEFAULT_VXLAN_PORT) &&
	    (pkt->packet_type & RTE_PTYPE_TUNNEL_MASK) == 0)
		return -1;
	outer_header_len = info.outer_l2_len + info.outer_l3_len + sizeof(struct rte_udp_hdr) +
			   sizeof(struct rte_vxlan_hdr);

	rte_pktmbuf_adj(pkt, outer_header_len);

	return 0;
}

static void
tunnel_decapsulation(struct rte_node *node, struct rte_mbuf *m)
{
	const int dyn = TNL_DECAP_NODE_PRIV1_OFF(node->ctx);
	uint16_t tnl_type;

	tnl_type = node_mbuf_priv1(m, dyn)->tnl_type;
	dao_dbg("	tnl_type %x", tnl_type);

	switch (tnl_type) {
	case RTE_FLOW_ITEM_TYPE_VXLAN:
		dao_dbg("VxLAN tunnel decapsulation");
		vxlan_decapsulation(m);
		break;
	case RTE_FLOW_ITEM_TYPE_VXLAN_GPE:
		break;
	case RTE_FLOW_ITEM_TYPE_GRE:
		break;
	default:
		dao_err("Invalid tunnel type %x", tnl_type);
		break;
	};
}

static uint16_t
tnl_decap_node_process(struct rte_graph *graph, struct rte_node *node, void **objs,
		       uint16_t nb_objs)
{
	uint16_t last_spec = 0;
	rte_edge_t next_index, next;
	uint16_t held = 0;
	void **to_next, **from;
	struct rte_mbuf *mbuf;
	int i;

	/* Next flow mapper node */
	from = objs;
	next_index = TNL_DECAP_NEXT_FLOW_MAPPER;

	/* Get stream for the speculated next node */
	to_next = rte_node_next_stream_get(graph, node, next_index, nb_objs);
	from = objs;
	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		next = TNL_DECAP_NEXT_FLOW_MAPPER;
		/* Get the mark id from the packet */
		dao_dbg("	Worker %d Packet %d source port %d  new dest %d, total pkts %d",
			rte_lcore_id(), i, mbuf->port, next, nb_objs);
		tunnel_decapsulation(node, mbuf);
		if (unlikely(next_index != next)) {
			/* Copy things successfully speculated till now */
			rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;

			rte_node_enqueue_x1(graph, node, next, from[0]);
			from += 1;
		} else {
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

static int
tnl_decap_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	RTE_SET_USED(graph);
	static bool init_once;

	if (!init_once) {
		node_mbuf_priv1_dynfield_queue =
			rte_mbuf_dynfield_register(&node_mbuf_priv1_dynfield_desc);
		if (node_mbuf_priv1_dynfield_queue < 0)
			return -rte_errno;

		if (tnl_decap_nm == NULL) {
			tnl_decap_nm =
				rte_zmalloc("tunnel_decap", sizeof(struct tnl_decap_node_main),
					    RTE_CACHE_LINE_SIZE);
			if (tnl_decap_nm == NULL)
				return -ENOMEM;
		}
		init_once = 1;
	}

	TNL_DECAP_NODE_PRIV1_OFF(node->ctx) = node_mbuf_priv1_dynfield_queue;
	dao_dbg("node_mbuf_priv1_dynfield_queue %d", node_mbuf_priv1_dynfield_queue);

	return 0;
}

static struct rte_node_register tnl_decap_node = {
	.process = tnl_decap_node_process,
	.name = "tunnel_decap",

	.init = tnl_decap_node_init,

	.nb_edges = TNL_DECAP_NEXT_MAX,
	.next_nodes = {
			[TNL_DECAP_NEXT_PKT_DROP] = "pkt_drop",
			[TNL_DECAP_NEXT_FLOW_MAPPER] = "flow_mapper",
		},
};

struct rte_node_register *
tnl_decap_node_get(void)
{
	return &tnl_decap_node;
}

RTE_NODE_REGISTER(tnl_decap_node);
