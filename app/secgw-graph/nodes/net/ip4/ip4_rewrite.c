/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_vect.h>

#include <nodes/net/ip_node_priv.h>
#include <nodes/node_api.h>

struct secgw_ip4_rewrite_node_ctx {
	/* Dynamic offset to mbuf priv1 */
	int mbuf_priv1_off;
	/* Cached next index */
	uint16_t next_index;
	dao_graph_feature_arc_t output_feature_arc;
};

typedef union {
	rte_be32_t u32;
	struct {
		uint8_t u8[4];
	};
} secgw_ip4_addr_t;

typedef enum {
	ERROR_DROP = 0,
	IFACE_OUT = 1,
} rewrite_next_node_t;

static struct secgw_ip4_rewrite_node_main *secgw_ip4_rewrite_nm;

#define SECGW_IP4_REWRITE_NODE_LAST_NEXT(ctx)		\
		(((struct secgw_ip4_rewrite_node_ctx *)ctx)->next_index)

#define SECGW_IP4_REWRITE_NODE_PRIV1_OFF(ctx)		\
		(((struct secgw_ip4_rewrite_node_ctx *)ctx)->mbuf_priv1_off)
#define SECGW_IP4_REWRITE_OUTPUT_FEATURE_ARC(ctx)	\
		(((struct secgw_ip4_rewrite_node_ctx *)ctx)->output_feature_arc)

static uint16_t
secgw_ip4_rewrite_node_process(struct rte_graph *graph, struct rte_node *node, void **objs,
			       uint16_t nb_objs)
{
	dao_graph_feature_arc_t _df = SECGW_IP4_REWRITE_OUTPUT_FEATURE_ARC(node->ctx);
	struct dao_graph_feature_arc *df = dao_graph_feature_arc_get(_df);
	struct secgw_ip4_rewrite_nh_header *nh = secgw_ip4_rewrite_nm->nh;
	const int dyn = SECGW_IP4_REWRITE_NODE_PRIV1_OFF(node->ctx);
	secgw_ip4_addr_t *dst_ip = NULL, *src_ip = NULL;
	dao_graph_feature_t feat = DAO_GRAPH_FEATURE_INVALID_VALUE;
	uint16_t n_left_from, held = 0, last_spec = 0;
	uint16_t next_index, next0 = IFACE_OUT;
	struct rte_mbuf *mbuf0 = NULL, **pkts;
	struct rte_ether_hdr *e = NULL;
	int64_t fdata = INT64_MAX;
	struct rte_ipv4_hdr *ip0;
	void **to_next, **from;
	void *d0;
	int i;

	RTE_SET_USED(e);
	/* Speculative next as last next */
	next_index = SECGW_IP4_REWRITE_NODE_LAST_NEXT(node->ctx);
	rte_prefetch0(nh);

	pkts = (struct rte_mbuf **)objs;
	from = objs;
	n_left_from = nb_objs;

	for (i = 0; i < 4 && i < n_left_from; i++)
		rte_prefetch0(pkts[i]);

	/* Get stream for the speculated next node */
	to_next = rte_node_next_stream_get(graph, node, next_index, nb_objs);
	/* Update Ethernet header of pkts */
	while (n_left_from > 0) {
		uint16_t chksum;

		mbuf0 = pkts[0];

		pkts += 1;
		n_left_from -= 1;

		d0 = rte_pktmbuf_mtod(mbuf0, void *);
		e = rte_pktmbuf_mtod(mbuf0, struct rte_ether_hdr *);
		rte_memcpy(d0, nh[secgw_mbuf_priv1(mbuf0, dyn)->nh].rewrite_data,
			   nh[secgw_mbuf_priv1(mbuf0, dyn)->nh].rewrite_len);

		SECGW_MBUF_EGRESS_PORT(mbuf0) = nh[secgw_mbuf_priv1(mbuf0, dyn)->nh].tx_node;
		ip0 = (struct rte_ipv4_hdr *)((uint8_t *)d0 + sizeof(struct rte_ether_hdr));
		chksum = secgw_mbuf_priv1(mbuf0, dyn)->cksum + rte_cpu_to_be_16(0x0100);
		chksum += chksum >= 0xffff;
		ip0->hdr_checksum = chksum;
		ip0->time_to_live = secgw_mbuf_priv1(mbuf0, dyn)->ttl - 1;
		dst_ip = (secgw_ip4_addr_t *)&ip0->dst_addr;
		src_ip = (secgw_ip4_addr_t *)&ip0->src_addr;

		if (unlikely(dao_graph_feature_arc_has_feature(df,
							       SECGW_MBUF_EGRESS_PORT(mbuf0),
							       &feat)))
			dao_graph_feature_arc_first_feature_data_get(df, feat,
								     SECGW_MBUF_EGRESS_PORT(mbuf0),
								     (rte_edge_t *)&next0,
								     &fdata);

		if (unlikely(next_index ^ next0)) {
			/* Copy things successfully speculated till now */
			rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;
			ip_debug("rewrite: (%s->%s), [%u:%u:%u:%u -> %u:%u:%u:%u]"
				 "[%x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x]",
				 secgw_get_device(SECGW_MBUF_INGRESS_PORT(mbuf0))->dev_name,
				 secgw_get_device(SECGW_MBUF_EGRESS_PORT(mbuf0))->dev_name,
				 src_ip->u8[0], src_ip->u8[1], src_ip->u8[2],
				 src_ip->u8[3], dst_ip->u8[0], dst_ip->u8[1],
				 dst_ip->u8[2], dst_ip->u8[3], _smac(e, 0),
				 _smac(e, 1), _smac(e, 2), _smac(e, 3),
				 _smac(e, 4), _smac(e, 5), _dmac(e, 0),
				 _dmac(e, 1), _dmac(e, 2), _dmac(e, 3),
				 _dmac(e, 4), _dmac(e, 5));
			rte_node_enqueue_x1(graph, node, next0, from[0]);
			from += 1;
		} else {
			ip_debug("rewrite: (%s->%s), [%u:%u:%u:%u -> %u:%u:%u:%u]"
				 "[%x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x]",
				 secgw_get_device(SECGW_MBUF_INGRESS_PORT(mbuf0))->dev_name,
				 secgw_get_device(SECGW_MBUF_EGRESS_PORT(mbuf0))->dev_name,
				 src_ip->u8[0], src_ip->u8[1], src_ip->u8[2],
				 src_ip->u8[3], dst_ip->u8[0], dst_ip->u8[1],
				 dst_ip->u8[2], dst_ip->u8[3], _smac(e, 0),
				 _smac(e, 1), _smac(e, 2), _smac(e, 3),
				 _smac(e, 4), _smac(e, 5), _dmac(e, 0),
				 _dmac(e, 1), _dmac(e, 2), _dmac(e, 3),
				 _dmac(e, 4), _dmac(e, 5));
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
	/* Save the last next used */
	SECGW_IP4_REWRITE_NODE_LAST_NEXT(node->ctx) = next_index;

	return nb_objs;
}

static int
secgw_ip4_rewrite_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	dao_graph_feature_arc_t df = DAO_GRAPH_FEATURE_ARC_INITIALIZER;
	static bool init_once;

	RTE_SET_USED(graph);
	RTE_BUILD_BUG_ON(sizeof(struct secgw_ip4_rewrite_node_ctx) > RTE_NODE_CTX_SZ);

	if (!init_once) {
		secgw_mbuf_priv1_dynfield_offset =
			rte_mbuf_dynfield_register(&secgw_mbuf_priv1_dynfield_desc);
		if (secgw_mbuf_priv1_dynfield_offset < 0)
			return -rte_errno;
		init_once = true;
	}
	SECGW_IP4_REWRITE_NODE_PRIV1_OFF(node->ctx) = secgw_mbuf_priv1_dynfield_offset;
	if (dao_graph_feature_arc_lookup_by_name(IP4_LOCAL_FEATURE_ARC_NAME, &df) < 0)
		return -1;

	SECGW_IP4_REWRITE_OUTPUT_FEATURE_ARC(node->ctx) = df;

	secgw_node_dbg("ip4_rewrite", "Initialized ip4_rewrite node initialized");

	return 0;
}

int
secgw_ip4_rewrite_set_next(uint16_t port_id, uint16_t next_index)
{
	if (secgw_ip4_rewrite_nm == NULL) {
		secgw_ip4_rewrite_nm = rte_zmalloc("ip4_rewrite",
						   sizeof(struct secgw_ip4_rewrite_node_main),
						   RTE_CACHE_LINE_SIZE);
		if (secgw_ip4_rewrite_nm == NULL)
			return -ENOMEM;
	}
	secgw_ip4_rewrite_nm->next_index[port_id] = next_index;

	return 0;
}

int
secgw_ip4_rewrite_add(uint16_t next_hop, uint8_t *rewrite_data, uint8_t rewrite_len,
		      uint16_t dst_port)
{
	struct secgw_ip4_rewrite_nh_header *nh;

	if (next_hop >= SECGW_GRAPH_IP4_REWRITE_MAX_NH)
		return -EINVAL;

	if (rewrite_len > SECGW_GRAPH_IP4_REWRITE_MAX_LEN)
		return -EINVAL;

	if (secgw_ip4_rewrite_nm == NULL) {
		secgw_ip4_rewrite_nm = rte_zmalloc("ip4_rewrite",
						   sizeof(struct secgw_ip4_rewrite_node_main),
						   RTE_CACHE_LINE_SIZE);
		if (secgw_ip4_rewrite_nm == NULL)
			return -ENOMEM;
	}
#ifdef SECGW_TODO
	/* Check if dst port doesn't exist as edge */
	if (!secgw_ip4_rewrite_nm->next_index[dst_port])
		return -EINVAL;
#endif
	/* Update next hop */
	nh = &secgw_ip4_rewrite_nm->nh[next_hop];

	memcpy(nh->rewrite_data, rewrite_data, rewrite_len);
	nh->tx_node = secgw_ip4_rewrite_nm->next_index[dst_port];
	dao_dbg("next_hop: %u, tx_node: %u", next_hop, nh->tx_node);
	nh->rewrite_len = rewrite_len;
	nh->enabled = true;

	return 0;
}

static struct rte_node_register secgw_ip4_rewrite_node = {
	.process = secgw_ip4_rewrite_node_process,
	.name = "secgw_ip4-rewrite",
	/* Default edge i.e '0' is pkt drop */
	.nb_edges = 1,
	.next_nodes = {
			[0] = "secgw_error-drop",
			[1] = "secgw_interface-output"
		},
	.init = secgw_ip4_rewrite_node_init,
};

struct rte_node_register *
secgw_ip4_rewrite_node_get(void)
{
	return &secgw_ip4_rewrite_node;
}

RTE_NODE_REGISTER(secgw_ip4_rewrite_node);
