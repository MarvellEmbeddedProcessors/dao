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

#include <nodes/node_api.h>
#define __hexdump(...)
typedef enum {
	SECGW_IPSEC_DROP,
	SECGW_IPSEC_IFACE_OUT,
	SECGW_IPSEC4_LOOKUP,
	SECGW_IPSEC_NEXT_MAX_EDGES
} secgw_ipsec_policy_output_next_t;

struct ipsec_policy_output_node_ctx {
	dao_graph_feature_arc_t output_feature_arc;
	/* Cached next index */
	uint16_t last_next_index;
	uint16_t last_port;
	dao_graph_feature_t last_feat;
};

#define IPSEC_POLICY_OUTPUT_NODE_LAST_PORT(ctx)                                                    \
	(((struct ipsec_policy_output_node_ctx *)ctx)->last_port)
#define IPSEC_POLICY_OUTPUT_NODE_LAST_NEXT(ctx)                                                    \
	(((struct ipsec_policy_output_node_ctx *)ctx)->last_next_index)
#define IPSEC_POLICY_OUTPUT_FEATURE_ARC(ctx)                                                       \
	(((struct ipsec_policy_output_node_ctx *)ctx)->output_feature_arc)
#define IPSEC_POLICY_OUTPUT_NODE_LAST_FEAT(ctx)                                                    \
	(((struct ipsec_policy_output_node_ctx *)ctx)->last_feat)

static uint16_t
__ipsec_policy_output_node_process(dao_graph_feature_arc_t _df, struct rte_graph *graph,
				   struct rte_node *node, void **objs, uint16_t nb_objs,
				   const char *node_name)
{
	uint16_t n_left_from, held = 0, last_spec = 0;
	secgw_ipsec4_policy_t *ips_policy = NULL;
	struct dao_graph_feature_arc *df = NULL;
	uint16_t next_index, next0, cached_port;
	dao_graph_feature_data_t *fdata = NULL;
	struct rte_mbuf *mbuf0 = NULL, **pkts;
	struct rte_ipv4_hdr *ip0 = NULL;
#ifdef SECGW_DEBUG_PKT_TRACE
	secgw_ip4_addr_t *dst_ip, *src_ip;
	secgw_ip4_addr_t dip, sip;
#endif
	struct rte_ether_hdr *e0 = NULL;
	secgw_ipsec_sa_t *sa = NULL;
	const uint8_t *acl_key[4];
	dao_graph_feature_t feat;
	secgw_ipsec_t *ips = NULL;
	void **to_next, **from;
	uint32_t acl_result[4];
	uint8_t *d0 = NULL;
	int i;

	RTE_SET_USED(node_name);
	df = dao_graph_feature_arc_get(_df);
	/* Speculative next as last next */
	cached_port = IPSEC_POLICY_OUTPUT_NODE_LAST_PORT(node->ctx);
	next_index = IPSEC_POLICY_OUTPUT_NODE_LAST_NEXT(node->ctx);
	feat = IPSEC_POLICY_OUTPUT_NODE_LAST_FEAT(node->ctx);
	pkts = (struct rte_mbuf **)objs;
	n_left_from = nb_objs;
	from = objs;

	for (i = 0; i < 4 && i < n_left_from; i++)
		rte_prefetch0(pkts[i]);

	/* Get stream for the speculated next node */
	to_next = rte_node_next_stream_get(graph, node, next_index, nb_objs);
	while (n_left_from > 0) {
		mbuf0 = pkts[0];
		ip0 = rte_pktmbuf_mtod_offset(mbuf0, struct rte_ipv4_hdr *,
					      sizeof(struct rte_ether_hdr));
#ifdef SECGW_DEBUG_PKT_TRACE
		src_ip = &sip;
		dst_ip = &dip;
		memcpy(src_ip, &ip0->src_addr, sizeof(secgw_ip4_addr_t));
		memcpy(dst_ip, &ip0->dst_addr, sizeof(secgw_ip4_addr_t));
#endif
		if (unlikely(SECGW_MBUF_EGRESS_PORT(mbuf0) != cached_port)) {
			cached_port = SECGW_MBUF_EGRESS_PORT(mbuf0);
			/* Get IPsec instance attached to this port */
			feat = SECGW_MBUF_FEATURE(mbuf0);
		}
		fdata = dao_graph_feature_data_get(dao_graph_feature_get(df, cached_port), feat);
		ips = secgw_ipsec_get(secgw_ipsec_main_get(), (uint32_t)fdata->data);
		ips_policy = &(ips->spds.outbound4);
		acl_key[0] = &ip0->next_proto_id;

		rte_acl_classify(ips_policy->acl_ctx, acl_key, acl_result, 1,
				 SECGW_ACL_CLASSIFY_ALGO);
		acl_result[0] -= 1;
		switch (acl_result[0]) {
		case SECGW_IPSEC_POLICY_BYPASS:
			/* Bypass send packet untouched */
			if (mbuf0->ol_flags & RTE_MBUF_F_TX_SEC_OFFLOAD) {
				e0 = rte_pktmbuf_mtod_offset(mbuf0, struct rte_ether_hdr *, 0);
				sa = (secgw_ipsec_sa_t *)SECGW_MBUF_USERPTR(mbuf0);
				/*
				 * Clear explicit flag and set if sa is valid via
				 * rte_ipsec_pkt_process() function
				 * This is not required though as other
				 * bypass packet won't till here
				 */
				mbuf0->ol_flags &= ~RTE_MBUF_F_TX_SEC_OFFLOAD;
				if (sa && (sa->sa_flags & (SECGW_IPSEC_SA_F_MODE_TUNNEL |
							   SECGW_IPSEC_SA_F_TUNNEL_IPV4))) {
					e0->ether_type = rte_bswap16(RTE_ETHER_TYPE_IPV4);
					mbuf0->l3_len = sizeof(struct rte_ipv4_hdr);
					mbuf0->l2_len = RTE_ETHER_HDR_LEN;
					ip0 = rte_pktmbuf_mtod_offset(
						mbuf0, struct rte_ipv4_hdr *,
						(RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr)));
					d0 = rte_pktmbuf_mtod_offset(mbuf0, uint8_t *,
								     (sizeof(struct rte_ipv4_hdr)));
					memcpy(d0, e0, RTE_ETHER_HDR_LEN);
					__hexdump(stdout, "Overwritten DMAC:", d0,
						  sizeof(struct rte_ipv4_hdr) + RTE_ETHER_HDR_LEN);
					rte_pktmbuf_adj(mbuf0, sizeof(struct rte_ipv4_hdr));
					rte_ipsec_pkt_process(&sa->lipsec_session, pkts, 1);
				}
				ip_debug("%15s(%p): [%u:%u:%u:%u -> %u:%u:%u:%u]"
					 "[acl_res: %d, Bypass ESP Outer IP]"
					 "[oflags: 0x%lx, doff: %u, l2t: 0x%x, l3t: 0x%x], [dlen:"
					 "%u, plen: %u, l2l:%u, l3l:%u]",
					 node_name, mbuf0, src_ip->u8[0], src_ip->u8[1],
					 src_ip->u8[2], src_ip->u8[3], dst_ip->u8[0], dst_ip->u8[1],
					 dst_ip->u8[2], dst_ip->u8[3], (int32_t)acl_result[0],
					 mbuf0->ol_flags, mbuf0->data_off, mbuf0->l2_type,
					 mbuf0->l3_type, mbuf0->data_len, mbuf0->pkt_len,
					 mbuf0->l2_len, mbuf0->l3_len);
				__hexdump(stdout, "Outbound ESP pkt",
					  rte_pktmbuf_mtod_offset(mbuf0, uint8_t *, 0),
					  mbuf0->pkt_len);
			} else {
				ip_debug(
					"%15s(%p): [%u:%u:%u:%u -> %u:%u:%u:%u][acl_res: %d, Bypass Pkt]"
					"[oflags: 0x%lx, doff: %u, l2t: 0x%x, l3t: 0x%x], [dlen:"
					"%u, plen: %u, l2l:%u, l3l:%u]",
					node_name, mbuf0, src_ip->u8[0], src_ip->u8[1],
					src_ip->u8[2], src_ip->u8[3], dst_ip->u8[0], dst_ip->u8[1],
					dst_ip->u8[2], dst_ip->u8[3], (int32_t)acl_result[0],
					mbuf0->ol_flags, mbuf0->data_off, mbuf0->l2_type,
					mbuf0->l3_type, mbuf0->data_len, mbuf0->pkt_len,
					mbuf0->l2_len, mbuf0->l3_len);
			}
			next0 = SECGW_IPSEC_IFACE_OUT;
			break;

		case SECGW_IPSEC_POLICY_DISCARD:
			ip_debug("%15s(%p): [%u:%u:%u:%u -> %u:%u:%u:%u][acl_res: %d, DISCARD PKT]"
				 "[oflags: 0x%lx, doff: %u, l2t: 0x%x, l3t: 0x%x], [dlen:"
				 "%u, plen: %u, l2l:%u, l3l:%u]",
				 node_name, mbuf0, src_ip->u8[0], src_ip->u8[1], src_ip->u8[2],
				 src_ip->u8[3], dst_ip->u8[0], dst_ip->u8[1], dst_ip->u8[2],
				 dst_ip->u8[3], (int32_t)acl_result[0], mbuf0->ol_flags,
				 mbuf0->data_off, mbuf0->l2_type, mbuf0->l3_type, mbuf0->data_len,
				 mbuf0->pkt_len, mbuf0->l2_len, mbuf0->l3_len);
			next0 = SECGW_IPSEC_DROP;
			break;

		default:
			sa = secgw_ipsec_sa_get(ips->sadb_v4, acl_result[0]);
			mbuf0->ol_flags |= RTE_MBUF_F_TX_SEC_OFFLOAD;
			ip_debug(
				"%15s(%p): [%s -> %s][%u:%u:%u:%u -> %u:%u:%u:%u][Protect, sa_idx: %d, SPI: %u]"
				"[oflags: 0x%lx, doff: %u, l2t: 0x%x, l3t: 0x%x], [dlen:"
				"%u, plen: %u, l2l:%u, l3l:%u]",
				node_name, mbuf0,
				secgw_get_device(SECGW_MBUF_INGRESS_PORT(mbuf0))->dev_name,
				secgw_get_device(SECGW_MBUF_EGRESS_PORT(mbuf0))->dev_name,
				src_ip->u8[0], src_ip->u8[1], src_ip->u8[2], src_ip->u8[3],
				dst_ip->u8[0], dst_ip->u8[1], dst_ip->u8[2], dst_ip->u8[3],
				(int32_t)acl_result[0], sa->xfrm_sa->spi, mbuf0->ol_flags,
				mbuf0->data_off, mbuf0->l2_type, mbuf0->l3_type, mbuf0->data_len,
				mbuf0->pkt_len, mbuf0->l2_len, mbuf0->l3_len);

			if (sa->sa_flags &
			    (SECGW_IPSEC_SA_F_MODE_TUNNEL | SECGW_IPSEC_SA_F_TUNNEL_IPV4)) {
				/* Make room for more extra IPv4 hdr */
				d0 = rte_pktmbuf_mtod_offset(mbuf0, uint8_t *,
							     (sizeof(struct rte_ether_hdr) -
							      sizeof(struct rte_ipv4_hdr)));
				memcpy(d0, &sa->v4_hdr, sizeof(struct rte_ipv4_hdr));
				__hexdump(stdout, "Pre-lookup double IP tunneled pkt", d0,
					  2 * sizeof(struct rte_ipv4_hdr));

				/* prepend mbuf by extra IPv4 header*/
				rte_pktmbuf_prepend(mbuf0, sizeof(struct rte_ipv4_hdr));

				/* TODO: Check if following statement required
				 * i.e reset mbuf feature
				 */
				SECGW_MBUF_FEATURE(mbuf0) = DAO_GRAPH_FEATURE_INVALID_VALUE;
				SECGW_MBUF_USERPTR(mbuf0) = (void *)sa;
				next0 = SECGW_IPSEC4_LOOKUP;
			} else {
				next0 = SECGW_IPSEC_DROP;
			}
			break;
		}
		if (unlikely(next_index ^ next0)) {
			/* Copy things successfully speculated till now */
			rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;
			rte_node_enqueue_x1(graph, node, next0, from[0]);
			from += 1;
		} else {
			last_spec += 1;
		}
		n_left_from--;
		pkts++;
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
	IPSEC_POLICY_OUTPUT_NODE_LAST_PORT(node->ctx) = cached_port;
	IPSEC_POLICY_OUTPUT_NODE_LAST_NEXT(node->ctx) = next_index;
	IPSEC_POLICY_OUTPUT_NODE_LAST_FEAT(node->ctx) = feat;

	return nb_objs;
}

static uint16_t
ipsec_policy_output_node_process(struct rte_graph *graph, struct rte_node *node, void **objs,
				 uint16_t nb_objs)
{
	dao_graph_feature_arc_t df = IPSEC_POLICY_OUTPUT_FEATURE_ARC(node->ctx);

	return (__ipsec_policy_output_node_process(df, graph, node, objs, nb_objs,
						   "ipsec4_policy_out"));
}

static int
ipsec_policy_output_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	dao_graph_feature_arc_t df = DAO_GRAPH_FEATURE_ARC_INITIALIZER;

	RTE_SET_USED(graph);

	if (dao_graph_feature_arc_lookup_by_name(IP4_OUTPUT_FEATURE_ARC_NAME, &df) < 0)
		return -1;

	IPSEC_POLICY_OUTPUT_FEATURE_ARC(node->ctx) = df;
	IPSEC_POLICY_OUTPUT_NODE_LAST_PORT(node->ctx) = ~0;
	IPSEC_POLICY_OUTPUT_NODE_LAST_NEXT(node->ctx) = 0;

	secgw_node_dbg("ipsec_policy_output", "Initialized ipsec_policy_output node initialized");

	return 0;
}

static struct rte_node_register secgw_ipsec_policy_output_node = {
	.process = ipsec_policy_output_node_process,
	.name = "secgw_ipsec-policy-output",
	/* Default edge i.e '0' is pkt drop */
	.nb_edges = SECGW_IPSEC_NEXT_MAX_EDGES,
	.next_nodes = {
			[SECGW_IPSEC_DROP] = "secgw_error-drop",
			[SECGW_IPSEC4_LOOKUP] = "secgw_ip4-lookup",
			[SECGW_IPSEC_IFACE_OUT] = "secgw_interface-output",
		},
	.init = ipsec_policy_output_node_init,
};

struct rte_node_register *
secgw_ipsec_policy_output_node_get(void)
{
	return &secgw_ipsec_policy_output_node;
}

RTE_NODE_REGISTER(secgw_ipsec_policy_output_node);
