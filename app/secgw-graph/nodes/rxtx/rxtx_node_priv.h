/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_GRAPH_NODES_RXTX_NODE_PRIV_H_
#define _APP_SECGW_GRAPH_NODES_RXTX_NODE_PRIV_H_

#include <secgw_worker.h>

#define SECGW_MBUF_DEVINDEX_DYNFIELD_NAME "secgw_mbuf_devindex"

#define _dmac(p, off) (p)->dst_addr.addr_bytes[off]
#define _smac(p, off) (p)->src_addr.addr_bytes[off]
#define _eth(p, off)  (p)->addr_bytes[off]

#define foreach_secgw_arp_op_code                                                                  \
	_(1, "REQ")                                                                                \
	_(2, "REPLY")                                                                              \
	_(3, "REVREQ")                                                                             \
	_(4, "REVREPLY")                                                                           \
	_(8, "INVREQ")                                                                             \
	_(9, "INVREPLY")

#define SECGW_INGRESS_PORT(dyn) (dyn)->ingress_port
#define SECGW_EGRESS_PORT(dyn)  (dyn)->egress_port

#define SECGW_MBUF_EGRESS_PORT(mbuf)  (secgw_mbuf_dynfield(mbuf))->egress_port
#define SECGW_MBUF_FEATURE(mbuf)      (secgw_mbuf_dynfield(mbuf))->feature
#define SECGW_MBUF_INGRESS_PORT(mbuf) (secgw_mbuf_dynfield(mbuf))->ingress_port
#define SECGW_MBUF_USERPTR(mbuf)      (secgw_mbuf_dynfield(mbuf))->userptr

/* For fast path node logs */
#define node_debug dao_dbg
#ifdef SECGW_DEBUG_PKT_TRACE
#define ip_debug dao_info
#else
#define ip_debug(...)
#endif

/* For control path node logs */
extern int rte_dao_logtype;
#define SECGW_NODE_LOG(level, node_name, ...)                                                      \
	rte_log(RTE_LOG_##level, rte_dao_logtype,                                                  \
		RTE_FMT("NODE %s: %s():%u " RTE_FMT_HEAD(__VA_ARGS__ ,) "\n", node_name, __func__, \
			__LINE__, RTE_FMT_TAIL(__VA_ARGS__ ,)))

#define secgw_node_err(node_name, ...)  SECGW_NODE_LOG(ERR, node_name, __VA_ARGS__)
#define secgw_node_info(node_name, ...) SECGW_NODE_LOG(INFO, node_name, __VA_ARGS__)
#define secgw_node_dbg(node_name, ...)  SECGW_NODE_LOG(DEBUG, node_name, __VA_ARGS__)

typedef enum {
	SECGW_SOURCE_NODE_NEXT_INDEX_PKT_CLS,
	SECGW_SOURCE_NODE_NEXT_INDEX_PORTMAPPER,
	SECGW_SOURCE_NODE_MAX_NEXT_INDEX,
} secgw_source_node_next_index_t;

typedef union {
	rte_be32_t u32;
	struct {
		uint8_t u8[4];
	};
} secgw_ip4_addr_t;

typedef struct {
	uint32_t ingress_port;
	uint32_t egress_port;
	dao_graph_feature_t feature;
	void *userptr;
} secgw_mbuf_dynfield_t;

extern int secgw_mbuf_dynfield_offset;

static inline secgw_mbuf_dynfield_t *
secgw_mbuf_dynfield(struct rte_mbuf *mbuf)
{
	return RTE_MBUF_DYNFIELD(mbuf, secgw_mbuf_dynfield_offset, secgw_mbuf_dynfield_t *);
}

static inline void
secgw_print_mbuf(struct rte_graph *graph, struct rte_node *node, struct rte_mbuf *mbuf,
		 int next_edge, const char *msg, int valid_out_port, int print_mbuf_details)
{
#ifdef SECGW_DEBUG_PKT_TRACE
	secgw_ip4_addr_t *dst_ip = NULL, *src_ip = NULL;
	struct rte_ether_addr *eda = NULL, *esa = NULL;
#ifdef SECGW_TODO
	union rte_pmd_cnxk_cpt_res_s *cpt_res = NULL;
#endif
	struct dao_ds ds = DS_EMPTY_INITIALIZER;
	struct rte_ipv4_hdr *ip4_hdr = NULL;
	struct rte_arp_ipv4 *arpip = NULL;
	secgw_device_main_t *sdm = NULL;
	struct rte_ether_hdr *e = NULL;
	struct rte_arp_hdr *arp = NULL;
	int print_flag = 0;

	RTE_SET_USED(graph);
	RTE_SET_USED(next_edge);
	RTE_SET_USED(print_mbuf_details);
	dao_ds_put_format(&ds, "%15s(%p): ", node->name, mbuf);

	sdm = secgw_get_device_main();
	if (SECGW_MBUF_INGRESS_PORT(mbuf) < (uint32_t)sdm->n_devices)
		dao_ds_put_format(&ds, "[%s -> ",
				  secgw_get_device(SECGW_MBUF_INGRESS_PORT(mbuf))->dev_name);
	if (valid_out_port && (SECGW_MBUF_EGRESS_PORT(mbuf) < (uint32_t)sdm->n_devices))
		dao_ds_put_format(&ds, "%s]",
				  (secgw_get_device(SECGW_MBUF_EGRESS_PORT(mbuf)))->dev_name);
	else
		dao_ds_put_format(&ds, "]");

	if (mbuf->packet_type & RTE_PTYPE_L2_ETHER_ARP) {
		arp = rte_pktmbuf_mtod_offset(mbuf, struct rte_arp_hdr *,
					      sizeof(struct rte_ether_hdr));
		arpip = &arp->arp_data;
		dst_ip = (secgw_ip4_addr_t *)&arpip->arp_tip;
		src_ip = (secgw_ip4_addr_t *)&arpip->arp_sip;
		eda = &arpip->arp_tha;
		esa = &arpip->arp_sha;
		e = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
		print_flag = 1;
#define _(op, str)                                                                                 \
	else if (rte_bswap16(arp->arp_opcode) == (op)) {                                           \
		dao_ds_put_format(&ds,                                                             \
				  "ARP_%s: [%u:%u:%u:%u -> %u:%u:%u:%u]"                           \
				  "[%x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x]"                       \
				  "[%x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x]",                      \
				  str, src_ip->u8[0], src_ip->u8[1], src_ip->u8[2], src_ip->u8[3], \
				  dst_ip->u8[0], dst_ip->u8[1], dst_ip->u8[2], dst_ip->u8[3],      \
				  _eth(esa, 0), _eth(esa, 1), _eth(esa, 2), _eth(esa, 3),          \
				  _eth(esa, 4), _eth(esa, 5), _eth(eda, 0), _eth(eda, 1),          \
				  _eth(eda, 2), _eth(eda, 3), _eth(eda, 4), _eth(eda, 5),          \
				  _smac(e, 0), _smac(e, 1), _smac(e, 2), _smac(e, 3), _smac(e, 4), \
				  _smac(e, 5), _dmac(e, 0), _dmac(e, 1), _dmac(e, 2), _dmac(e, 3), \
				  _dmac(e, 4), _dmac(e, 5));                                       \
	}
		if (0)
			;
		foreach_secgw_arp_op_code
#undef _
	}
	if (mbuf->packet_type & RTE_PTYPE_L3_IPV4) {
		e = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
		ip4_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *,
						  sizeof(struct rte_ether_hdr));
		dst_ip = (secgw_ip4_addr_t *)&ip4_hdr->dst_addr;
		src_ip = (secgw_ip4_addr_t *)&ip4_hdr->src_addr;
		print_flag = 1;
		if (print_mbuf_details)
			dao_ds_put_format(&ds,
					  "[IPv4]:[%u:%u:%u:%u -> %u:%u:%u:%u]"
					  "[%x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x]"
					  "[oflags: 0x%lx, doff: %u, l2t: 0x%x, l3t: 0x%x]"
					  "[dlen:%u, plen: %u, l2l:%u, l3l:%u]",
					  src_ip->u8[0], src_ip->u8[1], src_ip->u8[2],
					  src_ip->u8[3], dst_ip->u8[0], dst_ip->u8[1],
					  dst_ip->u8[2], dst_ip->u8[3], _smac(e, 0), _smac(e, 1),
					  _smac(e, 2), _smac(e, 3), _smac(e, 4), _smac(e, 5),
					  _dmac(e, 0), _dmac(e, 1), _dmac(e, 2), _dmac(e, 3),
					  _dmac(e, 4), _dmac(e, 5), mbuf->ol_flags, mbuf->data_off,
					  mbuf->l2_type, mbuf->l3_type, mbuf->data_len,
					  mbuf->pkt_len, mbuf->l2_len, mbuf->l3_len);
		else
			dao_ds_put_format(&ds,
					  "[IPv4]:[%u:%u:%u:%u -> %u:%u:%u:%u]"
					  "[%x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x]",
					  src_ip->u8[0], src_ip->u8[1], src_ip->u8[2],
					  src_ip->u8[3], dst_ip->u8[0], dst_ip->u8[1],
					  dst_ip->u8[2], dst_ip->u8[3], _smac(e, 0), _smac(e, 1),
					  _smac(e, 2), _smac(e, 3), _smac(e, 4), _smac(e, 5),
					  _dmac(e, 0), _dmac(e, 1), _dmac(e, 2), _dmac(e, 3),
					  _dmac(e, 4), _dmac(e, 5));
	}
	if (mbuf->packet_type & RTE_PTYPE_L3_IPV6)
		print_flag = 0;

	if (msg)
		dao_ds_put_format(&ds, "[Msg: %s]: ", msg);

	if ((next_edge >= 0) && (next_edge < node->nb_edges))
		dao_ds_put_format(&ds, "[Next_Node: %s]", (node->nodes[next_edge])->name);
#ifdef SECGW_TODO
	if (mbuf->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD) {
		cpt_res = rte_pmd_cnxk_inl_ipsec_res(mbuf);
		dao_ds_put_format(
			&ds,
			"[CPT: CompCode: 0x%x, Done: %x, UCode: 0x%x, rlen: 0x%x, spi: 0x%x, esn: 0x%x]",
			cpt_res->cn10k.compcode, cpt_res->cn10k.doneint, cpt_res->cn10k.uc_compcode,
			cpt_res->cn10k.rlen, cpt_res->cn10k.spi, cpt_res->cn10k.esn);
	}
#endif
	if (print_flag)
		dao_info("%s", dao_ds_cstr(&ds));

	dao_ds_destroy(&ds);
#else
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	RTE_SET_USED(mbuf);
	RTE_SET_USED(next_edge);
	RTE_SET_USED(msg);
	RTE_SET_USED(valid_out_port);
	RTE_SET_USED(print_mbuf_details);
#endif
}

struct rte_node_register *secgw_ethdevrx_node_get(void);
struct rte_node_register *secgw_ethdevtx_node_get(void);
struct rte_node_register *secgw_taprx_node_get(void);
struct rte_node_register *secgw_taptx_node_get(void);
#endif
