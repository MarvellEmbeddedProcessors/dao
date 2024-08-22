/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <dao_log.h>

#include "flow_dbg.h"

void
flow_dbg_dump_mbuf(struct rte_mbuf *mb)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	struct rte_ether_addr *src, *dst;

	eth_hdr = rte_pktmbuf_mtod(mb, struct rte_ether_hdr *);
	src = &eth_hdr->src_addr;
	dst = &eth_hdr->dst_addr;
	dao_info("-------- Mbuf dump %p --------", mb);
	dao_info(
		"Destination MAC %02x:%02x:%02x:%02x:%02x:%02x: Source MAC %02x:%02x:%02x:%02x:%02x:%02x",
		dst->addr_bytes[0], dst->addr_bytes[1], dst->addr_bytes[2], dst->addr_bytes[3],
		dst->addr_bytes[4], dst->addr_bytes[5], src->addr_bytes[0], src->addr_bytes[1],
		src->addr_bytes[2], src->addr_bytes[3], src->addr_bytes[4], src->addr_bytes[5]);
	dao_info("Ether type %x", rte_be_to_cpu_16(eth_hdr->ether_type));

	ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
	dao_info("Src IP %x, Dst IP %x", rte_be_to_cpu_32(ipv4_hdr->src_addr),
		 rte_be_to_cpu_32(ipv4_hdr->dst_addr));
	dao_info("IP: version_ihl %x type_of_service %x "
		 "total_length %x packet_id %x fragment_offset %x "
		 "time_to_live %x next_proto_id %x hdr_checksum %x ",
		 ipv4_hdr->version_ihl >> 4, ipv4_hdr->type_of_service, ipv4_hdr->total_length,
		 ipv4_hdr->packet_id, ipv4_hdr->fragment_offset, ipv4_hdr->time_to_live,
		 ipv4_hdr->next_proto_id, ipv4_hdr->hdr_checksum);

	udp_hdr = (struct rte_udp_hdr *)(ipv4_hdr + 1);
	dao_info("UDP: Src port %d, Dst port %d", rte_be_to_cpu_16(udp_hdr->src_port),
		 rte_be_to_cpu_16(udp_hdr->dst_port));

	tcp_hdr = (struct rte_tcp_hdr *)(ipv4_hdr + 1);
	dao_info("TCP: Src port %d, Dst port %d", rte_be_to_cpu_16(tcp_hdr->src_port),
		 rte_be_to_cpu_16(tcp_hdr->dst_port));

	dao_info("Port %d", mb->port);
	dao_info("Nb_segs %d", mb->nb_segs);
	dao_info("packet_type %x", mb->packet_type);
	dao_info("ol_flags %lx", mb->ol_flags);
	dao_info("Refcnt %d", rte_mbuf_refcnt_read(mb));
	dao_info("Length info");
	dao_info("	Packet length %d", mb->pkt_len);
	dao_info("	Data length %d", mb->data_len);
	dao_info("	Total length %d", mb->buf_len);
	dao_info("	Data offset %d", mb->data_off);
	dao_info("Vlan Info");
	dao_info("	Vlan TCI %d", mb->vlan_tci);
	dao_info("	Vlan TCI Outer %d", mb->vlan_tci_outer);
	dao_info("Layer info");
	dao_info("	l2_len %d", mb->l2_len);
	dao_info("	l3_len %d", mb->l3_len);
	dao_info("	l4_len %d", mb->l4_len);
	dao_info("Hash info");
	dao_info("	hash.rss %d", mb->hash.rss);
	dao_info("	hash.fdir.hi %d", mb->hash.fdir.hi);
	dao_info("	hash.fdir.lo %d", mb->hash.fdir.lo);
	dao_info("	hash.fdir.id %d", mb->hash.fdir.id);
	dao_info("tso_segsz %d", mb->tso_segsz);
	dao_info("--------------------------------");
}

static void
dump_item_string(const struct rte_flow_item *item)
{
	switch (item->type) {
	case RTE_FLOW_ITEM_TYPE_END:
		dao_info("	type %s", "END");
		break;
	case RTE_FLOW_ITEM_TYPE_VOID:
		dao_info("	type %s", "VOID");
		break;
	case RTE_FLOW_ITEM_TYPE_INVERT:
		dao_info("	type %s", "INVERT");
		break;
	case RTE_FLOW_ITEM_TYPE_ANY:
		dao_info("	type %s", "ANY");
		break;
	case RTE_FLOW_ITEM_TYPE_PORT_ID:
		struct rte_flow_item_port_id *port_id = (struct rte_flow_item_port_id *)item->spec;
		struct rte_flow_item_port_id *port_id_mask =
			(struct rte_flow_item_port_id *)item->mask;
		dao_info("	type %s spec id %d mask id %d", "PORT_ID", port_id->id,
			 port_id_mask->id);
		break;
	case RTE_FLOW_ITEM_TYPE_RAW:
		struct rte_flow_item_raw *raw = (struct rte_flow_item_raw *)item->spec;
		struct rte_flow_item_raw *raw_mask = (struct rte_flow_item_raw *)item->mask;

		dao_info("	type %s spec %p mask %p", "RAW", raw->pattern, raw_mask->pattern);
		break;
	case RTE_FLOW_ITEM_TYPE_ETH:
		struct rte_flow_item_eth *eth = (struct rte_flow_item_eth *)item->spec;
		struct rte_flow_item_eth *eth_mask = (struct rte_flow_item_eth *)item->mask;

		dao_info("	type %s", "ETH");
		dao_info(
			"	spec: dest %02x:%02x:%02x:%02x:%02x:%02x src %02x:%02x:%02x:%02x:%02x:%02x type %x has_vlan %d",
			eth->dst.addr_bytes[0], eth->dst.addr_bytes[1], eth->dst.addr_bytes[2],
			eth->dst.addr_bytes[3], eth->dst.addr_bytes[4], eth->dst.addr_bytes[5],
			eth->src.addr_bytes[0], eth->src.addr_bytes[1], eth->src.addr_bytes[2],
			eth->src.addr_bytes[3], eth->src.addr_bytes[4], eth->src.addr_bytes[5],
			eth->type, eth->has_vlan);
		dao_info(
			"	mask: dest %x:%x:%x:%x:%x:%x src %x:%x:%x:%x:%x:%x type %x has_vlan %d",
			eth_mask->dst.addr_bytes[0], eth_mask->dst.addr_bytes[1],
			eth_mask->dst.addr_bytes[2], eth_mask->dst.addr_bytes[3],
			eth_mask->dst.addr_bytes[4], eth_mask->dst.addr_bytes[5],
			eth_mask->src.addr_bytes[0], eth_mask->src.addr_bytes[1],
			eth_mask->src.addr_bytes[2], eth_mask->src.addr_bytes[3],
			eth_mask->src.addr_bytes[4], eth_mask->src.addr_bytes[5], eth_mask->type,
			eth_mask->has_vlan);
		break;
	case RTE_FLOW_ITEM_TYPE_VLAN:
		struct rte_flow_item_vlan *vlan = (struct rte_flow_item_vlan *)item->spec;
		struct rte_flow_item_vlan *vlan_mask = (struct rte_flow_item_vlan *)item->mask;

		dao_info("	type %s", "VLAN");
		dao_info("	spec: tci %x inner_type %x", vlan->tci, vlan->inner_type);
		dao_info("	mask: tci %x inner_type %x", vlan_mask->tci, vlan_mask->inner_type);
		break;
	case RTE_FLOW_ITEM_TYPE_IPV4:
		struct rte_flow_item_ipv4 *ipv4 = (struct rte_flow_item_ipv4 *)item->spec;
		struct rte_flow_item_ipv4 *ipv4_mask = (struct rte_flow_item_ipv4 *)item->mask;

		dao_info("	type %s", "IPV4");
		dao_info("	spec: src addr %x dest addr %x", ipv4->hdr.src_addr,
			 ipv4->hdr.dst_addr);
		dao_info("	mask: src addr %x dest addr %x", ipv4_mask->hdr.src_addr,
			 ipv4_mask->hdr.dst_addr);
		dao_info("	spec: version_ihl %x type_of_service %x "
			 "total_length %x packet_id %x fragment_offset %x "
			 "time_to_live %x next_proto_id %x hdr_checksum %x ",
			 ipv4->hdr.version_ihl >> 4, ipv4->hdr.type_of_service,
			 ipv4->hdr.total_length, ipv4->hdr.packet_id, ipv4->hdr.fragment_offset,
			 ipv4->hdr.time_to_live, ipv4->hdr.next_proto_id, ipv4->hdr.hdr_checksum);
		dao_info("	mask: version_ihl %x type_of_service %x "
			 "total_length %x packet_id %x fragment_offset %x "
			 "time_to_live %x next_proto_id %x hdr_checksum %x ",
			 ipv4_mask->hdr.version_ihl >> 4, ipv4_mask->hdr.type_of_service,
			 ipv4_mask->hdr.total_length, ipv4_mask->hdr.packet_id,
			 ipv4_mask->hdr.fragment_offset, ipv4_mask->hdr.time_to_live,
			 ipv4_mask->hdr.next_proto_id, ipv4_mask->hdr.hdr_checksum);
		break;
	case RTE_FLOW_ITEM_TYPE_IPV6:
		struct rte_flow_item_ipv6 *ipv6 = (struct rte_flow_item_ipv6 *)item->spec;
		struct rte_flow_item_ipv6 *ipv6_mask = (struct rte_flow_item_ipv6 *)item->mask;

		dao_info("	type %s", "IPV6");
		dao_info("	spec: version_tc_flow %x payload_len %x "
			 "proto %x hop_limits %x src_addr %p dst_addr %p",
			 ipv6->hdr.vtc_flow, ipv6->hdr.payload_len, ipv6->hdr.proto,
			 ipv6->hdr.hop_limits, ipv6->hdr.src_addr, ipv6->hdr.dst_addr);
		dao_info("	mask: version_tc_flow %x payload_len %x "
			 "proto %x hop_limits %x src_addr %p dst_addr %p",
			 ipv6_mask->hdr.vtc_flow, ipv6_mask->hdr.payload_len, ipv6_mask->hdr.proto,
			 ipv6_mask->hdr.hop_limits, ipv6_mask->hdr.src_addr,
			 ipv6_mask->hdr.dst_addr);
		break;
	case RTE_FLOW_ITEM_TYPE_ICMP:
		struct rte_flow_item_icmp *icmp = (struct rte_flow_item_icmp *)item->spec;
		struct rte_flow_item_icmp *icmp_mask = (struct rte_flow_item_icmp *)item->mask;

		dao_info("	type %s", "ICMP");
		dao_info("	spec: hdr.icmp_type %x hdr.icmp_code %x", icmp->hdr.icmp_type,
			 icmp->hdr.icmp_code);
		dao_info("	mask: hdr.icmp_type %x hdr.icmp_code %x", icmp_mask->hdr.icmp_type,
			 icmp_mask->hdr.icmp_code);
		break;
	case RTE_FLOW_ITEM_TYPE_UDP:
		struct rte_flow_item_udp *udp = (struct rte_flow_item_udp *)item->spec;
		struct rte_flow_item_udp *udp_mask = (struct rte_flow_item_udp *)item->mask;

		dao_info("	type %s", "UDP");
		dao_info("	spec: hdr.src_port %x hdr.dst_port %x", udp->hdr.src_port,
			 udp->hdr.dst_port);
		dao_info("	mask: hdr.src_port %x hdr.dst_port %x", udp_mask->hdr.src_port,
			 udp_mask->hdr.dst_port);
		break;
	case RTE_FLOW_ITEM_TYPE_TCP:
		struct rte_flow_item_tcp *tcp = (struct rte_flow_item_tcp *)item->spec;
		struct rte_flow_item_tcp *tcp_mask = (struct rte_flow_item_tcp *)item->mask;

		dao_info("	type %s", "TCP");
		dao_info("	spec: hdr.src_port %x hdr.dst_port %x sent_seq %x "
			 "recv_ack %x data_off %x tcp_flags %x rx_win %x  cksum %x tcp_urp %x",
			 tcp->hdr.src_port, tcp->hdr.dst_port, tcp->hdr.sent_seq, tcp->hdr.recv_ack,
			 tcp->hdr.data_off, tcp->hdr.tcp_flags, tcp->hdr.rx_win, tcp->hdr.cksum,
			 tcp->hdr.tcp_urp);
		dao_info("	mask: hdr.src_port %x hdr.dst_port %x", tcp_mask->hdr.src_port,
			 tcp_mask->hdr.dst_port);
		break;
	case RTE_FLOW_ITEM_TYPE_SCTP:
		struct rte_flow_item_sctp *sctp = (struct rte_flow_item_sctp *)item->spec;
		struct rte_flow_item_sctp *sctp_mask = (struct rte_flow_item_sctp *)item->mask;

		dao_info("	type %s", "SCTP");
		dao_info("	spec: hdr.src_port %x hdr.dst_port %x", sctp->hdr.src_port,
			 sctp->hdr.dst_port);
		dao_info("	mask: hdr.src_port %x hdr.dst_port %x", sctp_mask->hdr.src_port,
			 sctp_mask->hdr.dst_port);
		break;
	case RTE_FLOW_ITEM_TYPE_VXLAN:
		struct rte_flow_item_vxlan *vxlan = (struct rte_flow_item_vxlan *)item->spec;
		struct rte_flow_item_vxlan *vxlan_mask = (struct rte_flow_item_vxlan *)item->mask;

		dao_info("	type %s", "VXLAN");
		dao_info("	spec: flags %x vni[0] %x vni[1] %x vni[2] %x", vxlan->flags,
			 vxlan->vni[0], vxlan->vni[1], vxlan->vni[2]);
		dao_info("	mask: flags %x vni[0] %x vni[1] %x vni[2] %x", vxlan_mask->flags,
			 vxlan_mask->vni[0], vxlan_mask->vni[1], vxlan_mask->vni[2]);
		break;
	case RTE_FLOW_ITEM_TYPE_PORT_REPRESENTOR:
		struct rte_flow_item_ethdev *port_representor =
			(struct rte_flow_item_ethdev *)item->spec;
		struct rte_flow_item_ethdev *port_representor_mask =
			(struct rte_flow_item_ethdev *)item->mask;
		dao_info("	type %s spec id %d mask id %d", "PORT_REPRESENTOR",
			 port_representor->port_id, port_representor_mask->port_id);
		break;
	case RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT:
		struct rte_flow_item_ethdev *represented_port =
			(struct rte_flow_item_ethdev *)item->spec;
		struct rte_flow_item_ethdev *represented_port_mask =
			(struct rte_flow_item_ethdev *)item->mask;
		dao_info("	type %s spec id %d mask id %d", "REPRESENTED_PORT",
			 represented_port->port_id, represented_port_mask->port_id);
		break;
	case RTE_FLOW_ITEM_TYPE_E_TAG:
		dao_info("	type %s", "E_TAG");
		break;
	case RTE_FLOW_ITEM_TYPE_NVGRE:
		dao_info("	type %s", "NVGRE");
		break;
	case RTE_FLOW_ITEM_TYPE_MPLS:
		dao_info("	type %s", "MPLS");
		break;
	case RTE_FLOW_ITEM_TYPE_GRE:
		dao_info("	type %s", "GRE");
		break;
	case RTE_FLOW_ITEM_TYPE_FUZZY:
		dao_info("	type %s", "FUZZY");
		break;
	case RTE_FLOW_ITEM_TYPE_GTP:
		dao_info("	type %s", "GTP");
		break;
	case RTE_FLOW_ITEM_TYPE_GTPC:
		dao_info("	type %s", "GTPC");
		break;
	case RTE_FLOW_ITEM_TYPE_GTPU:
		dao_info("	type %s", "GTPU");
		break;
	case RTE_FLOW_ITEM_TYPE_ESP:
		dao_info("	type %s", "ESP");
		break;
	case RTE_FLOW_ITEM_TYPE_GENEVE:
		dao_info("	type %s", "GENEVE");
		break;
	case RTE_FLOW_ITEM_TYPE_VXLAN_GPE:
		dao_info("	type %s", "VXLAN_GPE");
		break;
	case RTE_FLOW_ITEM_TYPE_IPV6_EXT:
		dao_info("	type %s", "IPV6_EXT");
		break;
	case RTE_FLOW_ITEM_TYPE_ICMP6:
		dao_info("	type %s", "ICMP6");
		break;
	case RTE_FLOW_ITEM_TYPE_ICMP6_ND_NS:
		dao_info("	type %s", "ICMP6_ND_NS");
		break;
	case RTE_FLOW_ITEM_TYPE_ICMP6_ND_NA:
		dao_info("	type %s", "ICMP6_ND_NA");
		break;
	case RTE_FLOW_ITEM_TYPE_ICMP6_ND_OPT:
		dao_info("	type %s", "ICMP6_ND_OPT");
		break;
	case RTE_FLOW_ITEM_TYPE_ICMP6_ND_OPT_SLA_ETH:
		dao_info("	type %s", "ICMP6_ND_OPT_SLA_ETH");
		break;
	case RTE_FLOW_ITEM_TYPE_ICMP6_ND_OPT_TLA_ETH:
		dao_info("	type %s", "ICMP6_ND_OPT_TLA_ETH");
		break;
	case RTE_FLOW_ITEM_TYPE_MARK:
		struct rte_flow_item_mark *mark = (struct rte_flow_item_mark *)item->spec;
		struct rte_flow_item_mark *mark_mask = (struct rte_flow_item_mark *)item->mask;

		dao_info("	type %s spec id %d mask id %d", "MARK", mark->id, mark_mask->id);
		break;
	case RTE_FLOW_ITEM_TYPE_META:
		dao_info("	type %s", "META");
		break;
	case RTE_FLOW_ITEM_TYPE_GRE_KEY:
		dao_info("	type %s", "GRE_KEY");
		break;
	case RTE_FLOW_ITEM_TYPE_GTP_PSC:
		dao_info("	type %s", "GTP_PSC");
		break;
	case RTE_FLOW_ITEM_TYPE_PPPOES:
		dao_info("	type %s", "PPPOES");
		break;
	case RTE_FLOW_ITEM_TYPE_PPPOED:
		dao_info("	type %s", "PPPOED");
		break;
	case RTE_FLOW_ITEM_TYPE_PPPOE_PROTO_ID:
		dao_info("	type %s", "PPPOE_PROTO_ID");
		break;
	case RTE_FLOW_ITEM_TYPE_NSH:
		dao_info("	type %s", "NSH");
		break;
	case RTE_FLOW_ITEM_TYPE_IGMP:
		dao_info("	type %s", "IGMP");
		break;
	case RTE_FLOW_ITEM_TYPE_AH:
		dao_info("	type %s", "AH");
		break;
	case RTE_FLOW_ITEM_TYPE_HIGIG2:
		dao_info("	type %s", "HIGIG2");
		break;
	case RTE_FLOW_ITEM_TYPE_TAG:
		dao_info("	type %s", "TAG");
		break;
	case RTE_FLOW_ITEM_TYPE_L2TPV3OIP:
		dao_info("	type %s", "L2TPV3OIP");
		break;
	case RTE_FLOW_ITEM_TYPE_PFCP:
		dao_info("	type %s", "PFCP");
		break;
	case RTE_FLOW_ITEM_TYPE_ECPRI:
		dao_info("	type %s", "ECPRI");
		break;
	case RTE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT:
		dao_info("	type %s", "IPV6_FRAG_EXT");
		break;
	case RTE_FLOW_ITEM_TYPE_GENEVE_OPT:
		dao_info("	type %s", "GENEVE_OPT");
		break;
	case RTE_FLOW_ITEM_TYPE_INTEGRITY:
		dao_info("	type %s", "INTEGRITY");
		break;
	case RTE_FLOW_ITEM_TYPE_CONNTRACK:
		struct rte_flow_item_conntrack *conntrack =
			(struct rte_flow_item_conntrack *)item->spec;
		struct rte_flow_item_conntrack *conntrack_mask =
			(struct rte_flow_item_conntrack *)item->mask;
		dao_info("	type %s", "CONNTRACK");
		dao_info("	spec: flags %x ", conntrack->flags);
		dao_info("	mask: flags %x", conntrack_mask->flags);
		break;
	case RTE_FLOW_ITEM_TYPE_FLEX:
		dao_info("	type %s", "FLEX");
		break;
	case RTE_FLOW_ITEM_TYPE_L2TPV2:
		dao_info("	type %s", "L2TPV2");
		break;
	case RTE_FLOW_ITEM_TYPE_PPP:
		dao_info("	type %s", "PPP");
		break;
	case RTE_FLOW_ITEM_TYPE_GRE_OPTION:
		dao_info("	type %s", "GRE_OPTION");
		break;
	case RTE_FLOW_ITEM_TYPE_MACSEC:
		dao_info("	type %s", "MACSEC");
		break;
	case RTE_FLOW_ITEM_TYPE_METER_COLOR:
		dao_info("	type %s", "METER_COLOR");
		break;
	case RTE_FLOW_ITEM_TYPE_IPV6_ROUTING_EXT:
		dao_info("	type %s", "IPV6_ROUTING_EXT");
		break;
	case RTE_FLOW_ITEM_TYPE_ICMP6_ECHO_REQUEST:
		dao_info("	type %s", "ICMP6_ECHO_REQUEST");
		break;
	case RTE_FLOW_ITEM_TYPE_ICMP6_ECHO_REPLY:
		dao_info("	type %s", "ICMP6_ECHO_REPLY");
		break;
	case RTE_FLOW_ITEM_TYPE_QUOTA:
		dao_info("	type %s", "QUOTA");
		break;
	case RTE_FLOW_ITEM_TYPE_AGGR_AFFINITY:
		dao_info("	type %s", "AGGR_AFFINITY");
		break;
	case RTE_FLOW_ITEM_TYPE_TX_QUEUE:
		struct rte_flow_item_tx_queue *tx_queue =
			(struct rte_flow_item_tx_queue *)item->spec;
		struct rte_flow_item_tx_queue *tx_queue_mask =
			(struct rte_flow_item_tx_queue *)item->mask;
		dao_info("	type %s spec index %d mask index %d", "TX_QUEUE",
			 tx_queue->tx_queue, tx_queue_mask->tx_queue);
		break;
	case RTE_FLOW_ITEM_TYPE_IB_BTH:
		dao_info("	type %s", "IB_BTH");
		break;
	case RTE_FLOW_ITEM_TYPE_PTYPE:
		struct rte_flow_item_ptype *ptype = (struct rte_flow_item_ptype *)item->spec;
		struct rte_flow_item_ptype *ptype_mask = (struct rte_flow_item_ptype *)item->mask;

		dao_info("	type %s spec %x mask %x", "PTYPE", ptype->packet_type,
			 ptype_mask->packet_type);
		break;
	default:
		dao_info("	type %s", "UNKNOWN");
		break;
	}
}

static void
dump_action_string(enum rte_flow_action_type type, const void *conf)
{
	switch (type) {
	case RTE_FLOW_ACTION_TYPE_END:
		dao_info("	type %s", "END");
		break;
	case RTE_FLOW_ACTION_TYPE_VOID:
		dao_info("	type %s", "VOID");
		break;
	case RTE_FLOW_ACTION_TYPE_PASSTHRU:
		dao_info("	type %s", "PASSTHRU");
		break;
	case RTE_FLOW_ACTION_TYPE_JUMP:
		struct rte_flow_action_jump *jump = (struct rte_flow_action_jump *)conf;

		dao_info("	type %s GROUP %d", "JUMP", jump->group);
		break;
	case RTE_FLOW_ACTION_TYPE_MARK:
		struct rte_flow_action_mark *mark = (struct rte_flow_action_mark *)conf;

		dao_info("	type %s MARK id %d", "MARK", mark->id);
		break;
	case RTE_FLOW_ACTION_TYPE_FLAG:
		dao_info("	type %s", "FLAG");
		break;
	case RTE_FLOW_ACTION_TYPE_QUEUE:
		struct rte_flow_action_queue *queue = (struct rte_flow_action_queue *)conf;

		dao_info("	type %s QUEUE index %d", "QUEUE", queue->index);
		break;
	case RTE_FLOW_ACTION_TYPE_DROP:
		dao_info("	type %s", "DROP");
		break;
	case RTE_FLOW_ACTION_TYPE_COUNT:
		struct rte_flow_action_count *count = (struct rte_flow_action_count *)conf;

		if (conf)
			dao_info("	type %s COUNT id %d", "COUNT", count->id);
		else
			dao_info("	type %s conf %p", "COUNT", conf);
		break;
	case RTE_FLOW_ACTION_TYPE_RSS:
		struct rte_flow_action_rss *rss = (struct rte_flow_action_rss *)conf;

		dao_info("	type %s level %d types %lx key_len %d queue_num %d key %p queue %p",
			 "RSS", rss->level, rss->types, rss->key_len, rss->queue_num, rss->key,
			 rss->queue);
		break;
	case RTE_FLOW_ACTION_TYPE_PF:
		dao_info("	type %s", "PF");
		break;
	case RTE_FLOW_ACTION_TYPE_VF:
		dao_info("	type %s", "VF");
		break;
	case RTE_FLOW_ACTION_TYPE_PORT_ID:
		struct rte_flow_action_port_id *port_id = (struct rte_flow_action_port_id *)conf;

		dao_info("	type %s PORT_ID id %d", "PORT_ID", port_id->id);
		break;
	case RTE_FLOW_ACTION_TYPE_METER:
		struct rte_flow_action_meter *meter = (struct rte_flow_action_meter *)conf;

		dao_info("	type %s METER id %d", "METER", meter->mtr_id);
		break;
	case RTE_FLOW_ACTION_TYPE_SECURITY:
		struct rte_flow_action_security *security = (struct rte_flow_action_security *)conf;

		dao_info("	type %s SECURITY %p", "SECURITY", security->security_session);
		break;
	case RTE_FLOW_ACTION_TYPE_OF_DEC_NW_TTL:
		dao_info("	type %s", "OF_DEC_NW_TTL");
		break;
	case RTE_FLOW_ACTION_TYPE_OF_POP_VLAN:
		dao_info("	type %s", "OF_POP_VLAN");
		break;
	case RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN:
		struct rte_flow_action_of_push_vlan *of_push_vlan =
			(struct rte_flow_action_of_push_vlan *)conf;
		dao_info("	type %s VLAN proto %d", "OF_PUSH_VLAN", of_push_vlan->ethertype);
		break;
	case RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID:
		struct rte_flow_action_of_set_vlan_vid *of_set_vlan_vid =
			(struct rte_flow_action_of_set_vlan_vid *)conf;
		dao_info("	type %s VLAN id %d", "OF_SET_VLAN_VID", of_set_vlan_vid->vlan_vid);
		break;
	case RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP:
		struct rte_flow_action_of_set_vlan_pcp *of_set_vlan_pcp =
			(struct rte_flow_action_of_set_vlan_pcp *)conf;
		dao_info("	type %s VLAN pcp %d", "OF_SET_VLAN_PCP", of_set_vlan_pcp->vlan_pcp);
		break;
	case RTE_FLOW_ACTION_TYPE_OF_POP_MPLS:
		dao_info("	type %s", "OF_POP_MPLS");
		break;
	case RTE_FLOW_ACTION_TYPE_OF_PUSH_MPLS:
		struct rte_flow_action_of_push_mpls *of_push_mpls =
			(struct rte_flow_action_of_push_mpls *)conf;
		dao_info("	type %s MPLS proto %d", "OF_PUSH_MPLS", of_push_mpls->ethertype);
		break;
	case RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP:
		dao_info("	type %s", "VXLAN_ENCAP");

		break;
	case RTE_FLOW_ACTION_TYPE_VXLAN_DECAP:
		dao_info("	type %s", "VXLAN_DECAP");
		break;
	case RTE_FLOW_ACTION_TYPE_NVGRE_ENCAP:
		dao_info("	type %s", "NVGRE_ENCAP");
		break;
	case RTE_FLOW_ACTION_TYPE_NVGRE_DECAP:
		dao_info("	type %s", "NVGRE_DECAP");
		break;
	case RTE_FLOW_ACTION_TYPE_RAW_ENCAP:
		dao_info("	type %s", "RAW_ENCAP");
		break;
	case RTE_FLOW_ACTION_TYPE_RAW_DECAP:
		dao_info("	type %s", "RAW_DECAP");
		break;
	case RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC:
		struct rte_flow_action_set_ipv4 *set_ipv4_src =
			(struct rte_flow_action_set_ipv4 *)conf;
		dao_info("	type %s IPV4 src %x", "SET_IPV4_SRC", set_ipv4_src->ipv4_addr);
		break;
	case RTE_FLOW_ACTION_TYPE_SET_IPV4_DST:
		struct rte_flow_action_set_ipv4 *set_ipv4_dst =
			(struct rte_flow_action_set_ipv4 *)conf;
		dao_info("	type %s IPV4 dst %x", "SET_IPV4_DST", set_ipv4_dst->ipv4_addr);
		break;
	case RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC:
		struct rte_flow_action_set_ipv6 *set_ipv6_src =
			(struct rte_flow_action_set_ipv6 *)conf;
		dao_info("	type %s IPV6 src %p", "SET_IPV6_SRC", set_ipv6_src->ipv6_addr);
		break;
	case RTE_FLOW_ACTION_TYPE_SET_IPV6_DST:
		struct rte_flow_action_set_ipv6 *set_ipv6_dst =
			(struct rte_flow_action_set_ipv6 *)conf;
		dao_info("	type %s IPV6 dst %p", "SET_IPV6_DST", set_ipv6_dst->ipv6_addr);
		break;
	case RTE_FLOW_ACTION_TYPE_SET_TP_SRC:
		struct rte_flow_action_set_tp *set_tp_src = (struct rte_flow_action_set_tp *)conf;

		dao_info("	type %s TP src %d", "SET_TP_SRC", set_tp_src->port);
		break;
	case RTE_FLOW_ACTION_TYPE_SET_TP_DST:
		struct rte_flow_action_set_tp *set_tp_dst = (struct rte_flow_action_set_tp *)conf;

		dao_info("	type %s TP dst %d", "SET_TP_DST", set_tp_dst->port);
		break;
	case RTE_FLOW_ACTION_TYPE_MAC_SWAP:
		dao_info("	type %s", "MAC_SWAP");
		break;
	case RTE_FLOW_ACTION_TYPE_DEC_TTL:
		dao_info("	type %s", "DEC_TTL");
		break;
	case RTE_FLOW_ACTION_TYPE_SET_TTL:
		struct rte_flow_action_set_ttl *set_ttl = (struct rte_flow_action_set_ttl *)conf;

		dao_info("	type %s TTL %d", "SET_TTL", set_ttl->ttl_value);
		break;
	case RTE_FLOW_ACTION_TYPE_SET_MAC_SRC:
		struct rte_flow_action_set_mac *set_mac_src =
			(struct rte_flow_action_set_mac *)conf;
		dao_info("	type %s MAC src %p", "SET_MAC_SRC", set_mac_src->mac_addr);
		break;
	case RTE_FLOW_ACTION_TYPE_SET_MAC_DST:
		struct rte_flow_action_set_mac *set_mac_dst =
			(struct rte_flow_action_set_mac *)conf;
		dao_info("	type %s MAC dst %p", "SET_MAC_DST", set_mac_dst->mac_addr);
		break;
	case RTE_FLOW_ACTION_TYPE_INC_TCP_SEQ:
		dao_info("	type %s", "INC_TCP_SEQ");
		break;
	case RTE_FLOW_ACTION_TYPE_DEC_TCP_SEQ:
		dao_info("	type %s", "DEC_TCP_SEQ");
		break;
	case RTE_FLOW_ACTION_TYPE_INC_TCP_ACK:
		dao_info("	type %s", "INC_TCP_ACK");
		break;
	case RTE_FLOW_ACTION_TYPE_DEC_TCP_ACK:
		dao_info("	type %s", "DEC_TCP_ACK");
		break;
	case RTE_FLOW_ACTION_TYPE_SET_TAG:
		dao_info("	type %s", "SET_TAG");
		break;
	case RTE_FLOW_ACTION_TYPE_SET_META:
		dao_info("	type %s", "SET_META");
		break;
	case RTE_FLOW_ACTION_TYPE_SET_IPV4_DSCP:
		struct rte_flow_action_set_dscp *set_ipv4_dscp =
			(struct rte_flow_action_set_dscp *)conf;
		dao_info("	type %s IPV4 DSCP %d", "SET_IPV4_DSCP", set_ipv4_dscp->dscp);
		break;
	case RTE_FLOW_ACTION_TYPE_SET_IPV6_DSCP:
		struct rte_flow_action_set_dscp *set_ipv6_dscp =
			(struct rte_flow_action_set_dscp *)conf;
		dao_info("	type %s IPV6 DSCP %d", "SET_IPV6_DSCP", set_ipv6_dscp->dscp);
		break;
	case RTE_FLOW_ACTION_TYPE_AGE:
		struct rte_flow_action_age *age = (struct rte_flow_action_age *)conf;

		dao_info("	type %s AGE %d", "AGE", age->timeout);
		break;
	case RTE_FLOW_ACTION_TYPE_SAMPLE:
		struct rte_flow_action_sample *sample = (struct rte_flow_action_sample *)conf;

		dao_info("	type %s SAMPLE %d", "SAMPLE", sample->ratio);
		break;
	case RTE_FLOW_ACTION_TYPE_SHARED:
		dao_info("	type %s", "SHARED");
		break;
	case RTE_FLOW_ACTION_TYPE_MODIFY_FIELD:
		dao_info("	type %s", "MODIFY_FIELD");
		break;
	case RTE_FLOW_ACTION_TYPE_INDIRECT:
		dao_info("	type %s", "INDIRECT");
		break;
	case RTE_FLOW_ACTION_TYPE_CONNTRACK:
		struct rte_flow_action_conntrack *conntrack =
			(struct rte_flow_action_conntrack *)conf;
		dao_info("	type %s peer_port %d is_original_dir %d enable %d "
			 "live_connection %d selective_ack %d challenge_ack_passed %d "
			 "last_direction %d liberal_mode %d state %d max_ack_window %d "
			 "retransmission_limit %d last_window %d last_index %d last_seq %d "
			 "last_ack %d last_end %d",
			 "CONNTRACK", conntrack->peer_port, conntrack->is_original_dir,
			 conntrack->enable, conntrack->live_connection, conntrack->selective_ack,
			 conntrack->challenge_ack_passed, conntrack->last_direction,
			 conntrack->liberal_mode, conntrack->state, conntrack->max_ack_window,
			 conntrack->retransmission_limit, conntrack->last_window,
			 conntrack->last_index, conntrack->last_seq, conntrack->last_ack,
			 conntrack->last_end);
		break;
	case RTE_FLOW_ACTION_TYPE_METER_COLOR:
		struct rte_flow_action_meter_color *meter_color =
			(struct rte_flow_action_meter_color *)conf;
		dao_info("	type %s color %d", "METER_COLOR", meter_color->color);
		break;
	case RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR:
		struct rte_flow_action_ethdev *port_representor =
			(struct rte_flow_action_ethdev *)conf;
		dao_info("	type %s PORT_REPRESENTOR id %d", "PORT_REPRESENTOR",
			 port_representor->port_id);
		break;
	case RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT:
		struct rte_flow_action_ethdev *represented_port =
			(struct rte_flow_action_ethdev *)conf;
		dao_info("	type %s REPRESENTED_PORT id %d", "REPRESENTED_PORT",
			 represented_port->port_id);
		break;
	case RTE_FLOW_ACTION_TYPE_METER_MARK:
		dao_info("	type %s", "METER_MARK");
		break;
	case RTE_FLOW_ACTION_TYPE_SEND_TO_KERNEL:
		dao_info("	type %s", "SEND_TO_KERNEL");
		break;
	case RTE_FLOW_ACTION_TYPE_QUOTA:
		dao_info("	type %s", "QUOTA");
		break;
	case RTE_FLOW_ACTION_TYPE_SKIP_CMAN:
		dao_info("	type %s", "SKIP_CMAN");
		break;
	case RTE_FLOW_ACTION_TYPE_IPV6_EXT_PUSH:
		dao_info("	type %s", "IPV6_EXT_PUSH");
		break;
	case RTE_FLOW_ACTION_TYPE_IPV6_EXT_REMOVE:
		dao_info("	type %s", "IPV6_EXT_REMOVE");
		break;
	case RTE_FLOW_ACTION_TYPE_INDIRECT_LIST:
		dao_info("	type %s", "INDIRECT_LIST");
		break;
	case RTE_FLOW_ACTION_TYPE_PROG:
		dao_info("	type %s", "PROG");
		break;
	default:
		dao_info("	type %s", "UNKNOWN");
		break;
	}
}

void
flow_dbg_dump_flow(uint16_t port_id, const struct rte_flow_attr *attr,
		   const struct rte_flow_item pattern[], const struct rte_flow_action actions[])
{
	dao_info("===== New Flow Create Request =====");
	dao_info("Flow rule for port %d", port_id);
	/* Dumping attributes */
	dao_info("Flow attributes:");
	dao_info("	Group %d, Priority %d, Ingress %d, Egress %d, Transfer %d", attr->group,
		 attr->priority, attr->ingress, attr->egress, attr->transfer);
	/* Dumping patterns */
	dao_info("Pattern:");
	for (; pattern->type != RTE_FLOW_ITEM_TYPE_END; pattern++)
		dump_item_string(pattern);
	/* Dumping actions */
	dao_info("Actions:");
	for (; actions->type != RTE_FLOW_ACTION_TYPE_END; actions++)
		dump_action_string(actions->type, actions->conf);
	dao_info("====================================");
}
