/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include "rdma_net.h"
#include "rdma_av.h"
#include "rdma_priv.h"
#include <dao_log.h>

#define TX_IPV4_OFFLOAD (RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4)

#define UDP_HDR_ERR (1 << 0)
#define IP4_HDR_ERR (1 << 1)
#define ETH_HDR_ERR (1 << 2)

void
rdma_mbuf_init(struct rte_mbuf *pkt)
{
	pkt->ol_flags |= TX_IPV4_OFFLOAD;
}

static int
eth_hdr_insert(struct rte_mbuf *pkt, struct rdma_av *av)
{
	struct rte_ether_hdr *eth = (void *)rte_pktmbuf_prepend(pkt, sizeof(struct rte_ether_hdr));

	if (unlikely(eth == NULL))
		return ETH_HDR_ERR;

	rte_ether_addr_copy(&av->dmac, &eth->dst_addr);
	rte_ether_addr_copy(&av->smac, &eth->src_addr);
	if (av->network_type == RDMA_NETWORK_TYPE_IPV4)
		eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	else
		eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

	pkt->l2_len = sizeof(struct rte_ether_hdr);
	return 0;
}

static int
ipv4_hdr_insert(struct rte_mbuf *pkt, rte_be32_t saddr, rte_be32_t daddr, uint8_t tos, uint8_t ttl,
		uint16_t ip_id)
{
	struct rte_ipv4_hdr *iph = (void *)rte_pktmbuf_prepend(pkt, sizeof(struct rte_ipv4_hdr));

	if (unlikely(iph == NULL)) {
		return IP4_HDR_ERR;
	}

	iph->version_ihl = RTE_IPV4_VHL_DEF;
	iph->type_of_service = tos;
	iph->fragment_offset = htons(0x4000);
	iph->time_to_live = ttl;
	iph->next_proto_id = IPPROTO_UDP;
	iph->packet_id = rte_cpu_to_be_16(ip_id);
	iph->total_length = rte_cpu_to_be_16(pkt->pkt_len + RDMA_ICRC_SIZE);
	iph->src_addr = saddr;
	iph->dst_addr = daddr;

	pkt->l3_len = sizeof(struct rte_ipv4_hdr);
	return 0;
}

static int
udp_hdr_insert(struct rte_mbuf *pkt, rte_be16_t src_port, rte_be16_t dst_port)
{
	struct rte_udp_hdr *udph = (void *)rte_pktmbuf_prepend(pkt, sizeof(struct rte_udp_hdr));

	if (unlikely(udph == NULL)) {
		return UDP_HDR_ERR;
	}

	udph->dst_port = dst_port;
	udph->src_port = src_port;
	udph->dgram_len = rte_cpu_to_be_16(pkt->pkt_len + RDMA_ICRC_SIZE);
	udph->dgram_cksum = 0;

	pkt->l4_len = sizeof(struct rte_udp_hdr);
	return 0;
}

static int
prepare_ip4_pkt(struct rte_mbuf *pkt, struct rdma_av *av, uint16_t sport)
{
	uint32_t saddr = av->sgid_addr.ip4;
	uint32_t daddr = av->dgid_addr.ip4;
	int ret;

	ret = udp_hdr_insert(pkt, rte_cpu_to_be_16(sport), rte_cpu_to_be_16(RDMA_ROCEV2_PORT));
	ret |= ipv4_hdr_insert(pkt, saddr, daddr, av->iph.traffic_class, av->iph.hop_limit,
			       av->iph.ip_id);
	ret |= eth_hdr_insert(pkt, av);
	av->iph.ip_id += 1;

	if (ret)
		return -1;

	return 0;
}

int
rdma_net_hdr_insert(struct rte_mbuf *pkt, struct rdma_av *av, uint16_t sport)
{
	int ret = 0;

	if (av->network_type == RDMA_NETWORK_TYPE_IPV4)
		ret = prepare_ip4_pkt(pkt, av, sport);

	return ret;
}
