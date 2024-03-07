/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "flow.h"

#define MAX_PATTERN_NUM    8
#define MAX_ACTION_NUM     3
#define UDP_DST_VXLAN_PORT 4789
#define VXLAN_VNI          0x11223344
#define FRAG_OFFSET        0x7766
#define VLAN_TCI           0x1234
#define UDP_SRC_PORT       0x4256

static struct rte_flow_item_eth eth = {
	.dst = {.addr_bytes = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
	.src = {.addr_bytes = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66}},
	.type = RTE_BE16(RTE_ETHER_TYPE_IPV4),
};

static struct rte_flow_item_eth eth_mask = {
	.dst = {
		.addr_bytes = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	},
	.src = {
		.addr_bytes = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	},
	.type = RTE_BE16(0xFFFF),
};

struct test_ipaddr_mark {
	struct rte_flow_item_ipv4 ipv4;
	uint16_t mark;
};

static struct test_ipaddr_mark test_vals[3] = {
	{
		{
			.hdr = {
					.src_addr = RTE_BE32((RTE_IPV4(10, 11, 12, 13))),
					.dst_addr = RTE_BE32((RTE_IPV4(10, 11, 12, 14))),
				},
		},
		0x666,
	},
	{
		{
			.hdr = {
					.src_addr = RTE_BE32((RTE_IPV4(10, 15, 20, 22))),
					.dst_addr = RTE_BE32((RTE_IPV4(10, 15, 30, 33))),
				},
		},
		0x777,
	},
	{
		{
			.hdr = {
					.src_addr = RTE_BE32((RTE_IPV4(10, 15, 20, 25))),
					.dst_addr = RTE_BE32((RTE_IPV4(10, 15, 30, 35))),
				},
		},
		0,
	},
};

static struct rte_flow_item_eth inner_eth = {
	.dst = {.addr_bytes = {0xab, 0xbc, 0xcd, 0xde, 0xef, 0xff}},
	.src = {.addr_bytes = {0x1a, 0x2a, 0x3a, 0x4a, 0x5a, 0x6a}},
	.type = RTE_BE16(0x0800),
};

static struct rte_flow_item_ipv4 inner_ipv4 = {
	.hdr = {
			.src_addr = RTE_BE32(RTE_IPV4(1, 1, 1, 1)),
			.dst_addr = RTE_BE32(RTE_IPV4(2, 2, 2, 2)),
		},
};

#define MAX_RTE_FLOW_ACTIONS 16
#define MAX_RTE_FLOW_PATTERN 16

struct dao_flow *
basic_flow_test_create(uint16_t portid, int test_val_idx)
{
	struct rte_flow_action action[MAX_RTE_FLOW_ACTIONS] = {};
	struct rte_flow_item pattern[MAX_RTE_FLOW_PATTERN] = {};
	struct rte_flow_action_mark *act_mark;
	struct rte_flow_attr attr = {};
	struct rte_flow_error err = {};
	struct rte_flow_item_ipv4 ip_spec;
	struct rte_flow_item_ipv4 ip_mask;
	int pattern_idx = 0, act_idx = 0;
	struct dao_flow *dflow;
	struct rte_flow_action_port_id id = {
		.id = portid,
	};

	/* Define attributes */
	attr.egress = 0;
	attr.ingress = 1;

	act_mark = rte_zmalloc("Act_mark", sizeof(struct rte_flow_action_mark), 0);
	if (!act_mark) {
		dao_err("Failed to get memory mark action config");
		return NULL;
	}
	memset(action, 0, MAX_RTE_FLOW_ACTIONS * sizeof(struct rte_flow_action));
	memset(pattern, 0, MAX_RTE_FLOW_PATTERN * sizeof(struct rte_flow_item));
	memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
	/* Define actions */
	action[act_idx].type = RTE_FLOW_ACTION_TYPE_COUNT;
	act_idx++;
	/* Add mark ID action */
	action[act_idx].type = RTE_FLOW_ACTION_TYPE_MARK;
	act_mark->id = test_vals[test_val_idx].mark;
	action[act_idx].conf = (struct rte_flow_action_mark *)act_mark;
	act_idx++;
	action[act_idx].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
	action[act_idx].conf = &id;
	act_idx++;
	action[act_idx].type = RTE_FLOW_ACTION_TYPE_END;
	action[act_idx].conf = NULL;

	/* Define patterns */
	pattern[pattern_idx].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[pattern_idx].spec = &eth;
	pattern[pattern_idx].mask = &eth_mask;
	pattern[pattern_idx].last = NULL;
	pattern_idx++;

	pattern[pattern_idx].type = RTE_FLOW_ITEM_TYPE_IPV4;
	ip_spec.hdr.src_addr = test_vals[test_val_idx].ipv4.hdr.src_addr;
	ip_mask.hdr.src_addr = 0xFFFFFFFF;
	ip_spec.hdr.dst_addr = test_vals[test_val_idx].ipv4.hdr.dst_addr;
	ip_mask.hdr.dst_addr = 0xFFFFFFFF;
	pattern[pattern_idx].spec = &ip_spec;
	pattern[pattern_idx].mask = &ip_mask;
	pattern[pattern_idx].last = NULL;
	pattern_idx++;

	pattern[pattern_idx].type = RTE_FLOW_ITEM_TYPE_END;

	/* Flow create */
	dflow = dao_flow_create(portid, &attr, pattern, action, &err);
	if (!dflow)
		DAO_ERR_GOTO(errno, error, "Failed to create DOS rule");

	return dflow;
error:
	return NULL;
}

struct dao_flow *
ovs_flow_test_create(uint16_t portid, int test_val_idx)
{
	struct dao_flow *dflow;
	struct rte_flow_attr attr;
	struct rte_flow_error error;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow_action_mark mark = {.id = test_vals[test_val_idx].mark};
	struct rte_flow_item_eth eth_spec;
	struct rte_flow_item_eth eth_mask;
	struct rte_flow_item_vlan vlan_spec;
	struct rte_flow_item_vlan vlan_mask;
	struct rte_flow_item_ipv4 ip_spec;
	struct rte_flow_item_ipv4 ip_mask;
	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;
	struct rte_flow_item_vxlan vxlan_spec;
	struct rte_flow_item_vxlan vxlan_mask;
	struct rte_flow_item_eth inner_eth_spec;
	struct rte_flow_item_eth inner_eth_mask;
	struct rte_flow_item_ipv4 inner_ip_spec;
	struct rte_flow_item_ipv4 inner_ip_mask;
	uint8_t eth_addr[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	uint8_t eth_addr_mask[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));
	memset(&eth_spec, 0, sizeof(struct rte_flow_item_eth));
	memset(&eth_mask, 0, sizeof(struct rte_flow_item_eth));
	memset(&vlan_spec, 0, sizeof(struct rte_flow_item_vlan));
	memset(&vlan_mask, 0, sizeof(struct rte_flow_item_vlan));
	memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&udp_spec, 0, sizeof(struct rte_flow_item_udp));
	memset(&udp_mask, 0, sizeof(struct rte_flow_item_udp));
	memset(&vxlan_spec, 0, sizeof(struct rte_flow_item_vxlan));
	memset(&vxlan_mask, 0, sizeof(struct rte_flow_item_vxlan));
	memset(&inner_eth_spec, 0, sizeof(struct rte_flow_item_eth));
	memset(&inner_eth_mask, 0, sizeof(struct rte_flow_item_eth));
	memset(&inner_ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&inner_ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;

	action[0].type = RTE_FLOW_ACTION_TYPE_MARK;
	action[0].conf = &mark;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	memcpy(&eth_spec.hdr.dst_addr, eth_addr, sizeof(struct rte_ether_addr));
	memcpy(&eth_mask.hdr.dst_addr, eth_addr_mask, sizeof(struct rte_ether_addr));
	pattern[0].spec = &eth_spec;
	pattern[0].mask = &eth_mask;

	pattern[1].type = RTE_FLOW_ITEM_TYPE_VLAN;
	vlan_spec.hdr.vlan_tci = rte_cpu_to_be_16(VLAN_TCI);
	vlan_mask.hdr.vlan_tci = 0xFFFF;
	pattern[1].spec = &vlan_spec;
	pattern[1].mask = &vlan_mask;

	pattern[2].type = RTE_FLOW_ITEM_TYPE_IPV4;
	ip_spec.hdr.src_addr = (test_vals[test_val_idx].ipv4.hdr.src_addr);
	ip_mask.hdr.src_addr = 0xFFFFFFFF;
	ip_spec.hdr.dst_addr = (test_vals[test_val_idx].ipv4.hdr.dst_addr);
	ip_mask.hdr.dst_addr = 0xFFFFFFFF;
	pattern[2].spec = &ip_spec;
	pattern[2].mask = &ip_mask;

	pattern[3].type = RTE_FLOW_ITEM_TYPE_UDP;
	udp_spec.hdr.src_port = rte_cpu_to_be_16(UDP_SRC_PORT);
	udp_mask.hdr.src_port = 0xFFFF;
	udp_spec.hdr.dst_port = rte_cpu_to_be_16(UDP_DST_VXLAN_PORT);
	udp_mask.hdr.dst_port = 0xFFFF;
	pattern[3].spec = &udp_spec;
	pattern[3].mask = &udp_mask;

	pattern[4].type = RTE_FLOW_ITEM_TYPE_VXLAN;
	vxlan_spec.hdr.vx_vni = rte_cpu_to_be_32(VXLAN_VNI);
	vxlan_mask.hdr.vx_vni = 0xFFFFFFFF;
	pattern[4].spec = &vxlan_spec;
	pattern[4].mask = &vxlan_mask;

	pattern[5].type = RTE_FLOW_ITEM_TYPE_ETH;
	memcpy(&inner_eth_spec.hdr.dst_addr, &inner_eth.dst, sizeof(struct rte_ether_addr));
	memcpy(&inner_eth_mask.hdr.dst_addr, eth_addr_mask, sizeof(struct rte_ether_addr));
	memcpy(&inner_eth_spec.hdr.src_addr, &inner_eth.src, sizeof(struct rte_ether_addr));
	memcpy(&inner_eth_mask.hdr.src_addr, eth_addr_mask, sizeof(struct rte_ether_addr));
	pattern[5].spec = &inner_eth_spec;
	pattern[5].mask = &inner_eth_mask;

	pattern[6].type = RTE_FLOW_ITEM_TYPE_IPV4;
	inner_ip_spec.hdr.fragment_offset = rte_cpu_to_be_16(FRAG_OFFSET);
	inner_ip_mask.hdr.fragment_offset = 0xFFFF;
	pattern[6].spec = &inner_ip_spec;
	pattern[6].mask = &inner_ip_mask;

	pattern[7].type = RTE_FLOW_ITEM_TYPE_END;

	dflow = dao_flow_create(portid, &attr, pattern, action, &error);
	if (!dflow)
		DAO_ERR_GOTO(errno, error, "Failed to create DOS rule");

	return dflow;
error:
	return NULL;
}

struct dao_flow *
default_flow_test_create(uint16_t portid, int test_val_idx)
{
	struct dao_flow *dflow;
	struct rte_flow_attr attr;
	struct rte_flow_error error;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow_action_mark mark = {.id = test_vals[test_val_idx].mark};
	struct rte_flow_item_eth eth_spec;
	struct rte_flow_item_eth eth_mask;
	struct rte_flow_item_vlan vlan_spec;
	struct rte_flow_item_vlan vlan_mask;
	struct rte_flow_item_ipv4 ip_spec;
	struct rte_flow_item_ipv4 ip_mask;
	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;
	uint8_t eth_addr[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	uint8_t eth_addr_mask[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));
	memset(&eth_spec, 0, sizeof(struct rte_flow_item_eth));
	memset(&eth_mask, 0, sizeof(struct rte_flow_item_eth));
	memset(&vlan_spec, 0, sizeof(struct rte_flow_item_vlan));
	memset(&vlan_mask, 0, sizeof(struct rte_flow_item_vlan));
	memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&udp_spec, 0, sizeof(struct rte_flow_item_udp));
	memset(&udp_mask, 0, sizeof(struct rte_flow_item_udp));
	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;

	action[0].type = RTE_FLOW_ACTION_TYPE_MARK;
	action[0].conf = &mark;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	memcpy(&eth_spec.hdr.dst_addr, eth_addr, sizeof(struct rte_ether_addr));
	memcpy(&eth_mask.hdr.dst_addr, eth_addr_mask, sizeof(struct rte_ether_addr));
	pattern[0].spec = &eth_spec;
	pattern[0].mask = &eth_mask;

	pattern[1].type = RTE_FLOW_ITEM_TYPE_VLAN;
	vlan_spec.hdr.vlan_tci = rte_cpu_to_be_16(VLAN_TCI);
	vlan_mask.hdr.vlan_tci = 0xFFFF;
	pattern[1].spec = &vlan_spec;
	pattern[1].mask = &vlan_mask;

	pattern[2].type = RTE_FLOW_ITEM_TYPE_IPV4;
	ip_spec.hdr.src_addr = (test_vals[test_val_idx].ipv4.hdr.src_addr);
	ip_mask.hdr.src_addr = 0xFFFFFFFF;
	ip_spec.hdr.dst_addr = (test_vals[test_val_idx].ipv4.hdr.dst_addr);
	ip_mask.hdr.dst_addr = 0xFFFFFFFF;
	pattern[2].spec = &ip_spec;
	pattern[2].mask = &ip_mask;

	pattern[3].type = RTE_FLOW_ITEM_TYPE_UDP;
	udp_spec.hdr.src_port = rte_cpu_to_be_16(UDP_SRC_PORT);
	udp_mask.hdr.src_port = 0xFFFF;
	udp_spec.hdr.dst_port = rte_cpu_to_be_16(UDP_DST_VXLAN_PORT);
	udp_mask.hdr.dst_port = 0xFFFF;
	pattern[3].spec = &udp_spec;
	pattern[3].mask = &udp_mask;

	pattern[4].type = RTE_FLOW_ITEM_TYPE_END;

	dflow = dao_flow_create(portid, &attr, pattern, action, &error);
	if (!dflow)
		DAO_ERR_GOTO(errno, error, "Failed to create DOS rule");

	return dflow;
error:
	return NULL;
}

static inline void
copy_buf_to_pkt(void *buf, unsigned int len, struct rte_mbuf *pkt, unsigned int offset)
{
	if (offset + len <= pkt->data_len) {
		rte_memcpy(rte_pktmbuf_mtod_offset(pkt, char *, offset), buf, (size_t)len);
		return;
	}
}

int
sample_packet(struct rte_mempool *mbp, struct rte_mbuf **pkts)
{
	int test_val_sz = sizeof(test_vals) / sizeof(struct test_ipaddr_mark);
	struct rte_ether_hdr eth_hdr, inner_eth_hdr;
	struct rte_ipv4_hdr ip_hdr, inner_ip_hdr;
	struct rte_vxlan_hdr vxlan_hdr;
	struct rte_vlan_hdr vlan_hdr;
	struct rte_udp_hdr udp_hdr;
	struct rte_mbuf *pkt;
	uint32_t pkt_len, offset = 0;
	int i = 0;

	if (rte_mempool_get_bulk(mbp, (void **)pkts, BURST_SIZE))
		return false;

	for (i = 0; i < BURST_SIZE; i++) {
		pkt = pkts[i];
		rte_pktmbuf_reset_headroom(pkt);
		pkt->data_len = 128;
		pkt->l2_len = sizeof(struct rte_ether_hdr);
		pkt->l3_len = sizeof(struct rte_ipv4_hdr);

		pkt_len = pkt->data_len;
		pkt->next = NULL;

		pkt_len = (uint16_t)(pkt_len + sizeof(struct rte_ether_hdr));
		rte_ether_addr_copy(&eth.src, &eth_hdr.src_addr);
		rte_ether_addr_copy(&eth.dst, &eth_hdr.dst_addr);
		eth_hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);

		vlan_hdr.eth_proto = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		vlan_hdr.vlan_tci = rte_cpu_to_be_16(VLAN_TCI);

		ip_hdr.type_of_service = 0;
		ip_hdr.fragment_offset = 0;
		ip_hdr.time_to_live = 64;
		ip_hdr.next_proto_id = IPPROTO_UDP;
		ip_hdr.packet_id = 0;
		ip_hdr.total_length = rte_cpu_to_be_16(pkt_len);
		ip_hdr.src_addr = test_vals[i % test_val_sz].ipv4.hdr.src_addr;
		ip_hdr.dst_addr = test_vals[i % test_val_sz].ipv4.hdr.dst_addr;

		memset(&udp_hdr, 0, sizeof(udp_hdr));
		udp_hdr.src_port = rte_cpu_to_be_16(UDP_SRC_PORT);
		udp_hdr.dst_port = rte_cpu_to_be_16(UDP_DST_VXLAN_PORT);
		udp_hdr.dgram_len = rte_cpu_to_be_16(pkt_len);
		udp_hdr.dgram_cksum = 0;

		memset(&inner_eth_hdr, 0, sizeof(inner_eth_hdr));
		memset(&inner_ip_hdr, 0, sizeof(inner_eth_hdr));
		memset(&vxlan_hdr, 0, sizeof(vxlan_hdr));
		vxlan_hdr.vx_vni = rte_cpu_to_be_32(VXLAN_VNI);

		rte_ether_addr_copy(&inner_eth.src, &inner_eth_hdr.src_addr);
		rte_ether_addr_copy(&inner_eth.dst, &inner_eth_hdr.dst_addr);
		inner_eth_hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

		inner_ip_hdr.type_of_service = 0;
		inner_ip_hdr.fragment_offset = rte_cpu_to_be_16(FRAG_OFFSET);
		inner_ip_hdr.time_to_live = 64;
		inner_ip_hdr.next_proto_id = IPPROTO_UDP;
		inner_ip_hdr.packet_id = 0;
		inner_ip_hdr.total_length = rte_cpu_to_be_16(pkt_len);
		inner_ip_hdr.src_addr = inner_ipv4.hdr.src_addr;
		inner_ip_hdr.dst_addr = inner_ipv4.hdr.dst_addr;

		copy_buf_to_pkt(&eth_hdr, sizeof(struct rte_ether_hdr), pkt, 0);
		offset = sizeof(struct rte_ether_hdr);
		copy_buf_to_pkt(&vlan_hdr, sizeof(struct rte_vlan_hdr), pkt, offset);
		offset += sizeof(struct rte_vlan_hdr);
		copy_buf_to_pkt(&ip_hdr, sizeof(struct rte_ipv4_hdr), pkt, offset);
		offset += sizeof(struct rte_ipv4_hdr);
		copy_buf_to_pkt(&udp_hdr, sizeof(struct rte_udp_hdr), pkt, offset);
		offset += sizeof(struct rte_udp_hdr);
		copy_buf_to_pkt(&vxlan_hdr, sizeof(struct rte_vxlan_hdr), pkt, offset);
		offset += sizeof(struct rte_vxlan_hdr);
		copy_buf_to_pkt(&inner_eth_hdr, sizeof(struct rte_ether_hdr), pkt, offset);
		offset += sizeof(struct rte_ether_hdr);
		copy_buf_to_pkt(&inner_ip_hdr, sizeof(struct rte_ipv4_hdr), pkt, offset);
		offset += sizeof(struct rte_ipv4_hdr);
		pkt->pkt_len = pkt->data_len + offset;
	}

	return i;
}

int
validate_flow_match(struct rte_mbuf *pkt, uint16_t mark)
{
	struct rte_ipv4_hdr *ipv4_hdr;
	uint16_t offset = 0;
	int test_val_sz = sizeof(test_vals) / sizeof(struct test_ipaddr_mark);
	int i;

	offset = sizeof(struct rte_ether_hdr) + sizeof(struct rte_vlan_hdr);

	ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, offset);

	if (mark) {
		for (i = 0; i < test_val_sz; i++) {
			if (mark == test_vals[i].mark) {
				if (ipv4_hdr->src_addr == test_vals[i].ipv4.hdr.src_addr &&
				    ipv4_hdr->dst_addr == test_vals[i].ipv4.hdr.dst_addr)
					return 0;
			}
		}
	} else if (mark == 0) {
		if (ipv4_hdr->src_addr == test_vals[2].ipv4.hdr.src_addr &&
		    ipv4_hdr->dst_addr == test_vals[2].ipv4.hdr.dst_addr)
			return 0;
	}
	dao_err("Packet mark id %x not matching any flow src ip:%x, dst ip:%x", mark,
		rte_be_to_cpu_32(ipv4_hdr->src_addr), rte_be_to_cpu_32(ipv4_hdr->dst_addr));
	return -1;
}
