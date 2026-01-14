/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __RDMA_AV_H__
#define __RDMA_AV_H__

#include "rdma_priv.h"

#define RDMA_ADDR_VEC_MAX 1024

enum {
	RDMA_NETWORK_TYPE_IPV4 = 1,
	RDMA_NETWORK_TYPE_IPV6 = 2,
};

union rdma_gid {
	uint8_t raw[16];
	struct {
		rte_be64_t subnet_prefix;
		rte_be64_t interface_id;
	} global;
};

struct iph_attr {
	union rdma_gid dgid;
	uint32_t flow_label;
	uint8_t sgid_index;
	uint8_t hop_limit;
	uint8_t traffic_class;
	uint16_t ip_id;
};

typedef struct rdma_av {
	uint8_t port_num;
	uint16_t index;
	uint8_t network_type;
	uint32_t refcnt;
	struct rte_ether_addr dmac;
	struct rte_ether_addr smac;
	struct iph_attr iph;
	union {
		uint32_t ip4;
		uint32_t ip6[4];
	} sgid_addr, dgid_addr;
} rdma_av_t;

struct rdma_network_hdr {
	/* The IB spec states that if it's IPv4, the header
	 * is located in the last 20 bytes of the header.
	 */
	uint8_t reserved[20];
	struct rte_ipv4_hdr roce4grh;
};

const struct rdma_av *rdma_av_get(uint8_t port_num, uint16_t index);
int rdma_av_insert(void *av_data);
int rdma_av_remove(void *av_data);
int rdma_av_init(uint64_t **av, uint32_t num_av);
int rdma_av_free(struct rdma_av **av);

#endif /* __RDMA_AV_H__ */
