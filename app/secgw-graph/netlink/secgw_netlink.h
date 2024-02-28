/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_GRAPH_SECGW_NETLINK_H_
#define _APP_SECGW_GRAPH_SECGW_NETLINK_H_

#include <arpa/inet.h>
#include <nodes/node_api.h>

#define SECGW_NL_DBG dao_dbg
/**
 * A neigh entry
 */
typedef struct secgw_neigh_entry {
	STAILQ_ENTRY(secgw_neigh_entry) next_neigh_entry;
	int device_index;
	uint16_t edge;
	uint32_t prefixlen;
	struct in6_addr ip_addr;
	uint8_t dest_ll_addr[RTE_ETHER_ADDR_LEN];
} secgw_neigh_entry_t;

typedef struct secgw_route_partial_entry {
	STAILQ_ENTRY(secgw_route_partial_entry) next_partial_entry;
	dao_netlink_route_ip_route_t partial_route;
} secgw_route_partial_entry_t;

typedef struct secgw_route_dump_entry {
	STAILQ_ENTRY(secgw_route_dump_entry) next_dump_entry;
	dao_netlink_ip_addr_t ip_addr;
	rte_edge_t edge;
	int route_index;
	uint8_t rewrite_data[SECGW_GRAPH_IP4_REWRITE_MAX_LEN];
	size_t rewrite_length;
	int device_id;
} secgw_route_dump_entry_t;

typedef STAILQ_HEAD(, secgw_route_dump_entry) secgw_route_dump_list_head_t;
typedef STAILQ_HEAD(, secgw_route_partial_entry) secgw_route_partial_list_head_t;
typedef STAILQ_HEAD(, secgw_neigh_entry) secgw_neigh_list_head_t;

extern secgw_route_partial_list_head_t secgw_route_partial_list;
extern secgw_route_dump_list_head_t secgw_route_dump_list;
extern secgw_neigh_list_head_t secgw_neigh_list;

void secgw_print_ip_addr(struct in6_addr *addr, int prefixlen, struct dao_ds *str);
int secgw_neigh_find_and_add(struct in6_addr *addr, uint32_t prefixlen, uint8_t *mac,
			     int32_t *_index, uint16_t *edge, struct secgw_neigh_entry **_neigh,
			     int linux_device, int is_add);

#endif
