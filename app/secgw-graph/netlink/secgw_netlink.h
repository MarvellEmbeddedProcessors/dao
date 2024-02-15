/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_GRAPH_SECGW_NETLINK_H_
#define _APP_SECGW_GRAPH_SECGW_NETLINK_H_

#include <arpa/inet.h>
#include <nodes/node_api.h>

#define SECGW_NL_DBG dao_info
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

void secgw_print_ip_addr(struct in6_addr *addr, int prefixlen, struct dao_ds *str);
int secgw_neigh_find_and_add(struct in6_addr *addr, uint32_t prefixlen, uint8_t *mac,
			     int32_t *_index, uint16_t *edge, struct secgw_neigh_entry **_neigh,
			     int is_add);

#endif
