/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef APP_GRAPH_ETHDEV_H
#define APP_GRAPH_ETHDEV_H

#include <cmdline_parse.h>

#define ETHDEV_IPV6_ADDR_LEN 16

struct ipv4_addr_config {
	uint32_t ip;
	uint32_t mask;
};

struct ipv6_addr_config {
	uint8_t ip[ETHDEV_IPV6_ADDR_LEN];
	uint8_t mask[ETHDEV_IPV6_ADDR_LEN];
};

extern uint32_t enabled_port_mask;

void ethdev_start(void);
void ethdev_stop_all(void);
void *ethdev_mempool_list_by_portid(uint16_t portid);
int16_t ethdev_portid_by_ip4(uint32_t ip, uint32_t mask);
int16_t ethdev_portid_by_ip6(uint8_t *ip, uint8_t *mask);
void ethdev_list_clean(void);
uint32_t ethdev_port_mask(void);
int smc_ethdev_start(uint16_t portid);
int smc_ethdev_stop(uint16_t portid);

#endif
