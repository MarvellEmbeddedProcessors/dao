/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

/**
 * @file
 *
 * DAO Net
 *
 * It includes some useful utility functions for manipulating networks packets
 */

#ifndef __DAO_NET_H__
#define __DAO_NET_H__

#include <rte_ethdev.h>

/**
 * 32-bit value in network byte order which is 16-bit aligned
 */
typedef struct {
	rte_be16_t hi, lo;
} dao_16aligned_be32;

/* union used for byte conversion */
union dao_16aligned_in6_addr {
	rte_be16_t be16[8];
	dao_16aligned_be32 be32[4];
};

static inline rte_be32_t
dao_get_16aligned_be32(const dao_16aligned_be32 *x)
{
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	return ((rte_be32_t)x->hi << 16) | x->lo;
#else
	return ((rte_be32_t)x->lo << 16) | x->hi;
#endif
}

/**
 * Convert ip4 address from rte_be32_t to struct in6_addr format
 *
 * @param ip4
 *   ip4 address in rte_be32_t
 *
 * @return
 *   ipv4 address in struct in6_addr
 */
static inline struct in6_addr
dao_in6_addr_mapped_ipv4(rte_be32_t ip4)
{
	struct in6_addr ip6;

	memset(&ip6, 0, sizeof(ip6));
	ip6.s6_addr[10] = 0xff;
	ip6.s6_addr[11] = 0xff;
	memcpy(&ip6.s6_addr[12], &ip4, 4);
	return ip6;
}

/**
 * Convert ip4 address from rte_be32_t to struct in6_addr format
 *
 * @param[out] ip6
 *  Pointer to ip6 address in (struct in6_addr)
 * @param ip4
 *  ip4 address in rte_be32_t
 */
static inline void
dao_in6_addr_set_mapped_ipv4(struct in6_addr *ip6, rte_be32_t ip4)
{
	*ip6 = dao_in6_addr_mapped_ipv4(ip4);
}

/**
 * Extract rte_be32_t ipv4 address from struct in6_addr
 *
 * @param addr
 *   in6 address format
 *
 * @return
 *   Failure: INADDR_ANY
 *   Success: Valid IPv4 address
 */
static inline rte_be32_t
dao_in6_addr_get_mapped_ipv4(struct in6_addr *addr)
{
	union dao_16aligned_in6_addr *taddr =
		(union dao_16aligned_in6_addr *)addr;

	if (IN6_IS_ADDR_V4MAPPED(taddr))
		return dao_get_16aligned_be32(&taddr->be32[3]);
	else
		return INADDR_ANY;
}

#endif /* __DAO_NET_H__ */
