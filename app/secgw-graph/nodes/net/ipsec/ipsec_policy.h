/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_IPSEC_POLICY_H_
#define _APP_SECGW_IPSEC_POLICY_H_

#include <rte_acl.h>
#include <rte_ip.h>

#define SECGW_IPSEC_NAMELEN        64
#define SECGW_ACL_CLASSIFY_ALGO    RTE_ACL_CLASSIFY_SCALAR
#define SECGW_IPSEC_POLICY_DISCARD (UINT32_MAX)
#define SECGW_IPSEC_POLICY_BYPASS (UINT32_MAX - 2) /** Skipping -2 delibeartely */

#define SECGW_USE_ONLY_IP

#ifdef SECGW_USE_ONLY_IP
enum { PROTO_FIELD_IPV4, SRC_FIELD_IPV4, DST_FIELD_IPV4, NUM_FIELDS_IPV4 };

enum { SECGW_ACL_IPV4_PROTO, SECGW_ACL_IPV4_SRC, SECGW_ACL_IPV4_DST, SECGW_ACL_IPV4_NUM };

typedef struct __rte_packed secgw_ipsec4_policy_fields {
	uint8_t next_proto_id;
	rte_be32_t src_addr;
	rte_be32_t dst_addr;
} secgw_ipsec4_policy_fields_t;
#else
enum {
	PROTO_FIELD_IPV4,
	SRC_FIELD_IPV4,
	DST_FIELD_IPV4,
	SRCP_FIELD_IPV4,
	DSTP_FIELD_IPV4,
	NUM_FIELDS_IPV4
};

enum {
	SECGW_ACL_IPV4_PROTO,
	SECGW_ACL_IPV4_SRC,
	SECGW_ACL_IPV4_DST,
	SECGW_ACL_IPV4_PORTS,
	SECGW_ACL_IPV4_NUM
};

typedef struct __rte_packed secgw_ipsec4_policy_fields {
	uint8_t next_proto_id;
	rte_be32_t src_addr;
	rte_be32_t dst_addr;
	rte_be16_t src_port;
	rte_be16_t dst_port;
} secgw_ipsec4_policy_fields_t;
#endif

#ifdef SECGW_USE_ONLY_IP
static struct rte_acl_field_def secgw_ipsec4_policy_fields_acl[NUM_FIELDS_IPV4] = {
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint8_t),
		.field_index = PROTO_FIELD_IPV4,
		.input_index = SECGW_ACL_IPV4_PROTO,
		.offset = 0,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC_FIELD_IPV4,
		.input_index = SECGW_ACL_IPV4_SRC,
		.offset = offsetof(struct rte_ipv4_hdr, src_addr) -
			  offsetof(struct rte_ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST_FIELD_IPV4,
		.input_index = SECGW_ACL_IPV4_DST,
		.offset = offsetof(struct rte_ipv4_hdr, dst_addr) -
			  offsetof(struct rte_ipv4_hdr, next_proto_id),
	},
};
#else
static struct rte_acl_field_def secgw_ipsec4_policy_fields_acl[NUM_FIELDS_IPV4] = {
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint8_t),
		.field_index = PROTO_FIELD_IPV4,
		.input_index = SECGW_ACL_IPV4_PROTO,
		.offset = 0,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC_FIELD_IPV4,
		.input_index = SECGW_ACL_IPV4_SRC,
		.offset = offsetof(struct rte_ipv4_hdr, src_addr) -
			  offsetof(struct rte_ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST_FIELD_IPV4,
		.input_index = SECGW_ACL_IPV4_DST,
		.offset = offsetof(struct rte_ipv4_hdr, dst_addr) -
			  offsetof(struct rte_ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = SRCP_FIELD_IPV4,
		.input_index = SECGW_ACL_IPV4_PORTS,
		.offset =
			sizeof(struct rte_ipv4_hdr) - offsetof(struct rte_ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = DSTP_FIELD_IPV4,
		.input_index = SECGW_ACL_IPV4_PORTS,
		.offset = sizeof(struct rte_ipv4_hdr) -
			  offsetof(struct rte_ipv4_hdr, next_proto_id) + sizeof(uint16_t),
	},
};
#endif

typedef RTE_ACL_RULE_DEF(secgw_ipsec4_rules,
			 RTE_DIM(secgw_ipsec4_policy_fields_acl)) secgw_ipsec4_rules_t;

typedef struct __rte_cache_aligned secgw_ipsec4_policy {
	struct rte_acl_ctx *acl_ctx;
	uint32_t num_rules;
	uint32_t max_rules;
	void *bitmap_mem;
	struct rte_bitmap *bmap;
	char spd_name[SECGW_IPSEC_NAMELEN];
	secgw_ipsec4_rules_t *rules;
} secgw_ipsec4_policy_t;

typedef struct secgw_ipsec_policy {
	secgw_ipsec4_policy_t outbound4;
	secgw_ipsec4_policy_t inbound4;
} secgw_ipsec_policy_t;

struct rte_node_register *secgw_ipsec_policy_output_node_get(void);
#endif
