/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __DAO_CONNTRACK_PRIVATE_H__
#define __DAO_CONNTRACK_PRIVATE_H__

#include <rte_common.h>
#include <rte_hash.h>
#include <rte_log.h>
#include <rte_mbuf.h>

#include "dao_conntrack_stats.h"
#include "dao_log.h"

/* DPDK supports ECHO_REQUEST and ECHO_REPLY. */
#define DAO_ICMP_ECHO_REPLY     0
#define DAO_ICMP_DST_UNREACH    3
#define DAO_ICMP_SOURCEQUENCH   4
#define DAO_ICMP_REDIRECT       5
#define DAO_ICMP_ECHO_REQUEST   8
#define DAO_ICMP_TIME_EXCEEDED  11
#define DAO_ICMP_PARAM_PROB     12
#define DAO_ICMP_TIMESTAMP      13
#define DAO_ICMP_TIMESTAMPREPLY 14
#define DAO_ICMP_INFOREQUEST    15
#define DAO_ICMP_INFOREPLY      16

enum conn_update_res {
	CONN_UPDATE_INVALID,
	CONN_UPDATE_VALID,
	CONN_UPDATE_NEW,
	CONN_UPDATE_VALID_NEW,
};

enum conn_dir {
	CONN_DIR_FWD = 0,
	CONN_DIR_REV,
	CONN_DIRS,
};

enum conn_timeout {
	CONN_TO_TCP_SYN_SENT,
	CONN_TO_TCP_SYN_RECV,
	CONN_TO_TCP_ESTABLISHED,
	CONN_TO_TCP_FIN_WAIT,
	CONN_TO_TCP_TIME_WAIT,
	CONN_TO_TCP_CLOSE,
	CONN_TO_UDP_FIRST,
	CONN_TO_UDP_SINGLE,
	CONN_TO_UDP_MULTIPLE,
	CONN_TO_ICMP_FIRST,
	CONN_TO_ICMP_REPLY,
	CONN_TO_MAX,
};

static unsigned int conn_timeout_def[] = {
	[CONN_TO_TCP_SYN_SENT] = 30,
	[CONN_TO_TCP_SYN_RECV] = 30,
	[CONN_TO_TCP_ESTABLISHED] = 24 * 60 * 60,
	[CONN_TO_TCP_FIN_WAIT] = 15 * 60,
	[CONN_TO_TCP_TIME_WAIT] = 45,
	[CONN_TO_TCP_CLOSE] = 30,
	[CONN_TO_UDP_FIRST] = 60,
	[CONN_TO_UDP_SINGLE] = 60,
	[CONN_TO_UDP_MULTIPLE] = 30,
	[CONN_TO_ICMP_FIRST] = 60,
	[CONN_TO_ICMP_REPLY] = 30,
};

union ctx_addr {
	uint32_t ipv4_addr;
	uint8_t ipv6_addr[16];
};

struct ctx_endpoint {
	union ctx_addr addr;
	union {
		uint16_t port;
		struct {
			uint16_t icmp_id;
			uint8_t icmp_type;
			uint8_t icmp_code;
		};
	};
};

struct conn_key {
	struct ctx_endpoint src;
	struct ctx_endpoint dst;
	struct {
		uint32_t ep_hash;
		uint16_t dl_type;
		uint16_t zone;
		uint8_t nw_proto;
	} kdata;
};

struct dao_conn {
	struct conn_key conn_key[CONN_DIRS];
	rte_atomic64_t expiration;
	uint8_t l4_offset;
	enum dao_conn_state state;
	rte_spinlock_t clock;
};

struct conn_lookup_ctx {
	uint64_t ct_state;
	struct conn_key key;
	struct dao_conn *conn;
	bool reply;
	bool icmp_related;
	uint8_t l4_offset;
};

/*
 * List node holding pointer to the connection.
 */
struct dao_conn_node {
	STAILQ_ENTRY(dao_conn_node) next;
	uint64_t *own_ptr;
	uint64_t *ptr;
};

/*
 * Bucket containing list of nodes.
 */
struct dao_bucket_head {
	STAILQ_HEAD(conn_node_head, dao_conn_node) node_list;
	uint32_t num_node;
	rte_spinlock_t block;
};

/*
 * @struct dao_conntrack
 *
 * Connection tracking object.
 */
struct dao_conntrack {
	bool thread_exit;
	struct dao_bucket_head *blist;
	struct rte_rcu_qsbr *qsbr_obj;
	struct rte_rcu_qsbr_dq *dq;
	struct rte_hash *hash;
	uint32_t hbasis;
	rte_atomic64_t num_conn;
	uint64_t max_num_conn;
	rte_thread_t cleanup_thread;
};

struct ct_l4_proto {
	struct dao_conn *(*new_conn)(struct dao_conntrack *ct, struct conn_lookup_ctx *ctx,
				     struct rte_mbuf *pkt, uint64_t now);
	bool (*valid_new)(struct conn_lookup_ctx *ctx, struct rte_mbuf *pkt);
	enum conn_update_res (*conn_update)(struct dao_conntrack *ct, struct dao_conn *conn,
					    struct rte_mbuf *pkt, bool reply, uint64_t now);
};

/* Murmurhash by Austin Appleby,
 * from https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp
 *
 * The upstream license there says:
 *
 *    MurmurHash3 was written by Austin Appleby, and is placed in the public
 *    domain. The author hereby disclaims copyright to this source code.
 */

static __rte_always_inline uint32_t
hash_rot(uint32_t x, int k)
{
	return (x << k) | (x >> (32 - k));
}

static __rte_always_inline uint32_t
mhash_add__(uint32_t hash, uint32_t data)
{
	/* zero-valued 'data' will not change the 'hash' value */
	if (!data) {
		return hash;
	}

	data *= 0xcc9e2d51;
	data = hash_rot(data, 15);
	data *= 0x1b873593;
	return hash ^ data;
}

static __rte_always_inline uint32_t
mhash_add(uint32_t hash, uint32_t data)
{
	hash = mhash_add__(hash, data);
	hash = hash_rot(hash, 13);
	return hash * 5 + 0xe6546b64;
}

static __rte_always_inline uint32_t
hash_add(uint32_t hash, uint32_t data)
{
	return mhash_add(hash, data);
}

static __rte_always_inline uint32_t
hash_add_words(uint32_t hash, const uint32_t *p, size_t n_words)
{
	for (size_t i = 0; i < n_words; i++) {
		hash = hash_add(hash, p[i]);
	}
	return hash;
}

static __rte_always_inline uint32_t
hash_add_bytes32(uint32_t hash, const uint32_t *p, size_t n_bytes)
{
	return hash_add_words(hash, p, n_bytes / 4);
}

static __rte_always_inline void
conn_ex_timer_update(struct dao_conn *conn, uint64_t val, uint64_t now)
{
	uint64_t hz;
	uint64_t timeout;

	hz = rte_get_timer_hz();
	timeout = (hz * conn_timeout_def[val]) + now;

	rte_atomic64_set(&conn->expiration, timeout);
}

static __rte_always_inline void
conn_force_expire(struct dao_conn *conn, uint64_t now)
{
	rte_atomic64_set(&conn->expiration, now);
}

#endif /* __DAO_CONNTRACK_PRIVATE_H__ */
