/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __DAO_CONNTRACK_H__
#define __DAO_CONNTRACK_H__

#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/queue.h>

/* Max number of connection entries per conntrack object. */
#define MAX_CONN_ENTRIES (1 << 19)
/* BUCKET_SIZE should be same as RTE_HASH_BUCKET_ENTRIES in rte_hash library */
#define BUCKET_SIZE      8
#define NUM_CONN_BUCKETS (MAX_CONN_ENTRIES / BUCKET_SIZE)

#define DAO_CONN_STATE_FLAG(x) (1 << (x))
enum dao_conn_state {
	DAO_CONN_STATE_NEW,
	DAO_CONN_STATE_ESTABLISHED,
	DAO_CONN_STATE_RELATED,
	DAO_CONN_STATE_REPLY_DIR,
	DAO_CONN_STATE_INVALID,
	DAO_CONN_STATE_TRACKED,
};

extern int dao_ct_field_offset;
/*
 * Conntrack mbuf private data to store state of connection.
 */
struct dao_ct_pkt_metadata {
	/* conntrack data */
	uint64_t ct_state;
	/* Reserved: may need to save connection object for hairpin case. */
	uintptr_t ct_data_ptr;
};

static const struct rte_mbuf_dynfield dao_ct_field = {
	.name = "dao_ct_field",
	.size = sizeof(struct dao_ct_pkt_metadata),
	.align = __alignof__(struct dao_ct_pkt_metadata),
};

static __rte_always_inline struct dao_ct_pkt_metadata *
dao_ct_pkt_metadata(struct rte_mbuf *m)
{
	return RTE_MBUF_DYNFIELD(m, dao_ct_field_offset, struct dao_ct_pkt_metadata *);
}

/*
 * Init function to allocate and initialize conntrack structure.
 *
 * @param ptr
 *   Double pointer to hold qsbr object on successful return.
 *
 * @return
 *   0 on success, and less than 0 on failure.
 */
int dao_conntrack_init(void **ptr);

/*
 * Uninitialize and free up the conntrack object.
 */
void dao_conntrack_fini(void);

/*
 * Process the packet for the connection tracking.
 *
 * @param pkt
 *   Packets to be processed for the connection tracking.
 *
 * @param num_pkts
 *   Number of packets to be processed.
 *
 * @param commit
 *   When set to true, connection is pushed to the memory.
 *
 * @return
 *   0 on success, and less than 0 on failure.
 */
int dao_conntrack_execute(struct rte_mbuf **pkts, uint16_t num_pkts, bool commit);

/*
 * Dump conntrack entries.
 */
void dao_conntrack_dump(void);

/*
 * Dump conntrack stats.
 */
void dao_conntrack_stats_dump(void);
#endif /* __DAO_CONNTRACK_H__ */
