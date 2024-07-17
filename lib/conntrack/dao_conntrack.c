/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "dao_conntrack.h"
#include "dao_conntrack_private.h"

#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_icmp.h>
#include <rte_malloc.h>
#include <rte_tcp.h>
#include <rte_lcore.h>
#include <rte_random.h>

extern struct ct_l4_proto dao_ct_proto_icmp4;
static struct ct_l4_proto *l4_protos[UINT8_MAX + 1];
int dao_ct_field_offset = -1;
struct dao_conntrack *ct;

static bool extract_l4(struct conn_key *key, const void *l4_data, bool *related);

#ifndef STAILQ_FOREACH_SAFE
#define STAILQ_FOREACH_SAFE(var, head, field, tvar)                                                \
	for ((var) = STAILQ_FIRST((head)); (var) && ((tvar) = STAILQ_NEXT((var), field), 1);       \
	     (var) = (tvar))
#endif

#define DAO_NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

static uint8_t l2_len_map[16] = {
	[RTE_PTYPE_UNKNOWN] = 0,
	[RTE_PTYPE_L2_ETHER] = 14,
	[RTE_PTYPE_L2_ETHER_VLAN] = 18,
	[RTE_PTYPE_L2_ETHER_QINQ] = 22,

};

/* XXX: TODO: implement per thread error counters. */
static rte_atomic64_t dao_ct_stats_l3_cksum_erros;
static rte_atomic64_t dao_ct_stats_l4_cksum_erros;
static rte_atomic64_t dao_ct_stats_ct_full;

static void
conn_key_reverse(struct conn_key *key)
{
	struct ctx_endpoint tmp = key->src;
	key->src = key->dst;
	key->dst = tmp;
}

static uint8_t
reverse_icmp_type(uint8_t type)
{
	switch (type) {
		case DAO_ICMP_ECHO_REQUEST:
			return RTE_ICMP_TYPE_ECHO_REPLY;
		case DAO_ICMP_ECHO_REPLY:
			return RTE_ICMP_TYPE_ECHO_REQUEST;
		case DAO_ICMP_TIMESTAMP:
			return DAO_ICMP_TIMESTAMPREPLY;
		case DAO_ICMP_TIMESTAMPREPLY:
			return DAO_ICMP_TIMESTAMP;
		case DAO_ICMP_INFOREQUEST:
			return DAO_ICMP_INFOREPLY;
		case DAO_ICMP_INFOREPLY:
			return DAO_ICMP_INFOREQUEST;

		default:
			return (uint8_t)~0;
	}
}

static long long int
conn_expiration(struct dao_conn *conn)
{
	long long int expiration;

	expiration = rte_atomic64_read(&conn->expiration);
	return expiration;
}

static bool
conn_expired(struct dao_conn *conn, long long now)
{
	return now >= conn_expiration(conn);
}

static bool
extract_l3_ipv4(struct conn_key *key, const void *l3_data)
{
	const struct rte_ipv4_hdr *ip = (const struct rte_ipv4_hdr *)l3_data;

	/* Note: Fragmented packets are not supported. */
	if (rte_ipv4_frag_pkt_is_fragmented(ip))
		return false;

	key->src.addr.ipv4_addr = ip->src_addr;
	key->dst.addr.ipv4_addr = ip->dst_addr;
	key->kdata.dl_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
	key->kdata.nw_proto = ip->next_proto_id;

	return true;
}

static bool
extract_l3_ipv6(struct conn_key *key, void *l3_data)
{
	struct rte_ipv6_hdr *ipv6 = (struct rte_ipv6_hdr *)l3_data;

	/* Note: Fragmented packets are not supported. */
	if (rte_ipv6_frag_get_ipv6_fragment_header(ipv6))
		return false;

	memcpy(key->src.addr.ipv6_addr, ipv6->src_addr.a, sizeof(ipv6->src_addr));
	memcpy(key->dst.addr.ipv6_addr, ipv6->dst_addr.a, sizeof(ipv6->dst_addr));
	key->kdata.dl_type = RTE_BE16(RTE_ETHER_TYPE_IPV6);
	key->kdata.nw_proto = ipv6->proto;

	return true;
}

static inline bool
extract_l4_tcp(struct conn_key *key, const void *l4_data)
{
	const struct rte_tcp_hdr *tcp = (const struct rte_tcp_hdr *)l4_data;
	key->src.port = RTE_BE16(tcp->src_port);
	key->dst.port = RTE_BE16(tcp->dst_port);

	/* Port 0 is invalid */
	return key->src.port && key->dst.port;
}

static inline int
extract_l4_icmp(struct conn_key *key, const void *l4_data, bool *related)
{
	const struct rte_icmp_hdr *icmp = (const struct rte_icmp_hdr *)l4_data;

	switch (icmp->icmp_type) {
		case DAO_ICMP_ECHO_REQUEST:
		case DAO_ICMP_ECHO_REPLY:
		case DAO_ICMP_TIMESTAMP:
		case DAO_ICMP_TIMESTAMPREPLY:
		case DAO_ICMP_INFOREQUEST:
		case DAO_ICMP_INFOREPLY:
			if (icmp->icmp_code != 0)
				return false;
			key->src.icmp_id = key->dst.icmp_id = icmp->icmp_ident;
			key->src.icmp_type = icmp->icmp_type;
			key->dst.icmp_type = reverse_icmp_type(icmp->icmp_type);
			break;
		case DAO_ICMP_DST_UNREACH:
		case DAO_ICMP_TIME_EXCEEDED:
		case DAO_ICMP_PARAM_PROB:
		case DAO_ICMP_SOURCEQUENCH:
		case DAO_ICMP_REDIRECT: {
			/* ICMP packet part of another connection. We should
			 * extract the key from embedded packet header */
			struct conn_key inner_key;
			const char *l3 = (const char *) (icmp + 1);
			const char *l4 = l3 + sizeof(struct rte_ipv4_hdr);

			if (!related) {
			        return false;
			}

			memset(&inner_key, 0, sizeof inner_key);
			inner_key.kdata.dl_type = htons(RTE_ETHER_TYPE_IPV4);
			bool ok = extract_l3_ipv4(&inner_key, l3);
			if (!ok) {
			        return false;
			}

			if (inner_key.src.addr.ipv4_addr != key->dst.addr.ipv4_addr)
			        return false;

			key->src = inner_key.src;
			key->dst = inner_key.dst;
			key->kdata.nw_proto = inner_key.kdata.nw_proto;

			ok = extract_l4(key, l4, NULL);
			if (ok) {
			        conn_key_reverse(key);
			        *related = true;
			}
			break;
		}
		default:
			return false;
	}

	return true;
}

static bool
extract_l4(struct conn_key *key, const void *l4_data, bool *related)
{
	if (key->kdata.nw_proto == IPPROTO_TCP) {
		return extract_l4_tcp(key, l4_data);
	} else if (key->kdata.dl_type == htons(RTE_ETHER_TYPE_IPV4) &&
		   key->kdata.nw_proto == IPPROTO_ICMP) {
		return extract_l4_icmp(key, l4_data, related);
	}

	/* Add protocol support here. Currently tcp and icmp are supported. */

	return true;
}

static bool
conn_key_extract(struct rte_mbuf *pkt, struct conn_lookup_ctx *ctx)
{
	uint16_t l3_offset = l2_len_map[pkt->packet_type & RTE_PTYPE_L2_MASK];
	uint8_t l3_ptype = (pkt->packet_type & 0xf0);
	struct conn_key *key = &ctx->key;
	uint16_t l4_offset = 0;
	bool rc = true;
	uint8_t *buf;

	memset(ctx, 0, sizeof(struct conn_lookup_ctx));

	buf = (uint8_t *)(rte_pktmbuf_mtod(pkt, char *) + l3_offset);
	key->kdata.dl_type = l3_ptype;

	if (l3_ptype == RTE_PTYPE_L3_IPV4 || l3_ptype == RTE_PTYPE_L3_IPV4_EXT) {
		if (pkt->ol_flags & RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD) {
			rte_atomic64_inc(&dao_ct_stats_l3_cksum_erros);
			rc = false;
			goto done;
		}

		const struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)buf;
		l4_offset = l3_offset + (ip->ihl * 4);
		if (!extract_l3_ipv4(key, buf)) {
			rc = false;
			goto done;
		}
	} else if (l3_ptype == RTE_PTYPE_L3_IPV6) {
		l4_offset = l3_offset + sizeof(struct rte_ipv6_hdr);
		if (!extract_l3_ipv6(key, buf)) {
			rc = false;
			goto done;
		}
	} else if (l3_ptype == RTE_PTYPE_L3_IPV6_EXT) {
		rc = false;
		goto done;
	}

	ctx->l4_offset = l4_offset;
	buf = (uint8_t *)(rte_pktmbuf_mtod(pkt, char *) + l4_offset);
	if (pkt->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_BAD) {
		rte_atomic64_inc(&dao_ct_stats_l4_cksum_erros);
		return false;
	}

	if (!extract_l4(key, buf, &ctx->icmp_related))
		rc = false;
done:
	return rc;
}

static int
insert_conn_node(struct dao_bucket_head *bucket, void *conn)
{
	struct dao_conn_node *node = rte_malloc(NULL, sizeof(struct dao_conn_node), 0);

	if (node == NULL)
		return -1;

	node->own_ptr = (uint64_t *)node;
	node->ptr = (uint64_t *)conn;

	rte_spinlock_lock(&bucket->block);
	STAILQ_INSERT_HEAD(&bucket->node_list, node, next);
	bucket->num_node++;
	rte_spinlock_unlock(&bucket->block);

	return 0;
};

static int
delete_conn_node(void)
{
	uint32_t num_bucket = NUM_CONN_BUCKETS;
	struct dao_conn_node *node;
	uint32_t i;
	void *tmp;

	for (i = 0 ; i < num_bucket; i++) {
		struct dao_bucket_head *bucket = &ct->blist[i];
		rte_spinlock_lock(&bucket->block);
		STAILQ_FOREACH_SAFE(node, &bucket->node_list, next, tmp)
		{
			STAILQ_REMOVE(&bucket->node_list, node, dao_conn_node, next);
			rte_free(node->ptr);
			rte_free(node);
			bucket->num_node--;
		}
		rte_spinlock_unlock(&bucket->block);
	}

	return 0;
}

static struct dao_conn *
conn_blist_node_lookup(const struct conn_key *key, int bid, uint64_t now, bool *reply)
{
	struct dao_bucket_head *bucket;
	struct dao_conn *conn = NULL;
	struct dao_conn_node *node;
	bool conn_found = false;
	void *tmp;
	int j;

	bucket = &ct->blist[bid];

	rte_spinlock_lock(&bucket->block);
	STAILQ_FOREACH_SAFE(node, &bucket->node_list, next, tmp)
	{
		conn = (struct dao_conn *)node->ptr;
		rte_spinlock_lock(&conn->clock);
		for (j = 0; j < CONN_DIRS; j++) {
			if (memcmp(&conn->conn_key[j], key, sizeof(struct conn_key)) == 0) {
				if (conn_expired(conn, now)) {
					/* Connection has timedout. Cleanup thread will remove. */
					if (j == (CONN_DIRS - 1)) {
						rte_spinlock_unlock(&conn->clock);
						rte_spinlock_unlock(&bucket->block);
						return NULL;
					}
					continue;
				}

				if (reply)
					*reply = (j == CONN_DIR_REV);

				conn_found = true;
				break;
			}
		}
		rte_spinlock_unlock(&conn->clock);

		if (conn_found == true)
			break;
	}
	rte_spinlock_unlock(&bucket->block);

	/* blist lookup is called after successful hash lookup. If the connection node is not
	 * present in the blist means there is a memory corruption.
	 */
	if (conn_found == false)
		rte_panic("Matching connection node not found!");

	return conn;
}

static uint32_t
conn_endpoint_hash_add(uint32_t hash, const struct ctx_endpoint *ep)
{
	return hash_add_bytes32(hash, (const uint32_t *) ep, sizeof *ep);
}

static uint32_t
conn_key_hash(struct conn_key *key, uint32_t hbasis)
{
	uint32_t hsrc, hdst;
	hsrc = hdst = hbasis;
	hsrc = conn_endpoint_hash_add(hsrc, &key->src);
	hdst = conn_endpoint_hash_add(hdst, &key->dst);

	/* Even if source and destination are swapped the hash will be the same. */
	key->kdata.ep_hash = hsrc ^ hdst;

	return 0;
}

static bool
conn_hash_lookup(struct conn_key *key, int *bid)
{
	conn_key_hash(key, ct->hbasis);

	*bid = rte_hash_lookup(ct->hash, &key->kdata);
	if (*bid < 0 || *bid >= MAX_CONN_ENTRIES)
		return false;

	return true;
}

static struct dao_conn *
conn_create(struct rte_mbuf *pkt, struct conn_lookup_ctx *ctx, bool commit,
	    struct dao_ct_pkt_metadata *mdata, uint64_t now)
{
	struct conn_key *fwd_key, *rev_key;
	struct dao_conn *conn = NULL;
	int bid;
	bool rc;

	rc = l4_protos[ctx->key.kdata.nw_proto]->valid_new(ctx, pkt);
	if (rc == false) {
		mdata->ct_state = DAO_CONN_STATE_FLAG(DAO_CONN_STATE_INVALID);
		return NULL;
	}

	mdata->ct_state = DAO_CONN_STATE_FLAG(DAO_CONN_STATE_NEW);

	if (commit) {
		if ((uint64_t)rte_atomic64_read(&ct->num_conn) > ct->max_num_conn) {
			rte_atomic64_inc(&dao_ct_stats_ct_full);
			return NULL;
		}
		conn = l4_protos[ctx->key.kdata.nw_proto]->new_conn(ct, ctx, pkt, now);

		fwd_key = &conn->conn_key[CONN_DIR_FWD];
		rev_key = &conn->conn_key[CONN_DIR_REV];
		memcpy(fwd_key, &ctx->key, sizeof(struct conn_key));
		conn_key_hash(fwd_key, ct->hbasis);
		memcpy(rev_key, &ctx->key, sizeof(struct conn_key));
		conn_key_reverse(rev_key);
		conn_key_hash(rev_key, ct->hbasis);

		if (fwd_key->kdata.ep_hash != rev_key->kdata.ep_hash) {
			/* Not expected: MurMur hash is different. */
			dao_err("ERROR: fwd and rev hash not matched.");
			rte_free(conn);
			return NULL;
		}

		conn->l4_offset = ctx->l4_offset;
		bid = rte_hash_add_key(ct->hash, &fwd_key->kdata);
		if (bid < 0) {
			dao_err("ERROR: Adding forward key to the hash failed.");
			rte_free(conn);
			return NULL;
		}

		bid = bid & (NUM_CONN_BUCKETS - 1);
		insert_conn_node(&ct->blist[bid], (void *)conn);
		rte_atomic64_inc(&ct->num_conn);
	}

	return conn;
}

static enum conn_update_res
conn_update(struct dao_conn *conn, struct rte_mbuf *pkt, struct conn_lookup_ctx *ctx, uint64_t now)
{
	enum conn_update_res update_res;
	uint8_t nw_proto;

	rte_spinlock_lock(&conn->clock);
	nw_proto = conn->conn_key[CONN_DIR_FWD].kdata.nw_proto;
	update_res = l4_protos[nw_proto]->conn_update(ct, conn, pkt, ctx->reply, now);
	rte_spinlock_unlock(&conn->clock);

	return update_res;
}

static bool
conn_update_state(struct rte_mbuf *pkt, struct conn_lookup_ctx *ctx, struct dao_conn *conn,
		  struct dao_ct_pkt_metadata *mdata, uint64_t now)
{
	bool create_new_conn = false;
	enum conn_update_res res;

	if (ctx->icmp_related) {
		mdata->ct_state |= DAO_CONN_STATE_FLAG(DAO_CONN_STATE_RELATED);
		if (ctx->reply)
			mdata->ct_state |= DAO_CONN_STATE_FLAG(DAO_CONN_STATE_REPLY_DIR);
	} else {
		res = conn_update(conn, pkt, ctx, now);

		switch (res) {
			case CONN_UPDATE_VALID:
				mdata->ct_state |= DAO_CONN_STATE_FLAG(DAO_CONN_STATE_ESTABLISHED);
				mdata->ct_state &= ~DAO_CONN_STATE_FLAG(DAO_CONN_STATE_NEW);
				if (ctx->reply)
					mdata->ct_state |=
						DAO_CONN_STATE_FLAG(DAO_CONN_STATE_REPLY_DIR);
				break;
			case CONN_UPDATE_INVALID:
				mdata->ct_state = DAO_CONN_STATE_FLAG(DAO_CONN_STATE_INVALID);
				break;
			case CONN_UPDATE_NEW:
				int bid;
				if (conn_hash_lookup(&conn->conn_key[CONN_DIR_FWD], &bid))
					conn_force_expire(conn, now);
				create_new_conn = true;
				break;
			case CONN_UPDATE_VALID_NEW:
				mdata->ct_state |= DAO_CONN_STATE_FLAG(DAO_CONN_STATE_NEW);
				break;
			default:
				rte_panic("Invalid response from the protocol processing."
					  "res: %d\n", res);
		}
	}
	return create_new_conn;
}

static int
conn_process_pkt(struct rte_mbuf *mbuf, struct conn_lookup_ctx *ctx, bool commit,
		 struct dao_ct_pkt_metadata *mdata, uint64_t now)
{
	struct dao_conn *conn = NULL;
	bool create_new_conn = true;
	int bid;

	if (conn_hash_lookup(&ctx->key, &bid)) {
		conn = conn_blist_node_lookup(&ctx->key, bid, now, &ctx->reply);
		/* conn can be NULL in 2 cases:
		 * 1) connection node not present in the blist,
		 * 2) connection has timed out.
		 *
		 * In case of #1, there is a probability of memory corruption and
		 * conn_blist_node_lookup calls rte_panic(). In case of #2, connection timeout has
		 * occured and timer thread will cleanup the entry.
		 */
		if (conn == NULL)
			return -1;

		create_new_conn = conn_update_state(mbuf, ctx, conn, mdata, now);
	}

	if (!conn && ctx->icmp_related)
		return -1;

	if (create_new_conn) {
		conn = conn_create(mbuf, ctx, commit, mdata, now);
		if (conn == NULL)
			return -1;
	}

	return 0;
}

int
dao_conntrack_execute(struct rte_mbuf **pkts, uint16_t num_pkts, bool commit)
{
	struct dao_ct_pkt_metadata *mdata;
	struct conn_lookup_ctx ctx;
	struct rte_mbuf *mbuf;
	struct dao_conn *conn;
	uint64_t now;
	int i;

	now = rte_get_timer_cycles();
	for (i = 0; i < num_pkts; i++) {
		mbuf = pkts[i];
		mdata = dao_ct_pkt_metadata(mbuf);
		conn = (struct dao_conn *)mdata->ct_data_ptr;
		if (mdata->ct_state == DAO_CONN_STATE_FLAG(DAO_CONN_STATE_INVALID)) {
			mdata->ct_state |= DAO_CONN_STATE_FLAG(DAO_CONN_STATE_TRACKED);
		} else if (conn) {
			/* For future when NAT and zone support is implemented. */
		} else if (conn_key_extract(mbuf, &ctx) != true) {
			continue;
		} else {
			if (conn_process_pkt(mbuf, &ctx, commit, mdata, now) < 0) {
				mdata->ct_state = DAO_CONN_STATE_FLAG(DAO_CONN_STATE_INVALID);
				mdata->ct_state |= DAO_CONN_STATE_FLAG(DAO_CONN_STATE_TRACKED);
			}
		}
	}

	return 0;
}

static void
conn_node_freeup(void *p, void *data, unsigned int n)
{
	struct dao_conn_node *node = (struct dao_conn_node *)data;
	struct dao_conn *conn = (struct dao_conn *)node->ptr;

	RTE_SET_USED(p);
	RTE_SET_USED(n);

	/* own_ptr is needed as the address received in data is the local address from the differed
	 * queue.
	 */
	node = (struct dao_conn_node *)node->own_ptr;

	rte_free(conn);
	rte_free(node);
}

static int
conn_remove(struct dao_conn *conn, struct dao_bucket_head *bucket, struct dao_conn_node *node)
{
	int bid, ret;

	bid = rte_hash_del_key(ct->hash, &conn->conn_key[CONN_DIR_FWD].kdata);
	if (bid < 0)
		rte_panic("Hash del key failed. kdata: %x ret: %d \n",
				conn->conn_key[CONN_DIR_FWD].kdata.ep_hash, bid);

	STAILQ_REMOVE(&bucket->node_list, node, dao_conn_node, next);
	ret = rte_rcu_qsbr_dq_enqueue(ct->dq, node);
	if (ret != 0)
		dao_err("qsbr dq_enqueue failed. Ret: %d", ret);

	bucket->num_node--;
	rte_atomic64_dec(&ct->num_conn);

	return 0;
}

static int
conn_cleanup(void)
{
	uint32_t num_bucket = NUM_CONN_BUCKETS;
	struct dao_bucket_head *bucket;
	struct dao_conn_node *node;
	struct dao_conn *conn;
	unsigned int i;
	uint64_t now;
	void *tmp;

	now = rte_get_timer_cycles();
	for (i = 0; i < num_bucket; i++) {
		bucket = &ct->blist[i];
		rte_spinlock_lock(&bucket->block);
		STAILQ_FOREACH_SAFE(node, &bucket->node_list, next, tmp)
		{
			conn = (struct dao_conn *)node->ptr;
			if (conn_expired(conn, now))
				conn_remove(conn, bucket, node);
		}
		rte_spinlock_unlock(&bucket->block);
	}

	return 0;
}

static uint32_t
conn_cleanup_thread(void *arg)
{
	uint64_t prev_tsc = 0, cur_tsc, diff_tsc;
	uint64_t cleanup_interval_cycles;
	uint64_t hz;

	RTE_SET_USED(arg);

	hz = rte_get_timer_hz();
	cleanup_interval_cycles = hz * 200 / 1000; /* around 200ms */

	while (ct->thread_exit == false) {
		cur_tsc = rte_get_timer_cycles();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > cleanup_interval_cycles) {
			conn_cleanup();
			prev_tsc = cur_tsc;
		}
	}

	return 0;
}

static struct rte_hash *
conn_hash_init(void)
{
	struct rte_hash_parameters hp;
	struct rte_hash *hash;
	struct conn_key ckey;

	memset(&hp, 0, sizeof(struct rte_hash_parameters));
	hp.hash_func = rte_hash_crc;
	hp.name = "dao_conntrack_conns";
	hp.entries = MAX_CONN_ENTRIES + 1;
	hp.key_len = sizeof(ckey.kdata);
	hp.hash_func_init_val = 0;
	hp.socket_id = SOCKET_ID_ANY;
	hp.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF | RTE_HASH_EXTRA_FLAGS_EXT_TABLE;
	hash = rte_hash_create(&hp);
	if (hash == NULL) {
		dao_err("Conntrack hash create failed.");
		return NULL;
	}

	return hash;
}

static struct rte_rcu_qsbr *
conn_qsbr_obj_init(void)
{
	struct rte_rcu_qsbr *qsbr_obj;
	size_t sz;

	sz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
	qsbr_obj = (struct rte_rcu_qsbr *)rte_zmalloc("conn_qsbr", sz, RTE_CACHE_LINE_SIZE);
	if (qsbr_obj == NULL) {
		dao_err("qsbr object create failed.");
		return NULL;
	}

	if (rte_rcu_qsbr_init(qsbr_obj, RTE_MAX_LCORE)) {
		dao_err("qsbr init failed.");
		return NULL;
	}

	return qsbr_obj;
}

static struct dao_bucket_head *
conn_bucket_list_init(void)
{
	struct dao_bucket_head *blist;
	int i;

	blist = (struct dao_bucket_head *)rte_zmalloc("conn_bucket",
			  (sizeof(struct dao_bucket_head) * NUM_CONN_BUCKETS), RTE_CACHE_LINE_SIZE);
	if (blist == NULL) {
		dao_err("Bucket head create failed.");
		return NULL;
	}

	/* Initailise single linked-list head */
	for (i = 0; i < NUM_CONN_BUCKETS; i++)
		STAILQ_INIT(&blist[i].node_list);

	return blist;
}

static struct rte_rcu_qsbr_dq *
conn_qsbr_dq_init(struct rte_rcu_qsbr *qsbr_obj)
{
	struct rte_rcu_qsbr_dq_parameters params;
	struct rte_rcu_qsbr_dq *dq;

	memset(&params, 0, sizeof(struct rte_rcu_qsbr_dq_parameters));
	params.name = "conn_diff_queue";
	params.flags = 0;
	params.free_fn = conn_node_freeup;
	params.v = qsbr_obj;
	params.size = MAX_CONN_ENTRIES + 1;
	params.esize = sizeof(struct dao_conn_node);
	params.trigger_reclaim_limit = 0;
	params.max_reclaim_size = params.size;
	dq = rte_rcu_qsbr_dq_create(&params);
	if (dq == NULL) {
		dao_err("qsbr differed queue create failed.");
		return NULL;
	}

	return dq;
}

int
dao_conntrack_init(void **qsbr_obj)
{
	struct rte_hash_rcu_config rcu_cfg = {0};

	if (qsbr_obj == NULL) {
		dao_err("Function argument passed is NULL");
		return -1;
	}

	if (ct) {
		dao_info("Conntrack object already initialized.");
		*qsbr_obj = (void *)ct->qsbr_obj;
		return 0;
	}

	ct = rte_zmalloc("dao_conntrack_ctx", sizeof(struct dao_conntrack), RTE_CACHE_LINE_SIZE);
	if (ct == NULL) {
		dao_err("Conntrack object alloc failed");
		goto error;
	}

	memset(ct, 0, sizeof(struct dao_conntrack));
	ct->max_num_conn = MAX_CONN_ENTRIES;
	rte_atomic64_init(&ct->num_conn);
	ct->hbasis = rte_rand();

	ct->hash = conn_hash_init();
	if (ct->hash == NULL)
		goto error;

	/* Allocate qsbr object. */
	ct->qsbr_obj = conn_qsbr_obj_init();
	if (ct->qsbr_obj == NULL)
		goto error;

	rcu_cfg.v = ct->qsbr_obj;
	rcu_cfg.mode = RTE_HASH_QSBR_MODE_DQ;
	if (rte_hash_rcu_qsbr_add(ct->hash, &rcu_cfg)) {
		dao_err("qsbr hash add failed.");
		goto error;
	}

	ct->blist = conn_bucket_list_init();
	if (ct->blist == NULL)
		goto error;

	/* Differed queue for the linked-list node. */
	ct->dq = conn_qsbr_dq_init(ct->qsbr_obj);
	if (ct->dq == NULL)
		goto error;

	ct->thread_exit = false;
	if (rte_thread_create_internal_control(&ct->cleanup_thread, "conn_cleanup_thread",
					       conn_cleanup_thread, NULL)) {
		dao_err("conntrack cleanup thread create error.");
		goto error;
	}

	/* mbuf dynamic field register. */
	dao_ct_field_offset = rte_mbuf_dynfield_register(&dao_ct_field);
	if (dao_ct_field_offset < 0) {
		dao_err("mbuf dynamic field register failed.");
		goto error;
	}

	/* Register l4 protocols. */
	l4_protos[IPPROTO_ICMP] = &dao_ct_proto_icmp4;

	/* All done. Populate qsbr object now. */
	*qsbr_obj = (void *)ct->qsbr_obj;

	return 0;

error:
	if (ct->dq)
		rte_rcu_qsbr_dq_delete(ct->dq);
	if (ct->blist)
		rte_free(ct->blist);
	if (ct->qsbr_obj)
		rte_free(ct->qsbr_obj);
	if (ct->hash)
		rte_hash_free(ct->hash);
	if (ct)
		rte_free(ct);

	return -1;
}

void
dao_conntrack_fini(void)
{
	if (ct == NULL)
		return;

	ct->thread_exit = true;
	rte_thread_join(ct->cleanup_thread, NULL);

	delete_conn_node();

	if (ct->dq)
		rte_rcu_qsbr_dq_delete(ct->dq);
	if (ct->blist)
		rte_free(ct->blist);
	if (ct->qsbr_obj)
		rte_free(ct->qsbr_obj);
	if (ct->hash)
		rte_hash_free(ct->hash);
	if (ct)
		rte_free(ct);
}

void
dao_conntrack_dump(void)
{
	uint32_t num_bucket = NUM_CONN_BUCKETS;
	struct dao_conn_node *node;
	struct dao_conn *conn;
	uint64_t now, hz;
	float to_val;
	uint32_t i;
	void *tmp;

	now = rte_get_timer_cycles();
	hz = rte_get_timer_hz();
	for (i = 0 ; i < num_bucket; i++) {
		struct dao_bucket_head *bucket = &ct->blist[i];
		rte_spinlock_lock(&bucket->block);
		STAILQ_FOREACH_SAFE(node, &bucket->node_list, next, tmp)
		{
			conn = (struct dao_conn *)node->ptr;
			rte_spinlock_lock(&conn->clock);
			to_val = conn_expiration(conn);
			to_val = (to_val - now) / hz;
			dao_print("Expiration: %f [ORIG] saddr: %d.%d.%d.%d sport: %d "
				  "daddr: %d.%d.%d.%d dport: %d "
				  "[REV] saddr: %d.%d.%d.%d sport: %d daddr: %d.%d.%d.%d dport: %d "
				  "proto: %d\n", to_val,
				  DAO_NIPQUAD(conn->conn_key[CONN_DIR_FWD].src.addr.ipv4_addr),
				  conn->conn_key[CONN_DIR_FWD].src.port,
				  DAO_NIPQUAD(conn->conn_key[CONN_DIR_FWD].dst.addr.ipv4_addr),
				  conn->conn_key[CONN_DIR_FWD].dst.port,
				  DAO_NIPQUAD(conn->conn_key[CONN_DIR_REV].src.addr.ipv4_addr),
				  conn->conn_key[CONN_DIR_REV].src.port,
				  DAO_NIPQUAD(conn->conn_key[CONN_DIR_REV].dst.addr.ipv4_addr),
				  conn->conn_key[CONN_DIR_REV].dst.port,
				  conn->conn_key[CONN_DIR_FWD].kdata.nw_proto);
			rte_spinlock_unlock(&conn->clock);
		}
		rte_spinlock_unlock(&bucket->block);
	}
}
