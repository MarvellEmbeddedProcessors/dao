/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "dao_conntrack.h"
#include "dao_conntrack_private.h"

#include <rte_icmp.h>
#include <rte_malloc.h>

enum icmp_state {
	ICMP_FIRST,
	ICMP_REPLY,
};

struct conn_icmp {
	struct dao_conn up;
	enum icmp_state state; /* 'conn' lock protected. */
};

static const enum conn_timeout icmp_timeouts[] = {
	[ICMP_FIRST] = CONN_TO_ICMP_FIRST,
	[ICMP_REPLY] = CONN_TO_ICMP_REPLY,
};

static struct conn_icmp *
conn_icmp_cast(struct dao_conn *conn)
{
	return container_of(conn, struct conn_icmp, up);
}

static enum conn_update_res
icmp_conn_update(struct dao_conntrack *ct, struct dao_conn *conn_, struct rte_mbuf *pkt, bool reply,
		 uint64_t now)
{
	struct conn_icmp *conn = conn_icmp_cast(conn_);
	enum conn_update_res ret = CONN_UPDATE_VALID;

	RTE_SET_USED(ct);
	RTE_SET_USED(pkt);
	RTE_SET_USED(now);

	if (reply && conn->state == ICMP_FIRST) {
		conn->state = ICMP_REPLY;
	} else if (conn->state == ICMP_FIRST) {
		ret = CONN_UPDATE_VALID_NEW;
	}

	conn_ex_timer_update(&conn->up, icmp_timeouts[conn->state], now);
	return ret;
}

static bool
icmp_valid_new(struct conn_lookup_ctx *ctx, struct rte_mbuf *pkt)
{
	struct rte_icmp_hdr *icmp =
		(struct rte_icmp_hdr *)(rte_pktmbuf_mtod(pkt, char *) + ctx->l4_offset);

	return icmp->icmp_type == DAO_ICMP_ECHO_REQUEST ||
	       icmp->icmp_type == DAO_ICMP_INFOREQUEST || icmp->icmp_type == DAO_ICMP_TIMESTAMP;
}

static struct dao_conn *
icmp_new_conn(struct dao_conntrack *ct, struct conn_lookup_ctx *ctx, struct rte_mbuf *pkt,
	      uint64_t now)
{
	struct conn_icmp *new_conn;

	new_conn = (struct conn_icmp *)rte_zmalloc("icmp_ct_conn", sizeof(struct conn_icmp),
						   RTE_CACHE_LINE_SIZE);
	new_conn->state = ICMP_FIRST;

	RTE_SET_USED(ct);
	RTE_SET_USED(ctx);
	RTE_SET_USED(pkt);
	RTE_SET_USED(now);

	conn_ex_timer_update(&new_conn->up, icmp_timeouts[new_conn->state], now);
	return &new_conn->up;
}

struct ct_l4_proto dao_ct_proto_icmp4 = {
	.new_conn = icmp_new_conn,
	.valid_new = icmp_valid_new,
	.conn_update = icmp_conn_update,
};
