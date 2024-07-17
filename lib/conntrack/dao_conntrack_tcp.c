/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "dao_conntrack_tcp.h"

#include <rte_malloc.h>

#define DAO_DIV_ROUND_UP(n, d) (((n) + ((d) - 1)) / (d))

enum tcp_state {
	SYN_SENT,
	SYN_RECV,
	ESTABLISHED,
	FIN_WAIT,
	TIME_WAIT,
	CLOSE,
};

static const enum conn_timeout tcp_timeouts[] = {
	[SYN_SENT] = CONN_TO_TCP_SYN_SENT,
	[SYN_RECV] = CONN_TO_TCP_SYN_RECV,
	[ESTABLISHED] = CONN_TO_TCP_ESTABLISHED,
	[FIN_WAIT] = CONN_TO_TCP_FIN_WAIT,
	[TIME_WAIT] = CONN_TO_TCP_TIME_WAIT,
	[CLOSE] = CONN_TO_TCP_CLOSE,
};

static struct dao_conn_tcp*
conn_tcp_cast(struct dao_conn* conn)
{
	return container_of(conn, struct dao_conn_tcp, up);
}

static int
dao_get_tcp_payload_length(struct rte_mbuf *pkt, struct rte_tcp_hdr *tcp, uint8_t l4_offset)
{
	uint16_t data_len = rte_pktmbuf_data_len(pkt);
	return (data_len - l4_offset - (tcp->data_off * 4));
}

static bool
tcp_invalid_flags(uint8_t flags)
{

	if (flags & RTE_TCP_SYN_FLAG) {
		if (flags & RTE_TCP_RST_FLAG || flags & RTE_TCP_FIN_FLAG)
			return true;
	} else {
		if (!(flags & (RTE_TCP_ACK_FLAG | RTE_TCP_RST_FLAG)))
			return true;
	}

	if (!(flags & RTE_TCP_ACK_FLAG)) {
		if ((flags & RTE_TCP_FIN_FLAG) || (flags & RTE_TCP_PSH_FLAG) ||
		    (flags & RTE_TCP_URG_FLAG))
			return true;
	}

	return false;
}

static void
dao_get_tcp_opt(const struct rte_tcp_hdr *tcp, struct dao_conn_tcp_peer *state)
{
	int len = ((tcp->data_off * 4) - sizeof(*tcp));
	const uint8_t *opt = (const uint8_t *)(tcp + 1);
	uint8_t optlen;

	while (len >= 3) {
		switch (*opt) {
		case DAO_CONN_TCPOPT_EOL:
			return;
		case DAO_CONN_TCPOPT_NOP:
			opt++;
			len--;
			continue;
		case DAO_CONN_TCPOPT_WINDOW:
			state->wscale = RTE_MIN(opt[2], DAO_CONN_TCP_MAX_WSCALE);
			state->opt |= DAO_CONN_TCPOPT_FLAG(WSCALE_FLAG);
			break;
		case DAO_CONN_TCPOPT_SACK:
			state->opt |= DAO_CONN_TCPOPT_FLAG(SACK_FLAG);
			break;
		default:
		}

		optlen = opt[1];
		if (optlen < 2) {
			optlen = 2;
		}
		len -= optlen;
		opt += optlen;
	}

	return;
}

static enum conn_update_res
dao_tcp_conn_update(struct dao_conntrack *ct, struct dao_conn *conn, struct rte_mbuf *pkt,
		    bool reply, uint64_t now)
{
	struct rte_tcp_hdr *tcp =
		(struct rte_tcp_hdr *)(rte_pktmbuf_mtod(pkt, char *) + conn->l4_offset);
	struct dao_conn_tcp *conn_tcp = conn_tcp_cast(conn);
	struct dao_conn_tcp_peer *src = &conn_tcp->peer[reply ? 1 : 0];
	struct dao_conn_tcp_peer *dst = &conn_tcp->peer[reply ? 0 : 1];
	uint16_t win = rte_be_to_cpu_16(tcp->rx_win);
	uint32_t ack, end, seq, orig_seq;
	uint8_t sws = 0, dws = 0;
	uint16_t tcp_flags;
	uint32_t plen;

	RTE_SET_USED(ct);

	plen = dao_get_tcp_payload_length(pkt, tcp, conn->l4_offset);

	tcp_flags = tcp->tcp_flags;
	if (tcp_invalid_flags(tcp_flags))
		return CONN_UPDATE_INVALID;

	if ((tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG)) == RTE_TCP_SYN_FLAG) {
		if (dst->state >= DAO_CONN_TCP_FIN_WAIT_2
				&& src->state >= DAO_CONN_TCP_FIN_WAIT_2) {
			src->state = dst->state = DAO_CONN_TCP_CLOSED;
			return CONN_UPDATE_NEW;
		} else if (src->state <= DAO_CONN_TCP_SYN_SENT) {
			/* XXX: Will new scaling factor and window size be sent as
			 * part of SYN for renewed connection ?
			 */
			src->state = DAO_CONN_TCP_SYN_SENT;
			conn_ex_timer_update(&conn_tcp->up, tcp_timeouts[SYN_SENT], now);
			return CONN_UPDATE_VALID_NEW;
		}
	}

	/* RFC 1323:
	 * Both sides must send the Window Scale option
	 * to enable window scaling in either direction.
	 */
	if (src->opt & DAO_CONN_TCPOPT_FLAG(WSCALE_FLAG) &&
	    dst->opt & DAO_CONN_TCPOPT_FLAG(WSCALE_FLAG) && !(tcp_flags & RTE_TCP_SYN_FLAG)) {
		sws = src->wscale;
		dws = dst->wscale;
	} else if (src->opt & DAO_CONN_TCPOPT_FLAG(WSCALE_UNKNOWN) &&
		   dst->opt & DAO_CONN_TCPOPT_FLAG(WSCALE_UNKNOWN) &&
		   !(tcp_flags & RTE_TCP_SYN_FLAG)) {
		/* If nither peer have window scaling option unset, then set it to
		 * default max.
		 */
		sws = DAO_CONN_TCP_MAX_WSCALE;
		dws = DAO_CONN_TCP_MAX_WSCALE;
	}

	/*
	 * Sequence tracking algorithm from Guido van Rooij's paper:
	 *   http://www.madison-gurkha.com/publications/tcp_filtering/
	 *      tcp_filtering.ps
	 */

	orig_seq = seq = rte_be_to_cpu_32(tcp->sent_seq);
	bool check_ackskew = true;
	if (src->state < DAO_CONN_TCP_SYN_SENT) {
		/* First packet from this end. Set its state */
		ack = rte_be_to_cpu_32(tcp->recv_ack);
		end = seq + plen;
		if (tcp_flags & RTE_TCP_SYN_FLAG) {
			end++;
			if (dst->wscale & DAO_CONN_TCPOPT_FLAG(WSCALE_FLAG)) {
				dao_get_tcp_opt(tcp, src);
				if (src->wscale & DAO_CONN_TCPOPT_FLAG(WSCALE_FLAG)) {
					/* Remove scale factor from initial window */
					sws = src->wscale;
					win = DAO_DIV_ROUND_UP((uint32_t) win, 1 << sws);
					dws = dst->wscale;
				} else {
					/* RFC 1323:
					 * Both sides must send the Window Scale option
					 * to enable window scaling in either direction.
					 */
					src->wscale = 0;
					dst->wscale = 0;
					dst->opt &= ~DAO_CONN_TCPOPT_FLAG(WSCALE_FLAG);
				}
			}
		}

		if (tcp_flags & RTE_TCP_FIN_FLAG)
			end++;

		src->seqcur = seq;
		src->state = DAO_CONN_TCP_SYN_SENT;

		if (src->seqnxt == 1 ||
		    ((end + RTE_MAX(1, dst->maxwin << dws)) >= src->seqnxt)) {
			src->seqnxt = end + RTE_MAX(1, dst->maxwin << dws);
			/* We are either picking up a new connection or a connection which
			 * was already in place.  We are more permissive in terms of
			 * ackskew checking in these cases.
			 */
			check_ackskew = false;
		}

		if (win > src->maxwin)
			src->maxwin = win;
	} else {
		ack = rte_be_to_cpu_32(tcp->recv_ack);
		end = seq + plen;
		if (tcp_flags & RTE_TCP_SYN_FLAG)
			end++;

		if (tcp_flags & RTE_TCP_FIN_FLAG)
			end++;
	}

	if ((tcp_flags & RTE_TCP_ACK_FLAG) == 0)
		ack = dst->seqcur;
	else if ((ack == 0 && (tcp_flags & (RTE_TCP_ACK_FLAG | RTE_TCP_RST_FLAG)) ==
		 (RTE_TCP_ACK_FLAG | RTE_TCP_RST_FLAG)))
		ack = dst->seqcur;

	int ackskew = check_ackskew ? dst->seqcur - ack : 0;
#define MAXACKWINDOW (0xffff + 1500)    /* 1500 is an arbitrary fudge factor */

	if ((DAO_SEQ_GEQ(src->seqnxt, end)
		/* Last octet inside other's window space */
		&& DAO_SEQ_GEQ(seq, src->seqcur - (dst->maxwin << dws))
		/* Retrans: not more than one window back */
		&& (ackskew >= -MAXACKWINDOW)
		/* Acking not more than one reassembled fragment backwards */
		&& (ackskew <= (MAXACKWINDOW << sws))
		/* Acking not more than one window forward */
		&& ((tcp_flags & RTE_TCP_RST_FLAG) == 0 || orig_seq == src->seqcur
			|| (orig_seq == src->seqcur + 1) || (orig_seq + 1 == src->seqcur)))){
		/* Require an exact/+1 sequence match on resets when possible */

		/* update max window */
		if (src->maxwin < win)
			src->maxwin = win;

		/* synchronize sequencing */
		if (DAO_SEQ_GT(end, src->seqcur))
			src->seqcur = end;

		/* slide the window of what the other end can send */
		if (DAO_SEQ_GEQ(ack + (win << sws), dst->seqnxt))
			dst->seqnxt = ack + RTE_MAX((win << sws), 1);

		/* update states */
		if (tcp_flags & RTE_TCP_SYN_FLAG && src->state < DAO_CONN_TCP_SYN_SENT)
			src->state = DAO_CONN_TCP_SYN_SENT;

		if (tcp_flags & RTE_TCP_FIN_FLAG && src->state < DAO_CONN_TCP_CLOSING)
			src->state = DAO_CONN_TCP_CLOSING;

		if (tcp_flags & RTE_TCP_ACK_FLAG) {
			if (dst->state == DAO_CONN_TCP_SYN_SENT)
				dst->state = DAO_CONN_TCP_ESTABLISHED;
			else if (dst->state == DAO_CONN_TCP_CLOSING)
				dst->state = DAO_CONN_TCP_FIN_WAIT_2;
		}

		if (tcp_flags & RTE_TCP_RST_FLAG)
			src->state = dst->state = DAO_CONN_TCP_TIME_WAIT;

		if (src->state >= DAO_CONN_TCP_FIN_WAIT_2 && dst->state >= DAO_CONN_TCP_FIN_WAIT_2)
			conn_ex_timer_update(&conn_tcp->up, tcp_timeouts[CLOSE], now);
		else if (src->state >= DAO_CONN_TCP_CLOSING && dst->state >= DAO_CONN_TCP_CLOSING)
			conn_ex_timer_update(&conn_tcp->up, tcp_timeouts[FIN_WAIT], now);
		else if (src->state < DAO_CONN_TCP_ESTABLISHED ||
			 dst->state < DAO_CONN_TCP_ESTABLISHED)
			conn_ex_timer_update(&conn_tcp->up, tcp_timeouts[SYN_RECV], now);
		else if (src->state >= DAO_CONN_TCP_CLOSING || dst->state >= DAO_CONN_TCP_CLOSING)
			conn_ex_timer_update(&conn_tcp->up, tcp_timeouts[CLOSE], now);
		else
			conn_ex_timer_update(&conn_tcp->up, tcp_timeouts[ESTABLISHED], now);
	} else if ((dst->state < DAO_CONN_TCP_SYN_SENT || dst->state >= DAO_CONN_TCP_FIN_WAIT_2 ||
		    src->state >= DAO_CONN_TCP_FIN_WAIT_2) &&
		    DAO_SEQ_GEQ(src->seqnxt + MAXACKWINDOW, end) &&
		    /* Within a window forward of the originating packet */
		    DAO_SEQ_GEQ(seq, src->seqcur - MAXACKWINDOW)) {
		    /* Within a window backward of the originating packet */

		/*
		 * This currently handles three situations:
		 *  1) Stupid stacks will shotgun SYNs before their peer
		 *     replies.
		 *  2) When PF catches an already established stream (the
		 *     firewall rebooted, the state table was flushed, routes
		 *     changed...)
		 *  3) Packets get funky immediately after the connection
		 *     closes (this should catch Solaris spurious ACK|FINs
		 *     that web servers like to spew after a close)
		 *
		 * This must be a little more careful than the above code
		 * since packet floods will also be caught here. We don't
		 * update the TTL here to mitigate the damage of a packet
		 * flood and so the same code can handle awkward establishment
		 * and a loosened connection close.
		 * In the establishment case, a correct peer response will
		 * validate the connection, go through the normal state code
		 * and keep updating the state TTL.
		 */

		/* update max window */
		if (src->maxwin < win)
			src->maxwin = win;

		/* synchronize sequencing */
		if (DAO_SEQ_GT(end, src->seqcur))
			src->seqcur = end;

		/* slide the window of what the other end can send */
		if (DAO_SEQ_GEQ(ack + (win << sws), dst->seqnxt))
			dst->seqnxt = ack + RTE_MAX((win << sws), 1);

		/*
		 * Cannot set dst->seqhi here since this could be a shotgunned
		 * SYN and not an already established connection.
		 */

		if (tcp_flags & RTE_TCP_FIN_FLAG && src->state < DAO_CONN_TCP_CLOSING)
			src->state = DAO_CONN_TCP_CLOSING;

		if (tcp_flags & RTE_TCP_RST_FLAG)
			src->state = dst->state = DAO_CONN_TCP_TIME_WAIT;
	}
	else
		return CONN_UPDATE_INVALID;

	return CONN_UPDATE_VALID;
}

static bool
dao_tcp_valid_new(struct conn_lookup_ctx *ctx, struct rte_mbuf *pkt)
{
	struct rte_tcp_hdr *tcp =
		(struct rte_tcp_hdr *)(rte_pktmbuf_mtod(pkt, char *) + ctx->l4_offset);
	uint8_t tcp_flags = tcp->tcp_flags;

	if (tcp_invalid_flags(tcp_flags))
		return false;

	if ((tcp_flags & RTE_TCP_SYN_FLAG) && (tcp_flags & RTE_TCP_ACK_FLAG))
		return false;

	return true;
}

static struct dao_conn *
dao_tcp_new_conn(struct dao_conntrack *ct, struct conn_lookup_ctx *ctx, struct rte_mbuf *pkt,
		 uint64_t now)
{
	struct rte_tcp_hdr *tcp =
		(struct rte_tcp_hdr *)(rte_pktmbuf_mtod(pkt, char *) + ctx->l4_offset);
	struct dao_conn_tcp *newconn = NULL;
	struct dao_conn_tcp_peer *src, *dst;
	uint16_t tcp_flags = tcp->tcp_flags;
	uint8_t sws;

	RTE_SET_USED(ct);
	RTE_SET_USED(now);

	newconn = (struct dao_conn_tcp *)rte_zmalloc(
		"tcp_ct_conn", sizeof(struct dao_conn_tcp), RTE_CACHE_LINE_SIZE);
	if (!newconn)
		return NULL;

	src = &newconn->peer[0];
	dst = &newconn->peer[1];

	src->seqcur = rte_be_to_cpu_32(tcp->sent_seq);
	src->seqnxt = src->seqcur + dao_get_tcp_payload_length(pkt, tcp, ctx->l4_offset) + 1;

	if (tcp_flags & RTE_TCP_SYN_FLAG) {
		src->seqnxt++;
		dao_get_tcp_opt(tcp, src);
	} else {
		/* If its not a SYN packet, set window scale to MAX value. */
		src->wscale = DAO_CONN_TCP_MAX_WSCALE;
		src->opt |= DAO_CONN_TCPOPT_FLAG(WSCALE_FLAG);
		dst->wscale = DAO_CONN_TCP_MAX_WSCALE;
		dst->opt |= DAO_CONN_TCPOPT_FLAG(WSCALE_FLAG);
	}
	src->maxwin = RTE_MAX(rte_be_to_cpu_16(tcp->rx_win), 1);
	sws = src->wscale;
	if (sws)
		src->maxwin = DAO_DIV_ROUND_UP((uint32_t)src->maxwin, (1 << sws));

	if (tcp_flags & RTE_TCP_FIN_FLAG)
		src->seqnxt++;

	dst->seqnxt = 1;
	dst->maxwin = 1;
	src->state = DAO_CONN_TCP_SYN_SENT;
	dst->state = DAO_CONN_TCP_CLOSED;

	conn_ex_timer_update(&newconn->up, tcp_timeouts[SYN_SENT], now);
	return &newconn->up;
}

struct ct_l4_proto dao_ct_proto_tcp = {
	.new_conn = dao_tcp_new_conn,
	.valid_new = dao_tcp_valid_new,
	.conn_update = dao_tcp_conn_update,
};
