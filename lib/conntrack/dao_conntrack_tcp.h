/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "dao_conntrack.h"
#include "dao_conntrack_private.h"

#include <rte_tcp.h>

#define DAO_CONN_TCP_MAX_WSCALE 14

#define DAO_SEQ_LT(a, b)  ((int)((a) - (b)) < 0)
#define DAO_SEQ_LEQ(a, b) ((int)((a) - (b)) <= 0)
#define DAO_SEQ_GT(a, b)  ((int)((a) - (b)) > 0)
#define DAO_SEQ_GEQ(a, b) ((int)((a) - (b)) >= 0)

#define DAO_SEQ_MIN(a, b) ((DAO_SEQ_LT(a, b)) ? (a) : (b))
#define DAO_SEQ_MAX(a, b) ((DAO_SEQ_GT(a, b)) ? (a) : (b))

#define DAO_CONN_TCPOPT_FLAG(x) (1 << (x))
enum tcpopt_flag {
	WSCALE_FLAG,
	WSCALE_UNKNOWN,
	SACK_FLAG,
};

enum {
	DAO_CONN_TCPOPT_EOL,
	DAO_CONN_TCPOPT_NOP,
	DAO_CONN_TCPOPT_WINDOW = 3,
	DAO_CONN_TCPOPT_SACK = 4,
};

enum dao_tcp_state {
	DAO_CONN_TCP_CLOSED,
	DAO_CONN_TCP_LISTEN,
	DAO_CONN_TCP_SYN_SENT,
	DAO_CONN_TCP_SYN_RECV,
	DAO_CONN_TCP_ESTABLISHED,
	DAO_CONN_TCP_CLOSE_WAIT,
	DAO_CONN_TCP_FIN_WAIT_1,
	DAO_CONN_TCP_CLOSING,
	DAO_CONN_TCP_LAST_ACK,
	DAO_CONN_TCP_FIN_WAIT_2,
	DAO_CONN_TCP_TIME_WAIT,
	DAO_CONN_TCP_MAX_NUM,
};

struct dao_conn_tcp_peer {
	uint32_t seqcur;
	uint32_t seqnxt;
	uint16_t maxwin;
	uint8_t wscale;
	uint8_t opt;
	enum dao_tcp_state state;
};

struct dao_conn_tcp {
	struct dao_conn up;
	struct dao_conn_tcp_peer peer[2];
};
