/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_GRAPH_NODES_NET_CLASSIFIER_PKT_CLS_PRIV_H_
#define _APP_SECGW_GRAPH_NODES_NET_CLASSIFIER_PKT_CLS_PRIV_H_

#include <rte_common.h>

struct secgw_pkt_cls_node_ctx {
	uint16_t l2l3_type;
};

enum secgw_pkt_cls_next_nodes {
	SECGW_PKT_CLS_NEXT_PKT_DROP,
	SECGW_PKT_CLS_NEXT_IP4_LOOKUP,
	SECGW_PKT_CLS_NEXT_IP6_LOOKUP,
	SECGW_PKT_CLS_NEXT_MAX,
};

#endif
