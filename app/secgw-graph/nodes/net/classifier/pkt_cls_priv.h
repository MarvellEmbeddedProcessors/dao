/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_GRAPH_NODES_NET_CLASSIFIER_PKT_CLS_PRIV_H_
#define _APP_SECGW_GRAPH_NODES_NET_CLASSIFIER_PKT_CLS_PRIV_H_

#include <rte_common.h>

struct pkt_cls_node_ctx {
	uint16_t l2l3_type;
};

enum pkt_cls_next_nodes {
	PKT_CLS_NEXT_PKT_DROP,
	PKT_CLS_NEXT_IP4_LOOKUP,
	PKT_CLS_NEXT_IP6_LOOKUP,
	PKT_CLS_NEXT_MAX,
};

#endif
