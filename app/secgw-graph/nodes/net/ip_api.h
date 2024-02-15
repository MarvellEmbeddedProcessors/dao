/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_NODES_IP_API_H_
#define _APP_NODES_IP_API_H_

/* Public APIs exposed by header files */

#include <rte_ethdev.h>
#include <nodes/net/ip4/rte_node_ip4_api.h>
#include <nodes/net/ip4/ip4_rewrite_priv.h>
#include <nodes/net/ip_feature.h>

struct rte_node_register *pkt_classifier_node_get(void);
#endif
