/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _APP_SECGW_NODES_IP_FEATURE_H_
#define _APP_SECGW_NODES_IP_FEATURE_H_

#include <rte_graph.h>
#include <rte_graph_worker.h>

/** IP4 Feature Arc */
#define IP4_OUTPUT_FEATURE_ARC_NAME "ip4-output"
#define IP4_LOCAL_FEATURE_ARC_NAME  "ip4-local"
#define IP4_PUNT_FEATURE_ARC_NAME   "ip4-punt"

#define IP4_OUTPUT_FEATURE_ARC_MAX_FEATUES 8
#define IP4_PUNT_FEATURE_ARC_MAX_FEATUES   8
#define IP4_LOCAL_FEATURE_ARC_MAX_FEATUES  8

int ip_feature_arcs_register(int max_ports);

int ip_feature_punt_add(struct rte_node_register *feature);

int ip_feature_punt_enable(struct rte_node_register *feature, int interface_index, int64_t data);

int ip_feature_output_add(struct rte_node_register *feature, const char *before_feature,
			  const char *after_feature);

int ip_feature_output_enable(struct rte_node_register *feature, int interface_index, int64_t data);

int ip_feature_local_add(struct rte_node_register *feature, const char *before_feature,
			 const char *after_feature);

int ip_feature_local_enable(struct rte_node_register *feature, int interface_index, int64_t data);
#endif
