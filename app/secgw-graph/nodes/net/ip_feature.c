/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <rte_ethdev.h>

#include <nodes/net/ip_feature.h>
#include <nodes/net/ip4/ip4_lookup_priv.h>
#include <nodes/net/ip4/ip4_rewrite_priv.h>
#include <nodes/net/ip_node_priv.h>
#include <nodes/node_api.h>

dao_graph_feature_arc_t ip4_output_feature_arc = DAO_GRAPH_FEATURE_ARC_INITIALIZER;
dao_graph_feature_arc_t ip4_punt_feature_arc = DAO_GRAPH_FEATURE_ARC_INITIALIZER;
dao_graph_feature_arc_t ip4_local_feature_arc = DAO_GRAPH_FEATURE_ARC_INITIALIZER;

int
ip_feature_arcs_register(int max_ports)
{
	if (dao_graph_feature_arc_create(IP4_OUTPUT_FEATURE_ARC_NAME,
					 IP4_OUTPUT_FEATURE_ARC_MAX_FEATUES,
					 max_ports, ip4_rewrite_node_get(),
					 &ip4_output_feature_arc)) {
		dao_err("feature arc for ip4-output failed");
		return -1;
	}

	if (dao_graph_feature_arc_create(IP4_PUNT_FEATURE_ARC_NAME,
					 IP4_PUNT_FEATURE_ARC_MAX_FEATUES,
					 max_ports, ip4_lookup_node_get(),
					 &ip4_punt_feature_arc)) {
		dao_err("feature arc for ip4-punt failed");
		return -1;
	}

	if (dao_graph_feature_arc_create(IP4_LOCAL_FEATURE_ARC_NAME,
					 IP4_LOCAL_FEATURE_ARC_MAX_FEATUES,
					 max_ports, ip4_local_node_get(),
					 &ip4_local_feature_arc)) {
		dao_err("feature arc for ip4-local failed");
		return -1;
	}
	return 0;
}

int
ip_feature_punt_add(struct rte_node_register *feature)
{
	if (ip4_punt_feature_arc == DAO_GRAPH_FEATURE_ARC_INITIALIZER) {
		dao_err("ip_feature_arcs_register() call missing");
		return -1;
	}

	if (dao_graph_feature_add(ip4_punt_feature_arc, feature, NULL, NULL)) {
		dao_err("dao_graph_feature_add failed for feature node: %s", feature->name);
		return -1;
	}

	return 0;
}

int
ip_feature_punt_enable(struct rte_node_register *feature, int interface_index, int64_t data)
{
	if (ip4_punt_feature_arc == DAO_GRAPH_FEATURE_ARC_INITIALIZER) {
		dao_err("ip_feature_arcs_register() call missing");
		return -1;
	}

	if (dao_graph_feature_enable(ip4_punt_feature_arc, interface_index, feature->name, data)) {
		dao_err("punt feature enable failed for: %s", feature->name);
		return -1;
	}

	return 0;
}

int
ip_feature_output_add(struct rte_node_register *feature, const char *after, const char *before)
{
	if (ip4_output_feature_arc == DAO_GRAPH_FEATURE_ARC_INITIALIZER) {
		dao_err("ip_feature_arcs_register() call missing");
		return -1;
	}

	if (dao_graph_feature_add(ip4_output_feature_arc, feature, after, before)) {
		dao_err("dao_graph_feature_add failed for feature node: %s", feature->name);
		return -1;
	}

	return 0;
}

int
ip_feature_output_enable(struct rte_node_register *feature, int interface_index, int64_t data)
{
	if (ip4_output_feature_arc == DAO_GRAPH_FEATURE_ARC_INITIALIZER) {
		dao_err("ip_feature_arcs_register() call missing");
		return -1;
	}

	if (dao_graph_feature_enable(ip4_output_feature_arc,
				     interface_index, feature->name, data)) {
		dao_err("output feature enable failed for: %s", feature->name);
		return -1;
	}

	return 0;
}

int
ip_feature_local_add(struct rte_node_register *feature, const char *after, const char *before)
{
	if (ip4_local_feature_arc == DAO_GRAPH_FEATURE_ARC_INITIALIZER) {
		dao_err("ip_feature_arcs_register() call missing");
		return -1;
	}

	if (dao_graph_feature_add(ip4_local_feature_arc, feature, after, before)) {
		dao_err("dao_graph_feature_add failed for feature node: %s", feature->name);
		return -1;
	}

	return 0;
}

int
ip_feature_local_enable(struct rte_node_register *feature, int interface_index, int64_t data)
{
	if (ip4_local_feature_arc == DAO_GRAPH_FEATURE_ARC_INITIALIZER) {
		dao_err("ip_feature_arcs_register() call missing");
		return -1;
	}

	if (dao_graph_feature_enable(ip4_local_feature_arc, interface_index, feature->name, data)) {
		dao_err("output feature enable failed for: %s", feature->name);
		return -1;
	}

	return 0;
}
