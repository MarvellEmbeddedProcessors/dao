/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <dao_log.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_telemetry.h>
#include <stdlib.h>

#include "rdma_counter.h"
#include "rdma_port_priv.h"
#include "rdma_priv.h"
#include "rdma_qp.h"

rdma_counter_t **rdma_counter_table;
rdma_lcore_map_t *rdma_lcore_map;
uint8_t num_rport;

const char *rdma_port_counter_type_str[RDMA_MAX_NUM_PORT_COUNTERS] = {
#define X(name) #name,
	RDMA_PORT_COUNTER_LIST RDMA_PORT_DBG_COUNTER_LIST
#undef X
};

const char *rdma_qp_counter_type_str[RDMA_MAX_NUM_QP_COUNTERS] = {
#define X(name) #name,
	RDMA_QP_COUNTER_LIST
#undef X
};

int
rdma_counter_init(uint8_t nport)
{
	int lcore_id, nb_lcore = 0;

	rdma_lcore_map =
		rte_zmalloc("rdma_lcore_map", sizeof(rdma_lcore_map_t), RTE_CACHE_LINE_SIZE);

	if (!rdma_lcore_map) {
		dao_err("Failed to allocate rdma_lcore_map");
		return -ENOMEM;
	}

	RTE_LCORE_FOREACH(lcore_id) {
		rdma_lcore_map->lcore_to_index[lcore_id] = nb_lcore;
		rdma_lcore_map->index_to_lcore[nb_lcore++] = lcore_id;
	}

	rdma_lcore_map->nb_lcore = nb_lcore;
	rdma_counter_table = rte_zmalloc("rdma_counter_table", sizeof(rdma_counter_t *) * nb_lcore,
					 RTE_CACHE_LINE_SIZE);

	if (!rdma_counter_table) {
		dao_err("Failed to allocate rdma_counter_table");
		rte_free(rdma_lcore_map);
		return -ENOMEM;
	}

	num_rport = nport;
	for (int lcore = 0; lcore < nb_lcore; lcore++) {
		lcore_id = rdma_lcore_map->index_to_lcore[lcore];
		rdma_counter_table[lcore] =
			rte_zmalloc("rdma_counters_per_lcore", sizeof(rdma_counter_t) * num_rport,
				    RTE_CACHE_LINE_SIZE);
		if (!rdma_counter_table[lcore]) {
			dao_err("Failed to allocate counters for lcore %d", lcore_id);
			goto free_lcores;
		}
	}

	return 0;
free_lcores:
	for (int i = 0; i < nb_lcore; i++) {
		if (rdma_counter_table[i])
			rte_free(rdma_counter_table[i]);
	}

	rte_free(rdma_counter_table);
	rte_free(rdma_lcore_map);
	return -ENOMEM;
}

static int
fill_lcore_info(struct rte_tel_data *core_info)
{
	struct rte_tel_data *enabled_lcores = rte_tel_data_alloc();
	int lcore_id;

	if (!enabled_lcores)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory for enabled_lcores");

	rte_tel_data_start_array(enabled_lcores, RTE_TEL_INT_VAL);

	for (int i = 0; i < rdma_lcore_map->nb_lcore; i++) {
		lcore_id = rdma_lcore_map->index_to_lcore[i];
		rte_tel_data_add_array_int(enabled_lcores, lcore_id);
	}

	rte_tel_data_add_dict_int(core_info, "num_enabled_lcores", rdma_lcore_map->nb_lcore);
	rte_tel_data_add_dict_container(core_info, "enabled_lcores", enabled_lcores, 0);

	return 0;
fail:
	return -ENOMEM;
}

static int
fill_port_info(struct rte_tel_data *port_info)
{
	struct rte_tel_data *active_ports = rte_tel_data_alloc();
	int num_active_ports = 0;

	if (!active_ports)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory for active_ports");

	rte_tel_data_start_array(active_ports, RTE_TEL_INT_VAL);

	for (int portid = 0; portid < num_rport; portid++) {
		if (rdma_port_lookup(portid)) {
			num_active_ports++;
			rte_tel_data_add_array_int(active_ports, portid);
		}
	}

	rte_tel_data_add_dict_int(port_info, "num_active_ports", num_active_ports);
	rte_tel_data_add_dict_container(port_info, "active_ports", active_ports, 0);

	return 0;
fail:
	return -ENOMEM;
}

static int
rdma_port_counters_sum(int lcore, struct rte_tel_data *port_info)
{
	struct rte_tel_data *port_counters = rte_tel_data_alloc();
	int num_active_ports = 0;
	int lcore_idx;

	if (port_counters == NULL)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory for port_counters");

	fill_port_info(port_info);
	rte_tel_data_start_dict(port_counters);
	lcore_idx = rdma_lcore_map->lcore_to_index[lcore];

	for (int portid = 0; portid < num_rport; portid++)
		num_active_ports += (rdma_port_lookup(portid) != NULL ? 1 : 0);

	if (num_active_ports > 0) {
		for (int i = 0; i < RDMA_MAX_NUM_PORT_COUNTERS; i++) {
			uint64_t sum = 0;

			for (int portid = 0; portid < num_rport; portid++) {
				if (rdma_port_lookup(portid))
					sum += rdma_counter_table[lcore_idx][portid]
						       .port_counters[i];
			}
			rte_tel_data_add_dict_uint(port_counters, rdma_port_counter_type_str[i],
						   sum);
		}
	}

	rte_tel_data_add_dict_container(port_info, "port_counters", port_counters, 0);

	return 0;
fail:
	return -ENOMEM;
}

static int
rdma_all_port_counters_sum(struct rte_tel_data *port_info)
{
	struct rte_tel_data *port_counters = rte_tel_data_alloc();

	if (!port_counters)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory for port_counters");

	rte_tel_data_start_dict(port_counters);
	fill_lcore_info(port_info);
	fill_port_info(port_info);

	for (int i = 0; i < RDMA_MAX_NUM_PORT_COUNTERS; i++) {
		uint64_t sum = 0;

		for (int lcore = 0; lcore < rdma_lcore_map->nb_lcore; lcore++) {
			for (int portid = 0; portid < num_rport; portid++) {
				if (rdma_port_lookup(portid))
					sum += rdma_counter_table[lcore][portid].port_counters[i];
			}
		}

		rte_tel_data_add_dict_uint(port_counters, rdma_port_counter_type_str[i], sum);
	}

	rte_tel_data_add_dict_container(port_info, "port_counters", port_counters, 0);
	return 0;
fail:
	return -ENOMEM;
}

static int
fill_qp_info(int port_id, struct rte_tel_data *qp_info)
{
	struct rte_tel_data *valid_qps;
	struct rdma_port *port;

	port = rdma_port_lookup(port_id);
	if (!port)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get RDMA port %d", port_id);

	valid_qps = rte_tel_data_alloc();
	if (!valid_qps)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory for valid_qps");

	rte_tel_data_start_array(valid_qps, RTE_TEL_INT_VAL);
	rte_tel_data_add_dict_uint(qp_info, "num_active_qp", port->num_active_qp);

	for (int qid = 0; qid < RDMA_QP_MAX; qid++) {
		if (rdma_qp_query(qid, port->portid))
			rte_tel_data_add_array_int(valid_qps, qid);
	}

	rte_tel_data_add_dict_container(qp_info, "valid_qps", valid_qps, 0);

	return 0;
fail:
	if (valid_qps)
		rte_tel_data_free(valid_qps);
	return -ENOMEM;
}

static int
rdma_qp_counters_sum(int port_id, struct rte_tel_data *qp_info)
{
	struct rte_tel_data *qp_counters;
	struct rdma_port *port;
	int num_active_qp;
	int rc;

	port = rdma_port_lookup(port_id);
	if (!port) {
		rc = -EINVAL;
		DAO_ERR_GOTO(rc, fail, "Failed to get RDMA port %d", port_id);
	}

	qp_counters = rte_tel_data_alloc();
	if (!qp_counters) {
		rc = -ENOMEM;
		DAO_ERR_GOTO(rc, fail, "Failed to allocate memory for qp_counters");
	}

	rte_tel_data_start_dict(qp_counters);
	fill_qp_info(port_id, qp_info);
	num_active_qp = port->num_active_qp;

	if (num_active_qp > 0) {
		for (int i = 0; i < RDMA_MAX_NUM_QP_COUNTERS; i++) {
			uint64_t sum = 0;

			for (int qid = 0; qid < RDMA_QP_MAX; qid++) {
				rdma_qp_t *qp = rdma_qp_query(qid, port_id);
				int lcore_idx;

				if (!qp)
					continue;

				lcore_idx = rdma_lcore_map->lcore_to_index[qp->lcore];
				sum += rdma_counter_table[lcore_idx][port_id].qp_counters[qid][i];
			}
			rte_tel_data_add_dict_uint(qp_counters, rdma_qp_counter_type_str[i], sum);
		}
	}

	rte_tel_data_add_dict_container(qp_info, "qp_counters", qp_counters, 0);

	return 0;
fail:
	return rc;
}

static void
rdma_port_qp_info(struct rte_tel_data *info)
{
	for (int port_id = 0; port_id < num_rport; port_id++) {
		struct rte_tel_data *qp_info;
		struct rdma_port *port;
		char key[RTE_TEL_MAX_STRING_LEN];

		port = rdma_port_lookup(port_id);
		if (!port)
			continue;

		qp_info = rte_tel_data_alloc();
		if (!qp_info)
			continue;

		rte_tel_data_start_dict(qp_info);
		fill_qp_info(port_id, qp_info);
		snprintf(key, sizeof(key), "port_%d", port_id);
		rte_tel_data_add_dict_container(info, key, qp_info, 0);
	}
}

static int
rdma_all_qp_counters_sum(struct rte_tel_data *qp_info)
{
	struct rte_tel_data *qp_counters = rte_tel_data_alloc();

	if (!qp_counters) {
		dao_err("Failed to allocate memory for qp_counters");
		return -ENOMEM;
	}

	rte_tel_data_start_dict(qp_counters);

	for (int i = 0; i < RDMA_MAX_NUM_QP_COUNTERS; i++) {
		uint64_t sum = 0;

		for (int port_id = 0; port_id < num_rport; port_id++) {
			if (!rdma_port_lookup(port_id))
				continue;

			for (int qid = 0; qid < RDMA_QP_MAX; qid++) {
				rdma_qp_t *qp = rdma_qp_query(qid, port_id);

				if (!qp)
					continue;

				int lcore_idx = rdma_lcore_map->lcore_to_index[qp->lcore];

				sum += rdma_counter_table[lcore_idx][port_id].qp_counters[qid][i];
			}
		}

		rte_tel_data_add_dict_uint(qp_counters, rdma_qp_counter_type_str[i], sum);
	}

	rte_tel_data_add_dict_container(qp_info, "qp_counters", qp_counters, 0);
	return 0;
}

static int
rdma_port_list_handler(const char *cmd __rte_unused, const char *params __rte_unused,
		       struct rte_tel_data *d)
{
	struct rte_tel_data *info = rte_tel_data_alloc();
	struct rte_tel_data *core_info = rte_tel_data_alloc();
	struct rte_tel_data *port_info = rte_tel_data_alloc();

	if (info == NULL || core_info == NULL || port_info == NULL)
		DAO_ERR_GOTO(-ENOMEM, free, "Failed to allocate memory for telemetry data");

	rte_tel_data_start_dict(d);
	rte_tel_data_start_dict(info);
	rte_tel_data_start_dict(core_info);
	rte_tel_data_start_dict(port_info);

	fill_lcore_info(core_info);
	fill_port_info(port_info);

	rte_tel_data_add_dict_container(info, "core_info", core_info, 0);
	rte_tel_data_add_dict_container(info, "port_info", port_info, 0);
	rte_tel_data_add_dict_container(d, "rdma_system_info", info, 0);

	return 0;
free:
	if (info)
		rte_tel_data_free(info);
	if (core_info)
		rte_tel_data_free(core_info);
	if (port_info)
		rte_tel_data_free(port_info);
	return -ENOMEM;
}

static int
rdma_port_counters_handler(const char *cmd __rte_unused, const char *params, struct rte_tel_data *d)
{
	struct rte_tel_data *info;
	int filter_lcore = -2, filter_port = -2;
	char key[RTE_TEL_MAX_STRING_LEN];
	const char *port_param;
	char *end_param;
	int lcore_idx;
	int rc;

	if (!params || strlen(params) == 0)
		return -EINVAL;

	filter_lcore = strtol(params, &end_param, 0);
	if (end_param == params) {
		rc = -EINVAL;
		DAO_ERR_GOTO(rc, fail, "Invalid lcore number");
	}

	port_param = strtok(end_param, ",");
	if (!port_param || strlen(port_param) == 0) {
		rc = -EINVAL;
		DAO_ERR_GOTO(rc, fail, "Missing or invalid port parameter");
	}

	filter_port = strtol(port_param, &end_param, 0);
	if (end_param == port_param) {
		rc = -EINVAL;
		DAO_ERR_GOTO(rc, fail, "Invalid port number");
	}

	info = rte_tel_data_alloc();
	if (info == NULL) {
		rc = -ENOMEM;
		DAO_ERR_GOTO(rc, fail, "Failed to allocate memory for telemetry data");
	}

	rte_tel_data_start_dict(d);
	rte_tel_data_start_dict(info);

	if (filter_lcore == -1 && filter_port == -1) {
		snprintf(key, sizeof(key), "all_lcores_all_ports_sum");
		rdma_all_port_counters_sum(info);
		rte_tel_data_add_dict_container(d, key, info, 0);
		return 0;
	}

	if (filter_lcore < 0 || filter_lcore >= RTE_MAX_LCORE ||
	    !rte_lcore_is_enabled(filter_lcore)) {
		fill_lcore_info(info);
		snprintf(key, sizeof(key), "Lcore %d is not enabled.", filter_lcore);
		rte_tel_data_add_dict_string(info, "error", key);
		rte_tel_data_add_dict_container(d, "core_info", info, 0);
		return 0;
	}

	if (filter_port == -1) {
		rdma_port_counters_sum(filter_lcore, info);
		snprintf(key, sizeof(key), "lcore_%d_port_sum", filter_lcore);
		rte_tel_data_add_dict_container(d, key, info, 0);
		return 0;
	}

	if (filter_port < 0 || filter_port >= num_rport || !rdma_port_lookup(filter_port)) {
		fill_port_info(info);
		snprintf(key, sizeof(key), "Port %d is not a valid RDMA device.", filter_port);
		rte_tel_data_add_dict_string(info, "error", key);
		rte_tel_data_add_dict_container(d, "port_info", info, 0);
		return 0;
	}

	lcore_idx = rdma_lcore_map->lcore_to_index[filter_lcore];
	for (int i = 0; i < RDMA_MAX_NUM_PORT_COUNTERS; i++) {
		rte_tel_data_add_dict_uint(
			info, rdma_port_counter_type_str[i],
			rdma_counter_table[lcore_idx][filter_port].port_counters[i]);
	}

	snprintf(key, sizeof(key), "lcore_%d_port_%d", filter_lcore, filter_port);
	rte_tel_data_add_dict_container(d, key, info, 0);

	return 0;
fail:
	return rc;
}

static int
rdma_qp_list_handler(const char *cmd __rte_unused, const char *params __rte_unused,
		     struct rte_tel_data *d)
{
	struct rte_tel_data *info = rte_tel_data_alloc();

	if (info == NULL)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory for telemetry data");

	rte_tel_data_start_dict(d);
	rte_tel_data_start_dict(info);

	rdma_port_qp_info(info);
	rte_tel_data_add_dict_container(d, "port_qp_info", info, 0);

	return 0;
fail:
	if (info)
		rte_tel_data_free(info);
	return -ENOMEM;
}

static int
rdma_qp_counters_handler(const char *cmd __rte_unused, const char *params, struct rte_tel_data *d)
{
	int filter_port = -2, filter_qp = -2;
	char key[RTE_TEL_MAX_STRING_LEN];
	struct rte_tel_data *info;
	const char *qp_param;
	char *end_param;
	rdma_qp_t *qp;
	int lcore_idx;
	int rc;

	if (!params || strlen(params) == 0) {
		rc = -EINVAL;
		DAO_ERR_GOTO(rc, fail, "Invalid parameters");
	}

	filter_port = strtol(params, &end_param, 0);
	if (end_param == params) {
		rc = -EINVAL;
		DAO_ERR_GOTO(rc, fail, "Invalid port number");
	}

	qp_param = strtok(end_param, ",");
	if (!qp_param || strlen(qp_param) == 0) {
		rc = -EINVAL;
		DAO_ERR_GOTO(rc, fail, "Missing or invalid QP parameter");
	}

	filter_qp = strtol(qp_param, &end_param, 0);
	if (end_param == qp_param) {
		rc = -EINVAL;
		DAO_ERR_GOTO(rc, fail, "Invalid QP number");
	}

	info = rte_tel_data_alloc();
	if (info == NULL) {
		rc = -ENOMEM;
		DAO_ERR_GOTO(rc, fail, "Failed to allocate memory for telemetry data");
	}

	rte_tel_data_start_dict(d);
	rte_tel_data_start_dict(info);

	if (filter_port == -1 && filter_qp == -1) {
		snprintf(key, sizeof(key), "all_ports_all_qps_sum");
		rdma_all_qp_counters_sum(info);
		rte_tel_data_add_dict_container(d, key, info, 0);
		return 0;
	}

	if (filter_port < 0 || filter_port >= num_rport || !rdma_port_lookup(filter_port)) {
		fill_port_info(info);
		snprintf(key, sizeof(key), "Port %d is not a valid RDMA device.", filter_port);
		rte_tel_data_add_dict_string(info, "error", key);
		rte_tel_data_add_dict_container(d, "port_info", info, 0);
		return 0;
	}

	if (filter_qp == -1) {
		snprintf(key, sizeof(key), "port_%d_qp_sum", filter_port);
		rdma_qp_counters_sum(filter_port, info);
		rte_tel_data_add_dict_container(d, key, info, 0);
		return 0;
	}

	if (filter_qp < 0 || filter_qp >= RDMA_QP_MAX || !rdma_qp_query(filter_qp, filter_port)) {
		fill_qp_info(filter_port, info);
		snprintf(key, sizeof(key), "QP %d is not valid for RDMA Port %d.", filter_qp,
			 filter_port);
		rte_tel_data_add_dict_string(info, "error", key);
		rte_tel_data_add_dict_container(d, "port_qp_info", info, 0);
		return 0;
	}

	qp = rdma_qp_query(filter_qp, filter_port);
	if (qp == NULL) {
		rc = -EINVAL;
		DAO_ERR_GOTO(rc, free, "Failed to get qp %d on port %d", filter_qp, filter_port);
	}

	lcore_idx = rdma_lcore_map->lcore_to_index[qp->lcore];
	for (int i = 0; i < RDMA_MAX_NUM_QP_COUNTERS; i++) {
		rte_tel_data_add_dict_uint(
			info, rdma_qp_counter_type_str[i],
			rdma_counter_table[lcore_idx][filter_port].qp_counters[filter_qp][i]);
	}

	snprintf(key, sizeof(key), "lcore_%d_port_%d_qp_%d", lcore_idx, filter_port, filter_qp);
	rte_tel_data_add_dict_container(d, key, info, 0);

	return 0;
free:
	rte_tel_data_free(info);
fail:
	return rc;
}

static int
rdma_ethdev_stats_handler(const char *cmd __rte_unused, const char *params __rte_unused,
			  struct rte_tel_data *d)
{
	struct rte_eth_stats stats;
	uint16_t port_id;

	rte_tel_data_start_dict(d);

	/* clang-format off */
	RTE_ETH_FOREACH_DEV(port_id) {
		struct rte_tel_data *pdata = rte_tel_data_alloc();
		char key[32];

		if (!pdata)
			continue;
		rte_tel_data_start_dict(pdata);

		if (rte_eth_stats_get(port_id, &stats) == 0) {
			rte_tel_data_add_dict_uint(pdata, "ipackets", stats.ipackets);
			rte_tel_data_add_dict_uint(pdata, "opackets", stats.opackets);
			rte_tel_data_add_dict_uint(pdata, "ibytes", stats.ibytes);
			rte_tel_data_add_dict_uint(pdata, "obytes", stats.obytes);
			rte_tel_data_add_dict_uint(pdata, "imissed", stats.imissed);
			rte_tel_data_add_dict_uint(pdata, "ierrors", stats.ierrors);
			rte_tel_data_add_dict_uint(pdata, "oerrors", stats.oerrors);
			rte_tel_data_add_dict_uint(pdata, "rx_nombuf", stats.rx_nombuf);
		}

		snprintf(key, sizeof(key), "port_%u", port_id);
		rte_tel_data_add_dict_container(d, key, pdata, 0);
	}
	/* clang-format on */

	return 0;
}

RTE_INIT(rdma_register_counter_telemetry)
{
	rte_telemetry_register_cmd(
		"/rdma/port/list", rdma_port_list_handler,
		"Returns list of enabled lcores and active RDMA ports. No parameters.");

	rte_telemetry_register_cmd(
		"/rdma/port/counters", rdma_port_counters_handler,
		"Returns RDMA port statistics. Parameters: int lcore, int port.");

	rte_telemetry_register_cmd("/rdma/qp/list", rdma_qp_list_handler,
				   "Returns list of active QPs. No parameters.");

	rte_telemetry_register_cmd(
		"/rdma/qp/counters", rdma_qp_counters_handler,
		"Returns statistics for a specific RDMA Queue Pair (QP). Parameters: int port, int qp.");

	rte_telemetry_register_cmd(
		"/rdma/ethdev/stats", rdma_ethdev_stats_handler,
		"Returns DPDK ethdev HW stats (ipackets, opackets, imissed, oerrors, etc.). No parameters.");
}
