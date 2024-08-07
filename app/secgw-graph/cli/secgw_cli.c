/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <secgw_worker.h>
#include <netlink/secgw_netlink.h>
#include <cli_api.h>

//static const char cmd_show_interfaces_help[] = "show interfaces";
#define SCLI_NS_PER_SEC 1E9

static int
ports_show(struct scli_conn *conn, secgw_device_t *sdev, uint32_t len)
{
	uint64_t diff_pkts_rx, diff_pkts_tx, diff_bytes_rx, diff_bytes_tx;
	static const char *nic_stats_border = "########################";
	static uint64_t prev_pkts_rx[RTE_MAX_ETHPORTS];
	static uint64_t prev_pkts_tx[RTE_MAX_ETHPORTS];
	static uint64_t prev_bytes_rx[RTE_MAX_ETHPORTS];
	static uint64_t prev_bytes_tx[RTE_MAX_ETHPORTS];
	static uint64_t prev_cycles[RTE_MAX_ETHPORTS];
	uint64_t mpps_rx, mpps_tx, mbps_rx, mbps_tx;
	uint64_t diff_ns, diff_cycles, curr_cycles;
	struct rte_eth_stats stats;
	struct rte_eth_link link;
	char link_status[64] = "\0";
	int port_id;
	int rc;

	port_id = sdev->dp_port_id;
	rc = rte_eth_stats_get(port_id, &stats);
	if (rc != 0) {
		fprintf(stderr, "%s: Error: failed to get stats (port %u): %d", __func__, port_id,
			rc);
		return rc;
	}
	if (rte_eth_link_get(sdev->dp_port_id, &link)) {
		strncpy(link_status, "Unknown", strlen("Unknown") + 1);
	} else {
		if (link.link_status == RTE_ETH_LINK_UP)
			strncpy(link_status, "Up", strlen("Up") + 1);
		else
			strncpy(link_status, "Down", strlen("Down") + 1);
	}

	snprintf(conn->msg_out + len, conn->msg_out_len_max,
		 "\n  %s NIC statistics: %-7s %s\n"
		 "  Link-Status: %-10s RX-packets: %-11" PRIu64 " RX-missed: %-" PRIu64 "\n"
		 "  RX-bytes: %-14" PRIu64 "RX-errors: %-12" PRIu64 " RX-nombuf:  %-" PRIu64 "\n"
		 "  TX-packets: %-11" PRIu64 " TX-errors: %-12" PRIu64 " TX-bytes:  "
		 "%-" PRIu64 "\n",
		 nic_stats_border, sdev->dev_name, nic_stats_border, link_status,
		 stats.ipackets, stats.imissed, stats.ibytes, stats.ierrors,
		 stats.rx_nombuf, stats.opackets, stats.oerrors, stats.obytes);

	diff_ns = 0;
	diff_cycles = 0;

	curr_cycles = rte_rdtsc();
	if (prev_cycles[port_id] != 0)
		diff_cycles = curr_cycles - prev_cycles[port_id];

	prev_cycles[port_id] = curr_cycles;
	diff_ns = diff_cycles > 0 ?
		  diff_cycles * (1 / (double)rte_get_tsc_hz()) * SCLI_NS_PER_SEC : 0;

	diff_pkts_rx = (stats.ipackets > prev_pkts_rx[port_id]) ?
			       (stats.ipackets - prev_pkts_rx[port_id]) :
			       0;
	diff_pkts_tx = (stats.opackets > prev_pkts_tx[port_id]) ?
			       (stats.opackets - prev_pkts_tx[port_id]) :
			       0;
	prev_pkts_rx[port_id] = stats.ipackets;
	prev_pkts_tx[port_id] = stats.opackets;
	mpps_rx = diff_ns > 0 ? (double)diff_pkts_rx / diff_ns * SCLI_NS_PER_SEC : 0;
	mpps_tx = diff_ns > 0 ? (double)diff_pkts_tx / diff_ns * SCLI_NS_PER_SEC : 0;

	diff_bytes_rx = (stats.ibytes > prev_bytes_rx[port_id]) ?
				(stats.ibytes - prev_bytes_rx[port_id]) :
				0;
	diff_bytes_tx = (stats.obytes > prev_bytes_tx[port_id]) ?
				(stats.obytes - prev_bytes_tx[port_id]) :
				0;
	prev_bytes_rx[port_id] = stats.ibytes;
	prev_bytes_tx[port_id] = stats.obytes;
	mbps_rx = diff_ns > 0 ? (double)diff_bytes_rx / diff_ns * SCLI_NS_PER_SEC : 0;
	mbps_tx = diff_ns > 0 ? (double)diff_bytes_tx / diff_ns * SCLI_NS_PER_SEC : 0;

	len = strlen(conn->msg_out);
	snprintf(conn->msg_out + len, conn->msg_out_len_max,
		 "  Throughput (since last show)\n"
		 "  Rx-pps: %12" PRIu64 "          Rx-bps: %12" PRIu64 "\n  Tx-pps: %12" PRIu64
		 "          Tx-bps: %12" PRIu64 "\n",
		 mpps_rx, mbps_rx * 8, mpps_tx, mbps_tx * 8);
	return 0;
}

static int
show_graph(const char **graph_patterns, uint16_t nb_patterns, struct scli_conn *conn)
{
	struct rte_graph_cluster_stats_param s_param;
	struct rte_graph_cluster_stats *stats;
	FILE *fp = NULL;
	size_t sz, len;

	/* Prepare stats object */
	fp = fopen("/tmp/graph_stats.txt", "w+");
	if (fp == NULL)
		rte_exit(EXIT_FAILURE, "Error in opening stats file\n");

	memset(&s_param, 0, sizeof(s_param));
	s_param.f = fp;
	s_param.socket_id = SOCKET_ID_ANY;
	s_param.graph_patterns = graph_patterns;
	s_param.nb_graph_patterns = nb_patterns;

	stats = rte_graph_cluster_stats_create(&s_param);
	if (stats == NULL)
		rte_exit(EXIT_FAILURE, "Unable to create stats object\n");

	/* Clear screen and move to top left */
	rte_graph_cluster_stats_get(stats, 0);
	rte_delay_ms(1E3);

	fseek(fp, 0L, SEEK_END);
	sz = ftell(fp);
	fseek(fp, 0L, SEEK_SET);

	len = strlen(conn->msg_out);
	if (len > conn->msg_out_len_max)
		rte_exit(EXIT_FAILURE, "Invalid msg len\n");
	conn->msg_out += len;

	sz = fread(conn->msg_out, sizeof(char), sz, fp);
	conn->msg_out[sz + 1] = '\0';
	len = strlen(conn->msg_out);
	conn->msg_out_len_max -= len;
	rte_graph_cluster_stats_destroy(stats);

	fclose(fp);

	return 0;
}

void
cmd_show_ports_parsed(__rte_unused void *parsed_result, __rte_unused struct cmdline *cl,
		      __rte_unused void *data)
{
	dao_port_group_t edpg = DAO_PORT_GROUP_INITIALIZER;
	secgw_worker_t *sgw  = NULL;
	dao_worker_t *dw = NULL;
	struct scli_conn *conn = NULL;
	uint32_t length = 0;
	dao_port_t port;
	int i;

	dw = dao_workers_control_worker_get(dao_workers_get());
	if (!dw)
		return;

	if (dao_workers_app_data_get(dw, (void **)&sgw, NULL))
		return;

	if (!sgw->cli_conn)
		return;

	conn = sgw->cli_conn;

	if (dao_port_group_get_by_name(SECGW_ETHDEV_PORT_GROUP_NAME, &edpg) < 0)
		return;

	DAO_PORT_GROUP_FOREACH_PORT(edpg, port, i)
	{
		ports_show(conn, secgw_get_device(port), length);
		length = strlen(conn->msg_out);
	}

	if (dao_port_group_get_by_name(SECGW_TAP_PORT_GROUP_NAME, &edpg) < 0)
		return;

	DAO_PORT_GROUP_FOREACH_PORT(edpg, port, i)
	{
		ports_show(conn, secgw_get_device(port), length);
		length = strlen(conn->msg_out);
	}

	conn->msg_out_len_max -= length;
}

void
cmd_show_graph_parsed(__rte_unused void *parsed_result, __rte_unused struct cmdline *cl,
		      __rte_unused void *data)
{
	static const char **graph_patterns;
	int num_workers, num_graphs = 0;
	struct scli_conn *conn = NULL;
	secgw_worker_t *sgw  = NULL;
	dao_worker_t *dw = NULL;
	char *pattern = NULL;

	dw = dao_workers_control_worker_get(dao_workers_get());
	if (!dw)
		return;

	if (dao_workers_app_data_get(dw, (void **)&sgw, NULL))
		return;

	if (!sgw->cli_conn)
		return;

	conn = sgw->cli_conn;

	if (!graph_patterns)
		graph_patterns = calloc(dao_workers_num_workers_get(), sizeof(char *));
	if (!graph_patterns)
		assert(0);

	for (num_workers = 0; num_workers < dao_workers_num_cores_get(); num_workers++) {
		dw = dao_workers_worker_get(dao_workers_get(), num_workers);
		if (dw && dao_workers_is_control_worker(dw))
			continue;
		pattern = NULL;
		if (dw) {
			if (dao_workers_app_data_get(dw, (void **)&sgw, NULL))
				continue;
			if (sgw && sgw->graph) {
				pattern = malloc(SECGW_GRAPH_NAME + 1);
				if (pattern) {
					*(graph_patterns + num_graphs) = pattern;
					strcpy(pattern, sgw->graph_name);
					num_graphs++;
				}
			}
		}
	}
	if (num_graphs)
		show_graph(graph_patterns, num_graphs, conn);
}

static void
print_ip_addr(struct in6_addr *addr, int prefixlen, struct dao_ds *str)
{
	rte_be32_t ip4;
	char buf[256];

	if (IN6_IS_ADDR_V4MAPPED(addr)) {
		ip4 = dao_in6_addr_get_mapped_ipv4(addr);
		inet_ntop(AF_INET, (void *)&ip4, buf, sizeof(buf));
		if (prefixlen > 0)
			dao_ds_put_format(str, "%15s/%2d ", buf, prefixlen);
		else
			dao_ds_put_format(str, "%18s ", buf);
	} else {
		inet_ntop(AF_INET6, (void *)addr, buf, sizeof(buf));
		dao_ds_put_format(str, "%s ", buf);
	}
}

void
cmd_show_routes_parsed(__rte_unused void *parsed_result, __rte_unused struct cmdline *cl,
		       __rte_unused void *data)
{
	secgw_route_dump_entry_t *rdentry = NULL;
	struct dao_ds ds = DS_EMPTY_INITIALIZER;
	struct scli_conn *conn = NULL;
	secgw_worker_t *sgw  = NULL;
	dao_worker_t *dw = NULL;
	int n_routes = 0;

	dw = dao_workers_control_worker_get(dao_workers_get());
	if (!dw)
		return;

	if (dao_workers_app_data_get(dw, (void **)&sgw, NULL))
		return;

	if (!sgw->cli_conn)
		return;

	conn = sgw->cli_conn;

	STAILQ_FOREACH(rdentry, &secgw_route_dump_list, next_dump_entry)
		n_routes++;

	if (n_routes)
		dao_ds_put_format(&ds, "%6s%7s%1s%12s%6s%11s%17s\n",
				  "Route", "Type", " ", "IP", " ", "Device", "Rewrite-Data");

	STAILQ_FOREACH(rdentry, &secgw_route_dump_list, next_dump_entry) {
		dao_ds_put_format(&ds, "%6d", rdentry->route_index);
		switch (rdentry->edge) {
		case SECGW_NODE_IP4_LOOKUP_NEXT_REWRITE:
			dao_ds_put_format(&ds, "%8s ", "forward");
		break;
		case SECGW_NODE_IP4_LOOKUP_NEXT_IP4_LOCAL:
			dao_ds_put_format(&ds, "%8s ", "local");
		break;
		default:
			dao_ds_put_format(&ds, "%8s ", "unknown");
		break;
		}
		print_ip_addr(&rdentry->ip_addr.addr, rdentry->ip_addr.prefixlen, &ds);
		if (secgw_get_device(rdentry->device_id))
			dao_ds_put_format(&ds, " %9s",
					  (secgw_get_device(rdentry->device_id))->dev_name);
		else
			dao_ds_put_format(&ds, " %9d", rdentry->device_id);

		if (rdentry->rewrite_length) {
			dao_ds_put_format(&ds, " %3s", " ");
			dao_ds_put_hex(&ds, rdentry->rewrite_data, rdentry->rewrite_length);
		}
		dao_ds_put_cstr(&ds, "\n");
	}
	snprintf(conn->msg_out, conn->msg_out_len_max, "%s", dao_ds_cstr(&ds));
	dao_ds_destroy(&ds);
}

void
cmd_show_neigh_parsed(__rte_unused void *parsed_result, __rte_unused struct cmdline *cl,
		      __rte_unused void *data)
{
	secgw_route_partial_entry_t *rpentry = NULL;
	struct dao_ds ds = DS_EMPTY_INITIALIZER;
	secgw_neigh_entry_t *nentry = NULL;
	secgw_device_t *sdev = NULL;
	struct scli_conn *conn = NULL;
	secgw_worker_t *sgw  = NULL;
	dao_worker_t *dw = NULL;
	int n_neigh = 0;

	dw = dao_workers_control_worker_get(dao_workers_get());
	if (!dw)
		return;

	if (dao_workers_app_data_get(dw, (void **)&sgw, NULL))
		return;

	if (!sgw->cli_conn)
		return;

	conn = sgw->cli_conn;

	STAILQ_FOREACH(nentry, &secgw_neigh_list, next_neigh_entry) {
		if (nentry->edge == SECGW_NODE_IP4_LOOKUP_NEXT_REWRITE)
			n_neigh++;
	}

	STAILQ_FOREACH(rpentry, &secgw_route_partial_list, next_partial_entry)
		n_neigh++;

	if (n_neigh)
		dao_ds_put_format(&ds, "%12s%12s%6s%11s%17s\n",
				  "Type", "IP", " ", "Device", "Link addr");

	STAILQ_FOREACH(nentry, &secgw_neigh_list, next_neigh_entry) {
		switch (nentry->edge) {
		case SECGW_NODE_IP4_LOOKUP_NEXT_REWRITE:
			dao_ds_put_format(&ds, "%12s ", " ");
			print_ip_addr(&nentry->ip_addr, nentry->prefixlen, &ds);
			if (secgw_get_device(nentry->device_index)) {
				sdev = secgw_get_device(nentry->device_index);
				dao_ds_put_format(&ds, " %9s",
						  sdev->dev_name);
			} else {
				dao_ds_put_format(&ds, " %9d", nentry->device_index);
			}
			dao_ds_put_format(&ds, "%3s%2x:%2x:%2x:%2x:%2x:%2x", " ",
					  nentry->dest_ll_addr[0], nentry->dest_ll_addr[1],
					  nentry->dest_ll_addr[2], nentry->dest_ll_addr[3],
					  nentry->dest_ll_addr[4], nentry->dest_ll_addr[5]);
			dao_ds_put_cstr(&ds, "\n");
		break;
		default:
		break;
		}
	}
	STAILQ_FOREACH(rpentry, &secgw_route_partial_list, next_partial_entry) {
		if (rpentry->partial_route.is_next_hop) {
			dao_ds_put_format(&ds, "%12s ", "unresolved");
			print_ip_addr(&rpentry->partial_route.via_in6_addr,
				      rpentry->partial_route.via_addr_prefixlen, &ds);
			if (secgw_get_device(rpentry->partial_route.app_if_cookie)) {
				sdev = secgw_get_device(rpentry->partial_route.app_if_cookie);
				sdev = secgw_get_device(sdev->paired_device_index);
				dao_ds_put_format(&ds, " %9s",
						  sdev->dev_name);
			} else {
				dao_ds_put_format(&ds, " %9d",
						  rpentry->partial_route.app_if_cookie);
			}
		} else {
			dao_ds_put_format(&ds, " %9d", nentry->device_index);
		}
		dao_ds_put_format(&ds, " %10s", "?");
		dao_ds_put_cstr(&ds, "\n");
	}
	snprintf(conn->msg_out, conn->msg_out_len_max, "%s", dao_ds_cstr(&ds));
	dao_ds_destroy(&ds);
}

