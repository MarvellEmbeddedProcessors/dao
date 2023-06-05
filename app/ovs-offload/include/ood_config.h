/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __OOD_CONFIG_H__
#define __OOD_CONFIG_H__

#include <rte_ethdev.h>
#include <rte_graph.h>

/* Forward declaration */
struct ood_main_cfg_data;

struct port_pair_params {
#define NUM_PORTS 2
	uint16_t port[NUM_PORTS];
} __rte_cache_aligned;

typedef struct ood_config_param {
	/* Debug mode enable */
	bool enable_debug;
	/* MAC updating enabled by default */
	int mac_updating;
	/* Ports set in promiscuous mode off by default. */
	int promiscuous_on;
	/**< Use separate buffer pools per port; disabled */
	int per_port_pool;
	/* Max packet length */
	uint32_t max_pkt_len;
	/* mask of enabled ports */
	uint32_t enabled_port_mask;
	/* Total no of port pairs */
	uint16_t nb_port_pair_params;
	struct port_pair_params port_pair_param[RTE_MAX_ETHPORTS / 2];
	/* Pcap trace */
	char pcap_filename[RTE_GRAPH_PCAP_FILE_SZ];
	uint64_t packet_to_capture;
	int pcap_trace_enable;
	/* Enable graph statistics */
	bool enable_graph_stats;
} ood_config_param_t;

/* display usage */
void ood_print_usage(const char *prgname);

/* Parse the argument given in the command line of the application */
int ood_parse_args(int argc, char **argv, struct ood_main_cfg_data *ood_main_cfg);

#endif /* __OOD_CONFIG_H__ */
