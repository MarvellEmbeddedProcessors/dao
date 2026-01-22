/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __RDMA_CONFIG_H__
#define __RDMA_CONFIG_H__

#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_rcu_qsbr.h>

/* Forward declaration */
struct rdma_main_cfg_data;

struct rdma_graph_map {
	uint16_t id;
};

#define RDMA_MAX_DEVS 16

extern struct rdma_graph_map rdma_map[RDMA_MAX_DEVS];
extern struct rdma_graph_map eth_map[RDMA_MAX_DEVS];

typedef struct rdma_config_param {
	/* Debug mode enable */
	bool enable_debug;
	/* Ports set in promiscuous mode off by default. */
	int promiscuous_on;
	/**< Use separate buffer pools per port; disabled */
	int per_port_pool;
	/* Max packet length */
	uint32_t max_pkt_len;
	/* Optional override for mbuf data buffer size (bytes); 0 = use default */
	uint32_t mbuf_data_size;
	/* mask of enabled ports */
	uint32_t enabled_port_mask;
	/* mask of enabled dev */
	uint32_t enabled_dev_mask;
	/* Optional override for number of mbufs per pool; 0 = auto-calc */
	uint32_t num_mbufs;
	/* Pcap trace */
	char pcap_filename[RTE_GRAPH_PCAP_FILE_SZ];
	uint64_t packet_to_capture;
	int pcap_trace_enable;
	/* Enable graph statistics */
	bool enable_graph_stats;
	/* Number of RDMA ports */
	uint8_t num_rport;
	/* RDMA port mapping enabled*/
	int rdma_map_config_enable;
	/* DMA flush threshold for batching */
	uint16_t dma_flush_thr;
	/* DMA vchan descriptor count (nb_desc); default 2048 if not set */
	uint16_t dma_nb_desc;
	/* Disable congestion control globally (baseline CC). 0=enabled(default),1=disabled */
	bool disable_cc;
} rdma_config_param_t;

/* display usage */
void rdma_print_usage(const char *prgname);

/* Parse the argument given in the command line of the application */
int rdma_parse_args(int argc, char **argv, struct rdma_main_cfg_data *rdma_main_cfg);

#endif /* __RDMA_CONFIG_H__ */
