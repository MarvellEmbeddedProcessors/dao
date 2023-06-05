/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2024 Marvell.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_dmadev.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_graph_worker.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_rcu_qsbr.h>
#include <rte_string_fns.h>
#include <rte_vect.h>

#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>

#include <dao_dma.h>
#include <dao_virtio_netdev.h>

#include "l2_node.h"

/* Log type */
#define RTE_LOGTYPE_VIRTIO_L2FWD RTE_LOGTYPE_USER1

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024

#define DEFAULT_QUEUES_PER_PORT 1

#define MAX_ETHDEV_RX_PER_LCORE 128
#define MAX_VIRTIO_RX_PER_LCORE 128

#define MAX_LCORE_PARAMS 1024

#define NB_SOCKETS 8

#define MAX_DMA_VCHANS 4

#define APP_INFO(fmt, args...) RTE_LOG(INFO, VIRTIO_L2FWD, fmt, ##args)

#define APP_INFO_NH(fmt, args...) rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VIRTIO_L2FWD, fmt, ##args)

#define APP_ERR(fmt, args...) RTE_LOG(ERR, VIRTIO_L2FWD, fmt, ##args)

struct lcore_ethdev_rx {
	uint16_t portid;
	char node_name[RTE_NODE_NAMESIZE];
	struct l2_ethdev_rx_node_ctx *ethdev_rx;
	/* Tx can either be ethdev or virtio */
	struct l2_ethdev_tx_node_ctx *ethdev_tx;
	struct l2_virtio_tx_node_ctx *virtio_tx;
};

struct lcore_virtio_rx {
	uint16_t virtio_devid;
	char node_name[RTE_NODE_NAMESIZE];
	struct l2_virtio_rx_node_ctx *virtio_rx;
	/* Tx can either be ethdev or virtio */
	struct l2_ethdev_tx_node_ctx *ethdev_tx;
	struct l2_virtio_tx_node_ctx *virtio_tx;
};

/* Lcore conf */
struct lcore_conf {
	/* Fast path accessed */
	uint64_t netdev_map;
	uint16_t netdev_qp_count[DAO_VIRTIO_DEV_MAX];

	uint16_t nb_virtio_rx;
	struct lcore_virtio_rx virtio_rx[MAX_VIRTIO_RX_PER_LCORE];
	uint16_t nb_ethdev_rx;
	struct lcore_ethdev_rx ethdev_rx[MAX_ETHDEV_RX_PER_LCORE];
	uint32_t weight;

	bool service_lcore;
	int dev2mem_id;
	int mem2dev_id;
	int nb_vchans;
	struct rte_graph *graph;
	char name[RTE_GRAPH_NAMESIZE];
	rte_graph_t graph_id;
	struct rte_rcu_qsbr *qs_v;
} __rte_cache_aligned;

struct vlan_filter {
	TAILQ_ENTRY(vlan_filter) next;
	struct rte_flow *flow;
	uint16_t vlan_tci;
};

static uint64_t lcore_eth_mask[RTE_MAX_ETHPORTS];
static uint64_t lcore_virtio_mask[DAO_VIRTIO_DEV_MAX];

/* virtio_devid->eth_port */
struct l2fwd_map {
	uint16_t id;
#define ETHDEV_NEXT 1
#define VIRTIO_NEXT 2
	uint8_t type;
};

/* Static global variables used within this file. */
static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;

static struct lcore_conf lcore_conf[RTE_MAX_LCORE];
static uint16_t lcore_list_wt_sorted[RTE_MAX_LCORE];

/**< Ports set in promiscuous mode off by default. */
static int promiscuous_on;

static int disable_tx_mseg; /**< disable default ethdev Tx multi-seg offload */
static int per_port_pool; /**< Use separate buffer pools per port; disabled */
			  /**< by default */

static volatile bool force_quit;

static struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

/* Mask of enabled ports */
static uint64_t port_mask_ena[2];
static uint16_t nb_ethdevs;
/* Mask of enabled virtio devs */
static uint64_t virtio_mask_ena[2];
static uint16_t nb_virtio_netdevs;

/* Pcap trace */
static char pcap_filename[RTE_GRAPH_PCAP_FILE_SZ];
static uint64_t packet_to_capture = 1024;
static int pcap_trace_enable;
static int16_t dev2mem_ids[32];
static int16_t mem2dev_ids[32];
static uint16_t dev2mem_cnt;
static uint16_t mem2dev_cnt;
static int wrkr_dma_devs;
static uint16_t dma_flush_thr;
static uint32_t pktmbuf_count = 128 * 1024;

static bool override_dma_vfid;
static uint16_t dma_vfid;

static struct l2fwd_map virtio_map[DAO_VIRTIO_DEV_MAX];
static struct l2fwd_map eth_map[DAO_VIRTIO_DEV_MAX];

static struct rte_eth_dev_info eth_dev_info[RTE_MAX_ETHPORTS];
static struct rte_eth_conf eth_dev_conf[RTE_MAX_ETHPORTS];
static uint16_t eth_dev_q_count[RTE_MAX_ETHPORTS];

static rte_node_t ethdev_rx_nodes[DAO_VIRTIO_DEV_MAX];
static rte_node_t ethdev_tx_nodes[DAO_VIRTIO_DEV_MAX];
static rte_node_t virtio_rx_nodes[DAO_VIRTIO_DEV_MAX];
static rte_node_t virtio_tx_nodes[DAO_VIRTIO_DEV_MAX];

TAILQ_HEAD(vlan_filter_head, vlan_filter);
static struct vlan_filter_head virtio_dev_vlan_filters[DAO_VIRTIO_DEV_MAX];

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = RTE_ETH_MQ_RX_RSS,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = RTE_ETH_RSS_IP,
		},
	},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
		.offloads = RTE_ETH_TX_OFFLOAD_MULTI_SEGS,
	},
};

static int stats_enable;
static int verbose_stats;

static uint32_t max_pkt_len;
static int pool_buf_len = RTE_MBUF_DEFAULT_BUF_SIZE;

static struct rte_mempool *e_pktmbuf_pool[RTE_MAX_ETHPORTS];
static struct rte_mempool *v_pktmbuf_pool[DAO_VIRTIO_DEV_MAX];

static uint16_t virtio_netdev_dma_vchans[DAO_VIRTIO_DEV_MAX];
static uint16_t virtio_netdev_reta_sz[DAO_VIRTIO_DEV_MAX];
static bool virtio_netdev_autofree = true;
static uint16_t pem_devid;

/* RCU QSBR variable */
static struct rte_rcu_qsbr *qs_v;

struct rte_graph_cluster_stats *graph_stats[RTE_MAX_LCORE];

static bool
is_ethdev_enabled(uint16_t portid)
{
	uint64_t i = portid / 64;
	uint64_t j = portid % 64;

	if (i > 1)
		return false;
	return port_mask_ena[i] & RTE_BIT64(j);
}

static bool
is_virtio_dev_enabled(uint16_t virtio_devid)
{
	uint64_t i = virtio_devid / 64;
	uint64_t j = virtio_devid % 64;

	if (i > 1)
		return false;
	return virtio_mask_ena[i] & RTE_BIT64(j);
}

static int
check_lcore_params(void)
{
	uint8_t lcore;
	uint16_t i;

	for (i = 0; i < RTE_MAX_ETHPORTS; ++i) {
		if (!is_ethdev_enabled(i))
			continue;

		for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
			if (!(RTE_BIT64(lcore) & lcore_eth_mask[i]))
				continue;

			if (!rte_lcore_is_enabled(lcore)) {
				APP_ERR("Error: lcore %hhu is not enabled in lcore mask\n", lcore);
				return -1;
			}

			if (lcore == rte_get_main_lcore()) {
				APP_ERR("Error: lcore %u is main lcore\n", lcore);
				return -1;
			}
		}
	}

	for (i = 0; i < DAO_VIRTIO_DEV_MAX; ++i) {
		if (!is_virtio_dev_enabled(i))
			continue;

		for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
			if (!(RTE_BIT64(lcore) & lcore_virtio_mask[i]))
				continue;

			if (!rte_lcore_is_enabled(lcore)) {
				APP_ERR("Error: lcore %hhu is not enabled in lcore mask\n", lcore);
				return -1;
			}

			if (lcore == rte_get_main_lcore()) {
				APP_ERR("Error: lcore %u is main lcore\n", lcore);
				return -1;
			}
		}
	}
	return 0;
}

static int
check_port_config(void)
{
	uint16_t portid;

	for (portid = 0; portid < RTE_MAX_ETHPORTS; ++portid) {
		if (!is_ethdev_enabled(portid))
			continue;

		if (!rte_eth_dev_is_valid_port(portid)) {
			APP_INFO("Port %u is not present on the board\n", portid);
			return -1;
		}
	}

	return 0;
}

static int
check_virtio_config(void)
{
	uint16_t nb_lcores = 0, nb_dma_devs;
	uint16_t lcore;

	nb_dma_devs = rte_dma_count_avail();

	/* Check if we have enough DMA devices one per lcore */
	for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++)
		if (lcore_conf[lcore].nb_virtio_rx || lcore_conf[lcore].nb_ethdev_rx)
			nb_lcores++;

	/* Service lcore, control dma device */
	nb_lcores += 2;

	/* 2 dma devices for control */
	wrkr_dma_devs = 2 + (nb_lcores * 2);
	if (nb_dma_devs < wrkr_dma_devs) {
		APP_INFO("%u DMA devices not enough, need at least %u for %u lcores,"
			 " 1 ctrl core, 1 service core\n",
			 nb_dma_devs, wrkr_dma_devs, nb_lcores - 2);
		return -1;
	}

	return 0;
}

static int
init_lcore_ethdev_rx(void)
{
	uint16_t portid, nb_ethdev_rx;
	uint8_t lcore;

	for (portid = 0; portid < RTE_MAX_ETHPORTS; ++portid) {
		if (!is_ethdev_enabled(portid))
			continue;

		for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
			if (!(RTE_BIT64(lcore) & lcore_eth_mask[portid]))
				continue;

			nb_ethdev_rx = lcore_conf[lcore].nb_ethdev_rx;
			if (nb_ethdev_rx >= MAX_ETHDEV_RX_PER_LCORE) {
				APP_ERR("Error: too many ethdev rx (%u) for lcore: %u\n",
					(unsigned int)nb_ethdev_rx + 1, (unsigned int)lcore);
				return -1;
			}

			lcore_conf[lcore].ethdev_rx[nb_ethdev_rx].portid = portid;
			snprintf(lcore_conf[lcore].ethdev_rx[nb_ethdev_rx].node_name,
				 RTE_NODE_NAMESIZE, "l2_ethdev_rx-%u", portid);
			lcore_conf[lcore].nb_ethdev_rx++;
		}
	}

	/* Initialize lcore list */
	for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++)
		lcore_list_wt_sorted[lcore] = lcore;

	return 0;
}

static int
init_lcore_virtio_rx(void)
{
	uint16_t virtio_devid, nb_virtio_rx;
	uint8_t lcore;

	for (virtio_devid = 0; virtio_devid < DAO_VIRTIO_DEV_MAX; ++virtio_devid) {
		if (!is_virtio_dev_enabled(virtio_devid))
			continue;

		for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
			if (!(RTE_BIT64(lcore) & lcore_virtio_mask[virtio_devid]))
				continue;

			nb_virtio_rx = lcore_conf[lcore].nb_virtio_rx;

			lcore_conf[lcore].virtio_rx[nb_virtio_rx].virtio_devid = virtio_devid;
			snprintf(lcore_conf[lcore].virtio_rx[nb_virtio_rx].node_name,
				 RTE_NODE_NAMESIZE, "l2_virtio_rx-%u", virtio_devid);
			lcore_conf[lcore].nb_virtio_rx++;
		}
	}

	return 0;
}

/* Display usage */
static void
print_usage(const char *prgname)
{
	fprintf(stderr,
		"%s [EAL options] --"
		" -p PORTMASK_L[,PORTMASK_H]"
		" -v VIRTIOMASK_L[,VIRTIOMASK_H]"
		" [-d DMA_FLUSH_THR]"
		" [-P]"
		" [-s]"
		" [-f]"
		" [-y DMA_VFID]"
		" [--eth-config (port,lcore_mask)[,(port, lcore_mask)]]"
		" [--virtio-config (dev,lcore_mask)[,(dev,lcore_mask)]]"
		" [--l2fwd-map (port,dev)[,(port,dev)]]"
		" [--max-pkt-len PKTLEN]"
		" [--pool-buf-len PKTLEN]"
		" [--per-port-pool]"
		" [--disable-tx-mseg]"
		" [--num-pkt-cap]\n\n"

		"  -p PORTMASK_L[,PORTMASK_H]: Hexadecimal bitmask of ports to configure\n"
		"  -v VIRTIOMASK_L[,VIRTIOMASK_H]: Hexadecimal bitmask of virtio to configure\n"
		"  -d DMA_FLUSH_THR: Number of SGE's before DMA is flushed(1..15). Default is 8.\n"
		"  -P : Enable promiscuous mode\n"
		"  -s : Enable stats. Giving it multiple times makes stats verbose.\n"
		"  -f : Disable auto free with virtio Tx do sw freeing\n"
		"  -y : DMA_VFID: Value to override DMA VCHAN VFID\n"
		"  --eth-config (port,lcore_mask): Ethdev rx lcore mapping\n"
		"           Default is half of the found lcores would be mapped to all ethdevs\n"
		"  --virtio-config (dev,lcore_mask)[,(dev,lcore_mask)] : Virtio rx lcore mapping\n"
		"           Default is half of the found lcores would be mapped to all virtio devs\n"
		"  --l2fwd-map (eX,vY)[,(eX,vY)] : Ethdev Virtio map\n"
		"           Default is (e0,v0),(e1,v1)... i.e ethdev 0 is mapped to virtio 0\n"
		"  --max-pkt-len PKTLEN: maximum packet length in decimal (64-9600)\n"
		"  --pool-buf-len PKTLEN: maximum pool buffer length in decimal (64-9600)\n"
		"  --per-port-pool: Use separate buffer pool per port\n"
		"  --disable-tx-mseg: Disable ethdev Tx multi-seg offload capability\n"
		"  --pcap-enable: Enables pcap capture\n"
		"  --pcap-num-cap NUMPKT: Number of packets to capture\n"
		"  --pcap-file-name NAME: Pcap file name\n\n",
		prgname);
}

static uint64_t
parse_num_pkt_cap(const char *num_pkt_cap)
{
	uint64_t num_pkt;
	char *end = NULL;

	/* Parse decimal string */
	num_pkt = strtoull(num_pkt_cap, &end, 10);
	if ((num_pkt_cap[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	if (num_pkt == 0)
		return 0;

	return num_pkt;
}

static int
parse_max_pkt_len(const char *pktlen)
{
	unsigned long len;
	char *end = NULL;

	/* Parse decimal string */
	len = strtoul(pktlen, &end, 10);
	if ((pktlen[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (len == 0)
		return -1;

	return len;
}

static uint64_t
parse_uint(const char *str)
{
	char *end = NULL;
	unsigned long val;

	/* Parse hexadecimal string */
	val = strtoul(str, &end, 0);
	if ((str[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return val;
}

static int
parse_eth_config(const char *q_arg)
{
	enum fieldnames { FLD_PORT = 0, FLD_LCORE_MASK, _NUM_FLD };
	unsigned long int_fld[_NUM_FLD];
	const char *p, *p0 = q_arg;
	char *str_fld[_NUM_FLD];
	uint32_t size;
	char s[256];
	char *end;
	int i;

	while ((p = strchr(p0, '(')) != NULL) {
		++p;
		p0 = strchr(p, ')');
		if (p0 == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		memcpy(s, p, size);
		s[size] = '\0';
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i])
				return -1;
		}

		if (int_fld[FLD_PORT] >= RTE_MAX_ETHPORTS ||
		    int_fld[FLD_LCORE_MASK] >= RTE_BIT64(RTE_MAX_LCORE)) {
			APP_ERR("Invalid port/lcore mask\n");
			return -1;
		}

		lcore_eth_mask[int_fld[FLD_PORT]] = int_fld[FLD_LCORE_MASK];
	}

	return 0;
}

static int
parse_virtio_config(const char *q_arg)
{
	enum fieldnames { FLD_DEV = 0, FLD_LCORE_MASK, _NUM_FLD };
	unsigned long int_fld[_NUM_FLD];
	const char *p, *p0 = q_arg;
	char *str_fld[_NUM_FLD];
	uint32_t size;
	char s[256];
	char *end;
	int i;

	while ((p = strchr(p0, '(')) != NULL) {
		++p;
		p0 = strchr(p, ')');
		if (p0 == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		memcpy(s, p, size);
		s[size] = '\0';
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i])
				return -1;
		}

		if (int_fld[FLD_DEV] >= DAO_VIRTIO_DEV_MAX ||
		    int_fld[FLD_LCORE_MASK] >= RTE_BIT64(RTE_MAX_LCORE)) {
			APP_ERR("Invalid virtiodev/lcore mask\n");
			return -1;
		}

		lcore_virtio_mask[int_fld[FLD_DEV]] = int_fld[FLD_LCORE_MASK];
	}

	return 0;
}

static int
parse_l2fwd_map_config(const char *q_arg)
{
	enum fieldnames { FLD_PORTA = 0, FLD_PORTB, _NUM_FLD };
	unsigned long int_fld[_NUM_FLD];
	const char *p, *p0 = q_arg;
	char *str_fld[_NUM_FLD];
	uint32_t size;
	char s[256];
	char *end;
	int i;

	while ((p = strchr(p0, '(')) != NULL) {
		++p;
		p0 = strchr(p, ')');
		if (p0 == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		memcpy(s, p, size);
		s[size] = '\0';
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i] + 1, &end, 0);
			if (errno != 0 || end == str_fld[i])
				return -1;
		}

		if (int_fld[FLD_PORTA] >= RTE_MAX_ETHPORTS) {
			APP_ERR("Invalid port\n");
			return -1;
		}

		if (int_fld[FLD_PORTB] >= RTE_MAX_ETHPORTS) {
			APP_ERR("Invalid virtio_devid\n");
			return -1;
		}

		if (*str_fld[FLD_PORTA] == 'v') {
			virtio_map[int_fld[FLD_PORTA]].id = int_fld[FLD_PORTB];
			if (*str_fld[FLD_PORTB] == 'v') {
				virtio_map[int_fld[FLD_PORTA]].type = VIRTIO_NEXT;

				virtio_map[int_fld[FLD_PORTB]].id = int_fld[FLD_PORTA];
				virtio_map[int_fld[FLD_PORTB]].type = VIRTIO_NEXT;
			} else if (*str_fld[FLD_PORTB] == 'e') {
				virtio_map[int_fld[FLD_PORTA]].type = ETHDEV_NEXT;

				eth_map[int_fld[FLD_PORTB]].id = int_fld[FLD_PORTA];
				eth_map[int_fld[FLD_PORTB]].type = VIRTIO_NEXT;
			} else {
				APP_ERR("Invalid port type, not 'v' or 'e'\n");
				return -1;
			}
		} else if (*str_fld[FLD_PORTA] == 'e') {
			eth_map[int_fld[FLD_PORTA]].id = int_fld[FLD_PORTB];
			if (*str_fld[FLD_PORTB] == 'v') {
				eth_map[int_fld[FLD_PORTA]].type = VIRTIO_NEXT;

				virtio_map[int_fld[FLD_PORTB]].id = int_fld[FLD_PORTA];
				virtio_map[int_fld[FLD_PORTB]].type = ETHDEV_NEXT;
			} else if (*str_fld[FLD_PORTB] == 'e') {
				eth_map[int_fld[FLD_PORTA]].type = ETHDEV_NEXT;

				eth_map[int_fld[FLD_PORTB]].id = int_fld[FLD_PORTA];
				eth_map[int_fld[FLD_PORTB]].type = ETHDEV_NEXT;
			} else {
				APP_ERR("Invalid port type, not 'v' or 'e'\n");
				return -1;
			}
		} else {
			APP_ERR("Invalid port type, not 'v' or 'e'\n");
			return -1;
		}
	}

	return 0;
}

#define MAX_JUMBO_PKT_LEN  9600
#define MEMPOOL_CACHE_SIZE 512

static const char short_options[] = "p:" /* portmask */
				    "v:" /* virt dev mask */
				    "d:" /* DMA flush threshold */
				    "P"  /* promiscuous */
				    "f"  /* Disable auto free */
				    "s"  /* stats enable */
				    "y:" /* Override DMA vfid */
	;

#define CMD_LINE_OPT_ETH_CONFIG    "eth-config"
#define CMD_LINE_OPT_VIRTIO_CONFIG "virtio-config"
#define CMD_LINE_OPT_L2FWD_MAP     "l2fwd-map"
#define CMD_LINE_OPT_MAX_PKT_LEN   "max-pkt-len"
#define CMD_LINE_OPT_MAX_BUF_LEN   "pool-buf-len"
#define CMD_LINE_OPT_PER_PORT_POOL "per-port-pool"
#define CMD_LINE_OPT_DIS_TX_MSEG   "disable-tx-mseg"
#define CMD_LINE_OPT_PCAP_ENABLE   "pcap-enable"
#define CMD_LINE_OPT_NUM_PKT_CAP   "pcap-num-cap"
#define CMD_LINE_OPT_PCAP_FILENAME "pcap-file-name"
enum {
	/* Long options mapped to a short option */

	/* First long only option value must be >= 256, so that we won't
	 * conflict with short options
	 */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_ETH_CONFIG_NUM,
	CMD_LINE_OPT_VIRTIO_CONFIG_NUM,
	CMD_LINE_OPT_L2FWD_MAP_NUM,
	CMD_LINE_OPT_MAX_PKT_LEN_NUM,
	CMD_LINE_OPT_MAX_BUF_LEN_NUM,
	CMD_LINE_OPT_PARSE_PER_PORT_POOL,
	CMD_LINE_OPT_PARSE_DIS_TX_MSEG,
	CMD_LINE_OPT_PARSE_PCAP_ENABLE,
	CMD_LINE_OPT_PARSE_NUM_PKT_CAP,
	CMD_LINE_OPT_PCAP_FILENAME_CAP,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_ETH_CONFIG, 1, 0, CMD_LINE_OPT_ETH_CONFIG_NUM},
	{CMD_LINE_OPT_VIRTIO_CONFIG, 1, 0, CMD_LINE_OPT_VIRTIO_CONFIG_NUM},
	{CMD_LINE_OPT_L2FWD_MAP, 1, 0, CMD_LINE_OPT_L2FWD_MAP_NUM},
	{CMD_LINE_OPT_MAX_PKT_LEN, 1, 0, CMD_LINE_OPT_MAX_PKT_LEN_NUM},
	{CMD_LINE_OPT_MAX_BUF_LEN, 1, 0, CMD_LINE_OPT_MAX_BUF_LEN_NUM},
	{CMD_LINE_OPT_PER_PORT_POOL, 0, 0, CMD_LINE_OPT_PARSE_PER_PORT_POOL},
	{CMD_LINE_OPT_DIS_TX_MSEG, 0, 0, CMD_LINE_OPT_PARSE_DIS_TX_MSEG},
	{CMD_LINE_OPT_PCAP_ENABLE, 0, 0, CMD_LINE_OPT_PARSE_PCAP_ENABLE},
	{CMD_LINE_OPT_NUM_PKT_CAP, 1, 0, CMD_LINE_OPT_PARSE_NUM_PKT_CAP},
	{CMD_LINE_OPT_PCAP_FILENAME, 1, 0, CMD_LINE_OPT_PCAP_FILENAME_CAP},
	{NULL, 0, 0, 0},
};

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	uint16_t portid, virtio_devid, j;
	uint64_t virtio_mask_dflt = 0;
	uint64_t eth_mask_dflt = 0;
	uint16_t service_lcore = 0;
	char *prgname = argv[0];
	char *str, *saveptr;
	int option_index;
	char **argvopt;
	uint8_t lcore;
	int opt, rc;
	int i;

	/* Setup l2fwd map to defaults */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		eth_map[portid].type = VIRTIO_NEXT;
		eth_map[portid].id = portid;
	}

	for (virtio_devid = 0; virtio_devid < RTE_MAX_ETHPORTS; virtio_devid++) {
		virtio_map[virtio_devid].type = ETHDEV_NEXT;
		virtio_map[virtio_devid].id = virtio_devid;
	}

	/* Setup lcore mask of ethdev and virtio dev to default
	 * One for service lcore, one for main lcore and rest divided
	 * among ethdev and virtio.
	 */
	for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		if (!rte_lcore_is_enabled(lcore) || (lcore == rte_get_main_lcore()))
			continue;

		service_lcore = lcore;
		break;
	}

	j = 0;
	lcore = 0;
	for (; lcore < RTE_MAX_LCORE; lcore++) {
		if (j == (rte_lcore_count() - 2) / 2)
			break;
		if (!rte_lcore_is_enabled(lcore) || (lcore == rte_get_main_lcore()) ||
		    lcore == service_lcore)
			continue;

		eth_mask_dflt |= RTE_BIT64(lcore);
		j++;
	}

	j = 0;
	for (; lcore < RTE_MAX_LCORE; lcore++) {
		if (j == (rte_lcore_count() - 2) / 2)
			break;
		if (!rte_lcore_is_enabled(lcore) || (lcore == rte_get_main_lcore()) ||
		    lcore == service_lcore)
			continue;

		virtio_mask_dflt |= RTE_BIT64(lcore);
		j++;
	}

	for (i = 0; i < RTE_MAX_ETHPORTS; i++)
		lcore_eth_mask[i] = eth_mask_dflt;
	for (i = 0; i < DAO_VIRTIO_DEV_MAX; i++)
		lcore_virtio_mask[i] = virtio_mask_dflt;

	argvopt = argv;

	/* Error or normal output strings. */
	while ((opt = getopt_long(argc, argvopt, short_options, lgopts, &option_index)) != EOF) {
		switch (opt) {
		/* Portmask */
		case 'p':
			str = strtok_r(optarg, ",", &saveptr);
			if (str)
				port_mask_ena[0] = parse_uint(str);
			str = strtok_r(NULL, ",", &saveptr);
			if (str)
				port_mask_ena[1] = parse_uint(str);

			if (port_mask_ena[0] == 0 && port_mask_ena[1] == 0) {
				APP_ERR("Invalid portmask\n");
				print_usage(prgname);
				return -1;
			}
			nb_ethdevs = __builtin_popcountl(port_mask_ena[0]);
			nb_ethdevs += __builtin_popcountl(port_mask_ena[1]);
			break;
		case 'v':
			str = strtok_r(optarg, ",", &saveptr);
			if (str)
				virtio_mask_ena[0] = parse_uint(str);
			str = strtok_r(NULL, ",", &saveptr);
			if (str)
				virtio_mask_ena[1] = parse_uint(str);

			if (virtio_mask_ena[0] == 0 && virtio_mask_ena[1] == 0) {
				APP_ERR("Invalid portmask\n");
				print_usage(prgname);
				return -1;
			}
			nb_virtio_netdevs = __builtin_popcountl(virtio_mask_ena[0]);
			nb_virtio_netdevs += __builtin_popcountl(virtio_mask_ena[1]);
			break;
		case 'd':
			dma_flush_thr = parse_uint(optarg);
			if (dma_flush_thr < 1 || dma_flush_thr > 15) {
				APP_ERR("Invalid dma flush threshold\n");
				print_usage(prgname);
				return -1;
			}
			break;

		case 'P':
			promiscuous_on = 1;
			break;
		case 's':
			if (stats_enable)
				verbose_stats++;
			else
				stats_enable = 1;
			break;
		case 'f':
			virtio_netdev_autofree = false;
			break;
		case 'y':
			override_dma_vfid = true;
			dma_vfid = parse_uint(optarg);
			break;

		/* Long options */
		case CMD_LINE_OPT_ETH_CONFIG_NUM:
			rc = parse_eth_config(optarg);
			if (rc) {
				APP_ERR("Invalid eth config\n");
				print_usage(prgname);
				return -1;
			}
			break;

		case CMD_LINE_OPT_VIRTIO_CONFIG_NUM:
			rc = parse_virtio_config(optarg);
			if (rc) {
				APP_ERR("Invalid virt config\n");
				print_usage(prgname);
				return -1;
			}
			break;
		case CMD_LINE_OPT_L2FWD_MAP_NUM:
			rc = parse_l2fwd_map_config(optarg);
			if (rc) {
				APP_ERR("Invalid eth config\n");
				print_usage(prgname);
				return -1;
			}
			break;
		case CMD_LINE_OPT_MAX_PKT_LEN_NUM: {
			max_pkt_len = parse_max_pkt_len(optarg);
			break;
		}

		case CMD_LINE_OPT_MAX_BUF_LEN_NUM:
			pool_buf_len = parse_max_pkt_len(optarg);
			if (pool_buf_len == -1)
				pool_buf_len = RTE_MBUF_DEFAULT_BUF_SIZE;
			break;

		case CMD_LINE_OPT_PARSE_PER_PORT_POOL:
			APP_INFO("Per port buffer pool is enabled\n");
			per_port_pool = 1;
			break;

		case CMD_LINE_OPT_PARSE_DIS_TX_MSEG:
			APP_INFO("Ethdev Tx multi-seg offload is disabled\n");
			disable_tx_mseg = 1;
			break;

		case CMD_LINE_OPT_PARSE_PCAP_ENABLE:
			APP_INFO("Packet capture enabled\n");
			pcap_trace_enable = 1;
			break;

		case CMD_LINE_OPT_PARSE_NUM_PKT_CAP:
			packet_to_capture = parse_num_pkt_cap(optarg);
			APP_INFO("Number of packets to capture: %" PRIu64 "\n", packet_to_capture);
			break;

		case CMD_LINE_OPT_PCAP_FILENAME_CAP:
			rte_strlcpy(pcap_filename, optarg, sizeof(pcap_filename));
			APP_INFO("Pcap file name: %s\n", pcap_filename);
			break;

		default:
			print_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;
	rc = optind - 1;
	optind = 1; /* Reset getopt lib */

	if (!nb_ethdevs || !nb_virtio_netdevs) {
		APP_ERR("Need at least one port and virtio dev\n");
		return -1;
	}
	return rc;
}

static void
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];

	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	APP_INFO_NH("%s%s", name, buf);
}

static int
init_eth_mempool(uint16_t portid, uint32_t nb_mbuf)
{
	uint32_t lcore_id;
	char s[64];

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		if (e_pktmbuf_pool[portid] == NULL) {
			snprintf(s, sizeof(s), "mbuf_pool_e%d", portid);
			/* Create a pool with priv size of a cacheline */
			e_pktmbuf_pool[portid] =
				rte_pktmbuf_pool_create(s, nb_mbuf, MEMPOOL_CACHE_SIZE,
							RTE_CACHE_LINE_SIZE, pool_buf_len, 0);
			if (e_pktmbuf_pool[portid] == NULL)
				rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
			else
				APP_INFO("Allocated ethdev mbuf pool for portid=%d\n", portid);
		}
	}

	return 0;
}

static int
init_virtio_mempool(uint16_t devid, uint32_t nb_mbuf)
{
	uint32_t lcore_id;
	char s[64];

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		if (v_pktmbuf_pool[devid] == NULL) {
			snprintf(s, sizeof(s), "mbuf_pool_v%d", devid);
			/* Create a pool with priv size of a cacheline */
			v_pktmbuf_pool[devid] =
				rte_pktmbuf_pool_create(s, nb_mbuf, MEMPOOL_CACHE_SIZE,
							RTE_CACHE_LINE_SIZE, pool_buf_len, 0);
			if (v_pktmbuf_pool[devid] == NULL)
				rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
			else
				APP_INFO("Allocated virtio_dev mbuf pool for devid=%d\n", devid);
		}
	}

	return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(void)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	uint16_t portid;
	int rc;

	APP_INFO("\n");
	APP_INFO("Checking link status\n");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if (force_quit)
				return;
			if (!is_ethdev_enabled(portid))
				continue;
			memset(&link, 0, sizeof(link));
			rc = rte_eth_link_get_nowait(portid, &link);
			if (rc < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					APP_ERR("Port %u link get failed: %s\n", portid,
						rte_strerror(-rc));
				continue;
			}
			/* Print link status if flag set */
			if (print_flag == 1) {
				rte_eth_link_to_str(link_status_text, sizeof(link_status_text),
						    &link);
				APP_INFO("Port %d %s\n", portid, link_status_text);
				continue;
			}
			/* Clear all_ports_up flag if any link down */
			if (link.link_status == RTE_ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* After finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* Set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			APP_INFO("Done\n");
		}
	}
}

static void
signal_handler(int signum)
{
	APP_INFO("\n");
	if (signum == SIGINT || signum == SIGTERM) {
		APP_INFO("Signal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

static struct dao_dma_stats prev_stats[RTE_MAX_LCORE];

static void
print_lcore_dma_stats(uint16_t lcore_id)
{
	struct dao_dma_vchan_stats diff, *curr, *prev;
	struct dao_dma_stats stats;
	uint16_t i;

	dao_dma_stats_get(lcore_id, &stats);
	for (i = 0; i < stats.nb_dev2mem; i++) {
		curr = &stats.dev2mem[i];
		prev = &prev_stats[lcore_id].dev2mem[i];
		diff.ops = curr->ops - prev->ops;
		diff.ptrs = curr->ptrs - prev->ptrs;
		diff.dbells = curr->dbells - prev->dbells;
		diff.enq_errs = curr->enq_errs - prev->enq_errs;
		if (curr->ops)
			APP_INFO(
				"lcore %2u.....dev2mem[%u]: %2lu ptrs/op, %2lu ops/dbell %lu err\n",
				lcore_id, i, diff.ptrs / diff.ops, diff.ops / diff.dbells,
				diff.enq_errs);
	}
	for (i = 0; i < stats.nb_mem2dev; i++) {
		curr = &stats.mem2dev[i];
		prev = &prev_stats[lcore_id].mem2dev[i];
		diff.ops = curr->ops - prev->ops;
		diff.ptrs = curr->ptrs - prev->ptrs;
		diff.dbells = curr->dbells - prev->dbells;
		diff.enq_errs = curr->enq_errs - prev->enq_errs;
		if (curr->ops)
			APP_INFO(
				"lcore %2u.....mem2dev[%u]: %2lu ptrs/op, %2lu ops/dbell %lu err\n",
				lcore_id, i, diff.ptrs / diff.ops, diff.ops / diff.dbells,
				diff.enq_errs);
	}
	prev_stats[lcore_id] = stats;
}

static void
print_stats(void)
{
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
	const char clr[] = {27, '[', '2', 'J', '\0'};
	uint16_t lcore_id;

	while (!force_quit) {
		/* Clear screen and move to top left */
		printf("%s%s", clr, topLeft);
		if (verbose_stats != 2)
			rte_graph_cluster_stats_get(graph_stats[0], 0);
		for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
			/* Dump lcore graph stats */
			if (verbose_stats == 2 && graph_stats[lcore_id] &&
			    !lcore_conf[lcore_id].service_lcore)
				rte_graph_cluster_stats_get(graph_stats[lcore_id], 0);

			if (verbose_stats > 0)
				print_lcore_dma_stats(lcore_id);
		}
		rte_delay_ms(1E3);
	}
}

static __rte_always_inline uint16_t
l2_virtio_desc_process(uint64_t netdev_map, uint16_t *netdev_qp_count)
{
	uint16_t dev_id = 0;

	while (netdev_map) {
		if (!(netdev_map & 0x1)) {
			netdev_map >>= 1;
			dev_id++;
			continue;
		}
		dao_virtio_net_desc_manage(dev_id, netdev_qp_count[dev_id]);
		netdev_map >>= 1;
		dev_id++;
	}
	return 0;
}

static int
service_main_loop(void *conf)
{
	struct rte_rcu_qsbr *qs_v;
	struct lcore_conf *qconf;
	uint32_t lcore_id;
	int rc;

	RTE_SET_USED(conf);

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];
	qs_v = qconf->qs_v;

	/* Set per lcore DMA device id */
	rc = dao_dma_lcore_dev2mem_set(qconf->dev2mem_id, qconf->nb_vchans, dma_flush_thr);
	rc |= dao_dma_lcore_mem2dev_set(qconf->mem2dev_id, qconf->nb_vchans, dma_flush_thr);
	if (rc) {
		APP_ERR("Error in setting DMA device on lcore\n");
		return -1;
	}

	/* Register this thread to rdaort quiescent state */
	rte_rcu_qsbr_thread_register(qs_v, lcore_id);
	rte_rcu_qsbr_thread_online(qs_v, lcore_id);

	APP_INFO("Entering service main loop on lcore %u\n", lcore_id);

	while (likely(!force_quit)) {
		/* Process virtio descriptors */
		l2_virtio_desc_process(qconf->netdev_map, qconf->netdev_qp_count);

		/* Flush and submit DMA ops */
		dao_dma_flush_submit();

		/* Update quiescent state */
		rte_rcu_qsbr_quiescent(qs_v, lcore_id);
	}

	rte_rcu_qsbr_thread_offline(qs_v, lcore_id);
	rte_rcu_qsbr_thread_unregister(qs_v, lcore_id);
	return 0;
}

static int
graph_main_loop(void *conf)
{
	struct rte_rcu_qsbr *qs_v;
	struct lcore_conf *qconf;
	struct rte_graph *graph;
	uint32_t lcore_id;
	int rc, i;

	RTE_SET_USED(conf);

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];
	qs_v = qconf->qs_v;
	graph = qconf->graph;

	if (!graph) {
		APP_INFO("Lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	/* Set per lcore DMA device id */
	rc = dao_dma_lcore_dev2mem_set(qconf->dev2mem_id, qconf->nb_vchans, dma_flush_thr);
	rc |= dao_dma_lcore_mem2dev_set(qconf->mem2dev_id, qconf->nb_vchans, dma_flush_thr);
	for (i = 0; i < qconf->nb_vchans; i++)
		rc |= dao_dma_lcore_mem2dev_autofree_set(qconf->mem2dev_id, i,
							 virtio_netdev_autofree);

	if (rc) {
		APP_ERR("Error in setting DMA device on lcore\n");
		return -1;
	}

	/* Register this thread to rdaort quiescent state */
	rte_rcu_qsbr_thread_register(qs_v, lcore_id);
	rte_rcu_qsbr_thread_online(qs_v, lcore_id);

	APP_INFO("Entering graph main loop on lcore %u, %s(%p)\n", lcore_id, qconf->name, graph);

	while (likely(!force_quit)) {
		/* Walk through graph */
		rte_graph_walk(graph);

		/* Flush and submit DMA ops */
		dao_dma_flush_submit();

		/* Update quiescent state */
		rte_rcu_qsbr_quiescent(qs_v, lcore_id);
	}

	rte_rcu_qsbr_thread_offline(qs_v, lcore_id);
	rte_rcu_qsbr_thread_unregister(qs_v, lcore_id);
	return 0;
}

static uint32_t
eth_dev_get_overhead_len(uint32_t max_rx_pktlen, uint16_t max_mtu)
{
	uint32_t overhead_len;

	if (max_mtu != UINT16_MAX && max_rx_pktlen > max_mtu)
		overhead_len = max_rx_pktlen - max_mtu;
	else
		overhead_len = RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN;

	return overhead_len;
}

static int
config_port_max_pkt_len(struct rte_eth_conf *conf, struct rte_eth_dev_info *dev_info)
{
	uint32_t overhead_len;

	if (max_pkt_len == 0)
		return 0;

	if (max_pkt_len < RTE_ETHER_MIN_LEN || max_pkt_len > MAX_JUMBO_PKT_LEN)
		return -1;

	overhead_len = eth_dev_get_overhead_len(dev_info->max_rx_pktlen, dev_info->max_mtu);
	conf->rxmode.mtu = max_pkt_len - overhead_len;

	if (conf->rxmode.mtu > RTE_ETHER_MTU)
		conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

	return 0;
}

static void
dump_lcore_info(void)
{
	struct l2_virtio_rx_node_ctx *virtio_rx;
	struct l2_ethdev_rx_node_ctx *ethdev_rx;
	struct lcore_conf *qconf;
	uint32_t lcore_id;
	uint16_t i, q_id;
	uint64_t map;

	APP_INFO("\n");
	APP_INFO("Lcore info...\n");
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0 || lcore_id == rte_get_main_lcore())
			continue;

		qconf = &lcore_conf[lcore_id];
		if (!qconf->nb_ethdev_rx && !qconf->nb_virtio_rx && !qconf->service_lcore)
			continue;

		if (qconf->service_lcore) {
			APP_INFO("\tService lcore %u\n", lcore_id);
			continue;
		}

		APP_INFO("\tRx queues on lcore %u ... ", lcore_id);
		fflush(stdout);

		map = 0;
		for (i = 0; i < qconf->nb_virtio_rx; i++) {
			virtio_rx = qconf->virtio_rx[i].virtio_rx;
			map = virtio_rx->virt_q_map;
			q_id = 0;
			while (map) {
				if (map & 0x1)
					APP_INFO_NH("virtio_rxq=%d,%d ", virtio_rx->virtio_devid,
						    q_id);
				q_id++;
				map = map >> 1;
			}
		}

		fflush(stdout);

		map = 0;
		for (i = 0; i < qconf->nb_ethdev_rx; i++) {
			ethdev_rx = qconf->ethdev_rx[i].ethdev_rx;
			map = ethdev_rx->rx_q_map;
			q_id = 0;
			while (map) {
				if (map & 0x1)
					APP_INFO_NH("eth_rxq=%d,%d ", ethdev_rx->eth_port, q_id);
				q_id++;
				map = map >> 1;
			}
		}
		APP_INFO_NH("\n");
	}
	APP_INFO("\n");
}

static int
lcore_wt_cmp(const void *a, const void *b)
{
	uint16_t lcore_a = *(const uint16_t *)a;
	uint16_t lcore_b = *(const uint16_t *)b;

	if (lcore_conf[lcore_a].weight < lcore_conf[lcore_b].weight)
		return -1;

	if (lcore_conf[lcore_a].weight == lcore_conf[lcore_b].weight)
		return 0;

	return 1;
}

static int
rss_table_reset(uint16_t portid)
{
	struct rte_eth_rss_reta_entry64 reta_conf[4];
	int i;

	/* Setup all entries in RETA table to point to RQ 0.
	 * RETA table will get updated when number of queue count
	 * is available.
	 */
	memset(reta_conf, 0, sizeof(reta_conf));
	for (i = 0; i < 4; i++)
		reta_conf[i].mask = UINT64_MAX;

	return rte_eth_dev_rss_reta_update(portid, reta_conf, eth_dev_info[portid].reta_size);
}

static void
clear_lcore_queue_mapping(uint16_t virtio_devid)
{
	struct l2_virtio_rx_node_ctx *virtio_rx;
	struct l2_ethdev_rx_node_ctx *ethdev_rx;
	struct lcore_conf *qconf;
	uint32_t lcore_id;
	uint16_t i;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &lcore_conf[lcore_id];

		/* Skip Lcore if not needed */
		if (!qconf->nb_ethdev_rx && !qconf->nb_virtio_rx && !qconf->service_lcore)
			continue;

		for (i = 0; i < qconf->nb_virtio_rx; i++) {
			/* Check for matching virtio devid */
			if (qconf->virtio_rx[i].virtio_devid != virtio_devid)
				continue;

			/* Clear valid virtio queue map */
			virtio_rx = qconf->virtio_rx[i].virtio_rx;
			/* Update lcore weight */
			qconf->weight -= virtio_rx->virt_q_count;
			virtio_rx->virt_q_map = 0;
			virtio_rx->virt_q_count = 0;
		}

		for (i = 0; i < qconf->nb_ethdev_rx; i++) {
			/* Check for matching virtio devid */
			if (!qconf->ethdev_rx[i].virtio_tx ||
			    qconf->ethdev_rx[i].virtio_tx->virtio_devid != virtio_devid)
				continue;

			/* Clear valid ethdev queue map */
			ethdev_rx = qconf->ethdev_rx[i].ethdev_rx;
			/* Update lcore weight */
			qconf->weight -= ethdev_rx->rx_q_count;
			ethdev_rx->rx_q_map = 0;
			ethdev_rx->rx_q_count = 0;
		}

		if (qconf->service_lcore)
			qconf->netdev_map &= ~RTE_BIT64(virtio_devid);
	}
	rte_io_wmb();
	dump_lcore_info();
}

static int
reconfig_ethdev(uint16_t portid, uint16_t q_count)
{
	struct rte_eth_conf *local_port_conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	uint16_t nb_rx_queue;
	uint32_t nb_tx_queue;
	uint16_t queueid;
	int rc;

	APP_INFO("Reconfiguring ethdev portid=%d with q_count=%u\n", portid, q_count);

	local_port_conf = &eth_dev_conf[portid];
	nb_rx_queue = q_count;
	nb_tx_queue = nb_rx_queue;
	rc = rte_eth_dev_stop(portid);
	if (rc != 0) {
		APP_ERR("Failed to stop port %u: %s\n", portid, rte_strerror(-rc));
		return rc;
	}

	rc = rte_eth_dev_configure(portid, nb_rx_queue, nb_tx_queue, local_port_conf);
	if (rc < 0) {
		APP_ERR("Cannot configure device: err=%d, port=%d\n", rc, portid);
		return rc;
	}

	rte_eth_dev_info_get(portid, &dev_info);

	/* Setup Tx queues */
	for (queueid = eth_dev_q_count[portid]; queueid < nb_tx_queue; queueid++) {
		txconf = &dev_info.default_txconf;
		txconf->offloads = local_port_conf->txmode.offloads;

		rc = rte_eth_tx_queue_setup(portid, queueid, nb_txd, 0, txconf);
		if (rc < 0) {
			APP_ERR("rte_eth_tx_queue_setup: err=%d, port=%d\n", rc, portid);
			return rc;
		}
	}

	/* Setup RX queues */
	for (queueid = eth_dev_q_count[portid]; queueid < nb_rx_queue; queueid++) {
		struct rte_eth_rxconf rxq_conf;

		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = port_conf.rxmode.offloads;
		if (!per_port_pool)
			rc = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, 0, &rxq_conf,
						    e_pktmbuf_pool[0]);
		else
			rc = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, 0, &rxq_conf,
						    e_pktmbuf_pool[portid]);
		if (rc < 0) {
			APP_ERR("rte_eth_rx_queue_setup: err=%d, port=%d\n", rc, portid);
			return rc;
		}
	}

	rss_table_reset(portid);
	eth_dev_q_count[portid] = q_count;

	rc = rte_eth_dev_start(portid);
	if (rc < 0) {
		APP_ERR("rte_eth_dev_start: err=%d, port=%d\n", rc, portid);
		return rc;
	}
	return 0;
}

static int
setup_lcore_queue_mapping(uint16_t virtio_devid, uint16_t virt_q_count)
{
	struct l2_virtio_rx_node_ctx *virtio_rx;
	struct l2_ethdev_rx_node_ctx *ethdev_rx;
	uint16_t virt_rx_q, eth_rx_q;
	struct lcore_conf *qconf;
	uint32_t lcore_id, idx;
	uint16_t i, q_id;

	virt_rx_q = virt_q_count / 2;
	eth_rx_q = (virtio_map[virtio_devid].type == ETHDEV_NEXT) ? virt_rx_q : 0;

	/* Create a sorted lcore list based on its weight */
	qsort(lcore_list_wt_sorted, RTE_MAX_LCORE, sizeof(lcore_list_wt_sorted[0]), lcore_wt_cmp);
	/* Equally distribute virt rx queues among all the subscribed lcores */
	q_id = 0;
	while (q_id < virt_rx_q) {
		for (idx = 0; idx < RTE_MAX_LCORE && q_id < virt_rx_q; idx++) {
			lcore_id = lcore_list_wt_sorted[idx];
			if (rte_lcore_is_enabled(lcore_id) == 0)
				continue;

			qconf = &lcore_conf[lcore_id];

			/* Skip Lcore if not needed */
			if (!qconf->nb_virtio_rx)
				continue;

			for (i = 0; i < qconf->nb_virtio_rx; i++) {
				/* Check for matching virtio devid */
				if (qconf->virtio_rx[i].virtio_devid != virtio_devid)
					continue;
				/* Add queue to valid virtio queue map */
				virtio_rx = qconf->virtio_rx[i].virtio_rx;
				virtio_rx->virt_q_map |= RTE_BIT64(q_id);
				virtio_rx->virt_q_count++;
				/* Update lcore weight */
				qconf->weight++;
				q_id++;
				break;
			}
		}
		if (!q_id) {
			APP_INFO("Skipping virtio %u Rx, no lcore mapping found\n", virtio_devid);
			break;
		}
	}

	/* Create a sorted lcore list based on its weight */
	qsort(lcore_list_wt_sorted, RTE_MAX_LCORE, sizeof(lcore_list_wt_sorted[0]), lcore_wt_cmp);
	/* Equally distribute ethdev rx queues among all the subscribed lcores */
	q_id = 0;
	while (q_id < eth_rx_q) {
		for (idx = 0; idx < RTE_MAX_LCORE && q_id < eth_rx_q; idx++) {
			lcore_id = lcore_list_wt_sorted[idx];
			if (rte_lcore_is_enabled(lcore_id) == 0)
				continue;

			qconf = &lcore_conf[lcore_id];

			/* Skip Lcore if not needed */
			if (!qconf->nb_ethdev_rx)
				continue;

			for (i = 0; i < qconf->nb_ethdev_rx; i++) {
				/* Check for matching virtio devid */
				if (!qconf->ethdev_rx[i].virtio_tx ||
				    qconf->ethdev_rx[i].virtio_tx->virtio_devid != virtio_devid)
					continue;

				/* Add queue to valid ethdev queue map */
				ethdev_rx = qconf->ethdev_rx[i].ethdev_rx;
				ethdev_rx->rx_q_map |= RTE_BIT64(q_id);
				ethdev_rx->rx_q_count++;
				/* Update lcore weight */
				qconf->weight++;
				q_id++;
				break;
			}
		}
		if (!q_id) {
			APP_INFO("Skipping ethdev rx for virtio %u, no lcore mapping found\n",
				 virtio_devid);
			break;
		}
	}

	/* Add virtio device to service lcore */
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &lcore_conf[lcore_id];

		if (qconf->service_lcore) {
			qconf->netdev_map |= RTE_BIT64(virtio_devid);
			qconf->netdev_qp_count[virtio_devid] = virt_q_count / 2;
			break;
		}
	}

	dump_lcore_info();
	return 0;
}

static int
configure_promisc(uint16_t virtio_devid, uint8_t enable)
{
	if (enable)
		return rte_eth_promiscuous_enable(virtio_map[virtio_devid].id);
	return rte_eth_promiscuous_disable(virtio_map[virtio_devid].id);
}

static int
configure_allmulti(uint16_t virtio_devid, uint8_t enable)
{
	if (enable)
		return rte_eth_allmulticast_enable(virtio_map[virtio_devid].id);
	return rte_eth_allmulticast_disable(virtio_map[virtio_devid].id);
}

static int
mac_addr_set(uint16_t virtio_devid, uint8_t *mac)
{
	return rte_eth_dev_default_mac_addr_set(virtio_map[virtio_devid].id,
						(struct rte_ether_addr *)mac);
}

static int
mac_list_update(uint16_t port_id, struct rte_ether_addr *macs, int cnt)
{
	struct rte_eth_dev_info dev_info;
	struct rte_ether_addr addr[64];
	int i, rc;

	rc = rte_eth_dev_info_get(port_id, &dev_info);
	if (rc || (dev_info.max_mac_addrs >= 64))
		return 0;

	rc = rte_eth_macaddrs_get(port_id, addr, dev_info.max_mac_addrs);
	if (rc < 0)
		return rc;

	for (i = 1; i < rc; i++) {
		/* skip zero  and mcast address */
		if (rte_is_zero_ether_addr(&addr[i]) || rte_is_multicast_ether_addr(&addr[i]))
			continue;

		rte_eth_dev_mac_addr_remove(port_id, &addr[i]);
	}

	/* Update new MAC list */
	for (i = 0; i < cnt; i++) {
		/* skip zero  and mcast address */
		if (rte_is_zero_ether_addr(&macs[i]))
			continue;

		rc = rte_eth_dev_mac_addr_add(port_id, &macs[i], 0);
		if (rc)
			return rc;
	}
	return 0;
}

static int
mac_addr_add(uint16_t virtio_devid, struct virtio_net_ctrl_mac *mac_tbl, uint8_t type)
{
	struct rte_ether_addr *macs = (struct rte_ether_addr *)mac_tbl->macs;

	if (type)
		return rte_eth_dev_set_mc_addr_list(virtio_map[virtio_devid].id, macs,
						    mac_tbl->entries);
	return mac_list_update(virtio_map[virtio_devid].id, macs, mac_tbl->entries);
}

static int
vlan_add(uint16_t virtio_devid, uint16_t vlan_tci)
{
	struct rte_flow_action_rss act_rss_conf;
	struct rte_flow_item_vlan vlan, mask;
	struct rte_eth_rss_conf rss_conf;
	struct rte_flow_action actions[2];
	struct rte_flow_item patterns[2];
	struct vlan_filter_head *list;
	struct rte_flow *flow = NULL;
	struct rte_flow_attr attr;
	uint16_t portid, *queues;
	struct vlan_filter *node;
	bool flow_found = false;
	uint32_t i;
	int rc = 0;

	list = &virtio_dev_vlan_filters[virtio_devid];
	TAILQ_FOREACH(node, list, next) {
		if (node->vlan_tci == vlan_tci) {
			flow_found = true;
			break;
		}
	}

	if (flow_found) {
		APP_INFO("Filter already exists for vlan tci = %hu\n", vlan_tci);
		goto skip_flow_create;
	}

	portid = virtio_map[virtio_devid].id;

	/* Attributes */
	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;

	/* Patterns */
	memset(&vlan, 0, sizeof(struct rte_flow_item_vlan));
	memset(&mask, 0, sizeof(struct rte_flow_item_vlan));
	vlan.hdr.vlan_tci = rte_cpu_to_be_16(vlan_tci);
	mask.hdr.vlan_tci = rte_cpu_to_be_16(0xffff);
	patterns[0].type = RTE_FLOW_ITEM_TYPE_VLAN;
	patterns[0].spec = &vlan;
	patterns[0].last = NULL;
	patterns[0].mask = &mask;
	patterns[1].type = RTE_FLOW_ITEM_TYPE_END;
	patterns[1].spec = NULL;
	patterns[1].last = NULL;
	patterns[1].mask = NULL;

	/* Actions */
	memset(&act_rss_conf, 0, sizeof(struct rte_flow_action_rss));
	memset(&rss_conf, 0, sizeof(struct rte_eth_rss_conf));
	rc = rte_eth_dev_rss_hash_conf_get(portid, &rss_conf);
	if (rc < 0)
		goto skip_flow_create;

	act_rss_conf.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
	act_rss_conf.types = rss_conf.rss_hf;
	act_rss_conf.queue_num = eth_dev_q_count[portid];
	queues = calloc(act_rss_conf.queue_num, sizeof(uint16_t));
	if (queues == NULL) {
		rc = -ENOMEM;
		goto skip_flow_create;
	}

	for (i = 0; i < act_rss_conf.queue_num; i++)
		queues[i] = i;

	act_rss_conf.queue = queues;

	actions[0].type = RTE_FLOW_ACTION_TYPE_RSS;
	actions[0].conf = &act_rss_conf;
	actions[1].type = RTE_FLOW_ACTION_TYPE_END;
	actions[1].conf = NULL;

	flow = rte_flow_create(portid, &attr, patterns, actions, NULL);
	if (flow == NULL) {
		rc = -1;
		APP_ERR("rte_flow_create: port=%d failed\n", portid);
		goto error_flow_create;
	}

	node = calloc(1, sizeof(struct vlan_filter));
	if (node == NULL) {
		rc = -ENOMEM;
		goto free_created_flow;
	}

	node->flow = flow;
	node->vlan_tci = vlan_tci;
	TAILQ_INSERT_TAIL(list, node, next);
	APP_INFO("Filter for vlan tci = %hu is created successfully\n", vlan_tci);
	return 0;

free_created_flow:
	rte_flow_destroy(portid, flow, NULL);
error_flow_create:
	if (queues)
		free(queues);
skip_flow_create:
	return rc;
}

static int
vlan_del(uint16_t virtio_devid, uint16_t vlan_tci)
{
	struct vlan_filter_head *list;
	struct rte_flow *flow = NULL;
	struct vlan_filter *node;
	bool flow_found = false;
	uint16_t portid;
	int rc = 0;

	list = &virtio_dev_vlan_filters[virtio_devid];
	TAILQ_FOREACH(node, list, next) {
		if (node->vlan_tci == vlan_tci) {
			flow = node->flow;
			flow_found = true;
			break;
		}
	}

	if (!flow_found) {
		APP_INFO("No filter found for vlan tci = %hu\n", vlan_tci);
		goto skip_flow_delete;
	}

	portid = virtio_map[virtio_devid].id;
	rc = rte_flow_destroy(portid, flow, NULL);
	if (rc < 0) {
		APP_ERR("rte_flow_destroy: err= %d, port=%d\n", rc, portid);
		goto skip_flow_delete;
	}

	TAILQ_REMOVE(list, node, next);
	node->flow = NULL;
	node->vlan_tci = 0;
	free(node);
	APP_INFO("Filter for vlan tci = %hu is deleted successfully\n", vlan_tci);
	return 0;

skip_flow_delete:
	return rc;
}

static void
vlan_reset(uint16_t virtio_devid)
{
	struct vlan_filter_head *list;
	struct rte_flow *flow = NULL;
	struct vlan_filter *node;
	uint16_t portid;
	int rc = 0;

	portid = virtio_map[virtio_devid].id;
	list = &virtio_dev_vlan_filters[virtio_devid];

	while (!TAILQ_EMPTY(list)) {
		node = TAILQ_FIRST(list);
		flow = node->flow;

		rc = rte_flow_destroy(portid, flow, NULL);
		if (rc < 0)
			APP_ERR("rte_flow_destroy: err= %d, port=%d\n", rc, portid);

		TAILQ_REMOVE(list, node, next);
		node->flow = NULL;
		node->vlan_tci = 0;
		free(node);
	}
}

static int
chksum_offload_configure(uint16_t virtio_devid)
{
	uint64_t csum_offload, tx_offloads, rx_offloads;
	struct rte_eth_conf *local_port_conf;
	uint16_t virt_q_count, portid;
	int rc;

	csum_offload = dao_virtio_netdev_feature_bits_get(virtio_devid) & 0x3;

	portid = virtio_map[virtio_devid].id;
	local_port_conf = &eth_dev_conf[portid];
	virt_q_count = eth_dev_q_count[portid];

	tx_offloads = local_port_conf->txmode.offloads;
	rx_offloads = local_port_conf->rxmode.offloads;

	tx_offloads &= ~(RTE_ETH_TX_OFFLOAD_IPV4_CKSUM);
	rx_offloads &= ~(RTE_ETH_RX_OFFLOAD_CHECKSUM);
	if (csum_offload & RTE_BIT64(VIRTIO_NET_F_CSUM))
		tx_offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
	if (csum_offload & RTE_BIT64(VIRTIO_NET_F_GUEST_CSUM))
		rx_offloads |= RTE_ETH_RX_OFFLOAD_CHECKSUM;

	if ((local_port_conf->txmode.offloads == tx_offloads) &&
	    (local_port_conf->rxmode.offloads == rx_offloads)) {
		APP_INFO("No change in checksum offload, Skipping port %d reconfig\n", portid);
		return 0;
	}

	local_port_conf->txmode.offloads = tx_offloads;
	local_port_conf->rxmode.offloads = rx_offloads;

	rc = reconfig_ethdev(portid, virt_q_count);
	return rc;
}

static int
rss_reta_configure(uint16_t virtio_devid, struct virtio_net_ctrl_rss *rss)
{
	struct rte_eth_rss_reta_entry64
		reta_conf[VIRTIO_NET_RSS_RETA_SIZE / RTE_ETH_RETA_GROUP_SIZE];
	uint16_t virt_q_count, portid;
	uint16_t reta_size;
	uint16_t next_q;
	uint32_t i;
	int rc;

	if (rss == NULL) {
		clear_lcore_queue_mapping(virtio_devid);
		/* Synchronize RCU */
		rte_rcu_qsbr_synchronize(qs_v, RTE_QSBR_THRID_INVALID);
		return 0;
	}

	clear_lcore_queue_mapping(virtio_devid);

	/* Get active virt queue count */
	virt_q_count = dao_virtio_netdev_queue_count(virtio_devid);

	if (virt_q_count <= 0 || virt_q_count & 0x1 ||
	    virt_q_count >= (DAO_VIRTIO_MAX_QUEUES - 1)) {
		APP_ERR("virtio_dev=%d: invalid virt_q_count=%d\n", virtio_devid, virt_q_count);
		return -EIO;
	}

	if (virtio_map[virtio_devid].type != ETHDEV_NEXT)
		goto skip_eth_reconfig;

	portid = virtio_map[virtio_devid].id;
	/* Reconfigure ethdev with required number of queues */
	rc = reconfig_ethdev(portid, virt_q_count / 2);
	if (rc)
		return rc;

	memset(reta_conf, 0, sizeof(reta_conf));
	reta_size = virtio_netdev_reta_sz[virtio_devid];

	for (i = 0; i < reta_size; i++)
		reta_conf[i / RTE_ETH_RETA_GROUP_SIZE].mask = UINT64_MAX;

	next_q = rss->indirection_table[0];
	for (i = 0; i < reta_size; i++) {
		uint32_t reta_id = i / RTE_ETH_RETA_GROUP_SIZE;
		uint32_t reta_pos = i % RTE_ETH_RETA_GROUP_SIZE;

		reta_conf[reta_id].reta[reta_pos] = rss->indirection_table[i];
		if (eth_dev_info[portid].reta_size != reta_size &&
		    rss->indirection_table[i] != next_q) {
			APP_ERR("Found a non sequential RETA table, cannot work with"
				" mismatched reta table size (ethdev=%u, virtio=%u)\n",
				eth_dev_info[portid].reta_size, reta_size);
			APP_ERR("Please relaunch application with ethdev '%s' reta_size devarg"
			       " as %u.", rte_dev_name(eth_dev_info[portid].device),
			       virtio_netdev_reta_sz[virtio_devid]);
			return -ENOTSUP;
		}
		next_q = rss->indirection_table[i] + 1;
		if (next_q >= virt_q_count / 2)
			next_q = 0;
	}

	for (i = reta_size; i < eth_dev_info[portid].reta_size; i++) {
		uint32_t reta_id = i / RTE_ETH_RETA_GROUP_SIZE;
		uint32_t reta_pos = i % RTE_ETH_RETA_GROUP_SIZE;

		reta_conf[reta_id].reta[reta_pos] = rss->indirection_table[i];
		next_q = rss->indirection_table[i] + 1;
		if (next_q >= virt_q_count / 2)
			next_q = 0;
	}

	rc = rte_eth_dev_rss_reta_update(portid, reta_conf, eth_dev_info[portid].reta_size);
	if (rc) {
		APP_ERR("Failed to update RSS reta table for portid=%d, rc=%d\n",
			portid, rc);
		return rc;
	}

skip_eth_reconfig:
	rc = setup_lcore_queue_mapping(virtio_devid, virt_q_count);
	if (rc)
		APP_ERR("virtio_dev=%d: failed to setup lcore queue mapping, rc=%d\n", virtio_devid,
			rc);
	return rc;
}

static int
mq_configure(uint16_t virtio_devid, bool qmap_set)
{
	struct rte_eth_rss_reta_entry64
		reta_conf[VIRTIO_NET_RSS_RETA_SIZE / RTE_ETH_RETA_GROUP_SIZE];
	uint16_t virt_q_count, portid;
	uint16_t reta_size, i;
	int rc;

	if (!qmap_set) {
		clear_lcore_queue_mapping(virtio_devid);
		/* Synchronize RCU */
		rte_rcu_qsbr_synchronize(qs_v, RTE_QSBR_THRID_INVALID);
		return 0;
	}

	clear_lcore_queue_mapping(virtio_devid);

	/* Get active virt queue count */
	virt_q_count = dao_virtio_netdev_queue_count(virtio_devid);

	if (virt_q_count <= 0 || virt_q_count & 0x1 ||
	    virt_q_count >= (DAO_VIRTIO_MAX_QUEUES - 1)) {
		APP_ERR("virtio_dev=%d: invalid virt_q_count=%d\n", virtio_devid, virt_q_count);
		return -EIO;
	}

	/* Reconfigure ethdev with required number of queues */
	if (virtio_map[virtio_devid].type == ETHDEV_NEXT) {
		portid = virtio_map[virtio_devid].id;
		rc = reconfig_ethdev(virtio_map[virtio_devid].id, virt_q_count / 2);
		if (rc)
			return rc;
		memset(reta_conf, 0, sizeof(reta_conf));
		reta_size = eth_dev_info[portid].reta_size;

		for (i = 0; i < reta_size; i++)
			reta_conf[i / RTE_ETH_RETA_GROUP_SIZE].mask = UINT64_MAX;

		for (i = 0; i < reta_size; i++) {
			uint32_t reta_id = i / RTE_ETH_RETA_GROUP_SIZE;
			uint32_t reta_pos = i % RTE_ETH_RETA_GROUP_SIZE;

			reta_conf[reta_id].reta[reta_pos] = i % (virt_q_count / 2);
		}

		rc = rte_eth_dev_rss_reta_update(portid, reta_conf, reta_size);
		if (rc) {
			APP_ERR("Failed to update RSS reta table for portid=%d, rc=%d\n",
				portid, rc);
			return rc;
		}
	}

	rc = setup_lcore_queue_mapping(virtio_devid, virt_q_count);
	if (rc)
		APP_ERR("virtio_dev=%d: failed to setup lcore queue mapping, rc=%d\n", virtio_devid,
			rc);

	return 0;
}

static int
virtio_dev_status_cb(uint16_t virtio_devid, uint8_t status)
{
	bool reset_ethdev = false;
	uint16_t virt_q_count;
	int rc;

	APP_INFO("virtio_dev=%d: status=%s\n", virtio_devid, dao_virtio_dev_status_to_str(status));

	switch (status) {
	case VIRTIO_DEV_RESET:
	case VIRTIO_DEV_NEEDS_RESET:
		clear_lcore_queue_mapping(virtio_devid);
		reset_ethdev = true;
		break;
	case VIRTIO_DEV_DRIVER_OK:
		/* Configure checksum offload */
		chksum_offload_configure(virtio_devid);

		/* Get active virt queue count */
		virt_q_count = dao_virtio_netdev_queue_count(virtio_devid);

		if (virt_q_count <= 0 || virt_q_count & 0x1 ||
		    virt_q_count >= (DAO_VIRTIO_MAX_QUEUES - 1)) {
			APP_ERR("virtio_dev=%d: invalid virt_q_count=%d\n", virtio_devid,
				virt_q_count);
			return -EIO;
		}
		rc = setup_lcore_queue_mapping(virtio_devid, virt_q_count);
		if (rc)
			APP_ERR("virtio_dev=%d: failed to setup lcore queue mapping, rc=%d\n",
				virtio_devid, rc);
		break;
	default:
		break;
	};

	/* Synchronize RCU */
	rte_rcu_qsbr_synchronize(qs_v, RTE_QSBR_THRID_INVALID);
	/* After this point, all the core's see updated queue mapping */

	if (reset_ethdev && virtio_map[virtio_devid].type == ETHDEV_NEXT) {
		/* Reset RSS table */
		rss_table_reset(virtio_map[virtio_devid].id);
		/* Reset VLAN filters */
		vlan_reset(virtio_devid);
		/* Reconfigure ethdev with 1 queue */
		reconfig_ethdev(virtio_map[virtio_devid].id, 1);
	}
	return 0;
}

static int
lsc_event_callback(uint16_t port_id, enum rte_eth_event_type type __rte_unused, void *param,
		   void *ret_param __rte_unused)
{
	struct dao_virtio_netdev_link_info link_info;
	uint16_t virtio_devid = (uint64_t)param;
	struct rte_eth_link eth_link;

	rte_eth_link_get(port_id, &eth_link);
	link_info.status = eth_link.link_status;
	link_info.speed = eth_link.link_speed;
	link_info.duplex = eth_link.link_duplex;
	dao_virtio_netdev_link_sts_update(virtio_devid, &link_info);

	return 0;
}

static void
setup_mempools(void)
{
	uint32_t virtio_devid;
	uint16_t portid;
	int rc;

	/* Initialize all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid) {
		/* Skip ports that are not enabled */
		if (!is_ethdev_enabled(portid)) {
			APP_INFO("Skipping disabled port %d\n", portid);
			continue;
		}

		/* Init memory */
		if (!per_port_pool) {
			/* portid = 0; this is *not* signifying the first port,
			 * rather, it signifies that portid is ignored.
			 */
			rc = init_eth_mempool(0, pktmbuf_count);
		} else {
			rc = init_eth_mempool(portid, pktmbuf_count);
		}
		if (rc < 0)
			rte_exit(EXIT_FAILURE, "init_eth_mempool() failed\n");
	}

	for (virtio_devid = 0; virtio_devid < DAO_VIRTIO_DEV_MAX; virtio_devid++) {
		if (!is_virtio_dev_enabled(virtio_devid))
			continue;

		if (!per_port_pool) {
			/* portid = 0; this is *not* signifying the first port,
			 * rather, it signifies that portid is ignored.
			 */
			rc = init_virtio_mempool(0, pktmbuf_count);
		} else {
			rc = init_virtio_mempool(virtio_devid, pktmbuf_count);
		}
		if (rc < 0)
			rte_exit(EXIT_FAILURE, "init_virtio_mempool() failed\n");
	}
}

static void
setup_eth_devices(void)
{
	struct rte_eth_rss_reta_entry64 reta_conf[4];
	struct rte_eth_conf local_port_conf;
	struct rte_node_register *node_reg;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	uint16_t queueid, i, portid;
	uint16_t nb_rx_queue;
	uint32_t nb_tx_queue;
	char name[32];
	int rc;

	APP_INFO("\n");

	RTE_ETH_FOREACH_DEV(portid) {
		const char *edge_name = name;

		local_port_conf = port_conf;

		/* Skip ports that are not enabled */
		if (!is_ethdev_enabled(portid)) {
			APP_INFO("Skipping disabled port %d\n", portid);
			continue;
		}

		/* Init port */
		APP_INFO("Initializing port %d ...", portid);
		fflush(stdout);

		/* Setup ethdev with max Rx, Tx queues */
		if (eth_map[portid].type == VIRTIO_NEXT)
			nb_rx_queue = DEFAULT_QUEUES_PER_PORT;
		else
			nb_rx_queue =
				(dao_virtio_netdev_queue_count_max(pem_devid, eth_map[portid].id) /
				 2);
		nb_tx_queue = nb_rx_queue;
		eth_dev_q_count[portid] = nb_rx_queue;

		APP_INFO_NH("Creating queues: nb_rxq=%d nb_txq=%u... ", nb_rx_queue, nb_tx_queue);

		rte_eth_dev_info_get(portid, &dev_info);
		eth_dev_info[portid] = dev_info;

		rc = config_port_max_pkt_len(&local_port_conf, &dev_info);
		if (rc != 0)
			rte_exit(EXIT_FAILURE, "Invalid max packet length: %u (port %u)\n",
				 max_pkt_len, portid);

		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

		if (disable_tx_mseg)
			local_port_conf.txmode.offloads &= ~RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

		local_port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
		if (local_port_conf.rx_adv_conf.rss_conf.rss_hf !=
		    port_conf.rx_adv_conf.rss_conf.rss_hf) {
			APP_INFO("Port %u modified RSS hash function based on "
				 "hardware support,"
				 "requested:%#" PRIx64 " configured:%#" PRIx64 "\n",
				 portid, port_conf.rx_adv_conf.rss_conf.rss_hf,
				 local_port_conf.rx_adv_conf.rss_conf.rss_hf);
		}

		rc = rte_eth_dev_configure(portid, nb_rx_queue, nb_tx_queue, &local_port_conf);
		if (rc < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n", rc,
				 portid);
		eth_dev_conf[portid] = local_port_conf;

		rc = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
		if (rc < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, "
				 "port=%d\n",
				 rc, portid);

		rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
		print_ethaddr(" Address:", &ports_eth_addr[portid]);
		APP_INFO_NH("\n");

		/* Setup Tx queues */
		for (queueid = 0; queueid < nb_tx_queue; queueid++) {
			txconf = &dev_info.default_txconf;
			txconf->offloads = local_port_conf.txmode.offloads;

			rc = rte_eth_tx_queue_setup(portid, queueid, nb_txd, 0, txconf);
			if (rc < 0)
				rte_exit(EXIT_FAILURE,
					 "rte_eth_tx_queue_setup: err=%d, "
					 "port=%d\n",
					 rc, portid);
		}

		/* Setup RX queues */
		for (queueid = 0; queueid < nb_rx_queue; queueid++) {
			struct rte_eth_rxconf rxq_conf;

			rte_eth_dev_info_get(portid, &dev_info);
			rxq_conf = dev_info.default_rxconf;
			rxq_conf.offloads = port_conf.rxmode.offloads;
			if (!per_port_pool)
				rc = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, 0, &rxq_conf,
							    e_pktmbuf_pool[0]);
			else
				rc = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, 0, &rxq_conf,
							    e_pktmbuf_pool[portid]);
			if (rc < 0)
				rte_exit(EXIT_FAILURE,
					 "rte_eth_rx_queue_setup: err=%d, "
					 "port=%d\n",
					 rc, portid);
		}

		/* Setup all entries in RETA table to point to RQ 0.
		 * RETA table will get updated when number of queue count
		 * is available.
		 */
		rte_eth_dev_info_get(portid, &dev_info);
		memset(reta_conf, 0, sizeof(reta_conf));
		for (i = 0; i < 4; i++)
			reta_conf[i].mask = UINT64_MAX;

		rc = rte_eth_dev_rss_reta_update(portid, reta_conf, dev_info.reta_size);
		if (rc < 0)
			rte_exit(EXIT_FAILURE, "Failed to update reta table to RQ 0, rc=%d\n", rc);

		/* Disable ptype extraction */
		rc = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL, 0);
		if (rc < 0)
			rte_exit(EXIT_FAILURE, "Failed to disable ptype parsing\n");

		/* Clone ethdev rx and tx nodes for this ethdev */
		snprintf(name, sizeof(name), "%u", portid);
		node_reg = l2_ethdev_rx_node_get();
		ethdev_rx_nodes[portid] = rte_node_clone(node_reg->id, name);

		node_reg = l2_ethdev_tx_node_get();
		ethdev_tx_nodes[portid] = rte_node_clone(node_reg->id, name);

		/* Update graph edge info */
		if (eth_map[portid].type == ETHDEV_NEXT) {
			snprintf(name, sizeof(name), "l2_ethdev_tx-%u", eth_map[portid].id);
			rte_node_edge_update(ethdev_rx_nodes[portid], RTE_EDGE_ID_INVALID,
					     &edge_name, 1);
		} else {
			snprintf(name, sizeof(name), "l2_virtio_tx-%u", eth_map[portid].id);
			rte_node_edge_update(ethdev_rx_nodes[portid], RTE_EDGE_ID_INVALID,
					     &edge_name, 1);
		}
	}

	APP_INFO("\n");
	/* Dump L2FWD map */
	RTE_ETH_FOREACH_DEV(portid) {
		if (!is_ethdev_enabled(portid))
			continue;
		if (eth_map[portid].type == ETHDEV_NEXT)
			APP_INFO("L2FWD_MAP: ethdev_rx[%u] =====> ethdev_tx[%u] (lcores 0x%lX)\n",
				 portid, eth_map[portid].id, lcore_eth_mask[portid]);
		else
			APP_INFO(
				"L2FWD_MAP: ethdev_rx[%u] ======> virtiodev_tx[%u] (lcores 0x%lX)\n",
				portid, eth_map[portid].id, lcore_eth_mask[portid]);
	}
}

static void
setup_dma_devices(void)
{
	struct rte_dma_vchan_conf dma_qconf;
	uint16_t dev2mem_idx, mem2dev_idx;
	struct rte_dma_info dma_info;
	struct rte_dma_conf dma_conf;
	struct lcore_conf *qconf;
	uint32_t virtio_devid;
	uint32_t lcore_id;
	int16_t dma_devid;
	uint16_t vchan;
	uint64_t mask;
	int i, base;

	APP_INFO("\n");

	dma_devid = 0;
	/* Prepare half of the worker DMA devices half as dev2mem and half as mem2dev */
	for (i = 0; i < wrkr_dma_devs; i += 2) {
		/* Setup Inbound dma device with one vchan per virtio netdev */
		dma_devid = rte_dma_next_dev(dma_devid);
		if (dma_devid == -1)
			break;

		rte_dma_info_get(dma_devid, &dma_info);
		APP_INFO("Setting up dmadev %s(%d)\n", dma_info.dev_name, dma_devid);

		memset(&dma_conf, 0, sizeof(dma_conf));
		dma_conf.nb_vchans = nb_virtio_netdevs;

		if (rte_dma_configure(dma_devid, &dma_conf) != 0)
			rte_exit(EXIT_FAILURE, "Error with rte_dma_configure()\n");

		mask = virtio_mask_ena[0];
		base = 0;
		for (vchan = 0; vchan < nb_virtio_netdevs; vchan++) {
			/* Get next virtio device id */
			virtio_devid = __builtin_ffsl(mask);
			if (virtio_devid == 0)
				rte_exit(EXIT_FAILURE, "Error no virtio device\n");
			virtio_devid -= 1;
			virtio_devid += base;
			virtio_netdev_dma_vchans[virtio_devid] = vchan;

			memset(&dma_qconf, 0, sizeof(dma_qconf));
			dma_qconf.direction = RTE_DMA_DIR_DEV_TO_MEM;
			dma_qconf.nb_desc = 2048;
			dma_qconf.src_port.pcie.coreid = 0; /* TODO PEM id */
			dma_qconf.src_port.pcie.vfen = 1;
			dma_qconf.src_port.pcie.vfid = virtio_devid + 1;
			dma_qconf.src_port.port_type = RTE_DMA_PORT_PCIE;

			/* Override DMA VFID if needed */
			if (override_dma_vfid) {
				dma_qconf.src_port.pcie.vfen = dma_vfid ? 1 : 0;
				dma_qconf.src_port.pcie.vfid = dma_vfid;
			}

			if (rte_dma_vchan_setup(dma_devid, vchan, &dma_qconf) != 0)
				rte_exit(EXIT_FAILURE, "Error with inbound configuration\n");
			mask &= ~RTE_BIT64(virtio_devid);
			if (!mask) {
				base += 64;
				mask = virtio_mask_ena[1];
			}
		}

		if (rte_dma_start(dma_devid) != 0)
			rte_exit(EXIT_FAILURE, "Error with rte_dma_start()\n");

		dev2mem_ids[dev2mem_cnt++] = dma_devid;
		dma_devid++;

		/* Setup Outbound dma device with one vchan per virtio netdev */
		dma_devid = rte_dma_next_dev(dma_devid);
		if (dma_devid == -1)
			break;

		rte_dma_info_get(dma_devid, &dma_info);
		APP_INFO("Setting up dmadev %s(%d)\n", dma_info.dev_name, dma_devid);

		memset(&dma_conf, 0, sizeof(dma_conf));
		dma_conf.nb_vchans = nb_virtio_netdevs;

		if (rte_dma_configure(dma_devid, &dma_conf) != 0)
			rte_exit(EXIT_FAILURE, "Error with rte_dma_configure()\n");

		mask = virtio_mask_ena[0];
		base = 0;
		for (vchan = 0; vchan < nb_virtio_netdevs; vchan++) {
			/* Get next virtio device id */
			virtio_devid = __builtin_ffsl(mask);
			if (virtio_devid == 0)
				rte_exit(EXIT_FAILURE, "Error no virtio device\n");
			virtio_devid -= 1;
			virtio_devid += base;

			memset(&dma_qconf, 0, sizeof(dma_qconf));
			dma_qconf.direction = RTE_DMA_DIR_MEM_TO_DEV;
			dma_qconf.nb_desc = 2048;
			dma_qconf.dst_port.pcie.coreid = 0; /* TODO PEM id */
			dma_qconf.dst_port.pcie.vfen = 1;
			dma_qconf.dst_port.pcie.vfid = virtio_devid + 1;
			dma_qconf.dst_port.port_type = RTE_DMA_PORT_PCIE;

			if (virtio_map[virtio_devid].type == ETHDEV_NEXT) {
				/* Provide mempool for auto free after mem2dev */
				dma_qconf.auto_free.m2d.pool =
					per_port_pool ?
						e_pktmbuf_pool[virtio_map[virtio_devid].id] :
						e_pktmbuf_pool[0];
			} else {
				dma_qconf.auto_free.m2d.pool =
					per_port_pool ?
						v_pktmbuf_pool[virtio_map[virtio_devid].id] :
						v_pktmbuf_pool[0];
			}
			/* Override DMA VFID if needed */
			if (override_dma_vfid) {
				dma_qconf.dst_port.pcie.vfen = dma_vfid ? 1 : 0;
				dma_qconf.dst_port.pcie.vfid = dma_vfid;
			}

			if (rte_dma_vchan_setup(dma_devid, vchan, &dma_qconf) != 0)
				rte_exit(EXIT_FAILURE, "Error with outbound chan configuration\n");
			mask &= ~RTE_BIT64(virtio_devid);
			if (!mask) {
				base += 64;
				mask = virtio_mask_ena[1];
			}
		}

		if (rte_dma_start(dma_devid) != 0)
			rte_exit(EXIT_FAILURE, "Error with rte_dma_start()\n");
		mem2dev_ids[mem2dev_cnt++] = dma_devid;
		dma_devid++;
	}

	if (!dev2mem_cnt || !mem2dev_cnt)
		rte_exit(EXIT_FAILURE, "Not enough dma devices for workers\n");

	dev2mem_idx = 0;
	mem2dev_idx = 0;

	/* Provide DMA devices for virtio control */
	if (dao_dma_ctrl_dev_set(dev2mem_ids[dev2mem_idx++], mem2dev_ids[mem2dev_idx++]))
		rte_exit(EXIT_FAILURE, "Failed to set virtio control DMA dev\n");

	/* Setup two DMA devices per active DPDK lcore */
	APP_INFO("Lcore DMA map...\n");
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &lcore_conf[lcore_id];

		/* Skip Lcore if not needed */
		if (!qconf->nb_ethdev_rx && !qconf->nb_virtio_rx && !qconf->service_lcore)
			continue;

		if (dev2mem_idx == dev2mem_cnt || mem2dev_idx == mem2dev_cnt)
			rte_exit(EXIT_FAILURE, "Not enough dma devices for workers\n");

		/* Assign DMA device id */
		qconf->dev2mem_id = dev2mem_ids[dev2mem_idx++];
		qconf->mem2dev_id = mem2dev_ids[mem2dev_idx++];
		qconf->nb_vchans = nb_virtio_netdevs;

		APP_INFO("\tlcore %u ... dev2mem=%u mem2dev=%u\n", lcore_id, qconf->dev2mem_id,
			 qconf->mem2dev_id);
	}
	APP_INFO("\n");
}

static void
setup_pem_device(void)
{
	struct dao_pem_dev_conf pem_dev_conf;
	int rc;

	/* Setup pem0 */
	memset(&pem_dev_conf, 0, sizeof(pem_dev_conf));
	rc = dao_pem_dev_init(pem_devid, &pem_dev_conf);
	if (rc)
		rte_exit(EXIT_FAILURE, "Error with pem init, rc=%d\n", rc);
}

static void
setup_virtio_devices(void)
{
	struct rte_node_register *node_reg;
	struct dao_virtio_netdev_cbs cbs;
	uint32_t virtio_devid;
	uint16_t portid;
	char name[32];
	int rc;

	APP_INFO("\n");

	/* Setup Virtio devices */
	for (virtio_devid = 0; virtio_devid < DAO_VIRTIO_DEV_MAX; virtio_devid++) {
		struct dao_virtio_netdev_conf netdev_conf;
		const char *edge_name = name;
		int overhd = 0;

		if (!is_virtio_dev_enabled(virtio_devid))
			continue;

		/* Populate netdev conf */
		memset(&netdev_conf, 0, sizeof(netdev_conf));
		netdev_conf.auto_free_en = virtio_netdev_autofree;
		netdev_conf.pem_devid = pem_devid;
		netdev_conf.pool = per_port_pool ? v_pktmbuf_pool[virtio_devid] : v_pktmbuf_pool[0];
		netdev_conf.dma_vchan = virtio_netdev_dma_vchans[virtio_devid];
		netdev_conf.mtu = 0;
		if (virtio_map[virtio_devid].type == ETHDEV_NEXT) {
			struct rte_eth_link eth_link;

			portid = virtio_map[virtio_devid].id;
			netdev_conf.reta_size = RTE_MAX(VIRTIO_NET_RSS_RETA_SIZE,
							eth_dev_info[portid].reta_size);
			netdev_conf.hash_key_size = eth_dev_info[portid].hash_key_size;
			overhd = eth_dev_get_overhead_len(eth_dev_info[portid].max_rx_pktlen,
							  eth_dev_info[portid].max_mtu);
			rte_eth_link_get(portid, &eth_link);
			netdev_conf.link_info.status = eth_link.link_status;
			netdev_conf.link_info.speed = eth_link.link_speed;
			netdev_conf.link_info.duplex = eth_link.link_duplex;
			/* Register link status change interrupt callback */
			rte_eth_dev_callback_register(portid, RTE_ETH_EVENT_INTR_LSC,
						      lsc_event_callback,
						      (void *)(uint64_t)virtio_devid);

			/* Populate default mac address */
			rte_eth_macaddr_get(portid, (struct rte_ether_addr *)netdev_conf.mac);
		} else {
			netdev_conf.reta_size = VIRTIO_NET_RSS_RETA_SIZE;
			netdev_conf.hash_key_size = 48;
			/* Link status always UP */
			netdev_conf.link_info.status = 0x1;
			netdev_conf.link_info.speed = RTE_ETH_SPEED_NUM_UNKNOWN;
			netdev_conf.link_info.duplex = 0xFF;
		}

		if (max_pkt_len)
			netdev_conf.mtu = (max_pkt_len - overhd);
		netdev_conf.auto_free_en = virtio_netdev_autofree;

		/* Save reta size for future use */
		virtio_netdev_reta_sz[virtio_devid] = netdev_conf.reta_size;

		/* Initialize virtio net device */
		rc = dao_virtio_netdev_init(virtio_devid, &netdev_conf);
		if (rc)
			rte_exit(EXIT_FAILURE, "Failed to init virtio device\n");

		/* Clone virtio rx and tx nodes for this ethdev */
		snprintf(name, sizeof(name), "%u", virtio_devid);
		node_reg = l2_virtio_rx_node_get();
		virtio_rx_nodes[virtio_devid] = rte_node_clone(node_reg->id, name);

		node_reg = l2_virtio_tx_node_get();
		virtio_tx_nodes[virtio_devid] = rte_node_clone(node_reg->id, name);

		/* Prepare graph edge name for next node */
		if (virtio_map[virtio_devid].type == VIRTIO_NEXT) {
			snprintf(name, sizeof(name), "l2_virtio_tx-%u",
				 virtio_map[virtio_devid].id);
			rte_node_edge_update(virtio_rx_nodes[virtio_devid], RTE_EDGE_ID_INVALID,
					     &edge_name, 1);
		} else {
			snprintf(name, sizeof(name), "l2_ethdev_tx-%u",
				 virtio_map[virtio_devid].id);
			rte_node_edge_update(virtio_rx_nodes[virtio_devid], RTE_EDGE_ID_INVALID,
					     &edge_name, 1);
		}

		TAILQ_INIT(&virtio_dev_vlan_filters[virtio_devid]);
	}

	memset(&cbs, 0, sizeof(cbs));
	cbs.status_cb = virtio_dev_status_cb;
	cbs.rss_cb = rss_reta_configure;
	cbs.promisc_cb = configure_promisc;
	cbs.allmulti_cb = configure_allmulti;
	cbs.mac_set = mac_addr_set;
	cbs.mac_add = mac_addr_add;
	cbs.mq_configure = mq_configure;
	cbs.vlan_add = vlan_add;
	cbs.vlan_del = vlan_del;
	/* Register virtio dev callback register */
	dao_virtio_netdev_cb_register(&cbs);

	APP_INFO("\n");
	/* Dump L2FWD map */
	for (virtio_devid = 0; virtio_devid < DAO_VIRTIO_DEV_MAX; virtio_devid++) {
		if (!is_virtio_dev_enabled(virtio_devid))
			continue;
		if (virtio_map[virtio_devid].type == VIRTIO_NEXT)
			APP_INFO(
				"L2FWD_MAP: virtiodev_rx[%u] ====> virtiodev_tx[%u] (lcores 0x%lX)\n",
				virtio_devid, virtio_map[virtio_devid].id,
				lcore_virtio_mask[virtio_devid]);
		else
			APP_INFO("L2FWD_MAP: virtiodev_rx[%u] ====> ethdev_tx[%u] (lcores 0x%lX)\n",
				 virtio_devid, virtio_map[virtio_devid].id,
				 lcore_virtio_mask[virtio_devid]);
	}
}

static void
release_virtio_devices(void)
{
	uint32_t virtio_devid;
	int rc;

	/* Close virtio devices */
	for (virtio_devid = 0; virtio_devid < DAO_VIRTIO_DEV_MAX; virtio_devid++) {
		if (!is_virtio_dev_enabled(virtio_devid))
			continue;

		rc = dao_virtio_netdev_fini(virtio_devid);
		if (rc)
			APP_ERR("Failed to stop virtio device %u: %s\n", virtio_devid,
				rte_strerror(-rc));
	}
}

static void
release_pem_device(void)
{
	/* Close PEM */
	dao_pem_dev_fini(pem_devid);
}

static void
release_dma_devices(void)
{
	int16_t dma_devid;
	int rc;

	/* stop DMA devices */
	RTE_DMA_FOREACH_DEV(dma_devid) {
		rc = rte_dma_stop(dma_devid);
		if (rc)
			APP_ERR("Failed to stop dma dev %u: %s\n", dma_devid, rte_strerror(-rc));

		rc = rte_dma_close(dma_devid);
		if (rc)
			APP_ERR("Failed to close dma dev %u: %s\n", dma_devid, rte_strerror(-rc));
	}
}

static void
release_eth_devices(void)
{
	uint16_t portid;
	int rc;

	/* Stop ports */
	RTE_ETH_FOREACH_DEV(portid) {
		if (!is_ethdev_enabled(portid))
			continue;
		APP_INFO("Closing port %d...", portid);
		rc = rte_eth_dev_stop(portid);
		if (rc != 0)
			APP_ERR("Failed to stop port %u: %s\n", portid, rte_strerror(-rc));
		rte_eth_dev_close(portid);
		APP_INFO_NH(" Done\n");
	}
}

int
main(int argc, char **argv)
{
	/* Graph initialization. 8< */
	static const char *const default_patterns[] = {
		"pkt_drop",
	};
	struct rte_graph_cluster_stats_param s_param;
	struct rte_graph_param graph_conf;
	bool service_lcore_flag = false;
	const char **node_patterns;
	struct lcore_conf *qconf;
	uint32_t nb_lcores = 0;
	struct rte_node *node;
	uint32_t virtio_devid;
	uint16_t nb_patterns;
	rte_node_t node_id;
	uint32_t lcore_id;
	uint16_t portid;
	size_t sz;
	int rc;

	/* Init EAL */
	rc = rte_eal_init(argc, argv);
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	argc -= rc;
	argv += rc;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Parse application arguments (after the EAL ones) */
	rc = parse_args(argc, argv);
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "Invalid VIRTIO_L2FWD parameters\n");

	if (check_lcore_params() < 0)
		rte_exit(EXIT_FAILURE, "check_lcore_params() failed\n");

	rc = init_lcore_ethdev_rx();
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "init_lcore_rx_queues() failed\n");

	rc = init_lcore_virtio_rx();
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "init_lcore_virtio_dev() failed\n");

	if (check_port_config() < 0)
		rte_exit(EXIT_FAILURE, "check_port_config() failed\n");

	if (check_virtio_config() < 0)
		rte_exit(EXIT_FAILURE, "check_virtio_config() failed\n");

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0 || lcore_id == rte_get_main_lcore())
			continue;

		if (lcore_conf[lcore_id].nb_virtio_rx || lcore_conf[lcore_id].nb_ethdev_rx) {
			nb_lcores++;
		} else if (!service_lcore_flag) {
			/* Pick one non FP lcore for misc */
			lcore_conf[lcore_id].service_lcore = true;
			service_lcore_flag = true;
		}
	}

	if (!service_lcore_flag)
		rte_exit(EXIT_FAILURE, "LCORE not available for service lcore\n");

	/* Alloc mempools */
	setup_mempools();

	/* Initialize DMA devices */
	setup_dma_devices();

	/* Initialize PEM device */
	setup_pem_device();

	/* Initialize all ethdev ports. 8< */
	setup_eth_devices();

	/* Setup RCU QSBR variable */
	sz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
	qs_v = (struct rte_rcu_qsbr *)rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
							 SOCKET_ID_ANY);
	if (!qs_v)
		rte_exit(EXIT_FAILURE, "Failed to alloc rcu_qsbr variable\n");

	rc = rte_rcu_qsbr_init(qs_v, RTE_MAX_LCORE);
	if (rc)
		rte_exit(EXIT_FAILURE, "rte_rcu_qsbr_init(): failed to init, rc=%d\n", rc);

	/* Start ports */
	RTE_ETH_FOREACH_DEV(portid) {
		if (!is_ethdev_enabled(portid))
			continue;

		/* Start device */
		rc = rte_eth_dev_start(portid);
		if (rc < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n", rc, portid);

		if (promiscuous_on)
			rte_eth_promiscuous_enable(portid);
	}

	check_all_ports_link_status();

	/* Initialize virtio devices */
	setup_virtio_devices();

	/* Graph Initialization */
	nb_patterns = RTE_DIM(default_patterns);
	node_patterns = malloc((MAX_ETHDEV_RX_PER_LCORE + MAX_VIRTIO_RX_PER_LCORE + nb_patterns) *
			       sizeof(*node_patterns));
	if (!node_patterns)
		return -ENOMEM;
	memcpy(node_patterns, default_patterns, nb_patterns * sizeof(*node_patterns));

	memset(&graph_conf, 0, sizeof(graph_conf));
	graph_conf.node_patterns = node_patterns;

	/* Pcap config */
	graph_conf.pcap_enable = pcap_trace_enable;
	graph_conf.num_pkt_to_capture = packet_to_capture;
	graph_conf.pcap_filename = pcap_filename;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		rte_graph_t graph_id;
		rte_edge_t i;

		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		qconf = &lcore_conf[lcore_id];

		/* Skip Lcore if not needed */
		if (!qconf->nb_ethdev_rx && !qconf->nb_virtio_rx && !qconf->service_lcore)
			continue;

		qconf->qs_v = qs_v;
		if (qconf->service_lcore)
			continue;

		nb_patterns = RTE_DIM(default_patterns);
		snprintf(qconf->name, sizeof(qconf->name), "worker_%u", lcore_id);

		/* Add ethdev and virtio rx node patterns of this lcore */
		for (i = 0; i < qconf->nb_ethdev_rx; i++)
			graph_conf.node_patterns[nb_patterns + i] = qconf->ethdev_rx[i].node_name;
		nb_patterns += i;

		for (i = 0; i < qconf->nb_virtio_rx; i++)
			graph_conf.node_patterns[nb_patterns + i] = qconf->virtio_rx[i].node_name;
		nb_patterns += i;

		graph_conf.nb_node_patterns = nb_patterns;
		graph_conf.socket_id = rte_lcore_to_socket_id(lcore_id);

		graph_id = rte_graph_create(qconf->name, &graph_conf);
		if (graph_id == RTE_GRAPH_ID_INVALID)
			rte_exit(EXIT_FAILURE,
				 "rte_graph_create(): graph_id invalid"
				 " for lcore %u\n",
				 lcore_id);

		qconf->graph_id = graph_id;
		qconf->graph = rte_graph_lookup(qconf->name);
		/* >8 End of graph initialization. */
		if (!qconf->graph)
			rte_exit(EXIT_FAILURE, "rte_graph_lookup(): graph %s not found\n",
				 qconf->name);

		/* Update context data of ethdev rx and virtio tx nodes of this graph */
		for (i = 0; i < qconf->nb_ethdev_rx; i++) {
			portid = qconf->ethdev_rx[i].portid;

			/* ethdev rx ctx */
			node_id = ethdev_rx_nodes[portid];
			node = rte_graph_node_get(graph_id, node_id);
			qconf->ethdev_rx[i].ethdev_rx = (struct l2_ethdev_rx_node_ctx *)node->ctx;
			qconf->ethdev_rx[i].ethdev_rx->eth_port = portid;
			qconf->ethdev_rx[i].ethdev_rx->virtio_next = 1;

			if (eth_map[portid].type == ETHDEV_NEXT) {
				node_id = ethdev_tx_nodes[eth_map[portid].id];
				node = rte_graph_node_get(graph_id, node_id);
				qconf->ethdev_rx[i].ethdev_tx =
					(struct l2_ethdev_tx_node_ctx *)node->ctx;
				qconf->ethdev_rx[i].ethdev_tx->eth_port = portid;
				qconf->ethdev_rx[i].ethdev_rx->virtio_devid = DAO_VIRTIO_DEV_MAX;
			} else {
				/* Mapped virtio tx ctx */
				virtio_devid = eth_map[portid].id;
				node_id = virtio_tx_nodes[virtio_devid];
				node = rte_graph_node_get(graph_id, node_id);
				qconf->ethdev_rx[i].virtio_tx =
					(struct l2_virtio_tx_node_ctx *)node->ctx;
				qconf->ethdev_rx[i].virtio_tx->virtio_devid = virtio_devid;
				qconf->ethdev_rx[i].ethdev_rx->virtio_devid = virtio_devid;
			}
		}

		/* Update context data of virtio rx and ethdev tx nodes of this graph */
		for (i = 0; i < qconf->nb_virtio_rx; i++) {
			virtio_devid = qconf->virtio_rx[i].virtio_devid;

			/* virtio rx ctx */
			node_id = virtio_rx_nodes[virtio_devid];
			node = rte_graph_node_get(graph_id, node_id);
			qconf->virtio_rx[i].virtio_rx = (struct l2_virtio_rx_node_ctx *)node->ctx;
			qconf->virtio_rx[i].virtio_rx->virtio_devid = virtio_devid;
			qconf->virtio_rx[i].virtio_rx->eth_next = 1;

			if (virtio_map[virtio_devid].type == VIRTIO_NEXT) {
				/* Mapped virtio tx ctx */
				node_id = virtio_tx_nodes[virtio_devid];
				node = rte_graph_node_get(graph_id, node_id);
				qconf->virtio_rx[i].virtio_tx =
					(struct l2_virtio_tx_node_ctx *)node->ctx;
				qconf->virtio_rx[i].virtio_tx->virtio_devid = virtio_devid;
			} else {
				/* Mapped eth tx ctx */
				portid = virtio_map[virtio_devid].id;
				node_id = ethdev_tx_nodes[portid];
				node = rte_graph_node_get(graph_id, node_id);
				qconf->virtio_rx[i].ethdev_tx =
					(struct l2_ethdev_tx_node_ctx *)node->ctx;
				qconf->virtio_rx[i].ethdev_tx->eth_port = portid;
			}
		}

		if (rte_graph_has_stats_feature() && stats_enable && verbose_stats == 2) {
			const char *pattern = qconf->name;
			/* Prepare per-lcore stats object */
			memset(&s_param, 0, sizeof(s_param));
			s_param.f = stdout;
			s_param.socket_id = SOCKET_ID_ANY;
			s_param.graph_patterns = &pattern;
			s_param.nb_graph_patterns = 1;

			graph_stats[lcore_id] = rte_graph_cluster_stats_create(&s_param);
			if (graph_stats[lcore_id] == NULL)
				rte_exit(EXIT_FAILURE, "Unable to create stats object\n");
		}
	}

	APP_INFO("\n");

	/* Launch per-lcore init on every worker lcore */
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		qconf = &lcore_conf[lcore_id];
		if (qconf->service_lcore)
			rte_eal_remote_launch(service_main_loop, NULL, lcore_id);
		else if (qconf->graph)
			rte_eal_remote_launch(graph_main_loop, NULL, lcore_id);
	}

	if (rte_graph_has_stats_feature() && stats_enable && verbose_stats != 2) {
		const char *pattern = "worker_*";
		/* Prepare stats object */
		memset(&s_param, 0, sizeof(s_param));
		s_param.f = stdout;
		s_param.socket_id = SOCKET_ID_ANY;
		s_param.graph_patterns = &pattern;
		s_param.nb_graph_patterns = 1;

		graph_stats[0] = rte_graph_cluster_stats_create(&s_param);
		if (graph_stats[0] == NULL)
			rte_exit(EXIT_FAILURE, "Unable to create stats object\n");
	}

	/* Accumulate and print stats on main until exit */
	if (rte_graph_has_stats_feature() && stats_enable)
		print_stats();

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (graph_stats[lcore_id])
			rte_graph_cluster_stats_destroy(graph_stats[lcore_id]);
	}

	/* Wait for worker cores to exit */
	rc = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		rc = rte_eal_wait_lcore(lcore_id);
		/* Destroy graph */
		if (rc < 0 || rte_graph_destroy(rte_graph_from_name(lcore_conf[lcore_id].name))) {
			rc = -1;
			break;
		}
	}
	free(node_patterns);

	/* Close virtio devices */
	release_virtio_devices();

	/* Close dma devices */
	release_dma_devices();

	/* Close eth devices */
	release_eth_devices();

	/* Close pem device */
	release_pem_device();

	/* clean up the EAL */
	rte_eal_cleanup();
	APP_INFO("Bye...\n");

	return rc;
}
