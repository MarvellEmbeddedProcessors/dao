/* SPDX-License-Identifier: Marvell-MIT
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

#include <pthread.h>
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
#include <rte_thread.h>
#include <rte_vect.h>
#include <sched.h>

#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>

#include <dao_dma.h>
#include <dao_pal.h>
#include <dao_virtio_netdev.h>

#define GET_MBUF_FROM_DATA_ADDR(mbuf, sz)                                                          \
	((struct rte_mbuf *)((uint8_t *)(mbuf) + sz - RTE_PKTMBUF_HEADROOM -                       \
			     sizeof(struct rte_mbuf)))

#define GET_VIRTIO_ADDR_FROM_MBUF(mbuf, sz)                                                        \
	(struct dao_virtio_net_hdr *)rte_pktmbuf_prepend((mbuf), sz)

/* Log type */
#define RTE_LOGTYPE_VIRTIO_L2FWD_EXTBUF RTE_LOGTYPE_USER1

#define THREAD_INIT_TIME 10
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

#define THREAD_INITIALIZED 1

#define APP_INFO(fmt, args...) RTE_LOG(INFO, VIRTIO_L2FWD_EXTBUF, fmt, ##args)

#define APP_INFO_NH(fmt, args...)                                                                  \
	rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VIRTIO_L2FWD_EXTBUF, fmt, ##args)

#define APP_ERR(fmt, args...) RTE_LOG(ERR, VIRTIO_L2FWD_EXTBUF, fmt, ##args)

typedef struct {
	uint64_t netdev_map;
	uint32_t state;
	uint16_t netdev_qp_count;
} service_t;

typedef struct {
	uint32_t state;
	uint16_t virtio_devid;
	uint16_t eth_port_id;
	uint64_t rx_q_map;
} worker_t;

static worker_t worker;
static service_t service;
static uint64_t worker_mask;
static uint64_t virtio_port_mask;
static uint64_t eth_port_mask;
static uint16_t worker_lcore_id;
/* Static global variables used within this file. */
static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;

/**< Ports set in promiscuous mode off by default. */
static int promiscuous_on;

static volatile bool force_quit;

static struct rte_ether_addr port_eth_addr;

/* Pcap trace */
static uint32_t pktmbuf_count = 128 * 1024;

static struct rte_eth_dev_info eth_dev_info;
static struct rte_eth_conf eth_dev_conf;
static uint16_t eth_dev_q_count;

struct thread_context {
	pthread_t id;
	uint32_t wrk_id;
};

struct thread_context thread_contexts[RTE_MAX_LCORE];
unsigned int tid;

static struct rte_eth_conf port_conf;

static int stats_enable;
static int verbose_stats;
static int vhdr_sz;

static int pool_buf_len = RTE_MBUF_DEFAULT_BUF_SIZE;

static struct rte_mempool *pktmbuf_pool;

static uint16_t virtio_netdev_dma_vchans[DAO_VIRTIO_DEV_MAX];
static uint16_t virtio_netdev_reta_sz;
static bool virtio_netdev_autofree;
static uint16_t pem_devid;

static bool ethdev_cgx_loopback;

/* RCU QSBR variable */
static struct rte_rcu_qsbr *qs_v;

static uint64_t bitmap[2] = {0};

static int
vchan_id_allocate(void)
{
	int idx;
	int pos;

	for (int i = 0; i < DAO_VIRTIO_DEV_MAX; i++) {
		idx = i / 64;
		pos = i % 64;
		if (!(bitmap[idx] & (1ULL << pos))) {
			bitmap[idx] |= (1ULL << pos);
			return i;
		}
	}
	return -1;
}

static int
check_virtio_config(void)
{
	static int wrkr_dma_devs;
	uint16_t nb_lcores = 0, nb_dma_devs;

	nb_dma_devs = rte_dma_count_avail();
	/* Service lcore */
	nb_lcores += 1;
	/* 1 Worker */
	nb_lcores += 1;

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
		" [-l]"

		"  -p PORTMASK_L[,PORTMASK_H]: Hexadecimal bitmask of ports to configure\n"
		"  -v VIRTIOMASK_L[,VIRTIOMASK_H]: Hexadecimal bitmask of virtio to configure\n"
		"  -d DMA_FLUSH_THR: Number of SGE's before DMA is flushed(1..15). Default is 8.\n"
		"  -P : Enable promiscuous mode\n"
		"  -s : Enable stats. Giving it multiple times makes stats verbose.\n"
		"  -f : Disable auto free with virtio Tx do sw freeing\n"
		"  -l : Enable CGX loopback\n\n",
		prgname);
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

#define MAX_JUMBO_PKT_LEN  9600
#define MEMPOOL_CACHE_SIZE 512

static const struct option lgopts[] = {
	{NULL, 0, 0, 0},
};

static const char short_options[] = "p:" /* portmask */
				    "v:" /* virt dev mask */
				    "d:" /* DMA flush threshold */
				    "P"  /* promiscuous */
				    "f"  /* Disable auto free */
				    "y:" /* Override DMA vfid */
				    "l"  /* Enable CGX loopback */
	;

static const char short_eal_options[] = "a:" /* allow */
					"h"  /* help */
					"l:" /* corelist */
	;

#define OPT_FILE_PREFIX_NUM 256
static const struct option long_eal_options[] = {{"file-prefix", 1, NULL, OPT_FILE_PREFIX_NUM}};

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	uint16_t nb_virtio_netdevs = 0;
	uint16_t nb_ethdevs = 0;
	char *prgname = argv[0];
	char *str, *saveptr;
	int option_index;
	char **argvopt;
	int opt, rc;

	argvopt = argv;
	optind = 1; /* Reset getopt lib */

	/* Error or normal output strings. */
	while ((opt = getopt_long(argc, argvopt, short_options, lgopts, &option_index)) != EOF) {
		switch (opt) {
		/* Portmask */
		case 'p':
			str = strtok_r(optarg, ",", &saveptr);
			if (str)
				eth_port_mask = parse_uint(str);
			if (!eth_port_mask) {
				APP_ERR("Invalid portmask %d: str %s saveptr %s\n", __LINE__, str,
					saveptr);
				print_usage(prgname);
				return -1;
			}
			nb_ethdevs = __builtin_popcountl(eth_port_mask);
			break;
		case 'v':
			str = strtok_r(optarg, ",", &saveptr);
			if (str)
				virtio_port_mask = parse_uint(str);

			if (!virtio_port_mask) {
				APP_ERR("Invalid portmask line %d, str %s saveptr %s\n", __LINE__,
					str, saveptr);
				print_usage(prgname);
				return -1;
			}
			nb_virtio_netdevs = __builtin_popcountl(virtio_port_mask);
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
		case 'l':
			ethdev_cgx_loopback = true;
			APP_INFO("Ethdev CGX loopback enabled\n");
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

	if ((nb_ethdevs != 1) || (nb_virtio_netdevs != 1)) {
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

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(void)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];
	uint8_t count, all_ports_up, print_flag = 0;
	uint16_t portid = worker.eth_port_id;
	struct rte_eth_link link;
	int rc;

	APP_INFO("\n");
	APP_INFO("Checking link status\n");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		if (force_quit)
			return;
		memset(&link, 0, sizeof(link));
		rc = rte_eth_link_get_nowait(portid, &link);
		if (rc < 0) {
			all_ports_up = 0;
			if (print_flag == 1)
				APP_ERR("Port %u link get failed: %s\n", portid, rte_strerror(-rc));
		}
		/* Print link status if flag set */
		if (print_flag == 1) {
			rte_eth_link_to_str(link_status_text, sizeof(link_status_text), &link);
			APP_INFO("Port %d %s\n", portid, link_status_text);
		}
		/* Clear all_ports_up flag if any link down */
		if (link.link_status == RTE_ETH_LINK_DOWN) {
			all_ports_up = 0;
			break;
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

static __rte_always_inline uint16_t
l2_virtio_desc_process(uint64_t netdev_map, uint16_t netdev_qp_count)
{
	uint16_t dev_id = 0;

	while (netdev_map) {
		if (!(netdev_map & 0x1)) {
			netdev_map >>= 1;
			dev_id++;
			continue;
		}
		dao_virtio_net_desc_manage(dev_id, netdev_qp_count);
		netdev_map >>= 1;
		dev_id++;
	}
	return 0;
}

static void *
service_main_loop(void *conf)
{
	struct thread_context *t = (struct thread_context *)conf;
	uint32_t lcore_id;
	pthread_t thread;
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(t->wrk_id, &cpuset);
	thread = pthread_self();
	pthread_setaffinity_np(thread, sizeof(cpuset), &cpuset);

	APP_INFO("service thread received LCORE ID %u\n", t->wrk_id);

	dao_pal_thread_init(t->wrk_id);

	while (service.state != THREAD_INITIALIZED)
		rte_pause();

	lcore_id = rte_lcore_id();
	if (lcore_id != t->wrk_id)
		APP_INFO(" Both worker id and lcore id not same %u:%u\n", t->wrk_id, lcore_id);

	/* Register this thread to rdaort quiescent state */
	rte_rcu_qsbr_thread_register(qs_v, lcore_id);
	rte_rcu_qsbr_thread_online(qs_v, lcore_id);

	APP_INFO("Entering service main loop on lcore %u\n", t->wrk_id);

	while (likely(!force_quit)) {
		/* Process virtio descriptors */
		l2_virtio_desc_process(service.netdev_map, service.netdev_qp_count);

		/* Flush and submit DMA ops */
		dao_dma_flush_submit();

		/* Update quiescent state */
		rte_rcu_qsbr_quiescent(qs_v, lcore_id);
	}

	rte_rcu_qsbr_thread_offline(qs_v, lcore_id);
	rte_rcu_qsbr_thread_unregister(qs_v, lcore_id);
	dao_pal_thread_fini(t->wrk_id);
	return conf;
}

#define RX_BURST_MAX 128

static __rte_always_inline void
eth_extbuf_enqueue_inline(uint16_t port, uint16_t queue, struct rte_mbuf **mbufs, uint16_t nb_pkts)
{
	int i = 0, nb_sent = 0;
	uint32_t len = 0;
	struct dao_virtio_net_hdr *vhdr;

	for (i = 0; i < nb_pkts; i++) {
		vhdr = (struct dao_virtio_net_hdr *)mbufs[i];
		len = vhdr->desc_data[1];
		/* Get mbuf address from data address */
		mbufs[i] = GET_MBUF_FROM_DATA_ADDR(mbufs[i], sizeof(vhdr->desc_data) + vhdr_sz);
		mbufs[i]->data_len = len - vhdr_sz;
		mbufs[i]->pkt_len = len - vhdr_sz;
	}

	nb_sent = rte_eth_tx_burst(port, queue, mbufs, nb_pkts);
	if (nb_pkts != nb_sent)
		rte_pktmbuf_free_bulk(&mbufs[nb_sent], nb_pkts - nb_sent);
}

static __rte_always_inline void
virtio_extbuf_enqueue_inline(uint16_t virtio_devid, uint16_t virt_q, struct rte_mbuf **mbufs,
			     uint16_t nb_pkts)
{
	int i = 0;
	uint32_t len, nb_sent;
	void *buffs[nb_pkts];
	struct dao_virtio_net_hdr *dhdr;

	for (i = 0; i < nb_pkts; i++) {
		len = rte_pktmbuf_pkt_len(mbufs[i]) + vhdr_sz;
		/* Prepend virtio header from data : Note: handled only single segment */
		dhdr = GET_VIRTIO_ADDR_FROM_MBUF(mbufs[i], sizeof(dhdr->desc_data) + vhdr_sz);
		if (!dhdr)
			continue;
		dhdr->desc_data[1] = len;
		buffs[i] = (void *)dhdr;
		dhdr->hdr.flags = 0;
		dhdr->hdr.gso_type = 0;
		dhdr->hdr.gso_size = 0;
		dhdr->hdr.csum_start = 0;
		dhdr->hdr.csum_offset = 0;
		dhdr->hdr.num_buffers = 1;

		buffs[i] = (void *)dhdr;
	}

	nb_sent = dao_virtio_net_enqueue_burst_ext(virtio_devid, virt_q, buffs, nb_pkts);
	if (nb_sent != nb_pkts)
		rte_pktmbuf_free_bulk(&mbufs[nb_sent], nb_pkts - nb_sent);
}

static __rte_always_inline uint16_t
l2fwd_extbuf_process_inline(void)
{
	uint16_t virtio_devid = worker.virtio_devid;
	uint16_t count = 0;
	uint64_t rx_q_map = worker.rx_q_map;
	uint16_t port = worker.eth_port_id;
	struct rte_mbuf *mbufs[RX_BURST_MAX];
	uint16_t queue, virt_q;
	uint16_t q_count;

	queue = 0;
	q_count = __builtin_popcountl(rx_q_map);
	while (q_count) {
		if (!(rx_q_map & RTE_BIT64(queue))) {
			queue = queue + 1;
			continue;
		}

		virt_q = (queue << 1) + 1;

		count = dao_virtio_net_dequeue_burst_ext(virtio_devid, virt_q, (void **)mbufs,
							 RX_BURST_MAX);
		if (count)
			eth_extbuf_enqueue_inline(port, queue, mbufs, count);

		count = rte_eth_rx_burst(port, queue, mbufs, RX_BURST_MAX);
		if (count) {
			virt_q = (queue << 1);
			virtio_extbuf_enqueue_inline(virtio_devid, virt_q, mbufs, count);
		}

		queue = queue + 1;
		q_count--;
	}

	return count;
}

static void *
l2_fwd_main(void *conf)
{
	struct thread_context *t = (struct thread_context *)conf;
	uint32_t lcore_id;
	cpu_set_t cpuset;
	pthread_t thread;
	int rc;

	CPU_ZERO(&cpuset);
	CPU_SET(t->wrk_id, &cpuset);
	thread = pthread_self();
	pthread_setaffinity_np(thread, sizeof(cpuset), &cpuset);

	APP_INFO("worker thread received LCORE ID %u\n", t->wrk_id);
	dao_pal_thread_init(t->wrk_id);

	while (worker.state != THREAD_INITIALIZED)
		rte_pause();

	lcore_id = rte_lcore_id();
	if (lcore_id != t->wrk_id)
		APP_INFO("worker Both worker id and lcore id not same %u:%u\n", t->wrk_id,
			 lcore_id);

	rc = dao_pal_dma_lcore_mem2dev_autofree_set(t->wrk_id, virtio_netdev_autofree);
	if (rc) {
		APP_ERR("Error in setting DMA device on lcore %u rc %d\n", t->wrk_id, rc);
		return NULL;
	}

	/* Register this thread to rdaort quiescent state */
	rte_rcu_qsbr_thread_register(qs_v, lcore_id);
	rte_rcu_qsbr_thread_online(qs_v, lcore_id);

	APP_INFO("Entering main loop on lcore %u\n", t->wrk_id);

	while (likely(!force_quit)) {
		// l2fwd_process_inline();
		l2fwd_extbuf_process_inline();

		/* Flush and submit DMA ops */
		dao_dma_flush_submit();

		/* Update quiescent state */
		rte_rcu_qsbr_quiescent(qs_v, lcore_id);
	}

	rte_rcu_qsbr_thread_offline(qs_v, lcore_id);
	rte_rcu_qsbr_thread_unregister(qs_v, lcore_id);
	dao_pal_thread_fini(t->wrk_id);
	return conf;
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

	return rte_eth_dev_rss_reta_update(portid, reta_conf, eth_dev_info.reta_size);
}

static void
clear_lcore_queue_mapping(uint16_t virtio_devid)
{
	/* Clear valid virtio queue map */
	worker.rx_q_map = 0;
	service.netdev_map &= ~RTE_BIT64(virtio_devid);
	rte_io_wmb();
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

	local_port_conf = &eth_dev_conf;
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
	for (queueid = eth_dev_q_count; queueid < nb_tx_queue; queueid++) {
		txconf = &dev_info.default_txconf;
		txconf->offloads = local_port_conf->txmode.offloads;

		rc = rte_eth_tx_queue_setup(portid, queueid, nb_txd, 0, txconf);
		if (rc < 0) {
			APP_ERR("rte_eth_tx_queue_setup: err=%d, port=%d\n", rc, portid);
			return rc;
		}
	}

	/* Setup RX queues */
	for (queueid = eth_dev_q_count; queueid < nb_rx_queue; queueid++) {
		struct rte_eth_rxconf rxq_conf;

		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = port_conf.rxmode.offloads;
		rc = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, 0, &rxq_conf, pktmbuf_pool);
		if (rc < 0) {
			APP_ERR("rte_eth_rx_queue_setup: err=%d, port=%d\n", rc, portid);
			return rc;
		}
	}

	rss_table_reset(portid);
	eth_dev_q_count = q_count;

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
	uint16_t virt_rx_q, q_id;

	virt_rx_q = virt_q_count / 2;

	if (worker.virtio_devid != virtio_devid) {
		APP_ERR("[%s], virtio_id didn't match %u:%u\n", __func__, worker.virtio_devid,
			virtio_devid);
		return -1;
	}

	q_id = 0;
	while (q_id < virt_rx_q) {
		APP_INFO("virtio queue configuring for q_id %u, virtio_devid %u\n", q_id,
			 virtio_devid);
		/* Add queue to valid virtio queue map */
		worker.rx_q_map |= RTE_BIT64(q_id);
		q_id++;
	}

	service.netdev_map |= RTE_BIT64(virtio_devid);
	service.netdev_qp_count = virt_q_count / 2;
	return 0;
}

static int
configure_promisc(uint16_t virtio_devid, uint8_t enable)
{
	APP_INFO("[%s] virtio_devid: %u promisc? : %d\n", __func__, virtio_devid, enable);

	if (virtio_devid != worker.virtio_devid) {
		APP_ERR("[%s] virtio_devid != worker.virtio_devid :%u:%u\n", __func__, virtio_devid,
			worker.virtio_devid);
		return -1;
	}
	if (enable)
		return rte_eth_promiscuous_enable(worker.eth_port_id);
	return rte_eth_promiscuous_disable(worker.eth_port_id);

	return 0;
}

static int
configure_allmulti(uint16_t virtio_devid, uint8_t enable)
{
	APP_ERR("[%s] virtio_devid %d allmulti: %d\n", __func__, virtio_devid, enable);

	if (virtio_devid != worker.virtio_devid) {
		APP_ERR("[%s] virtio_devid != worker.virtio_devid :%u:%u\n", __func__, virtio_devid,
			worker.virtio_devid);
		return -1;
	}

	if (enable)
		return rte_eth_allmulticast_enable(worker.eth_port_id);
	return rte_eth_allmulticast_disable(worker.eth_port_id);
}

static int
mac_addr_set(uint16_t virtio_devid, uint8_t *mac)
{
	APP_ERR("[%s] virtio_devid :%d mac %s\n", __func__, virtio_devid, mac);

	if (virtio_devid != worker.virtio_devid) {
		APP_ERR("[%s] virtio_devid != worker.virtio_devid :%u:%u\n", __func__, virtio_devid,
			worker.virtio_devid);
		return -1;
	}
	return rte_eth_dev_default_mac_addr_set(worker.eth_port_id, (struct rte_ether_addr *)mac);
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

	APP_ERR("[%s] virtio_devid:%d\n", __func__, virtio_devid);

	if (virtio_devid != worker.virtio_devid) {
		APP_ERR("[%s] virtio_devid != worker.virtio_devid :%u:%u\n", __func__, virtio_devid,
			worker.virtio_devid);
		return -1;
	}

	if (type)
		return rte_eth_dev_set_mc_addr_list(worker.eth_port_id, macs, mac_tbl->entries);
	return mac_list_update(worker.eth_port_id, macs, mac_tbl->entries);
}

static int
chksum_offload_configure(uint16_t virtio_devid)
{
	uint64_t csum_offload, tx_offloads, rx_offloads;
	struct rte_eth_conf *local_port_conf;
	uint16_t virt_q_count, portid;
	int rc;

	csum_offload = dao_virtio_netdev_feature_bits_get(virtio_devid) & 0x3;

	portid = worker.eth_port_id;
	local_port_conf = &eth_dev_conf;
	virt_q_count = eth_dev_q_count;

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

	if (virtio_devid != worker.virtio_devid) {
		APP_ERR("[%s] virtio_devid != worker.virtio_devid :%u:%u\n", __func__, virtio_devid,
			worker.virtio_devid);
		return -1;
	}

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

	portid = worker.eth_port_id;
	/* Reconfigure ethdev with required number of queues */
	rc = reconfig_ethdev(portid, virt_q_count / 2);
	if (rc)
		return rc;

	memset(reta_conf, 0, sizeof(reta_conf));
	reta_size = virtio_netdev_reta_sz;

	for (i = 0; i < reta_size; i++)
		reta_conf[i / RTE_ETH_RETA_GROUP_SIZE].mask = UINT64_MAX;

	next_q = rss->indirection_table[0];
	for (i = 0; i < reta_size; i++) {
		uint32_t reta_id = i / RTE_ETH_RETA_GROUP_SIZE;
		uint32_t reta_pos = i % RTE_ETH_RETA_GROUP_SIZE;

		reta_conf[reta_id].reta[reta_pos] = rss->indirection_table[i];
		if (eth_dev_info.reta_size != reta_size && rss->indirection_table[i] != next_q) {
			APP_ERR("Found a non sequential RETA table, cannot work with"
				" mismatched reta table size (ethdev=%u, virtio=%u)\n",
				eth_dev_info.reta_size, reta_size);
			APP_ERR("Please relaunch application with ethdev '%s' reta_size devarg"
				" as %u.",
				rte_dev_name(eth_dev_info.device), virtio_netdev_reta_sz);
			return -ENOTSUP;
		}
		next_q = rss->indirection_table[i] + 1;
		if (next_q >= virt_q_count / 2)
			next_q = 0;
	}

	for (i = reta_size; i < eth_dev_info.reta_size; i++) {
		uint32_t reta_id = i / RTE_ETH_RETA_GROUP_SIZE;
		uint32_t reta_pos = i % RTE_ETH_RETA_GROUP_SIZE;

		reta_conf[reta_id].reta[reta_pos] = rss->indirection_table[i];
		next_q = rss->indirection_table[i] + 1;
		if (next_q >= virt_q_count / 2)
			next_q = 0;
	}

	rc = rte_eth_dev_rss_reta_update(portid, reta_conf, eth_dev_info.reta_size);
	if (rc) {
		APP_ERR("Failed to update RSS reta table for portid=%d, rc=%d\n", portid, rc);
		return rc;
	}

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

	APP_ERR("[%s] virtio_devid : %d qmap_set: %d\n", __func__, virtio_devid, qmap_set);

	if (virtio_devid != worker.virtio_devid) {
		APP_ERR("[%s] virtio_devid != worker.virtio_devid :%u:%u\n", __func__, virtio_devid,
			worker.virtio_devid);
		return -1;
	}

	if (!qmap_set) {
		clear_lcore_queue_mapping(virtio_devid);
		/* Synchronize RCU */
		rte_rcu_qsbr_synchronize(qs_v, RTE_QSBR_THRID_INVALID);
		return 0;
	}

	clear_lcore_queue_mapping(virtio_devid);

	/* Get active virt queue count */
	virt_q_count = dao_virtio_netdev_queue_count(virtio_devid);
	APP_ERR("[%s] virtio_devid : %d virt_q_count : %d\n", __func__, virtio_devid, virt_q_count);

	if (virt_q_count <= 0 || virt_q_count & 0x1 ||
	    virt_q_count >= (DAO_VIRTIO_MAX_QUEUES - 1)) {
		APP_ERR("virtio_dev=%d: invalid virt_q_count=%d\n", virtio_devid, virt_q_count);
		return -EIO;
	}

	portid = worker.eth_port_id;
	rc = reconfig_ethdev(portid, virt_q_count / 2);
	if (rc)
		return rc;
	memset(reta_conf, 0, sizeof(reta_conf));
	reta_size = eth_dev_info.reta_size;

	for (i = 0; i < reta_size; i++)
		reta_conf[i / RTE_ETH_RETA_GROUP_SIZE].mask = UINT64_MAX;

	for (i = 0; i < reta_size; i++) {
		uint32_t reta_id = i / RTE_ETH_RETA_GROUP_SIZE;
		uint32_t reta_pos = i % RTE_ETH_RETA_GROUP_SIZE;

		reta_conf[reta_id].reta[reta_pos] = i % (virt_q_count / 2);
	}

	rc = rte_eth_dev_rss_reta_update(portid, reta_conf, reta_size);
	if (rc) {
		APP_ERR("Failed to update RSS reta table for portid=%d, rc=%d\n", portid, rc);
		return rc;
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

	APP_ERR("[%s] virtio_dev=%d: status=%s\n", __func__, virtio_devid,
		dao_virtio_dev_status_to_str(status));
	if (virtio_devid != worker.virtio_devid) {
		APP_ERR("[%s] virtio_devid != worker.virtio_devid :%u:%u\n", __func__, virtio_devid,
			worker.virtio_devid);
		return -1;
	}

	switch (status) {
	case VIRTIO_DEV_RESET:
	case VIRTIO_DEV_NEEDS_RESET:
		clear_lcore_queue_mapping(virtio_devid);
		reset_ethdev = true;
		break;
	case VIRTIO_DEV_DRIVER_OK:
		/* Configure checksum offload */
		chksum_offload_configure(virtio_devid);
		vhdr_sz = dao_virtio_netdev_hdrlen_get(virtio_devid);

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

	/* Reset RSS table */
	if (reset_ethdev) {
		rss_table_reset(worker.eth_port_id);
		/* Reconfigure ethdev with 1 queue */
		reconfig_ethdev(worker.eth_port_id, 1);
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

static int
setup_mempools(void)
{
	char s[64];

	snprintf(s, sizeof(s), "mbuf_pool_e%d", worker.eth_port_id);
	/* Create a pool with priv size of a cacheline */
	pktmbuf_pool =
		rte_pktmbuf_pool_create(s, pktmbuf_count, MEMPOOL_CACHE_SIZE, 0, pool_buf_len, 0);
	if (pktmbuf_pool == NULL) {
		APP_ERR("Cannot init mbuf pool\n");
		return -1;
	}

	APP_INFO("Allocated ethdev mbuf pool for portid=%d:%d\n", worker.eth_port_id,
		 worker.virtio_devid);
	return 0;
}

static void
setup_eth_devices(void)
{
	uint16_t queueid, i, portid = worker.eth_port_id;
	struct rte_eth_rss_reta_entry64 reta_conf[4];
	struct rte_eth_conf local_port_conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	uint16_t nb_rx_queue;
	uint32_t nb_tx_queue;
	int rc;

	APP_INFO("\n");

	/* Init port */
	APP_INFO("Initializing port %d ...", portid);
	fflush(stdout);

	local_port_conf = port_conf;
	nb_rx_queue = DEFAULT_QUEUES_PER_PORT;
	nb_tx_queue = nb_rx_queue;
	eth_dev_q_count = nb_rx_queue;

	APP_INFO_NH("Creating queues: nb_rxq=%d nb_txq=%u... ", nb_rx_queue, nb_tx_queue);

	rte_eth_dev_info_get(portid, &dev_info);
	eth_dev_info = dev_info;

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	local_port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
	if (local_port_conf.rx_adv_conf.rss_conf.rss_hf != port_conf.rx_adv_conf.rss_conf.rss_hf) {
		APP_INFO("Port %u modified RSS hash function based on "
			 "hardware support,"
			 "requested:%#" PRIx64 " configured:%#" PRIx64 "\n",
			 portid, port_conf.rx_adv_conf.rss_conf.rss_hf,
			 local_port_conf.rx_adv_conf.rss_conf.rss_hf);
	}

	/* Enable CGX loopback mode if needed */
	local_port_conf.lpbk_mode = !!ethdev_cgx_loopback;

	rc = rte_eth_dev_configure(portid, nb_rx_queue, nb_tx_queue, &local_port_conf);
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n", rc, portid);
	eth_dev_conf = local_port_conf;

	rc = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
	if (rc < 0)
		rte_exit(EXIT_FAILURE,
			 "Cannot adjust number of descriptors: err=%d, "
			 "port=%d\n",
			 rc, portid);

	rte_eth_macaddr_get(portid, &port_eth_addr);
	print_ethaddr(" Address:", &port_eth_addr);
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
		rc = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, 0, &rxq_conf, pktmbuf_pool);
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

	APP_INFO("\n");
	/* Dump L2FWD map */
	APP_INFO("L2FWD_MAP: ethdev_rx[%u] ======> virtiodev_tx[%u] (lcore %u)\n", portid,
		 worker.virtio_devid, worker_lcore_id);
}

static int
virtio_netdev_extbuf_put(uint16_t devid, void *buffs[], uint16_t nb_buffs)
{
	int i = 0;
	struct rte_mbuf *mbufs[nb_buffs];
	struct dao_virtio_net_hdr hdr;

	RTE_SET_USED(devid);
	for (i = 0; i < nb_buffs; i++)
		mbufs[i] = GET_MBUF_FROM_DATA_ADDR(buffs[i], sizeof(hdr.desc_data) + vhdr_sz);

	rte_pktmbuf_free_bulk(mbufs, nb_buffs);
	return 0;
}

static int
virtio_netdev_extbuf_get(uint16_t devid, void *buffs[], uint16_t nb_buffs)
{
	int rv = 0;
	uint16_t i = 0;
	struct rte_mbuf *mbufs[nb_buffs];
	struct dao_virtio_net_hdr hdr;

	RTE_SET_USED(devid);
	rv = rte_pktmbuf_alloc_bulk(pktmbuf_pool, mbufs, nb_buffs);
	if (rv) {
		APP_INFO("rte_pktmbuf_alloc_bulk failed\n");
		return -1;
	}
	for (i = 0; i < nb_buffs; i++)
		buffs[i] = (void *)(rte_pktmbuf_mtod(mbufs[i], uint8_t *) - sizeof(hdr.desc_data) -
				    vhdr_sz);

	return 0;
}

static void
setup_virtio_devices(void)
{
	struct dao_virtio_netdev_conf netdev_conf;
	struct dao_virtio_netdev_cbs cbs;
	uint32_t virtio_devid = worker.virtio_devid;
	struct rte_eth_link eth_link;
	uint16_t portid = worker.eth_port_id;
	int rc;

	APP_INFO("\n");

	/* Setup Virtio devices */

	/* Populate netdev conf */
	memset(&netdev_conf, 0, sizeof(netdev_conf));
	netdev_conf.auto_free_en = virtio_netdev_autofree;
	netdev_conf.pem_devid = pem_devid;
	// netdev_conf.pool = pktmbuf_pool;
	netdev_conf.flags = DAO_VIRTIO_NETDEV_EXTBUF;
	netdev_conf.dataroom_size = pool_buf_len;
	netdev_conf.mtu = 0;

	netdev_conf.reta_size = RTE_MAX(VIRTIO_NET_RSS_RETA_SIZE, eth_dev_info.reta_size);
	netdev_conf.hash_key_size = eth_dev_info.hash_key_size;
	eth_dev_get_overhead_len(eth_dev_info.max_rx_pktlen, eth_dev_info.max_mtu);
	rte_eth_link_get(portid, &eth_link);
	netdev_conf.link_info.status = eth_link.link_status;
	netdev_conf.link_info.speed = eth_link.link_speed;
	netdev_conf.link_info.duplex = eth_link.link_duplex;
	/* Register link status change interrupt callback */
	rte_eth_dev_callback_register(portid, RTE_ETH_EVENT_INTR_LSC, lsc_event_callback,
				      (void *)(uint64_t)virtio_devid);

	/* Populate default mac address */
	rte_eth_macaddr_get(portid, (struct rte_ether_addr *)netdev_conf.mac);

	netdev_conf.auto_free_en = virtio_netdev_autofree;

	/* Save reta size for future use */
	virtio_netdev_reta_sz = netdev_conf.reta_size;

	netdev_conf.dma_vchan = vchan_id_allocate();
	virtio_netdev_dma_vchans[virtio_devid] = netdev_conf.dma_vchan;

	dao_pal_dma_vchan_setup(virtio_devid, netdev_conf.dma_vchan, NULL);
	/* Initialize virtio net device */
	rc = dao_virtio_netdev_init(virtio_devid, &netdev_conf);
	if (rc)
		rte_exit(EXIT_FAILURE, "Failed to init virtio device\n");

	memset(&cbs, 0, sizeof(cbs));
	cbs.status_cb = virtio_dev_status_cb;
	cbs.rss_cb = rss_reta_configure;
	cbs.promisc_cb = configure_promisc;
	cbs.allmulti_cb = configure_allmulti;
	cbs.mac_set = mac_addr_set;
	cbs.mac_add = mac_addr_add;
	cbs.mq_configure = mq_configure;
	cbs.extbuf_get = virtio_netdev_extbuf_get;
	cbs.extbuf_put = virtio_netdev_extbuf_put;
	/* Register virtio dev callback register */
	dao_virtio_netdev_cb_register(&cbs);

	APP_INFO("\n");
	/* Dump L2FWD map */
	APP_INFO("L2FWD_MAP: virtiodev_rx[%u] ====> ethdev_tx[%u] (lcore %u)\n", virtio_devid,
		 portid, worker_lcore_id);
}

static void
release_virtio_devices(void)
{
	int rc;

	rc = dao_virtio_netdev_fini(worker.virtio_devid);
	if (rc)
		APP_ERR("Failed to stop virtio device %u: %s\n", worker.virtio_devid,
			rte_strerror(-rc));
}

static void
release_eth_devices(void)
{
	int rc;

	/* Stop ports */
	APP_INFO("Closing port %d...", worker.eth_port_id);
	rc = rte_eth_dev_stop(worker.eth_port_id);
	if (rc != 0)
		APP_ERR("Failed to stop port %u: %s\n", worker.eth_port_id, rte_strerror(-rc));
	rte_eth_dev_close(worker.eth_port_id);
	APP_INFO_NH(" Done\n");
}

static char **
vec_add1(char **vec, uint16_t *nb_elem, char *optarg)
{
	vec = reallocarray(vec, *nb_elem + 1, sizeof(vec));
	if (!vec) {
		APP_ERR("reallocarray failed");
		return NULL;
	}

	vec[*nb_elem] = strdup(optarg);
	*nb_elem = *nb_elem + 1;

	return vec;
}

static uint64_t
get_worker_mask(char *lcore)
{
	int l_lcore = 0, h_lcore, i = 0;
	char *endptr = NULL;
	uint64_t worker_mask = 0;

	l_lcore = strtoul(lcore, &endptr, 0);
	h_lcore = l_lcore;
	if (endptr) {
		endptr++;
		h_lcore = strtoul(endptr, NULL, 0);
	}

	if (h_lcore >= 64)
		rte_exit(EXIT_FAILURE, "lcore mask\n");

	for (i = l_lcore; i <= h_lcore; i++)
		worker_mask |= RTE_BIT64(i);

	APP_INFO("FINAL lcore MASK %lx\n", worker_mask);
	return worker_mask;
}

static int
parse_eal_args(int argc, char **argv, dao_pal_global_conf_t *conf, uint64_t *worker_mask)
{
	int opt;
	int option_index;

	while ((opt = getopt_long(argc, argv, short_eal_options, long_eal_options,
				  &option_index)) != EOF) {
		switch (opt) {
		case 'a':
			conf->dma_devices = vec_add1(conf->dma_devices, &conf->nb_dma_devs, optarg);
			break;

		case 'l':
			*worker_mask = get_worker_mask(optarg);
			break;

		case OPT_FILE_PREFIX_NUM:
			/* Dummy to attach prefix name for CI */
			break;

		default:
			return -1;
		}
	}

	return optind - 1;
}

static int
create_pthread_on_every_lcore(void)
{
	int ret = 0;
	uint32_t lcore = 0;
	bool service_core = 0;
	void *(*func)(void *conf);
	struct thread_context *t;
	uint64_t worker_mask_cp = worker_mask;

	for (lcore = 0; worker_mask_cp; lcore++) {
		if (!(RTE_BIT64(lcore) & worker_mask_cp))
			continue;
		worker_mask_cp &= ~(RTE_BIT64(lcore));

		func = l2_fwd_main;

		t = &thread_contexts[tid];
		t->wrk_id = lcore;
		APP_INFO("LCORE In MASK %lu:%u\n", worker_mask_cp, lcore);
		if (!service_core) {
			service_core = 1;
			func = service_main_loop;
		}
		ret = pthread_create(&t->id, NULL, func, t);
		if (ret != 0) {
			APP_INFO("Cannot start send pkts thread: %d\n", ret);
			return -1;
		}
		worker_lcore_id = lcore;
		tid++;
	}

	return 0;
}

int
main(int argc, char **argv)
{
	dao_pal_global_conf_t conf = {0};
	uint64_t worker_mask_cp = 0;
	unsigned int i = 0;
	uint32_t wrk_id;
	size_t sz;
	int rc;

	port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
	port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
	port_conf.rx_adv_conf.rss_conf.rss_hf = RTE_ETH_RSS_IP;
	port_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
	port_conf.txmode.offloads = RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

	rc = parse_eal_args(argc, argv, &conf, &worker_mask);
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");

	argc -= rc;
	argv += rc;

	if (__builtin_popcountl(worker_mask) != 2)
		rte_exit(EXIT_FAILURE, "Invalid lcore parameters expected 2\n");

	conf.nb_virtio_devs = 1;
	dao_pal_global_init(&conf);

	worker_mask |= RTE_BIT64(rte_get_main_lcore());

	dao_pal_dma_dev_setup(worker_mask);

	worker_mask &= ~(RTE_BIT64(rte_get_main_lcore()));

	create_pthread_on_every_lcore();

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Parse application arguments (after the EAL ones) */
	rc = parse_args(argc, argv);
	if (rc < 0) {
		APP_ERR("Invalid VIRTIO_L2FWD parameters\n");
		goto exit;
	}

	worker.eth_port_id = __builtin_ctz(eth_port_mask);
	if (!rte_eth_dev_is_valid_port(worker.eth_port_id)) {
		APP_ERR("invalid eth port id %u\n", worker.eth_port_id);
		goto exit;
	}

	worker.virtio_devid = __builtin_ctz(virtio_port_mask);
	if (worker.virtio_devid >= DAO_VIRTIO_DEV_MAX) {
		APP_ERR("invalid virito dev id %u\n", worker.virtio_devid);
		goto exit;
	}

	if (check_virtio_config()) {
		APP_ERR("check_virtio_config failed\n");
		goto exit;
	}

	worker_mask_cp = worker_mask;
	for (wrk_id = 0; worker_mask_cp; wrk_id++) {
		if (!(RTE_BIT64(wrk_id) & worker_mask_cp))
			continue;
		worker_mask_cp &= ~RTE_BIT64(wrk_id);
	}

	/* Set DMA devices for virtio control */
	dao_pal_dma_ctrl_dev_set(rte_get_main_lcore());

	/* Alloc mempools */
	if (setup_mempools()) {
		APP_ERR("setup_mempools Failed\n");
		goto exit;
	}

	/* Initialize all ethdev ports. 8< */
	setup_eth_devices();

	/* Setup RCU QSBR variable */
	sz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
	qs_v = (struct rte_rcu_qsbr *)rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
							 SOCKET_ID_ANY);
	if (!qs_v) {
		APP_ERR("Failed to alloc rcu_qsbr variable\n");
		goto exit;
	}

	rc = rte_rcu_qsbr_init(qs_v, RTE_MAX_LCORE);
	if (rc) {
		APP_ERR("rte_rcu_qsbr_init(): failed to init, rc=%d\n", rc);
		goto exit;
	}

	/* Start device */
	rc = rte_eth_dev_start(worker.eth_port_id);
	if (rc < 0) {
		APP_ERR("rte_eth_dev_start: err=%d, port=%d\n", rc, worker.eth_port_id);
		goto exit;
	}

	if (promiscuous_on)
		rte_eth_promiscuous_enable(worker.eth_port_id);

	check_all_ports_link_status();

	/* Initialize virtio devices */
	setup_virtio_devices();

	APP_INFO("\n");
	/* Change worker state */
	service.state = THREAD_INITIALIZED;
	worker.state = THREAD_INITIALIZED;

	for (i = 0; i < tid; i++)
		pthread_join(thread_contexts[i].id, NULL);
exit:
	APP_INFO("Bye...===============================================\n");
	/* Close virtio devices */
	release_virtio_devices();

	/* Close eth devices */
	release_eth_devices();

	/* dao_pal_global_fini */
	dao_pal_global_fini();

	APP_INFO("Bye...\n");

	return rc;
}
