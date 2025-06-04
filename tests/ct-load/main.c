/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <dao_conntrack.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_prefetch.h>

#define MAX_QUEUES                      16
#define BURST_SIZE                      128
#define RX_RING_SIZE                    4096
#define TX_RING_SIZE                    4096
#define MBUF_CACHE_SIZE                 512
#define CT_PRIV_SIZE                    sizeof(struct dao_ct_pkt_metadata)
#define NUM_MBUFS(nb_ports, num_queues) (8192 * (nb_ports) * (num_queues))
#define INACTIVITY_TIMEOUT_SEC          50

static volatile bool force_quit = false;
volatile time_t last_global_rx_time;

struct lcore_params {
	uint16_t port_in;
	uint16_t port_out;
	uint16_t queue_id;
};

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		force_quit = true;
	}
}

static bool
is_ip_packet(struct rte_mbuf *mbuf)
{
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	return eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) ||
	       eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
}

static int
lcore_main_loop(void *arg)
{
	struct lcore_params *params = (struct lcore_params *)arg;
	uint16_t port_in = params->port_in;
	uint16_t port_out = params->port_out;
	uint16_t queue_id = params->queue_id;

	struct rte_mbuf *bufs[BURST_SIZE];
	struct rte_mbuf *valid_bufs[BURST_SIZE];
	uint16_t nb_rx, nb_tx, i, valid_count;
	uint64_t rx_total = 0, tx_total = 0, drop_total = 0;
	uint64_t *ct_ptr = NULL;

	time_t last_print = time(NULL);

	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(rte_lcore_id(), &cpuset);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

	if (dao_conntrack_init((void **)&ct_ptr) != 0) {
		fprintf(stderr, "Core %u: Conntrack init failed\n", rte_lcore_id());
		return -1;
	}

	while (!force_quit) {
		nb_rx = rte_eth_rx_burst(port_in, queue_id, bufs, BURST_SIZE);
		if (unlikely(nb_rx == 0)) {
			rte_delay_us_block(100);
		} else {
			last_global_rx_time = time(NULL); // update global timestamp
			rx_total += nb_rx;
			valid_count = 0;

			for (i = 0; i < nb_rx; i++) {
				rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));
				if (is_ip_packet(bufs[i])) {
					valid_bufs[valid_count++] = bufs[i];
				} else {
					rte_pktmbuf_free(bufs[i]);
				}
			}

			if (valid_count > 0)
				dao_conntrack_execute(valid_bufs, valid_count, true);

			nb_tx = rte_eth_tx_burst(port_out, queue_id, valid_bufs, valid_count);
			tx_total += nb_tx;

			if (unlikely(nb_tx < valid_count)) {
				for (i = nb_tx; i < valid_count; i++)
					rte_pktmbuf_free(valid_bufs[i]);
				drop_total += (valid_count - nb_tx);
			}
		}

		// Print live stats every second
		time_t now = time(NULL);
		if (now - last_print >= 1) {
			printf("Core %u [Queue %u]: RX=%" PRIu64 " TX=%" PRIu64 " DROP=%" PRIu64
			       "\n",
			       rte_lcore_id(), queue_id, rx_total, tx_total, drop_total);
			last_print = now;
		}
	}

	dao_conntrack_fini();
	rte_eth_tx_done_cleanup(port_out, queue_id, 0);
	printf("Core %u Summary:\n", rte_lcore_id());
	printf("  RX Packets : %" PRIu64 "\n", rx_total);
	printf("  TX Packets : %" PRIu64 "\n", tx_total);
	printf("  Dropped    : %" PRIu64 "\n", drop_total);

	return 0;
}

int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	uint16_t nb_ports, portid;
	int ret;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "EAL initialization failed\n");

	argc -= ret;
	argv += ret;

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2)
		rte_exit(EXIT_FAILURE, "At least 2 ports required\n");

	unsigned nb_lcores = rte_lcore_count();
	unsigned num_queues = RTE_MIN((unsigned)(nb_lcores / 2), (unsigned)MAX_QUEUES);

	int socket_id = rte_socket_id();
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS(nb_ports, num_queues),
					    MBUF_CACHE_SIZE, CT_PRIV_SIZE,
					    RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	RTE_ETH_FOREACH_DEV (portid) {
		struct rte_eth_conf port_conf = {
			.rxmode = {.mq_mode = RTE_ETH_MQ_RX_RSS},
			.rx_adv_conf =
				{
					.rss_conf =
						{
							.rss_key = NULL,
							.rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP,
						},
				},
		};

		ret = rte_eth_dev_configure(portid, num_queues, num_queues, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Device config failed: port=%u\n", portid);

		for (uint16_t q = 0; q < num_queues; q++) {
			ret = rte_eth_rx_queue_setup(portid, q, RX_RING_SIZE,
						     rte_eth_dev_socket_id(portid), NULL,
						     mbuf_pool);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "RX queue setup failed: port=%u\n", portid);

			ret = rte_eth_tx_queue_setup(portid, q, TX_RING_SIZE,
						     rte_eth_dev_socket_id(portid), NULL);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "TX queue setup failed: port=%u\n", portid);
		}

		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Device start failed: port=%u\n", portid);
		rte_eth_promiscuous_enable(portid);
	}

	last_global_rx_time = time(NULL); // Initialize global timestamp

	static struct lcore_params lcore_args[MAX_QUEUES * 2];
	unsigned lcore_id = -1;

	for (uint16_t q = 0; q < num_queues; q++) {
		lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
		if (lcore_id == RTE_MAX_LCORE)
			break;
		lcore_args[q] = (struct lcore_params){.port_in = 0, .port_out = 1, .queue_id = q};
		rte_eal_remote_launch(lcore_main_loop, &lcore_args[q], lcore_id);

		lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
		if (lcore_id == RTE_MAX_LCORE)
			break;
		lcore_args[q + num_queues] =
			(struct lcore_params){.port_in = 1, .port_out = 0, .queue_id = q};
		rte_eal_remote_launch(lcore_main_loop, &lcore_args[q + num_queues], lcore_id);
	}

	// Monitor global inactivity
	while (!force_quit) {
		sleep(1);
		if (time(NULL) - last_global_rx_time >= INACTIVITY_TIMEOUT_SEC) {
			printf("[INFO] No traffic on any core for %d seconds. Exiting...\n",
			       INACTIVITY_TIMEOUT_SEC);
			force_quit = true;
			break;
		}
	}

	rte_eal_mp_wait_lcore();

	printf("[INFO] Port statistics:\n");
	struct rte_eth_stats stats;
	for (int port = 0; port < 2; port++) {
		memset(&stats, 0, sizeof(stats));
		if (rte_eth_stats_get(port, &stats) == 0) {
			printf(" Port %u:\n", port);
			printf("  RX Packets: %" PRIu64 "\n", stats.ipackets);
			printf("  TX Packets: %" PRIu64 "\n", stats.opackets);
			printf("  RX Errors : %" PRIu64 "\n", stats.ierrors);
			printf("  TX Errors : %" PRIu64 "\n", stats.oerrors);
			printf("  RX Bytes  : %" PRIu64 "\n", stats.ibytes);
			printf("  TX Bytes  : %" PRIu64 "\n", stats.obytes);
			printf("  RX Drops  : %" PRIu64 "\n", stats.imissed);
		} else {
			printf(" Port %u: Statistics retrieval failed\n", port);
		}
	}
	printf("[INFO] Application exiting...\n");
	rte_eal_cleanup();
	return 0;
}
