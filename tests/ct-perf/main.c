/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_rcu_qsbr.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_debug.h>
#include <rte_malloc.h>
#include <rte_random.h>
#include <rte_ether.h>
#include <rte_icmp.h>
#include <rte_ip.h>

#include <dao_conntrack.h>

#define MAX_WORKER_NB 128
#define PKTS_PER_CORE 256
#define ETH_IP_ICMP_SZ 42

struct lcore_params {
	struct rte_mbuf **pkts;
	bool ready_flag;
	bool start_flag;
	bool stop_flag;
};

struct rte_rcu_qsbr *qsbr_obj;
static struct lcore_params *lcores[MAX_WORKER_NB];
static struct rte_mempool *pkt_pool;

uint8_t pkt_ethipicmp_req[ETH_IP_ICMP_SZ] = {0x00, 0x0f, 0xb7, 0x06, 0x78, 0x30, 0x70, 0x35, 0x09,
					     0xde, 0xb4, 0xc9, 0x08, 0x00, 0x45, 0x00, 0x00, 0x3c,
					     0x01, 0x9b, 0x00, 0x00, 0x74, 0x01, 0xca, 0x76, 0x0a,
					     0xc1, 0x42, 0x77, 0x0a, 0x1c, 0x23, 0x5c, 0x08, 0x00,
					     0x4d, 0x2f, 0x00, 0x01, 0x00, 0x2c};

uint8_t pkt_ethipicmp_rep[ETH_IP_ICMP_SZ] = {0x70, 0x35, 0x09, 0xde, 0xb4, 0xc9, 0x00, 0x0f, 0xb7,
					     0x06, 0x78, 0x30, 0x08, 0x00, 0x45, 0x00, 0x00, 0x3c,
					     0x37, 0x3c, 0x00, 0x00, 0x40, 0x01, 0xc8, 0xd5, 0x0a,
					     0x1c, 0x23, 0x5c, 0x0a, 0xc1, 0x42, 0x77, 0x00, 0x00,
					     0x55, 0x2f, 0x00, 0x01, 0x00, 0x2c};

static uint16_t
icmp_checksum(uint16_t *icmph, int len)
{
	uint16_t ret = 0;
	uint32_t sum = 0;
	uint16_t odd_byte;

	while (len > 1) {
		sum += *icmph++;
		len -= 2;
	}

	if (len == 1) {
		*(uint8_t*)(&odd_byte) = * (uint8_t*)icmph;
		sum += odd_byte;
	}

	sum =  (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	ret =  ~sum;

	return ret;
}

static int
dump_conntrack(void *arg)
{
	RTE_SET_USED(arg);

	printf("dump_conntrack\n");
	while (1) {
//		dao_conntrack_dump();
		dao_conntrack_stats_dump();

		sleep(2);
	};

	return 0;
}

static int
lcore_conntrack(void *arg)
{
	struct lcore_params *lc_param = (struct lcore_params *)arg;
	struct rte_mbuf **pkts;
        unsigned lcore_id;
	uint32_t rand = (rte_rand() % 25);
	uint32_t i = 0;
	uint32_t j = 0;

        lcore_id = rte_lcore_id();
        printf("Starting mainloop on core %u\n", lcore_id);

	pkts = lc_param->pkts;

	lc_param->stop_flag = false;
	lc_param->ready_flag = true;
	while (!lc_param->start_flag)
	sleep(rand);
		;

	printf("Connectrack start. Lcore: %d\n", lcore_id);
	rte_rcu_qsbr_thread_register(qsbr_obj, lcore_id);
	rte_rcu_qsbr_thread_online(qsbr_obj, lcore_id);

	while (lc_param->stop_flag != true) {
		dao_conntrack_execute(&pkts[i], 1, 1);
		rte_rcu_qsbr_quiescent(qsbr_obj, lcore_id);
		i = (i + 1) & (PKTS_PER_CORE - 1);

		if (j++ == 512)
			break;
	}

	rte_rcu_qsbr_thread_offline(qsbr_obj, lcore_id);
	rte_rcu_qsbr_thread_unregister(qsbr_obj, lcore_id);

	return 0;
}

static int
alloc_pkt_buffers(struct rte_mbuf ***pkts, uint32_t nb_lcores)
{
	uint16_t nr_buf = (PKTS_PER_CORE * nb_lcores);
	struct rte_ether_hdr *eth;
	struct rte_ipv4_hdr *ip;
	struct rte_icmp_hdr *icmp;
	uint16_t buf_size = 128;
	uint16_t i;

	pkt_pool = rte_pktmbuf_pool_create("conntrack pkt pool",
			nr_buf,
			0,
			0,
			buf_size + RTE_PKTMBUF_HEADROOM,
			0);
	if (pkt_pool == NULL) {
		printf("Error with source mempool creation.\n");
		return -1;
	}

	*pkts = rte_malloc(NULL, nr_buf * sizeof(struct rte_mbuf *), 0);
	if (*pkts == NULL) {
		printf("Error: srcs malloc failed.\n");
		return -1;
	}

	if (rte_pktmbuf_alloc_bulk(pkt_pool, *pkts, nr_buf) != 0) {
		printf("alloc src mbufs failed.\n");
		return -1;
	}

	for (i = 0; i < nr_buf;) {
		(*pkts)[i]->packet_type = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_ICMP;
		memcpy(rte_pktmbuf_mtod((*pkts)[i], void *), &pkt_ethipicmp_req[0], ETH_IP_ICMP_SZ);
		eth = rte_pktmbuf_mtod((*pkts)[i], struct rte_ether_hdr *);
		ip = (struct rte_ipv4_hdr *)(eth + 1);
		icmp = (struct rte_icmp_hdr *)(ip + 1);
		memset((void *)(icmp + 1), rte_rand(), 32);

		icmp->icmp_seq_nb = (i % PKTS_PER_CORE);
		icmp->icmp_ident = i;
		icmp->icmp_cksum = icmp_checksum((uint16_t *)icmp, (sizeof(struct rte_icmp_hdr) + 32));
		ip->hdr_checksum = 0;
		ip->hdr_checksum = rte_ipv4_cksum(ip);

		(*pkts)[i + 1]->packet_type = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_ICMP;
		memcpy(rte_pktmbuf_mtod((*pkts)[i + 1], void *), &pkt_ethipicmp_rep[0], ETH_IP_ICMP_SZ);
		eth = rte_pktmbuf_mtod((*pkts)[i + 1], struct rte_ether_hdr *);
		ip = (struct rte_ipv4_hdr *)(eth + 1);
		icmp = (struct rte_icmp_hdr *)(ip + 1);
		memset((void *)(icmp + 1), rte_rand(), 32);

		icmp->icmp_seq_nb = (i % PKTS_PER_CORE);
		icmp->icmp_ident = i;
		icmp->icmp_cksum = icmp_checksum((uint16_t *)icmp, (sizeof(struct rte_icmp_hdr) + 32));
		ip->hdr_checksum = 0;
		ip->hdr_checksum = rte_ipv4_cksum(ip);

		i += 2;
	}

	return 0;
}

int
main(int argc, char **argv)
{
	int ret;
	unsigned lcore_id;
	struct rte_mbuf **pkts = NULL;
	uint32_t nb_lcores, cores = 0, i;
	uint32_t offset;
	uint16_t nr_buf;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	if (dao_conntrack_init((void **)&qsbr_obj) != 0) {
		printf("Error: Unable to initialize contrack\n");
		return 0;
	}

	nb_lcores = rte_lcore_count();
	alloc_pkt_buffers(&pkts, nb_lcores);
	nr_buf = (PKTS_PER_CORE * nb_lcores);

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if ((cores + 1) == (nb_lcores - 1)) {
			rte_eal_remote_launch(dump_conntrack, NULL, lcore_id);
			break;
		}

		offset = nr_buf / nb_lcores * cores;
		lcores[cores] = rte_malloc(NULL, sizeof(struct lcore_params), 0);
		lcores[cores]->pkts = pkts + offset;
		lcores[cores]->ready_flag = false;
		lcores[cores]->start_flag = false;
		rte_eal_remote_launch(lcore_conntrack, (void *)(lcores[cores]), lcore_id);
		cores++;
	}

	while (1) {
		bool ready = true;
		for (i = 0; i < cores; i++) {
			if (lcores[i]->ready_flag == false) {
				ready = 0;
				break;
			}
		}
		if (ready)
			break;
	}

	for (i = 0; i < cores; i++)
		lcores[i]->start_flag = true;

	rte_eal_mp_wait_lcore();

	dao_conntrack_fini();

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
