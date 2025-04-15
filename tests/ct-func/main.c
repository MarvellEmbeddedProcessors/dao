/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_memory.h>

#include <dao_conntrack.h>
#include <pcap.h>

static uint16_t num_pkt = 0;
static struct rte_mempool *pkt_pool;

void run_test(struct rte_mbuf **pkts);
void pkt_handler(unsigned char *arg, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);

void
run_test(struct rte_mbuf **pkts)
{
	struct dao_ct_pkt_metadata *mdata;
	uint32_t conn_execute = 0;
	int i;

	for (i = 0; i < num_pkt; i++) {
		dao_conntrack_execute(&pkts[i], 1, 1);
		mdata = dao_ct_pkt_metadata(pkts[i]);
		if (!(mdata->ct_state & DAO_CONN_STATE_FLAG(DAO_CONN_STATE_INVALID)))
			conn_execute++;
	}

	dao_conntrack_dump();
	dao_conntrack_stats_dump();
	printf("Conntrack add success\n");
}

void
pkt_handler(unsigned char *arg, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
	struct rte_mbuf **pkts = (struct rte_mbuf **)arg;
	struct rte_ether_hdr *eth;
	struct rte_ipv4_hdr *ip;

	memcpy(rte_pktmbuf_mtod(pkts[num_pkt], void *), packet, pkthdr->len);
	eth = rte_pktmbuf_mtod(pkts[num_pkt], struct rte_ether_hdr *);

	pkts[num_pkt]->packet_type = RTE_PTYPE_L2_ETHER;

	if (ntohs(eth->ether_type) == RTE_ETHER_TYPE_IPV4)
		pkts[num_pkt]->packet_type |= RTE_PTYPE_L3_IPV4;

	ip = (struct rte_ipv4_hdr *)(eth + 1);
	if (ip->next_proto_id == IPPROTO_ICMP)
		pkts[num_pkt]->packet_type |= RTE_PTYPE_L4_ICMP;
	else if (ip->next_proto_id == IPPROTO_TCP)
		pkts[num_pkt]->packet_type |= RTE_PTYPE_L4_TCP;
	else if (ip->next_proto_id == IPPROTO_UDP)
		pkts[num_pkt]->packet_type |= RTE_PTYPE_L4_UDP;

	num_pkt++;
}

static int
alloc_pkt_buffers(struct rte_mbuf ***pkts, uint16_t nr_buf)
{
	uint16_t buf_size = 2048;

	pkt_pool = rte_pktmbuf_pool_create("conntrack pkt pool", nr_buf, 0, 0,
					   buf_size + RTE_PKTMBUF_HEADROOM, 0);
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

	return 0;
}

int
main(int argc, char **argv)
{
	unsigned int packet_counter = 0;
	struct rte_mbuf **pkts = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	const char *packet;
	pcap_t *handle;
	uint64_t *ptr;
	long pos;
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	if (dao_conntrack_init((void **)&ptr) != 0) {
		printf("Error: Unable to initialize contrack\n");
		return 0;
	}

	handle = pcap_open_offline(argv[1], errbuf);
	if (handle == NULL) {
		printf("Failed to open pcap file: %s\n", argv[1]);
		return -1;
	}

	pos = ftell(pcap_file(handle));
	while ((packet = (const char *)pcap_next(handle, &header)))
		packet_counter++;

	alloc_pkt_buffers(&pkts, packet_counter);
	fseek(pcap_file(handle), pos, SEEK_SET);

	if (pcap_loop(handle, packet_counter, pkt_handler, (unsigned char *)pkts) < 0) {
		printf("Iterating over pcap file failed\n");
		return -1;
	}

	pcap_close(handle);

	run_test(pkts);

	dao_conntrack_fini();

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
