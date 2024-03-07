/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "flow.h"

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS       8191
#define MBUF_CACHE_SIZE 250

#define MAX_RTE_FLOW_ACTIONS 16
#define MAX_RTE_FLOW_PATTERN 16

#define ACTION_MARK_ID 0x777

enum port_type {
	RX_PORT = 1,
	TX_PORT = 2,
};

struct lcore_conf {
	uint16_t lcore_id;
	uint16_t portid;
	enum port_type type;
	bool in_use;
};

struct flow_test_global_cfg {
	uint8_t trigger_transmit;
	uint8_t receive_done;
	uint16_t rx_portid;
	uint16_t tx_portid;
	struct rte_mempool *mbp;
	struct lcore_conf lconf[RTE_MAX_LCORE];
	bool start_rx_thread;
	bool start_tx_thread;
};

static inline void
wait_for_tx_trigger(struct flow_test_global_cfg *gbl_cfg)
{
	while (gbl_cfg->start_tx_thread &&
	       __atomic_load_n(&gbl_cfg->trigger_transmit, __ATOMIC_RELAXED) != 1)
		rte_pause();
}

static inline void
wait_for_rx_to_complete(struct flow_test_global_cfg *gbl_cfg)
{
	while (__atomic_load_n(&gbl_cfg->receive_done, __ATOMIC_RELAXED) != 1)
		rte_pause();

	__atomic_store_n(&gbl_cfg->receive_done, 0, __ATOMIC_RELAXED);
}

static inline void
trigger_tx(struct flow_test_global_cfg *gbl_cfg)
{
	__atomic_store_n(&gbl_cfg->trigger_transmit, 1, __ATOMIC_RELAXED);
}

static inline void
receive_done(struct flow_test_global_cfg *gbl_cfg)
{
	__atomic_store_n(&gbl_cfg->receive_done, 1, __ATOMIC_RELAXED);
}

static inline void
print_flow_error(struct rte_flow_error error)
{
	dao_info("Flow can't be created %d message: %s", error.type,
		 error.message ? error.message : "(no stated reason)");
}

static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	struct rte_ether_addr addr;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		dao_info("Error during getting device (port %u) info: %s", port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE, rte_eth_dev_socket_id(port),
						NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE, rte_eth_dev_socket_id(port),
						&txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	dao_info("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
		 " %02" PRIx8 "",
		 port, RTE_ETHER_ADDR_BYTES(&addr));

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}

static void
receive_thread_main(struct flow_test_global_cfg *gbl_cfg)
{
	struct rte_mbuf *bufs[BURST_SIZE];
	struct rte_mbuf *mbuf;
	uint16_t i, count = 0;
	int rc = 0;

	while (gbl_cfg->start_rx_thread) {
		/* Get burst of RX packets, from first port of pair. */
		const uint16_t nb_rx = rte_eth_rx_burst(gbl_cfg->rx_portid, 0, bufs, BURST_SIZE);

		if (unlikely(nb_rx == 0))
			continue;

		dao_dbg("	Received %d pkts lcore %d on port %d pkt %p", nb_rx, rte_lcore_id(),
			gbl_cfg->rx_portid, bufs[0]);

		dao_flow_lookup(gbl_cfg->rx_portid, bufs, nb_rx);

		for (i = 0; i < nb_rx; i++) {
			mbuf = bufs[i];
			if (bufs[i]->ol_flags & RTE_MBUF_F_RX_FDIR_ID) {
				rc = validate_flow_match(mbuf, mbuf->hash.fdir.hi);
				if (rc) {
					dao_err("Packet mark incorrect. exiting");
					exit(-1);
				}
			} else {
				rc = validate_flow_match(mbuf, 0);
				if (rc) {
					dao_err("Unmarked packet's ip address mismatch. exiting");
					exit(-1);
				}
			}
		}
		/* Free any all received packets. */
		if (nb_rx > 0) {
			for (i = 0; i < nb_rx; i++)
				rte_pktmbuf_free(bufs[i]);
		}
		count += nb_rx;
		if (count >= BURST_SIZE) {
			receive_done(gbl_cfg);
			count = 0;
		}
	}
}

static void
transmit_thread_main(struct flow_test_global_cfg *gbl_cfg)
{
	struct rte_mbuf *pkts[BURST_SIZE];
	uint16_t nb_tx;

	while (gbl_cfg->start_tx_thread) {
		wait_for_tx_trigger(gbl_cfg);
		sample_packet(gbl_cfg->mbp, pkts);
		nb_tx = rte_eth_tx_burst(gbl_cfg->tx_portid, 0, pkts, BURST_SIZE);

		dao_dbg("	Transmitting lcore_id %d pkt %p nb_tx %d", rte_lcore_id(), pkts[0],
			nb_tx);
		__atomic_store_n(&gbl_cfg->trigger_transmit, 0, __ATOMIC_RELAXED);

		DAO_ASSERT_EQUAL(nb_tx, BURST_SIZE, "All packets not transmitted");
	}
}

static int
flow_offload_launch_one_lcore(void *config)
{
	struct flow_test_global_cfg *gbl_cfg = config;
	struct lcore_conf *qconf;
	uint32_t lcore_id;

	RTE_SET_USED(config);
	lcore_id = rte_lcore_id();
	qconf = &gbl_cfg->lconf[lcore_id];
	qconf->lcore_id = lcore_id;
	qconf->in_use = true;
	dao_info("Entering main loop on lcore %u, port %d type %d", lcore_id, qconf->portid,
		 qconf->type);
	if (qconf->type == RX_PORT) {
		gbl_cfg->start_rx_thread = true;
		receive_thread_main(gbl_cfg);
	} else {
		gbl_cfg->start_tx_thread = true;
		transmit_thread_main(gbl_cfg);
	}

	return 0;
}

static inline void
run_test(struct flow_test_global_cfg *gbl_cfg)
{
	/* Signal tx thread to send packets and wait for reception to complete*/
	trigger_tx(gbl_cfg);
	wait_for_rx_to_complete(gbl_cfg);
}

static void
flow_test_info(struct flow_test_global_cfg *gbl_cfg, flow_test_create_t test_cb)
{
	struct rte_flow_error error = {0};
	struct dao_flow *flow[10];
	int i;

	dao_info("### Executing %s ###", __func__);
	for (i = 0; i < 10; i++) {
		flow[i] = test_cb(gbl_cfg->rx_portid, i % 2);
		if (!flow[i])
			dao_exit("Failed to create a flow");
	}

	run_test(gbl_cfg);
	run_test(gbl_cfg);
	run_test(gbl_cfg);
	run_test(gbl_cfg);
	DAO_ASSERT_EQUAL(dao_flow_info(gbl_cfg->rx_portid, stdout, &error), 0,
			 "Failed to get flow info for port %d, err %d", gbl_cfg->rx_portid, errno);

	for (i = 0; i < 10; i++) {
		if (dao_flow_destroy(gbl_cfg->rx_portid, flow[i], &error)) {
			print_flow_error(error);
			dao_err("error in deleting flow");
		}
	}
}

static void
flow_test_flush(struct flow_test_global_cfg *gbl_cfg, flow_test_create_t test_cb)
{
	struct dao_flow_count count;
	struct rte_flow_error error;
	struct dao_flow *flow[10];
	int i;

	dao_info("### Executing %s ###", __func__);
	for (i = 0; i < 10; i++) {
		flow[i] = test_cb(gbl_cfg->rx_portid, i % 2);
		if (!flow[i])
			dao_exit("Failed to create a flow");
	}

	/* Get flow count */
	DAO_ASSERT_SUCCESS(dao_flow_count(gbl_cfg->rx_portid, &count, &error),
			   "Failed to get flow info for port %d, err %d", gbl_cfg->rx_portid,
			   errno);
	DAO_ASSERT_NOT_ZERO(count.dao_flow, "DAO flow count is zero");
	DAO_ASSERT_NOT_ZERO(count.acl_rule, "ACL rule count is zero");

	/* Flush all the flows */
	DAO_ASSERT_SUCCESS(dao_flow_flush(gbl_cfg->rx_portid, &error),
			   "Failed to flush flows for port %d, err %d", gbl_cfg->rx_portid, errno);

	/* Get flow count */
	DAO_ASSERT_SUCCESS(dao_flow_count(gbl_cfg->rx_portid, &count, &error),
			   "Failed to get flow info for port %d, err %d", gbl_cfg->rx_portid,
			   errno);
	DAO_ASSERT_ZERO(count.dao_flow, "DAO flow count is non zero: %d", count.dao_flow);
	DAO_ASSERT_ZERO(count.acl_rule, "ACL rule count is non zero: %d", count.acl_rule);
	DAO_ASSERT_ZERO(count.hw_offload_flow, "HW offload flow count is non zero: %d",
			count.hw_offload_flow);
}

static void
flow_test_dump(struct flow_test_global_cfg *gbl_cfg, flow_test_create_t test_cb)
{
	struct rte_flow_error error;
	struct dao_flow *flow[2];
	int rc;

	dao_info("### Executing %s ###", __func__);
	flow[0] = test_cb(gbl_cfg->rx_portid, 0);
	flow[1] = test_cb(gbl_cfg->rx_portid, 1);
	if (!flow[0] || !flow[1])
		dao_exit("Failed to create a flow");

	run_test(gbl_cfg);
	run_test(gbl_cfg);
	run_test(gbl_cfg);
	run_test(gbl_cfg);
	rc = dao_flow_dev_dump(gbl_cfg->rx_portid, flow[0], stdout, &error);
	if (rc)
		dao_exit("Failed to dump flow");

	if (dao_flow_destroy(gbl_cfg->rx_portid, flow[0], &error)) {
		print_flow_error(error);
		dao_err("error in deleting flow");
	}
	if (dao_flow_destroy(gbl_cfg->rx_portid, flow[1], &error)) {
		print_flow_error(error);
		dao_err("error in deleting flow");
	}
}

static void
flow_test_query(struct flow_test_global_cfg *gbl_cfg, flow_test_create_t test_cb, bool reset)
{
	struct dao_flow_query_count count_query = {0};
	uint64_t hw_flow_count[2] = {0};
	struct rte_flow_action action;
	struct rte_flow_error error;
	struct dao_flow *flow[2];
	int i;

	dao_info("### Executing %s ###", __func__);
	flow[0] = test_cb(gbl_cfg->rx_portid, 0);
	flow[1] = test_cb(gbl_cfg->rx_portid, 1);
	if (!flow[0] || !flow[1])
		dao_exit("Failed to create a flow");

	action.type = RTE_FLOW_ACTION_TYPE_COUNT;
	count_query.reset = reset;
	run_test(gbl_cfg);
	for (i = 0; i < 2; i++) {
		DAO_ASSERT_EQUAL(
			dao_flow_query(gbl_cfg->rx_portid, flow[i], &action, &count_query, &error),
			0, "Failed to query flow, err %d", errno);
		DAO_ASSERT_EQUAL(count_query.hits_set, 1, "HW offload query hits not set");
		DAO_ASSERT_EQUAL(count_query.hits, 0, "HW offload flow hits non-zero: %ld",
				 count_query.hits);
		DAO_ASSERT_EQUAL(count_query.acl_rule_hits, BURST_SIZE / 3, "ACL rule hits zero");
		dao_dbg("Flow[%d] reset %s HW offload hit_set %d hits %ld acl_rule_hits %ld", i,
			reset ? "true" : "false", count_query.hits_set, count_query.hits,
			count_query.acl_rule_hits);
	}

	run_test(gbl_cfg);
	for (i = 0; i < 2; i++) {
		DAO_ASSERT_EQUAL(
			dao_flow_query(gbl_cfg->rx_portid, flow[i], &action, &count_query, &error),
			0, "Failed to query flow");
		if (reset) {
			DAO_ASSERT_EQUAL(count_query.hits_set, 1, "HW offload query hits not set");
			DAO_ASSERT_EQUAL(count_query.hits, BURST_SIZE / 3,
					 "HW offload flow hits zero");
			DAO_ASSERT_EQUAL(count_query.acl_rule_hits, 0, "ACL rule hits %ld non-zero",
					 count_query.acl_rule_hits);
		} else {
			hw_flow_count[i] += BURST_SIZE / 3;
			DAO_ASSERT_EQUAL(count_query.hits_set, 1, "HW offload query hits not set");
			DAO_ASSERT_EQUAL(count_query.hits, hw_flow_count[i],
					 "HW offload flow hits invalid, %ld != %ld",
					 count_query.hits, hw_flow_count[i]);
			DAO_ASSERT_EQUAL(count_query.acl_rule_hits, BURST_SIZE / 3,
					 "ACL rule hits zero");
		}
		dao_info("Flow[%d] reset %s HW offload hit_set %d hits %ld acl_rule_hits %ld", i,
			 reset ? "true" : "false", count_query.hits_set, count_query.hits,
			 count_query.acl_rule_hits);
	}

	run_test(gbl_cfg);
	for (i = 0; i < 2; i++) {
		DAO_ASSERT_EQUAL(
			dao_flow_query(gbl_cfg->rx_portid, flow[i], &action, &count_query, &error),
			0, "Failed to query flow");
		if (reset) {
			DAO_ASSERT_EQUAL(count_query.hits_set, 1, "HW offload query hits not set");
			DAO_ASSERT_EQUAL(count_query.hits, BURST_SIZE / 3,
					 "HW offload flow hits zero");
			DAO_ASSERT_EQUAL(count_query.acl_rule_hits, 0, "ACL rule hits non-zero");
		} else {
			hw_flow_count[i] += BURST_SIZE / 3;
			DAO_ASSERT_EQUAL(count_query.hits_set, 1, "HW offload query hits not set");
			DAO_ASSERT_EQUAL(count_query.hits, hw_flow_count[i],
					 "HW offload flow hits invalid, %ld != %ld",
					 count_query.hits, hw_flow_count[i]);
			DAO_ASSERT_EQUAL(count_query.acl_rule_hits, BURST_SIZE / 3,
					 "ACL rule hits zero");
		}
		dao_info("Flow[%d] reset %s HW offload hit_set %d hits %ld acl_rule_hits %ld", i,
			 reset ? "true" : "false", count_query.hits_set, count_query.hits,
			 count_query.acl_rule_hits);
	}

	run_test(gbl_cfg);
	for (i = 0; i < 2; i++) {
		DAO_ASSERT_EQUAL(
			dao_flow_query(gbl_cfg->rx_portid, flow[i], &action, &count_query, &error),
			0, "Failed to query flow");
		if (reset) {
			DAO_ASSERT_EQUAL(count_query.hits_set, 1, "HW offload query hits not set");
			DAO_ASSERT_EQUAL(count_query.hits, BURST_SIZE / 3,
					 "HW offload flow hits zero");
			DAO_ASSERT_EQUAL(count_query.acl_rule_hits, 0, "ACL rule hits non-zero");
		} else {
			hw_flow_count[i] += BURST_SIZE / 3;
			DAO_ASSERT_EQUAL(count_query.hits_set, 1, "HW offload query hits not set");
			DAO_ASSERT_EQUAL(count_query.hits, hw_flow_count[i],
					 "HW offload flow hits invalid, %ld != %ld",
					 count_query.hits, hw_flow_count[i]);
			DAO_ASSERT_EQUAL(count_query.acl_rule_hits, BURST_SIZE / 3,
					 "ACL rule hits zero");
		}
		dao_info("Flow[%d] reset %s HW offload hit_set %d hits %ld acl_rule_hits %ld", i,
			 reset ? "true" : "false", count_query.hits_set, count_query.hits,
			 count_query.acl_rule_hits);
	}

	if (dao_flow_destroy(gbl_cfg->rx_portid, flow[0], &error)) {
		print_flow_error(error);
		dao_err("error in deleting flow");
	}

	if (dao_flow_destroy(gbl_cfg->rx_portid, flow[1], &error)) {
		print_flow_error(error);
		dao_err("error in deleting flow");
	}
}

static void
flow_test_create_destroy(struct flow_test_global_cfg *gbl_cfg, flow_test_create_t test_cb)
{
	struct rte_flow_error error = {0};
	struct dao_flow *flow[9];

	dao_info("### Executing %s ###", __func__);
	flow[0] = test_cb(gbl_cfg->rx_portid, 0);
	flow[1] = test_cb(gbl_cfg->rx_portid, 1);
	if (!flow[0] || !flow[1])
		dao_exit("Failed to create a flow");

	run_test(gbl_cfg);

	flow[3] = test_cb(gbl_cfg->rx_portid, 0);
	flow[4] = test_cb(gbl_cfg->rx_portid, 1);
	if (!flow[3] || !flow[4])
		dao_exit("Failed to create a flow");

	flow[6] = test_cb(gbl_cfg->rx_portid, 0);
	flow[7] = test_cb(gbl_cfg->rx_portid, 1);
	if (!flow[6] || !flow[7])
		dao_exit("Failed to create a flow");

	run_test(gbl_cfg);

	if (dao_flow_destroy(gbl_cfg->rx_portid, flow[0], &error)) {
		print_flow_error(error);
		dao_err("error in deleting flow");
	}
	if (dao_flow_destroy(gbl_cfg->rx_portid, flow[1], &error)) {
		print_flow_error(error);
		dao_err("error in deleting flow");
	}

	run_test(gbl_cfg);

	if (dao_flow_destroy(gbl_cfg->rx_portid, flow[3], &error)) {
		print_flow_error(error);
		dao_err("error in deleting flow");
	}
	if (dao_flow_destroy(gbl_cfg->rx_portid, flow[4], &error)) {
		print_flow_error(error);
		dao_err("error in deleting flow");
	}

	run_test(gbl_cfg);

	flow[0] = test_cb(gbl_cfg->rx_portid, 0);
	flow[1] = test_cb(gbl_cfg->rx_portid, 1);
	if (!flow[0] || !flow[1])
		dao_exit("Failed to create a flow");

	run_test(gbl_cfg);
	run_test(gbl_cfg);
	run_test(gbl_cfg);

	if (dao_flow_destroy(gbl_cfg->rx_portid, flow[0], &error)) {
		print_flow_error(error);
		dao_err("error in deleting flow");
	}
	if (dao_flow_destroy(gbl_cfg->rx_portid, flow[1], &error)) {
		print_flow_error(error);
		dao_err("error in deleting flow");
	}
	if (dao_flow_destroy(gbl_cfg->rx_portid, flow[6], &error)) {
		print_flow_error(error);
		dao_err("error in deleting flow");
	}
	if (dao_flow_destroy(gbl_cfg->rx_portid, flow[7], &error)) {
		print_flow_error(error);
		dao_err("error in deleting flow");
	}
}

static void
profile_tests(struct flow_test_global_cfg *gbl_cfg, const char *prfl, bool hw_offload_enable)
{
	struct dao_flow_offload_config config;
	char name[RTE_ETH_NAME_MAX_LEN];
	uint16_t portid;
	int rc;

	dao_info("##### Executing tests for profile: %s, hw_offload: %s #####", prfl,
		 hw_offload_enable ? "enable" : "disable");
	RTE_ETH_FOREACH_DEV(portid) {
		if (rte_eth_dev_get_name_by_port(portid, name) < 0)
			continue;
		memset(&config, 0, sizeof(struct dao_flow_offload_config));
		/* Enable HW offloading */
		config.feature |= hw_offload_enable ? DAO_FLOW_HW_OFFLOAD_ENABLE : 0;
		rte_strscpy(config.parse_profile, prfl, DAO_FLOW_PROFILE_NAME_MAX);
		rc = dao_flow_init(portid, &config);
		if (rc) {
			dao_err("Error: DAO flow init failed, err %d", rc);
			return;
		}
	}

	if (strncmp(config.parse_profile, "ovs", DAO_FLOW_PROFILE_NAME_MAX) == 0) {
		flow_test_create_destroy(gbl_cfg, ovs_flow_test_create);
		flow_test_query(gbl_cfg, basic_flow_test_create, false);
		flow_test_query(gbl_cfg, basic_flow_test_create, true);
		flow_test_info(gbl_cfg, basic_flow_test_create);
		flow_test_dump(gbl_cfg, basic_flow_test_create);
		flow_test_flush(gbl_cfg, basic_flow_test_create);
	} else if (strncmp(config.parse_profile, "default", DAO_FLOW_PROFILE_NAME_MAX) == 0) {
		flow_test_create_destroy(gbl_cfg, default_flow_test_create);
	} else {
		dao_err("Invalid parse profile name %s", config.parse_profile);
	}

	RTE_ETH_FOREACH_DEV(portid) {
		if (rte_eth_dev_get_name_by_port(portid, name) < 0)
			continue;
		dao_flow_fini(portid);
	}
	dao_info("## Done ##");
}

int
main(int argc, char *argv[])
{
	struct flow_test_global_cfg *gbl_cfg;
	struct rte_mempool *mbuf_pool;
	uint16_t nb_ports;
	uint16_t portid;
	uint32_t lcore_id;
	int rc, i;

	/* Initializion the Environment Abstraction Layer (EAL). */
	rc = rte_eal_init(argc, argv);
	if (rc < 0)
		dao_err("Error with EAL initialization");

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports != 2)
		dao_err("Error: Test should be launched with 2 ports");

	gbl_cfg = calloc(1, sizeof(struct flow_test_global_cfg));
	if (!gbl_cfg)
		dao_exit("Error: Failed to allocate memory");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
					    RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		dao_err("Cannot create mbuf pool");

	lcore_id = 0;
	gbl_cfg->mbp = mbuf_pool;
	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid) {
		if (port_init(portid, mbuf_pool) != 0)
			dao_err("Cannot init port %" PRIu8 "", portid);

		while (!rte_lcore_is_enabled(lcore_id) || lcore_id == rte_get_main_lcore() ||
		       gbl_cfg->lconf[lcore_id].type != 0) {
			lcore_id++;
			if (lcore_id >= RTE_MAX_LCORE)
				dao_exit("Not enough cores");
		}
		if (portid % 2 == 0) {
			gbl_cfg->rx_portid = portid;
			gbl_cfg->lconf[lcore_id].portid = portid;
			gbl_cfg->lconf[lcore_id].type = RX_PORT;
		} else {
			gbl_cfg->tx_portid = portid;
			gbl_cfg->lconf[lcore_id].portid = portid;
			gbl_cfg->lconf[lcore_id].type = TX_PORT;
		}
	}

	/* Create a thread for handling msgs from VFs */
	rte_eal_mp_remote_launch(flow_offload_launch_one_lcore, gbl_cfg, SKIP_MAIN);
	/* Test cases */
	profile_tests(gbl_cfg, "ovs", true);
	profile_tests(gbl_cfg, "default", true);

	/* Exiting the mbox sync thread */
	if (gbl_cfg->start_tx_thread) {
		gbl_cfg->start_tx_thread = false;
		gbl_cfg->start_rx_thread = false;
	}

	for (i = 0; i < RTE_MAX_LCORE; i++) {
		if (gbl_cfg->lconf[i].in_use)
			rte_eal_wait_lcore(gbl_cfg->lconf[i].lcore_id);
	}

	RTE_ETH_FOREACH_DEV(portid) {
		dao_info("Closing port %d...", portid);
		rc = rte_eth_dev_stop(portid);
		if (rc != 0)
			dao_info("rte_eth_dev_stop: err=%d, port=%d\n", rc, portid);
		dao_info(" Done");
	}
	/* clean up the EAL */
	rte_eal_cleanup();
	free(gbl_cfg);

	return 0;
}
