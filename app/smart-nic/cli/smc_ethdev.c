/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_socket.h>
#include <rte_bitops.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>

#include <dao_util.h>

#include <smc_cli_api.h>
#include <smc_init.h>

#include "smc_ethdev_priv.h"

static const char cmd_ethdev_mtu_help[] = "ethdev <ethdev_name> mtu <mtu_sz>";

static const char cmd_ethdev_prom_mode_help[] = "ethdev <ethdev_name> promiscuous <on/off>";

static const char cmd_ethdev_help[] =
	"ethdev <ethdev_name> rxq <n_queues> txq <n_queues> <mempool_name>";

static const char cmd_ethdev_stats_help[] = "ethdev <ethdev_name> stats";

static const char cmd_ethdev_show_help[] = "ethdev <ethdev_name> show";

static struct rte_eth_conf port_conf_default = {
	.link_speeds = 0,
	.rxmode = {
		.mq_mode = RTE_ETH_MQ_RX_NONE,
		.mtu = 9000 - (RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN), /* Jumbo frame MTU */
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_key_len = 40,
			.rss_hf = 0,
		},
	},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
	.lpbk_mode = 0,
};

uint32_t enabled_port_mask;
static struct ethdev_head eth_node = TAILQ_HEAD_INITIALIZER(eth_node);

uint32_t
ethdev_port_mask(void)
{
	return enabled_port_mask;
}

static void
ethdev_check_port_link_status(uint16_t portid)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 30  /* 9s (90 * 100ms) in total */
	char link_rc_text[RTE_ETH_LINK_MAX_STR_LEN];
	uint8_t count, port_up, print_flag = 0;
	struct smc_main_cfg_data *cfg_data;
	struct rte_eth_link link;
	int rc;

	printf("\nChecking link status...");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		cfg_data = smc_main_cfg_handle();
		if (cfg_data && cfg_data->force_quit)
			return;

		if ((enabled_port_mask & (1 << portid)) == 0)
			continue;

		port_up = 1;
		memset(&link, 0, sizeof(link));
		rc = rte_eth_link_get_nowait(portid, &link);
		if (rc < 0) {
			port_up = 0;
			if (print_flag == 1)
				printf("Port %u link get failed: %s\n", portid, rte_strerror(-rc));
			continue;
		}

		/* Print link rc if flag set */
		if (print_flag == 1) {
			rte_eth_link_to_str(link_rc_text, sizeof(link_rc_text), &link);
			printf("Port %d %s\n", portid, link_rc_text);
			break;
		}

		/* Clear all_ports_up flag if any link down */
		if (link.link_status == RTE_ETH_LINK_DOWN)
			port_up = 0;

		if (port_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* Set the print_flag if all ports up or timeout */
		if (port_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("Done\n");
		}
	}
}

static struct ethdev *
ethdev_port_by_id(uint16_t port_id)
{
	struct ethdev *port;

	TAILQ_FOREACH(port, &eth_node, next) {
		if (port->config.port_id == port_id)
			return port;
	}
	return NULL;
}

void *
ethdev_mempool_list_by_portid(uint16_t portid)
{
	struct ethdev *port;

	if (portid >= RTE_MAX_ETHPORTS)
		return NULL;

	port = ethdev_port_by_id(portid);
	if (port)
		return &(port->config.rx.mp);
	else
		return NULL;
}

int16_t
ethdev_portid_by_ip4(uint32_t ip, uint32_t mask)
{
	int portid = -EINVAL;
	struct ethdev *port;

	TAILQ_FOREACH(port, &eth_node, next) {
		if (mask == 0) {
			if ((port->ip4_addr.ip & port->ip4_addr.mask) == (ip & port->ip4_addr.mask))
				return port->config.port_id;
		} else {
			if ((port->ip4_addr.ip & port->ip4_addr.mask) == (ip & mask))
				return port->config.port_id;
		}
	}

	return portid;
}

int16_t
ethdev_portid_by_ip6(uint8_t *ip, uint8_t *mask)
{
	int portid = -EINVAL;
	struct ethdev *port;
	int j;

	TAILQ_FOREACH(port, &eth_node, next) {
		for (j = 0; j < ETHDEV_IPV6_ADDR_LEN; j++) {
			if (mask == NULL) {
				if ((port->ip6_addr.ip[j] & port->ip6_addr.mask[j]) !=
				    (ip[j] & port->ip6_addr.mask[j]))
					break;

			} else {
				if ((port->ip6_addr.ip[j] & port->ip6_addr.mask[j]) !=
				    (ip[j] & mask[j]))
					break;
			}
		}
		if (j == ETHDEV_IPV6_ADDR_LEN)
			return port->config.port_id;
	}

	return portid;
}

void
ethdev_list_clean(void)
{
	struct ethdev *port;
	void *tmp;

	DAO_TAILQ_FOREACH_SAFE(port, &eth_node, next, tmp)
		TAILQ_REMOVE(&eth_node, port, next);
}

int
smc_ethdev_stop(uint16_t portid)
{
	int rc = 0;

	if ((enabled_port_mask & (1 << portid)) == 0)
		DAO_ERR_GOTO(rc, fail, "Port %d is not enabled", portid);

	dao_info("Stopping port %d...", portid);
	rc = rte_eth_dev_stop(portid);
	if (rc != 0)
		DAO_ERR_GOTO(rc, fail, "Failed to stop port %u: %s", portid, rte_strerror(-rc));
fail:
	return rc;
}

void
ethdev_stop_all(void)
{
	uint16_t portid;
	int rc;

	RTE_ETH_FOREACH_DEV(portid) {
		if ((enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		rc = rte_eth_dev_stop(portid);
		if (rc != 0)
			printf("Failed to stop port %u: %s\n",
			       portid, rte_strerror(-rc));
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}

	ethdev_list_clean();
	printf("Bye...\n");
}

int
smc_ethdev_start(uint16_t portid)
{
	int rc = 0;

	if ((enabled_port_mask & (1 << portid)) == 0)
		DAO_ERR_GOTO(rc, fail, "Port %d is not enabled", portid);

	dao_info("Starting port %d...", portid);
	rc = rte_eth_dev_start(portid);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to start port %d", portid);
	ethdev_check_port_link_status(portid);
fail:
	return rc;
}

void
ethdev_start(void)
{
	uint16_t portid;
	int rc;

	RTE_ETH_FOREACH_DEV(portid)
	{
		if ((enabled_port_mask & (1 << portid)) == 0)
			continue;

		rc = rte_eth_dev_start(portid);
		if (rc < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n", rc, portid);
	}
}

static int
ethdev_show(const char *name)
{
	uint16_t mtu = 0, port_id = 0;
	struct rte_eth_dev_info info;
	struct rte_eth_stats stats;
	struct rte_ether_addr addr;
	struct rte_eth_link link;
	struct conn *conn = NULL;
	uint32_t length;
	int rc;

	CONN_CONF_HANDLE(conn, -EINVAL);

	rc = rte_eth_dev_get_port_by_name(name, &port_id);
	if (rc < 0)
		return rc;

	rte_eth_dev_info_get(port_id, &info);
	rte_eth_stats_get(port_id, &stats);
	rte_eth_macaddr_get(port_id, &addr);
	rte_eth_link_get(port_id, &link);
	rte_eth_dev_get_mtu(port_id, &mtu);

	length = strlen(conn->msg_out);
	conn->msg_out += length;
	snprintf(conn->msg_out, conn->msg_out_len_max,
		 "%s: flags=<%s> mtu %u\n"
		 "\tether " RTE_ETHER_ADDR_PRT_FMT " rxqueues %u txqueues %u\n"
		 "\tport# %u  speed %s\n"
		 "\tRX packets %" PRIu64 "  bytes %" PRIu64 "\n"
		 "\tRX errors %" PRIu64 "  missed %" PRIu64 "  no-mbuf %" PRIu64 "\n"
		 "\tTX packets %" PRIu64 "  bytes %" PRIu64 "\n"
		 "\tTX errors %" PRIu64 "\n\n",
		 name, link.link_status ? "UP" : "DOWN", mtu, RTE_ETHER_ADDR_BYTES(&addr),
		 info.nb_rx_queues, info.nb_tx_queues, port_id,
		 rte_eth_link_speed_to_str(link.link_speed), stats.ipackets, stats.ibytes,
		 stats.ierrors, stats.imissed, stats.rx_nombuf, stats.opackets, stats.obytes,
		 stats.oerrors);

	length = strlen(conn->msg_out);
	conn->msg_out_len_max -= length;
	return 0;
}

static int
ethdev_prom_mode_config(const char *name, bool enable)
{
	struct ethdev *eth_hdl;
	uint16_t portid = 0;
	int rc;

	rc = rte_eth_dev_get_port_by_name(name, &portid);
	if (rc < 0)
		return rc;

	eth_hdl = ethdev_port_by_id(portid);

	if (eth_hdl) {
		if (enable)
			rc = rte_eth_promiscuous_enable(portid);
		else
			rc = rte_eth_promiscuous_disable(portid);
		if (rc < 0)
			return rc;

		eth_hdl->config.promiscuous = enable;
		return 0;
	}

	rc = -EINVAL;
	return rc;
}

static int
ethdev_mtu_config(const char *name, uint32_t mtu)
{
	struct ethdev *eth_hdl;
	uint16_t portid = 0;
	int rc;

	rc = rte_eth_dev_get_port_by_name(name, &portid);
	if (rc < 0)
		return rc;

	eth_hdl = ethdev_port_by_id(portid);

	if (eth_hdl) {
		rc = rte_eth_dev_set_mtu(portid, mtu);
		if (rc < 0)
			return rc;

		eth_hdl->config.mtu = mtu;
		return 0;
	}

	rc = -EINVAL;
	return rc;
}

static int
ethdev_process(const char *name, struct ethdev_config *params)
{
	struct rte_eth_dev_info port_info;
	struct rte_eth_conf port_conf;
	struct ethdev_rss_config *rss;
	struct rte_mempool *mempool;
	struct ethdev *ethdev_port;
	struct rte_ether_addr smac;
	uint16_t port_id = 0;
	int numa_node, rc;
	uint32_t i;

	/* Check input params */
	if (!name || !name[0] || (strlen(name) > RTE_ETH_NAME_MAX_LEN) || !params ||
	    !params->rx.n_queues || !params->rx.queue_size || !params->tx.n_queues ||
	    !params->tx.queue_size)
		return -EINVAL;

	rc = rte_eth_dev_get_port_by_name(name, &port_id);
	if (rc)
		return -EINVAL;

	if (!ethdev_port_by_id(port_id)) {
		ethdev_port = malloc(sizeof(struct ethdev));
		if (!ethdev_port)
			return -EINVAL;
	} else {
		return 0;
	}

	rc = rte_eth_dev_info_get(port_id, &port_info);
	if (rc) {
		rc = -EINVAL;
		goto exit;
	}

	mempool = rte_mempool_lookup(params->rx.mempool_name);
	if (!mempool) {
		rc = -EINVAL;
		goto exit;
	}

	params->rx.mp = mempool;

	rss = params->rx.rss;
	if (rss) {
		if (!port_info.reta_size || port_info.reta_size > RTE_ETH_RSS_RETA_SIZE_512) {
			rc = -EINVAL;
			goto exit;
		}

		if (!rss->n_queues || rss->n_queues >= ETHDEV_RXQ_RSS_MAX) {
			rc = -EINVAL;
			goto exit;
		}

		for (i = 0; i < rss->n_queues; i++)
			if (rss->queue_id[i] >= port_info.max_rx_queues) {
				rc = -EINVAL;
				goto exit;
			}
	}

	/* Port */
	memcpy(&port_conf, &port_conf_default, sizeof(struct rte_eth_conf));
	if (rss) {
		uint64_t rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP;

		port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
		port_conf.rx_adv_conf.rss_conf.rss_hf = rss_hf & port_info.flow_type_rss_offloads;
	}

	numa_node = rte_eth_dev_socket_id(port_id);
	if (numa_node == SOCKET_ID_ANY)
		numa_node = 0;

	if (params->mtu)
		port_conf.rxmode.mtu = params->mtu;

	rc = rte_eth_dev_configure(port_id, params->rx.n_queues, params->tx.n_queues, &port_conf);
	if (rc < 0) {
		rc = -EINVAL;
		goto exit;
	}

	rc = rte_eth_macaddr_get(port_id, &smac);
	if (rc < 0) {
		rc = -EINVAL;
		goto exit;
	}

	printf("Port_id = %d srcmac = %x:%x:%x:%x:%x:%x\n", port_id, smac.addr_bytes[0],
	       smac.addr_bytes[1], smac.addr_bytes[2], smac.addr_bytes[3], smac.addr_bytes[4],
	       smac.addr_bytes[5]);

	/* Port RX */
	for (i = 0; i < params->rx.n_queues; i++) {
		rc = rte_eth_rx_queue_setup(port_id, i, params->rx.queue_size, numa_node, NULL,
					    mempool);
		if (rc < 0) {
			rc = -EINVAL;
			goto exit;
		}
	}

	/* Port TX */
	for (i = 0; i < params->tx.n_queues; i++) {
		rc = rte_eth_tx_queue_setup(port_id, i, params->tx.queue_size, numa_node, NULL);
		if (rc < 0) {
			rc = -EINVAL;
			goto exit;
		}
	}

	memcpy(&ethdev_port->config, params, sizeof(struct ethdev_config));
	memcpy(ethdev_port->config.dev_name, name, strlen(name));
	ethdev_port->config.port_id = port_id;
	enabled_port_mask |= RTE_BIT32(port_id);

	TAILQ_INSERT_TAIL(&eth_node, ethdev_port, next);
	return 0;
exit:
	free(ethdev_port);
	return rc;
}

static int
ethdev_stats_show(const char *name)
{
	uint64_t diff_pkts_rx, diff_pkts_tx, diff_bytes_rx, diff_bytes_tx;
	static uint64_t prev_pkts_rx[RTE_MAX_ETHPORTS];
	static uint64_t prev_pkts_tx[RTE_MAX_ETHPORTS];
	static uint64_t prev_bytes_rx[RTE_MAX_ETHPORTS];
	static uint64_t prev_bytes_tx[RTE_MAX_ETHPORTS];
	static uint64_t prev_cycles[RTE_MAX_ETHPORTS];
	uint64_t mpps_rx, mpps_tx, mbps_rx, mbps_tx;
	uint64_t diff_ns, diff_cycles, curr_cycles;
	struct rte_eth_stats stats;
	static const char *nic_stats_border = "########################";
	uint16_t port_id, len;
	struct conn *conn = NULL;
	int rc;

	CONN_CONF_HANDLE(conn, -EINVAL);

	rc = rte_eth_dev_get_port_by_name(name, &port_id);
	if (rc < 0)
		return rc;

	rc = rte_eth_stats_get(port_id, &stats);
	if (rc != 0) {
		fprintf(stderr, "%s: Error: failed to get stats (port %u): %d", __func__, port_id,
			rc);
		return rc;
	}

	len = strlen(conn->msg_out);
	conn->msg_out += len;
	snprintf(conn->msg_out, conn->msg_out_len_max,
		 "\n  %s NIC statistics for port %-2d %s\n"
		 "  RX-packets: %-10" PRIu64 " RX-missed: %-10" PRIu64 " RX-bytes:  "
		 "%-" PRIu64 "\n"
		 "  RX-errors: %-" PRIu64 "\n"
		 "  RX-nombuf:  %-10" PRIu64 "\n"
		 "  TX-packets: %-10" PRIu64 " TX-errors: %-10" PRIu64 " TX-bytes:  "
		 "%-" PRIu64 "\n",
		 nic_stats_border, port_id, nic_stats_border, stats.ipackets, stats.imissed,
		 stats.ibytes, stats.ierrors, stats.rx_nombuf, stats.opackets, stats.oerrors,
		 stats.obytes);

	len = strlen(conn->msg_out) - len;
	conn->msg_out_len_max -= len;

	diff_ns = 0;
	diff_cycles = 0;

	curr_cycles = rte_rdtsc();
	if (prev_cycles[port_id] != 0)
		diff_cycles = curr_cycles - prev_cycles[port_id];

	prev_cycles[port_id] = curr_cycles;
	diff_ns = diff_cycles > 0 ? diff_cycles * (1 / (double)rte_get_tsc_hz()) * NS_PER_SEC : 0;

	diff_pkts_rx = (stats.ipackets > prev_pkts_rx[port_id]) ?
			       (stats.ipackets - prev_pkts_rx[port_id]) :
			       0;
	diff_pkts_tx = (stats.opackets > prev_pkts_tx[port_id]) ?
			       (stats.opackets - prev_pkts_tx[port_id]) :
			       0;
	prev_pkts_rx[port_id] = stats.ipackets;
	prev_pkts_tx[port_id] = stats.opackets;
	mpps_rx = diff_ns > 0 ? (double)diff_pkts_rx / diff_ns * NS_PER_SEC : 0;
	mpps_tx = diff_ns > 0 ? (double)diff_pkts_tx / diff_ns * NS_PER_SEC : 0;

	diff_bytes_rx = (stats.ibytes > prev_bytes_rx[port_id]) ?
				(stats.ibytes - prev_bytes_rx[port_id]) :
				0;
	diff_bytes_tx = (stats.obytes > prev_bytes_tx[port_id]) ?
				(stats.obytes - prev_bytes_tx[port_id]) :
				0;
	prev_bytes_rx[port_id] = stats.ibytes;
	prev_bytes_tx[port_id] = stats.obytes;
	mbps_rx = diff_ns > 0 ? (double)diff_bytes_rx / diff_ns * NS_PER_SEC : 0;
	mbps_tx = diff_ns > 0 ? (double)diff_bytes_tx / diff_ns * NS_PER_SEC : 0;

	len = strlen(conn->msg_out);
	snprintf(conn->msg_out + len, conn->msg_out_len_max,
		 "\n  Throughput (since last show)\n"
		 "  Rx-pps: %12" PRIu64 "          Rx-bps: %12" PRIu64 "\n  Tx-pps: %12" PRIu64
		 "          Tx-bps: %12" PRIu64 "\n"
		 "  %s############################%s\n",
		 mpps_rx, mbps_rx * 8, mpps_tx, mbps_tx * 8, nic_stats_border, nic_stats_border);
	return 0;
}

void
cmd_ethdev_dev_mtu_parsed(void *parsed_result, __rte_unused struct cmdline *cl,
			  void *data __rte_unused)
{
	struct cmd_ethdev_dev_mtu_result *res = parsed_result;
	int rc = -EINVAL;

	rc = ethdev_mtu_config(res->dev, res->size);
	if (rc < 0)
		printf(MSG_CMD_FAIL, res->ethdev);
}

void
cmd_ethdev_dev_promiscuous_parsed(void *parsed_result, __rte_unused struct cmdline *cl,
				  void *data __rte_unused)
{
	struct cmd_ethdev_dev_promiscuous_result *res = parsed_result;
	bool enable = false;
	int rc = -EINVAL;

	if (!strcmp(res->enable, "on"))
		enable = true;

	rc = ethdev_prom_mode_config(res->dev, enable);
	if (rc < 0)
		printf(MSG_CMD_FAIL, res->ethdev);
}

void
cmd_ethdev_dev_show_parsed(void *parsed_result, __rte_unused struct cmdline *cl,
			   void *data __rte_unused)
{
	struct cmd_ethdev_dev_show_result *res = parsed_result;
	int rc = -EINVAL;

	rc = ethdev_show(res->dev);
	if (rc < 0)
		printf(MSG_ARG_INVALID, res->dev);
}

void
cmd_ethdev_dev_stats_parsed(void *parsed_result, __rte_unused struct cmdline *cl,
			    void *data __rte_unused)
{
	struct cmd_ethdev_dev_stats_result *res = parsed_result;
	int rc = -EINVAL;

	rc = ethdev_stats_show(res->dev);
	if (rc < 0)
		printf(MSG_ARG_INVALID, res->dev);
}

void
cmd_ethdev_parsed(void *parsed_result, __rte_unused struct cmdline *cl, void *data __rte_unused)
{
	struct cmd_ethdev_result *res = parsed_result;
	struct ethdev_config config;
	int rc;
	size_t len;

	memset(&config, 0, sizeof(struct ethdev_config));
	config.rx.n_queues = res->nb_rxq;
	config.rx.queue_size = ETHDEV_RX_DESC_DEFAULT;

	len = strlen(res->mempool);
	if (len > RTE_MEMPOOL_NAMESIZE)
		rte_exit(EXIT_FAILURE, "Invalid mempool size");
	memcpy(config.rx.mempool_name, res->mempool, len);

	config.tx.n_queues = res->nb_txq;
	config.tx.queue_size = ETHDEV_TX_DESC_DEFAULT;

	config.mtu = port_conf_default.rxmode.mtu;

	rc = ethdev_process(res->dev, &config);
	if (rc < 0)
		printf(MSG_CMD_FAIL, res->ethdev);
}

static int
print_ethdev_help(void)
{
	struct conn *conn = NULL;
	size_t len;

	CONN_CONF_HANDLE(conn, -EINVAL);

	len = strlen(conn->msg_out);
	conn->msg_out += len;
	snprintf(conn->msg_out, conn->msg_out_len_max, "\n%s\n%s\n%s\n%s\n%s\n%s\n",
		 "----------------------------- ethdev command help -----------------------------",
		 cmd_ethdev_help, cmd_ethdev_prom_mode_help, cmd_ethdev_mtu_help,
		 cmd_ethdev_stats_help, cmd_ethdev_show_help);

	len = strlen(conn->msg_out);
	conn->msg_out_len_max -= len;

	return 0;
}

void
cmd_help_ethdev_parsed(__rte_unused void *parsed_result, __rte_unused struct cmdline *cl,
		       __rte_unused void *data)
{
	print_ethdev_help();
}
