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
#include <rte_ethdev.h>
#include <rte_node_ip4_api.h>

#include <smc_cli_api.h>
#include <smc_init.h>
#include <smc_node_ctrl.h>

#include "smc_pipeline_priv.h"
#include "smc_port_priv.h"

static const char cmd_pipeline_port_add_help[] = "pipeline port add <port_name>";
static const char cmd_pipeline_port_del_help[] = "pipeline port del <port_name>";
static const char cmd_pipeline_port_link_help[] = "pipeline port link <src_port> <dst_port>";
static const char cmd_pipeline_port_unlink_help[] = "pipeline port unlink <src_port> <dst_port>";

static struct prt_fw pfw = TAILQ_HEAD_INITIALIZER(pfw);

uint16_t
smc_pipeline_tx_link_for_rx_port(uint16_t portid_rx)
{
	struct port_forwarding *port_fwd;

	TAILQ_FOREACH(port_fwd, &pfw, next) {
		if (port_fwd->rx_port == portid_rx)
			return port_fwd->tx_port;
	}
	return UINT16_MAX;
}

static struct port_forwarding *
find_l2_entry(uint16_t portid_tx, uint16_t portid_rx)
{
	struct port_forwarding *port_fwd;

	TAILQ_FOREACH(port_fwd, &pfw, next) {
		if ((port_fwd->tx_port == portid_tx) && (port_fwd->rx_port == portid_rx))
			return port_fwd;
	}
	return NULL;
}

static int
ethdev_pfw_config(uint16_t portid_rx, uint16_t portid_tx)
{
	struct port_forwarding *pfwd;
	int rc;

	/* Check if ports already linked */
	pfwd = find_l2_entry(portid_tx, portid_rx);
	if (!pfwd) {
		pfwd = malloc(sizeof(struct port_forwarding));
		if (!pfwd) {
			dao_err("Fail to allocate port forwarding memory");
			return -ENOMEM;
		}
		pfwd->tx_port = portid_tx;
		pfwd->rx_port = portid_rx;
		TAILQ_INSERT_TAIL(&pfw, pfwd, next);
	}

	/* Update forwarding edge between rx and tx port nodes */
	rc = smc_node_link_unlink_ports(portid_rx, portid_tx, true);
	return rc;
}

static int
pipeline_port_link(struct cmd_pipeline_port_link_result *res)
{
	char name[RTE_ETH_NAME_MAX_LEN];
	char *tx_name = res->dst_port;
	char *rx_name = res->src_port;
	uint16_t portid_rx, portid_tx;
	struct port_info *port;
	int rc = -EINVAL;

	/* Get the RX port info */
	rc = rte_eth_dev_get_port_by_name(rx_name, &portid_rx);
	if (rc < 0)
		DAO_ERR_GOTO(rc, fail, "Failed to get port by name for %s", rx_name);

	port = port_entry_lookup(portid_rx);
	if (!port)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to find port %s info", rx_name);

	if (port->state == SMC_PORT_LINKED) {
		memset(name, 0, RTE_ETH_NAME_MAX_LEN);
		portid_tx = smc_pipeline_tx_link_for_rx_port(portid_rx);
		rte_eth_dev_get_name_by_port(portid_tx, name);
		dao_info("Port %s already lined to %s", rx_name, name);
		return 0;
	}

	if (port->state != SMC_PORT_ADDED)
		DAO_ERR_GOTO(-EINVAL, fail, "Port %s is not added", rx_name);

	/* Get the TX port info */
	rc = rte_eth_dev_get_port_by_name(tx_name, &portid_tx);
	if (rc < 0)
		DAO_ERR_GOTO(rc, fail, "Failed to get port by name for %s", tx_name);

	port = port_entry_lookup(portid_tx);
	if (!port)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to find port %s info", tx_name);

	if (port->state == SMC_PORT_LINKED) {
		memset(name, 0, RTE_ETH_NAME_MAX_LEN);
		portid_rx = smc_pipeline_tx_link_for_rx_port(portid_tx);
		rte_eth_dev_get_name_by_port(portid_rx, name);
		dao_info("Port %s already lined to %s", tx_name, name);
		return 0;
	}

	if (port->state != SMC_PORT_ADDED)
		DAO_ERR_GOTO(-EINVAL, fail, "Port %s is not added", tx_name);

	rc = ethdev_pfw_config(portid_rx, portid_tx);
	if (rc < 0)
		DAO_ERR_GOTO(rc, fail, "Failed to link ports %s <--> %s",
			     rx_name, tx_name);

	/* Add the port forwarding */
	rc = ethdev_pfw_config(portid_tx, portid_rx);
	if (rc < 0)
		DAO_ERR_GOTO(rc, fail, "Failed to link ports %s <--> %s",
			     tx_name, rx_name);

	/* Update port state to LINKED */
	rc = port_state_update(portid_rx, SMC_PORT_LINKED);
	if (rc < 0)
		DAO_ERR_GOTO(rc, fail, "Failed to update the state for port %s",
			     rx_name);
	rc = port_state_update(portid_tx, SMC_PORT_LINKED);
	if (rc < 0)
		DAO_ERR_GOTO(rc, fail, "Failed to update the state for port %s",
			     tx_name);
	dao_info("Ports %s <--> %s linked successfully", res->src_port, res->dst_port);
	return 0;
fail:
	return rc;
}

void
cmd_pipeline_port_link_parsed(void *parsed_result, __rte_unused struct cmdline *cl,
			      void *data __rte_unused)
{
	pipeline_port_link(parsed_result);
}

static int
ethdev_pfw_remove(char *tx_name, char *rx_name)
{
	struct port_forwarding *pfwd;
	uint16_t portid_rx = 0;
	uint16_t portid_tx = 0;
	int rc;

	rc = rte_eth_dev_get_port_by_name(tx_name, &portid_tx);
	if (rc < 0)
		return rc;

	rc = rte_eth_dev_get_port_by_name(rx_name, &portid_rx);
	if (rc < 0)
		return rc;

	pfwd = find_l2_entry(portid_tx, portid_rx);
	if (pfwd) {
		/* Update forwarding edge between rx and tx port nodes */
		rc = smc_node_link_unlink_ports(portid_rx, portid_tx, false);
		if (rc)
			DAO_ERR_GOTO(-EINVAL, fail, "Failed to unlink ports %s and %s", rx_name,
				     tx_name);
		TAILQ_REMOVE(&pfw, pfwd, next);
		memset(pfwd, 0, sizeof(struct port_forwarding));
		free(pfwd);
	} else {
		DAO_ERR_GOTO(-EINVAL, fail, "Port %s and %s are not linked", rx_name, tx_name);
	}
fail:
	return rc;
}

static int
pipeline_port_unlink(struct cmd_pipeline_port_link_result *res)
{
	char *tx_name = res->dst_port;
	char *rx_name = res->src_port;
	struct port_info *port;
	uint16_t portid_rx = 0;
	uint16_t portid_tx = 0;
	int rc = -EINVAL;

	rc = rte_eth_dev_get_port_by_name(rx_name, &portid_rx);
	if (rc < 0)
		return rc;

	port = port_entry_lookup(portid_rx);
	if (!port)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to find RX port %s info", rx_name);

	if (port->state != SMC_PORT_LINKED)
		DAO_ERR_GOTO(-EINVAL, fail, "RX port %s not in linked state", rx_name);

	rc = rte_eth_dev_get_port_by_name(tx_name, &portid_tx);
	if (rc < 0)
		return rc;

	port = port_entry_lookup(portid_tx);
	if (!port)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to find TX port %s info", tx_name);

	if (port->state != SMC_PORT_LINKED)
		DAO_ERR_GOTO(-EINVAL, fail, "TX port %s not in linked state", tx_name);

	rc = ethdev_pfw_remove(res->dst_port, res->src_port);
	if (rc < 0)
		printf(MSG_CMD_FAIL, res->src_port);

	rc = ethdev_pfw_remove(res->src_port, res->dst_port);
	if (rc < 0)
		printf(MSG_CMD_FAIL, res->dst_port);

	/* Update port state to just ADDED */
	rc = port_state_update(portid_rx, SMC_PORT_ADDED);
	if (rc < 0)
		DAO_ERR_GOTO(rc, fail, "Failed to update the state for port %s",
			     rx_name);
	rc = port_state_update(portid_tx, SMC_PORT_ADDED);
	if (rc < 0)
		DAO_ERR_GOTO(rc, fail, "Failed to update the state for port %s",
			     tx_name);
	dao_info("Ports %s <--> %s unlinked successfully", res->src_port, res->dst_port);
	return 0;
fail:
	return rc;
}

void
cmd_pipeline_port_unlink_parsed(void *parsed_result, __rte_unused struct cmdline *cl,
				void *data __rte_unused)
{
	pipeline_port_unlink(parsed_result);
}

static int
pipeline_port_del(const char *port)
{
	char name[RTE_ETH_NAME_MAX_LEN];
	struct port_info *port_info;
	uint16_t portid, portid_tx;
	int rc = -EINVAL;

	rc = rte_eth_dev_get_port_by_name(port, &portid);
	if (rc < 0)
		DAO_ERR_GOTO(rc, fail, "Failed to get port id for %s", port);

	port_info = port_entry_lookup(portid);
	if (!port_info)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to find port %s info", port);

	/* Already linked port should not be deleted */
	if (port_info->state != SMC_PORT_ADDED) {
		memset(name, 0, RTE_ETH_NAME_MAX_LEN);
		portid_tx = smc_pipeline_tx_link_for_rx_port(portid);
		rte_eth_dev_get_name_by_port(portid_tx, name);
		dao_info("Port %s cannot be deleted, its linked to %s", port, name);
		return 0;
	}

	/* Update rx port queue map */
	rc = smc_node_add_del_port(portid, false);
	if (rc < 0)
		DAO_ERR_GOTO(rc, fail, "Failed to add port %s", port);

	rc = smc_ethdev_stop(portid);
	if (rc < 0)
		DAO_ERR_GOTO(rc, fail, "Failed to start port %s ethdev", port);

	rc = port_delete(portid);
	if (rc < 0)
		DAO_ERR_GOTO(rc, fail, "Failed to delete port %s", port);

fail:
	return rc;
}

void
cmd_pipeline_port_del_parsed(void *parsed_result, __rte_unused struct cmdline *cl,
			     void *data __rte_unused)
{
	struct cmd_pipeline_port_del_result *res = parsed_result;

	pipeline_port_del(res->port_name);
}

static int
pipeline_port_add(const char *port)
{
	int rc = -EINVAL;
	uint16_t portid;

	rc = rte_eth_dev_get_port_by_name(port, &portid);
	if (rc < 0)
		DAO_ERR_GOTO(rc, fail, "Failed to get port id for %s", port);

	/* IF port already added, return */
	if (port_entry_lookup(portid))
		return 0;

	rc = smc_ethdev_start(portid);
	if (rc < 0)
		DAO_ERR_GOTO(rc, fail, "Failed to start port %s ethdev", port);

	/* Update rx port queue map */
	rc = smc_node_add_del_port(portid, true);
	if (rc < 0)
		DAO_ERR_GOTO(rc, fail, "Failed to add port %s", port);

	rc = port_insert(portid);
	if (rc < 0)
		DAO_ERR_GOTO(rc, fail, "Failed to insert port %s", port);

fail:
	return rc;
}

void
cmd_pipeline_port_add_parsed(void *parsed_result, __rte_unused struct cmdline *cl,
			     void *data __rte_unused)
{
	struct cmd_pipeline_port_add_result *res = parsed_result;

	pipeline_port_add(res->port_name);
}

static int
print_pipeline_help(void)
{
	struct conn *conn = NULL;
	size_t len;

	CONN_CONF_HANDLE(conn, -EINVAL);

	len = strlen(conn->msg_out);
	conn->msg_out += len;
	snprintf(conn->msg_out, conn->msg_out_len_max, "\n%s\n%s\n%s\n%s\n%s\n",
		 "---------------------------- pipeline command help ----------------------------",
		 cmd_pipeline_port_add_help, cmd_pipeline_port_del_help,
		 cmd_pipeline_port_link_help, cmd_pipeline_port_unlink_help);

	len = strlen(conn->msg_out);
	conn->msg_out_len_max -= len;

	return 0;
}

void
cmd_help_pipeline_parsed(__rte_unused void *parsed_result, __rte_unused struct cmdline *cl,
			 __rte_unused void *data)
{
	print_pipeline_help();
}
