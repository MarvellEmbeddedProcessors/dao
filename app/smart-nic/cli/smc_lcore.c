/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <stdlib.h>
#include <string.h>

#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_socket.h>
#include <rte_ethdev.h>

#include <smc_cli_api.h>
#include <smc_init.h>

#include "smc_lcore_priv.h"

static const char cmd_lcore_help[] = "lcore map port <ethdev_name> queue <q_num> core <core_id>";

static struct lcore_params lcore_params_array[LCORE_MAP_PARAMS_MAX];
struct rte_node_ethdev_config ethdev_conf[RTE_MAX_ETHPORTS];
struct lcore_params *lcore_params = lcore_params_array;
uint16_t nb_lcore_params;

static int
rx_map_configure(uint8_t port_id, uint32_t queue, uint32_t core)
{
	struct lcore_conf *lcore_conf = NULL;
	uint8_t n_rx_queue;

	LCORE_CONF_HANDLE(lcore_conf, -EINVAL);

	n_rx_queue = lcore_conf[core].n_rx_queue;
	lcore_conf[core].rx_queue_list[n_rx_queue].port_id = port_id;
	lcore_conf[core].rx_queue_list[n_rx_queue].queue_id = queue;
	snprintf(lcore_conf[core].rx_queue_list[n_rx_queue].node_name, RTE_NODE_NAMESIZE,
		 "smc_eth_rx-%u", port_id);
	lcore_conf[core].n_rx_queue++;

	return 0;
}

uint8_t
lcore_num_rx_queues_get(uint16_t port)
{
	int queue = -1;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		if (lcore_params[i].port_id == port) {
			if (lcore_params[i].queue_id == queue + 1)
				queue = lcore_params[i].queue_id;
			else
				rte_exit(EXIT_FAILURE,
					 "Queue ids of the port %d must be"
					 " in sequence and must start with 0\n",
					 lcore_params[i].port_id);
		}
	}

	return (uint8_t)(++queue);
}

static int
lcore_map_add(char *name, uint32_t queue, uint32_t core)
{
	struct conn *conn = NULL;
	uint64_t coremask;
	uint16_t port_id;
	size_t len;
	int rc;

	CONN_CONF_HANDLE(conn, -EINVAL);

	if (nb_lcore_params >= LCORE_MAP_PARAMS_MAX)
		return -EINVAL;

	rc = rte_eth_dev_get_port_by_name(name, &port_id);
	if (rc)
		return -EINVAL;

	coremask = graph_coremask_get();

	if (!(coremask & (1 << core)))
		DAO_ERR_GOTO(-EINVAL, fail, "Core %d not part of user coremask 0x%lx", core,
			     coremask);

	if (!rte_lcore_is_enabled(core)) {
		len = strlen(conn->msg_out);
		conn->msg_out += len;
		snprintf(conn->msg_out, conn->msg_out_len_max, "\n%s %d %s\n", "lcore", core,
			 "is not enabled");

		len = strlen(conn->msg_out);
		conn->msg_out_len_max -= len;
		return -EINVAL;
	}

	rx_map_configure(port_id, queue, core);

	lcore_params_array[nb_lcore_params].port_id = port_id;
	lcore_params_array[nb_lcore_params].queue_id = queue;
	lcore_params_array[nb_lcore_params].lcore_id = core;
	nb_lcore_params++;

	return 0;
fail:
	return errno;
}

static int
print_lcore_help(void)
{
	struct conn *conn = NULL;
	size_t len;

	CONN_CONF_HANDLE(conn, -EINVAL);

	len = strlen(conn->msg_out);
	conn->msg_out += len;
	snprintf(conn->msg_out, conn->msg_out_len_max, "\n%s\n%s\n",
		 "---------------------------- lcore command help ----------------------------",
		 cmd_lcore_help);

	len = strlen(conn->msg_out);
	conn->msg_out_len_max -= len;

	return 0;
}

void
cmd_help_lcore_parsed(__rte_unused void *parsed_result, __rte_unused struct cmdline *cl,
		      __rte_unused void *data)
{
	print_lcore_help();
}

void
cmd_lcore_map_port_parsed(void *parsed_result, __rte_unused struct cmdline *cl,
			  void *data __rte_unused)
{
	struct cmd_lcore_map_port_result *res = parsed_result;
	int rc = -EINVAL;

	rc = lcore_map_add(res->dev, res->qid, res->core_id);
	if (rc < 0) {
		printf(MSG_CMD_FAIL, res->lcore);
		dao_err("Input core %d queue %d mapping failed, err %d", res->core_id, res->qid,
			rc);
	}
}
