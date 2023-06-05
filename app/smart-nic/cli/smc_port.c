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
#include <rte_common.h>
#include <rte_mbuf.h>

#include <dao_util.h>

#include <smc_cli_api.h>
#include <smc_init.h>

#include "smc_port_priv.h"

static struct prt_lst plst = TAILQ_HEAD_INITIALIZER(plst);

int
port_state_update(uint16_t portid, enum port_state state)
{
	struct port_info *port;

	TAILQ_FOREACH(port, &plst, next) {
		if (port->portid == portid) {
			port->state = state;
			return 0;
		}
	}
	return -1;
}

int
port_insert(uint16_t portid)
{
	struct port_info *port;

	port = calloc(1, sizeof(struct port_info));
	if (!port)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory");

	port->portid = portid;
	port->state = SMC_PORT_ADDED;
	TAILQ_INSERT_TAIL(&plst, port, next);
	return 0;
fail:
	return errno;
}

int
port_delete(uint16_t portid)
{
	struct port_info *port;
	void *tmp;

	DAO_TAILQ_FOREACH_SAFE(port, &plst, next, tmp)
	{
		if (port->portid == portid) {
			TAILQ_REMOVE(&plst, port, next);
			free(port);
			return 0;
		}
	}
	return -1;
}

struct port_info *
port_entry_lookup(uint16_t portid)
{
	struct port_info *port;

	TAILQ_FOREACH(port, &plst, next) {
		if (port->portid == portid)
			return port;
	}
	return NULL;
}
