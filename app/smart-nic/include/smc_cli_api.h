/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef APP_GRAPH_MODULE_API_H
#define APP_GRAPH_MODULE_API_H

#include <stdbool.h>
#include <stdint.h>

#include "cli/smc_cli.h"
#include "cli/smc_conn.h"
#include "cli/smc_ethdev.h"
#include "cli/smc_graph_cli.h"
#include "cli/smc_lcore.h"
#include "cli/smc_mempool.h"
#include "cli/smc_pipeline.h"

#include "smc_commands.h"

/*
 * Externs
 */
extern volatile bool force_quit;
extern struct conn *conn;

bool app_graph_stats_enabled(void);
bool app_graph_exit(void);

#endif
