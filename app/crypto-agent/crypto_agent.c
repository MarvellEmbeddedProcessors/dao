/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <signal.h>
#include <stdlib.h>

#include <rte_common.h>
#include <rte_eal.h>

#include "crypto_agent.h"

static volatile bool force_quit;

static void
signal_handler(int signum)
{
	CA_INFO("\n");
	if (signum == SIGINT || signum == SIGTERM) {
		CA_INFO("Signal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

int
main(int argc, char **argv)
{
	int rc;

	rc = rte_eal_init(argc, argv);
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");

	argc -= rc;
	argv += rc;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	rte_eal_cleanup();

	return 0;
}
