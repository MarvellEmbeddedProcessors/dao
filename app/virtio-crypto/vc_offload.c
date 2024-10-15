/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_log.h>

#include <dao_virtio.h>

#include "vc_offload.h"
#include "vc_parser.h"

/* Mask of enabled virtio devs */
uint64_t virtio_mask_ena[2];
uint16_t nb_virtiodevs;
uint64_t lcore_virtio_mask[DAO_VIRTIO_DEV_MAX];

/* Mask of enabled crypto devs */
uint64_t crypto_mask_ena;
uint16_t nb_cryptodevs;
uint64_t lcore_crypto_mask[RTE_CRYPTO_MAX_DEVS];

static volatile bool force_quit;

static void
signal_handler(int signum)
{
	APP_INFO("\n");
	if (signum == SIGINT || signum == SIGTERM) {
		APP_INFO("Signal %d received, preparing to exit...\n", signum);
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

	rc = parse_args(argc, argv);
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "Invalid VC offload parameters\n");

	rte_eal_cleanup();

	return rc;
}
