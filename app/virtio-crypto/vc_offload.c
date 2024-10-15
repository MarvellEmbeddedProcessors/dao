/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>

#include <rte_common.h>
#include <rte_cryptodev.h>
#include <rte_eal.h>
#include <rte_graph.h>
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

#define MAX_VIRTIO_RX_PER_LCORE         128
#define MAX_VIRTIO_CRYPTO_DEQ_PER_LCORE 1

struct lcore_crypto_deq {
	uint16_t devid;
	char node_name[RTE_NODE_NAMESIZE];

	struct vc_cryptodev_deq_node_ctx *cryptodev_deq;
	struct vc_virtio_tx_node_ctx *virtio_tx;
};

struct lcore_virtio_rx {
	uint16_t virtio_devid;
	char node_name[RTE_NODE_NAMESIZE];
	struct vc_virtio_rx_node_ctx *virtio_rx;
	struct vc_cryptodev_enq_node_ctx *cryptodev_enq;
};

/* Lcore conf */
struct lcore_conf {
	/* Fast path accessed */

	uint16_t nb_virtio_rx;
	struct lcore_virtio_rx virtio_rx[MAX_VIRTIO_RX_PER_LCORE];
	uint16_t nb_crypto_deq;
	struct lcore_crypto_deq crypto_deq[MAX_VIRTIO_CRYPTO_DEQ_PER_LCORE];

} __rte_cache_aligned;

static struct lcore_conf lcore_conf[RTE_MAX_LCORE];

static volatile bool force_quit;

static bool
is_virtio_dev_enabled(uint16_t virtio_devid)
{
	uint64_t i = virtio_devid / 64;
	uint64_t j = virtio_devid % 64;

	if (i > 1)
		return false;
	return virtio_mask_ena[i] & RTE_BIT64(j);
}

static bool
is_crypto_dev_enabled(uint16_t crypto_devid)
{
	uint64_t i = crypto_devid % 64;

	if (crypto_devid >= RTE_CRYPTO_MAX_DEVS)
		return false;

	return crypto_mask_ena & RTE_BIT64(i);
}

static void
signal_handler(int signum)
{
	APP_INFO("\n");
	if (signum == SIGINT || signum == SIGTERM) {
		APP_INFO("Signal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

static int
check_lcore_params(void)
{
	uint8_t lcore;
	uint16_t i;

	for (i = 0; i < DAO_VIRTIO_DEV_MAX; ++i) {
		if (!is_virtio_dev_enabled(i))
			continue;

		for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
			if (!(RTE_BIT64(lcore) & lcore_virtio_mask[i]))
				continue;

			if (!rte_lcore_is_enabled(lcore)) {
				APP_ERR("Error: lcore %hhu is not enabled in lcore mask\n", lcore);
				return -1;
			}

			if (lcore == rte_get_main_lcore()) {
				APP_ERR("Error: lcore %u is main lcore\n", lcore);
				return -1;
			}
		}
	}

	for (i = 0; i < RTE_CRYPTO_MAX_DEVS; ++i) {
		if (!is_crypto_dev_enabled(i))
			continue;

		for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
			if (!(RTE_BIT64(lcore) & lcore_crypto_mask[i]))
				continue;

			if (!rte_lcore_is_enabled(lcore)) {
				APP_ERR("Error: lcore %hhu is not enabled in lcore mask\n", lcore);
				return -1;
			}

			if (lcore == rte_get_main_lcore()) {
				APP_ERR("Error: lcore %u is main lcore\n", lcore);
				return -1;
			}
		}
	}

	return 0;
}

static int
init_lcore_virtio_rx(void)
{
	uint16_t nb_crypto_deq, cdev_id = 0;
	uint16_t virtio_devid, nb_virtio_rx;
	uint8_t lcore;

	for (virtio_devid = 0; virtio_devid < DAO_VIRTIO_DEV_MAX; ++virtio_devid) {
		if (!is_virtio_dev_enabled(virtio_devid))
			continue;

		for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
			if (!(RTE_BIT64(lcore) & lcore_virtio_mask[virtio_devid]))
				continue;

			nb_virtio_rx = lcore_conf[lcore].nb_virtio_rx;

			lcore_conf[lcore].virtio_rx[nb_virtio_rx].virtio_devid = virtio_devid;
			snprintf(lcore_conf[lcore].virtio_rx[nb_virtio_rx].node_name,
				 RTE_NODE_NAMESIZE, "vc_virtio_rx-%u", virtio_devid);
			lcore_conf[lcore].nb_virtio_rx++;

			/* If virtio-dev is enabled, then create crypto dequeue nodes as well. */

			nb_crypto_deq = lcore_conf[lcore].nb_crypto_deq;

			if (nb_crypto_deq == 0) {
				lcore_conf[lcore].crypto_deq[nb_crypto_deq].devid = cdev_id;
				snprintf(lcore_conf[lcore].crypto_deq[nb_crypto_deq].node_name,
					 RTE_NODE_NAMESIZE, "vc_cryptodev_deq-%u", cdev_id);
				lcore_conf[lcore].nb_crypto_deq = 1;
			}
		}
	}

	return 0;
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

	if (check_lcore_params() < 0)
		rte_exit(EXIT_FAILURE, "Invalid lcore params\n");

	if (init_lcore_virtio_rx() < 0)
		rte_exit(EXIT_FAILURE, "Failed to init lcore virtio rx\n");

	rte_eal_cleanup();

	return rc;
}
