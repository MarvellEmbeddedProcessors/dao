/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <signal.h>
#include <stdlib.h>

#include <rte_common.h>
#include <rte_cryptodev.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_memzone.h>

#include "ca_admin.h"
#include "ca_cpt_deq.h"
#include "ca_crypto_queue.h"
#include "ca_eth_rx.h"
#include "ca_ethdev.h"
#include "crypto_agent.h"

static volatile bool force_quit;

static struct ca_global_ctx ca_glb_ctx;

static struct lcore_conf lcore_conf[CA_MAX_LCORE];

static void
signal_handler(int signum)
{
	CA_INFO("\n");
	if (signum == SIGINT || signum == SIGTERM) {
		CA_INFO("Signal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

struct ca_eth_dev_ctx *
ca_eth_dev_ctx_get(uint16_t port_id)
{
	uint16_t i;

	for (i = 0; i < ca_glb_ctx.nb_valid_ethdevs; i++) {
		if (ca_glb_ctx.eth_ctx[i].port_id == port_id)
			return &ca_glb_ctx.eth_ctx[i];
	}

	return NULL;
}

static int
crypto_devs_validate(void)
{
	uint16_t cdev_count, dev_id, name_id, i, nb_valid_devs = 0;
	struct rte_cryptodev_info cryptodev_info;
	static const char *const cdev_names[] = {
		"crypto_cn9k",
		"crypto_cn10k",
	};

	for (name_id = 0; name_id < RTE_DIM(cdev_names); name_id++) {
		cdev_count = rte_cryptodev_devices_get(
			cdev_names[name_id], ca_glb_ctx.cryptodev_ids, RTE_CRYPTO_MAX_DEVS);
		if (cdev_count)
			break;

		CA_INFO("No crypto devices of type %s found", cdev_names[name_id]);
	}

	CA_INFO("Crypto devices found: %u", cdev_count);

	/* Validate found cryptodevs. */
	for (i = 0; i < cdev_count; i++) {
		dev_id = ca_glb_ctx.cryptodev_ids[i];

		if (!rte_cryptodev_is_valid_dev(dev_id))
			continue;

		/* Valid device found. */
		ca_glb_ctx.cryptodev_ids[nb_valid_devs] = dev_id;
		nb_valid_devs++;
	}

	if (nb_valid_devs == 0) {
		CA_ERR("No valid crypto devices found. Please enable at least one cryptodev.");
		return -ENODEV;
	}

	CA_INFO("Valid crypto devices found: %u\n", nb_valid_devs);
	for (i = 0; i < nb_valid_devs; i++)
		CA_INFO("Crypto dev %u", nb_valid_devs);

	if (nb_valid_devs > 1)
		CA_INFO("Only one crypto device supported. Using first device.");

	memset(&cryptodev_info, 0, sizeof(cryptodev_info));
	rte_cryptodev_info_get(ca_glb_ctx.cryptodev_ids[0], &cryptodev_info);

	CA_INFO("Lcore count: %d", rte_lcore_count());

	if (cryptodev_info.max_nb_queue_pairs < rte_lcore_count()) {
		CA_INFO("Crypto dev %u does not support %d queue pairs",
			ca_glb_ctx.cryptodev_ids[0], rte_lcore_count());
		return -ENODEV;
	}

	return 0;
}

static int
eth_devs_validate(void)
{
	uint16_t eth_dev_count, dev_id, nb_queue_avail, nb_valid_devs = 0;
	int ret;

	eth_dev_count = rte_eth_dev_count_avail();
	if (eth_dev_count == 0) {
		CA_ERR("No ethernet devices found");
		return -ENODEV;
	}

	/* Validate found ethdevs. */
	for (dev_id = 0; dev_id < eth_dev_count; dev_id++) {
		struct rte_eth_dev_info ethdev_info;

		if (!rte_eth_dev_is_valid_port(dev_id))
			continue;

		memset(&ethdev_info, 0, sizeof(ethdev_info));
		ret = rte_eth_dev_info_get(dev_id, &ethdev_info);
		if (ret) {
			CA_ERR("Could not get ethdev info for port: %u", dev_id);
			return ret;
		}

		if ((strcmp(ethdev_info.driver_name, ETH_DEV_PMD_NAME_CN9K) == 0) ||
		    (strcmp(ethdev_info.driver_name, ETH_DEV_PMD_NAME_CN10K) == 0)) {
			/* Valid device found. */

			nb_queue_avail =
				RTE_MIN(ethdev_info.max_rx_queues, ethdev_info.max_tx_queues);
			nb_queue_avail = RTE_MIN(nb_queue_avail, CA_MAX_ETH_QUEUE);
			ca_glb_ctx.eth_ctx[nb_valid_devs].nb_queue_avail = nb_queue_avail;
			ca_glb_ctx.eth_ctx[nb_valid_devs].port_id = dev_id;
			nb_valid_devs++;
		}

		if (ethdev_info.min_rx_bufsize < ETH_DEV_MIN_BUF_LEN ||
		    ethdev_info.max_rx_pktlen > ETH_DEV_MAX_BUF_LEN) {
			CA_ERR("Eth dev %u, invalid buffer size", dev_id);
			CA_ERR("Min buffer size: %u, Max packet size: %u",
			       ethdev_info.min_rx_bufsize, ethdev_info.max_rx_pktlen);
			CA_ERR("Min buffer size should be >= %lu and max buffer size should be <= %lu",
			       ETH_DEV_MIN_BUF_LEN, ETH_DEV_MAX_BUF_LEN);
			return -EINVAL;
		}
	}

	CA_INFO("Valid eth devices found: %u\n", nb_valid_devs);
	if (nb_valid_devs == 0) {
		CA_ERR("No valid ethernet devices found. Please enable at least one ethdev.");
		return -ENODEV;
	}

	ca_glb_ctx.nb_valid_ethdevs = nb_valid_devs;

	return 0;
}

static int
crypto_devs_init(struct ca_dev_config *dev_config)
{
	struct rte_pmd_cnxk_crypto_qptr *cpt_qptr;
	struct rte_cryptodev_qp_conf qp_conf;
	uint16_t i, dev_id, nb_desc, qp_id;
	struct rte_cryptodev_config conf;
	int ret;

	/* Using only first device. */
	dev_id = ca_glb_ctx.cryptodev_ids[0];

	CA_INFO("Initializing cryptodev: %d", dev_id);

	/* Update nb_desc to next power of 2 to aid in pending queue checks */
	nb_desc = rte_align32pow2(dev_config->crypto.nb_desc);

	if (nb_desc < CA_CPT_MIN_QUEUE_DEPTH) {
		CA_INFO("Using minimum queue depth: %d", nb_desc);
		nb_desc = CA_CPT_MIN_QUEUE_DEPTH;
	}

	memset(&conf, 0, sizeof(conf));
	conf.socket_id = SOCKET_ID_ANY;
	conf.nb_queue_pairs = rte_lcore_count();
	ret = rte_cryptodev_configure(dev_id, &conf);
	if (ret) {
		CA_ERR("Could not configure cryptodev: %d.", dev_id);
		return ret;
	}

	for (i = 0; i < conf.nb_queue_pairs; i++) {
		memset(&qp_conf, 0, sizeof(qp_conf));
		qp_conf.nb_descriptors = nb_desc;
		ret = rte_cryptodev_queue_pair_setup(dev_id, i, &qp_conf, SOCKET_ID_ANY);
		if (ret) {
			CA_ERR("Could not setup queue [cryptodev: %d, qp: %d].", dev_id, i);
			return ret;
		}
	}

	ca_glb_ctx.nb_cpt_qp = conf.nb_queue_pairs;

	ret = rte_cryptodev_start(dev_id);
	if (ret) {
		CA_ERR("Could not start cryptodev: %d.", dev_id);
		return ret;
	}

	qp_id = 0;

	for (i = 0; i < CA_MAX_LCORE; i++) {
		if (rte_lcore_is_enabled(i) == 0)
			continue;

		cpt_qptr = rte_pmd_cnxk_crypto_qptr_get(dev_id, qp_id);
		if (cpt_qptr == NULL) {
			CA_ERR("Could not get CPT QPTR for [cryptodev: %d, qp: %d].", dev_id,
			       qp_id);
			ret = -ENODEV;
			goto cryptodev_stop;
		}

		ca_glb_ctx.cryptodev_ctx[i].cpt_qptr = cpt_qptr;
		ca_glb_ctx.cryptodev_ctx[i].nb_allowed = nb_desc;

		qp_id++;
	}

	return 0;

cryptodev_stop:
	rte_cryptodev_stop(dev_id);

	return ret;
}

static void
crypto_devs_fini(void)
{
	uint16_t dev_id;
	int ret;

	/* Using only first device. */
	dev_id = ca_glb_ctx.cryptodev_ids[0];

	CA_INFO("Closing cryptodev: %d", dev_id);

	rte_cryptodev_stop(dev_id);

	ret = rte_cryptodev_close(dev_id);
	if (ret)
		CA_ERR("Could not close cryptodev: %d.", dev_id);
}

static int
eth_devs_init(struct ca_dev_config *dev_config)
{
	struct dao_lc_eth_qconf qconf;
	uint16_t j, nb_queue;
	uint8_t i, port_id;
	int ret;

	for (i = 0; i < ca_glb_ctx.nb_valid_ethdevs; i++) {
		nb_queue = dev_config->eth.nb_queue[i];
		port_id = ca_glb_ctx.eth_ctx[i].port_id;

		ret = ca_eth_dev_init(port_id, nb_queue);
		if (ret) {
			CA_ERR("Could not initialize ethdev: %d", port_id);
			goto eth_devs_close;
		}

		memset(&qconf, 0, sizeof(qconf));
		qconf.nb_desc = 8192;
		qconf.max_seg_size = dev_config->max_payload_size;
		qconf.dev_id = port_id;

		for (j = 0; j < nb_queue; j++) {
			qconf.qp_id = j;
			ret = ca_eth_dev_q_configure(&qconf);
			if (ret) {
				CA_ERR("Could not configure ethdev queue: %d", j);
				ca_glb_ctx.eth_ctx[i].nb_queue = j;
				goto eth_devs_close;
			}
		}

		ret = ca_eth_dev_start(port_id);
		if (ret) {
			CA_ERR("Could not start ethdev: %d", port_id);
			goto eth_devs_close;
		}
	}

	return 0;

eth_devs_close:
	while (i > 0) {
		nb_queue = ca_glb_ctx.eth_ctx[--i].nb_queue;
		port_id = ca_glb_ctx.eth_ctx[i].port_id;

		ca_eth_dev_stop(port_id);
		ca_eth_dev_fini(port_id);

		for (j = 0; j < nb_queue; j++)
			ca_eth_dev_q_destroy(port_id, j);
	}

	return -ENODEV;
}

static void
eth_devs_fini(void)
{
	uint8_t port_id;
	uint16_t i, j;

	for (i = 0; i < ca_glb_ctx.nb_valid_ethdevs; i++) {
		port_id = ca_glb_ctx.eth_ctx[i].port_id;

		ca_eth_dev_stop(port_id);
		ca_eth_dev_fini(port_id);

		for (j = 0; j < ca_glb_ctx.eth_ctx[i].nb_queue; j++)
			ca_eth_dev_q_destroy(port_id, j);
	}
}

static int
worker_thread(__rte_unused void *arg)
{
	struct ca_eth_dev_queue_lcore_map *eth_map;
	struct rte_pmd_cnxk_crypto_qptr *cpt_qptr;
	struct ca_cryptodev_ctx *cdev_ctx;
	uint16_t nb_allowed, nb_pkts;
	struct lcore_conf *lconf;
	int i, lcore_id;

	lcore_id = rte_lcore_id();

	if (rte_lcore_is_enabled(lcore_id) == 0) {
		CA_ERR("Lcore %d is not enabled", lcore_id);
		return -ENODEV;
	}

	cdev_ctx = &ca_glb_ctx.cryptodev_ctx[lcore_id];

	cpt_qptr = cdev_ctx->cpt_qptr;
	if (cpt_qptr == NULL) {
		CA_ERR("Could not get CPT QPTR for lcore: %d", lcore_id);
		return -ENODEV;
	}

	nb_allowed = cdev_ctx->nb_allowed;
	if (nb_allowed == 0) {
		CA_ERR("Invalid number of allowed descriptors for lcore: %d", lcore_id);
		return -EINVAL;
	}

	eth_map = ca_eth_lcore_map_get(lcore_id);
	if (eth_map == NULL) {
		CA_ERR("Could not get eth map for lcore: %d", lcore_id);
		return -ENODEV;
	}

	/* Prepare lcore conf */

	lconf = &lcore_conf[lcore_id];

	lconf->nb_pq = eth_map->nb_links;
	for (i = 0; i < lconf->nb_pq; i++) {
		lconf->pq[i] = eth_map->link[i].pq;
		if (lconf->pq[i] == NULL) {
			CA_ERR("Could not get pending queue for lcore: %d, link: %d", lcore_id, i);
			return -ENODEV;
		}
	}

	/* Start worker thread */
	CA_ERR("[Lcore: %d] Starting worker thread", lcore_id);

	CA_ERR("[Lcore: %d] No of links: %d", lcore_id, lconf->nb_pq);
	for (i = 0; i < lconf->nb_pq; i++)
		CA_ERR("[Lcore: %d] \t\tLink %d: Port %u, Queue %u", lcore_id, i,
		       lconf->pq[i]->eth_port_id, lconf->pq[i]->eth_queue_id);

	while (!force_quit) {
		if (lconf->nb_pq == 0)
			continue;

		for (i = 0; i < lconf->nb_pq; i++) {
			nb_pkts = ca_eth_rx(lconf->pq[i], cpt_qptr, nb_allowed);
			nb_allowed -= nb_pkts;

			nb_pkts = ca_cpt_deq(lconf->pq[i]);
			nb_allowed += nb_pkts;
		}
	}

	return 0;
}

int
main(int argc, char **argv)
{
	struct ca_dev_config dev_config;
	int rc, i;

	rc = rte_eal_init(argc, argv);
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");

	argc -= rc;
	argv += rc;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	rc = crypto_devs_validate();
	if (rc) {
		CA_ERR("Could not validate crypto devices");
		goto eal_cleanup;
	}

	rc = eth_devs_validate();
	if (rc) {
		CA_ERR("Could not validate ethernet devices");
		goto eal_cleanup;
	}

	rc = ca_eth_lcore_map_init();
	if (rc) {
		CA_ERR("Could not initialize lcore map");
		goto eal_cleanup;
	}

	memset(&dev_config, 0, sizeof(dev_config));

	/* Wait for command to enable crypto & eth? */

	dev_config.crypto.nb_desc = CA_CPT_MIN_QUEUE_DEPTH;
	dev_config.eth.nb_devs = ca_glb_ctx.nb_valid_ethdevs;

	for (i = 0; i < dev_config.eth.nb_devs; i++)
		dev_config.eth.nb_queue[i] = CA_MAX_ETH_QUEUE;

	dev_config.max_payload_size = CA_MAX_PAYLOAD_SIZE;

	rc = crypto_devs_init(&dev_config);
	if (rc) {
		CA_ERR("Could not initialize crypto devices");
		goto eal_cleanup;
	}

	rc = eth_devs_init(&dev_config);
	if (rc) {
		CA_ERR("Could not initialize ethernet devices");
		goto crypto_devs_fini;
	}

	/* Launch on every worker lcore */
	rte_eal_mp_remote_launch(worker_thread, NULL, SKIP_MAIN);

	/* Wait for all cores to return */
	rte_eal_mp_wait_lcore();

	eth_devs_fini();

crypto_devs_fini:
	crypto_devs_fini();

eal_cleanup:
	rte_eal_cleanup();

	return 0;
}
