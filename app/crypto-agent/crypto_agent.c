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
	uint16_t eth_dev_count, dev_id, nb_valid_devs = 0;
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
			ca_glb_ctx.eth_ctx[nb_valid_devs].port_id = dev_id;
			nb_valid_devs++;
			CA_INFO("Eth dev %u, max rx queues: %d", ca_glb_ctx.eth_ctx[dev_id].port_id,
				ethdev_info.max_rx_queues);
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
mempool_init(struct ca_dev_config *ca_dev_config)
{
	uint16_t i, nb_devs, port_id, buf_sz;
	char name[RTE_MEMZONE_NAMESIZE];
	struct rte_mempool *mp;

	RTE_SET_USED(ca_dev_config);

	nb_devs = ca_glb_ctx.nb_valid_ethdevs;

	for (i = 0; i < nb_devs; i++) {
		port_id = ca_glb_ctx.eth_ctx[i].port_id;
		snprintf(name, sizeof(name), "ca_ethdev_%u", port_id);

		buf_sz = ca_dev_config->max_payload_size;

		/* TODO - add proper values */
		mp = rte_pktmbuf_pool_create(name, 8192, 256, 0, buf_sz, SOCKET_ID_ANY);
		if (mp == NULL) {
			CA_ERR("Could not create mempool for ethdev: %u", i);
			return -ENOMEM;
		}

		ca_glb_ctx.eth_ctx[i].mempool = mp;
	}

	return 0;
}

static void
mempool_fini(void)
{
	uint16_t i, nb_devs;

	nb_devs = ca_glb_ctx.nb_valid_ethdevs;

	for (i = 0; i < nb_devs; i++)
		rte_mempool_free(ca_glb_ctx.eth_ctx[i].mempool);
}

static void
ethdev_queue_name_get(uint16_t dev_id, uint16_t qp_id, char *name)
{
	snprintf(name, RTE_MEMZONE_NAMESIZE, "ca_ethdev_%u_q_%u", dev_id, qp_id);
}

static int
crypto_devs_init(struct ca_dev_config *dev_config)
{
	struct rte_cryptodev_qp_conf qp_conf;
	struct rte_cryptodev_config conf;
	uint16_t i, dev_id, nb_desc;
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

	for (i = 0; i < conf.nb_queue_pairs; i++) {
		ca_glb_ctx.cpt_qptr[i] = rte_pmd_cnxk_crypto_qptr_get(dev_id, i);
		if (ca_glb_ctx.cpt_qptr[i] == NULL) {
			CA_ERR("Could not get CPT QPTR for [cryptodev: %d, qp: %d].", dev_id, i);
			ret = -ENODEV;
			goto cryptodev_stop;
		}
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
	uint8_t i;
	int ret;

	for (i = 0; i < ca_glb_ctx.nb_valid_ethdevs; i++) {
		ret = ca_eth_dev_init(ca_glb_ctx.eth_ctx[i].port_id, dev_config,
				      ca_glb_ctx.eth_ctx[i].mempool);
		if (ret)
			goto eth_devs_close;

		ca_glb_ctx.eth_ctx[i].nb_queue = dev_config->eth.nb_queue[i];
	}

	return 0;

eth_devs_close:
	while (i > 0) {
		rte_eth_dev_stop(ca_glb_ctx.eth_ctx[--i].port_id);
		rte_eth_dev_close(ca_glb_ctx.eth_ctx[i].port_id);
	}

	return -ENODEV;
}

static void
eth_devs_fini(void)
{
	uint16_t i;

	for (i = 0; i < ca_glb_ctx.nb_valid_ethdevs; i++)
		ca_eth_dev_fini(&ca_glb_ctx.eth_ctx[i]);
}

static int
cpt_pq_init(struct ca_dev_config *dev_config)
{
	const struct rte_memzone *pq_mem;
	char name[RTE_MEMZONE_NAMESIZE];
	int i, j, len, ret;
	uint16_t port_id;
	void *req_queue;

	/* Should this match queue depth of eth queues? */
	len = dev_config->crypto.nb_desc * sizeof(struct cpt_inflight_req);

	for (i = 0; i < ca_glb_ctx.nb_valid_ethdevs; i++) {
		port_id = ca_glb_ctx.eth_ctx[i].port_id;

		for (j = 0; j < ca_glb_ctx.eth_ctx[i].nb_queue; j++) {
			/* Allocate SW queue to hold state */

			ethdev_queue_name_get(port_id, j, name);

			pq_mem = rte_memzone_reserve_aligned(name, len, SOCKET_ID_ANY, 0,
							     RTE_CACHE_LINE_SIZE);
			if (pq_mem == NULL) {
				CA_ERR("Could not reserve memzone for pending queue [ethdev: %d, queue: %d].",
				       i, j);
				ret = -ENOMEM;
				goto pq_mem_free;
			}

			req_queue = pq_mem->addr;

			memset(req_queue, 0, len);
			memset(&ca_glb_ctx.eth_ctx[i].cpt_pq[j], 0, sizeof(struct pending_queue));

			ca_glb_ctx.eth_ctx[i].cpt_pq[j].req_queue = req_queue;
			ca_glb_ctx.eth_ctx[i].cpt_pq[j].pq_mask =
				(len / sizeof(struct cpt_inflight_req)) - 1;
		}
	}

	return 0;

pq_mem_free:
	for (i = 0; i < ca_glb_ctx.nb_valid_ethdevs; i++) {
		port_id = ca_glb_ctx.eth_ctx[i].port_id;

		for (j = 0; j < ca_glb_ctx.eth_ctx[i].nb_queue; j++) {
			ethdev_queue_name_get(port_id, i, name);
			rte_memzone_free(rte_memzone_lookup(name));
		}
	}

	return ret;
}

static void
cpt_pq_fini(void)
{
	char name[RTE_MEMZONE_NAMESIZE];
	uint16_t port_id;
	int i, j;

	for (i = 0; i < ca_glb_ctx.nb_valid_ethdevs; i++) {
		port_id = ca_glb_ctx.eth_ctx[i].port_id;

		for (j = 0; j < ca_glb_ctx.eth_ctx[i].nb_queue; j++) {
			ethdev_queue_name_get(port_id, i, name);
			rte_memzone_free(rte_memzone_lookup(name));
		}
	}
}

static int
eth_cpt_mapping_populate(void)
{
	int i, j, nb_pq, lcore_id;
	struct pending_queue *pq;

	nb_pq = 0;
	lcore_id = 0;

	for (i = 0; i < ca_glb_ctx.nb_valid_ethdevs; i++) {
		for (j = 0; j < ca_glb_ctx.eth_ctx[i].nb_queue; j++) {
			pq = &ca_glb_ctx.eth_ctx[i].cpt_pq[j];

			pq->eth_port_id = ca_glb_ctx.eth_ctx[i].port_id;
			pq->eth_queue_id = j;

			lcore_conf[lcore_id].cpt_qptr = ca_glb_ctx.cpt_qptr[lcore_id];
			lcore_conf[lcore_id].pq[nb_pq] = pq;
			lcore_conf[lcore_id].nb_pq++;
			nb_pq++;

			if (nb_pq == CA_MAX_QUEUE_PER_CORE) {
				lcore_id++;
				nb_pq = 0;
			}

			if (lcore_id == CA_MAX_LCORE)
				break;
		}
	}

	return 0;
}

static void
eth_cpt_mapping_clear(void)
{
	int i;

	for (i = 0; i < CA_MAX_LCORE; i++) {
		lcore_conf[i].cpt_qptr = NULL;
		lcore_conf[i].nb_pq = 0;
	}
}

static int
eth_flow_create_all(void)
{
	uint8_t i;
	int ret;

	for (i = 0; i < ca_glb_ctx.nb_valid_ethdevs; i++) {
		ret = ca_eth_flow_create(ca_glb_ctx.eth_ctx[i].port_id);
		if (ret) {
			CA_ERR("Could not initialize flow rules for ethdev: %d", i);
			return ret;
		}
	}

	return 0;
}

static void
eth_flow_clear_all(void)
{
	uint8_t i;

	for (i = 0; i < ca_glb_ctx.nb_valid_ethdevs; i++)
		ca_eth_flow_clear(ca_glb_ctx.eth_ctx[i].port_id);
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

	memset(&dev_config, 0, sizeof(dev_config));

	/* Wait for command to enable crypto & eth? */

	dev_config.crypto.nb_desc = 1024;
	dev_config.eth.nb_devs = ca_glb_ctx.nb_valid_ethdevs;

	for (i = 0; i < dev_config.eth.nb_devs; i++)
		dev_config.eth.nb_queue[i] = CA_MAX_ETH_QUEUE;

	dev_config.max_payload_size = CA_MAX_PAYLOAD_SIZE;

	rc = mempool_init(&dev_config);
	if (rc) {
		CA_ERR("Could not initialize mempools");
		goto eal_cleanup;
	}

	rc = crypto_devs_init(&dev_config);
	if (rc) {
		CA_ERR("Could not initialize crypto devices");
		goto mempool_fini;
	}

	rc = eth_devs_init(&dev_config);
	if (rc) {
		CA_ERR("Could not initialize ethernet devices");
		goto crypto_devs_fini;
	}

	rc = cpt_pq_init(&dev_config);
	if (rc) {
		CA_ERR("Could not initialize crypto pending queues");
		goto eth_devs_fini;
	}

	rc = eth_cpt_mapping_populate();
	if (rc) {
		CA_ERR("Could not populate eth-cpt mapping");
		goto cpt_pq_fini;
	}

	rc = eth_flow_create_all();
	if (rc) {
		CA_ERR("Could not initialize flow rules");
		goto eth_cpt_mapping_clear;
	}

	while (!force_quit) {
		struct lcore_conf *lconf;
		int i;

		lconf = &lcore_conf[0];

		for (i = 0; i < lconf->nb_pq; i++) {
			ca_eth_rx(lconf->pq[i], lconf->cpt_qptr);
			ca_cpt_deq(lconf->pq[i]);
		}
	}

	eth_flow_clear_all();

eth_cpt_mapping_clear:
	eth_cpt_mapping_clear();

cpt_pq_fini:
	cpt_pq_fini();

eth_devs_fini:
	eth_devs_fini();

crypto_devs_fini:
	crypto_devs_fini();

mempool_fini:
	mempool_fini();

eal_cleanup:
	rte_eal_cleanup();

	return 0;
}
