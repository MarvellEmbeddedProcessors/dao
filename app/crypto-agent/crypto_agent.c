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
#include "ca_crypto_queue.h"
#include "ca_dp.h"
#include "crypto_agent.h"

#define ETH_DEV_PMD_NAME_CN9K  "net_cn9k"
#define ETH_DEV_PMD_NAME_CN10K "net_cn10k"

static volatile bool force_quit;

static struct ca_global_ctx ca_glb_ctx;

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

	/* TODO - decide whether we want to support multiple devices */
	if (nb_valid_devs > 1) {
		CA_INFO("Multiple primary cryptodevs not supported");
		return -ENODEV;
	}

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
crypto_queue_name_get(uint16_t dev_id, uint16_t qp_id, char *name)
{
	snprintf(name, RTE_MEMZONE_NAMESIZE, "ca_cryptodev_%u_qp_%u", dev_id, qp_id);
}

static int
crypto_devs_init(struct ca_dev_config *dev_config)
{
	struct rte_cryptodev_qp_conf qp_conf;
	struct rte_cryptodev_config conf;
	const struct rte_memzone *pq_mem;
	char name[RTE_MEMZONE_NAMESIZE];
	uint16_t i, dev_id, nb_desc;
	int ret, len;

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

		/* Allocate SW queue to hold state */

		len = sizeof(struct cpt_inflight_req) * qp_conf.nb_descriptors;

		crypto_queue_name_get(dev_id, i, name);

		pq_mem = rte_memzone_reserve_aligned(name, len, SOCKET_ID_ANY, 0,
						     RTE_CACHE_LINE_SIZE);
		if (pq_mem == NULL) {
			CA_ERR("Could not reserve memzone for pending queue [cryptodev: %d, qp: %d].",
			       dev_id, i);
			conf.nb_queue_pairs = i;
			goto pq_mem_free;
		}

		ca_glb_ctx.cpt_pq[i].req_queue = pq_mem->addr;
		memset(ca_glb_ctx.cpt_pq[i].req_queue, 0, len);

		ca_glb_ctx.cpt_pq[i].pq_mask = qp_conf.nb_descriptors - 1;
	}

	ca_glb_ctx.nb_cpt_qp = conf.nb_queue_pairs;

	ret = rte_cryptodev_start(dev_id);
	if (ret) {
		CA_ERR("Could not start cryptodev: %d.", dev_id);
		return ret;
	}

	for (i = 0; i < conf.nb_queue_pairs; i++) {
		ca_glb_ctx.cpt_pq[i].cpt_qptr = rte_pmd_cnxk_crypto_qptr_get(dev_id, i);
		if (ca_glb_ctx.cpt_pq[i].cpt_qptr == NULL) {
			CA_ERR("Could not get CPT QPTR for [cryptodev: %d, qp: %d].", dev_id, i);
			ret = -ENODEV;
			goto cryptodev_stop;
		}
	}

	return 0;

cryptodev_stop:
	rte_cryptodev_stop(dev_id);

pq_mem_free:
	for (i = 0; i < conf.nb_queue_pairs; i++) {
		crypto_queue_name_get(dev_id, i, name);
		rte_memzone_free(rte_memzone_lookup(name));
	}

	return ret;
}

static void
crypto_devs_fini(void)
{
	char name[RTE_MEMZONE_NAMESIZE];
	uint16_t dev_id;
	int ret, i;

	/* Using only first device. */
	dev_id = ca_glb_ctx.cryptodev_ids[0];

	for (i = 0; i < ca_glb_ctx.nb_cpt_qp; i++) {
		crypto_queue_name_get(dev_id, i, name);
		rte_memzone_free(rte_memzone_lookup(name));
	}

	CA_INFO("Closing cryptodev: %d", dev_id);

	rte_cryptodev_stop(dev_id);

	ret = rte_cryptodev_close(dev_id);
	if (ret)
		CA_ERR("Could not close cryptodev: %d.", dev_id);
}

static int
eth_devs_init(struct ca_dev_config *dev_config)
{
	uint16_t i, port_id, nb_queue, queue_id, nb_rxd, nb_txd, buf_sz;
	struct rte_ether_addr ports_eth_addr;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_conf port_conf;
	struct rte_eth_rxconf rx_conf;
	struct rte_eth_txconf tx_conf;
	struct rte_eth_link link;
	int ret;

	/* TODO - determine proper values */
	nb_rxd = 1024;
	nb_txd = 1024;

	buf_sz = dev_config->max_payload_size;

	for (i = 0; i < ca_glb_ctx.nb_valid_ethdevs; i++) {
		port_id = ca_glb_ctx.eth_ctx[i].port_id;

		CA_INFO("Initializing ethdev: %d", port_id);

		memset(&dev_info, 0, sizeof(dev_info));
		ret = rte_eth_dev_info_get(port_id, &dev_info);
		if (ret) {
			CA_ERR("Could not get ethdev info: %d.", port_id);
			return ret;
		}

		if (dev_info.max_rx_queues < dev_config->eth.nb_queue[i]) {
			CA_ERR("Requested queues %d > max rx queues %d",
			       dev_config->eth.nb_queue[i], dev_info.max_rx_queues);
			return -EINVAL;
		}

		if (dev_info.max_tx_queues < dev_config->eth.nb_queue[i]) {
			CA_ERR("Requested queues %d > max tx queues %d",
			       dev_config->eth.nb_queue[i], dev_info.max_tx_queues);
			return -EINVAL;
		}

		nb_queue = dev_config->eth.nb_queue[i];

		memset(&port_conf, 0, sizeof(port_conf));

		port_conf.rxmode.mtu = buf_sz;
		port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
		port_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
		port_conf.txmode.offloads = RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

		ret = rte_eth_dev_configure(port_id, nb_queue, nb_queue, &port_conf);
		if (ret) {
			CA_ERR("Could not configure ethdev: %d.", port_id);
			return ret;
		}

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
		if (ret) {
			CA_ERR("Could not adjust nb rx/tx desc: %d.", port_id);
			return ret;
		}

		rte_eth_macaddr_get(port_id, &ports_eth_addr);
		CA_INFO("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			" %02" PRIx8,
			port_id, ports_eth_addr.addr_bytes[0], ports_eth_addr.addr_bytes[1],
			ports_eth_addr.addr_bytes[2], ports_eth_addr.addr_bytes[3],
			ports_eth_addr.addr_bytes[4], ports_eth_addr.addr_bytes[5]);

		for (queue_id = 0; queue_id < nb_queue; queue_id++) {
			memset(&rx_conf, 0, sizeof(rx_conf));
			memset(&tx_conf, 0, sizeof(tx_conf));

			rx_conf.offloads = port_conf.rxmode.offloads;
			tx_conf.offloads = port_conf.txmode.offloads;

			ret = rte_eth_rx_queue_setup(port_id, queue_id, nb_rxd, 0, &rx_conf,
						     ca_glb_ctx.eth_ctx[i].mempool);
			if (ret) {
				CA_ERR("Could not setup Rx queue: %d.", port_id);
				return ret;
			}

			ret = rte_eth_tx_queue_setup(port_id, queue_id, nb_txd, 0, &tx_conf);
			if (ret) {
				CA_ERR("Could not setup Tx queue: %d.", port_id);
				return ret;
			}
		}

		ret = rte_eth_promiscuous_enable(port_id);
		if (ret) {
			CA_ERR("Could not enable promiscuous mode: %d.", port_id);
			return ret;
		}

		ret = rte_eth_dev_start(port_id);
		if (ret) {
			CA_ERR("Could not start ethdev: %d.", port_id);
			return ret;
		}

		ret = rte_eth_link_get(port_id, &link);
		if (ret) {
			CA_ERR("Could not get link status: %d.", port_id);
			goto eth_devs_close;
		}

		if (link.link_status == RTE_ETH_LINK_UP) {
			CA_INFO("Port %u Link Up - speed %u Mbps - %s", port_id, link.link_speed,
				(link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ? "full-duplex" :
										 "half-duplex");
		} else {
			CA_INFO("Port %u Link Down", port_id);
			goto eth_devs_close;
		}
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
	uint16_t i, port_id;

	for (i = 0; i < ca_glb_ctx.nb_valid_ethdevs; i++) {
		port_id = ca_glb_ctx.eth_ctx[i].port_id;

		CA_INFO("Closing ethdev: %d", port_id);

		rte_eth_dev_stop(port_id);
		rte_eth_dev_close(port_id);
	}
}

int
main(int argc, char **argv)
{
	struct ca_dev_config dev_config;
	int rc;

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
	dev_config.eth.nb_queue[0] = 1;
	dev_config.eth.nb_queue[1] = 1;
	dev_config.max_payload_size = 9000;

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

	while (!force_quit) {
		ca_eth_rx(ca_glb_ctx.nb_valid_ethdevs, &ca_glb_ctx.cpt_pq[0]);
		ca_cpt_deq(&ca_glb_ctx.cpt_pq[0]);
	}

	eth_devs_fini();

crypto_devs_fini:
	crypto_devs_fini();

mempool_fini:
	mempool_fini();

eal_cleanup:
	rte_eal_cleanup();

	return 0;
}
