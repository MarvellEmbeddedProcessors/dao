/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <pthread.h>
#include <signal.h>
#include <stdlib.h>

#include <rte_alarm.h>
#include <rte_common.h>
#include <rte_cryptodev.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_rcu_qsbr.h>

#include <dao_version.h>

#include "ca_admin.h"
#include "ca_cpt_deq.h"
#include "ca_crypto_queue.h"
#include "ca_eth_rx.h"
#include "ca_ethdev.h"
#include "crypto_agent.h"

static volatile bool force_quit;

static struct ca_global_ctx ca_glb_ctx;

struct lcore_conf lcore_conf[CA_MAX_LCORE];

static pthread_t stats_thread;

struct dao_card_config {
	int argc;
	char **argv;
	uint32_t crypto_nb_desc;
};

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

struct rte_rcu_qsbr *
ca_rcu_qsbr_get(void)
{
	return ca_glb_ctx.qsbr;
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

	if (nb_valid_devs > 1)
		CA_INFO("Only one crypto device supported. Using first device.");

	memset(&cryptodev_info, 0, sizeof(cryptodev_info));
	rte_cryptodev_info_get(ca_glb_ctx.cryptodev_ids[0], &cryptodev_info);

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

	CA_INFO("Eth devices found: %u", nb_valid_devs);
	if (nb_valid_devs == 0) {
		CA_ERR("No valid ethernet devices found. Please enable at least one ethdev.");
		return -ENODEV;
	}

	ca_glb_ctx.nb_valid_ethdevs = nb_valid_devs;

	return 0;
}

static int
crypto_devs_init(uint32_t nb_desc)
{
	struct rte_pmd_cnxk_crypto_qptr *cpt_qptr;
	struct rte_cryptodev_qp_conf qp_conf;
	struct rte_cryptodev_config conf;
	uint16_t i, dev_id, qp_id;
	int ret;

	/* Using only first device. */
	dev_id = ca_glb_ctx.cryptodev_ids[0];

	CA_INFO("Initializing cryptodev: %d", dev_id);

	/* Update nb_desc to next power of 2 to aid in pending queue checks */
	nb_desc = rte_align32pow2(nb_desc);

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
rcu_qsbr_init(void)
{
	struct rte_rcu_qsbr *qsbr;
	size_t sz;
	int ret;

	sz = rte_rcu_qsbr_get_memsize(CA_MAX_LCORE);
	if (sz == 0) {
		CA_ERR("Could not get RCU QSBR memsize");
		return -ENOMEM;
	}

	qsbr = rte_zmalloc(NULL, sz, RTE_CACHE_LINE_SIZE);
	if (qsbr == NULL) {
		CA_ERR("Could not allocate memory for RCU QSBR");
		return -ENOMEM;
	}

	ret = rte_rcu_qsbr_init(qsbr, CA_MAX_LCORE);
	if (ret) {
		CA_ERR("Could not initialize RCU QSBR");
		goto free_mem;
	}

	ca_glb_ctx.qsbr = qsbr;
	return 0;

free_mem:
	rte_free(qsbr);
	return ret;
}

static void
rcu_qsbr_fini(void)
{
	rte_free(ca_glb_ctx.qsbr);
	ca_glb_ctx.qsbr = NULL;
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

static void
print_stats(__rte_unused void *param)
{
	uint64_t total_rx = 0, total_tx = 0;
	unsigned int i = 0;

	/* Clear the screen and move the cursor to the top-left corner */
	const char clr[] = {27, '[', '2', 'J', '\0'};
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};

	CA_INFO("%s%s", clr, topLeft);

	CA_INFO("Core statistics:");
	CA_INFO("--------------------------------------------------");
	CA_INFO("| Core |      RX Packets      |      TX Packets      |");
	CA_INFO("--------------------------------------------------");

	for (i = 0; i < CA_MAX_LCORE; i++) {
		/* Skip disabled cores */
		if (!rte_lcore_is_enabled(i))
			continue;

		CA_INFO("| %4u | %20" PRIu64 " | %20" PRIu64 " |", i, lcore_conf[i].rx_packets,
			lcore_conf[i].tx_packets);
		total_rx += lcore_conf[i].rx_packets;
		total_tx += lcore_conf[i].tx_packets;
	}

	CA_INFO("--------------------------------------------------");
	CA_INFO("| Total| %20" PRIu64 " | %20" PRIu64 " |", total_rx, total_tx);
	CA_INFO("--------------------------------------------------");

	/* Print stats for every 5 seconds */
	if (rte_eal_alarm_set(5000000, print_stats, NULL) < 0)
		CA_ERR("Could not set alarm for stats");
}

static int
worker_thread(__rte_unused void *arg)
{
	struct rte_pmd_cnxk_crypto_qptr *cpt_qptr;
	struct ca_cryptodev_ctx *cdev_ctx;
	uint16_t nb_allowed, nb_pkts;
	struct rte_rcu_qsbr *qsbr;
	struct lcore_conf *lconf;
	int i, lcore_id;

	lcore_id = rte_lcore_id();

	if (rte_lcore_is_enabled(lcore_id) == 0) {
		CA_ERR("Lcore %d is not enabled", lcore_id);
		return -ENODEV;
	}

	qsbr = ca_rcu_qsbr_get();
	if (qsbr == NULL) {
		CA_ERR("Could not get RCU QSBR");
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

	lconf = &lcore_conf[lcore_id];

	/* Register this thread to report quiescent state */
	rte_rcu_qsbr_thread_register(qsbr, lcore_id);
	rte_rcu_qsbr_thread_online(qsbr, lcore_id);

	/* Start worker thread */
	CA_INFO("[Lcore: %d] Starting worker thread", lcore_id);

	CA_INFO("[Lcore: %d] No of links: %d", lcore_id, lconf->nb_pq);
	for (i = 0; i < lconf->nb_pq; i++)
		CA_INFO("[Lcore: %d] \t\tLink %d: Port %u, Queue %u", lcore_id, i,
			lconf->pq[i]->eth_port_id, lconf->pq[i]->eth_queue_id);

	while (!force_quit) {
		/* Update quiet state */
		rte_rcu_qsbr_quiescent(qsbr, lcore_id);

		if (lconf->nb_pq == 0)
			continue;

		for (i = 0; i < lconf->nb_pq; i++) {
			nb_pkts = ca_eth_rx(lconf->pq[i], cpt_qptr, nb_allowed);
			lconf->rx_packets += nb_pkts;
			nb_allowed -= nb_pkts;

			nb_pkts = ca_cpt_deq(lconf->pq[i]);
			lconf->tx_packets += nb_pkts;
			nb_allowed += nb_pkts;
		}
	}

	/* Unregister this thread from reporting quiescent state */
	rte_rcu_qsbr_thread_offline(qsbr, lcore_id);
	rte_rcu_qsbr_thread_unregister(qsbr, lcore_id);

	return 0;
}

static void *
stats_thread_cb(void *arg)
{
	if (force_quit) {
		if (rte_eal_alarm_cancel(print_stats, NULL) < 0)
			CA_ERR("Could not cancel alarm for stats");
		return NULL;
	}

	print_stats(arg);

	return NULL;
}

static int
card_init(struct dao_card_config *config)
{
	int ret, i;

	ret = rte_eal_init(config->argc, config->argv);
	if (ret < 0) {
		CA_ERR("Invalid EAL parameters");
		return ret;
	}

	ret = crypto_devs_validate();
	if (ret) {
		CA_ERR("Could not validate crypto devices");
		goto eal_cleanup;
	}

	ret = eth_devs_validate();
	if (ret) {
		CA_ERR("Could not validate ethernet devices");
		goto eal_cleanup;
	}

	ret = ca_eth_lcore_map_init();
	if (ret) {
		CA_ERR("Could not initialize lcore map");
		goto eal_cleanup;
	}

	ret = crypto_devs_init(config->crypto_nb_desc);
	if (ret) {
		CA_ERR("Could not initialize crypto devices");
		goto map_fini;
	}

	ret = rcu_qsbr_init();
	if (ret) {
		CA_ERR("Could not initialize RCU QSBR");
		goto cdev_fini;
	}

	for (i = 0; i < CA_MAX_LCORE; i++)
		memset(&lcore_conf[i], 0, sizeof(struct lcore_conf));

	/* Create a separate thread for printing stats */
	if (pthread_create(&stats_thread, NULL, stats_thread_cb, NULL) != 0) {
		CA_ERR("Could not create stats thread");
		goto cdev_fini;
	}

	return 0;

cdev_fini:
	crypto_devs_fini();
map_fini:
	ca_eth_lcore_map_fini();
eal_cleanup:
	rte_eal_cleanup();

	return ret;
}

static void
card_fini(void)
{
	int i;

	CA_INFO("Cleaning up DAO card");

	for (i = 0; i < CA_MAX_LCORE; i++)
		memset(&lcore_conf[i], 0, sizeof(struct lcore_conf));

	/* Wait for the stats thread to finish */
	force_quit = 1;
	pthread_join(stats_thread, NULL);

	rcu_qsbr_fini();
	crypto_devs_fini();
	ca_eth_lcore_map_fini();
	rte_eal_cleanup();
}

struct rte_mempool *
ca_host_sess_mempool_get(uint8_t dev_id)
{
	if (dev_id >= ca_glb_ctx.nb_host_dev) {
		CA_ERR("Invalid host dev id: %u", dev_id);
		return NULL;
	}

	return ca_glb_ctx.host_ctx[dev_id].sess_mempool;
}

static int
host_dev_sess_mempool_init(uint8_t dev_id, uint32_t nb_sess)
{
	char name[RTE_MEMZONE_NAMESIZE];
	struct rte_mempool *mp;
	uint16_t sess_sz;

	if (nb_sess == 0) {
		CA_ERR("Invalid number of sessions: %u", nb_sess);
		return -EINVAL;
	}

	snprintf(name, sizeof(name), "ca_host_sess_%u", dev_id);

	sess_sz = sizeof(struct dao_lc_sym_fc_ctx);

	mp = rte_mempool_create(name, nb_sess, sess_sz, 0, 0, NULL, NULL, NULL, NULL, SOCKET_ID_ANY,
				0);
	if (mp == NULL) {
		CA_ERR("Could not create mempool for host sessionsfor dev: %u", dev_id);
		return -ENOMEM;
	}

	ca_glb_ctx.host_ctx[dev_id].sess_mempool = mp;

	return 0;
}

static int
host_dev_init(void)
{
	uint16_t i, dev_id, nb_sess;
	int ret;

	for (i = 0; i < CA_MAX_HOST_DEV; i++) {
		dev_id = i;
		nb_sess = CA_MAX_SYM_SESSIONS;

		ret = host_dev_sess_mempool_init(dev_id, nb_sess);
		if (ret) {
			CA_ERR("Could not initialize host dev: %u", dev_id);
			return ret;
		}

		ca_glb_ctx.nb_host_dev++;
	}

	return 0;
}

static int
host_dev_fini(void)
{
	uint16_t i;

	for (i = 0; i < ca_glb_ctx.nb_host_dev; i++) {
		rte_mempool_free(ca_glb_ctx.host_ctx[i].sess_mempool);
		ca_glb_ctx.host_ctx[i].sess_mempool = NULL;
	}

	ca_glb_ctx.nb_host_dev = 0;

	return 0;
}

int
main(int argc, char **argv)
{
	struct ca_dev_config dev_config;
	int rc, i;

	struct dao_card_config config = {
		.argc = argc,
		.argv = argv,
		.crypto_nb_desc = CA_CPT_MIN_QUEUE_DEPTH,
	};

	CA_INFO("Crypto Agent Version: %s", dao_version());

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	rc = card_init(&config);
	if (rc) {
		CA_ERR("Could not initialize card");
		return rc;
	}

	memset(&dev_config, 0, sizeof(dev_config));

	/* Wait for command to enable crypto & eth? */
	dev_config.eth.nb_devs = ca_glb_ctx.nb_valid_ethdevs;

	for (i = 0; i < dev_config.eth.nb_devs; i++)
		dev_config.eth.nb_queue[i] = CA_MAX_ETH_QUEUE;

	dev_config.max_payload_size = CA_MAX_PAYLOAD_SIZE;

	rc = eth_devs_init(&dev_config);
	if (rc) {
		CA_ERR("Could not initialize ethernet devices");
		goto card_fini;
	}

	rc = host_dev_init();
	if (rc) {
		CA_ERR("Could not initialize host devices");
		goto eth_devs_fini;
	}

	/* Launch on every worker lcore */
	rte_eal_mp_remote_launch(worker_thread, NULL, SKIP_MAIN);

	/* Wait for all cores to return */
	rte_eal_mp_wait_lcore();

	host_dev_fini();

eth_devs_fini:
	eth_devs_fini();
card_fini:
	card_fini();
	return rc;
}
