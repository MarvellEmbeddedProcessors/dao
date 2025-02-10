/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>

#include <rte_common.h>
#include <rte_cryptodev.h>
#include <rte_dmadev.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_rcu_qsbr.h>

#include <dao_dma.h>
#include <dao_pem.h>
#include <dao_virtio.h>
#include <dao_virtio_cryptodev.h>

#include "vc_node.h"
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

struct lcore_vdev_vq_map lcore_vdev_vq_map[RTE_MAX_LCORE];

#define MAX_VIRTIO_RX_PER_LCORE         128
#define MAX_VIRTIO_CRYPTO_DEQ_PER_LCORE 1

#define QP_DRAIN_TIMEOUT 100

static uint16_t pem_devid;

static uint16_t virtio_cryptodev_dma_vchans[DAO_VIRTIO_DEV_MAX];

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
	uint64_t virt_dev_map;
	uint16_t virtio_queue_cnt[RTE_CRYPTO_MAX_DEVS];

	uint16_t nb_virtio_rx;
	struct lcore_virtio_rx virtio_rx[MAX_VIRTIO_RX_PER_LCORE];
	uint16_t nb_crypto_deq;
	struct lcore_crypto_deq crypto_deq[MAX_VIRTIO_CRYPTO_DEQ_PER_LCORE];

	bool service_lcore;
	int dev2mem_id;
	int mem2dev_id;
	int nb_vchans;
	struct rte_graph *graph;
	char name[RTE_GRAPH_NAMESIZE];
	rte_graph_t graph_id;
	struct rte_rcu_qsbr *qs_v;
} __rte_cache_aligned;

static struct lcore_conf lcore_conf[RTE_MAX_LCORE];

struct vc_cdev_ctx vc_cdev_ctx;

static volatile bool force_quit;

static int16_t dev2mem_ids[32];
static int16_t mem2dev_ids[32];
static uint16_t dev2mem_cnt;
static uint16_t mem2dev_cnt;
static int wrkr_dma_devs;
static uint16_t dma_flush_thr;

static rte_node_t virtio_rx_nodes[DAO_VIRTIO_DEV_MAX];
static rte_node_t cryptodev_enq_node;
static rte_node_t cryptodev_deq_node;
static rte_node_t virtio_tx_node;

#define MEMPOOL_CACHE_SIZE 512

/* RCU QSBR variable */
static struct rte_rcu_qsbr *qs_v;

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
check_crypto_config(void)
{
	static const char *const primary_cdev_names[] = {
		"crypto_cn10k",
	};
	struct rte_cryptodev_info cryptodev_info;
	uint16_t cdev_count, dev_id, name_id, i;

	for (name_id = 0; name_id < RTE_DIM(primary_cdev_names); name_id++) {
		cdev_count = rte_cryptodev_devices_get(primary_cdev_names[name_id],
						       vc_cdev_ctx.enabled_primary_cdevs,
						       RTE_CRYPTO_MAX_DEVS);
		if (cdev_count)
			break;

		APP_INFO("No crypto devices of type %s found\n", primary_cdev_names[name_id]);
	}

	/* Validate found cryptodevs. */
	for (i = 0; i < cdev_count; i++) {
		dev_id = vc_cdev_ctx.enabled_primary_cdevs[i];

		if (!rte_cryptodev_is_valid_dev(dev_id))
			continue;

		/* Valid device found. */
		vc_cdev_ctx.enabled_primary_cdevs[vc_cdev_ctx.nb_primary_cryptodevs] = dev_id;
		vc_cdev_ctx.nb_primary_cryptodevs++;
	}

	if (vc_cdev_ctx.nb_primary_cryptodevs == 0) {
		APP_INFO("No valid crypto devices found. Please enable at least one cryptodev\n");
		return -ENODEV;
	}

	APP_INFO("Valid crypto devices found: %u\n", vc_cdev_ctx.nb_primary_cryptodevs);
	for (i = 0; i < vc_cdev_ctx.nb_primary_cryptodevs; i++)
		APP_INFO("Crypto dev %u\n", vc_cdev_ctx.enabled_primary_cdevs[i]);

	/* TODO - decide whether we want to support multiple devices */
	if (vc_cdev_ctx.nb_primary_cryptodevs > 1) {
		APP_INFO("Multiple primary cryptodevs not supported\n");
		return -ENODEV;
	}

	memset(&cryptodev_info, 0, sizeof(cryptodev_info));
	rte_cryptodev_info_get(vc_cdev_ctx.enabled_primary_cdevs[0], &cryptodev_info);

	APP_INFO("%d\n", cryptodev_info.max_nb_queue_pairs);

	/* TODO - why 63? It should be 64. */
	if (cryptodev_info.max_nb_queue_pairs < 63) {
		APP_INFO("Crypto dev %u does not support 63 queue pairs\n",
			 vc_cdev_ctx.enabled_primary_cdevs[0]);
		return -ENODEV;
	}

	vc_cdev_ctx.nb_qp = RTE_MIN(cryptodev_info.max_nb_queue_pairs, (unsigned int)VC_NB_QP_MAX);

	return 0;
}

static int
init_lcore_virtio_rx(void)
{
	uint16_t nb_crypto_deq, cdev_id = vc_cdev_ctx.enabled_primary_cdevs[0];
	uint16_t virtio_devid, nb_virtio_rx;
	uint8_t lcore;

	for (virtio_devid = 0; virtio_devid < DAO_VIRTIO_DEV_MAX; ++virtio_devid) {
		if (!is_virtio_dev_enabled(virtio_devid))
			continue;

		for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
			if (!(RTE_BIT64(lcore) & lcore_virtio_mask[virtio_devid])) {
				/* Virtio RX nodes must be created for the default worker core
				 * because all virtio queues are mapped to the default core
				 */
				if (lcore != vc_cdev_ctx.default_worker_lcore)
					continue;
			}

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

static int
check_virtio_config(void)
{
	uint16_t nb_lcores = 0, nb_dma_devs;
	uint16_t lcore;

	nb_dma_devs = rte_dma_count_avail();

	/* Check if we have enough DMA devices one per lcore */
	for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++)
		if (lcore_conf[lcore].nb_virtio_rx)
			nb_lcores++;

	/* Service lcore, control dma device */
	nb_lcores += 2;

	/* 2 dma devices for control */
	wrkr_dma_devs = 2 + (nb_lcores * 2);
	if (nb_dma_devs < wrkr_dma_devs) {
		APP_INFO("%u DMA devices not enough, need at least %u for %u lcores,"
			 " 1 ctrl core, 1 service core\n",
			 nb_dma_devs, wrkr_dma_devs, nb_lcores - 2);
		return -1;
	}

	return 0;
}

static void
setup_mempools(void)
{
	char name[RTE_MEMZONE_NAMESIZE];
	struct rte_mempool *pool;
	uint16_t i;

	/* Mempools for datapath is associated with cryptodev qps. Create one per each qp. */

	for (i = 0; i < vc_cdev_ctx.nb_qp; i++) {
		snprintf(name, sizeof(name), "qp_obj_pool_%u", i);
		pool = rte_mempool_create(name, VC_NB_DESC_DEFAULT, VC_MEMPOOL_BUF_SIZE,
					  MEMPOOL_CACHE_SIZE, 0, NULL, NULL, NULL, NULL,
					  SOCKET_ID_ANY, 0);
		if (pool == NULL)
			rte_exit(EXIT_FAILURE, "Cannot init cop pool\n");

		vc_cdev_ctx.qp_pool[i] = pool;
	}
}

static void
mempools_release(void)
{
	uint16_t i;

	for (i = 0; i < vc_cdev_ctx.nb_qp; i++)
		rte_mempool_free(vc_cdev_ctx.qp_pool[i]);
}

static void
setup_dma_devices(void)
{
	struct rte_dma_vchan_conf dma_qconf;
	uint16_t dev2mem_idx, mem2dev_idx;
	struct rte_dma_info dma_info;
	struct rte_dma_conf dma_conf;
	struct lcore_conf *qconf;
	uint32_t virtio_devid;
	uint32_t lcore_id;
	int16_t dma_devid;
	uint16_t vchan;
	uint64_t mask;
	int i, base;

	dma_devid = 0;
	/* Prepare half of the worker DMA devices half as dev2mem and half as mem2dev */
	for (i = 0; i < rte_dma_count_avail(); i += 2) {
		/* Setup Inbound dma device with one vchan per virtio cryptodev */
		dma_devid = rte_dma_next_dev(dma_devid);
		if (dma_devid == -1)
			break;

		rte_dma_info_get(dma_devid, &dma_info);
		APP_INFO("Setting up dmadev %s(%d)\n", dma_info.dev_name, dma_devid);

		memset(&dma_conf, 0, sizeof(dma_conf));
		dma_conf.nb_vchans = nb_virtiodevs;

		if (rte_dma_configure(dma_devid, &dma_conf) != 0)
			rte_exit(EXIT_FAILURE, "Error with rte_dma_configure()\n");

		mask = virtio_mask_ena[0];
		base = 0;
		for (vchan = 0; vchan < nb_virtiodevs; vchan++) {
			/* Get next virtio device id */
			virtio_devid = __builtin_ffsl(mask);
			if (virtio_devid == 0)
				rte_exit(EXIT_FAILURE, "Error no virtio device\n");
			virtio_devid -= 1;
			virtio_devid += base;
			virtio_cryptodev_dma_vchans[virtio_devid] = vchan;

			memset(&dma_qconf, 0, sizeof(dma_qconf));
			dma_qconf.direction = RTE_DMA_DIR_DEV_TO_MEM;
			dma_qconf.nb_desc = 2048;
			dma_qconf.src_port.pcie.coreid = 0; /* TODO PEM id */
			dma_qconf.src_port.pcie.vfen = 1;
			dma_qconf.src_port.pcie.vfid = virtio_devid + 1;
			dma_qconf.src_port.port_type = RTE_DMA_PORT_PCIE;

			if (rte_dma_vchan_setup(dma_devid, vchan, &dma_qconf) != 0)
				rte_exit(EXIT_FAILURE, "Error with inbound configuration\n");
			mask &= ~RTE_BIT64(virtio_devid);
			if (!mask) {
				base += 64;
				mask = virtio_mask_ena[1];
			}
		}

		if (rte_dma_start(dma_devid) != 0)
			rte_exit(EXIT_FAILURE, "Error with rte_dma_start()\n");

		dev2mem_ids[dev2mem_cnt++] = dma_devid;
		dma_devid++;

		/* Setup Outbound dma device with one vchan per virtio cryptodev */
		dma_devid = rte_dma_next_dev(dma_devid);
		if (dma_devid == -1)
			break;

		rte_dma_info_get(dma_devid, &dma_info);
		APP_INFO("Setting up dmadev %s(%d)\n", dma_info.dev_name, dma_devid);

		memset(&dma_conf, 0, sizeof(dma_conf));
		dma_conf.nb_vchans = nb_virtiodevs;

		if (rte_dma_configure(dma_devid, &dma_conf) != 0)
			rte_exit(EXIT_FAILURE, "Error with rte_dma_configure()\n");

		mask = virtio_mask_ena[0];
		base = 0;
		for (vchan = 0; vchan < nb_virtiodevs; vchan++) {
			/* Get next virtio device id */
			virtio_devid = __builtin_ffsl(mask);
			if (virtio_devid == 0)
				rte_exit(EXIT_FAILURE, "Error no virtio device\n");
			virtio_devid -= 1;
			virtio_devid += base;

			memset(&dma_qconf, 0, sizeof(dma_qconf));
			dma_qconf.direction = RTE_DMA_DIR_MEM_TO_DEV;
			dma_qconf.nb_desc = 2048;
			dma_qconf.dst_port.pcie.coreid = 0; /* TODO PEM id */
			dma_qconf.dst_port.pcie.vfen = 1;
			dma_qconf.dst_port.pcie.vfid = virtio_devid + 1;
			dma_qconf.dst_port.port_type = RTE_DMA_PORT_PCIE;

			if (rte_dma_vchan_setup(dma_devid, vchan, &dma_qconf) != 0)
				rte_exit(EXIT_FAILURE, "Error with outbound chan configuration\n");
			mask &= ~RTE_BIT64(virtio_devid);
			if (!mask) {
				base += 64;
				mask = virtio_mask_ena[1];
			}
		}

		if (rte_dma_start(dma_devid) != 0)
			rte_exit(EXIT_FAILURE, "Error with rte_dma_start()\n");
		mem2dev_ids[mem2dev_cnt++] = dma_devid;
		dma_devid++;
	}

	if (!dev2mem_cnt || !mem2dev_cnt)
		rte_exit(EXIT_FAILURE, "Not enough dma devices for workers\n");

	dev2mem_idx = 0;
	mem2dev_idx = 0;

	/* Provide DMA devices for virtio control */
	if (dao_dma_ctrl_dev_set(dev2mem_ids[dev2mem_idx++], mem2dev_ids[mem2dev_idx++]))
		rte_exit(EXIT_FAILURE, "Failed to set virtio control DMA dev\n");

	/* Setup two DMA devices per active DPDK lcore */
	APP_INFO("Lcore DMA map...\n");
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &lcore_conf[lcore_id];

		/* Skip Lcore if not needed */
		if (!qconf->nb_virtio_rx && !qconf->service_lcore)
			continue;

		if (dev2mem_idx == dev2mem_cnt || mem2dev_idx == mem2dev_cnt)
			rte_exit(EXIT_FAILURE, "Not enough dma devices for workers\n");

		/* Assign DMA device id */
		qconf->dev2mem_id = dev2mem_ids[dev2mem_idx++];
		qconf->mem2dev_id = mem2dev_ids[mem2dev_idx++];
		qconf->nb_vchans = nb_virtiodevs;

		APP_INFO("\tlcore %u ... dev2mem=%u mem2dev=%u\n", lcore_id, qconf->dev2mem_id,
			 qconf->mem2dev_id);
	}
	APP_INFO("\n");
}

static void
release_dma_devices(void)
{
	int16_t dma_devid;
	int rc;

	/* stop DMA devices */
	RTE_DMA_FOREACH_DEV(dma_devid) {
		rc = rte_dma_stop(dma_devid);
		if (rc)
			APP_ERR("Failed to stop dma dev %u: %s\n", dma_devid, rte_strerror(-rc));

		rc = rte_dma_close(dma_devid);
		if (rc)
			APP_ERR("Failed to close dma dev %u: %s\n", dma_devid, rte_strerror(-rc));
	}
}

static void
setup_pem_device(void)
{
	struct dao_pem_dev_conf pem_dev_conf;
	int rc;

	/* Setup pem0 */
	memset(&pem_dev_conf, 0, sizeof(pem_dev_conf));
	rc = dao_pem_dev_init(pem_devid, &pem_dev_conf);
	if (rc)
		rte_exit(EXIT_FAILURE, "Error with pem init, rc=%d\n", rc);
}

static void
release_pem_device(void)
{
	/* Close PEM */
	dao_pem_dev_fini(pem_devid);
}

static int
setup_crypto_devices(void)
{
	struct rte_mempool *asym_sess_pool, *sym_sess_pool;
	struct rte_cryptodev_info cryptodev_info;
	struct rte_cryptodev_qp_conf qp_conf;
	struct rte_cryptodev_config conf;
	uint32_t session_size = 0;
	int socket_id, ret = 0;
	uint16_t i, j, dev_id;

	/* Create asymmetric session pool */
	asym_sess_pool = rte_cryptodev_asym_session_pool_create(
		"asym_session_pool", VC_NB_ASYM_SESSION, 0, 0, SOCKET_ID_ANY);
	if (asym_sess_pool == NULL) {
		APP_ERR("Could not create asymmetric session pool.");
		return -ENOMEM;
	}

	/* Initialize crypto device */
	for (i = 0; i < vc_cdev_ctx.nb_primary_cryptodevs; i++) {
		dev_id = vc_cdev_ctx.enabled_primary_cdevs[i];

		APP_INFO("Initializing cryptodev: %d", dev_id);

		socket_id = rte_cryptodev_socket_id(dev_id);
		if (socket_id == SOCKET_ID_ANY)
			socket_id = 0;

		memset(&cryptodev_info, 0, sizeof(cryptodev_info));
		rte_cryptodev_info_get(dev_id, &cryptodev_info);

		memset(&conf, 0, sizeof(conf));
		conf.socket_id = socket_id;
		conf.nb_queue_pairs = cryptodev_info.max_nb_queue_pairs;
		ret = rte_cryptodev_configure(dev_id, &conf);
		if (ret) {
			APP_ERR("Could not configure cryptodev: %d.", dev_id);
			goto free_asym_sess_pool;
		}

		memset(&qp_conf, 0, sizeof(qp_conf));
		qp_conf.mp_session = asym_sess_pool;
		qp_conf.nb_descriptors = vc_cdev_ctx.nb_desc;

		for (j = 0; j < conf.nb_queue_pairs; j++) {
			ret = rte_cryptodev_queue_pair_setup(dev_id, j, &qp_conf, socket_id);
			if (ret) {
				APP_ERR("Could not setup queue [cryptodev: %d, queue pair: %d].",
					dev_id, j);
				goto free_asym_sess_pool;
			}
		}

		ret = dao_virtio_cryptodev_cdev_add(dev_id, vc_cdev_ctx.nb_qp, vc_cdev_ctx.qp_pool);
		if (ret) {
			APP_ERR("Could not add cryptodev: %d to virtio cryptodev map.", dev_id);
			goto free_asym_sess_pool;
		}

		ret = rte_cryptodev_start(dev_id);
		if (ret) {
			APP_ERR("Could not start cryptodev: %d.", dev_id);
			goto free_asym_sess_pool;
		}
		session_size =
			RTE_MAX(rte_cryptodev_sym_get_private_session_size(dev_id), session_size);
	}

	/* Create symmetric session pool */
	sym_sess_pool = rte_cryptodev_sym_session_pool_create("sym_session_pool", VC_NB_SYM_SESSION,
							      session_size, 0, 0, SOCKET_ID_ANY);
	if (sym_sess_pool == NULL) {
		APP_ERR("Could not create symmetric session pool.");
		ret = -ENOMEM;
		goto free_asym_sess_pool;
	}

	/* Dump offload map */
	APP_INFO("\n");
	for (i = 0; i < vc_cdev_ctx.nb_primary_cryptodevs; i++) {
		dev_id = vc_cdev_ctx.enabled_primary_cdevs[i];

		APP_INFO("VC_MAP: cryptodev_enq[%u] ======> cryptodev_deq[%u] (lcores 0x%lX)\n",
			 dev_id, dev_id, lcore_crypto_mask[dev_id]);
	}

	vc_cdev_ctx.asym_sess_pool = asym_sess_pool;
	vc_cdev_ctx.sym_sess_pool = sym_sess_pool;

	return 0;

free_asym_sess_pool:
	rte_mempool_free(asym_sess_pool);

	return ret;
}

static void
release_crypto_devices(void)
{
	uint16_t dev_id, i;

	for (i = 0; i < vc_cdev_ctx.nb_primary_cryptodevs; i++) {
		dev_id = vc_cdev_ctx.enabled_primary_cdevs[i];

		dao_virtio_cryptodev_cdev_remove(dev_id);
		rte_cryptodev_stop(dev_id);
		rte_cryptodev_close(dev_id);
	}

	rte_mempool_free(vc_cdev_ctx.asym_sess_pool);
	vc_cdev_ctx.asym_sess_pool = NULL;

	rte_mempool_free(vc_cdev_ctx.sym_sess_pool);
	vc_cdev_ctx.sym_sess_pool = NULL;

	vc_cdev_ctx.nb_primary_cryptodevs = 0;
}

static int
clear_virtio_q_config_on_default_core(uint16_t lcore_id, uint16_t vdev_id)
{
	uint64_t *default_q_map =
		&lcore_vdev_vq_map[vc_cdev_ctx.default_worker_lcore].virt_q_map[vdev_id];
	uint64_t q_map = lcore_vdev_vq_map[lcore_id].virt_q_map[vdev_id];
	uint16_t q_id;

	while (q_map > 0) {
		q_id = __builtin_ffsl(q_map);
		q_id -= 1;
		*default_q_map &= ~RTE_BIT64(q_id);
		q_map &= ~RTE_BIT64(q_id);
	}
	return 0;
}

static int
setup_lcore_virtio_queue_config(void)
{
	uint8_t default_wkr_core = vc_cdev_ctx.default_worker_lcore;
	uint16_t virtio_devid, virt_q_count;
	uint8_t lcore;

	for (virtio_devid = 0; virtio_devid < DAO_VIRTIO_DEV_MAX; virtio_devid++) {
		if (!is_virtio_dev_enabled(virtio_devid))
			continue;

		virt_q_count = dao_virtio_cryptodev_max_dataqueue_cnt_get(virtio_devid);

		/* Map all virtio queues on default worker core */
		lcore_vdev_vq_map[default_wkr_core].virt_q_map[virtio_devid] =
			(1 << virt_q_count) - 1;
	}

	for (virtio_devid = 0; virtio_devid < DAO_VIRTIO_DEV_MAX; virtio_devid++) {
		if (!is_virtio_dev_enabled(virtio_devid))
			continue;

		for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
			if ((lcore != default_wkr_core) &&
			    (lcore_vdev_vq_map[lcore].virt_q_map[virtio_devid])) {
				if (clear_virtio_q_config_on_default_core(lcore, virtio_devid))
					return -ENOTSUP;
			}
		}
	}
	return 0;
}

static void
dump_lcore_info(void)
{
	struct vc_cryptodev_deq_node_ctx *cryptodev_deq;
	struct vc_virtio_rx_node_ctx *virtio_rx;
	struct lcore_conf *qconf;
	uint32_t lcore_id;
	uint16_t i, q_id;
	uint64_t map;

	APP_INFO("\n");
	APP_INFO("Lcore info...\n");
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0 || lcore_id == rte_get_main_lcore())
			continue;

		qconf = &lcore_conf[lcore_id];
		if (!qconf->nb_crypto_deq && !qconf->nb_virtio_rx && !qconf->service_lcore)
			continue;

		if (qconf->service_lcore) {
			APP_INFO("\tService lcore %u\n", lcore_id);
			continue;
		}

		APP_INFO("\tRx queues on lcore %u ... ", lcore_id);
		fflush(stdout);

		map = 0;
		for (i = 0; i < qconf->nb_virtio_rx; i++) {
			virtio_rx = qconf->virtio_rx[i].virtio_rx;
#ifdef UNSELECT
			map = virtio_rx->virt_q_map;
#endif
			q_id = 0;
			while (map) {
				if (map & 0x1)
					APP_INFO_NH("virtio_rxq=%d,%d ", virtio_rx->virtio_devid,
						    q_id);
				q_id++;
				map = map >> 1;
			}
		}

		fflush(stdout);

		map = 0;
		for (i = 0; i < qconf->nb_crypto_deq; i++) {
			cryptodev_deq = qconf->crypto_deq[i].cryptodev_deq;
			map = cryptodev_deq->crypto_q_map;
			q_id = 0;
			while (map) {
				if (map & 0x1)
					APP_INFO_NH("crypto_deq=%d,%d ", cryptodev_deq->devid,
						    q_id);
				q_id++;
				map = map >> 1;
			}
		}
		APP_INFO_NH("\n");
	}
	APP_INFO("\n");
}

static void
clear_lcore_queue_mapping(uint16_t virtio_devid)
{
	struct vc_virtio_rx_node_ctx *virtio_rx;
	struct lcore_conf *qconf;
	uint32_t lcore_id;
	uint16_t i;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &lcore_conf[lcore_id];

		/* Skip Lcore if not needed */
		if (!qconf->nb_virtio_rx && !qconf->service_lcore)
			continue;

		for (i = 0; i < qconf->nb_virtio_rx; i++) {
			/* Check for matching virtio devid */
			if (qconf->virtio_rx[i].virtio_devid != virtio_devid)
				continue;

			/* Clear valid virtio queue map */
			virtio_rx = qconf->virtio_rx[i].virtio_rx;

			virtio_rx->virt_q_map = 0;
			virtio_rx->virt_q_count = 0;
		}

		if (qconf->nb_crypto_deq) {
			qconf->crypto_deq[0].cryptodev_deq->crypto_q_map = 0;
			qconf->crypto_deq[0].virtio_tx->cdev_vdev_map = NULL;
		}

		if (qconf->service_lcore) {
			qconf->virtio_queue_cnt[virtio_devid] = 0;
			qconf->virt_dev_map &= ~RTE_BIT64(virtio_devid);
		}
	}

	rte_io_wmb();
	dump_lcore_info();
}

static int
cryptodev_queues_flush(uint8_t virt_dev_id)
{
	struct rte_crypto_op *crypto_ops[VC_CRYPTODEV_DEQ_BURST_MAX];
	uint16_t cdev_id, cdev_qp_id, nb_dequeued, virt_q_id;
	struct dao_virtio_crypto_buffer *buf;
	struct rte_mempool *mempool = NULL;
	uint64_t start, wait;
	int q_cnt, rc, i;

	q_cnt = dao_virtio_cryptodev_data_queue_cnt_get(virt_dev_id);

	for (virt_q_id = 0; virt_q_id < q_cnt; virt_q_id++) {
		rc = dao_virtio_cryptodev_cdev_map_queue_get(virt_dev_id, virt_q_id, &cdev_id,
							     &cdev_qp_id, &mempool);

		if (rc != 0) {
			APP_ERR("Failed to get cryptodev queue mapping: dev=%d queue id: %d\n",
				virt_dev_id, virt_q_id);
			return rc;
		}

		start = rte_get_timer_cycles();
		wait = rte_get_timer_hz() / 100; /* 10ms*/

		/* Drain the queue here as the worker threads will not be picking the queue. */
		while (rte_cryptodev_qp_depth_used(cdev_id, cdev_qp_id) != 0) {
			nb_dequeued = rte_cryptodev_dequeue_burst(cdev_id, cdev_qp_id, crypto_ops,
								  RTE_DIM(crypto_ops));

			for (i = 0; i < nb_dequeued; i++) {
				buf = RTE_PTR_SUB(crypto_ops[i],
						  offsetof(struct dao_virtio_crypto_buffer, cop));
				rte_mempool_put(mempool, buf);
			}

			if ((rte_get_timer_cycles() - start) > wait) {
				APP_INFO(
					"Drain queue pair: %d cryptodev=%d nb_dequeued = %d, depth = %d\n",
					cdev_qp_id, cdev_id, nb_dequeued,
					rte_cryptodev_qp_depth_used(cdev_id, cdev_qp_id));
				return 0;
			}
		}
	}

	return 0;
}

static uint64_t
vc_sym_sess_create_cb(uint16_t cdev_id, struct rte_crypto_sym_xform *sym_xform)
{
	void *session = NULL;

	rte_errno = 0;

	session = rte_cryptodev_sym_session_create(cdev_id, sym_xform, vc_cdev_ctx.sym_sess_pool);
	if (rte_errno) {
		APP_ERR("Sym session create failed with errno: %d", rte_errno);
		return 0;
	}

	APP_INFO("Sym session: %lx created\n", (uint64_t)session);

	return (uint64_t)session;
}

static uint64_t
vc_asym_sess_create_cb(uint16_t cdev_id, struct rte_crypto_asym_xform *asym_xform)
{
	void *session = NULL;
	int ret;

	ret = rte_cryptodev_asym_session_create(cdev_id, asym_xform, vc_cdev_ctx.asym_sess_pool,
						&session);
	if (ret) {
		APP_ERR("Asym session create failed with errno: %d", ret);
		return 0;
	}

	APP_INFO("Asym session: %lx created\n", (uint64_t)session);

	return (uint64_t)session;
}

static void
vc_sym_sess_destroy_cb(uint16_t cdev_id, uint64_t session)
{
	rte_cryptodev_sym_session_free(cdev_id, (void *)session);
}

static void
vc_asym_sess_destroy_cb(uint16_t cdev_id, uint64_t session)
{
	rte_cryptodev_asym_session_free(cdev_id, (void *)session);
}

static int
setup_lcore_cryptodev_qp_config(struct lcore_conf *qconf, uint64_t virt_q_map,
				uint16_t virtio_devid)
{
	struct rte_mempool *mp = NULL;
	uint16_t cdev_qp_id, cdev_id;
	uint64_t q_map = virt_q_map;
	uint16_t queue_id = 0;
	int ret;

	while (q_map > 0) {
		queue_id = __builtin_ffsl(q_map);
		queue_id -= 1;

		ret = dao_virtio_cryptodev_cdev_map_queue_get(virtio_devid, queue_id, &cdev_id,
							      &cdev_qp_id, &mp);
		if (ret) {
			dao_info("[dev %u] No cryptodev queue mapped for queue %d", virtio_devid,
				 queue_id);
			return -ENOTSUP;
		}

		qconf->crypto_deq[0].cryptodev_deq->crypto_q_map |= RTE_BIT64(cdev_qp_id);
		q_map &= ~RTE_BIT64(queue_id);
	}
	return 0;
}

static int
setup_lcore_queue_mapping(uint16_t virtio_devid, uint16_t virt_q_count)
{
	uint8_t cdev_id = vc_cdev_ctx.enabled_primary_cdevs[0];
	struct lcore_conf *qconf;
	uint32_t lcore_id;
	uint64_t vq_map;
	int i;

	const struct dao_virtio_cryptodev_vdev_q *cdev_vdev_q_map =
		dao_virtio_cryptodev_cdev_map_all_queues_get(cdev_id);

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		qconf = &lcore_conf[lcore_id];

		/* Add virtio device to service lcore */
		if (qconf->service_lcore) {
			qconf->virt_dev_map |= RTE_BIT64(virtio_devid);
			qconf->virtio_queue_cnt[virtio_devid] = virt_q_count;
			APP_INFO("Added virtio_devid=%d (queue count: %d) to service lcore=%d\n",
				 virtio_devid, virt_q_count, lcore_id);
		}

		if (!qconf->nb_virtio_rx)
			continue;

		for (i = 0; i < qconf->nb_virtio_rx; i++) {
			/* Update only matching contexts */
			if (qconf->virtio_rx[i].virtio_devid != virtio_devid)
				continue;

			qconf->crypto_deq[0].virtio_tx->cdev_vdev_map = cdev_vdev_q_map;
			vq_map = lcore_vdev_vq_map[lcore_id].virt_q_map[virtio_devid];
			qconf->virtio_rx[i].virtio_rx->virt_q_map = vq_map;

			if (setup_lcore_cryptodev_qp_config(qconf, vq_map, virtio_devid))
				return -ENOTSUP;
		}
	}
	return 0;
}

static int
vc_status_cb(uint16_t virtio_devid, uint8_t status)
{
	bool reset_cryptodev = false;
	uint16_t virt_q_count;
	int rc;

	APP_INFO("virtio_dev=%d: status=%s\n", virtio_devid, dao_virtio_dev_status_to_str(status));

	switch (status) {
	case VIRTIO_DEV_RESET:
	case VIRTIO_DEV_NEEDS_RESET:
		clear_lcore_queue_mapping(virtio_devid);
		reset_cryptodev = true;
		break;
	case VIRTIO_DEV_DRIVER_OK:
		virt_q_count = dao_virtio_cryptodev_data_queue_cnt_get(virtio_devid);
		rc = setup_lcore_queue_mapping(virtio_devid, virt_q_count);
		if (rc)
			APP_ERR("virtio_dev=%d: failed to setup lcore queue mapping, rc=%d\n",
				virtio_devid, rc);
		break;
	default:
		break;
	};

	/* Synchronize RCU */
	rte_rcu_qsbr_synchronize(qs_v, RTE_QSBR_THRID_INVALID);

	/* After this point, all the cores see updated queue mapping */

	if (reset_cryptodev)
		cryptodev_queues_flush(virtio_devid);

	return 0;
}

static void
setup_virtio_device(void)
{
	struct dao_virtio_cryptodev_cbs cbs;
	uint16_t virtio_devid;
	int rc;

	/* Initialize virtio crypto device */
	for (virtio_devid = 0; virtio_devid < DAO_VIRTIO_DEV_MAX; virtio_devid++) {
		struct dao_virtio_cryptodev_conf cryptodev_conf;

		if (!is_virtio_dev_enabled(virtio_devid))
			continue;

		/* Populate cryptodev conf */
		memset(&cryptodev_conf, 0, sizeof(cryptodev_conf));
		cryptodev_conf.pem_devid = pem_devid;
		cryptodev_conf.dma_vchan = virtio_cryptodev_dma_vchans[virtio_devid];
		/* FIXME: this need to be saved differently. */
		cryptodev_conf.pool = vc_cdev_ctx.qp_pool[0];

		cryptodev_conf.cdev_id = vc_cdev_ctx.enabled_primary_cdevs[0];

		/* Initialize virtio crypto device */
		rc = dao_virtio_cryptodev_init(virtio_devid, &cryptodev_conf);
		if (rc)
			rte_exit(EXIT_FAILURE, "Failed to init virtio device\n");
	}

	memset(&cbs, 0, sizeof(cbs));
	cbs.status_cb = vc_status_cb;
	cbs.sym_sess_create_cb = vc_sym_sess_create_cb;
	cbs.asym_sess_create_cb = vc_asym_sess_create_cb;
	cbs.sym_sess_destroy_cb = vc_sym_sess_destroy_cb;
	cbs.asym_sess_destroy_cb = vc_asym_sess_destroy_cb;
	dao_virtio_cryptodev_cb_register(&cbs);
}

static int
graph_node_init(void)
{
	uint16_t virtio_devid, cryptodev_id;
	struct rte_node_register *node_reg;
	char name[RTE_NODE_NAMESIZE];
	const char *edge_name = name;
	rte_node_t node;
	int rc;

	/* Assumption: only 1 cryptodev is used as primary device. */
	if (vc_cdev_ctx.nb_primary_cryptodevs != 1)
		APP_ERR("Only 1 primary cryptodev is mapped\n");

	cryptodev_id = vc_cdev_ctx.enabled_primary_cdevs[0];

	/*
	 * Setup virtio-Rx nodes per virtio-dev
	 * Connect virtio-Rx node to cryptodev enqueue.
	 */

	for (virtio_devid = 0; virtio_devid < DAO_VIRTIO_DEV_MAX; virtio_devid++) {
		/* Clone virtio Rx per virtio-dev */
		snprintf(name, sizeof(name), "%u", virtio_devid);
		node_reg = vc_virtio_rx_node_get();
		node = rte_node_clone(node_reg->id, name);
		if (node == RTE_NODE_ID_INVALID) {
			APP_ERR("Could not clone virtio Rx node\n");
			return -EINVAL;
		}

		virtio_rx_nodes[virtio_devid] = node;

		/* Update graph edge info for virtio Rx nodes */
		snprintf(name, sizeof(name), "vc_cryptodev_enq-%u", cryptodev_id);
		rc = rte_node_edge_update(virtio_rx_nodes[virtio_devid], RTE_EDGE_ID_INVALID,
					  &edge_name, 1);
		if (rc == RTE_EDGE_ID_INVALID) {
			APP_ERR("Could not update edge info for virtio Rx node\n");
			return -EINVAL;
		}
	}

	/*
	 * Setup cryptodev enqueue-dequeue nodes for cryptodev.
	 * Connect cryptodev-dequeue to virtio-Tx node.
	 */

	/* Clone cryptodev nodes for this cryptodev */
	snprintf(name, sizeof(name), "%u", cryptodev_id);

	node_reg = vc_cryptodev_enq_node_get();
	node = rte_node_clone(node_reg->id, name);
	if (node == RTE_NODE_ID_INVALID) {
		APP_ERR("Could not clone cryptodev enqueue node\n");
		return -EINVAL;
	}
	cryptodev_enq_node = node;

	node_reg = vc_cryptodev_deq_node_get();
	node = rte_node_clone(node_reg->id, name);
	if (node == RTE_NODE_ID_INVALID) {
		APP_ERR("Could not clone cryptodev dequeue node\n");
		return -EINVAL;
	}
	cryptodev_deq_node = node;

	/* Update graph edge info for cryptodev dequeue nodes. */
	snprintf(name, sizeof(name), "vc_virtio_tx");
	rc = rte_node_edge_update(cryptodev_deq_node, RTE_EDGE_ID_INVALID, &edge_name, 1);
	if (rc == RTE_EDGE_ID_INVALID) {
		APP_ERR("Could not update edge info for cryptodev dequeue node\n");
		return -EINVAL;
	}

	node = rte_node_from_name(name);
	if (node == RTE_NODE_ID_INVALID) {
		APP_ERR("Could not find virtio Tx node\n");
		return -EINVAL;
	}
	virtio_tx_node = node;

	return 0;
}

static void
release_virtio_devices(void)
{
	uint32_t virtio_devid = 0;
	int rc;

	rc = dao_virtio_cryptodev_fini(virtio_devid);
	if (rc)
		printf("Failed to stop virtio device %u: %d\n", virtio_devid, rc);
}

static __rte_always_inline uint16_t
vc_virtio_desc_process(uint64_t virt_dev_map, uint16_t *virtio_queue_cnt)
{
	uint16_t dev_id = 0;

	while (virt_dev_map) {
		if (!(virt_dev_map & 0x1)) {
			virt_dev_map >>= 1;
			dev_id++;
			continue;
		}
		dao_virtio_crypto_desc_manage(dev_id, virtio_queue_cnt[dev_id]);
		virt_dev_map >>= 1;
		dev_id++;
	}

	return 0;
}

static int
service_main_loop(void *conf)
{
	struct rte_rcu_qsbr *qs_v;
	struct lcore_conf *qconf;
	uint32_t lcore_id;
	int rc;

	RTE_SET_USED(conf);

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];
	qs_v = qconf->qs_v;

	/* Set per lcore DMA device id */
	rc = dao_dma_lcore_dev2mem_set(qconf->dev2mem_id, qconf->nb_vchans, dma_flush_thr);
	rc |= dao_dma_lcore_mem2dev_set(qconf->mem2dev_id, qconf->nb_vchans, dma_flush_thr);
	if (rc) {
		APP_ERR("Error in setting DMA device on lcore\n");
		return -1;
	}

	/* Register this thread to report quiescent state */
	rte_rcu_qsbr_thread_register(qs_v, lcore_id);
	rte_rcu_qsbr_thread_online(qs_v, lcore_id);

	APP_INFO("Entering service main loop on lcore %u\n", lcore_id);

	while (likely(!force_quit)) {
		/* Process virtio descriptors */
		vc_virtio_desc_process(qconf->virt_dev_map, qconf->virtio_queue_cnt);

		/* Flush and submit DMA ops */
		dao_dma_flush_submit();

		/* Update quiescent state */
		rte_rcu_qsbr_quiescent(qs_v, lcore_id);
	}

	rte_rcu_qsbr_thread_offline(qs_v, lcore_id);
	rte_rcu_qsbr_thread_unregister(qs_v, lcore_id);
	return 0;
}

static int
graph_main_loop(void *conf)
{
	struct rte_rcu_qsbr *qs_v;
	struct lcore_conf *qconf;
	struct rte_graph *graph;
	uint32_t lcore_id;
	int rc;

	RTE_SET_USED(conf);

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];
	qs_v = qconf->qs_v;
	graph = qconf->graph;

	if (!graph) {
		APP_INFO("Lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	/* Set per lcore DMA device id */
	rc = dao_dma_lcore_dev2mem_set(qconf->dev2mem_id, qconf->nb_vchans, dma_flush_thr);
	rc |= dao_dma_lcore_mem2dev_set(qconf->mem2dev_id, qconf->nb_vchans, dma_flush_thr);
	if (rc) {
		APP_ERR("Error in setting DMA device on lcore\n");
		return -1;
	}

	/* Register this thread to rdaort quiescent state */
	rte_rcu_qsbr_thread_register(qs_v, lcore_id);
	rte_rcu_qsbr_thread_online(qs_v, lcore_id);

	APP_INFO("Entering graph main loop on lcore %u, %s(%p)\n", lcore_id, qconf->name, graph);

	while (likely(!force_quit)) {
		/* Walk through graph */
		rte_graph_walk(graph);

		/* Flush and submit DMA ops */
		dao_dma_flush_submit();

		/* Update quiescent state */
		rte_rcu_qsbr_quiescent(qs_v, lcore_id);
	}

	rte_rcu_qsbr_thread_offline(qs_v, lcore_id);
	rte_rcu_qsbr_thread_unregister(qs_v, lcore_id);
	return 0;
}

int
main(int argc, char **argv)
{
	static const char *const default_patterns[] = {
		"cop_drop",
	};
	bool default_lcore_wkr_flag = false;
	struct rte_graph_param graph_conf;
	bool service_lcore_flag = false;
	bool is_lcore_used = false;
	const char **node_patterns;
	struct lcore_conf *qconf;
	struct rte_node *node;
	uint16_t nb_patterns;
	rte_node_t node_id;
	uint32_t lcore_id;
	uint32_t devid;
	size_t sz;
	int rc, i;

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

	if (check_crypto_config() < 0)
		rte_exit(EXIT_FAILURE, "check_crypto_config() failed\n");

	/* Pick one lcore for default worker core */
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0 || lcore_id == rte_get_main_lcore())
			continue;
		is_lcore_used = false;

		for (i = 0; i < DAO_VIRTIO_DEV_MAX; ++i) {
			if (!is_virtio_dev_enabled(i))
				continue;
			if ((RTE_BIT64(lcore_id) & lcore_virtio_mask[i])) {
				is_lcore_used = true;
				break;
			}
		}
		if (!is_lcore_used) {
			vc_cdev_ctx.default_worker_lcore = lcore_id;
			default_lcore_wkr_flag = true;
			break;
		}
	}

	if (!default_lcore_wkr_flag)
		rte_exit(EXIT_FAILURE, "LCORE not available for default worker lcore\n");

	if (init_lcore_virtio_rx() < 0)
		rte_exit(EXIT_FAILURE, "Failed to init lcore virtio rx\n");

	if (check_virtio_config() < 0)
		rte_exit(EXIT_FAILURE, "check_virtio_config() failed\n");

	dao_virtio_cryptodev_common_cfg_init();

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0 || lcore_id == rte_get_main_lcore())
			continue;

		/* Pick one non FP lcore for misc */
		if (lcore_conf[lcore_id].nb_virtio_rx == 0 &&
		    lcore_conf[lcore_id].nb_crypto_deq == 0) {
			lcore_conf[lcore_id].service_lcore = true;
			service_lcore_flag = true;
			break;
		}
	}

	if (!service_lcore_flag)
		rte_exit(EXIT_FAILURE, "LCORE not available for service lcore\n");

	/* Allocate crypto op pool */
	setup_mempools();

	/* Initialize DMA device */
	setup_dma_devices();

	/* Initialize PEM device */
	setup_pem_device();

	/* Initialize crypto devices */
	rc = setup_crypto_devices();
	if (rc)
		rte_exit(EXIT_FAILURE, "Could not setup crypto devices\n");

	/* Setup RCU QSBR variable */
	sz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
	qs_v = (struct rte_rcu_qsbr *)rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
							 SOCKET_ID_ANY);
	if (!qs_v)
		rte_exit(EXIT_FAILURE, "Failed to alloc rcu_qsbr variable\n");

	rc = rte_rcu_qsbr_init(qs_v, RTE_MAX_LCORE);
	if (rc)
		rte_exit(EXIT_FAILURE, "rte_rcu_qsbr_init(): failed to init, rc=%d\n", rc);

	/* Initialize virtio devices */
	setup_virtio_device();

	if (setup_lcore_virtio_queue_config() < 0)
		rte_exit(EXIT_FAILURE, "init_lcore_virtio_queue_config() failed\n");

	/* Initialize graph nodes */
	rc = graph_node_init();
	if (rc)
		rte_exit(EXIT_FAILURE, "Could not init graph nodes\n");

	/* Graph Initialization */
	nb_patterns = RTE_DIM(default_patterns);
	node_patterns =
		malloc((MAX_VIRTIO_RX_PER_LCORE + MAX_VIRTIO_CRYPTO_DEQ_PER_LCORE + nb_patterns) *
		       sizeof(*node_patterns));
	if (!node_patterns)
		return -ENOMEM;
	memcpy(node_patterns, default_patterns, nb_patterns * sizeof(*node_patterns));

	memset(&graph_conf, 0, sizeof(graph_conf));
	graph_conf.node_patterns = node_patterns;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		rte_graph_t graph_id;
		rte_edge_t i;

		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		qconf = &lcore_conf[lcore_id];

		/* Skip Lcore if not needed */
		if (!qconf->nb_virtio_rx && !qconf->nb_crypto_deq && !qconf->service_lcore)
			continue;

		qconf->qs_v = qs_v;
		if (qconf->service_lcore)
			continue;

		nb_patterns = RTE_DIM(default_patterns);
		snprintf(qconf->name, sizeof(qconf->name), "worker_%u", lcore_id);

		/* Add virtio rx node pattern of this lcore */
		for (i = 0; i < qconf->nb_virtio_rx; i++)
			graph_conf.node_patterns[nb_patterns + i] = qconf->virtio_rx[i].node_name;
		nb_patterns += i;

		for (i = 0; i < qconf->nb_crypto_deq; i++)
			graph_conf.node_patterns[nb_patterns + i] = qconf->crypto_deq[i].node_name;
		nb_patterns += i;

		graph_conf.nb_node_patterns = nb_patterns;
		graph_conf.socket_id = rte_lcore_to_socket_id(lcore_id);

		graph_id = rte_graph_create(qconf->name, &graph_conf);
		if (graph_id == RTE_GRAPH_ID_INVALID)
			rte_exit(EXIT_FAILURE, "Could not create graph for lcore %u\n", lcore_id);

		qconf->graph_id = graph_id;
		qconf->graph = rte_graph_lookup(qconf->name);
		if (qconf->graph == NULL)
			rte_exit(EXIT_FAILURE, "Could not lookup graph: %s\n", qconf->name);

		for (i = 0; i < qconf->nb_virtio_rx; i++) {
			devid = qconf->virtio_rx[i].virtio_devid;

			/* Virtio Rx ctx */
			node_id = virtio_rx_nodes[devid];
			node = rte_graph_node_get(graph_id, node_id);
			qconf->virtio_rx[i].virtio_rx = (struct vc_virtio_rx_node_ctx *)node->ctx;
			qconf->virtio_rx[i].virtio_rx->virtio_devid = devid;

			/* Cryptodev enq CTX. CTX is the same but associate with all virtio_rx
			 * members */
			node_id = cryptodev_enq_node;
			node = rte_graph_node_get(graph_id, node_id);
			qconf->virtio_rx[i].cryptodev_enq =
				(struct vc_cryptodev_enq_node_ctx *)node->ctx;
			qconf->virtio_rx[i].cryptodev_enq->devid =
				vc_cdev_ctx.enabled_primary_cdevs[0];
		}

		for (i = 0; i < qconf->nb_crypto_deq; i++) {
			devid = qconf->crypto_deq[i].devid;

			/* Cryptodev deq ctx */
			node_id = cryptodev_deq_node;
			node = rte_graph_node_get(graph_id, node_id);
			qconf->crypto_deq[i].cryptodev_deq =
				(struct vc_cryptodev_deq_node_ctx *)node->ctx;
			qconf->crypto_deq[i].cryptodev_deq->devid = devid;

			/* Virtio Tx CTX */
			node_id = virtio_tx_node;
			node = rte_graph_node_get(graph_id, node_id);
			qconf->crypto_deq[i].virtio_tx = (struct vc_virtio_tx_node_ctx *)node->ctx;
		}
	}

	APP_INFO("\n");

	/* Launch per lcore service and worker threads */
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		qconf = &lcore_conf[lcore_id];

		if (qconf->service_lcore)
			rte_eal_remote_launch(service_main_loop, NULL, lcore_id);
		else if (qconf->graph)
			rte_eal_remote_launch(graph_main_loop, qconf, lcore_id);
	}

	/* Wait for worker cores to exit */
	rc = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		rc = rte_eal_wait_lcore(lcore_id);
		/* Destroy graph */
		if (rc < 0 || rte_graph_destroy(rte_graph_from_name(lcore_conf[lcore_id].name))) {
			rc = -1;
			break;
		}
	}
	free(node_patterns);

	release_virtio_devices();

	release_crypto_devices();

	release_pem_device();

	release_dma_devices();

	mempools_release();

	rte_eal_cleanup();

	return rc;
}
