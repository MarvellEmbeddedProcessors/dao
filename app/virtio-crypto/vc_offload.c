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

#define MAX_VIRTIO_RX_PER_LCORE         128
#define MAX_VIRTIO_CRYPTO_DEQ_PER_LCORE 1

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

	uint16_t nb_virtio_rx;
	struct lcore_virtio_rx virtio_rx[MAX_VIRTIO_RX_PER_LCORE];
	uint16_t nb_crypto_deq;
	struct lcore_crypto_deq crypto_deq[MAX_VIRTIO_CRYPTO_DEQ_PER_LCORE];

	bool service_lcore;
	int dev2mem_id;
	int mem2dev_id;
	int nb_vchans;
} __rte_cache_aligned;

static struct lcore_conf lcore_conf[RTE_MAX_LCORE];

static struct vc_cdev_ctx vc_cdev_ctx;

static volatile bool force_quit;

static int16_t dev2mem_ids[32];
static int16_t mem2dev_ids[32];
static uint16_t dev2mem_cnt;
static uint16_t mem2dev_cnt;
static int wrkr_dma_devs;

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
		qp_conf.nb_descriptors = VC_NB_DESC_DEFAULT;

		for (j = 0; j < conf.nb_queue_pairs; j++) {
			ret = rte_cryptodev_queue_pair_setup(dev_id, j, &qp_conf, socket_id);
			if (ret) {
				APP_ERR("Could not setup queue [cryptodev: %d, queue pair: %d].",
					dev_id, j);
				goto free_asym_sess_pool;
			}
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
		rte_cryptodev_stop(dev_id);
		rte_cryptodev_close(dev_id);
	}

	rte_mempool_free(vc_cdev_ctx.asym_sess_pool);
	vc_cdev_ctx.asym_sess_pool = NULL;

	rte_mempool_free(vc_cdev_ctx.sym_sess_pool);
	vc_cdev_ctx.sym_sess_pool = NULL;

	vc_cdev_ctx.nb_primary_cryptodevs = 0;
}

static void
setup_virtio_device(void)
{
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

int
main(int argc, char **argv)
{
	bool service_lcore_flag = false;
	uint32_t lcore_id;
	size_t sz;
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

	if (check_crypto_config() < 0)
		rte_exit(EXIT_FAILURE, "check_crypto_config() failed\n");

	if (init_lcore_virtio_rx() < 0)
		rte_exit(EXIT_FAILURE, "Failed to init lcore virtio rx\n");

	if (check_virtio_config() < 0)
		rte_exit(EXIT_FAILURE, "check_virtio_config() failed\n");

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

	/* Initialize graph nodes */
	rc = graph_node_init();
	if (rc)
		rte_exit(EXIT_FAILURE, "Could not init graph nodes\n");

	release_virtio_devices();

	release_crypto_devices();

	release_pem_device();

	release_dma_devices();

	mempools_release();

	rte_eal_cleanup();

	return rc;
}
