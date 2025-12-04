/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <string.h>

#include <rte_bitmap.h>
#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include <dao_eth_trs.h>
#include <dao_liquid_crypto.h>
#include <dao_log.h>

#include "hw/cpt.h"
#include "liquid_crypto_asym.h"
#include "liquid_crypto_debug.h"
#include "liquid_crypto_op_defines.h"
#include "liquid_crypto_priv.h"
#include "liquid_crypto_sym.h"
#include "liquid_crypto_trs.h"
#include "mc/ae.h"
#include "mc/se.h"

#include "dao_card_grpc_client.h"
#include "dao_lc_grpc_client.h"

static struct dao_lc_info lc_info;

static struct liquid_crypto_dev liquid_crypto_devs[DAO_CRYPTO_MAX_NB_DEV];

/** Forward declarations */
static int liquid_crypto_qp_free(uint8_t dev_id, uint16_t qp_id);

static struct dao_lc_grpc_ctx *lc_ctx;

int
dao_liquid_crypto_init(void)
{
	struct dao_eth_trs_info trs_info;
	int rc, i;

	memset(&lc_info, 0, sizeof(lc_info));
	memset(liquid_crypto_devs, 0, sizeof(liquid_crypto_devs));

	lc_ctx = dao_lc_grpc_client_init("192.168.1.1", 50051);
	if (lc_ctx == NULL) {
		dao_err("Could not initialize card grpc client.");
		return -EINVAL;
	}

	rc = dao_eth_trs_init();
	if (rc != 0) {
		dao_err("Could not initialize ethernet transport.");
		goto lc_fini;
	}

	rc = dao_eth_trs_info(&trs_info);
	if (rc != 0) {
		dao_err("Could not get ethernet transport information.");
		goto trs_fini;
	}

	if (trs_info.nb_devs > DAO_CRYPTO_MAX_NB_DEV) {
		dao_err("[Internal error] Number of devices exceeds the maximum supported.");
		rc = -EINVAL;
		goto trs_fini;
	}

	if (trs_info.nb_queues > LIQUID_CRYPTO_MAX_NB_QP) {
		dao_err("[Internal error] Number of queues exceeds the maximum supported.");
		rc = -EINVAL;
		goto trs_fini;
	}

	strncpy(lc_info.version, DAO_LC_VERSION, sizeof(lc_info.version) - 1);
	lc_info.version[sizeof(lc_info.version) - 1] = '\0';
	lc_info.nb_dev = trs_info.nb_devs;

	for (i = 0; i < trs_info.nb_devs; i++)
		lc_info.nb_qp[i] = trs_info.nb_queues;

	return 0;

trs_fini:
	dao_eth_trs_fini();
lc_fini:
	dao_lc_grpc_client_fini(lc_ctx);
	lc_ctx = NULL;
	return rc;
}

int
dao_liquid_crypto_fini(void)
{
	int i, rc;

	for (i = 0; i < lc_info.nb_dev; i++) {
		if (liquid_crypto_devs[i].is_created)
			dao_liquid_crypto_dev_destroy(i);
	}

	rc = dao_eth_trs_fini();
	if (rc != 0) {
		dao_err("Could not finalize ethernet transport.");
		return rc;
	}

	dao_lc_grpc_client_fini(lc_ctx);
	lc_ctx = NULL;

	memset(liquid_crypto_devs, 0, sizeof(liquid_crypto_devs));
	memset(&lc_info, 0, sizeof(lc_info));

	return 0;
}

int
dao_liquid_crypto_info_get(struct dao_lc_info *info)
{
	if (info == NULL) {
		dao_err("Invalid argument.");
		return -EINVAL;
	}

	memcpy(info, &lc_info, sizeof(lc_info));

	return 0;
}

int
dao_liquid_crypto_dev_create(struct dao_lc_dev_conf *conf)
{
	struct dao_eth_trs_port_info *port_info;
	struct dao_eth_trs_dev_config trs_conf;
	struct liquid_crypto_dev *dev;
	uint16_t nb_qp, cmd_qp_idx;
	uint8_t dev_id;
	uint32_t i;
	int rc;

	if (conf == NULL) {
		dao_err("Invalid argument.");
		return -EINVAL;
	}

	cmd_qp_idx = conf->cmd_qp_idx;
	dev_id = conf->dev_id;
	nb_qp = conf->nb_qp;

	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}

	if (nb_qp == 0 || nb_qp > lc_info.nb_qp[dev_id]) {
		dao_err("Invalid argument. nb_qp must be between 1 and %u.", lc_info.nb_qp[dev_id]);
		return -EINVAL;
	}

	if (cmd_qp_idx != DAO_CMD_QP_IDX_INVALID && cmd_qp_idx >= nb_qp) {
		dao_err("Invalid argument. cmd_qp_idx must be between 0 and %u.", nb_qp - 1);
		return -EINVAL;
	}

	dev = &liquid_crypto_devs[dev_id];

	if (dev->is_destroyed) {
		dao_err("Device already destroyed. Cannot be created again.");
		return -EINVAL;
	}

	if (dev->is_created) {
		dao_err("Device already created.");
		return -EEXIST;
	}

	dev->nb_qp = nb_qp;
	dev->cmd_qp_idx = cmd_qp_idx;

	trs_conf.nb_queues = nb_qp;
	trs_conf.promiscuous = 1;

	rc = dao_eth_trs_dev_alloc(dev_id, &trs_conf);
	if (rc != 0) {
		dao_err("Could not allocate ethernet transport device.");
		return rc;
	}

	port_info = &dev->port_info;
	if (dao_eth_trs_port_info_get(dev_id, port_info) != 0) {
		dao_err("Failed to get port info");
		goto dev_free;
	}

	for (i = 0; i < port_info->nb_ports; i++) {
		int num_queues = port_info->nb_queues;

		if (i == port_info->nb_ports - 1)
			num_queues = nb_qp - i * port_info->nb_queues;

		rc = dao_lc_ethdev_create(lc_ctx, port_info->oct_dev_id[i], num_queues);
		if (rc != 0) {
			dao_err("Could not create card device.");
			goto lc_eth_dev_destroy;
		}
	}

	dev->nb_ports = port_info->nb_ports;
	dev->is_created = true;

	return 0;

lc_eth_dev_destroy:
	for (int j = i - 1; j >= 0; j--)
		dao_lc_ethdev_destroy(lc_ctx, port_info->oct_dev_id[j]);
dev_free:
	dao_eth_trs_dev_free(dev_id);
	return rc;
}

int
dao_liquid_crypto_dev_destroy(uint8_t dev_id)
{
	struct liquid_crypto_dev *dev;
	int rc, i;

	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}

	dev = &liquid_crypto_devs[dev_id];

	if (dev->is_created) {
		for (i = 0; i < dev->nb_ports; i++) {
			struct dao_eth_trs_port_info *port_info = &dev->port_info;

			rc = dao_lc_ethdev_destroy(lc_ctx, port_info->oct_dev_id[i]);
			if (rc != 0) {
				dao_err("Could not destroy card device.");
				return rc;
			}
		}
	}

	rc = dao_eth_trs_dev_free(dev_id);
	if (rc != 0) {
		dao_err("Could not free ethernet transport device.");
		return rc;
	}

	if (dev->is_created) {
		for (i = 0; i < dev->nb_qp; i++) {
			rc = liquid_crypto_qp_free(dev_id, i);
			if (rc != 0)
				dao_err("Could not destroy queue pair (%d. %d)", dev_id, i);
		}
	}

	memset(dev, 0, sizeof(*dev));

	dev->is_destroyed = true;
	dev->is_created = false;

	return 0;
}

int
dao_liquid_crypto_qp_configure(uint8_t dev_id, uint16_t qp_id, struct dao_lc_qp_conf *conf)
{
	struct dao_eth_trs_queue_config trs_queue_conf;
	uint16_t nb_desc, max_seg_size, desc_watermark;
	struct dao_lc_eth_qconf card_qp_conf;
	struct dao_eth_trs_info trs_info;
	uint16_t min_seg_sz, max_seg_sz;
	char name[RTE_MEMZONE_NAMESIZE];
	uint32_t oct_dev_id, oct_qp_id;
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	struct rte_mempool *mp;
	uint32_t bm_mem_size;
	unsigned int pool_sz;
	int rc, size;

	if (conf == NULL) {
		dao_err("Invalid argument.");
		return -EINVAL;
	}

	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}

	memset(&trs_queue_conf, 0, sizeof(trs_queue_conf));

	rc = dao_eth_trs_info(&trs_info);
	if (rc != 0) {
		dao_err("Could not get ethernet transport information.");
		return rc;
	}

	if (conf->nb_desc < trs_info.min_queue_size || conf->nb_desc > trs_info.max_queue_size) {
		dao_err("Invalid argument. nb_desc must be between %u and %u.",
			trs_info.min_queue_size, trs_info.max_queue_size);
		return -EINVAL;
	}

	/*
	 * Increase the min seg size to include headroom. Eth dev library validates buffer size
	 * including headroom.
	 */
	min_seg_sz = RTE_MAX(trs_info.min_buf_len + RTE_PKTMBUF_HEADROOM, LIQUID_CRYPTO_SEG_SZ_MIN);
	max_seg_sz = RTE_MIN(trs_info.max_pkt_len, LIQUID_CRYPTO_BUF_SZ_MAX);

	if (conf->max_seg_size < min_seg_sz || conf->max_seg_size > max_seg_sz) {
		dao_err("Invalid argument. max_seg_size must be between %u and %u.", min_seg_sz,
			max_seg_sz);
		return -EINVAL;
	}

	if (trs_info.min_buf_len > LIQUID_CRYPTO_BUF_SZ_MIN) {
		dao_err("[Internal error] Minimum buffer length exceeds the supported value.");
		return -EINVAL;
	}

	if (conf->max_seg_size > LIQUID_CRYPTO_BUF_SZ_MAX) {
		dao_err("Maximum segment size (%u) exceeds the supported value %llu.",
			conf->max_seg_size, LIQUID_CRYPTO_BUF_SZ_MAX);
		return -EINVAL;
	}

	dev = &liquid_crypto_devs[dev_id];

	if (!dev->is_created) {
		dao_err("Invalid device. Device(%d) not created.", dev_id);
		return -EINVAL;
	}

	if (qp_id >= dev->nb_qp) {
		dao_err("Invalid argument. qp_id must be between 0 and %u.", dev->nb_qp - 1);
		return -EINVAL;
	}

	snprintf(name, sizeof(name), "lc_qp_%hhu_%hu", dev_id, qp_id);

	qp = rte_zmalloc(name, sizeof(*qp), 0);
	if (qp == NULL) {
		dao_err("could not allocate memory.");
		return -ENOMEM;
	}

	/* Align to the next power of 2 to simplify datapath checks */
	nb_desc = rte_align32pow2(conf->nb_desc);

	max_seg_size = conf->max_seg_size;

	snprintf(name, sizeof(name), "lc_rx_mp_%hhu_%hu", dev_id, qp_id);

	/*
	 * Create Rx & Tx pools. To allow for some packets inflight and since mempool_alloc is
	 * optimal in terms of memory when using 2^q - 1, increase the Rx pool size.
	 */
	pool_sz = 2 * nb_desc - 1;

	mp = rte_pktmbuf_pool_create(
		name, pool_sz, RTE_MEMPOOL_CACHE_MAX_SIZE, 0,
		max_seg_size + RTE_PKTMBUF_HEADROOM + LIQUID_CRYPTO_BUF_SDP_DATA_LEN_SZ, 0);
	if (mp == NULL) {
		dao_err("Could not create Rx mbuf pool.");
		rc = -ENOMEM;
		goto qp_free;
	}

	qp->rx_mp = mp;

	snprintf(name, sizeof(name), "lc_tx_mp_%hhu_%hu", dev_id, qp_id);

	mp = rte_pktmbuf_pool_create(name, pool_sz, RTE_MEMPOOL_CACHE_MAX_SIZE, 0,
				     max_seg_size + RTE_PKTMBUF_HEADROOM, 0);
	if (mp == NULL) {
		dao_err("Could not create Tx mbuf pool.");
		rc = -ENOMEM;
		goto rx_mp_free;
	}

	qp->tx_mp = mp;

	snprintf(name, sizeof(name), "lc_req_q_%hhu_%hu", dev_id, qp_id);
	size = nb_desc * sizeof(struct liquid_crypto_inflight_req);

	qp->req_queue = rte_zmalloc(name, size, 0);
	if (qp->req_queue == NULL) {
		dao_err("Could not allocate memory for request queue.");
		rc = -ENOMEM;
		goto tx_mp_free;
	}

	trs_queue_conf.rx_mp = qp->rx_mp;
	trs_queue_conf.queue_size = nb_desc;
	rc = dao_eth_trs_dev_queue_configure(dev_id, qp_id, &trs_queue_conf);
	if (rc != 0) {
		dao_err("Could not configure ethernet transport queue.");
		goto req_queue_free;
	}

	rc = dao_eth_trs_dev_queue_map(dev_id, qp_id, &qp->port_id, &qp->queue_id);
	if (rc != 0) {
		dao_err("Could not map ethernet transport queue.");
		goto req_queue_free;
	}

	/* Configure inflight request bitmap to prevent exceeding SDP watermark threshold */
	desc_watermark = nb_desc / 8;
	bm_mem_size = rte_bitmap_get_memory_footprint(nb_desc - desc_watermark);
	if (bm_mem_size == 0) {
		dao_err("Could not get memory footprint for bitmap.");
		rc = -EINVAL;
		goto req_queue_free;
	}

	snprintf(name, sizeof(name), "liquid_crypto_bm_%hhu_%hu", dev_id, qp_id);
	qp->req_bm_mem = rte_zmalloc(name, bm_mem_size, 0);
	if (qp->req_bm_mem == NULL) {
		dao_err("Could not allocate memory for bitmap.");
		rc = -ENOMEM;
		goto req_queue_free;
	}

	qp->req_bm =
		rte_bitmap_init_with_all_set(nb_desc - desc_watermark, qp->req_bm_mem, bm_mem_size);
	if (qp->req_bm == NULL) {
		dao_err("Could not initialize bitmap.");
		rc = -EINVAL;
		goto bm_mem_free;
	}

	qp->req_bm_size = nb_desc - desc_watermark;

	if (qp_id == dev->cmd_qp_idx) {
		snprintf(name, sizeof(name), "liquid_crypto_cmd_bm_%hhu_%hu", dev_id, qp_id);
		qp->cmd_req_bm_mem = rte_zmalloc(name, bm_mem_size, 0);
		if (qp->cmd_req_bm_mem == NULL) {
			dao_err("Could not allocate memory for command queue bitmap.");
			rc = -ENOMEM;
			goto bitmap_free;
		}

		qp->cmd_req_bm = rte_bitmap_init_with_all_set(nb_desc - desc_watermark,
							      qp->cmd_req_bm_mem, bm_mem_size);
		if (qp->cmd_req_bm == NULL) {
			dao_err("Could not initialize command queue bitmap.");
			rc = -EINVAL;
			goto cmd_bm_mem_free;
		}

		rte_bitmap_reset(qp->req_bm);
	}

	oct_qp_id = qp_id % dev->port_info.nb_queues;
	oct_dev_id = dev->port_info.oct_dev_id[(qp_id / dev->port_info.nb_queues)];

	memset(&card_qp_conf, 0, sizeof(card_qp_conf));
	card_qp_conf.dev_id = oct_dev_id;
	card_qp_conf.qp_id = oct_qp_id;
	card_qp_conf.nb_desc = nb_desc;
	card_qp_conf.max_seg_size = conf->max_seg_size;
	card_qp_conf.out_of_order_delivery_en = conf->out_of_order_delivery_en;

	rc = dao_lc_ethdev_queue_configure(lc_ctx, &card_qp_conf);
	if (rc != 0) {
		dao_err("Could not configure card queue.");
		goto cmd_bm_mem_free;
	}

	dev->qp[qp_id] = qp;

	return 0;

cmd_bm_mem_free:
	if (qp_id == dev->cmd_qp_idx)
		rte_free(qp->cmd_req_bm_mem);

bitmap_free:
	rte_bitmap_free(qp->req_bm);

bm_mem_free:
	rte_free(qp->req_bm_mem);

req_queue_free:
	rte_free(qp->req_queue);

tx_mp_free:
	rte_mempool_free(qp->tx_mp);

rx_mp_free:
	rte_mempool_free(qp->rx_mp);

qp_free:
	rte_free(qp);
	return rc;
}

static int
liquid_crypto_qp_free(uint8_t dev_id, uint16_t qp_id)
{
	uint32_t oct_dev_id, oct_qp_id;
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	int rc = 0;

	dev = &liquid_crypto_devs[dev_id];
	qp = dev->qp[qp_id];

	if (qp == NULL)
		return 0;

	oct_qp_id = qp_id % dev->port_info.nb_queues;
	oct_dev_id = dev->port_info.oct_dev_id[(qp_id / dev->port_info.nb_queues)];
	rc = dao_lc_ethdev_queue_destroy(lc_ctx, oct_dev_id, oct_qp_id);
	if (rc != 0)
		dao_err("Could not destroy card queue.");

	if (qp_id == dev->cmd_qp_idx) {
		rte_bitmap_free(qp->cmd_req_bm);
		rte_free(qp->cmd_req_bm_mem);
	}

	rte_bitmap_free(qp->req_bm);
	rte_free(qp->req_bm_mem);
	rte_free(qp->req_queue);
	rte_mempool_free(qp->rx_mp);
	rte_mempool_free(qp->tx_mp);
	rte_free(qp);

	dev->qp[qp_id] = NULL;

	return rc;
}

int
dao_liquid_crypto_dev_start(uint8_t dev_id)
{
	struct dao_eth_trs_port_info *port_info;
	struct liquid_crypto_dev *dev;
	int rc, i;

	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}

	dev = &liquid_crypto_devs[dev_id];

	if (!dev->is_created) {
		dao_err("Invalid device. Device(%d) not created.", dev_id);
		return -EINVAL;
	}

	if (dev->is_started) {
		dao_err("Device already started.");
		return -EEXIST;
	}

	/* Start device only if all queues are configured. */
	for (i = 0; i < dev->nb_qp; i++) {
		if (dev->qp[i] == NULL) {
			dao_err("Invalid device. Queue pair(%d, %d) not configured.", dev_id, i);
			return -EINVAL;
		}
	}

	rc = dao_eth_trs_dev_start(dev_id);
	if (rc != 0) {
		dao_err("Could not start ethernet transport device.");
		return rc;
	}

	port_info = &dev->port_info;
	for (i = 0; i < dev->nb_ports; i++) {
		rc = dao_lc_ethdev_start(lc_ctx, port_info->oct_dev_id[i]);
		if (rc != 0) {
			dao_err("Could not start card device.");
			goto lc_ethdev_stop;
		}
	}

	dev->is_started = true;

	return 0;

lc_ethdev_stop:
	for (; i > 0; i--)
		dao_lc_ethdev_stop(lc_ctx, port_info->oct_dev_id[i - 1]);
	dao_eth_trs_dev_stop(dev_id);
	return rc;
}

int
dao_liquid_crypto_dev_stop(uint8_t dev_id)
{
	struct dao_eth_trs_port_info *port_info;
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	bool is_cmd_qp;
	int rc;
	int i;

	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}

	dev = &liquid_crypto_devs[dev_id];

	if (!dev->is_created) {
		dao_err("Invalid device. Device(%d) not created.", dev_id);
		return -EINVAL;
	}

	if (!dev->is_started) {
		dao_err("Invalid device. Device(%d) not started.", dev_id);
		return -EINVAL;
	}

	/* Check for inflight requests on all queue pairs */
	for (i = 0; i < dev->nb_qp; i++) {
		qp = dev->qp[i];
		if (qp == NULL)
			continue;

		is_cmd_qp = (i == dev->cmd_qp_idx);
		if (liquid_crypto_qp_has_inflight_req(qp, is_cmd_qp)) {
			dao_err("Cannot stop device %u: queue pair %d has inflight requests.",
				dev_id, i);
			return -EBUSY;
		}
	}

	rc = dao_eth_trs_dev_stop(dev_id);
	if (rc != 0) {
		dao_err("Could not stop ethernet transport device.");
		return rc;
	}

	port_info = &dev->port_info;
	for (i = 0; i < dev->nb_ports; i++) {
		rc = dao_lc_ethdev_stop(lc_ctx, port_info->oct_dev_id[i]);
		if (rc != 0) {
			dao_err("Could not stop card device.");
			return rc;
		}
	}

	dev->is_started = false;

	return 0;
}

static inline int
cpt_ae_rsa_oaep_label_len_validate(uint16_t label_len)
{
	if (label_len > DAO_LC_RSA_OAEP_MAX_LABEL_LEN) {
		dao_err("Invalid label length. label_len=%u (maximum allowed: %u).", label_len,
			DAO_LC_RSA_OAEP_MAX_LABEL_LEN);
		return -EINVAL;
	}

	return 0;
}

static inline int
cpt_ae_rsa_oaep_mod_len_max_validate(uint16_t mod_len)
{
	if (mod_len > DAO_LC_RSA_OAEP_MAX_MOD_LEN) {
		dao_err("Invalid modulus length. mod_len=%u (maximum allowed: %u).", mod_len,
			DAO_LC_RSA_OAEP_MAX_MOD_LEN);
		return -EINVAL;
	}

	return 0;
}

uint16_t
dao_liquid_crypto_seg_size_calc(struct dao_lc_feature_params *params)
{
	uint16_t asym_seg_sz = 0, sym_seg_sz = 0, rng_seg_size = 0, max_seg_size = 0;
	uint16_t rsa_seg_sz = 0, ecc_seg_sz = 0, rsa_oaep_seg_sz = 0, pqc_seg_sz = 0;
	struct dao_eth_trs_info trs_info;
	uint16_t req_resp_hdr_sz = 0;
	int kek_len, rc;

	if (params == NULL) {
		dao_err("Invalid argument.");
		return 0;
	}

	if (params->cmd_qp) {
		req_resp_hdr_sz = RTE_MAX(sizeof(struct __dao_lc_req_sess_create),
					  sizeof(struct __dao_lc_resp_sess_create));
		max_seg_size = req_resp_hdr_sz + sizeof(struct dao_lc_sym_ctx);
	} else {
		if (params->sym.cipher_auth_payload_len) {
			/* DAO LC sym header */
			sym_seg_sz = sizeof(struct __dao_lc_req_sym);
			/* Offset control word */
			sym_seg_sz += 8;

			/* IV */
			if (params->sym.iv_len < 16) {
				/*
				 * Handling for AES-GCM & AES-CCM involves passing few more fields
				 * as IV to microcode.
				 */
				sym_seg_sz += 16;
			} else {
				sym_seg_sz += params->sym.iv_len;
			}

			/* AAD */
			sym_seg_sz += params->sym.aad_len;
			/* Payload */
			sym_seg_sz += RTE_ALIGN(params->sym.cipher_auth_payload_len, 16);
			/* Digest */
			sym_seg_sz += params->sym.digest_len;

			if (params->sym.key_wrap_len > DAO_LC_AES_KEY_WRAP_MAX_KEY_DATA_LEN) {
				dao_err("Invalid key wrap length. key_wrap_len should be at most %u.",
					DAO_LC_AES_KEY_WRAP_MAX_KEY_DATA_LEN);
				return 0;
			}
			/* Key wrap length */
			sym_seg_sz += params->sym.key_wrap_len;

			kek_len = sym_sess_get_aes_kek_len(params->sym.aes_kek_type);
			if (kek_len < 0) {
				dao_err("Could not get KEK length for the given KEK type.");
				return 0;
			}

			/* AES KEK length */
			sym_seg_sz += kek_len;
		}

		if (params->rsa.mod_len) {
			bool is_crt;

			if (params->rsa.exp_len == 0)
				is_crt = true;
			else
				is_crt = false;

			rc = cpt_ae_rsa_mod_len_check(params->rsa.mod_len, is_crt);
			if (rc != 0)
				return 0;

			if (!is_crt) {
				rc = cpt_ae_rsa_exp_len_check(params->rsa.mod_len,
							      params->rsa.exp_len);
				if (rc != 0)
					return 0;
			}

			rc = cpt_ae_rsa_msg_len_check(params->rsa.mod_len, params->rsa.msg_len);
			if (rc != 0)
				return 0;

			/* DAO LC ASYM header */
			rsa_seg_sz = sizeof(struct __dao_lc_req_asym);

			if (is_crt)
				rsa_seg_sz += (params->rsa.mod_len / 2) * 5;
			else
				rsa_seg_sz += params->rsa.mod_len + params->rsa.exp_len;

			rsa_seg_sz += params->rsa.msg_len;
		}

		if (params->ecc.is_ecc_enabled) {
			uint16_t prime_len;

			rc = cpt_ec_curve_id_validate(params->ecc.curve_id);
			if (rc != 0) {
				dao_err("Invalid %d ECC curve ID.", params->ecc.curve_id);
				return 0;
			}

			prime_len = ecc_curve_id_to_prime_len(params->ecc.curve_id);
			if (prime_len == 0) {
				dao_err("Could not get prime length for the given %d curve ID.",
					params->ecc.curve_id);
				return 0;
			}

			rc = cpt_ae_ecdsa_digest_len_check(prime_len, params->ecc.digest_len);
			if (rc != 0) {
				dao_err("Invalid %d ECC digest length.", params->ecc.digest_len);
				return 0;
			}

			ecc_seg_sz += params->ecc.digest_len;

			rc = cpt_ae_ecdsa_nonce_len_check(prime_len, params->ecc.nonce_len,
							  params->ecc.curve_id);
			if (rc != 0) {
				dao_err("Invalid %d ECC nonce length.", params->ecc.nonce_len);
				return 0;
			}

			ecc_seg_sz += params->ecc.nonce_len;

			rc = cpt_ae_ecdsa_pkey_len_check(prime_len, params->ecc.pkey_len,
							 params->ecc.curve_id);
			if (rc != 0) {
				dao_err("Invalid %d ECC private key length.", params->ecc.pkey_len);
				return 0;
			}

			ecc_seg_sz += params->ecc.pkey_len;

			rc = cpt_ae_ecdsa_pubkey_len_check(prime_len, params->ecc.pubkey_x_len,
							   params->ecc.pubkey_y_len,
							   params->ecc.curve_id);
			if (rc != 0) {
				dao_err("Invalid ECC public key length.");
				return 0;
			}

			ecc_seg_sz += params->ecc.pubkey_x_len + params->ecc.pubkey_y_len;

			rc = cpt_ae_ecdsa_sign_comp_len_check(prime_len, params->ecc.sign_r_len,
							      params->ecc.sign_s_len,
							      params->ecc.curve_id);
			if (rc != 0) {
				dao_err("Invalid ECC signature length.");
				return 0;
			}

			ecc_seg_sz += params->ecc.sign_r_len + params->ecc.sign_s_len;

			/* Prime Order ConstantA and ConstantB */
			ecc_seg_sz += (prime_len * 4);

			/* DAO LC ASYM header */
			ecc_seg_sz += sizeof(struct __dao_lc_req_asym);
		}

		if (params->rsa_oaep.is_rsa_oaep_enabled) {
			rc = cpt_ae_oaep_msg_and_mod_len_check(params->rsa_oaep.mod_len,
							       params->rsa_oaep.msg_len,
							       params->rsa_oaep.hash_type);
			if (rc != 0) {
				dao_err("Invalid %d RSA-OAEP message length.",
					params->rsa_oaep.msg_len);
				return 0;
			}

			/* Message */
			rsa_oaep_seg_sz += params->rsa_oaep.msg_len;

			rc = cpt_ae_rsa_oaep_mod_len_max_validate(params->rsa_oaep.mod_len);
			if (rc != 0)
				return 0;

			rc = cpt_ae_rsa_oaep_mod_len_check(params->rsa_oaep.mod_len, false);
			if (rc != 0) {
				dao_err("Invalid %d RSA-OAEP modulus length.",
					params->rsa_oaep.mod_len);
				return 0;
			}

			/* Modulus */
			rsa_oaep_seg_sz += params->rsa_oaep.mod_len;

			rc = cpt_ae_rsa_exp_len_check(params->rsa_oaep.mod_len,
						      params->rsa_oaep.exp_len);
			if (rc != 0) {
				dao_err("Invalid %d RSA-OAEP exponent length.",
					params->rsa_oaep.exp_len);
				return 0;
			}

			/* Exponent */
			rsa_oaep_seg_sz += params->rsa_oaep.exp_len;

			rc = cpt_ae_rsa_oaep_label_len_validate(params->rsa_oaep.label_len);
			if (rc != 0) {
				dao_err("Invalid RSA-OAEP label length (%d). Maximum supported is %u.",
					params->rsa_oaep.label_len, DAO_LC_RSA_OAEP_MAX_LABEL_LEN);
				return 0;
			}

			/* OAEP Label */
			rsa_oaep_seg_sz += params->rsa_oaep.label_len;

			rc = cpt_ae_rsa_oaep_hash_type_check(params->rsa_oaep.hash_type);
			if (rc != 0) {
				dao_err("Invalid RSA-OAEP hash type %d.",
					params->rsa_oaep.hash_type);
				return 0;
			}

			/* OAEP Hash type */
			rsa_oaep_seg_sz += sizeof(params->rsa_oaep.hash_type);

			/* DAO LC ASYM header */
			rsa_oaep_seg_sz = sizeof(struct __dao_lc_req_asym);
		}

		asym_seg_sz = RTE_MAX(rsa_seg_sz, ecc_seg_sz);
		asym_seg_sz = RTE_MAX(asym_seg_sz, rsa_oaep_seg_sz);

		if (params->rng.rand_len) {
			uint16_t rand_len_max = LIQUID_CRYPTO_RAND_LEN_MAX;

			if (params->rng.rand_len > rand_len_max) {
				dao_err("Invalid RNG length. rand_len should be at most %u.",
					rand_len_max);
				return 0;
			}

			rng_seg_size = sizeof(struct __dao_lc_req_sym) + params->rng.rand_len;
		}
		pqc_seg_sz = RTE_MAX(pqc_seg_sz, DAO_LC_ML_KEM_1024_PRIV_KEY_LEN +
							 DAO_LC_ML_KEM_SHARED_SECRET_LEN +
							 DAO_LC_ML_KEM_1024_CIPHERTEXT_LEN);
		pqc_seg_sz = RTE_MAX(pqc_seg_sz, DAO_LC_ML_DSA_87_PRIV_KEY_LEN +
							 DAO_LC_ML_DSA_87_PUB_KEY_LEN +
							 DAO_LC_ML_DSA_87_SIGNATURE_LEN);

		max_seg_size = RTE_MAX(sym_seg_sz, asym_seg_sz);
		max_seg_size = RTE_MAX(max_seg_size, rng_seg_size);
		max_seg_size = RTE_MAX(max_seg_size, pqc_seg_sz);
	}
	max_seg_size = RTE_MAX(max_seg_size, LIQUID_CRYPTO_SEG_SZ_MIN);

	/* Make sure segment size is larger than min supported. */
	memset(&trs_info, 0, sizeof(trs_info));
	rc = dao_eth_trs_info(&trs_info);
	if (rc != 0) {
		dao_err("Could not get ethernet transport information.");
		return 0;
	}

	max_seg_size = RTE_MAX(max_seg_size, trs_info.min_buf_len);

	if (max_seg_size >
	    (LIQUID_CRYPTO_BUF_SZ_MAX - RTE_PKTMBUF_HEADROOM - LIQUID_CRYPTO_BUF_SDP_DATA_LEN_SZ)) {
		dao_err("Paylod length exceeds maximum supported packet size.");
		return 0;
	}

	return max_seg_size;
}

static inline void
lc_inflight_req_reset(struct liquid_crypto_inflight_req *req)
{
	req->digest = NULL;
	req->digest_len = 0;
	req->cipher_len = 0;
	req->wrap_unwrap_key_len = 0;
}

int
dao_liquid_crypto_enqueue_op_passthrough(uint8_t dev_id, uint16_t qp_id, uint64_t op_cookie)
{
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	struct __dao_lc_hdr *lc_hdr;
	struct rte_mbuf *mbuf;
	uint32_t req_idx = 0;
	uint16_t buf_len;
	int rc;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}
#endif

	dev = &liquid_crypto_devs[dev_id];

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (qp_id >= dev->nb_qp) {
		dao_err("Invalid argument. qp_id must be between 0 and %u.", dev->nb_qp - 1);
		return -EINVAL;
	}

	if (qp_id == dev->cmd_qp_idx) {
		dao_err("Invalid argument. qp_id cannot be the command queue index.");
		return -EINVAL;
	}

	if (!dev->is_started) {
		dao_err("Invalid device. Device(%d) not started.", dev_id);
		return -EINVAL;
	}
#endif
	qp = dev->qp[qp_id];

	req_idx = liquid_crypto_qp_req_idx_get(qp, false);

	if (unlikely(req_idx == UINT32_MAX)) {
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		dao_err("No available request index.");
#endif
		return -ENOSPC;
	}

	mbuf = rte_pktmbuf_alloc(qp->tx_mp);
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (unlikely(mbuf == NULL)) {
		dao_err("Could not allocate mbuf.");
		rc = -ENOMEM;
		goto idx_put;
	}
#endif

	lc_inflight_req_reset(&qp->req_queue[req_idx]);
	qp->req_queue[req_idx].op_cookie = op_cookie;

	buf_len = RTE_MAX(sizeof(struct __dao_lc_hdr), LIQUID_CRYPTO_BUF_SZ_MIN);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (buf_len > rte_pktmbuf_tailroom(mbuf)) {
		dao_err("Input data doesn't fit in single segment!");
		rc = -ENOMEM;
		goto mbuf_free;
	}

	if (buf_len > LIQUID_CRYPTO_BUF_SZ_MAX) {
		dao_err("Input data too large. buf_len = %u", buf_len);
		rc = -ENOMEM;
		goto mbuf_free;
	}
#endif

	rte_pktmbuf_append(mbuf, buf_len);

	lc_hdr = rte_pktmbuf_mtod(mbuf, struct __dao_lc_hdr *);
	lc_hdr->trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_REFLECT;
	lc_hdr->trs_hdr.op_len = sizeof(struct __dao_lc_hdr);
	lc_hdr->req_idx = req_idx;

	rc = rte_eth_tx_burst(qp->port_id, qp->queue_id, &mbuf, 1);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (rc != 1) {
		dao_err("Failed to transmit packet.");
		rc = -EIO;
		goto mbuf_free;
	}
#endif

	return 0;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
mbuf_free:
	rte_pktmbuf_free(mbuf);
idx_put:
	liquid_crypto_qp_req_idx_put(qp, req_idx, false);
#endif
	return rc;
}

int
dao_liquid_crypto_enq_op_pkcs1v15enc(uint8_t dev_id, uint16_t qp_id,
				     enum dao_liquid_crypto_rsa_key_type key_type, uint16_t mod_len,
				     uint16_t exp_len, uint16_t msg_len, const uint8_t *mod,
				     const uint8_t *exp, const uint8_t *msg, uint8_t *em,
				     uint64_t op_cookie)
{
	uint32_t dlen = mod_len + exp_len + msg_len;
	struct __dao_lc_req_asym *req;
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	struct rte_mbuf *mbuf;
	union cpt_inst_w4 w4;
	uint32_t req_idx = 0;
	uint16_t buf_len;
	uint8_t *dptr;
	int rc;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}
#endif

	dev = &liquid_crypto_devs[dev_id];

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (qp_id >= dev->nb_qp) {
		dao_err("Invalid argument. qp_id must be between 0 and %u.", dev->nb_qp - 1);
		return -EINVAL;
	}

	if (qp_id == dev->cmd_qp_idx) {
		dao_err("Invalid argument. qp_id cannot be the command queue index.");
		return -EINVAL;
	}

	if (!dev->is_started) {
		dao_err("Invalid device. Device(%d) not started.", dev_id);
		return -EINVAL;
	}

	if (mod == NULL) {
		dao_err("Invalid argument. mod cannot be NULL.");
		return -EINVAL;
	}

	if (exp == NULL) {
		dao_err("Invalid argument. exp cannot be NULL.");
		return -EINVAL;
	}

	if (msg == NULL) {
		dao_err("Invalid argument. msg cannot be NULL.");
		return -EINVAL;
	}

	if (em == NULL) {
		dao_err("Invalid argument. em cannot be NULL.");
		return -EINVAL;
	}

	rc = cpt_ae_rsa_mod_len_check(mod_len, false);
	if (rc != 0)
		return rc;

	rc = cpt_ae_rsa_exp_len_check(mod_len, exp_len);
	if (rc != 0)
		return rc;

	rc = cpt_ae_rsa_msg_len_check(mod_len, msg_len);
	if (rc != 0)
		return rc;

	rc = cpt_ae_rsa_msw_check(mod_len, mod);
	if (rc != 0) {
		dao_err("Invalid argument. MSW of modulus must be non-zero.");
		return -EINVAL;
	}
#endif
	qp = dev->qp[qp_id];

	req_idx = liquid_crypto_qp_req_idx_get(qp, false);

	if (unlikely(req_idx == UINT32_MAX)) {
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		dao_err("No available request index.");
#endif
		return -ENOSPC;
	}

	mbuf = rte_pktmbuf_alloc(qp->tx_mp);
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (unlikely(mbuf == NULL)) {
		dao_err("Could not allocate mbuf.");
		rc = -ENOMEM;
		goto idx_put;
	}
#endif

	lc_inflight_req_reset(&qp->req_queue[req_idx]);
	qp->req_queue[req_idx].op_cookie = op_cookie;
	qp->req_queue[req_idx].data_out = em;

	buf_len = sizeof(struct __dao_lc_req_asym) + dlen;
	buf_len = RTE_MAX(buf_len, LIQUID_CRYPTO_BUF_SZ_MIN);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (buf_len > rte_pktmbuf_tailroom(mbuf)) {
		dao_err("Input data doesn't fit in single segment!");
		rc = -ENOMEM;
		goto mbuf_free;
	}

	if (buf_len > LIQUID_CRYPTO_BUF_SZ_MAX) {
		dao_err("Input data too large. buf_len = %u", buf_len);
		rc = -ENOMEM;
		goto mbuf_free;
	}
#endif

	rte_pktmbuf_append(mbuf, buf_len);

	/* Add payload to mbuf */
	req = rte_pktmbuf_mtod(mbuf, struct __dao_lc_req_asym *);
	req->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_ASYM;
	req->hdr.trs_hdr.op_len = buf_len;
	req->hdr.req_idx = req_idx;
	req->op_type = LC_ASYM_RSA_ENCRYPT;

	/* Add instruction */
	w4.s.opcode_major = ROC_AE_MAJOR_OP_MODEX;
	w4.s.opcode_minor = ROC_AE_MINOR_OP_PKCS_ENC;
	w4.s.param1 = mod_len;
	w4.s.param2 = ((uint16_t)(exp_len) << 1) | (key_type != DAO_LC_RSA_KEY_TYPE_PRIVATE);
	w4.s.dlen = dlen;
	req->w4 = w4.u64;

	/* Add data */
	dptr = req->dptr;
	memcpy(dptr, mod, mod_len);
	dptr += mod_len;
	memcpy(dptr, exp, exp_len);
	dptr += exp_len;
	memcpy(dptr, msg, msg_len);

	rc = rte_eth_tx_burst(qp->port_id, qp->queue_id, &mbuf, 1);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (rc != 1) {
		dao_err("Failed to transmit packet.");
		rc = -EIO;
		goto mbuf_free;
	}
#endif

	return 0;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
mbuf_free:
	rte_pktmbuf_free(mbuf);
idx_put:
	liquid_crypto_qp_req_idx_put(qp, req_idx, false);
	return rc;
#endif
	RTE_SET_USED(rc);
}

int
dao_liquid_crypto_enq_op_pkcs1v15dec(uint8_t dev_id, uint16_t qp_id,
				     enum dao_liquid_crypto_rsa_key_type key_type, uint16_t mod_len,
				     uint16_t exp_len, const uint8_t *mod, const uint8_t *exp,
				     const uint8_t *em, uint8_t *msg, uint64_t op_cookie)
{
	uint32_t dlen = mod_len * 2 + exp_len;
	struct __dao_lc_req_asym *req;
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	struct rte_mbuf *mbuf;
	union cpt_inst_w4 w4;
	uint32_t req_idx = 0;
	uint16_t buf_len;
	uint8_t *dptr;
	int rc;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}
#endif

	dev = &liquid_crypto_devs[dev_id];

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (qp_id >= dev->nb_qp) {
		dao_err("Invalid argument. qp_id must be between 0 and %u.", dev->nb_qp - 1);
		return -EINVAL;
	}

	if (qp_id == dev->cmd_qp_idx) {
		dao_err("Invalid argument. qp_id cannot be the command queue index.");
		return -EINVAL;
	}

	if (!dev->is_started) {
		dao_err("Invalid device. Device(%d) not started.", dev_id);
		return -EINVAL;
	}

	if (mod == NULL) {
		dao_err("Invalid argument. mod cannot be NULL.");
		return -EINVAL;
	}

	if (exp == NULL) {
		dao_err("Invalid argument. exp cannot be NULL.");
		return -EINVAL;
	}

	if (msg == NULL) {
		dao_err("Invalid argument. msg cannot be NULL.");
		return -EINVAL;
	}

	if (em == NULL) {
		dao_err("Invalid argument. em cannot be NULL.");
		return -EINVAL;
	}

	rc = cpt_ae_rsa_mod_len_check(mod_len, false);
	if (rc != 0)
		return rc;

	rc = cpt_ae_rsa_exp_len_check(mod_len, exp_len);
	if (rc != 0)
		return rc;

	rc = cpt_ae_rsa_msw_check(mod_len, mod);
	if (rc != 0) {
		dao_err("Invalid argument. MSW of modulus must be non-zero.");
		return -EINVAL;
	}
#endif
	qp = dev->qp[qp_id];

	req_idx = liquid_crypto_qp_req_idx_get(qp, false);

	if (unlikely(req_idx == UINT32_MAX)) {
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		dao_err("No available request index.");
#endif
		return -ENOSPC;
	}

	mbuf = rte_pktmbuf_alloc(qp->tx_mp);
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (unlikely(mbuf == NULL)) {
		dao_err("Could not allocate mbuf.");
		rc = -ENOMEM;
		goto idx_put;
	}
#endif

	lc_inflight_req_reset(&qp->req_queue[req_idx]);
	qp->req_queue[req_idx].op_cookie = op_cookie;
	qp->req_queue[req_idx].data_out = msg;

	buf_len = sizeof(struct __dao_lc_req_asym) + dlen;
	buf_len = RTE_MAX(buf_len, LIQUID_CRYPTO_BUF_SZ_MIN);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (buf_len > rte_pktmbuf_tailroom(mbuf)) {
		dao_err("Input data doesn't fit in single segment!");
		rc = -ENOMEM;
		goto mbuf_free;
	}

	if (buf_len > LIQUID_CRYPTO_BUF_SZ_MAX) {
		dao_err("Input data too large. buf_len = %u", buf_len);
		rc = -ENOMEM;
		goto mbuf_free;
	}
#endif

	rte_pktmbuf_append(mbuf, buf_len);

	/* Append payload to mbuf */
	req = rte_pktmbuf_mtod(mbuf, struct __dao_lc_req_asym *);
	req->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_ASYM;
	req->hdr.trs_hdr.op_len = buf_len;
	req->hdr.req_idx = req_idx;
	req->op_type = LC_ASYM_RSA_DECRYPT;

	/* Add instruction */
	w4.s.opcode_major = ROC_AE_MAJOR_OP_MODEX;
	w4.s.opcode_minor = ROC_AE_MINOR_OP_PKCS_DEC;
	w4.s.param1 = mod_len;
	if (key_type == DAO_LC_RSA_KEY_TYPE_PRIVATE)
		w4.s.param2 = 1;
	else
		w4.s.param2 = 0;

	w4.s.dlen = dlen;
	req->w4 = w4.u64;

	/* Add data */
	dptr = req->dptr;
	memcpy(dptr, mod, mod_len);
	dptr += mod_len;
	memcpy(dptr, exp, exp_len);
	dptr += exp_len;
	memcpy(dptr, em, mod_len);

	rc = rte_eth_tx_burst(qp->port_id, qp->queue_id, &mbuf, 1);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (rc != 1) {
		dao_err("Failed to transmit packet.");
		rc = -EIO;
		goto mbuf_free;
	}
#endif

	return 0;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
mbuf_free:
	rte_pktmbuf_free(mbuf);
idx_put:
	liquid_crypto_qp_req_idx_put(qp, req_idx, false);
	return rc;
#endif
	RTE_SET_USED(rc);
}

int
dao_liquid_crypto_enq_op_pkcs1v15enc_crt(uint8_t dev_id, uint16_t qp_id, uint16_t mod_len,
					 uint16_t msg_len, const uint8_t *q, const uint8_t *dQ,
					 const uint8_t *p, const uint8_t *dP, const uint8_t *qInv,
					 const uint8_t *msg, uint8_t *em, uint64_t op_cookie)
{
	uint32_t dlen = (mod_len / 2) * 5 + msg_len;
	uint16_t comp_len = mod_len / 2;
	struct __dao_lc_req_asym *req;
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	struct rte_mbuf *mbuf;
	union cpt_inst_w4 w4;
	uint32_t req_idx = 0;
	uint16_t buf_len;
	uint8_t *dptr;
	int rc;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}
#endif

	dev = &liquid_crypto_devs[dev_id];

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (qp_id >= dev->nb_qp) {
		dao_err("Invalid argument. qp_id must be between 0 and %u.", dev->nb_qp - 1);
		return -EINVAL;
	}

	if (qp_id == dev->cmd_qp_idx) {
		dao_err("Invalid argument. qp_id cannot be the command queue index.");
		return -EINVAL;
	}

	if (!dev->is_started) {
		dao_err("Invalid device. Device(%d) not started.", dev_id);
		return -EINVAL;
	}

	if (msg == NULL) {
		dao_err("Invalid argument. msg cannot be NULL.");
		return -EINVAL;
	}

	if (em == NULL) {
		dao_err("Invalid argument. em cannot be NULL.");
		return -EINVAL;
	}

	rc = cpt_ae_rsa_mod_len_check(mod_len, true);
	if (rc != 0)
		return rc;

	rc = cpt_ae_rsa_msg_len_check(mod_len, msg_len);
	if (rc != 0)
		return rc;

	rc = cpt_ae_rsa_crt_params_check(mod_len, q, dQ, p, dP, qInv);
	if (rc != 0)
		return rc;
#endif

	if (cpt_ae_rsa_msw_check(mod_len / 2, q) != 0) {
		dao_err("Invalid CRT parameter. MSW of q must be non-zero.");
		return -EINVAL;
	}

	if (cpt_ae_rsa_msw_check(mod_len / 2, p) != 0) {
		dao_err("Invalid CRT parameter. MSW of p must be non-zero.");
		return -EINVAL;
	}

	qp = dev->qp[qp_id];

	req_idx = liquid_crypto_qp_req_idx_get(qp, false);

	if (unlikely(req_idx == UINT32_MAX)) {
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		dao_err("No available request index.");
#endif
		return -ENOSPC;
	}

	mbuf = rte_pktmbuf_alloc(qp->tx_mp);
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (unlikely(mbuf == NULL)) {
		dao_err("Could not allocate mbuf.");
		rc = -ENOMEM;
		goto idx_put;
	}
#endif

	lc_inflight_req_reset(&qp->req_queue[req_idx]);
	qp->req_queue[req_idx].op_cookie = op_cookie;
	qp->req_queue[req_idx].data_out = em;

	buf_len = sizeof(struct __dao_lc_req_asym) + dlen;
	buf_len = RTE_MAX(buf_len, LIQUID_CRYPTO_BUF_SZ_MIN);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (buf_len > rte_pktmbuf_tailroom(mbuf)) {
		dao_err("Input data doesn't fit in single segment!");
		rc = -ENOMEM;
		goto mbuf_free;
	}

	if (buf_len > LIQUID_CRYPTO_BUF_SZ_MAX) {
		dao_err("Input data too large. buf_len = %u", buf_len);
		rc = -ENOMEM;
		goto mbuf_free;
	}
#endif

	rte_pktmbuf_append(mbuf, buf_len);

	/* Append payload to mbuf */
	req = rte_pktmbuf_mtod(mbuf, struct __dao_lc_req_asym *);
	req->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_ASYM;
	req->hdr.trs_hdr.op_len = buf_len;
	req->hdr.req_idx = req_idx;
	req->op_type = LC_ASYM_RSA_ENCRYPT;

	/* Add instruction */
	w4.s.opcode_major = ROC_AE_MAJOR_OP_MODEX;
	w4.s.opcode_minor = ROC_AE_MINOR_OP_PKCS_ENC_CRT;
	w4.s.param1 = mod_len;
	w4.s.param2 = 0;
	w4.s.dlen = dlen;
	req->w4 = w4.u64;

	/* Add data */
	dptr = req->dptr;
	memcpy(dptr, q, comp_len);
	dptr += comp_len;
	memcpy(dptr, dQ, comp_len);
	dptr += comp_len;
	memcpy(dptr, p, comp_len);
	dptr += comp_len;
	memcpy(dptr, dP, comp_len);
	dptr += comp_len;
	memcpy(dptr, qInv, comp_len);
	dptr += comp_len;
	memcpy(dptr, msg, msg_len);

	rc = rte_eth_tx_burst(qp->port_id, qp->queue_id, &mbuf, 1);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (rc != 1) {
		dao_err("Failed to transmit packet.");
		rc = -EIO;
		goto mbuf_free;
	}
#endif

	return 0;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
mbuf_free:
	rte_pktmbuf_free(mbuf);
idx_put:
	liquid_crypto_qp_req_idx_put(qp, req_idx, false);
	return rc;
#endif
	RTE_SET_USED(rc);
}

int
dao_liquid_crypto_enq_op_pkcs1v15dec_crt(uint8_t dev_id, uint16_t qp_id, uint16_t mod_len,
					 const uint8_t *q, const uint8_t *dQ, const uint8_t *p,
					 const uint8_t *dP, const uint8_t *qInv, const uint8_t *em,
					 uint8_t *msg, uint64_t op_cookie)
{
	uint32_t dlen = (mod_len / 2) * 5 + mod_len;
	uint16_t comp_len = mod_len / 2;
	struct __dao_lc_req_asym *req;
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	struct rte_mbuf *mbuf;
	union cpt_inst_w4 w4;
	uint32_t req_idx = 0;
	uint16_t buf_len;
	uint8_t *dptr;
	int rc;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}

	if (em == NULL) {
		dao_err("Invalid argument. em cannot be NULL.");
		return -EINVAL;
	}

	if (msg == NULL) {
		dao_err("Invalid argument. msg cannot be NULL.");
		return -EINVAL;
	}
#endif

	dev = &liquid_crypto_devs[dev_id];

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (qp_id >= dev->nb_qp) {
		dao_err("Invalid argument. qp_id must be between 0 and %u.", dev->nb_qp - 1);
		return -EINVAL;
	}

	if (qp_id == dev->cmd_qp_idx) {
		dao_err("Invalid argument. qp_id cannot be the command queue index.");
		return -EINVAL;
	}

	if (!dev->is_started) {
		dao_err("Invalid device. Device(%d) not started.", dev_id);
		return -EINVAL;
	}

	rc = cpt_ae_rsa_mod_len_check(mod_len, true);
	if (rc != 0)
		return rc;

	rc = cpt_ae_rsa_crt_params_check(mod_len, q, dQ, p, dP, qInv);
	if (rc != 0)
		return rc;
#endif

	if (cpt_ae_rsa_msw_check(mod_len / 2, q) != 0) {
		dao_err("Invalid CRT parameter. MSW of q must be non-zero.");
		return -EINVAL;
	}

	if (cpt_ae_rsa_msw_check(mod_len / 2, p) != 0) {
		dao_err("Invalid CRT parameter. MSW of p must be non-zero.");
		return -EINVAL;
	}

	qp = dev->qp[qp_id];

	req_idx = liquid_crypto_qp_req_idx_get(qp, false);

	if (unlikely(req_idx == UINT32_MAX)) {
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		dao_err("No available request index.");
#endif
		return -ENOSPC;
	}

	mbuf = rte_pktmbuf_alloc(qp->tx_mp);
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (unlikely(mbuf == NULL)) {
		dao_err("Could not allocate mbuf.");
		rc = -ENOMEM;
		goto idx_put;
	}
#endif

	lc_inflight_req_reset(&qp->req_queue[req_idx]);
	qp->req_queue[req_idx].op_cookie = op_cookie;
	qp->req_queue[req_idx].data_out = msg;

	buf_len = sizeof(struct __dao_lc_req_asym) + dlen;
	buf_len = RTE_MAX(buf_len, LIQUID_CRYPTO_BUF_SZ_MIN);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (buf_len > rte_pktmbuf_tailroom(mbuf)) {
		dao_err("Input data doesn't fit in single segment!");
		rc = -ENOMEM;
		goto mbuf_free;
	}

	if (buf_len > LIQUID_CRYPTO_BUF_SZ_MAX) {
		dao_err("Input data too large. buf_len = %u", buf_len);
		rc = -ENOMEM;
		goto mbuf_free;
	}
#endif

	rte_pktmbuf_append(mbuf, buf_len);

	/* Append payload to mbuf */
	req = rte_pktmbuf_mtod(mbuf, struct __dao_lc_req_asym *);
	req->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_ASYM;
	req->hdr.trs_hdr.op_len = buf_len;
	req->hdr.req_idx = req_idx;
	req->op_type = LC_ASYM_RSA_DECRYPT;

	/* Add instruction */
	w4.s.opcode_major = ROC_AE_MAJOR_OP_MODEX;
	w4.s.opcode_minor = ROC_AE_MINOR_OP_PKCS_DEC_CRT;
	w4.s.param1 = mod_len;
	w4.s.param2 = 0x1;
	w4.s.dlen = dlen;
	req->w4 = w4.u64;

	/* Add data */
	dptr = req->dptr;
	memcpy(dptr, q, comp_len);
	dptr += comp_len;
	memcpy(dptr, dQ, comp_len);
	dptr += comp_len;
	memcpy(dptr, p, comp_len);
	dptr += comp_len;
	memcpy(dptr, dP, comp_len);
	dptr += comp_len;
	memcpy(dptr, qInv, comp_len);
	dptr += comp_len;
	memcpy(dptr, em, mod_len);

	rc = rte_eth_tx_burst(qp->port_id, qp->queue_id, &mbuf, 1);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (rc != 1) {
		dao_err("Failed to transmit packet.");
		rc = -EIO;
		goto mbuf_free;
	}
#endif

	return 0;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
mbuf_free:
	rte_pktmbuf_free(mbuf);
idx_put:
	liquid_crypto_qp_req_idx_put(qp, req_idx, false);
	return rc;
#endif
	RTE_SET_USED(rc);
}

int
dao_liquid_crypto_pqc_enqueue(uint8_t dev_id, uint16_t qp_id, struct dao_lc_pqc_op *op,
			      uint64_t op_cookie)
{
	struct __dao_lc_req_pqc *req;
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	struct rte_mbuf *mbuf;
	union cpt_inst_w4 w4;
	uint32_t req_idx = 0;
	uint8_t *dptr;
	int rc = 0;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}
#endif
	dev = &liquid_crypto_devs[dev_id];
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (qp_id >= dev->nb_qp) {
		dao_err("Invalid argument. qp_id must be between 0 and %u.", dev->nb_qp - 1);
		return -EINVAL;
	}

	if (qp_id == dev->cmd_qp_idx) {
		dao_err("Invalid argument. qp_id cannot be the command queue index.");
		return -EINVAL;
	}

	if (!dev->is_started) {
		dao_err("Invalid device. Device(%d) not started.", dev_id);
		return -EINVAL;
	}
#endif
	qp = dev->qp[qp_id];

	req_idx = liquid_crypto_qp_req_idx_get(qp, false);
	if (unlikely(req_idx == UINT32_MAX)) {
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		dao_err("No available request index.");
#endif
		return -ENOSPC;
	}

	mbuf = rte_pktmbuf_alloc(qp->tx_mp);
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (unlikely(mbuf == NULL)) {
		dao_err("Could not allocate mbuf.");
		rc = -ENOMEM;
		goto idx_put;
	}

	if (sizeof(struct __dao_lc_req_pqc) > rte_pktmbuf_tailroom(mbuf)) {
		dao_err("Input data doesn't fit in single segment!");
		rc = -ENOMEM;
		goto mbuf_free;
	}

	if (op->alg >= DAO_LC_ML_PQC_ALG_END || op->alg == 0) {
		dao_err("Unsupported PQC algorithm: %d", op->alg);
		rc = -EINVAL;
		goto mbuf_free;
	}

#endif

	rte_pktmbuf_append(mbuf, sizeof(struct __dao_lc_req_pqc));

	/* Append payload to mbuf */
	req = rte_pktmbuf_mtod(mbuf, struct __dao_lc_req_pqc *);
	req->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_PQC;
	req->hdr.req_idx = req_idx;

	qp->req_queue[req_idx].op_cookie = op_cookie;

	/* Add instruction */
	switch (op->op_type) {
	case DAO_LC_ML_KEM_OP_KEYGEN:
		w4.s.opcode_major = ROC_AE_MAJOR_OP_ML_KEM;
		w4.s.opcode_minor = ROC_AE_MINOR_OP_ML_KEM_KEYGEN;
		w4.s.param1 = 0; /* No parameters */
		w4.s.param2 = op->alg;
		w4.s.dlen = 0; /* No data length for keygen */
		req->w4 = w4.u64;
		qp->req_queue[req_idx].keygen.pub_key = op->keygen.pub_key;
		qp->req_queue[req_idx].keygen.priv_key = op->keygen.priv_key;
		break;
	case DAO_LC_ML_KEM_OP_ENCAP:
		w4.s.opcode_major = ROC_AE_MAJOR_OP_ML_KEM;
		w4.s.opcode_minor = ROC_AE_MINOR_OP_ML_KEM_ENCAP;
		w4.s.param1 = 0; /* No parameters */
		w4.s.param2 = op->alg;
		w4.s.dlen = pqc_ml_pub_key_len[op->alg];
		rte_pktmbuf_append(mbuf, w4.s.dlen);
		req->w4 = w4.u64;
		dptr = req->dptr;
		memcpy(dptr, op->encap.enc_key, pqc_ml_pub_key_len[op->alg]);
		qp->req_queue[req_idx].encap.shared_secret = op->encap.shared_secret;
		qp->req_queue[req_idx].encap.ciphertext = op->encap.ciphertext;
		break;
	case DAO_LC_ML_KEM_OP_DECAP:
		w4.s.opcode_major = ROC_AE_MAJOR_OP_ML_KEM;
		w4.s.opcode_minor = ROC_AE_MINOR_OP_ML_KEM_DECAP;
		w4.s.param1 = 0; /* No parameters */
		w4.s.param2 = op->alg;
		w4.s.dlen = pqc_ml_priv_key_len[op->alg] + pqc_ml_ciphertext_len[op->alg];
		rte_pktmbuf_append(mbuf, w4.s.dlen);
		req->w4 = w4.u64;
		dptr = req->dptr;
		memcpy(dptr, op->decap.dec_key, pqc_ml_priv_key_len[op->alg]);
		dptr += pqc_ml_priv_key_len[op->alg];
		memcpy(dptr, op->decap.ciphertext, pqc_ml_ciphertext_len[op->alg]);
		qp->req_queue[req_idx].decap.shared_secret = op->decap.shared_secret;
		break;
	case DAO_LC_ML_DSA_OP_KEYGEN:
		w4.s.opcode_major = ROC_AE_MAJOR_OP_ML_DSA;
		w4.s.opcode_minor = ROC_AE_MINOR_OP_ML_DSA_KEYGEN;
		w4.s.param1 = 0;           /* No parameters */
		w4.s.param2 = op->alg - 3; /* Adjust for DSA algorithms */
		w4.s.dlen = 0;             /* No data length for keygen */
		req->w4 = w4.u64;
		qp->req_queue[req_idx].keygen.pub_key = op->keygen.pub_key;
		qp->req_queue[req_idx].keygen.priv_key = op->keygen.priv_key;
		break;
	case DAO_LC_ML_DSA_OP_SIGN:
		w4.s.opcode_major = ROC_AE_MAJOR_OP_ML_DSA;
		w4.s.opcode_minor = ROC_AE_MINOR_OP_ML_DSA_SIGN;
		w4.s.param1 = op->sign.msg_len;
		w4.s.param2 =
			(op->sign.ctx_len << 2) | (op->alg - 3); /* Adjust for DSA algorithms */
		w4.s.dlen = pqc_ml_priv_key_len[op->alg] + op->sign.ctx_len + op->sign.msg_len;
		rte_pktmbuf_append(mbuf, w4.s.dlen);
		req->w4 = w4.u64;
		dptr = req->dptr;
		memcpy(dptr, op->sign.priv_key, pqc_ml_priv_key_len[op->alg]);
		dptr += pqc_ml_priv_key_len[op->alg];
		memcpy(dptr, op->sign.ctx, op->sign.ctx_len);
		dptr += op->sign.ctx_len;
		memcpy(dptr, op->sign.msg, op->sign.msg_len);
		qp->req_queue[req_idx].signature = op->sign.signature;
		break;
	case DAO_LC_ML_DSA_OP_VERIFY:
		w4.s.opcode_major = ROC_AE_MAJOR_OP_ML_DSA;
		w4.s.opcode_minor = ROC_AE_MINOR_OP_ML_DSA_VERIFY;
		w4.s.param1 = op->sign.msg_len;
		w4.s.param2 =
			(op->sign.ctx_len << 2) | (op->alg - 3); /* Adjust for DSA algorithms */
		w4.s.dlen = pqc_ml_pub_key_len[op->alg] + op->sign.ctx_len + op->sign.msg_len +
			    pqc_ml_signature_len[op->alg];
		rte_pktmbuf_append(mbuf, w4.s.dlen);
		req->w4 = w4.u64;
		dptr = req->dptr;
		memcpy(dptr, op->verify.pub_key, pqc_ml_pub_key_len[op->alg]);
		dptr += pqc_ml_pub_key_len[op->alg];
		memcpy(dptr, op->sign.ctx, op->sign.ctx_len);
		dptr += op->sign.ctx_len;
		memcpy(dptr, op->sign.msg, op->sign.msg_len);
		dptr += op->sign.msg_len;
		memcpy(dptr, op->verify.signature, pqc_ml_signature_len[op->alg]);
		break;
	default:
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		dao_err("Unsupported PQC type: %d", op->op_type);
#endif
		rte_pktmbuf_free(mbuf);
		liquid_crypto_qp_req_idx_put(qp, req_idx, false);
		return -EINVAL;
	}
	req->hdr.trs_hdr.op_len =
		RTE_MAX(sizeof(struct __dao_lc_req_pqc) + w4.s.dlen, LIQUID_CRYPTO_BUF_SZ_MIN);
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (req->hdr.trs_hdr.op_len > LIQUID_CRYPTO_BUF_SZ_MAX) {
		dao_err("Input data too large. buf_len = %u", req->hdr.trs_hdr.op_len);
		rc = -ENOMEM;
		goto mbuf_free;
	}
#endif
	rc = rte_eth_tx_burst(qp->port_id, qp->queue_id, &mbuf, 1);
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (rc != 1) {
		dao_err("Failed to transmit packet.");
		rc = -EIO;
		goto mbuf_free;
	}
#endif
	return 0;
#ifdef DAO_LIQUID_CRYPTO_DEBUG
mbuf_free:
	rte_pktmbuf_free(mbuf);
idx_put:
	liquid_crypto_qp_req_idx_put(qp, req_idx, false);
	return rc;
#endif
	RTE_SET_USED(rc);
}

static inline void
dao_lc_post_process_pqc(struct liquid_crypto_inflight_req *req, struct dao_lc_res *res,
			struct rte_mbuf *mbuf)
{
	struct __dao_lc_resp_pqc *resp;

	resp = rte_pktmbuf_mtod(mbuf, struct __dao_lc_resp_pqc *);
	memcpy(&res->res, &resp->res, sizeof(union dao_cpt_res_s));

	if (res->res.pqc.compcode == DAO_PQC_COMP_LIB_ERROR_LIBOQS) {
		dao_err("LibOQS library Not Found");
		rte_errno = ENOENT;
		return;
	}

	switch (res->res.pqc.op_type) {
	case DAO_LC_ML_KEM_OP_KEYGEN:
	case DAO_LC_ML_DSA_OP_KEYGEN:
		memcpy(req->keygen.pub_key, resp->rptr, pqc_ml_pub_key_len[res->res.pqc.alg]);
		memcpy(req->keygen.priv_key, resp->rptr + pqc_ml_pub_key_len[res->res.pqc.alg],
		       pqc_ml_priv_key_len[res->res.pqc.alg]);
		break;
	case DAO_LC_ML_KEM_OP_ENCAP:
		memcpy(req->encap.shared_secret, resp->rptr, DAO_LC_ML_KEM_SHARED_SECRET_LEN);
		memcpy(req->encap.ciphertext, resp->rptr + DAO_LC_ML_KEM_SHARED_SECRET_LEN,
		       pqc_ml_ciphertext_len[res->res.pqc.alg]);
		break;
	case DAO_LC_ML_KEM_OP_DECAP:
		memcpy(req->decap.shared_secret, resp->rptr, DAO_LC_ML_KEM_SHARED_SECRET_LEN);
		break;
	case DAO_LC_ML_DSA_OP_SIGN:
		memcpy(req->signature, resp->rptr, pqc_ml_signature_len[res->res.pqc.alg]);
		break;
	case DAO_LC_ML_DSA_OP_VERIFY:
		/* No output data for verify operation */
		break;
	default:
		dao_err("Unsupported PQC operation type: %d", res->res.pqc.op_type);
		rte_errno = EINVAL;
		return;
	}
}

static inline void
dao_lc_post_process_asym(struct liquid_crypto_inflight_req *req, struct dao_lc_res *res,
			 struct rte_mbuf *mbuf)
{
	struct __dao_lc_resp_asym *resp;
	uint8_t prime_len = 0;

	resp = rte_pktmbuf_mtod(mbuf, struct __dao_lc_resp_asym *);
	memcpy(&res->res, &resp->res, sizeof(union dao_cpt_res_s));

	switch (req->op_type) {
	case LC_ASYM_ECDSA_SIGN:
		prime_len = resp->res.cn9k.reserved_17_63;
		res->ecdsa.ecc_rs_out_len = (prime_len * 2);
		memcpy((uint8_t *)req->data_out, resp->rptr, prime_len);
		memcpy((uint8_t *)req->data_out + prime_len,
		       resp->rptr + RTE_ALIGN_CEIL(prime_len, 8), prime_len);
		break;
	case LC_ASYM_ECDSA_VERIFY:
		break;
	default:
		res->rsa.data_out_len = resp->res.cn9k.reserved_17_63;
		memcpy((uint8_t *)req->data_out, resp->rptr, resp->res.cn9k.reserved_17_63);
		break;
	}
}

static inline uint32_t
dao_lc_buf_copy_to_offset_from_mem(uint8_t *src, struct dao_lc_buf *dst, uint32_t offset,
				   uint32_t len)
{
	struct dao_lc_buf *tmp = dst;
	uint32_t copied = 0;
	uint32_t to_copy;

	if (len == 0)
		return 0;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (offset >= dst->total_len) {
		dao_err("Offset (%u) exceeds buffer total length (%u)", offset, dst->total_len);
		return 0;
	}
#endif

	/* Skip to the offset */
	while (tmp && offset >= tmp->frag_len) {
		offset -= tmp->frag_len;
		tmp = tmp->next;
	}

	do {
		to_copy = RTE_MIN(tmp->frag_len - offset, len - copied);

		memcpy((uint8_t *)tmp->data + offset, src + copied, to_copy);
		copied += to_copy;
		tmp = tmp->next;
		/* Reset offset for subsequent fragments */
		offset = 0;
	} while (tmp && copied < len);

	return copied;
}

static inline uint32_t
dao_lc_buf_copy_from_mem(uint8_t *src, struct dao_lc_buf *dst, uint32_t len)
{
	struct dao_lc_buf *tmp = dst;
	uint32_t copied = 0;
	uint32_t to_copy;

	do {
		to_copy = RTE_MIN(tmp->frag_len, len - copied);

		memcpy(tmp->data, src + copied, to_copy);
		copied += to_copy;
		tmp = tmp->next;
	} while (tmp && copied < len);

	return copied;
}

static inline void
dao_lc_post_process_sym(struct liquid_crypto_inflight_req *req, struct dao_lc_res *res,
			struct rte_mbuf *mbuf)
{
	uint32_t result_offset, result_len, lc_buf_offset, copied;
	struct __dao_lc_resp_sym *resp;

	resp = rte_pktmbuf_mtod(mbuf, struct __dao_lc_resp_sym *);
	memcpy(&res->res, &resp->res, sizeof(union dao_cpt_res_s));

	if (res->res.cn9k.uc_compcode != DAO_UC_SUCCESS)
		return;

	/* Auth only post process involves simply copying the digest data to digest buffer. */
	if ((req->sess_meta->op_type == LC_SYM_OP_AUTH_ONLY) ||
	    (req->sess_meta->op_type == LC_SYM_OP_HMAC_AUTH_ONLY)) {
		if (req->is_auth_gen) {
			memcpy(req->digest, resp->rptr, req->digest_len);
		} else {
			int diff = 0;

			diff = memcmp(req->digest, resp->rptr, req->digest_len);
			if (diff != 0)
				res->res.cn9k.uc_compcode = DAO_UC_ERR_GC_ICV_MISCOMPARE;
		}
		return;
	} else if (req->op_type == LC_SYM_OP_KEY_WRAP_UNWRAP) {
		result_len = req->wrap_unwrap_key_len;
		lc_buf_offset = req->lc_buf_offset;
		result_offset = req->result_offset;
		if ((!req->is_wrap) && req->is_wrap_pad)
			/* The length is stored in big-endian format, so convert it
			 */
			result_len =
				rte_be_to_cpu_16(*(uint16_t *)(resp->rptr + result_offset +
							       (req->wrap_unwrap_key_len - 2)));

		copied = dao_lc_buf_copy_to_offset_from_mem(
			resp->rptr + result_offset, req->data_out, lc_buf_offset, result_len);

		res->key_wrap.wrap_unwrap_key_len = result_len;
	} else {
		result_offset = req->result_offset;
		lc_buf_offset = req->lc_buf_offset;

		if (req->digest == NULL) {
			/* Case: Append Digest into the output buffer */
			result_len = req->cipher_len + req->digest_len;
			copied = dao_lc_buf_copy_to_offset_from_mem(resp->rptr + result_offset,
								    req->data_out, lc_buf_offset,
								    result_len);
		} else {
			/* Case: Copy Digest into separate digest buffer case */
			result_len = req->cipher_len;
			copied = dao_lc_buf_copy_to_offset_from_mem(resp->rptr + result_offset,
								    req->data_out, lc_buf_offset,
								    result_len);
			memcpy(req->digest, resp->rptr + result_offset + result_len,
			       req->digest_len);
		}
	}
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (copied != result_len) {
		dao_err("Failed to copy all data from response. "
			"Copied %u bytes, expected %u bytes.",
			copied, result_len);
		rte_errno = EIO;
		return;
	}
#else
	RTE_SET_USED(copied);
#endif
}

static inline uint32_t
dao_lc_buf_copy_from_offset_to_mem(struct dao_lc_buf *src, uint8_t *dst, uint32_t offset,
				   uint32_t len, bool is_zero_len_allowed)
{
	struct dao_lc_buf *tmp = src;
	uint32_t copied = 0;
	uint32_t to_copy;

	/* Skip to the offset */
	while (tmp && offset >= tmp->frag_len) {
		offset -= tmp->frag_len;
		tmp = tmp->next;
	}

	if (tmp == NULL) {
		/* Zero-len input buffer is a valid case for HASH/HMAC and AEAD operations. */
		if (len == 0 && is_zero_len_allowed)
			return 0;

		dao_err("Offset exceeds buffer length");
		return 0;
	}

	do {
		to_copy = RTE_MIN(tmp->frag_len - offset, len - copied);

		memcpy(dst + copied, (uint8_t *)tmp->data + offset, to_copy);
		copied += to_copy;
		tmp = tmp->next;
		/* Reset offset for subsequent fragments */
		offset = 0;
	} while (tmp && copied < len);

	return copied;
}

static inline void
dao_lc_sym_copy_iv(const struct dao_lc_sym_sess_meta *sess_meta, struct dao_lc_sym_op *op,
		   uint8_t *dptr)
{
	const uint8_t ctr_blk[4] = {0x00, 0x00, 0x00, 0x01};
	uint16_t alg_iv_len = sess_meta->alg_iv_len;

	if (sess_meta->pkt_iv_len == alg_iv_len) {
		/* Pass IV as is to microcode */
		memcpy(dptr, op->cipher_iv, alg_iv_len);
	} else if (sess_meta->hash_type == DAO_LC_HASH_TYPE_GMAC) {
		memcpy(dptr, op->auth_iv, alg_iv_len);
		memcpy(dptr + alg_iv_len, ctr_blk, 4);
	} else {
		/* Adjust the IV passed to microcode */
		if (sess_meta->cipher_type == DAO_LC_FC_ENC_CIPHER_AES_CCM) {
			/* flag = (15 - IV_length) - 1 */
			*dptr = (uint8_t)(14 - sess_meta->alg_iv_len);
			memcpy(dptr + 1, op->cipher_iv, alg_iv_len);
		} else if ((sess_meta->cipher_type == DAO_LC_FC_ENC_CIPHER_AES_GCM) ||
			   (sess_meta->cipher_type == DAO_LC_FC_ENC_CIPHER_CHACHA)) {
			memcpy(dptr, op->cipher_iv, alg_iv_len);
			memcpy(dptr + alg_iv_len, ctr_blk, 4);
		}
	}
}

static inline uint16_t
dao_lc_sym_prepare_ops_single_auth_only(struct liquid_crypto_qp *qp, struct dao_lc_sym_op *op,
					struct rte_mbuf *mbuf, uint32_t req_idx,
					const struct dao_lc_sym_sess_meta *sess_meta,
					const enum lc_crypto_op_type op_type)
{
	uint32_t buf_len, auth_len, off_ctrl_len, auth_offset = 0;
	uint16_t hmac_aligned_key_len = 0, pkt_iv_len = 0, dlen;
	struct __dao_lc_req_sym *req;
	uint16_t hmac_key_len = 0;
	uint64_t *offset_vaddr;
	union cpt_inst_w4 w4;
	uint8_t *dptr;

	auth_len = op->auth_len;
	auth_offset = op->auth_offset;

	if (op_type == LC_SYM_OP_HMAC_AUTH_ONLY) {
		hmac_key_len = sess_meta->auth_key_len;
		hmac_aligned_key_len = RTE_ALIGN_CEIL(hmac_key_len, 8);
		dlen = auth_len + hmac_aligned_key_len;
	} else if (sess_meta->hash_type == DAO_LC_HASH_TYPE_GMAC) {
		off_ctrl_len = ROC_SE_OFF_CTRL_LEN;
		pkt_iv_len = sess_meta->pkt_iv_len;
		dlen = off_ctrl_len + pkt_iv_len + auth_len;
	} else {
		dlen = auth_len;
	}

	qp->req_queue[req_idx].digest = op->digest;
	qp->req_queue[req_idx].digest_len = sess_meta->digest_len;
	qp->req_queue[req_idx].op_type = op_type;
	qp->req_queue[req_idx].is_auth_gen = op->auth_gen;

	buf_len = sizeof(struct __dao_lc_req_sym) + dlen;
	buf_len = RTE_MAX(buf_len, LIQUID_CRYPTO_BUF_SZ_MIN);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (buf_len > rte_pktmbuf_tailroom(mbuf)) {
		dao_err("Input data doesn't fit in single segment!");
		rte_errno = ENOMEM;
		return 0;
	}

	if (buf_len > LIQUID_CRYPTO_BUF_SZ_MAX) {
		dao_err("Input data too large. buf_len = %u", buf_len);
		rte_errno = ENOMEM;
		return 0;
	}
#endif

	/* Append transport header to mbuf */
	req = (struct __dao_lc_req_sym *)rte_pktmbuf_append(mbuf, buf_len);
	req->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_SYM;
	req->hdr.req_idx = req_idx;
	req->op_type = LC_SYM_OP_AUTH_ONLY;
	req->is_gmac = 0;
	dptr = req->dptr;

	w4.u64 = sess_meta->w4;
	w4.s.dlen = dlen;

	if (sess_meta->hash_type == DAO_LC_HASH_TYPE_GMAC) {
		req->is_gmac = 1;
		w4.s.param1 = 0;
		w4.s.param2 = auth_len;
		w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_ENCRYPT;
		buf_len += sess_meta->digest_len;

		offset_vaddr = (uint64_t *)dptr;
		*(uint64_t *)offset_vaddr = rte_cpu_to_be_64(
			((uint64_t)pkt_iv_len << 16) | ((uint64_t)0 << 8) | ((uint64_t)pkt_iv_len));
		dptr += off_ctrl_len;

		dao_lc_sym_copy_iv(sess_meta, op, dptr);
		dptr += pkt_iv_len;
	}

	req->hdr.trs_hdr.op_len = buf_len;
	req->w4 = w4.u64;
	req->w7 = DAO_LC_SYM_META_GET_PTR(op->sess_id)->w7;

	/* Add HMAC Authentication Key for HMAC ops */
	if (op_type == LC_SYM_OP_HMAC_AUTH_ONLY)
		memcpy(dptr, sess_meta->auth_key, hmac_key_len);

	/* Add data */
	dao_lc_buf_copy_from_offset_to_mem(op->in_buffer, dptr + hmac_aligned_key_len, auth_offset,
					   auth_len, true);

	return 1;
}

static inline uint16_t
dao_lc_sym_prepare_ops_single_cipher_auth(struct liquid_crypto_qp *qp, struct dao_lc_sym_op *op,
					  struct rte_mbuf *mbuf, uint32_t req_idx,
					  const struct dao_lc_sym_sess_meta *sess_meta,
					  const enum lc_crypto_op_type op_type)
{
	uint32_t buf_len, lc_buf_offset = 0, off_ctrl_len = ROC_SE_OFF_CTRL_LEN;
	uint32_t dlen, cipher_offset, cipher_len, auth_offset, auth_len;
	uint16_t pkt_iv_len, digest_len;
	const uint32_t iv_offset = 0;
	struct __dao_lc_req_sym *req;
	uint64_t *offset_vaddr;
	union cpt_inst_w4 w4;
	uint8_t *dptr;

	cipher_len = op->cipher_len;
	auth_len = op->auth_len;
	cipher_offset = op->cipher_offset;
	auth_offset = op->auth_offset;
	pkt_iv_len = sess_meta->pkt_iv_len;
	digest_len = sess_meta->digest_len;
	qp->req_queue[req_idx].digest = op->digest;
	if (op->encrypt)
		qp->req_queue[req_idx].digest_len = digest_len;

	qp->req_queue[req_idx].op_type = op_type;

	if (op->out_buffer != NULL)
		qp->req_queue[req_idx].data_out = op->out_buffer;
	else
		qp->req_queue[req_idx].data_out = op->in_buffer;

	lc_buf_offset = op->auth_offset;
	/* Input length starting from memory pointed by DPTR */
	dlen = off_ctrl_len + pkt_iv_len + op->in_buffer->total_len - lc_buf_offset;
	if ((op->digest != NULL) || (op->digest == NULL && op->out_buffer != NULL && op->encrypt))
		dlen += digest_len;
	buf_len = sizeof(struct __dao_lc_req_sym) + dlen;
	buf_len = RTE_MAX(buf_len, LIQUID_CRYPTO_BUF_SZ_MIN);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (buf_len > rte_pktmbuf_tailroom(mbuf)) {
		dao_err("Input data doesn't fit in single segment!");
		rte_errno = ENOMEM;
		return 0;
	}

	if (buf_len > LIQUID_CRYPTO_BUF_SZ_MAX) {
		dao_err("Input data too large. buf_len = %u", buf_len);
		rte_errno = ENOMEM;
		return 0;
	}
#endif

	/* Append transport header to mbuf */
	req = (struct __dao_lc_req_sym *)rte_pktmbuf_append(mbuf, buf_len);
	req->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_SYM;
	req->hdr.trs_hdr.op_len = buf_len;
	req->hdr.req_idx = req_idx;
	req->op_type = op_type;

	/* Add instruction */
	w4.u64 = sess_meta->w4;
	w4.s.param1 = cipher_len;
	w4.s.param2 = auth_len;

	if (op->encrypt)
		w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_ENCRYPT;
	else
		w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_DECRYPT;

	if (op->encrypt) {
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		if (dlen < digest_len) {
			dao_err("dlen is less than digest_len. dlen = %u, digest_len = %u", dlen,
				digest_len);
			rte_errno = EINVAL;
			return 0;
		}
#endif
		w4.s.dlen = dlen - digest_len;
	} else {
		w4.s.dlen = dlen;
	}

	req->w4 = w4.u64;
	req->w7 = DAO_LC_SYM_META_GET_PTR(op->sess_id)->w7;

	/* Add data */
	dptr = req->dptr;

	qp->req_queue[req_idx].lc_buf_offset = cipher_offset;
	qp->req_queue[req_idx].cipher_len = cipher_len;

	cipher_offset = iv_offset + pkt_iv_len + (cipher_offset - auth_offset);
	auth_offset = iv_offset + pkt_iv_len;

	qp->req_queue[req_idx].result_offset = cipher_offset;

	if (off_ctrl_len != 0) {
		offset_vaddr = (uint64_t *)dptr;

		/**
		 * TODO: For some algorithms, IV length can be specified as part of
		 * OFFSET_CTRL_WORD Bits 36:32
		 */
		*(uint64_t *)offset_vaddr =
			rte_cpu_to_be_64(((uint64_t)cipher_offset << 16) |
					 ((uint64_t)iv_offset << 8) | ((uint64_t)auth_offset));
		dptr += off_ctrl_len;
	}
	dptr += iv_offset;

	dao_lc_sym_copy_iv(sess_meta, op, dptr);
	dptr += pkt_iv_len;

	dao_lc_buf_copy_from_offset_to_mem(op->in_buffer, dptr, lc_buf_offset,
					   op->in_buffer->total_len - lc_buf_offset, true);

	if ((!op->encrypt) && (op->digest != NULL && digest_len != 0))
		memcpy(dptr + op->in_buffer->total_len - lc_buf_offset, op->digest, digest_len);

	return 1;
}

static inline uint16_t
dao_lc_sym_prepare_ops_single(struct liquid_crypto_qp *qp, struct dao_lc_sym_op *op,
			      struct rte_mbuf *mbuf, uint32_t req_idx,
			      const struct dao_lc_sym_sess_meta *sess_meta,
			      const enum lc_crypto_op_type op_type)
{
	uint32_t buf_len, lc_buf_offset = 0, off_ctrl_len = ROC_SE_OFF_CTRL_LEN;
	uint32_t dlen, cipher_offset, cipher_len, auth_offset, auth_len;
	uint16_t pkt_iv_len, aad_len, digest_len;
	const uint32_t iv_offset = 0;
	struct __dao_lc_req_sym *req;
	bool is_aead_op_type = false;
	uint64_t *offset_vaddr;
	union cpt_inst_w4 w4;
	uint8_t *dptr;

	if (op_type == LC_SYM_OP_CIPHER_ONLY) {
		aad_len = 0;
		cipher_len = op->cipher_len;
		auth_len = 0;
		pkt_iv_len = sess_meta->pkt_iv_len;
		digest_len = 0;
	} else if (op_type == LC_SYM_OP_AEAD) {
		is_aead_op_type = true;
		aad_len = op->aad_len;
		cipher_len = op->cipher_len;
		auth_len = cipher_len + aad_len;
		pkt_iv_len = sess_meta->pkt_iv_len;
		digest_len = sess_meta->digest_len;
		qp->req_queue[req_idx].digest = op->digest;
		if (op->encrypt)
			qp->req_queue[req_idx].digest_len = digest_len;
	} else {
		dao_err("Invalid operation type: %d", op_type);
		rte_errno = EINVAL;
		return 0;
	}

	qp->req_queue[req_idx].op_type = op_type;

	if (op->out_buffer != NULL)
		qp->req_queue[req_idx].data_out = op->out_buffer;
	else
		qp->req_queue[req_idx].data_out = op->in_buffer;

	lc_buf_offset = op->cipher_offset;
	/* Input length starting from memory pointed by DPTR */
	dlen = off_ctrl_len + pkt_iv_len + aad_len + op->in_buffer->total_len - lc_buf_offset;
	if ((op->digest != NULL) || (op->digest == NULL && op->out_buffer != NULL && op->encrypt))
		dlen += digest_len;
	buf_len = sizeof(struct __dao_lc_req_sym) + dlen;
	buf_len = RTE_MAX(buf_len, LIQUID_CRYPTO_BUF_SZ_MIN);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (buf_len > rte_pktmbuf_tailroom(mbuf)) {
		dao_err("Input data doesn't fit in single segment!");
		rte_errno = ENOMEM;
		return 0;
	}

	if (buf_len > LIQUID_CRYPTO_BUF_SZ_MAX) {
		dao_err("Input data too large. buf_len = %u", buf_len);
		rte_errno = ENOMEM;
		return 0;
	}
#endif

	/* Append transport header to mbuf */
	req = (struct __dao_lc_req_sym *)rte_pktmbuf_append(mbuf, buf_len);
	req->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_SYM;
	req->hdr.trs_hdr.op_len = buf_len;
	req->hdr.req_idx = req_idx;
	req->op_type = op_type;

	/* Add instruction */
	w4.u64 = sess_meta->w4;
	w4.s.param1 = cipher_len;
	w4.s.param2 = auth_len;

	if (op->encrypt)
		w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_ENCRYPT;
	else
		w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_DECRYPT;

	if (op->encrypt) {
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		if (dlen < digest_len) {
			dao_err("dlen is less than digest_len. dlen = %u, digest_len = %u", dlen,
				digest_len);
			rte_errno = EINVAL;
			return 0;
		}
#endif
		w4.s.dlen = dlen - digest_len;
	} else {
		w4.s.dlen = dlen;
	}

	req->w4 = w4.u64;
	req->w7 = DAO_LC_SYM_META_GET_PTR(op->sess_id)->w7;

	/* Add data */
	dptr = req->dptr;

	qp->req_queue[req_idx].lc_buf_offset = lc_buf_offset;
	qp->req_queue[req_idx].cipher_len = cipher_len;

	cipher_offset = iv_offset + pkt_iv_len + aad_len;
	auth_offset = iv_offset + pkt_iv_len;

	qp->req_queue[req_idx].result_offset = cipher_offset;

	if (off_ctrl_len != 0) {
		offset_vaddr = (uint64_t *)dptr;

		/**
		 * TODO: For some algorithms, IV length can be specified as part of
		 * OFFSET_CTRL_WORD Bits 36:32
		 */
		*(uint64_t *)offset_vaddr =
			rte_cpu_to_be_64(((uint64_t)cipher_offset << 16) |
					 ((uint64_t)iv_offset << 8) | ((uint64_t)auth_offset));
		dptr += off_ctrl_len;
	}
	dptr += iv_offset;

	dao_lc_sym_copy_iv(sess_meta, op, dptr);
	dptr += pkt_iv_len;

	if (op_type == LC_SYM_OP_AEAD) {
		/* Copy AAD */
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		if ((iv_offset + pkt_iv_len + aad_len) > buf_len) {
			dao_err("Buffer Length is too small to fit AAD. buf_len = %u", buf_len);
			rte_errno = ENOMEM;
			return 0;
		}
#endif
		if (aad_len != 0)
			memcpy(dptr, op->aad, aad_len);
		dptr += aad_len;
	}

	dao_lc_buf_copy_from_offset_to_mem(op->in_buffer, dptr, lc_buf_offset,
					   op->in_buffer->total_len - lc_buf_offset,
					   is_aead_op_type);

	if ((!op->encrypt) && (op->digest != NULL && digest_len != 0))
		memcpy(dptr + op->in_buffer->total_len - lc_buf_offset, op->digest, digest_len);

	return 1;
}

static inline uint16_t
dao_lc_sym_prepare_ops_single_keywrap(struct liquid_crypto_qp *qp, struct dao_lc_sym_op *op,
				      struct rte_mbuf *mbuf, uint32_t req_idx,
				      const struct dao_lc_sym_sess_meta *sess_meta,
				      const enum lc_crypto_op_type op_type)
{
	uint32_t buf_len, dlen, kek_len, key_len, pad_key_len;
	struct __dao_lc_req_sym *req;
	uint32_t lc_buf_offset = 0;
	union cpt_inst_w4 w4;
	uint8_t *dptr;

	kek_len = sess_meta->kek_len;
	lc_buf_offset = op->cipher_offset;
	key_len = op->wrap_unwrap_key_len;
	pad_key_len = key_len;
	dlen = key_len + kek_len;

	if (!(op->is_wrap_pad)) {
		if (key_len < 16) {
			dao_err("Invalid key length. Key length must be at least 16 bytes for AES-KW.");
			return -EINVAL;
		}
	}

	if (op->out_buffer != NULL)
		qp->req_queue[req_idx].data_out = op->out_buffer;
	else
		qp->req_queue[req_idx].data_out = op->in_buffer;

	qp->req_queue[req_idx].op_type = op_type;
	qp->req_queue[req_idx].lc_buf_offset = lc_buf_offset;
	qp->req_queue[req_idx].result_offset = 0;
	qp->req_queue[req_idx].is_wrap = op->is_wrap;
	qp->req_queue[req_idx].is_wrap_pad = op->is_wrap_pad;

	if (op->is_wrap_pad) {
		if (op->is_wrap)
			/* Pad to next multiple of 8 bytes */
			pad_key_len = RTE_ALIGN_CEIL(key_len, 8);
		else
			/* Reserve 2 extra bytes for AES KWP unwrap data length */
			pad_key_len = pad_key_len + 2;
	}

	if (op->is_wrap)
		qp->req_queue[req_idx].wrap_unwrap_key_len =
			pad_key_len + DAO_LC_AES_KEY_WRAP_IV_LEN;
	else
		qp->req_queue[req_idx].wrap_unwrap_key_len =
			pad_key_len - DAO_LC_AES_KEY_WRAP_IV_LEN;

	buf_len = sizeof(struct __dao_lc_req_sym) + dlen;
	buf_len = RTE_MAX(buf_len, LIQUID_CRYPTO_BUF_SZ_MIN);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (buf_len > rte_pktmbuf_tailroom(mbuf)) {
		dao_err("Input data doesn't fit in single segment!");
		rte_errno = ENOMEM;
		return 0;
	}

	if (buf_len > LIQUID_CRYPTO_BUF_SZ_MAX) {
		dao_err("Input data is too large. buf_len = %u", buf_len);
		rte_errno = ENOMEM;
		return 0;
	}
#endif

	/* Append transport header to mbuf */
	req = (struct __dao_lc_req_sym *)rte_pktmbuf_append(mbuf, buf_len);
	req->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_SYM;
	req->hdr.trs_hdr.op_len = buf_len;
	req->hdr.req_idx = req_idx;
	req->op_type = LC_SYM_OP_KEY_WRAP_UNWRAP;

	/* Add instruction */
	w4.u64 = sess_meta->w4;
	w4.s.param1 = key_len;
	w4.s.dlen = dlen;
	w4.s.opcode_minor |= (((!op->is_wrap) << 1) | ((op->is_wrap_pad ? 1 : 0) << 0));
	req->w4 = w4.u64;
	req->w7 = DAO_LC_SYM_META_GET_PTR(op->sess_id)->w7;

	/* Add KEK */
	dptr = req->dptr;
	memcpy(dptr, sess_meta->kek, kek_len);
	dptr += kek_len;

	/* Add data */
	dao_lc_buf_copy_from_offset_to_mem(op->in_buffer, dptr, lc_buf_offset,
					   op->in_buffer->total_len - lc_buf_offset, false);

	return 1;
}

static inline uint16_t
dao_lc_sym_prepare_ops(struct liquid_crypto_qp *qp, struct dao_lc_sym_op *ops,
		       struct rte_mbuf **mbufs, uint32_t *req_idxs, uint16_t nb_ops)
{
	struct dao_lc_sym_sess_meta *sess_meta;
	enum lc_crypto_op_type op_type;
	struct dao_lc_sym_op *op;
	uint32_t req_idx;
	uint16_t i;
	int ret;

	for (i = 0; i < nb_ops; i++) {
		op = &ops[i];
		req_idx = req_idxs[i];

		if (lc_debug_enabled()) {
			ret = lc_sym_op_validate(op);
			if (ret) {
				rte_errno = -ret;
				return 0;
			}
		}

		sess_meta = DAO_LC_SYM_META_GET_PTR(op->sess_id);
		lc_inflight_req_reset(&qp->req_queue[req_idx]);
		qp->req_queue[req_idx].op_cookie = op->op_cookie;
		qp->req_queue[req_idx].sess_meta = sess_meta;

		op_type = sess_meta->op_type;

		switch (op_type) {
		case LC_SYM_OP_CIPHER_ONLY:
			ret = dao_lc_sym_prepare_ops_single(qp, op, mbufs[i], req_idx, sess_meta,
							    LC_SYM_OP_CIPHER_ONLY);
			break;
		case LC_SYM_OP_AUTH_ONLY:
			ret = dao_lc_sym_prepare_ops_single_auth_only(
				qp, op, mbufs[i], req_idx, sess_meta, LC_SYM_OP_AUTH_ONLY);
			break;
		case LC_SYM_OP_CIPHER_AUTH:
			ret = dao_lc_sym_prepare_ops_single_cipher_auth(
				qp, op, mbufs[i], req_idx, sess_meta, LC_SYM_OP_CIPHER_AUTH);
			break;
		case LC_SYM_OP_HMAC_AUTH_ONLY:
			ret = dao_lc_sym_prepare_ops_single_auth_only(
				qp, op, mbufs[i], req_idx, sess_meta, LC_SYM_OP_HMAC_AUTH_ONLY);
			break;
		case LC_SYM_OP_KEY_WRAP_UNWRAP:
			ret = dao_lc_sym_prepare_ops_single_keywrap(
				qp, op, mbufs[i], req_idx, sess_meta, LC_SYM_OP_KEY_WRAP_UNWRAP);
			break;
		default:
			/* LC_SYM_OP_AEAD */
			ret = dao_lc_sym_prepare_ops_single(qp, op, mbufs[i], req_idx, sess_meta,
							    LC_SYM_OP_AEAD);
			break;
		}

		RTE_SET_USED(ret);
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		if (ret == 0) {
			/* Prepare operation failed, return the number of successful operations */
			return i;
		}
#endif
	}

	return nb_ops;
}

uint16_t
dao_liquid_crypto_sym_enqueue_burst(uint8_t dev_id, uint16_t qp_id, struct dao_lc_sym_op *ops,
				    uint16_t nb_ops)
{
	struct rte_mbuf *mbufs[LIQUID_CRYPTO_MAX_BURST];
	uint32_t req_idxs[LIQUID_CRYPTO_MAX_BURST];
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	uint16_t i = 0, tx_cnt = 0;
	int rc = 0;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		rte_errno = EINVAL;
		goto exit;
	}
#endif

	dev = &liquid_crypto_devs[dev_id];

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (qp_id >= dev->nb_qp) {
		dao_err("Invalid argument. qp_id must be between 0 and %u.", dev->nb_qp - 1);
		rte_errno = EINVAL;
		goto exit;
	}

	if (qp_id == dev->cmd_qp_idx) {
		dao_err("Invalid argument. qp_id cannot be the command queue index.");
		rte_errno = EINVAL;
		goto exit;
	}

	if (!dev->is_started) {
		dao_err("Invalid device. Device(%d) not started.", dev_id);
		rte_errno = EINVAL;
		goto exit;
	}

	if (ops == NULL) {
		dao_err("Invalid argument. ops cannot be NULL.");
		rte_errno = EINVAL;
		goto exit;
	}
#endif

	qp = dev->qp[qp_id];

	nb_ops = RTE_MIN(nb_ops, LIQUID_CRYPTO_MAX_BURST);

	for (i = 0; i < nb_ops; i++) {
		req_idxs[i] = liquid_crypto_qp_req_idx_get(qp, false);

		if (unlikely(req_idxs[i] == UINT32_MAX)) {
#ifdef DAO_LIQUID_CRYPTO_DEBUG
			dao_err("No available request index.");
#endif
			nb_ops = i;
			break;
		}
	}

	if (unlikely(nb_ops == 0))
		goto exit;

	rc = rte_pktmbuf_alloc_bulk(qp->tx_mp, mbufs, nb_ops);
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (unlikely(rc != 0)) {
		dao_err("Could not allocate mbufs.");
		rte_errno = ENOMEM;
		goto put_req_idx;
	}
#endif

	i = dao_lc_sym_prepare_ops(qp, ops, mbufs, req_idxs, nb_ops);

	tx_cnt = rte_eth_tx_burst(qp->port_id, qp->queue_id, mbufs, i);
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	/* Free mbufs that are not transmitted. */
	if (tx_cnt != i) {
		dao_err("Could not transmit all packets.");
		rte_errno = EIO;
		goto mbuf_free;
	}

	/* Free remaining mbufs if not all instructions are submitted. */
	if (nb_ops != i)
		goto mbuf_free;
#endif

	return tx_cnt;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
mbuf_free:
	rte_pktmbuf_free_bulk(mbufs + tx_cnt, nb_ops - tx_cnt);
	for (i = tx_cnt; i < nb_ops; i++)
		mbufs[i] = NULL;

put_req_idx:
	for (i = tx_cnt; i < nb_ops; i++)
		liquid_crypto_qp_req_idx_put(qp, req_idxs[i], false);

	return tx_cnt;

#endif
exit:
	RTE_SET_USED(rc);
	return 0;
}

static inline void
dao_lc_post_process_rng(struct liquid_crypto_inflight_req *req, struct dao_lc_res *res,
			struct rte_mbuf *mbuf)
{
	struct __dao_lc_resp_sym *resp = rte_pktmbuf_mtod(mbuf, struct __dao_lc_resp_sym *);
	uint32_t out_len;

	memcpy(&res->res, &resp->res, sizeof(union dao_cpt_res_s));
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (req->data_out == NULL) {
		dao_err("Invalid output buffer pointer for RNG operation.");
		rte_errno = EINVAL;
		return;
	}
#endif
	/* For RNG, we just copy the data to the output buffer */
	out_len = rte_pktmbuf_pkt_len(mbuf) - sizeof(struct __dao_lc_resp_sym);
	dao_lc_buf_copy_from_mem(resp->rptr, req->data_out, out_len);
}

uint16_t
dao_liquid_crypto_dequeue_burst(uint8_t dev_id, uint16_t qp_id, struct dao_lc_res *res,
				uint16_t nb_res)
{
	struct rte_mbuf *mbuf, *mbufs[LIQUID_CRYPTO_MAX_BURST];
	struct liquid_crypto_inflight_req *req;
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	struct __dao_lc_hdr *lc_hdr;
	uint16_t nb_rx = 0, i;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		rte_errno = EINVAL;
		goto exit;
	}

	if (res == NULL) {
		dao_err("Invalid argument. res cannot be NULL.");
		rte_errno = EINVAL;
		goto exit;
	}
#endif

	dev = &liquid_crypto_devs[dev_id];

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (qp_id >= dev->nb_qp) {
		dao_err("Invalid argument. qp_id must be between 0 and %u.", dev->nb_qp - 1);
		rte_errno = EINVAL;
		goto exit;
	}

	if (qp_id == dev->cmd_qp_idx) {
		dao_err("Invalid argument. qp_id cannot be the command queue index.");
		rte_errno = EINVAL;
		goto exit;
	}

	if (!dev->is_started) {
		dao_err("Invalid device. Device(%d) not started.", dev_id);
		rte_errno = EINVAL;
		goto exit;
	}
#endif
	qp = dev->qp[qp_id];

	nb_res = RTE_MIN(nb_res, LIQUID_CRYPTO_MAX_BURST);
	nb_rx = rte_eth_rx_burst(qp->port_id, qp->queue_id, mbufs, nb_res);

	for (i = 0; i < nb_rx; i++) {
		mbuf = mbufs[i];

		lc_hdr = rte_pktmbuf_mtod(mbuf, struct __dao_lc_hdr *);

		req = &qp->req_queue[lc_hdr->req_idx];

		/* Process the packet base on op_type */
		switch (lc_hdr->trs_hdr.op_type) {
		case DAO_ETH_TRS_OP_TYPE_REFLECT:
			break;
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_START:
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_MISC:
			break;
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_SYM:
			dao_lc_post_process_sym(req, &res[i], mbuf);
			break;
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_ASYM:
			dao_lc_post_process_asym(req, &res[i], mbuf);
			break;
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_RNG:
			dao_lc_post_process_rng(req, &res[i], mbuf);
			break;
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_OAEP_ENC:
			dao_lc_post_process_asym(req, &res[i], mbuf);
			break;
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_OAEP_DEC:
			dao_lc_post_process_asym(req, &res[i], mbuf);
			break;
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_PQC:
			dao_lc_post_process_pqc(req, &res[i], mbuf);
			break;
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_END:
		default:
			dao_err("Invalid op_type.");
			break;
		}

		res[i].op_cookie = req->op_cookie;

		rte_pktmbuf_free(mbuf);

		/* Free the request index */
		liquid_crypto_qp_req_idx_put(qp, lc_hdr->req_idx, false);
	}

	return nb_rx;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
exit:
	dao_err("Could not receive any packets. rte_errno = %d", rte_errno);
	return 0;
#endif
}

int
dao_liquid_crypto_sym_sess_create(uint8_t dev_id, const struct dao_lc_sym_ctx *ctx,
				  uint64_t op_cookie)
{
	struct dao_lc_sym_sess_meta *sess_meta;
	struct __dao_lc_req_sess_create *req;
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	struct rte_mbuf *mb;
	uint32_t req_idx;
	uint16_t buf_len;
	int rc;

	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}

	if (ctx == NULL) {
		dao_err("Invalid argument. ctx cannot be NULL.");
		return -EINVAL;
	}

	dev = &liquid_crypto_devs[dev_id];

	const uint16_t qp_id = dev->cmd_qp_idx;

	if (qp_id == DAO_CMD_QP_IDX_INVALID) {
		dao_err("Command queue is disabled!");
		return -EINVAL;
	}

	if (!dev->is_started) {
		dao_err("Invalid device. Device(%d) not started.", dev_id);
		return -EINVAL;
	}

	qp = dev->qp[qp_id];

	rc = liquid_crypto_sym_sess_verify(ctx);
	if (rc != 0)
		return rc;

	sess_meta = liquid_crypto_sym_sess_meta_alloc(ctx);
	if (sess_meta == NULL) {
		dao_err("Could not allocate session metadata.");
		return -ENOMEM;
	}

	req_idx = liquid_crypto_qp_req_idx_get(qp, true);

	if (unlikely(req_idx == UINT32_MAX)) {
		dao_err("No available request index.");
		rc = -ENOSPC;
		goto sess_meta_free;
	}

	lc_inflight_req_reset(&qp->req_queue[req_idx]);
	qp->req_queue[req_idx].op_cookie = op_cookie;
	qp->req_queue[req_idx].sess_meta = sess_meta;

	mb = rte_pktmbuf_alloc(qp->tx_mp);
	if (unlikely(mb == NULL)) {
		dao_err("Could not allocate mbuf.");
		rc = -ENOMEM;
		goto idx_put;
	}

	buf_len = sizeof(struct __dao_lc_req_sess_create) + sizeof(struct dao_lc_sym_ctx);
	buf_len = RTE_MAX(buf_len, LIQUID_CRYPTO_BUF_SZ_MIN);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (buf_len > rte_pktmbuf_tailroom(mb)) {
		dao_err("Input data doesn't fit in single segment!");
		rc = -ENOMEM;
		goto mbuf_free;
	}

	if (buf_len > LIQUID_CRYPTO_BUF_SZ_MAX) {
		dao_err("Input data too large. buf_len = %u", buf_len);
		rc = -ENOMEM;
		goto mbuf_free;
	}
#endif

	rte_pktmbuf_append(mb, buf_len);

	req = rte_pktmbuf_mtod(mb, struct __dao_lc_req_sess_create *);
	req->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_SYM_SESSION_CREATE;
	req->hdr.trs_hdr.op_len = buf_len;
	req->hdr.req_idx = req_idx;
	req->opcode = ctx->opcode;

	memcpy(req->cptr, &ctx->fc, sizeof(ctx->fc));

	rc = rte_eth_tx_burst(qp->port_id, qp->queue_id, &mb, 1);
	if (rc != 1) {
		dao_err("Failed to transmit packet.");
		rc = -EIO;
		goto mbuf_free;
	}

	return 0;

mbuf_free:
	rte_pktmbuf_free(mb);
idx_put:
	liquid_crypto_qp_req_idx_put(qp, req_idx, true);
sess_meta_free:
	liquid_crypto_sym_sess_meta_free(sess_meta);

	return rc;
}

int
dao_liquid_crypto_sym_sess_destroy(uint8_t dev_id, uint64_t sess_id, uint64_t sess_cookie)
{
	struct __dao_lc_req_resp_sess_destroy *req;
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	struct rte_mbuf *mb;
	uint32_t req_idx;
	uint16_t buf_len;
	int rc;

	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}

	if (sess_id == DAO_LC_SESS_ID_INVALID) {
		dao_err("Invalid argument. Need a valid sess_id.");
		return -EINVAL;
	}

	if (liquid_crypto_sym_sess_meta_lookup(sess_id) != 0) {
		dao_err("Invalid argument. sess_id not found.");
		return -EINVAL;
	}

	dev = &liquid_crypto_devs[dev_id];

	const uint16_t qp_id = dev->cmd_qp_idx;

	if (qp_id == DAO_CMD_QP_IDX_INVALID) {
		dao_err("Command queue is disabled!");
		return -EINVAL;
	}

	if (!dev->is_started) {
		dao_err("Invalid device. Device(%d) not started.", dev_id);
		return -EINVAL;
	}

	qp = dev->qp[qp_id];

	req_idx = liquid_crypto_qp_req_idx_get(qp, true);

	if (unlikely(req_idx == UINT32_MAX)) {
		dao_err("No available request index.");
		return -ENOSPC;
	}

	lc_inflight_req_reset(&qp->req_queue[req_idx]);
	qp->req_queue[req_idx].op_cookie = sess_cookie;

	mb = rte_pktmbuf_alloc(qp->tx_mp);
	if (unlikely(mb == NULL)) {
		dao_err("Could not allocate mbuf.");
		rc = -ENOMEM;
		goto idx_put;
	}

	buf_len = sizeof(struct __dao_lc_req_resp_sess_destroy);
	buf_len = RTE_MAX(buf_len, LIQUID_CRYPTO_BUF_SZ_MIN);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (buf_len > rte_pktmbuf_tailroom(mb)) {
		dao_err("Input data doesn't fit in single segment!");
		rc = -ENOMEM;
		goto mbuf_free;
	}

	if (buf_len > LIQUID_CRYPTO_BUF_SZ_MAX) {
		dao_err("Input data too large. buf_len = %u", buf_len);
		rc = -ENOMEM;
		goto mbuf_free;
	}
#endif

	req = (struct __dao_lc_req_resp_sess_destroy *)rte_pktmbuf_append(mb, buf_len);
	req->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_SYM_SESSION_DESTROY;
	req->hdr.trs_hdr.op_len = sizeof(struct __dao_lc_req_resp_sess_destroy);
	req->hdr.req_idx = req_idx;
	req->sess_id = DAO_LC_SYM_META_GET_PTR(sess_id)->w7;

	rc = rte_eth_tx_burst(qp->port_id, qp->queue_id, &mb, 1);

	if (rc != 1) {
		dao_err("Failed to transmit packet.");
		rc = -EIO;
		goto mbuf_free;
	}

	return 0;

mbuf_free:
	rte_pktmbuf_free(mb);
idx_put:
	liquid_crypto_qp_req_idx_put(qp, req_idx, true);
	return rc;
}

uint16_t
dao_liquid_crypto_cmd_event_dequeue(uint8_t dev_id, struct dao_lc_cmd_event *events,
				    uint16_t nb_events)
{
	struct rte_mbuf *mbuf, *mbufs[LIQUID_CRYPTO_MAX_BURST];
	struct __dao_lc_req_resp_sess_destroy *sess_destroy;
	struct __dao_lc_resp_sess_create *sess_create;
	struct liquid_crypto_inflight_req *req;
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	struct __dao_lc_hdr *lc_hdr;
	uint16_t nb_rx, i;

	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		rte_errno = EINVAL;
		return 0;
	}

	if (events == NULL) {
		dao_err("Invalid argument. events cannot be NULL.");
		rte_errno = EINVAL;
		return 0;
	}

	dev = &liquid_crypto_devs[dev_id];

	const uint16_t qp_id = dev->cmd_qp_idx;

	if (qp_id == DAO_CMD_QP_IDX_INVALID) {
		dao_err("Command queue is disabled!");
		rte_errno = EINVAL;
		return 0;
	}

	if (!dev->is_started) {
		dao_err("Invalid device. Device(%d) not started.", dev_id);
		rte_errno = EINVAL;
		return 0;
	}

	qp = dev->qp[qp_id];

	nb_events = RTE_MIN(nb_events, LIQUID_CRYPTO_MAX_BURST);
	nb_rx = rte_eth_rx_burst(qp->port_id, qp->queue_id, mbufs, nb_events);

	for (i = 0; i < nb_rx; i++) {
		mbuf = mbufs[i];

		lc_hdr = rte_pktmbuf_mtod(mbuf, struct __dao_lc_hdr *);

		req = &qp->req_queue[lc_hdr->req_idx];

		/* Process the packet base on op_type */
		switch (lc_hdr->trs_hdr.op_type) {
		case DAO_ETH_TRS_OP_TYPE_SYM_SESSION_CREATE:
			sess_create = rte_pktmbuf_mtod(mbuf, struct __dao_lc_resp_sess_create *);
			events[i].event_type = DAO_LC_CMD_EVENT_SESS_CREATE;
			events[i].sess_event.sess_cookie = req->op_cookie;
			if (sess_create->sess_id == DAO_LC_SESS_ID_INVALID) {
				events[i].sess_event.sess_id = DAO_LC_SESS_ID_INVALID;
				dao_err("Could not create session.");
			} else {
				events[i].sess_event.sess_id = (uint64_t)req->sess_meta;
				liquid_crypto_sym_sess_meta_insert(req->sess_meta,
								   sess_create->sess_id);
			}
			break;
		case DAO_ETH_TRS_OP_TYPE_SYM_SESSION_DESTROY:
			sess_destroy =
				rte_pktmbuf_mtod(mbuf, struct __dao_lc_req_resp_sess_destroy *);
			events[i].event_type = DAO_LC_CMD_EVENT_SESS_DESTROY;
			events[i].sess_event.sess_cookie = req->op_cookie;
			liquid_crypto_sym_sess_meta_remove(sess_destroy->sess_id,
							   &events[i].sess_event.sess_id);
			break;
		default:
			dao_err("Invalid op_type.");
			break;
		}

		rte_pktmbuf_free(mbuf);

		/* Free the request index */
		liquid_crypto_qp_req_idx_put(qp, lc_hdr->req_idx, true);
	}

	return nb_rx;
}

int
dao_liquid_crypto_enq_op_random(uint8_t dev_id, uint16_t qp_id, struct dao_lc_random_op *op)
{
	uint16_t buf_len, rand_len_max;
	struct liquid_crypto_dev *dev;
	struct __dao_lc_req_sym *req;
	struct liquid_crypto_qp *qp;
	struct rte_mbuf *mbuf;
	uint32_t req_idx = 0;
	union cpt_inst_w4 w4;
	union cpt_inst_w7 w7;
	int rc;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}
#endif

	dev = &liquid_crypto_devs[dev_id];

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (qp_id >= dev->nb_qp) {
		dao_err("Invalid argument. qp_id must be between 0 and %u.", dev->nb_qp - 1);
		return -EINVAL;
	}

	if (qp_id == dev->cmd_qp_idx) {
		dao_err("Invalid argument. qp_id cannot be the command queue index.");
		return -EINVAL;
	}

	if (!dev->is_started) {
		dao_err("Invalid device. Device(%d) not started.", dev_id);
		return -EINVAL;
	}

	if (op == NULL) {
		dao_err("Invalid argument. op cannot be NULL.");
		return -EINVAL;
	}

	rand_len_max = LIQUID_CRYPTO_RAND_LEN_MAX;
	if (op->rand_len == 0 || op->rand_len > rand_len_max) {
		dao_err("Invalid argument. rand_len must be between 1 and %u.", rand_len_max);
		return -EINVAL;
	}
#endif
	if (lc_debug_enabled()) {
		rc = lc_buf_validate(op->out_buf, false);
		if (rc != 0) {
			dao_err("Invalid output buffer.");
			return rc;
		}
	}

	if (op->type != DAO_LC_RANDOM_TYPE_HW) {
		dao_err("Invalid argument. Only HW RANDOM type is supported.");
		return -EINVAL;
	}

	qp = dev->qp[qp_id];

	req_idx = liquid_crypto_qp_req_idx_get(qp, false);

	if (unlikely(req_idx == UINT32_MAX)) {
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		dao_err("No available request index.");
#endif
		return -ENOSPC;
	}

	mbuf = rte_pktmbuf_alloc(qp->tx_mp);
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (unlikely(mbuf == NULL)) {
		dao_err("Could not allocate mbuf.");
		rc = -ENOMEM;
		goto idx_put;
	}
#endif

	lc_inflight_req_reset(&qp->req_queue[req_idx]);
	qp->req_queue[req_idx].op_cookie = op->op_cookie;
	qp->req_queue[req_idx].data_out = op->out_buf;

	/* TODO: For now support only HW RANDOM. No input required. */
	buf_len =
		RTE_MAX((sizeof(struct __dao_lc_req_sym) + op->rand_len), LIQUID_CRYPTO_BUF_SZ_MIN);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (buf_len > rte_pktmbuf_tailroom(mbuf)) {
		dao_err("Input data doesn't fit in single segment!");
		rc = -ENOMEM;
		goto mbuf_free;
	}

	if (buf_len > LIQUID_CRYPTO_BUF_SZ_MAX) {
		dao_err("Input data too large. buf_len = %u", buf_len);
		rc = -ENOMEM;
		goto mbuf_free;
	}
#endif

	req = (struct __dao_lc_req_sym *)rte_pktmbuf_append(mbuf, buf_len);
	req->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_RNG;
	req->hdr.trs_hdr.op_len = buf_len;
	req->hdr.req_idx = req_idx;

	/* Add instruction */
	w4.u64 = 0;
	w4.s.param1 = op->rand_len;
	w4.s.dlen = op->rand_len;

	w4.s.opcode_major = ROC_SE_MAJOR_OP_RANDOM;
	w4.s.opcode_minor = ROC_SE_MINOR_OP_RANDOM_HW_RANDOM;

	w7.u64 = 0;
	w7.s.egrp = ROC_LEGACY_CPT_DFLT_ENG_GRP_SE;

	req->w4 = w4.u64;
	req->w7 = w7.u64;
	rc = rte_eth_tx_burst(qp->port_id, qp->queue_id, &mbuf, 1);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (rc != 1) {
		dao_err("Failed to transmit packet.");
		rc = -EIO;
		goto mbuf_free;
	}
#endif

	return 0;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
mbuf_free:
	rte_pktmbuf_free(mbuf);
idx_put:
	liquid_crypto_qp_req_idx_put(qp, req_idx, false);
#endif
	RTE_SET_USED(rand_len_max);

	return rc;
}

int
dao_liquid_crypto_enq_op_ecdsa_sign(uint8_t dev_id, uint16_t qp_id,
				    enum dao_liquid_crypto_ec_curve_type curve_id,
				    uint16_t nonce_len, uint16_t pkey_len, uint16_t digest_len,
				    const uint8_t *nonce, const uint8_t *pkey,
				    const uint8_t *digest_data, uint8_t *rs_outdata,
				    uint64_t op_cookie)
{
	uint32_t p_align, nonce_align, m_align;
	struct __dao_lc_req_asym *req;
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	uint32_t req_idx = 0, dlen;
	int pk_offset, prime_len;
	struct rte_mbuf *mbuf;
	union cpt_inst_w4 w4;
	uint16_t buf_len;
	uint8_t *dptr;
	int rc;

	prime_len = ecc_curve_id_to_prime_len(curve_id);
	if (prime_len < 0) {
		dao_err("Invalid curve_id (%d).", curve_id);
		return -EINVAL;
	}

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}
#endif

	dev = &liquid_crypto_devs[dev_id];

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (qp_id >= dev->nb_qp) {
		dao_err("Invalid argument. qp_id must be between 0 and %u.", dev->nb_qp - 1);
		return -EINVAL;
	}

	if (qp_id == dev->cmd_qp_idx) {
		dao_err("Invalid argument. qp_id cannot be the command queue index.");
		return -EINVAL;
	}

	if (!dev->is_started) {
		dao_err("Invalid device. Device(%d) not started.", dev_id);
		return -EINVAL;
	}

	if (nonce == NULL) {
		dao_err("Invalid argument. nonce cannot be NULL.");
		return -EINVAL;
	}

	if (pkey == NULL) {
		dao_err("Invalid argument. pkey cannot be NULL.");
		return -EINVAL;
	}

	if (digest_data == NULL) {
		dao_err("Invalid argument. digest_data cannot be NULL.");
		return -EINVAL;
	}

	if (rs_outdata == NULL) {
		dao_err("Invalid argument. rs_outdata cannot be NULL.");
		return -EINVAL;
	}

	if (cpt_ec_curve_id_validate(curve_id)) {
		dao_err("Invalid argument. curve_id (%d) is not valid.", curve_id);
		return -EINVAL;
	}

	rc = cpt_ae_ecdsa_digest_len_check(prime_len, digest_len);
	if (rc != 0)
		return rc;

	rc = cpt_ae_ecdsa_nonce_len_check(prime_len, nonce_len, curve_id);
	if (rc != 0)
		return rc;

	rc = cpt_ae_ecdsa_pkey_len_check(prime_len, pkey_len, curve_id);
	if (rc != 0)
		return rc;

	rc = cpt_ae_ecdsa_pkey_validate(pkey_len, pkey, curve_id);
	if (rc != 0) {
		dao_err("Invalid ECC private key.");
		return rc;
	}
#endif
	qp = dev->qp[qp_id];

	req_idx = liquid_crypto_qp_req_idx_get(qp, false);

	if (unlikely(req_idx == UINT32_MAX)) {
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		dao_err("No available request index.");
#endif
		return -ENOSPC;
	}

	mbuf = rte_pktmbuf_alloc(qp->tx_mp);
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (unlikely(mbuf == NULL)) {
		dao_err("Could not allocate mbuf.");
		rc = -ENOMEM;
		goto idx_put;
	}
#endif

	lc_inflight_req_reset(&qp->req_queue[req_idx]);
	qp->req_queue[req_idx].op_cookie = op_cookie;
	qp->req_queue[req_idx].data_out = rs_outdata;
	qp->req_queue[req_idx].op_type = LC_ASYM_ECDSA_SIGN;

	if (digest_len > prime_len) {
		dao_err("Invalid argument. digest_len (%d) cannot be greater than prime_len (%d).",
			digest_len, prime_len);
		return -EINVAL;
	}

	/* Calculate aligned lengths and offsets */
	m_align = RTE_ALIGN_CEIL(digest_len, 8);
	p_align = RTE_ALIGN_CEIL(prime_len, 8);
	nonce_align = RTE_ALIGN_CEIL(nonce_len, 8);
	pk_offset = p_align - pkey_len;

	if (pk_offset < 0) {
		dao_err("Invalid offset: pk_offset = %d", pk_offset);
		return -EINVAL;
	}

	/* dlen = sum(sizeof(fpm address) + ROUNDUP8 (nonce_len) +  ROUNDUP8(digest_len) +
	 * ROUNDUP8 (prime_len) + ROUNDUP8 (order_len) +
	 * ROUNDUP8 (pkey_len) + ROUNDUP8 (consta_len) + ROUNDUP8 (constb_len)
	 */
	dlen = sizeof(uint64_t) + nonce_align + m_align + (p_align * 5);

	buf_len = sizeof(struct __dao_lc_req_asym) + dlen;
	rte_pktmbuf_append(mbuf, buf_len);
	mbuf->pkt_len = RTE_MAX(buf_len, LIQUID_CRYPTO_BUF_SZ_MIN);

	/* Add payload to mbuf */
	req = rte_pktmbuf_mtod(mbuf, struct __dao_lc_req_asym *);
	req->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_ASYM;
	req->hdr.trs_hdr.op_len = buf_len;
	req->hdr.req_idx = req_idx;
	req->op_type = LC_ASYM_ECDSA_SIGN;

	/* Add instruction */
	w4.s.opcode_major = ROC_AE_MAJOR_OP_EC;
	w4.s.opcode_minor = ROC_AE_MINOR_OP_EC_SIGN;
	w4.s.param1 = curve_id | (digest_len << 8);
	w4.s.param2 = (p_align << 8) | nonce_len;
	w4.s.dlen = dlen;
	req->w4 = w4.u64;

	/* Add data */
	dptr = req->dptr;

	/* Store curve_id in the first 8 bytes*/
	*(uint64_t *)dptr = (uint64_t)curve_id;
	dptr += sizeof(uint64_t);

	/* Copy Nonce */
	memcpy(dptr, nonce, nonce_len);
	dptr += nonce_align;

	/* Skip Prime */
	dptr += p_align;
	/* Skip Order */
	dptr += p_align;

	memset(dptr, 0, pk_offset);
	memcpy(dptr + pk_offset, pkey, pkey_len);
	dptr += p_align;

	memcpy(dptr, digest_data, digest_len);
	dptr += m_align;

	rc = rte_eth_tx_burst(qp->port_id, qp->queue_id, &mbuf, 1);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (rc != 1) {
		dao_err("Failed to transmit packet.");
		rc = -EIO;
		goto mbuf_free;
	}
#endif

	return 0;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
mbuf_free:
	rte_pktmbuf_free(mbuf);
idx_put:
	liquid_crypto_qp_req_idx_put(qp, req_idx, false);
#endif
	return rc;
}

int
dao_liquid_crypto_enq_op_ecdsa_verify(uint8_t dev_id, uint16_t qp_id,
				      enum dao_liquid_crypto_ec_curve_type curve_id, uint16_t r_len,
				      uint16_t s_len, uint16_t digest_len, uint16_t qx_len,
				      uint16_t qy_len, const uint8_t *r_data, const uint8_t *s_data,
				      const uint8_t *digest_data, const uint8_t *qx_data,
				      const uint8_t *qy_data, uint64_t op_cookie)
{
	int qx_offset, qy_offset, r_offset, s_offset;
	struct __dao_lc_req_asym *req;
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	uint32_t req_idx = 0, dlen;
	uint32_t p_align, m_align;
	struct rte_mbuf *mbuf;
	union cpt_inst_w4 w4;
	uint16_t buf_len;
	int prime_len;
	uint8_t *dptr;
	int rc;

	prime_len = ecc_curve_id_to_prime_len(curve_id);
	if (prime_len < 0) {
		dao_err("Invalid curve_id (%d).", curve_id);
		return -EINVAL;
	}

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}
#endif

	dev = &liquid_crypto_devs[dev_id];

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (qp_id >= dev->nb_qp) {
		dao_err("Invalid argument. qp_id must be between 0 and %u.", dev->nb_qp - 1);
		return -EINVAL;
	}

	if (qp_id == dev->cmd_qp_idx) {
		dao_err("Invalid argument. qp_id cannot be the command queue index.");
		return -EINVAL;
	}

	if (!dev->is_started) {
		dao_err("Invalid device. Device(%d) not started.", dev_id);
		return -EINVAL;
	}

	if (qx_data == NULL) {
		dao_err("Invalid argument. qx data cannot be NULL.");
		return -EINVAL;
	}

	if (qy_data == NULL) {
		dao_err("Invalid argument. qy_data cannot be NULL.");
		return -EINVAL;
	}

	if (digest_data == NULL) {
		dao_err("Invalid argument. digest_data cannot be NULL.");
		return -EINVAL;
	}

	if (r_data == NULL) {
		dao_err("Invalid argument. r_data cannot be NULL.");
		return -EINVAL;
	}

	if (s_data == NULL) {
		dao_err("Invalid argument. s_data cannot be NULL.");
		return -EINVAL;
	}

	if (cpt_ec_curve_id_validate(curve_id)) {
		dao_err("Invalid argument. curve_id (%d) is not valid.", curve_id);
		return -EINVAL;
	}

	rc = cpt_ae_ecdsa_pubkey_len_check(prime_len, qx_len, qy_len, curve_id);
	if (rc != 0)
		return rc;

	rc = cpt_ae_ecdsa_digest_len_check(prime_len, digest_len);
	if (rc != 0)
		return rc;

	rc = cpt_ae_ecdsa_sign_comp_len_check(prime_len, r_len, s_len, curve_id);
	if (rc != 0)
		return rc;

	rc = cpt_ae_ecdsa_pubkey_validate(qx_len, qx_data, qy_len, qy_data, curve_id);
	if (rc != 0) {
		dao_err("Invalid ECC public key.");
		return rc;
	}
#endif
	qp = dev->qp[qp_id];

	req_idx = liquid_crypto_qp_req_idx_get(qp, false);

	if (unlikely(req_idx == UINT32_MAX)) {
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		dao_err("No available request index.");
#endif
		return -ENOSPC;
	}

	mbuf = rte_pktmbuf_alloc(qp->tx_mp);
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (unlikely(mbuf == NULL)) {
		dao_err("Could not allocate mbuf.");
		rc = -ENOMEM;
		goto idx_put;
	}
#endif

	lc_inflight_req_reset(&qp->req_queue[req_idx]);
	qp->req_queue[req_idx].op_cookie = op_cookie;
	qp->req_queue[req_idx].op_type = LC_ASYM_ECDSA_VERIFY;

	if (digest_len > prime_len) {
		dao_err("Invalid argument. digest_len (%d) cannot be greater than prime_len (%d).",
			digest_len, prime_len);
		return -EINVAL;
	}

	/* Calculate aligned lengths and offsets */
	m_align = RTE_ALIGN_CEIL(digest_len, 8);
	p_align = RTE_ALIGN_CEIL(prime_len, 8);

	qx_offset = prime_len - qx_len;
	qy_offset = prime_len - qy_len;
	r_offset = prime_len - r_len;
	s_offset = prime_len - s_len;

	/* Check for negative offsets */
	if (qx_offset < 0 || qy_offset < 0 || r_offset < 0 || s_offset < 0) {
		dao_err("Invalid offset: qx_offset = %d, qy_offset = %d, r_offset = %d, s_offset = %d",
			qx_offset, qy_offset, r_offset, s_offset);
		return -EINVAL;
	}

	/* dlen = sum(sizeof(fpm address) + ROUNDUP8 (digest_len) +  ROUNDUP8(sign_len(r,s)) +
	 * ROUNDUP8 (public key len(x and y coordinates)) + (order_len) + (prime_len) +
	 * ROUNDUP8 (consta_len) + ROUNDUP8 (constb_len)
	 */
	dlen = sizeof(uint64_t) + m_align + (p_align * 8);

	buf_len = sizeof(struct __dao_lc_req_asym) + dlen;
	rte_pktmbuf_append(mbuf, buf_len);
	mbuf->pkt_len = RTE_MAX(buf_len, LIQUID_CRYPTO_BUF_SZ_MIN);

	/* Add payload to mbuf */
	req = rte_pktmbuf_mtod(mbuf, struct __dao_lc_req_asym *);
	req->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_ASYM;
	req->hdr.trs_hdr.op_len = buf_len;
	req->hdr.req_idx = req_idx;
	req->op_type = LC_ASYM_ECDSA_VERIFY;

	/* Add instruction */
	w4.s.opcode_major = ROC_AE_MAJOR_OP_EC;
	w4.s.opcode_minor = ROC_AE_MINOR_OP_EC_VERIFY;
	w4.s.param1 = curve_id | (digest_len << 8);
	w4.s.param2 = 0;
	w4.s.dlen = dlen;
	req->w4 = w4.u64;

	/* Add data */
	dptr = req->dptr;

	/* Store curve_id in the first 8 bytes*/
	*(uint64_t *)dptr = (uint64_t)curve_id;
	dptr += sizeof(uint64_t);

	memcpy(dptr + r_offset, r_data, r_len);
	dptr += p_align;

	memcpy(dptr + s_offset, s_data, s_len);
	dptr += p_align;

	memcpy(dptr, digest_data, digest_len);
	dptr += m_align;

	/* Skip Order */
	dptr += p_align;
	/* Skip Prime */
	dptr += p_align;

	memcpy(dptr + qx_offset, qx_data, qx_len);
	dptr += p_align;

	memcpy(dptr + qy_offset, qy_data, qy_len);
	dptr += p_align;

	rc = rte_eth_tx_burst(qp->port_id, qp->queue_id, &mbuf, 1);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (rc != 1) {
		dao_err("Failed to transmit packet.");
		rc = -EIO;
		goto mbuf_free;
	}
#endif

	return 0;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
mbuf_free:
	rte_pktmbuf_free(mbuf);
idx_put:
	liquid_crypto_qp_req_idx_put(qp, req_idx, false);
#endif
	return rc;
}

int
dao_liquid_crypto_enq_op_rsa_oaep_enc(uint8_t dev_id, uint16_t qp_id, uint8_t *label,
				      uint16_t label_len, enum dao_lc_hash_type hash_type,
				      uint16_t mod_len, uint16_t exp_len, uint16_t msg_len,
				      const uint8_t *mod, const uint8_t *exp, const uint8_t *msg,
				      uint8_t *em, uint64_t op_cookie)
{
	/* dlen = label_len + msg_len + 8 (control word) */
	uint32_t dlen = label_len + msg_len + 8;
	struct __dao_lc_req_asym *req;
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	uint32_t rsvd_space = 0;
	struct rte_mbuf *mbuf;
	union cpt_inst_w4 w4;
	uint32_t req_idx = 0;
	uint16_t buf_len;
	uint8_t *dptr;
	int rc;

	rc = cpt_ae_rsa_oaep_label_len_validate(label_len);
	if (rc != 0) {
		dao_err("Invalid argument. label_len exceeds maximum allowed length.");
		return rc;
	}

	rc = cpt_ae_rsa_oaep_mod_len_max_validate(mod_len);
	if (rc != 0) {
		dao_err("Invalid argument. mod_len exceeds maximum allowed length.");
		return rc;
	}

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}
#endif

	dev = &liquid_crypto_devs[dev_id];

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (qp_id >= dev->nb_qp) {
		dao_err("Invalid argument. qp_id must be between 0 and %u.", dev->nb_qp - 1);
		return -EINVAL;
	}

	if (qp_id == dev->cmd_qp_idx) {
		dao_err("Invalid argument. qp_id cannot be the command queue index.");
		return -EINVAL;
	}

	if (!dev->is_started) {
		dao_err("Invalid device. Device(%d) not started.", dev_id);
		return -EINVAL;
	}

	if (mod == NULL) {
		dao_err("Invalid argument. mod cannot be NULL.");
		return -EINVAL;
	}

	if (exp == NULL) {
		dao_err("Invalid argument. exp cannot be NULL.");
		return -EINVAL;
	}

	if (msg == NULL) {
		dao_err("Invalid argument. msg cannot be NULL.");
		return -EINVAL;
	}
	if (em == NULL) {
		dao_err("Invalid argument. em cannot be NULL.");
		return -EINVAL;
	}

	rc = cpt_ae_oaep_msg_and_mod_len_check(mod_len, msg_len, hash_type);
	if (rc != 0)
		return rc;

	rc = cpt_ae_rsa_oaep_mod_len_check(mod_len, false);
	if (rc != 0)
		return rc;

	rc = cpt_ae_rsa_exp_len_check(mod_len, exp_len);
	if (rc != 0)
		return rc;

	rc = cpt_ae_rsa_msw_check(mod_len, mod);
	if (rc != 0) {
		dao_err("Invalid argument. MSW of modulus must be non-zero.");
		return rc;
	}

	rc = cpt_ae_rsa_oaep_hash_type_check(hash_type);
	if (rc != 0)
		return rc;

	rc = cpt_ae_rsa_oaep_label_validate(label, label_len);
	if (rc != 0)
		return rc;
#endif
	qp = dev->qp[qp_id];

	req_idx = liquid_crypto_qp_req_idx_get(qp, false);

	if (unlikely(req_idx == UINT32_MAX)) {
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		dao_err("No available request index.");
#endif
		return -ENOSPC;
	}
	mbuf = rte_pktmbuf_alloc(qp->tx_mp);
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (unlikely(mbuf == NULL)) {
		dao_err("Could not allocate mbuf.");
		rc = -ENOMEM;
		goto idx_put;
	}
#endif

	lc_inflight_req_reset(&qp->req_queue[req_idx]);
	qp->req_queue[req_idx].op_cookie = op_cookie;
	qp->req_queue[req_idx].data_out = em;
	qp->req_queue[req_idx].op_type = LC_ASYM_RSA_OAEP_ENCRYPT;

	/* For RSA OAEP encryption stage 1 dlen = Label_len + msg_len + 8 (control word) */
	buf_len = sizeof(struct __dao_lc_req_asym) + dlen;

	/* If dlen(Label_len + msg_len + control word) is less than mod_len, reserve
	 * additional space to accommodate the encoded message length is exactly equal
	 * to the modulus length (mod_len).
	 */

	if (dlen < mod_len) {
		rsvd_space = mod_len - dlen;
		buf_len += rsvd_space;
	}

	/* Reserve 2 bytes for rptr offset */
	buf_len += 2;
	buf_len += mod_len + exp_len;

	rte_pktmbuf_append(mbuf, buf_len);
	mbuf->pkt_len = RTE_MAX(buf_len, LIQUID_CRYPTO_BUF_SZ_MIN);

	/* Add payload to mbuf */
	req = rte_pktmbuf_mtod(mbuf, struct __dao_lc_req_asym *);
	req->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_OAEP_ENC;
	req->hdr.trs_hdr.op_len = buf_len;
	req->hdr.req_idx = req_idx;
	req->op_type = LC_ASYM_RSA_OAEP_ENCODE;

	/* Add instruction */
	w4.s.opcode_major = ROC_SE_MAJOR_OP_OAEP_ENCODE_DECODE;
	w4.s.opcode_minor = ROC_SE_MINOR_OP_OAEP_ENCODE;
	w4.s.param1 = mod_len;
	w4.s.param2 = ((hash_type & 0xF) << 8);
	w4.s.dlen = dlen;
	req->w4 = w4.u64;
	req->exp_len = exp_len;

	/* Add data */
	dptr = req->dptr;

	memcpy(dptr, mod, mod_len);
	dptr += mod_len;

	memcpy(dptr, exp, exp_len);
	dptr += exp_len;

	/* Control word: [63:48 Reserved][47:32 SLen][31:16 LLen][15:0 MLen] (big endian) */
	*(uint64_t *)dptr = rte_cpu_to_be_64(((uint64_t)label_len << 16) | ((uint64_t)msg_len));
	dptr += 8;

	if (label_len)
		memcpy(dptr, label, label_len);
	dptr += label_len;

	memcpy(dptr, msg, msg_len);
	dptr += msg_len;

	rc = rte_eth_tx_burst(qp->port_id, qp->queue_id, &mbuf, 1);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (rc != 1) {
		dao_err("Failed to transmit packet.");
		rc = -EIO;
		goto mbuf_free;
	}
#endif
	return 0;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
mbuf_free:
	rte_pktmbuf_free(mbuf);
idx_put:
	liquid_crypto_qp_req_idx_put(qp, req_idx, false);
#endif
	return rc;
}

int
dao_liquid_crypto_enq_op_rsa_oaep_exp_dec(uint8_t dev_id, uint16_t qp_id, uint8_t *label,
					  uint16_t label_len, enum dao_lc_hash_type hash_type,
					  uint16_t mod_len, uint16_t exp_len, const uint8_t *mod,
					  const uint8_t *exp, const uint8_t *em, uint8_t *msg,
					  uint64_t op_cookie)
{
	uint32_t dlen = exp_len + (mod_len * 2);
	int msg_len_max, total_bufdata_len;
	struct __dao_lc_req_asym *req;
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	uint32_t rsvd_space = 0;
	struct rte_mbuf *mbuf;
	union cpt_inst_w4 w4;
	uint32_t req_idx = 0;
	uint16_t buf_len;
	uint8_t *dptr;
	int rc;

	rc = cpt_ae_rsa_oaep_label_len_validate(label_len);
	if (rc != 0) {
		dao_err("Invalid argument. label_len exceeds maximum allowed length.");
		return rc;
	}

	rc = cpt_ae_rsa_oaep_mod_len_max_validate(mod_len);
	if (rc != 0) {
		dao_err("Invalid argument. mod_len exceeds maximum allowed length.");
		return rc;
	}

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}
#endif

	dev = &liquid_crypto_devs[dev_id];

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (qp_id >= dev->nb_qp) {
		dao_err("Invalid argument. qp_id must be between 0 and %u.", dev->nb_qp - 1);
		return -EINVAL;
	}

	if (qp_id == dev->cmd_qp_idx) {
		dao_err("Invalid argument. qp_id cannot be the command queue index.");
		return -EINVAL;
	}

	if (!dev->is_started) {
		dao_err("Invalid device. Device(%d) not started.", dev_id);
		return -EINVAL;
	}

	if (mod == NULL) {
		dao_err("Invalid argument. mod cannot be NULL.");
		return -EINVAL;
	}

	if (exp == NULL) {
		dao_err("Invalid argument. exp cannot be NULL.");
		return -EINVAL;
	}

	if (em == NULL) {
		dao_err("Invalid argument. em cannot be NULL.");
		return -EINVAL;
	}

	if (msg == NULL) {
		dao_err("Invalid argument. msg cannot be NULL.");
		return -EINVAL;
	}

	rc = cpt_ae_rsa_oaep_mod_len_check(mod_len, false);
	if (rc != 0)
		return rc;

	rc = cpt_ae_rsa_exp_len_check(mod_len, exp_len);
	if (rc != 0)
		return rc;

	rc = cpt_ae_rsa_msw_check(mod_len, mod);
	if (rc != 0) {
		dao_err("Invalid argument. MSW of modulus must be non-zero.");
		return rc;
	}

	rc = cpt_ae_rsa_oaep_hash_type_check(hash_type);
	if (rc != 0)
		return rc;

	rc = cpt_ae_rsa_oaep_label_validate(label, label_len);
	if (rc != 0)
		return rc;
#endif
	qp = dev->qp[qp_id];

	req_idx = liquid_crypto_qp_req_idx_get(qp, false);

	if (unlikely(req_idx == UINT32_MAX)) {
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		dao_err("No available request index.");
#endif
		return -ENOSPC;
	}

	/* Reserve extra space in the mbuf for the output message because we do not know
	 * the actual length of the data. The reserved space is based on the
	 * maximum possible message length.
	 */
	msg_len_max = cpt_ae_rsa_oaep_msg_len_max(mod_len, hash_type);
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (msg_len_max < 0) {
		dao_err("Failed to get maximum message length.");
		rc = -EINVAL;
		goto idx_put;
	}
#endif

	mbuf = rte_pktmbuf_alloc(qp->tx_mp);
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (unlikely(mbuf == NULL)) {
		dao_err("Could not allocate mbuf.");
		rc = -ENOMEM;
		goto idx_put;
	}
#endif

	lc_inflight_req_reset(&qp->req_queue[req_idx]);
	qp->req_queue[req_idx].op_cookie = op_cookie;
	qp->req_queue[req_idx].data_out = msg;
	qp->req_queue[req_idx].op_type = LC_ASYM_RSA_OAEP_DECRYPT;

	/* OAEP Decoding */
	buf_len = sizeof(struct __dao_lc_req_asym);
	/* 8 bytes control word */
	buf_len += 8;
	if (label_len)
		buf_len += label_len;

	/* RSA decrypt */
	buf_len += dlen;
	total_bufdata_len = dlen + label_len + 8;

	if (msg_len_max > total_bufdata_len) {
		rsvd_space = msg_len_max - total_bufdata_len;
		buf_len += rsvd_space;
	}

	/* Reserve 2 bytes for rptr offset and 2 bytes for rlen */
	buf_len += 4;

	rte_pktmbuf_append(mbuf, buf_len);
	mbuf->pkt_len = RTE_MAX(buf_len, LIQUID_CRYPTO_BUF_SZ_MIN);

	/* Add payload to mbuf */
	req = rte_pktmbuf_mtod(mbuf, struct __dao_lc_req_asym *);
	req->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_OAEP_DEC;
	req->hdr.trs_hdr.op_len = buf_len;
	req->hdr.req_idx = req_idx;
	req->op_type = LC_ASYM_RSA_OAEP_DECRYPT;

	/* Add instruction */
	w4.s.opcode_major = ROC_AE_MAJOR_OP_MODEX;
	w4.s.opcode_minor = ROC_AE_MINOR_OP_MODEX_EXP;
	w4.s.param1 = mod_len;
	w4.s.param2 = exp_len;
	w4.s.dlen = dlen;
	req->w4 = w4.u64;
	req->hash_type = hash_type;

	/* Add data */
	dptr = req->dptr;

	/* Control word: [63:48 Reserved][47:32 SLen][31:16 LLen][15:0 MLen] (big endian) */
	*(uint64_t *)dptr = rte_cpu_to_be_64((uint64_t)label_len << 16);
	dptr += 8;

	if (label_len)
		memcpy(dptr, label, label_len);
	dptr += label_len;

	memcpy(dptr, mod, mod_len);
	dptr += mod_len;

	memcpy(dptr, exp, exp_len);
	dptr += exp_len;

	memcpy(dptr, em, mod_len);
	dptr += mod_len;

	rc = rte_eth_tx_burst(qp->port_id, qp->queue_id, &mbuf, 1);
#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (rc != 1) {
		dao_err("Failed to transmit packet.");
		rc = -EIO;
		goto mbuf_free;
	}
#endif
	return 0;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
mbuf_free:
	rte_pktmbuf_free(mbuf);
idx_put:
	liquid_crypto_qp_req_idx_put(qp, req_idx, false);
#endif
	return rc;
}
