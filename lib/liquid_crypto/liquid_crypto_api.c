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
#include "liquid_crypto_debug.h"
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
static inline int cpt_ae_rsa_mod_len_check(uint16_t mod_len, bool is_crt);
static inline int cpt_ae_rsa_exp_len_check(uint16_t mod_len, uint16_t exp_len);
static inline int cpt_ae_rsa_msg_len_check(uint16_t mod_len, uint16_t msg_len);

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
	struct dao_eth_trs_dev_config trs_conf;
	struct liquid_crypto_dev *dev;
	uint16_t nb_qp, cmd_qp_idx;
	uint8_t dev_id;
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

	rc = dao_lc_ethdev_create(lc_ctx, dev_id, nb_qp);
	if (rc != 0) {
		dao_err("Could not create card device.");
		goto eth_dev_free;
	}
	dev->is_created = true;

	return 0;

eth_dev_free:
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

	rc = dao_lc_ethdev_destroy(lc_ctx, dev_id);
	if (rc != 0) {
		dao_err("Could not destroy card device.");
		return rc;
	}

	rc = dao_eth_trs_dev_free(dev_id);
	if (rc != 0) {
		dao_err("Could not free ethernet transport device.");
		return rc;
	}

	dev = &liquid_crypto_devs[dev_id];

	if (dev->is_created) {
		for (i = 0; i < dev->nb_qp; i++)
			liquid_crypto_qp_free(dev_id, i);
	}

	memset(dev, 0, sizeof(*dev));

	dev->is_destroyed = true;

	return 0;
}

int
dao_liquid_crypto_qp_configure(uint8_t dev_id, uint16_t qp_id, struct dao_lc_qp_conf *conf)
{
	struct dao_eth_trs_queue_config trs_queue_conf;
	struct dao_lc_eth_qconf card_qp_conf;
	struct dao_eth_trs_info trs_info;
	char name[RTE_MEMZONE_NAMESIZE];
	uint16_t nb_desc, max_seg_size;
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	struct rte_mempool *mp;
	uint32_t bm_mem_size;
	unsigned int pool_sz;
	uint16_t min_seg_sz;
	int rc, size;

	if (conf == NULL) {
		dao_err("Invalid argument.");
		return -EINVAL;
	}

	if (conf->out_of_order_delivery_en) {
		dao_err("Out of order delivery is not supported.");
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
	min_seg_sz = trs_info.min_buf_len + RTE_PKTMBUF_HEADROOM;

	if (conf->max_seg_size < min_seg_sz || conf->max_seg_size > trs_info.max_pkt_len) {
		dao_err("Invalid argument. max_seg_size must be between %u and %u.", min_seg_sz,
			trs_info.max_pkt_len);
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

	/* TODO:
	 * Hardcoding the segment size to 4k, irrespective of the size specified by the application.
	 * This is to bypass the MTU configuration issue on Octeon side due to different buffer
	 * sizes for different queues.
	 * */
	conf->max_seg_size = 4096;

	max_seg_size = conf->max_seg_size;

	snprintf(name, sizeof(name), "lc_rx_mp_%hhu_%hu", dev_id, qp_id);

	/*
	 * Create Rx & Tx pools. To allow for some packets inflight and since mempool_alloc is
	 * optimal in terms of memory when using 2^q - 1, increase the Rx pool size.
	 */
	pool_sz = 2 * nb_desc - 1;

	mp = rte_pktmbuf_pool_create(name, pool_sz, RTE_MEMPOOL_CACHE_MAX_SIZE, 0, max_seg_size, 0);
	if (mp == NULL) {
		dao_err("Could not create Rx mbuf pool.");
		rc = -ENOMEM;
		goto qp_free;
	}

	qp->rx_mp = mp;

	snprintf(name, sizeof(name), "lc_tx_mp_%hhu_%hu", dev_id, qp_id);

	mp = rte_pktmbuf_pool_create(name, pool_sz, RTE_MEMPOOL_CACHE_MAX_SIZE, 0, max_seg_size, 0);
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

	bm_mem_size = rte_bitmap_get_memory_footprint(nb_desc);
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

	qp->req_bm = rte_bitmap_init_with_all_set(nb_desc, qp->req_bm_mem, bm_mem_size);
	if (qp->req_bm == NULL) {
		dao_err("Could not initialize bitmap.");
		rc = -EINVAL;
		goto bm_mem_free;
	}

	if (qp_id == dev->cmd_qp_idx) {
		snprintf(name, sizeof(name), "liquid_crypto_cmd_bm_%hhu_%hu", dev_id, qp_id);
		qp->cmd_req_bm_mem = rte_zmalloc(name, bm_mem_size, 0);
		if (qp->cmd_req_bm_mem == NULL) {
			dao_err("Could not allocate memory for command queue bitmap.");
			rc = -ENOMEM;
			goto bitmap_free;
		}

		qp->cmd_req_bm =
			rte_bitmap_init_with_all_set(nb_desc, qp->cmd_req_bm_mem, bm_mem_size);
		if (qp->cmd_req_bm == NULL) {
			dao_err("Could not initialize command queue bitmap.");
			rc = -EINVAL;
			goto cmd_bm_mem_free;
		}

		rte_bitmap_reset(qp->req_bm);
	}

	memset(&card_qp_conf, 0, sizeof(card_qp_conf));
	card_qp_conf.dev_id = dev_id;
	card_qp_conf.qp_id = qp_id;
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
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;

	dev = &liquid_crypto_devs[dev_id];
	qp = dev->qp[qp_id];

	if (qp == NULL)
		return 0;

	dao_lc_ethdev_queue_destroy(lc_ctx, dev_id, qp_id);

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

	return 0;
}

int
dao_liquid_crypto_dev_start(uint8_t dev_id)
{
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

	rc = dao_lc_ethdev_start(lc_ctx, dev_id);
	if (rc != 0) {
		dao_err("Could not start card device.");
		dao_eth_trs_dev_stop(dev_id);
		return rc;
	}

	dev->is_started = true;

	return 0;
}

int
dao_liquid_crypto_dev_stop(uint8_t dev_id)
{
	struct liquid_crypto_dev *dev;
	int rc;

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

	rc = dao_eth_trs_dev_stop(dev_id);
	if (rc != 0) {
		dao_err("Could not stop ethernet transport device.");
		return rc;
	}

	rc = dao_lc_ethdev_stop(lc_ctx, dev_id);
	if (rc != 0) {
		dao_err("Could not stop card device.");
		return rc;
	}

	dev->is_started = false;

	return 0;
}

uint16_t
dao_liquid_crypto_seg_size_calc(struct dao_lc_feature_params *params)
{
	uint16_t asym_seg_sz = 0, sym_seg_sz = 0, max_seg_size = 0;
	struct dao_eth_trs_info trs_info;
	uint16_t req_resp_hdr_sz = 0;
	int rc;

	if (params == NULL) {
		dao_err("Invalid argument.");
		return 0;
	}

	if (params->cmd_qp) {
		req_resp_hdr_sz = RTE_MAX(sizeof(struct __dao_lc_req_sess_create),
					  sizeof(struct __dao_lc_resp_sess_create));
		max_seg_size = req_resp_hdr_sz + sizeof(struct dao_lc_sym_ctx);
		max_seg_size = RTE_MAX(max_seg_size, LIQUID_CRYPTO_SEG_SZ_MIN);
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
			asym_seg_sz = sizeof(struct __dao_lc_req_asym);

			if (is_crt)
				asym_seg_sz += (params->rsa.mod_len / 2) * 5;
			else
				asym_seg_sz += params->rsa.mod_len + params->rsa.exp_len;

			asym_seg_sz += params->rsa.msg_len;
		}

		max_seg_size = RTE_MAX(sym_seg_sz, asym_seg_sz);
	}

	/* Make sure segment size is larger than min supported. */
	memset(&trs_info, 0, sizeof(trs_info));
	rc = dao_eth_trs_info(&trs_info);
	if (rc != 0) {
		dao_err("Could not get ethernet transport information.");
		return 0;
	}

	max_seg_size = RTE_MAX(max_seg_size, trs_info.min_buf_len + RTE_PKTMBUF_HEADROOM);

	max_seg_size = RTE_MIN(max_seg_size, LIQUID_CRYPTO_BUF_SZ_MAX);

	return max_seg_size;
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

static inline int
cpt_ae_rsa_mod_len_check(uint16_t mod_len, bool is_crt)
{
	uint16_t min_len = LIQUID_CRYPTO_RSA_MOD_LEN_MIN;

	if (is_crt)
		min_len = LIQUID_CRYPTO_RSA_MOD_LEN_MIN * 2;

	if (mod_len == 0) {
		dao_err("Invalid modulus length. mod_len cannot be zero.");
		return -EINVAL;
	}

	if (is_crt && mod_len % 2 != 0) {
		dao_err("Invalid modulus length. mod_len must be even.");
		return -EINVAL;
	}

	if (mod_len < min_len || mod_len > LIQUID_CRYPTO_RSA_MOD_LEN_MAX) {
		dao_err("Invalid modulus length. mod_len should be at least %u and at most %u bytes.",
			min_len, LIQUID_CRYPTO_RSA_MOD_LEN_MAX);
		return -EINVAL;
	}

	return 0;
}

static inline int
cpt_ae_rsa_msg_len_check(uint16_t mod_len, uint16_t msg_len)
{
	if (msg_len == 0) {
		dao_err("Invalid message length. msg_len cannot be zero.");
		return -EINVAL;
	}

	if (msg_len > mod_len - LIQUID_CRYPTO_RSA_MSG_LEN_PADDING) {
		dao_err("Invalid message length. msg_len should be at most %u bytes.",
			mod_len - LIQUID_CRYPTO_RSA_MSG_LEN_PADDING);
		return -EINVAL;
	}

	return 0;
}

static inline int
cpt_ae_rsa_exp_len_check(uint16_t mod_len, uint16_t exp_len)
{
	if (exp_len == 0) {
		dao_err("Invalid message length. exp_len cannot be zero.");
		return -EINVAL;
	}

	if (exp_len > mod_len) {
		dao_err("Invalid message length. exp_len should be at most %u bytes.", mod_len);
		return -EINVAL;
	}

	return 0;
}

static inline int
cpt_ae_rsa_msw_check(uint16_t plen, uint8_t *p)
{
	uint8_t len = plen % 8;
	uint64_t msw;

	if (p == NULL || plen == 0)
		return -EINVAL;

	if (len)
		memcpy(&msw, p, len);
	else
		memcpy(&msw, p, 8);

	if (msw == 0)
		return -EINVAL;

	return 0;
}

static inline int
cpt_ae_rsa_crt_params_check(uint16_t mod_len, uint8_t *q, uint8_t *dQ, uint8_t *p, uint8_t *dP,
			    uint8_t *qInv)
{
	if (q == NULL || dQ == NULL || p == NULL || dP == NULL || qInv == NULL) {
		dao_err("Invalid CRT parameters. None of the parameters can be NULL.");
		return -EINVAL;
	}

	if (q[mod_len / 2 - 1] % 2 == 0) {
		dao_err("Invalid CRT parameter. q must be odd.");
		return -EINVAL;
	}

	if (p[mod_len / 2 - 1] % 2 == 0) {
		dao_err("Invalid CRT parameter. p must be odd.");
		return -EINVAL;
	}

	if (cpt_ae_rsa_msw_check(mod_len / 2, q) != 0) {
		dao_err("Invalid CRT parameter. MSW of q must be non-zero.");
		return -EINVAL;
	}

	if (cpt_ae_rsa_msw_check(mod_len / 2, p) != 0) {
		dao_err("Invalid CRT parameter. MSW of p must be non-zero.");
		return -EINVAL;
	}

	return 0;
}

int
dao_liquid_crypto_enq_op_pkcs1v15enc(uint8_t dev_id, uint16_t qp_id,
				     enum dao_liquid_crypto_rsa_key_type key_type, uint16_t mod_len,
				     uint16_t exp_len, uint16_t msg_len, uint8_t *mod, uint8_t *exp,
				     uint8_t *msg, uint8_t *em, uint64_t op_cookie)
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
				     uint16_t exp_len, uint8_t *mod, uint8_t *exp, uint8_t *em,
				     uint8_t *msg, uint64_t op_cookie)
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
					 uint16_t msg_len, uint8_t *q, uint8_t *dQ, uint8_t *p,
					 uint8_t *dP, uint8_t *qInv, uint8_t *msg, uint8_t *em,
					 uint64_t op_cookie)
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
					 uint8_t *q, uint8_t *dQ, uint8_t *p, uint8_t *dP,
					 uint8_t *qInv, uint8_t *em, uint8_t *msg,
					 uint64_t op_cookie)
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

static inline void
dao_lc_post_process_asym(struct liquid_crypto_inflight_req *req, struct dao_lc_res *res,
			 struct rte_mbuf *mbuf)
{
	struct __dao_lc_resp_asym *resp;

	resp = rte_pktmbuf_mtod(mbuf, struct __dao_lc_resp_asym *);
	memcpy(&res->res, &resp->res, sizeof(union dao_cpt_res_s));
	res->rsa.data_out_len = resp->res.cn9k.reserved_17_63;
	memcpy((uint8_t *)req->data_out, resp->rptr, resp->res.cn9k.reserved_17_63);
}

static inline uint16_t
dao_lc_buf_copy_from_mem(uint8_t *src, struct dao_lc_buf *dst, uint32_t len)
{
	struct dao_lc_buf *tmp = dst;
	uint16_t copied = 0;
	uint16_t to_copy;

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
	uint16_t result_offset, result_len;
	struct __dao_lc_resp_sym *resp;

	resp = rte_pktmbuf_mtod(mbuf, struct __dao_lc_resp_sym *);
	memcpy(&res->res, &resp->res, sizeof(union dao_cpt_res_s));

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (req->sess_meta == NULL) {
		dao_err("Invalid session metadata pointer.");
		rte_errno = EINVAL;
		return;
	}
#endif

	/* Auth only post process involves simply copying the digest data to digest buffer. */
	if (req->sess_meta->op_type == LC_SYM_OP_AUTH_ONLY) {
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		if (req->digest == NULL) {
			dao_err("Invalid digest pointer.");
			rte_errno = EINVAL;
			return;
		}

		if (req->sess_meta->digest_len == 0 ||
		    req->sess_meta->digest_len > DAO_LC_MAX_DIGEST_LEN) {
			dao_err("Invalid digest length. digest_len: %d.",
				req->sess_meta->digest_len);
			rte_errno = EINVAL;
			return;
		}
#endif

		memcpy(req->digest, resp->rptr, req->sess_meta->digest_len);
	} else {
		result_offset = req->sess_meta->pkt_iv_len;

		/* OFFSET_CTRL_WORD len needs to be adjusted here */
		result_len =
			rte_pktmbuf_pkt_len(mbuf) -
			(ROC_SE_OFF_CTRL_LEN + sizeof(struct __dao_lc_resp_sym) + result_offset);

		dao_lc_buf_copy_from_mem(resp->rptr + result_offset, req->data_out, result_len);
	}
}

static inline uint16_t
dao_lc_buf_copy_to_mem(struct dao_lc_buf *src, uint8_t *dst, uint32_t len)
{
	struct dao_lc_buf *tmp = src;
	uint16_t to_copy, copied = 0;

	do {
		to_copy = RTE_MIN(tmp->frag_len, len - copied);

		memcpy(dst + copied, tmp->data, to_copy);
		copied += to_copy;
		tmp = tmp->next;
	} while (tmp && copied < len);

	return copied;
}

static inline void
dao_lc_sym_copy_iv(const struct dao_lc_sym_sess_meta *sess_meta, struct dao_lc_sym_op *op,
		   uint8_t *dptr, uint32_t iv_offset)
{
	uint16_t alg_iv_len = sess_meta->alg_iv_len;

	if (sess_meta->pkt_iv_len == alg_iv_len) {
		/* Pass IV as is to microcode */
		memcpy(dptr + iv_offset, op->cipher_iv, alg_iv_len);
	} else {
		/* Adjust the IV passed to microcode */
		if (sess_meta->cipher_type == DAO_LC_FC_ENC_CIPHER_AES_CCM) {
			/* flag = (15 - IV_length) - 1 */
			*(dptr + iv_offset) = (uint8_t)(14 - sess_meta->alg_iv_len);

			/* Adjust iv_offset after adding the flag byte */
			iv_offset += 1;

			memcpy(dptr + iv_offset, op->cipher_iv, alg_iv_len);
		} else if (sess_meta->cipher_type == DAO_LC_FC_ENC_CIPHER_AES_GCM) {
			const uint8_t ctr_blk[4] = {0x00, 0x00, 0x00, 0x01};

			memcpy(dptr + iv_offset, op->cipher_iv, alg_iv_len);
			memcpy(dptr + iv_offset + alg_iv_len, ctr_blk, 4);
		}
	}
}

static inline uint16_t
dao_lc_sym_prepare_ops_single(struct liquid_crypto_qp *qp, struct dao_lc_sym_op *op,
			      struct rte_mbuf *mbuf, uint32_t req_idx,
			      const struct dao_lc_sym_sess_meta *sess_meta,
			      const enum lc_sym_op_type op_type)
{
	uint32_t dlen, cipher_offset, cipher_len, auth_offset, auth_len, off_ctrl_len;
	uint16_t buf_len, pkt_iv_len;
	const uint32_t iv_offset = 0;
	struct __dao_lc_req_sym *req;
	uint8_t aad_len, digest_len;
	uint64_t *offset_vaddr;
	union cpt_inst_w4 w4;
	uint8_t *dptr;

	if (op_type == LC_SYM_OP_CIPHER_ONLY) {
		aad_len = 0;
		cipher_offset = op->cipher_offset;
		cipher_len = op->cipher_len;
		auth_offset = 0;
		auth_len = 0;
		pkt_iv_len = sess_meta->pkt_iv_len;
		digest_len = 0;
		off_ctrl_len = ROC_SE_OFF_CTRL_LEN;
	} else if (op_type == LC_SYM_OP_AUTH_ONLY) {
		aad_len = 0;
		cipher_offset = 0;
		cipher_len = 0;
		auth_offset = op->auth_offset;
		auth_len = op->auth_len;
		pkt_iv_len = 0;
		digest_len = sess_meta->digest_len;
		/* No offset control word for auth only */
		off_ctrl_len = 0;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
		if (op->digest == NULL) {
			dao_err("Invalid digest pointer for auth only operation.");
			rte_errno = EINVAL;
			return 0;
		}
#endif
		qp->req_queue[req_idx].digest = op->digest;
	} else if (op_type == LC_SYM_OP_AEAD) {
		aad_len = op->aad_len;
		cipher_offset = op->cipher_offset;
		cipher_len = op->cipher_len;
		auth_offset = cipher_offset;
		auth_len = cipher_len + aad_len;
		pkt_iv_len = sess_meta->pkt_iv_len;
		digest_len = sess_meta->digest_len;
		off_ctrl_len = ROC_SE_OFF_CTRL_LEN;
	} else {
		dao_err("Invalid operation type: %d", op_type);
		rte_errno = EINVAL;
		return 0;
	}

	if (op->out_buffer != NULL)
		qp->req_queue[req_idx].data_out = op->out_buffer;
	else
		qp->req_queue[req_idx].data_out = op->in_buffer;

	dlen = op->in_buffer->total_len;
	buf_len = sizeof(struct __dao_lc_req_sym) + off_ctrl_len + pkt_iv_len + dlen;
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

	if (op->cipher_len & 0xf) {
		if (sess_meta->cipher_type == DAO_LC_FC_ENC_CIPHER_AES_CBC) {
			dao_err("Invalid cipher length. cipher_len = %u", op->cipher_len);
			rte_errno = EINVAL;
			return 0;
		}
	}
#endif
	/* Input length starting from memory pointed by DPTR */
	dlen += off_ctrl_len + pkt_iv_len;

	/* Append transport header to mbuf */
	req = (struct __dao_lc_req_sym *)rte_pktmbuf_append(mbuf, buf_len);
	req->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_SYM;
	req->hdr.trs_hdr.op_len = buf_len;
	req->hdr.req_idx = req_idx;

	/* Add instruction */
	w4.u64 = sess_meta->w4;
	if (op_type != LC_SYM_OP_AUTH_ONLY) {
		w4.s.param1 = op->cipher_len;
		w4.s.param2 = auth_len;

		if (op->encrypt)
			w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_ENCRYPT;
		else
			w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_DECRYPT;
		req->is_hash_only = 0;
	} else {
		req->is_hash_only = 1;
	}

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

	cipher_offset = iv_offset + pkt_iv_len + aad_len + op->cipher_offset;
	auth_offset = iv_offset + pkt_iv_len + op->auth_offset;

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

	dao_lc_sym_copy_iv(sess_meta, op, dptr, iv_offset);

	if (op_type == LC_SYM_OP_AEAD) {
		/* Copy AAD */
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		if (op->aad == NULL || op->aad_len <= 0) {
			dao_err("Invalid AAD.");
			rte_errno = EINVAL;
			return 0;
		}

		if ((iv_offset + pkt_iv_len + aad_len) > buf_len) {
			dao_err("Buffer Length is too small to fit AAD. buf_len = %u", buf_len);
			rte_errno = ENOMEM;
			return 0;
		}
#endif
		memcpy(dptr + iv_offset + pkt_iv_len, op->aad, op->aad_len);
	}

	dao_lc_buf_copy_to_mem(op->in_buffer, dptr + iv_offset + aad_len + pkt_iv_len, dlen);

	return 1;
}

static inline uint16_t
dao_lc_sym_prepare_ops(struct liquid_crypto_qp *qp, struct dao_lc_sym_op *ops,
		       struct rte_mbuf **mbufs, uint32_t *req_idxs, uint16_t nb_ops)
{
	struct dao_lc_sym_sess_meta *sess_meta;
	enum lc_sym_op_type op_type;
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
		qp->req_queue[req_idx].op_cookie = op->op_cookie;
		qp->req_queue[req_idx].sess_meta = sess_meta;

		op_type = sess_meta->op_type;

		switch (op_type) {
		case LC_SYM_OP_CIPHER_ONLY:
			ret = dao_lc_sym_prepare_ops_single(qp, op, mbufs[i], req_idx, sess_meta,
							    LC_SYM_OP_CIPHER_ONLY);
			break;
		case LC_SYM_OP_AUTH_ONLY:
			ret = dao_lc_sym_prepare_ops_single(qp, op, mbufs[i], req_idx, sess_meta,
							    LC_SYM_OP_AUTH_ONLY);
			break;
		case LC_SYM_OP_CIPHER_AUTH:
			ret = dao_lc_sym_prepare_ops_single(qp, op, mbufs[i], req_idx, sess_meta,
							    LC_SYM_OP_CIPHER_AUTH);
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
	nb_rx = rte_eth_rx_burst(dev_id, qp_id, mbufs, nb_events);

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
