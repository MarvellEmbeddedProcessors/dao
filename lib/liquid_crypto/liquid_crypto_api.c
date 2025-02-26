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
#include "liquid_crypto_priv.h"
#include "liquid_crypto_trs.h"
#include "mc/ae.h"

static struct dao_lc_info lc_info;

static struct liquid_crypto_dev liquid_crypto_devs[DAO_CRYPTO_MAX_NB_DEV];

/** Forward declarations */
static int liquid_crypto_qp_free(uint8_t dev_id, uint16_t qp_id);

int
dao_liquid_crypto_init(void)
{
	struct dao_eth_trs_info trs_info;
	int rc, i;

	memset(&lc_info, 0, sizeof(lc_info));
	memset(liquid_crypto_devs, 0, sizeof(liquid_crypto_devs));

	rc = dao_eth_trs_init();
	if (rc != 0) {
		dao_err("Could not initialize ethernet transport.");
		return rc;
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

	lc_info.nb_dev = trs_info.nb_devs;

	for (i = 0; i < trs_info.nb_devs; i++)
		lc_info.nb_qp[i] = trs_info.nb_queues;

	return 0;

trs_fini:
	dao_eth_trs_fini();
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
	uint8_t dev_id;
	uint16_t nb_qp;
	int rc;

	if (conf == NULL) {
		dao_err("Invalid argument.");
		return -EINVAL;
	}

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

	dev = &liquid_crypto_devs[dev_id];

	if (dev->is_created) {
		dao_err("Device already created.");
		return -EEXIST;
	}

	dev->nb_qp = nb_qp;

	trs_conf.nb_queues = nb_qp;
	trs_conf.promiscuous = 1;

	rc = dao_eth_trs_dev_alloc(dev_id, &trs_conf);
	if (rc != 0) {
		dao_err("Could not allocate ethernet transport device.");
		return rc;
	}

	dev->is_created = true;

	return 0;
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

	return 0;
}

int
dao_liquid_crypto_qp_configure(uint8_t dev_id, uint16_t qp_id, struct dao_lc_qp_conf *conf)
{
	struct dao_eth_trs_queue_config trs_queue_conf;
	struct dao_eth_trs_info trs_info;
	char name[RTE_MEMZONE_NAMESIZE];
	uint16_t nb_desc, max_seg_size;
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	struct rte_mempool *mp;
	uint32_t bm_mem_size;
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

	if (conf->max_seg_size < trs_info.min_buf_len ||
	    conf->max_seg_size > trs_info.max_pkt_len) {
		dao_err("Invalid argument. max_seg_sz must be between %u and %u.",
			trs_info.min_buf_len, trs_info.max_pkt_len);
		return -EINVAL;
	}

	if (trs_info.min_buf_len > LIQUID_CRYPTO_BUF_SZ_MIN) {
		dao_err("[Internal error] Minimum buffer length exceeds the supported value.");
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

	snprintf(name, sizeof(name), "lc_qp_%u_%u", dev_id, qp_id);

	qp = rte_zmalloc(name, sizeof(*qp), 0);
	if (qp == NULL) {
		dao_err("could not allocate memory.");
		return -ENOMEM;
	}

	/* Align to the next power of 2 to simplify datapath checks */
	nb_desc = rte_align32pow2(conf->nb_desc);

	max_seg_size = conf->max_seg_size;

	snprintf(name, sizeof(name), "lc_rx_mp_%u_%u", dev_id, qp_id);

	mp = rte_pktmbuf_pool_create(name, nb_desc, 0, 0, max_seg_size, 0);
	if (mp == NULL) {
		dao_err("Could not create Rx mbuf pool.");
		goto qp_free;
	}

	qp->rx_mp = mp;

	snprintf(name, sizeof(name), "lc_tx_mp_%u_%u", dev_id, qp_id);

	mp = rte_pktmbuf_pool_create(name, nb_desc, 0, 0, max_seg_size, 0);
	if (mp == NULL) {
		dao_err("Could not create Tx mbuf pool.");
		goto rx_mp_free;
	}

	qp->tx_mp = mp;

	snprintf(name, sizeof(name), "lc_req_q_%u_%u", dev_id, qp_id);
	size = nb_desc * sizeof(struct liquid_crypto_inflight_req);

	qp->req_queue = rte_zmalloc(name, size, 0);
	if (qp->req_queue == NULL) {
		dao_err("Could not allocate memory for request queue.");
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

	dev->qp[qp_id] = qp;

	bm_mem_size = rte_bitmap_get_memory_footprint(nb_desc);
	if (bm_mem_size == 0) {
		dao_err("Could not get memory footprint for bitmap.");
		goto req_queue_free;
	}

	snprintf(name, sizeof(name), "liquid_crypto_bm_%u_%u", dev_id, qp_id);
	qp->req_bm_mem = rte_zmalloc(name, bm_mem_size, 0);
	if (qp->req_bm_mem == NULL) {
		dao_err("Could not allocate memory for bitmap.");
		goto req_queue_free;
	}

	qp->req_bm = rte_bitmap_init_with_all_set(nb_desc, qp->req_bm_mem, bm_mem_size);
	if (qp->req_bm == NULL) {
		dao_err("Could not initialize bitmap.");
		goto bm_mem_free;
	}

	return 0;

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
	return -ENOMEM;
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
	int rc;

	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}

	rc = dao_eth_trs_dev_start(dev_id);
	if (rc != 0) {
		dao_err("Could not start ethernet transport device.");
		return rc;
	}

	return 0;
}

int
dao_liquid_crypto_dev_stop(uint8_t dev_id)
{
	int rc;

	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}

	rc = dao_eth_trs_dev_stop(dev_id);
	if (rc != 0) {
		dao_err("Could not stop ethernet transport device.");
		return rc;
	}

	return 0;
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
	qp = dev->qp[qp_id];

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (qp == NULL) {
		dao_err("Invalid queue pair. Queue pair(%d, %d) not configured.", dev_id, qp_id);
		return -EINVAL;
	}
#endif

	mbuf = rte_pktmbuf_alloc(qp->tx_mp);
	if (unlikely(mbuf == NULL)) {
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		dao_err("Could not allocate mbuf.");
#endif
		return -ENOMEM;
	}

	req_idx = liquid_crypto_qp_req_idx_get(qp);

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (req_idx == UINT32_MAX) {
		dao_err("No available request index.");
		rc = -ENOSPC;
		goto mbuf_free;
	}
#endif

	qp->req_queue[req_idx].op_cookie = op_cookie;

	buf_len = RTE_MAX(sizeof(struct __dao_lc_hdr), LIQUID_CRYPTO_BUF_SZ_MIN);

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
		goto bm_put;
	}
#endif

	return 0;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
bm_put:
	liquid_crypto_qp_req_idx_put(qp, req_idx);
mbuf_free:
	rte_pktmbuf_free(mbuf);
#endif
	return rc;
}

#ifdef DAO_LIQUID_CRYPTO_DEBUG
static inline int
cpt_ae_rsa_mod_len_check(uint16_t mod_len)
{
	if (mod_len % 2 != 0) {
		dao_err("Invalid modulus length. mod_len must be even.");
		return -EINVAL;
	}

	if (mod_len < LIQUID_CRYPTO_RSA_MOD_LEN_MIN || mod_len > LIQUID_CRYPTO_RSA_MOD_LEN_MAX) {
		dao_err("Invalid modulus length. mod_len should be at least %u and at most %u bytes.",
			LIQUID_CRYPTO_RSA_MOD_LEN_MIN, LIQUID_CRYPTO_RSA_MOD_LEN_MAX);
		return -EINVAL;
	}

	return 0;
}

static inline int
cpt_ae_rsa_msg_len_check(uint16_t mod_len, uint16_t msg_len)
{
	if (msg_len > mod_len - LIQUID_CRYPTO_RSA_MSG_LEN_PADDING) {
		dao_err("Invalid message length. msg_len should be at most %u bytes.",
			mod_len - LIQUID_CRYPTO_RSA_MSG_LEN_PADDING);
		return -EINVAL;
	}

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

	return 0;
}
#endif

int
dao_crypto_enqueue_op_pkcs1v15enc(uint8_t dev_id, uint16_t qp_id,
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
	qp = dev->qp[qp_id];

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	rc = cpt_ae_rsa_mod_len_check(mod_len);
	if (rc != 0)
		return rc;
#endif

	mbuf = rte_pktmbuf_alloc(qp->tx_mp);
	if (unlikely(mbuf == NULL)) {
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		dao_err("Could not allocate mbuf.");
#endif
		return -ENOMEM;
	}

	req_idx = liquid_crypto_qp_req_idx_get(qp);

	qp->req_queue[req_idx].op_cookie = op_cookie;
	qp->req_queue[req_idx].data_out = em;

	buf_len = sizeof(struct __dao_lc_req_asym) + dlen;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (buf_len < LIQUID_CRYPTO_BUF_SZ_MIN) {
		dao_err("Buffer length is less than the minimum supported.");
		rc = -EINVAL;
		goto mbuf_free;
	}
#endif

	/* Append transport header to mbuf */
	req = (struct __dao_lc_req_asym *)rte_pktmbuf_append(mbuf, buf_len);
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

	rte_eth_tx_burst(qp->port_id, qp->queue_id, &mbuf, 1);

	return 0;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
mbuf_free:
	rte_pktmbuf_free(mbuf);
	return rc;
#endif
	RTE_SET_USED(rc);
}

int
dao_crypto_enqueue_op_pkcs1v15dec(uint8_t dev_id, uint16_t qp_id,
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
	qp = dev->qp[qp_id];

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	rc = cpt_ae_rsa_mod_len_check(mod_len);
	if (rc != 0)
		return rc;
#endif

	mbuf = rte_pktmbuf_alloc(qp->tx_mp);
	if (unlikely(mbuf == NULL)) {
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		dao_err("Could not allocate mbuf.");
#endif
		return -ENOMEM;
	}

	req_idx = liquid_crypto_qp_req_idx_get(qp);

	qp->req_queue[req_idx].op_cookie = op_cookie;
	qp->req_queue[req_idx].data_out = msg;

	buf_len = sizeof(struct __dao_lc_req_asym) + dlen;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (buf_len < LIQUID_CRYPTO_BUF_SZ_MIN) {
		dao_err("Buffer length is less than the minimum supported.");
		rc = -EINVAL;
		goto mbuf_free;
	}
#endif

	/* Append transport header to mbuf */
	req = (struct __dao_lc_req_asym *)rte_pktmbuf_append(mbuf, buf_len);
	req->hdr.trs_hdr.op_type = DAO_ETH_TRS_OP_TYPE_CRYPTO_ASYM;
	req->hdr.trs_hdr.op_len = buf_len;
	req->hdr.req_idx = req_idx;

	/* Add instruction */
	w4.s.opcode_major = ROC_AE_MAJOR_OP_MODEX;
	w4.s.opcode_minor = ROC_AE_MINOR_OP_PKCS_DEC;
	w4.s.param1 = mod_len;
	w4.s.param2 = ((uint16_t)(exp_len) << 1) | (key_type == DAO_LC_RSA_KEY_TYPE_PRIVATE);
	w4.s.dlen = dlen;
	req->w4 = w4.u64;

	/* Add data */
	dptr = req->dptr;
	memcpy(dptr, mod, mod_len);
	dptr += mod_len;
	memcpy(dptr, exp, exp_len);
	dptr += exp_len;
	memcpy(dptr, em, mod_len);

	rte_eth_tx_burst(qp->port_id, qp->queue_id, &mbuf, 1);

	return 0;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
mbuf_free:
	rte_pktmbuf_free(mbuf);
	return rc;
#endif
	RTE_SET_USED(rc);
}

int
dao_crypto_enqueue_op_pkcs1v15enc_crt(uint8_t dev_id, uint16_t qp_id, uint16_t mod_len,
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
	qp = dev->qp[qp_id];

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	rc = cpt_ae_rsa_mod_len_check(mod_len);
	if (rc != 0)
		return rc;

	rc = cpt_ae_rsa_msg_len_check(mod_len, msg_len);
	if (rc != 0)
		return rc;

	rc = cpt_ae_rsa_crt_params_check(mod_len, q, dQ, p, dP, qInv);
	if (rc != 0)
		return rc;
#endif

	mbuf = rte_pktmbuf_alloc(qp->tx_mp);
	if (unlikely(mbuf == NULL)) {
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		dao_err("Could not allocate mbuf.");
#endif
		return -ENOMEM;
	}

	req_idx = liquid_crypto_qp_req_idx_get(qp);

	qp->req_queue[req_idx].op_cookie = op_cookie;
	qp->req_queue[req_idx].data_out = em;

	buf_len = sizeof(struct __dao_lc_req_asym) + dlen;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (buf_len < LIQUID_CRYPTO_BUF_SZ_MIN) {
		dao_err("Buffer length is less than the minimum supported.");
		rc = -EINVAL;
		goto mbuf_free;
	}
#endif

	/* Append transport header to mbuf */
	req = (struct __dao_lc_req_asym *)rte_pktmbuf_append(mbuf, buf_len);
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

	rte_eth_tx_burst(qp->port_id, qp->queue_id, &mbuf, 1);

	return 0;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
mbuf_free:
	rte_pktmbuf_free(mbuf);
	return rc;
#endif
	RTE_SET_USED(rc);
}

int
dao_crypto_enqueue_op_pkcs1v15dec_crt(uint8_t dev_id, uint16_t qp_id, uint16_t mod_len, uint8_t *q,
				      uint8_t *dQ, uint8_t *p, uint8_t *dP, uint8_t *qInv,
				      uint8_t *em, uint8_t *msg, uint64_t op_cookie)
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
#endif

	dev = &liquid_crypto_devs[dev_id];
	qp = dev->qp[qp_id];

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	rc = cpt_ae_rsa_mod_len_check(mod_len);
	if (rc != 0)
		return rc;

	rc = cpt_ae_rsa_crt_params_check(mod_len, q, dQ, p, dP, qInv);
	if (rc != 0)
		return rc;
#endif

	mbuf = rte_pktmbuf_alloc(qp->tx_mp);
	if (unlikely(mbuf == NULL)) {
#ifdef DAO_LIQUID_CRYPTO_DEBUG
		dao_err("Could not allocate mbuf.");
#endif
		return -ENOMEM;
	}

	req_idx = liquid_crypto_qp_req_idx_get(qp);
	qp->req_queue[req_idx].op_cookie = op_cookie;
	qp->req_queue[req_idx].data_out = msg;

	buf_len = sizeof(struct __dao_lc_req_asym) + dlen;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (buf_len < LIQUID_CRYPTO_BUF_SZ_MIN) {
		dao_err("Buffer length is less than the minimum supported.");
		rc = -EINVAL;
		goto mbuf_free;
	}
#endif

	/* Append transport header to mbuf */
	req = (struct __dao_lc_req_asym *)rte_pktmbuf_append(mbuf, buf_len);
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

	rte_eth_tx_burst(qp->port_id, qp->queue_id, &mbuf, 1);

	return 0;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
mbuf_free:
	rte_pktmbuf_free(mbuf);
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

uint16_t
dao_liquid_crypto_dequeue_burst(uint8_t dev_id, uint16_t qp_id, struct dao_lc_res *res,
				uint16_t nb_res)
{
	struct rte_mbuf *mbuf, *mbufs[LIQUID_CRYPTO_MAX_BURST];
	struct liquid_crypto_inflight_req *req;
	struct liquid_crypto_dev *dev;
	struct liquid_crypto_qp *qp;
	struct __dao_lc_hdr *lc_hdr;
	uint16_t nb_rx, i;

#ifdef DAO_LIQUID_CRYPTO_DEBUG
	if (dev_id >= lc_info.nb_dev) {
		dao_err("Invalid argument. dev_id must be between 0 and %u.", lc_info.nb_dev - 1);
		return -EINVAL;
	}
#endif

	dev = &liquid_crypto_devs[dev_id];
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
		case DAO_ETH_TRS_OP_TYPE_CRYPTO_SYM:
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
		rte_bitmap_set(qp->req_bm, lc_hdr->req_idx);
	}

	return nb_rx;
}
