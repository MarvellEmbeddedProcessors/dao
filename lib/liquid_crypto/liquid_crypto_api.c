/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <string.h>

#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include <dao_eth_trs.h>
#include <dao_liquid_crypto.h>
#include <dao_log.h>

#include "liquid_crypto_priv.h"

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
dao_liquid_crypto_dev_create(uint8_t dev_id, uint16_t nb_qp)
{
	struct dao_eth_trs_dev_config trs_conf;
	struct liquid_crypto_dev *dev;
	int rc;

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
	int rc;

	if (conf == NULL) {
		dao_err("Invalid argument.");
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

	snprintf(name, sizeof(name), "liquid_crypto_qp_%u_%u", dev_id, qp_id);

	qp = rte_zmalloc(name, sizeof(*qp), 0);
	if (qp == NULL) {
		dao_err("could not allocate memory.");
		return -ENOMEM;
	}

	/* Align to the next power of 2 to simplify datapath checks */
	nb_desc = rte_align32pow2(conf->nb_desc);

	max_seg_size = conf->max_seg_size;

	snprintf(name, sizeof(name), "liquid_crypto_rx_mp_%u_%u", dev_id, qp_id);

	mp = rte_pktmbuf_pool_create(name, nb_desc, 0, 0, max_seg_size, 0);
	if (mp == NULL) {
		dao_err("Could not create Rx mbuf pool.");
		goto qp_free;
	}

	qp->rx_mp = mp;

	snprintf(name, sizeof(name), "liquid_crypto_tx_mp_%u_%u", dev_id, qp_id);

	mp = rte_pktmbuf_pool_create(name, nb_desc, 0, 0, max_seg_size, 0);
	if (mp == NULL) {
		dao_err("Could not create Tx mbuf pool.");
		goto rx_mp_free;
	}

	qp->tx_mp = mp;

	trs_queue_conf.rx_mp = qp->rx_mp;
	trs_queue_conf.queue_size = nb_desc;
	rc = dao_eth_trs_dev_queue_configure(dev_id, qp_id, &trs_queue_conf);
	if (rc != 0) {
		dao_err("Could not configure ethernet transport queue.");
		goto tx_mp_free;
	}

	rc = dao_eth_trs_dev_queue_map(dev_id, qp_id, &qp->port_id, &qp->queue_id);
	if (rc != 0) {
		dao_err("Could not map ethernet transport queue.");
		goto tx_mp_free;
	}

	dev->qp[qp_id] = qp;

	return 0;

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
	/* Call eth TRS API
	 * - Enqueue the operation
	 * rte_eth_tx_burst()
	 */

	RTE_SET_USED(dev_id);
	RTE_SET_USED(qp_id);
	RTE_SET_USED(op_cookie);

	return -ENOTSUP;
}

uint16_t
dao_liquid_crypto_dequeue_burst(uint8_t dev_id, uint16_t qp_id, struct dao_lc_res *res,
				uint16_t nb_res)
{
	/* Call eth TRS API
	 * - Dequeue the operation
	 * rte_eth_rx_burst()
	 */

	RTE_SET_USED(dev_id);
	RTE_SET_USED(qp_id);
	RTE_SET_USED(res);
	RTE_SET_USED(nb_res);

	return 0;
}
