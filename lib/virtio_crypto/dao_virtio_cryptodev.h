/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell
 */

/**
 * @file
 *
 * DAO virtio crypto library
 */

#ifndef __INCLUDE_DAO_VIRTIO_CRYPTO_H__
#define __INCLUDE_DAO_VIRTIO_CRYPTO_H__

#include <dao_virtio.h>

/** Virtio crypto device configuration */
struct dao_virtio_cryptodev_conf {
	/** PEM device ID */
	uint16_t pem_devid;
	/** Vchan to use for this virtio dev */
	uint16_t dma_vchan;
	/** Default dequeue mempool */
	struct rte_mempool *pool;
	/** ID of crypto device associated with this virtio device */
	uint16_t cdev_id;
};

/** Virtio crypto device data */
struct dao_virtio_cryptodev {
	/** Array of virtio queue pointers */
	void *qs[DAO_VIRTIO_MAX_QUEUES] __rte_cache_aligned;
	/** Dequeue function id */
	uint16_t deq_fn_id;
	/** Enqueue function id */
	uint16_t enq_fn_id;
	/** Descriptors management function id */
	uint16_t mgmt_fn_id;
#define DAO_VIRTIO_CRYPTODEV_MEM_SZ 8192
	uint8_t reserved[DAO_VIRTIO_CRYPTODEV_MEM_SZ];
};

/** Virtio crypto devices */
extern struct dao_virtio_cryptodev dao_virtio_cryptodevs[];

/* Fast path data */
/** Management function */
typedef int (*dao_crypto_desc_manage_fn_t)(uint16_t devid, uint16_t qp_count);

/** Array of management functions */
extern dao_crypto_desc_manage_fn_t dao_crypto_desc_manage_fns[];

/** Device status callback */
typedef int (*dao_virtio_cryptodev_status_cb_t)(uint16_t devid, uint8_t status);

/** Virtio crypto device callbacks */
struct dao_virtio_cryptodev_cbs {
	/** Device status callback */
	dao_virtio_cryptodev_status_cb_t status_cb;
};

/**
 * Virtio crypto device initialize.
 *
 * @param devid
 *    Virtio crypto device ID
 * @param conf
 *    Virtio crypto device config.
 * @return
 *    Zero on success.
 */
int dao_virtio_cryptodev_init(uint16_t devid, struct dao_virtio_cryptodev_conf *conf);

/**
 * Virtio crypto device cleanup.
 *
 * @param devid
 *    Virtio crypto device ID
 *
 * @return
 *    Zero on success.
 */
int dao_virtio_cryptodev_fini(uint16_t devid);

/**
 * Virtio crypto device callback register
 *
 * @param cbs
 *    Application callbacks for virtio crypto devices
 */
void dao_virtio_cryptodev_cb_register(struct dao_virtio_cryptodev_cbs *cbs);

/**
 * Virtio crypto device callback unregister
 */
void dao_virtio_cryptodev_cb_unregister(void);

/**
 * Fetch virtio cryptodev descriptors and acknowledge completions.
 *
 * To be called from service core as frequently as possible to
 * shadow descriptors between Host and Octeon memory.
 *
 * @param devid
 *    Virtio crypto device ID.
 * @param qp_count
 *    Number of queue pairs to manage.
 * @return
 *    Zero on success.
 */
static __rte_always_inline int
dao_virtio_crypto_desc_manage(uint16_t devid, uint16_t qp_count)
{
	struct dao_virtio_cryptodev *cryptodev = &dao_virtio_cryptodevs[devid];
	dao_crypto_desc_manage_fn_t mgmt_fn;

	mgmt_fn = dao_crypto_desc_manage_fns[cryptodev->mgmt_fn_id];

	return (*mgmt_fn)(devid, qp_count);
}

#endif /* __INCLUDE_DAO_VIRTIO_CRYPTO_H__ */
