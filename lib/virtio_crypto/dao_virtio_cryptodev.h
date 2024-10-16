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

#endif /* __INCLUDE_DAO_VIRTIO_CRYPTO_H__ */
