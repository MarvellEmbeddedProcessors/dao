/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */
#ifndef __INCLUDE_VIRTIO_CRYPTO_PRIV_H__
#define __INCLUDE_VIRTIO_CRYPTO_PRIV_H__

#include <virtio_dev_priv.h>

struct virtio_cryptodev {
	struct virtio_dev dev;
	/* config flags */
	uint16_t flags;
	/* Cryptodev ID */
	uint16_t cdev_id;
	/** Default dequeue mempool */
	struct rte_mempool *pool;

	/* Fast path */
	struct virtio_crypto_queue *qs[DAO_VIRTIO_MAX_QUEUES];
};

static inline struct virtio_cryptodev *
virtio_cryptodev_priv(struct dao_virtio_cryptodev *cryptodev)
{
	return (struct virtio_cryptodev *)cryptodev->reserved;
}

#endif /* __INCLUDE_VIRTIO_CRYPTO_PRIV_H__ */
