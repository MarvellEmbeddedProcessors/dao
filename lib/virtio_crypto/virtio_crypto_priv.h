/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */
#ifndef __INCLUDE_VIRTIO_CRYPTO_PRIV_H__
#define __INCLUDE_VIRTIO_CRYPTO_PRIV_H__

#include <virtio_dev_priv.h>

struct virtio_crypto_queue {
	/* Fast path */
	/* Read only, shared by both service and worker */
	uintptr_t desc_base __rte_cache_aligned;
	uint32_t *notify_addr;
	uint16_t q_sz;
	uint16_t dma_vchan;

	/* Slow path */
	struct dao_virtio_cryptodev *dao_cryptodev __rte_cache_aligned;
	uint16_t qid;

	/* Read-Write worker. */

	/* Read-Write service. */
	uint32_t *cb_notify_addr;
	uint64_t *cb_intr_addr;

	/* Shadow Ring space */
	uint64_t sd_desc_base[] __rte_cache_aligned;
} __rte_cache_aligned;

struct virtio_cryptodev {
	struct virtio_dev dev;
	/* config flags */
	uint16_t flags;
	/* Cryptodev ID */
	uint16_t cdev_id;
	/** Default dequeue mempool */
	struct rte_mempool *pool;
	/* Host interrupt for callback */
	bool cb_enabled;

	/* Fast path */
	struct virtio_crypto_queue *qs[DAO_VIRTIO_MAX_QUEUES];
};

static inline struct virtio_cryptodev *
virtio_cryptodev_priv(struct dao_virtio_cryptodev *cryptodev)
{
	return (struct virtio_cryptodev *)cryptodev->reserved;
}

static inline struct virtio_cryptodev *
virtio_dev_to_cryptodev(struct virtio_dev *dev)
{
	return (struct virtio_cryptodev *)dev;
}

static inline struct dao_virtio_cryptodev *
virtio_cryptodev_to_dao(struct virtio_cryptodev *cryptodev)
{
	return (struct dao_virtio_cryptodev *)((uintptr_t)cryptodev -
					       offsetof(struct dao_virtio_cryptodev, reserved));
}

/*
 * Virtio crypto descriptor management ops
 */
#define VIRTIO_CRYPTO_DESC_MANAGE_DEF       (0)
#define VIRTIO_CRYPTO_DESC_MANAGE_NOINORDER RTE_BIT64(0)
#define VIRTIO_CRYPTO_DESC_MANAGE_LAST      RTE_BIT64(0)

#define M_NOORDER_F VIRTIO_CRYPTO_DESC_MANAGE_NOINORDER

#define VIRTIO_CRYPTO_DESC_MANAGE_MODES                                                            \
	M(def, VIRTIO_CRYPTO_DESC_MANAGE_DEF)                                                      \
	M(noinorder, M_NOORDER_F)

#define M(name, flags) int virtio_crypto_desc_manage_##name(uint16_t devid, uint16_t qp_count);

VIRTIO_CRYPTO_DESC_MANAGE_MODES
#undef M

#endif /* __INCLUDE_VIRTIO_CRYPTO_PRIV_H__ */
