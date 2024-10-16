/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <stdint.h>

#include <rte_common.h>

#include <dao_virtio_cryptodev.h>
#include <spec/virtio_crypto.h>

#include "virtio_crypto_priv.h"

/** Virtio crypto devices */
struct dao_virtio_cryptodev dao_virtio_cryptodevs[DAO_VIRTIO_DEV_MAX + 1];

int
dao_virtio_cryptodev_init(uint16_t devid, struct dao_virtio_cryptodev_conf *conf)
{
	struct dao_virtio_cryptodev *virtio_cryptodev = &dao_virtio_cryptodevs[devid];
	struct virtio_cryptodev *cryptodev = virtio_cryptodev_priv(virtio_cryptodev);
	volatile struct virtio_crypto_config *dev_cfg;
	struct virtio_dev *dev = &cryptodev->dev;
	uint64_t services;
	int rc;

	dev->dev_id = devid;
	dev->dev_type = VIRTIO_DEV_TYPE_CRYPTO;
	dev->pem_devid = conf->pem_devid;
	dev->dma_vchan = conf->dma_vchan;
	cryptodev->pool = conf->pool;
	cryptodev->cdev_id = conf->cdev_id;

	/* Initialize base virtio device */
	rc = virtio_dev_init(dev);
	if (rc)
		return rc;

	/* Setup cryptodev config */
	dev_cfg = (volatile struct virtio_crypto_config *)dev->dev_cfg;
	services = RTE_BIT64(VIRTIO_CRYPTO_SERVICE_CIPHER) | RTE_BIT64(VIRTIO_CRYPTO_SERVICE_HASH) |
		   RTE_BIT64(VIRTIO_CRYPTO_SERVICE_MAC) | RTE_BIT64(VIRTIO_CRYPTO_SERVICE_AEAD) |
		   RTE_BIT64(VIRTIO_CRYPTO_SERVICE_AKCIPHER);

	dev_cfg->status |= VIRTIO_CRYPTO_S_HW_READY;
	dev_cfg->crypto_services = services;

	/*
	 * Host drivers expect 1 data virtqueue, followed by possible N-1 data queues used in
	 * multiqueue mode, followed by control VQ. Control VQ is the last virtio queue and is
	 * excluded from 'max_dataqueues' count.
	 */
	dev_cfg->max_dataqueues = dev->max_virtio_queues - 1;

	return 0;
}

int
dao_virtio_cryptodev_fini(uint16_t devid)
{
	struct dao_virtio_cryptodev *virtio_cryptodev = &dao_virtio_cryptodevs[devid];
	struct virtio_cryptodev *cryptodev = virtio_cryptodev_priv(virtio_cryptodev);
	struct virtio_dev *dev = &cryptodev->dev;

	return virtio_dev_fini(dev);
}
