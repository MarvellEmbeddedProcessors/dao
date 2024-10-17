/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <stdint.h>

#include <rte_common.h>
#include <rte_malloc.h>

#include <dao_virtio_cryptodev.h>
#include <spec/virtio_crypto.h>

#include "virtio_crypto_priv.h"

/** Virtio crypto devices */
struct dao_virtio_cryptodev dao_virtio_cryptodevs[DAO_VIRTIO_DEV_MAX + 1];

static struct dao_virtio_cryptodev_cbs user_cbs;

static void
virtio_cryptodev_cq_cmd_process(struct virtio_dev *dev, struct rte_dma_sge *src,
				struct rte_dma_sge *dst, uint16_t nb_desc)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(src);
	RTE_SET_USED(dst);
	RTE_SET_USED(nb_desc);
}

static void
virtio_cryptodev_clear_queue_info(struct virtio_cryptodev *cryptodev)
{
	struct dao_virtio_cryptodev *dao_cryptodev = virtio_cryptodev_to_dao(cryptodev);
	uint32_t max_vqs = cryptodev->dev.max_virtio_queues - 1;
	uint32_t i;

	for (i = 0; i < max_vqs; i++) {
		/* TODO: flush the queues */

		if (cryptodev->qs[i])
			rte_free(cryptodev->qs[i]);
		cryptodev->qs[i] = NULL;
		dao_cryptodev->qs[i] = NULL;
	}
}

static int
virtio_queue_driver_event_flag(struct virtio_dev *dev, rte_iova_t driver_area)
{
	struct vring_packed_desc_event *sd_driver_area;
	int16_t dev2mem = dao_dma_ctrl_dev2mem();
	uint16_t tmo_ms, event_flag;
	bool has_err = 0;
	int cnt, rc;

	sd_driver_area = rte_zmalloc("virtio_crypto_driver_area", sizeof(*sd_driver_area),
				     RTE_CACHE_LINE_SIZE);
	if (sd_driver_area == NULL) {
		dao_err("[dev %u] Couldn't allocate memory for virtqueue driver area", dev->dev_id);
		return -ENOMEM;
	}

	rc = rte_dma_copy(dev2mem, dev->dma_vchan, driver_area, (rte_iova_t)sd_driver_area,
			  sizeof(*sd_driver_area), RTE_DMA_OP_FLAG_SUBMIT);
	if (rc < 0) {
		dao_err("[dev %u] Couldn't submit dma for virtqueue driver area", dev->dev_id);
		goto exit;
	}

	rc = 0;
	tmo_ms = VIRTIO_DMA_TMO_MS;
	do {
		rte_delay_us_sleep(1000);
		cnt = rte_dma_completed(dev2mem, dev->dma_vchan, 1, NULL, &has_err);
		tmo_ms--;
		if (unlikely(has_err))
			dao_err("[dev %u] DMA failed for driver event flag", dev->dev_id);
		if (!tmo_ms) {
			dao_err("[dev %u] DMA timeout for driver event flag", dev->dev_id);
			rc = -EFAULT;
			goto exit;
		}
	} while (cnt != 1);

	event_flag = sd_driver_area->desc_event_flags;
exit:
	rte_free(sd_driver_area);
	if (rc)
		return rc;

	return event_flag;
}

static void
virtio_cryptodev_cb_interrupt_conf(struct virtio_cryptodev *cryptodev)
{
	uint32_t max_vqs = cryptodev->dev.max_virtio_queues - 1;
	struct virtio_dev *dev = &cryptodev->dev;
	struct virtio_crypto_queue *queue;
	uint32_t i, intr_idx;

	intr_idx = 0;
	for (i = 0; i < max_vqs; i++) {
		queue = cryptodev->qs[i];
		if (!queue)
			continue;

		queue->cb_intr_addr = dev->cb_intr_addr[intr_idx];
		queue->cb_notify_addr = queue->notify_addr + 1;
		__atomic_store_n(queue->cb_notify_addr, 0, __ATOMIC_RELAXED);
		intr_idx = (intr_idx + 1) % dev->nb_cb_intrs;
	}

	cryptodev->cb_enabled = 1;
	dao_dbg("[dev %u] Enabled driver events for %u queues", dev->dev_id, max_vqs);
}

static int
virtio_cryptodev_driver_ok_handle(struct virtio_dev *dev)
{
	struct virtio_cryptodev *cryptodev = virtio_dev_to_cryptodev(dev);
	struct virtio_queue_conf *q_conf;
	bool cb_enabled = false;
	rte_iova_t driver_area;
	int event_flag, i;

	/* Fetch event suppression data if queues is enabled */
	for (i = 0; i < dev->max_virtio_queues; i++) {
		q_conf = &dev->queue_conf[i];
		if (!q_conf->queue_enable)
			continue;

		driver_area = ((uint64_t)q_conf->queue_avail_hi << 32) | (q_conf->queue_avail_lo);
		event_flag = virtio_queue_driver_event_flag(dev, driver_area);
		if (event_flag < 0)
			continue;

		if (event_flag != RING_EVENT_FLAGS_DISABLE) {
			cb_enabled = true;
			break;
		}
	}

	/* Enable interrupts event if one queue wants events delivered */
	if (cb_enabled) {
		dao_dbg("Enabling driver events for queues");
		virtio_cryptodev_cb_interrupt_conf(cryptodev);
	}

	return 0;
}

static int
virtio_cryptodev_reset_handle(struct virtio_dev *dev)
{
	struct virtio_cryptodev *cryptodev = virtio_dev_to_cryptodev(dev);
	struct virtio_crypto_queue *queue;
	uint32_t i;

	for (i = 0; i < (DAO_VIRTIO_MAX_QUEUES - 1); i++) {
		queue = cryptodev->qs[i];

		/*
		 * DMA vchan is common for a device. Pick vchan from any queue and wait for it's
		 * completion to make sure all transactions on the device is complete.
		 */

		if (queue != NULL) {
			dao_dma_compl_wait(queue->dma_vchan);
			break;
		}
	}

	virtio_cryptodev_clear_queue_info(cryptodev);

	return 0;
}

static int
virtio_cryptodev_status_cb(struct virtio_dev *dev, uint8_t status)
{
	struct virtio_cryptodev *cryptodev = virtio_dev_to_cryptodev(dev);
	int rc;

	if (user_cbs.status_cb == NULL)
		return -ENOTSUP;

	rc = user_cbs.status_cb(cryptodev->dev.dev_id, status);
	if (rc)
		return rc;

	switch (status) {
	case VIRTIO_DEV_DRIVER_OK:
		return virtio_cryptodev_driver_ok_handle(dev);
	case VIRTIO_DEV_RESET:
		return virtio_cryptodev_reset_handle(dev);
	default:
		dao_err("[dev %u] Unknown status %u", dev->dev_id, status);
		return -EINVAL;
	}
}

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

	/* One time setup */
	dev_cbs[VIRTIO_DEV_TYPE_CRYPTO].dev_status = virtio_cryptodev_status_cb;
	dev_cbs[VIRTIO_DEV_TYPE_CRYPTO].cq_cmd_process = virtio_cryptodev_cq_cmd_process;

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
