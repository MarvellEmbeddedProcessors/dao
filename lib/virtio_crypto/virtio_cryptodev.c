/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <stdint.h>

#include <rte_common.h>
#include <rte_malloc.h>

#include <dao_virtio_cryptodev.h>
#include <spec/virtio_crypto.h>

#include "virtio_crypto_akcipher.h"
#include "virtio_crypto_priv.h"
#include "virtio_dev_priv.h"

struct virtio_crypto_queue_map {
	uint16_t cryptodev_id;
	uint16_t cryptodev_qp_cnt;
	struct rte_mempool *mempool[DAO_VIRTIO_CRYPTO_QP_MAX];
	struct dao_virtio_cryptodev_vdev_q crypto_queue_map[DAO_VIRTIO_CRYPTO_QP_MAX];
};

static struct virtio_crypto_queue_map dev_map[DAO_VIRTIO_CRYPTO_DEV_MAX];

/** Virtio crypto devices */
struct dao_virtio_cryptodev dao_virtio_cryptodevs[DAO_VIRTIO_DEV_MAX + 1];

dao_crypto_desc_manage_fn_t dao_crypto_desc_manage_fns[VIRTIO_CRYPTO_DESC_MANAGE_LAST << 1] = {
#define M(name, flags) [flags] = virtio_crypto_desc_manage_##name,
	VIRTIO_CRYPTO_DESC_MANAGE_MODES
#undef M
};

static struct dao_virtio_cryptodev_cbs user_cbs;

static void
virtio_cryptodev_cq_interrupt_trigger(struct virtio_cryptodev *cryptodev)
{
	__atomic_store_n(cryptodev->cq_cb_notify_addr, 1, __ATOMIC_RELAXED);
	__atomic_store_n(cryptodev->cq_cb_intr_addr, (1UL << 59), __ATOMIC_RELAXED);
}

static void
virtio_cryptodev_cq_cmd_process(struct virtio_dev *dev, struct rte_dma_sge *src,
				struct rte_dma_sge *dst, uint16_t nb_desc)
{
	struct virtio_crypto_op_ctrl_req *ctrl_req =
		(struct virtio_crypto_op_ctrl_req *)dst[0].addr;
	struct virtio_cryptodev *cryptodev = virtio_dev_to_cryptodev(dev);
	struct virtio_crypto_ctrl_header *ctrl_cmd = &ctrl_req->header;
	struct virtio_crypto_session_input session_input = {0};
	int16_t mem2dev = dao_dma_ctrl_mem2dev();
	struct rte_crypto_asym_xform asym_xform;
	struct virtio_crypto_inhdr inhdr = {0};
	uint16_t tmo_ms, cnt, cdev_id;
	bool has_err = 0;
	int ack_len = 0;
	int rc;

	cdev_id = cryptodev->cdev_id;

	dao_dbg("[dev %u] cq opcode: %u algo: %u nb_desc %d", dev->dev_id, ctrl_cmd->opcode,
		ctrl_cmd->algo, nb_desc);

	if (ctrl_cmd->opcode == VIRTIO_CRYPTO_AKCIPHER_CREATE_SESSION) {
		memset(&asym_xform, 0, sizeof(asym_xform));

		switch (ctrl_cmd->algo) {
		case VIRTIO_CRYPTO_AKCIPHER_RSA:

			if (virtio_crypto_akcipher_rsa_xform_prepare(ctrl_req, &asym_xform) != 0) {
				dao_err("Invalid RSA session parameters");
				break;
			}
			session_input.session_id =
				user_cbs.asym_sess_create_cb(cdev_id, &asym_xform);
			break;
		default:
			dao_warn("[dev %u] opcode:algo=%u:%u  is not supported", dev->dev_id,
				 ctrl_cmd->opcode, ctrl_cmd->algo);
			break;
		}

		/* Prepare ACK status */
		if (session_input.session_id) {
			/* Session created successfully. */
			dao_info("Session id: %lx created", session_input.session_id);
			session_input.status = VIRTIO_CRYPTO_OK;
		} else {
			/* Session creation failed. */
			dao_err("Session failed");
			session_input.status = VIRTIO_CRYPTO_ERR;
		}
		ack_len = sizeof(session_input);
		memcpy((void *)dst[0].addr, &session_input, ack_len);
	} else if (ctrl_cmd->opcode == VIRTIO_CRYPTO_AKCIPHER_DESTROY_SESSION) {
		user_cbs.asym_sess_destroy_cb(cdev_id, ctrl_req->u.destroy_session.session_id);

		/* Prepare ACK status */
		inhdr.status = VIRTIO_CRYPTO_OK;
		ack_len = sizeof(inhdr);
		memcpy((void *)dst[0].addr, &inhdr, ack_len);
		dao_info("Session_id: %lx freed", ctrl_req->u.destroy_session.session_id);
	} else {
		dao_warn("[dev %u] opcode=%u  is not supported", dev->dev_id, ctrl_cmd->opcode);
	}

	/* DMA ACK status to the host */
	rc = rte_dma_copy(mem2dev, dev->dma_vchan, dst[0].addr, src[nb_desc - 1].addr, ack_len,
			  RTE_DMA_OP_FLAG_SUBMIT);
	if (rc < 0) {
		dao_err("[dev %u] Couldn't submit dma for cq ack status", dev->dev_id);
		return;
	}
	tmo_ms = VIRTIO_DMA_TMO_MS;
	do {
		rte_delay_us_sleep(1000);
		cnt = rte_dma_completed(mem2dev, dev->dma_vchan, 1, NULL, &has_err);
		tmo_ms--;
		if (unlikely(has_err))
			dao_err("[dev %u] DMA failed for control queue ack status", dev->dev_id);
		if (!tmo_ms) {
			dao_err("[dev %u] DMA timeout for control queue ack status", dev->dev_id);
			break;
		}
	} while (cnt != 1);

	if (cryptodev->cb_enabled)
		virtio_cryptodev_cq_interrupt_trigger(cryptodev);
}

static void
virtio_cryptodev_clear_queue_info(struct virtio_cryptodev *cryptodev)
{
	struct dao_virtio_cryptodev *dao_cryptodev = virtio_cryptodev_to_dao(cryptodev);
	uint32_t max_vqs = cryptodev->dev.max_virtio_queues - 1;
	uint32_t i;

	for (i = 0; i < max_vqs; i++) {
		/* TODO: flush the queues */

		dao_virtio_cryptodev_cdev_queue_release(cryptodev->dev.dev_id, i);

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

	/**
	 * Configure the necessary addresses to trigger the control queue interrupt.
	 * This setup is essential for the proper functioning of the control queue
	 * in the virtio crypto device.
	 */
	cryptodev->cq_cb_intr_addr = dev->cb_intr_addr[intr_idx];
	cryptodev->cq_cb_notify_addr =
		(uint32_t *)(dev->notify_base + (max_vqs * dev->notify_off_mltpr)) + 1;
	__atomic_store_n(cryptodev->cq_cb_notify_addr, 0, __ATOMIC_RELAXED);

	cryptodev->cb_enabled = 1;
	dao_dbg("[dev %u] Enabled driver events for %u queues", dev->dev_id, max_vqs);
}

static int
virtio_cryptodev_queue_enable(struct virtio_dev *dev, uint16_t queue_id)
{
	struct dao_virtio_cryptodev *dao_cryptodev;
	uint16_t cryptodev_id, cryptodev_qp_id;
	struct rte_mempool *mempool = NULL;
	struct virtio_cryptodev *cryptodev;
	struct virtio_crypto_queue *queue;
	struct virtio_queue_conf *q_conf;
	uint32_t shadow_area;
	uint16_t start_off;
	uint32_t max_vqs;
	int ret;

	cryptodev = virtio_dev_to_cryptodev(dev);
	dao_cryptodev = virtio_cryptodev_to_dao(cryptodev);
	max_vqs = cryptodev->dev.max_virtio_queues - 1;

	if (queue_id >= max_vqs)
		return -EINVAL;

	ret = dao_virtio_cryptodev_cdev_queue_assign(dev->dev_id, queue_id);
	if (ret) {
		dao_info("[dev %u] Could not assign a cryptodev queue for virt queue %d",
			 dev->dev_id, queue_id);
		return -ENOTSUP;
	}

	ret = dao_virtio_cryptodev_cdev_map_queue_get(dev->dev_id, queue_id, &cryptodev_id,
						      &cryptodev_qp_id, &mempool);
	if (ret) {
		dao_info("[dev %u] No cryptodev queue mapped for queue %d", dev->dev_id, queue_id);
		return -ENOTSUP;
	}

	dao_cryptodev->cdev_id = cryptodev_id;
	dao_cryptodev->cdev_qp_id_map[queue_id] = cryptodev_qp_id;

	q_conf = &dev->queue_conf[queue_id];
	if (!q_conf->queue_enable || cryptodev->qs[queue_id] != NULL)
		return 0;

	/* Setup queue assuming only packed virt queue */

	/*
	 * Calculate shadow queue size. Shadow queue should be large enough to hold all descriptors.
	 */
	shadow_area = q_conf->queue_size * sizeof(struct vring_packed_desc);
	shadow_area = RTE_ALIGN(shadow_area, RTE_CACHE_LINE_SIZE);

	queue = rte_zmalloc("virtio_crypto_queue", sizeof(*queue) + shadow_area,
			    RTE_CACHE_LINE_SIZE);
	if (queue == NULL) {
		dao_err("[dev %u] Failed to allocate memory for virtio queue", dev->dev_id);
		return -ENOMEM;
	}

	queue->desc_base = (((uint64_t)q_conf->queue_desc_hi << 32) | (q_conf->queue_desc_lo));
	queue->q_sz = q_conf->queue_size;

	queue->notify_addr = (uint32_t *)(dev->notify_base + (queue_id * dev->notify_off_mltpr));

	/* Initial queue wrap counter is 1 as per spec? */
	start_off = RTE_BIT64(15);

	queue->shadow_q_head = start_off;
	queue->shadow_q_tail = start_off;
	queue->dma_shadow_q_head = start_off;
	queue->dma_shadow_q_tail = start_off;

	queue->data_q_head = start_off;
	queue->data_q_tail = start_off;
	queue->dma_data_q_head = start_off;
	queue->dma_data_q_tail = start_off;

	queue->mem2dev_desc_dma_pending = 0;
	queue->mem2dev_desc_dma_idx = 0;
	queue->dev2mem_desc_dma_idx = 0;

	queue->dev2mem_data_dma_idx = 0;
	queue->mem2dev_data_dma_idx = 0;

	queue->qid = queue_id;
	queue->dma_vchan = dev->dma_vchan;
	cryptodev->qs[queue_id] = queue;
	dao_cryptodev->qs[queue_id] = queue;
	queue->dao_cryptodev = dao_cryptodev;

	queue->cryptodev_id = cryptodev_id;
	queue->cryptodev_qp_id = cryptodev_qp_id;
	queue->mp = mempool;
	queue->nb_cache_buf_rx = 0;
	queue->nb_cache_buf_tx = 0;

	dao_dbg("[dev %u] Adding queue%d: desc_base %p q_sz %u", dev->dev_id, queue_id,
		(void *)queue->desc_base, queue->q_sz);
	dao_dbg("[dev %u] Adding queue[%d]: notify_addr %p val %08x", dev->dev_id, queue_id,
		queue->notify_addr, *queue->notify_addr);

	return 0;
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

static uint16_t
virtio_cryptodev_cq_id_get(struct virtio_dev *dev, uint64_t feature_bits)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(feature_bits);

	return dev->max_virtio_queues - 1;
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

	/* TODO determine this from capabilities.*/
	dev_cfg->akcipher_algo = RTE_BIT64(VIRTIO_CRYPTO_AKCIPHER_RSA);
	dev_cfg->cipher_algo_l = RTE_BIT32(VIRTIO_CRYPTO_CIPHER_AES_CBC);

	/* One time setup */
	dev_cbs[VIRTIO_DEV_TYPE_CRYPTO].dev_status = virtio_cryptodev_status_cb;
	dev_cbs[VIRTIO_DEV_TYPE_CRYPTO].cq_cmd_process = virtio_cryptodev_cq_cmd_process;
	dev_cbs[VIRTIO_DEV_TYPE_CRYPTO].cq_id_get = virtio_cryptodev_cq_id_get;
	dev_cbs[VIRTIO_DEV_TYPE_CRYPTO].queue_enable = virtio_cryptodev_queue_enable;

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

void
dao_virtio_cryptodev_cb_register(struct dao_virtio_cryptodev_cbs *cbs)
{
	user_cbs = *cbs;
}

void
dao_virtio_cryptodev_cb_unregister(void)
{
	memset(&user_cbs, 0, sizeof(user_cbs));
}

uint16_t
dao_virtio_cryptodev_data_queue_cnt_get(uint16_t dev_id)
{
	struct dao_virtio_cryptodev *virtio_cryptodev = &dao_virtio_cryptodevs[dev_id];
	struct virtio_cryptodev *cryptodev = virtio_cryptodev_priv(virtio_cryptodev);
	uint16_t cnt;

	for (cnt = 0; cnt < cryptodev->dev.max_virtio_queues - 1; cnt++) {
		if (cryptodev->qs[cnt] == NULL)
			break;
	}

	return cnt;
}

void
dao_virtio_cryptodev_common_cfg_init(void)
{
	uint16_t i, j;

	for (i = 0; i < DAO_VIRTIO_CRYPTO_DEV_MAX; i++) {
		dev_map[i].cryptodev_id = DAO_VIRTIO_INVALID_ID;
		for (j = 0; j < DAO_VIRTIO_CRYPTO_QP_MAX; j++) {
			dev_map[i].crypto_queue_map[j].virtio_dev_id = DAO_VIRTIO_INVALID_ID;
			dev_map[i].crypto_queue_map[j].virtio_queue_id = DAO_VIRTIO_INVALID_ID;
		}
	}
}

int
dao_virtio_cryptodev_cdev_add(uint16_t dev_id, uint16_t qp_count, struct rte_mempool *mempool[])
{
	uint16_t i;

	if (dev_id >= DAO_VIRTIO_CRYPTO_DEV_MAX)
		return -EINVAL;

	if (qp_count > DAO_VIRTIO_CRYPTO_QP_MAX)
		return -EINVAL;

	for (i = 0; i < qp_count; i++) {
		if (mempool[i] == NULL)
			return -EINVAL;
	}

	for (i = 0; i < DAO_VIRTIO_CRYPTO_DEV_MAX; i++) {
		if (dev_map[i].cryptodev_id == DAO_VIRTIO_INVALID_ID) {
			dev_map[i].cryptodev_id = dev_id;
			dev_map[i].cryptodev_qp_cnt = qp_count;
			memcpy(dev_map[i].mempool, mempool,
			       sizeof(struct rte_mempool *) * qp_count);
			return 0;
		}
	}

	return -ENOMEM;
}

int
dao_virtio_cryptodev_cdev_remove(uint16_t dev_id)
{
	uint16_t i, j;

	for (i = 0; i < DAO_VIRTIO_CRYPTO_DEV_MAX; i++) {
		if (dev_map[i].cryptodev_id == dev_id) {
			dev_map[i].cryptodev_id = DAO_VIRTIO_INVALID_ID;
			dev_map[i].cryptodev_qp_cnt = 0;
			for (j = 0; j < DAO_VIRTIO_CRYPTO_QP_MAX; j++) {
				dev_map[i].crypto_queue_map[j].virtio_dev_id =
					DAO_VIRTIO_INVALID_ID;
				dev_map[i].crypto_queue_map[j].virtio_queue_id =
					DAO_VIRTIO_INVALID_ID;
			}
			return 0;
		}
	}

	return -EINVAL;
}

int
dao_virtio_cryptodev_cdev_queue_assign(uint16_t virt_dev_id, uint16_t virt_queue_id)
{
	uint16_t i, j;

	for (i = 0; i < DAO_VIRTIO_CRYPTO_DEV_MAX; i++) {
		if (dev_map[i].cryptodev_id == DAO_VIRTIO_INVALID_ID)
			continue;

		for (j = 0; j < dev_map[i].cryptodev_qp_cnt; j++) {
			if (dev_map[i].crypto_queue_map[j].virtio_dev_id == DAO_VIRTIO_INVALID_ID) {
				dev_map[i].crypto_queue_map[j].virtio_dev_id = virt_dev_id;
				dev_map[i].crypto_queue_map[j].virtio_queue_id = virt_queue_id;
				return 0;
			}
		}
	}

	return -ENOMEM;
}

int
dao_virtio_cryptodev_cdev_queue_release(uint16_t virt_dev_id, uint16_t virt_queue_id)
{
	uint16_t i, j;

	for (i = 0; i < DAO_VIRTIO_CRYPTO_DEV_MAX; i++) {
		if (dev_map[i].cryptodev_id == DAO_VIRTIO_INVALID_ID)
			continue;

		for (j = 0; j < dev_map[i].cryptodev_qp_cnt; j++) {
			if (dev_map[i].crypto_queue_map[j].virtio_dev_id == virt_dev_id &&
			    dev_map[i].crypto_queue_map[j].virtio_queue_id == virt_queue_id) {
				dev_map[i].crypto_queue_map[j].virtio_dev_id =
					DAO_VIRTIO_INVALID_ID;
				dev_map[i].crypto_queue_map[j].virtio_queue_id =
					DAO_VIRTIO_INVALID_ID;
				return 0;
			}
		}
	}

	return -EINVAL;
}

int
dao_virtio_cryptodev_cdev_map_queue_get(uint16_t virt_dev_id, uint16_t virt_queue_id,
					uint16_t *cdev_id, uint16_t *cdev_qp_id,
					struct rte_mempool **mempool)
{
	uint16_t i, j;

	for (i = 0; i < DAO_VIRTIO_CRYPTO_DEV_MAX; i++) {
		if (dev_map[i].cryptodev_id == DAO_VIRTIO_INVALID_ID)
			continue;

		for (j = 0; j < dev_map[i].cryptodev_qp_cnt; j++) {
			if (dev_map[i].crypto_queue_map[j].virtio_dev_id == virt_dev_id &&
			    dev_map[i].crypto_queue_map[j].virtio_queue_id == virt_queue_id) {
				*cdev_id = dev_map[i].cryptodev_id;
				*cdev_qp_id = j;
				*mempool = dev_map[i].mempool[j];
				return 0;
			}
		}
	}

	return -EINVAL;
}

int
dao_virtio_cryptodev_virt_dev_map_queue_get(uint16_t cdev_id, uint16_t cdev_qp_id,
					    uint16_t *virt_dev_id, uint16_t *virt_queue_id)
{
	if (cdev_id >= DAO_VIRTIO_CRYPTO_DEV_MAX)
		return -EINVAL;

	if (dev_map[cdev_id].cryptodev_id == DAO_VIRTIO_INVALID_ID)
		return -EINVAL;

	if (cdev_qp_id >= dev_map[cdev_id].cryptodev_qp_cnt)
		return -EINVAL;

	*virt_dev_id = dev_map[cdev_id].crypto_queue_map[cdev_qp_id].virtio_dev_id;
	*virt_queue_id = dev_map[cdev_id].crypto_queue_map[cdev_qp_id].virtio_queue_id;

	return 0;
}

const struct dao_virtio_cryptodev_vdev_q *
dao_virtio_cryptodev_cdev_map_all_queues_get(uint16_t cdev_id)
{
	if (cdev_id >= DAO_VIRTIO_CRYPTO_DEV_MAX)
		return NULL;

	if (dev_map[cdev_id].cryptodev_id == DAO_VIRTIO_INVALID_ID)
		return NULL;

	return dev_map[cdev_id].crypto_queue_map;
}

static __rte_always_inline int
virtio_crypto_desc_manage(uint16_t devid, uint16_t qp_count, const uint16_t flags)
{
	uint16_t start, end, dma_vchan, shadow_q_head, dma_shadow_q_head, nb_pend_desc, next_head;
	struct dao_virtio_cryptodev *virtio_cryptodev = &dao_virtio_cryptodevs[devid];
	struct virtio_cryptodev *cryptodev = virtio_cryptodev_priv(virtio_cryptodev);
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	struct dao_dma_vchan_state *dev2mem, *mem2dev;
	struct virtio_crypto_queue *q;
	uint32_t notify_data;
	uint16_t q_sz;
	int i;

	RTE_SET_USED(flags);
	RTE_SET_USED(start);
	RTE_SET_USED(end);

	dma_vchan = cryptodev->qs[0]->dma_vchan;
	dev2mem = &vchan_info->dev2mem[dma_vchan];
	mem2dev = &vchan_info->mem2dev[dma_vchan];

	/* Fetch all DMA completed status */
	dao_dma_check_compl(dev2mem);
	dao_dma_check_compl(mem2dev);

	/* Copy descriptor from host */

	for (i = 0; i < qp_count; i++) {
		q = cryptodev->qs[i];

		q_sz = q->q_sz;

		/* Check descriptor DMA completion and update state to notfiy worker cores */

		shadow_q_head = q->shadow_q_head;
		dma_shadow_q_head = __atomic_load_n(&q->dma_shadow_q_head, __ATOMIC_ACQUIRE);
		nb_pend_desc = desc_off_diff(shadow_q_head, dma_shadow_q_head, q_sz);

		if (nb_pend_desc && dao_dma_op_status(dev2mem, q->dev2mem_desc_dma_idx)) {
			/* Validate descriptor */
			VIRTIO_CRYPTO_DESC_CHECK(q, dma_shadow_q_head, nb_pend_desc, true, false);

			nb_pend_desc = 0;

			/*
			 * Since the last DMA is complete, all the pending DMAs would be done.
			 * Update DMA shadow queue head to shadow queue head.
			 */
			__atomic_store_n(&q->dma_shadow_q_head, shadow_q_head, __ATOMIC_RELEASE);
		}

		/* Determine the number of descriptors to be DMA'ed from host */

		notify_data = __atomic_load_n(q->notify_addr, __ATOMIC_RELAXED);
		next_head = (notify_data >> 16) & 0xFFFF;
		if (unlikely(nb_pend_desc || next_head == shadow_q_head))
			continue;

		/* For DMA copy, at least 2 slots are required. Skip if space is not available. */
		if (!dao_dma_flush(dev2mem, 2))
			break;

		/* Copy descriptors from host queue to shadow queue. */
		host_to_local_desc_copy(q, dev2mem, shadow_q_head, next_head);
	}

	/* Copy descriptors to host */

	for (i = 0; i < qp_count; i++) {
		q = cryptodev->qs[i];

		/* For DMA copy, at least 2 slots are required. Skip if space is not available. */
		if (!dao_dma_flush(mem2dev, 2))
			break;

		/* Check descriptor DMA completion and trigger host interrupt */
		if (q->cb_intr_addr && q->mem2dev_desc_dma_pending &&
		    dao_dma_op_status(mem2dev, q->mem2dev_desc_dma_idx)) {
			dao_err("Interrupt triggered");
			__atomic_store_n(q->cb_notify_addr, 1, __ATOMIC_RELAXED);
			__atomic_store_n(q->cb_intr_addr, (1UL << 59), __ATOMIC_RELAXED);

			/* Clear DMA pending status */
			q->mem2dev_desc_dma_pending = 0;
		}

		/* Determine the number of descriptors that need to be DMA'ed */
		start = q->dma_shadow_q_tail;
		end = __atomic_load_n(&q->shadow_q_tail, __ATOMIC_ACQUIRE);
		if (start == end)
			continue;

		/* Need space for at least 2 pointer */
		if (!dao_dma_flush(mem2dev, 2))
			break;

		/* Copy descriptors from shadow queue to host queue. */
		local_to_host_desc_copy(q, mem2dev, start, end);
	}

	return 0;
}

#define M(name, flags)                                                                             \
	int virtio_crypto_desc_manage_##name(uint16_t devid, uint16_t qp_count)                    \
	{                                                                                          \
		return virtio_crypto_desc_manage(devid, qp_count, (flags));                        \
	}

VIRTIO_CRYPTO_DESC_MANAGE_MODES
#undef M
