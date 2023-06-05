/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2024 Marvell.
 */
#include <rte_io.h>
#include <rte_malloc.h>

#include "dao_virtio.h"
#include "virtio_dev_priv.h"
#include "virtio_mbox.h"

#define BIT_MASK32 (0xFFFFFFFFU)

#define VIRTIO_QUEUE_SELECT_DELAY  3
#define VIRTIO_DEVICE_STATUS_DELAY 5

#define VIRTIO_INVALID_QUEUE_INDEX 0xFFFF

struct virtio_ctrl_queue {
	uintptr_t desc_base;
	uint32_t *notify_addr;
	uint16_t q_sz;
	uint16_t last_off;
	uint16_t dma_vchan;
	struct virtio_dev *dev;

	uint16_t sd_desc_off;
	/* Shadow Ring space */
	uint64_t sd_desc_base[] __rte_cache_aligned;
} __rte_cache_aligned;

struct virtio_dev_cbs dev_cbs[VIRTIO_DEV_TYPE_MAX];

static int
virtio_process_device_feature_select(struct virtio_dev *dev, uintptr_t shadow,
				     uint32_t device_feature_select)
{
	struct virtio_pci_common_cfg *shadow_cfg = (struct virtio_pci_common_cfg *)shadow;
	volatile struct virtio_pci_common_cfg *common_cfg = dev->common_cfg;
	uint32_t feature_select = device_feature_select & 0x7fff;

	if (feature_select == 0)
		common_cfg->device_feature = (uint32_t)dev->dev_feature_bits & BIT_MASK32;
	else if (feature_select == 1)
		common_cfg->device_feature = (uint32_t)(dev->dev_feature_bits >> 32) & BIT_MASK32;

	dao_dbg("[dev %u] device_feature[%u]: 0x%08x", dev->dev_id, feature_select,
		common_cfg->device_feature);

	rte_wmb();
	shadow_cfg->device_feature_select = feature_select;
	shadow_cfg->device_feature = dev->common_cfg->device_feature;
	dev->common_cfg->device_feature_select = feature_select;
	rte_wmb();

	return 0;
}

static int
virtio_process_device_feature(struct virtio_dev *dev, uint32_t device_feature)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(device_feature);

	dao_dbg("[dev %u] device_feature: 0x%08x", dev->dev_id, device_feature);
	return 0;
}

static int
virtio_process_driver_feature_select(struct virtio_dev *dev, uintptr_t shadow,
				     uint32_t driver_feature_select)
{
	struct virtio_pci_common_cfg *shadow_cfg = (struct virtio_pci_common_cfg *)shadow;
	uint32_t prev_feature_select = dev->prev_drv_feature_select;
	uint32_t feature_select = driver_feature_select & 0x7fff;

	if (prev_feature_select != 0xffff) {
		if (prev_feature_select == 0)
			dev->drv_feature_bits_lo = dev->common_cfg->driver_feature;
		else if (prev_feature_select == 1)
			dev->drv_feature_bits_hi = dev->common_cfg->driver_feature;

		dao_dbg("[dev %u] driver_feature[%u]: 0x%08x", dev->dev_id, prev_feature_select,
			dev->common_cfg->driver_feature);
	}

	/* Store feature select as driver can proceed to write driver feature and again
	 * change driver feature select before device processing device_feature of
	 * previous one.
	 */
	dev->prev_drv_feature_select = feature_select;
	if (feature_select == 0)
		dev->common_cfg->driver_feature = dev->drv_feature_bits_lo;
	else if (feature_select == 1)
		dev->common_cfg->driver_feature = dev->drv_feature_bits_hi;

	rte_wmb();
	shadow_cfg->driver_feature_select = feature_select;
	shadow_cfg->driver_feature = dev->common_cfg->driver_feature;
	dev->common_cfg->driver_feature_select = feature_select;
	rte_wmb();

	dao_dbg("[dev %u] driver_feature[%u]: 0x%08x", dev->dev_id, feature_select,
		dev->common_cfg->driver_feature);
	return 0;
}

static int
virtio_process_driver_feature(struct virtio_dev *dev, uintptr_t shadow, uint32_t driver_feature)
{
	struct virtio_pci_common_cfg *shadow_cfg = (struct virtio_pci_common_cfg *)shadow;
	uint32_t feature_select = dev->common_cfg->driver_feature_select;

	if (feature_select == 0)
		dev->drv_feature_bits_lo = driver_feature;
	else if (feature_select == 1)
		dev->drv_feature_bits_hi = driver_feature;

	dao_dbg("[dev %u] driver_feature[%u]: 0x%08x", dev->dev_id, feature_select, driver_feature);

	shadow_cfg->driver_feature = driver_feature;
	rte_wmb();

	return 0;
}

static int
virtio_process_config_msix_vector(struct virtio_dev *dev, uintptr_t shadow,
				  uint32_t config_msix_vector)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(config_msix_vector);
	RTE_SET_USED(shadow);

	return 0;
}

static void
virtio_config_populate(struct virtio_dev *dev)
{
	volatile struct virtio_pci_common_cfg *common_cfg = dev->common_cfg;
	uint16_t max_virtio_queues = dev->max_virtio_queues;
	uint32_t *notify_addr;
	uint32_t i;

	/* Populate common config and init notify area with initial wrap count */
	common_cfg->num_queues = max_virtio_queues;
	common_cfg->device_feature_select = -1;
	common_cfg->driver_feature_select = -1;

	/* Reset notification area */
	for (i = 0; i < max_virtio_queues; i++) {
		notify_addr = (uint32_t *)(dev->notify_base + (i * dev->notify_off_mltpr));
		__atomic_store_n(notify_addr, RTE_BIT64(15) << 16, __ATOMIC_RELAXED);
	}

	dev->prev_queue_select = VIRTIO_INVALID_QUEUE_INDEX;
	dev->prev_drv_feature_select = 0xffff;

	/* Initialize queue config defaults */
	memset(dev->queue_conf, 0, max_virtio_queues * sizeof(struct virtio_queue_conf));
	for (i = 0; i < max_virtio_queues; i++)
		dev->queue_conf[i].queue_size = DAO_VIRTIO_MAX_QUEUE_SZ;

	dev->feature_bits = dev->dev_feature_bits;
}

static int
process_descs(struct virtio_ctrl_queue *q, struct rte_dma_sge *cmd_src, struct rte_dma_sge *cmd_dst,
	      uint16_t nb_desc)
{
	uintptr_t sd_desc_base = (uintptr_t)q->sd_desc_base;
	int16_t dev2mem = dao_dma_ctrl_dev2mem();
	uintptr_t desc_base = q->desc_base;
	uint32_t i, j, len, tot_len = 0;
	struct virtio_dev *dev = q->dev;
	rte_iova_t src, dst;
	uint16_t off, cnt;
	bool has_err = 0;
	uint16_t tmo_ms;
	int rc;

	/* Start DMA of descriptors */
	off = DESC_OFF(q->sd_desc_off);
	src = (rte_iova_t)DESC_PTR_OFF(desc_base, off, 0);
	dst = (rte_iova_t)DESC_PTR_OFF(sd_desc_base, off, 0);

	rc = rte_dma_copy(dev2mem, q->dma_vchan, src, dst, nb_desc << 4, RTE_DMA_OP_FLAG_SUBMIT);
	if (rc < 0) {
		dao_err("[dev %u] Couldn't submit dma for cq descriptors", dev->dev_id);
		return -ENOMEM;
	}

	tmo_ms = VIRTIO_DMA_TMO_MS;
	do {
		rte_delay_us_sleep(1000);
		cnt = rte_dma_completed(dev2mem, q->dma_vchan, 1, NULL, &has_err);
		tmo_ms--;
		if (unlikely(has_err))
			dao_err("[dev %u] DMA failed for cq descriptors", dev->dev_id);
		if (!tmo_ms) {
			dao_err("[dev %u] DMA timeout for cq descriptors", dev->dev_id);
			return -EFAULT;
		}
	} while (cnt != 1);

	for (i = off, j = 0; i < (off + nb_desc); i++, j++) {
		len = *DESC_PTR_OFF(sd_desc_base, i, 8) & (RTE_BIT64(32) - 1);
		cmd_src[j].addr = *DESC_PTR_OFF(sd_desc_base, i, 0);
		cmd_src[j].length = len;
		tot_len += len;
	}
	/* Allocate memory to DMA command in multiple descriptors to
	 * single pointer */
	cmd_dst[0].addr = (rte_iova_t)rte_zmalloc(NULL, tot_len, 0);
	if (cmd_dst[0].addr == 0) {
		dao_err("[dev %u] Couldn't allocate memory for cq command, tot_len=%u", dev->dev_id,
			tot_len);
		return -ENOMEM;
	}

	cmd_dst[0].length = tot_len;
	rc = rte_dma_copy_sg(dev2mem, q->dma_vchan, cmd_src, cmd_dst, nb_desc, 1,
			     RTE_DMA_OP_FLAG_SUBMIT);
	if (rc < 0) {
		dao_err("[dev %u] Couldn't submit dma for cq command", dev->dev_id);
		rte_free((void *)cmd_dst[0].addr);
		return -ENOMEM;
	}

	tmo_ms = VIRTIO_DMA_TMO_MS;
	do {
		rte_delay_us_sleep(1000);
		cnt = rte_dma_completed(dev2mem, q->dma_vchan, 1, NULL, &has_err);
		tmo_ms--;
		if (unlikely(has_err))
			dao_err("[dev %u] DMA failed for cq command", dev->dev_id);
		if (!tmo_ms) {
			dao_err("[dev %u] DMA timeout for cq command", dev->dev_id);
			return -EFAULT;
		}
	} while (cnt != 1);

	return 0;
}

static void
virtio_cq_cmd_process(struct virtio_dev *dev)
{
	struct rte_dma_sge cmd_src[15], cmd_dst[15];
	int16_t mem2dev = dao_dma_ctrl_mem2dev();
	uint16_t nb_desc = 0, q_sz, next_off;
	uintptr_t desc_base, sd_desc_base;
	struct virtio_ctrl_queue *q;
	uint32_t notify_data;
	rte_iova_t src, dst;
	uint16_t tmo_ms;
	uint16_t cnt;
	int rc;

	q = dev->cq;

	q_sz = q->q_sz;
	desc_base = q->desc_base;
	sd_desc_base = (uintptr_t)q->sd_desc_base;

	/* Start DMA of valid descriptors */
	notify_data = *q->notify_addr;
	/* Include the wrap bit */
	next_off = (notify_data >> 16) & 0xFFFF;
	if (next_off != q->sd_desc_off)
		nb_desc = desc_off_diff_no_wrap(next_off, q->sd_desc_off, q_sz);

	dao_dbg("[dev %u] nb_desc: %d", dev->dev_id, nb_desc);
	if (!nb_desc)
		return;

	rc = process_descs(q, cmd_src, cmd_dst, nb_desc);
	if (rc < 0)
		return;

	dev_cbs[dev->dev_type].cq_cmd_process(dev, cmd_src, cmd_dst, nb_desc);

	/* Change the descriptor flag to USED */
	*DESC_PTR_OFF(sd_desc_base, q->sd_desc_off, 8) = VRING_DESC_F_WRITE;
	*DESC_PTR_OFF(sd_desc_base, q->sd_desc_off, 8) |= VIRT_PACKED_RING_DESC_F_AVAIL_USED;

	dst = (rte_iova_t)DESC_PTR_OFF(desc_base, q->sd_desc_off, 0);
	src = (rte_iova_t)DESC_PTR_OFF(sd_desc_base, q->sd_desc_off, 0);

	rc = rte_dma_copy(mem2dev, dev->dma_vchan, src, dst, 16, RTE_DMA_OP_FLAG_SUBMIT);
	if (rc < 0) {
		dao_err("[dev %u] Couldn't submit dma for cq desc completion", dev->dev_id);
		goto exit;
	}

	tmo_ms = VIRTIO_DMA_TMO_MS;
	do {
		rte_delay_us_sleep(1000);
		cnt = rte_dma_completed(mem2dev, dev->dma_vchan, 1, NULL, NULL);
		tmo_ms--;
		if (!tmo_ms) {
			dao_err("[dev %u] DMA timeout for cq desc completion", dev->dev_id);
			break;
		}
	} while (cnt != 1);

	/* Update processed descriptor offset */
	q->sd_desc_off = next_off;
exit:
	rte_free((void *)cmd_dst[0].addr);
}

static int
virtio_cq_notify_cb(void *ctx, uintptr_t shadow, uint32_t offset, uint64_t val, uint64_t shadow_val)
{
	struct virtio_dev *dev = ctx;

	RTE_SET_USED(shadow);
	RTE_SET_USED(offset);
	RTE_SET_USED(val);
	RTE_SET_USED(shadow_val);

	*((uint64_t *)shadow) = val;
	virtio_cq_cmd_process(dev);
	return 0;
}

static void
virtio_clear_cq_info(struct virtio_dev *dev)
{
	struct virtio_ctrl_queue *cq = dev->cq;

	if (!cq)
		return;
	dao_pem_ctrl_region_unregister(dev->pem_devid, (uintptr_t)cq->notify_addr, 8,
				       virtio_cq_notify_cb, dev);
	rte_free(cq);
	dev->cq = NULL;
}

static int
virtio_setup_cq_info(struct virtio_dev *dev)
{
	struct virtio_queue_conf *q_conf;
	struct virtio_ctrl_queue *cq;
	uint32_t shadow_area;
	uint16_t qid;
	int rc;

	/* Need features OK to setup CQ */
	if (!dev->features_ok)
		return 0;

	qid = dev_cbs[dev->dev_type].cq_id_get(dev, dev->feature_bits);
	q_conf = &dev->queue_conf[qid];
	if (!q_conf->queue_enable || dev->cq != NULL)
		return 0;

	dao_dbg("[dev %u] Setting qid=%u as CQ", dev->dev_id, qid);
	/* Setup only enabled queues assuming packed virt queue */
	shadow_area = RTE_ALIGN(q_conf->queue_size * 16 + 8, RTE_CACHE_LINE_SIZE);
	cq = rte_zmalloc("virtio_ctrl_queue", sizeof(*cq) + shadow_area, RTE_CACHE_LINE_SIZE);
	if (!cq) {
		dao_err("[dev %u] Failed to allocate memory for virtio queue", dev->dev_id);
		return -ENOMEM;
	}

	cq->desc_base = (((uint64_t)q_conf->queue_desc_hi << 32) | (q_conf->queue_desc_lo));
	cq->q_sz = q_conf->queue_size;
	cq->dma_vchan = dev->dma_vchan;
	cq->dev = dev;

	cq->notify_addr = (uint32_t *)(dev->notify_base + (qid * dev->notify_off_mltpr));
	/* Initial queue wrap counter is 1 as per spec? */
	cq->sd_desc_off = RTE_BIT64(15);
	cq->last_off = RTE_BIT64(15);
	dev->cq = cq;

	/* Register window for polling on control queue notify data */
	rc = dao_pem_ctrl_region_register(dev->pem_devid, (uintptr_t)cq->notify_addr, 8,
					  virtio_cq_notify_cb, dev, false);
	if (rc)
		dao_err("[dev %u] Failed to register cq notify window", dev->dev_id);
	return rc;
}

static int
virtio_process_device_status(struct virtio_dev *dev, uintptr_t shadow, uint8_t device_status)
{
	struct virtio_pci_common_cfg *shadow_cfg = (struct virtio_pci_common_cfg *)shadow;
	virtio_dev_status_cb_t dev_status_cb = dev_cbs[dev->dev_type].dev_status;
	uint8_t status = device_status & 0x7f;

	dao_dbg("[dev %u] device_status: 0x%x", dev->dev_id, device_status);

	if (status == VIRTIO_DEV_RESET) {
		dao_info("[dev %u] %s", dev->dev_id,
			 dao_virtio_dev_status_to_str(VIRTIO_DEV_RESET));

		/* Call callback before starting reset */
		dev_status_cb(dev, VIRTIO_DEV_RESET);

		/* Reset control queue info */
		virtio_clear_cq_info(dev);

		/* Reset virtio config to default */
		virtio_config_populate(dev);

		dev->common_cfg->device_status = VIRTIO_DEV_RESET;
		shadow_cfg->device_status = VIRTIO_DEV_RESET;
		dev->device_state = 0;
	}

	if (status & VIRTIO_DEV_FEATURES_OK && !dev->features_ok) {
		dao_info("[dev %u] %s", dev->dev_id,
			 dao_virtio_dev_status_to_str(VIRTIO_DEV_FEATURES_OK));

		dev->feature_bits = dev->drv_feature_bits_lo | (uint64_t)dev->drv_feature_bits_hi
								       << 32;
		dev->features_ok = 1;
		shadow_cfg->device_status |= VIRTIO_DEV_FEATURES_OK;
		dao_info("[dev %u] Feature bits negotiated : %lx", dev->dev_id, dev->feature_bits);
		if ((dev->feature_bits & RTE_BIT64(VIRTIO_F_ORDER_PLATFORM)) == 0) {
			dao_warn("[dev %u] !!! VIRTIO_F_ORDER_PLATFORM not negotiated !!!",
				 dev->dev_id);
			dao_warn("[dev %u] !!! Can lead to out-of-sync descriptor data !!!",
				 dev->dev_id);
		}
	}

	if (status & VIRTIO_DEV_DRIVER_OK && !dev->driver_ok) {
		/* Return to go through other changes and come back as we might not seeing
		 * writes in order.
		 */
		if (dev->driver_ok_pend < 3) {
			dev->driver_ok_pend++;
			return 1;
		}
		dev->driver_ok_pend = 0;
		dev->driver_ok = 1;

		dao_info("[dev %u] %s", dev->dev_id,
			 dao_virtio_dev_status_to_str(VIRTIO_DEV_DRIVER_OK));

		/* Callback at last after all the library setup is over */
		dev_status_cb(dev, VIRTIO_DEV_DRIVER_OK);

		/* Setup control queue info */
		virtio_setup_cq_info(dev);

		shadow_cfg->device_status |= VIRTIO_DEV_DRIVER_OK;
	}

	if (status & VIRTIO_DEV_ACKNOWLEDGE && !dev->acknowledge) {
		dao_info("[dev %u] %s", dev->dev_id,
			 dao_virtio_dev_status_to_str(VIRTIO_DEV_ACKNOWLEDGE));
		dev->acknowledge = 1;
		shadow_cfg->device_status |= VIRTIO_DEV_ACKNOWLEDGE;
	}

	if (status & VIRTIO_DEV_DRIVER && !dev->driver) {
		dao_info("[dev %u] %s", dev->dev_id,
			 dao_virtio_dev_status_to_str(VIRTIO_DEV_DRIVER));
		dev->driver = 0;
		shadow_cfg->device_status |= VIRTIO_DEV_DRIVER;
	}

	return 0;
}

static bool
virtio_queue_conf_pending(struct virtio_dev *dev, uintptr_t shadow)
{
	volatile struct virtio_pci_common_cfg *common_cfg = dev->common_cfg;
	uint16_t queue_id = dev->prev_queue_select;
	struct virtio_queue_conf *queue;

	RTE_SET_USED(shadow);

	if (dev->prev_queue_select == VIRTIO_INVALID_QUEUE_INDEX)
		return false;

	if (queue_id >= DAO_VIRTIO_MAX_QUEUES) {
		dao_err("[dev %u] Invalid queue [%u]", dev->dev_id, queue_id);
		return false;
	}

	/* Check for all except queue enable */
	queue = &dev->queue_conf[queue_id];
	if (queue->queue_msix_vector != common_cfg->queue_msix_vector ||
	    queue->queue_desc_lo != common_cfg->queue_desc_lo ||
	    queue->queue_desc_hi != common_cfg->queue_desc_hi ||
	    queue->queue_used_lo != common_cfg->queue_used_lo ||
	    queue->queue_used_hi != common_cfg->queue_used_hi ||
	    queue->queue_avail_lo != common_cfg->queue_avail_lo ||
	    queue->queue_avail_hi != common_cfg->queue_avail_hi ||
	    queue->queue_size != common_cfg->queue_size)
		return true;

	return false;
}

static int
virtio_process_queue_select(struct virtio_dev *dev, uintptr_t shadow, uint16_t queue_select)
{
	struct virtio_pci_common_cfg *shadow_cfg = (struct virtio_pci_common_cfg *)shadow;
	volatile struct virtio_pci_common_cfg *common_cfg = dev->common_cfg;
	uint16_t queue_id = queue_select & 0x7fff;
	struct virtio_queue_conf *queue;
	int rc = 1;

	if (dev->queue_select_pend++ < VIRTIO_QUEUE_SELECT_DELAY)
		return 0;
	dev->queue_select_pend = 0;

	dao_dbg("[dev %u] prev_queue_select: %u queue_select: %u", dev->dev_id,
		dev->prev_queue_select, queue_id);
	if (queue_id >= DAO_VIRTIO_MAX_QUEUES ||
	    ((dev->prev_queue_select != VIRTIO_INVALID_QUEUE_INDEX) &&
	     (dev->prev_queue_select >= DAO_VIRTIO_MAX_QUEUES)))
		return -EINVAL;

	if (dev->prev_queue_select == queue_id)
		goto skip_update;

	if (dev->prev_queue_select != VIRTIO_INVALID_QUEUE_INDEX) {
		queue = &dev->queue_conf[dev->prev_queue_select];
		queue->queue_msix_vector = common_cfg->queue_msix_vector;
		queue->queue_enable = common_cfg->queue_enable;
		queue->queue_desc_lo = common_cfg->queue_desc_lo;
		queue->queue_desc_hi = common_cfg->queue_desc_hi;
		queue->queue_used_lo = common_cfg->queue_used_lo;
		queue->queue_used_hi = common_cfg->queue_used_hi;
		queue->queue_avail_lo = common_cfg->queue_avail_lo;
		queue->queue_avail_hi = common_cfg->queue_avail_hi;
		if (queue->queue_size != common_cfg->queue_size)
			queue->queue_size = common_cfg->queue_size;

		dao_dbg("\t\tqueue[%u]_size: %u", dev->prev_queue_select, queue->queue_size);
		dao_dbg("\t\tqueue[%u]_enable: %u", dev->prev_queue_select, queue->queue_enable);
		dao_dbg("\t\tqueue[%u]_notify_off: %u", dev->prev_queue_select,
			queue->queue_notify_off);
		dao_dbg("\t\tqueue[%u]_desc_lo: %x", dev->prev_queue_select, queue->queue_desc_lo);
		dao_dbg("\t\tqueue[%u]_desc_hi: %x", dev->prev_queue_select, queue->queue_desc_hi);
		dao_dbg("\t\tqueue[%u]_avail_lo: %x", dev->prev_queue_select,
			queue->queue_avail_lo);
		dao_dbg("\t\tqueue[%u]_avail_hi: %x", dev->prev_queue_select,
			queue->queue_avail_hi);
		dao_dbg("\t\tqueue[%u]_used_lo: %x", dev->prev_queue_select, queue->queue_used_lo);
		dao_dbg("\t\tqueue[%u]_used_hi: %x", dev->prev_queue_select, queue->queue_used_hi);
	}
	dev->prev_queue_select = queue_id;
	queue = &dev->queue_conf[queue_id];
	common_cfg->queue_size = queue->queue_size;
	common_cfg->queue_msix_vector = queue->queue_msix_vector;
	common_cfg->queue_enable = queue->queue_enable;
	common_cfg->queue_notify_off = queue_id;
	common_cfg->queue_desc_lo = queue->queue_desc_lo;
	common_cfg->queue_desc_hi = queue->queue_desc_hi;
	common_cfg->queue_used_lo = queue->queue_used_lo;
	common_cfg->queue_used_hi = queue->queue_used_hi;
	common_cfg->queue_avail_lo = queue->queue_avail_lo;
	common_cfg->queue_avail_hi = queue->queue_avail_hi;

	shadow_cfg->queue_size = common_cfg->queue_size;
	shadow_cfg->queue_msix_vector = common_cfg->queue_msix_vector;
	shadow_cfg->queue_enable = common_cfg->queue_enable;
	shadow_cfg->queue_notify_off = common_cfg->queue_notify_off;
	shadow_cfg->queue_desc_lo = common_cfg->queue_desc_lo;
	shadow_cfg->queue_desc_hi = common_cfg->queue_desc_hi;
	shadow_cfg->queue_used_lo = common_cfg->queue_used_lo;
	shadow_cfg->queue_used_hi = common_cfg->queue_used_hi;
	shadow_cfg->queue_avail_lo = common_cfg->queue_avail_lo;
	shadow_cfg->queue_avail_hi = common_cfg->queue_avail_hi;

	dao_dbg("\t\tqueue[%u]_size: %u", queue_id, common_cfg->queue_size);
	dao_dbg("\t\tqueue[%u]_enable: %u", queue_id, common_cfg->queue_enable);
	dao_dbg("\t\tqueue[%u]_notify_off: %u", queue_id, common_cfg->queue_notify_off);
	dao_dbg("\t\tqueue[%u]_desc_lo: %x", queue_id, common_cfg->queue_desc_lo);
	dao_dbg("\t\tqueue[%u]_desc_hi: %x", queue_id, common_cfg->queue_desc_hi);
	dao_dbg("\t\tqueue[%u]_avail_lo: %x", queue_id, common_cfg->queue_avail_lo);
	dao_dbg("\t\tqueue[%u]_avail_hi: %x", queue_id, common_cfg->queue_avail_hi);
	dao_dbg("\t\tqueue[%u]_used_lo: %x", queue_id, common_cfg->queue_used_lo);
	dao_dbg("\t\tqueue[%u]_used_hi: %x", queue_id, common_cfg->queue_used_hi);

skip_update:
	rte_io_wmb();
	common_cfg->queue_select = queue_id;
	shadow_cfg->queue_select = queue_id;
	rte_io_wmb();

	return rc;
}

static int
virtio_process_queue_size(struct virtio_dev *dev, uint16_t queue_size)
{
	uint16_t queue_id = dev->prev_queue_select;

	if (dev->prev_queue_select == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= DAO_VIRTIO_MAX_QUEUES) {
		dao_err("[dev %u] Invalid queue [%u]", dev->dev_id, queue_id);
		return -EINVAL;
	}

	dev->queue_conf[queue_id].queue_size = queue_size;

	dao_dbg("[dev %u] queue[%u]_size: 0x%04x", dev->dev_id, queue_id, queue_size);
	return 0;
}

static int
virtio_process_queue_msix_vector(struct virtio_dev *dev, uint16_t queue_msix_vector)
{
	uint16_t queue_id = dev->prev_queue_select;

	if (dev->prev_queue_select == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= DAO_VIRTIO_MAX_QUEUES) {
		dao_err("[dev %u] Invalid queue [%u]", dev->dev_id, queue_id);
		return -EINVAL;
	}

	dev->queue_conf[queue_id].queue_msix_vector = queue_msix_vector;
	dao_dbg("[dev %u] queue[%u]_msix_vector: 0x%04x", dev->dev_id, queue_id, queue_msix_vector);
	return 0;
}

static int
virtio_process_queue_enable(struct virtio_dev *dev, uint16_t queue_enable)
{
	uint16_t cq_id = dev_cbs[dev->dev_type].cq_id_get(dev, dev->feature_bits);
	uint16_t queue_id = dev->prev_queue_select;

	if (dev->prev_queue_select == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= DAO_VIRTIO_MAX_QUEUES) {
		dao_err("[dev %u] Invalid queue [%u]", dev->dev_id, queue_id);
		return -EINVAL;
	}

	dev->queue_conf[queue_id].queue_enable = queue_enable;

	dao_dbg("[dev %u] queue[%u]_enable: 0x%04x", dev->dev_id, queue_id, queue_enable);

	/* Setup control queue info */
	if (dev->features_ok && dev->driver_ok && queue_enable && (queue_id == cq_id) &&
	    (dev->cq == NULL))
		virtio_setup_cq_info(dev);
	return 0;
}

static int
virtio_process_queue_desc_lo(struct virtio_dev *dev, uint32_t queue_desc_lo)
{
	uint16_t queue_id = dev->prev_queue_select;

	if (dev->prev_queue_select == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= DAO_VIRTIO_MAX_QUEUES) {
		dao_err("[dev %u] Invalid queue [%u]", dev->dev_id, queue_id);
		return -EINVAL;
	}

	dao_dbg("[dev %u] queue[%u]_desc_lo: 0x%x", dev->dev_id, queue_id, queue_desc_lo);
	dev->queue_conf[queue_id].queue_desc_lo = queue_desc_lo;

	return 0;
}

static int
virtio_process_queue_desc_hi(struct virtio_dev *dev, uint32_t queue_desc_hi)
{
	uint16_t queue_id = dev->prev_queue_select;

	if (dev->prev_queue_select == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= DAO_VIRTIO_MAX_QUEUES) {
		dao_err("[dev %u] Invalid queue [%u]", dev->dev_id, queue_id);
		return -EINVAL;
	}

	dao_dbg("[dev %u] queue[%u]_desc_lo: 0x%x", dev->dev_id, queue_id, queue_desc_hi);
	dev->queue_conf[queue_id].queue_desc_hi = queue_desc_hi;

	return 0;
}

static int
virtio_process_queue_driver_lo(struct virtio_dev *dev, uint32_t queue_avail_lo)
{
	uint16_t queue_id = dev->prev_queue_select;

	if (dev->prev_queue_select == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= DAO_VIRTIO_MAX_QUEUES) {
		dao_err("[dev %u] Invalid queue [%u]", dev->dev_id, queue_id);
		return -EINVAL;
	}

	dao_dbg("[dev %u] queue[%u]_avail_lo: 0x%x", dev->dev_id, queue_id, queue_avail_lo);
	dev->queue_conf[queue_id].queue_avail_lo = queue_avail_lo;

	return 0;
}

static int
virtio_process_queue_driver_hi(struct virtio_dev *dev, uint32_t queue_avail_hi)
{
	uint16_t queue_id = dev->prev_queue_select;

	if (dev->prev_queue_select == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= DAO_VIRTIO_MAX_QUEUES) {
		dao_err("[dev %u] Invalid queue [%u]", dev->dev_id, queue_id);
		return -EINVAL;
	}

	dao_dbg("[dev %u] queue[%u]_avail_hi: 0x%x", dev->dev_id, queue_id, queue_avail_hi);
	dev->queue_conf[queue_id].queue_avail_hi = queue_avail_hi;

	return 0;
}

static int
virtio_process_queue_device_lo(struct virtio_dev *dev, uint32_t queue_used_lo)
{
	uint16_t queue_id = dev->prev_queue_select;

	if (dev->prev_queue_select == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= DAO_VIRTIO_MAX_QUEUES) {
		dao_err("[dev %u] Invalid queue [%u]", dev->dev_id, queue_id);
		return -EINVAL;
	}

	dao_dbg("[dev %u] queue[%u]_used_lo: 0x%x", dev->dev_id, queue_id, queue_used_lo);
	dev->queue_conf[queue_id].queue_used_lo = queue_used_lo;

	return 0;
}

static int
virtio_process_queue_device_hi(struct virtio_dev *dev, uint32_t queue_used_hi)
{
	uint16_t queue_id = dev->prev_queue_select;

	if (dev->prev_queue_select == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= DAO_VIRTIO_MAX_QUEUES) {
		dao_err("[dev %u] Invalid queue [%u]", dev->dev_id, queue_id);
		return -EINVAL;
	}

	dao_dbg("[dev %u] queue[%u]_used_hi: 0x%x", dev->dev_id, queue_id, queue_used_hi);
	dev->queue_conf[queue_id].queue_used_hi = queue_used_hi;

	return 0;
}

static int
virtio_process_queue_reset(struct virtio_dev *dev, uint16_t queue_reset)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(queue_reset);

	return 0;
}

static int
dao_virtio_common_cfg_cb(void *ctx, uintptr_t shadow, uint32_t offset, uint64_t val,
			 uint64_t shadow_val)
{
	struct virtio_pci_common_cfg up_cfg, shd_cfg;
	struct virtio_dev *dev = ctx;
	bool update_shadow = true;
	int rc = 0;

	switch (offset) {
	case 0:
		/* device_feature_select, device_feature */
		up_cfg.w0 = val;
		shd_cfg.w0 = shadow_val;
		update_shadow = false;
		if (up_cfg.device_feature_select != shd_cfg.device_feature_select)
			virtio_process_device_feature_select(dev, shadow,
							     up_cfg.device_feature_select);

		if (up_cfg.device_feature != shd_cfg.device_feature)
			virtio_process_device_feature(dev, up_cfg.device_feature);
		break;

	case 1:
		/* driver_feature_select, driver_feature */
		up_cfg.w1 = val;
		shd_cfg.w1 = shadow_val;
		update_shadow = false;
		if (up_cfg.driver_feature_select != shd_cfg.driver_feature_select)
			virtio_process_driver_feature_select(dev, shadow,
							     up_cfg.driver_feature_select);

		if (up_cfg.driver_feature != shd_cfg.driver_feature)
			virtio_process_driver_feature(dev, shadow, up_cfg.driver_feature);
		break;

	case 2:
		/* config_msix_vector, num_queues, device_status, config_generation, queue_select */
		up_cfg.w2 = val;
		shd_cfg.w2 = shadow_val;
		/* Updates to shadow taken care by handlers */
		update_shadow = false;
		if (up_cfg.config_msix_vector != shd_cfg.config_msix_vector)
			virtio_process_config_msix_vector(dev, shadow, up_cfg.config_msix_vector);

		if (up_cfg.device_status != shd_cfg.device_status)
			virtio_process_device_status(dev, shadow, up_cfg.device_status);

		if (up_cfg.queue_select != shd_cfg.queue_select)
			virtio_process_queue_select(dev, shadow, up_cfg.queue_select);
		break;
	case 3:
		/* queue_size, queue_msix_vector, queue_enable, queue_notify_off */
		up_cfg.w3 = val;
		shd_cfg.w3 = shadow_val;
		if (up_cfg.queue_size != shd_cfg.queue_size)
			virtio_process_queue_size(dev, up_cfg.queue_size);

		if (up_cfg.queue_msix_vector != shd_cfg.queue_msix_vector)
			virtio_process_queue_msix_vector(dev, up_cfg.queue_msix_vector);

		if (up_cfg.queue_enable != shd_cfg.queue_enable) {
			/* Delay the queue enable if other queue configs are pending */
			if (virtio_queue_conf_pending(dev, shadow) && up_cfg.queue_enable)
				update_shadow = false;
			else
				virtio_process_queue_enable(dev, up_cfg.queue_enable);
		}
		break;

	case 4:
		/* queue_desc_lo, queue_desc_hi */
		up_cfg.w4 = val;
		shd_cfg.w4 = shadow_val;
		if (up_cfg.queue_desc_lo != shd_cfg.queue_desc_lo)
			virtio_process_queue_desc_lo(dev, up_cfg.queue_desc_lo);

		if (up_cfg.queue_desc_hi != shd_cfg.queue_desc_hi)
			virtio_process_queue_desc_hi(dev, up_cfg.queue_desc_hi);
		break;

	case 5:
		/* queue_avail_lo, queue_avail_hi */
		up_cfg.w5 = val;
		shd_cfg.w5 = shadow_val;
		if (up_cfg.queue_avail_lo != shd_cfg.queue_avail_lo)
			virtio_process_queue_driver_lo(dev, up_cfg.queue_avail_lo);

		if (up_cfg.queue_avail_hi != shd_cfg.queue_avail_hi)
			virtio_process_queue_driver_hi(dev, up_cfg.queue_avail_hi);
		break;

	case 6:
		/* queue_used_lo, queue_used_hi */
		up_cfg.w6 = val;
		shd_cfg.w6 = shadow_val;
		if (up_cfg.queue_used_lo != shd_cfg.queue_used_lo)
			virtio_process_queue_device_lo(dev, up_cfg.queue_used_lo);

		if (up_cfg.queue_used_hi != shd_cfg.queue_used_hi)
			virtio_process_queue_device_hi(dev, up_cfg.queue_used_hi);
		break;

	case 7:
		/* queue_notify_data, queue_reset */
		up_cfg.w7 = val;
		shd_cfg.w7 = shadow_val;
		if (up_cfg.queue_reset != shd_cfg.queue_reset)
			virtio_process_queue_reset(dev, up_cfg.queue_reset);
		break;
	default:
		break;
	}

	if (update_shadow)
		*(((uint64_t *)shadow) + offset) = val;

	return rc;
}

static void
virtio_caps_populate(struct virtio_dev *dev, volatile uint8_t *base)
{
	uint32_t config_base, notify_base, isr_base, dev_cfg_base, mbox_base;
	volatile struct virtio_pci_cap *isr_cap, *dev_cfg_cap;
	volatile struct virtio_pci_notify_cap *notify_cap;
	volatile struct virtio_pci_cap *common_cfg_cap;
	struct virtio_pci_cap cap;
	uint32_t cap_end = 0;
	uint32_t off;

	/* Device common config cap */
	config_base = VIRTIO_PCI_CAP_COMMON_CFG_OFFSET + sizeof(struct virtio_pci_cap);
	config_base += sizeof(struct virtio_pci_notify_cap); /* Notify config cap */
	config_base += sizeof(struct virtio_pci_cap);        /* ISR config cap */
	config_base += sizeof(struct virtio_pci_cap);        /* Device config cap */
	/* Common config area aligned to 8B */
	config_base = RTE_ALIGN(config_base, 8);
	dev->common_cfg = (volatile struct virtio_pci_common_cfg *)(base + config_base);

	/* ISR area */
	isr_base = config_base + sizeof(struct virtio_pci_common_cfg);
	dev->isr_sz = 4;
	dev->isr = (uintptr_t)(base + isr_base);

	/* Device config aligned to 64B */
	dev_cfg_base = RTE_ALIGN(isr_base + dev->isr_sz, 64);
	dev->dev_cfg = (uintptr_t)(base + dev_cfg_base);

	/* Mbox area */
	mbox_base = dev_cfg_base + VIRTIO_PCI_DEV_CFG_LENGTH;
	dev->mbox = (volatile uintptr_t)(base + mbox_base);

	/* Notification area aligned to host page size is up to BAR4 end */
	notify_base = dev_cfg_base + VIRTIO_PCI_DEV_CFG_LENGTH;
	notify_base = RTE_ALIGN(notify_base, dev->notify_off_mltpr);
	dev->notify_base = (uintptr_t)(base + notify_base);

	RTE_ASSERT(notify_base == dev->host_page_sz);
	RTE_ASSERT((notify_base + dev->max_virtio_queues * dev->notify_off_mltpr) <= dev->bar4_sz);

	/* Populate common config cap */
	*(base + VIRTIO_PCI_CAP_PTR) = VIRTIO_PCI_CAP_COMMON_CFG_OFFSET;
	cap_end = VIRTIO_PCI_CAP_COMMON_CFG_OFFSET;

	common_cfg_cap =
		(volatile struct virtio_pci_cap *)(base + VIRTIO_PCI_CAP_COMMON_CFG_OFFSET);
	dao_dbg("[dev %u] virtio_common_cfg@%p, offset %u", dev->dev_id, dev->common_cfg,
		config_base);
	memset(&cap, 0, sizeof(cap));
	cap.cap_vndr = PCI_CAP_ID_VNDR;
	cap.cap_len = sizeof(struct virtio_pci_cap);
	cap.cap_next = cap_end + cap.cap_len;
	cap.offset = config_base;
	cap.cfg_type = VIRTIO_PCI_CAP_COMMON_CFG;
	cap.bar = PCI_CAP_BAR;
	cap.length = sizeof(struct virtio_pci_common_cfg);
	dao_dev_memcpy(common_cfg_cap, &cap, cap.cap_len);
	cap_end += sizeof(struct virtio_pci_cap);

	/* Populate notify cap */
	dao_dbg("[dev %u] virtio_notify_base@%p, offset %u", dev->dev_id, (void *)dev->notify_base,
		notify_base);
	off = dev->notify_off_mltpr;
	dao_dev_memset((volatile void *)dev->notify_base, 0, dev->max_virtio_queues * off);
	notify_cap = (volatile struct virtio_pci_notify_cap *)(base + cap_end);
	memset(&cap, 0, sizeof(cap));
	cap.cap_vndr = PCI_CAP_ID_VNDR;
	cap.cap_len = sizeof(struct virtio_pci_notify_cap);
	cap.cap_next = cap_end + sizeof(struct virtio_pci_notify_cap);
	cap.offset = notify_base;
	cap.cfg_type = VIRTIO_PCI_CAP_NOTIFY_CFG;
	cap.bar = PCI_CAP_BAR;
	cap.length = dev->max_virtio_queues * off;
	dao_dev_memcpy(&notify_cap->notify_off_multiplier, &off, 4);
	dao_dev_memcpy(&notify_cap->cap, &cap, sizeof(cap));
	cap_end += sizeof(struct virtio_pci_notify_cap);

	/* Populate ISR cap */
	dao_dbg("[dev %u] ISR area@%p, offset %u", dev->dev_id, (void *)dev->isr, isr_base);
	isr_cap = (volatile struct virtio_pci_cap *)(base + cap_end);
	memset(&cap, 0, sizeof(cap));
	cap.cap_vndr = PCI_CAP_ID_VNDR;
	cap.cap_len = sizeof(struct virtio_pci_cap);
	cap.cap_next = cap_end + sizeof(struct virtio_pci_cap);
	cap.offset = isr_base;
	cap.cfg_type = VIRTIO_PCI_CAP_ISR_CFG;
	cap.bar = PCI_CAP_BAR;
	cap.length = 4;
	dao_dev_memcpy(isr_cap, &cap, sizeof(cap));
	cap_end += sizeof(struct virtio_pci_cap);

	dao_dbg("[dev %u] Device config@%p, offset %u", dev->dev_id, (void *)dev->dev_cfg,
		dev_cfg_base);
	dev_cfg_cap = (volatile struct virtio_pci_cap *)(base + cap_end);
	memset(&cap, 0, sizeof(cap));
	cap.cap_vndr = PCI_CAP_ID_VNDR;
	cap.cap_len = sizeof(struct virtio_pci_cap);
	cap.cap_next = 0;
	cap.offset = dev_cfg_base;
	cap.cfg_type = VIRTIO_PCI_CAP_DEVICE_CFG;
	cap.bar = PCI_CAP_BAR;
	cap.length = VIRTIO_PCI_DEV_CFG_LENGTH;
	dao_dev_memcpy(dev_cfg_cap, &cap, sizeof(cap));
	cap_end += sizeof(struct virtio_pci_cap);
}

static void
virtio_dev_signature_add(struct virtio_dev *dev)
{
	uint32_t signature[2];

	/* Add signature for each device at beginning of BAR,
	 * so that host can make sure the virtio firmware is
	 * initialized.
	 */
	signature[0] = 0xfeedfeed;
	signature[1] = 0x3355ffaa;

	dao_dev_memcpy((void *)dev->bar4, signature, sizeof(signature));
}

void
virtio_dev_feature_bits_set(struct virtio_dev *dev, uint64_t feature_bits)
{
	dev->dev_feature_bits |= feature_bits;
	dev->feature_bits |= feature_bits;

	dao_dbg("[dev %u] device feature_bits: %lx", dev->dev_id, dev->dev_feature_bits);
}

int
virtio_dev_max_virtio_queues(uint16_t pem_devid, uint16_t devid)
{
	size_t host_page_sz = dao_pem_host_page_sz(pem_devid);
	uint64_t bar4, bar4_sz;
	uint16_t max_virtio_qs;
	int rc;

	rc = dao_pem_vf_region_info_get(pem_devid, devid, 4, &bar4, &bar4_sz);
	if (rc) {
		dao_err("[dev %u] Failed to get bar4 region info, rc=%d", devid, rc);
		return rc;
	}

	max_virtio_qs = (bar4_sz / host_page_sz) - 1;
	return RTE_MIN(max_virtio_qs, DAO_VIRTIO_MAX_QUEUES);
}

int
virtio_dev_init(struct virtio_dev *dev)
{
	uint8_t *base;
	int rc;

	/* Get BAR4 info for this device */
	rc = dao_pem_vf_region_info_get(dev->pem_devid, dev->dev_id, 4, &dev->bar4, &dev->bar4_sz);
	if (rc) {
		dao_err("[dev %u] Failed to get bar4 region info, rc=%d", dev->dev_id, rc);
		return rc;
	}

	/* Get host page size */
	dev->host_page_sz = dao_pem_host_page_sz(dev->pem_devid);

	/*
	 * Max virtio queue supported is one less than host
	 * pages available as BAR4. Each virtio queue notify region occupies
	 * one host page.
	 */
	dev->notify_off_mltpr = dev->host_page_sz;
	dev->max_virtio_queues = (dev->bar4_sz / dev->host_page_sz) - 1;
	dev->max_virtio_queues = RTE_MIN(dev->max_virtio_queues, (int)DAO_VIRTIO_MAX_QUEUES);

	if (dev->max_virtio_queues < 3) {
		dao_err("[dev %u] BAR4 space sz %luB insufficient, need for at least 3 queues",
			dev->dev_id, dev->bar4_sz);
		return -ENOSPC;
	}

	virtio_dev_signature_add(dev);
	/* Populate virtio PCI cap */
	base = (uint8_t *)dev->bar4;
	virtio_caps_populate(dev, base);

	/* Populate default common config */
	virtio_config_populate(dev);

	/* Set default device feature bits */
	dev->dev_feature_bits = RTE_BIT64(VIRTIO_F_RING_PACKED) | RTE_BIT64(VIRTIO_F_VERSION_1) |
				RTE_BIT64(VIRTIO_F_ANY_LAYOUT) | RTE_BIT64(VIRTIO_F_IN_ORDER) |
				RTE_BIT64(VIRTIO_F_ORDER_PLATFORM) |
				RTE_BIT64(VIRTIO_F_IOMMU_PLATFORM) |
				RTE_BIT64(VIRTIO_F_NOTIFICATION_DATA);

	dev->feature_bits = dev->dev_feature_bits;

	/* Setup virtio device host interrupt for the vring call */
	dao_pem_host_interrupt_setup(dev->pem_devid, dev->dev_id + 1, &dev->cb_intr_addr);

	/* Register control register region */
	rc = dao_pem_ctrl_region_register(dev->pem_devid, (uintptr_t)dev->common_cfg,
					  sizeof(struct virtio_pci_common_cfg),
					  dao_virtio_common_cfg_cb, dev, true);
	if (rc)
		dao_err("[dev %u] Failed to register control region, rc=%d", dev->dev_id, rc);

	rc = virtio_mbox_init(dev);
	if (rc)
		goto unregister_common_cfg;

	dao_dbg("[dev %u] Configured virtio dev with max_virtio_queues=%d", dev->dev_id,
		dev->max_virtio_queues);

	return 0;

unregister_common_cfg:
	dao_pem_ctrl_region_unregister(dev->pem_devid, (uintptr_t)dev->common_cfg,
				       sizeof(struct virtio_pci_common_cfg),
				       dao_virtio_common_cfg_cb, dev);
	return rc;
}

int
virtio_dev_fini(struct virtio_dev *dev)
{
	virtio_dev_status_cb_t dev_status_cb;
	int rc;

	if (!dev || (dev->dev_type >= VIRTIO_DEV_TYPE_MAX))
		return -EINVAL;

	dev_status_cb = dev_cbs[dev->dev_type].dev_status;
	if (dev->common_cfg->device_status != VIRTIO_DEV_RESET)
		dao_warn("[dev %u] Device not in reset state !! (%u)", dev->dev_id,
			 dev->common_cfg->device_status);

	virtio_mbox_fini(dev);
	/* Unregister control region from polling */
	rc = dao_pem_ctrl_region_unregister(dev->pem_devid, (uintptr_t)dev->common_cfg,
					    sizeof(struct virtio_pci_common_cfg),
					    dao_virtio_common_cfg_cb, dev);

	/* Clear any pending queue data */
	virtio_clear_cq_info(dev);
	dev_status_cb(dev, VIRTIO_DEV_RESET);

	dao_dev_memset(dev->common_cfg, 0, sizeof(struct virtio_pci_common_cfg));
	/* Clear the signature */
	dao_dev_memset((void *)dev->bar4, 0, 16);

	return rc;
}

const char *
dao_virtio_dev_status_to_str(uint8_t status)
{
	switch (status) {
	case VIRTIO_DEV_RESET:
		return "VIRTIO_DEV_RESET";
	case VIRTIO_DEV_ACKNOWLEDGE:
		return "VIRTIO_DEV_ACKNOWLEDGE";
	case VIRTIO_DEV_DRIVER:
		return "VIRTIO_DEV_DRIVER";
	case VIRTIO_DEV_DRIVER_OK:
		return "VIRTIO_DEV_DRIVER_OK";
	case VIRTIO_DEV_FEATURES_OK:
		return "VIRTIO_DEV_FEATURES_OK";
	case VIRTIO_DEV_NEEDS_RESET:
		return "VIRTIO_DEV_NEEDS_RESET";
	case VIRTIO_DEV_FAILED:
		return "VIRTIO_DEV_FAILED";
	default:
		return "UNKNOWN_STATUS";
	};
	return NULL;
}
