/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell.
 */
#include <rte_malloc.h>

#include "dao_virtio_blkdev.h"
#include "virtio_dev_priv.h"
#include "virtio_blk_priv.h"
#include "virtio_blk_trace.h"

/** Virtio blk devices */
struct dao_virtio_blkdev dao_virtio_blkdevs[DAO_VIRTIO_DEV_MAX + 1];

dao_virtio_blk_desc_manage_fn_t dao_blk_desc_manage_fns[VIRTIO_BLK_DESC_MANAGE_LAST << 1] = {
#define M(name, flags)[flags] = virtio_blk_desc_manage_##name,
	VIRTIO_BLK_DESC_MANAGE_MODES
#undef M
};

struct dao_virtio_blkdev_cbs blkdev_user_cbs;

static int
virtio_queue_driver_event_flag(struct virtio_dev *dev, struct virtio_blk_queue *queue)
{
	struct vring_packed_desc_event *sd_driver_area;
	int16_t dev2mem = dao_dma_ctrl_dev2mem();
	bool has_err = 0;
	uint16_t tmo_ms;
	int cnt, rc;

	sd_driver_area = (struct vring_packed_desc_event *)queue->sd_driver_area;
	rc = rte_dma_copy(dev2mem, dev->dma_vchan, (rte_iova_t)queue->driver_area,
			  (rte_iova_t)sd_driver_area, sizeof(*sd_driver_area),
			  RTE_DMA_OP_FLAG_SUBMIT);
	if (rc < 0) {
		dao_err("[dev %u] Couldn't submit dma for virtqueue driver area", dev->dev_id);
		return rc;
	}

	tmo_ms = VIRTIO_DMA_TMO_MS;
	do {
		rte_delay_us_sleep(1000);
		cnt = rte_dma_completed(dev2mem, dev->dma_vchan, 1, NULL, &has_err);
		tmo_ms--;
		if (unlikely(has_err))
			dao_err("[dev %u] DMA failed for driver event flag", dev->dev_id);
		if (!tmo_ms) {
			dao_err("[dev %u] DMA timeout for driver event flag", dev->dev_id);
			return -EFAULT;
		}
	} while (cnt != 1);

	return sd_driver_area->desc_event_flags;
}

static void
virtio_blkdev_cb_interrupt_conf(struct virtio_blkdev *blkdev)
{
	uint32_t max_vqs = blkdev->dev.max_virtio_queues;
	struct virtio_dev *dev = &blkdev->dev;
	struct virtio_blk_queue *queue;
	uint32_t i, intr_idx = 0;

	for (i = 0; i < max_vqs; i++) {
		queue = blkdev->qs[i];
		if (!queue)
			continue;

		queue->cb_intr_addr = dev->cb_intr_addr[intr_idx];
		queue->cb_notify_addr = queue->notify_addr + 1;
		__atomic_store_n(queue->cb_notify_addr, 0, __ATOMIC_RELAXED);
		intr_idx = (intr_idx + 1) % dev->nb_cb_intrs;
	}

	dao_dbg("[dev %u] Enabled driver events for %u queues", dev->dev_id, max_vqs);
}

static int
virtio_blkdev_feature_validate(struct virtio_dev *dev, uint64_t feature_bits)
{
	uint16_t dev_id = dev->dev_id;

	if ((feature_bits | dev->dev_feature_bits) != dev->dev_feature_bits) {
		dao_err("[dev %u] Invalid feature bits negotiated 0x%" PRIx64 "(dev %" PRIx64 ")",
			dev_id, feature_bits, dev->dev_feature_bits);
		return -EINVAL;
	}

	return 0;
}

static __rte_always_inline uint16_t
virtio_blkdev_flush_queue(struct virtio_blkdev *blkdev, uint16_t qid)
{
	struct dao_virtio_blkdev *dao_blkdev = virtio_blkdev_to_dao(blkdev);
	void *q = blkdev->qs[qid];

	if (unlikely(!q))
		return 0;

	if (!(dao_blkdev->mgmt_fn_id & VIRTIO_BLK_DESC_MANAGE_EXTBUF))
		virtio_blk_flush_deq(q);
	else
		virtio_blk_flush_deq_ext(q);
	return 0;
}

static __rte_always_inline  int
virtio_blkdev_clear_queue_info(struct virtio_blkdev *blkdev)
{
	struct dao_virtio_blkdev *dao_blkdev = virtio_blkdev_to_dao(blkdev);
	uint32_t max_vqs = blkdev->dev.max_virtio_queues;
	uint32_t i;

	for (i = 0; i < max_vqs; i++) {
		virtio_blkdev_flush_queue(blkdev, i);
		if (blkdev->qs[i])
			rte_free(blkdev->qs[i]);
		blkdev->qs[i] = NULL;
		dao_blkdev->qs[i] = NULL;
	}

	blkdev->num_queues = 0;

	return 0;
}

static int
virtio_blkdev_status_cb(struct virtio_dev *dev, uint8_t status)
{
	struct virtio_blkdev *blkdev = virtio_dev_to_blkdev(dev);
	struct dao_virtio_blkdev *dao_blkdev;
	struct virtio_blk_queue *queue;
	bool cb_enabled = false;
	int event_flag, i;
	int rc;

	if (blkdev_user_cbs.status_cb == NULL)
		return -ENOTSUP;

	/* Populate queue info for fast path */
	if (status & VIRTIO_DEV_DRIVER_OK) {
		dao_blkdev = virtio_blkdev_to_dao(blkdev);

		/* Fetch event suppression data if queues is enabled */
		for (i = 0; i < blkdev->dev.max_virtio_queues; i++) {
			queue = dao_blkdev->qs[i];
			if (!queue)
				continue;
			event_flag = virtio_queue_driver_event_flag(dev, queue);
			if (event_flag < 0)
				continue;

			cb_enabled = (event_flag != RING_EVENT_FLAGS_DISABLE);
			if (cb_enabled)
				break;
		}

		/* Enable interrupts event if one queue wants events delivered */
		if (cb_enabled)
			virtio_blkdev_cb_interrupt_conf(blkdev);

		dao_blkdev->deq_fn_id &= ~VIRTIO_BLK_DEQ_NOINOR;
		dao_blkdev->compl_fn_id &= ~VIRTIO_BLK_COMPL_NOINOR;
		dao_blkdev->mgmt_fn_id &= ~VIRTIO_BLK_DESC_MANAGE_NOINORDER;
		if (!(dev->feature_bits & RTE_BIT64(VIRTIO_F_IN_ORDER))) {
			dao_blkdev->deq_fn_id |= VIRTIO_BLK_DEQ_NOINOR;
			dao_blkdev->compl_fn_id |= VIRTIO_BLK_COMPL_NOINOR;
			dao_blkdev->mgmt_fn_id |= VIRTIO_BLK_DESC_MANAGE_NOINORDER;
		}

		return blkdev_user_cbs.status_cb(blkdev->dev.dev_id, status);
	} else if (status == VIRTIO_DEV_RESET) {
		struct virtio_blk_queue *q;
		uint32_t i;

		/* Any blk dev pending requests needs to be cleared/flused
		   in the cb function */
		rc = blkdev_user_cbs.status_cb(blkdev->dev.dev_id, status);
		for (i = 0; i < (DAO_VIRTIO_MAX_QUEUES - 1); i++) {
			if (blkdev->qs[i]) {
				q = (struct virtio_blk_queue *)blkdev->qs[i];
				dao_dma_compl_wait_inflight(q->dma_vchan);
				break;
			}
		}
		/* Clear queue info after user callback */
		virtio_blkdev_clear_queue_info(blkdev);
		return rc;
	}

	return blkdev_user_cbs.status_cb(blkdev->dev.dev_id, status);
}

static int
virtio_blkdev_queue_enable(struct virtio_dev *vdev, uint16_t queue_id)
{
	struct virtio_blkdev *blkdev = virtio_dev_to_blkdev(vdev);
	struct dao_virtio_blkdev *dao_blkdev = virtio_blkdev_to_dao(blkdev);
	uint32_t max_vqs = blkdev->dev.max_virtio_queues;
	volatile struct virtio_blk_config *dev_cfg;
	struct virtio_dev *dev = &blkdev->dev;
	struct virtio_queue_conf *q_conf;
	struct virtio_blk_queue *queue;
	bool cb_enabled = false;
	uint32_t shadow_area;
	uint32_t mbuf_area;
	uint16_t buf_len;
	int event_flag;

	if (queue_id >= max_vqs)
		return -EINVAL;

	if (!(blkdev->flags & DAO_VIRTIO_BLKDEV_EXTBUF))
		buf_len = blkdev->pool->elt_size;
	else
		buf_len = blkdev->dataroom_size;

	buf_len -= sizeof(struct dao_virtio_blk_hdr);
	q_conf = &dev->queue_conf[queue_id];
	if (!q_conf->queue_enable || blkdev->qs[queue_id] != NULL)
		return 0;

	/* Setup only enabled queues assuming packed virt queue */
	shadow_area = RTE_ALIGN(q_conf->queue_size * 16 + 8, RTE_CACHE_LINE_SIZE);
	mbuf_area = RTE_ALIGN(q_conf->queue_size * 8, RTE_CACHE_LINE_SIZE);
	queue = rte_zmalloc("virtio_blk_queue", sizeof(*queue) + shadow_area + mbuf_area,
			    RTE_CACHE_LINE_SIZE);
	if (!queue) {
		dao_err("[dev %u] Failed to allocate memory for virtio queue", dev->dev_id);
		return -ENOMEM;
	}

	queue->desc_base = (((uint64_t)q_conf->queue_desc_hi << 32) | (q_conf->queue_desc_lo));
	queue->q_sz = q_conf->queue_size;
	if (!(blkdev->flags & DAO_VIRTIO_BLKDEV_EXTBUF)) {
		queue->mp = blkdev->pool;
		/* Populate data offset along with queue for fast path purpose */
		queue->data_off = (sizeof(struct rte_mbuf));
		queue->data_off += RTE_PKTMBUF_HEADROOM;
		queue->data_off += rte_pktmbuf_priv_size(blkdev->pool);
	}

	queue->buf_len = buf_len;
	queue->notify_addr = (uint32_t *)(dev->notify_base + (queue_id * dev->notify_off_mltpr));
	queue->mbuf_arr = (void **)((uintptr_t)(queue + 1) + shadow_area);
	/* Initial queue wrap counter is 1 as per spec */
	queue->sd_desc_off = RTE_BIT64(15);
	queue->sd_mbuf_off = RTE_BIT64(15);
	queue->last_off = RTE_BIT64(15);
	queue->pend_compl_off = RTE_BIT64(15);
	queue->compl_off = RTE_BIT64(15);
	queue->auto_free = blkdev->auto_free_en;
	queue->qid = queue_id;
	queue->dma_vchan = dev->dma_vchan;
	blkdev->qs[queue_id] = queue;
	blkdev->num_queues++;
	dao_blkdev->qs[queue_id] = queue;
	queue->dao_blkdev = dao_blkdev;
	queue->blkdev_id = blkdev->dev.dev_id;
	queue->virtio_hdr_sz = sizeof(struct virtio_blk_hdr);

	dev_cfg = (volatile struct virtio_blk_config *)dev->dev_cfg;
	queue->io_depth = dev_cfg->seg_max + 2; /* +2 for header and status */
	queue->io_buf_sz = dev_cfg->size_max;

	queue->driver_area = (((uint64_t)q_conf->queue_avail_hi << 32) | (q_conf->queue_avail_lo));
	queue->sd_driver_area = (uintptr_t)queue->sd_desc_base + queue->q_sz * 16;
	/* Fetch data only after driver ok */
	if (dev->driver_ok) {
		event_flag = virtio_queue_driver_event_flag(dev, queue);
		if (event_flag < 0)
			return -1;

		/* Disable call interrupts only if events are disabled for all queues */
		cb_enabled = (event_flag != RING_EVENT_FLAGS_DISABLE);
		if (cb_enabled)
			virtio_blkdev_cb_interrupt_conf(blkdev);
	}

	dao_dbg("[dev %u] Adding queue%d: desc_base %p q_sz %u", dev->dev_id, queue_id,
		(void *)queue->desc_base, queue->q_sz);
	dao_dbg("[dev %u] Adding queue[%d]: notify_addr %p val %08x", dev->dev_id, queue_id,
		queue->notify_addr, *queue->notify_addr);

	return 0;
}

uint8_t
virtio_blkdev_hdr_size(struct virtio_blkdev *blkdev)
{
	struct virtio_dev *dev = &blkdev->dev;
	uint8_t virtio_hdr_sz;

	if (!(dev->features_ok))
		return 0;

	virtio_hdr_sz = sizeof(struct virtio_blk_hdr);
	return virtio_hdr_sz;
}

int
dao_virtio_blkdev_queue_count(uint16_t devid)
{
	struct dao_virtio_blkdev *dao_blkdev = &dao_virtio_blkdevs[devid];
	struct virtio_blkdev *blkdev = virtio_blkdev_priv(dao_blkdev);
	struct virtio_dev *dev = &blkdev->dev;

	if (!(dev->common_cfg->device_status & VIRTIO_DEV_DRIVER_OK))
		return 0;

	/* Return vq pairs set count if set or default to 1 as per spec */
	if (blkdev->num_queues)
		return blkdev->num_queues;
	return 1;
}

int
dao_virtio_blkdev_init(uint16_t devid, struct dao_virtio_blkdev_conf *conf)
{
	struct dao_virtio_blkdev *virtio_blkdev = &dao_virtio_blkdevs[devid];
	struct virtio_blkdev *blkdev = virtio_blkdev_priv(virtio_blkdev);
	volatile struct virtio_blk_config *dev_cfg;
	struct virtio_dev *dev = &blkdev->dev;
	int rc;

	dev->dev_id = devid;
	dev->dev_type = VIRTIO_DEV_TYPE_BLK;
	dev->pem_devid = conf->pem_devid;
	dev->dma_vchan = conf->dma_vchan;
	if (!(conf->flags & DAO_VIRTIO_BLKDEV_EXTBUF))
		blkdev->pool = conf->pool;
	else
		blkdev->dataroom_size = conf->dataroom_size;

	blkdev->flags = conf->flags;
	blkdev->auto_free_en = conf->auto_free_en;
	blkdev->num_queues = 0;

	if ((conf->flags & DAO_VIRTIO_BLKDEV_EXTBUF) & blkdev->auto_free_en) {
		dao_err("auto free is not supported with externally managed "
			"buffer pool\n");
		return -EINVAL;
	}

	if (conf->max_virt_queues)
		dev->max_virtio_queues_limit = conf->max_virt_queues;

	/* Initialize base virtio device */
	rc = virtio_dev_init(dev);
	if (rc)
		return rc;

	/* Setup blkdev config */
	dev_cfg = (volatile struct virtio_blk_config *)dev->dev_cfg;

	/* Copy default blkdev config */
	dev_cfg->num_queues = dev->max_virtio_queues;
	dev_cfg->blk_size = conf->blk_size;
	dev_cfg->capacity = conf->capacity;
	dev_cfg->seg_max = conf->seg_max;
	dev_cfg->size_max = conf->seg_size_max;

	virtio_dev_feature_bits_set(dev, conf->feat_bits);

	virtio_blkdev->deq_fn_id = 0;
	virtio_blkdev->compl_fn_id = 0;
	virtio_blkdev->mgmt_fn_id = 0;
	if (conf->flags & DAO_VIRTIO_BLKDEV_EXTBUF)
		virtio_blkdev->mgmt_fn_id |= VIRTIO_BLK_DESC_MANAGE_EXTBUF;

	/* One time setup */
	dev_cbs[VIRTIO_DEV_TYPE_BLK].dev_status = virtio_blkdev_status_cb;
	dev_cbs[VIRTIO_DEV_TYPE_BLK].queue_enable = virtio_blkdev_queue_enable;
	dev_cbs[VIRTIO_DEV_TYPE_BLK].feature_validate = virtio_blkdev_feature_validate;
	return 0;
}

int
dao_virtio_blkdev_fini(uint16_t devid)
{
	struct dao_virtio_blkdev *virtio_blkdev = &dao_virtio_blkdevs[devid];
	struct virtio_blkdev *blkdev = virtio_blkdev_priv(virtio_blkdev);

	return virtio_dev_fini(&blkdev->dev);
}

void
dao_virtio_blkdev_cb_register(struct dao_virtio_blkdev_cbs *cbs)
{
	blkdev_user_cbs = *cbs;
}

void
dao_virtio_blkdev_cb_unregister(void)
{
	memset(&blkdev_user_cbs, 0, sizeof(blkdev_user_cbs));
}

int
dao_virtio_blkdev_queue_count_max(uint16_t pem_devid, uint16_t devid)
{
	int rc;

	/* Get virtio device max queues */
	rc = virtio_dev_max_virtio_queues(pem_devid, devid);
	if (rc <= 0)
		return rc;
	return rc - 1;
}

void
virtio_blk_trace_dflags(struct virtio_blk_queue *q, uint16_t start, uint16_t count, bool used)
{
	struct vring_packed_desc *desc;
	uint16_t off;

	for (int i = 0; i < count; i++) {
		off = desc_off_add(start, i, q->q_sz);
		desc = (struct vring_packed_desc *)DESC_PTR_OFF(q->sd_desc_base,
				off & (q->q_sz - 1), 0);

		/* Intend to trace only used descriptor's for now to avoid bloat.
		 * useful in post trace verification. If some buf_id is not there in
		 * trace, it is probably not used. */
		if (!!(desc->flags & VRING_PACKED_DESC_F_AVAIL) == !!(desc->flags &
					VRING_PACKED_DESC_F_USED) && used) {
			virtio_blk_trace_desc_flags(used ? "used_ring" : "avail_ring",
						    q->blkdev_id, q->qid, off,
						    desc->flags, desc->id,
						    desc->len);
		}
	}
}

void
virtio_blk_desc_validate(struct virtio_blk_queue *q, uint16_t start, uint16_t count, bool avail,
			 bool used)
{
	struct virtio_blkdev *blkdev = virtio_blkdev_priv(q->dao_blkdev);
	uintptr_t sd_desc_base = (uintptr_t)q->sd_desc_base;
	struct virtio_dev *dev = &blkdev->dev;
	uint16_t q_sz = q->q_sz, off;
	uint16_t off_mask = q_sz - 1;
	uint64_t flags;
	int i;

	for (i = 0; i < count; i++) {
		off = desc_off_add(start, i, q_sz);

		/* Check if we need to clear the flags with 0x0 as debug */
		if (!avail) {
			*DESC_PTR_OFF(sd_desc_base, off, 8) = 0;
			continue;
		}

		flags = *DESC_PTR_OFF(sd_desc_base, off & off_mask, 8);
		if ((!!(flags & VIRT_PACKED_RING_DESC_F_AVAIL) != !!(off & RTE_BIT64(15))) ||
		    (flags == 0)) {
			dao_err("[dev %u] queue[%u]: avail does not match wrap bit,"
				" flags=%016lx addr=%p off=%08x",
				dev->dev_id, q->qid, flags,
				(void *)*DESC_PTR_OFF(sd_desc_base, off & off_mask, 0), off);
			abort();
		}

		if ((!!(flags & VIRT_PACKED_RING_DESC_F_USED) !=
		     !!(flags & VIRT_PACKED_RING_DESC_F_AVAIL)) &&
		    used) {
			dao_err("[dev %u] queue[%u]: used not set, flags=%016lx addr=%p off=%08x",
				dev->dev_id, q->qid, flags,
				(void *)*DESC_PTR_OFF(sd_desc_base, off & off_mask, 0), off);
			abort();
		}

		if ((!!(flags & VIRT_PACKED_RING_DESC_F_USED) ==
		     !!(flags & VIRT_PACKED_RING_DESC_F_AVAIL)) &&
		    !used) {
			dao_err("[dev %u] queue[%u]: used not clear, flags=%016lx addr=%p off=%08x",
				dev->dev_id, q->qid, flags,
				(void *)*DESC_PTR_OFF(sd_desc_base, off & off_mask, 0), off);
			abort();
		}
	}
}

static  __rte_always_inline int
virtio_blk_desc_manage(uint16_t devid, uint16_t q_count, const uint16_t flags)
{
	struct dao_virtio_blkdev *virtio_blkdev = &dao_virtio_blkdevs[devid];
	struct virtio_blkdev *blkdev = virtio_blkdev_priv(virtio_blkdev);
	struct dao_dma_vchan_info *vchan_info = RTE_PER_LCORE(dao_dma_vchan_info);
	struct dao_dma_vchan_state *dev2mem, *mem2dev;
	struct rte_dma_sge *src, *dst;
	struct virtio_blk_queue *q;
	uint16_t off, sg_i = 0;
	uint16_t compl_off;
	uint16_t dma_vchan;
	uint16_t nb_desc;
	int i;

	if (unlikely(!blkdev->qs[q_count - 1]))
		return 0;

	dma_vchan = blkdev->qs[0]->dma_vchan;
	dev2mem = &vchan_info->dev2mem[dma_vchan];
	mem2dev = &vchan_info->mem2dev[dma_vchan];

	/* Fetch all DMA completed status */
	dao_dma_check_meta_compl(dev2mem, 1 /* ATOMIC update */);
	dao_dma_check_meta_compl(mem2dev, 1 /* ATOMIC update */);

	for (i = 0; i < q_count; i++) {
		if (!dao_dma_flush(dev2mem, DAO_DMA_MAX_POINTER))
			break;

		q = blkdev->qs[i];
		src = dao_dma_sge_src(dev2mem);
		dst = dao_dma_sge_dst(dev2mem);
		sg_i = fetch_io_desc_prep(q, dev2mem, src, dst, flags);
		dev2mem->src_i += sg_i;
		dev2mem->dst_i += sg_i;
	}

	/* Process IO desc completion marking */
	for (i = 0; i < q_count; i++) {
		q = blkdev->qs[i];

		/* Check descriptor DMA completion and trigger host interrupt */
		if (q->cb_intr_addr && q->pend_compl &&
		    dao_dma_op_status(mem2dev, q->pend_compl_idx)) {
			__atomic_store_n(q->cb_notify_addr, 1, __ATOMIC_RELAXED);
			__atomic_store_n(q->cb_intr_addr, (1UL << 59), __ATOMIC_RELAXED);
			q->pend_compl = 0;
		}

		off = __atomic_load_n(&q->last_off, __ATOMIC_ACQUIRE);
		compl_off = q->compl_off;
		if (compl_off == off)
			continue;

		/* Need space for at least 2 pointer */
		if (!dao_dma_flush(mem2dev, 2))
			break;

		nb_desc = desc_off_diff(off, compl_off, q->q_sz);
		/* Enqueue Tx completion DMA */
		mark_io_desc_compl(q, mem2dev, compl_off, nb_desc, flags);
		q->compl_off = off;

		/* Store tail to check descriptor DMA completion */
		q->pend_compl_idx = mem2dev->tail;
		q->pend_compl = 1;

#ifdef VIRTIO_BLK_DEBUG
		virtio_blk_trace_queue_context(
			"virtio_blk_desc_manage", blkdev->dev.dev_id, q->qid,
			q->sd_desc_off, q->sd_mbuf_off, q->pend_sd_desc,
			q->pend_sd_mbuf, q->last_off, q->compl_off, q->m2d_pend_sd_mbuf);
#endif
	}

	return 0;
}

#define M(name, flags)                                                                             \
	int virtio_blk_desc_manage_##name(uint16_t devid, uint16_t qp_count)                       \
	{                                                                                          \
		return virtio_blk_desc_manage(devid, qp_count, (flags));                           \
	}

VIRTIO_BLK_DESC_MANAGE_MODES
#undef M
