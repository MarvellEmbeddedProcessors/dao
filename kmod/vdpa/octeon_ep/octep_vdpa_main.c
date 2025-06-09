/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 Marvell.
 */

#include <linux/bitfield.h>
#include <linux/interrupt.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/module.h>
#include <linux/iommu.h>
#include "octep_vdpa.h"

static struct octep_hw *vdpa_to_octep_hw(struct vdpa_device *vdpa_dev)
{
	struct octep_vdpa *oct_vdpa;

	oct_vdpa = container_of(vdpa_dev, struct octep_vdpa, vdpa);

	return oct_vdpa->oct_hw;
}

static irqreturn_t octep_vdpa_intr_handler(int irq, void *data)
{
	struct octep_hw *oct_hw = data;
	int i, start_ring_idx = -1;

	/* Each device has multiple interrupts (nb_irqs) shared among rings
	 * (nr_vring). Device interrupts are mapped to the rings in a
	 * round-robin fashion.
	 *
	 * For example, if nb_irqs = 8 and nr_vring = 64:
	 * 0 -> 0, 8, 16, 24, 32, 40, 48, 56;
	 * 1 -> 1, 9, 17, 25, 33, 41, 49, 57;
	 * ...
	 * 7 -> 7, 15, 23, 31, 39, 47, 55, 63;
	 */

	for (i = 0; i < oct_hw->nb_irqs; i++) {
		if (oct_hw->irqs[i] == irq) {
			start_ring_idx = i;
			break;
		}
	}
	if (start_ring_idx == -1)
		return IRQ_NONE;

	for (i = start_ring_idx; i < oct_hw->nr_vring; i += oct_hw->nb_irqs) {
		if (ioread8(oct_hw->vqs[i].cb_notify_addr)) {
			/* Acknowledge the per ring notification to the device */
			iowrite8(0, oct_hw->vqs[i].cb_notify_addr);

			if (likely(oct_hw->vqs[i].cb.callback))
				oct_hw->vqs[i].cb.callback(oct_hw->vqs[i].cb.private);
			break;
		}
	}

	/* Check for config interrupt. Config uses the first interrupt */
	if (unlikely(irq == oct_hw->irqs[0])) {
		if (ioread8(oct_hw->isr)) {
			iowrite8(0, oct_hw->isr);

			if (oct_hw->config_cb.callback)
				oct_hw->config_cb.callback(oct_hw->config_cb.private);
		}

		if (oct_hw->ops->handle_event)
			return oct_hw->ops->handle_event(irq, data);
	}

	return IRQ_HANDLED;
}

static u64 octep_vdpa_get_device_features(struct vdpa_device *vdpa_dev)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);

	return oct_hw->features;
}

static int octep_vdpa_set_driver_features(struct vdpa_device *vdpa_dev, u64 features)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);
	int ret;

	pr_debug("Driver Features: %llx\n", features);

	ret = octep_verify_features(features);
	if (ret) {
		pr_warn("Must negotiate minimum features 0x%llx for this device",
			BIT_ULL(VIRTIO_F_VERSION_1) | BIT_ULL(VIRTIO_F_NOTIFICATION_DATA) |
				BIT_ULL(VIRTIO_F_RING_PACKED));
		return ret;
	}
	octep_hw_set_drv_features(oct_hw, features);

	return 0;
}

static u64 octep_vdpa_get_driver_features(struct vdpa_device *vdpa_dev)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);

	return octep_hw_get_drv_features(oct_hw);
}

static u8 octep_vdpa_get_status(struct vdpa_device *vdpa_dev)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);

	return octep_hw_get_status(oct_hw);
}

static void octep_vdpa_set_status(struct vdpa_device *vdpa_dev, u8 status)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);
	u8 status_old;

	status_old = octep_hw_get_status(oct_hw);

	if (status_old == status)
		return;

	if ((status & VIRTIO_CONFIG_S_DRIVER_OK) && !(status_old & VIRTIO_CONFIG_S_DRIVER_OK)) {
		if (!oct_hw->ops->request_irqs ||
		    oct_hw->ops->request_irqs(oct_hw, octep_vdpa_intr_handler, oct_hw->nb_irqs))
			status = status_old | VIRTIO_CONFIG_S_FAILED;
	}
	octep_hw_set_status(oct_hw, status);
}

static int octep_vdpa_reset(struct vdpa_device *vdpa_dev)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);
	u8 status = octep_hw_get_status(oct_hw);
	u16 qid;

	if (status == 0)
		return 0;

	for (qid = 0; qid < oct_hw->nr_vring; qid++) {
		oct_hw->vqs[qid].cb.callback = NULL;
		oct_hw->vqs[qid].cb.private = NULL;
		oct_hw->config_cb.callback = NULL;
		oct_hw->config_cb.private = NULL;
	}
	octep_hw_reset(oct_hw);

	if (status & VIRTIO_CONFIG_S_DRIVER_OK) {
		if (oct_hw->ops->free_irqs)
			oct_hw->ops->free_irqs(oct_hw);
		if (oct_hw->ops->handle_event && oct_hw->ops->request_irqs)
			oct_hw->ops->request_irqs(oct_hw, oct_hw->ops->handle_event, 1);
	}

	return 0;
}

static u16 octep_vdpa_get_vq_num_max(struct vdpa_device *vdpa_dev)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);

	return octep_get_vq_size(oct_hw);
}

static int octep_vdpa_get_vq_state(struct vdpa_device *vdpa_dev, u16 qid,
				   struct vdpa_vq_state *state)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);

	return octep_get_vq_state(oct_hw, qid, state);
}

static int octep_vdpa_set_vq_state(struct vdpa_device *vdpa_dev, u16 qid,
				   const struct vdpa_vq_state *state)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);

	return octep_set_vq_state(oct_hw, qid, state);
}

static void octep_vdpa_set_vq_cb(struct vdpa_device *vdpa_dev, u16 qid, struct vdpa_callback *cb)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);

	oct_hw->vqs[qid].cb = *cb;
}

static void octep_vdpa_set_vq_ready(struct vdpa_device *vdpa_dev, u16 qid, bool ready)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);

	octep_set_vq_ready(oct_hw, qid, ready);
}

static bool octep_vdpa_get_vq_ready(struct vdpa_device *vdpa_dev, u16 qid)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);

	return octep_get_vq_ready(oct_hw, qid);
}

static void octep_vdpa_set_vq_num(struct vdpa_device *vdpa_dev, u16 qid, u32 num)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);

	octep_set_vq_num(oct_hw, qid, num);
}

static int octep_vdpa_set_vq_address(struct vdpa_device *vdpa_dev, u16 qid, u64 desc_area,
				     u64 driver_area, u64 device_area)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);

	pr_debug("qid[%d]: desc_area: %llx\n", qid, desc_area);
	pr_debug("qid[%d]: driver_area: %llx\n", qid, driver_area);
	pr_debug("qid[%d]: device_area: %llx\n\n", qid, device_area);

	return octep_set_vq_address(oct_hw, qid, desc_area, driver_area, device_area);
}

static void octep_vdpa_kick_vq(struct vdpa_device *vdpa_dev, u16 qid)
{
	/* Not supported */
}

static void octep_vdpa_kick_vq_with_data(struct vdpa_device *vdpa_dev, u32 data)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);
	u16 idx = data & 0xFFFF;

	vp_iowrite32(data, oct_hw->vqs[idx].notify_addr);
}

static u32 octep_vdpa_get_generation(struct vdpa_device *vdpa_dev)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);

	return vp_ioread8(&oct_hw->common_cfg->config_generation);
}

static u32 octep_vdpa_get_device_id(struct vdpa_device *vdpa_dev)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);

	return oct_hw->dev_id;
}

static u32 octep_vdpa_get_vendor_id(struct vdpa_device *vdpa_dev)
{
	return PCI_VENDOR_ID_CAVIUM;
}

static u32 octep_vdpa_get_vq_align(struct vdpa_device *vdpa_dev)
{
	return PAGE_SIZE;
}

static size_t octep_vdpa_get_config_size(struct vdpa_device *vdpa_dev)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);

	return oct_hw->config_size;
}

static void octep_vdpa_get_config(struct vdpa_device *vdpa_dev, unsigned int offset, void *buf,
				  unsigned int len)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);

	octep_read_dev_config(oct_hw, offset, buf, len);
}

static void octep_vdpa_set_config(struct vdpa_device *vdpa_dev, unsigned int offset,
				  const void *buf, unsigned int len)
{
	/* Not supported */
}

static void octep_vdpa_set_config_cb(struct vdpa_device *vdpa_dev, struct vdpa_callback *cb)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);

	oct_hw->config_cb.callback = cb->callback;
	oct_hw->config_cb.private = cb->private;
}

static struct vdpa_notification_area octep_get_vq_notification(struct vdpa_device *vdpa_dev,
							       u16 idx)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);
	struct vdpa_notification_area area;

	area.addr = oct_hw->vqs[idx].notify_pa;
	area.size = PAGE_SIZE;

	return area;
}

static int octep_vdpa_set_map(struct vdpa_device *vdev, unsigned int asid,
			      struct vhost_iotlb *iotlb)
{
	return 0;
}

static struct vdpa_config_ops octep_vdpa_ops = {
	.get_device_features = octep_vdpa_get_device_features,
	.set_driver_features = octep_vdpa_set_driver_features,
	.get_driver_features = octep_vdpa_get_driver_features,
	.get_status	= octep_vdpa_get_status,
	.set_status	= octep_vdpa_set_status,
	.reset		= octep_vdpa_reset,
	.get_vq_num_max	= octep_vdpa_get_vq_num_max,
	.get_vq_state	= octep_vdpa_get_vq_state,
	.set_vq_state	= octep_vdpa_set_vq_state,
	.set_vq_cb	= octep_vdpa_set_vq_cb,
	.set_vq_ready	= octep_vdpa_set_vq_ready,
	.get_vq_ready	= octep_vdpa_get_vq_ready,
	.set_vq_num	= octep_vdpa_set_vq_num,
	.set_vq_address	= octep_vdpa_set_vq_address,
	.get_vq_irq	= NULL,
	.kick_vq	= octep_vdpa_kick_vq,
	.kick_vq_with_data	= octep_vdpa_kick_vq_with_data,
	.get_generation	= octep_vdpa_get_generation,
	.get_device_id	= octep_vdpa_get_device_id,
	.get_vendor_id	= octep_vdpa_get_vendor_id,
	.get_vq_align	= octep_vdpa_get_vq_align,
	.get_config_size	= octep_vdpa_get_config_size,
	.get_config	= octep_vdpa_get_config,
	.set_config	= octep_vdpa_set_config,
	.set_config_cb  = octep_vdpa_set_config_cb,
	.get_vq_notification = octep_get_vq_notification,
};

int octep_vdpa_dev_add(struct vdpa_mgmt_dev *mdev, const char *name,
		       const struct vdpa_dev_set_config *config)
{
	struct octep_vdpa_mgmt_dev *mgmt_dev = container_of(mdev, struct octep_vdpa_mgmt_dev, mdev);
	struct octep_hw *oct_hw = &mgmt_dev->oct_hw;
	struct device *dev = oct_hw->dev;
	struct vdpa_device *vdpa_dev;
	struct octep_vdpa *oct_vdpa;
	struct device *dma_dev;
	u64 device_features;
	int ret;

	dma_dev = oct_hw->dma_dev ? oct_hw->dma_dev : dev;
	if (!device_iommu_capable(dma_dev, IOMMU_CAP_CACHE_COHERENCY)) {
		dev_info(dev, "NO-IOMMU\n");
		octep_vdpa_ops.set_map = octep_vdpa_set_map;
	}
	oct_vdpa =
		vdpa_alloc_device(struct octep_vdpa, vdpa, dev, &octep_vdpa_ops, 1, 1, NULL, false);
	if (IS_ERR(oct_vdpa)) {
		dev_err(dev, "Failed to allocate vDPA structure for octep vdpa device");
		return PTR_ERR(oct_vdpa);
	}

	oct_vdpa->vdpa.dma_dev = dma_dev;
	oct_vdpa->vdpa.mdev = mdev;
	oct_vdpa->oct_hw = oct_hw;
	vdpa_dev = &oct_vdpa->vdpa;
	mgmt_dev->oct_vdpa = oct_vdpa;

	device_features = oct_hw->features;
	if (config->mask & BIT_ULL(VDPA_ATTR_DEV_FEATURES)) {
		if (config->device_features & ~device_features) {
			dev_err(dev,
				"The provisioned features 0x%llx are not supported by this device with features 0x%llx\n",
				config->device_features, device_features);
			ret = -EINVAL;
			goto vdpa_dev_put;
		}
		device_features &= config->device_features;
	}

	oct_hw->features = device_features;
	dev_info(dev, "Vdpa management device features : %llx\n", device_features);

	ret = octep_verify_features(device_features);
	if (ret) {
		dev_warn(mdev->device,
			 "Must provision minimum features 0x%llx for this device",
			 BIT_ULL(VIRTIO_F_VERSION_1) | BIT_ULL(VIRTIO_F_ACCESS_PLATFORM) |
			 BIT_ULL(VIRTIO_F_NOTIFICATION_DATA) | BIT_ULL(VIRTIO_F_RING_PACKED));
		goto vdpa_dev_put;
	}
	if (name)
		ret = dev_set_name(&vdpa_dev->dev, "%s", name);
	else
		ret = dev_set_name(&vdpa_dev->dev, "vdpa%u", vdpa_dev->index);

	ret = _vdpa_register_device(&oct_vdpa->vdpa, oct_hw->nr_vring);
	if (ret) {
		dev_err(dev, "Failed to register to vDPA bus");
		goto vdpa_dev_put;
	}

	atomic_set(&mgmt_dev->status, OCTEP_VDPA_DEV_STATUS_ADDED);

	return 0;

vdpa_dev_put:
	put_device(&oct_vdpa->vdpa.dev);
	return ret;
}

void octep_vdpa_dev_del(struct vdpa_mgmt_dev *mdev, struct vdpa_device *vdpa_dev)
{
	struct octep_vdpa_mgmt_dev *mgmt_dev = container_of(mdev, struct octep_vdpa_mgmt_dev, mdev);

	_vdpa_unregister_device(vdpa_dev);

	atomic_set(&mgmt_dev->status, OCTEP_VDPA_DEV_STATUS_REMOVED);
}

static const struct vdpa_mgmtdev_ops octep_vdpa_mgmt_dev_ops = {
	.dev_add = octep_vdpa_dev_add,
	.dev_del = octep_vdpa_dev_del
};

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_NET, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

int octep_vdpa_mgmt_dev_register(struct octep_vdpa_mgmt_dev *mgmt_dev)
{
	struct octep_hw *oct_hw = &mgmt_dev->oct_hw;
	int ret;

	mgmt_dev->mdev.ops = &octep_vdpa_mgmt_dev_ops;
	mgmt_dev->mdev.id_table = id_table;
	mgmt_dev->mdev.max_supported_vqs = oct_hw->nr_vring;
	mgmt_dev->mdev.supported_features = oct_hw->features;
	mgmt_dev->mdev.config_attr_mask = (1 << VDPA_ATTR_DEV_FEATURES);
	mgmt_dev->mdev.device = oct_hw->dev;

	ret = vdpa_mgmtdev_register(&mgmt_dev->mdev);
	if (ret) {
		dev_err(oct_hw->dev, "Failed to register vdpa management interface\n");
		return ret;
	}

	return 0;
}
