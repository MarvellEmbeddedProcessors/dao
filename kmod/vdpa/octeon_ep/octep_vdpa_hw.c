/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 Marvell.
 */

#include "octep_vdpa.h"

#define OCTEP_HW_TIMEOUT  10000000UL

u8 octep_hw_get_status(struct octep_hw *oct_hw)
{
	return vp_ioread8(&oct_hw->common_cfg->device_status);
}

void octep_hw_set_status(struct octep_hw *oct_hw, uint8_t status)
{
	vp_iowrite8(status, &oct_hw->common_cfg->device_status);
}

void octep_hw_reset(struct octep_hw *oct_hw)
{
	u64 retry = 0;

	octep_hw_set_status(oct_hw, 0 | BIT_ULL(7));
	while (octep_hw_get_status(oct_hw) != 0) {
		if (retry++ > OCTEP_HW_TIMEOUT) {
			dev_warn(&oct_hw->pdev->dev, "Octeon device reset timeout");
			return;
		}
		udelay(1);
	}
}

u64 octep_hw_get_dev_features(struct octep_hw *oct_hw)
{
	uint32_t features_lo, features_hi;
	u64 retry = 0;

	vp_iowrite32(0 | BIT_ULL(15), &oct_hw->common_cfg->device_feature_select);
	while (vp_ioread32(&oct_hw->common_cfg->device_feature_select) != 0) {
		if (retry++ > OCTEP_HW_TIMEOUT) {
			dev_warn(&oct_hw->pdev->dev, "Feature select write timeout");
			return 0ULL;
		}
		udelay(1);
	}
	features_lo = vp_ioread32(&oct_hw->common_cfg->device_feature);

	retry = 0;
	vp_iowrite32(1 | BIT_ULL(15), &oct_hw->common_cfg->device_feature_select);
	while (vp_ioread32(&oct_hw->common_cfg->device_feature_select) != 1) {
		if (retry++ > OCTEP_HW_TIMEOUT) {
			dev_warn(&oct_hw->pdev->dev, "Feature select write timeout");
			return 0ULL;
		}
		udelay(1);
	}
	features_hi = vp_ioread32(&oct_hw->common_cfg->device_feature);

	return ((u64)features_hi << 32) | features_lo;
}

void octep_hw_set_drv_features(struct octep_hw *oct_hw, u64 features)
{
	u64 retry = 0;

	vp_iowrite32(0 | BIT_ULL(15), &oct_hw->common_cfg->guest_feature_select);
	while (vp_ioread32(&oct_hw->common_cfg->guest_feature_select) != 0) {
		if (retry++ > OCTEP_HW_TIMEOUT) {
			dev_warn(&oct_hw->pdev->dev, "Feature select write timeout");
			return;
		}
		udelay(1);
	}
	vp_iowrite32(features & (BIT_ULL(32) - 1), &oct_hw->common_cfg->guest_feature);

	retry = 0;
	vp_iowrite32(1 | BIT_ULL(15), &oct_hw->common_cfg->guest_feature_select);
	while (vp_ioread32(&oct_hw->common_cfg->guest_feature_select) != 1) {
		if (retry++ > OCTEP_HW_TIMEOUT) {
			dev_warn(&oct_hw->pdev->dev, "Feature select write timeout");
			return;
		}
		udelay(1);
	}
	vp_iowrite32(features >> 32, &oct_hw->common_cfg->guest_feature);
}

void octep_write_queue_select(uint16_t queue_id, struct octep_hw *oct_hw)
{
	u64 retry = 0;

	vp_iowrite16(queue_id | BIT_ULL(15), &oct_hw->common_cfg->queue_select);
	while (vp_ioread16(&oct_hw->common_cfg->queue_select) != queue_id) {
		if (retry++ > OCTEP_HW_TIMEOUT) {
			dev_warn(&oct_hw->pdev->dev, "Queue select write timeout");
			return;
		}
		udelay(1);
	}
}

void octep_notify_queue(struct octep_hw *oct_hw, uint16_t qid)
{
	vp_iowrite16(qid, oct_hw->vqs[qid].notify_addr);
}

void octep_read_dev_config(struct octep_hw *oct_hw, u64 offset, void *dst, int length)
{
	u8 old_gen, new_gen, *p;
	int i;

	WARN_ON(offset + length > oct_hw->config_size);
	do {
		old_gen = vp_ioread8(&oct_hw->common_cfg->config_generation);
		p = dst;
		for (i = 0; i < length; i++)
			*p++ = vp_ioread8(oct_hw->dev_cfg + offset + i);

		new_gen = vp_ioread8(&oct_hw->common_cfg->config_generation);
	} while (old_gen != new_gen);
}

void octep_write_dev_config(struct octep_hw *oct_hw, u64 offset, const void *src,
			    int length)
{
	const u8 *p;
	int i;

	p = src;
	WARN_ON(offset + length > oct_hw->config_size);
	for (i = 0; i < length; i++)
		vp_iowrite8(*p++, oct_hw->dev_cfg + offset + i);
}

int octep_set_vq_address(struct octep_hw *oct_hw, u16 qid, u64 desc_area, u64 driver_area,
			 u64 device_area)
{
	struct virtio_pci_common_cfg __iomem *cfg = oct_hw->common_cfg;

	octep_write_queue_select(qid, oct_hw);
	vp_iowrite64_twopart(desc_area, &cfg->queue_desc_lo,
			     &cfg->queue_desc_hi);
	vp_iowrite64_twopart(driver_area, &cfg->queue_avail_lo,
			     &cfg->queue_avail_hi);
	vp_iowrite64_twopart(device_area, &cfg->queue_used_lo,
			     &cfg->queue_used_hi);

	return 0;
}

void octep_set_vq_num(struct octep_hw *oct_hw, u16 qid, u32 num)
{
	struct virtio_pci_common_cfg __iomem *cfg = oct_hw->common_cfg;

	octep_write_queue_select(qid, oct_hw);
	vp_iowrite16(num, &cfg->queue_size);
}

void octep_set_vq_ready(struct octep_hw *oct_hw, u16 qid, bool ready)
{
	struct virtio_pci_common_cfg __iomem *cfg = oct_hw->common_cfg;

	octep_write_queue_select(qid, oct_hw);
	vp_iowrite16(ready, &cfg->queue_enable);
}

bool octep_get_vq_ready(struct octep_hw *oct_hw, u16 qid)
{
	struct virtio_pci_common_cfg __iomem *cfg = oct_hw->common_cfg;

	octep_write_queue_select(qid, oct_hw);
	return vp_ioread16(&cfg->queue_enable);
}

u16 octep_get_vq_size(struct octep_hw *oct_hw)
{
	octep_write_queue_select(0, oct_hw);
	return vp_ioread16(&oct_hw->common_cfg->queue_size);
}

static void __iomem *get_cap_addr(struct octep_hw *oct_hw, struct virtio_pci_cap *cap)
{
	struct device *dev = &oct_hw->pdev->dev;
	u32 length = cap->length;
	u32 offset = cap->offset;
	u8  bar    = cap->bar;
	u32 len;

	if (bar >= 6) {
		dev_err(dev, "invalid bar: %u", bar);
		return NULL;
	}
	if (offset + length < offset) {
		dev_err(dev, "offset(%u) + length(%u) overflows",
			offset, length);
		return NULL;
	}
	len = pci_resource_len(oct_hw->pdev, bar);
	if (offset + length > len) {
		dev_err(dev, "invalid cap: overflows bar space: %u > %u",
			offset + length, len);
		return NULL;
	}
	return oct_hw->base[bar] + offset;
}

void pci_caps_read(struct octep_hw *oct_hw, void *buf, size_t len, off_t offset)
{
	volatile u8 __iomem *bar = oct_hw->base[OCTEP_HW_CAPS_BAR];
	u8 *_buf = buf;
	int i;

	bar += offset;
	for (i = 0; i < len; i++)
		_buf[i] = bar[i];
}

static int pci_signature_verify(struct octep_hw *oct_hw)
{
	uint32_t signature[2];

	pci_caps_read(oct_hw, &signature, sizeof(signature), 0);

	if (signature[0] != OCTEP_FW_READY_SIGNATURE0)
		return -1;

	if (signature[1] != OCTEP_FW_READY_SIGNATURE1)
		return -1;

	return 0;
}

int octep_hw_caps_read(struct octep_hw *oct_hw, struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;
	struct virtio_pci_cap cap;
	uint8_t pos;
	int ret;

	oct_hw->pdev = pdev;
	ret = pci_signature_verify(oct_hw);
	if (ret) {
		dev_err(dev, "Octeon Virtio FW is not initialized\n");
		return -EIO;
	}

	pci_caps_read(oct_hw, &pos, 1, PCI_CAPABILITY_LIST);

	while (pos) {
		pci_caps_read(oct_hw, &cap, 2, pos);

		if (cap.cap_vndr != PCI_CAP_ID_VNDR) {
			dev_err(dev, "Found invalid capability vndr id: %d\n", cap.cap_vndr);
			break;
		}

		pci_caps_read(oct_hw, &cap, sizeof(cap), pos);

		dev_info(dev, "[%2x] cfg type: %u, bar: %u, offset: %04x, len: %u",
			 pos, cap.cfg_type, cap.bar, cap.offset, cap.length);

		switch (cap.cfg_type) {
		case VIRTIO_PCI_CAP_COMMON_CFG:
			oct_hw->common_cfg = get_cap_addr(oct_hw, &cap);
			break;
		case VIRTIO_PCI_CAP_NOTIFY_CFG:
			pci_caps_read(oct_hw, &oct_hw->notify_off_multiplier,
				      4, pos + sizeof(cap));

			oct_hw->notify_base = get_cap_addr(oct_hw, &cap);
			oct_hw->notify_bar = cap.bar;
			oct_hw->notify_base_pa = pci_resource_start(pdev, cap.bar) + cap.offset;
			break;
		case VIRTIO_PCI_CAP_DEVICE_CFG:
			oct_hw->dev_cfg = get_cap_addr(oct_hw, &cap);
			oct_hw->cap_dev_cfg_size = cap.length;
			break;
		case VIRTIO_PCI_CAP_ISR_CFG:
			oct_hw->isr = get_cap_addr(oct_hw, &cap);
			break;
		}

		pos = cap.cap_next;
	}
	if (oct_hw->common_cfg == NULL || oct_hw->notify_base == NULL ||
	    oct_hw->dev_cfg == NULL    || oct_hw->isr == NULL) {
		dev_err(dev, "Incomplete PCI capabilities");
		return -EIO;
	}

	dev_info(dev, "common cfg mapped at: 0x%016llx", (u64)oct_hw->common_cfg);
	dev_info(dev, "device cfg mapped at: 0x%016llx", (u64)oct_hw->dev_cfg);
	dev_info(dev, "isr cfg mapped at: 0x%016llx", (u64)oct_hw->isr);
	dev_info(dev, "notify base: 0x%016llx, notify off multiplier: %u",
		 (u64)oct_hw->notify_base, oct_hw->notify_off_multiplier);

	return 0;
}
