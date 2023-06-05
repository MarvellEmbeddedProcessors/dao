/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 Marvell.
 */

#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/iommu.h>
#include "octep_vdpa.h"

#define OCTEP_VDPA_DRIVER_NAME       "octep_vdpa"

struct octep_pf {
	void __iomem * const *base;
	int enabled_vfs;
	u32 vf_stride;
	u16 vf_devid;
};

struct octep_vdpa {
	struct vdpa_device vdpa;
	struct octep_hw oct_hw;
	struct pci_dev *pdev;
	/* Work entry to handle device setup */
	struct work_struct dev_setup_task;
	/* Device status */
	atomic_t status;
};

static int verify_features(u64 features)
{
	/* Minimum features to expect */
	if (!(features & BIT_ULL(VIRTIO_F_VERSION_1)))
		return -EOPNOTSUPP;

	if (!(features & BIT_ULL(VIRTIO_F_NOTIFICATION_DATA)))
		return -EOPNOTSUPP;

	if (!(features & BIT_ULL(VIRTIO_F_RING_PACKED)))
		return -EOPNOTSUPP;

	/* Per VIRTIO v1.1 specification, section 5.1.3.1 Feature bit
	 * requirements: "VIRTIO_NET_F_MQ Requires VIRTIO_NET_F_CTRL_VQ".
	 */
	if ((features & (BIT_ULL(VIRTIO_NET_F_MQ) | BIT_ULL(VIRTIO_NET_F_CTRL_VQ))) ==
	    BIT_ULL(VIRTIO_NET_F_MQ))
		return -EINVAL;

	return 0;
}

static struct octep_hw *vdpa_to_octep_hw(struct vdpa_device *vdpa_dev)
{
	struct octep_vdpa *oct_vdpa;

	oct_vdpa = container_of(vdpa_dev, struct octep_vdpa, vdpa);

	return &oct_vdpa->oct_hw;
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

	ret = verify_features(features);
	if (ret) {
		dev_err(&oct_hw->pdev->dev, "Failure in verifying driver features : %llx",
			features);
		return ret;
	}

	octep_hw_set_drv_features(oct_hw, features);
	oct_hw->drv_features = features;

	return 0;
}

static u64 octep_vdpa_get_driver_features(struct vdpa_device *vdpa_dev)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);

	return oct_hw->features & oct_hw->drv_features;
}

static u8 octep_vdpa_get_status(struct vdpa_device *vdpa_dev)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);

	return octep_hw_get_status(oct_hw);
}

static void octep_vdpa_set_status(struct vdpa_device *vdpa_dev, uint8_t status)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);
	u8 status_old;

	status_old = octep_hw_get_status(oct_hw);

	if (status_old == status)
		return;

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
	/* TODO, get avail idx/used idx from ep */
	return 0;
}

static int octep_vdpa_set_vq_state(struct vdpa_device *vdpa_dev, u16 qid,
				   const struct vdpa_vq_state *state)
{
	return 0;
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

	dev_info(&oct_hw->pdev->dev, "qid[%d]: desc_area: %llx\n", qid, desc_area);
	return octep_set_vq_address(oct_hw, qid, desc_area, driver_area, device_area);
}

static void octep_vdpa_kick_vq(struct vdpa_device *vdpa_dev, u16 qid)
{
	struct octep_hw *oct_hw = vdpa_to_octep_hw(vdpa_dev);

	octep_notify_queue(oct_hw, qid);
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
	return VIRTIO_ID_NET;
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

static void octep_vdpa_remove_pf(struct pci_dev *pdev)
{
	struct octep_pf *octpf = pci_get_drvdata(pdev);

	pci_disable_sriov(pdev);
	kfree(octpf);
}

static void octep_vdpa_remove_vf(struct pci_dev *pdev)
{
	struct octep_vdpa *oct_vdpa = pci_get_drvdata(pdev);
	int status;

	status = atomic_read(&oct_vdpa->status);
	atomic_set(&oct_vdpa->status, OCTEP_VDPA_DEV_STATUS_UNINIT);

	if (status == OCTEP_VDPA_DEV_STATUS_WAIT_FOR_BAR_INIT) {
		cancel_work_sync(&oct_vdpa->dev_setup_task);
		return;
	}

	if (status == OCTEP_VDPA_DEV_STATUS_READY) {
		free_irq(pci_irq_vector(pdev, 0), &oct_vdpa->oct_hw);
		pci_free_irq_vectors(pdev);
		kfree(oct_vdpa->oct_hw.vqs);
		vdpa_unregister_device(&oct_vdpa->vdpa);
	}
}

static void octep_vdpa_remove(struct pci_dev *pdev)
{
	if (pdev->is_virtfn)
		octep_vdpa_remove_vf(pdev);
	else
		octep_vdpa_remove_pf(pdev);
}

static u32 octep_get_config_size(struct octep_hw *oct_hw)
{
	return sizeof(struct virtio_net_config);
}

static irqreturn_t octep_vdpa_intr_handler(int irq, void *data)
{
	struct octep_hw *oct_hw = data;
	int i;

	for (i = 0; i < oct_hw->nr_vring; i++) {
		if (oct_hw->vqs[i].cb.callback && *oct_hw->vqs[i].cb_notify_addr) {
			*oct_hw->vqs[i].cb_notify_addr = 0;
			oct_hw->vqs[i].cb.callback(oct_hw->vqs[i].cb.private);
		}
	}

	return IRQ_HANDLED;
}

static int octep_vdpa_device_add(struct octep_vdpa *oct_vdpa)
{
	struct pci_dev *pdev = oct_vdpa->pdev;
	struct device *dev = &pdev->dev;
	struct octep_hw *oct_hw;
	u16 notify_off;
	int i, ret;

	oct_hw = &oct_vdpa->oct_hw;
	oct_hw->base = pcim_iomap_table(pdev);

	ret = octep_hw_caps_read(oct_hw, pdev);
	if (ret < 0)
		goto err;

	oct_hw->features = octep_hw_get_dev_features(oct_hw);
	ret = verify_features(oct_hw->features);
	if (ret) {
		dev_err(dev, "Octeon Virtio FW is not initialized\n");
		ret = -EIO;
		goto err;
	}
	oct_hw->nr_vring = vp_ioread16(&oct_hw->common_cfg->num_queues);
	oct_hw->vqs = kcalloc(oct_hw->nr_vring, sizeof(*oct_hw->vqs), GFP_KERNEL);
	if (!oct_hw->vqs) {
		ret = -ENOMEM;
		goto err;
	}
	dev_info(&pdev->dev, "Device features : %llx\n", oct_hw->features);
	dev_info(&pdev->dev, "Maximum queues : %u\n", oct_hw->nr_vring);

	for (i = 0; i < oct_hw->nr_vring; i++) {
		octep_write_queue_select(i, oct_hw);
		notify_off = vp_ioread16(&oct_hw->common_cfg->queue_notify_off);
		oct_hw->vqs[i].notify_addr = oct_hw->notify_base +
			notify_off * oct_hw->notify_off_multiplier;
		oct_hw->vqs[i].cb_notify_addr = (u32 *)oct_hw->vqs[i].notify_addr + 1;
		oct_hw->vqs[i].notify_pa = oct_hw->notify_base_pa +
			notify_off * oct_hw->notify_off_multiplier;
		oct_hw->vqs[i].irq = -EINVAL;
	}

	oct_hw->config_size = octep_get_config_size(oct_hw);
	oct_vdpa->vdpa.dma_dev = dev;

	ret = vdpa_register_device(&oct_vdpa->vdpa, oct_hw->nr_vring);
	if (ret) {
		dev_err(dev, "Failed to register to vDPA bus");
		goto err_vdpa_reg;
	}
	return 0;

err_vdpa_reg:
	kfree(oct_hw->vqs);
err:
	put_device(&oct_vdpa->vdpa.dev);
	return ret;
}

static bool get_device_ready_status(volatile u8 __iomem *addr)
{
	u64 signature = readq(addr + OCTEP_VF_MBOX_DATA(0));

	if (signature == OCTEP_DEV_READY_SIGNATURE) {
		writeq(0, addr + OCTEP_VF_MBOX_DATA(0));
		return true;
	}

	return false;
}

static void octep_vdpa_setup_task(struct work_struct *work)
{
	struct octep_vdpa *oct_vdpa = container_of(work, struct octep_vdpa, dev_setup_task);
	struct pci_dev *pdev = oct_vdpa->pdev;
	struct device *dev = &pdev->dev;
	void __iomem * const *base;
	unsigned long timeout;
	int ret;

	base = pcim_iomap_table(pdev);

	atomic_set(&oct_vdpa->status, OCTEP_VDPA_DEV_STATUS_WAIT_FOR_BAR_INIT);

	/* Wait for a maximum of 5 sec */
	timeout = jiffies + msecs_to_jiffies(5000);
	while (!time_after(jiffies, timeout)) {
		if (get_device_ready_status(base[OCTEP_HW_MBOX_BAR])) {
			atomic_set(&oct_vdpa->status, OCTEP_VDPA_DEV_STATUS_INIT);
			break;
		}

		if (atomic_read(&oct_vdpa->status) >= OCTEP_VDPA_DEV_STATUS_READY) {
			dev_info(&oct_vdpa->pdev->dev, "Stopping vDPA setup task.\n");
			return;
		}

		usleep_range(1000, 1500);
	}

	if (atomic_read(&oct_vdpa->status) != OCTEP_VDPA_DEV_STATUS_INIT) {
		dev_err(dev, "BAR initialization is timed out\n");
		goto err;
	}

	ret = pcim_iomap_regions(pdev, BIT(4), OCTEP_VDPA_DRIVER_NAME);
	if (ret) {
		dev_err(dev, "Failed to request BAR4 MMIO region\n");
		goto err;
	}

	ret = octep_vdpa_device_add(oct_vdpa);
	if (ret) {
		dev_err(dev, "Failed to add Octeon VDPA device\n");
		goto err;
	}

	/* Use one ring/interrupt per VF for virtio call interface. */
	ret = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_MSIX);
	if (ret < 0) {
		dev_err(dev, "Failed to alloc msix vector");
		goto err_irq_alloc;
	}

	oct_vdpa = pci_get_drvdata(pdev);
	snprintf(oct_vdpa->oct_hw.vqs->msix_name, sizeof(oct_vdpa->oct_hw.vqs->msix_name),
		 "%s-vf-%d", OCTEP_VDPA_DRIVER_NAME, pci_iov_vf_id(pdev));
	ret = request_irq(pci_irq_vector(pdev, 0), octep_vdpa_intr_handler, 0,
			  oct_vdpa->oct_hw.vqs->msix_name, &oct_vdpa->oct_hw);
	if (ret) {
		dev_err(dev, "Failed to register interrupt handle\n");
		goto err_irq_req;
	}

	atomic_set(&oct_vdpa->status, OCTEP_VDPA_DEV_STATUS_READY);

	return;

err_irq_req:
	pci_free_irq_vectors(pdev);
err_irq_alloc:
	vdpa_unregister_device(&oct_vdpa->vdpa);
	kfree(oct_vdpa->oct_hw.vqs);
err:
	return;
}

static int octep_vdpa_probe_vf(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;
	struct octep_vdpa *oct_vdpa;
	int ret;

	ret = pcim_enable_device(pdev);
	if (ret) {
		dev_err(dev, "Failed to enable device\n");
		return ret;
	}

	ret = pcim_iomap_regions(pdev, BIT(0), OCTEP_VDPA_DRIVER_NAME);
	if (ret) {
		dev_warn(dev, "Failed to request MMIO region\n");
		return ret;
	}

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret) {
		dev_err(dev, "No usable DMA configuration\n");
		return ret;
	}
	pci_set_master(pdev);

	if (!device_iommu_capable(dev, IOMMU_CAP_CACHE_COHERENCY)) {
		dev_info(dev, "NO-IOMMU\n");
		octep_vdpa_ops.set_map = octep_vdpa_set_map;
	}

	oct_vdpa = vdpa_alloc_device(struct octep_vdpa, vdpa, dev, &octep_vdpa_ops, 1, 1,
				     NULL, false);
	if (IS_ERR(oct_vdpa))
		return PTR_ERR(oct_vdpa);

	oct_vdpa->pdev = pdev;
	pci_set_drvdata(pdev, oct_vdpa);

	atomic_set(&oct_vdpa->status, OCTEP_VDPA_DEV_STATUS_ALLOC);
	INIT_WORK(&oct_vdpa->dev_setup_task, octep_vdpa_setup_task);
	schedule_work(&oct_vdpa->dev_setup_task);
	dev_info(&pdev->dev, "octep_vdpa device setup task queued\n");

	return 0;
}

static void octep_vdpa_assign_barspace(struct pci_dev *vf_dev, struct pci_dev *pf_dev, uint8_t idx)
{
	struct resource *vf_res = vf_dev->resource + PCI_STD_RESOURCES + 4;
	struct resource *pf_res = pf_dev->resource + PCI_STD_RESOURCES + 4;
	struct octep_pf *pf = pci_get_drvdata(pf_dev);
	struct pci_bus_region bus_region;

	vf_res->name = pci_name(vf_dev);
	vf_res->flags = pf_res->flags;
	vf_res->parent = vf_dev->resource + PCI_STD_RESOURCES;

	bus_region.start = pf_res->start + (idx * pf->vf_stride);
	bus_region.end = bus_region.start + pf->vf_stride - 1;
	pcibios_bus_to_resource(vf_dev->bus, vf_res, &bus_region);
}

static int octep_vdpa_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct octep_pf *pf = pci_get_drvdata(pdev);
	u8 __iomem *addr = pf->base[OCTEP_HW_MBOX_BAR];
	int ret, i;

	if (num_vfs > 0) {
		struct pci_dev *vf_pdev = NULL;
		bool done = false;
		int index = 0;

		ret = pci_enable_sriov(pdev, num_vfs);
		if (ret)
			return ret;

		pf->enabled_vfs = num_vfs;

		while ((vf_pdev = pci_get_device(PCI_VENDOR_ID_CAVIUM, PCI_ANY_ID, vf_pdev))) {
			if (vf_pdev->device != pf->vf_devid)
				continue;

			octep_vdpa_assign_barspace(vf_pdev, pdev, index);
			if (++index == num_vfs) {
				done = true;
				break;
			}
		}

		if (done) {
			for (i = 0; i < pf->enabled_vfs; i++)
				writeq(OCTEP_DEV_READY_SIGNATURE, addr + OCTEP_PF_MBOX_DATA(i));
		}
	} else {
		if (!pci_num_vf(pdev))
			return 0;

		pci_disable_sriov(pdev);
		pf->enabled_vfs = 0;
	}

	return num_vfs;
}

static uint16_t octep_get_vf_devid(struct pci_dev *pdev)
{
	uint16_t did;

	switch (pdev->device) {
	case OCTEP_VDPA_DEVID_CN106K_PF:
		did = OCTEP_VDPA_DEVID_CN106K_VF;
		break;
	case OCTEP_VDPA_DEVID_CN105K_PF:
		did = OCTEP_VDPA_DEVID_CN105K_VF;
		break;
	case OCTEP_VDPA_DEVID_CN103K_PF:
		did = OCTEP_VDPA_DEVID_CN103K_VF;
		break;
	default:
		did = 0xFFFF;
		break;
	}

	return did;
}

static int octep_vdpa_pf_setup(struct pci_dev *pdev)
{
	struct octep_pf *octpf = pci_get_drvdata(pdev);
	int totalvfs, ret = 0;
	u8 __iomem *addr;
	u64 val;

	octpf->base = pcim_iomap_table(pdev);
	totalvfs = pci_sriov_get_totalvfs(pdev);
	if (unlikely(!totalvfs)) {
		dev_info(&pdev->dev, "Total VFs are %d in PF sriov configuration\n", totalvfs);
		goto exit;
	}

	addr = octpf->base[OCTEP_HW_MBOX_BAR];
	val = readq(addr + OCTEP_EPF_RINFO(0));
	if (val == 0) {
		dev_err(&pdev->dev, "Invalid device configuration\n");
		ret = -EINVAL;
		goto exit;
	}

	if (OCTEP_EPF_RINFO_RPVF(val) != BIT_ULL(0)) {
		val &= ~GENMASK_ULL(35, 32);
		val |= BIT_ULL(32);
		writeq(val, addr + OCTEP_EPF_RINFO(0));
	}

	octpf->vf_stride = OCTEP_HW_BAR_SIZE / totalvfs;
	octpf->vf_devid = octep_get_vf_devid(pdev);

exit:
	return ret;
}

static int octep_vdpa_probe_pf(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;
	struct octep_pf *octpf;
	int ret;

	ret = pcim_enable_device(pdev);
	if (ret) {
		dev_err(dev, "Failed to enable device\n");
		return ret;
	}

	ret = pcim_iomap_regions(pdev, BIT(0), OCTEP_VDPA_DRIVER_NAME);
	if (ret) {
		dev_err(dev, "Failed to request MMIO region\n");
		return ret;
	}
	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret) {
		dev_err(dev, "No usable DMA configuration\n");
		return ret;
	}
	octpf = kzalloc(sizeof(*octpf), GFP_KERNEL);
	if (!octpf)
		return -ENOMEM;

	pci_set_master(pdev);
	pci_set_drvdata(pdev, octpf);

	ret = octep_vdpa_pf_setup(pdev);
	if (ret) {
		octep_vdpa_remove_pf(pdev);
		return ret;
	}

	return 0;
}

static int octep_vdpa_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	if (pdev->is_virtfn)
		return octep_vdpa_probe_vf(pdev);
	else
		return octep_vdpa_probe_pf(pdev);
}

static struct pci_device_id octep_pci_vdpa_map[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_VDPA_DEVID_CN106K_PF) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_VDPA_DEVID_CN106K_VF) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_VDPA_DEVID_CN105K_PF) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_VDPA_DEVID_CN105K_VF) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_VDPA_DEVID_CN103K_PF) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_VDPA_DEVID_CN103K_VF) },
	{ 0 },
};

static struct pci_driver octep_pci_vdpa = {
	.name     = OCTEP_VDPA_DRIVER_NAME,
	.id_table = octep_pci_vdpa_map,
	.probe    = octep_vdpa_probe,
	.remove   = octep_vdpa_remove,
	.sriov_configure = octep_vdpa_sriov_configure
};

module_pci_driver(octep_pci_vdpa);

MODULE_AUTHOR("Marvell");
MODULE_LICENSE("GPL");
