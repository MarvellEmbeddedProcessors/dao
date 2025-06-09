/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Marvell.
 */

#include <linux/bitfield.h>
#include <linux/interrupt.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/module.h>
#include <linux/iommu.h>
#include "octep_vdpa.h"

#define OCTEP_VDPA_DRIVER_NAME "octep_vdpa_pci"
#define OCTEP_VDPA_NAME_BUFSIZE 16
#define OCTEP_MBOX_BAR 0
#define OCTEP_CAPS_BAR 4

struct octep_pf {
	u8 __iomem *base[PCI_STD_NUM_BARS];
	struct pci_dev *pdev;
	struct resource res;
	u64 vf_base;
	int enabled_vfs;
	u32 vf_stride;
	u16 vf_devid;
};

static void octep_event_work(struct work_struct *work)
{
	struct octep_vdpa_event_wk *wk = container_of(work, struct octep_vdpa_event_wk, work);
	struct octep_vdpa_mgmt_dev *mgmt_dev = (struct octep_vdpa_mgmt_dev *)wk->ctxptr;
	u8 __iomem *addr = mgmt_dev->oct_hw.base[OCTEP_MBOX_BAR];
	struct pci_dev *pdev = to_pci_dev(mgmt_dev->oct_hw.dev);
	u8 event = readb(addr + OCTEP_VF_EVENT_REG(0));
	struct vdpa_dev_set_config config = { 0 };
	char name[OCTEP_VDPA_NAME_BUFSIZE];
	int ret = 0;

	switch (event) {
	case OCTEP_VDPA_DEV_ADD_EVENT:
		if (atomic_read(&mgmt_dev->status) != OCTEP_VDPA_DEV_STATUS_ADDED) {
			snprintf(name, sizeof(name), "%s-%x", "vdpa", pdev->devfn);
			ret = octep_vdpa_dev_add(&mgmt_dev->mdev, name, &config);
		}
		break;
	case OCTEP_VDPA_DEV_DEL_EVENT:
		if (atomic_read(&mgmt_dev->status) == OCTEP_VDPA_DEV_STATUS_ADDED)
			octep_vdpa_dev_del(&mgmt_dev->mdev, &mgmt_dev->oct_vdpa->vdpa);
		break;
	default:
		break;
	}

	event = ret ? OCTEP_VDPA_DEV_EVENT_NACK : OCTEP_VDPA_DEV_EVENT_ACK;
	writeb(event, addr + OCTEP_VF_EVENT_REG(0));
	writeb(OCTEP_VDPA_DEV_EVENT_DONE, addr + OCTEP_VF_EVENT_STATE(0));
}

static bool get_device_ready_status(u8 __iomem *addr)
{
	u32 signature = readl(addr + OCTEP_VF_MBOX_DATA(0));

	if (signature == OCTEP_DEV_READY_SIGNATURE) {
		writel(0, addr + OCTEP_VF_MBOX_DATA(0));
		return true;
	}

	return false;
}

static int octep_iomap_region(struct pci_dev *pdev, u8 __iomem **tbl, u8 bar)
{
	int ret;

	ret = pci_request_region(pdev, bar, OCTEP_VDPA_DRIVER_NAME);
	if (ret) {
		dev_err(&pdev->dev, "Failed to request BAR:%u region\n", bar);
		return ret;
	}

	tbl[bar] = pci_iomap(pdev, bar, pci_resource_len(pdev, bar));
	if (!tbl[bar]) {
		dev_err(&pdev->dev, "Failed to iomap BAR:%u\n", bar);
		pci_release_region(pdev, bar);
		ret = -ENOMEM;
	}

	return ret;
}

static void octep_iounmap_region(struct pci_dev *pdev, u8 __iomem **tbl, u8 bar)
{
	pci_iounmap(pdev, tbl[bar]);
	pci_release_region(pdev, bar);
}

static void octep_pci_free_irqs(struct octep_hw *oct_hw)
{
	struct pci_dev *pdev = to_pci_dev(oct_hw->dev);
	int i;

	if (!oct_hw->irqs)
		return;

	for (i = 0; i < oct_hw->requested_irqs; i++) {
		if (oct_hw->irqs[i])
			devm_free_irq(&pdev->dev, oct_hw->irqs[i], oct_hw);
	}

	pci_free_irq_vectors(pdev);
	devm_kfree(&pdev->dev, oct_hw->irqs);
	oct_hw->irqs = NULL;
	oct_hw->requested_irqs = 0;
}

static int octep_pci_request_irqs(struct octep_hw *oct_hw, irqreturn_t (*irq_handler)(int, void *),
				  int nb_irqs)
{
	struct pci_dev *pdev = to_pci_dev(oct_hw->dev);
	struct device *dev = oct_hw->dev;
	int ret, irq, idx;

	if ((oct_hw->requested_irqs != nb_irqs) || (nb_irqs == 1))
		octep_pci_free_irqs(oct_hw);
	else
		return 0;

	oct_hw->irqs = devm_kcalloc(dev, nb_irqs, sizeof(int), GFP_KERNEL);
	if (!oct_hw->irqs)
		return -ENOMEM;

	ret = pci_alloc_irq_vectors(pdev, nb_irqs, nb_irqs, PCI_IRQ_MSIX);
	if (ret < 0) {
		dev_err(dev, "Failed to alloc msix vector\n");
		goto free_irqs_array;
	}
	if (ret != nb_irqs) {
		dev_err(dev, "Requested %d MSI-X vectors but got %d\n", nb_irqs, ret);
		ret = -ENOSPC;
		goto free_irqs;
	}

	for (idx = 0; idx < nb_irqs; idx++) {
		irq = pci_irq_vector(pdev, idx);
		ret = devm_request_irq(dev, irq, irq_handler, 0, dev_name(dev), oct_hw);
		if (ret) {
			dev_err(dev, "Failed to register interrupt handler for IRQ %d\n", irq);
			goto free_irqs;
		}
		oct_hw->irqs[idx] = irq;
		oct_hw->requested_irqs++;
	}

	return 0;

free_irqs:
	octep_pci_free_irqs(oct_hw);
free_irqs_array:
	devm_kfree(dev, oct_hw->irqs);
	oct_hw->irqs = NULL;
	return ret;
}

static void octep_pci_pf_bar_shrink(struct octep_pf *octpf)
{
	struct pci_dev *pf_dev = octpf->pdev;
	struct resource *res = pf_dev->resource + PCI_STD_RESOURCES + 4;
	struct pci_bus_region bus_region;

	octpf->res.start = res->start;
	octpf->res.end = res->end;
	octpf->vf_base = res->start;

	bus_region.start = res->start;
	bus_region.end = res->start - 1;

	pcibios_bus_to_resource(pf_dev->bus, res, &bus_region);
}

static void octep_pci_pf_bar_expand(struct octep_pf *octpf)
{
	struct pci_dev *pf_dev = octpf->pdev;
	struct resource *res = pf_dev->resource + PCI_STD_RESOURCES + 4;
	struct pci_bus_region bus_region;

	bus_region.start = octpf->res.start;
	bus_region.end = octpf->res.end;

	pcibios_bus_to_resource(pf_dev->bus, res, &bus_region);
}

static void octep_pci_remove_pf(struct pci_dev *pdev)
{
	struct octep_pf *octpf = pci_get_drvdata(pdev);

	pci_disable_sriov(pdev);

	if (octpf->base[OCTEP_CAPS_BAR])
		octep_iounmap_region(pdev, octpf->base, OCTEP_CAPS_BAR);

	if (octpf->base[OCTEP_MBOX_BAR])
		octep_iounmap_region(pdev, octpf->base, OCTEP_MBOX_BAR);

	octep_pci_pf_bar_expand(octpf);
}

static void octep_pci_vf_bar_shrink(struct pci_dev *pdev)
{
	struct resource *vf_res = pdev->resource + PCI_STD_RESOURCES + 4;

	memset(vf_res, 0, sizeof(*vf_res));
}

static void octep_pci_remove_vf(struct pci_dev *pdev)
{
	struct octep_vdpa_mgmt_dev *mgmt_dev = pci_get_drvdata(pdev);
	struct octep_hw *oct_hw;
	int status;

	oct_hw = &mgmt_dev->oct_hw;
	status = atomic_read(&mgmt_dev->status);
	atomic_set(&mgmt_dev->status, OCTEP_VDPA_DEV_STATUS_UNINIT);

	cancel_work_sync(&mgmt_dev->setup_task);
	if (status == OCTEP_VDPA_DEV_STATUS_READY || status == OCTEP_VDPA_DEV_STATUS_ADDED ||
	    status == OCTEP_VDPA_DEV_STATUS_REMOVED)
		vdpa_mgmtdev_unregister(&mgmt_dev->mdev);

	if (oct_hw->base[OCTEP_CAPS_BAR])
		octep_iounmap_region(pdev, oct_hw->base, OCTEP_CAPS_BAR);

	if (oct_hw->base[OCTEP_MBOX_BAR])
		octep_iounmap_region(pdev, oct_hw->base, OCTEP_MBOX_BAR);

	octep_pci_vf_bar_shrink(pdev);

	octep_pci_free_irqs(oct_hw);
}

static void octep_pci_remove(struct pci_dev *pdev)
{
	if (pdev->is_virtfn)
		octep_pci_remove_vf(pdev);
	else
		octep_pci_remove_pf(pdev);
}

static inline void octep_pci_event_schedule(struct octep_hw *oct_hw)
{
	u8 __iomem *addr = oct_hw->base[OCTEP_MBOX_BAR];
	struct octep_vdpa_mgmt_dev *mgmt_dev;

	mgmt_dev = container_of(oct_hw, struct octep_vdpa_mgmt_dev, oct_hw);
	writeb(OCTEP_VDPA_DEV_EVENT_ACTIVE, addr + OCTEP_VF_EVENT_STATE(0));
	schedule_work(&mgmt_dev->event_wk.work);
}

static irqreturn_t octep_pci_event_handler(int irq, void *data)
{
	struct octep_hw *oct_hw = data;

	if (readb(oct_hw->base[OCTEP_MBOX_BAR] + OCTEP_VF_EVENT_STATE(0)) ==
	    OCTEP_VDPA_DEV_NEW_EVENT)
		octep_pci_event_schedule(oct_hw);

	return IRQ_HANDLED;
}

static const struct octep_hw_ops octep_pci_ops = {
	.request_irqs = octep_pci_request_irqs,
	.free_irqs = octep_pci_free_irqs,
	.handle_event = octep_pci_event_handler,
};

static void octep_pci_setup_task(struct work_struct *work)
{
	struct octep_vdpa_mgmt_dev *mgmt_dev =
		container_of(work, struct octep_vdpa_mgmt_dev, setup_task);
	struct octep_hw *oct_hw = &mgmt_dev->oct_hw;
	struct pci_dev *pdev = to_pci_dev(oct_hw->dev);
	struct device *dev = &pdev->dev;
	unsigned long timeout;
	u64 val;
	int ret;

	atomic_set(&mgmt_dev->status, OCTEP_VDPA_DEV_STATUS_WAIT_FOR_BAR_INIT);

	/* Wait for a maximum of 5 sec */
	timeout = jiffies + msecs_to_jiffies(5000);
	while (!time_after(jiffies, timeout)) {
		if (get_device_ready_status(oct_hw->base[OCTEP_MBOX_BAR])) {
			atomic_set(&mgmt_dev->status, OCTEP_VDPA_DEV_STATUS_INIT);
			break;
		}

		if (atomic_read(&mgmt_dev->status) >= OCTEP_VDPA_DEV_STATUS_READY) {
			dev_info(dev, "Stopping vDPA setup task.\n");
			return;
		}

		usleep_range(1000, 1500);
	}

	if (atomic_read(&mgmt_dev->status) != OCTEP_VDPA_DEV_STATUS_INIT) {
		dev_err(dev, "BAR initialization is timed out\n");
		return;
	}

	ret = octep_iomap_region(pdev, oct_hw->base, OCTEP_CAPS_BAR);
	if (ret)
		return;

	val = readq(oct_hw->base[OCTEP_MBOX_BAR] + OCTEP_VF_IN_CTRL(0));
	oct_hw->nb_irqs = OCTEP_VF_IN_CTRL_RPVF(val);
	if (!oct_hw->nb_irqs || oct_hw->nb_irqs > OCTEP_MAX_CB_INTR) {
		dev_err(dev, "Invalid number of interrupts %d\n", oct_hw->nb_irqs);
		goto unmap_region;
	}

	oct_hw->caps_bar = OCTEP_CAPS_BAR;
	ret = octep_hw_caps_read(oct_hw);
	if (ret < 0)
		goto unmap_region;

	ret = octep_vdpa_mgmt_dev_register(mgmt_dev);
	if (ret) {
		dev_err(dev, "Failed to register management device\n");
		goto unmap_region;
	}

	atomic_set(&mgmt_dev->status, OCTEP_VDPA_DEV_STATUS_READY);

	INIT_WORK(&mgmt_dev->event_wk.work, octep_event_work);
	mgmt_dev->event_wk.ctxptr = mgmt_dev;

	ret = oct_hw->ops->request_irqs(oct_hw, oct_hw->ops->handle_event, 1);
	if (ret) {
		dev_err(dev, "Failed to request IRQs\n");
		atomic_set(&mgmt_dev->status, OCTEP_VDPA_DEV_STATUS_INIT);
		vdpa_mgmtdev_unregister(&mgmt_dev->mdev);
		goto unmap_region;
	}

	return;

unmap_region:
	octep_iounmap_region(pdev, oct_hw->base, OCTEP_CAPS_BAR);
	oct_hw->base[OCTEP_CAPS_BAR] = NULL;
}

static int octep_pci_probe_vf(struct pci_dev *pdev)
{
	struct octep_vdpa_mgmt_dev *mgmt_dev;
	struct device *dev = &pdev->dev;
	int ret;

	ret = pcim_enable_device(pdev);
	if (ret) {
		dev_err(dev, "Failed to enable device\n");
		return ret;
	}

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret) {
		dev_err(dev, "No usable DMA configuration\n");
		return ret;
	}
	pci_set_master(pdev);

	mgmt_dev = devm_kzalloc(dev, sizeof(struct octep_vdpa_mgmt_dev), GFP_KERNEL);
	if (!mgmt_dev)
		return -ENOMEM;

	ret = octep_iomap_region(pdev, mgmt_dev->oct_hw.base, OCTEP_MBOX_BAR);
	if (ret)
		return ret;

	pci_set_drvdata(pdev, mgmt_dev);
	mgmt_dev->oct_hw.dev = dev;
	mgmt_dev->oct_hw.dma_dev = dev;
	mgmt_dev->oct_hw.dev_type = OCTEP_DEV_TYPE_PCI;
	mgmt_dev->oct_hw.ops = &octep_pci_ops;

	atomic_set(&mgmt_dev->status, OCTEP_VDPA_DEV_STATUS_ALLOC);
	INIT_WORK(&mgmt_dev->setup_task, octep_pci_setup_task);
	schedule_work(&mgmt_dev->setup_task);
	dev_info(&pdev->dev, "octep vdpa mgmt device setup task is queued\n");

	return 0;
}

static void octep_pci_assign_barspace(struct pci_dev *vf_dev, struct pci_dev *pf_dev, u8 idx)
{
	struct resource *vf_res = vf_dev->resource + PCI_STD_RESOURCES + 4;
	struct resource *pf_res = pf_dev->resource + PCI_STD_RESOURCES + 4;
	struct octep_pf *pf = pci_get_drvdata(pf_dev);
	struct pci_bus_region bus_region;

	vf_res->name = pci_name(vf_dev);
	vf_res->flags = pf_res->flags;
	vf_res->parent = (pf_dev->resource + PCI_STD_RESOURCES)->parent;

	bus_region.start = pf->vf_base + idx * pf->vf_stride;
	bus_region.end = bus_region.start + pf->vf_stride - 1;
	pcibios_bus_to_resource(vf_dev->bus, vf_res, &bus_region);
}

static int octep_sriov_enable(struct pci_dev *pdev, int num_vfs)
{
	struct octep_pf *pf = pci_get_drvdata(pdev);
	u8 __iomem *addr = pf->base[OCTEP_MBOX_BAR];
	struct pci_dev *vf_pdev = NULL;
	bool done = false;
	int index = 0;
	int ret, i;
	u8 rpvf;
	u64 val;

	ret = pci_enable_sriov(pdev, num_vfs);
	if (ret)
		return ret;

	pf->enabled_vfs = num_vfs;

	while ((vf_pdev = pci_get_device(PCI_VENDOR_ID_CAVIUM, PCI_ANY_ID, vf_pdev))) {
		if (vf_pdev->device != pf->vf_devid)
			continue;

		octep_pci_assign_barspace(vf_pdev, pdev, index);
		if (++index == num_vfs) {
			done = true;
			break;
		}
	}

	if (vf_pdev)
		pci_dev_put(vf_pdev);

	val = readq(addr + OCTEP_EPF_RINFO(0));
	rpvf = FIELD_GET(GENMASK_ULL(35, 32), val);
	if (done) {
		for (i = 0; i < pf->enabled_vfs; i++)
			writel(OCTEP_DEV_READY_SIGNATURE, addr + OCTEP_PF_MBOX_DATA(i * rpvf));
	}

	return num_vfs;
}

static int octep_sriov_disable(struct pci_dev *pdev)
{
	struct octep_pf *pf = pci_get_drvdata(pdev);

	if (!pci_num_vf(pdev))
		return 0;

	pci_disable_sriov(pdev);
	pf->enabled_vfs = 0;

	return 0;
}

static int octep_pci_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	if (num_vfs > 0)
		return octep_sriov_enable(pdev, num_vfs);
	else
		return octep_sriov_disable(pdev);
}

static u16 octep_get_vf_devid(struct pci_dev *pdev)
{
	u16 did;

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

static int octep_pci_pf_setup(struct octep_pf *octpf)
{
	u8 __iomem *addr = octpf->base[OCTEP_MBOX_BAR];
	struct pci_dev *pdev = octpf->pdev;
	int totalvfs;
	size_t len;
	u64 val;

	totalvfs = pci_sriov_get_totalvfs(pdev);
	if (unlikely(!totalvfs)) {
		dev_info(&pdev->dev, "Total VFs are %d in PF sriov configuration\n", totalvfs);
		return 0;
	}

	val = readq(addr + OCTEP_EPF_RINFO(0));
	if (val == 0) {
		dev_err(&pdev->dev, "Invalid device configuration\n");
		return -EINVAL;
	}

	len = pci_resource_len(pdev, OCTEP_CAPS_BAR);

	octpf->vf_stride = len / totalvfs;
	octpf->vf_devid = octep_get_vf_devid(pdev);

	octep_pci_pf_bar_shrink(octpf);

	return 0;
}

static int octep_pci_probe_pf(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;
	struct octep_pf *octpf;
	int ret;

	ret = pcim_enable_device(pdev);
	if (ret) {
		dev_err(dev, "Failed to enable device\n");
		return ret;
	}

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret) {
		dev_err(dev, "No usable DMA configuration\n");
		return ret;
	}
	octpf = devm_kzalloc(dev, sizeof(*octpf), GFP_KERNEL);
	if (!octpf)
		return -ENOMEM;

	ret = octep_iomap_region(pdev, octpf->base, OCTEP_MBOX_BAR);
	if (ret)
		return ret;

	pci_set_master(pdev);
	pci_set_drvdata(pdev, octpf);
	octpf->pdev = pdev;

	ret = octep_pci_pf_setup(octpf);
	if (ret)
		goto unmap_region;

	return 0;

unmap_region:
	octep_iounmap_region(pdev, octpf->base, OCTEP_MBOX_BAR);
	return ret;
}

static int octep_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	if (pdev->is_virtfn)
		return octep_pci_probe_vf(pdev);
	else
		return octep_pci_probe_pf(pdev);
}

static struct pci_device_id octep_vdpa_pci_map[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_VDPA_DEVID_CN106K_PF) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_VDPA_DEVID_CN106K_VF) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_VDPA_DEVID_CN105K_PF) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_VDPA_DEVID_CN105K_VF) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_VDPA_DEVID_CN103K_PF) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_VDPA_DEVID_CN103K_VF) },
	{ 0 },
};

static struct pci_driver octep_vdpa_pci = {
	.name     = OCTEP_VDPA_DRIVER_NAME,
	.id_table = octep_vdpa_pci_map,
	.probe    = octep_pci_probe,
	.remove   = octep_pci_remove,
	.sriov_configure = octep_pci_sriov_configure
};

module_pci_driver(octep_vdpa_pci);

MODULE_AUTHOR("Marvell");
MODULE_DESCRIPTION("Marvell Octeon PCIe endpoint vDPA driver");
MODULE_LICENSE("GPL");
