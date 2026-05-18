/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Marvell.
 *
 * Character device for RDMA Termination on Octeon.
 * Allocates a 64MB DDR region with BAR4-identical layout, exposes it
 * via mmap to the RDMA application, and provides the OCTTERM_IOC_FW_READY
 * ioctl for two-phase initialization.
 */

#ifdef CONFIG_OCTEP_RDMA_OCTTERM

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/dma-mapping.h>

#include <linux/etherdevice.h>

#include "octep_rdma.h"
#include "octterm_cdev.h"
#include "octep_rdma_netdev.h"
#include "octep_verbs.h"

#define MAC_OFFSET 9

static struct class *octterm_class;
static atomic_t octterm_next_id = ATOMIC_INIT(0);

static int octterm_dev_open(struct inode *inode, struct file *fp)
{
	struct octterm_cdev *odev = container_of(inode->i_cdev,
						 struct octterm_cdev, cdev);
	fp->private_data = odev;
	return 0;
}

static int octterm_dev_release(struct inode *inode, struct file *fp)
{
	struct octterm_cdev *odev = fp->private_data;

	if (!odev)
		return 0;

	/*
	 * RDMA App crashed or exited.  Invalidate the DDR signature so
	 * stale data is never mistaken for a valid capability region.
	 */
	if (odev->ddr_region)
		memset(odev->ddr_region, 0, 8);

	if (odev->ibdev_registered)
		odev->fw_gone = true;

	return 0;
}

static int octterm_dev_mmap(struct file *fp, struct vm_area_struct *vma)
{
	struct octterm_cdev *odev = fp->private_data;
	unsigned long size = vma->vm_end - vma->vm_start;

	if (!odev || !odev->ddr_region)
		return -EINVAL;

	if (size > OCTTERM_DDR_REGION_SIZE)
		return -EINVAL;

	return dma_mmap_coherent(&odev->pdev->dev, vma, odev->ddr_region,
				 odev->ddr_dma_addr, size);
}

/*
 * Deferred FW_READY work handler.
 *
 * Runs outside the ioctl context so the RDMA App is free to poll and
 * respond to mailbox messages while this executes.
 *
 * Steps: signature verify + caps read + mbox init (inside
 * octep_device_caps_read), then allocate netdev, register IBdev,
 * and initialise the management QP netdev.
 */
static void octterm_fw_ready_work_handler(struct work_struct *work)
{
	struct octterm_cdev *odev = container_of(work, struct octterm_cdev,
						 fw_ready_work);
	struct octep_caps_region *caps_rgn = odev->caps_rgn;
	struct pci_dev *pdev = odev->pdev;
	struct octep_rdma_dev *rdma_dev;
	struct octep_ep_dev *octep_dev;
	struct net_device *netdev;
	int ret;

	ret = octep_device_caps_read(caps_rgn, pdev);
	if (ret) {
		dev_err(&pdev->dev, "caps read failed during FW_READY: %d\n", ret);
		goto out;
	}

	/*
	 * Allocate a fresh rdma_dev.  After FW_CLEANUP the previous one
	 * was freed via ib_dealloc_device(); on first boot odev->rdma_dev
	 * is the one from probe -- free it first since ib_register_device
	 * requires a clean ib_device.
	 */
	if (odev->rdma_dev) {
		ib_dealloc_device(&odev->rdma_dev->ibdev);
		odev->rdma_dev = NULL;
		pci_set_drvdata(pdev, NULL);
	}

	rdma_dev = ib_alloc_device(octep_rdma_dev, ibdev);
	if (!rdma_dev) {
		dev_err(&pdev->dev, "ib_alloc_device failed during FW_READY\n");
		goto out;
	}

	rdma_dev->pdev = pdev;
	rdma_dev->dma_dev = &pdev->dev;
	rdma_dev->port.port_num = 0;
	rdma_dev->caps_rgn = caps_rgn;
	rdma_dev->octterm = odev;
	atomic_set(&rdma_dev->status, OCTEP_RDMA_DEV_STATUS_ALLOC);

	odev->rdma_dev = rdma_dev;
	pci_set_drvdata(pdev, rdma_dev);

	netdev = alloc_etherdev_mq(sizeof(struct octep_ep_dev), 1);
	if (!netdev) {
		dev_err(&pdev->dev, "Failed to allocate netdev\n");
		goto err_free_ibdev;
	}
	SET_NETDEV_DEV(netdev, &pdev->dev);

	octep_dev = netdev_priv(netdev);
	octep_dev->netdev = netdev;
	octep_dev->pdev = pdev;

	if (caps_rgn->dev_cfg)
		memcpy(octep_dev->mac_addr,
		       (u8 __iomem *)caps_rgn->dev_cfg + MAC_OFFSET, ETH_ALEN);
	else
		eth_random_addr(octep_dev->mac_addr);

	rdma_dev->octep_dev = octep_dev;
	rdma_dev->netdev = netdev;

	ret = octep_rdma_ib_device_add(rdma_dev);
	if (ret) {
		dev_err(&pdev->dev, "Failed to register ibdev: %d\n", ret);
		goto err_free_netdev;
	}

	ret = octep_rdma_mgmt_qp_netdev_init(rdma_dev, octep_dev, caps_rgn);
	if (ret) {
		dev_err(&pdev->dev, "Failed to init mgmt QP netdev: %d\n", ret);
		goto err_ibdev_remove;
	}

	odev->ibdev_registered = true;
	atomic_set(&rdma_dev->status, OCTEP_RDMA_DEV_STATUS_NETDEV_REG);
	dev_info(&pdev->dev, "OCTTERM: FW_READY complete, IBdev + netdev registered\n");
	return;

err_ibdev_remove:
	octep_rdma_ib_device_remove(rdma_dev);
err_free_netdev:
	rdma_dev->netdev = NULL;
	rdma_dev->octep_dev = NULL;
	free_netdev(netdev);
err_free_ibdev:
	odev->rdma_dev = NULL;
	pci_set_drvdata(pdev, NULL);
	ib_dealloc_device(&rdma_dev->ibdev);
out:
	odev->fw_ready_scheduled = false;
}

static int octterm_ioctl_fw_ready(struct octterm_cdev *odev)
{
	struct pci_dev *pdev = odev->pdev;

	if (odev->ibdev_registered) {
		dev_warn(&pdev->dev, "IBdev already registered\n");
		return -EALREADY;
	}

	if (odev->fw_ready_scheduled) {
		dev_warn(&pdev->dev, "FW_READY already in progress\n");
		return -EALREADY;
	}

	odev->fw_ready_scheduled = true;
	schedule_work(&odev->fw_ready_work);
	dev_info(&pdev->dev, "OCTTERM: FW_READY scheduled\n");

	return 0;
}

/*
 * Firmware-initiated cleanup.  Called via ioctl before the RDMA app
 * exits so the kmod can tear down all IB resources without sending
 * mailbox messages (firmware is about to go away).
 *
 * Full dealloc cycle: ib_unregister_device (triggers IB core cleanup
 * of any remaining user QPs/CQs/PDs) + ib_dealloc_device (frees the
 * rdma_dev).  A subsequent FW_READY will allocate a fresh rdma_dev.
 *
 * Sequence:
 *   1. Set device status to ALLOC so octep_rdma_device_ready() returns
 *      false -- all verbs-layer destroy functions will skip mbox.
 *   2. ib_unregister_device + res_cb_free (IB core cleanup, no mbox).
 *   3. Mgmt QP / netdev cleanup (mbox skipped via device_ready guard).
 *   4. Free netdev.
 *   5. ib_dealloc_device -- frees the rdma_dev structure.
 *   6. Wipe entire DDR region.
 *   7. Reset state for a subsequent FW_READY.
 */
static int octterm_ioctl_fw_cleanup(struct octterm_cdev *odev)
{
	struct octep_rdma_dev *rdma_dev = odev->rdma_dev;
	struct pci_dev *pdev = odev->pdev;
	struct net_device *netdev;

	if (!odev->ibdev_registered) {
		dev_info(&pdev->dev, "OCTTERM: FW_CLEANUP -- IBdev not registered, nothing to do\n");
		return 0;
	}

	dev_info(&pdev->dev, "OCTTERM: FW_CLEANUP -- tearing down IB resources\n");

	atomic_set(&rdma_dev->status, OCTEP_RDMA_DEV_STATUS_ALLOC);

	octep_rdma_ib_device_remove(rdma_dev);

	octep_rdma_mgmt_qp_netdev_cleanup(rdma_dev);

	netdev = rdma_dev->netdev;
	rdma_dev->netdev = NULL;
	rdma_dev->octep_dev = NULL;
	if (netdev)
		free_netdev(netdev);

	ib_dealloc_device(&rdma_dev->ibdev);
	odev->rdma_dev = NULL;
	pci_set_drvdata(pdev, NULL);

	if (odev->ddr_region)
		memset(odev->ddr_region, 0, OCTTERM_DDR_REGION_SIZE);

	odev->ibdev_registered = false;
	odev->fw_ready_scheduled = false;
	odev->fw_gone = false;

	dev_info(&pdev->dev, "OCTTERM: FW_CLEANUP complete, awaiting FW_READY\n");
	return 0;
}

static long octterm_ioctl_get_dma_vf_id(struct octterm_cdev *odev, unsigned long arg)
{
	if (copy_to_user((void __user *)arg, &odev->dma_vf_id,
			 sizeof(odev->dma_vf_id)))
		return -EFAULT;

	return 0;
}

static long octterm_ioctl_get_max_vfs(unsigned long arg)
{
	__u32 max_vfs = OCTTERM_MAX_VFS;

	if (copy_to_user((void __user *)arg, &max_vfs, sizeof(max_vfs)))
		return -EFAULT;

	return 0;
}

static long octterm_ioctl_get_mem_size(unsigned long arg)
{
	__u64 size = OCTTERM_DDR_REGION_SIZE;

	if (copy_to_user((void __user *)arg, &size, sizeof(size)))
		return -EFAULT;

	return 0;
}

static long octterm_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	struct octterm_cdev *odev = fp->private_data;

	if (!odev)
		return -EINVAL;

	switch (cmd) {
	case OCTTERM_IOC_GET_MEM_SIZE:
		return octterm_ioctl_get_mem_size(arg);
	case OCTTERM_IOC_GET_DMA_VF_ID:
		return octterm_ioctl_get_dma_vf_id(odev, arg);
	case OCTTERM_IOC_GET_MAX_VFS:
		return octterm_ioctl_get_max_vfs(arg);
	case OCTTERM_IOC_FW_READY:
		return octterm_ioctl_fw_ready(odev);
	case OCTTERM_IOC_FW_CLEANUP:
		return octterm_ioctl_fw_cleanup(odev);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations octterm_fops = {
	.owner          = THIS_MODULE,
	.open           = octterm_dev_open,
	.release        = octterm_dev_release,
	.mmap           = octterm_dev_mmap,
	.unlocked_ioctl = octterm_dev_ioctl,
	.compat_ioctl   = octterm_dev_ioctl,
};

int octterm_cdev_init(struct octterm_cdev *odev, struct pci_dev *pdev,
		      struct octep_rdma_dev *rdma_dev,
		      struct octep_caps_region *caps_rgn)
{
	int ret;

	odev->pdev = pdev;
	odev->rdma_dev = rdma_dev;
	odev->caps_rgn = caps_rgn;
	/* PCI devfn: (device << 3) | function — not bus; see OCTTERM_IOC_GET_DMA_VF_ID */
	odev->dma_vf_id = pdev->devfn;
	odev->ibdev_registered = false;
	odev->fw_ready_scheduled = false;
	odev->fw_gone = false;
	INIT_WORK(&odev->fw_ready_work, octterm_fw_ready_work_handler);

	/* Allocate 64MB DDR region with BAR4-identical layout */
	odev->ddr_region = dma_alloc_coherent(&pdev->dev, OCTTERM_DDR_REGION_SIZE,
					      &odev->ddr_dma_addr, GFP_KERNEL);
	if (!odev->ddr_region)
		return -ENOMEM;

	memset(odev->ddr_region, 0, OCTTERM_DDR_REGION_SIZE);

	/*
	 * Point caps_rgn BAR4 base at the DDR kernel VA so all existing
	 * BAR4-walking code (signature verify, caps read, mbox) works
	 * transparently via the octep_plat_* read/write helpers.
	 */
	caps_rgn->base[OCTEP_HW_MBOX_BAR] = (u8 __iomem *)odev->ddr_region;
	caps_rgn->ddr_coherent_va = odev->ddr_region;
	caps_rgn->ddr_coherent_dma = odev->ddr_dma_addr;

	odev->instance_id = atomic_fetch_add(1, &octterm_next_id);

	/* Register character device */
	ret = alloc_chrdev_region(&odev->devno, 0, 1, "octterm");
	if (ret) {
		dev_err(&pdev->dev, "alloc_chrdev_region failed: %d\n", ret);
		goto err_free_ddr;
	}

	cdev_init(&odev->cdev, &octterm_fops);
	odev->cdev.owner = THIS_MODULE;
	ret = cdev_add(&odev->cdev, odev->devno, 1);
	if (ret) {
		dev_err(&pdev->dev, "cdev_add failed: %d\n", ret);
		goto err_unreg_chrdev;
	}

	odev->cdev_device = device_create(octterm_class, &pdev->dev,
					  odev->devno, NULL, "octterm%d",
					  odev->instance_id);
	if (IS_ERR(odev->cdev_device)) {
		ret = PTR_ERR(odev->cdev_device);
		dev_err(&pdev->dev, "device_create failed: %d\n", ret);
		goto err_cdev_del;
	}

	dev_info(&pdev->dev,
		 "OCTTERM cdev registered: DDR %pK (DMA base 0x%llx), size %lu MB\n",
		 odev->ddr_region, (u64)odev->ddr_dma_addr, OCTTERM_DDR_REGION_SIZE >> 20);

	return 0;

err_cdev_del:
	cdev_del(&odev->cdev);
err_unreg_chrdev:
	unregister_chrdev_region(odev->devno, 1);
err_free_ddr:
	caps_rgn->base[OCTEP_HW_MBOX_BAR] = NULL;
	caps_rgn->ddr_coherent_va = NULL;
	caps_rgn->ddr_coherent_dma = 0;
	dma_free_coherent(&pdev->dev, OCTTERM_DDR_REGION_SIZE,
			  odev->ddr_region, odev->ddr_dma_addr);
	odev->ddr_region = NULL;
	return ret;
}

void octterm_cdev_destroy(struct octterm_cdev *odev)
{
	if (!odev)
		return;

	cancel_work_sync(&odev->fw_ready_work);

	if (odev->cdev_device) {
		device_destroy(octterm_class, odev->devno);
		odev->cdev_device = NULL;
	}

	cdev_del(&odev->cdev);
	unregister_chrdev_region(odev->devno, 1);

	if (odev->ddr_region) {
		if (odev->caps_rgn) {
			odev->caps_rgn->base[OCTEP_HW_MBOX_BAR] = NULL;
			odev->caps_rgn->ddr_coherent_va = NULL;
			odev->caps_rgn->ddr_coherent_dma = 0;
		}
		dma_free_coherent(&odev->pdev->dev, OCTTERM_DDR_REGION_SIZE,
				  odev->ddr_region, odev->ddr_dma_addr);
		odev->ddr_region = NULL;
	}
}

int octterm_class_init(void)
{
	octterm_class = class_create("octterm");
	if (IS_ERR(octterm_class)) {
		int ret = PTR_ERR(octterm_class);

		octterm_class = NULL;
		pr_err("octterm: class_create failed: %d\n", ret);
		return ret;
	}
	return 0;
}

void octterm_class_exit(void)
{
	if (octterm_class) {
		class_destroy(octterm_class);
		octterm_class = NULL;
	}
}

#endif /* CONFIG_OCTEP_RDMA_OCTTERM */
