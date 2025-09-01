/* SPDX-License-Identifier: GPL-2.0
 * Iliad Platform Device Driver with Character Device Interface
 * Copyright (c) 2025 Marvell.
 */

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#define DRIVER_NAME "iliad_cdev"
#define DEVICE_NAME "iliad_cdev"

/* PEM BAR4 configuration registers */
#define PEM_BAR4_INDEX_START 0
#define PEM_BAR4_INDEX_END 15 /* 16 indices total */
#define PEM_BAR4_INDEX_SIZE (1ULL << 22) /* 4MB per index */
#define PEM_BAR4_TOTAL_SIZE ((PEM_BAR4_INDEX_END - PEM_BAR4_INDEX_START + 1) * PEM_BAR4_INDEX_SIZE)

/* PEM register offsets */
#define PEM_BAR4_INDEX(i) (0x700ull | ((i) << 3))
#define PEM_BAR4_INDEX_ADDR_IDX(addr) ((addr) << 4)
#define PEM_BAR4_INDEX_ADDR_V BIT_ULL(0)
#define PEM_DIS_PORT (0x50ull)

struct iliad_device {
	struct platform_device *pdev;
	struct cdev cdev;
	struct class *class;
	struct device *device;
	dev_t devt;

	/* Platform device memory regions */
	void __iomem *pem_base; /* Memory region 0 - PEM registers */
	void __iomem *odm_base; /* Memory region 1 - ODM PF space */
	resource_size_t pem_size;
	resource_size_t odm_size;

	/* BAR4 memory allocation */
	void *bar4_virt;
	dma_addr_t bar4_dma;
	size_t bar4_size;
};

static int iliad_configure_bar4(struct iliad_device *idev)
{
	int i, ret = 0;
	u64 reg_val;

	dev_info(&idev->pdev->dev, "Configuring PEM BAR4 registers (indices %d to %d)\n",
		 PEM_BAR4_INDEX_START, PEM_BAR4_INDEX_END);

	for (i = PEM_BAR4_INDEX_START; i <= PEM_BAR4_INDEX_END; i++) {
		u64 bar4_iova = idev->bar4_dma + (i * PEM_BAR4_INDEX_SIZE);

		reg_val = PEM_BAR4_INDEX_ADDR_IDX(bar4_iova >> 22) | PEM_BAR4_INDEX_ADDR_V;

		dev_dbg(&idev->pdev->dev,
			"Writing BAR4 index %d: offset=0x%llx reg_val=0x%llx "
			"(bar4_iova=0x%llx)\n",
			i, PEM_BAR4_INDEX(i), reg_val, bar4_iova);

		writeq(reg_val, idev->pem_base + PEM_BAR4_INDEX(i));
	}

	/* Enable PEM port */
	writeq(1, idev->pem_base + PEM_DIS_PORT);

	dev_info(&idev->pdev->dev, "PEM BAR4 configuration completed successfully\n");
	return ret;
}

static void iliad_disable_bar4(struct iliad_device *idev)
{
	int i;

	dev_info(&idev->pdev->dev, "Disabling PEM BAR4 registers (indices %d to %d)\n",
		 PEM_BAR4_INDEX_START, PEM_BAR4_INDEX_END);

	/* Disable PEM port first to stop hardware transactions */
	writeq(0, idev->pem_base + PEM_DIS_PORT);

	/* Clear BAR4 index registers to invalidate hardware mappings */
	for (i = PEM_BAR4_INDEX_START; i <= PEM_BAR4_INDEX_END; i++) {
		dev_dbg(&idev->pdev->dev, "Clearing BAR4 index %d: offset=0x%llx\n", i,
			PEM_BAR4_INDEX(i));
		writeq(0, idev->pem_base + PEM_BAR4_INDEX(i));
	}

	dev_info(&idev->pdev->dev, "PEM BAR4 disabled successfully\n");
}

static int iliad_open(struct inode *inode, struct file *file)
{
	struct iliad_device *idev = container_of(inode->i_cdev, struct iliad_device, cdev);

	file->private_data = idev;
	dev_dbg(&idev->pdev->dev, "Character device opened\n");
	return 0;
}

static int iliad_release(struct inode *inode, struct file *file)
{
	struct iliad_device *idev = file->private_data;

	dev_dbg(&idev->pdev->dev, "Character device released\n");
	return 0;
}

static int iliad_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct iliad_device *idev = file->private_data;
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	unsigned long size = vma->vm_end - vma->vm_start;
	resource_size_t phys_addr;
	int ret;

	dev_dbg(&idev->pdev->dev, "mmap: offset=0x%lx size=0x%lx\n", offset, size);

	/* Use vm_pgoff to determine which memory region to map. 0 = BAR4, 1 = ODM PF */
	if (vma->vm_pgoff == 0) {
		if (size > idev->bar4_size) {
			dev_err(&idev->pdev->dev,
				"mmap: BAR4 size too large (requested: 0x%lx, available: 0x%lx)\n",
				size, idev->bar4_size);
			return -EINVAL;
		}

		phys_addr = idev->bar4_dma;
		dev_info(&idev->pdev->dev, "Mapping BAR4 memory: phys=0x%llx size=0x%lx\n",
			 (u64)phys_addr, size);
	} else if (vma->vm_pgoff == 1) {
		struct resource *odm_res;

		if (size > idev->odm_size) {
			dev_err(&idev->pdev->dev,
				"mmap: ODM size too large (requested: 0x%lx, available: 0x%llx)\n",
				size, (u64)idev->odm_size);
			return -EINVAL;
		}

		/* Get ODM PF physical address from platform device resource 1 */
		odm_res = platform_get_resource(idev->pdev, IORESOURCE_MEM, 1);
		if (!odm_res) {
			dev_err(&idev->pdev->dev, "Failed to get ODM resource for mmap\n");
			return -ENODEV;
		}

		phys_addr = odm_res->start;
		dev_info(&idev->pdev->dev, "Mapping ODM PF memory: phys=0x%llx size=0x%lx\n",
			 (u64)phys_addr, size);
	} else {
		dev_err(&idev->pdev->dev, "Invalid mmap offset: pgoff=%lu\n", vma->vm_pgoff);
		return -EINVAL;
	}

	/* Set up memory mapping attributes */
	if (vma->vm_pgoff == 0) {
		/* BAR4 memory - Iliad DRAM accessible via PCIe
		 * Cache coherency assumptions:
		 * - PCIe writes to BAR4 will invalidate CPU cache lines
		 * - PCIe reads from BAR4 will see latest data (cache flushed if needed)
		 * - ARM64 hardware cache coherency protocol handles CPU<->PCIe ordering
		 */
		vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP | VM_DONTCOPY);
		/* Keep default caching for DRAM */
	} else {
		/* ODM PF memory - Hardware registers */
		vm_flags_set(vma, VM_IO | VM_DONTEXPAND | VM_DONTDUMP | VM_DONTCOPY);
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	}

	ret = remap_pfn_range(vma, vma->vm_start, phys_addr >> PAGE_SHIFT, size, vma->vm_page_prot);
	if (ret) {
		dev_err(&idev->pdev->dev, "remap_pfn_range failed: %d\n", ret);
		return ret;
	}

	dev_info(&idev->pdev->dev, "mmap successful: virt=0x%lx phys=0x%llx size=0x%lx\n",
		 vma->vm_start, (u64)phys_addr, size);
	return 0;
}

static const struct file_operations iliad_fops = {
	.owner = THIS_MODULE,
	.open = iliad_open,
	.release = iliad_release,
	.mmap = iliad_mmap,
};

static int iliad_create_chardev(struct iliad_device *idev)
{
	int ret;

	ret = alloc_chrdev_region(&idev->devt, 0, 1, DEVICE_NAME);
	if (ret) {
		dev_err(&idev->pdev->dev, "Failed to allocate character device number: %d\n", ret);
		return ret;
	}

	cdev_init(&idev->cdev, &iliad_fops);
	idev->cdev.owner = THIS_MODULE;

	ret = cdev_add(&idev->cdev, idev->devt, 1);
	if (ret) {
		dev_err(&idev->pdev->dev, "Failed to add character device: %d\n", ret);
		goto err_unregister_chrdev;
	}

	idev->class = class_create(DEVICE_NAME);
	if (IS_ERR(idev->class)) {
		ret = PTR_ERR(idev->class);
		dev_err(&idev->pdev->dev, "Failed to create device class: %d\n", ret);
		goto err_cdev_del;
	}

	idev->device = device_create(idev->class, &idev->pdev->dev, idev->devt, idev, DEVICE_NAME);
	if (IS_ERR(idev->device)) {
		ret = PTR_ERR(idev->device);
		dev_err(&idev->pdev->dev, "Failed to create device: %d\n", ret);
		goto err_class_destroy;
	}

	dev_info(&idev->pdev->dev, "Character device created: /dev/%s (major=%d, minor=%d)\n",
		 DEVICE_NAME, MAJOR(idev->devt), MINOR(idev->devt));

	return 0;

err_class_destroy:
	class_destroy(idev->class);
err_cdev_del:
	cdev_del(&idev->cdev);
err_unregister_chrdev:
	unregister_chrdev_region(idev->devt, 1);
	return ret;
}

static void iliad_destroy_chardev(struct iliad_device *idev)
{
	if (idev->device) {
		device_destroy(idev->class, idev->devt);
		idev->device = NULL;
	}

	if (idev->class) {
		class_destroy(idev->class);
		idev->class = NULL;
	}

	cdev_del(&idev->cdev);
	unregister_chrdev_region(idev->devt, 1);

	dev_info(&idev->pdev->dev, "Character device destroyed\n");
}

static int iliad_probe(struct platform_device *pdev)
{
	struct iliad_device *idev;
	struct resource *res;
	int ret;

	dev_info(&pdev->dev, "Probing Iliad platform device\n");

	idev = devm_kzalloc(&pdev->dev, sizeof(*idev), GFP_KERNEL);
	if (!idev)
		return -ENOMEM;

	idev->pdev = pdev;
	platform_set_drvdata(pdev, idev);

	/* Map PEM register space (memory region 0) */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev, "Failed to get PEM memory resource 0\n");
		return -ENODEV;
	}

	idev->pem_base = devm_ioremap(&pdev->dev, res->start, resource_size(res));
	if (!idev->pem_base) {
		dev_err(&pdev->dev, "Failed to map PEM registers\n");
		return -ENOMEM;
	}
	idev->pem_size = resource_size(res);

	dev_info(&pdev->dev, "PEM registers mapped: phys=0x%llx virt=%p size=0x%llx\n",
		 (u64)res->start, idev->pem_base, (u64)idev->pem_size);

	/* Map ODM PF space (memory region 1) */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!res) {
		dev_err(&pdev->dev, "Failed to get ODM memory resource 1\n");
		return -ENODEV;
	}

	idev->odm_base = devm_ioremap(&pdev->dev, res->start, resource_size(res));
	if (!idev->odm_base) {
		dev_err(&pdev->dev, "Failed to map ODM registers\n");
		return -ENOMEM;
	}
	idev->odm_size = resource_size(res);

	dev_info(&pdev->dev, "ODM registers mapped: phys=0x%llx virt=%p size=0x%llx\n",
		 (u64)res->start, idev->odm_base, (u64)idev->odm_size);

	idev->bar4_size = PEM_BAR4_TOTAL_SIZE;
	idev->bar4_virt =
		dma_alloc_coherent(&pdev->dev, idev->bar4_size, &idev->bar4_dma, GFP_KERNEL);
	if (!idev->bar4_virt) {
		dev_err(&pdev->dev, "Failed to allocate BAR4 memory (size: 0x%lx)\n",
			idev->bar4_size);
		return -ENOMEM;
	}

	dev_info(&pdev->dev, "BAR4 memory allocated: virt=%p dma=0x%llx size=0x%lx\n",
		 idev->bar4_virt, (u64)idev->bar4_dma, idev->bar4_size);

	ret = iliad_configure_bar4(idev);
	if (ret) {
		dev_err(&pdev->dev, "Failed to configure BAR4: %d\n", ret);
		goto err_free_bar4;
	}

	ret = iliad_create_chardev(idev);
	if (ret) {
		dev_err(&pdev->dev, "Failed to create character device: %d\n", ret);
		goto err_disable_bar4;
	}

	dev_info(&pdev->dev, "Iliad platform device probed successfully\n");
	dev_info(&pdev->dev, "Usage:\n");
	dev_info(&pdev->dev, "  mmap with offset 0: maps BAR4 memory (0x%lx bytes)\n",
		 idev->bar4_size);
	dev_info(&pdev->dev, "  mmap with offset 1: maps ODM PF memory (0x%llx bytes)\n",
		 (u64)idev->odm_size);

	return 0;

err_disable_bar4:
	iliad_disable_bar4(idev);
err_free_bar4:
	dma_free_coherent(&pdev->dev, idev->bar4_size, idev->bar4_virt, idev->bar4_dma);
	return ret;
}

static int iliad_remove(struct platform_device *pdev)
{
	struct iliad_device *idev = platform_get_drvdata(pdev);

	dev_info(&pdev->dev, "Removing Iliad platform device\n");

	iliad_destroy_chardev(idev);

	/* Disable hardware configuration before freeing DMA memory to prevent
	 * hardware from accessing freed memory
	 */
	if (idev->bar4_virt) {
		iliad_disable_bar4(idev);
		dma_free_coherent(&pdev->dev, idev->bar4_size, idev->bar4_virt, idev->bar4_dma);
	}

	dev_info(&pdev->dev, "Iliad platform device removed\n");
	return 0;
}

static const struct of_device_id iliad_of_match[] = {
	{ .compatible = "marvell,iliad-epf0", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, iliad_of_match);

static const struct platform_device_id iliad_platform_ids[] = {
	{ .name = "MRVL0012:00", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(platform, iliad_platform_ids);

static struct platform_driver iliad_driver = {
	.driver = {
		.name = DRIVER_NAME,
		.of_match_table = iliad_of_match,
	},
	.probe = iliad_probe,
	.remove = iliad_remove,
	.id_table = iliad_platform_ids,
};

module_platform_driver(iliad_driver);

MODULE_DESCRIPTION("Iliad Platform Device Driver with Character Device Interface");
MODULE_AUTHOR("Marvell");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:MRVL0012:00");
