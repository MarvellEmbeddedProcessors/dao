/* SPDX-License-Identifier: GPL-2.0
 * Iliad Platform Device Driver with Character Device Interface
 * Copyright (c) 2026 Marvell.
 */

#include <linux/init.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#define PCI_DEVICE_ID_CAVIUM_CXL 0xc1e1
#define OCTEP_VDPA_PLAT_NAME "octep_vdpa_plat"

/* Vectors 8-15: 8 vectors for up to OCTEP_PLAT_MAX_DEVICES */
#define OCTEP_MSIX_VEC_BASE 8
#define OCTEP_MSIX_VEC_COUNT 8

/* BAR4 signature magic values written by the board application */
#define OCTEP_FW_READY_SIG0 0xfeedfeed
#define OCTEP_FW_READY_SIG1 0x3355ffaa

#define OCTEP_PLAT_MAX_DEVICES 4

/* Resource divisor for splitting the MSI-X vectors and BAR4 among devices. */
#define ILIAD_RESOURCE_DIVISOR(n) ((n) > 2 ? 4 : (n))

static struct platform_device *octep_plat[OCTEP_PLAT_MAX_DEVICES];

/* Verify BAR4 firmware signature and read parameters. */
static int octep_cxl_quirk_verify_fw_ready(struct pci_dev *pdev, u32 *per_dev_bar4_sz, int *max_vfs)
{
	resource_size_t bar4_total;
	void __iomem *bar4_map;
	u32 sig[4];

	bar4_total = pci_resource_len(pdev, 4);
	if (!bar4_total) {
		pr_err("CXL device does not have BAR4\n");
		return -ENODEV;
	}

	/* Read the firmware signature and parameters from BAR4. */
	bar4_map = ioremap(pci_resource_start(pdev, 4), 16);
	if (!bar4_map) {
		pr_err("Failed to ioremap BAR4 for signature read\n");
		return -ENOMEM;
	}

	sig[0] = ioread32(bar4_map + 0);
	sig[1] = ioread32(bar4_map + 4);
	sig[2] = ioread32(bar4_map + 8);
	sig[3] = ioread32(bar4_map + 12);
	iounmap(bar4_map);

	if (sig[0] != OCTEP_FW_READY_SIG0 || sig[1] != OCTEP_FW_READY_SIG1) {
		pr_err("BAR4 signature mismatch (0x%08x 0x%08x); is app running?\n", sig[0],
		       sig[1]);
		return -ENODEV;
	}

	*per_dev_bar4_sz = sig[2];
	*max_vfs = (int)sig[3];

	if (!*per_dev_bar4_sz || (bar4_total % *per_dev_bar4_sz) != 0) {
		pr_err("Invalid per-device BAR4 size %u (total %llu)\n", *per_dev_bar4_sz,
		       (unsigned long long)bar4_total);
		return -EINVAL;
	}

	if (!*max_vfs || *max_vfs > OCTEP_PLAT_MAX_DEVICES) {
		pr_err("Invalid max_vfs %d from BAR4 signature\n", *max_vfs);
		return -EINVAL;
	}

	return 0;
}

static int __init octep_cxl_quirk_init(void)
{
	int max_vfs, rsrc_div, vecs_per_dev;
	struct pci_dev *pdev = NULL;
	int dev_idx, res_idx, irq;
	struct resource res[10];
	u32 per_dev_bar4_sz;
	int i, rc = 0;

	pdev = pci_get_device(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_CAVIUM_CXL, NULL);
	if (!pdev) {
		pr_err("CXL PCI device not found\n");
		return -ENODEV;
	}

	if (!pdev->msix_enabled || pci_msix_vec_count(pdev) <= 0) {
		pr_err("CXL device does not support MSI-X or has no vectors\n");
		rc = -ENODEV;
		goto put_dev;
	}

	rc = octep_cxl_quirk_verify_fw_ready(pdev, &per_dev_bar4_sz, &max_vfs);
	if (rc)
		goto put_dev;

	rsrc_div = ILIAD_RESOURCE_DIVISOR(max_vfs);
	vecs_per_dev = OCTEP_MSIX_VEC_COUNT / rsrc_div;

	dev_info(&pdev->dev,
		 "BAR4 signature OK: per_dev_sz=%u max_vfs=%d rsrc_div=%d vecs_per_dev=%d\n",
		 per_dev_bar4_sz, max_vfs, rsrc_div, vecs_per_dev);

	/* Register one platform device per virtual device */
	for (dev_idx = 0; dev_idx < max_vfs; dev_idx++) {
		memset(res, 0, sizeof(res));
		res_idx = 0;

		/* MSIX vectors for this device */
		for (i = 0; i < vecs_per_dev; i++) {
			int vec = OCTEP_MSIX_VEC_BASE + dev_idx * vecs_per_dev + i;

			irq = pci_irq_vector(pdev, vec);
			if (irq <= 0 || irq_has_action(irq)) {
				pr_err("MSI-X vector %d not available for device %d\n", vec,
				       dev_idx);
				rc = -ENODEV;
				goto unregister;
			}
			res[res_idx].start = irq;
			res[res_idx].end = irq;
			res[res_idx].flags = IORESOURCE_IRQ;
			res_idx++;
		}

		/* Per-device BAR4 slice */
		res[res_idx].start =
			pci_resource_start(pdev, 4) + (resource_size_t)dev_idx * per_dev_bar4_sz;
		res[res_idx].end = res[res_idx].start + per_dev_bar4_sz - 1;
		res[res_idx].flags = IORESOURCE_MEM;
		dev_info(&pdev->dev, "Device %d BAR4 slice: start=0x%llx end=0x%llx\n", dev_idx,
			 (unsigned long long)res[res_idx].start,
			 (unsigned long long)res[res_idx].end);
		res_idx++;

		octep_plat[dev_idx] = platform_device_register_simple(OCTEP_VDPA_PLAT_NAME, dev_idx,
								      res, res_idx);
		if (IS_ERR(octep_plat[dev_idx])) {
			rc = PTR_ERR(octep_plat[dev_idx]);
			pr_err("Failed to register platform device %d: %d\n", dev_idx, rc);
			octep_plat[dev_idx] = NULL;
			goto unregister;
		}
		octep_plat[dev_idx]->dev.parent = &pdev->dev;
		dev_info(&pdev->dev, "Registered %s.%d\n", OCTEP_VDPA_PLAT_NAME, dev_idx);
	}

	pci_dev_put(pdev);
	return 0;

unregister:
	for (i = dev_idx - 1; i >= 0; i--) {
		if (!IS_ERR_OR_NULL(octep_plat[i])) {
			platform_device_unregister(octep_plat[i]);
			octep_plat[i] = NULL;
		}
	}
put_dev:
	pci_dev_put(pdev);
	return rc;
}

static void __exit octep_cxl_quirk_exit(void)
{
	int dev_idx;

	for (dev_idx = OCTEP_PLAT_MAX_DEVICES - 1; dev_idx >= 0; dev_idx--) {
		if (!IS_ERR_OR_NULL(octep_plat[dev_idx])) {
			dev_info(&octep_plat[dev_idx]->dev, "Unregistering %s.%d\n",
				 OCTEP_VDPA_PLAT_NAME, dev_idx);
			platform_device_unregister(octep_plat[dev_idx]);
			octep_plat[dev_idx] = NULL;
		}
	}
}

module_init(octep_cxl_quirk_init);
module_exit(octep_cxl_quirk_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Module to register Octeon EP vDPA platform devices for CXL");
