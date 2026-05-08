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

/* Maximum number of CXL PCI functions we will service. */
#define OCTEP_MAX_CXL_PCI 4

/* Resource divisor for splitting the MSI-X vectors and BAR4 among devices. */
#define ILIAD_RESOURCE_DIVISOR(n) ((n) > 2 ? 4 : (n))

static struct platform_device *octep_plat[OCTEP_MAX_CXL_PCI][OCTEP_PLAT_MAX_DEVICES];

/* Verify BAR4 firmware signature and read parameters. */
static int octep_cxl_quirk_verify_fw_ready(struct pci_dev *pdev, u32 *per_dev_bar4_sz, int *max_vfs)
{
	resource_size_t bar4_total;
	void __iomem *bar4_map;
	u32 sig[4];

	bar4_total = pci_resource_len(pdev, 4);
	if (!bar4_total) {
		dev_warn(&pdev->dev, "CXL device does not have BAR4\n");
		return -ENODEV;
	}

	/* Read the firmware signature and parameters from BAR4. */
	bar4_map = ioremap(pci_resource_start(pdev, 4), 16);
	if (!bar4_map) {
		dev_warn(&pdev->dev, "Failed to ioremap BAR4 for signature read\n");
		return -ENOMEM;
	}

	sig[0] = ioread32(bar4_map + 0);
	sig[1] = ioread32(bar4_map + 4);
	sig[2] = ioread32(bar4_map + 8);
	sig[3] = ioread32(bar4_map + 12);
	iounmap(bar4_map);

	if (sig[0] != OCTEP_FW_READY_SIG0 || sig[1] != OCTEP_FW_READY_SIG1) {
		dev_warn(&pdev->dev, "BAR4 signature mismatch (0x%08x 0x%08x); is app running?\n",
			 sig[0], sig[1]);
		return -ENODEV;
	}

	*per_dev_bar4_sz = sig[2];
	*max_vfs = (int)sig[3];

	if (!*per_dev_bar4_sz || (bar4_total % *per_dev_bar4_sz) != 0) {
		dev_warn(&pdev->dev, "Invalid per-device BAR4 size %u (total %llu)\n",
			 *per_dev_bar4_sz, (unsigned long long)bar4_total);
		return -EINVAL;
	}

	if (!*max_vfs || *max_vfs > OCTEP_PLAT_MAX_DEVICES) {
		dev_warn(&pdev->dev, "Invalid max_vfs %d from BAR4 signature\n", *max_vfs);
		return -EINVAL;
	}

	return 0;
}

static void octep_cxl_quirk_unregister_pci(int pci_idx)
{
	int i;

	for (i = OCTEP_PLAT_MAX_DEVICES - 1; i >= 0; i--) {
		if (!IS_ERR_OR_NULL(octep_plat[pci_idx][i])) {
			dev_info(&octep_plat[pci_idx][i]->dev, "Unregistering %s.%d\n",
				 OCTEP_VDPA_PLAT_NAME, octep_plat[pci_idx][i]->id);
			platform_device_unregister(octep_plat[pci_idx][i]);
			octep_plat[pci_idx][i] = NULL;
		}
	}
}

/* Register one set of vDPA platform devices for a single CXL PCI function.
 * Returns 0 on success, negative errno on failure (in which case any partial
 * registrations made for this pdev are rolled back).
 */
static int octep_cxl_quirk_register_pci(struct pci_dev *pdev, int pci_idx)
{
	int max_vfs, rsrc_div, vecs_per_dev;
	int dev_idx, res_idx, irq;
	struct resource res[10];
	u32 per_dev_bar4_sz;
	int i, rc;

	if (!pdev->msix_enabled || pci_msix_vec_count(pdev) <= 0) {
		dev_warn(&pdev->dev, "MSI-X not enabled or no vectors\n");
		return -ENODEV;
	}

	rc = octep_cxl_quirk_verify_fw_ready(pdev, &per_dev_bar4_sz, &max_vfs);
	if (rc)
		return rc;

	rsrc_div = ILIAD_RESOURCE_DIVISOR(max_vfs);
	vecs_per_dev = OCTEP_MSIX_VEC_COUNT / rsrc_div;

	dev_info(&pdev->dev,
		 "BAR4 signature OK: per_dev_sz=%u max_vfs=%d rsrc_div=%d vecs_per_dev=%d\n",
		 per_dev_bar4_sz, max_vfs, rsrc_div, vecs_per_dev);

	for (dev_idx = 0; dev_idx < max_vfs; dev_idx++) {
		int plat_id = pci_idx * OCTEP_PLAT_MAX_DEVICES + dev_idx;

		memset(res, 0, sizeof(res));
		res_idx = 0;

		/* MSIX vectors for this device */
		for (i = 0; i < vecs_per_dev; i++) {
			int vec = OCTEP_MSIX_VEC_BASE + dev_idx * vecs_per_dev + i;

			irq = pci_irq_vector(pdev, vec);
			if (irq <= 0 || irq_has_action(irq)) {
				dev_warn(&pdev->dev,
					 "MSI-X vector %d not available for device %d\n", vec,
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

		octep_plat[pci_idx][dev_idx] = platform_device_register_simple(
			OCTEP_VDPA_PLAT_NAME, plat_id, res, res_idx);
		if (IS_ERR(octep_plat[pci_idx][dev_idx])) {
			rc = PTR_ERR(octep_plat[pci_idx][dev_idx]);
			dev_warn(&pdev->dev, "Failed to register platform device %d.%d: %d\n",
				 pci_idx, dev_idx, rc);
			octep_plat[pci_idx][dev_idx] = NULL;
			goto unregister;
		}
		octep_plat[pci_idx][dev_idx]->dev.parent = &pdev->dev;
		dev_info(&pdev->dev, "Registered %s.%d\n", OCTEP_VDPA_PLAT_NAME, plat_id);
	}

	return 0;

unregister:
	octep_cxl_quirk_unregister_pci(pci_idx);
	return rc;
}

static int __init octep_cxl_quirk_init(void)
{
	struct pci_dev *pdev = NULL;
	int pci_idx = 0;
	int n_success = 0;
	int rc;

	while ((pdev = pci_get_device(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_CAVIUM_CXL, pdev))) {
		if (pci_idx >= OCTEP_MAX_CXL_PCI) {
			dev_warn(&pdev->dev,
				 "Reached OCTEP_MAX_CXL_PCI=%d; skipping further CXL devices\n",
				 OCTEP_MAX_CXL_PCI);
			pci_dev_put(pdev);
			break;
		}

		rc = octep_cxl_quirk_register_pci(pdev, pci_idx);
		if (rc)
			dev_warn(&pdev->dev, "Skipping CXL device %d (error %d)\n", pci_idx, rc);
		else
			n_success++;

		pci_idx++;
	}

	if (pci_idx == 0) {
		pr_err("No CXL PCI device found\n");
		return -ENODEV;
	}

	if (!n_success) {
		pr_err("Found %d CXL PCI device(s) but none could be registered\n", pci_idx);
		return -ENODEV;
	}

	pr_info("Registered platform devices for %d/%d CXL PCI device(s)\n", n_success, pci_idx);
	return 0;
}

static void __exit octep_cxl_quirk_exit(void)
{
	int pci_idx;

	for (pci_idx = OCTEP_MAX_CXL_PCI - 1; pci_idx >= 0; pci_idx--)
		octep_cxl_quirk_unregister_pci(pci_idx);
}

module_init(octep_cxl_quirk_init);
module_exit(octep_cxl_quirk_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Module to register Octeon EP vDPA platform devices for CXL");
