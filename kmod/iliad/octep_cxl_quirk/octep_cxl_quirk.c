#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#define PCI_DEVICE_ID_CAVIUM_CXL 0xc1e1
#define CXL_BAR0_ODM_OFFSET 0x100000
#define OCTEP_VDPA_PLAT_NAME "octep_vdpa_plat"
#define OCTEP_MSIX_VEC_ENA_MASK 0xFF00 /* Vectors 8-15 */

static struct platform_device *octep_plat;

static int octep_plat_setup_mem(struct pci_dev *pdev, int bar, struct resource *res)
{
	if (!pci_resource_len(pdev, bar)) {
		pr_err("CXL device does not have BAR%d\n", bar);
		return -ENODEV;
	}

	if (bar == 0) {
		res->start = pci_resource_start(pdev, bar) + CXL_BAR0_ODM_OFFSET;
		res->end = res->start + 0x200 - 1; /* 512B for BAR0 */
	} else {
		res->start = pci_resource_start(pdev, bar);
		res->end = res->start + pci_resource_len(pdev, bar) - 1;
	}
	res->flags = IORESOURCE_MEM;

	dev_info(&pdev->dev, "Setting up BAR%d resource: start=0x%llx, end=0x%llx\n", bar,
		 (unsigned long long)res->start, (unsigned long long)res->end);
	return 0;
}

static int __init octep_cxl_quirk_init(void)
{
	uint8_t max_vec, vec_count, res_idx = 0;
	struct pci_dev *pdev = NULL;
	int nvec, irq, i, rc = 0;
	struct resource *res;

	pdev = pci_get_device(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_CAVIUM_CXL, NULL);
	if (!pdev) {
		pr_err("CXL PCI device not found\n");
		return -ENODEV;
	}

	/* IRQ vectors and 2 MEM resources (BAR0 and BAR4) */
	max_vec = fls(OCTEP_MSIX_VEC_ENA_MASK) - 1;
	vec_count = hweight16(OCTEP_MSIX_VEC_ENA_MASK);
	res = kcalloc(vec_count + 2, sizeof(*res), GFP_KERNEL);
	if (!res) {
		pr_err("Failed to allocate memory for resources\n");
		rc = -ENOMEM;
		goto put_dev;
	}

	nvec = pci_msix_vec_count(pdev);
	if (!pdev->msix_enabled || nvec <= 0) {
		rc = -ENODEV;
		pr_err("CXL device does not support MSI-X or has no vectors\n");
		goto exit;
	}

	/* Set up resources for MSI-X vectors */
	for (i = 0; i <= max_vec; i++) {
		if (!((1 << i) & OCTEP_MSIX_VEC_ENA_MASK))
			continue;

		irq = pci_irq_vector(pdev, i);
		if (irq <= 0 || irq_has_action(irq)) {
			rc = -ENODEV;
			pr_err("CXL device MSI-X vector %d is not available\n", i);
			goto exit;
		}

		res[res_idx].start = irq;
		res[res_idx].end = irq;
		res[res_idx].flags = IORESOURCE_IRQ;
		res_idx++;

		dev_info(&pdev->dev, "Setting up MSI-X vector %d resource: irq=%d\n", i, irq);
	}

	/* Set up MEM resources */
	rc = octep_plat_setup_mem(pdev, 0, &res[res_idx]);
	if (rc) {
		pr_err("Failed to set up BAR0 resource: %d\n", rc);
		goto exit;
	}

	res_idx++;
	rc = octep_plat_setup_mem(pdev, 4, &res[res_idx]);
	if (rc) {
		pr_err("Failed to set up BAR4 resource: %d\n", rc);
		goto exit;
	}
	res_idx++;

	octep_plat = platform_device_register_simple(OCTEP_VDPA_PLAT_NAME, -1, res, res_idx);
	if (IS_ERR(octep_plat)) {
		rc = PTR_ERR(octep_plat);
		pr_err("Failed to register platform device: %d\n", rc);
		octep_plat = NULL;
		goto exit;
	}

	octep_plat->dev.parent = &pdev->dev;
	dev_info(&pdev->dev, "Octeon EP vDPA platform device registered\n");
exit:
	if (rc && octep_plat)
		platform_device_unregister(octep_plat);
	kfree(res);
put_dev:
	pci_dev_put(pdev);
	return rc;
}

static void __exit octep_cxl_quirk_exit(void)
{
	if (!IS_ERR_OR_NULL(octep_plat)) {
		dev_info(&octep_plat->dev, "Octeon EP vDPA platform device unregistered\n");
		platform_device_unregister(octep_plat);
	}
}

module_init(octep_cxl_quirk_init);
module_exit(octep_cxl_quirk_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Module to register Octeon EP vDPA platform device for CXL");
