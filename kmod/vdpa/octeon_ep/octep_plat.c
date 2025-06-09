/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Marvell.
 */

#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/version.h>

#include "octep_vdpa.h"

#define OCTEP_REGS_BAR 0
#define OCTEP_CAPS_BAR 1

static void octep_plat_free_irqs(struct octep_hw *oct_hw)
{
	struct device *dev = oct_hw->dev;
	int i;

	if (oct_hw->requested_irqs <= 0) {
		dev_info(dev, "No IRQs to free\n");
		return;
	}

	for (i = 0; i < oct_hw->requested_irqs; i++) {
		if (oct_hw->irqs && oct_hw->irqs[i] >= 0)
			devm_free_irq(dev, oct_hw->irqs[i], oct_hw);
	}

	if (oct_hw->irqs) {
		devm_kfree(dev, oct_hw->irqs);
		oct_hw->irqs = NULL;
	}

	oct_hw->requested_irqs = 0;
}

static int octep_plat_request_irqs(struct octep_hw *oct_hw, irqreturn_t (*irq_handler)(int, void *),
				   int nb_irqs)
{
	struct platform_device *pdev = to_platform_device(oct_hw->dev);
	struct device *dev = oct_hw->dev;
	int i, ret;

	/* Free existing IRQs before requesting new ones */
	octep_plat_free_irqs(oct_hw);

	oct_hw->irqs = devm_kcalloc(dev, nb_irqs, sizeof(int), GFP_KERNEL);
	if (!oct_hw->irqs)
		return -ENOMEM;

	for (i = 0; i < nb_irqs; i++)
		oct_hw->irqs[i] = -1;

	for (i = 0; i < nb_irqs; i++) {
		struct resource *res = platform_get_resource(pdev, IORESOURCE_IRQ, i);

		if (!res) {
			dev_err(dev, "Failed to get resource for IRQ %d\n", i);
			octep_plat_free_irqs(oct_hw);
			return -ENODEV;
		}

		if (res->start > INT_MAX) {
			dev_err(dev, "IRQ number %llu exceeds int range\n",
				(unsigned long long)res->start);
			octep_plat_free_irqs(oct_hw);
			return -EINVAL;
		}

		ret = devm_request_irq(dev, res->start, irq_handler, IRQF_SHARED, dev_name(dev),
				       oct_hw);
		if (ret) {
			dev_err(dev, "Failed to request IRQ %llu\n",
				(unsigned long long)res->start);
			octep_plat_free_irqs(oct_hw);
			return ret;
		}

		oct_hw->irqs[i] = (int)res->start;
		oct_hw->requested_irqs++;
	}

	return 0;
}

static const struct octep_hw_ops octep_plat_ops = {
	.request_irqs = octep_plat_request_irqs,
	.free_irqs = octep_plat_free_irqs,
	.handle_event = NULL,
};

static int octep_plat_probe(struct platform_device *pdev)
{
	struct octep_vdpa_mgmt_dev *mgmt_dev;
	struct device *dev = &pdev->dev;
	struct octep_hw *oct_hw;
	int ret;

	mgmt_dev = devm_kzalloc(dev, sizeof(struct octep_vdpa_mgmt_dev), GFP_KERNEL);
	if (!mgmt_dev)
		return -ENOMEM;

	platform_set_drvdata(pdev, mgmt_dev);
	mgmt_dev->oct_hw.dev_type = OCTEP_DEV_TYPE_PLATFORM;

	oct_hw = &mgmt_dev->oct_hw;
	oct_hw->dev = dev;
	oct_hw->dma_dev = dev->parent ? dev->parent : dev;
	oct_hw->ops = &octep_plat_ops;
	oct_hw->nb_irqs = platform_irq_count(pdev);

	if (oct_hw->nb_irqs <= 0) {
		dev_err(dev, "No IRQs available for platform device\n");
		return -ENODEV;
	}

	oct_hw->base[OCTEP_REGS_BAR] =
		devm_platform_get_and_ioremap_resource(pdev, OCTEP_REGS_BAR, NULL);
	if (IS_ERR(oct_hw->base[OCTEP_REGS_BAR])) {
		dev_err(dev, "Failed to get and map memory resource%d\n", OCTEP_REGS_BAR);
		return PTR_ERR(oct_hw->base[OCTEP_REGS_BAR]);
	}

	oct_hw->base[OCTEP_CAPS_BAR] =
		devm_platform_get_and_ioremap_resource(pdev, OCTEP_CAPS_BAR, NULL);
	if (IS_ERR(oct_hw->base[OCTEP_CAPS_BAR])) {
		dev_err(dev, "Failed to get and map memory resource%d\n", OCTEP_CAPS_BAR);
		return PTR_ERR(oct_hw->base[OCTEP_CAPS_BAR]);
	}

	oct_hw->caps_bar = OCTEP_CAPS_BAR;

	ret = octep_hw_caps_read(oct_hw);
	if (ret < 0) {
		dev_err(dev, "Failed to read device capabilities\n");
		return ret;
	}

	ret = octep_vdpa_mgmt_dev_register(mgmt_dev);
	if (ret) {
		dev_err(dev, "Failed to register management device\n");
		atomic_set(&mgmt_dev->status, OCTEP_VDPA_DEV_STATUS_INVALID);
		return ret;
	}

	atomic_set(&mgmt_dev->status, OCTEP_VDPA_DEV_STATUS_READY);
	dev_info(dev, "octep vdpa platform device probed successfully\n");

	return 0;
}

/**
 * Remove function signature changed in kernel 6.11.
 * Only the latest kernel signature will be upstreamed.
 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(6, 10, 0)
static void octep_plat_remove(struct platform_device *pdev)
#else
static int octep_plat_remove(struct platform_device *pdev)
#endif
{
	struct octep_vdpa_mgmt_dev *mgmt_dev = platform_get_drvdata(pdev);
	struct octep_hw *oct_hw = &mgmt_dev->oct_hw;

	oct_hw->ops->free_irqs(oct_hw);

	if (atomic_read(&mgmt_dev->status) == OCTEP_VDPA_DEV_STATUS_READY)
		vdpa_mgmtdev_unregister(&mgmt_dev->mdev);

	dev_info(&pdev->dev, "octep vdpa platform device removed\n");
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6, 10, 0)
	return 0;
#endif
}

static const struct platform_device_id octep_vdpa_plat_ids[] = {
	{ .name = "octep_vdpa_plat", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(platform, octep_vdpa_plat_ids);

static struct platform_driver octep_vdpa_plat = {
	.probe = octep_plat_probe,
	.remove = octep_plat_remove,
	.id_table = octep_vdpa_plat_ids,
	.driver = {
		.name = "octep_vdpa_plat",
	},
};

module_platform_driver(octep_vdpa_plat);

MODULE_AUTHOR("Marvell");
MODULE_DESCRIPTION("Marvell Octeon platform vDPA driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:octep_vdpa_plat");
