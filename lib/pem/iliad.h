/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __INCLUDE_ILIAD_H__
#define __INCLUDE_ILIAD_H__

#include <dao_pem.h>
#include <dao_vfio.h>
#include <rte_common.h>
#include <stdint.h>

#include "iliad_cdev.h"

enum iliad_device_type {
	ILIAD_DEVICE_TYPE_PLAT, /* Platform device */
	ILIAD_DEVICE_TYPE_CDEV, /* Character device */
};

struct iliad_device {
	enum iliad_device_type device_type;
	union {
		struct {
			struct dao_vfio_device pdev;
			const struct rte_memzone *bar4_memzone; /**< BAR4 memory zone */
		} plat;
		struct iliad_cdev_device cdev; /**< Character device */
	};
};

int iliad_dev_init(struct iliad_device *ili_dev);
void iliad_dev_fini(struct iliad_device *ili_dev);

uint8_t iliad_dev_host_interrupt_setup(struct iliad_device *ili_dev, uint64_t **intr_addr);

size_t iliad_dev_bar4_size_get(void);
void *iliad_dev_bar4_base_get(struct iliad_device *ili_dev);

#endif /* __INCLUDE_ILIAD_H__ */
