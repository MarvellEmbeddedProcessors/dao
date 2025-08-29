/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __ILIAD_CDEV_H__
#define __ILIAD_CDEV_H__

#include <stdint.h>
#include <sys/types.h>

/**
 * Iliad character device structure
 */
struct iliad_cdev_device {
	int fd;          /* Character device file descriptor */
	void *bar4_base; /* Mapped BAR4 memory base */
	void *odm_base;  /* Mapped ODM PF memory base */
};

/**
 * Initialize Iliad character device
 *
 * @param dev
 *   Pointer to Iliad character device structure
 *
 * @return
 *   0 on success, negative error code on failure
 */
int iliad_cdev_init(struct iliad_cdev_device *dev);

/**
 * Finalize Iliad character device
 *
 * @param dev
 *   Pointer to Iliad character device structure
 */
void iliad_cdev_fini(struct iliad_cdev_device *dev);
#endif /* __ILIAD_CDEV_H__ */
