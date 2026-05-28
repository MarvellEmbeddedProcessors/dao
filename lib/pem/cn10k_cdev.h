/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2026 Marvell.
 */

#ifndef __CN10K_CDEV_H__
#define __CN10K_CDEV_H__

#include <stdint.h>
#include <sys/types.h>

/**
 * CN10K character device structure
 */
struct cn10k_cdev_device {
	int fd;              /* Character device file descriptor */
	void *base;          /* Mapped memory base */
	size_t size;         /* Total size */
	size_t size_per_dev; /* size per device */
	uint8_t sec_strm_id; /* Secondary stream ID */
	uint8_t max_vfs;     /* Number of virtual functions */
};

/**
 * Initialize CN10K character device
 *
 * @param cn10k char dev
 *
 * @return
 *   0 on success, negative error on failure
 */
int cn10k_cdev_init(struct cn10k_cdev_device *dev);

/**
 * Close CN10K character device
 *
 * @param cn10k char dev
 */
void cn10k_cdev_fini(struct cn10k_cdev_device *dev);

/**
 * Get dev base address
 */
void *cn10k_cdev_base_get(struct cn10k_cdev_device *dev);

/**
 * Get dev total size
 */
size_t cn10k_cdev_size_get(struct cn10k_cdev_device *dev);

/**
 * Get secondary stream ID
 */
uint8_t cn10k_cdev_sec_strm_id_get(struct cn10k_cdev_device *dev);

/**
 * Get max VFs
 */
uint16_t cn10k_cdev_max_vfs_get(struct cn10k_cdev_device *dev);

/**
 * Get secondary stream ID
 */
int cn10k_cdev_sec_strm_id_get_early(uint8_t *sec_strm_id);

/**
 * Get max VFs
 */
int cn10k_cdev_max_vfs_get_early(uint16_t *max_vfs);

/**
 * Notify about FW ready
 */
int cn10k_cdev_fw_ready_notify(struct cn10k_cdev_device *dev);

/**
 * Notify about FW clean up
 */
int cn10k_cdev_fw_cleanup_notify(struct cn10k_cdev_device *dev);

/**
 * Get the character device name
 */
int cn10k_cdev_name_get(char *name, size_t len);

#endif /* __CN10K_CDEV_H__ */
