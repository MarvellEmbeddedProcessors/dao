/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

/**
 * @file
 *
 * DAO VFIO platform library
 *
 * DAO VFIO platform APIs are used to probe VFIO platform devices and map the resources.
 */

#ifndef __DAO_VFIO_PLATFORM_H__
#define __DAO_VFIO_PLATFORM_H__

#define VFIO_DEV_NAME_MAX_LEN 64

/**
 * VFIO platform device memory resource.
 */
struct dao_vfio_mem_resouce {
	uint8_t *addr; /**< Mapped virtual address. */
	uint64_t len;  /**< Length of the resource. */
};

/** VFIO platform device */
struct dao_vfio_platform_device {
	char name[VFIO_DEV_NAME_MAX_LEN]; /**< Device name */
	int device_fd;                    /**< VFIO device fd */
	int group_fd;                     /**< VFIO group fd */
	unsigned int num_resource;        /**< Number of device resources */
	struct dao_vfio_mem_resouce *mem; /**< Device resources */
};

/* End of structure dao_vfio_platform_device. */

/**
 * Initialize the VFIO platform library by opening a container.
 *
 * @return
 *    Zero on success.
 */
int dao_vfio_platform_init(void);

/**
 * Probe a VFIO platform device and map its regions. Upon a successful probe,
 * the device details are set in the memory referenced by the pdev pointer.
 *
 * @param dev_name
 *    VFIO platform device name
 * @param pdev
 *    Pointer to VFIO platform device structure.
 * @return
 *    Zero on success.
 */
int dao_vfio_platform_device_setup(const char *dev_name, struct dao_vfio_platform_device *pdev);

/**
 * Release a VFIO platform device and free the associated memory.
 *
 * @param pdev
 *    Pointer to VFIO platform device structure.
 */
void dao_vfio_platform_device_free(struct dao_vfio_platform_device *pdev);

/**
 * Close the container.
 */
void dao_vfio_platform_fini(void);

#endif /* __DAO_VFIO_PLATFORM_H__ */
