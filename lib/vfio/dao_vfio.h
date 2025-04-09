/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

/**
 * @file
 *
 * DAO VFIO library
 *
 * DAO VFIO APIs are used to probe VFIO devices and map the resources.
 */

#ifndef __DAO_VFIO_H__
#define __DAO_VFIO_H__

#define VFIO_DEV_NAME_MAX_LEN 64

#define DAO_VFIO_DEV_BAR0 (0)
#define DAO_VFIO_DEV_BAR2 (2)
#define DAO_VFIO_DEV_BAR4 (4)

/**
 * VFIO device type.
 */
enum dao_vfio_dev_type {
	DAO_VFIO_DEV_PLATFORM, /**< Platform device. */
	DAO_VFIO_DEV_PCIE      /**< PCIe device. */
};

/**
 * VFIO device memory resource.
 */
struct dao_vfio_mem_resouce {
	uint8_t *addr; /**< Mapped virtual address. */
	uint64_t len;  /**< Length of the resource. */
};

/** DAO VFIO device */
struct dao_vfio_device {
	char name[VFIO_DEV_NAME_MAX_LEN]; /**< Device name */
	int device_fd;                    /**< VFIO device fd */
	int group_fd;                     /**< VFIO group fd */
	unsigned int num_resource;        /**< Number of device resources */
	struct dao_vfio_mem_resouce *mem; /**< Device resources */
	enum dao_vfio_dev_type type;      /**< Device type */
	uint8_t prime;                    /**< Primary device */
	uint8_t mbar;                     /**< Bar index of memory */
};

/* End of structure dao_vfio_device. */

/**
 * Initialize the VFIO library by opening a container.
 *
 * @return
 *    Zero on success.
 */
int dao_vfio_init(void);

/**
 * Probe a VFIO device and map its regions. Upon a successful probe,
 * the device details are set in the memory referenced by the pdev pointer.
 *
 * @param dev_name
 *    VFIO device name
 * @param pdev
 *    Pointer to VFIO device structure.
 * @return
 *    Zero on success.
 */
int dao_vfio_device_setup(const char *dev_name, struct dao_vfio_device *pdev);

/**
 * Release a VFIO device and free the associated memory.
 *
 * @param pdev
 *    Pointer to VFIO device structure.
 */
void dao_vfio_device_free(struct dao_vfio_device *pdev);

/**
 * Close the container.
 */
void dao_vfio_fini(void);

#endif /* __DAO_VFIO_H__ */
