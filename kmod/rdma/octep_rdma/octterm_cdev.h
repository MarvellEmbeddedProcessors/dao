/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Marvell.
 *
 * Character device for RDMA Termination on Octeon.
 * Exposes a 64MB DDR region with BAR4-identical layout via mmap
 * and provides OCTTERM_IOC_FW_READY ioctl for two-phase init.
 */

#ifndef __OCTTERM_CDEV_H__
#define __OCTTERM_CDEV_H__

#ifdef CONFIG_OCTEP_RDMA_OCTTERM

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/types.h>

#define OCTTERM_DDR_REGION_SIZE  (64UL * 1024 * 1024)
#define OCTTERM_IOC_MAGIC         'O'
#define OCTTERM_IOC_GET_MEM_SIZE  _IOR(OCTTERM_IOC_MAGIC, 1, __u64)
#define OCTTERM_IOC_GET_DMA_VF_ID _IOR(OCTTERM_IOC_MAGIC, 2, __u32)
#define OCTTERM_IOC_GET_MAX_VFS   _IOR(OCTTERM_IOC_MAGIC, 3, __u32)
#define OCTTERM_IOC_FW_READY      _IO(OCTTERM_IOC_MAGIC, 4)
#define OCTTERM_IOC_FW_CLEANUP    _IO(OCTTERM_IOC_MAGIC, 5)

#define OCTTERM_MAX_VFS           8

struct octep_rdma_dev;
struct octep_caps_region;

struct octterm_cdev {
	struct pci_dev *pdev;

	/* 64MB DDR region (BAR4-identical layout) */
	void *ddr_region;
	dma_addr_t ddr_dma_addr;

	/* Character device */
	struct cdev cdev;
	struct device *cdev_device;
	dev_t devno;
	int instance_id;

	/* DPI VF identification */
	u32 dma_vf_id;

	/* Deferred FW_READY work */
	struct work_struct fw_ready_work;
	bool fw_ready_scheduled;

	/* State */
	bool ibdev_registered;
	bool fw_gone;

	/* Back-pointers set during probe */
	struct octep_rdma_dev *rdma_dev;
	struct octep_caps_region *caps_rgn;
};

int octterm_class_init(void);
void octterm_class_exit(void);
int octterm_cdev_init(struct octterm_cdev *odev, struct pci_dev *pdev,
		      struct octep_rdma_dev *rdma_dev,
		      struct octep_caps_region *caps_rgn);
void octterm_cdev_destroy(struct octterm_cdev *odev);

#endif /* CONFIG_OCTEP_RDMA_OCTTERM */
#endif /* __OCTTERM_CDEV_H__ */
