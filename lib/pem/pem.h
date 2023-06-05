/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */
#ifndef __INCLUDE_PEM_H__
#define __INCLUDE_PEM_H__

#include <stdint.h>

#include <dao_log.h>
#include <dao_util.h>
#include <dao_vfio_platform.h>

#define PEM_BAR4_NUM_INDEX     16
#define PEM_BAR4_INDEX_START   0
#define PEM_BAR4_INDEX_END     15
#define PEM_BAR4_INDEX_SIZE    0x400000ULL

struct pem_region {
	uintptr_t reg_base;
	uint32_t sz;
	dao_pem_ctrl_region_cb_t cb;
	void *ctx;

	uint64_t shadow[];
};

struct pem {
	uint8_t pem_id;
	uintptr_t bar2;
	size_t bar2_sz;
	size_t host_page_sz;
	uint64_t host_pages_per_dev;
	uint16_t max_vfs;

	rte_thread_t ctrl_thread;
	bool ctrl_done;
	struct pem_region *regions[DAO_PEM_CTRL_REGION_MAX];
	uint64_t region_mask[DAO_PEM_CTRL_REGION_MASK_MAX];
	struct dao_vfio_platform_device bar4_pdev;
	struct dao_vfio_platform_device sdp_pdev;
};

#endif /* __INCLUDE_PEM_H__ */
