/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */
#ifndef __INCLUDE_PEM_H__
#define __INCLUDE_PEM_H__

#include <stdint.h>

#include <dao_log.h>
#include <dao_pem.h>
#include <dao_platform.h>
#include <dao_util.h>
#include <dao_vfio.h>

#include "iliad.h"

#define PEM_BAR4_NUM_INDEX         16
#define PEM_BAR4_INDEX_START       0
#define PEM_BAR4_INDEX_END         15
#define PEM_BAR4_INDEX_SIZE        0x400000ULL
#define PEM_BAR4_INDEX_ADDR_IDX(x) ((x) << 4)
#define PEM_BAR4_INDEX_ADDR_V      (1ull)

/* PF BAR0 register offsets */
#define PEM_BAR4_INDEX(x) (0x700ull | ((x) << 3))
#define PEM_DIS_PORT      (0x50ull)

#define PEM_EVENT_MASK 0xFF

enum pem_host_dev_event_state {
	PEM_HOST_DEV_NO_EVENT,
	PEM_HOST_DEV_NEW_EVENT,
	PEM_HOST_DEV_EVENT_ACTIVE,
	PEM_HOST_DEV_EVENT_DONE,
};

enum pem_host_dev_event {
	PEM_HOST_DEV_EVENT_NONE,
	PEM_HOST_DEV_EVENT_ACK,
	PEM_HOST_DEV_EVENT_NACK,
	PEM_HOST_DEV_ADD_EVENT,
	PEM_HOST_DEV_DEL_EVENT,
};

struct pem_region {
	uintptr_t reg_base;
	uint32_t sz;
	dao_pem_ctrl_region_cb_t cb;
	void *ctx;

	uint64_t shadow[];
};

/* CN10K device structure */
struct cn10k_device {
	struct dao_vfio_device sdp_pdev;  /**< SDP device */
	struct dao_vfio_device bar4_pdev; /**< BAR4 device */
};

struct pem {
	uint8_t pem_id;
	uintptr_t bar2;
	size_t bar2_sz;
	size_t host_page_sz;
	uint64_t host_pages_per_dev;
	uint16_t max_vfs;
	uint16_t rpvf;
	bool sdp_inuse;

	rte_thread_t ctrl_thread;
	bool ctrl_done;
	struct pem_region *regions[DAO_PEM_CTRL_REGION_MAX];
	uint64_t region_mask[DAO_PEM_CTRL_REGION_MASK_MAX];

	enum dao_platform platform;

	/* Platform-specific device structures */
	union {
		struct cn10k_device cn10k; /**< CN10K device (SDP + BAR4) */
		struct iliad_device ili;   /**< Iliad device (VFIO or character device) */
	};
};

int iliad_init(struct dao_vfio_device *ili_pdev, rte_iova_t bar4_base);
void iliad_fini(struct dao_vfio_device *ili_pdev);
uint8_t iliad_host_interrupt_setup(struct dao_vfio_device *ili_pdev, uint64_t **intr_addr);
#endif /* __INCLUDE_PEM_H__ */
