/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 Marvell.
 */

#ifndef __OCTEP_RDMA_H__
#define __OCTEP_RDMA_H__

#include <linux/bitfield.h>
#include <net/addrconf.h>

#include <rdma/ib_addr.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_pack.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_user_ioctl_verbs.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_verbs.h>

#include "octep_ep.h"
#ifdef CONFIG_OCTEP_RDMA_OCTTERM
#include "octterm_cdev.h"
#endif

#define OCTEP_RDMA_DRV_NAME "octep_rdma"
#define OCTEP_DRV_STRING "Marvell Octeon EndPoint RDMA Adaptor Driver"
#define OCTEP_RDMA_NODE_DESC OCTEP_DRV_STRING

#define OCTEP_RDMA_DB_SIZE 8
#define OCTEP_RDMA_EXTRA_BUFFER_SIZE OCTEP_RDMA_DB_SIZE
#define WARPPED_BUFSIZE(size) ((size) + OCTEP_RDMA_EXTRA_BUFFER_SIZE)

/* CQ doorbell slot offsets within BAR4 notify region (relative to CQ slot base)
 * CQ slot base = notify_base + (cqn * 3 + 2) * notify_off_multiplier
 * pi_dbl is at offset +0 (uint16_t *)
 *
 * EP (pts_rdma) computes (note the different parenthesization / units):
 *   cb_notify_addr        = (uint32_t *)pi_addr + 4   → byte offset +16
 *   cb_cq_req_notify_addr = (uint32_t *)(pi_addr + 6) → byte offset +12
 *
 * Kernel must read/write at the SAME byte offsets as the EP. The EP accesses
 * these as uint32_t; the host uses byte I/O (works on LE).
 */
#define OCTEP_RDMA_CQ_NOTIFY_OFFSET \
	16 /* cb_notify_addr ((u32*)pi+4): EP writes 1 when data ready */
#define OCTEP_RDMA_CQ_ARM_OFFSET 12 /* req_notify_addr ((u32*)(pi+6)): host writes to arm CQ */

/* arm_byte values */
#define OCTEP_RDMA_CQ_DISARMED 0
#define OCTEP_RDMA_CQ_ARM_SOLICITED 1
#define OCTEP_RDMA_CQ_ARM_NEXT_COMP 2

/* RDMA Capability. */
#define OCTEP_RDMA_MAX_SEND_WR 8192
#define OCTEP_RDMA_MAX_RECV_WR 8192
#define OCTEP_RDMA_MIN_SEND_WR 64
#define OCTEP_RDMA_MIN_RECV_WR 64
#define OCTEP_RDMA_MAX_CONTEXT (128 * 1024)

#define OCTEP_RDMA_SET_FIELD(ptr, mask, value)                       \
	({                                                           \
		typeof(*(ptr)) *_ptr = (ptr);                        \
		*_ptr = (*_ptr & ~(mask)) | FIELD_PREP(mask, value); \
	})

struct octep_rdma_port {
	uint16_t port_num;
	enum ib_port_state state;
	struct ib_port_attr attr;
	u32 qp_gsi_index;
};

struct octep_rdma_resource_cb {
	unsigned long *bitmap;
	spinlock_t lock; /* lock for synchronization */
	u32 next_alloc_idx;
	u32 max_cap;
	u32 start_idx;
};

enum {
	OCTEP_RDMA_RES_TYPE_PD = 0,
	OCTEP_RDMA_RES_TYPE_STAG_IDX,
	OCTEP_RDMA_RES_TYPE_CQ,
	OCTEP_RDMA_RES_TYPE_QP,
	OCTEP_RDMA_RES_TYPE_AH,
	OCTEP_RDMA_RES_CNT,
};

#ifndef CONFIG_OCTEP_RDMA_OCTTERM
struct octep_pf {
	u8 __iomem *base[PCI_STD_NUM_BARS];
	struct pci_dev *pdev;
	struct resource res;
	u64 vf_base;
	int enabled_vfs;
	u32 vf_stride;
	u16 vf_devid;
	struct octep_ep_dev *octep_dev;
};
#endif

struct octep_rdma_dev {
	struct ib_device ibdev;
	struct ib_device_attr attr;

	struct notifier_block netdev_nb;
	struct net_device *netdev;
	struct octep_rdma_port port;
	struct octep_ep_dev *octep_dev;
	/** OS dependent PCI device pointer */
	struct pci_dev *pdev;
	/** device status */
	atomic_t status;

	u32 mtu;
	/* Work entry to handle device setup */
	struct work_struct setup_task;
	atomic_t num_ctx;
	struct octep_rdma_resource_cb res_cb[OCTEP_RDMA_RES_CNT];
	struct octep_caps_region *caps_rgn;

#ifdef CONFIG_OCTEP_RDMA_OCTTERM
	struct octterm_cdev *octterm;
	struct device *dma_dev;
#endif

	/* CQ interrupt notification support */
	bool cq_intr_enabled; /* CQ IRQ registration succeeded */
	u8 nb_cq_irqs; /* Number of CQ interrupt vectors available */
	struct octep_rdma_cq __rcu **cq_table; /* CQ lookup table indexed by cqn; RCU-protected */
	u32 max_cqs; /* Max CQ entries */
	struct work_struct cq_work; /* Bottom half: scans cq_table + wakes consumers */
	struct delayed_work cq_watchdog; /* Periodic scan: recover lost MSI-X edges */
	atomic_t armed_nc; /* # of CQs currently armed for NEXT_COMP; gates the watchdog */

	/* QP lookup table for poll_cq: resolves qp_id -> ib_qp* for
	 * synthesized CQEs that carry only qp_id and not the kernel ibqp pointer.
	 */
	struct octep_rdma_qp **qp_table; /* QP lookup table indexed by qp_num */
	u32 max_qps; /* Max QP entries (= attr.max_qp) */
	spinlock_t qp_table_lock; /* serializes qp_table slot access vs QP teardown */
};

int octep_rdma_ib_device_add(struct octep_rdma_dev *rdma_dev);
void octep_rdma_ib_device_remove(struct octep_rdma_dev *rdma_dev);

/* (Re)start the CQ watchdog; safe to call repeatedly (idempotent while queued).
 * Called when a CQ is armed for NEXT_COMP so the watchdog runs only while there
 * is at least one such CQ to service.
 */
void octep_rdma_cq_watchdog_kick(struct octep_rdma_dev *rdma_dev);

static inline bool
octep_rdma_device_ready(struct octep_rdma_dev *rdma_dev)
{
	int status = atomic_read(&rdma_dev->status);

	return ((status >= OCTEP_RDMA_DEV_STATUS_INIT &&
		 status <= OCTEP_RDMA_DEV_STATUS_NETDEV_REG) ||
		status == OCTEP_RDMA_DEV_STATUS_UNINIT);
}

/* Queue utility functions */
static inline bool
octep_rdma_is_queue_full(uint16_t pi, uint16_t ci, uint16_t qmask)
{
	return ((pi + 1 - ci) & qmask) == 0;
}

static inline bool
octep_rdma_is_queue_empty(uint16_t pi, uint16_t ci)
{
	return (pi == ci);
}

#endif /* __OCTEP_RDMA_H__ */
