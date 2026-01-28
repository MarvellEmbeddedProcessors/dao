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

#include "octep_sdp.h"

#define OCTEP_RDMA_DRV_NAME  "octep_rdma"
#define OCTEP_DRV_STRING     "Marvell Octeon EndPoint RDMA Adaptor Driver"
#define OCTEP_RDMA_NODE_DESC OCTEP_DRV_STRING

#define OCTEP_RDMA_DB_SIZE           8
#define OCTEP_RDMA_EXTRA_BUFFER_SIZE OCTEP_RDMA_DB_SIZE
#define WARPPED_BUFSIZE(size)        ((size) + OCTEP_RDMA_EXTRA_BUFFER_SIZE)

/* RDMA Capability. */
#define OCTEP_RDMA_MAX_SEND_WR  8192
#define OCTEP_RDMA_MAX_RECV_WR  8192
#define OCTEP_RDMA_MIN_SEND_WR  64
#define OCTEP_RDMA_MIN_RECV_WR  64
#define OCTEP_RDMA_MAX_ORD      128
#define OCTEP_RDMA_MAX_IRD      128
#define OCTEP_RDMA_MAX_CONTEXT  (128 * 1024)
#define OCTEP_RDMA_MAX_SEND_SGE 6
#define OCTEP_RDMA_MAX_RECV_SGE 1

#define OCTEP_RDMA_SET_FIELD(ptr, mask, value)                                                     \
	({                                                                                         \
		typeof(*(ptr)) *_ptr = (ptr);                                                      \
		*_ptr = (*_ptr & ~(mask)) | FIELD_PREP(mask, value);                               \
	})

struct octep_rdma_port {
	uint16_t port_num;
	enum ib_port_state state;
	struct ib_port_attr attr;
	__be64 port_guid;
	__be64 subnet_prefix;
	spinlock_t port_lock; /* guard port */
	unsigned int mtu_cap;
	/* special QPs */
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

struct octep_pf {
	u8 __iomem *base[PCI_STD_NUM_BARS];
	struct pci_dev *pdev;
	struct resource res;
	u64 vf_base;
	int enabled_vfs;
	u32 vf_stride;
	u16 vf_devid;
	struct octep_sdp_dev *octep_dev;
	atomic_t active_vf_count;
};

struct octep_rdma_dev {
	struct ib_device ibdev;
	struct ib_device_attr attr;

	struct notifier_block netdev_nb;
	struct net_device *netdev;
	struct octep_rdma_port port;
	struct octep_sdp_dev *octep_dev;
	/** OS dependent PCI device pointer */
	struct pci_dev *pdev;
	/** device status */
	atomic_t status;
	/* physical port state (only one port per device) */

	u32 mtu;
	/* Work entry to handle device setup */
	struct work_struct setup_task;
	atomic_t num_ctx;
	struct octep_rdma_resource_cb res_cb[OCTEP_RDMA_RES_CNT];
	struct xarray mem_xa;
	struct octep_caps_region *caps_rgn;
};

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
