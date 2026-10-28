/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Marvell.
 */
#ifndef __OCTEP_DEV_CFG_H__
#define __OCTEP_DEV_CFG_H__

#include <linux/stddef.h>
#include <linux/types.h>

#define OCTEP_RDMA_DEV_CFG_OPAQUE_DATA_SIZE 48

/*
 * Device config region in BAR4 (OCTEP_RDMA_DEV_PCI_CAP_DEV_CFG).
 * Must mirror struct pts_rdma_dev_cfg in the firmware
 * (lib/pts_rdma/pts_rdma_dev_priv.h). Natural alignment is used on both
 * sides, so opaque_data (which carries the port MAC) is at offset 17.
 */
struct octep_rdma_dev_cfg {
	u64 host_meta_addr;
	u32 max_qps;
	u32 max_cqs;
	u8 device_status;
	u8 opaque_data[OCTEP_RDMA_DEV_CFG_OPAQUE_DATA_SIZE];
};

/* Offset of the port MAC address inside dev_cfg. */
#define MAC_OFFSET offsetof(struct octep_rdma_dev_cfg, opaque_data)

#endif /* __OCTEP_DEV_CFG_H__ */
