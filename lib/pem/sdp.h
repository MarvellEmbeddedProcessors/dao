/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __INCLUDE_SDP_H__
#define __INCLUDE_SDP_H__

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include <dao_vfio.h>

#define SDP_RX_OUT_ENABLE(x)           (0x00010170 | (x) << 17)
#define SDP_RX_OUT_CNTS(x)             (0x00010100 | (x) << 17)
#define SDP_RX_OUT_INT_LEVELS(x)       (0x00010110 | (x) << 17)
#define SDP_MAC0_PF_RING_CTL           (0x0002c000)
#define SDP_MAC0_PF_RING_CTL_RPPF_MASK DAO_GENMASK_ULL(21, 16)
#define SDP_EPVF_RINGX(x)              (0x00026000 | (x) << 4)
#define SDP_EPFX_RINFO(x)              (0x000209f0 | (x) << 25)
#define SDP_VF_EVENT_STATE(x)          (0x00010030 | (x) << 17)
#define SDP_VF_EVENT_REG(x)            (0x00010060 | (x) << 17)
#define SDP_PF_MBOX_DATA(x)            (0x00022000 | ((x) << 4))
#define SDP_VF_MBOX_DATA(x)            (0x00010210 | ((x) << 17))
#define SDP_EPFX_RINFO_RPVF_SHIFT      32
#define SDP_EPFX_RINFO_NVVF_SHIFT      48
#define SDP_RX_OUT_INTERRUPT_SHIFT     59
#define SDP_EPFX_RINFO_SRN_MASK        DAO_GENMASK_ULL(6, 0)

int sdp_init(struct dao_vfio_device *sdp_pdev, bool sdp_inuse);
uint64_t sdp_reg_read(struct dao_vfio_device *sdp_pdev, uint64_t offset);
void sdp_reg_write(struct dao_vfio_device *sdp_pdev, uint64_t offset, uint64_t val);
uint64_t *sdp_reg_addr(struct dao_vfio_device *sdp_pdev, uint64_t offset);
void sdp_fini(struct dao_vfio_device *sdp_pdev);

#endif /* __INCLUDE_SDP_H__ */
