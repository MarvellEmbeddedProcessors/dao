/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __INCLUDE_SDP_H__
#define __INCLUDE_SDP_H__

#include <stdint.h>

#include <dao_vfio_platform.h>

#define SDP_EPVF_RINGX(x)        (0x80026000 | (x) << 4)
#define SDP_RX_OUT_ENABLE(x)     (0x80010170 | (x) << 17)
#define SDP_RX_OUT_CNTS(x)       (0x80010100 | (x) << 17)
#define SDP_RX_OUT_INT_LEVELS(x) (0x80010110 | (x) << 17)

int sdp_init(struct dao_vfio_platform_device *sdp_pdev);
uint64_t sdp_reg_read(struct dao_vfio_platform_device *sdp_pdev, uint64_t offset);
int sdp_reg_write(struct dao_vfio_platform_device *sdp_pdev, uint64_t offset, uint64_t val);
uint64_t *sdp_reg_addr(struct dao_vfio_platform_device *sdp_pdev, uint64_t offset);
void sdp_fini(struct dao_vfio_platform_device *sdp_pdev);

#endif /* __INCLUDE_SDP_H__ */
