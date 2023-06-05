/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sdp.h"
#include <dao_log.h>
#include <dao_util.h>

#define SDP_PLAT_DEV_NAME        "86e000000000.dpi_sdp_regs"
#define SDP_EPFX_RINFO(x)        (0x800209f0UL | (x) << 25)
#define SDP_MAC0_PF_RING_CTL     0x8002c000
#define SDP_EPFX_RINFO_NVFS_MASK DAO_GENMASK_ULL(54, 48)

int
sdp_reg_write(struct dao_vfio_platform_device *sdp_pdev, uint64_t offset, uint64_t val)
{
	if (offset > sdp_pdev->mem[0].len)
		return -ENOMEM;

	*((volatile uint64_t *)(sdp_pdev->mem[0].addr + offset)) = val;
	return 0;
}

uint64_t
sdp_reg_read(struct dao_vfio_platform_device *sdp_pdev, uint64_t offset)
{
	if (offset > sdp_pdev->mem[0].len)
		return -ENOMEM;

	return *(volatile uint64_t *)(sdp_pdev->mem[0].addr + offset);
}

uint64_t *
sdp_reg_addr(struct dao_vfio_platform_device *sdp_pdev, uint64_t offset)
{
	if (offset > sdp_pdev->mem[0].len)
		return NULL;

	return (uint64_t *)(sdp_pdev->mem[0].addr + offset);
}

int
sdp_init(struct dao_vfio_platform_device *sdp_pdev)
{
	uint64_t reg_val;
	int rc;

	rc = dao_vfio_platform_device_setup(SDP_PLAT_DEV_NAME, sdp_pdev);
	if (rc < 0) {
		dao_err("Filed to setup VFIO platform device %s", SDP_PLAT_DEV_NAME);
		return errno;
	}

	reg_val = sdp_reg_read(sdp_pdev, SDP_EPFX_RINFO(0));
	reg_val &= SDP_EPFX_RINFO_NVFS_MASK;
	/* 0 ring per PF and 1 ring per VF. */
	reg_val |= (1UL << 32);
	sdp_reg_write(sdp_pdev, SDP_EPFX_RINFO(0), reg_val);

	return 0;
}

void
sdp_fini(struct dao_vfio_platform_device *sdp_pdev)
{
	dao_vfio_platform_device_free(sdp_pdev);
}
