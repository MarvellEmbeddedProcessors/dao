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
#include <rte_io.h>

#define SDP0_PCIE_DEV_NAME "0002:18:00.0"
#define SDP1_PCIE_DEV_NAME "0002:19:00.0"

static inline void
cp_write64(uint64_t value, volatile void *addr)
{
	rte_io_wmb();
	/* Direct write to memory mapped address */
	*(volatile uint64_t *)addr = value;
}

static inline void *
devmem_map_oei_reg(uint64_t addr, size_t len, off_t *offset)
{
	off_t pg_addr, pg_offset;
	long pg_sz;
	void *map;
	int fd;

	fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (fd <= 0)
		return NULL;

	/* Page alignment calculation */
	pg_sz = sysconf(_SC_PAGESIZE);
	pg_addr = ((addr / pg_sz) * pg_sz); /* Page-aligned base address */
	pg_offset = addr % pg_sz;           /* Offset within page */

	/* Map page-aligned region */
	map = mmap(0, (pg_offset + len), PROT_READ | PROT_WRITE, MAP_SHARED, fd, pg_addr);
	if (map == MAP_FAILED) {
		dao_err("mmap[0x%lx] error: %s", addr, strerror(errno));
		close(fd);
		return NULL;
	}
	close(fd);

	if (offset)
		*offset = pg_offset;

	return ((char *)map + pg_offset);
}

int
sdp_oei_reg_write(uint64_t offset, uint64_t val)
{
	/* OEI trigger registers - these are physical addresses, not BAR offsets.
	 * Need mapping for proper page alignment.
	 */
	dao_dbg("OEI trigger register write: offset=0x%lx, value=0x%lx", offset, val);

	off_t pg_offset;
	void *mapped_addr = devmem_map_oei_reg(offset, sizeof(uint64_t), &pg_offset);

	if (mapped_addr) {
		dao_dbg("OEI mapped: addr=%p, page_offset=0x%lx", mapped_addr, pg_offset);
		cp_write64(val, mapped_addr);

		/* Unmap the region (calculate original map size) */
		munmap((char *)mapped_addr - pg_offset, pg_offset + sizeof(uint64_t));
		dao_dbg("OEI trigger write completed successfully");
		return 0;
	}

	dao_err("Failed to map OEI trigger register at 0x%lx", offset);
	return -1;
}

/* Valid pointers and offsets are always guaranteed; no validation checks are necessary */
static inline void
is_sdp_offset_valid(struct dao_vfio_device *sdp_pdev, uint64_t offset)
{
	assert(sdp_pdev && sdp_pdev->mem[DAO_VFIO_DEV_BAR2].addr);
	assert((offset % sizeof(uint64_t) == 0) &&
	       (offset + sizeof(uint64_t) <= sdp_pdev->mem[DAO_VFIO_DEV_BAR2].len));
}

void
sdp_reg_write(struct dao_vfio_device *sdp_pdev, uint64_t offset, uint64_t val)
{
	is_sdp_offset_valid(sdp_pdev, offset);
	*((volatile uint64_t *)(sdp_pdev->mem[DAO_VFIO_DEV_BAR2].addr + offset)) = val;
}

uint64_t
sdp_reg_read(struct dao_vfio_device *sdp_pdev, uint64_t offset)
{
	is_sdp_offset_valid(sdp_pdev, offset);
	return *(volatile uint64_t *)(sdp_pdev->mem[DAO_VFIO_DEV_BAR2].addr + offset);
}

uint64_t *
sdp_reg_addr(struct dao_vfio_device *sdp_pdev, uint64_t offset)
{
	is_sdp_offset_valid(sdp_pdev, offset);
	return (uint64_t *)(sdp_pdev->mem[DAO_VFIO_DEV_BAR2].addr + offset);
}

int
sdp_init(struct dao_vfio_device *sdp_pdev, bool sdp_inuse)
{
	uint8_t idx, ring_idx, rpvf, vfid, num_vfs;
	uint64_t reg_val, info;
	int rc;

	sdp_pdev->type = DAO_VFIO_DEV_PCIE;
	if (sdp_pdev->prime)
		rc = dao_vfio_device_setup(SDP0_PCIE_DEV_NAME, sdp_pdev);
	else
		rc = dao_vfio_device_setup(SDP1_PCIE_DEV_NAME, sdp_pdev);
	if (rc < 0) {
		dao_err("Failed to setup DAO VFIO device %s",
			sdp_pdev->prime ? SDP0_PCIE_DEV_NAME : SDP1_PCIE_DEV_NAME);
		return rc;
	}

	sdp_pdev->mbar = DAO_VFIO_DEV_BAR4;

	if (sdp_pdev->prime && !sdp_inuse) {
		reg_val = sdp_reg_read(sdp_pdev, SDP_EPFX_RINFO(0));
		reg_val &= ~SDP_EPFX_RINFO_SRN_MASK;
		sdp_reg_write(sdp_pdev, SDP_EPFX_RINFO(0), reg_val);

		reg_val = sdp_reg_read(sdp_pdev, SDP_EPFX_RINFO(0));

		rpvf = (reg_val >> SDP_EPFX_RINFO_RPVF_SHIFT) & 0xf;
		num_vfs = (reg_val >> SDP_EPFX_RINFO_NVVF_SHIFT) & 0x7f;

		/* Disable PF Ring */
		reg_val = sdp_reg_read(sdp_pdev, SDP_MAC0_PF_RING_CTL);
		reg_val &= ~SDP_MAC0_PF_RING_CTL_RPPF_MASK;
		sdp_reg_write(sdp_pdev, SDP_MAC0_PF_RING_CTL, reg_val);

		for (vfid = 1; vfid <= num_vfs; vfid++) {
			for (idx = 0; idx < rpvf; idx++) {
				ring_idx = idx + ((vfid - 1) * rpvf);

				sdp_reg_write(sdp_pdev, SDP_EPVF_RINGX(ring_idx), vfid);
			}
		}

		vfid = 0;
		info = rpvf | ((uint64_t)vfid << 8) | ((uint64_t)num_vfs << 16);
		info <<= 32;
		sdp_reg_write(sdp_pdev, SDP_PF_MBOX_DATA(0), info);
		vfid = num_vfs >> 1;
		if (vfid) {
			info = rpvf | ((uint64_t)vfid << 8) | ((uint64_t)num_vfs << 16);
			info <<= 32;
			sdp_reg_write(sdp_pdev, SDP_PF_MBOX_DATA(vfid * rpvf), info);
		}
	}

	return 0;
}

void
sdp_fini(struct dao_vfio_device *sdp_pdev)
{
	dao_vfio_device_free(sdp_pdev);
}
