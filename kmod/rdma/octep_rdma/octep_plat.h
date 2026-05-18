/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Marvell.
 *
 * Platform abstraction for x86 EP vs Octeon Termination modes.
 * All mode-specific I/O, DMA device, doorbell, and mmap differences
 * are captured here as static inline functions so .c files remain
 * #ifdef-free.
 */

#ifndef __OCTEP_PLAT_H__
#define __OCTEP_PLAT_H__

#include <linux/compiler.h>
#include <linux/io.h>
#include <linux/pci.h>

struct octep_rdma_dev;
struct octep_caps_region;

/* ----------------------------------------------------------------
 * 1. Shared region read/write (BAR4 MMIO vs DDR)
 * ---------------------------------------------------------------- */
static inline u8 octep_plat_read8(void __iomem *addr)
{
#ifdef CONFIG_OCTEP_RDMA_OCTTERM
	return READ_ONCE(*(__force u8 *)addr);
#else
	return ioread8(addr);
#endif
}

static inline u16 octep_plat_read16(void __iomem *addr)
{
#ifdef CONFIG_OCTEP_RDMA_OCTTERM
	return READ_ONCE(*(__force u16 *)addr);
#else
	return ioread16(addr);
#endif
}

static inline u32 octep_plat_read32(void __iomem *addr)
{
#ifdef CONFIG_OCTEP_RDMA_OCTTERM
	return READ_ONCE(*(__force u32 *)addr);
#else
	return ioread32(addr);
#endif
}

static inline void octep_plat_write16(u16 val, void __iomem *addr)
{
#ifdef CONFIG_OCTEP_RDMA_OCTTERM
	WRITE_ONCE(*(__force u16 *)addr, val);
	/* Ensure DDR write is visible to firmware before proceeding */
	wmb();
#else
	iowrite16(val, addr);
#endif
}

static inline void octep_plat_write32(u32 val, void __iomem *addr)
{
#ifdef CONFIG_OCTEP_RDMA_OCTTERM
	WRITE_ONCE(*(__force u32 *)addr, val);
	/* Ensure DDR write is visible to firmware before proceeding */
	wmb();
#else
	iowrite32(val, addr);
#endif
}

static inline void octep_plat_memset(void __iomem *addr, int val, size_t count)
{
#ifdef CONFIG_OCTEP_RDMA_OCTTERM
	memset((void *)addr, val, count);
	/* Ensure DDR region is fully written before firmware reads it */
	wmb();
#else
	memset_io(addr, val, count);
#endif
}

/* ----------------------------------------------------------------
 * 2. Doorbell mapping (ioremap vs DDR kernel VA)
 * ---------------------------------------------------------------- */
static inline void __iomem *
octep_plat_map_doorbell(struct octep_caps_region *caps,
			phys_addr_t notify_base_pa,
			void __iomem *notify_base,
			u32 notify_sz)
{
#ifdef CONFIG_OCTEP_RDMA_OCTTERM
	(void)notify_base_pa;
	(void)notify_sz;
	return notify_base;
#else
	(void)notify_base;
	return ioremap(notify_base_pa, notify_sz);
#endif
}

static inline void
octep_plat_unmap_doorbell(void __iomem *addr)
{
#ifndef CONFIG_OCTEP_RDMA_OCTTERM
	if (addr)
		iounmap(addr);
#else
	(void)addr;
#endif
}

#endif /* __OCTEP_PLAT_H__ */
