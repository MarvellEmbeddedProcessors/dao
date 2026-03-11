/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 Marvell.
 */

#ifndef __OCTEP_EP_H__
#define __OCTEP_EP_H__

#include <linux/cpumask.h>
#include <linux/etherdevice.h>
#include <linux/if.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include <rdma/octep_rdma-abi.h>

#include "octep_mbox.h"
#include "octep_mbox_priv.h"
#include "octep_pfvf_mbox.h"

struct octep_rdma_mgmt_qp_ctx;

#include <asm/io.h>

/*
 * Flush dirty CPU cache lines to DRAM so DPI DMA sees fresh data.
 * On ARM64, dma_alloc_coherent may return cacheable memory when the system
 * advertises hardware DMA coherence.  DPI DMA reads/writes go directly to
 * DRAM, not through the CPU cache, so explicit cache maintenance is needed.
 *   TX (host->FW): clean+invalidate after CPU writes, before FW DMA reads
 */
static inline void octep_flush_to_dram(void *addr, size_t len)
{
#ifdef CONFIG_ARM64
	unsigned long a = (unsigned long)addr & ~63UL;
	unsigned long end = (unsigned long)addr + len;

	for (; a < end; a += 64)
		asm volatile("dc civac, %0" : : "r"(a) : "memory");
	asm volatile("dsb ish" ::: "memory");
#else
	(void)addr;
	(void)len;
#endif
}

/*
 * Invalidate CPU cache lines so subsequent reads fetch from DRAM.
 *   RX (FW->host): invalidate before CPU reads, after FW DMA writes
 * Uses dc ivac (invalidate only) to avoid writing back stale cachelines
 * that could corrupt freshly DMA-written data.
 */
static inline void octep_invalidate_cache(void *addr, size_t len)
{
#ifdef CONFIG_ARM64
	unsigned long a = (unsigned long)addr & ~63UL;
	unsigned long end = (unsigned long)addr + len;

	for (; a < end; a += 64)
		asm volatile("dc ivac, %0" : : "r"(a) : "memory");
	asm volatile("dsb ish" ::: "memory");
#else
	(void)addr;
	(void)len;
#endif
}

#define OCTEP_RDMA_DEVID_CN106K_PF 0xb900
#define OCTEP_RDMA_DEVID_CN106K_VF 0xb903
#define OCTEP_RDMA_DEVID_CN105K_PF 0xba00
#define OCTEP_RDMA_DEVID_CN105K_VF 0xba03
#define OCTEP_RDMA_DEVID_CN103K_PF 0xbd00
#define OCTEP_RDMA_DEVID_CN103K_VF 0xbd03

#define OCTEP_MAX_VF     128

#define OCTEP_MMIO_REGIONS 6

#define OCTEP_MSIX_NAME_SIZE (IFNAMSIZ + 32)

/* Device status */
enum octep_dev_status {
	OCTEP_DEV_STATUS_READY,
	OCTEP_DEV_STATUS_UNINIT
};

extern struct workqueue_struct *octep_wq;

/* PCI address space mapping information.
 * Each of the 3 address spaces given by BAR0, BAR2 and BAR4 of
 * Octeon gets mapped to different physical address spaces in
 * the kernel.
 */
struct octep_mmio {
	/* The physical address to which the PCI address space is mapped. */
	u8 __iomem *hw_addr;

	/* Flag indicating the mapping was successful. */
	int mapped;
};

struct octep_pci_win_regs {
	u8 __iomem *pci_win_wr_addr;
	u8 __iomem *pci_win_wr_data;
};

struct octep_hw_ops {
	void (*setup_mbox_regs)(struct octep_ep_dev *octep_dev, int mbox);

	irqreturn_t (*mbox_intr_handler)(void *ioq_vector);
	irqreturn_t (*oei_intr_handler)(void *ioq_vector);
	irqreturn_t (*misc_intr_handler)(void *ioq_vector);
	irqreturn_t (*rsvd_intr_handler)(void *ioq_vector);

	void (*enable_interrupts)(struct octep_ep_dev *octep_dev);
	void (*disable_interrupts)(struct octep_ep_dev *octep_dev);
	void (*poll_non_ioq_interrupts)(struct octep_ep_dev *octep_dev);
};

#define MAX_VF_PF_MBOX_DATA_SIZE 384
/* wrappers around work structs */
struct octep_pfvf_mbox_wk {
	struct work_struct work;
	void *ctxptr;
	u64 ctxul;
};

/* PCIe EP device PFVF mailbox */
struct octep_ep_mbox {
	/* A mutex to protect access to this q_mbox. */
	struct mutex lock;
	u32 vf_id;
	u8 __iomem *pf_vf_data_reg;
	u8 __iomem *vf_pf_data_reg;
	struct octep_pfvf_mbox_wk wk;
	struct octep_ep_dev *octep_dev;
};

/* VF information structure */
struct octep_pfvf_info {
	u32 mbox_version;
};

struct octep_vf_mbox_wk {
	struct work_struct work;
	void *ctxptr;
};

/* Octeon EP VF mailbox */
struct octep_ep_vf_mbox {
	/* A mutex to protect access to this q_mbox. */
	struct mutex lock;

	u8 __iomem *mbox_write_reg;
	u8 __iomem *mbox_read_reg;

	/* Octeon VF mailbox work handler to process Mbox messages */
	struct octep_vf_mbox_wk wk;
};

/* Device state */
enum octep_dev_state {
	OCTEP_DEV_STATE_OPEN,
};

struct octep_ep_dev {
	struct octep_config *conf;
	/** OS dependent PCI device pointer */
	struct pci_dev *pdev;

	/* Octeon Chip type. */
	u16 chip_id;
	u16 rev_id;
	/* memory mapped io range */
	struct octep_mmio mmio[OCTEP_MMIO_REGIONS];

	/* Netdev corresponding to the Octeon device */
	struct net_device *netdev;
	/* MAC address */
	u8 mac_addr[ETH_ALEN];

	/* PCI Window registers to access some hardware CSRs */
	struct octep_pci_win_regs pci_win_regs;
	/* Hardware operations */
	struct octep_hw_ops hw_ops;

	/* IRQ info */
	u16 num_custom_irqs;
	char *non_ioq_irq_names;
	struct msix_entry *msix_entries;
	struct octep_caps_region oct_caps;
	/* PF VF mailbox */
	struct octep_ep_mbox *mbox[OCTEP_MAX_VF];
	/* VFs info */
	struct octep_pfvf_info vf_info[OCTEP_MAX_VF];
	/* VF mailbox */
	struct octep_ep_vf_mbox *vf_mbox;
	/* Enable non-ioq interrupt polling */
	bool poll_non_ioq_intr;
	/* Work entry to poll non-ioq interrupts */
	struct delayed_work intr_poll_task;
	/* Device status */
	atomic_t status;
	/* Firmware heartbeat miss count tracked by timer */
	atomic_t hb_miss_cnt;
	/* Task to reset device on heartbeat miss */
	struct delayed_work hb_task;
	/* Task to reset VF device on heartbeat miss */
	struct delayed_work vf_hb_task;
	/* Device state */
	unsigned long state;
	/* Negotiated Mbox version */
	u32 mbox_neg_ver;

	/* Management QP context for non-RDMA packet path (set by octep_rdma_mgmt_qp_netdev_init) */
	struct octep_rdma_mgmt_qp_ctx *mgmt_qp_ctx;
};

static inline u16 OCTEP_MAJOR_REV(struct octep_ep_dev *octep_dev)
{
	u16 rev = (octep_dev->rev_id & 0xC) >> 2;

	return (rev == 0) ? 1 : rev;
}

static inline u16
OCTEP_MINOR_REV(struct octep_ep_dev *octep_dev)
{
	return (octep_dev->rev_id & 0x3);
}

/* Octeon CSR read/write access APIs */
#define octep_write_csr64(octep_dev, reg_off, val64)                                               \
	writeq(val64, (octep_dev)->mmio[0].hw_addr + (reg_off))

#define octep_read_csr64(octep_dev, reg_off) readq((octep_dev)->mmio[0].hw_addr + (reg_off))

/* Write windowed register.
 * @param  oct  -  pointer to the Octeon device.
 * @param  addr -  Address of the register to write
 * @param  val  -  Value to write
 *
 * This routine is called to write to the indirectly accessed
 * Octeon registers that are visible through a PCI BAR0 mapped window
 * register.
 * @return   Nothing.
 */
static inline void
OCTEP_PCI_WIN_WRITE(struct octep_ep_dev *octep_dev, u64 addr, u64 val)
{
	writeq(addr, octep_dev->pci_win_regs.pci_win_wr_addr);
	writeq(val, octep_dev->pci_win_regs.pci_win_wr_data);

	dev_dbg(&octep_dev->pdev->dev, "%s: reg: 0x%016llx val: 0x%016llx\n", __func__, addr, val);
}

int octep_setup_msix(struct octep_ep_dev *octep_dev);
void octep_cleanup_msix(struct octep_ep_dev *octep_dev);
void octep_device_setup_cnxk_pf(struct octep_ep_dev *octep_dev);
void octep_device_setup_cnxk_vf(struct octep_ep_dev *octep_dev);
int octep_rdma_probe_dev(struct octep_ep_dev *octep_dev);
void octep_device_cleanup(struct octep_ep_dev *octep_dev);

/* Function prototypes for work queue tasks and interrupt handlers */
void octep_intr_poll_task(struct work_struct *work);
void octep_hb_timeout_task(struct work_struct *work);
void cancel_all_tasks(struct octep_ep_dev *octep_dev);

#endif /* __OCTEP_EP_H__ */
