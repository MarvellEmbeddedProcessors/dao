/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 Marvell.
 */

#include <linux/etherdevice.h>
#include <linux/pci.h>
#include <linux/workqueue.h>

#include "octep_ep.h"
#include "octep_ep_regs.h"
#include "octep_pfvf_mbox.h"

/* Names of Hardware non-queue generic interrupts */
static char *cnxk_non_ioq_msix_names[] = {
	"epf_ire_rint", "epf_ore_rint", "epf_vfire_rint", "epf_rsvd0", "epf_vfore_rint",
	"epf_rsvd1", "epf_mbox_rint", "epf_rsvd2_0", "epf_rsvd2_1", "epf_dma_rint",
	"epf_dma_vf_rint", "epf_rsvd3", "epf_pp_vf_rint", "epf_rsvd3", "epf_misc_rint", "epf_rsvd5",
	/* Next 16 are for OEI_RINT */
	"epf_oei_rint0", "epf_oei_rint1", "epf_oei_rint2", "epf_oei_rint3", "epf_oei_rint4",
	"epf_oei_rint5", "epf_oei_rint6", "epf_oei_rint7", "epf_oei_rint8", "epf_oei_rint9",
	"epf_oei_rint10", "epf_oei_rint11", "epf_oei_rint12", "epf_oei_rint13", "epf_oei_rint14",
	"epf_oei_rint15"};

/* Initialize windowed addresses to access some hardware registers */
static void
octep_setup_pci_window_regs_cnxk_pf(struct octep_ep_dev *octep_dev)
{
	u8 __iomem *bar0_pciaddr = octep_dev->mmio[0].hw_addr;

	octep_dev->pci_win_regs.pci_win_wr_addr =
		(u8 __iomem *)(bar0_pciaddr + CNXK_SDP_WIN_WR_ADDR64);
	octep_dev->pci_win_regs.pci_win_wr_data =
		(u8 __iomem *)(bar0_pciaddr + CNXK_SDP_WIN_WR_DATA64);
}

/* Initialize configuration limits and initial active config */
static void
octep_init_config_cnxk_pf(struct octep_ep_dev *octep_dev)
{
	struct octep_config *conf = octep_dev->conf;
	struct pci_dev *pdev = octep_dev->pdev;
	u64 val;

	/* Read SR-IOV configuration: number of VFs and rings per VF */
	val = octep_read_csr64(octep_dev, CNXK_SDP_EPF_RINFO);
	dev_info(&pdev->dev, "SDP_EPF_RINFO[0x%x]:0x%llx\n", CNXK_SDP_EPF_RINFO, val);
	conf->sriov_cfg.max_rings_per_vf = CNXK_SDP_EPF_RINFO_RPVF(val);
	conf->sriov_cfg.active_rings_per_vf = conf->sriov_cfg.max_rings_per_vf;
	conf->sriov_cfg.max_vfs = CNXK_SDP_EPF_RINFO_NVFS(val);
	conf->sriov_cfg.active_vfs = 0;
	conf->sriov_cfg.vf_srn = CNXK_SDP_EPF_RINFO_SRN(val);
	dev_info(&pdev->dev, "rpvf=%u nvfs=%u vf_srn=%u\n",
		 conf->sriov_cfg.active_rings_per_vf, conf->sriov_cfg.max_vfs,
		 conf->sriov_cfg.vf_srn);

	conf->msix_cfg.non_ioq_msix = CNXK_NUM_NON_IOQ_INTR;
	conf->msix_cfg.non_ioq_msix_names = cnxk_non_ioq_msix_names;

	conf->fw_info.hb_interval = OCTEP_DEFAULT_FW_HB_INTERVAL;
	conf->fw_info.hb_miss_count = OCTEP_DEFAULT_FW_HB_MISS_COUNT;
}

/* Setup registers for a PF mailbox */
static void octep_setup_mbox_regs_cnxk_pf(struct octep_ep_dev *octep_dev, int q_no)
{
	struct octep_ep_mbox *mbox = octep_dev->mbox[q_no];

	/* PF to VF DATA reg. PF writes into this reg */
	mbox->pf_vf_data_reg = octep_dev->mmio[0].hw_addr + CNXK_SDP_MBOX_PF_VF_DATA(q_no);

	/* VF to PF DATA reg. PF reads from this reg */
	mbox->vf_pf_data_reg = octep_dev->mmio[0].hw_addr + CNXK_SDP_MBOX_VF_PF_DATA(q_no);
}

static void octep_poll_pfvf_mailbox_cnxk_pf(struct octep_ep_dev *octep_dev)
{
	u32 vf, active_vfs, active_rings_per_vf, vf_mbox_queue;
	u64 reg0;

	reg0 = octep_read_csr64(octep_dev, CNXK_SDP_EPF_MBOX_RINT(0));
	if (reg0) {
		active_vfs = CFG_GET_ACTIVE_VFS(octep_dev->conf);
		active_rings_per_vf = CFG_GET_ACTIVE_RPVF(octep_dev->conf);
		for (vf = 0; vf < active_vfs; vf++) {
			vf_mbox_queue = vf * active_rings_per_vf;
			if (!(reg0 & (0x1UL << vf_mbox_queue)))
				continue;

			if (!octep_dev->mbox[vf_mbox_queue]) {
				dev_err(&octep_dev->pdev->dev, "bad mbox vf %d\n", vf);
				continue;
			}
			schedule_work(&octep_dev->mbox[vf_mbox_queue]->wk.work);
		}
		if (reg0)
			octep_write_csr64(octep_dev, CNXK_SDP_EPF_MBOX_RINT(0), reg0);
	}
}

/* Mailbox Interrupt handler */
static irqreturn_t octep_pfvf_mbox_intr_handler_cnxk_pf(void *dev)
{
	struct octep_ep_dev *octep_dev = (struct octep_ep_dev *)dev;

	octep_poll_pfvf_mailbox_cnxk_pf(octep_dev);
	return IRQ_HANDLED;
}

/* Poll OEI events like heartbeat */
static void octep_poll_oei_cnxk_pf(struct octep_ep_dev *octep_dev)
{
	u64 reg0;
	u32 active_vfs, vf;

	/* Check for OEI INTR */
	reg0 = octep_read_csr64(octep_dev, CNXK_SDP_EPF_OEI_RINT);
	if (reg0) {
		/* Clear the interrupt bits by writing back the same value */
		octep_write_csr64(octep_dev, CNXK_SDP_EPF_OEI_RINT, reg0);

		if (reg0 & CNXK_SDP_EPF_OEI_RINT_DATA_BIT_HBEAT) {
			int current_count = atomic_read(&octep_dev->hb_miss_cnt);

			dev_dbg(&octep_dev->pdev->dev,
				"*** HEARTBEAT INTERRUPT (miss_cnt: %d -> 0) ***", current_count);
			atomic_set(&octep_dev->hb_miss_cnt, 0);
		}

		if (reg0 & CNXK_SDP_EPF_OEI_RINT_DATA_BIT_LINK_STATUS_MASK) {
			active_vfs = CFG_GET_ACTIVE_VFS(octep_dev->conf);
			if (!active_vfs) {
				dev_err(&octep_dev->pdev->dev, "No active VFs to notify");
				return;
			}

			/* Check for Link DOWN events (bits 2-17) */
			if (reg0 & CNXK_SDP_EPF_OEI_RINT_DATA_BIT_LINK_DOWN_MASK) {
				for (vf = 0; vf < active_vfs; vf++) {
					if (reg0 & (0x1UL << (vf + 2))) {
						dev_warn(
							&octep_dev->pdev->dev,
							"*** LINK DOWN INTERRUPT FOR VF %d (port %d) ***",
							vf, vf);
						octep_rdma_send_link_status(
							octep_dev, vf,
							OCTEP_RDMA_PFVF_LINK_STATUS_DOWN);
					}
				}
			}

			/* Check for Link UP events (bits 18-33) */
			if (reg0 & CNXK_SDP_EPF_OEI_RINT_DATA_BIT_LINK_UP_MASK) {
				for (vf = 0; vf < active_vfs; vf++) {
					if (reg0 & (0x1UL << (vf + 18))) {
						dev_warn(
							&octep_dev->pdev->dev,
							"*** LINK UP INTERRUPT FOR VF %d (port %d) ***",
							vf, vf);
						octep_rdma_send_link_status(
							octep_dev, vf,
							OCTEP_RDMA_PFVF_LINK_STATUS_UP);
					}
				}
			}
		}

		if (!(reg0 & (CNXK_SDP_EPF_OEI_RINT_DATA_BIT_HBEAT |
			      CNXK_SDP_EPF_OEI_RINT_DATA_BIT_LINK_STATUS_MASK))) {
			dev_warn(&octep_dev->pdev->dev,
				 "*** OEI interrupt with unknown bits: 0x%llx ***", reg0);
		}
	}
}

/* OEI interrupt handler */
static irqreturn_t octep_oei_intr_handler_cnxk_pf(void *dev)
{
	struct octep_ep_dev *octep_dev = (struct octep_ep_dev *)dev;

	dev_dbg(&octep_dev->pdev->dev, "Received OEI_RINT intr\n");
	octep_poll_oei_cnxk_pf(octep_dev);
	return IRQ_HANDLED;
}

static void octep_poll_non_ioq_interrupts_cnxk_pf(struct octep_ep_dev *octep_dev)
{
	octep_poll_pfvf_mailbox_cnxk_pf(octep_dev);
	octep_poll_oei_cnxk_pf(octep_dev);
	dev_dbg(&octep_dev->pdev->dev, "Polling non-ioq interrupts\n");
}

/* Interrupt handler for mac related interrupts. */
static irqreturn_t
octep_misc_intr_handler_cnxk_pf(void *dev)
{
	struct octep_ep_dev *octep_dev = (struct octep_ep_dev *)dev;
	struct pci_dev *pdev = octep_dev->pdev;
	u64 reg_val = 0;

	/* Check for MISC INTR */
	reg_val = octep_read_csr64(octep_dev, CNXK_SDP_EPF_MISC_RINT);
	if (reg_val) {
		dev_info(&pdev->dev, "Received MISC_RINT intr: 0x%llx\n", reg_val);
		octep_write_csr64(octep_dev, CNXK_SDP_EPF_MISC_RINT, reg_val);
	}
	return IRQ_HANDLED;
}

/* Interrupts handler for all reserved interrupts. */
static irqreturn_t
octep_rsvd_intr_handler_cnxk_pf(void *dev)
{
	struct octep_ep_dev *octep_dev = (struct octep_ep_dev *)dev;
	struct pci_dev *pdev = octep_dev->pdev;

	dev_info(&pdev->dev, "Reserved interrupts raised; Ignore\n");
	return IRQ_HANDLED;
}

/* Enable all interrupts */
static void
octep_enable_interrupts_cnxk_pf(struct octep_ep_dev *octep_dev)
{
	octep_write_csr64(octep_dev, CNXK_SDP_EPF_OEI_RINT_ENA_W1S, -1ULL);
	octep_write_csr64(octep_dev, CNXK_SDP_EPF_MBOX_RINT_ENA_W1S(0), -1ULL);
	octep_write_csr64(octep_dev, CNXK_SDP_EPF_MISC_RINT_ENA_W1S, -1ULL);
}

/* Disable all interrupts */
static void octep_disable_interrupts_cnxk_pf(struct octep_ep_dev *octep_dev)
{
	octep_write_csr64(octep_dev, CNXK_SDP_EPF_OEI_RINT_ENA_W1C, -1ULL);
	octep_write_csr64(octep_dev, CNXK_SDP_EPF_MBOX_RINT_ENA_W1C(0), -1ULL);
	octep_write_csr64(octep_dev, CNXK_SDP_EPF_MISC_RINT_ENA_W1C, -1ULL);
}

/**
 * octep_device_setup_cnxk_pf() - Setup Octeon PF device.
 *
 * @octep_dev: Octeon device private data structure.
 *
 * - initialize hardware operations.
 * - setup window access to hardware registers.
 * - set initial SR-IOV and interrupt configuration.
 */
void
octep_device_setup_cnxk_pf(struct octep_ep_dev *octep_dev)
{
	octep_dev->hw_ops.setup_mbox_regs = octep_setup_mbox_regs_cnxk_pf;

	octep_dev->hw_ops.mbox_intr_handler = octep_pfvf_mbox_intr_handler_cnxk_pf;
	octep_dev->hw_ops.oei_intr_handler = octep_oei_intr_handler_cnxk_pf;
	octep_dev->hw_ops.misc_intr_handler = octep_misc_intr_handler_cnxk_pf;
	octep_dev->hw_ops.rsvd_intr_handler = octep_rsvd_intr_handler_cnxk_pf;

	octep_dev->hw_ops.enable_interrupts = octep_enable_interrupts_cnxk_pf;
	octep_dev->hw_ops.disable_interrupts = octep_disable_interrupts_cnxk_pf;
	octep_dev->hw_ops.poll_non_ioq_interrupts = octep_poll_non_ioq_interrupts_cnxk_pf;

	octep_setup_pci_window_regs_cnxk_pf(octep_dev);
	octep_init_config_cnxk_pf(octep_dev);

	/* Firmware status CSR is supposed to be cleared by
	 * core domain reset, but due to IPBUPEM-38842, it is not.
	 * Set it to RUNNING early in boot, so that unexpected resets
	 * leave it in a state that is not READY (1).
	 */
	OCTEP_PCI_WIN_WRITE(octep_dev, CNXK_PEMX_PFX_CSX_PFCFGX(0, 0, CNXK_PCIEEP_VSECST_CTL),
			    FW_STATUS_RUNNING);
}

/* Setup registers for a VF mailbox */
static void octep_vf_setup_mbox_regs_cnxk(struct octep_ep_dev *octep_dev, int q_no)
{
	struct octep_ep_vf_mbox *mbox = octep_dev->vf_mbox;

	/* PF to VF DATA reg. VF reads from this reg */
	mbox->mbox_read_reg = octep_dev->mmio[0].hw_addr + CNXK_VF_SDP_R_MBOX_PF_VF_DATA(q_no);

	/* VF to PF DATA reg. VF writes into this reg */
	mbox->mbox_write_reg = octep_dev->mmio[0].hw_addr + CNXK_VF_SDP_R_MBOX_VF_PF_DATA(q_no);
}

/* Enable all interrupts */
static void
octep_vf_enable_interrupts_cnxk(struct octep_ep_dev *octep_dev)
{
	/* Enable PF to VF mbox interrupt */
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_MBOX_PF_VF_INT(0),
			  CNXK_VF_SDP_R_MBOX_PF_VF_INT_ENAB);
}

/* Disable all interrupts */
static void
octep_vf_disable_interrupts_cnxk(struct octep_ep_dev *octep_dev)
{
	/* Disable PF to VF mbox interrupt */
	if (octep_dev->vf_mbox)
		octep_write_csr64(octep_dev, CNXK_VF_SDP_R_MBOX_PF_VF_INT(0), 0x0);
}

/**
 * octep_device_setup_cnxk_vf() - Setup Octeon VF device.
 *
 * @octep_dev: Octeon device private data structure.
 *
 * - initialize hardware operations (mailbox, interrupts).
 */
void
octep_device_setup_cnxk_vf(struct octep_ep_dev *octep_dev)
{
	octep_dev->hw_ops.setup_mbox_regs = octep_vf_setup_mbox_regs_cnxk;

	octep_dev->hw_ops.enable_interrupts = octep_vf_enable_interrupts_cnxk;
	octep_dev->hw_ops.disable_interrupts = octep_vf_disable_interrupts_cnxk;
}
