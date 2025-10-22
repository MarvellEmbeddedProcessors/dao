/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 Marvell.
 */

#include <linux/etherdevice.h>
#include <linux/pci.h>

#include "octep_sdp.h"
#include "octep_sdp_regs.h"

/* We will support 128 pf's in control mbox */
#define CTRL_MBOX_MAX_PF 128
#define CTRL_MBOX_SZ     (size_t)(0x400000 / CTRL_MBOX_MAX_PF)

/* Names of Hardware non-queue generic interrupts */
static char *cnxk_non_ioq_msix_names[] = {
	"epf_ire_rint", "epf_ore_rint", "epf_vfire_rint", "epf_rsvd0", "epf_vfore_rint",
	"epf_rsvd1", "epf_mbox_rint", "epf_rsvd2_0", "epf_rsvd2_1", "epf_dma_rint",
	"epf_dma_vf_rint", "epf_rsvd3", "epf_pp_vf_rint", "epf_rsvd3", "epf_misc_rint", "epf_rsvd5",
	/* Next 16 are for OEI_RINT */
	"epf_oei_rint0", "epf_oei_rint1", "epf_oei_rint2", "epf_oei_rint3", "epf_oei_rint4",
	"epf_oei_rint5", "epf_oei_rint6", "epf_oei_rint7", "epf_oei_rint8", "epf_oei_rint9",
	"epf_oei_rint10", "epf_oei_rint11", "epf_oei_rint12", "epf_oei_rint13", "epf_oei_rint14",
	"epf_oei_rint15",
	/* IOQ interrupt */
	"octeon_ep"};

/* Dump useful hardware CSRs for debug purpose */
static void
cnxk_dump_regs(struct octep_sdp_dev *octep_dev, int qno)
{
	struct device *dev = &octep_dev->pdev->dev;

	dev_info(dev, "IQ-%d register dump\n", qno);
	dev_info(dev, "R[%d]_IN_INSTR_DBELL[0x%llx]: 0x%016llx\n", qno,
		 CNXK_SDP_R_IN_INSTR_DBELL(qno),
		 octep_read_csr64(octep_dev, CNXK_SDP_R_IN_INSTR_DBELL(qno)));
	dev_info(dev, "R[%d]_IN_CONTROL[0x%llx]: 0x%016llx\n", qno, CNXK_SDP_R_IN_CONTROL(qno),
		 octep_read_csr64(octep_dev, CNXK_SDP_R_IN_CONTROL(qno)));
	dev_info(dev, "R[%d]_IN_ENABLE[0x%llx]: 0x%016llx\n", qno, CNXK_SDP_R_IN_ENABLE(qno),
		 octep_read_csr64(octep_dev, CNXK_SDP_R_IN_ENABLE(qno)));
	dev_info(dev, "R[%d]_IN_INSTR_BADDR[0x%llx]: 0x%016llx\n", qno,
		 CNXK_SDP_R_IN_INSTR_BADDR(qno),
		 octep_read_csr64(octep_dev, CNXK_SDP_R_IN_INSTR_BADDR(qno)));
	dev_info(dev, "R[%d]_IN_INSTR_RSIZE[0x%llx]: 0x%016llx\n", qno,
		 CNXK_SDP_R_IN_INSTR_RSIZE(qno),
		 octep_read_csr64(octep_dev, CNXK_SDP_R_IN_INSTR_RSIZE(qno)));
	dev_info(dev, "R[%d]_IN_CNTS[0x%llx]: 0x%016llx\n", qno, CNXK_SDP_R_IN_CNTS(qno),
		 octep_read_csr64(octep_dev, CNXK_SDP_R_IN_CNTS(qno)));
	dev_info(dev, "R[%d]_IN_INT_LEVELS[0x%llx]: 0x%016llx\n", qno,
		 CNXK_SDP_R_IN_INT_LEVELS(qno),
		 octep_read_csr64(octep_dev, CNXK_SDP_R_IN_INT_LEVELS(qno)));
	dev_info(dev, "R[%d]_IN_PKT_CNT[0x%llx]: 0x%016llx\n", qno, CNXK_SDP_R_IN_PKT_CNT(qno),
		 octep_read_csr64(octep_dev, CNXK_SDP_R_IN_PKT_CNT(qno)));
	dev_info(dev, "R[%d]_IN_BYTE_CNT[0x%llx]: 0x%016llx\n", qno, CNXK_SDP_R_IN_BYTE_CNT(qno),
		 octep_read_csr64(octep_dev, CNXK_SDP_R_IN_BYTE_CNT(qno)));

	dev_info(dev, "OQ-%d register dump\n", qno);
	dev_info(dev, "R[%d]_OUT_SLIST_DBELL[0x%llx]: 0x%016llx\n", qno,
		 CNXK_SDP_R_OUT_SLIST_DBELL(qno),
		 octep_read_csr64(octep_dev, CNXK_SDP_R_OUT_SLIST_DBELL(qno)));
	dev_info(dev, "R[%d]_OUT_CONTROL[0x%llx]: 0x%016llx\n", qno, CNXK_SDP_R_OUT_CONTROL(qno),
		 octep_read_csr64(octep_dev, CNXK_SDP_R_OUT_CONTROL(qno)));
	dev_info(dev, "R[%d]_OUT_ENABLE[0x%llx]: 0x%016llx\n", qno, CNXK_SDP_R_OUT_ENABLE(qno),
		 octep_read_csr64(octep_dev, CNXK_SDP_R_OUT_ENABLE(qno)));
	dev_info(dev, "R[%d]_OUT_SLIST_BADDR[0x%llx]: 0x%016llx\n", qno,
		 CNXK_SDP_R_OUT_SLIST_BADDR(qno),
		 octep_read_csr64(octep_dev, CNXK_SDP_R_OUT_SLIST_BADDR(qno)));
	dev_info(dev, "R[%d]_OUT_SLIST_RSIZE[0x%llx]: 0x%016llx\n", qno,
		 CNXK_SDP_R_OUT_SLIST_RSIZE(qno),
		 octep_read_csr64(octep_dev, CNXK_SDP_R_OUT_SLIST_RSIZE(qno)));
	dev_info(dev, "R[%d]_OUT_CNTS[0x%llx]: 0x%016llx\n", qno, CNXK_SDP_R_OUT_CNTS(qno),
		 octep_read_csr64(octep_dev, CNXK_SDP_R_OUT_CNTS(qno)));
	dev_info(dev, "R[%d]_OUT_INT_LEVELS[0x%llx]: 0x%016llx\n", qno,
		 CNXK_SDP_R_OUT_INT_LEVELS(qno),
		 octep_read_csr64(octep_dev, CNXK_SDP_R_OUT_INT_LEVELS(qno)));
	dev_info(dev, "R[%d]_OUT_PKT_CNT[0x%llx]: 0x%016llx\n", qno, CNXK_SDP_R_OUT_PKT_CNT(qno),
		 octep_read_csr64(octep_dev, CNXK_SDP_R_OUT_PKT_CNT(qno)));
	dev_info(dev, "R[%d]_OUT_BYTE_CNT[0x%llx]: 0x%016llx\n", qno, CNXK_SDP_R_OUT_BYTE_CNT(qno),
		 octep_read_csr64(octep_dev, CNXK_SDP_R_OUT_BYTE_CNT(qno)));
	dev_info(dev, "R[%d]_ERR_TYPE[0x%llx]: 0x%016llx\n", qno, CNXK_SDP_R_ERR_TYPE(qno),
		 octep_read_csr64(octep_dev, CNXK_SDP_R_ERR_TYPE(qno)));
}

/* Reset Hardware Tx queue */
static int
cnxk_reset_iq(struct octep_sdp_dev *octep_dev, int q_no)
{
	struct octep_config *conf = octep_dev->conf;
	u64 val = 0ULL;

	dev_dbg(&octep_dev->pdev->dev, "Reset PF IQ-%d\n", q_no);

	/* Get absolute queue number */
	q_no += conf->ring_cfg.srn;

	/* Disable the Tx/Instruction Ring */
	octep_write_csr64(octep_dev, CNXK_SDP_R_IN_ENABLE(q_no), val);

	/* clear the Instruction Ring packet/byte counts and doorbell CSRs */
	octep_write_csr64(octep_dev, CNXK_SDP_R_IN_CNTS(q_no), val);
	octep_write_csr64(octep_dev, CNXK_SDP_R_IN_INT_LEVELS(q_no), val);
	octep_write_csr64(octep_dev, CNXK_SDP_R_IN_PKT_CNT(q_no), val);
	octep_write_csr64(octep_dev, CNXK_SDP_R_IN_BYTE_CNT(q_no), val);
	octep_write_csr64(octep_dev, CNXK_SDP_R_IN_INSTR_BADDR(q_no), val);
	octep_write_csr64(octep_dev, CNXK_SDP_R_IN_INSTR_RSIZE(q_no), val);

	val = 0xFFFFFFFF;
	octep_write_csr64(octep_dev, CNXK_SDP_R_IN_INSTR_DBELL(q_no), val);

	return 0;
}

/* Reset Hardware Rx queue */
static void
cnxk_reset_oq(struct octep_sdp_dev *octep_dev, int q_no)
{
	u64 val = 0ULL;

	q_no += CFG_GET_PORTS_PF_SRN(octep_dev->conf);

	/* Disable Output (Rx) Ring */
	octep_write_csr64(octep_dev, CNXK_SDP_R_OUT_ENABLE(q_no), val);
	octep_write_csr64(octep_dev, CNXK_SDP_R_OUT_SLIST_BADDR(q_no), val);
	octep_write_csr64(octep_dev, CNXK_SDP_R_OUT_SLIST_RSIZE(q_no), val);
	octep_write_csr64(octep_dev, CNXK_SDP_R_OUT_INT_LEVELS(q_no), val);

	/* Clear count CSRs */
	val = octep_read_csr(octep_dev, CNXK_SDP_R_OUT_CNTS(q_no));
	octep_write_csr(octep_dev, CNXK_SDP_R_OUT_CNTS(q_no), val);

	octep_write_csr64(octep_dev, CNXK_SDP_R_OUT_PKT_CNT(q_no), 0xFFFFFFFFFULL);
	octep_write_csr64(octep_dev, CNXK_SDP_R_OUT_SLIST_DBELL(q_no), 0xFFFFFFFF);
}

/* Reset all hardware Tx/Rx queues */
static void
octep_reset_io_queues_cnxk_pf(struct octep_sdp_dev *octep_dev)
{
	struct pci_dev *pdev = octep_dev->pdev;
	int q;

	dev_dbg(&pdev->dev, "Reset OCTEP_CNXK PF IO Queues\n");

	for (q = 0; q < CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf); q++) {
		cnxk_reset_iq(octep_dev, q);
		cnxk_reset_oq(octep_dev, q);
	}
}

static void
octep_reset_iqueue_cnxk_pf(struct octep_sdp_dev *octep_dev, int q_no)
{
	cnxk_reset_iq(octep_dev, q_no);
}

/* Initialize windowed addresses to access some hardware registers */
static void
octep_setup_pci_window_regs_cnxk_pf(struct octep_sdp_dev *octep_dev)
{
	u8 __iomem *bar0_pciaddr = octep_dev->mmio[0].hw_addr;

	octep_dev->pci_win_regs.pci_win_wr_addr =
		(u8 __iomem *)(bar0_pciaddr + CNXK_SDP_WIN_WR_ADDR64);
	octep_dev->pci_win_regs.pci_win_rd_addr =
		(u8 __iomem *)(bar0_pciaddr + CNXK_SDP_WIN_RD_ADDR64);
	octep_dev->pci_win_regs.pci_win_wr_data =
		(u8 __iomem *)(bar0_pciaddr + CNXK_SDP_WIN_WR_DATA64);
	octep_dev->pci_win_regs.pci_win_rd_data =
		(u8 __iomem *)(bar0_pciaddr + CNXK_SDP_WIN_RD_DATA64);
}

/* Configure Hardware mapping: inform hardware which rings belong to PF. */
static void
octep_configure_ring_mapping_cnxk_pf(struct octep_sdp_dev *octep_dev)
{
	struct octep_config *conf = octep_dev->conf;
	struct pci_dev *pdev = octep_dev->pdev;
	u64 pf_srn = CFG_GET_PORTS_PF_SRN(octep_dev->conf);
	int q;

	for (q = 0; q < CFG_GET_PORTS_ACTIVE_IO_RINGS(conf); q++) {
		u64 regval = 0;

		if (octep_dev->pcie_port)
			regval = 8 << CNXK_SDP_FUNC_SEL_EPF_BIT_POS;

		octep_write_csr64(octep_dev, CNXK_SDP_EPVF_RING(pf_srn + q), regval);

		regval = octep_read_csr64(octep_dev, CNXK_SDP_EPVF_RING(pf_srn + q));
		dev_dbg(&pdev->dev, "Write SDP_EPVF_RING[0x%llx] = 0x%llx\n",
			CNXK_SDP_EPVF_RING(pf_srn + q), regval);
	}
}

static int
octep_update_config_active_io_rings(struct octep_sdp_dev *octep_dev, u8 enable)
{
	struct octep_config *conf = octep_dev->conf;

	if (conf->ring_cfg.max_io_rings < conf->ring_cfg.active_io_rings + 1) {
		dev_err(&octep_dev->pdev->dev, "Max IO rings reached\n");
		return -1;
	}

	if (enable)
		conf->ring_cfg.active_io_rings += 1;
	else
		conf->ring_cfg.active_io_rings -= 1;
	dev_info(&octep_dev->pdev->dev, "pf_srn=%u rppf=%u\n", conf->ring_cfg.srn,
		 conf->ring_cfg.active_io_rings);

	return 0;
}

/* Initialize configuration limits and initial active config */
static void
octep_init_config_cnxk_pf(struct octep_sdp_dev *octep_dev)
{
	struct octep_config *conf = octep_dev->conf;
	struct pci_dev *pdev = octep_dev->pdev;
	u64 val;
	int pos;
	u8 link = 0;

	/* Read ring configuration:
	 * PF ring count, number of VFs and rings per VF supported
	 */
	val = octep_read_csr64(octep_dev, CNXK_SDP_EPF_RINFO);
	dev_info(&pdev->dev, "SDP_EPF_RINFO[0x%x]:0x%llx\n", CNXK_SDP_EPF_RINFO, val);
	conf->sriov_cfg.max_rings_per_vf = CNXK_SDP_EPF_RINFO_RPVF(val);
	conf->sriov_cfg.active_rings_per_vf = conf->sriov_cfg.max_rings_per_vf;
	conf->sriov_cfg.max_vfs = CNXK_SDP_EPF_RINFO_NVFS(val);
	conf->sriov_cfg.active_vfs = 0;
	conf->sriov_cfg.vf_srn = CNXK_SDP_EPF_RINFO_SRN(val);

	val = octep_read_csr64(octep_dev, CNXK_SDP_MAC_PF_RING_CTL(octep_dev->pcie_port));
	dev_info(&pdev->dev, "SDP_MAC_PF_RING_CTL[%d]:0x%llx\n", octep_dev->pcie_port, val);
	conf->ring_cfg.srn = CNXK_SDP_MAC_PF_RING_CTL_SRN(val);
	conf->ring_cfg.max_io_rings = CNXK_SDP_MAC_PF_RING_CTL_RPPF(val);
	conf->ring_cfg.active_io_rings = conf->ring_cfg.max_io_rings;
	conf->ring_cfg.active_io_rings = 1;
	dev_info(&pdev->dev, "pf_srn=%u rpvf=%u nvfs=%u rppf=%u\n", conf->ring_cfg.srn,
		 conf->sriov_cfg.active_rings_per_vf, conf->sriov_cfg.active_vfs,
		 conf->ring_cfg.active_io_rings);

	conf->iq.num_descs = OCTEP_IQ_MAX_DESCRIPTORS;
	conf->iq.instr_type = OCTEP_64BYTE_INSTR;
	conf->iq.db_min = OCTEP_DB_MIN;
	conf->iq.intr_threshold = OCTEP_IQ_INTR_THRESHOLD;

	conf->oq.num_descs = OCTEP_OQ_MAX_DESCRIPTORS;
	conf->oq.buf_size = OCTEP_OQ_BUF_SIZE;
	conf->oq.refill_threshold = OCTEP_OQ_REFILL_THRESHOLD;
	conf->oq.oq_intr_pkt = OCTEP_OQ_INTR_PKT_THRESHOLD;
	conf->oq.oq_intr_time = OCTEP_OQ_INTR_TIME_THRESHOLD;
	conf->oq.wmark = OCTEP_OQ_WMARK_MIN;

	conf->msix_cfg.non_ioq_msix = CNXK_NUM_NON_IOQ_INTR;
	conf->msix_cfg.ioq_msix = conf->ring_cfg.active_io_rings;
	conf->msix_cfg.non_ioq_msix_names = cnxk_non_ioq_msix_names;

	pos = pci_find_ext_capability(octep_dev->pdev, PCI_EXT_CAP_ID_SRIOV);
	if (pos) {
		pci_read_config_byte(octep_dev->pdev, pos + PCI_SRIOV_FUNC_LINK, &link);
		link = PCI_DEVFN(PCI_SLOT(octep_dev->pdev->devfn), link);
	}
	conf->ctrl_mbox_cfg.barmem_addr = (void __iomem *)octep_dev->mmio[2].hw_addr +
					  CNXK_PEM_BAR4_INDEX_OFFSET + (link * CTRL_MBOX_SZ);

	conf->fw_info.hb_interval = OCTEP_DEFAULT_FW_HB_INTERVAL;
	conf->fw_info.hb_miss_count = OCTEP_DEFAULT_FW_HB_MISS_COUNT;
}

/* Setup registers for a hardware Tx Queue  */
static void
octep_setup_iq_regs_cnxk_pf(struct octep_sdp_dev *octep_dev, int iq_no)
{
	struct octep_iq *iq = octep_dev->iq[iq_no];
	u32 reset_instr_cnt;
	u64 reg_val;

	iq_no += CFG_GET_PORTS_PF_SRN(octep_dev->conf);
	reg_val = octep_read_csr64(octep_dev, CNXK_SDP_R_IN_CONTROL(iq_no));

	/* wait for IDLE to set to 1 */
	if (!(reg_val & CNXK_R_IN_CTL_IDLE)) {
		do {
			reg_val = octep_read_csr64(octep_dev, CNXK_SDP_R_IN_CONTROL(iq_no));
		} while (!(reg_val & CNXK_R_IN_CTL_IDLE));
	}

	reg_val |= CNXK_R_IN_CTL_RDSIZE;
	reg_val |= CNXK_R_IN_CTL_IS_64B;
	reg_val |= CNXK_R_IN_CTL_ESR;
	octep_write_csr64(octep_dev, CNXK_SDP_R_IN_CONTROL(iq_no), reg_val);

	/* Write the start of the input queue's ring and its size  */
	octep_write_csr64(octep_dev, CNXK_SDP_R_IN_INSTR_BADDR(iq_no), iq->desc_ring_dma);
	octep_write_csr64(octep_dev, CNXK_SDP_R_IN_INSTR_RSIZE(iq_no), iq->max_count);

	/* Remember the doorbell & instruction count register addr
	 * for this queue
	 */
	iq->doorbell_reg = octep_dev->mmio[0].hw_addr + CNXK_SDP_R_IN_INSTR_DBELL(iq_no);
	iq->inst_cnt_reg = octep_dev->mmio[0].hw_addr + CNXK_SDP_R_IN_CNTS(iq_no);
	iq->intr_lvl_reg = octep_dev->mmio[0].hw_addr + CNXK_SDP_R_IN_INT_LEVELS(iq_no);

	/* Store the current instruction counter (used in flush_iq calculation) */
	reset_instr_cnt = readl(iq->inst_cnt_reg);
	writel(reset_instr_cnt, iq->inst_cnt_reg);

	/* INTR_THRESHOLD is set to max(FFFFFFFF) to disable the INTR */
	reg_val = CFG_GET_IQ_INTR_THRESHOLD(octep_dev->conf) & 0xffffffff;
	octep_write_csr64(octep_dev, CNXK_SDP_R_IN_INT_LEVELS(iq_no), reg_val);
}

/* Setup registers for a hardware Rx Queue  */
static int
octep_setup_oq_regs_cnxk_pf(struct octep_sdp_dev *octep_dev, int oq_no)
{
	u64 reg_val;
	u64 oq_ctl = 0ULL;
	u64 reg_ba_val;
	u32 time_threshold = 0;
	struct octep_oq *oq = octep_dev->oq[oq_no];

	oq_no += CFG_GET_PORTS_PF_SRN(octep_dev->conf);
	reg_val = octep_read_csr64(octep_dev, CNXK_SDP_R_OUT_CONTROL(oq_no));

	/* wait for IDLE to set to 1 */
	if (!(reg_val & CNXK_R_OUT_CTL_IDLE)) {
		do {
			reg_val = octep_read_csr64(octep_dev, CNXK_SDP_R_OUT_CONTROL(oq_no));
		} while (!(reg_val & CNXK_R_OUT_CTL_IDLE));
	}
	octep_write_csr64(octep_dev, CNXK_SDP_R_OUT_WMARK(oq_no), oq->max_count);
	/* Wait for WMARK to get applied */
	usleep_range(10, 20);

	octep_write_csr64(octep_dev, CNXK_SDP_R_OUT_SLIST_BADDR(oq_no), oq->desc_ring_dma);
	octep_write_csr64(octep_dev, CNXK_SDP_R_OUT_SLIST_RSIZE(oq_no), oq->max_count);
	reg_ba_val = octep_read_csr64(octep_dev, CNXK_SDP_R_OUT_SLIST_BADDR(oq_no));
	if (reg_ba_val != oq->desc_ring_dma) {
		do {
			if (reg_ba_val == UINT64_MAX)
				return -1;
			octep_write_csr64(octep_dev, CNXK_SDP_R_OUT_SLIST_BADDR(oq_no),
					  oq->desc_ring_dma);
			octep_write_csr64(octep_dev, CNXK_SDP_R_OUT_SLIST_RSIZE(oq_no),
					  oq->max_count);
			reg_ba_val = octep_read_csr64(octep_dev, CNXK_SDP_R_OUT_SLIST_BADDR(oq_no));
		} while (reg_ba_val != oq->desc_ring_dma);
	}

	reg_val &= ~(CNXK_R_OUT_CTL_IMODE);
	reg_val &= ~(CNXK_R_OUT_CTL_ROR_P);
	reg_val &= ~(CNXK_R_OUT_CTL_NSR_P);
	reg_val &= ~(CNXK_R_OUT_CTL_ROR_I);
	reg_val &= ~(CNXK_R_OUT_CTL_NSR_I);
	reg_val &= ~(CNXK_R_OUT_CTL_ES_I);
	reg_val &= ~(CNXK_R_OUT_CTL_ROR_D);
	reg_val &= ~(CNXK_R_OUT_CTL_NSR_D);
	reg_val &= ~(CNXK_R_OUT_CTL_ES_D);
	reg_val |= (CNXK_R_OUT_CTL_ES_P);

	octep_write_csr64(octep_dev, CNXK_SDP_R_OUT_CONTROL(oq_no), reg_val);

	oq_ctl = octep_read_csr64(octep_dev, CNXK_SDP_R_OUT_CONTROL(oq_no));

	/* Clear the ISIZE and BSIZE (22-0) */
	oq_ctl &= ~0x7fffffULL;

	/* Populate the BSIZE (15-0) */
	oq_ctl |= (oq->buffer_size & 0xffff);
	octep_write_csr64(octep_dev, CNXK_SDP_R_OUT_CONTROL(oq_no), oq_ctl);

	/* Get the mapped address of the pkt_sent and pkts_credit regs */
	oq->pkts_sent_reg = octep_dev->mmio[0].hw_addr + CNXK_SDP_R_OUT_CNTS(oq_no);
	oq->pkts_credit_reg = octep_dev->mmio[0].hw_addr + CNXK_SDP_R_OUT_SLIST_DBELL(oq_no);

	time_threshold = CFG_GET_OQ_INTR_TIME(octep_dev->conf);
	reg_val = ((u64)time_threshold << 32) | CFG_GET_OQ_INTR_PKT(octep_dev->conf);
	octep_write_csr64(octep_dev, CNXK_SDP_R_OUT_INT_LEVELS(oq_no), reg_val);

	/* set watermark for backpressure */
	reg_val = octep_read_csr64(octep_dev, CNXK_SDP_R_OUT_WMARK(oq_no));
	reg_val &= ~0xFFFFFFFFULL;
	reg_val |= CFG_GET_OQ_WMARK(octep_dev->conf);
	octep_write_csr64(octep_dev, CNXK_SDP_R_OUT_WMARK(oq_no), reg_val);

	return 0;
}

/* OEI interrupt handler */
static irqreturn_t
octep_oei_intr_handler_cnxk_pf(void *dev)
{
	struct octep_sdp_dev *octep_dev = (struct octep_sdp_dev *)dev;

	dev_info(&octep_dev->pdev->dev, "Received OEI_RINT intr\n");
	return IRQ_HANDLED;
}

static void
octep_poll_non_ioq_interrupts_cnxk_pf(struct octep_sdp_dev *octep_dev)
{
	dev_info(&octep_dev->pdev->dev, "Polling non-ioq interrupts\n");
}

/* Interrupt handler for input ring error interrupts. */
static irqreturn_t
octep_ire_intr_handler_cnxk_pf(void *dev)
{
	struct octep_sdp_dev *octep_dev = (struct octep_sdp_dev *)dev;
	struct pci_dev *pdev = octep_dev->pdev;
	u64 reg_val = 0;
	int i = 0;

	/* Check for IRERR INTR */
	reg_val = octep_read_csr64(octep_dev, CNXK_SDP_EPF_IRERR_RINT);
	if (reg_val) {
		dev_info(&pdev->dev, "received IRERR_RINT intr: 0x%llx\n", reg_val);
		octep_write_csr64(octep_dev, CNXK_SDP_EPF_IRERR_RINT, reg_val);

		for (i = 0; i < CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf); i++) {
			reg_val = octep_read_csr64(octep_dev, CNXK_SDP_R_ERR_TYPE(i));
			if (reg_val) {
				dev_info(&pdev->dev, "Received err type on IQ-%d: 0x%llx\n", i,
					 reg_val);
				octep_write_csr64(octep_dev, CNXK_SDP_R_ERR_TYPE(i), reg_val);
			}
		}
	}
	return IRQ_HANDLED;
}

/* Interrupt handler for output ring error interrupts. */
static irqreturn_t
octep_ore_intr_handler_cnxk_pf(void *dev)
{
	struct octep_sdp_dev *octep_dev = (struct octep_sdp_dev *)dev;
	struct pci_dev *pdev = octep_dev->pdev;
	u64 reg_val = 0;
	int i = 0;

	/* Check for ORERR INTR */
	reg_val = octep_read_csr64(octep_dev, CNXK_SDP_EPF_ORERR_RINT);
	if (reg_val) {
		dev_info(&pdev->dev, "Received ORERR_RINT intr: 0x%llx\n", reg_val);
		octep_write_csr64(octep_dev, CNXK_SDP_EPF_ORERR_RINT, reg_val);
		for (i = 0; i < CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf); i++) {
			reg_val = octep_read_csr64(octep_dev, CNXK_SDP_R_ERR_TYPE(i));
			if (reg_val) {
				dev_info(&pdev->dev, "Received err type on OQ-%d: 0x%llx\n", i,
					 reg_val);
				octep_write_csr64(octep_dev, CNXK_SDP_R_ERR_TYPE(i), reg_val);
			}
		}
	}
	return IRQ_HANDLED;
}

/* Interrupt handler for vf input ring error interrupts. */
static irqreturn_t
octep_vfire_intr_handler_cnxk_pf(void *dev)
{
	struct octep_sdp_dev *octep_dev = (struct octep_sdp_dev *)dev;
	struct pci_dev *pdev = octep_dev->pdev;
	u64 reg_val = 0;

	/* Check for VFIRE INTR */
	reg_val = octep_read_csr64(octep_dev, CNXK_SDP_EPF_VFIRE_RINT(0));
	if (reg_val) {
		dev_info(&pdev->dev, "Received VFIRE_RINT intr: 0x%llx\n", reg_val);
		octep_write_csr64(octep_dev, CNXK_SDP_EPF_VFIRE_RINT(0), reg_val);
	}
	return IRQ_HANDLED;
}

/* Interrupt handler for vf output ring error interrupts. */
static irqreturn_t
octep_vfore_intr_handler_cnxk_pf(void *dev)
{
	struct octep_sdp_dev *octep_dev = (struct octep_sdp_dev *)dev;
	struct pci_dev *pdev = octep_dev->pdev;
	u64 reg_val = 0;

	/* Check for VFORE INTR */
	reg_val = octep_read_csr64(octep_dev, CNXK_SDP_EPF_VFORE_RINT(0));
	if (reg_val) {
		dev_info(&pdev->dev, "Received VFORE_RINT intr: 0x%llx\n", reg_val);
		octep_write_csr64(octep_dev, CNXK_SDP_EPF_VFORE_RINT(0), reg_val);
	}
	return IRQ_HANDLED;
}

/* Interrupt handler for dpi dma related interrupts. */
static irqreturn_t
octep_dma_intr_handler_cnxk_pf(void *dev)
{
	struct octep_sdp_dev *octep_dev = (struct octep_sdp_dev *)dev;
	u64 reg_val = 0;

	/* Check for DMA INTR */
	reg_val = octep_read_csr64(octep_dev, CNXK_SDP_EPF_DMA_RINT);
	if (reg_val)
		octep_write_csr64(octep_dev, CNXK_SDP_EPF_DMA_RINT, reg_val);

	return IRQ_HANDLED;
}

/* Interrupt handler for dpi dma transaction error interrupts for VFs  */
static irqreturn_t
octep_dma_vf_intr_handler_cnxk_pf(void *dev)
{
	struct octep_sdp_dev *octep_dev = (struct octep_sdp_dev *)dev;
	struct pci_dev *pdev = octep_dev->pdev;
	u64 reg_val = 0;

	/* Check for DMA VF INTR */
	reg_val = octep_read_csr64(octep_dev, CNXK_SDP_EPF_DMA_VF_RINT(0));
	if (reg_val) {
		dev_info(&pdev->dev, "Received DMA_VF_RINT intr: 0x%llx\n", reg_val);
		octep_write_csr64(octep_dev, CNXK_SDP_EPF_DMA_VF_RINT(0), reg_val);
	}
	return IRQ_HANDLED;
}

/* Interrupt handler for pp transaction error interrupts for VFs  */
static irqreturn_t
octep_pp_vf_intr_handler_cnxk_pf(void *dev)
{
	struct octep_sdp_dev *octep_dev = (struct octep_sdp_dev *)dev;
	struct pci_dev *pdev = octep_dev->pdev;
	u64 reg_val = 0;

	/* Check for PPVF INTR */
	reg_val = octep_read_csr64(octep_dev, CNXK_SDP_EPF_PP_VF_RINT(0));
	if (reg_val) {
		dev_info(&pdev->dev, "Received PP_VF_RINT intr: 0x%llx\n", reg_val);
		octep_write_csr64(octep_dev, CNXK_SDP_EPF_PP_VF_RINT(0), reg_val);
	}
	return IRQ_HANDLED;
}

/* Interrupt handler for mac related interrupts. */
static irqreturn_t
octep_misc_intr_handler_cnxk_pf(void *dev)
{
	struct octep_sdp_dev *octep_dev = (struct octep_sdp_dev *)dev;
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
	struct octep_sdp_dev *octep_dev = (struct octep_sdp_dev *)dev;
	struct pci_dev *pdev = octep_dev->pdev;

	dev_info(&pdev->dev, "Reserved interrupts raised; Ignore\n");
	return IRQ_HANDLED;
}

/* Tx/Rx queue interrupt handler */
static irqreturn_t
octep_ioq_intr_handler_cnxk_pf(void *data)
{
	struct octep_ioq_vector *vector = (struct octep_ioq_vector *)data;
	struct octep_oq *oq;

	if (!vector)
		return IRQ_HANDLED;
	oq = vector->oq;

	if (!oq)
		return IRQ_HANDLED;

	if (!(oq->napi))
		return IRQ_HANDLED;

	napi_schedule_irqoff(oq->napi);
	return IRQ_HANDLED;
}

/* soft reset */
static int
octep_soft_reset_cnxk_pf(struct octep_sdp_dev *octep_dev)
{
	dev_info(&octep_dev->pdev->dev, "CNXKXX: Doing soft reset\n");

	octep_write_csr64(octep_dev, CNXK_SDP_WIN_WR_MASK_REG, 0xFF);

	OCTEP_PCI_WIN_WRITE(octep_dev, CNXK_PEMX_PFX_CSX_PFCFGX(0, 0, CNXK_PCIEEP_VSECST_CTL),
			    FW_STATUS_DOWNING);

	/* Set chip domain reset bit */
	OCTEP_PCI_WIN_WRITE(octep_dev, CNXK_RST_CHIP_DOMAIN_W1S, 1);
	/* Wait till Octeon resets. */
	mdelay(10);
	/* restore the  reset value */
	octep_write_csr64(octep_dev, CNXK_SDP_WIN_WR_MASK_REG, 0xFF);

	return 0;
}

/* Re-initialize Octeon hardware registers */
static void
octep_reinit_regs_cnxk_pf(struct octep_sdp_dev *octep_dev)
{
	u32 i;

	for (i = 0; i < CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf); i++)
		octep_dev->hw_ops.setup_iq_regs(octep_dev, i);

	for (i = 0; i < CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf); i++)
		octep_dev->hw_ops.setup_oq_regs(octep_dev, i);

	octep_dev->hw_ops.enable_interrupts(octep_dev);
	octep_dev->hw_ops.enable_io_queues(octep_dev);

	for (i = 0; i < CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf); i++)
		writel(octep_dev->oq[i]->max_count, octep_dev->oq[i]->pkts_credit_reg);
}

/* Enable all interrupts */
static void
octep_enable_interrupts_cnxk_pf(struct octep_sdp_dev *octep_dev)
{
	u64 intr_mask = 0ULL;
	int srn, num_rings, i;

	srn = CFG_GET_PORTS_PF_SRN(octep_dev->conf);
	num_rings = CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf);

	for (i = 0; i < num_rings; i++)
		intr_mask |= (0x1ULL << (srn + i));

	octep_write_csr64(octep_dev, CNXK_SDP_EPF_IRERR_RINT_ENA_W1S, intr_mask);
	octep_write_csr64(octep_dev, CNXK_SDP_EPF_ORERR_RINT_ENA_W1S, intr_mask);
	octep_write_csr64(octep_dev, CNXK_SDP_EPF_OEI_RINT_ENA_W1S, -1ULL);

	octep_write_csr64(octep_dev, CNXK_SDP_EPF_VFIRE_RINT_ENA_W1S(0), -1ULL);
	octep_write_csr64(octep_dev, CNXK_SDP_EPF_VFORE_RINT_ENA_W1S(0), -1ULL);

	octep_write_csr64(octep_dev, CNXK_SDP_EPF_MISC_RINT_ENA_W1S, intr_mask);
	octep_write_csr64(octep_dev, CNXK_SDP_EPF_DMA_RINT_ENA_W1S, intr_mask);
	octep_write_csr64(octep_dev, CNXK_SDP_EPF_MBOX_RINT_ENA_W1S(0), -1ULL);

	octep_write_csr64(octep_dev, CNXK_SDP_EPF_DMA_VF_RINT_ENA_W1S(0), -1ULL);
	octep_write_csr64(octep_dev, CNXK_SDP_EPF_PP_VF_RINT_ENA_W1S(0), -1ULL);
}

/* Disable all interrupts */
static void
octep_disable_interrupts_cnxk_pf(struct octep_sdp_dev *octep_dev)
{
	u64 reg_val, intr_mask = 0ULL;
	int srn, num_rings, i;

	srn = CFG_GET_PORTS_PF_SRN(octep_dev->conf);
	num_rings = CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf);

	for (i = 0; i < num_rings; i++) {
		intr_mask |= (0x1ULL << (srn + i));
		reg_val = octep_read_csr64(octep_dev, CNXK_SDP_R_IN_INT_LEVELS(srn + i));
		reg_val &= ~(0x1ULL << 62);
		octep_write_csr64(octep_dev, CNXK_SDP_R_IN_INT_LEVELS(srn + i), reg_val);

		reg_val = octep_read_csr64(octep_dev, CNXK_SDP_R_OUT_INT_LEVELS(srn + i));
		reg_val &= ~(0x1ULL << 62);
		octep_write_csr64(octep_dev, CNXK_SDP_R_OUT_INT_LEVELS(srn + i), reg_val);
	}

	octep_write_csr64(octep_dev, CNXK_SDP_EPF_IRERR_RINT_ENA_W1C, intr_mask);
	octep_write_csr64(octep_dev, CNXK_SDP_EPF_ORERR_RINT_ENA_W1C, intr_mask);
	octep_write_csr64(octep_dev, CNXK_SDP_EPF_OEI_RINT_ENA_W1C, -1ULL);

	octep_write_csr64(octep_dev, CNXK_SDP_EPF_VFIRE_RINT_ENA_W1C(0), -1ULL);
	octep_write_csr64(octep_dev, CNXK_SDP_EPF_VFORE_RINT_ENA_W1C(0), -1ULL);

	octep_write_csr64(octep_dev, CNXK_SDP_EPF_MISC_RINT_ENA_W1C, intr_mask);
	octep_write_csr64(octep_dev, CNXK_SDP_EPF_DMA_RINT_ENA_W1C, intr_mask);
	octep_write_csr64(octep_dev, CNXK_SDP_EPF_MBOX_RINT_ENA_W1C(0), -1ULL);

	octep_write_csr64(octep_dev, CNXK_SDP_EPF_DMA_VF_RINT_ENA_W1C(0), -1ULL);
	octep_write_csr64(octep_dev, CNXK_SDP_EPF_PP_VF_RINT_ENA_W1C(0), -1ULL);
}

/* Get new Octeon Read Index: index of descriptor that Octeon reads next. */
static u32
octep_update_iq_read_index_cnxk_pf(struct octep_iq *iq)
{
	u32 pkt_in_done = readl(iq->inst_cnt_reg);
	u32 last_done, new_idx;

	if (unlikely(pkt_in_done == 0xFFFFFFFF)) {
		last_done = 0;
		dev_err_ratelimited(iq->dev, "IQ-%u count read failure\n", iq->q_no);
	} else {
		last_done = pkt_in_done - iq->pkt_in_done;
		iq->pkt_in_done = pkt_in_done;
	}

	new_idx = (iq->octep_read_index + last_done) % iq->max_count;

	return new_idx;
}

/* Enable a hardware Tx Queue */
static void
octep_enable_iq_cnxk_pf(struct octep_sdp_dev *octep_dev, int iq_no)
{
	u64 loop = HZ;
	u64 reg_val;

	iq_no += CFG_GET_PORTS_PF_SRN(octep_dev->conf);

	octep_write_csr64(octep_dev, CNXK_SDP_R_IN_INSTR_DBELL(iq_no), 0xFFFFFFFF);

	while (octep_read_csr64(octep_dev, CNXK_SDP_R_IN_INSTR_DBELL(iq_no)) && loop--)
		schedule_timeout_interruptible(1);

	reg_val = octep_read_csr64(octep_dev, CNXK_SDP_R_IN_INT_LEVELS(iq_no));
	reg_val |= (0x1ULL << 62);
	octep_write_csr64(octep_dev, CNXK_SDP_R_IN_INT_LEVELS(iq_no), reg_val);

	reg_val = octep_read_csr64(octep_dev, CNXK_SDP_R_IN_ENABLE(iq_no));
	reg_val |= 0x1ULL;
	octep_write_csr64(octep_dev, CNXK_SDP_R_IN_ENABLE(iq_no), reg_val);
}

/* Enable a hardware Rx Queue */
static void
octep_enable_oq_cnxk_pf(struct octep_sdp_dev *octep_dev, int oq_no)
{
	u64 reg_val = 0ULL;

	oq_no += CFG_GET_PORTS_PF_SRN(octep_dev->conf);

	reg_val = octep_read_csr64(octep_dev, CNXK_SDP_R_OUT_INT_LEVELS(oq_no));
	reg_val |= (0x1ULL << 62);
	octep_write_csr64(octep_dev, CNXK_SDP_R_OUT_INT_LEVELS(oq_no), reg_val);

	octep_write_csr64(octep_dev, CNXK_SDP_R_OUT_SLIST_DBELL(oq_no), 0xFFFFFFFF);

	reg_val = octep_read_csr64(octep_dev, CNXK_SDP_R_OUT_ENABLE(oq_no));
	reg_val |= 0x1ULL;
	octep_write_csr64(octep_dev, CNXK_SDP_R_OUT_ENABLE(oq_no), reg_val);
}

/* Enable all hardware Tx/Rx Queues assigned to PF */
static void
octep_enable_io_queues_cnxk_pf(struct octep_sdp_dev *octep_dev)
{
	u8 q;

	for (q = 0; q < CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf); q++) {
		octep_enable_iq_cnxk_pf(octep_dev, q);
		octep_enable_oq_cnxk_pf(octep_dev, q);
	}
}

/* Disable a hardware Tx Queue assigned to PF */
static void
octep_disable_iq_cnxk_pf(struct octep_sdp_dev *octep_dev, int iq_no)
{
	u64 reg_val = 0ULL;

	iq_no += CFG_GET_PORTS_PF_SRN(octep_dev->conf);

	reg_val = octep_read_csr64(octep_dev, CNXK_SDP_R_IN_ENABLE(iq_no));
	reg_val &= ~0x1ULL;
	octep_write_csr64(octep_dev, CNXK_SDP_R_IN_ENABLE(iq_no), reg_val);
}

/* Disable a hardware Rx Queue assigned to PF */
static void
octep_disable_oq_cnxk_pf(struct octep_sdp_dev *octep_dev, int oq_no)
{
	u64 reg_val = 0ULL;

	oq_no += CFG_GET_PORTS_PF_SRN(octep_dev->conf);
	reg_val = octep_read_csr64(octep_dev, CNXK_SDP_R_OUT_ENABLE(oq_no));
	reg_val &= ~0x1ULL;
	octep_write_csr64(octep_dev, CNXK_SDP_R_OUT_ENABLE(oq_no), reg_val);
}

/* Disable all hardware Tx/Rx Queues assigned to PF */
static void
octep_disable_io_queues_cnxk_pf(struct octep_sdp_dev *octep_dev)
{
	int q = 0;

	for (q = 0; q < CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf); q++) {
		octep_disable_iq_cnxk_pf(octep_dev, q);
		octep_disable_oq_cnxk_pf(octep_dev, q);
	}
}

/* Dump hardware registers (including Tx/Rx queues) for debugging. */
static void
octep_dump_registers_cnxk_pf(struct octep_sdp_dev *octep_dev)
{
	u8 srn, num_rings, q;

	srn = CFG_GET_PORTS_PF_SRN(octep_dev->conf);
	num_rings = CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf);

	for (q = srn; q < srn + num_rings; q++)
		cnxk_dump_regs(octep_dev, q);
}

/**
 * octep_sdp_dev_setup_cnxk_pf() - Setup Octeon device.
 *
 * @oct: Octeon device private data structure.
 *
 * - initialize hardware operations.
 * - get target side pcie port number for the device.
 * - setup window access to hardware registers.
 * - set initial configuration and max limits.
 * - setup hardware mapping of rings to the PF device.
 */
void
octep_device_setup_cnxk_pf(struct octep_sdp_dev *octep_dev)
{
	octep_dev->hw_ops.setup_iq_regs = octep_setup_iq_regs_cnxk_pf;
	octep_dev->hw_ops.setup_oq_regs = octep_setup_oq_regs_cnxk_pf;

	octep_dev->hw_ops.oei_intr_handler = octep_oei_intr_handler_cnxk_pf;
	octep_dev->hw_ops.ire_intr_handler = octep_ire_intr_handler_cnxk_pf;
	octep_dev->hw_ops.ore_intr_handler = octep_ore_intr_handler_cnxk_pf;
	octep_dev->hw_ops.vfire_intr_handler = octep_vfire_intr_handler_cnxk_pf;
	octep_dev->hw_ops.vfore_intr_handler = octep_vfore_intr_handler_cnxk_pf;
	octep_dev->hw_ops.dma_intr_handler = octep_dma_intr_handler_cnxk_pf;
	octep_dev->hw_ops.dma_vf_intr_handler = octep_dma_vf_intr_handler_cnxk_pf;
	octep_dev->hw_ops.pp_vf_intr_handler = octep_pp_vf_intr_handler_cnxk_pf;
	octep_dev->hw_ops.misc_intr_handler = octep_misc_intr_handler_cnxk_pf;
	octep_dev->hw_ops.rsvd_intr_handler = octep_rsvd_intr_handler_cnxk_pf;
	octep_dev->hw_ops.ioq_intr_handler = octep_ioq_intr_handler_cnxk_pf;
	octep_dev->hw_ops.soft_reset = octep_soft_reset_cnxk_pf;
	octep_dev->hw_ops.reinit_regs = octep_reinit_regs_cnxk_pf;

	octep_dev->hw_ops.enable_interrupts = octep_enable_interrupts_cnxk_pf;
	octep_dev->hw_ops.disable_interrupts = octep_disable_interrupts_cnxk_pf;
	octep_dev->hw_ops.poll_non_ioq_interrupts = octep_poll_non_ioq_interrupts_cnxk_pf;

	octep_dev->hw_ops.update_iq_read_idx = octep_update_iq_read_index_cnxk_pf;

	octep_dev->hw_ops.enable_iq = octep_enable_iq_cnxk_pf;
	octep_dev->hw_ops.enable_oq = octep_enable_oq_cnxk_pf;
	octep_dev->hw_ops.enable_io_queues = octep_enable_io_queues_cnxk_pf;

	octep_dev->hw_ops.disable_iq = octep_disable_iq_cnxk_pf;
	octep_dev->hw_ops.disable_oq = octep_disable_oq_cnxk_pf;
	octep_dev->hw_ops.disable_io_queues = octep_disable_io_queues_cnxk_pf;
	octep_dev->hw_ops.reset_io_queues = octep_reset_io_queues_cnxk_pf;
	octep_dev->hw_ops.reset_iqueue = octep_reset_iqueue_cnxk_pf;

	octep_dev->hw_ops.dump_registers = octep_dump_registers_cnxk_pf;
	octep_dev->hw_ops.octep_update_config_active_io_ring = octep_update_config_active_io_rings;

	octep_setup_pci_window_regs_cnxk_pf(octep_dev);

	octep_dev->pcie_port = octep_read_csr64(octep_dev, CNXK_SDP_MAC_NUMBER) & 0xff;
	dev_info(&octep_dev->pdev->dev, "Octeon device using PCIE Port %d\n", octep_dev->pcie_port);

	octep_init_config_cnxk_pf(octep_dev);
	octep_configure_ring_mapping_cnxk_pf(octep_dev);

	/* Firmware status CSR is supposed to be cleared by
	 * core domain reset, but due to IPBUPEM-38842, it is not.
	 * Set it to RUNNING early in boot, so that unexpected resets
	 * leave it in a state that is not READY (1).
	 */
	OCTEP_PCI_WIN_WRITE(octep_dev, CNXK_PEMX_PFX_CSX_PFCFGX(0, 0, CNXK_PCIEEP_VSECST_CTL),
			    FW_STATUS_RUNNING);
}

/* Dump useful hardware IQ/OQ CSRs for debug purpose */
static void
cnxk_vf_dump_q_regs(struct octep_sdp_dev *octep_dev, int qno)
{
	struct device *dev = &octep_dev->pdev->dev;

	dev_info(dev, "IQ-%d register dump\n", qno);
	dev_info(dev, "R[%d]_IN_INSTR_DBELL[0x%llx]: 0x%016llx\n", qno,
		 CNXK_VF_SDP_R_IN_INSTR_DBELL(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_IN_INSTR_DBELL(qno)));
	dev_info(dev, "R[%d]_IN_CONTROL[0x%llx]: 0x%016llx\n", qno, CNXK_VF_SDP_R_IN_CONTROL(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_IN_CONTROL(qno)));
	dev_info(dev, "R[%d]_IN_ENABLE[0x%llx]: 0x%016llx\n", qno, CNXK_VF_SDP_R_IN_ENABLE(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_IN_ENABLE(qno)));
	dev_info(dev, "R[%d]_IN_INSTR_BADDR[0x%llx]: 0x%016llx\n", qno,
		 CNXK_VF_SDP_R_IN_INSTR_BADDR(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_IN_INSTR_BADDR(qno)));
	dev_info(dev, "R[%d]_IN_INSTR_RSIZE[0x%llx]: 0x%016llx\n", qno,
		 CNXK_VF_SDP_R_IN_INSTR_RSIZE(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_IN_INSTR_RSIZE(qno)));
	dev_info(dev, "R[%d]_IN_CNTS[0x%llx]: 0x%016llx\n", qno, CNXK_VF_SDP_R_IN_CNTS(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_IN_CNTS(qno)));
	dev_info(dev, "R[%d]_IN_INT_LEVELS[0x%llx]: 0x%016llx\n", qno,
		 CNXK_VF_SDP_R_IN_INT_LEVELS(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_IN_INT_LEVELS(qno)));
	dev_info(dev, "R[%d]_IN_PKT_CNT[0x%llx]: 0x%016llx\n", qno, CNXK_VF_SDP_R_IN_PKT_CNT(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_IN_PKT_CNT(qno)));
	dev_info(dev, "R[%d]_IN_BYTE_CNT[0x%llx]: 0x%016llx\n", qno, CNXK_VF_SDP_R_IN_BYTE_CNT(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_IN_BYTE_CNT(qno)));

	dev_info(dev, "OQ-%d register dump\n", qno);
	dev_info(dev, "R[%d]_OUT_SLIST_DBELL[0x%llx]: 0x%016llx\n", qno,
		 CNXK_VF_SDP_R_OUT_SLIST_DBELL(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_SLIST_DBELL(qno)));
	dev_info(dev, "R[%d]_OUT_CONTROL[0x%llx]: 0x%016llx\n", qno, CNXK_VF_SDP_R_OUT_CONTROL(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_CONTROL(qno)));
	dev_info(dev, "R[%d]_OUT_ENABLE[0x%llx]: 0x%016llx\n", qno, CNXK_VF_SDP_R_OUT_ENABLE(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_ENABLE(qno)));
	dev_info(dev, "R[%d]_OUT_SLIST_BADDR[0x%llx]: 0x%016llx\n", qno,
		 CNXK_VF_SDP_R_OUT_SLIST_BADDR(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_SLIST_BADDR(qno)));
	dev_info(dev, "R[%d]_OUT_SLIST_RSIZE[0x%llx]: 0x%016llx\n", qno,
		 CNXK_VF_SDP_R_OUT_SLIST_RSIZE(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_SLIST_RSIZE(qno)));
	dev_info(dev, "R[%d]_OUT_CNTS[0x%llx]: 0x%016llx\n", qno, CNXK_VF_SDP_R_OUT_CNTS(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_CNTS(qno)));
	dev_info(dev, "R[%d]_OUT_INT_LEVELS[0x%llx]: 0x%016llx\n", qno,
		 CNXK_VF_SDP_R_OUT_INT_LEVELS(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_INT_LEVELS(qno)));
	dev_info(dev, "R[%d]_OUT_PKT_CNT[0x%llx]: 0x%016llx\n", qno, CNXK_VF_SDP_R_OUT_PKT_CNT(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_PKT_CNT(qno)));
	dev_info(dev, "R[%d]_OUT_BYTE_CNT[0x%llx]: 0x%016llx\n", qno,
		 CNXK_VF_SDP_R_OUT_BYTE_CNT(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_BYTE_CNT(qno)));
	dev_info(dev, "R[%d]_ERR_TYPE[0x%llx]: 0x%016llx\n", qno, CNXK_VF_SDP_R_ERR_TYPE(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_ERR_TYPE(qno)));
}

/* Reset Hardware Tx queue */
static int
cnxk_vf_reset_iq(struct octep_sdp_dev *octep_dev, int q_no)
{
	u64 val = 0ULL;

	dev_dbg(&octep_dev->pdev->dev, "Reset VF IQ-%d\n", q_no);

	/* Disable the Tx/Instruction Ring */
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_IN_ENABLE(q_no), val);

	/* clear the Instruction Ring packet/byte counts and doorbell CSRs */
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_IN_INT_LEVELS(q_no), val);
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_IN_PKT_CNT(q_no), val);
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_IN_BYTE_CNT(q_no), val);
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_IN_INSTR_BADDR(q_no), val);
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_IN_INSTR_RSIZE(q_no), val);

	val = 0xFFFFFFFF;
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_IN_INSTR_DBELL(q_no), val);

	val = octep_read_csr64(octep_dev, CNXK_VF_SDP_R_IN_CNTS(q_no));
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_IN_CNTS(q_no), val & 0xFFFFFFFF);

	return 0;
}

/* Reset Hardware Rx queue */
static void
cnxk_vf_reset_oq(struct octep_sdp_dev *octep_dev, int q_no)
{
	u64 val = 0ULL;

	/* Disable Output (Rx) Ring */
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_OUT_ENABLE(q_no), val);

	/* Clear count CSRs */
	val = octep_read_csr(octep_dev, CNXK_VF_SDP_R_OUT_CNTS(q_no));
	octep_write_csr(octep_dev, CNXK_VF_SDP_R_OUT_CNTS(q_no), val);

	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_OUT_PKT_CNT(q_no), 0xFFFFFFFFFULL);
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_OUT_SLIST_DBELL(q_no), 0xFFFFFFFF);
}

/* Reset all hardware Tx/Rx queues */
static void
octep_vf_reset_io_queues_cnxk(struct octep_sdp_dev *octep_dev)
{
	struct pci_dev *pdev = octep_dev->pdev;
	int q;

	dev_dbg(&pdev->dev, "Reset OCTEP_CNXK VF IO Queues\n");

	for (q = 0; q < CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf); q++) {
		cnxk_vf_reset_iq(octep_dev, q);
		cnxk_vf_reset_oq(octep_dev, q);
	}
}

/* Initialize configuration limits and initial active config */
static void
octep_vf_init_config_cnxk_vf(struct octep_sdp_dev *octep_dev)
{
	struct octep_config *conf = octep_dev->conf;
	u64 reg_val;

	reg_val = octep_read_csr64(octep_dev, CNXK_VF_SDP_R_IN_CONTROL(0));
	conf->ring_cfg.max_io_rings =
		(reg_val >> CNXK_VF_R_IN_CTL_RPVF_POS) & CNXK_VF_R_IN_CTL_RPVF_MASK;
	conf->ring_cfg.active_io_rings = conf->ring_cfg.max_io_rings;
	conf->ring_cfg.active_io_rings = 1;

	conf->iq.num_descs = OCTEP_IQ_MAX_DESCRIPTORS;
	conf->iq.instr_type = OCTEP_64BYTE_INSTR;
	conf->iq.db_min = OCTEP_DB_MIN;
	conf->iq.intr_threshold = OCTEP_IQ_INTR_THRESHOLD;

	conf->oq.num_descs = OCTEP_OQ_MAX_DESCRIPTORS;
	conf->oq.buf_size = OCTEP_OQ_BUF_SIZE;
	conf->oq.refill_threshold = OCTEP_OQ_REFILL_THRESHOLD;
	conf->oq.oq_intr_pkt = OCTEP_OQ_INTR_PKT_THRESHOLD;
	conf->oq.oq_intr_time = OCTEP_OQ_INTR_TIME_THRESHOLD;
	conf->oq.wmark = OCTEP_OQ_WMARK_MIN;

	conf->msix_cfg.ioq_msix = conf->ring_cfg.active_io_rings;
}

/* Setup registers for a hardware Tx Queue  */
/* TODO: create octep_sdp_dev or struct octep_sdp_dev_vf */
static void
octep_vf_setup_iq_regs_cnxk(struct octep_sdp_dev *octep_dev, int iq_no)
{
	struct octep_iq *iq = octep_dev->iq[iq_no];
	u32 reset_instr_cnt;
	u64 reg_val;

	reg_val = octep_read_csr64(octep_dev, CNXK_VF_SDP_R_IN_CONTROL(iq_no));

	/* wait for IDLE to set to 1 */
	if (!(reg_val & CNXK_VF_R_IN_CTL_IDLE)) {
		do {
			reg_val = octep_read_csr64(octep_dev, CNXK_VF_SDP_R_IN_CONTROL(iq_no));
		} while (!(reg_val & CNXK_VF_R_IN_CTL_IDLE));
	}
	reg_val |= CNXK_VF_R_IN_CTL_RDSIZE;
	reg_val |= CNXK_VF_R_IN_CTL_IS_64B;
	reg_val |= CNXK_VF_R_IN_CTL_ESR;
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_IN_CONTROL(iq_no), reg_val);

	/* Write the start of the input queue's ring and its size  */
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_IN_INSTR_BADDR(iq_no), iq->desc_ring_dma);
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_IN_INSTR_RSIZE(iq_no), iq->max_count);

	/* Remember the doorbell & instruction count register addr for this queue */
	iq->doorbell_reg = octep_dev->mmio[0].hw_addr + CNXK_VF_SDP_R_IN_INSTR_DBELL(iq_no);
	iq->inst_cnt_reg = octep_dev->mmio[0].hw_addr + CNXK_VF_SDP_R_IN_CNTS(iq_no);
	iq->intr_lvl_reg = octep_dev->mmio[0].hw_addr + CNXK_VF_SDP_R_IN_INT_LEVELS(iq_no);

	/* Store the current instruction counter (used in flush_iq calculation) */
	reset_instr_cnt = readl(iq->inst_cnt_reg);
	writel(reset_instr_cnt, iq->inst_cnt_reg);

	/* TODO: remove after testing */
	dev_info(&octep_dev->pdev->dev, "VF: InstQ[%d]:dbell reg @ 0x%p instcnt_reg @ 0x%p\n",
		 iq_no, iq->doorbell_reg, iq->inst_cnt_reg);

	/* INTR_THRESHOLD is set to max(FFFFFFFF) to disable the INTR */
	reg_val = CFG_GET_IQ_INTR_THRESHOLD(octep_dev->conf) & 0xffffffff;
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_IN_INT_LEVELS(iq_no), reg_val);
}

/* Setup registers for a hardware Rx Queue  */
static int
octep_vf_setup_oq_regs_cnxk(struct octep_sdp_dev *octep_dev, int oq_no)
{
	struct octep_oq *oq = octep_dev->oq[oq_no];
	u32 time_threshold = 0;
	u64 oq_ctl = 0ULL;
	u64 reg_ba_val;
	u64 reg_val;

	reg_val = octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_CONTROL(oq_no));

	/* wait for IDLE to set to 1 */
	if (!(reg_val & CNXK_VF_R_OUT_CTL_IDLE)) {
		do {
			reg_val = octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_CONTROL(oq_no));
		} while (!(reg_val & CNXK_VF_R_OUT_CTL_IDLE));
	}
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_OUT_WMARK(oq_no), oq->max_count);
	/* Wait for WMARK to get applied */
	usleep_range(10, 20);

	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_OUT_SLIST_BADDR(oq_no), oq->desc_ring_dma);
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_OUT_SLIST_RSIZE(oq_no), oq->max_count);
	reg_ba_val = octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_SLIST_BADDR(oq_no));
	if (reg_ba_val != oq->desc_ring_dma) {
		do {
			if (reg_ba_val == UINT64_MAX)
				return -1;
			octep_write_csr64(octep_dev, CNXK_VF_SDP_R_OUT_SLIST_BADDR(oq_no),
					  oq->desc_ring_dma);
			octep_write_csr64(octep_dev, CNXK_VF_SDP_R_OUT_SLIST_RSIZE(oq_no),
					  oq->max_count);
			reg_ba_val =
				octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_SLIST_BADDR(oq_no));
		} while (reg_ba_val != oq->desc_ring_dma);
	}

	reg_val &= ~(CNXK_VF_R_OUT_CTL_IMODE);
	reg_val &= ~(CNXK_VF_R_OUT_CTL_ROR_P);
	reg_val &= ~(CNXK_VF_R_OUT_CTL_NSR_P);
	reg_val &= ~(CNXK_VF_R_OUT_CTL_ROR_I);
	reg_val &= ~(CNXK_VF_R_OUT_CTL_NSR_I);
	reg_val &= ~(CNXK_VF_R_OUT_CTL_ES_I);
	reg_val &= ~(CNXK_VF_R_OUT_CTL_ROR_D);
	reg_val &= ~(CNXK_VF_R_OUT_CTL_NSR_D);
	reg_val &= ~(CNXK_VF_R_OUT_CTL_ES_D);
	reg_val |= (CNXK_VF_R_OUT_CTL_ES_P);

	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_OUT_CONTROL(oq_no), reg_val);

	oq_ctl = octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_CONTROL(oq_no));

	/* Clear the ISIZE and BSIZE (22-0) */
	oq_ctl &= ~0x7fffffULL;

	/* Populate the BSIZE (15-0) */
	oq_ctl |= (oq->buffer_size & 0xffff);
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_OUT_CONTROL(oq_no), oq_ctl);

	/* Get the mapped address of the pkt_sent and pkts_credit regs */
	oq->pkts_sent_reg = octep_dev->mmio[0].hw_addr + CNXK_VF_SDP_R_OUT_CNTS(oq_no);
	oq->pkts_credit_reg = octep_dev->mmio[0].hw_addr + CNXK_VF_SDP_R_OUT_SLIST_DBELL(oq_no);

	time_threshold = CFG_GET_OQ_INTR_TIME(octep_dev->conf);
	reg_val = ((u64)time_threshold << 32) | CFG_GET_OQ_INTR_PKT(octep_dev->conf);
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_OUT_INT_LEVELS(oq_no), reg_val);

	/* set watermark for backpressure */
	reg_val = octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_WMARK(oq_no));
	reg_val &= ~0xFFFFFFFFULL;
	reg_val |= CFG_GET_OQ_WMARK(octep_dev->conf);
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_OUT_WMARK(oq_no), reg_val);
	return 0;
}

/* Tx/Rx queue interrupt handler */
static irqreturn_t
octep_vf_ioq_intr_handler_cnxk(void *data)
{
	struct octep_ioq_vector *vector = (struct octep_ioq_vector *)data;
	struct octep_oq *oq;

	if (!vector)
		return IRQ_HANDLED;

	oq = vector->oq;
	if (!oq)
		return IRQ_HANDLED;

	if (!(oq->napi))
		return IRQ_HANDLED;

	napi_schedule_irqoff(oq->napi);
	return IRQ_HANDLED;
}

/* Re-initialize Octeon hardware registers */
static void
octep_vf_reinit_regs_cnxk(struct octep_sdp_dev *octep_dev)
{
	u32 i;

	for (i = 0; i < CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf); i++)
		octep_dev->hw_ops.setup_iq_regs(octep_dev, i);

	for (i = 0; i < CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf); i++)
		octep_dev->hw_ops.setup_oq_regs(octep_dev, i);

	octep_dev->hw_ops.enable_interrupts(octep_dev);
	octep_dev->hw_ops.enable_io_queues(octep_dev);

	for (i = 0; i < CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf); i++)
		writel(octep_dev->oq[i]->max_count, octep_dev->oq[i]->pkts_credit_reg);
}

/* Enable all interrupts */
static void
octep_vf_enable_interrupts_cnxk(struct octep_sdp_dev *octep_dev)
{
	int num_rings, q;
	u64 reg_val;

	num_rings = CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf);
	for (q = 0; q < num_rings; q++) {
		reg_val = octep_read_csr64(octep_dev, CNXK_VF_SDP_R_IN_INT_LEVELS(q));
		reg_val |= (0x1ULL << 62);
		octep_write_csr64(octep_dev, CNXK_VF_SDP_R_IN_INT_LEVELS(q), reg_val);

		reg_val = octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_INT_LEVELS(q));
		reg_val |= (0x1ULL << 62);
		octep_write_csr64(octep_dev, CNXK_VF_SDP_R_OUT_INT_LEVELS(q), reg_val);
	}
}

/* Disable all interrupts */
static void
octep_vf_disable_interrupts_cnxk(struct octep_sdp_dev *octep_dev)
{
	int num_rings, q;
	u64 reg_val;

	num_rings = CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf);
	for (q = 0; q < num_rings; q++) {
		reg_val = octep_read_csr64(octep_dev, CNXK_VF_SDP_R_IN_INT_LEVELS(q));
		reg_val &= ~(0x1ULL << 62);
		octep_write_csr64(octep_dev, CNXK_VF_SDP_R_IN_INT_LEVELS(q), reg_val);

		reg_val = octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_INT_LEVELS(q));
		reg_val &= ~(0x1ULL << 62);
		octep_write_csr64(octep_dev, CNXK_VF_SDP_R_OUT_INT_LEVELS(q), reg_val);
	}
}

/* Get new Octeon Read Index: index of descriptor that Octeon reads next. */
static u32
octep_vf_update_iq_read_index_cnxk(struct octep_iq *iq)
{
	u32 pkt_in_done = readl(iq->inst_cnt_reg);
	u32 last_done, new_idx;

	if (unlikely(pkt_in_done == 0xFFFFFFFF)) {
		last_done = 0;
		dev_err_ratelimited(iq->dev, "IQ-%u count read failure\n", iq->q_no);
	} else {
		last_done = pkt_in_done - iq->pkt_in_done;
		iq->pkt_in_done = pkt_in_done;
	}

	new_idx = (iq->octep_read_index + last_done) % iq->max_count;

	return new_idx;
}

/* Enable a hardware Tx Queue */
static void
octep_vf_enable_iq_cnxk(struct octep_sdp_dev *octep_dev, int iq_no)
{
	u64 loop = HZ;
	u64 reg_val;

	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_IN_INSTR_DBELL(iq_no), 0xFFFFFFFF);

	while (octep_read_csr64(octep_dev, CNXK_VF_SDP_R_IN_INSTR_DBELL(iq_no)) && loop--)
		schedule_timeout_interruptible(1);

	reg_val = octep_read_csr64(octep_dev, CNXK_VF_SDP_R_IN_INT_LEVELS(iq_no));
	reg_val |= (0x1ULL << 62);
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_IN_INT_LEVELS(iq_no), reg_val);

	reg_val = octep_read_csr64(octep_dev, CNXK_VF_SDP_R_IN_ENABLE(iq_no));
	reg_val |= 0x1ULL;
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_IN_ENABLE(iq_no), reg_val);
}

/* Enable a hardware Rx Queue */
static void
octep_vf_enable_oq_cnxk(struct octep_sdp_dev *octep_dev, int oq_no)
{
	u64 reg_val = 0ULL;

	reg_val = octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_INT_LEVELS(oq_no));
	reg_val |= (0x1ULL << 62);
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_OUT_INT_LEVELS(oq_no), reg_val);

	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_OUT_SLIST_DBELL(oq_no), 0xFFFFFFFF);

	reg_val = octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_ENABLE(oq_no));
	reg_val |= 0x1ULL;
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_OUT_ENABLE(oq_no), reg_val);
}

/* Enable all hardware Tx/Rx Queues assigned to VF */
static void
octep_vf_enable_io_queues_cnxk(struct octep_sdp_dev *octep_dev)
{
	u8 q;

	for (q = 0; q < CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf); q++) {
		octep_vf_enable_iq_cnxk(octep_dev, q);
		octep_vf_enable_oq_cnxk(octep_dev, q);
	}
}

/* Disable a hardware Tx Queue assigned to VF */
static void
octep_vf_disable_iq_cnxk(struct octep_sdp_dev *octep_dev, int iq_no)
{
	u64 reg_val = 0ULL;

	reg_val = octep_read_csr64(octep_dev, CNXK_VF_SDP_R_IN_ENABLE(iq_no));
	reg_val &= ~0x1ULL;
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_IN_ENABLE(iq_no), reg_val);
}

/* Disable a hardware Rx Queue assigned to VF */
static void
octep_vf_disable_oq_cnxk(struct octep_sdp_dev *octep_dev, int oq_no)
{
	u64 reg_val = 0ULL;

	reg_val = octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_ENABLE(oq_no));
	reg_val &= ~0x1ULL;
	octep_write_csr64(octep_dev, CNXK_VF_SDP_R_OUT_ENABLE(oq_no), reg_val);
}

/* Disable all hardware Tx/Rx Queues assigned to VF */
static void
octep_vf_disable_io_queues_cnxk(struct octep_sdp_dev *octep_dev)
{
	int q = 0;

	for (q = 0; q < CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf); q++) {
		octep_vf_disable_iq_cnxk(octep_dev, q);
		octep_vf_disable_oq_cnxk(octep_dev, q);
	}
}

/* Dump hardware registers (including Tx/Rx queues) for debugging. */
static void
octep_vf_dump_registers_cnxk(struct octep_sdp_dev *octep_dev)
{
	u8 num_rings, q;

	num_rings = CFG_GET_PORTS_ACTIVE_IO_RINGS(octep_dev->conf);
	for (q = 0; q < num_rings; q++)
		cnxk_vf_dump_q_regs(octep_dev, q);
}

static void
cnxk_vf_dump_oq_regs(struct octep_sdp_dev *octep_dev, int qno)
{
	struct device *dev = &octep_dev->pdev->dev;

	dev_info(dev, "OQ-%d register dump\n", qno);
	dev_info(dev, "R[%d]_OUT_SLIST_DBELL[0x%llx]: 0x%016llx\n", qno,
		 CNXK_VF_SDP_R_OUT_SLIST_DBELL(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_SLIST_DBELL(qno)));
	dev_info(dev, "R[%d]_OUT_CONTROL[0x%llx]: 0x%016llx\n", qno, CNXK_VF_SDP_R_OUT_CONTROL(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_CONTROL(qno)));
	dev_info(dev, "R[%d]_OUT_ENABLE[0x%llx]: 0x%016llx\n", qno, CNXK_VF_SDP_R_OUT_ENABLE(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_ENABLE(qno)));
	dev_info(dev, "R[%d]_OUT_SLIST_BADDR[0x%llx]: 0x%016llx\n", qno,
		 CNXK_VF_SDP_R_OUT_SLIST_BADDR(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_SLIST_BADDR(qno)));
	dev_info(dev, "R[%d]_OUT_SLIST_RSIZE[0x%llx]: 0x%016llx\n", qno,
		 CNXK_VF_SDP_R_OUT_SLIST_RSIZE(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_SLIST_RSIZE(qno)));
	dev_info(dev, "R[%d]_OUT_CNTS[0x%llx]: 0x%016llx\n", qno, CNXK_VF_SDP_R_OUT_CNTS(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_CNTS(qno)));
	dev_info(dev, "R[%d]_OUT_INT_LEVELS[0x%llx]: 0x%016llx\n", qno,
		 CNXK_VF_SDP_R_OUT_INT_LEVELS(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_INT_LEVELS(qno)));
	dev_info(dev, "R[%d]_OUT_PKT_CNT[0x%llx]: 0x%016llx\n", qno, CNXK_VF_SDP_R_OUT_PKT_CNT(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_PKT_CNT(qno)));
	dev_info(dev, "R[%d]_OUT_BYTE_CNT[0x%llx]: 0x%016llx\n", qno,
		 CNXK_VF_SDP_R_OUT_BYTE_CNT(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_OUT_BYTE_CNT(qno)));
	dev_info(dev, "R[%d]_ERR_TYPE[0x%llx]: 0x%016llx\n", qno, CNXK_VF_SDP_R_ERR_TYPE(qno),
		 octep_read_csr64(octep_dev, CNXK_VF_SDP_R_ERR_TYPE(qno)));
}

/* Dump queue hardware registers (including Tx/Rx queues) for debugging. */
static void
octep_vf_dump_OQ_registers_cnxk(struct octep_sdp_dev *octep_dev, int q)
{
	cnxk_vf_dump_oq_regs(octep_dev, q);
}

/**
 * octep_sdp_dev_setup_cnxk() - Setup Octeon device.
 *
 * @oct: Octeon device private data structure.
 *
 * - initialize hardware operations.
 * - get target side pcie port number for the device.
 * - set initial configuration and max limits.
 */
void
octep_device_setup_cnxk_vf(struct octep_sdp_dev *octep_dev)
{
	octep_dev->hw_ops.setup_iq_regs = octep_vf_setup_iq_regs_cnxk;
	octep_dev->hw_ops.setup_oq_regs = octep_vf_setup_oq_regs_cnxk;

	octep_dev->hw_ops.ioq_intr_handler = octep_vf_ioq_intr_handler_cnxk;
	octep_dev->hw_ops.reinit_regs = octep_vf_reinit_regs_cnxk;

	octep_dev->hw_ops.enable_interrupts = octep_vf_enable_interrupts_cnxk;
	octep_dev->hw_ops.disable_interrupts = octep_vf_disable_interrupts_cnxk;

	octep_dev->hw_ops.update_iq_read_idx = octep_vf_update_iq_read_index_cnxk;

	octep_dev->hw_ops.enable_iq = octep_vf_enable_iq_cnxk;
	octep_dev->hw_ops.enable_oq = octep_vf_enable_oq_cnxk;
	octep_dev->hw_ops.enable_io_queues = octep_vf_enable_io_queues_cnxk;

	octep_dev->hw_ops.disable_iq = octep_vf_disable_iq_cnxk;
	octep_dev->hw_ops.disable_oq = octep_vf_disable_oq_cnxk;
	octep_dev->hw_ops.disable_io_queues = octep_vf_disable_io_queues_cnxk;
	octep_dev->hw_ops.reset_io_queues = octep_vf_reset_io_queues_cnxk;

	octep_dev->hw_ops.dump_registers = octep_vf_dump_registers_cnxk;
	octep_dev->hw_ops.dump_OQ_registers = octep_vf_dump_OQ_registers_cnxk;
	octep_vf_init_config_cnxk_vf(octep_dev);
}
