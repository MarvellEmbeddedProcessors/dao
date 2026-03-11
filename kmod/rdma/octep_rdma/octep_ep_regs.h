/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 Marvell.
 */

#ifndef __OCTEP_EP_REGS_H__
#define __OCTEP_EP_REGS_H__

/* ################# Offsets of EPF, BIT_ARRAY ######################### */
#define CNXK_BIT_ARRAY_OFFSET (0x1ULL << 4)
#define CNXK_EPVF_RING_OFFSET (0x1ULL << 4)

/* ################# Scratch Registers ######################### */
#define CNXK_SDP_EPF_SCRATCH 0x209E0

/* ################# Window Registers ######################### */
#define CNXK_SDP_WIN_WR_ADDR64 0x20000
#define CNXK_SDP_WIN_WR_DATA64 0x20020

/* ################# Global Previliged registers ######################### */
#define CNXK_SDP_EPF_RINFO 0x209F0

#define CNXK_SDP_EPF_RINFO_SRN(val)  ((val) & 0x7F)
#define CNXK_SDP_EPF_RINFO_RPVF(val) (((val) >> 32) & 0xF)
#define CNXK_SDP_EPF_RINFO_NVFS(val) (((val) >> 48) & 0x7F)

/* ##################### EPF Mail Box Registers ########################## */
#define CNXK_SDP_MBOX_VF_PF_DATA_START 0x24000
#define CNXK_SDP_MBOX_PF_VF_DATA_START 0x22000

#define CNXK_SDP_MBOX_VF_PF_DATA(ring)                                                             \
	(CNXK_SDP_MBOX_VF_PF_DATA_START + ((ring) * CNXK_EPVF_RING_OFFSET))

#define CNXK_SDP_MBOX_PF_VF_DATA(ring)                                                             \
	(CNXK_SDP_MBOX_PF_VF_DATA_START + ((ring) * CNXK_EPVF_RING_OFFSET))

/* ##################### Interrupt Registers ########################## */
#define CNXK_SDP_EPF_MBOX_RINT_START         0x20100
#define CNXK_SDP_EPF_MBOX_RINT_ENA_W1C_START 0x20140
#define CNXK_SDP_EPF_MBOX_RINT_ENA_W1S_START 0x20160

#define CNXK_SDP_EPF_OEI_RINT         0x20400
#define CNXK_SDP_EPF_OEI_RINT_ENA_W1C 0x20600
#define CNXK_SDP_EPF_OEI_RINT_ENA_W1S 0x20700

#define CNXK_SDP_EPF_MISC_RINT         0x208A0
#define CNXK_SDP_EPF_MISC_RINT_ENA_W1C 0x208C0
#define CNXK_SDP_EPF_MISC_RINT_ENA_W1S 0x208D0

#define CNXK_SDP_EPF_MBOX_RINT(index)                                                              \
	(CNXK_SDP_EPF_MBOX_RINT_START + ((index) * CNXK_BIT_ARRAY_OFFSET))
#define CNXK_SDP_EPF_MBOX_RINT_ENA_W1C(index)                                                      \
	(CNXK_SDP_EPF_MBOX_RINT_ENA_W1C_START + ((index) * CNXK_BIT_ARRAY_OFFSET))
#define CNXK_SDP_EPF_MBOX_RINT_ENA_W1S(index)                                                      \
	(CNXK_SDP_EPF_MBOX_RINT_ENA_W1S_START + ((index) * CNXK_BIT_ARRAY_OFFSET))

/*############################ VF Registers ########################*/
#define CNXK_VF_RING_OFFSET (0x1ULL << 17)

/* VF Mailbox Registers */
#define CNXK_VF_SDP_R_MBOX_PF_VF_DATA_START 0x10210
#define CNXK_VF_SDP_R_MBOX_PF_VF_INT_START  0x10220
#define CNXK_VF_SDP_R_MBOX_VF_PF_DATA_START 0x10230

#define CNXK_VF_SDP_R_MBOX_PF_VF_INT_ENAB (1ULL << 1)

#define CNXK_VF_SDP_R_MBOX_PF_VF_DATA(ring)                                                        \
	(CNXK_VF_SDP_R_MBOX_PF_VF_DATA_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_MBOX_PF_VF_INT(ring)                                                         \
	(CNXK_VF_SDP_R_MBOX_PF_VF_INT_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_MBOX_VF_PF_DATA(ring)                                                        \
	(CNXK_VF_SDP_R_MBOX_VF_PF_DATA_START + ((ring) * CNXK_VF_RING_OFFSET))

/* Number of non-queue interrupts in CNXKxx */
#define CNXK_NUM_NON_IOQ_INTR 32
/* bit 1 for firmware heartbeat interrupt */
#define CNXK_SDP_EPF_OEI_RINT_DATA_BIT_HBEAT BIT_ULL(1)
/* bit 2-17 for link status interrupt */
#define CNXK_SDP_EPF_OEI_RINT_DATA_BIT_LINK_STATUS_MASK (GENMASK_ULL(17, 2) | GENMASK_ULL(33, 18))
#define CNXK_SDP_EPF_OEI_RINT_DATA_BIT_LINK_DOWN_MASK GENMASK_ULL(17, 2)
#define CNXK_SDP_EPF_OEI_RINT_DATA_BIT_LINK_UP_MASK GENMASK_ULL(33, 18)

/* Firmware status definitions */
#define FW_STATUS_DOWNING 0ULL
#define FW_STATUS_RUNNING 2ULL

#define CNXK_PEMX_PFX_CSX_PFCFGX(pem, pf, offset)                                              \
	((0x8e0000008000 | (uint64_t)(pem) << 36 | (pf) << 18 | (((offset) >> 16) & 1) << 16 | \
	  (offset >> 3) << 3) +                                                                \
	 (((offset >> 2) & 1) << 2))

/* Register defines for use with CNXK_PEMX_PFX_CSX_PFCFGX */
#define CNXK_PCIEEP_VSECST_CTL 0x418

/***************************************************/

/* pf heartbeat interval in milliseconds */
#define OCTEP_DEFAULT_FW_HB_INTERVAL 5000
/* pf heartbeat miss count - 5 attempts × 5s = 25 seconds total timeout */
#define OCTEP_DEFAULT_FW_HB_MISS_COUNT 5

#define CFG_GET_ACTIVE_VFS(cfg) ((cfg)->sriov_cfg.active_vfs)
#define CFG_GET_MAX_RPVF(cfg) ((cfg)->sriov_cfg.max_rings_per_vf)
#define CFG_GET_ACTIVE_RPVF(cfg) ((cfg)->sriov_cfg.active_rings_per_vf)

#define CFG_GET_NON_IOQ_MSIX(cfg) ((cfg)->msix_cfg.non_ioq_msix)
#define CFG_GET_NON_IOQ_MSIX_NAMES(cfg) ((cfg)->msix_cfg.non_ioq_msix_names)

/* PF/PCIe device state check interval in milliseconds - aligned with DPU (5 seconds) */
#define OCTEP_DEFAULT_VF_HB_INTERVAL 5000

/* Octeon Hardware SRIOV config */
struct octep_sriov_config {
	/* Max number of VF devices supported */
	u16 max_vfs;

	/* Number of VF devices enabled   */
	u16 active_vfs;

	/* Max number of rings assigned to VF  */
	u8 max_rings_per_vf;

	/* Number of rings enabled per VF */
	u8 active_rings_per_vf;

	/* starting ring number of VF's: ring-0 of VF-0 of the PF */
	u16 vf_srn;
};

/* Octeon MSI-x config. */
struct octep_msix_config {
	/* Number of Non IOQ interrupts */
	u16 non_ioq_msix;

	/* Names of Non IOQ interrupts */
	char **non_ioq_msix_names;
};

/* Info from firmware */
struct octep_fw_info {
	/* heartbeat interval in milliseconds */
	u16 hb_interval;

	/* heartbeat miss count */
	u16 hb_miss_count;
};

/* Data Structure to hold configuration limits and active config */
struct octep_config {
	/* SRIOV configuration of the PF */
	struct octep_sriov_config sriov_cfg;

	/* MSI-X interrupt config */
	struct octep_msix_config msix_cfg;

	/* fw info */
	struct octep_fw_info fw_info;
};
#endif /* __OCTEP_EP_REGS_H__ */
