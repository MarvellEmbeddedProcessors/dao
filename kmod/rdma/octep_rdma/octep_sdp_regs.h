/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 Marvell.
 */

#ifndef __OCTEP_SDP_REGS_H__
#define __OCTEP_SDP_REGS_H__

/* ############################ RST ######################### */
#define CNXK_RST_BOOT            0x000087E006001600ULL
#define CNXK_RST_CHIP_DOMAIN_W1S 0x000087E006001810ULL
#define CNXK_RST_CORE_DOMAIN_W1S 0x000087E006001820ULL
#define CNXK_RST_CORE_DOMAIN_W1C 0x000087E006001828ULL

#define CNXK_CONFIG_XPANSION_BAR 0x38
#define CNXK_CONFIG_PCIE_CAP     0x70
#define CNXK_CONFIG_PCIE_DEVCAP  0x74
#define CNXK_CONFIG_PCIE_DEVCTL  0x78
#define CNXK_CONFIG_PCIE_LINKCAP 0x7C
#define CNXK_CONFIG_PCIE_LINKCTL 0x80
#define CNXK_CONFIG_PCIE_SLOTCAP 0x84
#define CNXK_CONFIG_PCIE_SLOTCTL 0x88

#define CNXK_PCIE_SRIOV_FDL         0x188 /* 0x98 */
#define CNXK_PCIE_SRIOV_FDL_BIT_POS 0x10
#define CNXK_PCIE_SRIOV_FDL_MASK    0xFF

#define CNXK_CONFIG_PCIE_FLTMSK 0x720

/* ################# Offsets of RING, EPF, MAC ######################### */
#define CNXK_RING_OFFSET      (0x1ULL << 17)
#define CNXK_EPF_OFFSET       (0x1ULL << 25)
#define CNXK_MAC_OFFSET       (0x1ULL << 4)
#define CNXK_BIT_ARRAY_OFFSET (0x1ULL << 4)
#define CNXK_EPVF_RING_OFFSET (0x1ULL << 4)

/* ################# Scratch Registers ######################### */
#define CNXK_SDP_EPF_SCRATCH 0x209E0

/* ################# Window Registers ######################### */
#define CNXK_SDP_WIN_WR_ADDR64   0x20000
#define CNXK_SDP_WIN_RD_ADDR64   0x20010
#define CNXK_SDP_WIN_WR_DATA64   0x20020
#define CNXK_SDP_WIN_WR_MASK_REG 0x20030
#define CNXK_SDP_WIN_RD_DATA64   0x20040

#define CNXK_SDP_MAC_NUMBER 0x2C100

/* ################# Global Previliged registers ######################### */
#define CNXK_SDP_EPF_RINFO 0x209F0

#define CNXK_SDP_EPF_RINFO_SRN(val)  ((val) & 0x7F)
#define CNXK_SDP_EPF_RINFO_RPVF(val) (((val) >> 32) & 0xF)
#define CNXK_SDP_EPF_RINFO_NVFS(val) (((val) >> 48) & 0x7F)

/* SDP Function select */
#define CNXK_SDP_FUNC_SEL_EPF_BIT_POS  7
#define CNXK_SDP_FUNC_SEL_FUNC_BIT_POS 0

/* ##### RING IN (Into device from PCI: Tx Ring) REGISTERS #### */
#define CNXK_SDP_R_IN_CONTROL_START     0x10000
#define CNXK_SDP_R_IN_ENABLE_START      0x10010
#define CNXK_SDP_R_IN_INSTR_BADDR_START 0x10020
#define CNXK_SDP_R_IN_INSTR_RSIZE_START 0x10030
#define CNXK_SDP_R_IN_INSTR_DBELL_START 0x10040
#define CNXK_SDP_R_IN_CNTS_START        0x10050
#define CNXK_SDP_R_IN_INT_LEVELS_START  0x10060
#define CNXK_SDP_R_IN_PKT_CNT_START     0x10080
#define CNXK_SDP_R_IN_BYTE_CNT_START    0x10090

#define CNXK_SDP_R_IN_CONTROL(ring) (CNXK_SDP_R_IN_CONTROL_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_IN_ENABLE(ring) (CNXK_SDP_R_IN_ENABLE_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_IN_INSTR_BADDR(ring)                                                            \
	(CNXK_SDP_R_IN_INSTR_BADDR_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_IN_INSTR_RSIZE(ring)                                                            \
	(CNXK_SDP_R_IN_INSTR_RSIZE_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_IN_INSTR_DBELL(ring)                                                            \
	(CNXK_SDP_R_IN_INSTR_DBELL_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_IN_CNTS(ring) (CNXK_SDP_R_IN_CNTS_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_IN_INT_LEVELS(ring)                                                             \
	(CNXK_SDP_R_IN_INT_LEVELS_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_IN_PKT_CNT(ring) (CNXK_SDP_R_IN_PKT_CNT_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_IN_BYTE_CNT(ring) (CNXK_SDP_R_IN_BYTE_CNT_START + ((ring) * CNXK_RING_OFFSET))

/* Rings per Virtual Function */
#define CNXK_R_IN_CTL_RPVF_MASK (0xF)
#define CNXK_R_IN_CTL_RPVF_POS  (48)

/* Number of instructions to be read in one MAC read request.
 * setting to Max value(4)
 */
#define CNXK_R_IN_CTL_IDLE   (0x1ULL << 28)
#define CNXK_R_IN_CTL_RDSIZE (0x3ULL << 25)
#define CNXK_R_IN_CTL_IS_64B (0x1ULL << 24)
#define CNXK_R_IN_CTL_D_NSR  (0x1ULL << 8)
#define CNXK_R_IN_CTL_D_ESR  (0x1ULL << 6)
#define CNXK_R_IN_CTL_D_ROR  (0x1ULL << 5)
#define CNXK_R_IN_CTL_NSR    (0x1ULL << 3)
#define CNXK_R_IN_CTL_ESR    (0x1ULL << 1)
#define CNXK_R_IN_CTL_ROR    (0x1ULL << 0)

#define CNXK_R_IN_CTL_MASK (CNXK_R_IN_CTL_RDSIZE | CNXK_R_IN_CTL_IS_64B)

/* ##### RING OUT (out from device to PCI host: Rx Ring) REGISTERS #### */
#define CNXK_SDP_R_OUT_CNTS_START        0x10100
#define CNXK_SDP_R_OUT_INT_LEVELS_START  0x10110
#define CNXK_SDP_R_OUT_SLIST_BADDR_START 0x10120
#define CNXK_SDP_R_OUT_SLIST_RSIZE_START 0x10130
#define CNXK_SDP_R_OUT_SLIST_DBELL_START 0x10140
#define CNXK_SDP_R_OUT_CONTROL_START     0x10150
#define CNXK_SDP_R_OUT_WMARK_START       0x10160
#define CNXK_SDP_R_OUT_ENABLE_START      0x10170
#define CNXK_SDP_R_OUT_PKT_CNT_START     0x10180
#define CNXK_SDP_R_OUT_BYTE_CNT_START    0x10190

#define CNXK_SDP_R_OUT_CONTROL(ring) (CNXK_SDP_R_OUT_CONTROL_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_OUT_ENABLE(ring) (CNXK_SDP_R_OUT_ENABLE_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_OUT_SLIST_BADDR(ring)                                                           \
	(CNXK_SDP_R_OUT_SLIST_BADDR_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_OUT_SLIST_RSIZE(ring)                                                           \
	(CNXK_SDP_R_OUT_SLIST_RSIZE_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_OUT_SLIST_DBELL(ring)                                                           \
	(CNXK_SDP_R_OUT_SLIST_DBELL_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_OUT_WMARK(ring) (CNXK_SDP_R_OUT_WMARK_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_OUT_CNTS(ring) (CNXK_SDP_R_OUT_CNTS_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_OUT_INT_LEVELS(ring)                                                            \
	(CNXK_SDP_R_OUT_INT_LEVELS_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_OUT_PKT_CNT(ring) (CNXK_SDP_R_OUT_PKT_CNT_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_OUT_BYTE_CNT(ring) (CNXK_SDP_R_OUT_BYTE_CNT_START + ((ring) * CNXK_RING_OFFSET))

/*------------------ R_OUT Masks ----------------*/
#define CNXK_R_OUT_INT_LEVELS_BMODE BIT_ULL(63)
#define CNXK_R_OUT_INT_LEVELS_TIMET (32)

#define CNXK_R_OUT_CTL_IDLE  BIT_ULL(40)
#define CNXK_R_OUT_CTL_ES_I  BIT_ULL(34)
#define CNXK_R_OUT_CTL_NSR_I BIT_ULL(33)
#define CNXK_R_OUT_CTL_ROR_I BIT_ULL(32)
#define CNXK_R_OUT_CTL_ES_D  BIT_ULL(30)
#define CNXK_R_OUT_CTL_NSR_D BIT_ULL(29)
#define CNXK_R_OUT_CTL_ROR_D BIT_ULL(28)
#define CNXK_R_OUT_CTL_ES_P  BIT_ULL(26)
#define CNXK_R_OUT_CTL_NSR_P BIT_ULL(25)
#define CNXK_R_OUT_CTL_ROR_P BIT_ULL(24)
#define CNXK_R_OUT_CTL_IMODE BIT_ULL(23)

/* ############### Interrupt Moderation Registers ############### */
#define CNXK_SDP_R_IN_INT_MDRT_CTL0_START 0x10280
#define CNXK_SDP_R_IN_INT_MDRT_CTL1_START 0x102A0
#define CNXK_SDP_R_IN_INT_MDRT_DBG_START  0x102C0

#define CNXK_SDP_R_OUT_INT_MDRT_CTL0_START 0x10380
#define CNXK_SDP_R_OUT_INT_MDRT_CTL1_START 0x103A0
#define CNXK_SDP_R_OUT_INT_MDRT_DBG_START  0x103C0

#define CNXK_SDP_R_MBOX_ISM_START     0x10500
#define CNXK_SDP_R_OUT_CNTS_ISM_START 0x10510
#define CNXK_SDP_R_IN_CNTS_ISM_START  0x10520

#define CNXK_SDP_R_IN_INT_MDRT_CTL0(ring)                                                          \
	(CNXK_SDP_R_IN_INT_MDRT_CTL0_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_IN_INT_MDRT_CTL1(ring)                                                          \
	(CNXK_SDP_R_IN_INT_MDRT_CTL1_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_IN_INT_MDRT_DBG(ring)                                                           \
	(CNXK_SDP_R_IN_INT_MDRT_DBG_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_OUT_INT_MDRT_CTL0(ring)                                                         \
	(CNXK_SDP_R_OUT_INT_MDRT_CTL0_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_OUT_INT_MDRT_CTL1(ring)                                                         \
	(CNXK_SDP_R_OUT_INT_MDRT_CTL1_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_OUT_INT_MDRT_DBG(ring)                                                          \
	(CNXK_SDP_R_OUT_INT_MDRT_DBG_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_MBOX_ISM(ring) (CNXK_SDP_R_MBOX_ISM_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_OUT_CNTS_ISM(ring) (CNXK_SDP_R_OUT_CNTS_ISM_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_IN_CNTS_ISM(ring) (CNXK_SDP_R_IN_CNTS_ISM_START + ((ring) * CNXK_RING_OFFSET))

/* ##################### Mail Box Registers ########################## */
/* INT register for VF. when a MBOX write from PF happed to a VF,
 * corresponding bit will be set in this register as well as in
 * PF_VF_INT register.
 *
 * This is a RO register, the int can be cleared by writing 1 to PF_VF_INT
 */
/* Basically first 3 are from PF to VF. The last one is data from VF to PF */
#define CNXK_SDP_R_MBOX_PF_VF_DATA_START 0x10210
#define CNXK_SDP_R_MBOX_PF_VF_INT_START  0x10220
#define CNXK_SDP_R_MBOX_VF_PF_DATA_START 0x10230

#define CNXK_SDP_MBOX_VF_PF_DATA_START 0x24000
#define CNXK_SDP_MBOX_PF_VF_DATA_START 0x22000

#define CNXK_SDP_R_MBOX_PF_VF_DATA(ring)                                                           \
	(CNXK_SDP_R_MBOX_PF_VF_DATA_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_MBOX_PF_VF_INT(ring)                                                            \
	(CNXK_SDP_R_MBOX_PF_VF_INT_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_MBOX_VF_PF_DATA(ring)                                                           \
	(CNXK_SDP_R_MBOX_VF_PF_DATA_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_MBOX_VF_PF_DATA(ring)                                                             \
	(CNXK_SDP_MBOX_VF_PF_DATA_START + ((ring) * CNXK_EPVF_RING_OFFSET))

#define CNXK_SDP_MBOX_PF_VF_DATA(ring)                                                             \
	(CNXK_SDP_MBOX_PF_VF_DATA_START + ((ring) * CNXK_EPVF_RING_OFFSET))

/* ##################### Interrupt Registers ########################## */
#define CNXK_SDP_R_ERR_TYPE_START 0x10400

#define CNXK_SDP_R_ERR_TYPE(ring) (CNXK_SDP_R_ERR_TYPE_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_MBOX_ISM_START     0x10500
#define CNXK_SDP_R_OUT_CNTS_ISM_START 0x10510
#define CNXK_SDP_R_IN_CNTS_ISM_START  0x10520

#define CNXK_SDP_R_MBOX_ISM(ring) (CNXK_SDP_R_MBOX_ISM_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_OUT_CNTS_ISM(ring) (CNXK_SDP_R_OUT_CNTS_ISM_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_R_IN_CNTS_ISM(ring) (CNXK_SDP_R_IN_CNTS_ISM_START + ((ring) * CNXK_RING_OFFSET))

#define CNXK_SDP_EPF_MBOX_RINT_START         0x20100
#define CNXK_SDP_EPF_MBOX_RINT_W1S_START     0x20120
#define CNXK_SDP_EPF_MBOX_RINT_ENA_W1C_START 0x20140
#define CNXK_SDP_EPF_MBOX_RINT_ENA_W1S_START 0x20160

#define CNXK_SDP_EPF_VFIRE_RINT_START         0x20180
#define CNXK_SDP_EPF_VFIRE_RINT_W1S_START     0x201A0
#define CNXK_SDP_EPF_VFIRE_RINT_ENA_W1C_START 0x201C0
#define CNXK_SDP_EPF_VFIRE_RINT_ENA_W1S_START 0x201E0

#define CNXK_SDP_EPF_IRERR_RINT         0x20200
#define CNXK_SDP_EPF_IRERR_RINT_W1S     0x20210
#define CNXK_SDP_EPF_IRERR_RINT_ENA_W1C 0x20220
#define CNXK_SDP_EPF_IRERR_RINT_ENA_W1S 0x20230

#define CNXK_SDP_EPF_VFORE_RINT_START         0x20240
#define CNXK_SDP_EPF_VFORE_RINT_W1S_START     0x20260
#define CNXK_SDP_EPF_VFORE_RINT_ENA_W1C_START 0x20280
#define CNXK_SDP_EPF_VFORE_RINT_ENA_W1S_START 0x202A0

#define CNXK_SDP_EPF_ORERR_RINT         0x20320
#define CNXK_SDP_EPF_ORERR_RINT_W1S     0x20330
#define CNXK_SDP_EPF_ORERR_RINT_ENA_W1C 0x20340
#define CNXK_SDP_EPF_ORERR_RINT_ENA_W1S 0x20350

#define CNXK_SDP_EPF_OEI_RINT         0x20400
#define CNXK_SDP_EPF_OEI_RINT_W1S     0x20500
#define CNXK_SDP_EPF_OEI_RINT_ENA_W1C 0x20600
#define CNXK_SDP_EPF_OEI_RINT_ENA_W1S 0x20700

#define CNXK_SDP_EPF_DMA_RINT         0x20800
#define CNXK_SDP_EPF_DMA_RINT_W1S     0x20810
#define CNXK_SDP_EPF_DMA_RINT_ENA_W1C 0x20820
#define CNXK_SDP_EPF_DMA_RINT_ENA_W1S 0x20830

#define CNXK_SDP_EPF_DMA_INT_LEVEL_START 0x20840
#define CNXK_SDP_EPF_DMA_CNT_START       0x20860
#define CNXK_SDP_EPF_DMA_TIM_START       0x20880

#define CNXK_SDP_EPF_MISC_RINT         0x208A0
#define CNXK_SDP_EPF_MISC_RINT_W1S     0x208B0
#define CNXK_SDP_EPF_MISC_RINT_ENA_W1C 0x208C0
#define CNXK_SDP_EPF_MISC_RINT_ENA_W1S 0x208D0

#define CNXK_SDP_EPF_DMA_VF_RINT_START         0x208E0
#define CNXK_SDP_EPF_DMA_VF_RINT_W1S_START     0x20900
#define CNXK_SDP_EPF_DMA_VF_RINT_ENA_W1C_START 0x20920
#define CNXK_SDP_EPF_DMA_VF_RINT_ENA_W1S_START 0x20940

#define CNXK_SDP_EPF_PP_VF_RINT_START         0x20960
#define CNXK_SDP_EPF_PP_VF_RINT_W1S_START     0x20980
#define CNXK_SDP_EPF_PP_VF_RINT_ENA_W1C_START 0x209A0
#define CNXK_SDP_EPF_PP_VF_RINT_ENA_W1S_START 0x209C0

#define CNXK_SDP_EPF_MBOX_RINT(index)                                                              \
	(CNXK_SDP_EPF_MBOX_RINT_START + ((index) * CNXK_BIT_ARRAY_OFFSET))
#define CNXK_SDP_EPF_MBOX_RINT_W1S(index)                                                          \
	(CNXK_SDP_EPF_MBOX_RINT_W1S_START + ((index) * CNXK_BIT_ARRAY_OFFSET))
#define CNXK_SDP_EPF_MBOX_RINT_ENA_W1C(index)                                                      \
	(CNXK_SDP_EPF_MBOX_RINT_ENA_W1C_START + ((index) * CNXK_BIT_ARRAY_OFFSET))
#define CNXK_SDP_EPF_MBOX_RINT_ENA_W1S(index)                                                      \
	(CNXK_SDP_EPF_MBOX_RINT_ENA_W1S_START + ((index) * CNXK_BIT_ARRAY_OFFSET))

#define CNXK_SDP_EPF_VFIRE_RINT(index)                                                             \
	(CNXK_SDP_EPF_VFIRE_RINT_START + ((index) * CNXK_BIT_ARRAY_OFFSET))
#define CNXK_SDP_EPF_VFIRE_RINT_W1S(index)                                                         \
	(CNXK_SDP_EPF_VFIRE_RINT_W1S_START + ((index) * CNXK_BIT_ARRAY_OFFSET))
#define CNXK_SDP_EPF_VFIRE_RINT_ENA_W1C(index)                                                     \
	(CNXK_SDP_EPF_VFIRE_RINT_ENA_W1C_START + ((index) * CNXK_BIT_ARRAY_OFFSET))
#define CNXK_SDP_EPF_VFIRE_RINT_ENA_W1S(index)                                                     \
	(CNXK_SDP_EPF_VFIRE_RINT_ENA_W1S_START + ((index) * CNXK_BIT_ARRAY_OFFSET))

#define CNXK_SDP_EPF_VFORE_RINT(index)                                                             \
	(CNXK_SDP_EPF_VFORE_RINT_START + ((index) * CNXK_BIT_ARRAY_OFFSET))
#define CNXK_SDP_EPF_VFORE_RINT_W1S(index)                                                         \
	(CNXK_SDP_EPF_VFORE_RINT_W1S_START + ((index) * CNXK_BIT_ARRAY_OFFSET))
#define CNXK_SDP_EPF_VFORE_RINT_ENA_W1C(index)                                                     \
	(CNXK_SDP_EPF_VFORE_RINT_ENA_W1C_START + ((index) * CNXK_BIT_ARRAY_OFFSET))
#define CNXK_SDP_EPF_VFORE_RINT_ENA_W1S(index)                                                     \
	(CNXK_SDP_EPF_VFORE_RINT_ENA_W1S_START + ((index) * CNXK_BIT_ARRAY_OFFSET))

#define CNXK_SDP_EPF_DMA_VF_RINT(index)                                                            \
	(CNXK_SDP_EPF_DMA_VF_RINT_START + ((index) + CNXK_BIT_ARRAY_OFFSET))
#define CNXK_SDP_EPF_DMA_VF_RINT_W1S(index)                                                        \
	(CNXK_SDP_EPF_DMA_VF_RINT_W1S_START + ((index) + CNXK_BIT_ARRAY_OFFSET))
#define CNXK_SDP_EPF_DMA_VF_RINT_ENA_W1C(index)                                                    \
	(CNXK_SDP_EPF_DMA_VF_RINT_ENA_W1C_START + ((index) + CNXK_BIT_ARRAY_OFFSET))
#define CNXK_SDP_EPF_DMA_VF_RINT_ENA_W1S(index)                                                    \
	(CNXK_SDP_EPF_DMA_VF_RINT_ENA_W1S_START + ((index) + CNXK_BIT_ARRAY_OFFSET))

#define CNXK_SDP_EPF_PP_VF_RINT(index)                                                             \
	(CNXK_SDP_EPF_PP_VF_RINT_START + ((index) + CNXK_BIT_ARRAY_OFFSET))
#define CNXK_SDP_EPF_PP_VF_RINT_W1S(index)                                                         \
	(CNXK_SDP_EPF_PP_VF_RINT_W1S_START + ((index) + CNXK_BIT_ARRAY_OFFSET))
#define CNXK_SDP_EPF_PP_VF_RINT_ENA_W1C(index)                                                     \
	(CNXK_SDP_EPF_PP_VF_RINT_ENA_W1C_START + ((index) + CNXK_BIT_ARRAY_OFFSET))
#define CNXK_SDP_EPF_PP_VF_RINT_ENA_W1S(index)                                                     \
	(CNXK_SDP_EPF_PP_VF_RINT_ENA_W1S_START + ((index) + CNXK_BIT_ARRAY_OFFSET))

/*------------------ Interrupt Masks ----------------*/
#define CNXK_INTR_R_SEND_ISM BIT_ULL(63)
#define CNXK_INTR_R_OUT_INT  BIT_ULL(62)
#define CNXK_INTR_R_IN_INT   BIT_ULL(61)
#define CNXK_INTR_R_MBOX_INT BIT_ULL(60)
#define CNXK_INTR_R_RESEND   BIT_ULL(59)
#define CNXK_INTR_R_CLR_TIM  BIT_ULL(58)

/* ####################### Ring Mapping Registers ################################## */
#define CNXK_SDP_EPVF_RING_START       0x26000
#define CNXK_SDP_IN_RING_TB_MAP_START  0x28000
#define CNXK_SDP_IN_RATE_LIMIT_START   0x2A000
#define CNXK_SDP_MAC_PF_RING_CTL_START 0x2C000

#define CNXK_SDP_EPVF_RING(ring) (CNXK_SDP_EPVF_RING_START + ((ring) * CNXK_EPVF_RING_OFFSET))
#define CNXK_SDP_IN_RING_TB_MAP(ring)                                                              \
	(CNXK_SDP_IN_RING_TB_MAP_START + ((ring) * CNXK_EPVF_RING_OFFSET))
#define CNXK_SDP_IN_RATE_LIMIT(ring)                                                               \
	(CNXK_SDP_IN_RATE_LIMIT_START + ((ring) * CNXK_EPVF_RING_OFFSET))
#define CNXK_SDP_MAC_PF_RING_CTL(mac) (CNXK_SDP_MAC_PF_RING_CTL_START + ((mac) * CNXK_MAC_OFFSET))

#define CNXK_SDP_MAC_PF_RING_CTL_NPFS(val) ((val) & 0x3)
#define CNXK_SDP_MAC_PF_RING_CTL_SRN(val)  (((val) >> 8) & 0x7F)
#define CNXK_SDP_MAC_PF_RING_CTL_RPPF(val) (((val) >> 16) & 0x3F)

/*############################ SDP VF REGs ##################*/
/*############################ RST #########################*/
#define CNXK_VF_CONFIG_XPANSION_BAR 0x38
#define CNXK_VF_CONFIG_PCIE_CAP     0x70
#define CNXK_VF_CONFIG_PCIE_DEVCAP  0x74
#define CNXK_VF_CONFIG_PCIE_DEVCTL  0x78
#define CNXK_VF_CONFIG_PCIE_LINKCAP 0x7C
#define CNXK_VF_CONFIG_PCIE_LINKCTL 0x80
#define CNXK_VF_CONFIG_PCIE_SLOTCAP 0x84
#define CNXK_VF_CONFIG_PCIE_SLOTCTL 0x88

#define CNXK_VF_RING_OFFSET (0x1ULL << 17)

/*###################### RING IN REGISTERS #########################*/
#define CNXK_VF_SDP_R_IN_CONTROL_START     0x10000
#define CNXK_VF_SDP_R_IN_ENABLE_START      0x10010
#define CNXK_VF_SDP_R_IN_INSTR_BADDR_START 0x10020
#define CNXK_VF_SDP_R_IN_INSTR_RSIZE_START 0x10030
#define CNXK_VF_SDP_R_IN_INSTR_DBELL_START 0x10040
#define CNXK_VF_SDP_R_IN_CNTS_START        0x10050
#define CNXK_VF_SDP_R_IN_INT_LEVELS_START  0x10060
#define CNXK_VF_SDP_R_IN_PKT_CNT_START     0x10080
#define CNXK_VF_SDP_R_IN_BYTE_CNT_START    0x10090
#define CNXK_VF_SDP_R_ERR_TYPE_START       0x10400

#define CNXK_VF_SDP_R_ERR_TYPE(ring) (CNXK_VF_SDP_R_ERR_TYPE_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_IN_CONTROL(ring)                                                             \
	(CNXK_VF_SDP_R_IN_CONTROL_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_IN_ENABLE(ring)                                                              \
	(CNXK_VF_SDP_R_IN_ENABLE_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_IN_INSTR_BADDR(ring)                                                         \
	(CNXK_VF_SDP_R_IN_INSTR_BADDR_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_IN_INSTR_RSIZE(ring)                                                         \
	(CNXK_VF_SDP_R_IN_INSTR_RSIZE_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_IN_INSTR_DBELL(ring)                                                         \
	(CNXK_VF_SDP_R_IN_INSTR_DBELL_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_IN_CNTS(ring) (CNXK_VF_SDP_R_IN_CNTS_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_IN_INT_LEVELS(ring)                                                          \
	(CNXK_VF_SDP_R_IN_INT_LEVELS_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_IN_PKT_CNT(ring)                                                             \
	(CNXK_VF_SDP_R_IN_PKT_CNT_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_IN_BYTE_CNT(ring)                                                            \
	(CNXK_VF_SDP_R_IN_BYTE_CNT_START + ((ring) * CNXK_VF_RING_OFFSET))

/*------------------ R_IN Masks ----------------*/

/** Rings per Virtual Function **/
#define CNXK_VF_R_IN_CTL_RPVF_MASK (0xF)
#define CNXK_VF_R_IN_CTL_RPVF_POS  (48)

/* Number of instructions to be read in one MAC read request.
 * setting to Max value(4)
 **/
#define CNXK_VF_R_IN_CTL_IDLE   (0x1ULL << 28)
#define CNXK_VF_R_IN_CTL_RDSIZE (0x3ULL << 25)
#define CNXK_VF_R_IN_CTL_IS_64B (0x1ULL << 24)
#define CNXK_VF_R_IN_CTL_D_NSR  (0x1ULL << 8)
#define CNXK_VF_R_IN_CTL_D_ESR  (0x1ULL << 6)
#define CNXK_VF_R_IN_CTL_D_ROR  (0x1ULL << 5)
#define CNXK_VF_R_IN_CTL_NSR    (0x1ULL << 3)
#define CNXK_VF_R_IN_CTL_ESR    (0x1ULL << 1)
#define CNXK_VF_R_IN_CTL_ROR    (0x1ULL << 0)

#define CNXK_VF_R_IN_CTL_MASK (CNXK_VF_R_IN_CTL_RDSIZE | CNXK_VF_R_IN_CTL_IS_64B)

/*###################### RING OUT REGISTERS #########################*/
#define CNXK_VF_SDP_R_OUT_CNTS_START        0x10100
#define CNXK_VF_SDP_R_OUT_INT_LEVELS_START  0x10110
#define CNXK_VF_SDP_R_OUT_SLIST_BADDR_START 0x10120
#define CNXK_VF_SDP_R_OUT_SLIST_RSIZE_START 0x10130
#define CNXK_VF_SDP_R_OUT_SLIST_DBELL_START 0x10140
#define CNXK_VF_SDP_R_OUT_CONTROL_START     0x10150
#define CNXK_VF_SDP_R_OUT_WMARK_START       0x10160
#define CNXK_VF_SDP_R_OUT_ENABLE_START      0x10170
#define CNXK_VF_SDP_R_OUT_PKT_CNT_START     0x10180
#define CNXK_VF_SDP_R_OUT_BYTE_CNT_START    0x10190

#define CNXK_VF_SDP_R_OUT_CONTROL(ring)                                                            \
	(CNXK_VF_SDP_R_OUT_CONTROL_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_OUT_ENABLE(ring)                                                             \
	(CNXK_VF_SDP_R_OUT_ENABLE_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_OUT_SLIST_BADDR(ring)                                                        \
	(CNXK_VF_SDP_R_OUT_SLIST_BADDR_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_OUT_SLIST_RSIZE(ring)                                                        \
	(CNXK_VF_SDP_R_OUT_SLIST_RSIZE_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_OUT_SLIST_DBELL(ring)                                                        \
	(CNXK_VF_SDP_R_OUT_SLIST_DBELL_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_OUT_WMARK(ring)                                                              \
	(CNXK_VF_SDP_R_OUT_WMARK_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_OUT_CNTS(ring) (CNXK_VF_SDP_R_OUT_CNTS_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_OUT_INT_LEVELS(ring)                                                         \
	(CNXK_VF_SDP_R_OUT_INT_LEVELS_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_OUT_PKT_CNT(ring)                                                            \
	(CNXK_VF_SDP_R_OUT_PKT_CNT_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_OUT_BYTE_CNT(ring)                                                           \
	(CNXK_VF_SDP_R_OUT_BYTE_CNT_START + ((ring) * CNXK_VF_RING_OFFSET))

/*------------------ R_OUT Masks ----------------*/
#define CNXK_VF_R_OUT_INT_LEVELS_BMODE (1ULL << 63)
#define CNXK_VF_R_OUT_INT_LEVELS_TIMET (32)

#define CNXK_VF_R_OUT_CTL_IDLE  (1ULL << 40)
#define CNXK_VF_R_OUT_CTL_ES_I  (1ULL << 34)
#define CNXK_VF_R_OUT_CTL_NSR_I (1ULL << 33)
#define CNXK_VF_R_OUT_CTL_ROR_I (1ULL << 32)
#define CNXK_VF_R_OUT_CTL_ES_D  (1ULL << 30)
#define CNXK_VF_R_OUT_CTL_NSR_D (1ULL << 29)
#define CNXK_VF_R_OUT_CTL_ROR_D (1ULL << 28)
#define CNXK_VF_R_OUT_CTL_ES_P  (1ULL << 26)
#define CNXK_VF_R_OUT_CTL_NSR_P (1ULL << 25)
#define CNXK_VF_R_OUT_CTL_ROR_P (1ULL << 24)
#define CNXK_VF_R_OUT_CTL_IMODE (1ULL << 23)

/* ##################### Mail Box Registers ########################## */
/* SDP PF to VF Mailbox Data Register */
#define CNXK_VF_SDP_R_MBOX_PF_VF_DATA_START 0x10210
/* SDP Packet PF to VF Mailbox Interrupt Register */
#define CNXK_VF_SDP_R_MBOX_PF_VF_INT_START 0x10220
/* SDP VF to PF Mailbox Data Register */
#define CNXK_VF_SDP_R_MBOX_VF_PF_DATA_START 0x10230

#define CNXK_VF_SDP_R_MBOX_PF_VF_INT_ENAB   (1ULL << 1)
#define CNXK_VF_SDP_R_MBOX_PF_VF_INT_STATUS (1ULL << 0)

#define CNXK_VF_SDP_R_MBOX_PF_VF_DATA(ring)                                                        \
	(CNXK_VF_SDP_R_MBOX_PF_VF_DATA_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_MBOX_PF_VF_INT(ring)                                                         \
	(CNXK_VF_SDP_R_MBOX_PF_VF_INT_START + ((ring) * CNXK_VF_RING_OFFSET))

#define CNXK_VF_SDP_R_MBOX_VF_PF_DATA(ring)                                                        \
	(CNXK_VF_SDP_R_MBOX_VF_PF_DATA_START + ((ring) * CNXK_VF_RING_OFFSET))
/* Number of non-queue interrupts in CNXKxx */
#define CNXK_NUM_NON_IOQ_INTR 32

/* bit 0 for control mbox interrupt */
#define CNXK_SDP_EPF_OEI_RINT_DATA_BIT_MBOX BIT_ULL(0)
/* bit 1 for firmware heartbeat interrupt */
#define CNXK_SDP_EPF_OEI_RINT_DATA_BIT_HBEAT BIT_ULL(1)

#define FW_STATUS_DOWNING 0ULL
#define FW_STATUS_READY   1ULL
#define FW_STATUS_RUNNING 2ULL
#define CNXK_PEMX_PFX_CSX_PFCFGX(pem, pf, offset)                                                  \
	((0x8e0000008000 | (uint64_t)(pem) << 36 | (pf) << 18 | (((offset) >> 16) & 1) << 16 |     \
	  (offset >> 3) << 3) +                                                                    \
	 (((offset >> 2) & 1) << 2))

/* Register defines for use with CNXK_PEMX_PFX_CSX_PFCFGX */
#define CNXK_PCIEEP_VSECST_CTL 0x418

#define CNXK_PEM_BAR4_INDEX        7
#define CNXK_PEM_BAR4_INDEX_SIZE   0x400000ULL
#define CNXK_PEM_BAR4_INDEX_OFFSET (CNXK_PEM_BAR4_INDEX * CNXK_PEM_BAR4_INDEX_SIZE)

/***************************************************/
/* Tx instruction types by length */
#define OCTEP_32BYTE_INSTR 32
#define OCTEP_64BYTE_INSTR 64

/* Tx Queue: maximum descriptors per ring */
/* This needs to be a power of 2 */
#define OCTEP_IQ_MAX_DESCRIPTORS 1024
/* Minimum input (Tx) requests to be enqueued to ring doorbell */
#define OCTEP_DB_MIN 8
/* Packet threshold for Tx queue interrupt */
#define OCTEP_IQ_INTR_THRESHOLD 0x0

/* Minimum watermark for backpressure */
#define OCTEP_OQ_WMARK_MIN 256

/* Rx Queue: maximum descriptors per ring */
#define OCTEP_OQ_MAX_DESCRIPTORS 1024

/* Rx buffer size: Use page size buffers.
 * Build skb from allocated page buffer once the packet is received.
 * When a gathered packet is received, make head page as skb head and
 * page buffers in consecutive Rx descriptors as fragments.
 */
#define OCTEP_OQ_BUF_SIZE         (SKB_WITH_OVERHEAD(PAGE_SIZE))
#define OCTEP_OQ_PKTS_PER_INTR    128
#define OCTEP_OQ_REFILL_THRESHOLD (OCTEP_OQ_MAX_DESCRIPTORS / 4)

#define OCTEP_OQ_INTR_PKT_THRESHOLD  1
#define OCTEP_OQ_INTR_TIME_THRESHOLD 10

#define OCTEP_MSIX_NAME_SIZE (IFNAMSIZ + 32)

/* Tx Queue wake threshold
 * wakeup a stopped Tx queue if minimum 2 descriptors are available.
 * Even a skb with fragments consume only one Tx queue descriptor entry.
 */
#define OCTEP_WAKE_QUEUE_THRESHOLD 2

/* Minimum MTU supported by Octeon network interface */
#define OCTEP_MIN_MTU ETH_MIN_MTU
/* Maximum MTU supported by Octeon interface*/
#define OCTEP_MAX_MTU (10000 - (ETH_HLEN + ETH_FCS_LEN))
/* Default MTU */
#define OCTEP_DEFAULT_MTU 1500

/* pf heartbeat interval in milliseconds */
#define OCTEP_DEFAULT_FW_HB_INTERVAL 1000
/* pf heartbeat miss count */
#define OCTEP_DEFAULT_FW_HB_MISS_COUNT 20

/* Macros to get octeon config params */
#define CFG_GET_IQ_CFG(cfg)            ((cfg)->iq)
#define CFG_GET_IQ_NUM_DESC(cfg)       ((cfg)->iq.num_descs)
#define CFG_GET_IQ_INSTR_TYPE(cfg)     ((cfg)->iq.instr_type)
#define CFG_GET_IQ_INSTR_SIZE(cfg)     (64)
#define CFG_GET_IQ_DB_MIN(cfg)         ((cfg)->iq.db_min)
#define CFG_GET_IQ_INTR_THRESHOLD(cfg) ((cfg)->iq.intr_threshold)

#define CFG_GET_OQ_NUM_DESC(cfg)         ((cfg)->oq.num_descs)
#define CFG_GET_OQ_BUF_SIZE(cfg)         ((cfg)->oq.buf_size)
#define CFG_GET_OQ_REFILL_THRESHOLD(cfg) ((cfg)->oq.refill_threshold)
#define CFG_GET_OQ_INTR_PKT(cfg)         ((cfg)->oq.oq_intr_pkt)
#define CFG_GET_OQ_INTR_TIME(cfg)        ((cfg)->oq.oq_intr_time)
#define CFG_GET_OQ_WMARK(cfg)            ((cfg)->oq.wmark)

#define CFG_GET_PORTS_MAX_IO_RINGS(cfg)    ((cfg)->ring_cfg.max_io_rings)
#define CFG_GET_PORTS_ACTIVE_IO_RINGS(cfg) ((cfg)->ring_cfg.active_io_rings)
#define CFG_GET_PORTS_PF_SRN(cfg)          ((cfg)->ring_cfg.srn)

#define CFG_GET_CORE_TICS_PER_US(cfg)   ((cfg)->core_cfg.core_tics_per_us)
#define CFG_GET_COPROC_TICS_PER_US(cfg) ((cfg)->core_cfg.coproc_tics_per_us)

#define CFG_GET_MAX_VFS(cfg)     ((cfg)->sriov_cfg.max_vfs)
#define CFG_GET_ACTIVE_VFS(cfg)  ((cfg)->sriov_cfg.active_vfs)
#define CFG_GET_MAX_RPVF(cfg)    ((cfg)->sriov_cfg.max_rings_per_vf)
#define CFG_GET_ACTIVE_RPVF(cfg) ((cfg)->sriov_cfg.active_rings_per_vf)
#define CFG_GET_VF_SRN(cfg)      ((cfg)->sriov_cfg.vf_srn)

#define CFG_GET_IOQ_MSIX(cfg)           ((cfg)->msix_cfg.ioq_msix)
#define CFG_GET_NON_IOQ_MSIX(cfg)       ((cfg)->msix_cfg.non_ioq_msix)
#define CFG_GET_NON_IOQ_MSIX_NAMES(cfg) ((cfg)->msix_cfg.non_ioq_msix_names)

#define CFG_GET_CTRL_MBOX_MEM_ADDR(cfg) ((cfg)->ctrl_mbox_cfg.barmem_addr)

/* Hardware Tx Queue configuration. */
struct octep_iq_config {
	/* Size of the Input queue (number of commands) */
	u16 num_descs;

	/* Command size - 32 or 64 bytes */
	u16 instr_type;

	/* Minimum number of commands pending to be posted to Octeon before driver
	 * hits the Input queue doorbell.
	 */
	u16 db_min;

	/* Trigger the IQ interrupt when processed cmd count reaches
	 * this level.
	 */
	u32 intr_threshold;
};

/* Hardware Rx Queue configuration. */
struct octep_oq_config {
	/* Size of Output queue (number of descriptors) */
	u16 num_descs;

	/* Size of buffer in this Output queue. */
	u16 buf_size;

	/* The number of buffers that were consumed during packet processing
	 * by the driver on this Output queue before the driver attempts to
	 * replenish the descriptor ring with new buffers.
	 */
	u16 refill_threshold;

	/* Interrupt Coalescing (Packet Count). Octeon will interrupt the host
	 * only if it sent as many packets as specified by this field.
	 * The driver usually does not use packet count interrupt coalescing.
	 */
	u32 oq_intr_pkt;

	/* Interrupt Coalescing (Time Interval). Octeon will interrupt the host
	 * if at least one packet was sent in the time interval specified by
	 * this field. The driver uses time interval interrupt coalescing by
	 * default. The time is specified in microseconds.
	 */
	u32 oq_intr_time;

	/* Water mark for backpressure.
	 * Output queue sends backpressure signal to source when
	 * free buffer count falls below wmark.
	 */
	u32 wmark;
};

/* Tx/Rx configuration */
struct octep_ring_config {
	/* Max number of IOQs */
	u16 max_io_rings;

	/* Number of active IOQs */
	u16 active_io_rings;

	/* Starting IOQ number: this changes based on which PEM is used */
	u16 srn;
};

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
	/* Number of IOQ interrupts */
	u16 ioq_msix;

	/* Number of Non IOQ interrupts */
	u16 non_ioq_msix;

	/* Names of Non IOQ interrupts */
	char **non_ioq_msix_names;
};

struct octep_ctrl_mbox_config {
	/* Barmem address for control mbox */
	void __iomem *barmem_addr;
};

/* Info from firmware */
struct octep_fw_info {
	/* interface pkind */
	u8 pkind;

	/* front size data */
	u8 fsz;

	/* heartbeat interval in milliseconds */
	u16 hb_interval;

	/* heartbeat miss count */
	u16 hb_miss_count;

	/* reserved */
	u16 reserved1;

	/* supported rx offloads OCTEP_ETH_RX_OFFLOAD_* */
	u16 rx_ol_flags;

	/* supported tx offloads OCTEP_ETH_TX_OFFLOAD_* */
	u16 tx_ol_flags;

	/* reserved */
	u32 reserved_offloads;

	/* extra offload flags */
	u64 ext_ol_flags;

	/* supported features */
	u64 features[2];

	/* reserved */
	u64 reserved2[3];
};

/* Data Structure to hold configuration limits and active config */
struct octep_config {
	/* Input Queue attributes. */
	struct octep_iq_config iq;

	/* Output Queue attributes. */
	struct octep_oq_config oq;

	/* NIC Port Configuration */
	struct octep_ring_config ring_cfg;

	/* SRIOV configuration of the PF */
	struct octep_sriov_config sriov_cfg;

	/* MSI-X interrupt config */
	struct octep_msix_config msix_cfg;

	/* ctrl mbox config */
	struct octep_ctrl_mbox_config ctrl_mbox_cfg;

	/* fw info */
	struct octep_fw_info fw_info;
};
#endif /* __OCTEP_SDP_REGS_H__ */
