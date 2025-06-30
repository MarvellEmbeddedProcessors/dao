/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */
#ifndef __MC_SE_H__
#define __MC_SE_H__

/* SE opcodes */
#define ROC_SE_MAJOR_OP_MISC             0x01ULL
#define ROC_SE_MISC_MINOR_OP_PASSTHROUGH 0x03ULL

#define ROC_SE_MAJOR_OP_FC         0x33ULL
#define ROC_SE_MAJOR_OP_HASH       0x34ULL
#define ROC_SE_FC_MINOR_OP_ENCRYPT 0x0
#define ROC_SE_FC_MINOR_OP_DECRYPT 0x1

#define ROC_SE_OFF_CTRL_LEN 8

#define ROC_SE_MAJOR_OP_RANDOM           0x32ULL
#define ROC_SE_MINOR_OP_RANDOM_HW_RANDOM 0x0ULL

#endif /* __MC_SE_H__ */
