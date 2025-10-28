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
#define ROC_SE_MAJOR_OP_HMAC       0x35ULL
#define ROC_SE_FC_MINOR_OP_ENCRYPT 0x0
#define ROC_SE_FC_MINOR_OP_DECRYPT 0x1

#define ROC_SE_OFF_CTRL_LEN  8
#define ROC_SE_CTRL_WORD_LEN 8

#define ROC_SE_MAJOR_OP_RANDOM           0x32ULL
#define ROC_SE_MINOR_OP_RANDOM_HW_RANDOM 0x0ULL

#define ROC_SE_MAJOR_OP_OAEP_ENCODE_DECODE 0x3BULL
#define ROC_SE_MINOR_OP_OAEP_ENCODE        0x0ULL
#define ROC_SE_MINOR_OP_OAEP_DECODE        0x1ULL

#define ROC_SE_MAJOR_OP_AES_KEY_WRAP 0x1DULL

#endif /* __MC_SE_H__ */
