/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright (c) 2025 Marvell
 */

#ifndef __MC_AE_H__
#define __MC_AE_H__

/* AE opcodes */
#define ROC_AE_MAJOR_OP_MODEX         0x03
#define ROC_AE_MINOR_OP_PKCS_ENC      0x02
#define ROC_AE_MINOR_OP_PKCS_ENC_CRT  0x03
#define ROC_AE_MINOR_OP_PKCS_DEC      0x04
#define ROC_AE_MINOR_OP_PKCS_DEC_CRT  0x05
#define ROC_AE_MAJOR_OP_EC            0x04
#define ROC_AE_MINOR_OP_EC_SIGN       0x01
#define ROC_AE_MINOR_OP_EC_VERIFY     0x02
#define ROC_AE_MINOR_OP_MODEX_EXP     0x01
#define ROC_AE_MINOR_OP_MODEX_EXP_CRT 0x06

/* ML KEM/DSA opcodes */
#define ROC_AE_MAJOR_OP_ML_KEM        0x1A
#define ROC_AE_MINOR_OP_ML_KEM_KEYGEN 0x00
#define ROC_AE_MINOR_OP_ML_KEM_ENCAP  0x01
#define ROC_AE_MINOR_OP_ML_KEM_DECAP  0x02
#define ROC_AE_MAJOR_OP_ML_DSA        0x1B
#define ROC_AE_MINOR_OP_ML_DSA_KEYGEN 0x00
#define ROC_AE_MINOR_OP_ML_DSA_SIGN   0x01
#define ROC_AE_MINOR_OP_ML_DSA_VERIFY 0x02

#endif /*  __MC_AE_H__ */
