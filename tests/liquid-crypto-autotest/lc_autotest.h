/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __LC_AUTOTEST_H__
#define __LC_AUTOTEST_H__

#include <rte_log.h>

/* Log type */
#define RTE_LOGTYPE_TEST              RTE_LOGTYPE_USER1
#define TEST_LC_INFO(fmt, args...)    RTE_LOG(INFO, TEST, fmt "\n", ##args)
#define TEST_LC_INFO_NH(fmt, args...) rte_log(RTE_LOG_INFO, RTE_LOGTYPE_AGENT, fmt "\n", ##args)
#define TEST_LC_ERR(fmt, args...)     RTE_LOG(ERR, TEST, fmt "\n", ##args)

/* Test timeout */
#define TEST_LC_TIMEOUT 10

/* Maximum length of output buffer */
#define TEST_LC_MAX_OUTPUT_LEN 5120
/* Maximum length of plaintext */
#define TEST_LC_MAX_PLAINTEXT_LEN 1024
/* Maximum length of ciphertext */
#define TEST_LC_MAX_CIPHERTEXT_LEN 1024
/* Maximum length of IV */
#define TEST_LC_MAX_IV_LEN 16
/* Maximum length of AAD */
#define TEST_LC_MAX_AAD_LEN 1024
/* Maximum length of digest */
#define TEST_LC_MAX_DIGEST_LEN 255
/* Maximum offset length to test*/
#define TEST_LC_MAX_OFFSET 32
/* Maximum Authentication HMAC key length */
#define TEST_LC_MAX_HMAC_KEY_LEN 1024
/* Minimum length of RSA sign modulus */
#define TEST_LC_MIN_RSA_SIGN_MOD_LEN 34
/* Minimum length of RSA encrypt modulus */
#define TEST_LC_MIN_RSA_ENC_MOD_LEN 17
/* Maximum length of RSA modulus */
#define TEST_LC_MAX_RSA_MOD_LEN 1024
/* Maximum Random Data Length */
#define TEST_LC_MAX_RANDOM_LEN 1024
/* Maximum iteration for random test */
#define TEST_LC_MAX_RANDOM_ITER 1024
/* Maximum length of auth key */
#define TEST_LC_MAX_AUTH_KEY_LEN 64
/* Maximum length of ECC digest */
#define TEST_LC_MAX_ECC_DIGEST_LEN 66
/* Maximum length of AES key wrap key data */
#define TEST_LC_MAX_KEY_DATA_LEN 3072
/* AES Key Wrap IV length */
#define TEST_LC_AES_KEY_WRAP_IV_LEN 8
/* RSA OAEP maximum label length in bytes */
#define TEST_LC_RSA_OAEP_MAX_LABEL_LEN 1024
/* RSA OAEP maximum modulus length in bytes */
#define TEST_LC_RSA_OAEP_MAX_MOD_LEN 988

#endif /* __LC_AUTOTEST_H__ */
