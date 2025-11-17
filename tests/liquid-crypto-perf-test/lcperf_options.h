/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef _LCPERF_OPTIONS_
#define _LCPERF_OPTIONS_

#include <stdio.h>

#include <rte_common.h>
#include <rte_memory.h>

#include <dao_liquid_crypto.h>

#define LCPERF_PTEST_TYPE        ("ptest")
#define LCPERF_TOTAL_OPS         ("total-ops")
#define LCPERF_DESC_NB           ("desc-nb")
#define LCPERF_OPTYPE            ("optype")
#define LCPERF_ASYM_OP           ("asym-op")
#define LCPERF_RSA_PRIV_KEYTYPE  ("rsa-priv-keytype")
#define LCPERF_RSA_MODLEN        ("rsa-modlen")
#define LCPERF_BURST_SIZE        ("burst-size")
#define LCPERF_SYM_OP            ("sym-op")
#define LCPERF_SYM_CIPHER_OP     ("cipher-op")
#define LCPERF_SYM_CIPHER_ALG    ("cipher-algo")
#define LCPERF_SYM_CIPHER_KEY_SZ ("cipher-key-sz")
#define LCPERF_SYM_AUTH_OP       ("auth-op")
#define LCPERF_SYM_AUTH_ALGO     ("auth-algo")
#define LCPERF_BUFFER_SIZE       ("buffer-size")
#define LCPERF_ENABLE_OOO        ("enable-ooo")

#define MAX_LIST 1

enum lcperf_perf_test_type {
	LCPERF_TEST_TYPE_THROUGHPUT,
	LCPERF_TEST_TYPE_LATENCY,
};

extern const char *lcperf_test_type_strs[];

enum lcperf_op_type {
	LCPERF_OP_PASSTHROUGH = 1,
	LCPERF_OP_ASYM_RSA,
	LCPERF_OP_SYM,
};

enum lcperf_crypto_asym_op_type {
	LCPERF_CRYPTO_ASYM_OP_PUB_ENCRYPT,
	LCPERF_CRYPTO_ASYM_OP_PRV_DECRYPT,
	LCPERF_CRYPTO_ASYM_OP_PRV_ENCRYPT,
	LCPERF_CRYPTO_ASYM_OP_PUB_DECRYPT,
};

enum lcperf_rsa_priv_keytype {
	LCPERF_RSA_KEY_TYPE_EXP,
	LCPERF_RSA_KEY_TYPE_QT,
	LCPERF_RSA_KEY_TYPE_MAX,
};

enum lcperf_crypto_sym_op_type {
	LCPERF_CRYPTO_SYM_OP_CIPHER_ONLY,
	LCPERF_CRYPTO_SYM_OP_AUTH_ONLY,
};

enum lcperf_crypto_sym_cipher_op_type {
	LCPERF_CRYPTO_SYM_CIPHER_OP_ENCRYPT,
	LCPERF_CRYPTO_SYM_CIPHER_OP_DECRYPT,
};

enum lcperf_crypto_sym_auth_op_type {
	LCPERF_CRYPTO_SYM_AUTH_OP_GENERATE,
	LCPERF_CRYPTO_SYM_AUTH_OP_VERIFY,
};

extern const char *lcperf_op_type_strs[];
extern const char *lcperf_rsa_priv_keytype_strs[];
extern const char *lcperf_crypto_asym_op_type_strs[];
extern const char *lcperf_crypto_sym_op_type_strs[];
extern const char *lcperf_crypto_sym_cipher_op_type_strs[];
extern const char *lcperf_crypto_sym_cipher_algo_strs[];
extern const char *lcperf_crypto_sym_auth_op_type_strs[];
extern const char *lcperf_crypto_sym_auth_algo_strs[];

struct lcperf_options {
	enum lcperf_perf_test_type test;

	uint32_t total_ops;
	uint32_t test_buffer_size;
	uint32_t nb_descriptors;

	enum lcperf_op_type op_type;
	enum lcperf_crypto_asym_op_type asym_op_type;
	enum lcperf_rsa_priv_keytype rsa_priv_keytype;

	uint32_t burst_size;

	uint32_t rsa_modlen;
	struct lcperf_rsa_test_data *rsa_data;

	enum dao_lc_fc_enc_cipher cipher_algo;
	enum lcperf_crypto_sym_op_type sym_op;
	enum lcperf_crypto_sym_cipher_op_type cipher_op;
	uint32_t cipher_key_sz;

	enum lcperf_crypto_sym_auth_op_type auth_op;
	enum dao_lc_hash_type auth_algo;

	/** Enable out-of-order delivery for performance testing */
	bool enable_ooo;
};

void lcperf_options_default(struct lcperf_options *options);

int lcperf_options_parse(struct lcperf_options *options, int argc, char **argv);

int lcperf_options_check(struct lcperf_options *options);

void lcperf_options_dump(struct lcperf_options *options);

#endif /* _LCPERF_OPTIONS_ */
