/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2026 Marvell.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_cycles.h>
#include <rte_random.h>

#include <dao_liquid_crypto.h>

#include "lc_autotest.h"
#include "lc_test_cpt_compdev_mix.h"
#include "lc_test_generic.h"
#include "test.h"

#define MIXED_TEST_CFG_FILE "tests/liquid-crypto-autotest/compress_test.cfg"
#define MIXED_OPS_MAX       1024
#define RNG_LEN             64

#define SYM_PLAIN_LEN  16
#define SYM_CIPHER_LEN 16
#define COMP_LEVEL_1   1

/* RSA PKCS1 v1.5 verify (public key decrypt) test vector - 1024-bit key */
#define RSA_MOD_LEN       128
#define RSA_EXP_LEN       3
#define RSA_PLAINTEXT_LEN 20

/* NIST SP 800-38A AES-128-CBC one block vector */
static const uint8_t sym_key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
				    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
static const uint8_t sym_iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
static const uint8_t sym_plaintext[SYM_PLAIN_LEN] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40,
						     0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11,
						     0x73, 0x93, 0x17, 0x2a};
static const uint8_t sym_ciphertext[SYM_CIPHER_LEN] = {0x76, 0x49, 0xab, 0xac, 0x81, 0x19,
						       0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b,
						       0x12, 0xe9, 0x19, 0x7d};

/* Compress test data (same as lc_test_comp.c) */
static const uint8_t comp_plain_text[] = {0x4D, 0x41, 0x52, 0x56, 0x45, 0x4C, 0x4C, 0x20, 0x4C,
					  0x43, 0x3A, 0x20, 0x54, 0x45, 0x53, 0x54, 0x20, 0x43,
					  0x4F, 0x4D, 0x50, 0x52, 0x45, 0x53, 0x53, 0x20, 0x44,
					  0x45, 0x56, 0x49, 0x43, 0x45, 0x0A};
static const uint8_t comp_compressed_text[] = {
	0xED, 0xFD, 0x47, 0x8E, 0x24, 0x49, 0xD2, 0xBC, 0xFF, 0xEF, 0xED, 0x14, 0x72,
	0x0E, 0xDB, 0x19, 0xD4, 0x64, 0x61, 0x80, 0x2A, 0xCC, 0xA0, 0xA2, 0xD0, 0xFB,
	0x1F, 0xC5, 0x4E, 0xF2, 0xC1, 0xE7, 0x20, 0xB1, 0xB2, 0xE9, 0x0E, 0xB7, 0x89,
	0xA2, 0x0A, 0x76, 0xE3, 0x25, 0x25, 0x6C, 0xF6, 0x31, 0x8E, 0x0F};

#define COMP_PLAIN_LEN      (sizeof(comp_plain_text))
#define COMP_COMPRESSED_LEN (sizeof(comp_compressed_text))

/* RSA PKCS#1 v1.5 verify test data (public key decrypt: sign -> plaintext) */
static const uint8_t rsa_n[RSA_MOD_LEN] = {
	0xb3, 0xa1, 0xaf, 0xb7, 0x13, 0x08, 0x00, 0x0a, 0x35, 0xdc, 0x2b, 0x20, 0x8d, 0xa1, 0xb5,
	0xce, 0x47, 0x8a, 0xc3, 0x80, 0xf4, 0x7d, 0x4a, 0xa2, 0x62, 0xfd, 0x61, 0x7f, 0xb5, 0xa8,
	0xde, 0x0a, 0x17, 0x97, 0xa0, 0xbf, 0xdf, 0x56, 0x5a, 0x3d, 0x51, 0x56, 0x4f, 0x70, 0x70,
	0x3f, 0x63, 0x6a, 0x44, 0x5b, 0xad, 0x84, 0x0d, 0x3f, 0x27, 0x6e, 0x3b, 0x34, 0x91, 0x60,
	0x14, 0xb9, 0xaa, 0x72, 0xfd, 0xa3, 0x64, 0xd2, 0x03, 0xa7, 0x53, 0x87, 0x9e, 0x88, 0x0b,
	0xc1, 0x14, 0x93, 0x1a, 0x62, 0xff, 0xb1, 0x5d, 0x74, 0xcd, 0x59, 0x63, 0x18, 0x11, 0x3d,
	0x4f, 0xba, 0x75, 0xd4, 0x33, 0x4e, 0x23, 0x6b, 0x7b, 0x57, 0x44, 0xe1, 0xd3, 0x03, 0x13,
	0xa6, 0xf0, 0x8b, 0x60, 0xb0, 0x9e, 0xee, 0x75, 0x08, 0x9d, 0x71, 0x63, 0x13, 0xcb, 0xa6,
	0x81, 0x92, 0x14, 0x03, 0x22, 0x2d, 0xde, 0x55};

static const uint8_t rsa_e[RSA_EXP_LEN] = {0x01, 0x00, 0x01};

static const uint8_t rsa_sign[RSA_MOD_LEN] = {
	0x2f, 0x42, 0xb3, 0xb1, 0x7f, 0xa8, 0x66, 0x00, 0xc6, 0xb4, 0x7d, 0x12, 0x67, 0x5f, 0x94,
	0xf7, 0x25, 0xd6, 0x7e, 0x14, 0xe4, 0xc2, 0x63, 0xb2, 0xdc, 0x1b, 0x13, 0xc0, 0xda, 0xda,
	0x0d, 0x32, 0x9b, 0xf4, 0x8a, 0x62, 0x90, 0xe7, 0xb3, 0xf3, 0xbb, 0x5a, 0xab, 0x5f, 0xf8,
	0xaf, 0xf4, 0x19, 0x0d, 0xa5, 0x66, 0x25, 0x95, 0x69, 0x57, 0x43, 0x87, 0x44, 0xb0, 0x92,
	0x1a, 0x39, 0xa6, 0x97, 0x06, 0xfd, 0xf3, 0x20, 0x72, 0xfb, 0xea, 0xef, 0xcf, 0xd1, 0x88,
	0xca, 0x23, 0x26, 0xa9, 0xa9, 0x22, 0xcd, 0xa0, 0x10, 0xf9, 0x14, 0x28, 0xc7, 0x0e, 0x82,
	0xe1, 0xcd, 0xc3, 0x31, 0x0f, 0x75, 0x6d, 0x69, 0xcd, 0x55, 0x30, 0xa3, 0x26, 0xcb, 0xf8,
	0xbc, 0xf3, 0xc5, 0xfa, 0xd7, 0x7e, 0x51, 0x81, 0xc9, 0x5c, 0x9f, 0x2a, 0x40, 0x40, 0x83,
	0xb3, 0xba, 0xdb, 0x94, 0x2d, 0x31, 0x1c, 0xf8,
};

static const uint8_t rsa_plaintext[RSA_PLAINTEXT_LEN] = {0xf8, 0xba, 0x1a, 0x55, 0xd0, 0x2f, 0x85,
							 0xae, 0x96, 0x7b, 0xb6, 0x2f, 0xb6, 0xcd,
							 0xa8, 0xeb, 0x7e, 0x78, 0xa0, 0x50};

/* Mixed test: CPT + compress device op types (sym, asym, rng, comp, decomp). */
enum mixed_op_type { OP_SYM = 0, OP_ASYM, OP_RNG, OP_COMP, OP_DECOMP, OP_TYPE_MAX };

/* One repeating unit: 2×(SYM|RNG|ASYM), (COMP|DECOMP), (SYM|RNG|ASYM), (COMP|DECOMP). */
#define MIXED_FIXED_PATTERN_LEN 5u

static uint32_t num_mixed_ops_cfg = 10;
static int mixed_cfg_loaded;

int
cpt_compdev_testsuite_setup(void)
{
	uint8_t dev_id = glb_params.dev_id;
	struct dao_lc_dev_caps caps = {0};
	int ret;

	ret = dao_liquid_crypto_dev_caps_get(&caps);
	if (ret < 0) {
		TEST_LC_ERR("Could not get liquid crypto device %d capabilities", dev_id);
		return TEST_SKIPPED;
	}

	if (caps.compdev_en)
		return 0;

	return TEST_SKIPPED;
}

static void
load_mixed_test_config(void)
{
	char line[256];
	uint32_t val;
	FILE *f;

	if (mixed_cfg_loaded)
		return;
	mixed_cfg_loaded = 1;

	f = fopen(MIXED_TEST_CFG_FILE, "r");
	if (f == NULL) {
		TEST_LC_INFO("Config '%s' not found, using num_mixed_ops=%u", MIXED_TEST_CFG_FILE,
			     num_mixed_ops_cfg);
		return;
	}

	while (fgets(line, sizeof(line), f) != NULL) {
		char *p = line;

		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '#' || *p == '\n' || *p == '\0')
			continue;
		if (sscanf(p, "num_mixed_ops=%u", &val) == 1) {
			if (val > 0 && val <= MIXED_OPS_MAX)
				num_mixed_ops_cfg = val;
			if (val > MIXED_OPS_MAX)
				num_mixed_ops_cfg = MIXED_OPS_MAX;
			break;
		}
	}
	fclose(f);
	TEST_LC_INFO("Mixed test: num_mixed_ops=%u from config", num_mixed_ops_cfg);
}

static int
sess_event_dequeue(uint8_t dev_id, struct dao_lc_cmd_event *ev)
{
	uint64_t timeout = rte_get_timer_cycles() + rte_get_timer_hz();
	int ret;

	do {
		ret = dao_liquid_crypto_cmd_event_dequeue(dev_id, ev, 1);
		if (ret == 1)
			break;
		if (rte_get_timer_cycles() > timeout) {
			TEST_LC_ERR("Session event timed out");
			return -1;
		}
	} while (ret == 0);

	if (ret != 1) {
		TEST_LC_ERR("Could not dequeue session event");
		return -1;
	}

	return 0;
}

/* Build symmetric context for AES-128-CBC (cipher only). */
static void
build_aes128_cbc_ctx(struct dao_lc_sym_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->opcode = DAO_LC_SYM_OPCODE_FC;
	ctx->iv_len = 16;
	ctx->fc.iv_source = DAO_LC_FC_IV_SRC_OP;
	ctx->fc.aes_key_len = DAO_LC_FC_AES_KEY_LEN_128;
	ctx->fc.enc_cipher = DAO_LC_FC_ENC_CIPHER_AES_CBC;
	memcpy(ctx->fc.encr_key, sym_key, sizeof(sym_key));
}

/* Random CPT op: symmetric, RNG, or asymmetric (used in pattern slots 0–1 and 3). */
static uint8_t
mixed_pattern_rand_crypto(void)
{
	switch (rte_rand() % 3) {
	case 0:
		return OP_SYM;
	case 1:
		return OP_RNG;
	default:
		return OP_ASYM;
	}
}

/* Random compress-device op: deflate compress or decompress (slots 2 and 4). */
static uint8_t
mixed_pattern_rand_comp_or_decomp(void)
{
	return (rte_rand() & 1u) ? OP_COMP : OP_DECOMP;
}

/**
 *  Mixed test: repeating 5-op blocks for all total_ops — per block:
 *   (SYM|RNG|ASYM), (SYM|RNG|ASYM), (COMP|DECOMP), (SYM|RNG|ASYM), (COMP|DECOMP).
 * total_ops is rounded up to a multiple of 5 (capped by MIXED_OPS_MAX).
 */

static int
ut_mixed_fixed_pattern_ops(void)
{
	struct dao_lc_buf *sym_in_bufs, *sym_out_bufs, *rng_out_bufs;
	uint8_t **comp_out, **decomp_out, **rng_out, **rsa_out;
	uint32_t n_sym, n_asym, n_rng, n_comp, n_decomp;
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	struct dao_lc_res *res = NULL;
	struct dao_lc_sym_ctx sym_ctx;
	uint8_t **sym_in, **sym_out;
	uint32_t count[OP_TYPE_MAX];
	struct dao_lc_cmd_event ev;
	int ret, rc = TEST_FAILED;
	int session_created = 0;
	uint16_t *op_buf_idx;
	uint64_t sess_cookie;
	uint64_t *op_cookie;
	uint32_t total_ops;
	uint8_t *op_type;
	uint32_t i, k;

	load_mixed_test_config();
	total_ops = num_mixed_ops_cfg;
	if (total_ops == 0)
		total_ops = 10;
	/**
	 * Entire run is N identical 5-op blocks (e.g. 100 -> 20 blocks).
	 * Round up to multiple of 5.
	 */
	total_ops = ((total_ops + MIXED_FIXED_PATTERN_LEN - 1) / MIXED_FIXED_PATTERN_LEN) *
		    MIXED_FIXED_PATTERN_LEN;
	if (total_ops > MIXED_OPS_MAX)
		total_ops = (MIXED_OPS_MAX / MIXED_FIXED_PATTERN_LEN) * MIXED_FIXED_PATTERN_LEN;
	if (total_ops < MIXED_FIXED_PATTERN_LEN)
		total_ops = MIXED_FIXED_PATTERN_LEN;

	op_type = malloc(total_ops * sizeof(*op_type));
	op_buf_idx = malloc(total_ops * sizeof(*op_buf_idx));
	op_cookie = malloc(total_ops * sizeof(*op_cookie));
	res = calloc(total_ops, sizeof(*res));
	if (op_type == NULL || op_buf_idx == NULL || op_cookie == NULL || res == NULL) {
		TEST_LC_ERR("Allocation failed");
		goto alloc_fail;
	}

	/* Per-op cookie; each 5-op block picks random CPT / comp types as allowed. */
	for (i = 0; i < total_ops; i++)
		op_cookie[i] = rte_rand();

	for (i = 0; i < total_ops; i += MIXED_FIXED_PATTERN_LEN) {
		op_type[i + 0] = mixed_pattern_rand_crypto();
		op_type[i + 1] = mixed_pattern_rand_crypto();
		op_type[i + 2] = mixed_pattern_rand_comp_or_decomp();
		op_type[i + 3] = mixed_pattern_rand_crypto();
		op_type[i + 4] = mixed_pattern_rand_comp_or_decomp();
	}

	/* Count each type and assign buffer index per op */
	memset(count, 0, sizeof(count));
	for (i = 0; i < total_ops; i++)
		op_buf_idx[i] = (uint16_t)count[op_type[i]]++;

	n_sym = count[OP_SYM];
	n_asym = count[OP_ASYM];
	n_rng = count[OP_RNG];
	n_comp = count[OP_COMP];
	n_decomp = count[OP_DECOMP];

	/* Allocate per-type buffers */
	sym_in = n_sym ? calloc(n_sym, sizeof(*sym_in)) : NULL;
	sym_out = n_sym ? calloc(n_sym, sizeof(*sym_out)) : NULL;
	comp_out = n_comp ? calloc(n_comp, sizeof(*comp_out)) : NULL;
	decomp_out = n_decomp ? calloc(n_decomp, sizeof(*decomp_out)) : NULL;
	rng_out = n_rng ? calloc(n_rng, sizeof(*rng_out)) : NULL;
	rsa_out = n_asym ? calloc(n_asym, sizeof(*rsa_out)) : NULL;
	sym_in_bufs = n_sym ? calloc(n_sym, sizeof(*sym_in_bufs)) : NULL;
	sym_out_bufs = n_sym ? calloc(n_sym, sizeof(*sym_out_bufs)) : NULL;
	rng_out_bufs = n_rng ? calloc(n_rng, sizeof(*rng_out_bufs)) : NULL;

	if ((n_sym && (!sym_in || !sym_out || !sym_in_bufs || !sym_out_bufs)) ||
	    (n_comp && !comp_out) || (n_decomp && !decomp_out) ||
	    (n_rng && (!rng_out || !rng_out_bufs)) || (n_asym && !rsa_out)) {
		TEST_LC_ERR("Buffer allocation failed");
		goto cleanup;
	}

	for (k = 0; k < n_sym; k++) {
		sym_in[k] = malloc(SYM_PLAIN_LEN);
		sym_out[k] = malloc(SYM_CIPHER_LEN);
		if (sym_in[k] == NULL || sym_out[k] == NULL)
			goto cleanup;
		memcpy(sym_in[k], sym_plaintext, SYM_PLAIN_LEN);
		sym_in_bufs[k].data = sym_in[k];
		sym_in_bufs[k].frag_len = SYM_PLAIN_LEN;
		sym_in_bufs[k].total_len = SYM_PLAIN_LEN;
		sym_out_bufs[k].data = sym_out[k];
		sym_out_bufs[k].frag_len = SYM_CIPHER_LEN;
		sym_out_bufs[k].total_len = SYM_CIPHER_LEN;
	}
	for (k = 0; k < n_comp; k++) {
		comp_out[k] = malloc(COMP_COMPRESSED_LEN);
		if (comp_out[k] == NULL)
			goto cleanup;
	}
	for (k = 0; k < n_decomp; k++) {
		decomp_out[k] = malloc(COMP_PLAIN_LEN);
		if (decomp_out[k] == NULL)
			goto cleanup;
	}
	for (k = 0; k < n_rng; k++) {
		rng_out[k] = malloc(RNG_LEN);
		if (rng_out[k] == NULL)
			goto cleanup;
		rng_out_bufs[k].data = rng_out[k];
		rng_out_bufs[k].frag_len = RNG_LEN;
		rng_out_bufs[k].total_len = RNG_LEN;
	}
	for (k = 0; k < n_asym; k++) {
		rsa_out[k] = malloc(RSA_MOD_LEN);
		if (rsa_out[k] == NULL)
			goto cleanup;
		memset(rsa_out[k], 0, RSA_MOD_LEN);
	}

	/* Create symmetric session if needed */
	if (n_sym > 0) {
		build_aes128_cbc_ctx(&sym_ctx);
		ret = dao_liquid_crypto_sym_sess_create(dev_id, &sym_ctx, sess_cookie = rte_rand());
		if (ret < 0) {
			TEST_LC_ERR("Could not create symmetric session");
			goto cleanup;
		}
		ret = sess_event_dequeue(dev_id, &ev);
		if (ret < 0 || ev.event_type != DAO_LC_CMD_EVENT_SESS_CREATE ||
		    ev.sess_event.sess_id == DAO_LC_SESS_ID_INVALID) {
			TEST_LC_ERR("Invalid session event");
			goto cleanup;
		}
		session_created = 1;
	}

	/* Enqueue all ops: same 5-slot pattern repeated for every block of 5 indices */
	for (i = 0; i < total_ops; i++) {
		k = op_buf_idx[i];
		switch (op_type[i]) {
		case OP_SYM: {
			struct dao_lc_buf *in_buf = &sym_in_bufs[k];
			struct dao_lc_buf *out_buf = &sym_out_bufs[k];
			struct dao_lc_sym_op op = {0};

			op.op_cookie = op_cookie[i];
			op.sess_id = ev.sess_event.sess_id;
			op.in_buffer = in_buf;
			op.out_buffer = out_buf;
			op.cipher_offset = 0;
			op.cipher_len = SYM_CIPHER_LEN;
			op.auth_offset = 0;
			op.auth_len = SYM_CIPHER_LEN;
			op.cipher_iv = (uint8_t *)sym_iv;
			op.encrypt = true;
			ret = dao_liquid_crypto_sym_enqueue_burst(dev_id, qp_id, &op, 1);
			break;
		}
		case OP_ASYM:
			ret = dao_liquid_crypto_enq_op_pkcs1v15dec(
				dev_id, qp_id, DAO_LC_RSA_KEY_TYPE_PUBLIC, RSA_MOD_LEN, RSA_EXP_LEN,
				rsa_n, rsa_e, rsa_sign, rsa_out[k], op_cookie[i]);
			break;
		case OP_RNG: {
			struct dao_lc_random_op rng_op = {.type = DAO_LC_RANDOM_TYPE_HW,
							  .out_buf = &rng_out_bufs[k],
							  .rand_len = RNG_LEN,
							  .op_cookie = op_cookie[i]};

			ret = dao_liquid_crypto_enq_op_random(dev_id, qp_id, &rng_op);
			break;
		}
		case OP_COMP: {
			struct dao_lc_comp_req_params req = {
				.in_data = (uint8_t *)comp_plain_text,
				.in_data_len = COMP_PLAIN_LEN,
				.out_data = comp_out[k],
				.out_data_len = COMP_COMPRESSED_LEN,
				.level = COMP_LEVEL_1,
				.huff_enc_type = DAO_LC_COMP_HUFFMAN_DYNAMIC,
			};

			ret = dao_liquid_crypto_enq_comp_op_deflate(dev_id, qp_id, &req,
								    op_cookie[i]);
			break;
		}
		case OP_DECOMP: {
			struct dao_lc_decomp_req_params req = {
				.in_data = (uint8_t *)comp_compressed_text,
				.in_data_len = COMP_COMPRESSED_LEN,
				.out_data = decomp_out[k],
				.out_data_len = COMP_PLAIN_LEN};

			ret = dao_liquid_crypto_enq_decomp_op_deflate(dev_id, qp_id, &req,
								      op_cookie[i]);
			break;
		}
		default:
			ret = -1;
			break;
		}
		if (op_type[i] == OP_SYM) {
			if (ret != 1) {
				TEST_LC_ERR("Sym enqueue failed for op %u", i);
				goto cleanup;
			}
		} else if (ret < 0) {
			TEST_LC_ERR("Enqueue failed for op %u type %u", i, op_type[i]);
			goto cleanup;
		}
	}

	uint32_t deq_ops, op_count = 0, l_total_ops = total_ops, retry = 0;

	do {
		deq_ops = op_dequeue_multi(dev_id, qp_id, res + op_count, l_total_ops);
		op_count += deq_ops;
		l_total_ops -= deq_ops;
		retry++;
		if (retry == 2)
			break;
	} while (op_count != total_ops);

	if (op_count != total_ops) {
		TEST_LC_ERR("All ops are not dequeued");
		goto cleanup;
	}

	/* Validate each result by cookie */
	for (i = 0; i < op_count; i++) {
		uint64_t cookie = res[i].op_cookie;
		uint32_t j;

		for (j = 0; j < total_ops && op_cookie[j] != cookie; j++)
			;
		if (j >= total_ops) {
			TEST_LC_ERR("Unknown cookie in result");
			goto cleanup;
		}
		k = op_buf_idx[j];
		switch (op_type[j]) {
		case OP_SYM:
			if (res[i].res.cn9k.compcode != DAO_CPT_COMP_GOOD ||
			    res[i].res.cn9k.uc_compcode != DAO_UC_SUCCESS) {
				TEST_LC_ERR("Sym op failed");
				goto cleanup;
			}
			if (memcmp(sym_out[k], sym_ciphertext, SYM_CIPHER_LEN) != 0) {
				TEST_LC_ERR("Sym result mismatch");
				goto cleanup;
			}
			break;
		case OP_ASYM:
			if (res[i].res.cn9k.compcode != DAO_CPT_COMP_GOOD ||
			    res[i].res.cn9k.uc_compcode != DAO_UC_SUCCESS ||
			    res[i].rsa.data_out_len != RSA_PLAINTEXT_LEN) {
				TEST_LC_ERR("Asym op failed");
				goto cleanup;
			}
			if (memcmp(rsa_out[k], rsa_plaintext, RSA_PLAINTEXT_LEN) != 0) {
				TEST_LC_ERR("Asym result mismatch");
				goto cleanup;
			}
			break;
		case OP_RNG: {
			uint32_t z;

			for (z = 0; z < RNG_LEN && rng_out[k][z] == 0; z++)
				;
			if (z >= RNG_LEN) {
				TEST_LC_ERR("RNG output all zeros");
				goto cleanup;
			}
			break;
		}
		case OP_COMP:
			if (res[i].compdev_res.status != DAO_LC_COMP_OP_STATUS_SUCCESS ||
			    res[i].compdev_res.produced != COMP_COMPRESSED_LEN) {
				TEST_LC_ERR("Comp op failed");
				goto cleanup;
			}
			if (memcmp(comp_out[k], comp_compressed_text, COMP_COMPRESSED_LEN) != 0) {
				TEST_LC_ERR("Comp result mismatch");
				goto cleanup;
			}
			break;
		case OP_DECOMP:
			if (res[i].compdev_res.status != DAO_LC_COMP_OP_STATUS_SUCCESS ||
			    res[i].compdev_res.produced != COMP_PLAIN_LEN) {
				TEST_LC_ERR("Decomp op failed");
				goto cleanup;
			}
			if (memcmp(decomp_out[k], comp_plain_text, COMP_PLAIN_LEN) != 0) {
				TEST_LC_ERR("Decomp result mismatch");
				goto cleanup;
			}
			break;
		default:
			goto cleanup;
		}
	}

	rc = TEST_SUCCESS;

cleanup:
	if (session_created) {
		sess_cookie = rte_rand();
		dao_liquid_crypto_sym_sess_destroy(dev_id, ev.sess_event.sess_id, sess_cookie);
		sess_event_dequeue(dev_id, &ev);
	}

	if (sym_in || sym_out) {
		for (k = 0; k < n_sym; k++) {
			if (sym_in)
				free(sym_in[k]);
			if (sym_out)
				free(sym_out[k]);
		}
	}

	if (comp_out) {
		for (k = 0; k < n_comp; k++)
			free(comp_out[k]);
	}
	if (decomp_out) {
		for (k = 0; k < n_decomp; k++)
			free(decomp_out[k]);
	}
	if (rng_out) {
		for (k = 0; k < n_rng; k++)
			free(rng_out[k]);
	}
	if (rsa_out) {
		for (k = 0; k < n_asym; k++)
			free(rsa_out[k]);
	}

	free(sym_in);
	free(sym_out);
	free(comp_out);
	free(decomp_out);
	free(rng_out);
	free(rsa_out);
	free(sym_in_bufs);
	free(sym_out_bufs);
	free(rng_out_bufs);
alloc_fail:
	free(op_type);
	free(op_buf_idx);
	free(op_cookie);
	free(res);
	return rc;
}

/* -------- Test suite -------- */
struct unit_test_suite lc_testsuite_cpt_compdev_mix = {
	.suite_name = "Liquid Crypto CPT + Compress Device Combined Test Suite",
	.setup = cpt_compdev_testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		TEST_CASE_NAMED_ST("Mixed CPT + Compress + CPT tests", ut_setup,
				   ut_teardown, ut_mixed_fixed_pattern_ops),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};
