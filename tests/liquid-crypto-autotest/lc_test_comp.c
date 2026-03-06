/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2026 Marvell.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dao_liquid_crypto.h>

#include <rte_random.h>

#include "lc_autotest.h"
#include "lc_test_comp.h"
#include "lc_test_comp_priv.h"
#include "lc_test_generic.h"
#include "test.h"

#define COMP_LEVEL_1       1
#define COMP_TEST_CFG_FILE "tests/liquid-crypto-autotest/compress_test.cfg"

/* Below values are supported with 8 hugepages for compress device */
#define CA_MAX_COMP_OPERATIONS           2048
#define COMP_TEST_MAX_OPS                CA_MAX_COMP_OPERATIONS
#define COMP_TEST_DEFAULT_COMPRESS_OPS   10
#define COMP_TEST_DEFAULT_DECOMPRESS_OPS 10
#define COMP_TEST_DEFAULT_ITERATIONS     10

struct comp_test_config {
	uint32_t num_compress_ops;
	uint32_t num_decompress_ops;
	uint16_t iterations;
};

static struct comp_test_config comp_test_cfg = {
	.num_compress_ops = COMP_TEST_DEFAULT_COMPRESS_OPS,
	.num_decompress_ops = COMP_TEST_DEFAULT_DECOMPRESS_OPS,
	.iterations = COMP_TEST_DEFAULT_ITERATIONS,
};

static uint32_t g_comp_data_len, g_plain_data_len;
static uint8_t *g_comp_data;

extern struct global_params glb_params;
static int comp_test_cfg_loaded;

static const uint8_t plain_text[] = {0x4D, 0x41, 0x52, 0x56, 0x45, 0x4C, 0x4C, 0x20, 0x4C,
				     0x43, 0x3A, 0x20, 0x54, 0x45, 0x53, 0x54, 0x20, 0x43,
				     0x4F, 0x4D, 0x50, 0x52, 0x45, 0x53, 0x53, 0x20, 0x44,
				     0x45, 0x56, 0x49, 0x43, 0x45, 0x0A};

static const uint8_t compressed_text[] = {
	0xED, 0xFD, 0x47, 0x8E, 0x24, 0x49, 0xD2, 0xBC, 0xFF, 0xEF, 0xED, 0x14, 0x72,
	0x0E, 0xDB, 0x19, 0xD4, 0x64, 0x61, 0x80, 0x2A, 0xCC, 0xA0, 0xA2, 0xD0, 0xFB,
	0x1F, 0xC5, 0x4E, 0xF2, 0xC1, 0xE7, 0x20, 0xB1, 0xB2, 0xE9, 0x0E, 0xB7, 0x89,
	0xA2, 0x0A, 0x76, 0xE3, 0x25, 0x25, 0x6C, 0xF6, 0x31, 0x8E, 0x0F};

uint8_t *
text_to_bytes_with_null(const char *text, size_t *out_len)
{
	uint8_t *buf;
	size_t len;

	if (!text || !out_len) {
		TEST_LC_ERR("Input parameter is NULL");
		return NULL;
	}

	len = strlen(text) + 1;

	buf = malloc(len);
	if (buf == NULL)
		return NULL;

	memcpy(buf, text, len); /* includes '\0' */

	*out_len = len;

	return buf;
}

/**
 * Parse compress_test.cfg from tests/liquid-crypto-autotest/ directory.
 * Key=value format; keys: num_compress_ops, num_decompress_ops, iterations.
 * Values must be in [1, COMP_TEST_MAX_OPS]. out-of-range values are ignored
 * and defaults remain in effect.
 */
static void
load_comp_test_config(void)
{
	char line[256];
	FILE *f;

	if (comp_test_cfg_loaded)
		return;

	comp_test_cfg_loaded = 1;

	f = fopen(COMP_TEST_CFG_FILE, "r");
	if (f == NULL) {
		TEST_LC_INFO("Config '%s' not found, using defaults", COMP_TEST_CFG_FILE);
		return;
	}

	while (fgets(line, sizeof(line), f) != NULL) {
		char *p = line;
		unsigned int val;

		/* Trim leading whitespace and skip empty / comment lines */
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '#' || *p == '\n' || *p == '\0')
			continue;

		if (sscanf(p, "num_compress_ops=%u", &val) == 1) {
			if (val > 0 && val <= COMP_TEST_MAX_OPS)
				comp_test_cfg.num_compress_ops = val;
		} else if (sscanf(p, "num_decompress_ops=%u", &val) == 1) {
			if (val > 0 && val <= COMP_TEST_MAX_OPS)
				comp_test_cfg.num_decompress_ops = val;
		} else if (sscanf(p, "iterations=%u", &val) == 1) {
			if (val > 0 && val <= COMP_TEST_MAX_OPS)
				comp_test_cfg.iterations = val;
		}
	}

	fclose(f);
	TEST_LC_INFO("Config loaded from '%s': compress_ops=%u, decompress_ops=%u, iterations=%u",
		     COMP_TEST_CFG_FILE, comp_test_cfg.num_compress_ops,
		     comp_test_cfg.num_decompress_ops, comp_test_cfg.iterations);
}

static void
fill_compress_req_param(struct dao_lc_comp_req_params *req, const uint8_t *in_data,
			uint32_t in_data_len, uint8_t *out_data, uint32_t out_data_len)
{
	if (!req) {
		TEST_LC_ERR("Compress request is NULL");
		return;
	}

	req->huff_enc_type = DAO_LC_COMP_HUFFMAN_DYNAMIC;
	req->level = COMP_LEVEL_1;
	req->in_data = (uint8_t *)in_data;
	req->in_data_len = in_data_len;
	req->out_data = out_data;
	req->out_data_len = out_data_len;
}

static void
fill_decompress_req_param(struct dao_lc_decomp_req_params *req, const uint8_t *in_data,
			  uint32_t in_data_len, uint8_t *out_data, uint32_t out_data_len)
{
	if (!req) {
		TEST_LC_ERR("Decompress request is NULL");
		return;
	}

	req->in_data = (uint8_t *)in_data;
	req->in_data_len = in_data_len;
	req->out_data = out_data;
	req->out_data_len = out_data_len;
}

int
compdev_testsuite_setup(void)
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

/**
 * Test compress device compress operation
 */
static int
ut_compdev_compress_op(void)
{
	struct dao_lc_comp_req_params req = {0};
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	struct dao_lc_res *res;
	uint32_t data_len;
	uint8_t *data_out;
	int ret;

	const uint8_t *test_data = plain_text;

	data_len = sizeof(plain_text);
	res = malloc(sizeof(struct dao_lc_res) + data_len);
	if (res == NULL) {
		TEST_LC_ERR("Could not allocate memory for res");
		return TEST_FAILED;
	}
	data_out = malloc(sizeof(compressed_text));
	if (data_out == NULL) {
		TEST_LC_ERR("Could not allocate memory for data_out");
		free(res);
		return TEST_FAILED;
	}

	fill_compress_req_param(&req, test_data, data_len, data_out, sizeof(compressed_text));

	/* Enqueue deflate compress operation */
	ret = dao_liquid_crypto_enq_comp_op_deflate(dev_id, qp_id, &req, op_cookie);

	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue deflate operation");
		free(res);
		free(data_out);
		return TEST_FAILED;
	}

	/* Dequeue result */
	ret = op_dequeue(dev_id, qp_id, res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue deflate operation");
		free(res);
		free(data_out);
		return TEST_FAILED;
	}

	/* Validate operation cookie */
	TEST_ASSERT(res->op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res->compdev_res.status == DAO_LC_COMP_OP_STATUS_SUCCESS,
		    "Expected status did not match");
	TEST_ASSERT(res->compdev_res.produced == sizeof(compressed_text),
		    "Compressed output size did not match the expected size");
	ret = memcmp(data_out, compressed_text, res->compdev_res.produced);
	TEST_ASSERT(ret == 0, "Compressed Text did not match with the expected");

	free(res);
	free(data_out);

	return TEST_SUCCESS;
}

static int
ut_compdev_decompress_op(void)
{
	struct dao_lc_decomp_req_params req = {0};
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	struct dao_lc_res *res;
	uint32_t data_len;
	uint8_t *data_out;
	int ret;

	data_len = sizeof(compressed_text);
	res = malloc(sizeof(struct dao_lc_res) + data_len);
	if (res == NULL) {
		TEST_LC_ERR("Could not allocate memory for res");
		return TEST_FAILED;
	}
	data_out = malloc(sizeof(plain_text));
	if (data_out == NULL) {
		TEST_LC_ERR("Could not allocate memory for data");
		free(res);
		return TEST_FAILED;
	}

	fill_decompress_req_param(&req, compressed_text, data_len, data_out, sizeof(plain_text));
	ret = dao_liquid_crypto_enq_decomp_op_deflate(dev_id, qp_id, &req, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue deflate decomp operation");
		free(res);
		free(data_out);
		return TEST_FAILED;
	}

	/* Dequeue result */
	ret = op_dequeue(dev_id, qp_id, res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue deflate operation");
		free(res);
		free(data_out);
		return TEST_FAILED;
	}

	/* Validate operation cookie */
	TEST_ASSERT(res->op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res->compdev_res.status == DAO_LC_COMP_OP_STATUS_SUCCESS,
		    "Expected status did not match");
	TEST_ASSERT(res->compdev_res.produced == sizeof(plain_text),
		    "Decompressed output size did not match the expected size");

	ret = memcmp(data_out, plain_text, res->compdev_res.produced);
	TEST_ASSERT(ret == 0, "Plain text did not match with the expected");

	free(res);
	free(data_out);

	return TEST_SUCCESS;
}

static const uint8_t repeated_text[] = {
	0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E,
	0x20, 0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70, 0x73, 0x20, 0x6F, 0x76, 0x65, 0x72,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x6C, 0x61, 0x7A, 0x79, 0x20, 0x64, 0x6F, 0x67, 0x2E, 0x0A,
	0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E,
	0x20, 0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70, 0x73, 0x20, 0x6F, 0x76, 0x65, 0x72,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x6C, 0x61, 0x7A, 0x79, 0x20, 0x64, 0x6F, 0x67, 0x2E, 0x0A,
	0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E,
	0x20, 0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70, 0x73, 0x20, 0x6F, 0x76, 0x65, 0x72,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x6C, 0x61, 0x7A, 0x79, 0x20, 0x64, 0x6F, 0x67, 0x2E, 0x0A,
	0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E,
	0x20, 0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70, 0x73, 0x20, 0x6F, 0x76, 0x65, 0x72,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x6C, 0x61, 0x7A, 0x79, 0x20, 0x64, 0x6F, 0x67, 0x2E, 0x0A,
	0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E,
	0x20, 0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70, 0x73, 0x20, 0x6F, 0x76, 0x65, 0x72,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x6C, 0x61, 0x7A, 0x79, 0x20, 0x64, 0x6F, 0x67, 0x2E, 0x0A,
	0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E,
	0x20, 0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70, 0x73, 0x20, 0x6F, 0x76, 0x65, 0x72,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x6C, 0x61, 0x7A, 0x79, 0x20, 0x64, 0x6F, 0x67, 0x2E, 0x0A,
	0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E,
	0x20, 0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70, 0x73, 0x20, 0x6F, 0x76, 0x65, 0x72,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x6C, 0x61, 0x7A, 0x79, 0x20, 0x64, 0x6F, 0x67, 0x2E, 0x0A,
};

static const uint8_t compressed_text_for_repeated[] = {
	0xED, 0xFD, 0x47, 0x8E, 0x24, 0x49, 0xD2, 0xBC, 0xFF, 0xEF, 0xFD, 0x14, 0x72, 0x02,
	0x3F, 0x8D, 0x5D, 0xC0, 0x89, 0xBA, 0x9B, 0x13, 0x33, 0x35, 0xCE, 0x4E, 0x6F, 0x5B,
	0x3B, 0x84, 0x3D, 0x78, 0x96, 0x9F, 0x43, 0x08, 0x49, 0xB0, 0xF1, 0x39, 0x3E, 0xEC,
	0x8E, 0xB3, 0xC6, 0xC5, 0x05, 0x6F, 0x54, 0xC6, 0x83, 0x13, 0x39, 0x04, 0x49, 0xF8,
	0xB7, 0x56, 0x71, 0xF2, 0xBD, 0x2E, 0x62, 0xE2, 0x01, 0x77,
};

/**
 * Test compress device compress operation for repeated text.
 */
static int
ut_compdev_compress_repeated_text(void)
{
	const uint8_t *test_data = repeated_text;
	struct dao_lc_comp_req_params req = {0};
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint32_t data_len, comp_data_len;
	uint64_t op_cookie = rte_rand();
	struct dao_lc_res *res;
	uint8_t *data_out;
	int ret, rc;

	data_len = sizeof(repeated_text);
	comp_data_len = sizeof(compressed_text_for_repeated);
	res = malloc(sizeof(struct dao_lc_res) + data_len);
	if (res == NULL) {
		TEST_LC_ERR("Could not allocate memory for res");
		return TEST_FAILED;
	}
	data_out = malloc(comp_data_len);
	if (data_out == NULL) {
		TEST_LC_ERR("Could not allocate memory for data");
		free(res);
		return TEST_FAILED;
	}

	fill_compress_req_param(&req, test_data, data_len, data_out, comp_data_len);

	/* Enqueue deflate compress operation */
	ret = dao_liquid_crypto_enq_comp_op_deflate(dev_id, qp_id, &req, op_cookie);

	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue deflate operation");
		rc = TEST_FAILED;
		goto cleanup;
	}

	/* Dequeue result */
	ret = op_dequeue(dev_id, qp_id, res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue deflate operation");
		rc = TEST_FAILED;
		goto cleanup;
	}

	/* Validate operation cookie */
	TEST_ASSERT(res->op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res->compdev_res.status == DAO_LC_COMP_OP_STATUS_SUCCESS,
		    "Expected status did not match");
	TEST_ASSERT(res->compdev_res.produced == sizeof(compressed_text_for_repeated),
		    "Compressed output size did not match the expected size");

	ret = memcmp(data_out, compressed_text_for_repeated, res->compdev_res.produced);
	TEST_ASSERT(ret == 0, "Compressed Text for repeated text did not match with the expected");
	rc = TEST_SUCCESS;

cleanup:
	free(res);
	free(data_out);

	return rc;
}

static int
ut_compdev_decompress_repeated_text(void)
{
	struct dao_lc_decomp_req_params req = {0};
	uint8_t dev_id = glb_params.dev_id;
	uint32_t data_len, plain_text_len;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	struct dao_lc_res *res;
	uint8_t *data_out;
	int ret, rc;

	data_len = sizeof(compressed_text_for_repeated);
	plain_text_len = sizeof(repeated_text);
	/* Plain text length is greater than compressed text */
	res = malloc(sizeof(struct dao_lc_res) + data_len);
	if (res == NULL) {
		TEST_LC_ERR("Could not allocate memory for res");
		return TEST_FAILED;
	}
	data_out = malloc(plain_text_len);
	if (data_out == NULL) {
		TEST_LC_ERR("Could not allocate memory for data");
		free(res);
		return TEST_FAILED;
	}

	fill_decompress_req_param(&req, compressed_text_for_repeated, data_len, data_out,
				  plain_text_len);
	ret = dao_liquid_crypto_enq_decomp_op_deflate(dev_id, qp_id, &req, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue deflate decomp operation");
		rc = TEST_FAILED;
		goto cleanup;
	}

	/* Dequeue result */
	ret = op_dequeue(dev_id, qp_id, res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue deflate operation");
		rc = TEST_FAILED;
		goto cleanup;
	}

	/* Validate operation cookie */
	TEST_ASSERT(res->op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res->compdev_res.status == DAO_LC_COMP_OP_STATUS_SUCCESS,
		    "Expected status did not match");
	TEST_ASSERT(res->compdev_res.produced == sizeof(repeated_text),
		    "Decompressed output size did not match the expected size");

	ret = memcmp(data_out, repeated_text, res->compdev_res.produced);
	TEST_ASSERT(ret == 0, "Repeated plain text did not match with the expected");
	rc = TEST_SUCCESS;

cleanup:
	free(res);
	free(data_out);

	return rc;
}

/**
 * Test compress device compress operation
 */
static int
ut_compdev_compress_op_with_less_output_buf(void)
{
	struct dao_lc_comp_req_params req = {0};
	const uint8_t *test_data = plain_text;
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	uint32_t data_len, op_data_len;
	struct dao_lc_res *res;
	uint8_t *data_out;
	int ret, rc;

	data_len = sizeof(plain_text);
	op_data_len = sizeof(compressed_text);
	res = malloc(sizeof(struct dao_lc_res) + data_len);
	if (res == NULL) {
		TEST_LC_ERR("Could not allocate memory for res");
		return TEST_FAILED;
	}
	data_out = malloc(op_data_len);
	if (data_out == NULL) {
		TEST_LC_ERR("Could not allocate memory for data");
		free(res);
		return TEST_FAILED;
	}

	fill_compress_req_param(&req, test_data, data_len, data_out, (op_data_len - 1));

	/* Enqueue compress operation with less output buffer length */
	ret = dao_liquid_crypto_enq_comp_op_deflate(dev_id, qp_id, &req, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue deflate operation");
		rc = TEST_FAILED;
		goto cleanup;
	}

	/* Dequeue result */
	ret = op_dequeue(dev_id, qp_id, res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue deflate operation");
		rc = TEST_FAILED;
		goto cleanup;
	}

	/* Validate operation cookie */
	TEST_ASSERT(res->op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res->compdev_res.status == DAO_LC_COMP_OP_STATUS_RESP_BUF_SPACE_ISSUE,
		    "Expected status did not match");
	TEST_ASSERT(res->compdev_res.required == op_data_len,
		    "Required length of buffer did not match");

	op_cookie = rte_rand();
	fill_compress_req_param(&req, test_data, data_len, data_out, op_data_len);
	/* Enqueue compress operation with correct length */
	ret = dao_liquid_crypto_enq_comp_op_deflate(dev_id, qp_id, &req, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue deflate operation");
		rc = TEST_FAILED;
		goto cleanup;
	}

	/* Dequeue result */
	ret = op_dequeue(dev_id, qp_id, res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue deflate operation");
		rc = TEST_FAILED;
		goto cleanup;
	}

	TEST_ASSERT(res->op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res->compdev_res.status == DAO_LC_COMP_OP_STATUS_SUCCESS,
		    "Expected status did not match");
	TEST_ASSERT(res->compdev_res.produced == sizeof(compressed_text),
		    "Compressed output size did not match the expected size");
	ret = memcmp(data_out, compressed_text, res->compdev_res.produced);
	TEST_ASSERT(ret == 0, "Compressed Text did not match with the expected");
	rc = TEST_SUCCESS;

cleanup:
	free(res);
	free(data_out);

	return rc;
}

/**
 * This test compresses large text (input) and stores the compressed output in a global
 * pointer.
 * In ut_compdev_decompress_with_large_text function, it uses this compressed data as
 * input and decompresses it. After decompression, it validates the decompressed
 * output with the input data provided in this function.
 */
static int
ut_compdev_compress_op_with_large_text(void)
{
	struct dao_lc_comp_req_params req = {0};
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	uint8_t *test_buf, *data_out;
	struct dao_lc_res *res;
	size_t out_len = 0;
	int op_len = 4000;
	int ret, rc;

	test_buf = text_to_bytes_with_null(large_text, &out_len);
	if (!test_buf) {
		TEST_LC_ERR("Could not allocate memory for test buf");
		return TEST_FAILED;
	}
	g_plain_data_len = out_len;
	res = malloc(sizeof(struct dao_lc_res) + g_plain_data_len);
	if (res == NULL) {
		TEST_LC_ERR("Could not allocate memory for res");
		free(test_buf);
		return TEST_FAILED;
	}
	data_out = malloc(op_len);
	if (data_out == NULL) {
		TEST_LC_ERR("Could not allocate memory for data");
		free(res);
		free(test_buf);
		return TEST_FAILED;
	}

	fill_compress_req_param(&req, test_buf, g_plain_data_len, data_out, op_len);

	ret = dao_liquid_crypto_enq_comp_op_deflate(dev_id, qp_id, &req, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue deflate operation");
		rc = TEST_FAILED;
		goto cleanup;
	}

	/* Dequeue result */
	ret = op_dequeue(dev_id, qp_id, res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue deflate operation");
		rc = TEST_FAILED;
		goto cleanup;
	}

	g_comp_data = data_out;

	TEST_ASSERT(res->op_cookie == op_cookie, "Invalid operation cookie");
	TEST_ASSERT(res->compdev_res.status == DAO_LC_COMP_OP_STATUS_SUCCESS,
		    "Expected status did not match");

	rc = TEST_SUCCESS;
	g_comp_data_len = res->compdev_res.produced;
cleanup:
	if (rc != TEST_SUCCESS)
		free(data_out);
	free(res);
	free(test_buf);

	return rc;
}

/**
 * This function takes compressed data from ut_compdev_compress_op_with_large_text
 * as input. It compares the decompressed output with the plain large text, which
 * was used input in ut_compdev_compress_op_with_large_text test.
 */
static int
ut_compdev_decompress_with_large_text(void)
{
	struct dao_lc_decomp_req_params req = {0};
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = rte_rand();
	uint8_t *data_out, *test_buf;
	struct dao_lc_res *res;
	size_t out_len;
	int ret, rc;

	if (!g_comp_data_len) {
		TEST_LC_ERR("Compress data length not set");
		return TEST_SKIPPED;
	}

	res = malloc(sizeof(struct dao_lc_res) + g_comp_data_len);
	if (res == NULL) {
		TEST_LC_ERR("Could not allocate memory for res");
		return TEST_FAILED;
	}

	data_out = malloc(g_plain_data_len);
	if (data_out == NULL) {
		TEST_LC_ERR("Could not allocate memory for data");
		free(res);
		return TEST_FAILED;
	}

	fill_decompress_req_param(&req, g_comp_data, g_comp_data_len, data_out, g_plain_data_len);
	ret = dao_liquid_crypto_enq_decomp_op_deflate(dev_id, qp_id, &req, op_cookie);
	if (ret < 0) {
		TEST_LC_ERR("Could not enqueue deflate decomp operation");
		rc = TEST_FAILED;
		goto cleanup;
	}

	/* Dequeue result */
	ret = op_dequeue(dev_id, qp_id, res);
	if (ret < 0) {
		TEST_LC_ERR("Could not dequeue deflate operation");
		rc = TEST_FAILED;
		goto cleanup;
	}

	/* Validate operation cookie */
	TEST_ASSERT(res->op_cookie == op_cookie, "Invalid operation cookie");

	test_buf = text_to_bytes_with_null(large_text, &out_len);
	if (test_buf == NULL) {
		TEST_LC_ERR("Failed to allocate buffer for expected plain text");
		rc = TEST_FAILED;
		goto cleanup;
	}
	TEST_ASSERT(res->compdev_res.produced == out_len,
		    "Decompressed output size did not match the expected size");
	ret = memcmp(data_out, test_buf, res->compdev_res.produced);

	TEST_ASSERT(ret == 0, "Plain text did not match with the expected");
	rc = TEST_SUCCESS;

	free(test_buf);
cleanup:
	free(res);
	free(g_comp_data);
	g_comp_data = NULL;
	g_comp_data_len = 0;
	free(data_out);

	return rc;
}

static int
ut_compdev_multi_compress_ops_in_order(void)
{
	struct dao_lc_comp_req_params req = {0};
	uint32_t num_op, i, data_len, rc_multi;
	const uint8_t *test_data = plain_text;
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	struct dao_lc_res *comp_res;
	int ret, rc;

	load_comp_test_config();
	num_op = comp_test_cfg.num_compress_ops;

	uint64_t op_cookie[num_op];
	uint8_t *data_out[num_op];

	memset(data_out, 0, sizeof(data_out));
	data_len = sizeof(plain_text);
	comp_res = calloc(num_op, sizeof(*comp_res));
	if (comp_res == NULL) {
		TEST_LC_ERR("Could not allocate memory for comp_res");
		return TEST_FAILED;
	}

	for (i = 0; i < num_op; i++) {
		data_out[i] = malloc(sizeof(compressed_text));
		if (data_out[i] == NULL) {
			TEST_LC_ERR("Could not allocate memory for data: %d", i);
			rc = TEST_FAILED;
			goto cleanup;
		}
		op_cookie[i] = rte_rand();
	}

	TEST_LC_INFO("Testing with %u compress requests", num_op);
	for (i = 0; i < num_op; i++) {
		fill_compress_req_param(&req, test_data, data_len, data_out[i],
					sizeof(compressed_text));
		/* Enqueue deflate compress operation */
		ret = dao_liquid_crypto_enq_comp_op_deflate(dev_id, qp_id, &req, op_cookie[i]);

		if (ret < 0) {
			TEST_LC_ERR("Could not enqueue deflate operation");
			rc = TEST_FAILED;
			goto cleanup;
		}
	}
	rc_multi = op_dequeue_multi(dev_id, qp_id, comp_res, num_op);
	if (rc_multi != num_op) {
		TEST_LC_ERR("Could not dequeue operation");
		rc = TEST_FAILED;
		goto cleanup;
	}

	for (i = 0; i < num_op; i++) {
		TEST_ASSERT(comp_res[i].op_cookie == op_cookie[i],
			    "Invalid operation cookie for OP: %d", i);
		TEST_ASSERT(comp_res[i].compdev_res.produced == sizeof(compressed_text),
			    "Compressed output size did not match the expected size");
		ret = memcmp(data_out[i], compressed_text, comp_res[i].compdev_res.produced);
		TEST_ASSERT(ret == 0, "Compressed Text did not match with the expected");
	}
	rc = TEST_SUCCESS;

cleanup:
	/* Cleanup memory */
	if (comp_res != NULL)
		free(comp_res);

	if (data_out != NULL) {
		for (i = 0; i < num_op; i++) {
			if (data_out[i] != NULL)
				free(data_out[i]);
		}
	}

	return rc;
}

static int
ut_compdev_multi_decompress_ops_in_order(void)
{
	struct dao_lc_decomp_req_params req = {0};
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	struct dao_lc_res *comp_res;
	uint32_t num_op, i, ret_multi;
	uint32_t data_len;
	int ret, rc;

	load_comp_test_config();
	num_op = comp_test_cfg.num_decompress_ops;

	uint64_t op_cookie[num_op];
	uint8_t *data_out[num_op];

	memset(data_out, 0, sizeof(data_out));
	data_len = sizeof(compressed_text);
	comp_res = calloc(num_op, sizeof(*comp_res));
	if (comp_res == NULL) {
		TEST_LC_ERR("Could not allocate memory for res");
		return TEST_FAILED;
	}

	for (i = 0; i < num_op; i++) {
		data_out[i] = malloc(sizeof(plain_text));
		if (data_out[i] == NULL) {
			rc = TEST_FAILED;
			goto cleanup;
		}
		op_cookie[i] = rte_rand();
	}

	TEST_LC_INFO("Testing decompress operations with %u requests", num_op);

	for (i = 0; i < num_op; i++) {
		fill_decompress_req_param(&req, compressed_text, data_len, data_out[i],
					  sizeof(plain_text));
		/* Enqueue deflate decompress operation */
		ret = dao_liquid_crypto_enq_decomp_op_deflate(dev_id, qp_id, &req, op_cookie[i]);
		if (ret < 0) {
			TEST_LC_ERR("Could not enqueue deflate decomp operation");
			rc = TEST_FAILED;
			goto cleanup;
		}
	}

	ret_multi = op_dequeue_multi(dev_id, qp_id, comp_res, num_op);
	if (ret_multi != num_op) {
		TEST_LC_ERR("Could not dequeue all operations");
		rc = TEST_FAILED;
		goto cleanup;
	}

	for (i = 0; i < num_op; i++) {
		TEST_ASSERT(comp_res[i].op_cookie == op_cookie[i],
			    "Invalid operation cookie for OP: %d", i);
		TEST_ASSERT(comp_res[i].compdev_res.produced == sizeof(plain_text),
			    "Decompressed output size did not match the expected size");
		ret = memcmp(data_out[i], plain_text, comp_res[i].compdev_res.produced);
		TEST_ASSERT(ret == 0,
			    "Plain text did not match with the expected for operation: %d", i);
	}
	TEST_ASSERT(num_op == ret_multi, "Expected(%d) dequeue count not matched(%d)", num_op,
		    ret_multi);
	rc = TEST_SUCCESS;

cleanup:
	/* Cleanup memory */
	for (i = 0; i < num_op; i++) {
		if (data_out[i] != NULL)
			free(data_out[i]);
	}

	free(comp_res);

	return rc;
}

static int
ut_compdev_multi_compress_decompress_ops_in_order(void)
{
	uint32_t i, num_op, data_len = sizeof(plain_text);
	uint32_t comp_data_len = sizeof(compressed_text);
	uint32_t total_ops, op_count = 0, deq_ops = 0;
	struct dao_lc_decomp_req_params dreq = {0};
	struct dao_lc_comp_req_params req = {0};
	const uint8_t *test_data = plain_text;
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	struct dao_lc_res *comp_res;
	uint16_t test_iteration = 0;
	int ret, rc = TEST_FAILED;

	load_comp_test_config();
	num_op = comp_test_cfg.num_compress_ops;

	uint8_t *data_out[num_op], *plain_data_out[num_op];

	memset(data_out, 0, sizeof(data_out));
	memset(plain_data_out, 0, sizeof(plain_data_out));
	/* Considering same number of decompress operations. */
	total_ops = num_op * 2;

	comp_res = calloc(total_ops, sizeof(*comp_res));
	if (comp_res == NULL) {
		TEST_LC_ERR("Could not allocate memory for comp_res");
		return TEST_FAILED;
	}

	uint64_t op_cookie[total_ops];

	for (i = 0; i < num_op; i++) {
		data_out[i] = malloc(sizeof(compressed_text));
		if (data_out[i] == NULL) {
			rc = TEST_FAILED;
			goto cleanup;
		}
		op_cookie[op_count] = rte_rand();
		op_count++;
		plain_data_out[i] = malloc(sizeof(plain_text));
		if (plain_data_out[i] == NULL) {
			rc = TEST_FAILED;
			goto cleanup;
		}
		op_cookie[op_count] = rte_rand();
		op_count++;
	}

	op_count = 0;

	TEST_LC_INFO("Testing compress & decompress operations with %d requests for %u iterations",
		     total_ops, comp_test_cfg.iterations);
	do {
		op_count = 0;
		for (i = 0; i < num_op; i++) {
			fill_compress_req_param(&req, test_data, data_len, data_out[i],
						sizeof(compressed_text));
			/* Enqueue deflate compress operation */
			ret = dao_liquid_crypto_enq_comp_op_deflate(dev_id, qp_id, &req,
								    op_cookie[op_count]);

			if (ret < 0) {
				TEST_LC_ERR("Could not enqueue deflate operation");
				rc = TEST_FAILED;
				goto cleanup;
			}
			op_count++;
			fill_decompress_req_param(&dreq, compressed_text, comp_data_len,
						  plain_data_out[i], sizeof(plain_text));
			ret = dao_liquid_crypto_enq_decomp_op_deflate(dev_id, qp_id, &dreq,
								      op_cookie[op_count]);
			if (ret < 0) {
				TEST_LC_ERR("Could not enqueue deflate decomp operation");
				rc = TEST_FAILED;
				goto cleanup;
			}
			op_count++;
		}

		TEST_ASSERT(op_count == total_ops,
			    "Expected(%d) compress/decompress operations are not enqueued (%d)",
			    total_ops, op_count);

		deq_ops = op_dequeue_multi(dev_id, qp_id, comp_res, op_count);
		if (deq_ops != op_count) {
			TEST_LC_ERR("Could not dequeue all operations");
			rc = TEST_FAILED;
			goto cleanup;
		}

		TEST_ASSERT(deq_ops == total_ops, "Expected(%d) dequeue count not matched(%d)",
			    total_ops, deq_ops);

		op_count = 0;
		for (i = 0; i < num_op; i++) {
			TEST_ASSERT(comp_res[op_count].op_cookie == op_cookie[op_count],
				    "Invalid operation cookie for Compress operation: %d", i);
			TEST_ASSERT(comp_res[op_count].compdev_res.produced ==
					    sizeof(compressed_text),
				    "Compressed output size did not match the expected size");
			ret = memcmp(data_out[i], compressed_text,
				     comp_res[op_count].compdev_res.produced);
			TEST_ASSERT(ret == 0, "Compressed Text did not match with the expected");
			op_count++;
			TEST_ASSERT(comp_res[op_count].op_cookie == op_cookie[op_count],
				    "Invalid operation cookie for Decomp operation: %d", i);
			TEST_ASSERT(comp_res[op_count].compdev_res.produced == sizeof(plain_text),
				    "Decompressed output size did not match the expected size");
			ret = memcmp(plain_data_out[i], plain_text,
				     comp_res[op_count].compdev_res.produced);
			TEST_ASSERT(ret == 0, "Plain text did not match with the expected");
			op_count++;
		}
		test_iteration++;
	} while (test_iteration < comp_test_cfg.iterations);
	rc = TEST_SUCCESS;

cleanup:
	/* Cleanup */
	for (i = 0; i < num_op; i++) {
		if (data_out[i] != NULL)
			free(data_out[i]);
		if (plain_data_out[i] != NULL)
			free(plain_data_out[i]);
	}
	free(comp_res);

	return rc;
}

/**
 * Unit test cases for compress device
 */
struct unit_test_suite lc_testsuite_comp = {
	.suite_name = "Liquid Crypto Compress Device Test Suite",
	.setup = compdev_testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		TEST_CASE_NAMED_ST("Compress Basic", ut_setup, ut_teardown, ut_compdev_compress_op),
		TEST_CASE_NAMED_ST("Decompress Basic", ut_setup, ut_teardown,
				   ut_compdev_decompress_op),
		TEST_CASE_NAMED_ST("Compress Repeated Text", ut_setup, ut_teardown,
				   ut_compdev_compress_repeated_text),
		TEST_CASE_NAMED_ST("Decompress Repeated Text", ut_setup, ut_teardown,
				   ut_compdev_decompress_repeated_text),
		TEST_CASE_NAMED_ST("Compress With Less Output Buffer", ut_setup, ut_teardown,
				   ut_compdev_compress_op_with_less_output_buf),
		TEST_CASE_NAMED_ST("Compress With Large Input Text", ut_setup, ut_teardown,
				   ut_compdev_compress_op_with_large_text),
		TEST_CASE_NAMED_ST("Decompress With Large Text", ut_setup, ut_teardown,
				   ut_compdev_decompress_with_large_text),
		TEST_CASE_NAMED_ST("Multiple Compress Operations (In-Order)", ut_setup, ut_teardown,
				   ut_compdev_multi_compress_ops_in_order),
		TEST_CASE_NAMED_ST("Multiple Decompress Operations (In-Order)", ut_setup,
				   ut_teardown, ut_compdev_multi_decompress_ops_in_order),
		TEST_CASE_NAMED_ST("Multiple Compress & Decompress Operations (In-Order)", ut_setup,
				   ut_teardown, ut_compdev_multi_compress_decompress_ops_in_order),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};
