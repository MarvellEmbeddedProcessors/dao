/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>

#include "lcperf_options.h"
#include "lcperf_test_vectors.h"

struct name_id_map {
	const char *name;
	uint32_t id;
};

static void
usage(char *progname)
{
	printf("%s [EAL options] --\n"
	       " --ptest throughput :"
	       " set test type\n"
	       " --total-ops N: set the number of total operations performed\n"
	       " --desc-nb N: set number of descriptors for each liquid crypto device\n"
	       " --optype passthrough / rsa : set operation type\n"
	       " --asym-op pub-encrypt / pub-decrypt / prv-encrypt / prv-decrypt :"
	       " set asym operation type\n"
	       " --rsa-priv-keytype exp / qt : set rsa private key type\n"
	       " --rsa-keysize N : set RSA modulus length, supported length are 256, 1024, "
	       " 2048, 4096 and 8192. default is 1024\n"
	       " -h: prints this help\n",
	       progname);
}

static int
get_str_key_id_mapping(struct name_id_map *map, unsigned int map_len, const char *str_key)
{
	unsigned int i;

	for (i = 0; i < map_len; i++) {
		if (strcmp(str_key, map[i].name) == 0)
			return map[i].id;
	}

	return -1;
}

static int
parse_lcperf_test_type(struct lcperf_options *opts, const char *arg)
{
	struct name_id_map lcperftest_namemap[] = {
		{lcperf_test_type_strs[LCPERF_TEST_TYPE_THROUGHPUT], LCPERF_TEST_TYPE_THROUGHPUT},
	};

	int id = get_str_key_id_mapping((struct name_id_map *)lcperftest_namemap,
					RTE_DIM(lcperftest_namemap), arg);
	if (id < 0) {
		RTE_LOG(ERR, USER1, "Failed to parse test type");
		return -1;
	}

	opts->test = (enum lcperf_perf_test_type)id;

	return 0;
}

static int
parse_uint32_t(uint32_t *value, const char *arg)
{
	char *end = NULL;
	unsigned long n = strtoul(arg, &end, 10);

	if ((optarg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (n > UINT32_MAX)
		return -ERANGE;

	*value = (uint32_t)n;

	return 0;
}

static int
parse_total_ops(struct lcperf_options *opts, const char *arg)
{
	int ret = parse_uint32_t(&opts->total_ops, arg);

	if (ret)
		RTE_LOG(ERR, USER1, "Failed to parse total operations count\n");

	if (opts->total_ops == 0) {
		RTE_LOG(ERR, USER1, "Invalid total operations count number specified\n");
		return -1;
	}

	return ret;
}

static int
parse_desc_nb(struct lcperf_options *opts, const char *arg)
{
	int ret = parse_uint32_t(&opts->nb_descriptors, arg);

	if (ret) {
		RTE_LOG(ERR, USER1, "Failed to parse descriptors number\n");
		return -1;
	}

	if (opts->nb_descriptors == 0) {
		RTE_LOG(ERR, USER1, "Invalid descriptors number specified\n");
		return -1;
	}

	return 0;
}

static int
parse_op_type(struct lcperf_options *opts, const char *arg)
{
	struct name_id_map optype_namemap[] = {
		{
			lcperf_op_type_strs[LCPERF_OP_PASSTHROUGH],
			LCPERF_OP_PASSTHROUGH,
		},
		{
			lcperf_op_type_strs[LCPERF_OP_ASYM_RSA],
			LCPERF_OP_ASYM_RSA,
		},

	};

	int id = get_str_key_id_mapping(optype_namemap, RTE_DIM(optype_namemap), arg);

	if (id < 0) {
		RTE_LOG(ERR, USER1, "Invalid opt type specified\n");
		return -1;
	}

	opts->op_type = (enum lcperf_op_type)id;

	return 0;
}

static int
parse_asym_op(struct lcperf_options *opts, const char *arg)
{
	struct name_id_map asym_op_namemap[] = {
		{lcperf_crypto_asym_op_type_strs[LCPERF_CRYPTO_ASYM_OP_PUB_ENCRYPT],
		 LCPERF_CRYPTO_ASYM_OP_PUB_ENCRYPT},
		{lcperf_crypto_asym_op_type_strs[LCPERF_CRYPTO_ASYM_OP_PRV_DECRYPT],
		 LCPERF_CRYPTO_ASYM_OP_PRV_DECRYPT},
		{lcperf_crypto_asym_op_type_strs[LCPERF_CRYPTO_ASYM_OP_PRV_ENCRYPT],
		 LCPERF_CRYPTO_ASYM_OP_PRV_ENCRYPT},
		{lcperf_crypto_asym_op_type_strs[LCPERF_CRYPTO_ASYM_OP_PUB_DECRYPT],
		 LCPERF_CRYPTO_ASYM_OP_PUB_DECRYPT},
	};

	int id = get_str_key_id_mapping(asym_op_namemap, RTE_DIM(asym_op_namemap), arg);

	if (id < 0) {
		RTE_LOG(ERR, USER1, "Invalid ASYM operation specified\n");
		return -1;
	}

	opts->asym_op_type = (enum lcperf_crypto_asym_op_type)id;

	return 0;
}

static int
parse_rsa_priv_keytype(struct lcperf_options *opts, const char *arg)
{
	struct name_id_map rsa_keytype_namemap[] = {
		{lcperf_rsa_priv_keytype_strs[LCPERF_RSA_KEY_TYPE_EXP], LCPERF_RSA_KEY_TYPE_EXP},
		{lcperf_rsa_priv_keytype_strs[LCPERF_RSA_KEY_TYPE_QT], LCPERF_RSA_KEY_TYPE_QT},
	};

	int id = get_str_key_id_mapping(rsa_keytype_namemap, RTE_DIM(rsa_keytype_namemap), arg);

	if (id < 0) {
		RTE_LOG(ERR, USER1, "Invalid RSA private key type\n");
		return -1;
	}

	opts->rsa_priv_keytype = (enum lcperf_rsa_priv_keytype)id;
	return 0;
}

static int
parse_rsa_modlen(struct lcperf_options *opts, const char *arg)
{
	int ret = parse_uint32_t(&opts->rsa_modlen, arg);

	if (ret) {
		RTE_LOG(ERR, USER1, "Failed to parse keysize\n");
		return -1;
	}

	return 0;
}

void
lcperf_options_default(struct lcperf_options *opts)
{
	opts->test = LCPERF_TEST_TYPE_THROUGHPUT;

	opts->total_ops = 10000000;
	opts->nb_descriptors = 2048;

	opts->buffer_size_list[0] = 64;
	opts->buffer_size_count = 1;
	opts->burst_size_list[0] = 32;
	opts->burst_size_count = 1;

	opts->nb_qps = 1;

	opts->op_type = LCPERF_OP_PASSTHROUGH;

	opts->asym_op_type = LCPERF_CRYPTO_ASYM_OP_PUB_ENCRYPT;
	opts->rsa_priv_keytype = LCPERF_RSA_KEY_TYPE_MAX;
	opts->rsa_modlen = 1024;
}

typedef int (*option_parser_t)(struct lcperf_options *opts, const char *arg);

struct long_opt_parser {
	const char *lgopt_name;
	option_parser_t parser_fn;
};

static struct option lgopts[] = {{LCPERF_PTEST_TYPE, required_argument, 0, 0},
				 {LCPERF_TOTAL_OPS, required_argument, 0, 0},
				 {LCPERF_DESC_NB, required_argument, 0, 0},
				 {LCPERF_OPTYPE, required_argument, 0, 0},
				 {LCPERF_ASYM_OP, required_argument, 0, 0},
				 {LCPERF_RSA_PRIV_KEYTYPE, required_argument, 0, 0},
				 {LCPERF_RSA_MODLEN, required_argument, 0, 0},
				 {NULL, 0, 0, 0}};

static int
lcperf_opts_parse_long(int opt_idx, struct lcperf_options *opts)
{
	struct long_opt_parser parsermap[] = {
		{LCPERF_PTEST_TYPE, parse_lcperf_test_type},
		{LCPERF_TOTAL_OPS, parse_total_ops},
		{LCPERF_DESC_NB, parse_desc_nb},
		{LCPERF_OPTYPE, parse_op_type},
		{LCPERF_ASYM_OP, parse_asym_op},
		{LCPERF_RSA_PRIV_KEYTYPE, parse_rsa_priv_keytype},
		{LCPERF_RSA_MODLEN, parse_rsa_modlen},
	};
	unsigned int i;

	for (i = 0; i < RTE_DIM(parsermap); i++) {
		if (strncmp(lgopts[opt_idx].name, parsermap[i].lgopt_name,
			    strlen(lgopts[opt_idx].name)) == 0)
			return parsermap[i].parser_fn(opts, optarg);
	}

	return -EINVAL;
}

int
lcperf_options_parse(struct lcperf_options *options, int argc, char **argv)
{
	int opt, retval, opt_idx;

	while ((opt = getopt_long(argc, argv, "h", lgopts, &opt_idx)) != EOF) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		/* long options */
		case 0:
			retval = lcperf_opts_parse_long(opt_idx, options);
			if (retval != 0)
				return retval;

			break;

		default:
			usage(argv[0]);
			return -EINVAL;
		}
	}

	return 0;
}

void
lcperf_options_dump(struct lcperf_options *opts)
{
	uint8_t size_idx;

	printf("# Liquid Crypto Performance Application Options:\n");
	printf("#\n");
	printf("# lcperf test: %s\n", lcperf_test_type_strs[opts->test]);
	printf("#\n");
	printf("# total number of ops: %u\n", opts->total_ops);
	printf("#\n");

	printf("# buffer sizes: ");
	for (size_idx = 0; size_idx < opts->buffer_size_count; size_idx++)
		printf("%u ", opts->buffer_size_list[size_idx]);
	printf("\n");
	printf("# burst sizes: ");
	for (size_idx = 0; size_idx < opts->burst_size_count; size_idx++)
		printf("%u ", opts->burst_size_list[size_idx]);
	printf("\n");
	printf("# number of queue pairs per device: %u\n", opts->nb_qps);
	printf("#\n");

	printf("# lcperf operation type: %s\n", lcperf_op_type_strs[opts->op_type]);
	printf("#\n");
	if (opts->op_type == LCPERF_OP_ASYM_RSA) {
		printf("# RSA operation type: %s\n",
		       lcperf_crypto_asym_op_type_strs[opts->asym_op_type]);
		if ((opts->asym_op_type == LCPERF_CRYPTO_ASYM_OP_PRV_ENCRYPT) ||
		    opts->asym_op_type == LCPERF_CRYPTO_ASYM_OP_PRV_DECRYPT)
			printf("# RSA private key type: %s\n",
			       lcperf_rsa_priv_keytype_strs[opts->rsa_priv_keytype]);
		printf("# RSA modulus length: %u\n", opts->rsa_modlen);
	}
	printf("#\n");
}

int
lcperf_options_check(struct lcperf_options *options)
{
	if ((options->asym_op_type == LCPERF_CRYPTO_ASYM_OP_PRV_ENCRYPT) ||
	    (options->asym_op_type == LCPERF_CRYPTO_ASYM_OP_PRV_DECRYPT)) {
		if ((options->rsa_priv_keytype != LCPERF_RSA_KEY_TYPE_EXP) &&
		    (options->rsa_priv_keytype != LCPERF_RSA_KEY_TYPE_QT)) {
			RTE_LOG(ERR, USER1, "Invalid RSA private key type specified\n");
			return -EINVAL;
		}
	}

	if ((options->asym_op_type == LCPERF_CRYPTO_ASYM_OP_PUB_ENCRYPT ||
	     options->asym_op_type == LCPERF_CRYPTO_ASYM_OP_PUB_DECRYPT) &&
	    (options->rsa_priv_keytype == LCPERF_RSA_KEY_TYPE_EXP ||
	     options->rsa_priv_keytype == LCPERF_RSA_KEY_TYPE_QT)) {
		RTE_LOG(ERR, USER1,
			"Private key type cannot be configured for public encrypt or decrypt operations\n");
		return -EINVAL;
	}

	switch (options->rsa_modlen) {
	case 1024:
		options->rsa_data = &rsa_1024_params;
		break;
	case 2048:
		options->rsa_data = &rsa_2048_params;
		break;
	case 4096:
		options->rsa_data = &rsa_4096_params;
		break;
	case 8192:
		options->rsa_data = &rsa_8192_params;
		break;
	case 256:
		options->rsa_data = &rsa_256_params;
		break;
	default:
		RTE_LOG(ERR, USER1, "Invalid RSA modulus length specified\n");
		return -EINVAL;
	}

	return 0;
}
