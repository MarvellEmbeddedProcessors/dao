/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>

#include "lcperf_options.h"
#include "lcperf_test_vectors.h"

#define AES_BLOCK_SIZE 16

struct name_id_map {
	const char *name;
	uint32_t id;
};

static void
usage(char *progname)
{
	printf("%s [EAL options] --\n"
	       " --ptest throughput / latency :"
	       " set test type\n"
	       " --total-ops N: set the number of total operations performed\n"
	       " --desc-nb N: set number of descriptors for each liquid crypto device\n"
	       " --optype passthrough / rsa / symmetric : set operation type\n"
	       " --asym-op pub-encrypt / pub-decrypt / prv-encrypt / prv-decrypt :"
	       " set asym operation type\n"
	       " --rsa-priv-keytype exp / qt : set rsa private key type\n"
	       " --rsa-keysize N : set RSA modulus length, supported length are 256, 1024, "
	       " 2048, 4096 and 8192. default is 1024\n"
	       " --burst-size N : set burst size for enqueue/dequeue operations\n"
	       " --sym-op cipher-only / auth-only : set symmetric operation type\n"
	       " --cipher-alg aes-cbc : set cipher algorithm\n"
	       " --cipher-key-sz N : set symmetric cipher key size in bytes\n"
	       " --cipher-op encrypt / decrypt : set symmetric cipher operation type\n"
	       " --auth-alg sha1 : set symmetric authentication algorithm\n"
	       " --auth-op generate : set symmetric authentication operation type\n"
	       " --buffer-size N : set buffer size for operations (1-%u bytes, AES requires"
	       " multiple of %u bytes)\n"
	       " -h: prints this help\n",
	       progname, TEST_LC_MAX_PLAINTEXT_LEN, AES_BLOCK_SIZE);
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
		{lcperf_test_type_strs[LCPERF_TEST_TYPE_LATENCY], LCPERF_TEST_TYPE_LATENCY},
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

	if ((arg[0] == '\0') || (end == NULL) || (*end != '\0'))
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
		{
			lcperf_op_type_strs[LCPERF_OP_SYM],
			LCPERF_OP_SYM,
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

static int
parse_sym_op(struct lcperf_options *opts, const char *arg)
{
	struct name_id_map sym_op_namemap[] = {
		{lcperf_crypto_sym_op_type_strs[LCPERF_CRYPTO_SYM_OP_CIPHER_ONLY],
		 LCPERF_CRYPTO_SYM_OP_CIPHER_ONLY},
		{lcperf_crypto_sym_op_type_strs[LCPERF_CRYPTO_SYM_OP_AUTH_ONLY],
		 LCPERF_CRYPTO_SYM_OP_AUTH_ONLY},
	};

	int id = get_str_key_id_mapping(sym_op_namemap, RTE_DIM(sym_op_namemap), arg);

	if (id < 0) {
		RTE_LOG(ERR, USER1, "Invalid SYM operation specified\n");
		return -1;
	}

	opts->sym_op = (enum lcperf_crypto_sym_op_type)id;

	return 0;
}

static int
parse_sym_cipher_op(struct lcperf_options *opts, const char *arg)
{
	struct name_id_map sym_cipher_op_namemap[] = {
		{lcperf_crypto_sym_cipher_op_type_strs[LCPERF_CRYPTO_SYM_CIPHER_OP_ENCRYPT],
		 LCPERF_CRYPTO_SYM_CIPHER_OP_ENCRYPT},
		{lcperf_crypto_sym_cipher_op_type_strs[LCPERF_CRYPTO_SYM_CIPHER_OP_DECRYPT],
		 LCPERF_CRYPTO_SYM_CIPHER_OP_DECRYPT},
	};

	int id = get_str_key_id_mapping(sym_cipher_op_namemap, RTE_DIM(sym_cipher_op_namemap), arg);

	if (id < 0) {
		RTE_LOG(ERR, USER1, "Invalid SYM cipher-only operation specified\n");
		return -1;
	}

	opts->cipher_op = (enum lcperf_crypto_sym_cipher_op_type)id;

	return 0;
}

static int
parse_sym_cipher_algo(struct lcperf_options *opts, const char *arg)
{
	struct name_id_map cipher_algo_namemap[] = {
		{lcperf_crypto_sym_cipher_algo_strs[DAO_LC_FC_ENC_CIPHER_AES_CBC],
		 DAO_LC_FC_ENC_CIPHER_AES_CBC},
	};

	int id = get_str_key_id_mapping(cipher_algo_namemap, RTE_DIM(cipher_algo_namemap), arg);

	if (id < 0) {
		RTE_LOG(ERR, USER1, "Invalid cipher algorithm specified\n");
		return -1;
	}

	opts->cipher_algo = (enum dao_lc_fc_enc_cipher)id;

	return 0;
}

static int
parse_sym_cipher_key_sz(struct lcperf_options *opts, const char *arg)
{
	int ret = parse_uint32_t(&opts->cipher_key_sz, arg);

	if (ret) {
		RTE_LOG(ERR, USER1, "Failed to parse cipher key size\n");
		return -1;
	}

	return 0;
}

static int
parse_sym_auth_op(struct lcperf_options *opts, const char *arg)
{
	struct name_id_map auth_op_namemap[] = {
		{lcperf_crypto_sym_auth_op_type_strs[LCPERF_CRYPTO_SYM_AUTH_OP_GENERATE],
		 LCPERF_CRYPTO_SYM_AUTH_OP_GENERATE},
		{lcperf_crypto_sym_auth_op_type_strs[LCPERF_CRYPTO_SYM_AUTH_OP_VERIFY],
		 LCPERF_CRYPTO_SYM_AUTH_OP_VERIFY},
	};

	int id = get_str_key_id_mapping(auth_op_namemap, RTE_DIM(auth_op_namemap), arg);

	if (id < 0) {
		RTE_LOG(ERR, USER1, "Invalid SYM auth operation specified\n");
		return -1;
	}

	opts->auth_op = (enum lcperf_crypto_sym_auth_op_type)id;

	return 0;
}

static int
parse_sym_auth_algo(struct lcperf_options *opts, const char *arg)
{
	struct name_id_map auth_algo_namemap[] = {
		{lcperf_crypto_sym_auth_algo_strs[DAO_LC_FC_HASH_TYPE_SHA1],
		 DAO_LC_FC_HASH_TYPE_SHA1},
	};

	int id = get_str_key_id_mapping(auth_algo_namemap, RTE_DIM(auth_algo_namemap), arg);

	if (id < 0) {
		RTE_LOG(ERR, USER1, "Invalid SYM auth algorithm specified\n");
		return -1;
	}

	opts->auth_algo = (enum dao_lc_fc_hash_type)id;

	return 0;
}

static int
parse_burst_size(struct lcperf_options *opts, const char *arg)
{
	int ret = parse_uint32_t(&opts->burst_size, arg);

	if (ret) {
		RTE_LOG(ERR, USER1, "Failed to parse burst size\n");
		return -1;
	}

	if (opts->burst_size == 0) {
		RTE_LOG(ERR, USER1, "Invalid burst size specified\n");
		return -1;
	}

	if (opts->burst_size > TEST_LC_MAX_BURST_SIZE) {
		RTE_LOG(ERR, USER1, "Burst size %u exceeds maximum limit of %u\n", opts->burst_size,
			TEST_LC_MAX_BURST_SIZE);
		return -1;
	}

	return 0;
}

static int
parse_buffer_size(struct lcperf_options *opts, const char *arg)
{
	int ret = parse_uint32_t(&opts->test_buffer_size, arg);

	if (ret) {
		RTE_LOG(ERR, USER1, "Failed to parse buffer size\n");
		return -1;
	}

	if (opts->test_buffer_size == 0) {
		RTE_LOG(ERR, USER1, "Invalid buffer size specified\n");
		return -1;
	}

	if (opts->test_buffer_size > TEST_LC_MAX_PLAINTEXT_LEN) {
		RTE_LOG(ERR, USER1, "Buffer size %u exceeds maximum limit of %u\n",
			opts->test_buffer_size, TEST_LC_MAX_PLAINTEXT_LEN);
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

	opts->test_buffer_size = 64;
	opts->burst_size = 128;

	opts->op_type = LCPERF_OP_PASSTHROUGH;

	opts->asym_op_type = LCPERF_CRYPTO_ASYM_OP_PUB_ENCRYPT;
	opts->rsa_priv_keytype = LCPERF_RSA_KEY_TYPE_MAX;
	opts->rsa_modlen = 1024;

	opts->sym_op = LCPERF_CRYPTO_SYM_OP_CIPHER_ONLY;
	opts->cipher_op = LCPERF_CRYPTO_SYM_CIPHER_OP_ENCRYPT;
	opts->cipher_algo = DAO_LC_FC_ENC_CIPHER_AES_CBC;
	opts->cipher_key_sz = 16;

	opts->auth_op = LCPERF_CRYPTO_SYM_AUTH_OP_GENERATE;
	opts->auth_algo = DAO_LC_FC_HASH_TYPE_SHA1;
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
				 {LCPERF_BURST_SIZE, required_argument, 0, 0},
				 {LCPERF_SYM_OP, required_argument, 0, 0},
				 {LCPERF_SYM_CIPHER_OP, required_argument, 0, 0},
				 {LCPERF_SYM_CIPHER_ALG, required_argument, 0, 0},
				 {LCPERF_SYM_CIPHER_KEY_SZ, required_argument, 0, 0},
				 {LCPERF_SYM_AUTH_ALGO, required_argument, 0, 0},
				 {LCPERF_SYM_AUTH_OP, required_argument, 0, 0},
				 {LCPERF_BUFFER_SIZE, required_argument, 0, 0},
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
		{LCPERF_BURST_SIZE, parse_burst_size},
		{LCPERF_SYM_OP, parse_sym_op},
		{LCPERF_SYM_CIPHER_OP, parse_sym_cipher_op},
		{LCPERF_SYM_CIPHER_ALG, parse_sym_cipher_algo},
		{LCPERF_SYM_CIPHER_KEY_SZ, parse_sym_cipher_key_sz},
		{LCPERF_SYM_AUTH_ALGO, parse_sym_auth_algo},
		{LCPERF_SYM_AUTH_OP, parse_sym_auth_op},
		{LCPERF_BUFFER_SIZE, parse_buffer_size},
	};
	unsigned int i;

	for (i = 0; i < RTE_DIM(parsermap); i++) {
		if (strncmp(lgopts[opt_idx].name, parsermap[i].lgopt_name,
			    strlen(parsermap[i].lgopt_name) + 1) == 0)
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
	printf("# Liquid Crypto Performance Application Options:\n");
	printf("#\n");
	printf("# lcperf test: %s\n", lcperf_test_type_strs[opts->test]);
	printf("#\n");
	printf("# total number of ops: %u\n", opts->total_ops);
	printf("#\n");

	printf("# buffer size: %u bytes\n", opts->test_buffer_size);
	printf("\n");
	printf("# burst size: %u\n", opts->burst_size);
	printf("\n");

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

	if (opts->op_type == LCPERF_OP_SYM) {
		printf("# Symmetric operation type: %s\n",
		       lcperf_crypto_sym_op_type_strs[opts->sym_op]);

		if (opts->sym_op == LCPERF_CRYPTO_SYM_OP_CIPHER_ONLY) {
			printf("# Symmetric cipher operation type: %s\n",
			       lcperf_crypto_sym_cipher_op_type_strs[opts->cipher_op]);
			printf("# Symmetric cipher algorithm: %s\n",
			       lcperf_crypto_sym_cipher_algo_strs[opts->cipher_algo]);
			printf("# Symmetric cipher key size: %u bytes\n", opts->cipher_key_sz);
		} else if (opts->sym_op == LCPERF_CRYPTO_SYM_OP_AUTH_ONLY) {
			printf("# Symmetric auth algorithm: %s\n",
			       lcperf_crypto_sym_auth_algo_strs[opts->auth_algo]);
			printf("# Symmetric auth operation type: %s\n",
			       lcperf_crypto_sym_auth_op_type_strs[opts->auth_op]);
		}
	}

	printf("#\n");
}

static int
check_cipher_buffer_length(struct lcperf_options *options)
{
	if (options->cipher_algo == DAO_LC_FC_ENC_CIPHER_AES_CBC) {
		if (options->test_buffer_size % AES_BLOCK_SIZE != 0) {
			RTE_LOG(ERR, USER1,
				"Test buffer size must be a multiple of %d for AES CBC cipher\n",
				AES_BLOCK_SIZE);
			return -EINVAL;
		}
	}

	return 0;
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

	if (options->op_type == LCPERF_OP_SYM) {
		if (options->sym_op == LCPERF_CRYPTO_SYM_OP_CIPHER_ONLY) {
			switch (options->cipher_algo) {
			case DAO_LC_FC_ENC_CIPHER_AES_CBC:
				if (options->cipher_key_sz != 16 && options->cipher_key_sz != 24 &&
				    options->cipher_key_sz != 32) {
					RTE_LOG(ERR, USER1,
						"Invalid AES CBC cipher key size specified\n");
					return -EINVAL;
				}
				break;
			default:
				RTE_LOG(ERR, USER1,
					"Invalid symmetric cipher algorithm specified\n");
				return -EINVAL;
			}

			if (check_cipher_buffer_length(options) < 0)
				return -EINVAL;
		} else if (options->sym_op == LCPERF_CRYPTO_SYM_OP_AUTH_ONLY) {
			switch (options->auth_algo) {
			case DAO_LC_FC_HASH_TYPE_SHA1:
				/* SHA1 is supported */
				break;
			default:
				RTE_LOG(ERR, USER1,
					"Invalid symmetric authentication algorithm specified\n");
				return -EINVAL;
			}
		} else {
			RTE_LOG(ERR, USER1, "Invalid symmetric operation type specified\n");
			return -EINVAL;
		}
	}

	if (options->burst_size > options->nb_descriptors) {
		RTE_LOG(ERR, USER1, "Burst size cannot be greater than number of descriptors\n");
		return -EINVAL;
	}

	return 0;
}
