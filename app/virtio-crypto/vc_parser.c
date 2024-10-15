/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>
#include <getopt.h>

#include <rte_string_fns.h>

#include <dao_virtio.h>

#include "vc_offload.h"
#include "vc_parser.h"

static const char short_options[] = "V:" /* virtio-config */
				    "C:" /* crypto-config */
				    "v:" /* virtio dev mask */
				    "c:" /* crypto dev mask */
				    "m:" /* offload map */
	;

#define CMD_LINE_OPT_VIRTIO_CONFIG "virtio-config"
#define CMD_LINE_OPT_CRYPTO_CONFIG "crypto-config"
#define CMD_LINE_OPT_VIRTIO_MASK   "virtio-mask"
#define CMD_LINE_OPT_CRYPTO_MASK   "crypto-mask"
#define CMD_LINE_OPT_OFFLOAD_MAP   "offload-map"

enum {
	/* Long options mapped to a short option */

	/* First long only option value must be >= 256, so that we won't
	 * conflict with short options
	 */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_VIRTIO_CONFIG_NUM,
	CMD_LINE_OPT_CRYPTO_CONFIG_NUM,
	CMD_LINE_OPT_VIRTIO_MASK_NUM,
	CMD_LINE_OPT_CRYPTO_MASK_NUM,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_VIRTIO_CONFIG, required_argument, 0, CMD_LINE_OPT_VIRTIO_CONFIG_NUM},
	{CMD_LINE_OPT_CRYPTO_CONFIG, required_argument, 0, CMD_LINE_OPT_CRYPTO_CONFIG_NUM},
	{CMD_LINE_OPT_VIRTIO_MASK, required_argument, 0, CMD_LINE_OPT_VIRTIO_MASK_NUM},
	{CMD_LINE_OPT_CRYPTO_MASK, required_argument, 0, CMD_LINE_OPT_CRYPTO_MASK_NUM},
	{NULL, 0, 0, 0}};

static void
print_usage(const char *prgname)
{
	fprintf(stderr,
		"%s [EAL options] -- [VC offload options]\n"
		"VC offload options:\n"
		"  -h, --help\n"
		"  -v, --virtio-mask=<VIRTO_MASK_L[,VIRTIO_MARK_H]> Hexadecimal bitmask of virtio devices\n"
		"  -c, --crypto-mask=<CRYPTO_MASK_L[,CRYPTO_MARK_H]> Hexadecimal bitmask of crypto devices\n"
		"  -V, --virtio-config=(dev,lcore_mask)[,(dev,lcore_mask)] : Virtio rx lcore mapping\n"
		"  -C, --crypto-config=(dev,lcore_mask)[,(dev,lcore_mask)] : Crypto enq lcore mapping\n",
		prgname);
}

static int
parse_virtio_config(const char *q_arg)
{
	enum fieldnames { FLD_DEV = 0, FLD_LCORE_MASK, _NUM_FLD };
	unsigned long int_fld[_NUM_FLD];
	const char *p, *p0 = q_arg;
	char *str_fld[_NUM_FLD];
	uint32_t size;
	char s[256];
	char *end;
	int i;

	while ((p = strchr(p0, '(')) != NULL) {
		++p;
		p0 = strchr(p, ')');
		if (p0 == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		memcpy(s, p, size);
		s[size] = '\0';
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i])
				return -1;
		}

		if (int_fld[FLD_DEV] >= DAO_VIRTIO_DEV_MAX ||
		    int_fld[FLD_LCORE_MASK] >= RTE_BIT64(RTE_MAX_LCORE)) {
			APP_ERR("Invalid virtiodev/lcore mask\n");
			return -1;
		}

		lcore_virtio_mask[int_fld[FLD_DEV]] = int_fld[FLD_LCORE_MASK];
	}

	return 0;
}

static int
parse_crypto_config(const char *q_arg)
{
	enum fieldnames { FLD_DEV = 0, FLD_LCORE_MASK, _NUM_FLD };
	unsigned long int_fld[_NUM_FLD];
	const char *p, *p0 = q_arg;
	char *str_fld[_NUM_FLD];
	uint32_t size;
	char s[256];
	char *end;
	int i;

	while ((p = strchr(p0, '(')) != NULL) {
		++p;
		p0 = strchr(p, ')');
		if (p0 == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		memcpy(s, p, size);
		s[size] = '\0';
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i])
				return -1;
		}

		if (int_fld[FLD_DEV] >= RTE_CRYPTO_MAX_DEVS ||
		    int_fld[FLD_LCORE_MASK] >= RTE_BIT64(RTE_MAX_LCORE)) {
			APP_ERR("Invalid cryptodev/lcore mask\n");
			return -1;
		}

		lcore_crypto_mask[int_fld[FLD_DEV]] = int_fld[FLD_LCORE_MASK];
	}

	return 0;
}

int
parse_args(int argc, char **argv)
{
	uint64_t virtio_mask_dflt = 0;
	uint16_t service_lcore = 0;
	char *prgname = argv[0];
	uint16_t devid, j = 0;
	char *str, *save_ptr;
	int option_index;
	char **argvopt;
	uint8_t lcore;
	int opt;

	for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		if (!rte_lcore_is_enabled(lcore) || (lcore == rte_get_main_lcore()))
			continue;

		service_lcore = lcore;
		break;
	}

	lcore = 0;
	for (; lcore < RTE_MAX_LCORE; lcore++) {
		if (j == (rte_lcore_count() - 2) / 2)
			break;

		if (!rte_lcore_is_enabled(lcore) || (lcore == rte_get_main_lcore()) ||
		    lcore == service_lcore)
			continue;

		virtio_mask_dflt |= RTE_BIT64(lcore);
		j++;
	}

	for (devid = 0; devid < DAO_VIRTIO_DEV_MAX; devid++)
		lcore_virtio_mask[devid] = virtio_mask_dflt;

	argvopt = argv;
	while ((opt = getopt_long(argc, argvopt, short_options, lgopts, &option_index)) != EOF) {
		switch (opt) {
		case 'V':
		case CMD_LINE_OPT_VIRTIO_CONFIG_NUM:
			if (parse_virtio_config(optarg) < 0) {
				APP_ERR("Invalid virtio config\n");
				return -1;
			}
			break;
		case 'C':
		case CMD_LINE_OPT_CRYPTO_CONFIG_NUM:
			if (parse_crypto_config(optarg) < 0) {
				APP_ERR("Invalid crypto config\n");
				return -1;
			}
			break;
		case 'v':
		case CMD_LINE_OPT_VIRTIO_MASK_NUM:
			str = strtok_r(optarg, ",", &save_ptr);
			if (str)
				virtio_mask_ena[0] = strtoull(str, NULL, 16);

			str = strtok_r(NULL, ",", &save_ptr);
			if (str)
				virtio_mask_ena[1] = strtoull(str, NULL, 16);

			if (virtio_mask_ena[0] == 0 && virtio_mask_ena[1] == 0) {
				APP_ERR("Invalid virtio dev mask\n");
				print_usage(prgname);
				return -1;
			}

			nb_virtiodevs = __builtin_popcountll(virtio_mask_ena[0]);
			nb_virtiodevs += __builtin_popcountll(virtio_mask_ena[1]);
			break;
		case 'c':
		case CMD_LINE_OPT_CRYPTO_MASK_NUM:
			str = strtok_r(optarg, ",", &save_ptr);
			if (str)
				crypto_mask_ena = strtoull(str, NULL, 16);

			if (crypto_mask_ena == 0) {
				APP_ERR("Invalid crypto dev mask\n");
				print_usage(prgname);
				return -1;
			}
			nb_cryptodevs = __builtin_popcountll(crypto_mask_ena);
			break;
		default:
			print_usage(argv[0]);
			return -1;
		}
	}
	while ((opt = getopt_long(argc, argvopt, "", lgopts, &option_index)) != EOF) {
		switch (opt) {
		default:
			break;
		}
	}

	return 0;
}
