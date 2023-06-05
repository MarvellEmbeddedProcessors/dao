/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dao_log.h>

#include <smc_config.h>

static const char usage[] = "%s EAL_ARGS -- -s SCRIPT [-h HOST] [-p PORT] [--enable-graph-stats] "
			    "[--enable-debug] [--help]\n";

int
smc_parse_args(int argc, char **argv, struct smc_config_param *cfg_prm)
{
	struct option lgopts[] = {
		{"help", 0, 0, 'H'},
		{"enable-debug", 0, 0, 'd'},
		{"enable-graph-stats", 0, 0, 'g'},
	};
	int h_present, p_present, s_present;
	char *app_name = argv[0];
	int opt, option_index;

	/* Parse args */
	h_present = 0;
	p_present = 0;
	s_present = 0;

	while ((opt = getopt_long(argc, argv, "h:p:s:", lgopts, &option_index)) != EOF) {
		switch (opt) {
		case 'h':
			if (h_present) {
				dao_err("Error: Multiple -h arguments");
				return -1;
			}
			h_present = 1;

			if (!strlen(optarg)) {
				dao_err("Error: Argument for -h not provided");
				return -1;
			}

			cfg_prm->conn.addr = strdup(optarg);
			if (cfg_prm->conn.addr == NULL) {
				dao_err("Error: Not enough memory");
				return -1;
			}
			break;

		case 'p':
			if (p_present) {
				dao_err("Error: Multiple -p arguments");
				return -1;
			}
			p_present = 1;

			if (!strlen(optarg)) {
				dao_err("Error: Argument for -p not provided");
				return -1;
			}

			cfg_prm->conn.port = (uint16_t)strtoul(optarg, NULL, 10);
			break;

		case 's':
			if (s_present) {
				dao_err("Error: Multiple -s arguments");
				return -1;
			}
			s_present = 1;

			if (!strlen(optarg)) {
				dao_err("Error: Argument for -s not provided");
				return -1;
			}

			cfg_prm->script_name = strdup(optarg);
			if (cfg_prm->script_name == NULL) {
				dao_err("Error: Not enough memory");
				return -1;
			}
			break;

		case 'g':
			cfg_prm->enable_graph_stats = true;
			dao_warn("WARNING! Telnet session can not be accessed with"
				 "--enable-graph-stats");
			break;

		case 'd':
			cfg_prm->enable_debug = true;
			break;

		case 'H':
		default:
			printf(usage, app_name);
			return -1;
		}
	}
	optind = 1; /* reset getopt lib */

	return 0;
}

int
smc_default_config(struct smc_config_param *cfg_prm)
{
	static struct smc_config_param default_cfg_prm = {
		.conn = {
			.welcome = "\nWelcome!\n\n",
			.prompt = "smart-nic> ",
			.addr = "0.0.0.0",
			.port = 8086,
			.buf_size = 1024 * 1024,
			.msg_in_len_max = 1024,
			.msg_out_len_max = 1024 * 1024,
			.msg_handle = cli_process,
			.msg_handle_arg = NULL, /* set later. */
		},
		.script_name = NULL,
		.enable_graph_stats = false,
	};

	rte_memcpy(cfg_prm, &default_cfg_prm, sizeof(struct smc_config_param));

	return 0;
}
