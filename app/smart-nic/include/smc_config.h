/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __SMC_CONFIG_H__
#define __SMC_CONFIG_H__

#include <smc_cli_api.h>

typedef struct smc_config_param {
	struct conn_params conn;
	char *script_name;
	bool enable_debug;
	bool enable_graph_stats;
} smc_config_param_t;

/* Display usage */
void ood_print_usage(const char *prgname);

/* Populate default config */
int smc_default_config(struct smc_config_param *cfg_prm);

/* Parse command line arguments */
int smc_parse_args(int argc, char **argv, struct smc_config_param *cfg_prm);

#endif /* __SMC_CONFIG_H__ */
