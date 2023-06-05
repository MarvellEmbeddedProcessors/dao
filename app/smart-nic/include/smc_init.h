/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __SMC_INIT_H__
#define __SMC_INIT_H__

#include <dao_log.h>

#include <smc_cli_api.h>
#include <smc_config.h>
#include <smc_graph.h>

#define SMC_MAIN_CFG_MZ_NAME "smc_main_cfg_data"

#define CONF_HANDLE(conf, ret)                                                                     \
	{                                                                                          \
		struct smc_main_cfg_data *data;                                                    \
		do {                                                                               \
			data = smc_main_cfg_handle();                                              \
			if (!data)                                                                 \
				return ret;                                                        \
			conf = data->cli_cfg.conf;                                                 \
			if (!conf)                                                                 \
				return ret;                                                        \
		} while (0);                                                                       \
	}

struct smc_cli_configs {
	struct lcore_conf *lcore_conf;
	struct conn *conn;
};

struct smc_main_cfg_data {
	smc_config_param_t *cfg_prm;
	smc_graph_param_t *graph_prm;
	struct smc_cli_configs cli_cfg;
	volatile bool force_quit;
};

static inline struct smc_main_cfg_data *
smc_main_cfg_handle(void)
{
	const struct rte_memzone *mz;

	mz = rte_memzone_lookup(SMC_MAIN_CFG_MZ_NAME);
	if (!mz) {
		dao_err("Failed to lookup for main_cfg, err %d", errno);
		return NULL;
	}

	return mz->addr;
}

#endif /* __SMC_INIT_H__ */
