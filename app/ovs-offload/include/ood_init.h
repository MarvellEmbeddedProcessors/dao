/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __OOD_INIT_H__
#define __OOD_INIT_H__

#include <ood_config.h>
#include <ood_ctrl_chan.h>
#include <ood_eth_init.h>
#include <ood_graph.h>
#include <ood_lcore.h>
#include <ood_repr.h>

#define OOD_MAIN_CFG_MZ_NAME "ood_main_cfg_data"

struct ood_main_cfg_data {
	ood_config_param_t *cfg_prm;
	ood_ethdev_param_t *eth_prm;
	ood_lcore_param_t *lcore_prm;
	ood_graph_param_t *graph_prm;
	ood_repr_param_t *repr_prm;
	ood_ctrl_chan_param_t *ctrl_chan_prm;
	volatile bool force_quit;
};

#endif /* __OOD_INIT_H__ */
