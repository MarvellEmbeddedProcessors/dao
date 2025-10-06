/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __RDMA_INIT_H__
#define __RDMA_INIT_H__

#include "rdma_config.h"
#include "rdma_eth_init.h"
#include "rdma_graph.h"
#include "rdma_lcore.h"
#include "rdma_pem_init.h"

#define RDMA_MAIN_CFG_MZ_NAME "rdma_main_cfg_data"

struct rdma_main_cfg_data {
	rdma_config_param_t *cfg_prm;
	rdma_ethdev_param_t *eth_prm;
	rdma_lcore_param_t *lcore_prm;
	rdma_graph_param_t *graph_prm;
	rdma_pemdev_param_t *pem_prm;
	volatile bool force_quit;
};

int rdma_qp_status_cb(uint16_t devid, uint16_t qp_id, bool status);
void rdma_rcu_qsbr_synchronize(void);

#endif /* __RDMA_INIT_H__ */
