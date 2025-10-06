/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __RDMA_DMA_INIT_H__
#define __RDMA_DMA_INIT_H__

#include "rdma_config.h"

int rdma_dma_init(struct rdma_main_cfg_data *rdma_main_cfg);

int rdma_dma_dev_assign(struct rdma_main_cfg_data *rdma_main_cfg, uint16_t lcore_id);

#endif /* __RDMA_ETH_INIT_H__ */
