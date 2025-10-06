/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __RDMA_PEM_H__
#define __RDMA_PEM_H__

#include "rdma_config.h"

#include <dao_pts_rdma_dev.h>

typedef struct rdma_pem {
	uint8_t pem_id;
} rdma_pemdev_param_t;

int rdma_pem_init(struct rdma_main_cfg_data *rdma_main_cfg);

#endif /* __RDMA_PEM_H__ */
