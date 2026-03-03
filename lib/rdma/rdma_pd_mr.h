/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef RDMA_PD_MR_H
#define RDMA_PD_MR_H

#include <stdint.h>

#include <rte_malloc.h>

#include "rdma_dev_cap_priv.h"
#include "rdma_kernel_abi.h"

#define RDMA_MR_KEY_SHIFT 20

struct pd_entry {
	uint32_t pd_id;
	struct octep_rdma_mr_data *mr_pool[RDMA_MAX_PD];
};

int pd_init(uint32_t max_num_pd);
int pd_add(void *add);
int pd_delete(void *del);
int mr_reg(void *reg);
int mr_dereg(void *dereg);
struct pd_entry *pd_find_by_id(uint32_t pd_id, uint32_t port_num);
struct pd_entry **rdma_port_get_pd_array(uint8_t port_num);
void rdma_pd_free(struct pd_entry **pd_array);

#endif // RDMA_PD_MR_H
