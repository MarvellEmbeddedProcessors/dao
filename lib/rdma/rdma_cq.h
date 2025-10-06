/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __RDMA_CQ_H__
#define __RDMA_CQ_H__

uint64_t rdma_cq_get(uint8_t index);
void rdma_cq_put(void);
int rdma_cq_insert(uint64_t addr, uint8_t index);
int rdma_cq_remove(uint8_t index);

#endif /* __RDMA_CQ_H__ */
