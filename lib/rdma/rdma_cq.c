/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rdma_cq.h"

#define RDMA_MAX_CQ 100

static uint64_t cq_addr[RDMA_MAX_CQ];

uint64_t
rdma_cq_get(uint8_t index)
{
	if (index >= RDMA_MAX_CQ)
		return 0;

	/* XXX: Increment refcnt */
	return cq_addr[index];
}

void
rdma_cq_put(void)
{
	/* XXX: Decrement the refcnt */
}

int
rdma_cq_insert(uint64_t addr, uint8_t index)
{
	if (index >= RDMA_MAX_CQ)
		return -1;

	/* TODO: Fix get cq_id from QP_ID */
	// cq_addr[index] = addr;
	cq_addr[1] = addr;

	return 0;
}

int
rdma_cq_remove(uint8_t index)
{
	if (index >= RDMA_MAX_CQ)
		return -1;

	cq_addr[index] = 0;

	return 0;
}
