/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __DAO_RDMA_MBOX_H__
#define __DAO_RDMA_MBOX_H__

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include "dao_pts_rdma_dev.h"

int dao_rdma_mbox_process(uint16_t devid, volatile struct dao_pts_rdma_mbox *mbox, uint8_t *rsp,
			  uint16_t *rsp_len);

#endif /* __DAO_RDMA_MBOX_H__ */
