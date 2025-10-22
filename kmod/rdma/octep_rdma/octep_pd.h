/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Marvell.
 */

#ifndef __OCTEP_PD_H__
#define __OCTEP_PD_H__

#include "octep_rdma.h"

int octep_rdma_prepare_pd_add_cmd(struct octep_rdma_dev *rdma_dev, u32 pdn);
int octep_rdma_prepare_pd_del_cmd(struct octep_rdma_dev *rdma_dev, u32 pdn);

#endif /* __OCTEP_PD_H__ */
