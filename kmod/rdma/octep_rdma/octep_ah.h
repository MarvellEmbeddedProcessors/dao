/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Marvell.
 */

#ifndef __OCTEP_AH_H__
#define __OCTEP_AH_H__

#include "octep_rdma.h"
#include <rdma/octep_rdma-abi.h>

enum ah_cmd {
	AH_CREATE = 0,
	AH_MODIFY,
};

struct octep_rdma_ah {
	struct ib_ah ibah;
	struct octep_rdma_av av;
	bool is_user;
	u32 ah_num;
};

void octep_rdma_init_av(struct rdma_ah_attr *attr, struct octep_rdma_av *av);
void octep_rdma_av_to_attr(struct octep_rdma_av *av, struct rdma_ah_attr *attr);
int octep_rdma_ah_chk_attr(struct octep_rdma_ah *ah, struct rdma_ah_attr *attr);
int octep_rdma_prepare_ah_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_ah *ah,
			      struct octep_rdma_av *av, enum ah_cmd cmd);
int octep_rdma_prepare_ah_destroy_cmd(struct octep_rdma_dev *rdma_dev, struct octep_rdma_ah *ah);
#endif /* __OCTEP_AH_H__ */
