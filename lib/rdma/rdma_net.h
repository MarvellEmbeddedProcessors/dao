/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __RDMA_NET_H__
#define __RDMA_NET_H__
#include "rdma_av.h"
#include "rdma_hdr.h"
#include <rte_mbuf.h>

void rdma_mbuf_init(struct rte_mbuf *mbuf);

int rdma_net_hdr_insert(struct rte_mbuf *mbuf, struct rdma_av *av, uint16_t sport);

#endif /* __RDMA_NET_H__ */
