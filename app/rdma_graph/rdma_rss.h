/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef RDMA_RSS_H
#define RDMA_RSS_H

#include <rte_thash.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include <dao_log.h>

/* Cache per-port RETA for HW-equivalent RSS mapping */
int rdma_rss_cache_port(uint16_t portid);
uint16_t rdma_get_queue_id(uint32_t qp_id, uint8_t nb_queues, uint16_t port_id);

#endif /* RDMA_RSS_H */
