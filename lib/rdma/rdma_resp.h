/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include "rdma_hdr.h"

int rdma_responder(struct pkt_info *pinfo);
struct rte_mbuf *get_ack_list(unsigned int lcore_id, uint32_t index);
uint32_t get_num_ack_pkts(unsigned int lcore_id);
