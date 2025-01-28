/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __CA_DP_H__
#define __CA_DP_H__

#include "ca_cpt_deq.h"
#include "ca_crypto_queue.h"

void ca_eth_rx(struct pending_queue *pq, struct rte_pmd_cnxk_crypto_qptr *cpt_qptr);

#endif /* __CA_DP_H__ */
