/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __CA_DP_H__
#define __CA_DP_H__

#include "ca_crypto_queue.h"

void ca_eth_rx(uint16_t nb_valid_ethdevs, struct pending_queue *pq);

#endif /* __CA_DP_H__ */
