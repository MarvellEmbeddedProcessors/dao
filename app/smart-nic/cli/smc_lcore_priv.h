/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef APP_GRAPH_ETHDEV_RX_PRIV_H
#define APP_GRAPH_ETHDEV_RX_PRIV_H

#include <stdint.h>

struct lcore_params {
	uint16_t port_id;
	uint8_t queue_id;
	uint8_t lcore_id;
} __rte_cache_aligned;

#endif
