/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 *
 * This file contains the items related methods
 */

#ifndef FLOW_PERF_ITEMS_GEN
#define FLOW_PERF_ITEMS_GEN

#include <rte_flow.h>
#include <stdint.h>

#include "config.h"
#include "flow_gen.h"

void fill_items(struct rte_flow_item *items, uint64_t *flow_items, uint8_t core_idx,
		struct test_ipaddr_port *test_arg);

#endif /* FLOW_PERF_ITEMS_GEN */
