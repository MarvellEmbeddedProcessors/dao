/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __FLOW_DBG_H__
#define __FLOW_DBG_H__

#include <dao_flow.h>

void flow_dbg_dump_mbuf(struct rte_mbuf *mb);
void flow_dbg_dump_flow(uint16_t port_id, const struct rte_flow_attr *attr,
			const struct rte_flow_item pattern[],
			const struct rte_flow_action actions[]);
#endif /* __FLOW_DBG_H__ */
