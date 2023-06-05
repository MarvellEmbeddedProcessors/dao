/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __SMC_PORT_PRIV_H__
#define __SMC_PORT_PRIV_H__

enum port_state {
	SMC_PORT_ADDED = 1,
	SMC_PORT_LINKED,
};

struct port_info {
	TAILQ_ENTRY(port_info) next;
	uint16_t portid;
	enum port_state state;
} __rte_cache_aligned;

TAILQ_HEAD(prt_lst, port_info);

struct port_info *port_entry_lookup(uint16_t portid);
int port_state_update(uint16_t portid, enum port_state state);
int port_insert(uint16_t portid);
int port_delete(uint16_t portid);
#endif /* __SMC_PORT_PRIV_H__ */
