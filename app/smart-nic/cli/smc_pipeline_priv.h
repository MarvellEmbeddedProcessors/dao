/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef __SMC_PIPELINE_PRIV_H__
#define __SMC_PIPELINE_PRIV_H__

struct port_forwarding {
	TAILQ_ENTRY(port_forwarding) next;
	uint16_t tx_port;
	uint16_t rx_port;
	bool is_used;
} __rte_cache_aligned;

TAILQ_HEAD(prt_fw, port_forwarding);

#endif /* __SMC_PIPELINE_PRIV_H__ */
