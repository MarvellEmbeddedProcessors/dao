/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __FLOW_GBL_PRIV_H__
#define __FLOW_GBL_PRIV_H__

#include "flow_acl_priv.h"
#include "flow_hw_offload_priv.h"

#include "flow_parser_priv.h"

#define FLOW_GBL_CFG_MZ_NAME       "flow_global_cfg"
#define FLOW_DEFAULT_AGING_TIMEOUT 20

extern struct flow_global_cfg *gbl_cfg;
struct flow_data {
	TAILQ_ENTRY(flow_data) next;
	struct dao_flow *flow;
	uint32_t acl_rule_idx;
};

/* Managing flow rules per port */
struct flow_config_per_port {
	bool list_initialized;
	uint16_t port_id;
	uint32_t num_flows;
	rte_spinlock_t flow_list_lock;

	TAILQ_HEAD(flow_data_list, flow_data) flow_list;
};

extern struct flow_parser_tcam_kex default_kex_profile;
extern struct parse_profile_ops default_prfl_ops;
extern struct flow_parser_tcam_kex ovs_kex_profile;
extern struct parse_profile_ops ovs_prfl_ops;

struct parse_profile_ops {
	int (*key_generation)(struct rte_mbuf *pkt, uint16_t channel, uint8_t *key_buf);
};

struct flow_global_cfg {
	struct acl_global_config *acl_gbl;
	struct hw_offload_global_config *hw_off_gbl;
	bool hw_offload_enabled;
	/* Aging timeout */
	uint32_t aging_tmo;
	struct flow_parser parser;
	struct flow_parser_tcam_kex *parse_prfl;
	struct parse_profile_ops *prfl_ops;
	struct flow_config_per_port flow_cfg[RTE_MAX_ETHPORTS];
};

static inline void
reverse_memcpy(uint8_t *ptr, const uint8_t *data, int len)
{
	int idx;

	for (idx = 0; idx < len; idx++)
		ptr[idx] = data[len - 1 - idx];
}
#endif /* __FLOW_GBL_PRIV_H__ */
