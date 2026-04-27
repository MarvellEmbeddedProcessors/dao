/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __FLOW_GBL_PRIV_H__
#define __FLOW_GBL_PRIV_H__

#include "flow_acl_priv.h"
#include "flow_em_priv.h"
#include "flow_hw_offload_priv.h"

#include "flow_parser_priv.h"

#define FLOW_GBL_CFG_MZ_NAME       "flow_global_cfg"
#define FLOW_DEFAULT_AGING_TIMEOUT 20

extern struct flow_global_cfg *gbl_cfg;

struct flow_data {
	TAILQ_ENTRY(flow_data) next;
	struct dao_flow *flow;
	uint32_t rule_idx;
};

/** Managing flow rules per port */
struct flow_config_per_port {
	/** Is flow list initialized */
	bool list_initialized;
	/** Port ID */
	uint16_t port_id;
	/** Number of flow rules */
	uint32_t num_flows;
	/** Spinlock for flow list */
	rte_spinlock_t flow_list_lock;
	/** Is flow offloaded to the hardware */
	bool hw_offload_enabled;
	/** Aging timeout */
	uint32_t aging_tmo_sec;
	/** Flow parser */
	struct flow_parser parser;
	/** Flow parsing profile */
	struct flow_parser_tcam_kex *parse_prfl;
	/** Flow parsing profile operations */
	struct parse_profile_ops *prfl_ops;
	/** Algorithm selected for this port (DAO_FLOW_ALG_*) */
	uint32_t alg;
	/** Per-port CPT EM context-cache enable */
	bool cpt_ctx_cache_enable;

	TAILQ_HEAD(flow_data_list, flow_data) flow_list;
};

struct parse_profile_ops {
	int (*key_generation)(struct rte_mbuf *pkt, uint16_t channel, uint8_t *key_buf);
};

struct flow_global_cfg {
	void *sw_flow_cfg;
	struct hw_offload_global_config *hw_off_gbl;
	struct flow_config_per_port flow_cfg[RTE_MAX_ETHPORTS];
	uint16_t num_initialized_ports;
	struct flow_fops_t *flow_ops;
	uint8_t cpt_egrp;
	bool cpt_ctx_cache_enable;
};

extern int cpt_em_ctx_cache_warm(void *gcfg, uint16_t port_id);

struct flow_fops_t {
	int (*init)(uint16_t port_id, void **gcfg);
	int (*fini)(uint16_t port_id, void *gcfg);
	void *(*create)(void *cfg, const struct rte_flow_attr *attr,
			const struct rte_flow_item pattern[],
			const struct rte_flow_action actions[], uint16_t port_id,
			uint32_t *rule_idx, struct rte_flow_error *error);
	int (*destroy)(void *cfg, uint16_t port_id, uint32_t tbl_id, void *rule_data);
	int (*lookup)(void *cfg, uint16_t port_id, struct rte_mbuf **objs, uint16_t nb_objs,
		      uint32_t *result, uint8_t depth);
	int (*query)(void *cfg, uint16_t port_id, uint32_t tbl_id, void *rule_data,
		     struct dao_flow_query_count *query);
	int (*dump)(void *cfg, uint16_t port_id, uint32_t tbl_id, void *rule_data, FILE *file);
	int (*flush)(void *cfg, uint16_t port_id);
	int (*info)(void *rule_data, FILE *file, bool is_hw_offloaded);
	int (*count)(void *cfg, uint16_t port_id);
};

extern struct flow_parser_tcam_kex default_kex_profile;
extern struct parse_profile_ops default_prfl_ops;

extern struct flow_parser_tcam_kex ovs_kex_profile;
extern struct parse_profile_ops ovs_prfl_ops;

extern struct flow_parser_tcam_kex exact_match_kex_profile;
extern struct parse_profile_ops exact_match_prfl_ops;

extern struct flow_parser_tcam_kex cpt_em_kex_profile;

extern struct flow_fops_t acl_flow_ops;
extern struct flow_fops_t em_flow_ops;
extern struct flow_fops_t cpt_em_flow_ops;

static inline void
reverse_memcpy(uint8_t *ptr, const uint8_t *data, int len)
{
	int idx;

	for (idx = 0; idx < len; idx++)
		ptr[idx] = data[len - 1 - idx];
}
#endif /* __FLOW_GBL_PRIV_H__ */
