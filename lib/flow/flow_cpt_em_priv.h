/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __FLOW_CPT_EM_PRIV_H__
#define __FLOW_CPT_EM_PRIV_H__
#include "key.h"
#include <rte_mbuf.h>
#include <stdint.h>

#define CPT_EM_INVALID_INDEX (uint64_t)(-1)

struct cpt_em_entry {
#define CPT_EM_ENTRY_DATA_SIZE  64
#define CPT_EM_ACTION_DATA_SIZE 24
	uint64_t prev;
	uint64_t next;
	uint64_t id;
	uint64_t index;
	uint64_t rsvd : 6;
	uint64_t valid : 1;
	uint64_t direct : 1;
	uint64_t reserved : 56;
	uint8_t key[CPT_EM_ENTRY_DATA_SIZE];
	uint8_t action[CPT_EM_ACTION_DATA_SIZE];
};

struct key_info {
	uint8_t user_key;
	uint8_t alg_key;
	uint8_t size;
};

struct key_config_int {
	int num_fields;
	struct key_info kinfo[64];
};

union ctx_hdr {
	struct {
		uint64_t rsvd : 48;
		uint64_t ctx_push_size : 7;
		uint64_t rsvd1 : 1;
		uint64_t ctx_hdr_size : 2;
		uint64_t aop_valid : 1;
		uint64_t rsvd2 : 1;
		uint64_t ctx_size : 4;
	} s;
	uint64_t u64;
};

struct cpt_em_table_info {
	uint32_t table_type;
	uint32_t table_size;
	uint16_t key_size;
	uint16_t action_size;
	uint32_t reserved;
};

struct cpt_em_table {
	union ctx_hdr w0;
	struct cpt_em_table_info tbl;
	uint64_t free_index;
	struct key_config_int *key_fields;
	uint8_t ptype_len[4][16];
	struct key_ext_opaque ext_opaque;
	struct cpt_em_entry entries[];
};

struct cpt_em_parse_info {
	const struct rte_flow_item *pattern;
};

struct cpt_em_rule_data {
	TAILQ_ENTRY(cpt_em_rule_data) next;
	bool is_hw_offloaded;
	uint16_t port_id;
	uint16_t tbl_id;
	/* Contiguous match string */
	uint64_t parsed_flow_data[FLOW_PARSER_MAX_MCAM_WIDTH_DWORDS];
	uint64_t parsed_flow_data_mask[FLOW_PARSER_MAX_MCAM_WIDTH_DWORDS];
	uint64_t rule_idx;
	uint32_t act_idx;
	uint32_t rule_hits;
};

struct cpt_em_actions {
	bool in_use;
	bool is_hw_offloaded;
	bool counter_enable;
#define CPT_EM_ACTION_MARK  RTE_BIT64(0)
#define CPT_EM_ACTION_COUNT RTE_BIT64(1)
#define CPT_EM_ACTION_JUMP  RTE_BIT64(2)
	uint64_t act_map;
	uint32_t index;
	uint32_t n_tblid;
	union {
		uint64_t rx_action;
		uint64_t tx_action;
	} u;
	uint64_t vtag_action;
	struct cpt_em_rule_data *rule_data;
};

/* Single ACL table instance for a port */
struct dao_cpt_em_table {
	uint16_t port_id;
	uint16_t tbl_id;
	bool tbl_val;
	uint32_t num_rules;
	struct cpt_em_table *cpt_em_table;
	struct cpt_em_table *ttable_ctx;
	struct key_config_int key_fields;
	struct key_config_int *kf_ptr_save;
	struct cpt_em_table_info tbl_info;
	struct cpt_em_actions *action;
	uint64_t *delete_ptr;
	uint32_t size;
	struct parse_profile_ops *prfl_ops;
	bool init_done;
	struct rte_mempool *mempool;
	struct cpt_inst_s *inst_mem;
#define NB_DESC 20000
	void *data_ptrs[NB_DESC];
	/* Spinlock */
	rte_spinlock_t ctx_lock;

	TAILQ_HEAD(cpt_em_rule_list, cpt_em_rule_data) flow_list;
};

/* Per port ACL tables */
struct cpt_em_config_per_port {
	struct dao_cpt_em_table dao_cpt_em_tbl;
	uint32_t num_rules_per_prt;
};

/* Global ACL confiuration - across all ports */
struct cpt_em_global_config {
	struct cpt_em_config_per_port cpt_em_cfg_prt[RTE_MAX_ETHPORTS];
};
#endif
