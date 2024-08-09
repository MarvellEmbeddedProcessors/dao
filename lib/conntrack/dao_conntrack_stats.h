/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __DAO_CONNTRACK_STATS_H__
#define __DAO_CONNTRACK_STATS_H__

enum ct_stats_id {
	CT_CORE_PKT,

	/* Error stats */
	/* Core stats */
	CT_CORE_ERR_L3_CSUM,
	CT_CORE_ERR_IP4_FRAG,
	CT_CORE_ERR_IP6_FRAG,
	CT_CORE_ERR_L4_CSUM,
	CT_CORE_ERR_INVALID_STATE,
	CT_CORE_ERR_HASH_ADD,
	CT_CORE_ERR_BLIST_LOOKUP,
	CT_CORE_ERR_CONN_LOOKUP,
	CT_CORE_ERR_CONN_CREAT,
	CT_CORE_ERR_CT_FULL,

	/* TCP stats */
	CT_TCP_ERR_STATS_1,
	CT_TCP_ERR_STATS_2,

	/* ICMP stats */
	CT_ICMP_ERR_STATS_1,
	CT_ICMP_ERR_STATS_2,

	/* Debug stats */

	/* This shall always be last */
	CT_STATS_MAX,
};

struct dao_ct_stats {
	uint64_t stats[CT_STATS_MAX];
};

extern struct dao_ct_stats ct_stats[RTE_MAX_LCORE];

#define DAO_CT_STATS_INC(x) 						\
do {									\
	unsigned int lcore = rte_lcore_id();				\
	uint32_t stat_id = (uint32_t)x;					\
	ct_stats[lcore].stats[stat_id]++;				\
}while (0);								\

#define DAO_CT_STATS_DEC(x) 						\
do {									\
	unsigned int lcore = rte_lcore_id();				\
	uint32_t stat_id = (uint32_t)x;					\
	ct_stats[lcore].stats[stat_id]--;				\
}while (0);								\

#define DAO_CT_STATS_ADD(x, v) 						\
do {									\
	unsigned int lcore = rte_lcore_id();				\
	uint32_t stat_id = (uint32_t)x;					\
	uint64_t val = (uint64_t)v;					\
	ct_stats[lcore].stats[stat_id] += val;				\
}while (0);								\

/* XXX: Debug stats for future. */
#define DAO_CT_DBG_STATS_INC(x) 					\
do {									\
}while (0);								\

#define DAO_CT_DBG_STATS_DEC(x) 					\
do {									\
}while (0);								\

#define DAO_CT_DBG_STATS_ADD(x, v) 					\
do {									\
}while (0);								\

/* Get error string using id. */
const char *ct_stats_id2str_get(uint32_t id);

#endif /* __DAO_CONNTRACK_STATS_H__ */
