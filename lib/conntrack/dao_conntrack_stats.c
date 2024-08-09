/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <rte_lcore.h>

#include "dao_conntrack_stats.h"

struct dao_ct_stats ct_stats[RTE_MAX_LCORE];

static const char *ct_stats_id2str[] = {
	[CT_CORE_PKT] = "ct-pkts",

	/* Core stats */
	[CT_CORE_ERR_L3_CSUM] = "l3-csum-err",
	[CT_CORE_ERR_IP4_FRAG] = "ip4-frag-no-support",
	[CT_CORE_ERR_IP6_FRAG] = "ip6-frag-no-support",
	[CT_CORE_ERR_L4_CSUM] = "l4-csum-err",
	[CT_CORE_ERR_INVALID_STATE] = "invalid-state",
	[CT_CORE_ERR_HASH_ADD] = "hash-add-fail",
	[CT_CORE_ERR_BLIST_LOOKUP] = "blist-lookup-fail",
	[CT_CORE_ERR_CONN_LOOKUP] = "conn-lookup-fail",
	[CT_CORE_ERR_CONN_CREAT] = "conn-creat-err",
	[CT_CORE_ERR_CT_FULL] = "ct-table-full",

	/* TCP stats */
	[CT_TCP_ERR_STATS_1] = "tcp-1",
	[CT_TCP_ERR_STATS_2] = "tcp-2",

	/* ICMP stats */
	[CT_ICMP_ERR_STATS_1] = "icmp-1",
	[CT_ICMP_ERR_STATS_2] = "icmp-2",

	[CT_STATS_MAX] = NULL,
};

const char *
ct_stats_id2str_get(uint32_t id)
{
	return ct_stats_id2str[id];
}
