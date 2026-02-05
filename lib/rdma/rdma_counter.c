/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <dao_log.h>
#include <rte_malloc.h>

#include "rdma_counter.h"
#include "rdma_priv.h"
#include "rdma_port_priv.h"

rdma_counter_t **rdma_counter_table;
rdma_lcore_map_t *rdma_lcore_map;
uint8_t num_rport;

int rdma_counter_init(uint8_t nport)
{
	int lcore_id, nb_lcore = 0;

	rdma_lcore_map = rte_zmalloc("rdma_lcore_map", sizeof(rdma_lcore_map_t),
				     RTE_CACHE_LINE_SIZE);

	if (!rdma_lcore_map) {
		dao_err("Failed to allocate rdma_lcore_map");
		return -ENOMEM;
	}

	RTE_LCORE_FOREACH(lcore_id) {
		rdma_lcore_map->lcore_to_index[lcore_id] = nb_lcore;
		rdma_lcore_map->index_to_lcore[nb_lcore++] = lcore_id;
	}

	rdma_lcore_map->nb_lcore = nb_lcore;
	rdma_counter_table = rte_zmalloc("rdma_counter_table",
					 sizeof(rdma_counter_t *) * nb_lcore,
					 RTE_CACHE_LINE_SIZE);

	if (!rdma_counter_table) {
		dao_err("Failed to allocate rdma_counter_table");
		rte_free(rdma_lcore_map);
		return -ENOMEM;
	}

	num_rport = nport;
	for (int lcore = 0; lcore < nb_lcore; lcore++) {
		lcore_id = rdma_lcore_map->index_to_lcore[lcore];
		rdma_counter_table[lcore] = rte_zmalloc("rdma_counters_per_lcore",
							sizeof(rdma_counter_t) * num_rport,
							RTE_CACHE_LINE_SIZE);
		if (!rdma_counter_table[lcore]) {
			dao_err("Failed to allocate counters for lcore %d", lcore_id);
			goto free_lcores;
		}
	}

	return 0;
free_lcores:
	for (int i = 0; i < nb_lcore; i++) {
		if (rdma_counter_table[i])
			rte_free(rdma_counter_table[i]);
	}

	rte_free(rdma_counter_table);
	rte_free(rdma_lcore_map);
	return -ENOMEM;
}
