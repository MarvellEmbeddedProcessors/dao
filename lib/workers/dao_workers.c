/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <dao_workers.h>

dao_workers_main_t *__dao_workers;

int
dao_workers_init(uint64_t core_mask, uint32_t control_core_index, size_t per_core_app_data_sz)
{
	dao_workers_main_t *dao_workers = NULL;
	uint64_t total_sz = 0, worker_sz;
	dao_worker_t *wrkr = NULL;
	uint64_t num_bits;
	uint64_t i, j, k;

	num_bits = rte_popcount64(core_mask);

	if (!num_bits) {
		dao_err("core_mask cannot be 0");
		return -1;
	}

	DAO_WORKERS_LOG("core_mask: 0x%lx, num_bits in core_mask: %lu, app_sz:%lu",
			core_mask, num_bits, per_core_app_data_sz);

	if (__dao_workers) {
		dao_err("dao_workers_main already initialized");
		return -1;
	}

	if (control_core_index != DAO_WORKER_INVALID_INDEX) {
		if (!(RTE_BIT64(control_core_index) & core_mask)) {
			dao_err("Valid control_core_index: %u must be part of core_mask: 0x%lx",
				control_core_index, core_mask);
			return -1;
		}
	} else {
		control_core_index = DAO_WORKER_INVALID_INDEX;
	}
	worker_sz = sizeof(dao_worker_t) +
		DAO_ROUNDUP(per_core_app_data_sz, RTE_CACHE_LINE_SIZE);
	total_sz = (sizeof(dao_workers_main_t) + (num_bits * worker_sz));

	dao_workers = malloc(total_sz);
	if (!dao_workers)
		DAO_ERR_GOTO(ENOMEM, error, "dao_workers_main mem alloc failed");

	memset(dao_workers, 0, total_sz);

	dao_workers->num_cores = num_bits;
	dao_workers->core_mask = core_mask;
	dao_workers->per_worker_sz = worker_sz;
	dao_workers->workers_main_sz = total_sz;
	dao_workers->control_core_index = control_core_index;

	/* Set number of workers equal to number of bits set in core_mask for now.
	 * We set correct num_workers later in this function
	 */
	dao_workers->num_workers = num_bits;

	for (i = 0, j = 0, k = 0; i < RTE_MAX_LCORE; i++) {
		if (!rte_lcore_is_enabled((unsigned int)i))
			continue;

		if (!(RTE_BIT64(i) & core_mask))
			continue;

		wrkr = dao_workers_worker_get(dao_workers, j);

		memset(wrkr, 0, worker_sz);

		wrkr->dpdk_lcore_id = i;
		wrkr->dpdk_cpu_id = rte_lcore_to_cpu_id(i);
		wrkr->dpdk_core_index = rte_lcore_index(i);
		wrkr->dpdk_numa_id = rte_lcore_to_socket_id(i);
		wrkr->dao_workers = dao_workers;
		wrkr->core_index = j++;
		wrkr->app_private_size = per_core_app_data_sz;

		if (i == control_core_index) {
			wrkr->is_main = 1;
			wrkr->worker_index = DAO_WORKER_INVALID_INDEX;
			dao_workers->control_core_index = wrkr->core_index;
			dao_info("main[C%u, C%u]: dpdk_lcore_id: %d, dpdk_core_index: %d, dpdk_cpu_id: %d",
				 wrkr->core_index, dao_workers->control_core_index,
				 wrkr->dpdk_lcore_id, wrkr->dpdk_core_index,
				 wrkr->dpdk_cpu_id);
		} else {
			wrkr->worker_index = (uint32_t)k++;
			wrkr->is_main = 0;
			dao_info("wrkr[C%u, W%u]: dpdk_lcore_id:%d, dpdk_core_index: %d, dpdk_cpu_id: %d",
				 wrkr->core_index, wrkr->worker_index, wrkr->dpdk_lcore_id,
				 wrkr->dpdk_core_index, wrkr->dpdk_cpu_id);
		}
	}
	dao_workers->num_workers = k;
	__dao_workers = dao_workers;
	return 0;
error:
	return -1;
}

int dao_workers_fini(void)
{
	if (__dao_workers) {
		free(__dao_workers);
		__dao_workers = NULL;
		return 0;
	}
	return -1;
}

int dao_workers_barrier_sync(dao_worker_t *worker)
{
	dao_workers_main_t *dwm = (dao_workers_main_t *)worker->dao_workers;
	uint64_t num_workers;

	if (dwm->num_workers < 2)
		return 0;

	if (!dao_workers_is_control_worker(worker))
		return -1;

	if (dwm->barrier_recursion_level > 0)
		return -1;

	num_workers = __dao_workers_num_workers_get(dwm);

	/* Indicate barrier is taken */
	DAO_WORKERS_LOG("Core: %d about to sync_barrier", dao_workers_core_index_get(worker));

	__atomic_store_n(&dwm->parked_at_barrier, 1, __ATOMIC_RELAXED);

	dwm->barrier_recursion_level++;

	/* Busy wait until all workers reaches to barrier */
	while (__atomic_load_n(&dwm->barrier_count, __ATOMIC_RELAXED) != num_workers)
		rte_pause();

	DAO_WORKERS_LOG("C%d: All cores stopped", dao_workers_core_index_get(worker));

	return 0;
}

int dao_workers_barrier_release(dao_worker_t *worker)
{
	dao_workers_main_t *dwm = (dao_workers_main_t *)worker->dao_workers;

	if (dwm->num_workers < 2)
		return 0;

	if (!dao_workers_is_control_worker(worker))
		return -1;

	if (dwm->barrier_recursion_level > 1)
		return -1;

	if (dwm->barrier_recursion_level < 1)
		return -1;

	dwm->barrier_recursion_level--;

	/* Complete all core-writes */
	rte_smp_wmb();

	DAO_WORKERS_LOG("Core: %d about to release_barrier", dao_workers_core_index_get(worker));

	/* release barrier */
	__atomic_store_n(&dwm->parked_at_barrier, 0, __ATOMIC_RELAXED);

	/* reset barrier count for next usage */
	__atomic_store_n(&dwm->barrier_count, 0, __ATOMIC_RELAXED);

	DAO_WORKERS_LOG("C%d: All cores released", dao_workers_core_index_get(worker));

	return 0;
}
