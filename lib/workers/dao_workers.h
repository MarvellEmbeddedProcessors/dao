/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef _DAO_LIB_WORKERS_H_
#define _DAO_LIB_WORKERS_H_

/**
 * @file dao_workers.h
 *
 * DAO workers provides set of APIs to manage workers for following use-cases:
 * - From a given set of core-lists (via rte_eal), application can designate
 *   subset of cores as @b app-workers and @b app-control-core (See @ref
 *   dao_workers_init())
 *
 * - API assigns each app-worker a unique @b worker-id ranging from [0 -
 *   num_workers], excluding app-control-core, which allows application to
 *   sequentially allocate/manage data structures for workers
 *
 * - If valid @b control_core_index is passed to @ref dao_workers_init(),
 *   core having (lcore-id == control_core_index) is designated as @b
 *   app-control-core instead of app-worker. app-control-core does @b not get
 *   valid worker-id. @ref dao_workers_is_control_worker() returns true
 *   for app-control-core and false for app-workers. In case no app-control-core is
 *   required by application, @ref DAO_WORKER_INVALID_INDEX shall be passed for
 *   @b control_core_index argument in @ref dao_workers_init()
 *
 * - @ref dao_workers_init() also allows to allocate cache-aligned memory
 *   for each worker with size equal to @b per_core_app_data_sz argument. API
 *   rounds-up this size to nearest cache-line value and allocates memory for
 *   each worker-core.. Each worker, once launched, can access to its memory via
 *   @ref dao_workers_app_data_get()
 *
 * - A core can grab its @b "dao worker handle" via @ref
 *   dao_workers_self_worker_get() which can be saved in software cache for
 *   accessing fast path APIs like (@ref dao_workers_worker_index_get())
 *
 * - In order to apply control configurations like route-updates or IPsec SA/policy updates, it
 *   might be required by application to
 *   - Stop all app-workers (See @ref dao_workers_barrier_sync())
 *   - Apply control configuration changes like route updates etc.
 *   - Release all workers from barrier to resume their work (See @ref
 *     dao_workers_barrier_release())
 *
 *   Each workers must be calling @ref dao_workers_barrier_check() at the start
 *   of data-path loop.
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <assert.h>

#include <rte_common.h>
#include <rte_compat.h>
#include <rte_debug.h>
#include <rte_lcore.h>
#include <rte_bitops.h>
#include <rte_atomic.h>
#include <rte_pause.h>

#include <dao_log.h>
#include <dao_util.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Invalid index of workers */
#define DAO_WORKER_INVALID_INDEX UINT32_C(~0)

#define DAO_WORKERS_LOG dao_dbg

/**
 * struct dao_worker represents single worker which holds fast path access to
 * - core_index (including control_core)
 * - worker_index (excluding control_core)
 * - socket_id or numa_id
 * - Pointer to barrier_mask
 */
typedef struct dao_worker {
	/** Same as rte_lcore_id */
	unsigned int dpdk_lcore_id;

	/** Same as rte_cpu_id() */
	int dpdk_cpu_id;

	/** Same as  rte_lcore_index() */
	int dpdk_core_index;

	/** worker index.  excluding rte_get_main_lcore()i */
	uint32_t worker_index;

	/** index in dao_workers_main->workers */
	uint32_t core_index;

	int dpdk_numa_id;

	/* is this worker dpdk_main_core where rte_eal_init*/
	int is_main;

	/* back pointer to dao_workers_main */
	void *dao_workers;

	/* Size of app_private[] on worker */
	size_t app_private_size;

	RTE_MARKER c1 __rte_cache_aligned;
	uint8_t app_private[];
} dao_worker_t __rte_cache_aligned;

typedef struct dao_workers_main {
	RTE_MARKER c0 __rte_cache_aligned;

	/** num_cores including main_core */
	uint16_t num_cores;

	/** number of workers exclusing control_core */
	uint16_t num_workers;

	/** core_mask provided during initialization */
	uint64_t core_mask;

	uint32_t control_core_index;

	/** Size of element workers[0] */
	size_t per_worker_sz;

	/** Size of this structure */
	size_t workers_main_sz;

	/** Guarding recursive call of dao_workers_barrier_sync/release APIs */
	int barrier_recursion_level;

	/** cacheline 1 */
	RTE_MARKER c1  __rte_cache_aligned;
	uint64_t parked_at_barrier;

	/** cacheline 2 */
	RTE_MARKER c2  __rte_cache_aligned;
	uint64_t barrier_count;

	RTE_MARKER c3 __rte_cache_aligned;
	/** Holding dao_worker_t for each core */
	dao_worker_t workers[];
} dao_workers_main_t;

/** Variable declaration of global workers main */
extern dao_workers_main_t *__dao_workers;

/* Static inline functions */

/**
 * Get dao_worker_t pointer in fast path
 *
 * @param dwm
 *   dao worker main received by dao_workers_get()
 * @param worker_index
 *   worker_index in the range of [0 - dwm->num_workers]
 */
static inline dao_worker_t *
dao_workers_worker_get(dao_workers_main_t *dwm, uint8_t worker_index)
{
	RTE_VERIFY(dwm);
	RTE_VERIFY(worker_index <= dwm->num_workers);

	return ((dao_worker_t *)((uint8_t *)dwm->workers + (worker_index * dwm->per_worker_sz)));
}

/**
 * Grab cache-aligned memory for app-worker with size >= per_core_app_data_sz
 * passed to @ref dao_workers_init()
 *
 * @param wrkr
 *   "dao worker handle". (@see dao_workers_self_worker_get)
 * @param[out] app_data
 *   If passed, Pointer to cache-aligned memory
 * @param[out] size
 *   If passed, size of cache-aligned memory. Should be >= per_core_app_data_sz
 */
static inline int
dao_workers_app_data_get(dao_worker_t *wrkr, void **app_data, size_t *size)
{
	if (likely(wrkr)) {
		if (app_data)
			*app_data = wrkr->app_private;

		if (size)
			*size = wrkr->app_private_size;

		return 0;
	}
	return -1;
}

/**
 * Get core index for provided wrkr handle. Ranging from [0 - num_cores]
 * including app-control-core
 *
 * @param wrkr
 *   dao worker handle
 *
 * @return
 *   Core index
 */
static inline int
dao_workers_core_index_get(dao_worker_t *wrkr)
{
	return wrkr->core_index;
}

/**
 * Get worker index for provided wrkr handle. Ranging from [0 - num_workers]
 * excluding app-control-core
 *
 * @param wrkr
 *   dao worker handle
 *
 * @return
 *   Worker index
 */
static inline int
dao_workers_worker_index_get(dao_worker_t *wrkr)
{
	return wrkr->worker_index;
}

/**
 * Get socket/numa id for the worker
 *
 * @return
 *   Valid socket-id. Same as @b rte_lcore_to_socket_id()
 */
static inline int
dao_workers_numa_get(dao_worker_t *wrkr)
{
	return wrkr->dpdk_numa_id;
}

/**
 * Returns true or false if passed worker is app-control-core
 *
 * @return
 *   1: Passed worker is app-control-core
 *   0: Passed worker is not app-control-core
 */
static inline int dao_workers_is_control_worker(dao_worker_t *worker)
{
	return worker->is_main;
}

/**
 * Get dao worker handle corresponding to app-control-core. Returns NULL if
 * control_core_index passed to @ref dao_workers_init() is equal to @ref
 * DAO_WORKER_INVALID_INDEX
 *
 * @return
 *   NULL: Failure
 *   !NULL: Success
 */
static inline dao_worker_t *
dao_workers_control_worker_get(dao_workers_main_t *dwm)
{
	if (likely(dwm && (dwm->control_core_index != DAO_WORKER_INVALID_INDEX)))
		return (dwm->workers + dwm->control_core_index);
	return NULL;
}

/**
 * Get dao worker main handle
 *
 * @return
 *   NULL: Failure
 *   !NULL: Success
 */
static inline dao_workers_main_t *dao_workers_get(void)
{
	return __dao_workers;
}

static inline int
__dao_workers_num_workers_get(dao_workers_main_t *dwm)
{
	return dwm->num_workers;
}

/**
 * Get number of workers.
 *
 * @return
 *  Number of cores
 */
static inline int dao_workers_num_workers_get(void)
{
	return __dao_workers_num_workers_get(dao_workers_get());
}

/**
 * Get number of cores. Includes app-workers and app-control-core
 *
 * @return
 *  Number of cores
 */
static inline int dao_workers_num_cores_get(void)
{
	dao_workers_main_t *dwm = dao_workers_get();

	return dwm->num_cores;
}

/**
 * Get dao_worker_t object corresponding to worker core on which this API is
 * called
 *
 * @return
 *   NULL: Failure
 *   !NULL: Success
 */
static inline dao_worker_t *
dao_workers_self_worker_get(void)
{
	dao_workers_main_t *wm = dao_workers_get();
	dao_worker_t *wrkr = NULL;
	unsigned int lcore_id;
	uint16_t i;

	lcore_id = rte_lcore_id();

	for (i = 0; i < wm->num_cores; i++) {
		wrkr = dao_workers_worker_get(wm, i);

		/* wrkr is sane */
		assert(wrkr->core_index == i);
		assert(wm == wrkr->dao_workers);

		if (wrkr->dpdk_lcore_id != lcore_id)
			continue;

		if (LCORE_ID_ANY == lcore_id)
			continue;

		break;
	}
	if (i < wm->num_cores)
		return (dao_workers_worker_get(wm, i));

	/* We should not reach here */
	return NULL;
}

/* Function declaration */

/**
 * Initialize dao workers API infra.
 *
 * @b rte_eal_init() is a pre-requisite for this API. Each core bit set in
 * core_mask must have valid rte_lcore_id().
 *
 * @param core_mask
 *   For each set-bit, excluding control_core_index bit, designates
 *   core as @b app-worker.
 * @param control_core_index
 *   If control_core_index != DAO_WORKER_INVALID_INDEX, designate core having
 *   (lcore_id == control_core_index) as @b app-control-core. Here core_id means
 *   set bit in core_mask
 * @param per_core_app_data_sz
 *   Size of cache-aligned memory to be allocated for each app-worker (not for
 *   app-control-core)
 *
 * @return
 *  0: Success
 * <0: Failure
 */
int dao_workers_init(uint64_t core_mask, uint32_t control_core_index, size_t per_core_app_data_sz);

/**
 * Cleanup memory associated with dao workers APIs
 *
 * @return
 *  0: Success
 * <0: Failure
 */
int dao_workers_fini(void);
/**
 * Take barrier sync lock and make all app-workers to stop before returning from API
 *
 * API must be called by app-control-core
 *
 * @param worker
 *    dao worker handle
 *
 * @return
 *  0: Success
 * <0: Failure
 */
int dao_workers_barrier_sync(dao_worker_t *worker);

/**
 * Release barrier held-up by app-control-core and allows workers to resume their work
 *
 * API must be called by app-control-core
 *
 * @param worker
 *    dao worker handle
 *
 * @return
 *  0: Success
 * <0: Failure
 */
int dao_workers_barrier_release(dao_worker_t *worker);

/**
 * Check for worker barrier which makes this worker to stop if app-control-core has called @ref
 * dao_workers_barrier_sync(). API hangs until app-control-core does not call
 * @ref dao_workers_barrier_release
 *
 * API must be called by each app-workers in a fast-path while-loop
 *
 * @param worker
 *    dao worker handle
 */
static inline void
dao_workers_barrier_check(dao_worker_t *worker)
{
	dao_workers_main_t *dwm = (dao_workers_main_t *)worker->dao_workers;

	if (unlikely(__atomic_load_n(&dwm->parked_at_barrier, __ATOMIC_ACQUIRE))) {
		DAO_WORKERS_LOG("Worker%d: going to barrier 0x%lx ",
				dao_workers_worker_index_get(worker),
				__atomic_load_n(&dwm->barrier_count, __ATOMIC_RELAXED));

		__atomic_add_fetch(&dwm->barrier_count, 1, __ATOMIC_RELEASE);

		/* Busy wait worker core until control-core releases barrier */
		while (__atomic_load_n(&dwm->parked_at_barrier, __ATOMIC_RELAXED))
			rte_pause();

		DAO_WORKERS_LOG("Worker: %d released from barrier",
				dao_workers_worker_index_get(worker));
		}
}

#ifdef __cplusplus
}
#endif
#endif
