/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef _DAO_PORT_QUEUE_GROUP_WORKER_H_
#define _DAO_PORT_QUEUE_GROUP_WORKER_H_

/**
 * @file
 *
 * dao_portq_group_worker.h
 *
 * Fast Path PortQ [port, queue] group APIs
 *
 * Once application creates @ref dao_portq_group_t and assign @ref dao_portq_t by core_id
 * in control path, on each worker, list of @ref dao_portq_t (aka @ref dao_portq_list_t)
 * can be retrieved using @ref dao_portq_group_list_get().
 *
 * Caller either can manually iterate over @ref dao_portq_list_t OR use fast path defined macro
 * DAO_PORTQ_GROUP_FOREACH_CORE()
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

#include <dao_portq_group.h>
#include <dao_log.h>
#include <dao_util.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DAO_PORTQ_GROUP_NAMELEN         64     /**< Max length of portq group name */
#define DAO_PORTQ_INVALID_VALUE         ((uint32_t)(~1)) /**< Default value, if uninitialized */

/** List/Array of dao_portq_t */
typedef struct dao_portq_list {
	RTE_MARKER cacheline0 __rte_cache_aligned;

	uint32_t num_portqs; /**< Number of [port, queue] (@ref dao_portq_t) added */

	/**< Memory allocated for [dao_portq_list:portqs] (@ref dao_portq_list_t::portqs) */
	uint32_t max_portqs_supported;

	dao_portq_t portqs[]; /**< Array holding [portq, queue] (@ref dao_portq_t) */

} dao_portq_list_t; /* do not cache align */

/**
 * Internal structure corresponding to dao_portq_group_t for maintaining
 * portq_group per core
 */
struct dao_portq_group {
	char portq_group_name[DAO_PORTQ_GROUP_NAMELEN]; /**< portq_group name */

	/**
	 * Number of cores for which @ref dao_portq_list_t is maintained.
	 *
	 * @see dao_portq_group_create()
	 */
	uint32_t num_cores;

	/** Index of this portq_group in __portq_group_main */
	uint32_t portq_group_index;

	/**
	 * Sizeof each element in (@ref  dao_portq_group::core_portq_list)
	 *
	 * aka sizeof(core_portq_list[0])
	 */
	size_t per_core_portq_list_size;

	void *portq_group_main; /**< Back pointer to __portq_group_main */

	RTE_MARKER cacheline1 __rte_cache_aligned;
	/** Per core @ref dao_portq_list_t */
	dao_portq_list_t core_portq_list[];
};

/**
 * dao portq_group main
 */
typedef struct dao_portq_group_main {
	/**
	 * Number of portq_groups supported by library
	 *
	 * @see dao_portq_group_init()
	 */
	uint32_t num_portq_groups;

	/**
	 * Maximum number of @ref dao_portq_group which can be saved in
	 * (@ref  dao_portq_group_main::portq_groups)
	 */
	uint32_t max_portq_groups_supported;

	/** Array holding @ref dao_portq_group objects */
	struct dao_portq_group *portq_groups[];

} dao_portq_group_main_t;

/**
 * @def __portq_group_main
 *
 * Internal main structure for portq_group APIs
 */
extern dao_portq_group_main_t *__portq_group_main;

/** Function definitions */

/**
 * Translate from public portq_group object to internal structure
 */
static inline struct dao_portq_group *
dao_portq_group_get(dao_portq_group_t epg)
{
	dao_portq_group_main_t *pm = __portq_group_main;

	RTE_VERIFY(epg < pm->max_portq_groups_supported);

	return(pm->portq_groups[epg]);
}

/**
 * Fast path API: Get list of dao_portq_t for core_id in a portq_group object
 *
 * @param epg
 *   Pointer to struct dao_portq_group
 * @param core_id
 *   Core_id ranging from 0 to "num_cores -1" (dao_portq_group_create())
 *
 * @return dao_portq_list_t
 *   List of dao_portq_t for a core
 */
static inline dao_portq_list_t *
__dao_portq_group_list_get(struct dao_portq_group *epg, uint32_t core_id)
{
	if (unlikely(!epg))
		assert(0);

	RTE_VERIFY(core_id < epg->num_cores);

	return ((dao_portq_list_t *)((uint8_t *)epg->core_portq_list +
				     (core_id * epg->per_core_portq_list_size)));
}

/**
 * Per core Fast path API: Get list of dao_portq_t for core_id in a portq_group
 *                         object
 *
 * @param epg
 *   dao_portq_group_t object
 * @param core_id
 *   Core_id ranging from 0 to "num_cores -1" (dao_portq_group_create())
 *
 * @return dao_portq_list_t
 *   List of dao_portq_t for a core
 */
static inline dao_portq_list_t *
dao_portq_group_list_get(dao_portq_group_t epg, uint32_t core_id)
{
	return(__dao_portq_group_list_get(dao_portq_group_get(epg), core_id));
}

/**
 * Fast path API for getting first "dao_portq_t" from a portq_group whose returned_index (@see
 * dao_portq_group_portq_add() is greater than "index" parameter. This function
 * helps to iterate over a port group. -1 is valid value for "index" parameter
 *
 * @param epg
 *   "dao_port_group_t" object.
 * @param core_id
 *   core_id ranging from 0 to "num_cores-1" (provided in @ref dao_portq_group_create())
 * @param[out] portq
 *   Pointer to "dao_portq_t *". Valid if function returns 0
 * @param[out] index
 *   -1 or Returned index from @ref dao_port_group_port_get_next() or @ref dao_port_group_port_add()
 *
 * @return
 *   >=0: Success. Returns index where returned "port" is saved
 *  <0: Failure
 */
static inline int32_t
dao_portq_group_portq_get_next(dao_portq_group_t epg, uint32_t core_id, dao_portq_t **portq,
			       int32_t index)
{
	dao_portq_list_t *epl = NULL;
	int32_t iter = index + 1;

	epl = dao_portq_group_list_get(epg, core_id);

	if (unlikely(iter < 0))
		return -1;

	while (epl->max_portqs_supported > (uint32_t)iter) {
		if (epl->portqs[iter].port_id == DAO_PORTQ_INVALID_VALUE) {
			iter++;
			continue;
		}
		break;
	}
	if (likely((uint32_t)iter < epl->max_portqs_supported)) {
		*portq = epl->portqs + iter;
		return iter;
	}

	return -1;
}

/**
 * Fast path macro for iterating over dao_portq_t
 *
 * Usage:
 *
 * @param epg
 *   dao_portq_group_t object.
 * @param core_id
 *   core_id ranging from 0 to "num_cores-1" (provided in @ref dao_portq_group_create())
 *   Type: (uint32_t)
 * @param portq
 *   Pointer to dao_portq_t
 * @param i
 *   Iterator. (int32_t)
 *
 */
#define DAO_PORTQ_GROUP_FOREACH_CORE(epg, core_id, portq, i)					   \
		for (i = dao_portq_group_portq_get_next(epg, core_id, &portq, -1);		   \
			(i > -1) && (portq->port_id != DAO_PORTQ_INVALID_VALUE);		   \
			i = dao_portq_group_portq_get_next(epg, core_id, &portq, i))

#ifdef __cplusplus
}
#endif

#endif
