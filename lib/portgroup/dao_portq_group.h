/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef _DAO_PORT_QUEUE_GROUP_H_
#define _DAO_PORT_QUEUE_GROUP_H_

/**
 * @file
 *
 * dao_portq_group.h
 *
 * Control Path PortQ [port, queue] group APIs
 */

#ifdef __cplusplus
extern "C" {
#endif

/**< Initializer value for dao_portq_group_t */
#define DAO_PORTQ_GROUP_INITIALIZER    ((dao_portq_group_t)(~0))

typedef uint32_t dao_portq_group_t; /**< dao port_queue group object */

/**
 * DAO Port-queue aka combination of [port, rq_id]
 */
typedef struct dao_portq {
	uint32_t rq_id; /**< Receive queue id */
	uint32_t port_id; /**< Port_id/ethdev_id */
} dao_portq_t;

/**
 * Port queue group library
 *
 * Port queue group library allow applications to poll list-of [port, queue]
 * (@ref dao_portq_t) per core in fast path.
 *
 * In a typical fast path processing, each worker core calls rte_eth_rx_burst()
 * for combination of [port/ethdev, rq_id] assigned to each core via RSS based
 * scheme. In a runtime environment, number of ethdevs/port can change based on
 * how many of them are newly probed or unprobed. This library facilitates
 * maintaining [port, queue] per worker core as per any change in control path
 * actions.
 *
 * This file declares control path APIs for Portq group object:
 * - Initialize dao portq structures (dao_portq_group_init())
 * - Create dao_portq object (dao_portq_group_create())
 * - Get portq_group object by name (dao_portq_group_get_by_name())
 * - Destroy portq_group (dao_portq_group_destroy())
 *
 * Maintenance of dao_portq_t (aka [port, rq_id]) in a portq_group per core:
 * - Assigning dao_portq_t object for a core to portq_group (dao_portq_group_portq_add())
 * - Deleting dao_portq_t from portq_group for a core (dao_portq_group_portq_delete())
 * - Get number of dao_portq_t in a portq_group for a core(dao_portq_group_portq_get_num())
 */

/**
 * Initialize portq_group main.
 *
 * If not explicitly called, dao_portq_group_create() internally calls with
 * default value of num_portq_groups
 *
 * @param num_portq_groups
 *   Initialize dao portq main library to support num_portq_groups
 *
 * @return
 *  <0: Failure
 *  0: Success
 */
int dao_portq_group_init(uint32_t num_portq_groups);

/**
 * Create portq_group object
 *
 * @param portq_name
 *   Name of portq group
 * @param num_cores
 *   Number of worker cores for which @ref dao_portq_t to be maintained
 * @param num_portqs
 *   Number of dao_portq_t per core.
 * @param[out] epg
 *   Pointer to dao_portq_group_t. Valid when return is success
 *
 * @return
 *   <0: Failure
 *    0: Success
 */
int dao_portq_group_create(const char *portq_name, uint32_t num_cores, uint32_t num_portqs,
			   dao_portq_group_t *epg);

/**
 * Get portq_group object by name
 *
 * @param portq_name
 *   Name of portq group
 * @param[out] epg
 *   Pointer to dao_portq_group_t. Valid when return is SUCCESS
 *
 * @return
 *   <0: Failure
 *    0: Success
 */
int dao_portq_group_get_by_name(const char *portq_name, dao_portq_group_t *epg);

/**
 * Add dao_portq_t to portq_group object for a core
 *
 * @param epg
 *   dao_portq_group_t object
 * @param core_id
 *   Core_id ranging from 0 to "num_cores-1" ("num_cores" provided in dao_portq_group_create())
 * @param portq
 *   Pointer to dao_portq_t provided by caller
 * @param[out] returned_index
 *   Returned index where portq is added. Valid when return is SUCCESS
 *
 * @return
 *   <0: Failure
 *    0: Success
 */
int dao_portq_group_portq_add(dao_portq_group_t epg, uint32_t core_id, dao_portq_t *portq,
			      int32_t *returned_index);

/**
 * Get dao_portq_t for a core using returned index
 *
 * @param epg
 *   dao_portq_group_t object
 * @param core_id
 *   Core_id ranging from 0 to "num_cores-1" ("num_cores" provided in dao_portq_group_create())
 * @param returned_index
 *   Returned index where portq is added
 * @param[out] portq
 *   Pointer to dao_portq_t provided by caller. Valid if return is SUCCESS
 *
 * @return
 *   <0: Failure
 *    0: Success
 */
int dao_portq_group_portq_get(dao_portq_group_t epg, uint32_t core_id, int32_t returned_index,
			      dao_portq_t *portq);

/**
 * Get number of dao_portq_t for a core in a portq_group object
 *
 * @param epg
 *   dao_portq_group_t object
 * @param core_id
 *   Core_id ranging from 0 to "num_cores-1" ("num_cores" provided in dao_portq_group_create())
 * @param[out] num_ports
 *   Pointer to num_ports set by API. Valid if API returns successfully
 *
 * @return
 *   <0: Failure
 *    0: Success
 */
int dao_portq_group_portq_get_num(dao_portq_group_t epg, uint32_t core_id, uint32_t *num_ports);

/**
 * Delete dao_portq_t for a core using returned index
 *
 * @param epg
 *   dao_portq_group_t object
 * @param core_id
 *   Core_id ranging from 0 to "num_cores-1" ("num_cores" provided in dao_portq_group_create())
 * @param returned_index
 *   Returned index where portq is added
 *
 * @return
 *   <0: Failure
 *    0: Success
 */
int dao_portq_group_portq_delete(dao_portq_group_t epg, uint32_t core_id, int32_t returned_index);

/**
 * Delete portq_group object
 *
 *   <0: Failure
 *    0: Success
 */
int dao_portq_group_destroy(dao_portq_group_t epg);

#ifdef __cplusplus
}
#endif

#endif
