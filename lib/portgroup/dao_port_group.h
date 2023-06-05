/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#ifndef _DAO_PORT_GROUP_H_
#define _DAO_PORT_GROUP_H_

/**
 * @file
 *
 * DAO Port group
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

#ifdef __cplusplus
extern "C" {
#endif

#define DAO_PORT_GROUP_MAX            8  /**< Default number of port_groups which are supported */
#define DAO_PORT_GROUP_NAMELEN        64 /**< Max Length of port_group name */
/**< Initializer for dao_port_group_t */
#define DAO_PORT_GROUP_INITIALIZER    ((dao_port_group_t)(~0))
#define DAO_PORT_INVALID_VALUE        ((dao_port_t)(~0)) /**< Initializer value for dao_port_t */

typedef uint32_t dao_port_group_t; /**< dao port_group object holding list of @ref dao_port_t */
typedef uint64_t dao_port_t;       /**< Application level identifier to represent port */

/**
 * Port group library
 *
 * Port group library allows applications to keep track of homogeneous ports
 * (or ethdevs) created in the system and facilitates iterating over these
 * ports in slow path seamlessly.
 *
 * Typically, in a given system varieties of ports are probed like Ethernet
 * PMD devices, LINUX TUN/TAP devices, virtio devices, DMA devices etc.
 * Application, for instance, can create "dao_port_group_t" object (@see
 * dao_port_group_create()) and add all LINUX tap devices to this newly created
 * "dao_port_group_t" object (dao_port_group_port_add()) and iterate over
 * these TAP devices via slow path macro (DAO_PORT_GROUP_FOREACH_PORT).
 *
 * Application can create (DAO_PORT_GROUP_MAX) number of
 * "dao_port_group_t" objects in the system.
 */

/**
 * Create port_group object
 *
 * @param group_name
 *   Name of the port_group name
 * @param max_num_ports
 *   Maximum number of "dao_port_t" objects that application would like to add
 * @param[out] epg
 *   Pointer to newly created "dao_port_group_t" object. Valid if return is 0.
 *
 * @return
 *   0: Success
 *  <0: Failure
 */
int dao_port_group_create(const char *group_name, uint32_t max_num_ports, dao_port_group_t *epg);

/**
 * Get already created port_group object by its name
 *
 * @param group_name
 *   Name of the group with which port_group was created
 * @param[out] epg
 *   Pointer to "dao_port_group_t" object. Valid if return is 0.
 *
 * @return
 *   0: Success
 *  <0: Failure
 */
int dao_port_group_get_by_name(const char *group_name, dao_port_group_t *epg);

/**
 * Add "dao_port_t" to port_group object
 *
 * @param epg
 *   "dao_port_group_t" object.
 * @param port
 *   "dao_port_t" to be added to port_group object
 * @param[out] returned_index
 *   Pointer to returned index at which library stores provided port. Can be
 *   used by caller for port iteration.
 *
 *   @see dao_port_group_port_get()
 *   @see dao_port_group_next_active_port_get()
 *
 * @return
 *   0: Success
 *  <0: Failure
 */
int dao_port_group_port_add(dao_port_group_t epg, dao_port_t port, int32_t *returned_index);

/**
 * Get "dao_port_t" from port_group object using returned_index retrieved from
 * @ref dao_port_group_port_add()
 *
 * @param epg
 *   "dao_port_group_t" object.
 * @param returned_index
 *   Returned index retrieved from @ref dao_port_group_port_add()
 * @param[out] port
 *   Pointer to @ref dao_port_t. Valid if function returns 0
 *
 * @return
 *   0: Success
 *  <0: Failure
 */
int dao_port_group_port_get(dao_port_group_t epg, int32_t returned_index, dao_port_t *port);

/**
 * Get first "dao_port_t" from a port_group whose returned_index (@see
 * dao_port_group_port_add() is greater than "index" parameter. This function
 * helps to iterate over a port_group. -1 is valid value for "index" parameter
 *
 * @param epg
 *   "dao_port_group_t" object.
 * @param port
 *   Pointer to "dao_port_t". Valid if function returns 0
 * @param index
 *   -1 or Returned index from @ref dao_port_group_port_get_next() or @ref dao_port_group_port_add()
 *
 * @return
 *   >=0: Success. Returns index where returned "port" is saved
 *  <0: Failure
 */
int32_t dao_port_group_port_get_next(dao_port_group_t epg, dao_port_t *port, int32_t index);

/**
 * Get number of "dao_port_t" saved in a port_group.
 *
 * @param epg
 *   "dao_port_group_t" object.
 * @param[out] num_ports
 *   Pointer to num_ports saved by API. Valid if function returns 0
 *
 * @return
 *   0: Success
 *  <0: Failure
 */
int dao_port_group_port_get_num(dao_port_group_t epg, uint32_t *num_ports);

/**
 * Delete already created "dao_port_t" from a port_group
 *
 * @param epg
 *   "dao_port_group_t" object.
 * @param returned_index
 *   Index either retrieved by dao_port_group_port_add() or dao_port_group_port_get_next_port()
 *
 * @return
 *   0: Success
 *  <0: Failure
 */

int dao_port_group_port_delete(dao_port_group_t epg, int32_t returned_index);

/**
 * Destroy port_group object
 *
 * @param epg
 *   "dao_port_group_t" object.
 *
 * @return
 *   0: Success
 *  <0: Failure
 */
int dao_port_group_destroy(dao_port_group_t epg);

/**
 * Loop for all ports in a dao_port_group_t
 *
 * Recommended to be used in control path
 *
 * @param epg (dao_port_group_t)
 * @param port (dao_port_t ) value set by application at index `iter`
 * @param index (int32_t). Array Index where port is saved. Caller can use `index`
 *        to call dao_port_group_delete_port(epg, index)
 */
#define DAO_PORT_GROUP_FOREACH_PORT(epg, port, index)                    \
	for (index = dao_port_group_port_get_next(epg, &port, -1);            \
		(index > -1) && (port != DAO_PORT_INVALID_VALUE);                \
		index = dao_port_group_port_get_next(epg, &port, index))

#endif
