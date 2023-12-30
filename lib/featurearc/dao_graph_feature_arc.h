/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2024 Marvell International Ltd.
 */

#ifndef _DAO_GRAPH_FEATURE_ARC_H_
#define _DAO_GRAPH_FEATURE_ARC_H_

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_common.h>
#include <rte_compat.h>
#include <rte_debug.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 *
 * dao_graph_feature_arc.h
 *
 * Define APIs and structures/variables with respect to
 *
 * - Feature arc(s)
 * - Feature(s)
 *
 * A feature arc represents an ordered list of features/protocols at a given
 * networking layer. Feature arc provides a high level abstraction to connect
 * various rte_graph nodes, designated as *feature nodes*, and allowing
 * steering of packets across these feature nodes fast path processing in a
 * generic manner. In a typical network stack, often a protocol or feature must
 * be first enabled on a given interface, before any packet received on that
 * interface is steered to feature processing. For eg: incoming IPv4 packets
 * are sent to routing sub-system only after a valid IPv4 address is assigned
 * to the received interface. In other words, often packets needs to be steered
 * across features not based on the packet content but based on whether feature
 * is enable or disable on a given incoming/outgoing interface. Feature arc
 * provides mechanism to enable/disable feature(s) on each interface and
 * allowing seamless packet steering across enabled feature nodes in fast path.
 *
 * Feature arc also provides a way to steer packets from standard nodes to
 * custom/user-defined *feature nodes* without any change in standard node's
 * fast path functions
 *
 * On a given interface multiple feature(s) might be enabled in a particular
 * feature arc. For instance, both "ipv4-output" and "IPsec policy output"
 * features may be enabled on "eth0" interface in "L3-output" feature arc.
 * Similarly, "ipv6-output" and "ipsec-output" may be enabled on "eth1"
 * interface in same "L3-output" feature arc.
 *
 * When multiple features are present in a given feature arc, its imperative
 * to allow each feature processing in a particular sequential order. For
 * instance, in "L3-input" feature arc it may be required to run "IPsec
 * input" feature first, for packet decryption, before "ip-lookup".  So a
 * sequential order must be maintained among features present in a feature arc.
 *
 * Features are enabled/disabled multiple times at runtime to some or all
 * available interfaces present in the system. Features can be enabled/disabled
 * even after @b rte_graph_create() is called. Enable/disabling features on one
 * interface is independent of other interface.
 *
 * A given feature might consume packet (if it's configured to consume) or may
 * forward it to next enabled feature. For instance, "IPsec input" feature may
 * consume/drop all packets with "Protect" policy action while all packets with
 * policy action as "Bypass" may be forwarded to next enabled feature (with in
 * same feature arc)
 *
 * This library facilitates rte graph based applications to steer packets in
 * fast path to different feature nodes with-in a feature arc and support all
 * functionalities described above
 *
 * In order to use feature-arc APIs, applications needs to do following in
 * control path:
 * - Initialize feature arc library via dao_graph_feature_arc_init()
 * - Create feature arc via dao_graph_feature_arc_create()
 * - Before calling rte_graph_create(), features must be added to feature-arc
 *   via dao_graph_feature_add(). dao_graph_feature_add() allows adding
 *   features in a sequential order with "runs_after" and "runs_before"
 *   constraints.
 * - Post rte_graph_create(), features can be enabled/disabled at runtime on
 *   any interface via dao_graph_feature_enable()/dao_graph_feature_disable()
 *
 * In fast path, nodes uses
 * - dao_graph_feature_arc_has_feature() and
 *   dao_graph_feature_arc_feature_data_get() APIs to steer packets across
 *   feature nodes
 *
 * dao_graph_feature_enable()/dao_graph_feature_disable() APIs are not
 * thread-safe hence must be called by single core while other cores are not
 * using any fast path feature arc APIs.
 */

/**< Initializer value for dao_graph_feature_arc_t */
#define DAO_GRAPH_FEATURE_ARC_INITIALIZER ((dao_graph_feature_arc_t)UINT64_MAX)

/**< Initializer value for dao_graph_feature_arc_t */
#define DAO_GRAPH_FEATURE_INVALID_VALUE UINT8_MAX

/** Max number of features supported in a given feature arc */
#define DAO_GRAPH_FEATURE_MAX_PER_ARC 64

/** Length of feature arc name */
#define DAO_GRAPH_FEATURE_ARC_NAMELEN RTE_NODE_NAMESIZE

/** @internal */
#define dao_graph_feature_cast(x) ((dao_graph_feature_t)x)

/** dao_graph feature arc object */
typedef uint64_t dao_graph_feature_arc_t;

/** dao_graph feature object */
typedef uint8_t dao_graph_feature_t;

/**
 * Initialize feature arc subsystem
 *
 * @param max_feature_arcs
 *   Maximum number of feature arcs required to be supported
 *
 * @return
 *  0: Success
 * <0: Failure
 */
int dao_graph_feature_arc_init(int max_feature_arcs);

/**
 * Create a feature arc
 *
 * @param feature_arc_name
 *   Feature arc name with max length of @ref DAO_GRAPH_FEATURE_ARC_NAMELEN
 * @param max_features
 *   Maximum number of features to be supported in this feature arc
 * @param max_indexes
 *   Maximum number of interfaces/ports/indexes to be supported
 * @param start_node
 *   Base node where this feature arc's features are checked in fast path
 * @param[out] _dfl
 *  Feature arc object
 *
 * @return
 *  0: Success
 * <0: Failure
 */
int dao_graph_feature_arc_create(const char *feature_arc_name, int max_features, int max_indexes,
				 struct rte_node_register *start_node,
				 dao_graph_feature_arc_t *_dfl);

/**
 * Get feature arc object with name
 *
 * @param arc_name
 *   Feature arc name provided to successful @ref dao_graph_feature_arc_create
 * @param[out] _dfl
 *   Feature arc object returned
 *
 * @return
 *  0: Success
 * <0: Failure
 */
int dao_graph_feature_arc_lookup_by_name(const char *arc_name, dao_graph_feature_arc_t *_dfl);

/**
 * Add a feature to already created feature arc
 *
 * @param _dfl
 *   Feature arc handle returned from @ref dao_graph_feature_arc_create()
 * @param feature_node
 *   Graph node representing feature. On success, feature_node is next_node of
 *   feature_arc->start_node
 * @param runs_after
 *   Add this feature_node after already added "runs_after". Creates
 *   start_node -> runs_after -> this_feature sequence
 * @param runs_before
 *  Add this feature_node before already added "runs_before". Creates
 *  start_node -> this_feature -> runs_before sequence
 *
 * <I> Must be called before rte_graph_create </I>
 *
 * @return
 *  0: Success
 * <0: Failure
 */
int dao_graph_feature_add(dao_graph_feature_arc_t _dfl, struct rte_node_register *feature_node,
			  const char *runs_after, const char *runs_before);

/**
 * Enable feature within a feature arc
 *
 * Must be called after @b rte_graph_create(). API is NOT Thread-safe
 *
 * @param _dfl
 *   Feature arc object returned by @ref dao_graph_feature_arc_create or @ref
 *   dao_graph_feature_arc_lookup_by_name
 * @param index
 *   Application specific index. Can be corresponding to interface_id/port_id etc
 * @param feature_name
 *   Name of the node which is already added via @ref dao_graph_feature_add
 * @param data
 *   Application specific data which is retrieved in fast path
 *
 * @return
 *  0: Success
 * <0: Failure
 */
int dao_graph_feature_enable(dao_graph_feature_arc_t _dfl, uint32_t index, const char *feature_name,
			     int64_t data);

/**
 * Validate whether subsequent enable/disable feature would succeed or not
 * API is thread-safe
 *
 * @param _dfl
 *   Feature arc object returned by @ref dao_graph_feature_arc_create or @ref
 *   dao_graph_feature_arc_lookup_by_name
 * @param index
 *   Application specific index. Can be corresponding to interface_id/port_id etc
 * @param feature_name
 *   Name of the node which is already added via @ref dao_graph_feature_add
 * @param is_enable_disable
 *   If 1, validate whether subsequent @ref dao_graph_feature_enable would pass or not
 *   If 0, validate whether subsequent @ref dao_graph_feature_disable would pass or not
 *
 * @return
 *  0: Subsequent enable/disable API would pass
 * <0: Subsequent enable/disable API would not pass
 */
int dao_graph_feature_validate(dao_graph_feature_arc_t _dfl, uint32_t index,
			       const char *feature_name, int is_enable_disable);

/**
 * Disable already enabled feature within a feature arc
 *
 * Must be called after @b rte_graph_create(). API is NOT Thread-safe
 *
 * @param _dfl
 *   Feature arc object returned by @ref dao_graph_feature_arc_create or @ref
 *   dao_graph_feature_arc_lookup_by_name
 * @param index
 *   Application specific index. Can be corresponding to interface_id/port_id etc
 * @param feature_name
 *   Name of the node which is already added via @ref dao_graph_feature_add
 *
 * @return
 *  0: Success
 * <0: Failure
 */
int dao_graph_feature_disable(dao_graph_feature_arc_t _dfl, uint32_t index,
			      const char *feature_name);

/**
 * Destroy Feature
 *
 * @param _dfl
 *   Feature arc object returned by @ref dao_graph_feature_arc_create or @ref
 *   dao_graph_feature_arc_lookup_by_name
 * @param feature_name
 *   Feature name provided to @ref dao_graph_feature_add
 *
 * @return
 *  0: Success
 * <0: Failure
 */
int dao_graph_feature_destroy(dao_graph_feature_arc_t _dfl, const char *feature_name);

/**
 * Delete feature_arc object
 *
 * @param _dfl
 *   Feature arc object returned by @ref dao_graph_feature_arc_create or @ref
 *   dao_graph_feature_arc_lookup_by_name
 *
 * @return
 *  0: Success
 * <0: Failure
 */
int dao_graph_feature_arc_destroy(dao_graph_feature_arc_t _dfl);

/**
 * Cleanup all feature arcs
 *
 * @return
 *  0: Success
 * <0: Failure
 */
int dao_graph_feature_arc_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif
