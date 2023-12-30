/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2024 Marvell International Ltd.
 */

#ifndef _DAO_GRAPH_FEATURE_ARC_WORKER_H_
#define _DAO_GRAPH_FEATURE_ARC_WORKER_H_

#include <stddef.h>
#include <stdalign.h>
#include <dao_graph_feature_arc.h>
#include <rte_bitops.h>

/**
 * @file
 *
 * dao_graph_feature_arc_worker.h
 *
 * Defines fast path structure
 */

#ifdef __cplusplus
extern "C" {
#endif

/** @internal
 *
 * Slow path feature node info list
 */
struct __rte_cache_aligned dao_graph_feature_node_list {
	/** Next feature */
	STAILQ_ENTRY(dao_graph_feature_node_list) next_feature;

	/** node representing feature */
	struct rte_node_register *feature_node;

	/** How many indexes/interfaces using this feature */
	int32_t ref_count;

	/** Back pointer to feature arc */
	void *feature_arc;

	/** rte_edge_t to this feature node from feature_arc->start_node */
	rte_edge_t edge_to_this_feature;
};

/**
 * DAO_GRAPH feature data representing a fast path feature object on an interface/index
 */
typedef struct dao_graph_feature_data {
	/** Data provided by application during @ref dao_graph_feature_enable on interface */
	int64_t data;

	/** this feature data index */
	uint32_t feature_data_index;

	/** Edge to this feature node from feature_arc->start_node */
	rte_edge_t edge_to_this_feature;

	/**
	 * Edge to next enabled feature on a given interface/index. This field
	 * keeps on changing as @ref dao_graph_feature_enable()/@ref
	 * dao_graph_feature_disable() are called on a given interface/index
	 */
	rte_edge_t edge_to_next_feature;

	/** Slow path node_info object */
	struct dao_graph_feature_node_list *node_info;
} dao_graph_feature_data_t;

/**
 * dao_graph feature object
 *
 * Holds all feature related data of a given feature on *all* interfaces
 */
struct __rte_cache_aligned dao_graph_feature {
	/**
	 * Slow path node_info
	 * 1st DWORD
	 */
	struct dao_graph_feature_node_list *node_info;

	/** Feature arc back pointer
	 *  2nd DWORD
	 */
	void *feature_arc;

	/**
	 * Number of enabled features in this feature_arc
	 * 3rd WORD
	 */
	uint32_t num_enabled_features;

	/* uint32_t reserved; */

	/**
	 * Array of feature_data by index/interface
	 *
	 */
	struct dao_graph_feature_data feature_data[DAO_GRAPH_FEATURE_MAX_PER_ARC];
};

/**
 * dao_graph feature arc object
 *
 * Representing a feature arc holding all features which are enabled/disabled on any interfaces
 */
struct __rte_cache_aligned dao_graph_feature_arc {
	/** All feature lists */
	STAILQ_HEAD(, dao_graph_feature_node_list) all_features;

	/** feature arc name */
	char feature_arc_name[DAO_GRAPH_FEATURE_ARC_NAMELEN];

	/** this feature group index in feature_arc_main */
	uint32_t feature_arc_index;

	/** Back pointer to feature_arc_main */
	void *feature_arc_main;

	/**
	 * Start_node or Base node where this feature arc is checked for any feature
	 */
	struct rte_node_register *start_node;

	/** Max features supported in this arc */
	uint32_t max_features;

	/** Max interfaces supported */
	uint32_t max_indexes;

	/* Fast path stuff*/
	alignas(RTE_CACHE_LINE_SIZE) RTE_MARKER cacheline1;
	/**
	 * Number of enabled features at runtime. Accessed in fast path via
	 * dao_graph_feature_arc_has_feature()
	 */
	int runtime_enabled_features;

	/** DAO_GRAPH feature by interface */
	struct dao_graph_feature *features_by_index;

	/** Bitmask by interface. Set bit indicates feature is enabled on interface */
	uint64_t feature_bit_mask_by_index[];
};

/** Feature arc main */
typedef struct feature_arc_main {
	/** number of feature arcs created by application */
	uint32_t num_feature_arcs;

	/** max features arcs allowed */
	uint32_t max_feature_arcs;

	/** feature arcs */
	dao_graph_feature_arc_t feature_arcs[];
} dao_graph_feature_arc_main_t;

/** @internal Get feature arc pointer from object */
#define dao_graph_feature_arc_get(dfl) ((struct dao_graph_feature_arc *)dfl)

extern dao_graph_feature_arc_main_t *__feature_arc_main;

/**
 * @internal
 */
static inline int
__bsf64_safe(uint64_t v, uint8_t *pos)
{
	if (v == 0)
		return 0;

	*pos = (uint8_t)rte_ctz64(v);
	return 1;
}

/**
 * Get dao_graph feature data object for a index in feature
 *
 * @param df
 *   Feature pointer
 * @param feature_index
 *  Index of feature maintained in slow path linked list
 *
 * @return
 *   Valid feature data
 */
static inline struct dao_graph_feature_data *
dao_graph_feature_data_get(struct dao_graph_feature *df, uint8_t feature_index)
{
	return (df->feature_data + feature_index);
}

/**
 * Get dao_graph_feature object for a given interface/index from feature arc
 *
 * @param dfl
 *   Feature arc pointer
 * @param index
 *   Interface index
 *
 * @return
 *   Valid feature pointer
 */
static inline struct dao_graph_feature *
dao_graph_feature_get(struct dao_graph_feature_arc *dfl, uint32_t index)
{
	return (dfl->features_by_index + index);
}

/**
 * Fast path API to check if first feature enabled on a feature arc
 *
 * Must be called in feature_arc->start_node processing
 *
 * @param dfl
 *   Feature arc object
 * @param index
 *   Interface/Index
 * @param[out] feature
 *   Pointer to dao_graph_feature_t. Valid if API returns 1
 *
 * @return
 * 1: If feature is enabled
 * 0: If feature is not enabled
 *
 */
static inline int
dao_graph_feature_arc_has_first_feature(struct dao_graph_feature_arc *dfl,
					uint32_t index, dao_graph_feature_t *feature)
{
	return __bsf64_safe(dfl->feature_bit_mask_by_index[index], feature);
}

/**
 * Fast path API to get next feature when current node is already on an feature
 * arc and not consuming packet. This feature must forward the packet to next
 * enabled feature by passing returned dao_graph_feature_t to
 * dao_graph_feature_arc_next_feature_data_get()
 *
 * @param dfl
 *   Feature arc object
 * @param index
 *   Interface/Index
 * @param[out] feature
 *   Pointer to dao_graph_feature_t. Valid if API returns 1
 *
 * @return
 * 1: If next feature is enabled
 * 0: If next feature is not enabled
 */
static inline int
dao_graph_feature_arc_has_next_feature(struct dao_graph_feature_arc *dfl,
				       uint32_t index, dao_graph_feature_t *feature)
{
	uint64_t bitmask;

#ifdef DAO_GRAPH_FEATURE_ARC_DEBUG
	struct dao_graph_feature *df = dao_graph_feature_get(dfl, index);
	struct dao_graph_feature_data *dfd = NULL;

	dfd = dao_graph_feature_data_get(df, *feature);
	/** Check feature sanity */
	if (unlikely(dfd->feature_data_index != *feature))
		return 0;
#endif

	/* Create bitmask where current feature is cleared to get next feature
	 * bit set
	 */
	bitmask = UINT64_MAX << (*feature + 1);
	bitmask = dfl->feature_bit_mask_by_index[index] & bitmask;

	return __bsf64_safe(bitmask, feature);
}

/**
 * Prefetch feature arc fast path cache line
 *
 * @param dfl
 *   DAO_GRAPH feature arc object
 * @param index
 *   Interface/index
 */
static inline void
dao_graph_feature_arc_prefetch(struct dao_graph_feature_arc *dfl, uint32_t index)
{
	rte_prefetch0((uint8_t *)dfl +
		      (offsetof(struct dao_graph_feature_arc, feature_bit_mask_by_index) +
		      (index * sizeof(uint64_t *))));
}

/**
 * Get number of enabled features in an arc
 *
 * @param arc
 *   DAO_GRAPH feature arc object
 */
static inline int
dao_graph_feature_arc_num_enabled_features(struct dao_graph_feature_arc *arc)
{
	return arc->runtime_enabled_features;
}

/**
 * Fast path API to check if any feature enabled on a feature arc
 *
 * @param dfl
 *   Feature arc object
 * @param index
 *   Interface/Index
 * @param[out] feature
 *   Pointer to dao_graph_feature_t. Valid if API returns 1
 *
 * @return
 * 1: If feature is enabled
 * 0: If feature is not enabled
 *
 */
static inline int
dao_graph_feature_arc_has_feature(struct dao_graph_feature_arc *dfl, uint32_t index,
				  dao_graph_feature_t *feature)
{
#ifdef DAO_GRAPH_FEATURE_ARC_DEBUG
	if (unlikely(dfl->max_indexes < index))
		return 0;

	if (unlikely(!feature))
		return 0;
#endif
	if (likely(!dfl->feature_bit_mask_by_index[index]))
		return 0;

	/* Look for first feature */
	if (*feature == DAO_GRAPH_FEATURE_INVALID_VALUE)
		return dao_graph_feature_arc_has_first_feature(dfl, index, feature);
	else
		return dao_graph_feature_arc_has_next_feature(dfl, index, feature);
}

/**
 * Prefetch feature data upfront
 *
 * @param dfl
 *   DAO_GRAPH feature arc object
 * @param index
 *   Interface/index
 * @param feature
 *   Pointer to feature object returned from @ref
 *   dao_graph_feature_arc_has_feature() or @ref
 *   dao_graph_feature_arc_first_feature_data_get()
 */
static inline void
__dao_graph_prefetch_data_prefetch(struct dao_graph_feature_arc *dfl, int index,
				   dao_graph_feature_t feature)
{
	struct dao_graph_feature *df = dao_graph_feature_get(dfl, index);

	rte_prefetch0((void *)dao_graph_feature_data_get(df, feature));
}

/**
 * Prefetch feature data upfront. Perform sanity
 *
 * @param dfl
 *   DAO_GRAPH feature arc object
 * @param index
 *   Interface/index
 * @param feature
 *   Pointer to feature object returned from @ref
 *   dao_graph_feature_arc_has_feature() or @ref
 *   dao_graph_feature_arc_first_feature_data_get()
 */
static inline void
dao_graph_feature_data_prefetch(struct dao_graph_feature_arc *dfl, uint32_t index,
				dao_graph_feature_t feature)
{
#ifdef DAO_GRAPH_FEATURE_ARC_DEBUG
	if (unlikely(index >= dfl->max_indexes))
		return;

	if (unlikely(feature >= dao_graph_feature_cast(dfl->max_features)))
		return;
#endif
	if (feature != DAO_GRAPH_FEATURE_INVALID_VALUE)
		__dao_graph_prefetch_data_prefetch(dfl, index, feature);
}

/**
 * Fast path API to get first feature data aka {edge, int32_t data}
 *
 * Must be called in feature_arc->start_node processing
 *
 * @param dfl
 *   Feature arc object
 * @param feature
 *  returned from dao_graph_feature_arc_has_feature()
 * @param index
 *   Interface/Index
 * @param[out] edge
 *   Pointer to rte_node edge. Valid if API returns Success
 * @param[out] data
 *   Pointer to int64_t data set via dao_graph_feature_enable(). Valid if API returns
 *   Success
 *
 * @return
 *  0: Success
 * <0: Failure
 */
static inline int
dao_graph_feature_arc_first_feature_data_get(struct dao_graph_feature_arc *dfl,
					     dao_graph_feature_t feature,
					     uint32_t index, rte_edge_t *edge,
					     int64_t *data)
{
	struct dao_graph_feature *df = dao_graph_feature_get(dfl, index);
	struct dao_graph_feature_data *dfd = NULL;

	dfd = dao_graph_feature_data_get(df, feature);

#ifdef DAO_GRAPH_FEATURE_ARC_DEBUG
	/** Check feature sanity */
	if (unlikely(dfd->feature_data_index != feature))
		return -1;

	if (unlikely(!edge && !data))
		return -1;
#endif

	*edge = dfd->edge_to_this_feature;
	*data = dfd->data;

	return 0;
}

/**
 * Fast path API to get next feature data aka {edge, int32_t data}
 *
 * Must NOT be called in feature_arc->start_node processing instead must be
 * called in intermediate feature nodes on a featur-arc.
 *
 * @param dfl
 *   Feature arc object
 * @param feature
 *  returned from dao_graph_feature_arc_has_next_feature()
 * @param index
 *   Interface/Index
 * @param[out] edge
 *   Pointer to rte_node edge. Valid if API returns Success
 * @param[out] data
 *   Pointer to int64_t data set via dao_graph_feature_enable(). Valid if API returns
 *   Success
 *
 * @return
 *  0: Success
 * <0: Failure
 */
static inline int
dao_graph_feature_arc_next_feature_data_get(struct dao_graph_feature_arc *dfl,
					    dao_graph_feature_t feature,
					    uint32_t index, rte_edge_t *edge,
					    int64_t *data)
{
	struct dao_graph_feature *df = dao_graph_feature_get(dfl, index);
	struct dao_graph_feature_data *dfd = NULL;

	dfd = dao_graph_feature_data_get(df, feature);

#ifdef DAO_GRAPH_FEATURE_ARC_DEBUG
	/** Check feature sanity */
	if (unlikely(dfd->feature_data_index != feature))
		return -1;

	if (unlikely(!edge && !data))
		return -1;
#endif

	*edge = dfd->edge_to_next_feature;
	*data = dfd->data;

	return 0;
}

/**
 * Fast path API to get next feature data aka {edge, int32_t data}
 *
 * @param dfl
 *   Feature arc object
 * @param feature
 *  returned from dao_graph_feature_arc_has_feature()
 * @param index
 *   Interface/Index
 * @param[out] edge
 *   Pointer to rte_node edge. Valid if API returns Success
 * @param[out] data
 *   Pointer to int64_t data set via dao_graph_feature_enable(). Valid if API returns
 *   Success
 *
 * @return
 *  0: Success
 * <0: Failure
 */
static inline int
dao_graph_feature_arc_feature_data_get(struct dao_graph_feature_arc *dfl,
				       dao_graph_feature_t feature,
				       uint32_t index, rte_edge_t *edge,
				       int64_t *data)
{
	if (feature == DAO_GRAPH_FEATURE_INVALID_VALUE)
		return dao_graph_feature_arc_first_feature_data_get(dfl, feature, index, edge,
								    data);
	else
		return dao_graph_feature_arc_next_feature_data_get(dfl, feature, index, edge, data);
}

#ifdef __cplusplus
}
#endif
#endif
