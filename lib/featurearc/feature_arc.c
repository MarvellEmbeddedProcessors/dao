/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */
#include <dao_log.h>
#include <dao_util.h>
#include <dao_graph_feature_arc_worker.h>
#include <rte_malloc.h>

#define graph_dbg dao_dbg
#define graph_err dao_err
#define SET_ERR_JMP DAO_ERR_GOTO

#define __DAO_GRAPH_FEATURE_ARC_MAX 32

#define dao_graph_uint_cast(x) ((unsigned int)x)

dao_graph_feature_arc_main_t *__feature_arc_main;

static int
feature_lookup(struct dao_graph_feature_arc *dfl, const char *feat_name,
	       struct dao_graph_feature_node_list **ffinfo, uint32_t *slot)
{
	struct dao_graph_feature_node_list *finfo = NULL;
	const char *name;

	if (!feat_name)
		return -1;

	if (slot)
		*slot = 0;

	STAILQ_FOREACH(finfo, &dfl->all_features, next_feature) {
		RTE_VERIFY(finfo->feature_arc == dfl);
		name = rte_node_id_to_name(finfo->feature_node->id);
		if (!strncmp(name, feat_name, RTE_GRAPH_NAMESIZE)) {
			if (ffinfo)
				*ffinfo = finfo;
			return 0;
		}
		if (slot)
			(*slot)++;
	}
	return -1;
}

static int
feature_arc_lookup(dao_graph_feature_arc_t _dfl)
{
	struct dao_graph_feature_arc *dfl = dao_graph_feature_arc_get(_dfl);
	dao_graph_feature_arc_main_t *dm = __feature_arc_main;
	uint32_t iter;

	if (!__feature_arc_main)
		return -1;

	for (iter = 0; iter < dm->max_feature_arcs; iter++) {
		if (dm->feature_arcs[iter] == DAO_GRAPH_FEATURE_ARC_INITIALIZER)
			continue;

		if (dfl == (dao_graph_feature_arc_get(dm->feature_arcs[iter])))
			return 0;
	}
	return -1;
}

static int
get_existing_edge(const char *arc_name, struct rte_node_register *parent_node,
		  struct rte_node_register *child_node, rte_edge_t *_edge)
{
	char **next_edges = NULL;
	uint32_t count, i;

	RTE_SET_USED(arc_name);

	count = rte_node_edge_get(parent_node->id, NULL);
	next_edges = malloc(count);

	if (!next_edges)
		return -1;

	count = rte_node_edge_get(parent_node->id, next_edges);
	for (i = 0; i < count; i++) {
		if (strstr(child_node->name, next_edges[i])) {
			graph_dbg("%s: Edge exists [%s[%u]: \"%s\"]", arc_name,
				  parent_node->name, i, child_node->name);
			if (_edge)
				*_edge = (rte_edge_t)i;

			free(next_edges);
			return 0;
		}
	}
	free(next_edges);

	return -1;
}

static int
connect_graph_nodes(struct rte_node_register *parent_node, struct rte_node_register *child_node,
		    rte_edge_t *_edge, char *arc_name)
{
	const char *next_node = NULL;
	rte_edge_t edge;

	if (!get_existing_edge(arc_name, parent_node, child_node, &edge)) {
		graph_dbg("%s: add_feature: Edge reused [%s[%u]: \"%s\"]", arc_name,
			  parent_node->name, edge, child_node->name);

		if (_edge)
			*_edge = edge;

		return 0;
	}

	/* Node to be added */
	next_node = child_node->name;

	edge = rte_node_edge_update(parent_node->id, RTE_EDGE_ID_INVALID, &next_node, 1);

	if (edge == RTE_EDGE_ID_INVALID) {
		graph_err("edge invalid");
		return -1;
	}
	edge = rte_node_edge_count(parent_node->id) - 1;

	graph_dbg("%s: add_feature: edge added [%s[%u]: \"%s\"]", arc_name, parent_node->name, edge,
		  child_node->name);

	if (_edge)
		*_edge = edge;

	return 0;
}

static int
feature_arc_init(dao_graph_feature_arc_main_t **pfl, uint32_t max_feature_arcs)
{
	dao_graph_feature_arc_main_t *pm = NULL;
	uint32_t i;
	size_t sz;

	if (!pfl)
		return -1;

	sz = sizeof(dao_graph_feature_arc_main_t) +
		(sizeof(pm->feature_arcs[0]) * max_feature_arcs);

	pm = malloc(sz);
	if (!pm)
		return -1;

	memset(pm, 0, sz);

	for (i = 0; i < max_feature_arcs; i++)
		pm->feature_arcs[i] = DAO_GRAPH_FEATURE_ARC_INITIALIZER;

	pm->max_feature_arcs = max_feature_arcs;

	*pfl = pm;

	return 0;
}

int
dao_graph_feature_arc_init(int max_feature_arcs)
{
	if (!max_feature_arcs)
		return -1;

	if (__feature_arc_main)
		return -1;

	return feature_arc_init(&__feature_arc_main, max_feature_arcs);
}

int
dao_graph_feature_arc_create(const char *feature_arc_name, int max_features, int max_indexes,
			     struct rte_node_register *start_node, dao_graph_feature_arc_t *_dfl)
{
	char name[2 * DAO_GRAPH_FEATURE_ARC_NAMELEN];
	dao_graph_feature_arc_main_t *dfm = NULL;
	struct dao_graph_feature_arc *dfl = NULL;
	struct dao_graph_feature_data *dfd = NULL;
	struct dao_graph_feature *df = NULL;
	uint32_t iter, j, arc_index;
	size_t sz;

	if (!_dfl)
		return -1;

	if (max_features < 1)
		return -1;

	if (!start_node)
		return -1;

	if (!feature_arc_name)
		return -1;

	if (max_features > DAO_GRAPH_FEATURE_MAX_PER_ARC) {
		graph_err("Invalid max features: %u", max_features);
		return -1;
	}

	/*
	 * Application hasn't called dao_graph_feature_arc_init(). Initialize with
	 * default values
	 */
	if (!__feature_arc_main) {
		if (dao_graph_feature_arc_init((int)__DAO_GRAPH_FEATURE_ARC_MAX) < 0) {
			graph_err("dao_graph_feature_arc_init() failed");
			return -1;
		}
	}

	dfm = __feature_arc_main;

	/* threshold check */
	if (dfm->num_feature_arcs > (dfm->max_feature_arcs - 1)) {
		graph_err("max threshold for num_feature_arcs: %d reached",
			  dfm->max_feature_arcs - 1);
		return -1;
	}
	/* Find the free slot for feature arc */
	for (iter = 0; iter < dfm->max_feature_arcs; iter++) {
		if (dfm->feature_arcs[iter] == DAO_GRAPH_FEATURE_ARC_INITIALIZER)
			break;
	}
	arc_index = iter;

	if (arc_index >= dfm->max_feature_arcs) {
		graph_err("No free slot found for num_feature_arc");
		return -1;
	}

	/* This should not happen */
	RTE_VERIFY(dfm->feature_arcs[arc_index] == DAO_GRAPH_FEATURE_ARC_INITIALIZER);

	sz = sizeof(*dfl) + (sizeof(uint64_t) * max_indexes);

	dfl = rte_malloc(feature_arc_name, sz, RTE_CACHE_LINE_SIZE);

	if (!dfl) {
		graph_err("malloc failed for feature_arc_create()");
		return -1;
	}

	memset(dfl, 0, sz);

	snprintf(name, sizeof(name), "%s-%s", feature_arc_name, "feat");

	dfl->features_by_index =
		rte_malloc(name, sizeof(struct dao_graph_feature) * max_indexes,
			   RTE_CACHE_LINE_SIZE);

	if (!dfl->features_by_index) {
		rte_free(dfl);
		graph_err("rte_malloc failed for allocating features_by_index()");
		return -ENOMEM;
	}
	memset(dfl->features_by_index, 0, sizeof(dao_graph_feature_t) * max_indexes);

	/* Initialize dao_graph port group fixed variables */
	STAILQ_INIT(&dfl->all_features);
	strncpy(dfl->feature_arc_name, feature_arc_name, DAO_GRAPH_FEATURE_ARC_NAMELEN - 1);
	dfl->feature_arc_main = (void *)dfm;
	dfl->start_node = start_node;
	dfl->max_features = max_features;
	dfl->max_indexes = max_indexes;

	for (iter = 0; iter < dfl->max_indexes; iter++) {
		df = dao_graph_feature_get(dfl, iter);
		for (j = 0; j < dfl->max_features; j++) {
			dfd = dao_graph_feature_data_get(df, j);
			dfd->feature_data_index = DAO_GRAPH_FEATURE_INVALID_VALUE;
		}
	}
	dfl->feature_arc_index = arc_index;
	dfm->feature_arcs[dfl->feature_arc_index] = (dao_graph_feature_arc_t)dfl;
	dfm->num_feature_arcs++;

	if (_dfl)
		*_dfl = (dao_graph_feature_arc_t)dfl;

	return 0;
}

int
dao_graph_feature_add(dao_graph_feature_arc_t _dfl, struct rte_node_register *feature_node,
		      const char *after_feature, const char *before_feature)
{
	struct dao_graph_feature_node_list *after_finfo = NULL, *before_finfo = NULL;
	struct dao_graph_feature_node_list *temp = NULL, *finfo = NULL;
	struct dao_graph_feature_arc *dfl = dao_graph_feature_arc_get(_dfl);
	uint32_t slot, add_flag;
	rte_edge_t edge = -1;

	RTE_VERIFY(dfl->feature_arc_main == __feature_arc_main);

	if (feature_arc_lookup(_dfl)) {
		graph_err("invalid feature arc: 0x%016" PRIx64, (uint64_t)_dfl);
		return -1;
	}

	if (dfl->runtime_enabled_features) {
		graph_err("adding features after enabling any one of them is not supported");
		return -1;
	}

	if ((after_feature != NULL) && (before_feature != NULL) &&
	    (after_feature == before_feature)) {
		graph_err("after_feature and before_feature are same '%s:%s]", after_feature,
			  before_feature);
		return -1;
	}

	if (!feature_node) {
		graph_err("feature_node: %p invalid", feature_node);
		return -1;
	}

	dfl = dao_graph_feature_arc_get(_dfl);

	if (feature_node->id == RTE_NODE_ID_INVALID) {
		graph_err("Invalid node: %s", feature_node->name);
		return -1;
	}

	if (!feature_lookup(dfl, feature_node->name, &finfo, &slot)) {
		graph_err("%s feature already added", feature_node->name);
		return -1;
	}

	if (slot >= DAO_GRAPH_FEATURE_MAX_PER_ARC) {
		graph_err("Max slot %u reached for feature addition", slot);
		return -1;
	}

	if (strstr(feature_node->name, dfl->start_node->name)) {
		graph_err("Feature %s cannot point to itself: %s", feature_node->name,
			  dfl->start_node->name);
		return -1;
	}

	if (connect_graph_nodes(dfl->start_node, feature_node, &edge, dfl->feature_arc_name)) {
		graph_err("unable to connect %s -> %s", dfl->start_node->name, feature_node->name);
		return -1;
	}

	finfo = malloc(sizeof(*finfo));
	if (!finfo)
		return -1;

	memset(finfo, 0, sizeof(*finfo));

	finfo->feature_arc = (void *)dfl;
	finfo->feature_node = feature_node;
	finfo->edge_to_this_feature = edge;

	/* Check for before and after constraints */
	if (before_feature) {
		/* before_feature sanity */
		if (feature_lookup(dfl, before_feature, &before_finfo, NULL))
			SET_ERR_JMP(EINVAL, finfo_free,
				    "Invalid before feature name: %s", before_feature);

		if (!before_finfo)
			SET_ERR_JMP(EINVAL, finfo_free,
				    "before_feature %s does not exist", before_feature);

		/*
		 * Starting from 0 to before_feature, continue connecting edges
		 */
		add_flag = 1;
		STAILQ_FOREACH(temp, &dfl->all_features, next_feature) {
			/*
			 * As soon as we see before_feature. stop adding edges
			 */
			if (!strncmp(temp->feature_node->name, before_feature,
				     RTE_GRAPH_NAMESIZE))
				if (!connect_graph_nodes(finfo->feature_node, temp->feature_node,
							 &edge, dfl->feature_arc_name))
					add_flag = 0;

			if (add_flag)
				connect_graph_nodes(temp->feature_node, finfo->feature_node, NULL,
						    dfl->feature_arc_name);
		}
	}

	if (after_feature) {
		if (feature_lookup(dfl, after_feature, &after_finfo, NULL))
			SET_ERR_JMP(EINVAL, finfo_free,
				    "Invalid after feature_name %s", after_feature);

		if (!after_finfo)
			SET_ERR_JMP(EINVAL, finfo_free,
				    "after_feature %s does not exist", after_feature);

		/* Starting from after_feature to end continue connecting edges */
		add_flag = 0;
		STAILQ_FOREACH(temp, &dfl->all_features, next_feature) {
			/* We have already seen after_feature now */
			if (add_flag)
				/* Add all features as next node to current feature*/
				connect_graph_nodes(finfo->feature_node, temp->feature_node, NULL,
						    dfl->feature_arc_name);

			/* as soon as we see after_feature. start adding edges
			 * from next iteration
			 */
			if (!strncmp(temp->feature_node->name, after_feature, RTE_GRAPH_NAMESIZE))
				/* connect after_feature to this feature */
				if (!connect_graph_nodes(temp->feature_node, finfo->feature_node,
							 &edge, dfl->feature_arc_name))
					add_flag = 1;
		}

		/* add feature next to after_feature */
		STAILQ_INSERT_AFTER(&dfl->all_features, after_finfo, finfo, next_feature);
	} else {
		if (before_finfo) {
			after_finfo = NULL;
			STAILQ_FOREACH(temp, &dfl->all_features, next_feature) {
				if (before_finfo == temp) {
					if (after_finfo)
						STAILQ_INSERT_AFTER(&dfl->all_features, after_finfo,
								    finfo, next_feature);
					else
						STAILQ_INSERT_HEAD(&dfl->all_features, finfo,
								   next_feature);

					return 0;
				}
				after_finfo = temp;
			}
		} else {
			STAILQ_INSERT_TAIL(&dfl->all_features, finfo, next_feature);
		}
	}

	return 0;

finfo_free:
	free(finfo);

	return -1;
}

int
dao_graph_feature_destroy(dao_graph_feature_arc_t _dfl, const char *feature_name)
{
	RTE_SET_USED(_dfl);
	RTE_SET_USED(feature_name);
	return 0;
}

int
dao_graph_feature_validate(dao_graph_feature_arc_t _dfl, uint32_t index, const char *feature_name,
			   int is_enable_disable)
{
	struct dao_graph_feature_arc *dfl = dao_graph_feature_arc_get(_dfl);
	struct dao_graph_feature_node_list *finfo = NULL;
	struct dao_graph_feature_data *dfd = NULL;
	struct dao_graph_feature *df = NULL;
	uint32_t slot;

	/* validate _dfl */
	if (dfl->feature_arc_main != __feature_arc_main) {
		graph_err("invalid feature arc: 0x%016" PRIx64, (uint64_t)_dfl);
		return -EINVAL;
	}

	/* validate index */
	if (index >= dfl->max_indexes) {
		graph_err("%s: Invalid provided index: %u >= %u configured", dfl->feature_arc_name,
			  index, dfl->max_indexes);
		return -1;
	}

	/* validate feature_name is already added or not  */
	if (feature_lookup(dfl, feature_name, &finfo, &slot)) {
		graph_err("%s: No feature %s added", dfl->feature_arc_name, feature_name);
		return -EINVAL;
	}

	if (!finfo) {
		graph_err("%s: No feature: %s found", dfl->feature_arc_name, feature_name);
		return -EINVAL;
	}

	/* slot should be in valid range */
	if (slot >= dfl->max_features) {
		graph_err("%s/%s: Invalid free slot %u(max=%u) for feature", dfl->feature_arc_name,
			  feature_name, slot, dfl->max_features);
		return -EINVAL;
	}

	df = dao_graph_feature_get(dfl, index);

	/* Exceeded all enabled features for index */
	if (is_enable_disable && (df->num_enabled_features >= dfl->max_features)) {
		graph_err("%s: Index: %u has already enabled all features(%d/%d)",
			  dfl->feature_arc_name, index,
			  df->num_enabled_features, dfl->max_features);
		return -EINVAL;
	}

	dfd = dao_graph_feature_data_get(df, slot);

	/* validate via bitmask if asked feature is already enabled on index */
	if (is_enable_disable && (dfl->feature_bit_mask_by_index[index] &
				  RTE_BIT64(slot))) {
		graph_err("%s: %s already enabled on index: %u",
			  dfl->feature_arc_name, feature_name, index);
		return -1;
	}

	if (!is_enable_disable && !(dfl->feature_bit_mask_by_index[index] & RTE_BIT64(slot))) {
		graph_err("%s: %s not enabled in bitmask for index: %u", dfl->feature_arc_name,
			  feature_name, index);
		return -1;
	}

	/* validate via feature data that feature_data not in use */
	if (is_enable_disable && (dfd->feature_data_index !=
				  DAO_GRAPH_FEATURE_INVALID_VALUE)) {
		graph_err("%s/%s: slot: %u already in use by %s",
			  dfl->feature_arc_name, feature_name, slot,
			  dfd->node_info->feature_node->name);
		return -1;
	}

	if (!is_enable_disable && (dfd->feature_data_index == DAO_GRAPH_FEATURE_INVALID_VALUE)) {
		graph_err("%s/%s: feature data slot: %u not in use ", dfl->feature_arc_name,
			  feature_name, slot);
		return -1;
	}
	return 0;
}

int
dao_graph_feature_enable(dao_graph_feature_arc_t _dfl, uint32_t index, const
			 char *feature_name, int64_t data)
{
	struct dao_graph_feature_data *dfd = NULL, *prev_dfd = NULL, *next_dfd = NULL;
	uint64_t original_mask, lower_feature_mask, upper_feature_mask;
	struct dao_graph_feature_arc *dfl = dao_graph_feature_arc_get(_dfl);
	struct dao_graph_feature_node_list *finfo = NULL;
	uint32_t slot, prev_feature, next_feature;
	struct dao_graph_feature *df = NULL;
	rte_edge_t edge = 0;
	int rc = 0;

	if (dao_graph_feature_validate(_dfl, index, feature_name, 1))
		return -1;

	if (feature_lookup(dfl, feature_name, &finfo, &slot))
		return -1;

	df = dao_graph_feature_get(dfl, index);
	dfd = dao_graph_feature_data_get(df, slot);

	graph_dbg("%s: Enabling feature %s in index: %u at slot %u", dfl->feature_arc_name,
		  feature_name, index, slot);

	memset(dfd, 0, sizeof(*dfd));

	/* app data */
	dfd->data = data;
	/* First fill invalid value until everything succeeds */
	dfd->feature_data_index = DAO_GRAPH_FEATURE_INVALID_VALUE;
	dfd->node_info = finfo;

	/* edge from base feature arc node to this feature */
	dfd->edge_to_this_feature = finfo->edge_to_this_feature;
	dfd->edge_to_next_feature = DAO_GRAPH_FEATURE_INVALID_VALUE;

	/* This should be the case */
	RTE_VERIFY(slot == (dfd - df->feature_data));

	/* Adjust next edge for previous enabled feature and next enabled
	 * feature for this index
	 */
	original_mask = dfl->feature_bit_mask_by_index[index];

	/* If slot == 0, no lower feature is enabled
	 * if slot = 1, lower_feature_mask = 0x1,
	 * if slot = 2, lower_feature_mask = 0x3,
	 * if slot = 3, lower_feature_mask = 0x7,
	 */
	lower_feature_mask = (slot) ? (RTE_BIT64(slot) - 1) : 0;

	/*
	 * If slot =0, upper_feature_mask = (0xff ff ff ff ff ff ff ff) & ~lower_feature_mask
	 * If slot =1, upper_feature_mask = (0xff ff ff ff ff ff ff fe) & ~lower_feature_mask
	 * If slot =2, upper_feature_mask = (0xff ff ff ff ff ff ff fc) & ~lower_feature_mask
	 * If slot =3, upper_feature_mask = (0xff ff ff ff ff ff ff f8) & ~lower_feature_mask
	 * If slot =4, upper_feature_mask = (0xff ff ff ff ff ff ff f0) & ~lower_feature_mask
	 */
	upper_feature_mask = ~(RTE_BIT64(slot)) & (~lower_feature_mask);

	/* And with original bit mask */
	upper_feature_mask &= original_mask;

	/* set bits lesser than slot */
	lower_feature_mask &= original_mask;

	/* immediate lower enabled feature wrt slot is most significant bit in
	 * lower_feature_mask
	 */
	prev_feature = rte_fls_u64(lower_feature_mask);

	if (prev_feature) {
		/* for us slot starts from 0 instead of 1 */
		prev_feature--;
		prev_dfd = dao_graph_feature_data_get(df, prev_feature);

		graph_dbg("%s: enabling for index: %u, %s[] = %s", dfl->feature_arc_name, index,
			  prev_dfd->node_info->feature_node->name,
			  dfd->node_info->feature_node->name);
		RTE_VERIFY(prev_dfd->feature_data_index != DAO_GRAPH_FEATURE_INVALID_VALUE);
		if (get_existing_edge(dfl->feature_arc_name, prev_dfd->node_info->feature_node,
				      dfd->node_info->feature_node, &edge)) {
			graph_err("%s: index: %u, Could not add next edge from %s to %s",
				  dfl->feature_arc_name, index,
				  prev_dfd->node_info->feature_node->name,
				  dfd->node_info->feature_node->name);
			rc = -1;
		} else {
			graph_dbg("%s: enabled for index: %u, slot %u, %s[%u] = %s",
				  dfl->feature_arc_name, index, slot,
				  prev_dfd->node_info->feature_node->name,
				  edge, dfd->node_info->feature_node->name);
			prev_dfd->edge_to_next_feature = edge;
		}
		if (rc < 0)
			return -1;
	}

	/* immediate next upper feature wrt slot is least significant bit in
	 * upper_feature_mask
	 */
	rc = 0;
	if (rte_bsf64_safe(upper_feature_mask, &next_feature)) {
		next_dfd = dao_graph_feature_data_get(df, next_feature);

		graph_dbg("%s: enabling for index: %u, %s[] = %s ", dfl->feature_arc_name, index,
			  dfd->node_info->feature_node->name,
			  next_dfd->node_info->feature_node->name);
		RTE_VERIFY(next_dfd->feature_data_index != DAO_GRAPH_FEATURE_INVALID_VALUE);
		if (get_existing_edge(dfl->feature_arc_name, dfd->node_info->feature_node,
				      next_dfd->node_info->feature_node, &edge)) {
			graph_err("%s: index: %u, Could not add next edge from %s to %s",
				  dfl->feature_arc_name, index,
				  dfd->node_info->feature_node->name,
				  next_dfd->node_info->feature_node->name);
			rc = -1;
		} else {
			graph_dbg("%s: enabled for index: %u, slot %u, %s[%u] = %s",
				  dfl->feature_arc_name, index, slot,
				  dfd->node_info->feature_node->name, edge,
				  next_dfd->node_info->feature_node->name);
			dfd->edge_to_next_feature = edge;
		}
		if (rc < 0)
			return -1;
	}

	graph_dbg("%s: enabled for index: %u, slot %u, %s[%u] = %s", dfl->feature_arc_name, index,
		  slot, dfl->start_node->name, dfd->edge_to_this_feature,
		  dfd->node_info->feature_node->name);

	/* Make dfd valid now */
	dfd->feature_data_index = dfd - df->feature_data;

	/* Increase feature node info reference count */
	finfo->ref_count++;

	/* Increment number of enabled feature on this index */
	df->num_enabled_features++;

	/* Make dao_graph_feature_add() disable for this feature arc now */
	dfl->runtime_enabled_features++;

	/* Update bitmask feature arc bit mask */
	rte_bit_relaxed_set64(dao_graph_uint_cast(slot), &dfl->feature_bit_mask_by_index[index]);

	/* Make sure changes made into affect */
	RTE_VERIFY(dfl->feature_bit_mask_by_index[index] & RTE_BIT64(slot));

	return 0;
}

int
dao_graph_feature_disable(dao_graph_feature_arc_t _dfl, uint32_t index, const char *feature_name)
{
	struct dao_graph_feature_data *dfd = NULL, *prev_dfd = NULL, *next_dfd = NULL;
	uint64_t original_mask, lower_feature_mask, upper_feature_mask;
	struct dao_graph_feature_arc *dfl = dao_graph_feature_arc_get(_dfl);
	struct dao_graph_feature_node_list *finfo = NULL;
	uint32_t slot, prev_feature, next_feature;
	struct dao_graph_feature *df = NULL;
	rte_edge_t edge = 0;
	int rc = 0;

	if (dao_graph_feature_validate(_dfl, index, feature_name, 0))
		return -1;

	if (feature_lookup(dfl, feature_name, &finfo, &slot))
		return -1;

	df = dao_graph_feature_get(dfl, index);
	dfd = dao_graph_feature_data_get(df, slot);

	/* This should be the case */
	RTE_VERIFY(slot == (dfd - df->feature_data));

	graph_dbg("%s: Disbling feature %s in index: %u at slot %u", dfl->feature_arc_name,
		  feature_name, index, slot);

	/* Adjust next edge for previous enabled feature and next enabled
	 * feature for this index
	 */
	original_mask = dfl->feature_bit_mask_by_index[index];

	lower_feature_mask = (slot) ? (RTE_BIT64(slot) - 1) : 0;
	upper_feature_mask = ~(RTE_BIT64(slot)) & (~lower_feature_mask);
	upper_feature_mask &= original_mask;
	lower_feature_mask &= original_mask;

	/* immediate lower enabled feature wrt slot is most significant bit in
	 * lower_feature_mask
	 */
	prev_feature = rte_fls_u64(lower_feature_mask);

	if (prev_feature) {
		/* for us slot starts from 0 instead of 1 */
		prev_feature--;
		prev_dfd = dao_graph_feature_data_get(df, prev_feature);

		/* Adjust later to next enabled feature below */
		prev_dfd->edge_to_next_feature = DAO_GRAPH_FEATURE_INVALID_VALUE;

		/* If we also have next enable feature */
		if (rte_bsf64_safe(upper_feature_mask, &next_feature)) {
			next_dfd = dao_graph_feature_data_get(df, next_feature);

			graph_dbg("%s: index: %u updating next enabled feature for %s to %s ",
				  dfl->feature_arc_name, index,
				  prev_dfd->node_info->feature_node->name,
				  next_dfd->node_info->feature_node->name);
			if (get_existing_edge(dfl->feature_arc_name,
					      prev_dfd->node_info->feature_node,
					      next_dfd->node_info->feature_node, &edge)) {
				graph_err("%s: index: %u, Could not get next edge from %s to %s",
					  dfl->feature_arc_name, index,
					  prev_dfd->node_info->feature_node->name,
					  next_dfd->node_info->feature_node->name);
				rc = -1;
			} else {
				graph_dbg("%s: index: %u updated next enable feature for %s to %s at edge %u",
					  dfl->feature_arc_name, index,
					  prev_dfd->node_info->feature_node->name,
					  next_dfd->node_info->feature_node->name, edge);
				prev_dfd->edge_to_next_feature = edge;
			}
			if (rc < 9)
				return -1;
		}
	}

	/* First fill invalid value until everything succeeds */
	dfd->feature_data_index = DAO_GRAPH_FEATURE_INVALID_VALUE;
	dfd->edge_to_this_feature = DAO_GRAPH_FEATURE_INVALID_VALUE;
	dfd->edge_to_next_feature = DAO_GRAPH_FEATURE_INVALID_VALUE;

	/* Decrease feature node info reference count */
	finfo->ref_count--;

	/* Decrement  number of enabled feature on this index */
	df->num_enabled_features++;

	/* Update bitmask feature arc bit mask */
	rte_bit_relaxed_clear64(dao_graph_uint_cast(slot), &dfl->feature_bit_mask_by_index[index]);

	return 0;
}

int
dao_graph_feature_arc_destroy(dao_graph_feature_arc_t epg)
{
	RTE_SET_USED(epg);
	return 0;
}

int
dao_graph_feature_arc_cleanup(void)
{
	dao_graph_feature_arc_main_t *dm = __feature_arc_main;
	uint32_t iter;

	if (!__feature_arc_main)
		return -1;

	for (iter = 0; iter < dm->max_feature_arcs; iter++) {
		if (dm->feature_arcs[iter] == DAO_GRAPH_FEATURE_ARC_INITIALIZER)
			continue;

		dao_graph_feature_arc_destroy((dao_graph_feature_arc_t)dm->feature_arcs[iter]);
	}

	return 0;
}

int
dao_graph_feature_arc_lookup_by_name(const char *arc_name, dao_graph_feature_arc_t *_dfl)
{
	dao_graph_feature_arc_main_t *dm = __feature_arc_main;
	struct dao_graph_feature_arc *dfl = NULL;
	uint32_t iter;

	if (!__feature_arc_main)
		return -1;

	for (iter = 0; iter < dm->max_feature_arcs; iter++) {
		if (dm->feature_arcs[iter] == DAO_GRAPH_FEATURE_ARC_INITIALIZER)
			continue;

		dfl = dao_graph_feature_arc_get(dm->feature_arcs[iter]);

		if (strstr(arc_name, dfl->feature_arc_name)) {
			if (_dfl)
				*_dfl = (dao_graph_feature_arc_t)dfl;
			return 0;
		}
	}

	return -1;
}
