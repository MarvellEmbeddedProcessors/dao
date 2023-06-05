/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <dao_portq_group_worker.h>
#include <dao_log.h>

#define __DAO_PORTQ_GROUP_MAX           8
#define DAO_PORTQ_GROUP_INVALID_VALUE   ((struct dao_portq_group *)(~0))

dao_portq_group_main_t *__portq_group_main;

static inline int
portq_group_check_sanity(dao_portq_group_t epg)
{
	dao_portq_group_main_t *pm = __portq_group_main;
	struct dao_portq_group *pg = NULL;

	if (!pm)
		return -1;

	if (epg >= pm->max_portq_groups_supported)
		return -1;

	if (epg >= pm->num_portq_groups)
		return -1;

	pg = dao_portq_group_get(epg);

	if (pg->portq_group_main != pm)
		return -1;

	return 0;
}

static int
portq_group_main_init(dao_portq_group_main_t **pgm, uint32_t num_portq_groups)
{
	dao_portq_group_main_t *pm = NULL;
	uint32_t i;
	size_t sz;

	if (!pgm)
		return -1;

	sz =  sizeof(dao_portq_group_main_t) + (sizeof(pm->portq_groups[0]) * num_portq_groups);

	pm = malloc(sz);
	if (!pm)
		return -1;

	memset(pm, 0, sz);

	for (i = 0; i < num_portq_groups; i++)
		pm->portq_groups[i] = DAO_PORTQ_GROUP_INVALID_VALUE;

	pm->max_portq_groups_supported = num_portq_groups;

	*pgm = pm;

	return 0;
}

int
dao_portq_group_init(uint32_t num_portq_groups)
{
	if (!num_portq_groups)
		return -1;

	if (__portq_group_main)
		return -1;

	return (portq_group_main_init(
		(dao_portq_group_main_t **)&__portq_group_main, num_portq_groups));
}

int
dao_portq_group_create(const char *portq_name, uint32_t num_cores, uint32_t
			num_portqs, dao_portq_group_t *_epg)
{
	dao_portq_group_main_t *epm = NULL;
	struct dao_portq_group *epg = NULL;
	dao_portq_list_t *epl = NULL;
	size_t sz, per_core_sz;
	uint32_t iter, j;

	if (!_epg)
		return -1;

	if (num_cores < 1)
		return -1;

	if (num_portqs < 1)
		return -1;

	/*
	 * Application hasn't called dao_portq_group_main_init(). Initialize with
	 * default values
	 */
	if (!__portq_group_main) {
		if (dao_portq_group_init((uint32_t)__DAO_PORTQ_GROUP_MAX) < 0) {
			dao_err("dao_portq_group_main_init() failed");
			return -1;
		}
	}

	epm = __portq_group_main;

	/* threshold check */
	if (epm->num_portq_groups > (epm->max_portq_groups_supported - 1)) {
		dao_err("max threshold for num_portq_groups: %d reached",
			epm->num_portq_groups + 1);
		return -1;
	}

	/* Allocate dao_portq_group object with num_cores */
	per_core_sz = sizeof(dao_portq_list_t) + (sizeof(dao_portq_t) * num_portqs);
	per_core_sz = DAO_ROUNDUP(per_core_sz, RTE_CACHE_LINE_SIZE);

	sz = sizeof(struct dao_portq_group) + (per_core_sz * num_cores);

	epg = malloc(sz);

	if (!epg)
		DAO_ERR_GOTO(-ENOMEM, portq_group_alloc_fail, "malloc failed for portq_group_create");

	memset(epg, 0, sz);

	/* Initialize dao port group fixed variables */
	epg->num_cores = num_cores;
	if (portq_name)
		strncpy(epg->portq_group_name, portq_name, DAO_PORTQ_GROUP_NAMELEN - 1);
	epg->per_core_portq_list_size = per_core_sz;
	epg->portq_group_main = (void *)epm;

	for (iter = 0; iter < epm->max_portq_groups_supported; iter++) {
		if (epm->portq_groups[iter] == DAO_PORTQ_GROUP_INVALID_VALUE)
			break;
	}
	RTE_VERIFY(epm->portq_groups[iter] == DAO_PORTQ_GROUP_INVALID_VALUE);
	epg->portq_group_index = iter;
	epm->portq_groups[epg->portq_group_index] = epg;

	/* Add default invalid value for all ports in dao_portq for each core */
	for (iter = 0; iter < num_cores; iter++) {
		epl = __dao_portq_group_list_get(epg, iter);
		epl->max_portqs_supported = num_portqs;
		for (j = 0; j < epl->max_portqs_supported; j++)
			epl->portqs[j].port_id = DAO_PORTQ_INVALID_VALUE;
	}
	epm->num_portq_groups++;

	*_epg = (dao_portq_group_t)epg->portq_group_index;

	return 0;

portq_group_alloc_fail:
	return -1;
}

int dao_portq_group_portq_add(dao_portq_group_t _epg, uint32_t core_id,
			      dao_portq_t *portq, int32_t *returned_index)
{
	struct dao_portq_group *epg = NULL;
	dao_portq_list_t *epl = NULL;
	uint32_t iter = 0;

	if (!portq) {
		dao_err("null portq");
		return -1;
	}

	if (portq_group_check_sanity(_epg) < 0) {
		dao_err("portq group sanity failed: %u", _epg);
		return -1;
	}
	epg = dao_portq_group_get(_epg);

	if (core_id >= epg->num_cores) {
		dao_err("invalid core_id: %u > threshold: %u", core_id, epg->num_cores - 1);
		return -1;
	}

	epl = __dao_portq_group_list_get(epg, core_id);

	if (epl->num_portqs > epl->max_portqs_supported - 1) {
		dao_err("threshold reached for core_id: %u, num_portqs: %u, max: %u",
			core_id, epl->num_portqs, epl->max_portqs_supported);
		return -1;
	}

	for (iter = 0; iter < epl->max_portqs_supported; iter++) {
		if (epl->portqs[iter].port_id == DAO_PORTQ_INVALID_VALUE) {
			epl->portqs[iter].port_id = portq->port_id;
			epl->portqs[iter].rq_id = portq->rq_id;
			epl->num_portqs++;

			if (returned_index)
				*returned_index = iter;

			return 0;
		}
	}

	return -1;
}

int dao_portq_group_get_by_name(const char *portq_name, dao_portq_group_t *_dpg)
{
	dao_portq_group_main_t *dpm = __portq_group_main;
	struct dao_portq_group *dpg = NULL;
	uint32_t iter;

	if (!__portq_group_main) {
		dao_err("portq_group_main not initialized");
		return -1;
	}

	if (!_dpg) {
		dao_err("_dpg cannot be null");
		return -1;
	}

	if (!portq_name) {
		dao_err("matched name cannot be NUll");
		return -1;
	}

	for (iter = 0; iter < dpm->max_portq_groups_supported; iter++) {
		if (dpm->portq_groups[iter] == DAO_PORTQ_GROUP_INVALID_VALUE)
			continue;

		dpg = dao_portq_group_get((dao_portq_group_t)iter);

		if (!strncmp(dpg->portq_group_name, portq_name, DAO_PORTQ_GROUP_NAMELEN)) {
			if (_dpg) {
				*_dpg = (dao_portq_group_t)iter;
				return 0;
			}
		}
	}

	return -1;
}
