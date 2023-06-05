/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <dao_port_group.h>
#include <dao_log.h>

#define PORT_GROUP_INITIALIZER        ((port_group_t *)(~0))

static void *__port_group_main;

/** Port group */
typedef struct port_group {
	RTE_MARKER cacheline0 __rte_cache_aligned;

	char port_group_name[DAO_PORT_GROUP_NAMELEN];

	/** this port group index in port_group_main */
	int port_group_index;

	/** Number of allocated elements in *ports_list */
	uint32_t max_ports_supported;

	/** Total allocated size for this structure */
	size_t total_alloc_size;

	/** Back pointer to port_group_main */
	void *port_group_main;

	/** Number of ports in this group */
	uint32_t num_ports;

	/** List of dao_ports in sequence */
	dao_port_t *ports_list;
} port_group_t;

/**
 * Port group main holding all port group info
 */
typedef struct port_group_main {
	/** Used number of port groups */
	uint32_t num_port_groups;

	/** Allocated number of elements in port_groups */
	uint32_t max_port_groups_supported;

	port_group_t *port_groups[];
} port_group_main_t;

static port_group_t *
port_group_get(dao_port_group_t epg)
{
	port_group_main_t *pm = __port_group_main;

	RTE_VERIFY(epg < pm->max_port_groups_supported);

	return(pm->port_groups[epg]);
}

static int
port_group_check_sanity(dao_port_group_t epg)
{
	port_group_main_t *pm = __port_group_main;
	port_group_t *pg = NULL;

	if (!pm)
		return -1;

	if (epg >= pm->max_port_groups_supported)
		return -1;

	if (epg >= pm->num_port_groups)
		return -1;

	pg = port_group_get(epg);

	if (pg->port_group_main != pm)
		return -1;

	return 0;
}

static int port_group_main_init(port_group_main_t **pgm, uint32_t num_port_groups)
{
	port_group_main_t *pm = NULL;
	uint32_t iter;
	size_t sz;

	if (!pgm)
		return -1;

	sz =  sizeof(port_group_main_t) + (sizeof(pm->port_groups[0]) * num_port_groups);

	pm = malloc(sz);
	if (!pm)
		return -1;

	memset(pm, 0, sz);

	pm->max_port_groups_supported = num_port_groups;

	for (iter = 0; iter < num_port_groups; iter++)
		pm->port_groups[iter] = PORT_GROUP_INITIALIZER;

	*pgm = pm;

	return 0;
}

/* TODO: static for now */
static int
dao_port_group_main_init(uint32_t num_port_groups)
{
	if (!num_port_groups)
		return -1;

	if (__port_group_main)
		return -1;

	return (port_group_main_init((port_group_main_t **)&__port_group_main, num_port_groups));
}

int dao_port_group_create(const char *group_name, uint32_t max_num_ports, dao_port_group_t *epg)
{
	port_group_main_t *pm = NULL;
	port_group_t *pg = NULL;
	uint32_t iter;
	size_t sz;

	if (!epg)
		return -1;

	if (max_num_ports < 1)
		return -1;

	if (!__port_group_main) {
		if (dao_port_group_main_init((uint32_t)DAO_PORT_GROUP_MAX) < 0) {
			dao_err("port_group_main_init() failed");
			return -1;
		}
	}
	pm = __port_group_main;

	/* threshold check */
	if (pm->num_port_groups == (pm->max_port_groups_supported - 1)) {
		dao_err("max threshold for num_port_groups: %d reached", pm->num_port_groups + 1);
		return -1;
	}

	sz = sizeof(port_group_t);

	pg = malloc(sz);

	if (!pg) {
		dao_err("malloc failed for port_group_create");
		return -1;
	}
	memset(pg, 0, sz);

	pg->ports_list = calloc(max_num_ports, sizeof(dao_port_t));

	if (!pg->ports_list) {
		free(pg);
		dao_err("ports_list alloc failed");
		return -1;
	}

	pg->port_group_index = pm->num_port_groups;
	pg->max_ports_supported = max_num_ports;
	pg->total_alloc_size = sz;
	pg->port_group_main = pm;

	if (group_name)
		strncpy(pg->port_group_name, group_name, DAO_PORT_GROUP_NAMELEN - 1);

	pm->port_groups[pg->port_group_index] = pg;

	/* Set default value */
	for (iter = 0; iter < max_num_ports; iter++)
		pg->ports_list[iter] = DAO_PORT_INVALID_VALUE;

	if (epg)
		*epg = pg->port_group_index;

	dao_dbg("Created port_group at Index: %u with supported ports: %u",
		pg->port_group_index, pg->max_ports_supported);

	pm->num_port_groups++;

	return 0;
}

int dao_port_group_port_add(dao_port_group_t epg, dao_port_t port, int32_t *returned_index)
{
	port_group_t *pg = NULL;
	uint32_t iter;

	if (port_group_check_sanity(epg) < 0) {
		dao_err("port_group sanity failed");
		return -1;
	}
	pg = port_group_get(epg);

	/* Overflow check */
	if (pg->num_ports > (pg->max_ports_supported - 1)) {
		dao_err("Reached max num_ports: %u (Limit: %u)", pg->num_ports,
			pg->max_ports_supported);
		return -1;
	}

	for (iter = 0; (iter < pg->max_ports_supported) && pg->ports_list[iter] != DAO_PORT_INVALID_VALUE; iter++)
		;

	if (iter >= pg->max_ports_supported) {
		dao_err("No valid port index found in %s. It's a bug", pg->port_group_name);
		return -1;
	}

	pg->ports_list[iter] = port;

	dao_dbg("Added port: %lu at index %u in port_group: %s", port, iter, pg->port_group_name);

	if (returned_index)
		*returned_index = (int32_t)iter;

	pg->num_ports++;

	return 0;
}

int
dao_port_group_port_get(dao_port_group_t _epg, int32_t port_index, dao_port_t *port)
{
	port_group_t *pg;

	if (!port)
		return -1;

	if (port_index < 0) {
		dao_err("Invalid port index: %d", port_index);
		return -1;
	}

	if (port_group_check_sanity(_epg) < 0) {
		dao_err("%u port group is not sane", (uint32_t)_epg);
		return -1;
	}
	pg = port_group_get(_epg);

	if (pg->ports_list[port_index] == DAO_PORT_INVALID_VALUE) {
		dao_err("Value not set at port index: %d", port_index);
		return -1;
	}

	if (port)
		*port = pg->ports_list[port_index];

	return 0;
}

int32_t
dao_port_group_port_get_next(dao_port_group_t _epg, dao_port_t *port, int32_t port_index)
{
	port_group_t *pg;
	int32_t iter;

	if (!port)
		return -1;

	/* Only -1 is valid (<0) for port_index */
	if (port_index < -1) {
		*port = DAO_PORT_INVALID_VALUE;
		return -1;
	}

	if (port_group_check_sanity(_epg) < 0) {
		dao_err("%u port group is not sane", (uint32_t)_epg);
		*port = DAO_PORT_INVALID_VALUE;
		return -1;
	}

	pg = port_group_get(_epg);

	/* Loop from port_index + 1 to num_ports */
	iter = port_index + 1;
	while (pg->max_ports_supported > (uint32_t)iter) {
		if (pg->ports_list[iter] == DAO_PORT_INVALID_VALUE) {
			iter++;
			continue;
		}
		break;
	}
	if (pg->max_ports_supported <= (uint32_t)iter)
		return -1;

	if (dao_port_group_port_get(_epg, iter, port) < 0) {
		*port = DAO_PORT_INVALID_VALUE;
		return -1;
	}
	dao_dbg("Found valid port_group: %lu at index: %d", (uint64_t)*port, iter);

	return iter;
}

int dao_port_group_port_get_num(dao_port_group_t epg, uint32_t *num_ports)
{
	port_group_t *pg = NULL;

	if (port_group_check_sanity(epg) < 0) {
		dao_err("port_group sanity failed");
		return -1;
	}

	pg = port_group_get(epg);

	if (num_ports)
		*num_ports = pg->num_ports;

	return 0;
}

int dao_port_group_port_delete(dao_port_group_t epg, int32_t port_index)
{
	port_group_t *pg = NULL;

	if (port_group_check_sanity(epg) < 0) {
		dao_err("port_group sanity failed");
		return -1;
	}

	pg = port_group_get(epg);

	if (port_index < 0)
		return -1;

	if (pg->num_ports <= (uint32_t)port_index)
		return -1;

	pg->ports_list[port_index] = DAO_PORT_INVALID_VALUE;

	pg->num_ports--;

	return 0;
}

int dao_port_group_destroy(dao_port_group_t _epg)
{
	port_group_main_t *pm = __port_group_main;
	uint32_t epg = (uint32_t)_epg;
	port_group_t *pg = NULL;

	if (port_group_check_sanity(epg) < 0) {
		dao_err("port_group sanity failed");
		return -1;
	}
	pg = port_group_get(epg);

	/* free ports list */
	if (pg->ports_list)
		free(pg->ports_list);

	pm->port_groups[pg->port_group_index] = PORT_GROUP_INITIALIZER;

	free(pg);

	return 0;
}

int dao_port_group_get_by_name(const char *port_group_name, dao_port_group_t *_dpg)
{
	port_group_main_t *dpm = __port_group_main;
	port_group_t *dpg = NULL;
	uint32_t iter;

	if (!__port_group_main) {
		dao_err("port_group_main not initialized");
		return -1;
	}

	if (!_dpg) {
		dao_err("_dpg cannot be null");
		return -1;
	}

	if (!port_group_name) {
		dao_err("matched name cannot be NUll");
		return -1;
	}

	for (iter = 0; iter < dpm->max_port_groups_supported; iter++) {
		if (dpm->port_groups[iter] == PORT_GROUP_INITIALIZER)
			continue;

		dpg = port_group_get((dao_port_group_t)iter);

		if (!strncmp(dpg->port_group_name, port_group_name, DAO_PORT_GROUP_NAMELEN)) {
			if (_dpg) {
				*_dpg = (dao_port_group_t)iter;
				return 0;
			}
		}
	}

	return -1;
}
