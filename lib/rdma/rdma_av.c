/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <dao_log.h>

#include "rdma_av.h"
#include "rdma_port_priv.h"
#include "rdma_priv.h"

extern rcu_cb_t rcu_cb;

const struct rdma_av *
rdma_av_get(uint8_t port_num, uint16_t index)
{
	struct rdma_port *port;
	rdma_av_t *av;

	if (index >= RDMA_ADDR_VEC_MAX)
		return NULL;

	port = rdma_port_lookup(port_num);
	if (port == NULL) {
		return NULL;
	}

	av = port->av[index];

	return av;
}

int
rdma_av_insert(void *av_data)
{
	struct rdma_av *avd = (struct rdma_av *)av_data;
	struct rdma_port *port;
	struct rdma_av *av;

	if (avd->index >= RDMA_ADDR_VEC_MAX)
		return -1;

	if (!avd->sgid_addr.ip4)
		return -1;

	port = rdma_port_lookup(avd->port_num);
	if (port == NULL) {
		dao_err("AV -- Invalid RDMA port number for lookup");
		return -1;
	}

	av = port->av[avd->index];
	if (av) {
		dao_err("AV id: %u already exist", avd->index);
		return -1;
	}

	av = (struct rdma_av *)rte_zmalloc("rdma_av", sizeof(struct rdma_av), 0);
	if (av == NULL) {
		dao_err("Error assigning mem for AH index %d\n", avd->index);
		return -1;
	}

	memcpy(av, avd, sizeof(struct rdma_av));
	av->iph.ip_id = rte_rand() % 0xffff;

	dao_dbg("AV inserted: port_num %d index %u", av->port_num, av->index);
	port->av[avd->index] = av;

	return 0;
}

int
rdma_av_remove(void *av_data)
{
	struct rdma_av *avd = (struct rdma_av *)av_data;
	struct rdma_port *port;
	struct rdma_av *av;

	if (avd->index >= RDMA_ADDR_VEC_MAX)
		return -1;

	port = rdma_port_lookup(avd->port_num);
	if (port == NULL) {
		dao_err("AV -- Invalid RDMA port number for lookup");
		return -1;
	}

	av = port->av[avd->index];
	/* XXX: set the timer thread to cleanup on refcnt == 0. */
	if (!av) {
		dao_err("AV at index %u is NULL; already removed or never inserted", avd->index);
		return -1;
	}
	port->av[avd->index] = NULL;

	if (rcu_cb)
		rcu_cb();
	else
		rte_free(av);

	return 0;
}

int
rdma_av_init(uint64_t **av, uint32_t num_av)
{
	uint32_t av_count = num_av;
	uint32_t i;

	if (av_count == 0)
		av_count = RDMA_ADDR_VEC_MAX;

	for (i = 0; i < av_count; i++) {
		av[i] = rte_zmalloc("rdma_av", sizeof(rdma_av_t), 0);
		if (av[i] == NULL) {
			dao_err("Failed to allocate memory for AV");
			return -1;
		}

		memset(av[i], 0, sizeof(rdma_av_t));
	}

	return 0;
}

int
rdma_av_free(struct rdma_av **av)
{
	uint32_t i;

	/* We are here means the system is going down or the interface is getting deleted.
	 * Freeup the memory without checking the refcnt.
	 */
	for (i = 0; i < RDMA_ADDR_VEC_MAX; i++) {
		if (av[i]) {
			rte_free(av[i]);
			av[i] = NULL;
		}
	}

	return 0;
}
