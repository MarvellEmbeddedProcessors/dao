/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include "rdma_rss.h"
#include <errno.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <string.h>

/* Simple per-port RETA cache. Assumes a single process configuring the ports. */
struct rdma_rss_port_cache {
	uint16_t reta_size; /* number of entries in RETA */
	uint16_t *reta;     /* array of queue IDs of length reta_size */
	uint8_t valid;      /* set when cache populated */
};

static struct rdma_rss_port_cache g_rss_cache[RTE_MAX_ETHPORTS];

int
rdma_rss_cache_port(uint16_t portid)
{
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rss_reta_entry64 *reta_entries = NULL;
	struct rdma_rss_port_cache *pc;
	int rc = 0;

	if (portid >= RTE_MAX_ETHPORTS)
		return -EINVAL;

	pc = &g_rss_cache[portid];
	memset(&dev_info, 0, sizeof(dev_info));
	rc = rte_eth_dev_info_get(portid, &dev_info);
	if (rc)
		return rc;

	if (dev_info.reta_size == 0)
		return -ENOTSUP;

	/* Allocate or reallocate RETA buffer and plain array */
	if (pc->reta && pc->reta_size != dev_info.reta_size) {
		rte_free(pc->reta);
		pc->reta = NULL;
	}
	if (!pc->reta) {
		pc->reta = rte_zmalloc("rdma_rss_reta", dev_info.reta_size * sizeof(uint16_t), 0);
		if (!pc->reta)
			return -ENOMEM;
	}

	uint32_t n_entries = RTE_ALIGN_MUL_CEIL(dev_info.reta_size, RTE_ETH_RETA_GROUP_SIZE) /
			     RTE_ETH_RETA_GROUP_SIZE;
	reta_entries = rte_zmalloc("reta_entries", n_entries * sizeof(*reta_entries), 0);
	if (!reta_entries)
		return -ENOMEM;

	/* Set mask to request all entries */
	for (uint32_t i = 0; i < n_entries; i++)
		reta_entries[i].mask = ~0ULL;

	rc = rte_eth_dev_rss_reta_query(portid, reta_entries, dev_info.reta_size);
	if (rc) {
		rte_free(reta_entries);
		return rc;
	}

	/* Flatten to a simple array of queue ids */
	for (uint16_t i = 0; i < dev_info.reta_size; i++) {
		uint32_t grp = i / RTE_ETH_RETA_GROUP_SIZE;
		uint32_t off = i % RTE_ETH_RETA_GROUP_SIZE;

		pc->reta[i] = reta_entries[grp].reta[off];
	}

	pc->reta_size = dev_info.reta_size;
	pc->valid = 1;

	rte_free(reta_entries);
	return 0;
}

uint16_t
rdma_get_queue_id(uint32_t qp_id, uint8_t nb_queues, uint16_t port_id)
{
	uint32_t hash = 0;
	const uint8_t rss_key[48] = {0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67,
				     0x25, 0x3d, 0x2d, 0x8a, 0x60, 0x6d, 0x1e, 0x9f, 0x5e, 0x4f,
				     0x3b, 0x7d, 0x4b, 0x3c, 0x36, 0x9b, 0x1e, 0x69, 0x7f, 0x6a,
				     0x0c, 0x2e, 0x2f, 0x5c, 0x28, 0xf3, 0x4e, 0x2f, 0x2e, 0x66,
				     0x1a, 0x3b, 0x9c, 0x7e, 0x4d, 0x2a, 0x5f, 0x11};

	/* Compute same hash as HW */
	qp_id = qp_id << 8;
	hash = rte_softrss(&qp_id, 1, (uint8_t *)rss_key);

	if (g_rss_cache[port_id].valid && g_rss_cache[port_id].reta_size) {
		uint16_t idx = hash % g_rss_cache[port_id].reta_size;
		uint16_t q = g_rss_cache[port_id].reta[idx];

		dao_dbg("RDMA RSS: qp_id=%u, hash=%x -> RETA[%u]=q%u\n", qp_id >> 8, hash, idx, q);
		return q;
	}

	dao_dbg("RDMA RSS: qp_id=%u, hash=%x -> no RETA cache for port %u\n", qp_id >> 8, hash,
		port_id);
	return nb_queues ? (hash % nb_queues) : 0;
}
