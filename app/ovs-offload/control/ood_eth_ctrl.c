/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <stdint.h>

#include <rte_malloc.h>

#include <dao_log.h>

#include <ood_ctrl_chan.h>
#include <ood_eth_ctrl.h>

int
ood_set_mac_address(uint16_t rep_portid, uint8_t *mac_addr)
{
	representor_mapping_t *rep_map;
	struct rte_ether_addr addr;
	int rc = 0;

	/* Get the flow ctrl structure */
	rep_map = ood_representor_mapping_get(rep_portid);
	if (!rep_map)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get valid representor port map for %d",
			     rep_portid);

	dao_dbg("Representor portid %d mac portid %d", rep_portid, rep_map->mac_port);

	rte_memcpy(&addr.addr_bytes, mac_addr, RTE_ETHER_ADDR_LEN);
	rc = rte_eth_dev_default_mac_addr_set(rep_map->mac_port, &addr);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Set MAC failed for rep port %d mac port %d, err %d",
			     rep_portid, rep_map->mac_port, rc);

	return 0;
fail:
	return rc;
}

int
ood_eth_stats_get_clear(uint16_t rep_portid, ood_msg_t msg, ood_msg_ack_data_t *adata)
{
	representor_mapping_t *rep_map;
	struct rte_eth_stats stats;
	int rc = 0, sz;

	/* Get the flow ctrl structure */
	rep_map = ood_representor_mapping_get(rep_portid);
	if (!rep_map)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get valid representor port map for %d",
			     rep_portid);

	dao_dbg("Representor portid %d host portid %d", rep_portid, rep_map->host_port);

	switch (msg) {
	case OOD_MSG_ETH_STATS_GET:
		rc = rte_eth_stats_get(rep_map->host_port, &stats);
		if (rc)
			DAO_ERR_GOTO(rc, fail,
				     "Failed to get eth stats rep port %d host port %d, err %d",
				     rep_portid, rep_map->host_port, rc);

		/* Return stats as part of adata */
		sz = sizeof(struct rte_eth_stats);
		dao_dbg("Stats for host port %d of size %d, stats.ipackets %ld stats.opackets %ld",
			rep_map->host_port, sz, stats.ipackets, stats.opackets);
		adata->u.data = rte_zmalloc("Ack Data", sz, 0);
		rte_memcpy(adata->u.data, &stats, sz);
		adata->size = sz;

		break;
	case OOD_MSG_ETH_STATS_CLEAR:
		rc = rte_eth_stats_reset(rep_map->host_port);
		if (rc)
			DAO_ERR_GOTO(rc, fail,
				     "Failed to reset eth stats rep port %d host port %d, err %d",
				     rep_portid, rep_map->host_port, rc);
		/* Return success */
		adata->u.sval = rc;
		adata->size = sizeof(uint64_t);
		break;
	default:
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid message type %d", msg);
		break;
	};

	return 0;
fail:
	adata->u.sval = rc;
	adata->size = sizeof(uint64_t);
	return rc;
}
