/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "flow_gbl_priv.h"

/* Global definition */
struct flow_global_cfg *gbl_cfg;

struct dao_flow *
dao_flow_create(uint16_t port_id, const struct rte_flow_attr *attr,
		const struct rte_flow_item pattern[], const struct rte_flow_action actions[],
		struct rte_flow_error *error)
{
	struct acl_config_per_port *acl_cfg_prt;
	struct acl_rule_data *rule = NULL;
	struct acl_table *acl_tbl = NULL;
	struct dao_flow *flow = NULL;
	uint16_t tbl_id = 0;

	RTE_SET_USED(error);
	acl_cfg_prt = &gbl_cfg->acl_gbl->acl_cfg_prt[port_id];
	if (!acl_cfg_prt)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get per acl tables for port %d", port_id);

	acl_tbl = &acl_cfg_prt->acl_tbl[tbl_id];
	if (!acl_tbl)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get table for tbl_id %d, port id %d", tbl_id,
			     port_id);

	acl_tbl->port_id = port_id;
	rule = acl_create_rule(acl_tbl, attr, pattern, actions, error);
	if (!rule)
		DAO_ERR_GOTO(errno, fail, "Failed to create rule");

	flow = rte_zmalloc("dao_flow", sizeof(struct dao_flow), RTE_CACHE_LINE_SIZE);
	if (!flow)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory");

	flow->arule = rule;
	flow->port_id = port_id;
	flow->tbl_id = tbl_id;

	return flow;
fail:
	return NULL;
}

int
dao_flow_init(struct dao_flow_offload_config *config)
{
	int rc;

	RTE_SET_USED(config);
	/* Allocate global memory for storing all configurations and parameters */
	gbl_cfg = rte_zmalloc(FLOW_GBL_CFG_MZ_NAME, sizeof(struct flow_global_cfg),
			      RTE_CACHE_LINE_SIZE);
	if (!gbl_cfg)
		DAO_ERR_GOTO(-ENOMEM, error, "Failed to reserve mem for main_cfg");

	rc = acl_global_config_init(gbl_cfg);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to initialize acl ctx map");

	return 0;
fail:
	rte_free(gbl_cfg);
error:
	return errno;
}

int
dao_flow_fini(void)
{
	if (acl_global_config_fini(gbl_cfg))
		dao_err("Failed to cleanup ACL global config");

	rte_free(gbl_cfg);

	return 0;
}

int
dao_flow_lookup(uint16_t port_id, struct rte_mbuf **objs, uint16_t nb_objs)
{
	struct acl_config_per_port *acl_cfg_prt;
	struct acl_table *acl_tbl = NULL;
	uint16_t tbl_id = 0;
	int rc;

	acl_cfg_prt = &gbl_cfg->acl_gbl->acl_cfg_prt[port_id];
	if (!acl_cfg_prt)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get per acl tables for port %d", port_id);

	acl_tbl = &acl_cfg_prt->acl_tbl[tbl_id];
	if (!acl_tbl)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get table for tbl_id %d, port id %d", tbl_id,
			     port_id);

	rc = acl_flow_lookup(acl_tbl, objs, nb_objs);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to lookup for a flow");

	return 0;
fail:
	return errno;
}

int
dao_flow_destroy(uint16_t port_id, struct dao_flow *flow, struct rte_flow_error *error)
{
	struct acl_config_per_port *acl_cfg_prt;
	struct acl_table *acl_tbl = NULL;
	int rc;

	RTE_SET_USED(error);
	if (flow->port_id != port_id)
		DAO_ERR_GOTO(-EINVAL, fail, "Mismatch in Flow portid %d and passed portid %d",
			     flow->port_id, port_id);

	acl_cfg_prt = &gbl_cfg->acl_gbl->acl_cfg_prt[port_id];
	if (!acl_cfg_prt)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get per acl tables for port %d", port_id);

	acl_tbl = &acl_cfg_prt->acl_tbl[flow->tbl_id];
	if (!acl_tbl)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get table for tbl_id %d, port id %d",
			     flow->tbl_id, port_id);

	/* ACL Flow destroy */
	rc = acl_delete_rule(acl_tbl, flow->arule);
	if (rc)
		DAO_ERR_GOTO(-rc, fail, "Failed to delete flow");

	return 0;
fail:
	return errno;
}
