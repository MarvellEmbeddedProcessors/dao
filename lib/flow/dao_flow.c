/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <dao_util.h>

#include "flow_gbl_priv.h"

/* Global definition */
struct flow_global_cfg *gbl_cfg;

struct dao_flow *
dao_flow_create(uint16_t port_id, const struct rte_flow_attr *attr,
		const struct rte_flow_item pattern[], const struct rte_flow_action actions[],
		struct rte_flow_error *error)
{
	struct hw_offload_config_per_port *hw_off_cfg = NULL;
	struct flow_config_per_port *flow_cfg_prt;
	struct acl_config_per_port *acl_cfg_prt;
	struct hw_offload_flow *hflow = NULL;
	struct acl_rule_data *rule = NULL;
	struct acl_table *acl_tbl = NULL;
	struct flow_data *fdata = NULL;
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
	/* ACL userdata can establish as relation between acl and HW flow rule */
	flow->port_id = port_id;
	flow->tbl_id = tbl_id;

	/* If Hw offload enable, create rte_flow rules */
	if (gbl_cfg->hw_offload_enabled) {
		hw_off_cfg = &gbl_cfg->hw_off_gbl->hw_off_cfg[port_id];
		if (!hw_off_cfg)
			dao_err("Failed to get per HW off config for port %d", port_id);

		hw_off_cfg->port_id = port_id;
		hw_off_cfg->aging_tmo = gbl_cfg->aging_tmo;
		hflow = hw_offload_flow_reserve(hw_off_cfg, attr, pattern, actions, error);
		if (!hflow)
			dao_err("HW offload flow reserve failed");
		flow->hflow = hflow;
	}

	fdata = rte_zmalloc("flow_data", sizeof(struct flow_data), RTE_CACHE_LINE_SIZE);
	if (!fdata)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory");

	flow_cfg_prt = &gbl_cfg->flow_cfg[port_id];
	if (!flow_cfg_prt->list_initialized) {
		TAILQ_INIT(&flow_cfg_prt->flow_list);
		flow_cfg_prt->list_initialized = true;
		/* Synchronizing addition/deletion/lookup for flow rules */
		rte_spinlock_init(&flow_cfg_prt->flow_list_lock);
	}

	fdata->flow = flow;
	fdata->acl_rule_idx = rule->rule_idx;

	rte_spinlock_lock(&flow_cfg_prt->flow_list_lock);
	TAILQ_INSERT_TAIL(&flow_cfg_prt->flow_list, fdata, next);
	rte_spinlock_unlock(&flow_cfg_prt->flow_list_lock);

	dao_dbg("New DAO flow created %p - acl rule %p HW flow %p", flow, flow->arule, flow->hflow);

	return flow;
fail:
	return NULL;
}

int
dao_flow_init(struct dao_flow_offload_config *config)
{
	int rc;

	/* Allocate global memory for storing all configurations and parameters */
	gbl_cfg = rte_zmalloc(FLOW_GBL_CFG_MZ_NAME, sizeof(struct flow_global_cfg),
			      RTE_CACHE_LINE_SIZE);
	if (!gbl_cfg)
		DAO_ERR_GOTO(-ENOMEM, error, "Failed to reserve mem for main_cfg");

	rc = acl_global_config_init(gbl_cfg);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to initialize acl ctx map");

	rc = hw_offload_global_config_init(gbl_cfg);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to initialize hw offload global config");

	/* If user enabled HW offloading configuration */
	if (config->feature & DAO_FLOW_HW_OFFLOAD_ENABLE)
		gbl_cfg->hw_offload_enabled = true;

	/* If user provide timeout, else use DEFAULT aging timeout */
	gbl_cfg->aging_tmo = config->aging_tmo ? config->aging_tmo : FLOW_DEFAULT_AGING_TIMEOUT;

	return 0;
fail:
	rte_free(gbl_cfg);
error:
	return errno;
}

static int
flow_cleanup(struct flow_global_cfg *gbl_cfg)
{
	struct hw_offload_config_per_port *hw_off_cfg;
	struct flow_config_per_port *flow_cfg_prt;
	struct hw_offload_flow *hflow;
	struct flow_data *fdata;
	uint16_t port_id;
	void *tmp;

	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		flow_cfg_prt = &gbl_cfg->flow_cfg[port_id];
		rte_spinlock_lock(&flow_cfg_prt->flow_list_lock);
		DAO_TAILQ_FOREACH_SAFE(fdata, &flow_cfg_prt->flow_list, next, tmp) {
			dao_dbg("Removing flow rule %p, flow %p", fdata, fdata->flow);
			TAILQ_REMOVE(&flow_cfg_prt->flow_list, fdata, next);
			hflow = fdata->flow->hflow;
			rte_free(fdata->flow);
			rte_free(fdata);
			if (!hflow || hflow->offloaded)
				continue;
			hw_off_cfg = &gbl_cfg->hw_off_gbl->hw_off_cfg[port_id];
			if (hw_offload_flow_destroy(hw_off_cfg, hflow))
				dao_err("Failed to cleanup flow %p, port id %d", hflow, port_id);
		}
		rte_spinlock_unlock(&flow_cfg_prt->flow_list_lock);
	}
	return 0;
}

int
dao_flow_fini(void)
{
	if (flow_cleanup(gbl_cfg))
		dao_err("Failed to cleanup flows");

	if (acl_global_config_fini(gbl_cfg))
		dao_err("Failed to cleanup ACL global config");

	if (hw_offload_global_config_fini(gbl_cfg))
		dao_err("Failed to cleanup HW offload global config");

	rte_free(gbl_cfg);

	return 0;
}

static int
flow_install_hardware(struct flow_global_cfg *gbl_cfg, uint16_t port_id, uint32_t rule_idx)
{
	struct hw_offload_config_per_port *hw_off_cfg;
	struct flow_config_per_port *flow_cfg_prt;
	struct hw_offload_flow *hflow;
	struct flow_data *fdata;

	flow_cfg_prt = &gbl_cfg->flow_cfg[port_id];
	rte_spinlock_lock(&flow_cfg_prt->flow_list_lock);
	TAILQ_FOREACH(fdata, &flow_cfg_prt->flow_list, next) {
		if (fdata->acl_rule_idx == rule_idx) {
			hflow = fdata->flow->hflow;
			if (!hflow)
				DAO_ERR_GOTO(-EINVAL, fail, "HW offload flow not reserved, port %d",
					     port_id);
			if (hflow->offloaded) {
				rte_spinlock_unlock(&flow_cfg_prt->flow_list_lock);
				return 0;
			}
			hw_off_cfg = &gbl_cfg->hw_off_gbl->hw_off_cfg[port_id];
			if (hw_offload_flow_create(hw_off_cfg, hflow))
				DAO_ERR_GOTO(errno, fail, "Failed to create flow %p, port id %d",
					     hflow, port_id);
		}
	}
	rte_spinlock_unlock(&flow_cfg_prt->flow_list_lock);
	return 0;
fail:
	rte_spinlock_unlock(&flow_cfg_prt->flow_list_lock);
	return errno;
}

int
dao_flow_lookup(uint16_t port_id, struct rte_mbuf **objs, uint16_t nb_objs)
{
	struct acl_config_per_port *acl_cfg_prt;
	struct acl_table *acl_tbl = NULL;
	uint32_t result[nb_objs];
	uint16_t tbl_id = 0;
	int rc, i;

	acl_cfg_prt = &gbl_cfg->acl_gbl->acl_cfg_prt[port_id];
	if (!acl_cfg_prt)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get per acl tables for port %d", port_id);

	acl_tbl = &acl_cfg_prt->acl_tbl[tbl_id];
	if (!acl_tbl)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get table for tbl_id %d, port id %d", tbl_id,
			     port_id);

	rc = acl_flow_lookup(acl_tbl, objs, nb_objs, result);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to lookup for a flow");

	for (i = 0; i < nb_objs; i++) {
		if (result[i]) {
			rc = flow_install_hardware(gbl_cfg, port_id, result[i]);
			if (rc)
				dao_err("Failed to install the flow to HW");
		}
	}

	return 0;
fail:
	return errno;
}

int
dao_flow_destroy(uint16_t port_id, struct dao_flow *flow, struct rte_flow_error *error)
{
	struct hw_offload_config_per_port *hw_off_cfg;
	struct flow_config_per_port *flow_cfg_prt;
	struct acl_config_per_port *acl_cfg_prt;
	struct acl_table *acl_tbl = NULL;
	struct hw_offload_flow *hflow;
	struct acl_rule_data *arule;
	struct flow_data *fdata;
	void *tmp;
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

	arule = flow->arule;
	hflow = flow->hflow;
	flow_cfg_prt = &gbl_cfg->flow_cfg[port_id];
	rte_spinlock_lock(&flow_cfg_prt->flow_list_lock);
	DAO_TAILQ_FOREACH_SAFE(fdata, &flow_cfg_prt->flow_list, next, tmp) {
		if (flow == fdata->flow) {
			TAILQ_REMOVE(&flow_cfg_prt->flow_list, fdata, next);
			dao_dbg("Removing flow %p, acl rule %p hw flow %p", fdata->flow,
				fdata->flow->arule, fdata->flow->hflow);
			rte_free(fdata->flow);
			rte_free(fdata);
		}
	}
	rte_spinlock_unlock(&flow_cfg_prt->flow_list_lock);

	/* ACL Flow destroy */
	rc = acl_delete_rule(acl_tbl, arule);
	if (rc)
		DAO_ERR_GOTO(-rc, fail, "Failed to delete flow");

	hw_off_cfg = &gbl_cfg->hw_off_gbl->hw_off_cfg[port_id];
	rc = hw_offload_flow_destroy(hw_off_cfg, hflow);
	if (rc)
		DAO_ERR_GOTO(-rc, fail, "Failed to delete HW offloaded flow");

	return 0;
fail:
	return errno;
}
