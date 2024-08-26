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

	rule->tbl_id = tbl_id;
	acl_cfg_prt->num_rules_per_prt++;
	flow = rte_zmalloc("dao_flow", sizeof(struct dao_flow), RTE_CACHE_LINE_SIZE);
	if (!flow)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory");

	flow->arule = rule;
	/* ACL userdata can establish as relation between acl and HW flow rule */
	flow->port_id = port_id;
	flow->tbl_id = tbl_id;

	/* If Hw offload enable, create rte_flow rules */
	if (gbl_cfg->flow_cfg[port_id].hw_offload_enabled) {
		hw_off_cfg = &gbl_cfg->hw_off_gbl->hw_off_cfg[port_id];
		if (!hw_off_cfg)
			dao_err("Failed to get per HW off config for port %d", port_id);

		hw_off_cfg->port_id = port_id;
		hw_off_cfg->aging_tmo_sec = gbl_cfg->flow_cfg[port_id].aging_tmo_sec;
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
	flow_cfg_prt->num_flows++;
	TAILQ_INSERT_TAIL(&flow_cfg_prt->flow_list, fdata, next);
	rte_spinlock_unlock(&flow_cfg_prt->flow_list_lock);

	dao_dbg("New DAO flow created %p - acl rule %p HW flow %p", flow, flow->arule, flow->hflow);

	return flow;
fail:
	return NULL;
}

struct dao_flow *
dao_flow_install_hardware(uint16_t port_id, const struct rte_flow_attr *attr,
			  const struct rte_flow_item pattern[],
			  const struct rte_flow_action actions[], struct rte_flow_error *error)
{
	struct hw_offload_config_per_port *hw_off_cfg = NULL;
	struct flow_config_per_port *flow_cfg_prt;
	struct hw_offload_flow *hflow = NULL;
	struct flow_data *fdata = NULL;
	struct dao_flow *flow = NULL;

	if (!gbl_cfg->flow_cfg[port_id].hw_offload_enabled)
		DAO_ERR_GOTO(-EINVAL, fail, "HW offload not enabled");

	flow = rte_zmalloc("dao_flow", sizeof(struct dao_flow), RTE_CACHE_LINE_SIZE);
	if (!flow)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory");

	hw_off_cfg = &gbl_cfg->hw_off_gbl->hw_off_cfg[port_id];
	if (!hw_off_cfg)
		dao_err("Failed to get per HW off config for port %d", port_id);

	hw_off_cfg->port_id = port_id;
	hw_off_cfg->aging_tmo_sec = gbl_cfg->flow_cfg[port_id].aging_tmo_sec;
	hflow = hw_offload_flow_install(hw_off_cfg, attr, pattern, actions, error);
	if (!hflow)
		dao_err("HW offload flow reserve failed");

	flow->hflow = hflow;

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
	rte_spinlock_lock(&flow_cfg_prt->flow_list_lock);
	flow_cfg_prt->num_flows++;
	TAILQ_INSERT_TAIL(&flow_cfg_prt->flow_list, fdata, next);
	rte_spinlock_unlock(&flow_cfg_prt->flow_list_lock);

	dao_dbg("New DAO flow created %p - HW flow %p viz directly installed in hardware", flow,
		flow->hflow);

	return flow;
fail:
	return NULL;
}

static void
parse_profile_setup(uint16_t port_id, struct flow_global_cfg *gbl_cfg,
		    struct dao_flow_offload_config *config)
{
	if (strncmp(config->parse_profile, "ovs", DAO_FLOW_PROFILE_NAME_MAX) == 0) {
		gbl_cfg->flow_cfg[port_id].prfl_ops = &ovs_prfl_ops;
		gbl_cfg->flow_cfg[port_id].parse_prfl = &ovs_kex_profile;
	} else if (strncmp(config->parse_profile, "default", DAO_FLOW_PROFILE_NAME_MAX) == 0) {
		gbl_cfg->flow_cfg[port_id].prfl_ops = &default_prfl_ops;
		gbl_cfg->flow_cfg[port_id].parse_prfl = &default_kex_profile;
	} else {
		dao_err("Invalid parse profile name %s", config->parse_profile);
	}
}

int
dao_flow_init(uint16_t port_id, struct dao_flow_offload_config *config)
{
	int rc;

	/* Allocate global memory for storing all configurations and parameters */
	if (!gbl_cfg) {
		gbl_cfg = rte_zmalloc(FLOW_GBL_CFG_MZ_NAME, sizeof(struct flow_global_cfg),
				      RTE_CACHE_LINE_SIZE);
		if (!gbl_cfg)
			DAO_ERR_GOTO(-ENOMEM, error, "Failed to reserve mem for main_cfg");
	}

	parse_profile_setup(port_id, gbl_cfg, config);
	rc = acl_global_config_init(port_id, gbl_cfg);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to initialize acl ctx map");

	rc = hw_offload_global_config_init(gbl_cfg);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to initialize hw offload global config");

	/* If user enabled HW offloading configuration */
	if (config->feature & DAO_FLOW_HW_OFFLOAD_ENABLE)
		gbl_cfg->flow_cfg[port_id].hw_offload_enabled = true;

	flow_parser_init(&gbl_cfg->flow_cfg[port_id].parser, gbl_cfg->flow_cfg[port_id].parse_prfl);

	/* If user provide timeout, else use DEFAULT aging timeout */
	gbl_cfg->flow_cfg[port_id].aging_tmo_sec = config->aging_tmo_sec ? config->aging_tmo_sec :
								FLOW_DEFAULT_AGING_TIMEOUT;
	gbl_cfg->num_initialized_ports++;

	return 0;
fail:
	rte_free(gbl_cfg);
error:
	return errno;
}

static int
flow_cleanup(uint16_t port_id, struct flow_global_cfg *gbl_cfg)
{
	struct hw_offload_config_per_port *hw_off_cfg;
	struct flow_config_per_port *flow_cfg_prt;
	struct hw_offload_flow *hflow;
	struct flow_data *fdata;
	void *tmp;

	flow_cfg_prt = &gbl_cfg->flow_cfg[port_id];
	rte_spinlock_lock(&flow_cfg_prt->flow_list_lock);
	DAO_TAILQ_FOREACH_SAFE(fdata, &flow_cfg_prt->flow_list, next, tmp) {
		dao_dbg("Removing flow rule %p, flow %p", fdata, fdata->flow);
		TAILQ_REMOVE(&flow_cfg_prt->flow_list, fdata, next);
		hflow = fdata->flow->hflow;
		rte_free(fdata->flow);
		rte_free(fdata);
		flow_cfg_prt->num_flows--;
		if (!hflow || hflow->offloaded)
			continue;
		hw_off_cfg = &gbl_cfg->hw_off_gbl->hw_off_cfg[port_id];
		if (hw_offload_flow_destroy(hw_off_cfg, hflow))
			dao_err("Failed to cleanup flow %p, port id %d", hflow, port_id);
	}
	rte_spinlock_unlock(&flow_cfg_prt->flow_list_lock);

	return 0;
}

int
dao_flow_fini(uint16_t port_id)
{
	if (flow_cleanup(port_id, gbl_cfg))
		dao_err("Failed to cleanup flows for port %d", port_id);

	if (acl_global_config_fini(port_id, gbl_cfg))
		dao_err("Failed to cleanup ACL global config for port %d",
			port_id);

	gbl_cfg->num_initialized_ports--;
	if (!gbl_cfg->num_initialized_ports) {
		if (hw_offload_global_config_fini(gbl_cfg))
			dao_err("Failed to cleanup HW offload global config");

		rte_free(gbl_cfg->acl_gbl);
		gbl_cfg->acl_gbl = NULL;
		rte_free(gbl_cfg->hw_off_gbl);
		gbl_cfg->hw_off_gbl = NULL;
		rte_free(gbl_cfg);
		gbl_cfg = NULL;
	}

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
			fdata->flow->arule->is_hw_offloaded = true;
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

	memset(result, 0, nb_objs * sizeof(uint32_t));
	rc = acl_flow_lookup(acl_tbl, objs, nb_objs, result);
	if (rc)
		return rc;

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
			flow_cfg_prt->num_flows--;
		}
	}
	rte_spinlock_unlock(&flow_cfg_prt->flow_list_lock);

	/* ACL Flow destroy */
	rc = acl_delete_rule(acl_tbl, arule);
	if (rc)
		DAO_ERR_GOTO(-rc, fail, "Failed to delete flow");
	acl_cfg_prt->num_rules_per_prt--;

	/* HW offload Flow destroy */
	hw_off_cfg = &gbl_cfg->hw_off_gbl->hw_off_cfg[port_id];
	rc = hw_offload_flow_destroy(hw_off_cfg, hflow);
	if (rc)
		DAO_ERR_GOTO(-rc, fail, "Failed to delete HW offloaded flow");

	return 0;
fail:
	return errno;
}

int
dao_flow_uninstall_hardware(uint16_t port_id, struct dao_flow *flow, struct rte_flow_error *error)
{
	struct hw_offload_config_per_port *hw_off_cfg;
	struct flow_config_per_port *flow_cfg_prt;
	struct hw_offload_flow *hflow;
	struct flow_data *fdata;
	void *tmp;
	int rc;

	RTE_SET_USED(error);
	if (!gbl_cfg->flow_cfg[port_id].hw_offload_enabled)
		DAO_ERR_GOTO(-EINVAL, fail, "HW offload not enabled");

	if (flow->port_id != port_id)
		DAO_ERR_GOTO(-EINVAL, fail, "Mismatch in Flow portid %d and passed portid %d",
			     flow->port_id, port_id);

	hflow = flow->hflow;
	flow_cfg_prt = &gbl_cfg->flow_cfg[port_id];
	rte_spinlock_lock(&flow_cfg_prt->flow_list_lock);
	DAO_TAILQ_FOREACH_SAFE(fdata, &flow_cfg_prt->flow_list, next, tmp) {
		if (flow == fdata->flow) {
			TAILQ_REMOVE(&flow_cfg_prt->flow_list, fdata, next);
			dao_dbg("Removing flow %p, hw flow %p", fdata->flow, fdata->flow->hflow);
			rte_free(fdata->flow);
			rte_free(fdata);
			flow_cfg_prt->num_flows--;
		}
	}
	rte_spinlock_unlock(&flow_cfg_prt->flow_list_lock);

	/* HW offload Flow destroy */
	hw_off_cfg = &gbl_cfg->hw_off_gbl->hw_off_cfg[port_id];
	rc = hw_offload_flow_uninstall(hw_off_cfg, hflow);
	if (rc)
		DAO_ERR_GOTO(-rc, fail, "Failed to delete HW offloaded flow");

	return 0;
fail:
	return errno;
}

int
dao_flow_query(uint16_t port_id, struct dao_flow *flow, const struct rte_flow_action *action,
	       void *data, struct rte_flow_error *error)
{
	struct hw_offload_config_per_port *hw_off_cfg;
	struct dao_flow_query_count *query = data;
	struct acl_config_per_port *acl_cfg_prt;
	struct acl_table *acl_tbl = NULL;
	struct acl_rule_data *arule;
	struct hw_offload_flow *hflow;
	int rc = -EINVAL;

	if (flow->port_id != port_id)
		DAO_ERR_GOTO(-EINVAL, fail, "Mismatch in Flow portid %d and passed portid %d",
			     flow->port_id, port_id);

	if (action->type != RTE_FLOW_ACTION_TYPE_COUNT)
		DAO_ERR_GOTO(-EINVAL, fail, "Only COUNT is supported in query");

	/* Query the HW offloaded flow */
	hflow = flow->hflow;
	if (hflow->offloaded) {
		hw_off_cfg = &gbl_cfg->hw_off_gbl->hw_off_cfg[port_id];
		rc = hw_offload_flow_query(hw_off_cfg, hflow, action, query, error);
		if (rc)
			DAO_ERR_GOTO(rc, fail, "Failed to dump the flow %p for port %d",
				     hflow->flow, port_id);
	}

	/* Query the ACL rule hits */
	acl_cfg_prt = &gbl_cfg->acl_gbl->acl_cfg_prt[port_id];
	if (!acl_cfg_prt)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get per acl tables for port %d", port_id);

	acl_tbl = &acl_cfg_prt->acl_tbl[flow->tbl_id];
	if (!acl_tbl)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get table for tbl_id %d, port id %d",
			     flow->tbl_id, port_id);

	arule = flow->arule;
	rc = acl_rule_query(acl_tbl, arule, query);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to dump the ACL rule %p for port %d", hflow->flow,
			     port_id);
	return 0;
fail:
	return errno;
}

int
dao_flow_dev_dump(uint16_t port_id, struct dao_flow *flow, FILE *file, struct rte_flow_error *error)
{
	struct hw_offload_config_per_port *hw_off_cfg;
	struct acl_config_per_port *acl_cfg_prt;
	struct acl_table *acl_tbl = NULL;
	struct hw_offload_flow *hflow;
	struct acl_rule_data *arule;
	int rc = -EINVAL;

	if (flow->port_id != port_id)
		DAO_ERR_GOTO(-EINVAL, fail, "Mismatch in Flow portid %d and passed portid %d",
			     flow->port_id, port_id);

	/* Dump the HW offloaded flow */
	hflow = flow->hflow;
	if (hflow->offloaded) {
		hw_off_cfg = &gbl_cfg->hw_off_gbl->hw_off_cfg[port_id];
		rc = hw_offload_flow_dump(hw_off_cfg, hflow, file, error);
		if (rc)
			DAO_ERR_GOTO(rc, fail, "Failed to dump the flow %p for port %d",
				     hflow->flow, port_id);
	}
	/* Dump ACL rule */
	acl_cfg_prt = &gbl_cfg->acl_gbl->acl_cfg_prt[port_id];
	if (!acl_cfg_prt)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get per acl tables for port %d", port_id);

	acl_tbl = &acl_cfg_prt->acl_tbl[flow->tbl_id];
	if (!acl_tbl)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get table for tbl_id %d, port id %d",
			     flow->tbl_id, port_id);

	arule = flow->arule;
	rc = acl_rule_dump(acl_tbl, arule, file);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to dump the ACL rule %p for port %d", hflow->flow,
			     port_id);

	return 0;
fail:
	return rc;
}

int
dao_flow_count(uint16_t port_id, struct dao_flow_count *count, struct rte_flow_error *error)
{
	struct hw_offload_config_per_port *hw_off_cfg;
	struct flow_config_per_port *flow_cfg_prt;
	struct acl_config_per_port *acl_cfg_prt;

	RTE_SET_USED(error);
	flow_cfg_prt = &gbl_cfg->flow_cfg[port_id];
	hw_off_cfg = &gbl_cfg->hw_off_gbl->hw_off_cfg[port_id];
	acl_cfg_prt = &gbl_cfg->acl_gbl->acl_cfg_prt[port_id];

	count->dao_flow = flow_cfg_prt->num_flows;
	count->hw_offload_flow = hw_off_cfg->num_rules;
	count->acl_rule = acl_cfg_prt->num_rules_per_prt;

	return 0;
}

int
dao_flow_info(uint16_t port_id, FILE *file, struct rte_flow_error *error)
{
	struct hw_offload_config_per_port *hw_off_cfg;
	struct flow_config_per_port *flow_cfg_prt;
	struct acl_config_per_port *acl_cfg_prt;
	struct flow_data *fdata;
	int rc = -EINVAL;
	int count = 0;

	RTE_SET_USED(error);
	flow_cfg_prt = &gbl_cfg->flow_cfg[port_id];
	hw_off_cfg = &gbl_cfg->hw_off_gbl->hw_off_cfg[port_id];
	acl_cfg_prt = &gbl_cfg->acl_gbl->acl_cfg_prt[port_id];
	fprintf(file, "Total Dao Flows %d for port %d\n", flow_cfg_prt->num_flows, port_id);
	fprintf(file, "Total ACL flows %d for port %d\n", acl_cfg_prt->num_rules_per_prt, port_id);
	fprintf(file, "Total HW offloaded flows %d\n", hw_off_cfg->num_rules);
	fprintf(file, "HW offload Flow timeout %d\n", hw_off_cfg->aging_tmo_sec);
	rte_spinlock_lock(&flow_cfg_prt->flow_list_lock);
	TAILQ_FOREACH(fdata, &flow_cfg_prt->flow_list, next) {
		fprintf(file, "Dao Flow %d handle %p\n", count++, fdata->flow);
		/* HW offloaded flows information */
		if (gbl_cfg->flow_cfg[port_id].hw_offload_enabled) {
			if (fdata->flow->hflow->offloaded) {
				rc = hw_offload_flow_info(fdata->flow->hflow, file);
				if (rc)
					DAO_ERR_GOTO(rc, fail,
						     "Failed to flush all flows for port %d",
						     port_id);
			}
		}

		/* ACL rules information */
		rc = acl_rule_info(fdata->flow->arule, file);
		if (rc)
			DAO_ERR_GOTO(rc, fail, "Failed to flush all ACL rules for port %d",
				     port_id);
	}
	rte_spinlock_unlock(&flow_cfg_prt->flow_list_lock);

	return 0;
fail:
	rte_spinlock_unlock(&flow_cfg_prt->flow_list_lock);
	return rc;
}

int
dao_flow_flush(uint16_t port_id, struct rte_flow_error *error)
{
	struct hw_offload_config_per_port *hw_off_cfg;
	struct flow_config_per_port *flow_cfg_prt;
	struct acl_config_per_port *acl_cfg_prt;
	struct flow_data *fdata;
	int rc = -EINVAL;
	void *tmp;

	/* Flush HW offloaded flows */
	if (gbl_cfg->flow_cfg[port_id].hw_offload_enabled) {
		hw_off_cfg = &gbl_cfg->hw_off_gbl->hw_off_cfg[port_id];
		rc = hw_offload_flow_flush(hw_off_cfg, error);
		if (rc)
			DAO_ERR_GOTO(rc, fail, "Failed to flush all flows for port %d", port_id);
		hw_off_cfg->num_rules = 0;
	}

	/* Flush ACL rules */
	acl_cfg_prt = &gbl_cfg->acl_gbl->acl_cfg_prt[port_id];
	rc = acl_rule_flush(acl_cfg_prt);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to flush all ACL rules for port %d", port_id);

	/* Flushing DAO flows */
	flow_cfg_prt = &gbl_cfg->flow_cfg[port_id];
	rte_spinlock_lock(&flow_cfg_prt->flow_list_lock);
	DAO_TAILQ_FOREACH_SAFE(fdata, &flow_cfg_prt->flow_list, next, tmp) {
		dao_dbg("Removing flow rule %p, flow %p", fdata, fdata->flow);
		TAILQ_REMOVE(&flow_cfg_prt->flow_list, fdata, next);
		flow_cfg_prt->num_flows--;
		rte_free(fdata->flow);
		rte_free(fdata);
	}
	rte_spinlock_unlock(&flow_cfg_prt->flow_list_lock);

	return 0;
fail:
	return rc;
}
