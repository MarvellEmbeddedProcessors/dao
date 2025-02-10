/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
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
	struct hw_offload_flow *hflow = NULL;
	struct flow_data *fdata = NULL;
	struct dao_flow *flow = NULL;
	struct flow_fops_t *flow_ops;
	uint16_t tbl_id = 0;
	uint32_t rule_idx;
	void *rule = NULL;

	RTE_SET_USED(error);

	flow_ops = gbl_cfg->flow_ops;

	rule = flow_ops->create(gbl_cfg->sw_flow_cfg, attr, pattern, actions, port_id, &rule_idx,
				error);
	if (!rule)
		DAO_ERR_GOTO(errno, fail, "Failed to create rule");

	flow = rte_zmalloc("dao_flow", sizeof(struct dao_flow), RTE_CACHE_LINE_SIZE);
	if (!flow)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory");

	flow->rule_data = rule;
	/* Userdata and HW flow rule mapping */
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
	fdata->rule_idx = rule_idx;

	rte_spinlock_lock(&flow_cfg_prt->flow_list_lock);
	flow_cfg_prt->num_flows++;
	TAILQ_INSERT_TAIL(&flow_cfg_prt->flow_list, fdata, next);
	rte_spinlock_unlock(&flow_cfg_prt->flow_list_lock);

	dao_dbg("New DAO flow created %p - rule %p HW flow %p", flow, flow->rule_data,
		flow->hflow);

	return flow;
fail:
	return NULL;
}

struct dao_flow *
dao_flow_hw_install(uint16_t port_id, const struct rte_flow_attr *attr,
		    const struct rte_flow_item pattern[], const struct rte_flow_action actions[],
		    struct rte_flow_error *error)
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
	flow->port_id = port_id;

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

static int
validate_feature(struct dao_flow_offload_config *config)
{
	if (config->feature & DAO_FLOW_KEX_OVS && config->feature & DAO_FLOW_KEX_DEFAULT) {
		dao_err("More than one KEX profile specified");
		return -EINVAL;
	}
	if (config->feature & DAO_FLOW_ALG_EM && config->feature & DAO_FLOW_ALG_ACL) {
		dao_err("More than one flow algorithm specified");
		return -EINVAL;
	}

	return 0;
}

static void
parse_profile_setup(uint16_t port_id, struct flow_global_cfg *gbl_cfg,
		    struct dao_flow_offload_config *config)
{
	if (config->feature & DAO_FLOW_KEX_OVS) {
		gbl_cfg->flow_cfg[port_id].prfl_ops = &ovs_prfl_ops;
		gbl_cfg->flow_cfg[port_id].parse_prfl = &ovs_kex_profile;
	} else if (config->feature & DAO_FLOW_KEX_DEFAULT) {
		gbl_cfg->flow_cfg[port_id].prfl_ops = &default_prfl_ops;
		gbl_cfg->flow_cfg[port_id].parse_prfl = &default_kex_profile;
	} else {
		dao_err("Invalid kex profile: %s", config->parse_profile);
	}
}

int
dao_flow_init(uint16_t port_id, struct dao_flow_offload_config *hw_offload_cfg)
{
	struct dao_flow_offload_config *config = hw_offload_cfg;
	int rc;

	/* Allocate global memory for storing all configurations and parameters */
	if (!gbl_cfg) {
		gbl_cfg = rte_zmalloc(FLOW_GBL_CFG_MZ_NAME, sizeof(struct flow_global_cfg),
				      RTE_CACHE_LINE_SIZE);
		if (!gbl_cfg)
			DAO_ERR_GOTO(-ENOMEM, error, "Failed to reserve mem for main_cfg");
	}

	rc = validate_feature(config);
	if (rc)
		return rc;

	parse_profile_setup(port_id, gbl_cfg, config);

	if (config->feature & DAO_FLOW_ALG_EM)
		gbl_cfg->flow_ops = &em_flow_ops;
	else if (config->feature & DAO_FLOW_ALG_ACL)
		gbl_cfg->flow_ops = &acl_flow_ops;
	else
		DAO_ERR_GOTO(-EINVAL, error, "Flow alg not supported.");

	rc = gbl_cfg->flow_ops->init(port_id, &gbl_cfg->sw_flow_cfg);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to initialize ctx map");

	rc = hw_offload_global_config_init(gbl_cfg);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to initialize hw offload global config");

	dao_info("config->feature: %x\n", config->feature);
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

	if (gbl_cfg->flow_ops->fini(port_id, gbl_cfg->sw_flow_cfg))
		dao_err("Failed to cleanup global config for port %d", port_id);

	gbl_cfg->num_initialized_ports--;
	if (!gbl_cfg->num_initialized_ports) {
		if (hw_offload_global_config_fini(gbl_cfg))
			dao_err("Failed to cleanup HW offload global config");

		rte_free(gbl_cfg->sw_flow_cfg);
		gbl_cfg->sw_flow_cfg = NULL;
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
	/* TODO: Store fdata in another data structure. May be combination of hash and array. */
	TAILQ_FOREACH(fdata, &flow_cfg_prt->flow_list, next) {
		if (fdata->rule_idx == rule_idx) {
			hflow = fdata->flow->hflow;
			if (!hflow) {
				dao_dbg("HW offload flow not reserved, port %d", port_id);
				continue;
			}
			if (hflow->offloaded) {
				rte_spinlock_unlock(&flow_cfg_prt->flow_list_lock);
				return 0;
			}
			hw_off_cfg = &gbl_cfg->hw_off_gbl->hw_off_cfg[port_id];
			if (hw_offload_flow_create(hw_off_cfg, hflow))
				DAO_ERR_GOTO(errno, fail, "Failed to create flow %p, port id %d",
					     hflow, port_id);
			fdata->flow->is_hw_offloaded = true;
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
	uint32_t result[nb_objs];
	int rc, i;

	memset(result, 0, nb_objs * sizeof(uint32_t));
	rc = gbl_cfg->flow_ops->lookup(gbl_cfg->sw_flow_cfg, port_id, objs, nb_objs, result);
	if (rc)
		return rc;

	if (gbl_cfg->flow_cfg[port_id].hw_offload_enabled) {
		for (i = 0; i < nb_objs; i++) {
			if (result[i]) {
				rc = flow_install_hardware(gbl_cfg, port_id, result[i]);
				if (rc)
					dao_err("Failed to install the flow to HW");
			}
		}
	}

	return 0;
}

int
dao_flow_destroy(uint16_t port_id, struct dao_flow *fl, struct rte_flow_error *error)
{
	struct hw_offload_config_per_port *hw_off_cfg;
	struct flow_config_per_port *flow_cfg_prt;
	struct hw_offload_flow *hflow;
	struct dao_flow *flow = fl;
	struct flow_data *fdata;
	void *rule_data;
	uint16_t tbl_id;
	void *tmp;
	int rc;

	RTE_SET_USED(error);
	if (flow->port_id != port_id)
		DAO_ERR_GOTO(-EINVAL, fail, "Mismatch in Flow portid %d and passed portid %d",
			     flow->port_id, port_id);

	tbl_id = flow->tbl_id;
	rule_data = flow->rule_data;
	hflow = flow->hflow;
	flow_cfg_prt = &gbl_cfg->flow_cfg[port_id];
	rte_spinlock_lock(&flow_cfg_prt->flow_list_lock);
	DAO_TAILQ_FOREACH_SAFE(fdata, &flow_cfg_prt->flow_list, next, tmp) {
		if (flow == fdata->flow) {
			TAILQ_REMOVE(&flow_cfg_prt->flow_list, fdata, next);
			dao_dbg("Removing flow %p, rule %p hw flow %p", fdata->flow,
				fdata->flow->rule_data, fdata->flow->hflow);
			rte_free(fdata->flow);
			rte_free(fdata);
			flow_cfg_prt->num_flows--;
		}
	}
	rte_spinlock_unlock(&flow_cfg_prt->flow_list_lock);

	/* Flow destroy */
	rc = gbl_cfg->flow_ops->destroy(gbl_cfg->sw_flow_cfg, port_id, tbl_id, rule_data);
	if (rc)
		DAO_ERR_GOTO(-rc, fail, "Failed to delete flow");

	/* HW offload Flow destroy */
	if (!hflow || hflow->offloaded)
		return 0;

	hw_off_cfg = &gbl_cfg->hw_off_gbl->hw_off_cfg[port_id];
	rc = hw_offload_flow_destroy(hw_off_cfg, hflow);
	if (rc)
		DAO_ERR_GOTO(-rc, fail, "Failed to delete HW offloaded flow");

	return 0;
fail:
	return errno;
}

int
dao_flow_hw_uninstall(uint16_t port_id, struct dao_flow *flow, struct rte_flow_error *error)
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
			dao_dbg("Removing flow %p, hw flow %p", fdata->flow,
				fdata->flow->hflow);
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
dao_flow_query(uint16_t port_id, struct dao_flow *fl, const struct rte_flow_action *action,
	       void *data, struct rte_flow_error *error)
{
	struct hw_offload_config_per_port *hw_off_cfg;
	struct dao_flow_query_count *fquery = data;
	struct hw_offload_flow *hflow;
	struct dao_flow *flow = fl;
	int rc = -EINVAL;

	if (flow->port_id != port_id)
		DAO_ERR_GOTO(-EINVAL, fail, "Mismatch in Flow portid %d and passed portid %d",
			     flow->port_id, port_id);

	if (action->type != RTE_FLOW_ACTION_TYPE_COUNT)
		DAO_ERR_GOTO(-EINVAL, fail, "Only COUNT is supported in query");

	/* Query the HW offloaded flow */
	hflow = flow->hflow;
	if (hflow && hflow->offloaded) {
		hw_off_cfg = &gbl_cfg->hw_off_gbl->hw_off_cfg[port_id];
		rc = hw_offload_flow_query(hw_off_cfg, hflow, action, fquery, error);
		if (rc)
			DAO_ERR_GOTO(rc, fail, "Failed to dump the flow %p for port %d",
				     hflow->flow, port_id);
	}

	/* Query the ACL rule hits */
	rc = gbl_cfg->flow_ops->query(gbl_cfg->sw_flow_cfg, port_id, flow->tbl_id, flow->rule_data,
				      fquery);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to dump the rule %p for port %d", hflow->flow,
			     port_id);
	return 0;
fail:
	return errno;
}

int
dao_flow_dev_dump(uint16_t port_id, struct dao_flow *fl, FILE *file, struct rte_flow_error *error)
{
	struct hw_offload_config_per_port *hw_off_cfg;
	struct hw_offload_flow *hflow;
	struct dao_flow *flow = fl;
	int rc = -EINVAL;

	if (flow->port_id != port_id)
		DAO_ERR_GOTO(-EINVAL, fail, "Mismatch in Flow portid %d and passed portid %d",
			     flow->port_id, port_id);

	/* Dump the HW offloaded flow */
	hflow = flow->hflow;
	if (hflow && hflow->offloaded) {
		hw_off_cfg = &gbl_cfg->hw_off_gbl->hw_off_cfg[port_id];
		rc = hw_offload_flow_dump(hw_off_cfg, hflow, file, error);
		if (rc)
			DAO_ERR_GOTO(rc, fail, "Failed to dump the flow %p for port %d",
				     hflow->flow, port_id);
	}

	/* Dump ACL rule */
	rc = gbl_cfg->flow_ops->dump(gbl_cfg->sw_flow_cfg, port_id, flow->tbl_id, flow->rule_data,
				     file);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to dump the rule %p for port %d", hflow->flow,
			     port_id);

	return 0;
fail:
	return rc;
}

int
dao_flow_count(uint16_t port_id, struct dao_flow_count *cnt, struct rte_flow_error *error)
{
	struct hw_offload_config_per_port *hw_off_cfg;
	struct flow_config_per_port *flow_cfg_prt;
	struct dao_flow_count *count = cnt;

	RTE_SET_USED(error);
	flow_cfg_prt = &gbl_cfg->flow_cfg[port_id];
	hw_off_cfg = &gbl_cfg->hw_off_gbl->hw_off_cfg[port_id];

	count->dao_flow = flow_cfg_prt->num_flows;
	count->hw_offload_flow = hw_off_cfg->num_rules;
	count->rule_per_port = gbl_cfg->flow_ops->count(gbl_cfg->sw_flow_cfg, port_id);

	return 0;
}

int
dao_flow_info(uint16_t port_id, FILE *file, struct rte_flow_error *error)
{
	struct hw_offload_config_per_port *hw_off_cfg;
	struct flow_config_per_port *flow_cfg_prt;
	struct flow_data *fdata;
	int rc = -EINVAL;
	int count = 0;

	RTE_SET_USED(error);
	flow_cfg_prt = &gbl_cfg->flow_cfg[port_id];
	hw_off_cfg = &gbl_cfg->hw_off_gbl->hw_off_cfg[port_id];
	fprintf(file, "Total Dao Flows %d for port %d\n", flow_cfg_prt->num_flows, port_id);
	fprintf(file, "Total flows %d for port %d\n",
		gbl_cfg->flow_ops->count(gbl_cfg->sw_flow_cfg, port_id), port_id);
	fprintf(file, "Total HW offloaded flows %d\n", hw_off_cfg->num_rules);
	fprintf(file, "HW offload Flow timeout %d\n", hw_off_cfg->aging_tmo_sec);
	rte_spinlock_lock(&flow_cfg_prt->flow_list_lock);
	TAILQ_FOREACH (fdata, &flow_cfg_prt->flow_list, next) {
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

		/* rules information */
		rc = gbl_cfg->flow_ops->info(fdata->flow->rule_data, file, fdata->flow->is_hw_offloaded);
		if (rc)
			DAO_ERR_GOTO(rc, fail, "Failed to flush all rules for port %d",
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

	/* Flush rules */
	rc = gbl_cfg->flow_ops->flush(gbl_cfg->sw_flow_cfg, port_id);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to flush all rules for port %d", port_id);

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
