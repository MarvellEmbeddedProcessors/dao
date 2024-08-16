/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "flow_gbl_priv.h"
#include "flow_hw_offload_priv.h"

#include "dao_util.h"

static int
aging_action_append(struct hw_offload_flow *hflow, uint32_t aging_tmo)
{
	struct rte_flow_action *new_actions, *old_actions;
	struct rte_flow_action_age *age = NULL;
	int num_actions = 0;

	old_actions = hflow->actions;
	for (; old_actions->type != RTE_FLOW_ACTION_TYPE_END; old_actions++)
		num_actions++;

	/* Allocate same size +1 item for the additional raw pattern: */
	new_actions = rte_zmalloc(NULL, (num_actions + 1) * sizeof(*new_actions), 0);
	if (new_actions == NULL) {
		dao_err("New actions memory allocation failed");
		return -ENOMEM;
	}

	old_actions = hflow->actions;
	rte_memcpy(&new_actions[0], &old_actions[0], (num_actions) * sizeof(*new_actions));

	/* Add mark ID action */
	age = rte_zmalloc("Aging action", sizeof(struct rte_flow_action_age), RTE_CACHE_LINE_SIZE);
	dao_dbg("Allocating age action mem %p", age);
	new_actions[num_actions].type = RTE_FLOW_ACTION_TYPE_AGE;
	age->timeout = aging_tmo;
	age->context = hflow;
	new_actions[num_actions].conf = (struct rte_flow_action_age *)age;
	num_actions++;

	/* End action */
	new_actions[num_actions].type = RTE_FLOW_ACTION_TYPE_END;
	new_actions[num_actions].conf = NULL;

	hflow->actions = new_actions;

	/* Freeing old instance of action memory allocated */
	old_actions = NULL;

	return 0;
}

static int
flow_attr_conv(struct hw_offload_flow *hflow, const struct rte_flow_attr *attr,
	       struct rte_flow_error *error)
{
	int ret;

	ret = rte_flow_conv(RTE_FLOW_CONV_OP_ATTR, NULL, 0, attr, error);
	if (ret < 0)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid bytes received %d", ret);

	hflow->attr = rte_zmalloc("Attr", ret, RTE_CACHE_LINE_SIZE);
	if (!hflow->attr)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory");

	ret = rte_flow_conv(RTE_FLOW_CONV_OP_ATTR, hflow->attr, ret, attr, error);
	if (ret < 0)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid bytes received %d", ret);

	return 0;
fail:
	return errno;
}

static int
flow_actions_conv(struct hw_offload_flow *hflow, const struct rte_flow_action *actions,
		  struct rte_flow_error *error)
{
	int ret;

	ret = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS, NULL, 0, actions, error);
	if (ret < 0)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid bytes received %d", ret);

	hflow->actions = rte_zmalloc("Actions", ret, RTE_CACHE_LINE_SIZE);
	if (!hflow->actions)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory");

	ret = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS, hflow->actions, ret, actions, error);
	if (ret < 0)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid bytes received %d", ret);

	return 0;
fail:
	return errno;
}

static int
flow_patterns_conv(struct hw_offload_flow *hflow, const struct rte_flow_item *pattern,
		   struct rte_flow_error *error)
{
	int ret;

	ret = rte_flow_conv(RTE_FLOW_CONV_OP_PATTERN, NULL, 0, pattern, error);
	if (ret < 0)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid bytes received %d", ret);

	hflow->pattern = rte_zmalloc("Patterns", ret, RTE_CACHE_LINE_SIZE);
	if (!hflow->pattern)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory");

	ret = rte_flow_conv(RTE_FLOW_CONV_OP_PATTERN, hflow->pattern, ret, pattern, error);
	if (ret < 0)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid bytes received %d", ret);

	return 0;
fail:
	return errno;
}

struct hw_offload_flow *
hw_offload_flow_reserve(struct hw_offload_config_per_port *hw_off_cfg,
			const struct rte_flow_attr *attr, const struct rte_flow_item pattern[],
			const struct rte_flow_action actions[], struct rte_flow_error *error)
{
	struct hw_offload_flow *hflow = NULL;
	int rc;

	hflow = rte_zmalloc("Flow Rule", sizeof(struct hw_offload_flow), RTE_CACHE_LINE_SIZE);
	if (!hflow)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory");

	rc = flow_attr_conv(hflow, attr, error);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to convert flow patterns");

	rc = flow_patterns_conv(hflow, pattern, error);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to convert flow patterns");

	rc = flow_actions_conv(hflow, actions, error);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to convert flow actions");

	/* Append aging action to the action list */
	rc = aging_action_append(hflow, hw_off_cfg->aging_tmo);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Failed to append aging action");

	hflow->offloaded = false;
	hflow->ctr_idx = -1;

	return hflow;
fail:
	rte_free(hflow);
	return NULL;
}

int
hw_offload_flow_create(struct hw_offload_config_per_port *hw_off_cfg, struct hw_offload_flow *hflow)
{
	struct rte_flow *flow = NULL;
	struct rte_flow_error error;
	struct parsed_flow *pflow;
	int rc;

	/* Validate the flow */
	rc = rte_flow_validate(hw_off_cfg->port_id, hflow->attr, hflow->pattern, hflow->actions,
			       &error);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Flow validation failed while creating flow");

	flow = rte_flow_create(hw_off_cfg->port_id, hflow->attr, hflow->pattern, hflow->actions,
			       &error);
	if (flow == NULL)
		DAO_ERR_GOTO(-EINVAL, fail, "RTE Flow creation failed");

	hflow->flow = flow;
	pflow = (struct parsed_flow *)flow;
	hflow->cam_idx = pflow->cam_idx;
	if (pflow->use_ctr)
		hflow->ctr_idx = pflow->ctr_idx;
	hflow->offloaded = true;
	hw_off_cfg->num_rules++;
	dao_dbg("Offloading new hflow %p flow %p to hardware, num_rule %d", hflow, flow,
		hw_off_cfg->num_rules);

	return 0;
fail:
	return errno;
}

struct hw_offload_flow *
hw_offload_flow_install(struct hw_offload_config_per_port *hw_off_cfg,
			const struct rte_flow_attr *attr, const struct rte_flow_item pattern[],
			const struct rte_flow_action actions[], struct rte_flow_error *error)
{
	struct hw_offload_flow *hflow = NULL;
	struct rte_flow *flow = NULL;
	struct parsed_flow *pflow;
	int rc;

	hflow = rte_zmalloc("HW Flow Rule", sizeof(struct hw_offload_flow), RTE_CACHE_LINE_SIZE);
	if (!hflow)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory");

	/* Validate the flow */
	rc = rte_flow_validate(hw_off_cfg->port_id, attr, pattern, actions, error);
	if (rc)
		DAO_ERR_GOTO(rc, fail, "Flow validation failed while creating flow");

	flow = rte_flow_create(hw_off_cfg->port_id, attr, pattern, actions, error);
	if (flow == NULL)
		DAO_ERR_GOTO(-EINVAL, fail, "RTE Flow creation failed");

	hflow->flow = flow;
	pflow = (struct parsed_flow *)flow;
	hflow->cam_idx = pflow->cam_idx;
	if (pflow->use_ctr)
		hflow->ctr_idx = pflow->ctr_idx;
	hflow->offloaded = true;
	hw_off_cfg->num_rules++;
	dao_dbg("Directly installing new hflow %p flow %p to hardware, num_rule %d", hflow, flow,
		hw_off_cfg->num_rules);

	return hflow;
fail:
	rte_free(hflow);
	return NULL;
}

int
hw_offload_flow_destroy(struct hw_offload_config_per_port *hw_off_cfg,
			struct hw_offload_flow *hflow)
{
	struct rte_flow_action *actions;
	struct rte_flow_error error;
	uint16_t port_id;

	if (!hw_off_cfg)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid HW offload config");

	port_id = hw_off_cfg->port_id;
	dao_dbg("Destroying hflow %p flow %p from hardware, num_rule %d", hflow, hflow->flow,
		hw_off_cfg->num_rules);
	/* Free memory allocated for Age action */
	actions = hflow->actions;
	for (; actions->type != RTE_FLOW_ACTION_TYPE_END; actions++) {
		struct rte_flow_action_age *age;

		if (actions->type == RTE_FLOW_ACTION_TYPE_AGE) {
			age = (struct rte_flow_action_age *)actions->conf;
			dao_dbg("Removing age action memory %p", age);
			rte_free(age);
		}
	}

	if (hflow->offloaded) {
		if (rte_flow_destroy(port_id, hflow->flow, &error))
			dao_err("Error in deleting flow");

		hw_off_cfg->num_rules--;
	}

	hflow->ctr_idx = -1;
	hflow->offloaded = false;
	rte_free(hflow->actions);
	rte_free(hflow->pattern);
	rte_free(hflow);

	return 0;
fail:
	return errno;
}

int
hw_offload_flow_uninstall(struct hw_offload_config_per_port *hw_off_cfg,
			  struct hw_offload_flow *hflow)
{
	struct rte_flow_error error;
	uint16_t port_id;

	if (!hw_off_cfg)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid HW offload config");

	if (!hflow->offloaded)
		DAO_ERR_GOTO(-EINVAL, fail, "Flow is not offloaded");

	port_id = hw_off_cfg->port_id;
	dao_dbg("Destroying direct hflow %p flow %p from hardware, num_rule %d", hflow, hflow->flow,
		hw_off_cfg->num_rules);
	/* Free memory allocated for Age action */

	if (rte_flow_destroy(port_id, hflow->flow, &error))
		dao_err("Error in deleting flow");

	hw_off_cfg->num_rules--;
	hflow->ctr_idx = -1;
	hflow->offloaded = false;
	rte_free(hflow);

	return 0;
fail:
	return errno;
}
static int
query_aged_flows(uint16_t port_id, uint8_t destroy)
{
	struct hw_offload_flow *hflow = NULL;
	int nb_context, total = 0, idx;
	struct rte_flow *flow = NULL;
	struct rte_flow_error error;
	void **contexts = NULL;

	total = rte_flow_get_aged_flows(port_id, NULL, 0, &error);
	if (total < 0)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid aged flows");

	if (total == 0)
		return 0;

	contexts = malloc(sizeof(void *) * total);
	if (contexts == NULL)
		DAO_ERR_GOTO(-ENOMEM, fail, "Cannot allocate contexts for aged flow");

	nb_context = rte_flow_get_aged_flows(port_id, contexts, total, &error);
	if (nb_context < 0)
		DAO_ERR_GOTO(-EINVAL, fail, "Port:%d get aged flows context count %d", port_id,
			     nb_context);
	total = 0;
	for (idx = 0; idx < nb_context; idx++) {
		if (!contexts[idx]) {
			dao_err("Error: get Null context in port %u", port_id);
			continue;
		}
		hflow = contexts[idx];
		flow = hflow->flow;
		dao_info("Destroying aged flow %p nb_context %d, total %d", flow, nb_context,
			 total);
		/* Destroying the aged flow */
		if (destroy) {
			if (rte_flow_destroy(port_id, flow, &error))
				DAO_ERR_GOTO(errno, fail, "Error in deleting flow");
			hflow->offloaded = false;
		}
		total++;
	}

	dao_dbg("%d flows destroyed", total);
	free(contexts);
	return 0;
fail:
	free(contexts);
	return errno;
}

static uint32_t
flow_aging_thread(void *arg)
{
	struct hw_offload_global_config *hw_off_gbl = (struct hw_offload_global_config *)arg;
	struct hw_offload_config_per_port *hw_off_cfg = NULL;
	int port_id = 0;

	while (hw_off_gbl->aging_thrd_quit) {
		for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
			hw_off_cfg = &hw_off_gbl->hw_off_cfg[port_id];
			if (hw_off_cfg->num_rules)
				query_aged_flows(port_id, true);
		}
	}

	dao_dbg("Exiting flow aging thread");

	return 0;
}

int
hw_offload_global_config_init(struct flow_global_cfg *gbl_cfg)
{
	struct hw_offload_global_config *hw_off_gbl;
	rte_thread_t thread;
	int rc;

	hw_off_gbl = rte_zmalloc("hw_offload_global_config",
				 sizeof(struct hw_offload_global_config), RTE_CACHE_LINE_SIZE);
	if (!hw_off_gbl)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory");

	gbl_cfg->hw_off_gbl = hw_off_gbl;

	/* Create a thread for handling control messages */
	hw_off_gbl->aging_thrd_quit = true;
	rc = rte_thread_create_control(&thread, "flow-aging-thrd", flow_aging_thread, hw_off_gbl);
	if (rc != 0)
		DAO_ERR_GOTO(rc, fail, "Failed to create thread for VF mbox handling");

	/* Save the thread handle to join later */
	hw_off_gbl->aging_thrd = thread;

	return rc;
fail:
	return errno;
}

int
hw_offload_global_config_fini(struct flow_global_cfg *gbl_cfg)
{
	struct hw_offload_global_config *hw_off_gbl;

	if (!gbl_cfg)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid flow global cfg handle");

	hw_off_gbl = gbl_cfg->hw_off_gbl;
	if (!hw_off_gbl)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid hw offload cfg handle");

	hw_off_gbl->aging_thrd_quit = false;
	rte_thread_join(hw_off_gbl->aging_thrd, NULL);
	rte_free(hw_off_gbl);

	return 0;
fail:
	return errno;
}

int
hw_offload_flow_query(struct hw_offload_config_per_port *hw_off_cfg, struct hw_offload_flow *hflow,
		      const struct rte_flow_action *action, struct dao_flow_query_count *query,
		      struct rte_flow_error *error)
{
	if (!hw_off_cfg)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid HW offload config");

	return rte_flow_query(hw_off_cfg->port_id, hflow->flow, action, query, error);
fail:
	return errno;
}

int
hw_offload_flow_dump(struct hw_offload_config_per_port *hw_off_cfg, struct hw_offload_flow *hflow,
		     FILE *file, struct rte_flow_error *error)
{
	if (!hw_off_cfg)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid HW offload config");

	return rte_flow_dev_dump(hw_off_cfg->port_id, hflow->flow, file, error);
fail:
	return errno;
}

int
hw_offload_flow_info(struct hw_offload_flow *hflow, FILE *file)
{
	fprintf(file, "\t HW offload Flow handle %p\n", hflow->flow);
	fprintf(file, "\t CAM Index: %d\n", hflow->cam_idx);
	fprintf(file, "\t Counter Index: %d\n", hflow->ctr_idx);
	fprintf(file, "\n");

	return 0;
}

int
hw_offload_flow_flush(struct hw_offload_config_per_port *hw_off_cfg, struct rte_flow_error *error)
{
	if (!hw_off_cfg)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid HW offload config");

	return rte_flow_flush(hw_off_cfg->port_id, error);
fail:
	return errno;
}
