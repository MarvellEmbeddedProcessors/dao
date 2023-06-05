/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <stdint.h>
#include <stdlib.h>

#include <rte_errno.h>
#include <rte_malloc.h>

#include <dao_log.h>
#include <dao_util.h>

#include <ood_ctrl_chan.h>
#include <ood_node_ctrl.h>

#define DEFAULT_DUMP_FILE_NAME "/tmp/fdump"
#define MAX_RTE_FLOW_ACTIONS   5
#define MAX_RTE_FLOW_PATTERN   5

#ifndef STAILQ_FOREACH_SAFE
#define STAILQ_FOREACH_SAFE(var, head, field, tvar)                                                \
	for ((var) = STAILQ_FIRST((head)); (var) && ((tvar) = STAILQ_NEXT((var), field), 1);       \
	     (var) = (tvar))
#endif

/** Print a message out of a flow error. */
static int
elaborate_flow_error(struct rte_flow_error *error)
{
	static const char *const errstrlist[] = {
		[RTE_FLOW_ERROR_TYPE_NONE] = "no error",
		[RTE_FLOW_ERROR_TYPE_UNSPECIFIED] = "cause unspecified",
		[RTE_FLOW_ERROR_TYPE_HANDLE] = "flow rule (handle)",
		[RTE_FLOW_ERROR_TYPE_ATTR_GROUP] = "group field",
		[RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY] = "priority field",
		[RTE_FLOW_ERROR_TYPE_ATTR_INGRESS] = "ingress field",
		[RTE_FLOW_ERROR_TYPE_ATTR_EGRESS] = "egress field",
		[RTE_FLOW_ERROR_TYPE_ATTR_TRANSFER] = "transfer field",
		[RTE_FLOW_ERROR_TYPE_ATTR] = "attributes structure",
		[RTE_FLOW_ERROR_TYPE_ITEM_NUM] = "pattern length",
		[RTE_FLOW_ERROR_TYPE_ITEM_SPEC] = "item specification",
		[RTE_FLOW_ERROR_TYPE_ITEM_LAST] = "item specification range",
		[RTE_FLOW_ERROR_TYPE_ITEM_MASK] = "item specification mask",
		[RTE_FLOW_ERROR_TYPE_ITEM] = "specific pattern item",
		[RTE_FLOW_ERROR_TYPE_ACTION_NUM] = "number of actions",
		[RTE_FLOW_ERROR_TYPE_ACTION_CONF] = "action configuration",
		[RTE_FLOW_ERROR_TYPE_ACTION] = "specific action",
	};
	const char *errstr;
	char buf[32];
	int err = rte_errno;

	if ((unsigned int)error->type >= RTE_DIM(errstrlist) || !errstrlist[error->type])
		errstr = "unknown type";
	else
		errstr = errstrlist[error->type];
	fprintf(stderr, "%s(): Caught PMD error type %d (%s): %s%s: %s\n", __func__, error->type,
		errstr,
		error->cause ? (snprintf(buf, sizeof(buf), "cause: %p, ", error->cause), buf) : "",
		error->message ? error->message : "(no stated reason)", rte_strerror(err));

	return -err;
}

static struct rte_flow *
insert_flow(uint16_t portid, struct rte_flow_attr *attr, struct rte_flow_item *pattern,
	    struct rte_flow_action *action, struct rte_flow_error *err)
{
	struct rte_flow *flow;
	int rc;

	/* Validate the flow */
	rc = rte_flow_validate(portid, attr, pattern, action, err);
	if (rc) {
		rc = elaborate_flow_error(err);
		DAO_ERR_GOTO(rc, error, "Flow validation failed");
	}

	/* Flow create */
	flow = rte_flow_create(portid, attr, pattern, action, err);
	if (flow == NULL) {
		rc = elaborate_flow_error(err);
		DAO_ERR_GOTO(rc, error, "Flow creation failed");
	}

	return flow;
error:
	return NULL;
}

static int
remove_flow(uint16_t portid, struct rte_flow *flow, struct rte_flow_error *err)
{
	int rc;

	if (!flow)
		return 0;

	rc = rte_flow_destroy(portid, flow, err);
	if (rc) {
		rc = elaborate_flow_error(err);
		dao_err("portid %d cause: %p msg: %s type %d", portid, err->cause, err->message,
			err->type);
	}
	flow = NULL;

	return rc;
}

static struct rte_flow *
mark_action_hw_offload_flow_add(uint16_t portid)
{
	struct rte_flow_action action[MAX_RTE_FLOW_ACTIONS] = {};
	struct rte_flow_item pattern[MAX_RTE_FLOW_PATTERN] = {};
	struct rte_flow_action_mark *mark_action;
	struct rte_flow_attr attr = {};
	struct rte_flow_error err = {};
	int pattern_idx = 0, act_idx = 0;

	mark_action = rte_zmalloc("Act_mark", sizeof(struct rte_flow_action_mark), 0);
	if (!mark_action) {
		dao_err("Failed to get memory mark action config");
		return NULL;
	}

	/* Define attributes */
	attr.egress = 0;
	attr.ingress = 1;

	/* Define actions */
	mark_action->id = 1;
	dao_dbg("mark_action->id %d (0x%x)", mark_action->id, mark_action->id);
	action[act_idx].type = RTE_FLOW_ACTION_TYPE_MARK;
	action[act_idx].conf = mark_action;
	act_idx++;
	action[act_idx].type = RTE_FLOW_ACTION_TYPE_END;
	action[act_idx].conf = NULL;

	/* Define patterns */
	pattern[pattern_idx].type = RTE_FLOW_ITEM_TYPE_VOID;
	pattern[pattern_idx].spec = NULL;
	pattern[pattern_idx].mask = NULL;
	pattern[pattern_idx].last = NULL;
	pattern_idx++;
	pattern[pattern_idx].type = RTE_FLOW_ITEM_TYPE_END;

	return insert_flow(portid, &attr, pattern, action, &err);
}

static int
remove_encap_action(struct rte_flow_action **actions)
{
	int num_actions = 0, encap_action_idx = -1, i, j = 0;
	struct rte_flow_action *action, *new_actions;

	action = *actions;
	for (; action->type != RTE_FLOW_ACTION_TYPE_END; action++) {
		if (action->type == RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP)
			encap_action_idx = num_actions;
		num_actions++;
	}
	/* For END action */
	num_actions++;

	/* Allocate same size +1 item for the additional raw pattern: */
	new_actions = rte_zmalloc(NULL, (num_actions - 1) * sizeof(*new_actions), 0);
	if (new_actions == NULL) {
		dao_err("New actions memory allocation failed");
		return -ENOMEM;
	}

	action = *actions;
	for (i = 0; i < num_actions - 1; i++) {
		if (i == encap_action_idx)
			continue;
		rte_memcpy(&new_actions[j], &action[i], sizeof(*new_actions));
		j++;
	}

	*actions = new_actions;

	/* Freeing old instance of action memory allocated */
	rte_free(action);
	action = NULL;

	return 0;
}

static uint16_t
generate_mark_id(ood_node_action_config_t *act_cfg, uint16_t act_cfg_idx)
{
	uint16_t mark_id, type = NRML_FWD_MARK_ID;

	/* Order of the following checks is important, it describes what action
	 * to happen first. Eg a tunneled packet may be required for host to
	 * host forwarding - packet undergoes encap first followed by port id
	 * action.
	 */
	/* PORT ID enabled */
	if (dao_check_bit_is_set(act_cfg->act_cfg_map, PORT_ID_ACTION_CONFIG + 1))
		type = HOST_TO_HOST_FWD_MARK_ID;

	/* VxLAN enabled */
	if (dao_check_bit_is_set(act_cfg->act_cfg_map, VXLAN_ENCAP_ACTION_CONFIG + 1))
		type = VXLAN_ENCAP_MARK_ID;

	mark_id = (act_cfg_idx << OOD_MARK_ID_SHIFT) | type;
	dao_dbg("Mark_id 0x%x, type %d, index %d", mark_id, type, act_cfg_idx);

	return mark_id;
}

static int
add_mark_action(uint16_t portid, struct rte_flow_action **actions,
		ood_node_action_config_t *act_cfg, uint16_t act_cfg_idx)
{
	struct rte_flow_action *new_actions, *old_actions;
	struct rte_flow_action_port_id *port_id;
	struct rte_flow_action_mark *act_mark;
	int num_actions = 0;

	act_mark = rte_zmalloc("Act_mark", sizeof(struct rte_flow_action_mark), 0);
	if (!act_mark) {
		dao_err("Failed to get memory mark action config");
		return -ENOMEM;
	}
	port_id = rte_zmalloc("port_id", sizeof(struct rte_flow_action_port_id), 0);
	if (!act_mark) {
		dao_err("Failed to get memory portid action config");
		return -ENOMEM;
	}
	old_actions = *actions;
	for (; old_actions->type != RTE_FLOW_ACTION_TYPE_END; old_actions++) {
		if (old_actions->type == RTE_FLOW_ACTION_TYPE_MARK) {
			/* TODO: what to do if action already has mark ID added */
			dao_dbg("Flow already has a markid");
			act_mark->id = generate_mark_id(act_cfg, act_cfg_idx);
			old_actions->conf = (struct rte_flow_action_mark *)act_mark;
			return 0;
		}
		if (old_actions->type == RTE_FLOW_ACTION_TYPE_PORT_ID) {
			port_id->id = portid;
			old_actions->conf = (struct rte_flow_action_port_id *)port_id;
		}

		num_actions++;
	}

	/* Allocate same size +1 item for the additional raw pattern: */
	new_actions = rte_zmalloc(NULL, (num_actions + 2) * sizeof(*new_actions), 0);
	if (new_actions == NULL) {
		dao_err("New actions memory allocation failed");
		return -ENOMEM;
	}

	old_actions = *actions;
	rte_memcpy(&new_actions[0], &old_actions[0], (num_actions) * sizeof(*new_actions));

	/* Add mark ID action */
	new_actions[num_actions].type = RTE_FLOW_ACTION_TYPE_MARK;
	act_mark->id = generate_mark_id(act_cfg, act_cfg_idx);
	new_actions[num_actions].conf = (struct rte_flow_action_mark *)act_mark;
	num_actions++;

	/* End action */
	new_actions[num_actions].type = RTE_FLOW_ACTION_TYPE_END;
	new_actions[num_actions].conf = NULL;

	*actions = new_actions;

	/* Freeing old instance of action memory allocated */
	rte_free(old_actions);
	old_actions = NULL;

	return 0;
}

static struct rte_flow *
host_port_flow_add(uint16_t portid, ood_node_action_config_t *act_cfg, uint16_t act_cfg_idx,
		   struct rte_flow_attr *attr, struct rte_flow_item *pattern,
		   struct rte_flow_action *action, struct rte_flow_error *err)
{
	if (add_mark_action(portid, &action, act_cfg, act_cfg_idx)) {
		dao_err("Failed to add mark action to mac port");
		return NULL;
	}

	return insert_flow(portid, attr, pattern, action, err);
}

static struct rte_flow *
mac_port_vlan_insert_flow_add(uint16_t portid, struct rte_flow_action *tx_actions)
{
	struct rte_flow_item pattern[MAX_RTE_FLOW_PATTERN] = {};
	struct rte_flow_attr attr = {};
	struct rte_flow_error err = {};
	int pattern_idx = 0;

	/* Define attributes */
	attr.egress = 1;
	attr.ingress = 0;

	/* Define patterns */
	pattern[pattern_idx].type = RTE_FLOW_ITEM_TYPE_ANY;
	pattern[pattern_idx].spec = NULL;
	pattern[pattern_idx].mask = NULL;
	pattern[pattern_idx].last = NULL;
	pattern_idx++;
	pattern[pattern_idx].type = RTE_FLOW_ITEM_TYPE_END;

	return insert_flow(portid, &attr, pattern, tx_actions, &err);
}

static struct rte_flow *
vlan_insert_action_config_process(struct rte_flow_action **actions, uint16_t portid)
{
	struct rte_flow_action *action, *new_actions, *tx_actions;
	int num_actions = 0, j = 0, k = 0;
	struct rte_flow *mac_flow;

	action = *actions;
	for (; action->type != RTE_FLOW_ACTION_TYPE_END; action++)
		num_actions++;

	/* For END action */
	num_actions++;

	new_actions = rte_zmalloc(NULL, num_actions * sizeof(*new_actions), 0);
	if (!new_actions)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate new actions array");

	tx_actions = rte_zmalloc("TX action", num_actions * sizeof(struct rte_flow_action), 0);
	if (!tx_actions)
		DAO_ERR_GOTO(-ENOMEM, remove_new_actions, "Failed to allocate TX actions array");

	action = *actions;
	for (; action->type != RTE_FLOW_ACTION_TYPE_END; action++) {
		switch (action->type) {
		case RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID:
		case RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN:
		case RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP:
			rte_memcpy(&tx_actions[k++], &action[0], sizeof(*tx_actions));
			break;
		case RTE_FLOW_ACTION_TYPE_COUNT:
			rte_memcpy(&tx_actions[k++], &action[0], sizeof(*tx_actions));
			rte_memcpy(&new_actions[j++], &action[0], sizeof(*new_actions));
			break;
		default:
			rte_memcpy(&new_actions[j++], &action[0], sizeof(*new_actions));
			break;
		}
	}

	dao_dbg("Total actions %d new actions %d tx actions %d", num_actions, j, k);
	/* End action */
	new_actions[j].type = RTE_FLOW_ACTION_TYPE_END;
	new_actions[j].conf = NULL;
	tx_actions[k].type = RTE_FLOW_ACTION_TYPE_END;
	tx_actions[k].conf = NULL;

	/* Install MAC TX rule */
	mac_flow = mac_port_vlan_insert_flow_add(portid, tx_actions);

	action = *actions;
	*actions = new_actions;
	/* Freeing old instance of action memory allocated */
	rte_free(action);
	action = NULL;

	return mac_flow;
remove_new_actions:
	free(new_actions);
fail:
	return NULL;
}

static int
vxlan_encap_action_config_process(struct rte_flow_action *action, struct rte_flow_error *error)
{
	const struct rte_flow_action_vxlan_encap *vxlan_conf;
	const struct rte_flow_item *pattern;
	int tnl_cfg_idx;

	vxlan_conf = action->conf;
	pattern = vxlan_conf->definition;
	tnl_cfg_idx = ood_node_vxlan_encap_tunnel_config_ctrl(pattern, error);
	if (tnl_cfg_idx < 0)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid tunnel config index received, err %d",
			     tnl_cfg_idx);

	dao_dbg("tnl_cfg_idx %d", tnl_cfg_idx);

	return tnl_cfg_idx;
fail:
	return errno;
}

static int
portid_action_config_process(struct rte_flow_action *action, uint16_t src_host_port)
{
	const struct rte_flow_action_port_id *portid_conf;
	representor_mapping_t *rep_map;
	int hst_cfg_idx = 0;

	portid_conf = action->conf;
	/* Parse portid action config, destination ID is non zero to steering packet to another
	 * host port.
	 */
	if (portid_conf->id) {
		/* Get the destination host port mapping to received portid_conf->id */
		rep_map = ood_representor_mapping_get(portid_conf->id);
		if (!rep_map)
			DAO_ERR_GOTO(-EINVAL, fail,
				     "Failed to get valid flow ctrl handle for repr queue %d",
				     portid_conf->id);

		dao_dbg("portid_conf->id %d, src_host_port %d dst_host_port %d", portid_conf->id,
			src_host_port, rep_map->host_port);
		hst_cfg_idx = ood_node_host_to_host_config_ctrl(src_host_port, rep_map->host_port);
		if (hst_cfg_idx < 0)
			DAO_ERR_GOTO(-EINVAL, fail, "Invalid tunnel config index received, err %d",
				     hst_cfg_idx);

		dao_dbg("hst_cfg_idx %d", hst_cfg_idx);
	}

	return hst_cfg_idx;
fail:
	return errno;
}

static int
action_config_process(struct rte_flow_action **actions, ood_node_action_config_t *act_cfg,
		      uint16_t src_host_port, struct rte_flow_error *error)
{
	struct rte_flow_action *action;
	int hst_cfg_idx = 0;
	bool has_encap = false;

	action = *actions;
	for (; action->type != RTE_FLOW_ACTION_TYPE_END; action++) {
		switch (action->type) {
		case RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP:
			/* Setup vxlan action context set */
			act_cfg->tnl_cfg_idx = vxlan_encap_action_config_process(action, error);
			if (act_cfg->tnl_cfg_idx <= 0)
				DAO_ERR_GOTO(-EINVAL, fail, "Invalid tnl cfg idx %d",
					     act_cfg->tnl_cfg_idx);

			act_cfg->act_cfg_map |= DAO_BIT(VXLAN_ENCAP_ACTION_CONFIG);
			has_encap = true;
			break;
		case RTE_FLOW_ACTION_TYPE_PORT_ID:
			hst_cfg_idx = portid_action_config_process(action, src_host_port);
			if (hst_cfg_idx < 0)
				DAO_ERR_GOTO(-EINVAL, fail, "Invalid prt_cfg_idx %d",
					     act_cfg->hst_cfg_idx);

			if (hst_cfg_idx > 0) {
				act_cfg->act_cfg_map |= DAO_BIT(PORT_ID_ACTION_CONFIG);
				act_cfg->hst_cfg_idx = hst_cfg_idx;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID:
		case RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN:
		case RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP:
			if (dao_check_bit_is_set(act_cfg->act_cfg_map,
						 VLAN_INSERT_ACTION_CONFIG + 1) == 0) {
				act_cfg->act_cfg_map |= DAO_BIT(VLAN_INSERT_ACTION_CONFIG);
			}
			break;
		default:
			break;
		};
	}

	/* Remove encap action from list, as current HW doesn't support VXLAN
	 * encap/decap action
	 */
	if (has_encap && remove_encap_action(actions))
		DAO_ERR_GOTO(errno, fail, "Failed to remove encap action");

	return 0;
fail:
	return errno;
}

struct rte_flow *
ood_flow_create(uint16_t repr_qid, struct rte_flow_attr *attr, struct rte_flow_item *pattern,
		struct rte_flow_action *action, struct rte_flow_error *err)
{
	struct rte_flow *host_flow = NULL, *mac_flow = NULL;
	ood_node_action_config_t *act_cfg = NULL;
	representor_mapping_t *rep_map;
	struct flows *iflow;
	int act_cfg_idx = 0;

	act_cfg = calloc(1, sizeof(ood_node_action_config_t));
	if (!act_cfg)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to alloc memory for act cfg");

	/* Get the flow ctrl structure */
	rep_map = ood_representor_mapping_get(repr_qid);
	if (!rep_map)
		DAO_ERR_GOTO(-EINVAL, fail,
			     "Failed to get valid flow ctrl handle for repr queue %d", repr_qid);

	dao_dbg("Representor ID %d mac port %d host port %d", repr_qid, rep_map->mac_port,
		rep_map->host_port);

	/* Following void rule just to enable mark action HW offloading on MAC VF ports */
	if (!rep_map->mark_offload_enable) {
		mac_flow = mark_action_hw_offload_flow_add(rep_map->mac_port);
		if (!mac_flow)
			DAO_ERR_GOTO(errno, remove_host_flow,
				     "Failed to add mark action hw offload flow");

		remove_flow(rep_map->mac_port, mac_flow, err);
		mac_flow = NULL;
		rep_map->mark_offload_enable = true;
	}

	/* Check if action has encap action */
	if (action_config_process(&action, act_cfg, rep_map->host_port, err))
		goto fail;

	/* Save the action config stat into respective bmap maintained at node ctrl layer */
	if (act_cfg->act_cfg_map) {
		act_cfg_idx = ood_node_action_config_alloc(act_cfg);
		if (act_cfg_idx <= 0)
			DAO_ERR_GOTO(errno, fail, "Failed to get valid act cfg idx %d",
				     act_cfg_idx);
		dao_dbg("act_cfg_idx %d", act_cfg_idx);

		/* If vlan insert action is enabled, create new egress flow to
		 * be installed at mac port, while original ingress flow shall
		 * be installed at host port with flow vlan insert actions removed
		 * as octeon HW does not support vlan insert ar NPC RX.
		 */

		if (dao_check_bit_is_set(act_cfg->act_cfg_map, VLAN_INSERT_ACTION_CONFIG + 1)) {
			mac_flow = vlan_insert_action_config_process(&action, rep_map->mac_port);
			if (!mac_flow)
				DAO_ERR_GOTO(errno, fail,
					     "Failed to add vlan insert hw offload flow");
		}
	}

	/* TODO add logic to check destination port */
	/* Insert host flow */
	host_flow = host_port_flow_add(rep_map->host_port, act_cfg, act_cfg_idx, attr, pattern,
				       action, err);
	if (!host_flow)
		DAO_ERR_GOTO(errno, fail, "Failed to add host flow");

	/* Add the flows to flow_list so both can be destroyed later */
	iflow = rte_zmalloc("Insert flow", sizeof(struct flows), 0);
	if (!iflow)
		DAO_ERR_GOTO(-ENOMEM, remove_mac_flow, "No memory available");

	iflow->host_flow = host_flow;
	iflow->mac_flow = mac_flow;
	if (act_cfg_idx)
		iflow->act_cfg_idx = act_cfg_idx;

	STAILQ_INSERT_TAIL(&rep_map->flow_list, iflow, next);

	dao_dbg("repr qid %d iflow %p mac flow %p host flow %p act_cfg_idx %d\n", repr_qid, iflow,
		mac_flow, host_flow, iflow->act_cfg_idx);

	free(act_cfg);

	return host_flow;
remove_mac_flow:
	remove_flow(rep_map->mac_port, mac_flow, err);
remove_host_flow:
	remove_flow(rep_map->host_port, host_flow, err);
fail:
	free(act_cfg);
	return NULL;
}

int
ood_flow_destroy(uint16_t repr_qid, struct rte_flow *flow, struct rte_flow_error *err)
{
	representor_mapping_t *rep_map;
	bool found = false;
	struct flows *iflow;
	void *tmp;
	int rc = 0;

	/* Get the flow ctrl structure */
	rep_map = ood_representor_mapping_get(repr_qid);
	if (!rep_map)
		DAO_ERR_GOTO(-EINVAL, fail,
			     "Failed to get valid flow ctrl handle for repr queue %d", repr_qid);

	/* Traverse the flow list for the flow */
	STAILQ_FOREACH_SAFE(iflow, &rep_map->flow_list, next, tmp)
	{
		if (iflow->host_flow == flow) {
			STAILQ_REMOVE(&rep_map->flow_list, iflow, flows, next);
			found = true;
			break;
		}
	}

	if (found) {
		dao_dbg("Found flows to be removed: repr qid %d iflow %p mac flow %p host flow %p"
			" act_cfg_idx %d",
			repr_qid, iflow, iflow->mac_flow, iflow->host_flow, iflow->act_cfg_idx);

		/* Remove host port flow */
		rc = remove_flow(rep_map->host_port, iflow->host_flow, err);
		if (rc)
			DAO_ERR_GOTO(rc, fail, "Failed to remove host flow, rc %d", rc);

		/* Remove mac port flow */
		rc = remove_flow(rep_map->mac_port, iflow->mac_flow, err);
		if (rc)
			DAO_ERR_GOTO(rc, fail, "Failed to remove host flow, rc %d", rc);

		/* Free tnl_cfg_index */
		if (iflow->act_cfg_idx)
			ood_node_action_config_release(iflow->act_cfg_idx);

		rte_free(iflow);
	} else {
		rc = -EINVAL;
		DAO_ERR_GOTO(rc, fail, "Flow %p not found for repr qid %d", flow, repr_qid);
	}

	return 0;
fail:
	return rc;
}

int
ood_flow_validate(uint16_t repr_qid, struct rte_flow_attr *attr, struct rte_flow_item *pattern,
		  struct rte_flow_action *action, struct rte_flow_error *err)
{
	representor_mapping_t *rep_map;
	int rc = 0;

	/* Get the flow ctrl structure */
	rep_map = ood_representor_mapping_get(repr_qid);
	if (!rep_map)
		DAO_ERR_GOTO(-EINVAL, fail,
			     "Failed to get valid flow ctrl handle for repr queue %d", repr_qid);
	/* Validate the flow */
	rc = rte_flow_validate(rep_map->host_port, attr, pattern, action, err);
	if (rc) {
		rc = elaborate_flow_error(err);
		DAO_ERR_GOTO(rc, fail, "Flow validation failed, err %d", rc);
	}

	return 0;
fail:
	return errno;
}

int
ood_flow_flush(uint16_t repr_qid, struct rte_flow_error *err)
{
	representor_mapping_t *rep_map;
	struct flows *iflow;
	int rc = 0;

	/* Get the flow ctrl structure */
	rep_map = ood_representor_mapping_get(repr_qid);
	if (!rep_map)
		DAO_ERR_GOTO(-EINVAL, fail,
			     "Failed to get valid flow ctrl handle for repr queue %d", repr_qid);

	/* Flush host port flows */
	rc = rte_flow_flush(rep_map->host_port, err);
	if (rc) {
		rc = elaborate_flow_error(err);
		DAO_ERR_GOTO(rc, fail, "Failed to flush host port %d flows", rep_map->host_port);
	}

	/* Flush mac port flows */
	rc = rte_flow_flush(rep_map->mac_port, err);
	if (rc) {
		rc = elaborate_flow_error(err);
		DAO_ERR_GOTO(rc, fail, "Failed to flush host port %d flows", rep_map->mac_port);
	}

	/* Cleanup the link list of flows added */
	STAILQ_FOREACH(iflow, &rep_map->flow_list, next)
		rte_free(iflow);

	return 0;
fail:
	return rc;
}

int
ood_flow_dump(uint16_t repr_qid, struct rte_flow *flow, uint8_t is_stdout,
	      struct rte_flow_error *err)
{
	representor_mapping_t *rep_map;
	FILE *file;
	int rc = 0;

	/* Get the flow ctrl structure */
	rep_map = ood_representor_mapping_get(repr_qid);
	if (!rep_map)
		DAO_ERR_GOTO(-EINVAL, fail,
			     "Failed to get valid flow ctrl handle for repr queue %d", repr_qid);

	/* If stdout print on screen, else use default dump file which will be
	 * copied in PMD.
	 */
	if (is_stdout) {
		file = stdout;
	} else {
		file = fopen(DEFAULT_DUMP_FILE_NAME, "w");
		if (file == NULL)
			DAO_ERR_GOTO(errno, fail,
				     "Failed to write to default dump file: %s, err %d",
				     DEFAULT_DUMP_FILE_NAME, errno);
	}
	/* Dump the flow */
	rc = rte_flow_dev_dump(rep_map->host_port, flow, file, err);
	if (rc) {
		rc = elaborate_flow_error(err);
		dao_err("Failed to dump the flow %p for port %d", flow, rep_map->mac_port);
	}

	if (!is_stdout)
		fclose(file);

	return rc;
fail:
	return rc;
}

int
ood_flow_query(uint16_t repr_qid, struct rte_flow *flow, uint8_t reset,
	       struct rte_flow_action *action, struct rte_flow_error *err,
	       ood_msg_ack_data_t *adata)
{
	/* Currently only query count supported by cnxk driver */
	struct rte_flow_query_count query;
	representor_mapping_t *rep_map;
	size_t sz;
	int rc = 0;

	sz = sizeof(struct rte_flow_query_count);
	/* Get the flow ctrl structure */
	rep_map = ood_representor_mapping_get(repr_qid);
	if (!rep_map)
		DAO_ERR_GOTO(-EINVAL, fail,
			     "Failed to get valid flow ctrl handle for repr queue %d", repr_qid);

	/* Query the flow */
	query.reset = reset;
	rc = rte_flow_query(rep_map->host_port, flow, action, &query, err);
	if (rc) {
		rc = elaborate_flow_error(err);
		DAO_ERR_GOTO(rc, fail, "Failed to dump the flow %p for port %d", flow,
			     rep_map->host_port);
	}

	dao_dbg("Flow query: hits %ld hits_set %d", query.hits, query.hits_set);

	adata->u.data = rte_zmalloc("Ack Data", sz, 0);
	rte_memcpy(adata->u.data, &query, sz);
	adata->size = sz;
	return 0;
fail:
	/* Prepare ack data */
	adata->u.sval = rc;
	adata->size = sizeof(uint64_t);
	return rc;
}
