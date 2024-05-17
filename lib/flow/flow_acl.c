/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <rte_hexdump.h>

#include "flow_acl_priv.h"
#include "flow_gbl_priv.h"

#include "dao_util.h"

static int
get_rule_size(void)
{
	return RTE_ACL_RULE_SZ(RTE_DIM(ovs_kex_acl_defs));
}

static int
acl_action_mark_id(uint64_t rx_action, struct rte_mbuf *mbuf)
{
	uint16_t mark;

	if (!rx_action)
		DAO_ERR_GOTO(-EINVAL, fail, "Mark ID not received");

	mark = ((uint64_t)rx_action >> 40) & 0xFFFF;

	dao_dbg("Action Mark id is %d", mark);

	mbuf->ol_flags |= RTE_MBUF_F_RX_FDIR_ID;
	mbuf->hash.fdir.hi = mark;

	return 0;
fail:
	return errno;
}

static int
acl_flow_action_execute(struct acl_table *acl_tbl, uint32_t index, struct rte_mbuf *obj)
{
	struct acl_actions *acl_act = NULL;

	if (!acl_tbl)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid acl table");

	acl_act = &acl_tbl->action[index];
	if (acl_act->index != index)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid action index mismatch %d and %d",
			     acl_act->index, index);

	if (!acl_act->in_use)
		DAO_ERR_GOTO(-EINVAL, fail, "Action %d marked unused", acl_act->index);

	if (acl_act->act_map & ACL_ACTION_MARK)
		if (acl_action_mark_id(acl_act->u.rx_action, obj))
			goto fail;

	return 0;
fail:
	return errno;
}

static int
acl_lookup_process(struct acl_table *acl_tbl, struct rte_mbuf **objs, uint16_t nb_objs,
		   uint32_t *result)
{
	uint8_t key_buf[nb_objs][ACL_X4_RULE_DEF_SIZE * 4];
	uint8_t *data[nb_objs];
	int i, j, rc;

	memset(data, 0, nb_objs);
	memset(key_buf, 0, nb_objs * ACL_X4_RULE_DEF_SIZE * 4);

	j = 0;
	for (i = 0; i < nb_objs; i++) {
		if (objs[i]->ol_flags & RTE_MBUF_F_RX_FDIR_ID)
			continue;
		acl_tbl->prfl_ops->key_generation(objs[i], 0, (uint8_t *)&key_buf[j] + 4);
		key_buf[j][0] = acl_tbl->tbl_id;
		data[j] = (uint8_t *)key_buf[j];
		j++;
	}

	/* ctx, data, results, num, category */
	rte_spinlock_lock(&acl_tbl->ctx_lock);
	rc = rte_acl_classify(acl_tbl->ctx, (const uint8_t **)data, result, j,
			      ACL_DEFAULT_MAX_CATEGORIES);
	rte_spinlock_unlock(&acl_tbl->ctx_lock);
	return rc;
}

int
acl_flow_lookup(struct acl_table *acl_tbl, struct rte_mbuf **objs, uint16_t nb_objs,
		uint32_t *result)
{
	int i;

	if (!acl_tbl)
		return ACL_RULE_TBL_INVALID;
	if (!acl_tbl->ctx)
		return ACL_RULE_CTX_INVALID;
	if (!acl_tbl->num_rules)
		return ACL_RULE_EMPTY;
	if (!objs)
		return ACL_RULE_OBJ_INVALID;

	acl_lookup_process(acl_tbl, objs, nb_objs, result);
	for (i = 0; i < nb_objs; i++) {
		if (result[i] && acl_tbl->num_rules)
			acl_flow_action_execute(acl_tbl, result[i], objs[i]);
	}

	return 0;
}

static int
acl_populate_action(const struct rte_flow_action actions[], struct acl_actions *acl_act)
{
	const struct rte_flow_action_mark *act_mark;
	uint16_t mark = 0;

	for (; actions->type != RTE_FLOW_ACTION_TYPE_END; actions++) {
		switch (actions->type) {
		case RTE_FLOW_ACTION_TYPE_VOID:
			break;
		case RTE_FLOW_ACTION_TYPE_MARK:
			act_mark = (const struct rte_flow_action_mark *)actions->conf;
			mark = act_mark->id;
			acl_act->in_use = true;
			acl_act->act_map |= ACL_ACTION_MARK;
			acl_act->u.rx_action |= (uint64_t)mark << 40;
			break;
		case RTE_FLOW_ACTION_TYPE_END:
			break;
		default:
			break;
		}
	}
	return 0;
}

static int
acl_parse_action(const struct rte_flow_action actions[], struct acl_table *acl_tbl)
{
	uint32_t action;
	uint32_t i;

	if (!acl_tbl->action) {
		/* Allocate space for action data */
		acl_tbl->action = rte_zmalloc("acl_action",
					      sizeof(struct acl_actions) * ACL_MAX_RULES_PER_CTX,
					      RTE_CACHE_LINE_SIZE);
		if (acl_tbl->action == NULL)
			return -ENOMEM;

		acl_tbl->size = ACL_MAX_RULES_PER_CTX;

		/* MRU mechanism, action[0] holds next free index */
		for (i = 0; i < ACL_MAX_RULES_PER_CTX - 1; i++)
			acl_tbl->action[i].index = i + 1;
		acl_tbl->action[i].index = (uint32_t)~0x0;
	}

	/* Out of space, expand the array */
	if (acl_tbl->action[0].index == (uint32_t)~0x0) {
		acl_tbl->action =
			rte_realloc(acl_tbl->action, acl_tbl->size * 2, RTE_CACHE_LINE_SIZE);
		for (i = acl_tbl->size; i < (acl_tbl->size * 2) - 1; i++)
			acl_tbl->action[i].index = i + 1;
		acl_tbl->action[i].index = (uint32_t)~0x0;
		acl_tbl->action[0].index = acl_tbl->size;
		acl_tbl->size = (acl_tbl->size * 2);
	}
	/* Get free action index */
	action = acl_tbl->action[0].index;
	/* Point free index to next free location */
	acl_tbl->action[0].index = acl_tbl->action[action].index;
	acl_tbl->action[action].index = action;

	dao_dbg("	New action index %d allotted, earlier free action index was %d", action,
		acl_tbl->action[0].index);
	if (acl_populate_action(actions, &acl_tbl->action[action]))
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to populate action");

	return action;
fail:
	return errno;
}

static void
acl_rule_prepare(struct acl_rule_data *rule_data, struct parsed_flow *flow)
{
	uint32_t *parsed_data = (uint32_t *)&flow->parsed_data;
	uint32_t *parsed_data_mask = (uint32_t *)&flow->parsed_data_mask;
	int i;

	for (i = 1; i <= ACL_X4_RULE_DEF_SIZE - 1; i++) {
		rule_data->rule->field[i].value.u32 = rte_be_to_cpu_32(parsed_data[i - 1]);
		rule_data->rule->field[i].mask_range.u32 =
			rte_be_to_cpu_32(parsed_data_mask[i - 1]);
	}
}

struct acl_rule_data *
acl_create_rule(struct acl_table *acl_tbl, const struct rte_flow_attr *attr,
		const struct rte_flow_item pattern[], const struct rte_flow_action actions[],
		struct rte_flow_error *error)
{
	enum rte_acl_classify_alg alg = RTE_ACL_CLASSIFY_SCALAR;
	struct rte_acl_config acl_build_param;
	struct acl_rule_data *rule_data;
	char name[RTE_ACL_NAMESIZE];
	struct parsed_flow *flow;
	struct rte_acl_param param;
	int rc, action;

	RTE_SET_USED(error);
	RTE_SET_USED(attr);
	RTE_SET_USED(action);

	if (!acl_tbl)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid acl table handle");

	snprintf(name, RTE_ACL_NAMESIZE, "acl_ctx_%x_%x", acl_tbl->port_id, acl_tbl->tbl_id);
	acl_tbl->ctx = rte_acl_find_existing(name);
	/* Context doesn't exists, create one */
	if (!acl_tbl->ctx) {
		memset(&param, 0, sizeof(struct rte_acl_param));
		param.max_rule_num = ACL_MAX_RULES_PER_CTX;
		param.rule_size = get_rule_size();
		param.name = name;
		param.socket_id = rte_socket_id();
		acl_tbl->ctx = rte_acl_create(&param);
		if (acl_tbl->ctx == NULL)
			return NULL;
		rc = rte_acl_set_ctx_classify(acl_tbl->ctx, alg);
		if (rc) {
			rte_acl_free(acl_tbl->ctx);
			acl_tbl->ctx = NULL;
			return NULL;
		}
		/* Synchronizing ACL context */
		rte_spinlock_init(&acl_tbl->ctx_lock);
		acl_tbl->tbl_val = true;

		TAILQ_INIT(&acl_tbl->flow_list);
	}

	flow = flow_parse(&gbl_cfg->parser, attr, pattern, actions);
	if (flow == NULL)
		return NULL;

	/* Parse action */
	action = acl_parse_action(actions, acl_tbl);
	if (action < 0)
		DAO_ERR_GOTO(action, free, "Failed to parse actions %d", action);

	rule_data = rte_zmalloc("acl_rule_data", sizeof(struct acl_rule_data), RTE_CACHE_LINE_SIZE);
	if (!rule_data)
		DAO_ERR_GOTO(-ENOMEM, free, "Failed to allocate rule_data memory");

	rule_data->rule = rte_zmalloc("acl_rule", sizeof(struct acl_rule), RTE_CACHE_LINE_SIZE);
	if (!rule_data->rule)
		DAO_ERR_GOTO(-ENOMEM, free_rule_data, "Failed to allocate rule memory");

	acl_rule_prepare(rule_data, flow);
	rule_data->rule->field[0].value.u8 = acl_tbl->tbl_id;
	rule_data->rule->field[0].mask_range.u8 = 0xff;

	rule_data->rule->data.priority = attr->priority + 1;
	rule_data->rule->data.category_mask = -1;
	rule_data->rule->data.userdata = action;

	rte_spinlock_lock(&acl_tbl->ctx_lock);
	rc = rte_acl_add_rules(acl_tbl->ctx, (struct rte_acl_rule *)rule_data->rule, 1);
	if (rc)
		DAO_ERR_GOTO(rc, free_rule, "Failed to add acl rule %d", rc);

	/* Perform builds */
	memset(&acl_build_param, 0, sizeof(acl_build_param));

	acl_build_param.num_categories = ACL_DEFAULT_MAX_CATEGORIES;
	acl_build_param.num_fields = RTE_DIM(ovs_kex_acl_defs);
	memcpy(&acl_build_param.defs, ovs_kex_acl_defs, sizeof(ovs_kex_acl_defs));

	rc = rte_acl_build(acl_tbl->ctx, &acl_build_param);
	if (rc)
		DAO_ERR_GOTO(rc, free_rule, "Failed to build acl context %d", rc);

	acl_tbl->num_rules++;
	acl_tbl->action[rule_data->rule->data.userdata].rule_data = rule_data;
	rule_data->rule_idx = rule_data->rule->data.userdata;
	rte_spinlock_unlock(&acl_tbl->ctx_lock);

	rte_acl_dump(acl_tbl->ctx);

	TAILQ_INSERT_TAIL(&acl_tbl->flow_list, rule_data, next);
	dao_dbg("Added new ACL rule data %p rule %p", rule_data, rule_data->rule);

	return rule_data;
free_rule:
	rte_spinlock_unlock(&acl_tbl->ctx_lock);
	rte_free(rule_data->rule);
free_rule_data:
	rte_free(rule_data);
free:
	rte_acl_free(acl_tbl->ctx);
	acl_tbl->ctx = NULL;
fail:
	return NULL;
}

int
acl_global_config_init(struct flow_global_cfg *gbl_cfg)
{
	struct acl_config_per_port *acl_cfg_prt;
	struct acl_global_config *acl_gbl;
	struct acl_table *acl_tbl;
	int i, j;

	acl_gbl = rte_zmalloc("acl_global_config", sizeof(struct acl_global_config),
			      RTE_CACHE_LINE_SIZE);
	if (!acl_gbl)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory");

	gbl_cfg->acl_gbl = acl_gbl;
	/* Initialize global ACL configuration */
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		acl_cfg_prt = &gbl_cfg->acl_gbl->acl_cfg_prt[i];
		if (!acl_cfg_prt)
			DAO_ERR_GOTO(-EINVAL, fail, "Failed to get per acl tables for port %d", i);

		for (j = 0; j < ACL_MAX_PORT_TABLES; j++) {
			acl_tbl = &acl_cfg_prt->acl_tbl[j];
			if (!acl_tbl)
				DAO_ERR_GOTO(-EINVAL, fail,
					     "Failed to get table for tbl_id %d, port id %d", j, i);
			acl_tbl->prfl_ops = gbl_cfg->prfl_ops;
		}
	}
	return 0;
fail:
	return errno;
}

static int
acl_table_cleanup(struct acl_table *acl_tbl)
{
	struct acl_rule_data *prule;
	void *tmp;

	if (!acl_tbl->tbl_val)
		return 0;

	DAO_TAILQ_FOREACH_SAFE(prule, &acl_tbl->flow_list, next, tmp) {
		dao_dbg("[%s]: Removed ACL rule data %p rule %p", __func__, prule, prule->rule);
		TAILQ_REMOVE(&acl_tbl->flow_list, prule, next);
		rte_free(prule->rule);
		rte_free(prule);
		acl_tbl->num_rules--;
	}
	if (acl_tbl->num_rules != 0)
		DAO_ERR_GOTO(-EINVAL, fail, "Flow list should be empty: num_rules %d",
			     acl_tbl->num_rules);
	rte_free(acl_tbl->action);
	rte_spinlock_lock(&acl_tbl->ctx_lock);
	rte_acl_reset(acl_tbl->ctx);
	rte_acl_free(acl_tbl->ctx);
	rte_spinlock_unlock(&acl_tbl->ctx_lock);
	acl_tbl->tbl_val = false;

	return 0;
fail:
	return errno;
}

int
acl_global_config_fini(struct flow_global_cfg *gbl_cfg)
{
	struct acl_config_per_port *acl_cfg_prt;
	struct acl_global_config *acl_gbl;
	struct acl_table *acl_tbl;
	int i, j;

	acl_gbl = gbl_cfg->acl_gbl;
	if (!acl_gbl)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid acl_gbl handle");

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		acl_cfg_prt = &gbl_cfg->acl_gbl->acl_cfg_prt[i];
		if (!acl_cfg_prt)
			DAO_ERR_GOTO(-EINVAL, fail, "Failed to get per acl tables for port %d", i);

		for (j = 0; j < ACL_MAX_PORT_TABLES; j++) {
			acl_tbl = &acl_cfg_prt->acl_tbl[j];
			if (!acl_tbl)
				DAO_ERR_GOTO(-EINVAL, fail,
					     "Failed to get table for tbl_id %d, port id %d", j, i);
			if (acl_table_cleanup(acl_tbl))
				goto fail;
		}
	}

	return 0;
fail:
	return errno;
}

uint32_t
acl_delete_rule(struct acl_table *acl_tbl, struct acl_rule_data *rule)
{
	struct rte_acl_ctx *ctx = acl_tbl->ctx;
	struct rte_acl_config acl_build_param;
	struct acl_rule_data *prule;
	uint32_t tid, count = 0;
	int rc;

	rte_spinlock_lock(&acl_tbl->ctx_lock);
	/* Free all the rules from original context */
	rte_acl_reset_rules(ctx);
	/* Add rules back to context except the one to be deleted */
	TAILQ_FOREACH(prule, &acl_tbl->flow_list, next) {
		if ((uintptr_t)prule != (uintptr_t)rule) {
			count++;
			dao_dbg("Moving ACL rule %p %p", prule, prule->rule);
			rc = rte_acl_add_rules(ctx, (struct rte_acl_rule *)prule->rule, 1);
			if (rc)
				DAO_ERR_GOTO(rc, fail, "Failed to add rules to context %d", rc);
		}
	}

	if (count) {
		/* Perform builds */
		memset(&acl_build_param, 0, sizeof(acl_build_param));
		acl_build_param.num_categories = ACL_DEFAULT_MAX_CATEGORIES;
		acl_build_param.num_fields = RTE_DIM(ovs_kex_acl_defs);
		memcpy(&acl_build_param.defs, ovs_kex_acl_defs, sizeof(ovs_kex_acl_defs));
		rc = rte_acl_build(ctx, &acl_build_param);
		if (rc)
			DAO_ERR_GOTO(rc, fail, "Failed to build acl context %d", rc);

	} else {
		rte_acl_reset_rules(ctx);
	}
	acl_tbl->num_rules--;
	rte_spinlock_unlock(&acl_tbl->ctx_lock);
	rte_acl_dump(ctx);

	TAILQ_REMOVE(&acl_tbl->flow_list, rule, next);
	tid = acl_tbl->action[0].index;
	acl_tbl->action[0].index = rule->rule->data.userdata;
	memset(&acl_tbl->action[rule->rule->data.userdata], 0, sizeof(struct acl_actions));
	acl_tbl->action[rule->rule->data.userdata].index = tid;
	dao_dbg("	After deleted - index made free %d, earlier free index was %d",
		acl_tbl->action[0].index, tid);
	dao_dbg("[%s]: Removed ACL rule data %p rule %p", __func__, rule, rule->rule);
	rte_free(rule->rule);
	rte_free(rule);

	return 0;
fail:
	rte_spinlock_unlock(&acl_tbl->ctx_lock);
	return errno;
}
