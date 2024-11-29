/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */
#include <rte_hexdump.h>
#include <rte_jhash.h>

#include "flow_em_priv.h"
#include "flow_gbl_priv.h"

#include "dao_util.h"

int
em_global_config_init(uint16_t port_id, void **gcfg)
{
	struct em_global_config *em_gbl = (struct em_global_config *)*gcfg;
	struct em_per_port *em_cfg_prt;

	if (!em_gbl) {
		em_gbl = rte_zmalloc("em_global_config", sizeof(struct em_global_config),
				     RTE_CACHE_LINE_SIZE);
		if (!em_gbl)
			DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory");

		*gcfg = (void *)em_gbl;
	}
	/* Initialize global ACL configuration */
	em_cfg_prt = &em_gbl->em_cfg_prt[port_id];
	if (!em_cfg_prt)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get per acl tables for port %d", port_id);

	em_cfg_prt->prfl_ops = gbl_cfg->flow_cfg[port_id].prfl_ops;

	return 0;
fail:
	return errno;
}

int
em_delete_rule(void *em_cfg, uint16_t port_id, uint32_t tbl_id, void *arule)
{
	struct em_global_config *em_gbl = (struct em_global_config *)em_cfg;
	struct em_rule_data *rule = (struct em_rule_data *)arule;
	struct em_rule_data *prule;
	struct em_per_port *em;
	int rc = 0;

	RTE_SET_USED(tbl_id);

	em = &em_gbl->em_cfg_prt[port_id];

	rte_spinlock_lock(&em->hash_lock);
	/* Add rules back to context except the one to be deleted */
	TAILQ_FOREACH(prule, &em->flow_list, next) {
		if ((uintptr_t)prule == (uintptr_t)rule) {
			rc = rte_hash_del_key(em->hash, prule->parsed_flow_data);
			if (rc < 0)
				goto fail;
			TAILQ_REMOVE(&em->flow_list, rule, next);
		}
	}

	em->num_rules--;
	rte_spinlock_unlock(&em->hash_lock);

	memset(&em->action[rc], 0, sizeof(struct em_actions));

	rte_free(rule);

	return 0;
fail:
	rte_spinlock_unlock(&em->hash_lock);
	return errno;
}

static int
em_cleanup(struct em_per_port *port_em)
{
	struct em_rule_data *prule;
	const void *next_key;
	uint32_t iter = 0;
	void *next_data;
	void *tmp;
	int rc;

	if (!port_em->num_rules)
		return 0;

	dao_info("Taking lock.. %s", __func__);
	rte_spinlock_lock(&port_em->hash_lock);
	while (rte_hash_iterate(port_em->hash, &next_key, &next_data, &iter) >= 0) {
		rc = rte_hash_del_key(port_em->hash, next_key);
		if (rc < 0) {
			rte_spinlock_unlock(&port_em->hash_lock);
			return -1;
		}
	}

	DAO_TAILQ_FOREACH_SAFE(prule, &port_em->flow_list, next, tmp) {
		TAILQ_REMOVE(&port_em->flow_list, prule, next);
		rte_free(prule);
	}

	rte_free(port_em->action);
	rte_hash_free(port_em->hash);
	port_em->hash = NULL;

	rte_spinlock_unlock(&port_em->hash_lock);

	return 0;
}

int
em_global_config_fini(uint16_t port_id, void *gcfg)
{
	struct em_global_config *em_gbl = (struct em_global_config *)gcfg;
	struct em_per_port *em_cfg_prt;

	if (!em_gbl)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid em_gbl hash");

	em_cfg_prt = &em_gbl->em_cfg_prt[port_id];
	if (!em_cfg_prt)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get per em tables for port %d", port_id);

	if (em_cleanup(em_cfg_prt))
		goto fail;

	return 0;
fail:
	return errno;
}

static int
em_populate_action(const struct rte_flow_action actions[], struct em_actions *em_act)
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
			em_act->in_use = true;
			em_act->act_map |= EM_ACTION_MARK;
			em_act->u.rx_action |= (uint64_t)mark << 40;
			break;
		case RTE_FLOW_ACTION_TYPE_COUNT:
			em_act->counter_enable = true;
			em_act->act_map |= EM_ACTION_COUNT;
			break;
		case RTE_FLOW_ACTION_TYPE_END:
			break;
		default:
			break;
		}
	}
	/* Enabling count action for all */
	em_act->counter_enable = true;
	em_act->act_map |= EM_ACTION_COUNT;

	return 0;
}

static void
em_rule_prepare(struct em_rule_data *rule_data, struct parsed_flow *flow)
{
	int i;

	for (i = 0; i < FLOW_PARSER_MAX_MCAM_WIDTH_DWORDS; i++)
		rule_data->parsed_flow_data[i] = flow->parsed_data[i];
}

void *
em_create_rule(void *em_cfg, const struct rte_flow_attr *attr,
	       const struct rte_flow_item pattern[], const struct rte_flow_action actions[],
	       uint16_t port_id, uint32_t *rule_idx, struct rte_flow_error *error)
{
	struct em_global_config *em_gbl = (struct em_global_config *)em_cfg;
	struct rte_hash_parameters hparam;
	struct em_rule_data *rule_data;
	struct parsed_flow *flow;
	struct em_per_port *em;
	char name[32];
	int ret;

	RTE_SET_USED(error);
	RTE_SET_USED(attr);

	em = &em_gbl->em_cfg_prt[port_id];
	em->port_id = port_id;

	if (!em->hash) {
		memset(&hparam, 0, sizeof(struct rte_hash_parameters));
		hparam.entries = EM_MAX_RULES_PER_PORT;
		hparam.key_len = 13;
		hparam.hash_func = rte_jhash;
		hparam.hash_func_init_val = 0;
		hparam.socket_id = rte_socket_id();

		snprintf(name, 32, "em_hash_%x", em->port_id);
		hparam.name = name;
		em->hash = rte_hash_create(&hparam);
		if (em->hash == NULL)
			return NULL;

		em->action = rte_zmalloc("em_action",
					 sizeof(struct em_actions) * EM_MAX_RULES_PER_PORT,
					 RTE_CACHE_LINE_SIZE);
		if (em->action == NULL) {
			rte_hash_free(em->hash);
			return NULL;
		}
		em->size = EM_MAX_RULES_PER_PORT;

		/* Synchronizing EM context */
		rte_spinlock_init(&em->hash_lock);

		TAILQ_INIT(&em->flow_list);
	}

	flow = flow_parse(&gbl_cfg->flow_cfg[em->port_id].parser, attr, pattern, actions);
	if (flow == NULL) {
		dao_info("Flow create failed..");
		return NULL;
	}

	rule_data = rte_zmalloc("em_rule_data", sizeof(struct em_rule_data), RTE_CACHE_LINE_SIZE);
	if (!rule_data) {
		//DAO_ERR_GOTO(-ENOMEM, free, "Failed to allocate rule_data memory");
		dao_info("Failed to allocate rule_data memory");
		return NULL;
	}

	em_rule_prepare(rule_data, flow);

	rte_spinlock_lock(&em->hash_lock);
	ret = rte_hash_add_key(em->hash, (void *)flow->parsed_data);
	if (ret < 0) {
		rte_spinlock_unlock(&em->hash_lock);
		return NULL;
	}
	/* Parse action */
	em->action[ret].rule_data = rule_data;
	em->action[ret].index = ret;
	rule_data->rule_idx = ret;
	em->num_rules++;
	rte_spinlock_unlock(&em->hash_lock);

	em_populate_action(actions, &em->action[ret]);
	TAILQ_INSERT_TAIL(&em->flow_list, rule_data, next);
	dao_dbg("Added new ACL rule data %p ", rule_data);

	em->num_rules_per_prt++;
	*rule_idx = rule_data->rule_idx;

	return (void *)rule_data;
}

static int
em_action_mark_id(uint64_t rx_action, struct rte_mbuf *mbuf)
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
em_flow_action_execute(struct em_per_port *em, uint32_t index, struct rte_mbuf *obj)
{
	struct em_actions *em_act = NULL;

	if (!em)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid em table");

	em_act = &em->action[index];
	if (em_act->index != index)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid action index mismatch %d and %d",
			     em_act->index, index);

	RTE_SET_USED(obj);

	if (!em_act->in_use)
		DAO_ERR_GOTO(-EINVAL, fail, "Action %d marked unused", em_act->index);

	if (em_act->act_map & EM_ACTION_MARK)
		if (em_action_mark_id(em_act->u.rx_action, obj))
			goto fail;

	if ((em_act->counter_enable) && (em_act->act_map & EM_ACTION_COUNT))
		em_act->rule_data->rule_hits++;

	return 0;
fail:
	return errno;
}

static int
em_lookup_process(struct em_per_port *em, struct rte_mbuf **objs, uint16_t nb_objs,
		  uint32_t *result)
{
	uint8_t key_buf[nb_objs][EM_X4_RULE_DEF_SIZE * 4];
	int i, j;

	memset(key_buf, 0, nb_objs * EM_X4_RULE_DEF_SIZE * 4);

	j = 0;
	for (i = 0; i < nb_objs; i++) {
		em->prfl_ops->key_generation(objs[i], 0, key_buf[j]);

		rte_spinlock_lock(&em->hash_lock);
		result[i] = rte_hash_lookup(em->hash, (const void *)key_buf[j]);
		rte_spinlock_unlock(&em->hash_lock);
		j++;
	}

	return 0;
}

int
em_flow_lookup(void *em_cfg, uint16_t port_id, struct rte_mbuf **objs, uint16_t nb_objs,
	       uint32_t *result)
{
	struct em_global_config *em_gbl = (struct em_global_config *)em_cfg;
	struct em_per_port *em;
	int i;

	em = &em_gbl->em_cfg_prt[port_id];

	if (!em)
		return EM_RULE_TBL_INVALID;
	if (!em->hash)
		return EM_RULE_HASH_INVALID;
	if (!em->num_rules)
		return EM_RULE_EMPTY;
	if (!objs)
		return EM_RULE_OBJ_INVALID;

	em_lookup_process(em, objs, nb_objs, result);
	for (i = 0; i < nb_objs; i++) {
		if (objs[i]->ol_flags & RTE_MBUF_F_RX_FDIR_ID)
			continue;
		if ((result[i] != UINT32_MAX) && em->num_rules)
			em_flow_action_execute(em, result[i], objs[i]);
	}

	return 0;
}

int
em_rule_query(void *em_cfg, uint16_t port_id, uint32_t tbl_id, void *arule,
	      struct dao_flow_query_count *query)
{
	struct em_global_config *em_gbl = (struct em_global_config *)em_cfg;
	struct em_rule_data *rule_data = (struct em_rule_data *)arule;
	struct em_per_port *em_cfg_prt;

	RTE_SET_USED(tbl_id);

	em_cfg_prt = &em_gbl->em_cfg_prt[port_id];
	if (!em_cfg_prt)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get per acl tables for port %d", port_id);

	query->rule_hits = rule_data->rule_hits;

	/* If user to reset the count */
	if (query->reset)
		rule_data->rule_hits = 0;

	return 0;
fail:
	return errno;
}

int
em_rule_dump(void *em_cfg, uint16_t port_id, uint32_t tbl_id, void *arule, FILE *file)
{
	RTE_SET_USED(em_cfg);
	RTE_SET_USED(port_id);
	RTE_SET_USED(tbl_id);
	RTE_SET_USED(arule);
	RTE_SET_USED(file);

	return 0;
}

int
em_rule_flush(void *em_cfg, uint16_t port_id)
{
	RTE_SET_USED(em_cfg);
	RTE_SET_USED(port_id);

	return 0;
}

int
em_rule_info(void *rule_data, FILE *file, bool is_hw_offloaded)
{
	struct em_rule_data *arule = (struct em_rule_data *)rule_data;

	fprintf(file, "\tEM Rule handle: %p\n", arule);
	fprintf(file, "\tEM Rule Index: %d\n", arule->rule_idx);
	fprintf(file, "\tEM rule hits: %d\n", arule->rule_hits);
	fprintf(file, "\tEM rule HW offloaded: %s\n", is_hw_offloaded ? "true" : "false");
	fprintf(file, "\n");

	return 0;
}

int
em_port_rule_count(void *em_cfg, uint16_t port_id)
{
	struct em_global_config *em_gbl = (struct em_global_config *)em_cfg;
	struct em_per_port *em_cfg_prt;

	em_cfg_prt = &em_gbl->em_cfg_prt[port_id];
	if (em_cfg_prt)
		return em_cfg_prt->num_rules_per_prt;

	return 0;
}

struct flow_fops_t em_flow_ops = {
	.init = em_global_config_init,
	.fini = em_global_config_fini,
	.create = em_create_rule,
	.destroy = em_delete_rule,
	.lookup = em_flow_lookup,
	.query = em_rule_query,
	.dump = em_rule_dump,
	.flush = em_rule_flush,
	.info = em_rule_info,
	.count = em_port_rule_count,
};
