/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <rte_hexdump.h>

#include "flow_acl_priv.h"
#include "flow_gbl_priv.h"

#include "dao_util.h"

struct acl_pkt_hdr {
	struct rte_ether_hdr eth;
	struct rte_flow_item_ipv4 ipv4;
	struct rte_flow_item_udp udp;
	struct rte_flow_item_vxlan vxlan;
	struct rte_ether_hdr ieth;
	struct rte_flow_item_ipv4 iipv4;
} __attribute((packed));

struct rte_acl_field_def rule_defs[] = {
	/* Table Id */
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 1,
		.field_index = 0,
		.input_index = 0,
		.offset = 0,
	},
	/* First 4B DMAC */
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 4,
		.field_index = 1,
		.input_index = 1,
		.offset = 1 + offsetof(struct acl_pkt_hdr, eth.dst_addr),
	},
	/* Last 2B DMAC */
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 2,
		.field_index = 2,
		.input_index = 2,
		.offset = 1 + offsetof(struct acl_pkt_hdr, eth.dst_addr) + 4,
	},
	/* 2B Padding */
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 2,
		.field_index = 3,
		.input_index = 2,
		.offset = 0,
	},
	/* First 4B SMAC */
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 4,
		.field_index = 4,
		.input_index = 3,
		.offset = 1 + offsetof(struct acl_pkt_hdr, eth.src_addr),
	},
	/* Last 2B SMAC */
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 2,
		.field_index = 5,
		.input_index = 4,
		.offset = 1 + offsetof(struct acl_pkt_hdr, eth.src_addr) + 4,
	},
	/* 2B Padding */
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 2,
		.field_index = 6,
		.input_index = 4,
		.offset = 0,
	},
	/* ETHERTYPE */
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 2,
		.field_index = 7,
		.input_index = 5,
		.offset = 1 + offsetof(struct acl_pkt_hdr, eth.ether_type),
	},
	/* 2B Padding */
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 2,
		.field_index = 8,
		.input_index = 5,
		.offset = 0,
	},
	/* SIP */
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = 4,
		.field_index = 9,
		.input_index = 6,
		.offset = 1 + offsetof(struct acl_pkt_hdr, ipv4.hdr.src_addr),
	},
	/* DIP */
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = 4,
		.field_index = 10,
		.input_index = 7,
		.offset = 1 + offsetof(struct acl_pkt_hdr, ipv4.hdr.dst_addr),
	},
	/* Proto ID */
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 1,
		.field_index = 11,
		.input_index = 8,
		.offset = 1 + offsetof(struct acl_pkt_hdr, ipv4.hdr.next_proto_id),
	},
	/* 1B Padding */
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 1,
		.field_index = 12,
		.input_index = 8,
		.offset = 0,
	},
	/* 2B Padding */
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = 2,
		.field_index = 13,
		.input_index = 8,
		.offset = 0,
	},
};

RTE_ACL_RULE_DEF(acl_rule, RTE_DIM(rule_defs));

static int
get_rule_size(void)
{
	return RTE_ACL_RULE_SZ(RTE_DIM(rule_defs));
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

int
acl_flow_lookup(struct acl_table *acl_tbl, struct rte_mbuf **objs, uint16_t nb_objs,
		uint32_t *result)
{
	uint16_t key_size = get_rule_size();
	uint8_t *data[nb_objs];
	struct rte_mbuf *mbuf;
	int i;

	memset(result, 0, nb_objs * sizeof(uint32_t));
	for (i = 0; i < nb_objs; i++) {
		uint8_t *data_p;
		uint8_t *buf;
		uint16_t lkp_id = 0;

		data[i] = calloc(1, sizeof(uint8_t) * key_size);
		data_p = data[i];
		mbuf = (struct rte_mbuf *)objs[i];
		buf = rte_pktmbuf_mtod(mbuf, uint8_t *);

		*(uint16_t *)data_p = lkp_id;
		data_p += sizeof(uint8_t);

		memcpy(data_p, buf, mbuf->data_len);
	}
	rte_spinlock_lock(&acl_tbl->ctx_lock);
	rte_acl_classify(acl_tbl->ctx, (const uint8_t **)data, result, nb_objs,
			 ACL_DEFAULT_MAX_CATEGORIES);
	rte_spinlock_unlock(&acl_tbl->ctx_lock);
	for (i = 0; i < nb_objs; i++) {
		if (result[i] && acl_tbl->num_rules)
			acl_flow_action_execute(acl_tbl, result[i], objs[i]);
		free(data[i]);
	}

	return 0;
}

static const struct rte_flow_item *
skip_void_and_any_items(const struct rte_flow_item *pattern)
{
	while ((pattern->type == RTE_FLOW_ITEM_TYPE_VOID) ||
	       (pattern->type == RTE_FLOW_ITEM_TYPE_ANY))
		pattern++;

	return pattern;
}

static int
parse_la(struct acl_parse_info *pi, struct acl_rule *rule)
{
	const struct rte_flow_item *pattern = pi->pattern;
	const uint8_t *spec, *mask;
	uint8_t none_data[100] = {0};

	if (pattern->type != RTE_FLOW_ITEM_TYPE_ETH)
		return 0;

	spec = pattern->spec ? (const uint8_t *)pattern->spec : none_data;
	mask = pattern->mask ? (const uint8_t *)pattern->mask : none_data;

	/* Copy 4B DMAC */
	rule->field[1].value.u32 =
		RTE_BE32(*(const uint32_t *)(spec + offsetof(struct rte_ether_hdr, dst_addr)));
	rule->field[1].mask_range.u32 =
		RTE_BE32(*(const uint32_t *)(mask + offsetof(struct rte_ether_hdr, dst_addr)));

	/* Copy remaining 2B DMAC */
	rule->field[2].value.u16 =
		RTE_BE16(*(const uint16_t *)(spec + offsetof(struct rte_ether_hdr, dst_addr) + 4));
	rule->field[2].mask_range.u16 =
		RTE_BE16(*(const uint16_t *)(mask + offsetof(struct rte_ether_hdr, dst_addr) + 4));
	/* 2B Padding */
	rule->field[3].value.u16 = 0;
	rule->field[3].mask_range.u16 = 0;

	/* Copy 4B SMAC */
	rule->field[4].value.u32 =
		RTE_BE32(*(const uint32_t *)(spec + offsetof(struct rte_ether_hdr, src_addr)));
	rule->field[4].mask_range.u32 =
		RTE_BE32(*(const uint32_t *)(mask + offsetof(struct rte_ether_hdr, src_addr)));

	/* Copy remaining 2B DMAC */
	rule->field[5].value.u16 =
		RTE_BE16(*(const uint16_t *)(spec + offsetof(struct rte_ether_hdr, src_addr) + 4));
	rule->field[5].mask_range.u16 =
		RTE_BE16(*(const uint16_t *)(mask + offsetof(struct rte_ether_hdr, src_addr) + 4));
	/* 2B Padding */
	rule->field[6].value.u16 = 0;
	rule->field[6].mask_range.u16 = 0;

	/* Copy 2B ETHERTYPE */
	rule->field[7].value.u16 =
		RTE_BE16(*(const uint16_t *)(spec + offsetof(struct rte_ether_hdr, ether_type)));
	rule->field[7].mask_range.u16 =
		*(const uint16_t *)(mask + offsetof(struct rte_ether_hdr, ether_type));

	/* 2B Padding */
	rule->field[8].value.u16 = 0;
	rule->field[8].mask_range.u16 = 0;
	pi->pattern++;

	return 0;
}

static int
parse_lb(struct acl_parse_info *pi, struct acl_rule *rule)
{
	const struct rte_flow_item *pattern = pi->pattern;
	const uint8_t *spec, *mask;
	uint8_t none_data[100] = {0};

	if (pattern->type != RTE_FLOW_ITEM_TYPE_VLAN)
		return 0;

	spec = pattern->spec ? (const uint8_t *)pattern->spec : none_data;
	mask = pattern->mask ? (const uint8_t *)pattern->mask : none_data;

	/* Copy 2B VID */
	rule->field[3].value.u16 =
		*(const uint16_t *)(spec + offsetof(struct rte_vlan_hdr, vlan_tci));
	rule->field[3].mask_range.u16 =
		*(const uint16_t *)(mask + offsetof(struct rte_vlan_hdr, vlan_tci));
	pi->pattern++;
	return 0;
}

static int
parse_lc(struct acl_parse_info *pi, struct acl_rule *rule)
{
	const struct rte_flow_item *pattern = pi->pattern;
	const uint8_t *spec, *mask;
	uint8_t none_data[100] = {0};

	if (pattern->type != RTE_FLOW_ITEM_TYPE_IPV4)
		return 0;

	spec = pattern->spec ? (const uint8_t *)pattern->spec : none_data;
	mask = pattern->mask ? (const uint8_t *)pattern->mask : none_data;

	/* Copy 4B SIP */
	rule->field[9].value.u32 = RTE_BE32(
		*(const uint32_t *)(spec + offsetof(struct rte_flow_item_ipv4, hdr.src_addr)));
	rule->field[9].mask_range.u32 =
		*(const uint32_t *)(mask + offsetof(struct rte_flow_item_ipv4, hdr.src_addr));

	/* Copy 4B DIP */
	rule->field[10].value.u32 = RTE_BE32(
		*(const uint64_t *)(spec + offsetof(struct rte_flow_item_ipv4, hdr.dst_addr)));
	rule->field[10].mask_range.u32 =
		*(const uint64_t *)(mask + offsetof(struct rte_flow_item_ipv4, hdr.dst_addr));
	pi->pattern++;
	return 0;
}

static int
parse_ld(struct acl_parse_info *pi, struct acl_rule *rule)
{
	const struct rte_flow_item *pattern = pi->pattern;
	const uint8_t *spec, *mask;
	uint8_t none_data[100] = {0};

	if (pattern->type != RTE_FLOW_ITEM_TYPE_UDP)
		return 0;

	spec = pattern->spec ? (const uint8_t *)pattern->spec : none_data;
	mask = pattern->mask ? (const uint8_t *)pattern->mask : none_data;

	/* Protocol value */
	rule->field[6].value.u8 = 0x11;
	rule->field[6].mask_range.u8 = 0xff;

	/* Copy 4B SPORT+DPORT */
	rule->field[8].value.u32 =
		*(const uint32_t *)(spec + offsetof(struct rte_flow_item_udp, hdr.src_port));
	rule->field[8].mask_range.u32 =
		*(const uint32_t *)(mask + offsetof(struct rte_flow_item_udp, hdr.src_port));
	pi->pattern++;
	return 0;
}

static int
parse_le(struct acl_parse_info *pi, struct acl_rule *rule)
{
	const struct rte_flow_item *pattern = pi->pattern;
	const uint8_t *spec, *mask;
	uint8_t none_data[100] = {0};

	if (pattern->type != RTE_FLOW_ITEM_TYPE_VXLAN)
		return 0;

	spec = pattern->spec ? (const uint8_t *)pattern->spec : none_data;
	mask = pattern->mask ? (const uint8_t *)pattern->mask : none_data;

	/* Copy 4B VNI */
	rule->field[9].value.u32 =
		*(const uint32_t *)(spec + offsetof(struct rte_flow_item_vxlan, vni));
	rule->field[9].mask_range.u32 =
		*(const uint32_t *)(mask + offsetof(struct rte_flow_item_vxlan, vni));
	pi->pattern++;
	return 0;
}

static int
parse_lf(struct acl_parse_info *pi, struct acl_rule *rule)
{
	const struct rte_flow_item *pattern = pi->pattern;
	const uint8_t *spec, *mask;
	uint8_t none_data[100] = {0};

	if (pattern->type != RTE_FLOW_ITEM_TYPE_ETH)
		return 0;

	spec = pattern->spec ? (const uint8_t *)pattern->spec : none_data;
	mask = pattern->mask ? (const uint8_t *)pattern->mask : none_data;

	/* Copy 6B DMAC + 2B SMAC */
	rule->field[10].value.u64 =
		*(const uint64_t *)(spec + offsetof(struct rte_ether_hdr, dst_addr));
	rule->field[10].mask_range.u64 =
		*(const uint64_t *)(mask + offsetof(struct rte_ether_hdr, dst_addr));

	/* Copy remaining 4B SMAC */
	rule->field[11].value.u32 = *(const uint32_t *)(spec + 8);
	rule->field[11].mask_range.u32 = *(const uint32_t *)(mask + 8);

	/* Copy 2B ETHERTYPE */
	rule->field[12].value.u16 =
		*(const uint16_t *)(spec + offsetof(struct rte_ether_hdr, ether_type));
	rule->field[12].mask_range.u16 =
		*(const uint16_t *)(mask + offsetof(struct rte_ether_hdr, ether_type));
	pi->pattern++;
	return 0;
}

static int
parse_lg(struct acl_parse_info *pi, struct acl_rule *rule)
{
	const struct rte_flow_item *pattern = pi->pattern;
	const uint8_t *spec, *mask;
	uint8_t none_data[100] = {0};

	if (pattern->type != RTE_FLOW_ITEM_TYPE_IPV4)
		return 0;

	spec = pattern->spec ? (const uint8_t *)pattern->spec : none_data;
	mask = pattern->mask ? (const uint8_t *)pattern->mask : none_data;

	/* Copy 2B FRAGOFFSET */
	rule->field[13].value.u16 = *(
		const uint16_t *)(spec + offsetof(struct rte_flow_item_ipv4, hdr.fragment_offset));
	rule->field[13].mask_range.u16 = *(
		const uint16_t *)(mask + offsetof(struct rte_flow_item_ipv4, hdr.fragment_offset));
	pi->pattern++;
	return 0;
}

static int
parse_lh(struct acl_parse_info *pi, struct acl_rule *rule)
{
	RTE_SET_USED(pi);
	RTE_SET_USED(rule);
	return 0;
}

typedef int (*parse_stage_func_t)(struct acl_parse_info *pi, struct acl_rule *rule);

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

static int
acl_parse_pattern(const struct rte_flow_item pattern[], struct acl_table *acl_tbl,
		  struct acl_rule_data *rule_data)
{
	RTE_SET_USED(acl_tbl);
	struct acl_parse_info pi;
	parse_stage_func_t parse_stage_funcs[] = {
		parse_la, parse_lb, parse_lc, parse_ld, parse_le, parse_lf, parse_lg, parse_lh,
	};
	uint8_t layer = 0;
	int rc;

	while (pattern->type != RTE_FLOW_ITEM_TYPE_END && layer < RTE_DIM(parse_stage_funcs)) {
		pattern = skip_void_and_any_items(pattern);

		pi.pattern = pattern;
		rc = parse_stage_funcs[layer](&pi, rule_data->rule);
		if (rc != 0)
			DAO_ERR_GOTO(rc, fail, "Failed to parse layer %d: err %d", layer, rc);
		layer++;
		pattern = pi.pattern;
	}

	pattern = skip_void_and_any_items(pattern);
	if (pattern->type != RTE_FLOW_ITEM_TYPE_END)
		return -EINVAL;

	return 0;
fail:
	return errno;
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

	rule_data = rte_zmalloc("acl_rule_data", sizeof(struct acl_rule_data), RTE_CACHE_LINE_SIZE);
	if (!rule_data)
		DAO_ERR_GOTO(-ENOMEM, free, "Failed to allocate rule_data memory");

	rule_data->rule = rte_zmalloc("acl_rule", sizeof(struct acl_rule), RTE_CACHE_LINE_SIZE);
	if (!rule_data->rule)
		DAO_ERR_GOTO(-ENOMEM, free_rule_data, "Failed to allocate rule memory");

	rule_data->rule->field[0].value.u8 = acl_tbl->tbl_id;
	rule_data->rule->field[0].mask_range.u8 = 0xff;

	/* Parse pattern */
	rc = acl_parse_pattern(pattern, acl_tbl, rule_data);
	if (rc)
		DAO_ERR_GOTO(rc, free_rule, "Failed to parse patterns %d", rc);

	/* Parse action */
	action = acl_parse_action(actions, acl_tbl);
	if (action < 0)
		DAO_ERR_GOTO(action, free_rule, "Failed to parse actions %d", action);

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
	acl_build_param.num_fields = RTE_DIM(rule_defs);
	memcpy(&acl_build_param.defs, rule_defs, sizeof(rule_defs));

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
	struct acl_global_config *acl_gbl;

	acl_gbl = rte_zmalloc("acl_global_config", sizeof(struct acl_global_config),
			      RTE_CACHE_LINE_SIZE);
	if (!acl_gbl)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory");

	gbl_cfg->acl_gbl = acl_gbl;

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
		acl_build_param.num_fields = RTE_DIM(rule_defs);
		memcpy(&acl_build_param.defs, rule_defs, sizeof(rule_defs));
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
