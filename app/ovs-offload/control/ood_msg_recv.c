/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2023 Marvell.
 */

#include <stdint.h>
#include <stdlib.h>

#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include <dao_log.h>

#include <ood_eth_ctrl.h>
#include <ood_flow_ctrl.h>
#include <ood_init.h>
#include <ood_msg_ctrl.h>

static int
parse_validate_header(void *msg_buf, uint32_t *buf_trav_len)
{
	ood_type_data_t *tdata = NULL;
	ood_header_t *hdr = NULL;
	void *data = NULL;
	uint16_t len = 0;

	/* Read first bytes of type data */
	data = msg_buf;
	tdata = (ood_type_data_t *)data;
	if (tdata->type != OOD_TYPE_HEADER)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid type %d, type header expected", tdata->type);

	/* Get the header value */
	data = RTE_PTR_ADD(msg_buf, sizeof(ood_type_data_t));
	len += sizeof(ood_type_data_t);

	/* Validate the header */
	hdr = (ood_header_t *)data;
	dao_dbg("Header signature 0x%lx", hdr->signature);
	if (OOD_SIGN != hdr->signature)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid signature detected: %lx", hdr->signature);

	/* Update length read till point */
	len += tdata->length;

	*buf_trav_len = len;
	return 0;
fail:
	return errno;
}

static void
populate_flow_attr(void *data, struct rte_flow_attr *attr, uint32_t sz)
{
	rte_memcpy(attr, data, sz);
}

static void
populate_flow_pattern(void *pattern_data, struct rte_flow_item *pattern, uint16_t nb_pattern)
{
	ood_pattern_meta_t *phdr;
	void *spec = NULL, *last = NULL, *mask = NULL;
	int i = 0;

	for (i = 0; i < nb_pattern; i++) {
		phdr = (ood_pattern_meta_t *)pattern_data;
		dao_dbg("Pattern type %d spec sz %d last sz %d mask sz %d", phdr->type,
			phdr->spec_sz, phdr->last_sz, phdr->mask_sz);
		pattern[i].type = phdr->type;
		/* Set pattern spec pointer */
		if (phdr->spec_sz) {
			/* Advance to address containing spec */
			spec = RTE_PTR_ADD(pattern_data, sizeof(ood_pattern_meta_t));
			pattern[i].spec = spec;
		}

		/* Set pattern last pointer */
		if (phdr->last_sz) {
			last = RTE_PTR_ADD(pattern_data,
					   sizeof(ood_pattern_meta_t) + phdr->spec_sz);
			pattern[i].last = last;
		}

		/* Set pattern mask pointer */
		if (phdr->mask_sz) {
			mask = RTE_PTR_ADD(pattern_data, sizeof(ood_pattern_meta_t) +
								 phdr->spec_sz + phdr->last_sz);
			pattern[i].mask = mask;
		}

		/* Advance to next pattern */
		pattern_data =
			RTE_PTR_ADD(pattern_data, sizeof(ood_pattern_meta_t) + phdr->spec_sz +
							  phdr->last_sz + phdr->mask_sz);
	}
}

static void *
populate_rss_action_conf(void *conf, uint16_t len)
{
	struct rte_flow_action_rss *rss_conf;
	uint16_t *queue_arr;
	uint8_t *key_data;
	uint16_t sz;

	rss_conf = calloc(1, sizeof(struct rte_flow_action_rss));
	if (!rss_conf) {
		dao_err("Failed to allocate memory for rss conf");
		return NULL;
	}
	sz = sizeof(struct rte_flow_action_rss) - sizeof(rss_conf->key) - sizeof(rss_conf->queue);

	rte_memcpy(rss_conf, conf, sz);

	queue_arr = calloc(1, rss_conf->queue_num * sizeof(uint16_t));
	key_data = calloc(1, rss_conf->key_len);
	if (!queue_arr || !key_data)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory for rss queue or key data");

	rte_memcpy(key_data, RTE_PTR_ADD(conf, sz), rss_conf->key_len);
	sz += rss_conf->key_len;

	rte_memcpy(queue_arr, RTE_PTR_ADD(conf, sz), rss_conf->queue_num * sizeof(uint16_t));

	sz += rss_conf->queue_num * sizeof(rss_conf->queue);

	if (sz != len)
		dao_err("RSS action conf size issue in populated size %d and actual %d", sz, len);

	rss_conf->queue = queue_arr;
	rss_conf->key = key_data;

	return rss_conf;
fail:
	if (queue_arr)
		free(queue_arr);
	if (key_data)
		free(key_data);
	free(rss_conf);

	return NULL;
}

static void *
populate_vxlan_encap_action_conf(void *conf, uint16_t len)
{
	struct rte_flow_action_vxlan_encap *vxlan_conf;
	struct rte_flow_item *pattern;
	uint64_t nb_pattern;
	int sz = 0;

	RTE_SET_USED(len);
	vxlan_conf = calloc(1, sizeof(struct rte_flow_action_vxlan_encap));
	if (!vxlan_conf) {
		dao_err("Failed to allocate memory for vxlan conf");
		return NULL;
	}
	sz = sizeof(uint64_t);

	rte_memcpy(&nb_pattern, conf, sz);

	dao_dbg("No of patterns %ld", nb_pattern);

	/* Allocate the memory for patterns */
	pattern = rte_zmalloc("Pattern", nb_pattern * sizeof(struct rte_flow_item), 0);
	if (!pattern)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory for patterns");

	/* Populate the patterns */
	populate_flow_pattern(RTE_PTR_ADD(conf, sz), pattern, nb_pattern);

	vxlan_conf->definition = pattern;

	return vxlan_conf;
fail:
	free(vxlan_conf);
	return NULL;
}

static void
populate_flow_action(void *action_data, struct rte_flow_action *action, uint16_t nb_action)
{
	ood_action_meta_t *ahdr;
	void *conf = NULL;
	int i = 0;

	for (i = 0; i < nb_action; i++) {
		ahdr = (ood_action_meta_t *)action_data;
		dao_dbg("Action type %d config sz %d", ahdr->type, ahdr->conf_sz);

		/* Set action type */
		action[i].type = ahdr->type;
		/* Set action spec pointer */
		if (ahdr->conf_sz) {
			/* Advance to address containing spec */
			switch (ahdr->type) {
			case RTE_FLOW_ACTION_TYPE_RSS:
				conf = populate_rss_action_conf(
					RTE_PTR_ADD(action_data, sizeof(ood_action_meta_t)),
					ahdr->conf_sz);
				break;
			case RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP:
				conf = populate_vxlan_encap_action_conf(
					RTE_PTR_ADD(action_data, sizeof(ood_action_meta_t)),
					ahdr->conf_sz);
				break;
			default:
				conf = RTE_PTR_ADD(action_data, sizeof(ood_action_meta_t));
				break;
			}
			action[i].conf = conf;
		}

		/* Advance to next action */
		action_data = RTE_PTR_ADD(action_data, sizeof(ood_action_meta_t) + ahdr->conf_sz);
	}
}

static int
flow_message_process(void *msg_buf, uint32_t *buf_trav_len, uint32_t msg_len,
		     ood_msg_ack_data_t *adata, ood_msg_t msg)
{
	ood_msg_flow_create_meta_t *msg_fc_data;
	uint16_t portid, nb_pattern, nb_action;
	struct rte_flow_item *pattern;
	struct rte_flow_action *action;
	ood_type_data_t *tdata = NULL;
	uint16_t len = *buf_trav_len;
	struct rte_flow_attr attr;
	struct rte_flow_error err;
	struct rte_flow *flow;
	void *data;

	/* Get the flow create message data */
	dao_dbg("Processing flow create\n");

	/* Get the message type data viz flow create fields */
	data = RTE_PTR_ADD(msg_buf, len);
	msg_fc_data = (ood_msg_flow_create_meta_t *)data;
	portid = msg_fc_data->portid;
	nb_pattern = msg_fc_data->nb_pattern;
	nb_action = msg_fc_data->nb_action;

	dao_dbg("Port Id %d nb_pattern %d nb_action %d", portid, nb_pattern, nb_action);

	/* Advance length to flow create data i.e. attr, pattern, actions */
	len += msg_len;

	/* Get the flow create data */
	tdata = (ood_type_data_t *)RTE_PTR_ADD(msg_buf, len);
	if (tdata->type != OOD_TYPE_ATTR)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid type %d, type ATTR expected", tdata->type);

	/* Get the attribute info */
	len += sizeof(ood_type_data_t);
	populate_flow_attr(RTE_PTR_ADD(msg_buf, len), &attr, tdata->length);

	/* Advancing length to read patterns */
	len += tdata->length;
	tdata = (ood_type_data_t *)RTE_PTR_ADD(msg_buf, len);
	if (tdata->type != OOD_TYPE_PATTERN)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid type %d, type PATTERN expected", tdata->type);

	/* Allocate the memory for patterns */
	pattern = rte_zmalloc("Pattern", nb_pattern * sizeof(struct rte_flow_item), 0);
	if (!pattern)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory for patterns");

	/* Populate the patterns */
	len += sizeof(ood_type_data_t);
	data = RTE_PTR_ADD(msg_buf, len);
	populate_flow_pattern(data, pattern, nb_pattern);

	/* Advancing length to read actions */
	len += tdata->length;
	tdata = (ood_type_data_t *)RTE_PTR_ADD(msg_buf, len);
	if (tdata->type != OOD_TYPE_ACTION)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid type %d, type ACTION expected", tdata->type);

	/* Allocate the memory for patterns */
	action = rte_zmalloc("Action", nb_action * sizeof(struct rte_flow_action), 0);
	if (!action)
		DAO_ERR_GOTO(-ENOMEM, fail, "Failed to allocate memory for actions");

	/* Populate the actions */
	len += sizeof(ood_type_data_t);
	data = RTE_PTR_ADD(msg_buf, len);
	populate_flow_action(data, action, nb_action);

	if (msg == OOD_MSG_FLOW_CREATE) {
		/* Installing the flow */
		flow = ood_flow_create(portid, &attr, pattern, action, &err);
		if (!flow)
			DAO_ERR_GOTO(errno, error, "Failed to create the flow, err %d", errno);

		/* Prepare ack data */
		adata->u.val = (uint64_t)flow;
		adata->size = sizeof(uint64_t);
	} else {
		if (ood_flow_validate(portid, &attr, pattern, action, &err))
			DAO_ERR_GOTO(errno, error, "Failed to validate the flow, err %d", errno);

		/* Prepare ack data */
		adata->u.val = 0; /* Success */
		adata->size = sizeof(uint64_t);
	}

	/* Advancing length for next message */
	len += tdata->length;
	*buf_trav_len = len;

	return 0;
error:
	/* TODO return rte flow err data */
	adata->u.sval = errno;
	adata->size = sizeof(uint64_t);
fail:
	/* Prepare ack data */
	adata->u.sval = errno;
	adata->size = sizeof(uint64_t);

	/* Advancing length for next message */
	len += tdata->length;
	*buf_trav_len = len;

	return errno;
}

static ood_msg_data_t *
message_data_extract(void *msg_buf, uint32_t *buf_trav_len)
{
	ood_type_data_t *tdata = NULL;
	ood_msg_data_t *msg = NULL;
	uint16_t len = *buf_trav_len;
	void *data;

	tdata = (ood_type_data_t *)RTE_PTR_ADD(msg_buf, len);
	if (tdata->type != OOD_TYPE_MSG)
		DAO_ERR_GOTO(-EINVAL, fail, "Invalid type %d, type MSG expected", tdata->type);

	/* Get the message type */
	len += sizeof(ood_type_data_t);
	data = RTE_PTR_ADD(msg_buf, len);
	msg = (ood_msg_data_t *)data;

	/* Advance to actual message data */
	len += tdata->length;
	*buf_trav_len = len;

	return msg;
fail:
	return NULL;
}

static int
flow_destroy_message_process(void *msg_buf, uint32_t *buf_trav_len, uint32_t msg_len,
			     ood_msg_ack_data_t *adata)
{
	ood_msg_flow_destroy_meta_t *msg_fd_data;
	uint16_t len = *buf_trav_len;
	struct rte_flow_error err;
	void *data;
	int rc = 0;

	/* Get the flow create message data */
	dao_dbg("Processing flow destroy");

	/* Get the message type data viz flow create fields */
	data = RTE_PTR_ADD(msg_buf, len);
	msg_fd_data = (ood_msg_flow_destroy_meta_t *)data;

	dao_dbg("Flow to be destroyed %lx port %d", msg_fd_data->flow, msg_fd_data->portid);

	rc = ood_flow_destroy(msg_fd_data->portid, (struct rte_flow *)msg_fd_data->flow, &err);
	if (rc)
		dao_err("Failed to delete the flow ");

	len += msg_len;
	*buf_trav_len = len;

	/* Prepare ack data */
	adata->u.sval = rc;
	adata->size = sizeof(uint64_t);

	return rc;
}

static int
flow_flush_message_process(void *msg_buf, uint32_t *buf_trav_len, uint32_t msg_len,
			   ood_msg_ack_data_t *adata)
{
	ood_msg_flow_flush_meta_t *msg_ff_data;
	uint16_t len = *buf_trav_len;
	struct rte_flow_error err;
	void *data;
	int rc = 0;

	/* Get the flow create message data */
	dao_dbg("Processing flow flush\n");

	/* Get the message type data viz flow create fields */
	data = RTE_PTR_ADD(msg_buf, len);
	msg_ff_data = (ood_msg_flow_flush_meta_t *)data;

	dao_dbg("Flow to be flushed for port %d", msg_ff_data->portid);

	rc = ood_flow_flush(msg_ff_data->portid, &err);
	if (rc)
		dao_err("Failed to flush the flows");

	len += msg_len;
	*buf_trav_len = len;

	/* Prepare ack data */
	adata->u.sval = rc;
	adata->size = sizeof(uint64_t);

	return rc;
}

static int
flow_dump_message_process(void *msg_buf, uint32_t *buf_trav_len, uint32_t msg_len,
			  ood_msg_ack_data_t *adata)
{
	ood_msg_flow_dump_meta_t *msg_fp_data;
	uint16_t len = *buf_trav_len;
	struct rte_flow_error err;
	void *data;
	int rc = 0;

	/* Get the flow create message data */
	dao_dbg("Processing flow dump");

	/* Get the message type data viz flow create fields */
	data = RTE_PTR_ADD(msg_buf, len);
	msg_fp_data = (ood_msg_flow_dump_meta_t *)data;

	dao_dbg("Flow to be dumped 0x%lx for rep port %d on stdout %d", msg_fp_data->flow,
		msg_fp_data->portid, msg_fp_data->is_stdout);

	rc = ood_flow_dump(msg_fp_data->portid, (struct rte_flow *)msg_fp_data->flow,
			   msg_fp_data->is_stdout, &err);
	if (rc)
		dao_err("Failed to dump the flows");

	len += msg_len;
	*buf_trav_len = len;

	/* Prepare ack data */
	adata->u.sval = rc;
	adata->size = sizeof(uint64_t);

	return rc;
}

static int
flow_query_message_process(void *msg_buf, uint32_t *buf_trav_len, uint32_t msg_len,
			   ood_msg_ack_data_t *adata)
{
	ood_msg_flow_query_meta_t *msg_fq_data;
	uint16_t len = *buf_trav_len;
	struct rte_flow_action action;
	struct rte_flow_error err;
	void *data;
	int rc = 0;

	/* Get the flow create message data */
	dao_dbg("Processing flow query");

	/* Get the message type data viz flow create fields */
	data = RTE_PTR_ADD(msg_buf, len);
	msg_fq_data = (ood_msg_flow_query_meta_t *)data;

	dao_dbg("Flow to be queries 0x%lx for rep port %d reset %d action data sz %d",
		msg_fq_data->flow, msg_fq_data->portid, msg_fq_data->reset,
		msg_fq_data->action_data_sz);

	populate_flow_action(msg_fq_data->action_data, &action, 1);

	rc = ood_flow_query(msg_fq_data->portid, (struct rte_flow *)msg_fq_data->flow,
			    msg_fq_data->reset, &action, &err, adata);
	if (rc)
		dao_err("Failed to query the flows");

	len += msg_len;
	*buf_trav_len = len;

	return rc;
}

static int
eth_stats_message_process(void *msg_buf, uint32_t *buf_trav_len, uint32_t msg_len,
			  ood_msg_ack_data_t *adata, ood_msg_t msg)
{
	ood_msg_eth_stats_meta_t *msg_st_data;
	uint16_t len = *buf_trav_len;
	void *data;
	int rc = 0;

	/* Get the eth stats message data */
	data = RTE_PTR_ADD(msg_buf, len);
	msg_st_data = (ood_msg_eth_stats_meta_t *)data;

	dao_dbg("Processing eth stats, portid %d", msg_st_data->portid);
	rc = ood_eth_stats_get_clear(msg_st_data->portid, msg, adata);
	if (rc)
		dao_err("Failed to get/reset stats");

	len += msg_len;
	*buf_trav_len = len;

	return rc;
}

static int
set_mac_message_process(void *msg_buf, uint32_t *buf_trav_len, uint32_t msg_len,
			ood_msg_ack_data_t *adata)
{
	ood_msg_eth_set_mac_meta_t *msg_sm_data;
	uint16_t len = *buf_trav_len;
	void *data;
	int rc = 0;

	/* Get the flow create message data */
	dao_dbg("Processing set mac");

	/* Get the message type data viz flow create fields */
	data = RTE_PTR_ADD(msg_buf, len);
	msg_sm_data = (ood_msg_eth_set_mac_meta_t *)data;

	dao_dbg("Set mac address 0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x port %d",
		msg_sm_data->addr_bytes[0], msg_sm_data->addr_bytes[1], msg_sm_data->addr_bytes[2],
		msg_sm_data->addr_bytes[3], msg_sm_data->addr_bytes[4], msg_sm_data->addr_bytes[5],
		msg_sm_data->portid);

	rc = ood_set_mac_address(msg_sm_data->portid, msg_sm_data->addr_bytes);
	if (rc)
		dao_err("Failed to set the mac address");

	len += msg_len;
	*buf_trav_len = len;

	/* Prepare ack data */
	adata->u.sval = rc;
	adata->size = sizeof(uint64_t);

	return rc;
}

static int
enable_ctrl_msg_polling(ood_msg_ack_data1_t *adata)
{
	const struct rte_memzone *mz;
	struct ood_main_cfg_data *ood_main_cfg;
	int i = 0, sz;

	mz = rte_memzone_lookup(OOD_MAIN_CFG_MZ_NAME);
	if (!mz) {
		dao_err("Failed to lookup for main_cfg, err %d", rte_errno);
		return -rte_errno;
	}
	ood_main_cfg = mz->addr;
	ood_main_cfg->ctrl_chan_prm->ctrl_msg_polling_enabled = true;

	sz = adata->size / sizeof(uint64_t);
	if (sz != ood_main_cfg->repr_prm->nb_repr) {
		dao_err("Representor ID count %d not equal to identified representors %d",
			sz, ood_main_cfg->repr_prm->nb_repr);
		return -EINVAL;
	}

	for (i = 0; i < sz; i++)
		ood_main_cfg->repr_prm->repr_map[i] = adata->data[i];

	return 0;
}

static int
trigger_ood_teardown(void)
{
	const struct rte_memzone *mz;
	struct ood_main_cfg_data *ood_main_cfg;

	mz = rte_memzone_lookup(OOD_MAIN_CFG_MZ_NAME);
	if (!mz) {
		dao_err("Failed to lookup for main_cfg, err %d", rte_errno);
		return -rte_errno;
	}
	ood_main_cfg = mz->addr;
	dao_dbg("Triggering force quit");
	ood_main_cfg->force_quit = true;

	return 0;
}

static void
process_ack_message(void *msg_buf, uint32_t *buf_trav_len, uint32_t msg_len)
{
	ood_msg_ack_data1_t *adata = NULL;
	uint16_t len = *buf_trav_len;
	bool nack = false;
	void *buf;

	/* Get the message type data viz ack data */
	buf = RTE_PTR_ADD(msg_buf, len);
	adata = (ood_msg_ack_data1_t *)buf;

	dao_info("Adata type %d, size %d val %ld", adata->type, adata->size,
		 adata->data[0]);
	switch (adata->type) {
	case OOD_MSG_READY:
		dao_info("Received ack for ready message");
		if (adata->size == sizeof(uint64_t)) {
			switch (adata->data[0]) {
			case OOD_MSG_NACK_INV_RDY_DATA:
				dao_err("Received NACK: Invalid ready message");
				nack = true;
				break;
			case OOD_MSG_NACK_INV_REP_CNT:
				dao_err("Received NACK: Invalid representor count");
				nack = true;
				break;
			case OOD_MSG_NACK_REPE_STP_FAIL:
				dao_err("Received NACK: Representee setup failed");
				nack = true;
				break;
			}
		}
		if (!nack)
			enable_ctrl_msg_polling(adata);
		break;
	case OOD_MSG_EXIT:
		dao_info("Received ack for exit message");
		if (adata->data[0])
			dao_err("Received NACK for exit message");
		else
			trigger_ood_teardown();
		break;
	default:
		dao_err("Ack received with invalid message type %d", adata->type);
	};

	/* Advance length to nex message */
	len += msg_len;
	*buf_trav_len = len;
}

static int
message_parse(void *msg_buf, uint32_t *buf_trav_len)
{
	ood_msg_data_t *msg = NULL;
	ood_msg_ack_data_t adata;
	bool send_ack;

	/* Get the message data */
	msg = message_data_extract(msg_buf, buf_trav_len);
	if (!msg)
		DAO_ERR_GOTO(-EINVAL, fail, "Failed to get message data");

	/* Different message type processing */
	while (msg->type != OOD_MSG_END) {
		send_ack = true;
		memset(&adata, 0, sizeof(ood_msg_ack_data_t));
		send_ack = true;
		switch (msg->type) {
		case OOD_MSG_ACK:
			dao_dbg("Received ACK message\n");
			process_ack_message(msg_buf, buf_trav_len, msg->length);
			send_ack = false;
			break;
		case OOD_MSG_FLOW_CREATE:
		case OOD_MSG_FLOW_VALIDATE:
			if (flow_message_process(msg_buf, buf_trav_len, msg->length, &adata,
						 msg->type))
				dao_err("Failed to process flow create request, err %d", errno);
			break;
		case OOD_MSG_FLOW_DESTROY:
			if (flow_destroy_message_process(msg_buf, buf_trav_len, msg->length,
							 &adata))
				dao_err("Failed to destroy flow, err %d", errno);
			break;
		case OOD_MSG_FLOW_FLUSH:
			if (flow_flush_message_process(msg_buf, buf_trav_len, msg->length, &adata))
				dao_err("Failed to flush flow, err %d", errno);
			break;
		case OOD_MSG_FLOW_DUMP:
			if (flow_dump_message_process(msg_buf, buf_trav_len, msg->length, &adata))
				dao_err("Failed to dump flow, err %d", errno);
			break;
		case OOD_MSG_FLOW_QUERY:
			if (flow_query_message_process(msg_buf, buf_trav_len, msg->length, &adata))
				dao_err("Failed to query flow, err %d", errno);
			break;
		case OOD_MSG_ETH_SET_MAC:
			if (set_mac_message_process(msg_buf, buf_trav_len, msg->length, &adata))
				dao_err("Failed to set mac, err %d", errno);
			break;
		case OOD_MSG_ETH_STATS_CLEAR:
		case OOD_MSG_ETH_STATS_GET:
			if (eth_stats_message_process(msg_buf, buf_trav_len, msg->length, &adata,
						      msg->type))
				dao_err("Failed to get/reset stats, err %d", errno);
			break;
		default:
			send_ack = false;
			DAO_ERR_GOTO(-EINVAL, fail, "Invalid message type: %d", msg->type);
		};

		/* Send ACK message to the server */
		if (send_ack)
			ood_send_ack_message(&adata);

		/* Advance to next message */
		msg = message_data_extract(msg_buf, buf_trav_len);
		if (!msg)
			DAO_ERR_GOTO(-EINVAL, fail, "Failed to get message data");
	}

	return 0;
fail:
	return errno;
}

int
ood_process_control_packet(void *msg_buf, uint32_t sz)
{
	uint32_t buf_trav_len = 0;
	/* Validate the validity of the received message */
	parse_validate_header(msg_buf, &buf_trav_len);

	/* Detect message and process */
	message_parse(msg_buf, &buf_trav_len);

	/* Ensuring entire message has been processed */
	if (sz != buf_trav_len)
		DAO_ERR_GOTO(-EFAULT, fail, "Out of %d bytes %d bytes of msg_buf processed", sz,
			     buf_trav_len);

	return 0;
fail:
	return errno;
}
